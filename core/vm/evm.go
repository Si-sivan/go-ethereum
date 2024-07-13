// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"errors"
	"math/big"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

type (
	// CanTransferFunc is the signature of a transfer guard function
	CanTransferFunc func(StateDB, common.Address, *uint256.Int) bool
	// TransferFunc is the signature of a transfer function
	TransferFunc func(StateDB, common.Address, common.Address, *uint256.Int)
	// GetHashFunc 返回区块链中第n个区块的哈希，并用于 BLOCKHASH EVM 操作码
	GetHashFunc func(uint64) common.Hash
)

func (evm *EVM) precompile(addr common.Address) (PrecompiledContract, bool) {
	var precompiles map[common.Address]PrecompiledContract
	switch {
	case evm.chainRules.IsVerkle:
		precompiles = PrecompiledContractsVerkle
	case evm.chainRules.IsPrague:
		precompiles = PrecompiledContractsPrague
	case evm.chainRules.IsCancun:
		precompiles = PrecompiledContractsCancun
	case evm.chainRules.IsBerlin:
		precompiles = PrecompiledContractsBerlin
	case evm.chainRules.IsIstanbul:
		precompiles = PrecompiledContractsIstanbul
	case evm.chainRules.IsByzantium:
		precompiles = PrecompiledContractsByzantium
	default:
		precompiles = PrecompiledContractsHomestead
	}
	p, ok := precompiles[addr]
	return p, ok
}

// BlockContext 为EVM提供辅助信息。提供后不应修改。
type BlockContext struct {
	// CanTransfer 返回账户是否有足够的以太币转移
	CanTransfer CanTransferFunc
	// Transfer 将以太币从一个账户转移到另一个账户
	// GetHash 返回对应 n 的哈希
	GetHash GetHashFunc

	// 区块信息
	Coinbase    common.Address // Provides information for COINBASE
	GasLimit    uint64         // Provides information for GASLIMIT
	BlockNumber *big.Int       // Provides information for NUMBER
	Time        uint64         // Provides information for TIME
	Difficulty  *big.Int       // Provides information for DIFFICULTY
	BaseFee     *big.Int       // Provides information for BASEFEE (0 if vm runs with NoBaseFee flag and 0 gas price)
	BlobBaseFee *big.Int       // Provides information for BLOBBASEFEE (0 if vm runs with NoBaseFee flag and 0 blob gas price)
	Random      *common.Hash   // Provides information for PREVRANDAO
}

// TxContext 为 EVM 提供有关交易的信息。所有字段可以在交易之间变化
type TxContext struct {
	// Message information
	Origin       common.Address      // Provides information for ORIGIN
	GasPrice     *big.Int            // Provides information for GASPRICE (and is used to zero the basefee if NoBaseFee is set)
	BlobHashes   []common.Hash       // Provides information for BLOBHASH
	BlobFeeCap   *big.Int            // Is used to zero the blobbasefee if NoBaseFee is set
	AccessEvents *state.AccessEvents // 捕获此交易的所有状态访问
}

// EVM 是以太坊虚拟机的基本对象，并提供在给定状态下运行合约所需的工具。
// 需要注意的是，通过任何调用产生的任何错误都应被视为恢复状态并消耗所有gas的操作，
// 不应对特定错误执行任何检查。解释器确保任何产生的错误都应被视为代码错误
//
// The EVM 不应重复使用，并且不是线程安全的
type EVM struct {
	// Context 提供辅助区块链相关信息
	TxContext
	// StateDB 访问底层状态
	// Depth 是当前调用堆栈的深度
	depth int

	// chainConfig 包含有关当前链的信息
	chainConfig *params.ChainConfig
	// chain rules 包含当前时代的链规则
	chainRules params.Rules
	// 虚拟机配置选项，用于初始化evm
	Config Config
	// 在此上下文中使用的全局以太坊虚拟机在交易执行过程中使用
	interpreter *EVMInterpreter
	// abort 用于中止EVM调用操作
	// callGasTemp 保存当前调用可用的gas。因为根据63/64规则计算可用gas并在 opCall*中应用.
	callGasTemp uint64
}

// NewEVM 返回一个新的EVM。返回的EVM不是线程安全的，只应使用一次.
func NewEVM(blockCtx BlockContext, txCtx TxContext, statedb StateDB, chainConfig *params.ChainConfig, config Config) *EVM {
	// 如果禁用了basefee跟踪（eth_call,eth_estimateGas等），且未指定gas价格，
	// 则将basefee降低为0，以避免破环EVM 不变量(basefee < feecap)
	if config.NoBaseFee {
		if txCtx.GasPrice.BitLen() == 0 {
			blockCtx.BaseFee = new(big.Int)
		}
		if txCtx.BlobFeeCap != nil && txCtx.BlobFeeCap.BitLen() == 0 {
			blockCtx.BlobBaseFee = new(big.Int)
		}
	}
	evm := &EVM{
		Context:     blockCtx,
		TxContext:   txCtx,
		StateDB:     statedb,
		Config:      config,
		chainConfig: chainConfig,
		chainRules:  chainConfig.Rules(blockCtx.BlockNumber, blockCtx.Random != nil, blockCtx.Time),
	}
	evm.interpreter = NewEVMInterpreter(evm)
	return evm
}

// Reset使用新的交易上下文重置EVM.
// 这不是线程安全的，应该非常谨慎地进行
func (evm *EVM) Reset(txCtx TxContext, statedb StateDB) {
	if evm.chainRules.IsEIP4762 {
		txCtx.AccessEvents = state.NewAccessEvents(statedb.PointCache())
	}
	evm.TxContext = txCtx
	evm.StateDB = statedb
}

// Cancel 取消任何正在运行的EVM操作。可以并发调用，并且可以安全地多次调用
func (evm *EVM) Cancel() {
	evm.abort.Store(true)
}

// Cancelled 返回true当Cancel已被调用
func (evm *EVM) Cancelled() bool {
	return evm.abort.Load()
}

// Interpreter 返回当前的解释器
func (evm *EVM) Interpreter() *EVMInterpreter {
	return evm.interpreter
}

// Call 执行与addr关联的合约，并将给定的输入作为参数
// 它还处理任何必要的value转移并采取必要步骤创建账户，在执行错误或value转移失败的情况下恢复状态
func (evm *EVM) Call(caller ContractRef, addr common.Address, input []byte, gas uint64, value *uint256.Int) (ret []byte, leftOverGas uint64, err error) {
	// 在调试模式下捕获跟踪器start/end 事件
	if evm.Config.Tracer != nil {
		evm.captureBegin(evm.depth, CALL, caller.Address(), addr, input, gas, value.ToBig())
		defer func(startGas uint64) {
			evm.captureEnd(evm.depth, startGas, leftOverGas, ret, err)
		}(gas)
	}
	// 如果我们试图执行超过调用depth limit的操作，则失败
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// 当试图转移超过可用余额的金额时，返回失败
	if !value.IsZero() && !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}
	snapshot := evm.StateDB.Snapshot()
	p, isPrecompile := evm.precompile(addr)

	if !evm.StateDB.Exist(addr) {
		if !isPrecompile && evm.chainRules.IsEIP4762 {
			// add proof of absence to witness
			wgas := evm.AccessEvents.AddAccount(addr, false)
			if gas < wgas {
				evm.StateDB.RevertToSnapshot(snapshot)
				return nil, 0, ErrOutOfGas
			}
			gas -= wgas
		}

		if !isPrecompile && evm.chainRules.IsEIP158 && value.IsZero() {
			// Calling a non-existing account, don't do anything.
			return nil, gas, nil
		}
		evm.StateDB.CreateAccount(addr)
	}
	evm.Context.Transfer(evm.StateDB, caller.Address(), addr, value)

	if isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas, evm.Config.Tracer)
	} else {
		// 初始化一个新的合约并设置EVM将要使用的代码
		// 该合约仅是本次执行山下文中的一个作用域环境.
		code := evm.StateDB.GetCode(addr)
		if witness := evm.StateDB.Witness(); witness != nil {
			witness.AddCode(code)
		}
		if len(code) == 0 {
			ret, err = nil, nil // gas 保持不变
		} else {
			addrCopy := addr
			// 如果账户没有代码，我们可以在这里中止
			// depth-check 已经完成，并且预编译处理已在上方完成
			contract := NewContract(caller, AccountRef(addrCopy), value, gas)
			contract.SetCallCode(&addrCopy, evm.StateDB.GetCodeHash(addrCopy), code)
			ret, err = evm.interpreter.Run(contract, input, false)
			gas = contract.Gas
		}
	}
	// 如果EVM返回了一个错误或者在上方设置创建合约时
	// 我们回滚到快照并消耗任何剩余的gas.此外,
	// 在homestead 期间，这也适用于代码存储gas错误.
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			if evm.Config.Tracer != nil && evm.Config.Tracer.OnGasChange != nil {
				evm.Config.Tracer.OnGasChange(gas, 0, tracing.GasChangeCallFailedExecution)
			}

			gas = 0
		}
		// TODO: consider clearing up unused snapshots:
		//} else {
		//	evm.StateDB.DiscardSnapshot(snapshot)
	}
	return ret, gas, err
}

// CallCode 使用给定的输入作为参数执行与addr相关的合约
// 这也处理任何必要的价值转移并采取必要的步骤来创建账户，并在执行错误或失败的价值转移情况下恢复状态。
//
// CallCode differs from Call in the sense that it executes the given address'
// code with the caller as context.
func (evm *EVM) CallCode(caller ContractRef, addr common.Address, input []byte, gas uint64, value *uint256.Int) (ret []byte, leftOverGas uint64, err error) {
	// 调用tracer钩子信号 entering/exiting 调用框架
	if evm.Config.Tracer != nil {
		evm.captureBegin(evm.depth, CALLCODE, caller.Address(), addr, input, gas, value.ToBig())
		defer func(startGas uint64) {
			evm.captureEnd(evm.depth, startGas, leftOverGas, ret, err)
		}(gas)
	}
	//  如果我们试图执行超出调用深度限制，失败
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// 如果我们试图转移超过可用余额的金额，失败
	// Note although it's noop to transfer X ether to caller itself. But
	// if caller doesn't have enough balance, it would be an error to allow
	// over-charging itself. So the check here is necessary.
	if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}
	var snapshot = evm.StateDB.Snapshot()

	// 允许调用预编译，即使是通过delegatecall
	if p, isPrecompile := evm.precompile(addr); isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas, evm.Config.Tracer)
	} else {
		addrCopy := addr
		// 初始化一个新的合约并设置EVM将要使用的代码。.
		// 该合约仅是本次执行上下文中的一个作用域环境。
		contract := NewContract(caller, AccountRef(caller.Address()), value, gas)
		if witness := evm.StateDB.Witness(); witness != nil {
			witness.AddCode(evm.StateDB.GetCode(addrCopy))
		}
		contract.SetCallCode(&addrCopy, evm.StateDB.GetCodeHash(addrCopy), evm.StateDB.GetCode(addrCopy))
		ret, err = evm.interpreter.Run(contract, input, false)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			if evm.Config.Tracer != nil && evm.Config.Tracer.OnGasChange != nil {
				evm.Config.Tracer.OnGasChange(gas, 0, tracing.GasChangeCallFailedExecution)
			}

			gas = 0
		}
	}
	return ret, gas, err
}

// DelegateCall使用给定的输入作为参数执行与addr相关的合约
// 并在执行错误的情况下恢复状态。
//
// DelegateCall与CallCode的不同之处在于它以调用者的上下文执行给定地址的代码，
// 并且调用者被设置为调用者的调用者。
func (evm *EVM) DelegateCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	// 调用tracer钩子信号 entering/exiting 调用框架
	if evm.Config.Tracer != nil {
		// 注意：调用者必须始终是合约。不应该发生调用者是合约以外的情况。
		parent := caller.(*Contract)
		// DELEGATECALL inherits value from parent call
		evm.captureBegin(evm.depth, DELEGATECALL, caller.Address(), addr, input, gas, parent.value.ToBig())
		defer func(startGas uint64) {
			evm.captureEnd(evm.depth, startGas, leftOverGas, ret, err)
		}(gas)
	}
	// 如果我们试图执行超出调用深度限制，失败
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	var snapshot = evm.StateDB.Snapshot()

	// 允许调用预编译，即使是通过delegatecall
	if p, isPrecompile := evm.precompile(addr); isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas, evm.Config.Tracer)
	} else {
		addrCopy := addr
		// 初始化一个新的合约并初始化delegate值
		contract := NewContract(caller, AccountRef(caller.Address()), nil, gas).AsDelegate()
		if witness := evm.StateDB.Witness(); witness != nil {
			witness.AddCode(evm.StateDB.GetCode(addrCopy))
		}
		contract.SetCallCode(&addrCopy, evm.StateDB.GetCodeHash(addrCopy), evm.StateDB.GetCode(addrCopy))
		ret, err = evm.interpreter.Run(contract, input, false)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			if evm.Config.Tracer != nil && evm.Config.Tracer.OnGasChange != nil {
				evm.Config.Tracer.OnGasChange(gas, 0, tracing.GasChangeCallFailedExecution)
			}
			gas = 0
		}
	}
	return ret, gas, err
}

// StaticCall使用给定的输入作为参数执行与addr相关的合约
// 同时不允许在调用期间对状态进行任何修改。
// 试图执行此类修改的操作码将导致异常，而不是执行修改。
func (evm *EVM) StaticCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	// Invoke tracer hooks that signal entering/exiting a call frame
	if evm.Config.Tracer != nil {
		evm.captureBegin(evm.depth, STATICCALL, caller.Address(), addr, input, gas, nil)
		defer func(startGas uint64) {
			evm.captureEnd(evm.depth, startGas, leftOverGas, ret, err)
		}(gas)
	}
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// We take a snapshot here. This is a bit counter-intuitive, and could probably be skipped.
	// However, even a staticcall is considered a 'touch'. On mainnet, static calls were introduced
	// after all empty accounts were deleted, so this is not required. However, if we omit this,
	// then certain tests start failing; stRevertTest/RevertPrecompiledTouchExactOOG.json.
	// We could change this, but for now it's left for legacy reasons
	var snapshot = evm.StateDB.Snapshot()

	// 我们在这里增加零余额，只是为了触发一个 touch.
	// 这在Mainnet上没有关系，因为在Byzantium时期所有空账户都已删除，
	// 但在其他网络、测试以及未来潜在场景中是正确的做法
	evm.StateDB.AddBalance(addr, new(uint256.Int), tracing.BalanceChangeTouchAccount)

	if p, isPrecompile := evm.precompile(addr); isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas, evm.Config.Tracer)
	} else {
		//  在这一点上，我们使用地址的副本。如果不这样做，go编译器将
		// 把'contract'泄漏到外部作用域，并为'contract'进行分配
		// 即使实际执行在上面的RunPrecompiled中结束
		addrCopy := addr
		// 初始化一个新的合约并设置EVM将要使用的代码。
		// 该合约仅是本次执行上下文中的一个作用域环境。
		contract := NewContract(caller, AccountRef(addrCopy), new(uint256.Int), gas)
		if witness := evm.StateDB.Witness(); witness != nil {
			witness.AddCode(evm.StateDB.GetCode(addrCopy))
		}
		contract.SetCallCode(&addrCopy, evm.StateDB.GetCodeHash(addrCopy), evm.StateDB.GetCode(addrCopy))
		// 当EVM返回错误或在上面设置创建代码时
		// 我们回滚到快照并消耗任何剩余的gas。此外
		// 在Homestead期间，这也适用于代码存储gas错误。
		ret, err = evm.interpreter.Run(contract, input, true)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			if evm.Config.Tracer != nil && evm.Config.Tracer.OnGasChange != nil {
				evm.Config.Tracer.OnGasChange(gas, 0, tracing.GasChangeCallFailedExecution)
			}

			gas = 0
		}
	}
	return ret, gas, err
}

type codeAndHash struct {
	code []byte
	hash common.Hash
}

func (c *codeAndHash) Hash() common.Hash {
	if c.hash == (common.Hash{}) {
		c.hash = crypto.Keccak256Hash(c.code)
	}
	return c.hash
}

// create使用code作为部署代码创建一个新合约。
func (evm *EVM) create(caller ContractRef, codeAndHash *codeAndHash, gas uint64, value *uint256.Int, address common.Address, typ OpCode) (ret []byte, createAddress common.Address, leftOverGas uint64, err error) {
	if evm.Config.Tracer != nil {
		evm.captureBegin(evm.depth, typ, caller.Address(), address, codeAndHash.code, gas, value.ToBig())
		defer func(startGas uint64) {
			evm.captureEnd(evm.depth, startGas, leftOverGas, ret, err)
		}(gas)
	}
	// Depth check execution. Fail if we're trying to execute above the
	// limit.
	if evm.depth > int(params.CallCreateDepth) {
		return nil, common.Address{}, gas, ErrDepth
	}
	if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, common.Address{}, gas, ErrInsufficientBalance
	}
	nonce := evm.StateDB.GetNonce(caller.Address())
	if nonce+1 < nonce {
		return nil, common.Address{}, gas, ErrNonceUintOverflow
	}
	evm.StateDB.SetNonce(caller.Address(), nonce+1)

	// 我们在快照之前将此添加到访问列表中。即使
	// 创建失败，访问列表更改也不应回滚。
	if evm.chainRules.IsEIP2929 {
		evm.StateDB.AddAddressToAccessList(address)
	}
	// 确保在指定地址没有现有合约。
	// 如果满足以下三个条件之一，则视为存在账户：
	// - nonce非零
	// - 代码非空
	// - 存储非空
	contractHash := evm.StateDB.GetCodeHash(address)
	storageRoot := evm.StateDB.GetStorageRoot(address)
	if evm.StateDB.GetNonce(address) != 0 ||
		(contractHash != (common.Hash{}) && contractHash != types.EmptyCodeHash) || // non-empty code
		(storageRoot != (common.Hash{}) && storageRoot != types.EmptyRootHash) { // non-empty storage
		if evm.Config.Tracer != nil && evm.Config.Tracer.OnGasChange != nil {
			evm.Config.Tracer.OnGasChange(gas, 0, tracing.GasChangeCallFailedExecution)
		}
		return nil, common.Address{}, 0, ErrContractAddressCollision
	}
	// 仅在对象不存在时在状态中创建新账户。 
	// 可能的情况是合约代码部署到一个预先存在的账户，余额非零。
	snapshot := evm.StateDB.Snapshot()
	if !evm.StateDB.Exist(address) {
		evm.StateDB.CreateAccount(address)
	}
	// CreateContract意味着无论账户先前是否存在于状态树中，它现在作为一个合约账户创建。
	// 这在执行initcode之前进行，因为initcode在该账户内部执行。
	evm.StateDB.CreateContract(address)

	if evm.chainRules.IsEIP158 {
		evm.StateDB.SetNonce(address, 1)
	}
	evm.Context.Transfer(evm.StateDB, caller.Address(), address, value)

	// 初始化一个新的合约并设置EVM将要使用的代码。
	// 该合约仅是本次执行上下文中的一个作用域环境。
	contract := NewContract(caller, AccountRef(address), value, gas)
	contract.SetCodeOptionalHash(&address, codeAndHash)
	contract.IsDeployment = true

	// 在verkle模式下为合约创建初始化gas收费
	if evm.chainRules.IsEIP4762 {
		if !contract.UseGas(evm.AccessEvents.ContractCreateInitGas(address, value.Sign() != 0), evm.Config.Tracer, tracing.GasChangeWitnessContractInit) {
			err = ErrOutOfGas
		}
	}

	if err == nil {
		ret, err = evm.interpreter.Run(contract, nil, false)
	}

	// 检查是否超过最大代码大小，如果是则分配错误。
	if err == nil && evm.chainRules.IsEIP158 && len(ret) > params.MaxCodeSize {
		err = ErrMaxCodeSizeExceeded
	}

	// 如果启用了EIP-3541，拒绝以0xEF开头的代码。
	if err == nil && len(ret) >= 1 && ret[0] == 0xEF && evm.chainRules.IsLondon {
		err = ErrInvalidCode
	}

	// 如果合约创建成功并且没有返回错误，
	// 计算存储代码所需的gas。如果由于gas不足无法存储代码
	// 设置错误并让它在下面的错误检查条件下处理。
	if err == nil {
		if !evm.chainRules.IsEIP4762 {
			createDataGas := uint64(len(ret)) * params.CreateDataGas
			if !contract.UseGas(createDataGas, evm.Config.Tracer, tracing.GasChangeCallCodeStorage) {
				err = ErrCodeStoreOutOfGas
			}
		} else {
			// 合约创建完成，触碰合约中缺失的字段
			if !contract.UseGas(evm.AccessEvents.AddAccount(address, true), evm.Config.Tracer, tracing.GasChangeWitnessContractCreation) {
				err = ErrCodeStoreOutOfGas
			}

			if err == nil && len(ret) > 0 && !contract.UseGas(evm.AccessEvents.CodeChunksRangeGas(address, 0, uint64(len(ret)), uint64(len(ret)), true), evm.Config.Tracer, tracing.GasChangeWitnessCodeChunk) {
				err = ErrCodeStoreOutOfGas
			}
		}

		if err == nil {
			evm.StateDB.SetCode(address, ret)
		}
	}

	// 当EVM返回错误或在上面设置创建代码时
	// 我们回滚到快照并消耗任何剩余的gas。此外，
	// 在Homestead期间，这也适用于代码存储gas错误。
	if err != nil && (evm.chainRules.IsHomestead || err != ErrCodeStoreOutOfGas) {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			contract.UseGas(contract.Gas, evm.Config.Tracer, tracing.GasChangeCallFailedExecution)
		}
	}

	return ret, address, contract.Gas, err
}

// Create使用code作为部署代码创建一个新合约
func (evm *EVM) Create(caller ContractRef, code []byte, gas uint64, value *uint256.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	contractAddr = crypto.CreateAddress(caller.Address(), evm.StateDB.GetNonce(caller.Address()))
	return evm.create(caller, &codeAndHash{code: code}, gas, value, contractAddr, CREATE)
}

//  Create2使用code作为部署代码创建一个新合约。
//
// Create2与Create的不同之处在于Create2使用keccak256(0xff ++ msg.sender ++ salt ++ keccak256(init_code))[12:]
// 而不是通常的发送者和nonce哈希作为合约初始化的地址。
func (evm *EVM) Create2(caller ContractRef, code []byte, gas uint64, endowment *uint256.Int, salt *uint256.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	codeAndHash := &codeAndHash{code: code}
	contractAddr = crypto.CreateAddress2(caller.Address(), salt.Bytes32(), codeAndHash.Hash().Bytes())
	return evm.create(caller, codeAndHash, gas, endowment, contractAddr, CREATE2)
}

// ChainConfig返回环境的链配置
func (evm *EVM) ChainConfig() *params.ChainConfig { return evm.chainConfig }

func (evm *EVM) captureBegin(depth int, typ OpCode, from common.Address, to common.Address, input []byte, startGas uint64, value *big.Int) {
	tracer := evm.Config.Tracer
	if tracer.OnEnter != nil {
		tracer.OnEnter(depth, byte(typ), from, to, input, startGas, value)
	}
	if tracer.OnGasChange != nil {
		tracer.OnGasChange(0, startGas, tracing.GasChangeCallInitialBalance)
	}
}

func (evm *EVM) captureEnd(depth int, startGas uint64, leftOverGas uint64, ret []byte, err error) {
	tracer := evm.Config.Tracer
	if leftOverGas != 0 && tracer.OnGasChange != nil {
		tracer.OnGasChange(leftOverGas, 0, tracing.GasChangeCallLeftOverReturned)
	}
	var reverted bool
	if err != nil {
		reverted = true
	}
	if !evm.chainRules.IsHomestead && errors.Is(err, ErrCodeStoreOutOfGas) {
		reverted = false
	}
	if tracer.OnExit != nil {
		tracer.OnExit(depth, ret, startGas-leftOverGas, VMErrorFromErr(err), reverted)
	}
}

// GetVMContext提供有关正在执行的区块以及状态的上下文
// 给tracers。
func (evm *EVM) GetVMContext() *tracing.VMContext {
	return &tracing.VMContext{
		Coinbase:    evm.Context.Coinbase,
		BlockNumber: evm.Context.BlockNumber,
		Time:        evm.Context.Time,
		Random:      evm.Context.Random,
		GasPrice:    evm.TxContext.GasPrice,
		ChainConfig: evm.ChainConfig(),
		StateDB:     evm.StateDB,
	}
}
