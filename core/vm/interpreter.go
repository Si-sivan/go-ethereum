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
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/holiman/uint256"
)

// Config are the configuration options for the Interpreter
type Config struct {
	Tracer                  *tracing.Hooks
	NoBaseFee               bool  // Forces the EIP-1559 baseFee to 0 (needed for 0 price calls)
	EnablePreimageRecording bool  // Enables recording of SHA3/keccak preimages
	ExtraEips               []int // Additional EIPS that are to be enabled
	EnableWitnessCollection bool  // true if witness collection is enabled
}

// ScopeContext contains the things that are per-call, such as stack and memory,
// but not transients like pc and gas
type ScopeContext struct {
	Memory   *Memory
	Stack    *Stack
	Contract *Contract
}

// MemoryData returns the underlying memory slice. Callers must not modify the contents
// of the returned data.
func (ctx *ScopeContext) MemoryData() []byte {
	if ctx.Memory == nil {
		return nil
	}
	return ctx.Memory.Data()
}

// StackData returns the stack data. Callers must not modify the contents
// of the returned data.
func (ctx *ScopeContext) StackData() []uint256.Int {
	if ctx.Stack == nil {
		return nil
	}
	return ctx.Stack.Data()
}

// Caller returns the current caller.
func (ctx *ScopeContext) Caller() common.Address {
	return ctx.Contract.Caller()
}

// Address returns the address where this scope of execution is taking place.
func (ctx *ScopeContext) Address() common.Address {
	return ctx.Contract.Address()
}

// CallValue returns the value supplied with this call.
func (ctx *ScopeContext) CallValue() *uint256.Int {
	return ctx.Contract.Value()
}

// CallInput returns the input/calldata with this call. Callers must not modify
// the contents of the returned data.
func (ctx *ScopeContext) CallInput() []byte {
	return ctx.Contract.Input
}

// EVMInterpreter represents an EVM interpreter
type EVMInterpreter struct {
	evm   *EVM
	table *JumpTable

	hasher    crypto.KeccakState // Keccak256 hasher instance shared across opcodes
	hasherBuf common.Hash        // Keccak256 hasher result array shared across opcodes

	readOnly   bool   // Whether to throw on stateful modifications
	returnData []byte // Last CALL's return data for subsequent reuse
}

// NewEVMInterpreter returns a new instance of the Interpreter.
func NewEVMInterpreter(evm *EVM) *EVMInterpreter {
	// If jump table was not initialised we set the default one.
	var table *JumpTable
	switch {
	case evm.chainRules.IsVerkle:
		// TODO replace with proper instruction set when fork is specified
		table = &verkleInstructionSet
	case evm.chainRules.IsCancun:
		table = &cancunInstructionSet
	case evm.chainRules.IsShanghai:
		table = &shanghaiInstructionSet
	case evm.chainRules.IsMerge:
		table = &mergeInstructionSet
	case evm.chainRules.IsLondon:
		table = &londonInstructionSet
	case evm.chainRules.IsBerlin:
		table = &berlinInstructionSet
	case evm.chainRules.IsIstanbul:
		table = &istanbulInstructionSet
	case evm.chainRules.IsConstantinople:
		table = &constantinopleInstructionSet
	case evm.chainRules.IsByzantium:
		table = &byzantiumInstructionSet
	case evm.chainRules.IsEIP158:
		table = &spuriousDragonInstructionSet
	case evm.chainRules.IsEIP150:
		table = &tangerineWhistleInstructionSet
	case evm.chainRules.IsHomestead:
		table = &homesteadInstructionSet
	default:
		table = &frontierInstructionSet
	}
	var extraEips []int
	if len(evm.Config.ExtraEips) > 0 {
		// Deep-copy jumptable to prevent modification of opcodes in other tables
		table = copyJumpTable(table)
	}
	for _, eip := range evm.Config.ExtraEips {
		if err := EnableEIP(eip, table); err != nil {
			// Disable it, so caller can check if it's activated or not
			log.Error("EIP activation failed", "eip", eip, "error", err)
		} else {
			extraEips = append(extraEips, eip)
		}
	}
	evm.Config.ExtraEips = extraEips
	return &EVMInterpreter{evm: evm, table: table}
}

// Run loops and evaluates the contract's code with the given input data and returns
// the return byte-slice and an error if one occurred.
//
// 需要注意的是，解释器返回的任何错误都应被视为回滚并消耗所以gas的操作，
// 除了ErrExecutionReverted,它意味着回滚并保留剩余的gas
func (in *EVMInterpreter) Run(contract *Contract, input []byte, readOnly bool) (ret []byte, err error) {
	// 增加调用深度，限制为1024
	in.evm.depth++
	defer func() { in.evm.depth-- }()

	// Make sure the readOnly is only set if we aren't in readOnly yet.
	// This also makes sure that the readOnly flag isn't removed for child calls.
	if readOnly && !in.readOnly {
		in.readOnly = true
		defer func() { in.readOnly = false }()
	}

	// Reset the previous call's return data. It's unimportant to preserve the old buffer
	// as every returning call will return new data anyway.
	in.returnData = nil

	// 如果没有代码，就不用执行了
	if len(contract.Code) == 0 {
		return nil, nil
	}

	var (
		op          OpCode        // 当前操作码
		mem         = NewMemory() // 内存
		stack       = newstack()  // 本地堆栈
		callContext = &ScopeContext{
			Memory:   mem,
			Stack:    stack,
			Contract: contract,
		}
		//出于优化原因，我们使用unit64作为程序计数器
		// 理论上有可能超过2^64. YP定义PC为uint256.在实践中这种情况几乎不可能发送
		pc   = uint64(0) //程序计数器
		cost uint64
		// 用于 tracer的副本
		pcCopy  uint64 // 延迟EVMLogger所需
		gasCopy uint64 // EVMLogger记录执行前剩余的gas
		logged  bool   // 延迟EVMLogger 应忽略已记录的步骤
		res     []byte // 操作码执行函数的结果
		debug   = in.evm.Config.Tracer != nil
	)
	// Don't move this deferred function, it's placed before the OnOpcode-deferred method,
	// so that it gets executed _after_: the OnOpcode needs the stacks before
	// they are returned to the pools
	defer func() {
		returnStack(stack)
	}()
	contract.Input = input

	if debug {
		defer func() { // this deferred method handles exit-with-error
			if err == nil {
				return
			}
			if !logged && in.evm.Config.Tracer.OnOpcode != nil {
				in.evm.Config.Tracer.OnOpcode(pcCopy, byte(op), gasCopy, cost, callContext, in.returnData, in.evm.depth, VMErrorFromErr(err))
			}
			if logged && in.evm.Config.Tracer.OnFault != nil {
				in.evm.Config.Tracer.OnFault(pcCopy, byte(op), gasCopy, cost, callContext, in.evm.depth, VMErrorFromErr(err))
			}
		}()
	}
	// 解释器主运行循环（上下文相关）。该循环运行直到执行显式STOP、RETURN或SELFDESTRUCT，
        // 或者执行操作期间发生错误，或者父上下文设置完成标志。
	for {
		if debug {
			// 捕获执行前的值以进行跟踪
			logged, pcCopy, gasCopy = false, pc, contract.Gas
		}

		if in.evm.chainRules.IsEIP4762 && !contract.IsDeployment {
			// if the PC ends up in a new "chunk" of verkleized code, charge the
			// associated costs.
			contractAddr := contract.Address()
			contract.Gas -= in.evm.TxContext.AccessEvents.CodeChunksRangeGas(contractAddr, pc, 1, uint64(len(contract.Code)), false)
		}

		// 从跳转表中获取操作并验证堆栈以确保有足够的堆栈项来执行操作
		op = contract.GetOp(pc)
		operation := in.table[op]
		cost = operation.constantGas // 用于跟踪
		// 验证堆栈
		if sLen := stack.len(); sLen < operation.minStack {
			return nil, &ErrStackUnderflow{stackLen: sLen, required: operation.minStack}
		} else if sLen > operation.maxStack {
			return nil, &ErrStackOverflow{stackLen: sLen, limit: operation.maxStack}
		}
		if !contract.UseGas(cost, in.evm.Config.Tracer, tracing.GasChangeIgnored) {
			return nil, ErrOutOfGas
		}

		if operation.dynamicGas != nil {
			// 所以具有动态内存使用的操作也具有动态gas成本
			var memorySize uint64
			// 计算新的内存大小并扩展内存以适应操作
			// 内存检查需要在评估动态gas部分之前进行，以检测计算溢出
			if operation.memorySize != nil {
				memSize, overflow := operation.memorySize(stack)
				if overflow {
					return nil, ErrGasUintOverflow
				}
				// 内存以32字节的words为单位扩展。
				// Gas也按words计算
				if memorySize, overflow = math.SafeMul(toWordSize(memSize), 32); overflow {
					return nil, ErrGasUintOverflow
				}
			}
			// 消耗gas并在没有足够的gas时返回错误
			// 显式设置成本，以便捕获状态的延迟方法可用获得适当的成本
			var dynamicCost uint64
			dynamicCost, err = operation.dynamicGas(in.evm, contract, stack, mem, memorySize)
			cost += dynamicCost // for tracing
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrOutOfGas, err)
			}
			if !contract.UseGas(dynamicCost, in.evm.Config.Tracer, tracing.GasChangeIgnored) {
				return nil, ErrOutOfGas
			}

			// 在内存扩展之前进行跟踪
			if debug {
				if in.evm.Config.Tracer.OnGasChange != nil {
					in.evm.Config.Tracer.OnGasChange(gasCopy, gasCopy-cost, tracing.GasChangeCallOpCode)
				}
				if in.evm.Config.Tracer.OnOpcode != nil {
					in.evm.Config.Tracer.OnOpcode(pc, byte(op), gasCopy, cost, callContext, in.returnData, in.evm.depth, VMErrorFromErr(err))
					logged = true
				}
			}
			if memorySize > 0 {
				mem.Resize(memorySize)
			}
		} else if debug {
			if in.evm.Config.Tracer.OnGasChange != nil {
				in.evm.Config.Tracer.OnGasChange(gasCopy, gasCopy-cost, tracing.GasChangeCallOpCode)
			}
			if in.evm.Config.Tracer.OnOpcode != nil {
				in.evm.Config.Tracer.OnOpcode(pc, byte(op), gasCopy, cost, callContext, in.returnData, in.evm.depth, VMErrorFromErr(err))
				logged = true
			}
		}

		// 执行操作
		res, err = operation.execute(&pc, in, callContext)
		if err != nil {
			break
		}
		pc++
	}

	if err == errStopToken {
		err = nil // 清除停止标志错误
	}

	return res, err
}
