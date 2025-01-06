Response: My thinking process to summarize the C++ code goes like this:

1. **Understand the Goal:** The request asks for a functional summary of a C++ source file, relating it to JavaScript if applicable, and noting that it's part 6 of 8. The "part 6 of 8" hints that this file likely handles a specific aspect of a larger system.

2. **Identify Key Data Structures and Concepts:**  I quickly scan the code for recurring keywords, macros, and function names. Some initial observations:
    * Lots of `kExpr...`: This strongly suggests the code is dealing with different kinds of expressions or operations. The `wasm` namespace further points towards WebAssembly.
    * `RegMode`, `OperatorMode`:  These enum-like structures hint at managing data flow and instruction processing. "Reg" likely refers to registers.
    * `EMIT_INSTR_HANDLER`, `Emit...`: These macros and functions are clearly involved in generating some kind of output, likely bytecode or instructions.
    * `stack_`, `slots_`: These names suggest a stack-based virtual machine or interpreter.
    * `BlockData`, `eh_data_`:  These suggest handling control flow (blocks) and exception handling.
    * `WasmInterpreter`, `WasmBytecodeGenerator`:  These class names are highly indicative of the file's primary purpose.
    * Mentions of `Isolate`: This ties it to V8's architecture, where isolates are independent JavaScript execution environments.

3. **Infer High-Level Functionality:** Based on the identified keywords, I form a preliminary hypothesis: This file implements part of a WebAssembly interpreter. It seems to be responsible for translating WebAssembly operations into lower-level instructions, potentially bytecode for an internal virtual machine. The register and operator modes suggest optimization or different execution paths.

4. **Focus on the Core Logic (the `switch` statement):** The massive `switch (instr.opcode)` block is the heart of the file. Each `case` handles a different WebAssembly opcode. I look for patterns in how these cases are structured:
    * They often emit instruction handlers (`EMIT_INSTR_HANDLER`).
    * They manipulate the `stack_` and `slots_`.
    * They sometimes emit constants or indices.
    * There's logic for control flow (`kExprBlock`, `kExprIf`, `kExprBr`, etc.) and function calls (`kExprCallFunction`, `kExprCallIndirect`).
    * Memory access opcodes (`kExprI32LoadMem`, `kExprI32StoreMem`) are present.

5. **Refine the Summary:** Based on the core logic, I can now refine the summary:  The file translates WebAssembly opcodes into a lower-level bytecode format for the interpreter. It manages a stack to store intermediate values and uses slots to represent local variables and other data. It handles control flow constructs and function calls.

6. **Address the JavaScript Relationship:** WebAssembly is designed to be a compilation target for languages like C++ and can run in JavaScript environments. The connection lies in how JavaScript engines like V8 implement WebAssembly support. I look for explicit mentions or implied connections:
    * The file is in the `v8/src/wasm/interpreter` directory, indicating it's part of V8.
    * The presence of `Isolate` further strengthens this connection.
    * The concept of a stack-based interpreter is analogous to how JavaScript engines sometimes execute code.
    * I consider how a WebAssembly `i32.add` instruction might be represented and executed in JavaScript (using the `+` operator).

7. **Construct the JavaScript Example:** I choose a simple WebAssembly operation (like `i32.add`, `local.get`, `local.set`) and show how it maps to a conceptually similar JavaScript operation. This helps illustrate the functional relationship.

8. **Incorporate "Part 6 of 8":** This reinforces that the file has a specific role within a larger WebAssembly implementation. It likely focuses on the *interpretation* aspect, as opposed to compilation or other stages.

9. **Review and Refine:** I read through the summary to ensure it's clear, concise, and accurate. I check for any jargon that might need explanation. I make sure the JavaScript example is illustrative and easy to understand. I also ensure I've addressed all parts of the original request.

This iterative process of scanning, identifying patterns, hypothesizing, and refining allows me to arrive at a comprehensive and accurate summary of the C++ code's functionality. The "part 6 of 8" is a crucial piece of context that guides the interpretation towards a specific role within a larger system.


这个C++源代码文件 `wasm-interpreter.cc` 是 V8 JavaScript 引擎中 WebAssembly 解释器的一部分，具体来说，它负责 **将 WebAssembly 的字节码指令翻译成解释器可以执行的操作**。 这是整个解释器实现的核心部分。

**功能归纳:**

1. **WebAssembly 指令解码与分发:**  代码的核心是一个巨大的 `switch` 语句，它根据当前 WebAssembly 指令的操作码 (`instr.opcode`) 来执行相应的处理逻辑。这就像一个指令分发器，将不同的指令引导到对应的处理分支。

2. **模拟 WebAssembly 虚拟机:**  代码维护了 WebAssembly 虚拟机的状态，包括：
   - **栈 (`stack_`)**: 用于存储操作数和中间结果。
   - **局部变量槽 (`slots_`)**:  用于存储函数的局部变量和参数。
   - **控制流块 (`blocks_`)**:  用于处理 `block`, `loop`, `if` 等控制流结构。
   - **异常处理数据 (`eh_data_`)**:  用于处理 `try`, `catch`, `throw` 等异常处理机制。

3. **指令处理逻辑:**  `switch` 语句的每个 `case` 分支都实现了特定 WebAssembly 指令的语义，例如：
   - **算术运算 (`kExprI32Add`, `kExprF64Mul` 等)**: 从栈中弹出操作数，执行运算，并将结果压入栈中。
   - **内存访问 (`kExprI32LoadMem`, `kExprI32StoreMem` 等)**:  计算内存地址，从内存中加载或存储数据。
   - **控制流 (`kExprBlock`, `kExprLoop`, `kExprBr`, `kExprBrIf` 等)**:  管理代码的执行流程，跳转到不同的代码位置。
   - **函数调用 (`kExprCallFunction`, `kExprCallIndirect`, `kExprReturn` 等)**:  处理函数的调用和返回，包括参数传递和返回值处理。
   - **全局变量访问 (`kExprGlobalGet`, `kExprGlobalSet`)**:  读取和写入全局变量。
   - **局部变量访问 (`kExprLocalGet`, `kExprLocalSet`, `kExprLocalTee`)**: 读取和写入局部变量。
   - **类型转换 (`kExprI32ConvertI64`, `kExprF32ReinterpretI32` 等)**:  执行不同数据类型之间的转换。
   - **引用类型操作 (`kExprRefNull`, `kExprRefIsNull`, `kExprRefFunc`, `kExprBrOnNull`, `kExprBrOnNonNull`, `kExprRefCast`, `kExprRefAsNonNull`)**: 处理 WebAssembly 的引用类型。
   - **表操作 (`kExprTableGet`, `kExprTableSet`)**:  访问和修改 WebAssembly 的表。
   - **原子操作 (`kExprAtomic...`)**:  处理多线程环境下的原子操作。
   - **SIMD 操作 (`kExprS128Load`, `kExprV128AddI32x4` 等)**: 处理 SIMD 向量指令。
   - **异常处理 (`kExprTry`, `kExprCatch`, `kExprThrow`, `kExprRethrow`, `kExprDelegate`)**:  实现 WebAssembly 的异常处理机制。

4. **字节码生成 (WasmBytecodeGenerator):** 文件中还包含 `WasmBytecodeGenerator` 类，虽然名字包含 "Generator"，但在这个解释器的上下文中，它实际上是在解释执行的过程中，为了优化或其他目的，可能会生成一些临时的、更低级的字节码。这部分代码负责将 WebAssembly 的高级指令转化为解释器更容易处理的指令序列。 这可以看作是一种“即时”的、针对解释器的优化手段，而不是传统的提前编译。

5. **与 JavaScript 的关系:**  这个文件是 V8 引擎的一部分，V8 负责执行 JavaScript 代码。WebAssembly 是一种可以与 JavaScript 代码一起运行的二进制指令格式。  当 JavaScript 代码调用 WebAssembly 模块时，V8 引擎会使用这个解释器（或其他执行策略，如编译）来执行 WebAssembly 的代码。

**JavaScript 示例:**

假设有一个简单的 WebAssembly 模块，包含一个将两个整数相加的函数：

```wat
(module
  (func $add (param $p1 i32) (param $p2 i32) (result i32)
    local.get $p1
    local.get $p2
    i32.add
  )
  (export "add" (func $add))
)
```

在 JavaScript 中加载并调用这个模块：

```javascript
async function runWasm() {
  const response = await fetch('module.wasm'); // 假设模块保存在 module.wasm 文件中
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.instantiate(buffer);
  const addFunction = module.instance.exports.add;
  const result = addFunction(5, 10);
  console.log(result); // 输出 15
}

runWasm();
```

当执行 `addFunction(5, 10)` 时，V8 引擎会：

1. **识别这是对 WebAssembly 函数的调用。**
2. **如果选择解释执行，`wasm-interpreter.cc` 中的代码将被调用。**
3. **解释器会逐步执行 `add` 函数的 WebAssembly 指令：**
   - `local.get $p1`:  `wasm-interpreter.cc` 中 `kExprLocalGet` 的 `case` 会将参数 `$p1` (值为 5) 从局部变量槽中取出并压入栈。
   - `local.get $p2`:  `kExprLocalGet` 的 `case` 会将参数 `$p2` (值为 10) 从局部变量槽中取出并压入栈。
   - `i32.add`: `wasm-interpreter.cc` 中 `kExprI32Add` 的 `case` 会从栈中弹出 10 和 5，执行整数加法，并将结果 15 压入栈。
4. **函数执行完毕，结果 15 返回到 JavaScript。**

**总结（针对第6部分/共8部分）:**

考虑到这是第6部分，可以推测之前的模块可能负责 WebAssembly 模块的加载、解析、验证等前期工作。 这部分 `wasm-interpreter.cc` 作为核心的执行引擎，负责具体的指令翻译和模拟执行。  后续的模块可能涉及优化、编译或其他运行时支持。  因此，第6部分专注于 **WebAssembly 解释器的核心执行逻辑和状态管理**。

Prompt: 
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第6部分，共8部分，请归纳一下它的功能

"""
 ctype, type, op_ctype, op_type, operation) \
  case kExpr##name: {                                                       \
    MachineType memtype = MachineType::Type();                              \
    MemoryAccessImmediate imm(decoder, code->at(pc + *len),                 \
                              ElementSizeLog2Of(memtype.representation()),  \
                              IsMemory64(), Decoder::kNoValidation);        \
    optional->offset = imm.offset;                                          \
    *len += imm.length;                                                     \
    break;                                                                  \
  }
      FOREACH_ATOMIC_BINOP(ATOMIC_BINOP)
#undef ATOMIC_BINOP

#define ATOMIC_OP(name, Type, ctype, type, op_ctype, op_type)              \
  case kExpr##name: {                                                      \
    MachineType memtype = MachineType::Type();                             \
    MemoryAccessImmediate imm(decoder, code->at(pc + *len),                \
                              ElementSizeLog2Of(memtype.representation()), \
                              IsMemory64(), Decoder::kNoValidation);       \
    optional->offset = imm.offset;                                         \
    *len += imm.length;                                                    \
    break;                                                                 \
  }
      FOREACH_ATOMIC_COMPARE_EXCHANGE_OP(ATOMIC_OP)
      FOREACH_ATOMIC_LOAD_OP(ATOMIC_OP)
      FOREACH_ATOMIC_STORE_OP(ATOMIC_OP)
#undef ATOMIC_OP

    default:
      FATAL("Unknown or unimplemented opcode #%d:%s", code->start[pc],
            WasmOpcodes::OpcodeName(static_cast<WasmOpcode>(code->start[pc])));
      UNREACHABLE();
  }
}

const char* GetRegModeString(RegMode reg_mode) {
  switch (reg_mode) {
    case RegMode::kNoReg:
      return "NoReg";
    case RegMode::kAnyReg:
      return "AnyReg";
    case RegMode::kI32Reg:
      return "I32Reg";
    case RegMode::kI64Reg:
      return "I64Reg";
    case RegMode::kF32Reg:
      return "F32Reg";
    case RegMode::kF64Reg:
      return "F64Reg";
    default:
      UNREACHABLE();
  }
}

const char* GetOperatorModeString(OperatorMode mode) {
  switch (mode) {
    case kR2R:
      return "R2R";
    case kR2S:
      return "R2S";
    case kS2R:
      return "S2R";
    case kS2S:
      return "S2S";
    default:
      UNREACHABLE();
  }
}

#if !defined(V8_DRUMBRAKE_BOUNDS_CHECKS)
INSTRUCTION_HANDLER_FUNC
TrapMemOutOfBounds(const uint8_t* code, uint32_t* sp,
                   WasmInterpreterRuntime* wasm_runtime, int64_t r0,
                   double fp0) {
  TRAP(TrapReason::kTrapMemOutOfBounds)
}
#endif  // !defined(V8_DRUMBRAKE_BOUNDS_CHECKS)

// static
void WasmInterpreter::InitializeOncePerProcess() {
  WasmInterpreterThread::Initialize();
}

// static
void WasmInterpreter::GlobalTearDown() {
  // TODO(paolosev@microsoft.com): Support multithreading.

#ifdef DRUMBRAKE_ENABLE_PROFILING
  PrintAndClearProfilingData();
#endif  // DRUMBRAKE_ENABLE_PROFILING

  WasmInterpreterThread::Terminate();
}

void WasmBytecodeGenerator::InitSlotsForFunctionArgs(const FunctionSig* sig,
                                                     bool is_indirect_call) {
  size_t stack_index;
  if (is_indirect_call) {
    // Subtract one to discard the function index on the top of the stack.
    DCHECK_LE(sig->parameter_count(), stack_.size() - 1);
    stack_index = stack_.size() - sig->parameter_count() - 1;
  } else {
    DCHECK_LE(sig->parameter_count(), stack_.size());
    stack_index = stack_.size() - sig->parameter_count();
  }

  bool fast_path =
      sig->parameter_count() > 1 && !WasmBytecode::HasRefOrSimdArgs(sig);
  if (fast_path) {
    if (sig->parameter_count() == 2) {
      const ValueType type0 = sig->GetParam(0);
      const ValueKind kind0 = type0.kind();
      ValueType type1 = sig->GetParam(1);
      const ValueKind kind1 = type1.kind();
      uint32_t to = CreateSlot(type0);
      CreateSlot(type1);

      uint32_t copyslot32_two_args_func_id =
          ((kind0 == kI64 || kind0 == kF64) ? 0x01 : 0x00) |
          ((kind1 == kI64 || kind1 == kF64) ? 0x02 : 0x00);
      static const InstructionHandler kCopySlot32TwoArgFuncs[4] = {
          k_s2s_CopySlot_ll, k_s2s_CopySlot_lq, k_s2s_CopySlot_ql,
          k_s2s_CopySlot_qq};

      EmitFnId(kCopySlot32TwoArgFuncs[copyslot32_two_args_func_id]);
      EmitI32Const(slots_[to].slot_offset);
      EmitI32Const(slots_[stack_[stack_index]].slot_offset);
      stack_index++;
      EmitI32Const(slots_[stack_[stack_index]].slot_offset);
      stack_index++;
    } else {
      EMIT_INSTR_HANDLER(s2s_CopySlotMulti);
      EmitI32Const(static_cast<uint32_t>(sig->parameter_count()));

      uint32_t to = 0;
      for (size_t index = 0; index < sig->parameter_count(); index++) {
        const ValueType value_type = sig->GetParam(index);
        const ValueKind kind = value_type.kind();
        to = CreateSlot(value_type);
        if (index == 0) {
          EmitI32Const(slots_[to].slot_offset);
        }

        uint32_t flag_64 = 0;
        switch (kind) {
          case kI32:
          case kF32:
            break;
          case kI64:
          case kF64:
            flag_64 = kCopySlotMultiIs64Flag;
            break;
          case kRef:
          case kRefNull:
          default:
            UNREACHABLE();
        }

        EmitI32Const(flag_64 | slots_[stack_[stack_index]].slot_offset);
        stack_index++;
      }
    }
  } else {
    for (size_t index = 0; index < sig->parameter_count(); index++) {
      ValueType value_type = sig->GetParam(index);
      uint32_t to = CreateSlot(value_type);
      EmitCopySlot(value_type, stack_[stack_index], to);
      stack_index++;
    }
  }
}

// static
void WasmInterpreter::NotifyIsolateDisposal(Isolate* isolate) {
  WasmInterpreterThread::NotifyIsolateDisposal(isolate);
}

// Checks if {obj} is a subtype of type, thus checking will always
// succeed.
bool WasmBytecodeGenerator::TypeCheckAlwaysSucceeds(ValueType obj_type,
                                                    HeapType type) const {
  return IsSubtypeOf(obj_type, ValueType::RefNull(type), module_);
}

// Returns true if type checking will always fail, either because the types
// are unrelated or because the target_type is one of the null sentinels and
// conversion to null does not succeed.
bool WasmBytecodeGenerator::TypeCheckAlwaysFails(ValueType obj_type,
                                                 HeapType expected_type,
                                                 bool null_succeeds) const {
  bool types_unrelated =
      !IsSubtypeOf(ValueType::Ref(expected_type), obj_type, module_) &&
      !IsSubtypeOf(obj_type, ValueType::RefNull(expected_type), module_);
  // (Comment copied from function-body-decoder-impl.h).
  // For "unrelated" types the check can still succeed for the null value on
  // instructions treating null as a successful check.
  // TODO(12868): For string views, this implementation anticipates that
  // https://github.com/WebAssembly/stringref/issues/40 will be resolved
  // by making the views standalone types.
  return (types_unrelated &&
          (!null_succeeds || !obj_type.is_nullable() ||
           obj_type.is_string_view() || expected_type.is_string_view())) ||
         (!null_succeeds &&
          (expected_type.representation() == HeapType::kNone ||
           expected_type.representation() == HeapType::kNoFunc ||
           expected_type.representation() == HeapType::kNoExtern));
}

RegMode WasmBytecodeGenerator::EncodeInstruction(const WasmInstruction& instr,
                                                 RegMode curr_reg_mode,
                                                 RegMode next_reg_mode) {
  DCHECK(curr_reg_mode != RegMode::kAnyReg);

#ifdef DEBUG
  was_current_instruction_reachable_ = is_instruction_reachable_;
#endif  // DEBUG
  if (!is_instruction_reachable_) {
    if (instr.opcode == kExprBlock || instr.opcode == kExprLoop ||
        instr.opcode == kExprIf || instr.opcode == kExprTry) {
      unreachable_block_count_++;
    } else if (instr.opcode == kExprEnd || instr.opcode == kExprDelegate) {
      DCHECK_GT(unreachable_block_count_, 0);
      if (0 == --unreachable_block_count_) {
        is_instruction_reachable_ = true;
      }
    } else if (instr.opcode == kExprElse || instr.opcode == kExprCatch ||
               instr.opcode == kExprCatchAll) {
      if (1 == unreachable_block_count_) {
        is_instruction_reachable_ = true;
        unreachable_block_count_ = 0;
      }
    }
  }
  if (!is_instruction_reachable_) return RegMode::kNoReg;

  ValueKind top_stack_slot_type = GetTopStackType(curr_reg_mode);

  OperatorMode mode = kS2S;
  if (v8_flags.drumbrake_register_optimization) {
    switch (next_reg_mode) {
      case RegMode::kNoReg:
        if (curr_reg_mode != RegMode::kNoReg) {
          mode = kR2S;
        }
        break;
      case RegMode::kAnyReg:
      default:  // kI32Reg|kI64Reg|kF32Reg|kF64Reg
        if (curr_reg_mode == RegMode::kNoReg) {
          if (ToRegisterIsAllowed(instr)) {
            mode = kS2R;
          } else {
            mode = kS2S;
          }
        } else {
          if (ToRegisterIsAllowed(instr)) {
            mode = kR2R;
          } else {
            mode = kR2S;
          }
        }
        break;
    }
  }

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_bytecode_generator) {
    printf("PRE   @%-3u:         %-24s: %3s %-7s -> %-7s\n", instr.pc,
           wasm::WasmOpcodes::OpcodeName(static_cast<WasmOpcode>(instr.opcode)),
           GetOperatorModeString(mode), GetRegModeString(curr_reg_mode),
           GetRegModeString(next_reg_mode));
  }

  if (v8_flags.trace_drumbrake_execution) {
    EMIT_INSTR_HANDLER(s2s_TraceInstruction);
    EmitI32Const(instr.pc);
    EmitI32Const(instr.opcode);
    EmitI32Const(static_cast<int>(curr_reg_mode));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  switch (instr.opcode) {
    case kExprUnreachable: {
      EMIT_INSTR_HANDLER_WITH_PC(s2s_Unreachable, instr.pc);
      SetUnreachableMode();
      break;
    }
    case kExprNop:
      break;
    case kExprBlock:
    case kExprLoop: {
      PreserveArgsAndLocals();
      BeginBlock(instr.opcode, instr.optional.block);
      break;
    }
    case kExprTry: {
      PreserveArgsAndLocals();
      int parent_or_matching_try_block_index = GetCurrentTryBlockIndex(true);
      int ancestor_try_block_index = GetCurrentTryBlockIndex(false);
      int try_block_index = BeginBlock(instr.opcode, instr.optional.block);
      eh_data_.AddTryBlock(try_block_index, parent_or_matching_try_block_index,
                           ancestor_try_block_index);
      break;
    }
    case kExprIf: {
      PreserveArgsAndLocals();
      if (mode == kR2S) {
        EMIT_INSTR_HANDLER(r2s_If);
      } else {
        DCHECK_EQ(mode, kS2S);
        EMIT_INSTR_HANDLER(s2s_If);
        I32Pop();  // cond
      }
      BeginBlock(instr.opcode, instr.optional.block);
      EmitIfElseBranchOffset();
      break;
    }
    case kExprElse: {
      DCHECK_GT(current_block_index_, 0);
      DCHECK(blocks_[current_block_index_].IsIf());
      BeginElseBlock(current_block_index_, false);
      EMIT_INSTR_HANDLER(s2s_Else);
      EmitIfElseBranchOffset();  // Jumps to the end of the 'else' block.
      break;
    }
    case kExprCatch:
    case kExprCatchAll: {
      DCHECK_GT(current_block_index_, 0);

      int try_block_index = eh_data_.GetCurrentTryBlockIndex();
      DCHECK_GT(try_block_index, 0);

      EndBlock(instr.opcode);  // End previous try or catch.

      stack_.resize(blocks_[try_block_index].stack_size_);
      int32_t catch_block_index =
          BeginBlock(instr.opcode, blocks_[try_block_index].signature_);

      EMIT_INSTR_HANDLER(s2s_Catch);
      EmitTryCatchBranchOffset();  // Jumps to the end of the try/catch blocks.

      uint32_t first_param_slot_index = UINT_MAX;
      uint32_t first_ref_param_slot_index = UINT_MAX;
      if (instr.opcode == kExprCatch) {
        // Exception arguments are pushed into the stack.
        const WasmTag& tag = module_->tags[instr.optional.index];
        const FunctionSig* sig = tag.sig;
        for (size_t i = 0; i < sig->parameter_count(); ++i) {
          const ValueType value_type = sig->GetParam(i);
          const ValueKind kind = value_type.kind();
          switch (kind) {
            case kI32:
            case kI64:
            case kF32:
            case kF64:
            case kS128:
            case kRef:
            case kRefNull: {
              uint32_t slot_index = CreateSlot(value_type);
              if (first_param_slot_index == UINT_MAX) {
                first_param_slot_index = slot_index;
              }
              if ((kind == kRefNull || kind == kRef) &&
                  first_ref_param_slot_index == UINT_MAX) {
                first_ref_param_slot_index = slot_index;
              }
              PushSlot(slot_index);
              slots_[slot_index].value_type = value_type;
              break;
            }
            default:
              UNREACHABLE();
          }
        }
      }

      blocks_[catch_block_index].first_block_index_ =
          blocks_[try_block_index].first_block_index_;

      if (instr.opcode == kExprCatch) {
        eh_data_.AddCatchBlock(
            current_block_index_, instr.optional.index,
            first_param_slot_index == UINT_MAX
                ? 0
                : slots_[first_param_slot_index].slot_offset,
            first_ref_param_slot_index == UINT_MAX
                ? 0
                : slots_[first_ref_param_slot_index].ref_stack_index,
            static_cast<int>(code_.size()));
      } else {  // kExprCatchAll
        eh_data_.AddCatchBlock(current_block_index_,
                               WasmEHData::kCatchAllTagIndex, 0, 0,
                               static_cast<int>(code_.size()));
      }

      break;
    }
    case kExprDelegate: {
      int32_t target_block_index = GetTargetBranch(instr.optional.depth + 1);
      DCHECK_LT(target_block_index, blocks_.size());
      int32_t delegated_try_block_index = WasmEHData::kDelegateToCallerIndex;
      if (target_block_index > 0) {
        const BlockData& target_block = blocks_[target_block_index];
        delegated_try_block_index = target_block.IsTry()
                                        ? target_block_index
                                        : target_block.parent_try_block_index_;
      }
      eh_data_.AddDelegatedBlock(delegated_try_block_index);
      EndBlock(kExprDelegate);
      break;
    }
    case kExprThrow: {
      EMIT_INSTR_HANDLER(s2s_Throw);
      EmitI32Const(instr.optional.index);

      // Exception arguments are popped from the stack (in reverse order!)
      const WasmTag& tag = module_->tags[instr.optional.index];
      const WasmTagSig* sig = tag.sig;
      DCHECK_GE(stack_.size(), sig->parameter_count());
      size_t stack_index = stack_.size() - sig->parameter_count();
      for (size_t index = 0; index < sig->parameter_count();
           index++, stack_index++) {
        ValueKind kind = sig->GetParam(index).kind();
        DCHECK(CheckEqualKind(kind, slots_[stack_[stack_index]].kind()));
        switch (kind) {
          case kI32:
          case kI64:
          case kF32:
          case kF64:
          case kS128: {
            uint32_t slot_offset = slots_[stack_[stack_index]].slot_offset;
            Emit(&slot_offset, sizeof(uint32_t));
            break;
          }
          case kRef:
          case kRefNull: {
            uint32_t ref_index = slots_[stack_[stack_index]].ref_stack_index;
            Emit(&ref_index, sizeof(uint32_t));
            break;
          }
          default:
            UNREACHABLE();
        }
      }

      stack_.resize(stack_.size() - sig->parameter_count());
      eh_data_.RecordPotentialExceptionThrowingInstruction(instr.opcode,
                                                           CurrentCodePos());
      SetUnreachableMode();
      break;
    }
    case kExprRethrow: {
      EMIT_INSTR_HANDLER(s2s_Rethrow);
      int32_t target_branch_index = GetTargetBranch(instr.optional.depth);
      DCHECK(blocks_[target_branch_index].IsCatch() ||
             blocks_[target_branch_index].IsCatchAll());
      Emit(&target_branch_index, sizeof(int32_t));
      eh_data_.RecordPotentialExceptionThrowingInstruction(instr.opcode,
                                                           CurrentCodePos());
      SetUnreachableMode();
      break;
    }
    case kExprEnd: {
      // If there is an 'if...end' statement without an 'else' branch, create
      // a dummy else branch used to store results.
      if (blocks_[current_block_index_].IsIf()) {
        uint32_t if_block_index = current_block_index_;
        DCHECK(!blocks_[if_block_index].HasElseBranch());
        uint32_t params_count = ParamsCount(blocks_[if_block_index]);
        if (params_count > 0) {
          BeginElseBlock(if_block_index, true);
          EMIT_INSTR_HANDLER(s2s_Else);
          EmitIfElseBranchOffset();  // Jumps to the end of the 'else' block.
        }
      }

      if (EndBlock(kExprEnd) < 0) {
        Return();
      }
      break;
    }
    case kExprBr: {
      int32_t target_branch_index = GetTargetBranch(instr.optional.depth);
      StoreBlockParamsAndResultsIntoSlots(target_branch_index, kExprBr);

      EMIT_INSTR_HANDLER(s2s_Branch);
      EmitBranchOffset(instr.optional.depth);
      SetUnreachableMode();
      break;
    }
    case kExprBrIf: {
      int32_t target_branch_index = GetTargetBranch(instr.optional.depth);
      const WasmBytecodeGenerator::BlockData& target_block_data =
          blocks_[target_branch_index];
      if (HasVoidSignature(target_block_data)) {
        if (mode == kR2S) {
          EMIT_INSTR_HANDLER(r2s_BranchIf);
        } else {
          DCHECK_EQ(mode, kS2S);
          EMIT_INSTR_HANDLER(s2s_BranchIf);
          I32Pop();  // condition
        }
        // Emit code offset to branch to if the condition is true.
        EmitBranchOffset(instr.optional.depth);
      } else {
        if (mode == kR2S) {
          EMIT_INSTR_HANDLER(r2s_BranchIfWithParams);
        } else {
          DCHECK_EQ(mode, kS2S);
          EMIT_INSTR_HANDLER(s2s_BranchIfWithParams);
          I32Pop();  // condition
        }

        // Emit code offset to branch to if the condition is not true.
        const uint32_t if_false_code_offset = CurrentCodePos();
        Emit(&if_false_code_offset, sizeof(if_false_code_offset));

        StoreBlockParamsAndResultsIntoSlots(target_branch_index, kExprBrIf);

        EMIT_INSTR_HANDLER(s2s_Branch);
        EmitBranchOffset(instr.optional.depth);

        // Patch the 'if-false' offset with the correct jump offset.
        int32_t delta = CurrentCodePos() - if_false_code_offset;
        base::WriteUnalignedValue<uint32_t>(
            reinterpret_cast<Address>(code_.data() + if_false_code_offset),
            delta);
      }
      break;
    }
    case kExprBrOnNull: {
      DCHECK_EQ(mode, kS2S);
      int32_t target_branch_index = GetTargetBranch(instr.optional.depth);
      const WasmBytecodeGenerator::BlockData& target_block_data =
          blocks_[target_branch_index];
      if (HasVoidSignature(target_block_data)) {
        EMIT_INSTR_HANDLER(s2s_BranchOnNull);
        ValueType value_type = RefPop();  // pop condition
        EmitI32Const(value_type.raw_bit_field());
        // Remove nullability.
        if (value_type.kind() == kRefNull) {
          value_type = ValueType::Ref(value_type.heap_type());
        }
        RefPush(value_type);  // re-push condition value
        // Emit code offset to branch to if the condition is true.
        EmitBranchOffset(instr.optional.depth);
      } else {
        EMIT_INSTR_HANDLER(s2s_BranchOnNullWithParams);
        ValueType value_type = RefPop();  // pop condition
        EmitI32Const(value_type.raw_bit_field());
        // Remove nullability.
        if (value_type.kind() == kRefNull) {
          value_type = ValueType::Ref(value_type.heap_type());
        }
        RefPush(value_type);  // re-push condition value

        // Emit code offset to branch to if the condition is not true.
        const uint32_t if_false_code_offset = CurrentCodePos();
        Emit(&if_false_code_offset, sizeof(if_false_code_offset));

        uint32_t stack_top = stack_.back();
        RefPop(false);  // Drop the null reference.

        StoreBlockParamsAndResultsIntoSlots(target_branch_index, kExprBrIf);

        EMIT_INSTR_HANDLER(s2s_Branch);
        EmitBranchOffset(instr.optional.depth);

        stack_.push_back(stack_top);  // re-push non-null ref on top of stack

        // Patch the 'if-false' offset with the correct jump offset.
        int32_t delta = CurrentCodePos() - if_false_code_offset;
        base::WriteUnalignedValue<uint32_t>(
            reinterpret_cast<Address>(code_.data() + if_false_code_offset),
            delta);
      }
      break;
    }
    case kExprBrOnNonNull: {
      DCHECK_EQ(mode, kS2S);
      int32_t target_branch_index = GetTargetBranch(instr.optional.depth);
      const WasmBytecodeGenerator::BlockData& target_block_data =
          blocks_[target_branch_index];
      if (HasVoidSignature(target_block_data)) {
        EMIT_INSTR_HANDLER(s2s_BranchOnNonNull);
        ValueType value_type = RefPop();  // pop condition
        EmitI32Const(value_type.raw_bit_field());
        RefPush(value_type);  // re-push condition value
        // Emit code offset to branch to if the condition is true.
        EmitBranchOffset(instr.optional.depth);
      } else {
        EMIT_INSTR_HANDLER(s2s_BranchOnNonNullWithParams);
        ValueType value_type = RefPop();  // pop condition
        EmitI32Const(value_type.raw_bit_field());
        RefPush(value_type);  // re-push condition value

        // Emit code offset to branch to if the condition is not true.
        const uint32_t if_false_code_offset = CurrentCodePos();
        Emit(&if_false_code_offset, sizeof(if_false_code_offset));

        StoreBlockParamsAndResultsIntoSlots(target_branch_index, kExprBrIf);

        EMIT_INSTR_HANDLER(s2s_Branch);
        EmitBranchOffset(instr.optional.depth);

        // Patch the 'if-false' offset with the correct jump offset.
        int32_t delta = CurrentCodePos() - if_false_code_offset;
        base::WriteUnalignedValue<uint32_t>(
            reinterpret_cast<Address>(code_.data() + if_false_code_offset),
            delta);

        RefPop(false);  // Drop the null reference.
      }
      break;
    }
    case kExprBrOnCast: {
      const BranchOnCastData& br_on_cast_data = instr.optional.br_on_cast_data;
      const int32_t target_branch_index =
          GetTargetBranch(br_on_cast_data.label_depth);
      bool null_succeeds = br_on_cast_data.res_is_null;
      const ValueType target_type =
          ValueType::RefMaybeNull(br_on_cast_data.target_type,
                                  null_succeeds ? kNullable : kNonNullable);

      const ValueType obj_type = slots_[stack_.back()].value_type;
      DCHECK(obj_type.is_object_reference());

      // This logic ensures that code generation can assume that functions can
      // only be cast to function types, and data objects to data types.
      if (V8_UNLIKELY(
              TypeCheckAlwaysSucceeds(obj_type, target_type.heap_type()))) {
        StoreBlockParamsAndResultsIntoSlots(target_branch_index, kExprBrOnCast);
        // The branch will still not be taken on null if not {null_succeeds}.
        if (obj_type.is_nullable() && !null_succeeds) {
          EMIT_INSTR_HANDLER(s2s_BranchOnNull);
          RefPop();  // pop condition
          EmitI32Const(obj_type.raw_bit_field());
          RefPush(target_type);  // re-push condition value with a new HeapType.
          EmitBranchOffset(br_on_cast_data.label_depth);
        } else {
          EMIT_INSTR_HANDLER(s2s_Branch);
          EmitBranchOffset(br_on_cast_data.label_depth);
        }
      } else if (V8_LIKELY(!TypeCheckAlwaysFails(
                     obj_type, target_type.heap_type(), null_succeeds))) {
        EMIT_INSTR_HANDLER(s2s_BranchOnCast);
        EmitI32Const(null_succeeds);
        HeapType br_on_cast_data_target_type(br_on_cast_data.target_type);
        EmitI32Const(br_on_cast_data_target_type.is_index()
                         ? br_on_cast_data_target_type.representation()
                         : target_type.heap_type().representation());
        ValueType value_type = RefPop();
        EmitI32Const(value_type.raw_bit_field());
        RefPush(value_type);
        // Emit code offset to branch to if the condition is not true.
        const uint32_t no_branch_code_offset = CurrentCodePos();
        Emit(&no_branch_code_offset, sizeof(no_branch_code_offset));
        StoreBlockParamsAndResultsIntoSlots(target_branch_index, kExprBrOnCast);
        EMIT_INSTR_HANDLER(s2s_Branch);
        EmitBranchOffset(br_on_cast_data.label_depth);
        // Patch the 'if-false' offset with the correct jump offset.
        int32_t delta = CurrentCodePos() - no_branch_code_offset;
        base::WriteUnalignedValue<uint32_t>(
            reinterpret_cast<Address>(code_.data() + no_branch_code_offset),
            delta);
      }
      break;
    }
    case kExprBrOnCastFail: {
      const BranchOnCastData& br_on_cast_data = instr.optional.br_on_cast_data;
      int32_t target_branch_index =
          GetTargetBranch(br_on_cast_data.label_depth);
      bool null_succeeds = br_on_cast_data.res_is_null;
      HeapType br_on_cast_data_target_type(br_on_cast_data.target_type);
      const ValueType target_type =
          ValueType::RefMaybeNull(br_on_cast_data_target_type,
                                  null_succeeds ? kNullable : kNonNullable);

      const ValueType obj_type = slots_[stack_.back()].value_type;
      DCHECK(obj_type.is_object_reference());

      // This logic ensures that code generation can assume that functions can
      // only be cast to function types, and data objects to data types.
      if (V8_UNLIKELY(TypeCheckAlwaysFails(obj_type, target_type.heap_type(),
                                           null_succeeds))) {
        StoreBlockParamsAndResultsIntoSlots(target_branch_index, kExprBrOnCast);
        EMIT_INSTR_HANDLER(s2s_Branch);
        EmitBranchOffset(br_on_cast_data.label_depth);
      } else if (V8_UNLIKELY(TypeCheckAlwaysSucceeds(
                     obj_type, target_type.heap_type()))) {
        // The branch can still be taken on null.
        if (obj_type.is_nullable() && !null_succeeds) {
          StoreBlockParamsAndResultsIntoSlots(target_branch_index,
                                              kExprBrOnCast);
          EMIT_INSTR_HANDLER(s2s_BranchOnNull);
          RefPop();  // pop condition
          EmitI32Const(obj_type.raw_bit_field());
          RefPush(target_type);  // re-push condition value with a new HeapType.
          EmitBranchOffset(br_on_cast_data.label_depth);
        } else {
          // Fallthrough.
        }
      } else {
        EMIT_INSTR_HANDLER(s2s_BranchOnCastFail);
        EmitI32Const(null_succeeds);
        EmitI32Const(br_on_cast_data_target_type.is_index()
                         ? br_on_cast_data_target_type.representation()
                         : target_type.heap_type().representation());
        ValueType value_type = RefPop();
        EmitI32Const(value_type.raw_bit_field());
        RefPush(value_type);
        // Emit code offset to branch to if the condition is not true.
        const uint32_t no_branch_code_offset = CurrentCodePos();
        Emit(&no_branch_code_offset, sizeof(no_branch_code_offset));
        StoreBlockParamsAndResultsIntoSlots(target_branch_index, kExprBrOnCast);
        EMIT_INSTR_HANDLER(s2s_Branch);
        EmitBranchOffset(br_on_cast_data.label_depth);
        // Patch the 'if-false' offset with the correct jump offset.
        int32_t delta = CurrentCodePos() - no_branch_code_offset;
        base::WriteUnalignedValue<uint32_t>(
            reinterpret_cast<Address>(code_.data() + no_branch_code_offset),
            delta);
      }
      break;
    }
    case kExprBrTable: {
      if (mode == kR2S) {
        EMIT_INSTR_HANDLER(r2s_BrTable);
      } else {
        DCHECK_EQ(mode, kS2S);
        EMIT_INSTR_HANDLER(s2s_BrTable);
        I32Pop();  // branch label
      }

      // We emit the following bytecode for a br_table instruction:
      // s2s_BrTable handler id
      // (uint32) labels_count
      // (uint32) offset branch 0
      // (uint32) offset branch 1
      // ...
      // (uint32) offset branch labels_count - 1
      // (uint32) offset branch labels_count (default branch)
      // { Branch 0 slots }
      // { Branch 1 slots }
      // ...
      // { Branch labels_count slots }
      //
      // Where each {Branch i slots} contains the slots to execute a Branch
      // instruction:
      // { CopySlots for branch results, if present }
      // s2s_Branch handler id
      // (uint32) branch_offset (to be patched later)
      //
      const uint32_t labels_count = instr.optional.br_table.table_count;
      EmitI32Const(labels_count);
      uint32_t labels_offset_start = CurrentCodePos();
      for (uint32_t i = 0; i <= labels_count; i++) {
        // Here we don't know what will be the offset of this branch yet, so we
        // pass the current bytecode position as offset. This value will be
        // overwritten in the next loop.
        const uint32_t label_offset = CurrentCodePos();
        Emit(&label_offset, sizeof(label_offset));
      }
      for (uint32_t i = 0; i <= labels_count; i++) {
        uint32_t label =
            br_table_labels_[instr.optional.br_table.labels_index + i];
        int32_t target_branch_index = GetTargetBranch(label);
        uint32_t branch_code_start = CurrentCodePos();
        StoreBlockParamsAndResultsIntoSlots(target_branch_index, kExprBrTable);

        EMIT_INSTR_HANDLER(s2s_Branch);
        EmitBranchTableOffset(label, CurrentCodePos());

        // Patch the branch offset with the correct jump offset.
        uint32_t label_offset = labels_offset_start + i * sizeof(uint32_t);
        int32_t delta = branch_code_start - label_offset;
        base::WriteUnalignedValue<uint32_t>(
            reinterpret_cast<Address>(code_.data() + label_offset), delta);
      }
      SetUnreachableMode();
      break;
    }
    case kExprReturn: {
      Return();
      SetUnreachableMode();
      break;
    }
    case kExprCallFunction:
    case kExprReturnCall: {
      uint32_t function_index = instr.optional.index;
      const FunctionSig* sig = GetFunctionSignature(function_index);

      // Layout of a frame:
      // ------------------
      // stack slot #N-1 ‾\
      // ...              |
      // stack slot #0   _/
      // local #L-1      ‾\
      // ...              |
      // local #0        _/
      // const #C-1      ‾\
      // ...              |
      // const #0        _/
      // param #P-1      ‾\
      // ...              |
      // param #0        _/
      // return #R-1     ‾\
      // ...              |
      // return #0       _/
      // ------------------

      const bool is_imported = (module_->functions[function_index].imported);
      const bool is_tail_call = (instr.opcode == kExprReturnCall);
      uint32_t slot_offset = GetStackFrameSize() * kSlotSize;
      uint32_t ref_stack_fp_offset = ref_slots_count_;

      std::vector<uint32_t> rets_slots;
      rets_slots.resize(sig->return_count());
      for (size_t index = 0; index < sig->return_count(); index++) {
        rets_slots[index] = is_tail_call ? static_cast<uint32_t>(index)
                                         : CreateSlot(sig->GetReturn(index));
      }

      InitSlotsForFunctionArgs(sig, false);

      if (is_imported) {
        if (is_tail_call) {
          EMIT_INSTR_HANDLER_WITH_PC(s2s_ReturnCallImportedFunction, instr.pc);
          EmitI32Const(WasmBytecode::RetsSizeInSlots(sig) * kSlotSize);
          EmitI32Const(WasmBytecode::ArgsSizeInSlots(sig) * kSlotSize);
          EmitI32Const(WasmBytecode::RefRetsCount(sig));
          EmitI32Const(WasmBytecode::RefArgsCount(sig));
        } else {
          EMIT_INSTR_HANDLER_WITH_PC(s2s_CallImportedFunction, instr.pc);
        }
      } else {
        if (is_tail_call) {
          EMIT_INSTR_HANDLER_WITH_PC(s2s_ReturnCall, instr.pc);
          EmitI32Const(WasmBytecode::RetsSizeInSlots(sig) * kSlotSize);
          EmitI32Const(WasmBytecode::ArgsSizeInSlots(sig) * kSlotSize);
          EmitI32Const(WasmBytecode::RefRetsCount(sig));
          EmitI32Const(WasmBytecode::RefArgsCount(sig));
        } else {
          EMIT_INSTR_HANDLER_WITH_PC(s2s_CallFunction, instr.pc);
        }
      }
      EmitI32Const(function_index);
      EmitI32Const(static_cast<uint32_t>(stack_.size()));
      EmitI32Const(slot_offset);
      EmitI32Const(ref_stack_fp_offset);

      // Function arguments are popped from the stack.
      for (size_t index = sig->parameter_count(); index > 0; index--) {
        Pop(sig->GetParam(index - 1).kind(), false);
      }

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
      if (v8_flags.trace_drumbrake_execution) {
        EmitI32Const(rets_slots.empty()
                         ? 0
                         : slots_[rets_slots[0]].slot_offset * kSlotSize);
      }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

      if (!is_tail_call) {
        eh_data_.RecordPotentialExceptionThrowingInstruction(instr.opcode,
                                                             CurrentCodePos());
      }

      // Function results are pushed to the stack.
      for (size_t index = 0; index < sig->return_count(); index++) {
        const ValueType value_type = sig->GetReturn(index);
        const ValueKind kind = value_type.kind();
        switch (kind) {
          case kI32:
          case kI64:
          case kF32:
          case kF64:
          case kS128:
          case kRef:
          case kRefNull:
            PushSlot(rets_slots[index]);
            SetSlotType(stack_top_index(), value_type);
            break;
          default:
            UNREACHABLE();
        }
      }

      // If this is a tail call, the following instructions in this block are
      // unreachable.
      if (is_tail_call) {
        SetUnreachableMode();
      }

      return RegMode::kNoReg;
    }
    case kExprCallIndirect:
    case kExprReturnCallIndirect: {
      const FunctionSig* sig =
          module_->signature(instr.optional.indirect_call.sig_index);

      const bool is_tail_call = (instr.opcode == kExprReturnCallIndirect);
      uint32_t slot_offset = GetStackFrameSize() * kSlotSize;
      uint32_t ref_stack_fp_offset = ref_slots_count_;

      // Reserve space for return values.
      std::vector<uint32_t> rets_slots;
      rets_slots.resize(sig->return_count());
      for (size_t index = 0; index < sig->return_count(); index++) {
        rets_slots[index] = is_tail_call ? static_cast<uint32_t>(index)
                                         : CreateSlot(sig->GetReturn(index));
      }

      InitSlotsForFunctionArgs(sig, true);

      if (is_tail_call) {
        EMIT_INSTR_HANDLER_WITH_PC(s2s_ReturnCallIndirect, instr.pc);
        EmitI32Const(WasmBytecode::RetsSizeInSlots(sig) * kSlotSize);
        EmitI32Const(WasmBytecode::ArgsSizeInSlots(sig) * kSlotSize);
        EmitI32Const(WasmBytecode::RefRetsCount(sig));
        EmitI32Const(WasmBytecode::RefArgsCount(sig));
      } else {
        EMIT_INSTR_HANDLER_WITH_PC(s2s_CallIndirect, instr.pc);
      }

      // Pops the index of the function to call.
      I32Pop();

      EmitI32Const(instr.optional.indirect_call.table_index);
      EmitI32Const(instr.optional.indirect_call.sig_index);

      EmitI32Const(stack_size());
      EmitI32Const(slot_offset);
      EmitI32Const(ref_stack_fp_offset);

      // Function arguments are popped from the stack.
      for (size_t index = sig->parameter_count(); index > 0; index--) {
        Pop(sig->GetParam(index - 1).kind(), false);
      }

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
      if (v8_flags.trace_drumbrake_execution) {
        EmitI32Const(rets_slots.empty()
                         ? 0
                         : slots_[rets_slots[0]].slot_offset * kSlotSize);
      }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

      if (!is_tail_call) {
        eh_data_.RecordPotentialExceptionThrowingInstruction(instr.opcode,
                                                             CurrentCodePos());
      }

      // Function result is pushed to the stack.
      for (size_t index = 0; index < sig->return_count(); index++) {
        ValueType value_type = sig->GetReturn(index);
        switch (value_type.kind()) {
          case kI32:
          case kI64:
          case kF32:
          case kF64:
          case kS128:
          case kRef:
          case kRefNull:
            PushSlot(rets_slots[index]);
            SetSlotType(stack_top_index(), value_type);
            break;
          default:
            UNREACHABLE();
        }
      }

      // If this is a tail call, the following instructions in this block are
      // unreachable.
      if (is_tail_call) {
        SetUnreachableMode();
      }

      return RegMode::kNoReg;
    }

    case kExprCallRef:
    case kExprReturnCallRef: {
      const FunctionSig* sig = module_->signature(instr.optional.index);
      const bool is_tail_call = (instr.opcode == kExprReturnCallRef);
      uint32_t slot_offset = GetStackFrameSize() * kSlotSize;
      uint32_t ref_stack_fp_offset = ref_slots_count_;

      // Reserve space for return values.
      std::vector<uint32_t> rets_slots;
      rets_slots.resize(sig->return_count());
      for (size_t index = 0; index < sig->return_count(); index++) {
        rets_slots[index] = is_tail_call ? static_cast<uint32_t>(index)
                                         : CreateSlot(sig->GetReturn(index));
      }

      InitSlotsForFunctionArgs(sig, true);

      if (is_tail_call) {
        EMIT_INSTR_HANDLER_WITH_PC(s2s_ReturnCallRef, instr.pc);
        EmitI32Const(WasmBytecode::RetsSizeInSlots(sig) * kSlotSize);
        EmitI32Const(WasmBytecode::ArgsSizeInSlots(sig) * kSlotSize);
        EmitI32Const(WasmBytecode::RefRetsCount(sig));
        EmitI32Const(WasmBytecode::RefArgsCount(sig));
      } else {
        EMIT_INSTR_HANDLER_WITH_PC(s2s_CallRef, instr.pc);
      }

      // Pops the function to call.
      RefPop();

      EmitI32Const(instr.optional.index);  // Signature index.
      EmitI32Const(stack_size());
      EmitI32Const(slot_offset);
      EmitI32Const(ref_stack_fp_offset);

      // Function arguments are popped from the stack.
      for (size_t index = sig->parameter_count(); index > 0; index--) {
        Pop(sig->GetParam(index - 1).kind(), false);
      }

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
      if (v8_flags.trace_drumbrake_execution) {
        EmitI32Const(rets_slots.empty()
                         ? 0
                         : slots_[rets_slots[0]].slot_offset * kSlotSize);
      }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

      if (!is_tail_call) {
        eh_data_.RecordPotentialExceptionThrowingInstruction(instr.opcode,
                                                             CurrentCodePos());
      }

      // Function result is pushed to the stack.
      for (size_t index = 0; index < sig->return_count(); index++) {
        const ValueType value_type = sig->GetReturn(index);
        const ValueKind kind = value_type.kind();
        switch (kind) {
          case kI32:
          case kI64:
          case kF32:
          case kF64:
          case kS128:
          case kRef:
          case kRefNull:
            PushSlot(rets_slots[index]);
            SetSlotType(stack_top_index(), value_type);
            break;
          default:
            UNREACHABLE();
        }
      }

      // If this is a tail call, the following instructions in this block are
      // unreachable.
      if (is_tail_call) {
        SetUnreachableMode();
      }

      return RegMode::kNoReg;
    }

    case kExprDrop: {
      switch (top_stack_slot_type) {
        case kI32:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_I32Drop);
              return RegMode::kNoReg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_I32Drop);
              I32Pop();
              return RegMode::kNoReg;
          }
          break;
        case kI64:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_I64Drop);
              return RegMode::kNoReg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_I64Drop);
              I64Pop();
              return RegMode::kNoReg;
          }
          break;
        case kF32:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_F32Drop);
              return RegMode::kNoReg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_F32Drop);
              F32Pop();
              return RegMode::kNoReg;
          }
          break;
        case kF64:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_F64Drop);
              return RegMode::kNoReg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_F64Drop);
              F64Pop();
              return RegMode::kNoReg;
          }
          break;
        case kS128:
          switch (mode) {
            case kR2R:
            case kR2S:
            case kS2R:
              UNREACHABLE();
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_S128Drop);
              S128Pop();
              return RegMode::kNoReg;
          }
          break;
        case kRef:
        case kRefNull:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_RefDrop);
              return RegMode::kNoReg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_RefDrop);
              RefPop();
              return RegMode::kNoReg;
          }
          break;
        default:
          UNREACHABLE();
      }
      break;
    }
    case kExprSelect:
    case kExprSelectWithType: {
      DCHECK_GE(stack_size(), 2);
      switch (slots_[stack_[stack_size() - 2]].kind()) {
        case kI32:
          switch (mode) {
            case kR2R:
              EMIT_INSTR_HANDLER(r2r_I32Select);
              I32Pop();  // val2
              I32Pop();  // val1
              return RegMode::kI32Reg;
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_I32Select);
              I32Pop();   // val2
              I32Pop();   // val1
              I32Push();  // result
              return RegMode::kNoReg;
            case kS2R:
              EMIT_INSTR_HANDLER(s2r_I32Select);
              I32Pop();  // condition
              I32Pop();  // val2
              I32Pop();  // val1
              return RegMode::kI32Reg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_I32Select);
              I32Pop();   // condition
              I32Pop();   // val2
              I32Pop();   // val1
              I32Push();  // result
              return RegMode::kNoReg;
          }
          break;
        case kI64:
          switch (mode) {
            case kR2R:
              EMIT_INSTR_HANDLER(r2r_I64Select);
              I64Pop();  // val2
              I64Pop();  // val1
              return RegMode::kI64Reg;
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_I64Select);
              I64Pop();   // val2
              I64Pop();   // val1
              I64Push();  // result
              return RegMode::kNoReg;
            case kS2R:
              EMIT_INSTR_HANDLER(s2r_I64Select);
              I32Pop();  // condition
              I64Pop();  // val2
              I64Pop();  // val1
              return RegMode::kI64Reg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_I64Select);
              I32Pop();  // condition
              I64Pop();
              I64Pop();
              I64Push();
              return RegMode::kNoReg;
          }
          break;
        case kF32:
          switch (mode) {
            case kR2R:
              EMIT_INSTR_HANDLER(r2r_F32Select);
              F32Pop();  // val2
              F32Pop();  // val1
              return RegMode::kF32Reg;
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_F32Select);
              F32Pop();   // val2
              F32Pop();   // val1
              F32Push();  // result
              return RegMode::kNoReg;
            case kS2R:
              EMIT_INSTR_HANDLER(s2r_F32Select);
              I32Pop();  // condition
              F32Pop();  // val2
              F32Pop();  // val1
              return RegMode::kF32Reg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_F32Select);
              I32Pop();  // condition
              F32Pop();
              F32Pop();
              F32Push();
              return RegMode::kNoReg;
          }
          break;
        case kF64:
          switch (mode) {
            case kR2R:
              EMIT_INSTR_HANDLER(r2r_F64Select);
              F64Pop();  // val2
              F64Pop();  // val1
              return RegMode::kF64Reg;
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_F64Select);
              F64Pop();   // val2
              F64Pop();   // val1
              F64Push();  // result
              return RegMode::kNoReg;
            case kS2R:
              EMIT_INSTR_HANDLER(s2r_F64Select);
              I32Pop();  // condition
              F64Pop();  // val2
              F64Pop();  // val1
              return RegMode::kF64Reg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_F64Select);
              I32Pop();  // condition
              F64Pop();
              F64Pop();
              F64Push();
              return RegMode::kNoReg;
          }
          break;
        case kS128:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_S128Select);
              S128Pop();
              S128Pop();
              S128Push();
              return RegMode::kNoReg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_S128Select);
              I32Pop();  // condition
              S128Pop();
              S128Pop();
              S128Push();
              return RegMode::kNoReg;
          }
          break;
        case kRef:
        case kRefNull:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S: {
              EMIT_INSTR_HANDLER(r2s_RefSelect);
              RefPop();                   // val2
              ValueType type = RefPop();  // val1
              RefPush(type);              // result
              return RegMode::kNoReg;
            }
            case kS2S: {
              EMIT_INSTR_HANDLER(s2s_RefSelect);
              I32Pop();  // condition
              RefPop();
              ValueType type = RefPop();
              RefPush(type);
              return RegMode::kNoReg;
            }
          }
          break;
        default:
          UNREACHABLE();
      }
      break;
    }

    case kExprLocalGet: {
      switch (slots_[stack_[instr.optional.index]].kind()) {
        case kI32:
        case kI64:
        case kF32:
        case kF64:
        case kS128:
        case kRef:
        case kRefNull:
          switch (mode) {
            case kR2R:
            case kR2S:
            case kS2R:
              UNREACHABLE();
            case kS2S:
              PushCopySlot(instr.optional.index);
              return RegMode::kNoReg;
          }
          break;
        default:
          UNREACHABLE();
      }
      break;
    }
    case kExprLocalSet: {
      DCHECK_LE(instr.optional.index, stack_size());
      // Validation ensures that the target slot type must be the same as the
      // stack top slot type.
      const ValueType value_type =
          slots_[stack_[instr.optional.index]].value_type;
      const ValueKind kind = value_type.kind();
      DCHECK(CheckEqualKind(kind, top_stack_slot_type));
      switch (kind) {
        case kI32:
        case kI64:
        case kF32:
        case kF64:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S:
              CopyToSlotAndPop(value_type, instr.optional.index, false, true);
              return RegMode::kNoReg;
            case kS2S:
              CopyToSlotAndPop(value_type, instr.optional.index, false, false);
              return RegMode::kNoReg;
          }
          break;
        case kS128:
          switch (mode) {
            case kR2R:
            case kR2S:
            case kS2R:
              UNREACHABLE();
            case kS2S:
              CopyToSlotAndPop(value_type, instr.optional.index, false, false);
              return RegMode::kNoReg;
          }
          break;
        case kRef:
        case kRefNull:
          switch (mode) {
            case kR2R:
            case kR2S:
            case kS2R:
              UNREACHABLE();
            case kS2S:
              CopyToSlotAndPop(slots_[stack_.back()].value_type,
                               instr.optional.index, false, false);
              return RegMode::kNoReg;
          }
          break;
        default:
          UNREACHABLE();
      }
      break;
    }
    case kExprLocalTee: {
      DCHECK_LE(instr.optional.index, stack_size());
      // Validation ensures that the target slot type must be the same as the
      // stack top slot type.
      const ValueType value_type =
          slots_[stack_[instr.optional.index]].value_type;
      const ValueKind kind = value_type.kind();
      DCHECK(CheckEqualKind(kind, top_stack_slot_type));
      switch (kind) {
        case kI32:
        case kI64:
        case kF32:
        case kF64:
          switch (mode) {
            case kR2R:
              CopyToSlotAndPop(value_type, instr.optional.index, true, true);
              return GetRegMode(value_type.kind());
            case kR2S:
              UNREACHABLE();
            case kS2R:
              UNREACHABLE();
            case kS2S:
              CopyToSlotAndPop(value_type, instr.optional.index, true, false);
              return RegMode::kNoReg;
          }
          break;
        case kS128:
          switch (mode) {
            case kR2R:
            case kR2S:
            case kS2R:
              UNREACHABLE();
            case kS2S:
              CopyToSlotAndPop(value_type, instr.optional.index, true, false);
              return RegMode::kNoReg;
          }
          break;
        case kRef:
        case kRefNull:
          switch (mode) {
            case kR2R:
            case kR2S:
            case kS2R:
              UNREACHABLE();
            case kS2S:
              CopyToSlotAndPop(slots_[stack_.back()].value_type,
                               instr.optional.index, true, false);
              return RegMode::kNoReg;
          }
          break;
        default:
          UNREACHABLE();
      }
      break;
    }
    case kExprGlobalGet: {
      switch (GetGlobalType(instr.optional.index)) {
        case kI32:
          switch (mode) {
            case kR2R:
            case kR2S:
              UNREACHABLE();
            case kS2R:
              EMIT_INSTR_HANDLER(s2r_I32GlobalGet);
              EmitGlobalIndex(instr.optional.index);
              return RegMode::kI32Reg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_I32GlobalGet);
              EmitGlobalIndex(instr.optional.index);
              I32Push();
              return RegMode::kNoReg;
          }
          break;
        case kI64:
          switch (mode) {
            case kR2R:
            case kR2S:
              UNREACHABLE();
            case kS2R:
              EMIT_INSTR_HANDLER(s2r_I64GlobalGet);
              EmitGlobalIndex(instr.optional.index);
              return RegMode::kI64Reg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_I64GlobalGet);
              EmitGlobalIndex(instr.optional.index);
              I64Push();
              return RegMode::kNoReg;
          }
          break;
        case kF32:
          switch (mode) {
            case kR2R:
            case kR2S:
              UNREACHABLE();
            case kS2R:
              EMIT_INSTR_HANDLER(s2r_F32GlobalGet);
              EmitGlobalIndex(instr.optional.index);
              return RegMode::kF32Reg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_F32GlobalGet);
              EmitGlobalIndex(instr.optional.index);
              F32Push();
              return RegMode::kNoReg;
          }
          break;
        case kF64:
          switch (mode) {
            case kR2R:
            case kR2S:
              UNREACHABLE();
            case kS2R:
              EMIT_INSTR_HANDLER(s2r_F64GlobalGet);
              EmitGlobalIndex(instr.optional.index);
              return RegMode::kF64Reg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_F64GlobalGet);
              EmitGlobalIndex(instr.optional.index);
              F64Push();
              return RegMode::kNoReg;
          }
          break;
        case kS128:
          switch (mode) {
            case kR2R:
            case kR2S:
            case kS2R:
              UNREACHABLE();
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_S128GlobalGet);
              EmitGlobalIndex(instr.optional.index);
              S128Push();
              return RegMode::kNoReg;
          }
          break;
        case kRef:
        case kRefNull:
          switch (mode) {
            case kR2R:
            case kR2S:
            case kS2R:
              UNREACHABLE();
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_RefGlobalGet);
              EmitGlobalIndex(instr.optional.index);
              RefPush(module_->globals[instr.optional.index].type);
              return RegMode::kNoReg;
          }
          break;
        default:
          UNREACHABLE();
      }
      break;
    }
    case kExprGlobalSet: {
      switch (top_stack_slot_type) {
        case kI32:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_I32GlobalSet);
              EmitGlobalIndex(instr.optional.index);
              return RegMode::kNoReg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_I32GlobalSet);
              EmitGlobalIndex(instr.optional.index);
              I32Pop();
              return RegMode::kNoReg;
          }
          break;
        case kI64:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_I64GlobalSet);
              EmitGlobalIndex(instr.optional.index);
              return RegMode::kNoReg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_I64GlobalSet);
              EmitGlobalIndex(instr.optional.index);
              I64Pop();
              return RegMode::kNoReg;
          }
          break;
        case kF32:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_F32GlobalSet);
              EmitGlobalIndex(instr.optional.index);
              return RegMode::kNoReg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_F32GlobalSet);
              EmitGlobalIndex(instr.optional.index);
              F32Pop();
              return RegMode::kNoReg;
          }
          break;
        case kF64:
          switch (mode) {
            case kR2R:
            case kS2R:
              UNREACHABLE();
            case kR2S:
              EMIT_INSTR_HANDLER(r2s_F64GlobalSet);
              EmitGlobalIndex(instr.optional.index);
              return RegMode::kNoReg;
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_F64GlobalSet);
              EmitGlobalIndex(instr.optional.index);
              F64Pop();
              return RegMode::kNoReg;
          }
          break;
        case kS128:
          switch (mode) {
            case kR2R:
            case kR2S:
            case kS2R:
              UNREACHABLE();
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_S128GlobalSet);
              EmitGlobalIndex(instr.optional.index);
              S128Pop();
              return RegMode::kNoReg;
          }
          break;
        case kRef:
        case kRefNull:
          switch (mode) {
            case kR2R:
            case kR2S:
            case kS2R:
              UNREACHABLE();
            case kS2S:
              EMIT_INSTR_HANDLER(s2s_RefGlobalSet);
              EmitGlobalIndex(instr.optional.index);
              RefPop();
              return RegMode::kNoReg;
          }
          break;
        default:
          UNREACHABLE();
      }
      break;
    }

    case kExprTableGet: {
      EMIT_INSTR_HANDLER_WITH_PC(s2s_TableGet, instr.pc);
      EmitI32Const(instr.optional.index);
      I32Pop();
      RefPush(module_->tables[instr.optional.index].type);
      break;
    }

    case kExprTableSet: {
      EMIT_INSTR_HANDLER_WITH_PC(s2s_TableSet, instr.pc);
      EmitI32Const(instr.optional.index);
      RefPop();
      I32Pop();
      break;
    }

#define LOAD_CASE(name, ctype, mtype, rep, type)          \
  case kExpr##name: {                                     \
    switch (mode) {                                       \
      case kR2R:                                          \
        EMIT_INSTR_HANDLER_WITH_PC(r2r_##name, instr.pc); \
        EmitI64Const(instr.optional.offset);              \
        return RegMode::k##type##Reg;                     \
      case kR2S:                                          \
        EMIT_INSTR_HANDLER_WITH_PC(r2s_##name, instr.pc); \
        EmitI64Const(instr.optional.offset);              \
        type##Push();                                     \
        return RegMode::kNoReg;                           \
      case kS2R:                                          \
        EMIT_INSTR_HANDLER_WITH_PC(s2r_##name, instr.pc); \
        EmitI64Const(instr.optional.offset);              \
        I32Pop();                                         \
        return RegMode::k##type##Reg;                     \
      case kS2S:                                          \
        EMIT_INSTR_HANDLER_WITH_PC(s2s_##name, instr.pc); \
        EmitI64Const(instr.optional.offset);              \
        I32Pop();                                         \
        type##Push();                                     \
        return RegMode::kNoReg;                           \
    }                                                     \
    break;                                                \
  }
      LOAD_CASE(I32LoadMem8S, int32_t, int8_t, kWord8, I32);
      LOAD_CASE(I32LoadMem8U, int32_t, uint8_t, kWord8, I32);
      LOAD_CASE(I32LoadMem16S, int32_t, int16_t, kWord16, I32);
      LOAD_CASE(I32LoadMem16U, int32_t, uint16_t, kWord16, I32);
      LOAD_CASE(I64LoadMem8S, int64_t, int8_t, kWord8, I64);
      LOAD_CASE(I64LoadMem8U, int64_t, uint8_t, kWord16, I64);
      LOAD_CASE(I64LoadMem16S, int64_t, int16_t, kWord16, I64);
      LOAD_CASE(I64LoadMem16U, int64_t, uint16_t, kWord16, I64);
      LOAD_CASE(I64LoadMem32S, int64_t, int32_t, kWord32, I64);
      LOAD_CASE(I64LoadMem32U, int64_t, uint32_t, kWord32, I64);
      LOAD_CASE(I32LoadMem, int32_t, int32_t, kWord32, I32);
      LOAD_CASE(I64LoadMem, int64_t, int64_t, kWord64, I64);
      LOAD_CASE(F32LoadMem, Float32, uint32_t, kFloat32, F32);
      LOAD_CASE(F64LoadMem, Float64, uint64_t, kFloat64, F64);
#undef LOAD_CASE

#define STORE_CASE(name, ctype, mtype, rep, type)         \
  case kExpr##name: {                                     \
    switch (mode) {                                       \
      case kR2R:                                          \
      case kS2R:                                          \
        UNREACHABLE();                                    \
        break;                                            \
      case kR2S:                                          \
        EMIT_INSTR_HANDLER_WITH_PC(r2s_##name, instr.pc); \
        EmitI64Const(instr.optional.offset);              \
        I32Pop();                                         \
        return RegMode::kNoReg;                           \
      case kS2S:                                          \
        EMIT_INSTR_HANDLER_WITH_PC(s2s_##name, instr.pc); \
        type##Pop();                                      \
        EmitI64Const(instr.optional.offset);              \
        I32Pop();                                         \
        return RegMode::kNoReg;                           \
    }                                                     \
    break;                                                \
  }
      STORE_CASE(I32StoreMem8, int32_t, int8_t, kWord8, I32);
      STORE_CASE(I32StoreMem16, int32_t, int16_t, kWord16, I32);
      STORE_CASE(I64StoreMem8, int64_t, int8_t, kWord8, I64);
      STORE_CASE(I64StoreMem16, int64_t, int16_t, kWord16, I64);
      STORE_CASE(I64StoreMem32, int64_t, int32_t, kWord32, I64);
      STORE_CASE(I32StoreMem, int32_t, int32_t, kWord32, I32);
      STORE_CASE(I64StoreMem, int64_t, int64_t, kWord64, I64);
      STORE_CASE(F32StoreMem, Float32, uint32_t, kFloat32, F32);
      STORE_CASE(F64StoreMem, Float64, uint64_t, kFloat64, F64);
#undef STORE_CASE

    case kExprMemoryGrow: {
      EMIT_INSTR_HANDLER(s2s_MemoryGrow);
      I32Pop();
      I32Push();
      break;
    }
    case kExprMemorySize:
      EMIT_INSTR_HANDLER(s2s_MemorySize);
      if (IsMemory64()) {
        I64Push();
      } else {
        I32Push();
      }
      break;

    case kExprI32Const: {
      switch (mode) {
        case kR2R:
        case kR2S:
        case kS2R:
          UNREACHABLE();
        case kS2S:
          PushConstSlot<int32_t>(instr.optional.i32);
          return RegMode::kNoReg;
      }
      break;
    }
    case kExprI64Const: {
      switch (mode) {
        case kR2R:
        case kR2S:
        case kS2R:
          UNREACHABLE();
        case kS2S:
          PushConstSlot<int64_t>(instr.optional.i64);
          return RegMode::kNoReg;
      }
      break;
    }
    case kExprF32Const: {
      switch (mode) {
        case kR2R:
        case kR2S:
        case kS2R:
          UNREACHABLE();
        case kS2S:
          PushConstSlot<float>(instr.optional.f32);
          return RegMode::kNoReg;
      }
      break;
    }
    case kExprF64Const: {
      switch (mode) {
        case kR2R:
        case kR2S:
        case kS2R:
          UNREACHABLE();
        case kS2S:
          PushConstSlot<double>(instr.optional.f64);
          return RegMode::kNoReg;
      }
      break;
    }

#define EXECUTE_BINOP(name, ctype, reg, op, type) \
  case kExpr##name: {                             \
    switch (mode) {                               \
      case kR2R:                                  \
        EMIT_INSTR_HANDLER(r2r_##name);           \
        type##Pop();                              \
        return RegMode::kI32Reg;                  \
      case kR2S:                                  \
        EMIT_INSTR_HANDLER(r2s_##name);           \
        type##Pop();                              \
        I32Push();                                \
        return RegMode::kNoReg;                   \
      case kS2R:                                  \
        EMIT_INSTR_HANDLER(s2r_##name);           \
        type##Pop();                              \
        type##Pop();                              \
        return RegMode::kI32Reg;                  \
      case kS2S:                                  \
        EMIT_INSTR_HANDLER(s2s_##name);           \
        type##Pop();                              \
        type##Pop();                              \
        I32Push();                                \
        return RegMode::kNoReg;                   \
    }                                             \
    break;                                        \
  }
      FOREACH_COMPARISON_BINOP(EXECUTE_BINOP)
#undef EXECUTE_BINOP

#define EXECUTE_BINOP(name, ctype, reg, op, type) \
  case kExpr##name: {                             \
    switch (mode) {                               \
      case kR2R:                                  \
        EMIT_INSTR_HANDLER(r2r_##name);           \
        type##Pop();                              \
        return RegMode::k##type##Reg;             \
      case kR2S:                                  \
        EMIT_INSTR_HANDLER(r2s_##name);           \
        type##Pop();                              \
        type##Push();                             \
        return RegMode::kNoReg;                   \
      case kS2R:                                  \
        EMIT_INSTR_HANDLER(s2r_
"""


```