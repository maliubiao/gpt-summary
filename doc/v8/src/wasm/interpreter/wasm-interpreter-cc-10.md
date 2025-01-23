Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/wasm/interpreter/wasm-interpreter.cc`. The request has several specific constraints:

1. **List Functionalities:** Identify the main actions performed by the code.
2. **Torque Check:** Determine if the file is a Torque file based on the `.tq` extension (it's not).
3. **JavaScript Relationship:** If the C++ code relates to JavaScript functionality, provide a JavaScript example.
4. **Code Logic Inference:** If there's a logical flow, describe it with a hypothetical input and output.
5. **Common Errors:** Point out potential programming errors the code helps prevent or handle.
6. **Part of a Series:** Note that this is part 11 of 15.
7. **Overall Function:** Provide a concise summary of the code's role.

Let's break down the provided code:

* **Macros for Atomic Operations:**  The code defines macros `FOREACH_ATOMIC_BINOP`, `ATOMIC_BINOP`, and `ATOMIC_OP` to generate `case` statements within a `switch` block. These cases handle different types of atomic operations in WebAssembly. They seem to extract memory access information (offset and length) from the bytecode.
* **`GetRegModeString` and `GetOperatorModeString`:** These functions convert enum values (`RegMode`, `OperatorMode`) into human-readable strings. This is likely for debugging or tracing purposes.
* **`TrapMemOutOfBounds`:** This function seems to be a handler for memory access violations during WebAssembly execution. It likely triggers an error or exception. The `#if !defined(V8_DRUMBRAKE_BOUNDS_CHECKS)` suggests this might be related to a specific build configuration or optimization.
* **`InitializeOncePerProcess` and `GlobalTearDown`:** These static functions likely handle initialization and cleanup tasks for the Wasm interpreter at a global level.
* **`WasmBytecodeGenerator::InitSlotsForFunctionArgs`:** This function manages the allocation and initialization of stack slots for function arguments during bytecode generation. It optimizes for cases with multiple simple arguments.
* **`NotifyIsolateDisposal`:** This static function likely handles notifications when an isolate (a V8 execution environment) is being disposed of.
* **`TypeCheckAlwaysSucceeds` and `TypeCheckAlwaysFails`:** These functions perform static analysis to determine if type checks in WebAssembly code will always succeed or always fail. This is useful for optimization and potentially catching type errors early.
* **`WasmBytecodeGenerator::EncodeInstruction`:** This is a core function. It seems to be responsible for translating individual WebAssembly instructions into a lower-level bytecode format used by the interpreter. It handles various opcodes, including control flow (blocks, loops, if/else, try/catch), branching, function calls, and memory access. The logic includes register allocation considerations (`RegMode`, `OperatorMode`) and handling of unreachable code. There's also code for tracing and debugging.

**Plan:**

1. State the file's functionality based on the `EncodeInstruction` function, which appears central.
2. Confirm it's not a Torque file.
3. Explain the connection to JavaScript through WebAssembly execution. Provide a simple JS example that would trigger Wasm execution.
4. Provide a hypothetical example for `EncodeInstruction`, focusing on a simple opcode like `kExprNop`.
5. Explain how type checking functions help prevent common type-related errors. Give a JavaScript example that would lead to a type error in Wasm.
6. Acknowledge that it's part 11/15, implying it's a component within a larger system.
7. Summarize the file's main purpose as part of the Wasm interpreter.
好的，根据你提供的代码片段，以下是`v8/src/wasm/interpreter/wasm-interpreter.cc` 的一些功能归纳：

**功能列举:**

1. **处理原子操作:** 代码中定义了宏来处理各种 WebAssembly 的原子操作指令，例如原子加载、原子存储、原子比较交换等。这些操作通常用于多线程环境下的数据同步。
2. **获取寄存器和操作模式字符串:** 提供了将内部的寄存器模式 (`RegMode`) 和操作模式 (`OperatorMode`) 枚举值转换为可读字符串的函数，主要用于调试和日志输出。
3. **处理内存越界陷阱:** 定义了 `TrapMemOutOfBounds` 函数，用于处理 WebAssembly 代码执行过程中发生的内存访问越界错误。这个函数会触发一个陷阱 (`TrapReason::kTrapMemOutOfBounds`)。
4. **解释器生命周期管理:** 提供了 `InitializeOncePerProcess` 和 `GlobalTearDown` 静态方法，用于管理 WebAssembly 解释器在进程级别的初始化和清理工作。
5. **初始化函数参数的槽位:** `WasmBytecodeGenerator::InitSlotsForFunctionArgs` 函数负责为函数调用准备栈上的槽位，用于存放函数的参数。它会根据参数的类型和数量进行优化。
6. **处理 Isolate 的销毁通知:** `NotifyIsolateDisposal` 静态方法用于接收 V8 Isolate 被销毁的通知，进行相关的清理工作。
7. **静态类型检查辅助:** `TypeCheckAlwaysSucceeds` 和 `TypeCheckAlwaysFails` 函数用于静态地判断 WebAssembly 中的类型检查是否总是成功或总是失败，这有助于编译器进行优化。
8. **核心的指令编码逻辑:** `WasmBytecodeGenerator::EncodeInstruction` 是该文件的核心功能。它负责将 WebAssembly 的高级指令（`WasmInstruction`）转换为解释器可以执行的更低级的字节码。这个函数处理了各种不同的 WebAssembly 指令，包括控制流、算术运算、内存访问、函数调用等。其中也包含了寄存器优化的考虑 (`v8_flags.drumbrake_register_optimization`) 和对不可达代码的处理。

**Torque 源代码检查:**

`v8/src/wasm/interpreter/wasm-interpreter.cc` 以 `.cc` 结尾，而不是 `.tq`，因此它不是一个 v8 Torque 源代码。

**与 JavaScript 的关系及举例:**

`v8/src/wasm/interpreter/wasm-interpreter.cc` 是 V8 引擎中 WebAssembly 解释器的实现部分。当 JavaScript 代码调用 WebAssembly 模块时，V8 会使用这个解释器来执行 WebAssembly 的字节码。

**JavaScript 例子:**

```javascript
// 假设你有一个名为 'module.wasm' 的 WebAssembly 模块
fetch('module.wasm')
  .then(response => response.arrayBuffer())
  .then(bytes => WebAssembly.instantiate(bytes))
  .then(results => {
    const instance = results.instance;
    // 调用 WebAssembly 模块导出的函数
    const result = instance.exports.add(5, 10);
    console.log(result); // 输出 WebAssembly 函数的计算结果
  });
```

在这个例子中，`WebAssembly.instantiate` 负责加载和实例化 WebAssembly 模块。当调用 `instance.exports.add(5, 10)` 时，V8 内部会调用 WebAssembly 解释器（包括 `wasm-interpreter.cc` 中的代码）来执行 `add` 函数的 WebAssembly 字节码。

**代码逻辑推理及假设输入与输出:**

假设 `EncodeInstruction` 函数接收到一个表示 WebAssembly `nop` 指令的 `WasmInstruction` 结构体作为输入：

**假设输入:**

```c++
WasmInstruction instr;
instr.opcode = kExprNop;
instr.pc = 10; // 假设指令在字节码流中的位置
// ... 其他字段可能未初始化，因为对于 nop 指令来说并不重要
```

**推断输出:**

`EncodeInstruction` 函数对于 `kExprNop` 指令的处理很简单，它会直接返回，并且在字节码流中不会添加任何实质性的指令来执行操作。可能会有一些调试或 tracing 的代码被插入，但这取决于编译选项。  该函数主要负责根据指令类型生成相应的底层字节码，`nop` 指令在解释器层面通常就是一个空操作。

**用户常见的编程错误举例:**

代码中的 `TrapMemOutOfBounds` 函数处理了内存越界错误。这是一个 WebAssembly 中常见的运行时错误。

**例子:**

假设一个 WebAssembly 模块尝试访问超出其线性内存范围的地址：

**WebAssembly 代码 (WAT 示例):**

```wat
(module
  (memory (export "memory") 1) ; 定义一个大小为 1 页的内存 (64KB)
  (func (export "write_oob") (param $offset i32) (result i32)
    (i32.store (local.get $offset) (i32.const 123)) ; 尝试存储数据到指定偏移
    (i32.const 0)
  )
)
```

**JavaScript 调用:**

```javascript
fetch('module.wasm')
  .then(response => response.arrayBuffer())
  .then(bytes => WebAssembly.instantiate(bytes))
  .then(results => {
    const instance = results.instance;
    const memory = instance.exports.memory;
    // 尝试写入超出内存范围的地址，例如 100000 (远大于 64KB)
    instance.exports.write_oob(100000); // 这将导致内存越界
  });
```

在这个例子中，`instance.exports.write_oob(100000)` 尝试写入超出已分配内存范围的地址，这会触发 WebAssembly 运行时的内存越界错误，`TrapMemOutOfBounds` 函数会被调用来处理这个错误，阻止程序继续执行并报告错误信息。

**功能归纳 (第 11 部分，共 15 部分):**

作为第 11 部分，`v8/src/wasm/interpreter/wasm-interpreter.cc` 的主要功能是 **将 WebAssembly 的高级指令转换为解释器能够执行的低级字节码，并处理执行过程中可能出现的运行时错误，如内存越界**。它处于 WebAssembly 解释器实现的核心位置，负责指令的翻译和初步的执行控制。考虑到这是 15 部分中的一部分，可以推断出这个文件专注于解释执行流程中的核心指令处理环节，其他部分可能负责加载、验证、优化或其他辅助功能。

### 提示词
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第11部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
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
          EmitI32Const(WasmBytecode::RefArgsCount(sig)
```