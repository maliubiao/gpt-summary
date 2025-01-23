Response:
The user wants to understand the functionality of the provided C++ code snippet from V8's `macro-assembler-s390.cc`. The request has several parts:

1. **List the functions:** I need to identify the purpose of each function in the code.
2. **Check for Torque source:** Determine if the filename ends with `.tq`. This is straightforward.
3. **Relate to JavaScript:**  If the code is related to JavaScript functionality, provide a JavaScript example. This will involve understanding the concepts like "tail call optimization", "optimized code", and "runtime calls".
4. **Provide code logic inference:**  Give examples of inputs and outputs for some of the functions. This might be tricky for low-level assembly-related functions without deeper context.
5. **Illustrate common programming errors:** Identify potential mistakes a programmer might make related to the concepts in the code.
6. **Summarize the functionality:**  Provide a concise overview of the code's purpose.
7. **Address the "part 3 of 8" instruction:** Acknowledge this context, but since I only have this one part, the summary will focus on the provided code.

**Mental Sandbox:**

* **Function Listing:** I can iterate through the code and describe each function's role based on its name and operations. For example, `TailCallOptimizedCodeSlot` likely handles calling optimized code, `ReplaceClosureCodeWithOptimizedCode` updates a closure, and `CallRuntime` invokes runtime functions.
* **Torque Check:** The filename clearly ends with `.cc`, so it's not a Torque file.
* **JavaScript Relation:** The code deals with optimizing function calls, which is directly related to JavaScript performance. A simple example of a function that could be optimized would be useful. The concepts of "closure" and "optimized code" are relevant here.
* **Code Logic Inference:** For functions like `TailCallOptimizedCodeSlot`, I can hypothesize the input registers (containing the optimized code entry, etc.) and the outcome (jumping to the optimized code or calling the runtime). For simpler functions like `AssertFeedbackCell`, the input is a register potentially holding a feedback cell, and the output is either continuation or an abort.
* **Common Errors:**  A common error related to optimization is prematurely assuming code is optimized or incorrectly handling deoptimization. Another could be issues with the number of arguments when calling runtime functions.
* **Summary:** The core function seems to be related to efficient function calls, including handling optimized versions and fallback scenarios.
* **Part 3 of 8:** This is a reminder that the provided snippet is a piece of a larger file.

**Confidence Score:** 4/5 (Slight uncertainty about providing very specific input/output examples for all functions without deeper context).

Strategizing complete. I will now generate the response following these steps.
这是 `v8/src/codegen/s390/macro-assembler-s390.cc` 文件的第三部分，它是一个 V8 引擎中用于 s390 架构的宏汇编器实现。 宏汇编器提供了一组高级的、更易于使用的指令，它们会被扩展成实际的机器码指令。

**功能列举:**

这部分代码主要关注以下功能：

1. **尾调用优化 (Tail Call Optimization):**
   - `TailCallOptimizedCodeSlot`:  负责执行到优化后的代码的尾调用。它会检查优化后的代码槽是否有效，如果有效则跳转到优化后的代码，否则会调用运行时函数来更新优化标记。
   - `ReplaceClosureCodeWithOptimizedCode`:  将优化后的代码地址存储到闭包对象中。
   - `GenerateTailCallToReturnedCode`:  生成一个到返回代码的尾调用，通常用于调用运行时函数并跳转到其返回的代码。
   - `OptimizeCodeOrTailCallOptimizedCodeSlot`:  根据反馈向量中的标志，决定是调用运行时函数进行优化还是直接尾调用优化后的代码槽。

2. **反馈向量 (Feedback Vector) 处理:**
   - `LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing`:  加载反馈向量的标志位，并检查是否需要进行进一步的处理（例如，优化或日志记录）。
   - `LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing`:  加载反馈向量的标志位，如果需要处理则跳转到指定的标签。

3. **运行时 (Runtime) 调用:**
   - `CallRuntime`:  生成调用运行时函数的代码。
   - `TailCallRuntime`:  生成尾调用运行时函数的代码。
   - `JumpToExternalReference`:  跳转到外部引用（通常是 C++ 函数）。

4. **弱引用处理:**
   - `LoadWeakValue`:  加载弱引用对象的值，如果弱引用已被清除，则跳转到指定的标签。

5. **性能计数器:**
   - `EmitIncrementCounter`:  递增性能计数器的值。
   - `EmitDecrementCounter`:  递减性能计数器的值。

6. **断言 (Assertions) 和错误处理:**
   - `Check`:  如果条件不满足，则触发 `Abort`。
   - `Abort`:  终止程序执行，通常用于报告错误。

7. **对象和 Map 操作:**
   - `LoadCompressedMap`: 加载压缩的 Map 对象。
   - `LoadMap`: 加载 Map 对象。
   - `LoadFeedbackVector`: 从闭包中加载反馈向量。
   - `LoadNativeContextSlot`: 加载本地上下文槽的值。

8. **调试代码 (Debug Code) 相关的断言:**  一系列以 `Assert` 开头的函数，用于在调试模式下检查代码的假设是否成立，例如：
   - `AssertFeedbackCell`
   - `AssertFeedbackVector`
   - `AssertNotSmi`
   - `AssertSmi`
   - `AssertConstructor`
   - `AssertFunction`
   - `AssertCallableFunction`
   - `AssertBoundFunction`
   - `AssertGeneratorObject`
   - `AssertUndefinedOrAllocationSite`
   - `AssertJSAny`

9. **C 函数调用:**
   - `PrepareCallCFunction`:  为调用 C 函数准备栈帧。
   - `CallCFunction`:  生成调用 C 函数的代码。

10. **页面标志检查:**
    - `CheckPageFlag`: 检查内存页的标志位。

11. **寄存器操作:**
    - `mov`:  在寄存器之间或寄存器和立即数之间移动数据。
    - `MulS32`, `MulHighS32`, `MulHighU32`, `Mul32WithOverflowIfCCUnequal`:  32 位乘法操作。
    - `DivS32`, `DivU32`: 32 位除法操作。

**关于文件扩展名:**

`v8/src/codegen/s390/macro-assembler-s390.cc` 的扩展名是 `.cc`，表示这是一个 C++ 源文件，而不是 Torque 源文件。如果以 `.tq` 结尾，那才是 V8 Torque 源代码。

**与 JavaScript 的关系 (以及 JavaScript 示例):**

这部分代码直接参与了 JavaScript 代码的执行优化过程。 尾调用优化、内联缓存、类型反馈等优化技术都依赖于 `macro-assembler-s390.cc` 中生成的机器码。

**JavaScript 示例 (尾调用优化):**

```javascript
"use strict";

function factorial(n, accumulator = 1) {
  if (n <= 1) {
    return accumulator;
  }
  return factorial(n - 1, n * accumulator); // 尾调用
}

console.log(factorial(5)); // 输出 120
```

在这个例子中，`factorial` 函数的递归调用是尾调用，这意味着递归调用是函数执行的最后一个操作。 V8 的优化器（如 TurboFan）可以识别这种模式并将其转换为循环，避免了创建新的栈帧，从而提高了性能并防止栈溢出。 `TailCallOptimizedCodeSlot` 等函数就参与了将这种优化后的代码连接到执行流程中。

**代码逻辑推理 (假设输入与输出):**

**示例：`TailCallOptimizedCodeSlot`**

**假设输入:**

* `optimized_code_entry` 寄存器： 包含指向 `CodeWrapper` 对象的指针，该对象包装了优化后的代码。
* `r2` 寄存器： 实际参数个数。
* `r5` 寄存器： `new.target` 的值。
* `r3` 寄存器： 目标函数 (闭包)。

**可能的输出:**

* **情况 1 (优化代码有效):** 程序跳转到优化后的代码的入口点 (`r4` 被设置为优化代码的起始地址，然后执行 `Jump(r4)`）。闭包对象的代码字段会被更新为指向优化后的代码。
* **情况 2 (优化代码无效或需要 deopt):** 程序跳转到 `heal_optimized_code_slot` 标签，然后调用 `Runtime::kHealOptimizedCodeSlot` 运行时函数来处理。

**示例：`LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing`**

**假设输入:**

* `feedback_vector` 寄存器： 指向反馈向量对象的指针。
* `current_code_kind`： 表示当前代码的类型（例如，基线代码，优化代码）。

**可能的输出:**

* **输出 (标志位寄存器 `flags`):**  `flags` 寄存器会被加载反馈向量的标志位。
* **输出 (条件码):**  根据标志位是否指示需要处理（例如，请求分层编译，可能存在优化后的代码），设置条件码。

**用户常见的编程错误 (涉及用户常见的编程错误):**

1. **不正确的尾调用:**  用户可能认为他们的递归函数是尾调用，但实际上不是，导致无法进行尾调用优化。例如：

   ```javascript
   function notTailCallFactorial(n) {
     if (n <= 1) {
       return 1;
     }
     return n * notTailCallFactorial(n - 1); // 乘法操作在递归调用之后
   }
   ```
   在这个例子中，乘法操作 `n * ...` 在递归调用之后执行，因此不是真正的尾调用。

2. **假设代码已经被优化:**  用户可能会编写依赖于代码已经被优化的性能关键代码，但优化是动态发生的。如果优化尚未发生，代码可能会执行得较慢。

3. **错误地理解闭包和优化代码的关系:**  用户可能不理解 V8 如何将优化后的代码与特定的闭包关联起来，导致对性能特性的误解。

4. **在调试模式下看到性能差异:**  调试模式下，很多优化会被禁用，用户可能会看到与生产环境不同的性能表现。

**归纳一下它的功能 (针对这部分代码):**

这部分 `v8/src/codegen/s390/macro-assembler-s390.cc` 代码主要负责**实现 s390 架构下的代码优化和运行时支持的关键功能**，特别是：

* **高效的函数调用机制:**  通过尾调用优化和与优化代码的集成来提升性能。
* **分层编译和代码优化管理:**  通过反馈向量来跟踪代码的执行情况，并触发优化或去优化。
* **与 V8 运行时的交互:**  提供调用运行时函数来执行一些高级操作的接口。
* **提供底层的断言和错误处理机制:**  用于保证代码的正确性。

总而言之，这部分代码是 V8 引擎在 s390 架构上实现高性能 JavaScript 执行的核心组成部分。

### 提示词
```
这是目录为v8/src/codegen/s390/macro-assembler-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/s390/macro-assembler-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
);
  beq(done);
}

namespace {

void TailCallOptimizedCodeSlot(MacroAssembler* masm,
                               Register optimized_code_entry,
                               Register scratch) {
  // ----------- S t a t e -------------
  //  -- r2 : actual argument count
  //  -- r5 : new target (preserved for callee if needed, and caller)
  //  -- r3 : target function (preserved for callee if needed, and caller)
  // -----------------------------------
  DCHECK(!AreAliased(r3, r5, optimized_code_entry, scratch));

  Register closure = r3;
  Label heal_optimized_code_slot;

  // If the optimized code is cleared, go to runtime to update the optimization
  // marker field.
  __ LoadWeakValue(optimized_code_entry, optimized_code_entry,
                   &heal_optimized_code_slot);

  // The entry references a CodeWrapper object. Unwrap it now.
  __ LoadTaggedField(
      optimized_code_entry,
      FieldMemOperand(optimized_code_entry, CodeWrapper::kCodeOffset));

  // Check if the optimized code is marked for deopt. If it is, call the
  // runtime to clear it.
  {
    __ TestCodeIsMarkedForDeoptimization(optimized_code_entry, scratch);
    __ bne(&heal_optimized_code_slot);
  }

  // Optimized code is good, get it into the closure and link the closure
  // into the optimized functions list, then tail call the optimized code.
  __ ReplaceClosureCodeWithOptimizedCode(optimized_code_entry, closure, scratch,
                                         r7);
  static_assert(kJavaScriptCallCodeStartRegister == r4, "ABI mismatch");
  __ LoadCodeInstructionStart(r4, optimized_code_entry);
  __ Jump(r4);

  // Optimized code slot contains deoptimized code or code is cleared and
  // optimized code marker isn't updated. Evict the code, update the marker
  // and re-enter the closure's code.
  __ bind(&heal_optimized_code_slot);
  __ GenerateTailCallToReturnedCode(Runtime::kHealOptimizedCodeSlot);
}

}  // namespace

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::AssertFeedbackCell(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    IsObjectType(object, scratch, scratch, FEEDBACK_CELL_TYPE);
    Assert(eq, AbortReason::kExpectedFeedbackCell);
  }
}
void MacroAssembler::AssertFeedbackVector(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    IsObjectType(object, scratch, scratch, FEEDBACK_VECTOR_TYPE);
    Assert(eq, AbortReason::kExpectedFeedbackVector);
  }
}
void MacroAssembler::AssertFeedbackVector(Register object) {
  if (v8_flags.debug_code) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    CompareObjectType(object, scratch, scratch, FEEDBACK_VECTOR_TYPE);
    Assert(eq, AbortReason::kExpectedFeedbackVector);
  }
}
#endif  // V8_ENABLE_DEBUG_CODE

// Optimized code is good, get it into the closure and link the closure
// into the optimized functions list, then tail call the optimized code.
void MacroAssembler::ReplaceClosureCodeWithOptimizedCode(
    Register optimized_code, Register closure, Register scratch1,
    Register slot_address) {
  DCHECK(!AreAliased(optimized_code, closure, scratch1, slot_address));
  DCHECK_EQ(closure, kJSFunctionRegister);
  DCHECK(!AreAliased(optimized_code, closure));
  // Store code entry in the closure.
  StoreTaggedField(optimized_code,
                   FieldMemOperand(closure, JSFunction::kCodeOffset), r0);
  // Write barrier clobbers scratch1 below.
  Register value = scratch1;
  mov(value, optimized_code);

  RecordWriteField(closure, JSFunction::kCodeOffset, value, slot_address,
                   kLRHasNotBeenSaved, SaveFPRegsMode::kIgnore,
                   SmiCheck::kOmit);
}

void MacroAssembler::GenerateTailCallToReturnedCode(
    Runtime::FunctionId function_id) {
  // ----------- S t a t e -------------
  //  -- r2 : actual argument count
  //  -- r3 : target function (preserved for callee)
  //  -- r5 : new target (preserved for callee)
  // -----------------------------------
  {
    FrameAndConstantPoolScope scope(this, StackFrame::INTERNAL);
    // Push a copy of the target function, the new target and the actual
    // argument count.
    // Push function as parameter to the runtime call.
    SmiTag(kJavaScriptCallArgCountRegister);
    Push(kJavaScriptCallTargetRegister, kJavaScriptCallNewTargetRegister,
         kJavaScriptCallArgCountRegister, kJavaScriptCallTargetRegister);

    CallRuntime(function_id, 1);
    mov(r4, r2);

    // Restore target function, new target and actual argument count.
    Pop(kJavaScriptCallTargetRegister, kJavaScriptCallNewTargetRegister,
        kJavaScriptCallArgCountRegister);
    SmiUntag(kJavaScriptCallArgCountRegister);
  }
  static_assert(kJavaScriptCallCodeStartRegister == r4, "ABI mismatch");
  JumpCodeObject(r4);
}

// Read off the flags in the feedback vector and check if there
// is optimized code or a tiering state that needs to be processed.
Condition MacroAssembler::LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing(
    Register flags, Register feedback_vector, CodeKind current_code_kind) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(flags, feedback_vector));
  DCHECK(CodeKindCanTierUp(current_code_kind));
  LoadU16(flags,
          FieldMemOperand(feedback_vector, FeedbackVector::kFlagsOffset));
  uint32_t kFlagsMask = FeedbackVector::kFlagsTieringStateIsAnyRequested |
                        FeedbackVector::kFlagsMaybeHasTurbofanCode |
                        FeedbackVector::kFlagsLogNextExecution;
  if (current_code_kind != CodeKind::MAGLEV) {
    kFlagsMask |= FeedbackVector::kFlagsMaybeHasMaglevCode;
  }
  CHECK(is_uint16(kFlagsMask));
  tmll(flags, Operand(kFlagsMask));
  return Condition(7);
}

// Read off the flags in the feedback vector and check if there
// is optimized code or a tiering state that needs to be processed.
void MacroAssembler::LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
    Register flags, Register feedback_vector, CodeKind current_code_kind,
    Label* flags_need_processing) {
  ASM_CODE_COMMENT(this);
  b(LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing(flags, feedback_vector,
                                                     current_code_kind),
    flags_need_processing);
}

void MacroAssembler::OptimizeCodeOrTailCallOptimizedCodeSlot(
    Register flags, Register feedback_vector) {
  DCHECK(!AreAliased(flags, feedback_vector));
  Label maybe_has_optimized_code, maybe_needs_logging;
  // Check if optimized code is available
  TestBitMask(flags, FeedbackVector::kFlagsTieringStateIsAnyRequested, r0);
  beq(&maybe_needs_logging);

  GenerateTailCallToReturnedCode(Runtime::kCompileOptimized);

  bind(&maybe_needs_logging);
  TestBitMask(flags, FeedbackVector::LogNextExecutionBit::kMask, r0);
  beq(&maybe_has_optimized_code);
  GenerateTailCallToReturnedCode(Runtime::kFunctionLogNextExecution);

  bind(&maybe_has_optimized_code);
  Register optimized_code_entry = flags;
  LoadTaggedField(optimized_code_entry,
                  FieldMemOperand(feedback_vector,
                                  FeedbackVector::kMaybeOptimizedCodeOffset));
  TailCallOptimizedCodeSlot(this, optimized_code_entry, r1);
}

void MacroAssembler::CallRuntime(const Runtime::Function* f,
                                 int num_arguments) {
  // All parameters are on the stack.  r2 has the return value after call.

  // If the expected number of arguments of the runtime function is
  // constant, we check that the actual number of arguments match the
  // expectation.
  CHECK(f->nargs < 0 || f->nargs == num_arguments);

  // TODO(1236192): Most runtime routines don't need the number of
  // arguments passed in because it is constant. At some point we
  // should remove this need and make the runtime routine entry code
  // smarter.
  mov(r2, Operand(num_arguments));
  Move(r3, ExternalReference::Create(f));
  CallBuiltin(Builtins::RuntimeCEntry(f->result_size));
}

void MacroAssembler::TailCallRuntime(Runtime::FunctionId fid) {
  const Runtime::Function* function = Runtime::FunctionForId(fid);
  DCHECK_EQ(1, function->result_size);
  if (function->nargs >= 0) {
    mov(r2, Operand(function->nargs));
  }
  JumpToExternalReference(ExternalReference::Create(fid));
}

void MacroAssembler::JumpToExternalReference(const ExternalReference& builtin,
                                             bool builtin_exit_frame) {
  Move(r3, builtin);
  TailCallBuiltin(Builtins::CEntry(1, ArgvMode::kStack, builtin_exit_frame));
}

void MacroAssembler::LoadWeakValue(Register out, Register in,
                                   Label* target_if_cleared) {
  CmpS32(in, Operand(kClearedWeakHeapObjectLower32));
  beq(target_if_cleared);

  AndP(out, in, Operand(~kWeakHeapObjectMask));
}

void MacroAssembler::EmitIncrementCounter(StatsCounter* counter, int value,
                                          Register scratch1,
                                          Register scratch2) {
  DCHECK(value > 0 && is_int8(value));
  if (v8_flags.native_code_counters && counter->Enabled()) {
    Move(scratch2, ExternalReference::Create(counter));
    // @TODO(john.yan): can be optimized by asi()
    LoadS32(scratch1, MemOperand(scratch2));
    AddS64(scratch1, Operand(value));
    StoreU32(scratch1, MemOperand(scratch2));
  }
}

void MacroAssembler::EmitDecrementCounter(StatsCounter* counter, int value,
                                          Register scratch1,
                                          Register scratch2) {
  DCHECK(value > 0 && is_int8(value));
  if (v8_flags.native_code_counters && counter->Enabled()) {
    Move(scratch2, ExternalReference::Create(counter));
    // @TODO(john.yan): can be optimized by asi()
    LoadS32(scratch1, MemOperand(scratch2));
    AddS64(scratch1, Operand(-value));
    StoreU32(scratch1, MemOperand(scratch2));
  }
}

void MacroAssembler::Check(Condition cond, AbortReason reason, CRegister cr) {
  Label L;
  b(to_condition(cond), &L);
  Abort(reason);
  // will not return here
  bind(&L);
}

void MacroAssembler::Abort(AbortReason reason) {
  Label abort_start;
  bind(&abort_start);
  if (v8_flags.code_comments) {
    const char* msg = GetAbortReason(reason);
    RecordComment("Abort message: ");
    RecordComment(msg);
  }

  // Avoid emitting call to builtin if requested.
  if (trap_on_abort()) {
    stop();
    return;
  }

  if (should_abort_hard()) {
    // We don't care if we constructed a frame. Just pretend we did.
    FrameScope assume_frame(this, StackFrame::NO_FRAME_TYPE);
    lgfi(r2, Operand(static_cast<int>(reason)));
    PrepareCallCFunction(1, 0, r3);
#if V8_OS_ZOS
    CallCFunction(ExternalReference::abort_with_reason(), 1, 0);
#else
    Move(r3, ExternalReference::abort_with_reason());
    // Use Call directly to avoid any unneeded overhead. The function won't
    // return anyway.
    Call(r3);
#endif
    return;
  }

  LoadSmiLiteral(r3, Smi::FromInt(static_cast<int>(reason)));

  {
    // We don't actually want to generate a pile of code for this, so just
    // claim there is a stack frame, without generating one.
    FrameScope scope(this, StackFrame::NO_FRAME_TYPE);
    if (root_array_available()) {
      // Generate an indirect call via builtins entry table here in order to
      // ensure that the interpreter_entry_return_pc_offset is the same for
      // InterpreterEntryTrampoline and InterpreterEntryTrampolineForProfiling
      // when v8_flags.debug_code is enabled.
      LoadEntryFromBuiltin(Builtin::kAbort, ip);
      Call(ip);
    } else {
      CallBuiltin(Builtin::kAbort);
    }
  }
  // will not return here
}

void MacroAssembler::LoadCompressedMap(Register destination, Register object) {
  CHECK(COMPRESS_POINTERS_BOOL);
  LoadU32(destination, FieldMemOperand(object, HeapObject::kMapOffset));
}

void MacroAssembler::LoadMap(Register destination, Register object) {
  LoadTaggedField(destination, FieldMemOperand(object, HeapObject::kMapOffset));
}

void MacroAssembler::LoadFeedbackVector(Register dst, Register closure,
                                        Register scratch, Label* fbv_undef) {
  Label done;

  // Load the feedback vector from the closure.
  LoadTaggedField(dst,
                  FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  LoadTaggedField(dst, FieldMemOperand(dst, FeedbackCell::kValueOffset));

  // Check if feedback vector is valid.
  IsObjectType(dst, scratch, scratch, FEEDBACK_VECTOR_TYPE);
  b(eq, &done);

  // Not valid, load undefined.
  LoadRoot(dst, RootIndex::kUndefinedValue);
  b(fbv_undef);

  bind(&done);
}

void MacroAssembler::LoadNativeContextSlot(Register dst, int index) {
  LoadMap(dst, cp);
  LoadTaggedField(
      dst, FieldMemOperand(
               dst, Map::kConstructorOrBackPointerOrNativeContextOffset));
  LoadTaggedField(dst, MemOperand(dst, Context::SlotOffset(index)));
}

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::Assert(Condition cond, AbortReason reason, CRegister cr) {
  if (v8_flags.debug_code) Check(cond, reason, cr);
}

void MacroAssembler::AssertUnreachable(AbortReason reason) {
  if (v8_flags.debug_code) Abort(reason);
}

void MacroAssembler::AssertZeroExtended(Register int32_register) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  mov(r0, Operand(kMaxUInt32));
  CmpS64(int32_register, r0);
  Check(le, AbortReason::k32BitValueInRegisterIsNotZeroExtended);
}

void MacroAssembler::AssertMap(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  TestIfSmi(object);
  Check(ne, AbortReason::kOperandIsNotAMap);
  Push(object);
  LoadMap(object, object);
  CompareInstanceType(object, object, MAP_TYPE);
  Pop(object);
  Check(eq, AbortReason::kOperandIsNotAMap);
}

void MacroAssembler::AssertNotSmi(Register object) {
  if (v8_flags.debug_code) {
    static_assert(kSmiTag == 0);
    TestIfSmi(object);
    Check(ne, AbortReason::kOperandIsASmi, cr0);
  }
}

void MacroAssembler::AssertSmi(Register object) {
  if (v8_flags.debug_code) {
    static_assert(kSmiTag == 0);
    TestIfSmi(object);
    Check(eq, AbortReason::kOperandIsNotASmi, cr0);
  }
}

void MacroAssembler::AssertConstructor(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    static_assert(kSmiTag == 0);
    TestIfSmi(object);
    Check(ne, AbortReason::kOperandIsASmiAndNotAConstructor);
    LoadMap(scratch, object);
    tm(FieldMemOperand(scratch, Map::kBitFieldOffset),
       Operand(Map::Bits1::IsConstructorBit::kMask));
    Check(ne, AbortReason::kOperandIsNotAConstructor);
  }
}

void MacroAssembler::AssertFunction(Register object) {
  if (v8_flags.debug_code) {
    static_assert(kSmiTag == 0);
    TestIfSmi(object);
    Check(ne, AbortReason::kOperandIsASmiAndNotAFunction, cr0);
    push(object);
    LoadMap(object, object);
    CompareInstanceTypeRange(object, object, object, FIRST_JS_FUNCTION_TYPE,
                             LAST_JS_FUNCTION_TYPE);
    pop(object);
    Check(le, AbortReason::kOperandIsNotAFunction);
  }
}

void MacroAssembler::AssertCallableFunction(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  static_assert(kSmiTag == 0);
  TestIfSmi(object);
  Check(ne, AbortReason::kOperandIsASmiAndNotAFunction);
  push(object);
  LoadMap(object, object);
  CompareInstanceTypeRange(object, object, object,
                           FIRST_CALLABLE_JS_FUNCTION_TYPE,
                           LAST_CALLABLE_JS_FUNCTION_TYPE);
  pop(object);
  Check(le, AbortReason::kOperandIsNotACallableFunction);
}

void MacroAssembler::AssertBoundFunction(Register object) {
  if (v8_flags.debug_code) {
    static_assert(kSmiTag == 0);
    TestIfSmi(object);
    Check(ne, AbortReason::kOperandIsASmiAndNotABoundFunction, cr0);
    push(object);
    IsObjectType(object, object, object, JS_BOUND_FUNCTION_TYPE);
    pop(object);
    Check(eq, AbortReason::kOperandIsNotABoundFunction);
  }
}

void MacroAssembler::AssertGeneratorObject(Register object) {
  if (!v8_flags.debug_code) return;
  TestIfSmi(object);
  Check(ne, AbortReason::kOperandIsASmiAndNotAGeneratorObject, cr0);

  // Load map
  Register map = object;
  push(object);
  LoadMap(map, object);

  // Check if JSGeneratorObject
  Register scratch = object;
  CompareInstanceTypeRange(map, scratch, scratch,
                           FIRST_JS_GENERATOR_OBJECT_TYPE,
                           LAST_JS_GENERATOR_OBJECT_TYPE);
  // Restore generator object to register and perform assertion
  pop(object);
  Check(le, AbortReason::kOperandIsNotAGeneratorObject);
}

void MacroAssembler::AssertUndefinedOrAllocationSite(Register object,
                                                     Register scratch) {
  if (v8_flags.debug_code) {
    Label done_checking;
    AssertNotSmi(object);
    CompareRoot(object, RootIndex::kUndefinedValue);
    beq(&done_checking, Label::kNear);
    LoadMap(scratch, object);
    CompareInstanceType(scratch, scratch, ALLOCATION_SITE_TYPE);
    Assert(eq, AbortReason::kExpectedUndefinedOrCell);
    bind(&done_checking);
  }
}

void MacroAssembler::AssertJSAny(Register object, Register map_tmp,
                                 Register tmp, AbortReason abort_reason) {
  if (!v8_flags.debug_code) return;

  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, map_tmp, tmp));
  Label ok;

  JumpIfSmi(object, &ok);

  LoadMap(map_tmp, object);
  CompareInstanceType(map_tmp, tmp, LAST_NAME_TYPE);
  ble(&ok);

  CompareInstanceType(map_tmp, tmp, FIRST_JS_RECEIVER_TYPE);
  bge(&ok);

  CompareRoot(map_tmp, RootIndex::kHeapNumberMap);
  beq(&ok);

  CompareRoot(map_tmp, RootIndex::kBigIntMap);
  beq(&ok);

  CompareRoot(object, RootIndex::kUndefinedValue);
  beq(&ok);

  CompareRoot(object, RootIndex::kTrueValue);
  beq(&ok);

  CompareRoot(object, RootIndex::kFalseValue);
  beq(&ok);

  CompareRoot(object, RootIndex::kNullValue);
  beq(&ok);

  Abort(abort_reason);

  bind(&ok);
}

#endif  // V8_ENABLE_DEBUG_CODE

int MacroAssembler::CalculateStackPassedWords(int num_reg_arguments,
                                              int num_double_arguments) {
  int stack_passed_words = 0;
  if (num_double_arguments > DoubleRegister::kNumRegisters) {
    stack_passed_words +=
        2 * (num_double_arguments - DoubleRegister::kNumRegisters);
  }
  // Up to five simple arguments are passed in registers r2..r6
  if (num_reg_arguments > kRegisterPassedArguments) {
    stack_passed_words += num_reg_arguments - kRegisterPassedArguments;
  }
  return stack_passed_words;
}

void MacroAssembler::PrepareCallCFunction(int num_reg_arguments,
                                          int num_double_arguments,
                                          Register scratch) {
  int frame_alignment = ActivationFrameAlignment();
  int stack_passed_arguments =
      CalculateStackPassedWords(num_reg_arguments, num_double_arguments);
  int stack_space = kNumRequiredStackFrameSlots;
  if (frame_alignment > kSystemPointerSize) {
    // Make stack end at alignment and make room for stack arguments
    // -- preserving original value of sp.
    mov(scratch, sp);
    lay(sp, MemOperand(sp, -(stack_passed_arguments + 1) * kSystemPointerSize));
    DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
    ClearRightImm(sp, sp,
                  Operand(base::bits::WhichPowerOfTwo(frame_alignment)));
    StoreU64(scratch,
             MemOperand(sp, (stack_passed_arguments)*kSystemPointerSize));
  } else {
    stack_space += stack_passed_arguments;
  }
  lay(sp, MemOperand(sp, (-stack_space) * kSystemPointerSize));
}

void MacroAssembler::PrepareCallCFunction(int num_reg_arguments,
                                          Register scratch) {
  PrepareCallCFunction(num_reg_arguments, 0, scratch);
}

void MacroAssembler::MovToFloatParameter(DoubleRegister src) { Move(d0, src); }

void MacroAssembler::MovToFloatResult(DoubleRegister src) { Move(d0, src); }

void MacroAssembler::MovToFloatParameters(DoubleRegister src1,
                                          DoubleRegister src2) {
  if (src2 == d0) {
    DCHECK(src1 != d2);
    Move(d2, src2);
    Move(d0, src1);
  } else {
    Move(d0, src1);
    Move(d2, src2);
  }
}

int MacroAssembler::CallCFunction(ExternalReference function,
                                  int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  bool has_function_descriptor,
                                  Label* return_label) {
  Move(ip, function);
  return CallCFunction(ip, num_reg_arguments, num_double_arguments,
                       set_isolate_data_slots, has_function_descriptor,
                       return_label);
}

int MacroAssembler::CallCFunction(Register function, int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  bool has_function_descriptor,
                                  Label* return_label) {
  ASM_CODE_COMMENT(this);
  DCHECK_LE(num_reg_arguments + num_double_arguments, kMaxCParameters);
  DCHECK(has_frame());

#if V8_OS_ZOS
  // Shuffle input arguments
  mov(r1, r2);
  mov(r2, r3);
  mov(r3, r4);

  // XPLINK treats r7 as voliatile return register, but r14 as preserved
  // Since Linux is the other way around, perserve r7 value in r14 across
  // the call.
  mov(r14, r7);

  // XPLINK linkage requires args in r5,r6,r7,r8,r9 to be passed on the stack.
  // However, for DirectAPI C calls, there may not be stack slots
  // for these 4th and 5th parameters if num_reg_arguments are less
  // than 3.  In that case, we need to still preserve r5/r6 into
  // register save area, as they are considered volatile in XPLINK.
  if (num_reg_arguments == 4) {
    StoreU64(r5, MemOperand(sp, 19 * kSystemPointerSize));
    StoreU64(r6, MemOperand(sp, 6 * kSystemPointerSize));
  } else if (num_reg_arguments >= 5) {
    // Save original r5 - r6  to Stack, r7 - r9 already saved to Stack
    StoreMultipleP(r5, r6, MemOperand(sp, 19 * kSystemPointerSize));
  } else {
    StoreMultipleP(r5, r6, MemOperand(sp, 5 * kSystemPointerSize));
  }
#endif

  Label get_pc;

  if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
    // Save the frame pointer and PC so that the stack layout remains iterable,
    // even without an ExitFrame which normally exists between JS and C frames.
    // See x64 code for reasoning about how to address the isolate data fields.
    larl(r0, &get_pc);
    CHECK(root_array_available());
    StoreU64(r0,
             ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerPC));
    StoreU64(fp,
             ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
  }

#if V8_OS_ZOS
  // Set up the system stack pointer with the XPLINK bias.
  lay(r4, MemOperand(sp, -kStackPointerBias));

  Register dest = function;
  if (has_function_descriptor) {
    LoadMultipleP(r5, r6, MemOperand(function));
    dest = r6;
  }
#else
  // Just call directly. The function called cannot cause a GC, or
  // allow preemption, so the return address in the link register
  // stays correct.
  Register dest = function;
  if (ABI_CALL_VIA_IP) {
    Move(ip, function);
    dest = ip;
  }
#endif

#if V8_OS_ZOS
  if (has_function_descriptor) {
    // Branch to target via indirect branch
    basr(r7, dest);
    nop(BASR_CALL_TYPE_NOP);
  } else {
    basr(r7, dest);
  }

  // Restore r5-r9 from the appropriate stack locations (see notes above).
  if (num_reg_arguments == 4) {
    LoadU64(r5, MemOperand(sp, 19 * kSystemPointerSize));
    LoadU64(r6, MemOperand(sp, 6 * kSystemPointerSize));
  } else if (num_reg_arguments >= 5) {
    LoadMultipleP(r5, r6, MemOperand(sp, 19 * kSystemPointerSize));
  } else {
    LoadMultipleP(r5, r6, MemOperand(sp, 5 * kSystemPointerSize));
  }

  // Restore original r7
  mov(r7, r14);

  // Shuffle the result
  mov(r2, r3);
#else
  Call(dest);
#endif

  int call_pc_offset = pc_offset();
  bind(&get_pc);
  if (return_label) bind(return_label);

  if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
    // We don't unset the PC; the FP is the source of truth.
    Register zero_scratch = r0;
    lghi(zero_scratch, Operand::Zero());

    StoreU64(zero_scratch,
             ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
  }

  int stack_passed_arguments =
      CalculateStackPassedWords(num_reg_arguments, num_double_arguments);
  int stack_space = kNumRequiredStackFrameSlots + stack_passed_arguments;
  if (ActivationFrameAlignment() > kSystemPointerSize) {
    // Load the original stack pointer (pre-alignment) from the stack
    LoadU64(sp, MemOperand(sp, stack_space * kSystemPointerSize));
  } else {
    la(sp, MemOperand(sp, stack_space * kSystemPointerSize));
  }

  return call_pc_offset;
}

int MacroAssembler::CallCFunction(ExternalReference function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  bool has_function_descriptor,
                                  Label* return_label) {
  return CallCFunction(function, num_arguments, 0, set_isolate_data_slots,
                       has_function_descriptor, return_label);
}

int MacroAssembler::CallCFunction(Register function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  bool has_function_descriptor,
                                  Label* return_label) {
  return CallCFunction(function, num_arguments, 0, set_isolate_data_slots,
                       has_function_descriptor, return_label);
}

void MacroAssembler::CheckPageFlag(
    Register object,
    Register scratch,  // scratch may be same register as object
    int mask, Condition cc, Label* condition_met) {
  DCHECK(cc == ne || cc == eq);
  ClearRightImm(scratch, object, Operand(kPageSizeBits));

  if (base::bits::IsPowerOfTwo(mask)) {
    // If it's a power of two, we can use Test-Under-Mask Memory-Imm form
    // which allows testing of a single byte in memory.
    int32_t byte_offset = 4;
    uint32_t shifted_mask = mask;
    // Determine the byte offset to be tested
    if (mask <= 0x80) {
      byte_offset = kSystemPointerSize - 1;
    } else if (mask < 0x8000) {
      byte_offset = kSystemPointerSize - 2;
      shifted_mask = mask >> 8;
    } else if (mask < 0x800000) {
      byte_offset = kSystemPointerSize - 3;
      shifted_mask = mask >> 16;
    } else {
      byte_offset = kSystemPointerSize - 4;
      shifted_mask = mask >> 24;
    }
#if V8_TARGET_LITTLE_ENDIAN
    // Reverse the byte_offset if emulating on little endian platform
    byte_offset = kSystemPointerSize - byte_offset - 1;
#endif
    tm(MemOperand(scratch, MemoryChunk::FlagsOffset() + byte_offset),
       Operand(shifted_mask));
  } else {
    LoadU64(scratch, MemOperand(scratch, MemoryChunk::FlagsOffset()));
    AndP(r0, scratch, Operand(mask));
  }
  // Should be okay to remove rc

  if (cc == ne) {
    bne(condition_met);
  }
  if (cc == eq) {
    beq(condition_met);
  }
}

Register GetRegisterThatIsNotOneOf(Register reg1, Register reg2, Register reg3,
                                   Register reg4, Register reg5,
                                   Register reg6) {
  RegList regs = {reg1, reg2, reg3, reg4, reg5, reg6};

  const RegisterConfiguration* config = RegisterConfiguration::Default();
  for (int i = 0; i < config->num_allocatable_general_registers(); ++i) {
    int code = config->GetAllocatableGeneralCode(i);
    Register candidate = Register::from_code(code);
    if (regs.has(candidate)) continue;
    return candidate;
  }
  UNREACHABLE();
}

void MacroAssembler::mov(Register dst, Register src) { lgr(dst, src); }

void MacroAssembler::mov(Register dst, const Operand& src) {
  int64_t value = 0;

  if (src.is_heap_number_request()) {
    RequestHeapNumber(src.heap_number_request());
  } else {
    value = src.immediate();
  }

  if (src.rmode() != RelocInfo::NO_INFO) {
    // some form of relocation needed
    RecordRelocInfo(src.rmode(), value);
  }

  int32_t hi_32 = static_cast<int32_t>(value >> 32);
  int32_t lo_32 = static_cast<int32_t>(value);

  if (src.rmode() == RelocInfo::NO_INFO) {
    if (hi_32 == 0) {
      if (is_uint16(lo_32)) {
        llill(dst, Operand(lo_32));
        return;
      }
      llilf(dst, Operand(lo_32));
      return;
    } else if (lo_32 == 0) {
      if (is_uint16(hi_32)) {
        llihl(dst, Operand(hi_32));
        return;
      }
      llihf(dst, Operand(hi_32));
      return;
    } else if (is_int16(value)) {
      lghi(dst, Operand(value));
      return;
    } else if (is_int32(value)) {
      lgfi(dst, Operand(value));
      return;
    }
  } else if (src.rmode() == RelocInfo::WASM_CANONICAL_SIG_ID) {
    CHECK(is_int32(value));
    // If this is changed then also change `uint32_constant_at` and
    // `set_uint32_constant_at`.
    lgfi(dst, Operand(value));
    return;
  }

  iihf(dst, Operand(hi_32));
  iilf(dst, Operand(lo_32));
}

void MacroAssembler::MulS32(Register dst, const MemOperand& src1) {
  if (is_uint12(src1.offset())) {
    ms(dst, src1);
  } else if (is_int20(src1.offset())) {
    msy(dst, src1);
  } else {
    UNIMPLEMENTED();
  }
}

void MacroAssembler::MulS32(Register dst, Register src1) { msr(dst, src1); }

void MacroAssembler::MulS32(Register dst, const Operand& src1) {
  msfi(dst, src1);
}

#define Generate_MulHigh32(instr) \
  {                               \
    lgfr(dst, src1);              \
    instr(dst, src2);             \
    srlg(dst, dst, Operand(32));  \
  }

void MacroAssembler::MulHighS32(Register dst, Register src1,
                                const MemOperand& src2) {
  Generate_MulHigh32(msgf);
}

void MacroAssembler::MulHighS32(Register dst, Register src1, Register src2) {
  if (dst == src2) {
    std::swap(src1, src2);
  }
  Generate_MulHigh32(msgfr);
}

void MacroAssembler::MulHighS32(Register dst, Register src1,
                                const Operand& src2) {
  Generate_MulHigh32(msgfi);
}

#undef Generate_MulHigh32

#define Generate_MulHighU32(instr) \
  {                                \
    lr(r1, src1);                  \
    instr(r0, src2);               \
    LoadU32(dst, r0);              \
  }

void MacroAssembler::MulHighU32(Register dst, Register src1,
                                const MemOperand& src2) {
  Generate_MulHighU32(ml);
}

void MacroAssembler::MulHighU32(Register dst, Register src1, Register src2) {
  Generate_MulHighU32(mlr);
}

void MacroAssembler::MulHighU32(Register dst, Register src1,
                                const Operand& src2) {
  USE(dst);
  USE(src1);
  USE(src2);
  UNREACHABLE();
}

#undef Generate_MulHighU32

#define Generate_Mul32WithOverflowIfCCUnequal(instr) \
  {                                                  \
    lgfr(dst, src1);                                 \
    instr(dst, src2);                                \
    cgfr(dst, dst);                                  \
  }

void MacroAssembler::Mul32WithOverflowIfCCUnequal(Register dst, Register src1,
                                                  const MemOperand& src2) {
  Register result = dst;
  if (src2.rx() == dst || src2.rb() == dst) dst = r0;
  Generate_Mul32WithOverflowIfCCUnequal(msgf);
  if (result != dst) llgfr(result, dst);
}

void MacroAssembler::Mul32WithOverflowIfCCUnequal(Register dst, Register src1,
                                                  Register src2) {
  if (dst == src2) {
    std::swap(src1, src2);
  }
  Generate_Mul32WithOverflowIfCCUnequal(msgfr);
}

void MacroAssembler::Mul32WithOverflowIfCCUnequal(Register dst, Register src1,
                                                  const Operand& src2) {
  Generate_Mul32WithOverflowIfCCUnequal(msgfi);
}

#undef Generate_Mul32WithOverflowIfCCUnequal

#define Generate_Div32(instr) \
  {                           \
    lgfr(r1, src1);           \
    instr(r0, src2);          \
    LoadU32(dst, r1);         \
  }

void MacroAssembler::DivS32(Register dst, Register src1,
                            const MemOperand& src2) {
  Generate_Div32(dsgf);
}

void MacroAssembler::DivS32(Register dst, Register src1, Register src2) {
  Generate_Div32(dsgfr);
}

#undef Generate_Div32

#define Generate_DivU32(instr) \
  {                            \
    lr(r0, src1);              \
    srdl(r0, Operand(32));     \
    instr(r0, src2);           \
    LoadU32(dst, r1);          \
  }

void MacroAssembler::DivU32(Register dst, Register src1,
                            const MemOperand& src2) {
  Generate_DivU32(dl);
}

void MacroAssembler::DivU32(Register dst, Register src1, Register src2) {
  Generate_DivU32(dlr);
}

#undef Generate_DivU32

#define Generate_Div64(instr) \
  {
```