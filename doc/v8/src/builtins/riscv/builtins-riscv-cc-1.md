Response:
The user wants to understand the functionality of a specific code snippet from `v8/src/builtins/riscv/builtins-riscv.cc`.

Here's a breakdown of the user's request and how to address it:

1. **List the functionalities:** I need to analyze the provided RISC-V assembly code and identify the high-level operations it performs. This involves understanding the purpose of each assembly instruction and how they work together.

2. **Torque source check:** The user provided a conditional statement about `.tq` files. Since the provided code is `.cc`, this condition is not met. I should mention this.

3. **Relationship to JavaScript and examples:**  I need to determine if the code snippet is related to any JavaScript functionality. If so, I should provide a simple JavaScript example to illustrate the connection. This requires understanding how the V8 engine executes JavaScript.

4. **Code logic and I/O:** If the code performs a logical operation, I need to provide a hypothetical input and its corresponding output. This requires abstracting the assembly code's behavior.

5. **Common programming errors:** If the code is related to preventing or handling common programming errors, I need to provide an example of such an error.

6. **Summarize the functionality:**  I need to provide a concise summary of the code snippet's overall purpose within the V8 engine.

**Analysis of the provided code snippet:**

The code primarily focuses on a function called `AdvanceBytecodeOffsetOrReturn`. This function seems to be a crucial part of the V8 interpreter's execution loop. It determines the next action based on the current bytecode: either advance to the next bytecode or return from the function.

The code also includes functions related to managing the stack frame during function calls, such as `ResetSharedFunctionInfoAge`, `ResetJSFunctionAge`, `ResetFeedbackVectorOsrUrgency`, and `Generate_BaselineOutOfLinePrologueDeopt`.

Finally, the snippet shows the beginning of the `Generate_InterpreterEntryTrampoline` function, which is the entry point for executing JavaScript code in the interpreter.

**Plan:**

1. Identify the core functionality of `AdvanceBytecodeOffsetOrReturn`.
2. Explain the role of the code related to stack frame management.
3. Explain the role of the initial part of `Generate_InterpreterEntryTrampoline`.
4. Confirm that the file is a `.cc` file, not a `.tq` file.
5. Provide a JavaScript example related to function calls and returns.
6. Create a simple input/output example for `AdvanceBytecodeOffsetOrReturn`.
7. Identify potential programming errors related to incorrect function calls or stack management.
8. Summarize the functionalities.
这是目录为v8/src/builtins/riscv/builtins-riscv.cc的V8源代码片段的第二部分，主要功能是关于 **V8 JavaScript 解释器中的字节码处理和函数调用相关的底层实现**。具体来说，它涉及以下几个核心方面：

**1. 字节码偏移量的推进和返回处理 (`AdvanceBytecodeOffsetOrReturn`)**

* **功能:**  该函数负责根据当前执行的字节码指令，更新字节码数组的偏移量 (`bytecode_offset`)，以便指向下一条需要执行的字节码。如果当前字节码是返回指令，则跳转到返回标签。
* **逻辑推理:**
    * **假设输入:**
        * `bytecode`: 当前执行的字节码，假设值为 `interpreter::Bytecode::kLdar`.
        * `bytecode_offset`: 当前字节码在字节码数组中的偏移量，假设为 10。
        * `bytecode_size_table`:  字节码大小查找表，假设 `kLdar` 的大小为 2 字节。
    * **输出:**
        * `bytecode_offset`: 更新后的偏移量将为 12 (10 + 2)。程序流程将继续执行 `__ bind(&end)` 之后的代码。
    * **假设输入 (返回指令):**
        * `bytecode`: 当前执行的字节码，假设值为 `interpreter::Bytecode::kReturn`.
    * **输出:**
        * 程序流程将跳转到 `__ bind(&if_return)`.
* **与 JavaScript 的关系:**  JavaScript 代码会被编译成字节码，解释器会逐条执行这些字节码。`AdvanceBytecodeOffsetOrReturn` 是解释器循环中的关键部分，确保指令按顺序执行。
* **JavaScript 示例:**  考虑一个简单的函数：
  ```javascript
  function add(a, b) {
    return a + b;
  }
  ```
  当解释器执行 `return a + b;` 这行代码时，会执行类似 `interpreter::Bytecode::kReturn` 这样的字节码，`AdvanceBytecodeOffsetOrReturn` 会识别到这是一个返回指令，并跳转到返回处理逻辑。

**2. 函数调用前后的状态重置 (Reset SharedFunctionInfoAge, ResetJSFunctionAge, ResetFeedbackVectorOsrUrgency)**

* **功能:** 这些函数用于在函数调用前后重置一些与性能优化和代码优化（例如，内联缓存和分层编译）相关的状态信息。
    * `ResetSharedFunctionInfoAge`: 重置 `SharedFunctionInfo` 对象的 age 字段。
    * `ResetJSFunctionAge`: 重置 `JSFunction` 对象关联的 `SharedFunctionInfo` 的 age 字段。
    * `ResetFeedbackVectorOsrUrgency`: 重置 `FeedbackVector` 对象的 OSR (On-Stack Replacement) 紧急程度标志。
* **与 JavaScript 的关系:** 这些操作是 V8 优化 JavaScript 代码执行的一部分。例如，函数被调用多次后可能会被优化，重置这些状态可以在特定场景下触发或阻止优化行为。

**3. 优化代码 prologue 的回退处理 (`Generate_BaselineOutOfLinePrologueDeopt`)**

* **功能:** 当 Baseline 代码的 prologue 阶段因为栈溢出等原因需要回退（deoptimize）到解释器执行时，该函数生成相应的汇编代码。它负责清理 Baseline 代码 prologue 创建的栈帧，并将控制权转移回解释器入口。
* **与 JavaScript 的关系:**  这是 V8 分层编译的一部分。Baseline 是一种轻量级的优化，如果执行过程中出现问题，需要回退到解释器。

**4. Baseline 代码的 prologue (`Generate_BaselineOutOfLinePrologue`)**

* **功能:**  当 JavaScript 函数第一次被 Baseline 编译器编译执行时，会执行这段 prologue 代码。它负责进行一些初始化操作，例如：
    * 加载并检查 `FeedbackVector` (用于收集运行时类型信息，以便进行后续优化)。
    * 检查 tiering 状态（是否需要进一步优化）。
    * 增加函数的调用计数。
    * 设置栈帧。
    * 进行栈溢出检查。
* **与 JavaScript 的关系:** 这是 V8 分层编译的关键步骤。Baseline prologue 为后续的优化执行做准备。

**5. 解释器入口跳转 (`Generate_InterpreterEntryTrampoline`)**

* **功能:**  这是 V8 解释器执行 JavaScript 代码的入口点。当 JavaScript 函数需要通过解释器执行时，控制流会跳转到这里。该函数负责：
    * 获取字节码数组。
    * 加载 `FeedbackVector`。
    * 设置解释器栈帧。
    * 分配局部变量和临时变量的空间。
    * 跳转到字节码分发器开始执行字节码。
* **与 JavaScript 的关系:**  所有未被 JIT 编译的 JavaScript 代码都通过这个入口进入解释器执行。

**用户常见的编程错误 (可能与这些代码相关):**

* **栈溢出:**  如果 JavaScript 代码导致过多的函数调用或过大的局部变量，可能会导致栈溢出。V8 的栈溢出检查机制（例如，在 `Generate_BaselineOutOfLinePrologue` 和 `Generate_InterpreterEntryTrampoline` 中）可以捕获这种错误。
  ```javascript
  function recursiveFunction() {
    recursiveFunction(); // 导致无限递归
  }
  recursiveFunction(); // 可能导致栈溢出
  ```
* **类型错误:**  V8 的优化依赖于类型反馈。如果 JavaScript 代码中的类型使用不一致，可能导致优化失效或触发 deoptimization。虽然这里没有直接处理类型错误，但 `FeedbackVector` 的使用与类型推断和优化密切相关。
  ```javascript
  function add(a, b) {
    return a + b;
  }
  add(1, 2); // 第一次调用，V8 可能会推断出 a 和 b 是数字
  add("hello", "world"); // 后续调用类型不一致，可能影响优化
  ```

**归纳一下它的功能:**

这段代码片段是 V8 JavaScript 引擎中 RISC-V 架构下，关于解释器核心功能和函数调用优化的底层实现。它涵盖了字节码的读取、执行和控制流转移，以及为函数调用建立和管理栈帧、收集运行时信息以便进行后续优化的关键步骤。 这些代码是 V8 引擎执行 JavaScript 代码的基础组成部分。

**关于 .tq 文件:**

你提到的 `.tq` 文件是 V8 的 Torque 语言编写的源代码。Torque 是一种用于生成高效内置函数的领域特定语言。由于 `v8/src/builtins/riscv/builtins-riscv.cc` 是 `.cc` 文件，因此它不是 Torque 源代码，而是使用 C++ 和 RISC-V 汇编编写的。

Prompt: 
```
这是目录为v8/src/builtins/riscv/builtins-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/riscv/builtins-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能

"""
 static_cast<int>(interpreter::Bytecode::kDebugBreakExtraWide));
  __ Branch(&process_bytecode, Ugreater, bytecode, Operand(3),
            Label::Distance::kNear);
  __ And(scratch2, bytecode, Operand(1));
  __ Branch(&extra_wide, ne, scratch2, Operand(zero_reg),
            Label::Distance::kNear);

  // Load the next bytecode and update table to the wide scaled table.
  __ AddWord(bytecode_offset, bytecode_offset, Operand(1));
  __ AddWord(scratch2, bytecode_array, bytecode_offset);
  __ Lbu(bytecode, MemOperand(scratch2));
  __ AddWord(bytecode_size_table, bytecode_size_table,
             Operand(kByteSize * interpreter::Bytecodes::kBytecodeCount));
  __ BranchShort(&process_bytecode);

  __ bind(&extra_wide);
  // Load the next bytecode and update table to the extra wide scaled table.
  __ AddWord(bytecode_offset, bytecode_offset, Operand(1));
  __ AddWord(scratch2, bytecode_array, bytecode_offset);
  __ Lbu(bytecode, MemOperand(scratch2));
  __ AddWord(bytecode_size_table, bytecode_size_table,
             Operand(2 * kByteSize * interpreter::Bytecodes::kBytecodeCount));

  __ bind(&process_bytecode);

// Bailout to the return label if this is a return bytecode.
#define JUMP_IF_EQUAL(NAME)          \
  __ Branch(if_return, eq, bytecode, \
            Operand(static_cast<int64_t>(interpreter::Bytecode::k##NAME)));
  RETURN_BYTECODE_LIST(JUMP_IF_EQUAL)
#undef JUMP_IF_EQUAL

  // If this is a JumpLoop, re-execute it to perform the jump to the beginning
  // of the loop.
  Label end, not_jump_loop;
  __ Branch(&not_jump_loop, ne, bytecode,
            Operand(static_cast<int64_t>(interpreter::Bytecode::kJumpLoop)),
            Label::Distance::kNear);
  // We need to restore the original bytecode_offset since we might have
  // increased it to skip the wide / extra-wide prefix bytecode.
  __ Move(bytecode_offset, original_bytecode_offset);
  __ BranchShort(&end);

  __ bind(&not_jump_loop);
  // Otherwise, load the size of the current bytecode and advance the offset.
  __ AddWord(scratch2, bytecode_size_table, bytecode);
  __ Lb(scratch2, MemOperand(scratch2));
  __ AddWord(bytecode_offset, bytecode_offset, scratch2);

  __ bind(&end);
}

namespace {
void ResetSharedFunctionInfoAge(MacroAssembler* masm, Register sfi) {
  __ Sh(zero_reg, FieldMemOperand(sfi, SharedFunctionInfo::kAgeOffset));
}

void ResetJSFunctionAge(MacroAssembler* masm, Register js_function,
                        Register scratch) {
  const Register shared_function_info(scratch);
  __ LoadTaggedField(
      shared_function_info,
      FieldMemOperand(js_function, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, shared_function_info);
}

void ResetFeedbackVectorOsrUrgency(MacroAssembler* masm,
                                   Register feedback_vector, Register scratch) {
  DCHECK(!AreAliased(feedback_vector, scratch));
  __ Lbu(scratch,
         FieldMemOperand(feedback_vector, FeedbackVector::kOsrStateOffset));
  __ And(scratch, scratch, Operand(~FeedbackVector::OsrUrgencyBits::kMask));
  __ Sb(scratch,
        FieldMemOperand(feedback_vector, FeedbackVector::kOsrStateOffset));
}

}  // namespace

// static
void Builtins::Generate_BaselineOutOfLinePrologueDeopt(MacroAssembler* masm) {
  // We're here because we got deopted during BaselineOutOfLinePrologue's stack
  // check. Undo all its frame creation and call into the interpreter instead.

  // Drop bytecode offset (was the feedback vector but got replaced during
  // deopt) and bytecode array.
  __ AddWord(sp, sp, Operand(3 * kSystemPointerSize));

  // Context, closure, argc.
  __ Pop(kContextRegister, kJavaScriptCallTargetRegister,
         kJavaScriptCallArgCountRegister);

  // Drop frame pointer
  __ LeaveFrame(StackFrame::BASELINE);

  // Enter the interpreter.
  __ TailCallBuiltin(Builtin::kInterpreterEntryTrampoline);
}

void Builtins::Generate_BaselineOutOfLinePrologue(MacroAssembler* masm) {
  UseScratchRegisterScope temps(masm);
  temps.Include({kScratchReg, kScratchReg2, s1});
  auto descriptor =
      Builtins::CallInterfaceDescriptorFor(Builtin::kBaselineOutOfLinePrologue);
  Register closure = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kClosure);
  // Load the feedback cell and vector from the closure.
  Register feedback_cell = temps.Acquire();
  Register feedback_vector = temps.Acquire();
  __ LoadTaggedField(feedback_cell,
                     FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  __ LoadTaggedField(
      feedback_vector,
      FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset));
  {
    UseScratchRegisterScope temp(masm);
    Register type = temps.Acquire();
    __ AssertFeedbackVector(feedback_vector, type);
  }

  // Check for an tiering state.
  Label flags_need_processing;
  Register flags = temps.Acquire();
  __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      flags, feedback_vector, CodeKind::BASELINE, &flags_need_processing);
  {
    UseScratchRegisterScope temps(masm);
    ResetFeedbackVectorOsrUrgency(masm, feedback_vector, temps.Acquire());
  }
  // Increment invocation count for the function.
  {
    UseScratchRegisterScope temps(masm);
    Register invocation_count = temps.Acquire();
    __ Lw(invocation_count,
          FieldMemOperand(feedback_vector,
                          FeedbackVector::kInvocationCountOffset));
    __ Add32(invocation_count, invocation_count, Operand(1));
    __ Sw(invocation_count,
          FieldMemOperand(feedback_vector,
                          FeedbackVector::kInvocationCountOffset));
  }

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  {
    ASM_CODE_COMMENT_STRING(masm, "Frame Setup");
    // Normally the first thing we'd do here is Push(lr, fp), but we already
    // entered the frame in BaselineCompiler::Prologue, as we had to use the
    // value lr before the call to this BaselineOutOfLinePrologue builtin.

    Register callee_context = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kCalleeContext);
    Register callee_js_function = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kClosure);
    {
      UseScratchRegisterScope temps(masm);
      ResetJSFunctionAge(masm, callee_js_function, temps.Acquire());
    }
    __ Push(callee_context, callee_js_function);
    DCHECK_EQ(callee_js_function, kJavaScriptCallTargetRegister);
    DCHECK_EQ(callee_js_function, kJSFunctionRegister);

    Register argc = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kJavaScriptCallArgCount);
    // We'll use the bytecode for both code age/OSR resetting, and pushing onto
    // the frame, so load it into a register.
    Register bytecode_array = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kInterpreterBytecodeArray);
    __ Push(argc, bytecode_array, feedback_cell, feedback_vector);
    // Baseline code frames store the feedback vector where interpreter would
    // store the bytecode offset.
    {
      UseScratchRegisterScope temp(masm);
      Register type = temps.Acquire();
      __ AssertFeedbackVector(feedback_vector, type);
    }
  }

  Label call_stack_guard;
  Register frame_size = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kStackFrameSize);
  {
    ASM_CODE_COMMENT_STRING(masm, "Stack/interrupt check");
    // Stack check. This folds the checks for both the interrupt stack limit
    // check and the real stack limit into one by just checking for the
    // interrupt limit. The interrupt limit is either equal to the real stack
    // limit or tighter. By ensuring we have space until that limit after
    // building the frame we can quickly precheck both at once.
    UseScratchRegisterScope temps(masm);
    Register sp_minus_frame_size = temps.Acquire();
    __ SubWord(sp_minus_frame_size, sp, frame_size);
    Register interrupt_limit = temps.Acquire();
    __ LoadStackLimit(interrupt_limit, StackLimitKind::kInterruptStackLimit);
    __ Branch(&call_stack_guard, Uless, sp_minus_frame_size,
              Operand(interrupt_limit));
  }

  // Do "fast" return to the caller pc in lr.
  // TODO(v8:11429): Document this frame setup better.
  __ Ret();

  __ bind(&flags_need_processing);
  {
    ASM_CODE_COMMENT_STRING(masm, "Optimized marker check");
    // Drop the frame created by the baseline call.
    __ Pop(ra, fp);
    __ OptimizeCodeOrTailCallOptimizedCodeSlot(flags, feedback_vector);
    __ Trap();
  }

  __ bind(&call_stack_guard);
  {
    ASM_CODE_COMMENT_STRING(masm, "Stack/interrupt call");
    FrameScope frame_scope(masm, StackFrame::INTERNAL);
    // Save incoming new target or generator
    __ Push(kJavaScriptCallNewTargetRegister);
    __ SmiTag(frame_size);
    __ Push(frame_size);
    __ CallRuntime(Runtime::kStackGuardWithGap);
    __ Pop(kJavaScriptCallNewTargetRegister);
  }
  __ Ret();
  temps.Exclude({kScratchReg, kScratchReg2, s1});
}

// Generate code for entering a JS function with the interpreter.
// On entry to the function the receiver and arguments have been pushed on the
// stack left to right.
//
// The live registers are:
//   o a0 : actual argument count
//   o a1: the JS function object being called.
//   o a3: the incoming new target or generator object
//   o cp: our context
//   o fp: the caller's frame pointer
//   o sp: stack pointer
//   o ra: return address
//
// The function builds an interpreter frame.  See InterpreterFrameConstants in
// frames-constants.h for its layout.
void Builtins::Generate_InterpreterEntryTrampoline(
    MacroAssembler* masm, InterpreterEntryTrampolineMode mode) {
  Register closure = a1;
  // Get the bytecode array from the function object and load it into
  // kInterpreterBytecodeArrayRegister.
  Register sfi = a4;
  __ LoadTaggedField(
      sfi, FieldMemOperand(closure, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, sfi);

  // The bytecode array could have been flushed from the shared function info,
  // if so, call into CompileLazy.
  Label is_baseline, compile_lazy;
  GetSharedFunctionInfoBytecodeOrBaseline(
      masm, sfi, kInterpreterBytecodeArrayRegister, kScratchReg, &is_baseline,
      &compile_lazy);

  Label push_stack_frame;
  Register feedback_vector = a2;
  __ LoadFeedbackVector(feedback_vector, closure, a4, &push_stack_frame);

#ifndef V8_JITLESS
  // If feedback vector is valid, check for optimized code and update invocation
  // count.

  // Check the tiering state.
  Label flags_need_processing;
  Register flags = a4;
  __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      flags, feedback_vector, CodeKind::INTERPRETED_FUNCTION,
      &flags_need_processing);
  ResetFeedbackVectorOsrUrgency(masm, feedback_vector, a4);

  // Increment invocation count for the function.
  __ Lw(a4, FieldMemOperand(feedback_vector,
                            FeedbackVector::kInvocationCountOffset));
  __ Add32(a4, a4, Operand(1));
  __ Sw(a4, FieldMemOperand(feedback_vector,
                            FeedbackVector::kInvocationCountOffset));

  // Open a frame scope to indicate that there is a frame on the stack.  The
  // MANUAL indicates that the scope shouldn't actually generate code to set up
  // the frame (that is done below).
#else
  // Note: By omitting the above code in jitless mode we also disable:
  // - kFlagsLogNextExecution: only used for logging/profiling; and
  // - kInvocationCountOffset: only used for tiering heuristics and code
  //   coverage.
#endif  // !V8_JITLESS

  __ bind(&push_stack_frame);
  FrameScope frame_scope(masm, StackFrame::MANUAL);
  __ PushStandardFrame(closure);

  // Load initial bytecode offset.
  __ li(kInterpreterBytecodeOffsetRegister,
        Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));

  // Push bytecode array, Smi tagged bytecode array offset, and the feedback
  // vector.
  __ SmiTag(a4, kInterpreterBytecodeOffsetRegister);
  __ Push(kInterpreterBytecodeArrayRegister, a4, feedback_vector);

  // Allocate the local and temporary register file on the stack.
  Label stack_overflow;
  {
    // Load frame size (word) from the BytecodeArray object.
    __ Lw(a4, FieldMemOperand(kInterpreterBytecodeArrayRegister,
                              BytecodeArray::kFrameSizeOffset));

    // Do a stack check to ensure we don't go over the limit.
    __ SubWord(a5, sp, Operand(a4));
    __ LoadStackLimit(a2, StackLimitKind::kRealStackLimit);
    __ Branch(&stack_overflow, Uless, a5, Operand(a2));

    // If ok, push undefined as the initial value for all register file entries.
    Label loop_header;
    Label loop_check;
    __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
    __ BranchShort(&loop_check);
    __ bind(&loop_header);
    // TODO(rmcilroy): Consider doing more than one push per loop iteration.
    __ push(kInterpreterAccumulatorRegister);
    // Continue loop if not done.
    __ bind(&loop_check);
    __ SubWord(a4, a4, Operand(kSystemPointerSize));
    __ Branch(&loop_header, ge, a4, Operand(zero_reg));
  }

  // If the bytecode array has a valid incoming new target or generator object
  // register, initialize it with incoming value which was passed in a3.
  Label no_incoming_new_target_or_generator_register;
  __ Lw(a5, FieldMemOperand(
                kInterpreterBytecodeArrayRegister,
                BytecodeArray::kIncomingNewTargetOrGeneratorRegisterOffset));
  __ Branch(&no_incoming_new_target_or_generator_register, eq, a5,
            Operand(zero_reg), Label::Distance::kNear);
  __ CalcScaledAddress(a5, fp, a5, kSystemPointerSizeLog2);
  __ StoreWord(a3, MemOperand(a5));
  __ bind(&no_incoming_new_target_or_generator_register);

  // Perform interrupt stack check.
  // TODO(solanes): Merge with the real stack limit check above.
  Label stack_check_interrupt, after_stack_check_interrupt;
  __ LoadStackLimit(a5, StackLimitKind::kInterruptStackLimit);
  __ Branch(&stack_check_interrupt, Uless, sp, Operand(a5),
            Label::Distance::kNear);
  __ bind(&after_stack_check_interrupt);

  // Load the dispatch table into a register and dispatch to the bytecode
  // handler at the current bytecode offset.
  Label do_dispatch;
  __ bind(&do_dispatch);
  __ li(kInterpreterDispatchTableRegister,
        ExternalReference::interpreter_dispatch_table_address(masm->isolate()));
  __ AddWord(a1, kInterpreterBytecodeArrayRegister,
             kInterpreterBytecodeOffsetRegister);
  __ Lbu(a7, MemOperand(a1));
  __ CalcScaledAddress(kScratchReg, kInterpreterDispatchTableRegister, a7,
                       kSystemPointerSizeLog2);
  __ LoadWord(kJavaScriptCallCodeStartRegister, MemOperand(kScratchReg));
  __ Call(kJavaScriptCallCodeStartRegister);

  __ RecordComment("--- InterpreterEntryReturnPC point ---");
  if (mode == InterpreterEntryTrampolineMode::kDefault) {
    masm->isolate()->heap()->SetInterpreterEntryReturnPCOffset(
        masm->pc_offset());
  } else {
    DCHECK_EQ(mode, InterpreterEntryTrampolineMode::kForProfiling);
    // Both versions must be the same up to this point otherwise the builtins
    // will not be interchangable.
    CHECK_EQ(
        masm->isolate()->heap()->interpreter_entry_return_pc_offset().value(),
        masm->pc_offset());
  }

  // Any returns to the entry trampoline are either due to the return bytecode
  // or the interpreter tail calling a builtin and then a dispatch.

  // Get bytecode array and bytecode offset from the stack frame.
  __ LoadWord(kInterpreterBytecodeArrayRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ LoadWord(kInterpreterBytecodeOffsetRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);

  // Either return, or advance to the next bytecode and dispatch.
  Label do_return;
  __ AddWord(a1, kInterpreterBytecodeArrayRegister,
             kInterpreterBytecodeOffsetRegister);
  __ Lbu(a1, MemOperand(a1));
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, a1, a2, a3,
                                a4, &do_return);
  __ Branch(&do_dispatch);

  __ bind(&do_return);
  // The return value is in a0.
  LeaveInterpreterFrame(masm, t0, t1);
  __ Jump(ra);

  __ bind(&stack_check_interrupt);
  // Modify the bytecode offset in the stack to be kFunctionEntryBytecodeOffset
  // for the call to the StackGuard.
  __ li(kInterpreterBytecodeOffsetRegister,
        Operand(Smi::FromInt(BytecodeArray::kHeaderSize - kHeapObjectTag +
                             kFunctionEntryBytecodeOffset)));
  __ StoreWord(
      kInterpreterBytecodeOffsetRegister,
      MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ CallRuntime(Runtime::kStackGuard);

  // After the call, restore the bytecode array, bytecode offset and accumulator
  // registers again. Also, restore the bytecode offset in the stack to its
  // previous value.
  __ LoadWord(kInterpreterBytecodeArrayRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ li(kInterpreterBytecodeOffsetRegister,
        Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);

  __ SmiTag(a5, kInterpreterBytecodeOffsetRegister);
  __ StoreWord(
      a5, MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  __ Branch(&after_stack_check_interrupt);

#ifndef V8_JITLESS
  __ bind(&flags_need_processing);
  __ OptimizeCodeOrTailCallOptimizedCodeSlot(flags, feedback_vector);
  __ bind(&is_baseline);
  {
    // Load the feedback vector from the closure.
    __ LoadTaggedField(
        feedback_vector,
        FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
    __ LoadTaggedField(
        feedback_vector,
        FieldMemOperand(feedback_vector, FeedbackCell::kValueOffset));

    Label install_baseline_code;
    // Check if feedback vector is valid. If not, call prepare for baseline to
    // allocate it.
    __ LoadTaggedField(
        t0, FieldMemOperand(feedback_vector, HeapObject::kMapOffset));
    __ Lhu(t0, FieldMemOperand(t0, Map::kInstanceTypeOffset));
    __ Branch(&install_baseline_code, ne, t0, Operand(FEEDBACK_VECTOR_TYPE));

    // Check for an tiering state.
    __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
        flags, feedback_vector, CodeKind::BASELINE, &flags_need_processing);

#ifndef V8_ENABLE_LEAPTIERING
    // TODO(olivf, 42204201): This fastcase is difficult to support with the
    // sandbox as it requires getting write access to the dispatch table. See
    // `JSFunction::UpdateCode`. We might want to remove it for all
    // configurations as it does not seem to be performance sensitive.
    // Load the baseline code into the closure.
    __ Move(a2, kInterpreterBytecodeArrayRegister);
    static_assert(kJavaScriptCallCodeStartRegister == a2, "ABI mismatch");
    __ ReplaceClosureCodeWithOptimizedCode(a2, closure);
    __ JumpCodeObject(a2, kJSEntrypointTag);
#endif  // V8_ENABLE_LEAPTIERING

    __ bind(&install_baseline_code);
    __ GenerateTailCallToReturnedCode(Runtime::kInstallBaselineCode);
  }
#endif  // !V8_JITLESS

  __ bind(&compile_lazy);
  __ GenerateTailCallToReturnedCode(Runtime::kCompileLazy);
  // Unreachable code.
  __ break_(0xCC);

  __ bind(&stack_overflow);
  __ CallRuntime(Runtime::kThrowStackOverflow);
  // Unreachable code.
  __ break_(0xCC);
}

static void GenerateInterpreterPushArgs(MacroAssembler* masm, Register num_args,
                                        Register start_address,
                                        Register scratch) {
  ASM_CODE_COMMENT(masm);
  // Find the address of the last argument.
  __ SubWord(scratch, num_args, Operand(1));
  __ SllWord(scratch, scratch, kSystemPointerSizeLog2);
  __ SubWord(start_address, start_address, scratch);

  // Push the arguments.
  __ PushArray(start_address, num_args,
               MacroAssembler::PushArrayOrder::kReverse);
}

// static
void Builtins::Generate_InterpreterPushArgsThenCallImpl(
    MacroAssembler* masm, ConvertReceiverMode receiver_mode,
    InterpreterPushArgsMode mode) {
  DCHECK(mode != InterpreterPushArgsMode::kArrayFunction);
  // ----------- S t a t e -------------
  //  -- a0 : the number of arguments
  //  -- a2 : the address of the first argument to be pushed. Subsequent
  //          arguments should be consecutive above this, in the same order as
  //          they are to be pushed onto the stack.
  //  -- a1 : the target to call (can be any Object).
  // -----------------------------------
  Label stack_overflow;
  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ SubWord(a0, a0, Operand(1));
  }

  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ SubWord(a3, a0, Operand(kJSArgcReceiverSlots));
  } else {
    __ Move(a3, a0);
  }
  __ StackOverflowCheck(a3, a4, t0, &stack_overflow);

  // This function modifies a2 and a4.
  GenerateInterpreterPushArgs(masm, a3, a2, a4);
  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ PushRoot(RootIndex::kUndefinedValue);
  }

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Pass the spread in the register a2.
    // a2 already points to the penultime argument, the spread
    // is below that.
    __ LoadWord(a2, MemOperand(a2, -kSystemPointerSize));
  }

  // Call the target.
  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    __ TailCallBuiltin(Builtin::kCallWithSpread);
  } else {
    __ TailCallBuiltin(Builtins::Call(receiver_mode));
  }

  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    // Unreachable code.
    __ break_(0xCC);
  }
}

// static
void Builtins::Generate_InterpreterPushArgsThenConstructImpl(
    MacroAssembler* masm, InterpreterPushArgsMode mode) {
  // ----------- S t a t e -------------
  // -- a0 : argument count
  // -- a3 : new target
  // -- a1 : constructor to call
  // -- a2 : allocation site feedback if available, undefined otherwise.
  // -- a4 : address of the first argument
  // -----------------------------------
  Label stack_overflow;
  __ StackOverflowCheck(a0, a5, t0, &stack_overflow);

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ SubWord(a0, a0, Operand(1));
  }
  Register argc_without_receiver = a6;
  __ SubWord(argc_without_receiver, a0, Operand(kJSArgcReceiverSlots));
  // Push the arguments, This function modifies a4 and a5.
  GenerateInterpreterPushArgs(masm, argc_without_receiver, a4, a5);

  // Push a slot for the receiver.
  __ push(zero_reg);

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Pass the spread in the register a2.
    // a4 already points to the penultimate argument, the spread
    // lies in the next interpreter register.
    __ LoadWord(a2, MemOperand(a4, -kSystemPointerSize));
  } else {
    __ AssertUndefinedOrAllocationSite(a2, t0);
  }

  if (mode == InterpreterPushArgsMode::kArrayFunction) {
    __ AssertFunction(a1);

    // Tail call to the function-specific construct stub (still in the caller
    // context at this point).
    __ TailCallBuiltin(Builtin::kArrayConstructorImpl);
  } else if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Call the constructor with a0, a1, and a3 unmodified.
    __ TailCallBuiltin(Builtin::kConstructWithSpread);
  } else {
    DCHECK_EQ(InterpreterPushArgsMode::kOther, mode);
    // Call the constructor with a0, a1, and a3 unmodified.
    __ TailCallBuiltin(Builtin::kConstruct);
  }

  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    // Unreachable code.
    __ break_(0xCC);
  }
}

// static
void Builtins::Generate_ConstructForwardAllArgsImpl(
    MacroAssembler* masm, ForwardWhichFrame which_frame) {
  // ----------- S t a t e -------------
  // -- a3 : new target
  // -- a1 : constructor to call
  // -----------------------------------
  Label stack_overflow;

  // Load the frame pointer into a4.
  switch (which_frame) {
    case ForwardWhichFrame::kCurrentFrame:
      __ Move(a4, fp);
      break;
    case ForwardWhichFrame::kParentFrame:
      __ LoadWord(a4, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
      break;
  }

  // Load the argument count into a0.
  __ LoadWord(a0, MemOperand(a4, StandardFrameConstants::kArgCOffset));
  __ StackOverflowCheck(a0, a5, t0, &stack_overflow);

  // Point a4 to the base of the argument list to forward, excluding the
  // receiver.
  __ AddWord(a4, a4,
             Operand((StandardFrameConstants::kFixedSlotCountAboveFp + 1) *
                     kSystemPointerSize));

  // Copy arguments on the stack. a5 is a scratch register.
  Register argc_without_receiver = a6;
  __ SubWord(argc_without_receiver, a0, Operand(kJSArgcReceiverSlots));
  __ PushArray(a4, argc_without_receiver);

  // Push a slot for the receiver.
  __ push(zero_reg);

  // Call the constructor with a0, a1, and a3 unmodified.
  __ TailCallBuiltin(Builtin::kConstruct);

  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    // Unreachable code.
    __ break_(0xCC);
  }
}

namespace {

void NewImplicitReceiver(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  // -- a0 : the number of arguments
  // -- a1 : constructor to call (checked to be a JSFunction)
  // -- a3 : new target
  //
  //  Stack:
  //  -- Implicit Receiver
  //  -- [arguments without receiver]
  //  -- Implicit Receiver
  //  -- Context
  //  -- FastConstructMarker
  //  -- FramePointer
  // -----------------------------------
  Register implicit_receiver = a4;

  // Save live registers.
  __ SmiTag(a0);
  __ Push(a0, a1, a3);
  __ CallBuiltin(Builtin::kFastNewObject);
  // Save result.
  __ mv(implicit_receiver, a0);
  __ Pop(a0, a1, a3);
  __ SmiUntag(a0);

  // Patch implicit receiver (in arguments)
  __ StoreReceiver(implicit_receiver);
  // Patch second implicit (in construct frame)
  __ StoreWord(
      implicit_receiver,
      MemOperand(fp, FastConstructFrameConstants::kImplicitReceiverOffset));

  // Restore context.
  __ LoadWord(cp, MemOperand(fp, FastConstructFrameConstants::kContextOffset));
}

}  // namespace

// static
void Builtins::Generate_InterpreterPushArgsThenFastConstructFunction(
    MacroAssembler* masm) {
  // ----------- S t a t e -------------
  // -- a0 : argument count
  // -- a1 : constructor to call (checked to be a JSFunction)
  // -- a3 : new target
  // -- a4 : address of the first argument
  // -- cp : context pointer
  // -----------------------------------
  __ AssertFunction(a1);

  // Check if target has a [[Construct]] internal method.
  Label non_constructor;
  __ LoadMap(a2, a1);
  __ Lbu(a2, FieldMemOperand(a2, Map::kBitFieldOffset));
  __ And(a2, a2, Operand(Map::Bits1::IsConstructorBit::kMask));
  __ Branch(&non_constructor, eq, a2, Operand(zero_reg));

  // Add a stack check before pushing arguments.
  Label stack_overflow;
  __ StackOverflowCheck(a0, a2, a5, &stack_overflow);

  // Enter a construct frame.
  FrameScope scope(masm, StackFrame::MANUAL);
  __ EnterFrame(StackFrame::FAST_CONSTRUCT);

  // Implicit receiver stored in the construct frame.
  __ LoadRoot(a2, RootIndex::kTheHoleValue);
  __ Push(cp, a2);

  // Push arguments + implicit receiver.
  Register argc_without_receiver = a7;
  __ SubWord(argc_without_receiver, a0, Operand(kJSArgcReceiverSlots));
  GenerateInterpreterPushArgs(masm, argc_without_receiver, a4, a5);
  __ Push(a2);

  // Check if it is a builtin call.
  Label builtin_call;
  __ LoadTaggedField(
      a2, FieldMemOperand(a1, JSFunction::kSharedFunctionInfoOffset));
  __ Load32U(a2, FieldMemOperand(a2, SharedFunctionInfo::kFlagsOffset));
  __ And(a5, a2, Operand(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ Branch(&builtin_call, ne, a5, Operand(zero_reg));

  // Check if we need to create an implicit receiver.
  Label not_create_implicit_receiver;
  __ DecodeField<SharedFunctionInfo::FunctionKindBits>(a2);
  __ JumpIfIsInRange(
      a2, static_cast<uint32_t>(FunctionKind::kDefaultDerivedConstructor),
      static_cast<uint32_t>(FunctionKind::kDerivedConstructor),
      &not_create_implicit_receiver);
  NewImplicitReceiver(masm);
  __ bind(&not_create_implicit_receiver);

  // Call the function.
  __ InvokeFunctionWithNewTarget(a1, a3, a0, InvokeType::kCall);

  // ----------- S t a t e -------------
  //  -- x0     constructor result
  //
  //  Stack:
  //  -- Implicit Receiver
  //  -- Context
  //  -- FastConstructMarker
  //  -- FramePointer
  // -----------------------------------

  // Store offset of return address for deoptimizer.
  masm->isolate()->heap()->SetConstructStubInvokeDeoptPCOffset(
      masm->pc_offset());

  // If the result is an object (in the ECMA sense), we should get rid
  // of the receiver and use the result; see ECMA-262 section 13.2.2-7
  // on page 74.
  Label use_receiver, do_throw, leave_and_return, check_receiver;

  // If the result is undefined, we jump out to using the implicit receiver.
  __ JumpIfNotRoot(a0, RootIndex::kUndefinedValue, &check_receiver);
  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ LoadWord(
      a0, MemOperand(fp, FastConstructFrameConstants::kImplicitReceiverOffset));
  __ JumpIfRoot(a0, RootIndex::kTheHoleValue, &do_throw);

  __ bind(&leave_and_return);
  // Leave construct frame.
  __ LeaveFrame(StackFrame::FAST_CONSTRUCT);
  __ Ret();

  // Otherwise we do a smi check and fall through to check if the return value
  // is a valid receiver.
  __ bind(&check_receiver);

  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ JumpIfSmi(a0, &use_receiver);

  // Check if the type of the result is not an object in the ECMA sense.
  __ JumpIfJSAnyIsNotPrimitive(a0, a4, &leave_and_return);
  __ Branch(&use_receiver);

  __ bind(&builtin_call);
  // TODO(victorgomes): Check the possibility to turn this into a tailcall.
  __ InvokeFunctionWithNewTarget(a1, a3, a0, InvokeType::kCall);
  __ LeaveFrame(StackFrame::FAST_CONSTRUCT);
  __ Ret();

  __ bind(&do_throw);
  // Restore the context from the frame.
  __ LoadWord(cp, MemOperand(fp, FastConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  // Unreachable code.
  __ Trap();

  __ bind(&stack_overflow);
  __ TailCallRuntime(Runtime::kThrowStackOverflow);
  // Unreachable code.
  __ Trap();

  // Called Construct on an Object that doesn't have a [[Construct]] internal
  // method.
  __ bind(&non_constructor);
  __ TailCallBuiltin(Builtin::kConstructedNonConstructable);
}

static void Generate_InterpreterEnterBytecode(MacroAssembler* masm) {
  // Set the return address to the correct point in the interpreter entry
  // trampoline.
  Label builtin_trampoline, trampoline_loaded;
  Tagged<Smi> interpreter_entry_return_pc_offset(
      masm->isolate()->heap()->interpreter_entry_return_pc_offset());
  DCHECK_NE(interpreter_entry_return_pc_offset, Smi::zero());

  // If the SFI function_data is an InterpreterData, the function will have a
  // custom copy of the interpreter entry trampoline for profiling. If so,
  // get the custom trampoline, otherwise grab the entry address of the global
  // trampoline.
  __ LoadWord(t0, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ LoadTaggedField(
      t0, FieldMemOperand(t0, JSFunction::kSharedFunctionInfoOffset));
  __ LoadTrustedPointerField(
      t0, FieldMemOperand(t0, SharedFunctionInfo::kTrustedFunctionDataOffset),
      kUnknownIndirectPointerTag);
  __ GetObjectType(t0, kInterpreterDispatchTableRegister,
                   kInterpreterDispatchTableRegister);
  __ Branch(&builtin_trampoline, ne, kInterpreterDispatchTableRegister,
            Operand(INTERPRETER_DATA_TYPE), Label::Distance::kNear);

  __ LoadProtectedPointerField(
      t0, FieldMemOperand(t0, InterpreterData::kInterpreterTrampolineOffset));
  __ LoadCodeInstructionStart(t0, t0, kJSEntrypointTag);
  __ BranchShort(&trampoline_loaded);

  __ bind(&builtin_trampoline);
  __ li(t0, ExternalReference::
                address_of_interpreter_entry_trampoline_instruction_start(
                    masm->isolate()));
  __ LoadWord(t0, MemOperand(t0));

  __ bind(&trampoline_loaded);
  __ AddWord(ra, t0, Operand(interpreter_entry_return_pc_offset.value()));

  // Initialize the dispatch table register.
  __ li(kInterpreterDispatchTableRegister,
        ExternalReference::interpre
"""


```