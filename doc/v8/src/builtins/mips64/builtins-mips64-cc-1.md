Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code is part of the V8 JavaScript engine and specifically targets the MIPS64 architecture. The file name suggests it contains built-in functions or helper functions for built-ins.

Here's a breakdown of the functions and their likely purpose:

*   `ResetJSFunctionAge`: Resets some age-related information in a `JSFunction` object.
*   `ResetFeedbackVectorOsrUrgency`: Resets the "OSR urgency" flag in a `FeedbackVector`. OSR likely stands for On-Stack Replacement, a mechanism for optimizing code during execution.
*   `Generate_BaselineOutOfLinePrologue`: Generates code for the prologue of a baseline-compiled function that is called "out-of-line". This likely handles tasks like setting up the stack frame, checking for optimization opportunities, and incrementing invocation counts.
*   `Generate_BaselineOutOfLinePrologueDeopt`: Generates code for handling deoptimization from the baseline out-of-line prologue. This involves unwinding the stack and transitioning to the interpreter.
*   `Generate_InterpreterEntryTrampoline`: Generates code for the entry point when a JavaScript function is called and needs to be executed by the interpreter. This involves setting up the interpreter frame, allocating space for local variables, and dispatching to the correct bytecode.
*   `GenerateInterpreterPushArgs`: Helper function to push arguments onto the stack for function calls.
*   `Generate_InterpreterPushArgsThenCallImpl`: Generates code for calling a JavaScript function using the interpreter after pushing arguments onto the stack.
*   `Generate_InterpreterPushArgsThenConstructImpl`: Generates code for calling a JavaScript constructor using the interpreter after pushing arguments onto the stack.
*   `Generate_ConstructForwardAllArgsImpl`: Generates code to forward all arguments from a current or parent frame to a constructor.
*   `NewImplicitReceiver`: Helper function to create an implicit receiver object during constructor calls.
*   `Generate_InterpreterPushArgsThenFastConstructFunction`: Generates code for a fast path for constructing objects using the interpreter, potentially optimizing the receiver creation.
*   `Generate_InterpreterEnterBytecode`: Generates code to enter the interpreter at a specific bytecode offset within a function.
*   `Generate_InterpreterEnterAtNextBytecode`: Generates code to advance the interpreter to the next bytecode instruction in the current function.

Based on the names and operations, the code primarily deals with the execution of JavaScript functions in V8, particularly focusing on the transition between different execution modes (baseline compilation, interpreter) and the setup of stack frames and arguments.

Given the user's constraints, I need to:

1. Identify the main purpose of the code.
2. Acknowledge it's a V8 source file for the MIPS64 architecture.
3. Confirm it's C++ and not Torque-based on the `.cc` extension.
4. Note its relevance to JavaScript function execution.
5. Summarize its overall functionality based on the individual functions.
这是v8源代码文件 `v8/src/builtins/mips64/builtins-mips64.cc` 的一部分，它主要负责 **为 MIPS64 架构生成 V8 引擎的内置函数 (builtins) 的汇编代码**。

由于文件以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码。

这个文件与 javascript 的功能有密切关系，因为它实现了 V8 引擎执行 JavaScript 代码的关键部分，例如函数调用、构造函数调用以及与解释器之间的交互。

**功能归纳:**

这段代码片段主要实现了以下功能：

1. **辅助函数:**
    *   `ResetJSFunctionAge`: 用于重置 `JSFunction` 对象的某些老化信息，这可能与垃圾回收或优化有关。
    *   `ResetFeedbackVectorOsrUrgency`: 用于重置 `FeedbackVector` 对象的 OSR (On-Stack Replacement) 紧急状态。`FeedbackVector` 用于存储函数执行的反馈信息，以便 V8 能够更好地优化代码。

2. **Baseline 编译器的序言 (Prologue):**
    *   `Generate_BaselineOutOfLinePrologue`:  为基线编译器生成的“外部”序言代码。基线编译器是 V8 中一种相对快速的编译器，用于在解释器和完全优化编译器之间提供性能提升。这个序言负责设置栈帧、检查是否需要进行代码优化、更新调用计数等。
    *   `Generate_BaselineOutOfLinePrologueDeopt`:  处理从基线编译器生成的外部序言中反优化的过程。当基线代码无法继续执行时，会跳转到这里，撤销之前的栈帧设置，并调用解释器入口。

3. **解释器入口跳板 (Trampoline):**
    *   `Generate_InterpreterEntryTrampoline`: 生成进入 JavaScript 函数解释器的跳板代码。当一个函数首次被调用或者从非优化代码调用时，会进入解释器。这段代码负责设置解释器栈帧，加载字节码，并跳转到相应的字节码处理程序。

4. **解释器辅助函数 (Push Arguments):**
    *   `GenerateInterpreterPushArgs`:  一个辅助函数，用于将参数压入栈中，为函数调用做准备。
    *   `Generate_InterpreterPushArgsThenCallImpl`: 生成代码，在将参数压入栈后，使用解释器调用 JavaScript 函数。
    *   `Generate_InterpreterPushArgsThenConstructImpl`: 生成代码，在将参数压入栈后，使用解释器调用 JavaScript 构造函数。

5. **构造函数调用辅助函数:**
    *   `Generate_ConstructForwardAllArgsImpl`: 生成代码，将所有参数从当前或父级栈帧转发到构造函数。
    *   `NewImplicitReceiver`:  在快速构造函数调用中创建一个隐式的接收者对象。
    *   `Generate_InterpreterPushArgsThenFastConstructFunction`:  生成代码，用于执行更快速的构造函数调用路径，尤其是在已知目标是函数的情况下。

6. **解释器执行控制:**
    *   `Generate_InterpreterEnterBytecode`:  生成代码，直接进入解释器的字节码执行循环。
    *   `Generate_InterpreterEnterAtNextBytecode`: 生成代码，使解释器执行下一个字节码指令。

**总结来说，这段代码是 V8 引擎在 MIPS64 架构上执行 JavaScript 代码的核心组成部分，它涵盖了从函数调用准备、解释器执行到基线编译优化的关键流程。** 它确保了 JavaScript 代码能够在 MIPS64 架构的系统上正确高效地运行。

由于这是一个代码片段，没有完整的上下文，我们无法进行详细的代码逻辑推理或举例说明用户常见的编程错误。不过，基于这些函数的名称和操作，我们可以推断出一些与 JavaScript 功能的关系。

Prompt: 
```
这是目录为v8/src/builtins/mips64/builtins-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/mips64/builtins-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能

"""
e(MacroAssembler* masm, Register js_function,
                        Register scratch) {
  __ Ld(scratch,
        FieldMemOperand(js_function, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, scratch);
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
void Builtins::Generate_BaselineOutOfLinePrologue(MacroAssembler* masm) {
  UseScratchRegisterScope temps(masm);
  temps.Include({s1, s2, s3});
  auto descriptor =
      Builtins::CallInterfaceDescriptorFor(Builtin::kBaselineOutOfLinePrologue);
  Register closure = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kClosure);
  // Load the feedback vector from the closure.
  Register feedback_cell = temps.Acquire();
  Register feedback_vector = temps.Acquire();
  __ Ld(feedback_cell,
        FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  __ Ld(feedback_vector,
        FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset));
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ AssertFeedbackVector(feedback_vector, scratch);
  }
  // Check for an tiering state.
  Label flags_need_processing;
  Register flags = no_reg;
  {
    UseScratchRegisterScope temps(masm);
    flags = temps.Acquire();
    // flags will be used only in |flags_need_processing|
    // and outside it can be reused.
    __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
        flags, feedback_vector, CodeKind::BASELINE, &flags_need_processing);
  }
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
    __ Addu(invocation_count, invocation_count, Operand(1));
    __ Sw(invocation_count,
          FieldMemOperand(feedback_vector,
                          FeedbackVector::kInvocationCountOffset));
  }

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  {
    ASM_CODE_COMMENT_STRING(masm, "Frame Setup");
    // Normally the first thing we'd do here is Push(ra, fp), but we already
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

    {
      UseScratchRegisterScope temps(masm);
      Register invocation_count = temps.Acquire();
      __ AssertFeedbackVector(feedback_vector, invocation_count);
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
    __ Dsubu(sp_minus_frame_size, sp, frame_size);
    Register interrupt_limit = temps.Acquire();
    __ LoadStackLimit(interrupt_limit,
                      MacroAssembler::StackLimitKind::kInterruptStackLimit);
    __ Branch(&call_stack_guard, Uless, sp_minus_frame_size,
              Operand(interrupt_limit));
  }

  // Do "fast" return to the caller pc in ra.
  // TODO(v8:11429): Document this frame setup better.
  __ Ret();

  __ bind(&flags_need_processing);
  {
    ASM_CODE_COMMENT_STRING(masm, "Optimized marker check");
    UseScratchRegisterScope temps(masm);
    temps.Exclude(flags);
    // Ensure the flags is not allocated again.
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
  temps.Exclude({s1, s2, s3});
}

// static
void Builtins::Generate_BaselineOutOfLinePrologueDeopt(MacroAssembler* masm) {
  // We're here because we got deopted during BaselineOutOfLinePrologue's stack
  // check. Undo all its frame creation and call into the interpreter instead.

  // Drop the feedback vector, the bytecode offset (was the feedback vector
  // but got replaced during deopt) and bytecode array.
  __ Drop(3);

  // Context, closure, argc.
  __ Pop(kContextRegister, kJavaScriptCallTargetRegister,
         kJavaScriptCallArgCountRegister);

  // Drop frame pointer
  __ LeaveFrame(StackFrame::BASELINE);

  // Enter the interpreter.
  __ TailCallBuiltin(Builtin::kInterpreterEntryTrampoline);
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
// frame-constants.h for its layout.
void Builtins::Generate_InterpreterEntryTrampoline(
    MacroAssembler* masm, InterpreterEntryTrampolineMode mode) {
  Register closure = a1;

  // Get the bytecode array from the function object and load it into
  // kInterpreterBytecodeArrayRegister.
  __ Ld(kScratchReg,
        FieldMemOperand(closure, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, kScratchReg);

  // The bytecode array could have been flushed from the shared function info,
  // if so, call into CompileLazy.
  Label is_baseline, compile_lazy;
  GetSharedFunctionInfoBytecodeOrBaseline(
      masm, kScratchReg, kInterpreterBytecodeArrayRegister, kScratchReg2,
      &is_baseline, &compile_lazy);

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
  __ Addu(a4, a4, Operand(1));
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
    __ Dsubu(a5, sp, Operand(a4));
    __ LoadStackLimit(a2, MacroAssembler::StackLimitKind::kRealStackLimit);
    __ Branch(&stack_overflow, lo, a5, Operand(a2));

    // If ok, push undefined as the initial value for all register file entries.
    Label loop_header;
    Label loop_check;
    __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
    __ Branch(&loop_check);
    __ bind(&loop_header);
    // TODO(rmcilroy): Consider doing more than one push per loop iteration.
    __ push(kInterpreterAccumulatorRegister);
    // Continue loop if not done.
    __ bind(&loop_check);
    __ Dsubu(a4, a4, Operand(kSystemPointerSize));
    __ Branch(&loop_header, ge, a4, Operand(zero_reg));
  }

  // If the bytecode array has a valid incoming new target or generator object
  // register, initialize it with incoming value which was passed in r3.
  Label no_incoming_new_target_or_generator_register;
  __ Lw(a5, FieldMemOperand(
                kInterpreterBytecodeArrayRegister,
                BytecodeArray::kIncomingNewTargetOrGeneratorRegisterOffset));
  __ Branch(&no_incoming_new_target_or_generator_register, eq, a5,
            Operand(zero_reg));
  __ Dlsa(a5, fp, a5, kSystemPointerSizeLog2);
  __ Sd(a3, MemOperand(a5));
  __ bind(&no_incoming_new_target_or_generator_register);

  // Perform interrupt stack check.
  // TODO(solanes): Merge with the real stack limit check above.
  Label stack_check_interrupt, after_stack_check_interrupt;
  __ LoadStackLimit(a5, MacroAssembler::StackLimitKind::kInterruptStackLimit);
  __ Branch(&stack_check_interrupt, lo, sp, Operand(a5));
  __ bind(&after_stack_check_interrupt);

  // The accumulator is already loaded with undefined.

  // Load the dispatch table into a register and dispatch to the bytecode
  // handler at the current bytecode offset.
  Label do_dispatch;
  __ bind(&do_dispatch);
  __ li(kInterpreterDispatchTableRegister,
        ExternalReference::interpreter_dispatch_table_address(masm->isolate()));
  __ Daddu(a0, kInterpreterBytecodeArrayRegister,
           kInterpreterBytecodeOffsetRegister);
  __ Lbu(a7, MemOperand(a0));
  __ Dlsa(kScratchReg, kInterpreterDispatchTableRegister, a7,
          kSystemPointerSizeLog2);
  __ Ld(kJavaScriptCallCodeStartRegister, MemOperand(kScratchReg));
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
  __ Ld(kInterpreterBytecodeArrayRegister,
        MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ Ld(kInterpreterBytecodeOffsetRegister,
        MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);

  // Either return, or advance to the next bytecode and dispatch.
  Label do_return;
  __ Daddu(a1, kInterpreterBytecodeArrayRegister,
           kInterpreterBytecodeOffsetRegister);
  __ Lbu(a1, MemOperand(a1));
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, a1, a2, a3,
                                a4, &do_return);
  __ jmp(&do_dispatch);

  __ bind(&do_return);
  // The return value is in v0.
  LeaveInterpreterFrame(masm, t0, t1);
  __ Jump(ra);

  __ bind(&stack_check_interrupt);
  // Modify the bytecode offset in the stack to be kFunctionEntryBytecodeOffset
  // for the call to the StackGuard.
  __ li(kInterpreterBytecodeOffsetRegister,
        Operand(Smi::FromInt(BytecodeArray::kHeaderSize - kHeapObjectTag +
                             kFunctionEntryBytecodeOffset)));
  __ Sd(kInterpreterBytecodeOffsetRegister,
        MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ CallRuntime(Runtime::kStackGuard);

  // After the call, restore the bytecode array, bytecode offset and accumulator
  // registers again. Also, restore the bytecode offset in the stack to its
  // previous value.
  __ Ld(kInterpreterBytecodeArrayRegister,
        MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ li(kInterpreterBytecodeOffsetRegister,
        Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);

  __ SmiTag(a5, kInterpreterBytecodeOffsetRegister);
  __ Sd(a5, MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  __ jmp(&after_stack_check_interrupt);

#ifndef V8_JITLESS
  __ bind(&flags_need_processing);
  __ OptimizeCodeOrTailCallOptimizedCodeSlot(flags, feedback_vector);
  __ bind(&is_baseline);
  {
    // Load the feedback vector from the closure.
    __ Ld(feedback_vector,
          FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
    __ Ld(feedback_vector,
          FieldMemOperand(feedback_vector, FeedbackCell::kValueOffset));

    Label install_baseline_code;
    // Check if feedback vector is valid. If not, call prepare for baseline to
    // allocate it.
    __ Ld(t0, FieldMemOperand(feedback_vector, HeapObject::kMapOffset));
    __ Lhu(t0, FieldMemOperand(t0, Map::kInstanceTypeOffset));
    __ Branch(&install_baseline_code, ne, t0, Operand(FEEDBACK_VECTOR_TYPE));

    // Check for an tiering state.
    __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
        flags, feedback_vector, CodeKind::BASELINE, &flags_need_processing);

#ifndef V8_ENABLE_LEAPTIERING
    // TODO(mips64, 42204201): This fastcase is difficult to support with the
    // sandbox as it requires getting write access to the dispatch table. See
    // `JSFunction::UpdateCode`. We might want to remove it for all
    // configurations as it does not seem to be performance sensitive.

    // Load the baseline code into the closure.
    __ Move(a2, kInterpreterBytecodeArrayRegister);
    static_assert(kJavaScriptCallCodeStartRegister == a2, "ABI mismatch");
    __ ReplaceClosureCodeWithOptimizedCode(a2, closure, t0, t1);
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
                                        Register scratch, Register scratch2) {
  // Find the address of the last argument.
  __ Dsubu(scratch, num_args, Operand(1));
  __ dsll(scratch, scratch, kSystemPointerSizeLog2);
  __ Dsubu(start_address, start_address, scratch);

  // Push the arguments.
  __ PushArray(start_address, num_args, scratch, scratch2,
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
    __ Dsubu(a0, a0, Operand(1));
  }

  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ Dsubu(a3, a0, Operand(kJSArgcReceiverSlots));
  } else {
    __ mov(a3, a0);
  }

  __ StackOverflowCheck(a3, a4, t0, &stack_overflow);

  // This function modifies a2, t0 and a4.
  GenerateInterpreterPushArgs(masm, a3, a2, a4, t0);

  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ PushRoot(RootIndex::kUndefinedValue);
  }

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Pass the spread in the register a2.
    // a2 already points to the penultime argument, the spread
    // is below that.
    __ Ld(a2, MemOperand(a2, -kSystemPointerSize));
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
    __ Dsubu(a0, a0, Operand(1));
  }

  Register argc_without_receiver = a6;
  __ Dsubu(argc_without_receiver, a0, Operand(kJSArgcReceiverSlots));
  // Push the arguments, This function modifies t0, a4 and a5.
  GenerateInterpreterPushArgs(masm, argc_without_receiver, a4, a5, t0);

  // Push a slot for the receiver.
  __ push(zero_reg);

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Pass the spread in the register a2.
    // a4 already points to the penultimate argument, the spread
    // lies in the next interpreter register.
    __ Ld(a2, MemOperand(a4, -kSystemPointerSize));
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
      __ Ld(a4, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
      break;
  }

  // Load the argument count into a0.
  __ Ld(a0, MemOperand(a4, StandardFrameConstants::kArgCOffset));
  __ StackOverflowCheck(a0, a5, t0, &stack_overflow);

  // Point a4 to the base of the argument list to forward, excluding the
  // receiver.
  __ Daddu(a4, a4,
           Operand((StandardFrameConstants::kFixedSlotCountAboveFp + 1) *
                   kSystemPointerSize));

  // Copy arguments on the stack. a5 and t0 are scratch registers.
  Register argc_without_receiver = a6;
  __ Dsubu(argc_without_receiver, a0, Operand(kJSArgcReceiverSlots));
  __ PushArray(a4, argc_without_receiver, a5, t0);

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

  // Save live registers.
  __ SmiTag(a0);
  __ Push(a0, a1, a3);
  __ CallBuiltin(Builtin::kFastNewObject);
  __ Pop(a0, a1, a3);
  __ SmiUntag(a0);

  // Patch implicit receiver (in arguments)
  __ StoreReceiver(v0);
  // Patch second implicit (in construct frame)
  __ Sd(v0,
        MemOperand(fp, FastConstructFrameConstants::kImplicitReceiverOffset));

  // Restore context.
  __ Ld(cp, MemOperand(fp, FastConstructFrameConstants::kContextOffset));
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
  __ Dsubu(argc_without_receiver, a0, Operand(kJSArgcReceiverSlots));
  GenerateInterpreterPushArgs(masm, argc_without_receiver, a4, a5, a6);
  __ Push(a2);

  // Check if it is a builtin call.
  Label builtin_call;
  __ Ld(a2, FieldMemOperand(a1, JSFunction::kSharedFunctionInfoOffset));
  __ Lwu(a2, FieldMemOperand(a2, SharedFunctionInfo::kFlagsOffset));
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
  //  -- v0     constructor result
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
  __ JumpIfNotRoot(v0, RootIndex::kUndefinedValue, &check_receiver);

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ Ld(v0,
        MemOperand(fp, FastConstructFrameConstants::kImplicitReceiverOffset));
  __ JumpIfRoot(v0, RootIndex::kTheHoleValue, &do_throw);

  __ bind(&leave_and_return);
  // Leave construct frame.
  __ LeaveFrame(StackFrame::FAST_CONSTRUCT);
  __ Ret();

  // Otherwise we do a smi check and fall through to check if the return value
  // is a valid receiver.
  __ bind(&check_receiver);

  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ JumpIfSmi(v0, &use_receiver);

  // Check if the type of the result is not an object in the ECMA sense.
  __ GetObjectType(v0, a4, a4);
  __ Branch(&leave_and_return, hs, a4, Operand(FIRST_JS_RECEIVER_TYPE));
  __ Branch(&use_receiver);

  __ bind(&builtin_call);
  // TODO(victorgomes): Check the possibility to turn this into a tailcall.
  __ InvokeFunctionWithNewTarget(a1, a3, a0, InvokeType::kCall);
  __ LeaveFrame(StackFrame::FAST_CONSTRUCT);
  __ Ret();

  __ bind(&do_throw);
  // Restore the context from the frame.
  __ Ld(cp, MemOperand(fp, FastConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  // Unreachable code.
  __ break_(0xCC);

  __ bind(&stack_overflow);
  __ TailCallRuntime(Runtime::kThrowStackOverflow);
  // Unreachable code.
  __ break_(0xCC);

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
  __ Ld(t0, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ Ld(t0, FieldMemOperand(t0, JSFunction::kSharedFunctionInfoOffset));
  __ Ld(t0,
        FieldMemOperand(t0, SharedFunctionInfo::kTrustedFunctionDataOffset));
  __ GetObjectType(t0, kInterpreterDispatchTableRegister,
                   kInterpreterDispatchTableRegister);
  __ Branch(&builtin_trampoline, ne, kInterpreterDispatchTableRegister,
            Operand(INTERPRETER_DATA_TYPE));

  __ Ld(t0, FieldMemOperand(t0, InterpreterData::kInterpreterTrampolineOffset));
  __ LoadCodeInstructionStart(t0, t0, kJSEntrypointTag);
  __ Branch(&trampoline_loaded);

  __ bind(&builtin_trampoline);
  __ li(t0, ExternalReference::
                address_of_interpreter_entry_trampoline_instruction_start(
                    masm->isolate()));
  __ Ld(t0, MemOperand(t0));

  __ bind(&trampoline_loaded);
  __ Daddu(ra, t0, Operand(interpreter_entry_return_pc_offset.value()));

  // Initialize the dispatch table register.
  __ li(kInterpreterDispatchTableRegister,
        ExternalReference::interpreter_dispatch_table_address(masm->isolate()));

  // Get the bytecode array pointer from the frame.
  __ Ld(kInterpreterBytecodeArrayRegister,
        MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));

  if (v8_flags.debug_code) {
    // Check function data field is actually a BytecodeArray object.
    __ SmiTst(kInterpreterBytecodeArrayRegister, kScratchReg);
    __ Assert(ne,
              AbortReason::kFunctionDataShouldBeBytecodeArrayOnInterpreterEntry,
              kScratchReg, Operand(zero_reg));
    __ GetObjectType(kInterpreterBytecodeArrayRegister, a1, a1);
    __ Assert(eq,
              AbortReason::kFunctionDataShouldBeBytecodeArrayOnInterpreterEntry,
              a1, Operand(BYTECODE_ARRAY_TYPE));
  }

  // Get the target bytecode offset from the frame.
  __ SmiUntag(kInterpreterBytecodeOffsetRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  if (v8_flags.debug_code) {
    Label okay;
    __ Branch(&okay, ge, kInterpreterBytecodeOffsetRegister,
              Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));
    // Unreachable code.
    __ break_(0xCC);
    __ bind(&okay);
  }

  // Dispatch to the target bytecode.
  __ Daddu(a1, kInterpreterBytecodeArrayRegister,
           kInterpreterBytecodeOffsetRegister);
  __ Lbu(a7, MemOperand(a1));
  __ Dlsa(a1, kInterpreterDispatchTableRegister, a7, kSystemPointerSizeLog2);
  __ Ld(kJavaScriptCallCodeStartRegister, MemOperand(a1));
  __ Jump(kJavaScriptCallCodeStartRegister);
}

void Builtins::Generate_InterpreterEnterAtNextBytecode(MacroAssembler* masm) {
  // Advance the current bytecode offset stored within the given interpreter
  // stack frame. This simulates what all bytecode handlers do upon completion
  // of the underlying operation.
  __ Ld(kInterpreterBytecodeArrayRegister,
        MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ Ld(kInterpreterBytecodeOffsetRegister,
        MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);

  Label enter_bytecode, function_entry_bytecode;
  __ Branch(&function_entry_bytecode, eq, kInterpreterBytecodeOffsetRegister,
            Operand(BytecodeArray::kHeaderSize - kHeapObjectTag +
                    kFunctionEntryBytecodeOffset));

  // Load the current bytecode.
  __ Daddu(a1, kInterpreterBytecodeArrayRegister,
           kInterpreterBytecodeOffsetRegister);
  __ Lbu(a1, MemOperand(a1));

  // Advance to the next bytecode.
  Label if_return;
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, a1, a2, a3,
                                a4, &if_return);


"""


```