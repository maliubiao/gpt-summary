Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/builtins/x64/builtins-x64.cc`.

Here's a breakdown of the code's responsibilities:

1. **Generator Resume:** Handles the resumption of JavaScript generator functions.
2. **Interpreter Frame Management:**  Provides a function to tear down interpreter frames.
3. **Bytecode Offset Advancement:**  A utility function to move the interpreter's bytecode pointer forward, handling wide and extra-wide opcodes and return opcodes.
4. **Function Age Reset:** Functions to reset the optimization "age" of JavaScript functions and their shared information.
5. **Interpreter Entry Trampoline:** The core logic for entering a JavaScript function through the interpreter. This involves setting up the interpreter frame, handling stack checks, and dispatching to the correct bytecode handler.
6. **Interpreter Argument Pushing:**  Functions to push arguments onto the stack in preparation for function calls within the interpreter.
7. **Interpreter Calls and Constructs:** Implementations for making regular calls and constructor calls from within the interpreter, including handling spread syntax.
8. **Argument Forwarding:** A mechanism for forwarding arguments from one stack frame to another, used in constructors.
9. **Fast Construction:** Optimized path for constructing objects with functions that have a `[[Construct]]` internal method.

Therefore, the primary focus of this code is on the *execution of JavaScript code within V8's interpreter*, specifically on the x64 architecture. It handles the setup, execution, and teardown of interpreter frames and manages the flow of control within interpreted functions.
这是 `v8/src/builtins/x64/builtins-x64.cc` 源代码的第 2 部分，主要关注以下功能：

1. **生成器函数的恢复执行 (Generator Resume):**
   - 当一个 JavaScript 生成器函数通过 `yield` 暂停后，需要恢复执行时，这段代码负责处理参数的准备和跳转到生成器函数的执行入口。
   - 它会从生成器对象中取出参数，并将它们压入栈中，然后跳转到生成器函数的代码入口点继续执行。
   - 涉及到调试器的步进 (stepping) 功能。

   **假设输入与输出：**
   - **假设输入:** 一个已暂停的生成器对象 `rdx`，以及恢复执行时可能传入的参数（通过栈或寄存器）。
   - **输出:**  将生成器对象的参数和接收者压入栈中，并将控制权转移到生成器函数的执行代码。

   **JavaScript 示例:**
   ```javascript
   function* myGenerator(a, b) {
     yield a + b;
     yield a * b;
   }

   const gen = myGenerator(2, 3);
   console.log(gen.next()); // { value: 5, done: false }
   console.log(gen.next(10)); // 这里触发 builtins-x64.cc 中的生成器恢复逻辑，假设传入参数 10
   ```
   在第二个 `gen.next(10)` 调用时，`builtins-x64.cc` 中的代码会负责将 `10` 作为参数（尽管在这个例子中 `myGenerator` 并没有使用传递给 `next` 的参数）准备好，并跳转到 `myGenerator` 内部 `yield` 之后的代码继续执行。

2. **离开解释器栈帧 (Leave Interpreter Frame):**
   - 提供一个函数 `LeaveInterpreterFrame`，用于在解释器执行完毕后清理栈帧，恢复调用者的状态。
   - 它会根据实际参数和形式参数的数量来调整栈指针，并执行 `leave` 指令来清理栈帧。

3. **字节码偏移量前进或返回 (AdvanceBytecodeOffsetOrReturn):**
   - 这是一个核心的辅助函数，用于模拟解释器执行完一个字节码后的行为。
   - 它会根据当前字节码的类型，更新字节码偏移量，指向下一个要执行的字节码。
   - 特殊处理了 `Wide` 和 `ExtraWide` 前缀字节码以及 `JumpLoop` 字节码。
   - 如果遇到 `return` 相关的字节码，则跳转到指定的返回标签。

   **假设输入与输出：**
   - **假设输入:** 当前的字节码数组 `bytecode_array`，当前的字节码偏移量 `bytecode_offset`，当前的字节码 `bytecode`。
   - **输出:**  更新后的字节码偏移量，指向下一个要执行的字节码的开始位置。如果是 `return` 字节码，则跳转到 `if_return` 标签。

4. **重置共享函数信息和 JS 函数的 Age 属性 (Reset SharedFunctionInfoAge, ResetJSFunctionAge):**
   - 这两个函数用于重置 `SharedFunctionInfo` 和 `JSFunction` 对象的 `age` 属性。
   - `age` 属性通常用于 V8 的优化管道中，标记函数被调用的次数或时间，以决定是否进行进一步的优化。

5. **重置 FeedbackVector 的 OSR Urgency (ResetFeedbackVectorOsrUrgency):**
   -  重置 `FeedbackVector` 对象中与 On-Stack Replacement (OSR) 相关的紧急状态位。`FeedbackVector` 用于收集运行时类型信息，帮助优化器进行决策。

6. **解释器入口跳板 (InterpreterEntryTrampoline):**
   - 这是进入 JavaScript 函数解释执行的核心入口点。
   - 它负责创建解释器栈帧，包括保存上下文、函数对象、参数数量等信息。
   - 它会加载函数的字节码数组，并跳转到字节码的第一个指令开始执行。
   - 它还会处理栈溢出检查和中断栈检查。
   - 涉及到与 `FeedbackVector` 相关的优化流程，如检查是否需要编译优化代码。

   **用户常见的编程错误:**
   - **栈溢出:**  如果 JavaScript 代码中存在无限递归或其他导致栈空间耗尽的情况，这段代码中的栈检查会捕获到，并抛出栈溢出错误。
     ```javascript
     function recursiveFunction() {
       recursiveFunction(); // 无终止条件的递归
     }
     recursiveFunction(); // 这会导致栈溢出
     ```

7. **解释器参数压栈后调用 (InterpreterPushArgsThenCallImpl):**
   -  用于在解释器中调用函数时，将参数压入栈中。
   -  支持不同的调用模式，例如处理 `null` 或 `undefined` 作为接收者，以及处理剩余参数 (spread syntax)。

   **JavaScript 示例:**
   ```javascript
   function myFunction(a, b) {
     console.log(a, b);
   }

   const args = [1, 2];
   myFunction(...args); // 这里会触发 builtins-x64.cc 中的参数压栈调用逻辑
   ```

8. **解释器参数压栈后构造 (InterpreterPushArgsThenConstructImpl):**
   -  类似于上面的函数，但用于在解释器中调用构造函数创建对象。
   -  同样支持不同的模式，包括处理剩余参数。

   **JavaScript 示例:**
   ```javascript
   class MyClass {
     constructor(a, b) {
       this.a = a;
       this.b = b;
     }
   }

   const args = [1, 2];
   const obj = new MyClass(...args); // 这里会触发构造函数的参数压栈调用逻辑
   ```

9. **构造函数转发所有参数 (ConstructForwardAllArgsImpl):**
   -  用于在构造函数中转发所有接收到的参数到另一个构造函数。

   **JavaScript 示例:**
   ```javascript
   class Base {
     constructor(a, b) {
       this.a = a;
       this.b = b;
     }
   }

   class Derived extends Base {
     constructor(...args) {
       super(...args); // 转发所有参数给父类构造函数
     }
   }

   const obj = new Derived(1, 2); // 这里会触发参数转发的逻辑
   ```

10. **新的隐式接收者 (NewImplicitReceiver):**
    -  在特定类型的构造函数调用中（例如派生类的构造函数），需要创建一个临时的“隐式接收者”对象。此函数负责创建这个对象。

11. **解释器参数压栈后快速构造函数 (InterpreterPushArgsThenFastConstructFunction):**
    -  一种优化的构造函数调用路径，适用于已知是构造函数的函数。
    -  它会尝试创建一个快速构造栈帧，并直接调用构造函数。

总的来说，这段代码是 V8 引擎在 x64 架构上解释执行 JavaScript 代码的关键组成部分，负责管理函数调用、参数传递、栈帧的创建和销毁，以及处理生成器函数的恢复执行等核心任务。它与 JavaScript 的函数调用、构造函数调用、生成器函数等功能密切相关。

Prompt: 
```
这是目录为v8/src/builtins/x64/builtins-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/x64/builtins-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共7部分，请归纳一下它的功能

"""
meterCount(0)));
    __ j(kGreaterThan, &push_arguments, Label::kNear);
    __ movl(argc, Immediate(JSParameterCount(0)));
    __ jmp(&done_loop, Label::kNear);
#else
    // Generator functions are always created from user code and thus the
    // formal parameter count is never equal to kDontAdaptArgumentsSentinel,
    // which is used only for certain non-generator builtin functions.
#endif  // V8_ENABLE_LEAPTIERING

    __ bind(&push_arguments);
    __ LoadTaggedField(
        params_array,
        FieldOperand(rdx, JSGeneratorObject::kParametersAndRegistersOffset));

    // Exclude receiver.
    __ leal(index, Operand(argc, -1));

    __ bind(&loop);
    __ decl(index);
    __ j(kLessThan, &done_loop, Label::kNear);
    __ PushTaggedField(FieldOperand(params_array, index, times_tagged_size,
                                    OFFSET_OF_DATA_START(FixedArray)),
                       decompr_scratch1);
    __ jmp(&loop);
    __ bind(&done_loop);

    // Push the receiver.
    __ PushTaggedField(FieldOperand(rdx, JSGeneratorObject::kReceiverOffset),
                       decompr_scratch1);
  }

  // Underlying function needs to have bytecode available.
  if (v8_flags.debug_code) {
    Label is_baseline, is_unavailable, ok;
    Register scratch = ReassignRegister(params_array);
    __ LoadTaggedField(
        scratch, FieldOperand(rdi, JSFunction::kSharedFunctionInfoOffset));
    GetSharedFunctionInfoBytecodeOrBaseline(masm, scratch, scratch,
                                            kScratchRegister, &is_baseline,
                                            &is_unavailable);
    __ jmp(&ok);

    __ bind(&is_unavailable);
    __ Abort(AbortReason::kMissingBytecodeArray);

    __ bind(&is_baseline);
    __ IsObjectType(scratch, CODE_TYPE, scratch);
    __ Assert(equal, AbortReason::kMissingBytecodeArray);

    __ bind(&ok);
  }

  // Resume (Ignition/TurboFan) generator object.
  {
    __ PushReturnAddressFrom(return_address);
    // We abuse new.target both to indicate that this is a resume call and to
    // pass in the generator object.  In ordinary calls, new.target is always
    // undefined because generator functions are non-constructable.
    static_assert(kJavaScriptCallCodeStartRegister == rcx, "ABI mismatch");
#if V8_ENABLE_LEAPTIERING
    // Actual arguments count and code start are already initialized above.
    __ jmp(rcx);
#else
    // Actual arguments count is already initialized above.
    __ JumpJSFunction(rdi);
#endif  // V8_ENABLE_LEAPTIERING
  }

  __ bind(&prepare_step_in_if_stepping);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(rdx);
    __ Push(rdi);
    // Push hole as receiver since we do not use it for stepping.
    __ PushRoot(RootIndex::kTheHoleValue);
    __ CallRuntime(Runtime::kDebugOnFunctionCall);
    __ Pop(rdx);
    __ LoadTaggedField(rdi,
                       FieldOperand(rdx, JSGeneratorObject::kFunctionOffset));
  }
  __ jmp(&stepping_prepared);

  __ bind(&prepare_step_in_suspended_generator);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(rdx);
    __ CallRuntime(Runtime::kDebugPrepareStepInSuspendedGenerator);
    __ Pop(rdx);
    __ LoadTaggedField(rdi,
                       FieldOperand(rdx, JSGeneratorObject::kFunctionOffset));
  }
  __ jmp(&stepping_prepared);

  __ bind(&stack_overflow);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    __ int3();  // This should be unreachable.
  }
}

static void LeaveInterpreterFrame(MacroAssembler* masm, Register scratch1,
                                  Register scratch2) {
  ASM_CODE_COMMENT(masm);
  Register params_size = scratch1;
  // Get the size of the formal parameters (in bytes).
  __ movq(params_size,
          Operand(rbp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ movzxwl(params_size,
             FieldOperand(params_size, BytecodeArray::kParameterSizeOffset));

  Register actual_params_size = scratch2;
  // Compute the size of the actual parameters (in bytes).
  __ movq(actual_params_size,
          Operand(rbp, StandardFrameConstants::kArgCOffset));

  // If actual is bigger than formal, then we should use it to free up the stack
  // arguments.
  __ cmpq(params_size, actual_params_size);
  __ cmovq(kLessThan, params_size, actual_params_size);

  // Leave the frame (also dropping the register file).
  __ leave();

  // Drop receiver + arguments.
  __ DropArguments(params_size, scratch2);
}

// Tail-call |function_id| if |actual_state| == |expected_state|
// Advance the current bytecode offset. This simulates what all bytecode
// handlers do upon completion of the underlying operation. Will bail out to a
// label if the bytecode (without prefix) is a return bytecode. Will not advance
// the bytecode offset if the current bytecode is a JumpLoop, instead just
// re-executing the JumpLoop to jump to the correct bytecode.
static void AdvanceBytecodeOffsetOrReturn(MacroAssembler* masm,
                                          Register bytecode_array,
                                          Register bytecode_offset,
                                          Register bytecode, Register scratch1,
                                          Register scratch2, Label* if_return) {
  ASM_CODE_COMMENT(masm);
  Register bytecode_size_table = scratch1;

  // The bytecode offset value will be increased by one in wide and extra wide
  // cases. In the case of having a wide or extra wide JumpLoop bytecode, we
  // will restore the original bytecode. In order to simplify the code, we have
  // a backup of it.
  Register original_bytecode_offset = scratch2;
  DCHECK(!AreAliased(bytecode_array, bytecode_offset, bytecode,
                     bytecode_size_table, original_bytecode_offset));

  __ movq(original_bytecode_offset, bytecode_offset);

  __ Move(bytecode_size_table,
          ExternalReference::bytecode_size_table_address());

  // Check if the bytecode is a Wide or ExtraWide prefix bytecode.
  Label process_bytecode, extra_wide;
  static_assert(0 == static_cast<int>(interpreter::Bytecode::kWide));
  static_assert(1 == static_cast<int>(interpreter::Bytecode::kExtraWide));
  static_assert(2 == static_cast<int>(interpreter::Bytecode::kDebugBreakWide));
  static_assert(3 ==
                static_cast<int>(interpreter::Bytecode::kDebugBreakExtraWide));
  __ cmpb(bytecode, Immediate(0x3));
  __ j(above, &process_bytecode, Label::kNear);
  // The code to load the next bytecode is common to both wide and extra wide.
  // We can hoist them up here. incl has to happen before testb since it
  // modifies the ZF flag.
  __ incl(bytecode_offset);
  __ testb(bytecode, Immediate(0x1));
  __ movzxbq(bytecode, Operand(bytecode_array, bytecode_offset, times_1, 0));
  __ j(not_equal, &extra_wide, Label::kNear);

  // Update table to the wide scaled table.
  __ addq(bytecode_size_table,
          Immediate(kByteSize * interpreter::Bytecodes::kBytecodeCount));
  __ jmp(&process_bytecode, Label::kNear);

  __ bind(&extra_wide);
  // Update table to the extra wide scaled table.
  __ addq(bytecode_size_table,
          Immediate(2 * kByteSize * interpreter::Bytecodes::kBytecodeCount));

  __ bind(&process_bytecode);

// Bailout to the return label if this is a return bytecode.
#define JUMP_IF_EQUAL(NAME)                                             \
  __ cmpb(bytecode,                                                     \
          Immediate(static_cast<int>(interpreter::Bytecode::k##NAME))); \
  __ j(equal, if_return, Label::kFar);
  RETURN_BYTECODE_LIST(JUMP_IF_EQUAL)
#undef JUMP_IF_EQUAL

  // If this is a JumpLoop, re-execute it to perform the jump to the beginning
  // of the loop.
  Label end, not_jump_loop;
  __ cmpb(bytecode,
          Immediate(static_cast<int>(interpreter::Bytecode::kJumpLoop)));
  __ j(not_equal, &not_jump_loop, Label::kNear);
  // We need to restore the original bytecode_offset since we might have
  // increased it to skip the wide / extra-wide prefix bytecode.
  __ movq(bytecode_offset, original_bytecode_offset);
  __ jmp(&end, Label::kNear);

  __ bind(&not_jump_loop);
  // Otherwise, load the size of the current bytecode and advance the offset.
  __ movzxbl(kScratchRegister,
             Operand(bytecode_size_table, bytecode, times_1, 0));
  __ addl(bytecode_offset, kScratchRegister);

  __ bind(&end);
}

namespace {

void ResetSharedFunctionInfoAge(MacroAssembler* masm, Register sfi) {
  __ movw(FieldOperand(sfi, SharedFunctionInfo::kAgeOffset), Immediate(0));
}

void ResetJSFunctionAge(MacroAssembler* masm, Register js_function) {
  const Register shared_function_info(kScratchRegister);
  __ LoadTaggedField(
      shared_function_info,
      FieldOperand(js_function, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, shared_function_info);
}

void ResetFeedbackVectorOsrUrgency(MacroAssembler* masm,
                                   Register feedback_vector, Register scratch) {
  __ movb(scratch,
          FieldOperand(feedback_vector, FeedbackVector::kOsrStateOffset));
  __ andb(scratch, Immediate(~FeedbackVector::OsrUrgencyBits::kMask));
  __ movb(FieldOperand(feedback_vector, FeedbackVector::kOsrStateOffset),
          scratch);
}

}  // namespace

// Generate code for entering a JS function with the interpreter.
// On entry to the function the receiver and arguments have been pushed on the
// stack left to right.
//
// The live registers are:
//   o rax: actual argument count
//   o rdi: the JS function object being called
//   o rdx: the incoming new target or generator object
//   o rsi: our context
//   o rbp: the caller's frame pointer
//   o rsp: stack pointer (pointing to return address)
//
// The function builds an interpreter frame. See InterpreterFrameConstants in
// frame-constants.h for its layout.
void Builtins::Generate_InterpreterEntryTrampoline(
    MacroAssembler* masm, InterpreterEntryTrampolineMode mode) {
  Register closure = rdi;

  // Get the bytecode array from the function object and load it into
  // kInterpreterBytecodeArrayRegister.
  const Register shared_function_info(r11);
  __ LoadTaggedField(
      shared_function_info,
      FieldOperand(closure, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, shared_function_info);

  // The bytecode array could have been flushed from the shared function info,
  // if so, call into CompileLazy.
  Label is_baseline, compile_lazy;
  GetSharedFunctionInfoBytecodeOrBaseline(
      masm, shared_function_info, kInterpreterBytecodeArrayRegister,
      kScratchRegister, &is_baseline, &compile_lazy);

#ifdef V8_ENABLE_LEAPTIERING
  // Validate the parameter count. This protects against an attacker swapping
  // the bytecode (or the dispatch handle) such that the parameter count of the
  // dispatch entry doesn't match the one of the BytecodeArray.
  // TODO(saelo): instead of this validation step, it would probably be nicer
  // if we could store the BytecodeArray directly in the dispatch entry and
  // load it from there. Then we can easily guarantee that the parameter count
  // of the entry matches the parameter count of the bytecode.
  Register dispatch_handle = kJavaScriptCallDispatchHandleRegister;
  __ LoadParameterCountFromJSDispatchTable(r8, dispatch_handle);
  __ cmpw(r8, FieldOperand(kInterpreterBytecodeArrayRegister,
                           BytecodeArray::kParameterSizeOffset));
  __ SbxCheck(equal, AbortReason::kJSSignatureMismatch);
#endif  // V8_ENABLE_LEAPTIERING

  Label push_stack_frame;
  Register feedback_vector = rbx;
  __ LoadFeedbackVector(feedback_vector, closure, &push_stack_frame,
                        Label::kNear);

#ifndef V8_JITLESS
#ifndef V8_ENABLE_LEAPTIERING
  // If feedback vector is valid, check for optimized code and update invocation
  // count.
  Label flags_need_processing;
  __ CheckFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      feedback_vector, CodeKind::INTERPRETED_FUNCTION, &flags_need_processing);
#endif  // !V8_ENABLE_LEAPTIERING

  ResetFeedbackVectorOsrUrgency(masm, feedback_vector, kScratchRegister);

  // Increment invocation count for the function.
  __ incl(
      FieldOperand(feedback_vector, FeedbackVector::kInvocationCountOffset));

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
  __ pushq(rbp);  // Caller's frame pointer.
  __ movq(rbp, rsp);
  __ Push(kContextRegister);                 // Callee's context.
  __ Push(kJavaScriptCallTargetRegister);    // Callee's JS function.
  __ Push(kJavaScriptCallArgCountRegister);  // Actual argument count.

  // Load initial bytecode offset.
  __ Move(kInterpreterBytecodeOffsetRegister,
          BytecodeArray::kHeaderSize - kHeapObjectTag);

  // Push bytecode array and Smi tagged bytecode offset.
  __ Push(kInterpreterBytecodeArrayRegister);
  __ SmiTag(rcx, kInterpreterBytecodeOffsetRegister);
  __ Push(rcx);

  // Push feedback vector.
  __ Push(feedback_vector);

  // Allocate the local and temporary register file on the stack.
  Label stack_overflow;
  {
    // Load frame size from the BytecodeArray object.
    __ movl(rcx, FieldOperand(kInterpreterBytecodeArrayRegister,
                              BytecodeArray::kFrameSizeOffset));

    // Do a stack check to ensure we don't go over the limit.
    __ movq(rax, rsp);
    __ subq(rax, rcx);
    __ cmpq(rax, __ StackLimitAsOperand(StackLimitKind::kRealStackLimit));
    __ j(below, &stack_overflow);

    // If ok, push undefined as the initial value for all register file entries.
    Label loop_header;
    Label loop_check;
    __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
    __ jmp(&loop_check, Label::kNear);
    __ bind(&loop_header);
    // TODO(rmcilroy): Consider doing more than one push per loop iteration.
    __ Push(kInterpreterAccumulatorRegister);
    // Continue loop if not done.
    __ bind(&loop_check);
    __ subq(rcx, Immediate(kSystemPointerSize));
    __ j(greater_equal, &loop_header, Label::kNear);
  }

  // If the bytecode array has a valid incoming new target or generator object
  // register, initialize it with incoming value which was passed in rdx.
  Label no_incoming_new_target_or_generator_register;
  __ movsxlq(
      rcx,
      FieldOperand(kInterpreterBytecodeArrayRegister,
                   BytecodeArray::kIncomingNewTargetOrGeneratorRegisterOffset));
  __ testl(rcx, rcx);
  __ j(zero, &no_incoming_new_target_or_generator_register, Label::kNear);
  __ movq(Operand(rbp, rcx, times_system_pointer_size, 0), rdx);
  __ bind(&no_incoming_new_target_or_generator_register);

  // Perform interrupt stack check.
  // TODO(solanes): Merge with the real stack limit check above.
  Label stack_check_interrupt, after_stack_check_interrupt;
  __ cmpq(rsp, __ StackLimitAsOperand(StackLimitKind::kInterruptStackLimit));
  __ j(below, &stack_check_interrupt);
  __ bind(&after_stack_check_interrupt);

  // The accumulator is already loaded with undefined.

  // Load the dispatch table into a register and dispatch to the bytecode
  // handler at the current bytecode offset.
  Label do_dispatch;
  __ bind(&do_dispatch);
  __ Move(
      kInterpreterDispatchTableRegister,
      ExternalReference::interpreter_dispatch_table_address(masm->isolate()));
  __ movzxbq(kScratchRegister,
             Operand(kInterpreterBytecodeArrayRegister,
                     kInterpreterBytecodeOffsetRegister, times_1, 0));
  __ movq(kJavaScriptCallCodeStartRegister,
          Operand(kInterpreterDispatchTableRegister, kScratchRegister,
                  times_system_pointer_size, 0));

  // X64 has this location as the interpreter_entry_return_offset for CET
  // shadow stack rather than after `call`. InterpreterEnterBytecode will
  // jump to this location and call kJavaScriptCallCodeStartRegister, which
  // will form the valid shadow stack.
  __ RecordComment("--- InterpreterEntryPC point ---");
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
  __ call(kJavaScriptCallCodeStartRegister);

  // Any returns to the entry trampoline are either due to the return bytecode
  // or the interpreter tail calling a builtin and then a dispatch.

  // Get bytecode array and bytecode offset from the stack frame.
  __ movq(kInterpreterBytecodeArrayRegister,
          Operand(rbp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ SmiUntagUnsigned(
      kInterpreterBytecodeOffsetRegister,
      Operand(rbp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  // Either return, or advance to the next bytecode and dispatch.
  Label do_return;
  __ movzxbq(rbx, Operand(kInterpreterBytecodeArrayRegister,
                          kInterpreterBytecodeOffsetRegister, times_1, 0));
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, rbx, rcx,
                                r8, &do_return);
  __ jmp(&do_dispatch);

  __ bind(&do_return);
  // The return value is in rax.
  LeaveInterpreterFrame(masm, rbx, rcx);
  __ ret(0);

  __ bind(&stack_check_interrupt);
  // Modify the bytecode offset in the stack to be kFunctionEntryBytecodeOffset
  // for the call to the StackGuard.
  __ Move(Operand(rbp, InterpreterFrameConstants::kBytecodeOffsetFromFp),
          Smi::FromInt(BytecodeArray::kHeaderSize - kHeapObjectTag +
                       kFunctionEntryBytecodeOffset));
  __ CallRuntime(Runtime::kStackGuard);

  // After the call, restore the bytecode array, bytecode offset and accumulator
  // registers again. Also, restore the bytecode offset in the stack to its
  // previous value.
  __ movq(kInterpreterBytecodeArrayRegister,
          Operand(rbp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ Move(kInterpreterBytecodeOffsetRegister,
          BytecodeArray::kHeaderSize - kHeapObjectTag);
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);

  __ SmiTag(rcx, kInterpreterBytecodeArrayRegister);
  __ movq(Operand(rbp, InterpreterFrameConstants::kBytecodeOffsetFromFp), rcx);

  __ jmp(&after_stack_check_interrupt);

  __ bind(&compile_lazy);
  __ GenerateTailCallToReturnedCode(Runtime::kCompileLazy);
  __ int3();  // Should not return.

#ifndef V8_JITLESS
#ifndef V8_ENABLE_LEAPTIERING
  __ bind(&flags_need_processing);
  __ OptimizeCodeOrTailCallOptimizedCodeSlot(feedback_vector, closure,
                                             JumpMode::kJump);
#endif  // !V8_ENABLE_LEAPTIERING

  __ bind(&is_baseline);
  {
#ifndef V8_ENABLE_LEAPTIERING
    // Load the feedback vector from the closure.
    TaggedRegister feedback_cell(feedback_vector);
    __ LoadTaggedField(feedback_cell,
                       FieldOperand(closure, JSFunction::kFeedbackCellOffset));
    __ LoadTaggedField(feedback_vector,
                       FieldOperand(feedback_cell, FeedbackCell::kValueOffset));

    Label install_baseline_code;
    // Check if feedback vector is valid. If not, call prepare for baseline to
    // allocate it.
    __ IsObjectType(feedback_vector, FEEDBACK_VECTOR_TYPE, rcx);
    __ j(not_equal, &install_baseline_code);

    // Check the tiering state.
    __ CheckFeedbackVectorFlagsAndJumpIfNeedsProcessing(
        feedback_vector, CodeKind::BASELINE, &flags_need_processing);

    // TODO(olivf, 42204201): This fastcase is difficult to support with the
    // sandbox as it requires getting write access to the dispatch table. See
    // `JSFunction::UpdateCode`. We might want to remove it for all
    // configurations as it does not seem to be performance sensitive.

    // Load the baseline code into the closure.
    __ Move(rcx, kInterpreterBytecodeArrayRegister);
    static_assert(kJavaScriptCallCodeStartRegister == rcx, "ABI mismatch");
    __ ReplaceClosureCodeWithOptimizedCode(
        rcx, closure, kInterpreterBytecodeArrayRegister,
        WriteBarrierDescriptor::SlotAddressRegister());
    __ JumpCodeObject(rcx, kJSEntrypointTag);

    __ bind(&install_baseline_code);
#endif  // !V8_ENABLE_LEAPTIERING

    __ GenerateTailCallToReturnedCode(Runtime::kInstallBaselineCode);
  }
#endif  // !V8_JITLESS

  __ bind(&stack_overflow);
  __ CallRuntime(Runtime::kThrowStackOverflow);
  __ int3();  // Should not return.
}

static void GenerateInterpreterPushArgs(MacroAssembler* masm, Register num_args,
                                        Register start_address,
                                        Register scratch) {
  ASM_CODE_COMMENT(masm);
  // Find the argument with lowest address.
  __ movq(scratch, num_args);
  __ negq(scratch);
  __ leaq(start_address,
          Operand(start_address, scratch, times_system_pointer_size,
                  kSystemPointerSize));
  // Push the arguments.
  __ PushArray(start_address, num_args, scratch,
               MacroAssembler::PushArrayOrder::kReverse);
}

// static
void Builtins::Generate_InterpreterPushArgsThenCallImpl(
    MacroAssembler* masm, ConvertReceiverMode receiver_mode,
    InterpreterPushArgsMode mode) {
  DCHECK(mode != InterpreterPushArgsMode::kArrayFunction);
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rbx : the address of the first argument to be pushed. Subsequent
  //           arguments should be consecutive above this, in the same order as
  //           they are to be pushed onto the stack.
  //  -- rdi : the target to call (can be any Object).
  // -----------------------------------
  Label stack_overflow;

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ decl(rax);
  }

  __ movl(rcx, rax);
  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ decl(rcx);  // Exclude receiver.
  }

  // Add a stack check before pushing arguments.
  __ StackOverflowCheck(rcx, &stack_overflow);

  // Pop return address to allow tail-call after pushing arguments.
  __ PopReturnAddressTo(kScratchRegister);

  // rbx and rdx will be modified.
  GenerateInterpreterPushArgs(masm, rcx, rbx, rdx);

  // Push "undefined" as the receiver arg if we need to.
  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ PushRoot(RootIndex::kUndefinedValue);
  }

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Pass the spread in the register rbx.
    // rbx already points to the penultime argument, the spread
    // is below that.
    __ movq(rbx, Operand(rbx, -kSystemPointerSize));
  }

  // Call the target.
  __ PushReturnAddressFrom(kScratchRegister);  // Re-push return address.

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    __ TailCallBuiltin(Builtin::kCallWithSpread);
  } else {
    __ TailCallBuiltin(Builtins::Call(receiver_mode));
  }

  // Throw stack overflow exception.
  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    // This should be unreachable.
    __ int3();
  }
}

// static
void Builtins::Generate_InterpreterPushArgsThenConstructImpl(
    MacroAssembler* masm, InterpreterPushArgsMode mode) {
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdx : the new target (either the same as the constructor or
  //           the JSFunction on which new was invoked initially)
  //  -- rdi : the constructor to call (can be any Object)
  //  -- rbx : the allocation site feedback if available, undefined otherwise
  //  -- rcx : the address of the first argument to be pushed. Subsequent
  //           arguments should be consecutive above this, in the same order as
  //           they are to be pushed onto the stack.
  // -----------------------------------
  Label stack_overflow;

  // Add a stack check before pushing arguments.
  __ StackOverflowCheck(rax, &stack_overflow);

  // Pop return address to allow tail-call after pushing arguments.
  __ PopReturnAddressTo(kScratchRegister);

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ decl(rax);
  }

  // rcx and r8 will be modified.
  Register argc_without_receiver = r11;
  __ leaq(argc_without_receiver, Operand(rax, -kJSArgcReceiverSlots));
  GenerateInterpreterPushArgs(masm, argc_without_receiver, rcx, r8);

  // Push slot for the receiver to be constructed.
  __ Push(Immediate(0));

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Pass the spread in the register rbx.
    __ movq(rbx, Operand(rcx, -kSystemPointerSize));
    // Push return address in preparation for the tail-call.
    __ PushReturnAddressFrom(kScratchRegister);
  } else {
    __ PushReturnAddressFrom(kScratchRegister);
    __ AssertUndefinedOrAllocationSite(rbx);
  }

  if (mode == InterpreterPushArgsMode::kArrayFunction) {
    // Tail call to the array construct stub (still in the caller
    // context at this point).
    __ AssertFunction(rdi);
    // Jump to the constructor function (rax, rbx, rdx passed on).
    __ TailCallBuiltin(Builtin::kArrayConstructorImpl);
  } else if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Call the constructor (rax, rdx, rdi passed on).
    __ TailCallBuiltin(Builtin::kConstructWithSpread);
  } else {
    DCHECK_EQ(InterpreterPushArgsMode::kOther, mode);
    // Call the constructor (rax, rdx, rdi passed on).
    __ TailCallBuiltin(Builtin::kConstruct);
  }

  // Throw stack overflow exception.
  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    // This should be unreachable.
    __ int3();
  }
}

// static
void Builtins::Generate_ConstructForwardAllArgsImpl(
    MacroAssembler* masm, ForwardWhichFrame which_frame) {
  // ----------- S t a t e -------------
  //  -- rdx : the new target (either the same as the constructor or
  //           the JSFunction on which new was invoked initially)
  //  -- rdi : the constructor to call (can be any Object)
  // -----------------------------------
  Label stack_overflow;

  // Load the frame pointer into rcx.
  switch (which_frame) {
    case ForwardWhichFrame::kCurrentFrame:
      __ movq(rcx, rbp);
      break;
    case ForwardWhichFrame::kParentFrame:
      __ movq(rcx, Operand(rbp, StandardFrameConstants::kCallerFPOffset));
      break;
  }

  // Load the argument count into rax.
  __ movq(rax, Operand(rcx, StandardFrameConstants::kArgCOffset));

  // Add a stack check before copying arguments.
  __ StackOverflowCheck(rax, &stack_overflow);

  // Pop return address to allow tail-call after forwarding arguments.
  __ PopReturnAddressTo(kScratchRegister);

  // Point rcx to the base of the argument list to forward, excluding the
  // receiver.
  __ addq(rcx, Immediate((StandardFrameConstants::kFixedSlotCountAboveFp + 1) *
                         kSystemPointerSize));

  // Copy the arguments on the stack. r8 is a scratch register.
  Register argc_without_receiver = r11;
  __ leaq(argc_without_receiver, Operand(rax, -kJSArgcReceiverSlots));
  __ PushArray(rcx, argc_without_receiver, r8);

  // Push slot for the receiver to be constructed.
  __ Push(Immediate(0));

  __ PushReturnAddressFrom(kScratchRegister);

  // Call the constructor (rax, rdx, rdi passed on).
  __ TailCallBuiltin(Builtin::kConstruct);

  // Throw stack overflow exception.
  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    // This should be unreachable.
    __ int3();
  }
}

namespace {

void NewImplicitReceiver(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdx : the new target
  //  -- rdi : the constructor to call (checked to be a JSFunction)
  //
  //  Stack:
  //  -- Implicit Receiver
  //  -- [arguments without receiver]
  //  -- Implicit Receiver
  //  -- Context
  //  -- FastConstructMarker
  //  -- FramePointer
  // -----------------------------------
  Register implicit_receiver = rcx;

  // Save live registers.
  __ SmiTag(rax);
  __ Push(rax);  // Number of arguments
  __ Push(rdx);  // NewTarget
  __ Push(rdi);  // Target
  __ CallBuiltin(Builtin::kFastNewObject);
  // Save result.
  __ movq(implicit_receiver, rax);
  // Restore live registers.
  __ Pop(rdi);
  __ Pop(rdx);
  __ Pop(rax);
  __ SmiUntagUnsigned(rax);

  // Patch implicit receiver (in arguments)
  __ movq(Operand(rsp, 0 /* first argument */), implicit_receiver);
  // Patch second implicit (in construct frame)
  __ movq(Operand(rbp, FastConstructFrameConstants::kImplicitReceiverOffset),
          implicit_receiver);

  // Restore context.
  __ movq(rsi, Operand(rbp, FastConstructFrameConstants::kContextOffset));
}

}  // namespace

// static
void Builtins::Generate_InterpreterPushArgsThenFastConstructFunction(
    MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdx : the new target
  //  -- rdi : the constructor to call (checked to be a JSFunction)
  //  -- rcx : the address of the first argument to be pushed. Subsequent
  //           arguments should be consecutive above this, in the same order as
  //           they are to be pushed onto the stack.
  // -----------------------------------
  __ AssertFunction(rdi);

  // Check if target has a [[Construct]] internal method.
  Label non_constructor;
  __ LoadMap(kScratchRegister, rdi);
  __ testb(FieldOperand(kScratchRegister, Map::kBitFieldOffset),
           Immediate(Map::Bits1::IsConstructorBit::kMask));
  __ j(zero, &non_constructor);

  // Add a stack check before pushing arguments.
  Label stack_overflow;
  __ StackOverflowCheck(rax, &stack_overflow);

  // Enter a construct frame.
  FrameScope scope(masm, StackFrame::MANUAL);
  __ EnterFrame(StackFrame::FAST_CONSTRUCT);
  __ Push(rsi);
  // Implicit receiver stored in the construct frame.
  __ PushRoot(RootIndex::kTheHoleValue);

  // Push arguments + implicit receiver.
  Register argc_without_receiver = r11;
  __ leaq(argc_without_receiver, Operand(rax, -kJSArgcReceiverSlots));
  GenerateInterpreterPushArgs(masm, argc_without_receiver, rcx, r12);
  // Implicit receiver as part of the arguments (patched later if needed).
  __ PushRoot(RootIndex::kTheHoleValue);

  // Check if it is a builtin call.
  Label builtin_call;
  const TaggedRegister shared_function_info(kScratchRegister);
  __ LoadTaggedField(shared_function_info,
                     FieldOperand(rdi, JSFunction::kSharedFunctionInfoOffset));
  __ testl(FieldOperand(shared_function_info, SharedFunctionInfo::kFlagsOffset),
           Immediate(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ j(not_zero, &builtin_call);

  // Check if we need to create an implicit receiver.
  Label not_create_implicit_receiver;
  __ movl(kScratchRegister,
          FieldOperand(shared_function_info, SharedFunctionInfo::kFlagsOffset));
  __ DecodeField<SharedFunctionInfo::FunctionKindBits>(kScratchRegister);
  __ JumpIfIsInRange(
      kScratchRegister,
      static_cast<uint32_t>(FunctionKind::kDefaultDerivedConstructor),
      static_cast<uint32_t>(FunctionKind::kDerivedConstructor),
      &not_create_implicit_receiver, Label::kNear);
  NewImplicitReceiver(masm);
  __ bind(&not_create_implicit_receiver);

  // Call the function.
  __ InvokeFunction(rdi, rdx, rax, InvokeType::kCall);

  // ----------- S t a t e -------------
  //  -- rax     constructor result
  //
  //  Stack:
  //  -- Implicit Receiver
  //  -- Context
  //  -- FastConstructMarker
  //  -- FramePointer
  // -----------------------------------

  Label deopt_entry;
  __ bind(&deopt_entry);

  // If the result is an object (in the ECMA sense), we should get rid
  // of the receiver and use the result; see ECMA-262 section 13.2.2-7
  // on page 74.
  Label use_receiver, do_throw, leave_and_return, check_result;

  // If the result is undefined, we'll use the implicit receiver. Otherwise we
  // do a smi check and fall through to check if the return value is a valid
  // receiver.
  __ JumpIfNotRo
"""


```