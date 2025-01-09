Response:
The user wants me to analyze a C++ source code file from the V8 JavaScript engine.
Specifically, they want to understand the functionality of `v8/src/builtins/ppc/builtins-ppc.cc`.

Here's a breakdown of the request and my plan:

1. **Identify the core purpose:** The filename suggests this file contains built-in functions for the PowerPC (ppc) architecture within the V8 engine. Built-ins are highly optimized, architecture-specific implementations of JavaScript functionality.

2. **Check for Torque:** The user asks if the file ends in `.tq`, indicating a Torque source file. This file ends in `.cc`, so it's a regular C++ source file. Torque is a newer language used for defining built-ins in a more platform-independent way, which then generates C++ code.

3. **Relate to JavaScript functionality:** I need to identify which JavaScript features these built-ins are implementing. This will involve looking for patterns in the code, such as calls to runtime functions or manipulation of JavaScript objects.

4. **Provide JavaScript examples:** For the identified JavaScript functionalities, I need to provide corresponding JavaScript code snippets to illustrate how these built-ins are used.

5. **Analyze code logic with examples:** If the code performs specific logical operations, I need to devise hypothetical inputs and their expected outputs. This is more applicable to self-contained functions or code blocks.

6. **Identify common programming errors:** Based on the code, I should try to pinpoint common programming mistakes that the built-in might be designed to handle or prevent.

7. **Summarize the functionality:** Finally, I need to synthesize all the findings into a concise summary of the file's purpose.

**Focusing on this specific part (part 2 of 5):** This snippet seems to focus heavily on entry points and trampoline functions for executing JavaScript code, as well as handling stack frames and exceptions. Keywords like `JSEntry`, `JSConstructEntry`, `InterpreterEntryTrampoline`, `StackFrame`, `PushStackHandler`, `CallBuiltin`, and `CallRuntime` are indicative of this.

**Plan for this part:**

*   Focus on the `Generate_JSEntry`, `Generate_JSConstructEntry`, `Generate_JSRunMicrotasksEntry`, `Generate_JSEntryTrampoline`, `Generate_JSConstructEntryTrampoline`, `Generate_RunMicrotasksTrampoline`, and `Generate_InterpreterEntryTrampoline` functions.
*   Explain how these functions set up the execution environment for JavaScript code, including stack frames, argument passing, and exception handling.
*   Relate these functions to the JavaScript concepts of function calls, constructor calls, and microtasks.
*   Provide JavaScript examples demonstrating function and constructor calls.
*   Briefly touch on the stack overflow checks and their relation to potential errors.
这是 `v8/src/builtins/ppc/builtins-ppc.cc` 源代码的第 2 部分，主要功能是定义了 PowerPC (ppc) 架构下 V8 引擎用于进入和执行 JavaScript 代码的内置函数（builtins）。这些内置函数充当了从 C++ 代码调用 JavaScript 代码的入口点，以及在解释器和编译代码之间切换的关键桥梁。

**功能归纳:**

这部分代码主要负责以下功能：

1. **`Generate_JSEntry` 和 `Generate_JSConstructEntry`:**  定义了从 C++ 代码进入 JavaScript 函数调用的入口点。`Generate_JSEntry` 用于标准的函数调用，而 `Generate_JSConstructEntry` 用于构造函数调用（使用 `new` 关键字）。它们负责设置 JavaScript 执行所需的栈帧结构，包括保存调用者的信息，设置异常处理机制，并跳转到实际执行 JavaScript 代码的入口点（trampoline）。

2. **`Generate_JSRunMicrotasksEntry`:**  定义了执行 JavaScript 微任务队列的入口点。微任务是在 JavaScript 事件循环的特定阶段执行的异步操作。

3. **`Generate_JSEntryTrampoline` 和 `Generate_JSConstructEntryTrampoline`:** 这两个函数生成了实际执行 JavaScript 代码的“跳板”（trampoline）代码。它们负责从入口点接收参数（函数、接收者、参数等），在栈上为参数分配空间，调用实际的 JavaScript 代码，并在执行完成后清理栈帧。`Generate_JSEntryTrampoline` 用于普通函数调用，`Generate_JSConstructEntryTrampoline` 用于构造函数调用。

4. **`Generate_RunMicrotasksTrampoline`:**  生成了执行微任务的跳板代码，它会将微任务队列传递给实际执行微任务的内置函数。

5. **`Generate_InterpreterEntryTrampoline`:**  定义了进入 JavaScript 解释器的入口点。当 V8 引擎需要解释执行 JavaScript 代码时，会跳转到这个内置函数。它负责设置解释器执行所需的栈帧结构，加载字节码，并开始执行字节码指令。

6. **栈帧管理和异常处理:** 代码中涉及到创建和管理不同类型的栈帧（如 `ENTRY`、`CONSTRUCT_ENTRY`、`INTERNAL`、`INTERPRETED`），以及设置异常处理机制（通过 `PushStackHandler` 和 `handler_entry` 标签）。这保证了在 JavaScript 代码执行过程中，调用栈的正确性和异常的捕获。

7. **参数传递:** 代码演示了如何将参数从 C++ 代码传递到 JavaScript 代码，以及如何在 JavaScript 代码执行过程中访问这些参数。

8. **性能优化:**  内置函数通常是高度优化的，例如，直接操作寄存器和使用特定的汇编指令来提高执行效率。

**与 JavaScript 功能的关系以及 JavaScript 示例:**

*   **函数调用:** `Generate_JSEntry` 和 `Generate_JSEntryTrampoline` 与 JavaScript 的函数调用直接相关。

    ```javascript
    function myFunction(a, b) {
      return a + b;
    }

    myFunction(5, 3); // 当执行此行代码时，V8 可能会通过 Generate_JSEntry 进入 JavaScript 代码。
    ```

*   **构造函数调用:** `Generate_JSConstructEntry` 和 `Generate_JSConstructEntryTrampoline` 与 JavaScript 的构造函数调用相关。

    ```javascript
    class MyClass {
      constructor(value) {
        this.value = value;
      }
    }

    const myObject = new MyClass(10); // 当执行此行代码时，V8 可能会通过 Generate_JSConstructEntry 进入 JavaScript 代码。
    ```

*   **微任务:** `Generate_JSRunMicrotasksEntry` 和 `Generate_RunMicrotasksTrampoline` 与 JavaScript 的微任务相关。

    ```javascript
    Promise.resolve().then(() => {
      console.log("This is a microtask.");
    });

    console.log("This is synchronous code.");
    // 在同步代码执行完毕后，V8 会执行微任务队列中的任务，此时可能会用到 Generate_JSRunMicrotasksEntry。
    ```

*   **解释器执行:** `Generate_InterpreterEntryTrampoline`  在 JavaScript 代码没有被编译优化时使用。

    ```javascript
    function potentiallyUnoptimizedFunction() {
      // 一些不常执行或者比较简单的函数可能不会被立即编译优化，而是由解释器执行。
      console.log("Executing in the interpreter.");
    }

    potentiallyUnoptimizedFunction(); // V8 可能会通过 Generate_InterpreterEntryTrampoline 进入解释器执行此函数。
    ```

**代码逻辑推理和假设输入输出:**

以 `Generate_JSEntry` 为例，假设从 C++ 代码调用一个 JavaScript 函数：

**假设输入:**

*   `r4`:  指向要调用的 JavaScript 函数对象的指针。
*   `r6`:  接收者对象（如果是非方法调用，则可能是 `undefined` 或 `null`）。
*   `r7`:  参数个数。
*   `r8`:  指向参数数组的指针。

**代码逻辑:**

1. 保存当前的栈指针 `sp` 到 `js_entry_sp`。
2. 检查是否是最外层的 JavaScript 调用。
3. 在栈上创建一个新的 JavaScript 入口帧 (`ENTRY` 类型的栈帧)。
4. 跳转到一个伪造的 `try` 块，该块会调用 JavaScript 函数。
5. 设置一个伪造的 `catch` 块，用于捕获 JavaScript 代码执行过程中抛出的异常。
6. 调用通过 `entry_trampoline` 指定的入口跳板（通常是 `Generate_JSEntryTrampoline` 生成的代码）。
7. 在 JavaScript 代码执行完成后，清理栈帧。

**假设输出 (正常执行):**

*   `r3`:  JavaScript 函数的返回值。
*   栈恢复到调用 `Generate_JSEntry` 之前的状态。

**假设输出 (发生异常):**

*   异常对象被存储到 `IsolateAddressId::kExceptionAddress` 指定的内存位置。
*   `r3`:  一个表示失败的哨兵值 (通常是预定义的异常对象或错误码)。

**用户常见的编程错误 (与栈溢出检查相关):**

代码中多次出现 `__ StackOverflowCheck`，这是用于检测是否会发生栈溢出的机制。用户常见的编程错误可能导致栈溢出：

*   **无限递归:**  一个函数不断调用自身而没有终止条件。

    ```javascript
    function recursiveFunction() {
      recursiveFunction(); // 缺少终止条件，导致无限递归
    }

    recursiveFunction(); // 这将很快导致栈溢出。
    ```

*   **调用栈过深的函数调用链:**  连续调用多个函数，导致调用栈超出限制。虽然不是直接的编程错误，但在某些情况下，过于复杂的调用关系可能触发栈溢出。

*   **在单个函数中声明过多的局部变量:** 虽然相对少见，但在某些极端情况下，如果一个函数声明了非常多的局部变量，也可能耗尽栈空间。

**总结:**

这段 `v8/src/builtins/ppc/builtins-ppc.cc` 代码的核心功能是定义了 PowerPC 架构下 V8 引擎进入和执行 JavaScript 代码的关键入口点和跳板。它负责设置执行环境，包括栈帧管理、参数传递和异常处理，并区分了不同类型的 JavaScript 调用（普通函数、构造函数、微任务、解释执行）。这些内置函数对于 V8 引擎高效执行 JavaScript 代码至关重要。

Prompt: 
```
这是目录为v8/src/builtins/ppc/builtins-ppc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/ppc/builtins-ppc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能

"""
_entry_sp =
      ExternalReference::Create(IsolateAddressId::kJSEntrySPAddress,
                                masm->isolate());
  __ Move(r3, js_entry_sp);
  __ LoadU64(scratch, MemOperand(r3));
  __ cmpi(scratch, Operand::Zero());
  __ bne(&non_outermost_js);
  __ StoreU64(fp, MemOperand(r3));
  __ mov(scratch, Operand(StackFrame::OUTERMOST_JSENTRY_FRAME));
  Label cont;
  __ b(&cont);
  __ bind(&non_outermost_js);
  __ mov(scratch, Operand(StackFrame::INNER_JSENTRY_FRAME));
  __ bind(&cont);
  __ push(scratch);  // frame-type

  // Jump to a faked try block that does the invoke, with a faked catch
  // block that sets the exception.
  __ b(&invoke);

  // Block literal pool emission whilst taking the position of the handler
  // entry. This avoids making the assumption that literal pools are always
  // emitted after an instruction is emitted, rather than before.
  {
    ConstantPoolUnavailableScope constant_pool_unavailable(masm);
    __ bind(&handler_entry);

    // Store the current pc as the handler offset. It's used later to create the
    // handler table.
    masm->isolate()->builtins()->SetJSEntryHandlerOffset(handler_entry.pos());

    // Caught exception: Store result (exception) in the exception
    // field in the JSEnv and return a failure sentinel.  Coming in here the
    // fp will be invalid because the PushStackHandler below sets it to 0 to
    // signal the existence of the JSEntry frame.
    __ Move(scratch, ExternalReference::Create(
                         IsolateAddressId::kExceptionAddress, masm->isolate()));
  }

  __ StoreU64(r3, MemOperand(scratch));
  __ LoadRoot(r3, RootIndex::kException);
  __ b(&exit);

  // Invoke: Link this frame into the handler chain.
  __ bind(&invoke);
  // Must preserve r4-r8.
  __ PushStackHandler();
  // If an exception not caught by another handler occurs, this handler
  // returns control to the code after the b(&invoke) above, which
  // restores all kCalleeSaved registers (including cp and fp) to their
  // saved values before returning a failure to C.

  // Invoke the function by calling through JS entry trampoline builtin.
  // Notice that we cannot store a reference to the trampoline code directly in
  // this stub, because runtime stubs are not traversed when doing GC.

  // Invoke the function by calling through JS entry trampoline builtin and
  // pop the faked function when we return.
  __ CallBuiltin(entry_trampoline);

  // Unlink this frame from the handler chain.
  __ PopStackHandler();

  __ bind(&exit);  // r3 holds result
  // Check if the current stack frame is marked as the outermost JS frame.
  Label non_outermost_js_2;
  __ pop(r8);
  __ cmpi(r8, Operand(StackFrame::OUTERMOST_JSENTRY_FRAME));
  __ bne(&non_outermost_js_2);
  __ mov(scratch, Operand::Zero());
  __ Move(r8, js_entry_sp);
  __ StoreU64(scratch, MemOperand(r8));
  __ bind(&non_outermost_js_2);

  // Restore the top frame descriptors from the stack.
  __ pop(r6);
  __ LoadIsolateField(scratch, IsolateFieldId::kFastCCallCallerPC);
  __ StoreU64(r6, MemOperand(scratch));

  __ pop(r6);
  __ LoadIsolateField(scratch, IsolateFieldId::kFastCCallCallerFP);
  __ StoreU64(r6, MemOperand(scratch));

  __ pop(r6);
  __ Move(scratch, ExternalReference::Create(IsolateAddressId::kCEntryFPAddress,
                                             masm->isolate()));
  __ StoreU64(r6, MemOperand(scratch));

  // Reset the stack to the callee saved registers.
  __ addi(sp, sp, Operand(-EntryFrameConstants::kNextExitFrameFPOffset));

  // Restore callee-saved double registers.
  __ MultiPopDoubles(kCalleeSavedDoubles);

  // Restore callee-saved registers.
  __ MultiPop(kCalleeSaved);

  // Return
  __ LoadU64(r0, MemOperand(sp, kStackFrameLRSlot * kSystemPointerSize));
  __ mtlr(r0);
  __ blr();
}

}  // namespace

void Builtins::Generate_JSEntry(MacroAssembler* masm) {
  Generate_JSEntryVariant(masm, StackFrame::ENTRY, Builtin::kJSEntryTrampoline);
}

void Builtins::Generate_JSConstructEntry(MacroAssembler* masm) {
  Generate_JSEntryVariant(masm, StackFrame::CONSTRUCT_ENTRY,
                          Builtin::kJSConstructEntryTrampoline);
}

void Builtins::Generate_JSRunMicrotasksEntry(MacroAssembler* masm) {
  Generate_JSEntryVariant(masm, StackFrame::ENTRY,
                          Builtin::kRunMicrotasksTrampoline);
}

static void Generate_JSEntryTrampolineHelper(MacroAssembler* masm,
                                             bool is_construct) {
  // Called from Generate_JS_Entry
  // r4: new.target
  // r5: function
  // r6: receiver
  // r7: argc
  // r8: argv
  // r0,r3,r9, cp may be clobbered

  // Enter an internal frame.
  {
    FrameScope scope(masm, StackFrame::INTERNAL);

    // Setup the context (we need to use the caller context from the isolate).
    ExternalReference context_address = ExternalReference::Create(
        IsolateAddressId::kContextAddress, masm->isolate());
    __ Move(cp, context_address);
    __ LoadU64(cp, MemOperand(cp));

    // Push the function.
    __ Push(r5);

    // Check if we have enough stack space to push all arguments.
    Label enough_stack_space, stack_overflow;
    __ mr(r3, r7);
    __ StackOverflowCheck(r3, r9, &stack_overflow);
    __ b(&enough_stack_space);
    __ bind(&stack_overflow);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    // Unreachable code.
    __ bkpt(0);

    __ bind(&enough_stack_space);

    // Copy arguments to the stack.
    // r4: function
    // r7: argc
    // r8: argv, i.e. points to first arg
    Generate_PushArguments(masm, r8, r7, r9, ArgumentsElementType::kHandle);

    // Push the receiver.
    __ Push(r6);

    // r3: argc
    // r4: function
    // r6: new.target
    __ mr(r3, r7);
    __ mr(r6, r4);
    __ mr(r4, r5);

    // Initialize all JavaScript callee-saved registers, since they will be seen
    // by the garbage collector as part of handlers.
    __ LoadRoot(r7, RootIndex::kUndefinedValue);
    __ mr(r8, r7);
    __ mr(r14, r7);
    __ mr(r15, r7);
    __ mr(r16, r7);
    __ mr(r17, r7);

    // Invoke the code.
    Builtin builtin = is_construct ? Builtin::kConstruct : Builtins::Call();
    __ CallBuiltin(builtin);

    // Exit the JS frame and remove the parameters (except function), and
    // return.
  }
  __ blr();

  // r3: result
}

void Builtins::Generate_JSEntryTrampoline(MacroAssembler* masm) {
  Generate_JSEntryTrampolineHelper(masm, false);
}

void Builtins::Generate_JSConstructEntryTrampoline(MacroAssembler* masm) {
  Generate_JSEntryTrampolineHelper(masm, true);
}

void Builtins::Generate_RunMicrotasksTrampoline(MacroAssembler* masm) {
  // This expects two C++ function parameters passed by Invoke() in
  // execution.cc.
  //   r3: root_register_value
  //   r4: microtask_queue

  __ mr(RunMicrotasksDescriptor::MicrotaskQueueRegister(), r4);
  __ TailCallBuiltin(Builtin::kRunMicrotasks);
}

static void LeaveInterpreterFrame(MacroAssembler* masm, Register scratch1,
                                  Register scratch2) {
  Register params_size = scratch1;
  // Get the size of the formal parameters + receiver (in bytes).
  __ LoadU64(params_size,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ LoadU16(params_size,
             FieldMemOperand(params_size, BytecodeArray::kParameterSizeOffset));

  Register actual_params_size = scratch2;
  // Compute the size of the actual parameters + receiver (in bytes).
  __ LoadU64(actual_params_size,
             MemOperand(fp, StandardFrameConstants::kArgCOffset));

  // If actual is bigger than formal, then we should use it to free up the stack
  // arguments.
  Label corrected_args_count;
  __ CmpS64(params_size, actual_params_size);
  __ bge(&corrected_args_count);
  __ mr(params_size, actual_params_size);
  __ bind(&corrected_args_count);
  // Leave the frame (also dropping the register file).
  __ LeaveFrame(StackFrame::INTERPRETED);

  __ DropArguments(params_size);
}

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
  Register bytecode_size_table = scratch1;
  Register scratch3 = bytecode;

  // The bytecode offset value will be increased by one in wide and extra wide
  // cases. In the case of having a wide or extra wide JumpLoop bytecode, we
  // will restore the original bytecode. In order to simplify the code, we have
  // a backup of it.
  Register original_bytecode_offset = scratch2;
  DCHECK(!AreAliased(bytecode_array, bytecode_offset, bytecode_size_table,
                     bytecode, original_bytecode_offset));
  __ Move(bytecode_size_table,
          ExternalReference::bytecode_size_table_address());
  __ Move(original_bytecode_offset, bytecode_offset);

  // Check if the bytecode is a Wide or ExtraWide prefix bytecode.
  Label process_bytecode, extra_wide;
  static_assert(0 == static_cast<int>(interpreter::Bytecode::kWide));
  static_assert(1 == static_cast<int>(interpreter::Bytecode::kExtraWide));
  static_assert(2 == static_cast<int>(interpreter::Bytecode::kDebugBreakWide));
  static_assert(3 ==
                static_cast<int>(interpreter::Bytecode::kDebugBreakExtraWide));
  __ cmpi(bytecode, Operand(0x3));
  __ bgt(&process_bytecode);
  __ andi(r0, bytecode, Operand(0x1));
  __ bne(&extra_wide, cr0);

  // Load the next bytecode and update table to the wide scaled table.
  __ addi(bytecode_offset, bytecode_offset, Operand(1));
  __ lbzx(bytecode, MemOperand(bytecode_array, bytecode_offset));
  __ addi(bytecode_size_table, bytecode_size_table,
          Operand(kByteSize * interpreter::Bytecodes::kBytecodeCount));
  __ b(&process_bytecode);

  __ bind(&extra_wide);
  // Load the next bytecode and update table to the extra wide scaled table.
  __ addi(bytecode_offset, bytecode_offset, Operand(1));
  __ lbzx(bytecode, MemOperand(bytecode_array, bytecode_offset));
  __ addi(bytecode_size_table, bytecode_size_table,
          Operand(2 * kByteSize * interpreter::Bytecodes::kBytecodeCount));

  // Load the size of the current bytecode.
  __ bind(&process_bytecode);

  // Bailout to the return label if this is a return bytecode.
#define JUMP_IF_EQUAL(NAME)                                           \
  __ cmpi(bytecode,                                                   \
          Operand(static_cast<int>(interpreter::Bytecode::k##NAME))); \
  __ beq(if_return);
  RETURN_BYTECODE_LIST(JUMP_IF_EQUAL)
#undef JUMP_IF_EQUAL

  // If this is a JumpLoop, re-execute it to perform the jump to the beginning
  // of the loop.
  Label end, not_jump_loop;
  __ cmpi(bytecode,
          Operand(static_cast<int>(interpreter::Bytecode::kJumpLoop)));
  __ bne(&not_jump_loop);
  // We need to restore the original bytecode_offset since we might have
  // increased it to skip the wide / extra-wide prefix bytecode.
  __ Move(bytecode_offset, original_bytecode_offset);
  __ b(&end);

  __ bind(&not_jump_loop);
  // Otherwise, load the size of the current bytecode and advance the offset.
  __ lbzx(scratch3, MemOperand(bytecode_size_table, bytecode));
  __ add(bytecode_offset, bytecode_offset, scratch3);

  __ bind(&end);
}

// static
void Builtins::Generate_BaselineOutOfLinePrologue(MacroAssembler* masm) {
  auto descriptor =
      Builtins::CallInterfaceDescriptorFor(Builtin::kBaselineOutOfLinePrologue);
  Register closure = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kClosure);
  // Load the feedback cell and vector from the closure.
  Register feedback_cell = r7;
  Register feedback_vector = ip;
  __ LoadTaggedField(feedback_cell,
                     FieldMemOperand(closure, JSFunction::kFeedbackCellOffset),
                     r0);
  __ LoadTaggedField(feedback_vector,
                     FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset),
                     r0);
  __ AssertFeedbackVector(feedback_vector, r11);

  // Check for an tiering state.
  Label flags_need_processing;
  Register flags = r10;
  {
    __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
        flags, feedback_vector, CodeKind::BASELINE, &flags_need_processing);
  }

  { ResetFeedbackVectorOsrUrgency(masm, feedback_vector, r11, r0); }

  // Increment invocation count for the function.
  {
    Register invocation_count = r11;
    __ LoadU32(invocation_count,
               FieldMemOperand(feedback_vector,
                               FeedbackVector::kInvocationCountOffset),
               r0);
    __ AddS32(invocation_count, invocation_count, Operand(1));
    __ StoreU32(invocation_count,
                FieldMemOperand(feedback_vector,
                                FeedbackVector::kInvocationCountOffset),
                r0);
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
    ResetJSFunctionAge(masm, callee_js_function, r11, r0);
    __ Push(callee_context, callee_js_function);
    DCHECK_EQ(callee_js_function, kJavaScriptCallTargetRegister);
    DCHECK_EQ(callee_js_function, kJSFunctionRegister);

    Register argc = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kJavaScriptCallArgCount);
    // We'll use the bytecode for both code age/OSR resetting, and pushing onto
    // the frame, so load it into a register.
    Register bytecodeArray = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kInterpreterBytecodeArray);

    __ Push(argc, bytecodeArray);

    if (v8_flags.debug_code) {
      Register scratch = r11;
      __ CompareObjectType(feedback_vector, scratch, scratch,
                           FEEDBACK_VECTOR_TYPE);
      __ Assert(eq, AbortReason::kExpectedFeedbackVector);
    }
    __ Push(feedback_cell);
    __ Push(feedback_vector);
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

    Register sp_minus_frame_size = r11;
    Register interrupt_limit = r0;
    __ SubS64(sp_minus_frame_size, sp, frame_size);
    __ LoadStackLimit(interrupt_limit, StackLimitKind::kInterruptStackLimit,
                      r0);
    __ CmpU64(sp_minus_frame_size, interrupt_limit);
    __ blt(&call_stack_guard);
  }

  // Do "fast" return to the caller pc in lr.
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
  __ Ret();

  __ bind(&flags_need_processing);
  {
    ASM_CODE_COMMENT_STRING(masm, "Optimized marker check");

    // Drop the frame created by the baseline call.
    if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
      __ Pop(r0, fp, kConstantPoolRegister);
    } else {
      __ Pop(r0, fp);
    }
    __ mtlr(r0);
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

  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
  __ Ret();
}

// static
void Builtins::Generate_BaselineOutOfLinePrologueDeopt(MacroAssembler* masm) {
  // We're here because we got deopted during BaselineOutOfLinePrologue's stack
  // check. Undo all its frame creation and call into the interpreter instead.

  // Drop the feedback vector, the bytecode offset (was the feedback vector but
  // got replaced during deopt) and bytecode array.
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
//   o r3: actual argument count
//   o r4: the JS function object being called.
//   o r6: the incoming new target or generator object
//   o cp: our context
//   o pp: the caller's constant pool pointer (if enabled)
//   o fp: the caller's frame pointer
//   o sp: stack pointer
//   o lr: return address
//
// The function builds an interpreter frame.  See InterpreterFrameConstants in
// frame-constants.h for its layout.
void Builtins::Generate_InterpreterEntryTrampoline(
    MacroAssembler* masm, InterpreterEntryTrampolineMode mode) {
  Register closure = r4;

  // Get the bytecode array from the function object and load it into
  // kInterpreterBytecodeArrayRegister.
  Register sfi = r7;
  __ LoadTaggedField(
      sfi, FieldMemOperand(closure, JSFunction::kSharedFunctionInfoOffset), r0);
  ResetSharedFunctionInfoAge(masm, sfi, ip);

  // The bytecode array could have been flushed from the shared function info,
  // if so, call into CompileLazy.
  Label is_baseline, compile_lazy;
  GetSharedFunctionInfoBytecodeOrBaseline(masm, sfi,
                                          kInterpreterBytecodeArrayRegister, ip,
                                          &is_baseline, &compile_lazy);

  Label push_stack_frame;
  Register feedback_vector = r5;
  __ LoadFeedbackVector(feedback_vector, closure, r7, &push_stack_frame);

#ifndef V8_JITLESS
  // If feedback vector is valid, check for optimized code and update invocation
  // count.

  Register flags = r7;
  Label flags_need_processing;
  __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      flags, feedback_vector, CodeKind::INTERPRETED_FUNCTION,
      &flags_need_processing);

    ResetFeedbackVectorOsrUrgency(masm, feedback_vector, ip, r0);

  // Increment invocation count for the function.
  __ LoadU32(
      r8,
      FieldMemOperand(feedback_vector, FeedbackVector::kInvocationCountOffset),
      r0);
  __ addi(r8, r8, Operand(1));
  __ StoreU32(
      r8,
      FieldMemOperand(feedback_vector, FeedbackVector::kInvocationCountOffset),
      r0);

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
  __ mov(kInterpreterBytecodeOffsetRegister,
         Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));

  // Push bytecode array and Smi tagged bytecode array offset.
  __ SmiTag(r7, kInterpreterBytecodeOffsetRegister);
  __ Push(kInterpreterBytecodeArrayRegister, r7, feedback_vector);

  // Allocate the local and temporary register file on the stack.
  Label stack_overflow;
  {
    // Load frame size (word) from the BytecodeArray object.
    __ lwz(r5, FieldMemOperand(kInterpreterBytecodeArrayRegister,
                               BytecodeArray::kFrameSizeOffset));

    // Do a stack check to ensure we don't go over the limit.
    __ sub(r8, sp, r5);
    __ LoadStackLimit(ip, StackLimitKind::kRealStackLimit, r0);
    __ CmpU64(r8, ip);
    __ blt(&stack_overflow);

    // If ok, push undefined as the initial value for all register file entries.
    // TODO(rmcilroy): Consider doing more than one push per loop iteration.
    Label loop, no_args;
    __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
    __ ShiftRightU64(r5, r5, Operand(kSystemPointerSizeLog2), SetRC);
    __ beq(&no_args, cr0);
    __ mtctr(r5);
    __ bind(&loop);
    __ push(kInterpreterAccumulatorRegister);
    __ bdnz(&loop);
    __ bind(&no_args);
  }

  // If the bytecode array has a valid incoming new target or generator object
  // register, initialize it with incoming value which was passed in r6.
  Label no_incoming_new_target_or_generator_register;
  __ LoadS32(r8,
             FieldMemOperand(
                 kInterpreterBytecodeArrayRegister,
                 BytecodeArray::kIncomingNewTargetOrGeneratorRegisterOffset),
             r0);
  __ cmpi(r8, Operand::Zero());
  __ beq(&no_incoming_new_target_or_generator_register);
  __ ShiftLeftU64(r8, r8, Operand(kSystemPointerSizeLog2));
  __ StoreU64(r6, MemOperand(fp, r8));
  __ bind(&no_incoming_new_target_or_generator_register);

  // Perform interrupt stack check.
  // TODO(solanes): Merge with the real stack limit check above.
  Label stack_check_interrupt, after_stack_check_interrupt;
  __ LoadStackLimit(ip, StackLimitKind::kInterruptStackLimit, r0);
  __ CmpU64(sp, ip);
  __ blt(&stack_check_interrupt);
  __ bind(&after_stack_check_interrupt);

  // The accumulator is already loaded with undefined.

  // Load the dispatch table into a register and dispatch to the bytecode
  // handler at the current bytecode offset.
  Label do_dispatch;
  __ bind(&do_dispatch);
  __ Move(
      kInterpreterDispatchTableRegister,
      ExternalReference::interpreter_dispatch_table_address(masm->isolate()));
  __ lbzx(r6, MemOperand(kInterpreterBytecodeArrayRegister,
                         kInterpreterBytecodeOffsetRegister));
  __ ShiftLeftU64(r6, r6, Operand(kSystemPointerSizeLog2));
  __ LoadU64(kJavaScriptCallCodeStartRegister,
             MemOperand(kInterpreterDispatchTableRegister, r6));
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
  __ LoadU64(kInterpreterBytecodeArrayRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ LoadU64(kInterpreterBytecodeOffsetRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);

  // Either return, or advance to the next bytecode and dispatch.
  Label do_return;
  __ lbzx(r4, MemOperand(kInterpreterBytecodeArrayRegister,
                         kInterpreterBytecodeOffsetRegister));
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, r4, r5, r6,
                                &do_return);
  __ b(&do_dispatch);

  __ bind(&do_return);
  // The return value is in r3.
  LeaveInterpreterFrame(masm, r5, r7);
  __ blr();

  __ bind(&stack_check_interrupt);
  // Modify the bytecode offset in the stack to be kFunctionEntryBytecodeOffset
  // for the call to the StackGuard.
  __ mov(kInterpreterBytecodeOffsetRegister,
         Operand(Smi::FromInt(BytecodeArray::kHeaderSize - kHeapObjectTag +
                              kFunctionEntryBytecodeOffset)));
  __ StoreU64(kInterpreterBytecodeOffsetRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ CallRuntime(Runtime::kStackGuard);

  // After the call, restore the bytecode array, bytecode offset and accumulator
  // registers again. Also, restore the bytecode offset in the stack to its
  // previous value.
  __ LoadU64(kInterpreterBytecodeArrayRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ mov(kInterpreterBytecodeOffsetRegister,
         Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);

  __ SmiTag(r0, kInterpreterBytecodeOffsetRegister);
  __ StoreU64(r0,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  __ jmp(&after_stack_check_interrupt);

#ifndef V8_JITLESS
  __ bind(&flags_need_processing);
  __ OptimizeCodeOrTailCallOptimizedCodeSlot(flags, feedback_vector);

  __ bind(&is_baseline);
  {
    // Load the feedback vector from the closure.
    __ LoadTaggedField(
        feedback_vector,
        FieldMemOperand(closure, JSFunction::kFeedbackCellOffset), r0);
    __ LoadTaggedField(
        feedback_vector,
        FieldMemOperand(feedback_vector, FeedbackCell::kValueOffset), r0);

    Label install_baseline_code;
    // Check if feedback vector is valid. If not, call prepare for baseline to
    // allocate it.
    __ LoadTaggedField(
        ip, FieldMemOperand(feedback_vector, HeapObject::kMapOffset), r0);
    __ LoadU16(ip, FieldMemOperand(ip, Map::kInstanceTypeOffset));
    __ CmpS32(ip, Operand(FEEDBACK_VECTOR_TYPE), r0);
    __ b(ne, &install_baseline_code);

    // Check for an tiering state.
    __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
        flags, feedback_vector, CodeKind::BASELINE, &flags_need_processing);

#ifndef V8_ENABLE_LEAPTIERING
    // TODO(olivf, 42204201): This fastcase is difficult to support with the
    // sandbox as it requires getting write access to the dispatch table. See
    // `JSFunction::UpdateCode`. We might want to remove it for all
    // configurations as it does not seem to be performance sensitive.

    // Load the baseline code into the closure.
    __ mr(r5, kInterpreterBytecodeArrayRegister);
    static_assert(kJavaScriptCallCodeStartRegister == r5, "ABI mismatch");
    __ ReplaceClosureCodeWithOptimizedCode(r5, closure, ip, r7);
    __ JumpCodeObject(r5);

#endif  // V8_ENABLE_LEAPTIERING

    __ bind(&install_baseline_code);
    __ GenerateTailCallToReturnedCode(Runtime::kInstallBaselineCode);
  }
#endif  // !V8_JITLESS

  __ bind(&compile_lazy);
  __ GenerateTailCallToReturnedCode(Runtime::kCompileLazy);

  __ bind(&stack_overflow);
  __ CallRuntime(Runtime::kThrowStackOverflow);
  __ bkpt(0);  // Should not return.
}

static void GenerateInterpreterPushArgs(MacroAssembler* masm, Register num_args,
                                        Register start_address,
                                        Register scratch) {
  ASM_CODE_COMMENT(masm);
  __ subi(scratch, num_args, Operand(1));
  __ ShiftLeftU64(scratch, scratch, Operand(kSystemPointerSizeLog2));
  __ sub(start_address, start_address, scratch);
  // Push the arguments.
  __ PushArray(start_address, num_args, scratch, r0,
               MacroAssembler::PushArrayOrder::kReverse);
}

// static
void Builtins::Generate_InterpreterPushArgsThenCallImpl(
    MacroAssembler* masm, ConvertReceiverMode receiver_mode,
    InterpreterPushArgsMode mode) {
  DCHECK(mode != InterpreterPushArgsMode::kArrayFunction);
  // ----------- S t a t e -------------
  //  -- r3 : the number of arguments
  //  -- r5 : the address of the first argument to be pushed. Subsequent
  //          arguments should be consecutive above this, in the same order as
  //          they are to be pushed onto the stack.
  //  -- r4 : the target to call (can be any Object).
  // -----------------------------------
  Label stack_overflow;

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ subi(r3, r3, Operand(1));
  }

  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ subi(r6, r3, Operand(kJSArgcReceiverSlots));
  } else {
    __ mr(r6, r3);
  }

  __ StackOverflowCheck(r6, ip, &stack_overflow);

  // Push the arguments.
  GenerateInterpreterPushArgs(masm, r6, r5, r7);

  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ PushRoot(RootIndex::kUndefinedValue);
  }

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Pass the spread in the register r3.
    // r2 already points to the penultimate argument, the spread
    // lies in the next interpreter register.
    __ LoadU64(r5, MemOperand(r5, -kSystemPointerSize));
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
    // Unreachable Code.
    __ bkpt(0);
  }
}

// static
void Builtins::Generate_InterpreterPushArgsThenConstructImpl(
    MacroAssembler* masm, InterpreterPushArgsMode mode) {
  // ----------- S t a t e -------------
  // -- r3 : argument count
  // -- r6 : new target
  // -- r4 : constructor to call
  // -- r5 : allocation site feedback if available, undefined otherwise.
  // -- r7 : address of the first argument
  // -----------------------------------
  Label stack_overflow;
  __ StackOverflowCheck(r3, ip, &stack_overflow);

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ subi(r3, r3, Operand(1));
  }

  Register argc_without_receiver = ip;
  __ subi(argc_without_receiver, r3, Operand(kJSArgcReceiverSlots));

  // Push the arguments.
  GenerateInterpreterPushArgs(masm, argc_without_receiver, r7, r8);

  // Push a slot for the receiver to be constructed.
  __ li(r0, Operand::Zero());
  __ push(r0);

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Pass the spread in the register r2.
    // r4 already points to the penultimate argument, the spread
    // lies in the next interpreter register.
    __ subi(r7, r7, Operand(kSystemPointerSize));
    __ LoadU64(r5, MemOperand(r7));
  } else {
    __ AssertUndefinedOrAllocationSite(r5, r8);
  }

  if (mode == InterpreterPushArgsMode::kArrayFunction) {
    __ AssertFunction(r4);

    // Tail call to the array construct stub (still in the caller
    // context at this point).
    __ TailCallBuiltin(Builtin::kArrayConstructorImpl);
  } else if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Call the constructor with r3, r4, and r6 unmodified.
    __ TailCallBuiltin(Builtin::kConstructWithSpread);
  } else {
    DCHECK_EQ(InterpreterPushArgsMode::kOther, mode);
    // Call the constructor with r3, r4, and r6 unmodified.
    __ TailCallBuiltin(Builtin::kConstruct);
  }

  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    // Unreachable Code.
    __ bkpt(0);
  }
}

// static
void Builtins::Generate_ConstructForwardAllArgsImpl(
    MacroAssembler* masm, ForwardWhichFrame which_frame) {
  // ----------- S t a t e -------------
  // -- r6 : new target
  // -- r4 : constructor to call
  // -----------------------------------
  Label stack_overflow;

  // Load the frame pointer into r7.
  switch (which_frame) {
    case ForwardWhichFrame::kCurrentFrame:
      __ Move(r7, fp);
      break;
    case ForwardWhichFrame::kParentFrame:
      __ LoadU64(r7, MemOperand(fp,
"""


```