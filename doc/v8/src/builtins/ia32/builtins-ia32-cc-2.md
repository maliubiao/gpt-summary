Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/builtins/ia32/builtins-ia32.cc`. I need to analyze the different `Generate_` functions and describe what they do. Since it's part 3 of 7, I should focus on the specific functions present here and avoid speculating on the overall structure or missing parts.

Here's a breakdown of the functions and their likely functionalities:

*   `Generate_InterpreterEnterBytecode`: Likely sets up the interpreter state and jumps to the appropriate bytecode.
*   `Generate_InterpreterEnterAtNextBytecode`:  Seems to advance the interpreter to the next bytecode instruction.
*   `Generate_InterpreterEnterAtBytecode`:  Appears to be a direct entry point to interpreter bytecode execution.
*   `Generate_BaselineOutOfLinePrologue`:  Likely handles the setup for baseline compiled functions, including stack frame creation and feedback vector handling.
*   `Generate_BaselineOutOfLinePrologueDeopt`: Deals with deoptimization from the baseline prologue, cleaning up the stack and transitioning to the interpreter.
*   `Generate_ContinueToCodeStubBuiltin`, `Generate_ContinueToCodeStubBuiltinWithResult`, `Generate_ContinueToJavaScriptBuiltin`, `Generate_ContinueToJavaScriptBuiltinWithResult`:  These seem to be related to resuming execution after a code stub or builtin call, potentially handling return values.
*   `Generate_NotifyDeoptimized`:  Probably notifies the runtime system about a deoptimization event.
*   `Generate_FunctionPrototypeApply`, `Generate_FunctionPrototypeCall`: Implement the core logic of `Function.prototype.apply` and `Function.prototype.call`.
*   `Generate_ReflectApply`, `Generate_ReflectConstruct`: Implement the functionality of `Reflect.apply` and `Reflect.construct`.
*   `Generate_CallOrConstructVarargs`, `Generate_CallOrConstructForwardVarargs`: Handle variable arguments for function calls and constructor calls.
*   `Generate_CallFunction`: Implements the basic function call mechanism.

I will now structure the response to cover the requested aspects: a list of functionalities, whether it's related to Javascript and an example if so, potential code logic inferences with examples, common programming errors, and finally, a summary of its function as part 3.
这是 `v8/src/builtins/ia32/builtins-ia32.cc` 源代码的第 3 部分，主要包含以下功能：

**1. 解释器入口点和执行：**

*   **`Generate_InterpreterEnterBytecode(MacroAssembler* masm)`:**  当进入 JavaScript 代码的解释执行模式时，这个函数负责设置必要的寄存器，例如加载解释器分发表格的地址，获取 bytecode 数组的指针和当前 bytecode 的偏移量，并最终跳转到目标 bytecode 进行执行。

    *   **与 Javascript 的关系：** 这是 V8 引擎执行未编译的 JavaScript 代码的核心部分。
    *   **Javascript 例子：** 当一个函数第一次被调用，或者优化后的代码被反优化时，会进入解释器执行。
    *   **代码逻辑推理：**
        *   **假设输入：** 一个未编译的 JavaScript 函数被调用。
        *   **输出：** CPU 的执行流程跳转到该函数对应的 bytecode 指令。

*   **`Generate_InterpreterEnterAtNextBytecode(MacroAssembler* masm)`:**  在解释器执行过程中，当需要执行下一个 bytecode 指令时，这个函数会被调用。它负责计算下一个 bytecode 的偏移量，并更新栈帧中的 bytecode 偏移量。

    *   **与 Javascript 的关系：** 这是解释器执行 JavaScript 代码的步进过程。
    *   **Javascript 例子：**  解释器执行完一条 bytecode 指令后，会调用这个函数来执行下一条。
    *   **代码逻辑推理：**
        *   **假设输入：** 解释器当前执行在某个 bytecode 偏移量。
        *   **输出：** 栈帧中保存的 bytecode 偏移量被更新为下一个指令的起始位置。

*   **`Generate_InterpreterEnterAtBytecode(MacroAssembler* masm)`:**  这个函数看起来是 `Generate_InterpreterEnterBytecode` 的一个别名或者简化版本，用于直接进入指定 bytecode 偏移量的执行。

    *   **与 Javascript 的关系：** 同样是解释器执行 JavaScript 代码的一部分。

**2. 基线编译代码的入口和退出：**

*   **`Generate_BaselineOutOfLinePrologue(MacroAssembler* masm)`:**  这是基线编译器（Baseline Compiler）生成的函数的入口序言（prologue）。它负责设置栈帧，保存必要的寄存器，检查栈溢出，并处理反馈向量（Feedback Vector）以进行可能的优化。

    *   **与 Javascript 的关系：** 基线编译是 V8 的一个中间编译层级，用于在解释器和优化编译器之间提供性能提升。
    *   **Javascript 例子：**  一个函数被多次调用后，可能会被基线编译。
    *   **代码逻辑推理：**
        *   **假设输入：** 一个基线编译的 JavaScript 函数被调用。
        *   **输出：**  建立了一个新的栈帧，并执行了初步的性能优化准备工作。

*   **`Generate_BaselineOutOfLinePrologueDeopt(MacroAssembler* masm)`:**  当基线编译的代码需要反优化（deoptimize）回解释器执行时，这个函数会被调用。它负责清理基线编译代码设置的栈帧，并将控制权转移回解释器入口。

    *   **与 Javascript 的关系：**  处理基线编译代码执行过程中出现需要反优化的场景。
    *   **Javascript 例子：**  基线编译的代码执行时，如果遇到了某些无法处理的情况（例如参数类型不符合预期），会触发反优化。

**3. 从 CodeStub 或 Builtin 返回：**

*   **`Generate_ContinueToCodeStubBuiltin(MacroAssembler* masm)`, `Generate_ContinueToCodeStubBuiltinWithResult(MacroAssembler* masm)`, `Generate_ContinueToJavaScriptBuiltin(MacroAssembler* masm)`, `Generate_ContinueToJavaScriptBuiltinWithResult(MacroAssembler* masm)`:**  这些函数用于在执行完一个 CodeStub 或 Builtin 函数后，恢复执行流程。它们负责将寄存器中的值恢复到栈上，并跳转回调用点。`WithResult` 版本表示被调用的函数有返回值。

    *   **与 Javascript 的关系：**  JavaScript 代码的执行经常会调用底层的 CodeStub 或 Builtin 函数来实现某些功能。
    *   **Javascript 例子：**  执行 `Array.prototype.push()` 方法会调用一个底层的 Builtin 函数。
    *   **代码逻辑推理：**
        *   **假设输入：**  一个 CodeStub 或 Builtin 函数执行完毕，返回值在 `eax` 寄存器中（对于 `WithResult` 版本）。
        *   **输出：**  CPU 的执行流程返回到调用该 CodeStub 或 Builtin 的位置。

**4. 反优化通知：**

*   **`Generate_NotifyDeoptimized(MacroAssembler* masm)`:**  这个函数负责通知 V8 运行时系统发生了反优化事件。

    *   **与 Javascript 的关系：**  当优化后的代码需要回退到解释器执行时，会触发这个通知。

**5. `Function.prototype.apply` 和 `Function.prototype.call` 的实现：**

*   **`Generate_FunctionPrototypeApply(MacroAssembler* masm)`:**  实现了 `Function.prototype.apply()` 方法的核心逻辑，包括处理 `thisArg` 和参数数组 `argArray`。

    *   **与 Javascript 的关系：** 这是 JavaScript 中调用函数的一种重要方式。
    *   **Javascript 例子：**
        ```javascript
        function greet(name) {
          console.log(`Hello, ${name}! My name is ${this.myName}.`);
        }
        const obj = { myName: 'V8' };
        greet.apply(obj, ['Alice']); // 输出: Hello, Alice! My name is V8.
        ```
    *   **用户常见的编程错误：**  传递给 `apply` 的第二个参数不是一个数组或者 `null`/`undefined`。

*   **`Generate_FunctionPrototypeCall(MacroAssembler* masm)`:**  实现了 `Function.prototype.call()` 方法的核心逻辑，包括处理 `thisArg` 和一系列参数。

    *   **与 Javascript 的关系：**  这是 JavaScript 中调用函数的另一种重要方式。
    *   **Javascript 例子：**
        ```javascript
        function greet(name1, name2) {
          console.log(`Hello, ${name1} and ${name2}! My name is ${this.myName}.`);
        }
        const obj = { myName: 'V8' };
        greet.call(obj, 'Bob', 'Charlie'); // 输出: Hello, Bob and Charlie! My name is V8.
        ```
    *   **用户常见的编程错误：**  传递给 `call` 的第一个参数不是一个对象（作为 `this` 的绑定）。

**6. `Reflect.apply` 和 `Reflect.construct` 的实现：**

*   **`Generate_ReflectApply(MacroAssembler* masm)`:**  实现了 `Reflect.apply()` 方法的核心逻辑。

    *   **与 Javascript 的关系：**  这是 ES6 引入的 `Reflect` API 的一部分，用于更细粒度地控制函数调用。
    *   **Javascript 例子：**
        ```javascript
        function greet(name) {
          console.log(`Hello, ${name}!`);
        }
        Reflect.apply(greet, null, ['David']); // 输出: Hello, David!
        ```
    *   **用户常见的编程错误：**  传递给 `Reflect.apply` 的第二个参数不是一个对象或者 `null`。

*   **`Generate_ReflectConstruct(MacroAssembler* masm)`:**  实现了 `Reflect.construct()` 方法的核心逻辑。

    *   **与 Javascript 的关系：**  这是 ES6 引入的 `Reflect` API 的一部分，用于创建对象。
    *   **Javascript 例子：**
        ```javascript
        class Point {
          constructor(x, y) {
            this.x = x;
            this.y = y;
          }
        }
        const point = Reflect.construct(Point, [10, 20]);
        console.log(point.x, point.y); // 输出: 10 20
        ```
    *   **用户常见的编程错误：**  传递给 `Reflect.construct` 的第一个参数不是一个构造函数。

**7. 处理变长参数的函数调用和构造：**

*   **`Generate_CallOrConstructVarargs(MacroAssembler* masm, Builtin target_builtin)`:**  处理使用 `...` 展开运算符或者 `arguments` 对象等变长参数进行函数调用或构造的情况。

    *   **与 Javascript 的关系：**  用于支持 JavaScript 中灵活的参数传递方式。
    *   **Javascript 例子：**
        ```javascript
        function sum(...numbers) {
          return numbers.reduce((a, b) => a + b, 0);
        }
        const nums = [1, 2, 3, 4];
        console.log(sum(...nums)); // 输出: 10

        function Point(x, y) {
          this.x = x;
          this.y = y;
        }
        const coords = [5, 10];
        const point = new Point(...coords);
        console.log(point.x, point.y); // 输出: 5 10
        ```
    *   **用户常见的编程错误：**  尝试传递过多的参数，导致栈溢出。

*   **`Generate_CallOrConstructForwardVarargs(MacroAssembler* masm, CallOrConstructMode mode, Builtin target_builtin)`:**  处理在函数调用或构造过程中，将调用者的参数直接转发给被调用函数的情况，例如在使用 `apply` 或 `call` 时。

    *   **与 Javascript 的关系：**  支持函数参数的转发和代理。
    *   **Javascript 例子：**  内部实现 `Function.prototype.apply` 和 `Function.prototype.call` 时会使用到。

**8. 基本的函数调用机制：**

*   **`Generate_CallFunction(MacroAssembler* masm, ConvertReceiverMode mode)`:**  实现了基本的函数调用机制，包括获取函数上下文、处理 `this` 绑定（根据 `ConvertReceiverMode` 的不同处理 `null` 或 `undefined` 的 `this`）。

    *   **与 Javascript 的关系：**  这是 JavaScript 中最基础的函数调用方式。
    *   **Javascript 例子：**
        ```javascript
        function sayHello() {
          console.log("Hello!");
        }
        sayHello();
        ```

**总结：**

`v8/src/builtins/ia32/builtins-ia32.cc` 的第 3 部分主要负责 IA-32 架构下 V8 引擎中以下关键功能的实现：**解释器模式的进入和执行、基线编译代码的入口和反优化处理、从 CodeStub 和 Builtin 函数返回、`Function.prototype.apply` 和 `Function.prototype.call`、`Reflect.apply` 和 `Reflect.construct` 的实现，以及处理变长参数的函数调用和基本的函数调用机制。**  这些功能都是 V8 引擎执行 JavaScript 代码的核心组成部分。

### 提示词
```
这是目录为v8/src/builtins/ia32/builtins-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/ia32/builtins-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
table register.
  __ Move(kInterpreterDispatchTableRegister,
          Immediate(ExternalReference::interpreter_dispatch_table_address(
              masm->isolate())));

  // Get the bytecode array pointer from the frame.
  __ mov(kInterpreterBytecodeArrayRegister,
         Operand(ebp, InterpreterFrameConstants::kBytecodeArrayFromFp));

  if (v8_flags.debug_code) {
    // Check function data field is actually a BytecodeArray object.
    __ AssertNotSmi(kInterpreterBytecodeArrayRegister);
    __ CmpObjectType(kInterpreterBytecodeArrayRegister, BYTECODE_ARRAY_TYPE,
                     scratch);
    __ Assert(
        equal,
        AbortReason::kFunctionDataShouldBeBytecodeArrayOnInterpreterEntry);
  }

  // Get the target bytecode offset from the frame.
  __ mov(kInterpreterBytecodeOffsetRegister,
         Operand(ebp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);

  if (v8_flags.debug_code) {
    Label okay;
    __ cmp(kInterpreterBytecodeOffsetRegister,
           Immediate(BytecodeArray::kHeaderSize - kHeapObjectTag));
    __ j(greater_equal, &okay, Label::kNear);
    __ int3();
    __ bind(&okay);
  }

  // Dispatch to the target bytecode.
  __ movzx_b(scratch, Operand(kInterpreterBytecodeArrayRegister,
                              kInterpreterBytecodeOffsetRegister, times_1, 0));
  __ mov(kJavaScriptCallCodeStartRegister,
         Operand(kInterpreterDispatchTableRegister, scratch,
                 times_system_pointer_size, 0));
  __ jmp(kJavaScriptCallCodeStartRegister);
}

void Builtins::Generate_InterpreterEnterAtNextBytecode(MacroAssembler* masm) {
  // Get bytecode array and bytecode offset from the stack frame.
  __ mov(kInterpreterBytecodeArrayRegister,
         Operand(ebp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ mov(kInterpreterBytecodeOffsetRegister,
         Operand(ebp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);

  Label enter_bytecode, function_entry_bytecode;
  __ cmp(kInterpreterBytecodeOffsetRegister,
         Immediate(BytecodeArray::kHeaderSize - kHeapObjectTag +
                   kFunctionEntryBytecodeOffset));
  __ j(equal, &function_entry_bytecode);

  // Advance to the next bytecode.
  Label if_return;
  __ Push(eax);
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, ecx, esi,
                                eax, &if_return);
  __ Pop(eax);

  __ bind(&enter_bytecode);
  // Convert new bytecode offset to a Smi and save in the stackframe.
  __ mov(ecx, kInterpreterBytecodeOffsetRegister);
  __ SmiTag(ecx);
  __ mov(Operand(ebp, InterpreterFrameConstants::kBytecodeOffsetFromFp), ecx);

  Generate_InterpreterEnterBytecode(masm);

  __ bind(&function_entry_bytecode);
  // If the code deoptimizes during the implicit function entry stack interrupt
  // check, it will have a bailout ID of kFunctionEntryBytecodeOffset, which is
  // not a valid bytecode offset. Detect this case and advance to the first
  // actual bytecode.
  __ mov(kInterpreterBytecodeOffsetRegister,
         Immediate(BytecodeArray::kHeaderSize - kHeapObjectTag));
  __ jmp(&enter_bytecode);

  // We should never take the if_return path.
  __ bind(&if_return);
  // No need to pop eax here since we will be aborting anyway.
  __ Abort(AbortReason::kInvalidBytecodeAdvance);
}

void Builtins::Generate_InterpreterEnterAtBytecode(MacroAssembler* masm) {
  Generate_InterpreterEnterBytecode(masm);
}

// static
void Builtins::Generate_BaselineOutOfLinePrologue(MacroAssembler* masm) {
  auto descriptor =
      Builtins::CallInterfaceDescriptorFor(Builtin::kBaselineOutOfLinePrologue);
  Register arg_count = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kJavaScriptCallArgCount);
  Register frame_size = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kStackFrameSize);

  // Save argument count and bytecode array.
  XMMRegister saved_arg_count = xmm0;
  XMMRegister saved_bytecode_array = xmm1;
  XMMRegister saved_frame_size = xmm2;
  XMMRegister saved_feedback_cell = xmm3;
  XMMRegister saved_feedback_vector = xmm4;
  __ movd(saved_arg_count, arg_count);
  __ movd(saved_frame_size, frame_size);

  // Use the arg count (eax) as the scratch register.
  Register scratch = arg_count;

  // Load the feedback cell and vector from the closure.
  Register closure = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kClosure);
  Register feedback_cell = ecx;
  __ mov(feedback_cell, FieldOperand(closure, JSFunction::kFeedbackCellOffset));
  __ movd(saved_feedback_cell, feedback_cell);
  Register feedback_vector = ecx;
  __ mov(feedback_vector,
         FieldOperand(feedback_cell, FeedbackCell::kValueOffset));
  __ AssertFeedbackVector(feedback_vector, scratch);
  feedback_cell = no_reg;

  // Load the optimization state from the feedback vector and re-use the
  // register.
  Label flags_need_processing;
  Register flags = ecx;
  __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      flags, saved_feedback_vector, CodeKind::BASELINE, &flags_need_processing);

  // Reload the feedback vector.
  __ movd(feedback_vector, saved_feedback_vector);

  {
    DCHECK_EQ(arg_count, eax);
    ResetFeedbackVectorOsrUrgency(masm, feedback_vector, eax);
    __ movd(arg_count, saved_arg_count);  // Restore eax.
  }

  // Increment the invocation count.
  __ inc(FieldOperand(feedback_vector, FeedbackVector::kInvocationCountOffset));

  XMMRegister return_address = xmm5;
  // Save the return address, so that we can push it to the end of the newly
  // set-up frame once we're done setting it up.
  __ PopReturnAddressTo(return_address, scratch);
  // The bytecode array was pushed to the stack by the caller.
  __ Pop(saved_bytecode_array, scratch);
  FrameScope frame_scope(masm, StackFrame::MANUAL);
  {
    ASM_CODE_COMMENT_STRING(masm, "Frame Setup");
    __ EnterFrame(StackFrame::BASELINE);

    __ Push(descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kCalleeContext));  // Callee's
                                                                // context.
    Register callee_js_function = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kClosure);
    DCHECK_EQ(callee_js_function, kJavaScriptCallTargetRegister);
    DCHECK_EQ(callee_js_function, kJSFunctionRegister);
    ResetJSFunctionAge(masm, callee_js_function, scratch);
    __ Push(callee_js_function);        // Callee's JS function.
    __ Push(saved_arg_count, scratch);  // Push actual argument count.

    // We'll use the bytecode for both code age/OSR resetting, and pushing onto
    // the frame, so load it into a register.
    __ Push(saved_bytecode_array, scratch);
    __ Push(saved_feedback_cell, scratch);
    __ Push(saved_feedback_vector, scratch);
  }

  Label call_stack_guard;
  {
    ASM_CODE_COMMENT_STRING(masm, "Stack/interrupt check");
    // Stack check. This folds the checks for both the interrupt stack limit
    // check and the real stack limit into one by just checking for the
    // interrupt limit. The interrupt limit is either equal to the real stack
    // limit or tighter. By ensuring we have space until that limit after
    // building the frame we can quickly precheck both at once.
    //
    // TODO(v8:11429): Backport this folded check to the
    // InterpreterEntryTrampoline.
    __ movd(frame_size, saved_frame_size);
    __ Move(scratch, esp);
    DCHECK_NE(frame_size, kJavaScriptCallNewTargetRegister);
    __ sub(scratch, frame_size);
    __ CompareStackLimit(scratch, StackLimitKind::kInterruptStackLimit);
    __ j(below, &call_stack_guard);
  }

  // Push the return address back onto the stack for return.
  __ PushReturnAddressFrom(return_address, scratch);
  // Return to caller pushed pc, without any frame teardown.
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
  __ Ret();

  __ bind(&flags_need_processing);
  {
    ASM_CODE_COMMENT_STRING(masm, "Optimized marker check");
    // Drop the return address and bytecode array, rebalancing the return stack
    // buffer by using JumpMode::kPushAndReturn. We can't leave the slot and
    // overwrite it on return since we may do a runtime call along the way that
    // requires the stack to only contain valid frames.
    __ Drop(2);
    __ movd(arg_count, saved_arg_count);  // Restore actual argument count.
    __ OptimizeCodeOrTailCallOptimizedCodeSlot(flags, saved_feedback_vector);
    __ Trap();
  }

  __ bind(&call_stack_guard);
  {
    ASM_CODE_COMMENT_STRING(masm, "Stack/interrupt call");
    {
      // Push the baseline code return address now, as if it had been pushed by
      // the call to this builtin.
      __ PushReturnAddressFrom(return_address, scratch);
      FrameScope frame_scope(masm, StackFrame::INTERNAL);
      // Save incoming new target or generator
      __ Push(kJavaScriptCallNewTargetRegister);
      __ SmiTag(frame_size);
      __ Push(frame_size);
      __ CallRuntime(Runtime::kStackGuardWithGap, 1);
      __ Pop(kJavaScriptCallNewTargetRegister);
    }

    // Return to caller pushed pc, without any frame teardown.
    __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
    __ Ret();
  }
}

// static
void Builtins::Generate_BaselineOutOfLinePrologueDeopt(MacroAssembler* masm) {
  // We're here because we got deopted during BaselineOutOfLinePrologue's stack
  // check. Undo all its frame creation and call into the interpreter instead.

  // Drop the feedback vector.
  __ Pop(ecx);
  // Drop bytecode offset (was the feedback vector but got replaced during
  // deopt).
  __ Pop(ecx);
  // Drop bytecode array
  __ Pop(ecx);

  // argc.
  __ Pop(kJavaScriptCallArgCountRegister);
  // Closure.
  __ Pop(kJavaScriptCallTargetRegister);
  // Context.
  __ Pop(kContextRegister);

  // Drop frame pointer
  __ LeaveFrame(StackFrame::BASELINE);

  // Enter the interpreter.
  __ TailCallBuiltin(Builtin::kInterpreterEntryTrampoline);
}

namespace {
void Generate_ContinueToBuiltinHelper(MacroAssembler* masm,
                                      bool javascript_builtin,
                                      bool with_result) {
  const RegisterConfiguration* config(RegisterConfiguration::Default());
  int allocatable_register_count = config->num_allocatable_general_registers();
  if (with_result) {
    if (javascript_builtin) {
      // xmm0 is not included in the allocateable registers.
      __ movd(xmm0, eax);
    } else {
      // Overwrite the hole inserted by the deoptimizer with the return value
      // from the LAZY deopt point.
      __ mov(
          Operand(esp, config->num_allocatable_general_registers() *
                               kSystemPointerSize +
                           BuiltinContinuationFrameConstants::kFixedFrameSize),
          eax);
    }
  }

  // Replace the builtin index Smi on the stack with the start address of the
  // builtin loaded from the builtins table. The ret below will return to this
  // address.
  int offset_to_builtin_index = allocatable_register_count * kSystemPointerSize;
  __ mov(eax, Operand(esp, offset_to_builtin_index));
  __ LoadEntryFromBuiltinIndex(eax, eax);
  __ mov(Operand(esp, offset_to_builtin_index), eax);

  for (int i = allocatable_register_count - 1; i >= 0; --i) {
    int code = config->GetAllocatableGeneralCode(i);
    __ pop(Register::from_code(code));
    if (javascript_builtin && code == kJavaScriptCallArgCountRegister.code()) {
      __ SmiUntag(Register::from_code(code));
    }
  }
  if (with_result && javascript_builtin) {
    // Overwrite the hole inserted by the deoptimizer with the return value from
    // the LAZY deopt point. eax contains the arguments count, the return value
    // from LAZY is always the last argument.
    __ movd(Operand(esp, eax, times_system_pointer_size,
                    BuiltinContinuationFrameConstants::kFixedFrameSize -
                        kJSArgcReceiverSlots * kSystemPointerSize),
            xmm0);
  }
  __ mov(
      ebp,
      Operand(esp, BuiltinContinuationFrameConstants::kFixedFrameSizeFromFp));
  const int offsetToPC =
      BuiltinContinuationFrameConstants::kFixedFrameSizeFromFp -
      kSystemPointerSize;
  __ pop(Operand(esp, offsetToPC));
  __ Drop(offsetToPC / kSystemPointerSize);
  __ ret(0);
}
}  // namespace

void Builtins::Generate_ContinueToCodeStubBuiltin(MacroAssembler* masm) {
  Generate_ContinueToBuiltinHelper(masm, false, false);
}

void Builtins::Generate_ContinueToCodeStubBuiltinWithResult(
    MacroAssembler* masm) {
  Generate_ContinueToBuiltinHelper(masm, false, true);
}

void Builtins::Generate_ContinueToJavaScriptBuiltin(MacroAssembler* masm) {
  Generate_ContinueToBuiltinHelper(masm, true, false);
}

void Builtins::Generate_ContinueToJavaScriptBuiltinWithResult(
    MacroAssembler* masm) {
  Generate_ContinueToBuiltinHelper(masm, true, true);
}

void Builtins::Generate_NotifyDeoptimized(MacroAssembler* masm) {
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kNotifyDeoptimized);
    // Tear down internal frame.
  }

  DCHECK_EQ(kInterpreterAccumulatorRegister.code(), eax.code());
  __ mov(eax, Operand(esp, 1 * kSystemPointerSize));
  __ ret(1 * kSystemPointerSize);  // Remove eax.
}

// static
void Builtins::Generate_FunctionPrototypeApply(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax     : argc
  //  -- esp[0]  : return address
  //  -- esp[1]  : receiver
  //  -- esp[2]  : thisArg
  //  -- esp[3]  : argArray
  // -----------------------------------

  // 1. Load receiver into xmm0, argArray into edx (if present), remove all
  // arguments from the stack (including the receiver), and push thisArg (if
  // present) instead.
  {
    Label no_arg_array, no_this_arg;
    StackArgumentsAccessor args(eax);
    // Spill receiver to allow the usage of edi as a scratch register.
    __ movd(xmm0, args.GetReceiverOperand());

    __ LoadRoot(edx, RootIndex::kUndefinedValue);
    __ mov(edi, edx);
    __ cmp(eax, Immediate(JSParameterCount(0)));
    __ j(equal, &no_this_arg, Label::kNear);
    {
      __ mov(edi, args[1]);
      __ cmp(eax, Immediate(JSParameterCount(1)));
      __ j(equal, &no_arg_array, Label::kNear);
      __ mov(edx, args[2]);
      __ bind(&no_arg_array);
    }
    __ bind(&no_this_arg);
    __ DropArgumentsAndPushNewReceiver(eax, edi, ecx);

    // Restore receiver to edi.
    __ movd(edi, xmm0);
  }

  // ----------- S t a t e -------------
  //  -- edx    : argArray
  //  -- edi    : receiver
  //  -- esp[0] : return address
  //  -- esp[4] : thisArg
  // -----------------------------------

  // 2. We don't need to check explicitly for callable receiver here,
  // since that's the first thing the Call/CallWithArrayLike builtins
  // will do.

  // 3. Tail call with no arguments if argArray is null or undefined.
  Label no_arguments;
  __ JumpIfRoot(edx, RootIndex::kNullValue, &no_arguments, Label::kNear);
  __ JumpIfRoot(edx, RootIndex::kUndefinedValue, &no_arguments, Label::kNear);

  // 4a. Apply the receiver to the given argArray.
  __ TailCallBuiltin(Builtin::kCallWithArrayLike);

  // 4b. The argArray is either null or undefined, so we tail call without any
  // arguments to the receiver.
  __ bind(&no_arguments);
  {
    __ Move(eax, JSParameterCount(0));
    __ TailCallBuiltin(Builtins::Call());
  }
}

// static
void Builtins::Generate_FunctionPrototypeCall(MacroAssembler* masm) {
  // Stack Layout:
  // esp[0]           : Return address
  // esp[8]           : Argument 0 (receiver: callable to call)
  // esp[16]          : Argument 1
  //  ...
  // esp[8 * n]       : Argument n-1
  // esp[8 * (n + 1)] : Argument n
  // eax contains the number of arguments, n.

  // 1. Get the callable to call (passed as receiver) from the stack.
  {
    StackArgumentsAccessor args(eax);
    __ mov(edi, args.GetReceiverOperand());
  }

  // 2. Save the return address and drop the callable.
  __ PopReturnAddressTo(edx);
  __ Pop(ecx);

  // 3. Make sure we have at least one argument.
  {
    Label done;
    __ cmp(eax, Immediate(JSParameterCount(0)));
    __ j(greater, &done, Label::kNear);
    __ PushRoot(RootIndex::kUndefinedValue);
    __ inc(eax);
    __ bind(&done);
  }

  // 4. Push back the return address one slot down on the stack (overwriting the
  // original callable), making the original first argument the new receiver.
  __ PushReturnAddressFrom(edx);
  __ dec(eax);  // One fewer argument (first argument is new receiver).

  // 5. Call the callable.
  __ TailCallBuiltin(Builtins::Call());
}

void Builtins::Generate_ReflectApply(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax     : argc
  //  -- esp[0]  : return address
  //  -- esp[4]  : receiver
  //  -- esp[8]  : target         (if argc >= 1)
  //  -- esp[12] : thisArgument   (if argc >= 2)
  //  -- esp[16] : argumentsList  (if argc == 3)
  // -----------------------------------

  // 1. Load target into edi (if present), argumentsList into edx (if present),
  // remove all arguments from the stack (including the receiver), and push
  // thisArgument (if present) instead.
  {
    Label done;
    StackArgumentsAccessor args(eax);
    __ LoadRoot(edi, RootIndex::kUndefinedValue);
    __ mov(edx, edi);
    __ mov(ecx, edi);
    __ cmp(eax, Immediate(JSParameterCount(1)));
    __ j(below, &done, Label::kNear);
    __ mov(edi, args[1]);  // target
    __ j(equal, &done, Label::kNear);
    __ mov(ecx, args[2]);  // thisArgument
    __ cmp(eax, Immediate(JSParameterCount(3)));
    __ j(below, &done, Label::kNear);
    __ mov(edx, args[3]);  // argumentsList
    __ bind(&done);

    // Spill argumentsList to use edx as a scratch register.
    __ movd(xmm0, edx);

    __ DropArgumentsAndPushNewReceiver(eax, ecx, edx);

    // Restore argumentsList.
    __ movd(edx, xmm0);
  }

  // ----------- S t a t e -------------
  //  -- edx    : argumentsList
  //  -- edi    : target
  //  -- esp[0] : return address
  //  -- esp[4] : thisArgument
  // -----------------------------------

  // 2. We don't need to check explicitly for callable target here,
  // since that's the first thing the Call/CallWithArrayLike builtins
  // will do.

  // 3. Apply the target to the given argumentsList.
  __ TailCallBuiltin(Builtin::kCallWithArrayLike);
}

void Builtins::Generate_ReflectConstruct(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax     : argc
  //  -- esp[0]  : return address
  //  -- esp[4]  : receiver
  //  -- esp[8]  : target
  //  -- esp[12] : argumentsList
  //  -- esp[16] : new.target (optional)
  // -----------------------------------

  // 1. Load target into edi (if present), argumentsList into ecx (if present),
  // new.target into edx (if present, otherwise use target), remove all
  // arguments from the stack (including the receiver), and push thisArgument
  // (if present) instead.
  {
    Label done;
    StackArgumentsAccessor args(eax);
    __ LoadRoot(edi, RootIndex::kUndefinedValue);
    __ mov(edx, edi);
    __ mov(ecx, edi);
    __ cmp(eax, Immediate(JSParameterCount(1)));
    __ j(below, &done, Label::kNear);
    __ mov(edi, args[1]);  // target
    __ mov(edx, edi);
    __ j(equal, &done, Label::kNear);
    __ mov(ecx, args[2]);  // argumentsList
    __ cmp(eax, Immediate(JSParameterCount(3)));
    __ j(below, &done, Label::kNear);
    __ mov(edx, args[3]);  // new.target
    __ bind(&done);

    // Spill argumentsList to use ecx as a scratch register.
    __ movd(xmm0, ecx);

    __ DropArgumentsAndPushNewReceiver(
        eax, masm->RootAsOperand(RootIndex::kUndefinedValue), ecx);

    // Restore argumentsList.
    __ movd(ecx, xmm0);
  }

  // ----------- S t a t e -------------
  //  -- ecx    : argumentsList
  //  -- edx    : new.target
  //  -- edi    : target
  //  -- esp[0] : return address
  //  -- esp[4] : receiver (undefined)
  // -----------------------------------

  // 2. We don't need to check explicitly for constructor target here,
  // since that's the first thing the Construct/ConstructWithArrayLike
  // builtins will do.

  // 3. We don't need to check explicitly for constructor new.target here,
  // since that's the second thing the Construct/ConstructWithArrayLike
  // builtins will do.

  // 4. Construct the target with the given new.target and argumentsList.
  __ TailCallBuiltin(Builtin::kConstructWithArrayLike);
}

namespace {

// Allocate new stack space for |count| arguments and shift all existing
// arguments already on the stack. |pointer_to_new_space_out| points to the
// first free slot on the stack to copy additional arguments to and
// |argc_in_out| is updated to include |count|.
void Generate_AllocateSpaceAndShiftExistingArguments(
    MacroAssembler* masm, Register count, Register argc_in_out,
    Register pointer_to_new_space_out, Register scratch1, Register scratch2) {
  DCHECK(!AreAliased(count, argc_in_out, pointer_to_new_space_out, scratch1,
                     scratch2));
  // Use pointer_to_new_space_out as scratch until we set it to the correct
  // value at the end.
  Register old_esp = pointer_to_new_space_out;
  Register new_space = scratch1;
  __ mov(old_esp, esp);

  __ lea(new_space, Operand(count, times_system_pointer_size, 0));
  __ AllocateStackSpace(new_space);

  Register current = scratch1;
  Register value = scratch2;

  Label loop, entry;
  __ mov(current, 0);
  __ jmp(&entry);
  __ bind(&loop);
  __ mov(value, Operand(old_esp, current, times_system_pointer_size, 0));
  __ mov(Operand(esp, current, times_system_pointer_size, 0), value);
  __ inc(current);
  __ bind(&entry);
  __ cmp(current, argc_in_out);
  __ j(less_equal, &loop, Label::kNear);

  // Point to the next free slot above the shifted arguments (argc + 1 slot for
  // the return address).
  __ lea(
      pointer_to_new_space_out,
      Operand(esp, argc_in_out, times_system_pointer_size, kSystemPointerSize));
  // Update the total number of arguments.
  __ add(argc_in_out, count);
}

}  // namespace

// static
// TODO(v8:11615): Observe Code::kMaxArguments in CallOrConstructVarargs
void Builtins::Generate_CallOrConstructVarargs(MacroAssembler* masm,
                                               Builtin target_builtin) {
  // ----------- S t a t e -------------
  //  -- edi    : target
  //  -- esi    : context for the Call / Construct builtin
  //  -- eax    : number of parameters on the stack
  //  -- ecx    : len (number of elements to from args)
  //  -- edx    : new.target (checked to be constructor or undefined)
  //  -- esp[4] : arguments list (a FixedArray)
  //  -- esp[0] : return address.
  // -----------------------------------

  __ movd(xmm0, edx);  // Spill new.target.
  __ movd(xmm1, edi);  // Spill target.
  __ movd(xmm3, esi);  // Spill the context.

  const Register kArgumentsList = esi;
  const Register kArgumentsLength = ecx;

  __ PopReturnAddressTo(edx);
  __ pop(kArgumentsList);
  __ PushReturnAddressFrom(edx);

  if (v8_flags.debug_code) {
    // Allow kArgumentsList to be a FixedArray, or a FixedDoubleArray if
    // kArgumentsLength == 0.
    Label ok, fail;
    __ AssertNotSmi(kArgumentsList);
    __ mov(edx, FieldOperand(kArgumentsList, HeapObject::kMapOffset));
    __ CmpInstanceType(edx, FIXED_ARRAY_TYPE);
    __ j(equal, &ok);
    __ CmpInstanceType(edx, FIXED_DOUBLE_ARRAY_TYPE);
    __ j(not_equal, &fail);
    __ cmp(kArgumentsLength, 0);
    __ j(equal, &ok);
    // Fall through.
    __ bind(&fail);
    __ Abort(AbortReason::kOperandIsNotAFixedArray);

    __ bind(&ok);
  }

  // Check the stack for overflow. We are not trying to catch interruptions
  // (i.e. debug break and preemption) here, so check the "real stack limit".
  Label stack_overflow;
  __ StackOverflowCheck(kArgumentsLength, edx, &stack_overflow);

  __ movd(xmm4, kArgumentsList);  // Spill the arguments list.
  // Move the arguments already in the stack,
  // including the receiver and the return address.
  // kArgumentsLength (ecx): Number of arguments to make room for.
  // eax: Number of arguments already on the stack.
  // edx: Points to first free slot on the stack after arguments were shifted.
  Generate_AllocateSpaceAndShiftExistingArguments(masm, kArgumentsLength, eax,
                                                  edx, edi, esi);
  __ movd(kArgumentsList, xmm4);  // Recover arguments list.
  __ movd(xmm2, eax);             // Spill argument count.

  // Push additional arguments onto the stack.
  {
    __ Move(eax, Immediate(0));
    Label done, push, loop;
    __ bind(&loop);
    __ cmp(eax, kArgumentsLength);
    __ j(equal, &done, Label::kNear);
    // Turn the hole into undefined as we go.
    __ mov(edi, FieldOperand(kArgumentsList, eax, times_tagged_size,
                             OFFSET_OF_DATA_START(FixedArray)));
    __ CompareRoot(edi, RootIndex::kTheHoleValue);
    __ j(not_equal, &push, Label::kNear);
    __ LoadRoot(edi, RootIndex::kUndefinedValue);
    __ bind(&push);
    __ mov(Operand(edx, 0), edi);
    __ add(edx, Immediate(kSystemPointerSize));
    __ inc(eax);
    __ jmp(&loop);
    __ bind(&done);
  }

  // Restore eax, edi and edx.
  __ movd(esi, xmm3);  // Restore the context.
  __ movd(eax, xmm2);  // Restore argument count.
  __ movd(edi, xmm1);  // Restore target.
  __ movd(edx, xmm0);  // Restore new.target.

  // Tail-call to the actual Call or Construct builtin.
  __ TailCallBuiltin(target_builtin);

  __ bind(&stack_overflow);
  __ movd(esi, xmm3);  // Restore the context.
  __ TailCallRuntime(Runtime::kThrowStackOverflow);
}

// static
void Builtins::Generate_CallOrConstructForwardVarargs(MacroAssembler* masm,
                                                      CallOrConstructMode mode,
                                                      Builtin target_builtin) {
  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edi : the target to call (can be any Object)
  //  -- esi : context for the Call / Construct builtin
  //  -- edx : the new target (for [[Construct]] calls)
  //  -- ecx : start index (to support rest parameters)
  // -----------------------------------

  __ movd(xmm0, esi);  // Spill the context.

  Register scratch = esi;

  // Check if new.target has a [[Construct]] internal method.
  if (mode == CallOrConstructMode::kConstruct) {
    Label new_target_constructor, new_target_not_constructor;
    __ JumpIfSmi(edx, &new_target_not_constructor, Label::kNear);
    __ mov(scratch, FieldOperand(edx, HeapObject::kMapOffset));
    __ test_b(FieldOperand(scratch, Map::kBitFieldOffset),
              Immediate(Map::Bits1::IsConstructorBit::kMask));
    __ j(not_zero, &new_target_constructor, Label::kNear);
    __ bind(&new_target_not_constructor);
    {
      FrameScope scope(masm, StackFrame::MANUAL);
      __ EnterFrame(StackFrame::INTERNAL);
      __ Push(edx);
      __ movd(esi, xmm0);  // Restore the context.
      __ CallRuntime(Runtime::kThrowNotConstructor);
    }
    __ bind(&new_target_constructor);
  }

  __ movd(xmm1, edx);  // Preserve new.target (in case of [[Construct]]).

  Label stack_done, stack_overflow;
  __ mov(edx, Operand(ebp, StandardFrameConstants::kArgCOffset));
  __ dec(edx);  // Exclude receiver.
  __ sub(edx, ecx);
  __ j(less_equal, &stack_done);
  {
    // ----------- S t a t e -------------
    //  -- eax : the number of arguments already in the stack
    //  -- ecx : start index (to support rest parameters)
    //  -- edx : number of arguments to copy, i.e. arguments count - start index
    //  -- edi : the target to call (can be any Object)
    //  -- ebp : point to the caller stack frame
    //  -- xmm0 : context for the Call / Construct builtin
    //  -- xmm1 : the new target (for [[Construct]] calls)
    // -----------------------------------

    // Forward the arguments from the caller frame.
    __ movd(xmm2, edi);  // Preserve the target to call.
    __ StackOverflowCheck(edx, edi, &stack_overflow);
    __ movd(xmm3, ebx);  // Preserve root register.

    Register scratch = ebx;

    // Move the arguments already in the stack,
    // including the receiver and the return address.
    // edx: Number of arguments to make room for.
    // eax: Number of arguments already on the stack.
    // esi: Points to first free slot on the stack after arguments were shifted.
    Generate_AllocateSpaceAndShiftExistingArguments(masm, edx, eax, esi, ebx,
                                                    edi);

    // Point to the first argument to copy (skipping receiver).
    __ lea(ecx, Operand(ecx, times_system_pointer_size,
                        CommonFrameConstants::kFixedFrameSizeAboveFp +
                            kSystemPointerSize));
    __ add(ecx, ebp);

    // Copy the additional caller arguments onto the stack.
    // TODO(victorgomes): Consider using forward order as potentially more cache
    // friendly.
    {
      Register src = ecx, dest = esi, num = edx;
      Label loop;
      __ bind(&loop);
      __ dec(num);
      __ mov(scratch, Operand(src, num, times_system_pointer_size, 0));
      __ mov(Operand(dest, num, times_system_pointer_size, 0), scratch);
      __ j(not_zero, &loop);
    }

    __ movd(ebx, xmm3);  // Restore root register.
    __ movd(edi, xmm2);  // Restore the target to call.
  }
  __ bind(&stack_done);

  __ movd(edx, xmm1);  // Restore new.target (in case of [[Construct]]).
  __ movd(esi, xmm0);  // Restore the context.

  // Tail-call to the actual Call or Construct builtin.
  __ TailCallBuiltin(target_builtin);

  __ bind(&stack_overflow);
  __ movd(edi, xmm2);  // Restore the target to call.
  __ movd(esi, xmm0);  // Restore the context.
  __ TailCallRuntime(Runtime::kThrowStackOverflow);
}

// static
void Builtins::Generate_CallFunction(MacroAssembler* masm,
                                     ConvertReceiverMode mode) {
  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edi : the function to call (checked to be a JSFunction)
  // -----------------------------------
  StackArgumentsAccessor args(eax);
  __ AssertCallableFunction(edi, edx);

  __ mov(edx, FieldOperand(edi, JSFunction::kSharedFunctionInfoOffset));

  // Enter the context of the function; ToObject has to run in the function
  // context, and we also need to take the global proxy from the function
  // context in case of conversion.
  __ mov(esi, FieldOperand(edi, JSFunction::kContextOffset));
  // We need to convert the receiver for non-native sloppy mode functions.
  Label done_convert;
  __ test(FieldOperand(edx, SharedFunctionInfo::kFlagsOffset),
          Immediate(SharedFunctionInfo::IsNativeBit::kMask |
                    SharedFunctionInfo::IsStrictBit::kMask));
  __ j(not_zero, &done_convert);
  {
    // ----------- S t a t e -------------
    //  -- eax : the number of arguments
    //  -- edx : the shared function info.
    //  -- edi : the function to call (checked to be a JSFunction)
    //  -- esi : the function context.
    // -----------------------------------

    if (mode == ConvertReceiverMode::kNullOrUndefined) {
      // Patch receiver to global proxy.
      __ LoadGlobalProxy(ecx);
    } else {
      Label convert_to_object, convert_receiver;
      __ mov(ecx, args.GetReceiverOperand());
      __ JumpIfSmi(ecx, &convert_to_object, Label::kNear);
      static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
      __ CmpObjectType(ecx, FIRST_JS_RECEIVER_TYPE, ecx);  // Clobbers ecx.
      __ j(above_equal, &done_convert);
      // Reload the receiver (it was clobbered by CmpObjectType).
      __ mov(ecx, args.GetReceiverOperand());
      if (mode != ConvertReceiverMode::kNotNullOrUndefined) {
        Label convert_global_proxy;
        __ JumpIfRoot(ecx, RootIndex::kUndefinedValue, &convert_global_proxy,
                      Label::kNear);
        __ JumpIfNotRoot(ecx, RootIndex::kNullValue, &convert_to_object,
                         Label::kNear);
        __ bind(&convert_global_proxy);
        {
          // Patch receiver to global proxy.
          __ LoadGlobalProxy(ecx);
        }
        __ jmp(&convert_receiver);
      }
      __ bind(&convert_to_object);
      {
        // Convert receiver using ToObject.
        // TODO(bmeurer): Inline the allocation here to avoid building the frame
        // in the fast case? (fall back to AllocateInNewSpace?)
        FrameScope scope(masm, StackFrame::INTERNAL);
        __ SmiTag(eax);
        __ Push(eax);
        __ Push(edi);
        __ mov(eax, ecx);
        __ Push(esi);
        __ CallBuiltin(Builtin::kToObject);
        __ Pop(esi);
```