Response:
The user wants me to analyze a V8 source code file written in assembly for the x64 architecture.
The file is located at `v8/src/builtins/x64/builtins-x64.cc`.

Here's a breakdown of what I need to do:

1. **List the functionalities:**  I will go through the code and identify the purpose of each generated assembly function. The function names (like `Generate_FastConstruct`, `Generate_InterpreterEnterBytecode`, etc.) provide strong hints.

2. **Torque check:** I need to verify if the filename ends with `.tq`. In this case, it ends with `.cc`, so it's not a Torque file.

3. **JavaScript relationship:** If a function is related to JavaScript functionality, I'll provide a JavaScript example. This involves understanding what each assembly function does in the context of JavaScript execution.

4. **Code logic reasoning:** For functions with clear logical steps, I will create a hypothetical input and predict the output based on the code. This might be tricky for low-level assembly.

5. **Common programming errors:** If a function relates to common programming mistakes, I'll provide examples.

6. **Part identification:** The user specified this is "Part 3 of 7". I need to keep this context in mind, although it doesn't directly affect the analysis of this specific code snippet.

7. **Summarize the functionalities:** Finally, I need to provide a concise summary of the overall purpose of the code.

**Plan:**

* Scan the code for function definitions starting with `Generate_`.
* For each function:
    * Briefly describe its purpose based on its name and code.
    * If related to JavaScript, create a simple JavaScript example.
    * If there's clear logic, provide an input/output example.
    * If it relates to common errors, give an example of such an error.
* After analyzing all functions, write a summary.
这是V8 JavaScript引擎中用于x64架构的内置函数实现代码片段。以下是该代码片段中各个函数的功能归纳：

**1. `Generate_FastConstruct(MacroAssembler* masm)`**

* **功能:**  实现快速的对象构造过程。当使用 `new` 关键字调用构造函数时，如果满足某些优化条件，V8会尝试使用这个快速路径来创建对象。它处理了构造函数调用、结果检查以及可能的异常抛出。
* **JavaScript 示例:**
   ```javascript
   class MyClass {
     constructor(value) {
       this.value = value;
     }
   }
   const instance = new MyClass(10);
   ```
* **代码逻辑推理 (假设):**
    * **输入:**  一个构造函数 `MyClass` 和参数 `10`。
    * **输出:**  一个新的 `MyClass` 实例，其 `value` 属性为 `10`。
* **常见编程错误:**  在构造函数中忘记 `return this;` (虽然在严格模式下是隐式的，但在非严格模式下可能导致问题，但 `FastConstruct` 通常会处理这种情况)。
   ```javascript
   function BadClass(value) {
     this.value = value;
     // 忘记 return this;
   }
   const badInstance = new BadClass(5);
   console.log(badInstance); // 在非严格模式下可能输出 undefined
   ```

**2. `Generate_InterpreterEnterBytecode(MacroAssembler* masm)`**

* **功能:**  负责进入字节码解释器。当JavaScript代码需要被解释执行时，这个函数会设置解释器所需的环境，例如加载字节码数组、偏移量以及分发表格等，然后跳转到解释器的入口点。
* **JavaScript 示例:**  所有未被编译成机器码的JavaScript代码都会通过解释器执行。
   ```javascript
   function myFunction(a, b) {
     return a + b; // 这段代码可能会被解释执行
   }
   myFunction(1, 2);
   ```

**3. `Builtins::Generate_InterpreterEnterAtNextBytecode(MacroAssembler* masm)`**

* **功能:**  在解释器中执行下一个字节码指令。它首先检查是否需要处理去优化的情况，然后计算下一个字节码的偏移量，并跳转到相应的指令。
* **JavaScript 示例:**  在解释器执行过程中，会逐个执行字节码指令。
   ```javascript
   function add(x, y) {
     return x + y; // 这会被编译成一系列字节码指令
   }
   add(5, 3);
   ```

**4. `Builtins::Generate_InterpreterEnterAtBytecode(MacroAssembler* masm)`**

* **功能:**  直接进入解释器执行指定的字节码。它也处理去优化的情况，然后直接跳转到解释器的入口。
* **JavaScript 示例:**  类似于 `Generate_InterpreterEnterBytecode`，用于启动解释器执行。

**5. `Builtins::Generate_BaselineOutOfLinePrologue(MacroAssembler* masm)`**

* **功能:**  在基线（Baseline）编译代码中，为函数调用设置栈帧的序言部分。它处理了反馈向量的加载、调用计数器的增加、栈溢出检查以及保存必要的寄存器。基线编译是一种轻量级的优化，用于在解释执行之后，全速优化之前提供一定的性能提升。
* **JavaScript 示例:** 当一个函数被多次调用但尚未被完全优化时，可能会使用基线编译。
   ```javascript
   function count(n) {
     let sum = 0;
     for (let i = 0; i < n; i++) {
       sum += i;
     }
     return sum;
   }
   for (let i = 0; i < 1000; i++) {
     count(i); // 在多次调用后可能会触发基线编译
   }
   ```

**6. `Builtins::Generate_BaselineOutOfLinePrologueDeopt(MacroAssembler* masm)`**

* **功能:**  处理从基线编译代码去优化（deoptimization）的情况。当基线代码遇到无法处理的情况时，需要回退到解释器执行。这个函数负责清理基线代码的栈帧，并跳转回解释器入口。
* **JavaScript 示例:**  当基线编译的代码遇到假设失效的情况时，会发生去优化。
   ```javascript
   function maybeNumber(x) {
     if (typeof x === 'number') {
       return x + 1; // 假设 x 是数字
     } else {
       return undefined;
     }
   }
   maybeNumber(5); // 正常执行
   maybeNumber("not a number"); // 触发去优化，因为类型假设失效
   ```

**7. `Builtins::Generate_ContinueToCodeStubBuiltin(MacroAssembler* masm)`**

* **功能:**  用于在执行完一段代码存根（CodeStub）后继续执行。它负责恢复之前保存的寄存器状态，并跳转到目标地址。代码存根是V8中用于执行特定操作的预编译代码片段。

**8. `Builtins::Generate_ContinueToCodeStubBuiltinWithResult(MacroAssembler* masm)`**

* **功能:**  类似于 `Generate_ContinueToCodeStubBuiltin`，但它处理带有返回结果的代码存根。

**9. `Builtins::Generate_ContinueToJavaScriptBuiltin(MacroAssembler* masm)`**

* **功能:**  用于在执行完一段 JavaScript 内置函数后继续执行。

**10. `Builtins::Generate_ContinueToJavaScriptBuiltinWithResult(MacroAssembler* masm)`**

* **功能:**  类似于 `Generate_ContinueToJavaScriptBuiltin`，但处理带有返回结果的 JavaScript 内置函数。

**11. `Builtins::Generate_NotifyDeoptimized(MacroAssembler* masm)`**

* **功能:**  通知运行时系统发生了去优化。这通常涉及到调用运行时函数来记录和处理去优化事件。

**12. `Builtins::Generate_FunctionPrototypeApply(MacroAssembler* masm)`**

* **功能:**  实现 `Function.prototype.apply()` 方法。它负责设置 `this` 上下文和参数，并调用目标函数。
* **JavaScript 示例:**
   ```javascript
   function greet(greeting) {
     console.log(greeting + ' ' + this.name);
   }
   const person = { name: 'Alice' };
   greet.apply(person, ['Hello']); // 输出 "Hello Alice"
   ```

**13. `Builtins::Generate_FunctionPrototypeCall(MacroAssembler* masm)`**

* **功能:**  实现 `Function.prototype.call()` 方法。类似于 `apply`，但参数是直接传递的，而不是作为数组。
* **JavaScript 示例:**
   ```javascript
   function greet(greeting, punctuation) {
     console.log(greeting + ' ' + this.name + punctuation);
   }
   const person = { name: 'Bob' };
   greet.call(person, 'Hi', '!'); // 输出 "Hi Bob!"
   ```

**14. `Builtins::Generate_ReflectApply(MacroAssembler* masm)`**

* **功能:**  实现 `Reflect.apply()` 方法，它提供了与 `Function.prototype.apply()` 类似的功能，但更加清晰和规范。
* **JavaScript 示例:**
   ```javascript
   function multiply(a, b) {
     return a * b;
   }
   const result = Reflect.apply(multiply, null, [2, 3]);
   console.log(result); // 输出 6
   ```

**15. `Builtins::Generate_ReflectConstruct(MacroAssembler* masm)`**

* **功能:**  实现 `Reflect.construct()` 方法，用于调用构造函数，类似于使用 `new` 关键字。
* **JavaScript 示例:**
   ```javascript
   class Point {
     constructor(x, y) {
       this.x = x;
       this.y = y;
     }
   }
   const point = Reflect.construct(Point, [1, 2]);
   console.log(point.x, point.y); // 输出 1 2
   ```

**16. `Builtins::Generate_CallOrConstructVarargs(MacroAssembler* masm, Builtin target_builtin)`**

* **功能:**  一个通用的函数，用于处理使用可变数量的参数进行函数调用或构造函数调用的情况。它从一个固定数组中获取参数并将它们推入栈中。
* **JavaScript 示例:** 这通常用于实现像 `...` 扩展运算符这样的功能。
   ```javascript
   function sum(...numbers) {
     return numbers.reduce((a, b) => a + b, 0);
   }
   const args = [1, 2, 3];
   sum(...args); // 使用扩展运算符
   ```

**17. `Builtins::Generate_CallOrConstructForwardVarargs(MacroAssembler* masm, CallOrConstructMode mode, Builtin target_builtin)`**

* **功能:**  类似于 `Generate_CallOrConstructVarargs`，但它直接从调用者的栈帧中转发可变数量的参数。这在实现 rest 参数或转发参数时非常有用。
* **JavaScript 示例:**
   ```javascript
   function outer(a, b, ...rest) {
     inner(...rest); // 转发 rest 参数
   }
   function inner(x, y) {
     console.log(x, y);
   }
   outer(1, 2, 3, 4); // 调用 outer 会转发参数 3 和 4 给 inner
   ```

**18. `Builtins::Generate_CallFunction(MacroAssembler* masm, ConvertReceiverMode mode)`**

* **功能:**  实现标准的函数调用过程。它负责设置接收者（`this`）并调用目标函数。`ConvertReceiverMode` 参数决定了在非对象接收者的情况下如何处理 `this` 值。
* **JavaScript 示例:**  最常见的函数调用方式。
   ```javascript
   function sayHello() {
     console.log('Hello, ' + this.name);
   }
   const obj = { name: 'Charlie', greet: sayHello };
   obj.greet(); //  this 指向 obj
   ```

**总结：**

这段 `v8/src/builtins/x64/builtins-x64.cc` 代码片段是 V8 引擎中 x64 架构下实现多种核心内置函数的关键部分。它包含了对象构造、解释器入口和执行、基线编译的序言和去优化处理，以及 `Function.prototype.call`、`apply` 和 `Reflect` API 的实现。这些内置函数是 JavaScript 语言运行的基础，提供了诸如函数调用、对象创建等核心能力。这段代码直接操作底层的机器指令，以实现最高的执行效率。

Prompt: 
```
这是目录为v8/src/builtins/x64/builtins-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/x64/builtins-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共7部分，请归纳一下它的功能

"""
ot(rax, RootIndex::kUndefinedValue, &check_result,
                   Label::kNear);

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ movq(rax,
          Operand(rbp, FastConstructFrameConstants::kImplicitReceiverOffset));
  __ JumpIfRoot(rax, RootIndex::kTheHoleValue, &do_throw, Label::kNear);

  __ bind(&leave_and_return);
  __ LeaveFrame(StackFrame::FAST_CONSTRUCT);
  __ ret(0);

  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ bind(&check_result);
  __ JumpIfSmi(rax, &use_receiver, Label::kNear);

  // Check if the type of the result is not an object in the ECMA sense.
  __ JumpIfJSAnyIsNotPrimitive(rax, rcx, &leave_and_return, Label::kNear);
  __ jmp(&use_receiver);

  __ bind(&do_throw);
  __ movq(rsi, Operand(rbp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  // We don't return here.
  __ int3();

  __ bind(&builtin_call);
  // TODO(victorgomes): Check the possibility to turn this into a tailcall.
  __ InvokeFunction(rdi, rdx, rax, InvokeType::kCall);
  __ LeaveFrame(StackFrame::FAST_CONSTRUCT);
  __ ret(0);

  // Called Construct on an Object that doesn't have a [[Construct]] internal
  // method.
  __ bind(&non_constructor);
  __ TailCallBuiltin(Builtin::kConstructedNonConstructable);

  // Throw stack overflow exception.
  __ bind(&stack_overflow);
  __ TailCallRuntime(Runtime::kThrowStackOverflow);
  // This should be unreachable.
  __ int3();

  Generate_CallToAdaptShadowStackForDeopt(masm, false);
  // Store offset of return address for deoptimizer.
  masm->isolate()->heap()->SetConstructStubInvokeDeoptPCOffset(
      masm->pc_offset());
  __ jmp(&deopt_entry);
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
  __ movq(rbx, Operand(rbp, StandardFrameConstants::kFunctionOffset));
  const Register shared_function_info(rbx);
  __ LoadTaggedField(shared_function_info,
                     FieldOperand(rbx, JSFunction::kSharedFunctionInfoOffset));

  __ LoadTrustedPointerField(
      rbx,
      FieldOperand(shared_function_info,
                   SharedFunctionInfo::kTrustedFunctionDataOffset),
      kUnknownIndirectPointerTag, kScratchRegister);
  __ IsObjectType(rbx, INTERPRETER_DATA_TYPE, kScratchRegister);
  __ j(not_equal, &builtin_trampoline, Label::kNear);
  __ LoadProtectedPointerField(
      rbx, FieldOperand(rbx, InterpreterData::kInterpreterTrampolineOffset));
  __ LoadCodeInstructionStart(rbx, rbx, kJSEntrypointTag);
  __ jmp(&trampoline_loaded, Label::kNear);

  __ bind(&builtin_trampoline);
  // TODO(jgruber): Replace this by a lookup in the builtin entry table.
  __ movq(rbx,
          __ ExternalReferenceAsOperand(
              ExternalReference::
                  address_of_interpreter_entry_trampoline_instruction_start(
                      masm->isolate()),
              kScratchRegister));

  __ bind(&trampoline_loaded);
  __ addq(rbx, Immediate(interpreter_entry_return_pc_offset.value()));
  __ movq(kScratchRegister, rbx);

  // Initialize dispatch table register.
  __ Move(
      kInterpreterDispatchTableRegister,
      ExternalReference::interpreter_dispatch_table_address(masm->isolate()));

  // Get the bytecode array pointer from the frame.
  __ movq(kInterpreterBytecodeArrayRegister,
          Operand(rbp, InterpreterFrameConstants::kBytecodeArrayFromFp));

  if (v8_flags.debug_code) {
    // Check function data field is actually a BytecodeArray object.
    __ AssertNotSmi(kInterpreterBytecodeArrayRegister);
    __ IsObjectType(kInterpreterBytecodeArrayRegister, BYTECODE_ARRAY_TYPE,
                    kScratchRegister);
    __ Assert(
        equal,
        AbortReason::kFunctionDataShouldBeBytecodeArrayOnInterpreterEntry);
  }

  // Get the target bytecode offset from the frame.
  __ SmiUntagUnsigned(
      kInterpreterBytecodeOffsetRegister,
      Operand(rbp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  if (v8_flags.debug_code) {
    Label okay;
    __ cmpq(kInterpreterBytecodeOffsetRegister,
            Immediate(BytecodeArray::kHeaderSize - kHeapObjectTag));
    __ j(greater_equal, &okay, Label::kNear);
    __ int3();
    __ bind(&okay);
  }

  // Dispatch to the target bytecode.
  __ movzxbq(kScratchRegister,
             Operand(kInterpreterBytecodeArrayRegister,
                     kInterpreterBytecodeOffsetRegister, times_1, 0));
  __ movq(kJavaScriptCallCodeStartRegister,
          Operand(kInterpreterDispatchTableRegister, kScratchRegister,
                  times_system_pointer_size, 0));

  // Jump to the interpreter entry, and call kJavaScriptCallCodeStartRegister.
  __ jmp(rbx);
}

void Builtins::Generate_InterpreterEnterAtNextBytecode(MacroAssembler* masm) {
  Generate_CallToAdaptShadowStackForDeopt(masm, true);
  masm->isolate()->heap()->SetDeoptPCOffsetAfterAdaptShadowStack(
      masm->pc_offset());

  // Get bytecode array and bytecode offset from the stack frame.
  __ movq(kInterpreterBytecodeArrayRegister,
          Operand(rbp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ SmiUntagUnsigned(
      kInterpreterBytecodeOffsetRegister,
      Operand(rbp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  Label enter_bytecode, function_entry_bytecode;
  __ cmpq(kInterpreterBytecodeOffsetRegister,
          Immediate(BytecodeArray::kHeaderSize - kHeapObjectTag +
                    kFunctionEntryBytecodeOffset));
  __ j(equal, &function_entry_bytecode);

  // Load the current bytecode.
  __ movzxbq(rbx, Operand(kInterpreterBytecodeArrayRegister,
                          kInterpreterBytecodeOffsetRegister, times_1, 0));

  // Advance to the next bytecode.
  Label if_return;
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, rbx, rcx,
                                r8, &if_return);

  __ bind(&enter_bytecode);
  // Convert new bytecode offset to a Smi and save in the stackframe.
  __ SmiTag(kInterpreterBytecodeOffsetRegister);
  __ movq(Operand(rbp, InterpreterFrameConstants::kBytecodeOffsetFromFp),
          kInterpreterBytecodeOffsetRegister);

  Generate_InterpreterEnterBytecode(masm);

  __ bind(&function_entry_bytecode);
  // If the code deoptimizes during the implicit function entry stack interrupt
  // check, it will have a bailout ID of kFunctionEntryBytecodeOffset, which is
  // not a valid bytecode offset. Detect this case and advance to the first
  // actual bytecode.
  __ Move(kInterpreterBytecodeOffsetRegister,
          BytecodeArray::kHeaderSize - kHeapObjectTag);
  __ jmp(&enter_bytecode);

  // We should never take the if_return path.
  __ bind(&if_return);
  __ Abort(AbortReason::kInvalidBytecodeAdvance);
}

void Builtins::Generate_InterpreterEnterAtBytecode(MacroAssembler* masm) {
  Generate_CallToAdaptShadowStackForDeopt(masm, true);
  masm->isolate()->heap()->SetDeoptPCOffsetAfterAdaptShadowStack(
      masm->pc_offset());

  Generate_InterpreterEnterBytecode(masm);
}

// static
void Builtins::Generate_BaselineOutOfLinePrologue(MacroAssembler* masm) {
  Register feedback_cell = r8;
  Register feedback_vector = r9;
  Register return_address = r11;

#ifdef DEBUG
  for (auto reg : BaselineOutOfLinePrologueDescriptor::registers()) {
    DCHECK(!AreAliased(feedback_vector, return_address, reg));
  }
#endif

  auto descriptor =
      Builtins::CallInterfaceDescriptorFor(Builtin::kBaselineOutOfLinePrologue);
  Register closure = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kClosure);
  // Load the feedback cell and vector from the closure.
  __ LoadTaggedField(feedback_cell,
                     FieldOperand(closure, JSFunction::kFeedbackCellOffset));
  __ LoadTaggedField(feedback_vector,
                     FieldOperand(feedback_cell, FeedbackCell::kValueOffset));
  __ AssertFeedbackVector(feedback_vector, kScratchRegister);

#ifndef V8_ENABLE_LEAPTIERING
  // Check the tiering state.
  Label flags_need_processing;
  __ CheckFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      feedback_vector, CodeKind::BASELINE, &flags_need_processing);
#endif  // !V8_ENABLE_LEAPTIERING

  ResetFeedbackVectorOsrUrgency(masm, feedback_vector, kScratchRegister);

  // Increment invocation count for the function.
  __ incl(
      FieldOperand(feedback_vector, FeedbackVector::kInvocationCountOffset));

    // Save the return address, so that we can push it to the end of the newly
    // set-up frame once we're done setting it up.
    __ PopReturnAddressTo(return_address);
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
      ResetJSFunctionAge(masm, callee_js_function);
      __ Push(callee_js_function);  // Callee's JS function.
      __ Push(descriptor.GetRegisterParameter(
          BaselineOutOfLinePrologueDescriptor::
              kJavaScriptCallArgCount));  // Actual argument count.

      // We'll use the bytecode for both code age/OSR resetting, and pushing
      // onto the frame, so load it into a register.
      Register bytecode_array = descriptor.GetRegisterParameter(
          BaselineOutOfLinePrologueDescriptor::kInterpreterBytecodeArray);
      __ Push(bytecode_array);
      __ Push(feedback_cell);
      __ Push(feedback_vector);
    }

  Register new_target = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kJavaScriptCallNewTarget);

  Label call_stack_guard;
  Register frame_size = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kStackFrameSize);
  {
    ASM_CODE_COMMENT_STRING(masm, " Stack/interrupt check");
    // Stack check. This folds the checks for both the interrupt stack limit
    // check and the real stack limit into one by just checking for the
    // interrupt limit. The interrupt limit is either equal to the real stack
    // limit or tighter. By ensuring we have space until that limit after
    // building the frame we can quickly precheck both at once.
    //
    // TODO(v8:11429): Backport this folded check to the
    // InterpreterEntryTrampoline.
    __ Move(kScratchRegister, rsp);
    DCHECK_NE(frame_size, new_target);
    __ subq(kScratchRegister, frame_size);
    __ cmpq(kScratchRegister,
            __ StackLimitAsOperand(StackLimitKind::kInterruptStackLimit));
    __ j(below, &call_stack_guard);
  }

  // Push the return address back onto the stack for return.
  __ PushReturnAddressFrom(return_address);
  // Return to caller pushed pc, without any frame teardown.
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
  __ Ret();

#ifndef V8_ENABLE_LEAPTIERING
  __ bind(&flags_need_processing);
  {
    ASM_CODE_COMMENT_STRING(masm, "Optimized marker check");
    // Drop the return address, rebalancing the return stack buffer by using
    // JumpMode::kPushAndReturn. We can't leave the slot and overwrite it on
    // return since we may do a runtime call along the way that requires the
    // stack to only contain valid frames.
    __ Drop(1);
    __ OptimizeCodeOrTailCallOptimizedCodeSlot(feedback_vector, closure,
                                               JumpMode::kPushAndReturn);
    __ Trap();
  }
#endif  //! V8_ENABLE_LEAPTIERING

  __ bind(&call_stack_guard);
  {
    ASM_CODE_COMMENT_STRING(masm, "Stack/interrupt call");
    {
      // Push the baseline code return address now, as if it had been pushed by
      // the call to this builtin.
      __ PushReturnAddressFrom(return_address);
      FrameScope inner_frame_scope(masm, StackFrame::INTERNAL);
      // Save incoming new target or generator
      __ Push(new_target);
#ifdef V8_ENABLE_LEAPTIERING
      // No need to SmiTag as dispatch handles always look like Smis.
      static_assert(kJSDispatchHandleShift > 0);
      __ Push(kJavaScriptCallDispatchHandleRegister);
#endif
      __ SmiTag(frame_size);
      __ Push(frame_size);
      __ CallRuntime(Runtime::kStackGuardWithGap, 1);
#ifdef V8_ENABLE_LEAPTIERING
      __ Pop(kJavaScriptCallDispatchHandleRegister);
#endif
      __ Pop(new_target);
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

  // Drop feedback vector.
  __ Pop(kScratchRegister);
  // Drop bytecode offset (was the feedback vector but got replaced during
  // deopt).
  __ Pop(kScratchRegister);
  // Drop bytecode array
  __ Pop(kScratchRegister);

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
  Generate_CallToAdaptShadowStackForDeopt(masm, true);
  masm->isolate()->heap()->SetDeoptPCOffsetAfterAdaptShadowStack(
      masm->pc_offset());

  ASM_CODE_COMMENT(masm);
  const RegisterConfiguration* config(RegisterConfiguration::Default());
  int allocatable_register_count = config->num_allocatable_general_registers();
  if (with_result) {
    if (javascript_builtin) {
      // kScratchRegister is not included in the allocateable registers.
      __ movq(kScratchRegister, rax);
    } else {
      // Overwrite the hole inserted by the deoptimizer with the return value
      // from the LAZY deopt point.
      __ movq(
          Operand(rsp, config->num_allocatable_general_registers() *
                               kSystemPointerSize +
                           BuiltinContinuationFrameConstants::kFixedFrameSize),
          rax);
    }
  }
  for (int i = allocatable_register_count - 1; i >= 0; --i) {
    int code = config->GetAllocatableGeneralCode(i);
    __ popq(Register::from_code(code));
    if (javascript_builtin && code == kJavaScriptCallArgCountRegister.code()) {
      __ SmiUntagUnsigned(Register::from_code(code));
    }
  }
  if (with_result && javascript_builtin) {
    // Overwrite the hole inserted by the deoptimizer with the return value from
    // the LAZY deopt point. rax contains the arguments count, the return value
    // from LAZY is always the last argument.
    __ movq(Operand(rsp, rax, times_system_pointer_size,
                    BuiltinContinuationFrameConstants::kFixedFrameSize -
                        kJSArgcReceiverSlots * kSystemPointerSize),
            kScratchRegister);
  }
  __ movq(
      rbp,
      Operand(rsp, BuiltinContinuationFrameConstants::kFixedFrameSizeFromFp));
  const int offsetToPC =
      BuiltinContinuationFrameConstants::kFixedFrameSizeFromFp -
      kSystemPointerSize;
  __ popq(Operand(rsp, offsetToPC));
  __ Drop(offsetToPC / kSystemPointerSize);

  // Replace the builtin index Smi on the stack with the instruction start
  // address of the builtin from the builtins table, and then jump to this
  // address
  __ popq(kScratchRegister);
  __ movq(kScratchRegister,
          __ EntryFromBuiltinIndexAsOperand(kScratchRegister));
  __ jmp(kScratchRegister);
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
  // Enter an internal frame.
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kNotifyDeoptimized);
    // Tear down internal frame.
  }

  DCHECK_EQ(kInterpreterAccumulatorRegister.code(), rax.code());
  __ movq(rax, Operand(rsp, kPCOnStackSize));
  __ ret(1 * kSystemPointerSize);  // Remove rax.
}

// static
void Builtins::Generate_FunctionPrototypeApply(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- rax     : argc
  //  -- rsp[0]  : return address
  //  -- rsp[1]  : receiver
  //  -- rsp[2]  : thisArg
  //  -- rsp[3]  : argArray
  // -----------------------------------

  // 1. Load receiver into rdi, argArray into rbx (if present), remove all
  // arguments from the stack (including the receiver), and push thisArg (if
  // present) instead.
  {
    Label no_arg_array, no_this_arg;
    StackArgumentsAccessor args(rax);
    __ LoadRoot(rdx, RootIndex::kUndefinedValue);
    __ movq(rbx, rdx);
    __ movq(rdi, args[0]);
    __ cmpq(rax, Immediate(JSParameterCount(0)));
    __ j(equal, &no_this_arg, Label::kNear);
    {
      __ movq(rdx, args[1]);
      __ cmpq(rax, Immediate(JSParameterCount(1)));
      __ j(equal, &no_arg_array, Label::kNear);
      __ movq(rbx, args[2]);
      __ bind(&no_arg_array);
    }
    __ bind(&no_this_arg);
    __ DropArgumentsAndPushNewReceiver(rax, rdx, rcx);
  }

  // ----------- S t a t e -------------
  //  -- rbx     : argArray
  //  -- rdi     : receiver
  //  -- rsp[0]  : return address
  //  -- rsp[8]  : thisArg
  // -----------------------------------

  // 2. We don't need to check explicitly for callable receiver here,
  // since that's the first thing the Call/CallWithArrayLike builtins
  // will do.

  // 3. Tail call with no arguments if argArray is null or undefined.
  Label no_arguments;
  __ JumpIfRoot(rbx, RootIndex::kNullValue, &no_arguments, Label::kNear);
  __ JumpIfRoot(rbx, RootIndex::kUndefinedValue, &no_arguments, Label::kNear);

  // 4a. Apply the receiver to the given argArray.
  __ TailCallBuiltin(Builtin::kCallWithArrayLike);

  // 4b. The argArray is either null or undefined, so we tail call without any
  // arguments to the receiver. Since we did not create a frame for
  // Function.prototype.apply() yet, we use a normal Call builtin here.
  __ bind(&no_arguments);
  {
    __ Move(rax, JSParameterCount(0));
    __ TailCallBuiltin(Builtins::Call());
  }
}

// static
void Builtins::Generate_FunctionPrototypeCall(MacroAssembler* masm) {
  // Stack Layout:
  // rsp[0]           : Return address
  // rsp[8]           : Argument 0 (receiver: callable to call)
  // rsp[16]          : Argument 1
  //  ...
  // rsp[8 * n]       : Argument n-1
  // rsp[8 * (n + 1)] : Argument n
  // rax contains the number of arguments, n.

  // 1. Get the callable to call (passed as receiver) from the stack.
  {
    StackArgumentsAccessor args(rax);
    __ movq(rdi, args.GetReceiverOperand());
  }

  // 2. Save the return address and drop the callable.
  __ PopReturnAddressTo(rbx);
  __ Pop(kScratchRegister);

  // 3. Make sure we have at least one argument.
  {
    Label done;
    __ cmpq(rax, Immediate(JSParameterCount(0)));
    __ j(greater, &done, Label::kNear);
    __ PushRoot(RootIndex::kUndefinedValue);
    __ incq(rax);
    __ bind(&done);
  }

  // 4. Push back the return address one slot down on the stack (overwriting the
  // original callable), making the original first argument the new receiver.
  __ PushReturnAddressFrom(rbx);
  __ decq(rax);  // One fewer argument (first argument is new receiver).

  // 5. Call the callable.
  // Since we did not create a frame for Function.prototype.call() yet,
  // we use a normal Call builtin here.
  __ TailCallBuiltin(Builtins::Call());
}

void Builtins::Generate_ReflectApply(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- rax     : argc
  //  -- rsp[0]  : return address
  //  -- rsp[8]  : receiver
  //  -- rsp[16] : target         (if argc >= 1)
  //  -- rsp[24] : thisArgument   (if argc >= 2)
  //  -- rsp[32] : argumentsList  (if argc == 3)
  // -----------------------------------

  // 1. Load target into rdi (if present), argumentsList into rbx (if present),
  // remove all arguments from the stack (including the receiver), and push
  // thisArgument (if present) instead.
  {
    Label done;
    StackArgumentsAccessor args(rax);
    __ LoadRoot(rdi, RootIndex::kUndefinedValue);
    __ movq(rdx, rdi);
    __ movq(rbx, rdi);
    __ cmpq(rax, Immediate(JSParameterCount(1)));
    __ j(below, &done, Label::kNear);
    __ movq(rdi, args[1]);  // target
    __ j(equal, &done, Label::kNear);
    __ movq(rdx, args[2]);  // thisArgument
    __ cmpq(rax, Immediate(JSParameterCount(3)));
    __ j(below, &done, Label::kNear);
    __ movq(rbx, args[3]);  // argumentsList
    __ bind(&done);
    __ DropArgumentsAndPushNewReceiver(rax, rdx, rcx);
  }

  // ----------- S t a t e -------------
  //  -- rbx     : argumentsList
  //  -- rdi     : target
  //  -- rsp[0]  : return address
  //  -- rsp[8]  : thisArgument
  // -----------------------------------

  // 2. We don't need to check explicitly for callable target here,
  // since that's the first thing the Call/CallWithArrayLike builtins
  // will do.

  // 3. Apply the target to the given argumentsList.
  __ TailCallBuiltin(Builtin::kCallWithArrayLike);
}

void Builtins::Generate_ReflectConstruct(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- rax     : argc
  //  -- rsp[0]  : return address
  //  -- rsp[8]  : receiver
  //  -- rsp[16] : target
  //  -- rsp[24] : argumentsList
  //  -- rsp[32] : new.target (optional)
  // -----------------------------------

  // 1. Load target into rdi (if present), argumentsList into rbx (if present),
  // new.target into rdx (if present, otherwise use target), remove all
  // arguments from the stack (including the receiver), and push thisArgument
  // (if present) instead.
  {
    Label done;
    StackArgumentsAccessor args(rax);
    __ LoadRoot(rdi, RootIndex::kUndefinedValue);
    __ movq(rdx, rdi);
    __ movq(rbx, rdi);
    __ cmpq(rax, Immediate(JSParameterCount(1)));
    __ j(below, &done, Label::kNear);
    __ movq(rdi, args[1]);                     // target
    __ movq(rdx, rdi);                         // new.target defaults to target
    __ j(equal, &done, Label::kNear);
    __ movq(rbx, args[2]);  // argumentsList
    __ cmpq(rax, Immediate(JSParameterCount(3)));
    __ j(below, &done, Label::kNear);
    __ movq(rdx, args[3]);  // new.target
    __ bind(&done);
    __ DropArgumentsAndPushNewReceiver(
        rax, masm->RootAsOperand(RootIndex::kUndefinedValue), rcx);
  }

  // ----------- S t a t e -------------
  //  -- rbx     : argumentsList
  //  -- rdx     : new.target
  //  -- rdi     : target
  //  -- rsp[0]  : return address
  //  -- rsp[8]  : receiver (undefined)
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
                     scratch2, kScratchRegister));
  // Use pointer_to_new_space_out as scratch until we set it to the correct
  // value at the end.
  Register old_rsp = pointer_to_new_space_out;
  Register new_space = kScratchRegister;
  __ movq(old_rsp, rsp);

  __ leaq(new_space, Operand(count, times_system_pointer_size, 0));
  __ AllocateStackSpace(new_space);

  Register copy_count = argc_in_out;
  Register current = scratch2;
  Register value = kScratchRegister;

  Label loop, entry;
  __ Move(current, 0);
  __ jmp(&entry);
  __ bind(&loop);
  __ movq(value, Operand(old_rsp, current, times_system_pointer_size, 0));
  __ movq(Operand(rsp, current, times_system_pointer_size, 0), value);
  __ incq(current);
  __ bind(&entry);
  __ cmpq(current, copy_count);
  __ j(less_equal, &loop, Label::kNear);

  // Point to the next free slot above the shifted arguments (copy_count + 1
  // slot for the return address).
  __ leaq(
      pointer_to_new_space_out,
      Operand(rsp, copy_count, times_system_pointer_size, kSystemPointerSize));
  // We use addl instead of addq here because we can omit REX.W, saving 1 byte.
  // We are especially constrained here because we are close to reaching the
  // limit for a near jump to the stackoverflow label, so every byte counts.
  __ addl(argc_in_out, count);  // Update total number of arguments.
}

}  // namespace

// static
// TODO(v8:11615): Observe Code::kMaxArguments in CallOrConstructVarargs
void Builtins::Generate_CallOrConstructVarargs(MacroAssembler* masm,
                                               Builtin target_builtin) {
  // ----------- S t a t e -------------
  //  -- rdi    : target
  //  -- rax    : number of parameters on the stack
  //  -- rbx    : arguments list (a FixedArray)
  //  -- rcx    : len (number of elements to push from args)
  //  -- rdx    : new.target (for [[Construct]])
  //  -- rsp[0] : return address
  // -----------------------------------

  if (v8_flags.debug_code) {
    // Allow rbx to be a FixedArray, or a FixedDoubleArray if rcx == 0.
    Label ok, fail;
    __ AssertNotSmi(rbx);
    Register map = r9;
    __ LoadMap(map, rbx);
    __ CmpInstanceType(map, FIXED_ARRAY_TYPE);
    __ j(equal, &ok);
    __ CmpInstanceType(map, FIXED_DOUBLE_ARRAY_TYPE);
    __ j(not_equal, &fail);
    __ Cmp(rcx, 0);
    __ j(equal, &ok);
    // Fall through.
    __ bind(&fail);
    __ Abort(AbortReason::kOperandIsNotAFixedArray);

    __ bind(&ok);
  }

  Label stack_overflow;
  __ StackOverflowCheck(rcx, &stack_overflow,
                        DEBUG_BOOL ? Label::kFar : Label::kNear);

  // Push additional arguments onto the stack.
  // Move the arguments already in the stack,
  // including the receiver and the return address.
  // rcx: Number of arguments to make room for.
  // rax: Number of arguments already on the stack.
  // r8: Points to first free slot on the stack after arguments were shifted.
  Generate_AllocateSpaceAndShiftExistingArguments(masm, rcx, rax, r8, r9, r12);
  // Copy the additional arguments onto the stack.
  {
    Register value = r12;
    Register src = rbx, dest = r8, num = rcx, current = r9;
    __ Move(current, 0);
    Label done, push, loop;
    __ bind(&loop);
    __ cmpl(current, num);
    __ j(equal, &done, Label::kNear);
    // Turn the hole into undefined as we go.
    __ LoadTaggedField(value, FieldOperand(src, current, times_tagged_size,
                                           OFFSET_OF_DATA_START(FixedArray)));
    __ CompareRoot(value, RootIndex::kTheHoleValue);
    __ j(not_equal, &push, Label::kNear);
    __ LoadRoot(value, RootIndex::kUndefinedValue);
    __ bind(&push);
    __ movq(Operand(dest, current, times_system_pointer_size, 0), value);
    __ incl(current);
    __ jmp(&loop);
    __ bind(&done);
  }

  // Tail-call to the actual Call or Construct builtin.
  __ TailCallBuiltin(target_builtin);

  __ bind(&stack_overflow);
  __ TailCallRuntime(Runtime::kThrowStackOverflow);
}

// static
void Builtins::Generate_CallOrConstructForwardVarargs(MacroAssembler* masm,
                                                      CallOrConstructMode mode,
                                                      Builtin target_builtin) {
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdx : the new target (for [[Construct]] calls)
  //  -- rdi : the target to call (can be any Object)
  //  -- rcx : start index (to support rest parameters)
  // -----------------------------------

  // Check if new.target has a [[Construct]] internal method.
  if (mode == CallOrConstructMode::kConstruct) {
    Label new_target_constructor, new_target_not_constructor;
    __ JumpIfSmi(rdx, &new_target_not_constructor, Label::kNear);
    __ LoadMap(rbx, rdx);
    __ testb(FieldOperand(rbx, Map::kBitFieldOffset),
             Immediate(Map::Bits1::IsConstructorBit::kMask));
    __ j(not_zero, &new_target_constructor, Label::kNear);
    __ bind(&new_target_not_constructor);
    {
      FrameScope scope(masm, StackFrame::MANUAL);
      __ EnterFrame(StackFrame::INTERNAL);
      __ Push(rdx);
      __ CallRuntime(Runtime::kThrowNotConstructor);
    }
    __ bind(&new_target_constructor);
  }

  Label stack_done, stack_overflow;
  __ movq(r8, Operand(rbp, StandardFrameConstants::kArgCOffset));
  __ decq(r8);  // Exclude receiver.
  __ subl(r8, rcx);
  __ j(less_equal, &stack_done);
  {
    // ----------- S t a t e -------------
    //  -- rax : the number of arguments already in the stack
    //  -- rbp : point to the caller stack frame
    //  -- rcx : start index (to support rest parameters)
    //  -- rdx : the new target (for [[Construct]] calls)
    //  -- rdi : the target to call (can be any Object)
    //  -- r8  : number of arguments to copy, i.e. arguments count - start index
    // -----------------------------------

    // Check for stack overflow.
    __ StackOverflowCheck(r8, &stack_overflow, Label::kNear);

    // Forward the arguments from the caller frame.
    // Move the arguments already in the stack,
    // including the receiver and the return address.
    // r8: Number of arguments to make room for.
    // rax: Number of arguments already on the stack.
    // r9: Points to first free slot on the stack after arguments were shifted.
    Generate_AllocateSpaceAndShiftExistingArguments(masm, r8, rax, r9, r12,
                                                    r15);

    // Point to the first argument to copy (skipping receiver).
    __ leaq(rcx, Operand(rcx, times_system_pointer_size,
                         CommonFrameConstants::kFixedFrameSizeAboveFp +
                             kSystemPointerSize));
    __ addq(rcx, rbp);

    // Copy the additional caller arguments onto the stack.
    // TODO(victorgomes): Consider using forward order as potentially more cache
    // friendly.
    {
      Register src = rcx, dest = r9, num = r8;
      Label loop;
      __ bind(&loop);
      __ decq(num);
      __ movq(kScratchRegister,
              Operand(src, num, times_system_pointer_size, 0));
      __ movq(Operand(dest, num, times_system_pointer_size, 0),
              kScratchRegister);
      __ j(not_zero, &loop);
    }
  }
  __ bind(&stack_done);
  // Tail-call to the actual Call or Construct builtin.
  __ TailCallBuiltin(target_builtin);

  __ bind(&stack_overflow);
  __ TailCallRuntime(Runtime::kThrowStackOverflow);
}

// static
void Builtins::Generate_CallFunction(MacroAssembler* masm,
                                     ConvertReceiverMode mode) {
  // ----------- S t a 
"""


```