Response: The user wants me to summarize the functionality of the provided C++ code snippet. This is part 2 of a 4-part file. The code seems to define built-in functions for the V8 JavaScript engine on the IA-32 architecture.

I should focus on the functions defined in this specific part and try to understand their roles in the JavaScript execution process. I will also look for connections to JavaScript features and provide illustrative JavaScript examples if applicable.

Based on the code, it seems like this part focuses on:
- Entering and exiting the interpreter.
- Handling baseline compilation and deoptimization.
- Implementing `Function.prototype.apply` and `Function.prototype.call`.
- Implementing `Reflect.apply` and `Reflect.construct`.
- Implementing `Call` and `Construct` operations, including handling bound functions and proxies.
- On-stack replacement (OSR) mechanisms for the interpreter and baseline compiler.
- WebAssembly specific builtins like frame setup, lazy compilation, and debug break.
- Support for continuations in WebAssembly.
这是 `v8/src/builtins/ia32/builtins-ia32.cc` 文件的一部分，主要负责实现 V8 JavaScript 引擎在 IA-32 架构下的内置函数。 这部分代码延续了第一部分的功能，继续实现了更多的 JavaScript 内置功能，并涉及到了优化的相关机制。

以下是对这部分代码功能的归纳：

**核心功能：**

* **控制流相关的内置函数：**
    * `Generate_ContinueToCodeStubBuiltin`, `Generate_ContinueToCodeStubBuiltinWithResult`, `Generate_ContinueToJavaScriptBuiltin`, `Generate_ContinueToJavaScriptBuiltinWithResult`:  这些函数用于在执行 CodeStub 或 JavaScript 内置函数后，从 deoptimized 的状态恢复执行。它们负责恢复寄存器状态，并跳转到正确的执行地址。
    * `Generate_NotifyDeoptimized`:  当代码发生 deoptimization 时，调用此内置函数通知运行时系统。

* **`Function.prototype` 的内置方法：**
    * `Generate_FunctionPrototypeApply`: 实现了 `Function.prototype.apply()` 方法。它允许以指定的 `this` 值和数组形式的参数调用函数。
    * `Generate_FunctionPrototypeCall`: 实现了 `Function.prototype.call()` 方法。它允许以指定的 `this` 值和逐个列出的参数调用函数。

* **`Reflect` 对象的内置方法：**
    * `Generate_ReflectApply`: 实现了 `Reflect.apply()` 方法。它与 `Function.prototype.apply()` 类似，但接受目标函数作为第一个参数。
    * `Generate_ReflectConstruct`: 实现了 `Reflect.construct()` 方法。它允许使用指定的构造函数和参数列表创建对象，并可以选择指定 `new.target`。

* **调用和构造相关的内置函数：**
    * `Generate_CallOrConstructVarargs`:  实现调用或构造函数，其参数来自一个数组（`arguments list`）。
    * `Generate_CallOrConstructForwardVarargs`: 实现调用或构造函数，其参数从调用者的栈帧中转发。这通常用于 rest 参数的场景。
    * `Generate_CallFunction`:  实现了 `Call` 操作。它负责调用一个 JavaScript 函数，并处理 `this` 值的转换（例如，当在非严格模式下调用函数时，将 `null` 或 `undefined` 转换为全局对象）。
    * `Generate_CallBoundFunctionImpl`: 实现了调用绑定函数（通过 `Function.prototype.bind()` 创建的函数）。
    * `Generate_Call`: 实现了通用的 `Call` 操作，它会根据目标对象的类型（例如，JSFunction, BoundFunction, Proxy）分发到不同的内置函数。
    * `Generate_ConstructFunction`: 实现了构造 JavaScript 函数的操作。
    * `Generate_ConstructBoundFunction`: 实现了构造绑定函数的操作。
    * `Generate_Construct`: 实现了通用的 `Construct` 操作，与 `Call` 类似，它根据目标对象的类型分发到不同的构造函数内置函数。

* **优化相关的内置函数：**
    * `Generate_InterpreterOnStackReplacement`:  实现了从解释器代码进行 On-Stack Replacement (OSR) 的入口。OSR 是一种优化技术，允许在函数执行过程中切换到更优化的代码版本。
    * `Generate_BaselineOnStackReplacement`: 实现了从 Baseline 代码进行 OSR 的入口。

* **WebAssembly 相关的内置函数：**
    * `Generate_WasmLiftoffFrameSetup`:  为 WebAssembly Liftoff 编译器设置栈帧。
    * `Generate_WasmCompileLazy`:  实现 WebAssembly 函数的延迟编译。
    * `Generate_WasmDebugBreak`:  处理 WebAssembly 代码中的断点。
    * 代码中还包含大量关于 WebAssembly 延续 (Continuations) 的实现，包括栈的切换、状态的保存和加载，这是一种用于实现异步控制流的高级机制。

**与 JavaScript 功能的关系及 JavaScript 示例：**

这部分代码直接实现了许多核心的 JavaScript 语言特性和 API。

1. **`Function.prototype.apply` 和 `Function.prototype.call`:**

   ```javascript
   function greet(greeting) {
     console.log(greeting + ', ' + this.name);
   }

   const person = { name: 'Alice' };

   // 使用 apply
   greet.apply(person, ['Hello']); // 输出: Hello, Alice

   // 使用 call
   greet.call(person, 'Hi');     // 输出: Hi, Alice
   ```

2. **`Reflect.apply` 和 `Reflect.construct`:**

   ```javascript
   function sum(a, b) {
     return a + b;
   }

   const args = [5, 10];
   const result = Reflect.apply(sum, null, args);
   console.log(result); // 输出: 15

   class Point {
     constructor(x, y) {
       this.x = x;
       this.y = y;
     }
   }

   const pointArgs = [1, 2];
   const point = Reflect.construct(Point, pointArgs);
   console.log(point.x, point.y); // 输出: 1 2
   ```

3. **`Call` 和 `Construct` 操作:** 这些是 JavaScript 引擎内部执行函数调用和对象创建的核心机制，在用户代码中通过直接调用函数或使用 `new` 关键字触发。

   ```javascript
   function myFunction(arg1, arg2) {
     console.log(arg1, arg2);
   }

   myFunction(1, 2); // 触发 Call 操作

   class MyClass {}
   const instance = new MyClass(); // 触发 Construct 操作
   ```

4. **On-Stack Replacement (OSR):**  这是 V8 内部的优化机制，用户代码不会直接感知，但它的存在使得长时间运行的 JavaScript 代码可以被动态优化，提高性能。

5. **WebAssembly:**  相关的内置函数支持在 JavaScript 中执行 WebAssembly 代码。

   ```javascript
   // 假设你已经加载了一个 WebAssembly 模块
   const wasmInstance = // ... 加载的 WebAssembly 实例 ...
   const add = wasmInstance.exports.add;
   console.log(add(5, 3)); // 调用 WebAssembly 函数
   ```

6. **Continuations (WebAssembly):**  这是一个更高级的特性，允许 WebAssembly 代码挂起执行并在稍后恢复，用于实现更复杂的异步流程控制。

总而言之，这部分 `builtins-ia32.cc` 代码是 V8 引擎在 IA-32 架构上实现各种关键 JavaScript 功能的底层基础，它连接了 JavaScript 语法和底层的机器指令执行。

### 提示词
```
这是目录为v8/src/builtins/ia32/builtins-ia32.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```
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
        __ mov(ecx, eax);
        __ Pop(edi);
        __ Pop(eax);
        __ SmiUntag(eax);
      }
      __ mov(edx, FieldOperand(edi, JSFunction::kSharedFunctionInfoOffset));
      __ bind(&convert_receiver);
    }
    __ mov(args.GetReceiverOperand(), ecx);
  }
  __ bind(&done_convert);

  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edx : the shared function info.
  //  -- edi : the function to call (checked to be a JSFunction)
  //  -- esi : the function context.
  // -----------------------------------

  __ movzx_w(
      ecx, FieldOperand(edx, SharedFunctionInfo::kFormalParameterCountOffset));
  __ InvokeFunctionCode(edi, no_reg, ecx, eax, InvokeType::kJump);
}

namespace {

void Generate_PushBoundArguments(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edx : new.target (only in case of [[Construct]])
  //  -- edi : target (checked to be a JSBoundFunction)
  // -----------------------------------
  __ movd(xmm0, edx);  // Spill edx.

  // Load [[BoundArguments]] into ecx and length of that into edx.
  Label no_bound_arguments;
  __ mov(ecx, FieldOperand(edi, JSBoundFunction::kBoundArgumentsOffset));
  __ mov(edx, FieldOperand(ecx, offsetof(FixedArray, length_)));
  __ SmiUntag(edx);
  __ test(edx, edx);
  __ j(zero, &no_bound_arguments);
  {
    // ----------- S t a t e -------------
    //  -- eax  : the number of arguments
    //  -- xmm0 : new.target (only in case of [[Construct]])
    //  -- edi  : target (checked to be a JSBoundFunction)
    //  -- ecx  : the [[BoundArguments]] (implemented as FixedArray)
    //  -- edx  : the number of [[BoundArguments]]
    // -----------------------------------

    // Check the stack for overflow.
    {
      Label done, stack_overflow;
      __ StackOverflowCheck(edx, ecx, &stack_overflow);
      __ jmp(&done);
      __ bind(&stack_overflow);
      {
        FrameScope frame(masm, StackFrame::MANUAL);
        __ EnterFrame(StackFrame::INTERNAL);
        __ CallRuntime(Runtime::kThrowStackOverflow);
        __ int3();
      }
      __ bind(&done);
    }

    // Spill context.
    __ movd(xmm3, esi);

    // Save Return Address and Receiver into registers.
    __ pop(esi);
    __ movd(xmm1, esi);
    __ pop(esi);
    __ movd(xmm2, esi);

    // Push [[BoundArguments]] to the stack.
    {
      Label loop;
      __ mov(ecx, FieldOperand(edi, JSBoundFunction::kBoundArgumentsOffset));
      __ mov(edx, FieldOperand(ecx, offsetof(FixedArray, length_)));
      __ SmiUntag(edx);
      // Adjust effective number of arguments (eax contains the number of
      // arguments from the call not including receiver plus the number of
      // [[BoundArguments]]).
      __ add(eax, edx);
      __ bind(&loop);
      __ dec(edx);
      __ mov(esi, FieldOperand(ecx, edx, times_tagged_size,
                               OFFSET_OF_DATA_START(FixedArray)));
      __ push(esi);
      __ j(greater, &loop);
    }

    // Restore Receiver and Return Address.
    __ movd(esi, xmm2);
    __ push(esi);
    __ movd(esi, xmm1);
    __ push(esi);

    // Restore context.
    __ movd(esi, xmm3);
  }

  __ bind(&no_bound_arguments);
  __ movd(edx, xmm0);  // Reload edx.
}

}  // namespace

// static
void Builtins::Generate_CallBoundFunctionImpl(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edi : the function to call (checked to be a JSBoundFunction)
  // -----------------------------------
  __ AssertBoundFunction(edi);

  // Patch the receiver to [[BoundThis]].
  StackArgumentsAccessor args(eax);
  __ mov(ecx, FieldOperand(edi, JSBoundFunction::kBoundThisOffset));
  __ mov(args.GetReceiverOperand(), ecx);

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Call the [[BoundTargetFunction]] via the Call builtin.
  __ mov(edi, FieldOperand(edi, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtins::Call());
}

// static
void Builtins::Generate_Call(MacroAssembler* masm, ConvertReceiverMode mode) {
  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edi : the target to call (can be any Object).
  // -----------------------------------
  Register argc = eax;
  Register target = edi;
  Register map = ecx;
  Register instance_type = edx;
  DCHECK(!AreAliased(argc, target, map, instance_type));

  StackArgumentsAccessor args(argc);

  Label non_callable, non_smi, non_callable_jsfunction, non_jsboundfunction,
      non_proxy, non_wrapped_function, class_constructor;
  __ JumpIfSmi(target, &non_callable);
  __ bind(&non_smi);
  __ LoadMap(map, target);
  __ CmpInstanceTypeRange(map, instance_type, map,
                          FIRST_CALLABLE_JS_FUNCTION_TYPE,
                          LAST_CALLABLE_JS_FUNCTION_TYPE);
  __ j(above, &non_callable_jsfunction);
  __ TailCallBuiltin(Builtins::CallFunction(mode));

  __ bind(&non_callable_jsfunction);
  __ cmpw(instance_type, Immediate(JS_BOUND_FUNCTION_TYPE));
  __ j(not_equal, &non_jsboundfunction);
  __ TailCallBuiltin(Builtin::kCallBoundFunction);

  // Check if target is a proxy and call CallProxy external builtin
  __ bind(&non_jsboundfunction);
  __ LoadMap(map, target);
  __ test_b(FieldOperand(map, Map::kBitFieldOffset),
            Immediate(Map::Bits1::IsCallableBit::kMask));
  __ j(zero, &non_callable);

  // Call CallProxy external builtin
  __ cmpw(instance_type, Immediate(JS_PROXY_TYPE));
  __ j(not_equal, &non_proxy);
  __ TailCallBuiltin(Builtin::kCallProxy);

  // Check if target is a wrapped function and call CallWrappedFunction external
  // builtin
  __ bind(&non_proxy);
  __ cmpw(instance_type, Immediate(JS_WRAPPED_FUNCTION_TYPE));
  __ j(not_equal, &non_wrapped_function);
  __ TailCallBuiltin(Builtin::kCallWrappedFunction);

  // ES6 section 9.2.1 [[Call]] ( thisArgument, argumentsList)
  // Check that the function is not a "classConstructor".
  __ bind(&non_wrapped_function);
  __ cmpw(instance_type, Immediate(JS_CLASS_CONSTRUCTOR_TYPE));
  __ j(equal, &class_constructor);

  // 2. Call to something else, which might have a [[Call]] internal method (if
  // not we raise an exception).
  // Overwrite the original receiver with the (original) target.
  __ mov(args.GetReceiverOperand(), target);
  // Let the "call_as_function_delegate" take care of the rest.
  __ LoadNativeContextSlot(target, Context::CALL_AS_FUNCTION_DELEGATE_INDEX);
  __ TailCallBuiltin(
      Builtins::CallFunction(ConvertReceiverMode::kNotNullOrUndefined));

  // 3. Call to something that is not callable.
  __ bind(&non_callable);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(target);
    __ CallRuntime(Runtime::kThrowCalledNonCallable);
    __ Trap();  // Unreachable.
  }

  // 4. The function is a "classConstructor", need to raise an exception.
  __ bind(&class_constructor);
  {
    FrameScope frame(masm, StackFrame::INTERNAL);
    __ Push(target);
    __ CallRuntime(Runtime::kThrowConstructorNonCallableError);
    __ Trap();  // Unreachable.
  }
}

// static
void Builtins::Generate_ConstructFunction(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edx : the new target (checked to be a constructor)
  //  -- edi : the constructor to call (checked to be a JSFunction)
  // -----------------------------------
  __ AssertConstructor(edi);
  __ AssertFunction(edi, ecx);

  Label call_generic_stub;

  // Jump to JSBuiltinsConstructStub or JSConstructStubGeneric.
  __ mov(ecx, FieldOperand(edi, JSFunction::kSharedFunctionInfoOffset));
  __ test(FieldOperand(ecx, SharedFunctionInfo::kFlagsOffset),
          Immediate(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ j(zero, &call_generic_stub, Label::kNear);

  // Calling convention for function specific ConstructStubs require
  // ecx to contain either an AllocationSite or undefined.
  __ LoadRoot(ecx, RootIndex::kUndefinedValue);
  __ TailCallBuiltin(Builtin::kJSBuiltinsConstructStub);

  __ bind(&call_generic_stub);
  // Calling convention for function specific ConstructStubs require
  // ecx to contain either an AllocationSite or undefined.
  __ LoadRoot(ecx, RootIndex::kUndefinedValue);
  __ TailCallBuiltin(Builtin::kJSConstructStubGeneric);
}

// static
void Builtins::Generate_ConstructBoundFunction(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edx : the new target (checked to be a constructor)
  //  -- edi : the constructor to call (checked to be a JSBoundFunction)
  // -----------------------------------
  __ AssertConstructor(edi);
  __ AssertBoundFunction(edi);

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Patch new.target to [[BoundTargetFunction]] if new.target equals target.
  {
    Label done;
    __ cmp(edi, edx);
    __ j(not_equal, &done, Label::kNear);
    __ mov(edx, FieldOperand(edi, JSBoundFunction::kBoundTargetFunctionOffset));
    __ bind(&done);
  }

  // Construct the [[BoundTargetFunction]] via the Construct builtin.
  __ mov(edi, FieldOperand(edi, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtin::kConstruct);
}

// static
void Builtins::Generate_Construct(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edx : the new target (either the same as the constructor or
  //           the JSFunction on which new was invoked initially)
  //  -- edi : the constructor to call (can be any Object)
  // -----------------------------------
  Register argc = eax;
  Register target = edi;
  Register map = ecx;
  DCHECK(!AreAliased(argc, target, map));

  StackArgumentsAccessor args(argc);

  // Check if target is a Smi.
  Label non_constructor, non_proxy, non_jsfunction, non_jsboundfunction;
  __ JumpIfSmi(target, &non_constructor);

  // Check if target has a [[Construct]] internal method.
  __ mov(map, FieldOperand(target, HeapObject::kMapOffset));
  __ test_b(FieldOperand(map, Map::kBitFieldOffset),
            Immediate(Map::Bits1::IsConstructorBit::kMask));
  __ j(zero, &non_constructor);

  // Dispatch based on instance type.
  __ CmpInstanceTypeRange(map, map, map, FIRST_JS_FUNCTION_TYPE,
                          LAST_JS_FUNCTION_TYPE);
  __ j(above, &non_jsfunction);
  __ TailCallBuiltin(Builtin::kConstructFunction);

  // Only dispatch to bound functions after checking whether they are
  // constructors.
  __ bind(&non_jsfunction);
  __ mov(map, FieldOperand(target, HeapObject::kMapOffset));
  __ CmpInstanceType(map, JS_BOUND_FUNCTION_TYPE);
  __ j(not_equal, &non_jsboundfunction);
  __ TailCallBuiltin(Builtin::kConstructBoundFunction);

  // Only dispatch to proxies after checking whether they are constructors.
  __ bind(&non_jsboundfunction);
  __ CmpInstanceType(map, JS_PROXY_TYPE);
  __ j(not_equal, &non_proxy);
  __ TailCallBuiltin(Builtin::kConstructProxy);

  // Called Construct on an exotic Object with a [[Construct]] internal method.
  __ bind(&non_proxy);
  {
    // Overwrite the original receiver with the (original) target.
    __ mov(args.GetReceiverOperand(), target);
    // Let the "call_as_constructor_delegate" take care of the rest.
    __ LoadNativeContextSlot(target,
                             Context::CALL_AS_CONSTRUCTOR_DELEGATE_INDEX);
    __ TailCallBuiltin(Builtins::CallFunction());
  }

  // Called Construct on an Object that doesn't have a [[Construct]] internal
  // method.
  __ bind(&non_constructor);
  __ TailCallBuiltin(Builtin::kConstructedNonConstructable);
}

namespace {

void Generate_OSREntry(MacroAssembler* masm, Register entry_address) {
  ASM_CODE_COMMENT(masm);
  // Overwrite the return address on the stack.
  __ mov(Operand(esp, 0), entry_address);

  // And "return" to the OSR entry point of the function.
  __ ret(0);
}

enum class OsrSourceTier {
  kInterpreter,
  kBaseline,
};

void OnStackReplacement(MacroAssembler* masm, OsrSourceTier source,
                        Register maybe_target_code) {
  Label jump_to_optimized_code;
  {
    // If maybe_target_code is not null, no need to call into runtime. A
    // precondition here is: if maybe_target_code is an InstructionStream
    // object, it must NOT be marked_for_deoptimization (callers must ensure
    // this).
    __ cmp(maybe_target_code, Immediate(0));
    __ j(not_equal, &jump_to_optimized_code, Label::kNear);
  }

  ASM_CODE_COMMENT(masm);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kCompileOptimizedOSR);
  }

  // If the code object is null, just return to the caller.
  __ cmp(eax, Immediate(0));
  __ j(not_equal, &jump_to_optimized_code, Label::kNear);
  __ ret(0);

  __ bind(&jump_to_optimized_code);
  DCHECK_EQ(maybe_target_code, eax);  // Already in the right spot.

  // OSR entry tracing.
  {
    Label next;
    __ cmpb(__ ExternalReferenceAsOperand(
                ExternalReference::address_of_log_or_trace_osr(), ecx),
            Immediate(0));
    __ j(equal, &next, Label::kNear);

    {
      FrameScope scope(masm, StackFrame::INTERNAL);
      __ Push(eax);  // Preserve the code object.
      __ CallRuntime(Runtime::kLogOrTraceOptimizedOSREntry, 0);
      __ Pop(eax);
    }

    __ bind(&next);
  }

  if (source == OsrSourceTier::kInterpreter) {
    // Drop the handler frame that is be sitting on top of the actual
    // JavaScript frame. This is the case then OSR is triggered from bytecode.
    __ leave();
  }

  // Load deoptimization data from the code object.
  __ mov(ecx, Operand(eax, Code::kDeoptimizationDataOrInterpreterDataOffset -
                               kHeapObjectTag));

  // Load the OSR entrypoint offset from the deoptimization data.
  __ mov(ecx, Operand(ecx, FixedArray::OffsetOfElementAt(
                               DeoptimizationData::kOsrPcOffsetIndex) -
                               kHeapObjectTag));
  __ SmiUntag(ecx);

  __ LoadCodeInstructionStart(eax, eax);

  // Compute the target address = code_entry + osr_offset
  __ add(eax, ecx);

  Generate_OSREntry(masm, eax);
}

}  // namespace

void Builtins::Generate_InterpreterOnStackReplacement(MacroAssembler* masm) {
  using D = OnStackReplacementDescriptor;
  static_assert(D::kParameterCount == 1);
  OnStackReplacement(masm, OsrSourceTier::kInterpreter,
                     D::MaybeTargetCodeRegister());
}

void Builtins::Generate_BaselineOnStackReplacement(MacroAssembler* masm) {
  using D = OnStackReplacementDescriptor;
  static_assert(D::kParameterCount == 1);

  __ mov(kContextRegister,
         MemOperand(ebp, BaselineFrameConstants::kContextOffset));
  OnStackReplacement(masm, OsrSourceTier::kBaseline,
                     D::MaybeTargetCodeRegister());
}

#if V8_ENABLE_WEBASSEMBLY

// Returns the offset beyond the last saved FP register.
int SaveWasmParams(MacroAssembler* masm) {
  // Save all parameter registers (see wasm-linkage.h). They might be
  // overwritten in the subsequent runtime call. We don't have any callee-saved
  // registers in wasm, so no need to store anything else.
  static_assert(WasmLiftoffSetupFrameConstants::kNumberOfSavedGpParamRegs + 1 ==
                    arraysize(wasm::kGpParamRegisters),
                "frame size mismatch");
  for (Register reg : wasm::kGpParamRegisters) {
    __ Push(reg);
  }
  static_assert(WasmLiftoffSetupFrameConstants::kNumberOfSavedFpParamRegs ==
                    arraysize(wasm::kFpParamRegisters),
                "frame size mismatch");
  __ AllocateStackSpace(kSimd128Size * arraysize(wasm::kFpParamRegisters));
  int offset = 0;
  for (DoubleRegister reg : wasm::kFpParamRegisters) {
    __ movdqu(Operand(esp, offset), reg);
    offset += kSimd128Size;
  }
  return offset;
}

// Consumes the offset beyond the last saved FP register (as returned by
// {SaveWasmParams}).
void RestoreWasmParams(MacroAssembler* masm, int offset) {
  for (DoubleRegister reg : base::Reversed(wasm::kFpParamRegisters)) {
    offset -= kSimd128Size;
    __ movdqu(reg, Operand(esp, offset));
  }
  DCHECK_EQ(0, offset);
  __ add(esp, Immediate(kSimd128Size * arraysize(wasm::kFpParamRegisters)));
  for (Register reg : base::Reversed(wasm::kGpParamRegisters)) {
    __ Pop(reg);
  }
}

// When this builtin is called, the topmost stack entry is the calling pc.
// This is replaced with the following:
//
// [    calling pc      ]  <-- esp; popped by {ret}.
// [  feedback vector   ]
// [ Wasm instance data ]
// [ WASM frame marker  ]
// [    saved ebp       ]  <-- ebp; this is where "calling pc" used to be.
void Builtins::Generate_WasmLiftoffFrameSetup(MacroAssembler* masm) {
  constexpr Register func_index = wasm::kLiftoffFrameSetupFunctionReg;

  // We have zero free registers at this point. Free up a temp. Its value
  // could be tagged, but we're only storing it on the stack for a short
  // while, and no GC or stack walk can happen during this time.
  Register tmp = eax;  // Arbitrarily chosen.
  __ Push(tmp);        // This is the "marker" slot.
  {
    Operand saved_ebp_slot = Operand(esp, kSystemPointerSize);
    __ mov(tmp, saved_ebp_slot);  // tmp now holds the "calling pc".
    __ mov(saved_ebp_slot, ebp);
    __ lea(ebp, Operand(esp, kSystemPointerSize));
  }
  __ Push(tmp);  // This is the "instance" slot.

  // Stack layout is now:
  // [calling pc]  <-- instance_data_slot  <-- esp
  // [saved tmp]   <-- marker_slot
  // [saved ebp]
  Operand marker_slot = Operand(ebp, WasmFrameConstants::kFrameTypeOffset);
  Operand instance_data_slot =
      Operand(ebp, WasmFrameConstants::kWasmInstanceDataOffset);

  // Load the feedback vector from the trusted instance data.
  __ mov(tmp, FieldOperand(kWasmImplicitArgRegister,
                           WasmTrustedInstanceData::kFeedbackVectorsOffset));
  __ mov(tmp, FieldOperand(tmp, func_index, times_tagged_size,
                           OFFSET_OF_DATA_START(FixedArray)));
  Label allocate_vector;
  __ JumpIfSmi(tmp, &allocate_vector);

  // Vector exists. Finish setting up the stack frame.
  __ Push(tmp);                // Feedback vector.
  __ mov(tmp, instance_data_slot);  // Calling PC.
  __ Push(tmp);
  __ mov(instance_data_slot, kWasmImplicitArgRegister);
  __ mov(tmp, marker_slot);
  __ mov(marker_slot, Immediate(StackFrame::TypeToMarker(StackFrame::WASM)));
  __ ret(0);

  __ bind(&allocate_vector);
  // Feedback vector doesn't exist yet. Call the runtime to allocate it.
  // We temporarily change the frame type for this, because we need special
  // handling by the stack walker in case of GC.
  // For the runtime call, we create the following stack layout:
  //
  // [ reserved slot for NativeModule ]  <-- arg[2]
  // [  ("declared") function index   ]  <-- arg[1] for runtime func.
  // [       Wasm instance data       ]  <-- arg[0]
  // [ ...spilled Wasm parameters...  ]
  // [           calling pc           ]  <-- already in place
  // [   WASM_LIFTOFF_SETUP marker    ]
  // [           saved ebp            ]  <-- already in place

  __ mov(tmp, marker_slot);
  __ mov(marker_slot,
         Immediate(StackFrame::TypeToMarker(StackFrame::WASM_LIFTOFF_SETUP)));

  int offset = SaveWasmParams(masm);

  // Arguments to the runtime function: instance, func_index.
  __ Push(kWasmImplicitArgRegister);
  __ SmiTag(func_index);
  __ Push(func_index);
  // Allocate a stack slot where the runtime function can spill a pointer
  // to the NativeModule.
  __ Push(esp);
  __ Move(kContextRegister, Smi::zero());
  __ CallRuntime(Runtime::kWasmAllocateFeedbackVector, 3);
  tmp = func_index;
  __ mov(tmp, kReturnRegister0);

  RestoreWasmParams(masm, offset);

  // Finish setting up the stack frame:
  //                             [    calling pc      ]
  //              (tmp reg) ---> [  feedback vector   ]
  // [     calling pc     ]  =>  [ Wasm instance data ]  <-- instance_data_slot
  // [ WASM_LIFTOFF_SETUP ]      [       WASM         ]  <-- marker_slot
  // [      saved ebp     ]      [    saved ebp       ]
  __ mov(marker_slot, Immediate(StackFrame::TypeToMarker(StackFrame::WASM)));
  __ Push(tmp);                // Feedback vector.
  __ mov(tmp, instance_data_slot);  // Calling PC.
  __ Push(tmp);
  __ mov(instance_data_slot, kWasmImplicitArgRegister);
  __ ret(0);
}

void Builtins::Generate_WasmCompileLazy(MacroAssembler* masm) {
  // The function index was put in edi by the jump table trampoline.
  // Convert to Smi for the runtime call.
  __ SmiTag(kWasmCompileLazyFuncIndexRegister);
  {
    HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
    FrameScope scope(masm, StackFrame::INTERNAL);
    int offset = SaveWasmParams(masm);

    // Push arguments for the runtime function.
    __ Push(kWasmImplicitArgRegister);
    __ Push(kWasmCompileLazyFuncIndexRegister);
    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ Move(kContextRegister, Smi::zero());
    __ CallRuntime(Runtime::kWasmCompileLazy, 2);
    // The runtime function returns the jump table slot offset as a Smi. Use
    // that to compute the jump target in edi.
    __ SmiUntag(kReturnRegister0);
    __ mov(edi, kReturnRegister0);

    RestoreWasmParams(masm, offset);

    // After the instance data register has been restored, we can add the jump
    // table start to the jump table offset already stored in edi.
    __ add(edi, MemOperand(kWasmImplicitArgRegister,
                           WasmTrustedInstanceData::kJumpTableStartOffset -
                               kHeapObjectTag));
  }

  // Finally, jump to the jump table slot for the function.
  __ jmp(edi);
}

void Builtins::Generate_WasmDebugBreak(MacroAssembler* masm) {
  HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
  {
    FrameScope scope(masm, StackFrame::WASM_DEBUG_BREAK);

    // Save all parameter registers. They might hold live values, we restore
    // them after the runtime call.
    for (Register reg :
         base::Reversed(WasmDebugBreakFrameConstants::kPushedGpRegs)) {
      __ Push(reg);
    }

    constexpr int kFpStackSize =
        kSimd128Size * WasmDebugBreakFrameConstants::kNumPushedFpRegisters;
    __ AllocateStackSpace(kFpStackSize);
    int offset = kFpStackSize;
    for (DoubleRegister reg :
         base::Reversed(WasmDebugBreakFrameConstants::kPushedFpRegs)) {
      offset -= kSimd128Size;
      __ movdqu(Operand(esp, offset), reg);
    }

    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ Move(kContextRegister, Smi::zero());
    __ CallRuntime(Runtime::kWasmDebugBreak, 0);

    // Restore registers.
    for (DoubleRegister reg : WasmDebugBreakFrameConstants::kPushedFpRegs) {
      __ movdqu(reg, Operand(esp, offset));
      offset += kSimd128Size;
    }
    __ add(esp, Immediate(kFpStackSize));
    for (Register reg : WasmDebugBreakFrameConstants::kPushedGpRegs) {
      __ Pop(reg);
    }
  }

  __ ret(0);
}

namespace {
// Check that the stack was in the old state (if generated code assertions are
// enabled), and switch to the new state.
void SwitchStackState(MacroAssembler* masm, Register jmpbuf,
                      wasm::JumpBuffer::StackState old_state,
                      wasm::JumpBuffer::StackState new_state) {
  __ cmp(MemOperand(jmpbuf, wasm::kJmpBufStateOffset), Immediate(old_state));
  Label ok;
  __ j(equal, &ok, Label::kNear);
  __ Trap();
  __ bind(&ok);
  __ mov(MemOperand(jmpbuf, wasm::kJmpBufStateOffset), Immediate(new_state));
}

void FillJumpBuffer(MacroAssembler* masm, Register jmpbuf, Register scratch,
                    Label* pc) {
  DCHECK(!AreAliased(scratch, jmpbuf));

  __ mov(MemOperand(jmpbuf, wasm::kJmpBufSpOffset), esp);
  __ mov(MemOperand(jmpbuf, wasm::kJmpBufFpOffset), ebp);
  __ mov(scratch, __ StackLimitAsOperand(StackLimitKind::kRealStackLimit));
  __ mov(MemOperand(jmpbuf, wasm::kJmpBufStackLimitOffset), scratch);
  __ LoadLabelAddress(scratch, pc);
  __ mov(MemOperand(jmpbuf, wasm::kJmpBufPcOffset), scratch);
}

void LoadJumpBuffer(MacroAssembler* masm, Register jmpbuf, bool load_pc,
                    wasm::JumpBuffer::StackState expected_state) {
  __ mov(esp, MemOperand(jmpbuf, wasm::kJmpBufSpOffset));
  __ mov(ebp, MemOperand(jmpbuf, wasm::kJmpBufFpOffset));
  SwitchStackState(masm, jmpbuf, expected_state, wasm::JumpBuffer::Active);
  if (load_pc) {
    __ jmp(MemOperand(jmpbuf, wasm::kJmpBufPcOffset));
  }
  // The stack limit is set separately under the ExecutionAccess lock.
}

void SaveState(MacroAssembler* masm, Register active_continuation, Register tmp,
               Register tmp2, Label* suspend) {
  DCHECK(!AreAliased(active_continuation, tmp));
  Register jmpbuf = tmp;
  __ mov(jmpbuf, FieldOperand(active_continuation,
                              WasmContinuationObject::kJmpbufOffset));
  FillJumpBuffer(masm, jmpbuf, tmp2, suspend);
}

void LoadTargetJumpBuffer(MacroAssembler* masm, Register target_continuation,
                          wasm::JumpBuffer::StackState expected_state) {
  Register target_jmpbuf = target_continuation;
  __ mov(target_jmpbuf, FieldOperand(target_continuation,
                                     WasmContinuationObject::kJmpbufOffset));
  MemOperand GCScanSlotPlace =
      MemOperand(ebp, StackSwitchFrameConstants::kGCScanSlotCountOffset);
  __ Move(GCScanSlotPlace, Immediate(0));
  // Switch stack!
  LoadJumpBuffer(masm, target_jmpbuf, false, expected_state);
}

// Updates the stack limit to match the new active stack.
// Pass the {finished_continuation} argument to indicate that the stack that we
// are switching from has returned, and in this case return its memory to the
// stack pool.
void SwitchStacks(MacroAssembler* masm, Register finished_continuation,
                  const Register& keep1, const Register& keep2 = no_reg,
                  const Register& keep3 = no_reg) {
  using ER = ExternalReference;
  __ Push(keep1);
  if (keep2 != no_reg) {
    __ Push(keep2);
  }
  if (keep3 != no_reg) {
    __ Push(keep3);
  }
  if (finished_continuation != no_reg) {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ PrepareCallCFunction(2, eax);
    __ Move(Operand(esp, 0 * kSystemPointerSize),
            Immediate(ER::isolate_address(masm->isolate())));
    __ mov(Operand(esp, 1 * kSystemPointerSize), finished_continuation);
    __ CallCFunction(ER::wasm_return_switch(), 2);
  } else {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ PrepareCallCFunction(1, eax);
    __ Move(Operand(esp, 0 * kSystemPointerSize),
            Immediate(ER::isolate_address()));
    __ CallCFunction(ER::wasm_sync_stack_limit(), 1);
  }
  if (keep3 != no_reg) {
    __ Pop(keep3);
  }
  if (keep2 != no_reg) {
    __ Pop(keep2);
  }
  __ Pop(keep1);
}

void ReloadParentContinuation(MacroAssembler* masm, Register promise,
                              Register return_value, Register context,
                              Register tmp, Register tmp2) {
  Register active_continuation = tmp;
  __ LoadRoot(active_continuation, RootIndex::kActiveContinuation);

  DCHECK(!AreAliased(promise, return_value, context, tmp));

  __ Push(promise);

  // We don't need to save the full register state since we are switching out of
  // this stack for the last time. Mark the stack as retired.
  Register jmpbuf = promise;
  __ mov(jmpbuf, FieldOperand(active_continuation,
                              WasmContinuationObject::kJmpbufOffset));
  SwitchStackState(masm, jmpbuf, wasm::JumpBuffer::Active,
                   wasm::JumpBuffer::Retired);

  Register parent = tmp2;
  __ mov(parent, FieldOperand(active_continuation,
                              WasmContinuationObject::kParentOffset));

  // Update active continuation root.
  __ mov(masm->RootAsOperand(RootIndex::kActiveContinuation), parent);
  jmpbuf = parent;
  __ mov(jmpbuf, FieldOperand(parent, WasmContinuationObject::kJmpbufOffset));

  __ Pop(promise);
  // Switch stack!
  LoadJumpBuffer(masm, jmpbuf, false, wasm::JumpBuffer::Inactive);
  SwitchStacks(masm, active_continuation, promise, return_value, context);
}

// Loads the context field of the WasmTrustedInstanceData or WasmImportData
// depending on the data's type, and places the result in the input register.
void GetContextFromImplicitArg(MacroAssembler* masm, Register data,
                               Register scratch) {
  __ Move(scratch, FieldOperand(data, HeapObject::kMapOffset));
  __ CmpInstanceType(scratch, WASM_TRUSTED_INSTANCE_DATA_TYPE);
  Label instance;
  Label end;
  __ j(equal, &instance);
  __ Move(data, FieldOperand(data, WasmImportData::kNativeContextOffset));
  __ jmp(&end);
  __ bind(&instance);
  __ Move(data,
          FieldOperand(data, WasmTrustedInstanceData::kNativeContextOffset));
  __ bind(&end);
}

void RestoreParentSuspender(MacroAssembler* masm, Register tmp1,
                            Register tmp2) {
  Register suspender = tmp1;
  __ LoadRoot(suspender, RootIndex::kActiveSuspender);
  __ mov(FieldOperand(suspender, WasmSuspenderObject::kStateOffset),
         Immediate(Smi::FromInt(WasmSuspenderObject::kInactive)));
  __ Move(suspender,
          FieldOperand(suspender, WasmSuspenderObject::kParentOffset));
  __ CompareRoot(suspender, RootIndex::kUndefinedValue);
  Label undefined;
  __ j(equal, &undefined, Label::kNear);
#ifdef DEBUG
  // Check that the parent suspender is active.
  Label parent_inactive;
  Register state = tmp2;
  __ Move(state, FieldOperand(suspender, WasmSuspenderObject::kStateOffset));
  __ SmiCompare(state, Smi::FromInt(WasmSuspenderObject::kActive));
  __ j(equal, &parent_inactive, Label::kNear);
  __ Trap();
  __ bind(&parent_inactive);
#endif
  __ Move(FieldOperand(suspender, WasmSuspenderObject::kStateOffset),
          Immediate(Smi::FromInt(WasmSuspenderObject::kActive)));
  __ bind(&undefined);
  __ mov(masm->RootAsOperand(RootIndex::kActiveSuspender), suspender);
}

void ResetStackSwitchFrameStackSlots(MacroAssembler* masm) {
  __ mov(MemOperand(ebp, StackSwitchFrameConstants::kImplicitArgOffset),
         Immediate(0));
  __ mov(MemOperand(ebp, StackSwitchFrameConstants::kResultArrayOffset),
         Immediate(0));
}

void SwitchToAllocatedStack(MacroAssembler* masm, Register wrapper_buffer,
                            Register original_fp, Register new_wrapper_buffer,
                            Register scratch, Register scratch2,
                            Label* suspend) {
  ResetStackSwitchFrameStackSlots(masm);
  Register parent_continuation = new_wrapper_buffer;
  __ LoadRoot(parent_continuation, RootIndex::kActiveContinuation);
  __ Move(
      parent_continuation,
      FieldOperand(parent_continuation, WasmContinuationObject::kParentOffset));
  SaveState(masm, parent_continuation, scratch, scratch2, suspend);
  SwitchStacks(masm, no_reg, wrapper_buffer);
  parent_continuation = no_reg;
  Register target_continuation = scratch;
  __ LoadRoot(target_continuation, RootIndex::kActiveContinuation);
  // Save the old stack's ebp, and use it to access the parameters in
  // the parent frame.
  __ mov(original_fp, ebp);
  LoadTargetJumpBuffer(masm, target_continuation, wasm::JumpBuffer::Suspended);
  // Push the loaded ebp. We know it is null, because there is no frame yet,
  // so we could also push 0 directly. In any case we need to push it, because
  // this marks the base of the stack segment for the stack frame iterator.
  __ EnterFrame(StackFrame::STACK_SWITCH);
  int stack_space =
      StackSwitchFrameConstants::kNumSpillSlots * kSystemPointerSize +
      JSToWasmWrapperFrameConstants::kWrapperBufferSize;
  __ AllocateStackSpace(stack_space);
  __ AlignStackPointer();
  __ mov(new_wrapper_buffer, esp);
  // Copy data needed for return handling from old wrapper buffer to new one.
  __ mov(scratch,
         MemOperand(wrapper_buffer,
                    JSToWasmWrapperFrameConstants::kWrapperBufferReturnCount));
  __ mov(MemOperand(new_wrapper_buffer,
                    JSToWasmWrapperFrameConstants::kWrapperBufferReturnCount),
         scratch);
  __ mov(
      scratch,
      MemOperand(wrapper_buffer,
                 JSToWasmWrapperFrameConstants::kWrapperBufferRefReturnCount));
  __ mov(
      MemOperand(new_wrapper_buffer,
                 JSToWasmWrapperFrameConstants::kWrapperBufferRefReturnCount),
      scratch);
  __ mov(
      scratch,
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferSigRepresentationArray));
  __ mov(
      MemOperand(
          new_wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferSigRepresentationArray),
      scratch);
  __ mov(
      scratch,
      MemOperand(
          wrappe
```