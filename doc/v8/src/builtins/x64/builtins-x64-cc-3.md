Response:
The user wants me to analyze a C++ source code file for V8, specifically `v8/src/builtins/x64/builtins-x64.cc`. I need to identify its functionalities, relate them to JavaScript if possible, provide examples, discuss potential programming errors, and summarize its purpose within the context of being the 4th part of a 7-part series.

Here's a breakdown of the code and how to address each point:

1. **Functionality:** The code seems to define implementations for various built-in functions in V8 for the x64 architecture. This involves handling function calls, construction, on-stack replacement (OSR), and potentially WebAssembly-related features. I need to go through each function and describe what it does.

2. **Torque Source:**  The prompt mentions `.tq` files. This file is `.cc`, so it's not a Torque file.

3. **Relationship to JavaScript (with examples):**  Many of these built-ins directly correspond to JavaScript language features. I need to identify those connections and provide JavaScript examples.

4. **Code Logic Reasoning (with assumptions and I/O):**  For some of the more complex functions, like `Generate_Call` or `Generate_Construct`, I can outline the decision-making process based on the input and expected outcomes. I'll need to make reasonable assumptions about the state of the arguments.

5. **Common Programming Errors:** I can infer potential errors by looking at the checks the code performs (e.g., calling a non-callable object, calling `Construct` on a non-constructor).

6. **Summary of Functionality (as part 4/7):** Given that this is part of a larger set, this file likely focuses on specific aspects of built-in function implementation for the x64 architecture. I need to synthesize the individual functionalities into a higher-level summary.

**Plan:**

*   Iterate through each `Generate_` function.
*   Describe its purpose in V8's execution model.
*   For functions related to JavaScript, provide a simple JavaScript example.
*   For functions with complex logic, describe the flow based on input conditions.
*   Identify potential user errors based on the code's checks.
*   Finally, summarize the overall functionality of the file.
这是 V8 源代码文件 `v8/src/builtins/x64/builtins-x64.cc` 的第 4 部分，它定义了 **x64 架构** 下 V8 JavaScript 引擎内置函数的实现。这些内置函数是 JavaScript 语言核心功能的基础，例如函数调用、对象构造等。

**功能归纳：**

本文件主要负责实现以下功能：

*   **函数调用 (Call):**  处理 JavaScript 函数的调用，包括普通函数和绑定函数，并处理 `this` 绑定的转换。
*   **对象构造 (Construct):**  处理 JavaScript 对象的构造，包括普通构造函数和绑定构造函数。
*   **代码优化入口 (On-Stack Replacement - OSR):**  支持在代码执行过程中从解释器或基线编译器切换到优化后的代码，提升性能。
*   **WebAssembly 支持:**  提供 WebAssembly 相关的内置函数，例如 WebAssembly 帧设置、延迟编译和调试中断。
*   **异常处理 (Continuation - 间接体现):**  虽然没有直接的异常处理代码，但涉及到了 Continuation 对象，这与异步操作和异常处理机制有关。

**详细功能列举和 JavaScript 示例：**

1. **`Generate_CallFunction(MacroAssembler* masm, ConvertReceiverMode mode)`:**

    *   **功能:**  实现 JavaScript 函数的调用。它会检查被调用对象是否可调用，并根据不同的情况（普通函数、绑定函数、Proxy、Wrapped Function）跳转到相应的处理逻辑。`ConvertReceiverMode` 参数决定了如何处理 `this` 的绑定。
    *   **JavaScript 示例:**

        ```javascript
        function myFunction(a, b) {
          console.log(this, a, b);
        }

        myFunction(1, 2); // 普通函数调用，this 通常指向全局对象 (非严格模式) 或 undefined (严格模式)

        const obj = { value: 'hello' };
        myFunction.call(obj, 3, 4); // 使用 call 改变 this 的绑定

        const boundFunction = myFunction.bind({ value: 'bound' }, 5);
        boundFunction(6); // 调用绑定函数
        ```

2. **`Generate_CallBoundFunctionImpl(MacroAssembler* masm)`:**

    *   **功能:**  专门处理绑定函数的调用。它会将绑定函数的 `this` 值和绑定参数压入栈中，然后调用目标函数。
    *   **JavaScript 示例:**

        ```javascript
        function originalFunction(a, b) {
          console.log(this, a, b);
        }

        const boundFn = originalFunction.bind({ value: 'bound' }, 10);
        boundFn(20); // 调用 boundFn，this 被绑定为 { value: 'bound' }，第一个参数是 10
        ```

3. **`Builtins::Generate_Call(MacroAssembler* masm, ConvertReceiverMode mode)`:**

    *   **功能:**  这是 `Generate_CallFunction` 的入口点，它会进行初步的类型检查，判断被调用对象是否是 Smi、JSFunction、JSBoundFunction、JSProxy 等，然后跳转到相应的处理逻辑。
    *   **JavaScript 示例:**  与 `Generate_CallFunction` 相同。

4. **`Builtins::Generate_ConstructFunction(MacroAssembler* masm)`:**

    *   **功能:**  处理使用 `new` 关键字调用普通 JavaScript 函数的情况。它会根据函数的 `SharedFunctionInfo` 中的标志位，选择调用 `JSBuiltinsConstructStub` (用于内置构造函数) 或 `JSConstructStubGeneric` (用于普通构造函数)。
    *   **JavaScript 示例:**

        ```javascript
        function MyClass(value) {
          this.value = value;
        }

        const instance = new MyClass(42);
        console.log(instance.value);
        ```

5. **`Builtins::Generate_ConstructBoundFunction(MacroAssembler* masm)`:**

    *   **功能:**  处理使用 `new` 关键字调用绑定函数的情况。它会将绑定函数的绑定参数压入栈中，并调用目标构造函数。
    *   **JavaScript 示例:**

        ```javascript
        function OriginalConstructor(value) {
          this.value = value;
        }

        const BoundConstructor = OriginalConstructor.bind(null, 'bound value');
        const instance = new BoundConstructor();
        console.log(instance.value);
        ```

6. **`Builtins::Generate_Construct(MacroAssembler* masm)`:**

    *   **功能:**  这是 `Generate_ConstructFunction` 和 `Generate_ConstructBoundFunction` 的入口点，负责初步的类型检查，判断被构造的对象是否是 Smi、JSFunction、JSBoundFunction、JSProxy 等，并跳转到相应的处理逻辑。
    *   **JavaScript 示例:** 与 `Generate_ConstructFunction` 相同。

7. **`Builtins::Generate_InterpreterOnStackReplacement(MacroAssembler* masm)`**, **`Builtins::Generate_BaselineOnStackReplacement(MacroAssembler* masm)`**, **`Builtins::Generate_MaglevOnStackReplacement(MacroAssembler* masm)`:**

    *   **功能:**  这些函数实现了在代码执行过程中进行优化的机制。当解释器或基线编译器执行的代码达到一定的优化条件时，V8 可以将执行切换到由优化编译器 (例如 Maglev) 生成的代码，从而提高性能。
    *   **JavaScript 示例:**  这个过程是 V8 内部自动进行的，用户代码不需要显式操作。

8. **`Builtins::Generate_WasmLiftoffFrameSetup(MacroAssembler* masm)`**, **`Builtins::Generate_WasmCompileLazy(MacroAssembler* masm)`**, **`Builtins::Generate_WasmDebugBreak(MacroAssembler* masm)`:**

    *   **功能:**  这些函数提供了对 WebAssembly 的支持。
        *   `Generate_WasmLiftoffFrameSetup`:  设置 WebAssembly 函数的栈帧。
        *   `Generate_WasmCompileLazy`:  实现 WebAssembly 函数的延迟编译。
        *   `Generate_WasmDebugBreak`:  处理 WebAssembly 代码中的断点。
    *   **JavaScript 示例:**

        ```javascript
        const wasmCode = new Uint8Array([
          0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
          0x00, 0x03, 0x02, 0x01, 0x00, 0x07, 0x0a, 0x01,
          0x07, 0x61, 0x64, 0x64, 0x00, 0x00, 0x0a, 0x09,
          0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a,
          0x0b
        ]);
        WebAssembly.instantiate(wasmCode).then(module => {
          console.log(module.instance.exports.add(5, 3));
        });
        ```

9. **`Builtins::Generate_AdaptShadowStackForDeopt(MacroAssembler* masm)` (在 `V8_ENABLE_CET_SHADOW_STACK` 宏定义下):**

    *   **功能:**  在启用 CET (Control-flow Enforcement Technology) 影子栈的情况下，协助反优化过程。它会调整影子栈，确保在反优化后，用户栈和影子栈中的返回地址能够正确匹配。
    *   **代码逻辑推理 (假设输入与输出):**  该函数主要处理栈帧和寄存器的恢复，具体输入和输出取决于反优化的具体场景，难以用简单的假设输入输出描述。其核心逻辑是操作栈指针和寄存器，恢复到之前的状态。

**用户常见的编程错误示例：**

1. **调用不可调用的对象：**

    ```javascript
    const obj = { a: 1 };
    obj(); // TypeError: obj is not a function
    ```

    在 `Builtins::Generate_Call` 中，会检查 `target` 是否可调用，如果不可调用，会抛出 `TypeError`。

2. **尝试 `new` 一个非构造函数：**

    ```javascript
    function myFunction() {
      return 1;
    }
    const instance = new myFunction(); // TypeError: myFunction is not a constructor
    ```

    在 `Builtins::Generate_Construct` 中，会检查 `target` 是否是构造函数，如果不是，会抛出 `TypeError`。

3. **在类构造函数中忘记调用 `super` (涉及更复杂的编译和运行时机制，这里简单提及):** 虽然这个文件可能不直接处理 `super` 的调用，但它处理了构造函数的调用流程。忘记调用 `super` 会导致 `this` 未初始化，最终会在运行时抛出错误。

**总结：**

`v8/src/builtins/x64/builtins-x64.cc` 是 V8 引擎中负责在 x64 架构下实现核心 JavaScript 功能的关键部分。它包含了处理函数调用、对象构造、代码优化和 WebAssembly 支持的底层汇编代码实现。这些内置函数的正确实现直接关系到 JavaScript 代码的执行效率和语言特性的正确性。作为 7 个部分中的第 4 部分，它很可能专注于这些核心的、与代码执行流程紧密相关的内置函数的实现。

Prompt: 
```
这是目录为v8/src/builtins/x64/builtins-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/x64/builtins-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共7部分，请归纳一下它的功能

"""
t e -------------
  //  -- rax : the number of arguments
  //  -- rdi : the function to call (checked to be a JSFunction)
  // -----------------------------------

  StackArgumentsAccessor args(rax);
  __ AssertCallableFunction(rdi);

  __ LoadTaggedField(rdx,
                     FieldOperand(rdi, JSFunction::kSharedFunctionInfoOffset));
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdx : the shared function info.
  //  -- rdi : the function to call (checked to be a JSFunction)
  // -----------------------------------

  // Enter the context of the function; ToObject has to run in the function
  // context, and we also need to take the global proxy from the function
  // context in case of conversion.
  __ LoadTaggedField(rsi, FieldOperand(rdi, JSFunction::kContextOffset));
  // We need to convert the receiver for non-native sloppy mode functions.
  Label done_convert;
  __ testl(FieldOperand(rdx, SharedFunctionInfo::kFlagsOffset),
           Immediate(SharedFunctionInfo::IsNativeBit::kMask |
                     SharedFunctionInfo::IsStrictBit::kMask));
  __ j(not_zero, &done_convert);
  {
    // ----------- S t a t e -------------
    //  -- rax : the number of arguments
    //  -- rdx : the shared function info.
    //  -- rdi : the function to call (checked to be a JSFunction)
    //  -- rsi : the function context.
    // -----------------------------------

    if (mode == ConvertReceiverMode::kNullOrUndefined) {
      // Patch receiver to global proxy.
      __ LoadGlobalProxy(rcx);
    } else {
      Label convert_to_object, convert_receiver;
      __ movq(rcx, args.GetReceiverOperand());
      __ JumpIfSmi(rcx, &convert_to_object,
                   DEBUG_BOOL ? Label::kFar : Label::kNear);
      __ JumpIfJSAnyIsNotPrimitive(rcx, rbx, &done_convert,
                                   DEBUG_BOOL ? Label::kFar : Label::kNear);
      if (mode != ConvertReceiverMode::kNotNullOrUndefined) {
        Label convert_global_proxy;
        __ JumpIfRoot(rcx, RootIndex::kUndefinedValue, &convert_global_proxy,
                      DEBUG_BOOL ? Label::kFar : Label::kNear);
        __ JumpIfNotRoot(rcx, RootIndex::kNullValue, &convert_to_object,
                         DEBUG_BOOL ? Label::kFar : Label::kNear);
        __ bind(&convert_global_proxy);
        {
          // Patch receiver to global proxy.
          __ LoadGlobalProxy(rcx);
        }
        __ jmp(&convert_receiver);
      }
      __ bind(&convert_to_object);
      {
        // Convert receiver using ToObject.
        // TODO(bmeurer): Inline the allocation here to avoid building the frame
        // in the fast case? (fall back to AllocateInNewSpace?)
        FrameScope scope(masm, StackFrame::INTERNAL);
        __ SmiTag(rax);
        __ Push(rax);
        __ Push(rdi);
        __ movq(rax, rcx);
        __ Push(rsi);
        __ CallBuiltin(Builtin::kToObject);
        __ Pop(rsi);
        __ movq(rcx, rax);
        __ Pop(rdi);
        __ Pop(rax);
        __ SmiUntagUnsigned(rax);
      }
      __ LoadTaggedField(
          rdx, FieldOperand(rdi, JSFunction::kSharedFunctionInfoOffset));
      __ bind(&convert_receiver);
    }
    __ movq(args.GetReceiverOperand(), rcx);
  }
  __ bind(&done_convert);

  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdx : the shared function info.
  //  -- rdi : the function to call (checked to be a JSFunction)
  //  -- rsi : the function context.
  // -----------------------------------

#ifdef V8_ENABLE_LEAPTIERING
  __ InvokeFunctionCode(rdi, no_reg, rax, InvokeType::kJump);
#else
  __ movzxwq(
      rbx, FieldOperand(rdx, SharedFunctionInfo::kFormalParameterCountOffset));
  __ InvokeFunctionCode(rdi, no_reg, rbx, rax, InvokeType::kJump);
#endif
}

namespace {

void Generate_PushBoundArguments(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdx : new.target (only in case of [[Construct]])
  //  -- rdi : target (checked to be a JSBoundFunction)
  // -----------------------------------

  // Load [[BoundArguments]] into rcx and length of that into rbx.
  Label no_bound_arguments;
  __ LoadTaggedField(rcx,
                     FieldOperand(rdi, JSBoundFunction::kBoundArgumentsOffset));
  __ SmiUntagFieldUnsigned(rbx,
                           FieldOperand(rcx, offsetof(FixedArray, length_)));
  __ testl(rbx, rbx);
  __ j(zero, &no_bound_arguments);
  {
    // ----------- S t a t e -------------
    //  -- rax : the number of arguments
    //  -- rdx : new.target (only in case of [[Construct]])
    //  -- rdi : target (checked to be a JSBoundFunction)
    //  -- rcx : the [[BoundArguments]] (implemented as FixedArray)
    //  -- rbx : the number of [[BoundArguments]] (checked to be non-zero)
    // -----------------------------------

    // TODO(victor): Use Generate_StackOverflowCheck here.
    // Check the stack for overflow.
    {
      Label done;
      __ shlq(rbx, Immediate(kSystemPointerSizeLog2));
      __ movq(kScratchRegister, rsp);
      __ subq(kScratchRegister, rbx);

      // We are not trying to catch interruptions (i.e. debug break and
      // preemption) here, so check the "real stack limit".
      __ cmpq(kScratchRegister,
              __ StackLimitAsOperand(StackLimitKind::kRealStackLimit));
      __ j(above_equal, &done, Label::kNear);
      {
        FrameScope scope(masm, StackFrame::MANUAL);
        __ EnterFrame(StackFrame::INTERNAL);
        __ CallRuntime(Runtime::kThrowStackOverflow);
      }
      __ bind(&done);
    }

    // Save Return Address and Receiver into registers.
    __ Pop(r8);
    __ Pop(r10);

    // Push [[BoundArguments]] to the stack.
    {
      Label loop;
      __ LoadTaggedField(
          rcx, FieldOperand(rdi, JSBoundFunction::kBoundArgumentsOffset));
      __ SmiUntagFieldUnsigned(
          rbx, FieldOperand(rcx, offsetof(FixedArray, length_)));
      __ addq(rax, rbx);  // Adjust effective number of arguments.
      __ bind(&loop);
      // Instead of doing decl(rbx) here subtract kTaggedSize from the header
      // offset in order to be able to move decl(rbx) right before the loop
      // condition. This is necessary in order to avoid flags corruption by
      // pointer decompression code.
      __ LoadTaggedField(
          r12, FieldOperand(rcx, rbx, times_tagged_size,
                            OFFSET_OF_DATA_START(FixedArray) - kTaggedSize));
      __ Push(r12);
      __ decl(rbx);
      __ j(greater, &loop);
    }

    // Recover Receiver and Return Address.
    __ Push(r10);
    __ Push(r8);
  }
  __ bind(&no_bound_arguments);
}

}  // namespace

// static
void Builtins::Generate_CallBoundFunctionImpl(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdi : the function to call (checked to be a JSBoundFunction)
  // -----------------------------------
  __ AssertBoundFunction(rdi);

  // Patch the receiver to [[BoundThis]].
  StackArgumentsAccessor args(rax);
  __ LoadTaggedField(rbx, FieldOperand(rdi, JSBoundFunction::kBoundThisOffset));
  __ movq(args.GetReceiverOperand(), rbx);

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Call the [[BoundTargetFunction]] via the Call builtin.
  __ LoadTaggedField(
      rdi, FieldOperand(rdi, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtins::Call());
}

// static
void Builtins::Generate_Call(MacroAssembler* masm, ConvertReceiverMode mode) {
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdi : the target to call (can be any Object)
  // -----------------------------------
  Register argc = rax;
  Register target = rdi;
  Register map = rcx;
  Register instance_type = rdx;
  DCHECK(!AreAliased(argc, target, map, instance_type));

  StackArgumentsAccessor args(argc);

  Label non_callable, class_constructor;
  __ JumpIfSmi(target, &non_callable);
  __ LoadMap(map, target);
  __ CmpInstanceTypeRange(map, instance_type, FIRST_CALLABLE_JS_FUNCTION_TYPE,
                          LAST_CALLABLE_JS_FUNCTION_TYPE);
  __ TailCallBuiltin(Builtins::CallFunction(mode), below_equal);

  __ cmpw(instance_type, Immediate(JS_BOUND_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kCallBoundFunction, equal);

  // Check if target has a [[Call]] internal method.
  __ testb(FieldOperand(map, Map::kBitFieldOffset),
           Immediate(Map::Bits1::IsCallableBit::kMask));
  __ j(zero, &non_callable, Label::kNear);

  // Check if target is a proxy and call CallProxy external builtin
  __ cmpw(instance_type, Immediate(JS_PROXY_TYPE));
  __ TailCallBuiltin(Builtin::kCallProxy, equal);

  // Check if target is a wrapped function and call CallWrappedFunction external
  // builtin
  __ cmpw(instance_type, Immediate(JS_WRAPPED_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kCallWrappedFunction, equal);

  // ES6 section 9.2.1 [[Call]] ( thisArgument, argumentsList)
  // Check that the function is not a "classConstructor".
  __ cmpw(instance_type, Immediate(JS_CLASS_CONSTRUCTOR_TYPE));
  __ j(equal, &class_constructor);

  // 2. Call to something else, which might have a [[Call]] internal method (if
  // not we raise an exception).

  // Overwrite the original receiver with the (original) target.
  __ movq(args.GetReceiverOperand(), target);
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
  //  -- rax : the number of arguments
  //  -- rdx : the new target (checked to be a constructor)
  //  -- rdi : the constructor to call (checked to be a JSFunction)
  // -----------------------------------
  __ AssertConstructor(rdi);
  __ AssertFunction(rdi);

  // Calling convention for function specific ConstructStubs require
  // rbx to contain either an AllocationSite or undefined.
  __ LoadRoot(rbx, RootIndex::kUndefinedValue);

  // Jump to JSBuiltinsConstructStub or JSConstructStubGeneric.
  const TaggedRegister shared_function_info(rcx);
  __ LoadTaggedField(shared_function_info,
                     FieldOperand(rdi, JSFunction::kSharedFunctionInfoOffset));
  __ testl(FieldOperand(shared_function_info, SharedFunctionInfo::kFlagsOffset),
           Immediate(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ TailCallBuiltin(Builtin::kJSBuiltinsConstructStub, not_zero);

  __ TailCallBuiltin(Builtin::kJSConstructStubGeneric);
}

// static
void Builtins::Generate_ConstructBoundFunction(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdx : the new target (checked to be a constructor)
  //  -- rdi : the constructor to call (checked to be a JSBoundFunction)
  // -----------------------------------
  __ AssertConstructor(rdi);
  __ AssertBoundFunction(rdi);

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Patch new.target to [[BoundTargetFunction]] if new.target equals target.
  {
    Label done;
    __ cmpq(rdi, rdx);
    __ j(not_equal, &done, Label::kNear);
    __ LoadTaggedField(
        rdx, FieldOperand(rdi, JSBoundFunction::kBoundTargetFunctionOffset));
    __ bind(&done);
  }

  // Construct the [[BoundTargetFunction]] via the Construct builtin.
  __ LoadTaggedField(
      rdi, FieldOperand(rdi, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtin::kConstruct);
}

// static
void Builtins::Generate_Construct(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdx : the new target (either the same as the constructor or
  //           the JSFunction on which new was invoked initially)
  //  -- rdi : the constructor to call (can be any Object)
  // -----------------------------------
  Register argc = rax;
  Register target = rdi;
  Register map = rcx;
  Register instance_type = r8;
  DCHECK(!AreAliased(argc, target, map, instance_type));

  StackArgumentsAccessor args(argc);

  // Check if target is a Smi.
  Label non_constructor;
  __ JumpIfSmi(target, &non_constructor);

  // Check if target has a [[Construct]] internal method.
  __ LoadMap(map, target);
  __ testb(FieldOperand(map, Map::kBitFieldOffset),
           Immediate(Map::Bits1::IsConstructorBit::kMask));
  __ j(zero, &non_constructor);

  // Dispatch based on instance type.
  __ CmpInstanceTypeRange(map, instance_type, FIRST_JS_FUNCTION_TYPE,
                          LAST_JS_FUNCTION_TYPE);
  __ TailCallBuiltin(Builtin::kConstructFunction, below_equal);

  // Only dispatch to bound functions after checking whether they are
  // constructors.
  __ cmpw(instance_type, Immediate(JS_BOUND_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kConstructBoundFunction, equal);

  // Only dispatch to proxies after checking whether they are constructors.
  __ cmpw(instance_type, Immediate(JS_PROXY_TYPE));
  __ TailCallBuiltin(Builtin::kConstructProxy, equal);

  // Called Construct on an exotic Object with a [[Construct]] internal method.
  {
    // Overwrite the original receiver with the (original) target.
    __ movq(args.GetReceiverOperand(), target);
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
  // Drop the return address on the stack and jump to the OSR entry
  // point of the function.
  __ Drop(1);
  // TODO(sroettger): Use the notrack prefix since not all OSR entries emit an
  // endbr instruction yet.
  __ jmp(entry_address, /*notrack=*/true);
}

enum class OsrSourceTier {
  kInterpreter,
  kBaseline,
  kMaglev,
};

void OnStackReplacement(MacroAssembler* masm, OsrSourceTier source,
                        Register maybe_target_code) {
  Label jump_to_optimized_code;
  {
    // If maybe_target_code is not null, no need to call into runtime. A
    // precondition here is: if maybe_target_code is an InstructionStream
    // object, it must NOT be marked_for_deoptimization (callers must ensure
    // this).
    __ testq(maybe_target_code, maybe_target_code);
    __ j(not_equal, &jump_to_optimized_code, Label::kNear);
  }

  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kCompileOptimizedOSR);
  }

  // If the code object is null, just return to the caller.
  __ testq(rax, rax);
  __ j(not_equal, &jump_to_optimized_code, Label::kNear);
  __ ret(0);

  __ bind(&jump_to_optimized_code);
  DCHECK_EQ(maybe_target_code, rax);  // Already in the right spot.

  if (source == OsrSourceTier::kMaglev) {
    // Maglev doesn't enter OSR'd code itself, since OSR depends on the
    // unoptimized (~= Ignition) stack frame layout. Instead, return to Maglev
    // code and let it deoptimize.
    __ ret(0);
    return;
  }

  // OSR entry tracing.
  {
    Label next;
    __ cmpb(
        __ ExternalReferenceAsOperand(
            ExternalReference::address_of_log_or_trace_osr(), kScratchRegister),
        Immediate(0));
    __ j(equal, &next, Label::kNear);

    {
      FrameScope scope(masm, StackFrame::INTERNAL);
      __ Push(rax);  // Preserve the code object.
      __ CallRuntime(Runtime::kLogOrTraceOptimizedOSREntry, 0);
      __ Pop(rax);
    }

    __ bind(&next);
  }

  if (source == OsrSourceTier::kInterpreter) {
    // Drop the handler frame that is be sitting on top of the actual
    // JavaScript frame.
    __ leave();
  }

  // Load deoptimization data from the code object.
  const Register deopt_data(rbx);
  __ LoadProtectedPointerField(
      deopt_data,
      FieldOperand(rax, Code::kDeoptimizationDataOrInterpreterDataOffset));

  // Load the OSR entrypoint offset from the deoptimization data.
  __ SmiUntagField(
      rbx,
      FieldOperand(deopt_data, TrustedFixedArray::OffsetOfElementAt(
                                   DeoptimizationData::kOsrPcOffsetIndex)));

  __ LoadCodeInstructionStart(rax, rax, kJSEntrypointTag);

  // Compute the target address = code_entry + osr_offset
  __ addq(rax, rbx);

  Generate_OSREntry(masm, rax);
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
  __ movq(kContextRegister,
          MemOperand(rbp, BaselineFrameConstants::kContextOffset));
  OnStackReplacement(masm, OsrSourceTier::kBaseline,
                     D::MaybeTargetCodeRegister());
}

void Builtins::Generate_MaglevOnStackReplacement(MacroAssembler* masm) {
  using D =
      i::CallInterfaceDescriptorFor<Builtin::kMaglevOnStackReplacement>::type;
  static_assert(D::kParameterCount == 1);
  OnStackReplacement(masm, OsrSourceTier::kMaglev,
                     D::MaybeTargetCodeRegister());
}

#ifdef V8_ENABLE_MAGLEV

// static
void Builtins::Generate_MaglevFunctionEntryStackCheck(MacroAssembler* masm,
                                                      bool save_new_target) {
  // Input (rax): Stack size (Smi).
  // This builtin can be invoked just after Maglev's prologue.
  // All registers are available, except (possibly) new.target.
  ASM_CODE_COMMENT(masm);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ AssertSmi(rax);
    if (save_new_target) {
      if (PointerCompressionIsEnabled()) {
        __ AssertSmiOrHeapObjectInMainCompressionCage(
            kJavaScriptCallNewTargetRegister);
      }
      __ Push(kJavaScriptCallNewTargetRegister);
    }
    __ Push(rax);
    __ CallRuntime(Runtime::kStackGuardWithGap, 1);
    if (save_new_target) {
      __ Pop(kJavaScriptCallNewTargetRegister);
    }
  }
  __ Ret();
}

#endif  // V8_ENABLE_MAGLEV

namespace {

void Generate_RestoreFrameDescriptionRegisters(MacroAssembler* masm,
                                               Register frame_description) {
  // Set the xmm (simd / double) registers.
  const RegisterConfiguration* config = RegisterConfiguration::Default();
  int simd128_regs_offset = FrameDescription::simd128_registers_offset();
  for (int i = 0; i < config->num_allocatable_simd128_registers(); ++i) {
    int code = config->GetAllocatableSimd128Code(i);
    XMMRegister xmm_reg = XMMRegister::from_code(code);
    int src_offset = code * kSimd128Size + simd128_regs_offset;
    __ movdqu(xmm_reg, Operand(frame_description, src_offset));
  }

  // Restore the non-xmm registers from the stack.
  for (int i = Register::kNumRegisters - 1; i >= 0; i--) {
    Register r = Register::from_code(i);
    // Do not restore rsp and kScratchRegister.
    if (r == rsp || r == kScratchRegister) continue;
    __ popq(r);
  }
}

}  // namespace

#ifdef V8_ENABLE_CET_SHADOW_STACK
// AdaptShadowStackForDeopt assists the deoptimizer in getting continuation
// addresses placed on the shadow stack. This can only be done with a call
// instruction. Earlier in the deoptimization process, the user stack was
// seeded with return addresses into the continuations. At this stage, we
// make calls into the continuations such that the shadow stack contains
// precisely those necessary return addresses back into those continuations,
// and in the appropriate order that the shadow stack and the user stack
// perfectly match up at the points where return instructions are executed.
//
// The stack layout on entry to AdaptShadowStackForDeopt is as follows:
//
// ReturnAddress_1
// ReturnAddress_2
// ...
// ReturnAddresss_N
// LastFrameDescription (for restoring registers)
// savedRegister_1
// savedRegister_2
// ...
//
// kAdaptShadowStackCountRegister, on entry, has the value N, matching the
// number of identifiers to pop from the stack above. It is decremented each
// time AdaptShadowStackForDeopt pops a return address from the stack. This
// happens once per invocation of AdaptShadowStackForDeopt. When the value
// is 0, the function jumps to the last return address and will not be called
// again for this deoptimization process.
//
// The other cpu registers have already been populated with the required values
// to kick off execution running the builtin continuation associated with
// ReturnAddress_N on the stack above. AdaptShadowStackForDeopt uses
// kScratchRegister and kAdaptShadowStackRegister for its own work, and
// that is why those registers are additionaly saved on the stack, to be
// restored at the end of the process.

// kAdaptShadowStackDispatchFirstEntryOffset marks the "kick-off" location in
// AdaptShadowStackForDeopt for the process.
constexpr int kAdaptShadowStackDispatchFirstEntryOffset = 1;

// kAdaptShadowStackCountRegister contains the number of identifiers on
// the stack to be consumed via repeated calls into AdaptShadowStackForDeopt.
constexpr Register kAdaptShadowStackCountRegister = r11;

void Builtins::Generate_AdaptShadowStackForDeopt(MacroAssembler* masm) {
  Register count_reg = kAdaptShadowStackCountRegister;
  Register addr = rax;

  // Pop unnecessary return address on stack.
  __ popq(addr);

  // DeoptimizationEntry enters here.
  CHECK_EQ(masm->pc_offset(), kAdaptShadowStackDispatchFirstEntryOffset);

  __ decl(count_reg);
  __ popq(addr);  // Pop the next target address.

  __ pushq(count_reg);
  __ Move(kCArgRegs[0], ExternalReference::isolate_address());
  __ movq(kCArgRegs[1], addr);
  __ PrepareCallCFunction(2);
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    // We should block jumps to arbitrary locations for a security reason.
    // This function will crash if the address is not in the allow list.
    // And, return the given address if it is valid.
    __ CallCFunction(ExternalReference::ensure_valid_return_address(), 2);
  }
  __ popq(count_reg);
  // Now `kReturnRegister0` is the address we want to jump to.

  __ cmpl(count_reg, Immediate(0));
  Label finished;
  __ j(equal, &finished, Label::kNear);
  // This will jump to CallToAdaptShadowStackForDeopt which call back into this
  // function and continue adapting shadow stack.
  __ jmp(kReturnRegister0);

  __ bind(&finished);
  __ movb(__ ExternalReferenceAsOperand(IsolateFieldId::kStackIsIterable),
          Immediate(1));
  __ movq(kScratchRegister, kReturnRegister0);

  __ popq(rbx);  // Restore the last FrameDescription.
  Generate_RestoreFrameDescriptionRegisters(masm, rbx);
  __ jmp(kScratchRegister);
}
#endif  // V8_ENABLE_CET_SHADOW_STACK

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
    __ movdqu(Operand(rsp, offset), reg);
    offset += kSimd128Size;
  }
  return offset;
}

// Consumes the offset beyond the last saved FP register (as returned by
// {SaveWasmParams}).
void RestoreWasmParams(MacroAssembler* masm, int offset) {
  for (DoubleRegister reg : base::Reversed(wasm::kFpParamRegisters)) {
    offset -= kSimd128Size;
    __ movdqu(reg, Operand(rsp, offset));
  }
  DCHECK_EQ(0, offset);
  __ addq(rsp, Immediate(kSimd128Size * arraysize(wasm::kFpParamRegisters)));
  for (Register reg : base::Reversed(wasm::kGpParamRegisters)) {
    __ Pop(reg);
  }
}

// When this builtin is called, the topmost stack entry is the calling pc.
// This is replaced with the following:
//
// [    calling pc      ]  <-- rsp; popped by {ret}.
// [  feedback vector   ]
// [ Wasm instance data ]
// [ WASM frame marker  ]
// [    saved rbp       ]  <-- rbp; this is where "calling pc" used to be.
void Builtins::Generate_WasmLiftoffFrameSetup(MacroAssembler* masm) {
  Register func_index = wasm::kLiftoffFrameSetupFunctionReg;
  Register vector = r15;
  Register calling_pc = rdi;

  __ Pop(calling_pc);
  __ Push(rbp);
  __ Move(rbp, rsp);
  __ Push(Immediate(StackFrame::TypeToMarker(StackFrame::WASM)));
  __ LoadTaggedField(
      vector, FieldOperand(kWasmImplicitArgRegister,
                           WasmTrustedInstanceData::kFeedbackVectorsOffset));
  __ LoadTaggedField(vector, FieldOperand(vector, func_index, times_tagged_size,
                                          OFFSET_OF_DATA_START(FixedArray)));
  Label allocate_vector, done;
  __ JumpIfSmi(vector, &allocate_vector);
  __ bind(&done);
  __ Push(kWasmImplicitArgRegister);
  __ Push(vector);
  __ Push(calling_pc);
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
  // [           calling pc           ]
  // [   WASM_LIFTOFF_SETUP marker    ]
  // [           saved rbp            ]
  __ movq(Operand(rbp, TypedFrameConstants::kFrameTypeOffset),
          Immediate(StackFrame::TypeToMarker(StackFrame::WASM_LIFTOFF_SETUP)));
  __ set_has_frame(true);
  __ Push(calling_pc);
  int offset = SaveWasmParams(masm);

  // Arguments to the runtime function: instance data, func_index.
  __ Push(kWasmImplicitArgRegister);
  __ SmiTag(func_index);
  __ Push(func_index);
  // Allocate a stack slot where the runtime function can spill a pointer
  // to the NativeModule.
  __ Push(rsp);
  __ Move(kContextRegister, Smi::zero());
  __ CallRuntime(Runtime::kWasmAllocateFeedbackVector, 3);
  __ movq(vector, kReturnRegister0);

  RestoreWasmParams(masm, offset);
  __ Pop(calling_pc);
  // Restore correct frame type.
  __ movq(Operand(rbp, TypedFrameConstants::kFrameTypeOffset),
          Immediate(StackFrame::TypeToMarker(StackFrame::WASM)));
  __ jmp(&done);
}

void Builtins::Generate_WasmCompileLazy(MacroAssembler* masm) {
  // The function index was pushed to the stack by the caller as int32.
  __ Pop(r15);
  // Convert to Smi for the runtime call.
  __ SmiTag(r15);

  {
    HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
    FrameScope scope(masm, StackFrame::INTERNAL);

    int offset = SaveWasmParams(masm);

    // Push arguments for the runtime function.
    __ Push(kWasmImplicitArgRegister);
    __ Push(r15);
    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ Move(kContextRegister, Smi::zero());
    __ CallRuntime(Runtime::kWasmCompileLazy, 2);
    // The runtime function returns the jump table slot offset as a Smi. Use
    // that to compute the jump target in r15.
    __ SmiUntagUnsigned(kReturnRegister0);
    __ movq(r15, kReturnRegister0);

    RestoreWasmParams(masm, offset);
    // After the instance data register has been restored, we can add the jump
    // table start to the jump table offset already stored in r15.
    __ addq(r15,
            MemOperand(kWasmImplicitArgRegister,
                       wasm::ObjectAccess::ToTagged(
                           WasmTrustedInstanceData::kJumpTableStartOffset)));
  }

  // Finally, jump to the jump table slot for the function.
  __ jmp(r15);
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
      __ movdqu(Operand(rsp, offset), reg);
    }

    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ Move(kContextRegister, Smi::zero());
    __ CallRuntime(Runtime::kWasmDebugBreak, 0);

    // Restore registers.
    for (DoubleRegister reg : WasmDebugBreakFrameConstants::kPushedFpRegs) {
      __ movdqu(reg, Operand(rsp, offset));
      offset += kSimd128Size;
    }
    __ addq(rsp, Immediate(kFpStackSize));
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
#if V8_ENABLE_SANDBOX
  __ cmpl(MemOperand(jmpbuf, wasm::kJmpBufStateOffset), Immediate(old_state));
  Label ok;
  __ j(equal, &ok, Label::kNear);
  __ Trap();
  __ bind(&ok);
#endif
  __ movl(MemOperand(jmpbuf, wasm::kJmpBufStateOffset), Immediate(new_state));
}

void FillJumpBuffer(MacroAssembler* masm, Register jmpbuf, Label* pc) {
  __ movq(MemOperand(jmpbuf, wasm::kJmpBufSpOffset), rsp);
  __ movq(MemOperand(jmpbuf, wasm::kJmpBufFpOffset), rbp);
  __ movq(kScratchRegister,
          __ StackLimitAsOperand(StackLimitKind::kRealStackLimit));
  __ movq(MemOperand(jmpbuf, wasm::kJmpBufStackLimitOffset), kScratchRegister);
  __ leaq(kScratchRegister, MemOperand(pc, 0));
  __ movq(MemOperand(jmpbuf, wasm::kJmpBufPcOffset), kScratchRegister);
}

void LoadJumpBuffer(MacroAssembler* masm, Register jmpbuf, bool load_pc,
                    wasm::JumpBuffer::StackState expected_state) {
  __ movq(rsp, MemOperand(jmpbuf, wasm::kJmpBufSpOffset));
  __ movq(rbp, MemOperand(jmpbuf, wasm::kJmpBufFpOffset));
  SwitchStackState(masm, jmpbuf, expected_state, wasm::JumpBuffer::Active);
  if (load_pc) {
    __ jmp(MemOperand(jmpbuf, wasm::kJmpBufPcOffset));
  }
  // The stack limit is set separately under the ExecutionAccess lock.
}

void SaveState(MacroAssembler* masm, Register active_continuation, Register tmp,
               Label* suspend) {
  Register jmpbuf = tmp;
  __ LoadExternalPointerField(
      jmpbuf,
      FieldOperand(active_continuation, WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag, kScratchRegister);
  FillJumpBuffer(masm, jmpbuf, suspend);
}

void LoadTargetJumpBuffer(MacroAssembler* masm, Register target_continuation,
                          wasm::JumpBuffer::StackState expected_state) {
  Register target_jmpbuf = target_continuation;
  __ LoadExternalPointerField(
      target_jmpbuf,
      FieldOperand(target_continuation, WasmContinuationObject::kJmpbufOffset),
      kW
"""


```