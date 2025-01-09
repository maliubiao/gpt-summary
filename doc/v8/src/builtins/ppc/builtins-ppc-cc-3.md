Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/builtins/ppc/builtins-ppc.cc`. I need to identify the different functionalities implemented in this code.

The code seems to define various built-in functions for the PPC architecture in V8. Keywords like `Generate_Call`, `Generate_Construct`, `Generate_CEntry`, and `Generate_Wasm*` suggest the implementation of core JavaScript functionalities like function calls, object construction, C++ entry points, and WebAssembly support.

I need to go through each `Generate_` function and summarize its role. If any of these relate to standard JavaScript features, I'll provide a JavaScript example. If there's a clear logical flow with inputs and outputs, I'll illustrate that. I also need to be on the lookout for common programming errors that might be relevant to these built-ins. Finally, I need to remember this is part 4 of 5 and summarize the functionalities covered in this specific part.

Here's a breakdown of the functionalities I can identify:

- `Generate_ForwardVarargs`: Handles forwarding variable arguments during function calls.
- `Generate_CallFunction`: Implements the core logic for calling JavaScript functions.
- `Generate_PushBoundArguments`: Manages pushing bound arguments for bound functions.
- `Generate_CallBoundFunctionImpl`:  Specific logic for calling bound functions.
- `Generate_Call`: High-level call logic that dispatches to `CallFunction` or `CallBoundFunctionImpl`.
- `Generate_ConstructFunction`: Logic for constructing JavaScript objects using regular functions.
- `Generate_ConstructBoundFunction`: Logic for constructing objects using bound functions.
- `Generate_Construct`: High-level construction logic dispatching to appropriate constructors.
- `Generate_WasmLiftoffFrameSetup`: Sets up the frame for WebAssembly liftoff compilation.
- `Generate_WasmCompileLazy`: Handles lazy compilation of WebAssembly functions.
- `Generate_WasmDebugBreak`: Implements a WebAssembly debug break.
- `Generate_WasmReturnPromiseOnSuspendAsm`, `Generate_JSToWasmStressSwitchStacksAsm`, `Generate_WasmTrapHandlerLandingPad`, `Generate_WasmSuspend`, `Generate_WasmResume`, `Generate_WasmReject`, `Generate_WasmOnStackReplace`: Placeholders or implementations for various WebAssembly related features.
- `Generate_WasmToJsWrapperAsm`: Handles calls from WebAssembly to JavaScript.
- `Generate_JSToWasmWrapperAsm`: Handles calls from JavaScript to WebAssembly.
- `Generate_CEntry`: Implements the entry point for calling C++ functions from JavaScript.
- `Generate_WasmHandleStackOverflow`: Handles stack overflow in WebAssembly.
- `Generate_DoubleToI`: Converts a double-precision floating-point number to an integer.

Now I can start structuring the response based on these identified functionalities.
这是 `v8/src/builtins/ppc/builtins-ppc.cc` 源代码的第 4 部分，它定义了针对 PowerPC (PPC) 架构的 V8 JavaScript 引擎的内置函数。 这些内置函数是用汇编语言实现的，用于提高性能，并涵盖了 JavaScript 引擎执行的各种核心操作。

以下是这段代码的功能归纳：

**核心 JavaScript 功能实现:**

1. **函数调用 (`Generate_CallFunction`, `Generate_CallBoundFunctionImpl`, `Generate_Call`)**:
    *   `Generate_CallFunction`:  负责调用普通的 JavaScript 函数。它处理参数传递、查找函数代码并跳转执行。
    *   `Generate_CallBoundFunctionImpl`:  专门处理调用绑定函数的情况。绑定函数是使用 `bind()` 方法创建的，具有预设的 `this` 值和部分参数。此函数会先将绑定参数压栈，然后调用目标函数。
    *   `Generate_Call`:  作为更高级别的调用入口点，它会检查被调用对象是否可调用，并根据对象类型（普通函数、绑定函数、代理等）分派到相应的处理程序。

    **JavaScript 示例:**

    ```javascript
    function myFunction(a, b) {
      console.log(this, a, b);
    }

    myFunction(1, 2); // 调用普通函数

    const boundFunction = myFunction.bind({ customThis: 'bound' }, 3);
    boundFunction(4); // 调用绑定函数
    ```

2. **对象构造 (`Generate_ConstructFunction`, `Generate_ConstructBoundFunction`, `Generate_Construct`)**:
    *   `Generate_ConstructFunction`:  处理使用 `new` 关键字调用普通函数（作为构造函数）来创建对象的过程。它负责查找构造函数的代码，并调用相应的构造器桩 (stub)。
    *   `Generate_ConstructBoundFunction`:  处理使用 `new` 关键字调用绑定函数的情况。它会先压入绑定参数，然后调用绑定目标函数的构造逻辑。
    *   `Generate_Construct`:  作为对象构造的入口点，它会检查被调用的对象是否是构造函数，并根据对象类型分派到相应的构造逻辑处理程序。

    **JavaScript 示例:**

    ```javascript
    class MyClass {
      constructor(value) {
        this.value = value;
      }
    }

    const obj1 = new MyClass(10); // 使用 new 调用类构造函数

    function MyFunctionConstructor(value) {
      this.value = value;
    }
    const boundConstructor = MyFunctionConstructor.bind(null, 20);
    const obj2 = new boundConstructor(); // 使用 new 调用绑定函数
    ```

3. **可变参数转发 (`Generate_ForwardVarargs`)**:  此功能用于在函数调用中高效地传递和处理可变数量的参数（使用剩余参数或 `arguments` 对象）。 它将参数从调用者的栈帧复制到被调用者的栈帧。

    **JavaScript 示例:**

    ```javascript
    function sum(...numbers) {
      return numbers.reduce((acc, val) => acc + val, 0);
    }

    function forwarder(a, b, ...rest) {
      console.log("Forwarder received:", a, b, rest);
      return sum(...rest); // 使用剩余参数转发
    }

    forwarder(1, 2, 3, 4, 5);
    ```

4. **C++ 内置函数入口 (`Generate_CEntry`)**:  `Generate_CEntry` 定义了从 JavaScript 代码调用 C++ 内置函数的入口点。 它负责设置 C++ 调用的环境，包括保存寄存器、传递参数和处理返回值，以及处理可能发生的异常。

    **编程错误示例:**  在 JavaScript 中调用一个期望特定类型参数的 C++ 内置函数时，如果传递了错误类型的参数，可能会导致 C++ 代码崩溃或产生未定义的行为。 例如，一个 C++ 函数期望接收一个整数，但 JavaScript 传递了一个字符串。

5. **WebAssembly 支持 (`Generate_WasmLiftoffFrameSetup`, `Generate_WasmCompileLazy`, `Generate_WasmDebugBreak`, `Generate_WasmToJsWrapperAsm`, `Generate_JSToWasmWrapperAsm` 等)**:  代码包含了多个用于支持 WebAssembly (Wasm) 的内置函数。
    *   `Generate_WasmLiftoffFrameSetup`:  为 WebAssembly 的快速编译路径 (Liftoff) 设置栈帧。
    *   `Generate_WasmCompileLazy`:  处理 WebAssembly 函数的延迟编译。
    *   `Generate_WasmDebugBreak`:  实现 WebAssembly 中的断点调试功能。
    *   `Generate_WasmToJsWrapperAsm`:  定义了从 WebAssembly 调用 JavaScript 函数的包装器。 它负责参数的转换和传递。
    *   `Generate_JSToWasmWrapperAsm`:  定义了从 JavaScript 调用 WebAssembly 函数的包装器。 它负责设置栈帧、传递参数和处理返回值。
    *   其他 `Generate_Wasm...` 函数可能是占位符或用于处理 WebAssembly 执行过程中的其他事件，例如栈溢出、挂起、恢复、拒绝 Promise 等。

    **代码逻辑推理 (以 `Generate_JSToWasmWrapperAsm` 为例):**

    **假设输入:**
    *   `r3`:  结果数组的大小 (用于多返回值的情况)
    *   `r4`:  指向结果 JSArray 的指针 (用于多返回值)
    *   栈上：JavaScript 传递给 WebAssembly 函数的参数，以及一些元数据（wrapper buffer 等）。

    **输出:**
    *   WebAssembly 函数的返回值会存储在特定的寄存器中 (`wasm::kGpReturnRegisters`, `wasm::kFpReturnRegisters`) 以及 `wrapper_buffer` 指向的内存区域。

    **用户常见的编程错误 (与 WebAssembly 调用相关):**

    *   **类型不匹配:** 在 JavaScript 中调用 WebAssembly 函数时，传递的参数类型与 WebAssembly 函数期望的类型不匹配。例如，WebAssembly 函数期望一个 32 位整数，但 JavaScript 传递了一个浮点数或一个字符串。
    *   **参数数量错误:**  调用 WebAssembly 函数时，传递的参数数量与函数签名不符。
    *   **内存访问错误:**  在 WebAssembly 模块中，尝试访问超出其线性内存边界的内存。

6. **双精度浮点数转整数 (`Generate_DoubleToI`)**:  此函数将双精度浮点数转换为整数。 代码中包含了快速路径优化，以及处理溢出和负数的情况。

**总结第 4 部分的功能:**

这段代码主要负责实现 V8 引擎中与函数调用、对象构造以及 WebAssembly 互操作相关的核心内置功能。 它包含了处理普通 JavaScript 函数和绑定函数的调用和构造逻辑，定义了从 JavaScript 进入 C++ 内置函数的入口点，并提供了支持 WebAssembly 模块与 JavaScript 代码相互调用的机制。 此外，还包含了一个用于双精度浮点数到整数转换的优化实现。 总体而言，这部分代码是 V8 引擎执行 JavaScript 代码和与外部 (C++ 和 WebAssembly) 代码交互的关键组成部分。

Prompt: 
```
这是目录为v8/src/builtins/ppc/builtins-ppc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/ppc/builtins-ppc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
ieldMemOperand(r5, SharedFunctionInfo::kFormalParameterCountOffset));
  __ InvokeFunctionCode(r4, no_reg, r5, r3, InvokeType::kJump);
}

namespace {

void Generate_PushBoundArguments(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r3 : the number of arguments
  //  -- r4 : target (checked to be a JSBoundFunction)
  //  -- r6 : new.target (only in case of [[Construct]])
  // -----------------------------------

  // Load [[BoundArguments]] into r5 and length of that into r7.
  Label no_bound_arguments;
  __ LoadTaggedField(
      r5, FieldMemOperand(r4, JSBoundFunction::kBoundArgumentsOffset), r0);
  __ SmiUntag(r7, FieldMemOperand(r5, offsetof(FixedArray, length_)), SetRC,
              r0);
  __ beq(&no_bound_arguments, cr0);
  {
    // ----------- S t a t e -------------
    //  -- r3 : the number of arguments
    //  -- r4 : target (checked to be a JSBoundFunction)
    //  -- r5 : the [[BoundArguments]] (implemented as FixedArray)
    //  -- r6 : new.target (only in case of [[Construct]])
    //  -- r7 : the number of [[BoundArguments]]
    // -----------------------------------

    Register scratch = r9;
    // Reserve stack space for the [[BoundArguments]].
    {
      Label done;
      __ ShiftLeftU64(r10, r7, Operand(kSystemPointerSizeLog2));
      __ sub(r0, sp, r10);
      // Check the stack for overflow. We are not trying to catch interruptions
      // (i.e. debug break and preemption) here, so check the "real stack
      // limit".
      {
        __ LoadStackLimit(scratch, StackLimitKind::kRealStackLimit, ip);
        __ CmpU64(r0, scratch);
      }
      __ bgt(&done);  // Signed comparison.
      {
        FrameScope scope(masm, StackFrame::MANUAL);
        __ EnterFrame(StackFrame::INTERNAL);
        __ CallRuntime(Runtime::kThrowStackOverflow);
      }
      __ bind(&done);
    }

    // Pop receiver.
    __ Pop(r8);

    // Push [[BoundArguments]].
    {
      Label loop, done;
      __ add(r3, r3, r7);  // Adjust effective number of arguments.
      __ addi(r5, r5,
              Operand(OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag));
      __ mtctr(r7);

      __ bind(&loop);
      __ subi(r7, r7, Operand(1));
      __ ShiftLeftU64(scratch, r7, Operand(kTaggedSizeLog2));
      __ add(scratch, scratch, r5);
      __ LoadTaggedField(scratch, MemOperand(scratch), r0);
      __ Push(scratch);
      __ bdnz(&loop);
      __ bind(&done);
    }

    // Push receiver.
    __ Push(r8);
  }
  __ bind(&no_bound_arguments);
}

}  // namespace

// static
void Builtins::Generate_CallBoundFunctionImpl(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r3 : the number of arguments
  //  -- r4 : the function to call (checked to be a JSBoundFunction)
  // -----------------------------------
  __ AssertBoundFunction(r4);

  // Patch the receiver to [[BoundThis]].
  __ LoadTaggedField(r6, FieldMemOperand(r4, JSBoundFunction::kBoundThisOffset),
                     r0);
  __ StoreReceiver(r6);

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Call the [[BoundTargetFunction]] via the Call builtin.
  __ LoadTaggedField(
      r4, FieldMemOperand(r4, JSBoundFunction::kBoundTargetFunctionOffset), r0);
  __ TailCallBuiltin(Builtins::Call());
}

// static
void Builtins::Generate_Call(MacroAssembler* masm, ConvertReceiverMode mode) {
  // ----------- S t a t e -------------
  //  -- r3 : the number of arguments
  //  -- r4 : the target to call (can be any Object).
  // -----------------------------------
  Register target = r4;
  Register map = r7;
  Register instance_type = r8;
  Register scratch = r9;
  DCHECK(!AreAliased(r3, target, map, instance_type));

  Label non_callable, class_constructor;
  __ JumpIfSmi(target, &non_callable);
  __ LoadMap(map, target);
  __ CompareInstanceTypeRange(map, instance_type, scratch,
                              FIRST_CALLABLE_JS_FUNCTION_TYPE,
                              LAST_CALLABLE_JS_FUNCTION_TYPE);
  __ TailCallBuiltin(Builtins::CallFunction(mode), le);
  __ cmpi(instance_type, Operand(JS_BOUND_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kCallBoundFunction, eq);

  // Check if target has a [[Call]] internal method.
  {
    Register flags = r7;
    __ lbz(flags, FieldMemOperand(map, Map::kBitFieldOffset));
    map = no_reg;
    __ TestBit(flags, Map::Bits1::IsCallableBit::kShift, r0);
    __ beq(&non_callable, cr0);
  }

  // Check if target is a proxy and call CallProxy external builtin
  __ cmpi(instance_type, Operand(JS_PROXY_TYPE));
  __ TailCallBuiltin(Builtin::kCallProxy, eq);

  // Check if target is a wrapped function and call CallWrappedFunction external
  // builtin
  __ cmpi(instance_type, Operand(JS_WRAPPED_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kCallWrappedFunction, eq);

  // ES6 section 9.2.1 [[Call]] ( thisArgument, argumentsList)
  // Check that the function is not a "classConstructor".
  __ cmpi(instance_type, Operand(JS_CLASS_CONSTRUCTOR_TYPE));
  __ beq(&class_constructor);

  // 2. Call to something else, which might have a [[Call]] internal method (if
  // not we raise an exception).
  // Overwrite the original receiver the (original) target.
  __ StoreReceiver(target);
  // Let the "call_as_function_delegate" take care of the rest.
  __ LoadNativeContextSlot(target, Context::CALL_AS_FUNCTION_DELEGATE_INDEX);
  __ TailCallBuiltin(
      Builtins::CallFunction(ConvertReceiverMode::kNotNullOrUndefined));

  // 3. Call to something that is not callable.
  __ bind(&non_callable);
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
    __ Push(target);
    __ CallRuntime(Runtime::kThrowCalledNonCallable);
    __ Trap();  // Unreachable.
  }

  // 4. The function is a "classConstructor", need to raise an exception.
  __ bind(&class_constructor);
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
    __ Push(target);
    __ CallRuntime(Runtime::kThrowConstructorNonCallableError);
    __ Trap();  // Unreachable.
  }
}

// static
void Builtins::Generate_ConstructFunction(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r3 : the number of arguments
  //  -- r4 : the constructor to call (checked to be a JSFunction)
  //  -- r6 : the new target (checked to be a constructor)
  // -----------------------------------
  __ AssertConstructor(r4);
  __ AssertFunction(r4);

  // Calling convention for function specific ConstructStubs require
  // r5 to contain either an AllocationSite or undefined.
  __ LoadRoot(r5, RootIndex::kUndefinedValue);

  Label call_generic_stub;

  // Jump to JSBuiltinsConstructStub or JSConstructStubGeneric.
  __ LoadTaggedField(
      r7, FieldMemOperand(r4, JSFunction::kSharedFunctionInfoOffset), r0);
  __ lwz(r7, FieldMemOperand(r7, SharedFunctionInfo::kFlagsOffset));
  __ mov(ip, Operand(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ and_(r7, r7, ip, SetRC);
  __ beq(&call_generic_stub, cr0);

  __ TailCallBuiltin(Builtin::kJSBuiltinsConstructStub);

  __ bind(&call_generic_stub);
  __ TailCallBuiltin(Builtin::kJSConstructStubGeneric);
}

// static
void Builtins::Generate_ConstructBoundFunction(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r3 : the number of arguments
  //  -- r4 : the function to call (checked to be a JSBoundFunction)
  //  -- r6 : the new target (checked to be a constructor)
  // -----------------------------------
  __ AssertConstructor(r4);
  __ AssertBoundFunction(r4);

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Patch new.target to [[BoundTargetFunction]] if new.target equals target.
  Label skip;
  __ CompareTagged(r4, r6);
  __ bne(&skip);
  __ LoadTaggedField(
      r6, FieldMemOperand(r4, JSBoundFunction::kBoundTargetFunctionOffset), r0);
  __ bind(&skip);

  // Construct the [[BoundTargetFunction]] via the Construct builtin.
  __ LoadTaggedField(
      r4, FieldMemOperand(r4, JSBoundFunction::kBoundTargetFunctionOffset), r0);
  __ TailCallBuiltin(Builtin::kConstruct);
}

// static
void Builtins::Generate_Construct(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r3 : the number of arguments
  //  -- r4 : the constructor to call (can be any Object)
  //  -- r6 : the new target (either the same as the constructor or
  //          the JSFunction on which new was invoked initially)
  // -----------------------------------
  Register target = r4;
  Register map = r7;
  Register instance_type = r8;
  Register scratch = r9;
  DCHECK(!AreAliased(r3, target, map, instance_type, scratch));

  // Check if target is a Smi.
  Label non_constructor, non_proxy;
  __ JumpIfSmi(target, &non_constructor);

  // Check if target has a [[Construct]] internal method.
  __ LoadTaggedField(map, FieldMemOperand(target, HeapObject::kMapOffset), r0);
  {
    Register flags = r5;
    DCHECK(!AreAliased(r3, target, map, instance_type, flags));
    __ lbz(flags, FieldMemOperand(map, Map::kBitFieldOffset));
    __ TestBit(flags, Map::Bits1::IsConstructorBit::kShift, r0);
    __ beq(&non_constructor, cr0);
  }

  // Dispatch based on instance type.
  __ CompareInstanceTypeRange(map, instance_type, scratch,
                              FIRST_JS_FUNCTION_TYPE, LAST_JS_FUNCTION_TYPE);
  __ TailCallBuiltin(Builtin::kConstructFunction, le);

  // Only dispatch to bound functions after checking whether they are
  // constructors.
  __ cmpi(instance_type, Operand(JS_BOUND_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kConstructBoundFunction, eq);

  // Only dispatch to proxies after checking whether they are constructors.
  __ cmpi(instance_type, Operand(JS_PROXY_TYPE));
  __ bne(&non_proxy);
  __ TailCallBuiltin(Builtin::kConstructProxy);

  // Called Construct on an exotic Object with a [[Construct]] internal method.
  __ bind(&non_proxy);
  {
    // Overwrite the original receiver with the (original) target.
    __ StoreReceiver(target);
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

#if V8_ENABLE_WEBASSEMBLY

struct SaveWasmParamsScope {
  explicit SaveWasmParamsScope(MacroAssembler* masm) : masm(masm) {
    for (Register gp_param_reg : wasm::kGpParamRegisters) {
      gp_regs.set(gp_param_reg);
    }
    for (DoubleRegister fp_param_reg : wasm::kFpParamRegisters) {
      fp_regs.set(fp_param_reg);
    }

    CHECK_EQ(gp_regs.Count(), arraysize(wasm::kGpParamRegisters));
    CHECK_EQ(fp_regs.Count(), arraysize(wasm::kFpParamRegisters));
    CHECK_EQ(simd_regs.Count(), arraysize(wasm::kFpParamRegisters));
    CHECK_EQ(WasmLiftoffSetupFrameConstants::kNumberOfSavedGpParamRegs + 1,
             gp_regs.Count());
    CHECK_EQ(WasmLiftoffSetupFrameConstants::kNumberOfSavedFpParamRegs,
             fp_regs.Count());
    CHECK_EQ(WasmLiftoffSetupFrameConstants::kNumberOfSavedFpParamRegs,
             simd_regs.Count());

    __ MultiPush(gp_regs);
    __ MultiPushF64AndV128(fp_regs, simd_regs, ip, r0);
  }
  ~SaveWasmParamsScope() {
    __ MultiPopF64AndV128(fp_regs, simd_regs, ip, r0);
    __ MultiPop(gp_regs);
  }

  RegList gp_regs;
  DoubleRegList fp_regs;
  // List must match register numbers under kFpParamRegisters.
  Simd128RegList simd_regs = {v1, v2, v3, v4, v5, v6, v7, v8};
  MacroAssembler* masm;
};

void Builtins::Generate_WasmLiftoffFrameSetup(MacroAssembler* masm) {
  Register func_index = wasm::kLiftoffFrameSetupFunctionReg;
  Register vector = r11;
  Register scratch = ip;
  Label allocate_vector, done;

  __ LoadTaggedField(
      vector,
      FieldMemOperand(kWasmImplicitArgRegister,
                      WasmTrustedInstanceData::kFeedbackVectorsOffset),
      scratch);
  __ ShiftLeftU64(scratch, func_index, Operand(kTaggedSizeLog2));
  __ AddS64(vector, vector, scratch);
  __ LoadTaggedField(vector,
                     FieldMemOperand(vector, OFFSET_OF_DATA_START(FixedArray)),
                     scratch);
  __ JumpIfSmi(vector, &allocate_vector);
  __ bind(&done);
  __ push(kWasmImplicitArgRegister);
  __ push(vector);
  __ Ret();

  __ bind(&allocate_vector);

  // Feedback vector doesn't exist yet. Call the runtime to allocate it.
  // We temporarily change the frame type for this, because we need special
  // handling by the stack walker in case of GC.
  __ mov(scratch,
         Operand(StackFrame::TypeToMarker(StackFrame::WASM_LIFTOFF_SETUP)));
  __ StoreU64(scratch, MemOperand(sp));

  // Save current return address as it will get clobbered during CallRuntime.
  __ mflr(scratch);
  __ push(scratch);
  {
    SaveWasmParamsScope save_params(masm);  // Will use r0 and ip as scratch.
    // Arguments to the runtime function: instance data, func_index.
    __ push(kWasmImplicitArgRegister);
    __ SmiTag(func_index);
    __ push(func_index);
    // Allocate a stack slot where the runtime function can spill a pointer
    // to the {NativeModule}.
    __ push(r11);
    __ LoadSmiLiteral(cp, Smi::zero());
    __ CallRuntime(Runtime::kWasmAllocateFeedbackVector, 3);
    __ mr(vector, kReturnRegister0);
    // Saved parameters are restored at the end of this block.
  }
  __ pop(scratch);
  __ mtlr(scratch);

  __ mov(scratch, Operand(StackFrame::TypeToMarker(StackFrame::WASM)));
  __ StoreU64(scratch, MemOperand(sp));
  __ b(&done);
}

void Builtins::Generate_WasmCompileLazy(MacroAssembler* masm) {
  // The function index was put in a register by the jump table trampoline.
  // Convert to Smi for the runtime call.
  __ SmiTag(kWasmCompileLazyFuncIndexRegister);

  {
    HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
    FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);

    {
      SaveWasmParamsScope save_params(masm);  // Will use r0 and ip as scratch.

      // Push the instance data as an explicit argument to the runtime function.
      __ push(kWasmImplicitArgRegister);
      // Push the function index as second argument.
      __ push(kWasmCompileLazyFuncIndexRegister);
      // Initialize the JavaScript context with 0. CEntry will use it to
      // set the current context on the isolate.
      __ LoadSmiLiteral(cp, Smi::zero());
      __ CallRuntime(Runtime::kWasmCompileLazy, 2);
      // The runtime function returns the jump table slot offset as a Smi. Use
      // that to compute the jump target in r11.
      __ SmiUntag(kReturnRegister0);
      __ mr(r11, kReturnRegister0);

      // Saved parameters are restored at the end of this block.
    }

    // After the instance data register has been restored, we can add the jump
    // table start to the jump table offset already stored in r11.
    __ LoadU64(ip,
               FieldMemOperand(kWasmImplicitArgRegister,
                               WasmTrustedInstanceData::kJumpTableStartOffset),
               r0);
    __ AddS64(r11, r11, ip);
  }

  // Finally, jump to the jump table slot for the function.
  __ Jump(r11);
}

void Builtins::Generate_WasmDebugBreak(MacroAssembler* masm) {
  HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::WASM_DEBUG_BREAK);

    // Save all parameter registers. They might hold live values, we restore
    // them after the runtime call.
    __ MultiPush(WasmDebugBreakFrameConstants::kPushedGpRegs);
    __ MultiPushF64AndV128(WasmDebugBreakFrameConstants::kPushedFpRegs,
                           WasmDebugBreakFrameConstants::kPushedSimd128Regs, ip,
                           r0);

    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ LoadSmiLiteral(cp, Smi::zero());
    __ CallRuntime(Runtime::kWasmDebugBreak, 0);

    // Restore registers.
    __ MultiPopF64AndV128(WasmDebugBreakFrameConstants::kPushedFpRegs,
                          WasmDebugBreakFrameConstants::kPushedSimd128Regs, ip,
                          r0);
    __ MultiPop(WasmDebugBreakFrameConstants::kPushedGpRegs);
  }
  __ Ret();
}

void Builtins::Generate_WasmReturnPromiseOnSuspendAsm(MacroAssembler* masm) {
  __ Trap();
}

void Builtins::Generate_JSToWasmStressSwitchStacksAsm(MacroAssembler* masm) {
  __ Trap();
}

// Loads the context field of the WasmTrustedInstanceData or WasmImportData
// depending on the data's type, and places the result in the input register.
void GetContextFromImplicitArg(MacroAssembler* masm, Register data,
                               Register scratch) {
  __ LoadTaggedField(scratch, FieldMemOperand(data, HeapObject::kMapOffset),
                     r0);
  __ CompareInstanceType(scratch, scratch, WASM_TRUSTED_INSTANCE_DATA_TYPE);
  Label instance;
  Label end;
  __ beq(&instance);
  __ LoadTaggedField(
      data, FieldMemOperand(data, WasmImportData::kNativeContextOffset), r0);
  __ jmp(&end);
  __ bind(&instance);
  __ LoadTaggedField(
      data,
      FieldMemOperand(data, WasmTrustedInstanceData::kNativeContextOffset), r0);
  __ bind(&end);
}

void Builtins::Generate_WasmToJsWrapperAsm(MacroAssembler* masm) {
  // Push registers in reverse order so that they are on the stack like
  // in an array, with the first item being at the lowest address.
  DoubleRegList fp_regs;
  for (DoubleRegister fp_param_reg : wasm::kFpParamRegisters) {
    fp_regs.set(fp_param_reg);
  }
  __ MultiPushDoubles(fp_regs);

  // Push the GP registers in reverse order so that they are on the stack like
  // in an array, with the first item being at the lowest address.
  RegList gp_regs;
  for (size_t i = arraysize(wasm::kGpParamRegisters) - 1; i > 0; --i) {
    gp_regs.set(wasm::kGpParamRegisters[i]);
  }
  __ MultiPush(gp_regs);
  // Reserve a slot for the signature.
  __ Push(r3);
  __ TailCallBuiltin(Builtin::kWasmToJsWrapperCSA);
}

void Builtins::Generate_WasmTrapHandlerLandingPad(MacroAssembler* masm) {
  __ Trap();
}

void Builtins::Generate_WasmSuspend(MacroAssembler* masm) {
  // TODO(v8:12191): Implement for this platform.
  __ Trap();
}

void Builtins::Generate_WasmResume(MacroAssembler* masm) {
  // TODO(v8:12191): Implement for this platform.
  __ Trap();
}

void Builtins::Generate_WasmReject(MacroAssembler* masm) {
  // TODO(v8:12191): Implement for this platform.
  __ Trap();
}

void Builtins::Generate_WasmOnStackReplace(MacroAssembler* masm) {
  // Only needed on x64.
  __ Trap();
}

void ResetStackSwitchFrameStackSlots(MacroAssembler* masm) {
  Register zero = r3;
  __ Move(zero, Smi::zero());
  __ StoreU64(zero,
              MemOperand(fp, StackSwitchFrameConstants::kResultArrayOffset));
  __ StoreU64(zero,
              MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
}

void Builtins::Generate_JSToWasmWrapperAsm(MacroAssembler* masm) {
  __ EnterFrame(StackFrame::JS_TO_WASM);

  constexpr int kNumSpillSlots = StackSwitchFrameConstants::kNumSpillSlots;
  __ AllocateStackSpace(kNumSpillSlots * kSystemPointerSize);
  ResetStackSwitchFrameStackSlots(masm);

  Register wrapper_buffer =
      WasmJSToWasmWrapperDescriptor::WrapperBufferRegister();
  // Push the wrapper_buffer stack, it's needed later for the results.
  __ StoreU64(
      wrapper_buffer,
      MemOperand(fp, JSToWasmWrapperFrameConstants::kWrapperBufferOffset));

  Register result_size = r3;
  __ LoadU64(
      result_size,
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferStackReturnBufferSize),
      r0);
  __ ShiftLeftU64(r0, result_size, Operand(kSystemPointerSizeLog2));
  __ SubS64(sp, sp, r0);

  __ StoreU64(
      sp,
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferStackReturnBufferStart));
  // Push stack parameters on the stack.
  Register params_end = r4;
  __ LoadU64(params_end,
             MemOperand(wrapper_buffer,
                        JSToWasmWrapperFrameConstants::kWrapperBufferParamEnd),
             r0);

  Register params_start = ip;
  __ LoadU64(
      params_start,
      MemOperand(wrapper_buffer,
                 JSToWasmWrapperFrameConstants::kWrapperBufferParamStart),
      r0);

  // The first GP parameter holds the trusted instance data or the import data.
  // This is handled specially.
  int stack_params_offset =
      (arraysize(wasm::kGpParamRegisters) - 1) * kSystemPointerSize +
      arraysize(wasm::kFpParamRegisters) * kDoubleSize;
  Register last_stack_param = r3;
  __ AddS64(last_stack_param, params_start, Operand(stack_params_offset));

  Label loop_start;
  __ bind(&loop_start);

  Label finish_stack_params;
  __ CmpS64(last_stack_param, params_end);
  __ bge(&finish_stack_params);

  // Push parameter
  {
    // TODO(miladfarca): Use a different register for scratch.
    __ AddS64(params_end, params_end, Operand(-kSystemPointerSize));
    __ LoadU64(r0, MemOperand(params_end), r0);
    __ push(r0);
  }

  __ jmp(&loop_start);

  __ bind(&finish_stack_params);

  size_t next_offset = 0;
  for (size_t i = 1; i < arraysize(wasm::kGpParamRegisters); ++i) {
    // Check that {params_start} does not overlap with any of the parameter
    // registers, so that we don't overwrite it by accident with the loads
    // below.
    DCHECK_NE(params_start, wasm::kGpParamRegisters[i]);
    __ LoadU64(wasm::kGpParamRegisters[i],
               MemOperand(params_start, next_offset), r0);
    next_offset += kSystemPointerSize;
  }

  for (size_t i = 0; i < arraysize(wasm::kFpParamRegisters); ++i) {
    __ LoadF64(wasm::kFpParamRegisters[i],
               MemOperand(params_start, next_offset), r0);
    next_offset += kDoubleSize;
  }
  DCHECK_EQ(next_offset, stack_params_offset);

  // Load the instance data (implicit arg) into r6.
  __ LoadU64(kWasmImplicitArgRegister,
             MemOperand(fp, JSToWasmWrapperFrameConstants::kImplicitArgOffset),
             r0);

  {
    Register thread_in_wasm_flag_addr = r4;
    __ LoadU64(thread_in_wasm_flag_addr,
               MemOperand(kRootRegister,
                          Isolate::thread_in_wasm_flag_address_offset()),
               r0);
    __ mov(r0, Operand(1));
    __ StoreU32(r0, MemOperand(thread_in_wasm_flag_addr, 0), no_reg);
  }

  Register function_entry = r4;
  __ LoadU64(
      function_entry,
      MemOperand(wrapper_buffer,
                 JSToWasmWrapperFrameConstants::kWrapperBufferCallTarget),
      r0);
  __ Call(function_entry);
  {
    Register thread_in_wasm_flag_addr = r7;
    __ LoadU64(thread_in_wasm_flag_addr,
               MemOperand(kRootRegister,
                          Isolate::thread_in_wasm_flag_address_offset()),
               r0);
    __ mov(r0, Operand(0));
    __ StoreU32(r0, MemOperand(thread_in_wasm_flag_addr, 0), no_reg);
  }

  // `wrapper_buffer` is a parameter for `JSToWasmHandleReturns`, it therefore
  // has to be in r5.
  wrapper_buffer = r5;
  __ LoadU64(
      wrapper_buffer,
      MemOperand(fp, JSToWasmWrapperFrameConstants::kWrapperBufferOffset), r0);

  __ StoreF64(
      wasm::kFpReturnRegisters[0],
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferFPReturnRegister1));
  __ StoreF64(
      wasm::kFpReturnRegisters[1],
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferFPReturnRegister2));
  __ StoreU64(
      wasm::kGpReturnRegisters[0],
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister1));
  __ StoreU64(
      wasm::kGpReturnRegisters[1],
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister2));

  // r3: wasm instance.
  // r4: the result JSArray for multi-return.
  // r5: pointer to the byte buffer which contains all parameters.
  __ LoadU64(
      r4,
      MemOperand(fp, JSToWasmWrapperFrameConstants::kResultArrayParamOffset),
      r0);
  __ LoadU64(r3,
             MemOperand(fp, JSToWasmWrapperFrameConstants::kImplicitArgOffset),
             r0);
  Register scratch = r6;
  GetContextFromImplicitArg(masm, r3, scratch);

  __ CallBuiltin(Builtin::kJSToWasmHandleReturns);

  __ LeaveFrame(StackFrame::JS_TO_WASM);
  __ AddS64(sp, sp, Operand(2 * kSystemPointerSize));
  __ blr();
}

#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_CEntry(MacroAssembler* masm, int result_size,
                               ArgvMode argv_mode, bool builtin_exit_frame,
                               bool switch_to_central_stack) {
  // Called from JavaScript; parameters are on stack as if calling JS function.
  // r3: number of arguments including receiver
  // r4: pointer to builtin function
  // fp: frame pointer  (restored after C call)
  // sp: stack pointer  (restored as callee's sp after C call)
  // cp: current context  (C callee-saved)
  //
  // If argv_mode == ArgvMode::kRegister:
  // r5: pointer to the first argument

  using ER = ExternalReference;

  // Move input arguments to more convenient registers.
  static constexpr Register argc_input = r3;
  static constexpr Register target_fun = r15;  // C callee-saved
  static constexpr Register argv = r4;
  static constexpr Register scratch = ip;
  static constexpr Register argc_sav = r14;  // C callee-saved

  __ mr(target_fun, argv);

  if (argv_mode == ArgvMode::kRegister) {
    // Move argv into the correct register.
    __ mr(argv, r5);
  } else {
    // Compute the argv pointer.
    __ ShiftLeftU64(argv, argc_input, Operand(kSystemPointerSizeLog2));
    __ add(argv, argv, sp);
    __ subi(argv, argv, Operand(kSystemPointerSize));
  }

  // Enter the exit frame that transitions from JavaScript to C++.
  FrameScope scope(masm, StackFrame::MANUAL);

  int arg_stack_space = 0;

  // Pass buffer for return value on stack if necessary
  bool needs_return_buffer =
      (result_size == 2 && !ABI_RETURNS_OBJECT_PAIRS_IN_REGS);
  if (needs_return_buffer) {
    arg_stack_space += result_size;
  }

  __ EnterExitFrame(
      scratch, arg_stack_space,
      builtin_exit_frame ? StackFrame::BUILTIN_EXIT : StackFrame::EXIT);

  // Store a copy of argc in callee-saved registers for later.
  __ mr(argc_sav, argc_input);

  // r3: number of arguments including receiver
  // r14: number of arguments including receiver (C callee-saved)
  // r4: pointer to the first argument
  // r15: pointer to builtin function  (C callee-saved)

  // Result returned in registers or stack, depending on result size and ABI.

  Register isolate_reg = r5;
  if (needs_return_buffer) {
    // The return value is a non-scalar value.
    // Use frame storage reserved by calling function to pass return
    // buffer as implicit first argument.
    __ mr(r5, r4);
    __ mr(r4, r3);
    __ addi(r3, sp,
            Operand((kStackFrameExtraParamSlot + 1) * kSystemPointerSize));
    isolate_reg = r6;
  }

  // Call C built-in.
  __ Move(isolate_reg, ER::isolate_address());
  __ StoreReturnAddressAndCall(target_fun);

  // If return value is on the stack, pop it to registers.
  if (needs_return_buffer) {
    __ LoadU64(r4, MemOperand(r3, kSystemPointerSize));
    __ LoadU64(r3, MemOperand(r3));
  }

  // Check result for exception sentinel.
  Label exception_returned;
  __ CompareRoot(r3, RootIndex::kException);
  __ beq(&exception_returned);

  // Check that there is no exception, otherwise we
  // should have returned the exception sentinel.
  if (v8_flags.debug_code) {
    Label okay;
    ER exception_address =
        ER::Create(IsolateAddressId::kExceptionAddress, masm->isolate());
    __ LoadU64(scratch,
               __ ExternalReferenceAsOperand(exception_address, no_reg));
    __ LoadRoot(r0, RootIndex::kTheHoleValue);
    __ CompareTagged(r0, scratch);
    // Cannot use check here as it attempts to generate call into runtime.
    __ beq(&okay);
    __ stop();
    __ bind(&okay);
  }

  // Exit C frame and return.
  // r3:r4: result
  // sp: stack pointer
  // fp: frame pointer
  // r14: still holds argc (C caller-saved).
  __ LeaveExitFrame(scratch);
  if (argv_mode == ArgvMode::kStack) {
    DCHECK(!AreAliased(scratch, argc_sav));
    __ ShiftLeftU64(scratch, argc_sav, Operand(kSystemPointerSizeLog2));
    __ AddS64(sp, sp, scratch);
  }

  __ blr();

  // Handling of exception.
  __ bind(&exception_returned);

  ER pending_handler_context_address = ER::Create(
      IsolateAddressId::kPendingHandlerContextAddress, masm->isolate());
  ER pending_handler_entrypoint_address = ER::Create(
      IsolateAddressId::kPendingHandlerEntrypointAddress, masm->isolate());
  ER pending_handler_constant_pool_address = ER::Create(
      IsolateAddressId::kPendingHandlerConstantPoolAddress, masm->isolate());
  ER pending_handler_fp_address =
      ER::Create(IsolateAddressId::kPendingHandlerFPAddress, masm->isolate());
  ER pending_handler_sp_address =
      ER::Create(IsolateAddressId::kPendingHandlerSPAddress, masm->isolate());

  // Ask the runtime for help to determine the handler. This will set r3 to
  // contain the current exception, don't clobber it.
  {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ PrepareCallCFunction(3, 0, r3);
    __ li(kCArgRegs[0], Operand::Zero());
    __ li(kCArgRegs[1], Operand::Zero());
    __ Move(kCArgRegs[2], ER::isolate_address());
    __ CallCFunction(ER::Create(Runtime::kUnwindAndFindExceptionHandler), 3,
                     SetIsolateDataSlots::kNo);
  }

  // Retrieve the handler context, SP and FP.
  __ Move(cp, pending_handler_context_address);
  __ LoadU64(cp, MemOperand(cp));
  __ Move(sp, pending_handler_sp_address);
  __ LoadU64(sp, MemOperand(sp));
  __ Move(fp, pending_handler_fp_address);
  __ LoadU64(fp, MemOperand(fp));

  // If the handler is a JS frame, restore the context to the frame. Note that
  // the context will be set to (cp == 0) for non-JS frames.
  Label skip;
  __ cmpi(cp, Operand::Zero());
  __ beq(&skip);
  __ StoreU64(cp, MemOperand(fp, StandardFrameConstants::kContextOffset));
  __ bind(&skip);

  // Clear c_entry_fp, like we do in `LeaveExitFrame`.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, masm->isolate());
  __ mov(scratch, Operand::Zero());
  __ StoreU64(scratch,
              __ ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  // Compute the handler entry address and jump to it.
  ConstantPoolUnavailableScope constant_pool_unavailable(masm);
  __ LoadU64(
      scratch,
      __ ExternalReferenceAsOperand(pending_handler_entrypoint_address, no_reg),
      r0);
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    __ Move(kConstantPoolRegister, pending_handler_constant_pool_address);
    __ LoadU64(kConstantPoolRegister, MemOperand(kConstantPoolRegister));
  }
  __ Jump(scratch);
}

#if V8_ENABLE_WEBASSEMBLY
void Builtins::Generate_WasmHandleStackOverflow(MacroAssembler* masm) {
  __ Trap();
}
#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_DoubleToI(MacroAssembler* masm) {
  Label out_of_range, only_low, negate, done, fastpath_done;
  Register result_reg = r3;

  HardAbortScope hard_abort(masm);  // Avoid calls to Abort.

  // Immediate values for this stub fit in instructions, so it's safe to use ip.
  Register scratch = GetRegisterThatIsNotOneOf(result_reg);
  Register scratch_low = GetRegisterThatIsNotOneOf(result_reg, scratch);
  Register scratch_high =
      GetRegisterThatIsNotOneOf(result_reg, scratch, scratch_low);
  DoubleRegister double_scratch = kScratchDoubleReg;

  __ Push(result_reg, scratch);
  // Account for saved regs.
  int argument_offset = 2 * kSystemPointerSize;

  // Load double input.
  __ lfd(double_scratch, MemOperand(sp, argument_offset));

  // Do fast-path convert from double to int.
  __ ConvertDoubleToInt64(double_scratch,
                          result_reg, d0);

// Test for overflow
  __ TestIfInt32(result_reg, r0);
  __ beq(&fastpath_done);

  __ Push(scratch_high, scratch_low);
  // Account for saved regs.
  argument_offset += 2 * kSystemPointerSize;

  __ lwz(scratch_high,
         MemOperand(sp, argument_offset + Register::kExponentOffset));
  __ lwz(scratch_low,
         MemOperand(sp, argument_offset + Register::kMantissaOffset));

  __ ExtractBitMask(scratch, scratch_high, HeapNumber::kExponentMask);
  // Load scratch with exponent - 1. This is faster than loading
  // with exponent because Bias + 1 = 1024 which is a *PPC* immediate value.
  static_assert(HeapNumber::kExponentBias + 1 == 1024);
  __ subi(scratch, scratch, Operand(HeapNumber::kExponentBias + 1));
  // If exponent is greater than or equal to 84, the 32 less significant
  // bits are 0s (2^84 = 1, 52 significant
"""


```