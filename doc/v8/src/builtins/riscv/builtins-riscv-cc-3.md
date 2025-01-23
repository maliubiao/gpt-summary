Response:
The user wants me to analyze the provided RISC-V assembly code from a V8 source file.
I need to:
1. **List the functionalities** of the code.
2. **Determine if it's a Torque file** based on the `.tq` extension (it's not).
3. **If related to JavaScript, provide JavaScript examples.**
4. **Provide code logic reasoning with hypothetical input and output.**
5. **Point out common programming errors this code might help prevent or handle.**
6. **Summarize the overall function of this specific code snippet.**

Based on the code, it seems to handle various aspects of function calls and execution within the V8 engine on the RISC-V architecture. This includes:

- **Calling functions:** Handling different types of calls (regular, bound, class constructors, proxies).
- **Constructing objects:** Managing object creation with different constructor types.
- **WebAssembly integration:** Setting up WebAssembly call frames, handling lazy compilation, and dealing with traps.
- **Exception handling:** Managing exceptions thrown from C++ code.
- **Stack management:** Potentially dealing with stack overflow checks and switching between different stacks (central stack for WebAssembly).
- **Type checking and dispatch:** Identifying function types and dispatching to appropriate built-in functions.
- **Double to integer conversion:**  Converting double-precision floating-point numbers to integers.

Let's break down each point with more detail and examples where applicable.
这是 `v8/src/builtins/riscv/builtins-riscv.cc` 文件的第 4 部分，它包含了一些用于在 RISC-V 架构上执行 JavaScript 代码的内置函数的实现。以下是根据提供的代码片段归纳的功能：

1. **调用绑定函数 (`Generate_CallBoundFunctionImpl`)**:
    *   该函数负责调用 `JSBoundFunction` 类型的函数。
    *   它会从绑定函数对象中获取绑定的 `this` 值，并将其设置为接收者。
    *   它会将绑定参数压入栈中。
    *   最后，它会调用绑定的目标函数。

    ```javascript
    function originalFunction(a, b) {
      console.log(this, a, b);
    }

    const boundObject = { value: 'bound' };
    const boundFunction = originalFunction.bind(boundObject, 1);
    boundFunction(2); // 输出: { value: 'bound' }, 1, 2
    ```
    当调用 `boundFunction` 时，`Generate_CallBoundFunctionImpl` 确保 `boundObject` 成为 `this`，并且参数 `1` 被预先添加到参数列表中。

2. **调用函数 (`Generate_Call`)**:
    *   这是一个通用的函数调用入口点，处理不同类型的可调用对象。
    *   它检查目标是否为 `Smi` (小整数)，如果不是，则加载其 `Map` 和实例类型。
    *   它会根据实例类型分发到不同的内置函数，例如 `CallFunction` (用于普通的 JS 函数), `CallBoundFunction`, `CallProxy`, `CallWrappedFunction`。
    *   它还处理调用类构造器时的错误情况。
    *   如果目标不是可调用对象，则抛出异常。

    ```javascript
    function myFunction(a) {
      console.log(a);
    }

    myFunction(5); // 会通过 `Generate_Call` 和 `CallFunction` 调用

    const notCallable = {};
    // notCallable(); // 会在 `Generate_Call` 中抛出 "TypeError: notCallable is not a function"
    ```

3. **构造函数 (`Generate_ConstructFunction`)**:
    *   用于构造 `JSFunction` 类型的对象。
    *   它会根据函数的 `SharedFunctionInfo` 中的标志位，跳转到 `JSBuiltinsConstructStub` (用于内置函数) 或 `JSConstructStubGeneric` (用于普通函数)。

    ```javascript
    function MyClass(value) {
      this.value = value;
    }

    const instance = new MyClass(10); // 会通过 `Generate_ConstructFunction` 创建实例
    ```

4. **构造绑定函数 (`Generate_ConstructBoundFunction`)**:
    *   用于通过 `new` 关键字构造 `JSBoundFunction` 类型的对象。
    *   它会将绑定参数压入栈中。
    *   如果 `new.target` 与绑定函数相同，则会将 `new.target` 替换为绑定的目标函数。
    *   最后，它会调用绑定的目标函数进行构造。

    ```javascript
    function OriginalConstructor(a, b) {
      this.a = a;
      this.b = b;
    }

    const BoundConstructor = OriginalConstructor.bind(null, 1);
    const instance = new BoundConstructor(2); // 会通过 `Generate_ConstructBoundFunction` 创建实例
    console.log(instance.a, instance.b); // 输出: 1, 2
    ```

5. **构造对象 (`Generate_Construct`)**:
    *   这是一个通用的对象构造入口点，处理不同类型的构造器。
    *   它检查目标是否为 `Smi`，如果不是，则加载其 `Map` 和实例类型。
    *   它根据实例类型分发到不同的内置函数，例如 `ConstructFunction`, `ConstructBoundFunction`, `ConstructProxy`。
    *   如果尝试构造非构造器对象，则抛出异常。

    ```javascript
    class MyClass {}
    const instance = new MyClass(); // 会通过 `Generate_Construct` 和 `ConstructFunction` 创建实例

    const notAConstructor = {};
    // new notAConstructor(); // 会在 `Generate_Construct` 中抛出 "TypeError: notAConstructor is not a constructor"
    ```

6. **WebAssembly 相关功能 (如果 `V8_ENABLE_WEBASSEMBLY` 为真)**:
    *   **`Generate_WasmLiftoffFrameSetup`**:  在 WebAssembly Liftoff 代码执行前设置栈帧，包括分配和推送反馈向量。
    *   **`Generate_WasmCompileLazy`**:  处理 WebAssembly 函数的延迟编译。当首次调用尚未编译的 WebAssembly 函数时，会调用此函数进行编译。
    *   **`Generate_WasmDebugBreak`**:  处理 WebAssembly 代码中的断点。
    *   **`Generate_WasmHandleStackOverflow`**:  处理 WebAssembly 代码中的栈溢出错误。
    *   **`Generate_WasmToJsWrapperAsm`**:  作为从 WebAssembly 调用 JavaScript 的包装器，负责调整栈并调用 `WasmToJsWrapperCSA`。
    *   **`Generate_WasmTrapHandlerLandingPad`**:  当 WebAssembly 代码发生陷阱（如内存越界访问）时，作为着陆点，模拟从触发指令到运行时系统的调用。

7. **C 函数入口 (`Generate_CEntry`)**:
    *   这是一个关键的内置函数，用于从 JavaScript 代码调用 C++ 函数。
    *   它设置了调用 C++ 函数所需的栈帧和参数。
    *   它处理了参数的传递（通过寄存器或栈）。
    *   它还处理了从 C++ 函数返回后的结果和异常情况。
    *   包含了在 WebAssembly 环境中切换到中心栈的逻辑。

    ```javascript
    // 假设有一个 C++ 函数可以通过 V8 的绑定机制暴露给 JavaScript
    // 并且它的实现会通过 `Generate_CEntry` 被调用
    // 例如:
    // %DebugPrint(someNativeFunction); // 可以看到它会调用 CEntry
    ```

8. **双精度浮点数转整数 (`Generate_DoubleToI`)**:
    *   将双精度浮点数转换为 32 位有符号整数。
    *   它处理了各种情况，包括 NaN、Infinity 和超出整数范围的值。

    ```javascript
    const floatValue = 123.456;
    const intValue = Math.trunc(floatValue); // 在底层可能会使用类似的转换逻辑
    ```

9. **栈状态切换相关 (`SwitchSimulatorStackLimit`, `SwitchToTheCentralStackIfNeeded`, `SwitchFromTheCentralStackIfNeeded`, `SwitchStackState`, `SwitchStackPointerAndSimulatorStackLimit`)**:
    *   这些函数主要用于管理不同栈状态之间的切换，尤其是在 WebAssembly 环境中。
    *   `SwitchToTheCentralStackIfNeeded` 和 `SwitchFromTheCentralStackIfNeeded` 负责在需要时切换到和从中心栈切换。
    *   `SwitchSimulatorStackLimit` 用于在模拟器环境下设置栈限制。

**常见的编程错误**:

*   **尝试调用不可调用的对象**:  `Generate_Call` 负责捕获并抛出 `TypeError: xxx is not a function` 类似的错误。
    ```javascript
    const notAFunction = {};
    // notAFunction(); // 抛出 TypeError
    ```
*   **尝试 `new` 一个非构造器**: `Generate_Construct` 负责捕获并抛出 `TypeError: xxx is not a constructor` 类似的错误。
    ```javascript
    const notAConstructor = {};
    // new notAConstructor(); // 抛出 TypeError
    ```
*   **WebAssembly 内存越界访问或空指针解引用**: `Generate_WasmTrapHandlerLandingPad` 用于处理这些运行时错误。

**总结**:

`v8/src/builtins/riscv/builtins-riscv.cc` 的这一部分定义了在 RISC-V 架构上执行 JavaScript 代码的核心内置函数。它涵盖了函数调用、对象构造、WebAssembly 集成、异常处理以及底层的栈管理和类型检查等关键功能。这些内置函数是 V8 引擎将 JavaScript 代码转换为可在 RISC-V 处理器上执行的机器码的关键组成部分。它们提供了执行 JavaScript 语义所需的底层操作和错误处理机制。
### 提示词
```
这是目录为v8/src/builtins/riscv/builtins-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/riscv/builtins-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
a1, no_reg, a2, a0, InvokeType::kJump);
}

namespace {

void Generate_PushBoundArguments(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- a0 : the number of arguments
  //  -- a1 : target (checked to be a JSBoundFunction)
  //  -- a3 : new.target (only in case of [[Construct]])
  // -----------------------------------
  UseScratchRegisterScope temps(masm);
  temps.Include(t0, t1);
  Register bound_argc = a4;
  Register bound_argv = a2;
  // Load [[BoundArguments]] into a2 and length of that into a4.
  Label no_bound_arguments;
  __ LoadTaggedField(
      bound_argv, FieldMemOperand(a1, JSBoundFunction::kBoundArgumentsOffset));
  __ SmiUntagField(bound_argc,
                   FieldMemOperand(bound_argv, offsetof(FixedArray, length_)));
  __ Branch(&no_bound_arguments, eq, bound_argc, Operand(zero_reg));
  {
    // ----------- S t a t e -------------
    //  -- a0 : the number of arguments
    //  -- a1 : target (checked to be a JSBoundFunction)
    //  -- a2 : the [[BoundArguments]] (implemented as FixedArray)
    //  -- a3 : new.target (only in case of [[Construct]])
    //  -- a4: the number of [[BoundArguments]]
    // -----------------------------------
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    Label done;
    // Reserve stack space for the [[BoundArguments]].
    {
      // Check the stack for overflow. We are not trying to catch interruptions
      // (i.e. debug break and preemption) here, so check the "real stack
      // limit".
      __ StackOverflowCheck(a4, temps.Acquire(), temps.Acquire(), nullptr,
                            &done);
      {
        FrameScope scope(masm, StackFrame::MANUAL);
        __ EnterFrame(StackFrame::INTERNAL);
        __ CallRuntime(Runtime::kThrowStackOverflow);
      }
      __ bind(&done);
    }

    // Pop receiver.
    __ Pop(scratch);

    // Push [[BoundArguments]].
    {
      Label loop, done_loop;
      __ SmiUntag(a4, FieldMemOperand(a2, offsetof(FixedArray, length_)));
      __ AddWord(a0, a0, Operand(a4));
      __ AddWord(a2, a2,
                 Operand(OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag));
      __ bind(&loop);
      __ SubWord(a4, a4, Operand(1));
      __ Branch(&done_loop, lt, a4, Operand(zero_reg), Label::Distance::kNear);
      __ CalcScaledAddress(a5, a2, a4, kTaggedSizeLog2);
      __ LoadTaggedField(kScratchReg, MemOperand(a5));
      __ Push(kScratchReg);
      __ Branch(&loop);
      __ bind(&done_loop);
    }

    // Push receiver.
    __ Push(scratch);
  }
  __ bind(&no_bound_arguments);
}

}  // namespace

// static
void Builtins::Generate_CallBoundFunctionImpl(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- a0 : the number of arguments
  //  -- a1 : the function to call (checked to be a JSBoundFunction)
  // -----------------------------------
  __ AssertBoundFunction(a1);

  // Patch the receiver to [[BoundThis]].
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ LoadTaggedField(scratch,
                       FieldMemOperand(a1, JSBoundFunction::kBoundThisOffset));
    __ StoreReceiver(scratch);
  }

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Call the [[BoundTargetFunction]] via the Call builtin.
  __ LoadTaggedField(
      a1, FieldMemOperand(a1, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtins::Call());
}

// static
void Builtins::Generate_Call(MacroAssembler* masm, ConvertReceiverMode mode) {
  // ----------- S t a t e -------------
  //  -- a0 : the number of arguments
  //  -- a1 : the target to call (can be any Object).
  // -----------------------------------

  Register target = a1;
  Register map = t1;
  Register instance_type = t2;
  Register scratch = t6;
  DCHECK(!AreAliased(a0, target, map, instance_type, scratch));

  Label non_callable, class_constructor;
  __ JumpIfSmi(target, &non_callable);
  __ LoadMap(map, target);
  __ GetInstanceTypeRange(map, instance_type, FIRST_CALLABLE_JS_FUNCTION_TYPE,
                          scratch);
  __ TailCallBuiltin(Builtins::CallFunction(mode), ule, scratch,
                     Operand(LAST_CALLABLE_JS_FUNCTION_TYPE -
                             FIRST_CALLABLE_JS_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kCallBoundFunction, eq, instance_type,
                     Operand(JS_BOUND_FUNCTION_TYPE));

  // Check if target has a [[Call]] internal method.
  {
    Register flags = t1;
    __ Lbu(flags, FieldMemOperand(map, Map::kBitFieldOffset));
    map = no_reg;
    __ And(flags, flags, Operand(Map::Bits1::IsCallableBit::kMask));
    __ Branch(&non_callable, eq, flags, Operand(zero_reg));
  }

  __ TailCallBuiltin(Builtin::kCallProxy, eq, instance_type,
                     Operand(JS_PROXY_TYPE));

  // Check if target is a wrapped function and call CallWrappedFunction external
  // builtin
  __ TailCallBuiltin(Builtin::kCallWrappedFunction, eq, instance_type,
                     Operand(JS_WRAPPED_FUNCTION_TYPE));

  // ES6 section 9.2.1 [[Call]] ( thisArgument, argumentsList)
  // Check that the function is not a "classConstructor".
  __ Branch(&class_constructor, eq, instance_type,
            Operand(JS_CLASS_CONSTRUCTOR_TYPE));

  // 2. Call to something else, which might have a [[Call]] internal method (if
  // not we raise an exception).
  // Overwrite the original receiver with the (original) target.
  __ StoreReceiver(target);
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
  }

  // 4. The function is a "classConstructor", need to raise an exception.
  __ bind(&class_constructor);
  {
    FrameScope frame(masm, StackFrame::INTERNAL);
    __ Push(target);
    __ CallRuntime(Runtime::kThrowConstructorNonCallableError);
  }
}

void Builtins::Generate_ConstructFunction(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- a0 : the number of arguments
  //  -- a1 : the constructor to call (checked to be a JSFunction)
  //  -- a3 : the new target (checked to be a constructor)
  // -----------------------------------
  __ AssertConstructor(a1);
  __ AssertFunction(a1);

  // Calling convention for function specific ConstructStubs require
  // a2 to contain either an AllocationSite or undefined.
  __ LoadRoot(a2, RootIndex::kUndefinedValue);

  Label call_generic_stub;

  // Jump to JSBuiltinsConstructStub or JSConstructStubGeneric.
  __ LoadTaggedField(
      a4, FieldMemOperand(a1, JSFunction::kSharedFunctionInfoOffset));
  __ Load32U(a4, FieldMemOperand(a4, SharedFunctionInfo::kFlagsOffset));
  __ And(a4, a4, Operand(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ Branch(&call_generic_stub, eq, a4, Operand(zero_reg),
            Label::Distance::kNear);

  __ TailCallBuiltin(Builtin::kJSBuiltinsConstructStub);

  __ bind(&call_generic_stub);
  __ TailCallBuiltin(Builtin::kJSConstructStubGeneric);
}

// static
void Builtins::Generate_ConstructBoundFunction(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- a0 : the number of arguments
  //  -- a1 : the function to call (checked to be a JSBoundFunction)
  //  -- a3 : the new target (checked to be a constructor)
  // -----------------------------------
  __ AssertBoundFunction(a1);

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Patch new.target to [[BoundTargetFunction]] if new.target equals target.
  Label skip;
  __ CompareTaggedAndBranch(&skip, ne, a1, Operand(a3));
  __ LoadTaggedField(
      a3, FieldMemOperand(a1, JSBoundFunction::kBoundTargetFunctionOffset));
  __ bind(&skip);

  // Construct the [[BoundTargetFunction]] via the Construct builtin.
  __ LoadTaggedField(
      a1, FieldMemOperand(a1, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtin::kConstruct);
}

void Builtins::Generate_Construct(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- a0 : the number of arguments
  //  -- a1 : the constructor to call (can be any Object)
  //  -- a3 : the new target (either the same as the constructor or
  //          the JSFunction on which new was invoked initially)
  // -----------------------------------

  Register target = a1;
  Register map = t1;
  Register instance_type = t2;
  Register scratch = t6;
  DCHECK(!AreAliased(a0, target, map, instance_type, scratch));

  // Check if target is a Smi.
  Label non_constructor, non_proxy;
  __ JumpIfSmi(target, &non_constructor);

  // Check if target has a [[Construct]] internal method.
  __ LoadTaggedField(map, FieldMemOperand(target, HeapObject::kMapOffset));
  {
    Register flags = t3;
    __ Lbu(flags, FieldMemOperand(map, Map::kBitFieldOffset));
    __ And(flags, flags, Operand(Map::Bits1::IsConstructorBit::kMask));
    __ Branch(&non_constructor, eq, flags, Operand(zero_reg));
  }

  // Dispatch based on instance type.
  __ GetInstanceTypeRange(map, instance_type, FIRST_JS_FUNCTION_TYPE, scratch);
  __ TailCallBuiltin(Builtin::kConstructFunction, Uless_equal, scratch,
                     Operand(LAST_JS_FUNCTION_TYPE - FIRST_JS_FUNCTION_TYPE));

  // Only dispatch to bound functions after checking whether they are
  // constructors.
  __ TailCallBuiltin(Builtin::kConstructBoundFunction, eq, instance_type,
                     Operand(JS_BOUND_FUNCTION_TYPE));

  // Only dispatch to proxies after checking whether they are constructors.
  __ Branch(&non_proxy, ne, instance_type, Operand(JS_PROXY_TYPE));
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
// Compute register lists for parameters to be saved. We save all parameter
// registers (see wasm-linkage.h). They might be overwritten in the runtime
// call below. We don't have any callee-saved registers in wasm, so no need to
// store anything else.
constexpr RegList kSavedGpRegs = ([]() constexpr {
  static_assert(WasmLiftoffSetupFrameConstants::kNumberOfSavedGpParamRegs ==
                    arraysize(wasm::kGpParamRegisters) - 1,
                "frame size mismatch");
  RegList saved_gp_regs;
  for (Register gp_param_reg : wasm::kGpParamRegisters) {
    saved_gp_regs.set(gp_param_reg);
  }

  // The instance data has already been stored in the fixed part of the frame.
  saved_gp_regs.clear(kWasmImplicitArgRegister);
  // All set registers were unique.
  CHECK_EQ(saved_gp_regs.Count(), arraysize(wasm::kGpParamRegisters) - 1);
  CHECK_EQ(WasmLiftoffSetupFrameConstants::kNumberOfSavedGpParamRegs,
           saved_gp_regs.Count());
  return saved_gp_regs;
})();

constexpr DoubleRegList kSavedFpRegs = ([]() constexpr {
  static_assert(WasmLiftoffSetupFrameConstants::kNumberOfSavedFpParamRegs ==
                    arraysize(wasm::kFpParamRegisters),
                "frame size mismatch");
  DoubleRegList saved_fp_regs;
  for (DoubleRegister fp_param_reg : wasm::kFpParamRegisters) {
    saved_fp_regs.set(fp_param_reg);
  }

  CHECK_EQ(saved_fp_regs.Count(), arraysize(wasm::kFpParamRegisters));
  CHECK_EQ(WasmLiftoffSetupFrameConstants::kNumberOfSavedFpParamRegs,
           saved_fp_regs.Count());
  return saved_fp_regs;
})();

// When entering this builtin, we have just created a Wasm stack frame:
//
// [ Wasm instance data ]  <-- sp
// [ WASM frame marker  ]
// [     saved fp       ]  <-- fp
//
// Add the feedback vector to the stack.
//
// [  feedback vector   ]  <-- sp
// [ Wasm instance data ]
// [ WASM frame marker  ]
// [     saved fp       ]  <-- fp
void Builtins::Generate_WasmLiftoffFrameSetup(MacroAssembler* masm) {
  Register func_index = wasm::kLiftoffFrameSetupFunctionReg;
  Register vector = t1;
  Register scratch = t2;
  Label allocate_vector, done;

  __ LoadTaggedField(
      vector, FieldMemOperand(kWasmImplicitArgRegister,
                              WasmTrustedInstanceData::kFeedbackVectorsOffset));
  __ CalcScaledAddress(vector, vector, func_index, kTaggedSizeLog2);
  __ LoadTaggedField(vector,
                     FieldMemOperand(vector, OFFSET_OF_DATA_START(FixedArray)));
  __ JumpIfSmi(vector, &allocate_vector);
  __ bind(&done);
  __ Push(vector);
  __ Ret();

  __ bind(&allocate_vector);
  // Feedback vector doesn't exist yet. Call the runtime to allocate it.
  // We temporarily change the frame type for this, because we need special
  // handling by the stack walker in case of GC.
  __ li(scratch, StackFrame::TypeToMarker(StackFrame::WASM_LIFTOFF_SETUP));
  __ StoreWord(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));

  // Save registers.
  __ MultiPush(kSavedGpRegs);
  __ MultiPushFPU(kSavedFpRegs);
  __ Push(ra);

  // Arguments to the runtime function: instance data, func_index, and an
  // additional stack slot for the NativeModule.
  __ SmiTag(func_index);
  __ Push(kWasmImplicitArgRegister, func_index, zero_reg);
  __ Move(cp, Smi::zero());
  __ CallRuntime(Runtime::kWasmAllocateFeedbackVector, 3);
  __ mv(vector, kReturnRegister0);

  // Restore registers and frame type.
  __ Pop(ra);
  __ MultiPopFPU(kSavedFpRegs);
  __ MultiPop(kSavedGpRegs);
  __ LoadWord(kWasmImplicitArgRegister,
              MemOperand(fp, WasmFrameConstants::kWasmInstanceDataOffset));
  __ li(scratch, StackFrame::TypeToMarker(StackFrame::WASM));
  __ StoreWord(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));
  __ Branch(&done);
}

void Builtins::Generate_WasmCompileLazy(MacroAssembler* masm) {
  // The function index was put in t0 by the jump table trampoline.
  // Convert to Smi for the runtime call
  __ SmiTag(kWasmCompileLazyFuncIndexRegister);

  {
    HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
    FrameScope scope(masm, StackFrame::INTERNAL);

    // Save registers that we need to keep alive across the runtime call.
    __ Push(kWasmImplicitArgRegister);
    __ MultiPush(kSavedGpRegs);
    __ MultiPushFPU(kSavedFpRegs);

    __ Push(kWasmImplicitArgRegister, kWasmCompileLazyFuncIndexRegister);
    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ Move(kContextRegister, Smi::zero());
    __ CallRuntime(Runtime::kWasmCompileLazy, 2);

    __ SmiUntag(s1, a0);  // move return value to s1 since a0 will be restored
                          // to the value before the call
    CHECK(!kSavedGpRegs.has(s1));

    // Restore registers.
    __ MultiPopFPU(kSavedFpRegs);
    __ MultiPop(kSavedGpRegs);
    __ Pop(kWasmImplicitArgRegister);
  }

  // The runtime function returned the jump table slot offset as a Smi (now in
  // x17). Use that to compute the jump target.
  __ LoadWord(kScratchReg,
              FieldMemOperand(kWasmImplicitArgRegister,
                              WasmTrustedInstanceData::kJumpTableStartOffset));
  __ AddWord(s1, s1, Operand(kScratchReg));
  // Finally, jump to the entrypoint.
  __ Jump(s1);
}

void Builtins::Generate_WasmDebugBreak(MacroAssembler* masm) {
  HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
  {
    FrameScope scope(masm, StackFrame::WASM_DEBUG_BREAK);

    // Save all parameter registers. They might hold live values, we restore
    // them after the runtime call.
    __ MultiPush(WasmDebugBreakFrameConstants::kPushedGpRegs);
    __ MultiPushFPU(WasmDebugBreakFrameConstants::kPushedFpRegs);

    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ Move(cp, Smi::zero());
    __ CallRuntime(Runtime::kWasmDebugBreak, 0);

    // Restore registers.
    __ MultiPopFPU(WasmDebugBreakFrameConstants::kPushedFpRegs);
    __ MultiPop(WasmDebugBreakFrameConstants::kPushedGpRegs);
  }
  __ Ret();
}

#endif  // V8_ENABLE_WEBASSEMBLY

namespace {
void SwitchSimulatorStackLimit(MacroAssembler* masm) {
#ifdef V8_TARGET_ARCH_RISCV64
  if (masm->options().enable_simulator_code) {
    UseScratchRegisterScope temps(masm);
    temps.Exclude(kSimulatorBreakArgument);
    __ RecordComment("-- Set simulator stack limit --");
    __ LoadStackLimit(kSimulatorBreakArgument, StackLimitKind::kRealStackLimit);
    __ break_(kExceptionIsSwitchStackLimit, false);
  }
#endif
}

static constexpr Register kOldSPRegister = s9;
static constexpr Register kSwitchFlagRegister = s10;

void SwitchToTheCentralStackIfNeeded(MacroAssembler* masm, Register argc_input,
                                     Register target_input,
                                     Register argv_input) {
  using ER = ExternalReference;

  __ li(kSwitchFlagRegister, 0);
  __ mv(kOldSPRegister, sp);

  // Using x2-x4 as temporary registers, because they will be rewritten
  // before exiting to native code anyway.

  ER on_central_stack_flag_loc = ER::Create(
      IsolateAddressId::kIsOnCentralStackFlagAddress, masm->isolate());
  const Register& on_central_stack_flag = a2;
  __ li(on_central_stack_flag, on_central_stack_flag_loc);
  __ Lb(on_central_stack_flag, MemOperand(on_central_stack_flag));

  Label do_not_need_to_switch;
  __ Branch(&do_not_need_to_switch, ne, on_central_stack_flag,
            Operand(zero_reg));
  // Switch to central stack.

  static constexpr Register central_stack_sp = a4;
  DCHECK(!AreAliased(central_stack_sp, argc_input, argv_input, target_input));
  {
    __ Push(argc_input, target_input, argv_input);
    __ PrepareCallCFunction(2, argc_input);
    __ li(kCArgRegs[0], ER::isolate_address(masm->isolate()));
    __ mv(kCArgRegs[1], kOldSPRegister);
    __ CallCFunction(ER::wasm_switch_to_the_central_stack(), 2,
                     SetIsolateDataSlots::kNo);
    __ mv(central_stack_sp, kReturnRegister0);
    __ Pop(argc_input, target_input, argv_input);
  }

  SwitchSimulatorStackLimit(masm);

  static constexpr int kReturnAddressSlotOffset = 1 * kSystemPointerSize;
  static constexpr int kPadding = 1 * kSystemPointerSize;
  __ SubWord(sp, central_stack_sp, kReturnAddressSlotOffset + kPadding);
  __ li(kSwitchFlagRegister, 1);

  // Update the sp saved in the frame.
  // It will be used to calculate the callee pc during GC.
  // The pc is going to be on the new stack segment, so rewrite it here.
  __ AddWord(central_stack_sp, sp, kSystemPointerSize);
  __ StoreWord(central_stack_sp, MemOperand(fp, ExitFrameConstants::kSPOffset));

  __ bind(&do_not_need_to_switch);
}

void SwitchFromTheCentralStackIfNeeded(MacroAssembler* masm) {
  using ER = ExternalReference;

  Label no_stack_change;
  __ Branch(&no_stack_change, eq, kSwitchFlagRegister, Operand(zero_reg));

  {
    __ Push(kReturnRegister0, kReturnRegister1);
    __ li(kCArgRegs[0], ER::isolate_address(masm->isolate()));
    DCHECK_NE(kReturnRegister1, kCArgRegs[0]);
    __ PrepareCallCFunction(1, kReturnRegister1);
    __ CallCFunction(ER::wasm_switch_from_the_central_stack(), 1,
                     SetIsolateDataSlots::kNo);
    __ Pop(kReturnRegister0, kReturnRegister1);
  }

  __ mv(sp, kOldSPRegister);

  __ bind(&no_stack_change);
}
}  // namespace

void Builtins::Generate_CEntry(MacroAssembler* masm, int result_size,
                               ArgvMode argv_mode, bool builtin_exit_frame,
                               bool switch_to_central_stack) {
  // Called from JavaScript; parameters are on stack as if calling JS function
  // a0: number of arguments including receiver
  // a1: pointer to c++ function
  // fp: frame pointer    (restored after C call)
  // sp: stack pointer    (restored as callee's sp after C call)
  // cp: current context  (C callee-saved)
  // If argv_mode == ArgvMode::kRegister:
  // a2: pointer to the first argument
  using ER = ExternalReference;

  static constexpr Register argc_input = a0;
  static constexpr Register target_input = a1;
  // Initialized below if ArgvMode::kStack.
  static constexpr Register argv_input = s1;
  static constexpr Register argc_sav = s3;
  static constexpr Register scratch = a3;
  if (argv_mode == ArgvMode::kRegister) {
    // Move argv into the correct register.
    __ Move(s1, a2);
  } else {
    // Compute the argv pointer in a callee-saved register.
    __ CalcScaledAddress(s1, sp, a0, kSystemPointerSizeLog2);
    __ SubWord(s1, s1, kSystemPointerSize);
  }

  // Enter the exit frame that transitions from JavaScript to C++.
  FrameScope scope(masm, StackFrame::MANUAL);
  __ EnterExitFrame(
      scratch, 0,
      builtin_exit_frame ? StackFrame::BUILTIN_EXIT : StackFrame::EXIT);

  // s3: number of arguments  including receiver (C callee-saved)
  // s1: pointer to first argument (C callee-saved)
  // s2: pointer to builtin function (C callee-saved)

  // Prepare arguments for C routine.
  // a0 = argc
  __ Move(argc_sav, argc_input);
  __ Move(s2, target_input);

  // We are calling compiled C/C++ code. a0 and a1 hold our two arguments. We
  // also need to reserve the 4 argument slots on the stack.

  __ AssertStackIsAligned();

#if V8_ENABLE_WEBASSEMBLY
  if (switch_to_central_stack) {
    SwitchToTheCentralStackIfNeeded(masm, argc_input, target_input, argv_input);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // a0 = argc, a1 = argv, a2 = isolate
  __ li(a2, ER::isolate_address(masm->isolate()));
  __ Move(a1, s1);

  __ StoreReturnAddressAndCall(s2);

  // Result returned in a0 or a1:a0 - do not destroy these registers!
#if V8_ENABLE_WEBASSEMBLY
  if (switch_to_central_stack) {
    SwitchFromTheCentralStackIfNeeded(masm);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // Check result for exception sentinel.
  Label exception_returned;
  // The returned value may be a trusted object, living outside of the main
  // pointer compression cage, so we need to use full pointer comparison here.
  __ CompareRootAndBranch(a0, RootIndex::kException, eq, &exception_returned,
                          ComparisonMode::kFullPointer);

  // Exit C frame and return.
  // a0:a1: result
  // sp: stack pointer
  // fp: frame pointer
  // s3: still holds argc (C caller-saved).
  __ LeaveExitFrame(scratch);
  if (argv_mode == ArgvMode::kStack) {
    DCHECK(!AreAliased(scratch, argc_sav));
    __ DropArguments(argc_sav);
  }
  __ Ret();

  // Handling of exception.
  __ bind(&exception_returned);

  ER pending_handler_context_address = ER::Create(
      IsolateAddressId::kPendingHandlerContextAddress, masm->isolate());
  ER pending_handler_entrypoint_address = ER::Create(
      IsolateAddressId::kPendingHandlerEntrypointAddress, masm->isolate());
  ER pending_handler_fp_address =
      ER::Create(IsolateAddressId::kPendingHandlerFPAddress, masm->isolate());
  ER pending_handler_sp_address =
      ER::Create(IsolateAddressId::kPendingHandlerSPAddress, masm->isolate());

  // Ask the runtime for help to determine the handler. This will set a0 to
  // contain the current exception, don't clobber it.
  ER find_handler = ER::Create(Runtime::kUnwindAndFindExceptionHandler);
  {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ PrepareCallCFunction(3, 0, a0);
    __ Move(a0, zero_reg);
    __ Move(a1, zero_reg);
    __ li(a2, ER::isolate_address());
    __ CallCFunction(find_handler, 3, SetIsolateDataSlots::kNo);
  }

  // Retrieve the handler context, SP and FP.
  __ li(cp, pending_handler_context_address);
  __ LoadWord(cp, MemOperand(cp));
  __ li(sp, pending_handler_sp_address);
  __ LoadWord(sp, MemOperand(sp));
  __ li(fp, pending_handler_fp_address);
  __ LoadWord(fp, MemOperand(fp));

  // If the handler is a JS frame, restore the context to the frame. Note that
  // the context will be set to (cp == 0) for non-JS frames.
  Label zero;
  __ Branch(&zero, eq, cp, Operand(zero_reg), Label::Distance::kNear);
  __ StoreWord(cp, MemOperand(fp, StandardFrameConstants::kContextOffset));
  __ bind(&zero);

  // Clear c_entry_fp, like we do in `LeaveExitFrame`.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, masm->isolate());
  __ StoreWord(zero_reg,
               __ ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  // Compute the handler entry address and jump to it.
  __ LoadWord(scratch, __ ExternalReferenceAsOperand(
                           pending_handler_entrypoint_address, no_reg));
  __ Jump(scratch);
}

#if V8_ENABLE_WEBASSEMBLY
void Builtins::Generate_WasmHandleStackOverflow(MacroAssembler* masm) {
  __ Trap();
}
#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_DoubleToI(MacroAssembler* masm) {
  Label done;
  Register result_reg = t0;

  Register scratch = GetRegisterThatIsNotOneOf(result_reg);
  Register scratch2 = GetRegisterThatIsNotOneOf(result_reg, scratch);
  Register scratch3 = GetRegisterThatIsNotOneOf(result_reg, scratch, scratch2);
  DoubleRegister double_scratch = kScratchDoubleReg;

  // Account for saved regs.
  const int kArgumentOffset = 4 * kSystemPointerSize;

  __ Push(result_reg);
  __ Push(scratch, scratch2, scratch3);

  // Load double input.
  __ LoadDouble(double_scratch, MemOperand(sp, kArgumentOffset));

  // Try a conversion to a signed integer, if exception occurs, scratch is
  // set to 0
  __ Trunc_w_d(scratch3, double_scratch, scratch);

  // If we had no exceptions then set result_reg and we are done.
  Label error;
  __ Branch(&error, eq, scratch, Operand(zero_reg), Label::Distance::kNear);
  __ Move(result_reg, scratch3);
  __ Branch(&done);
  __ bind(&error);

  // Load the double value and perform a manual truncation.
  Register input_high = scratch2;
  Register input_low = scratch3;

  __ Lw(input_low, MemOperand(sp, kArgumentOffset + Register::kMantissaOffset));
  __ Lw(input_high,
        MemOperand(sp, kArgumentOffset + Register::kExponentOffset));

  Label normal_exponent;
  // Extract the biased exponent in result.
  __ ExtractBits(result_reg, input_high, HeapNumber::kExponentShift,
                 HeapNumber::kExponentBits);

  // Check for Infinity and NaNs, which should return 0.
  __ Sub32(scratch, result_reg, HeapNumber::kExponentMask);
  __ LoadZeroIfConditionZero(
      result_reg,
      scratch);  // result_reg = scratch == 0 ? 0 : result_reg
  __ Branch(&done, eq, scratch, Operand(zero_reg));

  // Express exponent as delta to (number of mantissa bits + 31).
  __ Sub32(result_reg, result_reg,
           Operand(HeapNumber::kExponentBias + HeapNumber::kMantissaBits + 31));

  // If the delta is strictly positive, all bits would be shifted away,
  // which means that we can return 0.
  __ Branch(&normal_exponent, le, result_reg, Operand(zero_reg),
            Label::Distance::kNear);
  __ Move(result_reg, zero_reg);
  __ Branch(&done);

  __ bind(&normal_exponent);
  const int kShiftBase = HeapNumber::kNonMantissaBitsInTopWord - 1;
  // Calculate shift.
  __ Add32(scratch, result_reg,
           Operand(kShiftBase + HeapNumber::kMantissaBits));

  // Save the sign.
  Register sign = result_reg;
  result_reg = no_reg;
  __ And(sign, input_high, Operand(HeapNumber::kSignMask));

  // We must specially handle shifts greater than 31.
  Label high_shift_needed, high_shift_done;
  __ Branch(&high_shift_needed, lt, scratch, Operand(32),
            Label::Distance::kNear);
  __ Move(input_high, zero_reg);
  __ BranchShort(&high_shift_done);
  __ bind(&high_shift_needed);

  // Set the implicit 1 before the mantissa part in input_high.
  __ Or(input_high, input_high,
        Operand(1 << HeapNumber::kMantissaBitsInTopWord));
  // Shift the mantissa bits to the correct position.
  // We don't need to clear non-mantissa bits as they will be shifted away.
  // If they weren't, it would mean that the answer is in the 32bit range.
  __ Sll32(input_high, input_high, scratch);

  __ bind(&high_shift_done);

  // Replace the shifted bits with bits from the lower mantissa word.
  Label pos_shift, shift_done, sign_negative;
  __ li(kScratchReg, 32);
  __ Sub32(scratch, kScratchReg, scratch);
  __ Branch(&pos_shift, ge, scratch, Operand(zero_reg), Label::Distance::kNear);

  // Negate scratch.
  __ Sub32(scratch, zero_reg, scratch);
  __ Sll32(input_low, input_low, scratch);
  __ BranchShort(&shift_done);

  __ bind(&pos_shift);
  __ Srl32(input_low, input_low, scratch);

  __ bind(&shift_done);
  __ Or(input_high, input_high, Operand(input_low));
  // Restore sign if necessary.
  __ Move(scratch, sign);
  result_reg = sign;
  sign = no_reg;
  __ Sub32(result_reg, zero_reg, input_high);
  __ Branch(&sign_negative, ne, scratch, Operand(zero_reg),
            Label::Distance::kNear);
  __ Move(result_reg, input_high);
  __ bind(&sign_negative);

  __ bind(&done);

  __ StoreWord(result_reg, MemOperand(sp, kArgumentOffset));
  __ Pop(scratch, scratch2, scratch3);
  __ Pop(result_reg);
  __ Ret();
}

void Builtins::Generate_WasmToJsWrapperAsm(MacroAssembler* masm) {
  int required_stack_space = arraysize(wasm::kFpParamRegisters) * kDoubleSize;
  __ SubWord(sp, sp, Operand(required_stack_space));
  for (int i = 0; i < static_cast<int>(arraysize(wasm::kFpParamRegisters));
       ++i) {
    __ StoreDouble(wasm::kFpParamRegisters[i], MemOperand(sp, i * kDoubleSize));
  }

  constexpr int num_gp = arraysize(wasm::kGpParamRegisters) - 1;
  required_stack_space = num_gp * kSystemPointerSize;
  __ SubWord(sp, sp, Operand(required_stack_space));
  for (int i = 1; i < static_cast<int>(arraysize(wasm::kGpParamRegisters));
       ++i) {
    __ StoreWord(wasm::kGpParamRegisters[i],
                 MemOperand(sp, (i - 1) * kSystemPointerSize));
  }
  // Reserve a slot for the signature.
  __ Push(zero_reg);
  __ TailCallBuiltin(Builtin::kWasmToJsWrapperCSA);
}

void Builtins::Generate_WasmTrapHandlerLandingPad(MacroAssembler* masm) {
  // This builtin gets called from the WebAssembly trap handler when an
  // out-of-bounds memory access happened or when a null reference gets
  // dereferenced. This builtin then fakes a call from the instruction that
  // triggered the signal to the runtime. This is done by setting a return
  // address and then jumping to a builtin which will call further to the
  // runtime.
  // As the return address we use the fault address + 1. Using the fault address
  // itself would cause problems with safepoints and source positions.
  //
  // The problem with safepoints is that a safepoint has to be registered at the
  // return address, and that at most one safepoint should be registered at a
  // location. However, there could already be a safepoint registered at the
  // fault address if the fault address is the return address of a call.
  //
  // The problem with source positions is that the stack trace code looks for
  // the source position of a call before the return address. The source
  // position of the faulty memory access, however, is recorded at the fault
  // address. Therefore the stack trace code would not find the source position
  // if we used the fault address as the return address.
  __ AddWord(ra, kWasmTrapHandlerFaultAddressRegister, 1);
  __ TailCallBuiltin(Builtin::kWasmTrapHandlerThrowTrap);
}

namespace {
// Check that the stack was in the old state (if generated code assertions are
// enabled), and switch to the new state.
void SwitchStackState(MacroAssembler* masm, Register jmpbuf, Register tmp,
                      wasm::JumpBuffer::StackState old_state,
                      wasm::JumpBuffer::StackState new_state) {
  ASM_CODE_COMMENT(masm);
#if V8_ENABLE_SANDBOX
  __ Lw(tmp, MemOperand(jmpbuf, wasm::kJmpBufStateOffset));
  Label ok;
  // is branch32?
  __ Branch(&ok, eq, tmp, Operand(old_state));
  __ Trap();
  __ bind(&ok);
#endif
  __ li(tmp, new_state);
  __ Sw(tmp, MemOperand(jmpbuf, wasm::kJmpBufStateOffset));
}

// Switch the stack pointer. Also switch the simulator's stack limit when
// running on the simulator. This needs to be done as close as possible to
// changing the stack pointer, as a mismatch between the stack pointer and the
// simulator's stack limit can cause stack access check failures.
void SwitchStackPointerAndSimulatorStackLimit(MacroAssembler* masm,
                                              Re
```