Response:
The user wants a summary of the functionality of the provided C++ code snippet.
The code is part of the V8 JavaScript engine, specifically for the s390 architecture.
The filename `builtins-s390.cc` suggests that it defines built-in functions for this architecture.

I need to:
1. Identify the different functions defined in the code.
2. Describe the purpose of each function.
3. Check if any of the functions have a corresponding JavaScript functionality and provide an example if so.
4. Look for code logic that can be explained with input/output examples.
5. Identify potential user programming errors related to these built-ins.
6. Confirm that this is part 4 of 5 and incorporate this information into the summary.
这是 `v8/src/builtins/s390/builtins-s390.cc` 源代码的第 4 部分，主要包含以下功能：

**1. 函数调用相关的 Built-ins:**

*   **`Generate_CallFunction(MacroAssembler* masm, ConvertReceiverMode mode)`:**  这个 Built-in 函数负责调用一个 JavaScript 函数。
    *   它会检查目标对象是否可以调用 (JSFunction, JSBoundFunction, JSProxy, Wrapped Function 等)。
    *   根据 `ConvertReceiverMode` 的不同，处理 `this` 绑定的方式。
    *   如果目标不是可调用对象，会抛出异常。
    *   如果目标是 `classConstructor`，会抛出错误。
    *   **JavaScript 例子:**
        ```javascript
        function myFunction(a, b) {
          console.log(this, a, b);
        }

        myFunction(1, 2); // 直接调用，this 通常是全局对象 (非严格模式) 或 undefined (严格模式)

        const obj = { value: 10 };
        myFunction.call(obj, 1, 2); // 使用 call 改变 this 的绑定

        const boundFunction = myFunction.bind({ value: 20 }, 3);
        boundFunction(4); // 调用 bind 后的函数
        ```
*   **`Generate_CallBoundFunctionImpl(MacroAssembler* masm)`:**  专门用于调用 `JSBoundFunction` (通过 `bind` 创建的函数)。
    *   它会设置 `this` 值为绑定时的 `this`。
    *   将绑定时传入的参数压入栈。
    *   最终调用目标函数。
*   **`Generate_Call(MacroAssembler* masm, ConvertReceiverMode mode)`:**  `CallFunction` 的入口点，负责更通用的调用逻辑。
    *   会根据目标对象的类型，分发到不同的 Built-in 函数处理 (例如 `CallFunction`, `CallBoundFunction`, `CallProxy`, `CallWrappedFunction`)。
*   **`Generate_PushBoundArguments(MacroAssembler* masm)`:**  辅助函数，用于将 `JSBoundFunction` 中绑定的参数压入栈。

**2. 构造函数调用相关的 Built-ins:**

*   **`Generate_ConstructFunction(MacroAssembler* masm)`:**  用于构造通过 `new` 调用的普通 JavaScript 函数。
    *   区分内置构造函数和普通构造函数，调用不同的 Stub。
    *   **JavaScript 例子:**
        ```javascript
        function MyClass(value) {
          this.value = value;
        }

        const instance = new MyClass(5);
        console.log(instance.value);
        ```
*   **`Generate_ConstructBoundFunction(MacroAssembler* masm)`:** 用于构造通过 `new` 调用的 `JSBoundFunction`。
    *   处理 `new.target` 的情况。
    *   最终调用目标构造函数。
*   **`Generate_Construct(MacroAssembler* masm)`:** `ConstructFunction` 和 `ConstructBoundFunction` 的入口点，处理通用的构造函数调用逻辑。
    *   检查目标对象是否是构造函数。
    *   根据目标类型分发到不同的 Built-in 函数 (`ConstructFunction`, `ConstructBoundFunction`, `ConstructProxy`)。
    *   如果目标不是构造函数，会抛出异常。
    *   **用户常见的编程错误:** 尝试 `new` 一个非构造函数对象，例如普通对象或 `null`。
        ```javascript
        const notAConstructor = {};
        try {
          const instance = new notAConstructor(); // TypeError: notAConstructor is not a constructor
        } catch (e) {
          console.error(e);
        }
        ```

**3. Maglev 特性相关 (如果启用):**

*   **`Generate_MaglevFunctionEntryStackCheck(MacroAssembler* masm, bool save_new_target)`:**  在 Maglev 优化编译的函数入口处进行栈检查。

**4. WebAssembly 相关 (如果启用):**

这部分定义了多个与 WebAssembly 交互相关的 Built-ins，包括：

*   **`Generate_WasmLiftoffFrameSetup(MacroAssembler* masm)`:**  为 WebAssembly Liftoff 编译的代码设置栈帧。
*   **`Generate_WasmCompileLazy(MacroAssembler* masm)`:**  延迟编译 WebAssembly 函数。
*   **`Generate_WasmDebugBreak(MacroAssembler* masm)`:**  处理 WebAssembly 代码中的断点。
*   **`Generate_WasmReturnPromiseOnSuspendAsm(MacroAssembler* masm)`:**  在 WebAssembly 挂起时返回 Promise。
*   **`Generate_JSToWasmStressSwitchStacksAsm(MacroAssembler* masm)`:**  用于压力测试的栈切换。
*   **`GetContextFromImplicitArg(MacroAssembler* masm, Register data, Register scratch)`:**  从 `WasmTrustedInstanceData` 或 `WasmImportData` 中获取上下文。
*   **`Generate_WasmToJsWrapperAsm(MacroAssembler* masm)`:**  从 WebAssembly 调用 JavaScript 的包装器。
*   **`Generate_WasmTrapHandlerLandingPad(MacroAssembler* masm)`:**  WebAssembly 陷阱处理器的着陆点。
*   **`Generate_WasmSuspend(MacroAssembler* masm)`:**  挂起 WebAssembly 执行。
*   **`Generate_WasmResume(MacroAssembler* masm)`:**  恢复 WebAssembly 执行。
*   **`Generate_WasmReject(MacroAssembler* masm)`:**  拒绝 WebAssembly 调用。
*   **`Generate_WasmOnStackReplace(MacroAssembler* masm)`:**  WebAssembly 的栈上替换 (OSR)。
*   **`ResetStackSwitchFrameStackSlots(MacroAssembler* masm)`:**  重置栈切换帧的栈槽。
*   **`Generate_JSToWasmWrapperAsm(MacroAssembler* masm)`:**  从 JavaScript 调用 WebAssembly 的包装器。
*   **`Generate_WasmHandleStackOverflow(MacroAssembler* masm)`:**  处理 WebAssembly 的栈溢出。

**5. C++ 调用相关的 Built-in:**

*   **`Generate_CEntry(MacroAssembler* masm, int result_size, ArgvMode argv_mode, bool builtin_exit_frame, bool switch_to_central_stack)`:**  用于从 JavaScript 代码调用 C++ 函数。
    *   负责设置调用 C++ 函数所需的栈帧和参数。
    *   处理 C++ 函数的返回值和异常。
    *   **代码逻辑推理:**  假设 `result_size` 为 1，表示 C++ 函数返回一个标量值，那么 `Generate_CEntry` 会将返回值存储在 `r2` 寄存器中。如果 `result_size` 为 2，且平台支持寄存器返回 pair，则返回值会存储在 `r2` 和 `r3` 中。
    *   **用户常见的编程错误:**  在声明 Native 函数时，返回值类型与 C++ 函数实际返回值类型不匹配，可能导致数据解析错误或崩溃。

**归纳一下它的功能:**

这部分 `builtins-s390.cc` 文件主要定义了 **函数调用和构造函数调用** 相关的底层实现，以及在启用了 WebAssembly 的情况下，**JavaScript 与 WebAssembly 之间互操作** 的相关 Built-ins。 此外，它还包含了用于 **从 JavaScript 调用 C++ 函数** 的基础设施。这些 Built-ins 是 V8 引擎执行 JavaScript 代码的关键组成部分。

由于这是第 4 部分，可以推断前面的部分可能包含了其他类型的 Built-ins，例如对象操作、属性访问、算术运算等。而后续的部分可能会涉及错误处理、调试支持或者其他更底层的机制。

Prompt: 
```
这是目录为v8/src/builtins/s390/builtins-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/s390/builtins-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
(Builtin::kToObject);
        __ Pop(cp);
        __ mov(r5, r2);
        __ Pop(r2, r3);
        __ SmiUntag(r2);
      }
      __ LoadTaggedField(
          r4, FieldMemOperand(r3, JSFunction::kSharedFunctionInfoOffset));
      __ bind(&convert_receiver);
    }
    __ StoreReceiver(r5);
  }
  __ bind(&done_convert);

  // ----------- S t a t e -------------
  //  -- r2 : the number of arguments
  //  -- r3 : the function to call (checked to be a JSFunction)
  //  -- r4 : the shared function info.
  //  -- cp : the function context.
  // -----------------------------------

  __ LoadU16(
      r4, FieldMemOperand(r4, SharedFunctionInfo::kFormalParameterCountOffset));
  __ InvokeFunctionCode(r3, no_reg, r4, r2, InvokeType::kJump);
}

namespace {

void Generate_PushBoundArguments(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r2 : the number of arguments
  //  -- r3 : target (checked to be a JSBoundFunction)
  //  -- r5 : new.target (only in case of [[Construct]])
  // -----------------------------------

  // Load [[BoundArguments]] into r4 and length of that into r6.
  Label no_bound_arguments;
  __ LoadTaggedField(
      r4, FieldMemOperand(r3, JSBoundFunction::kBoundArgumentsOffset));
  __ SmiUntagField(r6, FieldMemOperand(r4, offsetof(FixedArray, length_)));
  __ LoadAndTestP(r6, r6);
  __ beq(&no_bound_arguments);
  {
    // ----------- S t a t e -------------
    //  -- r2 : the number of arguments
    //  -- r3 : target (checked to be a JSBoundFunction)
    //  -- r4 : the [[BoundArguments]] (implemented as FixedArray)
    //  -- r5 : new.target (only in case of [[Construct]])
    //  -- r6 : the number of [[BoundArguments]]
    // -----------------------------------

    Register scratch = r8;
    // Reserve stack space for the [[BoundArguments]].
    {
      Label done;
      __ ShiftLeftU64(scratch, r6, Operand(kSystemPointerSizeLog2));
      __ SubS64(r1, sp, scratch);
      // Check the stack for overflow. We are not trying to catch interruptions
      // (i.e. debug break and preemption) here, so check the "real stack
      // limit".
      __ CmpU64(r1, __ StackLimitAsMemOperand(StackLimitKind::kRealStackLimit));
      __ bgt(&done);  // Signed comparison.
      // Restore the stack pointer.
      {
        FrameScope scope(masm, StackFrame::MANUAL);
        __ EnterFrame(StackFrame::INTERNAL);
        __ CallRuntime(Runtime::kThrowStackOverflow);
      }
      __ bind(&done);
    }

    // Pop receiver.
    __ Pop(r7);

    // Push [[BoundArguments]].
    {
      Label loop, done;
      __ AddS64(r2, r2, r6);  // Adjust effective number of arguments.
      __ AddS64(r4, r4,
                Operand(OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag));

      __ bind(&loop);
      __ SubS64(r1, r6, Operand(1));
      __ ShiftLeftU64(r1, r1, Operand(kTaggedSizeLog2));
      __ LoadTaggedField(scratch, MemOperand(r4, r1), r0);
      __ Push(scratch);
      __ SubS64(r6, r6, Operand(1));
      __ bgt(&loop);
      __ bind(&done);
    }

    // Push receiver.
    __ Push(r7);
  }
  __ bind(&no_bound_arguments);
}

}  // namespace

// static
void Builtins::Generate_CallBoundFunctionImpl(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r2 : the number of arguments
  //  -- r3 : the function to call (checked to be a JSBoundFunction)
  // -----------------------------------
  __ AssertBoundFunction(r3);

  // Patch the receiver to [[BoundThis]].
  __ LoadTaggedField(r5,
                     FieldMemOperand(r3, JSBoundFunction::kBoundThisOffset));
  __ StoreReceiver(r5);

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Call the [[BoundTargetFunction]] via the Call builtin.
  __ LoadTaggedField(
      r3, FieldMemOperand(r3, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtins::Call());
}

// static
void Builtins::Generate_Call(MacroAssembler* masm, ConvertReceiverMode mode) {
  // ----------- S t a t e -------------
  //  -- r2 : the number of arguments
  //  -- r3 : the target to call (can be any Object).
  // -----------------------------------
  Register target = r3;
  Register map = r6;
  Register instance_type = r7;
  Register scratch = r8;
  DCHECK(!AreAliased(r2, target, map, instance_type));

  Label non_callable, class_constructor;
  __ JumpIfSmi(target, &non_callable);
  __ LoadMap(map, target);
  __ CompareInstanceTypeRange(map, instance_type, scratch,
                              FIRST_CALLABLE_JS_FUNCTION_TYPE,
                              LAST_CALLABLE_JS_FUNCTION_TYPE);
  __ TailCallBuiltin(Builtins::CallFunction(mode), le);
  __ CmpS64(instance_type, Operand(JS_BOUND_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kCallBoundFunction, eq);

  // Check if target has a [[Call]] internal method.
  {
    Register flags = r6;
    __ LoadU8(flags, FieldMemOperand(map, Map::kBitFieldOffset));
    map = no_reg;
    __ TestBit(flags, Map::Bits1::IsCallableBit::kShift);
    __ beq(&non_callable);
  }

  // Check if target is a proxy and call CallProxy external builtin
  __ CmpS64(instance_type, Operand(JS_PROXY_TYPE));
  __ TailCallBuiltin(Builtin::kCallProxy, eq);

  // Check if target is a wrapped function and call CallWrappedFunction external
  // builtin
  __ CmpS64(instance_type, Operand(JS_WRAPPED_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kCallWrappedFunction, eq);

  // ES6 section 9.2.1 [[Call]] ( thisArgument, argumentsList)
  // Check that the function is not a "classConstructor".
  __ CmpS64(instance_type, Operand(JS_CLASS_CONSTRUCTOR_TYPE));
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
  //  -- r2 : the number of arguments
  //  -- r3 : the constructor to call (checked to be a JSFunction)
  //  -- r5 : the new target (checked to be a constructor)
  // -----------------------------------
  __ AssertConstructor(r3, r1);
  __ AssertFunction(r3);

  // Calling convention for function specific ConstructStubs require
  // r4 to contain either an AllocationSite or undefined.
  __ LoadRoot(r4, RootIndex::kUndefinedValue);

  Label call_generic_stub;

  // Jump to JSBuiltinsConstructStub or JSConstructStubGeneric.
  __ LoadTaggedField(
      r6, FieldMemOperand(r3, JSFunction::kSharedFunctionInfoOffset));
  __ LoadU32(r6, FieldMemOperand(r6, SharedFunctionInfo::kFlagsOffset));
  __ AndP(r6, Operand(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ beq(&call_generic_stub);

  __ TailCallBuiltin(Builtin::kJSBuiltinsConstructStub);

  __ bind(&call_generic_stub);
  __ TailCallBuiltin(Builtin::kJSConstructStubGeneric);
}

// static
void Builtins::Generate_ConstructBoundFunction(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r2 : the number of arguments
  //  -- r3 : the function to call (checked to be a JSBoundFunction)
  //  -- r5 : the new target (checked to be a constructor)
  // -----------------------------------
  __ AssertConstructor(r3, r1);
  __ AssertBoundFunction(r3);

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Patch new.target to [[BoundTargetFunction]] if new.target equals target.
  Label skip;
  __ CompareTagged(r3, r5);
  __ bne(&skip);
  __ LoadTaggedField(
      r5, FieldMemOperand(r3, JSBoundFunction::kBoundTargetFunctionOffset));
  __ bind(&skip);

  // Construct the [[BoundTargetFunction]] via the Construct builtin.
  __ LoadTaggedField(
      r3, FieldMemOperand(r3, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtin::kConstruct);
}

// static
void Builtins::Generate_Construct(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r2 : the number of arguments
  //  -- r3 : the constructor to call (can be any Object)
  //  -- r5 : the new target (either the same as the constructor or
  //          the JSFunction on which new was invoked initially)
  // -----------------------------------
  Register target = r3;
  Register map = r6;
  Register instance_type = r7;
  Register scratch = r8;
  DCHECK(!AreAliased(r2, target, map, instance_type, scratch));

  // Check if target is a Smi.
  Label non_constructor, non_proxy;
  __ JumpIfSmi(target, &non_constructor);

  // Check if target has a [[Construct]] internal method.
  __ LoadTaggedField(map, FieldMemOperand(target, HeapObject::kMapOffset));
  {
    Register flags = r4;
    DCHECK(!AreAliased(r2, target, map, instance_type, flags));
    __ LoadU8(flags, FieldMemOperand(map, Map::kBitFieldOffset));
    __ TestBit(flags, Map::Bits1::IsConstructorBit::kShift);
    __ beq(&non_constructor);
  }

  // Dispatch based on instance type.
  __ CompareInstanceTypeRange(map, instance_type, scratch,
                              FIRST_JS_FUNCTION_TYPE, LAST_JS_FUNCTION_TYPE);
  __ TailCallBuiltin(Builtin::kConstructFunction, le);

  // Only dispatch to bound functions after checking whether they are
  // constructors.
  __ CmpS64(instance_type, Operand(JS_BOUND_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kConstructBoundFunction, eq);

  // Only dispatch to proxies after checking whether they are constructors.
  __ CmpS64(instance_type, Operand(JS_PROXY_TYPE));
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

#ifdef V8_ENABLE_MAGLEV

void Builtins::Generate_MaglevFunctionEntryStackCheck(MacroAssembler* masm,
                                                      bool save_new_target) {
  // Input (r0): Stack size (Smi).
  // This builtin can be invoked just after Maglev's prologue.
  // All registers are available, except (possibly) new.target.
  ASM_CODE_COMMENT(masm);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ AssertSmi(r2);
    if (save_new_target) {
      __ Push(kJavaScriptCallNewTargetRegister);
    }
    __ Push(r2);
    __ CallRuntime(Runtime::kStackGuardWithGap, 1);
    if (save_new_target) {
      __ Pop(kJavaScriptCallNewTargetRegister);
    }
  }
  __ Ret();
}

#endif  // V8_ENABLE_MAGLEV

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
    CHECK_EQ(WasmLiftoffSetupFrameConstants::kNumberOfSavedGpParamRegs + 1,
             gp_regs.Count());
    CHECK_EQ(WasmLiftoffSetupFrameConstants::kNumberOfSavedFpParamRegs,
             fp_regs.Count());

    __ MultiPush(gp_regs);
    __ MultiPushF64OrV128(fp_regs, r1);
  }
  ~SaveWasmParamsScope() {
    __ MultiPopF64OrV128(fp_regs, r1);
    __ MultiPop(gp_regs);
  }

  RegList gp_regs;
  DoubleRegList fp_regs;
  MacroAssembler* masm;
};

void Builtins::Generate_WasmLiftoffFrameSetup(MacroAssembler* masm) {
  Register func_index = wasm::kLiftoffFrameSetupFunctionReg;
  Register vector = ip;
  Register scratch = r0;
  Label allocate_vector, done;

  __ LoadTaggedField(
      vector, FieldMemOperand(kWasmImplicitArgRegister,
                              WasmTrustedInstanceData::kFeedbackVectorsOffset));
  __ ShiftLeftU64(scratch, func_index, Operand(kTaggedSizeLog2));
  __ AddS64(vector, vector, scratch);
  __ LoadTaggedField(vector,
                     FieldMemOperand(vector, OFFSET_OF_DATA_START(FixedArray)));
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
  __ push(r14);
  {
    SaveWasmParamsScope save_params(masm);
    // Arguments to the runtime function: instance data, func_index.
    __ push(kWasmImplicitArgRegister);
    __ SmiTag(func_index);
    __ push(func_index);
    // Allocate a stack slot where the runtime function can spill a pointer
    // to the {NativeModule}.
    __ push(r10);
    __ LoadSmiLiteral(cp, Smi::zero());
    __ CallRuntime(Runtime::kWasmAllocateFeedbackVector, 3);
    __ mov(vector, kReturnRegister0);
    // Saved parameters are restored at the end of this block.
  }
  __ pop(r14);

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
      SaveWasmParamsScope save_params(masm);

      // Push the instance data as an explicit argument to the runtime function.
      __ push(kWasmImplicitArgRegister);
      // Push the function index as second argument.
      __ push(kWasmCompileLazyFuncIndexRegister);
      // Initialize the JavaScript context with 0. CEntry will use it to
      // set the current context on the isolate.
      __ LoadSmiLiteral(cp, Smi::zero());
      __ CallRuntime(Runtime::kWasmCompileLazy, 2);
      // The runtime function returns the jump table slot offset as a Smi. Use
      // that to compute the jump target in ip.
      __ SmiUntag(kReturnRegister0);
      __ mov(ip, kReturnRegister0);

      // Saved parameters are restored at the end of this block.
    }

    // After the instance data register has been restored, we can add the jump
    // table start to the jump table offset already stored in r8.
    __ LoadU64(r0,
               FieldMemOperand(kWasmImplicitArgRegister,
                               WasmTrustedInstanceData::kJumpTableStartOffset));
    __ AddS64(ip, ip, r0);
  }

  // Finally, jump to the jump table slot for the function.
  __ Jump(ip);
}

void Builtins::Generate_WasmDebugBreak(MacroAssembler* masm) {
  HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::WASM_DEBUG_BREAK);

    // Save all parameter registers. They might hold live values, we restore
    // them after the runtime call.
    __ MultiPush(WasmDebugBreakFrameConstants::kPushedGpRegs);
    __ MultiPushF64OrV128(WasmDebugBreakFrameConstants::kPushedFpRegs, ip);

    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ LoadSmiLiteral(cp, Smi::zero());
    __ CallRuntime(Runtime::kWasmDebugBreak, 0);

    // Restore registers.
    __ MultiPopF64OrV128(WasmDebugBreakFrameConstants::kPushedFpRegs, ip);
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
  __ LoadTaggedField(scratch, FieldMemOperand(data, HeapObject::kMapOffset));
  __ CompareInstanceType(scratch, scratch, WASM_TRUSTED_INSTANCE_DATA_TYPE);
  Label instance;
  Label end;
  __ beq(&instance);
  __ LoadTaggedField(
      data, FieldMemOperand(data, WasmImportData::kNativeContextOffset));
  __ jmp(&end);
  __ bind(&instance);
  __ LoadTaggedField(
      data,
      FieldMemOperand(data, WasmTrustedInstanceData::kNativeContextOffset));
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
  __ Push(r2);
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
  Register zero = r2;
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

  Register result_size = r2;
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
  Register params_end = r1;
  __ LoadU64(params_end,
             MemOperand(wrapper_buffer,
                        JSToWasmWrapperFrameConstants::kWrapperBufferParamEnd));

  Register params_start = ip;
  __ LoadU64(
      params_start,
      MemOperand(wrapper_buffer,
                 JSToWasmWrapperFrameConstants::kWrapperBufferParamStart));
  // The first GP parameter holds the trusted instance data or the import data.
  // This is handled specially.
  int stack_params_offset =
      (arraysize(wasm::kGpParamRegisters) - 1) * kSystemPointerSize +
      arraysize(wasm::kFpParamRegisters) * kDoubleSize;
  Register last_stack_param = r2;
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
    __ LoadU64(r0, MemOperand(params_end));
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
               MemOperand(params_start, next_offset));
    next_offset += kSystemPointerSize;
  }

  for (size_t i = 0; i < arraysize(wasm::kFpParamRegisters); ++i) {
    __ LoadF64(wasm::kFpParamRegisters[i],
               MemOperand(params_start, next_offset));
    next_offset += kDoubleSize;
  }
  DCHECK_EQ(next_offset, stack_params_offset);

  // Load the implicit argument into r5.
  __ LoadU64(kWasmImplicitArgRegister,
             MemOperand(fp, JSToWasmWrapperFrameConstants::kImplicitArgOffset));

  {
    Register thread_in_wasm_flag_addr = r3;
    __ LoadU64(thread_in_wasm_flag_addr,
               MemOperand(kRootRegister,
                          Isolate::thread_in_wasm_flag_address_offset()));
    __ mov(r0, Operand(1));
    __ StoreU32(r0, MemOperand(thread_in_wasm_flag_addr, 0));
  }

  Register function_entry = r3;
  __ LoadU64(
      function_entry,
      MemOperand(wrapper_buffer,
                 JSToWasmWrapperFrameConstants::kWrapperBufferCallTarget));
  __ Call(function_entry);

  {
    Register thread_in_wasm_flag_addr = r6;
    __ LoadU64(thread_in_wasm_flag_addr,
               MemOperand(kRootRegister,
                          Isolate::thread_in_wasm_flag_address_offset()));
    __ mov(r0, Operand(0));
    __ StoreU32(r0, MemOperand(thread_in_wasm_flag_addr, 0));
  }

  // `wrapper_buffer` is a parameter for `JSToWasmHandleReturns`, it therefore
  // has to be in r4.
  wrapper_buffer = r4;
  __ LoadU64(
      wrapper_buffer,
      MemOperand(fp, JSToWasmWrapperFrameConstants::kWrapperBufferOffset));

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

  // r2: wasm instance.
  // r3: the result JSArray for multi-return.
  // r4: pointer to the byte buffer which contains all parameters.
  __ LoadU64(
      r3,
      MemOperand(fp, JSToWasmWrapperFrameConstants::kResultArrayParamOffset));
  __ LoadU64(r2,
             MemOperand(fp, JSToWasmWrapperFrameConstants::kImplicitArgOffset));
  Register scratch = r5;
  GetContextFromImplicitArg(masm, r2, scratch);

  __ CallBuiltin(Builtin::kJSToWasmHandleReturns);

  __ LeaveFrame(StackFrame::JS_TO_WASM);
  __ AddS64(sp, sp, Operand(2 * kSystemPointerSize));
  __ b(r14);
}

#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_CEntry(MacroAssembler* masm, int result_size,
                               ArgvMode argv_mode, bool builtin_exit_frame,
                               bool switch_to_central_stack) {
  // Called from JavaScript; parameters are on stack as if calling JS function.
  // r2: number of arguments including receiver
  // r3: pointer to builtin function
  // fp: frame pointer  (restored after C call)
  // sp: stack pointer  (restored as callee's sp after C call)
  // cp: current context  (C callee-saved)
  //
  // If argv_mode == ArgvMode::kRegister:
  // r4: pointer to the first argument

  using ER = ExternalReference;

  // Move input arguments to more convenient registers.
  static constexpr Register argc_input = r2;
  static constexpr Register target_fun = r7;  // C callee-saved
  static constexpr Register argv = r3;
  static constexpr Register scratch = ip;
#if V8_OS_ZOS
  static constexpr Register argc_sav = r9;  // C callee-saved
#else
  static constexpr Register argc_sav = r6;  // C callee-saved
#endif

  __ mov(target_fun, argv);

  if (argv_mode == ArgvMode::kRegister) {
    // Move argv into the correct register.
    __ mov(argv, r4);
  } else {
    // Compute the argv pointer.
    __ ShiftLeftU64(argv, argc_input, Operand(kSystemPointerSizeLog2));
    __ lay(argv, MemOperand(argv, sp, -kSystemPointerSize));
  }

  // Enter the exit frame that transitions from JavaScript to C++.
  FrameScope scope(masm, StackFrame::MANUAL);

  int arg_stack_space = 0;

  // Pass buffer for return value on stack if necessary
  bool needs_return_buffer =
      result_size == 2 && !ABI_RETURNS_OBJECTPAIR_IN_REGS;
  if (needs_return_buffer) {
    arg_stack_space += result_size;
  }

  // 64-bit linux pass Argument object by reference not value
  arg_stack_space += 2;

  __ EnterExitFrame(
      scratch, arg_stack_space,
      builtin_exit_frame ? StackFrame::BUILTIN_EXIT : StackFrame::EXIT);

  // Store a copy of argc, argv in callee-saved registers for later.
  __ mov(argc_sav, argc_input);
  __ mov(r8, argv);
  // r2: number of arguments including receiver
  // r6: number of arguments including receiver (C callee-saved)
  // r3, r8: pointer to the first argument
  // r7: pointer to builtin function  (C callee-saved)

  // Result returned in registers or stack, depending on result size and ABI.

  Register isolate_reg = r4;
  if (needs_return_buffer) {
    // The return value is 16-byte non-scalar value.
    // Use frame storage reserved by calling function to pass return
    // buffer as implicit first argument in R2.  Shfit original parameters
    // by one register each.
    __ mov(r4, r3);
    __ mov(r3, r2);
    __ la(r2,
          MemOperand(sp, (kStackFrameExtraParamSlot + 1) * kSystemPointerSize));
    isolate_reg = r5;
    // Clang doesn't preserve r2 (result buffer)
    // write to r8 (preserved) before entry
    __ mov(r8, r2);
  }
  // Call C built-in.
  __ Move(isolate_reg, ER::isolate_address());

#if V8_OS_ZOS
  // Shuffle input arguments to match XPLINK ABI
  __ mov(r1, r2);
  __ mov(r2, r3);
  __ mov(r3, r4);
  // Save stack arguments to XPLINK extra param slot
  const int stack_args = 3;
  const int stack_space = kXPLINKStackFrameExtraParamSlot + stack_args;
  __ lay(r4, MemOperand(sp, -((stack_space * kSystemPointerSize) +
                              kStackPointerBias)));
  __ StoreMultipleP(
      r5, target_fun,
      MemOperand(r4, kStackPointerBias +
                         kXPLINKStackFrameExtraParamSlot * kSystemPointerSize));
  // Load environment from slot 0 of fn desc.
  __ LoadU64(r5, MemOperand(target_fun));
  // Load function pointer from slot 1 of fn desc.
  __ LoadU64(r8, MemOperand(target_fun, kSystemPointerSize));
  __ StoreReturnAddressAndCall(r8);

  // r9 and r13 are used to store argc and argv on z/OS instead
  // of r6 and r8 since r6 is not callee saved.
  __ mov(r6, r9);
  __ mov(r8, r13);

  // Shuffler arguments based on result_size to match XPLINK ABI
  if (result_size == 1) {
    __ mov(r2, r3);
  } else if (result_size == 2) {
    __ mov(r3, r2);
    __ mov(r2, r1);
  } else {
    __ mov(r4, r3);
    __ mov(r3, r2);
    __ mov(r2, r1);
  }
#else
  __ StoreReturnAddressAndCall(target_fun);

  // If return value is on the stack, pop it to registers.
  if (needs_return_buffer) {
    __ mov(r2, r8);
    __ LoadU64(r3, MemOperand(r2, kSystemPointerSize));
    __ LoadU64(r2, MemOperand(r2));
  }
#endif

  // Check result for exception sentinel.
  Label exception_returned;
  __ CompareRoot(r2, RootIndex::kException);
  __ beq(&exception_returned, Label::kNear);

  // Check that there is no exception, otherwise we
  // should have returned the exception sentinel.
  if (v8_flags.debug_code) {
    Label okay;
    ER exception_address =
        ER::Create(IsolateAddressId::kExceptionAddress, masm->isolate());
    __ LoadU64(scratch,
               __ ExternalReferenceAsOperand(exception_address, no_reg));
    __ CompareRoot(scratch, RootIndex::kTheHoleValue);
    // Cannot use check here as it attempts to generate call into runtime.
    __ beq(&okay, Label::kNear);
    __ stop();
    __ bind(&okay);
  }

  // Exit C frame and return.
  // r2:r3: result
  // sp: stack pointer
  // fp: frame pointer
  // r6: still holds argc (C caller-saved).
  __ LeaveExitFrame(scratch);
  if (argv_mode == ArgvMode::kStack) {
    DCHECK(!AreAliased(scratch, argc_sav));
    __ ShiftLeftU64(scratch, argc_sav, Operand(kSystemPointerSizeLog2));
    __ AddS64(sp, sp, scratch);
  }

  __ b(r14);

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

  // Ask the runtime for help to determine the handler. This will set r3 to
  // contain the current exception, don't clobber it.
  {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ PrepareCallCFunction(3, 0, r2);
    __ mov(kCArgRegs[0], Operand::Zero());
    __ mov(kCArgRegs[1], Operand::Zero());
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
  __ CmpS64(cp, Operand::Zero());
  __ beq(&skip, Label::kNear);
  __ StoreU64(cp, MemOperand(fp, StandardFrameConstants::kContextOffset));
  __ bind(&skip);

  // Clear c_entry_fp, like we do in `LeaveExitFrame`.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, masm->isolate());
  __ mov(scratch, Operand::Zero());
  __ StoreU64(scratch,
              __ ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  // Compute the handler entry address and jump to it.
  __ LoadU64(scratch, __ ExternalReferenceAsOperand(
                          pending_handler_entrypoint_address, no_reg));
  __ Jump(scratch);
}

#if V8_ENABLE_WEBASSEMBLY
void Builtins::Generate_WasmHandleStackOverflow(MacroAssembler* masm) {
  __ Trap();
}
#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_DoubleToI(MacroAssembler* masm) {
  Label out_of_range, only_low, negate, done, fastpath_done;
  Register result_reg = r2;

  HardAbortSco
"""


```