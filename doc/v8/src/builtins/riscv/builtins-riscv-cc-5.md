Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/builtins/riscv/builtins-riscv.cc`. I need to identify the main functions and their roles within the V8 JavaScript engine, specifically for the RISC-V architecture.

Here's a breakdown of the functions and their purpose:

1. **`JSToWasmWrapperHelper`**: Handles calls from JavaScript to WebAssembly functions. It manages stack frames, argument passing, and potential promise handling for asynchronous WebAssembly calls.

2. **`Builtins::Generate_JSToWasmWrapperAsm`**: Generates assembly code for the standard JavaScript-to-WebAssembly wrapper.

3. **`Builtins::Generate_WasmReturnPromiseOnSuspendAsm`**: Generates assembly code for a wrapper that returns a promise when a WebAssembly function suspends.

4. **`Builtins::Generate_JSToWasmStressSwitchStacksAsm`**: Generates assembly code for a wrapper used for stress-testing stack switching in WebAssembly.

5. **`Builtins::Generate_CallApiCallbackImpl`**: Generates assembly code for calling native C++ functions (API callbacks) from JavaScript. It handles argument setup and context management.

6. **`Builtins::Generate_CallApiGetter`**: Generates assembly code for calling native C++ getter functions associated with JavaScript objects. It sets up the necessary arguments for the getter callback.

7. **`Builtins::Generate_DirectCEntry`**: Generates assembly code for making direct calls to C functions from generated code, ensuring safety during garbage collection.

8. **`Generate_DeoptimizationEntry`**:  A template function (used by the following two) that generates assembly code for handling deoptimization, the process of reverting from optimized code back to interpreter or baseline code.

9. **`Builtins::Generate_DeoptimizationEntry_Eager`**: Generates assembly code for eager deoptimization.

10. **`Builtins::Generate_DeoptimizationEntry_Lazy`**: Generates assembly code for lazy deoptimization.

11. **`Generate_BaselineOrInterpreterEntry`**: A template function (used by the following three) that generates assembly code to enter either baseline-compiled code or the interpreter, potentially performing on-stack replacement (OSR).

12. **`Builtins::Generate_BaselineOrInterpreterEnterAtBytecode`**: Generates assembly code to enter baseline or interpreter at a specific bytecode offset.

13. **`Builtins::Generate_BaselineOrInterpreterEnterAtNextBytecode`**: Generates assembly code to enter baseline or interpreter at the next bytecode offset.

14. **`Builtins::Generate_InterpreterOnStackReplacement_ToBaseline`**: Generates assembly code for transitioning from the interpreter to baseline code during on-stack replacement.

15. **`Builtins::Generate_RestartFrameTrampoline`**: Generates assembly code for restarting an interpreted function call after its stack frame has been dropped.

I will now formulate the summary, provide JavaScript examples where applicable, explain code logic with assumptions, and illustrate common user errors.
`v8/src/builtins/riscv/builtins-riscv.cc` 是 V8 JavaScript 引擎中针对 RISC-V 架构的内置函数实现文件。它的主要功能是提供一些底层的、性能关键的操作，用于支持 JavaScript 和 WebAssembly 的执行。

根据代码内容，可以归纳出以下主要功能：

1. **JavaScript 到 WebAssembly 的调用包装器 (JSToWasmWrapper)**:
    *   允许 JavaScript 代码调用 WebAssembly 模块导出的函数。
    *   处理参数传递、上下文切换以及可能的异步调用（通过 Promise）。
    *   支持在 WebAssembly 调用期间进行栈切换 (stack switching)，用于测试和调试。
    *   针对不同的调用模式生成不同的包装器，例如：标准调用、返回 Promise 的异步调用、压力测试栈切换的调用。

    **JavaScript 示例:**

    ```javascript
    // 假设 'wasmModule' 是一个已加载的 WebAssembly 模块实例
    const wasmFunction = wasmModule.exports.myFunction;
    const result = wasmFunction(10, 20); // 调用 WebAssembly 函数
    console.log(result);
    ```

    **代码逻辑推理:**

    *   **假设输入:** 一个 WebAssembly 模块实例和一个要调用的导出函数，以及传递给该函数的参数。
    *   **输出:** WebAssembly 函数的返回值，或者一个代表异步操作的 Promise。

    **常见编程错误:**
    *   传递给 WebAssembly 函数的参数类型与函数签名不匹配。
    *   在异步 WebAssembly 调用完成之前就尝试访问结果。

2. **调用 API 回调 (CallApiCallback)**:
    *   用于从 JavaScript 中调用由 C++ 实现的 API 回调函数。
    *   设置 `FunctionCallbackInfo` 对象，其中包含回调函数的参数、接收者、上下文等信息。
    *   支持不同的调用模式，例如：通用模式、优化模式（带或不带性能分析）。

    **JavaScript 示例:**

    ```javascript
    // 假设我们注册了一个名为 'myCallback' 的 C++ API 回调函数
    function callNativeFunction(obj) {
      // 当访问 obj 的某个属性时，可能会触发 myCallback
      console.log(obj.someProperty);
    }

    const myObject = {};
    // ... (假设通过某种方式将 C++ 回调与 myObject 的属性关联)
    callNativeFunction(myObject);
    ```

    **代码逻辑推理:**

    *   **假设输入:** 一个指向 C++ 回调函数的指针，要传递给回调的参数，接收者对象，以及一些元数据（如 `FunctionTemplateInfo`）。
    *   **输出:** C++ 回调函数的返回值，该返回值会被转换回 JavaScript 值。

    **常见编程错误:**
    *   C++ 回调函数中的逻辑错误导致程序崩溃或产生意外结果。
    *   在回调函数中错误地操作 V8 的内部结构。

3. **调用 API Getter (CallApiGetter)**:
    *   专门用于调用 C++ 实现的属性 getter 函数。
    *   设置 `PropertyCallbackInfo` 对象，包含属性名、接收者、持有者等信息。

    **JavaScript 示例:**

    ```javascript
    const myObject = {
      get myProperty() {
        // 这里的 getter 实际上是由 C++ 代码提供的
        return 'Value from C++';
      }
    };
    console.log(myObject.myProperty); // 触发 C++ getter
    ```

    **代码逻辑推理:**

    *   **假设输入:** 一个指向 C++ getter 函数的指针，接收者对象，持有者对象，以及一些元数据（如 `AccessorInfo`）。
    *   **输出:** C++ getter 函数返回的属性值。

    **常见编程错误:**
    *   C++ getter 函数中可能存在的副作用导致程序状态异常。
    *   Getter 函数抛出异常而没有被 JavaScript 代码捕获。

4. **直接 C 入口 (DirectCEntry)**:
    *   提供了一种从 V8 生成的代码直接调用 C 函数的机制。
    *   主要目的是为了允许在可能触发垃圾回收的情况下安全地调用 C 函数。
    *   通过将返回地址保存在栈上，GC 可以正确地更新该地址，即使代码在 GC 过程中被移动。

    **代码逻辑推理:**

    *   **假设输入:** 一个指向要调用的 C 函数的指针。
    *   **输出:** C 函数的返回值。

    **常见编程错误:**
    *   C 函数的参数传递错误。
    *   C 函数中可能存在的内存泄漏或资源管理问题。

5. **反优化入口 (DeoptimizationEntry)**:
    *   处理代码从优化状态回退到非优化状态（解释器或基线代码）。
    *   保存当前寄存器状态和 FPU 寄存器。
    *   创建一个 `Deoptimizer` 对象，用于管理反优化过程。
    *   将当前帧的信息复制到 `FrameDescription` 中。
    *   计算并恢复到反优化后的帧状态。
    *   存在 eager（立即）和 lazy（延迟）两种反优化模式。

    **代码逻辑推理:**

    *   **假设输入:** 当前执行的代码对象和栈帧状态。
    *   **输出:**  程序执行流跳转到解释器或基线代码的相应位置。

    **常见编程错误:**
    *   反优化过程中的逻辑错误可能导致程序崩溃或状态不一致。

6. **基线代码或解释器入口 (BaselineOrInterpreterEntry)**:
    *   用于进入函数的基线编译版本或解释器。
    *   检查是否存在基线代码。如果存在，则尝试进入基线代码执行；否则，进入解释器。
    *   支持在栈上替换 (OSR - On-Stack Replacement)，将正在解释执行的函数切换到基线代码执行。

    **代码逻辑推理:**

    *   **假设输入:** 一个函数对象。
    *   **输出:** 程序执行流跳转到函数的基线代码入口点或解释器入口点。

    **常见编程错误:**
    *   基线代码生成中的错误可能导致程序在进入基线代码后崩溃。

7. **重启帧跳板 (RestartFrameTrampoline)**:
    *   用于在函数帧被丢弃后重新启动函数的执行。
    *   通常发生在异常处理或其他控制流转移之后。

    **代码逻辑推理:**

    *   **假设输入:** 一个被丢弃的函数帧。
    *   **输出:** 重新调用该函数。

    **常见编程错误:**
    *   在帧被丢弃后尝试访问帧上的数据可能导致错误。

**归纳一下 `v8/src/builtins/riscv/builtins-riscv.cc` 的功能:**

该文件包含了 V8 引擎在 RISC-V 架构上执行 JavaScript 和 WebAssembly 代码的关键底层 built-in 函数的实现。这些 built-in 函数负责处理 JavaScript 和 WebAssembly 之间的互操作、调用原生 C++ 代码、处理代码的优化和反优化，以及在解释器和编译代码之间切换。它们是 V8 引擎高性能执行代码的基础组成部分。

**关于文件扩展名 `.tq`:**

如果 `v8/src/builtins/riscv/builtins-riscv.cc` 以 `.tq` 结尾，那么它将是一个 **Torque** 源代码文件。Torque 是 V8 用于定义 built-in 函数的领域特定语言。Torque 代码会被编译成 C++ 代码。由于这里的文件名是 `.cc`，所以它是直接用 C++ 编写的。

### 提示词
```
这是目录为v8/src/builtins/riscv/builtins-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/riscv/builtins-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
set));
    __ LoadWord(
        a0, MemOperand(fp, JSToWasmWrapperFrameConstants::kImplicitArgOffset));
  }
  {
    UseScratchRegisterScope temps(masm);
    GetContextFromImplicitArg(masm, a0, temps.Acquire());
  }
  __ CallBuiltin(Builtin::kJSToWasmHandleReturns);

  Label return_promise;
  if (stack_switch) {
    SwitchBackAndReturnPromise(masm, mode, &return_promise);
  }
  __ bind(&suspend);

  __ LeaveFrame(stack_switch ? StackFrame::STACK_SWITCH
                             : StackFrame::JS_TO_WASM);
  // Despite returning to the different location for regular and stack switching
  // versions, incoming argument count matches both cases:
  // instance and result array without suspend or
  // or promise resolve/reject params for callback.
  constexpr int64_t stack_arguments_in = 2;
  // __ DropArguments(stack_arguments_in);
  __ AddWord(sp, sp, Operand(stack_arguments_in * kSystemPointerSize));
  __ Ret();

  // Catch handler for the stack-switching wrapper: reject the promise with the
  // thrown exception.
  if (mode == wasm::kPromise) {
    GenerateExceptionHandlingLandingPad(masm, &return_promise);
  }
}
}  // namespace

void Builtins::Generate_JSToWasmWrapperAsm(MacroAssembler* masm) {
  JSToWasmWrapperHelper(masm, wasm::kNoPromise);
}
void Builtins::Generate_WasmReturnPromiseOnSuspendAsm(MacroAssembler* masm) {
  UseScratchRegisterScope temps(masm);
  temps.Include(t1, t2);
  DCHECK(!AreAliased(WasmJSToWasmWrapperDescriptor::WrapperBufferRegister(), t1,
                     t2));
  JSToWasmWrapperHelper(masm, wasm::kPromise);
}
void Builtins::Generate_JSToWasmStressSwitchStacksAsm(MacroAssembler* masm) {
  UseScratchRegisterScope temps(masm);
  temps.Include(t1, t2);
  DCHECK(!AreAliased(WasmJSToWasmWrapperDescriptor::WrapperBufferRegister(), t1,
                     t2));
  JSToWasmWrapperHelper(masm, wasm::kStressSwitch);
}

void Builtins::Generate_CallApiCallbackImpl(MacroAssembler* masm,
                                            CallApiCallbackMode mode) {
  // ----------- S t a t e -------------
  // CallApiCallbackMode::kOptimizedNoProfiling/kOptimized modes:
  //  -- a1                  : api function address
  // Both modes:
  //  -- a2                  : arguments count
  //  -- a3                  : FunctionTemplateInfo
  //  -- a0                  : holder
  //  -- cp                  : context
  //  -- sp[0]               : receiver
  //  -- sp[8]               : first argument
  //  -- ...
  //  -- sp[(argc) * 8]      : last argument
  // -----------------------------------
  Register function_callback_info_arg = kCArgRegs[0];

  Register api_function_address = no_reg;
  Register argc = no_reg;
  Register func_templ = no_reg;
  Register holder = no_reg;
  Register topmost_script_having_context = no_reg;
  Register scratch = t0;

  switch (mode) {
    case CallApiCallbackMode::kGeneric:
      topmost_script_having_context = CallApiCallbackGenericDescriptor::
          TopmostScriptHavingContextRegister();
      argc = CallApiCallbackGenericDescriptor::ActualArgumentsCountRegister();
      func_templ =
          CallApiCallbackGenericDescriptor::FunctionTemplateInfoRegister();
      holder = CallApiCallbackGenericDescriptor::HolderRegister();
      break;

    case CallApiCallbackMode::kOptimizedNoProfiling:
    case CallApiCallbackMode::kOptimized:
      // Caller context is always equal to current context because we don't
      // inline Api calls cross-context.
      topmost_script_having_context = kContextRegister;
      api_function_address =
          CallApiCallbackOptimizedDescriptor::ApiFunctionAddressRegister();
      argc = CallApiCallbackOptimizedDescriptor::ActualArgumentsCountRegister();
      func_templ =
          CallApiCallbackOptimizedDescriptor::FunctionTemplateInfoRegister();
      holder = CallApiCallbackOptimizedDescriptor::HolderRegister();
      break;
  }
  DCHECK(!AreAliased(api_function_address, topmost_script_having_context, argc,
                     holder, func_templ, scratch));

  using FCA = FunctionCallbackArguments;
  using ER = ExternalReference;
  using FC = ApiCallbackExitFrameConstants;

  static_assert(FCA::kArgsLength == 6);
  static_assert(FCA::kNewTargetIndex == 5);
  static_assert(FCA::kTargetIndex == 4);
  static_assert(FCA::kReturnValueIndex == 3);
  static_assert(FCA::kContextIndex == 2);
  static_assert(FCA::kIsolateIndex == 1);
  static_assert(FCA::kHolderIndex == 0);

  // Set up FunctionCallbackInfo's implicit_args on the stack as follows:
  // Target state:
  //   sp[0 * kSystemPointerSize]: kHolder   <= FCA::implicit_args_
  //   sp[1 * kSystemPointerSize]: kIsolate
  //   sp[2 * kSystemPointerSize]: kContext
  //   sp[3 * kSystemPointerSize]: undefined (kReturnValue)
  //   sp[4 * kSystemPointerSize]: kData
  //   sp[5 * kSystemPointerSize]: undefined (kNewTarget)
  // Existing state:
  //   sp[6 * kSystemPointerSize]:            <= FCA:::values_

  __ StoreRootRelative(IsolateData::topmost_script_having_context_offset(),
                       topmost_script_having_context);
  if (mode == CallApiCallbackMode::kGeneric) {
    api_function_address = ReassignRegister(topmost_script_having_context);
  }
  // Reserve space on the stack.
  static constexpr int kStackSize = FCA::kArgsLength;
  static_assert(kStackSize % 2 == 0);
  __ SubWord(sp, sp, Operand(kStackSize * kSystemPointerSize));

  // kHolder.
  __ StoreWord(holder, MemOperand(sp, FCA::kHolderIndex * kSystemPointerSize));

  // kIsolate.
  __ li(scratch, ER::isolate_address());
  __ StoreWord(scratch,
               MemOperand(sp, FCA::kIsolateIndex * kSystemPointerSize));

  // kContext
  __ StoreWord(cp, MemOperand(sp, FCA::kContextIndex * kSystemPointerSize));

  // kReturnValue
  __ LoadRoot(scratch, RootIndex::kUndefinedValue);
  __ StoreWord(scratch,
               MemOperand(sp, FCA::kReturnValueIndex * kSystemPointerSize));

  // kTarget.
  __ StoreWord(func_templ,
               MemOperand(sp, FCA::kTargetIndex * kSystemPointerSize));

  // kNewTarget.
  __ StoreWord(scratch,
               MemOperand(sp, FCA::kNewTargetIndex * kSystemPointerSize));

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  if (mode == CallApiCallbackMode::kGeneric) {
    __ LoadExternalPointerField(
        api_function_address,
        FieldMemOperand(func_templ,
                        FunctionTemplateInfo::kMaybeRedirectedCallbackOffset),
        kFunctionTemplateInfoCallbackTag);
  }

  __ EnterExitFrame(scratch, FC::getExtraSlotsCountFrom<ExitFrameConstants>(),
                    StackFrame::API_CALLBACK_EXIT);
  MemOperand argc_operand = MemOperand(fp, FC::kFCIArgcOffset);
  {
    ASM_CODE_COMMENT_STRING(masm, "Initialize v8::FunctionCallbackInfo");
    // FunctionCallbackInfo::length_.
    // TODO(ishell): pass JSParameterCount(argc) to simplify things on the
    // caller end.
    __ StoreWord(argc, argc_operand);
    // FunctionCallbackInfo::implicit_args_.
    __ AddWord(scratch, fp, Operand(FC::kImplicitArgsArrayOffset));
    __ StoreWord(scratch, MemOperand(fp, FC::kFCIImplicitArgsOffset));
    // FunctionCallbackInfo::values_ (points at JS arguments on the stack).
    __ AddWord(scratch, fp, Operand(FC::kFirstArgumentOffset));
    __ StoreWord(scratch, MemOperand(fp, FC::kFCIValuesOffset));
  }
  __ RecordComment("v8::FunctionCallback's argument");
  __ AddWord(function_callback_info_arg, fp,
             Operand(FC::kFunctionCallbackInfoOffset));
  DCHECK(!AreAliased(api_function_address, function_callback_info_arg));
  ExternalReference thunk_ref = ER::invoke_function_callback(mode);
  Register no_thunk_arg = no_reg;
  MemOperand return_value_operand = MemOperand(fp, FC::kReturnValueOffset);
  static constexpr int kSlotsToDropOnReturn =
      FC::kFunctionCallbackInfoArgsLength + kJSArgcReceiverSlots;
  const bool with_profiling =
      mode != CallApiCallbackMode::kOptimizedNoProfiling;
  CallApiFunctionAndReturn(masm, with_profiling, api_function_address,
                           thunk_ref, no_thunk_arg, kSlotsToDropOnReturn,
                           &argc_operand, return_value_operand);
}

void Builtins::Generate_CallApiGetter(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- cp                  : context
  //  -- a1                  : receiver
  //  -- a3                  : accessor info
  //  -- a0                  : holder
  // -----------------------------------

  Register name_arg = kCArgRegs[0];
  Register property_callback_info_arg = kCArgRegs[1];

  Register api_function_address = kCArgRegs[2];

  Register receiver = ApiGetterDescriptor::ReceiverRegister();
  Register holder = ApiGetterDescriptor::HolderRegister();
  Register callback = ApiGetterDescriptor::CallbackRegister();
  Register scratch = a4;
  DCHECK(!AreAliased(receiver, holder, callback, scratch));

  // Build v8::PropertyCallbackInfo::args_ array on the stack and push property
  // name below the exit frame to make GC aware of them.
  using PCA = PropertyCallbackArguments;
  using ER = ExternalReference;
  using FC = ApiAccessorExitFrameConstants;
  static_assert(PCA::kPropertyKeyIndex == 0);
  static_assert(PCA::kShouldThrowOnErrorIndex == 1);
  static_assert(PCA::kHolderIndex == 2);
  static_assert(PCA::kIsolateIndex == 3);
  static_assert(PCA::kHolderV2Index == 4);
  static_assert(PCA::kReturnValueIndex == 5);
  static_assert(PCA::kDataIndex == 6);
  static_assert(PCA::kThisIndex == 7);
  static_assert(PCA::kArgsLength == 8);
  // Set up v8::PropertyCallbackInfo's (PCI) args_ on the stack as follows:
  // Target state:
  //   sp[0 * kSystemPointerSize]: name                      <= PCI::args_
  //   sp[1 * kSystemPointerSize]: kShouldThrowOnErrorIndex
  //   sp[2 * kSystemPointerSize]: kHolderIndex
  //   sp[3 * kSystemPointerSize]: kIsolateIndex
  //   sp[4 * kSystemPointerSize]: kHolderV2Index
  //   sp[5 * kSystemPointerSize]: kReturnValueIndex
  //   sp[6 * kSystemPointerSize]: kDataIndex
  //   sp[7 * kSystemPointerSize]: kThisIndex / receiver
  __ SubWord(sp, sp, (PCA::kArgsLength)*kSystemPointerSize);
  __ StoreWord(receiver, MemOperand(sp, (PCA::kThisIndex)*kSystemPointerSize));
  __ LoadTaggedField(scratch,
                     FieldMemOperand(callback, AccessorInfo::kDataOffset));
  __ StoreWord(scratch, MemOperand(sp, (PCA::kDataIndex)*kSystemPointerSize));
  __ LoadRoot(scratch, RootIndex::kUndefinedValue);
  __ StoreWord(scratch,
               MemOperand(sp, (PCA::kReturnValueIndex)*kSystemPointerSize));
  __ StoreWord(zero_reg,
               MemOperand(sp, (PCA::kHolderV2Index)*kSystemPointerSize));
  __ li(scratch, ER::isolate_address());
  __ StoreWord(scratch,
               MemOperand(sp, (PCA::kIsolateIndex)*kSystemPointerSize));
  __ StoreWord(holder, MemOperand(sp, (PCA::kHolderIndex)*kSystemPointerSize));
  // should_throw_on_error -> false
  DCHECK_EQ(0, Smi::zero().ptr());
  __ StoreWord(
      zero_reg,
      MemOperand(sp, (PCA::kShouldThrowOnErrorIndex)*kSystemPointerSize));
  __ LoadTaggedField(scratch,
                     FieldMemOperand(callback, AccessorInfo::kNameOffset));
  __ StoreWord(scratch, MemOperand(sp, 0 * kSystemPointerSize));

  __ RecordComment("Load api_function_address");
  __ LoadExternalPointerField(
      api_function_address,
      FieldMemOperand(callback, AccessorInfo::kMaybeRedirectedGetterOffset),
      kAccessorInfoGetterTag);

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  __ EnterExitFrame(scratch, FC::getExtraSlotsCountFrom<ExitFrameConstants>(),
                    StackFrame::API_ACCESSOR_EXIT);
  __ RecordComment("Create v8::PropertyCallbackInfo object on the stack.");
  // property_callback_info_arg = v8::PropertyCallbackInfo&
  __ AddWord(property_callback_info_arg, fp, Operand(FC::kArgsArrayOffset));
  DCHECK(!AreAliased(api_function_address, property_callback_info_arg, name_arg,
                     callback, scratch));
#ifdef V8_ENABLE_DIRECT_HANDLE
  // name_arg = Local<Name>(name), name value was pushed to GC-ed stack space.
  // |name_arg| is already initialized above.
#else
  // name_arg = Local<Name>(&name), which is &args_array[kPropertyKeyIndex].
  static_assert(PCA::kPropertyKeyIndex == 0);
  __ mv(name_arg, property_callback_info_arg);
#endif

  ExternalReference thunk_ref = ER::invoke_accessor_getter_callback();
  // Pass AccessorInfo to thunk wrapper in case profiler or side-effect
  // checking is enabled.
  Register thunk_arg = callback;

  MemOperand return_value_operand = MemOperand(fp, FC::kReturnValueOffset);
  static constexpr int kSlotsToDropOnReturn =
      FC::kPropertyCallbackInfoArgsLength;
  MemOperand* const kUseStackSpaceConstant = nullptr;

  const bool with_profiling = true;
  CallApiFunctionAndReturn(masm, with_profiling, api_function_address,
                           thunk_ref, thunk_arg, kSlotsToDropOnReturn,
                           kUseStackSpaceConstant, return_value_operand);
}

void Builtins::Generate_DirectCEntry(MacroAssembler* masm) {
  // The sole purpose of DirectCEntry is for movable callers (e.g. any general
  // purpose InstructionStream object) to be able to call into C functions that
  // may trigger GC and thus move the caller.
  //
  // DirectCEntry places the return address on the stack (updated by the GC),
  // making the call GC safe. The irregexp backend relies on this.

  // Make place for arguments to fit C calling convention. Callers use
  // EnterExitFrame/LeaveExitFrame so they handle stack restoring and we don't
  // have to do that here. Any caller must drop kCArgsSlotsSize stack space
  // after the call.
  __ AddWord(sp, sp, -kCArgsSlotsSize);

  __ StoreWord(ra,
               MemOperand(sp, kCArgsSlotsSize));  // Store the return address.
  __ Call(t6);                                    // Call the C++ function.
  __ LoadWord(t6, MemOperand(sp, kCArgsSlotsSize));  // Return to calling code.

  if (v8_flags.debug_code && v8_flags.enable_slow_asserts) {
    // In case of an error the return address may point to a memory area
    // filled with kZapValue by the GC. Dereference the address and check for
    // this.
    __ Uld(a4, MemOperand(t6));
    __ Assert(ne, AbortReason::kReceivedInvalidReturnAddress, a4,
              Operand(kZapValue));
  }

  __ Jump(t6);
}

namespace {

// This code tries to be close to ia32 code so that any changes can be
// easily ported.
void Generate_DeoptimizationEntry(MacroAssembler* masm,
                                  DeoptimizeKind deopt_kind) {
  Isolate* isolate = masm->isolate();

  // Unlike on ARM we don't save all the registers, just the useful ones.
  // For the rest, there are gaps on the stack, so the offsets remain the same.
  const int kNumberOfRegisters = Register::kNumRegisters;

  RegList restored_regs = kJSCallerSaved | kCalleeSaved;
  RegList saved_regs = restored_regs | sp | ra;

  const int kDoubleRegsSize = kDoubleSize * DoubleRegister::kNumRegisters;

  // Save all double FPU registers before messing with them.
  __ SubWord(sp, sp, Operand(kDoubleRegsSize));
  const RegisterConfiguration* config = RegisterConfiguration::Default();
  for (int i = 0; i < config->num_allocatable_double_registers(); ++i) {
    int code = config->GetAllocatableDoubleCode(i);
    const DoubleRegister fpu_reg = DoubleRegister::from_code(code);
    int offset = code * kDoubleSize;
    __ StoreDouble(fpu_reg, MemOperand(sp, offset));
  }

  // Push saved_regs (needed to populate FrameDescription::registers_).
  // Leave gaps for other registers.
  __ SubWord(sp, sp, kNumberOfRegisters * kSystemPointerSize);
  for (int16_t i = kNumberOfRegisters - 1; i >= 0; i--) {
    if ((saved_regs.bits() & (1 << i)) != 0) {
      __ StoreWord(ToRegister(i), MemOperand(sp, kSystemPointerSize * i));
    }
  }

  __ li(a2,
        ExternalReference::Create(IsolateAddressId::kCEntryFPAddress, isolate));
  __ StoreWord(fp, MemOperand(a2));

  const int kSavedRegistersAreaSize =
      (kNumberOfRegisters * kSystemPointerSize) + kDoubleRegsSize;

  // Get the address of the location in the code object (a2) (return
  // address for lazy deoptimization) and compute the fp-to-sp delta in
  // register a4.
  __ Move(a2, ra);
  __ AddWord(a3, sp, Operand(kSavedRegistersAreaSize));

  __ SubWord(a3, fp, a3);

  // Allocate a new deoptimizer object.
  __ PrepareCallCFunction(5, a4);
  // Pass five arguments, according to n64 ABI.
  __ Move(a0, zero_reg);
  Label context_check;
  __ LoadWord(a1,
              MemOperand(fp, CommonFrameConstants::kContextOrFrameTypeOffset));
  __ JumpIfSmi(a1, &context_check);
  __ LoadWord(a0, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ bind(&context_check);
  __ li(a1, Operand(static_cast<int64_t>(deopt_kind)));
  // a2: code object address
  // a3: fp-to-sp delta
  __ li(a4, ExternalReference::isolate_address());

  // Call Deoptimizer::New().
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::new_deoptimizer_function(), 5);
  }

  // Preserve "deoptimizer" object in register a0 and get the input
  // frame descriptor pointer to a1 (deoptimizer->input_);
  __ LoadWord(a1, MemOperand(a0, Deoptimizer::input_offset()));

  // Copy core registers into FrameDescription::registers_[kNumRegisters].
  DCHECK_EQ(Register::kNumRegisters, kNumberOfRegisters);
  for (int i = 0; i < kNumberOfRegisters; i++) {
    int offset =
        (i * kSystemPointerSize) + FrameDescription::registers_offset();
    if ((saved_regs.bits() & (1 << i)) != 0) {
      __ LoadWord(a2, MemOperand(sp, i * kSystemPointerSize));
      __ StoreWord(a2, MemOperand(a1, offset));
    } else if (v8_flags.debug_code) {
      __ li(a2, kDebugZapValue);
      __ StoreWord(a2, MemOperand(a1, offset));
    }
  }

  int double_regs_offset = FrameDescription::double_registers_offset();
  // int simd128_regs_offset = FrameDescription::simd128_registers_offset();
  //  Copy FPU registers to
  //  double_registers_[DoubleRegister::kNumAllocatableRegisters]
  for (int i = 0; i < config->num_allocatable_double_registers(); ++i) {
    int code = config->GetAllocatableDoubleCode(i);
    int dst_offset = code * kDoubleSize + double_regs_offset;
    int src_offset =
        code * kDoubleSize + kNumberOfRegisters * kSystemPointerSize;
    __ LoadDouble(ft0, MemOperand(sp, src_offset));
    __ StoreDouble(ft0, MemOperand(a1, dst_offset));
  }
  // TODO(riscv): Add Simd128 copy

  // Remove the saved registers from the stack.
  __ AddWord(sp, sp, Operand(kSavedRegistersAreaSize));

  // Compute a pointer to the unwinding limit in register a2; that is
  // the first stack slot not part of the input frame.
  __ LoadWord(a2, MemOperand(a1, FrameDescription::frame_size_offset()));
  __ AddWord(a2, a2, sp);

  // Unwind the stack down to - but not including - the unwinding
  // limit and copy the contents of the activation frame to the input
  // frame description.
  __ AddWord(a3, a1, Operand(FrameDescription::frame_content_offset()));
  Label pop_loop;
  Label pop_loop_header;
  __ BranchShort(&pop_loop_header);
  __ bind(&pop_loop);
  __ pop(a4);
  __ StoreWord(a4, MemOperand(a3, 0));
  __ AddWord(a3, a3, kSystemPointerSize);
  __ bind(&pop_loop_header);
  __ Branch(&pop_loop, ne, a2, Operand(sp), Label::Distance::kNear);
  // Compute the output frame in the deoptimizer.
  __ push(a0);  // Preserve deoptimizer object across call.
  // a0: deoptimizer object; a1: scratch.
  __ PrepareCallCFunction(1, a1);
  // Call Deoptimizer::ComputeOutputFrames().
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::compute_output_frames_function(), 1);
  }
  __ pop(a0);  // Restore deoptimizer object (class Deoptimizer).

  __ LoadWord(sp, MemOperand(a0, Deoptimizer::caller_frame_top_offset()));

  // Replace the current (input) frame with the output frames.
  Label outer_push_loop, inner_push_loop, outer_loop_header, inner_loop_header;
  // Outer loop state: a4 = current "FrameDescription** output_",
  // a1 = one past the last FrameDescription**.
  __ Lw(a1, MemOperand(a0, Deoptimizer::output_count_offset()));
  __ LoadWord(a4,
              MemOperand(a0, Deoptimizer::output_offset()));  // a4 is output_.
  __ CalcScaledAddress(a1, a4, a1, kSystemPointerSizeLog2);
  __ BranchShort(&outer_loop_header);
  __ bind(&outer_push_loop);
  // Inner loop state: a2 = current FrameDescription*, a3 = loop index.
  __ LoadWord(a2, MemOperand(a4, 0));  // output_[ix]
  __ LoadWord(a3, MemOperand(a2, FrameDescription::frame_size_offset()));
  __ BranchShort(&inner_loop_header);
  __ bind(&inner_push_loop);
  __ SubWord(a3, a3, Operand(kSystemPointerSize));
  __ AddWord(a6, a2, Operand(a3));
  __ LoadWord(a7, MemOperand(a6, FrameDescription::frame_content_offset()));
  __ push(a7);
  __ bind(&inner_loop_header);
  __ Branch(&inner_push_loop, ne, a3, Operand(zero_reg));

  __ AddWord(a4, a4, Operand(kSystemPointerSize));
  __ bind(&outer_loop_header);
  __ Branch(&outer_push_loop, lt, a4, Operand(a1));

  __ LoadWord(a1, MemOperand(a0, Deoptimizer::input_offset()));
  for (int i = 0; i < config->num_allocatable_double_registers(); ++i) {
    int code = config->GetAllocatableDoubleCode(i);
    const DoubleRegister fpu_reg = DoubleRegister::from_code(code);
    int src_offset = code * kDoubleSize + double_regs_offset;
    __ LoadDouble(fpu_reg, MemOperand(a1, src_offset));
  }

  // Push pc and continuation from the last output frame.
  __ LoadWord(a6, MemOperand(a2, FrameDescription::pc_offset()));
  __ push(a6);
  __ LoadWord(a6, MemOperand(a2, FrameDescription::continuation_offset()));
  __ push(a6);

  // Technically restoring 't3' should work unless zero_reg is also restored
  // but it's safer to check for this.
  DCHECK(!(restored_regs.has(t3)));
  // Restore the registers from the last output frame.
  __ Move(t3, a2);
  for (int i = kNumberOfRegisters - 1; i >= 0; i--) {
    int offset =
        (i * kSystemPointerSize) + FrameDescription::registers_offset();
    if ((restored_regs.bits() & (1 << i)) != 0) {
      __ LoadWord(ToRegister(i), MemOperand(t3, offset));
    }
  }

  __ pop(t6);  // Get continuation, leave pc on stack.
  __ pop(ra);
  Label end;
  __ Branch(&end, eq, t6, Operand(zero_reg));
  __ Jump(t6);
  __ bind(&end);
  __ Ret();
  __ stop();
}

}  // namespace

void Builtins::Generate_DeoptimizationEntry_Eager(MacroAssembler* masm) {
  Generate_DeoptimizationEntry(masm, DeoptimizeKind::kEager);
}

void Builtins::Generate_DeoptimizationEntry_Lazy(MacroAssembler* masm) {
  Generate_DeoptimizationEntry(masm, DeoptimizeKind::kLazy);
}

namespace {

// Restarts execution either at the current or next (in execution order)
// bytecode. If there is baseline code on the shared function info, converts an
// interpreter frame into a baseline frame and continues execution in baseline
// code. Otherwise execution continues with bytecode.
void Generate_BaselineOrInterpreterEntry(MacroAssembler* masm,
                                         bool next_bytecode,
                                         bool is_osr = false) {
  Label start;
  __ bind(&start);

  // Get function from the frame.
  Register closure = a1;
  __ LoadWord(closure, MemOperand(fp, StandardFrameConstants::kFunctionOffset));

  // Get the InstructionStream object from the shared function info.
  Register code_obj = s1;
  __ LoadTaggedField(
      code_obj,
      FieldMemOperand(closure, JSFunction::kSharedFunctionInfoOffset));

  if (is_osr) {
    ResetSharedFunctionInfoAge(masm, code_obj);
  }

  __ LoadTrustedPointerField(
      code_obj,
      FieldMemOperand(code_obj, SharedFunctionInfo::kTrustedFunctionDataOffset),
      kUnknownIndirectPointerTag);

  // Check if we have baseline code. For OSR entry it is safe to assume we
  // always have baseline code.
  if (!is_osr) {
    Label start_with_baseline;
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ GetObjectType(code_obj, scratch, scratch);
    __ Branch(&start_with_baseline, eq, scratch, Operand(CODE_TYPE));

    // Start with bytecode as there is no baseline code.
    Builtin builtin = next_bytecode ? Builtin::kInterpreterEnterAtNextBytecode
                                    : Builtin::kInterpreterEnterAtBytecode;
    __ TailCallBuiltin(builtin);

    // Start with baseline code.
    __ bind(&start_with_baseline);
  } else if (v8_flags.debug_code) {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ GetObjectType(code_obj, scratch, scratch);
    __ Assert(eq, AbortReason::kExpectedBaselineData, scratch,
              Operand(CODE_TYPE));
  }
  if (v8_flags.debug_code) {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    AssertCodeIsBaseline(masm, code_obj, scratch);
  }

  // Load the feedback cell and vector.
  Register feedback_cell = a2;
  Register feedback_vector = t4;
  __ LoadTaggedField(feedback_cell,
                     FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  __ LoadTaggedField(
      feedback_vector,
      FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset));
  Label install_baseline_code;
  // Check if feedback vector is valid. If not, call prepare for baseline to
  // allocate it.
  {
    UseScratchRegisterScope temps(masm);
    Register type = temps.Acquire();
    __ GetObjectType(feedback_vector, type, type);
    __ Branch(&install_baseline_code, ne, type, Operand(FEEDBACK_VECTOR_TYPE));
  }
  // Save BytecodeOffset from the stack frame.
  __ SmiUntag(kInterpreterBytecodeOffsetRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  // Replace bytecode offset with feedback cell.
  static_assert(InterpreterFrameConstants::kBytecodeOffsetFromFp ==
                BaselineFrameConstants::kFeedbackCellFromFp);
  __ StoreWord(feedback_cell,
               MemOperand(fp, BaselineFrameConstants::kFeedbackCellFromFp));
  feedback_cell = no_reg;
  // Update feedback vector cache.
  static_assert(InterpreterFrameConstants::kFeedbackVectorFromFp ==
                BaselineFrameConstants::kFeedbackVectorFromFp);
  __ StoreWord(
      feedback_vector,
      MemOperand(fp, InterpreterFrameConstants::kFeedbackVectorFromFp));
  feedback_vector = no_reg;

  // Compute baseline pc for bytecode offset.
  ExternalReference get_baseline_pc_extref;
  if (next_bytecode || is_osr) {
    get_baseline_pc_extref =
        ExternalReference::baseline_pc_for_next_executed_bytecode();
  } else {
    get_baseline_pc_extref =
        ExternalReference::baseline_pc_for_bytecode_offset();
  }

  Register get_baseline_pc = a3;
  __ li(get_baseline_pc, get_baseline_pc_extref);

  // If the code deoptimizes during the implicit function entry stack interrupt
  // check, it will have a bailout ID of kFunctionEntryBytecodeOffset, which is
  // not a valid bytecode offset.
  // TODO(pthier): Investigate if it is feasible to handle this special case
  // in TurboFan instead of here.
  Label valid_bytecode_offset, function_entry_bytecode;
  if (!is_osr) {
    __ Branch(&function_entry_bytecode, eq, kInterpreterBytecodeOffsetRegister,
              Operand(BytecodeArray::kHeaderSize - kHeapObjectTag +
                      kFunctionEntryBytecodeOffset));
  }

  __ SubWord(kInterpreterBytecodeOffsetRegister,
             kInterpreterBytecodeOffsetRegister,
             (BytecodeArray::kHeaderSize - kHeapObjectTag));

  __ bind(&valid_bytecode_offset);
  // Get bytecode array from the stack frame.
  __ LoadWord(kInterpreterBytecodeArrayRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ Push(kInterpreterAccumulatorRegister);
  {
    __ Move(kCArgRegs[0], code_obj);
    __ Move(kCArgRegs[1], kInterpreterBytecodeOffsetRegister);
    __ Move(kCArgRegs[2], kInterpreterBytecodeArrayRegister);
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ PrepareCallCFunction(3, 0, a4);
    __ CallCFunction(get_baseline_pc, 3, 0);
  }
  __ LoadCodeInstructionStart(code_obj, code_obj, kJSEntrypointTag);
  __ AddWord(code_obj, code_obj, kReturnRegister0);
  __ Pop(kInterpreterAccumulatorRegister);

  if (is_osr) {
    // Reset the OSR loop nesting depth to disarm back edges.
    // TODO(pthier): Separate baseline Sparkplug from TF arming and don't disarm
    // Sparkplug here.
    __ LoadWord(
        kInterpreterBytecodeArrayRegister,
        MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
    Generate_OSREntry(masm, code_obj);
  } else {
    __ Jump(code_obj);
  }
  __ Trap();  // Unreachable.

  if (!is_osr) {
    __ bind(&function_entry_bytecode);
    // If the bytecode offset is kFunctionEntryOffset, get the start address of
    // the first bytecode.
    __ li(kInterpreterBytecodeOffsetRegister, Operand(0));
    if (next_bytecode) {
      __ li(get_baseline_pc,
            ExternalReference::baseline_pc_for_bytecode_offset());
    }
    __ Branch(&valid_bytecode_offset);
  }

  __ bind(&install_baseline_code);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(kInterpreterAccumulatorRegister);
    __ Push(closure);
    __ CallRuntime(Runtime::kInstallBaselineCode, 1);
    __ Pop(kInterpreterAccumulatorRegister);
  }
  // Retry from the start after installing baseline code.
  __ Branch(&start);
}

}  // namespace

void Builtins::Generate_BaselineOrInterpreterEnterAtBytecode(
    MacroAssembler* masm) {
  Generate_BaselineOrInterpreterEntry(masm, false);
}

void Builtins::Generate_BaselineOrInterpreterEnterAtNextBytecode(
    MacroAssembler* masm) {
  Generate_BaselineOrInterpreterEntry(masm, true);
}

void Builtins::Generate_InterpreterOnStackReplacement_ToBaseline(
    MacroAssembler* masm) {
  Generate_BaselineOrInterpreterEntry(masm, false, true);
}

void Builtins::Generate_RestartFrameTrampoline(MacroAssembler* masm) {
  // Frame is being dropped:
  // - Look up current function on the frame.
  // - Leave the frame.
  // - Restart the frame by calling the function.

  __ LoadWord(a1, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ LoadWord(a0, MemOperand(fp, StandardFrameConstants::kArgCOffset));

  // Pop return address and frame.
  __ LeaveFrame(StackFrame::INTERPRETED);

  __ li(a2, Operand(kDontAdaptArgumentsSentinel));

  __ InvokeFunction(a1, a2, a0, InvokeType::kJump);
}

#undef __

}  // namespace internal
}  // namespace v8
```