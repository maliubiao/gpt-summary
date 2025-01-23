Response: The user wants a summary of the C++ code provided, which is part of the `builtins-ia32.cc` file in the V8 JavaScript engine.

The code seems to implement various low-level functionalities related to interactions between JavaScript and WebAssembly, as well as other core runtime functionalities on the IA-32 architecture.

I need to identify the key functions and their purposes, and if they relate to JavaScript, provide a concise JavaScript example to illustrate the connection.

The request explicitly mentions this is part 3 of 4, so I should focus on the functionality within this specific code snippet.

Here's a breakdown of the code sections and their likely functions:

1. **`SwitchBackAndReturnPromise` and `GenerateExceptionHandlingLandingPad`**: These functions deal with the asynchronous nature of WebAssembly promises, handling successful returns and exceptions.
2. **`JSToWasmWrapperHelper`**: This is a crucial function responsible for setting up the environment when calling a WebAssembly function from JavaScript. It handles stack management, parameter passing, and calling the WebAssembly code.
3. **`Builtins::Generate_JSToWasmWrapperAsm`, `Builtins::Generate_WasmReturnPromiseOnSuspendAsm`, `Builtins::Generate_JSToWasmStressSwitchStacksAsm`**: These functions appear to be entry points for different variations of the `JSToWasmWrapperHelper`, likely for different use cases or optimization levels.
4. **`Builtins::Generate_WasmToJsWrapperAsm`**: This function handles the reverse scenario, setting up the environment when calling a JavaScript function from WebAssembly. It deals with stack manipulation and parameter passing.
5. **`Builtins::Generate_WasmTrapHandlerLandingPad`**: This function seems to be a simple handler for WebAssembly traps (runtime errors).
6. **`Builtins::Generate_WasmSuspend`**: This function implements the logic for suspending the execution of a WebAssembly function, likely related to asynchronous operations.
7. **`Generate_WasmResumeHelper`, `Builtins::Generate_WasmResume`, `Builtins::Generate_WasmReject`**: These functions deal with resuming a suspended WebAssembly function, either successfully (`Resume`) or due to an error (`Reject`).
8. **`Builtins::Generate_WasmOnStackReplace`**: This function is marked as "Only needed on x64", indicating it's not relevant for IA-32.
9. **`SwitchToTheCentralStackIfNeeded` and `SwitchFromTheCentralStackIfNeeded`**: These functions seem related to managing different stack segments, potentially for security or resource management.
10. **`Builtins::Generate_CEntry`**: This is a core function responsible for calling C++ functions from JavaScript (or other runtime contexts). It handles argument passing, stack setup, and exception handling.
11. **`Builtins::Generate_WasmHandleStackOverflow`**: This function handles stack overflow errors that might occur during WebAssembly execution, attempting to grow the stack or trigger a runtime error.
12. **`Builtins::Generate_DoubleToI`**: This function converts a JavaScript double-precision floating-point number to an integer.
13. **`Builtins::Generate_CallApiCallbackImpl`**: This function handles calling JavaScript API callbacks from native C++ code.
14. **`Builtins::Generate_CallApiGetter`**: This function handles calls to JavaScript API getters.
15. **`Builtins::Generate_DirectCEntry`**: Marked as "Unused on this architecture".
16. **`MemMoveEmitMainLoop`, `MemMoveEmitPopAndReturn`, `Builtins::Generate_MemMove`**: These functions implement a highly optimized memory copy routine.
17. **`Generate_DeoptimizationEntry`,**: This function is responsible for setting up the state when the JavaScript engine needs to fall back from optimized code to a less optimized version (deoptimization).

Now, I will structure the summary based on these identified functionalities and include JavaScript examples where applicable.
这个C++源代码文件 `v8/src/builtins/ia32/builtins-ia32.cc` 的第 3 部分主要包含以下功能：

**1. WebAssembly 与 JavaScript 的互操作 (JSToWasm)**

*   **`SwitchBackAndReturnPromise(MacroAssembler* masm, Register tmp, Register tmp2, wasm::Promise mode, Label* return_promise)`**:  处理从 WebAssembly 函数返回 Promise 的情况。它负责将 WebAssembly 函数的返回值作为参数传递给 JavaScript 的 Promise 的 fulfill 或 reject 内置函数，并将该 Promise 作为包装器的返回值。
*   **`GenerateExceptionHandlingLandingPad(MacroAssembler* masm, Label* return_promise)`**: 当 WebAssembly 代码抛出异常时，这个函数会被调用。它负责恢复栈状态，并将异常作为参数传递给 JavaScript 的 Promise 的 reject 内置函数。
*   **`JSToWasmWrapperHelper(MacroAssembler* masm, wasm::Promise mode)`**:  这是一个核心辅助函数，用于生成从 JavaScript 调用 WebAssembly 函数的包装器代码。它负责：
    *   设置栈帧 (`StackFrame::JS_TO_WASM` 或 `StackFrame::STACK_SWITCH`)。
    *   保存必要的寄存器和参数。
    *   在需要时切换栈（用于 Promise 或压力测试）。
    *   将 JavaScript 的参数传递给 WebAssembly 函数。
    *   调用 WebAssembly 函数。
    *   获取 WebAssembly 函数的返回值。
    *   调用 JavaScript 的内置函数 `kJSToWasmHandleReturns` 来处理返回值。
    *   处理 Promise 的返回情况。
*   **`Builtins::Generate_JSToWasmWrapperAsm(MacroAssembler* masm)`**:  生成用于直接调用 WebAssembly 函数的包装器代码（非 Promise）。
*   **`Builtins::Generate_WasmReturnPromiseOnSuspendAsm(MacroAssembler* masm)`**: 生成用于调用返回 Promise 的 WebAssembly 函数的包装器代码。
*   **`Builtins::Generate_JSToWasmStressSwitchStacksAsm(MacroAssembler* masm)`**: 生成用于压力测试栈切换的 WebAssembly 函数的包装器代码。

**JavaScript 示例 (JSToWasm):**

假设你有一个 WebAssembly 模块，其中导出一个函数 `add`，它接受两个整数并返回它们的和。你可以像这样从 JavaScript 调用它：

```javascript
async function loadAndRunWasm() {
  const response = await fetch('module.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);

  const result = instance.exports.add(5, 10);
  console.log(result); // 输出 15
}

loadAndRunWasm();
```

`JSToWasmWrapperHelper` 及其相关的 `Generate_*Asm` 函数就负责生成在 `instance.exports.add(5, 10)` 这一步实际执行的底层代码，包括参数的传递和返回值的处理。

**2. WebAssembly 调用 JavaScript (WasmToJs)**

*   **`Builtins::Generate_WasmToJsWrapperAsm(MacroAssembler* masm)`**: 生成从 WebAssembly 代码调用 JavaScript 函数的包装器代码。它负责：
    *   保存 WebAssembly 函数的参数到栈上。
    *   调用 JavaScript 的内置函数 `kWasmToJsWrapperCSA`，该内置函数会处理实际的 JavaScript 函数调用。

**JavaScript 示例 (WasmToJs):**

假设你的 WebAssembly 模块需要调用 JavaScript 中的 `console.log` 函数。你可能需要在 WebAssembly 模块的导入对象中提供 `console.log`。

```javascript
// JavaScript 代码
const importObject = {
  imports: {
    log: (value) => console.log("From WASM:", value),
  },
};

async function loadAndRunWasm() {
  const response = await fetch('module.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module, importObject);

  instance.exports.callJsLog(42); // 假设 WebAssembly 中有一个函数 callJsLog 调用了导入的 log 函数
}

loadAndRunWasm();
```

`Builtins::Generate_WasmToJsWrapperAsm` 负责生成当 WebAssembly 代码尝试调用导入的 `log` 函数时所执行的底层代码。

**3. WebAssembly 运行时支持**

*   **`Builtins::Generate_WasmTrapHandlerLandingPad(MacroAssembler* masm)`**:  生成一个用于处理 WebAssembly 陷阱 (trap) 的着陆点。当 WebAssembly 代码执行非法操作时（例如，越界内存访问），会跳转到这个位置。
*   **`Builtins::Generate_WasmSuspend(MacroAssembler* masm)`**:  实现 WebAssembly 的挂起 (suspend) 功能。当 WebAssembly 代码执行到挂起操作时，会调用此函数来保存当前状态并切换到另一个 continuation。
*   **`Generate_WasmResumeHelper(MacroAssembler* masm, wasm::OnResume on_resume)`**:  这是一个辅助函数，用于生成恢复 (resume) WebAssembly 执行的代码。它可以用于正常恢复 (`kContinue`) 或抛出异常 (`kThrow`)。
*   **`Builtins::Generate_WasmResume(MacroAssembler* masm)`**: 生成恢复 WebAssembly 执行的代码。
*   **`Builtins::Generate_WasmReject(MacroAssembler* masm)`**: 生成由于错误而拒绝 (reject) WebAssembly 挂起操作的代码。
*   **`Builtins::Generate_WasmOnStackReplace(MacroAssembler* masm)`**:  在 IA-32 架构上未使用，因为该功能主要用于 x64 架构上的栈替换优化。
*   **`SwitchToTheCentralStackIfNeeded(MacroAssembler* masm, int edi_slot_index)` 和 `SwitchFromTheCentralStackIfNeeded(MacroAssembler* masm)`**:  实现栈的切换，可能是为了隔离 WebAssembly 的执行栈。

**JavaScript 示例 (WebAssembly 运行时支持):**

WebAssembly 的 `suspend` 和 `resume` 功能通常与异步操作相关，例如使用 `WebAssembly.Suspender` API。

```javascript
// 假设你的 WebAssembly 模块导出了一个会挂起的函数
async function runWasmWithSuspend() {
  const response = await fetch('module_with_suspend.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);

  const suspender = instance.exports.startAsyncOperation(); // 假设这个函数会挂起

  // ... 等待某些事件发生 ...

  const result = suspender.resume("some result"); // 恢复执行
  console.log("Resumed with:", result);
}

runWasmWithSuspend();
```

`Builtins::Generate_WasmSuspend`, `Generate_WasmResumeHelper`, 和 `Builtins::Generate_WasmResume` 就负责实现 `suspender.resume()` 内部的底层操作。

**4. C++ 函数调用 (CEntry)**

*   **`Builtins::Generate_CEntry(MacroAssembler* masm, int result_size, ArgvMode argv_mode, bool builtin_exit_frame, bool switch_to_central_stack)`**:  生成从 JavaScript (或其他 V8 内部) 调用 C++ 函数的入口代码。它负责设置栈帧、传递参数、调用 C++ 函数，并处理返回值和异常。

**JavaScript 示例 (CEntry):**

虽然 JavaScript 代码本身不会直接调用 `CEntry` 生成的代码，但 V8 引擎内部的许多操作，例如调用内置函数或执行某些优化的 JavaScript 代码，最终可能会通过 `CEntry` 调用到 C++ 代码。

**5. WebAssembly 栈溢出处理**

*   **`Builtins::Generate_WasmHandleStackOverflow(MacroAssembler* masm)`**:  处理 WebAssembly 执行期间发生的栈溢出。它尝试增加栈的大小，如果无法增加，则会调用运行时错误处理函数。

**6. 类型转换**

*   **`Builtins::Generate_DoubleToI(MacroAssembler* masm)`**:  生成将 JavaScript 的双精度浮点数转换为整数的代码。

**JavaScript 示例 (DoubleToI):**

```javascript
const floatValue = 3.14;
const integerValue = Math.floor(floatValue); // 或使用其他转换方法
console.log(integerValue); // 输出 3
```

当 JavaScript 引擎执行类似 `Math.floor()` 这样的操作时，底层可能会调用 `Builtins::Generate_DoubleToI` 生成的代码来进行实际的类型转换。

**7. API 回调处理**

*   **`Builtins::Generate_CallApiCallbackImpl(MacroAssembler* masm, CallApiCallbackMode mode)`**: 生成用于调用 JavaScript API 回调函数的代码。这通常用于处理在 C++ 扩展中定义的回调函数。
*   **`Builtins::Generate_CallApiGetter(MacroAssembler* masm)`**: 生成用于调用 JavaScript API getter 的代码。

**JavaScript 示例 (API 回调):**

```javascript
// C++ 扩展代码中定义了一个模板
v8::Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate, myCallback);

// ...

void myCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // ... 在 C++ 中处理回调 ...
}
```

当 JavaScript 调用通过此模板创建的函数时，`Builtins::Generate_CallApiCallbackImpl` 生成的代码会被执行，以调用 C++ 中的 `myCallback` 函数。

**8. 内存操作**

*   **`Builtins::Generate_MemMove(MacroAssembler* masm)`**:  生成优化的内存移动 (copy) 代码。

**JavaScript 示例 (MemMove):**

虽然 JavaScript 本身没有直接的 `memmove` 函数，但在进行数组操作或底层数据处理时，V8 引擎内部可能会使用这个优化的 `memmove` 实现。

```javascript
const buffer = new ArrayBuffer(16);
const view = new Uint8Array(buffer);
view.set([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

// 模拟内存移动 (实际 JavaScript 不会直接调用 memmove)
// 将 buffer 中索引 2 开始的 8 个字节移动到索引 5 的位置
const sourceView = new Uint8Array(buffer, 2, 8);
const targetView = new Uint8Array(buffer, 5, 8);
targetView.set(sourceView);

console.log(Array.from(view));
// 输出类似于: [0, 1, 2, 3, 4, 2, 3, 4, 5, 6, 7, 8, 12, 13, 14, 15]
```

**9. 代码去优化入口**

*   **`Generate_DeoptimizationEntry(MacroAssembler* masm, DeoptimizeKind deopt_kind)`**:  生成代码去优化 (deoptimization) 的入口点。当 V8 引擎需要从优化的代码回退到未优化的代码时，会跳转到这个位置。

**总结**

总而言之，`v8/src/builtins/ia32/builtins-ia32.cc` 的第 3 部分包含了在 IA-32 架构上实现 V8 引擎核心功能的低级代码，特别是与 WebAssembly 和 JavaScript 之间的互操作、WebAssembly 运行时支持、C++ 函数调用、类型转换、API 回调处理、内存操作以及代码去优化相关的关键功能。 这些底层的汇编代码支撑着 JavaScript 和 WebAssembly 代码的执行。

### 提示词
```
这是目录为v8/src/builtins/ia32/builtins-ia32.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```
r_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferSigRepresentationArray +
              4));
  __ mov(
      MemOperand(
          new_wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferSigRepresentationArray +
              4),
      scratch);
}

void SwitchBackAndReturnPromise(MacroAssembler* masm, Register tmp,
                                Register tmp2, wasm::Promise mode,
                                Label* return_promise) {
  // The return value of the wasm function becomes the parameter of the
  // FulfillPromise builtin, and the promise is the return value of this
  // wrapper.

  static const Builtin_FulfillPromise_InterfaceDescriptor desc;
  static_assert(kReturnRegister0 == desc.GetRegisterParameter(0));

  Register promise = desc.GetRegisterParameter(0);
  Register return_value = desc.GetRegisterParameter(1);

  if (mode == wasm::kPromise) {
    __ mov(return_value, kReturnRegister0);
    __ LoadRoot(promise, RootIndex::kActiveSuspender);
    __ Move(promise,
            FieldOperand(promise, WasmSuspenderObject::kPromiseOffset));
  }
  __ mov(kContextRegister,
         MemOperand(ebp, StackSwitchFrameConstants::kImplicitArgOffset));
  GetContextFromImplicitArg(masm, kContextRegister, tmp);

  ReloadParentContinuation(masm, promise, return_value, kContextRegister, tmp,
                           tmp2);
  __ Push(promise);
  RestoreParentSuspender(masm, promise, tmp);
  __ Pop(promise);

  if (mode == wasm::kPromise) {
    __ Move(MemOperand(ebp, StackSwitchFrameConstants::kGCScanSlotCountOffset),
            Immediate(1));
    __ Push(promise);
    __ CallBuiltin(Builtin::kFulfillPromise);
    __ Pop(promise);
  }

  __ bind(return_promise);
}

void GenerateExceptionHandlingLandingPad(MacroAssembler* masm,
                                         Label* return_promise) {
  int catch_handler = __ pc_offset();

  // Restore esp to free the reserved stack slots for the sections.
  __ lea(esp, MemOperand(ebp, StackSwitchFrameConstants::kLastSpillOffset));

  // Unset thread_in_wasm_flag.
  Register thread_in_wasm_flag_addr = ecx;
  __ mov(
      thread_in_wasm_flag_addr,
      MemOperand(kRootRegister, Isolate::thread_in_wasm_flag_address_offset()));
  __ mov(MemOperand(thread_in_wasm_flag_addr, 0), Immediate(0));
  thread_in_wasm_flag_addr = no_reg;

  // The exception becomes the parameter of the RejectPromise builtin, and the
  // promise is the return value of this wrapper.
  static const Builtin_RejectPromise_InterfaceDescriptor desc;
  constexpr Register promise = desc.GetRegisterParameter(0);
  constexpr Register reason = desc.GetRegisterParameter(1);
  DCHECK(kReturnRegister0 == promise);

  __ mov(reason, kReturnRegister0);

  __ LoadRoot(promise, RootIndex::kActiveSuspender);
  __ Move(promise, FieldOperand(promise, WasmSuspenderObject::kPromiseOffset));

  __ mov(kContextRegister,
         MemOperand(ebp, StackSwitchFrameConstants::kImplicitArgOffset));
  constexpr Register tmp1 = edi;
  static_assert(tmp1 != promise && tmp1 != reason && tmp1 != kContextRegister);
  constexpr Register tmp2 = edx;
  static_assert(tmp2 != promise && tmp2 != reason && tmp2 != kContextRegister);
  GetContextFromImplicitArg(masm, kContextRegister, tmp1);
  ReloadParentContinuation(masm, promise, reason, kContextRegister, tmp1, tmp2);
  __ Push(promise);
  RestoreParentSuspender(masm, promise, edi);
  __ Pop(promise);

  __ Move(MemOperand(ebp, StackSwitchFrameConstants::kGCScanSlotCountOffset),
          Immediate(1));
  __ Push(promise);

  Register debug_event = desc.GetRegisterParameter(2);
  __ LoadRoot(debug_event, RootIndex::kTrueValue);
  __ CallBuiltin(Builtin::kRejectPromise);
  __ Pop(promise);

  // Run the rest of the wrapper normally (switch to the old stack,
  // deconstruct the frame, ...).
  __ jmp(return_promise);

  masm->isolate()->builtins()->SetJSPIPromptHandlerOffset(catch_handler);
}

void JSToWasmWrapperHelper(MacroAssembler* masm, wasm::Promise mode) {
  bool stack_switch = mode == wasm::kPromise || mode == wasm::kStressSwitch;
  __ EnterFrame(stack_switch ? StackFrame::STACK_SWITCH
                             : StackFrame::JS_TO_WASM);

  constexpr int kNumSpillSlots = StackSwitchFrameConstants::kNumSpillSlots;
  __ sub(esp, Immediate(kNumSpillSlots * kSystemPointerSize));

  ResetStackSwitchFrameStackSlots(masm);

  Register wrapper_buffer =
      WasmJSToWasmWrapperDescriptor::WrapperBufferRegister();

  Register original_fp = stack_switch ? esi : ebp;
  Register new_wrapper_buffer = stack_switch ? ecx : wrapper_buffer;

  Label suspend;
  if (stack_switch) {
    SwitchToAllocatedStack(masm, wrapper_buffer, original_fp,
                           new_wrapper_buffer, eax, edx, &suspend);
  }
  __ mov(MemOperand(ebp, JSToWasmWrapperFrameConstants::kWrapperBufferOffset),
         new_wrapper_buffer);
  if (stack_switch) {
    // Preserve wasm_instance across the switch.
    __ mov(eax, MemOperand(original_fp,
                           JSToWasmWrapperFrameConstants::kImplicitArgOffset));
    __ mov(MemOperand(ebp, StackSwitchFrameConstants::kImplicitArgOffset), eax);

    Register result_array = eax;
    __ mov(result_array,
           MemOperand(original_fp,
                      JSToWasmWrapperFrameConstants::kResultArrayParamOffset));
    __ mov(MemOperand(ebp, StackSwitchFrameConstants::kResultArrayOffset),
           result_array);
  }

  Register result_size = eax;
  original_fp = no_reg;

  MemOperand GCScanSlotPlace =
      MemOperand(ebp, StackSwitchFrameConstants::kGCScanSlotCountOffset);
  __ Move(GCScanSlotPlace, Immediate(0));

  __ mov(
      result_size,
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferStackReturnBufferSize));
  __ shl(result_size, kSystemPointerSizeLog2);
  __ sub(esp, result_size);
  __ mov(
      MemOperand(
          new_wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferStackReturnBufferStart),
      esp);

  result_size = no_reg;
  new_wrapper_buffer = no_reg;

  // param_start should not alias with any parameter registers.
  Register params_start = eax;
  __ mov(params_start,
         MemOperand(wrapper_buffer,
                    JSToWasmWrapperFrameConstants::kWrapperBufferParamStart));
  Register params_end = esi;
  __ mov(params_end,
         MemOperand(wrapper_buffer,
                    JSToWasmWrapperFrameConstants::kWrapperBufferParamEnd));

  Register last_stack_param = ecx;

  // The first GP parameter holds the trusted instance data or the import data.
  // This is handled specially.
  int stack_params_offset =
      (arraysize(wasm::kGpParamRegisters) - 1) * kSystemPointerSize +
      arraysize(wasm::kFpParamRegisters) * kDoubleSize;

  int param_padding = stack_params_offset & kSystemPointerSize;
  stack_params_offset += param_padding;
  __ lea(last_stack_param, MemOperand(params_start, stack_params_offset));

  Label loop_start;
  __ bind(&loop_start);

  Label finish_stack_params;
  __ cmp(last_stack_param, params_end);
  __ j(greater_equal, &finish_stack_params);

  // Push parameter
  __ sub(params_end, Immediate(kSystemPointerSize));
  __ push(MemOperand(params_end, 0));
  __ jmp(&loop_start);

  __ bind(&finish_stack_params);

  int next_offset = stack_params_offset;
  for (size_t i = arraysize(wasm::kFpParamRegisters) - 1;
       i < arraysize(wasm::kFpParamRegisters); --i) {
    next_offset -= kDoubleSize;
    __ Movsd(wasm::kFpParamRegisters[i], MemOperand(params_start, next_offset));
  }

  // Set the flag-in-wasm flag before loading the parameter registers. There are
  // not so many registers, so we use one of the parameter registers before it
  // is blocked.
  Register thread_in_wasm_flag_addr = ecx;
  __ mov(
      thread_in_wasm_flag_addr,
      MemOperand(kRootRegister, Isolate::thread_in_wasm_flag_address_offset()));
  __ mov(MemOperand(thread_in_wasm_flag_addr, 0), Immediate(1));

  next_offset -= param_padding;
  for (size_t i = arraysize(wasm::kGpParamRegisters) - 1; i > 0; --i) {
    next_offset -= kSystemPointerSize;
    __ mov(wasm::kGpParamRegisters[i], MemOperand(params_start, next_offset));
  }
  DCHECK_EQ(next_offset, 0);
  // Since there are so few registers, {params_start} overlaps with one of the
  // parameter registers. Make sure it overlaps with the last one we fill.
  DCHECK_EQ(params_start, wasm::kGpParamRegisters[1]);

  // Load the implicit argument (instance data or import data) from the frame.
  if (stack_switch) {
    __ mov(kWasmImplicitArgRegister,
           MemOperand(ebp, StackSwitchFrameConstants::kImplicitArgOffset));
  } else {
    __ mov(kWasmImplicitArgRegister,
           MemOperand(ebp, JSToWasmWrapperFrameConstants::kImplicitArgOffset));
  }

  Register call_target = edi;
  __ mov(call_target,
         MemOperand(wrapper_buffer,
                    JSToWasmWrapperFrameConstants::kWrapperBufferCallTarget));
  if (stack_switch) {
    __ Move(MemOperand(ebp, StackSwitchFrameConstants::kGCScanSlotCountOffset),
            Immediate(0));
  }
  __ CallWasmCodePointer(call_target);

  __ mov(
      thread_in_wasm_flag_addr,
      MemOperand(kRootRegister, Isolate::thread_in_wasm_flag_address_offset()));
  __ mov(MemOperand(thread_in_wasm_flag_addr, 0), Immediate(0));
  thread_in_wasm_flag_addr = no_reg;

  wrapper_buffer = esi;
  __ mov(wrapper_buffer,
         MemOperand(ebp, JSToWasmWrapperFrameConstants::kWrapperBufferOffset));

  __ Movsd(MemOperand(
               wrapper_buffer,
               JSToWasmWrapperFrameConstants::kWrapperBufferFPReturnRegister1),
           wasm::kFpReturnRegisters[0]);
  __ Movsd(MemOperand(
               wrapper_buffer,
               JSToWasmWrapperFrameConstants::kWrapperBufferFPReturnRegister2),
           wasm::kFpReturnRegisters[1]);
  __ mov(MemOperand(
             wrapper_buffer,
             JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister1),
         wasm::kGpReturnRegisters[0]);
  __ mov(MemOperand(
             wrapper_buffer,
             JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister2),
         wasm::kGpReturnRegisters[1]);

  // Call the return value builtin with
  // eax: wasm instance.
  // ecx: the result JSArray for multi-return.
  // edx: pointer to the byte buffer which contains all parameters.
  if (stack_switch) {
    __ mov(eax, MemOperand(ebp, StackSwitchFrameConstants::kImplicitArgOffset));
    __ mov(ecx, MemOperand(ebp, StackSwitchFrameConstants::kResultArrayOffset));
  } else {
    __ mov(eax,
           MemOperand(ebp, JSToWasmWrapperFrameConstants::kImplicitArgOffset));
    __ mov(ecx,
           MemOperand(ebp,
                      JSToWasmWrapperFrameConstants::kResultArrayParamOffset));
  }
  Register scratch = edx;
  GetContextFromImplicitArg(masm, eax, scratch);
  __ mov(edx, wrapper_buffer);
  __ CallBuiltin(Builtin::kJSToWasmHandleReturns);

  Label return_promise;

  if (stack_switch) {
    SwitchBackAndReturnPromise(masm, edx, edi, mode, &return_promise);
  }
  __ bind(&suspend);

  __ LeaveFrame(stack_switch ? StackFrame::STACK_SWITCH
                             : StackFrame::JS_TO_WASM);
  __ ret(0);

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
  JSToWasmWrapperHelper(masm, wasm::kPromise);
}

void Builtins::Generate_JSToWasmStressSwitchStacksAsm(MacroAssembler* masm) {
  JSToWasmWrapperHelper(masm, wasm::kStressSwitch);
}

void Builtins::Generate_WasmToJsWrapperAsm(MacroAssembler* masm) {
  // Pop the return address into a scratch register and push it later again. The
  // return address has to be on top of the stack after all registers have been
  // pushed, so that the return instruction can find it.
  Register scratch = edi;
  __ pop(scratch);

  int required_stack_space = arraysize(wasm::kFpParamRegisters) * kDoubleSize;
  __ sub(esp, Immediate(required_stack_space));
  for (int i = 0; i < static_cast<int>(arraysize(wasm::kFpParamRegisters));
       ++i) {
    __ Movsd(MemOperand(esp, i * kDoubleSize), wasm::kFpParamRegisters[i]);
  }
  // eax is pushed for alignment, so that the pushed register parameters and
  // stack parameters look the same as the layout produced by the js-to-wasm
  // wrapper for out-going parameters. Having the same layout allows to share
  // code in Torque, especially the `LocationAllocator`. eax has been picked
  // arbitrarily.
  __ push(eax);
  // Push the GP registers in reverse order so that they are on the stack like
  // in an array, with the first item being at the lowest address.
  for (size_t i = arraysize(wasm::kGpParamRegisters) - 1; i > 0; --i) {
    __ push(wasm::kGpParamRegisters[i]);
  }
  // Reserve a slot for the signature.
  __ push(eax);
  // Push the return address again.
  __ push(scratch);
  __ TailCallBuiltin(Builtin::kWasmToJsWrapperCSA);
}

void Builtins::Generate_WasmTrapHandlerLandingPad(MacroAssembler* masm) {
  __ Trap();
}

void Builtins::Generate_WasmSuspend(MacroAssembler* masm) {
  // Set up the stackframe.
  __ EnterFrame(StackFrame::STACK_SWITCH);

  Register suspender = eax;

  __ AllocateStackSpace(StackSwitchFrameConstants::kNumSpillSlots *
                        kSystemPointerSize);
  // Set a sentinel value for the spill slots visited by the GC.
  ResetStackSwitchFrameStackSlots(masm);

  // -------------------------------------------
  // Save current state in active jump buffer.
  // -------------------------------------------
  Label resume;
  Register continuation = ecx;
  __ LoadRoot(continuation, RootIndex::kActiveContinuation);
  Register jmpbuf = edi;
  __ Move(jmpbuf,
          FieldOperand(continuation, WasmContinuationObject::kJmpbufOffset));
  FillJumpBuffer(masm, jmpbuf, edx, &resume);
  SwitchStackState(masm, jmpbuf, wasm::JumpBuffer::Active,
                   wasm::JumpBuffer::Suspended);
  __ Move(FieldOperand(suspender, WasmSuspenderObject::kStateOffset),
          Immediate(Smi::FromInt(WasmSuspenderObject::kSuspended)));
  jmpbuf = no_reg;

  Register suspender_continuation = edi;
  __ Move(suspender_continuation,
          FieldOperand(suspender, WasmSuspenderObject::kContinuationOffset));
#ifdef DEBUG
  // -------------------------------------------
  // Check that the suspender's continuation is the active continuation.
  // -------------------------------------------
  // TODO(thibaudm): Once we add core stack-switching instructions, this check
  // will not hold anymore: it's possible that the active continuation changed
  // (due to an internal switch), so we have to update the suspender.
  __ cmp(suspender_continuation, continuation);
  Label ok;
  __ j(equal, &ok);
  __ Trap();
  __ bind(&ok);
#endif

  // -------------------------------------------
  // Update roots.
  // -------------------------------------------
  Register caller = ecx;
  __ Move(caller, FieldOperand(suspender_continuation,
                               WasmContinuationObject::kParentOffset));
  __ mov(masm->RootAsOperand(RootIndex::kActiveContinuation), caller);
  Register parent = edi;
  __ Move(parent, FieldOperand(suspender, WasmSuspenderObject::kParentOffset));
  __ mov(masm->RootAsOperand(RootIndex::kActiveSuspender), parent);
  parent = no_reg;

  // -------------------------------------------
  // Load jump buffer.
  // -------------------------------------------
  SwitchStacks(masm, no_reg, caller, suspender);
  jmpbuf = caller;
  __ Move(jmpbuf, FieldOperand(caller, WasmContinuationObject::kJmpbufOffset));
  caller = no_reg;
  __ Move(kReturnRegister0,
          FieldOperand(suspender, WasmSuspenderObject::kPromiseOffset));
  MemOperand GCScanSlotPlace =
      MemOperand(ebp, StackSwitchFrameConstants::kGCScanSlotCountOffset);
  __ Move(GCScanSlotPlace, Immediate(0));
  LoadJumpBuffer(masm, jmpbuf, true, wasm::JumpBuffer::Inactive);
  __ Trap();
  __ bind(&resume);
  __ LeaveFrame(StackFrame::STACK_SWITCH);
  __ ret(0);
}

namespace {
// Resume the suspender stored in the closure. We generate two variants of this
// builtin: the onFulfilled variant resumes execution at the saved PC and
// forwards the value, the onRejected variant throws the value.

void Generate_WasmResumeHelper(MacroAssembler* masm, wasm::OnResume on_resume) {
  __ EnterFrame(StackFrame::STACK_SWITCH);

  Register closure = kJSFunctionRegister;  // edi

  __ AllocateStackSpace(StackSwitchFrameConstants::kNumSpillSlots *
                        kSystemPointerSize);
  // Set a sentinel value for the spill slots visited by the GC.
  ResetStackSwitchFrameStackSlots(masm);

  // -------------------------------------------
  // Load suspender from closure.
  // -------------------------------------------
  Register sfi = closure;
  __ Move(
      sfi,
      MemOperand(
          closure,
          wasm::ObjectAccess::SharedFunctionInfoOffsetInTaggedJSFunction()));
  Register function_data = sfi;
  __ Move(function_data,
          FieldOperand(sfi, SharedFunctionInfo::kUntrustedFunctionDataOffset));
  // The write barrier uses a fixed register for the host object (edi). The next
  // barrier is on the suspender, so load it in edi directly.
  Register suspender = edi;
  __ Move(suspender,
          FieldOperand(function_data, WasmResumeData::kSuspenderOffset));
  // Check the suspender state.
  Label suspender_is_suspended;
  Register state = edx;
  __ Move(state, FieldOperand(suspender, WasmSuspenderObject::kStateOffset));
  __ SmiCompare(state, Smi::FromInt(WasmSuspenderObject::kSuspended));
  __ j(equal, &suspender_is_suspended);
  __ Trap();
  closure = no_reg;
  sfi = no_reg;

  __ bind(&suspender_is_suspended);
  // -------------------------------------------
  // Save current state.
  // -------------------------------------------

  Label suspend;
  Register active_continuation = edx;
  __ LoadRoot(active_continuation, RootIndex::kActiveContinuation);
  Register current_jmpbuf = eax;
  __ Move(current_jmpbuf, FieldOperand(active_continuation,
                                       WasmContinuationObject::kJmpbufOffset));
  active_continuation = no_reg;  // We reload this later.
  FillJumpBuffer(masm, current_jmpbuf, edx, &suspend);
  SwitchStackState(masm, current_jmpbuf, wasm::JumpBuffer::Active,
                   wasm::JumpBuffer::Inactive);
  current_jmpbuf = no_reg;

  // -------------------------------------------
  // Set the suspender and continuation parents and update the roots.
  // -------------------------------------------
  Register active_suspender = edx;
  Register slot_address = WriteBarrierDescriptor::SlotAddressRegister();
  // Check that the fixed register isn't one that is already in use.
  DCHECK(!AreAliased(slot_address, suspender, active_suspender));

  __ LoadRoot(active_suspender, RootIndex::kActiveSuspender);
  __ mov(FieldOperand(suspender, WasmSuspenderObject::kParentOffset),
         active_suspender);
  __ RecordWriteField(suspender, WasmSuspenderObject::kParentOffset,
                      active_suspender, slot_address, SaveFPRegsMode::kIgnore);
  __ Move(FieldOperand(suspender, WasmSuspenderObject::kStateOffset),
          Immediate(Smi::FromInt(WasmSuspenderObject::kActive)));
  __ mov(masm->RootAsOperand(RootIndex::kActiveSuspender), suspender);

  active_suspender = no_reg;

  Register target_continuation = suspender;
  __ Move(target_continuation,
          FieldOperand(suspender, WasmSuspenderObject::kContinuationOffset));
  suspender = no_reg;
  active_continuation = edx;
  __ LoadRoot(active_continuation, RootIndex::kActiveContinuation);
  __ mov(
      FieldOperand(target_continuation, WasmContinuationObject::kParentOffset),
      active_continuation);
  __ RecordWriteField(
      target_continuation, WasmContinuationObject::kParentOffset,
      active_continuation, slot_address, SaveFPRegsMode::kIgnore);
  active_continuation = no_reg;
  __ mov(masm->RootAsOperand(RootIndex::kActiveContinuation),
         target_continuation);

  SwitchStacks(masm, no_reg, target_continuation);

  // -------------------------------------------
  // Load state from target jmpbuf (longjmp).
  // -------------------------------------------
  Register target_jmpbuf = edi;
  __ Move(target_jmpbuf, FieldOperand(target_continuation,
                                      WasmContinuationObject::kJmpbufOffset));
  // Move resolved value to return register.
  __ mov(kReturnRegister0, Operand(ebp, 3 * kSystemPointerSize));
  __ Move(MemOperand(ebp, StackSwitchFrameConstants::kGCScanSlotCountOffset),
          Immediate(0));
  if (on_resume == wasm::OnResume::kThrow) {
    // Switch to the continuation's stack without restoring the PC.
    LoadJumpBuffer(masm, target_jmpbuf, false, wasm::JumpBuffer::Suspended);
    // Pop this frame now. The unwinder expects that the first STACK_SWITCH
    // frame is the outermost one.
    __ LeaveFrame(StackFrame::STACK_SWITCH);
    // Forward the onRejected value to kThrow.
    __ push(kReturnRegister0);
    __ Move(kContextRegister, Smi::zero());
    __ CallRuntime(Runtime::kThrow);
  } else {
    // Resume the continuation normally.
    LoadJumpBuffer(masm, target_jmpbuf, true, wasm::JumpBuffer::Suspended);
  }
  __ Trap();
  __ bind(&suspend);
  __ LeaveFrame(StackFrame::STACK_SWITCH);
  // Pop receiver + parameter.
  __ ret(2 * kSystemPointerSize);
}
}  // namespace

void Builtins::Generate_WasmResume(MacroAssembler* masm) {
  Generate_WasmResumeHelper(masm, wasm::OnResume::kContinue);
}

void Builtins::Generate_WasmReject(MacroAssembler* masm) {
  Generate_WasmResumeHelper(masm, wasm::OnResume::kThrow);
}

void Builtins::Generate_WasmOnStackReplace(MacroAssembler* masm) {
  // Only needed on x64.
  __ Trap();
}

namespace {
static constexpr Register kOldSPRegister = esi;

void SwitchToTheCentralStackIfNeeded(MacroAssembler* masm, int edi_slot_index) {
  using ER = ExternalReference;

  // Preserve edi on the stack as a local.
  __ mov(ExitFrameStackSlotOperand(edi_slot_index * kSystemPointerSize), edi);

  // kOldSPRegister used as a switch flag, if it is zero - no switch performed
  // if it is not zero, it contains old sp value.
  __ Move(kOldSPRegister, 0);

  DCHECK(!AreAliased(kOldSPRegister, ecx, ebx));

  ER on_central_stack_flag = ER::Create(
      IsolateAddressId::kIsOnCentralStackFlagAddress, masm->isolate());

  Label do_not_need_to_switch;
  __ cmpb(__ ExternalReferenceAsOperand(on_central_stack_flag, ecx),
          Immediate(0));
  __ j(not_zero, &do_not_need_to_switch);

  // Perform switching to the central stack.
  __ mov(kOldSPRegister, esp);

  Register argc_input = eax;
  Register central_stack_sp = edi;
  DCHECK(!AreAliased(central_stack_sp, argc_input));
  {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ push(argc_input);
    __ push(kRuntimeCallFunctionRegister);

    __ PrepareCallCFunction(2, ecx);

    __ Move(Operand(esp, 0 * kSystemPointerSize),
            Immediate(ER::isolate_address()));
    __ mov(Operand(esp, 1 * kSystemPointerSize), kOldSPRegister);

    __ CallCFunction(ER::wasm_switch_to_the_central_stack(), 2,
                     SetIsolateDataSlots::kNo);
    __ mov(central_stack_sp, kReturnRegister0);

    __ pop(kRuntimeCallFunctionRegister);
    __ pop(argc_input);
  }

  static constexpr int kReturnAddressSlotOffset = 4 * kSystemPointerSize;
  __ sub(central_stack_sp, Immediate(kReturnAddressSlotOffset));
  __ mov(esp, central_stack_sp);

  // esp should be aligned by 16 bytes,
  // but it is not guaranteed for stored SP.
  __ AlignStackPointer();

  // Update the sp saved in the frame.
  // It will be used to calculate the callee pc during GC.
  // The pc is going to be on the new stack segment, so rewrite it here.
  __ mov(Operand(ebp, ExitFrameConstants::kSPOffset), esp);

  Label exitLabel;
  // Restore bashed edi, so we can make the CCall properly.
  __ mov(edi, Operand(kOldSPRegister, edi_slot_index * kSystemPointerSize));
  __ jmp(&exitLabel);
  __ bind(&do_not_need_to_switch);
  __ mov(edi, ExitFrameStackSlotOperand(edi_slot_index * kSystemPointerSize));

  __ bind(&exitLabel);
}

void SwitchFromTheCentralStackIfNeeded(MacroAssembler* masm) {
  using ER = ExternalReference;

  Label no_stack_change;
  __ cmp(kOldSPRegister, Immediate(0));
  __ j(equal, &no_stack_change);
  __ mov(esp, kOldSPRegister);

  {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ push(kReturnRegister0);
    __ push(kReturnRegister1);

    __ PrepareCallCFunction(1, ecx);
    __ Move(Operand(esp, 0 * kSystemPointerSize),
            Immediate(ER::isolate_address()));
    __ CallCFunction(ER::wasm_switch_from_the_central_stack(), 1,
                     SetIsolateDataSlots::kNo);

    __ pop(kReturnRegister1);
    __ pop(kReturnRegister0);
  }

  __ bind(&no_stack_change);
}

}  // namespace

#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_CEntry(MacroAssembler* masm, int result_size,
                               ArgvMode argv_mode, bool builtin_exit_frame,
                               bool switch_to_central_stack) {
  CHECK(result_size == 1 || result_size == 2);

  using ER = ExternalReference;

  // eax: number of arguments including receiver
  // edx: pointer to C function
  // ebp: frame pointer  (restored after C call)
  // esp: stack pointer  (restored after C call)
  // esi: current context (C callee-saved)
  // edi: JS function of the caller (C callee-saved)
  //
  // If argv_mode == ArgvMode::kRegister:
  // ecx: pointer to the first argument

  static_assert(eax == kRuntimeCallArgCountRegister);
  static_assert(ecx == kRuntimeCallArgvRegister);
  static_assert(edx == kRuntimeCallFunctionRegister);
  static_assert(esi == kContextRegister);
  static_assert(edi == kJSFunctionRegister);

  DCHECK(!AreAliased(kRuntimeCallArgCountRegister, kRuntimeCallArgvRegister,
                     kRuntimeCallFunctionRegister, kContextRegister,
                     kJSFunctionRegister, kRootRegister));

  const int kSwitchToTheCentralStackSlots = switch_to_central_stack ? 1 : 0;
  const int kReservedStackSlots = 3 + kSwitchToTheCentralStackSlots;

#if V8_ENABLE_WEBASSEMBLY
  const int kEdiSlot = kReservedStackSlots - 1;
#endif  // V8_ENABLE_WEBASSEMBLY

  __ EnterExitFrame(
      kReservedStackSlots,
      builtin_exit_frame ? StackFrame::BUILTIN_EXIT : StackFrame::EXIT, edi);

  // Set up argv in a callee-saved register. It is reused below so it must be
  // retained across the C call.
  static constexpr Register kArgvRegister = edi;
  if (argv_mode == ArgvMode::kRegister) {
    __ mov(kArgvRegister, ecx);
  } else {
    int offset =
        StandardFrameConstants::kFixedFrameSizeAboveFp - kReceiverOnStackSize;
    __ lea(kArgvRegister, Operand(ebp, eax, times_system_pointer_size, offset));
  }

  // edx: pointer to C function
  // ebp: frame pointer  (restored after C call)
  // esp: stack pointer  (restored after C call)
  // eax: number of arguments including receiver
  // edi: pointer to the first argument (C callee-saved)

#if V8_ENABLE_WEBASSEMBLY
  if (switch_to_central_stack) {
    SwitchToTheCentralStackIfNeeded(masm, kEdiSlot);
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  // Result returned in eax, or eax+edx if result size is 2.

  // Check stack alignment.
  if (v8_flags.debug_code) {
    __ CheckStackAlignment();
  }
  // Call C function.
  __ mov(Operand(esp, 0 * kSystemPointerSize), eax);            // argc.
  __ mov(Operand(esp, 1 * kSystemPointerSize), kArgvRegister);  // argv.
  __ Move(ecx, Immediate(ER::isolate_address()));
  __ mov(Operand(esp, 2 * kSystemPointerSize), ecx);
  __ call(kRuntimeCallFunctionRegister);

  // Result is in eax or edx:eax - do not destroy these registers!

#if V8_ENABLE_WEBASSEMBLY
  if (switch_to_central_stack) {
    SwitchFromTheCentralStackIfNeeded(masm);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // Check result for exception sentinel.
  Label exception_returned;
  __ CompareRoot(eax, RootIndex::kException);
  __ j(equal, &exception_returned);

  // Check that there is no exception, otherwise we
  // should have returned the exception sentinel.
  if (v8_flags.debug_code) {
    __ push(edx);
    __ LoadRoot(edx, RootIndex::kTheHoleValue);
    Label okay;
    ER exception_address =
        ER::Create(IsolateAddressId::kExceptionAddress, masm->isolate());
    __ cmp(edx, __ ExternalReferenceAsOperand(exception_address, ecx));
    // Cannot use check here as it attempts to generate call into runtime.
    __ j(equal, &okay, Label::kNear);
    __ int3();
    __ bind(&okay);
    __ pop(edx);
  }

  __ LeaveExitFrame(esi);
  if (argv_mode == ArgvMode::kStack) {
    // Drop arguments and the receiver from the caller stack.
    DCHECK(!AreAliased(esi, kArgvRegister));
    __ PopReturnAddressTo(ecx);
    __ lea(esp, Operand(kArgvRegister, kReceiverOnStackSize));
    __ PushReturnAddressFrom(ecx);
  }
  __ ret(0);

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

  // Ask the runtime for help to determine the handler. This will set eax to
  // contain the current exception, don't clobber it.
  ER find_handler = ER::Create(Runtime::kUnwindAndFindExceptionHandler);
  {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ PrepareCallCFunction(3, eax);
    __ mov(Operand(esp, 0 * kSystemPointerSize), Immediate(0));  // argc.
    __ mov(Operand(esp, 1 * kSystemPointerSize), Immediate(0));  // argv.
    __ Move(esi, Immediate(ER::isolate_address()));
    __ mov(Operand(esp, 2 * kSystemPointerSize), esi);
    __ CallCFunction(find_handler, 3, SetIsolateDataSlots::kNo);
  }

  // Retrieve the handler context, SP and FP.
  __ mov(esp, __ ExternalReferenceAsOperand(pending_handler_sp_address, esi));
  __ mov(ebp, __ ExternalReferenceAsOperand(pending_handler_fp_address, esi));
  __ mov(esi,
         __ ExternalReferenceAsOperand(pending_handler_context_address, esi));

  // If the handler is a JS frame, restore the context to the frame. Note that
  // the context will be set to (esi == 0) for non-JS frames.
  Label skip;
  __ test(esi, esi);
  __ j(zero, &skip, Label::kNear);
  __ mov(Operand(ebp, StandardFrameConstants::kContextOffset), esi);
  __ bind(&skip);

  // Clear c_entry_fp, like we do in `LeaveExitFrame`.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, masm->isolate());
  __ mov(__ ExternalReferenceAsOperand(c_entry_fp_address, esi), Immediate(0));

  // Compute the handler entry address and jump to it.
  __ mov(edi, __ ExternalReferenceAsOperand(pending_handler_entrypoint_address,
                                            edi));
  __ jmp(edi);
}

#if V8_ENABLE_WEBASSEMBLY
void Builtins::Generate_WasmHandleStackOverflow(MacroAssembler* masm) {
  using ER = ExternalReference;
  Register frame_base =
      WasmHandleStackOverflowDescriptor::FrameBaseRegister();       // eax
  Register gap = WasmHandleStackOverflowDescriptor::GapRegister();  // ecx
  Register original_fp = edx;
  Register original_sp = esi;
  __ mov(original_fp, ebp);
  __ mov(original_sp, esp);
  // Calculate frame size before SP is updated.
  __ sub(frame_base, esp);
  {
    Register scratch = edi;
    DCHECK(!AreAliased(original_fp, original_sp, frame_base, gap, scratch));
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ push(gap);
    __ PrepareCallCFunction(5, scratch);
    __ mov(Operand(esp, 4 * kSystemPointerSize), original_fp);
    __ mov(Operand(esp, 3 * kSystemPointerSize), gap);
    __ mov(Operand(esp, 2 * kSystemPointerSize), frame_base);
    __ mov(Operand(esp, 1 * kSystemPointerSize), original_sp);
    __ Move(Operand(esp, 0 * kSystemPointerSize),
            Immediate(ExternalReference::isolate_address()));
    __ CallCFunction(ER::wasm_grow_stack(), 5);
    __ pop(gap);
    DCHECK_NE(kReturnRegister0, gap);
  }
  Label call_runtime;
  // wasm_grow_stack returns zero if it cannot grow a stack.
  __ test(kReturnRegister0, kReturnRegister0);
  __ j(zero, &call_runtime, Label::kNear);
  Register new_fp = edx;
  // Calculate old FP - SP offset to adjust FP accordingly to new SP.
  __ sub(ebp, esp);
  __ add(ebp, kReturnRegister0);
  __ mov(esp, kReturnRegister0);
  Register tmp = new_fp;
  __ mov(tmp,
         Immediate(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
  __ mov(MemOperand(ebp, TypedFrameConstants::kFrameTypeOffset), tmp);
  __ ret(0);

  // If wasm_grow_stack returns zero interruption or stack overflow
  // should be handled by runtime call.
  {
    __ bind(&call_runtime);
    __ mov(kWasmImplicitArgRegister,
           MemOperand(ebp, WasmFrameConstants::kWasmInstanceDataOffset));
    __ mov(kContextRegister,
           FieldOperand(kWasmImplicitArgRegister,
                        WasmTrustedInstanceData::kNativeContextOffset));
    FrameScope scope(masm, StackFrame::MANUAL);
    __ EnterFrame(StackFrame::INTERNAL);
    __ SmiTag(gap);
    __ push(gap);
    __ CallRuntime(Runtime::kWasmStackGuard);
    __ LeaveFrame(StackFrame::INTERNAL);
    __ ret(0);
  }
}
#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_DoubleToI(MacroAssembler* masm) {
  Label check_negative, process_64_bits, done;

  // Account for return address and saved regs.
  const int kArgumentOffset = 4 * kSystemPointerSize;

  MemOperand mantissa_operand(MemOperand(esp, kArgumentOffset));
  MemOperand exponent_operand(
      MemOperand(esp, kArgumentOffset + kDoubleSize / 2));

  // The result is returned on the stack.
  MemOperand return_operand = mantissa_operand;

  Register scratch1 = ebx;

  // Since we must use ecx for shifts below, use some other register (eax)
  // to calculate the result.
  Register result_reg = eax;
  // Save ecx if it isn't the return register and therefore volatile, or if it
  // is the return register, then save the temp register we use in its stead for
  // the result.
  Register save_reg = eax;
  __ push(ecx);
  __ push(scratch1);
  __ push(save_reg);

  __ mov(scratch1, mantissa_operand);
  if (CpuFeatures::IsSupported(SSE3)) {
    CpuFeatureScope scope(masm, SSE3);
    // Load x87 register with heap number.
    __ fld_d(mantissa_operand);
  }
  __ mov(ecx, exponent_operand);

  __ and_(ecx, HeapNumber::kExponentMask);
  __ shr(ecx, HeapNumber::kExponentShift);
  __ lea(result_reg, MemOperand(ecx, -HeapNumber::kExponentBias));
  __ cmp(result_reg, Immediate(HeapNumber::kMantissaBits));
  __ j(below, &process_64_bits);

  // Result is entirely in lower 32-bits of mantissa
  int delta =
      HeapNumber::kExponentBias + base::Double::kPhysicalSignificandSize;
  if (CpuFeatures::IsSupported(SSE3)) {
    __ fstp(0);
  }
  __ sub(ecx, Immediate(delta));
  __ xor_(result_reg, result_reg);
  __ cmp(ecx, Immediate(31));
  __ j(above, &done);
  __ shl_cl(scratch1);
  __ jmp(&check_negative);

  __ bind(&process_64_bits);
  if (CpuFeatures::IsSupported(SSE3)) {
    CpuFeatureScope scope(masm, SSE3);
    // Reserve space for 64 bit answer.
    __ AllocateStackSpace(kDoubleSize);  // Nolint.
    // Do conversion, which cannot fail because we checked the exponent.
    __ fisttp_d(Operand(esp, 0));
    __ mov(result_reg, Operand(esp, 0));  // Load low word of answer as result
    __ add(esp, Immediate(kDoubleSize));
    __ jmp(&done);
  } else {
    // Result must be extracted from shifted 32-bit mantissa
    __ sub(ecx, Immediate(delta));
    __ neg(ecx);
    __ mov(result_reg, exponent_operand);
    __ and_(
        result_reg,
        Immediate(static_cast<uint32_t>(base::Double::kSignificandMask >> 32)));
    __ add(result_reg,
           Immediate(static_cast<uint32_t>(base::Double::kHiddenBit >> 32)));
    __ shrd_cl(scratch1, result_reg);
    __ shr_cl(result_reg);
    __ test(ecx, Immediate(32));
    __ cmov(not_equal, scratch1, result_reg);
  }

  // If the double was negative, negate the integer result.
  __ bind(&check_negative);
  __ mov(result_reg, scratch1);
  __ neg(result_reg);
  __ cmp(exponent_operand, Immediate(0));
  __ cmov(greater, result_reg, scratch1);

  // Restore registers
  __ bind(&done);
  __ mov(return_operand, result_reg);
  __ pop(save_reg);
  __ pop(scratch1);
  __ pop(ecx);
  __ ret(0);
}

void Builtins::Generate_CallApiCallbackImpl(MacroAssembler* masm,
                                            CallApiCallbackMode mode) {
  // ----------- S t a t e -------------
  // CallApiCallbackMode::kOptimizedNoProfiling/kOptimized modes:
  //  -- eax                 : api function address
  // Both modes:
  //  -- ecx                 : arguments count (not including the receiver)
  //  -- edx                 : FunctionTemplateInfo
  //  -- edi                 : holder
  //  -- esi                 : context
  //  -- esp[0]              : return address
  //  -- esp[8]              : argument 0 (receiver)
  //  -- esp[16]             : argument 1
  //  -- ...
  //  -- esp[argc * 8]       : argument (argc - 1)
  //  -- esp[(argc + 1) * 8] : argument argc
  // -----------------------------------

  Register api_function_address = no_reg;
  Register argc = no_reg;
  Register func_templ = no_reg;
  Register holder = no_reg;
  Register topmost_script_having_context = no_reg;

  switch (mode) {
    case CallApiCallbackMode::kGeneric:
      argc = CallApiCallbackGenericDescriptor::ActualArgumentsCountRegister();
      topmost_script_having_context = CallApiCallbackGenericDescriptor::
          TopmostScriptHavingContextRegister();
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
                     func_templ, holder));

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
  //
  // Current state:
  //   esp[0]: return address
  //
  // Target state:
  //   esp[0 * kSystemPointerSize]: return address
  //   esp[1 * kSystemPointerSize]: kHolder   <= implicit_args_
  //   esp[2 * kSystemPointerSize]: kIsolate
  //   esp[3 * kSystemPointerSize]: kContext
  //   esp[4 * kSystemPointerSize]: undefined (kReturnValue)
  //   esp[5 * kSystemPointerSize]: kTarget
  //   esp[6 * kSystemPointerSize]: undefined (kNewTarget)
  // Existing state:
  //   esp[7 * kSystemPointerSize]:          <= FCA:::values_

  __ StoreRootRelative(IsolateData::topmost_script_having_context_offset(),
                       topmost_script_having_context);

  if (mode == CallApiCallbackMode::kGeneric) {
    api_function_address = ReassignRegister(topmost_script_having_context);
  }

  // Park argc in xmm0.
  __ movd(xmm0, argc);

  __ PopReturnAddressTo(argc);
  __ PushRoot(RootIndex::kUndefinedValue);  // kNewTarget
  __ Push(func_templ);                      // kTarget
  __ PushRoot(RootIndex::kUndefinedValue);  // kReturnValue
  __ Push(kContextRegister);                // kContext

  // TODO(ishell): Consider using LoadAddress+push approach here.
  __ Push(Immediate(ER::isolate_address()));
  __ Push(holder);

  Register scratch = ReassignRegister(holder);

  // The API function takes v8::FunctionCallbackInfo reference, allocate it
  // in non-GCed space of the exit frame.
  static constexpr int kApiArgc = 1;
  static constexpr int kApiArg0Offset = 0 * kSystemPointerSize;

  if (mode == CallApiCallbackMode::kGeneric) {
    __ mov(api_function_address,
           FieldOperand(func_templ,
                        FunctionTemplateInfo::kMaybeRedirectedCallbackOffset));
  }

  __ PushReturnAddressFrom(argc);

  // The ApiCallbackExitFrame must be big enough to store the outgoing
  // parameters for C function on the stack.
  constexpr int extra_slots =
      FC::getExtraSlotsCountFrom<ExitFrameConstants>() + kApiArgc;
  __ EnterExitFrame(extra_slots, StackFrame::API_CALLBACK_EXIT,
                    api_function_address);

  if (v8_flags.debug_code) {
    __ mov(esi, Immediate(base::bit_cast<int32_t>(kZapValue)));
  }

  // Reload argc from xmm0.
  __ movd(argc, xmm0);

  Operand argc_operand = Operand(ebp, FC::kFCIArgcOffset);
  {
    ASM_CODE_COMMENT_STRING(masm, "Initialize v8::FunctionCallbackInfo");
    // FunctionCallbackInfo::length_.
    // TODO(ishell): pass JSParameterCount(argc) to simplify things on the
    // caller end.
    __ mov(argc_operand, argc);

    // FunctionCallbackInfo::implicit_args_.
    __ lea(scratch, Operand(ebp, FC::kImplicitArgsArrayOffset));
    __ mov(Operand(ebp, FC::kFCIImplicitArgsOffset), scratch);

    // FunctionCallbackInfo::values_ (points at JS arguments on the stack).
    __ lea(scratch, Operand(ebp, FC::kFirstArgumentOffset));
    __ mov(Operand(ebp, FC::kFCIValuesOffset), scratch);
  }

  __ RecordComment("v8::FunctionCallback's argument.");
  __ lea(scratch, Operand(ebp, FC::kFunctionCallbackInfoOffset));
  __ mov(ExitFrameStackSlotOperand(kApiArg0Offset), scratch);

  ExternalReference thunk_ref = ER::invoke_function_callback(mode);
  Register no_thunk_arg = no_reg;

  Operand return_value_operand = Operand(ebp, FC::kReturnValueOffset);
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
  //  -- esi                 : context
  //  -- edx                 : receiver
  //  -- ecx                 : holder
  //  -- eax                 : accessor info
  //  -- esp[0]              : return address
  // -----------------------------------

  Register receiver = ApiGetterDescriptor::ReceiverRegister();
  Register holder = ApiGetterDescriptor::HolderRegister();
  Register callback = ApiGetterDescriptor::CallbackRegister();
  Register scratch = edi;
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
  // Current state:
  //   esp[0]: return address
  //
  // Target state:
  //   esp[0 * kSystemPointerSize]: return address
  //   esp[1 * kSystemPointerSize]: name                      <= PCI::args_
  //   esp[2 * kSystemPointerSize]: kShouldThrowOnErrorIndex
  //   esp[3 * kSystemPointerSize]: kHolderIndex
  //   esp[4 * kSystemPointerSize]: kIsolateIndex
  //   esp[5 * kSystemPointerSize]: kHolderV2Index
  //   esp[6 * kSystemPointerSize]: kReturnValueIndex
  //   esp[7 * kSystemPointerSize]: kDataIndex
  //   esp[8 * kSystemPointerSize]: kThisIndex / receiver

  __ PopReturnAddressTo(scratch);
  __ push(receiver);
  __ push(FieldOperand(callback, AccessorInfo::kDataOffset));
  __ PushRoot(RootIndex::kUndefinedValue);  // kReturnValue
  __ Push(Smi::zero());                     // kHolderV2
  Register isolate_reg = ReassignRegister(receiver);
  __ LoadAddress(isolate_reg, ER::isolate_address());
  __ push(isolate_reg);
  __ push(holder);
  __ Push(Smi::FromInt(kDontThrow));  // should_throw_on_error -> kDontThrow

  Register name = ReassignRegister(holder);
  __ mov(name, FieldOperand(callback, AccessorInfo::kNameOffset));
  __ push(name);
  __ PushReturnAddressFrom(scratch);

  // The API function takes a name local handle and v8::PropertyCallbackInfo
  // reference, allocate them in non-GCed space of the exit frame.
  static constexpr int kApiArgc = 2;
  static constexpr int kApiArg0Offset = 0 * kSystemPointerSize;
  static constexpr int kApiArg1Offset = 1 * kSystemPointerSize;

  Register api_function_address = ReassignRegister(isolate_reg);
  __ RecordComment("Load function_address");
  __ mov(api_function_address,
         FieldOperand(callback, AccessorInfo::kMaybeRedirectedGetterOffset));

  __ EnterExitFrame(FC::getExtraSlotsCountFrom<ExitFrameConstants>() + kApiArgc,
                    StackFrame::API_ACCESSOR_EXIT, api_function_address);
  if (v8_flags.debug_code) {
    __ mov(esi, Immediate(base::bit_cast<int32_t>(kZapValue)));
  }

  __ RecordComment("Create v8::PropertyCallbackInfo object on the stack.");
  // property_callback_info_arg = v8::PropertyCallbackInfo&
  Register property_callback_info_arg = ReassignRegister(scratch);
  __ lea(property_callback_info_arg, Operand(ebp, FC::kArgsArrayOffset));

  DCHECK(!AreAliased(api_function_address, property_callback_info_arg, name,
                     callback));

  __ RecordComment("Local<Name>");
#ifdef V8_ENABLE_DIRECT_HANDLE
  // name_arg = Local<Name>(name), name value was pushed to GC-ed stack space.
  __ mov(ExitFrameStackSlotOperand(kApiArg0Offset), name);
#else
  // name_arg = Local<Name>(&name), which is &args_array[kPropertyKeyIndex].
  static_assert(PCA::kPropertyKeyIndex == 0);
  __ mov(ExitFrameStackSlotOperand(kApiArg0Offset), property_callback_info_arg);
#endif

  __ RecordComment("v8::PropertyCallbackInfo<T>&");
  __ mov(ExitFrameStackSlotOperand(kApiArg1Offset), property_callback_info_arg);

  ExternalReference thunk_ref = ER::invoke_accessor_getter_callback();
  // Pass AccessorInfo to thunk wrapper in case profiler or side-effect
  // checking is enabled.
  Register thunk_arg = callback;

  Operand return_value_operand = Operand(ebp, FC::kReturnValueOffset);
  static constexpr int kSlotsToDropOnReturn =
      FC::kPropertyCallbackInfoArgsLength;
  Operand* const kUseStackSpaceConstant = nullptr;

  const bool with_profiling = true;
  CallApiFunctionAndReturn(masm, with_profiling, api_function_address,
                           thunk_ref, thunk_arg, kSlotsToDropOnReturn,
                           kUseStackSpaceConstant, return_value_operand);
}

void Builtins::Generate_DirectCEntry(MacroAssembler* masm) {
  __ int3();  // Unused on this architecture.
}

namespace {

enum Direction { FORWARD, BACKWARD };
enum Alignment { MOVE_ALIGNED, MOVE_UNALIGNED };

// Expects registers:
// esi - source, aligned if alignment == ALIGNED
// edi - destination, always aligned
// ecx - count (copy size in bytes)
// edx - loop count (number of 64 byte chunks)
void MemMoveEmitMainLoop(MacroAssembler* masm, Label* move_last_15,
                         Direction direction, Alignment alignment) {
  ASM_CODE_COMMENT(masm);
  Register src = esi;
  Register dst = edi;
  Register count = ecx;
  Register loop_count = edx;
  Label loop, move_last_31, move_last_63;
  __ cmp(loop_count, 0);
  __ j(equal, &move_last_63);
  __ bind(&loop);
  // Main loop. Copy in 64 byte chunks.
  if (direction == BACKWARD) __ sub(src, Immediate(0x40));
  __ movdq(alignment == MOVE_ALIGNED, xmm0, Operand(src, 0x00));
  __ movdq(alignment == MOVE_ALIGNED, xmm1, Operand(src, 0x10));
  __ movdq(alignment == MOVE_ALIGNED, xmm2, Operand(src, 0x20));
  __ movdq(alignment == MOVE_ALIGNED, xmm3, Operand(src, 0x30));
  if (direction == FORWARD) __ add(src, Immediate(0x40));
  if (direction == BACKWARD) __ sub(dst, Immediate(0x40));
  __ movdqa(Operand(dst, 0x00), xmm0);
  __ movdqa(Operand(dst, 0x10), xmm1);
  __ movdqa(Operand(dst, 0x20), xmm2);
  __ movdqa(Operand(dst, 0x30), xmm3);
  if (direction == FORWARD) __ add(dst, Immediate(0x40));
  __ dec(loop_count);
  __ j(not_zero, &loop);
  // At most 63 bytes left to copy.
  __ bind(&move_last_63);
  __ test(count, Immediate(0x20));
  __ j(zero, &move_last_31);
  if (direction == BACKWARD) __ sub(src, Immediate(0x20));
  __ movdq(alignment == MOVE_ALIGNED, xmm0, Operand(src, 0x00));
  __ movdq(alignment == MOVE_ALIGNED, xmm1, Operand(src, 0x10));
  if (direction == FORWARD) __ add(src, Immediate(0x20));
  if (direction == BACKWARD) __ sub(dst, Immediate(0x20));
  __ movdqa(Operand(dst, 0x00), xmm0);
  __ movdqa(Operand(dst, 0x10), xmm1);
  if (direction == FORWARD) __ add(dst, Immediate(0x20));
  // At most 31 bytes left to copy.
  __ bind(&move_last_31);
  __ test(count, Immediate(0x10));
  __ j(zero, move_last_15);
  if (direction == BACKWARD) __ sub(src, Immediate(0x10));
  __ movdq(alignment == MOVE_ALIGNED, xmm0, Operand(src, 0));
  if (direction == FORWARD) __ add(src, Immediate(0x10));
  if (direction == BACKWARD) __ sub(dst, Immediate(0x10));
  __ movdqa(Operand(dst, 0), xmm0);
  if (direction == FORWARD) __ add(dst, Immediate(0x10));
}

void MemMoveEmitPopAndReturn(MacroAssembler* masm) {
  __ pop(esi);
  __ pop(edi);
  __ ret(0);
}

}  // namespace

void Builtins::Generate_MemMove(MacroAssembler* masm) {
  // Generated code is put into a fixed, unmovable buffer, and not into
  // the V8 heap. We can't, and don't, refer to any relocatable addresses
  // (e.g. the JavaScript nan-object).

  // 32-bit C declaration function calls pass arguments on stack.

  // Stack layout:
  // esp[12]: Third argument, size.
  // esp[8]: Second argument, source pointer.
  // esp[4]: First argument, destination pointer.
  // esp[0]: return address

  const int kDestinationOffset = 1 * kSystemPointerSize;
  const int kSourceOffset = 2 * kSystemPointerSize;
  const int kSizeOffset = 3 * kSystemPointerSize;

  // When copying up to this many bytes, use special "small" handlers.
  const size_t kSmallCopySize = 8;
  // When copying up to this many bytes, use special "medium" handlers.
  const size_t kMediumCopySize = 63;
  // When non-overlapping region of src and dst is less than this,
  // use a more careful implementation (slightly slower).
  const size_t kMinMoveDistance = 16;
  // Note that these values are dictated by the implementation below,
  // do not just change them and hope things will work!

  int stack_offset = 0;  // Update if we change the stack height.

  Label backward, backward_much_overlap;
  Label forward_much_overlap, small_size, medium_size, pop_and_return;
  __ push(edi);
  __ push(esi);
  stack_offset += 2 * kSystemPointerSize;
  Register dst = edi;
  Register src = esi;
  Register count = ecx;
  Register loop_count = edx;
  __ mov(dst, Operand(esp, stack_offset + kDestinationOffset));
  __ mov(src, Operand(esp, stack_offset + kSourceOffset));
  __ mov(count, Operand(esp, stack_offset + kSizeOffset));

  __ cmp(dst, src);
  __ j(equal, &pop_and_return);

  __ prefetch(Operand(src, 0), 1);
  __ cmp(count, kSmallCopySize);
  __ j(below_equal, &small_size);
  __ cmp(count, kMediumCopySize);
  __ j(below_equal, &medium_size);
  __ cmp(dst, src);
  __ j(above, &backward);

  {
    // |dst| is a lower address than |src|. Copy front-to-back.
    Label unaligned_source, move_last_15, skip_last_move;
    __ mov(eax, src);
    __ sub(eax, dst);
    __ cmp(eax, kMinMoveDistance);
    __ j(below, &forward_much_overlap);
    // Copy first 16 bytes.
    __ movdqu(xmm0, Operand(src, 0));
    __ movdqu(Operand(dst, 0), xmm0);
    // Determine distance to alignment: 16 - (dst & 0xF).
    __ mov(edx, dst);
    __ and_(edx, 0xF);
    __ neg(edx);
    __ add(edx, Immediate(16));
    __ add(dst, edx);
    __ add(src, edx);
    __ sub(count, edx);
    // dst is now aligned. Main copy loop.
    __ mov(loop_count, count);
    __ shr(loop_count, 6);
    // Check if src is also aligned.
    __ test(src, Immediate(0xF));
    __ j(not_zero, &unaligned_source);
    // Copy loop for aligned source and destination.
    MemMoveEmitMainLoop(masm, &move_last_15, FORWARD, MOVE_ALIGNED);
    // At most 15 bytes to copy. Copy 16 bytes at end of string.
    __ bind(&move_last_15);
    __ and_(count, 0xF);
    __ j(zero, &skip_last_move, Label::kNear);
    __ movdqu(xmm0, Operand(src, count, times_1, -0x10));
    __ movdqu(Operand(dst, count, times_1, -0x10), xmm0);
    __ bind(&skip_last_move);
    MemMoveEmitPopAndReturn(masm);

    // Copy loop for unaligned source and aligned destination.
    __ bind(&unaligned_source);
    MemMoveEmitMainLoop(masm, &move_last_15, FORWARD, MOVE_UNALIGNED);
    __ jmp(&move_last_15);

    // Less than kMinMoveDistance offset between dst and src.
    Label loop_until_aligned, last_15_much_overlap;
    __ bind(&loop_until_aligned);
    __ mov_b(eax, Operand(src, 0));
    __ inc(src);
    __ mov_b(Operand(dst, 0), eax);
    __ inc(dst);
    __ dec(count);
    __ bind(&forward_much_overlap);  // Entry point into this block.
    __ test(dst, Immediate(0xF));
    __ j(not_zero, &loop_until_aligned);
    // dst is now aligned, src can't be. Main copy loop.
    __ mov(loop_count, count);
    __ shr(loop_count, 6);
    MemMoveEmitMainLoop(masm, &last_15_much_overlap, FORWARD, MOVE_UNALIGNED);
    __ bind(&last_15_much_overlap);
    __ and_(count, 0xF);
    __ j(zero, &pop_and_return);
    __ cmp(count, kSmallCopySize);
    __ j(below_equal, &small_size);
    __ jmp(&medium_size);
  }

  {
    // |dst| is a higher address than |src|. Copy backwards.
    Label unaligned_source, move_first_15, skip_last_move;
    __ bind(&backward);
    // |dst| and |src| always point to the end of what's left to copy.
    __ add(dst, count);
    __ add(src, count);
    __ mov(eax, dst);
    __ sub(eax, src);
    __ cmp(eax, kMinMoveDistance);
    __ j(below, &backward_much_overlap);
    // Copy last 16 bytes.
    __ movdqu(xmm0, Operand(src, -0x10));
    __ movdqu(Operand(dst, -0x10), xmm0);
    // Find distance to alignment: dst & 0xF
    __ mov(edx, dst);
    __ and_(edx, 0xF);
    __ sub(dst, edx);
    __ sub(src, edx);
    __ sub(count, edx);
    // dst is now aligned. Main copy loop.
    __ mov(loop_count, count);
    __ shr(loop_count, 6);
    // Check if src is also aligned.
    __ test(src, Immediate(0xF));
    __ j(not_zero, &unaligned_source);
    // Copy loop for aligned source and destination.
    MemMoveEmitMainLoop(masm, &move_first_15, BACKWARD, MOVE_ALIGNED);
    // At most 15 bytes to copy. Copy 16 bytes at beginning of string.
    __ bind(&move_first_15);
    __ and_(count, 0xF);
    __ j(zero, &skip_last_move, Label::kNear);
    __ sub(src, count);
    __ sub(dst, count);
    __ movdqu(xmm0, Operand(src, 0));
    __ movdqu(Operand(dst, 0), xmm0);
    __ bind(&skip_last_move);
    MemMoveEmitPopAndReturn(masm);

    // Copy loop for unaligned source and aligned destination.
    __ bind(&unaligned_source);
    MemMoveEmitMainLoop(masm, &move_first_15, BACKWARD, MOVE_UNALIGNED);
    __ jmp(&move_first_15);

    // Less than kMinMoveDistance offset between dst and src.
    Label loop_until_aligned, first_15_much_overlap;
    __ bind(&loop_until_aligned);
    __ dec(src);
    __ dec(dst);
    __ mov_b(eax, Operand(src, 0));
    __ mov_b(Operand(dst, 0), eax);
    __ dec(count);
    __ bind(&backward_much_overlap);  // Entry point into this block.
    __ test(dst, Immediate(0xF));
    __ j(not_zero, &loop_until_aligned);
    // dst is now aligned, src can't be. Main copy loop.
    __ mov(loop_count, count);
    __ shr(loop_count, 6);
    MemMoveEmitMainLoop(masm, &first_15_much_overlap, BACKWARD, MOVE_UNALIGNED);
    __ bind(&first_15_much_overlap);
    __ and_(count, 0xF);
    __ j(zero, &pop_and_return);
    // Small/medium handlers expect dst/src to point to the beginning.
    __ sub(dst, count);
    __ sub(src, count);
    __ cmp(count, kSmallCopySize);
    __ j(below_equal, &small_size);
    __ jmp(&medium_size);
  }
  {
    // Special handlers for 9 <= copy_size < 64. No assumptions about
    // alignment or move distance, so all reads must be unaligned and
    // must happen before any writes.
    Label f9_16, f17_32, f33_48, f49_63;

    __ bind(&f9_16);
    __ movsd(xmm0, Operand(src, 0));
    __ movsd(xmm1, Operand(src, count, times_1, -8));
    __ movsd(Operand(dst, 0), xmm0);
    __ movsd(Operand(dst, count, times_1, -8), xmm1);
    MemMoveEmitPopAndReturn(masm);

    __ bind(&f17_32);
    __ movdqu(xmm0, Operand(src, 0));
    __ movdqu(xmm1, Operand(src, count, times_1, -0x10));
    __ movdqu(Operand(dst, 0x00), xmm0);
    __ movdqu(Operand(dst, count, times_1, -0x10), xmm1);
    MemMoveEmitPopAndReturn(masm);

    __ bind(&f33_48);
    __ movdqu(xmm0, Operand(src, 0x00));
    __ movdqu(xmm1, Operand(src, 0x10));
    __ movdqu(xmm2, Operand(src, count, times_1, -0x10));
    __ movdqu(Operand(dst, 0x00), xmm0);
    __ movdqu(Operand(dst, 0x10), xmm1);
    __ movdqu(Operand(dst, count, times_1, -0x10), xmm2);
    MemMoveEmitPopAndReturn(masm);

    __ bind(&f49_63);
    __ movdqu(xmm0, Operand(src, 0x00));
    __ movdqu(xmm1, Operand(src, 0x10));
    __ movdqu(xmm2, Operand(src, 0x20));
    __ movdqu(xmm3, Operand(src, count, times_1, -0x10));
    __ movdqu(Operand(dst, 0x00), xmm0);
    __ movdqu(Operand(dst, 0x10), xmm1);
    __ movdqu(Operand(dst, 0x20), xmm2);
    __ movdqu(Operand(dst, count, times_1, -0x10), xmm3);
    MemMoveEmitPopAndReturn(masm);

    __ bind(&medium_size);  // Entry point into this block.
    __ mov(eax, count);
    __ dec(eax);
    __ shr(eax, 4);
    if (v8_flags.debug_code) {
      Label ok;
      __ cmp(eax, 3);
      __ j(below_equal, &ok);
      __ int3();
      __ bind(&ok);
    }

    // Dispatch to handlers.
    Label eax_is_2_or_3;

    __ cmp(eax, 1);
    __ j(greater, &eax_is_2_or_3);
    __ j(less, &f9_16);  // eax == 0.
    __ jmp(&f17_32);     // eax == 1.

    __ bind(&eax_is_2_or_3);
    __ cmp(eax, 3);
    __ j(less, &f33_48);  // eax == 2.
    __ jmp(&f49_63);      // eax == 3.
  }
  {
    // Specialized copiers for copy_size <= 8 bytes.
    Label f0, f1, f2, f3, f4, f5_8;
    __ bind(&f0);
    MemMoveEmitPopAndReturn(masm);

    __ bind(&f1);
    __ mov_b(eax, Operand(src, 0));
    __ mov_b(Operand(dst, 0), eax);
    MemMoveEmitPopAndReturn(masm);

    __ bind(&f2);
    __ mov_w(eax, Operand(src, 0));
    __ mov_w(Operand(dst, 0), eax);
    MemMoveEmitPopAndReturn(masm);

    __ bind(&f3);
    __ mov_w(eax, Operand(src, 0));
    __ mov_b(edx, Operand(src, 2));
    __ mov_w(Operand(dst, 0), eax);
    __ mov_b(Operand(dst, 2), edx);
    MemMoveEmitPopAndReturn(masm);

    __ bind(&f4);
    __ mov(eax, Operand(src, 0));
    __ mov(Operand(dst, 0), eax);
    MemMoveEmitPopAndReturn(masm);

    __ bind(&f5_8);
    __ mov(eax, Operand(src, 0));
    __ mov(edx, Operand(src, count, times_1, -4));
    __ mov(Operand(dst, 0), eax);
    __ mov(Operand(dst, count, times_1, -4), edx);
    MemMoveEmitPopAndReturn(masm);

    __ bind(&small_size);  // Entry point into this block.
    if (v8_flags.debug_code) {
      Label ok;
      __ cmp(count, 8);
      __ j(below_equal, &ok);
      __ int3();
      __ bind(&ok);
    }

    // Dispatch to handlers.
    Label count_is_above_3, count_is_2_or_3;

    __ cmp(count, 3);
    __ j(greater, &count_is_above_3);

    __ cmp(count, 1);
    __ j(greater, &count_is_2_or_3);
    __ j(less, &f0);  // count == 0.
    __ jmp(&f1);      // count == 1.

    __ bind(&count_is_2_or_3);
    __ cmp(count, 3);
    __ j(less, &f2);  // count == 2.
    __ jmp(&f3);      // count == 3.

    __ bind(&count_is_above_3);
    __ cmp(count, 5);
    __ j(less, &f4);  // count == 4.
    __ jmp(&f5_8);    // count in [5, 8[.
  }

  __ bind(&pop_and_return);
  MemMoveEmitPopAndReturn(masm);
}

namespace {

void Generate_DeoptimizationEntry(MacroAssembler* masm,
                                  DeoptimizeKind deopt_kind) {
  Isolate* isolate = masm->isolate();

  // Save all general purpose registers before messing with them.
  const int kNumberOfRegisters = Register::kNumRegisters;

  const int kXmmRegsSize = kSimd128Size * XMMRegister::kNumRegisters;
  __ AllocateStackSpace(kXmmRegsSize);
  const RegisterConfiguration* config = RegisterConfiguration::Default();
  DCHECK_GE(XMMRegister::kNumRegisters,
            config->num_allocatable_simd128_registers());
  DCHECK_EQ(config->num_allocatable_simd128_registers(),
            config->num_allocatable_double_registers());
  for (int i = 0; i < config->num_allocatable_simd128_registers(); ++i) {
    int code = config->GetAllocatableSimd128Code(i);
    XMMRegister xmm_reg = XMMRegister::from_code(code);
    int offset = code * kSimd128Size;
    __ movdqu(Operand(esp, offset), xmm_reg);
  }

  __ pushad();

  ExternalReference c_entry_fp_address =
      ExternalReference::Create(IsolateAddressId::kCEntryFPAddress, isolate);
  __ mov(masm->ExternalReferenceAsOperand(c_entry_fp_address, esi), ebp);

  const int kSavedRegistersAreaSize =
      kNumberOfRegisters * kSystemPointerSize + kXmmRegsSize;

  // Get the address of the location in the code object
  // and compute the fp-to-sp delta in register edx.
  __ mov(ecx, Operand(esp, kSavedRegistersAreaSize));
  __ lea(edx, Operand(esp, kSavedRegistersAreaSize + 1 * kSystemPointerSize));

  __ sub(edx, ebp);
  __ neg(edx);

  // Allocate a new deoptimizer object.
  __ PrepareCallCFunction(5, eax);
  __ mov(eax, Immediate(0));
  Label context_check;
  __ mov(edi, Operand(ebp, CommonFrameConstants::kContextOrFrameTypeOffset));
  __ JumpIfSmi(edi, &context_check);
  __ mov(eax, Operand(ebp, StandardFrameConstants::kFunctionOffset));
  __ bind(&context_check);
  __ mov(Operand(esp, 0 * kSystemPointerSize), eax);  // Function.
  __ mov(Operand(esp, 1 * kSystemPointerSize),
         Immediate(static_cast<int>(deopt_kind)));
  __ mov(Operand(esp, 2 * kSystemPointerSize),
         ecx);  // InstructionStream address or 0.
  __ mov(Operand(esp, 3 * kSystemPointerSize), edx);  // Fp-to-sp delta.
  __ Move(Operand(esp, 4 * kSystemPointerSize),
          Immediate(ExternalReference::isolate_address()));
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::new_deoptimizer_function(), 5);
  }

  // Preserve deoptimizer object in register eax and get the input
  // frame descriptor pointer.
  __ mov(esi, Operand(eax, Deoptimizer::input_offset()));

  // Fill in the input registers.
  for (int i = kNumberOfRegisters - 1; i >= 0; i--) {
    int offset =
        (i * kSystemPointerSize) + FrameDescription::registers_offset();
    __ pop(Operand(esi, offset));
  }

  int simd128_regs_offset = FrameDescription::simd128_registers_offset();
  // Fill in the xmm (simd128 / double) input registers.
  for (int i = 0; i < config->num_allocatable_simd128_registers(); ++i) {
    int code = config->GetAllocatableSimd128Code(i);
    int dst_offset = code * kSimd128Size + simd128_regs_offset;
    int src_offset = code * kSimd128Size;
    __ movdqu(xmm0, Operand(esp, src_offset));
    __ movdqu(Operand(esi, dst_offset), xmm0);
  }

  // Clear FPU all exceptions.
  // TODO(ulan): Find out why the TOP register is not zero here in some cases,
  // and check that the generated code never deoptimizes with unbalanced stack.
  __ fnclex();

  // Mark the stack as not iterable for the CPU profiler which won't be able to
  // walk the stack without the return address.
  __ mov_b(__ ExternalReferenceAsOperand(IsolateFieldId::kStackIsIterable),
           Immediate(0));

  // Remove the return address and the xmm registers.
  __ add(esp, Immediate(kXmmRegsSize + 1 * kSystemPointerSize));

  // Compute a pointer to the unwinding limit in register ecx; that is
  // the first stack slot not part of the input frame.
  __ mov(ecx, Operand(esi, FrameDescription::frame_size_offset()));
  __ add(ecx, esp);

  // Unwind the stack down to - but not including - the unwinding
  // limit and copy the contents of the activation frame to the input
  // frame description.
  __ lea(edx, Operand(esi, FrameDescription::frame_content_offset()));
  Label pop_loop_header;
  __ jmp(&pop_loop_header);
  La
```