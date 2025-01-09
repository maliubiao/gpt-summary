Response:
The user wants a summary of the functionality of the provided C++ code snippet from V8. The code is part of the `builtins-ia32.cc` file, specifically for the IA32 architecture.

Here's a breakdown of the thought process to analyze the code and generate the summary:

1. **Identify the File's Purpose:** The file `builtins-ia32.cc` suggests it contains implementations of built-in functions for the IA32 architecture in V8. Built-ins are low-level, performance-critical functions often written in assembly or a close-to-metal language.

2. **Scan for Key Function Names and Patterns:** Look for function names starting with `Generate_`, indicating code generation for specific built-in functions. Also, notice keywords like `Wasm`, `JSToWasm`, `WasmToJs`, `Promise`, `Suspend`, `Resume`, `CEntry`, which hint at the functionalities.

3. **Analyze Individual Functions:** Go through each `Generate_` function and try to understand its purpose based on its name and the code within it.

    * **`Generate_JSToWasmWrapperAsm`:**  The name clearly indicates a wrapper for calls from JavaScript to WebAssembly. The code uses `JSToWasmWrapperHelper`.
    * **`Generate_WasmReturnPromiseOnSuspendAsm`:** This also uses `JSToWasmWrapperHelper` but with a `wasm::kPromise` mode, suggesting it's related to handling promises in WebAssembly when a suspension occurs.
    * **`Generate_JSToWasmStressSwitchStacksAsm`:**  Again, `JSToWasmWrapperHelper` is used, this time with `wasm::kStressSwitch`. This likely relates to stack switching for stress testing or specific scenarios.
    * **`Generate_WasmToJsWrapperAsm`:**  The opposite of the first one, this handles calls from WebAssembly back to JavaScript.
    * **`Generate_WasmTrapHandlerLandingPad`:**  A simple function that traps, indicating an error condition in WebAssembly.
    * **`Generate_WasmSuspend`:**  Deals with suspending WebAssembly execution, likely related to asynchronous operations.
    * **`Generate_WasmResume` and `Generate_WasmReject`:**  These seem to handle the resumption of WebAssembly execution after a suspension, with `WasmReject` probably handling the case where the promise is rejected.
    * **`Generate_WasmOnStackReplace`:**  The comment says "Only needed on x64," so on IA32 it simply traps, indicating it's not implemented or relevant for this architecture.
    * **`Generate_CEntry`:**  This is a crucial function for calling C++ functions from JavaScript.
    * **`Generate_WasmHandleStackOverflow`:** Handles stack overflow errors within WebAssembly.

4. **Identify Helper Functions:** Notice functions like `JSToWasmWrapperHelper`, `SwitchBackAndReturnPromise`, `GenerateExceptionHandlingLandingPad`, `ResetStackSwitchFrameStackSlots`, `FillJumpBuffer`, `SwitchStackState`, `SwitchStacks`, `LoadJumpBuffer`, `Generate_WasmResumeHelper`, `SwitchToTheCentralStackIfNeeded`, and `SwitchFromTheCentralStackIfNeeded`. These are internal functions used by the `Generate_` functions to implement their logic.

5. **Relate to JavaScript Concepts:**  Think about how the WebAssembly-related built-ins connect to JavaScript. For example, the `Promise` built-ins directly relate to JavaScript's Promise API. The `JSToWasm` and `WasmToJs` wrappers facilitate the interaction between the two environments.

6. **Infer Code Logic and Potential Errors:**

    * **Stack Switching:**  The code heavily uses stack manipulation, especially for promise handling and suspension/resumption. This is a complex area where mistakes can easily lead to crashes or unpredictable behavior.
    * **Promise Handling:**  The code explicitly deals with fulfilling and rejecting promises, which is a core part of asynchronous programming in JavaScript.
    * **Type Conversions:** Although not explicitly shown in this snippet, the wrappers likely handle the conversion of data between JavaScript and WebAssembly types.
    * **Memory Management:**  The code interacts with memory through `MemOperand` and potentially uses V8's garbage collector. Incorrect memory management can lead to leaks or crashes.

7. **Construct the Summary:**  Organize the findings into a coherent summary, addressing all points in the user's request.

    * Start with the overall purpose of the file.
    * List the functionalities of the main `Generate_` functions.
    * Explain the role of helper functions.
    * Provide JavaScript examples where relevant (focusing on WebAssembly interaction and Promises).
    * Give examples of potential programming errors (focusing on areas identified in the code analysis).
    * Conclude with a concise summary of the file's purpose.

8. **Review and Refine:** Read through the generated summary to ensure accuracy, clarity, and completeness. Make sure it directly answers the user's prompt. For example, ensuring the distinction between the different `JSToWasmWrapperAsm` variants is clear.
这是对 `v8/src/builtins/ia32/builtins-ia32.cc` 文件代码片段的功能归纳：

**主要功能：**

这段代码片段是 V8 JavaScript 引擎中针对 IA32 架构实现的内置函数（builtins）。它主要负责处理 JavaScript 和 WebAssembly 代码之间的互操作，以及 WebAssembly 内部的特定操作，尤其是与异步操作和错误处理相关的部分。

**具体功能点：**

1. **JavaScript 到 WebAssembly 的调用包装器 (JSToWasmWrapper):**
   - `Generate_JSToWasmWrapperAsm`:  生成从 JavaScript 调用普通 WebAssembly 函数的汇编代码。它负责设置栈帧，传递参数，调用 WebAssembly 代码，并处理返回值。
   - `Generate_WasmReturnPromiseOnSuspendAsm`: 生成用于处理 WebAssembly 挂起并返回 Promise 的汇编代码。当 WebAssembly 函数挂起时，它会创建一个 Promise 并返回给 JavaScript。
   - `Generate_JSToWasmStressSwitchStacksAsm`:  生成用于在 JavaScript 到 WebAssembly 调用期间进行栈切换的汇编代码，可能用于压力测试或特定场景。
   - `JSToWasmWrapperHelper`:  是以上三个函数的共享代码实现，负责进行栈帧设置、参数传递、调用 WebAssembly 代码以及处理返回值的通用逻辑。它根据 `mode` 参数区分不同的调用场景（普通调用、Promise 返回、压力测试）。
   - `SwitchToAllocatedStack` 和 `SwitchBackAndReturnPromise`:  处理栈的切换，这在异步操作或需要更大栈空间时很有用。
   - `GenerateExceptionHandlingLandingPad`:  当 WebAssembly 代码抛出异常时，该函数会生成相应的处理代码，将异常转换为 Promise 的 rejection。

2. **WebAssembly 到 JavaScript 的调用包装器 (WasmToJsWrapper):**
   - `Generate_WasmToJsWrapperAsm`: 生成从 WebAssembly 调用 JavaScript 函数的汇编代码。它负责设置栈帧，传递参数，并调用 `kWasmToJsWrapperCSA` 这个 Torque 实现的内置函数。

3. **WebAssembly 陷阱处理 (WasmTrapHandler):**
   - `Generate_WasmTrapHandlerLandingPad`: 生成 WebAssembly 陷阱 (trap) 发生时的处理代码，通常会导致程序终止或抛出错误。

4. **WebAssembly 挂起和恢复 (Wasm Suspend/Resume):**
   - `Generate_WasmSuspend`: 生成 WebAssembly 代码执行 `suspend` 操作时的汇编代码。它负责保存当前执行状态，切换到父 Continuation，并将 Promise 返回给 JavaScript。
   - `Generate_WasmResume`: 生成用于恢复已挂起的 WebAssembly 执行的汇编代码。当 Promise resolve 时，会调用此函数来恢复 WebAssembly 的执行。
   - `Generate_WasmReject`: 生成用于拒绝已挂起的 WebAssembly 执行的汇编代码。当 Promise reject 时，会调用此函数将错误传递回 WebAssembly。
   - `Generate_WasmResumeHelper`: 是 `Generate_WasmResume` 和 `Generate_WasmReject` 的共享代码实现。

5. **WebAssembly 栈上替换 (On-Stack Replace):**
   - `Generate_WasmOnStackReplace`:  在 IA32 架构上，此功能通过 `Trap()` 实现，表示该架构上可能不需要或未实现此优化。

6. **C 函数调用入口 (CEntry):**
   - `Generate_CEntry`:  生成从 JavaScript 调用 C++ 函数的汇编代码。它负责设置 ExitFrame，传递参数，调用 C++ 函数，并处理返回值和异常。
   - `SwitchToTheCentralStackIfNeeded` 和 `SwitchFromTheCentralStackIfNeeded`:  处理在调用 C 函数前后是否需要切换到中央栈。

7. **WebAssembly 栈溢出处理 (WasmHandleStackOverflow):**
   - `Generate_WasmHandleStackOverflow`: 生成处理 WebAssembly 栈溢出的汇编代码。它会尝试扩展栈空间，如果无法扩展，则调用运行时函数处理。

**如果 `v8/src/builtins/ia32/builtins-ia32.cc` 以 `.tq` 结尾：**

如果该文件以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是一种类型化的中间语言，用于生成高效的汇编代码。在这种情况下，你提供的 C++ 代码很可能是由 Torque 代码生成的。

**与 JavaScript 的功能关系和示例：**

这些内置函数是 JavaScript 与 WebAssembly 交互的基础。

**示例 (JavaScript 调用 WebAssembly 函数并处理 Promise):**

```javascript
async function callWasmFunction() {
  const response = await fetch('my_wasm_module.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);

  // 假设 WebAssembly 模块导出一个返回 Promise 的函数
  try {
    const result = await instance.exports.asyncFunction();
    console.log("WebAssembly 函数返回:", result);
  } catch (error) {
    console.error("WebAssembly 函数抛出错误:", error);
  }
}

callWasmFunction();
```

在这个例子中，`Generate_JSToWasmWrapperAsm` 或 `Generate_WasmReturnPromiseOnSuspendAsm` (取决于 WebAssembly 函数是否会挂起) 会被用来创建 `instance.exports.asyncFunction` 的调用包装器。如果 WebAssembly 函数内部使用了 `suspend`，那么 `Generate_WasmSuspend` 会被调用，并且 JavaScript 侧会接收到一个 Promise。当 WebAssembly 通过 `resume` 或抛出异常完成时，`Generate_WasmResume` 或 `GenerateExceptionHandlingLandingPad` 将分别处理 Promise 的 resolve 或 reject。

**代码逻辑推理 (假设输入与输出):**

**假设输入 (对于 `JSToWasmWrapperHelper`):**

* `wrapper_buffer`:  一个指向包含 WebAssembly 调用信息的缓冲区的指针，包括目标函数地址、参数等。
* JavaScript 函数调用 WebAssembly 函数时传递的参数。

**假设输出:**

* WebAssembly 函数的返回值会被写入到 `wrapper_buffer` 指定的位置。
* 如果 WebAssembly 函数返回一个 Promise (通过 `suspend`)，则会创建一个 JavaScript Promise 对象并返回。

**用户常见的编程错误：**

1. **WebAssembly 函数签名不匹配：**  JavaScript 调用 WebAssembly 函数时，参数类型和数量必须与 WebAssembly 导出的函数签名一致。不匹配会导致类型错误或崩溃。
   ```javascript
   // WebAssembly expects an integer, but JavaScript provides a string
   instance.exports.wasmFunction("hello"); // 可能会出错
   ```

2. **异步 WebAssembly 函数处理不当：** 如果 WebAssembly 函数返回 Promise，JavaScript 代码必须使用 `async/await` 或 `.then()`/`.catch()` 来正确处理 Promise 的 resolve 或 reject。
   ```javascript
   // 忘记 await 或 then/catch 处理
   instance.exports.asyncWasmFunction(); // Promise 没有被妥善处理
   ```

3. **在 WebAssembly 模块卸载后尝试调用：**  在 WebAssembly 模块被卸载后尝试调用其导出的函数会导致错误。

4. **内存访问错误：**  如果 WebAssembly 代码尝试访问超出其线性内存范围的地址，或者与 JavaScript 共享内存时出现同步问题，可能会导致错误。

**第 5 部分功能归纳：**

这段代码片段主要关注 **JavaScript 和 WebAssembly 之间的互操作**，特别是 **处理异步操作 (Promises) 和错误**。它定义了从 JavaScript 调用 WebAssembly，以及从 WebAssembly 调用 JavaScript 的底层机制。此外，它还包括了 WebAssembly 内部的控制流操作，如挂起和恢复，以及处理异常和栈溢出的机制。这些内置函数是 V8 引擎执行 WebAssembly 代码的关键组成部分。

Prompt: 
```
这是目录为v8/src/builtins/ia32/builtins-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/ia32/builtins-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共7部分，请归纳一下它的功能

"""
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
  __ mov(esp
"""


```