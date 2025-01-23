Response:
The user wants me to analyze a V8 source code snippet. I need to:
1. **List the functionalities** present in the provided code.
2. **Determine if it's a Torque file:** Based on the filename ending.
3. **Illustrate with JavaScript:** If the code relates to JavaScript features.
4. **Provide logic examples:** With hypothetical inputs and outputs.
5. **Highlight common programming errors:** If applicable.
6. **Summarize the overall function:** As this is part 5 of 6.

Let's break down the code:

- **`StoreTaggedField`, `LoadTaggedField`, `RecordWriteField`:** These suggest interactions with V8's object model and garbage collection.
- **`WasmSuspenderObject`, `WasmContinuationObject`:** Indicate WebAssembly suspension and resumption mechanisms.
- **`SwitchStacks`:**  Points towards context switching, likely related to WebAssembly coroutines or async operations.
- **`LoadJumpBuffer`:**  Suggests restoring execution state.
- **`Generate_WasmResume`, `Generate_WasmReject`:**  Clearly related to resuming or rejecting WebAssembly suspended functions.
- **`SwitchToAllocatedStack`, `SwitchBackAndReturnPromise`:** Indicate stack manipulation for WebAssembly promises.
- **`GenerateExceptionHandlingLandingPad`:** Handles exceptions thrown within WebAssembly.
- **`JSToWasmWrapperHelper`:** Deals with transitions between JavaScript and WebAssembly.
- **`Generate_JSToWasmWrapperAsm`, `Generate_WasmReturnPromiseOnSuspendAsm`, `Generate_JSToWasmStressSwitchStacksAsm`:**  Different entry points for the JSToWasm wrapper.
- **`Generate_CEntry`:** Handles calls from JavaScript to C++ functions.
- **`Generate_WasmHandleStackOverflow`:** Manages stack overflow situations in WebAssembly.
- **`Generate_DoubleToI`:** Converts double-precision floating-point numbers to integers.
- **`Generate_CallApiCallbackImpl`:**  Implements callbacks from C++ to JavaScript.

Based on the file path (`v8/src/builtins/loong64/builtins-loong64.cc`), this is a platform-specific implementation for the LoongArch 64-bit architecture.

The code heavily revolves around WebAssembly and the interaction between JavaScript and WebAssembly.
这是v8源代码文件 `v8/src/builtins/loong64/builtins-loong64.cc` 的一部分，它为 LoongArch 64 位架构实现了 V8 引擎的内置函数。  根据提供的代码片段，我们可以归纳出以下功能：

**主要功能:**

* **WebAssembly 协程 (Coroutines) 的恢复和拒绝:**  这段代码实现了 WebAssembly 协程的恢复 (`Generate_WasmResumeHelper`) 和拒绝 (`Generate_WasmReject`) 操作。这允许 WebAssembly 代码挂起执行并在稍后恢复，或者在发生错误时被拒绝。
* **WebAssembly 栈切换:** 代码中包含了处理 WebAssembly 栈切换的逻辑 (`SwitchToAllocatedStack`, `SwitchStacks`, `SwitchBackAndReturnPromise`)。这通常用于实现异步操作或协程，其中需要切换到不同的栈来继续执行。
* **JavaScript 到 WebAssembly 的调用包装器:**  `JSToWasmWrapperHelper` 函数及其相关的生成函数 (`Generate_JSToWasmWrapperAsm`, `Generate_WasmReturnPromiseOnSuspendAsm`, `Generate_JSToWasmStressSwitchStacksAsm`)  负责处理从 JavaScript 调用 WebAssembly 函数的场景。 这包括设置必要的栈帧、传递参数、调用 WebAssembly 代码以及处理返回值。
* **异常处理 (WebAssembly):**  `GenerateExceptionHandlingLandingPad` 函数定义了当 WebAssembly 代码抛出异常时如何处理，通常涉及到拒绝一个 Promise。

**更详细的功能分解:**

1. **`Generate_WasmResumeHelper` (用于 `Generate_WasmResume` 和 `Generate_WasmReject`)**:
   - **状态存储和激活:** 存储当前挂起对象的状态，并将其设置为活动挂起对象。
   - **目标延续的加载:** 加载目标延续对象，这是要恢复执行的协程的状态。
   - **父延续的设置:** 将当前激活的延续对象设置为目标延续对象的父对象。
   - **栈切换:** 使用 `SwitchStacks` 宏切换到目标延续的栈。
   - **状态加载 (longjmp 模拟):** 从目标延续的 jmpbuf 中加载状态，模拟 `longjmp` 的行为。
   - **返回值处理:**  根据 `on_resume` 的值，正常恢复执行或抛出一个异常。

2. **`SwitchToAllocatedStack`:**
   - **保存父延续状态:** 保存父延续的状态信息。
   - **栈切换:**  切换到为 WebAssembly 实例分配的栈。
   - **加载目标 jmpbuf:**  加载目标延续的 jmpbuf。
   - **分配和初始化新的包装器缓冲区:** 在新的栈上分配空间，并从旧的包装器缓冲区复制必要的数据。

3. **`SwitchBackAndReturnPromise`:**
   - **重置寄存器:** 清理寄存器状态。
   - **处理 WebAssembly 函数的返回值:**  将 WebAssembly 函数的返回值设置为 Promise 的结果。
   - **重新加载父延续和挂起对象:** 恢复执行前的上下文。
   - **调用 Promise 的解决 (FulfillPromise) 或拒绝 (在 `GenerateExceptionHandlingLandingPad` 中)。**

4. **`GenerateExceptionHandlingLandingPad`:**
   - **设置异常参数:**  将捕获的异常设置为拒绝 Promise 的原因。
   - **重新加载父延续和挂起对象:** 恢复执行前的上下文。
   - **调用 Promise 的拒绝 (RejectPromise)。**

5. **`JSToWasmWrapperHelper`:**
   - **设置栈帧:** 创建一个 `STACK_SWITCH` 或 `JS_TO_WASM` 类型的栈帧。
   - **加载隐式参数:**  加载 WebAssembly 实例数据或导入数据。
   - **分配栈空间:**  为 WebAssembly 函数的返回结果分配栈空间。
   - **参数传递:** 从包装器缓冲区加载参数，并将它们放入寄存器或栈中。
   - **设置 `thread_in_wasm_flag`:** 标记当前线程正在执行 WebAssembly 代码。
   - **调用 WebAssembly 函数:**  使用 `Call` 宏调用目标 WebAssembly 函数。
   - **处理返回值:** 将 WebAssembly 函数的返回值存储到包装器缓冲区。
   - **调用返回值处理内置函数 (`JSToWasmHandleReturns`)。**
   - **处理栈切换后的返回 (通过 `SwitchBackAndReturnPromise`)。**
   - **处理异常 (调用 `GenerateExceptionHandlingLandingPad`)。**

**与 JavaScript 的关系及示例:**

这段代码直接关联到 JavaScript 调用 WebAssembly 功能。以下 JavaScript 示例展示了 WebAssembly 的挂起和恢复概念，虽然具体的实现细节在 V8 内部，但核心思想是一致的：

```javascript
// 假设我们有一个 WebAssembly 模块，其中包含一个可以挂起的函数
async function runWasm() {
  const response = await fetch('my_module.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const importObject = {}; // 可能的导入
  const instance = await WebAssembly.instantiate(module, importObject);

  const wasmFunction = instance.exports.mySuspendingFunction;

  try {
    const result = await wasmFunction(); // 调用 WebAssembly 函数，可能挂起
    console.log("WebAssembly function returned:", result);
  } catch (error) {
    console.error("WebAssembly function encountered an error:", error);
  }
}

runWasm();
```

在这个例子中，`mySuspendingFunction` 在 WebAssembly 内部可能执行到某个点，然后挂起。V8 的内置函数（例如 `Generate_WasmResume` 和 `Generate_WasmReject` 中涉及的逻辑）负责管理这种挂起和后续的恢复或拒绝。 `JSToWasmWrapperHelper` 确保了从 JavaScript 到 WebAssembly 的正确调用和返回值处理。

**代码逻辑推理示例:**

**假设输入:**

* `suspender`: 一个指向 `WasmSuspenderObject` 的指针，表示当前挂起的 WebAssembly 执行状态。
* `active_continuation`: 一个指向当前激活的 `WasmContinuationObject` 的指针。
* `target_continuation` (在恢复时): 一个指向要恢复的 `WasmContinuationObject` 的指针。
* `on_resume`:  枚举值，指示是正常恢复 (`wasm::OnResume::kContinue`) 还是抛出异常 (`wasm::OnResume::kThrow`)。

**输出 (以 `Generate_WasmResumeHelper` 为例):**

* 如果 `on_resume` 是 `wasm::OnResume::kContinue`:  程序执行流切换到 `target_continuation` 的栈，并从其保存的状态继续执行。
* 如果 `on_resume` 是 `wasm::OnResume::kThrow`:  程序执行流切换到 `target_continuation` 的栈，并抛出一个异常。

**用户常见的编程错误 (与此代码相关的概念):**

* **在 JavaScript 中错误地处理 WebAssembly Promise:**  如果 WebAssembly 函数返回一个 Promise（表示可能挂起），开发者需要正确地使用 `async/await` 或 `.then()`/`.catch()` 来处理 Promise 的解决或拒绝。 忘记处理 Promise 的拒绝会导致未捕获的错误。
* **WebAssembly 模块导出错误的函数签名:** 如果 JavaScript 调用 WebAssembly 函数时传递的参数类型或数量与 WebAssembly 导出的函数签名不匹配，会导致运行时错误。 `JSToWasmWrapperHelper` 负责进行一定的类型转换和检查，但根本上，开发者需要确保接口的正确性。
* **WebAssembly 代码中未处理的异常:** 如果 WebAssembly 代码抛出异常且没有在内部捕获，这个异常会传播到 JavaScript 代码中。开发者需要在 JavaScript 中适当地捕获和处理这些异常。

**归纳总结 (作为第 5 部分):**

到目前为止，我们分析的代码片段主要关注了 **V8 引擎中 LoongArch64 架构下对 WebAssembly 协程和 JavaScript 到 WebAssembly 调用的底层支持**。 这部分代码实现了核心的栈切换、状态管理、以及异常处理机制，使得 JavaScript 可以安全地调用和管理可能挂起的 WebAssembly 函数。它为实现 `async/await` 等异步编程模型在 WebAssembly 中的应用奠定了基础。接下来的部分可能涉及其他 V8 内置函数的实现，或者与此相关的更具体的功能模块。

### 提示词
```
这是目录为v8/src/builtins/loong64/builtins-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/loong64/builtins-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
StoreTaggedField(
      scratch, FieldMemOperand(suspender, WasmSuspenderObject::kStateOffset));
  int32_t active_suspender_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveSuspender);
  __ St_d(suspender, MemOperand(kRootRegister, active_suspender_offset));

  // Next line we are going to load a field from suspender, but we have to use
  // the same register for target_continuation to use it in RecordWriteField.
  // So, free suspender here to use pinned reg, but load from it next line.
  FREE_REG(suspender);
  DEFINE_PINNED(target_continuation, WriteBarrierDescriptor::ObjectRegister());
  suspender = target_continuation;
  __ LoadTaggedField(
      target_continuation,
      FieldMemOperand(suspender, WasmSuspenderObject::kContinuationOffset));
  suspender = no_reg;

  __ StoreTaggedField(active_continuation,
                      FieldMemOperand(target_continuation,
                                      WasmContinuationObject::kParentOffset));
  __ RecordWriteField(
      target_continuation, WasmContinuationObject::kParentOffset,
      active_continuation, kRAHasBeenSaved, SaveFPRegsMode::kIgnore);
  FREE_REG(active_continuation);
  int32_t active_continuation_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveContinuation);
  __ St_d(target_continuation,
          MemOperand(kRootRegister, active_continuation_offset));

  SwitchStacks(masm, no_reg, target_continuation);

  regs.ResetExcept(target_continuation);

  // -------------------------------------------
  // Load state from target jmpbuf (longjmp).
  // -------------------------------------------
  regs.Reserve(kReturnRegister0);
  DEFINE_REG(target_jmpbuf);
  ASSIGN_REG(scratch);
  __ LoadExternalPointerField(
      target_jmpbuf,
      FieldMemOperand(target_continuation,
                      WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);
  // Move resolved value to return register.
  __ Ld_d(kReturnRegister0, MemOperand(fp, 3 * kSystemPointerSize));
  MemOperand GCScanSlotPlace =
      MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset);
  __ St_d(zero_reg, GCScanSlotPlace);
  if (on_resume == wasm::OnResume::kThrow) {
    // Switch to the continuation's stack without restoring the PC.
    LoadJumpBuffer(masm, target_jmpbuf, false, scratch,
                   wasm::JumpBuffer::Suspended);
    // Pop this frame now. The unwinder expects that the first STACK_SWITCH
    // frame is the outermost one.
    __ LeaveFrame(StackFrame::STACK_SWITCH);
    // Forward the onRejected value to kThrow.
    __ Push(kReturnRegister0);
    __ CallRuntime(Runtime::kThrow);
  } else {
    // Resume the continuation normally.
    LoadJumpBuffer(masm, target_jmpbuf, true, scratch,
                   wasm::JumpBuffer::Suspended);
  }
  __ Trap();
  __ bind(&suspend);
  __ LeaveFrame(StackFrame::STACK_SWITCH);
  // Pop receiver + parameter.
  __ Add_d(sp, sp, Operand(2 * kSystemPointerSize));
  __ Ret();
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
void SwitchToAllocatedStack(MacroAssembler* masm, RegisterAllocator& regs,
                            Register wasm_instance, Register wrapper_buffer,
                            Register& original_fp, Register& new_wrapper_buffer,
                            Label* suspend) {
  ResetStackSwitchFrameStackSlots(masm);
  DEFINE_SCOPED(scratch)
  DEFINE_REG(target_continuation)
  __ LoadRoot(target_continuation, RootIndex::kActiveContinuation);
  DEFINE_REG(parent_continuation)
  __ LoadTaggedField(parent_continuation,
                     FieldMemOperand(target_continuation,
                                     WasmContinuationObject::kParentOffset));

  SaveState(masm, parent_continuation, scratch, suspend);

  SwitchStacks(masm, no_reg, wasm_instance, wrapper_buffer);

  FREE_REG(parent_continuation);
  // Save the old stack's fp in t0, and use it to access the parameters in
  // the parent frame.
  regs.Pinned(t1, &original_fp);
  __ mov(original_fp, fp);
  __ LoadRoot(target_continuation, RootIndex::kActiveContinuation);
  LoadTargetJumpBuffer(masm, target_continuation, scratch,
                       wasm::JumpBuffer::Suspended);
  FREE_REG(target_continuation);

  // Push the loaded fp. We know it is null, because there is no frame yet,
  // so we could also push 0 directly. In any case we need to push it,
  // because this marks the base of the stack segment for
  // the stack frame iterator.
  __ EnterFrame(StackFrame::STACK_SWITCH);

  int stack_space =
      RoundUp(StackSwitchFrameConstants::kNumSpillSlots * kSystemPointerSize +
                  JSToWasmWrapperFrameConstants::kWrapperBufferSize,
              16);
  __ Sub_d(sp, sp, Operand(stack_space));

  ASSIGN_REG(new_wrapper_buffer)

  __ mov(new_wrapper_buffer, sp);
  // Copy data needed for return handling from old wrapper buffer to new one.
  // kWrapperBufferRefReturnCount will be copied too, because 8 bytes are copied
  // at the same time.
  static_assert(JSToWasmWrapperFrameConstants::kWrapperBufferRefReturnCount ==
                JSToWasmWrapperFrameConstants::kWrapperBufferReturnCount + 4);
  __ Ld_d(scratch,
          MemOperand(wrapper_buffer,
                     JSToWasmWrapperFrameConstants::kWrapperBufferReturnCount));
  __ St_d(scratch,
          MemOperand(new_wrapper_buffer,
                     JSToWasmWrapperFrameConstants::kWrapperBufferReturnCount));
  __ Ld_d(
      scratch,
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferSigRepresentationArray));
  __ St_d(
      scratch,
      MemOperand(
          new_wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferSigRepresentationArray));
}

void SwitchBackAndReturnPromise(MacroAssembler* masm, RegisterAllocator& regs,
                                wasm::Promise mode, Label* return_promise) {
  regs.ResetExcept();
  // The return value of the wasm function becomes the parameter of the
  // FulfillPromise builtin, and the promise is the return value of this
  // wrapper.
  static const Builtin_FulfillPromise_InterfaceDescriptor desc;
  DEFINE_PINNED(promise, desc.GetRegisterParameter(0));
  DEFINE_PINNED(return_value, desc.GetRegisterParameter(1));
  DEFINE_SCOPED(tmp);
  DEFINE_SCOPED(tmp2);
  DEFINE_SCOPED(tmp3);
  if (mode == wasm::kPromise) {
    __ mov(return_value, kReturnRegister0);
    __ LoadRoot(promise, RootIndex::kActiveSuspender);
    __ LoadTaggedField(
        promise, FieldMemOperand(promise, WasmSuspenderObject::kPromiseOffset));
  }

  __ Ld_d(kContextRegister,
          MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
  GetContextFromImplicitArg(masm, kContextRegister, tmp);

  ReloadParentContinuation(masm, promise, return_value, kContextRegister, tmp,
                           tmp2, tmp3);
  RestoreParentSuspender(masm, tmp, tmp2);

  if (mode == wasm::kPromise) {
    __ li(tmp, Operand(1));
    __ St_d(tmp,
            MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset));
    __ Push(promise);
    __ CallBuiltin(Builtin::kFulfillPromise);
    __ Pop(promise);
  }
  FREE_REG(promise);
  FREE_REG(return_value);

  __ bind(return_promise);
}

void GenerateExceptionHandlingLandingPad(MacroAssembler* masm,
                                         RegisterAllocator& regs,
                                         Label* return_promise) {
  regs.ResetExcept();
  static const Builtin_RejectPromise_InterfaceDescriptor desc;
  DEFINE_PINNED(promise, desc.GetRegisterParameter(0));
  DEFINE_PINNED(reason, desc.GetRegisterParameter(1));
  DEFINE_PINNED(debug_event, desc.GetRegisterParameter(2));
  int catch_handler = __ pc_offset();

  DEFINE_SCOPED(thread_in_wasm_flag_addr);
  thread_in_wasm_flag_addr = a2;

  // Unset thread_in_wasm_flag.
  __ Ld_d(
      thread_in_wasm_flag_addr,
      MemOperand(kRootRegister, Isolate::thread_in_wasm_flag_address_offset()));
  __ St_w(zero_reg, MemOperand(thread_in_wasm_flag_addr, 0));

  // The exception becomes the parameter of the RejectPromise builtin, and the
  // promise is the return value of this wrapper.
  __ mov(reason, kReturnRegister0);
  __ LoadRoot(promise, RootIndex::kActiveSuspender);
  __ LoadTaggedField(
      promise, FieldMemOperand(promise, WasmSuspenderObject::kPromiseOffset));

  __ Ld_d(kContextRegister,
          MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));

  DEFINE_SCOPED(tmp);
  DEFINE_SCOPED(tmp2);
  DEFINE_SCOPED(tmp3);
  GetContextFromImplicitArg(masm, kContextRegister, tmp);
  ReloadParentContinuation(masm, promise, reason, kContextRegister, tmp, tmp2,
                           tmp3);
  RestoreParentSuspender(masm, tmp, tmp2);

  __ li(tmp, Operand(1));
  __ St_d(tmp,
          MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset));
  __ Push(promise);
  __ LoadRoot(debug_event, RootIndex::kTrueValue);
  __ CallBuiltin(Builtin::kRejectPromise);
  __ Pop(promise);

  // Run the rest of the wrapper normally (deconstruct the frame, ...).
  __ jmp(return_promise);

  masm->isolate()->builtins()->SetJSPIPromptHandlerOffset(catch_handler);
}

void JSToWasmWrapperHelper(MacroAssembler* masm, wasm::Promise mode) {
  bool stack_switch = mode == wasm::kPromise || mode == wasm::kStressSwitch;
  auto regs = RegisterAllocator::WithAllocatableGeneralRegisters();

  __ EnterFrame(stack_switch ? StackFrame::STACK_SWITCH
                             : StackFrame::JS_TO_WASM);

  __ AllocateStackSpace(StackSwitchFrameConstants::kNumSpillSlots *
                        kSystemPointerSize);

  // Load the implicit argument (instance data or import data) from the frame.
  DEFINE_PINNED(implicit_arg, kWasmImplicitArgRegister);
  __ Ld_d(implicit_arg,
          MemOperand(fp, JSToWasmWrapperFrameConstants::kImplicitArgOffset));

  DEFINE_PINNED(wrapper_buffer,
                WasmJSToWasmWrapperDescriptor::WrapperBufferRegister());

  Label suspend;
  Register original_fp = no_reg;
  Register new_wrapper_buffer = no_reg;
  if (stack_switch) {
    SwitchToAllocatedStack(masm, regs, implicit_arg, wrapper_buffer,
                           original_fp, new_wrapper_buffer, &suspend);
  } else {
    original_fp = fp;
    new_wrapper_buffer = wrapper_buffer;
  }

  regs.ResetExcept(original_fp, wrapper_buffer, implicit_arg,
                   new_wrapper_buffer);

  {
    __ St_d(
        new_wrapper_buffer,
        MemOperand(fp, JSToWasmWrapperFrameConstants::kWrapperBufferOffset));
    if (stack_switch) {
      __ St_d(implicit_arg,
              MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
      DEFINE_SCOPED(scratch)
      __ Ld_d(
          scratch,
          MemOperand(original_fp,
                     JSToWasmWrapperFrameConstants::kResultArrayParamOffset));
      __ St_d(scratch,
              MemOperand(fp, StackSwitchFrameConstants::kResultArrayOffset));
    }
  }
  {
    DEFINE_SCOPED(result_size);
    __ Ld_d(result_size, MemOperand(wrapper_buffer,
                                    JSToWasmWrapperFrameConstants::
                                        kWrapperBufferStackReturnBufferSize));
    __ slli_d(result_size, result_size, kSystemPointerSizeLog2);
    __ Sub_d(sp, sp, result_size);
  }

  __ St_d(
      sp,
      MemOperand(
          new_wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferStackReturnBufferStart));

  if (stack_switch) {
    FREE_REG(new_wrapper_buffer)
  }
  FREE_REG(implicit_arg)
  for (auto reg : wasm::kGpParamRegisters) {
    regs.Reserve(reg);
  }

  // The first GP parameter holds the trusted instance data or the import data.
  // This is handled specially.
  int stack_params_offset =
      (arraysize(wasm::kGpParamRegisters) - 1) * kSystemPointerSize +
      arraysize(wasm::kFpParamRegisters) * kDoubleSize;
  int param_padding = stack_params_offset & kSystemPointerSize;
  stack_params_offset += param_padding;

  {
    DEFINE_SCOPED(params_start);
    __ Ld_d(
        params_start,
        MemOperand(wrapper_buffer,
                   JSToWasmWrapperFrameConstants::kWrapperBufferParamStart));
    {
      // Push stack parameters on the stack.
      DEFINE_SCOPED(params_end);
      __ Ld_d(
          params_end,
          MemOperand(wrapper_buffer,
                     JSToWasmWrapperFrameConstants::kWrapperBufferParamEnd));
      DEFINE_SCOPED(last_stack_param);

      __ Add_d(last_stack_param, params_start, Operand(stack_params_offset));
      Label loop_start;
      __ bind(&loop_start);

      Label finish_stack_params;
      __ Branch(&finish_stack_params, ge, last_stack_param,
                Operand(params_end));

      // Push parameter
      {
        DEFINE_SCOPED(scratch);
        __ Sub_d(params_end, params_end, Operand(kSystemPointerSize));
        __ Ld_d(scratch, MemOperand(params_end, 0));
        __ Push(scratch);
      }

      __ Branch(&loop_start);

      __ bind(&finish_stack_params);
    }

    size_t next_offset = 0;
    for (size_t i = 1; i < arraysize(wasm::kGpParamRegisters); ++i) {
      // Check that {params_start} does not overlap with any of the parameter
      // registers, so that we don't overwrite it by accident with the loads
      // below.
      DCHECK_NE(params_start, wasm::kGpParamRegisters[i]);
      __ Ld_d(wasm::kGpParamRegisters[i],
              MemOperand(params_start, next_offset));
      next_offset += kSystemPointerSize;
    }

    next_offset += param_padding;
    for (size_t i = 0; i < arraysize(wasm::kFpParamRegisters); ++i) {
      __ Fld_d(wasm::kFpParamRegisters[i],
               MemOperand(params_start, next_offset));
      next_offset += kDoubleSize;
    }
    DCHECK_EQ(next_offset, stack_params_offset);
  }

  {
    DEFINE_SCOPED(thread_in_wasm_flag_addr);
    __ Ld_d(thread_in_wasm_flag_addr,
            MemOperand(kRootRegister,
                       Isolate::thread_in_wasm_flag_address_offset()));
    DEFINE_SCOPED(scratch);
    __ li(scratch, Operand(1));
    __ St_w(scratch, MemOperand(thread_in_wasm_flag_addr, 0));
  }

  __ St_d(zero_reg,
          MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset));
  {
    DEFINE_SCOPED(call_target);
    __ Ld_d(
        call_target,
        MemOperand(wrapper_buffer,
                   JSToWasmWrapperFrameConstants::kWrapperBufferCallTarget));
    __ Call(call_target);
  }

  regs.ResetExcept();
  // The wrapper_buffer has to be in a2 as the correct parameter register.
  regs.Reserve(kReturnRegister0, kReturnRegister1);
  ASSIGN_PINNED(wrapper_buffer, a2);
  {
    DEFINE_SCOPED(thread_in_wasm_flag_addr);
    __ Ld_d(thread_in_wasm_flag_addr,
            MemOperand(kRootRegister,
                       Isolate::thread_in_wasm_flag_address_offset()));
    __ St_w(zero_reg, MemOperand(thread_in_wasm_flag_addr, 0));
  }

  __ Ld_d(wrapper_buffer,
          MemOperand(fp, JSToWasmWrapperFrameConstants::kWrapperBufferOffset));

  __ Fst_d(wasm::kFpReturnRegisters[0],
           MemOperand(
               wrapper_buffer,
               JSToWasmWrapperFrameConstants::kWrapperBufferFPReturnRegister1));
  __ Fst_d(wasm::kFpReturnRegisters[1],
           MemOperand(
               wrapper_buffer,
               JSToWasmWrapperFrameConstants::kWrapperBufferFPReturnRegister2));
  __ St_d(wasm::kGpReturnRegisters[0],
          MemOperand(
              wrapper_buffer,
              JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister1));
  __ St_d(wasm::kGpReturnRegisters[1],
          MemOperand(
              wrapper_buffer,
              JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister2));

  // Call the return value builtin with
  // a0: wasm instance.
  // a1: the result JSArray for multi-return.
  // a2: pointer to the byte buffer which contains all parameters.
  if (stack_switch) {
    __ Ld_d(a1, MemOperand(fp, StackSwitchFrameConstants::kResultArrayOffset));
    __ Ld_d(a0, MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
  } else {
    __ Ld_d(
        a1,
        MemOperand(fp, JSToWasmWrapperFrameConstants::kResultArrayParamOffset));
    __ Ld_d(a0,
            MemOperand(fp, JSToWasmWrapperFrameConstants::kImplicitArgOffset));
  }

  Register scratch = a3;
  GetContextFromImplicitArg(masm, a0, scratch);
  __ Call(BUILTIN_CODE(masm->isolate(), JSToWasmHandleReturns),
          RelocInfo::CODE_TARGET);

  Label return_promise;
  if (stack_switch) {
    SwitchBackAndReturnPromise(masm, regs, mode, &return_promise);
  }
  __ bind(&suspend);

  __ LeaveFrame(stack_switch ? StackFrame::STACK_SWITCH
                             : StackFrame::JS_TO_WASM);
  // Despite returning to the different location for regular and stack switching
  // versions, incoming argument count matches both cases:
  // instance and result array without suspend or
  // or promise resolve/reject params for callback.
  __ Add_d(sp, sp, Operand(2 * kSystemPointerSize));
  __ Ret();

  // Catch handler for the stack-switching wrapper: reject the promise with the
  // thrown exception.
  if (mode == wasm::kPromise) {
    GenerateExceptionHandlingLandingPad(masm, regs, &return_promise);
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

namespace {

static constexpr Register kOldSPRegister = s3;
static constexpr Register kSwitchFlagRegister = s4;

void SwitchToTheCentralStackIfNeeded(MacroAssembler* masm, Register argc_input,
                                     Register target_input,
                                     Register argv_input) {
  using ER = ExternalReference;

  __ mov(kSwitchFlagRegister, zero_reg);
  __ mov(kOldSPRegister, sp);

  // Using a2-a4 as temporary registers, because they will be rewritten
  // before exiting to native code anyway.

  ER on_central_stack_flag_loc = ER::Create(
      IsolateAddressId::kIsOnCentralStackFlagAddress, masm->isolate());
  const Register& on_central_stack_flag = a2;
  __ li(on_central_stack_flag, on_central_stack_flag_loc);
  __ Ld_b(on_central_stack_flag, MemOperand(on_central_stack_flag, 0));

  Label do_not_need_to_switch;
  __ Branch(&do_not_need_to_switch, ne, on_central_stack_flag,
            Operand(zero_reg));

  // Switch to central stack.
  Register central_stack_sp = a4;
  DCHECK(!AreAliased(central_stack_sp, argc_input, argv_input, target_input));
  {
    __ Push(argc_input, target_input, argv_input);
    __ PrepareCallCFunction(2, a0);
    __ li(kCArgRegs[0], ER::isolate_address(masm->isolate()));
    __ mov(kCArgRegs[1], kOldSPRegister);
    __ CallCFunction(ER::wasm_switch_to_the_central_stack(), 2,
                     SetIsolateDataSlots::kNo);
    __ mov(central_stack_sp, kReturnRegister0);
    __ Pop(argc_input, target_input, argv_input);
  }

  static constexpr int kReturnAddressSlotOffset = 1 * kSystemPointerSize;
  static constexpr int kPadding = 1 * kSystemPointerSize;
  __ Sub_d(sp, central_stack_sp, Operand(kReturnAddressSlotOffset + kPadding));
  __ li(kSwitchFlagRegister, 1);

  // Update the sp saved in the frame.
  // It will be used to calculate the callee pc during GC.
  // The pc is going to be on the new stack segment, so rewrite it here.
  __ Add_d(central_stack_sp, sp, Operand(kSystemPointerSize));
  __ St_d(central_stack_sp, MemOperand(fp, ExitFrameConstants::kSPOffset));

  __ bind(&do_not_need_to_switch);
}

void SwitchFromTheCentralStackIfNeeded(MacroAssembler* masm) {
  using ER = ExternalReference;

  Label no_stack_change;

  __ Branch(&no_stack_change, eq, kSwitchFlagRegister, Operand(zero_reg));

  {
    __ Push(kReturnRegister0, kReturnRegister1);
    __ PrepareCallCFunction(1, a0);
    __ li(kCArgRegs[0], ER::isolate_address(masm->isolate()));
    __ CallCFunction(ER::wasm_switch_from_the_central_stack(), 1,
                     SetIsolateDataSlots::kNo);
    __ Pop(kReturnRegister0, kReturnRegister1);
  }

  __ mov(sp, kOldSPRegister);

  __ bind(&no_stack_change);
}

}  // namespace

#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_CEntry(MacroAssembler* masm, int result_size,
                               ArgvMode argv_mode, bool builtin_exit_frame,
                               bool switch_to_central_stack) {
  // Called from JavaScript; parameters are on stack as if calling JS function
  // a0: number of arguments including receiver
  // a1: pointer to C++ function
  // fp: frame pointer    (restored after C call)
  // sp: stack pointer    (restored as callee's sp after C call)
  // cp: current context  (C callee-saved)

  // If argv_mode == ArgvMode::kRegister:
  // a2: pointer to the first argument

  using ER = ExternalReference;

  // Move input arguments to more convenient registers.
  static constexpr Register argc_input = a0;
  static constexpr Register target_fun = s1;  // C callee-saved
  static constexpr Register argv = a1;
  static constexpr Register scratch = a3;
  static constexpr Register argc_sav = s0;  // C callee-saved

  __ mov(target_fun, argv);

  if (argv_mode == ArgvMode::kRegister) {
    // Move argv into the correct register.
    __ mov(argv, a2);
  } else {
    // Compute the argv pointer in a callee-saved register.
    __ Alsl_d(argv, argc_input, sp, kSystemPointerSizeLog2, t7);
    __ Sub_d(argv, argv, kSystemPointerSize);
  }

  // Enter the exit frame that transitions from JavaScript to C++.
  FrameScope scope(masm, StackFrame::MANUAL);
  __ EnterExitFrame(
      scratch, 0,
      builtin_exit_frame ? StackFrame::BUILTIN_EXIT : StackFrame::EXIT);

  // Store a copy of argc in callee-saved registers for later.
  __ mov(argc_sav, argc_input);

  // a0: number of arguments including receiver
  // s0: number of arguments  including receiver (C callee-saved)
  // a1: pointer to first argument
  // s1: pointer to builtin function (C callee-saved)

  // We are calling compiled C/C++ code. a0 and a1 hold our two arguments. We
  // also need to reserve the 4 argument slots on the stack.

  __ AssertStackIsAligned();

#if V8_ENABLE_WEBASSEMBLY
  if (switch_to_central_stack) {
    SwitchToTheCentralStackIfNeeded(masm, argc_input, target_fun, argv);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // Call C built-in.
  // a0 = argc, a1 = argv, a2 = isolate, s1 = target_fun
  DCHECK_EQ(kCArgRegs[0], argc_input);
  DCHECK_EQ(kCArgRegs[1], argv);
  __ li(kCArgRegs[2], ER::isolate_address());

  __ StoreReturnAddressAndCall(target_fun);

#if V8_ENABLE_WEBASSEMBLY
  if (switch_to_central_stack) {
    SwitchFromTheCentralStackIfNeeded(masm);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // Result returned in a0 or a1:a0 - do not destroy these registers!

  // Check result for exception sentinel.
  Label exception_returned;
  // The returned value may be a trusted object, living outside of the main
  // pointer compression cage, so we need to use full pointer comparison here.
  __ CompareRootAndBranch(a0, RootIndex::kException, eq, &exception_returned,
                          ComparisonMode::kFullPointer);

  // Check that there is no exception, otherwise we
  // should have returned the exception sentinel.
  if (v8_flags.debug_code) {
    Label okay;
    ER exception_address =
        ER::Create(IsolateAddressId::kExceptionAddress, masm->isolate());
    __ Ld_d(scratch, __ ExternalReferenceAsOperand(exception_address, no_reg));
    // Cannot use check here as it attempts to generate call into runtime.
    __ Branch(&okay, eq, scratch, RootIndex::kTheHoleValue);
    __ stop();
    __ bind(&okay);
  }

  // Exit C frame and return.
  // a0:a1: result
  // sp: stack pointer
  // fp: frame pointer
  // s0: still holds argc (C caller-saved).
  __ LeaveExitFrame(scratch);
  if (argv_mode == ArgvMode::kStack) {
    DCHECK(!AreAliased(scratch, argc_sav));
    __ Alsl_d(sp, argc_sav, sp, kSystemPointerSizeLog2);
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
  {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ PrepareCallCFunction(3, 0, a0);
    __ mov(kCArgRegs[0], zero_reg);
    __ mov(kCArgRegs[1], zero_reg);
    __ li(kCArgRegs[2], ER::isolate_address());
    __ CallCFunction(ER::Create(Runtime::kUnwindAndFindExceptionHandler), 3,
                     SetIsolateDataSlots::kNo);
  }

  // Retrieve the handler context, SP and FP.
  __ li(cp, pending_handler_context_address);
  __ Ld_d(cp, MemOperand(cp, 0));
  __ li(sp, pending_handler_sp_address);
  __ Ld_d(sp, MemOperand(sp, 0));
  __ li(fp, pending_handler_fp_address);
  __ Ld_d(fp, MemOperand(fp, 0));

  // If the handler is a JS frame, restore the context to the frame. Note that
  // the context will be set to (cp == 0) for non-JS frames.
  Label zero;
  __ Branch(&zero, eq, cp, Operand(zero_reg));
  __ St_d(cp, MemOperand(fp, StandardFrameConstants::kContextOffset));
  __ bind(&zero);

  // Clear c_entry_fp, like we do in `LeaveExitFrame`.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, masm->isolate());
  __ St_d(zero_reg, __ ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  // Compute the handler entry address and jump to it.
  __ Ld_d(scratch, __ ExternalReferenceAsOperand(
                       pending_handler_entrypoint_address, no_reg));
  __ Jump(scratch);
}

#if V8_ENABLE_WEBASSEMBLY
void Builtins::Generate_WasmHandleStackOverflow(MacroAssembler* masm) {
  using ER = ExternalReference;
  Register frame_base = WasmHandleStackOverflowDescriptor::FrameBaseRegister();
  Register gap = WasmHandleStackOverflowDescriptor::GapRegister();
  {
    DCHECK_NE(kCArgRegs[1], frame_base);
    DCHECK_NE(kCArgRegs[3], frame_base);
    __ mov(kCArgRegs[3], gap);
    __ mov(kCArgRegs[1], sp);
    __ sub_d(kCArgRegs[2], frame_base, kCArgRegs[1]);
    __ mov(kCArgRegs[4], fp);
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(kCArgRegs[3]);
    __ li(kCArgRegs[0], ER::isolate_address());
    __ PrepareCallCFunction(5, kScratchReg);
    __ CallCFunction(ER::wasm_grow_stack(), 5);
    __ Pop(gap);
    DCHECK_NE(kReturnRegister0, gap);
  }
  Label call_runtime;
  // wasm_grow_stack returns zero if it cannot grow a stack.
  __ BranchShort(&call_runtime, eq, kReturnRegister0, Operand(zero_reg));
  {
    UseScratchRegisterScope temps(masm);
    Register new_fp = temps.Acquire();
    // Calculate old FP - SP offset to adjust FP accordingly to new SP.
    __ sub_d(new_fp, fp, sp);
    __ add_d(new_fp, kReturnRegister0, new_fp);
    __ mov(fp, new_fp);
  }
  __ mov(sp, kReturnRegister0);
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ li(scratch, StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START));
    __ St_d(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));
  }
  __ Ret();

  __ bind(&call_runtime);
  // If wasm_grow_stack returns zero interruption or stack overflow
  // should be handled by runtime call.
  {
    __ Ld_d(kWasmImplicitArgRegister,
            MemOperand(fp, WasmFrameConstants::kWasmInstanceDataOffset));
    __ LoadTaggedField(
        cp, FieldMemOperand(kWasmImplicitArgRegister,
                            WasmTrustedInstanceData::kNativeContextOffset));
    FrameScope scope(masm, StackFrame::MANUAL);
    __ EnterFrame(StackFrame::INTERNAL);
    __ SmiTag(gap);
    __ Push(gap);
    __ CallRuntime(Runtime::kWasmStackGuard);
    __ LeaveFrame(StackFrame::INTERNAL);
    __ Ret();
  }
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
  __ Fld_d(double_scratch, MemOperand(sp, kArgumentOffset));

  // Try a conversion to a signed integer.
  __ TryInlineTruncateDoubleToI(result_reg, double_scratch, &done);

  // Load the double value and perform a manual truncation.
  Register input_high = scratch2;
  Register input_low = scratch3;

  // TryInlineTruncateDoubleToI destory kScratchDoubleReg, so reload it.
  __ Ld_d(result_reg, MemOperand(sp, kArgumentOffset));

  // Extract the biased exponent in result.
  __ bstrpick_d(input_high, result_reg,
                HeapNumber::kMantissaBits + HeapNumber::kExponentBits - 1,
                HeapNumber::kMantissaBits);

  __ Sub_d(scratch, input_high,
           HeapNumber::kExponentBias + HeapNumber::kMantissaBits + 32);
  Label not_zero;
  __ Branch(&not_zero, lt, scratch, Operand(zero_reg));
  __ mov(result_reg, zero_reg);
  __ Branch(&done);
  __ bind(&not_zero);

  // Isolate the mantissa bits, and set the implicit '1'.
  __ bstrpick_d(input_low, result_reg, HeapNumber::kMantissaBits - 1, 0);
  __ Or(input_low, input_low, Operand(1ULL << HeapNumber::kMantissaBits));

  Label lessthan_zero_reg;
  __ Branch(&lessthan_zero_reg, ge, result_reg, Operand(zero_reg));
  __ Sub_d(input_low, zero_reg, Operand(input_low));
  __ bind(&lessthan_zero_reg);

  // Shift the mantissa bits in the correct place. We know that we have to shift
  // it left here, because exponent >= 63 >= kMantissaBits.
  __ Sub_d(input_high, input_high,
           Operand(HeapNumber::kExponentBias + HeapNumber::kMantissaBits));
  __ sll_w(result_reg, input_low, input_high);

  __ bind(&done);

  __ St_d(result_reg, MemOperand(sp, kArgumentOffset));
  __ Pop(scratch, scratch2, scratch3);
  __ Pop(result_reg);
  __ Ret();
}

void Builtins::Generate_CallApiCallbackImpl(MacroAssembler* masm,
                                            CallApiCallbackMode mode) {
  // ----------- S t a t e -------------
  // CallApiCallbackMode::kOptimizedNoProfiling/kOptimized modes:
  //  -- a1                  : api function address
  // Both modes:
  //  -- a2                  : arguments count (not including the receiver)
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
          CallApiCallbackOptimizedDescriptor::Functi
```