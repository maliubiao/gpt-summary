Response: The user wants a summary of the C++ source code file `v8/src/builtins/loong64/builtins-loong64.cc`. This is the third part of a three-part file. The goal is to understand the functionality of this specific portion of the code and how it relates to JavaScript.

**Plan:**

1. **Analyze the code snippets:** Go through each function and code block, understanding its purpose based on its name, operations performed, and interaction with V8 internals (like `MacroAssembler`, `Builtins`, `Runtime`, `Wasm`).
2. **Identify key functionalities:** Group related code blocks to determine the main functionalities implemented in this part of the file.
3. **Relate to JavaScript:**  For each identified functionality, determine if and how it connects to JavaScript behavior.
4. **Provide JavaScript examples:**  If a connection to JavaScript exists, create simple and illustrative JavaScript code snippets that would trigger or relate to the functionality described in the C++ code.
The provided C++ code snippet is the third part of the `builtins-loong64.cc` file in the V8 JavaScript engine. This part primarily deals with:

**1. WebAssembly (Wasm) Specific Builtins:**

* **`Generate_WasmResumeHelper(MacroAssembler* masm, wasm::OnResume on_resume)`:** This function seems to handle the resumption of a suspended WebAssembly function. It takes a `wasm::OnResume` enum indicating whether the resumption should proceed normally (`kContinue`) or throw an exception (`kThrow`). It manipulates the stack, continuation objects, and potentially jumps back into the Wasm code.
* **`Generate_WasmResume(MacroAssembler* masm)`:** Calls `Generate_WasmResumeHelper` with `wasm::OnResume::kContinue`.
* **`Generate_WasmReject(MacroAssembler* masm)`:** Calls `Generate_WasmResumeHelper` with `wasm::OnResume::kThrow`.
* **`Generate_WasmOnStackReplace(MacroAssembler* masm)`:** This function seems to be a placeholder (`__ Trap()`) indicating it's not implemented or needed on the LoongArch64 architecture. It's likely related to stack replacement during debugging or optimization, a feature more relevant on other architectures.
* **`SwitchToAllocatedStack(...)`:** This function is involved in switching to a newly allocated stack, likely during asynchronous operations in WebAssembly. It saves the current state, switches stacks, and prepares the new stack frame.
* **`SwitchBackAndReturnPromise(...)`:**  Handles the process of switching back to the original stack and returning a Promise from a WebAssembly function. It deals with fulfilling or rejecting the promise based on the `mode`.
* **`GenerateExceptionHandlingLandingPad(...)`:**  Sets up a landing pad for handling exceptions thrown from WebAssembly. It catches the exception and rejects the associated Promise.
* **`JSToWasmWrapperHelper(MacroAssembler* masm, wasm::Promise mode)`:** This is a crucial function for bridging the gap between JavaScript and WebAssembly. It sets up the necessary stack frame when calling a WebAssembly function from JavaScript. It handles argument passing, calls the Wasm function, and then handles the return value, potentially involving Promises for asynchronous operations.
* **`Generate_JSToWasmWrapperAsm(MacroAssembler* masm)`:** Calls `JSToWasmWrapperHelper` for synchronous calls (no Promises).
* **`Generate_WasmReturnPromiseOnSuspendAsm(MacroAssembler* masm)`:** Calls `JSToWasmWrapperHelper` for WebAssembly functions that return a Promise (for asynchronous operations).
* **`Generate_JSToWasmStressSwitchStacksAsm(MacroAssembler* masm)`:** Calls `JSToWasmWrapperHelper` for stress testing stack switching in WebAssembly.
* **`SwitchToTheCentralStackIfNeeded(...)` and `SwitchFromTheCentralStackIfNeeded(...)`:** These functions are related to potentially switching to a central stack for WebAssembly execution, likely for better resource management or security.
* **`Generate_WasmHandleStackOverflow(MacroAssembler* masm)`:**  Handles stack overflow conditions within WebAssembly. It attempts to grow the stack and, if that fails, calls into the V8 runtime to handle the error.

**2. General C++ Builtins and Support Functions:**

* **`Generate_CEntry(...)`:** This is a fundamental builtin for calling C++ functions from JavaScript. It sets up the necessary stack frame, passes arguments, calls the C++ function, and handles the return value, including potential exceptions.
* **`Generate_DoubleToI(MacroAssembler* masm)`:** Implements the conversion of a double-precision floating-point number to an integer. It handles both fast-path (inline truncation) and slower-path manual truncation.
* **`Generate_CallApiCallbackImpl(...)`:** Handles calls to JavaScript API callbacks from native code. It sets up the `FunctionCallbackInfo` object and calls the provided function pointer.
* **`Generate_CallApiGetter(MacroAssembler* masm)`:**  Handles calls to JavaScript API getter functions. It sets up the `PropertyCallbackInfo` object and calls the getter function.
* **`Generate_DirectCEntry(MacroAssembler* masm)`:**  A specialized entry point for calling C++ functions in a way that is safe for garbage collection, particularly important for code that might trigger GC.
* **`Generate_DeoptimizationEntry(...)`:**  Handles the process of deoptimizing code. When optimized code needs to fall back to a less optimized version (e.g., the interpreter), this builtin manages the transfer of state and control.
* **`Generate_DeoptimizationEntry_Eager(MacroAssembler* masm)`:** Calls `Generate_DeoptimizationEntry` for eager deoptimization.
* **`Generate_DeoptimizationEntry_Lazy(MacroAssembler* masm)`:** Calls `Generate_DeoptimizationEntry` for lazy deoptimization.
* **`Generate_BaselineOrInterpreterEntry(...)`:**  Determines whether to enter the baseline compiler's code or the interpreter when calling a function. It checks if baseline code is available and handles the transition.
* **`Generate_BaselineOrInterpreterEnterAtBytecode(MacroAssembler* masm)`:** Calls `Generate_BaselineOrInterpreterEntry` to start at the beginning of the bytecode.
* **`Generate_BaselineOrInterpreterEnterAtNextBytecode(MacroAssembler* masm)`:** Calls `Generate_BaselineOrInterpreterEntry` to start at the next bytecode.
* **`Generate_InterpreterOnStackReplacement_ToBaseline(MacroAssembler* masm)`:** Calls `Generate_BaselineOrInterpreterEntry` for transitioning from the interpreter to baseline code during on-stack replacement (OSR).
* **`Generate_RestartFrameTrampoline(MacroAssembler* masm)`:** Implements a trampoline for restarting the execution of the current JavaScript frame, useful for debugging or error recovery.

**Relationship to JavaScript and Examples:**

This file contains low-level code that directly supports the execution of JavaScript and WebAssembly. Here are some examples illustrating the connection:

**1. `Generate_WasmResume` and `Generate_WasmReject`:** These are used when a WebAssembly function that has suspended (e.g., due to an asynchronous operation) is being resumed with either a success or failure result.

```javascript
// Example scenario: WebAssembly with async operations (using a hypothetical API)
async function wasmAsyncOperation() {
  const instance = await WebAssembly.instantiateStreaming(fetch('my_module.wasm'));
  const result = await instance.exports.asyncFunction(); // asyncFunction might suspend
  console.log("Wasm async operation completed:", result);
}

wasmAsyncOperation();
```
Internally, when `asyncFunction` in the Wasm module reaches a point where it needs to wait, it might suspend. When the awaited operation completes, V8 would use `Generate_WasmResume` (for success) or a mechanism involving `Generate_WasmReject` (for failure) to resume the Wasm execution.

**2. `Generate_JSToWasmWrapperAsm` and `Generate_WasmReturnPromiseOnSuspendAsm`:** These builtins are responsible for calling WebAssembly functions from JavaScript.

```javascript
// Calling a synchronous WebAssembly function:
const instance = await WebAssembly.instantiateStreaming(fetch('my_module.wasm'));
const syncResult = instance.exports.add(5, 3); // Calls a Wasm function synchronously
console.log("Synchronous Wasm call:", syncResult);

// Calling an asynchronous WebAssembly function (returning a Promise):
const asyncInstance = await WebAssembly.instantiateStreaming(fetch('my_async_module.wasm'));
asyncInstance.exports.asyncOperation().then(result => {
  console.log("Asynchronous Wasm call:", result);
});
```
When `instance.exports.add(5, 3)` is called, V8 uses `Generate_JSToWasmWrapperAsm` to set up the call. For `asyncInstance.exports.asyncOperation()`, which returns a Promise, `Generate_WasmReturnPromiseOnSuspendAsm` would be involved.

**3. `Generate_CEntry`:** This is used extensively for calling built-in JavaScript functions implemented in C++.

```javascript
// Many built-in JavaScript functions are implemented in C++.
// For example, Math.max() is likely implemented in C++.
const maxVal = Math.max(10, 20);
```
When `Math.max(10, 20)` is executed, V8 uses `Generate_CEntry` to call the underlying C++ implementation of `Math.max`.

**4. `Generate_DoubleToI`:** This is used when JavaScript code explicitly or implicitly converts a double to an integer.

```javascript
const floatValue = 3.14;
const integerValue = parseInt(floatValue); // Explicit conversion
const anotherIntegerValue = floatValue | 0; // Implicit conversion (bitwise OR with 0)
```
Both `parseInt(floatValue)` and the bitwise operation will likely involve `Generate_DoubleToI` in the V8 engine to perform the conversion at a low level.

**5. `Generate_CallApiCallbackImpl`:** This is used when native C++ code interacts with JavaScript through V8's API, particularly when calling JavaScript functions provided as callbacks.

```c++
// Example (simplified, demonstrating the concept):
v8::Local<v8::Function> callbackFunction = ...; // Get a JavaScript function object
v8::Local<v8::Value> args[1] = { v8::String::NewFromUtf8(isolate, "Hello").ToLocalChecked() };
callbackFunction->Call(context, receiver, 1, args);
```
When the `callbackFunction->Call` is executed, V8 uses `Generate_CallApiCallbackImpl` to transition into JavaScript and execute the callback.

**6. `Generate_DeoptimizationEntry_Eager` and `Generate_DeoptimizationEntry_Lazy`:**  These builtins are invoked when the V8 engine decides that optimized code needs to be deoptimized, perhaps due to type changes or other factors that invalidate the optimizations. This is usually transparent to the JavaScript developer.

In summary, this part of the `builtins-loong64.cc` file contains critical low-level functions that enable the execution of both JavaScript and WebAssembly on the LoongArch64 architecture. It handles function calls between JavaScript and native code, WebAssembly specific operations, type conversions, and deoptimization processes. These builtins are fundamental to the performance and functionality of the V8 engine.

Prompt: 
```
这是目录为v8/src/builtins/loong64/builtins-loong64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
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
          CallApiCallbackOptimizedDescriptor::FunctionTemplateInfoRegister();
      holder = CallApiCallbackOptimizedDescriptor::HolderRegister();
      break;
  }
  DCHECK(!AreAliased(api_function_address, topmost_script_having_context, argc,
                     holder, scratch));

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
  // Target state:
  //   sp[0 * kSystemPointerSize]: kHolder   <= FCA::implicit_args_
  //   sp[1 * kSystemPointerSize]: kIsolate
  //   sp[2 * kSystemPointerSize]: kContext
  //   sp[3 * kSystemPointerSize]: undefined (kReturnValue)
  //   sp[4 * kSystemPointerSize]: kData
  //   sp[5 * kSystemPointerSize]: undefined (kNewTarget)
  // Existing state:
  //   sp[6 * kSystemPointerSize]:           <= FCA:::values_

  __ StoreRootRelative(IsolateData::topmost_script_having_context_offset(),
                       topmost_script_having_context);
  if (mode == CallApiCallbackMode::kGeneric) {
    api_function_address = ReassignRegister(topmost_script_having_context);
  }

  // Reserve space on the stack.
  __ Sub_d(sp, sp, Operand(FCA::kArgsLength * kSystemPointerSize));

  // kHolder.
  __ St_d(holder, MemOperand(sp, FCA::kHolderIndex * kSystemPointerSize));

  // kIsolate.
  __ li(scratch, ER::isolate_address());
  __ St_d(scratch, MemOperand(sp, FCA::kIsolateIndex * kSystemPointerSize));

  // kContext.
  __ St_d(cp, MemOperand(sp, FCA::kContextIndex * kSystemPointerSize));

  // kReturnValue.
  __ LoadRoot(scratch, RootIndex::kUndefinedValue);
  __ St_d(scratch, MemOperand(sp, FCA::kReturnValueIndex * kSystemPointerSize));

  // kTarget.
  __ St_d(func_templ, MemOperand(sp, FCA::kTargetIndex * kSystemPointerSize));

  // kNewTarget.
  __ St_d(scratch, MemOperand(sp, FCA::kNewTargetIndex * kSystemPointerSize));

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
    ASM_CODE_COMMENT_STRING(masm, "Initialize FunctionCallbackInfo");
    // FunctionCallbackInfo::length_.
    // TODO(ishell): pass JSParameterCount(argc) to simplify things on the
    // caller end.
    __ St_d(argc, argc_operand);

    // FunctionCallbackInfo::implicit_args_.
    __ Add_d(scratch, fp, Operand(FC::kImplicitArgsArrayOffset));
    __ St_d(scratch, MemOperand(fp, FC::kFCIImplicitArgsOffset));

    // FunctionCallbackInfo::values_ (points at JS arguments on the stack).
    __ Add_d(scratch, fp, Operand(FC::kFirstArgumentOffset));
    __ St_d(scratch, MemOperand(fp, FC::kFCIValuesOffset));
  }

  __ RecordComment("v8::FunctionCallback's argument.");
  // function_callback_info_arg = v8::FunctionCallbackInfo&
  __ Add_d(function_callback_info_arg, fp,
           Operand(FC::kFunctionCallbackInfoOffset));

  DCHECK(
      !AreAliased(api_function_address, scratch, function_callback_info_arg));

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

  Register api_function_address = a2;
  Register receiver = ApiGetterDescriptor::ReceiverRegister();
  Register holder = ApiGetterDescriptor::HolderRegister();
  Register callback = ApiGetterDescriptor::CallbackRegister();
  Register scratch = a4;
  Register undef = a5;
  Register scratch2 = a6;

  DCHECK(!AreAliased(receiver, holder, callback, scratch, undef, scratch2));

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
  //   sp[0 * kSystemPointerSize]: name                       <= PCI:args_
  //   sp[1 * kSystemPointerSize]: kShouldThrowOnErrorIndex
  //   sp[2 * kSystemPointerSize]: kHolderIndex
  //   sp[3 * kSystemPointerSize]: kIsolateIndex
  //   sp[4 * kSystemPointerSize]: kHolderV2Index
  //   sp[5 * kSystemPointerSize]: kReturnValueIndex
  //   sp[6 * kSystemPointerSize]: kDataIndex
  //   sp[7 * kSystemPointerSize]: kThisIndex / receiver

  __ LoadTaggedField(scratch,
                     FieldMemOperand(callback, AccessorInfo::kDataOffset));
  __ LoadRoot(undef, RootIndex::kUndefinedValue);
  __ li(scratch2, ER::isolate_address());
  Register holderV2 = zero_reg;
  __ Push(receiver, scratch,  // kThisIndex, kDataIndex
          undef, holderV2);   // kReturnValueIndex, kHolderV2Index
  __ Push(scratch2, holder);  // kIsolateIndex, kHolderIndex

  // |name_arg| clashes with |holder|, so we need to push holder first.
  __ LoadTaggedField(name_arg,
                     FieldMemOperand(callback, AccessorInfo::kNameOffset));
  static_assert(kDontThrow == 0);
  Register should_throw_on_error =
      zero_reg;  // should_throw_on_error -> kDontThrow
  __ Push(should_throw_on_error, name_arg);

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
  __ Add_d(property_callback_info_arg, fp, Operand(FC::kArgsArrayOffset));

  DCHECK(!AreAliased(api_function_address, property_callback_info_arg, name_arg,
                     callback, scratch, scratch2));

#ifdef V8_ENABLE_DIRECT_HANDLE
  // name_arg = Local<Name>(name), name value was pushed to GC-ed stack space.
  // |name_arg| is already initialized above.
#else
  // name_arg = Local<Name>(&name), which is &args_array[kPropertyKeyIndex].
  static_assert(PCA::kPropertyKeyIndex == 0);
  __ mov(name_arg, property_callback_info_arg);
#endif

  ER thunk_ref = ER::invoke_accessor_getter_callback();
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

  __ St_d(ra, MemOperand(sp, 0));  // Store the return address.
  __ Call(t7);                     // Call the C++ function.
  __ Ld_d(ra, MemOperand(sp, 0));  // Return to calling code.

  // TODO(LOONG_dev): LOONG64 Check this assert.
  if (v8_flags.debug_code && v8_flags.enable_slow_asserts) {
    // In case of an error the return address may point to a memory area
    // filled with kZapValue by the GC. Dereference the address and check for
    // this.
    __ Ld_d(a4, MemOperand(ra, 0));
    __ Assert(ne, AbortReason::kReceivedInvalidReturnAddress, a4,
              Operand(reinterpret_cast<uint64_t>(kZapValue)));
  }

  __ Jump(ra);
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

  const int kSimd128RegsSize = kSimd128Size * Simd128Register::kNumRegisters;

  // Save all allocatable simd128 / double registers before messing with them.
  // TODO(loong64): Add simd support here.
  __ Sub_d(sp, sp, Operand(kSimd128RegsSize));
  const RegisterConfiguration* config = RegisterConfiguration::Default();
  for (int i = 0; i < config->num_allocatable_double_registers(); ++i) {
    int code = config->GetAllocatableDoubleCode(i);
    const DoubleRegister fpu_reg = DoubleRegister::from_code(code);
    int offset = code * kSimd128Size;
    __ Fst_d(fpu_reg, MemOperand(sp, offset));
  }

  // Push saved_regs (needed to populate FrameDescription::registers_).
  // Leave gaps for other registers.
  __ Sub_d(sp, sp, kNumberOfRegisters * kSystemPointerSize);
  for (int16_t i = kNumberOfRegisters - 1; i >= 0; i--) {
    if ((saved_regs.bits() & (1 << i)) != 0) {
      __ St_d(ToRegister(i), MemOperand(sp, kSystemPointerSize * i));
    }
  }

  __ li(a2,
        ExternalReference::Create(IsolateAddressId::kCEntryFPAddress, isolate));
  __ St_d(fp, MemOperand(a2, 0));

  const int kSavedRegistersAreaSize =
      (kNumberOfRegisters * kSystemPointerSize) + kSimd128RegsSize;

  // Get the address of the location in the code object (a2) (return
  // address for lazy deoptimization) and compute the fp-to-sp delta in
  // register a3.
  __ mov(a2, ra);
  __ Add_d(a3, sp, Operand(kSavedRegistersAreaSize));

  __ sub_d(a3, fp, a3);

  // Allocate a new deoptimizer object.
  __ PrepareCallCFunction(5, a4);
  // Pass six arguments, according to n64 ABI.
  __ mov(a0, zero_reg);
  Label context_check;
  __ Ld_d(a1, MemOperand(fp, CommonFrameConstants::kContextOrFrameTypeOffset));
  __ JumpIfSmi(a1, &context_check);
  __ Ld_d(a0, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ bind(&context_check);
  __ li(a1, Operand(static_cast<int>(deopt_kind)));
  // a2: code address or 0 already loaded.
  // a3: already has fp-to-sp delta.
  __ li(a4, ExternalReference::isolate_address());

  // Call Deoptimizer::New().
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::new_deoptimizer_function(), 5);
  }

  // Preserve "deoptimizer" object in register a0 and get the input
  // frame descriptor pointer to a1 (deoptimizer->input_);
  // Move deopt-obj to a0 for call to Deoptimizer::ComputeOutputFrames() below.
  __ Ld_d(a1, MemOperand(a0, Deoptimizer::input_offset()));

  // Copy core registers into FrameDescription::registers_[kNumRegisters].
  DCHECK_EQ(Register::kNumRegisters, kNumberOfRegisters);
  for (int i = 0; i < kNumberOfRegisters; i++) {
    int offset =
        (i * kSystemPointerSize) + FrameDescription::registers_offset();
    if ((saved_regs.bits() & (1 << i)) != 0) {
      __ Ld_d(a2, MemOperand(sp, i * kSystemPointerSize));
      __ St_d(a2, MemOperand(a1, offset));
    } else if (v8_flags.debug_code) {
      __ li(a2, Operand(kDebugZapValue));
      __ St_d(a2, MemOperand(a1, offset));
    }
  }

  // Copy simd128 / double registers to the input frame.
  // TODO(loong64): Add simd support here.
  int simd128_regs_offset = FrameDescription::simd128_registers_offset();
  for (int i = 0; i < config->num_allocatable_simd128_registers(); ++i) {
    int code = config->GetAllocatableSimd128Code(i);
    int dst_offset = code * kSimd128Size + simd128_regs_offset;
    int src_offset =
        code * kSimd128Size + kNumberOfRegisters * kSystemPointerSize;
    __ Fld_d(f0, MemOperand(sp, src_offset));
    __ Fst_d(f0, MemOperand(a1, dst_offset));
  }

  // Remove the saved registers from the stack.
  __ Add_d(sp, sp, Operand(kSavedRegistersAreaSize));

  // Compute a pointer to the unwinding limit in register a2; that is
  // the first stack slot not part of the input frame.
  __ Ld_d(a2, MemOperand(a1, FrameDescription::frame_size_offset()));
  __ add_d(a2, a2, sp);

  // Unwind the stack down to - but not including - the unwinding
  // limit and copy the contents of the activation frame to the input
  // frame description.
  __ Add_d(a3, a1, Operand(FrameDescription::frame_content_offset()));
  Label pop_loop;
  Label pop_loop_header;
  __ Branch(&pop_loop_header);
  __ bind(&pop_loop);
  __ Pop(a4);
  __ St_d(a4, MemOperand(a3, 0));
  __ addi_d(a3, a3, sizeof(uint64_t));
  __ bind(&pop_loop_header);
  __ BranchShort(&pop_loop, ne, a2, Operand(sp));
  // Compute the output frame in the deoptimizer.
  __ Push(a0);  // Preserve deoptimizer object across call.
  // a0: deoptimizer object; a1: scratch.
  __ PrepareCallCFunction(1, a1);
  // Call Deoptimizer::ComputeOutputFrames().
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::compute_output_frames_function(), 1);
  }
  __ Pop(a0);  // Restore deoptimizer object (class Deoptimizer).

  __ Ld_d(sp, MemOperand(a0, Deoptimizer::caller_frame_top_offset()));

  // Replace the current (input) frame with the output frames.
  Label outer_push_loop, inner_push_loop, outer_loop_header, inner_loop_header;
  // Outer loop state: a4 = current "FrameDescription** output_",
  // a1 = one past the last FrameDescription**.
  __ Ld_w(a1, MemOperand(a0, Deoptimizer::output_count_offset()));
  __ Ld_d(a4, MemOperand(a0, Deoptimizer::output_offset()));  // a4 is output_.
  __ Alsl_d(a1, a1, a4, kSystemPointerSizeLog2);
  __ Branch(&outer_loop_header);

  __ bind(&outer_push_loop);
  Register current_frame = a2;
  Register frame_size = a3;
  __ Ld_d(current_frame, MemOperand(a4, 0));
  __ Ld_d(frame_size,
          MemOperand(current_frame, FrameDescription::frame_size_offset()));
  __ Branch(&inner_loop_header);

  __ bind(&inner_push_loop);
  __ Sub_d(frame_size, frame_size, Operand(sizeof(uint64_t)));
  __ Add_d(a6, current_frame, Operand(frame_size));
  __ Ld_d(a7, MemOperand(a6, FrameDescription::frame_content_offset()));
  __ Push(a7);

  __ bind(&inner_loop_header);
  __ BranchShort(&inner_push_loop, ne, frame_size, Operand(zero_reg));

  __ Add_d(a4, a4, Operand(kSystemPointerSize));

  __ bind(&outer_loop_header);
  __ BranchShort(&outer_push_loop, lt, a4, Operand(a1));

  // TODO(loong64): Add simd support here.
  for (int i = 0; i < config->num_allocatable_simd128_registers(); ++i) {
    int code = config->GetAllocatableSimd128Code(i);
    const DoubleRegister fpu_reg = DoubleRegister::from_code(code);
    int src_offset = code * kSimd128Size + simd128_regs_offset;
    __ Fld_d(fpu_reg, MemOperand(current_frame, src_offset));
  }

  // Push pc and continuation from the last output frame.
  __ Ld_d(a6, MemOperand(current_frame, FrameDescription::pc_offset()));
  __ Push(a6);
  __ Ld_d(a6,
          MemOperand(current_frame, FrameDescription::continuation_offset()));
  __ Push(a6);

  // Technically restoring 'at' should work unless zero_reg is also restored
  // but it's safer to check for this.
  DCHECK(!(restored_regs.has(t7)));
  // Restore the registers from the last output frame.
  __ mov(t7, current_frame);
  for (int i = kNumberOfRegisters - 1; i >= 0; i--) {
    int offset =
        (i * kSystemPointerSize) + FrameDescription::registers_offset();
    if ((restored_regs.bits() & (1 << i)) != 0) {
      __ Ld_d(ToRegister(i), MemOperand(t7, offset));
    }
  }

  // If the continuation is non-zero (JavaScript), branch to the continuation.
  // For Wasm just return to the pc from the last output frame in the lr
  // register.
  Label end;
  __ Pop(t7);  // Get continuation, leave pc on stack.
  __ Pop(ra);
  __ BranchShort(&end, eq, t7, Operand(zero_reg));
  __ Jump(t7);
  __ bind(&end);
  __ Jump(ra);
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
  __ Ld_d(closure, MemOperand(fp, StandardFrameConstants::kFunctionOffset));

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
    __ JumpIfObjectType(&start_with_baseline, eq, code_obj, CODE_TYPE, t2);

    // Start with bytecode as there is no baseline code.
    Builtin builtin = next_bytecode ? Builtin::kInterpreterEnterAtNextBytecode
                                    : Builtin::kInterpreterEnterAtBytecode;
    __ TailCallBuiltin(builtin);

    // Start with baseline code.
    __ bind(&start_with_baseline);
  } else if (v8_flags.debug_code) {
    __ GetObjectType(code_obj, t2, t2);
    __ Assert(eq, AbortReason::kExpectedBaselineData, t2, Operand(CODE_TYPE));
  }

  if (v8_flags.debug_code) {
    AssertCodeIsBaseline(masm, code_obj, t2);
  }

  // Load the feedback cell and vector.
  Register feedback_cell = a2;
  Register feedback_vector = t8;
  __ LoadTaggedField(feedback_cell,
                     FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  __ LoadTaggedField(
      feedback_vector,
      FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset));

  Label install_baseline_code;
  // Check if feedback vector is valid. If not, call prepare for baseline to
  // allocate it.
  __ JumpIfObjectType(&install_baseline_code, ne, feedback_vector,
                      FEEDBACK_VECTOR_TYPE, t2);

  // Save BytecodeOffset from the stack frame.
  __ SmiUntag(kInterpreterBytecodeOffsetRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  // Replace bytecode offset with feedback cell.
  static_assert(InterpreterFrameConstants::kBytecodeOffsetFromFp ==
                BaselineFrameConstants::kFeedbackCellFromFp);
  __ St_d(feedback_cell,
          MemOperand(fp, BaselineFrameConstants::kFeedbackCellFromFp));
  feedback_cell = no_reg;
  // Update feedback vector cache.
  static_assert(InterpreterFrameConstants::kFeedbackVectorFromFp ==
                BaselineFrameConstants::kFeedbackVectorFromFp);
  __ St_d(feedback_vector,
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

  __ Sub_d(kInterpreterBytecodeOffsetRegister,
           kInterpreterBytecodeOffsetRegister,
           (BytecodeArray::kHeaderSize - kHeapObjectTag));

  __ bind(&valid_bytecode_offset);
  // Get bytecode array from the stack frame.
  __ Ld_d(kInterpreterBytecodeArrayRegister,
          MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  // Save the accumulator register, since it's clobbered by the below call.
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
  __ Add_d(code_obj, code_obj, kReturnRegister0);
  __ Pop(kInterpreterAccumulatorRegister);

  if (is_osr) {
    // TODO(liuyu): Remove Ld as arm64 after register reallocation.
    __ Ld_d(kInterpreterBytecodeArrayRegister,
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
    __ mov(kInterpreterBytecodeOffsetRegister, zero_reg);
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
  // Restart the current frame:
  // - Look up current function on the frame.
  // - Leave the frame.
  // - Restart the frame by calling the function.

  __ Ld_d(a1, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ Ld_d(a0, MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ LeaveFrame(StackFrame::INTERPRETED);

  // The arguments are already in the stack (including any necessary padding),
  // we should not try to massage the arguments again.
#ifdef V8_ENABLE_LEAPTIERING
  __ InvokeFunction(a1, a0, InvokeType::kJump,
                    ArgumentAdaptionMode::kDontAdapt);
#else
  __ li(a2, Operand(kDontAdaptArgumentsSentinel));
  __ InvokeFunction(a1, a2, a0, InvokeType::kJump);
#endif
}

#undef __

}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_LOONG64

"""


```