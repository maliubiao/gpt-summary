Response: The user wants a summary of the functionality of the C++ code in the file `v8/src/builtins/x64/builtins-x64.cc`. This is part 3 of 4, suggesting it focuses on a specific subset of the file's overall responsibilities. The request also asks to illustrate the connection to Javascript with examples.

Given the code snippets provided, they primarily deal with:

1. **Stack Switching and Continuations:** Functions like `SwitchStacks`, `ReloadParentContinuation`, `SwitchToAllocatedStack`, `SwitchBackAndReturnPromise`, and `GenerateExceptionHandlingLandingPad` are heavily involved in managing different call stacks, particularly in the context of WebAssembly and asynchronous operations (Promises).
2. **Wasm Interop:**  Functions like `JSToWasmWrapperHelper` and `WasmToJsWrapperAsm` are responsible for bridging the gap between Javascript and WebAssembly code, handling argument passing, return values, and potential exceptions.
3. **Suspension and Resumption:** Functions like `Generate_WasmSuspend` and `Generate_WasmResumeHelper` manage the suspension and resumption of WebAssembly execution, often related to asynchronous operations.
4. **Exception Handling:** The `GenerateExceptionHandlingLandingPad` function demonstrates handling exceptions thrown from WebAssembly and propagating them back to Javascript Promises.
5. **C++ Call Interfacing:**  `Generate_CEntry` handles calls from Javascript to C++ functions, managing arguments and return values.
6. **Deoptimization:** The `Generate_DeoptimizationEntry` functions manage the process of reverting from optimized code back to a more basic form.

Therefore, the primary focus of this part of the file seems to be the mechanisms for **interoperability between Javascript and WebAssembly, especially dealing with asynchronous operations and managing different execution stacks.**

To provide Javascript examples, I need to show how these C++ functions are invoked or related to Javascript features.
这个C++源代码文件（`v8/src/builtins/x64/builtins-x64.cc` 的第3部分）主要负责实现 **WebAssembly 和 Javascript 之间互操作的关键底层机制，特别是处理异步操作和堆栈切换**。

具体来说，它包含了以下功能：

1. **堆栈切换 (Stack Switching)：**  定义了如何在不同的执行栈之间切换，这对于实现 WebAssembly 的异步特性（例如 `async` 函数和 `await` 表达式）至关重要。它管理着 continuation 对象，保存和恢复寄存器状态，并更新栈顶指针。
2. **WebAssembly 调用 Javascript (Wasm To Js)：**  实现了从 WebAssembly 代码调用 Javascript 函数的包装器 (Wrapper)。它负责设置正确的调用约定，将 WebAssembly 的参数转换为 Javascript 可以理解的格式，并调用 Javascript 的 builtin 函数。
3. **Javascript 调用 WebAssembly (Js To Wasm)：**  实现了从 Javascript 代码调用 WebAssembly 函数的包装器。它负责设置 WebAssembly 的调用约定，将 Javascript 的参数转换为 WebAssembly 可以理解的格式，并处理 WebAssembly 函数的返回值。
4. **WebAssembly 的挂起和恢复 (Suspend and Resume)：** 实现了 WebAssembly 代码的挂起和恢复机制，这通常与 Promise 相关联。当 WebAssembly 代码需要等待异步操作完成时，它可以被挂起，并在操作完成后被恢复。
5. **异常处理 (Exception Handling)：**  定义了如何在 WebAssembly 代码执行过程中捕获异常，并将这些异常传递回 Javascript 的 Promise。
6. **C++ 函数调用接口 (C Entry)：**  定义了 Javascript 代码调用 C++ 函数的入口点。它负责设置调用约定，传递参数，并处理返回值。
7. **去优化入口 (Deoptimization Entry)：**  实现了从优化后的代码回退到未优化代码的入口点。这在运行时遇到某些情况（例如类型推断错误）时发生。

**与 Javascript 功能的关系和示例：**

这个文件中的代码是 V8 引擎实现 WebAssembly 功能的基石，因此它与 Javascript 的 WebAssembly API 紧密相关，并且间接地与 Javascript 的异步特性（Promise、async/await）相关。

**Javascript 示例 1：调用 WebAssembly 函数**

```javascript
// 假设我们加载了一个 WebAssembly 模块
const wasmModule = await WebAssembly.instantiateStreaming(fetch('my_module.wasm'));
const wasmInstance = wasmModule.instance;

// 调用 WebAssembly 导出的函数
const result = wasmInstance.exports.add(5, 3);
console.log(result); // 输出 8
```

在上述例子中，当 Javascript 调用 `wasmInstance.exports.add(5, 3)` 时，`Generate_JSToWasmWrapperAsm`（或其相关的变体）会发挥作用，负责将 Javascript 的参数 (5 和 3) 传递给 WebAssembly 的 `add` 函数，并获取其返回值。

**Javascript 示例 2：WebAssembly 调用 Javascript 函数**

```javascript
// 在 Javascript 中定义一个要被 WebAssembly 调用的函数
globalThis.jsCallback = (value) => {
  console.log(`WebAssembly 调用了 Javascript，参数为：${value}`);
  return value * 2;
};

// 假设 WebAssembly 模块导出了一个会调用 jsCallback 的函数
const wasmModule = await WebAssembly.instantiateStreaming(fetch('my_module_calls_js.wasm'));
const wasmInstance = wasmModule.instance;

// 调用 WebAssembly 函数，该函数会回调 Javascript
const wasmResult = wasmInstance.exports.callJavascript(10);
console.log(`WebAssembly 回调 Javascript 的返回值：${wasmResult}`); // 输出 WebAssembly 回调 Javascript 的返回值：20
```

在这个例子中，当 WebAssembly 代码调用 `jsCallback` 时，`Generate_WasmToJsWrapperAsm` 会负责将 WebAssembly 的参数 (10) 传递给 Javascript 的 `jsCallback` 函数，并处理其返回值。

**Javascript 示例 3：WebAssembly 的异步操作和 Promise**

```javascript
// 假设 WebAssembly 模块导出了一个返回 Promise 的函数
const wasmModule = await WebAssembly.instantiateStreaming(fetch('my_async_wasm.wasm'));
const wasmInstance = wasmModule.instance;

wasmInstance.exports.asyncOperation()
  .then(result => {
    console.log(`WebAssembly 异步操作完成，结果为：${result}`);
  });
```

当 WebAssembly 的 `asyncOperation` 函数返回一个 Promise 时，`Generate_WasmSuspend` 会参与到挂起 WebAssembly 的执行，直到 Promise 解决。 `SwitchStacks` 等函数会管理堆栈的切换。 当 Promise 解决后，`Generate_WasmResumeHelper` 会被用来恢复 WebAssembly 的执行。 `SwitchBackAndReturnPromise` 会负责将 WebAssembly 的结果传递给 Javascript 的 Promise。如果 WebAssembly 代码抛出异常，`GenerateExceptionHandlingLandingPad` 会将该异常传递给 Promise 的 `reject` 方法。

总而言之，这个 C++ 源代码文件的第 3 部分是 V8 引擎中实现 WebAssembly 与 Javascript 互操作性的核心组成部分，它处理了跨语言调用、异步操作以及异常处理等关键任务，使得 WebAssembly 能够与 Javascript 环境无缝集成。

### 提示词
```
这是目录为v8/src/builtins/x64/builtins-x64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```
asmContinuationJmpbufTag, kScratchRegister);
  MemOperand GCScanSlotPlace =
      MemOperand(rbp, StackSwitchFrameConstants::kGCScanSlotCountOffset);
  __ Move(GCScanSlotPlace, 0);
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
    __ Move(kCArgRegs[0], ExternalReference::isolate_address(masm->isolate()));
    __ Move(kCArgRegs[1], finished_continuation);
    __ PrepareCallCFunction(2);
    __ CallCFunction(ER::wasm_return_switch(), 2);
  } else {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ Move(kCArgRegs[0], ExternalReference::isolate_address());
    __ PrepareCallCFunction(1);
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
                              Register tmp1, Register tmp2) {
  Register active_continuation = tmp1;
  __ LoadRoot(active_continuation, RootIndex::kActiveContinuation);

  // We don't need to save the full register state since we are switching out of
  // this stack for the last time. Mark the stack as retired.
  Register jmpbuf = kScratchRegister;
  __ LoadExternalPointerField(
      jmpbuf,
      FieldOperand(active_continuation, WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag, tmp2);
  SwitchStackState(masm, jmpbuf, wasm::JumpBuffer::Active,
                   wasm::JumpBuffer::Retired);

  Register parent = tmp2;
  __ LoadTaggedField(
      parent,
      FieldOperand(active_continuation, WasmContinuationObject::kParentOffset));

  // Update active continuation root.
  __ movq(masm->RootAsOperand(RootIndex::kActiveContinuation), parent);
  jmpbuf = parent;
  __ LoadExternalPointerField(
      jmpbuf, FieldOperand(parent, WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag, kScratchRegister);

  // Switch stack!
  LoadJumpBuffer(masm, jmpbuf, false, wasm::JumpBuffer::Inactive);
  SwitchStacks(masm, active_continuation, promise, return_value, context);
}

// Loads the context field of the WasmTrustedInstanceData or WasmImportData
// depending on the data's type, and places the result in the input register.
void GetContextFromImplicitArg(MacroAssembler* masm, Register data) {
  __ LoadTaggedField(kScratchRegister,
                     FieldOperand(data, HeapObject::kMapOffset));
  __ CmpInstanceType(kScratchRegister, WASM_TRUSTED_INSTANCE_DATA_TYPE);
  Label instance;
  Label end;
  __ j(equal, &instance);
  __ LoadTaggedField(data,
                     FieldOperand(data, WasmImportData::kNativeContextOffset));
  __ jmp(&end);
  __ bind(&instance);
  __ LoadTaggedField(
      data, FieldOperand(data, WasmTrustedInstanceData::kNativeContextOffset));
  __ bind(&end);
}

void RestoreParentSuspender(MacroAssembler* masm, Register tmp1,
                            Register tmp2) {
  Register suspender = tmp1;
  __ LoadRoot(suspender, RootIndex::kActiveSuspender);
  __ StoreTaggedSignedField(
      FieldOperand(suspender, WasmSuspenderObject::kStateOffset),
      Smi::FromInt(WasmSuspenderObject::kInactive));
  __ LoadTaggedField(
      suspender, FieldOperand(suspender, WasmSuspenderObject::kParentOffset));
  __ CompareRoot(suspender, RootIndex::kUndefinedValue);
  Label undefined;
  __ j(equal, &undefined, Label::kNear);
#ifdef DEBUG
  // Check that the parent suspender is active.
  Label parent_inactive;
  Register state = tmp2;
  __ LoadTaggedSignedField(
      state, FieldOperand(suspender, WasmSuspenderObject::kStateOffset));
  __ SmiCompare(state, Smi::FromInt(WasmSuspenderObject::kActive));
  __ j(equal, &parent_inactive, Label::kNear);
  __ Trap();
  __ bind(&parent_inactive);
#endif
  __ StoreTaggedSignedField(
      FieldOperand(suspender, WasmSuspenderObject::kStateOffset),
      Smi::FromInt(WasmSuspenderObject::kActive));
  __ bind(&undefined);
  __ movq(masm->RootAsOperand(RootIndex::kActiveSuspender), suspender);
}

void ResetStackSwitchFrameStackSlots(MacroAssembler* masm) {
  __ Move(kScratchRegister, Smi::zero());
  __ movq(MemOperand(rbp, StackSwitchFrameConstants::kImplicitArgOffset),
          kScratchRegister);
  __ movq(MemOperand(rbp, StackSwitchFrameConstants::kResultArrayOffset),
          kScratchRegister);
}

void SwitchToAllocatedStack(MacroAssembler* masm, Register wasm_instance,
                            Register wrapper_buffer, Register original_fp,
                            Register new_wrapper_buffer, Register scratch,
                            Label* suspend) {
  ResetStackSwitchFrameStackSlots(masm);
  Register parent_continuation = new_wrapper_buffer;
  __ LoadRoot(parent_continuation, RootIndex::kActiveContinuation);
  __ LoadTaggedField(
      parent_continuation,
      FieldOperand(parent_continuation, WasmContinuationObject::kParentOffset));
  SaveState(masm, parent_continuation, scratch, suspend);
  SwitchStacks(masm, no_reg, kWasmImplicitArgRegister, wrapper_buffer);
  parent_continuation = no_reg;
  Register target_continuation = scratch;
  __ LoadRoot(target_continuation, RootIndex::kActiveContinuation);
  // Save the old stack's rbp in r9, and use it to access the parameters in
  // the parent frame.
  __ movq(original_fp, rbp);
  LoadTargetJumpBuffer(masm, target_continuation, wasm::JumpBuffer::Suspended);
  // Push the loaded rbp. We know it is null, because there is no frame yet,
  // so we could also push 0 directly. In any case we need to push it, because
  // this marks the base of the stack segment for the stack frame iterator.
  __ EnterFrame(StackFrame::STACK_SWITCH);
  int stack_space =
      StackSwitchFrameConstants::kNumSpillSlots * kSystemPointerSize +
      JSToWasmWrapperFrameConstants::kWrapperBufferSize;
  __ AllocateStackSpace(stack_space);
  __ movq(new_wrapper_buffer, rsp);
  // Copy data needed for return handling from old wrapper buffer to new one.
  // kWrapperBufferRefReturnCount will be copied too, because 8 bytes are copied
  // at the same time.
  static_assert(JSToWasmWrapperFrameConstants::kWrapperBufferRefReturnCount ==
                JSToWasmWrapperFrameConstants::kWrapperBufferReturnCount + 4);
  __ movq(kScratchRegister,
          MemOperand(wrapper_buffer,
                     JSToWasmWrapperFrameConstants::kWrapperBufferReturnCount));
  __ movq(MemOperand(new_wrapper_buffer,
                     JSToWasmWrapperFrameConstants::kWrapperBufferReturnCount),
          kScratchRegister);
  __ movq(
      kScratchRegister,
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferSigRepresentationArray));
  __ movq(
      MemOperand(
          new_wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferSigRepresentationArray),
      kScratchRegister);
}

void SwitchBackAndReturnPromise(MacroAssembler* masm, Register tmp1,
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
    __ movq(return_value, kReturnRegister0);
    __ LoadRoot(promise, RootIndex::kActiveSuspender);
    __ LoadTaggedField(
        promise, FieldOperand(promise, WasmSuspenderObject::kPromiseOffset));
  }

  __ movq(kContextRegister,
          MemOperand(rbp, StackSwitchFrameConstants::kImplicitArgOffset));
  GetContextFromImplicitArg(masm, kContextRegister);
  ReloadParentContinuation(masm, promise, return_value, kContextRegister, tmp1,
                           tmp2);
  RestoreParentSuspender(masm, tmp1, tmp2);

  if (mode == wasm::kPromise) {
    __ Move(MemOperand(rbp, StackSwitchFrameConstants::kGCScanSlotCountOffset),
            1);
    __ Push(promise);
    __ CallBuiltin(Builtin::kFulfillPromise);
    __ Pop(promise);
  }

  __ bind(return_promise);
}

void GenerateExceptionHandlingLandingPad(MacroAssembler* masm,
                                         Label* return_promise) {
  int catch_handler = __ pc_offset();

  __ endbr64();

  // Restore rsp to free the reserved stack slots for the sections.
  __ leaq(rsp, MemOperand(rbp, StackSwitchFrameConstants::kLastSpillOffset));

  // Unset thread_in_wasm_flag.
  Register thread_in_wasm_flag_addr = r8;
  __ movq(
      thread_in_wasm_flag_addr,
      MemOperand(kRootRegister, Isolate::thread_in_wasm_flag_address_offset()));
  __ movl(MemOperand(thread_in_wasm_flag_addr, 0), Immediate(0));
  thread_in_wasm_flag_addr = no_reg;

  // The exception becomes the parameter of the RejectPromise builtin, and the
  // promise is the return value of this wrapper.
  static const Builtin_RejectPromise_InterfaceDescriptor desc;
  Register promise = desc.GetRegisterParameter(0);
  Register reason = desc.GetRegisterParameter(1);
  Register debug_event = desc.GetRegisterParameter(2);
  __ movq(reason, kReturnRegister0);
  __ LoadRoot(promise, RootIndex::kActiveSuspender);
  __ LoadTaggedField(
      promise, FieldOperand(promise, WasmSuspenderObject::kPromiseOffset));
  __ movq(kContextRegister,
          MemOperand(rbp, StackSwitchFrameConstants::kImplicitArgOffset));
  GetContextFromImplicitArg(masm, kContextRegister);

  ReloadParentContinuation(masm, promise, reason, kContextRegister, r8, rdi);
  RestoreParentSuspender(masm, r8, rdi);

  __ Move(MemOperand(rbp, StackSwitchFrameConstants::kGCScanSlotCountOffset),
          1);
  __ Push(promise);
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

  __ AllocateStackSpace(StackSwitchFrameConstants::kNumSpillSlots *
                        kSystemPointerSize);

  // Load the implicit argument (instance data or import data) from the frame.
  __ movq(kWasmImplicitArgRegister,
          MemOperand(rbp, JSToWasmWrapperFrameConstants::kImplicitArgOffset));

  Register wrapper_buffer =
      WasmJSToWasmWrapperDescriptor::WrapperBufferRegister();
  Register original_fp = stack_switch ? r9 : rbp;
  Register new_wrapper_buffer = stack_switch ? rbx : wrapper_buffer;
  Label suspend;
  if (stack_switch) {
    SwitchToAllocatedStack(masm, kWasmImplicitArgRegister, wrapper_buffer,
                           original_fp, new_wrapper_buffer, rax, &suspend);
  }

  __ movq(MemOperand(rbp, JSToWasmWrapperFrameConstants::kWrapperBufferOffset),
          new_wrapper_buffer);
  if (stack_switch) {
    __ movq(MemOperand(rbp, StackSwitchFrameConstants::kImplicitArgOffset),
            kWasmImplicitArgRegister);
    Register result_array = kScratchRegister;
    __ movq(result_array,
            MemOperand(original_fp,
                       JSToWasmWrapperFrameConstants::kResultArrayParamOffset));
    __ movq(MemOperand(rbp, StackSwitchFrameConstants::kResultArrayOffset),
            result_array);
  }

  Register result_size = rax;
  __ movq(
      result_size,
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferStackReturnBufferSize));
  __ shlq(result_size, Immediate(kSystemPointerSizeLog2));
  __ subq(rsp, result_size);
  __ movq(
      MemOperand(
          new_wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferStackReturnBufferStart),
      rsp);
  Register call_target = rdi;
  // param_start should not alias with any parameter registers.
  Register params_start = r11;
  __ movq(params_start,
          MemOperand(wrapper_buffer,
                     JSToWasmWrapperFrameConstants::kWrapperBufferParamStart));
  Register params_end = rbx;
  __ movq(params_end,
          MemOperand(wrapper_buffer,
                     JSToWasmWrapperFrameConstants::kWrapperBufferParamEnd));

  __ LoadWasmCodePointer(
      call_target,
      MemOperand(wrapper_buffer,
                 JSToWasmWrapperFrameConstants::kWrapperBufferCallTarget));

  Register last_stack_param = rcx;

  // The first GP parameter is the data, which we handle specially.
  int stack_params_offset =
      (arraysize(wasm::kGpParamRegisters) - 1) * kSystemPointerSize +
      arraysize(wasm::kFpParamRegisters) * kDoubleSize;

  __ leaq(last_stack_param, MemOperand(params_start, stack_params_offset));

  Label loop_start;
  __ bind(&loop_start);

  Label finish_stack_params;
  __ cmpq(last_stack_param, params_end);
  __ j(greater_equal, &finish_stack_params);

  // Push parameter
  __ subq(params_end, Immediate(kSystemPointerSize));
  __ pushq(MemOperand(params_end, 0));
  __ jmp(&loop_start);

  __ bind(&finish_stack_params);

  int next_offset = 0;
  for (size_t i = 1; i < arraysize(wasm::kGpParamRegisters); ++i) {
    // Check that {params_start} does not overlap with any of the parameter
    // registers, so that we don't overwrite it by accident with the loads
    // below.
    DCHECK_NE(params_start, wasm::kGpParamRegisters[i]);
    __ movq(wasm::kGpParamRegisters[i], MemOperand(params_start, next_offset));
    next_offset += kSystemPointerSize;
  }

  for (size_t i = 0; i < arraysize(wasm::kFpParamRegisters); ++i) {
    __ Movsd(wasm::kFpParamRegisters[i], MemOperand(params_start, next_offset));
    next_offset += kDoubleSize;
  }
  DCHECK_EQ(next_offset, stack_params_offset);

  Register thread_in_wasm_flag_addr = r12;
  __ movq(
      thread_in_wasm_flag_addr,
      MemOperand(kRootRegister, Isolate::thread_in_wasm_flag_address_offset()));
  __ movl(MemOperand(thread_in_wasm_flag_addr, 0), Immediate(1));
  if (stack_switch) {
    __ Move(MemOperand(rbp, StackSwitchFrameConstants::kGCScanSlotCountOffset),
            0);
  }

  __ CallWasmCodePointer(call_target);

  __ movq(
      thread_in_wasm_flag_addr,
      MemOperand(kRootRegister, Isolate::thread_in_wasm_flag_address_offset()));
  __ movl(MemOperand(thread_in_wasm_flag_addr, 0), Immediate(0));
  thread_in_wasm_flag_addr = no_reg;

  wrapper_buffer = rcx;
  for (size_t i = 0; i < arraysize(wasm::kGpReturnRegisters); ++i) {
    DCHECK_NE(wrapper_buffer, wasm::kGpReturnRegisters[i]);
  }

  __ movq(wrapper_buffer,
          MemOperand(rbp, JSToWasmWrapperFrameConstants::kWrapperBufferOffset));

  __ Movsd(MemOperand(
               wrapper_buffer,
               JSToWasmWrapperFrameConstants::kWrapperBufferFPReturnRegister1),
           wasm::kFpReturnRegisters[0]);
  __ Movsd(MemOperand(
               wrapper_buffer,
               JSToWasmWrapperFrameConstants::kWrapperBufferFPReturnRegister2),
           wasm::kFpReturnRegisters[1]);
  __ movq(MemOperand(
              wrapper_buffer,
              JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister1),
          wasm::kGpReturnRegisters[0]);
  __ movq(MemOperand(
              wrapper_buffer,
              JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister2),
          wasm::kGpReturnRegisters[1]);

  // Call the return value builtin with
  // rax: wasm instance.
  // rbx: the result JSArray for multi-return.
  // rcx: pointer to the byte buffer which contains all parameters.
  if (stack_switch) {
    __ movq(rbx,
            MemOperand(rbp, StackSwitchFrameConstants::kResultArrayOffset));
    __ movq(rax,
            MemOperand(rbp, StackSwitchFrameConstants::kImplicitArgOffset));
  } else {
    __ movq(rbx,
            MemOperand(rbp,
                       JSToWasmWrapperFrameConstants::kResultArrayParamOffset));
    __ movq(rax,
            MemOperand(rbp, JSToWasmWrapperFrameConstants::kImplicitArgOffset));
  }
  GetContextFromImplicitArg(masm, rax);
  __ CallBuiltin(Builtin::kJSToWasmHandleReturns);

  Label return_promise;
  if (stack_switch) {
    SwitchBackAndReturnPromise(masm, r8, rdi, mode, &return_promise);
  }
  __ bind(&suspend);
  __ endbr64();

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
  __ popq(kScratchRegister);

  int required_stack_space = arraysize(wasm::kFpParamRegisters) * kDoubleSize;
  __ subq(rsp, Immediate(required_stack_space));
  for (int i = 0; i < static_cast<int>(arraysize(wasm::kFpParamRegisters));
       ++i) {
    __ Movsd(MemOperand(rsp, i * kDoubleSize), wasm::kFpParamRegisters[i]);
  }
  // Push the GP registers in reverse order so that they are on the stack like
  // in an array, with the first item being at the lowest address.
  for (size_t i = arraysize(wasm::kGpParamRegisters) - 1; i > 0; --i) {
    __ pushq(wasm::kGpParamRegisters[i]);
  }
  // Signature slot.
  __ pushq(rax);
  // Push the return address again.
  __ pushq(kScratchRegister);
  __ TailCallBuiltin(Builtin::kWasmToJsWrapperCSA);
}

void Builtins::Generate_WasmTrapHandlerLandingPad(MacroAssembler* masm) {
  __ addq(
      kWasmTrapHandlerFaultAddressRegister,
      Immediate(WasmFrameConstants::kProtectedInstructionReturnAddressOffset));
  __ pushq(kWasmTrapHandlerFaultAddressRegister);
  __ TailCallBuiltin(Builtin::kWasmTrapHandlerThrowTrap);
}

void Builtins::Generate_WasmSuspend(MacroAssembler* masm) {
  // Set up the stackframe.
  __ EnterFrame(StackFrame::STACK_SWITCH);

  Register suspender = rax;

  __ AllocateStackSpace(StackSwitchFrameConstants::kNumSpillSlots *
                        kSystemPointerSize);
  // Set a sentinel value for the spill slots visited by the GC.
  ResetStackSwitchFrameStackSlots(masm);

  // -------------------------------------------
  // Save current state in active jump buffer.
  // -------------------------------------------
  Label resume;
  Register continuation = rcx;
  __ LoadRoot(continuation, RootIndex::kActiveContinuation);
  Register jmpbuf = rdx;
  __ LoadExternalPointerField(
      jmpbuf, FieldOperand(continuation, WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag, r8);
  FillJumpBuffer(masm, jmpbuf, &resume);
  SwitchStackState(masm, jmpbuf, wasm::JumpBuffer::Active,
                   wasm::JumpBuffer::Suspended);
  __ StoreTaggedSignedField(
      FieldOperand(suspender, WasmSuspenderObject::kStateOffset),
      Smi::FromInt(WasmSuspenderObject::kSuspended));
  jmpbuf = no_reg;
  // live: [rax, rbx, rcx]

  Register suspender_continuation = rdx;
  __ LoadTaggedField(
      suspender_continuation,
      FieldOperand(suspender, WasmSuspenderObject::kContinuationOffset));
#ifdef DEBUG
  // -------------------------------------------
  // Check that the suspender's continuation is the active continuation.
  // -------------------------------------------
  // TODO(thibaudm): Once we add core stack-switching instructions, this check
  // will not hold anymore: it's possible that the active continuation changed
  // (due to an internal switch), so we have to update the suspender.
  __ cmpq(suspender_continuation, continuation);
  Label ok;
  __ j(equal, &ok);
  __ Trap();
  __ bind(&ok);
#endif

  // -------------------------------------------
  // Update roots.
  // -------------------------------------------
  Register caller = rcx;
  __ LoadTaggedField(caller,
                     FieldOperand(suspender_continuation,
                                  WasmContinuationObject::kParentOffset));
  __ movq(masm->RootAsOperand(RootIndex::kActiveContinuation), caller);
  Register parent = rdx;
  __ LoadTaggedField(
      parent, FieldOperand(suspender, WasmSuspenderObject::kParentOffset));
  __ movq(masm->RootAsOperand(RootIndex::kActiveSuspender), parent);
  parent = no_reg;
  // live: [rax, rcx]

  // -------------------------------------------
  // Load jump buffer.
  // -------------------------------------------
  SwitchStacks(masm, no_reg, caller, suspender);
  jmpbuf = caller;
  __ LoadExternalPointerField(
      jmpbuf, FieldOperand(caller, WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag, r8);
  caller = no_reg;
  __ LoadTaggedField(
      kReturnRegister0,
      FieldOperand(suspender, WasmSuspenderObject::kPromiseOffset));
  MemOperand GCScanSlotPlace =
      MemOperand(rbp, StackSwitchFrameConstants::kGCScanSlotCountOffset);
  __ Move(GCScanSlotPlace, 0);
  LoadJumpBuffer(masm, jmpbuf, true, wasm::JumpBuffer::Inactive);
  __ Trap();
  __ bind(&resume);
  __ endbr64();
  __ LeaveFrame(StackFrame::STACK_SWITCH);
  __ ret(0);
}

namespace {
// Resume the suspender stored in the closure. We generate two variants of this
// builtin: the onFulfilled variant resumes execution at the saved PC and
// forwards the value, the onRejected variant throws the value.

void Generate_WasmResumeHelper(MacroAssembler* masm, wasm::OnResume on_resume) {
  __ EnterFrame(StackFrame::STACK_SWITCH);

  Register param_count = rax;
  __ decq(param_count);                    // Exclude receiver.
  Register closure = kJSFunctionRegister;  // rdi

  __ AllocateStackSpace(StackSwitchFrameConstants::kNumSpillSlots *
                        kSystemPointerSize);
  // Set a sentinel value for the spill slots visited by the GC.
  ResetStackSwitchFrameStackSlots(masm);

  param_count = no_reg;

  // -------------------------------------------
  // Load suspender from closure.
  // -------------------------------------------
  Register sfi = closure;
  __ LoadTaggedField(
      sfi,
      MemOperand(
          closure,
          wasm::ObjectAccess::SharedFunctionInfoOffsetInTaggedJSFunction()));
  Register resume_data = sfi;
  __ LoadTaggedField(
      resume_data,
      FieldOperand(sfi, SharedFunctionInfo::kUntrustedFunctionDataOffset));

  // The write barrier uses a fixed register for the host object (rdi). The next
  // barrier is on the suspender, so load it in rdi directly.
  Register suspender = rdi;
  __ LoadTaggedField(
      suspender, FieldOperand(resume_data, WasmResumeData::kSuspenderOffset));
  // Check the suspender state.
  Label suspender_is_suspended;
  Register state = rdx;
  __ LoadTaggedSignedField(
      state, FieldOperand(suspender, WasmSuspenderObject::kStateOffset));
  __ SmiCompare(state, Smi::FromInt(WasmSuspenderObject::kSuspended));
  __ j(equal, &suspender_is_suspended);
  __ Trap();  // TODO(thibaudm): Throw a wasm trap.
  closure = no_reg;
  sfi = no_reg;

  __ bind(&suspender_is_suspended);
  // -------------------------------------------
  // Save current state.
  // -------------------------------------------
  Label suspend;
  Register active_continuation = r9;
  __ LoadRoot(active_continuation, RootIndex::kActiveContinuation);
  Register current_jmpbuf = rax;
  __ LoadExternalPointerField(
      current_jmpbuf,
      FieldOperand(active_continuation, WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag, rdx);
  FillJumpBuffer(masm, current_jmpbuf, &suspend);
  SwitchStackState(masm, current_jmpbuf, wasm::JumpBuffer::Active,
                   wasm::JumpBuffer::Inactive);
  current_jmpbuf = no_reg;

  // -------------------------------------------
  // Set the suspender and continuation parents and update the roots
  // -------------------------------------------
  Register active_suspender = rcx;
  Register slot_address = WriteBarrierDescriptor::SlotAddressRegister();
  // Check that the fixed register isn't one that is already in use.
  DCHECK(slot_address == rbx || slot_address == r8);
  __ LoadRoot(active_suspender, RootIndex::kActiveSuspender);
  __ StoreTaggedField(
      FieldOperand(suspender, WasmSuspenderObject::kParentOffset),
      active_suspender);
  __ RecordWriteField(suspender, WasmSuspenderObject::kParentOffset,
                      active_suspender, slot_address, SaveFPRegsMode::kIgnore);
  __ StoreTaggedSignedField(
      FieldOperand(suspender, WasmSuspenderObject::kStateOffset),
      Smi::FromInt(WasmSuspenderObject::kActive));
  __ movq(masm->RootAsOperand(RootIndex::kActiveSuspender), suspender);

  Register target_continuation = suspender;
  __ LoadTaggedField(
      target_continuation,
      FieldOperand(suspender, WasmSuspenderObject::kContinuationOffset));
  suspender = no_reg;
  __ StoreTaggedField(
      FieldOperand(target_continuation, WasmContinuationObject::kParentOffset),
      active_continuation);
  __ RecordWriteField(
      target_continuation, WasmContinuationObject::kParentOffset,
      active_continuation, slot_address, SaveFPRegsMode::kIgnore);
  active_continuation = no_reg;
  __ movq(masm->RootAsOperand(RootIndex::kActiveContinuation),
          target_continuation);

  SwitchStacks(masm, no_reg, target_continuation);

  // -------------------------------------------
  // Load state from target jmpbuf (longjmp).
  // -------------------------------------------
  Register target_jmpbuf = rdi;
  __ LoadExternalPointerField(
      target_jmpbuf,
      FieldOperand(target_continuation, WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag, rax);
  // Move resolved value to return register.
  __ movq(kReturnRegister0, Operand(rbp, 3 * kSystemPointerSize));
  __ Move(MemOperand(rbp, StackSwitchFrameConstants::kGCScanSlotCountOffset),
          0);
  if (on_resume == wasm::OnResume::kThrow) {
    // Switch to the continuation's stack without restoring the PC.
    LoadJumpBuffer(masm, target_jmpbuf, false, wasm::JumpBuffer::Suspended);
    // Pop this frame now. The unwinder expects that the first STACK_SWITCH
    // frame is the outermost one.
    __ LeaveFrame(StackFrame::STACK_SWITCH);
    // Forward the onRejected value to kThrow.
    __ pushq(kReturnRegister0);
    __ Move(kContextRegister, Smi::zero());
    __ CallRuntime(Runtime::kThrow);
  } else {
    // Resume the continuation normally.
    LoadJumpBuffer(masm, target_jmpbuf, true, wasm::JumpBuffer::Suspended);
  }
  __ Trap();
  __ bind(&suspend);
  __ endbr64();
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
  MemOperand OSRTargetSlot(rbp, -wasm::kOSRTargetOffset);
  __ movq(kScratchRegister, OSRTargetSlot);
  __ Move(OSRTargetSlot, 0);
  __ jmp(kScratchRegister);
}

namespace {
static constexpr Register kOldSPRegister = r12;

void SwitchToTheCentralStackIfNeeded(MacroAssembler* masm,
                                     int r12_stack_slot_index) {
  using ER = ExternalReference;

  // Store r12 value on the stack to restore on exit from the builtin.
  __ movq(ExitFrameStackSlotOperand(r12_stack_slot_index * kSystemPointerSize),
          r12);

  // kOldSPRegister used as a switch flag, if it is zero - no switch performed
  // if it is not zero, it contains old sp value.
  __ Move(kOldSPRegister, 0);

  // Using arg1-2 regs as temporary registers, because they will be rewritten
  // before exiting to native code anyway.
  DCHECK(
      !AreAliased(kCArgRegs[0], kCArgRegs[1], kOldSPRegister, rax, rbx, r15));

  ER on_central_stack_flag = ER::Create(
      IsolateAddressId::kIsOnCentralStackFlagAddress, masm->isolate());

  Label do_not_need_to_switch;
  __ cmpb(__ ExternalReferenceAsOperand(on_central_stack_flag), Immediate(0));
  __ j(not_zero, &do_not_need_to_switch);

  // Perform switching to the central stack.

  __ movq(kOldSPRegister, rsp);

  static constexpr Register argc_input = rax;
  Register central_stack_sp = kCArgRegs[1];
  DCHECK(!AreAliased(central_stack_sp, argc_input));
  {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ pushq(argc_input);

    __ Move(kCArgRegs[0], ER::isolate_address());
    __ Move(kCArgRegs[1], kOldSPRegister);
    __ PrepareCallCFunction(2);
    __ CallCFunction(ER::wasm_switch_to_the_central_stack(), 2,
                     SetIsolateDataSlots::kNo);
    __ movq(central_stack_sp, kReturnRegister0);

    __ popq(argc_input);
  }

  static constexpr int kReturnAddressSlotOffset = 1 * kSystemPointerSize;
  __ subq(central_stack_sp, Immediate(kReturnAddressSlotOffset));
  __ movq(rsp, central_stack_sp);
  // rsp should be aligned by 16 bytes,
  // but it is not guaranteed for stored SP.
  __ AlignStackPointer();

#ifdef V8_TARGET_OS_WIN
  // When we switch stack we leave home space allocated on the old stack.
  // Allocate home space on the central stack to prevent stack corruption.
  __ subq(rsp, Immediate(kWindowsHomeStackSlots * kSystemPointerSize));
#endif  // V8_TARGET_OS_WIN

  // Update the sp saved in the frame.
  // It will be used to calculate the callee pc during GC.
  // The pc is going to be on the new stack segment, so rewrite it here.
  __ movq(Operand(rbp, ExitFrameConstants::kSPOffset), rsp);

  __ bind(&do_not_need_to_switch);
}

void SwitchFromTheCentralStackIfNeeded(MacroAssembler* masm,
                                       int r12_stack_slot_index) {
  using ER = ExternalReference;

  Label no_stack_change;
  __ cmpq(kOldSPRegister, Immediate(0));
  __ j(equal, &no_stack_change);
  __ movq(rsp, kOldSPRegister);

  {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ pushq(kReturnRegister0);
    __ pushq(kReturnRegister1);

    __ Move(kCArgRegs[0], ER::isolate_address());
    __ PrepareCallCFunction(1);
    __ CallCFunction(ER::wasm_switch_from_the_central_stack(), 1,
                     SetIsolateDataSlots::kNo);

    __ popq(kReturnRegister1);
    __ popq(kReturnRegister0);
  }

  __ bind(&no_stack_change);

  // Restore previous value of r12.
  __ movq(r12,
          ExitFrameStackSlotOperand(r12_stack_slot_index * kSystemPointerSize));
}

}  // namespace

#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_CEntry(MacroAssembler* masm, int result_size,
                               ArgvMode argv_mode, bool builtin_exit_frame,
                               bool switch_to_central_stack) {
  CHECK(result_size == 1 || result_size == 2);

  using ER = ExternalReference;

  // rax: number of arguments including receiver
  // rbx: pointer to C function  (C callee-saved)
  // rbp: frame pointer of calling JS frame (restored after C call)
  // rsp: stack pointer  (restored after C call)
  // rsi: current context (restored)
  //
  // If argv_mode == ArgvMode::kRegister:
  // r15: pointer to the first argument

  const int kSwitchToTheCentralStackSlots = switch_to_central_stack ? 1 : 0;
#ifdef V8_TARGET_OS_WIN
  // Windows 64-bit ABI only allows a single-word to be returned in register
  // rax. Larger return sizes must be written to an address passed as a hidden
  // first argument.
  static constexpr int kMaxRegisterResultSize = 1;
  const int kReservedStackSlots = kSwitchToTheCentralStackSlots +
      (result_size <= kMaxRegisterResultSize ? 0 : result_size);
#else
  // Simple results are returned in rax, and a struct of two pointers are
  // returned in rax+rdx.
  static constexpr int kMaxRegisterResultSize = 2;
  const int kReservedStackSlots = kSwitchToTheCentralStackSlots;
  CHECK_LE(result_size, kMaxRegisterResultSize);
#endif  // V8_TARGET_OS_WIN
#if V8_ENABLE_WEBASSEMBLY
  const int kR12SpillSlot = kReservedStackSlots - 1;
#endif  // V8_ENABLE_WEBASSEMBLY

  __ EnterExitFrame(
      kReservedStackSlots,
      builtin_exit_frame ? StackFrame::BUILTIN_EXIT : StackFrame::EXIT, rbx);

  // Set up argv in a callee-saved register. It is reused below so it must be
  // retained across the C call. In case of ArgvMode::kRegister, r15 has
  // already been set by the caller.
  static constexpr Register kArgvRegister = r15;
  if (argv_mode == ArgvMode::kStack) {
    int offset =
        StandardFrameConstants::kFixedFrameSizeAboveFp - kReceiverOnStackSize;
    __ leaq(kArgvRegister,
            Operand(rbp, rax, times_system_pointer_size, offset));
  }

  // rbx: pointer to builtin function  (C callee-saved).
  // rbp: frame pointer of exit frame  (restored after C call).
  // rsp: stack pointer (restored after C call).
  // rax: number of arguments including receiver
  // r15: argv pointer (C callee-saved).

#if V8_ENABLE_WEBASSEMBLY
  if (switch_to_central_stack) {
    SwitchToTheCentralStackIfNeeded(masm, kR12SpillSlot);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // Check stack alignment.
  if (v8_flags.debug_code) {
    __ CheckStackAlignment();
  }

  // Call C function. The arguments object will be created by stubs declared by
  // DECLARE_RUNTIME_FUNCTION().
  if (result_size <= kMaxRegisterResultSize) {
    // Pass a pointer to the Arguments object as the first argument.
    // Return result in single register (rax), or a register pair (rax, rdx).
    __ movq(kCArgRegs[0], rax);            // argc.
    __ movq(kCArgRegs[1], kArgvRegister);  // argv.
    __ Move(kCArgRegs[2], ER::isolate_address());
  } else {
#ifdef V8_TARGET_OS_WIN
    DCHECK_LE(result_size, 2);
    // Pass a pointer to the result location as the first argument.
    __ leaq(kCArgRegs[0], ExitFrameStackSlotOperand(0 * kSystemPointerSize));
    // Pass a pointer to the Arguments object as the second argument.
    __ movq(kCArgRegs[1], rax);            // argc.
    __ movq(kCArgRegs[2], kArgvRegister);  // argv.
    __ Move(kCArgRegs[3], ER::isolate_address());
#else
    UNREACHABLE();
#endif  // V8_TARGET_OS_WIN
  }
  __ call(rbx);

#ifdef V8_TARGET_OS_WIN
  if (result_size > kMaxRegisterResultSize) {
    // Read result values stored on stack.
    DCHECK_EQ(result_size, 2);
    __ movq(kReturnRegister0,
            ExitFrameStackSlotOperand(0 * kSystemPointerSize));
    __ movq(kReturnRegister1,
            ExitFrameStackSlotOperand(1 * kSystemPointerSize));
  }
#endif  // V8_TARGET_OS_WIN

  // Result is in rax or rdx:rax - do not destroy these registers!

#if V8_ENABLE_WEBASSEMBLY
  if (switch_to_central_stack) {
    SwitchFromTheCentralStackIfNeeded(masm, kR12SpillSlot);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // Check result for exception sentinel.
  Label exception_returned;
  // The returned value may be a trusted object, living outside of the main
  // pointer compression cage, so we need to use full pointer comparison here.
  __ CompareRoot(rax, RootIndex::kException, ComparisonMode::kFullPointer);
  __ j(equal, &exception_returned);

  // Check that there is no exception, otherwise we
  // should have returned the exception sentinel.
  if (v8_flags.debug_code) {
    Label okay;
    __ LoadRoot(kScratchRegister, RootIndex::kTheHoleValue);
    ER exception_address =
        ER::Create(IsolateAddressId::kExceptionAddress, masm->isolate());
    __ cmp_tagged(kScratchRegister,
                  masm->ExternalReferenceAsOperand(exception_address));
    __ j(equal, &okay, Label::kNear);
    __ int3();
    __ bind(&okay);
  }

  __ LeaveExitFrame();
  if (argv_mode == ArgvMode::kStack) {
    // Drop arguments and the receiver from the caller stack.
    __ PopReturnAddressTo(rcx);
    __ leaq(rsp, Operand(kArgvRegister, kReceiverOnStackSize));
    __ PushReturnAddressFrom(rcx);
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

  // Ask the runtime for help to determine the handler. This will set rax to
  // contain the current exception, don't clobber it.
  ER find_handler = ER::Create(Runtime::kUnwindAndFindExceptionHandler);
  {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ Move(kCArgRegs[0], 0);  // argc.
    __ Move(kCArgRegs[1], 0);  // argv.
    __ Move(kCArgRegs[2], ER::isolate_address());
    __ PrepareCallCFunction(3);
    __ CallCFunction(find_handler, 3, SetIsolateDataSlots::kNo);
  }

#ifdef V8_ENABLE_CET_SHADOW_STACK
  // Drop frames from the shadow stack.
  ER num_frames_above_pending_handler_address = ER::Create(
      IsolateAddressId::kNumFramesAbovePendingHandlerAddress, masm->isolate());
  __ movq(rcx, masm->ExternalReferenceAsOperand(
                   num_frames_above_pending_handler_address));
  __ IncsspqIfSupported(rcx, kScratchRegister);
#endif  // V8_ENABLE_CET_SHADOW_STACK

  // Retrieve the handler context, SP and FP.
  __ movq(rsi,
          masm->ExternalReferenceAsOperand(pending_handler_context_address));
  __ movq(rsp, masm->ExternalReferenceAsOperand(pending_handler_sp_address));
  __ movq(rbp, masm->ExternalReferenceAsOperand(pending_handler_fp_address));

  // If the handler is a JS frame, restore the context to the frame. Note that
  // the context will be set to (rsi == 0) for non-JS frames.
  Label skip;
  __ testq(rsi, rsi);
  __ j(zero, &skip, Label::kNear);
  __ movq(Operand(rbp, StandardFrameConstants::kContextOffset), rsi);
  __ bind(&skip);

  // Clear c_entry_fp, like we do in `LeaveExitFrame`.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, masm->isolate());
  Operand c_entry_fp_operand =
      masm->ExternalReferenceAsOperand(c_entry_fp_address);
  __ movq(c_entry_fp_operand, Immediate(0));

  // Compute the handler entry address and jump to it.
  __ movq(rdi,
          masm->ExternalReferenceAsOperand(pending_handler_entrypoint_address));
  __ jmp(rdi);
}

#if V8_ENABLE_WEBASSEMBLY
void Builtins::Generate_WasmHandleStackOverflow(MacroAssembler* masm) {
  using ER = ExternalReference;
  Register frame_base = WasmHandleStackOverflowDescriptor::FrameBaseRegister();
  Register gap = WasmHandleStackOverflowDescriptor::GapRegister();
  {
    DCHECK_NE(kCArgRegs[1], frame_base);
    DCHECK_NE(kCArgRegs[3], frame_base);
    __ movq(kCArgRegs[3], gap);
    __ movq(kCArgRegs[1], rsp);
    __ movq(kCArgRegs[2], frame_base);
    __ subq(kCArgRegs[2], kCArgRegs[1]);
#ifdef V8_TARGET_OS_WIN
    Register old_fp = rcx;
    // On windows we need preserve rbp value somewhere before entering
    // INTERNAL frame later. It will be placed on the stack as an argument.
    __ movq(old_fp, rbp);
#else
    __ movq(kCArgRegs[4], rbp);
#endif
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ pushq(kCArgRegs[3]);
    __ PrepareCallCFunction(5);
    // On windows put the arguments on the stack (PrepareCallCFunction
    // has created space for this).
#ifdef V8_TARGET_OS_WIN
    __ movq(Operand(rsp, 4 * kSystemPointerSize), old_fp);
#endif
    __ Move(kCArgRegs[0], ER::isolate_address());
    __ CallCFunction(ER::wasm_grow_stack(), 5);
    __ popq(gap);
    DCHECK_NE(kReturnRegister0, gap);
  }
  Label call_runtime;
  // wasm_grow_stack returns zero if it cannot grow a stack.
  __ testq(kReturnRegister0, kReturnRegister0);
  __ j(zero, &call_runtime, Label::kNear);
  // Calculate old FP - SP offset to adjust FP accordingly to new SP.
  __ subq(rbp, rsp);
  __ addq(rbp, kReturnRegister0);
  __ movq(rsp, kReturnRegister0);
  __ movq(kScratchRegister,
          Immediate(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
  __ movq(MemOperand(rbp, TypedFrameConstants::kFrameTypeOffset),
          kScratchRegister);
  __ ret(0);

  // If wasm_grow_stack returns zero, interruption or stack overflow
  // should be handled by runtime call.
  {
    __ bind(&call_runtime);
    __ movq(kWasmImplicitArgRegister,
            MemOperand(rbp, WasmFrameConstants::kWasmInstanceDataOffset));
    __ LoadTaggedField(
        kContextRegister,
        FieldOperand(kWasmImplicitArgRegister,
                     WasmTrustedInstanceData::kNativeContextOffset));
    FrameScope scope(masm, StackFrame::MANUAL);
    __ EnterFrame(StackFrame::INTERNAL);
    __ SmiTag(gap);
    __ pushq(gap);
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

  MemOperand mantissa_operand(MemOperand(rsp, kArgumentOffset));
  MemOperand exponent_operand(
      MemOperand(rsp, kArgumentOffset + kDoubleSize / 2));

  // The result is returned on the stack.
  MemOperand return_operand = mantissa_operand;

  Register scratch1 = rbx;

  // Since we must use rcx for shifts below, use some other register (rax)
  // to calculate the result if ecx is the requested return register.
  Register result_reg = rax;
  // Save ecx if it isn't the return register and therefore volatile, or if it
  // is the return register, then save the temp register we use in its stead
  // for the result.
  Register save_reg = rax;
  __ pushq(rcx);
  __ pushq(scratch1);
  __ pushq(save_reg);

  __ movl(scratch1, mantissa_operand);
  __ Movsd(kScratchDoubleReg, mantissa_operand);
  __ movl(rcx, exponent_operand);

  __ andl(rcx, Immediate(HeapNumber::kExponentMask));
  __ shrl(rcx, Immediate(HeapNumber::kExponentShift));
  __ leal(result_reg, MemOperand(rcx, -HeapNumber::kExponentBias));
  __ cmpl(result_reg, Immediate(HeapNumber::kMantissaBits));
  __ j(below, &process_64_bits, Label::kNear);

  // Result is entirely in lower 32-bits of mantissa
  int delta =
      HeapNumber::kExponentBias + base::Double::kPhysicalSignificandSize;
  __ subl(rcx, Immediate(delta));
  __ xorl(result_reg, result_reg);
  __ cmpl(rcx, Immediate(31));
  __ j(above, &done, Label::kNear);
  __ shll_cl(scratch1);
  __ jmp(&check_negative, Label::kNear);

  __ bind(&process_64_bits);
  __ Cvttsd2siq(result_reg, kScratchDoubleReg);
  __ jmp(&done, Label::kNear);

  // If the double was negative, negate the integer result.
  __ bind(&check_negative);
  __ movl(result_reg, scratch1);
  __ negl(result_reg);
  __ cmpl(exponent_operand, Immediate(0));
  __ cmovl(greater, result_reg, scratch1);

  // Restore registers
  __ bind(&done);
  __ movl(return_operand, result_reg);
  __ popq(save_reg);
  __ popq(scratch1);
  __ popq(rcx);
  __ ret(0);
}

// TODO(jgruber): Instead of explicitly setting up implicit_args_ on the stack
// in CallApiCallback, we could use the calling convention to set up the stack
// correctly in the first place.
//
// TODO(jgruber): I suspect that most of CallApiCallback could be implemented
// as a C++ trampoline, vastly simplifying the assembly implementation.

void Builtins::Generate_CallApiCallbackImpl(MacroAssembler* masm,
                                            CallApiCallbackMode mode) {
  // ----------- S t a t e -------------
  // CallApiCallbackMode::kOptimizedNoProfiling/kOptimized modes:
  //  -- rdx                 : api function address
  // Both modes:
  //  -- rcx                 : arguments count (not including the receiver)
  //  -- rbx                 : FunctionTemplateInfo
  //  -- rdi                 : holder
  //  -- rsi                 : context
  //  -- rsp[0]              : return address
  //  -- rsp[8]              : argument 0 (receiver)
  //  -- rsp[16]             : argument 1
  //  -- ...
  //  -- rsp[argc * 8]       : argument (argc - 1)
  //  -- rsp[(argc + 1) * 8] : argument argc
  // -----------------------------------

  Register function_callback_info_arg = kCArgRegs[0];

  Register api_function_address = no_reg;
  Register argc = no_reg;
  Register func_templ = no_reg;
  Register holder = no_reg;
  Register topmost_script_having_context = no_reg;
  Register scratch = rax;
  Register scratch2 = no_reg;

  switch (mode) {
    case CallApiCallbackMode::kGeneric:
      scratch2 = r9;
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
                     holder, func_templ, scratch, scratch2, kScratchRegister));

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
  //   rsp[0]: return address
  //
  // Target state:
  //   rsp[0 * kSystemPointerSize]: return address
  //   rsp[1 * kSystemPointerSize]: kHolder   <= implicit_args_
  //   rsp[2 * kSystemPointerSize]: kIsolate
  //   rsp[3 * kSystemPointerSize]: kContext
  //   rsp[4 * kSystemPointerSize]: undefined (kReturnValue)
  //   rsp[5 * kSystemPointerSize]: kTarget
  //   rsp[6 * kSystemPointerSize]: undefined (kNewTarget)
  // Existing state:
  //   rsp[7 * kSystemPointerSize]:          <= FCA:::values_

  __ StoreRootRelative(IsolateData::topmost_script_having_context_offset(),
                       topmost_script_having_context);

  if (mode == CallApiCallbackMode::kGeneric) {
    api_function_address = ReassignRegister(topmost_script_having_context);
  }

  __ PopReturnAddressTo(scratch);
  __ LoadRoot(kScratchRegister, RootIndex::kUndefinedValue);
  __ Push(kScratchRegister);  // kNewTarget
  __ Push(func_templ);        // kTarget
  __ Push(kScratchRegister);  // kReturnValue
  __ Push(kContextRegister);  // kContext
  __ PushAddress(ER::isolate_address());
  __ Push(holder);

  if (mode == CallApiCallbackMode::kGeneric) {
    __ LoadExternalPointerField(
        api_function_address,
        FieldOperand(func_templ,
                     FunctionTemplateInfo::kMaybeRedirectedCallbackOffset),
        kFunctionTemplateInfoCallbackTag, kScratchRegister);
  }

  __ PushReturnAddressFrom(scratch);
  __ EnterExitFrame(FC::getExtraSlotsCountFrom<ExitFrameConstants>(),
                    StackFrame::API_CALLBACK_EXIT, api_function_address);

  Operand argc_operand = Operand(rbp, FC::kFCIArgcOffset);
  {
    ASM_CODE_COMMENT_STRING(masm, "Initialize v8::FunctionCallbackInfo");
    // FunctionCallbackInfo::length_.
    // TODO(ishell): pass JSParameterCount(argc) to simplify things on the
    // caller end.
    __ movq(argc_operand, argc);

    // FunctionCallbackInfo::implicit_args_.
    __ leaq(scratch, Operand(rbp, FC::kImplicitArgsArrayOffset));
    __ movq(Operand(rbp, FC::kFCIImplicitArgsOffset), scratch);

    // FunctionCallbackInfo::values_ (points at JS arguments on the stack).
    __ leaq(scratch, Operand(rbp, FC::kFirstArgumentOffset));
    __ movq(Operand(rbp, FC::kFCIValuesOffset), scratch);
  }

  __ RecordComment("v8::FunctionCallback's argument.");
  __ leaq(function_callback_info_arg,
          Operand(rbp, FC::kFunctionCallbackInfoOffset));

  DCHECK(!AreAliased(api_function_address, function_callback_info_arg));

  ExternalReference thunk_ref = ER::invoke_function_callback(mode);
  Register no_thunk_arg = no_reg;

  Operand return_value_operand = Operand(rbp, FC::kReturnValueOffset);
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
  //  -- rsi                 : context
  //  -- rdx                 : receiver
  //  -- rcx                 : holder
  //  -- rbx                 : accessor info
  //  -- rsp[0]              : return address
  // -----------------------------------

  Register name_arg = kCArgRegs[0];
  Register property_callback_info_arg = kCArgRegs[1];

  Register api_function_address = r8;
  Register receiver = ApiGetterDescriptor::ReceiverRegister();
  Register holder = ApiGetterDescriptor::HolderRegister();
  Register callback = ApiGetterDescriptor::CallbackRegister();
  Register scratch = rax;
  Register decompr_scratch1 = COMPRESS_POINTERS_BOOL ? r15 : no_reg;

  DCHECK(!AreAliased(receiver, holder, callback, scratch, decompr_scratch1));

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
  //   rsp[0]: return address
  //
  // Target state:
  //   rsp[0 * kSystemPointerSize]: return address
  //   rsp[1 * kSystemPointerSize]: name                      <= PCI::args_
  //   rsp[2 * kSystemPointerSize]: kShouldThrowOnErrorIndex
  //   rsp[3 * kSystemPointerSize]: kHolderIndex
  //   rsp[4 * kSystemPointerSize]: kIsolateIndex
  //   rsp[5 * kSystemPointerSize]: kHolderV2Index
  //   rsp[6 * kSystemPointerSize]: kReturnValueIndex
  //   rsp[7 * kSystemPointerSize]: kDataIndex
  //   rsp[8 * kSystemPointerSize]: kThisIndex / receiver

  __ PopReturnAddressTo(scratch);
  __ Push(receiver);
  __ PushTaggedField(FieldOperand(callback, AccessorInfo::kDataOffset),
                     decompr_scratch1);
  __ LoadRoot(kScratchRegister, RootIndex::kUndefinedValue);
  __ Push(kScratchRegister);  // return value
  __ Push(Smi::zero());       // holderV2 value
  __ PushAddress(ER::isolate_address());
  __ Push(holder);
  __ Push(Smi::FromInt(kDontThrow));  // should_throw_on_error -> kDontThrow

  // Register name = ReassignRegister(receiver);
  __ LoadTaggedField(name_arg,
                     FieldOperand(callback, AccessorInfo::kNameOffset));
  __ Push(name_arg);

  __ RecordComment("Load api_function_address");
  __ LoadExternalPointerField(
      api_function_address,
      FieldOperand(callback, AccessorInfo::kMaybeRedirectedGetterOffset),
      kAccessorInfoGetterTag, kScratchRegister);

  __ PushReturnAddressFrom(scratch);
  __ EnterExitFrame(FC::getExtraSlotsCountFrom<ExitFrameConstants>(),
                    StackFrame::API_ACCESSOR_EXIT, api_function_address);

  __ RecordComment("Create v8::PropertyCallbackInfo object on the stack.");
  // The context register (rsi) might overlap with property_callback_info_arg
  // but the context value has been saved in EnterExitFrame and thus it could
  // be used to pass arguments.
  // property_callback_info_arg = v8::PropertyCallbackInfo&
  __ leaq(property_callback_info_arg, Operand(rbp, FC::kArgsArrayOffset));

  DCHECK(!AreAliased(api_function_address, property_callback_info_arg, name_arg,
                     callback, scratch));

#ifdef V8_ENABLE_DIRECT_HANDLE
  // name_arg = Local<Name>(name), name value was pushed to GC-ed stack space.
  //__ movq(name_arg, name);
  // |name_arg| is already initialized above.
#else
  // name_arg = Local<Name>(&name), which is &args_array[kPropertyKeyIndex].
  static_assert(PCA::kPropertyKeyIndex == 0);
  __ movq(name_arg, property_callback_info_arg);
#endif

  ExternalReference thunk_ref = ER::invoke_accessor_getter_callback();
  // Pass AccessorInfo to thunk wrapper in case profiler or side-effect
  // checking is enabled.
  Register thunk_arg = callback;

  Operand return_value_operand = Operand(rbp, FC::kReturnValueOffset);
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

void Generate_DeoptimizationEntry(MacroAssembler* masm,
                                  DeoptimizeKind deopt_kind) {
  Isolate* isolate = masm->isolate();

  // Save all xmm (simd / double) registers, they will later be copied to the
  // deoptimizer's FrameDescription.
  static constexpr int kXmmRegsSize = kSimd128Size * XMMRegister::kNumRegisters;
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
    __ movdqu(Operand(rsp, offset), xmm_reg);
  }

  // Save all general purpose registers, they will later be copied to the
  // deoptimizer's FrameDescription.
  static constexpr int kNumberOfRegisters = Register::kNumRegisters;
  for (int i = 0; i < kNumberOfRegisters; i++) {
    __ pushq(Register::from_code(i));
  }

  static constexpr int kSavedRegistersAreaSize =
      kNumberOfRegisters * kSystemPointerSize + kXmmRegsSize;
  static constexpr int kCurrentOffsetToReturnAddress = kSavedRegistersAreaSize;
  static constexpr int kCurrentOffsetToParentSP =
      kCurrentOffsetToReturnAddress + kPCOnStackSize;

  __ Store(
      ExternalReference::Create(IsolateAddressId::kCEntryFPAddress, isolate),
      rbp);

  // Get the address of the location in the code object
  // and compute the fp-to-sp delta in register arg5.
  __ movq(kCArgRegs[2], Operand(rsp, kCurrentOffsetToReturnAddress));
  // Load the fp-to-sp-delta.
  __ leaq(kCArgRegs[3], Operand(rsp, kCurrentOffsetToParentSP));
  __ subq(kCArgRegs[3], rbp);
  __ negq(kCArgRegs[3]);

  // Allocate a new deoptimizer object.
  __ PrepareCallCFunction(5);
  __ Move(rax, 0);
  Label context_check;
  __ movq(rdi, Operand(rbp, CommonFrameConstants::kContextOrFrameTypeOffset));
  __ JumpIfSmi(rdi, &context_check);
  __ movq(rax, Operand(rbp, StandardFrameConstants::kFunctionOffset));
  __ bind(&context_check);
  __ movq(kCArgRegs[0], rax);
  __ Move(kCArgRegs[1], static_cast<int>(deopt_kind));
  // Args 3 and 4 are already in the right registers.

  // On windows put the arguments on the stack (PrepareCallCFunction
  // has created space for this). On linux pass the arguments in r8.
#ifdef V8_TARGET_OS_WIN
  Register arg5 = r15;
  __ LoadAddress(arg5, ExternalReference::isolate_address());
  __ movq(Operand(rsp, 4 * kSystemPointerSize), arg5);
#else
  // r8 is kCArgRegs[4] on Linux.
  __ LoadAddress(r8, ExternalReference::isolate_address());
#endif

  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::new_deoptimizer_function(), 5);
  }
  // Preserve deoptimizer object in register rax and get the input
  // frame descriptor pointer.
  __ movq(rbx, Operand(rax, Deoptimizer::input_offset()));

  // Fill in the input registers.
  for (int i = kNumberOfRegisters - 1; i >= 0; i--) {
    int offset =
        (i * kSystemPointerSize) + FrameDescription::registers_offset();
    __ PopQuad(Operand(rbx, offset));
  }

  // Fill in the xmm (simd / double) input registers.
  int simd128_regs_offset = FrameDescription::simd128_registers_offset();
  for (int i = 0; i < XMMRegister::kNumRegisters; i++) {
    int dst_offset = i * kSimd128Size + simd128_regs_offset;
    __ movdqu(kScratchDoubleReg, Operand(rsp, i * kSimd128Size));
    __ movdqu(Operand(rbx, dst_offset), kScratchDoubleReg);
  }
  __ addq(rsp, Immediate(kXmmRegsSize));

  // Mark the stack as not iterable for the CPU profiler which won't be able to
  // walk the stack without the return address.
  __ movb(__ ExternalReferenceAsOperand(IsolateFieldId::kStackIsIterable),
          Immediate(0));

  // Remove the return address from the stack.
  __ addq(rsp, Immediate(kPCOnStackSize));

  // Compute a pointer to the unwinding limit in register rcx; that is
  // the first stack slot not part of the input frame.
  __ movq(rcx, Operand(rbx, FrameDescription::frame_size_offset()));
  __ addq(rcx, rsp);

  // Unwind the stack down to - but not including - the unwinding
  // limit and copy the contents of the activation frame to the input
  // frame description.
  __ leaq(rdx, Operand(rbx, FrameDescription::frame_content_offset()));
  Label pop_loop_header;
  __ jmp(&pop_loop_header);
  Label pop_loop;
  __ bind(&pop_loop);
  __ Pop(Operand(rdx, 0));
  __ addq(rdx, Immediate(sizeof(intptr_t)));
  __ bind(&pop_loop_header);
  __ cmpq(rcx, rsp);
  __ j(not_equal, &pop_loop);

  // Compute the output frame in the deoptimizer.
  __ pushq(rax);
  __ PrepareCallCFunction(2);
  __ movq(kCArgRegs[0], rax);
  __ LoadAddress(kCArgRegs[1], ExternalReference::isolate_address());
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::compute_output_frames_function(), 2);
  }
  __ popq(rax);
#ifdef V8_ENABLE_CET_SHADOW_STACK
  __ movq(r8, rax);
#endif  // V8_ENABLE_CET_SHADOW_STACK

  __ movq(rsp, Operand(rax, Deoptimizer::caller_frame_top_offset()));

  // Replace the current (input) frame with the output frames.
  Label outer_push_loop, inner_push_loop, outer_loop_header, inner_loop_header;
  // Outer loop state: rax = current FrameDescription**, rdx = one past the
  // last FrameDescription**.
  __ movl(rdx, Operand(rax, Deoptimizer::output_count_offset()));
  __ movq(rax, Operand(rax, Deoptimizer::output_offset()));
  __ leaq(rdx, Operand(rax, rdx, times_system_pointer_size, 0));
  __ jmp(&outer_loop_header);
  __ bind(&outer_push_loop);
  // Inner loop state: rbx = current FrameDescription*, rcx = loop index.
  __ movq(rbx, Operand(rax, 0));
  __ movq(rcx, Operand(rbx, FrameDescription::frame_size_offset()));
  __ jmp(&inner_loop_header);
  __ bind(&inner_push_loop);
  __ subq(rcx, Immediate(sizeof(intptr_t)));
  __ Push(Operand(rbx, rcx, times_1, FrameDescription::frame_content_offset()));
  __ bind(&inner_loop_header);
  __ testq(rcx, rcx);
  __ j(not_zero, &inner_push_loop);
  __ addq(rax, Immediate(kSystemPointerSize));
  __ bind(&outer_loop_header);
  __ cmpq(rax, rdx);
  __ j(below, &outer_push_loop);

  // Push pc and continuation from the last output frame.
  __ PushQuad(Operand(rbx, FrameDescription::pc_offset()));
  __ movq(rax, Operand(rbx, FrameDescription::continuation_offset()));
  // Skip pushing the continuation if it is zero. This is used as a marker for
  // wasm deopts that do not use a builtin call to finish the deopt.
  Label push_registers;
  __ testq(rax, rax);
  __ j(zero, &push_registers);
  __ Push(rax);
  __ bind(&push_registers);
  // Push the registers from the last output frame.
  for (int i = 0; i < kNumberOfRegisters; i++) {
    Register r = Register::from_code(i);
    // Do not restore rsp and kScratchRegister.
    if (r == rsp || r == kScratchRegister) continue;
    int offset =
        (i * kSystemPointerSize) + FrameDescription::registers_offset();
    __ PushQuad(Operand(rbx, offset));
  }

#ifdef V8_ENABLE_CET_SHADOW_STACK
  // Check v8_flags.cet_compatible.
  Label shadow_stack_push;
  __ cmpb(__ ExternalReferenceAsOperand(
              ExternalReference::address_of_cet_compatible_flag(),
              kScratchRegister),
          Immediate(0));
  __ j(not_equal, &shadow_stack_push);
#endif  // V8_ENABLE_CET_SHADOW_STACK

  Generate_RestoreFrameDescriptionRegisters(masm, rbx);

  __ movb(__ ExternalReferenceAsOperand(IsolateFieldId::kStackIsIterable),
          Immediate(1));

  // Return to the continuation point.
  __ ret(0);

#ifdef V8_ENABLE_CET_SHADOW_STACK
  // Push candidate return addresses for shadow stack onto the stack.
  __ bind(&shadow_stack_push);

  // push the last FrameDescription onto the stack for restoring xmm registers
  // later.
  __ pushq(rbx);

  // r8 = deoptimizer
  __ movl(kAdaptShadowStackCountRegister,
          Operand(r8, Deoptimizer::shadow_stack_count_offset()));
  __ movq(rax, Operand(r8, Deoptimizer::shadow_stack_offset()));

  Label check_more_pushes, next_push;
  __ Move(kScratchRegister, 0);
  __ jmp(&check_more_pushes, Label::kNear);
  __ bind(&next_push);
  // rax points to the start of the shadow stack array.
  __ pushq(Operand(rax, kScratchRegister, times_system_pointer_size, 0));
  __ incl(kScratchRegister);
  __ bind(&check_more_pushes);
  __ cmpl(kScratchRegister, kAdaptShadowStackCountRegister);
  __ j(not_equal, &next_push);

  // We drop 1 word from the shadow stack. It contains the return address from
  // DeoptimizationEntry.
  __ Move(rax, 1);
  __ IncsspqIfSupported(rax, kScratchRegister);

  // Now, kick off the process of getting our continuations onto the shadow
  // stack. Note that the stack has 2 extra words to be popped at the end
  // of the process:
  // 1) the kAdaptShadowStackCountRegister
  // 2) kScratchRegister
  __ movq(kScratchRegister,
          Operand(kRootRegister, IsolateData::BuiltinEntrySlotOffset(
                                     Builtin::kAdaptShadowStackForDeopt)));
  // We don't enter at the start of AdaptShadowStackForDeopt, because that
  // is designed to be called by builtin continuations in order to get
  // return addresses into those continuations on the stack. Therefore, we
  // have to make a special entry at kAdaptShadowStackDispatchFirstEntryOffset.
  __ addq(kScratchRegister,
          Immediate(kAdaptShadowStackDispatchFirstEntryOffset));
  __ jmp(kScratchRegister);

  __ int3();
#endif  // V8_ENABLE_CET_SHADOW_STACK
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
```