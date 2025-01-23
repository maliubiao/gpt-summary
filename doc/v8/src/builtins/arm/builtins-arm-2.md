Response: The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `builtins-arm.cc` file in the V8 JavaScript engine. This is the third part of a three-part file. The summary should also include an example of how it relates to JavaScript functionality.

The code snippet primarily deals with the interaction between JavaScript and WebAssembly, focusing on:

1. **Stack switching for WebAssembly calls:** This involves moving between the JavaScript stack and a dedicated WebAssembly stack.
2. **Exception handling in WebAssembly:**  Specifically, how exceptions thrown from WebAssembly are caught and handled, often resulting in the rejection of a JavaScript Promise.
3. **JSToWasm wrapper generation:** This is a crucial component for calling WebAssembly functions from JavaScript. It handles parameter passing, result retrieval, and potential stack switching.
4. **CEntry:**  The mechanism for calling C++ functions from JavaScript.
5. **Deoptimization:** The process of reverting from optimized (compiled) code back to interpreter or baseline code.
6. **Baseline and Interpreter entry points:** How the V8 engine decides whether to execute JavaScript code in the interpreter or using baseline compilation.
7. **API callbacks:**  How calls from native C++ code back into JavaScript are handled.

I should structure the summary to address these key areas and then provide a JavaScript example that illustrates the JSToWasm interaction and potentially the stack switching aspect.
这是 V8 JavaScript 引擎中 `v8/src/builtins/arm/builtins-arm.cc` 文件的第三部分，主要负责 **ARM 架构下 JavaScript 与 WebAssembly 之间的互操作，以及一些底层的 C++ 函数调用和优化相关的功能**。

以下是其功能的归纳：

**1. WebAssembly 的栈切换和异常处理：**

*   **`SwitchToAllocatedStack` 和 `SwitchBackAndReturnPromise`:**  这两个函数处理了在 JavaScript 调用 WebAssembly 时可能发生的栈切换。当 WebAssembly 函数需要挂起（例如，返回一个 Promise）时，需要切换到预先分配的 WebAssembly 栈。反之，当 WebAssembly 函数恢复执行或返回 Promise 时，需要切回 JavaScript 栈。
*   **`GenerateExceptionHandlingLandingPad`:**  定义了当 WebAssembly 代码抛出异常时，如何捕获并处理这些异常。通常，这会导致一个 JavaScript Promise 被拒绝。

**2. JSToWasm 包装器（Wrapper）：**

*   **`JSToWasmWrapperHelper`:**  这是生成 JavaScript 调用 WebAssembly 函数的包装器代码的核心函数。它负责设置调用栈帧，传递参数（包括基本类型和浮点数），调用 WebAssembly 代码，并处理返回值。它还处理了是否需要进行栈切换的情况。

**3. C 函数入口点 (`CEntry`)：**

*   **`Generate_CEntry`:**  负责生成从 JavaScript 代码调用 C++ 函数的入口点代码。它处理参数传递、设置调用栈帧、调用 C++ 函数，以及处理 C++ 函数可能抛出的异常。

**4. 栈溢出处理 (`WasmHandleStackOverflow`)：**

*   **`Generate_WasmHandleStackOverflow`:**  专门处理 WebAssembly 代码执行过程中发生的栈溢出情况。它会尝试扩展栈空间，如果无法扩展，则调用运行时函数来处理。

**5. 类型转换：**

*   **`Generate_DoubleToI`:**  实现了将 JavaScript 中的双精度浮点数转换为整数的逻辑。由于浮点数的范围和精度与整数不同，这个过程需要处理各种边界情况。

**6. API 回调 (`CallApiCallbackImpl`, `CallApiGetter`)：**

*   **`Generate_CallApiCallbackImpl`:**  生成调用 JavaScript API 回调函数的代码。这通常发生在原生 C++ 代码需要调用 JavaScript 函数时。
*   **`Generate_CallApiGetter`:**  生成调用 JavaScript API 属性访问器（getter）函数的代码。

**7. 直接 C 函数入口 (`DirectCEntry`)：**

*   **`Generate_DirectCEntry`:**  提供了一种更直接的方式从 JavaScript 调用 C++ 函数，特别用于那些可能触发垃圾回收的代码，以确保调用安全。

**8. 内存拷贝 (`MemCopyUint8Uint8`)：**

*   **`Generate_MemCopyUint8Uint8`:**  实现了一个高效的字节数组拷贝函数。

**9. 反优化入口点 (`DeoptimizationEntry_Eager`, `DeoptimizationEntry_Lazy`)：**

*   **`Generate_DeoptimizationEntry`:**  生成当 V8 引擎需要取消优化（deoptimization）代码执行时进入的代码。这会将执行状态回滚到解释器或基线编译状态。

**10. 基线或解释器入口点 (`BaselineOrInterpreterEntryAtBytecode`, `BaselineOrInterpreterEnterAtNextBytecode`, `InterpreterOnStackReplacement_ToBaseline`)：**

*   **`Generate_BaselineOrInterpreterEntry`:**  决定 JavaScript 函数应该以解释模式还是基线编译模式开始执行。它还会处理从解释器栈帧切换到基线栈帧的情况（OSR - On-Stack Replacement）。

**11. 重启帧跳转 (`RestartFrameTrampoline`)：**

*   **`Generate_RestartFrameTrampoline`:**  用于在某些情况下重启 JavaScript 函数的执行。

**与 JavaScript 的关系及示例：**

这些底层功能直接支撑着 JavaScript 与 WebAssembly 的交互和 V8 引擎的优化。以下是一个 JavaScript 示例，展示了调用 WebAssembly 函数并可能触发栈切换的情况：

```javascript
// 假设你已经加载了一个 WebAssembly 模块 instance
const wasmInstance = // ... 加载的 WebAssembly 实例

// 假设 WebAssembly 模块导出了一个名为 'fibonacci' 的函数
const fibonacciWasm = wasmInstance.exports.fibonacci;

async function runFibonacci() {
  console.log("开始调用 WebAssembly 函数");
  const result = fibonacciWasm(10);
  console.log("WebAssembly 函数返回结果:", result);
}

runFibonacci();

// 假设 WebAssembly 模块导出了一个返回 Promise 的异步函数
const asyncWasmFunction = wasmInstance.exports.asyncFunction;

async function runAsyncWasm() {
  console.log("开始调用异步 WebAssembly 函数");
  const resultPromise = asyncWasmFunction();
  console.log("异步 WebAssembly 函数返回 Promise:", resultPromise);
  const result = await resultPromise;
  console.log("异步 WebAssembly 函数 Promise 解析结果:", result);
}

runAsyncWasm();
```

在这个例子中：

*   当 `fibonacciWasm(10)` 被调用时，`JSToWasmWrapperHelper` 生成的包装器代码会被执行，它会处理参数传递并将控制权交给 WebAssembly 代码。
*   如果 `asyncWasmFunction()` 返回一个 Promise，V8 引擎可能会使用栈切换机制，在 JavaScript 栈和 WebAssembly 栈之间切换，以便处理 Promise 的挂起和恢复。`SwitchToAllocatedStack` 和 `SwitchBackAndReturnPromise` 等函数就参与了这个过程。
*   如果 WebAssembly 代码内部抛出异常，`GenerateExceptionHandlingLandingPad` 中生成的代码会捕获这个异常，并可能导致 `asyncWasmFunction()` 返回的 Promise 被拒绝。

总而言之，这部分 C++ 代码是 V8 引擎中实现 JavaScript 与 WebAssembly 高效、安全互操作的关键组成部分，同时也包含了 V8 引擎进行底层优化的重要机制。

### 提示词
```
这是目录为v8/src/builtins/arm/builtins-arm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```
e of the stack segment for
  // the stack frame iterator.
  __ EnterFrame(StackFrame::STACK_SWITCH);

  int stack_space =
      RoundUp(StackSwitchFrameConstants::kNumSpillSlots * kSystemPointerSize +
                  JSToWasmWrapperFrameConstants::kWrapperBufferSize,
              16);
  __ sub(sp, sp, Operand(stack_space));
  __ EnforceStackAlignment();

  ASSIGN_REG(new_wrapper_buffer)

  __ Move(new_wrapper_buffer, sp);
  // Copy data needed for return handling from old wrapper buffer to new one.

  __ ldr(scratch,
         MemOperand(wrapper_buffer,
                    JSToWasmWrapperFrameConstants::kWrapperBufferReturnCount));
  __ str(scratch,
         MemOperand(new_wrapper_buffer,
                    JSToWasmWrapperFrameConstants::kWrapperBufferReturnCount));
  __ ldr(
      scratch,
      MemOperand(wrapper_buffer,
                 JSToWasmWrapperFrameConstants::kWrapperBufferRefReturnCount));
  __ str(
      scratch,
      MemOperand(new_wrapper_buffer,
                 JSToWasmWrapperFrameConstants::kWrapperBufferRefReturnCount));
  __ ldr(
      scratch,
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferSigRepresentationArray));
  __ str(
      scratch,
      MemOperand(
          new_wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferSigRepresentationArray));

  __ ldr(
      scratch,
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferSigRepresentationArray +
              4));
  __ str(
      scratch,
      MemOperand(
          new_wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferSigRepresentationArray +
              4));
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
    __ Move(return_value, kReturnRegister0);
    __ LoadRoot(promise, RootIndex::kActiveSuspender);
    __ LoadTaggedField(
        promise, FieldMemOperand(promise, WasmSuspenderObject::kPromiseOffset));
  }
  __ ldr(kContextRegister,
         MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
  GetContextFromImplicitArg(masm, kContextRegister, tmp);

  ReloadParentContinuation(masm, promise, return_value, kContextRegister, tmp,
                           tmp2, tmp3);
  RestoreParentSuspender(masm, tmp, tmp2);

  if (mode == wasm::kPromise) {
    __ Move(tmp, Operand(1));
    __ str(tmp,
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
  thread_in_wasm_flag_addr = r2;

  // Unset thread_in_wasm_flag.
  __ ldr(
      thread_in_wasm_flag_addr,
      MemOperand(kRootRegister, Isolate::thread_in_wasm_flag_address_offset()));
  __ Zero(MemOperand(thread_in_wasm_flag_addr, 0));

  // The exception becomes the parameter of the RejectPromise builtin, and the
  // promise is the return value of this wrapper.
  __ Move(reason, kReturnRegister0);
  __ LoadRoot(promise, RootIndex::kActiveSuspender);
  __ LoadTaggedField(
      promise, FieldMemOperand(promise, WasmSuspenderObject::kPromiseOffset));

  DEFINE_SCOPED(tmp);
  DEFINE_SCOPED(tmp2);
  DEFINE_SCOPED(tmp3);
  __ ldr(kContextRegister,
         MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
  GetContextFromImplicitArg(masm, kContextRegister, tmp);
  ReloadParentContinuation(masm, promise, reason, kContextRegister, tmp, tmp2,
                           tmp3);
  RestoreParentSuspender(masm, tmp, tmp2);

  __ Move(tmp, Operand(1));
  __ str(tmp,
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
  __ ldr(implicit_arg,
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
    __ str(new_wrapper_buffer,
           MemOperand(fp, JSToWasmWrapperFrameConstants::kWrapperBufferOffset));
    if (stack_switch) {
      __ str(implicit_arg,
             MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
      DEFINE_SCOPED(scratch)
      __ ldr(
          scratch,
          MemOperand(original_fp,
                     JSToWasmWrapperFrameConstants::kResultArrayParamOffset));
      __ str(scratch,
             MemOperand(fp, StackSwitchFrameConstants::kResultArrayOffset));
    }
  }
  {
    DEFINE_SCOPED(result_size);
    __ ldr(result_size,
           MemOperand(wrapper_buffer, JSToWasmWrapperFrameConstants::
                                          kWrapperBufferStackReturnBufferSize));
    __ sub(sp, sp, Operand(result_size, LSL, kSystemPointerSizeLog2));
  }

  __ str(
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
    __ ldr(params_start,
           MemOperand(wrapper_buffer,
                      JSToWasmWrapperFrameConstants::kWrapperBufferParamStart));
    {
      // Push stack parameters on the stack.
      DEFINE_SCOPED(params_end);
      __ ldr(params_end,
             MemOperand(wrapper_buffer,
                        JSToWasmWrapperFrameConstants::kWrapperBufferParamEnd));
      DEFINE_SCOPED(last_stack_param);

      __ add(last_stack_param, params_start, Operand(stack_params_offset));
      Label loop_start;
      __ bind(&loop_start);

      Label finish_stack_params;
      __ cmp(last_stack_param, params_end);
      __ b(ge, &finish_stack_params);

      // Push parameter
      {
        DEFINE_SCOPED(scratch);
        __ ldr(scratch, MemOperand(params_end, -kSystemPointerSize, PreIndex));
        __ push(scratch);
      }
      __ jmp(&loop_start);

      __ bind(&finish_stack_params);
    }

    size_t next_offset = 0;
    for (size_t i = 1; i < arraysize(wasm::kGpParamRegisters); i++) {
      // Check that {params_start} does not overlap with any of the parameter
      // registers, so that we don't overwrite it by accident with the loads
      // below.
      DCHECK_NE(params_start, wasm::kGpParamRegisters[i]);
      __ ldr(wasm::kGpParamRegisters[i], MemOperand(params_start, next_offset));
      next_offset += kSystemPointerSize;
    }

    next_offset += param_padding;
    for (size_t i = 0; i < arraysize(wasm::kFpParamRegisters); i++) {
      __ vldr(wasm::kFpParamRegisters[i],
              MemOperand(params_start, next_offset));
      next_offset += kDoubleSize;
    }
    DCHECK_EQ(next_offset, stack_params_offset);
  }

  {
    DEFINE_SCOPED(thread_in_wasm_flag_addr);
    __ ldr(thread_in_wasm_flag_addr,
           MemOperand(kRootRegister,
                      Isolate::thread_in_wasm_flag_address_offset()));
    DEFINE_SCOPED(scratch);
    __ Move(scratch, Operand(1));
    __ str(scratch, MemOperand(thread_in_wasm_flag_addr, 0));
  }

  __ Zero(MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset));
  {
    DEFINE_SCOPED(call_target);
    __ ldr(call_target,
           MemOperand(wrapper_buffer,
                      JSToWasmWrapperFrameConstants::kWrapperBufferCallTarget));
    __ CallWasmCodePointer(call_target);
  }

  regs.ResetExcept();
  // The wrapper_buffer has to be in r2 as the correct parameter register.
  regs.Reserve(kReturnRegister0, kReturnRegister1);
  ASSIGN_PINNED(wrapper_buffer, r2);
  {
    DEFINE_SCOPED(thread_in_wasm_flag_addr);
    __ ldr(thread_in_wasm_flag_addr,
           MemOperand(kRootRegister,
                      Isolate::thread_in_wasm_flag_address_offset()));
    __ Zero(MemOperand(thread_in_wasm_flag_addr, 0));
  }

  __ ldr(wrapper_buffer,
         MemOperand(fp, JSToWasmWrapperFrameConstants::kWrapperBufferOffset));

  __ vstr(wasm::kFpReturnRegisters[0],
          MemOperand(
              wrapper_buffer,
              JSToWasmWrapperFrameConstants::kWrapperBufferFPReturnRegister1));
  __ vstr(wasm::kFpReturnRegisters[1],
          MemOperand(
              wrapper_buffer,
              JSToWasmWrapperFrameConstants::kWrapperBufferFPReturnRegister2));
  __ str(wasm::kGpReturnRegisters[0],
         MemOperand(
             wrapper_buffer,
             JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister1));
  __ str(wasm::kGpReturnRegisters[1],
         MemOperand(
             wrapper_buffer,
             JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister2));
  // Call the return value builtin with
  // r0: wasm instance.
  // r1: the result JSArray for multi-return.
  // r2: pointer to the byte buffer which contains all parameters.
  if (stack_switch) {
    __ ldr(r1, MemOperand(fp, StackSwitchFrameConstants::kResultArrayOffset));
    __ ldr(r0, MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
  } else {
    __ ldr(r1, MemOperand(
                   fp, JSToWasmWrapperFrameConstants::kResultArrayParamOffset));
    __ ldr(r0,
           MemOperand(fp, JSToWasmWrapperFrameConstants::kImplicitArgOffset));
  }
  Register scratch = r3;
  GetContextFromImplicitArg(masm, r0, scratch);

  __ CallBuiltin(Builtin::kJSToWasmHandleReturns);

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
  __ add(sp, sp, Operand(2 * kSystemPointerSize));
  __ Jump(lr);

  // Catch handler for the stack-switching wrapper: reject the promise with the
  // thrown exception.
  if (mode == wasm::kPromise) {
    // Block literal pool emission whilst taking the position of the handler
    // entry.
    Assembler::BlockConstPoolScope block_const_pool(masm);
    GenerateExceptionHandlingLandingPad(masm, regs, &return_promise);
  }
  // Emit constant pool now.
  __ CheckConstPool(true, false);
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

static constexpr Register kOldSPRegister = r7;
static constexpr Register kSwitchFlagRegister = r8;

void SwitchToTheCentralStackIfNeeded(MacroAssembler* masm, Register argc_input,
                                     Register target_input,
                                     Register argv_input) {
  using ER = ExternalReference;

  __ Move(kOldSPRegister, sp);

  // Using r2 & r3 as temporary registers, because they will be rewritten
  // before exiting to native code anyway.

  ER on_central_stack_flag_loc = ER::Create(
      IsolateAddressId::kIsOnCentralStackFlagAddress, masm->isolate());
  __ Move(kSwitchFlagRegister, on_central_stack_flag_loc);
  __ ldrb(kSwitchFlagRegister, MemOperand(kSwitchFlagRegister));

  Label do_not_need_to_switch;
  __ cmp(kSwitchFlagRegister, Operand(0));
  __ b(ne, &do_not_need_to_switch);

  // Switch to central stack.

  Register central_stack_sp = r2;
  DCHECK(!AreAliased(central_stack_sp, argc_input, argv_input, target_input));
  {
    __ Push(argc_input);
    __ Push(target_input);
    __ Push(argv_input);
    __ PrepareCallCFunction(2);
    __ Move(kCArgRegs[0], ER::isolate_address());
    __ Move(kCArgRegs[1], kOldSPRegister);
    __ CallCFunction(ER::wasm_switch_to_the_central_stack(), 2,
                     SetIsolateDataSlots::kNo);
    __ Move(central_stack_sp, kReturnRegister0);
    __ Pop(argv_input);
    __ Pop(target_input);
    __ Pop(argc_input);
  }

  static constexpr int kReturnAddressSlotOffset = 1 * kSystemPointerSize;
  static constexpr int kPadding = 1 * kSystemPointerSize;
  __ sub(sp, central_stack_sp, Operand(kReturnAddressSlotOffset + kPadding));
  __ EnforceStackAlignment();

  // Update the sp saved in the frame.
  // It will be used to calculate the callee pc during GC.
  // The pc is going to be on the new stack segment, so rewrite it here.
  __ add(central_stack_sp, sp, Operand(kSystemPointerSize));
  __ str(central_stack_sp, MemOperand(fp, ExitFrameConstants::kSPOffset));

  __ bind(&do_not_need_to_switch);
}

void SwitchFromTheCentralStackIfNeeded(MacroAssembler* masm) {
  using ER = ExternalReference;

  Label no_stack_change;

  __ cmp(kSwitchFlagRegister, Operand(0));
  __ b(ne, &no_stack_change);

  {
    __ Push(kReturnRegister0, kReturnRegister1);
    __ PrepareCallCFunction(1);
    __ Move(kCArgRegs[0], ER::isolate_address());
    __ CallCFunction(ER::wasm_switch_from_the_central_stack(), 1,
                     SetIsolateDataSlots::kNo);
    __ Pop(kReturnRegister0, kReturnRegister1);
  }

  __ Move(sp, kOldSPRegister);

  __ bind(&no_stack_change);
}

}  // namespace

#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_CEntry(MacroAssembler* masm, int result_size,
                               ArgvMode argv_mode, bool builtin_exit_frame,
                               bool switch_to_central_stack) {
  // Called from JavaScript; parameters are on stack as if calling JS function.
  // r0: number of arguments including receiver
  // r1: pointer to C++ function
  // fp: frame pointer  (restored after C call)
  // sp: stack pointer  (restored as callee's sp after C call)
  // cp: current context  (C callee-saved)

  // If argv_mode == ArgvMode::kRegister:
  // r2: pointer to the first argument

  using ER = ExternalReference;

  // Move input arguments to more convenient registers.
  static constexpr Register argc_input = r0;
  static constexpr Register target_fun = r5;  // C callee-saved
  static constexpr Register argv = r1;
  static constexpr Register scratch = r3;
  static constexpr Register argc_sav = r4;  // C callee-saved

  __ mov(target_fun, Operand(r1));

  if (argv_mode == ArgvMode::kRegister) {
    // Move argv into the correct register.
    __ mov(argv, Operand(r2));
  } else {
    // Compute the argv pointer in a callee-saved register.
    __ add(argv, sp, Operand(argc_input, LSL, kPointerSizeLog2));
    __ sub(argv, argv, Operand(kPointerSize));
  }

  // Enter the exit frame that transitions from JavaScript to C++.
  FrameScope scope(masm, StackFrame::MANUAL);
  __ EnterExitFrame(
      scratch, 0,
      builtin_exit_frame ? StackFrame::BUILTIN_EXIT : StackFrame::EXIT);

  // Store a copy of argc in callee-saved registers for later.
  __ mov(argc_sav, Operand(argc_input));

  // r0: number of arguments including receiver
  // r4: number of arguments including receiver  (C callee-saved)
  // r1: pointer to the first argument
  // r5: pointer to builtin function  (C callee-saved)

#if V8_HOST_ARCH_ARM
  int frame_alignment = MacroAssembler::ActivationFrameAlignment();
  int frame_alignment_mask = frame_alignment - 1;
  if (v8_flags.debug_code) {
    if (frame_alignment > kPointerSize) {
      Label alignment_as_expected;
      DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
      __ tst(sp, Operand(frame_alignment_mask));
      __ b(eq, &alignment_as_expected);
      // Don't use Check here, as it will call Runtime_Abort re-entering here.
      __ stop();
      __ bind(&alignment_as_expected);
    }
  }
#endif

#if V8_ENABLE_WEBASSEMBLY
  if (switch_to_central_stack) {
    SwitchToTheCentralStackIfNeeded(masm, argc_input, target_fun, argv);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // Call C built-in.
  // r0 = argc, r1 = argv, r2 = isolate, r5 = target_fun
  DCHECK_EQ(kCArgRegs[0], argc_input);
  DCHECK_EQ(kCArgRegs[1], argv);
  __ Move(kCArgRegs[2], ER::isolate_address());
  __ StoreReturnAddressAndCall(target_fun);

  // Result returned in r0 or r1:r0 - do not destroy these registers!

#if V8_ENABLE_WEBASSEMBLY
  if (switch_to_central_stack) {
    SwitchFromTheCentralStackIfNeeded(masm);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // Check result for exception sentinel.
  Label exception_returned;
  __ CompareRoot(r0, RootIndex::kException);
  __ b(eq, &exception_returned);

  // Check that there is no exception, otherwise we
  // should have returned the exception sentinel.
  if (v8_flags.debug_code) {
    Label okay;
    ER exception_address =
        ER::Create(IsolateAddressId::kExceptionAddress, masm->isolate());
    __ ldr(scratch, __ ExternalReferenceAsOperand(exception_address, no_reg));
    __ CompareRoot(scratch, RootIndex::kTheHoleValue);
    // Cannot use check here as it attempts to generate call into runtime.
    __ b(eq, &okay);
    __ stop();
    __ bind(&okay);
  }

  // Exit C frame and return.
  // r0:r1: result
  // sp: stack pointer
  // fp: frame pointer
  // r4: still holds argc (C caller-saved).
  __ LeaveExitFrame(scratch);
  if (argv_mode == ArgvMode::kStack) {
    DCHECK(!AreAliased(scratch, argc_sav));
    __ add(sp, sp, Operand(argc_sav, LSL, kPointerSizeLog2));
  }

  __ mov(pc, lr);

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

  // Ask the runtime for help to determine the handler. This will set r0 to
  // contain the current exception, don't clobber it.
  {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ PrepareCallCFunction(3, 0);
    __ mov(kCArgRegs[0], Operand(0));
    __ mov(kCArgRegs[1], Operand(0));
    __ Move(kCArgRegs[2], ER::isolate_address());
    __ CallCFunction(ER::Create(Runtime::kUnwindAndFindExceptionHandler), 3,
                     SetIsolateDataSlots::kNo);
  }

  // Retrieve the handler context, SP and FP.
  __ Move(cp, pending_handler_context_address);
  __ ldr(cp, MemOperand(cp));
  __ Move(sp, pending_handler_sp_address);
  __ ldr(sp, MemOperand(sp));
  __ Move(fp, pending_handler_fp_address);
  __ ldr(fp, MemOperand(fp));

  // If the handler is a JS frame, restore the context to the frame. Note that
  // the context will be set to (cp == 0) for non-JS frames.
  __ cmp(cp, Operand(0));
  __ str(cp, MemOperand(fp, StandardFrameConstants::kContextOffset), ne);

  // Clear c_entry_fp, like we do in `LeaveExitFrame`.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, masm->isolate());
  __ mov(scratch, Operand::Zero());
  __ str(scratch, __ ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  // Compute the handler entry address and jump to it.
  ConstantPoolUnavailableScope constant_pool_unavailable(masm);
  __ ldr(scratch, __ ExternalReferenceAsOperand(
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
    __ sub(kCArgRegs[2], frame_base, kCArgRegs[1]);
    // On Arm we need preserve rbp value somewhere before entering
    // INTERNAL frame later. It will be placed on the stack as an argument.
    __ mov(kCArgRegs[0], fp);
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ push(kCArgRegs[3]);
    __ PrepareCallCFunction(5);
    __ str(kCArgRegs[0], MemOperand(sp, 0 * kPointerSize));  // current_fp.
    __ Move(kCArgRegs[0], ER::isolate_address());
    __ CallCFunction(ER::wasm_grow_stack(), 5);
    __ pop(gap);
    DCHECK_NE(kReturnRegister0, gap);
  }
  Label call_runtime;
  // wasm_grow_stack returns zero if it cannot grow a stack.
  __ cmp(kReturnRegister0, Operand(0));
  __ b(eq, &call_runtime);

  // Calculate old FP - SP offset to adjust FP accordingly to new SP.
  __ sub(fp, fp, sp);
  __ add(fp, fp, kReturnRegister0);
  __ mov(sp, kReturnRegister0);
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ mov(scratch,
           Operand(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
    __ str(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));
  }
  __ Ret();

  __ bind(&call_runtime);
  // If wasm_grow_stack returns zero interruption or stack overflow
  // should be handled by runtime call.
  {
    __ ldr(kWasmImplicitArgRegister,
           MemOperand(fp, WasmFrameConstants::kWasmInstanceDataOffset));
    __ LoadTaggedField(
        cp, FieldMemOperand(kWasmImplicitArgRegister,
                            WasmTrustedInstanceData::kNativeContextOffset));
    FrameScope scope(masm, StackFrame::MANUAL);
    __ EnterFrame(StackFrame::INTERNAL);
    __ SmiTag(gap);
    __ push(gap);
    __ CallRuntime(Runtime::kWasmStackGuard);
    __ LeaveFrame(StackFrame::INTERNAL);
    __ Ret();
  }
}
#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_DoubleToI(MacroAssembler* masm) {
  Label negate, done;

  HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
  UseScratchRegisterScope temps(masm);
  Register result_reg = r7;
  Register double_low = GetRegisterThatIsNotOneOf(result_reg);
  Register double_high = GetRegisterThatIsNotOneOf(result_reg, double_low);
  LowDwVfpRegister double_scratch = temps.AcquireLowD();

  // Save the old values from these temporary registers on the stack.
  __ Push(result_reg, double_high, double_low);

  // Account for saved regs.
  const int kArgumentOffset = 3 * kPointerSize;

  MemOperand input_operand(sp, kArgumentOffset);
  MemOperand result_operand = input_operand;

  // Load double input.
  __ vldr(double_scratch, input_operand);
  __ vmov(double_low, double_high, double_scratch);
  // Try to convert with a FPU convert instruction. This handles all
  // non-saturating cases.
  __ TryInlineTruncateDoubleToI(result_reg, double_scratch, &done);

  Register scratch = temps.Acquire();
  __ Ubfx(scratch, double_high, HeapNumber::kExponentShift,
          HeapNumber::kExponentBits);
  // Load scratch with exponent - 1. This is faster than loading
  // with exponent because Bias + 1 = 1024 which is an *ARM* immediate value.
  static_assert(HeapNumber::kExponentBias + 1 == 1024);
  __ sub(scratch, scratch, Operand(HeapNumber::kExponentBias + 1));
  // If exponent is greater than or equal to 84, the 32 less significant
  // bits are 0s (2^84 = 1, 52 significant bits, 32 uncoded bits),
  // the result is 0.
  // Compare exponent with 84 (compare exponent - 1 with 83). If the exponent is
  // greater than this, the conversion is out of range, so return zero.
  __ cmp(scratch, Operand(83));
  __ mov(result_reg, Operand::Zero(), LeaveCC, ge);
  __ b(ge, &done);

  // If we reach this code, 30 <= exponent <= 83.
  // `TryInlineTruncateDoubleToI` above will have truncated any double with an
  // exponent lower than 30.
  if (v8_flags.debug_code) {
    // Scratch is exponent - 1.
    __ cmp(scratch, Operand(30 - 1));
    __ Check(ge, AbortReason::kUnexpectedValue);
  }

  // We don't have to handle cases where 0 <= exponent <= 20 for which we would
  // need to shift right the high part of the mantissa.
  // Scratch contains exponent - 1.
  // Load scratch with 52 - exponent (load with 51 - (exponent - 1)).
  __ rsb(scratch, scratch, Operand(51), SetCC);

  // 52 <= exponent <= 83, shift only double_low.
  // On entry, scratch contains: 52 - exponent.
  __ rsb(scratch, scratch, Operand::Zero(), LeaveCC, ls);
  __ mov(result_reg, Operand(double_low, LSL, scratch), LeaveCC, ls);
  __ b(ls, &negate);

  // 21 <= exponent <= 51, shift double_low and double_high
  // to generate the result.
  __ mov(double_low, Operand(double_low, LSR, scratch));
  // Scratch contains: 52 - exponent.
  // We needs: exponent - 20.
  // So we use: 32 - scratch = 32 - 52 + exponent = exponent - 20.
  __ rsb(scratch, scratch, Operand(32));
  __ Ubfx(result_reg, double_high, 0, HeapNumber::kMantissaBitsInTopWord);
  // Set the implicit 1 before the mantissa part in double_high.
  __ orr(result_reg, result_reg,
         Operand(1 << HeapNumber::kMantissaBitsInTopWord));
  __ orr(result_reg, double_low, Operand(result_reg, LSL, scratch));

  __ bind(&negate);
  // If input was positive, double_high ASR 31 equals 0 and
  // double_high LSR 31 equals zero.
  // New result = (result eor 0) + 0 = result.
  // If the input was negative, we have to negate the result.
  // Input_high ASR 31 equals 0xFFFFFFFF and double_high LSR 31 equals 1.
  // New result = (result eor 0xFFFFFFFF) + 1 = 0 - result.
  __ eor(result_reg, result_reg, Operand(double_high, ASR, 31));
  __ add(result_reg, result_reg, Operand(double_high, LSR, 31));

  __ bind(&done);
  __ str(result_reg, result_operand);

  // Restore registers corrupted in this routine and return.
  __ Pop(result_reg, double_high, double_low);
  __ Ret();
}

void Builtins::Generate_CallApiCallbackImpl(MacroAssembler* masm,
                                            CallApiCallbackMode mode) {
  // ----------- S t a t e -------------
  // CallApiCallbackMode::kOptimizedNoProfiling/kOptimized modes:
  //  -- r1                  : api function address
  // Both modes:
  //  -- r2                  : arguments count (not including the receiver)
  //  -- r3                  : FunctionTemplateInfo
  //  -- r0                  : holder
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
  Register scratch = r4;

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
  //   sp[1 * kSystemPointerSize]: kHolder   <= FCA::implicit_args_
  //   sp[2 * kSystemPointerSize]: kIsolate
  //   sp[3 * kSystemPointerSize]: kContext
  //   sp[4 * kSystemPointerSize]: undefined (kReturnValue)
  //   sp[5 * kSystemPointerSize]: kTarget
  //   sp[6 * kSystemPointerSize]: undefined (kNewTarget)
  // Existing state:
  //   sp[7 * kSystemPointerSize]:            <= FCA:::values_

  __ StoreRootRelative(IsolateData::topmost_script_having_context_offset(),
                       topmost_script_having_context);

  if (mode == CallApiCallbackMode::kGeneric) {
    api_function_address = ReassignRegister(topmost_script_having_context);
  }

  // Reserve space on the stack.
  __ AllocateStackSpace(FCA::kArgsLength * kSystemPointerSize);

  // kHolder.
  __ str(holder, MemOperand(sp, FCA::kHolderIndex * kSystemPointerSize));

  // kIsolate.
  __ Move(scratch, ER::isolate_address());
  __ str(scratch, MemOperand(sp, FCA::kIsolateIndex * kSystemPointerSize));

  // kContext.
  __ str(cp, MemOperand(sp, FCA::kContextIndex * kSystemPointerSize));

  // kReturnValue.
  __ LoadRoot(scratch, RootIndex::kUndefinedValue);
  __ str(scratch, MemOperand(sp, FCA::kReturnValueIndex * kSystemPointerSize));

  // kTarget.
  __ str(func_templ, MemOperand(sp, FCA::kTargetIndex * kSystemPointerSize));

  // kNewTarget.
  __ str(scratch, MemOperand(sp, FCA::kNewTargetIndex * kSystemPointerSize));

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  if (mode == CallApiCallbackMode::kGeneric) {
    __ ldr(
        api_function_address,
        FieldMemOperand(func_templ,
                        FunctionTemplateInfo::kMaybeRedirectedCallbackOffset));
  }
  __ EnterExitFrame(scratch, FC::getExtraSlotsCountFrom<ExitFrameConstants>(),
                    StackFrame::API_CALLBACK_EXIT);

  MemOperand argc_operand = MemOperand(fp, FC::kFCIArgcOffset);
  {
    ASM_CODE_COMMENT_STRING(masm, "Initialize v8::FunctionCallbackInfo");
    // FunctionCallbackInfo::length_.
    // TODO(ishell): pass JSParameterCount(argc) to simplify things on the
    // caller end.
    __ str(argc, argc_operand);

    // FunctionCallbackInfo::implicit_args_.
    __ add(scratch, fp, Operand(FC::kImplicitArgsArrayOffset));
    __ str(scratch, MemOperand(fp, FC::kFCIImplicitArgsOffset));

    // FunctionCallbackInfo::values_ (points at JS arguments on the stack).
    __ add(scratch, fp, Operand(FC::kFirstArgumentOffset));
    __ str(scratch, MemOperand(fp, FC::kFCIValuesOffset));
  }

  __ RecordComment("v8::FunctionCallback's argument.");
  __ add(function_callback_info_arg, fp,
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
  //  -- r1                  : receiver
  //  -- r3                  : accessor info
  //  -- r0                  : holder
  // -----------------------------------

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

  Register name_arg = kCArgRegs[0];
  Register property_callback_info_arg = kCArgRegs[1];

  Register api_function_address = r2;
  Register receiver = ApiGetterDescriptor::ReceiverRegister();
  Register holder = ApiGetterDescriptor::HolderRegister();
  Register callback = ApiGetterDescriptor::CallbackRegister();
  Register scratch = r4;
  Register smi_zero = r5;

  DCHECK(!AreAliased(receiver, holder, callback, scratch, smi_zero));

  __ ldr(scratch, FieldMemOperand(callback, AccessorInfo::kDataOffset));
  __ Push(receiver, scratch);  // kThisIndex, kDataIndex
  __ LoadRoot(scratch, RootIndex::kUndefinedValue);
  __ Move(smi_zero, Smi::zero());
  __ Push(scratch, smi_zero);  // kReturnValueIndex, kHolderV2Index
  __ Move(scratch, ER::isolate_address());
  __ Push(scratch, holder);  // kIsolateIndex, kHolderIndex

  __ ldr(name_arg, FieldMemOperand(callback, AccessorInfo::kNameOffset));
  static_assert(kDontThrow == 0);
  __ Push(smi_zero, name_arg);  // should_throw_on_error -> kDontThrow, name

  __ RecordComment("Load api_function_address");
  __ ldr(api_function_address,
         FieldMemOperand(callback, AccessorInfo::kMaybeRedirectedGetterOffset));

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  __ EnterExitFrame(scratch, FC::getExtraSlotsCountFrom<ExitFrameConstants>(),
                    StackFrame::API_ACCESSOR_EXIT);

  __ RecordComment("Create v8::PropertyCallbackInfo object on the stack.");
  // property_callback_info_arg = v8::PropertyCallbackInfo&
  __ add(property_callback_info_arg, fp, Operand(FC::kArgsArrayOffset));

  DCHECK(!AreAliased(api_function_address, property_callback_info_arg, name_arg,
                     callback, scratch));

#ifdef V8_ENABLE_DIRECT_HANDLE
  // name_arg = Local<Name>(name), name value was pushed to GC-ed stack space.
  // |name_arg| is already initialized above.
#else
  // name_arg = Local<Name>(&name), which is &args_array[kPropertyKeyIndex].
  static_assert(PCA::kPropertyKeyIndex == 0);
  __ mov(name_arg, property_callback_info_arg);
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

  __ str(lr, MemOperand(sp, 0));  // Store the return address.
  __ blx(ip);                     // Call the C++ function.
  __ ldr(pc, MemOperand(sp, 0));  // Return to calling code.
}

void Builtins::Generate_MemCopyUint8Uint8(MacroAssembler* masm) {
  Register dest = r0;
  Register src = r1;
  Register chars = r2;
  Register temp1 = r3;
  Label less_4;

  {
    UseScratchRegisterScope temps(masm);
    Register temp2 = temps.Acquire();
    Label loop;

    __ bic(temp2, chars, Operand(0x3), SetCC);
    __ b(&less_4, eq);
    __ add(temp2, dest, temp2);

    __ bind(&loop);
    __ ldr(temp1, MemOperand(src, 4, PostIndex));
    __ str(temp1, MemOperand(dest, 4, PostIndex));
    __ cmp(dest, temp2);
    __ b(&loop, ne);
  }

  __ bind(&less_4);
  __ mov(chars, Operand(chars, LSL, 31), SetCC);
  // bit0 => Z (ne), bit1 => C (cs)
  __ ldrh(temp1, MemOperand(src, 2, PostIndex), cs);
  __ strh(temp1, MemOperand(dest, 2, PostIndex), cs);
  __ ldrb(temp1, MemOperand(src), ne);
  __ strb(temp1, MemOperand(dest), ne);
  __ Ret();
}

namespace {

// This code tries to be close to ia32 code so that any changes can be
// easily ported.
void Generate_DeoptimizationEntry(MacroAssembler* masm,
                                  DeoptimizeKind deopt_kind) {
  Isolate* isolate = masm->isolate();

  // Note: This is an overapproximation; we always reserve space for 32 double
  // registers, even though the actual CPU may only support 16. In the latter
  // case, SaveFPRegs and RestoreFPRegs still use 32 stack slots, but only fill
  // 16.
  static constexpr int kDoubleRegsSize =
      kDoubleSize * DwVfpRegister::kNumRegisters;

  // Save all allocatable VFP registers before messing with them.
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ SaveFPRegs(sp, scratch);
  }

  // Save all general purpose registers before messing with them.
  static constexpr int kNumberOfRegisters = Register::kNumRegisters;
  static_assert(kNumberOfRegisters == 16);

  // Everything but pc, lr and ip which will be saved but not restored.
  RegList restored_regs = kJSCallerSaved | kCalleeSaved | RegList{ip};

  // Push all 16 registers (needed to populate FrameDescription::registers_).
  // TODO(v8:1588): Note that using pc with stm is deprecated, so we should
  // perhaps handle this a bit differently.
  __ stm(db_w, sp, restored_regs | RegList{sp, lr, pc});

  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ Move(scratch, ExternalReference::Create(
                         IsolateAddressId::kCEntryFPAddress, isolate));
    __ str(fp, MemOperand(scratch));
  }

  static constexpr int kSavedRegistersAreaSize =
      (kNumberOfRegisters * kPointerSize) + kDoubleRegsSize;

  // Get the address of the location in the code object (r3) (return
  // address for lazy deoptimization) and compute the fp-to-sp delta in
  // register r4.
  __ mov(r2, lr);
  __ add(r3, sp, Operand(kSavedRegistersAreaSize));
  __ sub(r3, fp, r3);

  // Allocate a new deoptimizer object.
  // Pass four arguments in r0 to r3 and fifth argument on stack.
  __ PrepareCallCFunction(5);
  __ mov(r0, Operand(0));
  Label context_check;
  __ ldr(r1, MemOperand(fp, CommonFrameConstants::kContextOrFrameTypeOffset));
  __ JumpIfSmi(r1, &context_check);
  __ ldr(r0, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ bind(&context_check);
  __ mov(r1, Operand(static_cast<int>(deopt_kind)));
  // r2: code address or 0 already loaded.
  // r3: Fp-to-sp delta already loaded.
  __ Move(r4, ExternalReference::isolate_address());
  __ str(r4, MemOperand(sp, 0 * kPointerSize));  // Isolate.
  // Call Deoptimizer::New().
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::new_deoptimizer_function(), 5);
  }

  // Preserve "deoptimizer" object in register r0 and get the input
  // frame descriptor pointer to r1 (deoptimizer->input_);
  __ ldr(r1, MemOperand(r0, Deoptimizer::input_offset()));

  // Copy core registers into FrameDescription::registers_.
  DCHECK_EQ(Register::kNumRegisters, kNumberOfRegisters);
  for (int i = 0; i < kNumberOfRegisters; i++) {
    int offset = (i * kPointerSize) + FrameDescription::registers_offset();
    __ ldr(r2, MemOperand(sp, i * kPointerSize));
    __ str(r2, MemOperand(r1, offset));
  }

  // Copy simd128 / double registers to the FrameDescription.
  static constexpr int kSimd128RegsOffset =
      FrameDescription::simd128_registers_offset();
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    Register src_location = r4;
    __ add(src_location, sp, Operand(kNumberOfRegisters * kPointerSize));
    __ RestoreFPRegs(src_location, scratch);

    Register dst_location = r4;
    __ add(dst_location, r1, Operand(kSimd128RegsOffset));
    __ SaveFPRegsToHeap(dst_location, scratch);
  }

  // Mark the stack as not iterable for the CPU profiler which won't be able to
  // walk the stack without the return address.
  {
    UseScratchRegisterScope temps(masm);
    Register is_iterable = temps.Acquire();
    Register zero = r4;
    __ LoadIsolateField(is_iterable, IsolateFieldId::kStackIsIterable);
    __ mov(zero, Operand(0));
    __ strb(zero, MemOperand(is_iterable));
  }

  // Remove the saved registers from the stack.
  __ add(sp, sp, Operand(kSavedRegistersAreaSize));

  // Compute a pointer to the unwinding limit in register r2; that is
  // the first stack slot not part of the input frame.
  __ ldr(r2, MemOperand(r1, FrameDescription::frame_size_offset()));
  __ add(r2, r2, sp);

  // Unwind the stack down to - but not including - the unwinding
  // limit and copy the contents of the activation frame to the input
  // frame description.
  __ add(r3, r1, Operand(FrameDescription::frame_content_offset()));
  Label pop_loop;
  Label pop_loop_header;
  __ b(&pop_loop_header);
  __ bind(&pop_loop);
  __ pop(r4);
  __ str(r4, MemOperand(r3, 0));
  __ add(r3, r3, Operand(sizeof(uint32_t)));
  __ bind(&pop_loop_header);
  __ cmp(r2, sp);
  __ b(ne, &pop_loop);

  // Compute the output frame in the deoptimizer.
  __ push(r0);  // Preserve deoptimizer object across call.
  // r0: deoptimizer object; r1: scratch.
  __ PrepareCallCFunction(1);
  // Call Deoptimizer::ComputeOutputFrames().
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::compute_output_frames_function(), 1);
  }
  __ pop(r0);  // Restore deoptimizer object (class Deoptimizer).

  __ ldr(sp, MemOperand(r0, Deoptimizer::caller_frame_top_offset()));

  // Replace the current (input) frame with the output frames.
  Label outer_push_loop, inner_push_loop, outer_loop_header, inner_loop_header;
  // Outer loop state: r4 = current "FrameDescription** output_",
  // r1 = one past the last FrameDescription**.
  __ ldr(r1, MemOperand(r0, Deoptimizer::output_count_offset()));
  __ ldr(r4, MemOperand(r0, Deoptimizer::output_offset()));  // r4 is output_.
  __ add(r1, r4, Operand(r1, LSL, 2));
  __ jmp(&outer_loop_header);
  __ bind(&outer_push_loop);
  // Inner loop state: r2 = current FrameDescription*, r3 = loop index.
  __ ldr(r2, MemOperand(r4, 0));  // output_[ix]
  __ ldr(r3, MemOperand(r2, FrameDescription::frame_size_offset()));
  __ jmp(&inner_loop_header);
  __ bind(&inner_push_loop);
  __ sub(r3, r3, Operand(sizeof(uint32_t)));
  __ add(r6, r2, Operand(r3));
  __ ldr(r6, MemOperand(r6, FrameDescription::frame_content_offset()));
  __ push(r6);
  __ bind(&inner_loop_header);
  __ cmp(r3, Operand::Zero());
  __ b(ne, &inner_push_loop);  // test for gt?
  __ add(r4, r4, Operand(kPointerSize));
  __ bind(&outer_loop_header);
  __ cmp(r4, r1);
  __ b(lt, &outer_push_loop);

  __ ldr(r1, MemOperand(r0, Deoptimizer::input_offset()));

  // State:
  // r1: Deoptimizer::input_ (FrameDescription*).
  // r2: The last output FrameDescription pointer (FrameDescription*).

  // Restore double registers from the output frame description.
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    Register src_location = r6;
    __ add(src_location, r2, Operand(kSimd128RegsOffset));
    __ RestoreFPRegsFromHeap(src_location, scratch);
  }

  // Push pc and continuation from the last output frame.
  __ ldr(r6, MemOperand(r2, FrameDescription::pc_offset()));
  __ push(r6);
  __ ldr(r6, MemOperand(r2, FrameDescription::continuation_offset()));
  __ push(r6);

  // Push the registers from the last output frame.
  for (int i = kNumberOfRegisters - 1; i >= 0; i--) {
    int offset = (i * kPointerSize) + FrameDescription::registers_offset();
    __ ldr(r6, MemOperand(r2, offset));
    __ push(r6);
  }

  // Restore the registers from the stack.
  __ ldm(ia_w, sp, restored_regs);  // all but pc registers.

  {
    UseScratchRegisterScope temps(masm);
    Register is_iterable = temps.Acquire();
    Register one = r4;
    __ push(one);  // Save the value from the output FrameDescription.
    __ LoadIsolateField(is_iterable, IsolateFieldId::kStackIsIterable);
    __ mov(one, Operand(1));
    __ strb(one, MemOperand(is_iterable));
    __ pop(one);  // Restore the value from the output FrameDescription.
  }

  // Remove sp, lr and pc.
  __ Drop(3);
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ pop(scratch);  // get continuation, leave pc on stack
    __ pop(lr);
    Label end;
    __ cmp(scratch, Operand::Zero());
    __ b(eq, &end);
    __ Jump(scratch);
    __ bind(&end);
    __ Ret();
  }

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
  Register closure = r1;
  __ ldr(closure, MemOperand(fp, StandardFrameConstants::kFunctionOffset));

  // Get the InstructionStream object from the shared function info.
  Register code_obj = r4;
  __ ldr(code_obj,
         FieldMemOperand(closure, JSFunction::kSharedFunctionInfoOffset));

  if (is_osr) {
    ResetSharedFunctionInfoAge(masm, code_obj, r3);
  }

  __ ldr(code_obj,
         FieldMemOperand(code_obj,
                         SharedFunctionInfo::kTrustedFunctionDataOffset));

  // Check if we have baseline code. For OSR entry it is safe to assume we
  // always have baseline code.
  if (!is_osr) {
    Label start_with_baseline;
    __ CompareObjectType(code_obj, r3, r3, CODE_TYPE);
    __ b(eq, &start_with_baseline);

    // Start with bytecode as there is no baseline code.
    Builtin builtin = next_bytecode ? Builtin::kInterpreterEnterAtNextBytecode
                                    : Builtin::kInterpreterEnterAtBytecode;
    __ TailCallBuiltin(builtin);

    // Start with baseline code.
    __ bind(&start_with_baseline);
  } else if (v8_flags.debug_code) {
    __ CompareObjectType(code_obj, r3, r3, CODE_TYPE);
    __ Assert(eq, AbortReason::kExpectedBaselineData);
  }

  if (v8_flags.debug_code) {
    AssertCodeIsBaseline(masm, code_obj, r3);
  }

  // Load the feedback cell and vector.
  Register feedback_cell = r2;
  Register feedback_vector = r9;
  __ ldr(feedback_cell,
         FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  __ ldr(feedback_vector,
         FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset));

  Label install_baseline_code;
  // Check if feedback vector is valid. If not, call prepare for baseline to
  // allocate it.
  __ CompareObjectType(feedback_vector, r3, r3, FEEDBACK_VECTOR_TYPE);
  __ b(ne, &install_baseline_code);

  // Save BytecodeOffset from the stack frame.
  __ ldr(kInterpreterBytecodeOffsetRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);
  // Replace bytecode offset with feedback cell.
  static_assert(InterpreterFrameConstants::kBytecodeOffsetFromFp ==
                BaselineFrameConstants::kFeedbackCellFromFp);
  __ str(feedback_cell,
         MemOperand(fp, BaselineFrameConstants::kFeedbackCellFromFp));
  feedback_cell = no_reg;
  // Update feedback vector cache.
  static_assert(InterpreterFrameConstants::kFeedbackVectorFromFp ==
                BaselineFrameConstants::kFeedbackVectorFromFp);
  __ str(feedback_vector,
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
  Register get_baseline_pc = r3;
  __ Move(get_baseline_pc, get_baseline_pc_extref);

  // If the code deoptimizes during the implicit function entry stack interrupt
  // check, it will have a bailout ID of kFunctionEntryBytecodeOffset, which is
  // not a valid bytecode offset.
  // TODO(pthier): Investigate if it is feasible to handle this special case
  // in TurboFan instead of here.
  Label valid_bytecode_offset, function_entry_bytecode;
  if (!is_osr) {
    __ cmp(kInterpreterBytecodeOffsetRegister,
           Operand(BytecodeArray::kHeaderSize - kHeapObjectTag +
                   kFunctionEntryBytecodeOffset));
    __ b(eq, &function_entry_bytecode);
  }

  __ sub(kInterpreterBytecodeOffsetRegister, kInterpreterBytecodeOffsetRegister,
         Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));

  __ bind(&valid_bytecode_offset);
  // Get bytecode array from the stack frame.
  __ ldr(kInterpreterBytecodeArrayRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  // Save the accumulator register, since it's clobbered by the below call.
  __ Push(kInterpreterAccumulatorRegister);
  {
    __ mov(kCArgRegs[0], code_obj);
    __ mov(kCArgRegs[1], kInterpreterBytecodeOffsetRegister);
    __ mov(kCArgRegs[2], kInterpreterBytecodeArrayRegister);
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ PrepareCallCFunction(3, 0);
    __ CallCFunction(get_baseline_pc, 3, 0);
  }
  __ LoadCodeInstructionStart(code_obj, code_obj);
  __ add(code_obj, code_obj, kReturnRegister0);
  __ Pop(kInterpreterAccumulatorRegister);

  if (is_osr) {
    Generate_OSREntry(masm, code_obj);
  } else {
    __ Jump(code_obj);
  }
  __ Trap();  // Unreachable.

  if (!is_osr) {
    __ bind(&function_entry_bytecode);
    // If the bytecode offset is kFunctionEntryOffset, get the start address of
    // the first bytecode.
    __ mov(kInterpreterBytecodeOffsetRegister, Operand(0));
    if (next_bytecode) {
      __ Move(get_baseline_pc,
              ExternalReference::baseline_pc_for_bytecode_offset());
    }
    __ b(&valid_bytecode_offset);
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
  __ b(&start);
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

  __ ldr(r1, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ ldr(r0, MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ LeaveFrame(StackFrame::INTERNAL);

  // The arguments are already in the stack (including any necessary padding),
  // we should not try to massage the arguments again.
  __ mov(r2, Operand(kDontAdaptArgumentsSentinel));
  __ InvokeFunction(r1, r2, r0, InvokeType::kJump);
}

#undef __

}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_ARM
```