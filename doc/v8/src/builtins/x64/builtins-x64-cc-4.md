Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/builtins/x64/builtins-x64.cc`. The snippet appears to be related to WebAssembly (Wasm) and stack switching within the V8 JavaScript engine.

Here's a breakdown of the thought process to analyze the code:

1. **Identify Key Concepts:** Look for repeated keywords, function names, and data structures. Terms like `SwitchStacks`, `LoadJumpBuffer`, `WasmContinuationObject`, `WasmSuspenderObject`, `JSToWasmWrapper`, `WasmToJsWrapper`, `Promise`, `ExceptionHandling`, and `CEntry` stand out. These suggest the code deals with:
    * Managing different stacks for JavaScript and WebAssembly.
    * Handling asynchronous operations (Promises).
    * Wrapping calls between JavaScript and WebAssembly.
    * Handling exceptions in WebAssembly.
    * Low-level entry points for calling C++ from JavaScript.

2. **Analyze Individual Functions:** Examine the purpose of each function:
    * `SwitchStackState`:  Modifies the state of a jump buffer, likely used to save and restore execution context.
    * `FillJumpBuffer`:  Saves the current execution state (registers, stack pointer) into a jump buffer.
    * `LoadJumpBuffer`:  Restores the execution state from a jump buffer.
    * `SwitchStacks`:  Performs the actual stack switch, potentially interacting with C++ functions for stack management.
    * `ReloadParentContinuation`:  Likely used when returning from a suspended WebAssembly function or promise, restoring the parent continuation's context.
    * `GetContextFromImplicitArg`: Retrieves the JavaScript context associated with a WebAssembly instance or import.
    * `RestoreParentSuspender`:  Manages the state of `WasmSuspenderObject`s, used for managing asynchronous WebAssembly calls.
    * `ResetStackSwitchFrameStackSlots`: Initializes stack slots in a stack switch frame.
    * `SwitchToAllocatedStack`:  Handles the stack switch when calling a WebAssembly function that might suspend.
    * `SwitchBackAndReturnPromise`:  Manages the return process when a WebAssembly function returns a promise.
    * `GenerateExceptionHandlingLandingPad`: Sets up a handler for exceptions thrown during WebAssembly execution.
    * `JSToWasmWrapperHelper`: A central function for generating the assembly code for wrapping JavaScript calls to WebAssembly.
    * `Generate_WasmToJsWrapperAsm`:  Generates assembly for wrapping WebAssembly calls to JavaScript.
    * `Generate_WasmTrapHandlerLandingPad`: Handles WebAssembly traps (runtime errors).
    * `Generate_WasmSuspend`: Implements the WebAssembly `suspend` operation.
    * `Generate_WasmResumeHelper`:  A helper for generating assembly to resume a suspended WebAssembly function.
    * `Generate_WasmOnStackReplace`: Handles on-stack replacement, an optimization technique.
    * `SwitchToTheCentralStackIfNeeded` and `SwitchFromTheCentralStackIfNeeded`:  Deal with switching to a central stack, potentially for debugging or other internal purposes.
    * `Generate_CEntry`:  Generates assembly for the entry point when calling C++ functions from JavaScript.

3. **Identify Relationships:**  Notice how functions are called within each other. For example, `SwitchToAllocatedStack` calls `ResetStackSwitchFrameStackSlots`, `SaveState`, and `SwitchStacks`. `SwitchBackAndReturnPromise` calls `GetContextFromImplicitArg` and `ReloadParentContinuation`. This reveals the flow of execution and dependencies between components.

4. **Infer Overall Purpose:** Based on the individual function functionalities and their relationships, deduce the high-level goal of the code. It's clearly focused on enabling seamless interaction between JavaScript and WebAssembly, including:
    * Calling WebAssembly functions from JavaScript and vice versa.
    * Handling asynchronous WebAssembly functions using Promises.
    * Managing separate stacks for JavaScript and WebAssembly.
    * Handling errors and exceptions.

5. **Address Specific Questions:**  Review the user's specific questions:
    * **Functionality:**  Provide a summary based on the analysis.
    * **.tq extension:**  State that it's not a Torque file.
    * **JavaScript Relationship:** Explain how the code bridges JavaScript and WebAssembly, providing relevant examples for calling Wasm functions from JS and handling asynchronous operations.
    * **Code Logic Inference:**  Focus on functions like `SwitchStackState`, `FillJumpBuffer`, and `LoadJumpBuffer` and provide a simple scenario with assumed inputs and outputs illustrating their role in saving and restoring execution context.
    * **Common Programming Errors:** Think about typical mistakes developers make when interacting with WebAssembly or asynchronous code (e.g., incorrect function signatures, not handling promises correctly).
    * **Part of a Larger System:** Acknowledge that this is one piece of the V8 engine's WebAssembly implementation.

6. **Structure the Answer:** Organize the information logically, starting with a general summary and then addressing the specific points. Use clear and concise language.

7. **Refine and Review:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Make any necessary adjustments to improve the quality of the explanation. For instance, initially, I might have focused too much on individual register usage, but realizing the user wants a higher-level understanding, I shifted the focus to the overall concepts and workflows.
这个代码片段是 `v8/src/builtins/x64/builtins-x64.cc` 的一部分，它定义了在 x64 架构下 V8 引擎内置函数的实现，特别是与 WebAssembly (Wasm) 相关的部分。

**主要功能归纳:**

这个代码片段主要负责以下 WebAssembly 相关的功能：

1. **栈切换 (Stack Switching):**  定义了在 JavaScript 栈和 WebAssembly 栈之间切换的机制。这包括保存和恢复执行上下文（寄存器、栈指针等），以及管理与栈相关的对象（如 continuation 和 suspender）。
2. **JavaScript 到 WebAssembly 的调用 (JSToWasmWrapper):**  实现了从 JavaScript 代码调用 WebAssembly 函数的包装器。这包括参数的传递、栈的准备、WebAssembly 代码的执行以及返回值的处理。
3. **WebAssembly 到 JavaScript 的调用 (WasmToJsWrapper):** 实现了从 WebAssembly 代码调用 JavaScript 函数的包装器。这涉及到参数的转换和传递，以及调用 JavaScript 内置函数。
4. **WebAssembly 的暂停和恢复 (Suspend/Resume):** 实现了 WebAssembly 函数的暂停 (suspend) 和恢复 (resume) 功能，这通常用于处理异步操作或实现类似协程的效果。
5. **Promise 集成 (Promise Integration):**  处理当 WebAssembly 函数返回 Promise 时的情况，以及在 WebAssembly 代码中与 Promise 交互。
6. **异常处理 (Exception Handling):**  定义了在 WebAssembly 代码执行过程中发生异常时的处理流程，例如将异常转换为 Promise 的拒绝。
7. **Trap 处理 (Trap Handling):**  定义了处理 WebAssembly 陷阱 (trap) 的逻辑，例如访问越界等运行时错误。
8. **On-Stack Replacement (OSR):**  支持在函数执行过程中进行代码替换的机制，用于优化。
9. **中央栈支持 (Central Stack Support):**  提供了在某些情况下切换到中央栈的机制，可能用于调试或其他特殊用途。
10. **C 函数调用接口 (CEntry):** 定义了从 JavaScript 调用 C++ 函数的入口点。

**关于 .tq 扩展:**

根据你的描述，如果 `v8/src/builtins/x64/builtins-x64.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。然而，当前提供的文件名是 `.cc`，这意味着它是一个 **C++** 源代码文件，包含了手写的汇编代码或者使用了宏来生成汇编代码。

**与 JavaScript 功能的关系及示例:**

这个文件中的代码是 V8 引擎执行 WebAssembly 代码的关键部分，它使得 JavaScript 能够无缝地调用和交互 WebAssembly 模块。

**JavaScript 示例：**

假设我们有一个简单的 WebAssembly 模块，导出一个函数 `add`，它接受两个整数并返回它们的和。

```javascript
// 假设已经加载了 WebAssembly 模块 instance
const wasmModule = instance.exports;
const result = wasmModule.add(5, 3);
console.log(result); // 输出 8
```

当 JavaScript 调用 `wasmModule.add(5, 3)` 时，`JSToWasmWrapperHelper` 中生成的代码会被执行，它会：

1. 设置 WebAssembly 的执行环境（例如，切换到 WebAssembly 栈）。
2. 将 JavaScript 的参数 (5 和 3) 转换为 WebAssembly 期望的格式。
3. 调用 WebAssembly 模块中的 `add` 函数。
4. 将 WebAssembly 函数的返回值转换回 JavaScript 的格式。
5. 将结果返回给 JavaScript 代码。

**涉及用户常见的编程错误及示例:**

1. **WebAssembly 函数签名不匹配:** 如果 JavaScript 调用的参数类型或数量与 WebAssembly 导出的函数签名不匹配，会导致错误。

   ```javascript
   // 假设 WebAssembly 的 add 函数接受两个 i32 参数
   // 错误：传递了字符串类型的参数
   wasmModule.add("5", 3); // 这可能会导致类型错误或意外的结果
   ```

2. **异步 WebAssembly 函数处理不当:**  如果 WebAssembly 函数返回一个 Promise，JavaScript 代码需要正确地处理这个 Promise，例如使用 `.then()` 或 `await`。

   ```javascript
   // 假设 WebAssembly 的 asyncAdd 函数返回一个 Promise
   wasmModule.asyncAdd(5, 3).then(result => {
       console.log(result);
   }).catch(error => {
       console.error("Promise rejected:", error);
   });

   // 错误：没有处理 Promise 的 rejected 状态
   wasmModule.asyncAdd(5, 3).then(result => {
       console.log(result);
   });
   ```

3. **访问 WebAssembly 模块中不存在的导出项:**  如果 JavaScript 尝试访问 WebAssembly 模块中没有导出的函数或变量，会导致错误。

   ```javascript
   // 假设 WebAssembly 模块没有导出名为 subtract 的函数
   wasmModule.subtract(10, 2); // 错误：wasmModule.subtract is not a function
   ```

**代码逻辑推理（假设输入与输出）:**

考虑 `SwitchStackState` 函数。

**假设输入:**

* `masm`: 指向 `MacroAssembler` 对象的指针，用于生成汇编代码。
* `target_jmpbuf`: 寄存器，其中包含目标 jump buffer 的地址。
* `expected_state`: `wasm::JumpBuffer::Active` (假设当前状态是活动的)。
* `new_state`: `wasm::JumpBuffer::Suspended` (假设要切换到暂停状态)。

**输出:**

`SwitchStackState` 函数会生成汇编代码，执行以下操作：

1. 从 `target_jmpbuf` 指向的内存位置加载当前 jump buffer 的状态。
2. 将加载的状态与 `expected_state` 进行比较（在本例中是 `wasm::JumpBuffer::Active`）。
3. 如果状态不匹配，可能会触发一个断言或错误处理（代码中未显示具体错误处理）。
4. 将 jump buffer 的状态更新为 `new_state` (`wasm::JumpBuffer::Suspended`) 并存储回内存。

**代码逻辑推理（`FillJumpBuffer` 和 `LoadJumpBuffer`）:**

**场景:**  假设 WebAssembly 代码要执行一个可能暂停的操作。

1. **`FillJumpBuffer` 的调用 (在暂停操作之前):**
   * **假设输入:**  `masm`, `jmpbuf` (指向当前 continuation 的 jump buffer), `resume_label` (代码中标记恢复执行点的标签)。
   * **输出:** `FillJumpBuffer` 会生成汇编代码，将当前的 CPU 状态（包括通用寄存器、浮点寄存器、栈指针 `rsp` 和指令指针 `rip` (通过 `__ pc_offset()` 获取)）保存到 `jmpbuf` 指向的内存区域。同时，会将 `resume_label` 对应的地址保存到 `jmpbuf` 中，以便稍后恢复执行。

2. **`LoadJumpBuffer` 的调用 (在恢复执行时):**
   * **假设输入:** `masm`, `target_jmpbuf` (指向之前保存了状态的 jump buffer), `do_return` (指示是否应该像函数返回一样恢复 `rip`，这里假设为 `true`), `expected_state` (`wasm::JumpBuffer::Suspended`)。
   * **输出:** `LoadJumpBuffer` 会生成汇编代码，从 `target_jmpbuf` 指向的内存区域加载之前保存的 CPU 状态，包括通用寄存器、浮点寄存器和栈指针 `rsp`。如果 `do_return` 为 `true`，它还会加载之前保存的 `rip` 并跳转到该地址，从而恢复 WebAssembly 代码的执行。同时，它会检查 jump buffer 的状态是否与 `expected_state` 匹配。

总而言之，这个代码片段是 V8 引擎中 WebAssembly 功能实现的基石，它处理了 JavaScript 和 WebAssembly 之间的互操作、栈管理、异步操作以及错误处理等关键方面。

### 提示词
```
这是目录为v8/src/builtins/x64/builtins-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/x64/builtins-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  static constexpr int kMaxReg
```