Response:
My thinking process to arrive at the summarized functionality of the provided ARM assembly code went something like this:

1. **Initial Scan for Keywords and Patterns:** I quickly scanned the code for recognizable patterns and keywords related to WebAssembly and JavaScript interaction. Terms like "Wasm," "Promise," "JSToWasmWrapper," "StackSwitch," "ExceptionHandling," "FulfillPromise," "RejectPromise," "Builtin," "MacroAssembler," "RegisterAllocator," and the register names themselves (like `sp`, `fp`, `lr`, `r0`-`r9`, `v`) stood out. The repeated use of `MemOperand` also indicated memory access patterns.

2. **High-Level Function Identification:**  Based on the function names (`JSToWasmWrapperHelper`, `SwitchToAllocatedStack`, `SwitchBackAndReturnPromise`, `GenerateExceptionHandlingLandingPad`), I started forming a mental model of the code's purpose. The "JSToWasmWrapper" clearly suggested a bridge between JavaScript and WebAssembly. The "StackSwitch" functions hinted at managing different stack contexts, likely for asynchronous operations or stack overflow handling. The "ExceptionHandlingLandingPad" pointed towards error management.

3. **Dissecting `JSToWasmWrapperHelper`:**  This function seemed central. I broke it down section by section:
    * **Stack Frame Setup:** `EnterFrame` with `STACK_SWITCH` or `JS_TO_WASM` flags indicated setting up different kinds of call frames.
    * **Stack Allocation:** `AllocateStackSpace` and calculations involving `StackSwitchFrameConstants` suggested managing memory for these frames.
    * **Implicit Argument Handling:** Loading and storing `implicit_arg` (instance or import data) pointed to passing data into the WebAssembly function.
    * **Wrapper Buffer:**  The `wrapper_buffer` and related memory operations (`kWrapperBufferOffset`, `kWrapperBufferParamStart`, etc.) suggested a structure for passing parameters and receiving results.
    * **Stack Switching Logic:** The `if (stack_switch)` block with calls to `SwitchToAllocatedStack` and `SwitchBackAndReturnPromise` confirmed the handling of stack switching scenarios.
    * **Parameter Passing:** The loop iterating through `wasm::kGpParamRegisters` and `wasm::kFpParamRegisters`, combined with loading from the `wrapper_buffer`, indicated how JavaScript arguments are passed to the WebAssembly function.
    * **Calling WebAssembly:** `CallWasmCodePointer` explicitly showed the invocation of the WebAssembly code.
    * **Result Handling:** Storing return values (`kGpReturnRegisters`, `kFpReturnRegisters`) back into the `wrapper_buffer` and then calling `kJSToWasmHandleReturns` suggested how WebAssembly results are passed back to JavaScript.
    * **Promise Handling:**  The `SwitchBackAndReturnPromise` function, along with checks for `wasm::kPromise`, highlighted support for asynchronous WebAssembly functions returning promises.
    * **Exception Handling:** `GenerateExceptionHandlingLandingPad` and the logic involving `RejectPromise` clearly addressed how WebAssembly exceptions are caught and propagated as JavaScript promise rejections.

4. **Analyzing Supporting Functions:**
    * **`SwitchToAllocatedStack`:**  The logic of saving the old stack pointer (`original_fp`), allocating a new stack, and copying data (especially related to the wrapper buffer) became clear as the mechanism for switching stacks.
    * **`SwitchBackAndReturnPromise`:** Reloading continuations and suspend information, then calling `FulfillPromise`, demonstrated the process of resolving a JavaScript promise after a WebAssembly function completes.
    * **`GenerateExceptionHandlingLandingPad`:** The calls to `RejectPromise` and the logic of resetting the `thread_in_wasm_flag` confirmed its role in handling WebAssembly exceptions and converting them to promise rejections.

5. **Identifying Key Concepts:** I focused on the core concepts illustrated by the code:
    * **Interoperability:** Bridging JavaScript and WebAssembly.
    * **Stack Management:** Handling different stack contexts for synchronous and asynchronous calls.
    * **Parameter and Return Value Marshalling:** Passing data between JavaScript and WebAssembly using a `wrapper_buffer`.
    * **Promise Integration:** Supporting asynchronous WebAssembly functions returning promises.
    * **Exception Handling:**  Managing errors originating from WebAssembly and propagating them to JavaScript.

6. **Inferring Functionality from Names:**  Functions like `Generate_JSToWasmWrapperAsm`, `Generate_WasmReturnPromiseOnSuspendAsm`, and `Generate_JSToWasmStressSwitchStacksAsm` directly indicated different entry points or variations of the JSToWasm wrapper based on the promise mode.

7. **Formulating the Summary:**  Based on the above analysis, I constructed a summary that highlighted the key responsibilities of the code, focusing on its role as a bridge between JavaScript and WebAssembly, managing stack switching for asynchronous operations, handling parameters and return values, and dealing with exceptions and promises. I tried to use clear and concise language, avoiding excessive technical jargon where possible while still accurately reflecting the code's purpose.

Essentially, my process was a combination of pattern recognition, keyword analysis, logical deduction based on function names and code structure, and relating the code to the broader concepts of JavaScript and WebAssembly interaction within the V8 engine.


好的，让我们来归纳一下这段代码的功能。

**功能归纳**

这段 C++ 代码（`v8/src/builtins/arm/builtins-arm.cc` 的一部分）是 V8 JavaScript 引擎中用于 ARM 架构的，专门负责处理 **JavaScript 调用 WebAssembly 函数** 的过程。  它定义了多种版本的 "JSToWasmWrapper"，以处理不同的场景，特别是涉及异步操作和栈切换的情况。

**核心功能点：**

1. **作为 JavaScript 和 WebAssembly 之间的桥梁:**  这段代码生成汇编指令，使得从 JavaScript 代码调用 WebAssembly 模块中的函数成为可能。它负责设置必要的栈帧、传递参数、调用 WebAssembly 代码，并处理 WebAssembly 函数的返回值。

2. **处理同步和异步 WebAssembly 调用:**
   - **同步调用 (`wasm::kNoPromise`):**  这是最基本的场景，JavaScript 直接调用 WebAssembly 函数并等待其返回。
   - **异步调用 (`wasm::kPromise`):**  当 WebAssembly 函数需要挂起（例如，等待异步操作完成）时，这段代码会处理 Promise 的创建和管理。它会在 WebAssembly 挂起时返回一个 Promise 给 JavaScript，并在 WebAssembly 恢复执行时 resolve 或 reject 这个 Promise。
   - **压力栈切换 (`wasm::kStressSwitch`):** 这可能是用于测试或特殊情况，强制进行栈切换。

3. **栈管理 (Stack Switching):**  对于异步 WebAssembly 调用，代码实现了栈切换机制。当 WebAssembly 函数挂起时，它会切换到一个专门的栈，以便 JavaScript 可以继续执行。当 WebAssembly 函数恢复时，它会切换回原来的栈。

4. **参数和返回值处理:**  代码负责将 JavaScript 的参数转换为 WebAssembly 可以理解的格式，并将 WebAssembly 的返回值转换回 JavaScript 的格式。它使用了 `wrapper_buffer` 来存储和传递这些数据。

5. **异常处理:** 当 WebAssembly 代码抛出异常时，这段代码会捕获这个异常，并将其转换为 JavaScript 的 Promise rejection。

**代码逻辑推理和假设输入/输出**

让我们聚焦在 `SwitchToAllocatedStack` 函数，因为它涉及到一些代码逻辑。

**假设输入:**

- `masm`: 指向 `MacroAssembler` 对象的指针，用于生成汇编代码。
- `regs`: `RegisterAllocator` 对象，用于管理寄存器分配。
- `implicit_arg`:  包含 WebAssembly 实例数据或导入数据的寄存器。
- `wrapper_buffer`:  指向用于参数和返回值传递的缓冲区的寄存器。
- `original_fp`:  用于存储原始帧指针的寄存器 (在 `SwitchToAllocatedStack` 中被赋值)。
- `new_wrapper_buffer`: 用于存储新 wrapper buffer 地址的寄存器 (在 `SwitchToAllocatedStack` 中被赋值)。
- `suspend`:  一个标签，用于跳转到挂起处理的代码。

**代码逻辑:**

1. **保存原始帧指针:**  `__ Move(original_fp, fp);` 将当前的帧指针保存到 `original_fp` 寄存器。
2. **计算新的栈空间:**  计算需要的栈空间大小，包括用于溢出槽和 wrapper buffer 的空间，并进行 16 字节对齐。
3. **分配新的栈空间:** `__ sub(sp, sp, Operand(stack_space));` 从栈指针 `sp` 中减去计算出的空间，从而分配新的栈空间。
4. **强制栈对齐:** `__ EnforceStackAlignment();` 确保栈指针是 16 字节对齐的。
5. **移动 wrapper buffer 指针:** 将新的栈顶地址赋值给 `new_wrapper_buffer`。
6. **从旧的 wrapper buffer 复制数据:**  从旧的 `wrapper_buffer` 中加载一些关键数据（例如，返回计数、信号表示数组），并将它们存储到新的 `new_wrapper_buffer` 中。这是为了在栈切换后保持必要的状态。

**假设输出 (执行 `SwitchToAllocatedStack` 后):**

- `original_fp`: 存储了调用 `SwitchToAllocatedStack` 之前的帧指针值。
- `sp`: 指向新分配的栈空间的栈顶。
- `new_wrapper_buffer`: 存储了新分配的栈空间的地址，这个地址也被用作新的 wrapper buffer 的起始地址。
- 新的栈空间已被预留，并与旧的栈空间隔离。
- 关键的 wrapper buffer 数据已被复制到新的 buffer 中。

**与 JavaScript 功能的关系 (以异步调用为例)**

假设我们有以下 JavaScript 代码调用一个会挂起的 WebAssembly 函数：

```javascript
async function callWasmFunction() {
  const instance = await WebAssembly.instantiateStreaming(fetch('my_module.wasm'));
  const resultPromise = instance.exports.asyncFunction(); // asyncFunction 会挂起
  console.log("JavaScript 继续执行...");
  const result = await resultPromise; // 等待 Promise resolve
  console.log("WebAssembly 函数返回:", result);
}

callWasmFunction();
```

当 `instance.exports.asyncFunction()` 被调用时，`Generate_WasmReturnPromiseOnSuspendAsm` 生成的包装器就会被执行。

- `SwitchToAllocatedStack` 会被调用，为 WebAssembly 的挂起分配新的栈空间。
- WebAssembly 函数执行到挂起的地方。
- `SwitchBackAndReturnPromise` 会被调用，创建一个 JavaScript Promise 并返回给 JavaScript。这个 Promise 关联着 WebAssembly 的挂起状态。
- JavaScript 可以继续执行 "JavaScript 继续执行..." 这行代码。
- 当 WebAssembly 函数恢复执行并返回结果时，`SwitchBackAndReturnPromise` 也会负责 resolve 之前返回的 Promise。
- `await resultPromise` 会接收到解析后的结果，并输出 "WebAssembly 函数返回: [结果]"。

**用户常见的编程错误 (与 WebAssembly 互操作相关)**

1. **类型不匹配:** 在 JavaScript 和 WebAssembly 之间传递参数或返回值时，类型不匹配会导致错误。例如，JavaScript 传递了一个字符串，而 WebAssembly 函数期望一个整数。

   ```javascript
   // WebAssembly 函数期望一个 i32
   instance.exports.wasmFunction( "不是一个数字" ); // 可能会导致错误
   ```

2. **内存访问错误:**  WebAssembly 可以直接访问线性内存。如果在 JavaScript 中创建了一个 `Uint8Array` 并将其传递给 WebAssembly，WebAssembly 代码可能会尝试访问超出数组边界的内存。

   ```javascript
   const buffer = new Uint8Array(10);
   // 假设 WebAssembly 代码会访问超过 10 个字节的内存
   instance.exports.accessMemory(buffer); // 可能会导致崩溃
   ```

3. **忘记处理 Promise:** 对于返回 Promise 的异步 WebAssembly 函数，如果没有使用 `await` 或 `.then()` 来处理 Promise，结果将无法被正确获取。

   ```javascript
   instance.exports.asyncFunction(); // Promise 被创建但没有被处理
   ```

4. **不正确的导入/导出:**  如果在 JavaScript 中尝试调用 WebAssembly 中不存在的导出函数，或者 WebAssembly 模块期望 JavaScript 提供但未提供的导入，则会导致错误。

**总结这段代码的功能**

总而言之，这段 `v8/src/builtins/arm/builtins-arm.cc` 的代码是 V8 引擎中至关重要的一部分，它实现了 JavaScript 与 WebAssembly 在 ARM 架构上的互操作，特别是处理了异步挂起和恢复的复杂情况，并确保了参数和返回值的正确传递以及异常的妥善处理。它为 JavaScript 调用 WebAssembly 函数提供了必要的底层支持。

Prompt: 
```
这是目录为v8/src/builtins/arm/builtins-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/arm/builtins-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能

"""
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
           
"""


```