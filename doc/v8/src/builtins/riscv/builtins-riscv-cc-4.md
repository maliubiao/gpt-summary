Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/builtins/riscv/builtins-riscv.cc`.

Here's a breakdown of the thought process to achieve the desired response:

1. **Identify the Core Purpose:** The code deals with managing the execution state of WebAssembly functions, particularly around suspension and resumption. Keywords like `JumpBuffer`, `Continuation`, `Suspender`, `SwitchStacks` are strong indicators.

2. **Group Related Functions:** Notice patterns in the function names and their arguments. For example, `FillJumpBuffer`, `LoadJumpBuffer`, and `SwitchStackPointerAndSimulatorStackLimit` all operate on `JumpBuffer` and related concepts. Similarly, `ReloadParentContinuation` and `RestoreParentSuspender` seem to handle moving between different execution contexts.

3. **Explain Key Concepts:**  Define the central data structures like `JumpBuffer`, `Continuation`, and `Suspender`. Explain their role in saving and restoring execution state.

4. **Analyze Individual Functions:** Briefly describe what each function does in the context of the overall purpose. Focus on the *what*, not the *how* of the RISC-V assembly instructions.

5. **Address Specific Instructions:**
    * **`.tq` extension:**  The code is `.cc`, so this part of the question is straightforward.
    * **JavaScript Relationship:** The code facilitates WebAssembly's interaction with JavaScript. Focus on the suspension/resumption mechanism, as this directly impacts how asynchronous operations in WebAssembly are handled within a JavaScript environment. Provide a clear JavaScript example illustrating the concept of asynchronous behavior, even if it's not a direct one-to-one mapping to the low-level C++ code.
    * **Code Logic Reasoning:** Choose a function with relatively clear logic. `FillJumpBuffer` is a good candidate. Define plausible input (register containing a memory location, label representing a program counter). Explain how the function manipulates memory based on these inputs.
    * **Common Programming Errors:** Think about typical pitfalls when dealing with manual memory management or asynchronous operations. Stack overflow and incorrect state management are relevant to the code.

6. **Synthesize a Summary:**  Combine the understanding gained from the individual function analysis into a concise overview of the file's purpose. Emphasize the core functionality: managing WebAssembly execution state, enabling suspension and resumption, and facilitating interaction with the JavaScript environment.

7. **Structure the Output:** Organize the information logically with clear headings and bullet points to improve readability. Address each part of the user's request.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus on the assembly instructions. **Correction:**  Shift focus to the high-level purpose of the code, explaining the concepts and workflows rather than just translating assembly.
* **Initial thought:** Provide a complex JavaScript example directly mirroring the C++. **Correction:** Simplify the JavaScript example to illustrate the *concept* of asynchronicity and promises, as a direct mapping isn't necessary or easy to construct.
* **Initial thought:**  Explain every single line of assembly. **Correction:**  Focus on the key operations within each function, omitting unnecessary low-level details for a high-level summary.
* **Initial thought:**  Only discuss the successful execution path. **Correction:** Include the error handling aspect and the potential for common programming errors related to stack management.

By following this structured approach, including self-correction, we can arrive at a comprehensive and understandable explanation of the provided C++ code snippet.
```cpp
gister);

  __ SubWord(
      sp, sp,
      Operand(StackSwitchFrameConstants::kNumSpillSlots * kSystemPointerSize));

  // Load the implicit argument (instance data or import data) from the frame.
  Register implicit_arg = kWasmImplicitArgRegister;
  __ LoadWord(
      implicit_arg,
      MemOperand(fp, JSToWasmWrapperFrameConstants::kImplicitArgOffset));

  Register wrapper_buffer =
      WasmJSToWasmWrapperDescriptor::WrapperBufferRegister();
  Label suspend;
  Register original_fp = kScratchReg;
  Register new_wrapper_buffer = kScratchReg2;
  if (stack_switch) {
    SwitchToAllocatedStack(masm, implicit_arg, wrapper_buffer, original_fp,
                           new_wrapper_buffer, &suspend);
  } else {
    original_fp = fp;
    new_wrapper_buffer = wrapper_buffer;
  }

  {
    __ StoreWord(
        new_wrapper_buffer,
        MemOperand(fp, JSToWasmWrapperFrameConstants::kWrapperBufferOffset));
    if (stack_switch) {
      __ StoreWord(
          implicit_arg,
          MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
      UseScratchRegisterScope temps(masm);
      Register scratch = temps.Acquire();
      __ LoadWord(
          scratch,
          MemOperand(original_fp,
                     JSToWasmWrapperFrameConstants::kResultArrayParamOffset));
      __ StoreWord(
          scratch,
          MemOperand(fp, StackSwitchFrameConstants::kResultArrayOffset));
    }
  }
  {
    UseScratchRegisterScope temps(masm);
    Register result_size = temps.Acquire();
    __ LoadWord(
        result_size,
        MemOperand(wrapper_buffer, JSToWasmWrapperFrameConstants::
                                       kWrapperBufferStackReturnBufferSize));
    // // The `result_size` is the number of slots needed on the stack to store
    // the
    // // return values of the wasm function. If `result_size` is an odd number,
    // we
    // // have to add `1` to preserve stack pointer alignment.
    // __ AddWord(result_size, result_size, 1);
    // __ Bic(result_size, result_size, 1);
    __ SllWord(result_size, result_size, kSystemPointerSizeLog2);
    __ SubWord(sp, sp, Operand(result_size));
  }
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ mv(scratch, sp);
    __ StoreWord(scratch, MemOperand(new_wrapper_buffer,
                                     JSToWasmWrapperFrameConstants::
                                         kWrapperBufferStackReturnBufferStart));
  }
  original_fp = no_reg;
  new_wrapper_buffer = no_reg;

  // The first GP parameter holds the trusted instance data or the import data.
  // This is handled specially.
  int stack_params_offset =
      (arraysize(wasm::kGpParamRegisters) - 1) * kSystemPointerSize +
      arraysize(wasm::kFpParamRegisters) * kDoubleSize;

  {
    UseScratchRegisterScope temps(masm);
    Register params_start = temps.Acquire();
    __ LoadWord(
        params_start,
        MemOperand(wrapper_buffer,
                   JSToWasmWrapperFrameConstants::kWrapperBufferParamStart));
    {
      // Push stack parameters on the stack.
      UseScratchRegisterScope temps(masm);
      Register params_end = kScratchReg;
      __ LoadWord(
          params_end,
          MemOperand(wrapper_buffer,
                     JSToWasmWrapperFrameConstants::kWrapperBufferParamEnd));
      Register last_stack_param = kScratchReg2;

      __ AddWord(last_stack_param, params_start, Operand(stack_params_offset));
      Label loop_start;
      __ bind(&loop_start);

      Label finish_stack_params;
      __ Branch(&finish_stack_params, ge, last_stack_param,
                Operand(params_end));

      // Push parameter
      {
        UseScratchRegisterScope temps(masm);
        Register scratch = temps.Acquire();
        __ SubWord(params_end, params_end, Operand(kSystemPointerSize));
        __ LoadWord(scratch, MemOperand(params_end, 0));
        __ Push(scratch);
      }
      __ Branch(&loop_start);

      __ bind(&finish_stack_params);
    }
    int next_offset = 0;
    for (size_t i = 1; i < arraysize(wasm::kGpParamRegisters); ++i) {
      // Check that {params_start} does not overlap with any of the parameter
      // registers, so that we don't overwrite it by accident with the loads
      // below.
      DCHECK_NE(params_start, wasm::kGpParamRegisters[i]);
      __ LoadWord(wasm::kGpParamRegisters[i],
                  MemOperand(params_start, next_offset));
      next_offset += kSystemPointerSize;
    }

    for (size_t i = 0; i < arraysize(wasm::kFpParamRegisters); ++i) {
      __ LoadDouble(wasm::kFpParamRegisters[i],
                    MemOperand(params_start, next_offset));
      next_offset += kDoubleSize;
    }
    DCHECK_EQ(next_offset, stack_params_offset);
  }

  {
    UseScratchRegisterScope temps(masm);
    Register thread_in_wasm_flag_addr = temps.Acquire();
    __ LoadWord(thread_in_wasm_flag_addr,
                MemOperand(kRootRegister,
                           Isolate::thread_in_wasm_flag_address_offset()));
    Register scratch = temps.Acquire();
    __ li(scratch, 1);
    __ Sw(scratch, MemOperand(thread_in_wasm_flag_addr, 0));
  }
  __ StoreWord(
      zero_reg,
      MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset));
  {
    UseScratchRegisterScope temps(masm);
    Register call_target = temps.Acquire();
    __ LoadWord(
        call_target,
        MemOperand(wrapper_buffer,
                   JSToWasmWrapperFrameConstants::kWrapperBufferCallTarget));
    __ Call(call_target);
  }
  {
    UseScratchRegisterScope temps(masm);
    Register thread_in_wasm_flag_addr = temps.Acquire();
    __ LoadWord(thread_in_wasm_flag_addr,
                MemOperand(kRootRegister,
                           Isolate::thread_in_wasm_flag_address_offset()));
    __ Sw(zero_reg, MemOperand(thread_in_wasm_flag_addr, 0));
  }

  wrapper_buffer = a2;
  __ LoadWord(
      wrapper_buffer,
      MemOperand(fp, JSToWasmWrapperFrameConstants::kWrapperBufferOffset));

  __ StoreDouble(
      wasm::kFpReturnRegisters[0],
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferFPReturnRegister1));
  __ StoreDouble(
      wasm::kFpReturnRegisters[1],
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferFPReturnRegister2));
  __ StoreWord(
      wasm::kGpReturnRegisters[0],
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister1));
  __ StoreWord(
      wasm::kGpReturnRegisters[1],
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister2));
  // Call the return value builtin with
  // x0: wasm instance.
  // x1: the result JSArray for multi-return.
  // x2: pointer to the byte buffer which contains all parameters.
  if (stack_switch) {
    __ LoadWord(a1,
                MemOperand(fp, StackSwitchFrameConstants::kResultArrayOffset));
    __ LoadWord(a0,
                MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
  } else {
    __ LoadWord(
        a1,
        MemOperand(fp, JSToWasmWrapperFrameConstants::kResultArrayParamOff));
    __ LoadWord(
        a0,
        MemOperand(fp, JSToWasmWrapperFrameConstants::kWasmInstanceParamOff));
  }
  Label return_promise;
  if (stack_switch) {
    SwitchBackAndReturnPromise(masm, mode, &return_promise);
  }

  __ CallBuiltin(Builtin::kWasmReturnValue);

  if (stack_switch) {
    __ bind(&suspend);
    GenerateExceptionHandlingLandingPad(masm, &return_promise);
    __ bind(&return_promise);
  }

  __ LeaveFrame(stack_switch ? StackFrame::STACK_SWITCH
                             : StackFrame::JS_TO_WASM);
  __ Ret();
}
}  // namespace

void Builtins::Generate_JSToWasmWrapper(MacroAssembler* masm) {
  JSToWasmWrapperHelper(masm, wasm::kPlain);
}

void Builtins::Generate_JSToWasmWrapperWithReturnPromise(MacroAssembler* masm) {
  JSToWasmWrapperHelper(masm, wasm::kPromise);
}

void Builtins::Generate_JSToWasmWrapperWithThrowUncaught(
    MacroAssembler* masm) {
  JSToWasmWrapperHelper(masm, wasm::kThrow);
}

void Builtins::Generate_JSToWasmWrapperWithStackSwitch(MacroAssembler* masm) {
  JSToWasmWrapperHelper(masm, wasm::kStressSwitch);
}

}  // namespace builtins
}  // namespace v8
```

## 功能列举

`v8/src/builtins/riscv/builtins-riscv.cc` 文件包含了为 RISC-V 架构实现的 V8 JavaScript 引擎的内置函数（builtins）。这些内置函数是用汇编语言编写的，用于执行一些关键的、性能敏感的操作。

具体来说，从提供的代码片段来看，这个文件主要关注于 **WebAssembly (Wasm) 的支持**，特别是以下几个方面：

* **Wasm 协程 (Continuations) 的实现：**  代码中出现了 `JumpBuffer`, `WasmContinuationObject`, `WasmSuspenderObject` 等概念，以及 `FillJumpBuffer`, `LoadJumpBuffer`, `SwitchStacks` 等函数，这些都与 Wasm 协程的创建、保存、加载和切换有关。协程允许 Wasm 代码暂停执行并在稍后恢复，这对于实现异步操作非常重要。
* **Wasm 的挂起 (Suspend) 和恢复 (Resume/Reject)：** `Generate_WasmSuspend`, `Generate_WasmResume`, `Generate_WasmReject` 等函数实现了 Wasm 代码的挂起和恢复机制。这允许 Wasm 代码与 JavaScript 的异步 Promise 集成。
* **JavaScript 到 Wasm 的调用 (JSToWasmWrapper)：** `Generate_JSToWasmWrapper` 及其变体（`WithReturnPromise`, `WithThrowUncaught`, `WithStackSwitch`) 负责处理 JavaScript 代码调用 Wasm 函数时的桥接工作，包括参数传递、栈帧设置、返回值处理等。它还处理了 Wasm 函数返回 Promise 的情况。
* **栈切换 (Stack Switching)：**  `SwitchToAllocatedStack` 等函数处理在 JavaScript 和 Wasm 之间切换执行栈的情况，这对于某些高级的 Wasm 功能（如协程）是必需的。
* **异常处理：** `GenerateExceptionHandlingLandingPad` 负责处理 Wasm 代码执行过程中抛出的异常，并将其转换为 JavaScript 的 Promise rejection。

## 关于源代码类型

`v8/src/builtins/riscv/builtins-riscv.cc` 文件以 `.cc` 结尾，因此它是一个 **C++ 源代码**文件，而不是 Torque 源代码。

## 与 JavaScript 的关系和示例

这些内置函数直接支持 JavaScript 中对 WebAssembly 的使用。例如，当你在 JavaScript 中调用一个 Wasm 函数时，`Generate_JSToWasmWrapper` 系列的内置函数会被调用来执行实际的 Wasm 代码。

**JavaScript 示例：**

```javascript
async function runWasm() {
  const response = await fetch('my_wasm_module.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);

  // 调用 Wasm 导出的函数
  const result = instance.exports.add(5, 3);
  console.log(result); // 输出 8

  // 调用返回 Promise 的 Wasm 函数 (需要 Wasm 代码支持 asyncify 或 similar)
  try {
    const asyncResult = await instance.exports.asyncOperation();
    console.log("异步结果:", asyncResult);
  } catch (error) {
    console.error("异步操作失败:", error);
  }
}

runWasm();
```

在这个例子中：

* `WebAssembly.compile` 和 `WebAssembly.instantiate`  内部可能会涉及到一些底层的 builtins 来加载和初始化 Wasm 模块。
* 当调用 `instance.exports.add(5, 3)` 时，如果 `add` 函数是在 Wasm 中定义的，那么 `Generate_JSToWasmWrapper` 相关的内置函数会被调用来执行 Wasm 代码并将结果返回给 JavaScript。
* 当调用 `instance.exports.asyncOperation()` 时，如果 Wasm 函数需要挂起和恢复（例如，返回一个 Promise），那么 `Generate_WasmSuspend`, `Generate_WasmResume`, `Generate_WasmReject` 以及相关的协程管理内置函数就会发挥作用。

## 代码逻辑推理

**函数：`FillJumpBuffer`**

**假设输入：**

* `masm`: 指向 MacroAssembler 对象的指针，用于生成 RISC-V 汇编代码。
* `jmpbuf`:  一个 RISC-V 寄存器，指向用于存储跳转信息的内存区域（`wasm::JumpBuffer` 结构）。
* `pc`: 一个指向代码中某个标签 (Label) 的指针，表示要跳转到的程序计数器地址。
* `tmp`: 一个临时的 RISC-V 寄存器。

**输出：**

假设 `jmpbuf` 指向内存地址 `0x1000`，`pc` 指向的标签的地址是 `0x2000`，当前栈指针 `sp` 的值是 `0x3000`，帧指针 `fp` 的值是 `0x4000`，栈限制的值是 `0x5000`。

执行 `FillJumpBuffer` 后，内存 `0x1000` 处的内容将变为：

* `0x1000 + kJmpBufSpOffset`: 存储 `sp` 的值，即 `0x3000`。
* `0x1000 + kJmpBufFpOffset`: 存储 `fp` 的值，即 `0x4000`。
* `0x1000 + kJmpBufStackLimitOffset`: 存储栈限制的值，即 `0x5000`。
* `0x1000 + kJmpBufPcOffset`: 存储 `pc` 指向的地址，即 `0x2000`。

**逻辑推理：**

`FillJumpBuffer` 的作用是将当前执行状态的关键信息（栈指针、帧指针、栈限制、程序计数器）保存到 `jmpbuf` 指向的内存区域，以便后续可以通过 `LoadJumpBuffer` 恢复到这个状态。

## 用户常见的编程错误

与这段代码相关的用户常见编程错误主要发生在编写或使用与 Wasm 协程或异步操作交互的 JavaScript 或 Wasm 代码时：

1. **在 Wasm 中错误地管理协程状态：**  如果 Wasm 代码在挂起和恢复时不正确地保存和恢复其内部状态，可能会导致程序逻辑错误或数据损坏。
2. **Promise 的不当处理：** 当 Wasm 函数返回 Promise 时，JavaScript 代码需要正确地使用 `async/await` 或 `.then()`/`.catch()` 来处理 Promise 的 resolve 或 reject 状态。忘记处理 rejection 可能导致未捕获的错误。
3. **与 JavaScript 的异步操作不匹配：** 如果 Wasm 代码的异步操作与 JavaScript 的期望不一致（例如，Wasm 认为操作已完成但 JavaScript 仍在等待），可能导致死锁或程序hang住。
4. **在 JSToWasmWrapper 中传递错误的参数：**  JavaScript 调用 Wasm 函数时，如果参数类型或数量与 Wasm 函数的签名不匹配，可能导致 Wasm 代码崩溃或产生意外结果。 这段 C++ 代码尝试正确地编排参数，但错误仍然可能发生在 JavaScript 一侧。
5. **栈溢出：**  虽然这段代码涉及到栈的管理，但用户更常见的是在 Wasm 代码或 JavaScript 代码中由于递归过深或分配过大的局部变量导致栈溢出。

**示例 (Promise 的不当处理):**

```javascript
async function runWasmAsync() {
  const instance = await loadWasmInstance();
  // 忘记处理 Promise 的 rejection
  instance.exports.mightFailAsyncOperation().then(result => {
    console.log("异步操作成功:", result);
  });
  // 如果 mightFailAsyncOperation 在 Wasm 中 reject 了 Promise，
  // 这里的错误将不会被捕获，可能导致程序状态异常。
}

runWasmAsync();

// 正确的做法是使用 catch 或 async/await 的 try/catch
async function runWasmAsyncCorrectly() {
  const instance = await loadWasmInstance();
  try {
    const result = await instance.exports.mightFailAsyncOperation();
    console.log("异步操作成功:", result);
  } catch (error) {
    console.error("异步操作失败:", error);
  }
}

runWasmAsyncCorrectly();
```

## 功能归纳

这是第 5 部分，主要关注以下功能：

* **Wasm 协程的恢复 (Resume/Reject) 内置函数：**  `Generate_WasmResumeHelper`, `Generate_WasmResume`, `Generate_WasmReject` 实现了 Wasm 协程从挂起状态恢复执行的逻辑，包括正常恢复和抛出异常两种情况。
* **Wasm 的栈替换 (OnStackReplace) 内置函数：**  `Generate_WasmOnStackReplace`  目前只是一个 `Trap` 指令，表明这个功能在 RISC-V 架构上可能尚未实现或不需要特定的实现。
* **JavaScript 到 Wasm 调用的包装器 (JSToWasmWrapper) 内置函数：**  `JSToWasmWrapperHelper`, `Generate_JSToWasmWrapper`, `Generate_JSToWasmWrapperWithReturnPromise`, `Generate_JSToWasmWrapperWithThrowUncaught`, `Generate_JSToWasmWrapperWithStackSwitch` 负责处理从 JavaScript 调用 Wasm 函数时的各种情况，包括参数传递、栈帧设置、返回值处理，以及处理返回 Promise 和需要栈切换的场景。它还包含了异常处理的逻辑，将 Wasm 的异常转换为 Promise 的 rejection。

总的来说，这部分代码主要负责 **连接 JavaScript 和 WebAssembly，并处理 Wasm 协程的恢复以及 JavaScript 调用 Wasm 函数的各种复杂情况，包括异步和栈切换**。

### 提示词
```
这是目录为v8/src/builtins/riscv/builtins-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/riscv/builtins-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
gister jmpbuf, Register tmp) {
#ifdef V8_TARGET_ARCH_RISCV64
  if (masm->options().enable_simulator_code) {
    UseScratchRegisterScope temps(masm);
    temps.Exclude(kSimulatorBreakArgument);
    __ LoadWord(tmp, MemOperand(jmpbuf, wasm::kJmpBufSpOffset));
    __ LoadWord(kSimulatorBreakArgument,
                MemOperand(jmpbuf, wasm::kJmpBufStackLimitOffset));
    __ mv(sp, tmp);
    __ break_(kExceptionIsSwitchStackLimit);
  } else {
    __ LoadWord(tmp, MemOperand(jmpbuf, wasm::kJmpBufSpOffset));
    __ mv(sp, tmp);
  }
#endif
}

void FillJumpBuffer(MacroAssembler* masm, Register jmpbuf, Label* pc,
                    Register tmp) {
  ASM_CODE_COMMENT(masm);
  __ mv(tmp, sp);
  __ StoreWord(tmp, MemOperand(jmpbuf, wasm::kJmpBufSpOffset));
  __ StoreWord(fp, MemOperand(jmpbuf, wasm::kJmpBufFpOffset));
  __ LoadStackLimit(tmp, StackLimitKind::kRealStackLimit);
  __ StoreWord(tmp, MemOperand(jmpbuf, wasm::kJmpBufStackLimitOffset));
  __ LoadAddress(tmp, pc);
  __ StoreWord(tmp, MemOperand(jmpbuf, wasm::kJmpBufPcOffset));
}

void LoadJumpBuffer(MacroAssembler* masm, Register jmpbuf, bool load_pc,
                    Register tmp, wasm::JumpBuffer::StackState expected_state) {
  ASM_CODE_COMMENT(masm);
  SwitchStackPointerAndSimulatorStackLimit(masm, jmpbuf, tmp);
  __ LoadWord(fp, MemOperand(jmpbuf, wasm::kJmpBufFpOffset));
  SwitchStackState(masm, jmpbuf, tmp, expected_state, wasm::JumpBuffer::Active);
  if (load_pc) {
    __ LoadWord(tmp, MemOperand(jmpbuf, wasm::kJmpBufPcOffset));
    __ Jump(tmp);
  }
  // The stack limit in StackGuard is set separately under the ExecutionAccess
  // lock.
}
// Updates the stack limit to match the new active stack.
// Pass the {finished_continuation} argument to indicate that the stack that we
// are switching from has returned, and in this case return its memory to the
// stack pool.
void SwitchStacks(MacroAssembler* masm, Register finished_continuation,
                  Register tmp) {
  ASM_CODE_COMMENT(masm);
  using ER = ExternalReference;
  if (finished_continuation != no_reg) {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ li(kCArgRegs[0], ExternalReference::isolate_address(masm->isolate()));
    __ mv(kCArgRegs[1], finished_continuation);
    __ PrepareCallCFunction(2, tmp);
    __ CallCFunction(ER::wasm_return_switch(), 2);
  } else {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ li(kCArgRegs[0], ER::isolate_address(masm->isolate()));
    __ PrepareCallCFunction(1, tmp);
    __ CallCFunction(ER::wasm_sync_stack_limit(), 1);
  }
}

void ReloadParentContinuation(MacroAssembler* masm, Register return_reg,
                              Register return_value, Register context,
                              Register tmp1, Register tmp2, Register tmp3) {
  ASM_CODE_COMMENT(masm);
  Register active_continuation = tmp1;
  __ LoadRoot(active_continuation, RootIndex::kActiveContinuation);

  // Set a null pointer in the jump buffer's SP slot to indicate to the stack
  // frame iterator that this stack is empty.
  Register jmpbuf = tmp2;
  __ LoadExternalPointerField(
      jmpbuf,
      FieldMemOperand(active_continuation,
                      WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);
  __ StoreWord(zero_reg, MemOperand(jmpbuf, wasm::kJmpBufSpOffset));
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    SwitchStackState(masm, jmpbuf, scratch, wasm::JumpBuffer::Active,
                     wasm::JumpBuffer::Retired);
  }
  Register parent = tmp2;
  __ LoadTaggedField(parent,
                     FieldMemOperand(active_continuation,
                                     WasmContinuationObject::kParentOffset));

  // Update active continuation root.
  int32_t active_continuation_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveContinuation);
  __ StoreWord(parent, MemOperand(kRootRegister, active_continuation_offset));
  jmpbuf = parent;
  __ LoadExternalPointerField(
      jmpbuf, FieldMemOperand(parent, WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);

  // Switch stack!
  LoadJumpBuffer(masm, jmpbuf, false, tmp3, wasm::JumpBuffer::Inactive);

  __ Push(return_reg, return_value, context);
  SwitchStacks(masm, active_continuation, tmp3);
  __ Pop(return_reg, return_value, context);
}

void RestoreParentSuspender(MacroAssembler* masm, Register tmp1,
                            Register tmp2) {
  ASM_CODE_COMMENT(masm);
  Register suspender = tmp1;
  __ LoadRoot(suspender, RootIndex::kActiveSuspender);
  MemOperand state_loc =
      FieldMemOperand(suspender, WasmSuspenderObject::kStateOffset);
  __ Move(tmp2, Smi::FromInt(WasmSuspenderObject::kInactive));
  __ StoreTaggedField(tmp2, state_loc);
  __ LoadTaggedField(
      suspender,
      FieldMemOperand(suspender, WasmSuspenderObject::kParentOffset));
  Label undefined;
  __ CompareRootAndBranch(suspender, RootIndex::kUndefinedValue, eq,
                          &undefined);
  if (v8_flags.debug_code) {
    // Check that the parent suspender is active.
    Label parent_inactive;
    Register state = tmp2;
    __ SmiUntag(state, state_loc);
    __ Branch(&parent_inactive, eq, state,
              Operand(WasmSuspenderObject::kActive));
    __ Trap();
    __ bind(&parent_inactive);
  }
  __ Move(tmp2, Smi::FromInt(WasmSuspenderObject::kActive));
  __ StoreTaggedField(tmp2, state_loc);
  __ bind(&undefined);
  int32_t active_suspender_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveSuspender);
  __ StoreWord(suspender, MemOperand(kRootRegister, active_suspender_offset));
}

void ResetStackSwitchFrameStackSlots(MacroAssembler* masm) {
  ASM_CODE_COMMENT(masm);
  __ StoreWord(zero_reg,
               MemOperand(fp, StackSwitchFrameConstants::kResultArrayOffset));
  __ StoreWord(zero_reg,
               MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
}

void LoadTargetJumpBuffer(MacroAssembler* masm, Register target_continuation,
                          Register tmp,
                          wasm::JumpBuffer::StackState expected_state) {
  ASM_CODE_COMMENT(masm);
  Register target_jmpbuf = target_continuation;
  __ LoadExternalPointerField(
      target_jmpbuf,
      FieldMemOperand(target_continuation,
                      WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);
  __ StoreWord(
      zero_reg,
      MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset));
  // Switch stack!
  LoadJumpBuffer(masm, target_jmpbuf, false, tmp, expected_state);
}
}  // namespace

void Builtins::Generate_WasmSuspend(MacroAssembler* masm) {
  // Set up the stackframe.
  __ EnterFrame(StackFrame::STACK_SWITCH);

  Register suspender = a0;  //  DEFINE_PINNED(suspender, x0);
  // Register context = kContextRegister; //  DEFINE_PINNED(context,
  // kContextRegister);

  __ SubWord(
      sp, sp,
      Operand(StackSwitchFrameConstants::kNumSpillSlots * kSystemPointerSize));
  // Set a sentinel value for the spill slots visited by the GC.
  ResetStackSwitchFrameStackSlots(masm);

  // -------------------------------------------
  // Save current state in active jump buffer.
  // -------------------------------------------
  Label resume;
  Register continuation = kScratchReg;  //  DEFINE_REG(continuation);
  __ LoadRoot(continuation, RootIndex::kActiveContinuation);
  Register jmpbuf = kScratchReg2;  //  DEFINE_REG(jmpbuf);
  UseScratchRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  __ LoadExternalPointerField(
      jmpbuf,
      FieldMemOperand(continuation, WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);
  FillJumpBuffer(masm, jmpbuf, &resume, scratch);
  SwitchStackState(masm, jmpbuf, scratch, wasm::JumpBuffer::Active,
                   wasm::JumpBuffer::Suspended);
  __ Move(scratch, Smi::FromInt(WasmSuspenderObject::kSuspended));
  __ StoreTaggedField(
      scratch, FieldMemOperand(suspender, WasmSuspenderObject::kStateOffset));
  temps.Include(scratch);
  scratch = no_reg;

  Register suspender_continuation = temps.Acquire();
  __ LoadTaggedField(
      suspender_continuation,
      FieldMemOperand(suspender, WasmSuspenderObject::kContinuationOffset));
  if (v8_flags.debug_code) {
    // -------------------------------------------
    // Check that the suspender's continuation is the active continuation.
    // -------------------------------------------
    // TODO(thibaudm): Once we add core stack-switching instructions, this
    // check will not hold anymore: it's possible that the active continuation
    // changed (due to an internal switch), so we have to update the suspender.
    Label ok;
    __ Branch(&ok, eq, suspender_continuation, Operand(continuation));
    __ Trap();
    __ bind(&ok);
  }
  continuation = no_reg;
  // -------------------------------------------
  // Update roots.
  // -------------------------------------------
  Register caller = kScratchReg;  //   DEFINE_REG(caller);
  __ LoadTaggedField(caller,
                     FieldMemOperand(suspender_continuation,
                                     WasmContinuationObject::kParentOffset));
  int32_t active_continuation_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveContinuation);
  __ StoreWord(caller, MemOperand(kRootRegister, active_continuation_offset));

  temps.Include(suspender_continuation);
  suspender_continuation = no_reg;

  Register parent = temps.Acquire();
  __ LoadTaggedField(
      parent, FieldMemOperand(suspender, WasmSuspenderObject::kParentOffset));
  int32_t active_suspender_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveSuspender);
  __ StoreWord(parent, MemOperand(kRootRegister, active_suspender_offset));
  temps.Include(parent);
  parent = no_reg;
  // -------------------------------------------
  // Load jump buffer.
  // -------------------------------------------
  __ Push(caller, suspender);
  SwitchStacks(masm, no_reg, caller);
  __ Pop(caller, suspender);
  __ LoadExternalPointerField(
      jmpbuf, FieldMemOperand(caller, WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);
  __ LoadTaggedField(
      kReturnRegister0,
      FieldMemOperand(suspender, WasmSuspenderObject::kPromiseOffset));
  MemOperand GCScanSlotPlace =
      MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset);
  __ StoreWord(zero_reg, GCScanSlotPlace);
  scratch = temps.Acquire();

  LoadJumpBuffer(masm, jmpbuf, true, scratch, wasm::JumpBuffer::Inactive);
  __ Trap();
  __ bind(&resume);
  __ LeaveFrame(StackFrame::STACK_SWITCH);
  __ Ret();
}


namespace {
// Resume the suspender stored in the closure. We generate two variants of this
// builtin: the onFulfilled variant resumes execution at the saved PC and
// forwards the value, the onRejected variant throws the value.
#define FREE_REG(x) \
  temps.Include(x); \
  x = no_reg;

void Generate_WasmResumeHelper(MacroAssembler* masm, wasm::OnResume on_resume) {
  UseScratchRegisterScope temps(masm);
  temps.Include(t1, t2);
  __ EnterFrame(StackFrame::STACK_SWITCH);

  Register closure = kJSFunctionRegister;  //  DEFINE_PINNED(closure,
                                           //  kJSFunctionRegister);  // x1

  __ SubWord(
      sp, sp,
      Operand(StackSwitchFrameConstants::kNumSpillSlots * kSystemPointerSize));
  // Set a sentinel value for the spill slots visited by the GC.
  ResetStackSwitchFrameStackSlots(masm);

  // -------------------------------------------
  // Load suspender from closure.
  // -------------------------------------------
  Register sfi = temps.Acquire();
  __ LoadTaggedField(
      sfi,
      MemOperand(
          closure,
          wasm::ObjectAccess::SharedFunctionInfoOffsetInTaggedJSFunction()));
  closure = no_reg;
  // Suspender should be ObjectRegister register to be used in
  // RecordWriteField calls later.
  Register suspender = WriteBarrierDescriptor::ObjectRegister();
  Register resume_data = temps.Acquire();
  __ LoadTaggedField(
      resume_data,
      FieldMemOperand(sfi, SharedFunctionInfo::kUntrustedFunctionDataOffset));
  // The write barrier uses a fixed register for the host object (rdi). The next
  // barrier is on the suspender, so load it in rdi directly.
  __ LoadTaggedField(
      suspender,
      FieldMemOperand(resume_data, WasmResumeData::kSuspenderOffset));
  FREE_REG(resume_data);
  FREE_REG(sfi);
  // Check the suspender state.
  Label suspender_is_suspended;
  Register state = temps.Acquire();
  __ SmiUntag(state,
              FieldMemOperand(suspender, WasmSuspenderObject::kStateOffset));
  __ Branch(&suspender_is_suspended, eq, state,
            Operand(WasmSuspenderObject::kSuspended));
  __ Trap();

  __ bind(&suspender_is_suspended);
  FREE_REG(state);
  // -------------------------------------------
  // Save current state.
  // -------------------------------------------
  Label suspend;
  Register active_continuation = temps.Acquire();
  __ LoadRoot(active_continuation, RootIndex::kActiveContinuation);
  Register current_jmpbuf = temps.Acquire();
  Register scratch = temps.Acquire();

  __ LoadExternalPointerField(
      current_jmpbuf,
      FieldMemOperand(active_continuation,
                      WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);
  FillJumpBuffer(masm, current_jmpbuf, &suspend, scratch);
  SwitchStackState(masm, current_jmpbuf, scratch, wasm::JumpBuffer::Active,
                   wasm::JumpBuffer::Inactive);
  FREE_REG(current_jmpbuf);
  // -------------------------------------------
  // Set the suspender and continuation parents and update the roots
  // -------------------------------------------
  Register active_suspender = kScratchReg;
  __ LoadRoot(active_suspender, RootIndex::kActiveSuspender);
  __ StoreTaggedField(
      active_suspender,
      FieldMemOperand(suspender, WasmSuspenderObject::kParentOffset));
  __ RecordWriteField(suspender, WasmSuspenderObject::kParentOffset,
                      active_suspender, kRAHasBeenSaved,
                      SaveFPRegsMode::kIgnore);
  active_suspender = no_reg;

  __ Move(scratch, Smi::FromInt(WasmSuspenderObject::kActive));
  __ StoreTaggedField(
      scratch, FieldMemOperand(suspender, WasmSuspenderObject::kStateOffset));
  int32_t active_suspender_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveSuspender);
  __ StoreWord(suspender, MemOperand(kRootRegister, active_suspender_offset));

  // Next line we are going to load a field from suspender, but we have to use
  // the same register for target_continuation to use it in RecordWriteField.
  // So, free suspender here to use pinned reg, but load from it next line.
  suspender = no_reg;
  Register target_continuation = WriteBarrierDescriptor::ObjectRegister();
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
  __ StoreWord(target_continuation,
               MemOperand(kRootRegister, active_continuation_offset));

  __ Push(target_continuation);
  SwitchStacks(masm, no_reg, scratch);
  __ Pop(target_continuation);

  // -------------------------------------------
  // Load state from target jmpbuf (longjmp).
  // -------------------------------------------
  Register target_jmpbuf = temps.Acquire();
  __ LoadExternalPointerField(
      target_jmpbuf,
      FieldMemOperand(target_continuation,
                      WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);
  // Move resolved value to return register.
  __ LoadWord(kReturnRegister0, MemOperand(fp, 3 * kSystemPointerSize));
  MemOperand GCScanSlotPlace =
      MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset);
  __ StoreWord(zero_reg, GCScanSlotPlace);
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
  // __ DropArguments(2);
  __ AddWord(sp, sp, Operand(2 * kSystemPointerSize));
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

void SaveState(MacroAssembler* masm, Register active_continuation, Register tmp,
               Label* suspend) {
  ASM_CODE_COMMENT(masm);
  Register jmpbuf = tmp;
  __ LoadExternalPointerField(
      jmpbuf,
      FieldMemOperand(active_continuation,
                      WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);
  UseScratchRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  FillJumpBuffer(masm, jmpbuf, suspend, scratch);
}

void SwitchToAllocatedStack(MacroAssembler* masm, Register wasm_instance,
                            Register wrapper_buffer, Register original_fp,
                            Register new_wrapper_buffer, Label* suspend) {
  ASM_CODE_COMMENT(masm);
  UseScratchRegisterScope temps(masm);

  ResetStackSwitchFrameStackSlots(masm);
  Register scratch = temps.Acquire();
  Register target_continuation = temps.Acquire();
  __ LoadRoot(target_continuation, RootIndex::kActiveContinuation);
  Register parent_continuation = temps.Acquire();
  __ LoadTaggedField(parent_continuation,
                     FieldMemOperand(target_continuation,
                                     WasmContinuationObject::kParentOffset));
  SaveState(masm, parent_continuation, scratch, suspend);
  __ Push(wasm_instance, wrapper_buffer);
  SwitchStacks(masm, no_reg, scratch);
  __ Pop(wasm_instance, wrapper_buffer);
  FREE_REG(parent_continuation);
  // Save the old stack's fp in x9, and use it to access the parameters in
  // the parent frame.
  __ mv(original_fp, fp);
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
  __ SubWord(sp, sp, Operand(stack_space));
  __ mv(new_wrapper_buffer, sp);
  // Copy data needed for return handling from old wrapper buffer to new one.
  // kWrapperBufferRefReturnCount will be copied too, because 8 bytes are copied
  // at the same time.
  static_assert(JSToWasmWrapperFrameConstants::kWrapperBufferRefReturnCount ==
                JSToWasmWrapperFrameConstants::kWrapperBufferReturnCount + 4);
  __ LoadWord(
      scratch,
      MemOperand(wrapper_buffer,
                 JSToWasmWrapperFrameConstants::kWrapperBufferReturnCount));
  __ StoreWord(
      scratch,
      MemOperand(new_wrapper_buffer,
                 JSToWasmWrapperFrameConstants::kWrapperBufferReturnCount));
  __ LoadWord(
      scratch,
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferSigRepresentationArray));
  __ StoreWord(
      scratch,
      MemOperand(
          new_wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferSigRepresentationArray));
}

// Loads the context field of the WasmTrustedInstanceData or WasmImportData
// depending on the data's type, and places the result in the input register.
void GetContextFromImplicitArg(MacroAssembler* masm, Register data,
                               Register scratch) {
  __ LoadTaggedField(scratch, FieldMemOperand(data, HeapObject::kMapOffset));
  Label instance;
  Label end;
  __ GetInstanceTypeRange(scratch, scratch, WASM_TRUSTED_INSTANCE_DATA_TYPE,
                          scratch);
  // __ CompareInstanceType(scratch, scratch, WASM_TRUSTED_INSTANCE_DATA_TYPE);
  __ Branch(&instance, eq, scratch, Operand(zero_reg));
  __ LoadTaggedField(
      data, FieldMemOperand(data, WasmImportData::kNativeContextOffset));
  __ Branch(&end);
  __ bind(&instance);
  __ LoadTaggedField(
      data,
      FieldMemOperand(data, WasmTrustedInstanceData::kNativeContextOffset));
  __ bind(&end);
}

void SwitchBackAndReturnPromise(MacroAssembler* masm, wasm::Promise mode,
                                Label* return_promise) {
  UseScratchRegisterScope temps(masm);
  // The return value of the wasm function becomes the parameter of the
  // FulfillPromise builtin, and the promise is the return value of this
  // wrapper.
  static const Builtin_FulfillPromise_InterfaceDescriptor desc;
  Register promise = desc.GetRegisterParameter(0);
  Register return_value = desc.GetRegisterParameter(1);
  Register tmp = kScratchReg;
  Register tmp2 = kScratchReg2;
  Register tmp3 = temps.Acquire();
  if (mode == wasm::kPromise) {
    __ Move(return_value, kReturnRegister0);
    __ LoadRoot(promise, RootIndex::kActiveSuspender);
    __ LoadTaggedField(
        promise, FieldMemOperand(promise, WasmSuspenderObject::kPromiseOffset));
  }
  __ LoadWord(kContextRegister,
              MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
  GetContextFromImplicitArg(masm, kContextRegister, tmp);

  ReloadParentContinuation(masm, promise, return_value, kContextRegister, tmp,
                           tmp2, tmp3);
  RestoreParentSuspender(masm, tmp, tmp2);

  if (mode == wasm::kPromise) {
    __ li(tmp, 1);
    __ StoreWord(
        tmp, MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset));
    __ Push(promise);
    __ CallBuiltin(Builtin::kFulfillPromise);
    __ Pop(promise);
  }
  tmp = no_reg;
  tmp2 = no_reg;
  __ bind(return_promise);
}

void GenerateExceptionHandlingLandingPad(MacroAssembler* masm,
                                         Label* return_promise) {
  static const Builtin_RejectPromise_InterfaceDescriptor desc;
  Register promise = desc.GetRegisterParameter(0);
  Register reason = desc.GetRegisterParameter(1);
  Register debug_event = desc.GetRegisterParameter(2);
  int catch_handler = __ pc_offset();
  {
    UseScratchRegisterScope temps(masm);
    Register thread_in_wasm_flag_addr = temps.Acquire();
    // Unset thread_in_wasm_flag.
    __ LoadWord(thread_in_wasm_flag_addr,
                MemOperand(kRootRegister,
                           Isolate::thread_in_wasm_flag_address_offset()));
    __ StoreWord(zero_reg, MemOperand(thread_in_wasm_flag_addr, 0));
  }
  // The exception becomes the parameter of the RejectPromise builtin, and the
  // promise is the return value of this wrapper.
  __ mv(reason, kReturnRegister0);
  __ LoadRoot(promise, RootIndex::kActiveSuspender);
  __ LoadTaggedField(
      promise, FieldMemOperand(promise, WasmSuspenderObject::kPromiseOffset));

  __ LoadWord(kContextRegister,
              MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
  Register tmp = kScratchReg;
  Register tmp2 = kScratchReg2;
  UseScratchRegisterScope temps(masm);
  Register tmp3 = temps.Acquire();
  GetContextFromImplicitArg(masm, kContextRegister, tmp);
  ReloadParentContinuation(masm, promise, reason, kContextRegister, tmp, tmp2,
                           tmp3);
  RestoreParentSuspender(masm, tmp, tmp2);

  __ li(tmp, 1);
  __ StoreWord(
      tmp, MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset));
  tmp = no_reg;
  tmp2 = no_reg;
  temps.Include(tmp3);
  tmp3 = no_reg;
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
  __ EnterFrame(stack_switch ? StackFrame::STACK_SWITCH
                             : StackFrame::JS_TO_WASM);

  __ SubWord(
      sp, sp,
      Operand(StackSwitchFrameConstants::kNumSpillSlots * kSystemPointerSize));

  // Load the implicit argument (instance data or import data) from the frame.
  Register implicit_arg = kWasmImplicitArgRegister;
  __ LoadWord(
      implicit_arg,
      MemOperand(fp, JSToWasmWrapperFrameConstants::kImplicitArgOffset));

  Register wrapper_buffer =
      WasmJSToWasmWrapperDescriptor::WrapperBufferRegister();
  Label suspend;
  Register original_fp = kScratchReg;
  Register new_wrapper_buffer = kScratchReg2;
  if (stack_switch) {
    SwitchToAllocatedStack(masm, implicit_arg, wrapper_buffer, original_fp,
                           new_wrapper_buffer, &suspend);
  } else {
    original_fp = fp;
    new_wrapper_buffer = wrapper_buffer;
  }

  {
    __ StoreWord(
        new_wrapper_buffer,
        MemOperand(fp, JSToWasmWrapperFrameConstants::kWrapperBufferOffset));
    if (stack_switch) {
      __ StoreWord(
          implicit_arg,
          MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
      UseScratchRegisterScope temps(masm);
      Register scratch = temps.Acquire();
      __ LoadWord(
          scratch,
          MemOperand(original_fp,
                     JSToWasmWrapperFrameConstants::kResultArrayParamOffset));
      __ StoreWord(
          scratch,
          MemOperand(fp, StackSwitchFrameConstants::kResultArrayOffset));
    }
  }
  {
    UseScratchRegisterScope temps(masm);
    Register result_size = temps.Acquire();
    __ LoadWord(
        result_size,
        MemOperand(wrapper_buffer, JSToWasmWrapperFrameConstants::
                                       kWrapperBufferStackReturnBufferSize));
    // // The `result_size` is the number of slots needed on the stack to store
    // the
    // // return values of the wasm function. If `result_size` is an odd number,
    // we
    // // have to add `1` to preserve stack pointer alignment.
    // __ AddWord(result_size, result_size, 1);
    // __ Bic(result_size, result_size, 1);
    __ SllWord(result_size, result_size, kSystemPointerSizeLog2);
    __ SubWord(sp, sp, Operand(result_size));
  }
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ mv(scratch, sp);
    __ StoreWord(scratch, MemOperand(new_wrapper_buffer,
                                     JSToWasmWrapperFrameConstants::
                                         kWrapperBufferStackReturnBufferStart));
  }
  original_fp = no_reg;
  new_wrapper_buffer = no_reg;

  // The first GP parameter holds the trusted instance data or the import data.
  // This is handled specially.
  int stack_params_offset =
      (arraysize(wasm::kGpParamRegisters) - 1) * kSystemPointerSize +
      arraysize(wasm::kFpParamRegisters) * kDoubleSize;

  {
    UseScratchRegisterScope temps(masm);
    Register params_start = temps.Acquire();
    __ LoadWord(
        params_start,
        MemOperand(wrapper_buffer,
                   JSToWasmWrapperFrameConstants::kWrapperBufferParamStart));
    {
      // Push stack parameters on the stack.
      UseScratchRegisterScope temps(masm);
      Register params_end = kScratchReg;
      __ LoadWord(
          params_end,
          MemOperand(wrapper_buffer,
                     JSToWasmWrapperFrameConstants::kWrapperBufferParamEnd));
      Register last_stack_param = kScratchReg2;

      __ AddWord(last_stack_param, params_start, Operand(stack_params_offset));
      Label loop_start;
      __ bind(&loop_start);

      Label finish_stack_params;
      __ Branch(&finish_stack_params, ge, last_stack_param,
                Operand(params_end));

      // Push parameter
      {
        UseScratchRegisterScope temps(masm);
        Register scratch = temps.Acquire();
        __ SubWord(params_end, params_end, Operand(kSystemPointerSize));
        __ LoadWord(scratch, MemOperand(params_end, 0));
        __ Push(scratch);
      }
      __ Branch(&loop_start);

      __ bind(&finish_stack_params);
    }
    int next_offset = 0;
    for (size_t i = 1; i < arraysize(wasm::kGpParamRegisters); ++i) {
      // Check that {params_start} does not overlap with any of the parameter
      // registers, so that we don't overwrite it by accident with the loads
      // below.
      DCHECK_NE(params_start, wasm::kGpParamRegisters[i]);
      __ LoadWord(wasm::kGpParamRegisters[i],
                  MemOperand(params_start, next_offset));
      next_offset += kSystemPointerSize;
    }

    for (size_t i = 0; i < arraysize(wasm::kFpParamRegisters); ++i) {
      __ LoadDouble(wasm::kFpParamRegisters[i],
                    MemOperand(params_start, next_offset));
      next_offset += kDoubleSize;
    }
    DCHECK_EQ(next_offset, stack_params_offset);
  }

  {
    UseScratchRegisterScope temps(masm);
    Register thread_in_wasm_flag_addr = temps.Acquire();
    __ LoadWord(thread_in_wasm_flag_addr,
                MemOperand(kRootRegister,
                           Isolate::thread_in_wasm_flag_address_offset()));
    Register scratch = temps.Acquire();
    __ li(scratch, 1);
    __ Sw(scratch, MemOperand(thread_in_wasm_flag_addr, 0));
  }
  __ StoreWord(
      zero_reg,
      MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset));
  {
    UseScratchRegisterScope temps(masm);
    Register call_target = temps.Acquire();
    __ LoadWord(
        call_target,
        MemOperand(wrapper_buffer,
                   JSToWasmWrapperFrameConstants::kWrapperBufferCallTarget));
    __ Call(call_target);
  }
  {
    UseScratchRegisterScope temps(masm);
    Register thread_in_wasm_flag_addr = temps.Acquire();
    __ LoadWord(thread_in_wasm_flag_addr,
                MemOperand(kRootRegister,
                           Isolate::thread_in_wasm_flag_address_offset()));
    __ Sw(zero_reg, MemOperand(thread_in_wasm_flag_addr, 0));
  }

  wrapper_buffer = a2;
  __ LoadWord(
      wrapper_buffer,
      MemOperand(fp, JSToWasmWrapperFrameConstants::kWrapperBufferOffset));

  __ StoreDouble(
      wasm::kFpReturnRegisters[0],
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferFPReturnRegister1));
  __ StoreDouble(
      wasm::kFpReturnRegisters[1],
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferFPReturnRegister2));
  __ StoreWord(
      wasm::kGpReturnRegisters[0],
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister1));
  __ StoreWord(
      wasm::kGpReturnRegisters[1],
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister2));
  // Call the return value builtin with
  // x0: wasm instance.
  // x1: the result JSArray for multi-return.
  // x2: pointer to the byte buffer which contains all parameters.
  if (stack_switch) {
    __ LoadWord(a1,
                MemOperand(fp, StackSwitchFrameConstants::kResultArrayOffset));
    __ LoadWord(a0,
                MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
  } else {
    __ LoadWord(
        a1,
        MemOperand(fp, JSToWasmWrapperFrameConstants::kResultArrayParamOff
```