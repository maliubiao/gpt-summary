Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/builtins/x64/builtins-x64.cc`.

Here's a breakdown of the code's functionality:

1. **`Builtins::Generate_CEntry`**: Handles calls from JavaScript to C++ runtime functions. It sets up the necessary stack frame, manages arguments, calls the C++ function, and handles potential exceptions.
2. **`Builtins::Generate_WasmHandleStackOverflow`**:  Manages stack overflow situations in WebAssembly. It attempts to grow the stack and, if that fails, calls the runtime for handling.
3. **`Builtins::Generate_DoubleToI`**: Converts a double-precision floating-point number to an integer.
4. **`Builtins::Generate_CallApiCallbackImpl`**:  Handles calls to JavaScript API callbacks. It sets up the arguments for the callback and manages the call.
5. **`Builtins::Generate_CallApiGetter`**: Handles calls to API getter functions. It sets up arguments and calls the getter function.
6. **`Builtins::Generate_DirectCEntry`**:  Marked as unused for this architecture.
7. **`Builtins::Generate_DeoptimizationEntry_Eager` and `Builtins::Generate_DeoptimizationEntry_Lazy`**:  Handle deoptimization, the process of reverting from optimized code to a less optimized version. They save the current state, call into the runtime to create a deoptimizer, and then restore the state to continue execution in the non-optimized code.

Based on the request, I need to:

*   List the functions' functionalities.
*   Check if the filename ends with `.tq` (it doesn't).
*   Determine if the code relates to JavaScript functionality and provide examples if it does.
*   Analyze code logic and provide examples of input/output.
*   Identify common programming errors related to the code.
*   Synthesize a general summary of the provided code.这是 `v8/src/builtins/x64/builtins-x64.cc` 源代码的第 6 部分，它定义了 x64 架构下 V8 引擎内置函数的实现。 这些内置函数是 V8 引擎中用汇编语言编写的关键代码段，用于执行一些底层操作和优化 JavaScript 代码的执行。

以下是这段代码中各个函数的功能归纳：

1. **`Builtins::Generate_CEntry`**:  这个函数负责处理从 JavaScript 代码调用 C++ 运行时函数的情况。
    *   它会建立一个退出框架（Exit Frame），用于保存必要的寄存器状态和管理栈。
    *   它会将 JavaScript 传递的参数准备好，以便 C++ 函数可以访问。
    *   它会调用指定的 C++ 函数。
    *   它会处理 C++ 函数的返回值，并将其传递回 JavaScript。
    *   如果 C++ 函数抛出异常，它会捕获并处理该异常，跳转到异常处理逻辑。

    **与 JavaScript 的关系和示例：**  当 JavaScript 代码调用 V8 提供的内置函数或者一些需要底层操作的 API 时，最终会通过 `Generate_CEntry` 调用到相应的 C++ 代码。

    ```javascript
    // 例如，调用 Math.max
    let max_value = Math.max(10, 20);

    // 或者当使用一些需要底层操作的 API 时
    let array = new ArrayBuffer(16);
    ```
    在这些情况下，V8 可能会通过 `Generate_CEntry` 调用 C++ 函数来完成 `Math.max` 的比较或 `ArrayBuffer` 的内存分配。

    **代码逻辑推理：**
    *   **假设输入：**  JavaScript 调用了一个需要两个参数的 C++ 运行时函数，参数分别为整数 5 和 10。
    *   **输出：**  `Generate_CEntry` 会将 5 和 10 放入特定的寄存器或栈位置，然后调用 C++ 函数。C++ 函数执行后，其返回值（假设是它们的和 15）会被放回寄存器 `rax` (或其他返回寄存器)。

    **用户常见的编程错误：**  虽然用户不会直接编写 `Generate_CEntry` 内部的代码，但错误的 JavaScript 调用可能会导致 `Generate_CEntry` 中调用的 C++ 函数出错，例如：
    *   传递了错误类型的参数给内置函数。
    *   调用了参数数量不匹配的函数。

2. **`Builtins::Generate_WasmHandleStackOverflow`**:  这个函数专门处理 WebAssembly 代码执行过程中发生的栈溢出错误。
    *   它会尝试调用 C++ 函数 `wasm_grow_stack` 来增加 WebAssembly 实例的栈大小。
    *   如果栈可以增长，它会调整栈指针和帧指针，然后继续执行。
    *   如果栈无法增长，它会调用 V8 运行时函数 `Runtime::kWasmStackGuard` 来处理栈溢出，通常会导致抛出错误。

    **与 JavaScript 的关系和示例：**  WebAssembly 模块可以在 JavaScript 中加载和执行。当 WebAssembly 代码执行需要的栈空间超过当前分配的大小时，就会触发栈溢出。

    ```javascript
    // 假设有一个 WebAssembly 模块 instance
    // 并且该模块中的某个函数会递归调用自身很多次导致栈溢出
    try {
      instance.exports.recursiveFunction();
    } catch (e) {
      console.error("WebAssembly stack overflow:", e);
    }
    ```

    **代码逻辑推理：**
    *   **假设输入：**  WebAssembly 代码执行时栈空间不足。
    *   **输出：**  `Generate_WasmHandleStackOverflow` 首先尝试调用 `wasm_grow_stack`。 如果 `wasm_grow_stack` 返回非零值（表示栈增长成功），则调整栈指针和帧指针。如果返回零，则调用 `Runtime::kWasmStackGuard`。

    **用户常见的编程错误：**
    *   在 WebAssembly 代码中编写无限递归或深度递归的函数。

3. **`Builtins::Generate_DoubleToI`**:  这个函数将双精度浮点数转换为整数。
    *   它从栈中读取双精度浮点数的尾数和指数部分。
    *   它使用位操作和浮点数指令来执行转换。
    *   它处理正数和负数的情况。
    *   结果被放回栈中。

    **与 JavaScript 的关系和示例：**  当 JavaScript 代码需要将浮点数转换为整数时，例如使用 `parseInt` 或进行位运算时，可能会调用此函数。

    ```javascript
    let float_num = 3.14;
    let int_num = parseInt(float_num); // 或者 Math.trunc(float_num) 等
    let bitwise_or = float_num | 0; // 将浮点数转换为整数的位运算
    ```

    **代码逻辑推理：**
    *   **假设输入：**  栈上存储了一个双精度浮点数 `3.7`。
    *   **输出：**  `Generate_DoubleToI` 会将 `3.7` 转换为整数 `3`，并将结果存储回栈中。

    **用户常见的编程错误：**
    *   期望浮点数到整数的转换是四舍五入，但实际 JavaScript 的 `parseInt` 或位运算是截断。
    *   未考虑浮点数的范围，可能导致转换后的整数溢出。

4. **`Builtins::Generate_CallApiCallbackImpl`**:  这个函数处理从 C++ 代码调用 JavaScript API 回调函数的情况。
    *   它设置 `FunctionCallbackInfo` 对象，该对象包含回调函数的参数、接收者、上下文等信息。
    *   它调用实际的 JavaScript 回调函数。
    *   它处理回调函数的返回值。

    **与 JavaScript 的关系和示例：**  当使用 V8 的 C++ API (如 Node.js 的 Addon) 定义 JavaScript 函数作为回调时，从 C++ 代码调用这些回调函数会经过 `Generate_CallApiCallbackImpl`。

    ```javascript
    // 在 Node.js Addon 中定义了一个 C++ 函数，该函数会调用 JavaScript 回调
    // 假设 addon.callCallback(callback, arg1, arg2);

    function myCallback(a, b) {
      console.log("Callback called with:", a, b);
    }

    addon.callCallback(myCallback, "hello", 123);
    ```

    **代码逻辑推理：**
    *   **假设输入：**  C++ 代码需要调用一个带有两个参数 "hello" 和 123 的 JavaScript 回调函数 `myCallback`。
    *   **输出：**  `Generate_CallApiCallbackImpl` 会创建一个 `FunctionCallbackInfo` 对象，将 "hello" 和 123 作为参数放入，然后调用 `myCallback` 函数。

    **用户常见的编程错误：**
    *   在 C++ 中传递了错误数量或类型的参数给 JavaScript 回调函数。
    *   JavaScript 回调函数中抛出未捕获的异常。

5. **`Builtins::Generate_CallApiGetter`**:  这个函数处理调用 JavaScript API 属性的 getter 函数的情况。
    *   它设置 `PropertyCallbackInfo` 对象，该对象包含属性的名称、接收者、持有者等信息。
    *   它调用 JavaScript 的 getter 函数。
    *   它处理 getter 函数的返回值。

    **与 JavaScript 的关系和示例：**  当使用 V8 的 C++ API 定义对象的访问器属性（getter）时，读取这些属性会经过 `Generate_CallApiGetter`。

    ```javascript
    // 在 Node.js Addon 中定义了一个带有 getter 的对象
    // 假设 addon.myObject.myProperty;  // 这会触发 getter

    const myObject = {
      get myProperty() {
        console.log("Getter called!");
        return "property value";
      }
    };
    ```

    **代码逻辑推理：**
    *   **假设输入：**  JavaScript 代码尝试读取一个由 C++ API 定义的对象的属性，该属性有一个 getter 函数。
    *   **输出：**  `Generate_CallApiGetter` 会创建一个 `PropertyCallbackInfo` 对象，包含属性名称等信息，然后调用 JavaScript 的 getter 函数。getter 函数的返回值会被返回。

    **用户常见的编程错误：**
    *   在 C++ 中定义的 getter 函数逻辑错误。
    *   JavaScript getter 函数中抛出未捕获的异常。

6. **`Builtins::Generate_DirectCEntry`**:  在这个架构下未使用。

7. **`Builtins::Generate_DeoptimizationEntry_Eager` 和 `Builtins::Generate_DeoptimizationEntry_Lazy`**:  这两个函数处理代码的反优化（Deoptimization）过程。
    *   它们保存当前的 CPU 寄存器和浮点寄存器的状态。
    *   它们调用 C++ 的反优化器来计算恢复到未优化代码所需的帧。
    *   它们恢复栈和寄存器的状态到未优化代码执行的状态。
    *   `Eager` 反优化通常发生在代码被认为不再优化有效时，而 `Lazy` 反优化发生在需要某些未优化代码才有的信息时。

    **与 JavaScript 的关系和示例：**  当 V8 引擎的优化编译器（TurboFan 或 Crankshaft）生成的优化代码由于某些原因（例如类型假设失败）不再适用时，会发生反优化，退回到解释执行或基线编译的代码。用户通常不会直接感知到反优化，但这会影响性能。

    ```javascript
    function add(a, b) {
      return a + b;
    }

    // 假设 V8 优化了 add 函数，认为 a 和 b 总是数字
    add(1, 2); // 优化执行

    // 如果之后调用 add 函数时传入了非数字类型
    add("hello", "world"); // 可能会触发反优化
    ```

    **代码逻辑推理：**
    *   **假设输入：**  V8 引擎判断当前正在执行的优化代码需要进行反优化。
    *   **输出：**  `Generate_DeoptimizationEntry_Eager` 或 `Generate_DeoptimizationEntry_Lazy` 会保存当前状态，调用反优化器，然后恢复到未优化代码的执行入口点。

    **用户常见的编程错误：**
    *   编写类型不稳定的 JavaScript 代码，导致 V8 的类型预测失败，频繁触发反优化，影响性能。

**总结：**

`v8/src/builtins/x64/builtins-x64.cc` 的这一部分定义了 x64 架构下 V8 引擎的关键底层操作的实现，包括与 C++ 运行时函数的交互、WebAssembly 栈溢出处理、数据类型转换（如浮点数转整数）、以及处理 JavaScript API 回调和代码反优化。这些内置函数是 V8 引擎高效执行 JavaScript 和 WebAssembly 代码的基础。

### 提示词
```
这是目录为v8/src/builtins/x64/builtins-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/x64/builtins-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
isterResultSize = 1;
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