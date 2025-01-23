Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/builtins/ia32/builtins-ia32.cc`. I need to analyze each function in the code and describe its purpose. Since this is part 6 of 7, I should also summarize the overall functionality covered in this specific part. I need to check if any of the functions relate to JavaScript functionality and provide JavaScript examples if they do. If there are logical operations, I should provide example inputs and outputs. I also need to identify and illustrate common programming errors that might be related to the code.

Here's a breakdown of the functions in the snippet and my plan for each:

1. **`Generate_WasmStackGuard`**: This function seems to handle stack overflow situations in WebAssembly. It checks the stack limit and potentially calls the runtime. I'll describe the stack check logic and the runtime call. I'll provide a hypothetical scenario for stack overflow in WebAssembly.

2. **`Generate_DoubleToI`**:  This function converts a double-precision floating-point number to an integer. I need to explain the steps involved, including handling of positive/negative numbers, large/small exponents, and the use of SSE3 instructions if available. I'll illustrate with JavaScript `parseInt()` or `Math.floor()` examples. I'll also give example inputs (e.g., 3.14, -2.7, 1e10) and their expected integer outputs. A common error would be assuming all doubles can be perfectly represented as integers.

3. **`Generate_CallApiCallbackImpl`**: This function appears to handle calls from JavaScript to native C++ functions (API callbacks). I'll explain how it sets up the arguments for the C++ function call, including `FunctionCallbackInfo`. A common mistake is not handling arguments correctly in the C++ callback.

4. **`Generate_CallApiGetter`**:  Similar to the previous function, but specifically for API getters. It sets up arguments for a C++ getter function, including `PropertyCallbackInfo`. A common error is not returning a value from the getter.

5. **`Generate_DirectCEntry`**: This function contains `__ int3()`, which is typically a breakpoint instruction. It's likely a placeholder or for debugging purposes. I'll note that it's unused on this architecture.

6. **`Generate_MemMove`**: This implements a memory move operation (like `memcpy`). I'll outline the different optimization strategies used based on the size of the memory block and potential overlap. A common error is incorrect size calculation or dealing with overlapping memory regions. I'll provide examples of how `memmove` would be used in C/C++, though there's no direct equivalent in JavaScript.

7. **`Generate_DeoptimizationEntry`**: This function handles deoptimization, a process where the optimized code needs to fall back to a less optimized version. I'll explain the steps involved in saving registers and setting up the deoptimizer object.

Finally, I will summarize the functions described in this part of the file.
This C++ code snippet from `v8/src/builtins/ia32/builtins-ia32.cc` defines various built-in functions specific to the IA32 (x86 32-bit) architecture within the V8 JavaScript engine. These built-ins are highly optimized assembly code routines that handle fundamental operations and interactions between JavaScript and the underlying system.

Here's a breakdown of the functionality of each function:

**1. `Generate_WasmStackGuard(MacroAssembler* masm)`**

*   **Functionality:** This function implements a stack guard mechanism for WebAssembly (Wasm) code execution. It checks if the current stack pointer is close to the stack limit. If it is, it calls a runtime function (`Runtime::kWasmStackGuard`) to either grow the stack or handle a stack overflow.
*   **Relationship to JavaScript:** This directly relates to the execution of WebAssembly code within a JavaScript environment. JavaScript can load and execute Wasm modules.
*   **Code Logic:**
    *   It calculates the remaining stack space (`gap`).
    *   If the `gap` is above a threshold, it marks the frame as a WASM segment start and returns.
    *   If the `gap` is below the threshold, it calls the `kWasmStackGuard` runtime function.
*   **Hypothetical Input and Output:**
    *   **Input:**  The current stack pointer (`esp`), the stack limit stored in the `Isolate`.
    *   **Output:**
        *   If stack is sufficient: The function returns, allowing Wasm execution to continue.
        *   If stack is near limit: A call to the `kWasmStackGuard` runtime function is made. This runtime function might grow the stack or throw a stack overflow error.
*   **User Common Programming Error:** In JavaScript when working with WebAssembly, a common error leading to stack overflow is deeply recursive function calls within the Wasm module or calls that allocate excessively large data structures on the stack.
    ```javascript
    // JavaScript example loading and calling a Wasm function that might cause stack overflow
    async function runWasm() {
      const response = await fetch('my_wasm_module.wasm');
      const buffer = await response.arrayBuffer();
      const module = await WebAssembly.instantiate(buffer);
      try {
        module.instance.exports.recursiveFunction(1000); // Deep recursion
      } catch (error) {
        console.error("Error during Wasm execution:", error);
      }
    }
    runWasm();
    ```

**2. `Builtins::Generate_DoubleToI(MacroAssembler* masm)`**

*   **Functionality:** This function converts a double-precision floating-point number (represented as a `HeapNumber` in V8) to an integer. It handles different cases based on the exponent of the double to perform the conversion efficiently.
*   **Relationship to JavaScript:** JavaScript's `parseInt()`, `Math.floor()`, `Math.ceil()`, and bitwise operators implicitly perform conversions from floating-point numbers to integers.
*   **Code Logic:**
    *   It extracts the mantissa and exponent from the `HeapNumber`.
    *   It checks the exponent to determine if the integer part fits within 32 bits.
    *   If it fits, it performs bitwise shifts to extract the integer.
    *   If it doesn't fit within the lower 32 bits, and SSE3 is available, it uses `fisttp_d` to perform the conversion. Otherwise, it uses manual bit manipulation.
    *   It handles negative numbers by negating the result.
*   **Hypothetical Input and Output:**
    *   **Input:** A `HeapNumber` representing a double (e.g., 3.14, -2.7, 1e10).
    *   **Output:** The integer representation of the double.
        *   `3.14` -> `3`
        *   `-2.7` -> `-2`
        *   `1e10` -> `10000000000`
*   **User Common Programming Error:**  Assuming that all double values can be perfectly represented as integers within the safe integer range of JavaScript can lead to unexpected results due to floating-point precision.
    ```javascript
    let doubleValue = 9007199254740992; // A large number near the limit
    let intValue = parseInt(doubleValue);
    console.log(intValue); // Output might be 9007199254740992 (or similar), but precision might be lost

    doubleValue = 0.1 + 0.2; // A classic floating-point imprecision
    intValue = parseInt(doubleValue);
    console.log(intValue); // Output will be 0, not the expected 0.3 (or rounded value)
    ```

**3. `Builtins::Generate_CallApiCallbackImpl(MacroAssembler* masm, CallApiCallbackMode mode)`**

*   **Functionality:** This function handles the execution of API callbacks – calls from JavaScript to native C++ functions registered through V8's API (e.g., using `v8::FunctionTemplate`). It sets up the necessary environment and arguments for calling the C++ function.
*   **Relationship to JavaScript:** This is fundamental to extending JavaScript functionality with native code. Node.js addons heavily rely on this mechanism.
*   **Code Logic:**
    *   It retrieves the API function address, argument count, `FunctionTemplateInfo`, and holder object.
    *   It sets up the `FunctionCallbackInfo` structure on the stack, which contains arguments, receiver, context, etc., needed by the C++ callback function.
    *   It enters an exit frame and calls the C++ function.
    *   It handles profiling if enabled.
*   **User Common Programming Error:**  Incorrectly defining the signature of the C++ callback function or failing to access arguments correctly through the `FunctionCallbackInfo` object are common errors.
    ```c++
    // Example C++ API callback (simplified)
    void MyCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
      v8::Isolate* isolate = args.GetIsolate();
      v8::Local<v8::Context> context = isolate->GetCurrentContext();

      if (args.Length() > 0) {
        v8::Local<v8::Value> arg0 = args[0];
        // ... process arg0 ...
      } else {
        isolate->ThrowException(v8::String::NewFromUtf8Literal(isolate, "Expected at least one argument"));
      }
      args.GetReturnValue().Set(v8::String::NewFromUtf8Literal(isolate, "Hello from C++"));
    }

    // JavaScript example calling the API callback
    myObject.myNativeFunction("some argument");
    ```
    A common error is accessing `args[0]` without checking `args.Length()`, potentially leading to out-of-bounds access.

**4. `Builtins::Generate_CallApiGetter(MacroAssembler* masm)`**

*   **Functionality:** This function is similar to `Generate_CallApiCallbackImpl` but specifically handles API getters. When a JavaScript property access triggers a getter defined through V8's API (using `v8::Accessor`), this function orchestrates the call to the corresponding C++ getter function.
*   **Relationship to JavaScript:** This enables native code to provide custom logic for retrieving JavaScript property values.
*   **Code Logic:**
    *   It retrieves the receiver, holder, and accessor information.
    *   It sets up the `PropertyCallbackArguments` structure on the stack, containing information about the property being accessed.
    *   It enters an exit frame and calls the C++ getter function.
*   **User Common Programming Error:** Forgetting to set the return value using `args.GetReturnValue().Set(...)` in the C++ getter is a common mistake.
    ```c++
    // Example C++ API getter
    void MyGetter(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
      v8::Isolate* isolate = info.GetIsolate();
      // ... perform some logic to get the value ...
      info.GetReturnValue().Set(v8::String::NewFromUtf8Literal(isolate, "Getter Value"));
      // ERROR: forgetting the line above will lead to undefined in JavaScript
    }

    // JavaScript example triggering the getter
    console.log(myObject.myProperty);
    ```

**5. `Builtins::Generate_DirectCEntry(MacroAssembler* masm)`**

*   **Functionality:** This function currently contains `__ int3()`, which is an instruction that triggers a breakpoint (software interrupt). It's likely a placeholder or a point for debugging and is generally unused in normal execution.
*   **Relationship to JavaScript:**  Not directly related to typical JavaScript code. It's an internal V8 mechanism.

**6. `Builtins::Generate_MemMove(MacroAssembler* masm)`**

*   **Functionality:** This function implements a highly optimized version of the `memmove` function, which copies a block of memory from a source location to a destination location. It handles potential overlapping memory regions correctly.
*   **Relationship to JavaScript:** While JavaScript doesn't have direct memory manipulation like C++, this function is used internally by V8 for operations like string manipulation, array manipulation, and copying data structures.
*   **Code Logic:**
    *   It handles different sizes of memory blocks with specialized code paths for efficiency.
    *   It checks for overlapping source and destination regions and copies backward if necessary to avoid overwriting data.
    *   It uses optimized instructions like `movdqu` (move unaligned double quadword) and `movdqa` (move aligned double quadword) for fast copying.
*   **Hypothetical Input and Output:**
    *   **Input:**  Source memory address, destination memory address, number of bytes to copy.
    *   **Output:** The destination memory region will contain a copy of the source memory region.
*   **User Common Programming Error:** In lower-level programming (like C/C++ where `memmove` is commonly used), errors include:
    *   **Incorrect size calculation:** Copying too few or too many bytes.
    *   **Incorrect pointer arithmetic:** Passing invalid source or destination pointers.
    *   **Not handling overlapping regions correctly (using `memcpy` instead of `memmove` when overlap exists).**

**7. `Builtins::Generate_DeoptimizationEntry(MacroAssembler* masm, DeoptimizeKind deopt_kind)`**

*   **Functionality:** This function handles the process of deoptimization. When the optimized (compiled) code encounters a situation where it can no longer proceed safely or efficiently (e.g., type assumptions are violated), it needs to fall back to the unoptimized (interpreted) version of the code. This function sets up the deoptimization process.
*   **Relationship to JavaScript:**  While invisible to the JavaScript programmer, deoptimization is a crucial mechanism for ensuring the correctness of JIT-compiled JavaScript code.
*   **Code Logic:**
    *   It saves the current register values.
    *   It allocates a `Deoptimizer` object.
    *   It populates the `Deoptimizer` object with the necessary information about the current execution state, such as register values, stack pointer, and the reason for deoptimization.
    *   It transitions execution back to the interpreter.

**Summary of Functionality in this Part (Part 6 of 7):**

This part of the `builtins-ia32.cc` file focuses on several low-level operations essential for the V8 engine on the IA32 architecture:

*   **WebAssembly Stack Management:**  Ensuring WebAssembly code doesn't overflow the stack.
*   **Type Conversion:** Efficiently converting double-precision floating-point numbers to integers.
*   **Native Code Integration:** Handling calls between JavaScript and native C++ functions (API callbacks and getters).
*   **Memory Manipulation:** Providing a highly optimized memory copy routine (`memmove`).
*   **Deoptimization:**  Managing the fallback from optimized code to the interpreter when necessary.

These built-ins are crucial for performance and the correct interaction between JavaScript and the underlying system and native extensions. The use of assembly language allows for fine-grained control and optimization for the specific architecture.

### 提示词
```
这是目录为v8/src/builtins/ia32/builtins-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/ia32/builtins-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
, kReturnRegister0);
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