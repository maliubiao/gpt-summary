Response:
The user wants to understand the functionality of a specific part of the V8 source code, `v8/src/wasm/interpreter/arm64/interpreter-builtins-arm64.cc`, and relate it to JavaScript concepts and potential programming errors.

Here's a breakdown of the thought process to analyze the provided code snippet:

1. **Identify the core function:** The code snippet consists of two C++ functions, `Generate_WasmInterpreterToJsWrapper` and `Generate_WasmInterpreterCWasmEntry`, both within the `Builtins` namespace and operating on `MacroAssembler`. This strongly suggests they are involved in generating assembly code for specific built-in functionalities.

2. **Analyze `Generate_WasmInterpreterToJsWrapper`:**
    * **Purpose from the name:** The name implies this function handles the transition from the WebAssembly interpreter to JavaScript.
    * **Stack frame setup:** The code sets up a `StackFrame::JS_TO_WASM`, indicating this is the entry point from JS into the Wasm world.
    * **Parameter handling:** It retrieves parameters (`param_count`) and iterates through them (`convert_parameters` loop). The code differentiates how it handles different Wasm value types (i32, i64, f32, f64, ref). It converts these Wasm types into their JavaScript equivalents (Smi, HeapNumber, BigInt, Number, JS Object).
    * **Return value handling:** It retrieves return values (`return_count`) and iterates through them (`convert_return_value` loop). Similarly to parameters, it converts JavaScript values back to Wasm types. It handles single and multiple return values (using a `FixedArray` for multiple).
    * **Built-in calls:** It makes calls to other V8 built-ins like `WasmInt32ToHeapNumber`, `I64ToBigInt`, `WasmFloat32ToNumber`, `WasmFloat64ToNumber`, and potentially `WasmFuncRefToJS`. These calls are crucial for type conversion and object creation.
    * **Key registers:**  Pay attention to registers like `return_value`, `current_return_slot`, `valuetypes_array_ptr`, `wasm_instance`, `fixed_array`, and `jsarray`. These hold important intermediate values and objects.
    * **Jump labels:** Labels like `smi`, `to_heapnumber`, `return_kWasmI64`, etc., indicate different code paths based on the type of the value being handled.
    * **Stack manipulation:** The function uses `Push`, `Pop`, `Ldr`, `Str`, `Add`, and `Sub` instructions extensively to manage data on the stack.
    * **Summary of functionality:** This function bridges the gap between the Wasm interpreter and JavaScript by converting parameters and return values between their respective type systems.

3. **Analyze `Generate_WasmInterpreterCWasmEntry`:**
    * **Purpose from the name:**  "CWasmEntry" suggests this is the entry point when calling a Wasm function from C/C++.
    * **Stack frame setup:**  It sets up a `StackFrame::C_WASM_ENTRY`.
    * **Callee-saved registers:** The function saves and restores callee-saved registers, a standard practice in function prologues and epilogues to maintain register state.
    * **Exception handling:** The presence of `handler_entry` and calls to `BindExceptionHandler` indicate this function sets up a try-catch-like mechanism for handling exceptions during the Wasm call.
    * **Invocation:** It calls `GenericWasmToJSInterpreterWrapper`, implying that even calls from C eventually go through a similar JS-Wasm transition process.
    * **Summary of functionality:** This function provides an entry point for calling Wasm functions from C/C++, handling stack setup, register saving, and exception management before invoking the actual Wasm function (likely through a JS wrapper).

4. **Relate to JavaScript:**
    * **Wasm to JS conversion:**  The parameter and return value conversions in `Generate_WasmInterpreterToJsWrapper` directly relate to how JavaScript interacts with Wasm. When a Wasm function is called from JS, or vice-versa, values need to be transformed.
    * **JavaScript examples:**  Illustrate how different Wasm types map to JavaScript types in function calls.
    * **Common errors:**  Think about type mismatches between Wasm and JS as common errors.

5. **Code logic reasoning (hypothetical inputs/outputs):**  Choose a simple example, like a Wasm function returning an `i32`. Trace the code flow for that specific type.

6. **`.tq` check:** Determine if the file extension ends with `.tq`. In this case, it's `.cc`, so it's not Torque.

7. **Synthesize the information for Part 2:**  Focus on summarizing the functionalities of the provided code snippet, referencing the analyses of the two functions. Emphasize their roles in the Wasm-JS interface and the C-Wasm entry point.

**(Self-correction during the process):**

* **Initial thought:** Might initially focus too much on the assembly instructions.
* **Correction:** Realize the higher-level purpose of the functions is more important for understanding the functionality. Focus on *what* the assembly code is achieving rather than the specific instructions.
* **Clarification:**  The `GenericWasmToJSInterpreterWrapper` being called from `Generate_WasmInterpreterCWasmEntry` clarifies the relationship between the two entry points. Calls from C are likely going through a similar conversion path as calls from JS.

By following these steps, the detailed analysis and the final summary of the code snippet's functionality can be generated.
Based on the provided code snippet from `v8/src/wasm/interpreter/arm64/interpreter-builtins-arm64.cc`, here's a breakdown of its functionality:

**Overall Functionality:**

This code defines two built-in functions for the WebAssembly interpreter on ARM64 architecture, which handle the transitions between WebAssembly code and JavaScript or C/C++ code. These transitions are crucial for enabling WebAssembly modules to interact with the JavaScript environment and for calling WebAssembly functions from native code.

**Detailed Functionality of Each Part:**

**1. `Generate_WasmInterpreterToJsWrapper(MacroAssembler* masm)`:**

* **Purpose:** This function generates assembly code that acts as a wrapper when calling a JavaScript function from WebAssembly code (Wasm-to-JS call). It's responsible for:
    * **Setting up the stack frame:**  It creates a `StackFrame::JS_TO_WASM` to manage the transition.
    * **Converting Wasm parameters to JavaScript types:** It iterates through the parameters of the Wasm function call and converts them to their corresponding JavaScript types. This involves handling different Wasm value types (i32, i64, f32, f64, and references) and potentially converting them to Smi, HeapNumber, BigInt, or JavaScript Number objects.
    * **Calling the JavaScript function:** It uses the `Call_ReceiverIsAny` built-in to invoke the target JavaScript function with the converted arguments.
    * **Converting JavaScript return values back to Wasm types:** After the JavaScript call, it converts the returned JavaScript value(s) back to their corresponding Wasm types. It handles single and multiple return values, potentially using `IterableToFixedArrayForWasm` to collect multiple results.
    * **Cleaning up the stack frame:** It removes the frame and returns control to the Wasm interpreter.

**2. `Generate_WasmInterpreterCWasmEntry(MacroAssembler* masm)`:**

* **Purpose:** This function generates assembly code that serves as an entry point for calling a WebAssembly function from C/C++ code. It's responsible for:
    * **Setting up a C-style stack frame:** It creates a `StackFrame::C_WASM_ENTRY`.
    * **Saving callee-saved registers:** It preserves the values of registers that the C/C++ caller expects to remain unchanged.
    * **Setting up exception handling:** It establishes a try-catch block using `BindExceptionHandler` to handle potential exceptions during the Wasm call.
    * **Calling the Wasm function:** It uses the `GenericWasmToJSInterpreterWrapper` built-in to actually invoke the Wasm function. This suggests that even calls from C/C++ may go through a similar wrapping mechanism as calls from JavaScript, possibly for consistency in handling arguments and return values.
    * **Restoring callee-saved registers:** It restores the saved register values before returning.
    * **Cleaning up the stack frame:** It removes the C-style frame.

**Is it a Torque file?**

The code snippet is from a `.cc` file, not a `.tq` file. Therefore, it's **not** a V8 Torque source code. It's written directly in C++ using V8's `MacroAssembler` to generate assembly instructions.

**Relationship with JavaScript and Examples:**

`Generate_WasmInterpreterToJsWrapper` directly deals with the interaction between WebAssembly and JavaScript. Here's how the type conversions relate and some JavaScript examples:

* **Wasm `i32` to JavaScript Number (or Smi):**
   ```javascript
   // Assume a Wasm function `add(a: i32, b: i32) : i32` is imported into JavaScript.
   const wasmModule = // ... load and instantiate your WASM module ...
   const add = wasmModule.instance.exports.add;

   let result = add(5, 10); // Wasm i32 values 5 and 10 are passed.
   // Inside `Generate_WasmInterpreterToJsWrapper`, these i32 values are likely
   // converted to JavaScript Numbers (or Smis if they are small enough).
   console.log(result); // JavaScript receives the i32 result (potentially converted).
   ```

* **Wasm `i64` to JavaScript BigInt:**
   ```javascript
   // Assume a Wasm function `largeNumber() : i64` exists.
   const wasmModule = // ...
   const largeNumber = wasmModule.instance.exports.largeNumber;

   let bigIntValue = largeNumber();
   // The i64 return value from Wasm is converted to a JavaScript BigInt.
   console.log(typeof bigIntValue); // Output: "bigint"
   ```

* **JavaScript Number to Wasm `f64`:**
   ```javascript
   // Assume a Wasm function `squareRoot(x: f64) : f64` exists.
   const wasmModule = // ...
   const squareRoot = wasmModule.instance.exports.squareRoot;

   let jsNumber = 25.5;
   let wasmResult = squareRoot(jsNumber);
   // The JavaScript Number `jsNumber` is converted to a Wasm f64 before
   // being passed to the Wasm function. The f64 result is likely
   // converted back to a JavaScript Number.
   console.log(wasmResult);
   ```

* **Wasm `ref` to JavaScript Object:**
   This part of the code handles Wasm references. Depending on the specific reference type (e.g., `funcref`), it might be converted to a JavaScript function wrapper.

**Code Logic Reasoning (Hypothetical Input and Output for `Generate_WasmInterpreterToJsWrapper`):**

**Assumption:** A Wasm function `add(a: i32, b: i32) : i32` is being called from JavaScript with arguments `5` and `10`.

**Hypothetical Input (at the start of `Generate_WasmInterpreterToJsWrapper`):**

* `target_js_function` (x0):  A pointer to the JavaScript function object corresponding to the Wasm import.
* `packed_args` (x1): A memory location containing the raw Wasm arguments (the bit representation of 5 and 10 as i32).
* `signature` (x3):  Information about the function's signature (parameter and return types).
* `param_count` (loaded from stack): 2 (the number of parameters).
* `valuetypes_array_ptr` (loaded from signature):  A pointer to an array describing the parameter types (likely `kWasmI32`, `kWasmI32`).

**Hypothetical Output (relevant steps within the function):**

1. **Parameter Conversion Loop:**
   * The code reads the first parameter type (`kWasmI32`).
   * It reads the raw i32 value (5) from `packed_args`.
   * It converts the i32 value 5 to a JavaScript Number (or a Smi).
   * This JavaScript value is stored on the stack as an argument for the JS function call.
   * The process repeats for the second parameter (10).

2. **JavaScript Function Call:**
   * The `Call_ReceiverIsAny` built-in is called with the JavaScript function and the converted arguments on the stack.

3. **Return Value Conversion (assuming the JS function returns 15):**
   * The JavaScript function returns the Number `15`.
   * The code reads the return type from the `signature` (likely `kWasmI32`).
   * It converts the JavaScript Number `15` back to a Wasm i32 value.
   * This i32 value is placed in the `packed_args` area for the Wasm interpreter to retrieve.

**Common Programming Errors Related to this Code:**

These built-ins are designed to handle the boundaries between Wasm and JS. Common errors often arise from mismatches or incorrect assumptions at these boundaries:

* **Type Mismatches:**
    * **JavaScript calling Wasm with incorrect argument types:**
      ```javascript
      // Wasm expects i32, but JavaScript passes a string:
      add("hello", 10); // This could lead to unexpected behavior or errors
      ```
    * **Wasm returning a type that JavaScript doesn't expect or cannot handle directly:** This is less common as V8 generally handles conversions.

* **Range Errors:**
    * **Wasm `i32` values exceeding JavaScript's safe integer range when converted to Number:** While JavaScript Numbers are double-precision floats, converting very large i32 values might lead to precision loss or unexpected behavior if not handled carefully. `BigInt` helps with `i64`.
    * **JavaScript Numbers passed to Wasm that are outside the valid range for a Wasm integer type:**  This can lead to truncation or incorrect values in Wasm.

* **Reference Errors (related to Wasm references):**
    * Passing invalid or null references from JavaScript to Wasm or vice-versa.
    * Incorrectly handling the lifetime of referenced objects.

* **Memory Access Errors (less directly related to this specific code, but relevant to Wasm-JS interaction):**
    * JavaScript attempting to access Wasm memory out of bounds.
    * Wasm attempting to access JavaScript objects in ways that are not permitted.

**Summary of Functionality (Part 2):**

The provided code snippet from `v8/src/wasm/interpreter/arm64/interpreter-builtins-arm64.cc` defines two key built-in functions for the ARM64 WebAssembly interpreter:

1. **`Generate_WasmInterpreterToJsWrapper`**: This function manages the transition from WebAssembly code to JavaScript code. Its primary responsibilities include converting Wasm parameters to their JavaScript equivalents, invoking the target JavaScript function, and converting the JavaScript return value(s) back to Wasm types. This ensures seamless interaction when Wasm calls into the JavaScript environment.

2. **`Generate_WasmInterpreterCWasmEntry`**: This function serves as the entry point when a WebAssembly function is called from C/C++ code. It handles setting up the necessary stack frame, managing callee-saved registers, and establishing exception handling. It then delegates the actual Wasm function invocation to `GenericWasmToJSInterpreterWrapper`, suggesting a unified approach for handling Wasm calls regardless of the caller (JavaScript or C++).

Both functions are crucial for enabling WebAssembly modules to effectively interact with the surrounding environment, whether it's the JavaScript runtime or native C/C++ code. They handle the necessary type conversions and stack management to bridge the gap between these different execution contexts.

### 提示词
```
这是目录为v8/src/wasm/interpreter/arm64/interpreter-builtins-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/arm64/interpreter-builtins-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
__ SmiTag(return_value);
    }
  }
  __ jmp(&return_value_done);

  // Handle the conversion of the I32 return value to HeapNumber when it cannot
  // be a smi.
  __ bind(&to_heapnumber);

  PrepareForWasmToJsConversionBuiltinCall(
      masm, return_count, result_index, current_return_slot,
      valuetypes_array_ptr, wasm_instance, fixed_array, jsarray);
  __ Call(BUILTIN_CODE(masm->isolate(), WasmInt32ToHeapNumber),
          RelocInfo::CODE_TARGET);
  RestoreAfterWasmToJsConversionBuiltinCall(
      masm, jsarray, fixed_array, wasm_instance, valuetypes_array_ptr,
      current_return_slot, result_index, return_count);
  __ jmp(&return_value_done);

  __ bind(&return_kWasmI64);
  __ Ldr(return_value, MemOperand(current_return_slot, 0));
  __ Add(current_return_slot, current_return_slot, Immediate(sizeof(int64_t)));
  PrepareForWasmToJsConversionBuiltinCall(
      masm, return_count, result_index, current_return_slot,
      valuetypes_array_ptr, wasm_instance, fixed_array, jsarray);
  __ Call(BUILTIN_CODE(masm->isolate(), I64ToBigInt), RelocInfo::CODE_TARGET);
  RestoreAfterWasmToJsConversionBuiltinCall(
      masm, jsarray, fixed_array, wasm_instance, valuetypes_array_ptr,
      current_return_slot, result_index, return_count);
  __ jmp(&return_value_done);

  __ bind(&return_kWasmF32);
  __ Ldr(v0, MemOperand(current_return_slot, 0));
  __ Add(current_return_slot, current_return_slot, Immediate(sizeof(float)));
  PrepareForWasmToJsConversionBuiltinCall(
      masm, return_count, result_index, current_return_slot,
      valuetypes_array_ptr, wasm_instance, fixed_array, jsarray);
  __ Call(BUILTIN_CODE(masm->isolate(), WasmFloat32ToNumber),
          RelocInfo::CODE_TARGET);
  RestoreAfterWasmToJsConversionBuiltinCall(
      masm, jsarray, fixed_array, wasm_instance, valuetypes_array_ptr,
      current_return_slot, result_index, return_count);
  __ jmp(&return_value_done);

  __ bind(&return_kWasmF64);
  __ Ldr(d0, MemOperand(current_return_slot, 0));
  __ Add(current_return_slot, current_return_slot, Immediate(sizeof(double)));
  PrepareForWasmToJsConversionBuiltinCall(
      masm, return_count, result_index, current_return_slot,
      valuetypes_array_ptr, wasm_instance, fixed_array, jsarray);
  __ Call(BUILTIN_CODE(masm->isolate(), WasmFloat64ToNumber),
          RelocInfo::CODE_TARGET);
  RestoreAfterWasmToJsConversionBuiltinCall(
      masm, jsarray, fixed_array, wasm_instance, valuetypes_array_ptr,
      current_return_slot, result_index, return_count);
  __ jmp(&return_value_done);

  __ bind(&return_kWasmRef);
  // Make sure slot for ref args are 64-bit aligned.
  __ And(scratch, current_return_slot, Immediate(0x04));
  __ Add(current_return_slot, current_return_slot, scratch);
  __ Ldr(return_value, MemOperand(current_return_slot, 0));
  __ Add(current_return_slot, current_return_slot,
         Immediate(kSystemPointerSize));
  // It might be cleaner to call Builtins_WasmFuncRefToJS here to extract
  // func.external from the ref object if the type is kWasmFuncRef.

  Label next_return_value;

  __ bind(&return_value_done);
  __ Add(valuetypes_array_ptr, valuetypes_array_ptr, Immediate(kValueTypeSize));
  __ Str(valuetypes_array_ptr, MemOperand(fp, kValueTypesArrayStartOffset));
  __ cmp(fixed_array, xzr);
  __ B(&next_return_value, eq);

  // Store result in JSArray
  DEFINE_REG(array_items);
  __ Add(array_items, fixed_array,
         OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag);
  __ StoreTaggedField(return_value, MemOperand(array_items, result_index, LSL,
                                               kTaggedSizeLog2));

  __ bind(&next_return_value);
  __ Add(result_index, result_index, 1);
  __ cmp(result_index, return_count);
  __ B(&convert_return_value, lt);

  __ bind(&all_results_conversion_done);
  ASSIGN_REG(param_count);
  __ Ldr(param_count, MemOperand(fp, kParamCountOffset));  // ???

  Label do_return;
  __ cmp(fixed_array, xzr);
  __ B(&do_return, eq);
  // The result is jsarray.
  __ Mov(return_value, jsarray);

  __ bind(&do_return);
  // Calculate the number of parameters we have to pop off the stack. This
  // number is max(in_param_count, param_count).
  DEFINE_REG(in_param_count);
  __ Ldr(in_param_count, MemOperand(fp, kInParamCountOffset));
  __ cmp(param_count, in_param_count);
  __ csel(param_count, in_param_count, param_count, lt);

  // -------------------------------------------
  // Deconstruct the stack frame.
  // -------------------------------------------
  __ LeaveFrame(StackFrame::JS_TO_WASM);

  // We have to remove the caller frame slots:
  //  - JS arguments
  //  - the receiver
  // and transfer the control to the return address (the return address is
  // expected to be on the top of the stack).
  // We cannot use just the ret instruction for this, because we cannot pass the
  // number of slots to remove in a Register as an argument.
  __ DropArguments(param_count);
  __ Ret(lr);
}

void Builtins::Generate_WasmInterpreterCWasmEntry(MacroAssembler* masm) {
  Label invoke, handler_entry, exit;

  __ EnterFrame(StackFrame::C_WASM_ENTRY);

  // Space to store c_entry_fp and current sp (used by exception handler).
  __ Push(xzr, xzr);

  {
    NoRootArrayScope no_root_array(masm);

    // Push callee saved registers.
    __ Push(d14, d15);
    __ Push(d12, d13);
    __ Push(d10, d11);
    __ Push(d8, d9);
    __ Push(x27, x28);
    __ Push(x25, x26);
    __ Push(x23, x24);
    __ Push(x21, x22);
    __ Push(x19, x20);

    // Set up the reserved register for 0.0.
    __ Fmov(fp_zero, 0.0);

    // Initialize the root register.
    __ Mov(kRootRegister, x2);

#ifdef V8_COMPRESS_POINTERS_IN_SHARED_CAGE
    // Initialize the pointer cage base register.
    __ LoadRootRelative(kPtrComprCageBaseRegister,
                        IsolateData::cage_base_offset());
#endif
  }

  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.AcquireX();
    __ Mov(scratch, sp);
    __ Str(scratch,
           MemOperand(fp, WasmInterpreterCWasmEntryConstants::kSPFPOffset));
  }

  __ Mov(x11, ExternalReference::Create(IsolateAddressId::kCEntryFPAddress,
                                        masm->isolate()));
  __ Ldr(x10, MemOperand(x11));  // x10 = C entry FP.

  __ Str(x10,
         MemOperand(fp, WasmInterpreterCWasmEntryConstants::kCEntryFPOffset));

  // Jump to a faked try block that does the invoke, with a faked catch
  // block that sets the pending exception.
  __ B(&invoke);

  // Prevent the constant pool from being emitted between the record of the
  // handler_entry position and the first instruction of the sequence here.
  // There is no risk because Assembler::Emit() emits the instruction before
  // checking for constant pool emission, but we do not want to depend on
  // that.
  {
    Assembler::BlockPoolsScope block_pools(masm);

    __ BindExceptionHandler(&handler_entry);

    // Store the current pc as the handler offset. It's used later to create the
    // handler table.
    masm->isolate()->builtins()->SetCWasmInterpreterEntryHandlerOffset(
        handler_entry.pos());
  }
  __ B(&exit);

  // Invoke: Link this frame into the handler chain.
  __ Bind(&invoke);

  // Link the current handler as the next handler.
  __ Mov(x11, ExternalReference::Create(IsolateAddressId::kHandlerAddress,
                                        masm->isolate()));
  __ Ldr(x10, MemOperand(x11));
  __ Push(padreg, x10);

  // Set this new handler as the current one.
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.AcquireX();
    __ Mov(scratch, sp);
    __ Str(scratch, MemOperand(x11));
  }

  // Invoke the JS function through the GenericWasmToJSInterpreterWrapper.
  __ Call(BUILTIN_CODE(masm->isolate(), GenericWasmToJSInterpreterWrapper),
          RelocInfo::CODE_TARGET);

  // Pop the stack handler and unlink this frame from the handler chain.
  static_assert(StackHandlerConstants::kNextOffset == 0 * kSystemPointerSize,
                "Unexpected offset for StackHandlerConstants::kNextOffset");
  __ Pop(x10, padreg);
  __ Mov(x11, ExternalReference::Create(IsolateAddressId::kHandlerAddress,
                                        masm->isolate()));
  __ Drop(StackHandlerConstants::kSlotCount - 2);
  __ Str(x10, MemOperand(x11));

  __ Bind(&exit);

  // Pop callee saved registers.
  __ Pop(x20, x19);
  __ Pop(x22, x21);
  __ Pop(x24, x23);
  __ Pop(x26, x25);
  __ Pop(x28, x27);
  __ Pop(d9, d8);
  __ Pop(d11, d10);
  __ Pop(d13, d12);
  __ Pop(d15, d14);

  // Deconstruct the stack frame.
  __ LeaveFrame(StackFrame::C_WASM_ENTRY);
  __ Ret();
}

void Builtins::Generate_GenericWasmToJSInterpreterWrapper(
    MacroAssembler* masm) {
  auto regs = RegisterAllocator::WithAllocatableGeneralRegisters();

  DEFINE_PINNED(target_js_function, x0);
  DEFINE_PINNED(packed_args, x1);
  DEFINE_PINNED(signature, x3);
  DEFINE_PINNED(callable, x5);

  // Set up the stackframe.
  __ EnterFrame(StackFrame::WASM_TO_JS);

  // -------------------------------------------
  // Compute offsets and prepare for GC.
  // -------------------------------------------
  // GenericJSToWasmInterpreterWrapperFrame:
  // sp = fp-N receiver                      ^
  // ...       JS arg 0                      |
  // ...       ...                           | Tagged
  // ...       JS arg n-1                    | objects
  // ...       (padding if num args is odd)  |
  // ...       context                       |
  // fp-0x58   callable                      v
  // -------------------------------------------
  // fp-0x50   current_param_offset/current_result_offset
  // fp-0x48   valuetypes_array_ptr
  //
  // fp-0x40   param_index/return_index
  // fp-0x38   signature
  //
  // fp-0x30   param_count
  // fp-0x28   return_count
  //
  // fp-0x20   packed_array
  // fp-0x18   GC_SP
  //
  // fp-0x10   GCScanSlotCount
  // fp-0x08   Marker(StackFrame::WASM_TO_JS)
  //
  // fp        Old fp
  // fp+0x08   return address

  static_assert(WasmToJSInterpreterFrameConstants::kGCSPOffset ==
                WasmToJSInterpreterFrameConstants::kGCScanSlotCountOffset -
                    kSystemPointerSize);
  constexpr int kPackedArrayOffset =
      WasmToJSInterpreterFrameConstants::kGCSPOffset - kSystemPointerSize;
  constexpr int kReturnCountOffset = kPackedArrayOffset - kSystemPointerSize;
  constexpr int kParamCountOffset = kReturnCountOffset - kSystemPointerSize;
  constexpr int kSignatureOffset = kParamCountOffset - kSystemPointerSize;
  constexpr int kParamIndexOffset = kSignatureOffset - kSystemPointerSize;
  // Reuse this slot when iterating over return values.
  constexpr int kResultIndexOffset = kParamIndexOffset;
  constexpr int kValueTypesArrayStartOffset =
      kParamIndexOffset - kSystemPointerSize;
  constexpr int kCurrentParamOffset =
      kValueTypesArrayStartOffset - kSystemPointerSize;
  // Reuse this slot when iterating over return values.
  constexpr int kCurrentResultOffset = kCurrentParamOffset;
  constexpr int kNumSpillSlots =
      (WasmToJSInterpreterFrameConstants::kGCScanSlotCountOffset -
       kCurrentParamOffset) /
      kSystemPointerSize;
  static_assert((kNumSpillSlots % 2) == 0);  // 16-bytes aligned.

  constexpr int kCallableOffset = kCurrentParamOffset - kSystemPointerSize;

  __ Sub(sp, sp, Immediate(kNumSpillSlots * kSystemPointerSize));

  __ Str(packed_args, MemOperand(fp, kPackedArrayOffset));

  // Store null into the stack slot that will contain sp to be used in GCs that
  // happen during the JS function call. See WasmToJsFrame::Iterate.
  __ Str(xzr, MemOperand(fp, WasmToJSInterpreterFrameConstants::kGCSPOffset));

  // Count the number of tagged objects at the top of the stack that need to be
  // visited during GC.
  __ Str(xzr,
         MemOperand(fp,
                    WasmToJSInterpreterFrameConstants::kGCScanSlotCountOffset));

  DEFINE_REG(shared_function_info);
  __ LoadTaggedField(
      shared_function_info,
      MemOperand(
          target_js_function,
          wasm::ObjectAccess::SharedFunctionInfoOffsetInTaggedJSFunction()));

  // Set the context of the function; the call has to run in the function
  // context.
  DEFINE_REG(context);
  __ LoadTaggedField(
      context, FieldMemOperand(target_js_function, JSFunction::kContextOffset));
  __ Mov(cp, context);

  // Load global receiver if sloppy else use undefined.
  Label receiver_undefined;
  Label calculate_js_function_arity;
  DEFINE_REG(receiver);
  DEFINE_REG(flags);
  __ Ldr(flags, FieldMemOperand(shared_function_info,
                                SharedFunctionInfo::kFlagsOffset));
  __ Tst(flags, Immediate(SharedFunctionInfo::IsNativeBit::kMask |
                          SharedFunctionInfo::IsStrictBit::kMask));
  FREE_REG(flags);
  __ B(&receiver_undefined, ne);
  __ LoadGlobalProxy(receiver);
  __ B(&calculate_js_function_arity);

  __ bind(&receiver_undefined);
  __ LoadRoot(receiver, RootIndex::kUndefinedValue);

  __ bind(&calculate_js_function_arity);

  // Load values from the signature.
  DEFINE_REG(return_count);
  DEFINE_REG(param_count);
  __ Str(signature, MemOperand(fp, kSignatureOffset));
  Register valuetypes_array_ptr = signature;
  LoadFromSignature(masm, valuetypes_array_ptr, return_count, param_count);
  __ Str(param_count, MemOperand(fp, kParamCountOffset));
  FREE_REG(shared_function_info);

  // Store callable and context.
  __ Push(callable, context);

  // Make room to pass the args and the receiver.
  DEFINE_REG(array_size);
  DEFINE_REG(scratch);
  __ Add(array_size, param_count, Immediate(1));
  // Ensure that the array is 16-bytes aligned.
  __ Add(scratch, array_size, Immediate(1));
  __ And(array_size, scratch, Immediate(-2));
  __ Sub(sp, sp, Operand(array_size, LSL, kSystemPointerSizeLog2));

  // The number of arguments at the top of the stack that need to be visited
  // during GC, also counting callable and context.
  __ Add(scratch, array_size, Immediate(2));
  __ Str(scratch,
         MemOperand(fp,
                    WasmToJSInterpreterFrameConstants::kGCScanSlotCountOffset));

  // Make sure that the padding slot (if present) is reset to zero. The other
  // slots will be initialized with the arguments.
  __ Sub(scratch, array_size, Immediate(1));
  __ Str(xzr, MemOperand(sp, scratch, LSL, kSystemPointerSizeLog2));
  FREE_REG(array_size);

  DEFINE_REG(param_index);
  __ Mov(param_index, xzr);

  // Store the receiver at the top of the stack.
  __ Str(receiver, MemOperand(sp, 0));

  // -------------------------------------------
  // Store signature-related values to the stack.
  // -------------------------------------------
  // We store values on the stack to restore them after function calls.
  __ Str(return_count, MemOperand(fp, kReturnCountOffset));
  __ Str(valuetypes_array_ptr, MemOperand(fp, kValueTypesArrayStartOffset));

  Label prepare_for_js_call;
  __ Cmp(param_count, 0);
  // If we have 0 params: jump through parameter handling.
  __ B(&prepare_for_js_call, eq);

  // Loop through the params starting with the first.
  DEFINE_REG(current_param_slot_offset);
  __ Mov(current_param_slot_offset, Immediate(0));

  // We have to check the types of the params. The ValueType array contains
  // first the return then the param types.

  // Set the ValueType array pointer to point to the first parameter.
  constexpr int kValueTypeSize = sizeof(wasm::ValueType);
  static_assert(kValueTypeSize == 4);
  const int32_t kValueTypeSizeLog2 = log2(kValueTypeSize);
  __ Add(valuetypes_array_ptr, valuetypes_array_ptr,
         Operand(return_count, LSL, kValueTypeSizeLog2));
  DEFINE_REG_W(valuetype);

  // -------------------------------------------
  // Copy reference type params first and initialize the stack for JS arguments.
  // -------------------------------------------

  // Heap pointers for ref type values in packed_args can be invalidated if GC
  // is triggered when converting wasm numbers to JS numbers and allocating
  // heap numbers. So, we have to move them to the stack first.
  Register param = target_js_function;  // x0
  {
    Label loop_copy_param_ref, load_ref_param, set_and_move;

    __ bind(&loop_copy_param_ref);
    __ Ldr(valuetype, MemOperand(valuetypes_array_ptr,
                                 wasm::ValueType::bit_field_offset()));
    __ And(valuetype, valuetype, Immediate(wasm::kWasmValueKindBitsMask));
    __ cmp(valuetype, Immediate(wasm::ValueKind::kRefNull));
    __ B(&load_ref_param, eq);
    __ cmp(valuetype, Immediate(wasm::ValueKind::kRef));
    __ B(&load_ref_param, eq);

    // Initialize non-ref type slots to zero since they can be visited by GC
    // when converting wasm numbers into heap numbers.
    __ Mov(param, Smi::zero());

    Label inc_param_32bit;
    __ cmp(valuetype, Immediate(wasm::kWasmI32.raw_bit_field()));
    __ B(&inc_param_32bit, eq);
    __ cmp(valuetype, Immediate(wasm::kWasmF32.raw_bit_field()));
    __ B(&inc_param_32bit, eq);

    Label inc_param_64bit;
    __ cmp(valuetype, Immediate(wasm::kWasmI64.raw_bit_field()));
    __ B(&inc_param_64bit, eq);
    __ cmp(valuetype, Immediate(wasm::kWasmF64.raw_bit_field()));
    __ B(&inc_param_64bit, eq);

    // Invalid type. Wasm cannot pass Simd arguments to JavaScript.
    __ DebugBreak();

    __ bind(&inc_param_32bit);
    __ Add(current_param_slot_offset, current_param_slot_offset,
           Immediate(sizeof(int32_t)));
    __ B(&set_and_move);

    __ bind(&inc_param_64bit);
    __ Add(current_param_slot_offset, current_param_slot_offset,
           Immediate(sizeof(int64_t)));
    __ B(&set_and_move);

    __ bind(&load_ref_param);
    // No need to align packed_args for ref values in wasm-to-js, because the
    // alignment is only required for GC code that visits the stack, and in this
    // case we are storing into the stack only heap (or Smi) objects, always
    // aligned.
    __ Ldr(param, MemOperand(packed_args, current_param_slot_offset));
    __ Add(current_param_slot_offset, current_param_slot_offset,
           Immediate(kSystemPointerSize));

    __ bind(&set_and_move);
    __ Add(param_index, param_index, 1);
    // Pre-increment param_index to skip receiver slot.
    __ Str(param, MemOperand(sp, param_index, LSL, kSystemPointerSizeLog2));
    __ Add(valuetypes_array_ptr, valuetypes_array_ptr,
           Immediate(kValueTypeSize));
    __ Cmp(param_index, param_count);
    __ B(&loop_copy_param_ref, lt);
  }

  // Reset pointers for the second param conversion loop.
  __ Ldr(return_count, MemOperand(fp, kReturnCountOffset));
  __ Ldr(valuetypes_array_ptr, MemOperand(fp, kValueTypesArrayStartOffset));
  __ Add(valuetypes_array_ptr, valuetypes_array_ptr,
         Operand(return_count, LSL, kValueTypeSizeLog2));
  __ Mov(current_param_slot_offset, xzr);
  __ Mov(param_index, xzr);

  // -------------------------------------------
  // Param evaluation loop.
  // -------------------------------------------
  Label loop_through_params;
  __ bind(&loop_through_params);

  __ Ldr(valuetype,
         MemOperand(valuetypes_array_ptr, wasm::ValueType::bit_field_offset()));

  // -------------------------------------------
  // Param conversion.
  // -------------------------------------------
  // If param is a Smi we can easily convert it. Otherwise we'll call a builtin
  // for conversion.
  Label param_conversion_done, check_ref_param, skip_ref_param, convert_param;
  __ cmp(valuetype, Immediate(wasm::kWasmI32.raw_bit_field()));
  __ B(&check_ref_param, ne);

  // I32 param: change to Smi.
  __ Ldr(param.W(), MemOperand(packed_args, current_param_slot_offset));

  // If pointer compression is disabled, we can convert to a smi.
  if (SmiValuesAre32Bits()) {
    __ SmiTag(param);
  } else {
    // Double the return value to test if it can be a Smi.
    __ Adds(wzr, param.W(), param.W());
    // If there was overflow, convert the return value to a HeapNumber.
    __ B(&convert_param, vs);
    // If there was no overflow, we can convert to Smi.
    __ SmiTag(param);
  }

  // Place the param into the proper slot.
  // Pre-increment param_index to skip the receiver slot.
  __ Add(param_index, param_index, 1);
  __ Str(param, MemOperand(sp, param_index, LSL, kSystemPointerSizeLog2));
  __ Add(current_param_slot_offset, current_param_slot_offset, sizeof(int32_t));

  __ B(&param_conversion_done);

  // Skip Ref params. We already copied reference params in the first loop.
  __ bind(&check_ref_param);
  __ And(valuetype, valuetype, Immediate(wasm::kWasmValueKindBitsMask));
  __ cmp(valuetype, Immediate(wasm::ValueKind::kRefNull));
  __ B(&skip_ref_param, eq);
  __ cmp(valuetype, Immediate(wasm::ValueKind::kRef));
  __ B(&convert_param, ne);

  __ bind(&skip_ref_param);
  __ Add(param_index, param_index, 1);
  __ Add(current_param_slot_offset, current_param_slot_offset,
         Immediate(kSystemPointerSize));
  __ B(&param_conversion_done);

  // -------------------------------------------------
  // Param conversion builtins (Wasm type -> JS type).
  // -------------------------------------------------
  __ bind(&convert_param);

  // Prepare for builtin call.

  // Need to specify how many heap objects, that should be scanned by GC, are
  // on the top of the stack. (Only the context).
  // The builtin expects the parameter to be in register param = rax.

  __ Str(param_index, MemOperand(fp, kParamIndexOffset));
  __ Str(valuetypes_array_ptr, MemOperand(fp, kValueTypesArrayStartOffset));
  __ Str(current_param_slot_offset, MemOperand(fp, kCurrentParamOffset));

  Label param_kWasmI32_not_smi;
  Label param_kWasmI64;
  Label param_kWasmF32;
  Label param_kWasmF64;
  Label finish_param_conversion;

  __ cmp(valuetype, Immediate(wasm::kWasmI32.raw_bit_field()));
  __ B(&param_kWasmI32_not_smi, eq);
  __ cmp(valuetype, Immediate(wasm::kWasmI64.raw_bit_field()));
  __ B(&param_kWasmI64, eq);
  __ cmp(valuetype, Immediate(wasm::kWasmF32.raw_bit_field()));
  __ B(&param_kWasmF32, eq);
  __ cmp(valuetype, Immediate(wasm::kWasmF64.raw_bit_field()));
  __ B(&param_kWasmF64, eq);

  // Invalid type. Wasm cannot pass Simd arguments to JavaScript.
  __ DebugBreak();

  Register increment = scratch;
  __ bind(&param_kWasmI32_not_smi);
  __ Call(BUILTIN_CODE(masm->isolate(), WasmInt32ToHeapNumber),
          RelocInfo::CODE_TARGET);
  // Param is the result of the builtin.
  __ Mov(increment, Immediate(sizeof(int32_t)));
  __ jmp(&finish_param_conversion);

  __ bind(&param_kWasmI64);
  __ Ldr(param, MemOperand(packed_args, current_param_slot_offset));
  __ Call(BUILTIN_CODE(masm->isolate(), I64ToBigInt), RelocInfo::CODE_TARGET);
  __ Mov(increment, Immediate(sizeof(int64_t)));
  __ jmp(&finish_param_conversion);

  __ bind(&param_kWasmF32);
  __ Ldr(v0, MemOperand(packed_args, current_param_slot_offset));
  __ Call(BUILTIN_CODE(masm->isolate(), WasmFloat32ToNumber),
          RelocInfo::CODE_TARGET);
  __ Mov(increment, Immediate(sizeof(float)));
  __ jmp(&finish_param_conversion);

  __ bind(&param_kWasmF64);
  __ Ldr(d0, MemOperand(packed_args, current_param_slot_offset));
  __ Call(BUILTIN_CODE(masm->isolate(), WasmFloat64ToNumber),
          RelocInfo::CODE_TARGET);
  __ Mov(increment, Immediate(sizeof(double)));

  // Restore after builtin call.
  __ bind(&finish_param_conversion);

  __ Ldr(current_param_slot_offset, MemOperand(fp, kCurrentParamOffset));
  __ Add(current_param_slot_offset, current_param_slot_offset, increment);
  __ Ldr(valuetypes_array_ptr, MemOperand(fp, kValueTypesArrayStartOffset));
  __ Ldr(param_index, MemOperand(fp, kParamIndexOffset));
  __ Ldr(packed_args, MemOperand(fp, kPackedArrayOffset));
  __ Ldr(param_count, MemOperand(fp, kParamCountOffset));

  __ Add(param_index, param_index, 1);
  __ Str(param, MemOperand(sp, param_index, LSL, kSystemPointerSizeLog2));

  // -------------------------------------------
  // Param conversion done.
  // -------------------------------------------
  __ bind(&param_conversion_done);

  __ Add(valuetypes_array_ptr, valuetypes_array_ptr, Immediate(kValueTypeSize));
  __ Cmp(param_index, param_count);
  __ B(&loop_through_params, lt);

  // -------------------------------------------
  // Prepare for the function call.
  // -------------------------------------------
  __ bind(&prepare_for_js_call);

  // Reset thread_in_wasm_flag.
  __ Ldr(scratch, MemOperand(kRootRegister,
                             Isolate::thread_in_wasm_flag_address_offset()));
  __ Str(wzr, MemOperand(scratch, 0));  // 32 bit.

  regs.ResetExcept(param, packed_args, valuetypes_array_ptr, context,
                   return_count, valuetype, scratch);

  // -------------------------------------------
  // Call the JS function.
  // -------------------------------------------
  // Call_ReceiverIsAny expects the arguments in the stack in this order:
  // sp + (n * 0x08)  JS arg n-1
  // ...              ...
  // sp + 0x08        JS arg 0
  // sp               Receiver
  //
  // It also expects two arguments passed in registers:
  // x0: number of arguments + 1 (receiver)
  // x1: target (JSFunction|JSBoundFunction|...)

  // The process of calling a JS function might increase the number of tagged
  // values on the stack (arguments adaptation, BuiltinExitFrame arguments,
  // v8::FunctionCallbackInfo implicit arguments, etc.). In any case these
  // additional values must be visited by GC too.
  // We store the current stack pointer to be able to detect when this happens.
  __ Mov(scratch, sp);
  __ Str(scratch,
         MemOperand(fp, WasmToJSInterpreterFrameConstants::kGCSPOffset));

  // x0: Receiver.
  __ Ldr(x0, MemOperand(fp, kParamCountOffset));
  __ Add(x0, x0, 1);  // Add 1 to count receiver.

  // x1: callable.
  __ Ldr(kJSFunctionRegister, MemOperand(fp, kCallableOffset));

  __ Call(BUILTIN_CODE(masm->isolate(), Call_ReceiverIsAny),
          RelocInfo::CODE_TARGET);

  // After the call sp points to the saved context.
  __ Ldr(cp, MemOperand(sp, 0));

  // The JS function returns its result in register x0.
  Register return_reg = kReturnRegister0;

  // No slots to visit during GC.
  __ Str(xzr,
         MemOperand(fp,
                    WasmToJSInterpreterFrameConstants::kGCScanSlotCountOffset));

  __ Str(xzr, MemOperand(fp, WasmToJSInterpreterFrameConstants::kGCSPOffset));

  // -------------------------------------------
  // Return handling.
  // -------------------------------------------
  __ Ldr(return_count, MemOperand(fp, kReturnCountOffset));
  __ Ldr(packed_args, MemOperand(fp, kPackedArrayOffset));
  __ Ldr(signature, MemOperand(fp, kSignatureOffset));
  __ Ldr(valuetypes_array_ptr,
         MemOperand(signature, wasm::FunctionSig::kRepsOffset));

  DEFINE_REG(result_index);
  __ Mov(result_index, xzr);
  DEFINE_REG(current_result_offset);
  __ Mov(current_result_offset, xzr);

  // If we have return values, convert them from JS types back to Wasm types.
  Label convert_return;
  Label return_done;
  Label all_done;
  Label loop_copy_return_refs;
  __ cmp(return_count, Immediate(1));
  __ B(&all_done, lt);
  __ B(&convert_return, eq);

  // We have multiple results. Convert the result into a FixedArray.
  DEFINE_REG(fixed_array);
  __ Mov(fixed_array, xzr);

  // The builtin expects three args:
  // x0: object.
  // x1: return_count as Smi.
  // x27 (cp): context.
  __ Ldr(x1, MemOperand(fp, kReturnCountOffset));
  __ Add(x1, x1, x1);
  // One tagged object at the top of the stack (the context).
  __ Mov(scratch, Immediate(1));
  __ Str(scratch,
         MemOperand(fp,
                    WasmToJSInterpreterFrameConstants::kGCScanSlotCountOffset));

  __ Call(BUILTIN_CODE(masm->isolate(), IterableToFixedArrayForWasm),
          RelocInfo::CODE_TARGET);
  __ Mov(fixed_array, kReturnRegister0);

  // Store fixed_array at the second top of the stack (in place of callable).
  __ Str(fixed_array, MemOperand(sp, kSystemPointerSize));
  __ Mov(scratch, Immediate(2));
  __ Str(scratch,
         MemOperand(fp,
                    WasmToJSInterpreterFrameConstants::kGCScanSlotCountOffset));

  __ Ldr(return_count, MemOperand(fp, kReturnCountOffset));
  __ Ldr(packed_args, MemOperand(fp, kPackedArrayOffset));
  __ Ldr(signature, MemOperand(fp, kSignatureOffset));
  __ Ldr(valuetypes_array_ptr,
         MemOperand(signature, wasm::FunctionSig::kRepsOffset));
  __ Mov(result_index, xzr);
  __ Mov(current_result_offset, xzr);

  __ Add(scratch, fixed_array,
         OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag);
  __ LoadTaggedField(return_reg,
                     MemOperand(scratch, result_index, LSL, kTaggedSizeLog2));

  // -------------------------------------------
  // Return conversions (JS type -> Wasm type).
  // -------------------------------------------
  __ bind(&convert_return);

  // Save registers in the stack before the builtin call.
  __ Str(current_result_offset, MemOperand(fp, kCurrentResultOffset));
  __ Str(result_index, MemOperand(fp, kResultIndexOffset));
  __ Str(valuetypes_array_ptr, MemOperand(fp, kValueTypesArrayStartOffset));

  // The builtin expects the parameter to be in register param = x0.

  // The first valuetype of the array is the return's valuetype.
  __ Ldr(valuetype,
         MemOperand(valuetypes_array_ptr, wasm::ValueType::bit_field_offset()));

  Label return_kWasmI32;
  Label return_kWasmI32_not_smi;
  Label return_kWasmI64;
  Label return_kWasmF32;
  Label return_kWasmF64;
  Label return_kWasmRef;

  // Prepare for builtin call.

  __ cmp(valuetype, Immediate(wasm::kWasmI32.raw_bit_field()));
  __ B(&return_kWasmI32, eq);
  __ cmp(valuetype, Immediate(wasm::kWasmI64.raw_bit_field()));
  __ B(&return_kWasmI64, eq);
  __ cmp(valuetype, Immediate(wasm::kWasmF32.raw_bit_field()));
  __ B(&return_kWasmF32, eq);
  __ cmp(valuetype, Immediate(wasm::kWasmF64.raw_bit_field()));
  __ B(&return_kWasmF64, eq);

  __ And(valuetype, valuetype, Immediate(wasm::kWasmValueKindBitsMask));
  __ cmp(valuetype, Immediate(wasm::ValueKind::kRefNull));
  __ B(&return_kWasmRef, eq);
  __ cmp(valuetype, Immediate(wasm::ValueKind::kRef));
  __ B(&return_kWasmRef, eq);

  // Invalid type. JavaScript cannot return Simd results to WebAssembly.
  __ DebugBreak();

  __ bind(&return_kWasmI32);
  __ JumpIfNotSmi(return_reg, &return_kWasmI32_not_smi);
  // Change the param from Smi to int32.
  __ SmiUntag(return_reg);
  __ AssertZeroExtended(return_reg);
  __ Ldr(packed_args, MemOperand(fp, kPackedArrayOffset));
  __ Str(return_reg.W(), MemOperand(packed_args, current_result_offset));
  __ Add(current_result_offset, current_result_offset,
         Immediate(sizeof(int32_t)));
  __ jmp(&return_done);

  __ bind(&return_kWasmI32_not_smi);
  __ Call(BUILTIN_CODE(masm->isolate(), WasmTaggedNonSmiToInt32),
          RelocInfo::CODE_TARGET);
  __ AssertZeroExtended(return_reg);
  __ Ldr(packed_args, MemOperand(fp, kPackedArrayOffset));
  __ Ldr(current_result_offset, MemOperand(fp, kCurrentResultOffset));
  __ Str(return_reg.W(), MemOperand(packed_args, current_result_offset));
  __ Add(current_result_offset, current_result_offset,
         Immediate(sizeof(int32_t)));
  __ jmp(&return_done);

  __ bind(&return_kWasmI64);
  __ Call(BUILTIN_CODE(masm->isolate(), BigIntToI64), RelocInfo::CODE_TARGET);
  __ Ldr(packed_args, MemOperand(fp, kPackedArrayOffset));
  __ Ldr(current_result_offset, MemOperand(fp, kCurrentResultOffset));
  __ Str(return_reg, MemOperand(packed_args, current_result_offset));
  __ Add(current_result_offset, current_result_offset,
         Immediate(sizeof(int64_t)));
  __ jmp(&return_done);

  __ bind(&return_kWasmF32);
  __ Call(BUILTIN_CODE(masm->isolate(), WasmTaggedToFloat32),
          RelocInfo::CODE_TARGET);
  __ Ldr(packed_args, MemOperand(fp, kPackedArrayOffset));
  __ Ldr(current_result_offset, MemOperand(fp, kCurrentResultOffset));
  __ Str(kFPReturnRegister0, MemOperand(packed_args, current_result_offset));
  __ Add(current_result_offset, current_result_offset,
         Immediate(sizeof(float)));
  __ jmp(&return_done);

  __ bind(&return_kWasmF64);
  __ Call(BUILTIN_CODE(masm->isolate(), WasmTaggedToFloat64),
          RelocInfo::CODE_TARGET);
  __ Ldr(packed_args, MemOperand(fp, kPackedArrayOffset));
  __ Ldr(current_result_offset, MemOperand(fp, kCurrentResultOffset));
  __ Str(kFPReturnRegister0, MemOperand(packed_args, current_result_offset));
  __ Add(current_result_offset, current_result_offset,
         Immediate(sizeof(double)));
  __ jmp(&return_done);

  __ bind(&return_kWasmRef);
  __ Ldr(packed_args, MemOperand(fp, kPackedArrayOffset));
  __ Str(return_reg,
         MemOperand(packed_args, result_index, LSL, kSystemPointerSizeLog2));
  __ Add(current_result_offset, current_result_offset,
         Immediate(sizeof(double)));

  // A result converted.
  __ bind(&return_done);

  // Restore after builtin call
  __
```