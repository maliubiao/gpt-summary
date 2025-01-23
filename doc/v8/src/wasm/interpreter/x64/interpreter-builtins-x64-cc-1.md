Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/wasm/interpreter/x64/interpreter-builtins-x64.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Functionality:** The code defines two main built-in functions for the WebAssembly interpreter on x64 architecture: `WasmInterpreterCWasmEntry` and `GenericWasmToJSInterpreterWrapper`. Recognize these names are significant and hint at their purpose.

2. **Analyze `WasmInterpreterCWasmEntry`:**
    * Look for keywords and comments. "CWasmEntryFrame," "Wasm-to-JS calls," "GenericWasmToJSInterpreterWrapper," "exceptions" are key.
    * Notice the stack frame setup. It's creating a specific type of frame (`C_WASM_ENTRY`) used for handling transitions from Wasm to JavaScript.
    * Observe the saving and restoring of registers. This is common in function prologues and epilogues.
    * See the jump to `GenericWasmToJSInterpreterWrapper` and the surrounding try/catch-like structure (`invoke` and `handler_entry`). This strongly suggests this function manages the call into JavaScript.
    * Conclude: This function sets up the necessary environment for a Wasm module to call a JavaScript function, including exception handling.

3. **Analyze `GenericWasmToJSInterpreterWrapper`:**
    * Look for keywords and comments. "WASM_TO_JS," "Compute offsets," "GC," "signature," "params," "return handling." These suggest the function's role is to manage the interface between Wasm and JS functions.
    * Observe the detailed stack frame setup (`WasmToJSInterpreterWrapperFrame`). This frame stores various metadata needed for the call.
    * Notice the handling of arguments (`packed_args`). The code iterates through the parameters, converting them from Wasm types to JavaScript types. Pay attention to the handling of reference types specifically.
    * Observe the call to the JavaScript function using `BUILTIN_CODE(masm->isolate(), Call_ReceiverIsAny)`.
    * See the handling of return values. The code converts the JavaScript return values back to Wasm types. Note the case for multiple return values and the use of `IterableToFixedArrayForWasm`. Also observe the separate handling of reference type return values.
    * Conclude: This function takes care of the heavy lifting of calling a JavaScript function from Wasm. It handles parameter conversion, the actual function call, and return value conversion, considering garbage collection implications.

4. **Check for `.tq` extension:** The prompt explicitly states to check for this. The provided code is `.cc`, not `.tq`, so it's C++, not Torque.

5. **Relate to JavaScript:**
    * `WasmInterpreterCWasmEntry`: This is the underlying mechanism that makes `wasmInstance.exports.someFunction()` work when `someFunction` is a JavaScript function.
    * `GenericWasmToJSInterpreterWrapper`: This is what happens behind the scenes during the call to the JavaScript function. The conversion of arguments and return values are key aspects. Provide concrete JavaScript/Wasm examples to illustrate this.

6. **Infer Code Logic and Provide Examples:**
    * For `WasmInterpreterCWasmEntry`, the key logic is setting up the stack frame and calling the wrapper. A simple Wasm module calling a JS function demonstrates its purpose.
    * For `GenericWasmToJSInterpreterWrapper`, the parameter and return value conversions are the core logic. Illustrate this with different Wasm and JS types. Show how a Wasm `i32` becomes a JavaScript number, and vice versa.

7. **Identify Common Programming Errors:**  Focus on errors related to the interaction between Wasm and JS: type mismatches, incorrect number of arguments, and unhandled exceptions in JS that propagate back to Wasm.

8. **Address the "歸納一下它的功能 (Summarize its functionality)" part of the prompt:**  Combine the individual analyses into a concise overview of the file's role in handling Wasm-to-JS calls in the interpreter.

9. **Review and Refine:**  Ensure the explanation is clear, accurate, and addresses all parts of the user's request. Check for consistency and clarity in the examples. Ensure the language used aligns with the context of V8 and WebAssembly.

This systematic analysis of the code, comments, and function names, combined with the prompt's instructions, leads to the comprehensive answer provided previously.
Based on the provided code snippet from `v8/src/wasm/interpreter/x64/interpreter-builtins-x64.cc`, here's a summary of its functionality:

**Core Functionality:**

This file defines architecture-specific (x64) built-in functions that are crucial for the WebAssembly interpreter in V8 when interacting with JavaScript. Specifically, it handles the transitions and data conversions necessary when a WebAssembly module calls a JavaScript function.

**Key Built-in Functions and Their Roles:**

1. **`Builtins::Generate_WasmInterpreterCWasmEntry(MacroAssembler* masm)`:**
   - **Purpose:** This built-in sets up the necessary environment for calling a JavaScript function from within the WebAssembly interpreter. It acts as an entry point when a Wasm module invokes a JavaScript function.
   - **Stack Frame Management:** It meticulously sets up a specific stack frame (`C_WASM_ENTRY`). This frame is critical for unwinding the interpreter stack correctly and handling exceptions that might occur within the JavaScript function.
   - **Exception Handling:** It includes a mechanism to catch exceptions thrown by the JavaScript function and propagate them back to the Wasm interpreter.
   - **Transition Point:** It bridges the gap between the Wasm interpreter's execution and the execution of JavaScript code. It calls `GenericWasmToJSInterpreterWrapper` to handle the actual invocation.

2. **`Builtins::Generate_GenericWasmToJSInterpreterWrapper(MacroAssembler* masm)`:**
   - **Purpose:** This is the core logic for calling a JavaScript function from Wasm within the interpreter. It manages the conversion of arguments from Wasm types to JavaScript types and the conversion of return values from JavaScript types back to Wasm types.
   - **Stack Frame Management:** It sets up a `WASM_TO_JS` stack frame to store temporary values and metadata needed for the call.
   - **Argument Conversion:** It iterates through the arguments passed from Wasm, examining their types and performing the necessary conversions to their JavaScript equivalents (e.g., Wasm `i32` to JavaScript Number, Wasm `i64` to BigInt, Wasm floats to JavaScript Numbers, and handling references). It has special handling for reference types to ensure their validity in the presence of garbage collection.
   - **Function Call:** It uses `BUILTIN_CODE(masm->isolate(), Call_ReceiverIsAny)` to actually invoke the JavaScript function.
   - **Return Value Conversion:** After the JavaScript function returns, it converts the returned JavaScript value(s) back to the expected Wasm type(s). It handles cases with single and multiple return values, including the use of `IterableToFixedArrayForWasm` for multiple returns. Similar to argument conversion, it has special handling for reference type return values.
   - **Garbage Collection (GC) Awareness:** The code is carefully designed to be aware of potential garbage collections during the conversion process. It marks objects that need to be tracked by the GC to prevent them from being prematurely collected.

**Relation to JavaScript (with examples):**

Yes, this code is directly related to JavaScript functionality. It's the mechanism that allows WebAssembly modules to seamlessly interact with JavaScript.

**Example:**

```javascript
// JavaScript code
function add(a, b) {
  return a + b;
}

// WebAssembly module (conceptual, simplified)
// ... exports a function that calls the JavaScript 'add' function ...

// When the Wasm module calls the JavaScript 'add' function:

// 1. `WasmInterpreterCWasmEntry` is invoked.
// 2. It sets up the `C_WASM_ENTRY` stack frame.
// 3. It calls `GenericWasmToJSInterpreterWrapper`.
// 4. `GenericWasmToJSInterpreterWrapper` does the following:
//    - Takes the Wasm arguments (e.g., two i32 values).
//    - Converts them to JavaScript Numbers.
//    - Calls the JavaScript `add` function with these JavaScript Numbers.
//    - Receives the JavaScript Number result.
//    - Converts the JavaScript Number result back to the expected Wasm return type (e.g., i32).
// 5. `WasmInterpreterCWasmEntry` handles any exceptions and returns control to the Wasm module.
```

**Code Logic Inference (with assumptions):**

**Assumption:** A WebAssembly function with the signature `(param i32 i32) (result i32)` calls a JavaScript function that expects two number arguments and returns a number.

**Input to `GenericWasmToJSInterpreterWrapper` (conceptual):**

- `target_js_function`: A pointer to the JavaScript `add` function object.
- `packed_args`: A memory region containing the two `i32` arguments from Wasm.
- `signature`: Information about the Wasm-to-JS call signature (parameter and return types).

**Output from `GenericWasmToJSInterpreterWrapper` (conceptual):**

- The `rax` register will contain the converted return value as a Wasm `i32`.
- The `packed_args` memory region will be updated with the converted return value.

**User-Related Programming Errors:**

Common programming errors that might surface due to the mechanisms in this code include:

1. **Type Mismatches:**
   - **Example:** The Wasm module tries to pass a 64-bit integer to a JavaScript function expecting a 32-bit integer, or vice-versa. The conversion logic in `GenericWasmToJSInterpreterWrapper` will handle some of these cases (e.g., converting to BigInt), but mismatches can lead to unexpected behavior or errors during conversion.

2. **Incorrect Number of Arguments:**
   - **Example:** The Wasm module calls a JavaScript function with too few or too many arguments. While JavaScript is more forgiving, the underlying machinery expects a certain number of arguments based on the function's definition.

3. **JavaScript Exceptions Not Handled in Wasm:**
   - **Example:** The JavaScript `add` function might throw an error (e.g., if the inputs are not numbers). If the Wasm module doesn't have a mechanism to catch and handle these exceptions, the execution might terminate unexpectedly. `WasmInterpreterCWasmEntry` plays a crucial role in propagating these exceptions.

**归纳一下它的功能 (Summarize its functionality):**

This part of the V8 source code, specifically the `interpreter-builtins-x64.cc` file, defines the low-level mechanisms for the WebAssembly interpreter to call JavaScript functions on the x64 architecture. It handles the intricate details of setting up the execution environment, converting data types between Wasm and JavaScript representations, and managing potential exceptions during these cross-language calls. Essentially, it's the bridge that enables seamless interoperability between WebAssembly and JavaScript within the V8 engine's interpreter.

### 提示词
```
这是目录为v8/src/wasm/interpreter/x64/interpreter-builtins-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/x64/interpreter-builtins-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
lt in JSArray
  __ StoreTaggedField(FieldOperand(fixed_array, result_index,
                                   static_cast<ScaleFactor>(kTaggedSizeLog2),
                                   OFFSET_OF_DATA_START(FixedArray)),
                      return_value);
  __ jmp(&next_return_value);
}

// For compiled code, V8 generates signature-specific CWasmEntries that manage
// the transition from C++ code to a JS function called from Wasm code and takes
// care of handling exceptions that arise from JS (see
// WasmWrapperGraphBuilder::BuildCWasmEntry()).
// This builtin does the same for the Wasm interpreter and it is used for
// Wasm-to-JS calls. It invokes GenericWasmToJSInterpreterWrapper and installs a
// specific frame of type C_WASM_ENTRY which is used in
// Isolate::UnwindAndFindHandler() to correctly unwind interpreter stack frames
// and handle exceptions.
void Builtins::Generate_WasmInterpreterCWasmEntry(MacroAssembler* masm) {
  Label invoke, handler_entry, exit;
  Register isolate_root = kCArgRegs[2];  // Windows: r8, Posix: rdx

  // -------------------------------------------
  // CWasmEntryFrame: (Win64)
  // rbp-0xe8  rbx
  // rbp-0xe0  rsi
  // rbp-0xd8  rdi
  // rbp-0xd0  r12
  // rbp-0xc8  r13
  // rbp-0xc0  r14
  // rbp-0xb8  r15
  // -------------------------------------------
  // rbp-0xb0  xmm6
  //           ...
  // rbp-0x20  xmm15
  // -------------------------------------------
  // rbp-0x18  rsp
  // rbp-0x10  CEntryFp
  // rbp-0x08  Marker(StackFrame::C_WASM_ENTRY)
  // rbp       Old RBP

  // -------------------------------------------
  // CWasmEntryFrame: (AMD64 ABI)
  // rbp-0x40  rbx
  // rbp-0x38  r12
  // rbp-0x30  r13
  // rbp-0x28  r14
  // rbp-0x20  r15
  // -------------------------------------------
  // rbp-0x18  rsp
  // rbp-0x10  CEntryFp
  // rbp-0x08  Marker(StackFrame::C_WASM_ENTRY)
  // rbp       Old RBP

#ifndef V8_OS_POSIX
  // Offsets for arguments passed in WasmToJSCallSig. See declaration of
  // {WasmToJSCallSig} in src/wasm/interpreter/wasm-interpreter-runtime.h.
  constexpr int kCEntryFpParameterOffset = 0x30;
  constexpr int kCallableOffset = 0x38;
#endif  // !V8_OS_POSIX

  // Set up the stackframe.
  __ EnterFrame(StackFrame::C_WASM_ENTRY);

  // Space to store c_entry_fp and current rsp (used by exception handler).
  __ subq(rsp, Immediate(0x10));

  // Save registers
#ifdef V8_TARGET_OS_WIN
  // On Win64 XMM6-XMM15 are callee-save.
  __ subq(rsp, Immediate(0xa0));
  __ movdqu(Operand(rsp, 0x00), xmm6);
  __ movdqu(Operand(rsp, 0x10), xmm7);
  __ movdqu(Operand(rsp, 0x20), xmm8);
  __ movdqu(Operand(rsp, 0x30), xmm9);
  __ movdqu(Operand(rsp, 0x40), xmm10);
  __ movdqu(Operand(rsp, 0x50), xmm11);
  __ movdqu(Operand(rsp, 0x60), xmm12);
  __ movdqu(Operand(rsp, 0x70), xmm13);
  __ movdqu(Operand(rsp, 0x80), xmm14);
  __ movdqu(Operand(rsp, 0x90), xmm15);
#endif  // V8_TARGET_OS_WIN
  __ pushq(r15);
  __ pushq(r14);
  __ pushq(r13);
  __ pushq(r12);
#ifdef V8_TARGET_OS_WIN
  __ pushq(rdi);  // Only callee save in Win64 ABI, argument in AMD64 ABI.
  __ pushq(rsi);  // Only callee save in Win64 ABI, argument in AMD64 ABI.
#endif            // V8_TARGET_OS_WIN
  __ pushq(rbx);

  // InitializeRootRegister
  __ movq(kRootRegister, isolate_root);  // kRootRegister: r13
#ifdef V8_COMPRESS_POINTERS_IN_SHARED_CAGE
  __ LoadRootRelative(kPtrComprCageBaseRegister,
                      IsolateData::cage_base_offset());
#endif
  isolate_root = no_reg;

  Register callable = r8;
#ifdef V8_OS_POSIX
  __ movq(MemOperand(rbp, WasmInterpreterCWasmEntryConstants::kCEntryFPOffset),
          r8);            // saved_c_entry_fp
  __ movq(callable, r9);  // callable
#else                     // Windows
  // Store c_entry_fp into slot
  __ movq(rbx, MemOperand(rbp, kCEntryFpParameterOffset));
  __ movq(MemOperand(rbp, WasmInterpreterCWasmEntryConstants::kCEntryFPOffset),
          rbx);
  __ movq(callable, MemOperand(rbp, kCallableOffset));
#endif                    // V8_OS_POSIX

  // Jump to a faked try block that does the invoke, with a faked catch
  // block that sets the pending exception.
  __ jmp(&invoke);

  // Handler.
  __ bind(&handler_entry);

  // Store the current pc as the handler offset. It's used later to create the
  // handler table.
  masm->isolate()->builtins()->SetCWasmInterpreterEntryHandlerOffset(
      handler_entry.pos());
  // Caught exception.
  __ jmp(&exit);

  // Invoke: Link this frame into the handler chain.
  __ bind(&invoke);
  __ movq(MemOperand(rbp, WasmInterpreterCWasmEntryConstants::kSPFPOffset),
          rsp);
  __ PushStackHandler();
  __ Call(BUILTIN_CODE(masm->isolate(), GenericWasmToJSInterpreterWrapper),
          RelocInfo::CODE_TARGET);

  // Unlink this frame from the handler chain.
  __ PopStackHandler();

  __ bind(&exit);
  // Restore registers.
  __ popq(rbx);
#ifdef V8_TARGET_OS_WIN
  __ popq(rsi);
  __ popq(rdi);
#endif  // V8_TARGET_OS_WIN
  __ popq(r12);
  __ popq(r13);
  __ popq(r14);
  __ popq(r15);
#ifdef V8_TARGET_OS_WIN
  // On Win64 XMM6-XMM15 are callee-save.
  __ movdqu(xmm15, Operand(rsp, 0x90));
  __ movdqu(xmm14, Operand(rsp, 0x80));
  __ movdqu(xmm13, Operand(rsp, 0x70));
  __ movdqu(xmm12, Operand(rsp, 0x60));
  __ movdqu(xmm11, Operand(rsp, 0x50));
  __ movdqu(xmm10, Operand(rsp, 0x40));
  __ movdqu(xmm9, Operand(rsp, 0x30));
  __ movdqu(xmm8, Operand(rsp, 0x20));
  __ movdqu(xmm7, Operand(rsp, 0x10));
  __ movdqu(xmm6, Operand(rsp, 0x00));
#endif  // V8_TARGET_OS_WIN

  // Deconstruct the stack frame.
  __ LeaveFrame(StackFrame::C_WASM_ENTRY);
  __ ret(0);
}

void Builtins::Generate_GenericWasmToJSInterpreterWrapper(
    MacroAssembler* masm) {
  Register target_js_function = kCArgRegs[0];  // Win: rcx, Posix: rdi
  Register packed_args = kCArgRegs[1];         // Win: rdx, Posix: rsi
  Register callable = rdi;
  Register signature = kCArgRegs[3];  // Win: r9, Posix: rcx

  // Set up the stackframe.
  __ EnterFrame(StackFrame::WASM_TO_JS);

  // -------------------------------------------
  // Compute offsets and prepare for GC.
  // -------------------------------------------
  // GenericWasmToJSInterpreterWrapperFrame:
  // rbp-N     receiver               ^
  // ...       JS arg 0               | Tagged
  // ...       ...                    | objects
  // rbp-0x68  JS arg n-1             |
  // rbp-0x60  context                v
  // -------------------------------------------
  // rbp-0x58  current_param_slot_index
  // rbp-0x50  valuetypes_array_ptr
  // rbp-0x48  param_index/return_index
  // rbp-0x40  signature
  // rbp-0x38  param_count
  // rbp-0x30  return_count
  // rbp-0x28  expected_arity
  // rbp-0x20  packed_array
  // rbp-0x18  GC_SP
  // rbp-0x10  GCScanSlotCount
  // rbp-0x08  Marker(StackFrame::WASM_TO_JS)
  // rbp       Old RBP

  constexpr int kMarkerOffset =
      WasmToJSInterpreterFrameConstants::kGCScanSlotCountOffset +
      kSystemPointerSize;
  static_assert(WasmToJSInterpreterFrameConstants::kGCSPOffset ==
                WasmToJSInterpreterFrameConstants::kGCScanSlotCountOffset -
                    kSystemPointerSize);
  constexpr int kPackedArrayOffset =
      WasmToJSInterpreterFrameConstants::kGCSPOffset - kSystemPointerSize;
  constexpr int kExpectedArityOffset = kPackedArrayOffset - kSystemPointerSize;
  constexpr int kReturnCountOffset = kExpectedArityOffset - kSystemPointerSize;
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
  constexpr int kCurrentResultAddressOffset = kCurrentParamOffset;
  constexpr int kNumSpillSlots =
      (kMarkerOffset - kCurrentResultAddressOffset) / kSystemPointerSize;
  __ subq(rsp, Immediate(kNumSpillSlots * kSystemPointerSize));

  __ movq(MemOperand(rbp, kPackedArrayOffset), packed_args);

  // Store null into the stack slot that will contain rsp to be used in GCs that
  // happen during the JS function call. See WasmToJsFrame::Iterate.
  __ Move(MemOperand(rbp, WasmToJSInterpreterFrameConstants::kGCSPOffset), 0);

  // Count the number of tagged objects at the top of the stack that need to be
  // visited during GC.
  __ Move(MemOperand(rbp,
                     WasmToJSInterpreterFrameConstants::kGCScanSlotCountOffset),
          0);

#if V8_OS_POSIX
  // Windows has a different calling convention.
  signature = r9;
  __ movq(signature, kCArgRegs[3]);
  target_js_function = rcx;
  __ movq(target_js_function, kCArgRegs[0]);
  packed_args = rdx;
  __ movq(packed_args, kCArgRegs[1]);
#endif                    // V8_OS_POSIX
  __ movq(callable, r8);  // Callable passed in r8.

  Register shared_function_info = r15;
  __ LoadTaggedField(
      shared_function_info,
      MemOperand(
          target_js_function,
          wasm::ObjectAccess::SharedFunctionInfoOffsetInTaggedJSFunction()));

  // Set the context of the function; the call has to run in the function
  // context.
  Register context = rsi;
  __ LoadTaggedField(
      context, FieldOperand(target_js_function, JSFunction::kContextOffset));
  target_js_function = no_reg;

  // Load global receiver if sloppy else use undefined.
  Label receiver_undefined;
  Label calculate_js_function_arity;
  Register receiver = r11;
  Register flags = rbx;
  __ movl(flags,
          FieldOperand(shared_function_info, SharedFunctionInfo::kFlagsOffset));
  __ testq(flags, Immediate(SharedFunctionInfo::IsNativeBit::kMask |
                            SharedFunctionInfo::IsStrictBit::kMask));
  flags = no_reg;
  __ j(not_equal, &receiver_undefined);
  __ LoadGlobalProxy(receiver);
  __ jmp(&calculate_js_function_arity);

  __ bind(&receiver_undefined);
  __ LoadRoot(receiver, RootIndex::kUndefinedValue);

  __ bind(&calculate_js_function_arity);

  // Load values from the signature.
  __ movq(MemOperand(rbp, kSignatureOffset), signature);
  Register valuetypes_array_ptr = signature;
  Register return_count = r8;
  Register param_count = rcx;
  LoadFromSignature(masm, valuetypes_array_ptr, return_count, param_count);
  __ movq(MemOperand(rbp, kParamCountOffset), param_count);
  shared_function_info = no_reg;

  // The arguments need to be visited during GC.
  __ movq(MemOperand(rbp,
                     WasmToJSInterpreterFrameConstants::kGCScanSlotCountOffset),
          param_count);

  // Calculate target function arity.
  Register expected_arity = rbx;
  __ movq(expected_arity, param_count);

  // Make room to pass args and store the context.
  __ movq(rax, expected_arity);
  __ incq(rax);  // To store the context.
  __ shlq(rax, Immediate(kSystemPointerSizeLog2));
  __ subq(rsp, rax);  // Args.

  Register param_index = param_count;
  __ Move(param_index, 0);

  // -------------------------------------------
  // Store signature-related values to the stack.
  // -------------------------------------------
  // We store values on the stack to restore them after function calls.
  __ movq(MemOperand(rbp, kReturnCountOffset), return_count);
  __ movq(MemOperand(rbp, kValueTypesArrayStartOffset), valuetypes_array_ptr);

  Label prepare_for_js_call;
  __ Cmp(expected_arity, 0);
  // If we have 0 params: jump through parameter handling.
  __ j(equal, &prepare_for_js_call);

  // Loop through the params starting with the first.
  Register current_param_slot_offset = r10;
  __ Move(current_param_slot_offset, Immediate(0));
  Register param = rax;

  // We have to check the types of the params. The ValueType array contains
  // first the return then the param types.
  constexpr int kValueTypeSize = sizeof(wasm::ValueType);
  static_assert(kValueTypeSize == 4);
  const int32_t kValueTypeSizeLog2 = log2(kValueTypeSize);

  // Set the ValueType array pointer to point to the first parameter.
  Register returns_size = return_count;
  return_count = no_reg;
  __ shlq(returns_size, Immediate(kValueTypeSizeLog2));
  __ addq(valuetypes_array_ptr, returns_size);
  returns_size = no_reg;
  Register valuetype = r12;

  // -------------------------------------------
  // Copy reference type params first and initialize the stack for JS arguments.
  // -------------------------------------------

  // Heap pointers for ref type values in packed_args can be invalidated if GC
  // is triggered when converting wasm numbers to JS numbers and allocating
  // heap numbers. So, we have to move them to the stack first.
  {
    Label loop_copy_param_ref, load_ref_param, set_and_move;

    __ bind(&loop_copy_param_ref);
    __ movl(valuetype,
            Operand(valuetypes_array_ptr, wasm::ValueType::bit_field_offset()));
    __ andl(valuetype, Immediate(wasm::kWasmValueKindBitsMask));
    __ cmpq(valuetype, Immediate(wasm::ValueKind::kRefNull));
    __ j(equal, &load_ref_param);
    __ cmpq(valuetype, Immediate(wasm::ValueKind::kRef));
    __ j(equal, &load_ref_param);

    // Initialize non-ref type slots to zero since they can be visited by GC
    // when converting wasm numbers into heap numbers.
    __ Move(param, Smi::zero());

    Label inc_param_32bit;
    __ cmpq(valuetype, Immediate(wasm::kWasmI32.raw_bit_field()));
    __ j(equal, &inc_param_32bit);
    __ cmpq(valuetype, Immediate(wasm::kWasmF32.raw_bit_field()));
    __ j(equal, &inc_param_32bit);

    Label inc_param_64bit;
    __ cmpq(valuetype, Immediate(wasm::kWasmI64.raw_bit_field()));
    __ j(equal, &inc_param_64bit);
    __ cmpq(valuetype, Immediate(wasm::kWasmF64.raw_bit_field()));
    __ j(equal, &inc_param_64bit);

    // Invalid type. Wasm cannot pass Simd arguments to JavaScript.
    __ int3();

    __ bind(&inc_param_32bit);
    __ addq(current_param_slot_offset, Immediate(sizeof(int32_t)));
    __ jmp(&set_and_move);

    __ bind(&inc_param_64bit);
    __ addq(current_param_slot_offset, Immediate(sizeof(int64_t)));
    __ jmp(&set_and_move);

    __ bind(&load_ref_param);
    __ movq(param,
            MemOperand(packed_args, current_param_slot_offset, times_1, 0));
    __ addq(current_param_slot_offset, Immediate(kSystemPointerSize));

    __ bind(&set_and_move);
    __ movq(MemOperand(rsp, param_index, times_system_pointer_size, 0), param);
    __ addq(valuetypes_array_ptr, Immediate(kValueTypeSize));
    __ incq(param_index);
    __ cmpq(param_index, MemOperand(rbp, kParamCountOffset));
    __ j(less, &loop_copy_param_ref);
  }

  // Reset pointers for the second param conversion loop.
  returns_size = r8;
  __ movq(returns_size, MemOperand(rbp, kReturnCountOffset));
  __ shlq(returns_size, Immediate(kValueTypeSizeLog2));
  __ movq(valuetypes_array_ptr, MemOperand(rbp, kValueTypesArrayStartOffset));
  __ addq(valuetypes_array_ptr, returns_size);
  returns_size = no_reg;
  __ movq(current_param_slot_offset, Immediate(0));
  __ movq(param_index, Immediate(0));

  // -------------------------------------------
  // Param evaluation loop.
  // -------------------------------------------
  Label loop_through_params;
  __ bind(&loop_through_params);

  __ movl(valuetype,
          Operand(valuetypes_array_ptr, wasm::ValueType::bit_field_offset()));

  // -------------------------------------------
  // Param conversion.
  // -------------------------------------------
  // If param is a Smi we can easily convert it. Otherwise we'll call a builtin
  // for conversion.
  Label param_conversion_done, check_ref_param, skip_ref_param, convert_param;

  __ cmpq(valuetype, Immediate(wasm::kWasmI32.raw_bit_field()));
  __ j(not_equal, &check_ref_param);

  // I32 param: change to Smi.
  __ movl(param,
          MemOperand(packed_args, current_param_slot_offset, times_1, 0));
  // If pointer compression is disabled, we can convert to a Smi.
  if (SmiValuesAre32Bits()) {
    __ SmiTag(param);
  } else {
    Register temp = r15;
    __ movq(temp, param);
    // Double the return value to test if it can be a Smi.
    __ addl(temp, param);
    temp = no_reg;
    // If there was overflow, convert the return value to a HeapNumber.
    __ j(overflow, &convert_param);
    // If there was no overflow, we can convert to Smi.
    __ SmiTag(param);
  }

  // Place the param into the proper slot.
  __ movq(MemOperand(rsp, param_index, times_system_pointer_size, 0), param);
  __ addq(current_param_slot_offset, Immediate(sizeof(int32_t)));
  __ jmp(&param_conversion_done);

  // Skip Ref params. We already copied reference params in the first loop.
  __ bind(&check_ref_param);
  __ andl(valuetype, Immediate(wasm::kWasmValueKindBitsMask));
  __ cmpq(valuetype, Immediate(wasm::ValueKind::kRefNull));
  __ j(equal, &skip_ref_param);
  __ cmpq(valuetype, Immediate(wasm::ValueKind::kRef));
  __ j(not_equal, &convert_param);

  __ bind(&skip_ref_param);
  __ addq(current_param_slot_offset, Immediate(kSystemPointerSize));

  // -------------------------------------------
  // Param conversion done.
  // -------------------------------------------
  __ bind(&param_conversion_done);
  __ addq(valuetypes_array_ptr, Immediate(kValueTypeSize));
  __ incq(param_index);
  __ decq(expected_arity);
  __ j(equal, &prepare_for_js_call);
  __ cmpq(param_index, MemOperand(rbp, kParamCountOffset));
  __ j(not_equal, &loop_through_params);

  // -------------------------------------------
  // Prepare for the function call.
  // -------------------------------------------
  __ bind(&prepare_for_js_call);

  // Store context to be retrieved after the call.
  __ movq(Operand(rsp, param_index, times_system_pointer_size, 0), context);
  __ incq(MemOperand(
      rbp, WasmToJSInterpreterFrameConstants::kGCScanSlotCountOffset));

  // Reset thread_in_wasm_flag.
  Register thread_in_wasm_flag_addr = rcx;
  __ movq(
      thread_in_wasm_flag_addr,
      MemOperand(kRootRegister, Isolate::thread_in_wasm_flag_address_offset()));
  __ movl(MemOperand(thread_in_wasm_flag_addr, 0), Immediate(0));
  thread_in_wasm_flag_addr = no_reg;

  // -------------------------------------------
  // Call the JS function.
  // -------------------------------------------
  // Call_ReceiverIsAny expects the arguments in the stack in this order:
  // rsp + offset_PC  Receiver
  // rsp + 0x10       JS arg 0
  // ...              ...
  // rsp + N          JS arg n-1
  //
  // It also expects two arguments passed in registers:
  // rax: number of arguments + 1 (receiver)
  // rdi: target JSFunction|JSBoundFunction|...
  //
  __ pushq(receiver);
  __ incq(MemOperand(
      rbp, WasmToJSInterpreterFrameConstants::kGCScanSlotCountOffset));

  // The process of calling a JS function might increase the number of tagged
  // values on the stack (arguments adaptation, BuiltinExitFrame arguments,
  // v8::FunctionCallbackInfo implicit arguments, etc.). In any case these
  // additional values must be visited by GC too.
  // We store the current stack pointer to be able to detect when this happens.
  __ movq(MemOperand(rbp, WasmToJSInterpreterFrameConstants::kGCSPOffset), rsp);

  __ movq(rax, MemOperand(rbp, kParamCountOffset));
  __ incq(rax);  // Count receiver.
  __ Call(BUILTIN_CODE(masm->isolate(), Call_ReceiverIsAny),
          RelocInfo::CODE_TARGET);

  __ movq(rsp, MemOperand(rbp, WasmToJSInterpreterFrameConstants::kGCSPOffset));
  __ movq(MemOperand(rbp, WasmToJSInterpreterFrameConstants::kGCSPOffset),
          Immediate(0));

  __ popq(receiver);

  // Retrieve context.
  __ movq(context,  // param_count
          MemOperand(
              rbp, WasmToJSInterpreterFrameConstants::kGCScanSlotCountOffset));
  __ subq(context, Immediate(2));  // do not count receiver and context.
  __ movq(context, Operand(rsp, context, times_system_pointer_size, 0));

  // -------------------------------------------
  // Return handling.
  // -------------------------------------------
  Register return_reg = rax;
  return_count = rcx;
  __ movq(return_count, MemOperand(rbp, kReturnCountOffset));
  __ movq(packed_args, MemOperand(rbp, kPackedArrayOffset));
  __ movq(signature, MemOperand(rbp, kSignatureOffset));
  __ movq(valuetypes_array_ptr,
          MemOperand(signature, wasm::FunctionSig::kRepsOffset));
  Register result_index = r8;
  __ movq(result_index, Immediate(0));

  // If we have return values, convert them from JS types back to Wasm types.
  Label convert_return;
  Label return_done;
  Label all_done;
  Label loop_copy_return_refs;
  Register fixed_array = r11;
  __ movq(fixed_array, Immediate(0));
  __ cmpl(return_count, Immediate(1));
  __ j(less, &all_done);
  __ j(equal, &convert_return);

  // We have multiple results. Convert the result into a FixedArray.
  // The builtin expects three args:
  // rax: object.
  // rbx: return_count as Smi.
  // rsi: context.
  __ movq(rbx, MemOperand(rbp, kReturnCountOffset));
  __ addq(rbx, rbx);
  __ pushq(context);
  // One tagged object at the top of the stack (the context).
  __ movq(MemOperand(rbp,
                     WasmToJSInterpreterFrameConstants::kGCScanSlotCountOffset),
          Immediate(1));
  __ Call(BUILTIN_CODE(masm->isolate(), IterableToFixedArrayForWasm),
          RelocInfo::CODE_TARGET);
  __ popq(context);
  __ movq(fixed_array, rax);
  __ movq(return_count, MemOperand(rbp, kReturnCountOffset));
  __ movq(packed_args, MemOperand(rbp, kPackedArrayOffset));
  __ movq(signature, MemOperand(rbp, kSignatureOffset));
  __ movq(valuetypes_array_ptr,
          MemOperand(signature, wasm::FunctionSig::kRepsOffset));
  __ movq(result_index, Immediate(0));

  __ LoadTaggedField(return_reg,
                     FieldOperand(fixed_array, result_index,
                                  static_cast<ScaleFactor>(kTaggedSizeLog2),
                                  OFFSET_OF_DATA_START(FixedArray)));
  __ jmp(&convert_return);

  // A result converted.
  __ bind(&return_done);

  // Restore after builtin call
  __ popq(context);
  __ popq(fixed_array);
  __ movq(valuetypes_array_ptr, MemOperand(rbp, kValueTypesArrayStartOffset));

  __ addq(valuetypes_array_ptr, Immediate(kValueTypeSize));
  __ movq(result_index, MemOperand(rbp, kResultIndexOffset));
  __ incq(result_index);
  __ cmpq(result_index, MemOperand(rbp, kReturnCountOffset));  // return_count
  __ j(greater_equal, &loop_copy_return_refs);

  __ LoadTaggedField(return_reg,
                     FieldOperand(fixed_array, result_index,
                                  static_cast<ScaleFactor>(kTaggedSizeLog2),
                                  OFFSET_OF_DATA_START(FixedArray)));
  __ jmp(&convert_return);

  // -------------------------------------------
  // Update refs after calling all builtins.
  // -------------------------------------------

  // Some builtin calls for return value conversion may trigger GC, and some
  // heap pointers of ref types might become invalid in the conversion loop.
  // Thus, copy the ref values again after finishing all the conversions.
  __ bind(&loop_copy_return_refs);

  // If there is only one return value, there should be no heap pointer in the
  // packed_args while calling any builtin. So, we don't need to update refs.
  __ movq(return_count, MemOperand(rbp, kReturnCountOffset));
  __ cmpl(return_count, Immediate(1));
  __ j(equal, &all_done);

  Label copy_return_if_ref, copy_return_ref, done_copy_return_ref;
  __ movq(packed_args, MemOperand(rbp, kPackedArrayOffset));
  __ movq(signature, MemOperand(rbp, kSignatureOffset));
  __ movq(valuetypes_array_ptr,
          MemOperand(signature, wasm::FunctionSig::kRepsOffset));
  __ movq(result_index, Immediate(0));

  // Copy if the current return value is a ref type.
  __ bind(&copy_return_if_ref);
  __ movl(valuetype,
          Operand(valuetypes_array_ptr, wasm::ValueType::bit_field_offset()));

  __ andl(valuetype, Immediate(wasm::kWasmValueKindBitsMask));
  __ cmpq(valuetype, Immediate(wasm::ValueKind::kRefNull));
  __ j(equal, &copy_return_ref);
  __ cmpq(valuetype, Immediate(wasm::ValueKind::kRef));
  __ j(equal, &copy_return_ref);

  Label inc_result_32bit;
  __ cmpq(valuetype, Immediate(wasm::kWasmI32.raw_bit_field()));
  __ j(equal, &inc_result_32bit);
  __ cmpq(valuetype, Immediate(wasm::kWasmF32.raw_bit_field()));
  __ j(equal, &inc_result_32bit);

  Label inc_result_64bit;
  __ cmpq(valuetype, Immediate(wasm::kWasmI64.raw_bit_field()));
  __ j(equal, &inc_result_64bit);
  __ cmpq(valuetype, Immediate(wasm::kWasmF64.raw_bit_field()));
  __ j(equal, &inc_result_64bit);

  // Invalid type. JavaScript cannot return Simd values to WebAssembly.
  __ int3();

  __ bind(&inc_result_32bit);
  __ addq(packed_args, Immediate(sizeof(int32_t)));
  __ jmp(&done_copy_return_ref);

  __ bind(&inc_result_64bit);
  __ addq(packed_args, Immediate(sizeof(int64_t)));
  __ jmp(&done_copy_return_ref);

  __ bind(&copy_return_ref);
  __ LoadTaggedField(return_reg,
                     FieldOperand(fixed_array, result_index,
                                  static_cast<ScaleFactor>(kTaggedSizeLog2),
                                  OFFSET_OF_DATA_START(FixedArray)));
  __ movq(MemOperand(packed_args, 0), return_reg);
  __ addq(packed_args, Immediate(kSystemPointerSize));

  // Move pointers.
  __ bind(&done_copy_return_ref);
  __ addq(valuetypes_array_ptr, Immediate(kValueTypeSize));
  __ incq(result_index);
  __ cmpq(result_index, MemOperand(rbp, kReturnCountOffset));
  __ j(less, &copy_return_if_ref);

  // -------------------------------------------
  // All done.
  // -------------------------------------------

  __ bind(&all_done);
  // Set thread_in_wasm_flag.
  thread_in_wasm_flag_addr = rcx;
  __ movq(
      thread_in_wasm_flag_addr,
      MemOperand(kRootRegister, Isolate::thread_in_wasm_flag_address_offset()));
  __ movl(MemOperand(thread_in_wasm_flag_addr, 0), Immediate(1));
  thread_in_wasm_flag_addr = no_reg;

  // Deconstruct the stack frame.
  __ LeaveFrame(StackFrame::WASM_TO_JS);

  __ xorq(rax, rax);
  __ ret(0);

  // --------------------------------------------------------------------------
  //                          Deferred code.
  // --------------------------------------------------------------------------

  // -------------------------------------------------
  // Param conversion builtins (Wasm type -> JS type).
  // -------------------------------------------------
  __ bind(&convert_param);

  // Prepare for builtin call.

  // Need to specify how many heap objects, that should be scanned by GC, are
  // on the top of the stack. (Only the context).
  // The builtin expects the parameter to be in register param = rax.

  __ movq(MemOperand(rbp, kExpectedArityOffset), expected_arity);
  __ movq(MemOperand(rbp, kParamIndexOffset), param_index);
  __ movq(MemOperand(rbp, kValueTypesArrayStartOffset), valuetypes_array_ptr);
  __ movq(MemOperand(rbp, kCurrentParamOffset), current_param_slot_offset);

  // When calling Wasm->JS conversion builtins, the top of the stack contains
  // three additional tagged objects that should be visited during GC: receiver
  // and callable.
  __ addq(MemOperand(rbp,
                     WasmToJSInterpreterFrameConstants::kGCScanSlotCountOffset),
          Immediate(3));
  __ pushq(receiver);
  __ pushq(callable);
  __ pushq(context);

  Label param_kWasmI32_not_smi;
  Label param_kWasmI64;
  Label param_kWasmF32;
  Label param_kWasmF64;
  Label finish_param_conversion;

  __ cmpq(valuetype, Immediate(wasm::kWasmI32.raw_bit_field()));
  __ j(equal, &param_kWasmI32_not_smi);

  __ cmpq(valuetype, Immediate(wasm::kWasmI64.raw_bit_field()));
  __ j(equal, &param_kWasmI64);

  __ cmpq(valuetype, Immediate(wasm::kWasmF32.raw_bit_field()));
  __ j(equal, &param_kWasmF32);

  __ cmpq(valuetype, Immediate(wasm::kWasmF64.raw_bit_field()));
  __ j(equal, &param_kWasmF64);

  // Invalid type. Wasm cannot pass Simd arguments to JavaScript.
  __ int3();

  __ bind(&param_kWasmI32_not_smi);
  __ Call(BUILTIN_CODE(masm->isolate(), WasmInt32ToHeapNumber),
          RelocInfo::CODE_TARGET);
  // Param is the result of the builtin.
  __ movq(rbx, Immediate(sizeof(int32_t)));
  __ jmp(&finish_param_conversion);

  __ bind(&param_kWasmI64);
  __ movq(param,
          MemOperand(packed_args, current_param_slot_offset, times_1, 0));
  __ Call(BUILTIN_CODE(masm->isolate(), I64ToBigInt), RelocInfo::CODE_TARGET);
  __ movq(rbx, Immediate(sizeof(int64_t)));
  __ jmp(&finish_param_conversion);

  __ bind(&param_kWasmF32);
  __ Movsd(xmm0,
           MemOperand(packed_args, current_param_slot_offset, times_1, 0));
  __ Call(BUILTIN_CODE(masm->isolate(), WasmFloat32ToNumber),
          RelocInfo::CODE_TARGET);
  __ movq(rbx, Immediate(sizeof(float)));
  __ jmp(&finish_param_conversion);

  __ bind(&param_kWasmF64);
  __ movq(xmm0, MemOperand(packed_args, current_param_slot_offset, times_1, 0));
  __ Call(BUILTIN_CODE(masm->isolate(), WasmFloat64ToNumber),
          RelocInfo::CODE_TARGET);
  __ movq(rbx, Immediate(sizeof(double)));

  // Restore after builtin call.
  __ bind(&finish_param_conversion);
  __ popq(context);
  __ popq(callable);
  __ popq(receiver);

  __ movq(current_param_slot_offset, MemOperand(rbp, kCurrentParamOffset));
  __ addq(current_param_slot_offset, rbx);
  __ movq(valuetypes_array_ptr, MemOperand(rbp, kValueTypesArrayStartOffset));
  __ movq(param_index, MemOperand(rbp, kParamIndexOffset));
  __ movq(expected_arity, MemOperand(rbp, kExpectedArityOffset));
  __ movq(packed_args, MemOperand(rbp, kPackedArrayOffset));

  __ movq(MemOperand(rsp, param_index, times_system_pointer_size, 0), param);
  __ subq(MemOperand(rbp,
                     WasmToJSInterpreterFrameConstants::kGCScanSlotCountOffset),
          Immediate(3));
  __ jmp(&param_conversion_done);

  // -------------------------------------------
  // Return conversions (JS type -> Wasm type).
  // -------------------------------------------
  __ bind(&convert_return);

  // Save registers in the stack before the builtin call.
  __ movq(MemOperand(rbp, kResultIndexOffset), result_index);
  __ movq(MemOperand(rbp, kValueTypesArrayStartOffset), valuetypes_array_ptr);
  __ movq(MemOperand(rbp, kCurrentResultAddressOffset), packed_args);

  // The following slots should be visited during GC.
  __ Move(MemOperand(rbp,
                     WasmToJSInterpreterFrameConstants::kGCScanSlotCountOffset),
          2);
  __ pushq(fixed_array);
  __ pushq(context);

  // The builtin expects the parameter to be in register param = rax.

  // The first valuetype of the array is the return's valuetype.
  __ movl(valuetype,
          Operand(valuetypes_array_ptr, wasm::ValueType::bit_field_offset()));

  Label return_kWasmI32;
  Label return_kWasmI32_not_smi;
  Label return_kWasmI64;
  Label return_kWasmF32;
  Label return_kWasmF64;
  Label return_kWasmRef;

  // Prepare for builtin call.

  __ cmpq(valuetype, Immediate(wasm::kWasmI32.raw_bit_field()));
  __ j(equal, &return_kWasmI32);

  __ cmpq(valuetype, Immediate(wasm::kWasmI64.raw_bit_field()));
  __ j(equal, &return_kWasmI64);

  __ cmpq(valuetype, Immediate(wasm::kWasmF32.raw_bit_field()));
  __ j(equal, &return_kWasmF32);

  __ cmpq(valuetype, Immediate(wasm::kWasmF64.raw_bit_field()));
  __ j(equal, &return_kWasmF64);

  __ andl(valuetype, Immediate(wasm::kWasmValueKindBitsMask));
  __ cmpq(valuetype, Immediate(wasm::ValueKind::kRefNull));
  __ j(equal, &return_kWasmRef);
  __ cmpq(valuetype, Immediate(wasm::ValueKind::kRef));
  __ j(equal, &return_kWasmRef);

  // Invalid type. JavaScript cannot return Simd results to WebAssembly.
  __ int3();

  __ bind(&return_kWasmI32);
  __ JumpIfNotSmi(return_reg, &return_kWasmI32_not_smi);
  // Change the param from Smi to int32.
  __ SmiUntag(return_reg);
  // Zero extend.
  __ movl(return_reg, return_reg);
  __ movl(MemOperand(packed_args, 0), return_reg);
  __ addq(packed_args, Immediate(sizeof(int32_t)));
  __ jmp(&return_done);

  __ bind(&return_kWasmI32_not_smi);
  __ Call(BUILTIN_CODE(masm->isolate(), WasmTaggedNonSmiToInt32),
          RelocInfo::CODE_TARGET);
  __ AssertZeroExtended(return_reg);
  __ movq(packed_args, MemOperand(rbp, kCurrentResultAddressOffset));
  __ movl(MemOperand(packed_args, 0), return_reg);
  __ addq(packed_args, Immediate(sizeof(int32_t)));
  __ jmp(&return_done);

  __ bind(&return_kWasmI64);
  __ Call(BUILTIN_CODE(masm->isolate(), BigIntToI64), RelocInfo::CODE_TARGET);
  __ movq(packed_args, MemOperand(rbp, kCurrentResultAddressOffset));
  __ movq(MemOperand(packed_args, 0), return_reg);
  __ addq(packed_args, Immediate(sizeof(int64_t)));
  __ jmp(&return_done);

  __ bind(&return_kWasmF32);
  __ Call(BUILTIN_CODE(masm->isola
```