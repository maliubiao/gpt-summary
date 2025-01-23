Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/codegen/arm64/macro-assembler-arm64.cc`. They are asking for a summary of its features, including:

1. **General Functionality:** What does this code do?
2. **Torque Source:**  Does the `.cc` extension imply it's Torque (it doesn't)?
3. **JavaScript Relevance:** How does this code relate to JavaScript execution, and can I have a JavaScript example?
4. **Logic Inference:** Provide an example of input and output if the code performs logical operations.
5. **Common Programming Errors:**  Are there common mistakes this code helps avoid or relates to?
6. **Part Summary:** A concise summary of the functionality of *this specific part* of the file (part 4 of 6).

Let's break down the provided code:

- **Function Calls & Invocation:**  The core functionality revolves around calling JavaScript functions. This includes handling debugging hooks, adapting arguments, and jumping to the function's code. The different `InvokeFunction` and `InvokeFunctionCode` variations handle cases with and without `new.target`.
- **Deoptimization Checks:**  The code checks if a function's code is marked for deoptimization or if it's a Turbofan-optimized function.
- **Data Access:** There are functions for accessing memory, specifically loading and storing tagged fields (V8's object representation). This includes handling compressed pointers.
- **Type Checking:**  Several functions (`JumpIfObjectType`, `IsObjectType`, `CompareObjectType`) are used for determining the type of JavaScript objects.
- **Stack Frame Management:** Functions like `Prologue`, `EnterFrame`, `LeaveFrame`, and `EnterExitFrame` manage the call stack.
- **Root Table Access:** The code interacts with V8's root table, which stores important objects.
- **Counters:** There's a function for incrementing performance counters.
- **Double to Integer Conversion:** A function for converting double-precision floating-point numbers to integers.

Now, let's address each of the user's points:

1. **General Functionality:** This code defines low-level building blocks (macros) used in V8's ARM64 code generator. These macros abstract away architecture-specific instructions for common operations in JavaScript execution, such as function calls, object access, and type checks.

2. **Torque Source:** The user correctly identifies that a `.tq` extension would indicate a Torque source file. `.cc` means this is standard C++ code.

3. **JavaScript Relevance:** This code is *directly* responsible for executing JavaScript. When the V8 engine runs JavaScript code, it compiles it into machine code. This `macro-assembler-arm64.cc` file provides the tools to generate that ARM64 machine code. The function call mechanisms are a key part of this.

4. **Logic Inference:**  The `JumpIfObjectType` family of functions provides clear logic. For example, if you want to check if an object is an Array:

   * **Hypothetical Input:**
     - `object` register contains a pointer to a JavaScript object.
     - `map` register will be loaded with the object's map.
     - `type_reg` will hold the instance type.
     - `InstanceType::JS_ARRAY_TYPE` is the target type.
     - `if_cond_pass` is a label to jump to if the object is an array.

   * **Hypothetical Output:**
     - If the object is an Array, execution will jump to the `if_cond_pass` label.
     - Otherwise, execution will continue to the next instruction.

5. **Common Programming Errors:**  This code helps *avoid* low-level assembly errors by providing a higher-level abstraction. However, related errors in JavaScript (from a user's perspective) might be:

   * **TypeError:**  Many of the type checking functions here directly relate to the runtime checks that result in `TypeError` exceptions in JavaScript. For example, trying to call a non-function, or accessing a property on `null` or `undefined`.

   ```javascript
   // Example leading to a TypeError (internally, similar type checks happen)
   let notAFunction = {};
   notAFunction(); // TypeError: notAFunction is not a function
   ```

6. **Part Summary:** This section of `macro-assembler-arm64.cc` primarily focuses on **function invocation and basic object manipulation**. It provides the building blocks for calling JavaScript functions, checking their types, and accessing their properties. It also includes mechanisms for debugging and managing the call stack.
This part of the `v8/src/codegen/arm64/macro-assembler-arm64.cc` file focuses on the following functionalities:

**1. Function Invocation:**

* **`CallDebugOnFunctionCall`:** This function handles the execution logic when a debug hook is active during a function call. It saves relevant information on the stack, calls the runtime function `Runtime::kDebugOnFunctionCall`, and restores the stack afterwards.
* **`InvokeFunction` and `InvokeFunctionWithNewTarget`:** These functions provide high-level ways to invoke JavaScript functions. They set up the context, handle the `new.target` if present, and then delegate the actual call to `InvokeFunctionCode`. The `#ifdef V8_ENABLE_LEAPTIERING` block indicates there are different implementations depending on whether the "Leaptiering" optimization is enabled.
* **`InvokeFunctionCode`:** This is the core function for actually invoking the JavaScript function. It retrieves the dispatch handle (which contains the entry point), checks for debug hooks, potentially adapts arguments based on `ArgumentAdaptionMode`, and finally performs the `Call` or `Jump` to the function's code. The distinction between `Call` and `Jump` relates to whether the current function expects to return or if it's a tail call.

**2. Code Deoptimization Checks:**

* **`JumpIfCodeIsMarkedForDeoptimization`:** Checks if a given code object is marked for deoptimization and jumps to a specified label if it is. This is crucial for the V8 engine's optimization and deoptimization pipeline.
* **`JumpIfCodeIsTurbofanned`:** Checks if a given code object was generated by Turbofan (V8's optimizing compiler) and jumps to a specified label if it is.

**3. Miscellaneous Helpers:**

* **`ClearedValue()`:** Returns an operand representing a cleared value, often used for initializing memory.
* **`ReceiverOperand()`:** Returns an operand representing the receiver (the `this` value) of a function call.
* **`TryConvertDoubleToInt64`:** Attempts to convert a double-precision floating-point number to a 64-bit integer using an FPU instruction. It handles potential saturation cases.
* **`TruncateDoubleToI`:**  Truncates a double-precision floating-point number to a 32-bit integer. It uses the FPU instruction if available and falls back to a runtime stub otherwise.

**4. Stack Frame Management:**

* **`Prologue()`:** Generates the standard function prologue code, saving the link register (return address) and frame pointer, and pushing some essential registers.
* **`EnterFrame()`:** Sets up a new stack frame, either a minimal "machine frame" for JavaScript calls or a more detailed frame for internal calls, including a frame type marker.
* **`LeaveFrame()`:** Tears down the current stack frame, restoring the stack pointer, frame pointer, and link register.
* **`EnterExitFrame()`:** Sets up a special "exit frame" when calling out from JavaScript code to native code (like C++). It saves the current frame pointer and context pointer and allocates space on the stack.
* **`LeaveExitFrame()`:**  Cleans up the exit frame, restoring the context pointer and popping the frame.

**5. Global Proxy Access:**

* **`LoadGlobalProxy()`:** Loads the global proxy object into a register.

**6. Weak Value Handling:**

* **`LoadWeakValue()`:**  Loads the value from a weak reference. If the referenced object has been garbage collected, it jumps to a specific label.

**7. Performance Counters:**

* **`EmitIncrementCounter()`:**  Increments a performance counter if native code counters are enabled.

**8. Object Type Checking:**

* **`JumpIfObjectType()`:** Checks the type of a JavaScript object and jumps to a label based on the result.
* **`JumpIfJSAnyIsNotPrimitive()`:** Checks if a value is a primitive type and jumps accordingly.
* **`CompareInstanceTypeWithUniqueCompressedMap()` and `IsObjectTypeFast()`:** Optimized ways to compare the instance type of an object, especially when dealing with compressed pointers.
* **`IsObjectType()` and `IsObjectTypeInRange()`:** Functions to check if an object's type matches a specific type or falls within a range of types.
* **`CompareObjectType()`:**  Loads the map of an object and then compares its instance type.
* **`CompareRange()` and `JumpIfIsInRange()`:**  Helper functions for comparing a value against a numerical range.

**9. Map and Feedback Vector Loading:**

* **`LoadCompressedMap()` and `LoadMap()`:** Load the map of a JavaScript object. The `CompressedMap` version is used when pointer compression is enabled.
* **`LoadFeedbackVector()`:** Loads the feedback vector associated with a function, which is used for optimization.

**10. Instance Type Comparison:**

* **`CompareInstanceType()` and `CompareInstanceTypeRange()`:** Compare the instance type of a map against a specific type or a range of types.

**11. Elements Kind Loading:**

* **`LoadElementsKindFromMap()`:**  Extracts the elements kind (e.g., packed, holey) from an object's map.

**12. Root Table Comparisons:**

* **`CompareTaggedRoot()`, `CompareRoot()`, `JumpIfRoot()`, `JumpIfNotRoot()`:** Functions for comparing a register's value with a value stored in the V8 root table.

**13. Immediate Value Range Checks:**

* **`JumpIfIsInRange()` (with immediate values):** Checks if a register's value falls within a given immediate value range.

**14. Tagged Field Access (with Pointer Compression Handling):**

* **`LoadTaggedField()`, `LoadTaggedFieldWithoutDecompressing()`, `LoadTaggedSignedField()`:** Functions to load tagged values (pointers to V8 objects or smis) from memory. They handle pointer decompression if necessary.
* **`SmiUntagField()`:** Untags a Smi value loaded from memory.
* **`StoreTwoTaggedFields()` and `StoreTaggedField()`:** Functions to store tagged values into memory, handling pointer compression.
* **`AtomicStoreTaggedField()`:**  Performs an atomic store of a tagged field.
* **`DecompressTaggedSigned()`, `DecompressTagged()`, `DecompressProtected()`:** Functions to decompress tagged pointers, handling different scenarios like signed values and protected pointers (in sandboxed environments).
* **`AtomicDecompressTaggedSigned()` and `AtomicDecompressTagged()`:**  Perform atomic decompression of tagged pointers.

**In summary, this part of `macro-assembler-arm64.cc` provides a set of fundamental building blocks (macros) for generating ARM64 assembly code within the V8 JavaScript engine. It covers essential operations like function calls, object manipulation, type checking, stack management, and memory access, all while considering optimizations like pointer compression and deoptimization.**

Regarding your specific questions:

* **`.tq` extension:** You are correct, a `.tq` extension would indicate a V8 Torque source file. This file is standard C++ (`.cc`).
* **JavaScript example:** The function invocation logic directly relates to how JavaScript function calls are executed. For example, when you call a function in JavaScript:

```javascript
function myFunction(a, b) {
  return a + b;
}

let result = myFunction(5, 10);
```

Internally, V8 will generate ARM64 assembly code using functions like `InvokeFunction` and `InvokeFunctionCode` to set up the call, pass arguments, and jump to the compiled code for `myFunction`. The type checks within these functions are also crucial for ensuring the correct behavior of JavaScript at runtime.
* **Code logic inference:**  Consider the `JumpIfObjectType` function.

   * **Hypothetical Input:**
      - `object` register holds a pointer to a JavaScript object.
      - `map` register is available for temporary storage.
      - `type_reg` is available for temporary storage.
      - `InstanceType::JS_OBJECT_TYPE` is the `type` we want to check.
      - `if_cond_pass` is a label to jump to if the object is a plain JavaScript object.
      - `cond` is `eq` (equal).

   * **Process:** The function will:
      1. Load the `map` of the `object` into the `map` register.
      2. Load the `InstanceType` from the `map` into the `type_reg` register.
      3. Compare the value in `type_reg` with `InstanceType::JS_OBJECT_TYPE`.
      4. If they are equal (based on the `eq` condition), jump to the `if_cond_pass` label.

   * **Hypothetical Output:** If the `object` is indeed a plain JavaScript object (like `{}`), the execution will jump to the `if_cond_pass` label. Otherwise, execution will continue to the next instruction.

* **User common programming errors:** This code is more about the internal workings of V8. However, the type checking functions directly relate to common JavaScript errors that result in `TypeError` exceptions. For instance, trying to call a non-function:

```javascript
let notAFunction = {};
notAFunction(); // This will result in a TypeError at runtime.
```

Internally, V8's generated code would likely use functions like `IsObjectType` to verify that `notAFunction` is indeed a function before attempting to call it.

This part of the `macro-assembler-arm64.cc` file is fundamental for the correct and efficient execution of JavaScript code on ARM64 architectures within the V8 engine.

### 提示词
```
这是目录为v8/src/codegen/arm64/macro-assembler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm64/macro-assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
actual_parameter_count) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(x5, fun, new_target,
                     expected_parameter_count_or_dispatch_handle,
                     actual_parameter_count));
  // Load receiver to pass it later to DebugOnFunctionCall hook.
  Peek(x5, ReceiverOperand());
  FrameScope frame(
      this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);

  if (!new_target.is_valid()) new_target = padreg;

  // Save values on stack.
  SmiTag(expected_parameter_count_or_dispatch_handle);
  SmiTag(actual_parameter_count);
  Push(expected_parameter_count_or_dispatch_handle, actual_parameter_count,
       new_target, fun);
  Push(fun, x5);
  CallRuntime(Runtime::kDebugOnFunctionCall);

  // Restore values from stack.
  Pop(fun, new_target, actual_parameter_count,
      expected_parameter_count_or_dispatch_handle);
  SmiUntag(actual_parameter_count);
  SmiUntag(expected_parameter_count_or_dispatch_handle);
}

#ifdef V8_ENABLE_LEAPTIERING
void MacroAssembler::InvokeFunction(
    Register function, Register actual_parameter_count, InvokeType type,
    ArgumentAdaptionMode argument_adaption_mode) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK(type == InvokeType::kJump || has_frame());

  // Contract with called JS functions requires that function is passed in x1.
  // (See FullCodeGenerator::Generate().)
  DCHECK_EQ(function, x1);

  // Set up the context.
  LoadTaggedField(cp, FieldMemOperand(function, JSFunction::kContextOffset));

  InvokeFunctionCode(function, no_reg, actual_parameter_count, type,
                     argument_adaption_mode);
}

void MacroAssembler::InvokeFunctionWithNewTarget(
    Register function, Register new_target, Register actual_parameter_count,
    InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK(type == InvokeType::kJump || has_frame());

  // Contract with called JS functions requires that function is passed in x1.
  // (See FullCodeGenerator::Generate().)
  DCHECK_EQ(function, x1);

  LoadTaggedField(cp, FieldMemOperand(function, JSFunction::kContextOffset));

  InvokeFunctionCode(function, new_target, actual_parameter_count, type);
}

void MacroAssembler::InvokeFunctionCode(
    Register function, Register new_target, Register actual_parameter_count,
    InvokeType type, ArgumentAdaptionMode argument_adaption_mode) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());
  DCHECK_EQ(function, x1);
  DCHECK_IMPLIES(new_target.is_valid(), new_target == x3);

  Register dispatch_handle = kJavaScriptCallDispatchHandleRegister;
  Ldr(dispatch_handle.W(),
      FieldMemOperand(function, JSFunction::kDispatchHandleOffset));

  // On function call, call into the debugger if necessary.
  Label debug_hook, continue_after_hook;
  {
    Mov(x5, ExternalReference::debug_hook_on_function_call_address(isolate()));
    Ldrsb(x5, MemOperand(x5));
    Cbnz(x5, &debug_hook);
  }
  bind(&continue_after_hook);

  // Clear the new.target register if not given.
  if (!new_target.is_valid()) {
    LoadRoot(x3, RootIndex::kUndefinedValue);
  }

  Register scratch = x20;
  if (argument_adaption_mode == ArgumentAdaptionMode::kAdapt) {
    Register expected_parameter_count = x2;
    LoadParameterCountFromJSDispatchTable(expected_parameter_count,
                                          dispatch_handle, scratch);
    InvokePrologue(expected_parameter_count, actual_parameter_count, type);
  }

  // We call indirectly through the code field in the function to
  // allow recompilation to take effect without changing any of the
  // call sites.
  LoadEntrypointFromJSDispatchTable(kJavaScriptCallCodeStartRegister,
                                    dispatch_handle, scratch);
  switch (type) {
    case InvokeType::kCall:
      Call(kJavaScriptCallCodeStartRegister);
      break;
    case InvokeType::kJump:
      // We jump through x17 here because for Branch Identification (BTI) we use
      // "Call" (`bti c`) rather than "Jump" (`bti j`) landing pads for
      // tail-called code. See TailCallBuiltin for more information.
      Mov(x17, kJavaScriptCallCodeStartRegister);
      Jump(x17);
      break;
  }
  Label done;
  B(&done);

  // Deferred debug hook.
  bind(&debug_hook);
  CallDebugOnFunctionCall(function, new_target, dispatch_handle,
                          actual_parameter_count);
  B(&continue_after_hook);

  bind(&done);
}
#else
void MacroAssembler::InvokeFunctionCode(Register function, Register new_target,
                                        Register expected_parameter_count,
                                        Register actual_parameter_count,
                                        InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());
  DCHECK_EQ(function, x1);
  DCHECK_IMPLIES(new_target.is_valid(), new_target == x3);

  // On function call, call into the debugger if necessary.
  Label debug_hook, continue_after_hook;
  {
    Mov(x5, ExternalReference::debug_hook_on_function_call_address(isolate()));
    Ldrsb(x5, MemOperand(x5));
    Cbnz(x5, &debug_hook);
  }
  bind(&continue_after_hook);

  // Clear the new.target register if not given.
  if (!new_target.is_valid()) {
    LoadRoot(x3, RootIndex::kUndefinedValue);
  }

  InvokePrologue(expected_parameter_count, actual_parameter_count, type);

  // The called function expects the call kind in x5.
  // We call indirectly through the code field in the function to
  // allow recompilation to take effect without changing any of the
  // call sites.
  constexpr int unused_argument_count = 0;
  switch (type) {
    case InvokeType::kCall:
      CallJSFunction(function, unused_argument_count);
      break;
    case InvokeType::kJump:
      JumpJSFunction(function);
      break;
  }
  Label done;
  B(&done);

  // Deferred debug hook.
  bind(&debug_hook);
  CallDebugOnFunctionCall(function, new_target, expected_parameter_count,
                          actual_parameter_count);
  B(&continue_after_hook);

  bind(&done);
}

void MacroAssembler::InvokeFunctionWithNewTarget(
    Register function, Register new_target, Register actual_parameter_count,
    InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK(type == InvokeType::kJump || has_frame());

  // Contract with called JS functions requires that function is passed in x1.
  // (See FullCodeGenerator::Generate().)
  DCHECK_EQ(function, x1);

  Register expected_parameter_count = x2;

  LoadTaggedField(cp, FieldMemOperand(function, JSFunction::kContextOffset));
  // The number of arguments is stored as an int32_t, and -1 is a marker
  // (kDontAdaptArgumentsSentinel), so we need sign
  // extension to correctly handle it.
  LoadTaggedField(
      expected_parameter_count,
      FieldMemOperand(function, JSFunction::kSharedFunctionInfoOffset));
  Ldrh(expected_parameter_count,
       FieldMemOperand(expected_parameter_count,
                       SharedFunctionInfo::kFormalParameterCountOffset));

  InvokeFunctionCode(function, new_target, expected_parameter_count,
                     actual_parameter_count, type);
}

void MacroAssembler::InvokeFunction(Register function,
                                    Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK(type == InvokeType::kJump || has_frame());

  // Contract with called JS functions requires that function is passed in x1.
  // (See FullCodeGenerator::Generate().)
  DCHECK_EQ(function, x1);

  // Set up the context.
  LoadTaggedField(cp, FieldMemOperand(function, JSFunction::kContextOffset));

  InvokeFunctionCode(function, no_reg, expected_parameter_count,
                     actual_parameter_count, type);
}
#endif  // V8_ENABLE_LEAPTIERING

void MacroAssembler::JumpIfCodeIsMarkedForDeoptimization(
    Register code, Register scratch, Label* if_marked_for_deoptimization) {
  Ldr(scratch.W(), FieldMemOperand(code, Code::kFlagsOffset));
  Tbnz(scratch.W(), Code::kMarkedForDeoptimizationBit,
       if_marked_for_deoptimization);
}

void MacroAssembler::JumpIfCodeIsTurbofanned(Register code, Register scratch,
                                             Label* if_turbofanned) {
  Ldr(scratch.W(), FieldMemOperand(code, Code::kFlagsOffset));
  Tbnz(scratch.W(), Code::kIsTurbofannedBit, if_turbofanned);
}

Operand MacroAssembler::ClearedValue() const {
  return Operand(static_cast<int32_t>(i::ClearedValue(isolate()).ptr()));
}

Operand MacroAssembler::ReceiverOperand() { return Operand(0); }

void MacroAssembler::TryConvertDoubleToInt64(Register result,
                                             DoubleRegister double_input,
                                             Label* done) {
  ASM_CODE_COMMENT(this);
  // Try to convert with an FPU convert instruction. It's trivial to compute
  // the modulo operation on an integer register so we convert to a 64-bit
  // integer.
  //
  // Fcvtzs will saturate to INT64_MIN (0x800...00) or INT64_MAX (0x7FF...FF)
  // when the double is out of range. NaNs and infinities will be converted to 0
  // (as ECMA-262 requires).
  Fcvtzs(result.X(), double_input);

  // The values INT64_MIN (0x800...00) or INT64_MAX (0x7FF...FF) are not
  // representable using a double, so if the result is one of those then we know
  // that saturation occurred, and we need to manually handle the conversion.
  //
  // It is easy to detect INT64_MIN and INT64_MAX because adding or subtracting
  // 1 will cause signed overflow.
  Cmp(result.X(), 1);
  Ccmp(result.X(), -1, VFlag, vc);

  B(vc, done);
}

void MacroAssembler::TruncateDoubleToI(Isolate* isolate, Zone* zone,
                                       Register result,
                                       DoubleRegister double_input,
                                       StubCallMode stub_mode,
                                       LinkRegisterStatus lr_status) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(JSCVT)) {
    Fjcvtzs(result.W(), double_input);
    return;
  }

  Label done;

  // Try to convert the double to an int64. If successful, the bottom 32 bits
  // contain our truncated int32 result.
  TryConvertDoubleToInt64(result, double_input, &done);

  // If we fell through then inline version didn't succeed - call stub instead.
  if (lr_status == kLRHasNotBeenSaved) {
    Push<MacroAssembler::kSignLR>(lr, double_input);
  } else {
    Push<MacroAssembler::kDontStoreLR>(xzr, double_input);
  }

  // DoubleToI preserves any registers it needs to clobber.
#if V8_ENABLE_WEBASSEMBLY
  if (stub_mode == StubCallMode::kCallWasmRuntimeStub) {
    Call(static_cast<Address>(Builtin::kDoubleToI), RelocInfo::WASM_STUB_CALL);
#else
  // For balance.
  if (false) {
#endif  // V8_ENABLE_WEBASSEMBLY
  } else {
    CallBuiltin(Builtin::kDoubleToI);
  }
  Ldr(result, MemOperand(sp, 0));

  DCHECK_EQ(xzr.SizeInBytes(), double_input.SizeInBytes());

  if (lr_status == kLRHasNotBeenSaved) {
    // Pop into xzr here to drop the double input on the stack:
    Pop<MacroAssembler::kAuthLR>(xzr, lr);
  } else {
    Drop(2);
  }

  Bind(&done);
  // Keep our invariant that the upper 32 bits are zero.
  Uxtw(result.W(), result.W());
}

void MacroAssembler::Prologue() {
  ASM_CODE_COMMENT(this);
  Push<MacroAssembler::kSignLR>(lr, fp);
  mov(fp, sp);
  static_assert(kExtraSlotClaimedByPrologue == 1);
  Push(cp, kJSFunctionRegister, kJavaScriptCallArgCountRegister, padreg);
}

void MacroAssembler::EnterFrame(StackFrame::Type type) {
  UseScratchRegisterScope temps(this);

  if (StackFrame::IsJavaScript(type)) {
    // Just push a minimal "machine frame", saving the frame pointer and return
    // address, without any markers.
    Push<MacroAssembler::kSignLR>(lr, fp);
    Mov(fp, sp);
    // sp[1] : lr
    // sp[0] : fp
  } else {
      Register type_reg = temps.AcquireX();
      Mov(type_reg, StackFrame::TypeToMarker(type));
      Register fourth_reg = padreg;
      if (type == StackFrame::CONSTRUCT || type == StackFrame::FAST_CONSTRUCT) {
        fourth_reg = cp;
      }
#if V8_ENABLE_WEBASSEMBLY
      if (type == StackFrame::WASM || type == StackFrame::WASM_LIFTOFF_SETUP ||
          type == StackFrame::WASM_EXIT) {
        fourth_reg = kWasmImplicitArgRegister;
      }
#endif  // V8_ENABLE_WEBASSEMBLY
      Push<MacroAssembler::kSignLR>(lr, fp, type_reg, fourth_reg);
      static constexpr int kSPToFPDelta  = 2 * kSystemPointerSize;
      Add(fp, sp, kSPToFPDelta);
      // sp[3] : lr
      // sp[2] : fp
      // sp[1] : type
      // sp[0] : cp | wasm instance | for alignment
  }
}

void MacroAssembler::LeaveFrame(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  // Drop the execution stack down to the frame pointer and restore
  // the caller frame pointer and return address.
  Mov(sp, fp);
  Pop<MacroAssembler::kAuthLR>(fp, lr);
}

void MacroAssembler::EnterExitFrame(const Register& scratch, int extra_space,
                                    StackFrame::Type frame_type) {
  ASM_CODE_COMMENT(this);
  DCHECK(frame_type == StackFrame::EXIT ||
         frame_type == StackFrame::BUILTIN_EXIT ||
         frame_type == StackFrame::API_ACCESSOR_EXIT ||
         frame_type == StackFrame::API_CALLBACK_EXIT);

  // Set up the new stack frame.
  Push<MacroAssembler::kSignLR>(lr, fp);
  Mov(fp, sp);
  Mov(scratch, StackFrame::TypeToMarker(frame_type));
  Push(scratch, xzr);
  //          fp[8]: CallerPC (lr)
  //    fp -> fp[0]: CallerFP (old fp)
  //          fp[-8]: STUB marker
  //    sp -> fp[-16]: Space reserved for SPOffset.
  static_assert((2 * kSystemPointerSize) ==
                ExitFrameConstants::kCallerSPOffset);
  static_assert((1 * kSystemPointerSize) ==
                ExitFrameConstants::kCallerPCOffset);
  static_assert((0 * kSystemPointerSize) ==
                ExitFrameConstants::kCallerFPOffset);
  static_assert((-2 * kSystemPointerSize) == ExitFrameConstants::kSPOffset);

  // Save the frame pointer and context pointer in the top frame.
  Mov(scratch,
      ExternalReference::Create(IsolateAddressId::kCEntryFPAddress, isolate()));
  Str(fp, MemOperand(scratch));
  Mov(scratch,
      ExternalReference::Create(IsolateAddressId::kContextAddress, isolate()));
  Str(cp, MemOperand(scratch));

  static_assert((-2 * kSystemPointerSize) ==
                ExitFrameConstants::kLastExitFrameField);

  // Round the number of space we need to claim to a multiple of two.
  int slots_to_claim = RoundUp(extra_space + 1, 2);

  // Reserve space for the return address and for user requested memory.
  // We do this before aligning to make sure that we end up correctly
  // aligned with the minimum of wasted space.
  Claim(slots_to_claim, kXRegSize);
  //         fp[8]: CallerPC (lr)
  //   fp -> fp[0]: CallerFP (old fp)
  //         fp[-8]: STUB marker
  //         fp[-16]: Space reserved for SPOffset.
  //         sp[8]: Extra space reserved for caller (if extra_space != 0).
  //   sp -> sp[0]: Space reserved for the return address.

  // ExitFrame::GetStateForFramePointer expects to find the return address at
  // the memory address immediately below the pointer stored in SPOffset.
  // It is not safe to derive much else from SPOffset, because the size of the
  // padding can vary.
  Add(scratch, sp, kXRegSize);
  Str(scratch, MemOperand(fp, ExitFrameConstants::kSPOffset));
}

// Leave the current exit frame.
void MacroAssembler::LeaveExitFrame(const Register& scratch,
                                    const Register& scratch2) {
  ASM_CODE_COMMENT(this);

  // Restore the context pointer from the top frame.
  Mov(scratch,
      ExternalReference::Create(IsolateAddressId::kContextAddress, isolate()));
  Ldr(cp, MemOperand(scratch));

  if (v8_flags.debug_code) {
    // Also emit debug code to clear the cp in the top frame.
    Mov(scratch2, Operand(Context::kInvalidContext));
    Mov(scratch, ExternalReference::Create(IsolateAddressId::kContextAddress,
                                           isolate()));
    Str(scratch2, MemOperand(scratch));
  }
  // Clear the frame pointer from the top frame.
  Mov(scratch,
      ExternalReference::Create(IsolateAddressId::kCEntryFPAddress, isolate()));
  Str(xzr, MemOperand(scratch));

  // Pop the exit frame.
  //         fp[8]: CallerPC (lr)
  //   fp -> fp[0]: CallerFP (old fp)
  //         fp[...]: The rest of the frame.
  Mov(sp, fp);
  Pop<MacroAssembler::kAuthLR>(fp, lr);
}

void MacroAssembler::LoadGlobalProxy(Register dst) {
  ASM_CODE_COMMENT(this);
  LoadNativeContextSlot(dst, Context::GLOBAL_PROXY_INDEX);
}

void MacroAssembler::LoadWeakValue(Register out, Register in,
                                   Label* target_if_cleared) {
  ASM_CODE_COMMENT(this);
  CompareAndBranch(in.W(), Operand(kClearedWeakHeapObjectLower32), eq,
                   target_if_cleared);

  and_(out, in, Operand(~kWeakHeapObjectMask));
}

void MacroAssembler::EmitIncrementCounter(StatsCounter* counter, int value,
                                          Register scratch1,
                                          Register scratch2) {
  ASM_CODE_COMMENT(this);
  DCHECK_NE(value, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    // This operation has to be exactly 32-bit wide in case the external
    // reference table redirects the counter to a uint32_t dummy_stats_counter_
    // field.
    Mov(scratch2, ExternalReference::Create(counter));
    Ldr(scratch1.W(), MemOperand(scratch2));
    Add(scratch1.W(), scratch1.W(), value);
    Str(scratch1.W(), MemOperand(scratch2));
  }
}

void MacroAssembler::JumpIfObjectType(Register object, Register map,
                                      Register type_reg, InstanceType type,
                                      Label* if_cond_pass, Condition cond) {
  ASM_CODE_COMMENT(this);
  CompareObjectType(object, map, type_reg, type);
  B(cond, if_cond_pass);
}

void MacroAssembler::JumpIfJSAnyIsNotPrimitive(Register heap_object,
                                               Register scratch, Label* target,
                                               Label::Distance distance,
                                               Condition cc) {
  CHECK(cc == Condition::kUnsignedLessThan ||
        cc == Condition::kUnsignedGreaterThanEqual);
  if (V8_STATIC_ROOTS_BOOL) {
#ifdef DEBUG
    Label ok;
    LoadMap(scratch, heap_object);
    CompareInstanceTypeRange(scratch, scratch, FIRST_JS_RECEIVER_TYPE,
                             LAST_JS_RECEIVER_TYPE);
    B(Condition::kUnsignedLessThanEqual, &ok);
    LoadMap(scratch, heap_object);
    CompareInstanceTypeRange(scratch, scratch, FIRST_PRIMITIVE_HEAP_OBJECT_TYPE,
                             LAST_PRIMITIVE_HEAP_OBJECT_TYPE);
    B(Condition::kUnsignedLessThanEqual, &ok);
    Abort(AbortReason::kInvalidReceiver);
    bind(&ok);
#endif  // DEBUG

    // All primitive object's maps are allocated at the start of the read only
    // heap. Thus JS_RECEIVER's must have maps with larger (compressed)
    // addresses.
    LoadCompressedMap(scratch, heap_object);
    CmpTagged(scratch, Immediate(InstanceTypeChecker::kNonJsReceiverMapLimit));
  } else {
    static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
    CompareObjectType(heap_object, scratch, scratch, FIRST_JS_RECEIVER_TYPE);
  }
  B(cc, target);
}

#if V8_STATIC_ROOTS_BOOL
void MacroAssembler::CompareInstanceTypeWithUniqueCompressedMap(
    Register map, Register scratch, InstanceType type) {
  std::optional<RootIndex> expected =
      InstanceTypeChecker::UniqueMapOfInstanceType(type);
  CHECK(expected);
  Tagged_t expected_ptr = ReadOnlyRootPtr(*expected);
  DCHECK_NE(map, scratch);
  UseScratchRegisterScope temps(this);
  CHECK(IsImmAddSub(expected_ptr) || scratch != Register::no_reg() ||
        temps.CanAcquire());
  if (!IsImmAddSub(expected_ptr)) {
    if (scratch == Register::no_reg()) {
      scratch = temps.AcquireX();
      DCHECK_NE(map, scratch);
    }
    Operand imm_operand =
        MoveImmediateForShiftedOp(scratch, expected_ptr, kAnyShift);
    CmpTagged(map, imm_operand);
  } else {
    CmpTagged(map, Immediate(expected_ptr));
  }
}

void MacroAssembler::IsObjectTypeFast(Register object,
                                      Register compressed_map_scratch,
                                      InstanceType type) {
  ASM_CODE_COMMENT(this);
  CHECK(InstanceTypeChecker::UniqueMapOfInstanceType(type));
  LoadCompressedMap(compressed_map_scratch, object);
  CompareInstanceTypeWithUniqueCompressedMap(compressed_map_scratch,
                                             Register::no_reg(), type);
}
#endif  // V8_STATIC_ROOTS_BOOL

// Sets equality condition flags.
void MacroAssembler::IsObjectType(Register object, Register scratch1,
                                  Register scratch2, InstanceType type) {
  ASM_CODE_COMMENT(this);

#if V8_STATIC_ROOTS_BOOL
  if (InstanceTypeChecker::UniqueMapOfInstanceType(type)) {
    LoadCompressedMap(scratch1, object);
    CompareInstanceTypeWithUniqueCompressedMap(
        scratch1, scratch1 != scratch2 ? scratch2 : Register::no_reg(), type);
    return;
  }
#endif  // V8_STATIC_ROOTS_BOOL

  CompareObjectType(object, scratch1, scratch2, type);
}

// Sets equality condition flags.
void MacroAssembler::IsObjectTypeInRange(Register heap_object, Register scratch,
                                         InstanceType lower_limit,
                                         InstanceType higher_limit) {
  DCHECK_LT(lower_limit, higher_limit);
#if V8_STATIC_ROOTS_BOOL
  if (auto range = InstanceTypeChecker::UniqueMapRangeOfInstanceTypeRange(
          lower_limit, higher_limit)) {
    LoadCompressedMap(scratch.W(), heap_object);
    CompareRange(scratch.W(), scratch.W(), range->first, range->second);
    return;
  }
#endif  // V8_STATIC_ROOTS_BOOL
  LoadMap(scratch, heap_object);
  CompareInstanceTypeRange(scratch, scratch, lower_limit, higher_limit);
}

// Sets condition flags based on comparison, and returns type in type_reg.
void MacroAssembler::CompareObjectType(Register object, Register map,
                                       Register type_reg, InstanceType type) {
  ASM_CODE_COMMENT(this);
  LoadMap(map, object);
  CompareInstanceType(map, type_reg, type);
}

void MacroAssembler::CompareRange(Register value, Register scratch,
                                  unsigned lower_limit, unsigned higher_limit) {
  ASM_CODE_COMMENT(this);
  DCHECK_LT(lower_limit, higher_limit);
  if (lower_limit != 0) {
    Sub(scratch.W(), value.W(), Operand(lower_limit));
    Cmp(scratch.W(), Operand(higher_limit - lower_limit));
  } else {
    Cmp(value.W(), Immediate(higher_limit));
  }
}

void MacroAssembler::JumpIfIsInRange(Register value, Register scratch,
                                     unsigned lower_limit,
                                     unsigned higher_limit,
                                     Label* on_in_range) {
  CompareRange(value, scratch, lower_limit, higher_limit);
  B(ls, on_in_range);
}

void MacroAssembler::LoadCompressedMap(Register dst, Register object) {
  ASM_CODE_COMMENT(this);
  Ldr(dst.W(), FieldMemOperand(object, HeapObject::kMapOffset));
}

void MacroAssembler::LoadMap(Register dst, Register object) {
  ASM_CODE_COMMENT(this);
  LoadTaggedField(dst, FieldMemOperand(object, HeapObject::kMapOffset));
}

void MacroAssembler::LoadFeedbackVector(Register dst, Register closure,
                                        Register scratch, Label* fbv_undef) {
  Label done;

  // Load the feedback vector from the closure.
  LoadTaggedField(dst,
                  FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  LoadTaggedField(dst, FieldMemOperand(dst, FeedbackCell::kValueOffset));

  // Check if feedback vector is valid.
  LoadTaggedField(scratch, FieldMemOperand(dst, HeapObject::kMapOffset));
  Ldrh(scratch, FieldMemOperand(scratch, Map::kInstanceTypeOffset));
  Cmp(scratch, FEEDBACK_VECTOR_TYPE);
  B(eq, &done);

  // Not valid, load undefined.
  LoadRoot(dst, RootIndex::kUndefinedValue);
  B(fbv_undef);

  Bind(&done);
}

// Sets condition flags based on comparison, and returns type in type_reg.
void MacroAssembler::CompareInstanceType(Register map, Register type_reg,
                                         InstanceType type) {
  ASM_CODE_COMMENT(this);
  Ldrh(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
  Cmp(type_reg, type);
}

// Sets condition flags based on comparison, and returns type in type_reg.
void MacroAssembler::CompareInstanceTypeRange(Register map, Register type_reg,
                                              InstanceType lower_limit,
                                              InstanceType higher_limit) {
  ASM_CODE_COMMENT(this);
  DCHECK_LT(lower_limit, higher_limit);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Ldrh(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
  CompareRange(type_reg, scratch, lower_limit, higher_limit);
}

void MacroAssembler::LoadElementsKindFromMap(Register result, Register map) {
  ASM_CODE_COMMENT(this);
  // Load the map's "bit field 2".
  Ldrb(result, FieldMemOperand(map, Map::kBitField2Offset));
  // Retrieve elements_kind from bit field 2.
  DecodeField<Map::Bits2::ElementsKindBits>(result);
}

void MacroAssembler::CompareTaggedRoot(const Register& obj, RootIndex index) {
  ASM_CODE_COMMENT(this);
  AssertSmiOrHeapObjectInMainCompressionCage(obj);
  UseScratchRegisterScope temps(this);
  if (V8_STATIC_ROOTS_BOOL && RootsTable::IsReadOnly(index)) {
    CmpTagged(obj, Immediate(ReadOnlyRootPtr(index)));
    return;
  }
  // Some smi roots contain system pointer size values like stack limits.
  DCHECK(base::IsInRange(index, RootIndex::kFirstStrongOrReadOnlyRoot,
                         RootIndex::kLastStrongOrReadOnlyRoot));
  Register temp = temps.AcquireX();
  DCHECK(!AreAliased(obj, temp));
  LoadRoot(temp, index);
  CmpTagged(obj, temp);
}

void MacroAssembler::CompareRoot(const Register& obj, RootIndex index,
                                 ComparisonMode mode) {
  ASM_CODE_COMMENT(this);
  if (mode == ComparisonMode::kFullPointer ||
      !base::IsInRange(index, RootIndex::kFirstStrongOrReadOnlyRoot,
                       RootIndex::kLastStrongOrReadOnlyRoot)) {
    // Some smi roots contain system pointer size values like stack limits.
    UseScratchRegisterScope temps(this);
    Register temp = temps.AcquireX();
    DCHECK(!AreAliased(obj, temp));
    LoadRoot(temp, index);
    Cmp(obj, temp);
    return;
  }
  CompareTaggedRoot(obj, index);
}

void MacroAssembler::JumpIfRoot(const Register& obj, RootIndex index,
                                Label* if_equal) {
  CompareRoot(obj, index);
  B(eq, if_equal);
}

void MacroAssembler::JumpIfNotRoot(const Register& obj, RootIndex index,
                                   Label* if_not_equal) {
  CompareRoot(obj, index);
  B(ne, if_not_equal);
}

void MacroAssembler::JumpIfIsInRange(const Register& value,
                                     unsigned lower_limit,
                                     unsigned higher_limit,
                                     Label* on_in_range) {
  ASM_CODE_COMMENT(this);
  if (lower_limit != 0) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.AcquireW();
    Sub(scratch, value, Operand(lower_limit));
    CompareAndBranch(scratch, Operand(higher_limit - lower_limit), ls,
                     on_in_range);
  } else {
    CompareAndBranch(value, Operand(higher_limit - lower_limit), ls,
                     on_in_range);
  }
}

void MacroAssembler::LoadTaggedField(const Register& destination,
                                     const MemOperand& field_operand) {
  if (COMPRESS_POINTERS_BOOL) {
    DecompressTagged(destination, field_operand);
  } else {
    Ldr(destination, field_operand);
  }
}

void MacroAssembler::LoadTaggedFieldWithoutDecompressing(
    const Register& destination, const MemOperand& field_operand) {
  if (COMPRESS_POINTERS_BOOL) {
    Ldr(destination.W(), field_operand);
  } else {
    Ldr(destination, field_operand);
  }
}

void MacroAssembler::LoadTaggedSignedField(const Register& destination,
                                           const MemOperand& field_operand) {
  if (COMPRESS_POINTERS_BOOL) {
    DecompressTaggedSigned(destination, field_operand);
  } else {
    Ldr(destination, field_operand);
  }
}

void MacroAssembler::SmiUntagField(Register dst, const MemOperand& src) {
  SmiUntag(dst, src);
}

void MacroAssembler::StoreTwoTaggedFields(const Register& value,
                                          const MemOperand& dst_field_operand) {
  if (COMPRESS_POINTERS_BOOL) {
    Stp(value.W(), value.W(), dst_field_operand);
  } else {
    Stp(value, value, dst_field_operand);
  }
}

void MacroAssembler::StoreTaggedField(const Register& value,
                                      const MemOperand& dst_field_operand) {
  if (COMPRESS_POINTERS_BOOL) {
    Str(value.W(), dst_field_operand);
  } else {
    Str(value, dst_field_operand);
  }
}

void MacroAssembler::AtomicStoreTaggedField(const Register& value,
                                            const Register& dst_base,
                                            const Register& dst_index,
                                            const Register& temp) {
  Add(temp, dst_base, dst_index);
  if (COMPRESS_POINTERS_BOOL) {
    Stlr(value.W(), temp);
  } else {
    Stlr(value, temp);
  }
}

void MacroAssembler::DecompressTaggedSigned(const Register& destination,
                                            const MemOperand& field_operand) {
  ASM_CODE_COMMENT(this);
  Ldr(destination.W(), field_operand);
  if (v8_flags.debug_code) {
    // Corrupt the top 32 bits. Made up of 16 fixed bits and 16 pc offset bits.
    Add(destination, destination,
        ((kDebugZapValue << 16) | (pc_offset() & 0xffff)) << 32);
  }
}

void MacroAssembler::DecompressTagged(const Register& destination,
                                      const MemOperand& field_operand) {
  ASM_CODE_COMMENT(this);
  Ldr(destination.W(), field_operand);
  Add(destination, kPtrComprCageBaseRegister, destination);
}

void MacroAssembler::DecompressTagged(const Register& destination,
                                      const Register& source) {
  ASM_CODE_COMMENT(this);
  Add(destination, kPtrComprCageBaseRegister, Operand(source, UXTW));
}

void MacroAssembler::DecompressTagged(const Register& destination,
                                      Tagged_t immediate) {
  ASM_CODE_COMMENT(this);
  if (IsImmAddSub(immediate)) {
    Add(destination, kPtrComprCageBaseRegister,
        Immediate(immediate, RelocInfo::Mode::NO_INFO));
  } else {
    // Immediate is larger than 12 bit and therefore can't be encoded directly.
    // Use destination as a temporary to not acquire a scratch register.
    DCHECK_NE(destination, sp);
    Operand imm_operand =
        MoveImmediateForShiftedOp(destination, immediate, kAnyShift);
    Add(destination, kPtrComprCageBaseRegister, imm_operand);
  }
}

void MacroAssembler::DecompressProtected(const Register& destination,
                                         const MemOperand& field_operand) {
#if V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Ldr(destination.W(), field_operand);
  Ldr(scratch,
      MemOperand(kRootRegister, IsolateData::trusted_cage_base_offset()));
  Orr(destination, destination, scratch);
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::AtomicDecompressTaggedSigned(const Register& destination,
                                                  const Register& base,
                                                  const Register& index,
                                                  const Register& temp) {
  ASM_CODE_COMMENT(this);
  Add(temp, base, index);
  Ldar(destination.W(), temp);
  if (v8_flags.debug_code) {
    // Corrupt the top 32 bits. Made up of 16 fixed bits and 16 pc offset bits.
    Add(destination, destination,
        ((kDebugZapValue << 16) | (pc_offset() & 0xffff)) << 32);
  }
}

void MacroAssembler::AtomicDecompressTagged(const Register& destination,
                                            const Register& base,
                                            const Register& index,
                                            const Register& temp) {
  ASM_CODE_COMMENT(this);
  Add(temp, base, index);
  Ldar(destination.W(), temp);
  Add
```