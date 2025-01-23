Response:
My thinking process to analyze the provided C++ code snippet and answer the user's request goes like this:

1. **Understand the Core Request:** The user wants to understand the functionality of a V8 source code file (`v8/src/compiler/wasm-compiler.cc`) based on a small snippet from it. They also provide specific constraints and questions (Torque, JavaScript relation, logic, errors, summary).

2. **Analyze the Code Snippet:** I carefully examine the provided C++ code. I notice several key elements:
    * **`WasmWrapperGraphBuilder`:** This suggests the code is involved in generating graph representations for WebAssembly wrapper functions.
    * **`WasmGraphAssembler`:** This confirms graph building and likely involves emitting machine code or intermediate representations.
    * **`Node*`:** The code manipulates nodes, a common concept in compiler intermediate representations (like V8's TurboFan).
    * **Function Calls:** There are calls to built-in functions (`Builtin::kWasmTaggedNonSmiToInt32`, `Builtin::kWasmFloat32ToNumber`, etc.) and runtime functions (`Runtime::kWasmThrowJSTypeError`).
    * **Type Conversions:**  Functions like `BuildChangeInt32ToNumber`, `BuildChangeFloat32ToNumber`, `BuildChangeTaggedToInt32`, and `FromJS`/`ToJS` clearly indicate type conversion logic between WebAssembly types and JavaScript types.
    * **Control Flow:**  `gasm_->GotoIf`, `gasm_->GotoIfNot`, `gasm_->Bind`, and `Diamond` suggest control flow management within the generated graph.
    * **Smi Handling:** There's specific logic for handling Smis (Small Integers), a common optimization in JavaScript engines.
    * **ThreadInWasm Flag:** The `ModifyThreadInWasmFlagScope` class points to interaction with a flag indicating whether the current thread is executing WebAssembly code.
    * **Fast Path/Slow Path:** The `QualifiesForFastTransform` and related code suggests optimization strategies.
    * **Promise Handling:** The `BuildSuspend` function explicitly deals with JavaScript Promises.

3. **Address Each Constraint and Question Systematically:**

    * **Functionality:** Based on the code analysis, I deduce the core functionality is generating code (likely TurboFan IR) for wrapping WebAssembly functions so they can be called from JavaScript and vice-versa. This involves handling type conversions between WebAssembly and JavaScript.

    * **Torque:**  The prompt explicitly states to check for `.tq` extension. Since the file is `.cc`, it's a standard C++ file, *not* a Torque file.

    * **JavaScript Relation:** The code heavily interacts with JavaScript concepts like Smis, Heap Numbers, Promises, and calls to built-in and runtime JavaScript functions. The `ToJS` and `FromJS` functions are direct evidence of this relationship. I then craft JavaScript examples to illustrate the type conversions being handled (e.g., a Wasm i32 becoming a JavaScript Number).

    * **Logic Inference:** I select a representative function (`BuildChangeTaggedToInt32`) and provide a simple scenario with a Smi input and a non-Smi input to demonstrate the conditional logic (fast path for Smis, call to a built-in for others). I provide the expected output for both scenarios.

    * **Common Programming Errors:** I think about typical issues when dealing with interop between different type systems. A common error is incorrect type conversion or assuming types are compatible when they aren't. I provide a JavaScript example of passing a non-numeric value to a Wasm function expecting an integer, which the generated wrapper code would likely handle (and potentially throw an error if `do_conversion` is true).

    * **归纳功能 (Summarize Functionality):** I synthesize the findings into a concise summary highlighting the key role of `wasm-compiler.cc` in the Wasm-to-JS interop within V8.

4. **Structure the Answer:** I organize the answer clearly, addressing each point from the user's request with appropriate headings and explanations. I use code formatting for the C++ snippet and JavaScript examples.

5. **Refine and Review:** I reread my answer to ensure it's accurate, comprehensive, and easy to understand. I check for any inconsistencies or ambiguities. I make sure the JavaScript examples clearly illustrate the points being made. I also double-check that I've addressed all parts of the prompt. For instance, I noticed the prompt mentions it's part 10 of 12, and while not directly impacting the *technical* analysis, it hints at a larger context within the V8 codebase, which I acknowledge in the summary.
Let's break down the functionality of the provided C++ code snippet from `v8/src/compiler/wasm-compiler.cc`.

**Core Functionality:**

This code snippet focuses on building TurboFan graph nodes for converting between WebAssembly (Wasm) types and JavaScript (JS) types within the V8 JavaScript engine's compiler. It's specifically involved in generating code for *wrapper functions* that allow JavaScript to call WebAssembly functions and vice-versa.

Here's a breakdown of the key functions and their purposes:

* **`BuildChangeInt32ToNumber(Node* value)`:** Converts a Wasm i32 value (represented as a `Node*`) to a JavaScript Number. It optimizes for Small Integers (Smis) for performance and uses a built-in function (`kWasmTaggedNonSmiToInt32`) for other cases.
* **`BuildChangeFloat32ToNumber(Node* value)` and `BuildChangeFloat64ToNumber(Node* value)`:** Convert Wasm f32 and f64 values to JavaScript Numbers, respectively, using dedicated built-in functions.
* **`BuildChangeTaggedToFloat64(Node* value, Node* context, Node* frame_state)`:** Converts a JavaScript value (represented as a "tagged" pointer) to a Wasm f64. It uses a built-in function (`kWasmTaggedToFloat64`). The `frame_state` parameter is relevant for debugging and exception handling.
* **`AddArgumentNodes(...)`:**  Prepares arguments for a JavaScript call by converting Wasm parameters to their JavaScript equivalents based on the `CanonicalSig`.
* **`ToJS(Node* node, wasm::CanonicalValueType type, Node* context)`:** This is a central function for converting a Wasm value (`node`) of a specific `type` to its JavaScript representation. It handles different Wasm types (i32, i64, f32, f64, references) and uses appropriate conversion mechanisms, including built-in calls for more complex types like function references.
* **`BuildChangeBigIntToInt64(...)`:** Converts a JavaScript BigInt to a Wasm i64.
* **`BuildCheckString(...)`:**  Ensures a JavaScript value is a string (or null if the Wasm type allows) before treating it as such. This is crucial for type safety.
* **`FromJS(Node* input, Node* js_context, wasm::CanonicalValueType type, Node* frame_state)`:** This is the counterpart to `ToJS`. It converts a JavaScript value (`input`) to a Wasm value of a specific `type`. It handles various JavaScript types and uses runtime calls (`kWasmJSToWasmObject`) for complex conversions.
* **`SmiToFloat32(Node* input)` and `SmiToFloat64(Node* input)`:** Optimized conversions from Smi to float types.
* **`HeapNumberToFloat64(Node* input)`:** Extracts the floating-point value from a JavaScript HeapNumber object.
* **`FromJSFast(...)`:** Provides a faster path for converting JavaScript values to Wasm types when certain conditions are met (e.g., dealing with Smis or HeapNumbers directly).
* **`ModifyThreadInWasmFlagScope`:**  A helper class to manage a flag that indicates whether the current thread is executing WebAssembly code. This is important for the V8 runtime's state management, especially for features like garbage collection and debugging.
* **`BuildMultiReturnFixedArrayFromIterable(...)` and `BuildCallAllocateJSArray(...)`:** Handle cases where a Wasm function returns multiple values, requiring the creation of a JavaScript array to hold them.
* **`BuildCallAndReturn(...)`:**  Generates the actual call to the underlying WebAssembly function (or an imported function) and handles the conversion of the return value back to JavaScript.
* **`QualifiesForFastTransform(...)` and `CanTransformFast(...)`:** Implement a fast path optimization for JavaScript-to-Wasm calls, checking if the JavaScript arguments can be quickly converted to their Wasm equivalents.
* **`BuildJSToWasmWrapper(...)`:** The core function for building the wrapper that allows calling a Wasm function from JavaScript. It handles argument conversion, the actual function call, and return value conversion. It also includes logic for the fast path optimization.
* **`BuildReceiverNode(...)`:** Determines the `this` value (receiver) for a JavaScript call to a Wasm function.
* **`BuildSuspend(...)`:**  Handles asynchronous WebAssembly calls that return Promises, allowing the JavaScript engine to suspend execution and resume when the Promise resolves.

**Is `v8/src/compiler/wasm-compiler.cc` a Torque Source File?**

No, the code snippet you provided is standard C++ code. Torque source files in V8 have the `.tq` extension.

**Relationship with JavaScript and Examples:**

This code is fundamentally about bridging the gap between WebAssembly and JavaScript. It ensures that data can be passed seamlessly between the two environments, handling type differences.

**JavaScript Examples:**

Let's illustrate some of the conversions with JavaScript:

1. **Wasm i32 to JavaScript Number (`BuildChangeInt32ToNumber`)**

   ```javascript
   // Assume we have a WebAssembly function that returns an i32
   const wasmInstance = await WebAssembly.instantiateStreaming(...);
   const wasmResult = wasmInstance.exports.getInt(); // Let's say this returns a Wasm i32

   // The V8 engine, using code like BuildChangeInt32ToNumber, will convert
   // wasmResult to a JavaScript Number automatically when it's accessed in JS.
   console.log(typeof wasmResult); // Output: "number"
   console.log(wasmResult + 5);    // You can perform standard JS number operations
   ```

2. **JavaScript Number to Wasm i32 (`FromJS` for `wasm::kI32`)**

   ```javascript
   // Assume we have a WebAssembly function that takes an i32 as input
   const wasmInstance = await WebAssembly.instantiateStreaming(...);
   const jsNumber = 42;

   // When calling the WebAssembly function, V8 will use code like FromJS
   // to convert the JavaScript number to a Wasm i32.
   wasmInstance.exports.acceptInt(jsNumber);
   ```

3. **Wasm f64 to JavaScript Number (`BuildChangeFloat64ToNumber`)**

   ```javascript
   const wasmInstance = await WebAssembly.instantiateStreaming(...);
   const wasmFloat = wasmInstance.exports.getFloat(); // Returns a Wasm f64

   console.log(typeof wasmFloat); // Output: "number"
   console.log(wasmFloat * 2.5);
   ```

4. **JavaScript String to Wasm String Ref (`FromJS` for `wasm::HeapType::kString`)**

   ```javascript
   const wasmInstance = await WebAssembly.instantiateStreaming(...);
   const jsString = "hello";
   wasmInstance.exports.acceptString(jsString); // V8 will use BuildCheckString and potentially kWasmJSToWasmObject
   ```

**Code Logic Inference (Example with `BuildChangeTaggedToInt32`)**

**Hypothetical Input:**

Let's assume `BuildChangeTaggedToInt32` is called with:

* `value`: A `Node*` representing a JavaScript value.
* `context`: A `Node*` representing the JavaScript context.
* `frame_state`:  (Potentially null) A `Node*` representing the current stack frame state.

**Scenario 1: `value` represents a JavaScript Smi (e.g., the number 5)**

* **Logic:** The code will first check `gasm_->GotoIfNot(IsSmi(value), &builtin);`. Since `value` is a Smi, the condition is false.
* **Output:**
    * The code jumps to the code block after the `GotoIfNot`.
    * `Node* smi = gasm_->BuildChangeSmiToInt32(value);` converts the Smi to its integer representation.
    * `gasm_->Goto(&done, smi);` jumps to the `done` label, passing the integer `smi` as the Phi node's input.
    * The function returns the `smi` node.

**Scenario 2: `value` represents a JavaScript non-Smi (e.g., a HeapNumber like 3.14)**

* **Logic:** The code checks `gasm_->GotoIfNot(IsSmi(value), &builtin);`. Since `value` is not a Smi, the condition is true.
* **Output:**
    * The code jumps to the `builtin` label.
    * It sets up a call to the built-in function `Builtin::kWasmTaggedNonSmiToInt32` to handle the conversion.
    * The `gasm_->Call(...)` instruction is executed, performing the actual conversion.
    * `gasm_->Goto(&done, call);` jumps to the `done` label, passing the result of the built-in call (`call`) as the Phi node's input.
    * The function returns the `call` node (representing the converted integer).

**Common Programming Errors:**

This code helps prevent common errors when working with WebAssembly and JavaScript interop. Some errors it addresses include:

1. **Incorrect Type Assumptions:** JavaScript is dynamically typed, while WebAssembly has static types. Without these conversion mechanisms, passing a JavaScript string to a Wasm function expecting an integer would lead to errors or undefined behavior. The `FromJS` and `ToJS` functions enforce type correctness.

   **Example Error (Without proper conversion):**

   ```javascript
   // Wasm function expects an i32
   // Without conversion, this might pass garbage data to Wasm
   wasmInstance.exports.acceptInt("hello");
   ```

2. **Loss of Precision:** Converting between floating-point and integer types requires careful handling. The `BuildChangeFloat32ToNumber` and related functions ensure correct conversion semantics, potentially truncating or rounding values as needed.

3. **Handling of Special Values:**  JavaScript has `null` and `undefined`, while WebAssembly has different ways of representing the absence of a value (e.g., nullable references). The conversion code needs to handle these cases correctly.

4. **Memory Management:**  When passing complex objects (like strings or arrays), the underlying memory needs to be managed correctly. This code interacts with V8's memory management system to ensure data is copied or accessed safely.

**归纳一下它的功能 (Summarize its Functionality):**

As part 10 of 12, this section of `v8/src/compiler/wasm-compiler.cc` is crucial for **enabling seamless communication between JavaScript and WebAssembly within the V8 engine.**  It focuses on generating the necessary compiler instructions (TurboFan graph nodes) to:

* **Convert data types** between JavaScript and WebAssembly when calling functions across the boundary. This includes handling integers, floating-point numbers, and more complex types like strings and references.
* **Optimize common conversion scenarios** (e.g., using fast paths for Smis).
* **Ensure type safety** by validating and converting data appropriately.
* **Manage the execution context** when transitioning between JavaScript and WebAssembly.
* **Handle asynchronous operations** involving Promises.

In essence, this code is a vital component of the WebAssembly integration in V8, making it possible for JavaScript developers to efficiently leverage the performance of WebAssembly while retaining the flexibility of JavaScript.

### 提示词
```
这是目录为v8/src/compiler/wasm-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/wasm-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第10部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
e = gasm_->MakeLabel(MachineRepresentation::kWord32);

    gasm_->GotoIfNot(IsSmi(value), &builtin);

    // If Smi, convert to int32.
    Node* smi = gasm_->BuildChangeSmiToInt32(value);
    gasm_->Goto(&done, smi);

    // Otherwise, call builtin which changes non-Smi to Int32.
    gasm_->Bind(&builtin);
    CommonOperatorBuilder* common = mcgraph()->common();
    Node* target = GetTargetForBuiltinCall(Builtin::kWasmTaggedNonSmiToInt32);
    if (!tagged_non_smi_to_int32_operator_.is_set()) {
      auto call_descriptor = Linkage::GetStubCallDescriptor(
          mcgraph()->zone(), WasmTaggedNonSmiToInt32Descriptor(), 0,
          frame_state ? CallDescriptor::kNeedsFrameState
                      : CallDescriptor::kNoFlags,
          Operator::kNoProperties, StubCallMode::kCallBuiltinPointer);
      tagged_non_smi_to_int32_operator_.set(common->Call(call_descriptor));
    }
    Node* call = frame_state
                     ? gasm_->Call(tagged_non_smi_to_int32_operator_.get(),
                                   target, value, context, frame_state)
                     : gasm_->Call(tagged_non_smi_to_int32_operator_.get(),
                                   target, value, context);
    // The source position here is needed for asm.js, see the comment on the
    // source position of the call to JavaScript in the wasm-to-js wrapper.
    SetSourcePosition(call, 1);
    gasm_->Goto(&done, call);
    gasm_->Bind(&done);
    return done.PhiAt(0);
  }

  Node* BuildChangeFloat32ToNumber(Node* value) {
    CommonOperatorBuilder* common = mcgraph()->common();
    Node* target = GetTargetForBuiltinCall(Builtin::kWasmFloat32ToNumber);
    if (!float32_to_number_operator_.is_set()) {
      auto call_descriptor = Linkage::GetStubCallDescriptor(
          mcgraph()->zone(), WasmFloat32ToNumberDescriptor(), 0,
          CallDescriptor::kNoFlags, Operator::kNoProperties,
          StubCallMode::kCallBuiltinPointer);
      float32_to_number_operator_.set(common->Call(call_descriptor));
    }
    return gasm_->Call(float32_to_number_operator_.get(), target, value);
  }

  Node* BuildChangeFloat64ToNumber(Node* value) {
    CommonOperatorBuilder* common = mcgraph()->common();
    Node* target = GetTargetForBuiltinCall(Builtin::kWasmFloat64ToNumber);
    if (!float64_to_number_operator_.is_set()) {
      auto call_descriptor = Linkage::GetStubCallDescriptor(
          mcgraph()->zone(), WasmFloat64ToTaggedDescriptor(), 0,
          CallDescriptor::kNoFlags, Operator::kNoProperties,
          StubCallMode::kCallBuiltinPointer);
      float64_to_number_operator_.set(common->Call(call_descriptor));
    }
    return gasm_->Call(float64_to_number_operator_.get(), target, value);
  }

  Node* BuildChangeTaggedToFloat64(Node* value, Node* context,
                                   Node* frame_state) {
    CommonOperatorBuilder* common = mcgraph()->common();
    Node* target = GetTargetForBuiltinCall(Builtin::kWasmTaggedToFloat64);
    bool needs_frame_state = frame_state != nullptr;
    if (!tagged_to_float64_operator_.is_set()) {
      auto call_descriptor = Linkage::GetStubCallDescriptor(
          mcgraph()->zone(), WasmTaggedToFloat64Descriptor(), 0,
          frame_state ? CallDescriptor::kNeedsFrameState
                      : CallDescriptor::kNoFlags,
          Operator::kNoProperties, StubCallMode::kCallBuiltinPointer);
      tagged_to_float64_operator_.set(common->Call(call_descriptor));
    }
    Node* call = needs_frame_state
                     ? gasm_->Call(tagged_to_float64_operator_.get(), target,
                                   value, context, frame_state)
                     : gasm_->Call(tagged_to_float64_operator_.get(), target,
                                   value, context);
    // The source position here is needed for asm.js, see the comment on the
    // source position of the call to JavaScript in the wasm-to-js wrapper.
    SetSourcePosition(call, 1);
    return call;
  }

  int AddArgumentNodes(base::Vector<Node*> args, int pos, int param_count,
                       const wasm::CanonicalSig* sig, Node* context) {
    // Convert wasm numbers to JS values and drop the instance node.
    for (int i = 0; i < param_count; ++i) {
      Node* param = Param(i + 1);
      args[pos++] = ToJS(param, sig->GetParam(i), context);
    }
    return pos;
  }

  Node* ToJS(Node* node, wasm::CanonicalValueType type, Node* context) {
    switch (type.kind()) {
      case wasm::kI32:
        return BuildChangeInt32ToNumber(node);
      case wasm::kI64:
        return BuildChangeInt64ToBigInt(node,
                                        StubCallMode::kCallBuiltinPointer);
      case wasm::kF32:
        return BuildChangeFloat32ToNumber(node);
      case wasm::kF64:
        return BuildChangeFloat64ToNumber(node);
      case wasm::kRef:
        switch (type.heap_representation_non_shared()) {
          case wasm::HeapType::kEq:
          case wasm::HeapType::kI31:
          case wasm::HeapType::kStruct:
          case wasm::HeapType::kArray:
          case wasm::HeapType::kAny:
          case wasm::HeapType::kExtern:
          case wasm::HeapType::kString:
          case wasm::HeapType::kNone:
          case wasm::HeapType::kNoFunc:
          case wasm::HeapType::kNoExtern:
          case wasm::HeapType::kExn:
          case wasm::HeapType::kNoExn:
            return node;
          case wasm::HeapType::kBottom:
          case wasm::HeapType::kTop:
          case wasm::HeapType::kStringViewWtf8:
          case wasm::HeapType::kStringViewWtf16:
          case wasm::HeapType::kStringViewIter:
            UNREACHABLE();
          case wasm::HeapType::kFunc:
          default:
            if (type.heap_representation_non_shared() ==
                    wasm::HeapType::kFunc ||
                wasm::GetTypeCanonicalizer()->IsFunctionSignature(
                    type.ref_index())) {
              // Function reference. Extract the external function.
              auto done =
                  gasm_->MakeLabel(MachineRepresentation::kTaggedPointer);
              Node* internal = gasm_->LoadTrustedPointerFromObject(
                  node,
                  wasm::ObjectAccess::ToTagged(
                      WasmFuncRef::kTrustedInternalOffset),
                  kWasmInternalFunctionIndirectPointerTag);
              Node* maybe_external = gasm_->LoadFromObject(
                  MachineType::TaggedPointer(), internal,
                  wasm::ObjectAccess::ToTagged(
                      WasmInternalFunction::kExternalOffset));
              gasm_->GotoIfNot(
                  gasm_->TaggedEqual(maybe_external, UndefinedValue()), &done,
                  maybe_external);
              Node* from_builtin = gasm_->CallBuiltin(
                  Builtin::kWasmInternalFunctionCreateExternal,
                  Operator::kNoProperties, internal, context);
              gasm_->Goto(&done, from_builtin);
              gasm_->Bind(&done);
              return done.PhiAt(0);
            } else {
              return node;
            }
        }
      case wasm::kRefNull:
        switch (type.heap_representation_non_shared()) {
          case wasm::HeapType::kExtern:
          case wasm::HeapType::kNoExtern:
          case wasm::HeapType::kExn:
          case wasm::HeapType::kNoExn:
            return node;
          case wasm::HeapType::kNone:
          case wasm::HeapType::kNoFunc:
            return LOAD_ROOT(NullValue, null_value);
          case wasm::HeapType::kEq:
          case wasm::HeapType::kStruct:
          case wasm::HeapType::kArray:
          case wasm::HeapType::kString:
          case wasm::HeapType::kI31:
          case wasm::HeapType::kAny: {
            auto done = gasm_->MakeLabel(MachineRepresentation::kTaggedPointer);
            gasm_->GotoIfNot(IsNull(node, type), &done, node);
            gasm_->Goto(&done, LOAD_ROOT(NullValue, null_value));
            gasm_->Bind(&done);
            return done.PhiAt(0);
          }
          case wasm::HeapType::kFunc:
          default: {
            if (type.heap_representation_non_shared() ==
                    wasm::HeapType::kFunc ||
                wasm::GetTypeCanonicalizer()->IsFunctionSignature(
                    type.ref_index())) {
              // Function reference. Extract the external function.
              auto done =
                  gasm_->MakeLabel(MachineRepresentation::kTaggedPointer);
              auto null_label = gasm_->MakeLabel();
              gasm_->GotoIf(IsNull(node, type), &null_label);
              Node* internal = gasm_->LoadTrustedPointerFromObject(
                  node,
                  wasm::ObjectAccess::ToTagged(
                      WasmFuncRef::kTrustedInternalOffset),
                  kWasmInternalFunctionIndirectPointerTag);
              Node* maybe_external = gasm_->LoadFromObject(
                  MachineType::TaggedPointer(), internal,
                  wasm::ObjectAccess::ToTagged(
                      WasmInternalFunction::kExternalOffset));
              gasm_->GotoIfNot(
                  gasm_->TaggedEqual(maybe_external, UndefinedValue()), &done,
                  maybe_external);
              Node* from_builtin = gasm_->CallBuiltin(
                  Builtin::kWasmInternalFunctionCreateExternal,
                  Operator::kNoProperties, internal, context);
              gasm_->Goto(&done, from_builtin);
              gasm_->Bind(&null_label);
              gasm_->Goto(&done, LOAD_ROOT(NullValue, null_value));
              gasm_->Bind(&done);
              return done.PhiAt(0);
            } else {
              auto done =
                  gasm_->MakeLabel(MachineRepresentation::kTaggedPointer);
              gasm_->GotoIfNot(IsNull(node, type), &done, node);
              gasm_->Goto(&done, LOAD_ROOT(NullValue, null_value));
              gasm_->Bind(&done);
              return done.PhiAt(0);
            }
          }
        }
      case wasm::kRtt:
      case wasm::kI8:
      case wasm::kI16:
      case wasm::kF16:
      case wasm::kS128:
      case wasm::kVoid:
      case wasm::kTop:
      case wasm::kBottom:
        // If this is reached, then IsJSCompatibleSignature() is too permissive.
        UNREACHABLE();
    }
  }

  Node* BuildChangeBigIntToInt64(Node* input, Node* context,
                                 Node* frame_state) {
    Node* target;
    if (mcgraph()->machine()->Is64()) {
      target = GetTargetForBuiltinCall(Builtin::kBigIntToI64);
    } else {
      DCHECK(mcgraph()->machine()->Is32());
      // On 32-bit platforms we already set the target to the
      // BigIntToI32Pair builtin here, so that we don't have to replace the
      // target in the int64-lowering.
      target = GetTargetForBuiltinCall(Builtin::kBigIntToI32Pair);
    }

    return frame_state ? gasm_->Call(GetBigIntToI64CallDescriptor(true), target,
                                     input, context, frame_state)
                       : gasm_->Call(GetBigIntToI64CallDescriptor(false),
                                     target, input, context);
  }

  Node* BuildCheckString(Node* input, Node* js_context,
                         wasm::CanonicalValueType type) {
    auto done = gasm_->MakeLabel(MachineRepresentation::kTagged);
    auto type_error = gasm_->MakeDeferredLabel();
    gasm_->GotoIf(IsSmi(input), &type_error, BranchHint::kFalse);
    if (type.is_nullable()) {
      auto not_null = gasm_->MakeLabel();
      gasm_->GotoIfNot(IsNull(input, wasm::kCanonicalExternRef), &not_null);
      gasm_->Goto(&done, LOAD_ROOT(WasmNull, wasm_null));
      gasm_->Bind(&not_null);
    }
    Node* map = gasm_->LoadMap(input);
    Node* instance_type = gasm_->LoadInstanceType(map);
    Node* check = gasm_->Uint32LessThan(
        instance_type, gasm_->Uint32Constant(FIRST_NONSTRING_TYPE));
    gasm_->GotoIf(check, &done, BranchHint::kTrue, input);
    gasm_->Goto(&type_error);
    gasm_->Bind(&type_error);
    BuildCallToRuntimeWithContext(Runtime::kWasmThrowJSTypeError, js_context,
                                  nullptr, 0);
    TerminateThrow(effect(), control());
    gasm_->Bind(&done);
    return done.PhiAt(0);
  }

  Node* FromJS(Node* input, Node* js_context, wasm::CanonicalValueType type,
               Node* frame_state = nullptr) {
    switch (type.kind()) {
      case wasm::kRef:
      case wasm::kRefNull: {
        switch (type.heap_representation_non_shared()) {
          // TODO(14034): Add more fast paths?
          case wasm::HeapType::kExtern:
          case wasm::HeapType::kExn:
            if (type.kind() == wasm::kRef) {
              Node* null_value = gasm_->LoadImmutable(
                  MachineType::Pointer(), gasm_->LoadRootRegister(),
                  IsolateData::root_slot_offset(RootIndex::kNullValue));
              auto throw_label = gasm_->MakeDeferredLabel();
              auto done = gasm_->MakeLabel();
              gasm_->GotoIf(gasm_->TaggedEqual(input, null_value),
                            &throw_label);
              gasm_->Goto(&done);

              gasm_->Bind(&throw_label);
              BuildCallToRuntimeWithContext(Runtime::kWasmThrowJSTypeError,
                                            js_context, {}, 0);
              gasm_->Unreachable();

              gasm_->Bind(&done);
            }
            return input;
          case wasm::HeapType::kString:
            return BuildCheckString(input, js_context, type);
          case wasm::HeapType::kNoExtern:
          case wasm::HeapType::kNoExn:
          case wasm::HeapType::kNone:
          case wasm::HeapType::kNoFunc:
          case wasm::HeapType::kI31:
          case wasm::HeapType::kAny:
          case wasm::HeapType::kFunc:
          case wasm::HeapType::kStruct:
          case wasm::HeapType::kArray:
          case wasm::HeapType::kEq:
          default: {
            // Make sure CanonicalValueType fits in a Smi.
            static_assert(wasm::CanonicalValueType::kLastUsedBit + 1 <=
                          kSmiValueSize);

            Node* inputs[] = {
                input, mcgraph()->IntPtrConstant(
                           IntToSmi(static_cast<int>(type.raw_bit_field())))};

            return BuildCallToRuntimeWithContext(Runtime::kWasmJSToWasmObject,
                                                 js_context, inputs, 2);
          }
        }
      }
      case wasm::kF32:
        return gasm_->TruncateFloat64ToFloat32(
            BuildChangeTaggedToFloat64(input, js_context, frame_state));

      case wasm::kF64:
        return BuildChangeTaggedToFloat64(input, js_context, frame_state);

      case wasm::kI32:
        return BuildChangeTaggedToInt32(input, js_context, frame_state);

      case wasm::kI64:
        // i64 values can only come from BigInt.
        return BuildChangeBigIntToInt64(input, js_context, frame_state);

      case wasm::kRtt:
      case wasm::kS128:
      case wasm::kI8:
      case wasm::kI16:
      case wasm::kF16:
      case wasm::kTop:
      case wasm::kBottom:
      case wasm::kVoid:
        // If this is reached, then IsJSCompatibleSignature() is too permissive.
        UNREACHABLE();
    }
  }

  Node* SmiToFloat32(Node* input) {
    return gasm_->RoundInt32ToFloat32(gasm_->BuildChangeSmiToInt32(input));
  }

  Node* SmiToFloat64(Node* input) {
    return gasm_->ChangeInt32ToFloat64(gasm_->BuildChangeSmiToInt32(input));
  }

  Node* HeapNumberToFloat64(Node* input) {
    return gasm_->LoadFromObject(
        MachineType::Float64(), input,
        wasm::ObjectAccess::ToTagged(
            AccessBuilder::ForHeapNumberValue().offset));
  }

  Node* FromJSFast(Node* input, wasm::CanonicalValueType type) {
    switch (type.kind()) {
      case wasm::kI32:
        return gasm_->BuildChangeSmiToInt32(input);
      case wasm::kF32: {
        auto done = gasm_->MakeLabel(MachineRepresentation::kFloat32);
        auto heap_number = gasm_->MakeLabel();
        gasm_->GotoIfNot(IsSmi(input), &heap_number);
        gasm_->Goto(&done, SmiToFloat32(input));
        gasm_->Bind(&heap_number);
        Node* value =
            gasm_->TruncateFloat64ToFloat32(HeapNumberToFloat64(input));
        gasm_->Goto(&done, value);
        gasm_->Bind(&done);
        return done.PhiAt(0);
      }
      case wasm::kF64: {
        auto done = gasm_->MakeLabel(MachineRepresentation::kFloat64);
        auto heap_number = gasm_->MakeLabel();
        gasm_->GotoIfNot(IsSmi(input), &heap_number);
        gasm_->Goto(&done, SmiToFloat64(input));
        gasm_->Bind(&heap_number);
        gasm_->Goto(&done, HeapNumberToFloat64(input));
        gasm_->Bind(&done);
        return done.PhiAt(0);
      }
      case wasm::kRef:
      case wasm::kRefNull:
      case wasm::kI64:
      case wasm::kRtt:
      case wasm::kS128:
      case wasm::kI8:
      case wasm::kI16:
      case wasm::kF16:
      case wasm::kTop:
      case wasm::kBottom:
      case wasm::kVoid:
        UNREACHABLE();
    }
  }

  class ModifyThreadInWasmFlagScope {
   public:
    ModifyThreadInWasmFlagScope(
        WasmWrapperGraphBuilder* wasm_wrapper_graph_builder,
        WasmGraphAssembler* gasm)
        : wasm_wrapper_graph_builder_(wasm_wrapper_graph_builder) {
      if (!trap_handler::IsTrapHandlerEnabled()) return;
      Node* isolate_root = wasm_wrapper_graph_builder_->BuildLoadIsolateRoot();

      thread_in_wasm_flag_address_ =
          gasm->Load(MachineType::Pointer(), isolate_root,
                     Isolate::thread_in_wasm_flag_address_offset());

      wasm_wrapper_graph_builder_->BuildModifyThreadInWasmFlagHelper(
          thread_in_wasm_flag_address_, true);
    }

    ModifyThreadInWasmFlagScope(const ModifyThreadInWasmFlagScope&) = delete;

    ~ModifyThreadInWasmFlagScope() {
      if (!trap_handler::IsTrapHandlerEnabled()) return;

      wasm_wrapper_graph_builder_->BuildModifyThreadInWasmFlagHelper(
          thread_in_wasm_flag_address_, false);
    }

   private:
    WasmWrapperGraphBuilder* wasm_wrapper_graph_builder_;
    Node* thread_in_wasm_flag_address_;
  };

  Node* BuildMultiReturnFixedArrayFromIterable(const wasm::CanonicalSig* sig,
                                               Node* iterable, Node* context) {
    Node* length = gasm_->BuildChangeUint31ToSmi(
        mcgraph()->Uint32Constant(static_cast<uint32_t>(sig->return_count())));
    return gasm_->CallBuiltin(Builtin::kIterableToFixedArrayForWasm,
                              Operator::kEliminatable, iterable, length,
                              context);
  }

  // Generate a call to the AllocateJSArray builtin.
  Node* BuildCallAllocateJSArray(Node* array_length, Node* context) {
    // Since we don't check that args will fit in an array,
    // we make sure this is true based on statically known limits.
    static_assert(wasm::kV8MaxWasmFunctionReturns <=
                  JSArray::kInitialMaxFastElementArray);
    return gasm_->CallBuiltin(Builtin::kWasmAllocateJSArray,
                              Operator::kEliminatable, array_length, context);
  }

  Node* BuildCallAndReturn(Node* js_context, Node* function_data,
                           base::SmallVector<Node*, 16> args,
                           bool do_conversion, Node* frame_state,
                           bool set_in_wasm_flag) {
    const int rets_count = static_cast<int>(wrapper_sig_->return_count());
    base::SmallVector<Node*, 1> rets(rets_count);

    // Set the ThreadInWasm flag before we do the actual call.
    {
      std::optional<ModifyThreadInWasmFlagScope>
          modify_thread_in_wasm_flag_builder;
      if (set_in_wasm_flag) {
        modify_thread_in_wasm_flag_builder.emplace(this, gasm_.get());
      }

      // Call to an import or a wasm function defined in this module.
      // The (cached) call target is the jump table slot for that function.
      // We do not use the imports dispatch table here so that the wrapper is
      // target independent, in particular for tier-up.
      Node* internal = gasm_->LoadImmutableProtectedPointerFromObject(
          function_data, wasm::ObjectAccess::ToTagged(
                             WasmFunctionData::kProtectedInternalOffset));
      args[0] =
          gasm_->LoadFromObject(MachineType::WasmCodePointer(), internal,
                                wasm::ObjectAccess::ToTagged(
                                    WasmInternalFunction::kCallTargetOffset));
      Node* implicit_arg = gasm_->LoadImmutableProtectedPointerFromObject(
          internal, wasm::ObjectAccess::ToTagged(
                        WasmInternalFunction::kProtectedImplicitArgOffset));
      BuildWasmCall(wrapper_sig_, base::VectorOf(args), base::VectorOf(rets),
                    wasm::kNoCodePosition, implicit_arg, frame_state);
    }

    Node* jsval;
    if (wrapper_sig_->return_count() == 0) {
      jsval = UndefinedValue();
    } else if (wrapper_sig_->return_count() == 1) {
      jsval = !do_conversion
                  ? rets[0]
                  : ToJS(rets[0], wrapper_sig_->GetReturn(), js_context);
    } else {
      int32_t return_count = static_cast<int32_t>(wrapper_sig_->return_count());
      Node* size = gasm_->NumberConstant(return_count);

      jsval = BuildCallAllocateJSArray(size, js_context);

      Node* fixed_array = gasm_->LoadJSArrayElements(jsval);

      for (int i = 0; i < return_count; ++i) {
        Node* value = ToJS(rets[i], wrapper_sig_->GetReturn(i), js_context);
        gasm_->StoreFixedArrayElementAny(fixed_array, i, value);
      }
    }
    return jsval;
  }

  bool QualifiesForFastTransform(const wasm::CanonicalSig* sig) {
    const int wasm_count = static_cast<int>(sig->parameter_count());
    for (int i = 0; i < wasm_count; ++i) {
      wasm::CanonicalValueType type = sig->GetParam(i);
      switch (type.kind()) {
        case wasm::kRef:
        case wasm::kRefNull:
        case wasm::kI64:
        case wasm::kRtt:
        case wasm::kS128:
        case wasm::kI8:
        case wasm::kI16:
        case wasm::kF16:
        case wasm::kTop:
        case wasm::kBottom:
        case wasm::kVoid:
          return false;
        case wasm::kI32:
        case wasm::kF32:
        case wasm::kF64:
          break;
      }
    }
    return true;
  }

  Node* IsSmi(Node* input) {
    return gasm_->Word32Equal(
        gasm_->Word32And(gasm_->BuildTruncateIntPtrToInt32(input),
                         Int32Constant(kSmiTagMask)),
        Int32Constant(kSmiTag));
  }

  void CanTransformFast(
      Node* input, wasm::CanonicalValueType type,
      v8::internal::compiler::GraphAssemblerLabel<0>* slow_path) {
    switch (type.kind()) {
      case wasm::kI32: {
        gasm_->GotoIfNot(IsSmi(input), slow_path);
        return;
      }
      case wasm::kF32:
      case wasm::kF64: {
        auto done = gasm_->MakeLabel();
        gasm_->GotoIf(IsSmi(input), &done);
        Node* map = gasm_->LoadMap(input);
        Node* heap_number_map = LOAD_ROOT(HeapNumberMap, heap_number_map);
#if V8_MAP_PACKING
        Node* is_heap_number = gasm_->WordEqual(heap_number_map, map);
#else
        Node* is_heap_number = gasm_->TaggedEqual(heap_number_map, map);
#endif
        gasm_->GotoIf(is_heap_number, &done);
        gasm_->Goto(slow_path);
        gasm_->Bind(&done);
        return;
      }
      case wasm::kRef:
      case wasm::kRefNull:
      case wasm::kI64:
      case wasm::kRtt:
      case wasm::kS128:
      case wasm::kI8:
      case wasm::kI16:
      case wasm::kF16:
      case wasm::kTop:
      case wasm::kBottom:
      case wasm::kVoid:
        UNREACHABLE();
    }
  }

  void BuildJSToWasmWrapper(bool do_conversion = true,
                            Node* frame_state = nullptr,
                            bool set_in_wasm_flag = true) {
    const int wasm_param_count =
        static_cast<int>(wrapper_sig_->parameter_count());

    // Build the start and the JS parameter nodes.
    // TODO(saelo): this should probably be a constant with a descriptive name.
    // As far as I understand, it's the number of additional parameters in the
    // JS calling convention. Also there should be a static_assert here that it
    // matches the number of parameters in the JSTrampolineDescriptor?
    // static_assert
    Start(wasm_param_count + 6);

    // Create the js_closure and js_context parameters.
    Node* js_closure = Param(Linkage::kJSCallClosureParamIndex, "%closure");
    Node* js_context = Param(
        Linkage::GetJSCallContextParamIndex(wasm_param_count + 1), "%context");
    Node* function_data = gasm_->LoadFunctionDataFromJSFunction(js_closure);

    if (!wasm::IsJSCompatibleSignature(wrapper_sig_)) {
      // Throw a TypeError. Use the js_context of the calling javascript
      // function (passed as a parameter), such that the generated code is
      // js_context independent.
      BuildCallToRuntimeWithContext(Runtime::kWasmThrowJSTypeError, js_context,
                                    nullptr, 0);
      TerminateThrow(effect(), control());
      return;
    }

#if V8_ENABLE_DRUMBRAKE
    if (v8_flags.wasm_enable_exec_time_histograms && v8_flags.slow_histograms &&
        !v8_flags.wasm_jitless) {
      Node* runtime_call = BuildCallToRuntimeWithContext(
          Runtime::kWasmTraceBeginExecution, js_context, nullptr, 0);
      SetControl(runtime_call);
    }
#endif  // V8_ENABLE_DRUMBRAKE

    const int args_count = wasm_param_count + 1;  // +1 for wasm_code.

    // Check whether the signature of the function allows for a fast
    // transformation (if any params exist that need transformation).
    // Create a fast transformation path, only if it does.
    bool include_fast_path = do_conversion && wasm_param_count > 0 &&
                             QualifiesForFastTransform(wrapper_sig_);

    // Prepare Param() nodes. Param() nodes can only be created once,
    // so we need to use the same nodes along all possible transformation paths.
    base::SmallVector<Node*, 16> params(args_count);
    for (int i = 0; i < wasm_param_count; ++i) params[i + 1] = Param(i + 1);

    auto done = gasm_->MakeLabel(MachineRepresentation::kTagged);
    if (include_fast_path) {
      auto slow_path = gasm_->MakeDeferredLabel();
      // Check if the params received on runtime can be actually transformed
      // using the fast transformation. When a param that cannot be transformed
      // fast is encountered, skip checking the rest and fall back to the slow
      // path.
      for (int i = 0; i < wasm_param_count; ++i) {
        CanTransformFast(params[i + 1], wrapper_sig_->GetParam(i), &slow_path);
      }
      // Convert JS parameters to wasm numbers using the fast transformation
      // and build the call.
      base::SmallVector<Node*, 16> args(args_count);
      for (int i = 0; i < wasm_param_count; ++i) {
        Node* wasm_param = FromJSFast(params[i + 1], wrapper_sig_->GetParam(i));
        args[i + 1] = wasm_param;
      }
      Node* jsval =
          BuildCallAndReturn(js_context, function_data, args, do_conversion,
                             frame_state, set_in_wasm_flag);

#if V8_ENABLE_DRUMBRAKE
      if (v8_flags.wasm_enable_exec_time_histograms &&
          v8_flags.slow_histograms && !v8_flags.wasm_jitless) {
        Node* runtime_call = BuildCallToRuntimeWithContext(
            Runtime::kWasmTraceEndExecution, js_context, nullptr, 0);
        SetControl(runtime_call);
      }
#endif  // V8_ENABLE_DRUMBRAKE

      gasm_->Goto(&done, jsval);
      gasm_->Bind(&slow_path);
    }
    // Convert JS parameters to wasm numbers using the default transformation
    // and build the call.
    base::SmallVector<Node*, 16> args(args_count);
    for (int i = 0; i < wasm_param_count; ++i) {
      if (do_conversion) {
        args[i + 1] = FromJS(params[i + 1], js_context,
                             wrapper_sig_->GetParam(i), frame_state);
      } else {
        Node* wasm_param = params[i + 1];

        // For Float32 parameters
        // we set UseInfo::CheckedNumberOrOddballAsFloat64 in
        // simplified-lowering and we need to add here a conversion from Float64
        // to Float32.
        if (wrapper_sig_->GetParam(i).kind() == wasm::kF32) {
          wasm_param = gasm_->TruncateFloat64ToFloat32(wasm_param);
        }

        args[i + 1] = wasm_param;
      }
    }

    Node* jsval =
        BuildCallAndReturn(js_context, function_data, args, do_conversion,
                           frame_state, set_in_wasm_flag);

#if V8_ENABLE_DRUMBRAKE
    if (v8_flags.wasm_enable_exec_time_histograms && v8_flags.slow_histograms &&
        !v8_flags.wasm_jitless) {
      Node* runtime_call = BuildCallToRuntimeWithContext(
          Runtime::kWasmTraceEndExecution, js_context, nullptr, 0);
      SetControl(runtime_call);
    }
#endif  // V8_ENABLE_DRUMBRAKE

    // If both the default and a fast transformation paths are present,
    // get the return value based on the path used.
    if (include_fast_path) {
      gasm_->Goto(&done, jsval);
      gasm_->Bind(&done);
      Return(done.PhiAt(0));
    } else {
      Return(jsval);
    }
    if (ContainsInt64(wrapper_sig_)) LowerInt64(wasm::kCalledFromJS);
  }

  Node* BuildReceiverNode(Node* callable_node, Node* native_context,
                          Node* undefined_node) {
    // Check function strict bit.
    Node* shared_function_info = gasm_->LoadSharedFunctionInfo(callable_node);
    Node* flags = gasm_->LoadFromObject(
        MachineType::Int32(), shared_function_info,
        wasm::ObjectAccess::FlagsOffsetInSharedFunctionInfo());
    Node* strict_check =
        Binop(wasm::kExprI32And, flags,
              Int32Constant(SharedFunctionInfo::IsNativeBit::kMask |
                            SharedFunctionInfo::IsStrictBit::kMask));

    // Load global receiver if sloppy else use undefined.
    Diamond strict_d(graph(), mcgraph()->common(), strict_check,
                     BranchHint::kNone);
    Node* old_effect = effect();
    SetControl(strict_d.if_false);
    Node* global_proxy = gasm_->LoadFixedArrayElementPtr(
        native_context, Context::GLOBAL_PROXY_INDEX);
    SetEffectControl(strict_d.EffectPhi(old_effect, global_proxy),
                     strict_d.merge);
    return strict_d.Phi(MachineRepresentation::kTagged, undefined_node,
                        global_proxy);
  }

  Node* BuildSuspend(Node* value, Node* import_data, Node** old_sp) {
    Node* native_context = gasm_->Load(
        MachineType::TaggedPointer(), import_data,
        wasm::ObjectAccess::ToTagged(WasmImportData::kNativeContextOffset));
    // If value is a promise, suspend to the js-to-wasm prompt, and resume later
    // with the promise's resolved value.
    auto resume = gasm_->MakeLabel(MachineRepresentation::kTagged,
                                   MachineType::UintPtr().representation());
    gasm_->GotoIf(IsSmi(value), &resume, value, *old_sp);
    gasm_->GotoIfNot(gasm_->HasInstanceType(value, JS_PROMISE_TYPE), &resume,
                     BranchHint::kTrue, value, *old_sp);

    // Trap if the suspender is undefined, which occurs when the export was
    // not wrapped with WebAssembly.promising.
    Node* suspender = LOAD_MUTABLE_ROOT(ActiveSuspender, active_suspender);
    auto bad_suspender = gasm_->MakeDeferredLabel();
    gasm_->GotoIf(gasm_->TaggedEqual(suspender, UndefinedValue()),
                  &bad_suspender, BranchHint::kFalse);

    if (v8_flags.stress_wasm_stack_switching) {
      Node* undefined = LOAD_ROOT(UndefinedValue, undefined_value);
      Node* for_stress_testing = gasm_->TaggedEqual(
          gasm_->Load(
              MachineType::TaggedPointer(), suspender,
              wasm::ObjectAccess::ToTagged(WasmSuspenderObject::kResumeOffset)),
          undefined);
      gasm_->GotoIf(for_stress_testing, &bad_suspender);
    }

    auto* call_descriptor = GetBuiltinCallDescriptor(
        Builtin::kWasmSuspend, zone_, StubCallMode::kCallBuiltinPointer);
    Node* call_target = GetTargetForBuiltinCall(Builtin::kWasmSuspend);
    // If {old_sp} is null, it must be that we were on the central stack before
    // entering the wasm-to-js wrapper, which means that there are JS frames in
    // the current suspender. JS frames cannot be suspended, so trap.
    Node* has_js_frames = gasm_->IntPtrEqual(gasm_->IntPtrConstant(0), *old_sp);
    auto suspend = gasm_->MakeLabel();
    gasm_->GotoIfNot(has_js_frames, &suspend);
    // {ThrowWasmError} expects to be called from wasm code, so set the
    // thread-in-wasm flag now.
    // Usually we set this flag later so that it stays off while we convert the
    // return values. This is a special case, it is safe to set it now because
    // the error will unwind this frame.
    BuildModifyThreadInWasmFlag(true);
    Node* error = gasm_->SmiConstant(
        Smi::FromInt(
            static_cast<int32_t>(Messag
```