Response: Let's break down the thought process for analyzing the provided Torque code.

1. **Initial Understanding of Torque:**  The first step is to recognize this isn't plain C++ or JavaScript. The `.tq` extension and the syntax (like `builtin`, `macro`, `typeswitch`) strongly suggest it's Torque, V8's intermediate language for defining built-in functions. Torque aims for type safety and closer mapping to the underlying C++ implementation.

2. **High-Level Goal:** The file is named `wasm.tq` and located in `v8/src/builtins/wasm`. This immediately signals that it's related to the implementation of WebAssembly features within V8. The code likely defines how certain WebAssembly operations are executed.

3. **Scanning for Keywords and Structure:** Quickly scan the code for prominent keywords and structural elements:
    * `// Copyright`: Standard license header, ignore for functionality.
    * `#include`:  Includes C++ headers, indicating interaction with lower-level code.
    * `namespace runtime { ... }`:  Declares external runtime functions. These are C++ functions that Torque builtins will call. This is a *key* part of understanding the functionality.
    * `extern operator ... macro`: Defines Torque macros, which are like inline functions.
    * `namespace unsafe { ... }`: Contains macros for unsafe memory allocation.
    * `macro ...`: Defines more Torque macros.
    * `builtin ...`: Defines Torque builtins. These are the core functions exposed to the WebAssembly runtime. Pay close attention to these.
    * `transitioning builtin ...`:  Similar to `builtin`, but might indicate state transitions or more complex logic.
    * `struct ...`: Defines data structures used within the Torque code.
    * `// Trap builtins.`:  A clear comment section indicating functions related to WebAssembly traps (errors).

4. **Analyzing Runtime Functions:**  Examine the `runtime` namespace. Each `extern runtime` declaration points to a C++ function. The names are often descriptive: `WasmMemoryGrow`, `WasmRefFunc`, `WasmTableInit`, etc. This gives a good initial understanding of the types of operations this code handles: memory management, function references, table manipulation, error handling, atomics, arrays, strings, etc.

5. **Analyzing Torque Macros:** Look at the `macro` definitions. These are often helper functions to simplify the builtins. For instance, `NumberToInt32`, `NumberToUint32`, `LoadContextFromFrame`, `UpdateCallRefOrIndirectIC`. These provide insights into common patterns and data conversions.

6. **Focusing on Torque Builtins:**  The `builtin` definitions are the most important. For each one:
    * **Identify the Name:**  The name usually reflects the WebAssembly operation it implements (e.g., `WasmMemoryGrow`, `WasmTableGet`, `WasmStringNewWtf8`).
    * **Examine Parameters and Return Type:**  The types provide crucial information about the inputs and outputs (e.g., `int32`, `uint32`, `Smi`, `Object`, `String`, `WasmArray`).
    * **Look for `runtime::` Calls:**  Most builtins will call one or more of the external runtime functions. This is where the actual work is delegated to the C++ layer.
    * **Identify Core Logic:** Look for `if` statements, `typeswitch`, `try...catch`, and other control flow elements. This reveals the specific steps taken for each operation.
    * **Note Error Handling:** Look for calls to `ThrowWasmTrap...` functions, indicating how WebAssembly errors are handled.

7. **Categorization and Grouping:** As you analyze the builtins, mentally group them by functionality:
    * **Memory:** `WasmMemoryGrow`, potentially related trap functions.
    * **Tables:** `WasmTableInit`, `WasmTableCopy`, `WasmTableFill`, `WasmTableGrow`, `WasmTableGet`, `WasmTableSet`, `WasmTableGetFuncRef`, `WasmTableSetFuncRef`.
    * **Function References:** `WasmRefFunc`, `WasmInternalFunctionCreateExternal`.
    * **Atomics:** `WasmI32AtomicWait`, `WasmI64AtomicWait`.
    * **Arrays:** `WasmArrayCopy`, `WasmArrayNewSegment`, `WasmArrayInitSegment`.
    * **Strings:**  A large section dedicated to string creation, manipulation, encoding, and decoding (`WasmStringNewWtf8`, `WasmStringNewWtf16`, `WasmStringMeasureUtf8`, `WasmStringEncodeWtf8`, etc.).
    * **Exceptions/Traps:**  The dedicated section of `ThrowWasmTrap...` functions.
    * **Type Feedback (IC):** `CallRefIC`, `CallIndirectIC`, `UpdateCallRefOrIndirectIC`.
    * **Other:**  Stack guard, tier-up, deoptimization, etc.

8. **Connecting to JavaScript (if applicable):** For builtins that directly correspond to JavaScript WebAssembly APIs, provide examples. For instance, `WasmMemoryGrow` maps to `WebAssembly.Memory.prototype.grow()`, table operations map to `WebAssembly.Table`, etc.

9. **Inferring Logic and Providing Examples:** For more complex builtins, infer the underlying logic. If there's a `try...catch` block, consider the conditions that might lead to the exception. For example, table access functions check for out-of-bounds indices. Provide hypothetical input and output scenarios.

10. **Identifying Potential Errors:**  Based on the error handling (`ThrowWasmTrap...`), identify common programming mistakes that could trigger these errors in WebAssembly code. Out-of-bounds memory access, table access, division by zero, type mismatches are common examples.

11. **Structuring the Output:** Organize the findings into clear sections:
    * **Functionality Summary:** A concise overview of the file's purpose.
    * **Relationship to JavaScript:**  Illustrate the connection to the JavaScript WebAssembly API.
    * **Code Logic and Examples:** Provide examples with assumed inputs and outputs for key builtins.
    * **Common Programming Errors:** List typical errors based on the trap conditions.

12. **Refinement and Review:**  Read through the summarized information to ensure accuracy and clarity. Check for any inconsistencies or areas where more detail might be needed. For instance, explaining the "IC" builtins requires understanding type feedback in V8.

This iterative process of scanning, analyzing keywords, understanding the role of runtime functions, focusing on builtins, and connecting to JavaScript allows for a comprehensive understanding of the `wasm.tq` file's functionality. The key is to recognize the structure of Torque code and how it interacts with the underlying V8 implementation.
Based on the provided v8 Torque source code (`v8/src/builtins/wasm.tq`), here's a breakdown of its functionality:

**Functionality Summary:**

This Torque file defines a collection of built-in functions (`builtin`) and supporting macros for the WebAssembly (Wasm) implementation within V8. These builtins handle various core Wasm operations, bridging the gap between the Wasm bytecode and V8's internal JavaScript engine. The code covers areas like:

* **Memory Management:** Growing Wasm memory.
* **Function References:** Creating and referencing Wasm functions.
* **Table Operations:** Initializing, copying, filling, growing, getting, and setting elements in Wasm tables.
* **Error Handling:** Throwing specific Wasm trap errors (e.g., out-of-bounds access, division by zero, stack overflow).
* **Atomic Operations:** Implementing atomic wait operations on shared memory.
* **Array Operations:** Copying, initializing, and creating segments of Wasm arrays.
* **String Operations:** Creating, measuring, encoding, decoding, concatenating, comparing, slicing, and iterating over Wasm strings (both UTF-8 and UTF-16).
* **Type Conversions:** Converting between Wasm types and JavaScript types (e.g., integers to numbers, function references to JS functions).
* **Type Feedback (Inline Caches):**  Optimizing indirect calls and `call_ref` through inline caches.
* **Deoptimization:** Handling deoptimization scenarios for Liftoff (V8's baseline Wasm compiler).
* **Stack Guard:** Implementing stack overflow protection.
* **Tracing:** Functions for debugging and profiling Wasm execution.
* **Fast API Calls:** Supporting optimized calls to JavaScript functions from Wasm.

**Relationship to JavaScript Functionality (with Examples):**

Many of these Torque builtins directly implement the functionality exposed by the JavaScript WebAssembly API. Here are some examples:

* **`WasmMemoryGrow(memIndex: int32, numPages: int32): int32`**: This corresponds to the `WebAssembly.Memory.prototype.grow()` method in JavaScript.

   ```javascript
   const memory = new WebAssembly.Memory({ initial: 1 });
   const oldSize = memory.grow(1); // Attempts to grow memory by 1 page
   console.log(oldSize); // Output will be the previous size in pages (1)
   ```

* **`WasmTableGet(tableIndex: intptr, index: intptr): Object` and `WasmTableSet(...)`**: These relate to accessing and modifying elements in a `WebAssembly.Table`.

   ```javascript
   const table = new WebAssembly.Table({ initial: 2, element: 'funcref' });
   const funcRef = table.get(0); // Get the element at index 0
   table.set(1, someWasmFunction); // Set the element at index 1
   ```

* **`WasmRefFunc(index: uint32, extractSharedData: boolean): Object`**: This is used internally to obtain a function reference, which is conceptually related to getting a function from an exported Wasm module or a table.

* **`WasmStringNewWtf8(...)` and other `WasmString...` functions**: These are used in the implementation of the [WebAssembly Stringref proposal](https://github.com/WebAssembly/stringref). While not directly exposed in early stages, they underlie how Wasm strings are created and manipulated.

* **`WasmI32AtomicWait(...)` and `WasmI64AtomicWait(...)`**: These implement the functionality of the `Atomics.wait()` methods for shared memory in Wasm.

   ```javascript
   const sab = new SharedArrayBuffer(8);
   const i32a = new Int32Array(sab);
   Atomics.store(i32a, 0, 0); // Initialize the value

   // In one thread:
   const result = Atomics.wait(i32a, 0, 0, 1000); // Wait for the value at index 0 to become non-zero (timeout 1000ms)
   console.log(result); // Possible results: "ok", "not-equal", "timed-out"

   // In another thread:
   Atomics.store(i32a, 0, 1);
   Atomics.notify(i32a, 0, 1); // Wake up one waiting thread
   ```

* **`WasmThrow(tag: Object, values: FixedArray): JSAny` and `WasmRethrow(exception: Object): JSAny`**: These are internal mechanisms for handling exceptions (using the exception handling proposal in Wasm). In JavaScript, this is surfaced through `try...catch` blocks around Wasm function calls that might throw.

**Code Logic Inference and Examples:**

Let's take the `WasmTableGet` builtin as an example for code logic inference:

```torque
builtin WasmTableGet(tableIndex: intptr, index: intptr): Object {
  const trustedData: WasmTrustedInstanceData = LoadInstanceDataFromFrame();
  try {
    dcheck(IsValidPositiveSmi(tableIndex));

    const tables: FixedArray = LoadTablesFromInstanceData(trustedData);
    const table: WasmTableObject = %RawDownCast<WasmTableObject>(
        LoadFixedArrayElement(tables, tableIndex));
    const entriesCount: uintptr =
        Unsigned(ChangeInt32ToIntPtr(SmiToInt32(table.current_length)));
    if (Unsigned(index) >= entriesCount) goto IndexOutOfRange;

    const entries: FixedArray = table.entries;
    const entry: Object = LoadFixedArrayElement(entries, index);
    return entry;
  } label IndexOutOfRange deferred {
    tail ThrowWasmTrapTableOutOfBounds();
  }
}
```

**Assumptions:**

* `tableIndex`: An integer representing the index of the table within the Wasm instance's table array.
* `index`: An integer representing the index of the element to retrieve from the table.

**Logic:**

1. **Load Instance Data:** Retrieves information about the current Wasm instance.
2. **Input Validation:** Checks if `tableIndex` is a valid positive Smi (Small Integer).
3. **Access Table Array:** Loads the array of tables from the instance data.
4. **Get Table Object:** Retrieves the specific `WasmTableObject` based on `tableIndex`.
5. **Get Table Length:**  Gets the current number of entries in the table.
6. **Boundary Check:** Checks if the requested `index` is within the bounds of the table.
7. **Access Entries Array:** If the index is valid, loads the array containing the table's elements.
8. **Retrieve Entry:** Retrieves the element at the specified `index`.
9. **Return Entry:** Returns the retrieved element.
10. **Error Handling:** If the `index` is out of bounds, it jumps to the `IndexOutOfRange` label and throws a `WasmTrapTableOutOfBounds` error.

**Hypothetical Input and Output:**

* **Input:** `tableIndex = 0`, `index = 1` (assuming a table exists at index 0 with at least 2 elements).
* **Output:** The element stored at index 1 of the Wasm table.

* **Input:** `tableIndex = 0`, `index = 10` (assuming the table at index 0 has fewer than 11 elements).
* **Output:** A Wasm trap error indicating table out-of-bounds access.

**User Common Programming Errors (with Examples):**

This file directly deals with the low-level implementation, but we can infer common programming errors in Wasm that would lead to these builtins being invoked with error conditions:

* **Out-of-Bounds Memory Access:** Trying to read or write memory outside the allocated Wasm memory bounds. This would likely trigger `ThrowWasmTrapMemOutOfBounds()`.

   ```c++ // Hypothetical Wasm code
   (memory $0 1)
   (func $access_memory (param $offset i32) (result i32)
     (i32.load (memory.get_local $offset)))

   ;; Calling this function with an offset beyond the memory size
   ;; would lead to a trap.
   ```

* **Out-of-Bounds Table Access:** Trying to access an element in a Wasm table using an index that is outside the table's valid range. This would trigger `ThrowWasmTrapTableOutOfBounds()`.

   ```c++ // Hypothetical Wasm code
   (table $t 2 funcref)
   (func $get_table_element (param $index i32) (result funcref)
     (table.get $t (local.get $index)))

   ;; Calling this with an index >= 2 would cause a trap.
   ```

* **Division by Zero:** Performing an integer division where the divisor is zero. This would trigger `ThrowWasmTrapDivByZero()`.

   ```c++ // Hypothetical Wasm code
   (func $divide (param $a i32) (param $b i32) (result i32)
     (i32.div_s (local.get $a) (local.get $b)))

   ;; Calling this with $b = 0 would cause a trap.
   ```

* **Type Mismatches (Indirect Calls):**  Attempting to call a function indirectly through a table where the function signature doesn't match the expected signature. This would trigger `ThrowWasmTrapFuncSigMismatch()`.

* **Unreachable Code:** Executing the `unreachable` instruction in Wasm. This directly calls `ThrowWasmTrapUnreachable()`.

* **Stack Overflow:**  Causing excessive recursion or allocating too much data on the stack within a Wasm function. This would lead to `WasmStackOverflow()`.

* **Null Pointer Dereference (with reference types):**  Attempting to access a member of a null reference (when the reference types proposal is used). This would trigger `ThrowWasmTrapNullDereference()`.

* **Array Out of Bounds (with Wasm arrays):** Trying to access an element of a Wasm array with an invalid index. This would trigger `ThrowWasmTrapArrayOutOfBounds()`.

In summary, this `wasm.tq` file is a crucial part of V8's Wasm implementation, defining the core logic for executing various Wasm operations and handling potential runtime errors. It directly supports the functionality exposed by the JavaScript WebAssembly API.

### 提示词
```
这是目录为v8/src/builtins/wasm.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include 'src/builtins/builtins-wasm-gen.h'
#include 'src/builtins/builtins-call-gen.h'

namespace runtime {
extern runtime WasmMemoryGrow(Context, WasmTrustedInstanceData, Smi, Smi): Smi;
extern runtime WasmRefFunc(Context, WasmTrustedInstanceData, Smi): JSAny;
extern runtime WasmInternalFunctionCreateExternal(
    Context, WasmInternalFunction): JSFunction;
extern runtime WasmTableInit(
    Context, WasmTrustedInstanceData, Object, Object, Smi, Smi, Smi): JSAny;
extern runtime WasmTableCopy(
    Context, WasmTrustedInstanceData, Object, Object, Smi, Smi, Smi): JSAny;
extern runtime WasmTableFill(
    Context, WasmTrustedInstanceData, Smi, Smi, Object, Smi): JSAny;
extern runtime WasmTableGrow(
    Context, WasmTrustedInstanceData, Smi, Object, Smi): Smi;
extern runtime WasmFunctionTableGet(Context, WasmTrustedInstanceData, Smi, Smi):
    JSAny;
extern runtime WasmFunctionTableSet(
    Context, WasmTrustedInstanceData, Smi, Smi, Object): JSAny;
extern runtime ThrowRangeError(Context, Smi): never;
extern runtime ThrowWasmError(Context, Smi): never;
extern runtime WasmThrowRangeError(Context, Smi): never;
extern runtime TrapHandlerThrowWasmError(Context): never;
extern runtime WasmThrowTypeError(Context, Smi, JSAny): never;
extern runtime WasmThrowDataViewTypeError(Context, Smi, JSAny): never;
extern runtime WasmThrowDataViewDetachedError(Context, Smi): never;
extern runtime WasmThrow(Context, Object, FixedArray): JSAny;
extern runtime WasmReThrow(Context, Object): JSAny;
extern runtime WasmTriggerTierUp(Context, WasmTrustedInstanceData): JSAny;
extern runtime WasmStackGuard(Context, Smi): JSAny;
extern runtime ThrowWasmStackOverflow(Context): JSAny;
extern runtime WasmTraceMemory(Context, Smi): JSAny;
extern runtime WasmTraceEnter(Context): JSAny;
extern runtime WasmTraceExit(Context, Smi): JSAny;
extern runtime WasmI32AtomicWait(
    Context, WasmTrustedInstanceData, Smi, Number, Number, BigInt): Smi;
extern runtime WasmI64AtomicWait(
    Context, WasmTrustedInstanceData, Smi, Number, BigInt, BigInt): Smi;
extern runtime WasmArrayCopy(Context, WasmArray, Smi, WasmArray, Smi, Smi):
    JSAny;
extern runtime WasmArrayNewSegment(
    Context, WasmTrustedInstanceData, Smi, Smi, Smi, Map): Object;
extern runtime WasmStringNewSegmentWtf8(
    Context, WasmTrustedInstanceData, Smi, Smi, Smi, Smi): String|WasmNull;
extern runtime WasmArrayInitSegment(
    Context, WasmTrustedInstanceData, Smi, WasmArray, Smi, Smi, Smi): JSAny;
extern runtime WasmStringNewWtf8(
    Context, WasmTrustedInstanceData, Smi, Smi, Number, Number): String
    |WasmNull;
extern runtime WasmStringNewWtf8Array(Context, Smi, WasmArray, Smi, Smi): String
    |WasmNull;
extern runtime WasmStringNewWtf16(
    Context, WasmTrustedInstanceData, Smi, Number, Number): String;
extern runtime WasmStringNewWtf16Array(Context, WasmArray, Smi, Smi): String;
extern runtime WasmStringConst(Context, WasmTrustedInstanceData, Smi): String;
extern runtime WasmStringMeasureUtf8(Context, String): Number;
extern runtime WasmStringMeasureWtf8(Context, String): Number;
extern runtime WasmStringEncodeWtf8(
    Context, WasmTrustedInstanceData, Smi, Smi, String, Number): Number;
extern runtime WasmStringEncodeWtf8Array(
    Context, Smi, String, WasmArray, Number): Number;
extern runtime WasmStringToUtf8Array(Context, String): WasmArray;
extern runtime WasmStringEncodeWtf16(
    Context, WasmTrustedInstanceData, Smi, String, Number, Smi, Smi): JSAny;
extern runtime WasmStringAsWtf8(Context, String): ByteArray;
extern runtime WasmStringViewWtf8Encode(
    Context, WasmTrustedInstanceData, Smi, ByteArray, Number, Number, Number,
    Smi): JSAny;
extern runtime WasmStringViewWtf8Slice(Context, ByteArray, Number, Number):
    String;
extern runtime WasmStringFromCodePoint(Context, Number): String;
extern runtime WasmStringHash(NoContext, String): Smi;
extern runtime WasmSubstring(Context, String, Smi, Smi): String;
extern runtime WasmJSToWasmObject(Context, JSAny, Smi): JSAny;
extern runtime WasmLiftoffDeoptFinish(NoContext, WasmTrustedInstanceData):
    Undefined;

extern runtime PropagateException(NoContext): JSAny;
}

extern operator '.wasm_exported_function_data' macro
    LoadSharedFunctionInfoWasmExportedFunctionData(SharedFunctionInfo):
        WasmExportedFunctionData;
extern operator '.wasm_js_function_data' macro
    LoadSharedFunctionInfoWasmJSFunctionData(SharedFunctionInfo):
        WasmJSFunctionData;

namespace unsafe {
extern macro Allocate(intptr): HeapObject;
extern macro Allocate(intptr, constexpr AllocationFlag): HeapObject;
}

macro NumberToInt32(input: Number): int32 {
  return Convert<int32>(input);
}
macro NumberToUint32(input: Number): uint32 {
  return Unsigned(Convert<int32>(input));
}

namespace wasm {
const kAnyType: constexpr int31
    generates 'wasm::kWasmAnyRef.raw_bit_field()';
const kMaxPolymorphism:
    constexpr int31 generates 'wasm::kMaxPolymorphism';
const kFixedFrameSizeAboveFp: constexpr int32
    generates 'CommonFrameConstants::kFixedFrameSizeAboveFp';

extern macro WasmCrossInstanceCallSymbolConstant(): Symbol;

extern macro WasmBuiltinsAssembler::LoadTrustedDataFromInstance(
    WasmInstanceObject): WasmTrustedInstanceData;

extern macro WasmBuiltinsAssembler::LoadInstanceDataFromFrame():
    WasmTrustedInstanceData;

// WasmTrustedInstanceData has a field layout that Torque can't handle yet.
// TODO(bbudge) Eliminate these functions when Torque is ready.
extern macro WasmBuiltinsAssembler::LoadContextFromInstanceData(
    WasmTrustedInstanceData): NativeContext;
extern macro WasmBuiltinsAssembler::LoadSharedPartFromInstanceData(
    WasmTrustedInstanceData): WasmTrustedInstanceData;
extern macro WasmBuiltinsAssembler::LoadTablesFromInstanceData(
    WasmTrustedInstanceData): FixedArray;
extern macro WasmBuiltinsAssembler::LoadFuncRefsFromInstanceData(
    WasmTrustedInstanceData): FixedArray;
extern macro WasmBuiltinsAssembler::LoadManagedObjectMapsFromInstanceData(
    WasmTrustedInstanceData): FixedArray;
extern macro WasmBuiltinsAssembler::LoadContextFromWasmOrJsFrame():
    NativeContext;

extern macro WasmBuiltinsAssembler::StringToFloat64(String): float64;

// This doesn't return, but the return type {never} confuses the CSA graph.
extern macro WasmBuiltinsAssembler::SignatureCheckFail(
    WasmInternalFunction, uintptr): Smi;

extern macro SwitchToTheCentralStackIfNeeded(): RawPtr;
extern macro SwitchFromTheCentralStack(RawPtr): void;

macro LoadContextFromFrame(): NativeContext {
  return LoadContextFromInstanceData(LoadInstanceDataFromFrame());
}

macro LoadMaybeSharedInstanceDataFromFrame(extractSharedData: bool):
    WasmTrustedInstanceData {
  const trustedData = LoadInstanceDataFromFrame();
  if (extractSharedData) {
    return LoadSharedPartFromInstanceData(trustedData);
  } else {
    return trustedData;
  }
}

macro LoadMaybeSharedInstanceDataFromFrame(extractSharedData: Smi):
    WasmTrustedInstanceData {
  const trustedData = LoadInstanceDataFromFrame();
  if (extractSharedData == SmiConstant(1)) {
    return LoadSharedPartFromInstanceData(trustedData);
  } else {
    return trustedData;
  }
}

builtin WasmInt32ToHeapNumber(val: int32): HeapNumber {
  return AllocateHeapNumberWithValue(Convert<float64>(val));
}

builtin WasmFuncRefToJS(
    implicit context: Context)(val: WasmFuncRef|WasmNull): JSFunction|Null {
  typeswitch (val) {
    case (WasmNull): {
      return Null;
    }
    case (func: WasmFuncRef): {
      const internal: WasmInternalFunction = func.internal;
      const maybeExternal: Object = internal.external;
      if (maybeExternal != Undefined) {
        return %RawDownCast<JSFunction>(maybeExternal);
      }
      tail runtime::WasmInternalFunctionCreateExternal(context, internal);
    }
  }
}

builtin WasmTaggedNonSmiToInt32(implicit context: Context)(val: HeapObject):
    int32 {
  return ChangeTaggedNonSmiToInt32(val);
}

builtin WasmTaggedToFloat64(implicit context: Context)(val: JSAny): float64 {
  return ChangeTaggedToFloat64(val);
}

builtin WasmTaggedToFloat32(implicit context: Context)(val: JSAny): float32 {
  return TruncateFloat64ToFloat32(ChangeTaggedToFloat64(val));
}

builtin WasmMemoryGrow(memIndex: int32, numPages: int32): int32 {
  dcheck(IsValidPositiveSmi(ChangeInt32ToIntPtr(memIndex)));
  if (!IsValidPositiveSmi(ChangeInt32ToIntPtr(numPages))) {
    return Int32Constant(-1);
  }
  const trustedData: WasmTrustedInstanceData = LoadInstanceDataFromFrame();
  const context: NativeContext = LoadContextFromInstanceData(trustedData);
  const result: Smi = runtime::WasmMemoryGrow(
      context, trustedData, SmiFromInt32(memIndex), SmiFromInt32(numPages));
  return SmiToInt32(result);
}

builtin WasmTableInit(
    dstRaw: intptr, srcRaw: uint32, sizeRaw: uint32, tableIndex: Smi,
    segmentIndex: Smi, extractSharedData: Smi): JSAny {
  try {
    const trustedData: WasmTrustedInstanceData =
        LoadMaybeSharedInstanceDataFromFrame(extractSharedData);
    const dst: Smi = Convert<PositiveSmi>(dstRaw) otherwise TableOutOfBounds;
    const src: Smi = Convert<PositiveSmi>(srcRaw) otherwise TableOutOfBounds;
    const size: Smi = Convert<PositiveSmi>(sizeRaw) otherwise TableOutOfBounds;
    tail runtime::WasmTableInit(
        LoadContextFromInstanceData(trustedData), trustedData, tableIndex,
        segmentIndex, dst, src, size);
  } label TableOutOfBounds deferred {
    tail ThrowWasmTrapTableOutOfBounds();
  }
}

builtin WasmTableCopy(
    dstRaw: intptr, srcRaw: intptr, sizeRaw: intptr, dstTable: Smi,
    srcTable: Smi, extractSharedData: Smi): JSAny {
  try {
    const trustedData: WasmTrustedInstanceData =
        LoadMaybeSharedInstanceDataFromFrame(extractSharedData);
    const dst: Smi = Convert<PositiveSmi>(dstRaw) otherwise TableOutOfBounds;
    const src: Smi = Convert<PositiveSmi>(srcRaw) otherwise TableOutOfBounds;
    const size: Smi = Convert<PositiveSmi>(sizeRaw) otherwise TableOutOfBounds;
    tail runtime::WasmTableCopy(
        LoadContextFromInstanceData(trustedData), trustedData, dstTable,
        srcTable, dst, src, size);
  } label TableOutOfBounds deferred {
    tail ThrowWasmTrapTableOutOfBounds();
  }
}

builtin WasmTableFill(
    startRaw: intptr, countRaw: intptr, extractSharedData: bool, table: Smi,
    value: Object): JSAny {
  try {
    const trustedData: WasmTrustedInstanceData =
        LoadMaybeSharedInstanceDataFromFrame(extractSharedData);
    const start: Smi =
        Convert<PositiveSmi>(startRaw) otherwise TableOutOfBounds;
    const count: Smi =
        Convert<PositiveSmi>(countRaw) otherwise TableOutOfBounds;
    tail runtime::WasmTableFill(
        LoadContextFromInstanceData(trustedData), trustedData, table, start,
        value, count);
  } label TableOutOfBounds deferred {
    tail ThrowWasmTrapTableOutOfBounds();
  }
}

builtin WasmTableGrow(
    table: Smi, deltaRaw: intptr, extractSharedData: bool, value: Object): Smi {
  try {
    const trustedData: WasmTrustedInstanceData =
        LoadMaybeSharedInstanceDataFromFrame(extractSharedData);
    const delta: Smi =
        Convert<PositiveSmi>(deltaRaw) otherwise TableOutOfBounds;
    tail runtime::WasmTableGrow(
        LoadContextFromInstanceData(trustedData), trustedData, table, value,
        delta);
  } label TableOutOfBounds deferred {
    return -1;
  }
}

builtin WasmTableGet(tableIndex: intptr, index: intptr): Object {
  const trustedData: WasmTrustedInstanceData = LoadInstanceDataFromFrame();
  try {
    dcheck(IsValidPositiveSmi(tableIndex));

    const tables: FixedArray = LoadTablesFromInstanceData(trustedData);
    const table: WasmTableObject = %RawDownCast<WasmTableObject>(
        LoadFixedArrayElement(tables, tableIndex));
    const entriesCount: uintptr =
        Unsigned(ChangeInt32ToIntPtr(SmiToInt32(table.current_length)));
    if (Unsigned(index) >= entriesCount) goto IndexOutOfRange;

    const entries: FixedArray = table.entries;
    const entry: Object = LoadFixedArrayElement(entries, index);
    return entry;
  } label IndexOutOfRange deferred {
    tail ThrowWasmTrapTableOutOfBounds();
  }
}

builtin WasmTableSet(
    tableIndex: intptr, extractSharedData: bool, index: intptr,
    value: Object): Object {
  const trustedData: WasmTrustedInstanceData =
      LoadMaybeSharedInstanceDataFromFrame(extractSharedData);
  try {
    dcheck(IsValidPositiveSmi(tableIndex));

    const tables: FixedArray = LoadTablesFromInstanceData(trustedData);
    const table: WasmTableObject = %RawDownCast<WasmTableObject>(
        LoadFixedArrayElement(tables, tableIndex));

    const entriesCount: uintptr =
        Unsigned(ChangeInt32ToIntPtr(SmiToInt32(table.current_length)));
    if (Unsigned(index) >= entriesCount) goto IndexOutOfRange;

    const entries: FixedArray = table.entries;
    StoreFixedArrayElement(entries, index, value);
    return Undefined;
  } label IndexOutOfRange deferred {
    tail ThrowWasmTrapTableOutOfBounds();
  }
}

// Returns WasmFuncRef or WasmNull, or throws an exception.
builtin WasmTableGetFuncRef(tableIndex: intptr, index: intptr): Object {
  const trustedData: WasmTrustedInstanceData = LoadInstanceDataFromFrame();
  try {
    dcheck(IsValidPositiveSmi(tableIndex));

    const tables: FixedArray = LoadTablesFromInstanceData(trustedData);
    const table: WasmTableObject = %RawDownCast<WasmTableObject>(
        LoadFixedArrayElement(tables, tableIndex));
    const entriesCount: uintptr =
        Unsigned(ChangeInt32ToIntPtr(SmiToInt32(table.current_length)));
    if (Unsigned(index) >= entriesCount) goto IndexOutOfRange;

    const entries: FixedArray = table.entries;
    const entry: HeapObject =
        UnsafeCast<HeapObject>(LoadFixedArrayElement(entries, index));

    dcheck(Is<WasmFuncRef>(entry) || Is<WasmNull>(entry) || Is<Tuple2>(entry));
    if (IsTuple2Map(entry.map)) goto CallRuntime;
    if (Is<WasmNull>(entry)) return entry;
    dcheck(Is<WasmFuncRef>(entry));
    return entry;
  } label CallRuntime deferred {
    tail runtime::WasmFunctionTableGet(
        LoadContextFromInstanceData(trustedData), trustedData,
        SmiFromIntPtr(tableIndex), SmiFromIntPtr(index));
  } label IndexOutOfRange deferred {
    tail ThrowWasmTrapTableOutOfBounds();
  }
}

// Stub to wrap around the slow path (runtime call) of table.get for funcref
// tables for which the reference is not yet initialized.
builtin WasmFunctionTableGet(
    tableIndex: intptr, index: intptr, extractSharedData: bool): Object {
  const trustedData: WasmTrustedInstanceData =
      LoadMaybeSharedInstanceDataFromFrame(extractSharedData);
  dcheck(IsValidPositiveSmi(tableIndex));
  dcheck(IsValidPositiveSmi(index));
  tail runtime::WasmFunctionTableGet(
      LoadContextFromInstanceData(trustedData), trustedData,
      SmiFromIntPtr(tableIndex), SmiFromIntPtr(index));
}

builtin WasmTableSetFuncRef(
    tableIndex: intptr, extractSharedData: bool, index: intptr,
    value: WasmFuncRef): Object {
  const trustedData: WasmTrustedInstanceData =
      LoadMaybeSharedInstanceDataFromFrame(extractSharedData);
  dcheck(Is<WasmFuncRef>(value) || Is<WasmNull>(value));
  try {
    dcheck(IsValidPositiveSmi(tableIndex));

    const tables: FixedArray = LoadTablesFromInstanceData(trustedData);
    const table: WasmTableObject = %RawDownCast<WasmTableObject>(
        LoadFixedArrayElement(tables, tableIndex));

    const entriesCount: uintptr =
        Unsigned(ChangeInt32ToIntPtr(SmiToInt32(table.current_length)));
    if (Unsigned(index) >= entriesCount) goto IndexOutOfRange;

    tail runtime::WasmFunctionTableSet(
        LoadContextFromInstanceData(trustedData), trustedData,
        SmiFromIntPtr(tableIndex), SmiFromIntPtr(index), value);
  } label IndexOutOfRange deferred {
    tail ThrowWasmTrapTableOutOfBounds();
  }
}

builtin WasmRefFunc(index: uint32, extractSharedData: bool): Object {
  const trustedData: WasmTrustedInstanceData =
      LoadMaybeSharedInstanceDataFromFrame(extractSharedData);
  try {
    const funcRefs: FixedArray = LoadFuncRefsFromInstanceData(trustedData);
    const funcref: Object = funcRefs.objects[index];
    // {funcref} is either a WasmFuncRef or Smi::zero(). A Smi check is the
    // fastest way to distinguish these two cases.
    if (TaggedIsSmi(funcref)) goto CallRuntime;
    dcheck(Is<WasmFuncRef>(funcref));
    return funcref;
  } label CallRuntime deferred {
    tail runtime::WasmRefFunc(
        LoadContextFromInstanceData(trustedData), trustedData,
        SmiFromUint32(index));
  }
}

builtin WasmInternalFunctionCreateExternal(
    context: Context, func: WasmInternalFunction): JSFunction {
  return runtime::WasmInternalFunctionCreateExternal(context, func);
}

builtin WasmAllocateZeroedFixedArray(size: intptr): FixedArray {
  if (size == 0) return kEmptyFixedArray;
  const result = UnsafeCast<FixedArray>(AllocateFixedArray(
      ElementsKind::PACKED_ELEMENTS, size, AllocationFlag::kNone));
  FillEntireFixedArrayWithSmiZero(ElementsKind::PACKED_ELEMENTS, result, size);
  return result;
}

builtin WasmAllocateFixedArray(size: intptr): FixedArray {
  if (size == 0) return kEmptyFixedArray;
  return UnsafeCast<FixedArray>(AllocateFixedArray(
      ElementsKind::PACKED_ELEMENTS, size, AllocationFlag::kNone));
}

builtin WasmLiftoffDeoptFinish(): Undefined {
  const trustedData = LoadInstanceDataFromFrame();
  tail runtime::WasmLiftoffDeoptFinish(kNoContext, trustedData);
}

builtin WasmThrow(tag: Object, values: FixedArray): JSAny {
  tail runtime::WasmThrow(LoadContextFromFrame(), tag, values);
}

builtin WasmRethrow(exception: Object): JSAny {
  dcheck(exception != kWasmNull);
  tail runtime::WasmReThrow(LoadContextFromFrame(), exception);
}

builtin WasmThrowRef(exception: Object): JSAny {
  if (exception == kWasmNull) tail ThrowWasmTrapRethrowNull();
  tail runtime::WasmReThrow(LoadContextFromFrame(), exception);
}

// We need this for frames that do not have the instance in the parameters.
// Currently, this is CapiCallWrapper frames.
builtin WasmRethrowExplicitContext(
    exception: Object, explicitContext: Context): JSAny {
  if (exception == Null) tail ThrowWasmTrapRethrowNull();
  tail runtime::WasmReThrow(explicitContext, exception);
}

builtin WasmTriggerTierUp(): JSAny {
  const trustedData = LoadInstanceDataFromFrame();
  tail runtime::WasmTriggerTierUp(LoadContextFromFrame(), trustedData);
}

extern builtin WasmHandleStackOverflow(RawPtr, uint32): JSAny;

// {paramSlotsSize} is the size of the incoming stack parameters of the
// currently-executing function, which have to be copied along with its
// stack frame if the stack needs to be grown.
builtin WasmGrowableStackGuard(paramSlotsSize: intptr): JSAny {
  tail WasmHandleStackOverflow(
      LoadParentFramePointer() + paramSlotsSize + kFixedFrameSizeAboveFp, 0);
}

builtin WasmStackGuard(): JSAny {
  tail runtime::WasmStackGuard(LoadContextFromFrame(), SmiConstant(0));
}

builtin WasmStackOverflow(): JSAny {
  tail runtime::ThrowWasmStackOverflow(LoadContextFromFrame());
}

builtin WasmTraceMemory(info: Smi): JSAny {
  tail runtime::WasmTraceMemory(LoadContextFromFrame(), info);
}

builtin WasmTraceEnter(): JSAny {
  tail runtime::WasmTraceEnter(LoadContextFromFrame());
}

builtin WasmTraceExit(info: Smi): JSAny {
  tail runtime::WasmTraceExit(LoadContextFromFrame(), info);
}

builtin WasmAllocateJSArray(implicit context: Context)(size: Smi): JSArray {
  const map: Map = GetFastPackedElementsJSArrayMap();
  return AllocateJSArray(ElementsKind::PACKED_ELEMENTS, map, size, size);
}

builtin WasmAllocateStructWithRtt(rtt: Map, instanceSize: int32): HeapObject {
  const result: HeapObject = unsafe::Allocate(Convert<intptr>(instanceSize));
  *UnsafeConstCast(&result.map) = rtt;
  // TODO(ishell): consider removing properties_or_hash field from WasmObjects.
  %RawDownCast<WasmStruct>(result).properties_or_hash = kEmptyFixedArray;
  return result;
}

builtin WasmAllocateArray_Uninitialized(
    rtt: Map, length: uint32, elementSize: uint32): WasmArray {
  // instanceSize = RoundUp(elementSize * length, kObjectAlignment)
  //              + WasmArray::kHeaderSize
  const instanceSize: intptr =
      torque_internal::AlignTagged(
          Convert<intptr>(length) * Convert<intptr>(elementSize)) +
      Convert<intptr>(kWasmArrayHeaderSize);
  const result: HeapObject = unsafe::Allocate(instanceSize);
  *UnsafeConstCast(&result.map) = rtt;
  // TODO(ishell): consider removing properties_or_hash field from WasmObjects.
  %RawDownCast<WasmArray>(result).properties_or_hash = kEmptyFixedArray;
  %RawDownCast<WasmArray>(result).length = length;
  return %RawDownCast<WasmArray>(result);
}

builtin WasmArrayNewSegment(
    segmentIndex: uint32, offset: uint32, length: uint32, isElement: Smi,
    extractSharedData: Smi, rtt: Map): Object {
  const trustedData: WasmTrustedInstanceData =
      LoadMaybeSharedInstanceDataFromFrame(extractSharedData);
  try {
    const smiOffset = Convert<PositiveSmi>(offset) otherwise SegmentOutOfBounds;
    const smiLength = Convert<PositiveSmi>(length) otherwise ArrayTooLarge;
    tail runtime::WasmArrayNewSegment(
        LoadContextFromInstanceData(trustedData), trustedData,
        SmiFromUint32(segmentIndex), smiOffset, smiLength, rtt);
  } label SegmentOutOfBounds {
    if (isElement == SmiConstant(0)) {
      tail ThrowWasmTrapDataSegmentOutOfBounds();
    } else {
      tail ThrowWasmTrapElementSegmentOutOfBounds();
    }
  } label ArrayTooLarge {
    tail ThrowWasmTrapArrayTooLarge();
  }
}

// {segmentIndex} has to be tagged as a possible stack parameter.
builtin WasmArrayInitSegment(
    arrayIndex: uint32, segmentOffset: uint32, length: uint32,
    segmentIndex: Smi, isElement: Smi, extractSharedData: Smi,
    arrayRaw: HeapObject): JSAny {
  const trustedData: WasmTrustedInstanceData =
      LoadMaybeSharedInstanceDataFromFrame(extractSharedData);
  if (arrayRaw == kWasmNull) {
    tail ThrowWasmTrapNullDereference();
  }
  const array = %RawDownCast<WasmArray>(arrayRaw);
  try {
    const smiArrayIndex =
        Convert<PositiveSmi>(arrayIndex) otherwise ArrayOutOfBounds;
    const smiOffset =
        Convert<PositiveSmi>(segmentOffset) otherwise SegmentOutOfBounds;
    const smiLength = Convert<PositiveSmi>(length) otherwise ArrayOutOfBounds;

    tail runtime::WasmArrayInitSegment(
        LoadContextFromInstanceData(trustedData), trustedData, segmentIndex,
        array, smiArrayIndex, smiOffset, smiLength);
  } label SegmentOutOfBounds {
    if (isElement == SmiConstant(0)) {
      tail ThrowWasmTrapDataSegmentOutOfBounds();
    } else {
      tail ThrowWasmTrapElementSegmentOutOfBounds();
    }
  } label ArrayOutOfBounds {
    tail ThrowWasmTrapArrayOutOfBounds();
  }
}

// We put all uint32 parameters at the beginning so that they are assigned to
// registers.
builtin WasmArrayCopy(
    dstIndex: uint32, srcIndex: uint32, length: uint32, dstObject: Object,
    srcObject: Object): JSAny {
  // Check destination array.
  if (dstObject == kWasmNull) tail ThrowWasmTrapNullDereference();
  const dstArray = UnsafeCast<WasmArray>(dstObject);
  if (dstIndex + length > dstArray.length || dstIndex + length < dstIndex) {
    tail ThrowWasmTrapArrayOutOfBounds();
  }
  // Check source array.
  if (srcObject == kWasmNull) tail ThrowWasmTrapNullDereference();
  const srcArray = UnsafeCast<WasmArray>(srcObject);
  if (srcIndex + length > srcArray.length || srcIndex + length < srcIndex) {
    tail ThrowWasmTrapArrayOutOfBounds();
  }

  if (length == 0) return Undefined;
  tail runtime::WasmArrayCopy(
      LoadContextFromFrame(), dstArray, SmiFromUint32(dstIndex), srcArray,
      SmiFromUint32(srcIndex), SmiFromUint32(length));
}

builtin WasmUint32ToNumber(value: uint32): Number {
  return ChangeUint32ToTagged(value);
}

builtin UintPtr53ToNumber(value: uintptr): Number {
  if (value <= kSmiMaxValue) return Convert<Smi>(Convert<intptr>(value));
  const valueFloat = ChangeUintPtrToFloat64(value);
  // Values need to be within [0..2^53], such that they can be represented as
  // float64.
  dcheck(ChangeFloat64ToUintPtr(valueFloat) == value);
  return AllocateHeapNumberWithValue(valueFloat);
}

// Suitable for indexes/offsets into memory: while values >2^53 will get
// rounded off, they're all OOB anyway, and an OOB check after a conversion
// back to uintptr can still detect that. (Alternatively we could trap
// right here.)
macro UintPtrToNumberRounding(value: uintptr): Number {
  if (value <= kSmiMaxValue) return Convert<Smi>(Convert<intptr>(value));
  return AllocateHeapNumberWithValue(ChangeUintPtrToFloat64(value));
}

extern builtin I64ToBigInt(intptr): BigInt;
extern builtin I32PairToBigInt(/*low*/ intptr, /*high*/ intptr): BigInt;

builtin WasmI32AtomicWait(
    memIndex: int32, offset: uintptr, expectedValue: int32,
    timeout: BigInt): uint32 {
  const trustedData: WasmTrustedInstanceData = LoadInstanceDataFromFrame();
  const result: Smi = runtime::WasmI32AtomicWait(
      LoadContextFromInstanceData(trustedData), trustedData,
      SmiFromInt32(memIndex), UintPtr53ToNumber(offset),
      ChangeInt32ToTagged(expectedValue), timeout);
  return Unsigned(SmiToInt32(result));
}

builtin WasmI64AtomicWait(
    memIndex: int32, offset: uintptr, expectedValue: BigInt,
    timeout: BigInt): uint32 {
  const trustedData: WasmTrustedInstanceData = LoadInstanceDataFromFrame();
  const result: Smi = runtime::WasmI64AtomicWait(
      LoadContextFromInstanceData(trustedData), trustedData,
      SmiFromInt32(memIndex), UintPtr53ToNumber(offset), expectedValue,
      timeout);
  return Unsigned(SmiToInt32(result));
}

// Type feedback collection support for `call_ref` and `call_indirect`.

// See {TransitiveTypeFeedbackProcessor::ProcessFunction} for the vector layout.
//
// TODO(rstz): The counter might overflow if it exceeds the range of a Smi.
// This can lead to incorrect inlining decisions.
macro UpdateCallRefOrIndirectIC(
    vector: FixedArray, index: intptr, target: Object): void {
  const firstSlot = vector.objects[index];
  const secondSlot = vector.objects[index + 1];
  if (TaggedEqual(firstSlot, target)) {
    // Monomorphic hit. Check for this case first to maximize its performance.
    const count = UnsafeCast<Smi>(secondSlot) + SmiConstant(1);
    vector.objects[index + 1] = count;
    return;
  }
  // Check for polymorphic hit; its performance is second-most-important.
  if (Is<FixedArray>(firstSlot)) {
    const entries = UnsafeCast<FixedArray>(firstSlot);
    for (let i: intptr = 0; i < entries.length_intptr; i += 2) {
      if (TaggedEqual(entries.objects[i], target)) {
        // Polymorphic hit.
        const count = UnsafeCast<Smi>(entries.objects[i + 1]) + SmiConstant(1);
        entries.objects[i + 1] = count;
        return;
      }
    }
  }
  // All other cases are some sort of miss.
  if (TaggedEqual(secondSlot, SmiConstant(0))) {
    // Was uninitialized.
    // Note that we inspect the second slot (the call count, see feedback vector
    // layout in {TransitiveTypeFeedbackProcessor::ProcessFunction}) for
    // determining whether the entry is uninitialized, not the first slot (the
    // call target), since the target may genuinely be zero for `call_indirect`
    // if the `WasmDispatchTable` happens to start at an address with many zero
    // least significant bits.
    dcheck(TaggedEqual(firstSlot, SmiConstant(0)));
    vector.objects[index] = target;
    vector.objects[index + 1] = SmiConstant(1);
  } else if (Is<FixedArray>(firstSlot)) {
    // Polymorphic miss.
    const entries = UnsafeCast<FixedArray>(firstSlot);
    const kMaxSlots = kMaxPolymorphism * 2;  // 2 slots per entry.
    if (entries.length == SmiConstant(kMaxSlots)) {
      // Polymorphic to megamorphic transition.
      vector.objects[index] = ic::kMegamorphicSymbol;
      // The second slot/counter has already been set to undefined below.
    } else {
      // Polymorphic(N) to polymorphic(N+1) transition.
      const newEntries = UnsafeCast<FixedArray>(AllocateFixedArray(
          ElementsKind::PACKED_ELEMENTS, entries.length_intptr + 2,
          AllocationFlag::kNone));
      for (let i: intptr = 0; i < entries.length_intptr; i++) {
        newEntries.objects[i] = entries.objects[i];
      }
      const newIndex = entries.length_intptr;
      newEntries.objects[newIndex] = target;
      newEntries.objects[newIndex + 1] = SmiConstant(1);
      vector.objects[index] = newEntries;
    }
  } else if (firstSlot == ic::kMegamorphicSymbol) {
    // The "ic::IsMegamorphic(firstSlot)" case doesn't need to do anything.
  } else {
    // Monomorphic miss.
    dcheck(
        Is<WasmFuncRef>(firstSlot) || Is<Smi>(firstSlot) ||
        firstSlot == WasmCrossInstanceCallSymbolConstant());
    const newEntries = UnsafeCast<FixedArray>(AllocateFixedArray(
        ElementsKind::PACKED_ELEMENTS, 4, AllocationFlag::kNone));
    newEntries.objects[0] = firstSlot;
    newEntries.objects[1] = secondSlot;
    newEntries.objects[2] = target;
    newEntries.objects[3] = SmiConstant(1);
    vector.objects[index] = newEntries;
    // Clear the first entry's counter; the specific value we write doesn't
    // matter.
    vector.objects[index + 1] = Undefined;
  }
}

// This is the return type of "CallRefIC" and "CallIndirectIC". The type is not
// used anywhere else; Liftoff uses the two returned values directly.
struct TargetAndImplicitArg {
  target: WasmCodePointer;
  implicit_arg: WasmTrustedInstanceData|WasmImportData;
}

builtin CallRefIC(
    vector: FixedArray, vectorIndex: int32, signatureHash: uintptr,
    funcref: WasmFuncRef): TargetAndImplicitArg {
  dcheck(Is<WasmFuncRef>(funcref));
  UpdateCallRefOrIndirectIC(vector, Convert<intptr>(vectorIndex), funcref);

  const internal = funcref.internal;
  @if(V8_ENABLE_SANDBOX) {
    if (signatureHash != internal.signature_hash) deferred {
        SignatureCheckFail(internal, signatureHash);
      }
  }
  @ifnot(V8_ENABLE_SANDBOX) {
    dcheck(signatureHash == 0);  // Avoids "unused variable" warning.
  }
  return TargetAndImplicitArg{
    target: internal.call_target,
    implicit_arg: internal.implicit_arg
  };
}

builtin CallIndirectIC(
    vector: FixedArray, vectorIndex: int32, target: WasmCodePointer,
    implicitArg: WasmTrustedInstanceData|WasmImportData): TargetAndImplicitArg {
  // If this is a cross-instance call, don't track the precise target (we can
  // only correctly inline same-instance calls anyway). Instead mark it as such,
  // so that we can prevent a deopt loop, see `TransitiveTypeFeedbackProcessor`.
  const instance = LoadInstanceDataFromFrame();
  const truncatedTargetOrCrossInstance = TaggedEqual(implicitArg, instance) ?
      SmiTag(Signed(Convert<uintptr>(target) & kSmiMaxValue)) :
      WasmCrossInstanceCallSymbolConstant();
  UpdateCallRefOrIndirectIC(
      vector, Convert<intptr>(vectorIndex), truncatedTargetOrCrossInstance);

  return TargetAndImplicitArg{target: target, implicit_arg: implicitArg};
}

extern macro TryHasOwnProperty(HeapObject, Map, InstanceType, Name): never
    labels Found, NotFound, Bailout;
type OnNonExistent constexpr 'OnNonExistent';
const kReturnUndefined: constexpr OnNonExistent
    generates 'OnNonExistent::kReturnUndefined';
extern macro SmiConstant(constexpr OnNonExistent): Smi;
extern transitioning builtin GetPropertyWithReceiver(
    implicit context: Context)(JSAny, Name, JSAny, Smi): JSAny;

transitioning builtin WasmGetOwnProperty(
    implicit context: Context)(object: Object, uniqueName: Name): JSAny {
  try {
    const heapObject: HeapObject =
        TaggedToHeapObject(object) otherwise NotFound;
    const receiver: JSReceiver =
        Cast<JSReceiver>(heapObject) otherwise NotFound;
    try {
      TryHasOwnProperty(
          receiver, receiver.map, receiver.instanceType, uniqueName)
          otherwise Found, NotFound, NotFound;
    } label Found {
      tail GetPropertyWithReceiver(
          receiver, uniqueName, receiver, SmiConstant(kReturnUndefined));
    }
  } label NotFound deferred {
    return Undefined;
  }
}

// Trap builtins.

builtin WasmTrap(error: Smi): JSAny {
  tail runtime::ThrowWasmError(LoadContextFromWasmOrJsFrame(), error);
}

builtin ThrowWasmTrapUnreachable(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapUnreachable));
}

builtin WasmTrapHandlerThrowTrap(): JSAny {
  tail runtime::TrapHandlerThrowWasmError(LoadContextFromWasmOrJsFrame());
}

builtin WasmPropagateException(): JSAny {
  tail runtime::PropagateException(kNoContext);
}

builtin ThrowWasmTrapMemOutOfBounds(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapMemOutOfBounds));
}

builtin ThrowWasmTrapUnalignedAccess(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapUnalignedAccess));
}

builtin ThrowWasmTrapDivByZero(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapDivByZero));
}

builtin ThrowWasmTrapDivUnrepresentable(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapDivUnrepresentable));
}

builtin ThrowWasmTrapRemByZero(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapRemByZero));
}

builtin ThrowWasmTrapFloatUnrepresentable(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapFloatUnrepresentable));
}

builtin ThrowWasmTrapFuncSigMismatch(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapFuncSigMismatch));
}

builtin ThrowWasmTrapDataSegmentOutOfBounds(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapDataSegmentOutOfBounds));
}

builtin ThrowWasmTrapElementSegmentOutOfBounds(): JSAny {
  tail WasmTrap(
      SmiConstant(MessageTemplate::kWasmTrapElementSegmentOutOfBounds));
}

builtin ThrowWasmTrapTableOutOfBounds(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapTableOutOfBounds));
}

builtin ThrowWasmTrapRethrowNull(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapRethrowNull));
}

builtin ThrowWasmTrapNullDereference(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapNullDereference));
}

builtin ThrowWasmTrapIllegalCast(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapIllegalCast));
}

builtin ThrowWasmTrapArrayOutOfBounds(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapArrayOutOfBounds));
}

builtin ThrowWasmTrapArrayTooLarge(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapArrayTooLarge));
}

builtin ThrowWasmTrapStringOffsetOutOfBounds(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapStringOffsetOutOfBounds));
}

macro GetRefAt<T: type, From: type>(base: From, offset: intptr): &T {
  return torque_internal::unsafe::NewOffHeapReference<T>(
      %RawDownCast<RawPtr<T>>(base + offset));
}

extern macro LoadPointerFromRootRegister(intptr): RawPtr;

const kThreadInWasmFlagAddressOffset: constexpr intptr
    generates 'Isolate::thread_in_wasm_flag_address_offset()';

const kActiveSuspenderOffset: constexpr intptr
    generates 'IsolateData::root_slot_offset(RootIndex::kActiveSuspender)';

macro ModifyThreadInWasmFlag(newValue: int32): void {
  const threadInWasmFlagAddress =
      LoadPointerFromRootRegister(kThreadInWasmFlagAddressOffset);
  const threadInWasmFlagRef = GetRefAt<int32>(threadInWasmFlagAddress, 0);
  *threadInWasmFlagRef = newValue;
}

builtin WasmStringNewWtf8(
    offset: uintptr, size: uint32, memory: uint32, utf8Variant: Smi): String
    |WasmNull {
  const trustedData = LoadInstanceDataFromFrame();
  tail runtime::WasmStringNewWtf8(
      LoadContextFromInstanceData(trustedData), trustedData,
      SmiFromUint32(memory), utf8Variant, UintPtrToNumberRounding(offset),
      WasmUint32ToNumber(size));
}
builtin WasmStringNewWtf8Array(
    start: uint32, end: uint32, array: WasmArray, utf8Variant: Smi): String
    |WasmNull {
  // This can be called from Wasm and from "JS String Builtins".
  const context = LoadContextFromWasmOrJsFrame();
  try {
    if (array.length < end) goto OffsetOutOfRange;
    if (end < start) goto OffsetOutOfRange;
    tail runtime::WasmStringNewWtf8Array(
        context, utf8Variant, array, SmiFromUint32(start), SmiFromUint32(end));
  } label OffsetOutOfRange deferred {
    const error = MessageTemplate::kWasmTrapArrayOutOfBounds;
    runtime::ThrowWasmError(context, SmiConstant(error));
  }
}
builtin WasmStringNewWtf16(memory: uint32, offset: uintptr, size: uint32):
    String {
  const trustedData = LoadInstanceDataFromFrame();
  tail runtime::WasmStringNewWtf16(
      LoadContextFromInstanceData(trustedData), trustedData,
      SmiFromUint32(memory), UintPtrToNumberRounding(offset),
      WasmUint32ToNumber(size));
}

struct TwoByteToOneByteIterator {
  macro Next(): char8 labels NoMore {
    if (this.start == this.end) goto NoMore;
    const raw: char16 = *torque_internal::unsafe::NewReference<char16>(
        this.object, this.start);
    const result: char8 = %RawDownCast<char8>(raw & 0xFF);
    this.start += 2;
    return result;
  }

  object: HeapObject|TaggedZeroPattern;
  start: intptr;
  end: intptr;
}

macro StringFromTwoByteSlice(length: uint32, slice: ConstSlice<char16>):
    String {
  // Ideas for additional future improvements:
  // (1) We could add a fast path for very short strings, e.g. <= 8 chars,
  //     and just allocate two-byte strings for them. That would save time
  //     here, and would only waste a couple of bytes at most. A concern is
  //     that such strings couldn't take one-byte fast paths later on, e.g.
  //     in toLower/toUpper case conversions.
  // (2) We could load more than one array element at a time, e.g. using
  //     intptr-wide loads, or possibly even wider SIMD instructions. We'd
  //     have to make sure that non-aligned start offsets are handled,
  //     and the implementation would become more platform-specific.
  // (3) We could shift the problem around by allocating two-byte strings
  //     here and checking whether they're one-byte-compatible later, e.g.
  //     when promoting them from new to old space. Drawback: rewriting
  //     strings to different maps isn't great for optimized code that's
  //     based on collected type feedback, or that wants to elide duplicate
  //     map checks within the function.
  // (4) We could allocate space for a two-byte string, then optimistically
  //     start writing one-byte characters into it, and then either restart
  //     in two-byte mode if needed, or return the over-allocated bytes to
  //     the allocator in the end.
  // (5) We could standardize a `string.new_ascii_array` instruction, which
  //     could safely produce one-byte strings without checking characters.
  //     See https://github.com/WebAssembly/stringref/issues/53.

  try {
    // To reduce the amount of branching, check 8 code units at a time. The
    // tradeoff for choosing 8 is that we want to check for early termination
    // of the loop often (to avoid unnecessary work) but not too often
    // (because each check has a cost).
    let i: intptr = 0;
    const intptrLength = slice.length;
    const eightElementLoopEnd = intptrLength - 8;
    while (i <= eightElementLoopEnd) {
      const bits = Convert<uint32>(*slice.UncheckedAtIndex(i)) |
          Convert<uint32>(*slice.UncheckedAtIndex(i + 1)) |
          Convert<uint32>(*slice.UncheckedAtIndex(i + 2)) |
          Convert<uint32>(*slice.UncheckedAtIndex(i + 3)) |
          Convert<uint32>(*slice.UncheckedAtIndex(i + 4)) |
          Convert<uint32>(*slice.UncheckedAtIndex(i + 5)) |
          Convert<uint32>(*slice.UncheckedAtIndex(i + 6)) |
          Convert<uint32>(*slice.UncheckedAtIndex(i + 7));
      if (bits > 0xFF) goto TwoByte;
      i += 8;
    }
    let bits: uint32 = 0;
    while (i < intptrLength) {
      bits |= Convert<uint32>(*slice.UncheckedAtIndex(i));
      i += 1;
    }
    if (bits > 0xFF) goto TwoByte;
  } label TwoByte {
    return AllocateSeqTwoByteString(length, slice.Iterator());
  }

  const end = slice.offset + torque_internal::TimesSizeOf<char16>(slice.length);
  return AllocateNonEmptySeqOneByteString(length, TwoByteToOneByteIterator{
    object: slice.object,
    start: slice.offset,
    end: end
  });
}

builtin WasmStringNewWtf16Array(array: WasmArray, start: uint32, end: uint32):
    String {
  try {
    if (array.length < end) goto OffsetOutOfRange;
    if (end < start) goto OffsetOutOfRange;
    const length: uint32 = end - start;
    if (length == 0) return kEmptyString;
    if (length == 1) {
      const offset = kWasmArrayHeaderSize +
          torque_internal::TimesSizeOf<char16>(Convert<intptr>(start));
      const code: char16 = *torque_internal::unsafe::NewReference<char16>(
          array, offset);
      // This makes sure we check the SingleCharacterStringTable.
      return StringFromSingleCharCode(code);
    }
    // Calling into the runtime has overhead, but once we're there it's faster,
    // so it pays off for long strings. The threshold has been determined
    // experimentally.
    if (length >= 32) goto Runtime;
    const intptrLength = Convert<intptr>(length);
    const arrayContent = torque_internal::unsafe::NewConstSlice<char16>(
        array, kWasmArrayHeaderSize, Convert<intptr>(array.length));
    const substring =
        Subslice(arrayContent, Convert<intptr>(start), intptrLength)
        otherwise goto OffsetOutOfRange;

    return StringFromTwoByteSlice(length, substring);
  } label OffsetOutOfRange deferred {
    // This can be called from Wasm and from "JS String Builtins".
    const context = LoadContextFromWasmOrJsFrame();
    const error = MessageTemplate::kWasmTrapArrayOutOfBounds;
    runtime::ThrowWasmError(context, SmiConstant(error));
  } label Runtime deferred {
    const context = LoadContextFromWasmOrJsFrame();
    tail runtime::WasmStringNewWtf16Array(
        context, array, SmiFromUint32(start), SmiFromUint32(end));
  }
}

// For imports based string constants.
// Always returns a String or WasmNull if it didn't trap; typed "JSAny" to
// satisfy Torque's type checker for tail calls.
builtin WasmStringFromDataSegment(
    segmentLength: uint32, arrayStart: uint32, arrayEnd: uint32,
    segmentIndex: Smi, segmentOffset: Smi, variant: Smi): JSAny|WasmNull {
  const trustedData = LoadInstanceDataFromFrame();
  try {
    const segmentOffsetU: uint32 = Unsigned(SmiToInt32(segmentOffset));
    if (segmentLength > Convert<uint32>(kSmiMax) - segmentOffsetU) {
      goto SegmentOOB;
    }
    if (arrayStart > segmentLength) goto ArrayOutOfBounds;
    if (arrayEnd < arrayStart) goto ArrayOutOfBounds;
    const arrayLength = arrayEnd - arrayStart;
    if (arrayLength > segmentLength - arrayStart) goto ArrayOutOfBounds;
    const smiOffset = Convert<PositiveSmi>(segmentOffsetU + arrayStart)
        otherwise SegmentOOB;
    const smiLength = Convert<PositiveSmi>(arrayLength) otherwise SegmentOOB;
    tail runtime::WasmStringNewSegmentWtf8(
        LoadContextFromInstanceData(trustedData), trustedData, segmentIndex,
        smiOffset, smiLength, variant);
  } label SegmentOOB deferred {
    tail ThrowWasmTrapElementSegmentOutOfBounds();
  } label ArrayOutOfBounds deferred {
    tail ThrowWasmTrapArrayOutOfBounds();
  }
}

// Contract: input is any string, output is a string that the TF operator
// "StringPrepareForGetCodeunit" can handle.
builtin WasmStringAsWtf16(str: String): String {
  const cons = Cast<ConsString>(str) otherwise return str;
  return Flatten(cons);
}

builtin WasmStringConst(index: uint32): String {
  const trustedData = LoadInstanceDataFromFrame();
  tail runtime::WasmStringConst(
      LoadContextFromInstanceData(trustedData), trustedData,
      SmiFromUint32(index));
}
builtin WasmStringMeasureUtf8(string: String): int32 {
  const result = runtime::WasmStringMeasureUtf8(LoadContextFromFrame(), string);
  return NumberToInt32(result);
}
builtin WasmStringMeasureWtf8(string: String): int32 {
  const result = runtime::WasmStringMeasureWtf8(LoadContextFromFrame(), string);
  return NumberToInt32(result);
}
builtin WasmStringEncodeWtf8(
    offset: uintptr, memory: uint32, utf8Variant: uint32,
    string: String): uint32 {
  const trustedData = LoadInstanceDataFromFrame();
  const result = runtime::WasmStringEncodeWtf8(
      LoadContextFromInstanceData(trustedData), trustedData,
      SmiFromUint32(memory), SmiFromUint32(utf8Variant), string,
      UintPtrToNumberRounding(offset));
  return NumberToUint32(result);
}
builtin WasmStringEncodeWtf8Array(
    string: String, array: WasmArray, start: uint32, utf8Variant: Smi): uint32 {
  const trustedData = LoadInstanceDataFromFrame();
  const result = runtime::WasmStringEncodeWtf8Array(
      LoadContextFromInstanceData(trustedData), utf8Variant, string, array,
      WasmUint32ToNumber(start));
  return NumberToUint32(result);
}
builtin WasmStringToUtf8Array(string: String): WasmArray {
  return runtime::WasmStringToUtf8Array(LoadContextFromFrame(), string);
}
builtin WasmStringEncodeWtf16(string: String, offset: uintptr, memory: uint32):
    uint32 {
  const trustedData = LoadInstanceDataFromFrame();
  runtime::WasmStringEncodeWtf16(
      LoadContextFromInstanceData(trustedData), trustedData,
      SmiFromUint32(memory), string, UintPtrToNumberRounding(offset),
      SmiConstant(0), SmiFromInt32(string.length));
  return Unsigned(string.length);
}
builtin WasmStringEncodeWtf16Array(
    string: String, array: WasmArray, start: uint32): uint32 {
  try {
    if (start > array.length) goto OffsetOutOfRange;
    if (array.length - start < Unsigned(string.length)) goto OffsetOutOfRange;

    const byteOffset: intptr = kWasmArrayHeaderSize +
        torque_internal::TimesSizeOf<char16>(Convert<intptr>(start));
    const arrayContent = torque_internal::unsafe::NewMutableSlice<char16>(
        array, byteOffset, string.length_intptr);
    try {
      StringToSlice(string) otherwise OneByte, TwoByte;
    } label OneByte(slice: ConstSlice<char8>) {
      let fromIt = slice.Iterator();
      let toIt = arrayContent.Iterator();
      while (true) {
        let toRef = toIt.NextReference() otherwise break;
        *toRef = %RawDownCast<char16>(Convert<uint16>(fromIt.NextNotEmpty()));
      }
    } label TwoByte(slice: ConstSlice<char16>) {
      let fromIt = slice.Iterator();
      let toIt = arrayContent.Iterator();
      while (true) {
        let toRef = toIt.NextReference() otherwise break;
        *toRef = fromIt.NextNotEmpty();
      }
    }
    return Unsigned(string.length);
  } label OffsetOutOfRange deferred {
    const error = MessageTemplate::kWasmTrapArrayOutOfBounds;
    runtime::ThrowWasmError(LoadContextFromWasmOrJsFrame(), SmiConstant(error));
  }
}

builtin ThrowToLowerCaseCalledOnNull(): JSAny {
  const context = LoadContextFromFrame();
  const error = MessageTemplate::kCalledOnNullOrUndefined;
  const name = StringConstant('String.prototype.toLowerCase');
  runtime::WasmThrowTypeError(context, SmiConstant(error), name);
}

builtin ThrowIndexOfCalledOnNull(): JSAny {
  const context = LoadContextFromFrame();
  const error = MessageTemplate::kCalledOnNullOrUndefined;
  const name = StringConstant('String.prototype.indexOf');
  runtime::WasmThrowTypeError(context, SmiConstant(error), name);
}

builtin ThrowDataViewTypeError(value: JSAny): JSAny {
  const context = LoadContextFromFrame();
  const error = MessageTemplate::kIncompatibleMethodReceiver;
  runtime::WasmThrowDataViewTypeError(context, SmiConstant(error), value);
}

builtin ThrowDataViewDetachedError(): JSAny {
  const context = LoadContextFromFrame();
  const error = MessageTemplate::kDetachedOperation;
  runtime::WasmThrowDataViewDetachedError(context, SmiConstant(error));
}

builtin ThrowDataViewOutOfBounds(): JSAny {
  const context = LoadContextFromFrame();
  const error = MessageTemplate::kInvalidDataViewAccessorOffset;
  runtime::WasmThrowRangeError(context, SmiConstant(error));
}

builtin WasmStringConcat(a: String, b: String): String {
  const context = LoadContextFromFrame();
  tail StringAdd_CheckNone(a, b);
}

extern builtin StringEqual(NoContext, String, String, intptr): Boolean;

builtin WasmStringEqual(a: String, b: String): int32 {
  if (TaggedEqual(a, b)) return 1;
  if (a.length != b.length) return 0;
  if (StringEqual(kNoContext, a, b, a.length_intptr) == True) {
    return 1;
  }
  return 0;
}

builtin WasmStringIsUSVSequence(str: String): int32 {
  if (IsOneByteStringMap(str.map)) return 1;
  const length = runtime::WasmStringMeasureUtf8(LoadContextFromFrame(), str);
  if (NumberToInt32(length) < 0) return 0;
  return 1;
}

builtin WasmStringAsWtf8(str: String): ByteArray {
  tail runtime::WasmStringAsWtf8(LoadContextFromFrame(), str);
}

macro IsWtf8CodepointStart(view: ByteArray, pos: uint32): bool {
  // We're already at the start of a codepoint if the current byte
  // doesn't start with 0b10xxxxxx.
  return (view.values[Convert<uintptr>(pos)] & 0xc0) != 0x80;
}
macro AlignWtf8PositionForward(view: ByteArray, pos: uint32): uint32 {
  const length = Unsigned(SmiToInt32(view.length));
  if (pos >= length) return length;

  if (IsWtf8CodepointStart(view, pos)) return pos;

  // Otherwise `pos` is part of a multibyte codepoint, and is not the
  // leading byte.  The next codepoint will start at pos + 1, pos + 2,
  // or pos + 3.
  if (pos + 1 == length) return length;
  if (IsWtf8CodepointStart(view, pos + 1)) return pos + 1;

  if (pos + 2 == length) return length;
  if (IsWtf8CodepointStart(view, pos + 2)) return pos + 2;

  return pos + 3;
}
macro AlignWtf8PositionBackward(view: ByteArray, pos: uint32): uint32 {
  // Return the highest offset that starts a codepoint which is not
  // greater than pos.  Preconditions: pos in [0, view.length), view
  // contains well-formed WTF-8.
  if (IsWtf8CodepointStart(view, pos)) return pos;
  if (IsWtf8CodepointStart(view, pos - 1)) return pos - 1;
  if (IsWtf8CodepointStart(view, pos - 2)) return pos - 2;
  return pos - 3;
}
builtin WasmStringViewWtf8Advance(view: ByteArray, pos: uint32, bytes: uint32):
    uint32 {
  const clampedPos = AlignWtf8PositionForward(view, pos);
  if (bytes == 0) return clampedPos;
  const length = Unsigned(SmiToInt32(view.length));
  if (bytes >= length - clampedPos) return length;
  return AlignWtf8PositionBackward(view, clampedPos + bytes);
}
struct NewPositionAndBytesWritten {
  newPosition: uint32;
  bytesWritten: uint32;
}
builtin WasmStringViewWtf8Encode(
    addr: uintptr, pos: uint32, bytes: uint32, view: ByteArray, memory: Smi,
    utf8Variant: Smi): NewPositionAndBytesWritten {
  const start = WasmStringViewWtf8Advance(view, pos, 0);
  const end = WasmStringViewWtf8Advance(view, start, bytes);
  const trustedData = LoadInstanceDataFromFrame();
  const context = LoadContextFromInstanceData(trustedData);

  // Always call out to run-time, to catch invalid addr.
  runtime::WasmStringViewWtf8Encode(
      context, trustedData, utf8Variant, view, UintPtrToNumberRounding(addr),
      WasmUint32ToNumber(start), WasmUint32ToNumber(end), memory);

  return NewPositionAndBytesWritten{
    newPosition: end,
    bytesWritten: end - start
  };
}
builtin WasmStringViewWtf8Slice(view: ByteArray, start: uint32, end: uint32):
    String {
  const start = WasmStringViewWtf8Advance(view, start, 0);
  const end = WasmStringViewWtf8Advance(view, end, 0);

  if (end <= start) return kEmptyString;

  tail runtime::WasmStringViewWtf8Slice(
      LoadContextFromFrame(), view, WasmUint32ToNumber(start),
      WasmUint32ToNumber(end));
}
transitioning builtin WasmStringViewWtf16GetCodeUnit(
    string: String, offset: uint32): uint32 {
  try {
    if (Unsigned(string.length) <= offset) goto OffsetOutOfRange;
    const code: char16 = StringCharCodeAt(string, Convert<uintptr>(offset));
    return Convert<uint32>(code);
  } label OffsetOutOfRange deferred {
    const error = MessageTemplate::kWasmTrapStringOffsetOutOfBounds;
    runtime::ThrowWasmError(LoadContextFromFrame(), SmiConstant(error));
  }
}
builtin WasmStringViewWtf16Encode(
    offset: uintptr, start: uint32, length: uint32, string: String,
    memory: Smi): uint32 {
  const trustedData = LoadInstanceDataFromFrame();
  const clampedStart =
      start < Unsigned(string.length) ? start : Unsigned(string.length);
  const maxLength = Unsigned(string.length) - clampedStart;
  const clampedLength = length < maxLength ? length : maxLength;
  runtime::WasmStringEncodeWtf16(
      LoadContextFromInstanceData(trustedData), trustedData, memory, string,
      UintPtrToNumberRounding(offset), SmiFromUint32(clampedStart),
      SmiFromUint32(clampedLength));
  return clampedLength;
}
transitioning builtin WasmStringViewWtf16Slice(
    string: String, start: uint32, end: uint32): String {
  const length = Unsigned(string.length);
  if (start >= length) return kEmptyString;
  if (end <= start) return kEmptyString;

  // On a high level, the intended logic is:
  // (1) If start == 0 && end == string.length, return string.
  // (2) If clampedLength == 1, use a cached single-character string.
  // (3) If clampedLength < SlicedString::kMinLength, make a copy.
  // (4) If clampedLength < string.length / 2, make a copy.
  // (5) Else, create a slice.
  // The reason for having case (4) is that case (5) has the risk of keeping
  // huge parent strings alive unnecessarily, and Wasm currently doesn't have a
  // way to control that behavior, so we have to be careful.
  // The reason for having case (5) is that case (4) would lead to quadratic
  // overall behavior if code repeatedly chops off a few characters of a long
  // string, which we want to avoid.
  // The string::SubString implementation can handle cases (1), (2), (3),
  // and (5). The inline code here handles case (4), and doesn't mind if it
  // also catches some of case (3).
  const clampedEnd = end <= length ? end : length;
  const clampedLength = clampedEnd - start;
  if (clampedLength > 1 && clampedLength < length / 2) {
    try {
      // Calling into the runtime has overhead, but once we're there it's
      // faster, so it pays off for long strings.
      if (clampedLength > 32) goto Runtime;
      StringToSlice(string) otherwise OneByte, TwoByte;
    } label OneByte(slice: ConstSlice<char8>) {
      let subslice = Subslice(
          slice, Convert<intptr>(start), Convert<intptr>(clampedLength))
          otherwise unreachable;
      return AllocateNonEmptySeqOneByteString(
          clampedLength, subslice.Iterator());
    } label TwoByte(slice: ConstSlice<char16>) {
      let subslice = Subslice(
          slice, Convert<intptr>(start), Convert<intptr>(clampedLength))
          otherwise unreachable;
      return StringFromTwoByteSlice(clampedLength, subslice);
    } label Runtime deferred {
      const context = LoadContextFromWasmOrJsFrame();
      tail runtime::WasmSubstring(
          context, string, SmiFromUint32(start), SmiFromUint32(clampedLength));
    }
  }
  return string::SubString(
      string, Convert<uintptr>(start), Convert<uintptr>(clampedEnd));
}
builtin WasmStringAsIter(string: String): WasmStringViewIter {
  return new WasmStringViewIter{string: string, offset: 0, optional_padding: 0};
}
macro IsLeadSurrogate(code: char16): bool {
  return (code & 0xfc00) == 0xd800;
}
macro IsTrailSurrogate(code: char16): bool {
  return (code & 0xfc00) == 0xdc00;
}
macro CombineSurrogatePair(lead: char16, trail: char16): int32 {
  const lead32 = Convert<uint32>(lead);
  const trail32 = Convert<uint32>(trail);
  // Surrogate pairs encode codepoints in the range
  // [0x010000, 0x10FFFF].  Each surrogate has 10 bits of information in
  // the low bits.  We can combine them together with a shift-and-add,
  // then add a bias of 0x010000 - 0xD800<<10 - 0xDC00 = 0xFCA02400.
  const surrogateBias: uint32 = 0xFCA02400;
  return Signed((lead32 << 10) + trail32 + surrogateBias);
}

builtin WasmStringCodePointAt(string: String, offset: uint32): uint32 {
  try {
    if (Unsigned(string.length) <= offset) goto OffsetOutOfRange;
    const lead: char16 = StringCharCodeAt(string, Convert<uintptr>(offset));
    if (!IsLeadSurrogate(lead)) return Convert<uint32>(lead);
    const trailOffset = offset + 1;
    if (Unsigned(string.length) <= trailOffset) return Convert<uint32>(lead);
    const trail: char16 =
        StringCharCodeAt(string, Convert<uintptr>(trailOffset));
    if (!IsTrailSurrogate(trail)) return Convert<uint32>(lead);
    return Unsigned(CombineSurrogatePair(lead, trail));
  } label OffsetOutOfRange deferred {
    const error = MessageTemplate::kWasmTrapStringOffsetOutOfBounds;
    runtime::ThrowWasmError(LoadContextFromFrame(), SmiConstant(error));
  }
}

builtin WasmStringViewIterNext(view: WasmStringViewIter): int32 {
  const string = view.string;
  const offset = view.offset;
  if (offset >= Unsigned(string.length)) return -1;
  const code: char16 = StringCharCodeAt(string, Convert<uintptr>(offset));
  try {
    if (IsLeadSurrogate(code) && offset + 1 < Unsigned(string.length)) {
      goto CheckForSurrogatePair;
    }
  } label CheckForSurrogatePair deferred {
    const code2: char16 =
        StringCharCodeAt(string, Convert<uintptr>(offset + 1));
    if (IsTrailSurrogate(code2)) {
      view.offset = offset + 2;
      return CombineSurrogatePair(code, code2);
    }
  }
  view.offset = offset + 1;
  return Signed(Convert<uint32>(code));
}
builtin WasmStringViewIterAdvance(
    view: WasmStringViewIter, codepoints: uint32): uint32 {
  const string = view.string;
  let offset = view.offset;
  let advanced: uint32 = 0;
  while (advanced < codepoints) {
    if (offset == Unsigned(string.length)) break;
    advanced = advanced + 1;
    if (offset + 1 < Unsigned(string.length) &&
        IsLeadSurrogate(StringCharCodeAt(string, Convert<uintptr>(offset))) &&
        IsTrailSurrogate(
            StringCharCodeAt(string, Convert<uintptr>(offset + 1)))) {
      offset = offset + 2;
    } else {
      offset = offset + 1;
    }
  }
  view.offset = offset;
  return advanced;
}
builtin WasmStringViewIterRewind(view: WasmStringViewIter, codepoints: uint32):
    uint32 {
  const string = view.string;
  let offset = view.offset;
  let rewound: uint32 = 0;
  if (string.length == 0) return 0;
  while (rewound < codepoints) {
    if (offset == 0) break;
    rewound = rewound + 1;
    if (offset >= 2 &&
        IsTrailSurrogate(
            StringCharCodeAt(string, Convert<uintptr>(offset - 1))) &&
        IsLeadSurrogate(
            StringCharCodeAt(string, Convert<uintptr>(offset - 2)))) {
      offset = offset - 2;
    } else {
      offset = offset - 1;
    }
  }
  view.offset = offset;
  return rewound;
}
builtin WasmStringViewIterSlice(view: WasmStringViewIter, codepoints: uint32):
    String {
  const string = view.string;
  const start = view.offset;
  let end = view.offset;
  let advanced: uint32 = 0;
  while (advanced < codepoints) {
    if (end == Unsigned(string.length)) break;
    advanced = advanced + 1;
    if (end + 1 < Unsigned(string.length) &&
        IsLeadSurrogate(StringCharCodeAt(string, Convert<uintptr>(end))) &&
        IsTrailSurrogate(StringCharCodeAt(string, Convert<uintptr>(end + 1)))) {
      end = end + 2;
    } else {
      end = end + 1;
    }
  }
  return (start == end) ?
      kEmptyString :
      string::SubString(string, Convert<uintptr>(start), Convert<uintptr>(end));
}

builtin WasmIntToString(x: int32, radix: int32): String {
  if (radix == 10) {
    const smi = SmiFromInt32(x);
    const untagged = SmiToInt32(smi);
    if (x == untagged) {
      // Queries and populates the NumberToStringCache, but needs tagged
      // inputs, so only call this for Smis.
      return NumberToString(smi);
    }
    return number::IntToDecimalString(x);
  }

  // Pretend that Number.prototype.toString was called.
  if (radix < 2 || radix > 36) {
    runtime::ThrowRangeError(
        LoadContextFromInstanceData(LoadInstanceDataFromFrame()),
        SmiConstant(MessageTemplate::kToRadixFormatRange));
  }
  return number::IntToString(x, Unsigned(radix));
}

builtin WasmStringToDouble(s: String): float64 {
  const hash: NameHash = s.raw_hash_field;
  if (IsIntegerIndex(hash) &&
      hash.array_index_length < kMaxCachedArrayIndexLength) {
    const arrayIndex: int32 = Signed(hash.array_index_value);
    return Convert<float64>(arrayIndex);
  }
  return StringToFloat64(Flatten(s));
}

builtin WasmStringFromCodePoint(codePoint: uint32): String {
  tail runtime::WasmStringFromCodePoint(
      LoadContextFromFrame(), WasmUint32ToNumber(codePoint));
}

builtin WasmStringHash(string: String): int32 {
  const result = runtime::WasmStringHash(kNoContext, string);
  return SmiToInt32(result);
}

builtin WasmAnyConvertExtern(externObject: JSAny): JSAny {
  const trustedData = LoadInstanceDataFromFrame();
  const context = LoadContextFromInstanceData(trustedData);

  tail runtime::WasmJSToWasmObject(
      context, externObject, SmiConstant(kAnyType));
}

extern macro CallOrConstructBuiltinsAssembler::GetCompatibleReceiver(
    JSReceiver, HeapObject, Context): JSReceiver;

builtin WasmFastApiCallTypeCheckAndUpdateIC(
    implicit context: Context)(data: WasmFastApiCallData,
    receiver: JSAny): Smi {
  try {
    const rec = Cast<JSReceiver>(receiver) otherwise goto IllegalCast;
    ModifyThreadInWasmFlag(0);
    // We don't care about the actual compatible receiver; we just rely
    // on this helper throwing an exception when there isn't one.
    GetCompatibleReceiver(rec, data.signature, context);
    ModifyThreadInWasmFlag(1);
    data.cached_map = StrongToWeak(rec.map);
    return 1;
  } label IllegalCast {
    const error = MessageTemplate::kIllegalInvocation;
    runtime::WasmThrowTypeError(context, SmiConstant(error), Convert<Smi>(0));
  }
}
}  // namespace wasm
```