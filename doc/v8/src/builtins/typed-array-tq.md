Response: Let's break down the thought process for analyzing this Torque code.

1. **Identify the Core Purpose:** The filename `typed-array.tq` and the namespace `typed_array` immediately suggest that this code deals with the implementation of JavaScript Typed Arrays within V8.

2. **Scan for Key Structures and Types:** Look for `struct`, `type`, and `macro` definitions. These define the fundamental building blocks and operations. The `ElementsKind` type and the various subtypes (like `Uint8Elements`, `Int32Elements`, etc.) are a strong indicator of handling different Typed Array types. The `TypedArrayElementsInfo` struct looks important for managing size and alignment. The `TypedArrayAccessor` struct seems to encapsulate read and write operations.

3. **Analyze `TypedArrayElementsInfo`:** This struct has `CalculateByteLength`, `CalculateLength`, and `IsUnaligned` macros. These directly relate to the core properties and operations of Typed Arrays – how much memory they use, how many elements they hold, and whether memory accesses are properly aligned. The `sizeLog2` and `kind` fields are the essential data for these calculations.

4. **Analyze `TypedArrayAccessor`:** This struct has `LoadNumeric`, `StoreNumeric`, and `StoreJSAny` macros. These are the fundamental operations of getting and setting values in a Typed Array. The `loadNumericFn`, `storeNumericFn`, and `storeJSAnyFn` members are function pointers (or their Torque equivalent), suggesting a dispatch mechanism for handling different element types.

5. **Trace the `GetTypedArrayAccessor` Macros:** There are two `GetTypedArrayAccessor` macros. The first one is generic, taking a type parameter. The second one takes an `ElementsKind`. This suggests a type-based dispatch or specialization. The logic within the second macro clearly maps `ElementsKind` values to specific `TypedArrayAccessor` instances. This is how V8 handles the type-specific behavior of different Typed Arrays (e.g., how a `Uint8Array` stores data versus an `Int32Array`).

6. **Examine `EnsureAttached` and Related Structures:** The `EnsureAttached` macro and the `AttachedJSTypedArray` type are about ensuring the underlying ArrayBuffer of a Typed Array is still valid (not detached). The `AttachedJSTypedArrayAndLength` and `AttachedJSTypedArrayWitness` structures appear to be optimizations or helper structures for working with attached Typed Arrays, potentially for performance reasons by avoiding repeated detachment checks. The `AttachedJSTypedArrayWitness` and its `RecheckIndex` macro hint at potential optimizations for repeated access within a loop.

7. **Identify External Functions and Macros:**  Pay attention to `extern` declarations. These are calls to C++ code or other Torque builtins. `TypedArrayCopyElements`, `ValidateTypedArray`, `CallCMemcpy`, `CallCMemmove`, `CallCMemset`, `GetTypedArrayBuffer`, `LoadFixedTypedArrayElementAsTagged`, and `StoreJSTypedArrayElementFromNumeric`/`StoreJSTypedArrayElementFromTagged` are all crucial interactions with V8's lower-level implementation.

8. **Connect to JavaScript Concepts:**  At this point, start connecting the dots to JavaScript. The various `ElementsKind` subtypes directly correspond to JavaScript Typed Array constructors (e.g., `Uint8Array`, `Int32Array`). The byte length and length calculations are used when creating Typed Arrays. The load and store operations correspond to accessing and modifying elements of a Typed Array using bracket notation or `set()` methods. Detachment and out-of-bounds errors are exceptions that can occur in JavaScript.

9. **Construct Examples:** Based on the identified functionalities, create JavaScript examples to illustrate them. For instance, the byte length calculation can be demonstrated by creating Typed Arrays of different lengths and inspecting their `byteLength` property. Detachment can be shown by detaching the underlying buffer. Out-of-bounds access will trigger errors.

10. **Infer Logic and Assumptions:** Analyze the code for conditional statements and potential assumptions. The `IsUnaligned` macro assumes that the element size is a power of 2, which is true for standard Typed Arrays. The `EnsureAttached` mechanism implies that Typed Arrays can be detached.

11. **Consider Common Errors:** Think about common mistakes developers make when working with Typed Arrays. Incorrectly calculating offsets, exceeding bounds, and trying to access a detached array are typical scenarios.

12. **Refine and Organize:**  Finally, organize the findings into a coherent summary, categorizing the functionality, linking it to JavaScript, providing examples, and highlighting potential pitfalls. This involves structuring the information logically and using clear language. The use of headings and bullet points makes the information easier to digest.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file is only about memory management for Typed Arrays.
* **Correction:**  The presence of `LoadNumeric` and `StoreNumeric` clearly indicates it's also about accessing and modifying elements, not just allocation.
* **Initial thought:** The `GetTypedArrayAccessor` macros seem overly complex.
* **Clarification:** Realizing that they are implementing type-specific behavior for different Typed Array types makes the complexity understandable.
* **Initial thought:** The `AttachedJSTypedArrayWitness` is confusing.
* **Refinement:** Understanding that it's likely an optimization to avoid repeated detachment checks clarifies its purpose.

By following this process of identification, analysis, connection, and refinement, we can effectively understand and summarize the functionality of complex code like the provided Torque source.
This Torque source file (`v8/src/builtins/typed-array.tq`) defines core functionalities and utilities for implementing JavaScript Typed Arrays within the V8 JavaScript engine. It provides the building blocks for various Typed Array operations and handles the specifics of different Typed Array types.

Here's a breakdown of its key functionalities:

**1. Defining Typed Array Element Kinds:**

- It defines various `type` aliases extending `ElementsKind`, representing different Typed Array element types: `Uint8Elements`, `Int8Elements`, `Uint16Elements`, `Int16Elements`, `Uint32Elements`, `Int32Elements`, `Float16Elements`, `Float32Elements`, `Float64Elements`, `Uint8ClampedElements`, `BigUint64Elements`, and `BigInt64Elements`.
- These types represent the underlying data type stored in the Typed Array (e.g., unsigned 8-bit integer, 32-bit floating-point number).

**2. `TypedArrayElementsInfo` Structure:**

- This structure holds information specific to a Typed Array's element type.
- **`CalculateByteLength(length: uintptr)`:**  Calculates the total byte length required for a Typed Array given the number of elements. It also checks for potential overflow (exceeding the maximum allowed byte length for an ArrayBuffer).
    - **JavaScript Example:** When you create a `Uint32Array` with a certain length, this macro is involved in determining how much memory to allocate for its underlying buffer.
    ```javascript
    const uint32Array = new Uint32Array(10); // length is 10
    console.log(uint32Array.byteLength); // Output: 40 (10 elements * 4 bytes per element)
    ```
    - **Assumption:**  Input `length` is a non-negative integer.
    - **IfInvalid:**  If `length` is too large, exceeding `kArrayBufferMaxByteLength >>> this.sizeLog2`, it jumps to the `IfInvalid` label (likely handling an error).
- **`CalculateLength(byteLength: uintptr)`:** Calculates the number of elements a Typed Array can hold given a byte length.
    - **JavaScript Example:**  You can create a Typed Array by providing a `byteLength`.
    ```javascript
    const uint16Array = new Uint16Array(16); // byteLength is 16 * 2 = 32
    const uint16ArrayFromBuffer = new Uint16Array(uint16Array.buffer);
    console.log(uint16ArrayFromBuffer.length); // Output: 16
    ```
    - **Assumption:** Input `byteLength` is a non-negative integer.
- **`IsUnaligned(bytes: uintptr)`:** Checks if a given byte offset or length is not a multiple of the element size. This is important for ensuring efficient memory access.
    - **JavaScript Relevance:** While JavaScript doesn't directly expose alignment issues to developers, V8 needs to handle them internally for performance. Unaligned access can be slower on some architectures.
    - **Assumption:**  Input `bytes` is a non-negative integer.
    - **Example:** If you have a `Uint32Array` (4 bytes per element), `IsUnaligned(5)` would be true, while `IsUnaligned(8)` would be false.
- **`sizeLog2: uintptr`:** Stores the base-2 logarithm of the element size (e.g., 3 for `Float64Array` because 2^3 = 8 bytes).
- **`kind: ElementsKind`:** Stores the specific `ElementsKind` of the Typed Array.

**3. External Runtime Functions and Macros:**

- It declares several external functions and macros that are implemented in C++ or other Torque files. These handle low-level operations:
    - `TypedArrayCopyElements`: Copies elements between Typed Arrays or from other array-like objects.
    - `ValidateTypedArray`: Ensures an object is a valid Typed Array.
    - `ValidateTypedArrayAndGetLength`: Validates a Typed Array and retrieves its length.
    - `CallCMemcpy`, `CallCMemmove`, `CallCMemset`, `CallCRelaxedMemcpy`, `CallCRelaxedMemmove`:  Wrappers for C memory manipulation functions (copy, move, set).
    - `GetTypedArrayBuffer`: Retrieves the underlying `ArrayBuffer` of a Typed Array.
    - `GetTypedArrayElementsInfo`: Retrieves the `TypedArrayElementsInfo` for a given Typed Array or its Map (internal representation).
    - `IsUint8ElementsKind`, `IsBigInt64ElementsKind`: Checks the element kind.
    - `LoadFixedTypedArrayElementAsTagged`: Loads an element from a Typed Array's raw memory as a tagged value (V8's internal representation).
    - `StoreJSTypedArrayElementFromNumeric`, `StoreJSTypedArrayElementFromTagged`: Stores a numeric or tagged value into a Typed Array's raw memory.
    - `LoadJSTypedArrayLengthAndCheckDetached`: Loads the length of a Typed Array and checks if its underlying buffer is detached.

**4. `TypedArrayAccessor` Structure:**

- This structure provides a way to access and manipulate elements of a Typed Array in a type-agnostic manner.
- **`LoadNumeric(array: JSTypedArray, index: uintptr)`:** Loads a numeric value from the Typed Array at the given index.
- **`StoreNumeric(context: Context, array: JSTypedArray, index: uintptr, value: Numeric)`:** Stores a numeric value into the Typed Array at the given index.
- **`StoreJSAnyInBounds(context: Context, array: JSTypedArray, index: uintptr, value: JSAny)`:** Stores a JavaScript value (which might need conversion) into the Typed Array at the given index, assuming the index is within bounds.
- **`StoreJSAny(context: Context, array: JSTypedArray, index: uintptr, value: JSAny)`:** Stores a JavaScript value into the Typed Array, handling potential detachment or out-of-bounds errors gracefully (as a no-op according to the specification).
- **`loadNumericFn: LoadNumericFn`, `storeNumericFn: StoreNumericFn`, `storeJSAnyFn: StoreJSAnyFn`:** These are function pointers (or their Torque equivalents) that point to the specific load and store implementations for the Typed Array's element type.

**5. `GetTypedArrayAccessor` Macros:**

- These macros are responsible for retrieving the correct `TypedArrayAccessor` based on the `ElementsKind` of the Typed Array. This is crucial for handling the type-specific logic of different Typed Arrays.
- It uses conditional logic to select the appropriate accessor based on the `elementsKind`.

**6. Detachment Handling:**

- **`EnsureAttached(array: JSTypedArray)`:** This macro checks if the underlying `ArrayBuffer` of a Typed Array is detached. If it is, it jumps to the `DetachedOrOutOfBounds` label (likely throwing an error).
    - **JavaScript Example:**
    ```javascript
    const buffer = new ArrayBuffer(16);
    const uint8Array = new Uint8Array(buffer);
    buffer.detach();
    // Accessing uint8Array now will throw a TypeError
    try {
      uint8Array[0];
    } catch (e) {
      console.error(e); // TypeError: Cannot perform %TypedArrayPrototype%.get on a detached ArrayBuffer
    }
    ```
- **`AttachedJSTypedArray`:** A type alias representing a Typed Array whose buffer is guaranteed to be attached (at the point of use).
- **`AttachedJSTypedArrayAndLength`:** A structure holding an attached Typed Array and its length.
- **`EnsureAttachedAndReadLength`:** Combines the detachment check and length retrieval.
- **`AttachedJSTypedArrayWitness`:** A structure used for optimized access to attached Typed Arrays, potentially to avoid redundant detachment checks in loops.

**7. Type-Specific Load and Store Builtins:**

- `LoadTypedElement<T : type extends ElementsKind>(...)`:  A generic builtin that loads an element from a Typed Array based on its element type `T`.
- `StoreTypedElementNumeric<T : type extends ElementsKind>(...)`: A generic builtin to store a numeric value into a Typed Array.
- `StoreTypedElementJSAny<T : type extends ElementsKind>(...)`: A generic builtin to store a JavaScript value into a Typed Array, handling potential detachment.

**Common Programming Errors Related to Typed Arrays (and potentially handled by this code):**

- **Accessing Detached Buffers:**  Trying to read or write to a Typed Array whose underlying `ArrayBuffer` has been detached. The `EnsureAttached` macro and related mechanisms are designed to prevent this.
    ```javascript
    const buffer = new ArrayBuffer(8);
    const uint8Array = new Uint8Array(buffer);
    buffer.detach();
    // Error: Cannot perform %TypedArrayPrototype%.get on a detached ArrayBuffer
    uint8Array[0] = 10;
    ```
- **Out-of-Bounds Access:** Attempting to access an element at an index that is outside the bounds of the Typed Array. While not explicitly shown in this snippet, V8's Typed Array implementation relies on checks that are likely built upon these core functionalities.
    ```javascript
    const int16Array = new Int16Array(5); // length is 5, valid indices are 0-4
    // Error (or undefined behavior if bounds checking is not strict in a particular context):
    int16Array[10] = 100;
    ```
- **Incorrectly Calculating Offsets/Lengths:** Providing incorrect byte offsets or lengths when creating or manipulating Typed Arrays, leading to unexpected behavior or errors. The `CalculateByteLength` and `CalculateLength` macros help ensure these calculations are correct internally.
    ```javascript
    const buffer = new ArrayBuffer(10);
    // Error: Offset is outside the bounds of the DataView's buffer.
    const dataView = new DataView(buffer, 10);
    ```
- **Type Mismatches (Less directly related to this file, but important for Typed Arrays in general):** Trying to store a value of an incompatible type into a Typed Array (e.g., storing a string into an `Int32Array`). While this file deals with the low-level storage, higher-level builtins would handle the type coercion or error reporting.

**Hypothetical Input and Output for `CalculateByteLength`:**

**Assumption:** `this.sizeLog2` is 2 (meaning element size is 4 bytes, like for `Uint32Array`).

**Input:** `length = 5`

**Logic:**
1. `maxArrayLength = kArrayBufferMaxByteLength >>> 2` (Right bit shift by 2, effectively dividing by 4). Let's assume `kArrayBufferMaxByteLength` is a large number like `2^30`. Then `maxArrayLength` would be `2^28`.
2. `5 > 2^28` would be false.
3. `byteLength = 5 << 2` (Left bit shift by 2, effectively multiplying by 4).
4. `byteLength = 20`

**Output:** `20`

**Hypothetical Input and Output for `IsUnaligned`:**

**Assumption:** `this.sizeLog2` is 2 (element size is 4 bytes).

**Input:** `bytes = 6`

**Logic:**
1. `(1 << 2) - 1` evaluates to `4 - 1 = 3`.
2. `bytes & 3` is `6 & 3`, which is `0b110 & 0b011 = 0b010 = 2`.
3. `2 != 0` is true.

**Output:** `true` (because 6 is not a multiple of 4).

In summary, this Torque file lays the foundational groundwork for the efficient and correct implementation of JavaScript Typed Arrays in V8. It defines the different element types, provides utilities for calculating sizes and checking alignment, and sets up the mechanisms for accessing and manipulating the underlying memory, while also addressing potential issues like detached buffers.

### 提示词
```
这是目录为v8/src/builtins/typed-array.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include 'src/builtins/builtins-typed-array-gen.h'

namespace typed_array {
// Naming convention from elements.cc. We have a similar intent but implement
// fastpaths using generics instead of using a class hierarchy for elements
// kinds specific implementations.
type Uint8Elements extends ElementsKind;
type Int8Elements extends ElementsKind;
type Uint16Elements extends ElementsKind;
type Int16Elements extends ElementsKind;
type Uint32Elements extends ElementsKind;
type Int32Elements extends ElementsKind;
type Float16Elements extends ElementsKind;
type Float32Elements extends ElementsKind;
type Float64Elements extends ElementsKind;
type Uint8ClampedElements extends ElementsKind;
type BigUint64Elements extends ElementsKind;
type BigInt64Elements extends ElementsKind;
type RabGsabUint8Elements extends ElementsKind;

@export
struct TypedArrayElementsInfo {
  // Calculates the number of bytes required for specified number of elements.
  macro CalculateByteLength(length: uintptr): uintptr labels IfInvalid {
    const maxArrayLength = kArrayBufferMaxByteLength >>> this.sizeLog2;
    if (length > maxArrayLength) goto IfInvalid;
    const byteLength = length << this.sizeLog2;
    return byteLength;
  }

  // Calculates the maximum number of elements supported by a specified number
  // of bytes.
  macro CalculateLength(byteLength: uintptr): uintptr {
    return byteLength >>> this.sizeLog2;
  }

  // Determines if `bytes` (byte offset or length) cannot be evenly divided by
  // element size.
  macro IsUnaligned(bytes: uintptr): bool {
    // Exploits the fact the element size is a power of 2. Determining whether
    // there is remainder (not aligned) can be achieved efficiently with bit
    // masking. Shift is safe as sizeLog2 can be 3 at most (see
    // ElementsKindToShiftSize).
    return (bytes & ((1 << this.sizeLog2) - 1)) != 0;
  }

  sizeLog2: uintptr;
  kind: ElementsKind;
}
extern runtime TypedArrayCopyElements(Context, JSTypedArray, Object, Number):
    void;
extern macro TypedArrayBuiltinsAssembler::ValidateTypedArray(
    Context, JSAny, constexpr string): JSTypedArray;
extern macro TypedArrayBuiltinsAssembler::ValidateTypedArrayAndGetLength(
    Context, JSAny, constexpr string): uintptr;

extern macro TypedArrayBuiltinsAssembler::CallCMemcpy(RawPtr, RawPtr, uintptr):
    void;
extern macro TypedArrayBuiltinsAssembler::CallCMemmove(
    RawPtr, RawPtr, uintptr): void;
extern macro TypedArrayBuiltinsAssembler::CallCMemset(RawPtr, intptr, uintptr):
    void;
extern macro TypedArrayBuiltinsAssembler::CallCRelaxedMemcpy(
    RawPtr, RawPtr, uintptr): void;
extern macro TypedArrayBuiltinsAssembler::CallCRelaxedMemmove(
    RawPtr, RawPtr, uintptr): void;
extern macro GetTypedArrayBuffer(implicit context: Context)(JSTypedArray):
    JSArrayBuffer;
extern macro TypedArrayBuiltinsAssembler::GetTypedArrayElementsInfo(
    JSTypedArray): TypedArrayElementsInfo;
extern macro TypedArrayBuiltinsAssembler::GetTypedArrayElementsInfo(Map):
    TypedArrayElementsInfo;
extern macro TypedArrayBuiltinsAssembler::IsUint8ElementsKind(ElementsKind):
    bool;
extern macro TypedArrayBuiltinsAssembler::IsBigInt64ElementsKind(ElementsKind):
    bool;
extern macro LoadFixedTypedArrayElementAsTagged(
    RawPtr, uintptr, constexpr ElementsKind): Numeric;
extern macro TypedArrayBuiltinsAssembler::StoreJSTypedArrayElementFromNumeric(
    Context, JSTypedArray, uintptr, Numeric, constexpr ElementsKind): void;
extern macro TypedArrayBuiltinsAssembler::StoreJSTypedArrayElementFromTagged(
    Context, JSTypedArray, uintptr, JSAny,
    constexpr ElementsKind): void labels IfDetached;

extern macro LoadJSTypedArrayLengthAndCheckDetached(JSTypedArray): uintptr
    labels IfDetached;

type LoadNumericFn = builtin(JSTypedArray, uintptr) => Numeric;
type StoreNumericFn = builtin(Context, JSTypedArray, uintptr, Numeric) => Smi;
type StoreJSAnyFn = builtin(Context, JSTypedArray, uintptr, JSAny) => Smi;

// The result codes returned by StoreNumericFn and StoreJSAnyFn builtins.
const kStoreSucceded: Smi = 0;
const kStoreFailureArrayDetachedOrOutOfBounds: Smi = 1;

struct TypedArrayAccessor {
  macro LoadNumeric(array: JSTypedArray, index: uintptr): Numeric {
    const loadfn: LoadNumericFn = this.loadNumericFn;
    return loadfn(array, index);
  }

  macro StoreNumeric(
      context: Context, array: JSTypedArray, index: uintptr,
      value: Numeric): void {
    const storefn: StoreNumericFn = this.storeNumericFn;
    const result = storefn(context, array, index, value);
    dcheck(result == kStoreSucceded);
  }

  macro StoreJSAnyInBounds(
      context: Context, array: JSTypedArray, index: uintptr,
      value: JSAny): void {
    const storefn: StoreJSAnyFn = this.storeJSAnyFn;
    const result = storefn(context, array, index, value);
    check(result == kStoreSucceded);
  }

  macro StoreJSAny(
      context: Context, array: JSTypedArray, index: uintptr,
      value: JSAny): void {
    const storefn: StoreJSAnyFn = this.storeJSAnyFn;
    const result = storefn(context, array, index, value);
    // ES#sec-typedarray-set
    //
    // A [[Set]] on a TypedArray with a detached or out-of-bounds
    // underlying ArrayBuffer is a no-op.
    dcheck(
        result == kStoreSucceded ||
        result == kStoreFailureArrayDetachedOrOutOfBounds);
  }

  loadNumericFn: LoadNumericFn;
  storeNumericFn: StoreNumericFn;
  storeJSAnyFn: StoreJSAnyFn;
}

macro GetTypedArrayAccessor<T : type extends ElementsKind>():
    TypedArrayAccessor {
  const loadNumericFn = LoadTypedElement<T>;
  const storeNumericFn = StoreTypedElementNumeric<T>;
  const storeJSAnyFn = StoreTypedElementJSAny<T>;
  return TypedArrayAccessor{loadNumericFn, storeNumericFn, storeJSAnyFn};
}

macro GetTypedArrayAccessor(elementsKindParam: ElementsKind):
    TypedArrayAccessor {
  let elementsKind = elementsKindParam;
  if (IsElementsKindGreaterThanOrEqual(
          elementsKind, kFirstRabGsabFixedTypedArrayElementsKind)) {
    elementsKind = %RawDownCast<ElementsKind>(
        elementsKind - kFirstRabGsabFixedTypedArrayElementsKind +
        kFirstFixedTypedArrayElementsKind);
  }
  if (IsElementsKindGreaterThan(elementsKind, ElementsKind::UINT32_ELEMENTS)) {
    if (elementsKind == ElementsKind::INT32_ELEMENTS) {
      return GetTypedArrayAccessor<Int32Elements>();
    } else if (elementsKind == ElementsKind::FLOAT16_ELEMENTS) {
      return GetTypedArrayAccessor<Float16Elements>();
    } else if (elementsKind == ElementsKind::FLOAT32_ELEMENTS) {
      return GetTypedArrayAccessor<Float32Elements>();
    } else if (elementsKind == ElementsKind::FLOAT64_ELEMENTS) {
      return GetTypedArrayAccessor<Float64Elements>();
    } else if (elementsKind == ElementsKind::UINT8_CLAMPED_ELEMENTS) {
      return GetTypedArrayAccessor<Uint8ClampedElements>();
    } else if (elementsKind == ElementsKind::BIGUINT64_ELEMENTS) {
      return GetTypedArrayAccessor<BigUint64Elements>();
    } else if (elementsKind == ElementsKind::BIGINT64_ELEMENTS) {
      return GetTypedArrayAccessor<BigInt64Elements>();
    }
  } else {
    if (elementsKind == ElementsKind::UINT8_ELEMENTS) {
      return GetTypedArrayAccessor<Uint8Elements>();
    } else if (elementsKind == ElementsKind::INT8_ELEMENTS) {
      return GetTypedArrayAccessor<Int8Elements>();
    } else if (elementsKind == ElementsKind::UINT16_ELEMENTS) {
      return GetTypedArrayAccessor<Uint16Elements>();
    } else if (elementsKind == ElementsKind::INT16_ELEMENTS) {
      return GetTypedArrayAccessor<Int16Elements>();
    } else if (elementsKind == ElementsKind::UINT32_ELEMENTS) {
      return GetTypedArrayAccessor<Uint32Elements>();
    }
  }
  unreachable;
}

extern macro TypedArrayBuiltinsAssembler::SetJSTypedArrayOnHeapDataPtr(
    JSTypedArray, ByteArray, uintptr): void;
extern macro TypedArrayBuiltinsAssembler::SetJSTypedArrayOffHeapDataPtr(
    JSTypedArray, RawPtr, uintptr): void;
extern macro IsJSArrayBufferViewDetachedOrOutOfBounds(JSArrayBufferView):
    never labels DetachedOrOutOfBounds, NotDetachedNorOutOfBounds;
extern macro IsJSArrayBufferViewDetachedOrOutOfBoundsBoolean(
    JSArrayBufferView): bool;

// AttachedJSTypedArray guards that the array's buffer is not detached.
transient type AttachedJSTypedArray extends JSTypedArray;

macro EnsureAttached(array: JSTypedArray): AttachedJSTypedArray
    labels DetachedOrOutOfBounds {
  try {
    IsJSArrayBufferViewDetachedOrOutOfBounds(array)
        otherwise DetachedOrOutOfBounds, NotDetachedNorOutOfBounds;
  } label NotDetachedNorOutOfBounds {
    return %RawDownCast<AttachedJSTypedArray>(array);
  }
}

struct AttachedJSTypedArrayAndLength {
  array: AttachedJSTypedArray;
  length: uintptr;
}

macro EnsureAttachedAndReadLength(array: JSTypedArray):
    AttachedJSTypedArrayAndLength
    labels DetachedOrOutOfBounds {
  const length = LoadJSTypedArrayLengthAndCheckDetached(array)
      otherwise DetachedOrOutOfBounds;
  return AttachedJSTypedArrayAndLength{
    array: %RawDownCast<AttachedJSTypedArray>(array),
    length: length
  };
}

struct AttachedJSTypedArrayWitness {
  macro GetStable(): JSTypedArray {
    return this.stable;
  }

  macro RecheckIndex(index: uintptr): void labels DetachedOrOutOfBounds {
    const length = LoadJSTypedArrayLengthAndCheckDetached(this.stable)
        otherwise DetachedOrOutOfBounds;
    if (index >= length) {
      goto DetachedOrOutOfBounds;
    }
    this.unstable = %RawDownCast<AttachedJSTypedArray>(this.stable);
  }

  macro Load(implicit context: Context)(k: uintptr): JSAny {
    const lf: LoadNumericFn = this.loadfn;
    return lf(this.unstable, k);
  }

  stable: JSTypedArray;
  unstable: AttachedJSTypedArray;
  loadfn: LoadNumericFn;
}

macro NewAttachedJSTypedArrayWitness(array: AttachedJSTypedArray):
    AttachedJSTypedArrayWitness {
  const kind = array.elements_kind;
  const accessor: TypedArrayAccessor = GetTypedArrayAccessor(kind);
  return AttachedJSTypedArrayWitness{
    stable: array,
    unstable: array,
    loadfn: accessor.loadNumericFn
  };
}

macro KindForArrayType<T : type extends ElementsKind>():
    constexpr ElementsKind;
KindForArrayType<Uint8Elements>(): constexpr ElementsKind {
  return ElementsKind::UINT8_ELEMENTS;
}
KindForArrayType<Int8Elements>(): constexpr ElementsKind {
  return ElementsKind::INT8_ELEMENTS;
}
KindForArrayType<Uint16Elements>(): constexpr ElementsKind {
  return ElementsKind::UINT16_ELEMENTS;
}
KindForArrayType<Int16Elements>(): constexpr ElementsKind {
  return ElementsKind::INT16_ELEMENTS;
}
KindForArrayType<Uint32Elements>(): constexpr ElementsKind {
  return ElementsKind::UINT32_ELEMENTS;
}
KindForArrayType<Int32Elements>(): constexpr ElementsKind {
  return ElementsKind::INT32_ELEMENTS;
}
KindForArrayType<Float16Elements>(): constexpr ElementsKind {
  return ElementsKind::FLOAT16_ELEMENTS;
}
KindForArrayType<Float32Elements>(): constexpr ElementsKind {
  return ElementsKind::FLOAT32_ELEMENTS;
}
KindForArrayType<Float64Elements>(): constexpr ElementsKind {
  return ElementsKind::FLOAT64_ELEMENTS;
}
KindForArrayType<Uint8ClampedElements>(): constexpr ElementsKind {
  return ElementsKind::UINT8_CLAMPED_ELEMENTS;
}
KindForArrayType<BigUint64Elements>(): constexpr ElementsKind {
  return ElementsKind::BIGUINT64_ELEMENTS;
}
KindForArrayType<BigInt64Elements>(): constexpr ElementsKind {
  return ElementsKind::BIGINT64_ELEMENTS;
}

builtin LoadTypedElement<T : type extends ElementsKind>(
    array: JSTypedArray, index: uintptr): Numeric {
  return LoadFixedTypedArrayElementAsTagged(
      array.data_ptr, index, KindForArrayType<T>());
}

builtin StoreTypedElementNumeric<T : type extends ElementsKind>(
    context: Context, typedArray: JSTypedArray, index: uintptr,
    value: Numeric): Smi {
  StoreJSTypedArrayElementFromNumeric(
      context, typedArray, index, value, KindForArrayType<T>());
  return kStoreSucceded;
}

// Returns True on success or False if the typedArrays was detached.
builtin StoreTypedElementJSAny<T : type extends ElementsKind>(
    context: Context, typedArray: JSTypedArray, index: uintptr,
    value: JSAny): Smi {
  try {
    StoreJSTypedArrayElementFromTagged(
        context, typedArray, index, value, KindForArrayType<T>())
        otherwise IfDetachedOrOutOfBounds;
  } label IfDetachedOrOutOfBounds {
    return kStoreFailureArrayDetachedOrOutOfBounds;
  }
  return kStoreSucceded;
}
}
```