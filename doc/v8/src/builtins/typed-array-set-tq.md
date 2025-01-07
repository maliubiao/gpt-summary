Response: Let's break down the thought process for analyzing this Torque code.

1. **Understand the Goal:** The request asks for a summary of the Torque code's functionality, its relation to JavaScript, examples, logical reasoning with inputs/outputs, and common errors. This means we need to connect the low-level Torque implementation to the higher-level JavaScript `TypedArray.prototype.set()` method.

2. **Identify the Entry Point:** The code starts with a `transitioning javascript builtin TypedArrayPrototypeSet`. This immediately tells us this Torque code *implements* the JavaScript `TypedArray.prototype.set()` method. The `builtin` keyword is a strong hint.

3. **Deconstruct the Logic:**  Go through the code section by section, focusing on the core operations and control flow:

    * **Initial Checks (Steps 2-8):**  The code first validates the `this` value (`receiver`) to ensure it's a `JSTypedArray`. It also handles the optional `offset` argument, converting it to an integer and checking for negative values. It also checks for detached buffers. *Key takeaway:* This is standard validation and setup.

    * **Overload Handling:** The code checks the type of the first argument (`overloadedArg`). This signifies the two overloads of `set()`: one taking another `TypedArray` and the other taking an array-like object. This is a crucial branching point.

    * **`TypedArray` Source Path (`TypedArrayPrototypeSetTypedArray`):** If the first argument is a `TypedArray`, the `TypedArrayPrototypeSetTypedArray` macro is called.
        * **More Checks:** This macro checks for offset overflow and detached buffers again (though some checks might be redundant due to the main function).
        * **Optimization (Memmove):**  It attempts to use `memmove` for faster copying if the element types are compatible (or are Uint8/Uint8Clamped). It considers shared array buffers and uses `CallCRelaxedMemmove` if necessary.
        * **Fallback (`CallCCopyTypedArrayElementsToTypedArray`):** If `memmove` isn't possible (e.g., different element types), it falls back to a more general copying mechanism.

    * **Array-Like Source Path (`TypedArrayPrototypeSetArray`):** If the first argument is array-like, the `TypedArrayPrototypeSetArray` macro is called.
        * **Conversion:** It converts the array-like object to a `JSReceiver` and gets its length.
        * **More Checks:**  Offset overflow and combined length exceeding target length are checked.
        * **Optimization (`CallCCopyFastNumberJSArrayElementsToTypedArray`):** It tries to use a fast path for copying from `FastJSArray` with specific numeric element kinds (SMI or double).
        * **Fallback (`TypedArraySet` runtime function):** If the fast path isn't applicable (e.g., non-fast array, BigInt elements), it calls a runtime function (`TypedArraySet`). This indicates that some logic is implemented in C++ runtime code.

4. **Identify JavaScript Equivalents:**  For each major section, think about how this translates to JavaScript:

    * Validating `this`:  Implicit in JavaScript's method calls.
    * Handling `offset`:  Standard JavaScript argument handling.
    * Checking for detached buffers: JavaScript throws errors when accessing detached buffers.
    * Overload resolution: JavaScript automatically handles this based on argument types.
    * Copying logic: JavaScript engines internally handle copying, often with optimizations.

5. **Construct Examples:**  Create JavaScript examples that demonstrate the different scenarios handled by the Torque code:

    * Setting from another `TypedArray`.
    * Setting from a regular array.
    * Using an offset.
    * Causing `RangeError` (offset out of bounds, insufficient space).
    * Causing `TypeError` (detached buffer, incorrect `this` value, mixing BigInt with non-BigInt arrays).

6. **Infer Logical Reasoning:** For the fast paths and slow paths, consider example inputs and what the expected output would be. This helps to solidify the understanding of the optimizations. For instance, the `memmove` optimization is for cases where the element types are the same, ensuring a direct byte-wise copy.

7. **Pinpoint Common Errors:**  Relate the checks and potential exceptions in the Torque code to common mistakes JavaScript developers might make when using `TypedArray.prototype.set()`. These errors often correspond to the exceptions thrown by the Torque implementation.

8. **Structure the Answer:** Organize the information logically:

    * **Functionality:** Start with a concise high-level summary.
    * **JavaScript Relation:** Clearly explain how the Torque code implements the JavaScript method and provide concrete examples.
    * **Logical Reasoning:** Explain the assumptions, inputs, and outputs for different scenarios (especially optimization paths).
    * **Common Errors:**  Provide practical JavaScript examples of errors and explain why they occur.

9. **Review and Refine:** Read through the answer to ensure clarity, accuracy, and completeness. Make sure the JavaScript examples are correct and illustrate the intended points. Ensure the explanation of the logical reasoning is easy to follow.

By following this structured approach, you can effectively analyze complex low-level code like this Torque example and connect it to its corresponding higher-level language functionality. The key is to break down the code into manageable parts, understand the purpose of each part, and then relate it back to the user-facing behavior.
This Torque code defines the implementation for the `set` method of JavaScript Typed Array prototypes (`%TypedArray%.prototype.set`). It handles two overloads of this method:

1. **Setting elements from another Typed Array:** `typedArray.set(anotherTypedArray, offset)`
2. **Setting elements from an array-like object:** `typedArray.set(arrayLike, offset)`

Let's break down its functionality step by step:

**Core Functionality:**

1. **Type Checking and Receiver Validation:**
    *   It first ensures that the `this` value (`receiver`) is indeed a `JSTypedArray`. If not, it throws a `TypeError`.

2. **Offset Handling:**
    *   It retrieves the optional `offset` argument. If provided, it converts it to an unsigned integer (`uintptr`).
    *   It checks for negative offsets, throwing a `RangeError` if found. It also handles potential overflow during `ToUintPtr` conversion.

3. **Detached Buffer Check:**
    *   It verifies that the underlying `ArrayBuffer` of the target Typed Array is not detached. If it is, a `TypeError` is thrown.

4. **Overload Dispatch:**
    *   It checks the type of the first argument (`overloadedArg`).
    *   If it's another `JSTypedArray`, it calls `TypedArrayPrototypeSetTypedArray`.
    *   If it's not a `JSTypedArray` (implying it's array-like), it calls `TypedArrayPrototypeSetArray`.

**`TypedArrayPrototypeSetTypedArray` (Setting from another Typed Array):**

1. **Detached Buffer Check (Source):** It checks if the source Typed Array's underlying buffer is detached.
2. **Length Checks:** It ensures that the combined length of the source Typed Array and the `targetOffset` does not exceed the length of the target Typed Array, throwing a `RangeError` if it does.
3. **Type Compatibility Check (Potentially):** Although commented out as "not observable," the code implicitly handles the case where the source and target Typed Arrays have different element types (e.g., Int32Array and Float64Array) later in the `IfSlow` path.
4. **Optimization (Memmove):**
    *   If the element types of the source and target Typed Arrays are the same (or both are `Uint8` or `Uint8Clamped`), it attempts to use `memmove` (or `CallCRelaxedMemmove` for SharedArrayBuffers) for a fast byte-wise copy. This is a significant performance optimization.
5. **Fallback (Element-wise Copy):**
    *   If the element types are different, it falls back to `CallCCopyTypedArrayElementsToTypedArray`, which performs an element-by-element copy, potentially involving type conversions. It also checks for mixing BigInt and non-BigInt typed arrays, throwing a `TypeError` if they are incompatible.

**`TypedArrayPrototypeSetArray` (Setting from an Array-like Object):**

1. **Convert to Object:** It converts the array-like source to a `JSReceiver`.
2. **Get Source Length:** It retrieves the `length` property of the source.
3. **Length Checks:** It ensures that the combined length of the source array and the `targetOffset` does not exceed the length of the target Typed Array, throwing a `RangeError` if it does.
4. **Optimization (Fast Path for Number Arrays):**
    *   If the target Typed Array is not a BigInt type and the source is a `FastJSArray` containing SMI (small integers) or double elements, it uses `CallCCopyFastNumberJSArrayElementsToTypedArray` for optimized copying.
5. **Fallback (Runtime Function):**
    *   If the fast path is not applicable (e.g., non-fast array, BigInt elements), it calls the `TypedArraySet` runtime function (which is implemented in C++ and not fully shown here) to handle the copying.

**Relationship to JavaScript:**

This Torque code directly implements the behavior of the `TypedArray.prototype.set()` method in JavaScript.

**JavaScript Examples:**

```javascript
// Example 1: Setting from another Typed Array
const sourceArray = new Int8Array([10, 20, 30]);
const targetArray = new Int8Array(5);
targetArray.set(sourceArray, 1); // targetArray becomes [0, 10, 20, 30, 0]

// Example 2: Setting from a regular array
const sourceArray2 = [40, 50];
targetArray.set(sourceArray2, 3); // targetArray becomes [0, 10, 20, 40, 50]

// Example 3: Using offset 0 (default)
const sourceArray3 = new Uint16Array([100, 200]);
const targetArray2 = new Uint16Array(3);
targetArray2.set(sourceArray3); // targetArray2 becomes [100, 200, 0]

// Example 4: Setting with overlapping regions (handled correctly)
const arr = new Uint8Array([1, 2, 3, 4, 5]);
arr.set(arr.subarray(2), 0); // arr becomes [3, 4, 5, 4, 5]
```

**Code Logic Reasoning (Assumptions, Inputs, Outputs):**

**Scenario 1: `TypedArrayPrototypeSetTypedArray` with same element types and sufficient space.**

*   **Assumption:** Source and target are `Int32Array`, no detached buffers, `targetOffset` is within bounds.
*   **Input:**
    *   `target`: `Int32Array([0, 0, 0, 0, 0])`
    *   `source`: `Int32Array([1, 2, 3])`
    *   `targetOffset`: `1`
*   **Output:** `target` becomes `Int32Array([0, 1, 2, 3, 0])` (likely using optimized `memmove`)

**Scenario 2: `TypedArrayPrototypeSetArray` with a regular array of numbers.**

*   **Assumption:** Target is `Float64Array`, source is a regular array of numbers, no detached buffers, sufficient space.
*   **Input:**
    *   `target`: `Float64Array([0, 0, 0])`
    *   `source`: `[3.14, 2.71]`
    *   `targetOffset`: `0`
*   **Output:** `target` becomes `Float64Array([3.14, 2.71, 0])` (potentially using `CallCCopyFastNumberJSArrayElementsToTypedArray` if the array is optimized).

**Scenario 3: `TypedArrayPrototypeSetTypedArray` with different element types.**

*   **Assumption:** Target is `Float64Array`, source is `Int32Array`, no detached buffers, sufficient space.
*   **Input:**
    *   `target`: `Float64Array([0, 0, 0])`
    *   `source`: `Int32Array([1, 2])`
    *   `targetOffset`: `0`
*   **Output:** `target` becomes `Float64Array([1.0, 2.0, 0.0])` (using the slower element-wise copy with type conversion).

**Common Programming Errors:**

1. **`TypeError: this is not a TypedArray object.`**
    ```javascript
    const regularArray = [1, 2, 3];
    regularArray.set(new Int8Array([4, 5])); // Error! 'set' is not a method of Array
    ```
    **Explanation:** The `set` method is specific to Typed Array instances.

2. **`TypeError: Cannot perform %TypedArray%.prototype.set on detached ArrayBuffer`**
    ```javascript
    const buffer = new ArrayBuffer(8);
    const typedArray = new Int32Array(buffer);
    buffer.detach();
    typedArray.set(new Int32Array([1, 2])); // Error! Buffer is detached
    ```
    **Explanation:**  Trying to operate on a Typed Array whose underlying buffer has been detached will result in this error.

3. **`RangeError: %TypedArray%.prototype.set offset is out of bounds`**
    ```javascript
    const targetArray = new Int8Array(3);
    targetArray.set(new Int8Array([1, 2, 3, 4]), 1); // Error! Not enough space
    targetArray.set(new Int8Array([1, 2]), -1);     // Error! Negative offset
    ```
    **Explanation:** This occurs when the `offset` is negative or when the combined length of the source and the offset exceeds the target Typed Array's length.

4. **`TypeError: Cannot set properties of #<Object> which has only a getter` (Less common with `set`, more with direct assignment, but related to mutability)**
    While `set` itself doesn't directly trigger this, understanding the underlying buffer is crucial. If you have a read-only view of a buffer, `set` might fail indirectly if it relies on writing to the buffer.

5. **Mixing BigInt and non-BigInt Typed Arrays without explicit conversion:**
    ```javascript
    const intArr = new Int32Array(2);
    const bigIntArr = new BigInt64Array([1n, 2n]);
    intArr.set(bigIntArr); // Likely throws a TypeError
    ```
    **Explanation:**  The code explicitly checks for this mismatch and throws a `TypeError`.

In summary, this Torque code provides the core logic for the `TypedArray.prototype.set` method, handling different input types, optimizing for common cases like copying between Typed Arrays of the same type, and ensuring adherence to JavaScript's specifications regarding error handling and behavior.

Prompt: 
```
这是目录为v8/src/builtins/typed-array-set.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include 'src/builtins/builtins-typed-array-gen.h'

namespace typed_array {
const kBuiltinNameSet: constexpr string = '%TypedArray%.prototype.set';

extern runtime TypedArraySet(Context, JSTypedArray, Object, Number, Number):
    void;

extern macro
    TypedArrayBuiltinsAssembler::CallCCopyFastNumberJSArrayElementsToTypedArray(
        Context,
        FastJSArray,           // source
        AttachedJSTypedArray,  // dest
        uintptr,               // sourceLength
        uintptr                // destOffset
        ): void;

extern macro
    TypedArrayBuiltinsAssembler::CallCCopyTypedArrayElementsToTypedArray(
        AttachedJSTypedArray,  // source
        AttachedJSTypedArray,  // dest
        uintptr,               // sourceLength
        uintptr                // destOffset
        ): void;

// %TypedArray%.prototype.set ( overloaded [ , offset ] )
// https://tc39.es/ecma262/#sec-%typedarray%.prototype.set-overloaded-offset
transitioning javascript builtin TypedArrayPrototypeSet(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  // Steps 2-8 are the same for
  // %TypedArray%.prototype.set ( array [ , offset ] ) and
  // %TypedArray%.prototype.set ( typedArray [ , offset ] ) overloads.

  let target: JSTypedArray;
  try {
    // 2. Let target be the this value.
    // 3. Perform ? RequireInternalSlot(target, [[TypedArrayName]]).
    // 4. Assert: target has a [[ViewedArrayBuffer]] internal slot.
    target = Cast<JSTypedArray>(receiver) otherwise NotTypedArray;
  } label NotTypedArray deferred {
    ThrowTypeError(MessageTemplate::kNotTypedArray, kBuiltinNameSet);
  }

  try {
    // 5. Let targetOffset be ? ToInteger(offset).
    // 6. If targetOffset < 0, throw a RangeError exception.
    let targetOffsetOverflowed: bool = false;
    let targetOffset: uintptr = 0;
    if (arguments.length > 1) {
      const offsetArg = arguments[1];
      try {
        targetOffset = ToUintPtr(offsetArg)
        // On values less than zero throw RangeError immediately.
            otherwise OffsetOutOfBounds,
            // On UintPtr or SafeInteger range overflow throw RangeError after
            // performing observable steps to follow the spec.
            OffsetOverflow, OffsetOverflow;
      } label OffsetOverflow {
        targetOffsetOverflowed = true;
      }
    } else {
      // If the offset argument is not provided then the targetOffset is 0.
    }

    // 7. Let targetBuffer be target.[[ViewedArrayBuffer]].
    // 8. If IsDetachedBuffer(targetBuffer) is true, throw a TypeError
    //   exception.
    const attachedTargetAndLength = EnsureAttachedAndReadLength(target)
        otherwise IsDetachedOrOutOfBounds;

    const overloadedArg = arguments[0];
    try {
      // 1. Choose SetTypedArrayFromTypedArray or SetTypedArrayFromArrayLike
      //   depending on whether the overloadedArg has a [[TypedArrayName]]
      //   internal slot.
      const typedArray =
          Cast<JSTypedArray>(overloadedArg) otherwise NotTypedArray;

      // Step 3 is not observable, do it later.

      // 4. Let srcBuffer be typedArray.[[ViewedArrayBuffer]].
      // 5. If IsDetachedBuffer(srcBuffer) is true, throw a TypeError
      //   exception.
      const attachedSourceAndLength = EnsureAttachedAndReadLength(typedArray)
          otherwise IsDetachedOrOutOfBounds;
      TypedArrayPrototypeSetTypedArray(
          attachedTargetAndLength, attachedSourceAndLength, targetOffset,
          targetOffsetOverflowed)
          otherwise OffsetOutOfBounds;
      return Undefined;
    } label NotTypedArray deferred {
      TypedArrayPrototypeSetArray(
          target, attachedTargetAndLength.length, overloadedArg, targetOffset,
          targetOffsetOverflowed)
          otherwise OffsetOutOfBounds;
      return Undefined;
    }
  } label OffsetOutOfBounds deferred {
    ThrowRangeError(MessageTemplate::kTypedArraySetOffsetOutOfBounds);
  } label IsDetachedOrOutOfBounds deferred {
    ThrowTypeError(MessageTemplate::kDetachedOperation, kBuiltinNameSet);
  }
}

// SetTypedArrayFromArrayLike
// https://tc39.es/ecma262/#sec-settypedarrayfromarraylike
transitioning macro TypedArrayPrototypeSetArray(
    implicit context: Context, receiver: JSAny)(target: JSTypedArray,
    targetLength: uintptr, arrayArg: JSAny, targetOffset: uintptr,
    targetOffsetOverflowed: bool): void labels IfOffsetOutOfBounds {
  // 4. Let src be ? ToObject(source).
  const src: JSReceiver = ToObject_Inline(context, arrayArg);

  // 5. Let srcLength be ? LengthOfArrayLike(src).
  const srcLengthNum: Number = GetLengthProperty(src);

  // 6. If targetOffset is +∞, throw a RangeError exception.
  if (targetOffsetOverflowed) goto IfOffsetOutOfBounds;

  // 7. If srcLength + targetOffset > targetLength, throw a RangeError
  //   exception.
  const srcLength = ChangeSafeIntegerNumberToUintPtr(srcLengthNum)
      otherwise IfOffsetOutOfBounds;
  CheckIntegerIndexAdditionOverflow(srcLength, targetOffset, targetLength)
      otherwise IfOffsetOutOfBounds;

  // All the obvervable side effects are executed, so there's nothing else
  // to do with the empty source array.
  if (srcLength == 0) return;

  try {
    // BigInt typed arrays are not handled by
    // CopyFastNumberJSArrayElementsToTypedArray.
    if (IsBigInt64ElementsKind(target.elements_kind)) goto IfSlow;

    const fastSrc: FastJSArray = Cast<FastJSArray>(src) otherwise goto IfSlow;
    const srcKind: ElementsKind = fastSrc.map.elements_kind;

    // CopyFastNumberJSArrayElementsToTypedArray() can be used only with the
    // following elements kinds:
    // PACKED_SMI_ELEMENTS, HOLEY_SMI_ELEMENTS, PACKED_DOUBLE_ELEMENTS,
    // HOLEY_DOUBLE_ELEMENTS.
    if (IsElementsKindInRange(
            srcKind, ElementsKind::PACKED_SMI_ELEMENTS,
            ElementsKind::HOLEY_SMI_ELEMENTS) ||
        IsElementsKindInRange(
            srcKind, ElementsKind::PACKED_DOUBLE_ELEMENTS,
            ElementsKind::HOLEY_DOUBLE_ELEMENTS)) {
      // If the source is a JSArray (no custom length getter or elements
      // getter), there's nothing that could detach or resize the target, so
      // it's always non-detached here. Also we don't need to reload the length.
      const utarget = typed_array::EnsureAttached(target) otherwise unreachable;
      CallCCopyFastNumberJSArrayElementsToTypedArray(
          context, fastSrc, utarget, srcLength, targetOffset);

    } else {
      goto IfSlow;
    }
  } label IfSlow deferred {
    TypedArraySet(
        context, target, src, srcLengthNum, Convert<Number>(targetOffset));
  }
}

// SetTypedArrayFromTypedArray
// https://tc39.es/ecma262/#sec-settypedarrayfromtypedarray
transitioning macro TypedArrayPrototypeSetTypedArray(
    implicit context: Context, receiver: JSAny)(
    attachedTargetAndLength: AttachedJSTypedArrayAndLength,
    attachedSourceAndLength: AttachedJSTypedArrayAndLength,
    targetOffset: uintptr,
    targetOffsetOverflowed: bool): void labels IfOffsetOutOfBounds {
  // Steps 6-14 are not observable, so we can handle offset overflow
  // at step 15 here.
  if (targetOffsetOverflowed) goto IfOffsetOutOfBounds;

  // 3. Let targetLength be IntegerIndexedObjectLength(target).
  const target = attachedTargetAndLength.array;
  const targetLength = attachedTargetAndLength.length;

  // 13. Let srcLength be IntegerIndexedObjectLength(source).
  const source = attachedSourceAndLength.array;
  const srcLength = attachedSourceAndLength.length;

  // 16. If srcLength + targetOffset > targetLength, throw a RangeError
  //   exception.
  CheckIntegerIndexAdditionOverflow(srcLength, targetOffset, targetLength)
      otherwise IfOffsetOutOfBounds;

  // 6. Let targetName be the String value of target.[[TypedArrayName]].
  // 7. Let targetType be the Element Type value in Table 62 for
  //    targetName.
  // 8. Let targetElementSize be the Element Size value specified in
  //   Table 62 for targetName.
  const targetElementsInfo = GetTypedArrayElementsInfo(target);

  // 10. Let srcName be the String value of source.[[TypedArrayName]].
  // 11. Let srcType be the Element Type value in Table 62 for srcName.
  // 12. Let srcElementSize be the Element Size value specified in
  //   Table 62 for srcName.
  const srcKind: ElementsKind = source.elements_kind;

  // We skip steps 18-20 because both memmove and
  // CopyTypedArrayElementsToTypedArray() properly handle overlapping
  // regions.

  // 18. If both IsSharedArrayBuffer(srcBuffer) and
  //   IsSharedArrayBuffer(targetBuffer) are true, then
  //   a. If srcBuffer.[[ArrayBufferData]] and
  //   targetBuffer.[[ArrayBufferData]] are the same Shared Data Block
  //   values, let same be true; else let same be false.
  // 19. Else, let same be SameValue(srcBuffer, targetBuffer).
  // 20. If same is true, then
  //   a. Let srcByteLength be source.[[ByteLength]].
  //   b. Set srcBuffer to ? CloneArrayBuffer(srcBuffer, srcByteOffset,
  //    srcByteLength, %ArrayBuffer%).
  //   c. NOTE: %ArrayBuffer% is used to clone srcBuffer because is it known
  //    to not have any observable side-effects.
  //   d. Let srcByteIndex be 0.

  try {
    // Use memmove if possible.
    // TODO(v8:11111): Enable fast copying between a RAB/GSAB element kind and
    // the corresponding non-RAB/GSAB element kind.
    if (srcKind != targetElementsInfo.kind) {
      // Uint8/Uint8Clamped elements could still be copied with memmove.
      if (!IsUint8ElementsKind(srcKind) ||
          !IsUint8ElementsKind(targetElementsInfo.kind)) {
        goto IfSlow;
      }
    }

    // All the obvervable side effects are executed, so there's nothing else
    // to do with the empty source array.
    if (srcLength == 0) return;

    // Source and destination typed arrays have same elements kinds (modulo
    // Uint8-Uint8Clamped difference) so we can use targetElementsInfo for
    // calculations.
    const countBytes: uintptr =
        targetElementsInfo.CalculateByteLength(srcLength)
        otherwise unreachable;
    const startOffset: uintptr =
        targetElementsInfo.CalculateByteLength(targetOffset)
        otherwise unreachable;
    const dstPtr: RawPtr = target.data_ptr + Convert<intptr>(startOffset);

    // We've already checked for detachedness, and there's nothing that could've
    // detached the buffers until here.
    @if(DEBUG) {
      const targetByteLength = LoadJSArrayBufferViewByteLength(
          target, target.buffer) otherwise unreachable;
      const sourceByteLength = LoadJSArrayBufferViewByteLength(
          source, source.buffer) otherwise unreachable;

      dcheck(countBytes <= targetByteLength - startOffset);
      dcheck(countBytes <= sourceByteLength);
    }

    // 24. If srcType is the same as targetType, then
    //   a. NOTE: If srcType and targetType are the same, the transfer must
    //      be performed in a manner that preserves the bit-level encoding of
    //      the source data.
    //   b. Repeat, while targetByteIndex < limit
    //      i. Let value be GetValueFromBuffer(srcBuffer, srcByteIndex, Uint8,
    //                                         true, Unordered).
    //     ii. Perform SetValueInBuffer(targetBuffer, targetByteIndex, Uint8,
    //                                  value, true, Unordered).
    //    iii. Set srcByteIndex to srcByteIndex + 1.
    //     iv. Set targetByteIndex to targetByteIndex + 1.
    if (IsSharedArrayBuffer(target.buffer) ||
        IsSharedArrayBuffer(source.buffer)) {
      // SABs need a relaxed memmove to preserve atomicity.
      CallCRelaxedMemmove(dstPtr, source.data_ptr, countBytes);
    } else {
      CallCMemmove(dstPtr, source.data_ptr, countBytes);
    }
  } label IfSlow deferred {
    // 17. If target.[[ContentType]] is not equal to
    //   source.[[ContentType]], throw a TypeError exception.
    if (IsBigInt64ElementsKind(srcKind) !=
        IsBigInt64ElementsKind(targetElementsInfo.kind))
      deferred {
        ThrowTypeError(MessageTemplate::kBigIntMixedTypes);
      }

    // All the obvervable side effects are executed, so there's nothing else
    // to do with the empty source array.
    if (srcLength == 0) return;

    // 25. Else,
    //   a. Repeat, while targetByteIndex < limit
    //      i. Let value be GetValueFromBuffer(srcBuffer, srcByteIndex,
    //                                         srcType, true, Unordered).
    //     ii. Perform SetValueInBuffer(targetBuffer, targetByteIndex,
    //                                  targetType, value, true, Unordered).
    //    iii. Set srcByteIndex to srcByteIndex + srcElementSize.
    //     iv. Set targetByteIndex to targetByteIndex + targetElementSize.
    CallCCopyTypedArrayElementsToTypedArray(
        source, target, srcLength, targetOffset);
  }
}
}

"""

```