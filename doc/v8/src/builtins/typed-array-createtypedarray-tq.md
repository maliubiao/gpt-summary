Response: Let's break down the thought process for analyzing this Torque code.

1. **Initial Understanding of Torque:** The first step is to recognize that this isn't standard JavaScript. The `.tq` extension and the syntax (`transitioning macro`, `builtin`, `implicit context`) immediately flag it as Torque, V8's internal language for defining built-in functions. Knowing this means the goal is to understand *how* Typed Arrays are *implemented* in V8, not just how they're used in JavaScript.

2. **Scanning for Keywords and Structure:** Look for recurring keywords and structural elements. `macro`, `transitioning`, `builtin`, `labels`, `try`, `catch`, `typeswitch`, and the various `ConstructBy...` prefixes are good indicators of the code's organization. Notice the structure of macros: name, parameters (including `implicit context`), return type, and the code block. Builtins also have a similar structure.

3. **Identifying the Core Functionality:** The filename `typed-array-createtypedarray.tq` and the repeated use of `TypedArray` in macro names strongly suggest this code is responsible for *creating* Typed Array objects in V8.

4. **Analyzing Individual Macros/Builtins:** Start with the easier or more central ones.

    * **`AllocateTypedArray`:** This seems fundamental. It takes various parameters related to memory allocation (`isOnHeap`, `map`, `buffer`, `byteOffset`, `byteLength`, `length`, `isLengthTracking`) and seems to create the underlying `JSTypedArray` object. The comments about on-heap vs. off-heap are important. The checks for `IsResizableArrayBuffer` also stand out.

    * **`TypedArrayInitialize`:** This macro calls `AllocateTypedArray`. It handles the allocation of the underlying buffer (either on the heap or by creating a new `ArrayBuffer`). The `initialize` parameter suggests the zero-filling behavior. The `try...label AllocateOffHeap` structure is a good indication of different allocation paths.

    * **`ConstructByLength`:** This seems like the case when you create a Typed Array with a specific length (e.g., `new Int32Array(10)`). It uses `TypedArrayInitialize`.

    * **`ConstructByArrayLike`:** This handles creating a Typed Array from an existing array-like object. The logic to handle different `ElementsKind` and the use of `TypedArrayCopyElements` are key here. The `Cast<JSTypedArray>` suggests type checking.

    * **`ConstructByIterable`:**  This deals with creating Typed Arrays from iterables. It uses `IterableToListConvertHoles`, which hints at converting the iterable to a standard JavaScript Array first.

    * **`ConstructByTypedArray`:**  Handles creating a copy of an existing Typed Array.

    * **`ConstructByArrayBuffer`:**  This is for the `new Int32Array(buffer, byteOffset, length)` scenario. It has detailed logic for validating `byteOffset` and `length` against the `ArrayBuffer`. The checks for alignment are crucial.

    * **`CreateTypedArray` (the builtin):**  This is the main entry point. The `typeswitch` on the first argument (`arg1`) clearly shows the different ways a Typed Array can be constructed (length, ArrayBuffer, another TypedArray, an iterable, or an array-like object). This ties directly to the JavaScript constructor behavior.

    * **`TypedArraySpeciesCreate` and related macros:** These deal with the `species` pattern, allowing subclasses of Typed Arrays to control the type of object returned by methods like `slice`.

5. **Identifying JavaScript Connections:** As you understand the macros, relate them back to the standard JavaScript Typed Array constructor behavior. For each `ConstructBy...` macro, think about the corresponding JavaScript constructor invocation.

6. **Code Logic Reasoning (Assumptions and Outputs):** Pick a macro or code block with clear logic and walk through it with example inputs. For `AllocateTypedArray`, consider the `isOnHeap` branch. If `isOnHeap` is true, the `elements` will be allocated using `AllocateByteArray`. If false, it uses `kEmptyByteArray` and relies on the provided `buffer`. For `ConstructByLength`, if you pass a valid length, it should allocate a Typed Array of that size, potentially zero-filling the memory. If you pass an invalid length (too large or negative), it should throw a `RangeError`.

7. **Common Programming Errors:**  Think about the error conditions handled in the code. `RangeError` for invalid lengths or offsets, `TypeError` for detached buffers or type mismatches (BigInt vs. regular numbers), and alignment errors are explicitly handled. These map directly to common mistakes developers make when working with Typed Arrays.

8. **Refinement and Summarization:**  After analyzing the individual parts, synthesize the information into a coherent summary. Focus on the main function, the different construction pathways, memory management aspects (on-heap/off-heap, resizable buffers), and the error handling. Organize the information logically, perhaps mirroring the structure of the code itself (different constructor forms).

9. **Review and Verification:** Read through the summary and examples to ensure they are accurate and clearly explain the code's functionality. Double-check the JavaScript examples to make sure they illustrate the concepts correctly.

By following these steps, you can systematically dissect and understand even complex Torque code like this, connecting it back to the familiar concepts of JavaScript. The key is to break down the problem, understand the individual components, and then put it all back together with the JavaScript context in mind.
这段V8 Torque源代码文件 `v8/src/builtins/typed-array-createtypedarray.tq` 的主要功能是**实现 JavaScript TypedArray 的创建过程**。它定义了多个 Torque 宏（macros）和内置函数（builtin），负责处理各种不同的 TypedArray 构造函数调用方式，包括：

* **通过长度创建:** `new Int32Array(10)`
* **通过ArrayBuffer创建:** `new Uint8Array(buffer, byteOffset, length)`
* **通过另一个TypedArray创建:** `new Float64Array(anotherTypedArray)`
* **通过可迭代对象创建:** `new Uint16Array(iterable)`
* **通过类数组对象创建:** `new BigInt64Array({ length: 5 })`

该文件还处理了与 TypedArray 创建相关的内存分配、类型检查、参数验证和错误处理。

**与 JavaScript 功能的关系及举例说明:**

这个 Torque 代码直接对应于 JavaScript 中 `TypedArray` 构造函数的行为。JavaScript 提供了多种方式来创建 TypedArray，而这段代码就是 V8 引擎中实现这些创建逻辑的具体步骤。

**JavaScript 示例:**

```javascript
// 通过长度创建
const int32Array = new Int32Array(5); // 创建一个包含 5 个 32 位整数的 TypedArray

// 通过 ArrayBuffer 创建
const buffer = new ArrayBuffer(16);
const uint8Array = new Uint8Array(buffer); // 创建一个指向 buffer 的 Uint8Array
const float32Array = new Float32Array(buffer, 4, 2); // 从 buffer 的偏移量 4 开始，创建包含 2 个 32 位浮点数的 TypedArray

// 通过另一个 TypedArray 创建
const anotherInt32Array = new Int32Array([1, 2, 3]);
const uint16ArrayFromInt32 = new Uint16Array(anotherInt32Array); // 创建一个包含相同元素的 Uint16Array

// 通过可迭代对象创建
const iterable = new Set([10, 20, 30]);
const uint8ClampedArrayFromIterable = new Uint8ClampedArray(iterable);

// 通过类数组对象创建
const arrayLike = { length: 3, 0: '1', 1: 2.5, 2: 3 };
const float64ArrayFromArrayLike = new Float64Array(arrayLike);
```

**代码逻辑推理（假设输入与输出）:**

**宏: `ConstructByLength(implicit context: Context)(map: Map, lengthObj: JSAny, elementsInfo: typed_array::TypedArrayElementsInfo): JSTypedArray`**

**假设输入:**

* `map`:  指向 `Int32Array` 的 Map 对象 (包含了类型信息)
* `lengthObj`:  一个 Smi 对象，值为 `10` (JavaScript 中的数字 `10`)
* `elementsInfo`:  包含 `Int32Array` 元素大小 (4 字节) 等信息的对象

**代码逻辑:**

1. `ToIndex(lengthObj)` 将 `lengthObj` (Smi 10) 转换为 uintptr 类型 `length` (值为 10)。
2. `TypedArrayInitialize(true, map, length, elementsInfo)` 被调用，其中 `true` 表示需要初始化内存为 0。
3. `TypedArrayInitialize` 计算所需的字节长度 (10 * 4 = 40 字节)。
4. 如果字节长度小于等于 `kMaxTypedArrayInHeap`，则在堆上分配一个 `ArrayBuffer`。
5. 使用 `AllocateTypedArray` 创建 `JSTypedArray` 对象，将 `elements` 指向新分配的内存。
6. 由于 `initialize` 为 `true`，使用 `CallCMemset` 将分配的内存设置为 0。

**预期输出:**

返回一个新的 `JSTypedArray` 对象，其类型为 `Int32Array`，长度为 10，内部 `ArrayBuffer` 的大小为 40 字节，并且所有元素都初始化为 0。

**宏: `ConstructByArrayBuffer(implicit context: Context)(target: JSFunction, newTarget: JSReceiver, buffer: JSArrayBuffer, byteOffset: JSAny, length: JSAny): JSTypedArray`**

**假设输入:**

* `target`:  `Uint8Array` 构造函数
* `newTarget`:  通常与 `target` 相同
* `buffer`:  一个 `ArrayBuffer` 对象，大小为 16 字节
* `byteOffset`:  一个 Smi 对象，值为 `4`
* `length`:  一个 Smi 对象，值为 `8`

**代码逻辑:**

1. 获取 `Uint8Array` 的 Map 对象。
2. 将 `byteOffset` (4) 和 `length` (8) 转换为 `uintptr` 类型。
3. 检查 `byteOffset` 是否与元素大小 (1 字节 for `Uint8Array`) 对齐 (4 % 1 == 0，对齐)。
4. 检查 `buffer` 是否已分离。
5. 计算 `newByteLength` 为 `length` * 元素大小 = 8 * 1 = 8 字节。
6. 检查 `offset + newByteLength` 是否超出 `bufferByteLength` (4 + 8 <= 16，未超出)。
7. 使用 `AllocateTypedArray` 创建 `JSTypedArray` 对象，指向 `buffer` 的偏移量 4，长度为 8。

**预期输出:**

返回一个新的 `JSTypedArray` 对象，其类型为 `Uint8Array`，指向提供的 `buffer`，起始偏移量为 4 字节，长度为 8 个元素（8 字节）。

**涉及用户常见的编程错误:**

1. **`RangeError: Invalid typed array length`:** 当尝试创建长度过大或负数的 TypedArray 时会发生。

   ```javascript
   // 错误示例
   const arr1 = new Int16Array(Number.MAX_SAFE_INTEGER + 1); // 长度过大
   const arr2 = new Float32Array(-5); // 长度为负数
   ```

2. **`RangeError: Offset is out of bounds`:** 当使用 `ArrayBuffer` 创建 TypedArray 时，提供的 `byteOffset` 超出了 `ArrayBuffer` 的范围。

   ```javascript
   // 错误示例
   const buffer = new ArrayBuffer(8);
   const arr = new Uint32Array(buffer, 10); // byteOffset 10 超出 buffer 大小
   ```

3. **`RangeError: Start offset of Uint32Array should be a multiple of 4` (或类似的消息):** 当使用 `ArrayBuffer` 创建 TypedArray 时，提供的 `byteOffset` 不是元素大小的倍数（未对齐）。

   ```javascript
   // 错误示例
   const buffer = new ArrayBuffer(8);
   const arr = new Uint32Array(buffer, 1); // byteOffset 1 不是 4 的倍数
   ```

4. **`TypeError: Detached operation`:** 当尝试操作已分离的 `ArrayBuffer` 或其视图时发生。

   ```javascript
   // 错误示例
   const buffer = new ArrayBuffer(8);
   const arr = new Uint8Array(buffer);
   buffer.detach();
   console.log(arr[0]); // 尝试访问已分离的 ArrayBuffer 的视图
   ```

5. **`TypeError: First argument to %TypedArray%'s constructor is not callable`:**  当传递给 TypedArray 构造函数的第一个参数是 Symbol.iterator 但对应的迭代器方法不可调用时发生。

   ```javascript
   // 错误示例
   const obj = { [Symbol.iterator]: null };
   new Uint8Array(obj);
   ```

这段 Torque 代码详细地实现了 TypedArray 的各种创建场景，并包含了必要的错误处理逻辑，确保了 JavaScript 中 TypedArray 的行为符合规范。理解这段代码有助于深入理解 V8 引擎如何处理底层的内存分配和类型转换，以及如何防止用户在 JavaScript 中创建和操作 TypedArray 时出现错误。

Prompt: 
```
这是目录为v8/src/builtins/typed-array-createtypedarray.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include 'src/builtins/builtins-constructor-gen.h'

namespace typed_array {
extern builtin IterableToListConvertHoles(Context, Object, Callable): JSArray;

extern macro TypedArrayBuiltinsAssembler::AllocateEmptyOnHeapBuffer(
    implicit context: Context)(): JSArrayBuffer;
extern macro TypedArrayBuiltinsAssembler::GetDefaultConstructor(
    implicit context: Context)(JSTypedArray): JSFunction;
extern macro TypedArrayBuiltinsAssembler::SetupTypedArrayEmbedderFields(
    JSTypedArray): void;

extern runtime ThrowInvalidTypedArrayAlignment(
    implicit context: Context)(Map, String): never;

extern runtime GrowableSharedArrayBufferByteLength(
    implicit context: Context)(Object): JSAny;

transitioning macro AllocateTypedArray(
    implicit context: Context)(isOnHeap: constexpr bool, map: Map,
    buffer: JSArrayBuffer, byteOffset: uintptr, byteLength: uintptr,
    length: uintptr, isLengthTracking: bool): JSTypedArray {
  let elements: ByteArray;
  if constexpr (isOnHeap) {
    dcheck(!IsResizableArrayBuffer(buffer));
    dcheck(!isLengthTracking);
    elements = AllocateByteArray(byteLength);
  } else {
    elements = kEmptyByteArray;

    // The max byteOffset is 8 * MaxSmi on the particular platform. 32 bit
    // platforms are self-limiting, because we can't allocate an array bigger
    // than our 32-bit arithmetic range anyway. 64 bit platforms could
    // theoretically have an offset up to 2^35 - 1.
    const backingStore: uintptr = Convert<uintptr>(buffer.backing_store_ptr);

    // Assert no overflow has occurred. Only assert if the mock array buffer
    // allocator is NOT used. When the mock array buffer is used, impossibly
    // large allocations are allowed that would erroneously cause an overflow
    // and this assertion to fail.
    dcheck(
        IsMockArrayBufferAllocatorFlag() ||
        (backingStore + byteOffset) >= backingStore);
  }

  // We can't just build the new object with "new JSTypedArray" here because
  // Torque doesn't know its full size including embedder fields, so use CSA
  // for the allocation step.
  const typedArray =
      UnsafeCast<JSTypedArray>(AllocateFastOrSlowJSObjectFromMap(map));
  typedArray.elements = elements;
  typedArray.buffer = buffer;
  typedArray.byte_offset = byteOffset;
  if (isLengthTracking) {
    dcheck(IsResizableArrayBuffer(buffer));
    // Set the byte_length and length fields of length-tracking TAs to zero, so
    // that we won't accidentally use them and access invalid data.
    typedArray.byte_length = 0;
    typedArray.length = 0;
  } else {
    typedArray.byte_length = byteLength;
    typedArray.length = length;
  }
  typedArray.bit_field.is_length_tracking = isLengthTracking;
  typedArray.bit_field.is_backed_by_rab =
      IsResizableArrayBuffer(buffer) && !IsSharedArrayBuffer(buffer);
  if constexpr (isOnHeap) {
    typed_array::SetJSTypedArrayOnHeapDataPtr(typedArray, elements, byteOffset);
  } else {
    typed_array::SetJSTypedArrayOffHeapDataPtr(
        typedArray, buffer.backing_store_ptr, byteOffset);
    dcheck(
        typedArray.data_ptr ==
        (buffer.backing_store_ptr + Convert<intptr>(byteOffset)));
  }
  SetupTypedArrayEmbedderFields(typedArray);
  return typedArray;
}

transitioning macro TypedArrayInitialize(
    implicit context: Context)(initialize: constexpr bool, map: Map,
    length: uintptr, elementsInfo: typed_array::TypedArrayElementsInfo):
    JSTypedArray labels IfRangeError {
  const byteLength = elementsInfo.CalculateByteLength(length)
      otherwise IfRangeError;
  const byteLengthNum = Convert<Number>(byteLength);
  const defaultConstructor = GetArrayBufferFunction();
  const byteOffset: uintptr = 0;

  try {
    if (byteLength > kMaxTypedArrayInHeap) goto AllocateOffHeap;

    const buffer = AllocateEmptyOnHeapBuffer();

    const isOnHeap: constexpr bool = true;
    const isLengthTracking: constexpr bool = false;
    const typedArray = AllocateTypedArray(
        isOnHeap, map, buffer, byteOffset, byteLength, length,
        isLengthTracking);

    if constexpr (initialize) {
      const backingStore = typedArray.data_ptr;
      typed_array::CallCMemset(backingStore, 0, byteLength);
    }

    return typedArray;
  } label AllocateOffHeap {
    if constexpr (initialize) {
      goto AttachOffHeapBuffer(Construct(defaultConstructor, byteLengthNum));
    } else {
      goto AttachOffHeapBuffer(Call(
          context, GetArrayBufferNoInitFunction(), Undefined, byteLengthNum));
    }
  } label AttachOffHeapBuffer(bufferObj: Object) {
    const buffer = Cast<JSArrayBuffer>(bufferObj) otherwise unreachable;
    const isOnHeap: constexpr bool = false;
    const isLengthTracking: constexpr bool = false;
    return AllocateTypedArray(
        isOnHeap, map, buffer, byteOffset, byteLength, length,
        isLengthTracking);
  }
}

// 22.2.4.2 TypedArray ( length )
// ES #sec-typedarray-length
transitioning macro ConstructByLength(
    implicit context: Context)(map: Map, lengthObj: JSAny,
    elementsInfo: typed_array::TypedArrayElementsInfo): JSTypedArray {
  try {
    const length: uintptr = ToIndex(lengthObj) otherwise RangeError;
    const initialize: constexpr bool = true;
    return TypedArrayInitialize(initialize, map, length, elementsInfo)
        otherwise RangeError;
  } label RangeError deferred {
    ThrowRangeError(MessageTemplate::kInvalidTypedArrayLength, lengthObj);
  }
}

// 22.2.4.4 TypedArray ( object )
// ES #sec-typedarray-object
transitioning macro ConstructByArrayLike(
    implicit context: Context)(map: Map, arrayLike: HeapObject,
    length: uintptr,
    elementsInfo: typed_array::TypedArrayElementsInfo): JSTypedArray {
  try {
    const initialize: constexpr bool = false;
    const typedArray =
        TypedArrayInitialize(initialize, map, length, elementsInfo)
        otherwise RangeError;

    try {
      const src: JSTypedArray = Cast<JSTypedArray>(arrayLike) otherwise IfSlow;
      let byteLength: uintptr;
      try {
        byteLength = LoadJSArrayBufferViewByteLength(src, src.buffer)
            otherwise DetachedOrOutOfBounds;
      } label DetachedOrOutOfBounds deferred {
        ThrowTypeError(MessageTemplate::kDetachedOperation, 'Construct');
      }
      if (src.elements_kind != elementsInfo.kind) {
        goto IfElementsKindMismatch(src.elements_kind);

      } else if (length > 0) {
        dcheck(byteLength <= kArrayBufferMaxByteLength);
        if (IsSharedArrayBuffer(src.buffer)) {
          typed_array::CallCRelaxedMemcpy(
              typedArray.data_ptr, src.data_ptr, byteLength);
        } else {
          typed_array::CallCMemcpy(
              typedArray.data_ptr, src.data_ptr, byteLength);
        }
      }
    } label IfElementsKindMismatch(srcKind: ElementsKind) deferred {
      if (IsBigInt64ElementsKind(srcKind) !=
          IsBigInt64ElementsKind(elementsInfo.kind)) {
        ThrowTypeError(MessageTemplate::kBigIntMixedTypes);
      }
      goto IfSlow;
    } label IfSlow deferred {
      if (length > 0) {
        TypedArrayCopyElements(
            context, typedArray, arrayLike, Convert<Number>(length));
      }
    }
    return typedArray;
  } label RangeError deferred {
    ThrowRangeError(
        MessageTemplate::kInvalidTypedArrayLength, Convert<Number>(length));
  }
}

// 22.2.4.4 TypedArray ( object )
// ES #sec-typedarray-object
transitioning macro ConstructByIterable(
    implicit context: Context)(iterable: JSReceiver,
    iteratorFn: Callable): never
    labels IfConstructByArrayLike(JSArray, uintptr) {
  const array: JSArray =
      IterableToListConvertHoles(context, iterable, iteratorFn);
  // Max JSArray length is a valid JSTypedArray length so we just use it.
  goto IfConstructByArrayLike(array, array.length_uintptr);
}

// 22.2.4.3 TypedArray ( typedArray )
// ES #sec-typedarray-typedarray
transitioning macro ConstructByTypedArray(
    implicit context: Context)(srcTypedArray: JSTypedArray): never
    labels IfConstructByArrayLike(JSTypedArray, uintptr) {
  let length: uintptr;
  try {
    // TODO(petermarshall): Throw on detached typedArray.
    length = LoadJSTypedArrayLengthAndCheckDetached(srcTypedArray)
        otherwise DetachedOrOutOfBounds;
  } label DetachedOrOutOfBounds {
    length = 0;
  }

  goto IfConstructByArrayLike(srcTypedArray, length);
}

// 22.2.4.5 TypedArray ( buffer, byteOffset, length )
// ES #sec-initializetypedarrayfromarraybuffer
transitioning macro ConstructByArrayBuffer(
    implicit context: Context)(target: JSFunction, newTarget: JSReceiver,
    buffer: JSArrayBuffer, byteOffset: JSAny, length: JSAny): JSTypedArray {
  let map: Map;
  const isLengthTracking: bool =
      IsResizableArrayBuffer(buffer) && (length == Undefined);
  // Pick the RAB / GSAB map (containing the corresponding RAB / GSAB
  // ElementsKind). GSAB-backed non-length-tracking TypedArrays behave just like
  // normal TypedArrays, so exclude them.
  const rabGsab: bool = IsResizableArrayBuffer(buffer) &&
      (!IsSharedArrayBuffer(buffer) || isLengthTracking);
  if (rabGsab) {
    map = GetDerivedRabGsabTypedArrayMap(target, newTarget);
  } else {
    map = GetDerivedMap(target, newTarget);
  }

  // 1. Let elementSize be TypedArrayElementSize(O).
  const elementsInfo = GetTypedArrayElementsInfo(map);

  try {
    // 2. Let offset be ? ToIndex(byteOffset).
    const offset: uintptr = ToIndex(byteOffset) otherwise IfInvalidOffset;

    // 3. If offset modulo elementSize ≠ 0, throw a RangeError exception.
    if (elementsInfo.IsUnaligned(offset)) {
      goto IfInvalidAlignment('start offset');
    }

    // 4. Let bufferIsResizable be IsResizableArrayBuffer(buffer).

    // 5. If length is not undefined, then
    // a. Let newLength be ? ToIndex(length).
    let newLength: uintptr = ToIndex(length) otherwise IfInvalidLength;
    let newByteLength: uintptr;

    // 6. If IsDetachedBuffer(buffer) is true, throw a TypeError exception.
    if (IsDetachedBuffer(buffer)) {
      ThrowTypeError(MessageTemplate::kDetachedOperation, 'Construct');
    }

    // 7. Let bufferByteLength be ArrayBufferByteLength(buffer, SeqCst).
    let bufferByteLength: uintptr;
    if (IsResizableArrayBuffer(buffer) && IsSharedArrayBuffer(buffer)) {
      bufferByteLength = ToIndex(GrowableSharedArrayBufferByteLength(buffer))
          otherwise unreachable;
    } else {
      bufferByteLength = buffer.byte_length;
    }

    // 8. If length is undefined and bufferIsResizable is true, then
    //   a. If offset > bufferByteLength, throw a RangeError exception.
    //   b. Set O.[[ByteLength]] to auto.
    //   c. Set O.[[ArrayLength]] to auto.
    if (isLengthTracking) {
      if (bufferByteLength < offset) goto IfInvalidOffset;
      newLength = 0;
      newByteLength = 0;
    } else {
      // 9. Else
      //   a. If length is undefined, then
      if (length == Undefined) {
        //   i. If bufferByteLength modulo elementSize ≠ 0, throw a RangeError
        //   exception.
        if (elementsInfo.IsUnaligned(bufferByteLength)) {
          goto IfInvalidAlignment('byte length');
        }

        //   ii. Let newByteLength be bufferByteLength - offset.
        //   iii. If newByteLength < 0, throw a RangeError exception.
        if (bufferByteLength < offset) goto IfInvalidOffset;

        newByteLength = bufferByteLength - offset;
        newLength = elementsInfo.CalculateLength(newByteLength);
      } else {
        // b. Else,
        //   i. Let newByteLength be newLength × elementSize.
        newByteLength = elementsInfo.CalculateByteLength(newLength)
            otherwise IfInvalidLength;

        //   ii. If offset + newByteLength > bufferByteLength, throw a
        //   RangeError
        // exception.
        if ((bufferByteLength < newByteLength) ||
            (offset > bufferByteLength - newByteLength))
          goto IfInvalidLength;
      }
    }

    const isOnHeap: constexpr bool = false;
    return AllocateTypedArray(
        isOnHeap, map, buffer, offset, newByteLength, newLength,
        isLengthTracking);
  } label IfInvalidAlignment(problemString: String) deferred {
    ThrowInvalidTypedArrayAlignment(map, problemString);
  } label IfInvalidLength deferred {
    ThrowRangeError(MessageTemplate::kInvalidTypedArrayLength, length);
  } label IfInvalidOffset deferred {
    ThrowRangeError(MessageTemplate::kInvalidOffset, byteOffset);
  }
}

// 22.2.4.6 TypedArrayCreate ( constructor, argumentList )
// ES #typedarray-create
@export
transitioning macro TypedArrayCreateByLength(
    implicit context: Context)(constructor: Constructor, length: Number,
    methodName: constexpr string): JSTypedArray {
  dcheck(IsSafeInteger(length));

  // 1. Let newTypedArray be ? Construct(constructor, argumentList).
  const newTypedArrayObj = Construct(constructor, length);

  // 2. Perform ? ValidateTypedArray(newTypedArray).
  //    ValidateTypedArray currently returns the array, not the ViewBuffer.
  const newTypedArrayLength =
      ValidateTypedArrayAndGetLength(context, newTypedArrayObj, methodName);
  const newTypedArray: JSTypedArray =
      UnsafeCast<JSTypedArray>(newTypedArrayObj);

  dcheck(
      newTypedArray.bit_field.is_backed_by_rab ==
      (IsResizableArrayBuffer(newTypedArray.buffer) &&
       !IsSharedArrayBuffer(newTypedArray.buffer)));
  dcheck(
      !newTypedArray.bit_field.is_length_tracking ||
      IsResizableArrayBuffer(newTypedArray.buffer));

  if (IsDetachedBuffer(newTypedArray.buffer)) deferred {
      ThrowTypeError(MessageTemplate::kDetachedOperation, methodName);
    }

  // 3. If argumentList is a List of a single Number, then
  //   a. If newTypedArray.[[ArrayLength]] < argumentList[0], throw a
  //      TypeError exception.
  if (newTypedArrayLength < Convert<uintptr>(length)) deferred {
      ThrowTypeError(MessageTemplate::kTypedArrayTooShort);
    }

  // 4. Return newTypedArray.
  return newTypedArray;
}

transitioning macro ConstructByJSReceiver(
    implicit context: Context)(obj: JSReceiver): never
    labels IfConstructByArrayLike(JSReceiver, uintptr),
    IfIteratorNotCallable(JSAny) {
  try {
    // TODO(v8:8906): Use iterator::GetIteratorMethod() once it supports
    // labels.
    const iteratorMethod = GetMethod(obj, IteratorSymbolConstant())
        otherwise IfIteratorUndefined, IfIteratorNotCallable;
    ConstructByIterable(obj, iteratorMethod)
        otherwise IfConstructByArrayLike;
  } label IfIteratorUndefined {
    const lengthObj: JSAny = GetProperty(obj, kLengthString);
    const lengthNumber: Number = ToLength_Inline(lengthObj);
    // Throw RangeError here if the length does not fit in uintptr because
    // such a length will not pass bounds checks in ConstructByArrayLike()
    // anyway.
    const length: uintptr = ChangeSafeIntegerNumberToUintPtr(lengthNumber)
        otherwise goto IfInvalidLength(lengthNumber);
    goto IfConstructByArrayLike(obj, length);
  } label IfInvalidLength(length: Number) {
    ThrowRangeError(MessageTemplate::kInvalidTypedArrayLength, length);
  }
}

// 22.2.4 The TypedArray Constructors
// ES #sec-typedarray-constructors
transitioning builtin CreateTypedArray(
    context: Context, target: JSFunction, newTarget: JSReceiver, arg1: JSAny,
    arg2: JSAny, arg3: JSAny): JSTypedArray {
  dcheck(IsConstructor(target));
  // 4. Let O be ? AllocateTypedArray(constructorName, NewTarget,
  // "%TypedArrayPrototype%").
  try {
    typeswitch (arg1) {
      case (length: Smi): {
        goto IfConstructByLength(length);
      }
      case (buffer: JSArrayBuffer): {
        return ConstructByArrayBuffer(target, newTarget, buffer, arg2, arg3);
      }
      case (typedArray: JSTypedArray): {
        ConstructByTypedArray(typedArray) otherwise IfConstructByArrayLike;
      }
      case (obj: JSReceiver): {
        ConstructByJSReceiver(obj) otherwise IfConstructByArrayLike,
            IfIteratorNotCallable;
      }
      // The first argument was a number or fell through and is treated as
      // a number. https://tc39.github.io/ecma262/#sec-typedarray-length
      case (lengthObj: JSAny): {
        goto IfConstructByLength(lengthObj);
      }
    }
  } label IfConstructByLength(length: JSAny) {
    const map = GetDerivedMap(target, newTarget);
    // 5. Let elementSize be the Number value of the Element Size value in Table
    // 56 for constructorName.
    const elementsInfo = GetTypedArrayElementsInfo(map);

    return ConstructByLength(map, length, elementsInfo);
  } label IfConstructByArrayLike(arrayLike: JSReceiver, length: uintptr) {
    const map = GetDerivedMap(target, newTarget);
    // 5. Let elementSize be the Number value of the Element Size value in Table
    // 56 for constructorName.
    const elementsInfo = GetTypedArrayElementsInfo(map);
    return ConstructByArrayLike(map, arrayLike, length, elementsInfo);
  } label IfIteratorNotCallable(_value: JSAny) deferred {
    ThrowTypeError(
        MessageTemplate::kFirstArgumentIteratorSymbolNonCallable,
        'TypedArray\'s constructor');
  }
}

transitioning macro TypedArraySpeciesCreate(
    implicit context: Context)(methodName: constexpr string,
    numArgs: constexpr int31, exemplar: JSTypedArray, arg0: JSAny, arg1: JSAny,
    arg2: JSAny): JSTypedArray {
  const defaultConstructor = GetDefaultConstructor(exemplar);

  try {
    if (!IsPrototypeTypedArrayPrototype(exemplar.map)) goto IfSlow;
    if (IsTypedArraySpeciesProtectorCellInvalid()) goto IfSlow;

    const typedArray = CreateTypedArray(
        context, defaultConstructor, defaultConstructor, arg0, arg1, arg2);

    // It is assumed that the CreateTypedArray builtin does not produce a
    // typed array that fails ValidateTypedArray
    dcheck(!IsDetachedBuffer(typedArray.buffer));

    return typedArray;
  } label IfSlow deferred {
    const constructor =
        Cast<Constructor>(SpeciesConstructor(exemplar, defaultConstructor))
        otherwise unreachable;

    // TODO(pwong): Simplify and remove numArgs when varargs are supported in
    // macros.
    let newObj: JSAny = Undefined;
    if constexpr (numArgs == 1) {
      newObj = Construct(constructor, arg0);
    } else {
      dcheck(numArgs == 3);
      newObj = Construct(constructor, arg0, arg1, arg2);
    }

    return ValidateTypedArray(context, newObj, methodName);
  }
}

@export
transitioning macro TypedArraySpeciesCreateByLength(
    implicit context: Context)(methodName: constexpr string,
    exemplar: JSTypedArray, length: uintptr): JSTypedArray {
  const numArgs: constexpr int31 = 1;
  // TODO(v8:4153): pass length further as uintptr.
  const typedArray: JSTypedArray = TypedArraySpeciesCreate(
      methodName, numArgs, exemplar, Convert<Number>(length), Undefined,
      Undefined);
  try {
    const createdArrayLength =
        LoadJSTypedArrayLengthAndCheckDetached(typedArray)
        otherwise DetachedOrOutOfBounds;
    if (createdArrayLength < length) deferred {
        ThrowTypeError(MessageTemplate::kTypedArrayTooShort);
      }
  } label DetachedOrOutOfBounds {
    ThrowTypeError(MessageTemplate::kTypedArrayTooShort);
  }
  return typedArray;
}

transitioning macro TypedArraySpeciesCreateByBuffer(
    implicit context: Context)(methodName: constexpr string,
    exemplar: JSTypedArray, buffer: JSArrayBuffer, beginByteOffset: uintptr,
    newLength: NumberOrUndefined): JSTypedArray {
  const numArgs: constexpr int31 = 3;
  // TODO(v8:4153): pass length further as uintptr.
  const typedArray: JSTypedArray = TypedArraySpeciesCreate(
      methodName, numArgs, exemplar, buffer, Convert<Number>(beginByteOffset),
      newLength);
  return typedArray;
}

transitioning macro TypedArrayCreateSameType(
    implicit context: Context)(exemplar: JSTypedArray,
    newLength: uintptr): JSTypedArray {
  const constructor = GetDefaultConstructor(exemplar);
  const typedArray = CreateTypedArray(
      context, constructor, constructor, Convert<Number>(newLength), Undefined,
      Undefined);
  dcheck(!IsDetachedBuffer(typedArray.buffer));
  // The elements kind are equal up to resizability / growability. The newly
  // created TypedArray is never backed by a resizable / growable buffer.
  dcheck(
      GetNonRabGsabElementsKind(exemplar.elements_kind) ==
      typedArray.elements_kind);
  return typedArray;
}
}

"""

```