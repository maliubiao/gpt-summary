Response: Let's break down the thought process for analyzing this Torque code.

1. **Initial Scan and Keyword Recognition:**  The first step is to quickly scan the code, looking for familiar keywords and structural elements. Keywords like `type`, `macro`, `namespace`, `struct`, `intrinsic`, `extends`, `if`, `goto`, `return`, `labels`, `const`, `let`, `while`, `dcheck`, `extern` jump out. This gives a high-level understanding that the code defines data structures (`struct`, `type`), functions/operations (`macro`, `intrinsic`), and uses control flow (`if`, `goto`, `while`). The `torque_internal` namespace suggests this is internal V8 infrastructure.

2. **Understanding Core Concepts:** The code introduces `Slice` and `Reference`. These seem like fundamental building blocks for accessing memory. The names suggest a `Slice` represents a contiguous block of memory, and a `Reference` points to a specific element within that memory. The `ConstSlice` and `MutableSlice` variants suggest read-only and read-write access, respectively.

3. **Analyzing `Slice` and `Reference`:**  Delving deeper, I examine the members and macros associated with `Slice` and `Reference`.

    * **`Reference`:**  It has `object` (likely the base object in the heap), `offset` (the position within the object), and `unsafeMarker`. The `GCUnsafeRawPtr` macro hints at direct memory access, which requires careful handling in a garbage-collected environment.

    * **`Slice`:** It contains `object`, `offset`, and `length`. The macros like `Subslice`, `AtIndex`, `TryAtIndex`, `Iterator`, and `GCUnsafeStartPointer` reveal its functionality: creating sub-regions, accessing elements (with bounds checking), iterating over elements, and getting the raw memory address. The existence of `MutableSlice` and `ConstSlice` variations is consistently reflected in these macros.

4. **Examining Key Macros:**  Certain macros appear frequently and seem crucial:

    * **`Subslice`:** Clearly for creating a smaller `Slice` from a larger one. The `OutOfBounds` label indicates error handling.
    * **`TimesSizeOf<T>`:** Calculates the size in bytes of `i` elements of type `T`. This is fundamental for memory manipulation.
    * **`unsafe::NewReference`, `unsafe::NewMutableSlice`, `unsafe::NewConstSlice`:** These are the constructors for `Reference` and `Slice` types, emphasizing the "unsafe" nature of direct memory manipulation.
    * **`AtIndex` and `TryAtIndex`:** Methods for accessing elements in the `Slice`, with `TryAtIndex` providing explicit error handling (`OutOfBounds`).
    * **`Iterator`:**  Provides a way to traverse the elements of a `Slice`.

5. **Identifying the Purpose of `torque_internal`:** The namespace name and the presence of the `Unsafe` marker strongly suggest that this code provides low-level, potentially dangerous, memory manipulation primitives for internal V8 use. It likely forms the basis for higher-level abstractions.

6. **Connecting to JavaScript (if applicable):**  The question asks for connections to JavaScript. While this code itself isn't directly exposed to JavaScript, it *enables* the implementation of JavaScript features. The concept of arrays and typed arrays in JavaScript directly relates to the `Slice` functionality. JavaScript's bounds checking on array access aligns with the `TryAtIndex` macro.

7. **Generating JavaScript Examples:** Based on the understanding of `Slice` and `Reference`, I can construct JavaScript analogies:

    * **`Slice` as Array/TypedArray:**  Demonstrates how a `Slice` represents a portion of an array.
    * **`Subslice` as `slice()` method:** Shows the equivalent JavaScript array method for creating subarrays.
    * **`AtIndex` as bracket notation:**  Illustrates the basic array access.
    * **Potential Errors:**  Highlights the JavaScript errors that correspond to the `OutOfBounds` condition in the Torque code.

8. **Analyzing Code Logic and Providing Examples:**  The `Subslice` macro is a good candidate for illustrating code logic. By providing concrete input values for the `slice`, `start`, and `length`, I can trace the execution path (both valid and `OutOfBounds` cases) and show the resulting output.

9. **Identifying Common Programming Errors:** The `OutOfBounds` checks in `Subslice` and `TryAtIndex` directly point to potential errors: accessing elements outside the bounds of an array or slice. I can provide JavaScript examples of these errors.

10. **Iterative Refinement:** After the initial analysis, I reread the code and my explanations to ensure accuracy and clarity. I look for any missing pieces or areas that need further clarification. For example, I might initially focus too much on `Slice` and then realize the importance of `Reference` and its role in accessing individual elements.

This systematic approach, moving from a high-level overview to detailed analysis of key components and then connecting those components to real-world scenarios (like JavaScript functionality and common errors), allows for a comprehensive understanding of the provided Torque code.
这段 Torque 源代码文件 `v8/src/builtins/torque-internal.tq` 定义了一些底层的、用于在 V8 的 Torque 语言中进行内存操作和数据结构处理的内部工具和类型。它与 JavaScript 的功能有间接关系，因为它提供的机制最终支撑了 JavaScript 引擎的实现。

**功能归纳:**

这个文件主要定义了以下几个核心概念和功能：

1. **`MutableSlice<T>` 和 `ConstSlice<T>`:**  表示内存中的一段连续区域（切片），分别对应可变和不可变的情况。这类似于 C++ 中的 `std::span` 或 Go 中的 slice。它们包含指向底层数据对象的指针、偏移量和长度。

2. **`Subslice` 宏:**  用于从一个已有的 `Slice` 中创建一个新的子切片。它会进行边界检查，确保子切片的起始位置和长度不会超出原始切片的范围。

3. **`unsafe` 命名空间:**  包含一些进行不安全内存操作的宏，例如 `AddOffset`，它允许在指针或引用上增加偏移量。这个命名空间的存在表明这些操作需要开发者小心使用，因为它们可能绕过类型安全检查。

4. **`torque_internal` 命名空间:**  包含一些 Torque 内部使用的结构体和宏，例如 `Unsafe` (一个标记，用于标识不安全的操作)，`SizeOf` (获取类型的大小)，`TimesSizeOf` (计算类型的倍数大小)，以及 `Reference` (表示对内存中某个位置的引用)。

5. **`Reference<T>`:**  表示对类型 `T` 的引用，它也包含指向底层对象的指针和偏移量。存在 `ConstReference` 和 `MutableReference` 的概念。

6. **`Slice<T, Reference>`:**  通用的切片结构，它使用 `Reference` 类型来指定切片中元素的访问方式（可变或不可变）。它提供了多种 `AtIndex` 宏用于安全地访问切片中的元素（带有边界检查），以及 `Iterator` 宏用于遍历切片。

7. **`SliceIterator<T, Reference>`:**  用于遍历 `Slice` 的迭代器。

8. **内存分配相关的宏:**  例如 `AddIndexedFieldSizeToObjectSize`，`AlignTagged`，`ValidAllocationSize`，`AllocateFromNew` 等，用于处理内存分配和对齐。

9. **类型转换和检查宏:**  例如 `DownCastForTorqueClass`，用于在 Torque 中进行类型转换并进行安全检查。

10. **其他实用工具:**  例如 `InitializeFieldsFromIterator` (从迭代器初始化切片字段)，`LoadFloat64OrHole`/`StoreFloat64OrHole` (处理可能为空洞的浮点数)，以及与 pending message 相关的宏。

**与 JavaScript 功能的关系及 JavaScript 示例:**

虽然这个文件中的代码不是直接的 JavaScript 代码，但它提供的底层机制是实现 JavaScript 各种功能的基础。例如：

* **数组 (Arrays) 和类型化数组 (Typed Arrays):** `MutableSlice` 和 `ConstSlice` 可以被用来表示 JavaScript 的 `ArrayBuffer` 和各种类型的 `TypedArray` (如 `Uint8Array`, `Float64Array` 等)。

   ```javascript
   // JavaScript 的 ArrayBuffer 类似于 Torque 中的一个 Slice
   const buffer = new ArrayBuffer(16);
   const uint8Array = new Uint8Array(buffer, 0, 8); // 类似于从 Slice 创建 Subslice

   uint8Array[0] = 10; // 访问 Slice 中的元素，类似于 Torque 的 AtIndex
   console.log(uint8Array[0]); // 输出 10
   ```

* **字符串 (Strings):** 字符串在 V8 内部也可能被表示为字符的切片。

* **对象的属性访问:**  当访问 JavaScript 对象的属性时，V8 可能会使用类似的偏移量计算来定位属性在内存中的位置。

**代码逻辑推理 (假设输入与输出):**

考虑 `Subslice` 宏的以下调用：

```torque
const originalSlice: ConstSlice<int32> = ...; // 假设 originalSlice 指向一个包含 [10, 20, 30, 40, 50] 的内存区域，长度为 5
const start: intptr = 1;
const length: intptr = 3;

const subSlice = Subslice<int32>(originalSlice, start, length) otherwise OutOfBoundsLabel;
```

**假设输入:**

* `originalSlice.object`: 指向包含整数数组的 `HeapObject` 的指针。
* `originalSlice.offset`: 数组在 `HeapObject` 中的起始偏移量。
* `originalSlice.length`: 5
* `start`: 1
* `length`: 3
* `SizeOf<int32>()`: 4 (假设 int32 占用 4 个字节)

**代码逻辑推理:**

1. **边界检查:**
   - `Unsigned(length) > Unsigned(slice.length)`: `Unsigned(3) > Unsigned(5)` 为 false。
   - `Unsigned(start) > Unsigned(slice.length - length)`: `Unsigned(1) > Unsigned(5 - 3)` 即 `Unsigned(1) > Unsigned(2)` 为 false。
   因此，边界检查通过。

2. **计算偏移量:**
   - `offset = slice.offset + torque_internal::TimesSizeOf<int32>(start)`
   - `offset = originalSlice.offset + 1 * 4`
   - `offset = originalSlice.offset + 4`

3. **创建子切片:**
   - `torque_internal::unsafe::NewConstSlice<int32>(originalSlice.object, offset, length)`
   - 创建一个新的 `ConstSlice<int32>`，其 `object` 与 `originalSlice` 相同，`offset` 为 `originalSlice.offset + 4`，`length` 为 3。

**预期输出:**

`subSlice` 将会是一个新的 `ConstSlice<int32>`，它指向 `originalSlice` 中从索引 1 开始的 3 个元素，即 `[20, 30, 40]`。

**如果输入导致 `OutOfBounds`:**

如果 `start` 或 `length` 的值导致任何一个边界检查失败，例如：

```torque
const subSlice = Subslice<int32>(originalSlice, 2, 5) otherwise OutOfBoundsLabel;
```

在这种情况下，`Unsigned(5) > Unsigned(5)` 为 false，但 `Unsigned(2) > Unsigned(5 - 5)` 即 `Unsigned(2) > Unsigned(0)` 为 true。因此，代码会跳转到 `OutOfBoundsLabel`。

**涉及用户常见的编程错误 (JavaScript 角度):**

这个文件中的代码主要处理底层的内存操作，与用户在 JavaScript 中直接遇到的编程错误关联性较弱。然而，它所提供的机制的错误使用会导致 V8 引擎内部的错误，这些错误最终可能会导致 JavaScript 程序的行为异常。

从 JavaScript 开发者的角度来看，与这里概念相关的常见错误是：

1. **数组越界访问:**  类似于 `Subslice` 中的边界检查，JavaScript 中访问数组超出其索引范围会导致错误（在严格模式下）或返回 `undefined`。

   ```javascript
   const arr = [1, 2, 3];
   console.log(arr[3]); // 输出 undefined (非严格模式) 或抛出错误 (严格模式)
   ```

2. **类型错误:** 虽然 Torque 有类型系统，JavaScript 是一种动态类型语言，但在处理类型化数组时，如果操作的类型与数组的类型不匹配，可能会导致错误。

   ```javascript
   const uint8 = new Uint8Array(1);
   uint8[0] = "hello"; // 尝试将字符串赋值给数字类型，会被隐式转换，可能不是预期行为
   ```

3. **内存泄漏 (间接相关):** 虽然用户无法直接控制 V8 的内存管理，但如果 V8 的内部实现（使用了类似 `Slice` 的结构）存在错误，可能导致内存泄漏。

**总结:**

`v8/src/builtins/torque-internal.tq` 文件定义了 V8 内部用于处理内存切片、引用和进行底层操作的关键工具。它为 Torque 编写的 built-in 函数提供了基础的数据结构和操作方法，最终支撑了 JavaScript 的各种语言特性。虽然用户不会直接编写 Torque 代码，但理解这些底层的概念有助于理解 JavaScript 引擎的工作原理以及可能出现的性能问题和错误。

### 提示词
```
这是目录为v8/src/builtins/torque-internal.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unfortunately, MutableSlice<> is currently not a subtype of ConstSlice.
// This would require struct subtyping, which is not yet supported.
type MutableSlice<T: type> extends torque_internal::Slice<T, &T>;
type ConstSlice<T: type> extends torque_internal::Slice<T, const &T>;

macro Subslice<T: type>(
    slice: ConstSlice<T>, start: intptr,
    length: intptr): ConstSlice<T>labels OutOfBounds {
  if (Unsigned(length) > Unsigned(slice.length)) goto OutOfBounds;
  if (Unsigned(start) > Unsigned(slice.length - length)) goto OutOfBounds;
  const offset = slice.offset + torque_internal::TimesSizeOf<T>(start);
  return torque_internal::unsafe::NewConstSlice<T>(
      slice.object, offset, length);
}
macro Subslice<T: type>(
    slice: MutableSlice<T>, start: intptr,
    length: intptr): MutableSlice<T>labels OutOfBounds {
  if (Unsigned(length) > Unsigned(slice.length)) goto OutOfBounds;
  if (Unsigned(start) > Unsigned(slice.length - length)) goto OutOfBounds;
  const offset = slice.offset + torque_internal::TimesSizeOf<T>(start);
  return torque_internal::unsafe::NewMutableSlice<T>(
      slice.object, offset, length);
}

namespace unsafe {

macro AddOffset<T: type>(ref: &T, offset: intptr): &T {
  return torque_internal::unsafe::NewReference<T>(
      ref.object, ref.offset + torque_internal::TimesSizeOf<T>(offset));
}

macro AddOffset<T: type>(ref: const &T, offset: intptr): const &T {
  return torque_internal::unsafe::NewReference<T>(
      ref.object, ref.offset + torque_internal::TimesSizeOf<T>(offset));
}

}  // namespace unsafe

namespace torque_internal {
// Unsafe is a marker that we require to be passed when calling internal APIs
// that might lead to unsoundness when used incorrectly. Unsafe markers should
// therefore not be instantiated anywhere outside of this namespace.
struct Unsafe {}

// Size of a type in memory (on the heap). For class types, this is the size
// of the pointer, not of the instance.
intrinsic %SizeOf<T: type>(): constexpr int31;

// `SizeOf` without the `%` to allow uses outside of `torque_internal`.
macro SizeOf<T: type>(): constexpr int31 {
  return %SizeOf<T>();
}

macro TimesSizeOf<T: type>(i: intptr): intptr {
  return i * %SizeOf<T>();
}

struct Reference<T: type> {
  macro GCUnsafeRawPtr(): RawPtr<T> {
    return %RawDownCast<RawPtr<T>>(
        unsafe::GCUnsafeReferenceToRawPtr(this.object, this.offset));
  }

  const object: HeapObject|TaggedZeroPattern;
  const offset: intptr;
  unsafeMarker: Unsafe;
}
type ConstReference<T: type> extends Reference<T>;
type MutableReference<T: type> extends ConstReference<T>;

namespace unsafe {
macro NewReference<T: type>(
    object: HeapObject|TaggedZeroPattern, offset: intptr):&T {
  return %RawDownCast<&T>(
      Reference<T>{object: object, offset: offset, unsafeMarker: Unsafe {}});
}
macro NewOffHeapReference<T: type>(ptr: RawPtr<T>):&T {
  return %RawDownCast<&T>(Reference<T>{
    object: kZeroBitPattern,
    offset: Convert<intptr>(Convert<RawPtr>(ptr)) + kHeapObjectTag,
    unsafeMarker: Unsafe {}
  });
}
macro ReferenceCast<T: type, U: type>(ref:&U):&T {
  const ref = NewReference<T>(ref.object, ref.offset);
  UnsafeCast<T>(*ref);
  return ref;
}

extern macro GCUnsafeReferenceToRawPtr(HeapObject|TaggedZeroPattern, intptr):
    RawPtr;

}  // namespace unsafe

struct Slice<T: type, Reference: type> {
  macro TryAtIndex(index: intptr): Reference labels OutOfBounds {
    if (Convert<uintptr>(index) < Convert<uintptr>(this.length)) {
      return this.UncheckedAtIndex(index);
    } else {
      goto OutOfBounds;
    }
  }
  macro UncheckedAtIndex(index: intptr): Reference {
    return unsafe::NewReference<T>(
        this.object, this.offset + TimesSizeOf<T>(index));
  }

  macro AtIndex(index: intptr): Reference {
    return this.TryAtIndex(index) otherwise unreachable;
  }

  macro AtIndex(index: uintptr): Reference {
    return this.TryAtIndex(Convert<intptr>(index)) otherwise unreachable;
  }

  macro AtIndex(index: constexpr IntegerLiteral): Reference {
    return this.AtIndex(FromConstexpr<uintptr>(index));
  }

  macro AtIndex(index: constexpr int31): Reference {
    const i: intptr = Convert<intptr>(index);
    return this.TryAtIndex(i) otherwise unreachable;
  }

  macro AtIndex(index: Smi): Reference {
    const i: intptr = Convert<intptr>(index);
    return this.TryAtIndex(i) otherwise unreachable;
  }

  macro AtIndex(index: uint32): Reference {
    const i: intptr = Convert<intptr>(index);
    return this.TryAtIndex(i) otherwise unreachable;
  }

  macro Iterator(): SliceIterator<T, Reference> {
    const end = this.offset + TimesSizeOf<T>(this.length);
    return SliceIterator<T, Reference>{
      object: this.object,
      start: this.offset,
      end: end,
      unsafeMarker: Unsafe {}
    };
  }
  macro Iterator(startIndex: intptr, endIndex: intptr):
      SliceIterator<T, Reference> {
    check(
        Convert<uintptr>(endIndex) <= Convert<uintptr>(this.length) &&
        Convert<uintptr>(startIndex) <= Convert<uintptr>(endIndex));
    const start = this.offset + TimesSizeOf<T>(startIndex);
    const end = this.offset + TimesSizeOf<T>(endIndex);
    return SliceIterator<T, Reference>{
      object: this.object,
      start,
      end,
      unsafeMarker: Unsafe {}
    };
  }

  // WARNING: This can return a raw pointer into the heap, which is not GC-safe.
  macro GCUnsafeStartPointer(): RawPtr<T> {
    return %RawDownCast<RawPtr<T>>(
        unsafe::GCUnsafeReferenceToRawPtr(this.object, this.offset));
  }

  const object: HeapObject|TaggedZeroPattern;
  const offset: intptr;
  const length: intptr;
  unsafeMarker: Unsafe;
}

namespace unsafe {

macro NewMutableSlice<T: type>(
    object: HeapObject|TaggedZeroPattern, offset: intptr,
    length: intptr): MutableSlice<T> {
  return %RawDownCast<MutableSlice<T>>(Slice<T, &T>{
    object: object,
    offset: offset,
    length: length,
    unsafeMarker: Unsafe {}
  });
}

macro NewConstSlice<T: type>(
    object: HeapObject|TaggedZeroPattern, offset: intptr,
    length: intptr): ConstSlice<T> {
  return %RawDownCast<ConstSlice<T>>(Slice<T, const &T>{
    object: object,
    offset: offset,
    length: length,
    unsafeMarker: Unsafe {}
  });
}

macro NewOffHeapMutableSlice<T: type>(
    startPointer: RawPtr<T>, length: intptr): MutableSlice<T> {
  return %RawDownCast<MutableSlice<T>>(Slice<T, &T>{
    object: kZeroBitPattern,
    offset: Convert<intptr>(Convert<RawPtr>(startPointer)) + kHeapObjectTag,
    length: length,
    unsafeMarker: Unsafe {}
  });
}

macro NewOffHeapConstSlice<T: type>(
    startPointer: RawPtr<T>, length: intptr): ConstSlice<T> {
  return %RawDownCast<ConstSlice<T>>(Slice<T, const &T>{
    object: kZeroBitPattern,
    offset: Convert<intptr>(Convert<RawPtr>(startPointer)) + kHeapObjectTag,
    length: length,
    unsafeMarker: Unsafe {}
  });
}

}  // namespace unsafe

struct SliceIterator<T: type, Reference: type> {
  macro Empty(): bool {
    return this.start == this.end;
  }

  macro Next(): T labels NoMore {
    return *this.NextReference() otherwise NoMore;
  }

  macro NextNotEmpty(): T {
    return *this.NextReferenceNotEmpty();
  }

  macro NextReference(): Reference labels NoMore {
    if (this.Empty()) {
      goto NoMore;
    } else {
      const result = unsafe::NewReference<T>(this.object, this.start);
      this.start += %SizeOf<T>();
      return result;
    }
  }

  macro NextReferenceNotEmpty(): Reference {
    dcheck(!this.Empty());
    const result = unsafe::NewReference<T>(this.object, this.start);
    this.start += %SizeOf<T>();
    return result;
  }

  object: HeapObject|TaggedZeroPattern;
  start: intptr;
  end: intptr;
  unsafeMarker: Unsafe;
}

macro AddIndexedFieldSizeToObjectSize(
    baseSize: intptr, arrayLength: intptr, fieldSize: constexpr int32): intptr {
  const arrayLength = Convert<int32>(arrayLength);
  const byteLength = TryInt32Mul(arrayLength, fieldSize)
      otherwise unreachable;
  return TryIntPtrAdd(baseSize, Convert<intptr>(byteLength))
      otherwise unreachable;
}

macro AlignTagged(x: intptr): intptr {
  // Round up to a multiple of kTaggedSize.
  return (x + kObjectAlignmentMask) & ~kObjectAlignmentMask;
}

macro IsTaggedAligned(x: intptr): bool {
  return (x & kObjectAlignmentMask) == 0;
}

macro ValidAllocationSize(sizeInBytes: intptr, map: Map): bool {
  if (sizeInBytes <= 0) return false;
  if (!IsTaggedAligned(sizeInBytes)) return false;
  const instanceSizeInWords = Convert<intptr>(map.instance_size_in_words);
  return instanceSizeInWords == kVariableSizeSentinel ||
      instanceSizeInWords * kTaggedSize == sizeInBytes;
}

type UninitializedHeapObject extends HeapObject;

extern macro GetInstanceTypeMap(constexpr InstanceType): Map;
extern macro Allocate(intptr, constexpr AllocationFlag):
    UninitializedHeapObject;

macro AllocateFromNew(
    sizeInBytes: intptr, map: Map, pretenured: bool,
    clearPadding: bool): UninitializedHeapObject {
  dcheck(ValidAllocationSize(sizeInBytes, map));
  let res: UninitializedHeapObject;
  if (pretenured) {
    res = Allocate(
        sizeInBytes,
        %RawConstexprCast<constexpr AllocationFlag>(
            %RawConstexprCast<constexpr int32>(AllocationFlag::kPretenured)));
  } else {
    res = Allocate(sizeInBytes, AllocationFlag::kNone);
  }
  if (clearPadding) {
    *unsafe::NewReference<Zero>(res, sizeInBytes - kObjectAlignment) = kZero;
  }
  return res;
}

macro InitializeFieldsFromIterator<T: type, Iterator: type>(
    target: MutableSlice<T>, originIterator: Iterator): void {
  let targetIterator = target.Iterator();
  let originIterator = originIterator;
  while (true) {
    const ref:&T = targetIterator.NextReference() otherwise break;
    *ref = originIterator.Next() otherwise unreachable;
  }
}
// Dummy implementations: do not initialize for UninitializedIterator.
InitializeFieldsFromIterator<char8, UninitializedIterator>(
    _target: MutableSlice<char8>,
    _originIterator: UninitializedIterator): void {}
InitializeFieldsFromIterator<char16, UninitializedIterator>(
    _target: MutableSlice<char16>,
    _originIterator: UninitializedIterator): void {}

extern macro IsDoubleHole(HeapObject, intptr): bool;
extern macro StoreDoubleHole(HeapObject, intptr): void;

macro LoadFloat64OrHole(r:&float64_or_hole): float64_or_hole {
  return float64_or_hole{
    is_hole: IsDoubleHole(
        %RawDownCast<HeapObject>(r.object), r.offset - kHeapObjectTag),
    value: *unsafe::NewReference<float64>(r.object, r.offset)
  };
}
macro StoreFloat64OrHole(r:&float64_or_hole, value: float64_or_hole): void {
  if (value.is_hole) {
    StoreDoubleHole(
        %RawDownCast<HeapObject>(r.object), r.offset - kHeapObjectTag);
  } else {
    *unsafe::NewReference<float64>(r.object, r.offset) = value.value;
  }
}

macro DownCastForTorqueClass<T : type extends HeapObject>(o: HeapObject):
    T labels CastError {
  const map = o.map;
  const minInstanceType = %MinInstanceType<T>();
  const maxInstanceType = %MaxInstanceType<T>();
  if constexpr (minInstanceType == maxInstanceType) {
    if constexpr (%ClassHasMapConstant<T>()) {
      if (map != %GetClassMapConstant<T>()) goto CastError;
    } else {
      if (map.instance_type != minInstanceType) goto CastError;
    }
  } else {
    const diff: int32 = maxInstanceType - minInstanceType;
    const offset = Convert<int32>(Convert<uint16>(map.instance_type)) -
        Convert<int32>(Convert<uint16>(
            FromConstexpr<InstanceType>(minInstanceType)));
    if (Unsigned(offset) > Unsigned(diff)) goto CastError;
  }
  return %RawDownCast<T>(o);
}

extern macro StaticAssert(bool, constexpr string): void;

// This is for the implementation of the dot operator. In any context where the
// dot operator is available, the correct way to get the length of an indexed
// field x from object o is `(&o.x).length`.
intrinsic %IndexedFieldLength<T: type>(o: T, f: constexpr string): intptr;

// If field x is defined as optional, then &o.x returns a reference to the field
// or crashes the program (unreachable) if the field is not present. Usually
// that's the most convenient behavior, but in rare cases such as the
// implementation of the dot operator, we may instead need to get a Slice to the
// optional field, which is either length zero or one depending on whether the
// field is present. This intrinsic provides Slices for both indexed fields
// (equivalent to &o.x) and optional fields.
intrinsic %FieldSlice<T: type, TSlice: type>(o: T, f: constexpr string):
    TSlice;

extern macro GetPendingMessage(): TheHole|JSMessageObject;
extern macro SetPendingMessage(TheHole|JSMessageObject): void;

// This is implicitly performed at the beginning of Torque catch-blocks.
macro GetAndResetPendingMessage(): TheHole|JSMessageObject {
  const message = GetPendingMessage();
  SetPendingMessage(TheHole);
  return message;
}

}  // namespace torque_internal

// Indicates that an array-field should not be initialized.
// For safety reasons, this is only allowed for untagged types.
struct UninitializedIterator {}

// %RawDownCast should *never* be used anywhere in Torque code except for
// in Torque-based UnsafeCast operators preceeded by an appropriate
// type dcheck()
intrinsic %RawDownCast<To: type, From: type>(x: From): To;
intrinsic %RawConstexprCast<To: type, From: type>(f: From): To;

intrinsic %MinInstanceType<T: type>(): constexpr InstanceType;
intrinsic %MaxInstanceType<T: type>(): constexpr InstanceType;

intrinsic %ClassHasMapConstant<T: type>(): constexpr bool;
intrinsic %GetClassMapConstant<T: type>(): Map;

struct IteratorSequence<
    T: type, FirstIterator: type, SecondIterator: type> {
  macro Empty(): bool {
    return this.first.Empty() && this.second.Empty();
  }

  macro Next(): T labels NoMore {
    return this.first.Next()
        otherwise return (this.second.Next() otherwise NoMore);
  }

  first: FirstIterator;
  second: SecondIterator;
}

macro
IteratorSequence<T: type, FirstIterator: type, SecondIterator: type>(
    first: FirstIterator, second: SecondIterator):
    IteratorSequence<T, FirstIterator, SecondIterator> {
  return IteratorSequence<T>{first, second};
}
```