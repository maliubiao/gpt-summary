Response:
The user wants a summary of the C++ header file `v8/src/objects/fixed-array.h`. I need to go through the code and identify the main functionalities provided by this file.

Here's a breakdown of the classes and their purposes:

- **`ArrayHeaderBase`**:  A base class for array headers, handling either length or capacity depending on a template parameter.
- **`TaggedArrayBase`**: A template class for arrays that store tagged pointers. It provides methods for getting and setting elements, moving/copying elements, and managing the array's size.
- **`FixedArray`**:  A concrete `TaggedArrayBase` that stores `Object` type elements. This is a fundamental array type in V8.
- **`TrustedFixedArray`**:  Similar to `FixedArray` but resides in the trusted heap and has a unique instance type.
- **`ProtectedFixedArray`**:  Stores protected pointers (to trusted objects) and resides in the trusted heap.
- **`FixedArrayExact`**: An alias for `FixedArray`, likely used for exact type checking.
- **`FixedArrayBase`**:  A base class for FixedArrays, providing some common properties and methods.
- **`PrimitiveArrayBase`**: A template class for arrays storing primitive types (like `double`, `uint8_t`).
- **`FixedDoubleArray`**: An array specifically for storing `double` values.
- **`WeakFixedArray`**:  An array holding weak references ( `MaybeObject`).
- **`TrustedWeakFixedArray`**: A `WeakFixedArray` located in the trusted heap.
- **`WeakArrayList`**: A dynamically growing array for weak references.
- **`ArrayList`**: A dynamically growing array for general `Object` type elements.
- **`ByteArray`**: An array for storing raw bytes.
- **`TrustedByteArray`**: A `ByteArray` in the trusted heap.
- **`FixedIntegerArrayBase`**: A template for creating arrays of fixed-size integers based on `ByteArray`.
- **`FixedAddressArrayBase`**: A template for creating arrays of raw memory addresses.
- **`PodArrayBase`**: A template for arrays of plain-old-data types, providing methods for copying data in and out.

The file defines various fixed-size and dynamically growing array types used internally by V8. These arrays are crucial for storing different kinds of data within the JavaScript engine's heap. The "trusted" variants are for storing data that is considered safe and doesn't require the same level of security checks.
好的，根据您提供的代码，`v8/src/objects/fixed-array.h` 的主要功能是定义了 V8 引擎中各种固定大小和可变大小数组的结构和操作。

以下是其功能的归纳：

1. **定义了多种类型的数组**:
    *   **`FixedArray`**: 这是最基础的固定大小数组，用于存储 `Object` 类型的元素（可以是指针或者 Smi）。
    *   **`TrustedFixedArray`**:  与 `FixedArray` 类似，但位于受信任的堆空间中，拥有唯一的实例类型。
    *   **`ProtectedFixedArray`**:  位于受信任的堆空间中，用于存储受保护的指针（指向其他的受信任对象）。
    *   **`FixedDoubleArray`**: 用于存储 `double` (双精度浮点数) 类型的元素。
    *   **`WeakFixedArray`**: 用于存储弱引用 (`MaybeObject`)，这些引用不会阻止垃圾回收。
    *   **`TrustedWeakFixedArray`**: 位于受信任堆空间的 `WeakFixedArray`。
    *   **`ByteArray`**: 用于存储原始字节数据 (`uint8_t`)，不被垃圾回收器扫描。
    *   **`TrustedByteArray`**: 位于受信任堆空间的 `ByteArray`。
    *   **`ArrayList`**:  动态增长的数组，用于存储 `Object` 类型的元素。
    *   **`WeakArrayList`**: 动态增长的数组，用于存储弱引用 (`MaybeObject`)。
    *   **`FixedArrayExact`**:  `FixedArray` 的别名，可能用于精确的类型检查。
    *   **`FixedIntegerArrayBase`**: 一个模板类，用于基于 `ByteArray` 创建固定大小的整数数组（如 `FixedInt8Array`, `FixedUInt32Array` 等）。
    *   **`FixedAddressArrayBase`**: 一个模板类，用于创建存储内存地址的数组。
    *   **`PodArrayBase`**:  一个模板类，用于存储普通数据类型 (Plain Old Data)，并提供高效的内存拷贝方法。

2. **提供了数组的基本操作**:
    *   **获取和设置元素**: 提供了 `get()` 和 `set()` 方法来访问和修改数组中的元素。针对不同的元素类型和内存模型（例如，是否需要写屏障）提供了不同的重载版本。
    *   **获取数组长度/容量**: 提供了 `length()` 和 `capacity()` 方法来获取数组的长度和容量。
    *   **内存管理**: 包含创建新数组的 `New()` 静态方法，以及调整数组大小 (`Resize()`) 和修剪数组 (`RightTrim()`) 的方法。
    *   **元素移动和拷贝**: 提供了 `MoveElements()` 和 `CopyElements()` 静态方法，用于在数组之间移动或复制元素。
    *   **填充**: 提供了 `FillWithHoles()` 方法，用于用特定的 "洞" 值填充数组。
    *   **比较和交换**: 提供了原子操作 `compare_and_swap()`。

3. **支持不同的内存模型和元素类型**:
    *   **Tagged 和 Untagged**:  区分存储 tagged 指针（可能指向堆中的对象或 Smi）和原始值（如 `double` 或 `uint8_t`）的数组。
    *   **受信任空间**: 定义了位于受信任堆空间中的数组类型，这些数组可能具有不同的安全性和访问特性。
    *   **弱引用**: 提供了存储弱引用的数组类型，允许在对象不再被强引用时进行垃圾回收。

4. **定义了数组的元数据**:
    *   **Shape**: 使用 `Shape` 结构体来定义数组的元素类型、压缩方案和对应的 Map 根索引。
    *   **Header**: 定义了数组对象的头部结构，包含长度或容量等信息。

5. **为动态数组提供了增长机制**:
    *   **`ArrayList` 和 `WeakArrayList`**:  提供了动态增长的功能，允许在需要时添加更多元素。

**关于文件名以 `.tq` 结尾**:  您提供的代码片段是 C++ 头文件 (`.h`)，并且其中包含了 `#include "torque-generated/src/objects/fixed-array-tq.inc"`. 这表示 V8 使用 Torque 语言来生成某些部分的 C++ 代码。如果 `v8/src/objects/fixed-array.h` 文件本身以 `.tq` 结尾，那么它确实是一个 Torque 源代码文件，用于描述对象的布局和访问方式，然后会被编译成 C++ 代码。

**与 JavaScript 的关系**:  这些数组类型是 V8 引擎实现 JavaScript 数组的基础。JavaScript 中的 `Array` 对象在底层可以使用这些固定或可变大小的数组来存储其元素。

**功能总结**: `v8/src/objects/fixed-array.h` 定义了 V8 引擎中用于存储各种类型数据的核心数据结构——不同类型的固定大小和动态大小的数组。这些数组是 V8 实现 JavaScript 数组和其他内部数据结构的关键组成部分，提供了高效的内存管理和元素访问机制。

Prompt: 
```
这是目录为v8/src/objects/fixed-array.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/fixed-array.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_FIXED_ARRAY_H_
#define V8_OBJECTS_FIXED_ARRAY_H_

#include <optional>

#include "src/common/globals.h"
#include "src/handles/maybe-handles.h"
#include "src/objects/heap-object.h"
#include "src/objects/instance-type.h"
#include "src/objects/maybe-object.h"
#include "src/objects/objects.h"
#include "src/objects/smi.h"
#include "src/objects/tagged.h"
#include "src/objects/trusted-object.h"
#include "src/roots/roots.h"
#include "src/utils/memcopy.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8::internal {

#include "torque-generated/src/objects/fixed-array-tq.inc"

namespace detail {
template <class Super, bool kLengthEqualsCapacity>
class ArrayHeaderBase;

V8_OBJECT template <class Super>
class ArrayHeaderBase<Super, false> : public Super {
 public:
  inline int capacity() const;
  inline int capacity(AcquireLoadTag tag) const;
  inline void set_capacity(int value);
  inline void set_capacity(int value, ReleaseStoreTag tag);

  // TODO(leszeks): Make this private.
 public:
  TaggedMember<Smi> capacity_;
} V8_OBJECT_END;

V8_OBJECT template <class Super>
class ArrayHeaderBase<Super, true> : public Super {
 public:
  inline int length() const;
  inline int length(AcquireLoadTag tag) const;
  inline void set_length(int value);
  inline void set_length(int value, ReleaseStoreTag tag);

  inline int capacity() const;
  inline int capacity(AcquireLoadTag tag) const;
  inline void set_capacity(int value);
  inline void set_capacity(int value, ReleaseStoreTag tag);

  // TODO(leszeks): Make this private.
 public:
  TaggedMember<Smi> length_;
} V8_OBJECT_END;

template <class Shape, class Super, typename = void>
struct TaggedArrayHeaderHelper {
  using type = ArrayHeaderBase<Super, Shape::kLengthEqualsCapacity>;
};
template <class Shape, class Super>
struct TaggedArrayHeaderHelper<
    Shape, Super, std::void_t<typename Shape::template ExtraFields<Super>>> {
  using BaseHeader = ArrayHeaderBase<Super, Shape::kLengthEqualsCapacity>;
  using type = typename Shape::template ExtraFields<BaseHeader>;
  static_assert(std::is_base_of<BaseHeader, type>::value);
};
template <class Shape, class Super>
using TaggedArrayHeader = typename TaggedArrayHeaderHelper<Shape, Super>::type;
}  // namespace detail

#define V8_ARRAY_EXTRA_FIELDS(...)    \
  V8_OBJECT template <typename Super> \
  struct ExtraFields : public Super __VA_ARGS__ V8_OBJECT_END

// Derived: must not have any fields - extra fields can be specified in the
// Shap using V8_ARRAY_EXTRA_FIELDS.
V8_OBJECT template <class Derived, class ShapeT, class Super = HeapObjectLayout>
class TaggedArrayBase : public detail::TaggedArrayHeader<ShapeT, Super> {
  static_assert(std::is_base_of<HeapObjectLayout, Super>::value);
  using ElementT = typename ShapeT::ElementT;

  static_assert(sizeof(TaggedMember<ElementT>) == kTaggedSize);
  static_assert(is_subtype_v<ElementT, MaybeObject>);

  using ElementMemberT =
      TaggedMember<ElementT, typename ShapeT::CompressionScheme>;

  template <typename ElementT>
  static constexpr bool kSupportsSmiElements =
      std::is_convertible_v<Smi, ElementT>;

  static constexpr WriteBarrierMode kDefaultMode =
      std::is_same_v<ElementT, Smi> ? SKIP_WRITE_BARRIER : UPDATE_WRITE_BARRIER;

 public:
  using Header = detail::TaggedArrayHeader<ShapeT, Super>;
  static constexpr bool kElementsAreMaybeObject = is_maybe_weak_v<ElementT>;
  static constexpr int kElementSize = kTaggedSize;

 private:
  using SlotType =
      std::conditional_t<kElementsAreMaybeObject, MaybeObjectSlot, ObjectSlot>;

 public:
  using Shape = ShapeT;

  inline Tagged<ElementT> get(int index) const;
  inline Tagged<ElementT> get(int index, RelaxedLoadTag) const;
  inline Tagged<ElementT> get(int index, AcquireLoadTag) const;
  inline Tagged<ElementT> get(int index, SeqCstAccessTag) const;

  inline void set(int index, Tagged<ElementT> value,
                  WriteBarrierMode mode = kDefaultMode);
  template <typename T = ElementT,
            typename = std::enable_if<kSupportsSmiElements<T>>>
  inline void set(int index, Tagged<Smi> value);
  inline void set(int index, Tagged<ElementT> value, RelaxedStoreTag,
                  WriteBarrierMode mode = kDefaultMode);
  template <typename T = ElementT,
            typename = std::enable_if<kSupportsSmiElements<T>>>
  inline void set(int index, Tagged<Smi> value, RelaxedStoreTag);
  inline void set(int index, Tagged<ElementT> value, ReleaseStoreTag,
                  WriteBarrierMode mode = kDefaultMode);
  template <typename T = ElementT,
            typename = std::enable_if<kSupportsSmiElements<T>>>
  inline void set(int index, Tagged<Smi> value, ReleaseStoreTag);
  inline void set(int index, Tagged<ElementT> value, SeqCstAccessTag,
                  WriteBarrierMode mode = kDefaultMode);
  template <typename T = ElementT,
            typename = std::enable_if<kSupportsSmiElements<T>>>
  inline void set(int index, Tagged<Smi> value, SeqCstAccessTag);

  inline Tagged<ElementT> swap(int index, Tagged<ElementT> value,
                               SeqCstAccessTag,
                               WriteBarrierMode mode = kDefaultMode);
  inline Tagged<ElementT> compare_and_swap(
      int index, Tagged<ElementT> expected, Tagged<ElementT> value,
      SeqCstAccessTag, WriteBarrierMode mode = kDefaultMode);

  // Move vs. Copy behaves like memmove vs. memcpy: for Move, the memory
  // regions may overlap, for Copy they must not overlap.
  inline static void MoveElements(Isolate* isolate, Tagged<Derived> dst,
                                  int dst_index, Tagged<Derived> src,
                                  int src_index, int len,
                                  WriteBarrierMode mode = kDefaultMode);
  inline static void CopyElements(Isolate* isolate, Tagged<Derived> dst,
                                  int dst_index, Tagged<Derived> src,
                                  int src_index, int len,
                                  WriteBarrierMode mode = kDefaultMode);

  // Right-trim the array.
  // Invariant: 0 < new_length <= length()
  inline void RightTrim(Isolate* isolate, int new_capacity);

  inline int AllocatedSize() const;
  static inline constexpr int SizeFor(int capacity) {
    return sizeof(Header) + capacity * kElementSize;
  }
  static inline constexpr int OffsetOfElementAt(int index) {
    return SizeFor(index);
  }

  // Gives access to raw memory which stores the array's data.
  inline SlotType RawFieldOfFirstElement() const;
  inline SlotType RawFieldOfElementAt(int index) const;

  // Maximal allowed capacity, in number of elements. Chosen s.t. the size fits
  // into a Smi which is necessary for being able to create a free space
  // filler.
  // TODO(jgruber): The kMaxCapacity could be larger (`(Smi::kMaxValue -
  // Shape::kHeaderSize) / kElementSize`), but our tests rely on a
  // smaller maximum to avoid timeouts.
  static constexpr int kMaxCapacity = 128 * MB - sizeof(Header) / kElementSize;
  static_assert(Smi::IsValid(SizeFor(kMaxCapacity)));

  // Maximally allowed length for regular (non large object space) object.
  static constexpr int kMaxRegularCapacity =
      (kMaxRegularHeapObjectSize - sizeof(Header)) / kElementSize;
  static_assert(kMaxRegularCapacity < kMaxCapacity);

 protected:
  template <class IsolateT>
  static Handle<Derived> Allocate(
      IsolateT* isolate, int capacity,
      std::optional<DisallowGarbageCollection>* no_gc_out,
      AllocationType allocation = AllocationType::kYoung);

  static constexpr int NewCapacityForIndex(int index, int old_capacity);

  inline bool IsInBounds(int index) const;
  inline bool IsCowArray() const;

  FLEXIBLE_ARRAY_MEMBER(ElementMemberT, objects);
} V8_OBJECT_END;

class TaggedArrayShape final : public AllStatic {
 public:
  using ElementT = Object;
  using CompressionScheme = V8HeapCompressionScheme;
  static constexpr RootIndex kMapRootIndex = RootIndex::kFixedArrayMap;
  static constexpr bool kLengthEqualsCapacity = true;
};

// FixedArray describes fixed-sized arrays with element type Object.
V8_OBJECT class FixedArray
    : public TaggedArrayBase<FixedArray, TaggedArrayShape> {
  using Super = TaggedArrayBase<FixedArray, TaggedArrayShape>;

 public:
  template <class IsolateT>
  static inline Handle<FixedArray> New(
      IsolateT* isolate, int capacity,
      AllocationType allocation = AllocationType::kYoung);

  using Super::CopyElements;
  using Super::MoveElements;

  // TODO(jgruber): Only needed for FixedArrays used as JSObject elements.
  inline void MoveElements(Isolate* isolate, int dst_index, int src_index,
                           int len, WriteBarrierMode mode);
  inline void CopyElements(Isolate* isolate, int dst_index,
                           Tagged<FixedArray> src, int src_index, int len,
                           WriteBarrierMode mode);

  // Return a grown copy if the index is bigger than the array's length.
  V8_EXPORT_PRIVATE static Handle<FixedArray> SetAndGrow(
      Isolate* isolate, Handle<FixedArray> array, int index,
      DirectHandle<Object> value);

  // Right-trim the array.
  // Invariant: 0 < new_length <= length()
  V8_EXPORT_PRIVATE void RightTrim(Isolate* isolate, int new_capacity);
  // Right-trims the array, and canonicalizes length 0 to empty_fixed_array.
  static Handle<FixedArray> RightTrimOrEmpty(Isolate* isolate,
                                             Handle<FixedArray> array,
                                             int new_length);

  // TODO(jgruber): Only needed for FixedArrays used as JSObject elements.
  inline void FillWithHoles(int from, int to);

  // For compatibility with FixedDoubleArray:
  // TODO(jgruber): Only needed for FixedArrays used as JSObject elements.
  inline bool is_the_hole(Isolate* isolate, int index);
  inline void set_the_hole(Isolate* isolate, int index);
  inline void set_the_hole(ReadOnlyRoots ro_roots, int index);

  DECL_PRINTER(FixedArray)
  DECL_VERIFIER(FixedArray)

  class BodyDescriptor;

  static constexpr int kMaxLength = FixedArray::kMaxCapacity;
  static constexpr int kMaxRegularLength = FixedArray::kMaxRegularCapacity;

 private:
  inline static Handle<FixedArray> Resize(
      Isolate* isolate, DirectHandle<FixedArray> xs, int new_capacity,
      AllocationType allocation = AllocationType::kYoung,
      WriteBarrierMode mode = UPDATE_WRITE_BARRIER);
} V8_OBJECT_END;

static_assert(sizeof(FixedArray) == Internals::kFixedArrayHeaderSize);

class TrustedArrayShape final : public AllStatic {
 public:
  using ElementT = Object;
  using CompressionScheme = V8HeapCompressionScheme;
  static constexpr RootIndex kMapRootIndex = RootIndex::kTrustedFixedArrayMap;
  static constexpr bool kLengthEqualsCapacity = true;
};

// A FixedArray in trusted space and with a unique instance type.
//
// Note: while the array itself is trusted, it contains tagged pointers into
// the main pointer compression heap and therefore to _untrusted_ objects.
// If you are storing references to other trusted object (i.e. protected
// pointers), use ProtectedFixedArray.
V8_OBJECT class TrustedFixedArray
    : public TaggedArrayBase<TrustedFixedArray, TrustedArrayShape,
                             TrustedObjectLayout> {
  using Super = TaggedArrayBase<TrustedFixedArray, TrustedArrayShape,
                                TrustedObjectLayout>;

 public:
  template <class IsolateT>
  static inline Handle<TrustedFixedArray> New(
      IsolateT* isolate, int capacity,
      AllocationType allocation = AllocationType::kTrusted);

  DECL_PRINTER(TrustedFixedArray)
  DECL_VERIFIER(TrustedFixedArray)

  class BodyDescriptor;

  static constexpr int kMaxLength = TrustedFixedArray::kMaxCapacity;
  static constexpr int kMaxRegularLength =
      TrustedFixedArray::kMaxRegularCapacity;
} V8_OBJECT_END;

class ProtectedArrayShape final : public AllStatic {
 public:
  using ElementT = Union<TrustedObject, Smi>;
  using CompressionScheme = TrustedSpaceCompressionScheme;
  static constexpr RootIndex kMapRootIndex = RootIndex::kProtectedFixedArrayMap;
  static constexpr bool kLengthEqualsCapacity = true;
};

// A FixedArray in trusted space, holding protected pointers (to other trusted
// objects). If you want to store JS-heap references, use TrustedFixedArray.
// ProtectedFixedArray has a unique instance type.
V8_OBJECT class ProtectedFixedArray
    : public TaggedArrayBase<ProtectedFixedArray, ProtectedArrayShape,
                             TrustedObjectLayout> {
  using Super = TaggedArrayBase<ProtectedFixedArray, ProtectedArrayShape,
                                TrustedObjectLayout>;

 public:
  // Allocate a new ProtectedFixedArray of the given capacity, initialized with
  // Smi::zero().
  template <class IsolateT>
  static inline Handle<ProtectedFixedArray> New(IsolateT* isolate,
                                                int capacity);

  DECL_PRINTER(ProtectedFixedArray)
  DECL_VERIFIER(ProtectedFixedArray)

  class BodyDescriptor;

  static constexpr int kMaxLength = Super::kMaxCapacity;
  static constexpr int kMaxRegularLength =
      ProtectedFixedArray::kMaxRegularCapacity;
} V8_OBJECT_END;

// FixedArray alias added only because of IsFixedArrayExact() predicate, which
// checks for the exact instance type FIXED_ARRAY_TYPE instead of a range
// check: [FIRST_FIXED_ARRAY_TYPE, LAST_FIXED_ARRAY_TYPE].
V8_OBJECT
class FixedArrayExact final : public FixedArray {
} V8_OBJECT_END;

// Common superclass for FixedArrays that allow implementations to share common
// accessors and some code paths. Note that due to single-inheritance
// restrictions, it is not part of the actual type hierarchy. Instead, we slot
// it in with manual is_subtype specializations in tagged.h.
// TODO(jgruber): This class is really specific to FixedArrays used as
// elements backing stores and should not be part of the common FixedArray
// hierarchy.
V8_OBJECT
class FixedArrayBase : public detail::ArrayHeaderBase<HeapObjectLayout, true> {
 public:
  static constexpr int kLengthOffset = HeapObject::kHeaderSize;
  static constexpr int kHeaderSize = kLengthOffset + kTaggedSize;
  static constexpr int kMaxLength = FixedArray::kMaxCapacity;
  static constexpr int kMaxRegularLength = FixedArray::kMaxRegularCapacity;

  static int GetMaxLengthForNewSpaceAllocation(ElementsKind kind);

  V8_EXPORT_PRIVATE bool IsCowArray() const;

  // Maximal allowed size, in bytes, of a single FixedArrayBase. Prevents
  // overflowing size computations, as well as extreme memory consumption.
  static constexpr int kMaxSize = 128 * kTaggedSize * MB;
  static_assert(Smi::IsValid(kMaxSize));

  DECL_VERIFIER(FixedArrayBase)
} V8_OBJECT_END;

V8_OBJECT
template <class Derived, class ShapeT, class Super = HeapObjectLayout>
class PrimitiveArrayBase : public detail::ArrayHeaderBase<Super, true> {
  static_assert(std::is_base_of<HeapObjectLayout, Super>::value);

  using ElementT = typename ShapeT::ElementT;
  static_assert(!is_subtype_v<ElementT, Object>);

  // Bug(v8:8875): Doubles may be unaligned.
  using ElementMemberT = std::conditional_t<std::is_same_v<ElementT, double>,
                                            UnalignedDoubleMember, ElementT>;
  static_assert(alignof(ElementMemberT) <= alignof(Tagged_t));

 public:
  using Shape = ShapeT;
  static constexpr bool kElementsAreMaybeObject = false;
  static constexpr int kElementSize = sizeof(ElementMemberT);
  using Header = detail::ArrayHeaderBase<Super, true>;

  inline ElementMemberT get(int index) const;
  inline void set(int index, ElementMemberT value);

  inline int AllocatedSize() const;
  static inline constexpr int SizeFor(int length) {
    return OBJECT_POINTER_ALIGN(OffsetOfElementAt(length));
  }
  static inline constexpr int OffsetOfElementAt(int index) {
    return sizeof(Header) + index * kElementSize;
  }

  // Gives access to raw memory which stores the array's data.
  // Note that on 32-bit archs and on 64-bit platforms with pointer compression
  // the pointers to 8-byte size elements are not guaranteed to be aligned.
  inline ElementMemberT* begin();
  inline const ElementMemberT* begin() const;
  inline ElementMemberT* end();
  inline const ElementMemberT* end() const;
  inline int DataSize() const;

  static inline Tagged<Derived> FromAddressOfFirstElement(Address address);

  // Maximal allowed length, in number of elements. Chosen s.t. the size fits
  // into a Smi which is necessary for being able to create a free space
  // filler.
  // TODO(jgruber): The kMaxLength could be larger (`(Smi::kMaxValue -
  // sizeof(Header)) / kElementSize`), but our tests rely on a
  // smaller maximum to avoid timeouts.
  static constexpr int kMaxLength =
      (FixedArrayBase::kMaxSize - sizeof(Header)) / kElementSize;
  static_assert(Smi::IsValid(SizeFor(kMaxLength)));

  // Maximally allowed length for regular (non large object space) object.
  static constexpr int kMaxRegularLength =
      (kMaxRegularHeapObjectSize - sizeof(Header)) / kElementSize;
  static_assert(kMaxRegularLength < kMaxLength);

 protected:
  template <class IsolateT>
  static Handle<Derived> Allocate(
      IsolateT* isolate, int length,
      std::optional<DisallowGarbageCollection>* no_gc_out,
      AllocationType allocation = AllocationType::kYoung);

  inline bool IsInBounds(int index) const;

  FLEXIBLE_ARRAY_MEMBER(ElementMemberT, values);
} V8_OBJECT_END;

class FixedDoubleArrayShape final : public AllStatic {
 public:
  using ElementT = double;
  static constexpr RootIndex kMapRootIndex = RootIndex::kFixedDoubleArrayMap;
};

// FixedDoubleArray describes fixed-sized arrays with element type double.
V8_OBJECT class FixedDoubleArray
    : public PrimitiveArrayBase<FixedDoubleArray, FixedDoubleArrayShape> {
  using Super = PrimitiveArrayBase<FixedDoubleArray, FixedDoubleArrayShape>;

 public:
  // Note this returns FixedArrayBase due to canonicalization to
  // empty_fixed_array.
  template <class IsolateT>
  static inline Handle<FixedArrayBase> New(
      IsolateT* isolate, int capacity,
      AllocationType allocation = AllocationType::kYoung);

  // Setter and getter for elements.
  inline double get_scalar(int index);
  inline uint64_t get_representation(int index);
  static inline Handle<Object> get(Tagged<FixedDoubleArray> array, int index,
                                   Isolate* isolate);
  inline void set(int index, double value);

  inline void set_the_hole(Isolate* isolate, int index);
  inline void set_the_hole(int index);
  inline bool is_the_hole(Isolate* isolate, int index);
  inline bool is_the_hole(int index);

  inline void MoveElements(Isolate* isolate, int dst_index, int src_index,
                           int len, WriteBarrierMode /* unused */);

  inline void FillWithHoles(int from, int to);

  DECL_PRINTER(FixedDoubleArray)
  DECL_VERIFIER(FixedDoubleArray)

  class BodyDescriptor;
} V8_OBJECT_END;

static_assert(FixedDoubleArray::kMaxLength <= FixedArray::kMaxLength);

class WeakFixedArrayShape final : public AllStatic {
 public:
  using ElementT = MaybeObject;
  using CompressionScheme = V8HeapCompressionScheme;
  static constexpr RootIndex kMapRootIndex = RootIndex::kWeakFixedArrayMap;
  static constexpr bool kLengthEqualsCapacity = true;
};

// WeakFixedArray describes fixed-sized arrays with element type
// Tagged<MaybeObject>.
V8_OBJECT class WeakFixedArray
    : public TaggedArrayBase<WeakFixedArray, WeakFixedArrayShape> {
  using Super = TaggedArrayBase<WeakFixedArray, WeakFixedArrayShape>;

 public:
  template <class IsolateT>
  static inline Handle<WeakFixedArray> New(
      IsolateT* isolate, int capacity,
      AllocationType allocation = AllocationType::kYoung,
      MaybeHandle<Object> initial_value = {});

  DECL_PRINTER(WeakFixedArray)
  DECL_VERIFIER(WeakFixedArray)

  class BodyDescriptor;
} V8_OBJECT_END;

class TrustedWeakFixedArrayShape final : public AllStatic {
 public:
  using ElementT = MaybeObject;
  using CompressionScheme = V8HeapCompressionScheme;
  static constexpr RootIndex kMapRootIndex =
      RootIndex::kTrustedWeakFixedArrayMap;
  static constexpr bool kLengthEqualsCapacity = true;
};

// A WeakFixedArray in trusted space and with a unique instance type.
V8_OBJECT class TrustedWeakFixedArray
    : public TaggedArrayBase<TrustedWeakFixedArray, TrustedWeakFixedArrayShape,
                             TrustedObjectLayout> {
  using Super =
      TaggedArrayBase<TrustedWeakFixedArray, TrustedWeakFixedArrayShape>;

 public:
  template <class IsolateT>
  static inline Handle<TrustedWeakFixedArray> New(IsolateT* isolate,
                                                  int capacity);

  DECL_PRINTER(TrustedWeakFixedArray)
  DECL_VERIFIER(TrustedWeakFixedArray)

  class BodyDescriptor;
} V8_OBJECT_END;

// WeakArrayList is like a WeakFixedArray with static convenience methods for
// adding more elements. length() returns the number of elements in the list and
// capacity() returns the allocated size. The number of elements is stored at
// kLengthOffset and is updated with every insertion. The array grows
// dynamically with O(1) amortized insertion.
class WeakArrayList
    : public TorqueGeneratedWeakArrayList<WeakArrayList, HeapObject> {
 public:
  NEVER_READ_ONLY_SPACE
  DECL_PRINTER(WeakArrayList)

  V8_EXPORT_PRIVATE static Handle<WeakArrayList> AddToEnd(
      Isolate* isolate, Handle<WeakArrayList> array,
      MaybeObjectDirectHandle value);

  // A version that adds to elements. This ensures that the elements are
  // inserted atomically w.r.t GC.
  V8_EXPORT_PRIVATE static Handle<WeakArrayList> AddToEnd(
      Isolate* isolate, Handle<WeakArrayList> array,
      MaybeObjectDirectHandle value1, Tagged<Smi> value2);

  // Appends an element to the array and possibly compacts and shrinks live weak
  // references to the start of the collection. Only use this method when
  // indices to elements can change.
  static V8_WARN_UNUSED_RESULT Handle<WeakArrayList> Append(
      Isolate* isolate, Handle<WeakArrayList> array,
      MaybeObjectDirectHandle value,
      AllocationType allocation = AllocationType::kYoung);

  // Compact weak references to the beginning of the array.
  V8_EXPORT_PRIVATE void Compact(Isolate* isolate);

  inline Tagged<MaybeObject> Get(int index) const;
  inline Tagged<MaybeObject> Get(PtrComprCageBase cage_base, int index) const;
  // TODO(jgruber): Remove this once it's no longer needed for compatibility
  // with WeakFixedArray.
  inline Tagged<MaybeObject> get(int index) const;

  // Set the element at index to obj. The underlying array must be large enough.
  // If you need to grow the WeakArrayList, use the static AddToEnd() method
  // instead.
  inline void Set(int index, Tagged<MaybeObject> value,
                  WriteBarrierMode mode = UPDATE_WRITE_BARRIER);
  inline void Set(int index, Tagged<Smi> value);

  static constexpr int SizeForCapacity(int capacity) {
    return SizeFor(capacity);
  }

  static constexpr int CapacityForLength(int length) {
    return length + std::max(length / 2, 2);
  }

  // Gives access to raw memory which stores the array's data.
  inline MaybeObjectSlot data_start();

  inline void CopyElements(Isolate* isolate, int dst_index,
                           Tagged<WeakArrayList> src, int src_index, int len,
                           WriteBarrierMode mode);

  V8_EXPORT_PRIVATE bool IsFull() const;

  inline int AllocatedSize() const;

  class BodyDescriptor;

  static const int kMaxCapacity =
      (FixedArrayBase::kMaxSize - kHeaderSize) / kTaggedSize;

  static Handle<WeakArrayList> EnsureSpace(
      Isolate* isolate, Handle<WeakArrayList> array, int length,
      AllocationType allocation = AllocationType::kYoung);

  // Returns the number of non-cleaned weak references in the array.
  int CountLiveWeakReferences() const;

  // Returns the number of non-cleaned elements in the array.
  int CountLiveElements() const;

  // Returns whether an entry was found and removed. Will move the elements
  // around in the array - this method can only be used in cases where the user
  // doesn't care about the indices! Users should make sure there are no
  // duplicates.
  V8_EXPORT_PRIVATE bool RemoveOne(MaybeObjectDirectHandle value);

  // Searches the array (linear time) and returns whether it contains the value.
  V8_EXPORT_PRIVATE bool Contains(Tagged<MaybeObject> value);

  class Iterator;

 private:
  static int OffsetOfElementAt(int index) {
    return kHeaderSize + index * kTaggedSize;
  }

  TQ_OBJECT_CONSTRUCTORS(WeakArrayList)
};

class WeakArrayList::Iterator {
 public:
  explicit Iterator(Tagged<WeakArrayList> array) : index_(0), array_(array) {}
  Iterator(const Iterator&) = delete;
  Iterator& operator=(const Iterator&) = delete;

  inline Tagged<HeapObject> Next();

 private:
  int index_;
  Tagged<WeakArrayList> array_;
  DISALLOW_GARBAGE_COLLECTION(no_gc_)
};

class ArrayListShape final : public AllStatic {
 public:
  using ElementT = Object;
  using CompressionScheme = V8HeapCompressionScheme;
  static constexpr RootIndex kMapRootIndex = RootIndex::kArrayListMap;
  static constexpr bool kLengthEqualsCapacity = false;

  V8_ARRAY_EXTRA_FIELDS({ TaggedMember<Smi> length_; });
};

// A generic array that grows dynamically with O(1) amortized insertion.
V8_OBJECT class ArrayList : public TaggedArrayBase<ArrayList, ArrayListShape> {
  using Super = TaggedArrayBase<ArrayList, ArrayListShape>;

 public:
  using Shape = ArrayListShape;

  template <class IsolateT>
  static inline Handle<ArrayList> New(
      IsolateT* isolate, int capacity,
      AllocationType allocation = AllocationType::kYoung);

  inline int length() const;
  inline void set_length(int value);

  V8_EXPORT_PRIVATE static Handle<ArrayList> Add(
      Isolate* isolate, Handle<ArrayList> array, Tagged<Smi> obj,
      AllocationType allocation = AllocationType::kYoung);
  V8_EXPORT_PRIVATE static Handle<ArrayList> Add(
      Isolate* isolate, Handle<ArrayList> array, DirectHandle<Object> obj,
      AllocationType allocation = AllocationType::kYoung);
  V8_EXPORT_PRIVATE static Handle<ArrayList> Add(
      Isolate* isolate, Handle<ArrayList> array, DirectHandle<Object> obj0,
      DirectHandle<Object> obj1,
      AllocationType allocation = AllocationType::kYoung);

  V8_EXPORT_PRIVATE static Handle<FixedArray> ToFixedArray(
      Isolate* isolate, DirectHandle<ArrayList> array,
      AllocationType allocation = AllocationType::kYoung);

  // Right-trim the array.
  // Invariant: 0 < new_length <= length()
  void RightTrim(Isolate* isolate, int new_capacity);

  DECL_PRINTER(ArrayList)
  DECL_VERIFIER(ArrayList)

  class BodyDescriptor;

 private:
  static Handle<ArrayList> EnsureSpace(
      Isolate* isolate, Handle<ArrayList> array, int length,
      AllocationType allocation = AllocationType::kYoung);
} V8_OBJECT_END;

class ByteArrayShape final : public AllStatic {
 public:
  static constexpr int kElementSize = kUInt8Size;
  using ElementT = uint8_t;
  static constexpr RootIndex kMapRootIndex = RootIndex::kByteArrayMap;
  static constexpr bool kLengthEqualsCapacity = true;
};

// ByteArray represents fixed sized arrays containing raw bytes that will not
// be scanned by the garbage collector.
V8_OBJECT class ByteArray
    : public PrimitiveArrayBase<ByteArray, ByteArrayShape> {
  using Super = PrimitiveArrayBase<ByteArray, ByteArrayShape>;

 public:
  using Shape = ByteArrayShape;

  template <class IsolateT>
  static inline Handle<ByteArray> New(
      IsolateT* isolate, int capacity,
      AllocationType allocation = AllocationType::kYoung);

  inline uint32_t get_int(int offset) const;
  inline void set_int(int offset, uint32_t value);

  // Given the full object size in bytes, return the length that should be
  // passed to New s.t. an object of the same size is created.
  static constexpr int LengthFor(int size_in_bytes) {
    DCHECK(IsAligned(size_in_bytes, kTaggedSize));
    DCHECK_GE(size_in_bytes, sizeof(Header));
    return size_in_bytes - sizeof(Header);
  }

  DECL_PRINTER(ByteArray)
  DECL_VERIFIER(ByteArray)

  class BodyDescriptor;
} V8_OBJECT_END;

class TrustedByteArrayShape final : public AllStatic {
 public:
  static constexpr int kElementSize = kUInt8Size;
  using ElementT = uint8_t;
  static constexpr RootIndex kMapRootIndex = RootIndex::kTrustedByteArrayMap;
  static constexpr bool kLengthEqualsCapacity = true;
};

// A ByteArray in trusted space.
V8_OBJECT
class TrustedByteArray
    : public PrimitiveArrayBase<TrustedByteArray, TrustedByteArrayShape,
                                TrustedObjectLayout> {
  using Super = PrimitiveArrayBase<TrustedByteArray, TrustedByteArrayShape,
                                   TrustedObjectLayout>;

 public:
  using Shape = TrustedByteArrayShape;

  template <class IsolateT>
  static inline Handle<TrustedByteArray> New(
      IsolateT* isolate, int capacity,
      AllocationType allocation_type = AllocationType::kTrusted);

  inline uint32_t get_int(int offset) const;
  inline void set_int(int offset, uint32_t value);

  // Given the full object size in bytes, return the length that should be
  // passed to New s.t. an object of the same size is created.
  static constexpr int LengthFor(int size_in_bytes) {
    DCHECK(IsAligned(size_in_bytes, kTaggedSize));
    DCHECK_GE(size_in_bytes, sizeof(Header));
    return size_in_bytes - sizeof(Header);
  }

  DECL_PRINTER(TrustedByteArray)
  DECL_VERIFIER(TrustedByteArray)

  class BodyDescriptor;
} V8_OBJECT_END;

// Convenience class for treating a ByteArray / TrustedByteArray as array of
// fixed-size integers.
V8_OBJECT
template <typename T, typename Base>
class FixedIntegerArrayBase : public Base {
  static_assert(std::is_integral<T>::value);

 public:
  // {MoreArgs...} allows passing the `AllocationType` if `Base` is `ByteArray`.
  template <typename... MoreArgs>
  static Handle<FixedIntegerArrayBase<T, Base>> New(Isolate* isolate,
                                                    int length,
                                                    MoreArgs&&... more_args);

  // Get/set the contents of this array.
  T get(int index) const;
  void set(int index, T value);

  // Code Generation support.
  static constexpr int OffsetOfElementAt(int index) {
    return sizeof(typename Base::Header) + index * sizeof(T);
  }

  inline int length() const;

 protected:
  Address get_element_address(int index) const;
} V8_OBJECT_END;

using FixedInt8Array = FixedIntegerArrayBase<int8_t, ByteArray>;
using FixedUInt8Array = FixedIntegerArrayBase<uint8_t, ByteArray>;
using FixedInt16Array = FixedIntegerArrayBase<int16_t, ByteArray>;
using FixedUInt16Array = FixedIntegerArrayBase<uint16_t, ByteArray>;
using FixedInt32Array = FixedIntegerArrayBase<int32_t, ByteArray>;
using FixedUInt32Array = FixedIntegerArrayBase<uint32_t, ByteArray>;
using FixedInt64Array = FixedIntegerArrayBase<int64_t, ByteArray>;
using FixedUInt64Array = FixedIntegerArrayBase<uint64_t, ByteArray>;

// Use with care! Raw addresses on the heap are not safe in combination with
// the sandbox. However, this can for example be used to store sandboxed
// pointers, which is safe.
V8_OBJECT
template <typename Base>
class FixedAddressArrayBase : public FixedIntegerArrayBase<Address, Base> {
  using Underlying = FixedIntegerArrayBase<Address, Base>;

 public:
  // Get/set a sandboxed pointer from this array.
  inline Address get_sandboxed_pointer(int index) const;
  inline void set_sandboxed_pointer(int index, Address value);

  // {MoreArgs...} allows passing the `AllocationType` if `Base` is `ByteArray`.
  template <typename... MoreArgs>
  static inline Handle<FixedAddressArrayBase> New(Isolate* isolate, int length,
                                                  MoreArgs&&... more_args);
} V8_OBJECT_END;

using FixedAddressArray = FixedAddressArrayBase<ByteArray>;
using TrustedFixedAddressArray = FixedAddressArrayBase<TrustedByteArray>;

V8_OBJECT
template <class T, class Super>
class PodArrayBase : public Super {
 public:
  void copy_out(int index, T* result, int length) {
    MemCopy(result, &this->values()[index * sizeof(T)], length * sizeof(T));
  }

  void copy_in(int index, const T* buffer, int length) {
    MemCopy(&this->values()[index * sizeof(T)], buffer, length * sizeof(T));
  }

  bool matches(const T* buffer, int length) {
    DCHECK_LE(length, this->length());
    return memcmp(this->begin(), buffer, length * sizeof(T)) == 0;
  }

  bool matches(int offset, const T* buffer, int length) {
    DCHECK_LE(offset, this->length());
    DCHECK_LE(offset + length, this->length());
    
"""


```