Response: The user wants a summary of the C++ source code file `v8/src/objects/elements.cc`.
The request specifically asks for the functionality of the code and how it relates to JavaScript.
It also indicates that this is the first part of a larger file.

**Plan:**
1. Identify the main purpose of the code based on its includes and the provided structure (inheritance hierarchy).
2. Explain the core concept of "ElementsAccessor" and its various implementations.
3. Find connections between the C++ code and JavaScript concepts like arrays and their different representations.
4. Provide a JavaScript example to illustrate the connection.
这个C++源代码文件 `v8/src/objects/elements.cc` 的主要功能是**管理和操作JavaScript对象中元素的存储和访问**。 它是V8引擎中处理各种不同类型的数组和类数组对象的关键部分。

更具体地说，这个文件的第1部分主要定义了以下内容：

1. **元素访问器 (ElementsAccessor) 的继承体系：**  代码定义了一个复杂的继承结构，其中 `ElementsAccessorBase` 是基类，而各种具体的子类（例如 `FastPackedSmiElementsAccessor`, `FastHoleyObjectElementsAccessor`, `Uint8ElementsAccessor`, `DictionaryElementsAccessor` 等）负责处理不同类型的元素存储方式。 这些不同的存储方式对应于JavaScript数组在内存中的不同优化形式。

2. **`ElementsKind` 枚举和 `ElementsKindTraits` 模板：**  `ElementsKind` 枚举定义了所有可能的元素类型（例如，只包含SMI的数组，包含对象的数组，包含双精度浮点数的数组，TypedArray等等）。 `ElementsKindTraits` 模板则为每种 `ElementsKind` 关联了相应的C++类型（例如，`PACKED_SMI_ELEMENTS` 对应 `FixedArray`，`PACKED_DOUBLE_ELEMENTS` 对应 `FixedDoubleArray`）。

3. **辅助函数和宏：**  定义了一些用于错误处理 (`RETURN_NOTHING_IF_NOT_SUCCESSFUL`, `RETURN_FAILURE_IF_NOT_SUCCESSFUL`) 和元素复制的辅助函数（例如 `CopyObjectToObjectElements`, `CopyDoubleToObjectElements` 等）。 这些函数根据不同的元素类型进行高效的内存操作。

4. **`InternalElementsAccessor` 类：**  这是一个辅助类，用于向子类公开受保护的方法，主要用于处理基于索引的元素访问。

**与JavaScript的功能关系：**

这个文件中的代码直接影响了JavaScript中数组的性能和行为。 JavaScript的数组在V8引擎内部并不是单一的结构，而是会根据其存储的元素类型和操作进行优化，使用不同的内部表示形式。 `elements.cc` 中定义的各种 `ElementsAccessor` 子类就对应着这些不同的内部表示。

例如：

* **`FastPackedSmiElementsAccessor` 和 `FastHoleySmiElementsAccessor`:**  对应于只包含小整数（SMI）的数组。 `FastPackedSmiElementsAccessor` 用于没有空洞的紧凑数组，而 `FastHoleySmiElementsAccessor` 用于可能存在 `undefined` 或空洞的数组。
* **`FastPackedDoubleElementsAccessor` 和 `FastHoleyDoubleElementsAccessor`:** 对应于只包含浮点数（双精度）的数组。
* **`FastPackedObjectElementsAccessor` 和 `FastHoleyObjectElementsAccessor`:** 对应于包含任意JavaScript对象的数组。
* **`DictionaryElementsAccessor`:**  对应于稀疏数组，其中元素的索引可能不连续，V8使用哈希表来存储这些元素。
* **`Uint8ElementsAccessor`， `Int32ElementsAccessor` 等：** 对应于 `TypedArray`，例如 `Uint8Array`, `Int32Array` 等。

**JavaScript示例：**

```javascript
// 示例 1: 快速 Packed Smi 数组
const arr1 = [1, 2, 3]; // V8可能会使用 FastPackedSmiElementsAccessor

// 示例 2: 快速 Holey Smi 数组
const arr2 = [1, , 3];  // V8可能会使用 FastHoleySmiElementsAccessor

// 示例 3: 快速 Packed Double 数组
const arr3 = [1.1, 2.2, 3.3]; // V8可能会使用 FastPackedDoubleElementsAccessor

// 示例 4: 快速 Holey Double 数组
const arr4 = [1.1, , 3.3]; // V8可能会使用 FastHoleyDoubleElementsAccessor

// 示例 5: 快速 Packed Object 数组
const arr5 = [{a: 1}, {b: 2}]; // V8可能会使用 FastPackedObjectElementsAccessor

// 示例 6: 字典类型数组 (稀疏数组)
const arr6 = [];
arr6[1000] = 'hello'; // V8可能会使用 DictionaryElementsAccessor

// 示例 7: Typed Array
const typedArray = new Uint8Array([10, 20, 30]); // V8会使用 Uint8ElementsAccessor
```

当你在JavaScript中创建和操作数组时，V8引擎会根据数组的内容和操作动态地选择最合适的 `ElementsAccessor` 来进行内存管理和访问优化。  例如，如果一个数组最初只包含整数，V8可能会使用 `FastPackedSmiElementsAccessor`。 如果你向这个数组中添加了一个非整数值，V8可能会将其转换为 `FastPackedObjectElementsAccessor`。 如果数组变得非常稀疏，V8甚至可能将其转换为 `DictionaryElementsAccessor`。

总而言之， `v8/src/objects/elements.cc` 的第1部分是V8引擎中一个核心组件的起始部分，它为JavaScript数组提供了灵活和高效的底层实现。

Prompt: 
```
这是目录为v8/src/objects/elements.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/elements.h"

#include "src/base/atomicops.h"
#include "src/base/safe_conversions.h"
#include "src/common/message-template.h"
#include "src/execution/arguments.h"
#include "src/execution/frames.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/protectors-inl.h"
#include "src/heap/factory.h"
#include "src/heap/heap-inl.h"  // For MaxNumberToStringCacheSize.
#include "src/heap/heap-write-barrier-inl.h"
#include "src/numbers/conversions.h"
#include "src/objects/arguments-inl.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-shared-array-inl.h"
#include "src/objects/keys.h"
#include "src/objects/objects-inl.h"
#include "src/objects/slots-atomic-inl.h"
#include "src/objects/slots.h"
#include "src/utils/utils.h"
#include "third_party/fp16/src/include/fp16.h"

// Each concrete ElementsAccessor can handle exactly one ElementsKind,
// several abstract ElementsAccessor classes are used to allow sharing
// common code.
//
// Inheritance hierarchy:
// - ElementsAccessorBase                        (abstract)
//   - FastElementsAccessor                      (abstract)
//     - FastSmiOrObjectElementsAccessor
//       - FastPackedSmiElementsAccessor
//       - FastHoleySmiElementsAccessor
//       - FastPackedObjectElementsAccessor
//       - FastNonextensibleObjectElementsAccessor: template
//         - FastPackedNonextensibleObjectElementsAccessor
//         - FastHoleyNonextensibleObjectElementsAccessor
//       - FastSealedObjectElementsAccessor: template
//         - FastPackedSealedObjectElementsAccessor
//         - FastHoleySealedObjectElementsAccessor
//       - FastFrozenObjectElementsAccessor: template
//         - FastPackedFrozenObjectElementsAccessor
//         - FastHoleyFrozenObjectElementsAccessor
//       - FastHoleyObjectElementsAccessor
//     - FastDoubleElementsAccessor
//       - FastPackedDoubleElementsAccessor
//       - FastHoleyDoubleElementsAccessor
//   - TypedElementsAccessor: template, with instantiations:
//     - Uint8ElementsAccessor
//     - Int8ElementsAccessor
//     - Uint16ElementsAccessor
//     - Int16ElementsAccessor
//     - Uint32ElementsAccessor
//     - Int32ElementsAccessor
//     - Float32ElementsAccessor
//     - Float64ElementsAccessor
//     - Uint8ClampedElementsAccessor
//     - BigUint64ElementsAccessor
//     - BigInt64ElementsAccessor
//     - RabGsabUint8ElementsAccessor
//     - RabGsabInt8ElementsAccessor
//     - RabGsabUint16ElementsAccessor
//     - RabGsabInt16ElementsAccessor
//     - RabGsabUint32ElementsAccessor
//     - RabGsabInt32ElementsAccessor
//     - RabGsabFloat32ElementsAccessor
//     - RabGsabFloat64ElementsAccessor
//     - RabGsabUint8ClampedElementsAccessor
//     - RabGsabBigUint64ElementsAccessor
//     - RabGsabBigInt64ElementsAccessor
//   - DictionaryElementsAccessor
//   - SloppyArgumentsElementsAccessor
//     - FastSloppyArgumentsElementsAccessor
//     - SlowSloppyArgumentsElementsAccessor
//   - StringWrapperElementsAccessor
//     - FastStringWrapperElementsAccessor
//     - SlowStringWrapperElementsAccessor

namespace v8 {
namespace internal {

namespace {

#define RETURN_NOTHING_IF_NOT_SUCCESSFUL(call) \
  do {                                         \
    if (!(call)) return Nothing<bool>();       \
  } while (false)

#define RETURN_FAILURE_IF_NOT_SUCCESSFUL(call)          \
  do {                                                  \
    ExceptionStatus status_enum_result = (call);        \
    if (!status_enum_result) return status_enum_result; \
  } while (false)

static const int kPackedSizeNotKnown = -1;

enum Where { AT_START, AT_END };

// First argument in list is the accessor class, the second argument is the
// accessor ElementsKind, and the third is the backing store class.  Use the
// fast element handler for smi-only arrays.  The implementation is currently
// identical.  Note that the order must match that of the ElementsKind enum for
// the |accessor_array[]| below to work.
#define ELEMENTS_LIST(V)                                                      \
  V(FastPackedSmiElementsAccessor, PACKED_SMI_ELEMENTS, FixedArray)           \
  V(FastHoleySmiElementsAccessor, HOLEY_SMI_ELEMENTS, FixedArray)             \
  V(FastPackedObjectElementsAccessor, PACKED_ELEMENTS, FixedArray)            \
  V(FastHoleyObjectElementsAccessor, HOLEY_ELEMENTS, FixedArray)              \
  V(FastPackedDoubleElementsAccessor, PACKED_DOUBLE_ELEMENTS,                 \
    FixedDoubleArray)                                                         \
  V(FastHoleyDoubleElementsAccessor, HOLEY_DOUBLE_ELEMENTS, FixedDoubleArray) \
  V(FastPackedNonextensibleObjectElementsAccessor,                            \
    PACKED_NONEXTENSIBLE_ELEMENTS, FixedArray)                                \
  V(FastHoleyNonextensibleObjectElementsAccessor,                             \
    HOLEY_NONEXTENSIBLE_ELEMENTS, FixedArray)                                 \
  V(FastPackedSealedObjectElementsAccessor, PACKED_SEALED_ELEMENTS,           \
    FixedArray)                                                               \
  V(FastHoleySealedObjectElementsAccessor, HOLEY_SEALED_ELEMENTS, FixedArray) \
  V(FastPackedFrozenObjectElementsAccessor, PACKED_FROZEN_ELEMENTS,           \
    FixedArray)                                                               \
  V(FastHoleyFrozenObjectElementsAccessor, HOLEY_FROZEN_ELEMENTS, FixedArray) \
  V(SharedArrayElementsAccessor, SHARED_ARRAY_ELEMENTS, FixedArray)           \
  V(DictionaryElementsAccessor, DICTIONARY_ELEMENTS, NumberDictionary)        \
  V(FastSloppyArgumentsElementsAccessor, FAST_SLOPPY_ARGUMENTS_ELEMENTS,      \
    FixedArray)                                                               \
  V(SlowSloppyArgumentsElementsAccessor, SLOW_SLOPPY_ARGUMENTS_ELEMENTS,      \
    FixedArray)                                                               \
  V(FastStringWrapperElementsAccessor, FAST_STRING_WRAPPER_ELEMENTS,          \
    FixedArray)                                                               \
  V(SlowStringWrapperElementsAccessor, SLOW_STRING_WRAPPER_ELEMENTS,          \
    FixedArray)                                                               \
  V(Uint8ElementsAccessor, UINT8_ELEMENTS, ByteArray)                         \
  V(Int8ElementsAccessor, INT8_ELEMENTS, ByteArray)                           \
  V(Uint16ElementsAccessor, UINT16_ELEMENTS, ByteArray)                       \
  V(Int16ElementsAccessor, INT16_ELEMENTS, ByteArray)                         \
  V(Uint32ElementsAccessor, UINT32_ELEMENTS, ByteArray)                       \
  V(Int32ElementsAccessor, INT32_ELEMENTS, ByteArray)                         \
  V(BigUint64ElementsAccessor, BIGUINT64_ELEMENTS, ByteArray)                 \
  V(BigInt64ElementsAccessor, BIGINT64_ELEMENTS, ByteArray)                   \
  V(Uint8ClampedElementsAccessor, UINT8_CLAMPED_ELEMENTS, ByteArray)          \
  V(Float32ElementsAccessor, FLOAT32_ELEMENTS, ByteArray)                     \
  V(Float64ElementsAccessor, FLOAT64_ELEMENTS, ByteArray)                     \
  V(Float16ElementsAccessor, FLOAT16_ELEMENTS, ByteArray)                     \
  V(RabGsabUint8ElementsAccessor, RAB_GSAB_UINT8_ELEMENTS, ByteArray)         \
  V(RabGsabInt8ElementsAccessor, RAB_GSAB_INT8_ELEMENTS, ByteArray)           \
  V(RabGsabUint16ElementsAccessor, RAB_GSAB_UINT16_ELEMENTS, ByteArray)       \
  V(RabGsabInt16ElementsAccessor, RAB_GSAB_INT16_ELEMENTS, ByteArray)         \
  V(RabGsabUint32ElementsAccessor, RAB_GSAB_UINT32_ELEMENTS, ByteArray)       \
  V(RabGsabInt32ElementsAccessor, RAB_GSAB_INT32_ELEMENTS, ByteArray)         \
  V(RabGsabBigUint64ElementsAccessor, RAB_GSAB_BIGUINT64_ELEMENTS, ByteArray) \
  V(RabGsabBigInt64ElementsAccessor, RAB_GSAB_BIGINT64_ELEMENTS, ByteArray)   \
  V(RabGsabUint8ClampedElementsAccessor, RAB_GSAB_UINT8_CLAMPED_ELEMENTS,     \
    ByteArray)                                                                \
  V(RabGsabFloat32ElementsAccessor, RAB_GSAB_FLOAT32_ELEMENTS, ByteArray)     \
  V(RabGsabFloat64ElementsAccessor, RAB_GSAB_FLOAT64_ELEMENTS, ByteArray)     \
  V(RabGsabFloat16ElementsAccessor, RAB_GSAB_FLOAT16_ELEMENTS, ByteArray)

template <ElementsKind Kind>
class ElementsKindTraits {
 public:
  using BackingStore = FixedArrayBase;
};

#define ELEMENTS_TRAITS(Class, KindParam, Store)    \
  template <>                                       \
  class ElementsKindTraits<KindParam> {             \
   public: /* NOLINT */                             \
    static constexpr ElementsKind Kind = KindParam; \
    using BackingStore = Store;                     \
  };                                                \
  constexpr ElementsKind ElementsKindTraits<KindParam>::Kind;
ELEMENTS_LIST(ELEMENTS_TRAITS)
#undef ELEMENTS_TRAITS

V8_WARN_UNUSED_RESULT
MaybeHandle<Object> ThrowArrayLengthRangeError(Isolate* isolate) {
  THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kInvalidArrayLength));
}

WriteBarrierMode GetWriteBarrierMode(Tagged<FixedArrayBase> elements,
                                     ElementsKind kind,
                                     const DisallowGarbageCollection& promise) {
  if (IsSmiElementsKind(kind)) return SKIP_WRITE_BARRIER;
  if (IsDoubleElementsKind(kind)) return SKIP_WRITE_BARRIER;
  return elements->GetWriteBarrierMode(promise);
}

// If kCopyToEndAndInitializeToHole is specified as the copy_size to
// CopyElements, it copies all of elements from source after source_start to
// destination array, padding any remaining uninitialized elements in the
// destination array with the hole.
constexpr int kCopyToEndAndInitializeToHole = -1;

void CopyObjectToObjectElements(Isolate* isolate,
                                Tagged<FixedArrayBase> from_base,
                                ElementsKind from_kind, uint32_t from_start,
                                Tagged<FixedArrayBase> to_base,
                                ElementsKind to_kind, uint32_t to_start,
                                int raw_copy_size) {
  ReadOnlyRoots roots(isolate);
  DCHECK(to_base->map() != roots.fixed_cow_array_map());
  DisallowGarbageCollection no_gc;
  int copy_size = raw_copy_size;
  if (raw_copy_size < 0) {
    DCHECK_EQ(kCopyToEndAndInitializeToHole, raw_copy_size);
    copy_size = std::min(from_base->length() - from_start,
                         to_base->length() - to_start);
    int start = to_start + copy_size;
    int length = to_base->length() - start;
    if (length > 0) {
      MemsetTagged(Cast<FixedArray>(to_base)->RawFieldOfElementAt(start),
                   roots.the_hole_value(), length);
    }
  }
  DCHECK((copy_size + static_cast<int>(to_start)) <= to_base->length() &&
         (copy_size + static_cast<int>(from_start)) <= from_base->length());
  if (copy_size == 0) return;
  Tagged<FixedArray> from = Cast<FixedArray>(from_base);
  Tagged<FixedArray> to = Cast<FixedArray>(to_base);
  DCHECK(IsSmiOrObjectElementsKind(from_kind));
  DCHECK(IsSmiOrObjectElementsKind(to_kind));

  WriteBarrierMode write_barrier_mode =
      (IsObjectElementsKind(from_kind) && IsObjectElementsKind(to_kind))
          ? UPDATE_WRITE_BARRIER
          : SKIP_WRITE_BARRIER;
  to->CopyElements(isolate, to_start, from, from_start, copy_size,
                   write_barrier_mode);
}

void CopyDictionaryToObjectElements(Isolate* isolate,
                                    Tagged<FixedArrayBase> from_base,
                                    uint32_t from_start,
                                    Tagged<FixedArrayBase> to_base,
                                    ElementsKind to_kind, uint32_t to_start,
                                    int raw_copy_size) {
  DisallowGarbageCollection no_gc;
  Tagged<NumberDictionary> from = Cast<NumberDictionary>(from_base);
  int copy_size = raw_copy_size;
  if (raw_copy_size < 0) {
    DCHECK_EQ(kCopyToEndAndInitializeToHole, raw_copy_size);
    copy_size = from->max_number_key() + 1 - from_start;
    int start = to_start + copy_size;
    int length = to_base->length() - start;
    if (length > 0) {
      MemsetTagged(Cast<FixedArray>(to_base)->RawFieldOfElementAt(start),
                   ReadOnlyRoots(isolate).the_hole_value(), length);
    }
  }
  DCHECK(to_base != from_base);
  DCHECK(IsSmiOrObjectElementsKind(to_kind));
  if (copy_size == 0) return;
  Tagged<FixedArray> to = Cast<FixedArray>(to_base);
  uint32_t to_length = to->length();
  if (to_start + copy_size > to_length) {
    copy_size = to_length - to_start;
  }
  WriteBarrierMode write_barrier_mode = GetWriteBarrierMode(to, to_kind, no_gc);
  for (int i = 0; i < copy_size; i++) {
    InternalIndex entry = from->FindEntry(isolate, i + from_start);
    if (entry.is_found()) {
      Tagged<Object> value = from->ValueAt(entry);
      DCHECK(!IsTheHole(value, isolate));
      to->set(i + to_start, value, write_barrier_mode);
    } else {
      to->set_the_hole(isolate, i + to_start);
    }
  }
}

// NOTE: this method violates the handlified function signature convention:
// raw pointer parameters in the function that allocates.
// See ElementsAccessorBase::CopyElements() for details.
void CopyDoubleToObjectElements(Isolate* isolate,
                                Tagged<FixedArrayBase> from_base,
                                uint32_t from_start,
                                Tagged<FixedArrayBase> to_base,
                                uint32_t to_start, int raw_copy_size) {
  int copy_size = raw_copy_size;
  if (raw_copy_size < 0) {
    DisallowGarbageCollection no_gc;
    DCHECK_EQ(kCopyToEndAndInitializeToHole, raw_copy_size);
    copy_size = std::min(from_base->length() - from_start,
                         to_base->length() - to_start);
    // Also initialize the area that will be copied over since HeapNumber
    // allocation below can cause an incremental marking step, requiring all
    // existing heap objects to be propertly initialized.
    int start = to_start;
    int length = to_base->length() - start;
    if (length > 0) {
      MemsetTagged(Cast<FixedArray>(to_base)->RawFieldOfElementAt(start),
                   ReadOnlyRoots(isolate).the_hole_value(), length);
    }
  }

  DCHECK((copy_size + static_cast<int>(to_start)) <= to_base->length() &&
         (copy_size + static_cast<int>(from_start)) <= from_base->length());
  if (copy_size == 0) return;

  // From here on, the code below could actually allocate. Therefore the raw
  // values are wrapped into handles.
  DirectHandle<FixedDoubleArray> from(Cast<FixedDoubleArray>(from_base),
                                      isolate);
  DirectHandle<FixedArray> to(Cast<FixedArray>(to_base), isolate);

  // Use an outer loop to not waste too much time on creating HandleScopes.
  // On the other hand we might overflow a single handle scope depending on
  // the copy_size.
  int offset = 0;
  while (offset < copy_size) {
    HandleScope scope(isolate);
    offset += 100;
    for (int i = offset - 100; i < offset && i < copy_size; ++i) {
      DirectHandle<Object> value =
          FixedDoubleArray::get(*from, i + from_start, isolate);
      to->set(i + to_start, *value, UPDATE_WRITE_BARRIER);
    }
  }
}

void CopyDoubleToDoubleElements(Tagged<FixedArrayBase> from_base,
                                uint32_t from_start,
                                Tagged<FixedArrayBase> to_base,
                                uint32_t to_start, int raw_copy_size) {
  DisallowGarbageCollection no_gc;
  int copy_size = raw_copy_size;
  if (raw_copy_size < 0) {
    DCHECK_EQ(kCopyToEndAndInitializeToHole, raw_copy_size);
    copy_size = std::min(from_base->length() - from_start,
                         to_base->length() - to_start);
    for (int i = to_start + copy_size; i < to_base->length(); ++i) {
      Cast<FixedDoubleArray>(to_base)->set_the_hole(i);
    }
  }
  DCHECK((copy_size + static_cast<int>(to_start)) <= to_base->length() &&
         (copy_size + static_cast<int>(from_start)) <= from_base->length());
  if (copy_size == 0) return;
  Tagged<FixedDoubleArray> from = Cast<FixedDoubleArray>(from_base);
  Tagged<FixedDoubleArray> to = Cast<FixedDoubleArray>(to_base);
  Address to_address = reinterpret_cast<Address>(to->begin());
  Address from_address = reinterpret_cast<Address>(from->begin());
  to_address += kDoubleSize * to_start;
  from_address += kDoubleSize * from_start;
#ifdef V8_COMPRESS_POINTERS
  // TODO(ishell, v8:8875): we use CopyTagged() in order to avoid unaligned
  // access to double values in the arrays. This will no longed be necessary
  // once the allocations alignment issue is fixed.
  int words_per_double = (kDoubleSize / kTaggedSize);
  CopyTagged(to_address, from_address,
             static_cast<size_t>(words_per_double * copy_size));
#else
  int words_per_double = (kDoubleSize / kSystemPointerSize);
  CopyWords(to_address, from_address,
            static_cast<size_t>(words_per_double * copy_size));
#endif
}

void CopySmiToDoubleElements(Tagged<FixedArrayBase> from_base,
                             uint32_t from_start,
                             Tagged<FixedArrayBase> to_base, uint32_t to_start,
                             int raw_copy_size) {
  DisallowGarbageCollection no_gc;
  int copy_size = raw_copy_size;
  if (raw_copy_size < 0) {
    DCHECK_EQ(kCopyToEndAndInitializeToHole, raw_copy_size);
    copy_size = from_base->length() - from_start;
    for (int i = to_start + copy_size; i < to_base->length(); ++i) {
      Cast<FixedDoubleArray>(to_base)->set_the_hole(i);
    }
  }
  DCHECK((copy_size + static_cast<int>(to_start)) <= to_base->length() &&
         (copy_size + static_cast<int>(from_start)) <= from_base->length());
  if (copy_size == 0) return;
  Tagged<FixedArray> from = Cast<FixedArray>(from_base);
  Tagged<FixedDoubleArray> to = Cast<FixedDoubleArray>(to_base);
  Tagged<Object> the_hole = from->GetReadOnlyRoots().the_hole_value();
  for (uint32_t from_end = from_start + static_cast<uint32_t>(copy_size);
       from_start < from_end; from_start++, to_start++) {
    Tagged<Object> hole_or_smi = from->get(from_start);
    if (hole_or_smi == the_hole) {
      to->set_the_hole(to_start);
    } else {
      to->set(to_start, Smi::ToInt(hole_or_smi));
    }
  }
}

void CopyPackedSmiToDoubleElements(Tagged<FixedArrayBase> from_base,
                                   uint32_t from_start,
                                   Tagged<FixedArrayBase> to_base,
                                   uint32_t to_start, int packed_size,
                                   int raw_copy_size) {
  DisallowGarbageCollection no_gc;
  int copy_size = raw_copy_size;
  uint32_t to_end;
  if (raw_copy_size < 0) {
    DCHECK_EQ(kCopyToEndAndInitializeToHole, raw_copy_size);
    copy_size = packed_size - from_start;
    to_end = to_base->length();
    for (uint32_t i = to_start + copy_size; i < to_end; ++i) {
      Cast<FixedDoubleArray>(to_base)->set_the_hole(i);
    }
  } else {
    to_end = to_start + static_cast<uint32_t>(copy_size);
  }
  DCHECK(static_cast<int>(to_end) <= to_base->length());
  DCHECK(packed_size >= 0 && packed_size <= copy_size);
  DCHECK((copy_size + static_cast<int>(to_start)) <= to_base->length() &&
         (copy_size + static_cast<int>(from_start)) <= from_base->length());
  if (copy_size == 0) return;
  Tagged<FixedArray> from = Cast<FixedArray>(from_base);
  Tagged<FixedDoubleArray> to = Cast<FixedDoubleArray>(to_base);
  for (uint32_t from_end = from_start + static_cast<uint32_t>(packed_size);
       from_start < from_end; from_start++, to_start++) {
    Tagged<Object> smi = from->get(from_start);
    DCHECK(!IsTheHole(smi));
    to->set(to_start, Smi::ToInt(smi));
  }
}

void CopyObjectToDoubleElements(Tagged<FixedArrayBase> from_base,
                                uint32_t from_start,
                                Tagged<FixedArrayBase> to_base,
                                uint32_t to_start, int raw_copy_size) {
  DisallowGarbageCollection no_gc;
  int copy_size = raw_copy_size;
  if (raw_copy_size < 0) {
    DCHECK_EQ(kCopyToEndAndInitializeToHole, raw_copy_size);
    copy_size = from_base->length() - from_start;
    for (int i = to_start + copy_size; i < to_base->length(); ++i) {
      Cast<FixedDoubleArray>(to_base)->set_the_hole(i);
    }
  }
  DCHECK((copy_size + static_cast<int>(to_start)) <= to_base->length() &&
         (copy_size + static_cast<int>(from_start)) <= from_base->length());
  if (copy_size == 0) return;
  Tagged<FixedArray> from = Cast<FixedArray>(from_base);
  Tagged<FixedDoubleArray> to = Cast<FixedDoubleArray>(to_base);
  Tagged<Hole> the_hole = from->GetReadOnlyRoots().the_hole_value();
  for (uint32_t from_end = from_start + copy_size; from_start < from_end;
       from_start++, to_start++) {
    Tagged<Object> hole_or_object = from->get(from_start);
    if (hole_or_object == the_hole) {
      to->set_the_hole(to_start);
    } else {
      to->set(to_start, Object::NumberValue(Cast<Number>(hole_or_object)));
    }
  }
}

void CopyDictionaryToDoubleElements(Isolate* isolate,
                                    Tagged<FixedArrayBase> from_base,
                                    uint32_t from_start,
                                    Tagged<FixedArrayBase> to_base,
                                    uint32_t to_start, int raw_copy_size) {
  DisallowGarbageCollection no_gc;
  Tagged<NumberDictionary> from = Cast<NumberDictionary>(from_base);
  int copy_size = raw_copy_size;
  if (copy_size < 0) {
    DCHECK_EQ(kCopyToEndAndInitializeToHole, copy_size);
    copy_size = from->max_number_key() + 1 - from_start;
    for (int i = to_start + copy_size; i < to_base->length(); ++i) {
      Cast<FixedDoubleArray>(to_base)->set_the_hole(i);
    }
  }
  if (copy_size == 0) return;
  Tagged<FixedDoubleArray> to = Cast<FixedDoubleArray>(to_base);
  uint32_t to_length = to->length();
  if (to_start + copy_size > to_length) {
    copy_size = to_length - to_start;
  }
  for (int i = 0; i < copy_size; i++) {
    InternalIndex entry = from->FindEntry(isolate, i + from_start);
    if (entry.is_found()) {
      to->set(i + to_start,
              Object::NumberValue(Cast<Number>(from->ValueAt(entry))));
    } else {
      to->set_the_hole(i + to_start);
    }
  }
}

void SortIndices(Isolate* isolate, DirectHandle<FixedArray> indices,
                 uint32_t sort_size) {
  if (sort_size == 0) return;

  // Use AtomicSlot wrapper to ensure that std::sort uses atomic load and
  // store operations that are safe for concurrent marking.
  AtomicSlot start(indices->RawFieldOfFirstElement());
  AtomicSlot end(start + sort_size);
  std::sort(start, end, [isolate](Tagged_t elementA, Tagged_t elementB) {
#ifdef V8_COMPRESS_POINTERS
    Tagged<Object> a(
        V8HeapCompressionScheme::DecompressTagged(isolate, elementA));
    Tagged<Object> b(
        V8HeapCompressionScheme::DecompressTagged(isolate, elementB));
#else
    Tagged<Object> a(elementA);
    Tagged<Object> b(elementB);
#endif
    if (IsSmi(a) || !IsUndefined(a, isolate)) {
      if (!IsSmi(b) && IsUndefined(b, isolate)) {
        return true;
      }
      return Object::NumberValue(Cast<Number>(a)) <
             Object::NumberValue(Cast<Number>(b));
    }
    return !IsSmi(b) && IsUndefined(b, isolate);
  });
  WriteBarrier::ForRange(isolate->heap(), *indices, ObjectSlot(start),
                         ObjectSlot(end));
}

Maybe<bool> IncludesValueSlowPath(Isolate* isolate, Handle<JSObject> receiver,
                                  DirectHandle<Object> value, size_t start_from,
                                  size_t length) {
  bool search_for_hole = IsUndefined(*value, isolate);
  for (size_t k = start_from; k < length; ++k) {
    LookupIterator it(isolate, receiver, k);
    if (!it.IsFound()) {
      if (search_for_hole) return Just(true);
      continue;
    }
    DirectHandle<Object> element_k;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, element_k,
                                     Object::GetProperty(&it), Nothing<bool>());

    if (Object::SameValueZero(*value, *element_k)) return Just(true);
  }

  return Just(false);
}

Maybe<int64_t> IndexOfValueSlowPath(Isolate* isolate, Handle<JSObject> receiver,
                                    DirectHandle<Object> value,
                                    size_t start_from, size_t length) {
  for (size_t k = start_from; k < length; ++k) {
    LookupIterator it(isolate, receiver, k);
    if (!it.IsFound()) {
      continue;
    }
    DirectHandle<Object> element_k;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, element_k, Object::GetProperty(&it), Nothing<int64_t>());

    if (Object::StrictEquals(*value, *element_k)) return Just<int64_t>(k);
  }

  return Just<int64_t>(-1);
}

// The InternalElementsAccessor is a helper class to expose otherwise protected
// methods to its subclasses. Namely, we don't want to publicly expose methods
// that take an entry (instead of an index) as an argument.
class InternalElementsAccessor : public ElementsAccessor {
 public:
  InternalIndex GetEntryForIndex(Isolate* isolate, Tagged<JSObject> holder,
                                 Tagged<FixedArrayBase> backing_store,
                                 size_t index) override = 0;

  PropertyDetails GetDetails(Tagged<JSObject> holder,
                             InternalIndex entry) override = 0;
};

// Base class for element handler implementations. Contains the
// the common logic for objects with different ElementsKinds.
// Subclasses must specialize method for which the element
// implementation differs from the base class implementation.
//
// This class is intended to be used in the following way:
//
//   class SomeElementsAccessor :
//       public ElementsAccessorBase<SomeElementsAccessor,
//                                   BackingStoreClass> {
//     ...
//   }
//
// This is an example of the Curiously Recurring Template Pattern (see
// http://en.wikipedia.org/wiki/Curiously_recurring_template_pattern).  We use
// CRTP to guarantee aggressive compile time optimizations (i.e.  inlining and
// specialization of SomeElementsAccessor methods).
template <typename Subclass, typename ElementsTraitsParam>
class ElementsAccessorBase : public InternalElementsAccessor {
 public:
  ElementsAccessorBase() = default;
  ElementsAccessorBase(const ElementsAccessorBase&) = delete;
  ElementsAccessorBase& operator=(const ElementsAccessorBase&) = delete;

  using ElementsTraits = ElementsTraitsParam;
  using BackingStore = typename ElementsTraitsParam::BackingStore;

  static ElementsKind kind() { return ElementsTraits::Kind; }

  static void ValidateContents(Tagged<JSObject> holder, size_t length) {}

  static void ValidateImpl(Tagged<JSObject> holder) {
    Tagged<FixedArrayBase> fixed_array_base = holder->elements();
    if (!IsHeapObject(fixed_array_base)) return;
    // Arrays that have been shifted in place can't be verified.
    if (IsFreeSpaceOrFiller(fixed_array_base)) return;
    size_t length = 0;
    if (IsJSArray(holder)) {
      Tagged<Object> length_obj = Cast<JSArray>(holder)->length();
      if (IsSmi(length_obj)) {
        length = Smi::ToInt(length_obj);
      }
    } else if (IsJSTypedArray(holder)) {
      length = Cast<JSTypedArray>(holder)->length();
    } else {
      length = fixed_array_base->length();
    }
    Subclass::ValidateContents(holder, length);
  }

  void Validate(Tagged<JSObject> holder) final {
    DisallowGarbageCollection no_gc;
    Subclass::ValidateImpl(holder);
  }

  bool HasElement(Tagged<JSObject> holder, uint32_t index,
                  Tagged<FixedArrayBase> backing_store,
                  PropertyFilter filter) final {
    return Subclass::HasElementImpl(holder->GetIsolate(), holder, index,
                                    backing_store, filter);
  }

  static bool HasElementImpl(Isolate* isolate, Tagged<JSObject> holder,
                             size_t index, Tagged<FixedArrayBase> backing_store,
                             PropertyFilter filter = ALL_PROPERTIES) {
    return Subclass::GetEntryForIndexImpl(isolate, holder, backing_store, index,
                                          filter)
        .is_found();
  }

  bool HasEntry(Tagged<JSObject> holder, InternalIndex entry) final {
    return Subclass::HasEntryImpl(holder->GetIsolate(), holder->elements(),
                                  entry);
  }

  static bool HasEntryImpl(Isolate* isolate,
                           Tagged<FixedArrayBase> backing_store,
                           InternalIndex entry) {
    UNIMPLEMENTED();
  }

  bool HasAccessors(Tagged<JSObject> holder) final {
    return Subclass::HasAccessorsImpl(holder, holder->elements());
  }

  static bool HasAccessorsImpl(Tagged<JSObject> holder,
                               Tagged<FixedArrayBase> backing_store) {
    return false;
  }

  Handle<Object> Get(Isolate* isolate, Handle<JSObject> holder,
                     InternalIndex entry) final {
    return Subclass::GetInternalImpl(isolate, holder, entry);
  }

  static Handle<Object> GetInternalImpl(Isolate* isolate,
                                        DirectHandle<JSObject> holder,
                                        InternalIndex entry) {
    return Subclass::GetImpl(isolate, holder->elements(), entry);
  }

  static Handle<Object> GetImpl(Isolate* isolate,
                                Tagged<FixedArrayBase> backing_store,
                                InternalIndex entry) {
    return handle(Cast<BackingStore>(backing_store)->get(entry.as_int()),
                  isolate);
  }

  Handle<Object> GetAtomic(Isolate* isolate, Handle<JSObject> holder,
                           InternalIndex entry, SeqCstAccessTag tag) final {
    return Subclass::GetAtomicInternalImpl(isolate, holder->elements(), entry,
                                           tag);
  }

  static Handle<Object> GetAtomicInternalImpl(
      Isolate* isolate, Tagged<FixedArrayBase> backing_store,
      InternalIndex entry, SeqCstAccessTag tag) {
    UNREACHABLE();
  }

  void SetAtomic(Handle<JSObject> holder, InternalIndex entry,
                 Tagged<Object> value, SeqCstAccessTag tag) final {
    Subclass::SetAtomicInternalImpl(holder->elements(), entry, value, tag);
  }

  static void SetAtomicInternalImpl(Tagged<FixedArrayBase> backing_store,
                                    InternalIndex entry, Tagged<Object> value,
                                    SeqCstAccessTag tag) {
    UNREACHABLE();
  }

  Handle<Object> SwapAtomic(Isolate* isolate, Handle<JSObject> holder,
                            InternalIndex entry, Tagged<Object> value,
                            SeqCstAccessTag tag) final {
    return Subclass::SwapAtomicInternalImpl(isolate, holder->elements(), entry,
                                            value, tag);
  }

  static Handle<Object> SwapAtomicInternalImpl(
      Isolate* isolate, Tagged<FixedArrayBase> backing_store,
      InternalIndex entry, Tagged<Object> value, SeqCstAccessTag tag) {
    UNREACHABLE();
  }

  Handle<Object> CompareAndSwapAtomic(Isolate* isolate, Handle<JSObject> holder,
                                      InternalIndex entry,
                                      Tagged<Object> expected,
                                      Tagged<Object> value,
                                      SeqCstAccessTag tag) final {
    return handle(HeapObject::SeqCst_CompareAndSwapField(
                      expected, value,
                      [=](Tagged<Object> expected_value,
                          Tagged<Object> new_value) {
                        return Subclass::CompareAndSwapAtomicInternalImpl(
                            holder->elements(), entry, expected_value,
                            new_value, tag);
                      }),
                  isolate);
  }

  static Tagged<Object> CompareAndSwapAtomicInternalImpl(
      Tagged<FixedArrayBase> backing_store, InternalIndex entry,
      Tagged<Object> expected, Tagged<Object> value, SeqCstAccessTag tag) {
    UNREACHABLE();
  }

  void Set(Handle<JSObject> holder, InternalIndex entry,
           Tagged<Object> value) final {
    Subclass::SetImpl(holder, entry, value);
  }

  void Reconfigure(Handle<JSObject> object, Handle<FixedArrayBase> store,
                   InternalIndex entry, Handle<Object> value,
                   PropertyAttributes attributes) final {
    Subclass::ReconfigureImpl(object, store, entry, value, attributes);
  }

  static void ReconfigureImpl(DirectHandle<JSObject> object,
                              DirectHandle<FixedArrayBase> store,
                              InternalIndex entry, DirectHandle<Object> value,
                              PropertyAttributes attributes) {
    UNREACHABLE();
  }

  Maybe<bool> Add(Handle<JSObject> object, uint32_t index,
                  DirectHandle<Object> value, PropertyAttributes attributes,
                  uint32_t new_capacity) final {
    return Subclass::AddImpl(object, index, value, attributes, new_capacity);
  }

  static Maybe<bool> AddImpl(DirectHandle<JSObject> object, uint32_t index,
                             DirectHandle<Object> value,
                             PropertyAttributes attributes,
                             uint32_t new_capacity) {
    UNREACHABLE();
  }

  Maybe<uint32_t> Push(Handle<JSArray> receiver, BuiltinArguments* args,
                       uint32_t push_size) final {
    return Subclass::PushImpl(receiver, args, push_size);
  }

  static Maybe<uint32_t> PushImpl(DirectHandle<JSArray> receiver,
                                  BuiltinArguments* args, uint32_t push_sized) {
    UNREACHABLE();
  }

  Maybe<uint32_t> Unshift(Handle<JSArray> receiver, BuiltinArguments* args,
                          uint32_t unshift_size) final {
    return Subclass::UnshiftImpl(receiver, args, unshift_size);
  }

  static Maybe<uint32_t> UnshiftImpl(DirectHandle<JSArray> receiver,
                                     BuiltinArguments* args,
                                     uint32_t unshift_size) {
    UNREACHABLE();
  }

  MaybeHandle<Object> Pop(Handle<JSArray> receiver) final {
    return Subclass::PopImpl(receiver);
  }

  static MaybeHandle<Object> PopImpl(DirectHandle<JSArray> receiver) {
    UNREACHABLE();
  }

  MaybeHandle<Object> Shift(Handle<JSArray> receiver) final {
    return Subclass::ShiftImpl(receiver);
  }

  static MaybeHandle<Object> ShiftImpl(DirectHandle<JSArray> receiver) {
    UNREACHABLE();
  }

  Maybe<bool> SetLength(Handle<JSArray> array, uint32_t length) final {
    return Subclass::SetLengthImpl(
        array->GetIsolate(), array, length,
        handle(array->elements(), array->GetIsolate()));
  }

  static Maybe<bool> SetLengthImpl(Isolate* isolate, Handle<JSArray> array,
                                   uint32_t length,
                                   DirectHandle<FixedArrayBase> backing_store) {
    DCHECK(!array->SetLengthWouldNormalize(length));
    DCHECK(IsFastElementsKind(array->GetElementsKind()));
    uint32_t old_length = 0;
    CHECK(Object::ToArrayIndex(array->length(), &old_length));

    if (old_length < length) {
      ElementsKind kind = array->GetElementsKind();
      if (!IsHoleyElementsKind(kind)) {
        kind = GetHoleyElementsKind(kind);
        JSObject::TransitionElementsKind(array, kind);
      }
    }

    // Check whether the backing store should be shrunk.
    uint32_t capacity = backing_store->length();
    old_length = std::min(old_length, capacity);
    if (length == 0) {
      array->initialize_elements();
    } else if (length <= capacity) {
      if (IsSmiOrObjectElementsKind(kind())) {
        JSObject::EnsureWritableFastElements(array);
        if (array->elements() != *backing_store) {
          backing_store = handle(array->elements(), isolate);
        }
      }
      if (2 * length + JSObject::kMinAddedElementsCapacity <= capacity) {
        // If more than half the elements won't be used, trim the array.
        // Do not trim from short arrays to prevent frequent trimming on
        // repeated pop operations.
        // Leave some space to allow for subsequent push operations.
        uint32_t new_capacity =
            length + 1 == old_length ? (capacity + length) / 2 : length;
        DCHECK_LT(new_capacity, capacity);
        isolate->heap()->RightTrimArray(Cast<BackingStore>(*backing_store),
                                        new_capacity, capacity);
        // Fill the non-trimmed elements with holes.
        Cast<BackingStore>(*backing_store)
            ->FillWithHoles(length, std::min(old_length, new_capacity));
      } else {
        // Otherwise, fill the unused tail with holes.
        Cast<BackingStore>(*backing_store)->FillWithHoles(length, old_length);
      }
    } else {
      // Check whether the backing store should be expanded.
      capacity = std::max(length, JSObject::NewElementsCapacity(capacity));
      MAYBE_RETURN(Subclass::GrowCapacityAndConvertImpl(array, capacity),
                   Nothing<bool>());
    }

    array->set_length(Smi::FromInt(length));
    JSObject::ValidateElements(*array);
    return Just(true);
  }

  size_t NumberOfElements(Isolate* isolate, Tagged<JSObject> receiver) final {
    return Subclass::NumberOfElementsImpl(isolate, receiver,
                                          receiver->elements());
  }

  static uint32_t NumberOfElementsImpl(Isolate* isolate,
                                       Tagged<JSObject> receiver,
                                       Tagged<FixedArrayBase> backing_store) {
    UNREACHABLE();
  }

  static size_t GetMaxIndex(Tagged<JSObject> receiver,
                            Tagged<FixedArrayBase> elements) {
    if (IsJSArray(receiver)) {
      DCHECK(IsSmi(Cast<JSArray>(receiver)->length()));
      return static_cast<uint32_t>(
          Smi::ToInt(Cast<JSArray>(receiver)->length()));
    }
    return Subclass::GetCapacityImpl(receiver, elements);
  }

  static size_t GetMaxNumberOfEntries(Isolate* isolate,
                                      Tagged<JSObject> receiver,
                                      Tagged<FixedArrayBase> elements) {
    return Subclass::GetMaxIndex(receiver, elements);
  }

  static MaybeHandle<FixedArrayBase> ConvertElementsWithCapacity(
      Handle<JSObject> object, Handle<FixedArrayBase> old_elements,
      ElementsKind from_kind, uint32_t capacity) {
    return ConvertElementsWithCapacity(object, old_elements, from_kind,
                                       capacity, 0, 0);
  }

  static MaybeHandle<FixedArrayBase> ConvertElementsWithCapacity(
      DirectHandle<JSObject> object, DirectHandle<FixedArrayBase> old_elements,
      ElementsKind from_kind, uint32_t capacity, uint32_t src_index,
      uint32_t dst_index) {
    Isolate* isolate = object->GetIsolate();
    Handle<FixedArrayBase> new_elements;
    // TODO(victorgomes): Retrieve native context in optimized code
    // and remove the check isolate->context().is_null().
    if (IsDoubleElementsKind(kind())) {
      if (!isolate->context().is_null() &&
          !base::IsInRange(capacity, 0, FixedDoubleArray::kMaxLength)) {
        THROW_NEW_ERROR(isolate,
                        NewRangeError(MessageTemplate::kInvalidArrayLength));
      }
      new_elements = isolate->factory()->NewFixedDoubleArray(capacity);
    } else {
      if (!isolate->context().is_null() &&
          !base::IsInRange(capacity, 0, FixedArray::kMaxLength)) {
        THROW_NEW_ERROR(isolate,
                        NewRangeError(MessageTemplate::kInvalidArrayLength));
      }
      new_elements = isolate->factory()->NewFixedArray(capacity);
    }

    int packed_size = kPackedSizeNotKnown;
    if (IsFastPackedElementsKind(from_kind) && IsJSArray(*object)) {
      packed_size = Smi::ToInt(Cast<JSArray>(*object)->length());
    }

    Subclass::CopyElementsImpl(isolate, *old_elements, src_index, *new_elements,
                               from_kind, dst_index, packed_size,
                               kCopyToEndAndInitializeToHole);

    return MaybeHandle<FixedArrayBase>(new_elements);
  }

  static Maybe<bool> TransitionElementsKindImpl(Handle<JSObject> object,
                                                DirectHandle<Map> to_map) {
    Isolate* isolate = object->GetIsolate();
    DirectHandle<Map> from_map(object->map(), isolate);
    ElementsKind from_kind = from_map->elements_kind();
    ElementsKind to_kind = to_map->elements_kind();
    if (IsHoleyElementsKind(from_kind)) {
      to_kind = GetHoleyElementsKind(to_kind);
    }
    if (from_kind != to_kind) {
      // This method should never be called for any other case.
      DCHECK(IsFastElementsKind(from_kind));
      DCHECK(IsFastElementsKind(to_kind));
      DCHECK_NE(TERMINAL_FAST_ELEMENTS_KIND, from_kind);

      Handle<FixedArrayBase> from_elements(object->elements(), isolate);
      if (object->elements() == ReadOnlyRoots(isolate).empty_fixed_array() ||
          IsDoubleElementsKind(from_kind) == IsDoubleElementsKind(to_kind)) {
        // No change is needed to the elements() buffer, the transition
        // only requires a map change.
        JSObject::MigrateToMap(isolate, object, to_map);
      } else {
        DCHECK(
            (IsSmiElementsKind(from_kind) && IsDoubleElementsKind(to_kind)) ||
            (IsDoubleElementsKind(from_kind) && IsObjectElementsKind(to_kind)));
        uint32_t capacity = static_cast<uint32_t>(object->elements()->length());
        Handle<FixedArrayBase> elements;
        ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            object->GetIsolate(), elements,
            ConvertElementsWithCapacity(object, from_elements, from_kind,
                                        capacity),
            Nothing<bool>());
        JSObject::SetMapAndElements(object, to_map, elements);
      }
      if (v8_flags.trace_elements_transitions) {
        JSObject::PrintElementsTransition(stdout, object, from_kind,
                                          from_elements, to_kind,
                                          handle(object->elements(), isolate));
      }
    }
    return Just(true);
  }

  static Maybe<bool> GrowCapacityAndConvertImpl(Handle<JSObject> object,
                                                uint32_t capacity) {
    ElementsKind from_kind = object->GetElementsKind();
    if (IsSmiOrObjectElementsKind(from_kind)) {
      // Array optimizations rely on the prototype lookups of Array objects
      // always returning undefined. If there is a store to the initial
      // prototype object, make sure all of these optimizations are invalidated.
      object->GetIsolate()->UpdateNoElementsProtectorOnSetLength(object);
    }
    Handle<FixedArrayBase> old_elements(object->elements(),
                                        object->GetIsolate());
    // This method should only be called if there's a reason to update the
    // elements.
    DCHECK(IsDoubleElementsKind(from_kind) != IsDoubleElementsKind(kind()) ||
           IsDictionaryElementsKind(from_kind) ||
           static_cast<uint32_t>(old_elements->length()) < capacity);
    return Subclass::BasicGrowCapacityAndConvertImpl(
        object, old_elements, from_kind, kind(), capacity);
  }

  static Maybe<bool> BasicGrowCapacityAndConvertImpl(
      Handle<JSObject> object, Handle<FixedArrayBase> old_elements,
      ElementsKind from_kind, ElementsKind to_kind, uint32_t capacity) {
    Handle<FixedArrayBase> elements;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        object->GetIsolate(), elements,
        ConvertElementsWithCapacity(object, old_elements, from_kind, capacity),
        Nothing<bool>());

    if (IsHoleyElementsKind(from_kind)) {
      to_kind = GetHoleyElementsKind(to_kind);
    }
    DirectHandle<Map> new_map =
        JSObject::GetElementsTransitionMap(object, to_kind);
    JSObject::SetMapAndElements(object, new_map, elements);

    // Transition through the allocation site as well if present.
    JSObject::UpdateAllocationSite(object, to_kind);

    if (v8_flags.trace_elements_transitions) {
      JSObject::PrintElementsTransition(stdout, object, from_kind, old_elements,
                                        to_kind, elements);
    }
    return Just(true);
  }

  Maybe<bool> TransitionElementsKind(Handle<JSObject> object,
                                     Handle<Map> map) final {
    return Subclass::TransitionElementsKindImpl(object, map);
  }

  Maybe<bool> GrowCapacityAndConvert(Handle<JSObject> object,
                                     uint32_t capacity) final {
    return Subclass::GrowCapacityAndConvertImpl(object, capacity);
  }

  Maybe<bool> GrowCapacity(Handle<JSObject> object, uint32_t index) final {
    // This function is intended to be called from optimized code. We don't
    // want to trigger lazy deopts there, so refuse to handle cases that would.
    if (object->map()->is_prototype_map() ||
        object->WouldConvertToSlowElements(index)) {
      return Just(false);
    }
    Handle<FixedArrayBase> old_elements(object->elements(),
                                        object->GetIsolate());
    uint32_t new_capacity = JSObject::NewElementsCapacity(index + 1);
    DCHECK(static_cast<uint32_t>(old_elements->length()) < new_capacity);
    const uint32_t kMaxLength = IsDoubleElementsKind(kind())
                                    ? FixedDoubleArray::kMaxLength
                                    : FixedArray::kMaxLength;
    if (new_capacity > kMaxLength) {
      return Just(false);
    }
    Handle<FixedArrayBase> elements;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        object->GetIsolate(), elements,
        ConvertElementsWithCapacity(object, old_elements, kind(), new_capacity),
        Nothing<bool>());

    DCHECK_EQ(object->GetElementsKind(), kind());
    // Transition through the allocation site as well if present.
    if (JSObject::UpdateAllocationSite<AllocationSiteUpdateMode::kCheckOnly>(
            object, kind())) {
      return Just(false);
    }

    object->set_elements(*elements);
    return Just(true);
  }

  void Delete(Handle<JSObject> obj, InternalIndex entry) final {
    Subclass::DeleteImpl(obj, entry);
  }

  static void CopyElementsImpl(Isolate* isolate, Tagged<FixedArrayBase> from,
                               uint32_t from_start, Tagged<FixedArrayBase> to,
                               ElementsKind from_kind, uint32_t to_start,
                               int packed_size, int copy_size) {
    UNREACHABLE();
  }

  void CopyElements(Isolate* isolate, Tagged<JSObject> from_holder,
                    uint32_t from_start, ElementsKind from_kind,
                    Handle<FixedArrayBase> to, uint32_t to_start,
                    int copy_size) final {
    int packed_size = kPackedSizeNotKnown;
    bool is_packed =
        IsFastPackedElementsKind(from_kind) && IsJSArray(from_holder);
    if (is_packed) {
      packed_size = Smi::ToInt(Cast<JSArray>(from_holder)->length());
      if (copy_size >= 0 && packed_size > copy_size) {
        packed_size = copy_size;
      }
    }
    Tagged<FixedArrayBase> from = from_holder->elements();
    // NOTE: the Subclass::CopyElementsImpl() methods
    // violate the handlified function signature convention:
    // raw pointer parameters in the function that allocates. This is done
    // intentionally to avoid ArrayConcat() builtin performance degradation.
    //
    // Details: The idea is that allocations actually happen only in case of
    // copying from object with fast double elements to object with object
    // elements. In all the other cases there are no allocations performed and
    // handle creation causes noticeable performance degradation of the builtin.
    Subclass::CopyElementsImpl(isolate, from, from_start, *to, from_kind,
                               to_start, packed_size, copy_size);
  }

  void CopyElements(Isolate* isolate, Handle<FixedArrayBase> source,
                    ElementsKind source_kind,
                    Handle<FixedArrayBase> destination, int size) override {
    Subclass::CopyElementsImpl(isolate, *source, 0, *destination, source_kind,
                               0, kPackedSizeNotKnown, size);
  }

  void CopyTypedArrayElementsSlice(Tagged<JSTypedArray> source,
                                   Tagged<JSTypedArray> destination,
                                   size_t start, size_t end) override {
    Subclass::CopyTypedArrayElementsSliceImpl(source, destination, start, end);
  }

  static void CopyTypedArrayElementsSliceImpl(Tagged<JSTypedArray> source,
                                              Tagged<JSTypedArray> destination,
                                              size_t start, size_t end) {
    UNREACHABLE();
  }

  Tagged<Object> CopyElements(Handle<JSAny> source,
                              Handle<JSObject> destination, size_t length,
                              size_t offset) final {
    return Subclass::CopyElementsHandleImpl(source, destination, length,
                                            offset);
  }

  static Tagged<Object> CopyElementsHandleImpl(
      DirectHandle<Object> source, DirectHandle<JSObject> destination,
      size_t length, size_t offset) {
    UNREACHABLE();
  }

  Handle<NumberDictionary> Normalize(Handle<JSObject> object) final {
    return Subclass::NormalizeImpl(
        object, handle(object->elements(), object->GetIsolate()));
  }

  static Handle<NumberDictionary> NormalizeImpl(
      DirectHandle<JSObject> object, DirectHandle<FixedArrayBase> elements) {
    UNREACHABLE();
  }

  Maybe<bool> CollectValuesOrEntries(Isolate* isolate, Handle<JSObject> object,
                                     Handle<FixedArray> values_or_entries,
                                     bool get_entries, int* nof_items,
                                     PropertyFilter filter) override {
    return Subclass::CollectValuesOrEntriesImpl(
        isolate, object, values_or_entries, get_entries, nof_items, filter);
  }

  static Maybe<bool> CollectValuesOrEntriesImpl(
      Isolate* isolate, Handle<JSObject> object,
      DirectHandle<FixedArray> values_or_entries, bool get_entries,
      int* nof_items, PropertyFilter filter) {
    DCHECK_EQ(*nof_items, 0);
    KeyAccumulator accumulator(isolate, KeyCollectionMode::kOwnOnly,
                               ALL_PROPERTIES);
    RETURN_NOTHING_IF_NOT_SUCCESSFUL(Subclass::CollectElementIndicesImpl(
        object, handle(object->elements(), isolate), &accumulator));
    DirectHandle<FixedArray> keys = accumulator.GetKeys();

    int count = 0;
    int i = 0;
    ElementsKind original_elements_kind = object->GetElementsKind();

    for (; i < keys->length(); ++i) {
      DirectHandle<Object> key(keys->get(i), isolate);
      uint32_t index;
      if (!Object::ToUint32(*key, &index)) continue;

      DCHECK_EQ(object->GetElementsKind(), original_elements_kind);
      InternalIndex entry = Subclass::GetEntryForIndexImpl(
          isolate, *object, object->elements(), index, filter);
      if (entry.is_not_found()) continue;
      PropertyDetails details = Subclass::GetDetailsImpl(*object, entry);

      DirectHandle<Object> value;
      if (details.kind() == PropertyKind::kData) {
        value = Subclass::GetInternalImpl(isolate, object, entry);
      } else {
        // This might modify the elements and/or change the elements kind.
        LookupIterator it(isolate, object, index, LookupIterator::OWN);
        ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, value, Object::GetProperty(&it), Nothing<bool>());
      }
      if (get_entries) value = MakeEntryPair(isolate, index, value);
      values_or_entries->set(count++, *value);
      if (object->GetElementsKind() != original_elements_kind) break;
    }

    // Slow path caused by changes in elements kind during iteration.
    for (; i < keys->length(); i++) {
      DirectHandle<Object> key(keys->get(i), isolate);
      uint32_t index;
      if (!Object::ToUint32(*key, &index)) continue;

      if (filter & ONLY_ENUMERABLE) {
        InternalElementsAccessor* accessor =
            reinterpret_cast<InternalElementsAccessor*>(
                object->GetElementsAccessor());
        InternalIndex entry = accessor->GetEntryForIndex(
            isolate, *object, object->elements(), index);
        if (entry.is_not_found()) continue;
        PropertyDetails details = accessor->GetDetails(*object, entry);
        if (!details.IsEnumerable()) continue;
      }

      Handle<Object> value;
      LookupIterator it(isolate, object, index, LookupIterator::OWN);
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, value, Object::GetProperty(&it),
                                       Nothing<bool>());

      if (get_entries) value = MakeEntryPair(isolate, index, value);
      values_or_entries->set(count++, *value);
    }

    *nof_items = count;
    return Just(true);
  }

  V8_WARN_UNUSED_RESULT ExceptionStatus CollectElementIndices(
      Handle<JSObject> object, Handle<FixedArrayBase> backing_store,
      KeyAccumulator* keys) final {
    return Subclass::CollectElementIndicesImpl(object, backing_store, keys);
  }

  V8_WARN_UNUSED_RESULT static ExceptionStatus CollectElementIndicesImpl(
      DirectHandle<JSObject> object, DirectHandle<FixedArrayBase> backing_store,
      KeyAccumulator* keys) {
    DCHECK_NE(DICTIONARY_ELEMENTS, kind());
    // Non-dictionary elements can't have all-can-read accessors.
    size_t length = Subclass::GetMaxIndex(*object, *backing_store);
    PropertyFilter filter = keys->filter();
    Isolate* isolate = keys->isolate();
    Factory* factory = isolate->factory();
    for (size_t i = 0; i < length; i++) {
      if (Subclass::HasElementImpl(isolate, *object, i, *backing_store,
                                   filter)) {
        RETURN_FAILURE_IF_NOT_SUCCESSFUL(
            keys->AddKey(factory->NewNumberFromSize(i)));
      }
    }
    return ExceptionStatus::kSuccess;
  }

  static Handle<FixedArray> DirectCollectElementIndicesImpl(
      Isolate* isolate, DirectHandle<JSObject> object,
      DirectHandle<FixedArrayBase> backing_store, GetKeysConversion convert,
      PropertyFilter filter, Handle<FixedArray> list, uint32_t* nof_indices,
      uint32_t insertion_index = 0) {
    size_t length = Subclass::GetMaxIndex(*object, *backing_store);
    uint32_t const kMaxStringTableEntries =
        isolate->heap()->MaxNumberToStringCacheSize();
    for (size_t i = 0; i < length; i++) {
      if (Subclass::HasElementImpl(isolate, *object, i, *backing_store,
                                   filter)) {
        if (convert == GetKeysConversion::kConvertToString) {
          bool use_cache = i < kMaxStringTableEntries;
          DirectHandle<String> index_string =
              isolate->factory()->SizeToString(i, use_cache);
          list->set(insertion_index, *index_string);
        } else {
          DirectHandle<Object> number =
              isolate->factory()->NewNumberFromSize(i);
          list->set(insertion_index, *number);
        }
        insertion_index++;
      }
    }
    *nof_indices = insertion_index;
    return list;
  }

  MaybeHandle<FixedArray> PrependElementIndices(
      Isolate* isolate, Handle<JSObject> object,
      Handle<FixedArrayBase> backing_store, Handle<FixedArray> keys,
      GetKeysConversion convert, PropertyFilter filter) final {
    return Subclass::PrependElementIndicesImpl(isolate, object, backing_store,
                                               keys, convert, filter);
  }

  static MaybeHandle<FixedArray> PrependElementIndicesImpl(
      Isolate* isolate, Handle<JSObject> object,
      Handle<FixedArrayBase> backing_store, DirectHandle<FixedArray> keys,
      GetKeysConversion convert, PropertyFilter filter) {
    uint32_t nof_property_keys = keys->length();
    size_t initial_list_length =
        Subclass::GetMaxNumberOfEntries(isolate, *object, *backing_store);

    if (initial_list_length > FixedArray::kMaxLength - nof_property_keys) {
      THROW_NEW_ERROR(isolate,
                      NewRangeError(MessageTemplate::kInvalidArrayLength));
    }
    initial_list_length += nof_property_keys;

    // Collect the element indices into a new list.
    DCHECK_LE(initial_list_length, std::numeric_limits<int>::max());
    MaybeHandle<FixedArray> raw_array = isolate->factory()->TryNewFixedArray(
        static_cast<int>(initial_list_length));
    Handle<FixedArray> combined_keys;

    // If we have a holey backing store try to precisely estimate the backing
    // store size as a last emergency measure if we cannot allocate the big
    // array.
    if (!raw_array.ToHandle(&combined_keys)) {
      if (IsHoleyOrDictionaryElementsKind(kind())) {
        // If we overestimate the result list size we might end up in the
        // large-object space which doesn't free memory on shrinking the list.
        // Hence we try to estimate the final size for holey backing stores more
        // precisely here.
        initial_list_length =
            Subclass::NumberOfElementsImpl(isolate, *object, *backing_store);
        initial_list_length += nof_property_keys;
      }
      DCHECK_LE(initial_list_length, std::numeric_limits<int>::max());
      combined_keys = isolate->factory()->NewFixedArray(
          static_cast<int>(initial_list_length));
    }

    uint32_t nof_indices = 0;
    bool needs_sorting = IsDictionaryElementsKind(kind()) ||
                         IsSloppyArgumentsElementsKind(kind());
    combined_keys = Subclass::DirectCollectElementIndicesImpl(
        isolate, object, backing_store,
        needs_sorting ? GetKeysConversion::kKeepNumbers : convert, filter,
        combined_keys, &nof_indices);

    if (needs_sorting) {
      SortIndices(isolate, combined_keys, nof_indices);
      // Indices from dictionary elements should only be converted after
      // sorting.
      if (convert == GetKeysConversion::kConvertToString) {
        for (uint32_t i = 0; i < nof_indices; i++) {
          DirectHandle<Object> index_string =
              isolate->factory()->Uint32ToString(
                  Object::NumberValue(combined_keys->get(i)));
          combined_keys->set(i, *index_string);
        }
      }
    }

    // Copy over the passed-in property keys.
    CopyObjectToObjectElements(isolate, *keys, PACKED_ELEMENTS, 0,
                               *combined_keys, PACKED_ELEMENTS, nof_indices,
                               nof_property_keys);

    // For holey elements and arguments we might have to shrink the collected
    // keys since the estimates might be off.
    if (IsHoleyOrDictionaryElementsKind(kind()) ||
        IsSloppyArgumentsElementsKind(kind())) {
      // Shrink combined_keys to the final size.
      int final_size = nof_indices + nof_property_keys;
      DCHECK_LE(final_size, combined_keys->length());
      return FixedArray::RightTrimOrEmpty(isolate, combined_keys, final_size);
    }

    return combined_keys;
  }

  V8_WARN_UNUSED_RESULT ExceptionStatus AddElementsToKeyAccumulator(
      Handle<JSObject> receiver, KeyAccumulator* accumulator,
      AddKeyConversion convert) final {
    return Subclass::AddElementsToKeyAccumulatorImpl(receiver, accumulator,
                                                     convert);
  }

  static uint32_t GetCapacityImpl(Tagged<JSObject> holder,
                                  Tagged<FixedArrayBase> backing_store) {
    return backing_store->length();
  }

  size_t GetCapacity(Tagged<JSObject> holder,
                     Tagged<FixedArrayBase> backing_store) final {
    return Subclass::GetCapacityImpl(holder, backing_store);
  }

  static MaybeHandle<Object> FillImpl(DirectHandle<JSObject> receiver,
                                      DirectHandle<Object> obj_value,
                                      size_t start, size_t end) {
    UNREACHABLE();
  }

  MaybeHandle<Object> Fill(Handle<JSObject> receiver, Handle<Object> obj_value,
                           size_t start, size_t end) override {
    return Subclass::FillImpl(receiver, obj_value, start, end);
  }

  static Maybe<bool> IncludesValueImpl(Isolate* isolate,
                                       Handle<JSObject> receiver,
                                       DirectHandle<Object> value,
                                       size_t start_from, size_t length) {
    return IncludesValueSlowPath(isolate, receiver, value, start_from, length);
  }

  Maybe<bool> IncludesValue(Isolate* isolate, Handle<JSObject> receiver,
                            Handle<Object> value, size_t start_from,
                            size_t length) final {
    return Subclass::IncludesValueImpl(isolate, receiver, value, start_from,
                                       length);
  }

  static Maybe<int64_t> IndexOfValueImpl(Isolate* isolate,
                                         Handle<JSObject> receiver,
                                         DirectHandle<Object> value,
                                         size_t start_from, size_t length) {
    return IndexOfValueSlowPath(isolate, receiver, value, start_from, length);
  }

  Maybe<int64_t> IndexOfValue(Isolate* isolate, Handle<JSObject> receiver,
                              Handle<Object> value, size_t start_from,
                              size_t length) final {
    return Subclass::IndexOfValueImpl(isolate, receiver, value, start_from,
                                      length);
  }

  static Maybe<int64_t> LastIndexOfValueImpl(DirectHandle<JSObject> receiver,
                                             DirectHandle<Object> value,
                                             size_t start_from) {
    UNREACHABLE();
  }

  Maybe<int64_t> LastIndexOfValue(Handle<JSObject> receiver,
                                  Handle<Object> value,
                                  size_t start_from) final {
    return Subclass::LastIndexOfValueImpl(receiver, value, start_from);
  }

  static void ReverseImpl(Tagged<JSObject> receiver) { UNREACHABLE(); }

  void Reverse(Tagged<JSObject> receiver) final {
    Subclass::ReverseImpl(receiver);
  }

  static InternalIndex GetEntryForIndexImpl(
      Isolate* isolate, Tagged<JSObject> holder,
      Tagged<FixedArrayBase> backing_store, size_t index,
      PropertyFilter filter) {
    DCHECK(IsFastElementsKind(kind()) ||
           IsAnyNonextensibleElementsKind(kind()));
    size_t length = Subclass::GetMaxIndex(holder, backing_store);
    if (IsHoleyElementsKindForRead(kind())) {
      DCHECK_IMPLIES(
          index < length,
          index <= static_cast<size_t>(std::numeric_limits<int>::max()));
      return index < length &&
                     !Cast<BackingStore>(backing_store)
                          ->is_the_hole(isolate, static_cast<int>(index))
                 ? InternalIndex(index)
                 : InternalIndex::NotFound();
    } else {
      return index < length ? InternalIndex(index) : InternalIndex::NotFound();
    }
  }

  InternalIndex GetEntryForIndex(Isolate* isolate, Tagged<JSObject> holder,
                                 Tagged<FixedArrayBase> backing_store,
                                 size_t index) final {
    return Subclass::GetEntryForIndexImpl(isolate, holder, backing_store, index,
                                          ALL_PROPERTIES);
  }

  static PropertyDetails GetDetailsImpl(Tagged<FixedArrayBase> backing_store,
                                        InternalIndex entry) {
    return PropertyDetails(PropertyKind::kData, NONE,
                           PropertyCellType::kNoCell);
  }

  static PropertyDetails GetDetailsImpl(Tagged<JSObject> holder,
                                        InternalIndex entry) {
    return PropertyDetails(PropertyKind::kData, NONE,
                           PropertyCellType::kNoCell);
  }

  PropertyDetails GetDetails(Tagged<JSObject> holder,
                             InternalIndex entry) final {
    return Subclass::GetDetailsImpl(holder, entry);
  }

  Handle<FixedArray> CreateListFromArrayLike(Isolate* isolate,
                                             Handle<JSObject> object,
                                             uint32_t length) final {
    return Subclass::CreateListFromArrayLikeImpl(isolate, object, length);
  }

  static Handle<FixedArray> CreateListFromArrayLikeImpl(
      Isolate* isolate, DirectHandle<JSObject> object, uint32_t length) {
    UNREACHABLE();
  }
};

class DictionaryElementsAccessor
    : public ElementsAccessorBase<DictionaryElementsAccessor,
                                  ElementsKindTraits<DICTIONARY_ELEMENTS>> {
 public:
  static uint32_t GetMaxIndex(Tagged<JSObject> receiver,
                              Tagged<FixedArrayBase> elements) {
    // We cannot properly estimate this for dictionaries.
    UNREACHABLE();
  }

  static uint32_t GetMaxNumberOfEntries(Isolate* isolate,
                                        Tagged<JSObject> receiver,
                                        Tagged<FixedArrayBase> backing_store) {
    return NumberOfElementsImpl(isolate, receiver, backing_store);
  }

  static uint32_t NumberOfElementsImpl(Isolate* isolate,
                                       Tagged<JSObject> receiver,
                                       Tagged<FixedArrayBase> backing_store) {
    Tagged<NumberDictionary> dict = Cast<NumberDictionary>(backing_store)
"""


```