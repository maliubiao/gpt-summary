Response:
Let's break down the thought process for analyzing the `fixed-array-inl.h` file.

1. **Understand the File Extension:** The filename ends with `.h`. This strongly suggests a header file in C++. Header files typically contain declarations, inline function definitions, and template definitions. The `inl` suffix is a common convention for header files containing inline function definitions. The prompt also provides information about `.tq` files, but since this file is `.h`, we know it's not a Torque file.

2. **Identify the Purpose:** The directory `v8/src/objects/` indicates this file defines or relates to object representations within the V8 engine. The filename `fixed-array-inl.h` suggests it's specifically about `FixedArray` objects and likely provides inline implementations for their methods.

3. **Scan for Key Structures and Templates:**  Quickly scan the file for class and template definitions. Notice the prominent use of templates like `detail::ArrayHeaderBase`, `TaggedArrayBase`, and `PrimitiveArrayBase`. This tells us the code uses a generic approach to handle different types of arrays.

4. **Analyze `detail::ArrayHeaderBase`:**  This template appears to manage the header information of arrays, specifically `capacity` and `length`. Notice the boolean template parameter. This likely differentiates between fixed-size and resizable arrays. The inline functions `capacity()`, `set_capacity()`, `length()`, and `set_length()` are basic accessors and mutators for these properties. The `AcquireLoadTag` and `ReleaseStoreTag` hint at memory ordering considerations for concurrency.

5. **Analyze `TaggedArrayBase`:** This template seems to represent arrays that hold tagged values (likely pointers to JavaScript objects).
    * `IsInBounds()`: Checks if an index is within the array's capacity.
    * `IsCowArray()`: Checks if it's a "copy-on-write" array.
    * `get()`: Overloaded functions to retrieve elements with different memory access semantics (`RelaxedLoadTag`, `AcquireLoadTag`, `SeqCstAccessTag`). This highlights the importance of memory visibility in a concurrent environment.
    * `set()`: Overloaded functions to set elements, including write barrier considerations (`WriteBarrierMode`). The write barrier is crucial for garbage collection.
    * `swap()`, `compare_and_swap()`: Atomic operations, further emphasizing concurrency control.
    * `MoveElements()`, `CopyElements()`:  Bulk operations for moving and copying array elements, interacting with the V8 heap.
    * `RightTrim()`:  Resizes the array by reducing its capacity.
    * `AllocatedSize()`: Returns the allocated memory size.
    * `RawFieldOfFirstElement()`, `RawFieldOfElementAt()`:  Provide raw access to the underlying memory.

6. **Analyze Concrete Array Types:**  Look for specific array types like `FixedArray`, `TrustedFixedArray`, `ProtectedFixedArray`, `FixedDoubleArray`, `WeakFixedArray`, `ArrayList`, `ByteArray`, `TrustedByteArray`, and the various `FixedIntegerArrayBase` and `PodArray` specializations. For each:
    * **`New()` static methods:**  These are factory functions for creating new instances of the array type. Note the handling of capacity/length, allocation types, and initialization.
    * **Specific methods:**  Look for methods unique to each type (e.g., `FixedDoubleArray::get_scalar()`, `set_the_hole()`).

7. **Analyze `PrimitiveArrayBase`:** This template appears to handle arrays of primitive types (like doubles or integers), as opposed to tagged pointers. It has `get()` and `set()` methods for direct access to the primitive values.

8. **Identify Relationships and Common Patterns:** Observe how the template bases are used. `FixedArray` inherits (implicitly through macros) from `TaggedArrayBase`. `FixedDoubleArray` inherits from `PrimitiveArrayBase`. This shows a clear class hierarchy for different kinds of arrays. Notice the consistent pattern of `New()` static methods across different array types.

9. **Address Specific Prompt Questions:**

    * **Functionality:** Based on the analysis, list the key features (data storage, access, manipulation, resizing, etc.).
    * **Torque:** The file extension is `.h`, so it's not a Torque file.
    * **JavaScript Relevance:**  Connect the concepts to JavaScript arrays. `FixedArray` is a fundamental building block. Provide examples of JavaScript code that would internally use these arrays.
    * **Code Logic/Assumptions:** For methods like `IsInBounds`, provide simple input/output examples. For `NewCapacityForIndex`, illustrate how the capacity grows.
    * **Common Programming Errors:** Think about typical array-related errors in JavaScript (index out of bounds, type errors, etc.) and how the C++ code prevents or handles them (e.g., `DCHECK(IsInBounds(index))`).

10. **Refine and Organize:** Structure the findings into a clear and logical format, using headings and bullet points. Provide code examples where appropriate. Ensure the explanation is understandable to someone with some C++ and JavaScript knowledge. For instance, the explanation about write barriers being related to garbage collection and pointer updates is important.

By following these steps, we can systematically analyze the C++ header file and extract its key functionalities and relationships to JavaScript. The key is to understand the purpose of header files, recognize common C++ idioms like templates and inline functions, and connect the low-level C++ concepts to the higher-level abstractions in JavaScript.
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_FIXED_ARRAY_INL_H_
#define V8_OBJECTS_FIXED_ARRAY_INL_H_

#include <optional>

#include "src/common/globals.h"
#include "src/handles/handles-inl.h"
#include "src/heap/heap-write-barrier-inl.h"
#include "src/numbers/conversions.h"
#include "src/objects/bigint.h"
#include "src/objects/compressed-slots.h"
#include "src/objects/fixed-array.h"
#include "src/objects/map.h"
#include "src/objects/maybe-object-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/oddball.h"
#include "src/objects/slots-inl.h"
#include "src/objects/slots.h"
#include "src/roots/roots-inl.h"
#include "src/sandbox/sandboxed-pointer-inl.h"
#include "src/torque/runtime-macro-shims.h"
#include "src/torque/runtime-support.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8::internal {

#include "torque-generated/src/objects/fixed-array-tq-inl.inc"

template <class S>
int detail::ArrayHeaderBase<S, false>::capacity() const {
  return capacity_.load().value();
}

template <class S>
int detail::ArrayHeaderBase<S, false>::capacity(AcquireLoadTag tag) const {
  return capacity_.Acquire_Load().value();
}

template <class S>
void detail::ArrayHeaderBase<S, false>::set_capacity(int value) {
  capacity_.store(this, Smi::FromInt(value));
}

template <class S>
void detail::ArrayHeaderBase<S, false>::set_capacity(int value,
                                                     ReleaseStoreTag tag) {
  capacity_.Release_Store(this, Smi::FromInt(value));
}

template <class S>
int detail::ArrayHeaderBase<S, true>::length() const {
  return length_.load().value();
}

template <class S>
int detail::ArrayHeaderBase<S, true>::length(AcquireLoadTag tag) const {
  return length_.Acquire_Load().value();
}

template <class S>
void detail::ArrayHeaderBase<S, true>::set_length(int value) {
  length_.store(this, Smi::FromInt(value));
}

template <class S>
void detail::ArrayHeaderBase<S, true>::set_length(int value,
                                                  ReleaseStoreTag tag) {
  length_.Release_Store(this, Smi::FromInt(value));
}

template <class S>
int detail::ArrayHeaderBase<S, true>::capacity() const {
  return length();
}

template <class S>
int detail::ArrayHeaderBase<S, true>::capacity(AcquireLoadTag tag) const {
  return length(tag);
}

template <class S>
void detail::ArrayHeaderBase<S, true>::set_capacity(int value) {
  set_length(value);
}

template <class S>
void detail::ArrayHeaderBase<S, true>::set_capacity(int value,
                                                    ReleaseStoreTag tag) {
  set_length(value, tag);
}

template <class D, class S, class P>
bool TaggedArrayBase<D, S, P>::IsInBounds(int index) const {
  return static_cast<unsigned>(index) < static_cast<unsigned>(this->capacity());
}

template <class D, class S, class P>
bool TaggedArrayBase<D, S, P>::IsCowArray() const {
  return this->map() ==
         this->EarlyGetReadOnlyRoots().unchecked_fixed_cow_array_map();
}

template <class D, class S, class P>
Tagged<typename TaggedArrayBase<D, S, P>::ElementT>
TaggedArrayBase<D, S, P>::get(int index) const {
  DCHECK(IsInBounds(index));
  // TODO(jgruber): This tag-less overload shouldn't be relaxed.
  return objects()[index].Relaxed_Load();
}

template <class D, class S, class P>
Tagged<typename TaggedArrayBase<D, S, P>::ElementT>
TaggedArrayBase<D, S, P>::get(int index, RelaxedLoadTag) const {
  DCHECK(IsInBounds(index));
  return objects()[index].Relaxed_Load();
}

template <class D, class S, class P>
Tagged<typename TaggedArrayBase<D, S, P>::ElementT>
TaggedArrayBase<D, S, P>::get(int index, AcquireLoadTag) const {
  DCHECK(IsInBounds(index));
  return objects()[index].Acquire_Load();
}

template <class D, class S, class P>
Tagged<typename TaggedArrayBase<D, S, P>::ElementT>
TaggedArrayBase<D, S, P>::get(int index, SeqCstAccessTag) const {
  DCHECK(IsInBounds(index));
  return objects()[index].SeqCst_Load();
}

template <class D, class S, class P>
void TaggedArrayBase<D, S, P>::set(int index, Tagged<ElementT> value,
                                   WriteBarrierMode mode) {
  DCHECK(!IsCowArray());
  DCHECK(IsInBounds(index));
  // TODO(jgruber): This tag-less overload shouldn't be relaxed.
  objects()[index].Relaxed_Store(this, value, mode);
}

template <class D, class S, class P>
template <typename, typename>
void TaggedArrayBase<D, S, P>::set(int index, Tagged<Smi> value) {
  set(index, value, SKIP_WRITE_BARRIER);
}

template <class D, class S, class P>
void TaggedArrayBase<D, S, P>::set(int index, Tagged<ElementT> value,
                                   RelaxedStoreTag tag, WriteBarrierMode mode) {
  DCHECK(!IsCowArray());
  DCHECK(IsInBounds(index));
  objects()[index].Relaxed_Store(this, value, mode);
}

template <class D, class S, class P>
template <typename, typename>
void TaggedArrayBase<D, S, P>::set(int index, Tagged<Smi> value,
                                   RelaxedStoreTag tag) {
  set(index, value, tag, SKIP_WRITE_BARRIER);
}

template <class D, class S, class P>
void TaggedArrayBase<D, S, P>::set(int index, Tagged<ElementT> value,
                                   ReleaseStoreTag tag, WriteBarrierMode mode) {
  DCHECK(!IsCowArray());
  DCHECK(IsInBounds(index));
  objects()[index].Release_Store(this, value, mode);
}

template <class D, class S, class P>
template <typename, typename>
void TaggedArrayBase<D, S, P>::set(int index, Tagged<Smi> value,
                                   ReleaseStoreTag tag) {
  set(index, value, tag, SKIP_WRITE_BARRIER);
}

template <class D, class S, class P>
void TaggedArrayBase<D, S, P>::set(int index, Tagged<ElementT> value,
                                   SeqCstAccessTag tag, WriteBarrierMode mode) {
  DCHECK(!IsCowArray());
  DCHECK(IsInBounds(index));
  objects()[index].SeqCst_Store(this, value, mode);
}

template <class D, class S, class P>
template <typename, typename>
void TaggedArrayBase<D, S, P>::set(int index, Tagged<Smi> value,
                                   SeqCstAccessTag tag) {
  set(index, value, tag, SKIP_WRITE_BARRIER);
}

template <class D, class S, class P>
Tagged<typename TaggedArrayBase<D, S, P>::ElementT>
TaggedArrayBase<D, S, P>::swap(int index, Tagged<ElementT> value,
                               SeqCstAccessTag, WriteBarrierMode mode) {
  DCHECK(!IsCowArray());
  DCHECK(IsInBounds(index));
  return objects()[index].SeqCst_Swap(this, value, mode);
}

template <class D, class S, class P>
Tagged<typename TaggedArrayBase<D, S, P>::ElementT>
TaggedArrayBase<D, S, P>::compare_and_swap(int index, Tagged<ElementT> expected,
                                           Tagged<ElementT> value,
                                           SeqCstAccessTag,
                                           WriteBarrierMode mode) {
  DCHECK(!IsCowArray());
  DCHECK(IsInBounds(index));
  return objects()[index].SeqCst_CompareAndSwap(this, expected, value, mode);
}

template <class D, class S, class P>
void TaggedArrayBase<D, S, P>::MoveElements(Isolate* isolate, Tagged<D> dst,
                                            int dst_index, Tagged<D> src,
                                            int src_index, int len,
                                            WriteBarrierMode mode) {
  if (len == 0) return;

  DCHECK_GE(len, 0);
  DCHECK(dst->IsInBounds(dst_index));
  DCHECK_LE(dst_index + len, dst->length());
  DCHECK(src->IsInBounds(src_index));
  DCHECK_LE(src_index + len, src->length());

  DisallowGarbageCollection no_gc;
  SlotType dst_slot(&dst->objects()[dst_index]);
  SlotType src_slot(&src->objects()[src_index]);
  isolate->heap()->MoveRange(dst, dst_slot, src_slot, len, mode);
}

template <class D, class S, class P>
void TaggedArrayBase<D, S, P>::CopyElements(Isolate* isolate, Tagged<D> dst,
                                            int dst_index, Tagged<D> src,
                                            int src_index, int len,
                                            WriteBarrierMode mode) {
  if (len == 0) return;

  DCHECK_GE(len, 0);
  DCHECK(dst->IsInBounds(dst_index));
  DCHECK_LE(dst_index + len, dst->capacity());
  DCHECK(src->IsInBounds(src_index));
  DCHECK_LE(src_index + len, src->capacity());

  DisallowGarbageCollection no_gc;
  SlotType dst_slot(&dst->objects()[dst_index]);
  SlotType src_slot(&src->objects()[src_index]);
  isolate->heap()->CopyRange(dst, dst_slot, src_slot, len, mode);
}

template <class D, class S, class P>
void TaggedArrayBase<D, S, P>::RightTrim(Isolate* isolate, int new_capacity) {
  int old_capacity = this->capacity();
  CHECK_GT(new_capacity, 0);  // Due to possible canonicalization.
  CHECK_LE(new_capacity, old_capacity);
  if (new_capacity == old_capacity) return;
  isolate->heap()->RightTrimArray(Cast<D>(this), new_capacity, old_capacity);
}

// Due to right-trimming (which creates a filler object before publishing the
// length through a release-store, see Heap::RightTrimArray), concurrent
// visitors need to read the length with acquire semantics.
template <class D, class S, class P>
int TaggedArrayBase<D, S, P>::AllocatedSize() const {
  return SizeFor(this->capacity(kAcquireLoad));
}

template <class D, class S, class P>
typename TaggedArrayBase<D, S, P>::SlotType
TaggedArrayBase<D, S, P>::RawFieldOfFirstElement() const {
  return RawFieldOfElementAt(0);
}

template <class D, class S, class P>
typename TaggedArrayBase<D, S, P>::SlotType
TaggedArrayBase<D, S, P>::RawFieldOfElementAt(int index) const {
  return SlotType(&objects()[index]);
}

// static
template <class IsolateT>
Handle<FixedArray> FixedArray::New(IsolateT* isolate, int capacity,
                                   AllocationType allocation) {
  if (V8_UNLIKELY(static_cast<unsigned>(capacity) >
                  FixedArrayBase::kMaxLength)) {
    FATAL("Fatal JavaScript invalid size error %d (see crbug.com/1201626)",
          capacity);
  } else if (V8_UNLIKELY(capacity == 0)) {
    return isolate->factory()->empty_fixed_array();
  }

  std::optional<DisallowGarbageCollection> no_gc;
  Handle<FixedArray> result =
      Cast<FixedArray>(Allocate(isolate, capacity, &no_gc, allocation));
  ReadOnlyRoots roots{isolate};
  MemsetTagged((*result)->RawFieldOfFirstElement(), roots.undefined_value(),
               capacity);
  return result;
}

// static
template <class IsolateT>
Handle<TrustedFixedArray> TrustedFixedArray::New(IsolateT* isolate,
                                                 int capacity,
                                                 AllocationType allocation) {
  DCHECK(allocation == AllocationType::kTrusted ||
         allocation == AllocationType::kSharedTrusted);

  if (V8_UNLIKELY(static_cast<unsigned>(capacity) >
                  TrustedFixedArray::kMaxLength)) {
    FATAL("Fatal JavaScript invalid size error %d (see crbug.com/1201626)",
          capacity);
  }
  // TODO(saelo): once we have trusted read-only roots, we can return the
  // empty_trusted_fixed_array here. Currently this isn't possible because the
  // (mutable) empty_trusted_fixed_array will be created via this function.
  // The same is true for the other trusted-space arrays below.

  std::optional<DisallowGarbageCollection> no_gc;
  Handle<TrustedFixedArray> result =
      Cast<TrustedFixedArray>(Allocate(isolate, capacity, &no_gc, allocation));
  MemsetTagged((*result)->RawFieldOfFirstElement(), Smi::zero(), capacity);
  return result;
}

// static
template <class IsolateT>
Handle<ProtectedFixedArray> ProtectedFixedArray::New(IsolateT* isolate,
                                                     int capacity) {
  if (V8_UNLIKELY(static_cast<unsigned>(capacity) >
                  ProtectedFixedArray::kMaxLength)) {
    FATAL("Fatal JavaScript invalid size error %d (see crbug.com/1201626)",
          capacity);
  }

  std::optional<DisallowGarbageCollection> no_gc;
  Handle<ProtectedFixedArray> result = Cast<ProtectedFixedArray>(
      Allocate(isolate, capacity, &no_gc, AllocationType::kTrusted));
  MemsetTagged((*result)->RawFieldOfFirstElement(), Smi::zero(), capacity);
  return result;
}

// static
template <class D, class S, class P>
template <class IsolateT>
Handle<D> TaggedArrayBase<D, S, P>::Allocate(
    IsolateT* isolate, int capacity,
    std::optional<DisallowGarbageCollection>* no_gc_out,
    AllocationType allocation) {
  // Note 0-capacity is explicitly allowed since not all subtypes can be
  // assumed to have canonical 0-capacity instances.
  DCHECK_GE(capacity, 0);
  DCHECK_LE(capacity, kMaxCapacity);
  DCHECK(!no_gc_out->has_value());

  Tagged<D> xs = UncheckedCast<D>(
      isolate->factory()->AllocateRawArray(SizeFor(capacity), allocation));

  ReadOnlyRoots roots{isolate};
  if (DEBUG_BOOL) no_gc_out->emplace();
  Tagged<Map> map = Cast<Map>(roots.object_at(S::kMapRootIndex));
  DCHECK(ReadOnlyHeap::Contains(map));

  xs->set_map_after_allocation(isolate, map, SKIP_WRITE_BARRIER);
  xs->set_capacity(capacity);

  return handle(xs, isolate);
}

// static
template <class D, class S, class P>
constexpr int TaggedArrayBase<D, S, P>::NewCapacityForIndex(int index,
                                                            int old_capacity) {
  DCHECK_GE(index, old_capacity);
  // Note this is currently based on JSObject::NewElementsCapacity.
  int capacity = old_capacity;
  do {
    capacity = capacity + (capacity >> 1) + 16;
  } while (capacity <= index);
  return capacity;
}

TQ_OBJECT_CONSTRUCTORS_IMPL(WeakArrayList)

NEVER_READ_ONLY_SPACE_IMPL(WeakArrayList)

bool FixedArray::is_the_hole(Isolate* isolate, int index) {
  return IsTheHole(get(index), isolate);
}

void FixedArray::set_the_hole(Isolate* isolate, int index) {
  set_the_hole(ReadOnlyRoots(isolate), index);
}

void FixedArray::set_the_hole(ReadOnlyRoots ro_roots, int index) {
  set(index, ro_roots.the_hole_value(), SKIP_WRITE_BARRIER);
}

void FixedArray::FillWithHoles(int from, int to) {
  ReadOnlyRoots roots = GetReadOnlyRoots();
  for (int i = from; i < to; i++) {
    set(i, roots.the_hole_value(), SKIP_WRITE_BARRIER);
  }
}

void FixedArray::MoveElements(Isolate* isolate, int dst_index, int src_index,
                              int len, WriteBarrierMode mode) {
  MoveElements(isolate, this, dst_index, this, src_index, len, mode);
}

void FixedArray::CopyElements(Isolate* isolate, int dst_index,
                              Tagged<FixedArray> src, int src_index, int len,
                              WriteBarrierMode mode) {
  CopyElements(isolate, this, dst_index, src, src_index, len, mode);
}

// static
Handle<FixedArray> FixedArray::Resize(Isolate* isolate,
                                      DirectHandle<FixedArray> xs,
                                      int new_capacity,
                                      AllocationType allocation,
                                      WriteBarrierMode mode) {
  Handle<FixedArray> ys = New(isolate, new_capacity, allocation);
  int elements_to_copy = std::min(new_capacity, xs->capacity());
  FixedArray::CopyElements(isolate, *ys, 0, *xs, 0, elements_to_copy, mode);
  return ys;
}

inline int WeakArrayList::AllocatedSize() const { return SizeFor(capacity()); }

template <class D, class S, class P>
bool PrimitiveArrayBase<D, S, P>::IsInBounds(int index) const {
  return static_cast<unsigned>(index) < static_cast<unsigned>(this->length());
}

template <class D, class S, class P>
auto PrimitiveArrayBase<D, S, P>::get(int index) const -> ElementMemberT {
  DCHECK(IsInBounds(index));
  return values()[index];
}

template <class D, class S, class P>
void PrimitiveArrayBase<D, S, P>::set(int index, ElementMemberT value) {
  DCHECK(IsInBounds(index));
  values()[index] = value;
}

// Due to right-trimming (which creates a filler object before publishing the
// length through a release-store, see Heap::RightTrimArray), concurrent
// visitors need to read the length with acquire semantics.
template <class D, class S, class P>
int PrimitiveArrayBase<D, S, P>::AllocatedSize() const {
  return SizeFor(this->length(kAcquireLoad));
}

template <class D, class S, class P>
auto PrimitiveArrayBase<D, S, P>::begin() -> ElementMemberT* {
  return &values()[0];
}

template <class D, class S, class P>
auto PrimitiveArrayBase<D, S, P>::begin() const -> const ElementMemberT* {
  return &values()[0];
}

template <class D, class S, class P>
auto PrimitiveArrayBase<D, S, P>::end() -> ElementMemberT* {
  return &values()[this->length()];
}

template <class D, class S, class P>
auto PrimitiveArrayBase<D, S, P>::end() const -> const ElementMemberT* {
  return &values()[this->length()];
}

template <class D, class S, class P>
int PrimitiveArrayBase<D, S, P>::DataSize() const {
  int data_size = SizeFor(this->length()) - sizeof(Header);
  DCHECK_EQ(data_size, OBJECT_POINTER_ALIGN(this->length() * kElementSize));
  return data_size;
}

// static
template <class D, class S, class P>
inline Tagged<D> PrimitiveArrayBase<D, S, P>::FromAddressOfFirstElement(
    Address address) {
  DCHECK_TAG_ALIGNED(address);
  return Cast<D>(Tagged<Object>(address - S::kHeaderSize + kHeapObjectTag));
}

// static
template <class IsolateT>
Handle<FixedArrayBase> FixedDoubleArray::New(IsolateT* isolate, int length,
                                             AllocationType allocation) {
  if (V8_UNLIKELY(static_cast<unsigned>(length) > kMaxLength)) {
    FATAL("Fatal JavaScript invalid size error %d (see crbug.com/1201626)",
          length);
  } else if (V8_UNLIKELY(length == 0)) {
    return isolate->factory()->empty_fixed_array();
  }

  std::optional<DisallowGarbageCollection> no_gc;
  return Cast<FixedDoubleArray>(Allocate(isolate, length, &no_gc, allocation));
}

// static
template <class D, class S, class P>
template <class IsolateT>
Handle<D> PrimitiveArrayBase<D, S, P>::Allocate(
    IsolateT* isolate, int length,
    std::optional<DisallowGarbageCollection>* no_gc_out,
    AllocationType allocation) {
  // Note 0-length is explicitly allowed since not all subtypes can be
  // assumed to have canonical 0-length instances.
  DCHECK_GE(length, 0);
  DCHECK_LE(length, kMaxLength);
  DCHECK(!no_gc_out->has_value());

  Tagged<D> xs = UncheckedCast<D>(
      isolate->factory()->AllocateRawArray(SizeFor(length), allocation));

  ReadOnlyRoots roots{isolate};
  if (DEBUG_BOOL) no_gc_out->emplace();
  Tagged<Map> map = Cast<Map>(roots.object_at(S::kMapRootIndex));
  DCHECK(ReadOnlyHeap::Contains(map));

  xs->set_map_after_allocation(isolate, map, SKIP_WRITE_BARRIER);
  xs->set_length(length);

  return handle(xs, isolate);
}

double FixedDoubleArray::get_scalar(int index) {
  DCHECK(!is_the_hole(index));
  return values()[index].value();
}

uint64_t FixedDoubleArray::get_representation(int index) {
  DCHECK(IsInBounds(index));
  return values()[index].value_as_bits();
}

Handle<Object> FixedDoubleArray::get(Tagged<FixedDoubleArray> array, int index,
                                     Isolate* isolate) {
  if (array->is_the_hole(index)) {
    return ReadOnlyRoots(isolate).the_hole_value_handle();
  } else {
    return isolate->factory()->NewNumber(array->get_scalar(index));
  }
}

void FixedDoubleArray::set(int index, double value) {
  if (std::isnan(value)) {
    value = std::numeric_limits<double>::quiet_NaN();
  }
  values()[index].set_value(value);
  DCHECK(!is_the_hole(index));
}

void FixedDoubleArray::set_the_hole(Isolate* isolate, int index) {
  set_the_hole(index);
}

void FixedDoubleArray::set_the_hole(int index) {
  DCHECK(IsInBounds(index));
  values()[index].set_value_as_bits(kHoleNanInt64);
}

bool FixedDoubleArray::is_the_hole(Isolate* isolate, int index) {
  return is_the_hole(index);
}

bool FixedDoubleArray::is_the_hole(int index) {
  return get_representation(index) == kHoleNanInt64;
}

void FixedDoubleArray::MoveElements(Isolate* isolate, int dst_index,
                                    int src_index, int len,
                                    WriteBarrierMode mode) {
  DCHECK_EQ(SKIP_WRITE_BARRIER, mode);
  MemMove(&values()[dst_index], &values()[src_index], len * kElementSize);
}

void FixedDoubleArray::FillWithHoles(int from, int to) {
  for (int i = from; i < to; i++) {
    set_the_hole(i);
  }
}

// static
template <class IsolateT>
Handle<WeakFixedArray> WeakFixedArray::New(IsolateT* isolate, int capacity,
                                           AllocationType allocation,
                                           MaybeHandle<Object> initial_value) {
  CHECK_LE(static_cast<unsigned>(capacity), kMaxCapacity);

  if (V8_UNLIKELY(capacity == 0)) {
    return isolate->factory()->empty_weak_fixed_array();
  }

  std::optional<DisallowGarbageCollection> no_gc;
  Handle<WeakFixedArray> result =
      Cast<WeakFixedArray>(Allocate(isolate, capacity, &no_gc, allocation));
  ReadOnlyRoots roots{isolate};
  MemsetTagged((*result)->RawFieldOfFirstElement(),
               initial_value.is_null() ? roots.undefined_value()
                                       : *initial_value.ToHandleChecked(),
               capacity);
  return result;
}

template <class IsolateT>
Handle<TrustedWeakFixedArray> TrustedWeakFixedArray::New(IsolateT* isolate,
                                                         int capacity) {
  if (V8_UNLIKELY(static_cast<unsigned>(capacity) >
                  TrustedFixedArray::kMaxLength)) {
    FATAL("Fatal JavaScript invalid size error %d (see crbug.com/1201626)",
          capacity);
  }

  std::optional<DisallowGarbageCollection> no_gc;
  Handle<TrustedWeakFixedArray> result = Cast<TrustedWeakFixedArray>(
      Allocate(isolate, capacity, &no_gc, AllocationType::kTrusted));
  MemsetTagged((*result)->RawFieldOfFirstElement(), Smi::zero(), capacity);
  return result;
}

Tagged<MaybeObject> WeakArrayList::Get(int index) const {
  PtrComprCageBase cage_base = GetPtrComprCageBase();
  return Get(cage_base, index);
}
Tagged<MaybeObject> WeakArrayList::get(int index) const { return Get(index); }

Tagged<MaybeObject> WeakArrayList::Get(PtrComprCageBase cage_base,
                                       int index) const {
  DCHECK_LT(static_cast<unsigned>(index), static_cast<unsigned>(capacity()));
  return objects(cage_base, index, kRelaxedLoad);
}

void WeakArrayList::Set(int index, Tagged<MaybeObject> value,
                        WriteBarrierMode mode) {
  set_objects(index, value, kRelaxedStore, mode);
}

void WeakArrayList::Set(int index, Tagged<Smi> value) {
  Set(index, value, SKIP_WRITE_BARRIER);
}

MaybeObjectSlot WeakArrayList::data_start() {
  return RawMaybeWeakField(kObjectsOffset);
}

void WeakArrayList::CopyElements(Isolate* isolate, int dst_index,
                                 Tagged<WeakArrayList> src, int src_index,
                                 int len, WriteBarrierMode mode) {
  if (len == 0) return;
  DCHECK_LE(dst_index + len, capacity());
  DCHECK_LE(src_index + len, src->capacity());
  DisallowGarbageCollection no_gc;

  MaybeObjectSlot dst_slot(data_start() + dst_index);
  MaybeObjectSlot src_slot(src->data_start() + src_index);
  isolate->heap()->CopyRange(*this, dst_slot, src
Prompt: 
```
这是目录为v8/src/objects/fixed-array-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/fixed-array-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_FIXED_ARRAY_INL_H_
#define V8_OBJECTS_FIXED_ARRAY_INL_H_

#include <optional>

#include "src/common/globals.h"
#include "src/handles/handles-inl.h"
#include "src/heap/heap-write-barrier-inl.h"
#include "src/numbers/conversions.h"
#include "src/objects/bigint.h"
#include "src/objects/compressed-slots.h"
#include "src/objects/fixed-array.h"
#include "src/objects/map.h"
#include "src/objects/maybe-object-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/oddball.h"
#include "src/objects/slots-inl.h"
#include "src/objects/slots.h"
#include "src/roots/roots-inl.h"
#include "src/sandbox/sandboxed-pointer-inl.h"
#include "src/torque/runtime-macro-shims.h"
#include "src/torque/runtime-support.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8::internal {

#include "torque-generated/src/objects/fixed-array-tq-inl.inc"

template <class S>
int detail::ArrayHeaderBase<S, false>::capacity() const {
  return capacity_.load().value();
}

template <class S>
int detail::ArrayHeaderBase<S, false>::capacity(AcquireLoadTag tag) const {
  return capacity_.Acquire_Load().value();
}

template <class S>
void detail::ArrayHeaderBase<S, false>::set_capacity(int value) {
  capacity_.store(this, Smi::FromInt(value));
}

template <class S>
void detail::ArrayHeaderBase<S, false>::set_capacity(int value,
                                                     ReleaseStoreTag tag) {
  capacity_.Release_Store(this, Smi::FromInt(value));
}

template <class S>
int detail::ArrayHeaderBase<S, true>::length() const {
  return length_.load().value();
}

template <class S>
int detail::ArrayHeaderBase<S, true>::length(AcquireLoadTag tag) const {
  return length_.Acquire_Load().value();
}

template <class S>
void detail::ArrayHeaderBase<S, true>::set_length(int value) {
  length_.store(this, Smi::FromInt(value));
}

template <class S>
void detail::ArrayHeaderBase<S, true>::set_length(int value,
                                                  ReleaseStoreTag tag) {
  length_.Release_Store(this, Smi::FromInt(value));
}

template <class S>
int detail::ArrayHeaderBase<S, true>::capacity() const {
  return length();
}

template <class S>
int detail::ArrayHeaderBase<S, true>::capacity(AcquireLoadTag tag) const {
  return length(tag);
}

template <class S>
void detail::ArrayHeaderBase<S, true>::set_capacity(int value) {
  set_length(value);
}

template <class S>
void detail::ArrayHeaderBase<S, true>::set_capacity(int value,
                                                    ReleaseStoreTag tag) {
  set_length(value, tag);
}

template <class D, class S, class P>
bool TaggedArrayBase<D, S, P>::IsInBounds(int index) const {
  return static_cast<unsigned>(index) < static_cast<unsigned>(this->capacity());
}

template <class D, class S, class P>
bool TaggedArrayBase<D, S, P>::IsCowArray() const {
  return this->map() ==
         this->EarlyGetReadOnlyRoots().unchecked_fixed_cow_array_map();
}

template <class D, class S, class P>
Tagged<typename TaggedArrayBase<D, S, P>::ElementT>
TaggedArrayBase<D, S, P>::get(int index) const {
  DCHECK(IsInBounds(index));
  // TODO(jgruber): This tag-less overload shouldn't be relaxed.
  return objects()[index].Relaxed_Load();
}

template <class D, class S, class P>
Tagged<typename TaggedArrayBase<D, S, P>::ElementT>
TaggedArrayBase<D, S, P>::get(int index, RelaxedLoadTag) const {
  DCHECK(IsInBounds(index));
  return objects()[index].Relaxed_Load();
}

template <class D, class S, class P>
Tagged<typename TaggedArrayBase<D, S, P>::ElementT>
TaggedArrayBase<D, S, P>::get(int index, AcquireLoadTag) const {
  DCHECK(IsInBounds(index));
  return objects()[index].Acquire_Load();
}

template <class D, class S, class P>
Tagged<typename TaggedArrayBase<D, S, P>::ElementT>
TaggedArrayBase<D, S, P>::get(int index, SeqCstAccessTag) const {
  DCHECK(IsInBounds(index));
  return objects()[index].SeqCst_Load();
}

template <class D, class S, class P>
void TaggedArrayBase<D, S, P>::set(int index, Tagged<ElementT> value,
                                   WriteBarrierMode mode) {
  DCHECK(!IsCowArray());
  DCHECK(IsInBounds(index));
  // TODO(jgruber): This tag-less overload shouldn't be relaxed.
  objects()[index].Relaxed_Store(this, value, mode);
}

template <class D, class S, class P>
template <typename, typename>
void TaggedArrayBase<D, S, P>::set(int index, Tagged<Smi> value) {
  set(index, value, SKIP_WRITE_BARRIER);
}

template <class D, class S, class P>
void TaggedArrayBase<D, S, P>::set(int index, Tagged<ElementT> value,
                                   RelaxedStoreTag tag, WriteBarrierMode mode) {
  DCHECK(!IsCowArray());
  DCHECK(IsInBounds(index));
  objects()[index].Relaxed_Store(this, value, mode);
}

template <class D, class S, class P>
template <typename, typename>
void TaggedArrayBase<D, S, P>::set(int index, Tagged<Smi> value,
                                   RelaxedStoreTag tag) {
  set(index, value, tag, SKIP_WRITE_BARRIER);
}

template <class D, class S, class P>
void TaggedArrayBase<D, S, P>::set(int index, Tagged<ElementT> value,
                                   ReleaseStoreTag tag, WriteBarrierMode mode) {
  DCHECK(!IsCowArray());
  DCHECK(IsInBounds(index));
  objects()[index].Release_Store(this, value, mode);
}

template <class D, class S, class P>
template <typename, typename>
void TaggedArrayBase<D, S, P>::set(int index, Tagged<Smi> value,
                                   ReleaseStoreTag tag) {
  set(index, value, tag, SKIP_WRITE_BARRIER);
}

template <class D, class S, class P>
void TaggedArrayBase<D, S, P>::set(int index, Tagged<ElementT> value,
                                   SeqCstAccessTag tag, WriteBarrierMode mode) {
  DCHECK(!IsCowArray());
  DCHECK(IsInBounds(index));
  objects()[index].SeqCst_Store(this, value, mode);
}

template <class D, class S, class P>
template <typename, typename>
void TaggedArrayBase<D, S, P>::set(int index, Tagged<Smi> value,
                                   SeqCstAccessTag tag) {
  set(index, value, tag, SKIP_WRITE_BARRIER);
}

template <class D, class S, class P>
Tagged<typename TaggedArrayBase<D, S, P>::ElementT>
TaggedArrayBase<D, S, P>::swap(int index, Tagged<ElementT> value,
                               SeqCstAccessTag, WriteBarrierMode mode) {
  DCHECK(!IsCowArray());
  DCHECK(IsInBounds(index));
  return objects()[index].SeqCst_Swap(this, value, mode);
}

template <class D, class S, class P>
Tagged<typename TaggedArrayBase<D, S, P>::ElementT>
TaggedArrayBase<D, S, P>::compare_and_swap(int index, Tagged<ElementT> expected,
                                           Tagged<ElementT> value,
                                           SeqCstAccessTag,
                                           WriteBarrierMode mode) {
  DCHECK(!IsCowArray());
  DCHECK(IsInBounds(index));
  return objects()[index].SeqCst_CompareAndSwap(this, expected, value, mode);
}

template <class D, class S, class P>
void TaggedArrayBase<D, S, P>::MoveElements(Isolate* isolate, Tagged<D> dst,
                                            int dst_index, Tagged<D> src,
                                            int src_index, int len,
                                            WriteBarrierMode mode) {
  if (len == 0) return;

  DCHECK_GE(len, 0);
  DCHECK(dst->IsInBounds(dst_index));
  DCHECK_LE(dst_index + len, dst->length());
  DCHECK(src->IsInBounds(src_index));
  DCHECK_LE(src_index + len, src->length());

  DisallowGarbageCollection no_gc;
  SlotType dst_slot(&dst->objects()[dst_index]);
  SlotType src_slot(&src->objects()[src_index]);
  isolate->heap()->MoveRange(dst, dst_slot, src_slot, len, mode);
}

template <class D, class S, class P>
void TaggedArrayBase<D, S, P>::CopyElements(Isolate* isolate, Tagged<D> dst,
                                            int dst_index, Tagged<D> src,
                                            int src_index, int len,
                                            WriteBarrierMode mode) {
  if (len == 0) return;

  DCHECK_GE(len, 0);
  DCHECK(dst->IsInBounds(dst_index));
  DCHECK_LE(dst_index + len, dst->capacity());
  DCHECK(src->IsInBounds(src_index));
  DCHECK_LE(src_index + len, src->capacity());

  DisallowGarbageCollection no_gc;
  SlotType dst_slot(&dst->objects()[dst_index]);
  SlotType src_slot(&src->objects()[src_index]);
  isolate->heap()->CopyRange(dst, dst_slot, src_slot, len, mode);
}

template <class D, class S, class P>
void TaggedArrayBase<D, S, P>::RightTrim(Isolate* isolate, int new_capacity) {
  int old_capacity = this->capacity();
  CHECK_GT(new_capacity, 0);  // Due to possible canonicalization.
  CHECK_LE(new_capacity, old_capacity);
  if (new_capacity == old_capacity) return;
  isolate->heap()->RightTrimArray(Cast<D>(this), new_capacity, old_capacity);
}

// Due to right-trimming (which creates a filler object before publishing the
// length through a release-store, see Heap::RightTrimArray), concurrent
// visitors need to read the length with acquire semantics.
template <class D, class S, class P>
int TaggedArrayBase<D, S, P>::AllocatedSize() const {
  return SizeFor(this->capacity(kAcquireLoad));
}

template <class D, class S, class P>
typename TaggedArrayBase<D, S, P>::SlotType
TaggedArrayBase<D, S, P>::RawFieldOfFirstElement() const {
  return RawFieldOfElementAt(0);
}

template <class D, class S, class P>
typename TaggedArrayBase<D, S, P>::SlotType
TaggedArrayBase<D, S, P>::RawFieldOfElementAt(int index) const {
  return SlotType(&objects()[index]);
}

// static
template <class IsolateT>
Handle<FixedArray> FixedArray::New(IsolateT* isolate, int capacity,
                                   AllocationType allocation) {
  if (V8_UNLIKELY(static_cast<unsigned>(capacity) >
                  FixedArrayBase::kMaxLength)) {
    FATAL("Fatal JavaScript invalid size error %d (see crbug.com/1201626)",
          capacity);
  } else if (V8_UNLIKELY(capacity == 0)) {
    return isolate->factory()->empty_fixed_array();
  }

  std::optional<DisallowGarbageCollection> no_gc;
  Handle<FixedArray> result =
      Cast<FixedArray>(Allocate(isolate, capacity, &no_gc, allocation));
  ReadOnlyRoots roots{isolate};
  MemsetTagged((*result)->RawFieldOfFirstElement(), roots.undefined_value(),
               capacity);
  return result;
}

// static
template <class IsolateT>
Handle<TrustedFixedArray> TrustedFixedArray::New(IsolateT* isolate,
                                                 int capacity,
                                                 AllocationType allocation) {
  DCHECK(allocation == AllocationType::kTrusted ||
         allocation == AllocationType::kSharedTrusted);

  if (V8_UNLIKELY(static_cast<unsigned>(capacity) >
                  TrustedFixedArray::kMaxLength)) {
    FATAL("Fatal JavaScript invalid size error %d (see crbug.com/1201626)",
          capacity);
  }
  // TODO(saelo): once we have trusted read-only roots, we can return the
  // empty_trusted_fixed_array here. Currently this isn't possible because the
  // (mutable) empty_trusted_fixed_array will be created via this function.
  // The same is true for the other trusted-space arrays below.

  std::optional<DisallowGarbageCollection> no_gc;
  Handle<TrustedFixedArray> result =
      Cast<TrustedFixedArray>(Allocate(isolate, capacity, &no_gc, allocation));
  MemsetTagged((*result)->RawFieldOfFirstElement(), Smi::zero(), capacity);
  return result;
}

// static
template <class IsolateT>
Handle<ProtectedFixedArray> ProtectedFixedArray::New(IsolateT* isolate,
                                                     int capacity) {
  if (V8_UNLIKELY(static_cast<unsigned>(capacity) >
                  ProtectedFixedArray::kMaxLength)) {
    FATAL("Fatal JavaScript invalid size error %d (see crbug.com/1201626)",
          capacity);
  }

  std::optional<DisallowGarbageCollection> no_gc;
  Handle<ProtectedFixedArray> result = Cast<ProtectedFixedArray>(
      Allocate(isolate, capacity, &no_gc, AllocationType::kTrusted));
  MemsetTagged((*result)->RawFieldOfFirstElement(), Smi::zero(), capacity);
  return result;
}

// static
template <class D, class S, class P>
template <class IsolateT>
Handle<D> TaggedArrayBase<D, S, P>::Allocate(
    IsolateT* isolate, int capacity,
    std::optional<DisallowGarbageCollection>* no_gc_out,
    AllocationType allocation) {
  // Note 0-capacity is explicitly allowed since not all subtypes can be
  // assumed to have canonical 0-capacity instances.
  DCHECK_GE(capacity, 0);
  DCHECK_LE(capacity, kMaxCapacity);
  DCHECK(!no_gc_out->has_value());

  Tagged<D> xs = UncheckedCast<D>(
      isolate->factory()->AllocateRawArray(SizeFor(capacity), allocation));

  ReadOnlyRoots roots{isolate};
  if (DEBUG_BOOL) no_gc_out->emplace();
  Tagged<Map> map = Cast<Map>(roots.object_at(S::kMapRootIndex));
  DCHECK(ReadOnlyHeap::Contains(map));

  xs->set_map_after_allocation(isolate, map, SKIP_WRITE_BARRIER);
  xs->set_capacity(capacity);

  return handle(xs, isolate);
}

// static
template <class D, class S, class P>
constexpr int TaggedArrayBase<D, S, P>::NewCapacityForIndex(int index,
                                                            int old_capacity) {
  DCHECK_GE(index, old_capacity);
  // Note this is currently based on JSObject::NewElementsCapacity.
  int capacity = old_capacity;
  do {
    capacity = capacity + (capacity >> 1) + 16;
  } while (capacity <= index);
  return capacity;
}

TQ_OBJECT_CONSTRUCTORS_IMPL(WeakArrayList)

NEVER_READ_ONLY_SPACE_IMPL(WeakArrayList)

bool FixedArray::is_the_hole(Isolate* isolate, int index) {
  return IsTheHole(get(index), isolate);
}

void FixedArray::set_the_hole(Isolate* isolate, int index) {
  set_the_hole(ReadOnlyRoots(isolate), index);
}

void FixedArray::set_the_hole(ReadOnlyRoots ro_roots, int index) {
  set(index, ro_roots.the_hole_value(), SKIP_WRITE_BARRIER);
}

void FixedArray::FillWithHoles(int from, int to) {
  ReadOnlyRoots roots = GetReadOnlyRoots();
  for (int i = from; i < to; i++) {
    set(i, roots.the_hole_value(), SKIP_WRITE_BARRIER);
  }
}

void FixedArray::MoveElements(Isolate* isolate, int dst_index, int src_index,
                              int len, WriteBarrierMode mode) {
  MoveElements(isolate, this, dst_index, this, src_index, len, mode);
}

void FixedArray::CopyElements(Isolate* isolate, int dst_index,
                              Tagged<FixedArray> src, int src_index, int len,
                              WriteBarrierMode mode) {
  CopyElements(isolate, this, dst_index, src, src_index, len, mode);
}

// static
Handle<FixedArray> FixedArray::Resize(Isolate* isolate,
                                      DirectHandle<FixedArray> xs,
                                      int new_capacity,
                                      AllocationType allocation,
                                      WriteBarrierMode mode) {
  Handle<FixedArray> ys = New(isolate, new_capacity, allocation);
  int elements_to_copy = std::min(new_capacity, xs->capacity());
  FixedArray::CopyElements(isolate, *ys, 0, *xs, 0, elements_to_copy, mode);
  return ys;
}

inline int WeakArrayList::AllocatedSize() const { return SizeFor(capacity()); }

template <class D, class S, class P>
bool PrimitiveArrayBase<D, S, P>::IsInBounds(int index) const {
  return static_cast<unsigned>(index) < static_cast<unsigned>(this->length());
}

template <class D, class S, class P>
auto PrimitiveArrayBase<D, S, P>::get(int index) const -> ElementMemberT {
  DCHECK(IsInBounds(index));
  return values()[index];
}

template <class D, class S, class P>
void PrimitiveArrayBase<D, S, P>::set(int index, ElementMemberT value) {
  DCHECK(IsInBounds(index));
  values()[index] = value;
}

// Due to right-trimming (which creates a filler object before publishing the
// length through a release-store, see Heap::RightTrimArray), concurrent
// visitors need to read the length with acquire semantics.
template <class D, class S, class P>
int PrimitiveArrayBase<D, S, P>::AllocatedSize() const {
  return SizeFor(this->length(kAcquireLoad));
}

template <class D, class S, class P>
auto PrimitiveArrayBase<D, S, P>::begin() -> ElementMemberT* {
  return &values()[0];
}

template <class D, class S, class P>
auto PrimitiveArrayBase<D, S, P>::begin() const -> const ElementMemberT* {
  return &values()[0];
}

template <class D, class S, class P>
auto PrimitiveArrayBase<D, S, P>::end() -> ElementMemberT* {
  return &values()[this->length()];
}

template <class D, class S, class P>
auto PrimitiveArrayBase<D, S, P>::end() const -> const ElementMemberT* {
  return &values()[this->length()];
}

template <class D, class S, class P>
int PrimitiveArrayBase<D, S, P>::DataSize() const {
  int data_size = SizeFor(this->length()) - sizeof(Header);
  DCHECK_EQ(data_size, OBJECT_POINTER_ALIGN(this->length() * kElementSize));
  return data_size;
}

// static
template <class D, class S, class P>
inline Tagged<D> PrimitiveArrayBase<D, S, P>::FromAddressOfFirstElement(
    Address address) {
  DCHECK_TAG_ALIGNED(address);
  return Cast<D>(Tagged<Object>(address - S::kHeaderSize + kHeapObjectTag));
}

// static
template <class IsolateT>
Handle<FixedArrayBase> FixedDoubleArray::New(IsolateT* isolate, int length,
                                             AllocationType allocation) {
  if (V8_UNLIKELY(static_cast<unsigned>(length) > kMaxLength)) {
    FATAL("Fatal JavaScript invalid size error %d (see crbug.com/1201626)",
          length);
  } else if (V8_UNLIKELY(length == 0)) {
    return isolate->factory()->empty_fixed_array();
  }

  std::optional<DisallowGarbageCollection> no_gc;
  return Cast<FixedDoubleArray>(Allocate(isolate, length, &no_gc, allocation));
}

// static
template <class D, class S, class P>
template <class IsolateT>
Handle<D> PrimitiveArrayBase<D, S, P>::Allocate(
    IsolateT* isolate, int length,
    std::optional<DisallowGarbageCollection>* no_gc_out,
    AllocationType allocation) {
  // Note 0-length is explicitly allowed since not all subtypes can be
  // assumed to have canonical 0-length instances.
  DCHECK_GE(length, 0);
  DCHECK_LE(length, kMaxLength);
  DCHECK(!no_gc_out->has_value());

  Tagged<D> xs = UncheckedCast<D>(
      isolate->factory()->AllocateRawArray(SizeFor(length), allocation));

  ReadOnlyRoots roots{isolate};
  if (DEBUG_BOOL) no_gc_out->emplace();
  Tagged<Map> map = Cast<Map>(roots.object_at(S::kMapRootIndex));
  DCHECK(ReadOnlyHeap::Contains(map));

  xs->set_map_after_allocation(isolate, map, SKIP_WRITE_BARRIER);
  xs->set_length(length);

  return handle(xs, isolate);
}

double FixedDoubleArray::get_scalar(int index) {
  DCHECK(!is_the_hole(index));
  return values()[index].value();
}

uint64_t FixedDoubleArray::get_representation(int index) {
  DCHECK(IsInBounds(index));
  return values()[index].value_as_bits();
}

Handle<Object> FixedDoubleArray::get(Tagged<FixedDoubleArray> array, int index,
                                     Isolate* isolate) {
  if (array->is_the_hole(index)) {
    return ReadOnlyRoots(isolate).the_hole_value_handle();
  } else {
    return isolate->factory()->NewNumber(array->get_scalar(index));
  }
}

void FixedDoubleArray::set(int index, double value) {
  if (std::isnan(value)) {
    value = std::numeric_limits<double>::quiet_NaN();
  }
  values()[index].set_value(value);
  DCHECK(!is_the_hole(index));
}

void FixedDoubleArray::set_the_hole(Isolate* isolate, int index) {
  set_the_hole(index);
}

void FixedDoubleArray::set_the_hole(int index) {
  DCHECK(IsInBounds(index));
  values()[index].set_value_as_bits(kHoleNanInt64);
}

bool FixedDoubleArray::is_the_hole(Isolate* isolate, int index) {
  return is_the_hole(index);
}

bool FixedDoubleArray::is_the_hole(int index) {
  return get_representation(index) == kHoleNanInt64;
}

void FixedDoubleArray::MoveElements(Isolate* isolate, int dst_index,
                                    int src_index, int len,
                                    WriteBarrierMode mode) {
  DCHECK_EQ(SKIP_WRITE_BARRIER, mode);
  MemMove(&values()[dst_index], &values()[src_index], len * kElementSize);
}

void FixedDoubleArray::FillWithHoles(int from, int to) {
  for (int i = from; i < to; i++) {
    set_the_hole(i);
  }
}

// static
template <class IsolateT>
Handle<WeakFixedArray> WeakFixedArray::New(IsolateT* isolate, int capacity,
                                           AllocationType allocation,
                                           MaybeHandle<Object> initial_value) {
  CHECK_LE(static_cast<unsigned>(capacity), kMaxCapacity);

  if (V8_UNLIKELY(capacity == 0)) {
    return isolate->factory()->empty_weak_fixed_array();
  }

  std::optional<DisallowGarbageCollection> no_gc;
  Handle<WeakFixedArray> result =
      Cast<WeakFixedArray>(Allocate(isolate, capacity, &no_gc, allocation));
  ReadOnlyRoots roots{isolate};
  MemsetTagged((*result)->RawFieldOfFirstElement(),
               initial_value.is_null() ? roots.undefined_value()
                                       : *initial_value.ToHandleChecked(),
               capacity);
  return result;
}

template <class IsolateT>
Handle<TrustedWeakFixedArray> TrustedWeakFixedArray::New(IsolateT* isolate,
                                                         int capacity) {
  if (V8_UNLIKELY(static_cast<unsigned>(capacity) >
                  TrustedFixedArray::kMaxLength)) {
    FATAL("Fatal JavaScript invalid size error %d (see crbug.com/1201626)",
          capacity);
  }

  std::optional<DisallowGarbageCollection> no_gc;
  Handle<TrustedWeakFixedArray> result = Cast<TrustedWeakFixedArray>(
      Allocate(isolate, capacity, &no_gc, AllocationType::kTrusted));
  MemsetTagged((*result)->RawFieldOfFirstElement(), Smi::zero(), capacity);
  return result;
}

Tagged<MaybeObject> WeakArrayList::Get(int index) const {
  PtrComprCageBase cage_base = GetPtrComprCageBase();
  return Get(cage_base, index);
}
Tagged<MaybeObject> WeakArrayList::get(int index) const { return Get(index); }

Tagged<MaybeObject> WeakArrayList::Get(PtrComprCageBase cage_base,
                                       int index) const {
  DCHECK_LT(static_cast<unsigned>(index), static_cast<unsigned>(capacity()));
  return objects(cage_base, index, kRelaxedLoad);
}

void WeakArrayList::Set(int index, Tagged<MaybeObject> value,
                        WriteBarrierMode mode) {
  set_objects(index, value, kRelaxedStore, mode);
}

void WeakArrayList::Set(int index, Tagged<Smi> value) {
  Set(index, value, SKIP_WRITE_BARRIER);
}

MaybeObjectSlot WeakArrayList::data_start() {
  return RawMaybeWeakField(kObjectsOffset);
}

void WeakArrayList::CopyElements(Isolate* isolate, int dst_index,
                                 Tagged<WeakArrayList> src, int src_index,
                                 int len, WriteBarrierMode mode) {
  if (len == 0) return;
  DCHECK_LE(dst_index + len, capacity());
  DCHECK_LE(src_index + len, src->capacity());
  DisallowGarbageCollection no_gc;

  MaybeObjectSlot dst_slot(data_start() + dst_index);
  MaybeObjectSlot src_slot(src->data_start() + src_index);
  isolate->heap()->CopyRange(*this, dst_slot, src_slot, len, mode);
}

Tagged<HeapObject> WeakArrayList::Iterator::Next() {
  if (!array_.is_null()) {
    while (index_ < array_->length()) {
      Tagged<MaybeObject> item = array_->Get(index_++);
      DCHECK(item.IsWeakOrCleared());
      if (!item.IsCleared()) return item.GetHeapObjectAssumeWeak();
    }
    array_ = WeakArrayList();
  }
  return Tagged<HeapObject>();
}

int ArrayList ::length() const { return length_.load().value(); }
void ArrayList ::set_length(int value) {
  length_.store(this, Smi::FromInt(value));
}

// static
template <class IsolateT>
Handle<ArrayList> ArrayList::New(IsolateT* isolate, int capacity,
                                 AllocationType allocation) {
  if (capacity == 0) return isolate->factory()->empty_array_list();

  DCHECK_GT(capacity, 0);
  DCHECK_LE(capacity, kMaxCapacity);

  std::optional<DisallowGarbageCollection> no_gc;
  Handle<ArrayList> result =
      Cast<ArrayList>(Allocate(isolate, capacity, &no_gc, allocation));
  result->set_length(0);
  ReadOnlyRoots roots{isolate};
  MemsetTagged(result->RawFieldOfFirstElement(), roots.undefined_value(),
               capacity);
  return result;
}

// static
template <class IsolateT>
Handle<ByteArray> ByteArray::New(IsolateT* isolate, int length,
                                 AllocationType allocation) {
  if (V8_UNLIKELY(static_cast<unsigned>(length) > kMaxLength)) {
    FATAL("Fatal JavaScript invalid size error %d", length);
  } else if (V8_UNLIKELY(length == 0)) {
    return isolate->factory()->empty_byte_array();
  }

  std::optional<DisallowGarbageCollection> no_gc;
  Handle<ByteArray> result =
      Cast<ByteArray>(Allocate(isolate, length, &no_gc, allocation));

  int padding_size = SizeFor(length) - OffsetOfElementAt(length);
  memset(&result->values()[length], 0, padding_size);

  return result;
}

uint32_t ByteArray::get_int(int offset) const {
  DCHECK(IsInBounds(offset));
  DCHECK_LE(offset + sizeof(uint32_t), length());
  return base::ReadUnalignedValue<uint32_t>(
      reinterpret_cast<Address>(&values()[offset]));
}

void ByteArray::set_int(int offset, uint32_t value) {
  DCHECK(IsInBounds(offset));
  DCHECK_LE(offset + sizeof(uint32_t), length());
  base::WriteUnalignedValue<uint32_t>(
      reinterpret_cast<Address>(&values()[offset]), value);
}

// static
template <class IsolateT>
Handle<TrustedByteArray> TrustedByteArray::New(IsolateT* isolate, int length,
                                               AllocationType allocation_type) {
  DCHECK(allocation_type == AllocationType::kTrusted ||
         allocation_type == AllocationType::kSharedTrusted);
  if (V8_UNLIKELY(static_cast<unsigned>(length) > kMaxLength)) {
    FATAL("Fatal JavaScript invalid size error %d", length);
  }

  std::optional<DisallowGarbageCollection> no_gc;
  Handle<TrustedByteArray> result = Cast<TrustedByteArray>(
      Allocate(isolate, length, &no_gc, allocation_type));

  int padding_size = SizeFor(length) - OffsetOfElementAt(length);
  memset(&result->values()[length], 0, padding_size);

  return result;
}

uint32_t TrustedByteArray::get_int(int offset) const {
  DCHECK(IsInBounds(offset));
  DCHECK_LE(offset + sizeof(uint32_t), length());
  return base::ReadUnalignedValue<uint32_t>(
      reinterpret_cast<Address>(&values()[offset]));
}

void TrustedByteArray::set_int(int offset, uint32_t value) {
  DCHECK(IsInBounds(offset));
  DCHECK_LE(offset + sizeof(uint32_t), length());
  base::WriteUnalignedValue<uint32_t>(
      reinterpret_cast<Address>(&values()[offset]), value);
}

template <typename Base>
template <typename... MoreArgs>
// static
Handle<FixedAddressArrayBase<Base>> FixedAddressArrayBase<Base>::New(
    Isolate* isolate, int length, MoreArgs&&... more_args) {
  return Cast<FixedAddressArrayBase>(
      Underlying::New(isolate, length, std::forward<MoreArgs>(more_args)...));
}

template <typename T, typename Base>
template <typename... MoreArgs>
// static
Handle<FixedIntegerArrayBase<T, Base>> FixedIntegerArrayBase<T, Base>::New(
    Isolate* isolate, int length, MoreArgs&&... more_args) {
  int byte_length;
  CHECK(!base::bits::SignedMulOverflow32(length, sizeof(T), &byte_length));
  return Cast<FixedIntegerArrayBase<T, Base>>(
      Base::New(isolate, byte_length, std::forward<MoreArgs>(more_args)...));
}

template <typename T, typename Base>
Address FixedIntegerArrayBase<T, Base>::get_element_address(int index) const {
  DCHECK_GE(index, 0);
  DCHECK_LT(index, length());
  return reinterpret_cast<Address>(&this->values()[index * sizeof(T)]);
}

template <typename T, typename Base>
T FixedIntegerArrayBase<T, Base>::get(int index) const {
  static_assert(std::is_integral<T>::value);
  return base::ReadUnalignedValue<T>(get_element_address(index));
}

template <typename T, typename Base>
void FixedIntegerArrayBase<T, Base>::set(int index, T value) {
  static_assert(std::is_integral<T>::value);
  return base::WriteUnalignedValue<T>(get_element_address(index), value);
}

template <typename T, typename Base>
int FixedIntegerArrayBase<T, Base>::length() const {
  DCHECK_EQ(Base::length() % sizeof(T), 0);
  return Base::length() / sizeof(T);
}

template <typename Base>
Address FixedAddressArrayBase<Base>::get_sandboxed_pointer(int index) const {
  PtrComprCageBase sandbox_base = GetPtrComprCageBase(this);
  return ReadSandboxedPointerField(this->get_element_address(index),
                                   sandbox_base);
}

template <typename Base>
void FixedAddressArrayBase<Base>::set_sandboxed_pointer(int index,
                                                        Address value) {
  PtrComprCageBase sandbox_base = GetPtrComprCageBase(this);
  WriteSandboxedPointerField(this->get_element_address(index), sandbox_base,
                             value);
}

template <class T, class Super>
int PodArrayBase<T, Super>::length() const {
  return Super::length() / sizeof(T);
}

// static
template <class T>
Handle<PodArray<T>> PodArray<T>::New(Isolate* isolate, int length,
                                     AllocationType allocation) {
  int byte_length;
  CHECK(!base::bits::SignedMulOverflow32(length, sizeof(T), &byte_length));
  return Cast<PodArray<T>>(
      isolate->factory()->NewByteArray(byte_length, allocation));
}

// static
template <class T>
Handle<PodArray<T>> PodArray<T>::New(LocalIsolate* isolate, int length,
                                     AllocationType allocation) {
  int byte_length;
  CHECK(!base::bits::SignedMulOverflow32(length, sizeof(T), &byte_length));
  return Cast<PodArray<T>>(
      isolate->factory()->NewByteArray(byte_length, allocation));
}

// static
template <class T>
Handle<TrustedPodArray<T>> TrustedPodArray<T>::New(Isolate* isolate,
                                                   int length) {
  int byte_length;
  CHECK(!base::bits::SignedMulOverflow32(length, sizeof(T), &byte_length));
  return Cast<TrustedPodArray<T>>(
      isolate->factory()->NewTrustedByteArray(byte_length));
}

// static
template <class T>
Handle<TrustedPodArray<T>> TrustedPodArray<T>::New(LocalIsolate* isolate,
                                                   int length) {
  int byte_length;
  CHECK(!base::bits::SignedMulOverflow32(length, sizeof(T), &byte_length));
  return Cast<TrustedPodArray<T>>(
      isolate->factory()->NewTrustedByteArray(byte_length));
}

}  // namespace v8::internal

#include "src/objects/object-macros-undef.h"

#endif  // V8_OBJECTS_FIXED_ARRAY_INL_H_

"""

```