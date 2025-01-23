Response: The user wants a summary of the C++ source code file `v8/src/objects/string.cc`.
This is the first part of a two-part file. The summary should focus on the functionalities implemented in this part and mention any relation to JavaScript features with examples.

**Plan:**

1. **Identify key data structures and classes:** Look for declarations of structs or classes related to strings.
2. **Analyze the functions:** Go through each function and understand its purpose. Focus on what operations are performed on strings.
3. **Categorize the functionalities:** Group related functions together.
4. **Find connections to JavaScript:** Think about which JavaScript string operations are likely implemented by these C++ functions.
5. **Provide JavaScript examples:** Write simple JavaScript code snippets that demonstrate the functionalities.
这个C++代码文件 `v8/src/objects/string.cc` 的第1部分主要负责实现 V8 引擎中字符串对象的核心功能。 它的主要功能可以归纳为以下几点：

**1. 字符串的创建和共享:**

*   **`String::SlowShare`:**  实现了字符串的共享机制。当 `v8_flags.shared_string_table` 启用时，这个函数会将传入的字符串进行扁平化处理，并尝试在共享字符串表中查找是否已存在相同的字符串。如果存在，则返回已存在的字符串，否则创建新的共享字符串。
*   **`String::MakeThin`:**  将一个字符串对象转换为 `ThinString`。`ThinString` 是一种优化的字符串表示，它存储一个指向实际字符串的指针，用于节省内存，尤其是在字符串被内部化 (internalized) 的情况下。

**2. 外部字符串 (External String) 的管理:**

*   **`ExternalString::InitExternalPointerFieldsDuringExternalization`:**  初始化外部字符串的指针字段。外部字符串的数据存储在 V8 堆外，并通过这个结构体来管理。
*   **`MigrateExternalStringResource` 和 `MigrateExternalString`:** 处理外部字符串在内部化过程中的资源迁移和清理。当一个外部字符串被内部化时，它的外部资源可能需要转移到新的内部化字符串，或者在某些情况下需要被释放。
*   **`String::MakeExternalDuringGC` 和 `String::MakeExternal`:**  将 V8 堆内的字符串转换为外部字符串。这允许将字符串的数据存储在 V8 堆外，适用于处理大量或生命周期较长的字符串，可以减轻 V8 堆的压力。
*   **`String::SupportsExternalization`:**  检查一个字符串是否可以被外部化。

**3. 字符串的比较和相等性判断:**

*   **`String::SlowEquals`:**  实现了字符串的慢速比较，用于判断两个字符串是否相等。它会处理各种字符串类型 (如 `ConsString`, `SlicedString`, `ThinString`)，并进行字符级别的比较。
*   **`String::Compare`:**  实现了字符串的比较，返回 `LessThan`, `GreaterThan` 或 `Equal` 的结果。

**4. 字符串的查找操作:**

*   **`String::IndexOf`:** 实现了查找子字符串在字符串中首次出现的位置的功能。这对应 JavaScript 中的 `String.prototype.indexOf()`。
*   **`String::LastIndexOf`:** 实现了查找子字符串在字符串中最后一次出现的位置的功能。这对应 JavaScript 中的 `String.prototype.lastIndexOf()`。

**5. 字符串的扁平化 (Flattening):**

虽然代码中没有直接名为 `Flatten` 的函数，但可以看到在 `SlowShare`, `SlowEquals`, `Compare`, `IndexOf` 等函数中都调用了 `Flatten` 函数。扁平化是指将由多个片段组成的字符串 (例如 `ConsString`, `SlicedString`) 转换为一个连续存储的字符串 (`SeqString` 或 `ExternalString`)，以便进行更直接的字符访问和比较。

**6. 字符串的哈希计算:**

*   **`String::ComputeAndSetRawHash`:** 计算并设置字符串的哈希值。哈希值用于快速比较字符串是否可能相等，是内部化字符串和字符串查找等操作的重要优化手段。

**7. 字符串的类型转换:**

*   **`String::ToArrayIndex`:**  尝试将字符串转换为数组索引。
*   **`String::ToNumber`:**  将字符串转换为数字。对应 JavaScript 中的 `Number(string)`。

**8. 字符串的调试和打印:**

*   **`String::PrefixForDebugPrint` 和 `String::SuffixForDebugPrint`:**  为调试打印提供字符串的前缀和后缀，用于区分不同类型的字符串。
*   **`String::StringShortPrint` 和 `String::PrintUC16`:**  用于以不同的格式打印字符串的内容。

**9. 字符串到 C 风格字符串的转换:**

*   **`String::ToCString`:**  将 V8 字符串转换为 C 风格的以 null 结尾的字符串。

**与 JavaScript 的关系及示例:**

这个文件中的 C++ 代码直接实现了 JavaScript 中 `String` 对象的一些核心方法和内部机制。以下是一些 JavaScript 示例，展示了这些 C++ 功能对应的 JavaScript 行为：

*   **字符串共享:**
    ```javascript
    const str1 = "hello";
    const str2 = "hello";
    // V8 可能会将 str1 和 str2 指向同一个内部字符串对象，这就是字符串共享。
    ```

*   **外部字符串:**
    ```javascript
    //  某些情况下，从外部源（如文件或网络）加载的字符串可能会以外部字符串的形式存在。
    //  JavaScript 开发者通常不需要直接操作外部字符串，V8 会自动处理。
    ```

*   **字符串比较:**
    ```javascript
    const a = "apple";
    const b = "banana";
    console.log(a === b); // 对应 C++ 中的 SlowEquals
    console.log(a < b);   // 对应 C++ 中的 Compare
    ```

*   **字符串查找:**
    ```javascript
    const text = "This is a test string.";
    console.log(text.indexOf("test"));    // 对应 C++ 中的 String::IndexOf
    console.log(text.lastIndexOf("is")); // 对应 C++ 中的 String::LastIndexOf
    ```

*   **字符串到数字的转换:**
    ```javascript
    const numStr = "123";
    const num = Number(numStr); // 对应 C++ 中的 String::ToNumber
    console.log(num + 1); // 输出 124
    ```

总而言之，`v8/src/objects/string.cc` 的第1部分是 V8 引擎中处理字符串对象的基础设施，它实现了字符串的创建、存储、比较、查找和转换等核心功能，这些功能直接支撑着 JavaScript 中 `String` 对象的各种操作。

### 提示词
```
这是目录为v8/src/objects/string.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/string.h"

#include "src/base/small-vector.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/execution/isolate-utils.h"
#include "src/execution/thread-id.h"
#include "src/handles/handles-inl.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/local-factory-inl.h"
#include "src/heap/local-heap-inl.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/heap/read-only-heap.h"
#include "src/numbers/conversions.h"
#include "src/objects/instance-type.h"
#include "src/objects/map.h"
#include "src/objects/oddball.h"
#include "src/objects/string-comparator.h"
#include "src/objects/string-inl.h"
#include "src/strings/char-predicates.h"
#include "src/strings/string-builder-inl.h"
#include "src/strings/string-hasher.h"
#include "src/strings/string-search.h"
#include "src/strings/string-stream.h"
#include "src/strings/unicode-inl.h"
#include "src/utils/ostreams.h"

namespace v8 {
namespace internal {

Handle<String> String::SlowShare(Isolate* isolate, Handle<String> source) {
  DCHECK(v8_flags.shared_string_table);
  Handle<String> flat = Flatten(isolate, source, AllocationType::kSharedOld);

  // Do not recursively call Share, so directly compute the sharing strategy for
  // the flat string, which could already be a copy or an existing string from
  // e.g. a shortcut ConsString.
  MaybeDirectHandle<Map> new_map;
  switch (isolate->factory()->ComputeSharingStrategyForString(flat, &new_map)) {
    case StringTransitionStrategy::kCopy:
      break;
    case StringTransitionStrategy::kInPlace:
      // A relaxed write is sufficient here, because at this point the string
      // has not yet escaped the current thread.
      DCHECK(HeapLayout::InAnySharedSpace(*flat));
      flat->set_map_no_write_barrier(isolate, *new_map.ToHandleChecked());
      return flat;
    case StringTransitionStrategy::kAlreadyTransitioned:
      return flat;
  }

  uint32_t length = flat->length();
  if (flat->IsOneByteRepresentation()) {
    Handle<SeqOneByteString> copy =
        isolate->factory()->NewRawSharedOneByteString(length).ToHandleChecked();
    DisallowGarbageCollection no_gc;
    WriteToFlat(*flat, copy->GetChars(no_gc), 0, length);
    return copy;
  }
  Handle<SeqTwoByteString> copy =
      isolate->factory()->NewRawSharedTwoByteString(length).ToHandleChecked();
  DisallowGarbageCollection no_gc;
  WriteToFlat(*flat, copy->GetChars(no_gc), 0, length);
  return copy;
}

namespace {

template <class StringClass>
void MigrateExternalStringResource(Isolate* isolate,
                                   Tagged<ExternalString> from,
                                   Tagged<StringClass> to) {
  Address to_resource_address = to->resource_as_address();
  if (to_resource_address == kNullAddress) {
    Tagged<StringClass> cast_from = Cast<StringClass>(from);
    // |to| is a just-created internalized copy of |from|. Migrate the resource.
    to->SetResource(isolate, cast_from->resource());
    // Zap |from|'s resource pointer to reflect the fact that |from| has
    // relinquished ownership of its resource.
    isolate->heap()->UpdateExternalString(
        from, Cast<ExternalString>(from)->ExternalPayloadSize(), 0);
    cast_from->SetResource(isolate, nullptr);
  } else if (to_resource_address != from->resource_as_address()) {
    // |to| already existed and has its own resource. Finalize |from|.
    isolate->heap()->FinalizeExternalString(from);
  }
}

void MigrateExternalString(Isolate* isolate, Tagged<String> string,
                           Tagged<String> internalized) {
  if (IsExternalOneByteString(internalized)) {
    MigrateExternalStringResource(isolate, Cast<ExternalString>(string),
                                  Cast<ExternalOneByteString>(internalized));
  } else if (IsExternalTwoByteString(internalized)) {
    MigrateExternalStringResource(isolate, Cast<ExternalString>(string),
                                  Cast<ExternalTwoByteString>(internalized));
  } else {
    // If the external string is duped into an existing non-external
    // internalized string, free its resource (it's about to be rewritten
    // into a ThinString below).
    isolate->heap()->FinalizeExternalString(string);
  }
}

}  // namespace

void ExternalString::InitExternalPointerFieldsDuringExternalization(
    Tagged<Map> new_map, Isolate* isolate) {
  resource_.Init(address(), isolate, kNullAddress);
  bool is_uncached = (new_map->instance_type() & kUncachedExternalStringMask) ==
                     kUncachedExternalStringTag;
  if (!is_uncached) {
    resource_data_.Init(address(), isolate, kNullAddress);
  }
}

template <typename IsolateT>
void String::MakeThin(IsolateT* isolate, Tagged<String> internalized) {
  DisallowGarbageCollection no_gc;
  DCHECK_NE(this, internalized);
  DCHECK(IsInternalizedString(internalized));

  Tagged<Map> initial_map = map(kAcquireLoad);
  StringShape initial_shape(initial_map);

  DCHECK(!initial_shape.IsThin());

#ifdef DEBUG
  // Check that shared strings can only transition to ThinStrings on the main
  // thread when no other thread is active.
  // The exception is during serialization, as no strings have escaped the
  // thread yet.
  if (initial_shape.IsShared() && !isolate->has_active_deserializer()) {
    isolate->AsIsolate()->global_safepoint()->AssertActive();
  }
#endif

  bool may_contain_recorded_slots = initial_shape.IsIndirect();
  int old_size = SizeFromMap(initial_map);
  ReadOnlyRoots roots(isolate);
  Tagged<Map> target_map = internalized->IsOneByteRepresentation()
                               ? roots.thin_one_byte_string_map()
                               : roots.thin_two_byte_string_map();
  if (initial_shape.IsExternal()) {
    // Notify GC about the layout change before the transition to avoid
    // concurrent marking from observing any in-between state (e.g.
    // ExternalString map where the resource external pointer is overwritten
    // with a tagged pointer).
    // ExternalString -> ThinString transitions can only happen on the
    // main-thread.
    isolate->AsIsolate()->heap()->NotifyObjectLayoutChange(
        Tagged(this), no_gc, InvalidateRecordedSlots::kYes,
        InvalidateExternalPointerSlots::kYes, sizeof(ThinString));
    MigrateExternalString(isolate->AsIsolate(), this, internalized);
  }

  // Update actual first and then do release store on the map word. This ensures
  // that the concurrent marker will read the pointer when visiting a
  // ThinString.
  Tagged<ThinString> thin = UncheckedCast<ThinString>(Tagged(this));
  thin->set_actual(internalized);

  DCHECK_GE(old_size, sizeof(ThinString));
  int size_delta = old_size - sizeof(ThinString);
  if (size_delta != 0) {
    if (!Heap::IsLargeObject(thin)) {
      isolate->heap()->NotifyObjectSizeChange(
          thin, old_size, sizeof(ThinString),
          may_contain_recorded_slots ? ClearRecordedSlots::kYes
                                     : ClearRecordedSlots::kNo);
    } else {
      // We don't need special handling for the combination IsLargeObject &&
      // may_contain_recorded_slots, because indirect strings never get that
      // large.
      DCHECK(!may_contain_recorded_slots);
    }
  }

  if (initial_shape.IsExternal()) {
    set_map(isolate, target_map, kReleaseStore);
  } else {
    set_map_safe_transition(isolate, target_map, kReleaseStore);
  }
}

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void String::MakeThin(
    Isolate* isolate, Tagged<String> internalized);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void String::MakeThin(
    LocalIsolate* isolate, Tagged<String> internalized);

template <typename T>
bool String::MarkForExternalizationDuringGC(Isolate* isolate, T* resource) {
  uint32_t raw_hash = raw_hash_field(kAcquireLoad);
  if (IsExternalForwardingIndex(raw_hash)) return false;
  if (IsInternalizedForwardingIndex(raw_hash)) {
    const int forwarding_index = ForwardingIndexValueBits::decode(raw_hash);
    if (!isolate->string_forwarding_table()->TryUpdateExternalResource(
            forwarding_index, resource)) {
      // The external resource was concurrently updated by another thread.
      return false;
    }
    resource->Unaccount(reinterpret_cast<v8::Isolate*>(isolate));
    raw_hash = Name::IsExternalForwardingIndexBit::update(raw_hash, true);
    set_raw_hash_field(raw_hash, kReleaseStore);
    return true;
  }
  // We need to store the hash in the forwarding table, as all non-external
  // shared strings are in-place internalizable. In case the string gets
  // internalized, we have to ensure that we can get the hash from the
  // forwarding table to satisfy the invariant that all internalized strings
  // have a computed hash value.
  if (!IsHashFieldComputed(raw_hash)) {
    raw_hash = EnsureRawHash();
  }
  DCHECK(IsHashFieldComputed(raw_hash));
  resource->Unaccount(reinterpret_cast<v8::Isolate*>(isolate));
  int forwarding_index =
      isolate->string_forwarding_table()->AddExternalResourceAndHash(
          this, resource, raw_hash);
  set_raw_hash_field(String::CreateExternalForwardingIndex(forwarding_index),
                     kReleaseStore);

  return true;
}

namespace {

template <bool is_one_byte>
Tagged<Map> ComputeExternalStringMap(Isolate* isolate, Tagged<String> string,
                                     int size) {
  ReadOnlyRoots roots(isolate);
  StringShape shape(string, isolate);
  const bool is_internalized = shape.IsInternalized();
  const bool is_shared = shape.IsShared();
  if constexpr (is_one_byte) {
    if (size < static_cast<int>(sizeof(ExternalString))) {
      if (is_internalized) {
        return roots.uncached_external_internalized_one_byte_string_map();
      } else {
        return is_shared ? roots.shared_uncached_external_one_byte_string_map()
                         : roots.uncached_external_one_byte_string_map();
      }
    } else {
      if (is_internalized) {
        return roots.external_internalized_one_byte_string_map();
      } else {
        return is_shared ? roots.shared_external_one_byte_string_map()
                         : roots.external_one_byte_string_map();
      }
    }
  } else {
    if (size < static_cast<int>(sizeof(ExternalString))) {
      if (is_internalized) {
        return roots.uncached_external_internalized_two_byte_string_map();
      } else {
        return is_shared ? roots.shared_uncached_external_two_byte_string_map()
                         : roots.uncached_external_two_byte_string_map();
      }
    } else {
      if (is_internalized) {
        return roots.external_internalized_two_byte_string_map();
      } else {
        return is_shared ? roots.shared_external_two_byte_string_map()
                         : roots.external_two_byte_string_map();
      }
    }
  }
}

}  // namespace

template <typename T>
void String::MakeExternalDuringGC(Isolate* isolate, T* resource) {
  isolate->heap()->safepoint()->AssertActive();
  DCHECK_NE(isolate->heap()->gc_state(), Heap::NOT_IN_GC);

  constexpr bool is_one_byte =
      std::is_base_of_v<v8::String::ExternalOneByteStringResource, T>;
  int size = this->Size();  // Byte size of the original string.
  DCHECK_GE(size, sizeof(UncachedExternalString));

  // Morph the string to an external string by replacing the map and
  // reinitializing the fields.  This won't work if the space the existing
  // string occupies is too small for a regular external string.  Instead, we
  // resort to an uncached external string instead, omitting the field caching
  // the address of the backing store.  When we encounter uncached external
  // strings in generated code, we need to bailout to runtime.
  Tagged<Map> new_map =
      ComputeExternalStringMap<is_one_byte>(isolate, this, size);

  // Byte size of the external String object.
  int new_size = this->SizeFromMap(new_map);

  // Shared strings are never indirect.
  DCHECK(!StringShape(this).IsIndirect());

  if (!isolate->heap()->IsLargeObject(this)) {
    isolate->heap()->NotifyObjectSizeChange(this, size, new_size,
                                            ClearRecordedSlots::kNo);
  }

  // The external pointer slots must be initialized before the new map is
  // installed. Otherwise, a GC marking thread may see the new map before the
  // slots are initialized and attempt to mark the (invalid) external pointers
  // table entries as alive.
  static_cast<ExternalString*>(this)
      ->InitExternalPointerFieldsDuringExternalization(new_map, isolate);

  // We are storing the new map using release store after creating a filler in
  // the NotifyObjectSizeChange call for the left-over space to avoid races with
  // the sweeper thread.
  this->set_map(isolate, new_map, kReleaseStore);

  if constexpr (is_one_byte) {
    Tagged<ExternalOneByteString> self = Cast<ExternalOneByteString>(this);
    self->SetResource(isolate, resource);
  } else {
    Tagged<ExternalTwoByteString> self = Cast<ExternalTwoByteString>(this);
    self->SetResource(isolate, resource);
  }
  isolate->heap()->RegisterExternalString(this);
}

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void String::
    MakeExternalDuringGC(Isolate* isolate,
                         v8::String::ExternalOneByteStringResource*);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void String::
    MakeExternalDuringGC(Isolate* isolate, v8::String::ExternalStringResource*);

bool String::MakeExternal(Isolate* isolate,
                          v8::String::ExternalStringResource* resource) {
  // Disallow garbage collection to avoid possible GC vs string access deadlock.
  DisallowGarbageCollection no_gc;

  // Externalizing twice leaks the external resource, so it's
  // prohibited by the API.
  DCHECK(
      this->SupportsExternalization(v8::String::Encoding::TWO_BYTE_ENCODING));
  DCHECK(resource->IsCacheable());
#ifdef ENABLE_SLOW_DCHECKS
  if (v8_flags.enable_slow_asserts) {
    // Assert that the resource and the string are equivalent.
    DCHECK(static_cast<size_t>(this->length()) == resource->length());
    base::ScopedVector<base::uc16> smart_chars(this->length());
    String::WriteToFlat(this, smart_chars.begin(), 0, this->length());
    DCHECK_EQ(0, memcmp(smart_chars.begin(), resource->data(),
                        resource->length() * sizeof(smart_chars[0])));
  }
#endif                      // DEBUG
  int size = this->Size();  // Byte size of the original string.
  // Abort if size does not allow in-place conversion.
  if (size < static_cast<int>(sizeof(UncachedExternalString))) return false;
  // Read-only strings cannot be made external, since that would mutate the
  // string.
  if (HeapLayout::InReadOnlySpace(this)) return false;
  if (IsShared()) {
    return MarkForExternalizationDuringGC(isolate, resource);
  }
  // For strings in the shared space we need the shared space isolate instead of
  // the current isolate.
  if (HeapLayout::InWritableSharedSpace(this)) {
    resource->Unaccount(reinterpret_cast<v8::Isolate*>(isolate));
    isolate = isolate->shared_space_isolate();
  }
  bool is_internalized = IsInternalizedString(this);
  bool has_pointers = StringShape(this).IsIndirect();

  base::SharedMutexGuardIf<base::kExclusive> shared_mutex_guard(
      isolate->internalized_string_access(), is_internalized);
  // Morph the string to an external string by replacing the map and
  // reinitializing the fields.  This won't work if the space the existing
  // string occupies is too small for a regular external string.  Instead, we
  // resort to an uncached external string instead, omitting the field caching
  // the address of the backing store.  When we encounter uncached external
  // strings in generated code, we need to bailout to runtime.
  constexpr bool is_one_byte = false;
  Tagged<Map> new_map =
      ComputeExternalStringMap<is_one_byte>(isolate, this, size);

  // Byte size of the external String object.
  int new_size = this->SizeFromMap(new_map);

  if (has_pointers) {
    isolate->heap()->NotifyObjectLayoutChange(
        this, no_gc, InvalidateRecordedSlots::kYes,
        InvalidateExternalPointerSlots::kNo, new_size);
  }

  if (!isolate->heap()->IsLargeObject(this)) {
    isolate->heap()->NotifyObjectSizeChange(
        this, size, new_size,
        has_pointers ? ClearRecordedSlots::kYes : ClearRecordedSlots::kNo);
  } else {
    // We don't need special handling for the combination IsLargeObject &&
    // has_pointers, because indirect strings never get that large.
    DCHECK(!has_pointers);
  }

  // The external pointer slots must be initialized before the new map is
  // installed. Otherwise, a GC marking thread may see the new map before the
  // slots are initialized and attempt to mark the (invalid) external pointers
  // table entries as alive.
  static_cast<ExternalString*>(this)
      ->InitExternalPointerFieldsDuringExternalization(new_map, isolate);

  // We are storing the new map using release store after creating a filler in
  // the NotifyObjectSizeChange call for the left-over space to avoid races with
  // the sweeper thread.
  this->set_map(isolate, new_map, kReleaseStore);

  Tagged<ExternalTwoByteString> self = Cast<ExternalTwoByteString>(this);
  self->SetResource(isolate, resource);
  isolate->heap()->RegisterExternalString(this);
  // Force regeneration of the hash value.
  if (is_internalized) self->EnsureHash();
  return true;
}

bool String::MakeExternal(Isolate* isolate,
                          v8::String::ExternalOneByteStringResource* resource) {
  // Disallow garbage collection to avoid possible GC vs string access deadlock.
  DisallowGarbageCollection no_gc;

  // Externalizing twice leaks the external resource, so it's
  // prohibited by the API.
  DCHECK(
      this->SupportsExternalization(v8::String::Encoding::ONE_BYTE_ENCODING));
  DCHECK(resource->IsCacheable());
#ifdef ENABLE_SLOW_DCHECKS
  if (v8_flags.enable_slow_asserts) {
    // Assert that the resource and the string are equivalent.
    DCHECK(static_cast<size_t>(this->length()) == resource->length());
    if (this->IsTwoByteRepresentation()) {
      base::ScopedVector<uint16_t> smart_chars(this->length());
      String::WriteToFlat(this, smart_chars.begin(), 0, this->length());
      DCHECK(String::IsOneByte(smart_chars.begin(), this->length()));
    }
    base::ScopedVector<char> smart_chars(this->length());
    String::WriteToFlat(this, smart_chars.begin(), 0, this->length());
    DCHECK_EQ(0, memcmp(smart_chars.begin(), resource->data(),
                        resource->length() * sizeof(smart_chars[0])));
  }
#endif                      // DEBUG
  int size = this->Size();  // Byte size of the original string.
  // Abort if size does not allow in-place conversion.
  if (size < static_cast<int>(sizeof(UncachedExternalString))) return false;
  // Read-only strings cannot be made external, since that would mutate the
  // string.
  if (HeapLayout::InReadOnlySpace(this)) return false;
  if (IsShared()) {
    return MarkForExternalizationDuringGC(isolate, resource);
  }
  // For strings in the shared space we need the shared space isolate instead of
  // the current isolate.
  if (HeapLayout::InWritableSharedSpace(this)) {
    resource->Unaccount(reinterpret_cast<v8::Isolate*>(isolate));
    isolate = isolate->shared_space_isolate();
  }
  bool is_internalized = IsInternalizedString(this);
  bool has_pointers = StringShape(this).IsIndirect();

  base::SharedMutexGuardIf<base::kExclusive> shared_mutex_guard(
      isolate->internalized_string_access(), is_internalized);
  // Morph the string to an external string by replacing the map and
  // reinitializing the fields.  This won't work if the space the existing
  // string occupies is too small for a regular external string.  Instead, we
  // resort to an uncached external string instead, omitting the field caching
  // the address of the backing store.  When we encounter uncached external
  // strings in generated code, we need to bailout to runtime.
  constexpr bool is_one_byte = true;
  Tagged<Map> new_map =
      ComputeExternalStringMap<is_one_byte>(isolate, this, size);

  if (!isolate->heap()->IsLargeObject(this)) {
    // Byte size of the external String object.
    int new_size = this->SizeFromMap(new_map);

    if (has_pointers) {
      DCHECK(!HeapLayout::InWritableSharedSpace(this));
      isolate->heap()->NotifyObjectLayoutChange(
          this, no_gc, InvalidateRecordedSlots::kYes,
          InvalidateExternalPointerSlots::kNo, new_size);
    }
    isolate->heap()->NotifyObjectSizeChange(
        this, size, new_size,
        has_pointers ? ClearRecordedSlots::kYes : ClearRecordedSlots::kNo);
  } else {
    // We don't need special handling for the combination IsLargeObject &&
    // has_pointers, because indirect strings never get that large.
    DCHECK(!has_pointers);
  }

  // The external pointer slots must be initialized before the new map is
  // installed. Otherwise, a GC marking thread may see the new map before the
  // slots are initialized and attempt to mark the (invalid) external pointers
  // table entries as alive.
  static_cast<ExternalString*>(this)
      ->InitExternalPointerFieldsDuringExternalization(new_map, isolate);

  // We are storing the new map using release store after creating a filler in
  // the NotifyObjectSizeChange call for the left-over space to avoid races with
  // the sweeper thread.
  this->set_map(isolate, new_map, kReleaseStore);

  Tagged<ExternalOneByteString> self = Cast<ExternalOneByteString>(this);
  self->SetResource(isolate, resource);
  isolate->heap()->RegisterExternalString(this);
  // Force regeneration of the hash value.
  if (is_internalized) self->EnsureHash();
  return true;
}

bool String::SupportsExternalization(v8::String::Encoding encoding) {
  if (IsThinString(this)) {
    return i::Cast<i::ThinString>(this)->actual()->SupportsExternalization(
        encoding);
  }

  // RO_SPACE strings cannot be externalized.
  if (HeapLayout::InReadOnlySpace(this)) {
    return false;
  }

#if V8_COMPRESS_POINTERS && !V8_ENABLE_SANDBOX
  // In this configuration, small strings may not be in-place externalizable.
  if (this->Size() < static_cast<int>(sizeof(UncachedExternalString))) {
    return false;
  }
#else
  DCHECK_LE(sizeof(UncachedExternalString), this->Size());
#endif

  StringShape shape(this);

  // Already an external string.
  if (shape.IsExternal()) {
    return false;
  }

  // Only strings in old space can be externalized.
  if (HeapLayout::InYoungGeneration(Tagged(this))) {
    return false;
  }

  // Encoding changes are not supported.
  static_assert(kStringEncodingMask == 1 << 3);
  static_assert(v8::String::Encoding::ONE_BYTE_ENCODING == 1 << 3);
  static_assert(v8::String::Encoding::TWO_BYTE_ENCODING == 0);
  return shape.encoding_tag() == static_cast<uint32_t>(encoding);
}

const char* String::PrefixForDebugPrint() const {
  StringShape shape(this);
  if (IsTwoByteRepresentation()) {
    if (shape.IsInternalized()) {
      return "u#";
    } else if (shape.IsCons()) {
      return "uc\"";
    } else if (shape.IsThin()) {
      return "u>\"";
    } else if (shape.IsExternal()) {
      return "ue\"";
    } else {
      return "u\"";
    }
  } else {
    if (shape.IsInternalized()) {
      return "#";
    } else if (shape.IsCons()) {
      return "c\"";
    } else if (shape.IsThin()) {
      return ">\"";
    } else if (shape.IsExternal()) {
      return "e\"";
    } else {
      return "\"";
    }
  }
  UNREACHABLE();
}

const char* String::SuffixForDebugPrint() const {
  StringShape shape(this);
  if (shape.IsInternalized()) return "";
  return "\"";
}

void String::StringShortPrint(StringStream* accumulator) {
  const uint32_t len = length();
  accumulator->Add("<String[%u]: ", len);
  accumulator->Add(PrefixForDebugPrint());

  if (len > kMaxShortPrintLength) {
    accumulator->Add("...<truncated>>");
    accumulator->Add(SuffixForDebugPrint());
    accumulator->Put('>');
    return;
  }

  PrintUC16(accumulator, 0, len);
  accumulator->Add(SuffixForDebugPrint());
  accumulator->Put('>');
}

void String::PrintUC16(std::ostream& os, int start, int end) {
  if (end < 0) end = length();
  StringCharacterStream stream(this, start);
  for (int i = start; i < end && stream.HasMore(); i++) {
    os << AsUC16(stream.GetNext());
  }
}

void String::PrintUC16(StringStream* accumulator, int start, int end) {
  if (end < 0) end = length();
  StringCharacterStream stream(this, start);
  for (int i = start; i < end && stream.HasMore(); i++) {
    uint16_t c = stream.GetNext();
    if (c == '\n') {
      accumulator->Add("\\n");
    } else if (c == '\r') {
      accumulator->Add("\\r");
    } else if (c == '\\') {
      accumulator->Add("\\\\");
    } else if (!std::isprint(c)) {
      accumulator->Add("\\x%02x", c);
    } else {
      accumulator->Put(static_cast<char>(c));
    }
  }
}

int32_t String::ToArrayIndex(Address addr) {
  DisallowGarbageCollection no_gc;
  Tagged<String> key(addr);

  uint32_t index;
  if (!key->AsArrayIndex(&index)) return -1;
  if (index <= INT_MAX) return index;
  return -1;
}

// static
Handle<Number> String::ToNumber(Isolate* isolate, Handle<String> subject) {
  return isolate->factory()->NewNumber(
      StringToDouble(isolate, subject, ALLOW_NON_DECIMAL_PREFIX));
}

String::FlatContent String::SlowGetFlatContent(
    const DisallowGarbageCollection& no_gc,
    const SharedStringAccessGuardIfNeeded& access_guard) {
  USE(no_gc);
  Tagged<String> string = this;
  StringShape shape(string);
  uint32_t offset = 0;

  // Extract cons- and sliced strings.
  if (shape.IsCons()) {
    Tagged<ConsString> cons = Cast<ConsString>(string);
    if (!cons->IsFlat()) return FlatContent(no_gc);
    string = cons->first();
    shape = StringShape(string);
  } else if (shape.IsSliced()) {
    Tagged<SlicedString> slice = Cast<SlicedString>(string);
    offset = slice->offset();
    string = slice->parent();
    shape = StringShape(string);
  }

  DCHECK(!shape.IsCons());
  DCHECK(!shape.IsSliced());

  // Extract thin strings.
  if (shape.IsThin()) {
    Tagged<ThinString> thin = Cast<ThinString>(string);
    string = thin->actual();
    shape = StringShape(string);
  }

  DCHECK(shape.IsDirect());
  return TryGetFlatContentFromDirectString(no_gc, string, offset, length(),
                                           access_guard)
      .value();
}

std::unique_ptr<char[]> String::ToCString(uint32_t offset, uint32_t length,
                                          size_t* length_return) {
  DCHECK_LE(length, this->length());
  DCHECK_LE(offset, this->length() - length);

  StringCharacterStream stream(this, offset);

  // First, compute the required size of the output buffer.
  size_t utf8_bytes = 0;
  uint32_t remaining_chars = length;
  uint16_t last = unibrow::Utf16::kNoPreviousCharacter;
  while (stream.HasMore() && remaining_chars-- != 0) {
    uint16_t character = stream.GetNext();
    utf8_bytes += unibrow::Utf8::Length(character, last);
    last = character;
  }
  if (length_return) {
    *length_return = utf8_bytes;
  }

  // Second, allocate the output buffer.
  size_t capacity = utf8_bytes + 1;
  char* result = NewArray<char>(capacity);

  // Third, encode the string into the output buffer.
  stream.Reset(this, offset);
  size_t pos = 0;
  remaining_chars = length;
  last = unibrow::Utf16::kNoPreviousCharacter;
  while (stream.HasMore() && remaining_chars-- != 0) {
    uint16_t character = stream.GetNext();
    if (character == 0) {
      character = ' ';
    }

    // Ensure that there's sufficient space for this character and the null
    // terminator. This should normally always be the case, unless there is
    // in-sandbox memory corruption.
    // Alternatively, we could also over-allocate the output buffer by three
    // bytes (the maximum we can write OOB) or consider allocating it inside
    // the sandbox, but it's not clear if that would be worth the effort as the
    // performance overhead of this check appears to be negligible in practice.
    SBXCHECK_LE(unibrow::Utf8::Length(character, last) + 1, capacity - pos);

    pos += unibrow::Utf8::Encode(result + pos, character, last);

    last = character;
  }

  DCHECK_LT(pos, capacity);
  result[pos++] = 0;

  return std::unique_ptr<char[]>(result);
}

std::unique_ptr<char[]> String::ToCString(size_t* length_return) {
  return ToCString(0, length(), length_return);
}

// static
template <typename sinkchar>
void String::WriteToFlat(Tagged<String> source, sinkchar* sink, uint32_t start,
                         uint32_t length) {
  DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(source));
  return WriteToFlat(source, sink, start, length,
                     SharedStringAccessGuardIfNeeded::NotNeeded());
}

// static
template <typename sinkchar>
void String::WriteToFlat(Tagged<String> source, sinkchar* sink, uint32_t start,
                         uint32_t length,
                         const SharedStringAccessGuardIfNeeded& access_guard) {
  DisallowGarbageCollection no_gc;
  if (length == 0) return;
  while (true) {
    DCHECK_GT(length, 0);
    DCHECK_LE(length, source->length());
    DCHECK_LT(start, source->length());
    DCHECK_LE(start + length, source->length());
    switch (StringShape(source).representation_and_encoding_tag()) {
      case kOneByteStringTag | kExternalStringTag:
        CopyChars(sink, Cast<ExternalOneByteString>(source)->GetChars() + start,
                  length);
        return;
      case kTwoByteStringTag | kExternalStringTag:
        CopyChars(sink, Cast<ExternalTwoByteString>(source)->GetChars() + start,
                  length);
        return;
      case kOneByteStringTag | kSeqStringTag:
        CopyChars(
            sink,
            Cast<SeqOneByteString>(source)->GetChars(no_gc, access_guard) +
                start,
            length);
        return;
      case kTwoByteStringTag | kSeqStringTag:
        CopyChars(
            sink,
            Cast<SeqTwoByteString>(source)->GetChars(no_gc, access_guard) +
                start,
            length);
        return;
      case kOneByteStringTag | kConsStringTag:
      case kTwoByteStringTag | kConsStringTag: {
        Tagged<ConsString> cons_string = Cast<ConsString>(source);
        Tagged<String> first = cons_string->first();
        uint32_t boundary = first->length();
        // Here we explicity use signed ints as the values can become negative.
        // The sum of {first_length} and {second_length} is always {length},
        // but the values can become negative, in which case no characters of
        // the respective string are needed.
        int32_t first_length = boundary - start;
        int32_t second_length = length - first_length;
        DCHECK_EQ(static_cast<uint32_t>(first_length + second_length), length);
        if (second_length >= first_length) {
          DCHECK_GT(second_length, 0);
          // Right hand side is longer.  Recurse over left.
          if (first_length > 0) {
            DCHECK_LT(first_length, length);
            DCHECK_LT(second_length, length);

            WriteToFlat(first, sink, start, first_length, access_guard);
            if (start == 0 && cons_string->second() == first) {
              DCHECK_LE(boundary * 2, length);
              CopyChars(sink + boundary, sink, boundary);
              return;
            }
            sink += first_length;
            start = 0;
            length -= first_length;
          } else {
            start -= boundary;
          }
          source = cons_string->second();
        } else {
          DCHECK_GT(first_length, 0);
          // Left hand side is longer.  Recurse over right.
          if (second_length > 0) {
            DCHECK_LT(first_length, length);
            DCHECK_LT(second_length, length);

            uint32_t second_start = first_length;
            DCHECK_EQ(second_start + second_length, length);
            Tagged<String> second = cons_string->second();
            // When repeatedly appending to a string, we get a cons string that
            // is unbalanced to the left, a list, essentially.  We inline the
            // common case of sequential one-byte right child.
            if (second_length == 1) {
              sink[second_start] =
                  static_cast<sinkchar>(second->Get(0, access_guard));
            } else if (IsSeqOneByteString(second)) {
              CopyChars(
                  sink + second_start,
                  Cast<SeqOneByteString>(second)->GetChars(no_gc, access_guard),
                  second_length);
            } else {
              WriteToFlat(second, sink + second_start, 0, second_length,
                          access_guard);
            }
            length -= second_length;
          }
          source = first;
        }
        if (length == 0) return;
        continue;
      }
      case kOneByteStringTag | kSlicedStringTag:
      case kTwoByteStringTag | kSlicedStringTag: {
        Tagged<SlicedString> slice = Cast<SlicedString>(source);
        uint32_t offset = slice->offset();
        source = slice->parent();
        start += offset;
        continue;
      }
      case kOneByteStringTag | kThinStringTag:
      case kTwoByteStringTag | kThinStringTag:
        source = Cast<ThinString>(source)->actual();
        continue;
    }
    UNREACHABLE();
  }
  UNREACHABLE();
}

namespace {

template <typename Char>
size_t WriteUtf8Impl(base::Vector<const Char> string, char* buffer,
                     size_t capacity, bool write_null,
                     bool replace_invalid_utf8) {
  constexpr bool kSourceIsOneByte = sizeof(Char) == 1;

  if constexpr (kSourceIsOneByte) {
    // Only 16-bit characters can contain invalid unicode.
    replace_invalid_utf8 = false;
  }

  size_t write_index = 0;
  const Char* characters = string.begin();
  size_t content_capacity = capacity - write_null;
  uint16_t last = unibrow::Utf16::kNoPreviousCharacter;
  for (size_t read_index = 0; read_index < string.size(); read_index++) {
    Char character = characters[read_index];

    size_t required_capacity;
    if constexpr (kSourceIsOneByte) {
      required_capacity = unibrow::Utf8::LengthOneByte(character);
    } else {
      required_capacity = unibrow::Utf8::Length(character, last);
    }
    size_t remaining_capacity = content_capacity - write_index;
    if (remaining_capacity < required_capacity) {
      // Not enough space left, so stop here.
      if (replace_invalid_utf8 && unibrow::Utf16::IsLeadSurrogate(last)) {
        DCHECK_GE(write_index, unibrow::Utf8::kSizeOfUnmatchedSurrogate);
        // We're in the middle of a surrogate pair. Delete the first part again.
        write_index -= unibrow::Utf8::kSizeOfUnmatchedSurrogate;
      }
      break;
    }

    if constexpr (kSourceIsOneByte) {
      write_index +=
          unibrow::Utf8::EncodeOneByte(buffer + write_index, character);
    } else {
      write_index += unibrow::Utf8::Encode(buffer + write_index, character,
                                           last, replace_invalid_utf8);
    }

    last = character;
  }
  DCHECK_LE(write_index, capacity);

  if (write_null) {
    DCHECK_LT(write_index, capacity);
    buffer[write_index++] = '\0';
  }

  return write_index;
}

}  // namespace

// static
size_t String::WriteUtf8(Isolate* isolate, Handle<String> string, char* buffer,
                         size_t capacity, Utf8EncodingFlags flags) {
  DCHECK_IMPLIES(flags & Utf8EncodingFlag::kNullTerminate, capacity > 0);
  DCHECK_IMPLIES(capacity > 0, buffer != nullptr);

  string = Flatten(isolate, string);

  DisallowGarbageCollection no_gc;
  FlatContent content = string->GetFlatContent(no_gc);
  DCHECK(content.IsFlat());
  if (content.IsOneByte()) {
    return WriteUtf8Impl<uint8_t>(content.ToOneByteVector(), buffer, capacity,
                                  flags & Utf8EncodingFlag::kNullTerminate,
                                  flags & Utf8EncodingFlag::kReplaceInvalid);
  } else {
    return WriteUtf8Impl<uint16_t>(content.ToUC16Vector(), buffer, capacity,
                                   flags & Utf8EncodingFlag::kNullTerminate,
                                   flags & Utf8EncodingFlag::kReplaceInvalid);
  }
}

template <typename SourceChar>
static void CalculateLineEndsImpl(String::LineEndsVector* line_ends,
                                  base::Vector<const SourceChar> src,
                                  bool include_ending_line) {
  const int src_len = src.length();
  for (int i = 0; i < src_len - 1; i++) {
    SourceChar current = src[i];
    SourceChar next = src[i + 1];
    if (IsLineTerminatorSequence(current, next)) line_ends->push_back(i);
  }

  if (src_len > 0 && IsLineTerminatorSequence(src[src_len - 1], 0)) {
    line_ends->push_back(src_len - 1);
  }
  if (include_ending_line) {
    // Include one character beyond the end of script. The rewriter uses that
    // position for the implicit return statement.
    line_ends->push_back(src_len);
  }
}

template <typename IsolateT>
String::LineEndsVector String::CalculateLineEndsVector(
    IsolateT* isolate, Handle<String> src, bool include_ending_line) {
  src = Flatten(isolate, src);
  // Rough estimate of line count based on a roughly estimated average
  // length of packed code. Most scripts have < 32 lines.
  int line_count_estimate = (src->length() >> 6) + 16;
  LineEndsVector line_ends;
  line_ends.reserve(line_count_estimate);
  {
    DisallowGarbageCollection no_gc;
    // Dispatch on type of strings.
    String::FlatContent content = src->GetFlatContent(no_gc);
    DCHECK(content.IsFlat());
    if (content.IsOneByte()) {
      CalculateLineEndsImpl(&line_ends, content.ToOneByteVector(),
                            include_ending_line);
    } else {
      CalculateLineEndsImpl(&line_ends, content.ToUC16Vector(),
                            include_ending_line);
    }
  }
  return line_ends;
}

template String::LineEndsVector String::CalculateLineEndsVector(
    Isolate* isolate, Handle<String> src, bool include_ending_line);
template String::LineEndsVector String::CalculateLineEndsVector(
    LocalIsolate* isolate, Handle<String> src, bool include_ending_line);

template <typename IsolateT>
Handle<FixedArray> String::CalculateLineEnds(IsolateT* isolate,
                                             Handle<String> src,
                                             bool include_ending_line) {
  LineEndsVector line_ends =
      CalculateLineEndsVector(isolate, src, include_ending_line);
  int line_count = static_cast<int>(line_ends.size());
  Handle<FixedArray> array =
      isolate->factory()->NewFixedArray(line_count, AllocationType::kOld);
  {
    DisallowGarbageCollection no_gc;
    Tagged<FixedArray> raw_array = *array;
    for (int i = 0; i < line_count; i++) {
      raw_array->set(i, Smi::FromInt(line_ends[i]));
    }
  }
  return array;
}

template Handle<FixedArray> String::CalculateLineEnds(Isolate* isolate,
                                                      Handle<String> src,
                                                      bool include_ending_line);
template Handle<FixedArray> String::CalculateLineEnds(LocalIsolate* isolate,
                                                      Handle<String> src,
                                                      bool include_ending_line);

bool String::SlowEquals(Tagged<String> other) const {
  DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(this));
  DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(other));
  return SlowEquals(other, SharedStringAccessGuardIfNeeded::NotNeeded());
}

bool String::SlowEquals(
    Tagged<String> other,
    const SharedStringAccessGuardIfNeeded& access_guard) const {
  DisallowGarbageCollection no_gc;
  // Fast check: negative check with lengths.
  uint32_t len = length();
  if (len != other->length()) return false;
  if (len == 0) return true;

  // Fast check: if at least one ThinString is involved, dereference it/them
  // and restart.
  if (IsThinString(this) || IsThinString(other)) {
    if (IsThinString(other)) other = Cast<ThinString>(other)->actual();
    if (IsThinString(this)) {
      return Cast<ThinString>(this)->actual()->Equals(other);
    } else {
      return this->Equals(other);
    }
  }

  // Fast check: if hash code is computed for both strings
  // a fast negative check can be performed.
  uint32_t this_hash;
  uint32_t other_hash;
  if (TryGetHash(&this_hash) && other->TryGetHash(&other_hash)) {
#ifdef ENABLE_SLOW_DCHECKS
    if (v8_flags.enable_slow_asserts) {
      if (this_hash != other_hash) {
        bool found_difference = false;
        for (uint32_t i = 0; i < len; i++) {
          if (Get(i) != other->Get(i)) {
            found_difference = true;
            break;
          }
        }
        DCHECK(found_difference);
      }
    }
#endif
    if (this_hash != other_hash) return false;
  }

  // We know the strings are both non-empty. Compare the first chars
  // before we try to flatten the strings.
  if (this->Get(0, access_guard) != other->Get(0, access_guard)) return false;

  if (IsSeqOneByteString(this) && IsSeqOneByteString(other)) {
    const uint8_t* str1 =
        Cast<SeqOneByteString>(this)->GetChars(no_gc, access_guard);
    const uint8_t* str2 =
        Cast<SeqOneByteString>(other)->GetChars(no_gc, access_guard);
    return CompareCharsEqual(str1, str2, len);
  }

  StringComparator comparator;
  return comparator.Equals(this, other, access_guard);
}

// static
bool String::SlowEquals(Isolate* isolate, Handle<String> one,
                        Handle<String> two) {
  // Fast check: negative check with lengths.
  const uint32_t one_length = one->length();
  if (one_length != two->length()) return false;
  if (one_length == 0) return true;

  // Fast check: if at least one ThinString is involved, dereference it/them
  // and restart.
  if (IsThinString(*one) || IsThinString(*two)) {
    if (IsThinString(*one)) {
      one = handle(Cast<ThinString>(*one)->actual(), isolate);
    }
    if (IsThinString(*two)) {
      two = handle(Cast<ThinString>(*two)->actual(), isolate);
    }
    return String::Equals(isolate, one, two);
  }

  // Fast check: if hash code is computed for both strings
  // a fast negative check can be performed.
  uint32_t one_hash;
  uint32_t two_hash;
  if (one->TryGetHash(&one_hash) && two->TryGetHash(&two_hash)) {
#ifdef ENABLE_SLOW_DCHECKS
    if (v8_flags.enable_slow_asserts) {
      if (one_hash != two_hash) {
        bool found_difference = false;
        for (uint32_t i = 0; i < one_length; i++) {
          if (one->Get(i) != two->Get(i)) {
            found_difference = true;
            break;
          }
        }
        DCHECK(found_difference);
      }
    }
#endif
    if (one_hash != two_hash) return false;
  }

  // We know the strings are both non-empty. Compare the first chars
  // before we try to flatten the strings.
  if (one->Get(0) != two->Get(0)) return false;

  one = String::Flatten(isolate, one);
  two = String::Flatten(isolate, two);

  DisallowGarbageCollection no_gc;
  String::FlatContent flat1 = one->GetFlatContent(no_gc);
  String::FlatContent flat2 = two->GetFlatContent(no_gc);

  if (flat1.IsOneByte() && flat2.IsOneByte()) {
    return CompareCharsEqual(flat1.ToOneByteVector().begin(),
                             flat2.ToOneByteVector().begin(), one_length);
  } else if (flat1.IsTwoByte() && flat2.IsTwoByte()) {
    return CompareCharsEqual(flat1.ToUC16Vector().begin(),
                             flat2.ToUC16Vector().begin(), one_length);
  } else if (flat1.IsOneByte() && flat2.IsTwoByte()) {
    return CompareCharsEqual(flat1.ToOneByteVector().begin(),
                             flat2.ToUC16Vector().begin(), one_length);
  } else if (flat1.IsTwoByte() && flat2.IsOneByte()) {
    return CompareCharsEqual(flat1.ToUC16Vector().begin(),
                             flat2.ToOneByteVector().begin(), one_length);
  }
  UNREACHABLE();
}

// static
ComparisonResult String::Compare(Isolate* isolate, Handle<String> x,
                                 Handle<String> y) {
  // A few fast case tests before we flatten.
  if (x.is_identical_to(y)) {
    return ComparisonResult::kEqual;
  } else if (y->length() == 0) {
    return x->length() == 0 ? ComparisonResult::kEqual
                            : ComparisonResult::kGreaterThan;
  } else if (x->length() == 0) {
    return ComparisonResult::kLessThan;
  }

  int const d = x->Get(0) - y->Get(0);
  if (d < 0) {
    return ComparisonResult::kLessThan;
  } else if (d > 0) {
    return ComparisonResult::kGreaterThan;
  }

  // Slow case.
  x = String::Flatten(isolate, x);
  y = String::Flatten(isolate, y);

  DisallowGarbageCollection no_gc;
  ComparisonResult result = ComparisonResult::kEqual;
  uint32_t prefix_length = x->length();
  if (y->length() < prefix_length) {
    prefix_length = y->length();
    result = ComparisonResult::kGreaterThan;
  } else if (y->length() > prefix_length) {
    result = ComparisonResult::kLessThan;
  }
  int r;
  String::FlatContent x_content = x->GetFlatContent(no_gc);
  String::FlatContent y_content = y->GetFlatContent(no_gc);
  if (x_content.IsOneByte()) {
    base::Vector<const uint8_t> x_chars = x_content.ToOneByteVector();
    if (y_content.IsOneByte()) {
      base::Vector<const uint8_t> y_chars = y_content.ToOneByteVector();
      r = CompareChars(x_chars.begin(), y_chars.begin(), prefix_length);
    } else {
      base::Vector<const base::uc16> y_chars = y_content.ToUC16Vector();
      r = CompareChars(x_chars.begin(), y_chars.begin(), prefix_length);
    }
  } else {
    base::Vector<const base::uc16> x_chars = x_content.ToUC16Vector();
    if (y_content.IsOneByte()) {
      base::Vector<const uint8_t> y_chars = y_content.ToOneByteVector();
      r = CompareChars(x_chars.begin(), y_chars.begin(), prefix_length);
    } else {
      base::Vector<const base::uc16> y_chars = y_content.ToUC16Vector();
      r = CompareChars(x_chars.begin(), y_chars.begin(), prefix_length);
    }
  }
  if (r < 0) {
    result = ComparisonResult::kLessThan;
  } else if (r > 0) {
    result = ComparisonResult::kGreaterThan;
  }
  return result;
}

namespace {

uint32_t ToValidIndex(Tagged<String> str, Tagged<Object> number) {
  uint32_t index = PositiveNumberToUint32(number);
  uint32_t length = str->length();
  if (index > length) return length;
  return index;
}

}  // namespace

Tagged<Object> String::IndexOf(Isolate* isolate, Handle<Object> receiver,
                               Handle<Object> search, Handle<Object> position) {
  if (IsNullOrUndefined(*receiver, isolate)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kCalledOnNullOrUndefined,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  "String.prototype.indexOf")));
  }
  Handle<String> receiver_string;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, receiver_string,
                                     Object::ToString(isolate, receiver));

  Handle<String> search_string;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, search_string,
                                     Object::ToString(isolate, search));

  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, position,
                                     Object::ToInteger(isolate, position));

  uint32_t index = ToValidIndex(*receiver_string, *position);
  return Smi::FromInt(
      String::IndexOf(isolate, receiver_string, search_string, index));
}

namespace {

template <typename T>
int SearchString(Isolate* isolate, String::FlatContent receiver_content,
                 base::Vector<T> pat_vector, int start_index) {
  if (receiver_content.IsOneByte()) {
    return SearchString(isolate, receiver_content.ToOneByteVector(), pat_vector,
                        start_index);
  }
  return SearchString(isolate, receiver_content.ToUC16Vector(), pat_vector,
                      start_index);
}

}  // namespace

int String::IndexOf(Isolate* isolate, Handle<String> receiver,
                    Handle<String> search, uint32_t start_index) {
  DCHECK_LE(start_index, receiver->length());

  uint32_t search_length = search->length();
  if (search_length == 0) return start_index;

  uint32_t receiver_length = receiver->length();
  if (start_index + search_length > receiver_length) return -1;

  receiver = String::Flatten(isolate, receiver);
  search = String::Flatten(isolate, search);

  DisallowGarbageCollection no_gc;  // ensure vectors stay valid
  // Extract flattened substrings of cons strings before getting encoding.
  String::FlatContent receiver_content = receiver->GetFlatContent(no_gc);
  String::FlatContent search_content = search->GetFlatContent(no_gc);

  // dispatch on type of strings
  if (search_content.IsOneByte()) {
    base::Vector<const uint8_t> pat_vector = search_content.ToOneByteVector();
    return SearchString<const uint8_t>(isolate, receiver_content, pat_vector,
                                       start_index);
  }
  base::Vector<const base::uc16> pat_vector = search_content.ToUC16Vector();
  return SearchString<const base::uc16>(isolate, receiver_content, pat_vector,
                                        start_index);
}

MaybeHandle<String> String::GetSubstitution(Isolate* isolate, Match* match,
                                            Handle<String> replacement,
                                            uint32_t start_index) {
  Factory* factory = isolate->factory();

  const int replacement_length = replacement->length();
  const int captures_length = match->CaptureCount();

  replacement = String::Flatten(isolate, replacement);

  Handle<String> dollar_string =
      factory->LookupSingleCharacterStringFromCode('$');
  int next_dollar_ix =
      String::IndexOf(isolate, replacement, dollar_string, start_index);
  if (next_dollar_ix < 0) {
    return replacement;
  }

  IncrementalStringBuilder builder(isolate);

  if (next_dollar_ix > 0) {
    builder.AppendString(factory->NewSubString(replacement, 0, next_dollar_ix));
  }

  while (true) {
    const int peek_ix = next_dollar_ix + 1;
    if (peek_ix >= replacement_length) {
      builder.AppendCharacter('$');
      return indirect_handle(builder.Finish(), isolate);
    }

    int continue_from_ix = -1;
    const uint16_t peek = replacement->Get(peek_ix);
    switch (peek) {
      case '$':  // $$
        builder.AppendCharacter('$');
        continue_from_ix = peek_ix + 1;
        break;
      case '&':  // $& - match
        builder.AppendString(match->GetMatch());
        continue_from_ix = peek_ix + 1;
        break;
      case '`':  // $` - prefix
        builder.AppendString(match->GetPrefix());
        continue_from_ix = peek_ix + 1;
        break;
      case '\'':  // $' - suffix
        builder.AppendString(match->GetSuffix());
        continue_from_ix = peek_ix + 1;
        break;
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9': {
        // Valid indices are $1 .. $9, $01 .. $09 and $10 .. $99
        int scaled_index = (peek - '0');
        int advance = 1;

        if (peek_ix + 1 < replacement_length) {
          const uint16_t next_peek = replacement->Get(peek_ix + 1);
          if (next_peek >= '0' && next_peek <= '9') {
            const int new_scaled_index = scaled_index * 10 + (next_peek - '0');
            if (new_scaled_index < captures_length) {
              scaled_index = new_scaled_index;
              advance = 2;
            }
          }
        }

        if (scaled_index == 0 || scaled_index >= captures_length) {
          builder.AppendCharacter('$');
          continue_from_ix = peek_ix;
          break;
        }

        bool capture_exists;
        Handle<String> capture;
        ASSIGN_RETURN_ON_EXCEPTION(
            isolate, capture, match->GetCapture(scaled_index, &capture_exists));
        if (capture_exists) builder.AppendString(capture);
        continue_from_ix = peek_ix + advance;
        break;
      }
      case '<': {  // $<name> - named capture
        using CaptureState = String::Match::CaptureState;

        if (!match->HasNamedCaptures()) {
          builder.AppendCharacter('$');
          continue_from_ix = peek_ix;
          break;
        }

        Handle<String> bracket_string =
            factory->LookupSingleCharacterStringFromCode('>');
        const int closing_bracket_ix =
            String::IndexOf(isolate, replacement, bracket_string, peek_ix + 1);

        if (closing_bracket_ix == -1) {
          // No closing bracket was found, treat '$<' as a string literal.
          builder.AppendCharacter('$');
          continue_from_ix = peek_ix;
          break;
        }

        Handle<String> capture_name =
            factory->NewSubString(replacement, peek_ix + 1, closing_bracket_ix);
        Handle<String> capture;
        CaptureState capture_state;
        ASSIGN_RETURN_ON_EXCEPTION(
            isolate, capture,
            match->GetNamedCapture(capture_name, &capture_state));

        if (capture_state == CaptureState::MATCHED) {
          builder.AppendString(capture);
        }

        continue_from_ix = closing_bracket_ix + 1;
        break;
      }
      default:
        builder.AppendCharacter('$');
        continue_from_ix = peek_ix;
        break;
    }

    // Go the the next $ in the replacement.
    // TODO(jgruber): Single-char lookups could be much more efficient.
    DCHECK_NE(continue_from_ix, -1);
    next_dollar_ix =
        String::IndexOf(isolate, replacement, dollar_string, continue_from_ix);

    // Return if there are no more $ characters in the replacement. If we
    // haven't reached the end, we need to append the suffix.
    if (next_dollar_ix < 0) {
      if (continue_from_ix < replacement_length) {
        builder.AppendString(factory->NewSubString(
            replacement, continue_from_ix, replacement_length));
      }
      return indirect_handle(builder.Finish(), isolate);
    }

    // Append substring between the previous and the next $ character.
    if (next_dollar_ix > continue_from_ix) {
      builder.AppendString(
          factory->NewSubString(replacement, continue_from_ix, next_dollar_ix));
    }
  }

  UNREACHABLE();
}

namespace {  // for String.Prototype.lastIndexOf

template <typename schar, typename pchar>
int StringMatchBackwards(base::Vector<const schar> subject,
                         base::Vector<const pchar> pattern, int idx) {
  int pattern_length = pattern.length();
  DCHECK_GE(pattern_length, 1);
  DCHECK(idx + pattern_length <= subject.length());

  if (sizeof(schar) == 1 && sizeof(pchar) > 1) {
    for (int i = 0; i < pattern_length; i++) {
      base::uc16 c = pattern[i];
      if (c > String::kMaxOneByteCharCode) {
        return -1;
      }
    }
  }

  pchar pattern_first_char = pattern[0];
  for (int i = idx; i >= 0; i--) {
    if (subject[i] != pattern_first_char) continue;
    int j = 1;
    while (j < pattern_length) {
      if (pattern[j] != subject[i + j]) {
        break;
      }
      j++;
    }
    if (j == pattern_length) {
      return i;
    }
  }
  return -1;
}

}  // namespace

Tagged<Object> String::LastIndexOf(Isolate* isolate, Handle<Object> receiver,
                                   Handle<Object> search,
                                   Handle<Object> position) {
  if (IsNullOrUndefined(*receiver, isolate)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kCalledOnNullOrUndefined,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  "String.prototype.lastIndexOf")));
  }
  Handle<String> receiver_string;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, receiver_string,
                                     Object::ToString(isolate, receiver));

  Handle<String> search_string;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, search_string,
                                     Object::ToString(isolate, search));

  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, position,
                                     Object::ToNumber(isolate, position));

  uint32_t start_index;

  if (IsNaN(*position)) {
    start_index = receiver_string->length();
  } else {
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, position,
                                       Object::ToInteger(isolate, position));
    start_index = ToValidIndex(*receiver_string, *position);
  }

  uint32_t pattern_length = search_string->length();
  uint32_t receiver_length = receiver_string->length();

  if (start_index + pattern_length > receiver_length) {
    start_index = receiver_length - pattern_length;
  }

  if (pattern_length == 0) {
    return Smi::FromInt(start_index);
  }

  receiver_string = String::Flatten(isolate, receiver_string);
  search_string = String::Flatten(isolate, search_string);

  int last_index = -1;
  DisallowGarbageCollection no_gc;  // ensure vectors stay valid

  String::FlatContent receiver_content = receiver_string->GetFlatContent(no_gc);
  String::FlatContent search_content = search_string->GetFlatContent(no_gc);

  if (search_content.IsOneByte()) {
    base::Vector<const uint8_t> pat_vector = search_content.ToOneByteVector();
    if (receiver_content.IsOneByte()) {
      last_index = StringMatchBackwards(receiver_content.ToOneByteVector(),
                                        pat_vector, start_index);
    } else {
      last_index = StringMatchBackwards(receiver_content.ToUC16Vector(),
                                        pat_vector, start_index);
    }
  } else {
    base::Vector<const base::uc16> pat_vector = search_content.ToUC16Vector();
    if (receiver_content.IsOneByte()) {
      last_index = StringMatchBackwards(receiver_content.ToOneByteVector(),
                                        pat_vector, start_index);
    } else {
      last_index = StringMatchBackwards(receiver_content.ToUC16Vector(),
                                        pat_vector, start_index);
    }
  }
  return Smi::FromInt(last_index);
}

bool String::HasOneBytePrefix(base::Vector<const char> str) {
  DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(this));
  return IsEqualToImpl<EqualityType::kPrefix>(
      str, SharedStringAccessGuardIfNeeded::NotNeeded());
}

namespace {

template <typename Char>
bool IsIdentifierVector(base::Vector<Char> vec) {
  if (vec.empty()) {
    return false;
  }
  if (!IsIdentifierStart(vec[0])) {
    return false;
  }
  for (size_t i = 1; i < vec.size(); ++i) {
    if (!IsIdentifierPart(vec[i])) {
      return false;
    }
  }
  return true;
}

}  // namespace

// static
bool String::IsIdentifier(Isolate* isolate, Handle<String> str) {
  str = String::Flatten(isolate, str);
  DisallowGarbageCollection no_gc;
  String::FlatContent flat = str->GetFlatContent(no_gc);
  return flat.IsOneByte() ? IsIdentifierVector(flat.ToOneByteVector())
                          : IsIdentifierVector(flat.ToUC16Vector());
}

namespace {

template <typename Char>
uint32_t HashString(Tagged<String> string, size_t start, uint32_t length,
                    uint64_t seed,
                    const SharedStringAccessGuardIfNeeded& access_guard) {
  DisallowGarbageCollection no_gc;

  if (length > String::kMaxHashCalcLength) {
    return StringHasher::GetTrivialHash(length);
  }

  std::unique_ptr<Char[]> buffer;
  const Char* chars;

  if (IsConsString(string)) {
    DCHECK_EQ(0, start);
    DCHECK(!string->IsFlat());
    buffer.reset(new Char[length]);
    String::WriteToFlat(string, buffer.get(), 0, length, access_guard);
    chars = buffer.get();
  } else {
    chars = string->GetDirectStringChars<Char>(no_gc, access_guard) + start;
  }

  return StringHasher::HashSequentialString<Char>(chars, length, seed);
}

}  // namespace

uint32_t String::ComputeAndSetRawHash() {
  DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(this));
  return ComputeAndSetRawHash(SharedStringAccessGuardIfNeeded::NotNeeded());
}

uint32_t String::ComputeAndSetRawHash(
    const SharedStringAccessGuardIfNeeded& access_guard) {
  DisallowGarbageCollection no_gc;
  // Should only be called if hash code has not yet been computed.
  //
  // If in-place internalizable strings are shared, there may be calls to
  // ComputeAndSetRawHash in parallel. Since only flat strings are in-place
  // internalizable and their contents do not change, the result hash is the
  // same. The raw hash field is stored with relaxed ordering.
  DCHECK_IMPLIES(!v8_flags.shared_string_table, !HasHashCode());

  // Store the hash code in the object.
  uint64_t seed = HashSeed(EarlyGetReadOnlyRoots());
  size_t start = 0;
  Tagged<String> string = this;
  StringShape shape(string);
  if (shape.IsSliced()) {
    Tagged<SlicedString> sliced = Cast<SlicedString>(string);
    start = sliced->offset();
    string = sliced->parent();
    shape = StringShape(string);
  }
  if (shape.IsCons() && string->IsFlat()) {
    string = Cast<ConsString>(string)->first();
    shape = StringShape(string);
  }
  if (shape.IsThin()) {
    string = Cast<ThinString>(string)->actual();
    shape = StringShape(string);
    if (length() == string->length()) {
      uint32_t raw_hash = string->RawHash();
      DCHECK(IsHashFieldComputed(raw_hash));
      set_raw_hash_field(raw_hash);
      return raw_hash;
    }
  }
  uint32_t raw_hash_field =
      shape.encoding_tag() == kOneByteStringTag
          ? HashString<uint8_t>(string, start, length(), seed, access_guard)
          : HashString<uint16_t>(string, start, length(), seed, access_guard);
  set_raw_hash_field_if_empty(raw_hash_field);
  // Check the hash code is there (or a forwarding index if the string was
  // internalized/externalized in parallel).
  DCHECK(HasHashCode() || HasForwardingIndex(kAcquireLoad));
  // Ensure that the hash value of 0 is never computed.
  DCHECK_NE(HashBits::decode(raw_hash_field), 0);
  return raw_hash_field;
}

bool String::SlowAsArrayIndex(uint32_t* index) {
  DisallowGarbageCollection no_gc;
  uint32_t length = this->length();
  if (length <= kMaxCachedArrayIndexLength) {
    uint32_t field = EnsureRawHash();  // Force computation of hash code.
    if (!IsIntegerIndex(field)) return false;
    *index = ArrayIndexValueBits::decode(field);
    return true;
  }
  if (length == 0 || length > kMaxArrayIndexSize) return false;
  StringCharacterStream stream(this);
  return StringToIndex(&stream, index);
}

bool String::SlowAsIntegerIndex(size_t* index) {
  DisallowGarbageCollection no_gc;
  uint32_t length = this->length();
  if (length <= kMaxCachedArrayIndexLength) {
    uint32_t field = EnsureRawHash();  // Force computation of hash code.
    if (!IsIntegerIndex(field)) return false;
    *index = ArrayIndexValueBits::decode(field);
    return true;
  }
  if (length == 0 || length > kMaxIntegerIndexSize) return false;
  StringCharacterStream stream(this);
  return StringToIndex<StringCharacterStream, size_t, kToIntegerIndex>(&stream,
                                                                       index);
}

void String::PrintOn(FILE* file) {
  uint32_t length = this->length();
  for (uint32_t i = 0; i < length; i++) {
    PrintF(file, "%c", Get(i));
  }
}

void String::PrintOn(std::ostream& ostream) {
  uint32_t length = this->length();
  for (uint32_t i = 0; i < length; i++) {
    ostream.put(Get(i));
  }
}

Handle<String> SeqString::Truncate(Isolate* isolate, Handle<SeqString> string,
                                   uint32_t new_length) {
  if (new_length == 0) return string->GetReadOnlyRoots().empty_string_handle();

  int new_size, old_size;
  uint32_t old_length = string->length();
  if (old_length <= new_length) return string;

  if (IsSeqOneByteString(*string)) {
    old_size = SeqOneByteString::SizeFor(old_length);
    new_size = SeqOneByteString::SizeFor(new_length);
  } else {
    DCHECK(IsSeqTwoByteString(*string));
    old_size = SeqTwoByteString::SizeFor(old_length);
    new_size = SeqTwoByteString::SizeFor(new_length);
  }

#if DEBUG
  Address start_of_string = (*string).address();
  DCHECK(IsAligned(start_of_string, kObjectAlignment));
  DCHECK(IsAligned(start_of_string + new_size, kObjectAlignment));
#endif

  Heap* heap = isolate->heap();
  if (!heap->IsLargeObject(*string)) {
    // Sizes are pointer size aligned, so that we can use filler objects
    // that are a multiple of pointer size.
    // No slot invalidation needed since this method is only used on freshly
    // allocated strings.
    heap->NotifyObjectSizeChange(*string, old_size, new_size,
                                 ClearRecordedSlots::kNo);
  }
  // We are storing the new length using release store after creating a filler
  // for the left-over space to avoid races with the sweeper thread.
  string->set_length(new_length, kReleaseStore);
  string->ClearPadding();

  return string;
}

SeqString::DataAndPaddingSizes SeqString::GetDataAndPaddingSizes() const {
  if (IsSeqOneByteString(this)) {
    return Cast<SeqOneByteString>(this)->GetDataAndPaddingSizes();
  }
  return Cast<SeqTwoByteString>(this)->GetDataAndPaddingSizes();
}

SeqString::DataAndPaddingSizes SeqOneByteString::GetDataAndPaddingSizes()
    const {
  int data_size = sizeof(SeqOneByteString) + length() * kOneByteSize;
  int padding_size = SizeFor(length()) - data_size;
  return
```