Response: The user wants a summary of the functionality of the C++ source code file `v8/test/unittests/objects/weakmaps-unittest.cc`.

This file contains unit tests for the `WeakMap` implementation in V8. The tests cover various aspects of `WeakMap` behavior, especially related to garbage collection and memory management.

Here's a plan to summarize the functionality:
1. Identify the main purpose of the file (unit testing WeakMaps).
2. Go through each test case (`TEST_F`) and determine what aspect of WeakMap functionality it tests.
3. Group related test cases for a more concise summary.
4. Summarize the overall functionality covered by the tests.
这个C++源代码文件 `v8/test/unittests/objects/weakmaps-unittest.cc` 是V8 JavaScript引擎的单元测试文件，专门用于测试 `WeakMap` 对象的各种功能和特性。

具体来说，这个文件中的测试用例主要涵盖了以下几个方面的 `WeakMap` 功能：

1. **弱引用特性 (Weakness):**
   - 测试当 `WeakMap` 的键不再被强引用时，其对应的条目是否会被垃圾回收器清除。
   - 测试使用了弱回调 (WeakCallback) 来验证键对象被回收时的行为。
   - 测试了符号 (Symbol) 作为键在 `WeakMap` 中的弱引用特性。

2. **容量调整 (Shrinking):**
   - 测试当 `WeakMap` 中的元素被垃圾回收清除后，其内部哈希表是否会缩小容量以节省内存。

3. **垃圾回收与晋升 (WeakMapPromotionMarkCompact):**
   - 测试在标记压缩 (Mark-Compact) 垃圾回收过程中，年轻代 (Young Generation) 的 `WeakMap` 及其条目晋升到老年代 (Old Generation) 的行为。

4. **Scavenge 垃圾回收 (WeakMapScavenge):**
   - 测试在 Scavenge (Minor GC) 垃圾回收过程中，年轻代的 `WeakMap` 及其条目的处理方式。

5. **记录槽缓冲区 (Regress2060a, Regress2060b):**
   - 测试在压缩垃圾回收过程中，`WeakMap` 的值对象（可能位于疏散候选页）能被正确记录在槽缓冲区中，即使没有其他强引用。
   - 测试在压缩垃圾回收过程中，`WeakMap` 的键对象（可能位于疏散候选页）如果被其他路径强引用，也能被正确记录在槽缓冲区中。

6. **增量标记 (Regress399527):**
   - 测试在增量标记 (Incremental Marking) 垃圾回收过程中，对 `WeakMap` 的处理，避免出现因标记状态不一致导致的问题。

7. **处理链式条目 (WeakMapsWithChainedEntries):**
   - 测试 `WeakMap` 如何处理相互引用的键值对，确保在没有强引用后能被正确回收。

总而言之，`v8/test/unittests/objects/weakmaps-unittest.cc` 文件的主要目的是**确保 V8 引擎中 `WeakMap` 的实现符合预期，特别是在各种垃圾回收场景下，其弱引用特性和内存管理行为是正确可靠的。** 这对于保证 JavaScript 中 `WeakMap` 的正确语义和性能至关重要。

Prompt: ```这是目录为v8/test/unittests/objects/weakmaps-unittest.cc的一个c++源代码文件， 请归纳一下它的功能

"""
// Copyright 2011 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <utility>

#include "src/execution/isolate.h"
#include "src/handles/global-handles-inl.h"
#include "src/heap/factory.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap-layout-inl.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/js-collection-inl.h"
#include "src/objects/objects-inl.h"
#include "test/unittests/heap/heap-utils.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace internal {
namespace test_weakmaps {

using WeakMapsTest = TestWithHeapInternalsAndContext;

static int NumberOfWeakCalls = 0;
static void WeakPointerCallback(const v8::WeakCallbackInfo<void>& data) {
  std::pair<v8::Persistent<v8::Value>*, int>* p =
      reinterpret_cast<std::pair<v8::Persistent<v8::Value>*, int>*>(
          data.GetParameter());
  CHECK_EQ(1234, p->second);
  NumberOfWeakCalls++;
  p->first->Reset();
}

TEST_F(WeakMapsTest, Weakness) {
  v8_flags.incremental_marking = false;
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);
  IndirectHandle<JSWeakMap> weakmap = isolate->factory()->NewJSWeakMap();
  GlobalHandles* global_handles = isolate->global_handles();

  // Keep global reference to the key.
  IndirectHandle<Object> key;
  {
    HandleScope inner_scope(isolate);
    DirectHandle<Map> map = factory->NewContextfulMapForCurrentContext(
        JS_OBJECT_TYPE, JSObject::kHeaderSize);
    DirectHandle<JSObject> object = factory->NewJSObjectFromMap(map);
    key = global_handles->Create(*object);
  }
  CHECK(!global_handles->IsWeak(key.location()));

  // Put two chained entries into weak map.
  {
    HandleScope inner_scope(isolate);
    DirectHandle<Map> map = factory->NewContextfulMapForCurrentContext(
        JS_OBJECT_TYPE, JSObject::kHeaderSize);
    Handle<JSObject> object = factory->NewJSObjectFromMap(map);
    DirectHandle<Smi> smi(Smi::FromInt(23), isolate);
    int32_t hash = Object::GetOrCreateHash(*key, isolate).value();
    JSWeakCollection::Set(weakmap, key, object, hash);
    int32_t object_hash = Object::GetOrCreateHash(*object, isolate).value();
    JSWeakCollection::Set(weakmap, object, smi, object_hash);
  }
  // Put a symbol key into weak map.
  {
    HandleScope inner_scope(isolate);
    Handle<Symbol> symbol = factory->NewSymbol();
    DirectHandle<Smi> smi(Smi::FromInt(23), isolate);
    JSWeakCollection::Set(weakmap, symbol, smi, symbol->hash());
  }
  CHECK_EQ(3, Cast<EphemeronHashTable>(weakmap->table())->NumberOfElements());

  // Force a full GC.
  {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        isolate->heap());
    InvokeAtomicMajorGC();
  }
  CHECK_EQ(0, NumberOfWeakCalls);
  // Symbol key should be deleted.
  CHECK_EQ(2, Cast<EphemeronHashTable>(weakmap->table())->NumberOfElements());
  CHECK_EQ(
      1, Cast<EphemeronHashTable>(weakmap->table())->NumberOfDeletedElements());

  // Make the global reference to the key weak.
  std::pair<IndirectHandle<Object>*, int> handle_and_id(&key, 1234);
  GlobalHandles::MakeWeak(
      key.location(), reinterpret_cast<void*>(&handle_and_id),
      &WeakPointerCallback, v8::WeakCallbackType::kParameter);
  CHECK(global_handles->IsWeak(key.location()));

  {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        isolate->heap());
    InvokeAtomicMajorGC();
  }
  CHECK_EQ(1, NumberOfWeakCalls);
  CHECK_EQ(0, Cast<EphemeronHashTable>(weakmap->table())->NumberOfElements());
  CHECK_EQ(
      3, Cast<EphemeronHashTable>(weakmap->table())->NumberOfDeletedElements());
}

TEST_F(WeakMapsTest, Shrinking) {
  Isolate* isolate = i_isolate();
  Factory* factory = isolate->factory();
  DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      isolate->heap());
  HandleScope scope(isolate);
  DirectHandle<JSWeakMap> weakmap = isolate->factory()->NewJSWeakMap();

  // Check initial capacity.
  CHECK_EQ(32, Cast<EphemeronHashTable>(weakmap->table())->Capacity());

  // Fill up weak map to trigger capacity change.
  {
    HandleScope inner_scope(isolate);
    DirectHandle<Map> map = factory->NewContextfulMapForCurrentContext(
        JS_OBJECT_TYPE, JSObject::kHeaderSize);
    for (int i = 0; i < 32; i++) {
      Handle<JSObject> object = factory->NewJSObjectFromMap(map);
      DirectHandle<Smi> smi(Smi::FromInt(i), isolate);
      int32_t object_hash = Object::GetOrCreateHash(*object, isolate).value();
      JSWeakCollection::Set(weakmap, object, smi, object_hash);
    }
  }

  // Check increased capacity.
  CHECK_EQ(128, Cast<EphemeronHashTable>(weakmap->table())->Capacity());

  // Force a full GC.
  CHECK_EQ(32, Cast<EphemeronHashTable>(weakmap->table())->NumberOfElements());
  CHECK_EQ(
      0, Cast<EphemeronHashTable>(weakmap->table())->NumberOfDeletedElements());
  InvokeAtomicMajorGC();
  CHECK_EQ(0, Cast<EphemeronHashTable>(weakmap->table())->NumberOfElements());
  CHECK_EQ(
      32,
      Cast<EphemeronHashTable>(weakmap->table())->NumberOfDeletedElements());

  // Check shrunk capacity.
  CHECK_EQ(32, Cast<EphemeronHashTable>(weakmap->table())->Capacity());
}

namespace {
bool EphemeronHashTableContainsKey(Tagged<EphemeronHashTable> table,
                                   Tagged<HeapObject> key) {
  for (InternalIndex i : table->IterateEntries()) {
    if (table->KeyAt(i) == key) return true;
  }
  return false;
}
}  // namespace

TEST_F(WeakMapsTest, WeakMapPromotionMarkCompact) {
  Isolate* isolate = i_isolate();
  ManualGCScope manual_gc_scope(isolate);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);
  DirectHandle<JSWeakMap> weakmap = isolate->factory()->NewJSWeakMap();

  InvokeMajorGC();

  CHECK(!HeapLayout::InYoungGeneration(weakmap->table()));

  DirectHandle<Map> map = factory->NewContextfulMapForCurrentContext(
      JS_OBJECT_TYPE, JSObject::kHeaderSize);
  Handle<JSObject> object = factory->NewJSObjectFromMap(map);
  DirectHandle<Smi> smi(Smi::FromInt(1), isolate);
  int32_t object_hash = Object::GetOrCreateHash(*object, isolate).value();
  JSWeakCollection::Set(weakmap, object, smi, object_hash);

  CHECK(EphemeronHashTableContainsKey(
      Cast<EphemeronHashTable>(weakmap->table()), *object));
  InvokeMajorGC();

  CHECK(!HeapLayout::InYoungGeneration(*object));
  CHECK(!HeapLayout::InYoungGeneration(weakmap->table()));
  CHECK(EphemeronHashTableContainsKey(
      Cast<EphemeronHashTable>(weakmap->table()), *object));

  InvokeMajorGC();
  CHECK(!HeapLayout::InYoungGeneration(*object));
  CHECK(!HeapLayout::InYoungGeneration(weakmap->table()));
  CHECK(EphemeronHashTableContainsKey(
      Cast<EphemeronHashTable>(weakmap->table()), *object));
}

TEST_F(WeakMapsTest, WeakMapScavenge) {
  if (i::v8_flags.single_generation) return;
  if (i::v8_flags.stress_incremental_marking) return;
  Isolate* isolate = i_isolate();
  ManualGCScope manual_gc_scope(isolate);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);
  DirectHandle<JSWeakMap> weakmap = isolate->factory()->NewJSWeakMap();

  InvokeAtomicMinorGC();
  CHECK(HeapLayout::InYoungGeneration(weakmap->table()));

  DirectHandle<Map> map = factory->NewContextfulMapForCurrentContext(
      JS_OBJECT_TYPE, JSObject::kHeaderSize);
  Handle<JSObject> object = factory->NewJSObjectFromMap(map);
  DirectHandle<Smi> smi(Smi::FromInt(1), isolate);
  int32_t object_hash = Object::GetOrCreateHash(*object, isolate).value();
  JSWeakCollection::Set(weakmap, object, smi, object_hash);

  CHECK(EphemeronHashTableContainsKey(
      Cast<EphemeronHashTable>(weakmap->table()), *object));

  if (!v8_flags.minor_ms) {
    InvokeAtomicMinorGC();
    CHECK(HeapLayout::InYoungGeneration(*object));
    CHECK(!HeapLayout::InYoungGeneration(weakmap->table()));
    CHECK(EphemeronHashTableContainsKey(
        Cast<EphemeronHashTable>(weakmap->table()), *object));
  }

  InvokeAtomicMajorGC();
  CHECK(!HeapLayout::InYoungGeneration(*object));
  CHECK(!HeapLayout::InYoungGeneration(weakmap->table()));
  CHECK(EphemeronHashTableContainsKey(
      Cast<EphemeronHashTable>(weakmap->table()), *object));
}

// Test that weak map values on an evacuation candidate which are not reachable
// by other paths are correctly recorded in the slots buffer.
TEST_F(WeakMapsTest, Regress2060a) {
  if (!i::v8_flags.compact) return;
  v8_flags.compact_on_every_full_gc = true;
  v8_flags.stress_concurrent_allocation = false;  // For SimulateFullSpace.
  Isolate* isolate = i_isolate();
  ManualGCScope manual_gc_scope(isolate);
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();
  HandleScope scope(isolate);
  Handle<JSFunction> function =
      factory->NewFunctionForTesting(factory->function_string());
  Handle<JSObject> key = factory->NewJSObject(function);
  DirectHandle<JSWeakMap> weakmap = isolate->factory()->NewJSWeakMap();

  // Start second old-space page so that values land on evacuation candidate.
  PageMetadata* first_page = heap->old_space()->first_page();
  SimulateFullSpace(heap->old_space());

  // Fill up weak map with values on an evacuation candidate.
  {
    HandleScope inner_scope(isolate);
    for (int i = 0; i < 32; i++) {
      DirectHandle<JSObject> object =
          factory->NewJSObject(function, AllocationType::kOld);
      CHECK(!HeapLayout::InYoungGeneration(*object));
      CHECK(!first_page->Contains(object->address()));
      int32_t hash = Object::GetOrCreateHash(*key, isolate).value();
      JSWeakCollection::Set(weakmap, key, object, hash);
    }
  }

  // Force compacting garbage collection.
  CHECK(v8_flags.compact_on_every_full_gc);
  InvokeMajorGC();
}

// Test that weak map keys on an evacuation candidate which are reachable by
// other strong paths are correctly recorded in the slots buffer.
TEST_F(WeakMapsTest, Regress2060b) {
  if (!i::v8_flags.compact) return;
  v8_flags.compact_on_every_full_gc = true;
#ifdef VERIFY_HEAP
  v8_flags.verify_heap = true;
#endif
  v8_flags.stress_concurrent_allocation = false;  // For SimulateFullSpace.

  Isolate* isolate = i_isolate();
  ManualGCScope manual_gc_scope(isolate);
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();
  HandleScope scope(isolate);
  Handle<JSFunction> function =
      factory->NewFunctionForTesting(factory->function_string());

  // Start second old-space page so that keys land on evacuation candidate.
  PageMetadata* first_page = heap->old_space()->first_page();
  SimulateFullSpace(heap->old_space());

  // Fill up weak map with keys on an evacuation candidate.
  Handle<JSObject> keys[32];
  for (int i = 0; i < 32; i++) {
    keys[i] = factory->NewJSObject(function, AllocationType::kOld);
    CHECK(!HeapLayout::InYoungGeneration(*keys[i]));
    CHECK(!first_page->Contains(keys[i]->address()));
  }
  DirectHandle<JSWeakMap> weakmap = isolate->factory()->NewJSWeakMap();
  for (int i = 0; i < 32; i++) {
    DirectHandle<Smi> smi(Smi::FromInt(i), isolate);
    int32_t hash = Object::GetOrCreateHash(*keys[i], isolate).value();
    JSWeakCollection::Set(weakmap, keys[i], smi, hash);
  }

  // Force compacting garbage collection. The subsequent collections are used
  // to verify that key references were actually updated.
  CHECK(v8_flags.compact_on_every_full_gc);
  InvokeMajorGC();
  InvokeMajorGC();
  InvokeMajorGC();
}

TEST_F(WeakMapsTest, Regress399527) {
  if (!v8_flags.incremental_marking) return;
  v8::HandleScope scope(v8_isolate());
  Isolate* isolate = i_isolate();
  Heap* heap = isolate->heap();
  {
    HandleScope inner_scope(isolate);
    isolate->factory()->NewJSWeakMap();
    SimulateIncrementalMarking(heap);
  }
  // The weak map is marked black here but leaving the handle scope will make
  // the object unreachable. Aborting incremental marking will clear all the
  // marking bits which makes the weak map garbage.
  InvokeMajorGC();
}

TEST_F(WeakMapsTest, WeakMapsWithChainedEntries) {
  ManualGCScope manual_gc_scope(i_isolate());
  v8::Isolate* isolate = v8_isolate();
  DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      i_isolate()->heap());
  v8::HandleScope scope(isolate);

  const int initial_gc_count = i_isolate()->heap()->gc_count();
  DirectHandle<JSWeakMap> weakmap1 = i_isolate()->factory()->NewJSWeakMap();
  DirectHandle<JSWeakMap> weakmap2 = i_isolate()->factory()->NewJSWeakMap();
  v8::Global<v8::Object> g1;
  v8::Global<v8::Object> g2;
  {
    v8::HandleScope inner_scope(isolate);
    v8::Local<v8::Object> o1 = v8::Object::New(isolate);
    g1.Reset(isolate, o1);
    g1.SetWeak();
    v8::Local<v8::Object> o2 = v8::Object::New(isolate);
    g2.Reset(isolate, o2);
    g2.SetWeak();
    Handle<Object> i_o1 = v8::Utils::OpenHandle(*o1);
    Handle<Object> i_o2 = v8::Utils::OpenHandle(*o2);
    int32_t hash1 = Object::GetOrCreateHash(*i_o1, i_isolate()).value();
    int32_t hash2 = Object::GetOrCreateHash(*i_o2, i_isolate()).value();
    JSWeakCollection::Set(weakmap1, i_o1, i_o2, hash1);
    JSWeakCollection::Set(weakmap2, i_o2, i_o1, hash2);
  }
  InvokeMajorGC();
  CHECK(g1.IsEmpty());
  CHECK(g2.IsEmpty());
  CHECK_EQ(1, i_isolate()->heap()->gc_count() - initial_gc_count);
}

}  // namespace test_weakmaps
}  // namespace internal
}  // namespace v8

"""
```