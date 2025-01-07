Response:
Let's break down the thought process to analyze the C++ unit test file for `WeakMaps`.

1. **Identify the Core Subject:** The filename `weakmaps-unittest.cc` immediately tells us the tests are about the `WeakMap` data structure in V8.

2. **Understand the Context:** The path `v8/test/unittests/objects/` indicates this is a *unit test* for the `WeakMap` implementation located within the `objects` component of V8. Unit tests are designed to verify individual units of code in isolation.

3. **Scan for Key V8 Concepts:** Look for familiar V8 terms and patterns:
    * `Isolate`: Represents an isolated instance of the V8 JavaScript engine. Tests will often create and manipulate isolates.
    * `Factory`: Used to create V8 objects on the heap.
    * `HandleScope`: Manages the lifetime of `Handle` objects, preventing memory leaks.
    * `Handle<T>`: A smart pointer to a V8 object on the heap, automatically managing garbage collection.
    * `Weak<T>` (or similar, though not directly present here):  A weak reference that doesn't prevent garbage collection. The file uses global handles and makes them weak.
    * `JSWeakMap`: The C++ representation of the JavaScript `WeakMap`.
    * `EphemeronHashTable`: The underlying hash table implementation used by `WeakMap`. The term "ephemeron" is a big hint about its weak nature.
    * `Smi`:  Small integer representation in V8.
    * `JSObject`:  A generic JavaScript object.
    * `Symbol`:  JavaScript symbol type.
    * `GlobalHandles`: A way to keep objects alive across garbage collections. The test explicitly makes some global handles *weak*.
    * `InvokeAtomicMajorGC()`, `InvokeAtomicMinorGC()`:  Functions to trigger garbage collection.
    * `ManualGCScope`:  Allows explicit control over garbage collection for testing.
    * `DisableConservativeStackScanningScopeForTesting`:  A testing utility related to garbage collection.
    * `PageMetadata`: Information about memory pages in V8's heap.
    * `HeapLayout`:  Functions to inspect the memory location of objects.
    * `AllocationType::kOld`:  Specifies that an object should be allocated in old generation space.

4. **Analyze Individual Tests (using a mental loop or by reading sequentially):**  For each `TEST_F` function:
    * **Test Name:**  The name (e.g., `Weakness`, `Shrinking`, `WeakMapPromotionMarkCompact`) provides a strong indication of the test's purpose.
    * **Setup:**  Look for the creation of `Isolate`, `Factory`, `HandleScope`, and the `JSWeakMap` itself. Identify any key objects being created (keys, values).
    * **Actions:** What operations are being performed on the `WeakMap` (e.g., `JSWeakCollection::Set`)? Are objects being created and then potentially becoming garbage?
    * **Assertions (`CHECK_EQ`, `CHECK`)**: These are the core of the test. What conditions are being verified after the actions?  This tells you what the test is *asserting* about the behavior of `WeakMap`.
    * **Garbage Collection:** Notice when `InvokeAtomicMajorGC()` or `InvokeAtomicMinorGC()` is called. This is crucial for testing the weak nature of `WeakMap`. Pay attention to the `DisableConservativeStackScanningScopeForTesting`.

5. **Connect C++ Concepts to JavaScript (if applicable):**  The core function of a `WeakMap` is the same in both C++ and JavaScript. Think about the JavaScript equivalents of the C++ operations. For instance:
    * `JSWeakCollection::Set(weakmap, key, value, hash)` roughly corresponds to `weakMap.set(key, value)`.
    * The "weakness" aspect relates to how garbage collection behaves when keys are no longer strongly referenced.

6. **Infer Functionality from Test Cases:**  Based on the tests, deduce the functionalities being tested:
    * **Weakness:**  Verifying that entries are removed when the key is only weakly referenced.
    * **Shrinking:** Checking if the underlying hash table resizes appropriately, including shrinking after garbage collection.
    * **Garbage Collection Interaction:** Tests for how `WeakMap` entries are handled during different types of garbage collection (major, minor, mark-compact, scavenge).
    * **Object Promotion:** How objects used as keys or values in weak maps are promoted to old generation during garbage collection.
    * **Specific Bug Fixes (e.g., `Regress2060a`, `Regress2060b`, `Regress399527`):**  These tests target specific scenarios or bugs that were previously found and fixed. The names often give clues about the issue.
    * **Chained Entries:** Testing how multiple entries with potential dependencies between keys and values are handled during garbage collection.

7. **Identify Potential User Errors:**  Consider how the *lack* of understanding about weak references could lead to programming errors in JavaScript. Think about scenarios where developers might expect a `WeakMap` entry to persist even when the key is no longer reachable through normal means.

8. **Check for Torque:** The prompt asks about `.tq` files. A quick scan of the filename reveals it ends in `.cc`, so it's C++, not Torque.

9. **Structure the Answer:** Organize the findings into clear categories:
    * Overall functionality
    * Relationship to JavaScript
    * Code logic/assumptions (using specific tests as examples)
    * Common programming errors

10. **Refine and Elaborate:** Review the generated answer and add more detail or clarity where needed. For instance, explicitly link the C++ `JSWeakCollection::Set` to the JavaScript `weakMap.set()`. Explain the concept of "ephemeron" in the context of weak maps.

By following this structured approach, combining code analysis with knowledge of V8 concepts and JavaScript `WeakMap` behavior, we can effectively understand the purpose and functionality of the given unit test file.
`v8/test/unittests/objects/weakmaps-unittest.cc` 是一个 V8 源代码文件，它包含了针对 V8 引擎中 `WeakMap` 对象实现的单元测试。

**功能列举:**

这个文件主要用于测试 `WeakMap` 对象的以下功能和特性：

1. **弱引用 (Weakness):**  测试 `WeakMap` 的关键特性，即当 `WeakMap` 的键（key）不再被其他强引用持有的时候，垃圾回收器能够回收该键，并且 `WeakMap` 中对应的条目也会被移除。 这通过创建弱全局句柄并观察垃圾回收后的 `WeakMap` 状态来实现。

2. **大小调整 (Shrinking):** 测试 `WeakMap` 内部的哈希表在元素被垃圾回收后是否能够缩小容量，以优化内存使用。

3. **垃圾回收 (Garbage Collection):**  详细测试 `WeakMap` 在不同类型的垃圾回收（主垃圾回收 Mark-Compact 和次垃圾回收 Scavenge）过程中的行为，包括：
    * **晋升 (Promotion):** 测试在主垃圾回收过程中，作为 `WeakMap` 键或值的对象是否会被正确晋升到老生代。
    * **记录槽缓冲区 (Slots Buffer):** 测试在紧凑型垃圾回收中，当 `WeakMap` 的键或值位于疏散候选页时，是否会被正确记录。
    * **增量标记 (Incremental Marking):** 测试在增量标记垃圾回收过程中，`WeakMap` 的状态和行为是否正确。

4. **链式条目 (Chained Entries):** 测试 `WeakMap` 中存在多个键发生哈希冲突时的行为，确保垃圾回收能够正确处理这些链式条目。

5. **回调函数 (Weak Callbacks):** 测试与弱句柄关联的回调函数在对象被垃圾回收后是否会被正确调用。

**关于文件类型和 Torque:**

`v8/test/unittests/objects/weakmaps-unittest.cc` 的后缀是 `.cc`，这表明它是一个 **C++ 源代码文件**。根据你的描述，如果文件以 `.tq` 结尾，那它才是一个 V8 Torque 源代码文件。因此，这个文件不是 Torque 代码。

**与 JavaScript 功能的关系及示例:**

`WeakMap` 是 JavaScript 中的一个内置对象，用于存储键值对，其中键是弱引用的。这意味着如果键不再被其他地方引用，垃圾回收器可以回收该键所占用的内存，即使该键仍然存在于 `WeakMap` 中。

**JavaScript 示例:**

```javascript
let key1 = {};
let key2 = {};
let weakMap = new WeakMap();

weakMap.set(key1, 'value1');
weakMap.set(key2, 'value2');

console.log(weakMap.has(key1)); // 输出: true

key1 = null; // 解除对 key1 的强引用

// 在某个时刻，垃圾回收器运行后...
console.log(weakMap.has(key1)); // 输出: false (可能，取决于垃圾回收器的执行)
console.log(weakMap.has(key2)); // 输出: true
```

**代码逻辑推理 (假设输入与输出):**

以 `TEST_F(WeakMapsTest, Weakness)` 为例：

**假设输入:**

1. 创建一个 `JSWeakMap` 对象。
2. 创建一个 JavaScript 对象作为键（通过全局句柄 `key` 保持强引用）。
3. 将该键和一个值关联存入 `WeakMap`。
4. 创建一个符号 (Symbol) 作为键存入 `WeakMap`。
5. 手动触发一次完整的垃圾回收。
6. 将全局句柄 `key` 设置为弱引用，并关联一个回调函数。
7. 再次手动触发完整的垃圾回收。

**预期输出:**

1. 第一次垃圾回收后，符号键因为没有其他强引用，应该被回收，`WeakMap` 的元素数量会减少。
2. 第二次垃圾回收后，之前作为键的 JavaScript 对象因为全局句柄变成了弱引用，也会被回收。
3. 与该弱引用关联的回调函数 `WeakPointerCallback` 应该被调用一次。
4. 最终 `WeakMap` 中没有任何元素。

**用户常见的编程错误及示例:**

1. **误解弱引用:**  开发者可能会错误地认为只要对象存在于 `WeakMap` 中，它就不会被垃圾回收。

   ```javascript
   let weakMap = new WeakMap();
   weakMap.set({}, 'some value'); // 匿名对象作为键

   // ... 在代码的某个地方，没有其他地方引用这个匿名对象

   // 开发者可能期望 weakMap 仍然有这个条目，但实际上该匿名对象很可能已被回收。
   console.log(weakMap.size); // 输出: 0
   ```

2. **在需要强引用的场景使用 WeakMap:**  `WeakMap` 适用于管理与对象生命周期相关的元数据，但不适合作为主要的存储机制，因为其中的条目可能会在不知不觉中消失。

   ```javascript
   // 错误用法：尝试用 WeakMap 存储需要持久存在的数据
   let cache = new WeakMap();
   function getValue(obj) {
       if (cache.has(obj)) {
           return cache.get(obj);
       }
       let value = expensiveOperation(obj);
       cache.set(obj, value);
       return value;
   }

   let myObject = {};
   let result1 = getValue(myObject); // 缓存
   myObject = null; // 解除对 myObject 的引用

   // 下次调用 getValue 时，即使逻辑上应该从缓存中获取，
   // 但由于 myObject 可能已被回收，缓存可能失效。
   let result2 = getValue(someOtherReferenceToTheSameObject); // 可能会重新计算
   ```

总而言之，`v8/test/unittests/objects/weakmaps-unittest.cc` 通过一系列精心设计的测试用例，确保 V8 引擎中的 `WeakMap` 实现符合预期，能够正确处理弱引用、垃圾回收以及内部数据结构的调整。理解这些测试用例有助于深入理解 `WeakMap` 的工作原理。

Prompt: 
```
这是目录为v8/test/unittests/objects/weakmaps-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/objects/weakmaps-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

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