Response: Let's break down the thought process to analyze the C++ code and relate it to JavaScript.

1. **Understanding the Core Goal:** The file name `test-compaction.cc` and the namespace `heap` immediately suggest this code is about testing the memory compaction process within V8's heap. The presence of "aborted" in the test names hints at scenarios where compaction fails or is interrupted.

2. **Dissecting the Includes:**  The included headers provide valuable context:
    * `src/execution/isolate.h`:  Deals with isolates (independent V8 instances).
    * `src/heap/*`:  A strong indication that the focus is on heap management, including mark-compact garbage collection, page metadata, remembered sets, etc.
    * `src/objects/objects-inl.h`:  Concerns V8's object representation in memory.
    * `test/cctest/*`: Indicates this is a C++ unit test.

3. **Analyzing Helper Functions:** The initial helper functions `CheckInvariantsOfAbortedPage` and `CheckAllObjectsOnPage` offer clues about the testing strategy:
    * `CheckInvariantsOfAbortedPage`: Verifies that after an aborted compaction, the page is in a consistent state (mark bits cleared, not marked for evacuation or as aborted).
    * `CheckAllObjectsOnPage`: Confirms that a set of objects resides on the same memory page.

4. **Examining the Test Cases (HEAP_TEST macros):**  This is where the core functionality lies. Each `HEAP_TEST` represents a distinct test scenario:
    * `CompactionFullAbortedPage`: Tests the scenario where an entire page fails to compact due to out-of-memory (OOM).
    * `CompactionPartiallyAbortedPage`: Tests when compaction starts on a page, some objects migrate, but then OOM occurs, leaving a partially compacted page.
    * `CompactionPartiallyAbortedPageIntraAbortedPointers`:  Similar to the above, but specifically checks how pointers *within* the aborted page are handled.
    * `CompactionPartiallyAbortedPageWithRememberedSetEntries`:  A more complex scenario involving remembered sets, which track cross-page references. This test ensures that these sets are correctly updated after an aborted compaction, especially when dealing with pointers to the young generation.

5. **Identifying Key Techniques within the Tests:**
    * **Manual GC Control:**  The use of `ManualGCScope` and `ManualEvacuationCandidatesSelectionScope` reveals the tests are controlling garbage collection behavior to set up specific scenarios.
    * **Forced OOM:** The `heap->set_force_oom(true)` line is crucial. It simulates memory exhaustion to trigger the aborted compaction paths.
    * **Page Manipulation:**  Code like `to_be_aborted_page->Chunk()->SetFlagNonExecutable(...)` shows direct manipulation of page metadata to influence compaction.
    * **Object Creation and Linking:** The tests create arrays and link them together to simulate realistic object relationships and test pointer updates.
    * **Assertions (CHECK macros):** The `CHECK` macros are used to verify expected conditions after the GC runs, confirming the correctness of the compaction and abort handling.

6. **Connecting to JavaScript:**  This is where the abstraction comes in. The C++ code is *implementing* the underlying memory management that JavaScript relies on. The connection points are:
    * **Garbage Collection:**  JavaScript's automatic memory management is implemented by V8's garbage collector. Compaction is a part of the full GC process. So, when a JavaScript developer writes code that creates and discards objects, they are indirectly causing this C++ compaction code to run.
    * **Heap:** The "heap" in the C++ code is the same heap where JavaScript objects reside.
    * **Out-of-Memory Errors:** The OOM scenarios tested in C++ directly relate to the `OutOfMemoryError` that a JavaScript program can encounter.
    * **Object References:** The C++ tests manipulating pointers between objects are analogous to how JavaScript objects hold references to each other.

7. **Crafting the JavaScript Example:** The goal is to demonstrate a JavaScript scenario that *could* lead to the kind of memory layout and compaction issues being tested in the C++ code. The example should focus on:
    * **Creating many objects:**  To fill up the heap and potentially trigger compaction.
    * **References between objects:** To mirror the linked list structure in the C++ tests.
    * **Potential for fragmentation:** While not directly tested in the provided C++, compaction is often triggered to reduce fragmentation.

8. **Review and Refinement:** Ensure the JavaScript example is clear, concise, and illustrates the connection to the C++ concepts. Explain the link between the C++ test scenarios and the potential JavaScript outcomes (e.g., OOM errors, performance issues due to fragmentation if compaction wasn't working correctly).

By following this breakdown, we can understand the C++ code's purpose, the specific scenarios it tests, and how those scenarios relate to the high-level behavior of JavaScript's memory management. The key is to bridge the gap between the low-level implementation (C++) and the user-facing behavior (JavaScript).
这个 C++ 代码文件 `test-compaction.cc` 是 V8 JavaScript 引擎的测试代码，专门用于测试 **堆压缩 (Heap Compaction)** 功能的各种场景，特别是当堆压缩由于内存不足 (Out Of Memory - OOM) 而 **部分或完全中止** 时的情况。

**功能归纳：**

1. **测试堆压缩的核心逻辑：** 该文件通过模拟不同的堆状态和内存压力，来验证 V8 堆压缩算法在正常和异常情况下的正确性。
2. **测试压缩中止的处理：** 重点测试了当堆压缩过程中遇到 OOM 错误时，V8 如何安全地中止压缩过程，并保持堆的完整性和一致性。这包括：
    * **完全中止的页面：** 测试当整个页面上的对象都无法迁移时，如何处理。
    * **部分中止的页面：** 测试当页面上的部分对象已经迁移，部分尚未迁移时，如何处理，以及如何更新对象之间的引用关系。
    * **处理中止页面的内部指针：**  测试中止页面内部对象之间的指针是否正确更新。
    * **处理中止页面的Remembered Set条目：** 测试当中止页面包含指向新生代的指针时，Remembered Set 是否被正确清理和重建，避免因错误的指针导致后续的垃圾回收崩溃。
3. **依赖底层的堆管理机制：** 测试代码直接操作 V8 的堆管理 API，例如创建对象、标记页面为待迁移、触发垃圾回收等，以精确控制测试场景。
4. **使用 C++ 测试框架：**  该文件使用了 V8 自带的 `cctest` 测试框架来组织和运行测试用例。

**与 JavaScript 的关系及 JavaScript 示例：**

虽然这段 C++ 代码是 V8 引擎的底层实现，与 JavaScript 代码没有直接的语法对应关系，但它直接影响着 JavaScript 程序的运行性能和稳定性。  堆压缩是 JavaScript 垃圾回收 (Garbage Collection - GC) 的一个重要环节。当 JavaScript 程序运行时，会不断创建和销毁对象，导致内存中出现碎片。堆压缩的目标是将存活的对象移动到一起，整理内存，从而减少碎片，提高内存利用率，并为新的对象分配腾出更大的连续空间。

该测试文件关注的是堆压缩失败的情况。在 JavaScript 中，如果堆压缩失败，可能会导致以下几种情况：

1. **`OutOfMemoryError` 异常：** 如果堆压缩无法有效整理内存，当 JavaScript 尝试分配新的大对象时，可能会因为找不到足够的连续空间而抛出 `OutOfMemoryError` 异常。

2. **性能下降：**  如果堆内存碎片化严重，即使总的可用内存足够，分配新对象的速度也会变慢，因为需要查找合适的空闲块。此外，频繁的 GC 和压缩也会占用 CPU 资源，影响 JavaScript 代码的执行速度。

**JavaScript 示例（模拟可能导致堆压缩失败的场景）：**

以下 JavaScript 代码模拟了创建大量对象，并保持它们之间的引用，这可能会导致堆内存碎片化，并触发堆压缩。如果内存不足，堆压缩可能会部分或完全失败。

```javascript
let largeObjects = [];

function createAndLinkObjects(count) {
  let previousObject = null;
  for (let i = 0; i < count; i++) {
    let obj = { data: new Array(1000).fill(i) }; // 创建一个相对较大的对象
    if (previousObject) {
      previousObject.next = obj; // 建立对象之间的引用链
    }
    largeObjects.push(obj);
    previousObject = obj;
  }
}

// 创建大量的互相引用的对象
createAndLinkObjects(10000);

// 保持对这些对象的引用，防止它们被立即回收
console.log(largeObjects.length);

// 尝试分配一个更大的对象，这可能会触发 GC 和堆压缩
let veryLargeObject = new Array(1000000).fill(0);

console.log("Done");
```

**解释：**

* **`createAndLinkObjects` 函数:** 创建指定数量的对象，每个对象包含一个较大的数组，并通过 `next` 属性将它们链接起来。这种链接方式会使得垃圾回收器难以回收这些对象，从而可能导致堆内存碎片化。
* **`largeObjects` 数组:**  保存了对所有创建的对象的引用，防止它们被过早回收。
* **`veryLargeObject`:**  尝试分配一个非常大的数组。当 JavaScript 引擎尝试分配这个大对象时，可能会触发垃圾回收，并尝试进行堆压缩来整理内存。

**与 C++ 测试的联系：**

C++ 测试代码中模拟的 OOM 场景，就像在这个 JavaScript 例子中，当尝试分配 `veryLargeObject` 时，如果之前的对象分配导致内存碎片化严重，且剩余内存不足以分配 `veryLargeObject`，那么 V8 的堆压缩机制会被触发。如果此时内存极度紧张，压缩过程就可能遇到 C++ 测试代码中模拟的“部分中止”或“完全中止”的情况。

**总结：**

`test-compaction.cc` 这个 C++ 文件是 V8 引擎中用于测试堆压缩功能的关键代码。它通过模拟各种内存压力和状态，特别是堆压缩失败的情况，来保证 V8 引擎在内存管理上的健壮性和可靠性。虽然 JavaScript 开发者不会直接编写这样的 C++ 代码，但这个测试所验证的底层机制直接影响着 JavaScript 程序的性能、稳定性和对内存的利用效率。了解这些底层机制有助于更好地理解 JavaScript 的内存管理行为，并在编写代码时避免可能导致内存问题的模式。

Prompt: 
```
这是目录为v8/test/cctest/heap/test-compaction.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/execution/isolate.h"
#include "src/heap/factory.h"
#include "src/heap/heap-inl.h"
#include "src/heap/mark-compact.h"
#include "src/heap/marking-state-inl.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/heap/remembered-set-inl.h"
#include "src/objects/objects-inl.h"
#include "test/cctest/cctest.h"
#include "test/cctest/heap/heap-tester.h"
#include "test/cctest/heap/heap-utils.h"

namespace v8 {
namespace internal {
namespace heap {

namespace {

void CheckInvariantsOfAbortedPage(PageMetadata* page) {
  // Check invariants:
  // 1) Markbits are cleared
  // 2) The page is not marked as evacuation candidate anymore
  // 3) The page is not marked as aborted compaction anymore.
  CHECK(page->marking_bitmap()->IsClean());
  CHECK(!page->Chunk()->IsEvacuationCandidate());
  CHECK(!page->Chunk()->IsFlagSet(MemoryChunk::COMPACTION_WAS_ABORTED));
}

void CheckAllObjectsOnPage(const DirectHandleVector<FixedArray>& handles,
                           PageMetadata* page) {
  for (DirectHandle<FixedArray> fixed_array : handles) {
    CHECK(PageMetadata::FromHeapObject(*fixed_array) == page);
  }
}

}  // namespace

HEAP_TEST(CompactionFullAbortedPage) {
  if (!v8_flags.compact) return;
  // Test the scenario where we reach OOM during compaction and the whole page
  // is aborted.

  // Disable concurrent sweeping to ensure memory is in an expected state, i.e.,
  // we can reach the state of a half aborted page.
  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  auto reset_oom = [](void* heap, size_t limit, size_t) -> size_t {
    reinterpret_cast<Heap*>(heap)->set_force_oom(false);
    return limit;
  };
  heap->AddNearHeapLimitCallback(reset_oom, heap);
  {
    HandleScope scope1(isolate);

    heap::SealCurrentObjects(heap);

    {
      HandleScope scope2(isolate);
      CHECK(heap->old_space()->TryExpand(heap->main_thread_local_heap(),
                                         AllocationOrigin::kRuntime));
      DirectHandleVector<FixedArray> compaction_page_handles(isolate);
      heap::CreatePadding(
          heap,
          static_cast<int>(MemoryChunkLayout::AllocatableMemoryInDataPage()),
          AllocationType::kOld, &compaction_page_handles);
      PageMetadata* to_be_aborted_page =
          PageMetadata::FromHeapObject(*compaction_page_handles.front());
      to_be_aborted_page->Chunk()->SetFlagNonExecutable(
          MemoryChunk::FORCE_EVACUATION_CANDIDATE_FOR_TESTING);
      CheckAllObjectsOnPage(compaction_page_handles, to_be_aborted_page);

      heap->set_force_oom(true);
      heap::InvokeMajorGC(heap);
      heap->EnsureSweepingCompleted(
          Heap::SweepingForcedFinalizationMode::kV8Only);

      // Check that all handles still point to the same page, i.e., compaction
      // has been aborted on the page.
      for (DirectHandle<FixedArray> object : compaction_page_handles) {
        CHECK_EQ(to_be_aborted_page, PageMetadata::FromHeapObject(*object));
      }
      CheckInvariantsOfAbortedPage(to_be_aborted_page);
    }
  }
  heap->RemoveNearHeapLimitCallback(reset_oom, 0u);
}

namespace {

int GetObjectSize(int objects_per_page) {
  int allocatable =
      static_cast<int>(MemoryChunkLayout::AllocatableMemoryInDataPage());
  // Make sure that object_size is a multiple of kTaggedSize.
  int object_size =
      ((allocatable / kTaggedSize) / objects_per_page) * kTaggedSize;
  return std::min(kMaxRegularHeapObjectSize, object_size);
}

}  // namespace

HEAP_TEST(CompactionPartiallyAbortedPage) {
  if (!v8_flags.compact) return;
  // Test the scenario where we reach OOM during compaction and parts of the
  // page have already been migrated to a new one.

  // Disable concurrent sweeping to ensure memory is in an expected state, i.e.,
  // we can reach the state of a half aborted page.
  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);

  const int objects_per_page = 10;
  const int object_size = GetObjectSize(objects_per_page);

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  auto reset_oom = [](void* heap, size_t limit, size_t) -> size_t {
    reinterpret_cast<Heap*>(heap)->set_force_oom(false);
    return limit;
  };
  heap->AddNearHeapLimitCallback(reset_oom, heap);
  {
    HandleScope scope1(isolate);

    heap::SealCurrentObjects(heap);

    {
      HandleScope scope2(isolate);
      // Fill another page with objects of size {object_size} (last one is
      // properly adjusted).
      CHECK(heap->old_space()->TryExpand(heap->main_thread_local_heap(),
                                         AllocationOrigin::kRuntime));
      DirectHandleVector<FixedArray> compaction_page_handles(isolate);
      heap::CreatePadding(
          heap,
          static_cast<int>(MemoryChunkLayout::AllocatableMemoryInDataPage()),
          AllocationType::kOld, &compaction_page_handles, object_size);
      PageMetadata* to_be_aborted_page =
          PageMetadata::FromHeapObject(*compaction_page_handles.front());
      to_be_aborted_page->Chunk()->SetFlagNonExecutable(
          MemoryChunk::FORCE_EVACUATION_CANDIDATE_FOR_TESTING);
      CheckAllObjectsOnPage(compaction_page_handles, to_be_aborted_page);

      {
        // Add another page that is filled with {num_objects} objects of size
        // {object_size}.
        HandleScope scope3(isolate);
        CHECK(heap->old_space()->TryExpand(heap->main_thread_local_heap(),
                                           AllocationOrigin::kRuntime));
        const int num_objects = 3;
        DirectHandleVector<FixedArray> page_to_fill_handles(isolate);
        heap::CreatePadding(heap, object_size * num_objects,
                            AllocationType::kOld, &page_to_fill_handles,
                            object_size);
        PageMetadata* page_to_fill =
            PageMetadata::FromAddress(page_to_fill_handles.front()->address());

        heap->set_force_oom(true);
        heap::InvokeMajorGC(heap);
        heap->EnsureSweepingCompleted(
            Heap::SweepingForcedFinalizationMode::kV8Only);

        bool migration_aborted = false;
        for (DirectHandle<FixedArray> object : compaction_page_handles) {
          // Once compaction has been aborted, all following objects still have
          // to be on the initial page.
          CHECK(!migration_aborted ||
                (PageMetadata::FromHeapObject(*object) == to_be_aborted_page));
          if (PageMetadata::FromHeapObject(*object) == to_be_aborted_page) {
            // This object has not been migrated.
            migration_aborted = true;
          } else {
            CHECK_EQ(PageMetadata::FromHeapObject(*object), page_to_fill);
          }
        }
        // Check that we actually created a scenario with a partially aborted
        // page.
        CHECK(migration_aborted);
        CheckInvariantsOfAbortedPage(to_be_aborted_page);
      }
    }
  }
  heap->RemoveNearHeapLimitCallback(reset_oom, 0u);
}

HEAP_TEST(CompactionPartiallyAbortedPageIntraAbortedPointers) {
  if (!v8_flags.compact) return;
  // Test the scenario where we reach OOM during compaction and parts of the
  // page have already been migrated to a new one. Objects on the aborted page
  // are linked together. This test makes sure that intra-aborted page pointers
  // get properly updated.

  // Disable concurrent sweeping to ensure memory is in an expected state, i.e.,
  // we can reach the state of a half aborted page.
  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);

  const int objects_per_page = 10;
  const int object_size = GetObjectSize(objects_per_page);

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  auto reset_oom = [](void* heap, size_t limit, size_t) -> size_t {
    reinterpret_cast<Heap*>(heap)->set_force_oom(false);
    return limit;
  };
  heap->AddNearHeapLimitCallback(reset_oom, heap);
  {
    HandleScope scope1(isolate);
    IndirectHandle<FixedArray> root_array =
        isolate->factory()->NewFixedArray(10, AllocationType::kOld);

    heap::SealCurrentObjects(heap);

    PageMetadata* to_be_aborted_page = nullptr;
    {
      HandleScope temporary_scope(isolate);
      // Fill a fresh page with objects of size {object_size} (last one is
      // properly adjusted).
      CHECK(heap->old_space()->TryExpand(heap->main_thread_local_heap(),
                                         AllocationOrigin::kRuntime));
      DirectHandleVector<FixedArray> compaction_page_handles(isolate);
      heap::CreatePadding(
          heap,
          static_cast<int>(MemoryChunkLayout::AllocatableMemoryInDataPage()),
          AllocationType::kOld, &compaction_page_handles, object_size);
      to_be_aborted_page =
          PageMetadata::FromHeapObject(*compaction_page_handles.front());
      to_be_aborted_page->Chunk()->SetFlagNonExecutable(
          MemoryChunk::FORCE_EVACUATION_CANDIDATE_FOR_TESTING);
      for (size_t i = compaction_page_handles.size() - 1; i > 0; i--) {
        compaction_page_handles[i]->set(0, *compaction_page_handles[i - 1]);
      }
      root_array->set(0, *compaction_page_handles.back());
      CheckAllObjectsOnPage(compaction_page_handles, to_be_aborted_page);
    }
    {
      // Add another page that is filled with {num_objects} objects of size
      // {object_size}.
      HandleScope scope3(isolate);
      CHECK(heap->old_space()->TryExpand(heap->main_thread_local_heap(),
                                         AllocationOrigin::kRuntime));
      const int num_objects = 2;
      int used_memory = object_size * num_objects;
      DirectHandleVector<FixedArray> page_to_fill_handles(isolate);
      heap::CreatePadding(heap, used_memory, AllocationType::kOld,
                          &page_to_fill_handles, object_size);
      PageMetadata* page_to_fill =
          PageMetadata::FromHeapObject(*page_to_fill_handles.front());

      // We need to invoke GC without stack, otherwise no compaction is
      // performed.
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);

      heap->set_force_oom(true);
      heap::InvokeMajorGC(heap);
      heap->EnsureSweepingCompleted(
          Heap::SweepingForcedFinalizationMode::kV8Only);

      // The following check makes sure that we compacted "some" objects, while
      // leaving others in place.
      bool in_place = true;
      IndirectHandle<FixedArray> current = root_array;
      while (current->get(0) != ReadOnlyRoots(heap).undefined_value()) {
        current = IndirectHandle<FixedArray>(Cast<FixedArray>(current->get(0)),
                                             isolate);
        CHECK(IsFixedArray(*current));
        if (PageMetadata::FromHeapObject(*current) != to_be_aborted_page) {
          in_place = false;
        }
        bool on_aborted_page =
            PageMetadata::FromHeapObject(*current) == to_be_aborted_page;
        bool on_fill_page =
            PageMetadata::FromHeapObject(*current) == page_to_fill;
        CHECK((in_place && on_aborted_page) || (!in_place && on_fill_page));
      }
      // Check that we at least migrated one object, as otherwise the test would
      // not trigger.
      CHECK(!in_place);
      CheckInvariantsOfAbortedPage(to_be_aborted_page);
    }
  }
  heap->RemoveNearHeapLimitCallback(reset_oom, 0u);
}

HEAP_TEST(CompactionPartiallyAbortedPageWithRememberedSetEntries) {
  if (!v8_flags.compact || v8_flags.single_generation) return;
  // Test the scenario where we reach OOM during compaction and parts of the
  // page have already been migrated to a new one. Objects on the aborted page
  // are linked together and the very first object on the aborted page points
  // into new space. The test verifies that the remembered set entries are
  // properly cleared and rebuilt after aborting a page. Failing to do so can
  // result in other objects being allocated in the free space where their
  // payload looks like a valid new space pointer.

  // Disable concurrent sweeping to ensure memory is in an expected state, i.e.,
  // we can reach the state of a half aborted page.
  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);

  const int objects_per_page = 10;
  const int object_size = GetObjectSize(objects_per_page);

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  auto reset_oom = [](void* heap, size_t limit, size_t) -> size_t {
    reinterpret_cast<Heap*>(heap)->set_force_oom(false);
    return limit;
  };
  heap->AddNearHeapLimitCallback(reset_oom, heap);
  {
    HandleScope scope1(isolate);
    IndirectHandle<FixedArray> root_array =
        isolate->factory()->NewFixedArray(10, AllocationType::kOld);
    heap::SealCurrentObjects(heap);

    PageMetadata* to_be_aborted_page = nullptr;
    {
      HandleScope temporary_scope(isolate);
      // Fill another page with objects of size {object_size} (last one is
      // properly adjusted).
      CHECK(heap->old_space()->TryExpand(heap->main_thread_local_heap(),
                                         AllocationOrigin::kRuntime));
      DirectHandleVector<FixedArray> compaction_page_handles(isolate);
      heap::CreatePadding(
          heap,
          static_cast<int>(MemoryChunkLayout::AllocatableMemoryInDataPage()),
          AllocationType::kOld, &compaction_page_handles, object_size);
      // Sanity check that we have enough space for linking up arrays.
      CHECK_GE(compaction_page_handles.front()->length(), 2);
      to_be_aborted_page =
          PageMetadata::FromHeapObject(*compaction_page_handles.front());
      to_be_aborted_page->Chunk()->SetFlagNonExecutable(
          MemoryChunk::FORCE_EVACUATION_CANDIDATE_FOR_TESTING);

      for (size_t i = compaction_page_handles.size() - 1; i > 0; i--) {
        compaction_page_handles[i]->set(0, *compaction_page_handles[i - 1]);
      }
      root_array->set(0, *compaction_page_handles.back());
      DirectHandle<FixedArray> new_space_array =
          isolate->factory()->NewFixedArray(1, AllocationType::kYoung);
      CHECK(HeapLayout::InYoungGeneration(*new_space_array));
      compaction_page_handles.front()->set(1, *new_space_array);
      CheckAllObjectsOnPage(compaction_page_handles, to_be_aborted_page);
    }

    {
      // Add another page that is filled with {num_objects} objects of size
      // {object_size}.
      HandleScope scope3(isolate);
      CHECK(heap->old_space()->TryExpand(heap->main_thread_local_heap(),
                                         AllocationOrigin::kRuntime));
      const int num_objects = 2;
      int used_memory = object_size * num_objects;
      DirectHandleVector<FixedArray> page_to_fill_handles(isolate);
      heap::CreatePadding(heap, used_memory, AllocationType::kOld,
                          &page_to_fill_handles, object_size);
      PageMetadata* page_to_fill =
          PageMetadata::FromHeapObject(*page_to_fill_handles.front());

      // We need to invoke GC without stack, otherwise no compaction is
      // performed.
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);

      heap->set_force_oom(true);
      heap::InvokeMajorGC(heap);
      heap->EnsureSweepingCompleted(
          Heap::SweepingForcedFinalizationMode::kV8Only);

      // The following check makes sure that we compacted "some" objects, while
      // leaving others in place.
      bool in_place = true;
      IndirectHandle<FixedArray> current = root_array;
      while (current->get(0) != ReadOnlyRoots(heap).undefined_value()) {
        current = IndirectHandle<FixedArray>(Cast<FixedArray>(current->get(0)),
                                             isolate);
        CHECK(!HeapLayout::InYoungGeneration(*current));
        CHECK(IsFixedArray(*current));
        if (PageMetadata::FromHeapObject(*current) != to_be_aborted_page) {
          in_place = false;
        }
        bool on_aborted_page =
            PageMetadata::FromHeapObject(*current) == to_be_aborted_page;
        bool on_fill_page =
            PageMetadata::FromHeapObject(*current) == page_to_fill;
        CHECK((in_place && on_aborted_page) || (!in_place && on_fill_page));
      }
      // Check that we at least migrated one object, as otherwise the test would
      // not trigger.
      CHECK(!in_place);
      CheckInvariantsOfAbortedPage(to_be_aborted_page);

      // Allocate a new object in new space.
      IndirectHandle<FixedArray> holder =
          isolate->factory()->NewFixedArray(10, AllocationType::kYoung);
      // Create a broken address that looks like a tagged pointer to a new space
      // object.
      Address broken_address = holder->address() + 2 * kTaggedSize + 1;
      // Convert it to a vector to create a string from it.
      base::Vector<const uint8_t> string_to_broken_address(
          reinterpret_cast<const uint8_t*>(&broken_address), kTaggedSize);

      IndirectHandle<String> string;
      do {
        // We know that the interesting slot will be on the aborted page and
        // hence we allocate until we get our string on the aborted page.
        // We used slot 1 in the fixed size array which corresponds to the
        // the first word in the string. Since the first object definitely
        // migrated we can just allocate until we hit the aborted page.
        string = isolate->factory()
                     ->NewStringFromOneByte(string_to_broken_address,
                                            AllocationType::kOld)
                     .ToHandleChecked();
      } while (PageMetadata::FromHeapObject(*string) != to_be_aborted_page);

      // If remembered set entries are not properly filtered/reset for aborted
      // pages we have now a broken address at an object slot in old space and
      // the following scavenge will crash.
      heap::InvokeMinorGC(CcTest::heap());
    }
  }
  heap->RemoveNearHeapLimitCallback(reset_oom, 0u);
}

}  // namespace heap
}  // namespace internal
}  // namespace v8

"""

```