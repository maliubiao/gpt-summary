Response:
Let's break down the thought process for analyzing the C++ test file.

1. **Understanding the Request:** The request asks for the functionality of the C++ file `v8/test/cctest/heap/test-compaction.cc`. It also has specific instructions regarding `.tq` files, JavaScript relevance, logic inference, and common programming errors.

2. **Initial Examination of the File Path and Name:**  The path `v8/test/cctest/heap/` immediately suggests that this is a test file within V8's continuous testing framework (`cctest`) and specifically related to the heap component. The `test-compaction.cc` name strongly indicates it's testing heap compaction.

3. **Scanning the File Content (Keywords and Includes):**  I'll start by quickly scanning the included headers:
    * `"src/execution/isolate.h"`:  Indicates interaction with the V8 isolate, the fundamental execution environment.
    * `"src/heap/factory.h"`: Used for creating objects on the heap.
    * `"src/heap/heap-inl.h"` and `"src/heap/mark-compact.h"`:  Crucial headers for heap management and the mark-compact garbage collector (which compaction is a part of).
    * `"src/heap/marking-state-inl.h"` and `"src/heap/mutable-page-metadata.h"`:  Deals with the internal state of the garbage collector and metadata about memory pages.
    * `"src/heap/remembered-set-inl.h"`:  Relevant to incremental garbage collection and tracking inter-generational pointers.
    * `"src/objects/objects-inl.h"`:  Deals with V8's object representation.
    * `"test/cctest/cctest.h"`, `"test/cctest/heap/heap-tester.h"`, `"test/cctest/heap/heap-utils.h"`:  Standard headers for the V8 testing framework.

4. **Identifying Test Cases (HEAP_TEST):** The code uses `HEAP_TEST`. This is a macro in V8's testing framework that defines individual test cases related to heap operations. I'll enumerate them:
    * `CompactionFullAbortedPage`
    * `CompactionPartiallyAbortedPage`
    * `CompactionPartiallyAbortedPageIntraAbortedPointers`
    * `CompactionPartiallyAbortedPageWithRememberedSetEntries`

5. **Analyzing Individual Test Cases (Purpose and Logic):**  I'll now examine each test case to understand its specific goal:

    * **`CompactionFullAbortedPage`**:  The comment `// Test the scenario where we reach OOM during compaction and the whole page is aborted.` is very clear. It sets up a situation where a full compaction cycle is triggered, but an out-of-memory (OOM) condition is simulated, causing the entire compaction of a chosen page to be cancelled. The test verifies that the page's metadata is reset correctly after abortion.

    * **`CompactionPartiallyAbortedPage`**: The comment `// Test the scenario where we reach OOM during compaction and parts of the page have already been migrated to a new one.` describes the scenario. This tests a more complex case where compaction starts moving objects from a page, but OOM occurs midway, leading to a partial migration. The test checks that some objects are moved while others remain on the original (aborted) page.

    * **`CompactionPartiallyAbortedPageIntraAbortedPointers`**:  This builds upon the previous test. The comment `// Objects on the aborted page are linked together.` is the key difference. This tests whether pointers *within* the aborted page are correctly updated after the partial abortion. It specifically makes sure that objects that weren't moved still point to each other correctly.

    * **`CompactionPartiallyAbortedPageWithRememberedSetEntries`**: This is the most intricate test. The comment `// and the very first object on the aborted page points into new space.` highlights the addition of a cross-generational pointer. The test focuses on verifying that the "remembered set" (which tracks such pointers) is correctly handled after a partial compaction abortion. It simulates a potential bug where incorrect remembered set information could lead to crashes during subsequent garbage collections.

6. **Looking for JavaScript Relevance:** The tests are about low-level heap management and garbage collection details. While these processes are *essential* for JavaScript's memory management, the C++ code itself doesn't directly interact with JavaScript code. The tests simulate scenarios that *could* occur when running JavaScript, but they don't execute JavaScript. Therefore, a direct JavaScript example is not really applicable. I'll note the indirect relationship.

7. **Logic Inference and Input/Output:**  The tests primarily focus on *state transitions* within the heap during compaction and abortion. Defining precise "input" and "output" in the traditional sense is challenging. The "input" is the initial state of the heap, the objects allocated, and the simulated OOM condition. The "output" is the verification of the heap's internal state (page metadata, object locations, remembered sets) after the aborted compaction. I'll provide a conceptual explanation of the input and output for one of the tests.

8. **Identifying Common Programming Errors:** The tests are designed to prevent *internal* errors in the V8 garbage collector. However, the scenarios they test can be related to common *user-level* programming errors that lead to memory pressure and potentially trigger the conditions being tested. Examples include:
    * **Memory Leaks:**  While not directly tested, memory leaks increase the likelihood of triggering OOM during compaction.
    * **Creating Large Numbers of Objects:**  This also increases memory pressure.
    * **Holding onto Unnecessary References:**  Similar to leaks, preventing garbage collection.

9. **Addressing the `.tq` Question:** The prompt specifically asks about `.tq` files (Torque). A quick check of the filename reveals it ends in `.cc`. Therefore, it's C++ and not Torque.

10. **Structuring the Answer:** I'll organize the answer logically, addressing each point in the prompt:
    * Functionality overview.
    * Explanation of each test case.
    * Clarification about the `.tq` extension.
    * Explanation of the indirect relationship to JavaScript.
    * A conceptual example of input/output for a test case.
    * Examples of related user-level programming errors.

By following these steps, I can thoroughly analyze the C++ test file and provide a comprehensive and accurate answer to the request.
这是一个V8源代码文件，路径为 `v8/test/cctest/heap/test-compaction.cc`。根据文件路径和名称，可以推断出它是一个用于测试V8堆压缩功能的C++测试文件。

**功能列举:**

这个文件包含了多个测试用例，用于验证在堆压缩过程中，特别是遇到内存不足 (OOM - Out Of Memory) 的情况时，V8的堆管理机制是否能正确处理。  具体来说，它主要测试了以下几种场景：

1. **完全中止的页 (CompactionFullAbortedPage):** 测试在堆压缩过程中，如果发生OOM，导致整个页面的压缩操作被中止的情况。它会检查中止后的页面是否恢复到正常状态，例如：
    * Markbits 被清除。
    * 页面不再被标记为疏散候选 (evacuation candidate)。
    * 页面不再被标记为中止压缩 (aborted compaction)。

2. **部分中止的页 (CompactionPartiallyAbortedPage):** 测试在堆压缩过程中，如果发生OOM，导致部分对象已经被迁移到新页面，而剩余对象的迁移被中止的情况。它会检查哪些对象被成功迁移，哪些对象仍然留在原来的页面。

3. **部分中止的页和页内指针 (CompactionPartiallyAbortedPageIntraAbortedPointers):**  与部分中止的页类似，但更进一步测试了在被中止压缩的页面内的对象之间存在相互引用的情况。它会检查这些页内指针在压缩中止后是否仍然有效。

4. **部分中止的页和Remembered Set条目 (CompactionPartiallyAbortedPageWithRememberedSetEntries):**  测试在部分中止的压缩页面中，如果存在指向新生代对象的指针（需要Remembered Set来跟踪），在压缩中止后，Remembered Set的条目是否能被正确清理和重建，以防止后续的垃圾回收出现错误。

**关于文件扩展名 `.tq`:**

根据您的描述，如果 `v8/test/cctest/heap/test-compaction.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。 然而，当前的文件名是 `.cc`，这表明它是一个 **C++** 源代码文件。  Torque 用于定义 V8 的内置函数和类型系统，通常与性能关键的代码相关。

**与 JavaScript 的功能关系:**

这个 C++ 测试文件直接测试的是 V8 引擎的底层堆管理和垃圾回收机制，这对于 JavaScript 的内存管理至关重要。 JavaScript 开发者不需要直接了解这些底层的实现细节，但这些机制的正确性直接影响到 JavaScript 程序的性能和稳定性。

**JavaScript 举例说明 (概念性):**

虽然这个 C++ 文件不包含 JavaScript 代码，但我们可以用 JavaScript 代码来模拟可能触发堆压缩和 OOM 的场景：

```javascript
// 模拟大量对象分配，可能导致堆内存压力
let largeArray = [];
for (let i = 0; i < 1000000; i++) {
  largeArray.push({ data: new Array(1000).fill(i) });
}

// 模拟对象之间的相互引用，可能增加垃圾回收的复杂性
let obj1 = {};
let obj2 = {};
obj1.ref = obj2;
obj2.ref = obj1;

// 在内存压力下，V8 可能会触发堆压缩来整理内存碎片

// 如果持续分配大量内存，可能会最终导致 OOM 错误
// (实际 JavaScript 环境中，V8 会尽力避免直接抛出 OOM，而是进行多次垃圾回收)
```

当 JavaScript 引擎执行这样的代码时，底层的 V8 堆管理机制会根据内存使用情况触发垃圾回收，其中可能包括堆压缩。 `test-compaction.cc` 中的测试用例就是为了验证在这种情况下，特别是发生 OOM 导致压缩中止时，V8 内部的处理逻辑是否正确。

**代码逻辑推理和假设输入输出 (以 `CompactionFullAbortedPage` 为例):**

**假设输入:**

1. **堆的状态:** 堆中存在一些已分配的对象。
2. **触发条件:** 模拟一个即将进行堆压缩的场景，并且设置在压缩过程中会遇到 OOM。
3. **目标页:** 选择一个特定的 Old Space 页面作为压缩目标。
4. **操作:** 触发 Major GC (Full GC)，其中包含堆压缩阶段。

**代码逻辑:**

1. **初始化:** 初始化 V8 虚拟机和堆。
2. **准备页面:**  创建一个 Old Space 页面，并在其中分配一些对象。将该页面标记为疏散候选，以便触发压缩。
3. **模拟 OOM:** 设置一个回调函数，在压缩过程中人为地触发 OOM 状态。
4. **执行 GC:** 调用 Major GC。
5. **验证:** 检查被选中的页面在 OOM 发生后是否被正确地中止了压缩，并验证页面元数据是否恢复到初始状态（markbits 清空，不再是疏散候选，不再标记为中止压缩）。

**预期输出:**

被选中的页面上的所有对象仍然存在于该页面上（因为压缩被中止了）。该页面的元数据满足 `CheckInvariantsOfAbortedPage` 函数中定义的条件。

**涉及用户常见的编程错误 (间接相关):**

虽然这些测试直接关注 V8 内部的机制，但它们与用户常见的编程错误间接相关。  用户编写的 JavaScript 代码中的某些模式可能会增加堆内存压力，从而更有可能触发堆压缩，甚至在极端情况下导致 OOM。

**例子:**

1. **内存泄漏:**  用户代码中如果存在未释放的对象引用，会导致对象无法被垃圾回收，长期积累会造成内存泄漏，最终可能导致 OOM。这会增加堆压缩发生的频率，并在内存极端紧张时可能触发压缩过程中的 OOM，从而暴露 `test-compaction.cc` 中测试的场景。

   ```javascript
   let leakedObjects = [];
   function createLeakedObject() {
     let obj = { data: new Array(10000).fill(1) };
     leakedObjects.push(obj); // 忘记移除引用，导致内存泄漏
   }

   setInterval(createLeakedObject, 100); // 持续创建泄漏对象
   ```

2. **创建过多的临时对象:**  在循环或高频操作中创建大量生命周期很短的临时对象，也会给堆带来压力，增加垃圾回收和堆压缩的负担。

   ```javascript
   function processData(data) {
     for (let i = 0; i < data.length; i++) {
       let temp = data[i].toString(); // 每次循环创建新的字符串对象
       // ... 对 temp 进行操作 ...
     }
   }
   ```

3. **持有过大的对象:**  创建非常大的对象，例如巨大的数组或字符串，会迅速消耗堆内存，更容易触发内存压力和堆压缩。

   ```javascript
   let hugeArray = new Array(10000000).fill(0);
   ```

总而言之，`v8/test/cctest/heap/test-compaction.cc` 是一个至关重要的测试文件，用于确保 V8 的堆压缩功能在各种异常情况下（特别是 OOM）的正确性和稳定性，这对于保证 JavaScript 程序的健壮性至关重要。虽然 JavaScript 开发者通常不需要直接接触这些底层细节，但理解这些机制有助于更好地理解 JavaScript 的内存管理特性。

### 提示词
```
这是目录为v8/test/cctest/heap/test-compaction.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/heap/test-compaction.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```