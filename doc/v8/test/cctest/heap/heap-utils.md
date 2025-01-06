Response: Let's break down the thought process for analyzing this C++ file and relating it to JavaScript.

**1. Understanding the Request:**

The request asks for two main things:

* **Summary of Functionality:** What does this C++ file *do*?
* **Relationship to JavaScript (with Examples):** How does this backend code relate to things a JavaScript developer might experience?

**2. Initial Scan and Keyword Identification:**

I'd first scan the file for prominent keywords and namespaces:

* `// Copyright 2016 the V8 project authors`:  Confirms it's V8 related.
* `#include`: Lots of includes pointing to V8's internal structures (`src/heap/*`, `src/objects/*`, `src/execution/*`). This immediately suggests it deals with low-level memory management within V8.
* `namespace v8 { namespace internal { namespace heap {`:  Confirms this is a utility file within V8's heap management system.
* Function names like `SealCurrentObjects`, `FillOldSpacePageWithFixedArrays`, `CreatePadding`, `SimulateIncrementalMarking`, `InvokeMajorGC`, `GrowNewSpace`. These names strongly suggest interactions with the garbage collection process and memory allocation.

**3. Grouping Functions by Purpose:**

As I read through the functions, I'd start mentally grouping them based on their apparent actions:

* **Garbage Collection Control:** `SealCurrentObjects`, `InvokeMajorGC`, `InvokeMinorGC`, `InvokeAtomicMajorGC`, `InvokeAtomicMinorGC`, `SimulateIncrementalMarking`, `CollectSharedGarbage`, `EmptyNewSpaceUsingGC`. These directly manipulate the GC.
* **Memory Allocation/Manipulation for Testing:** `FillOldSpacePageWithFixedArrays`, `CreatePadding`, `FillCurrentPage`, `FillCurrentPageButNBytes`. These seem designed to set up specific memory layouts for testing purposes.
* **Space Management:** `SimulateFullSpace`, `AbandonCurrentlyFreeMemory`, `GrowNewSpace`, `GrowNewSpaceToMaximumCapacity`. These modify the state of different memory spaces within the heap.
* **Internal Helpers:** `FixedArrayLenFromSize`, `InCorrectGeneration`. These are utility functions used by the other functions.
* **Setup/Teardown:** `ManualGCScope`. This is a class for controlling GC behavior during tests.

**4. Inferring High-Level Functionality:**

Based on the grouped functions, I can infer that the file's primary purpose is to provide **utilities for testing V8's heap management and garbage collection**. It allows testers to:

* **Force GCs:**  Trigger different types of garbage collections (major, minor, atomic).
* **Simulate GC Processes:** Control incremental marking.
* **Manipulate Memory Layout:** Fill pages with specific objects, create padding.
* **Control Space Properties:**  Simulate full spaces, abandon memory, grow spaces.
* **Control GC Behavior in Tests:** The `ManualGCScope` ensures predictable GC behavior during unit tests.

**5. Connecting to JavaScript (the Crucial Step):**

Now, the challenge is linking this low-level C++ to the high-level world of JavaScript. I'd think about what JavaScript developers experience related to memory:

* **Memory Allocation:** When we create objects, arrays, strings, functions, JavaScript engines allocate memory. This C++ code is part of *how* that allocation happens.
* **Garbage Collection:**  We don't manually free memory in JavaScript. The engine's garbage collector reclaims unused memory. This C++ code is about controlling and testing that GC.
* **Performance:**  Memory management and GC directly impact JavaScript performance. The tools in this file are used to test the efficiency and correctness of these processes.

**6. Crafting JavaScript Examples:**

For each connection, I'd come up with simple JavaScript examples that illustrate the concept:

* **Memory Allocation:** `const obj = {}; const arr = [];`  These actions trigger the memory allocation mechanisms this C++ code manages.
* **Garbage Collection (Implicit):**  Creating and then abandoning objects (`let x = {}; x = null;`) makes them eligible for GC. While we can't directly control *when* the GC runs in a browser, this C++ code is part of the engine that *does* the collecting.
* **Performance (Impact):**  Creating many objects or large data structures can trigger more frequent or intensive GCs, potentially causing pauses or slowdowns. This C++ file helps test and optimize the GC to minimize these impacts.

**7. Refinement and Clarity:**

Finally, I'd review my summary and examples for clarity and accuracy. I'd ensure the language is accessible and avoids overly technical jargon when explaining the JavaScript connections. I'd also emphasize that this C++ code is *behind the scenes* and not directly accessible to JavaScript developers.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  "This just seems like a bunch of low-level memory stuff."
* **Correction:** "Okay, but *why* would they need all these functions? It's for *testing*. That's the key purpose."
* **Initial thought (JavaScript connection):** "It's hard to directly show the connection."
* **Refinement:** "Focus on the *outcomes* in JavaScript. What user-visible effects are related to memory management and GC?"  This leads to the examples about object creation and potential performance impacts.
* **Ensuring Accuracy:** Double-checking the function names and comments in the C++ code to confirm my understanding of their purpose.

By following this systematic approach, combining code analysis with an understanding of JavaScript's runtime behavior, I can effectively explain the purpose of this C++ utility file and its relevance to JavaScript.
这个C++源代码文件 `v8/test/cctest/heap/heap-utils.cc` 提供了一系列用于在V8 JavaScript引擎的**堆（Heap）管理**相关的单元测试中使用的**辅助工具函数**。 它的主要功能可以归纳如下：

**主要功能:**

1. **控制和模拟垃圾回收 (Garbage Collection, GC):**
   - 提供函数来强制触发各种类型的垃圾回收，例如：
     - `InvokeMajorGC()`: 触发主垃圾回收 (Major GC)，清理老生代对象。
     - `InvokeMinorGC()`: 触发新生代垃圾回收 (Minor GC)，清理新生代对象。
     - `InvokeAtomicMajorGC()`: 触发原子性的主垃圾回收。
     - `InvokeMemoryReducingMajorGCs()`: 触发所有可用的垃圾回收以减少内存占用。
     - `CollectSharedGarbage()`:  收集共享堆的垃圾。
   - 提供函数来模拟增量标记 (Incremental Marking) 过程，允许逐步进行垃圾标记，这对测试增量 GC 的正确性非常重要。
     - `SimulateIncrementalMarking()`
   - 提供 `ManualGCScope` 类，用于在测试作用域内禁用并发垃圾回收等特性，以便更精确地控制 GC 行为。

2. **操纵堆内存布局:**
   - 提供函数来填充堆的不同区域，以便在特定条件下测试 GC 或内存分配行为。
     - `FillOldSpacePageWithFixedArrays()`:  用固定大小的数组填充老生代空间页面。
     - `CreatePadding()`: 在堆中创建指定大小的填充物。
     - `FillCurrentPage()` 和 `FillCurrentPageButNBytes()`: 填充当前的新生代空间页面。
   - 提供函数来模拟堆空间的状态，例如：
     - `SimulateFullSpace()`: 模拟堆空间已满的情况。
     - `AbandonCurrentlyFreeMemory()`: 标记当前空闲内存为不可分配，用于测试。

3. **控制内存分配:**
   - `SealCurrentObjects()`:  在执行某些测试前，确保当前的对象不会被移动或回收。
   - `GrowNewSpace()` 和 `GrowNewSpaceToMaximumCapacity()`: 增加新生代空间的大小，用于测试空间增长相关的逻辑。

4. **其他辅助功能:**
   - `FixedArrayLenFromSize()`:  根据给定的大小计算 `FixedArray` 的长度。
   - `InCorrectGeneration()`: 检查对象是否在期望的代龄中。
   - `ForceEvacuationCandidate()`: 强制页面成为疏散的候选者 (用于某些 GC 策略测试)。
   - `EmptyNewSpaceUsingGC()`: 通过触发 GC 来清空新生代空间。

**与 JavaScript 的关系 (并举例说明):**

尽管这是一个 C++ 文件，但它直接关系到 V8 如何管理 JavaScript 对象的内存。JavaScript 开发者通常不需要直接与这些底层机制交互，但这些工具函数所测试的正是 JavaScript 运行时环境的核心部分。

以下是一些 JavaScript 功能与这些 C++ 工具函数所测试的 V8 内部机制的关联示例：

**1. JavaScript 对象创建和垃圾回收:**

```javascript
// JavaScript 示例
let myObject = {}; // 创建一个 JavaScript 对象

// ... 一段时间后，不再使用 myObject
myObject = null; // 将引用设置为 null，使其成为垃圾回收的候选者
```

在 V8 内部，`InvokeMajorGC()` 和 `InvokeMinorGC()` 这样的 C++ 函数被用于测试当 JavaScript 代码执行类似上述操作时，V8 的垃圾回收器是否能够正确地识别并回收不再使用的 `myObject` 所占用的内存。`SimulateIncrementalMarking()` 可以测试增量 GC 是否能在不阻塞主线程的情况下逐步完成标记，从而减少 JavaScript 应用的卡顿。

**2. JavaScript 数组和内存分配:**

```javascript
// JavaScript 示例
const largeArray = new Array(10000); // 创建一个大型数组

for (let i = 0; i < largeArray.length; i++) {
  largeArray[i] = i * 2;
}
```

当 JavaScript 创建像 `largeArray` 这样的对象时，V8 需要在堆上分配足够的内存。`FillOldSpacePageWithFixedArrays()` 这样的 C++ 函数可以用来测试当 JavaScript 创建大量或大型对象时，V8 的内存分配器是否能有效地管理老生代空间。`GrowNewSpace()` 可以测试当新生代空间不足以容纳新对象时，V8 是否能正确地扩展新生代空间。

**3. JavaScript 性能和内存管理:**

```javascript
// JavaScript 示例
function createManyObjects() {
  for (let i = 0; i < 100000; i++) {
    let obj = { id: i };
  }
}

createManyObjects();
```

像 `createManyObjects` 这样的函数会创建大量的临时对象。V8 的垃圾回收器需要高效地处理这些对象。`ManualGCScope` 这样的工具可以帮助测试人员在特定的测试场景下禁用并发 GC，以便更精确地衡量特定 GC 算法的性能。`SimulateFullSpace()` 可以测试当堆内存接近极限时，GC 的行为是否符合预期，从而保证 JavaScript 应用的稳定性。

**总结:**

`v8/test/cctest/heap/heap-utils.cc` 文件中的工具函数是 V8 引擎开发和测试过程中的关键组成部分。它们允许开发者在底层 C++ 层面精确地控制和模拟堆内存的状态和垃圾回收行为，以确保 V8 引擎能够高效、稳定地执行 JavaScript 代码并管理内存。虽然 JavaScript 开发者通常不直接使用这些工具，但它们所测试的功能直接影响着 JavaScript 应用的性能和内存使用。

Prompt: 
```
这是目录为v8/test/cctest/heap/heap-utils.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/cctest/heap/heap-utils.h"

#include "src/base/platform/mutex.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/execution/isolate.h"
#include "src/heap/factory.h"
#include "src/heap/free-list.h"
#include "src/heap/gc-tracer-inl.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap.h"
#include "src/heap/incremental-marking.h"
#include "src/heap/mark-compact.h"
#include "src/heap/marking-barrier.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/heap/page-metadata-inl.h"
#include "src/heap/safepoint.h"
#include "src/heap/spaces.h"
#include "src/objects/free-space-inl.h"
#include "test/cctest/cctest.h"

namespace v8 {
namespace internal {
namespace heap {

void SealCurrentObjects(Heap* heap) {
  // If you see this check failing, disable the flag at the start of your test:
  // v8_flags.stress_concurrent_allocation = false;
  // Background thread allocating concurrently interferes with this function.
  CHECK(!v8_flags.stress_concurrent_allocation);
  heap::InvokeMajorGC(heap);
  heap::InvokeMajorGC(heap);
  heap->EnsureSweepingCompleted(Heap::SweepingForcedFinalizationMode::kV8Only);
  heap->FreeMainThreadLinearAllocationAreas();
  for (PageMetadata* page : *heap->old_space()) {
    page->MarkNeverAllocateForTesting();
  }
}

int FixedArrayLenFromSize(int size) {
  return std::min({(size - OFFSET_OF_DATA_START(FixedArray)) / kTaggedSize,
                   FixedArray::kMaxRegularLength});
}

void FillOldSpacePageWithFixedArrays(
    Heap* heap, int remainder, DirectHandleVector<FixedArray>* out_handles) {
  PauseAllocationObserversScope pause_observers(heap);
  Isolate* isolate = heap->isolate();
  const int kArraySize = 128;
  const int kArrayLen = heap::FixedArrayLenFromSize(kArraySize);
  int allocated = 0;
  bool empty = true;
  do {
    Handle<FixedArray> array;
    if (allocated + kArraySize * 2 >
        static_cast<int>(MemoryChunkLayout::AllocatableMemoryInDataPage())) {
      int size =
          kArraySize * 2 -
          ((allocated + kArraySize * 2) -
           static_cast<int>(MemoryChunkLayout::AllocatableMemoryInDataPage())) -
          remainder;
      int last_array_len = heap::FixedArrayLenFromSize(size);
      array = isolate->factory()->NewFixedArray(last_array_len,
                                                AllocationType::kOld);
      CHECK_EQ(size, array->Size());
      allocated += array->Size() + remainder;
    } else {
      array =
          isolate->factory()->NewFixedArray(kArrayLen, AllocationType::kOld);
      allocated += array->Size();
      CHECK_EQ(kArraySize, array->Size());
    }
    if (empty) {
      // Check that allocations started on a new page.
      CHECK_EQ(array->address(),
               PageMetadata::FromHeapObject(*array)->area_start());
      empty = false;
    }
    if (out_handles) out_handles->push_back(array);
  } while (allocated <
           static_cast<int>(MemoryChunkLayout::AllocatableMemoryInDataPage()));
  heap->FreeMainThreadLinearAllocationAreas();
}

void CreatePadding(Heap* heap, int padding_size, AllocationType allocation,
                   DirectHandleVector<FixedArray>* out_handles,
                   int object_size) {
  Isolate* isolate = heap->isolate();
  int allocate_memory;
  int length;
  int free_memory = padding_size;
  heap->FreeMainThreadLinearAllocationAreas();
  if (allocation == i::AllocationType::kOld) {
    int overall_free_memory = static_cast<int>(heap->old_space()->Available());
    CHECK(padding_size <= overall_free_memory || overall_free_memory == 0);
  } else {
    int overall_free_memory = static_cast<int>(heap->new_space()->Available());
    CHECK(padding_size <= overall_free_memory || overall_free_memory == 0);
  }
  while (free_memory > 0) {
    if (free_memory > object_size) {
      allocate_memory = object_size;
      length = FixedArrayLenFromSize(allocate_memory);
    } else {
      allocate_memory = free_memory;
      length = FixedArrayLenFromSize(allocate_memory);
      if (length <= 0) {
        // Not enough room to create another FixedArray, so create a filler.
        if (allocation == i::AllocationType::kOld) {
          heap->CreateFillerObjectAt(*heap->OldSpaceAllocationTopAddress(),
                                     free_memory);
        } else {
          heap->CreateFillerObjectAt(*heap->NewSpaceAllocationTopAddress(),
                                     free_memory);
        }
        break;
      }
    }
    auto array = isolate->factory()->NewFixedArray(length, allocation);
    if (out_handles) out_handles->push_back(array);
    CHECK((allocation == AllocationType::kYoung &&
           heap->new_space()->Contains(*array)) ||
          (allocation == AllocationType::kOld && heap->InOldSpace(*array)) ||
          v8_flags.single_generation);
    free_memory -= array->Size();
  }
  heap->FreeMainThreadLinearAllocationAreas();
}

namespace {
void FillPageInPagedSpace(PageMetadata* page,
                          DirectHandleVector<FixedArray>* out_handles) {
  Heap* heap = page->heap();
  Isolate* isolate = heap->isolate();
  DCHECK(page->SweepingDone());
  SafepointScope safepoint_scope(isolate,
                                 kGlobalSafepointForSharedSpaceIsolate);
  PagedSpaceBase* paged_space = static_cast<PagedSpaceBase*>(page->owner());
  heap->FreeLinearAllocationAreas();

  PauseAllocationObserversScope no_observers_scope(heap);

  CollectionEpoch full_epoch =
      heap->tracer()->CurrentEpoch(GCTracer::Scope::ScopeId::MARK_COMPACTOR);
  CollectionEpoch young_epoch = heap->tracer()->CurrentEpoch(
      GCTracer::Scope::ScopeId::MINOR_MARK_SWEEPER);

  for (PageMetadata* p : *paged_space) {
    if (p != page) paged_space->UnlinkFreeListCategories(p);
  }

  // If min_block_size is larger than OFFSET_OF_DATA_START(FixedArray), all
  // blocks in the free list can be used to allocate a fixed array. This
  // guarantees that we can fill the whole page.
  DCHECK_LT(OFFSET_OF_DATA_START(FixedArray),
            paged_space->free_list()->min_block_size());

  std::vector<int> available_sizes;
  // Collect all free list block sizes
  page->ForAllFreeListCategories(
      [&available_sizes](FreeListCategory* category) {
        category->IterateNodesForTesting(
            [&available_sizes](Tagged<FreeSpace> node) {
              int node_size = node->Size();
              if (node_size >= kMaxRegularHeapObjectSize) {
                available_sizes.push_back(node_size);
              }
            });
      });

  // Allocate as many max size arrays as possible, while making sure not to
  // leave behind a block too small to fit a FixedArray.
  const int max_array_length = FixedArrayLenFromSize(kMaxRegularHeapObjectSize);
  for (size_t i = 0; i < available_sizes.size(); ++i) {
    int available_size = available_sizes[i];
    while (available_size > kMaxRegularHeapObjectSize) {
      Handle<FixedArray> fixed_array = isolate->factory()->NewFixedArray(
          max_array_length, AllocationType::kYoung);
      if (out_handles) out_handles->push_back(fixed_array);
      available_size -= kMaxRegularHeapObjectSize;
    }
  }

  heap->FreeLinearAllocationAreas();

  // Allocate FixedArrays in remaining free list blocks, from largest
  // category to smallest.
  std::vector<std::vector<int>> remaining_sizes;
  page->ForAllFreeListCategories(
      [&remaining_sizes](FreeListCategory* category) {
        remaining_sizes.push_back({});
        std::vector<int>& sizes_in_category =
            remaining_sizes[remaining_sizes.size() - 1];
        category->IterateNodesForTesting(
            [&sizes_in_category](Tagged<FreeSpace> node) {
              int node_size = node->Size();
              DCHECK_LT(0, FixedArrayLenFromSize(node_size));
              sizes_in_category.push_back(node_size);
            });
      });
  for (auto it = remaining_sizes.rbegin(); it != remaining_sizes.rend(); ++it) {
    std::vector<int> sizes_in_category = *it;
    for (int size : sizes_in_category) {
      DCHECK_LE(size, kMaxRegularHeapObjectSize);
      int array_length = FixedArrayLenFromSize(size);
      DCHECK_LT(0, array_length);
      Handle<FixedArray> fixed_array = isolate->factory()->NewFixedArray(
          array_length, AllocationType::kYoung);
      if (out_handles) out_handles->push_back(fixed_array);
    }
  }

  DCHECK_EQ(0, page->AvailableInFreeList());
  DCHECK_EQ(0, page->AvailableInFreeListFromAllocatedBytes());

  for (PageMetadata* p : *paged_space) {
    if (p != page) paged_space->RelinkFreeListCategories(p);
  }

  // Allocations in this method should not require a GC.
  CHECK_EQ(full_epoch, heap->tracer()->CurrentEpoch(
                           GCTracer::Scope::ScopeId::MARK_COMPACTOR));
  CHECK_EQ(young_epoch, heap->tracer()->CurrentEpoch(
                            GCTracer::Scope::ScopeId::MINOR_MARK_SWEEPER));
  heap->FreeLinearAllocationAreas();
}
}  // namespace

void FillCurrentPage(v8::internal::NewSpace* space,
                     DirectHandleVector<FixedArray>* out_handles) {
  if (v8_flags.minor_ms) {
    const Address top = space->heap()->NewSpaceTop();
    space->heap()->FreeMainThreadLinearAllocationAreas();
    PauseAllocationObserversScope pause_observers(space->heap());
    if (top == kNullAddress) return;
    PageMetadata* page = PageMetadata::FromAllocationAreaAddress(top);
    space->heap()->EnsureSweepingCompleted(
        Heap::SweepingForcedFinalizationMode::kV8Only);
    FillPageInPagedSpace(page, out_handles);
    space->heap()->FreeMainThreadLinearAllocationAreas();
  } else {
    FillCurrentPageButNBytes(SemiSpaceNewSpace::From(space), 0, out_handles);
  }
}

void FillCurrentPageButNBytes(v8::internal::SemiSpaceNewSpace* space,
                              int extra_bytes,
                              DirectHandleVector<FixedArray>* out_handles) {
  space->heap()->FreeMainThreadLinearAllocationAreas();
  PauseAllocationObserversScope pause_observers(space->heap());
  // We cannot rely on `space->limit()` to point to the end of the current page
  // in the case where inline allocations are disabled, it actually points to
  // the current allocation pointer.
  DCHECK_IMPLIES(
      !space->heap()->IsInlineAllocationEnabled(),
      space->heap()->NewSpaceTop() == space->heap()->NewSpaceLimit());
  int space_remaining = space->GetSpaceRemainingOnCurrentPageForTesting();
  CHECK(space_remaining >= extra_bytes);
  int new_linear_size = space_remaining - extra_bytes;
  if (new_linear_size == 0) return;
  heap::CreatePadding(space->heap(), space_remaining, i::AllocationType::kYoung,
                      out_handles);
  space->heap()->FreeMainThreadLinearAllocationAreas();
}

void SimulateIncrementalMarking(i::Heap* heap, bool force_completion) {
  static constexpr auto kStepSize = v8::base::TimeDelta::FromMilliseconds(100);
  CHECK(v8_flags.incremental_marking);
  i::IncrementalMarking* marking = heap->incremental_marking();

  if (heap->sweeping_in_progress()) {
    IsolateSafepointScope scope(heap);
    heap->EnsureSweepingCompleted(
        Heap::SweepingForcedFinalizationMode::kV8Only);
  }

  if (marking->IsMinorMarking()) {
    // If minor incremental marking is running, we need to finalize it first
    // because of the AdvanceForTesting call in this function which is currently
    // only possible for MajorMC.
    heap->CollectGarbage(NEW_SPACE,
                         GarbageCollectionReason::kFinalizeConcurrentMinorMS);
  }

  if (marking->IsStopped()) {
    heap->StartIncrementalMarking(i::GCFlag::kNoFlags,
                                  i::GarbageCollectionReason::kTesting);
  }
  CHECK(marking->IsMarking());
  if (!force_completion) return;

  IsolateSafepointScope scope(heap);
  MarkingBarrier::PublishAll(heap);
  marking->MarkRootsForTesting();

  while (!marking->IsMajorMarkingComplete()) {
    marking->AdvanceForTesting(kStepSize);
  }
}

void SimulateFullSpace(v8::internal::PagedSpace* space) {
  Heap* heap = space->heap();
  IsolateSafepointScope safepoint_scope(heap);
  heap->FreeLinearAllocationAreas();

  // If you see this check failing, disable the flag at the start of your test:
  // v8_flags.stress_concurrent_allocation = false;
  // Background thread allocating concurrently interferes with this function.
  CHECK(!v8_flags.stress_concurrent_allocation);
  if (space->heap()->sweeping_in_progress()) {
    space->heap()->EnsureSweepingCompleted(
        Heap::SweepingForcedFinalizationMode::kV8Only);
  }
  space->ResetFreeList();
}

void AbandonCurrentlyFreeMemory(PagedSpace* space) {
  Heap* heap = space->heap();
  IsolateSafepointScope safepoint_scope(heap);
  heap->FreeLinearAllocationAreas();

  for (PageMetadata* page : *space) {
    page->MarkNeverAllocateForTesting();
  }
}

void InvokeMajorGC(Heap* heap) {
  heap->CollectGarbage(OLD_SPACE, GarbageCollectionReason::kTesting);
}

void InvokeMajorGC(Heap* heap, GCFlag gc_flag) {
  heap->CollectAllGarbage(gc_flag, GarbageCollectionReason::kTesting);
}

void InvokeMinorGC(Heap* heap) {
  heap->CollectGarbage(NEW_SPACE, GarbageCollectionReason::kTesting);
}

void InvokeAtomicMajorGC(Heap* heap) {
  heap->PreciseCollectAllGarbage(GCFlag::kNoFlags,
                                 GarbageCollectionReason::kTesting);
  if (heap->sweeping_in_progress()) {
    heap->EnsureSweepingCompleted(
        Heap::SweepingForcedFinalizationMode::kUnifiedHeap);
  }
}

void InvokeAtomicMinorGC(Heap* heap) {
  InvokeMinorGC(heap);
  if (heap->sweeping_in_progress()) {
    heap->EnsureSweepingCompleted(
        Heap::SweepingForcedFinalizationMode::kUnifiedHeap);
  }
}

void InvokeMemoryReducingMajorGCs(Heap* heap) {
  heap->CollectAllAvailableGarbage(GarbageCollectionReason::kTesting);
}

void CollectSharedGarbage(Heap* heap) {
  heap->CollectGarbageShared(heap->main_thread_local_heap(),
                             GarbageCollectionReason::kTesting);
}

void EmptyNewSpaceUsingGC(Heap* heap) { InvokeMajorGC(heap); }

void ForceEvacuationCandidate(PageMetadata* page) {
  Isolate* isolate = page->owner()->heap()->isolate();
  SafepointScope safepoint(isolate, kGlobalSafepointForSharedSpaceIsolate);
  CHECK(v8_flags.manual_evacuation_candidates_selection);
  page->Chunk()->SetFlagNonExecutable(
      MemoryChunk::FORCE_EVACUATION_CANDIDATE_FOR_TESTING);
  page->owner()->heap()->FreeLinearAllocationAreas();
}

bool InCorrectGeneration(Tagged<HeapObject> object) {
  return v8_flags.single_generation ? !i::HeapLayout::InYoungGeneration(object)
                                    : i::HeapLayout::InYoungGeneration(object);
}

void GrowNewSpace(Heap* heap) {
  IsolateSafepointScope scope(heap);
  NewSpace* new_space = heap->new_space();
  if (new_space->TotalCapacity() < new_space->MaximumCapacity()) {
    new_space->Grow();
  }
  CHECK(new_space->EnsureCurrentCapacity());
}

void GrowNewSpaceToMaximumCapacity(Heap* heap) {
  IsolateSafepointScope scope(heap);
  NewSpace* new_space = heap->new_space();
  while (new_space->TotalCapacity() < new_space->MaximumCapacity()) {
    new_space->Grow();
  }
  CHECK(new_space->EnsureCurrentCapacity());
}

}  // namespace heap

ManualGCScope::ManualGCScope(Isolate* isolate)
    : isolate_(isolate),
      flag_concurrent_marking_(v8_flags.concurrent_marking),
      flag_concurrent_sweeping_(v8_flags.concurrent_sweeping),
      flag_concurrent_minor_ms_marking_(v8_flags.concurrent_minor_ms_marking),
      flag_stress_concurrent_allocation_(v8_flags.stress_concurrent_allocation),
      flag_stress_incremental_marking_(v8_flags.stress_incremental_marking),
      flag_parallel_marking_(v8_flags.parallel_marking),
      flag_detect_ineffective_gcs_near_heap_limit_(
          v8_flags.detect_ineffective_gcs_near_heap_limit),
      flag_cppheap_concurrent_marking_(v8_flags.cppheap_concurrent_marking) {
  // Some tests run threaded (back-to-back) and thus the GC may already be
  // running by the time a ManualGCScope is created. Finalizing existing marking
  // prevents any undefined/unexpected behavior.
  if (isolate) {
    auto* heap = isolate->heap();
    if (heap->incremental_marking()->IsMarking()) {
      heap::InvokeAtomicMajorGC(heap);
    }
  }

  v8_flags.concurrent_marking = false;
  v8_flags.concurrent_sweeping = false;
  v8_flags.concurrent_minor_ms_marking = false;
  v8_flags.stress_incremental_marking = false;
  v8_flags.stress_concurrent_allocation = false;
  // Parallel marking has a dependency on concurrent marking.
  v8_flags.parallel_marking = false;
  v8_flags.detect_ineffective_gcs_near_heap_limit = false;
  // CppHeap concurrent marking has a dependency on concurrent marking.
  v8_flags.cppheap_concurrent_marking = false;

  if (isolate_ && isolate_->heap()->cpp_heap()) {
    CppHeap::From(isolate_->heap()->cpp_heap())
        ->UpdateGCCapabilitiesFromFlagsForTesting();
  }
}

ManualGCScope::~ManualGCScope() {
  v8_flags.concurrent_marking = flag_concurrent_marking_;
  v8_flags.concurrent_sweeping = flag_concurrent_sweeping_;
  v8_flags.concurrent_minor_ms_marking = flag_concurrent_minor_ms_marking_;
  v8_flags.stress_concurrent_allocation = flag_stress_concurrent_allocation_;
  v8_flags.stress_incremental_marking = flag_stress_incremental_marking_;
  v8_flags.parallel_marking = flag_parallel_marking_;
  v8_flags.detect_ineffective_gcs_near_heap_limit =
      flag_detect_ineffective_gcs_near_heap_limit_;
  v8_flags.cppheap_concurrent_marking = flag_cppheap_concurrent_marking_;

  if (isolate_ && isolate_->heap()->cpp_heap()) {
    CppHeap::From(isolate_->heap()->cpp_heap())
        ->UpdateGCCapabilitiesFromFlagsForTesting();
  }
}

}  // namespace internal
}  // namespace v8

"""

```