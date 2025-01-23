Response:
Let's break down the thought process to analyze the provided C++ code and answer the request.

1. **Understand the Goal:** The core request is to understand the functionality of `v8/test/cctest/heap/heap-utils.cc`. The prompt also has specific secondary requests related to Torque, JavaScript relevance, code logic, and common errors.

2. **Initial Scan for Clues:**  Quickly scan the file contents for keywords and structure.
    * `#include`:  See a lot of V8 internal headers related to `heap`, `objects`, `execution`, and `test`. This strongly suggests the file is about testing V8's heap management.
    * `namespace v8::internal::heap`: Confirms it's internal V8 code specifically for heap-related operations.
    * Function names like `SealCurrentObjects`, `FillOldSpacePageWithFixedArrays`, `CreatePadding`, `SimulateIncrementalMarking`, `InvokeMajorGC`, etc. These names are very descriptive and hint at the file's purpose.
    * The use of `CHECK` and `DCHECK` macros suggests this is test code with assertions.
    * The presence of `ManualGCScope` hints at controlling garbage collection during tests.

3. **Identify Key Functionality Areas:** Based on the function names, group them into logical categories:
    * **Memory Manipulation:**  Functions like `SealCurrentObjects`, `FillOldSpacePageWithFixedArrays`, `CreatePadding`, `FillCurrentPage`, `FillCurrentPageButNBytes`. These seem to be about allocating and filling memory in different heap spaces.
    * **Garbage Collection Control:** Functions like `SimulateIncrementalMarking`, `InvokeMajorGC`, `InvokeMinorGC`, `InvokeAtomicMajorGC`, `InvokeAtomicMinorGC`, `InvokeMemoryReducingMajorGCs`, `CollectSharedGarbage`, `EmptyNewSpaceUsingGC`. These clearly control and trigger garbage collection.
    * **Heap State Manipulation:** Functions like `SimulateFullSpace`, `AbandonCurrentlyFreeMemory`, `ForceEvacuationCandidate`, `GrowNewSpace`, `GrowNewSpaceToMaximumCapacity`. These modify the state of different heap spaces.
    * **Utility/Helper Functions:**  `FixedArrayLenFromSize`, `InCorrectGeneration`. These provide helper calculations or checks.
    * **Scope Management:** `ManualGCScope`. This helps manage GC behavior during tests.

4. **Elaborate on Functionality (High-Level):** For each category, summarize the overall purpose. For example, the memory manipulation functions are about setting up specific memory layouts for testing different GC scenarios. GC control functions are for explicitly triggering and simulating GC phases.

5. **Address Specific Requests:**

    * **Torque (.tq):** Explicitly check the file extension. Since it's `.cc`, it's C++, not Torque. State this clearly.
    * **JavaScript Relationship:**  Think about *why* these heap utilities exist. They're used to *test* the underlying heap, which is crucial for JavaScript object management. Provide a simple JavaScript example demonstrating object creation and garbage collection to connect it to the C++ code. Emphasize that this C++ code *tests* the mechanisms that make the JavaScript example work.
    * **Code Logic and Examples:** Choose a simpler function like `FixedArrayLenFromSize` for a code logic example. Provide clear input and output and explain the calculation. For a slightly more complex example, consider `CreatePadding`. Create hypothetical inputs and describe the expected allocation behavior.
    * **Common Programming Errors:** Think about what could go wrong if heap management isn't done correctly. Memory leaks and dangling pointers are the most common issues. Explain how V8's GC prevents these in JavaScript but can be issues in native code if not handled carefully.

6. **Refine and Structure:** Organize the information logically with clear headings. Use concise language. Ensure the examples are easy to understand. Double-check that all aspects of the prompt are addressed.

7. **Self-Correction/Review:**  Read through the generated answer. Are there any ambiguities?  Is the explanation clear and accurate?  Could any parts be explained better? For example, initially, I might have just said "controls GC". Refining that to "explicitly trigger and simulate different garbage collection phases" is more informative. Similarly, initially, the JavaScript example might have been too complex. Simplifying it to basic object creation and letting the GC handle it makes the connection clearer. Ensure the examples for code logic are clear and the assumptions are stated.

By following these steps, focusing on understanding the code's purpose, and systematically addressing each part of the request, a comprehensive and accurate answer can be generated.
这个C++源代码文件 `v8/test/cctest/heap/heap-utils.cc` 提供了一系列用于在V8的CCTests（Chromium C++ Tests）中操作和模拟V8堆行为的实用工具函数。 它的主要目的是简化编写涉及堆操作、垃圾回收（GC）以及内存管理的测试用例。

**主要功能列表:**

1. **控制垃圾回收 (Garbage Collection Control):**
   - `InvokeMajorGC(Heap* heap)`: 强制执行一次主垃圾回收（Old Space GC）。
   - `InvokeMinorGC(Heap* heap)`: 强制执行一次新生代垃圾回收（New Space GC）。
   - `InvokeAtomicMajorGC(Heap* heap)`: 强制执行一次原子主垃圾回收。
   - `InvokeAtomicMinorGC(Heap* heap)`: 强制执行一次原子新生代垃圾回收。
   - `InvokeMemoryReducingMajorGCs(Heap* heap)`:  触发所有可用的垃圾回收以减少内存使用。
   - `CollectSharedGarbage(Heap* heap)`:  收集共享堆的垃圾。
   - `EmptyNewSpaceUsingGC(Heap* heap)`: 通过执行主垃圾回收来清空新生代。
   - `SimulateIncrementalMarking(i::Heap* heap, bool force_completion)`: 模拟增量标记过程，可以控制是否强制完成。

2. **堆空间操作 (Heap Space Manipulation):**
   - `SealCurrentObjects(Heap* heap)`:  执行Full GC并标记Old Space的页为不可分配，用于隔离测试。
   - `FillOldSpacePageWithFixedArrays(Heap* heap, int remainder, DirectHandleVector<FixedArray>* out_handles)`: 在Old Space的一个页面上填充指定大小的 `FixedArray` 对象。
   - `CreatePadding(Heap* heap, int padding_size, AllocationType allocation, DirectHandleVector<FixedArray>* out_handles, int object_size)`: 在指定的堆空间（Old Space或New Space）中创建指定大小的填充对象。
   - `FillCurrentPage(v8::internal::NewSpace* space, DirectHandleVector<FixedArray>* out_handles)`: 填充当前新生代的页面。
   - `FillCurrentPageButNBytes(v8::internal::SemiSpaceNewSpace* space, int extra_bytes, DirectHandleVector<FixedArray>* out_handles)`: 填充当前新生代的页面，但留下指定数量的字节。
   - `SimulateFullSpace(v8::internal::PagedSpace* space)`: 模拟一个Old Space已满的状态。
   - `AbandonCurrentlyFreeMemory(PagedSpace* space)`: 标记Old Space的当前空闲内存为不可分配。
   - `ForceEvacuationCandidate(PageMetadata* page)`: 强制将指定的页面标记为疏散候选。
   - `GrowNewSpace(Heap* heap)`: 增加新生代的大小。
   - `GrowNewSpaceToMaximumCapacity(Heap* heap)`: 将新生代增长到最大容量。

3. **辅助功能 (Utility Functions):**
   - `FixedArrayLenFromSize(int size)`: 根据给定大小计算 `FixedArray` 的长度。
   - `InCorrectGeneration(Tagged<HeapObject> object)`: 检查对象是否在预期的代中（取决于单代模式的标志）。

4. **作用域管理 (Scope Management):**
   - `ManualGCScope`: 一个 RAII 风格的作用域类，用于在测试期间禁用并发垃圾回收相关的标志，以确保测试的确定性。

**关于文件类型和 JavaScript 关系:**

-  **文件类型:** `v8/test/cctest/heap/heap-utils.cc` 的后缀是 `.cc`，这表明它是一个 **C++** 源代码文件，而不是 Torque 文件。如果它的后缀是 `.tq`，那才会是 V8 Torque 源代码。

- **与 JavaScript 的关系:**  虽然这个文件本身不是 JavaScript 代码，但它提供的工具函数直接影响 V8 执行 JavaScript 代码时的堆内存管理。JavaScript 对象被分配在 V8 的堆上，而这些工具函数可以控制堆的状态、触发垃圾回收等，从而帮助测试 V8 的堆管理机制是否正确。

**JavaScript 示例说明:**

```javascript
// 这是一个 JavaScript 的例子，展示了 V8 的堆内存分配和垃圾回收
let myObject = {}; // 创建一个对象，会在 V8 的堆上分配内存

function createManyObjects() {
  let objects = [];
  for (let i = 0; i < 10000; i++) {
    objects.push({ data: new Array(1000).fill(i) });
  }
  return objects; // 这些对象在函数结束后可能会变成垃圾，等待 GC 回收
}

let largeObjects = createManyObjects();

// 在 C++ 测试中，可以使用 heap-utils.cc 提供的函数来模拟 GC 的发生，
// 并检查 'largeObjects' 是否被正确回收。
```

在这个 JavaScript 例子中，`myObject` 和 `largeObjects` 都会在 V8 的堆上分配内存。`heap-utils.cc` 中的函数，如 `InvokeMajorGC` 和 `InvokeMinorGC`，可以在 C++ 测试中被调用，来触发 V8 的垃圾回收机制，从而测试 V8 是否能正确地回收不再使用的 JavaScript 对象所占用的内存。

**代码逻辑推理示例 (以 `FixedArrayLenFromSize` 为例):**

**假设输入:** `size = 100`

**代码逻辑:**

```c++
int FixedArrayLenFromSize(int size) {
  return std::min({(size - OFFSET_OF_DATA_START(FixedArray)) / kTaggedSize,
                   FixedArray::kMaxRegularLength});
}
```

- `OFFSET_OF_DATA_START(FixedArray)`: 获取 `FixedArray` 对象数据开始的偏移量。这是 `FixedArray` 元数据所占用的空间。
- `size - OFFSET_OF_DATA_START(FixedArray)`: 计算实际可用于存储数据的字节数。
- `/ kTaggedSize`: 将可用于存储数据的字节数除以一个指针的大小 (`kTaggedSize`)，得到可以存储多少个指针（即数组的长度）。
- `std::min({... , FixedArray::kMaxRegularLength})`: 确保计算出的长度不超过 `FixedArray` 的最大常规长度。

**假设输出:**  假设 `OFFSET_OF_DATA_START(FixedArray)` 为 8，`kTaggedSize` 为 8，`FixedArray::kMaxRegularLength` 为一个较大的值（例如 1024）。

`(100 - 8) / 8 = 92 / 8 = 11` (整数除法)

如果 11 小于 `FixedArray::kMaxRegularLength`，则函数返回 11。这意味着一个大小为 100 字节的分配可以创建一个长度为 11 的 `FixedArray`。

**用户常见的编程错误示例:**

与这个 `heap-utils.cc` 文件相关的常见编程错误通常发生在编写 V8 内部或者测试代码时，涉及到对堆内存的错误假设或操作：

1. **手动管理内存时的错误释放或内存泄漏:**  虽然 V8 的 GC 负责 JavaScript 对象的内存管理，但在编写 V8 内部的 C++ 代码时，如果涉及到非 V8 管理的内存，程序员需要手动 `delete` 或释放。忘记释放或重复释放会导致内存泄漏或程序崩溃。

   ```c++
   // 错误的示例 (V8 内部 C++ 代码)
   char* buffer = new char[1024];
   // ... 使用 buffer
   // 忘记 delete[] buffer;  // 内存泄漏
   ```

2. **对垃圾回收行为的错误假设:**  开发者可能会假设某个对象会被立即回收，从而在其被回收后尝试访问，导致悬挂指针。虽然 `heap-utils.cc` 提供了控制 GC 的能力，但在实际的 V8 运行环境中，GC 的时机是不确定的。

   ```javascript
   let obj = { data: new Array(1000000) };
   obj = null; // 使 obj 可以被回收
   // 错误地假设此时 obj 已经被回收，并在 C++ 测试中进行了某种基于此假设的检查。
   ```

3. **在并发环境中不正确地访问堆对象:**  V8 内部存在并发操作，例如并发标记。如果在没有适当的同步机制下，多个线程同时访问或修改堆对象，可能导致数据竞争和程序崩溃。

   ```c++
   // 错误的示例 (V8 内部 C++ 代码，假设存在并发)
   Tagged<HeapObject> shared_object;

   // 线程 1
   shared_object->DoSomething();

   // 线程 2
   shared_object->DoSomethingElse(); // 如果没有同步，可能导致问题
   ```

4. **使用已失效的句柄 (Handles):**  V8 使用句柄来安全地引用堆对象，防止对象在 GC 过程中被移动后指针失效。不正确地管理句柄的生命周期，例如在句柄的作用域之外使用句柄，会导致访问无效内存。

   ```c++
   void MyFunction(Isolate* isolate) {
     HandleScope handle_scope(isolate);
     Local<v8::Object> obj = v8::Object::New(isolate);
     Handle<v8::Object> handle_obj = Persistent<v8::Object>::New(isolate, obj);
   } // handle_obj (Persistent) 应该被正确管理，否则可能导致问题

   // 错误地在 MyFunction 外部使用可能已经失效的 handle_obj。
   ```

`v8/test/cctest/heap/heap-utils.cc` 提供的工具正是为了帮助测试 V8 的堆管理机制，确保能够避免和检测这些常见的编程错误。

### 提示词
```
这是目录为v8/test/cctest/heap/heap-utils.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/heap/heap-utils.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```