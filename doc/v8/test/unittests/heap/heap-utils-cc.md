Response:
Let's break down the thought process for analyzing the `heap-utils.cc` file.

1. **Understanding the Context:** The file is located in `v8/test/unittests/heap/`. This immediately tells us it's a utility file for *testing* the *heap* component of V8. The `.cc` extension confirms it's C++ source code.

2. **Initial Code Scan (Headers and Namespaces):**
   - `#include ...`:  Notice the inclusion of various V8 internal headers like `heap/gc-tracer-inl.h`, `heap/incremental-marking.h`, `heap/new-spaces.h`, etc. This reinforces the focus on heap-related functionalities.
   - `namespace v8 { namespace internal { ... } }`:  This signifies that the code provides internal utilities for the V8 engine itself, not for external use.

3. **Analyzing Individual Functions:**  Go through each function and understand its purpose.

   - **`SimulateIncrementalMarking`:** The name is self-explanatory. It simulates incremental marking, a garbage collection technique. The `force_completion` parameter suggests controlling whether the simulation runs to completion. The use of `kStepSize` implies simulating the advancement of the marking process in steps.

   - **Helper Functions (within anonymous namespace):**  The anonymous namespace suggests these functions are internal to the `heap-utils.cc` file and not meant for direct external use.
     - **`FixedArrayLenFromSize`:**  Calculates the length of a `FixedArray` given a byte size. It accounts for the header size and a maximum length.
     - **`FillPageInPagedSpace`:**  A complex function that fills a page in a paged space with `FixedArray` objects. Key details to note: it disables allocation observers, iterates through free list blocks, and allocates `FixedArray`s to fill the page. The goal is likely to create a "full" page for testing purposes.
     - **`CreatePadding`:** Allocates `FixedArray`s to consume a specified amount of memory (padding). This is useful for controlling memory layout during tests.
     - **`FillCurrentSemiSpacePage` and `FillCurrentPagedSpacePage`:** These seem to be specialized versions of filling pages, one for the semi-space (young generation) and the other for paged spaces.
     - **`FillCurrentPage`:** A dispatcher function that chooses the appropriate page-filling function based on the minor garbage collector configuration (`v8_flags.minor_ms`).

   - **`SimulateFullSpace` (overloaded):**  The name indicates that these functions simulate filling up memory spaces. The overloaded versions handle `NewSpace` (young generation) and `PagedSpace` (old generation). They use the page-filling functions internally. The check for `v8_flags.stress_concurrent_allocation` suggests that concurrent allocation could interfere with these simulations.

   - **`IsNewObjectInCorrectGeneration`:** Checks if a newly allocated object resides in the expected generation (young or old) based on the `single_generation` flag.

   - **`ManualGCScope`:** This looks like a RAII (Resource Acquisition Is Initialization) class. The constructor disables concurrent GC and related flags. The destructor restores the original flag values. This is crucial for isolating tests and preventing interference from background GC processes.

4. **Identifying Key Functionalities:** Based on the function analysis, the core functionalities are:
   - Simulating different phases of garbage collection (incremental marking).
   - Filling memory spaces (new and old generations) to create specific heap states for testing.
   - Providing a way to temporarily disable concurrent garbage collection during tests.
   - Utility functions for calculating `FixedArray` lengths and creating padding.

5. **Checking for `.tq` Extension:** The prompt specifically asks about a `.tq` extension. Since the file is `.cc`, it's *not* a Torque file. Torque files are typically used for defining built-in JavaScript functions or runtime functions in V8.

6. **Relating to JavaScript:** The functions directly manipulate V8's internal heap structures. While not directly writing JavaScript code, these utilities are essential for *testing* the parts of V8 that manage JavaScript objects in memory. The example of creating `FixedArray`s demonstrates how these internal structures are used to represent JavaScript arrays behind the scenes.

7. **Code Logic and Assumptions:**
   - **`SimulateIncrementalMarking`:** Assumes incremental marking is enabled. The `kStepSize` is an assumption about how the simulation proceeds.
   - **`FillPageInPagedSpace`:** Assumes the page is initially empty (sweeping is done). Relies on the free list structure of the paged space.
   - **`CreatePadding`:** Assumes allocation succeeds.
   - **`ManualGCScope`:** Assumes the flags being modified are relevant to the tests being run.

8. **Common Programming Errors:** The `ManualGCScope` is directly related to preventing common errors in *testing*. Without it, tests could have unpredictable behavior due to concurrent GC running in the background. This highlights the importance of controlling the environment in testing.

9. **Structuring the Answer:** Organize the findings logically:
   - Start with a high-level summary of the file's purpose.
   - List the key functionalities.
   - Address the `.tq` extension question.
   - Provide a JavaScript example to connect the C++ code to JavaScript concepts.
   - Give an example of code logic reasoning with assumptions.
   - Illustrate a common programming error related to the utilities.

This systematic approach ensures a comprehensive understanding of the `heap-utils.cc` file and addresses all aspects of the prompt.
`v8/test/unittests/heap/heap-utils.cc` 是一个 V8 (JavaScript 引擎) 的 C++ 源代码文件，位于单元测试的目录中，专门用于提供一些操作和模拟堆的实用工具函数，方便在堆相关的单元测试中使用。

**主要功能列举：**

1. **模拟增量标记 (SimulateIncrementalMarking):**
   - 功能：模拟堆的增量标记垃圾回收过程。增量标记是一种将标记过程分解为多个小步骤执行的 GC 策略，避免长时间暂停。
   - 用途：允许测试在增量标记的不同阶段验证堆的状态。
   - 参数：
     - `Heap* heap`:  指向要操作的堆的指针。
     - `bool force_completion`:  一个布尔值，指示是否强制完成整个增量标记过程。
   - 代码逻辑推理：
     - 假设输入：一个正在运行的 V8 堆，并且启用了增量标记 (`v8_flags.incremental_marking` 为 true)。
     - 如果 `force_completion` 为 false，则函数会启动增量标记（如果尚未启动）并返回，允许测试在标记进行中检查状态。
     - 如果 `force_completion` 为 true，则函数会循环调用 `marking->AdvanceForTesting(kStepSize)`，模拟增量标记的推进，直到标记完成。
   - 与 JavaScript 的关系：增量标记是 V8 执行垃圾回收的关键部分，直接影响 JavaScript 程序的性能和内存管理。尽管这个 C++ 文件不包含 JavaScript 代码，但它的功能是为了测试 V8 如何管理 JavaScript 对象的内存。

2. **填充空间 (SimulateFullSpace):**
   - 功能：将指定的堆空间（NewSpace 或 PagedSpace）填充到接近满的状态，主要通过分配 `FixedArray` 对象。
   - 用途：方便测试在堆空间接近满时 V8 的行为，例如触发垃圾回收。
   - 参数：
     - 针对 NewSpace：`v8::internal::NewSpace* space`, `std::vector<Handle<FixedArray>>* out_handles` (可选，用于保存分配的对象的句柄)。
     - 针对 PagedSpace：`v8::internal::PagedSpace* space`。
   - 代码逻辑推理（以填充 PagedSpace 为例）：
     - 假设输入：一个指向 `PagedSpace` 的指针。
     - 函数会重置空间的空闲列表 (`space->ResetFreeList()`)，有效地让空间看起来是空的，然后后续的分配会逐渐填充它。
   - 与 JavaScript 的关系：JavaScript 对象的分配发生在这些堆空间中。填充空间会模拟 JavaScript 程序运行一段时间后，堆内存被大量对象占据的情况。

3. **填充当前页 (FillCurrentPage):**
   - 功能：填充当前 NewSpace 中的活动页。
   - 用途：更精细地控制 NewSpace 的状态，用于特定场景的测试。
   - 参数：`v8::internal::NewSpace* space`, `std::vector<Handle<FixedArray>>* out_handles` (可选)。

4. **创建填充 (CreatePadding):**
   - 功能：在堆中分配指定大小的填充对象 (`FixedArray`)。
   - 用途：在堆中创建特定大小的空洞或预留空间，方便测试内存布局和分配策略。
   - 参数：`Heap* heap`, `int padding_size`, `AllocationType allocation` (指定在老年代还是新生代分配)。
   - 代码逻辑推理：
     - 假设输入：一个堆指针，需要填充的字节大小，以及分配类型。
     - 函数会循环分配 `FixedArray`，直到分配的内存总和接近或等于 `padding_size`。如果剩余空间不足以分配一个完整的 `FixedArray`，会创建一个填充对象 (filler object)。
   - 与 JavaScript 的关系：虽然直接操作的是 `FixedArray`，但其目的是模拟 JavaScript 对象的内存占用。

5. **判断新对象是否在正确的代 (IsNewObjectInCorrectGeneration):**
   - 功能：检查新分配的对象是否位于预期的内存代（新生代或老年代）。
   - 用途：验证对象的分配策略是否正确。
   - 参数：`Tagged<HeapObject> object`。
   - 代码逻辑推理：
     - 函数根据 `v8_flags.single_generation` 标志来判断。如果启用了单代 GC，则所有对象都应在老年代；否则，新分配的对象应在新生代。

6. **手动 GC 作用域 (ManualGCScope):**
   - 功能：提供一个 RAII (Resource Acquisition Is Initialization) 风格的作用域，用于在测试期间禁用并发垃圾回收相关的标志。
   - 用途：确保测试的执行不会受到后台 GC 的干扰，使测试结果更可预测和可靠。
   - 机制：在构造函数中保存并禁用相关的全局标志（如 `concurrent_marking`、`concurrent_sweeping` 等），在析构函数中恢复这些标志的原始值。
   - 与 JavaScript 的关系：虽然不直接涉及 JavaScript 代码，但它确保了与垃圾回收机制相关的测试能够在一个受控的环境中运行，这对于保证 JavaScript 程序的稳定性和性能至关重要。

**关于 `.tq` 结尾：**

如果 `v8/test/unittests/heap/heap-utils.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是一种 V8 自研的类型化的中间语言，用于定义内置的 JavaScript 函数和运行时函数。`.tq` 文件会被编译成 C++ 代码。

**由于该文件名为 `.cc`，所以它是一个 C++ 源代码文件，而不是 Torque 文件。**

**与 JavaScript 功能的关系及示例：**

虽然 `heap-utils.cc` 是 C++ 代码，但其目的是为了测试 V8 的堆管理，这直接关系到 JavaScript 对象的生命周期和内存管理。

**示例：**

假设我们想测试在新生代空间接近满时分配新 JavaScript 对象会发生什么。我们可以使用 `SimulateFullSpace` 来填充新生代，然后尝试分配一个新的对象。

```cpp
// 假设在某个单元测试中
TEST_F(MyHeapTest, AllocationNearFullNewSpace) {
  // ... 初始化 Isolate 和 Heap ...

  Heap* heap = isolate()->heap();
  NewSpace* new_space = heap->new_space();

  // 填充新生代空间
  HeapInternalsBase::SimulateFullSpace(new_space);

  // 尝试分配一个新的 JavaScript 对象 (例如一个空对象)
  Local<Context> context = Context::New(isolate());
  Context::Scope context_scope(context);
  HandleScope handle_scope(isolate());

  TryCatch try_catch(isolate());
  Local<Object> obj = Object::New(isolate());

  // 断言分配是否成功，或者是否触发了 GC
  if (obj.IsEmpty()) {
    // 分配失败，可能触发了 GC
    EXPECT_TRUE(heap->gc_in_progress());
  } else {
    // 分配成功
    EXPECT_TRUE(new_space->Contains(*Utils::OpenHandle(*obj)));
  }

  // ... 清理 ...
}
```

在这个测试中，`SimulateFullSpace` 模拟了新生代空间被大量 JavaScript 对象占据的情况，然后我们尝试分配一个新的 JavaScript 对象。测试的目标是验证 V8 在这种内存压力下的行为是否符合预期（例如，是否触发了 Minor GC）。

**代码逻辑推理的假设输入与输出示例：**

**函数：`FixedArrayLenFromSize(int size)`**

* **假设输入：** `size = 24` (字节)
* **输出：** 这取决于 `OFFSET_OF_DATA_START(FixedArray)` 和 `kTaggedSize` 的值。假设 `OFFSET_OF_DATA_START(FixedArray) = 8`，`kTaggedSize = 8`。
   * `(size - OFFSET_OF_DATA_START(FixedArray))` = `24 - 8` = `16`
   * `16 / kTaggedSize` = `16 / 8` = `2`
   * 如果 `2` 小于 `FixedArray::kMaxRegularLength`，则输出为 `2`。
* **功能解释：** 此函数计算给定字节大小可以容纳的 `FixedArray` 的长度（以槽位计）。

**涉及用户常见的编程错误（在测试场景中模拟）：**

虽然 `heap-utils.cc` 本身是测试工具，但它帮助 V8 开发者测试 V8 引擎对各种内存管理场景的健壮性，其中也包括模拟一些可能导致问题的场景。

**示例：内存泄漏**

假设 V8 的某个部分存在内存泄漏，即对象被错误地保持引用，导致 GC 无法回收。我们可以编写一个单元测试，使用 `heap-utils.cc` 的功能来模拟这种情况：

1. **分配一些 JavaScript 对象。**
2. **人为地创建一些强引用，阻止这些对象被回收。**
3. **多次触发垃圾回收（可以使用 V8 提供的 API 或模拟 GC 步骤）。**
4. **检查堆的大小，如果存在泄漏，堆的大小会持续增长。**

`ManualGCScope` 对于编写这类测试至关重要，因为它可以避免并发 GC 的干扰，让测试结果更加可控。

**总结：**

`v8/test/unittests/heap/heap-utils.cc` 是一个用于 V8 堆单元测试的关键工具集，它提供了模拟各种堆状态和 GC 行为的功能，帮助开发者测试 V8 引擎的内存管理机制是否正确可靠。虽然它是 C++ 代码，但其功能直接关系到 JavaScript 程序的内存管理和性能。

### 提示词
```
这是目录为v8/test/unittests/heap/heap-utils.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/heap-utils.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/unittests/heap/heap-utils.h"

#include <algorithm>

#include "src/common/globals.h"
#include "src/flags/flags.h"
#include "src/heap/gc-tracer-inl.h"
#include "src/heap/incremental-marking.h"
#include "src/heap/mark-compact.h"
#include "src/heap/new-spaces.h"
#include "src/heap/page-metadata-inl.h"
#include "src/heap/safepoint.h"
#include "src/objects/free-space-inl.h"

namespace v8 {
namespace internal {

void HeapInternalsBase::SimulateIncrementalMarking(Heap* heap,
                                                   bool force_completion) {
  static constexpr auto kStepSize = v8::base::TimeDelta::FromMilliseconds(100);
  CHECK(v8_flags.incremental_marking);
  i::IncrementalMarking* marking = heap->incremental_marking();

  if (heap->sweeping_in_progress()) {
    IsolateSafepointScope scope(heap);
    heap->EnsureSweepingCompleted(
        Heap::SweepingForcedFinalizationMode::kV8Only);
  }

  if (marking->IsStopped()) {
    heap->StartIncrementalMarking(i::GCFlag::kNoFlags,
                                  i::GarbageCollectionReason::kTesting);
  }
  CHECK(marking->IsMajorMarking());
  if (!force_completion) return;

  while (!marking->IsMajorMarkingComplete()) {
    marking->AdvanceForTesting(kStepSize);
  }
}

namespace {

int FixedArrayLenFromSize(int size) {
  return std::min({(size - OFFSET_OF_DATA_START(FixedArray)) / kTaggedSize,
                   FixedArray::kMaxRegularLength});
}

void FillPageInPagedSpace(PageMetadata* page,
                          std::vector<Handle<FixedArray>>* out_handles) {
  Heap* heap = page->heap();
  ManualGCScope manual_gc_scope(heap->isolate());
  DCHECK(page->SweepingDone());
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

  Isolate* isolate = heap->isolate();

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

void HeapInternalsBase::SimulateFullSpace(
    v8::internal::NewSpace* space,
    std::vector<Handle<FixedArray>>* out_handles) {
  Heap* heap = space->heap();
  IsolateSafepointScope safepoint_scope(heap);
  heap->FreeLinearAllocationAreas();
  // If you see this check failing, disable the flag at the start of your test:
  // v8_flags.stress_concurrent_allocation = false;
  // Background thread allocating concurrently interferes with this function.
  CHECK(!v8_flags.stress_concurrent_allocation);
  space->heap()->EnsureSweepingCompleted(
      Heap::SweepingForcedFinalizationMode::kV8Only);
  if (v8_flags.minor_ms) {
    auto* space = heap->paged_new_space()->paged_space();
    space->AllocatePageUpToCapacityForTesting();
    for (PageMetadata* page : *space) {
      FillPageInPagedSpace(page, out_handles);
    }
    DCHECK_IMPLIES(space->free_list(), space->free_list()->Available() == 0);
  } else {
    SemiSpaceNewSpace* space = SemiSpaceNewSpace::From(heap->new_space());
    do {
      FillCurrentPage(space, out_handles);
    } while (space->AddFreshPage());
  }
}

void HeapInternalsBase::SimulateFullSpace(v8::internal::PagedSpace* space) {
  Heap* heap = space->heap();
  IsolateSafepointScope safepoint_scope(heap);
  heap->FreeLinearAllocationAreas();
  // If you see this check failing, disable the flag at the start of your test:
  // v8_flags.stress_concurrent_allocation = false;
  // Background thread allocating concurrently interferes with this function.
  CHECK(!v8_flags.stress_concurrent_allocation);
  if (heap->sweeping_in_progress()) {
    heap->EnsureSweepingCompleted(
        Heap::SweepingForcedFinalizationMode::kV8Only);
  }
  space->ResetFreeList();
}

namespace {
std::vector<Handle<FixedArray>> CreatePadding(Heap* heap, int padding_size,
                                              AllocationType allocation) {
  std::vector<Handle<FixedArray>> handles;
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
    if (free_memory > kMaxRegularHeapObjectSize) {
      allocate_memory = kMaxRegularHeapObjectSize;
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
    handles.push_back(isolate->factory()->NewFixedArray(length, allocation));
    CHECK((allocation == AllocationType::kYoung &&
           heap->new_space()->Contains(*handles.back())) ||
          (allocation == AllocationType::kOld &&
           heap->InOldSpace(*handles.back())) ||
          v8_flags.single_generation);
    free_memory -= handles.back()->Size();
  }
  return handles;
}

void FillCurrentSemiSpacePage(v8::internal::SemiSpaceNewSpace* space,
                              std::vector<Handle<FixedArray>>* out_handles) {
  // We cannot rely on `space->limit()` to point to the end of the current page
  // in the case where inline allocations are disabled, it actually points to
  // the current allocation pointer.
  DCHECK_IMPLIES(
      !space->heap()->IsInlineAllocationEnabled(),
      space->heap()->NewSpaceTop() == space->heap()->NewSpaceLimit());

  int space_remaining = space->GetSpaceRemainingOnCurrentPageForTesting();
  if (space_remaining == 0) return;
  std::vector<Handle<FixedArray>> handles =
      CreatePadding(space->heap(), space_remaining, i::AllocationType::kYoung);
  if (out_handles != nullptr) {
    out_handles->insert(out_handles->end(), handles.begin(), handles.end());
  }
}

void FillCurrentPagedSpacePage(v8::internal::NewSpace* space,
                               std::vector<Handle<FixedArray>>* out_handles) {
  const Address top = space->heap()->NewSpaceTop();
  if (top == kNullAddress) return;
  PageMetadata* page = PageMetadata::FromAllocationAreaAddress(top);
  space->heap()->EnsureSweepingCompleted(
      Heap::SweepingForcedFinalizationMode::kV8Only);
  FillPageInPagedSpace(page, out_handles);
}

}  // namespace

void HeapInternalsBase::FillCurrentPage(
    v8::internal::NewSpace* space,
    std::vector<Handle<FixedArray>>* out_handles) {
  PauseAllocationObserversScope pause_observers(space->heap());
  MainAllocator* allocator = space->heap()->allocator()->new_space_allocator();
  allocator->FreeLinearAllocationArea();
  if (v8_flags.minor_ms) {
    FillCurrentPagedSpacePage(space, out_handles);
  } else {
    FillCurrentSemiSpacePage(SemiSpaceNewSpace::From(space), out_handles);
  }
  allocator->FreeLinearAllocationArea();
}

bool IsNewObjectInCorrectGeneration(Tagged<HeapObject> object) {
  return v8_flags.single_generation ? !i::HeapLayout::InYoungGeneration(object)
                                    : i::HeapLayout::InYoungGeneration(object);
}

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
      InvokeAtomicMajorGC(isolate);
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