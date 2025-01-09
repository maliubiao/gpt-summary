Response:
Let's break down the thought process for analyzing this C++ code snippet.

**1. Initial Skim and Keywords:**

The first step is a quick skim to get a general sense of the code. I'm looking for keywords related to memory management, garbage collection, and heap organization. Keywords like `SemiSpace`, `PageMetadata`, `MemoryChunk`, `Allocate`, `Free`, `Commit`, `Uncommit`, `Reset`, `Grow`, `Shrink`, `Heap`, `GC`, and `Iterator` jump out. The comments at the beginning also explicitly mention "heap" and "new spaces."

**2. Identifying the Core Data Structures:**

The presence of classes like `SemiSpace` and `SemiSpaceNewSpace` (and later `PagedSpaceForNewSpace`) strongly suggests these are the fundamental building blocks. I start to form a mental model of their relationships:

* **`SemiSpace`:** Seems to represent one of the two halves of a new generation space (the "from" and "to" spaces). It manages a list of pages.
* **`SemiSpaceNewSpace`:** Likely manages the pair of `SemiSpace` instances, coordinating their behavior during garbage collection.
* **`PageMetadata`:**  Represents metadata associated with a memory page.
* **`MemoryChunk`:**  A larger unit of memory that contains one or more pages.

**3. Understanding `SemiSpace` Functionality:**

I go through the methods of `SemiSpace` and try to understand their purpose:

* **`InitializePage`:** Sets up a new page, marking it as either "from" or "to" space.
* **`EnsureCurrentCapacity`:** Manages the number of committed pages to match the target capacity, adding or removing pages as needed. This involves interacting with the `MemoryAllocator`.
* **`Commit`:**  Makes the semi-space usable by allocating and initializing a set of pages.
* **`Uncommit`:** Releases the memory held by the semi-space.
* **`GrowTo` and `ShrinkTo`:** Change the target capacity of the semi-space, adding or removing pages.
* **`AllocateFreshPage` and `RewindPages`:**  Helper functions for growing and shrinking.
* **`FixPagesFlags`:** Sets flags on the pages based on whether it's a "from" or "to" space.
* **`Reset`:**  Resets the allocation pointer within the semi-space.
* **`RemovePage` and `PrependPage`:**  Modify the list of pages.
* **`MovePageToTheEnd`:** Moves a page to the end of the list.
* **`Swap`:**  Exchanges the contents of two `SemiSpace` objects, a key operation in garbage collection.
* **`set_age_mark`:** Sets a boundary within the "from" space to differentiate between older and newer objects.

**4. Understanding `SemiSpaceNewSpace` Functionality:**

I analyze the methods of `SemiSpaceNewSpace`:

* **Constructor:** Initializes the "to" space and leaves the "from" space uncommitted.
* **`Grow` and `Shrink`:**  Manage the overall capacity of the new space by adjusting the capacities of the "from" and "to" spaces.
* **`set_age_mark_to_top`:** Sets the age mark to the current allocation top.
* **`ResetCurrentSpace`:**  Resets the "to" space for a new allocation phase.
* **`AddFreshPage`:** Allocates a new page in the "to" space.
* **`AllocateOnNewPageBeyondCapacity`:** Handles allocation when the current page is full, potentially growing the space.
* **`AddParkedAllocationBuffer` and `ResetParkedAllocationBuffers`:** Seems like an optimization for handling unused space on pages.
* **`FillCurrentPageForTesting`:** Fills the remaining space on the current page (likely for testing).
* **`Verify` and `VerifyObjects`:**  Functions for checking the integrity of the new space (debugging/testing).
* **`MakeIterable` and related methods:** Prepares the spaces for garbage collection by filling unused portions.
* **`ShouldBePromoted`:** Determines if an object should be moved to the old generation during garbage collection.
* **`GetObjectIterator`:** Provides a way to iterate over the objects in the new space.
* **`ContainsSlow`:** Checks if an address belongs to the new space.
* **`Size`:**  Calculates the used space within the new space.
* **`AllocatedSinceLastGC`:** Tracks how much memory has been allocated since the last garbage collection.
* **`GarbageCollectionPrologue`, `EvacuatePrologue`, `GarbageCollectionEpilogue`:**  Lifecycle methods related to the garbage collection process, coordinating the flipping of spaces.
* **`ZapUnusedMemory`:** Fills unused memory with a specific value (for debugging or security).
* **`Allocate`:**  The core allocation function for the new space.
* **`Free`:**  Simulates freeing memory by filling it.
* **`CreateAllocatorPolicy`:** Creates an allocator policy specific to the new space.

**5. Connecting to JavaScript (Conceptual):**

I think about how this low-level memory management relates to JavaScript. The new space is where recently created objects reside. When you create objects in JavaScript, like:

```javascript
let obj = {};
let arr = [];
let str = "hello";
```

These objects are initially allocated in the new space. The garbage collector then manages the lifecycle of these objects, moving them between the "from" and "to" spaces (evacuation) and eventually promoting them to the old generation if they survive multiple garbage collection cycles.

**6. Code Logic and Assumptions:**

I look for specific logic patterns, like the page management in `EnsureCurrentCapacity` or the space swapping in `SemiSpaceNewSpace::EvacuatePrologue`. I consider the assumptions being made, like the alignment of memory and the size of pages.

**7. Common Programming Errors (Conceptual):**

I think about how errors at this low level might manifest in JavaScript. Memory leaks (objects not being garbage collected) could be related to issues in the garbage collection logic implemented in these files (though this file focuses more on space management). Segmentation faults or crashes could occur if there are bugs in memory allocation or deallocation.

**8. Torque Consideration:**

The prompt mentions `.tq` files. Since this file is `.cc`, I know it's standard C++. If it *were* `.tq`, I'd be looking for specific Torque syntax and how it generates C++ code for more type-safe operations.

**9. Summarization:**

Finally, I synthesize the information gathered into a concise summary of the file's purpose, highlighting the key functionalities and relationships between the classes. I organize the information into logical categories (core functions, garbage collection, etc.) for clarity.

This iterative process of skimming, identifying core structures, understanding individual components, connecting to higher-level concepts, and summarizing is crucial for making sense of complex code like this.
这是v8/src/heap/new-spaces.cc源代码的功能归纳：

**总体功能:**

`v8/src/heap/new-spaces.cc` 实现了 V8 引擎中用于管理新生代堆内存空间（New Space）的核心逻辑。新生代是 V8 垃圾回收机制中用于存放新创建的短期存活对象的区域。 这个文件定义了 `SemiSpace` 和 `SemiSpaceNewSpace` 类，负责新生代的内存分配、管理和垃圾回收相关的操作。

**`SemiSpace` 类功能:**

`SemiSpace` 代表新生代的一个半区（From Space 或 To Space）。新生代采用复制式垃圾回收算法，需要两个这样的半区。`SemiSpace` 负责管理一个半区的内存页，并提供以下功能：

* **页面初始化 (`InitializePage`)**:  设置页面的元数据，标记为 From Page 或 To Page。
* **确保当前容量 (`EnsureCurrentCapacity`)**:  根据目标容量动态调整已提交的内存页数量，可以增加或减少页面。
* **提交内存 (`Commit`)**:  为半区分配并初始化内存页，使其可以用于分配对象。
* **取消提交内存 (`Uncommit`)**:  释放半区占用的内存。
* **增加容量 (`GrowTo`)**:  扩展半区的容量，增加新的内存页。
* **缩小容量 (`ShrinkTo`)**:  缩小半区的容量，释放多余的内存页。
* **分配新的页面 (`AllocateFreshPage`)**:  从内存分配器中分配一个新的页面给半区。
* **回退页面 (`RewindPages`)**:  移除半区末尾的若干个页面。
* **修复页面标志 (`FixPagesFlags`)**:  设置半区内页面的标志，例如标记为 From Space 或 To Space。
* **重置 (`Reset`)**:  将半区的分配指针重置到起始位置。
* **移除页面 (`RemovePage`)**:  从半区中移除一个页面。
* **前置页面 (`PrependPage`)**:  在半区开头添加一个页面。
* **将页面移到末尾 (`MovePageToTheEnd`)**:  将指定页面移动到半区的末尾。
* **交换 (`Swap`)**:  交换两个 `SemiSpace` 对象的所有属性（除了 ID），这是垃圾回收中 From Space 和 To Space 切换的关键操作。
* **管理已提交的物理内存 (`IncrementCommittedPhysicalMemory`, `DecrementCommittedPhysicalMemory`)**:  跟踪实际提交的物理内存。
* **添加活动系统页范围 (`AddRangeToActiveSystemPages`)**:  记录已使用的系统页面范围。
* **设置年龄标记 (`set_age_mark`)**:  在 From Space 中设置一个年龄标记，用于判断对象是否应该晋升到老年代。
* **获取对象迭代器 (`GetObjectIterator`)**:  提供遍历半区内对象的迭代器（在 `SemiSpace` 类中是 `UNREACHABLE()`，实际由 `SemiSpaceNewSpace` 实现）。
* **打印和验证 (DEBUG/VERIFY_HEAP)**:  提供调试和验证功能。
* **断言有效范围 (`AssertValidRange` - DEBUG)**:  在调试模式下断言地址范围的有效性。

**`SemiSpaceNewSpace` 类功能:**

`SemiSpaceNewSpace` 类负责管理整个新生代，包含两个 `SemiSpace` 对象（From Space 和 To Space），并协调它们的行为以实现复制式垃圾回收：

* **初始化 (`SemiSpaceNewSpace`)**:  创建和初始化 From Space 和 To Space。
* **增长 (`Grow`)**:  当空间不足时，增加新生代的总容量。
* **设置年龄标记到顶部 (`set_age_mark_to_top`)**:  将年龄标记设置为当前分配指针的位置。
* **收缩 (`Shrink`)**:  在垃圾回收后，缩小新生代的容量。
* **获取已提交的物理内存 (`CommittedPhysicalMemory`)**:  返回新生代已提交的物理内存大小。
* **确保当前容量 (`EnsureCurrentCapacity`)**:  确保 From Space 和 To Space 都具有足够的容量。
* **重置当前空间 (`ResetCurrentSpace`)**:  在垃圾回收后，重置 To Space 以供新的分配。
* **添加新的页面 (`AddFreshPage`)**:  在 To Space 中分配一个新的页面。
* **在超出容量的新页面上分配 (`AllocateOnNewPageBeyondCapacity`)**: 当当前页面已满且需要分配时，分配一个新的页面。
* **添加/重置停放的分配缓冲区 (`AddParkedAllocationBuffer`, `ResetParkedAllocationBuffers`)**:  管理和重用页面上未使用的空间，可能是一种优化策略。
* **填充当前页面用于测试 (`FillCurrentPageForTesting`)**:  用于测试，填充当前页面的剩余空间。
* **验证 (`Verify`, `VerifyObjects` - VERIFY_HEAP)**:  提供新生代状态的验证功能。
* **使可迭代 (`MakeIterable`, `MakeAllPagesInFromSpaceIterable`, `MakeUnusedPagesInToSpaceIterable`)**:  在垃圾回收过程中，将新生代中所有的对象都标记为可遍历，以便进行垃圾回收。
* **判断是否应该晋升 (`ShouldBePromoted`)**:  根据对象的地址和年龄标记判断对象是否应该晋升到老年代。
* **获取对象迭代器 (`GetObjectIterator`)**:  返回一个用于遍历新生代中所有存活对象的迭代器。
* **判断是否包含地址 (`ContainsSlow`)**:  判断给定的地址是否属于新生代。
* **获取大小 (`Size`)**:  返回新生代当前已使用的大小。
* **获取自上次 GC 以来的分配量 (`AllocatedSinceLastGC`)**:  跟踪自上次垃圾回收以来分配的内存量。
* **垃圾回收序言/尾声 (`GarbageCollectionPrologue`, `EvacuatePrologue`, `GarbageCollectionEpilogue`)**:  在垃圾回收的不同阶段执行必要的准备和清理工作，例如 From Space 和 To Space 的切换。
* **擦除未使用的内存 (`ZapUnusedMemory`)**:  在垃圾回收后，用特定值填充未使用的内存区域。
* **移除页面 (`RemovePage`)**:  从 From Space 中移除一个页面。
* **判断是否是晋升候选者 (`IsPromotionCandidate`)**:  判断页面是否是晋升到老年代的候选者。
* **分配内存 (`Allocate`)**:  在 To Space 中分配指定大小的内存。
* **释放内存 (`Free`)**:  在新生代中标记一块内存为空闲（通过填充）。
* **创建分配器策略 (`CreateAllocatorPolicy`)**:  为新生代创建一个特定的分配器策略。

**`PagedSpaceForNewSpace` 类功能:**

`PagedSpaceForNewSpace`  看起来是另一种管理新生代的方式，它基于 `PagedSpaceBase`，采用了更细粒度的页面管理，并使用了空闲列表 (`FreeList`) 来跟踪可用的内存块。

* **初始化 (`PagedSpaceForNewSpace`)**: 初始化基于页面的新生代空间。
* **页面初始化 (`InitializePage`)**: 设置页面的元数据，并初始化页面的空闲列表。

**关于 .tq 结尾：**

根据您的描述，如果 `v8/src/heap/new-spaces.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。 Torque 是一种 V8 自研的类型安全的领域特定语言，用于生成高效的 C++ 代码。 然而，当前提供的代码是以 `.cc` 结尾，所以它是标准的 C++ 代码。

**与 JavaScript 的关系及示例：**

新生代内存空间直接服务于 JavaScript 对象的分配。 当你在 JavaScript 中创建新的对象、数组或字符串时，V8 引擎通常会在新生代中为它们分配内存。

```javascript
// JavaScript 示例

let obj = {}; // 新对象会被分配到新生代
let arr = [1, 2, 3]; // 新数组会被分配到新生代
let str = "hello"; // 新字符串会被分配到新生代

function createObject() {
  return { data: Math.random() }; // 每次调用都会在新生代分配新对象
}

for (let i = 0; i < 1000; i++) {
  createObject(); // 持续创建短期对象，填充新生代
}
```

在这个例子中，每次执行 `let obj = {}` 等操作，V8 内部就会调用类似于 `SemiSpaceNewSpace::Allocate` 这样的函数，在 To Space 中分配内存来存储这些 JavaScript 对象。

**代码逻辑推理与假设：**

**假设输入：**
1. `SemiSpaceNewSpace` 的 `Allocate(100, kWordAligned)` 被调用，请求分配 100 字节的字对齐内存。
2. To Space 当前页面剩余空间足够容纳 100 字节。

**预期输出：**
1. `Allocate` 函数会计算出合适的起始地址 `start` 和结束地址 `end`。
2. `allocation_top()` 会增加 100 字节。
3. 返回一个包含 `start` 和 `end` 的 `std::optional<std::pair<Address, Address>>`。

**假设输入：**
1. `SemiSpaceNewSpace` 的 `Allocate(10000, kWordAligned)` 被调用，请求分配 10000 字节的字对齐内存。
2. To Space 当前页面剩余空间不足。

**预期输出：**
1. `Allocate` 会先在当前页面填充垃圾。
2. 尝试分配新的页面。
3. 如果成功分配新页面，则在新页面上分配 10000 字节，并更新 `allocation_top()`。
4. 如果分配新页面失败（例如，达到最大容量），则返回 `std::nullopt`。

**用户常见的编程错误（与新生代管理间接相关）：**

虽然用户通常不直接操作这些底层的内存管理代码，但 JavaScript 中的某些编程模式可能会影响新生代的压力和垃圾回收效率：

1. **频繁创建短期对象：** 在循环或高频调用的函数中创建大量生命周期很短的对象，会导致新生代迅速被填满，触发频繁的 Minor GC。

    ```javascript
    // 不推荐：频繁创建对象
    function processData(data) {
      for (let item of data) {
        let temp = { value: item * 2 }; // 每次循环都创建新对象
        // ... 对 temp 进行操作
      }
    }
    ```

2. **闭包引用导致意外的长期存活：**  闭包意外地捕获了本应是短期存活的对象，导致这些对象无法被新生代 GC 回收，最终晋升到老年代，可能引发内存泄漏。

    ```javascript
    function createHandler() {
      let data = { large: '...' }; // 本应是局部变量
      return function() {
        console.log(data.large); // 闭包引用了 data，可能导致 data 长期存活
      };
    }

    let handler = createHandler();
    // ... 如果 handler 一直存在，data 也不会被回收
    ```

**总结 `v8/src/heap/new-spaces.cc` 的功能 (第 1 部分):**

`v8/src/heap/new-spaces.cc` 的第 1 部分主要定义了管理 V8 引擎新生代内存空间的两个核心类：`SemiSpace` 和 `SemiSpaceNewSpace`。

*   **`SemiSpace` 负责管理新生代的一个半区（From Space 或 To Space）的内存页，** 提供页面初始化、容量管理（增长、收缩）、内存提交与取消提交、页面分配与移除、标志设置、状态重置以及半区间的交换等基本操作。

*   **`SemiSpaceNewSpace` 负责管理整个新生代，包含两个 `SemiSpace` 对象，** 并协调它们的行为以实现复制式垃圾回收。它提供了新生代的整体容量管理、对象分配、年龄标记设置、垃圾回收相关的序言和尾声处理、以及与对象迭代和内存验证相关的功能。

这段代码是 V8 引擎高效管理短期存活对象、实现快速垃圾回收的关键组成部分。 它体现了 V8 在内存管理方面的精细设计和优化。

Prompt: 
```
这是目录为v8/src/heap/new-spaces.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/new-spaces.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/new-spaces.h"

#include <atomic>
#include <optional>

#include "src/common/globals.h"
#include "src/heap/allocation-observer.h"
#include "src/heap/array-buffer-sweeper.h"
#include "src/heap/concurrent-marking.h"
#include "src/heap/free-list-inl.h"
#include "src/heap/gc-tracer-inl.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap-verifier.h"
#include "src/heap/incremental-marking.h"
#include "src/heap/mark-compact.h"
#include "src/heap/marking-state-inl.h"
#include "src/heap/marking-state.h"
#include "src/heap/memory-allocator.h"
#include "src/heap/memory-chunk.h"
#include "src/heap/page-metadata-inl.h"
#include "src/heap/paged-spaces.h"
#include "src/heap/safepoint.h"
#include "src/heap/spaces-inl.h"
#include "src/heap/spaces.h"
#include "src/heap/zapping.h"

namespace v8 {
namespace internal {

PageMetadata* SemiSpace::InitializePage(MutablePageMetadata* mutable_page) {
  bool in_to_space = (id() != kFromSpace);
  MemoryChunk* chunk = mutable_page->Chunk();
  chunk->SetFlagNonExecutable(in_to_space ? MemoryChunk::TO_PAGE
                                          : MemoryChunk::FROM_PAGE);
  PageMetadata* page = PageMetadata::cast(mutable_page);
  page->list_node().Initialize();
  if (v8_flags.minor_ms) {
    page->ClearLiveness();
  }
  chunk->InitializationMemoryFence();
  return page;
}

bool SemiSpace::EnsureCurrentCapacity() {
  if (IsCommitted()) {
    const int expected_pages =
        static_cast<int>(target_capacity_ / PageMetadata::kPageSize);
    // `target_capacity_` is a multiple of `PageMetadata::kPageSize`.
    DCHECK_EQ(target_capacity_, expected_pages * PageMetadata::kPageSize);
    MutablePageMetadata* current_page = first_page();
    int actual_pages = 0;

    // First iterate through the pages list until expected pages if so many
    // pages exist.
    while (current_page != nullptr && actual_pages < expected_pages) {
      actual_pages++;
      current_page = current_page->list_node().next();
    }

    DCHECK_LE(actual_pages, expected_pages);

    // Free all overallocated pages which are behind current_page.
    while (current_page) {
      DCHECK_EQ(actual_pages, expected_pages);
      MutablePageMetadata* next_current = current_page->list_node().next();
      // `current_page_` contains the current allocation area. Thus, we should
      // never free the `current_page_`. Furthermore, live objects generally
      // reside before the current allocation area, so `current_page_` also
      // serves as a guard against freeing pages with live objects on them.
      DCHECK_IMPLIES(id() == SemiSpaceId::kToSpace,
                     current_page != current_page_);
      AccountUncommitted(PageMetadata::kPageSize);
      DecrementCommittedPhysicalMemory(current_page->CommittedPhysicalMemory());
      memory_chunk_list_.Remove(current_page);
      // Clear new space flags to avoid this page being treated as a new
      // space page that is potentially being swept.
      current_page->Chunk()->ClearFlagsNonExecutable(
          MemoryChunk::kIsInYoungGenerationMask);
      heap()->memory_allocator()->Free(MemoryAllocator::FreeMode::kPool,
                                       current_page);
      current_page = next_current;
    }

    // Add more pages if we have less than expected_pages.
    while (actual_pages < expected_pages) {
      actual_pages++;
      current_page = heap()->memory_allocator()->AllocatePage(
          MemoryAllocator::AllocationMode::kUsePool, this, NOT_EXECUTABLE);
      if (current_page == nullptr) return false;
      DCHECK_NOT_NULL(current_page);
      AccountCommitted(PageMetadata::kPageSize);
      IncrementCommittedPhysicalMemory(current_page->CommittedPhysicalMemory());
      memory_chunk_list_.PushBack(current_page);
      current_page->ClearLiveness();
      current_page->Chunk()->SetFlagsNonExecutable(
          first_page()->Chunk()->GetFlags());
      heap()->CreateFillerObjectAt(current_page->area_start(),
                                   static_cast<int>(current_page->area_size()));
    }
    DCHECK_EQ(expected_pages, actual_pages);
  }
  allow_to_grow_beyond_capacity_ = false;
  return true;
}

// -----------------------------------------------------------------------------
// SemiSpace implementation

SemiSpace::~SemiSpace() {
  // Properly uncommit memory to keep the allocator counters in sync.
  if (IsCommitted()) {
    Uncommit();
  }
}

bool SemiSpace::Commit() {
  DCHECK(!IsCommitted());
  DCHECK_EQ(CommittedMemory(), size_t(0));
  const int num_pages =
      static_cast<int>(target_capacity_ / PageMetadata::kPageSize);
  DCHECK(num_pages);
  for (int pages_added = 0; pages_added < num_pages; pages_added++) {
    // Pages in the new spaces can be moved to the old space by the full
    // collector. Therefore, they must be initialized with the same FreeList as
    // old pages.
    if (!AllocateFreshPage()) {
      if (pages_added) RewindPages(pages_added);
      DCHECK(!IsCommitted());
      return false;
    }
  }
  Reset();
  DCHECK_EQ(target_capacity_, CommittedMemory());
  if (age_mark_ == kNullAddress) {
    age_mark_ = first_page()->area_start();
  }
  DCHECK(IsCommitted());
  return true;
}

void SemiSpace::Uncommit() {
  DCHECK(IsCommitted());
  int actual_pages = 0;
  while (!memory_chunk_list_.Empty()) {
    actual_pages++;
    MutablePageMetadata* chunk = memory_chunk_list_.front();
    DecrementCommittedPhysicalMemory(chunk->CommittedPhysicalMemory());
    memory_chunk_list_.Remove(chunk);
    heap()->memory_allocator()->Free(MemoryAllocator::FreeMode::kPool, chunk);
  }
  current_page_ = nullptr;
  current_capacity_ = 0;
  size_t removed_page_size =
      static_cast<size_t>(actual_pages * PageMetadata::kPageSize);
  DCHECK_EQ(CommittedMemory(), removed_page_size);
  DCHECK_EQ(CommittedPhysicalMemory(), 0);
  AccountUncommitted(removed_page_size);
  DCHECK(!IsCommitted());
}

size_t SemiSpace::CommittedPhysicalMemory() const {
  if (!IsCommitted()) return 0;
  if (!base::OS::HasLazyCommits()) return CommittedMemory();
  return committed_physical_memory_;
}

bool SemiSpace::GrowTo(size_t new_capacity) {
  if (!IsCommitted()) {
    if (!Commit()) return false;
  }
  DCHECK(MemoryChunk::IsAligned(new_capacity));
  DCHECK_LE(new_capacity, maximum_capacity_);
  DCHECK_GT(new_capacity, target_capacity_);
  const size_t delta = new_capacity - target_capacity_;
  DCHECK(IsAligned(delta, AllocatePageSize()));
  const int delta_pages = static_cast<int>(delta / PageMetadata::kPageSize);
  DCHECK(last_page());
  for (int pages_added = 0; pages_added < delta_pages; pages_added++) {
    if (!AllocateFreshPage()) {
      if (pages_added) RewindPages(pages_added);
      return false;
    }
  }
  target_capacity_ = new_capacity;
  return true;
}

bool SemiSpace::AllocateFreshPage() {
  PageMetadata* new_page = heap()->memory_allocator()->AllocatePage(
      MemoryAllocator::AllocationMode::kUsePool, this, NOT_EXECUTABLE);
  if (new_page == nullptr) {
    return false;
  }
  memory_chunk_list_.PushBack(new_page);
  new_page->ClearLiveness();
  IncrementCommittedPhysicalMemory(new_page->CommittedPhysicalMemory());
  AccountCommitted(PageMetadata::kPageSize);
  heap()->CreateFillerObjectAt(new_page->area_start(),
                               static_cast<int>(new_page->area_size()));
  return true;
}

void SemiSpace::RewindPages(int num_pages) {
  DCHECK_GT(num_pages, 0);
  DCHECK(last_page());
  while (num_pages > 0) {
    MutablePageMetadata* last = last_page();
    AccountUncommitted(PageMetadata::kPageSize);
    DecrementCommittedPhysicalMemory(last->CommittedPhysicalMemory());
    memory_chunk_list_.Remove(last);
    heap()->memory_allocator()->Free(MemoryAllocator::FreeMode::kPool, last);
    num_pages--;
  }
}

void SemiSpace::ShrinkTo(size_t new_capacity) {
  DCHECK(MemoryChunk::IsAligned(new_capacity));
  DCHECK_GE(new_capacity, minimum_capacity_);
  DCHECK_LT(new_capacity, target_capacity_);
  if (IsCommitted()) {
    const size_t delta = target_capacity_ - new_capacity;
    DCHECK(IsAligned(delta, PageMetadata::kPageSize));
    int delta_pages = static_cast<int>(delta / PageMetadata::kPageSize);
    RewindPages(delta_pages);
  }
  target_capacity_ = new_capacity;
}

void SemiSpace::FixPagesFlags() {
  const auto to_space_flags =
      MemoryChunk::YoungGenerationPageFlags(
          heap()->incremental_marking()->marking_mode()) |
      MemoryChunk::TO_PAGE;
  for (PageMetadata* page : *this) {
    MemoryChunk* chunk = page->Chunk();
    page->set_owner(this);
    if (id_ == kToSpace) {
      chunk->SetFlagsNonExecutable(to_space_flags);
    } else {
      DCHECK_EQ(id_, kFromSpace);
      // From space must preserve `NEW_SPACE_BELOW_AGE_MARK` which is used for
      // deciding on whether to copy or promote an object.
      chunk->SetFlagNonExecutable(MemoryChunk::FROM_PAGE);
      chunk->ClearFlagNonExecutable(MemoryChunk::TO_PAGE);
    }
    DCHECK(chunk->InYoungGeneration());
  }
}

void SemiSpace::Reset() {
  DCHECK(first_page());
  DCHECK(last_page());
  current_page_ = first_page();
  current_capacity_ = PageMetadata::kPageSize;
}

void SemiSpace::RemovePage(PageMetadata* page) {
  if (current_page_ == page) {
    if (page->prev_page()) {
      current_page_ = page->prev_page();
    }
  }
  memory_chunk_list_.Remove(page);
  AccountUncommitted(PageMetadata::kPageSize);
  DecrementCommittedPhysicalMemory(page->CommittedPhysicalMemory());
  ForAll<ExternalBackingStoreType>(
      [this, page](ExternalBackingStoreType type, int index) {
        DecrementExternalBackingStoreBytes(
            type, page->ExternalBackingStoreBytes(type));
      });
}

void SemiSpace::PrependPage(PageMetadata* page) {
  page->Chunk()->SetFlagsNonExecutable(current_page()->Chunk()->GetFlags());
  page->set_owner(this);
  memory_chunk_list_.PushFront(page);
  base::AsAtomicWord::Relaxed_Store(
      &current_capacity_, current_capacity_ + PageMetadata::kPageSize);
  AccountCommitted(PageMetadata::kPageSize);
  IncrementCommittedPhysicalMemory(page->CommittedPhysicalMemory());
  ForAll<ExternalBackingStoreType>(
      [this, page](ExternalBackingStoreType type, int index) {
        IncrementExternalBackingStoreBytes(
            type, page->ExternalBackingStoreBytes(type));
      });
}

void SemiSpace::MovePageToTheEnd(PageMetadata* page) {
  DCHECK_EQ(page->owner(), this);
  memory_chunk_list_.Remove(page);
  memory_chunk_list_.PushBack(page);
  current_page_ = page;
}

void SemiSpace::Swap(SemiSpace* from, SemiSpace* to) {
  // We won't be swapping semispaces without data in them.
  DCHECK(from->first_page());
  DCHECK(to->first_page());
  DCHECK_EQ(from->maximum_capacity_, to->maximum_capacity_);
  DCHECK_EQ(from->minimum_capacity_, to->minimum_capacity_);
  // We swap all properties but id_.
  std::swap(from->target_capacity_, to->target_capacity_);
  std::swap(from->age_mark_, to->age_mark_);
  std::swap(from->memory_chunk_list_, to->memory_chunk_list_);
  std::swap(from->current_page_, to->current_page_);
  ForAll<ExternalBackingStoreType>(
      [from, to](ExternalBackingStoreType type, int index) {
        const size_t tmp = from->external_backing_store_bytes_[index].load(
            std::memory_order_relaxed);
        from->external_backing_store_bytes_[index].store(
            to->external_backing_store_bytes_[index].load(
                std::memory_order_relaxed),
            std::memory_order_relaxed);
        to->external_backing_store_bytes_[index].store(
            tmp, std::memory_order_relaxed);
      });
  std::swap(from->committed_physical_memory_, to->committed_physical_memory_);
  {
    // Swap committed atomic counters.
    size_t to_commited = to->committed_.load();
    to->committed_.store(from->committed_.load());
    from->committed_.store(to_commited);
  }

  // Swapping the `memory_cunk_list_` essentially swaps out the pages (actual
  // payload) from to and from space.
  to->FixPagesFlags();
  from->FixPagesFlags();
}

void SemiSpace::IncrementCommittedPhysicalMemory(size_t increment_value) {
  if (!base::OS::HasLazyCommits()) return;
  DCHECK_LE(committed_physical_memory_,
            committed_physical_memory_ + increment_value);
  committed_physical_memory_ += increment_value;
}

void SemiSpace::DecrementCommittedPhysicalMemory(size_t decrement_value) {
  if (!base::OS::HasLazyCommits()) return;
  DCHECK_LE(decrement_value, committed_physical_memory_);
  committed_physical_memory_ -= decrement_value;
}

void SemiSpace::AddRangeToActiveSystemPages(Address start, Address end) {
  PageMetadata* page = current_page();
  MemoryChunk* chunk = page->Chunk();

  DCHECK_LE(chunk->address(), start);
  DCHECK_LT(start, end);
  DCHECK_LE(end, chunk->address() + PageMetadata::kPageSize);

  const size_t added_pages = page->active_system_pages()->Add(
      chunk->Offset(start), chunk->Offset(end),
      MemoryAllocator::GetCommitPageSizeBits());
  IncrementCommittedPhysicalMemory(added_pages *
                                   MemoryAllocator::GetCommitPageSize());
}

void SemiSpace::set_age_mark(Address mark) {
  age_mark_ = mark;
  PageMetadata* age_mark_page = PageMetadata::FromAllocationAreaAddress(mark);
  DCHECK_EQ(age_mark_page->owner(), this);
  // Mark all pages up to the one containing mark.
  for (PageMetadata* p : *this) {
    p->Chunk()->SetFlagNonExecutable(MemoryChunk::NEW_SPACE_BELOW_AGE_MARK);
    if (p == age_mark_page) break;
  }
}

std::unique_ptr<ObjectIterator> SemiSpace::GetObjectIterator(Heap* heap) {
  // Use the SemiSpaceNewSpace::NewObjectIterator to iterate the ToSpace.
  UNREACHABLE();
}

#ifdef DEBUG
void SemiSpace::Print() {}
#endif

#ifdef VERIFY_HEAP
void SemiSpace::VerifyPageMetadata() const {
  bool is_from_space = (id_ == kFromSpace);
  size_t external_backing_store_bytes[static_cast<int>(
      ExternalBackingStoreType::kNumValues)] = {0};

  int actual_pages = 0;
  size_t computed_committed_physical_memory = 0;

  for (const PageMetadata* page : *this) {
    const MemoryChunk* chunk = page->Chunk();
    CHECK_EQ(page->owner(), this);
    CHECK(chunk->InNewSpace());
    CHECK(chunk->IsFlagSet(is_from_space ? MemoryChunk::FROM_PAGE
                                         : MemoryChunk::TO_PAGE));
    CHECK(!chunk->IsFlagSet(is_from_space ? MemoryChunk::TO_PAGE
                                          : MemoryChunk::FROM_PAGE));
    CHECK(chunk->IsFlagSet(MemoryChunk::POINTERS_TO_HERE_ARE_INTERESTING));
    if (!is_from_space) {
      // The pointers-from-here-are-interesting flag isn't updated dynamically
      // on from-space pages, so it might be out of sync with the marking state.
      if (page->heap()->incremental_marking()->IsMarking()) {
        CHECK(page->heap()->incremental_marking()->IsMajorMarking());
        CHECK(
            chunk->IsFlagSet(MemoryChunk::POINTERS_FROM_HERE_ARE_INTERESTING));
      } else {
        CHECK(
            !chunk->IsFlagSet(MemoryChunk::POINTERS_FROM_HERE_ARE_INTERESTING));
      }
    }
    ForAll<ExternalBackingStoreType>(
        [&external_backing_store_bytes, page](ExternalBackingStoreType type,
                                              int index) {
          external_backing_store_bytes[index] +=
              page->ExternalBackingStoreBytes(type);
        });

    computed_committed_physical_memory += page->CommittedPhysicalMemory();

    CHECK_IMPLIES(page->list_node().prev(),
                  page->list_node().prev()->list_node().next() == page);
    actual_pages++;
  }
  CHECK_EQ(actual_pages * size_t(PageMetadata::kPageSize), CommittedMemory());
  CHECK_EQ(computed_committed_physical_memory, CommittedPhysicalMemory());
  ForAll<ExternalBackingStoreType>(
      [this, external_backing_store_bytes](ExternalBackingStoreType type,
                                           int index) {
        CHECK_EQ(external_backing_store_bytes[index],
                 ExternalBackingStoreBytes(type));
      });
}
#endif  // VERIFY_HEAP

#ifdef DEBUG
void SemiSpace::AssertValidRange(Address start, Address end) {
  // Addresses belong to same semi-space
  PageMetadata* page = PageMetadata::FromAllocationAreaAddress(start);
  PageMetadata* end_page = PageMetadata::FromAllocationAreaAddress(end);
  SemiSpace* space = reinterpret_cast<SemiSpace*>(page->owner());
  DCHECK_EQ(space, end_page->owner());
  // Start address is before end address, either on same page,
  // or end address is on a later page in the linked list of
  // semi-space pages.
  if (page == end_page) {
    DCHECK_LE(start, end);
  } else {
    while (page != end_page) {
      page = page->next_page();
    }
    DCHECK(page);
  }
}
#endif

// -----------------------------------------------------------------------------
// NewSpace implementation

NewSpace::NewSpace(Heap* heap)
    : SpaceWithLinearArea(heap, NEW_SPACE, nullptr) {}

void NewSpace::PromotePageToOldSpace(PageMetadata* page) {
  DCHECK(!page->Chunk()->IsFlagSet(MemoryChunk::PAGE_NEW_OLD_PROMOTION));
  DCHECK(page->Chunk()->InYoungGeneration());
  RemovePage(page);
  PageMetadata* new_page = PageMetadata::ConvertNewToOld(page);
  DCHECK(!new_page->Chunk()->InYoungGeneration());
  USE(new_page);
}

// -----------------------------------------------------------------------------
// SemiSpaceNewSpace implementation

SemiSpaceNewSpace::SemiSpaceNewSpace(Heap* heap,
                                     size_t initial_semispace_capacity,
                                     size_t max_semispace_capacity)
    : NewSpace(heap),
      to_space_(heap, kToSpace, initial_semispace_capacity,
                max_semispace_capacity),
      from_space_(heap, kFromSpace, initial_semispace_capacity,
                  max_semispace_capacity) {
  DCHECK(initial_semispace_capacity <= max_semispace_capacity);
  if (!to_space_.Commit()) {
    V8::FatalProcessOutOfMemory(heap->isolate(), "New space setup");
  }
  DCHECK(!from_space_.IsCommitted());  // No need to use memory yet.
  ResetCurrentSpace();
}

void SemiSpaceNewSpace::Grow() {
  heap()->safepoint()->AssertActive();
  // Double the semispace size but only up to maximum capacity.
  DCHECK(TotalCapacity() < MaximumCapacity());
  size_t new_capacity = std::min(
      MaximumCapacity(),
      static_cast<size_t>(v8_flags.semi_space_growth_factor) * TotalCapacity());
  if (to_space_.GrowTo(new_capacity)) {
    // Only grow from space if we managed to grow to-space.
    if (!from_space_.GrowTo(new_capacity)) {
      // If we managed to grow to-space but couldn't grow from-space,
      // attempt to shrink to-space.
      to_space_.ShrinkTo(from_space_.target_capacity());
    }
  }
  DCHECK_SEMISPACE_ALLOCATION_TOP(allocation_top(), to_space_);
}

void SemiSpaceNewSpace::set_age_mark_to_top() {
  to_space_.set_age_mark(allocation_top());
}

void SemiSpaceNewSpace::Shrink() {
  size_t new_capacity = std::max(InitialTotalCapacity(), 2 * Size());
  size_t rounded_new_capacity =
      ::RoundUp(new_capacity, PageMetadata::kPageSize);
  if (rounded_new_capacity < TotalCapacity()) {
    to_space_.ShrinkTo(rounded_new_capacity);
    // Only shrink from-space if we managed to shrink to-space.
    if (from_space_.IsCommitted()) from_space_.Reset();
    from_space_.ShrinkTo(rounded_new_capacity);
  }
  DCHECK_SEMISPACE_ALLOCATION_TOP(allocation_top(), to_space_);
  if (!from_space_.IsCommitted()) return;
  from_space_.Uncommit();
}

size_t SemiSpaceNewSpace::CommittedPhysicalMemory() const {
  if (!base::OS::HasLazyCommits()) return CommittedMemory();
  size_t size = to_space_.CommittedPhysicalMemory();
  if (from_space_.IsCommitted()) {
    size += from_space_.CommittedPhysicalMemory();
  }
  return size;
}

bool SemiSpaceNewSpace::EnsureCurrentCapacity() {
  // Order here is important to make use of the page pool.
  return to_space_.EnsureCurrentCapacity() &&
         from_space_.EnsureCurrentCapacity();
}

void SemiSpaceNewSpace::ResetCurrentSpace() {
  to_space_.Reset();
  // Clear all mark-bits in the to-space.
  for (PageMetadata* p : to_space_) {
    p->ClearLiveness();
    // Concurrent marking may have local live bytes for this page.
    heap()->concurrent_marking()->ClearMemoryChunkData(p);
  }
  ResetAllocationTopToCurrentPageStart();
}

bool SemiSpaceNewSpace::AddFreshPage() {
  DCHECK_EQ(allocation_top(), to_space_.page_high());

  if (to_space_.AdvancePage()) {
    ResetAllocationTopToCurrentPageStart();
    return true;
  }
  return false;
}
std::optional<std::pair<Address, Address>>
SemiSpaceNewSpace::AllocateOnNewPageBeyondCapacity(
    int size_in_bytes, AllocationAlignment alignment) {
  DCHECK_LT(Available(), size_in_bytes);
  DCHECK(!AddFreshPage());
  DCHECK(heap_->ShouldExpandYoungGenerationOnSlowAllocation(
      PageMetadata::kPageSize));
  to_space_.allow_to_grow_beyond_capacity_ = true;
  if (!to_space_.AllocateFreshPage()) return std::nullopt;
  return Allocate(size_in_bytes, alignment);
}

bool SemiSpaceNewSpace::AddParkedAllocationBuffer(
    int size_in_bytes, AllocationAlignment alignment) {
  int parked_size = 0;
  Address start = 0;
  for (auto it = parked_allocation_buffers_.begin();
       it != parked_allocation_buffers_.end();) {
    parked_size = it->first;
    start = it->second;
    int filler_size = Heap::GetFillToAlign(start, alignment);
    if (size_in_bytes + filler_size <= parked_size) {
      parked_allocation_buffers_.erase(it);
      PageMetadata* page = PageMetadata::FromAddress(start);
      // We move a page with a parked allocation to the end of the pages list
      // to maintain the invariant that the last page is the used one.
      to_space_.MovePageToTheEnd(page);
      SetAllocationTop(start);
      return true;
    } else {
      it++;
    }
  }
  return false;
}

void SemiSpaceNewSpace::ResetParkedAllocationBuffers() {
  parked_allocation_buffers_.clear();
}

int SemiSpaceNewSpace::GetSpaceRemainingOnCurrentPageForTesting() {
  return static_cast<int>(to_space_.page_high() - allocation_top());
}

void SemiSpaceNewSpace::FillCurrentPageForTesting() {
  int remaining = GetSpaceRemainingOnCurrentPageForTesting();
  heap()->CreateFillerObjectAt(allocation_top(), remaining);
  IncrementAllocationTop(to_space_.page_high());
}

#ifdef VERIFY_HEAP
// We do not use the SemiSpaceObjectIterator because verification doesn't assume
// that it works (it depends on the invariants we are checking).
void SemiSpaceNewSpace::Verify(Isolate* isolate,
                               SpaceVerificationVisitor* visitor) const {
  VerifyObjects(isolate, visitor);

  // Check semi-spaces.
  CHECK_EQ(from_space_.id(), kFromSpace);
  CHECK_EQ(to_space_.id(), kToSpace);
  from_space_.VerifyPageMetadata();
  to_space_.VerifyPageMetadata();
}

// We do not use the SemiSpaceObjectIterator because verification doesn't assume
// that it works (it depends on the invariants we are checking).
void SemiSpaceNewSpace::VerifyObjects(Isolate* isolate,
                                      SpaceVerificationVisitor* visitor) const {
  size_t external_space_bytes[static_cast<int>(
      ExternalBackingStoreType::kNumValues)] = {0};
  PtrComprCageBase cage_base(isolate);
  for (const PageMetadata* page = to_space_.first_page(); page;
       page = page->next_page()) {
    visitor->VerifyPage(page);

    Address current_address = page->area_start();

    while (!PageMetadata::IsAlignedToPageSize(current_address)) {
      Tagged<HeapObject> object = HeapObject::FromAddress(current_address);

      // The first word should be a map, and we expect all map pointers to
      // be in map space or read-only space.
      int size = object->Size(cage_base);

      visitor->VerifyObject(object);

      if (IsExternalString(object, cage_base)) {
        Tagged<ExternalString> external_string = Cast<ExternalString>(object);
        size_t string_size = external_string->ExternalPayloadSize();
        external_space_bytes[static_cast<int>(
            ExternalBackingStoreType::kExternalString)] += string_size;
      }

      current_address += ALIGN_TO_ALLOCATION_ALIGNMENT(size);
    }

    visitor->VerifyPageDone(page);
  }

  ForAll<ExternalBackingStoreType>(
      [this, external_space_bytes](ExternalBackingStoreType type, int index) {
        if (type == ExternalBackingStoreType::kArrayBuffer) {
          return;
        }
        CHECK_EQ(external_space_bytes[index], ExternalBackingStoreBytes(type));
      });

  if (!v8_flags.concurrent_array_buffer_sweeping) {
    size_t bytes = heap()->array_buffer_sweeper()->young().BytesSlow();
    CHECK_EQ(bytes,
             ExternalBackingStoreBytes(ExternalBackingStoreType::kArrayBuffer));
  }
}
#endif  // VERIFY_HEAP

void SemiSpaceNewSpace::MakeIterable() {
  MakeAllPagesInFromSpaceIterable();
  MakeUnusedPagesInToSpaceIterable();
}

void SemiSpaceNewSpace::MakeAllPagesInFromSpaceIterable() {
  if (!IsFromSpaceCommitted()) return;

  // Fix all pages in the "from" semispace.
  for (PageMetadata* page : from_space()) {
    heap()->CreateFillerObjectAt(page->area_start(),
                                 static_cast<int>(page->area_size()));
  }
}

void SemiSpaceNewSpace::MakeUnusedPagesInToSpaceIterable() {
  PageIterator it(to_space().current_page());

  // Fix the remaining unused pages in the "to" semispace.
  for (PageMetadata* page = *(++it); page != nullptr; page = *(++it)) {
    heap()->CreateFillerObjectAt(page->area_start(),
                                 static_cast<int>(page->area_size()));
  }
}

bool SemiSpaceNewSpace::ShouldBePromoted(Address address) const {
  PageMetadata* page = PageMetadata::FromAddress(address);
  Address current_age_mark = age_mark();
  return page->Chunk()->IsFlagSet(MemoryChunk::NEW_SPACE_BELOW_AGE_MARK) &&
         (!page->ContainsLimit(current_age_mark) || address < current_age_mark);
}

std::unique_ptr<ObjectIterator> SemiSpaceNewSpace::GetObjectIterator(
    Heap* heap) {
  return std::unique_ptr<ObjectIterator>(new SemiSpaceObjectIterator(this));
}

bool SemiSpaceNewSpace::ContainsSlow(Address a) const {
  return from_space_.ContainsSlow(a) || to_space_.ContainsSlow(a);
}

size_t SemiSpaceNewSpace::Size() const {
  size_t top = allocation_top();

  DCHECK_GE(top, to_space_.page_low());
  return (to_space_.current_capacity() - PageMetadata::kPageSize) /
             PageMetadata::kPageSize *
             MemoryChunkLayout::AllocatableMemoryInDataPage() +
         static_cast<size_t>(top - to_space_.page_low());
}

size_t SemiSpaceNewSpace::AllocatedSinceLastGC() const {
  const Address age_mark = to_space_.age_mark();
  DCHECK_NE(age_mark, kNullAddress);
  DCHECK_NE(allocation_top(), kNullAddress);
  PageMetadata* const age_mark_page =
      PageMetadata::FromAllocationAreaAddress(age_mark);
  PageMetadata* const last_page =
      PageMetadata::FromAllocationAreaAddress(allocation_top());
  PageMetadata* current_page = age_mark_page;
  size_t allocated = 0;
  if (current_page != last_page) {
    DCHECK_EQ(current_page, age_mark_page);
    DCHECK_GE(age_mark_page->area_end(), age_mark);
    allocated += age_mark_page->area_end() - age_mark;
    current_page = current_page->next_page();
  } else {
    DCHECK_GE(allocation_top(), age_mark);
    return allocation_top() - age_mark;
  }
  while (current_page != last_page) {
    DCHECK_NE(current_page, age_mark_page);
    allocated += MemoryChunkLayout::AllocatableMemoryInDataPage();
    current_page = current_page->next_page();
  }
  DCHECK_GE(allocation_top(), current_page->area_start());
  allocated += allocation_top() - current_page->area_start();
  DCHECK_LE(allocated, Size());
  return allocated;
}

void SemiSpaceNewSpace::GarbageCollectionPrologue() {
  ResetParkedAllocationBuffers();

  // We need to commit from space here to be able to check for from/to space
  // pages later on in the GC. We need to commit before sweeping starts to avoid
  // empty pages being reused for commiting from space and thus ending up with
  // remembered set entries that point to from space instead of freed memory.
  if (!from_space_.IsCommitted() && !from_space_.Commit()) {
    heap_->FatalProcessOutOfMemory("Committing semi space failed.");
  }
}

void SemiSpaceNewSpace::EvacuatePrologue() {
  // Flip the semispaces. After flipping, to space is empty and from space has
  // live objects.
  SemiSpace::Swap(&from_space_, &to_space_);
  ResetCurrentSpace();
  DCHECK_EQ(0u, Size());
}

void SemiSpaceNewSpace::GarbageCollectionEpilogue() {
  DCHECK(!heap()->allocator()->new_space_allocator()->IsLabValid());
  set_age_mark_to_top();

  if (heap::ShouldZapGarbage() || v8_flags.clear_free_memory) {
    ZapUnusedMemory();
  }

  MakeAllPagesInFromSpaceIterable();
}

void SemiSpaceNewSpace::ZapUnusedMemory() {
  if (!IsFromSpaceCommitted()) {
    return;
  }
  for (PageMetadata* page : PageRange(from_space().first_page(), nullptr)) {
    heap::ZapBlock(page->area_start(),
                   page->HighWaterMark() - page->area_start(),
                   heap::ZapValue());
  }
}

void SemiSpaceNewSpace::RemovePage(PageMetadata* page) {
  DCHECK(!page->Chunk()->IsToPage());
  DCHECK(page->Chunk()->IsFromPage());
  from_space().RemovePage(page);
}

bool SemiSpaceNewSpace::IsPromotionCandidate(
    const MutablePageMetadata* page) const {
  return !page->Contains(age_mark());
}

std::optional<std::pair<Address, Address>> SemiSpaceNewSpace::Allocate(
    int size_in_bytes, AllocationAlignment alignment) {
  size_in_bytes = ALIGN_TO_ALLOCATION_ALIGNMENT(size_in_bytes);
  DCHECK_SEMISPACE_ALLOCATION_TOP(allocation_top(), to_space_);

  Address top = allocation_top();
  Address high = to_space_.page_high();
  int filler_size = Heap::GetFillToAlign(top, alignment);
  int aligned_size_in_bytes = size_in_bytes + filler_size;

  if (top + aligned_size_in_bytes <= high) {
    IncrementAllocationTop(high);
    return std::pair(top, high);
  }

  int remaining_in_page = static_cast<int>(high - top);
  heap()->CreateFillerObjectAt(top, remaining_in_page);
  SetAllocationTop(high);

  // We park unused allocation buffer space of allocations happening from the
  // mutator.
  if (v8_flags.allocation_buffer_parking &&
      heap()->gc_state() == Heap::NOT_IN_GC &&
      remaining_in_page >= kAllocationBufferParkingThreshold) {
    parked_allocation_buffers_.push_back(
        ParkedAllocationBuffer(remaining_in_page, top));
  }

  if (AddFreshPage()) {
    Address start = allocation_top();
    Address end = to_space_.page_high();
    DCHECK_EQ(0, Heap::GetFillToAlign(start, alignment));
    IncrementAllocationTop(end);
    return std::pair(start, end);
  }

  if (v8_flags.allocation_buffer_parking &&
      AddParkedAllocationBuffer(size_in_bytes, alignment)) {
    Address start = allocation_top();
    Address end = to_space_.page_high();
    DCHECK_LT(start, end);
    IncrementAllocationTop(end);
    return std::pair(start, end);
  }

  return std::nullopt;
}

void SemiSpaceNewSpace::Free(Address start, Address end) {
  DCHECK_LE(start, end);
  heap()->CreateFillerObjectAt(start, static_cast<int>(end - start));

  if (end == allocation_top()) {
    DecrementAllocationTop(start);
  }
}

AllocatorPolicy* SemiSpaceNewSpace::CreateAllocatorPolicy(
    MainAllocator* allocator) {
  return new SemiSpaceNewSpaceAllocatorPolicy(this, allocator);
}

// -----------------------------------------------------------------------------
// PagedSpaceForNewSpace implementation

PagedSpaceForNewSpace::PagedSpaceForNewSpace(Heap* heap,
                                             size_t initial_capacity,
                                             size_t max_capacity)
    : PagedSpaceBase(heap, NEW_SPACE, NOT_EXECUTABLE,
                     FreeList::CreateFreeListForNewSpace(),
                     CompactionSpaceKind::kNone),
      initial_capacity_(RoundDown(initial_capacity, PageMetadata::kPageSize)),
      max_capacity_(RoundDown(max_capacity, PageMetadata::kPageSize)),
      target_capacity_(initial_capacity_) {
  DCHECK_LE(initial_capacity_, max_capacity_);
}

PageMetadata* PagedSpaceForNewSpace::InitializePage(
    MutablePageMetadata* mutable_page_metadata) {
  DCHECK_EQ(identity(), NEW_SPACE);
  MemoryChunk* chunk = mutable_page_metadata->Chunk();
  PageMetadata* page = PageMetadata::cast(mutable_page_metadata);
  DCHECK_EQ(
      MemoryChunkLayout::AllocatableMemoryInMemoryChunk(page->owner_identity()),
      page->area_size());
  // Make sure that categories are initialized before freeing the area.
  page->ResetAllocationStatistics();
  chunk->SetFlagNonExecutable(MemoryChunk::TO_PAGE);
  page->ClearLiveness();
  page->AllocateFreeListCategories();
  page->InitializeFreeListCategories();
  page->list_node().Initialize();
  chunk->InitializationMemoryFen
"""


```