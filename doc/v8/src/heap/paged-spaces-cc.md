Response:
Let's break down the thought process to analyze this C++ code and generate the desired information.

**1. Understanding the Goal:**

The request asks for an analysis of the `v8/src/heap/paged-spaces.cc` file, specifically focusing on its functionality, relationship with JavaScript (if any), code logic, and potential user errors.

**2. Initial Code Scan & Keywords:**

I started by quickly scanning the code for keywords and structural elements:

* **`// Copyright`**:  Confirms it's V8 source code.
* **`#include`**:  Indicates dependencies on other V8 components (heap, execution, flags, etc.). This immediately suggests the file is related to memory management.
* **Class Names**: `PagedSpaceObjectIterator`, `PagedSpaceBase`, `CompactionSpace`, `OldSpace`, `StickySpace`, `SharedSpace`. These are core entities.
* **Member Variables**:  `free_list_`, `executable_`, `accounting_stats_`, `memory_chunk_list_`, etc. These hint at the responsibilities of the classes.
* **Methods**: `InitializePage`, `TearDown`, `MergeCompactionSpace`, `AddPage`, `RemovePage`, `RefillFreeList`, `GetObjectIterator`, `Verify`, etc. These are the actions the classes perform.
* **Namespace**: `v8::internal`. Confirms it's an internal V8 implementation detail.
* **Comments**:  Provide valuable insights into the purpose of certain code sections (e.g., merging compaction spaces, handling lazy commits).

**3. Deconstructing the Core Classes:**

I then focused on understanding the roles of the main classes:

* **`PagedSpaceBase`**: This appears to be the fundamental building block for managing a region of memory divided into pages. It handles page allocation, deallocation, tracking of allocated memory, and iterating through objects within the space.
* **`PagedSpaceObjectIterator`**: A helper class for iterating over objects within a `PagedSpaceBase`.
* **`CompactionSpace`**:  Specifically designed for memory compaction. It seems to hold pages temporarily before merging them back into regular spaces. The "destination heap" concept is important here.
* **`OldSpace`, `StickySpace`, `SharedSpace`**: These seem to be specialized types of `PagedSpaceBase`, each with potentially unique behaviors or constraints. The names themselves give clues about their purpose (e.g., `OldSpace` likely holds long-lived objects, `SharedSpace` for shared objects).

**4. Identifying Key Functionalities:**

Based on the class structure and methods, I started listing the core functionalities:

* **Memory Management:** Allocation and deallocation of memory pages. Tracking of allocated and free memory.
* **Object Iteration:**  Providing a way to traverse all objects within a paged space.
* **Compaction Support:**  Managing temporary spaces for memory compaction and then merging them.
* **Sweeping Integration:** Interacting with the garbage collection sweeper to reclaim dead objects.
* **Free List Management:**  Using a free list to efficiently manage available memory blocks within pages.
* **Accounting and Statistics:** Tracking memory usage and related metrics.
* **Verification:**  Providing debugging and testing mechanisms to ensure heap integrity.
* **Lazy Commit Handling:**  Dealing with operating systems that don't immediately allocate physical memory.

**5. Connecting to JavaScript (If Applicable):**

The request specifically asked about the relationship to JavaScript. While this C++ code *directly* manages memory, which isn't exposed in JavaScript, it's the *foundation* upon which the JavaScript heap is built.

* **Garbage Collection:** The core functionality is directly related to how V8 performs garbage collection, which is essential for JavaScript's automatic memory management.
* **Object Allocation:** When you create JavaScript objects, V8 uses these `PagedSpace` mechanisms to allocate memory for them.
* **Memory Limits:** The underlying decisions about when and how to allocate memory influence the performance and memory usage of JavaScript applications.

**6. Code Logic and Examples:**

The request also asked for code logic examples. I looked for representative functions:

* **`AddPage`/`RemovePage`**: These are fundamental operations. I outlined the steps involved and considered potential inputs (a valid `PageMetadata*`).
* **`RefillFreeList`**: This function illustrates the interaction between paged spaces and the sweeper. I described its purpose and how it reclaims memory.

**7. Common Programming Errors:**

Thinking about how developers might interact with *concepts* related to this code (even though they don't directly access it) led to examples of common memory management errors in higher-level languages like JavaScript:

* **Memory Leaks:**  While V8 handles this automatically, the concept is relevant.
* **Out-of-Memory Errors:** This relates to the underlying allocation mechanisms.
* **Performance Issues Due to Excessive Object Creation:** This stresses the heap managed by these components.

**8. Handling the `.tq` Question:**

The request specifically asked about the `.tq` extension. A quick search or prior knowledge about V8 would confirm that `.tq` files are Torque (V8's internal type system and code generation language). Since the file ends in `.cc`, it's standard C++, not Torque.

**9. Structuring the Output:**

Finally, I organized the information into the requested categories:

* **Functionality:**  A bulleted list summarizing the key roles.
* **Torque:**  A direct answer stating it's C++.
* **JavaScript Relationship:** Explanation of the indirect connection through garbage collection and object allocation, with JavaScript examples.
* **Code Logic:**  Breakdown of `AddPage` and `RefillFreeList` with example inputs and outputs.
* **Common Programming Errors:** Examples of JavaScript errors related to memory management concepts.

**Self-Correction/Refinement:**

* Initially, I might have focused too much on the low-level details of memory management. I then shifted to also highlight the connection to higher-level concepts relevant to JavaScript developers.
* I ensured I addressed all parts of the request, including the `.tq` question and the need for JavaScript examples.
* I double-checked that the explanations were clear and concise, avoiding overly technical jargon where possible.
好的，让我们来分析一下 `v8/src/heap/paged-spaces.cc` 这个 V8 源代码文件。

**功能列举:**

`v8/src/heap/paged-spaces.cc` 文件是 V8 引擎中关于堆内存管理的关键部分，它定义并实现了**分页空间 (Paged Spaces)** 的相关功能。分页空间是 V8 堆内存组织的基本单元，用于存储各种类型的 JavaScript 对象。

其主要功能包括：

1. **定义和管理分页空间基类 (`PagedSpaceBase`)**:
   - 维护分页空间的元数据，如容量、已分配大小、空闲列表等。
   - 管理组成空间的内存页 (`PageMetadata`) 链表。
   - 提供添加、删除内存页的功能。
   - 跟踪已提交的物理内存。
   - 支持在空间内迭代对象。
   - 提供分配内存的基本接口。
   - 管理空闲列表 (`FreeList`)，用于高效分配小块内存。
   - 支持内存整理 (Compaction)。
   - 提供空间收缩的功能，释放未使用的内存。

2. **实现特定类型的分页空间**:
   - **`OldSpace` (老生代空间)**: 用于存储生命周期较长的对象。它继承自 `PagedSpaceBase` 并添加了特定于老生代的功能，例如处理从新生代晋升的对象。
   - **`CodeSpace` (代码空间)**: 用于存储编译后的 JavaScript 代码。它也继承自 `PagedSpaceBase`，并可能具有执行权限相关的特殊处理。
   - **`SharedSpace` (共享空间)**: 用于存储多个 Isolate 之间共享的对象（例如，内置对象）。它继承自 `PagedSpaceBase` 并可能具有特殊的生命周期管理。
   - **`StickySpace` (粘性空间)**:  一种特殊的空间，可能用于存储不参与常规垃圾回收的对象。
   - **`CompactionSpace` (整理空间)**:  在垃圾回收的整理阶段使用，用于临时存放需要移动的对象。
   - **`CompactionSpaceCollection`**:  管理不同类型的整理空间。

3. **实现对象迭代器 (`PagedSpaceObjectIterator`)**:
   - 提供了一种遍历分页空间中所有存活对象的方法，这对于垃圾回收标记等操作至关重要。

4. **支持内存整理 (Compaction)**:
   - 提供了将内存页合并到整理空间，然后再合并回正常空间的功能。

5. **与垃圾回收器 (Garbage Collector) 集成**:
   - 文件中的代码与垃圾回收器的各个阶段紧密相关，例如标记、清除和整理。
   - 提供了在垃圾回收过程中更新空间状态、重新填充空闲列表等功能。

6. **统计和监控**:
   - 维护分页空间的各种统计信息，例如已分配字节数、容量等，用于性能监控和调试。

7. **支持外部后备存储 (External Backing Store)**:
   - 跟踪由 `ArrayBuffer` 等外部资源支持的内存。

**关于 `.tq` 结尾:**

你提供的源代码 `v8/src/heap/paged-spaces.cc` 以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**。如果文件以 `.tq` 结尾，那么它才是一个 **V8 Torque 源代码文件**。Torque 是 V8 用于定义类型系统和生成高效 C++ 代码的内部语言。

**与 JavaScript 的关系 (及 JavaScript 示例):**

`v8/src/heap/paged-spaces.cc` 文件中的代码是 V8 引擎的核心组成部分，它直接关系到 JavaScript 程序的内存管理。当你创建 JavaScript 对象时，V8 引擎会在这些分页空间中为其分配内存。垃圾回收器也会扫描和管理这些空间来回收不再使用的内存。

**JavaScript 示例：**

```javascript
// 创建一个 JavaScript 对象
let obj = { name: "example", value: 123 };

// 创建一个数组
let arr = [1, 2, 3, 4, 5];

// 创建一个字符串
let str = "hello";
```

当执行上述 JavaScript 代码时，V8 引擎会在其内部的堆内存（由分页空间组成）中为 `obj`、`arr` 和 `str` 分配内存。`PagedSpaceBase` 及其子类负责管理这些内存的分配和回收。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个 `OldSpace` 实例，并且想要添加一个新的内存页。

**假设输入:**

- `OldSpace` 对象 `old_space`。
- 一个已分配的 `PageMetadata` 对象 `new_page`，代表新的内存页。

**代码逻辑 (核心是 `PagedSpaceBase::AddPage`):**

1. `AddPageImpl(new_page)` 被调用:
   - 设置 `new_page` 的所有者为 `old_space`。
   - 将 `new_page` 添加到 `old_space` 的内存页链表 `memory_chunk_list_` 的末尾。
   - 更新 `old_space` 的已提交内存计数器，增加 `new_page` 的大小。
   - 更新 `old_space` 的容量计数器，增加 `new_page` 的可分配区域大小。
   - 更新 `old_space` 的已分配字节数计数器，增加 `new_page` 的已分配字节数。
   - 更新 `old_space` 的外部后备存储字节数计数器。
   - 更新 `old_space` 的已提交物理内存计数器。

2. `RelinkFreeListCategories(new_page)` 被调用:
   - 遍历 `new_page` 的所有空闲列表类别 (`FreeListCategory`)。
   - 将这些类别重新链接到 `old_space` 的空闲列表 (`free_list_`) 中，使其可用于分配。
   - 增加 `old_space` 的浪费字节计数器。

**假设输出:**

- `new_page` 已成功添加到 `old_space` 中。
- `old_space` 的元数据（容量、已分配大小等）已更新以反映新页的添加。
- `new_page` 中的空闲内存块现在可以被 `old_space` 用于分配新的对象。

**用户常见的编程错误 (与概念相关):**

虽然用户不会直接操作 `paged-spaces.cc` 中的代码，但理解其背后的概念有助于避免 JavaScript 中的某些编程错误，这些错误最终会影响 V8 的内存管理。

1. **内存泄漏 (Memory Leaks):**  在 JavaScript 中，如果对象不再被引用但仍然持有对其他对象的引用，可能会导致内存泄漏。V8 的垃圾回收器依赖于能够识别不再可达的对象，因此理解对象生命周期至关重要。

   ```javascript
   let detachedElement;
   function createLeak() {
     let element = document.createElement('div');
     detachedElement = element; // detachedElement 现在持有对 element 的引用
     document.body.appendChild(element);
     document.body.removeChild(element); // 从 DOM 中移除，但 element 仍然存在
   }

   createLeak();
   // detachedElement 仍然指向 element，导致其无法被垃圾回收。
   ```

2. **意外地持有大对象的引用:**  长时间持有对大型对象的引用会导致内存占用过高，甚至可能引发 "Out of Memory" 错误。

   ```javascript
   let largeData = new Array(1000000).fill({ data: 'some large string' });

   function processData() {
     // ... 对 largeData 进行一些处理 ...
   }

   // 如果在 processData 执行完毕后，仍然存在对 largeData 的引用，
   // 那么这部分内存将无法被回收。
   processData();
   // 错误地将 largeData 保存在全局作用域或闭包中。
   ```

3. **频繁创建和销毁大量临时对象:**  虽然 V8 的垃圾回收器很高效，但频繁的分配和回收仍然会带来性能开销。

   ```javascript
   function processLotsOfData() {
     for (let i = 0; i < 100000; i++) {
       let tempObj = { index: i, result: i * 2 }; // 频繁创建临时对象
       // ... 使用 tempObj ...
     }
   }
   ```

4. **字符串拼接的低效使用:**  在旧版本的 JavaScript 引擎中，使用 `+` 进行大量的字符串拼接可能会导致创建大量的临时字符串对象。现代引擎通常对此进行了优化，但理解其背后的内存分配原理仍然重要。建议使用模板字符串或 `Array.prototype.join()`。

   ```javascript
   let result = "";
   for (let i = 0; i < 1000; i++) {
     result += "item " + i + "\n"; // 可能导致创建多个临时字符串
   }

   // 更高效的方式：
   const items = [];
   for (let i = 0; i < 1000; i++) {
     items.push(`item ${i}\n`);
   }
   const result = items.join("");
   ```

理解 `v8/src/heap/paged-spaces.cc` 中涉及的内存管理机制，可以帮助开发者编写更高效、更少出现内存问题的 JavaScript 代码。虽然我们不直接操作这些底层代码，但对其原理的了解有助于我们更好地理解 JavaScript 引擎的工作方式。

### 提示词
```
这是目录为v8/src/heap/paged-spaces.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/paged-spaces.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/paged-spaces.h"

#include <atomic>
#include <iterator>

#include "src/base/logging.h"
#include "src/base/platform/mutex.h"
#include "src/base/safe_conversions.h"
#include "src/common/globals.h"
#include "src/execution/isolate.h"
#include "src/execution/vm-state-inl.h"
#include "src/flags/flags.h"
#include "src/heap/allocation-observer.h"
#include "src/heap/array-buffer-sweeper.h"
#include "src/heap/free-list-inl.h"
#include "src/heap/gc-tracer-inl.h"
#include "src/heap/gc-tracer.h"
#include "src/heap/heap.h"
#include "src/heap/incremental-marking.h"
#include "src/heap/marking-state-inl.h"
#include "src/heap/memory-allocator.h"
#include "src/heap/memory-chunk-layout.h"
#include "src/heap/mutable-page-metadata-inl.h"
#include "src/heap/page-metadata-inl.h"
#include "src/heap/paged-spaces-inl.h"
#include "src/heap/read-only-heap.h"
#include "src/heap/safepoint.h"
#include "src/heap/spaces.h"
#include "src/heap/sweeper.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/string.h"
#include "src/utils/utils.h"

namespace v8 {
namespace internal {

// ----------------------------------------------------------------------------
// PagedSpaceObjectIterator

PagedSpaceObjectIterator::PagedSpaceObjectIterator(Heap* heap,
                                                   const PagedSpaceBase* space)
    : space_(space),
      page_range_(space->first_page(), nullptr),
      current_page_(page_range_.begin()) {
  heap->MakeHeapIterable();
  USE(space_);
}

// We have hit the end of the page and should advance to the next block of
// objects.  This happens at the end of the page.
bool PagedSpaceObjectIterator::AdvanceToNextPage() {
  if (current_page_ == page_range_.end()) return false;
  const PageMetadata* cur_page = *(current_page_++);
  HeapObjectRange heap_objects(cur_page);
  cur_ = heap_objects.begin();
  end_ = heap_objects.end();
  return true;
}

// ----------------------------------------------------------------------------
// PagedSpaceBase implementation

PagedSpaceBase::PagedSpaceBase(Heap* heap, AllocationSpace space,
                               Executability executable,
                               std::unique_ptr<FreeList> free_list,
                               CompactionSpaceKind compaction_space_kind)
    : SpaceWithLinearArea(heap, space, std::move(free_list)),
      executable_(executable),
      compaction_space_kind_(compaction_space_kind) {
  area_size_ = MemoryChunkLayout::AllocatableMemoryInMemoryChunk(space);
  accounting_stats_.Clear();
}

PageMetadata* PagedSpaceBase::InitializePage(
    MutablePageMetadata* mutable_page_metadata) {
  MemoryChunk* chunk = mutable_page_metadata->Chunk();
  PageMetadata* page = PageMetadata::cast(mutable_page_metadata);
  DCHECK_EQ(
      MemoryChunkLayout::AllocatableMemoryInMemoryChunk(page->owner_identity()),
      page->area_size());
  // Make sure that categories are initialized before freeing the area.
  page->ResetAllocationStatistics();
  page->AllocateFreeListCategories();
  page->InitializeFreeListCategories();
  page->list_node().Initialize();
  chunk->InitializationMemoryFence();
  return page;
}

void PagedSpaceBase::TearDown() {
  while (!memory_chunk_list_.Empty()) {
    MutablePageMetadata* chunk = memory_chunk_list_.front();
    memory_chunk_list_.Remove(chunk);
    heap()->memory_allocator()->Free(MemoryAllocator::FreeMode::kImmediately,
                                     chunk);
  }
  accounting_stats_.Clear();
}

void PagedSpaceBase::MergeCompactionSpace(CompactionSpace* other) {
  base::MutexGuard guard(mutex());

  DCHECK_NE(NEW_SPACE, identity());
  DCHECK_NE(NEW_SPACE, other->identity());

  // Move over pages.
  for (auto it = other->begin(); it != other->end();) {
    PageMetadata* p = *(it++);

    // Ensure that pages are initialized before objects on it are discovered by
    // concurrent markers.
    p->Chunk()->InitializationMemoryFence();

    // Relinking requires the category to be unlinked.
    other->RemovePage(p);
    AddPage(p);
    DCHECK_IMPLIES(
        !p->Chunk()->IsFlagSet(MemoryChunk::NEVER_ALLOCATE_ON_PAGE),
        p->AvailableInFreeList() == p->AvailableInFreeListFromAllocatedBytes());

    // TODO(leszeks): Here we should allocation step, but:
    //   1. Allocation groups are currently not handled properly by the sampling
    //      allocation profiler, and
    //   2. Observers might try to take the space lock, which isn't reentrant.
    // We'll have to come up with a better solution for allocation stepping
    // before shipping, which will likely be using LocalHeap.
  }
  const bool is_from_client_heap =
      (other->destination_heap() ==
       CompactionSpace::DestinationHeap::kSharedSpaceHeap);
  DCHECK_IMPLIES(is_from_client_heap, identity() == SHARED_SPACE);
  for (auto p : other->GetNewPages()) {
    heap()->NotifyOldGenerationExpansion(
        heap()->main_thread_local_heap(), identity(), p,
        is_from_client_heap
            ? Heap::OldGenerationExpansionNotificationOrigin::kFromClientHeap
            : Heap::OldGenerationExpansionNotificationOrigin::kFromSameHeap);
  }

  DCHECK_EQ(0u, other->Size());
  DCHECK_EQ(0u, other->Capacity());
}

size_t PagedSpaceBase::CommittedPhysicalMemory() const {
  if (!base::OS::HasLazyCommits()) {
    DCHECK_EQ(0, committed_physical_memory());
    return CommittedMemory();
  }
  return committed_physical_memory();
}

void PagedSpaceBase::IncrementCommittedPhysicalMemory(size_t increment_value) {
  if (!base::OS::HasLazyCommits() || increment_value == 0) return;
  size_t old_value = committed_physical_memory_.fetch_add(
      increment_value, std::memory_order_relaxed);
  USE(old_value);
  DCHECK_LT(old_value, old_value + increment_value);
}

void PagedSpaceBase::DecrementCommittedPhysicalMemory(size_t decrement_value) {
  if (!base::OS::HasLazyCommits() || decrement_value == 0) return;
  size_t old_value = committed_physical_memory_.fetch_sub(
      decrement_value, std::memory_order_relaxed);
  USE(old_value);
  DCHECK_GT(old_value, old_value - decrement_value);
}

#if DEBUG
void PagedSpaceBase::VerifyCommittedPhysicalMemory() const {
  heap()->safepoint()->AssertActive();
  size_t size = 0;
  for (const PageMetadata* page : *this) {
    DCHECK(page->SweepingDone());
    size += page->CommittedPhysicalMemory();
  }
  // Ensure that the space's counter matches the sum of all page counters.
  DCHECK_EQ(size, CommittedPhysicalMemory());
}
#endif  // DEBUG

bool PagedSpaceBase::ContainsSlow(Address addr) const {
  MemoryChunk* chunk = MemoryChunk::FromAddress(addr);
  for (const PageMetadata* page : *this) {
    if (page->Chunk() == chunk) return true;
  }
  return false;
}

void PagedSpaceBase::RefineAllocatedBytesAfterSweeping(PageMetadata* page) {
  CHECK(page->SweepingDone());
  // The live_byte on the page was accounted in the space allocated
  // bytes counter. After sweeping allocated_bytes() contains the
  // accurate live byte count on the page.
  size_t old_counter = page->live_bytes();
  size_t new_counter = page->allocated_bytes();
  DCHECK_GE(old_counter, new_counter);
  if (old_counter > new_counter) {
    size_t counter_diff = old_counter - new_counter;
    if (identity() == NEW_SPACE) size_at_last_gc_ -= counter_diff;
    DecreaseAllocatedBytes(counter_diff, page);
    DCHECK_EQ(new_counter, accounting_stats_.AllocatedOnPage(page));
    AdjustDifferenceInAllocatedBytes(counter_diff);
  }
  if (!v8_flags.sticky_mark_bits) {
    // With sticky mark-bits the counter is reset on unmarking.
    page->SetLiveBytes(0);
  }
}

PageMetadata* PagedSpaceBase::RemovePageSafe(int size_in_bytes) {
  base::MutexGuard guard(mutex());
  PageMetadata* page = free_list()->GetPageForSize(size_in_bytes);
  if (!page) return nullptr;
  RemovePage(page);
  return page;
}

void PagedSpaceBase::AddPageImpl(PageMetadata* page) {
  DCHECK_NOT_NULL(page);
  CHECK(page->SweepingDone());
  page->set_owner(this);
  DCHECK_IMPLIES(identity() == NEW_SPACE,
                 page->Chunk()->IsFlagSet(MemoryChunk::TO_PAGE));
  DCHECK_IMPLIES(identity() != NEW_SPACE,
                 !page->Chunk()->IsFlagSet(MemoryChunk::TO_PAGE));
  memory_chunk_list_.PushBack(page);
  AccountCommitted(page->size());
  IncreaseCapacity(page->area_size());
  IncreaseAllocatedBytes(page->allocated_bytes(), page);
  ForAll<ExternalBackingStoreType>(
      [this, page](ExternalBackingStoreType type, int index) {
        IncrementExternalBackingStoreBytes(
            type, page->ExternalBackingStoreBytes(type));
      });
  IncrementCommittedPhysicalMemory(page->CommittedPhysicalMemory());
}

size_t PagedSpaceBase::AddPage(PageMetadata* page) {
  AddPageImpl(page);
  return RelinkFreeListCategories(page);
}

void PagedSpaceBase::RemovePage(PageMetadata* page) {
  CHECK(page->SweepingDone());
  DCHECK_IMPLIES(identity() == NEW_SPACE,
                 page->Chunk()->IsFlagSet(MemoryChunk::TO_PAGE));
  memory_chunk_list_.Remove(page);
  UnlinkFreeListCategories(page);
  // Pages are only removed from new space when they are promoted to old space
  // during a GC. This happens after sweeping as started and the allocation
  // counters have been reset.
  DCHECK_IMPLIES(identity() == NEW_SPACE,
                 heap()->gc_state() != Heap::NOT_IN_GC);
  if (identity() == NEW_SPACE) {
    page->ReleaseFreeListCategories();
  } else {
    DecreaseAllocatedBytes(page->allocated_bytes(), page);
    free_list()->decrease_wasted_bytes(page->wasted_memory());
  }
  DecreaseCapacity(page->area_size());
  AccountUncommitted(page->size());
  ForAll<ExternalBackingStoreType>(
      [this, page](ExternalBackingStoreType type, int index) {
        DecrementExternalBackingStoreBytes(
            type, page->ExternalBackingStoreBytes(type));
      });
  DecrementCommittedPhysicalMemory(page->CommittedPhysicalMemory());
}

size_t PagedSpaceBase::ShrinkPageToHighWaterMark(PageMetadata* page) {
  size_t unused = page->ShrinkToHighWaterMark();
  accounting_stats_.DecreaseCapacity(static_cast<intptr_t>(unused));
  AccountUncommitted(unused);
  return unused;
}

void PagedSpaceBase::ResetFreeList() {
  for (PageMetadata* page : *this) {
    free_list_->EvictFreeListItems(page);
  }
  DCHECK(free_list_->IsEmpty());
  DCHECK_EQ(0, free_list_->Available());
}

void PagedSpaceBase::ShrinkImmortalImmovablePages() {
  DCHECK(!heap()->deserialization_complete());
  ResetFreeList();
  for (PageMetadata* page : *this) {
    DCHECK(page->Chunk()->IsFlagSet(MemoryChunk::NEVER_EVACUATE));
    ShrinkPageToHighWaterMark(page);
  }
}

bool PagedSpaceBase::TryExpand(LocalHeap* local_heap, AllocationOrigin origin) {
  DCHECK_EQ(!local_heap, origin == AllocationOrigin::kGC);
  const size_t accounted_size =
      MemoryChunkLayout::AllocatableMemoryInMemoryChunk(identity());
  if (origin != AllocationOrigin::kGC && identity() != NEW_SPACE) {
    base::MutexGuard expansion_guard(heap_->heap_expansion_mutex());
    if (!heap()->IsOldGenerationExpansionAllowed(accounted_size,
                                                 expansion_guard)) {
      return false;
    }
  }
  const MemoryAllocator::AllocationMode allocation_mode =
      (identity() == NEW_SPACE || identity() == OLD_SPACE)
          ? MemoryAllocator::AllocationMode::kUsePool
          : MemoryAllocator::AllocationMode::kRegular;
  PageMetadata* page = heap()->memory_allocator()->AllocatePage(
      allocation_mode, this, executable());
  if (page == nullptr) return false;
  DCHECK_EQ(page->area_size(), accounted_size);
  ConcurrentAllocationMutex guard(this);
  AddPage(page);
  if (origin != AllocationOrigin::kGC && identity() != NEW_SPACE) {
    heap()->NotifyOldGenerationExpansion(local_heap, identity(), page);
  }
  Free(page->area_start(), page->area_size());
  NotifyNewPage(page);
  return true;
}

int PagedSpaceBase::CountTotalPages() const {
  return base::checked_cast<int>(std::distance(begin(), end()));
}

size_t PagedSpaceBase::Available() const {
  ConcurrentAllocationMutex guard(this);
  return free_list_->Available();
}

size_t PagedSpaceBase::Waste() const {
  return free_list_->wasted_bytes();
}

void PagedSpaceBase::ReleasePage(PageMetadata* page) {
  ReleasePageImpl(page, MemoryAllocator::FreeMode::kImmediately);
}

void PagedSpaceBase::ReleasePageImpl(PageMetadata* page,
                                     MemoryAllocator::FreeMode free_mode) {
  DCHECK(page->SweepingDone());
  DCHECK_EQ(0, page->live_bytes());
  DCHECK_EQ(page->owner(), this);

  DCHECK_IMPLIES(identity() == NEW_SPACE,
                 page->Chunk()->IsFlagSet(MemoryChunk::TO_PAGE));

  memory_chunk_list().Remove(page);

  free_list_->EvictFreeListItems(page);

  if (identity() == CODE_SPACE) {
    heap()->isolate()->RemoveCodeMemoryChunk(page);
  }

  AccountUncommitted(page->size());
  DecrementCommittedPhysicalMemory(page->CommittedPhysicalMemory());
  accounting_stats_.DecreaseCapacity(page->area_size());
  heap()->memory_allocator()->Free(free_mode, page);
}

std::unique_ptr<ObjectIterator> PagedSpaceBase::GetObjectIterator(Heap* heap) {
  return std::unique_ptr<ObjectIterator>(
      new PagedSpaceObjectIterator(heap, this));
}

#ifdef DEBUG
void PagedSpaceBase::Print() {}
#endif

#ifdef VERIFY_HEAP
void PagedSpaceBase::Verify(Isolate* isolate,
                            SpaceVerificationVisitor* visitor) const {
  CHECK_IMPLIES(identity() != NEW_SPACE, size_at_last_gc_ == 0);

  size_t external_space_bytes[static_cast<int>(
      ExternalBackingStoreType::kNumValues)] = {0};
  PtrComprCageBase cage_base(isolate);
  for (const PageMetadata* page : *this) {
    size_t external_page_bytes[static_cast<int>(
        ExternalBackingStoreType::kNumValues)] = {0};

    CHECK_EQ(page->owner(), this);
    CHECK_IMPLIES(identity() != NEW_SPACE, page->AllocatedLabSize() == 0);
    visitor->VerifyPage(page);

    CHECK(page->SweepingDone());
    Address end_of_previous_object = page->area_start();
    Address top = page->area_end();

    for (Tagged<HeapObject> object : HeapObjectRange(page)) {
      CHECK(end_of_previous_object <= object.address());

      // Invoke verification method for each object.
      visitor->VerifyObject(object);

      // All the interior pointers should be contained in the heap.
      int size = object->Size(cage_base);
      CHECK(object.address() + size <= top);
      end_of_previous_object = object.address() + size;

      if (IsExternalString(object, cage_base)) {
        Tagged<ExternalString> external_string = Cast<ExternalString>(object);
        size_t payload_size = external_string->ExternalPayloadSize();
        external_page_bytes[static_cast<int>(
            ExternalBackingStoreType::kExternalString)] += payload_size;
      }
    }
    ForAll<ExternalBackingStoreType>(
        [page, external_page_bytes, &external_space_bytes](
            ExternalBackingStoreType type, int index) {
          CHECK_EQ(external_page_bytes[index],
                   page->ExternalBackingStoreBytes(type));
          external_space_bytes[index] += external_page_bytes[index];
        });

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
    if (identity() == OLD_SPACE) {
      size_t bytes = heap()->array_buffer_sweeper()->old().BytesSlow();
      CHECK_EQ(bytes, ExternalBackingStoreBytes(
                          ExternalBackingStoreType::kArrayBuffer));
    } else if (identity() == NEW_SPACE) {
      CHECK(v8_flags.minor_ms);
      size_t bytes = heap()->array_buffer_sweeper()->young().BytesSlow();
      CHECK_EQ(bytes, ExternalBackingStoreBytes(
                          ExternalBackingStoreType::kArrayBuffer));
    }
  }

#ifdef DEBUG
  VerifyCountersAfterSweeping(isolate->heap());
#endif
}

void PagedSpaceBase::VerifyLiveBytes() const {
  MarkingState* marking_state = heap()->marking_state();
  PtrComprCageBase cage_base(heap()->isolate());
  for (const PageMetadata* page : *this) {
    CHECK(page->SweepingDone());
    int black_size = 0;
    for (Tagged<HeapObject> object : HeapObjectRange(page)) {
      // All the interior pointers should be contained in the heap.
      if (marking_state->IsMarked(object)) {
        black_size += object->Size(cage_base);
      }
    }
    CHECK_LE(black_size, page->live_bytes());
  }
}
#endif  // VERIFY_HEAP

#ifdef DEBUG
void PagedSpaceBase::VerifyCountersAfterSweeping(Heap* heap) const {
  size_t total_capacity = 0;
  size_t total_allocated = 0;
  PtrComprCageBase cage_base(heap->isolate());
  for (const PageMetadata* page : *this) {
    DCHECK(page->SweepingDone());
    total_capacity += page->area_size();
    size_t real_allocated = 0;
    for (Tagged<HeapObject> object : HeapObjectRange(page)) {
      if (!IsFreeSpaceOrFiller(object)) {
        real_allocated +=
            ALIGN_TO_ALLOCATION_ALIGNMENT(object->Size(cage_base));
      }
    }
    total_allocated += page->allocated_bytes();
    // The real size can be smaller than the accounted size if array trimming,
    // object slack tracking happened after sweeping.
    DCHECK_LE(real_allocated, accounting_stats_.AllocatedOnPage(page));
    DCHECK_EQ(page->allocated_bytes(), accounting_stats_.AllocatedOnPage(page));
  }
  DCHECK_EQ(total_capacity, accounting_stats_.Capacity());
  DCHECK_EQ(total_allocated, accounting_stats_.Size());
}

void PagedSpaceBase::VerifyCountersBeforeConcurrentSweeping() const {
  size_t total_capacity = 0;
  size_t total_allocated = 0;
  for (const PageMetadata* page : *this) {
    size_t page_allocated =
        page->SweepingDone() ? page->allocated_bytes() : page->live_bytes();
    total_capacity += page->area_size();
    total_allocated += page_allocated;
    DCHECK_EQ(page_allocated, accounting_stats_.AllocatedOnPage(page));
  }
  DCHECK_EQ(total_capacity, accounting_stats_.Capacity());
  DCHECK_EQ(total_allocated, accounting_stats_.Size());
}
#endif

void PagedSpaceBase::AddRangeToActiveSystemPages(PageMetadata* page,
                                                 Address start, Address end) {
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

void PagedSpaceBase::ReduceActiveSystemPages(
    PageMetadata* page, ActiveSystemPages active_system_pages) {
  const size_t reduced_pages =
      page->active_system_pages()->Reduce(active_system_pages);
  DecrementCommittedPhysicalMemory(reduced_pages *
                                   MemoryAllocator::GetCommitPageSize());
}

void PagedSpaceBase::UnlinkFreeListCategories(PageMetadata* page) {
  DCHECK_EQ(this, page->owner());
  page->ForAllFreeListCategories([this](FreeListCategory* category) {
    free_list()->RemoveCategory(category);
  });
}

size_t PagedSpaceBase::RelinkFreeListCategories(PageMetadata* page) {
  DCHECK_EQ(this, page->owner());
  size_t added = 0;
  page->ForAllFreeListCategories([this, &added](FreeListCategory* category) {
    added += category->available();
    category->Relink(free_list());
  });
  free_list()->increase_wasted_bytes(page->wasted_memory());

  DCHECK_IMPLIES(!page->Chunk()->IsFlagSet(MemoryChunk::NEVER_ALLOCATE_ON_PAGE),
                 page->AvailableInFreeList() ==
                     page->AvailableInFreeListFromAllocatedBytes());
  return added;
}

void PagedSpaceBase::RefillFreeList() {
  // Any PagedSpace might invoke RefillFreeList.
  DCHECK(identity() == OLD_SPACE || identity() == CODE_SPACE ||
         identity() == SHARED_SPACE || identity() == NEW_SPACE ||
         identity() == TRUSTED_SPACE);
  DCHECK_IMPLIES(identity() == NEW_SPACE, heap_->IsMainThread());
  DCHECK(!is_compaction_space());

  for (PageMetadata* p : heap()->sweeper()->GetAllSweptPagesSafe(this)) {
    // We regularly sweep NEVER_ALLOCATE_ON_PAGE pages. We drop the freelist
    // entries here to make them unavailable for allocations.
    if (p->Chunk()->IsFlagSet(MemoryChunk::NEVER_ALLOCATE_ON_PAGE)) {
      free_list_->EvictFreeListItems(p);
    }

    ConcurrentAllocationMutex guard(this);
    DCHECK_EQ(this, p->owner());
    RefineAllocatedBytesAfterSweeping(p);
    RelinkFreeListCategories(p);
  }
}

AllocatorPolicy* PagedSpace::CreateAllocatorPolicy(MainAllocator* allocator) {
  return new PagedSpaceAllocatorPolicy(this, allocator);
}

// -----------------------------------------------------------------------------
// CompactionSpace implementation

void CompactionSpace::NotifyNewPage(PageMetadata* page) {
  // Incremental marking can be running on the main thread isolate, so when
  // allocating a new page for the client's compaction space we can get a black
  // allocated page. This is fine, since the page is not observed the main
  // isolate until it's merged.
  DCHECK_IMPLIES(identity() != SHARED_SPACE ||
                     destination_heap() != DestinationHeap::kSharedSpaceHeap,
                 !page->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));
  new_pages_.push_back(page);
}

void CompactionSpace::RefillFreeList() {
  DCHECK_NE(NEW_SPACE, identity());

  Sweeper* sweeper = heap()->sweeper();
  size_t added = 0;
  PageMetadata* p = nullptr;
  while ((added <= kCompactionMemoryWanted) &&
         (p = sweeper->GetSweptPageSafe(this))) {
    // We regularly sweep NEVER_ALLOCATE_ON_PAGE pages. We drop the freelist
    // entries here to make them unavailable for allocations.
    if (p->Chunk()->IsFlagSet(MemoryChunk::NEVER_ALLOCATE_ON_PAGE)) {
      free_list()->EvictFreeListItems(p);
    }

    // Only during compaction pages can actually change ownership. This is
    // safe because there exists no other competing action on the page links
    // during compaction.
    DCHECK_NE(this, p->owner());
    PagedSpace* owner = static_cast<PagedSpace*>(p->owner());
    base::MutexGuard guard(owner->mutex());
    owner->RefineAllocatedBytesAfterSweeping(p);
    owner->RemovePage(p);
    added += AddPage(p);
    added += p->wasted_memory();
  }
}

CompactionSpaceCollection::CompactionSpaceCollection(
    Heap* heap, CompactionSpaceKind compaction_space_kind)
    : old_space_(heap, OLD_SPACE, Executability::NOT_EXECUTABLE,
                 compaction_space_kind,
                 CompactionSpace::DestinationHeap::kSameHeap),
      code_space_(heap, CODE_SPACE, Executability::EXECUTABLE,
                  compaction_space_kind,
                  CompactionSpace::DestinationHeap::kSameHeap),
      trusted_space_(heap, TRUSTED_SPACE, Executability::NOT_EXECUTABLE,
                     compaction_space_kind,
                     CompactionSpace::DestinationHeap::kSameHeap) {
  if (heap->isolate()->has_shared_space()) {
    const CompactionSpace::DestinationHeap dest_heap =
        heap->isolate()->is_shared_space_isolate()
            ? CompactionSpace::DestinationHeap::kSameHeap
            : CompactionSpace::DestinationHeap::kSharedSpaceHeap;
    shared_space_.emplace(heap->isolate()->shared_space_isolate()->heap(),
                          SHARED_SPACE, Executability::NOT_EXECUTABLE,
                          compaction_space_kind, dest_heap);
  }
}

// -----------------------------------------------------------------------------
// OldSpace implementation

void OldSpace::AddPromotedPage(PageMetadata* page) {
  if (v8_flags.minor_ms) {
    // Reset the page's allocated bytes. The page will be swept and the
    // allocated bytes will be updated to match the live bytes.
    DCHECK_EQ(page->area_size(), page->allocated_bytes());
    page->DecreaseAllocatedBytes(page->area_size());
  }
  AddPageImpl(page);
  if (!v8_flags.minor_ms) {
    RelinkFreeListCategories(page);
  }
}

void OldSpace::ReleasePage(PageMetadata* page) {
  ReleasePageImpl(page, MemoryAllocator::FreeMode::kPool);
}

// -----------------------------------------------------------------------------
// StickySpace implementation

void StickySpace::AdjustDifferenceInAllocatedBytes(size_t diff) {
  DCHECK_GE(allocated_old_size_, diff);
  allocated_old_size_ -= diff;
}

// -----------------------------------------------------------------------------
// SharedSpace implementation

void SharedSpace::ReleasePage(PageMetadata* page) {
  // Old-to-new slots in old objects may be overwritten with references to
  // shared objects. Postpone releasing empty pages so that updating old-to-new
  // slots in dead old objects may access the dead shared objects.
  ReleasePageImpl(page, MemoryAllocator::FreeMode::kPostpone);
}

}  // namespace internal
}  // namespace v8
```