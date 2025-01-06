Response: The user wants a summary of the C++ source code file `v8/src/heap/paged-spaces.cc`.
The summary should describe the functionality of the code.
If the code relates to Javascript, the summary should include an example in Javascript.

Looking at the includes and the class names like `PagedSpaceBase`, `OldSpace`, `NewSpace`, `CodeSpace`, `FreeList`, it seems this file is about managing memory in V8's heap, specifically using a paged approach.

Key functionalities seem to include:
- Managing pages of memory.
- Tracking free space within these pages using a free list.
- Handling allocation and deallocation of memory within these pages.
- Supporting different types of memory spaces (e.g., old generation, new generation, code).
- Interacting with the garbage collector (sweeping, compaction).

The connection to Javascript lies in the fact that V8 is the Javascript engine for Chrome and Node.js. This code manages the memory where Javascript objects are stored.

Let's break down the major classes and their apparent roles:

- `PagedSpaceBase`: Seems like the base class for all paged spaces, providing common functionalities like adding/removing pages, tracking allocated memory, managing the free list.
- `PagedSpaceObjectIterator`:  An iterator to traverse objects within a paged space.
- `OldSpace`, `NewSpace`, `CodeSpace`, `SharedSpace`, `TrustedSpace`, `StickySpace`:  Represent different areas of the heap with potentially different allocation strategies or lifetimes for objects.
- `CompactionSpace`, `CompactionSpaceCollection`: Related to the memory compaction process.
- `FreeList`:  A data structure to keep track of available free blocks within pages.

Now, for the Javascript example. Consider a scenario where Javascript creates objects. These objects need to be stored in memory managed by this C++ code. When garbage collection occurs, this code is involved in identifying and freeing up unused memory.

Example:

```javascript
let myObject = { a: 1, b: "hello" }; // Javascript object allocated in V8's heap.
let myFunction = function() { console.log("world"); }; // Javascript function, also an object.

// After some time, if myObject is no longer reachable, the garbage collector
// (which interacts with this C++ code) will reclaim the memory occupied by myObject.
myObject = null;
```

This Javascript code directly leads to memory allocation and deallocation within the V8 heap, which is managed by the C++ code in this file. The different spaces (OldSpace, NewSpace, etc.) might be used based on the object's age and characteristics.
`v8/src/heap/paged-spaces.cc` 文件是 V8 JavaScript 引擎中负责管理**分页内存空间**的核心组件。它定义了用于组织和操作堆内存的各种分页空间，这些空间是 V8 存储 JavaScript 对象的主要场所。

**主要功能归纳:**

1. **定义和管理不同类型的分页内存空间:**
   - 文件中定义了 `PagedSpaceBase` 作为所有分页空间的基础类，提供了诸如添加/移除内存页、跟踪已分配内存、管理空闲列表等通用功能。
   - 派生自 `PagedSpaceBase` 的类，如 `OldSpace` (老生代空间)、`NewSpace` (新生代空间)、`CodeSpace` (代码空间)、`SharedSpace` (共享空间)、`TrustedSpace` 和 `StickySpace`，代表了堆内存的不同区域，用于存储具有不同生命周期和特性的 JavaScript 对象。例如，新生代空间用于存放新创建的临时对象，而老生代空间则存放经过多次垃圾回收仍然存活的对象。代码空间则专门用于存放编译后的 JavaScript 代码。
   - `CompactionSpace` 和 `CompactionSpaceCollection` 用于支持内存压缩过程，将存活对象整理到一起，减少内存碎片。

2. **内存页的管理:**
   - 文件负责内存页的分配、初始化、释放和管理。它维护了每个分页空间拥有的内存页列表。
   - `InitializePage` 函数用于初始化新分配的内存页，包括设置元数据和分配空闲列表的分类。
   - `AddPage` 和 `RemovePage` 函数用于向分页空间添加和移除内存页。

3. **空闲列表的管理:**
   - 每个分页空间都关联着一个 `FreeList`，用于跟踪内存页中可用的空闲内存块。
   - `RefillFreeList` 函数用于在垃圾回收后重新填充空闲列表，使得可用的空闲内存可以被分配。
   - `UnlinkFreeListCategories` 和 `RelinkFreeListCategories` 用于在添加或移除页面时更新空闲列表的结构。

4. **内存分配和释放的辅助功能:**
   - 提供了用于获取分页空间中对象迭代器的 `GetObjectIterator` 函数。
   - 提供了跟踪已提交物理内存的功能，并根据页面的添加和移除进行调整。
   - `ShrinkPageToHighWaterMark` 用于将页面缩小到其高水位线，释放未使用的内存。

5. **与垃圾回收的交互:**
   - 文件中的代码与 V8 的垃圾回收器紧密相关。例如，在垃圾回收的标记和清除阶段，需要遍历分页空间中的对象。
   - `RefineAllocatedBytesAfterSweeping` 函数在垃圾回收的清除阶段之后更新已分配字节的计数。
   - `MergeCompactionSpace` 函数用于将压缩空间中的页面合并回原始空间。

6. **提供调试和验证功能:**
   - 文件中包含了一些用于调试和验证堆状态的函数，例如 `Verify` 和 `VerifyLiveBytes`。

**与 Javascript 功能的关系以及 Javascript 示例:**

该文件直接负责 V8 引擎中 JavaScript 对象的内存管理。每当你在 JavaScript 中创建对象、函数、数组等时，V8 引擎就会从这些分页空间中分配内存来存储它们。垃圾回收机制也依赖于这里的代码来回收不再使用的内存。

**Javascript 示例:**

```javascript
// 当你在 Javascript 中创建一个对象时，V8 会在堆内存中为其分配空间，
// 这个分配过程会涉及到 paged-spaces.cc 中定义的各种分页空间。
let myObject = { name: "example", value: 123 };

// 创建一个数组也会在堆内存中分配空间。
let myArray = [1, 2, 3, 4, 5];

// 函数也是对象，同样需要在堆内存中分配空间。
function myFunction() {
  console.log("Hello");
}

// 当对象不再被引用时，垃圾回收器（与 paged-spaces.cc 协同工作）
// 会回收这些对象占用的内存。
myObject = null;
myArray = null;
myFunction = null;

// 字符串也是对象，存储在堆内存中。
let myString = "This is a string";
```

**更具体地，不同的分页空间可能用于存储不同类型的 JavaScript 对象:**

- **NewSpace (新生代):**  通常用于存储新创建的、生命周期较短的对象。当新生代空间满时，会触发 Minor GC (Scavenge 垃圾回收)。
- **OldSpace (老生代):**  存储经过多次 Minor GC 仍然存活的对象，或者生命周期较长的对象。当老生代空间满时，会触发 Major GC (Mark-Sweep 或 Mark-Compact 垃圾回收)。
- **CodeSpace (代码空间):**  用于存储 JIT (Just-In-Time) 编译器生成的机器码。
- **SharedSpace (共享空间):**  在启用了共享堆的情况下使用，用于存储多个 Isolate 可以共享的对象。

总而言之，`v8/src/heap/paged-spaces.cc` 是 V8 引擎堆内存管理的核心，它定义了内存的组织结构和管理机制，直接支撑着 JavaScript 程序的运行和内存回收。 你在 JavaScript 中操作的每一个对象，背后都有这个 C++ 文件中定义的机制在默默地工作。

Prompt: 
```
这是目录为v8/src/heap/paged-spaces.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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

"""

```