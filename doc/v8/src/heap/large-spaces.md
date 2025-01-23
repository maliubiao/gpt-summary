Response: The user wants to understand the functionality of the `large-spaces.cc` file in the V8 JavaScript engine. I need to:

1. **Summarize the core purpose** of this file.
2. **Explain its relationship to JavaScript**, focusing on how it enables certain JavaScript behaviors.
3. **Provide illustrative JavaScript examples** to connect the C++ implementation to observable JavaScript features.

Based on the code, the file manages the allocation and organization of "large objects" in the V8 heap. These are objects that are too big to fit into the regular heap pages.

Here's a breakdown of the code and its relation to JavaScript:

- **`LargeObjectSpace`**: The base class for managing large object spaces. It handles adding, removing, and iterating over large object pages.
- **`OldLargeObjectSpace`**:  Manages large objects in the old generation heap.
- **`NewLargeObjectSpace`**: Manages large objects during their initial allocation in the young generation heap. These objects might later be promoted to the old generation.
- **`CodeLargeObjectSpace`**:  A specialized space for large code objects, which need executable memory.
- **`SharedLargeObjectSpace`**, **`SharedTrustedLargeObjectSpace`**, **`TrustedLargeObjectSpace`**: Manage shared and trusted large objects, likely related to shared contexts and security.
- **Allocation and Deallocation**: The code handles the allocation (`AllocateRaw`, `AllocateLargePage`) and deallocation (`Free`, `ShrinkPageToObjectSize`, `FreeDeadObjects`) of these large objects.
- **Memory Management**: Concepts like committed memory, page management (`LargePageMetadata`), and interaction with the memory allocator are present.
- **Garbage Collection Integration**:  The code interacts with the garbage collection system (incremental marking, concurrent marking) to manage the lifecycle of large objects.
- **Allocation Observers**: The system allows for observing object allocations.

**Relationship to JavaScript:**

Large object spaces are crucial for handling large data structures in JavaScript, such as:

- **Large arrays and typed arrays**:  When a JavaScript array or typed array becomes very large, V8 allocates its backing store in a large object space.
- **Large strings**: Similar to arrays, very long strings might reside in large object spaces.
- **Wasm memory**:  The memory used by WebAssembly modules is allocated in the large object space.
- **Code objects**: Compiled JavaScript functions and WebAssembly code are also stored as large objects.

**JavaScript Examples:**

I can create JavaScript examples that would likely trigger the allocation of objects in the large object space.
`v8/src/heap/large-spaces.cc` 文件是 V8 JavaScript 引擎中负责管理**大对象空间 (Large Object Space)** 的源代码文件。它的主要功能是：

**核心功能：管理在堆中无法放入常规大小页面的大型对象。**

具体来说，这个文件定义了以下关键类和功能：

1. **`LargeObjectSpace` 基类:**
   - 定义了所有大对象空间共享的基本属性和行为，例如：
     - 维护一个由 `LargePageMetadata` 组成的链表，每个 `LargePageMetadata` 代表一个包含单个大对象的内存块。
     - 跟踪大对象空间的总大小、对象数量和已分配的物理内存。
     - 提供添加、删除和迭代大对象页面的方法。
     - 处理分配观察者 (Allocation Observers) 的添加和移除。
     - 提供检查一个对象是否属于该大对象空间的方法 (`Contains`)。
     - 提供获取大对象迭代器的方法 (`GetObjectIterator`)。

2. **`OldLargeObjectSpace` 类:**
   - 继承自 `LargeObjectSpace`，专门用于管理**旧生代 (Old Generation)** 中的大对象。
   - 提供了分配原始内存的方法 (`AllocateRaw`)，用于在旧生代中分配大对象。
   - 处理大对象的晋升 (Promotion) 过程，例如从新生代大对象空间晋升到旧生代大对象空间 (`PromoteNewLargeObject`)。

3. **`NewLargeObjectSpace` 类:**
   - 继承自 `LargeObjectSpace`，专门用于管理**新生代 (New Generation)** 中的大对象。
   - 与 `OldLargeObjectSpace` 类似，也提供了 `AllocateRaw` 方法用于分配。
   - 引入了容量 (capacity) 的概念，用于限制新生代大对象空间的大小。
   - 提供了 `Flip` 方法，这通常与 Scavenge 垃圾回收过程相关，用于切换 From-space 和 To-space。
   - 提供了 `FreeDeadObjects` 方法，用于回收不再使用的死对象。
   - 提供了设置容量的方法 (`SetCapacity`).

4. **`CodeLargeObjectSpace` 类:**
   - 继承自 `OldLargeObjectSpace`，专门用于管理**代码对象**（例如编译后的 JavaScript 函数和 WebAssembly 代码）等大型可执行对象。
   - 在分配时，会确保分配的内存具有可执行权限。
   - 在添加和移除页面时，会通知 `Isolate` 对象，以便跟踪代码内存。

5. **`SharedLargeObjectSpace`、`SharedTrustedLargeObjectSpace`、`TrustedLargeObjectSpace` 类:**
   - 继承自 `OldLargeObjectSpace`，用于管理不同类型的共享和受信任的大对象，可能与共享上下文和安全有关。

**与 JavaScript 功能的关系及 JavaScript 示例：**

大对象空间的存在使得 V8 能够高效地处理 JavaScript 中需要大量内存的对象，例如：

* **大型数组和类型化数组 (Typed Arrays):** 当 JavaScript 创建非常大的数组或类型化数组时，V8 会将其底层存储分配在大对象空间中，因为这些对象的大小可能超过常规页面大小的限制。

```javascript
// 创建一个非常大的数组
const largeArray = new Array(1000000);

// 创建一个大型的 Uint32Array 类型化数组
const largeTypedArray = new Uint32Array(1000000);
```

* **大型字符串:** 类似地，当 JavaScript 中创建非常长的字符串时，V8 可能会将其存储在大对象空间中。

```javascript
// 创建一个非常长的字符串
let longString = "";
for (let i = 0; i < 100000; i++) {
  longString += "a";
}
```

* **WebAssembly 内存 (Wasm Memory):** 当加载 WebAssembly 模块时，其线性内存通常会分配在大对象空间中。

```javascript
// 假设你有一个 WebAssembly 模块的 ArrayBuffer
const wasmMemoryBuffer = new ArrayBuffer(1024 * 1024 * 100); // 100MB

// 这通常由 WebAssembly 引擎内部处理，但其内存分配会涉及到大对象空间
```

* **编译后的代码:**  V8 将编译后的 JavaScript 函数和 WebAssembly 代码存储在 `CodeLargeObjectSpace` 中。

```javascript
function myFunction(x) {
  return x * 2;
}

// 当 myFunction 被编译时，其机器码会被存储在 CodeLargeObjectSpace 中
```

**总结：**

`v8/src/heap/large-spaces.cc` 文件实现了 V8 堆中用于存储大型对象的机制。这对于 JavaScript 引擎高效地处理大型数据结构、WebAssembly 内存以及编译后的代码至关重要。如果没有大对象空间，V8 将难以管理这些大型内存需求，并可能导致性能问题或内存溢出。 JavaScript 开发者通常不需要直接与大对象空间交互，但他们的代码（特别是处理大量数据或使用 WebAssembly 时）会间接地利用这一机制。

### 提示词
```
这是目录为v8/src/heap/large-spaces.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/large-spaces.h"

#include "src/base/logging.h"
#include "src/base/platform/mutex.h"
#include "src/base/sanitizer/msan.h"
#include "src/common/globals.h"
#include "src/execution/isolate.h"
#include "src/heap/combined-heap.h"
#include "src/heap/concurrent-marking.h"
#include "src/heap/heap-verifier.h"
#include "src/heap/incremental-marking.h"
#include "src/heap/large-page-metadata.h"
#include "src/heap/list.h"
#include "src/heap/marking-state-inl.h"
#include "src/heap/marking.h"
#include "src/heap/memory-allocator.h"
#include "src/heap/memory-chunk-layout.h"
#include "src/heap/mutable-page-metadata-inl.h"
#include "src/heap/remembered-set.h"
#include "src/heap/slot-set.h"
#include "src/heap/spaces-inl.h"
#include "src/logging/log.h"
#include "src/objects/objects-inl.h"
#include "src/utils/ostreams.h"

namespace v8 {
namespace internal {

// -----------------------------------------------------------------------------
// LargeObjectSpaceObjectIterator

LargeObjectSpaceObjectIterator::LargeObjectSpaceObjectIterator(
    LargeObjectSpace* space) {
  current_ = space->first_page();
}

Tagged<HeapObject> LargeObjectSpaceObjectIterator::Next() {
  while (current_ != nullptr) {
    Tagged<HeapObject> object = current_->GetObject();
    current_ = current_->next_page();
    if (!IsFreeSpaceOrFiller(object)) return object;
  }
  return Tagged<HeapObject>();
}

// -----------------------------------------------------------------------------
// OldLargeObjectSpace

LargeObjectSpace::LargeObjectSpace(Heap* heap, AllocationSpace id)
    : Space(heap, id, nullptr),
      size_(0),
      page_count_(0),
      objects_size_(0),
      pending_object_(0) {}

size_t LargeObjectSpace::Available() const {
  // We return zero here since we cannot take advantage of already allocated
  // large object memory.
  return 0;
}

void LargeObjectSpace::TearDown() {
  while (!memory_chunk_list_.Empty()) {
    LargePageMetadata* page = first_page();
    LOG(heap()->isolate(),
        DeleteEvent("LargeObjectChunk",
                    reinterpret_cast<void*>(page->ChunkAddress())));
    memory_chunk_list_.Remove(page);
    heap()->memory_allocator()->Free(MemoryAllocator::FreeMode::kImmediately,
                                     page);
  }
}

void LargeObjectSpace::AdvanceAndInvokeAllocationObservers(Address soon_object,
                                                           size_t object_size) {
  if (!heap()->IsAllocationObserverActive()) return;

  if (object_size >= allocation_counter_.NextBytes()) {
    // Ensure that there is a valid object
    heap_->CreateFillerObjectAt(soon_object, static_cast<int>(object_size));

    allocation_counter_.InvokeAllocationObservers(soon_object, object_size,
                                                  object_size);
  }

  // Large objects can be accounted immediately since no LAB is involved.
  allocation_counter_.AdvanceAllocationObservers(object_size);
}

void LargeObjectSpace::AddAllocationObserver(AllocationObserver* observer) {
  allocation_counter_.AddAllocationObserver(observer);
}

void LargeObjectSpace::RemoveAllocationObserver(AllocationObserver* observer) {
  allocation_counter_.RemoveAllocationObserver(observer);
}

AllocationResult OldLargeObjectSpace::AllocateRaw(LocalHeap* local_heap,
                                                  int object_size) {
  return AllocateRaw(local_heap, object_size, NOT_EXECUTABLE);
}

AllocationResult OldLargeObjectSpace::AllocateRaw(LocalHeap* local_heap,
                                                  int object_size,
                                                  Executability executable) {
  object_size = ALIGN_TO_ALLOCATION_ALIGNMENT(object_size);
  DCHECK_IMPLIES(identity() == SHARED_LO_SPACE,
                 !allocation_counter_.HasAllocationObservers());
  DCHECK_IMPLIES(identity() == SHARED_LO_SPACE,
                 pending_object() == kNullAddress);

  // Check if we want to force a GC before growing the old space further.
  // If so, fail the allocation.
  if (!heap()->ShouldExpandOldGenerationOnSlowAllocation(
          local_heap, AllocationOrigin::kRuntime) ||
      !heap()->CanExpandOldGeneration(object_size)) {
    return AllocationResult::Failure();
  }

  heap()->StartIncrementalMarkingIfAllocationLimitIsReached(
      local_heap, heap()->GCFlagsForIncrementalMarking(),
      kGCCallbackScheduleIdleGarbageCollection);

  LargePageMetadata* page = AllocateLargePage(object_size, executable);
  if (page == nullptr) return AllocationResult::Failure();
  Tagged<HeapObject> object = page->GetObject();
  if (local_heap->is_main_thread() && identity() != SHARED_LO_SPACE) {
    UpdatePendingObject(object);
  }
  if (v8_flags.sticky_mark_bits ||
      heap()->incremental_marking()->black_allocation()) {
    heap()->marking_state()->TryMarkAndAccountLiveBytes(object, object_size);
  }
  DCHECK_IMPLIES(heap()->incremental_marking()->black_allocation(),
                 heap()->marking_state()->IsMarked(object));
  page->Chunk()->InitializationMemoryFence();
  heap()->NotifyOldGenerationExpansion(local_heap, identity(), page);

  if (local_heap->is_main_thread() && identity() != SHARED_LO_SPACE) {
    AdvanceAndInvokeAllocationObservers(object.address(),
                                        static_cast<size_t>(object_size));
  }
  return AllocationResult::FromObject(object);
}

LargePageMetadata* LargeObjectSpace::AllocateLargePage(
    int object_size, Executability executable) {
  base::MutexGuard expansion_guard(heap_->heap_expansion_mutex());

  if (identity() != NEW_LO_SPACE &&
      !heap()->IsOldGenerationExpansionAllowed(object_size, expansion_guard)) {
    return nullptr;
  }

  LargePageMetadata* page = heap()->memory_allocator()->AllocateLargePage(
      this, object_size, executable);
  if (page == nullptr) return nullptr;
  DCHECK_GE(page->area_size(), static_cast<size_t>(object_size));

  {
    base::RecursiveMutexGuard guard(&allocation_mutex_);
    AddPage(page, object_size);
  }

  return page;
}

size_t LargeObjectSpace::CommittedPhysicalMemory() const {
  // On a platform that provides lazy committing of memory, we over-account
  // the actually committed memory. There is no easy way right now to support
  // precise accounting of committed memory in large object space.
  return CommittedMemory();
}

void OldLargeObjectSpace::PromoteNewLargeObject(LargePageMetadata* page) {
  MemoryChunk* chunk = page->Chunk();
  DCHECK_EQ(page->owner_identity(), NEW_LO_SPACE);
  DCHECK(chunk->IsLargePage());
  DCHECK(chunk->IsFlagSet(MemoryChunk::FROM_PAGE));
  DCHECK(!chunk->IsFlagSet(MemoryChunk::TO_PAGE));
  PtrComprCageBase cage_base(heap()->isolate());
  static_cast<LargeObjectSpace*>(page->owner())->RemovePage(page);
  chunk->ClearFlagNonExecutable(MemoryChunk::FROM_PAGE);
  chunk->SetOldGenerationPageFlags(
      heap()->incremental_marking()->marking_mode(), LO_SPACE);
  AddPage(page, static_cast<size_t>(page->GetObject()->Size(cage_base)));
}

void LargeObjectSpace::AddPage(LargePageMetadata* page, size_t object_size) {
  size_ += static_cast<int>(page->size());
  AccountCommitted(page->size());
  objects_size_ += object_size;
  page_count_++;
  memory_chunk_list_.PushBack(page);
  page->set_owner(this);
  ForAll<ExternalBackingStoreType>(
      [this, page](ExternalBackingStoreType type, int index) {
        IncrementExternalBackingStoreBytes(
            type, page->ExternalBackingStoreBytes(type));
      });
}

void LargeObjectSpace::RemovePage(LargePageMetadata* page) {
  size_ -= static_cast<int>(page->size());
  AccountUncommitted(page->size());
  page_count_--;
  memory_chunk_list_.Remove(page);
  page->set_owner(nullptr);
  ForAll<ExternalBackingStoreType>(
      [this, page](ExternalBackingStoreType type, int index) {
        DecrementExternalBackingStoreBytes(
            type, page->ExternalBackingStoreBytes(type));
      });
}

void LargeObjectSpace::ShrinkPageToObjectSize(LargePageMetadata* page,
                                              Tagged<HeapObject> object,
                                              size_t object_size) {
  MemoryChunk* chunk = page->Chunk();
#ifdef DEBUG
  PtrComprCageBase cage_base(heap()->isolate());
  DCHECK_EQ(object, page->GetObject());
  DCHECK_EQ(object_size, page->GetObject()->Size(cage_base));
  DCHECK_EQ(chunk->executable(), NOT_EXECUTABLE);
#endif  // DEBUG

  const size_t used_committed_size =
      ::RoundUp(chunk->Offset(object.address()) + object_size,
                MemoryAllocator::GetCommitPageSize());

  // Object shrunk since last GC.
  if (object_size < page->area_size()) {
    page->ClearOutOfLiveRangeSlots(object.address() + object_size);
    const Address new_area_end = page->area_start() + object_size;

    // Object shrunk enough that we can even free some OS pages.
    if (used_committed_size < page->size()) {
      const size_t bytes_to_free = page->size() - used_committed_size;
      heap()->memory_allocator()->PartialFreeMemory(
          page, chunk->address() + used_committed_size, bytes_to_free,
          new_area_end);
      size_ -= bytes_to_free;
      AccountUncommitted(bytes_to_free);
    } else {
      // Can't free OS page but keep object area up-to-date.
      page->set_area_end(new_area_end);
    }
  }

  DCHECK_EQ(used_committed_size, page->size());
  DCHECK_EQ(object_size, page->area_size());
}

bool LargeObjectSpace::Contains(Tagged<HeapObject> object) const {
  MemoryChunkMetadata* chunk = MemoryChunkMetadata::FromHeapObject(object);

  bool owned = (chunk->owner() == this);

  SLOW_DCHECK(!owned || ContainsSlow(object.address()));

  return owned;
}

bool LargeObjectSpace::ContainsSlow(Address addr) const {
  MemoryChunk* chunk = MemoryChunk::FromAddress(addr);
  for (const LargePageMetadata* page : *this) {
    if (page->Chunk() == chunk) return true;
  }
  return false;
}

std::unique_ptr<ObjectIterator> LargeObjectSpace::GetObjectIterator(
    Heap* heap) {
  return std::unique_ptr<ObjectIterator>(
      new LargeObjectSpaceObjectIterator(this));
}

#ifdef VERIFY_HEAP
// We do not assume that the large object iterator works, because it depends
// on the invariants we are checking during verification.
void LargeObjectSpace::Verify(Isolate* isolate,
                              SpaceVerificationVisitor* visitor) const {
  size_t external_backing_store_bytes[static_cast<int>(
      ExternalBackingStoreType::kNumValues)] = {0};

  PtrComprCageBase cage_base(isolate);
  for (const LargePageMetadata* chunk = first_page(); chunk != nullptr;
       chunk = chunk->next_page()) {
    visitor->VerifyPage(chunk);

    // Each chunk contains an object that starts at the large object page's
    // object area start.
    Tagged<HeapObject> object = chunk->GetObject();
    PageMetadata* page = PageMetadata::FromHeapObject(object);
    CHECK(object.address() == page->area_start());

    // Only certain types may be in the large object space:
#define V(Name) Is##Name(object, cage_base) ||
    const bool is_valid_lo_space_object =
        DYNAMICALLY_SIZED_HEAP_OBJECT_LIST(V) false;
#undef V
    if (!is_valid_lo_space_object) {
      i::Print(object);
      FATAL("Found invalid Object (instance_type=%i) in large object space.",
            object->map(cage_base)->instance_type());
    }

    // Invoke visitor on each object.
    visitor->VerifyObject(object);

    ForAll<ExternalBackingStoreType>(
        [chunk, &external_backing_store_bytes](ExternalBackingStoreType type,
                                               int index) {
          external_backing_store_bytes[index] +=
              chunk->ExternalBackingStoreBytes(type);
        });

    visitor->VerifyPageDone(chunk);
  }
  ForAll<ExternalBackingStoreType>(
      [this, external_backing_store_bytes](ExternalBackingStoreType type,
                                           int index) {
        CHECK_EQ(external_backing_store_bytes[index],
                 ExternalBackingStoreBytes(type));
      });
}
#endif

#ifdef DEBUG
void LargeObjectSpace::Print() {
  StdoutStream os;
  LargeObjectSpaceObjectIterator it(this);
  for (Tagged<HeapObject> obj = it.Next(); !obj.is_null(); obj = it.Next()) {
    i::Print(obj, os);
  }
}
#endif  // DEBUG

void LargeObjectSpace::UpdatePendingObject(Tagged<HeapObject> object) {
  base::SharedMutexGuard<base::kExclusive> guard(&pending_allocation_mutex_);
  pending_object_.store(object.address(), std::memory_order_release);
}

OldLargeObjectSpace::OldLargeObjectSpace(Heap* heap)
    : LargeObjectSpace(heap, LO_SPACE) {}

OldLargeObjectSpace::OldLargeObjectSpace(Heap* heap, AllocationSpace id)
    : LargeObjectSpace(heap, id) {}

NewLargeObjectSpace::NewLargeObjectSpace(Heap* heap, size_t capacity)
    : LargeObjectSpace(heap, NEW_LO_SPACE), capacity_(capacity) {}

AllocationResult NewLargeObjectSpace::AllocateRaw(LocalHeap* local_heap,
                                                  int object_size) {
  object_size = ALIGN_TO_ALLOCATION_ALIGNMENT(object_size);
  DCHECK(local_heap->is_main_thread());
  // Do not allocate more objects if promoting the existing object would exceed
  // the old generation capacity.
  if (!heap()->CanExpandOldGeneration(SizeOfObjects())) {
    return AllocationResult::Failure();
  }

  // Allocation for the first object must succeed independent from the capacity.
  if (SizeOfObjects() > 0 && static_cast<size_t>(object_size) > Available()) {
    if (!v8_flags.separate_gc_phases ||
        !heap()->ShouldExpandYoungGenerationOnSlowAllocation(object_size)) {
      return AllocationResult::Failure();
    }
  }

  LargePageMetadata* page = AllocateLargePage(object_size, NOT_EXECUTABLE);
  if (page == nullptr) return AllocationResult::Failure();

  // The size of the first object may exceed the capacity.
  capacity_ = std::max(capacity_, SizeOfObjects());

  Tagged<HeapObject> result = page->GetObject();
  MemoryChunk* chunk = page->Chunk();
  chunk->SetFlagNonExecutable(MemoryChunk::TO_PAGE);
  UpdatePendingObject(result);
  if (v8_flags.minor_ms) {
    page->ClearLiveness();
  }
  chunk->InitializationMemoryFence();
  DCHECK(chunk->IsLargePage());
  DCHECK_EQ(page->owner_identity(), NEW_LO_SPACE);
  AdvanceAndInvokeAllocationObservers(result.address(),
                                      static_cast<size_t>(object_size));
  return AllocationResult::FromObject(result);
}

size_t NewLargeObjectSpace::Available() const {
  DCHECK_GE(capacity_, SizeOfObjects());
  return capacity_ - SizeOfObjects();
}

void NewLargeObjectSpace::Flip() {
  for (LargePageMetadata* page = first_page(); page != nullptr;
       page = page->next_page()) {
    MemoryChunk* chunk = page->Chunk();
    chunk->SetFlagNonExecutable(MemoryChunk::FROM_PAGE);
    chunk->ClearFlagNonExecutable(MemoryChunk::TO_PAGE);
  }
}

void NewLargeObjectSpace::FreeDeadObjects(
    const std::function<bool(Tagged<HeapObject>)>& is_dead) {
  bool is_marking = heap()->incremental_marking()->IsMarking();
  DCHECK_IMPLIES(v8_flags.minor_ms, !is_marking);
  DCHECK_IMPLIES(is_marking, heap()->incremental_marking()->IsMajorMarking());
  size_t surviving_object_size = 0;
  PtrComprCageBase cage_base(heap()->isolate());
  for (auto it = begin(); it != end();) {
    LargePageMetadata* page = *it;
    it++;
    Tagged<HeapObject> object = page->GetObject();
    if (is_dead(object)) {
      RemovePage(page);
      if (v8_flags.concurrent_marking && is_marking) {
        heap()->concurrent_marking()->ClearMemoryChunkData(page);
      }
      heap()->memory_allocator()->Free(MemoryAllocator::FreeMode::kImmediately,
                                       page);
    } else {
      surviving_object_size += static_cast<size_t>(object->Size(cage_base));
    }
  }
  // Right-trimming does not update the objects_size_ counter. We are lazily
  // updating it after every GC.
  objects_size_ = surviving_object_size;
}

void NewLargeObjectSpace::SetCapacity(size_t capacity) {
  capacity_ = std::max(capacity, SizeOfObjects());
}

CodeLargeObjectSpace::CodeLargeObjectSpace(Heap* heap)
    : OldLargeObjectSpace(heap, CODE_LO_SPACE) {}

AllocationResult CodeLargeObjectSpace::AllocateRaw(LocalHeap* local_heap,
                                                   int object_size) {
  return OldLargeObjectSpace::AllocateRaw(local_heap, object_size, EXECUTABLE);
}

void CodeLargeObjectSpace::AddPage(LargePageMetadata* page,
                                   size_t object_size) {
  OldLargeObjectSpace::AddPage(page, object_size);
}

void CodeLargeObjectSpace::RemovePage(LargePageMetadata* page) {
  heap()->isolate()->RemoveCodeMemoryChunk(page);
  OldLargeObjectSpace::RemovePage(page);
}

SharedLargeObjectSpace::SharedLargeObjectSpace(Heap* heap)
    : OldLargeObjectSpace(heap, SHARED_LO_SPACE) {}

SharedTrustedLargeObjectSpace::SharedTrustedLargeObjectSpace(Heap* heap)
    : OldLargeObjectSpace(heap, SHARED_TRUSTED_LO_SPACE) {}

TrustedLargeObjectSpace::TrustedLargeObjectSpace(Heap* heap)
    : OldLargeObjectSpace(heap, TRUSTED_LO_SPACE) {}

}  // namespace internal
}  // namespace v8
```