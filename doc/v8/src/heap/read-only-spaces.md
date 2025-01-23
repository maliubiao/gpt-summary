Response: Let's break down the thought process to analyze the C++ code and explain its functionality and relation to JavaScript.

1. **Understand the Goal:** The request asks for a summary of the C++ code's functionality and its connection to JavaScript, with a JavaScript example if a relationship exists.

2. **Initial Scan for Keywords and Namespaces:** Quickly scan the file for key terms and namespaces. We see:
    * `v8::internal` and `v8`: This immediately signals that the code is part of the V8 JavaScript engine's internal implementation.
    * `ReadOnlyArtifacts`, `ReadOnlySpace`, `SharedReadOnlySpace`: These class names strongly suggest the code deals with memory spaces that are read-only.
    * `heap`, `allocation`, `pages`, `metadata`: These words point to memory management concepts within the V8 heap.
    * `snapshot`, `deserialization`: These terms suggest this code plays a role in loading pre-built states of the JavaScript environment.

3. **Focus on Class Responsibilities:** Analyze the primary classes and their methods.

    * **`ReadOnlyArtifacts`:**  The name "artifacts" implies it manages a collection of read-only data. The methods `Initialize`, `ReinstallReadOnlySpace`, `VerifyHeapAndSpaceRelationships`, `InitializeChecksum`, and `VerifyChecksum` suggest it handles setup, integrity checks, and loading from snapshots. The destructor freeing pages further reinforces its role in managing memory.

    * **`ReadOnlySpace`:** This seems to represent the actual read-only memory space. Methods like `TearDown`, `DetachPagesAndAddToArtifacts`, `Seal`, `Unseal`, `AllocateRaw`, `ShrinkPages`, and iterators (`ReadOnlySpaceObjectIterator`) clearly point to memory management operations (allocation, deallocation, locking/unlocking, iteration). The presence of `top_` and `limit_` strongly indicates a linear allocation scheme.

    * **`SharedReadOnlySpace`:**  The "Shared" prefix indicates this is a variation of `ReadOnlySpace` that can be shared across multiple isolates or contexts. The `TearDown` method's different behavior compared to `ReadOnlySpace` confirms this.

4. **Identify Core Functionality:** Based on the class analysis, the primary function of the code is to manage read-only memory within the V8 heap. This involves:
    * **Allocation:**  Providing mechanisms to allocate immutable objects.
    * **Organization:**  Structuring the read-only memory into pages.
    * **Protection:**  Setting memory permissions to read-only after initialization.
    * **Sharing:** Enabling sharing of read-only data across different parts of the V8 engine.
    * **Initialization from Snapshots:**  Loading pre-built read-only data from snapshots for faster startup.
    * **Integrity:** Verifying the integrity of the read-only data using checksums.

5. **Connect to JavaScript:**  Consider *why* a read-only space is needed in a JavaScript engine. Think about the core components of the JavaScript environment:
    * **Built-in Objects:**  Objects like `Object.prototype`, `Array.prototype`, `String.prototype`, etc., are fundamental and should ideally be immutable.
    * **Global Objects:**  The global object (`window` in browsers, `global` in Node.js) and its properties.
    * **Pre-compiled Code/Bytecode:**  Parts of the JavaScript engine's internal code.

    The read-only space is where these immutable, shared elements of the JavaScript environment are stored. This improves performance (no need to copy them for each context) and security (prevents accidental modification).

6. **Formulate the JavaScript Example:** Now that we know the *purpose* of the read-only space, we can create a JavaScript example demonstrating its impact. The key is to highlight the immutability of these built-in objects. Trying to modify a property of a built-in prototype will demonstrate this.

7. **Refine the Explanation:** Structure the explanation logically:
    * Start with a concise summary.
    * Elaborate on the core classes and their roles.
    * Explain the connection to JavaScript and the benefits of a read-only space.
    * Provide the JavaScript example with a clear explanation of what it demonstrates.
    * Include relevant details like the use of snapshots and checksums.

8. **Review and Iterate:** Read through the generated explanation. Are there any ambiguities?  Is the language clear and concise?  Is the JavaScript example effective?  For example, initially, I might have just said "built-in objects are stored there." But elaborating with specific examples like `Object.prototype` is much clearer. Similarly, explaining *why* trying to modify the prototype fails (because it's in read-only memory) strengthens the connection.

This methodical approach, starting with understanding the high-level purpose and then diving into the details of the code, helps in constructing a comprehensive and accurate explanation. The key is to bridge the gap between the low-level C++ implementation and the observable behavior in JavaScript.
这个C++源代码文件 `read-only-spaces.cc` 定义了 V8 JavaScript 引擎中用于管理**只读内存空间**的组件。它的主要功能是：

**1. 管理只读内存的分配和生命周期:**

* **`ReadOnlyArtifacts` 类:**  负责管理一组只读内存页面的集合。它持有 `ReadOnlyPageMetadata` 的指针，这些元数据描述了每个只读内存页面的属性，如起始地址、大小等。
    * 它的构造和析构函数负责分配和释放底层的内存页面。
    * 它还负责初始化只读空间，并将其重新安装到 `Isolate` (V8 的一个独立执行上下文) 中。
    * 提供了校验和功能，用于验证从快照加载的只读堆的完整性。

* **`ReadOnlySpace` 类:** 代表一个实际的只读内存空间。
    * 它继承自 `BaseSpace`，是 V8 堆内存管理的一部分。
    * 它维护了只读空间当前的顶部 (`top_`) 和限制 (`limit_`) 指针，用于线性分配。
    * 提供了分配只读对象的接口 (`AllocateRawAligned`, `AllocateRawUnaligned`)。
    * 提供了将只读空间标记为只读 (`Seal`) 和取消只读 (`Unseal`) 的功能。`Seal` 操作会设置内存页面的权限为只读，以防止修改。
    * 提供了迭代只读空间中对象的功能 (`ReadOnlySpaceObjectIterator`).
    * 包含了在反序列化后修复自由空间列表的功能 (`RepairFreeSpacesAfterDeserialization`).
    * 提供了收缩只读页面的功能 (`ShrinkPages`)，释放未使用的内存。

* **`SharedReadOnlySpace` 类:**  是 `ReadOnlySpace` 的一个变体，用于共享的只读堆。这允许不同的 `Isolate` 共享同一份只读数据，从而节省内存。

* **`ReadOnlyPageMetadata` 类:**  存储单个只读内存页面的元数据，例如页面的起始地址、大小、所属空间等。

**2. 与快照 (Snapshot) 功能集成:**

* 该文件与 V8 的快照机制紧密相关。只读空间通常从快照数据中恢复，快照包含了预先创建的 JavaScript 内置对象和其他不可变的数据。
* `InitializeChecksum` 和 `VerifyChecksum` 方法用于确保加载的只读堆与创建快照时的状态一致。

**3. 提高性能和安全性:**

* 将内置对象和运行时需要的常量数据存储在只读空间中，可以防止意外修改，提高了运行时的稳定性。
* 共享的只读空间可以减少内存占用，特别是在多个 `Isolate` 存在的情况下。
* 从快照加载只读空间可以加速 V8 的启动过程。

**与 JavaScript 的功能关系以及 JavaScript 示例:**

只读空间存储了 JavaScript 引擎运行所必需的一些核心对象和数据，包括**内置对象 (Built-in Objects) 的原型**。这些原型定义了 JavaScript 语言的基本行为。

例如，`Object.prototype`, `Array.prototype`, `String.prototype` 等对象都存储在只读空间中。这意味着你无法直接修改这些原型对象的属性。

**JavaScript 示例:**

```javascript
// 获取 Object 构造函数的原型对象
const objectPrototype = Object.prototype;

// 尝试修改 Object 原型上的属性
try {
  objectPrototype.newProperty = 'test';
} catch (error) {
  console.error("修改 Object.prototype 失败:", error);
}

console.log("Object.prototype 上是否存在 newProperty:", 'newProperty' in Object.prototype);

// 你可以访问 Object 原型上的属性
console.log("Object.prototype 的 toString 方法:", objectPrototype.toString);

// 尝试修改数组的原型
try {
  Array.prototype.myCustomMethod = function() { console.log("自定义数组方法"); };
} catch (error) {
  console.error("修改 Array.prototype 失败:", error);
}

// 原型对象是不可变的 (至少其默认属性是受保护的)
console.log("Array.prototype 上是否存在 myCustomMethod:", 'myCustomMethod' in Array.prototype);

// 但是你仍然可以在实例上添加属性
const myObject = {};
myObject.anotherProperty = 'works';
console.log(myObject.anotherProperty);
```

**解释:**

* 上述 JavaScript 代码尝试向 `Object.prototype` 和 `Array.prototype` 添加新的属性。
* 由于这些原型对象存储在只读内存空间中，直接修改它们会导致错误 (在严格模式下会抛出 `TypeError`) 或操作被忽略。
* 然而，你仍然可以访问这些原型对象的属性和方法。
* 你也可以在 JavaScript 对象的实例上添加新的属性，因为实例对象通常分配在可读写的堆空间中。

**总结:**

`v8/src/heap/read-only-spaces.cc` 文件定义了 V8 引擎中用于管理只读内存空间的关键组件。这个只读空间存储了 JavaScript 引擎的核心数据，特别是内置对象的原型，这保证了 JavaScript 语言基础的稳定性和安全性。尝试修改这些只读数据在 JavaScript 中是不允许的。 通过使用快照，V8 可以快速加载这些只读数据，从而提升启动速度。

### 提示词
```
这是目录为v8/src/heap/read-only-spaces.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/read-only-spaces.h"

#include <memory>

#include "include/v8-internal.h"
#include "include/v8-platform.h"
#include "src/base/logging.h"
#include "src/common/globals.h"
#include "src/common/ptr-compr-inl.h"
#include "src/execution/isolate.h"
#include "src/heap/allocation-stats.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap-verifier.h"
#include "src/heap/marking-state-inl.h"
#include "src/heap/memory-allocator.h"
#include "src/heap/memory-chunk-metadata.h"
#include "src/heap/read-only-heap.h"
#include "src/objects/objects-inl.h"
#include "src/snapshot/snapshot-data.h"
#include "src/snapshot/snapshot-source-sink.h"
#include "src/snapshot/snapshot-utils.h"

namespace v8 {
namespace internal {

ReadOnlyArtifacts::~ReadOnlyArtifacts() {
  // This particular SharedReadOnlySpace should not destroy its own pages as
  // TearDown requires MemoryAllocator which itself is tied to an Isolate.
  shared_read_only_space_->pages_.resize(0);

  for (ReadOnlyPageMetadata* metadata : pages_) {
    void* chunk_address = reinterpret_cast<void*>(metadata->ChunkAddress());
    size_t size =
        RoundUp(metadata->size(), page_allocator_->AllocatePageSize());
    CHECK(page_allocator_->FreePages(chunk_address, size));
    delete metadata;
  }
}

void ReadOnlyArtifacts::Initialize(Isolate* isolate,
                                   std::vector<ReadOnlyPageMetadata*>&& pages,
                                   const AllocationStats& stats) {
  page_allocator_ = isolate->isolate_group()->page_allocator();
  pages_ = std::move(pages);
  set_accounting_stats(stats);
  set_shared_read_only_space(
      std::make_unique<SharedReadOnlySpace>(isolate->heap(), this));
}

void ReadOnlyArtifacts::ReinstallReadOnlySpace(Isolate* isolate) {
  isolate->heap()->ReplaceReadOnlySpace(shared_read_only_space());
}

void ReadOnlyArtifacts::VerifyHeapAndSpaceRelationships(Isolate* isolate) {
  DCHECK_EQ(read_only_heap()->read_only_space(), shared_read_only_space());

  // Confirm the Isolate is using the shared ReadOnlyHeap and ReadOnlySpace.
  DCHECK_EQ(read_only_heap(), isolate->read_only_heap());
  DCHECK_EQ(shared_read_only_space(), isolate->heap()->read_only_space());
}

void ReadOnlyArtifacts::set_read_only_heap(
    std::unique_ptr<ReadOnlyHeap> read_only_heap) {
  read_only_heap_ = std::move(read_only_heap);
}

void ReadOnlyArtifacts::InitializeChecksum(
    SnapshotData* read_only_snapshot_data) {
#ifdef DEBUG
  read_only_blob_checksum_ = Checksum(read_only_snapshot_data->Payload());
#endif  // DEBUG
}

void ReadOnlyArtifacts::VerifyChecksum(SnapshotData* read_only_snapshot_data,
                                       bool read_only_heap_created) {
#ifdef DEBUG
  if (read_only_blob_checksum_) {
    // The read-only heap was set up from a snapshot. Make sure it's the always
    // the same snapshot.
    uint32_t snapshot_checksum = Checksum(read_only_snapshot_data->Payload());
    CHECK_WITH_MSG(snapshot_checksum,
                   "Attempt to create the read-only heap after already "
                   "creating from a snapshot.");
    if (!v8_flags.stress_snapshot) {
      // --stress-snapshot is only intended to check how well the
      // serializer/deserializer copes with unexpected objects, and is not
      // intended to test whether the newly deserialized Isolate would actually
      // work since it serializes a currently running Isolate, which is not
      // supported. As a result, it's possible that it will create a new
      // read-only snapshot that is not compatible with the original one (for
      // instance due to the string table being re-ordered). Since we won't
      // actually use that new Isolate, we're ok with any potential corruption.
      // See crbug.com/1043058.
      CHECK_EQ(read_only_blob_checksum_, snapshot_checksum);
    }
  } else {
    // If there's no checksum, then that means the read-only heap objects are
    // being created.
    CHECK(read_only_heap_created);
  }
#endif  // DEBUG
}

// -----------------------------------------------------------------------------
// ReadOnlySpace implementation

ReadOnlySpace::ReadOnlySpace(Heap* heap)
    : BaseSpace(heap, RO_SPACE),
      top_(kNullAddress),
      limit_(kNullAddress),
      capacity_(0),
      area_size_(MemoryChunkLayout::AllocatableMemoryInMemoryChunk(RO_SPACE)) {}

// Needs to be defined in the cc file to force the vtable to be emitted in
// component builds.
ReadOnlySpace::~ReadOnlySpace() = default;

void SharedReadOnlySpace::TearDown(MemoryAllocator* memory_allocator) {
  // SharedReadOnlySpaces do not tear down their own pages since they are either
  // freed down by the ReadOnlyArtifacts that contains them or in the case of
  // pointer compression, they are freed when the SharedMemoryMappings are
  // freed.
  pages_.resize(0);
  accounting_stats_.Clear();
}

void ReadOnlySpace::TearDown(MemoryAllocator* memory_allocator) {
  for (ReadOnlyPageMetadata* chunk : pages_) {
    memory_allocator->FreeReadOnlyPage(chunk);
  }
  pages_.resize(0);
  accounting_stats_.Clear();
}

void ReadOnlySpace::DetachPagesAndAddToArtifacts(ReadOnlyArtifacts* artifacts) {
  DCHECK(ReadOnlyHeap::IsReadOnlySpaceShared());

  Heap* heap = ReadOnlySpace::heap();
  // ReadOnlySpace pages are directly shared between all heaps in
  // the isolate group and so must be unregistered from
  // their originating allocator.
  Seal(SealMode::kDetachFromHeapAndUnregisterMemory);
  artifacts->Initialize(heap->isolate(), std::move(pages_), accounting_stats_);
}

ReadOnlyPageMetadata::ReadOnlyPageMetadata(Heap* heap, BaseSpace* space,
                                           size_t chunk_size,
                                           Address area_start, Address area_end,
                                           VirtualMemory reservation)
    : MemoryChunkMetadata(heap, space, chunk_size, area_start, area_end,
                          std::move(reservation)) {
  allocated_bytes_ = 0;
}

MemoryChunk::MainThreadFlags ReadOnlyPageMetadata::InitialFlags() const {
  return MemoryChunk::NEVER_EVACUATE | MemoryChunk::READ_ONLY_HEAP |
         MemoryChunk::CONTAINS_ONLY_OLD;
}

void ReadOnlyPageMetadata::MakeHeaderRelocatable() {
  heap_ = nullptr;
  owner_ = nullptr;
  reservation_.Reset();
}

void ReadOnlySpace::SetPermissionsForPages(MemoryAllocator* memory_allocator,
                                           PageAllocator::Permission access) {
  for (MemoryChunkMetadata* chunk : pages_) {
    // Read only pages don't have valid reservation object so we get proper
    // page allocator manually.
    v8::PageAllocator* page_allocator =
        memory_allocator->page_allocator(RO_SPACE);
    CHECK(SetPermissions(page_allocator, chunk->ChunkAddress(), chunk->size(),
                         access));
  }
}

// After we have booted, we have created a map which represents free space
// on the heap.  If there was already a free list then the elements on it
// were created with the wrong FreeSpaceMap (normally nullptr), so we need to
// fix them.
void ReadOnlySpace::RepairFreeSpacesAfterDeserialization() {
  MemoryChunkMetadata::UpdateHighWaterMark(top_);
  // Each page may have a small free space that is not tracked by a free list.
  // Those free spaces still contain null as their map pointer.
  // Overwrite them with new fillers.
  for (MemoryChunkMetadata* chunk : pages_) {
    Address start = chunk->HighWaterMark();
    Address end = chunk->area_end();
    // Put a filler object in the gap between the end of the allocated objects
    // and the end of the allocatable area.
    if (start < end) {
      heap()->CreateFillerObjectAt(start, static_cast<int>(end - start));
    }
  }
}

void ReadOnlySpace::Seal(SealMode ro_mode) {
  DCHECK(!is_marked_read_only_);

  FreeLinearAllocationArea();
  is_marked_read_only_ = true;
  auto* memory_allocator = heap()->memory_allocator();

  if (ro_mode != SealMode::kDoNotDetachFromHeap) {
    DetachFromHeap();
    for (ReadOnlyPageMetadata* p : pages_) {
      if (ro_mode == SealMode::kDetachFromHeapAndUnregisterMemory) {
        memory_allocator->UnregisterReadOnlyPage(p);
      }
      if (ReadOnlyHeap::IsReadOnlySpaceShared()) {
        p->MakeHeaderRelocatable();
      }
    }
  }

  SetPermissionsForPages(memory_allocator, PageAllocator::kRead);
}

void ReadOnlySpace::Unseal() {
  DCHECK(is_marked_read_only_);
  if (!pages_.empty()) {
    SetPermissionsForPages(heap()->memory_allocator(),
                           PageAllocator::kReadWrite);
  }
  is_marked_read_only_ = false;
}

bool ReadOnlySpace::ContainsSlow(Address addr) const {
  MemoryChunk* chunk = MemoryChunk::FromAddress(addr);
  for (MemoryChunkMetadata* metadata : pages_) {
    if (metadata->Chunk() == chunk) return true;
  }
  return false;
}

namespace {
// Only iterates over a single chunk as the chunk iteration is done externally.
class ReadOnlySpaceObjectIterator : public ObjectIterator {
 public:
  ReadOnlySpaceObjectIterator(const Heap* heap, const ReadOnlySpace* space,
                              MemoryChunkMetadata* chunk)
      : cur_addr_(chunk->area_start()),
        cur_end_(chunk->area_end()),
        space_(space) {}

  // Advance to the next object, skipping free spaces and other fillers and
  // skipping the special garbage section of which there is one per space.
  // Returns a null object when the iteration has ended.
  Tagged<HeapObject> Next() override {
    while (cur_addr_ != cur_end_) {
      if (cur_addr_ == space_->top() && cur_addr_ != space_->limit()) {
        cur_addr_ = space_->limit();
        continue;
      }
      Tagged<HeapObject> obj = HeapObject::FromAddress(cur_addr_);
      const int obj_size = obj->Size();
      cur_addr_ += ALIGN_TO_ALLOCATION_ALIGNMENT(obj_size);
      DCHECK_LE(cur_addr_, cur_end_);
      if (!IsFreeSpaceOrFiller(obj)) {
        DCHECK_OBJECT_SIZE(obj_size);
        return obj;
      }
    }
    return HeapObject();
  }

  Address cur_addr_;  // Current iteration point.
  Address cur_end_;   // End iteration point.
  const ReadOnlySpace* const space_;
};
}  // namespace

#ifdef VERIFY_HEAP
void ReadOnlySpace::Verify(Isolate* isolate,
                           SpaceVerificationVisitor* visitor) const {
  bool allocation_pointer_found_in_space = top_ == limit_;

  for (MemoryChunkMetadata* page : pages_) {
    if (ReadOnlyHeap::IsReadOnlySpaceShared()) {
      CHECK_NULL(page->owner());
    } else {
      CHECK_EQ(page->owner(), this);
    }

    visitor->VerifyPage(page);

    if (top_ && page == PageMetadata::FromAllocationAreaAddress(top_)) {
      allocation_pointer_found_in_space = true;
    }
    ReadOnlySpaceObjectIterator it(isolate->heap(), this, page);
    Address end_of_previous_object = page->area_start();
    Address top = page->area_end();

    for (Tagged<HeapObject> object = it.Next(); !object.is_null();
         object = it.Next()) {
      CHECK(end_of_previous_object <= object.address());

      visitor->VerifyObject(object);

      // All the interior pointers should be contained in the heap.
      int size = object->Size();
      CHECK(object.address() + size <= top);
      end_of_previous_object = object.address() + size;
    }

    visitor->VerifyPageDone(page);
  }
  CHECK(allocation_pointer_found_in_space);

#ifdef DEBUG
  VerifyCounters(isolate->heap());
#endif
}

#ifdef DEBUG
void ReadOnlySpace::VerifyCounters(Heap* heap) const {
  size_t total_capacity = 0;
  size_t total_allocated = 0;
  for (MemoryChunkMetadata* page : pages_) {
    total_capacity += page->area_size();
    ReadOnlySpaceObjectIterator it(heap, this, page);
    size_t real_allocated = 0;
    for (Tagged<HeapObject> object = it.Next(); !object.is_null();
         object = it.Next()) {
      if (!IsFreeSpaceOrFiller(object)) {
        real_allocated += object->Size();
      }
    }
    total_allocated += page->allocated_bytes();
    // The real size can be smaller than the accounted size if array trimming,
    // object slack tracking happened after sweeping.
    CHECK_LE(real_allocated, accounting_stats_.AllocatedOnPage(page));
    CHECK_EQ(page->allocated_bytes(), accounting_stats_.AllocatedOnPage(page));
  }
  CHECK_EQ(total_capacity, accounting_stats_.Capacity());
  CHECK_EQ(total_allocated, accounting_stats_.Size());
}
#endif  // DEBUG
#endif  // VERIFY_HEAP

size_t ReadOnlySpace::CommittedPhysicalMemory() const {
  if (!base::OS::HasLazyCommits()) return CommittedMemory();
  MemoryChunkMetadata::UpdateHighWaterMark(top_);
  size_t size = 0;
  for (auto* chunk : pages_) {
    size += chunk->size();
  }

  return size;
}

void ReadOnlySpace::FreeLinearAllocationArea() {
  // Mark the old linear allocation area with a free space map so it can be
  // skipped when scanning the heap.
  if (top_ == kNullAddress) {
    DCHECK_EQ(kNullAddress, limit_);
    return;
  }

  heap()->CreateFillerObjectAt(top_, static_cast<int>(limit_ - top_));

  MemoryChunkMetadata::UpdateHighWaterMark(top_);

  top_ = kNullAddress;
  limit_ = kNullAddress;
}

void ReadOnlySpace::EnsurePage() {
  if (pages_.empty()) {
    EnsureSpaceForAllocation(1);
  }
  CHECK(!pages_.empty());
  // For all configurations where static roots are supported the read only roots
  // are currently allocated in the first page of the cage.
  CHECK_IMPLIES(V8_STATIC_ROOTS_BOOL,
                heap_->isolate()->cage_base() == pages_.back()->ChunkAddress());
}

void ReadOnlySpace::EnsureSpaceForAllocation(int size_in_bytes) {
  if (top_ + size_in_bytes <= limit_) {
    return;
  }

  DCHECK_GE(size_in_bytes, 0);

  FreeLinearAllocationArea();

  ReadOnlyPageMetadata* metadata =
      heap()->memory_allocator()->AllocateReadOnlyPage(this);
  CHECK_NOT_NULL(metadata);

  capacity_ += AreaSize();

  accounting_stats_.IncreaseCapacity(metadata->area_size());
  AccountCommitted(metadata->size());
  pages_.push_back(metadata);

  heap()->CreateFillerObjectAt(metadata->area_start(),
                               static_cast<int>(metadata->area_size()));

  top_ = metadata->area_start();
  limit_ = metadata->area_end();
}

Tagged<HeapObject> ReadOnlySpace::TryAllocateLinearlyAligned(
    int size_in_bytes, AllocationAlignment alignment) {
  size_in_bytes = ALIGN_TO_ALLOCATION_ALIGNMENT(size_in_bytes);
  Address current_top = top_;
  int filler_size = Heap::GetFillToAlign(current_top, alignment);

  Address new_top = current_top + filler_size + size_in_bytes;
  if (new_top > limit_) return HeapObject();

  // Allocation always occurs in the last chunk for RO_SPACE.
  MemoryChunkMetadata* chunk = pages_.back();
  int allocated_size = filler_size + size_in_bytes;
  accounting_stats_.IncreaseAllocatedBytes(allocated_size, chunk);
  chunk->IncreaseAllocatedBytes(allocated_size);

  top_ = new_top;
  if (filler_size > 0) {
    return heap()->PrecedeWithFiller(HeapObject::FromAddress(current_top),
                                     filler_size);
  }

  return HeapObject::FromAddress(current_top);
}

AllocationResult ReadOnlySpace::AllocateRawAligned(
    int size_in_bytes, AllocationAlignment alignment) {
  DCHECK(!IsDetached());
  size_in_bytes = ALIGN_TO_ALLOCATION_ALIGNMENT(size_in_bytes);
  int allocation_size = size_in_bytes;

  Tagged<HeapObject> object =
      TryAllocateLinearlyAligned(allocation_size, alignment);
  if (object.is_null()) {
    // We don't know exactly how much filler we need to align until space is
    // allocated, so assume the worst case.
    EnsureSpaceForAllocation(allocation_size +
                             Heap::GetMaximumFillToAlign(alignment));
    allocation_size = size_in_bytes;
    object = TryAllocateLinearlyAligned(size_in_bytes, alignment);
    CHECK(!object.is_null());
  }
  MSAN_ALLOCATED_UNINITIALIZED_MEMORY(object.address(), size_in_bytes);

  return AllocationResult::FromObject(object);
}

AllocationResult ReadOnlySpace::AllocateRawUnaligned(int size_in_bytes) {
  DCHECK(!IsDetached());
  size_in_bytes = ALIGN_TO_ALLOCATION_ALIGNMENT(size_in_bytes);
  EnsureSpaceForAllocation(size_in_bytes);
  Address current_top = top_;
  Address new_top = current_top + size_in_bytes;
  DCHECK_LE(new_top, limit_);
  top_ = new_top;
  Tagged<HeapObject> object = HeapObject::FromAddress(current_top);

  DCHECK(!object.is_null());
  MSAN_ALLOCATED_UNINITIALIZED_MEMORY(object.address(), size_in_bytes);

  // Allocation always occurs in the last chunk for RO_SPACE.
  MemoryChunkMetadata* chunk = pages_.back();
  accounting_stats_.IncreaseAllocatedBytes(size_in_bytes, chunk);
  chunk->IncreaseAllocatedBytes(size_in_bytes);

  return AllocationResult::FromObject(object);
}

AllocationResult ReadOnlySpace::AllocateRaw(int size_in_bytes,
                                            AllocationAlignment alignment) {
  return USE_ALLOCATION_ALIGNMENT_BOOL && alignment != kTaggedAligned
             ? AllocateRawAligned(size_in_bytes, alignment)
             : AllocateRawUnaligned(size_in_bytes);
}

size_t ReadOnlyPageMetadata::ShrinkToHighWaterMark() {
  // Shrink pages to high water mark. The water mark points either to a filler
  // or the area_end.
  Tagged<HeapObject> filler = HeapObject::FromAddress(HighWaterMark());
  if (filler.address() == area_end()) return 0;
  CHECK(IsFreeSpaceOrFiller(filler));
  DCHECK_EQ(filler.address() + filler->Size(), area_end());

  size_t unused = RoundDown(static_cast<size_t>(area_end() - filler.address()),
                            MemoryAllocator::GetCommitPageSize());
  if (unused > 0) {
    DCHECK_EQ(0u, unused % MemoryAllocator::GetCommitPageSize());
    if (v8_flags.trace_gc_verbose) {
      PrintIsolate(heap()->isolate(), "Shrinking page %p: end %p -> %p\n",
                   reinterpret_cast<void*>(this),
                   reinterpret_cast<void*>(area_end()),
                   reinterpret_cast<void*>(area_end() - unused));
    }
    heap()->CreateFillerObjectAt(
        filler.address(),
        static_cast<int>(area_end() - filler.address() - unused));
    heap()->memory_allocator()->PartialFreeMemory(
        this, ChunkAddress() + size() - unused, unused, area_end() - unused);
    if (filler.address() != area_end()) {
      CHECK(IsFreeSpaceOrFiller(filler));
      CHECK_EQ(filler.address() + filler->Size(), area_end());
    }
  }
  return unused;
}

void ReadOnlySpace::ShrinkPages() {
  MemoryChunkMetadata::UpdateHighWaterMark(top_);
  heap()->CreateFillerObjectAt(top_, static_cast<int>(limit_ - top_));

  for (ReadOnlyPageMetadata* page : pages_) {
    DCHECK(page->Chunk()->IsFlagSet(MemoryChunk::NEVER_EVACUATE));
    size_t unused = page->ShrinkToHighWaterMark();
    capacity_ -= unused;
    accounting_stats_.DecreaseCapacity(static_cast<intptr_t>(unused));
    AccountUncommitted(unused);
  }
  limit_ = pages_.back()->area_end();
}

SharedReadOnlySpace::SharedReadOnlySpace(Heap* heap,
                                         ReadOnlyArtifacts* artifacts)
    : SharedReadOnlySpace(heap) {
  DCHECK(V8_SHARED_RO_HEAP_BOOL);
  accounting_stats_ = artifacts->accounting_stats();
  pages_ = artifacts->pages();
}

size_t ReadOnlySpace::IndexOf(const MemoryChunkMetadata* chunk) const {
  for (size_t i = 0; i < pages_.size(); i++) {
    if (chunk == pages_[i]) return i;
  }
  UNREACHABLE();
}

size_t ReadOnlySpace::AllocateNextPage() {
  ReadOnlyPageMetadata* page =
      heap_->memory_allocator()->AllocateReadOnlyPage(this);
  capacity_ += AreaSize();
  AccountCommitted(page->size());
  pages_.push_back(page);
  return pages_.size() - 1;
}

size_t ReadOnlySpace::AllocateNextPageAt(Address pos) {
  CHECK(IsAligned(pos, kRegularPageSize));
  ReadOnlyPageMetadata* page =
      heap_->memory_allocator()->AllocateReadOnlyPage(this, pos);
  if (!page) {
    heap_->FatalProcessOutOfMemory("ReadOnly allocation failure");
  }
  // If this fails we got a wrong page. This means something allocated a page in
  // the shared cage before us, stealing our required page (i.e.,
  // ReadOnlyHeap::SetUp was called too late).
  CHECK_EQ(pos, page->ChunkAddress());
  capacity_ += AreaSize();
  AccountCommitted(page->size());
  pages_.push_back(page);
  return pages_.size() - 1;
}

void ReadOnlySpace::InitializePageForDeserialization(
    ReadOnlyPageMetadata* page, size_t area_size_in_bytes) {
  page->IncreaseAllocatedBytes(area_size_in_bytes);
  limit_ = top_ = page->area_start() + area_size_in_bytes;
  page->high_water_mark_ = page->Offset(top_);
}

void ReadOnlySpace::FinalizeSpaceForDeserialization() {
  // The ReadOnlyRoots table is now initialized. Create fillers, shrink pages,
  // and update accounting stats.
  for (ReadOnlyPageMetadata* page : pages_) {
    Address top = page->ChunkAddress() + page->high_water_mark_;
    heap()->CreateFillerObjectAt(top, static_cast<int>(page->area_end() - top));
    page->ShrinkToHighWaterMark();
    accounting_stats_.IncreaseCapacity(page->area_size());
    accounting_stats_.IncreaseAllocatedBytes(page->allocated_bytes(), page);
  }
}

}  // namespace internal
}  // namespace v8
```