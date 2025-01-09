Response:
Let's break down the thought process for analyzing the `read-only-spaces.cc` file.

1. **Initial Scan and Keywords:**  The first step is a quick scan of the code, looking for keywords and structural elements. Keywords like `ReadOnly`, `Space`, `Heap`, `Allocate`, `Free`, `Initialize`, `Verify`, `Checksum`, `Seal`, `TearDown`, `Snapshot`, `Metadata`, and class names like `ReadOnlyArtifacts`, `ReadOnlySpace`, `SharedReadOnlySpace`, and `ReadOnlyPageMetadata` immediately jump out. These give a strong hint about the file's purpose.

2. **Identify Core Classes and Their Roles:** The class names themselves are very descriptive. It's clear we're dealing with read-only memory management within V8's heap. I'd start forming hypotheses about each class:

    * `ReadOnlyArtifacts`:  The name suggests this class manages collections or higher-level structures related to read-only memory. The destructor's comment about `SharedReadOnlySpace` and the `Initialize` method taking `ReadOnlyPageMetadata` suggest it *owns* these. The `ReinstallReadOnlySpace` and `VerifyHeapAndSpaceRelationships` methods indicate it interacts with the main `Heap` and `Isolate`.

    * `ReadOnlySpace`:  This likely represents the actual read-only memory region. Members like `top_`, `limit_`, `capacity_`, and methods like `AllocateRaw`, `FreeLinearAllocationArea`, `Seal`, `Unseal`, `ContainsSlow` confirm this.

    * `SharedReadOnlySpace`: The "Shared" prefix suggests this is a read-only space that's shared across isolates or some other boundary within V8. The `TearDown` implementation difference compared to `ReadOnlySpace` (not freeing pages directly) reinforces this.

    * `ReadOnlyPageMetadata`:  The name implies this class stores metadata *about* individual read-only pages. Members like `ChunkAddress`, `size`, `allocated_bytes_`, and methods like `MakeHeaderRelocatable` support this. It seems like the basic unit of management within the read-only space.

3. **Trace Key Operations:** Follow the flow of critical operations:

    * **Initialization:**  How is the read-only space created and configured? Look at `ReadOnlyArtifacts::Initialize`, `ReadOnlySpace` constructor, `SharedReadOnlySpace` constructor. The interaction with `Isolate`, `Heap`, and `AllocationStats` is important.

    * **Allocation:** How are objects placed in the read-only space? Examine `ReadOnlySpace::AllocateRaw`, `TryAllocateLinearlyAligned`, `EnsureSpaceForAllocation`. Notice the alignment considerations.

    * **Deallocation/Cleanup:** How is the read-only space managed over time?  Focus on `ReadOnlyArtifacts::~ReadOnlyArtifacts`, `ReadOnlySpace::TearDown`, and `SharedReadOnlySpace::TearDown`. The difference in page management is crucial.

    * **Read-Only Protection:** How is the read-only nature enforced?  The `Seal` and `Unseal` methods, and the use of `SetPermissionsForPages` with `PageAllocator::kRead` are key.

    * **Snapshots:**  What role do snapshots play? Look for `SnapshotData`, `InitializeChecksum`, `VerifyChecksum`. This indicates the read-only space can be populated from a pre-built image.

    * **Verification:** How is the integrity of the read-only space checked? Examine the `Verify` methods in `ReadOnlyArtifacts` and `ReadOnlySpace`, as well as the checksum verification.

4. **Infer Functionality from Code Structure and Logic:**

    * **Memory Management:** The code clearly implements a memory manager for read-only data. It handles page allocation, tracking allocated regions, and potentially shrinking pages.

    * **Sharing:** The `SharedReadOnlySpace` indicates a mechanism for sharing read-only data across different parts of V8 or different isolates.

    * **Immutability:** The "read-only" nature is enforced through memory protection mechanisms.

    * **Startup Optimization:** The use of snapshots suggests a way to speed up V8's startup by pre-populating the read-only space.

5. **Connect to JavaScript (if applicable):** Consider what kinds of JavaScript concepts might rely on read-only data. Think about built-in objects, constants, code (though code is often in a separate code space). The examples provided in the initial good answer (built-in functions, prototype chains, immutable data) are excellent illustrations.

6. **Consider Potential Errors:** Think about common programming mistakes related to read-only memory: trying to modify it. This leads to the example of attempting to assign a new property to a built-in object's prototype.

7. **Code Logic Reasoning (Hypothetical Inputs/Outputs):** For methods like `ContainsSlow`, think about simple scenarios:

    * Input: An address within a read-only page. Output: `true`.
    * Input: An address outside any read-only page. Output: `false`.
    * Input: `kNullAddress`. Output: `false`.

    For allocation methods, think about the input size and alignment, and how `top_` and `limit_` would change.

8. **Structure the Answer:** Organize the findings logically. Start with a high-level summary of the file's purpose, then detail the functionalities, relating them back to the code. Use clear headings and bullet points. Provide concrete examples where requested (JavaScript, error scenarios, input/output).

9. **Refine and Review:** After drafting the initial answer, review it for clarity, accuracy, and completeness. Ensure all parts of the prompt are addressed.

This systematic approach helps in understanding complex C++ code like this, by breaking it down into manageable pieces and focusing on the key functionalities and interactions. The descriptive naming conventions in V8's codebase are a significant help in this process.
Based on the provided C++ source code for `v8/src/heap/read-only-spaces.cc`, here's a breakdown of its functionalities:

**Core Functionality: Management of Read-Only Memory Regions**

The primary purpose of this file is to manage memory spaces within the V8 heap that are designated as read-only. This means that after these memory regions are initialized, their contents should not be modified during the normal execution of JavaScript code. This provides several benefits, including:

* **Performance:** Read-only memory can potentially be shared more efficiently and may have optimizations related to caching.
* **Security:** Prevents accidental or malicious modification of critical data structures and code.
* **Memory Sharing:**  In some configurations, read-only spaces can be shared between different isolates or processes.

**Key Components and Their Roles:**

* **`ReadOnlyArtifacts`:**  This class seems to manage a collection of read-only memory pages and associated metadata. It's responsible for initializing, verifying, and tearing down these read-only structures. It interacts with the `Isolate` and the `Heap`. It appears to handle the lifecycle of the shared read-only space.
* **`ReadOnlySpace`:** Represents a single read-only memory space within the heap. It manages allocation within this space, tracks the top and limit of allocated memory, and handles sealing (making it truly read-only) and unsealing (temporarily making it writable, likely for initialization).
* **`SharedReadOnlySpace`:**  A specialized `ReadOnlySpace` that can be shared between different V8 isolates or potentially different contexts within the same isolate. Its lifecycle seems to be tied to `ReadOnlyArtifacts`.
* **`ReadOnlyPageMetadata`:**  Stores metadata about individual read-only memory pages (or chunks). This includes information like the page's address, size, and associated flags.

**Specific Functionalities:**

1. **Initialization:**
   - `ReadOnlyArtifacts::Initialize`:  Sets up the read-only space by receiving a collection of pre-allocated read-only pages and associating them with the `Isolate` and `Heap`.
   - `ReadOnlySpace` Constructor: Initializes the basic state of a read-only space.
   - `SharedReadOnlySpace` Constructor:  Likely inherits from `ReadOnlySpace` and might have specific initialization for shared behavior.

2. **Allocation:**
   - `ReadOnlySpace::AllocateRawAligned`, `ReadOnlySpace::AllocateRawUnaligned`, `ReadOnlySpace::AllocateRaw`:  Functions responsible for allocating memory within the read-only space. They handle alignment requirements and ensure there's enough space.
   - `ReadOnlySpace::EnsureSpaceForAllocation`:  Allocates new read-only pages when the current space is full.
   - `ReadOnlySpace::TryAllocateLinearlyAligned`: Attempts to allocate a block of memory with specific alignment.

3. **Deallocation/Cleanup (Limited in Read-Only Spaces):**
   - `ReadOnlyArtifacts::~ReadOnlyArtifacts`:  Frees the underlying memory pages allocated for the read-only space. Notably, it avoids freeing pages of the `shared_read_only_space_` directly, suggesting a different ownership model for shared spaces.
   - `ReadOnlySpace::TearDown`: Frees the pages belonging to a non-shared read-only space.
   - `SharedReadOnlySpace::TearDown`:  Clears accounting statistics but doesn't free the pages directly, as their lifecycle is managed by `ReadOnlyArtifacts` or shared memory mechanisms.

4. **Read-Only Enforcement:**
   - `ReadOnlySpace::Seal`:  Marks the read-only space as immutable. This likely involves changing memory permissions using platform-specific APIs.
   - `ReadOnlySpace::Unseal`:  Temporarily makes the space writable (used during initialization).
   - `ReadOnlySpace::SetPermissionsForPages`:  Applies the appropriate memory permissions (read-only or read-write) to the pages.

5. **Snapshot Integration:**
   - `ReadOnlyArtifacts::InitializeChecksum`, `ReadOnlyArtifacts::VerifyChecksum`:  Deals with checksums of read-only snapshot data. This suggests that the contents of the read-only space can be loaded from a pre-generated snapshot file to speed up startup.

6. **Verification and Debugging:**
   - `ReadOnlyArtifacts::VerifyHeapAndSpaceRelationships`:  Performs checks to ensure the read-only space is correctly linked within the V8 heap structure.
   - `ReadOnlySpace::Verify`:  Performs heap verification within the read-only space, checking object integrity and consistency.

7. **Memory Management Operations:**
   - `ReadOnlySpace::ShrinkPages`:  Attempts to reduce the amount of physical memory used by the read-only space.
   - `ReadOnlySpace::FreeLinearAllocationArea`:  Marks the current linear allocation area as free.

8. **Iteration:**
   - The anonymous namespace contains `ReadOnlySpaceObjectIterator`, which allows iterating over the objects within a read-only space.

**If `v8/src/heap/read-only-spaces.cc` ended with `.tq`:**

If the file ended with `.tq`, it would be a **Torque** source file. Torque is V8's domain-specific language for writing highly optimized, low-level code, often related to object layout, built-in functions, and runtime support. In that case, the file would define the *interface* and some of the *implementation details* of the read-only spaces in a more type-safe and often more performant way than standard C++. The C++ file would then likely contain generated code from the Torque file or act as a higher-level manager.

**Relationship to JavaScript Functionality (with JavaScript Examples):**

The read-only spaces are crucial for storing core V8 data that should not be modified by JavaScript code. This includes:

* **Built-in Objects and their Properties:**  Objects like `Object.prototype`, `Array.prototype`, `String.prototype`, and their methods are often stored in read-only memory.

   ```javascript
   // Trying to modify a built-in prototype will likely fail silently or throw an error in strict mode.
   Object.prototype.myNewMethod = function() { console.log("This shouldn't be allowed directly"); };
   ```

* **Immutable Primitives and Constants:**  While JavaScript primitives themselves aren't stored directly in these spaces (they are often tagged values), data structures representing internal constants or frequently used immutable objects might reside there.

* **Code Objects (in some cases):**  While most compiled JavaScript code resides in separate code spaces, certain very core or built-in code might be placed in read-only memory.

* **Internal V8 Data Structures:**  Various internal tables, maps, and data structures used by the V8 engine itself are stored in read-only spaces for protection and efficiency.

**Code Logic Reasoning (Hypothetical Input and Output):**

Let's take the `ReadOnlySpace::ContainsSlow(Address addr)` function as an example:

**Assumption:** The read-only space contains two memory chunks (pages) with the following address ranges:
* Chunk 1: `0x1000` to `0x2000`
* Chunk 2: `0x3000` to `0x4000`

**Hypothetical Inputs and Outputs:**

* **Input:** `addr = 0x1500`
   * **Output:** `true` (because `0x1500` falls within the range of Chunk 1).

* **Input:** `addr = 0x3500`
   * **Output:** `true` (because `0x3500` falls within the range of Chunk 2).

* **Input:** `addr = 0x2500`
   * **Output:** `false` (because `0x2500` falls between the chunks and is not within either).

* **Input:** `addr = 0x0FFF`
   * **Output:** `false` (because `0x0FFF` is before the start of the first chunk).

* **Input:** `addr = 0x4000`
   * **Output:** `false` (assuming the end address is exclusive, if inclusive, it would be `true`).

**User-Common Programming Errors:**

Users don't directly interact with the read-only spaces at the C++ level when writing JavaScript. However, the existence of these spaces protects against certain kinds of errors or unintended modifications:

1. **Accidentally Modifying Built-in Prototypes (as shown in the JavaScript example):** While JavaScript allows adding properties to built-in prototypes, the underlying storage of the core properties is often read-only. V8's internal mechanisms will prevent these core properties from being overwritten directly.

2. **Trying to Modify "Constants":**  JavaScript doesn't have true compile-time constants in the way some other languages do. However, V8 uses read-only spaces to store data that should be treated as immutable. Attempts to change these internal structures would be prevented.

3. **Security Vulnerabilities:** The read-only nature of these spaces helps prevent attackers from potentially modifying core V8 functionality if they were to find a memory corruption vulnerability.

In summary, `v8/src/heap/read-only-spaces.cc` is a fundamental piece of V8's memory management system, responsible for creating and managing protected memory regions that are crucial for the engine's stability, performance, and security. Users writing JavaScript don't directly interact with it, but they benefit from the guarantees it provides.

Prompt: 
```
这是目录为v8/src/heap/read-only-spaces.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/read-only-spaces.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
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

"""

```