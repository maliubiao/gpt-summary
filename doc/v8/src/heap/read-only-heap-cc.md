Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Request:** The primary goal is to understand the functionality of `v8/src/heap/read-only-heap.cc`. The request also asks for specific considerations: Torque, JavaScript relevance, logic examples, and common errors.

2. **Initial Code Scan and High-Level Understanding:**

   * **Filename:** `read-only-heap.cc` immediately suggests this code manages a portion of the V8 heap that is read-only. This is a key concept.
   * **Includes:**  The `#include` statements provide valuable clues. We see references to:
     * `heap/*`:  Indicates this is part of the heap management system.
     * `objects/*`: Deals with V8's object representation.
     * `snapshot/*`:  Suggests involvement with snapshots (saving/restoring heap state).
     * `init/isolate-group.h`:  Points to multi-isolate support and potentially shared read-only heaps.
     * `sandbox/*`: Indicates security or isolation features might be involved.
   * **Namespace:**  `v8::internal` tells us this is internal V8 implementation, not part of the public API.
   * **Class `ReadOnlyHeap`:** This is the central class. We need to examine its members and methods.

3. **Analyzing `ReadOnlyHeap` Class Members and Methods:**

   * **Members:**
     * `read_only_space_`:  A pointer to a `ReadOnlySpace` object. This strongly suggests the `ReadOnlyHeap` *manages* the `ReadOnlySpace`.
     * `shared_ro_heap_` (with `#ifndef V8_COMPRESS_POINTERS_IN_MULTIPLE_CAGES`): Implies the possibility of a shared read-only heap across isolates under certain configurations.
     * `code_pointer_space_`, `js_dispatch_table_space_`: These, along with the preprocessor directives (`#ifdef V8_ENABLE_SANDBOX`, `#ifdef V8_ENABLE_LEAPTIERING`), indicate specialized areas within the read-only heap, likely for security or performance optimizations.
     * `roots_init_complete_`, `read_only_roots_`: These are related to the initialization of root objects within the read-only heap.

   * **Methods (and their significance):**
     * `~ReadOnlyHeap()`:  Destructor. Note the teardown of `code_pointer_space_` and `js_dispatch_table_space_`.
     * `SetUp()`:  Crucial for initializing the read-only heap. Handles cases with and without snapshots, and the shared read-only heap scenario. The mutex usage (`group->read_only_heap_creation_mutex()`) reinforces the shared heap concept and the need for thread safety.
     * `TearDown()`:  Cleans up the read-only heap, especially in the shared case.
     * `DeserializeIntoIsolate()`:  Handles loading the read-only heap from a snapshot.
     * `OnCreateRootsComplete()`, `OnCreateHeapObjectsComplete()`: Stages in the initialization process.
     * `CreateInitialHeapForBootstrapping()`:  Creates the initial read-only heap, likely during V8's startup.
     * `InitializeIsolateRoots()`, `InitializeFromIsolateRoots()`:  Methods for copying root object pointers.
     * `InitFromIsolate()`: Finalizes the read-only space after initialization.
     * `PopulateReadOnlySpaceStatistics()`:  Gathers statistics about the read-only space.
     * `Contains()` (static): Checks if an address or object is within the read-only heap.
     * `SandboxSafeContains()` (static):  A sandboxed version of `Contains()`.
     * `ReadOnlyHeapObjectIterator`, `ReadOnlyPageObjectIterator`: Classes for iterating through objects in the read-only heap.

4. **Answering Specific Questions:**

   * **Functionality:** Based on the methods and members, the core functionality is managing the read-only portion of the V8 heap. This involves creation, initialization (from snapshots or scratch), access checks, and iteration. The shared heap aspect is important.
   * **Torque:**  The filename ends in `.cc`, not `.tq`. So, it's C++, not Torque.
   * **JavaScript Relevance:**  The read-only heap holds fundamental JavaScript objects and code. The example of accessing a global variable demonstrates this. The concept of immutable built-in objects is also key.
   * **Logic Examples:**  Focus on `SetUp()` as it has branching logic based on snapshot availability and shared heap status. Create hypothetical input (snapshot data, isolate configuration) and trace the flow.
   * **Common Errors:**  Think about the implications of a read-only heap. Trying to modify objects in this space is the obvious error. Also, consider errors related to snapshot loading and shared heap initialization.

5. **Structuring the Output:** Organize the findings logically, starting with a summary of functionality, then address each specific question from the request. Use clear headings and formatting.

6. **Refinement and Review:**  Read through the generated explanation. Ensure accuracy, clarity, and completeness. For example, double-check the preprocessor conditions for shared heaps. Make sure the JavaScript example is relevant and correct.

**Self-Correction/Refinement Example During the Process:**

Initially, I might have focused too much on the iterator classes. However, after reviewing the overall structure and the `SetUp()` and `DeserializeIntoIsolate()` methods, it becomes clear that the *initialization* and *management* of the read-only heap are more central to its core functionality. The iterators are important but support this core functionality. So, I would adjust the emphasis accordingly in the explanation. Similarly, understanding the `#ifdef` directives helps prioritize the shared heap and sandboxing aspects.
`v8/src/heap/read-only-heap.cc` is a C++ source file within the V8 JavaScript engine that implements the **read-only heap**. Its primary function is to manage a dedicated memory region within the V8 heap where objects that are immutable and shared across isolates are stored.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Management of Read-Only Memory:**
   - It allocates and manages the `ReadOnlySpace`, a dedicated memory space for read-only objects.
   - It handles the creation and destruction of the read-only heap.

2. **Storage for Immutable Objects:**
   - This heap stores objects that are fundamental to the JavaScript environment and are intended to be immutable (unchangeable). Examples include:
     - Built-in prototypes (e.g., `Object.prototype`, `Array.prototype`).
     - Certain fundamental objects like `undefined`, `null`, `true`, `false`.
     - Compiled code for built-in functions.
     - String constants.

3. **Shared Across Isolates (Potentially):**
   - In certain configurations (indicated by `IsReadOnlySpaceShared()`), the read-only heap can be shared between different V8 isolates, reducing memory consumption. This sharing is managed through the `IsolateGroup`.

4. **Initialization from Snapshots:**
   - It plays a crucial role during V8 startup by deserializing the read-only heap from a snapshot (`read_only_snapshot_data`). This allows for faster startup by avoiding the need to reconstruct these immutable objects every time.

5. **Checksum Verification:**
   - It includes mechanisms to verify the integrity of the read-only snapshot using checksums.

6. **Iteration:**
   - Provides iterators (`ReadOnlyHeapObjectIterator`, `ReadOnlyPageObjectIterator`) to traverse the objects within the read-only heap.

7. **Containment Checks:**
   - Offers methods (`Contains`) to check if a given memory address or object resides within the read-only heap.

8. **Integration with Isolate:**
   - It provides methods to set up and tear down the read-only heap in relation to a specific `Isolate`.

9. **Sandboxing Support:**
   - Includes features for sandboxed environments (`V8_ENABLE_SANDBOX`) to manage code pointers in the read-only space.

10. **Leaptiering Support:**
    - Integrates with the Leaptiering feature (`V8_ENABLE_LEAPTIERING`) to manage a dispatch table in the read-only space.

**Relation to JavaScript and Examples:**

The read-only heap is fundamental to the execution of JavaScript. Many core JavaScript features rely on the immutable objects stored here.

**JavaScript Example:**

```javascript
// Accessing a built-in prototype:
const arr = [];
console.log(arr.__proto__ === Array.prototype); // true

// `Array.prototype` is an object stored in the read-only heap.
// You cannot modify it directly:
try {
  Array.prototype.customProperty = 'test'; // This will likely not work or have no effect
} catch (error) {
  console.error("Cannot modify read-only object:", error);
}

// Fundamental values:
console.log(undefined); // `undefined` is a primitive value represented by a specific object in the read-only heap.
console.log(null);      // `null` is also a primitive with its representation in the read-only heap.
```

**Explanation of the JavaScript Example:**

- When you access `arr.__proto__`, you are accessing the `prototype` property of the `Array` constructor. This `Array.prototype` object is stored in the read-only heap.
- Attempting to add a property to `Array.prototype` directly usually fails or has no effect because it's a read-only object.
- The values `undefined` and `null` are represented internally by specific objects within the read-only heap.

**Code Logic Reasoning (Hypothetical Example):**

Let's consider the `SetUp` function with a simplified scenario assuming `IsReadOnlySpaceShared()` is true and `read_only_snapshot_data` is not null (V8 is starting up with a snapshot).

**Assumptions (Input):**

- `isolate`: A valid V8 `Isolate` being initialized.
- `read_only_snapshot_data`: A pointer to data containing the serialized read-only heap.
- `can_rehash`: `true` (allows rehashing of hash tables during deserialization).
- `IsReadOnlySpaceShared()` returns `true`.
- `group->read_only_artifacts()` initially returns `nullptr`.

**Step-by-Step Logic:**

1. `ReadOnlyHeap::SetUp(isolate, read_only_snapshot_data, can_rehash)` is called.
2. `IsReadOnlySpaceShared()` is true, so the code enters the shared read-only heap logic.
3. `group->read_only_artifacts()` is `nullptr`, so the code proceeds to create the initial read-only heap.
4. `group->InitializeReadOnlyArtifacts()` is called, creating a new `ReadOnlyArtifacts` object.
5. `artifacts->InitializeChecksum(read_only_snapshot_data)` calculates and stores the checksum of the snapshot data.
6. `CreateInitialHeapForBootstrapping(isolate, artifacts)` is called:
   - A new `ReadOnlySpace` is created.
   - A new `ReadOnlyHeap` is created, managing the `ReadOnlySpace`.
   - This `ReadOnlyHeap` is associated with the `IsolateGroup`.
   - The `ReadOnlyHeap` is also stored in the `ReadOnlyArtifacts`.
7. `ro_heap->DeserializeIntoIsolate(isolate, read_only_snapshot_data, can_rehash)` is called:
   - A `ReadOnlyDeserializer` is created.
   - The deserializer reads the `read_only_snapshot_data` and reconstructs the objects in the `ReadOnlySpace`.
   - `OnCreateRootsComplete` is called after deserialization.
8. `artifacts->set_initial_next_unique_sfi_id(isolate->next_unique_sfi_id())` stores the initial SFI ID.
9. `artifacts->VerifyChecksum(read_only_snapshot_data, true)` verifies the integrity of the deserialized data against the stored checksum.
10. `ro_heap->InitializeIsolateRoots(isolate)` copies the root object pointers from the `read_only_roots_` array to the isolate's root table.

**Output:**

- A fully initialized read-only heap within the provided `isolate`, populated with objects deserialized from the snapshot.
- The `ReadOnlyArtifacts` object in the `IsolateGroup` now holds a pointer to this initialized read-only heap.

**User-Related Programming Errors:**

Directly interacting with the read-only heap from user-level JavaScript is generally not possible or intended. However, understanding its existence can help diagnose certain behaviors.

**Common Programming Errors (Conceptual):**

1. **Attempting to Modify Built-in Prototypes Directly:** While JavaScript allows you to modify object prototypes, attempting to modify the built-in prototypes directly (like `Object.prototype`, `Array.prototype`) in a way that violates their intended immutability can lead to unexpected behavior or errors in some environments or strict modes.

   ```javascript
   // Potentially problematic (may be restricted in some contexts)
   Object.prototype.customMethod = function() { console.log("Custom method"); };

   const obj = {};
   obj.customMethod(); // May or may not work as expected due to prototype pollution concerns.
   ```

   While this is possible in JavaScript, the underlying objects in the read-only heap are protected. Modifications might affect the "live" prototypes but not the fundamental read-only copies.

2. **Misunderstanding Immutability:**  Developers might assume that all objects are mutable. Understanding that core parts of the JavaScript environment are immutable and reside in the read-only heap is crucial for avoiding assumptions about object modification.

3. **Snapshot Issues (More Relevant to V8 Internals):** If there are errors or corruption in the read-only snapshot data, it can lead to crashes or unexpected behavior during V8 startup. This is less of a direct user programming error but a potential issue in the V8 build or deployment process.

**In summary, `v8/src/heap/read-only-heap.cc` is a vital component of the V8 engine responsible for managing the memory region that holds immutable, shared objects, crucial for the performance and integrity of the JavaScript environment.** It handles initialization from snapshots, sharing across isolates, and provides mechanisms to access and verify the contents of this read-only memory area.

Prompt: 
```
这是目录为v8/src/heap/read-only-heap.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/read-only-heap.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/read-only-heap.h"

#include <cstddef>
#include <cstring>

#include "src/common/globals.h"
#include "src/common/ptr-compr-inl.h"
#include "src/heap/heap-write-barrier-inl.h"
#include "src/heap/memory-chunk-metadata.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/heap/read-only-spaces.h"
#include "src/init/isolate-group.h"
#include "src/objects/heap-object-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/smi.h"
#include "src/sandbox/js-dispatch-table-inl.h"
#include "src/snapshot/read-only-deserializer.h"
#include "src/utils/allocation.h"

namespace v8 {
namespace internal {

#ifndef V8_COMPRESS_POINTERS_IN_MULTIPLE_CAGES
ReadOnlyHeap* ReadOnlyHeap::shared_ro_heap_ = nullptr;
#endif

ReadOnlyHeap::~ReadOnlyHeap() {
#ifdef V8_ENABLE_SANDBOX
  IsolateGroup::current()->code_pointer_table()->TearDownSpace(
      &code_pointer_space_);
#endif
#ifdef V8_ENABLE_LEAPTIERING
  GetProcessWideJSDispatchTable()->DetachSpaceFromReadOnlySegment(
      &js_dispatch_table_space_);
  GetProcessWideJSDispatchTable()->TearDownSpace(&js_dispatch_table_space_);
#endif
}

// static
void ReadOnlyHeap::SetUp(Isolate* isolate,
                         SnapshotData* read_only_snapshot_data,
                         bool can_rehash) {
  DCHECK_NOT_NULL(isolate);

  if (IsReadOnlySpaceShared()) {
    ReadOnlyHeap* ro_heap;
    IsolateGroup* group = isolate->isolate_group();
    if (read_only_snapshot_data != nullptr) {
      bool read_only_heap_created = false;
      base::MutexGuard guard(group->read_only_heap_creation_mutex());
      ReadOnlyArtifacts* artifacts = group->read_only_artifacts();
      if (!artifacts) {
        artifacts = group->InitializeReadOnlyArtifacts();
        artifacts->InitializeChecksum(read_only_snapshot_data);
        ro_heap = CreateInitialHeapForBootstrapping(isolate, artifacts);
        ro_heap->DeserializeIntoIsolate(isolate, read_only_snapshot_data,
                                        can_rehash);
        artifacts->set_initial_next_unique_sfi_id(
            isolate->next_unique_sfi_id());
        read_only_heap_created = true;
      } else {
        ro_heap = artifacts->read_only_heap();
        isolate->SetUpFromReadOnlyArtifacts(artifacts, ro_heap);
#ifdef V8_COMPRESS_POINTERS
        isolate->external_pointer_table().SetUpFromReadOnlyArtifacts(
            isolate->heap()->read_only_external_pointer_space(), artifacts);
#endif  // V8_COMPRESS_POINTERS
      }
      artifacts->VerifyChecksum(read_only_snapshot_data,
                                read_only_heap_created);
      ro_heap->InitializeIsolateRoots(isolate);
    } else {
      // This path should only be taken in mksnapshot, should only be run once
      // before tearing down the Isolate that holds this ReadOnlyArtifacts and
      // is not thread-safe.
      ReadOnlyArtifacts* artifacts = group->read_only_artifacts();
      CHECK(!artifacts);
      artifacts = group->InitializeReadOnlyArtifacts();
      ro_heap = CreateInitialHeapForBootstrapping(isolate, artifacts);

      // Ensure the first read-only page ends up first in the cage.
      ro_heap->read_only_space()->EnsurePage();
      artifacts->VerifyChecksum(read_only_snapshot_data, true);
    }
  } else {
    ReadOnlyHeap* ro_heap =
        new ReadOnlyHeap(new ReadOnlySpace(isolate->heap()));
    isolate->SetUpFromReadOnlyArtifacts(nullptr, ro_heap);
    if (read_only_snapshot_data != nullptr) {
      ro_heap->DeserializeIntoIsolate(isolate, read_only_snapshot_data,
                                      can_rehash);
    }
  }
}

// static
void ReadOnlyHeap::TearDown(Isolate* isolate) {
  IsolateGroup* group = isolate->isolate_group();
  if (group->DecrementIsolateCount() == 0) {
    base::MutexGuard guard(group->read_only_heap_creation_mutex());
    if (isolate->is_shared_space_isolate()) group->ClearSharedSpaceIsolate();
    group->ClearReadOnlyArtifacts();
  }
}

void ReadOnlyHeap::DeserializeIntoIsolate(Isolate* isolate,
                                          SnapshotData* read_only_snapshot_data,
                                          bool can_rehash) {
  DCHECK_NOT_NULL(read_only_snapshot_data);

  ReadOnlyDeserializer des(isolate, read_only_snapshot_data, can_rehash);
  des.DeserializeIntoIsolate();
  OnCreateRootsComplete(isolate);

#ifdef V8_ENABLE_EXTENSIBLE_RO_SNAPSHOT
  if (isolate->serializer_enabled()) {
    // If this isolate will be serialized, leave RO space unfinalized and
    // allocatable s.t. it can be extended (e.g. by future Context::New calls).
    // We reach this scenario when creating custom snapshots - these initially
    // create the isolate from the default V8 snapshot, create new customized
    // contexts, and finally reserialize.
  } else {
    InitFromIsolate(isolate);
  }
#else
  InitFromIsolate(isolate);
#endif  // V8_ENABLE_EXTENSIBLE_RO_SNAPSHOT
}

void ReadOnlyHeap::OnCreateRootsComplete(Isolate* isolate) {
  DCHECK_NOT_NULL(isolate);
  DCHECK(!roots_init_complete_);
  if (IsReadOnlySpaceShared()) InitializeFromIsolateRoots(isolate);
  roots_init_complete_ = true;
}

void ReadOnlyHeap::OnCreateHeapObjectsComplete(Isolate* isolate) {
  DCHECK_NOT_NULL(isolate);

  // InitFromIsolate mutates MemoryChunk flags which would race with any
  // concurrently-running sweeper tasks. Ensure that sweeping has been
  // completed, i.e. no sweeper tasks are currently running.
  isolate->heap()->EnsureSweepingCompleted(
      Heap::SweepingForcedFinalizationMode::kV8Only);

  InitFromIsolate(isolate);

#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) {
    HeapVerifier::VerifyReadOnlyHeap(isolate->heap());
    HeapVerifier::VerifyHeap(isolate->heap());
  }
#endif
}

// static
ReadOnlyHeap* ReadOnlyHeap::CreateInitialHeapForBootstrapping(
    Isolate* isolate, ReadOnlyArtifacts* artifacts) {
  DCHECK(IsReadOnlySpaceShared());

  std::unique_ptr<ReadOnlyHeap> ro_heap;
  ReadOnlySpace* ro_space = new ReadOnlySpace(isolate->heap());
  std::unique_ptr<ReadOnlyHeap> shared_ro_heap(new ReadOnlyHeap(ro_space));
  isolate->isolate_group()->set_shared_read_only_heap(shared_ro_heap.get());
#ifndef V8_COMPRESS_POINTERS_IN_MULTIPLE_CAGES
  shared_ro_heap_ = shared_ro_heap.get();
#endif
  ro_heap = std::move(shared_ro_heap);
  artifacts->set_read_only_heap(std::move(ro_heap));
  isolate->SetUpFromReadOnlyArtifacts(artifacts, artifacts->read_only_heap());
  return artifacts->read_only_heap();
}

void ReadOnlyHeap::InitializeIsolateRoots(Isolate* isolate) {
  void* const isolate_ro_roots =
      isolate->roots_table().read_only_roots_begin().location();
  std::memcpy(isolate_ro_roots, read_only_roots_,
              kEntriesCount * sizeof(Address));
}

void ReadOnlyHeap::InitializeFromIsolateRoots(Isolate* isolate) {
  void* const isolate_ro_roots =
      isolate->roots_table().read_only_roots_begin().location();
  std::memcpy(read_only_roots_, isolate_ro_roots,
              kEntriesCount * sizeof(Address));
}

void ReadOnlyHeap::InitFromIsolate(Isolate* isolate) {
  DCHECK(roots_init_complete_);
  read_only_space_->ShrinkPages();
  if (IsReadOnlySpaceShared()) {
    ReadOnlyArtifacts* artifacts =
        isolate->isolate_group()->read_only_artifacts();
    read_only_space()->DetachPagesAndAddToArtifacts(artifacts);
    artifacts->ReinstallReadOnlySpace(isolate);

    read_only_space_ = artifacts->shared_read_only_space();

#ifdef DEBUG
    artifacts->VerifyHeapAndSpaceRelationships(isolate);
#endif
  } else {
    read_only_space_->Seal(ReadOnlySpace::SealMode::kDoNotDetachFromHeap);
  }
}

ReadOnlyHeap::ReadOnlyHeap(ReadOnlySpace* ro_space)
    : read_only_space_(ro_space) {
#ifdef V8_ENABLE_SANDBOX
  IsolateGroup::current()->code_pointer_table()->InitializeSpace(
      &code_pointer_space_);
#endif  // V8_ENABLE_SANDBOX
#ifdef V8_ENABLE_LEAPTIERING
  GetProcessWideJSDispatchTable()->InitializeSpace(&js_dispatch_table_space_);
  // To avoid marking trying to write to these read-only cells they are
  // allocated black. Target code objects in the read-only dispatch table are
  // read-only code objects.
  js_dispatch_table_space_.set_allocate_black(true);
  GetProcessWideJSDispatchTable()->AttachSpaceToReadOnlySegment(
      &js_dispatch_table_space_);
  GetProcessWideJSDispatchTable()->PreAllocateEntries(
      &js_dispatch_table_space_, JSBuiltinDispatchHandleRoot::kCount,
      Isolate::kBuiltinDispatchHandlesAreStatic);
#endif  // V8_ENABLE_LEAPTIERING
}

// static
void ReadOnlyHeap::PopulateReadOnlySpaceStatistics(
    SharedMemoryStatistics* statistics) {
  statistics->read_only_space_size_ = 0;
  statistics->read_only_space_used_size_ = 0;
  statistics->read_only_space_physical_size_ = 0;
  if (IsReadOnlySpaceShared()) {
    ReadOnlyArtifacts* artifacts =
        IsolateGroup::current()->read_only_artifacts();
    if (artifacts) {
      SharedReadOnlySpace* ro_space = artifacts->shared_read_only_space();
      statistics->read_only_space_size_ = ro_space->CommittedMemory();
      statistics->read_only_space_used_size_ = ro_space->Size();
      statistics->read_only_space_physical_size_ =
          ro_space->CommittedPhysicalMemory();
    }
  }
}

// static
bool ReadOnlyHeap::Contains(Address address) {
  return MemoryChunk::FromAddress(address)->InReadOnlySpace();
}

// static
bool ReadOnlyHeap::Contains(Tagged<HeapObject> object) {
  return Contains(object.address());
}

// static
bool ReadOnlyHeap::SandboxSafeContains(Tagged<HeapObject> object) {
#ifdef V8_ENABLE_SANDBOX
  return MemoryChunk::FromHeapObject(object)->SandboxSafeInReadOnlySpace();
#else
  return Contains(object);
#endif
}

ReadOnlyHeapObjectIterator::ReadOnlyHeapObjectIterator(
    const ReadOnlyHeap* ro_heap)
    : ReadOnlyHeapObjectIterator(ro_heap->read_only_space()) {}

ReadOnlyHeapObjectIterator::ReadOnlyHeapObjectIterator(
    const ReadOnlySpace* ro_space)
    : ro_space_(ro_space),
      current_page_(ro_space->pages().begin()),
      page_iterator_(
          current_page_ == ro_space->pages().end() ? nullptr : *current_page_) {
}

Tagged<HeapObject> ReadOnlyHeapObjectIterator::Next() {
  while (current_page_ != ro_space_->pages().end()) {
    Tagged<HeapObject> obj = page_iterator_.Next();
    if (!obj.is_null()) return obj;

    ++current_page_;
    if (current_page_ == ro_space_->pages().end()) return Tagged<HeapObject>();
    page_iterator_.Reset(*current_page_);
  }

  DCHECK_EQ(current_page_, ro_space_->pages().end());
  return Tagged<HeapObject>();
}

ReadOnlyPageObjectIterator::ReadOnlyPageObjectIterator(
    const ReadOnlyPageMetadata* page,
    SkipFreeSpaceOrFiller skip_free_space_or_filler)
    : ReadOnlyPageObjectIterator(
          page, page == nullptr ? kNullAddress : page->GetAreaStart(),
          skip_free_space_or_filler) {}

ReadOnlyPageObjectIterator::ReadOnlyPageObjectIterator(
    const ReadOnlyPageMetadata* page, Address current_addr,
    SkipFreeSpaceOrFiller skip_free_space_or_filler)
    : page_(page),
      current_addr_(current_addr),
      skip_free_space_or_filler_(skip_free_space_or_filler) {
  DCHECK_GE(current_addr, page->GetAreaStart());
  DCHECK_LT(current_addr, page->GetAreaStart() + page->area_size());
}

Tagged<HeapObject> ReadOnlyPageObjectIterator::Next() {
  if (page_ == nullptr) return HeapObject();

  Address end = page_->GetAreaStart() + page_->area_size();
  for (;;) {
    DCHECK_LE(current_addr_, end);
    if (current_addr_ == end) return HeapObject();

    Tagged<HeapObject> object = HeapObject::FromAddress(current_addr_);
    const int object_size = object->Size();
    current_addr_ += ALIGN_TO_ALLOCATION_ALIGNMENT(object_size);

    if (skip_free_space_or_filler_ == SkipFreeSpaceOrFiller::kYes &&
        IsFreeSpaceOrFiller(object)) {
      continue;
    }

    DCHECK_OBJECT_SIZE(object_size);
    return object;
  }
}

void ReadOnlyPageObjectIterator::Reset(const ReadOnlyPageMetadata* page) {
  page_ = page;
  current_addr_ = page->GetAreaStart();
}

}  // namespace internal
}  // namespace v8

"""

```