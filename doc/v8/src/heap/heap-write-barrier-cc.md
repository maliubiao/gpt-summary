Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Understanding: The Core Task**

The file name `heap-write-barrier.cc` immediately suggests its primary function: managing write barriers within the V8 heap. Write barriers are crucial for garbage collection, ensuring the collector can track object references and prevent dangling pointers.

**2. Dissecting the Includes:**

The `#include` directives provide valuable clues about the file's dependencies and the concepts it interacts with:

* `"src/heap/heap-write-barrier.h"`: The header file for this source file, likely containing declarations.
* `"src/heap/heap-layout-inl.h"`, `"src/heap/heap-write-barrier-inl.h"`: Inline implementations related to heap layout and write barriers. This suggests performance considerations.
* `"src/heap/heap.h"`: The main heap management header.
* `"src/heap/marking-barrier-inl.h"`:  Related to marking phases of garbage collection.
* `"src/heap/memory-chunk-layout.h"`, `"src/heap/memory-chunk.h"`: Deals with the organization of memory into chunks.
* `"src/heap/remembered-set.h"`: Data structures for tracking cross-generational or cross-space references. This is a key aspect of write barriers.
* `"src/objects/code-inl.h"`, `"src/objects/slots-inl.h"`:  Specific object types and how to access their slots (fields).
* `"src/sandbox/js-dispatch-table-inl.h"`:  Related to a dispatch table, likely for optimized function calls (and potentially relevant to leap tiering).

**3. Examining the `namespace v8::internal` and the Anonymous Namespace:**

This confirms the code is part of V8's internal implementation. The anonymous namespace `namespace { ... }` is a common C++ practice to limit the scope of variables (like `current_marking_barrier`) to this translation unit, preventing naming conflicts.

**4. Analyzing Key Functions and Concepts:**

* **`MarkingBarrier* current_marking_barrier`:** A thread-local variable. This strongly implies that marking (and thus write barriers) can be handled differently on different threads.
* **`WriteBarrier::CurrentMarkingBarrier()` and `WriteBarrier::SetForThread()`:**  These manage the thread-local `MarkingBarrier`. The `DCHECK` calls are important for debugging and asserting invariants.
* **`WriteBarrier::MarkingSlow()` variations:** These functions are the core of the marking write barrier. The "Slow" suffix often indicates a path taken when optimizations don't apply or more complex logic is needed. The variations handle different scenarios (object slots, reloc info in code, C++ heap pointers, array buffer extensions, descriptor arrays, etc.).
* **`WriteBarrier::SharedSlow()` variations:** These deal with write barriers specifically for objects moving between the regular heap and the shared heap (used for cross-isolate communication). The use of `RememberedSet<OLD_TO_SHARED>` is a strong indicator of this.
* **`WriteBarrier::MarkingFromCode()` and `WriteBarrier::SharedFromCode()`:** The "FromCode" suffix suggests these are called directly from generated machine code (likely through stubs or inline code). They are optimized entry points.
* **`WriteBarrier::GenerationalBarrierSlow()`:**  This focuses on write barriers needed for generational garbage collection (tracking references from older generations to younger generations). The `RememberedSet<OLD_TO_NEW>` is key here.
* **`WriteBarrier::CombinedGenerationalAndShared*BarrierSlow()`:** These handle cases where an object write might trigger both generational and shared heap write barriers.
* **`WriteBarrier::ForRange()`:**  This is an important optimization for bulk write barriers, iterating over a range of slots within an object. The template nature allows it to work with different slot types. The logic within it efficiently determines which barriers are needed.
* **`WriteBarrier::PageFlagsAreConsistent()`:** A debugging function to verify the internal state of memory chunks.
* **`WriteBarrier::VerifyDispatchHandleMarkingState()`:**  Related to the `JSDispatchTable` and checking the marking state, likely for scenarios involving optimized function calls.

**5. Identifying Core Functionality:**

Based on the function names and the data structures involved, the primary functions are:

* **Tracking Object References:**  Ensuring the garbage collector knows when an object in one memory region references an object in another region.
* **Marking Objects:**  Informing the garbage collector's marking phase about reachable objects.
* **Handling Different Memory Spaces:**  Specifically dealing with writes involving the young generation, old generation, and shared heap.
* **Optimization:** The existence of "Slow" and "FromCode" variations indicates that performance is a concern, and optimized paths are used where possible.

**6. Connecting to JavaScript:**

The key is understanding *why* write barriers are needed. They are essential for the correctness of garbage collection, which is a fundamental part of JavaScript's memory management. When a JavaScript operation modifies object references, the write barrier ensures that the garbage collector is aware of these changes.

**7. Inferring Potential Errors:**

The complexity of the write barrier logic suggests opportunities for errors if not handled correctly. The code includes `DCHECK` calls, highlighting areas where V8 developers anticipate potential issues.

**8. Considering the `.tq` Extension:**

The prompt specifically asks about the `.tq` extension, which signals Torque. If this were a Torque file, the code would be more declarative, focusing on specifying the logic rather than the low-level implementation details. The absence of `.tq` confirms this is a standard C++ file.

**9. Structuring the Output:**

Finally, the information is organized into the requested sections:

* **Functionality:** A concise summary of the code's purpose.
* **Torque:** Addressing the `.tq` question.
* **JavaScript Relation:** Providing concrete JavaScript examples that *trigger* the write barriers indirectly.
* **Logic Inference:** Creating a simplified scenario to illustrate the core write barrier mechanism.
* **Common Programming Errors:** Identifying potential errors related to manual memory management or assumptions about object lifetimes (though these are less direct in managed languages like JavaScript).

This detailed analysis, combining code examination, understanding of garbage collection principles, and consideration of the specific prompt requirements, leads to the comprehensive answer provided previously.
The provided C++ code snippet is a part of the V8 JavaScript engine, specifically focusing on the **heap write barrier**. Let's break down its functionalities:

**Core Functionality of `v8/src/heap/heap-write-barrier.cc`:**

The primary responsibility of this code is to implement the **write barrier** mechanism for V8's garbage collector. A write barrier is a crucial component in garbage-collected environments that ensures the collector remains aware of all reachable objects, especially during concurrent or incremental garbage collection phases. It intercepts pointer writes (when one object starts pointing to another) and performs actions necessary to maintain the garbage collector's invariants.

Here's a breakdown of its key functionalities:

1. **Tracking Object References for Garbage Collection:**
   - When a pointer within a heap object is updated to point to another heap object, the write barrier is invoked.
   - It records these pointer updates so the garbage collector can accurately trace object graphs and identify live objects. This is crucial for avoiding premature collection of reachable objects.

2. **Handling Generational Garbage Collection:**
   - V8 uses a generational garbage collector, where objects are grouped into generations (young and old).
   - The write barrier is essential for tracking pointers from older generations to younger generations (often referred to as "old-to-new" pointers). This allows the young generation garbage collector to efficiently collect garbage without scanning the entire heap.
   - The `GenerationalBarrierSlow` functions and the use of `RememberedSet<OLD_TO_NEW>` are directly related to this.

3. **Supporting Concurrent and Incremental Marking:**
   - V8's garbage collector often performs marking (identifying reachable objects) concurrently with JavaScript execution or incrementally in smaller steps.
   - The write barrier ensures that changes made by the mutator (JavaScript code) during the marking phase are reflected in the collector's view of the heap. This prevents the "black-is-black" problem, where a reachable object might be missed because a pointer to it was created after the collector visited the source object.
   - The `MarkingSlow` functions and the interaction with `MarkingBarrier` are central to this.

4. **Managing Shared Heap and Cross-Isolate References:**
   - V8 supports shared heaps for scenarios like Web Workers, where different isolates (execution contexts) can share certain objects.
   - The write barrier handles updates to pointers in the shared heap and between different isolates.
   - The `SharedSlow` functions and the use of `RememberedSet<OLD_TO_SHARED>` are important for this.

5. **Handling Different Slot Types:**
   - The code handles write barriers for various types of slots (memory locations within objects that can hold pointers), such as `HeapObjectSlot`, `RelocInfo`, `CppHeapPointerSlot`, `ExternalPointerSlot`, etc.

6. **Optimized Write Barriers:**
   - The code includes "slow" and potentially faster paths for write barriers (though the provided snippet primarily shows the "slow" paths). Optimizations are crucial for minimizing the performance overhead of write barriers. The `MarkingFromCode` and `SharedFromCode` functions suggest entry points called directly from generated code for performance.

7. **Ephemeron Tables:**
   - The `EphemeronKeyWriteBarrierFromCode` function and the interaction with `EphemeronHashTable` are specific to ephemeron tables, which are hash tables where the presence of a key-value pair depends on the reachability of the key.

**Is `v8/src/heap/heap-write-barrier.cc` a Torque source file?**

No, based on the provided code, `v8/src/heap/heap-write-barrier.cc` is a standard C++ source file. The comment in the prompt mentions that if the file ended with `.tq`, it would be a V8 Torque source file. Since it ends with `.cc`, it's C++.

**Relationship with JavaScript and Examples:**

The `v8/src/heap/heap-write-barrier.cc` code is fundamental to how JavaScript's garbage collection works. While JavaScript developers don't directly interact with this C++ code, every time you perform an operation that modifies object references in JavaScript, you are implicitly triggering the write barrier.

Here are some JavaScript examples that would indirectly invoke the write barrier:

```javascript
// Creating an object and assigning a reference
let obj1 = { data: 1 };
let obj2 = { ref: obj1 }; // The assignment to obj2.ref triggers the write barrier

// Modifying an object's property to point to another object
let obj3 = {};
let obj4 = { value: 10 };
obj3.anotherRef = obj4; // Assigning obj4 to obj3.anotherRef triggers the write barrier

// Adding an element to an array that is an object
let arr = [];
let obj5 = { name: "test" };
arr.push(obj5); // Adding obj5 to the array triggers the write barrier

// Creating a closure that captures a variable
function createCounter() {
  let count = 0;
  return function() {
    count++; // The closure keeps 'count' alive, involving the garbage collector
    return count;
  };
}
let counter = createCounter();
```

In each of these examples, when a reference to an object is stored in another object or data structure, the write barrier ensures that the garbage collector knows about this new connection.

**Code Logic Inference (Hypothetical Scenario):**

Let's consider a simplified scenario focusing on generational garbage collection:

**Hypothetical Input:**

1. We have an object `oldGenObj` residing in the old generation.
2. We have an object `youngGenObj` residing in the young generation.
3. JavaScript code executes `oldGenObj.field = youngGenObj;`

**Code Logic (Simplified):**

1. The write operation to `oldGenObj.field` is intercepted.
2. `WriteBarrier::GenerationalBarrierSlow(oldGenObj, /* address of field */, youngGenObj)` is likely called (or a similar optimized function).
3. Inside `GenerationalBarrierSlow`:
   - It checks if `youngGenObj` is in the young generation (using `HeapLayout::InYoungGeneration`).
   - Since it is, the information about this "old-to-new" pointer is recorded in the `RememberedSet<OLD_TO_NEW>` associated with the memory page of `oldGenObj`.

**Hypothetical Output:**

- The `RememberedSet` for the memory page containing `oldGenObj` now contains an entry indicating that a slot within `oldGenObj` points to an object in the young generation.

**Purpose:** When the young generation garbage collector runs, it will consult these `RememberedSet`s to find pointers from older generations into the young generation. These pointers indicate that the pointed-to young generation objects are still live and should not be collected.

**Common Programming Errors Related to Write Barriers (Indirectly):**

While JavaScript developers don't directly manage write barriers, understanding their purpose helps in avoiding patterns that can hinder garbage collection performance or lead to memory leaks (though less common in garbage-collected languages compared to manual memory management).

1. **Creating Excessive Cross-Generational Pointers:**  While unavoidable in many cases, excessively creating pointers from old generations to young generations can increase the workload of the young generation garbage collector, as it needs to scan the remembered sets.

   ```javascript
   // Example (potentially inefficient if done excessively):
   let cache = {};
   function storeData(key, data) {
     cache[key] = data; // 'cache' might be in the old generation, 'data' in young
   }
   ```

2. **Detached DOM Elements:**  Holding references to detached DOM elements in JavaScript can prevent them and their associated resources from being garbage collected. This is because the JavaScript object holds a reference, and the garbage collector follows these references.

   ```javascript
   let detachedElement;
   function detach() {
     detachedElement = document.getElementById('someElement');
     detachedElement.parentNode.removeChild(detachedElement);
   }

   // If 'detachedElement' is still in scope and holds the reference,
   // the garbage collector won't reclaim the memory.
   ```

3. **Circular References (Less of an Issue with Modern GCs):** Older garbage collection algorithms struggled with circular references (where objects point to each other, preventing them from being collected even if no external references exist). Modern garbage collectors, like V8's, use mark-and-sweep or similar algorithms that can handle most circular references. However, very complex and large circular structures might still have some performance implications.

**In Summary:**

`v8/src/heap/heap-write-barrier.cc` is a crucial piece of V8's infrastructure responsible for ensuring the correctness and efficiency of garbage collection. It intercepts pointer writes and records information necessary for the garbage collector to track live objects across different generations and memory spaces. While JavaScript developers don't directly interact with this code, understanding its purpose helps in appreciating how V8 manages memory and can indirectly inform coding practices for better performance.

### 提示词
```
这是目录为v8/src/heap/heap-write-barrier.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/heap-write-barrier.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/heap-write-barrier.h"

#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap-write-barrier-inl.h"
#include "src/heap/heap.h"
#include "src/heap/marking-barrier-inl.h"
#include "src/heap/memory-chunk-layout.h"
#include "src/heap/memory-chunk.h"
#include "src/heap/remembered-set.h"
#include "src/objects/code-inl.h"
#include "src/objects/slots-inl.h"
#include "src/sandbox/js-dispatch-table-inl.h"

namespace v8::internal {

class DescriptorArray;

namespace {
thread_local MarkingBarrier* current_marking_barrier = nullptr;
}  // namespace

MarkingBarrier* WriteBarrier::CurrentMarkingBarrier(
    Tagged<HeapObject> verification_candidate) {
  MarkingBarrier* marking_barrier = current_marking_barrier;
  DCHECK_NOT_NULL(marking_barrier);
#if DEBUG
  if (!verification_candidate.is_null() &&
      !HeapLayout::InAnySharedSpace(verification_candidate)) {
    Heap* host_heap =
        MutablePageMetadata::FromHeapObject(verification_candidate)->heap();
    LocalHeap* local_heap = LocalHeap::Current();
    if (!local_heap) local_heap = host_heap->main_thread_local_heap();
    DCHECK_EQ(marking_barrier, local_heap->marking_barrier());
  }
#endif  // DEBUG
  return marking_barrier;
}

MarkingBarrier* WriteBarrier::SetForThread(MarkingBarrier* marking_barrier) {
  MarkingBarrier* existing = current_marking_barrier;
  current_marking_barrier = marking_barrier;
  return existing;
}

void WriteBarrier::MarkingSlow(Tagged<HeapObject> host, HeapObjectSlot slot,
                               Tagged<HeapObject> value) {
  MarkingBarrier* marking_barrier = CurrentMarkingBarrier(host);
  marking_barrier->Write(host, slot, value);
}

// static
void WriteBarrier::MarkingSlowFromTracedHandle(Tagged<HeapObject> value) {
  MarkingBarrier* marking_barrier = CurrentMarkingBarrier(value);
  marking_barrier->WriteWithoutHost(value);
}

// static
void WriteBarrier::MarkingSlowFromCppHeapWrappable(Heap* heap,
                                                   Tagged<JSObject> host,
                                                   CppHeapPointerSlot slot,
                                                   void* object) {
  // Note: this is currently a combined barrier for marking both the
  // CppHeapPointerTable entry and the referenced object (if any).

#ifdef V8_COMPRESS_POINTERS
  MarkingBarrier* marking_barrier = CurrentMarkingBarrier(host);
  IsolateForPointerCompression isolate(marking_barrier->heap()->isolate());

  CppHeapPointerTable& table = isolate.GetCppHeapPointerTable();
  CppHeapPointerTable::Space* space = isolate.GetCppHeapPointerTableSpace();

  ExternalPointerHandle handle = slot.Relaxed_LoadHandle();
  table.Mark(space, handle, slot.address());
#endif  // V8_COMPRESS_POINTERS

  if (heap->cpp_heap() && object) {
    CppHeap::From(heap->cpp_heap())->WriteBarrier(object);
  }
}

void WriteBarrier::MarkingSlow(Tagged<InstructionStream> host,
                               RelocInfo* reloc_info,
                               Tagged<HeapObject> value) {
  MarkingBarrier* marking_barrier = CurrentMarkingBarrier(host);
  marking_barrier->Write(host, reloc_info, value);
}

// static
void WriteBarrier::SharedSlow(Tagged<InstructionStream> host,
                              RelocInfo* reloc_info, Tagged<HeapObject> value) {
  MarkCompactCollector::RecordRelocSlotInfo info =
      MarkCompactCollector::ProcessRelocInfo(host, reloc_info, value);

  base::MutexGuard write_scope(info.page_metadata->mutex());
  RememberedSet<OLD_TO_SHARED>::InsertTyped(info.page_metadata, info.slot_type,
                                            info.offset);
}

// static
void WriteBarrier::SharedHeapBarrierSlow(Tagged<HeapObject> object,
                                         Address slot) {
  MemoryChunk* chunk = MemoryChunk::FromHeapObject(object);
  DCHECK(!chunk->InWritableSharedSpace());
  RememberedSet<OLD_TO_SHARED>::Insert<AccessMode::ATOMIC>(
      MutablePageMetadata::cast(chunk->Metadata()), chunk->Offset(slot));
}

// static
void WriteBarrier::SharedSlow(Tagged<TrustedObject> host,
                              ProtectedPointerSlot slot,
                              Tagged<TrustedObject> value) {
  DCHECK(MemoryChunk::FromHeapObject(value)->InWritableSharedSpace());
  if (!MemoryChunk::FromHeapObject(host)->InWritableSharedSpace()) {
    MutablePageMetadata* host_chunk_metadata =
        MutablePageMetadata::FromHeapObject(host);
    RememberedSet<TRUSTED_TO_SHARED_TRUSTED>::Insert<AccessMode::NON_ATOMIC>(
        host_chunk_metadata, host_chunk_metadata->Offset(slot.address()));
  }
}

void WriteBarrier::MarkingSlow(Tagged<JSArrayBuffer> host,
                               ArrayBufferExtension* extension) {
  MarkingBarrier* marking_barrier = CurrentMarkingBarrier(host);
  marking_barrier->Write(host, extension);
}

void WriteBarrier::MarkingSlow(Tagged<DescriptorArray> descriptor_array,
                               int number_of_own_descriptors) {
  MarkingBarrier* marking_barrier = CurrentMarkingBarrier(descriptor_array);
  marking_barrier->Write(descriptor_array, number_of_own_descriptors);
}

void WriteBarrier::MarkingSlow(Tagged<HeapObject> host,
                               ExternalPointerSlot slot) {
#ifdef V8_COMPRESS_POINTERS
  if (!slot.HasExternalPointerHandle()) return;

  MarkingBarrier* marking_barrier = CurrentMarkingBarrier(host);
  IsolateForPointerCompression isolate(marking_barrier->heap()->isolate());

  ExternalPointerTable& table = isolate.GetExternalPointerTableFor(slot.tag());
  ExternalPointerTable::Space* space =
      isolate.GetExternalPointerTableSpaceFor(slot.tag(), host.address());

  ExternalPointerHandle handle = slot.Relaxed_LoadHandle();
  table.Mark(space, handle, slot.address());
#endif  // V8_COMPRESS_POINTERS
}

void WriteBarrier::MarkingSlow(Tagged<HeapObject> host,
                               IndirectPointerSlot slot) {
  MarkingBarrier* marking_barrier = CurrentMarkingBarrier(host);
  marking_barrier->Write(host, slot);
}

void WriteBarrier::MarkingSlow(Tagged<TrustedObject> host,
                               ProtectedPointerSlot slot,
                               Tagged<TrustedObject> value) {
  MarkingBarrier* marking_barrier = CurrentMarkingBarrier(host);
  marking_barrier->Write(host, slot, value);
}

void WriteBarrier::MarkingSlow(Tagged<HeapObject> host,
                               JSDispatchHandle handle) {
#ifdef V8_ENABLE_LEAPTIERING
  MarkingBarrier* marking_barrier = CurrentMarkingBarrier(host);

  // The JSDispatchTable is only marked during major GC so we can skip the
  // barrier if we're only doing a minor GC.
  // This is mostly an optimization, but it does help avoid scenarios where a
  // minor GC marking barrier marks a table entry as alive but not the Code
  // object contained in it (because it's not a young-gen object).
  if (marking_barrier->is_minor()) return;

  // Mark both the table entry and its content.
  JSDispatchTable* jdt = GetProcessWideJSDispatchTable();
  static_assert(JSDispatchTable::kWriteBarrierSetsEntryMarkBit);
  jdt->Mark(handle);
  marking_barrier->MarkValue(host, jdt->GetCode(handle));

  // We don't need to record a slot here because the entries in the
  // JSDispatchTable are not compacted and because the pointers stored in the
  // table entries are updated after compacting GC.
  static_assert(!JSDispatchTable::kSupportsCompaction);
#else
  UNREACHABLE();
#endif
}

int WriteBarrier::MarkingFromCode(Address raw_host, Address raw_slot) {
  Tagged<HeapObject> host = Cast<HeapObject>(Tagged<Object>(raw_host));
  MaybeObjectSlot slot(raw_slot);
  Address value = (*slot).ptr();

#ifdef V8_MAP_PACKING
  if (slot.address() == host.address()) {
    // Clear metadata bits and fix object tag.
    value = (value & ~Internals::kMapWordMetadataMask &
             ~Internals::kMapWordXorMask) |
            (uint64_t)kHeapObjectTag;
  }
#endif

#if DEBUG
  Heap* heap = MutablePageMetadata::FromHeapObject(host)->heap();
  DCHECK(heap->incremental_marking()->IsMarking());

  // We will only reach local objects here while incremental marking in the
  // current isolate is enabled. However, we might still reach objects in the
  // shared space but only from the shared space isolate (= the main isolate).
  MarkingBarrier* barrier = CurrentMarkingBarrier(host);
  DCHECK_IMPLIES(HeapLayout::InWritableSharedSpace(host),
                 barrier->heap()->isolate()->is_shared_space_isolate());
  barrier->AssertMarkingIsActivated();
#endif  // DEBUG

  Marking(host, slot, Tagged<MaybeObject>(value));
  // Called by WriteBarrierCodeStubAssembler, which doesn't accept void type
  return 0;
}

int WriteBarrier::IndirectPointerMarkingFromCode(Address raw_host,
                                                 Address raw_slot,
                                                 Address raw_tag) {
  Tagged<HeapObject> host = Cast<HeapObject>(Tagged<Object>(raw_host));
  IndirectPointerTag tag = static_cast<IndirectPointerTag>(raw_tag);
  DCHECK(IsValidIndirectPointerTag(tag));
  IndirectPointerSlot slot(raw_slot, tag);

#if DEBUG
  DCHECK(!HeapLayout::InWritableSharedSpace(host));
  MarkingBarrier* barrier = CurrentMarkingBarrier(host);
  DCHECK(barrier->heap()->isolate()->isolate_data()->is_marking());

  DCHECK(IsExposedTrustedObject(slot.load(barrier->heap()->isolate())));
#endif

  Marking(host, slot);
  // Called by WriteBarrierCodeStubAssembler, which doesn't accept void type
  return 0;
}

int WriteBarrier::SharedMarkingFromCode(Address raw_host, Address raw_slot) {
  Tagged<HeapObject> host = Cast<HeapObject>(Tagged<Object>(raw_host));
  MaybeObjectSlot slot(raw_slot);
  Address raw_value = (*slot).ptr();
  Tagged<MaybeObject> value(raw_value);

  DCHECK(HeapLayout::InWritableSharedSpace(host));

#if DEBUG
  Heap* heap = MutablePageMetadata::FromHeapObject(host)->heap();
  DCHECK(heap->incremental_marking()->IsMajorMarking());
  Isolate* isolate = heap->isolate();
  DCHECK(isolate->is_shared_space_isolate());

  // The shared marking barrier will only be reached from client isolates (=
  // worker isolates).
  MarkingBarrier* barrier = CurrentMarkingBarrier(host);
  DCHECK(!barrier->heap()->isolate()->is_shared_space_isolate());
  barrier->AssertSharedMarkingIsActivated();
#endif  // DEBUG

  Marking(host, slot, Tagged<MaybeObject>(value));

  // Called by WriteBarrierCodeStubAssembler, which doesn't accept void type
  return 0;
}

int WriteBarrier::SharedFromCode(Address raw_host, Address raw_slot) {
  Tagged<HeapObject> host = Cast<HeapObject>(Tagged<Object>(raw_host));

  if (!HeapLayout::InWritableSharedSpace(host)) {
    SharedHeapBarrierSlow(host, raw_slot);
  }

  // Called by WriteBarrierCodeStubAssembler, which doesn't accept void type
  return 0;
}

// static
bool WriteBarrier::PageFlagsAreConsistent(Tagged<HeapObject> object) {
  MemoryChunkMetadata* metadata = MemoryChunkMetadata::FromHeapObject(object);
  MemoryChunk* chunk = MemoryChunk::FromHeapObject(object);

  // Slim chunk flags consistency.
  CHECK_EQ(chunk->IsFlagSet(MemoryChunk::INCREMENTAL_MARKING),
           chunk->IsMarking());

  if (!v8_flags.sticky_mark_bits) {
    AllocationSpace identity = metadata->owner()->identity();

    // Generation consistency.
    CHECK_EQ(identity == NEW_SPACE || identity == NEW_LO_SPACE,
             chunk->InYoungGeneration());
  }

  // Marking consistency.
  if (metadata->IsWritable()) {
    // RO_SPACE can be shared between heaps, so we can't use RO_SPACE objects to
    // find a heap. The exception is when the ReadOnlySpace is writeable, during
    // bootstrapping, so explicitly allow this case.
    Heap* heap = Heap::FromWritableHeapObject(object);
    if (chunk->InWritableSharedSpace()) {
      // The marking bit is not set for chunks in shared spaces during MinorMS
      // concurrent marking.
      CHECK_EQ(chunk->IsMarking(),
               heap->incremental_marking()->IsMajorMarking());
    } else {
      CHECK_EQ(chunk->IsMarking(), heap->incremental_marking()->IsMarking());
    }
  } else {
    // Non-writable RO_SPACE must never have marking flag set.
    CHECK(!chunk->IsMarking());
  }
  return true;
}

// static
void WriteBarrier::GenerationalBarrierForCodeSlow(
    Tagged<InstructionStream> host, RelocInfo* rinfo,
    Tagged<HeapObject> value) {
  DCHECK(HeapLayout::InYoungGeneration(value));
  const MarkCompactCollector::RecordRelocSlotInfo info =
      MarkCompactCollector::ProcessRelocInfo(host, rinfo, value);

  base::MutexGuard write_scope(info.page_metadata->mutex());
  RememberedSet<OLD_TO_NEW>::InsertTyped(info.page_metadata, info.slot_type,
                                         info.offset);
}

// static
void WriteBarrier::CombinedGenerationalAndSharedEphemeronBarrierSlow(
    Tagged<EphemeronHashTable> table, Address slot, Tagged<HeapObject> value) {
  if (HeapLayout::InYoungGeneration(value)) {
    MutablePageMetadata* table_chunk =
        MutablePageMetadata::FromHeapObject(table);
    table_chunk->heap()->ephemeron_remembered_set()->RecordEphemeronKeyWrite(
        table, slot);
  } else {
    DCHECK(MemoryChunk::FromHeapObject(value)->InWritableSharedSpace());
    DCHECK(!HeapLayout::InWritableSharedSpace(table));
    SharedHeapBarrierSlow(table, slot);
  }
}

// static
void WriteBarrier::CombinedGenerationalAndSharedBarrierSlow(
    Tagged<HeapObject> object, Address slot, Tagged<HeapObject> value) {
  if (HeapLayout::InYoungGeneration(value)) {
    GenerationalBarrierSlow(object, slot, value);

  } else {
    DCHECK(MemoryChunk::FromHeapObject(value)->InWritableSharedSpace());
    DCHECK(!HeapLayout::InWritableSharedSpace(object));
    SharedHeapBarrierSlow(object, slot);
  }
}

//  static
void WriteBarrier::GenerationalBarrierSlow(Tagged<HeapObject> object,
                                           Address slot,
                                           Tagged<HeapObject> value) {
  MemoryChunk* chunk = MemoryChunk::FromHeapObject(object);
  MutablePageMetadata* metadata = MutablePageMetadata::cast(chunk->Metadata());
  if (LocalHeap::Current() == nullptr) {
    RememberedSet<OLD_TO_NEW>::Insert<AccessMode::NON_ATOMIC>(
        metadata, chunk->Offset(slot));
  } else {
    RememberedSet<OLD_TO_NEW_BACKGROUND>::Insert<AccessMode::ATOMIC>(
        metadata, chunk->Offset(slot));
  }
}

// static
void WriteBarrier::EphemeronKeyWriteBarrierFromCode(Address raw_object,
                                                    Address key_slot_address,
                                                    Isolate* isolate) {
  Tagged<EphemeronHashTable> table =
      Cast<EphemeronHashTable>(Tagged<Object>(raw_object));
  ObjectSlot key_slot(key_slot_address);
  ForEphemeronHashTable(table, key_slot, *key_slot, UPDATE_WRITE_BARRIER);
}

namespace {

enum RangeWriteBarrierMode {
  kDoGenerationalOrShared = 1 << 0,
  kDoMarking = 1 << 1,
  kDoEvacuationSlotRecording = 1 << 2,
};

template <int kModeMask, typename TSlot>
void ForRangeImpl(Heap* heap, MemoryChunk* source_chunk,
                  Tagged<HeapObject> object, TSlot start_slot, TSlot end_slot) {
  // At least one of generational or marking write barrier should be requested.
  static_assert(kModeMask & (kDoGenerationalOrShared | kDoMarking));
  // kDoEvacuationSlotRecording implies kDoMarking.
  static_assert(!(kModeMask & kDoEvacuationSlotRecording) ||
                (kModeMask & kDoMarking));

  MarkingBarrier* marking_barrier = nullptr;
  static constexpr Tagged_t kPageMask =
      ~static_cast<Tagged_t>(PageMetadata::kPageSize - 1);
  Tagged_t cached_uninteresting_page =
      static_cast<Tagged_t>(heap->read_only_space()->FirstPageAddress()) &
      kPageMask;

  if (kModeMask & kDoMarking) {
    marking_barrier = WriteBarrier::CurrentMarkingBarrier(object);
  }

  MarkCompactCollector* collector = heap->mark_compact_collector();
  MutablePageMetadata* source_page_metadata =
      MutablePageMetadata::cast(source_chunk->Metadata());

  for (TSlot slot = start_slot; slot < end_slot; ++slot) {
    // If we *only* need the generational or shared WB, we can skip objects
    // residing on uninteresting pages.
    Tagged_t compressed_page;
    if (kModeMask == kDoGenerationalOrShared) {
      Tagged_t tagged_value = *slot.location();
      if (HAS_SMI_TAG(tagged_value)) continue;
      compressed_page = tagged_value & kPageMask;
      if (compressed_page == cached_uninteresting_page) {
#if DEBUG
        typename TSlot::TObject value = *slot;
        Tagged<HeapObject> value_heap_object;
        if (value.GetHeapObject(&value_heap_object)) {
          CHECK(!HeapLayout::InYoungGeneration(value_heap_object));
          CHECK(!HeapLayout::InWritableSharedSpace(value_heap_object));
        }
#endif  // DEBUG
        continue;
      }
      // Fall through to decompressing the pointer and fetching its actual
      // page header flags.
    }
    typename TSlot::TObject value = *slot;
    Tagged<HeapObject> value_heap_object;
    if (!value.GetHeapObject(&value_heap_object)) continue;

    if (kModeMask & kDoGenerationalOrShared) {
      if (HeapLayout::InYoungGeneration(value_heap_object)) {
        RememberedSet<OLD_TO_NEW>::Insert<AccessMode::NON_ATOMIC>(
            source_page_metadata, source_chunk->Offset(slot.address()));
      } else if (HeapLayout::InWritableSharedSpace(value_heap_object)) {
        RememberedSet<OLD_TO_SHARED>::Insert<AccessMode::ATOMIC>(
            source_page_metadata, source_chunk->Offset(slot.address()));
      } else if (kModeMask == kDoGenerationalOrShared) {
        cached_uninteresting_page = compressed_page;
      }
    }

    if (kModeMask & kDoMarking) {
      marking_barrier->MarkValue(object, value_heap_object);
      if (kModeMask & kDoEvacuationSlotRecording) {
        collector->RecordSlot(source_chunk, HeapObjectSlot(slot),
                              value_heap_object);
      }
    }
  }
}

}  // namespace

// Instantiate `WriteBarrier::WriteBarrierForRange()` for `ObjectSlot` and
// `MaybeObjectSlot`.
template void WriteBarrier::ForRange<ObjectSlot>(Heap* heap,
                                                 Tagged<HeapObject> object,
                                                 ObjectSlot start_slot,
                                                 ObjectSlot end_slot);
template void WriteBarrier::ForRange<MaybeObjectSlot>(
    Heap* heap, Tagged<HeapObject> object, MaybeObjectSlot start_slot,
    MaybeObjectSlot end_slot);

template <typename TSlot>
// static
void WriteBarrier::ForRange(Heap* heap, Tagged<HeapObject> object,
                            TSlot start_slot, TSlot end_slot) {
  if (v8_flags.disable_write_barriers) return;
  MemoryChunk* source_chunk = MemoryChunk::FromHeapObject(object);
  base::Flags<RangeWriteBarrierMode> mode;

  if (!HeapLayout::InYoungGeneration(object) &&
      !source_chunk->InWritableSharedSpace()) {
    mode |= kDoGenerationalOrShared;
  }

  if (heap->incremental_marking()->IsMarking()) {
    mode |= kDoMarking;
    if (!source_chunk->ShouldSkipEvacuationSlotRecording()) {
      mode |= kDoEvacuationSlotRecording;
    }
  }

  switch (mode) {
    // Nothing to be done.
    case 0:
      return;
    // Generational only.
    case kDoGenerationalOrShared:
      return ForRangeImpl<kDoGenerationalOrShared>(heap, source_chunk, object,
                                                   start_slot, end_slot);
    // Marking, no evacuation slot recording.
    case kDoMarking:
      return ForRangeImpl<kDoMarking>(heap, source_chunk, object, start_slot,
                                      end_slot);
    // Marking with evacuation slot recording.
    case kDoMarking | kDoEvacuationSlotRecording:
      return ForRangeImpl<kDoMarking | kDoEvacuationSlotRecording>(
          heap, source_chunk, object, start_slot, end_slot);
    // Generational and marking, no evacuation slot recording.
    case kDoGenerationalOrShared | kDoMarking:
      return ForRangeImpl<kDoGenerationalOrShared | kDoMarking>(
          heap, source_chunk, object, start_slot, end_slot);
    // Generational and marking with evacuation slot recording.
    case kDoGenerationalOrShared | kDoMarking | kDoEvacuationSlotRecording:
      return ForRangeImpl<kDoGenerationalOrShared | kDoMarking |
                          kDoEvacuationSlotRecording>(
          heap, source_chunk, object, start_slot, end_slot);
    default:
      UNREACHABLE();
  }
}

#ifdef ENABLE_SLOW_DCHECKS

// static
bool WriteBarrier::VerifyDispatchHandleMarkingState(Tagged<HeapObject> host,
                                                    JSDispatchHandle handle,
                                                    WriteBarrierMode mode) {
#ifdef V8_ENABLE_LEAPTIERING
  if (mode == SKIP_WRITE_BARRIER &&
      WriteBarrier::IsRequired(
          host, GetProcessWideJSDispatchTable()->GetCode(handle))) {
    return false;
  }

  if (CurrentMarkingBarrier(host)->is_not_major()) return true;

  // Ensure we don't have a black -> white -> black edge. This could happen when
  // skipping a write barrier while concurrently the dispatch entry is marked
  // from another JSFunction.
  if (ReadOnlyHeap::Contains(host) ||
      (IsMarking(host) && mode != SKIP_WRITE_BARRIER) ||
      !CurrentMarkingBarrier(host)->IsMarked(host)) {
    return true;
  }
  if (GetProcessWideJSDispatchTable()->IsMarked(handle)) {
    return true;
  }
  Tagged<Code> value = GetProcessWideJSDispatchTable()->GetCode(handle);
  if (ReadOnlyHeap::Contains(value)) {
    return true;
  }
  return !CurrentMarkingBarrier(host)->IsMarked(value);
#else
  return true;
#endif  // V8_ENABLE_LEAPTIERING
}

#endif  // ENABLE_SLOW_DCHECKS

}  // namespace v8::internal
```