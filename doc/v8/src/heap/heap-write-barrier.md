Response: Let's break down the thought process for analyzing the C++ code and generating the summary and JavaScript examples.

1. **Understand the Goal:** The primary goal is to understand the *purpose* of the C++ code, specifically how it relates to memory management in V8 (the JavaScript engine) and, if possible, to illustrate its effect with JavaScript examples.

2. **Identify Key Terms:** Scan the code for recurring keywords and concepts. In this case, "WriteBarrier," "MarkingBarrier," "HeapObject," "Slot," "YoungGeneration," "SharedSpace," "RememberedSet," "GC" (implied by marking and evacuation), and "Code" stand out. These are all related to memory management and garbage collection.

3. **Infer High-Level Functionality:** The name "WriteBarrier" strongly suggests a mechanism to control or record writes to memory. The presence of "MarkingBarrier" and the various `MarkingSlow` functions point towards garbage collection, specifically the marking phase. The terms "YoungGeneration" and "SharedSpace" suggest different regions of memory with different GC behaviors.

4. **Analyze Individual Functions (Initial Pass):** Go through each function and try to understand its immediate effect:
    * `CurrentMarkingBarrier`, `SetForThread`:  Manage the current marking barrier for a thread.
    * `MarkingSlow`: These functions seem to be the core write barrier logic during marking. They take a source object (`host`), a memory location (`slot`, `reloc_info`, etc.), and a value being written.
    * `SharedSlow`, `SharedHeapBarrierSlow`: Deal with writes involving shared memory.
    * `MarkingFromCode`, `SharedFromCode`:  Called from generated machine code.
    * `GenerationalBarrierSlow`: Handles writes where the target is in the "young generation."
    * `ForRange`: Applies write barriers to a range of slots.

5. **Connect Functions to Core Concepts:**  Start linking the individual function functionalities to the higher-level concepts identified earlier:
    * The `MarkingSlow` functions are clearly part of the garbage collection marking process. They likely mark objects as reachable.
    * The "Slow" suffix on many functions suggests these are not the typical fast-path write barriers but are used in specific, potentially more complex, scenarios.
    * The "Shared" functions deal with the complexities of managing shared memory between isolates (V8's execution contexts). This is important for web workers and shared array buffers.
    * The "Generational" functions relate to generational garbage collection, where younger objects are collected more frequently.

6. **Focus on the "Why":**  Think about *why* these write barriers are necessary:
    * **Garbage Collection:**  The core reason is to ensure the garbage collector doesn't collect live objects. When an object A points to object B, the GC needs to know about this relationship. Write barriers record these pointers so the marker can find all reachable objects.
    * **Generational GC:**  To efficiently collect young objects, the GC needs to know when an older object starts pointing to a younger one. This is what the generational write barrier handles.
    * **Shared Memory:**  Shared memory requires extra care to ensure consistency between different isolates. The shared write barriers manage this.

7. **Identify Relationship to JavaScript:** This is the crucial step. How do these low-level C++ mechanisms manifest in JavaScript?
    * **Object References:**  The most direct connection is the way JavaScript objects reference each other. Every time you assign an object to a property of another object, a write barrier might be involved.
    * **Garbage Collection:** While you don't directly interact with write barriers in JavaScript, their existence is fundamental to how JavaScript's automatic memory management works.
    * **Shared Array Buffers and Workers:** The shared memory aspects of the write barrier become relevant when using `SharedArrayBuffer` and Web Workers. Modifying a `SharedArrayBuffer` in one worker can trigger shared write barriers.

8. **Construct JavaScript Examples:**  Create simple JavaScript snippets that demonstrate the *effects* of the write barriers, even if you can't directly trigger the C++ code. The examples should illustrate:
    * Basic object references and how they create edges in the object graph.
    * Scenarios involving older objects referencing younger objects.
    * Use cases with `SharedArrayBuffer` to highlight shared memory management.

9. **Refine and Organize:** Structure the explanation logically, starting with a high-level summary, then delving into more detail about specific functionalities. Use clear and concise language, avoiding excessive jargon where possible. Ensure the JavaScript examples are easy to understand and directly relate to the C++ concepts. Use formatting (like bullet points and code blocks) to improve readability.

10. **Review and Verify:** Double-check the explanation for accuracy and completeness. Does it accurately reflect the purpose of the C++ code? Are the JavaScript examples relevant and helpful?  (Self-correction: Initially, I might have focused too much on the internal details of the marking process. It's more important for the explanation to highlight the *purpose* and the connection to JavaScript behavior.)

This iterative process of identifying keywords, understanding individual functions, connecting them to core concepts, and then finding the link to JavaScript is crucial for deciphering low-level code and explaining its relevance.
这个C++源代码文件 `v8/src/heap/heap-write-barrier.cc` 实现了 **V8 引擎的堆写屏障（Heap Write Barrier）机制**。

**功能归纳:**

1. **维护对象图的完整性，支持垃圾回收 (Garbage Collection, GC):**
   - 当一个堆中的对象（`host`）的某个槽位（`slot`）被更新为指向另一个堆对象（`value`）时，写屏障负责记录这种关系。
   - 这对于垃圾回收器至关重要，因为它需要追踪哪些对象是可达的，哪些是不可达的。写屏障确保了在并发或增量式垃圾回收过程中，对象间的引用关系能够被正确地记录，防止本应存活的对象被错误回收。

2. **支持分代垃圾回收 (Generational Garbage Collection):**
   - V8 使用分代垃圾回收，将堆内存分为新生代（Young Generation）和老生代（Old Generation）。
   - 当老生代的对象引用新生代的对象时，需要特别记录这种跨代引用。`GenerationalBarrierSlow` 等函数就负责处理这种情况，将这些引用信息添加到 Remembered Set 中，以便新生代 GC 时能考虑到来自老生代的引用。

3. **支持共享堆 (Shared Heap):**
   - V8 允许多个 Isolate（隔离的 JavaScript 执行环境）共享堆内存。
   - 当一个对象被写入共享堆时，或者从非共享堆的对象写入共享堆的对象时，需要使用特殊的写屏障 (`SharedSlow`, `SharedHeapBarrierSlow`) 来确保数据的一致性和 GC 的正确性。

4. **支持增量标记 (Incremental Marking):**
   - 在增量标记 GC 过程中，写屏障负责在对象被修改时触发标记操作，逐步完成整个堆的标记，减少主线程的暂停时间。

5. **支持压缩指针 (Compressed Pointers):**
   -  `MarkingSlowFromCppHeapWrappable`, `MarkingSlow(Tagged<HeapObject> host, ExternalPointerSlot slot)` 等函数涉及到压缩指针的场景，写屏障需要处理这些特殊的指针类型。

6. **与代码生成集成:**
   - `MarkingFromCode`, `SharedFromCode` 等函数说明写屏障机制与代码生成器集成，在生成的机器代码中会插入对写屏障函数的调用，以在运行时维护对象图。

7. **性能优化:**
   - 代码中存在一些优化，例如 `ForRangeImpl` 中对只关心分代或共享写屏障的情况进行优化，避免不必要的对象访问。

**与 JavaScript 的关系及示例:**

写屏障机制在 JavaScript 层面是不可见的，它是 V8 引擎为了实现高效、可靠的内存管理而在底层实现的。每当你在 JavaScript 中修改一个对象的属性，如果这个属性的值是一个对象，那么 V8 内部的写屏障机制就可能被触发。

**JavaScript 示例：**

```javascript
// 假设 objA 存在于老生代， objB 存在于新生代

let objA = { data: null };
let objB = { value: 10 };

// 当执行以下赋值操作时，V8 的写屏障机制会被触发
// 因为 objA (老生代) 现在引用了 objB (新生代)
objA.data = objB;

//  这会触发类似 `GenerationalBarrierSlow` 的操作，
//  记录 objA 指向 objB 的引用，以便新生代 GC 时不会错误回收 objB
```

```javascript
// 假设 sharedArray 是一个 SharedArrayBuffer

const sab = new SharedArrayBuffer(1024);
const view1 = new Int32Array(sab);
const view2 = new Int32Array(sab);

// 在一个 Worker 线程中修改 sharedArray
// 假设 worker 是一个 Worker 实例
worker.postMessage({ type: 'write', index: 0, value: 42 });

// 在 worker 线程执行类似的操作时，会触发类似 `SharedHeapBarrierSlow` 的操作
// 以确保主线程和其他 worker 线程能看到更新后的值，并通知 GC 相关的信息
```

**更底层的理解：**

当 JavaScript 代码执行 `obj.property = anotherObj;` 时，V8 内部会执行一系列操作，其中就包括写屏障。写屏障会检查 `obj` 和 `anotherObj` 所在的内存区域，如果需要，会更新相关的元数据结构（如 Remembered Set），以便垃圾回收器能够正确地追踪对象间的引用关系。

**总结:**

`heap-write-barrier.cc` 文件是 V8 引擎垃圾回收机制的关键组成部分。它在底层默默地工作，确保了 JavaScript 程序的内存安全和高效运行，开发者通常不需要直接与之交互，但理解其作用有助于理解 V8 的内存管理模型。

### 提示词
```
这是目录为v8/src/heap/heap-write-barrier.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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