Response:
The user wants to understand the functionality of the `v8/src/heap/heap.cc` file. I need to analyze the provided C++ code snippet and identify its key responsibilities within the V8 JavaScript engine.

Here's a breakdown of the request and how to approach it:

1. **List the functionalities:**  I will go through the included headers and the provided code to identify the main areas of responsibility. Keywords like "heap," "GC," "allocation," "memory," etc., in the code and header files will be helpful.

2. **Check for `.tq` extension:** The user asks if the file could be a Torque file. I need to explicitly state that based on the `.cc` extension, it's a C++ source file, not a Torque file.

3. **Relation to JavaScript with examples:**  I need to explain how the heap management implemented in this file directly impacts JavaScript execution. This involves explaining how JavaScript objects are stored and managed in the heap. Simple JavaScript examples demonstrating object creation will be useful.

4. **Code logic reasoning (input/output):**  While the provided snippet is mostly declarations and initializations, I can infer the behavior of certain functions. For example, the `YoungGenerationSizeFromOldGenerationSize` function takes an old generation size as input and calculates a young generation size. I can create a hypothetical input and its corresponding output based on the logic.

5. **Common programming errors:** Since this file deals with memory management, I can discuss common JavaScript errors related to memory leaks and how the heap management helps prevent or mitigate them.

6. **Overall summary:** Finally, I need to synthesize all the identified functionalities into a concise summary of the `v8/src/heap/heap.cc` file's role.
Based on the provided code snippet from `v8/src/heap/heap.cc`, here's a breakdown of its functionalities:

**Core Functionalities of `v8/src/heap/heap.cc`:**

1. **Heap Management:** This is the central responsibility of the file. It manages the V8 JavaScript heap, which is the region of memory where JavaScript objects are allocated. This includes:
    * **Space Organization:**  Defining and managing different memory spaces within the heap (e.g., New Space, Old Space, Code Space, Large Object Space). You can see this from the inclusion of headers like `"src/heap/new-spaces.h"`, `"src/heap/paged-spaces-inl.h"`, `"src/heap/large-spaces.h"`.
    * **Allocation:**  Providing mechanisms for allocating memory for JavaScript objects. Headers like `"src/heap/heap-allocator.h"` and the presence of functions like `YoungGenerationSizeFromOldGenerationSize` suggest control over how memory is allocated in different generations.
    * **Deallocation (Garbage Collection):** Implementing garbage collection algorithms to reclaim memory occupied by objects that are no longer in use. The inclusion of headers like `"src/heap/gc-tracer.h"`, `"src/heap/mark-compact.h"`, `"src/heap/scavenger-inl.h"`, and the function `SelectGarbageCollector` clearly indicate garbage collection management.
    * **Memory Limits and Growth:** Managing the size limits of the heap and how it can grow or shrink based on memory pressure. Functions like `MaxReserved`, `CanExpandOldGeneration`, and `HeapSizeFromPhysicalMemory` are relevant here.
    * **Memory Accounting:** Tracking memory usage within different parts of the heap. Functions like `Capacity`, `CommittedMemory`, and the `PrintShortHeapStatistics` function demonstrate this.

2. **Garbage Collection (GC) Implementation:**  This file is heavily involved in orchestrating different garbage collection strategies:
    * **Scavenger (Minor GC):**  For collecting garbage in the young generation (New Space).
    * **Mark-Compact (Major GC):** For collecting garbage in the old generation and performing compaction.
    * **Incremental Marking:**  Allowing the marking phase of garbage collection to happen in smaller steps to reduce pauses.
    * **Concurrent Marking:**  Performing marking concurrently with JavaScript execution.
    * **Minor Mark-Sweep:** Another strategy for young generation garbage collection.
    * The `SelectGarbageCollector` function demonstrates the logic for choosing the appropriate GC algorithm based on various factors.

3. **Heap Organization and Structure:** Defining the layout and metadata associated with the heap. Headers like `"src/heap/heap-layout-inl.h"`, `"src/heap/memory-chunk-layout.h"`, and `"src/heap/page-inl.h"` suggest this aspect.

4. **Integration with Isolate:** The `Heap` class is tightly coupled with the `Isolate`, which represents an isolated instance of the V8 engine. The constructor takes an `Isolate` pointer, and there are references to `isolate_` throughout the code.

5. **Support for Serialization:** Functions like `SetSerializedObjects` and `SetSerializedGlobalProxySizes` indicate support for serializing the heap state, likely for snapshots or transferring state between isolates.

6. **Debugging and Monitoring:** Providing functionalities for debugging and monitoring heap behavior. Functions like `PrintShortHeapStatistics`, `PrintFreeListsStats`, and `DumpJSONHeapStatistics` are examples of this. The `AllocationTrackerForDebugging` class is explicitly for debugging allocations.

**Is `v8/src/heap/heap.cc` a Torque file?**

No, `v8/src/heap/heap.cc` is a **C++ source file**. The `.cc` extension is the standard convention for C++ source files. Torque files in V8 typically have the `.tq` extension.

**Relationship with JavaScript and Examples:**

The heap managed by `v8/src/heap/heap.cc` is where all JavaScript objects (except for primitive values which might be optimized) are stored. When you create objects in JavaScript, the memory for those objects is allocated from this heap. The garbage collector implemented here reclaims memory from objects that are no longer reachable from your JavaScript code.

**JavaScript Examples:**

```javascript
// Creating a JavaScript object allocates memory on the heap.
let myObject = { name: "example", value: 10 };

// Creating an array also allocates memory on the heap.
let myArray = [1, 2, 3];

// Functions are also objects and reside on the heap.
function myFunction() {
  console.log("Hello");
}

// When these objects are no longer needed (no references pointing to them),
// the garbage collector in `v8/src/heap/heap.cc` will eventually reclaim
// the memory they occupy.
myObject = null;
myArray = null;
myFunction = null;
```

**Code Logic Reasoning (Hypothetical Example):**

Let's consider the function `YoungGenerationSizeFromOldGenerationSize(size_t old_generation)`. This function likely calculates the desired size of the young generation based on the size of the old generation.

**Hypothetical Input and Output:**

* **Assumption:** Let's assume `OldGenerationToSemiSpaceRatio()` returns 8 (meaning the old generation is roughly 8 times the size of a semi-space) and `DefaultMaxSemiSpaceSize()` is 64MB.
* **Input:** `old_generation = 100 * 1024 * 1024` (100MB)
* **Process:**
    * `semi_space = old_generation / 8 = 12.5MB`
    * `semi_space` is likely rounded up to the nearest page size. Let's assume page size is 4KB. So, `semi_space` might become something like `12800 * 1024` (rounding up to the nearest multiple of 4KB).
    * `YoungGenerationSizeFromSemiSpaceSize` would then use this `semi_space` to calculate the young generation size (likely considering two semi-spaces and potentially a new large object space). Let's assume it returns `3 * semi_space`.
* **Output (Estimated):**  `young_generation_size` would be approximately `3 * 12.5MB = 37.5MB` (after rounding and calculations in `YoungGenerationSizeFromSemiSpaceSize`).

**Common Programming Errors Related to Heap Management (from a user perspective):**

While JavaScript handles memory management automatically through garbage collection, certain programming patterns can lead to inefficient memory usage or even apparent memory leaks (where objects are still reachable but no longer needed).

**Examples of User Errors:**

1. **Holding onto unnecessary object references:**
   ```javascript
   let largeData = [];
   for (let i = 0; i < 1000000; i++) {
     largeData.push({ data: new Array(1000).fill(i) });
   }
   // If `largeData` is still in scope and accessible, the garbage collector
   // cannot reclaim the memory even if the individual objects inside are
   // no longer actively used.
   ```

2. **Closures capturing large amounts of data:**
   ```javascript
   function createCounter() {
     let veryLargeArray = new Array(1000000).fill(0);
     let count = 0;
     return function() {
       count++;
       console.log(count);
     };
   }

   const myCounter = createCounter();
   // `myCounter` (the returned function) maintains a closure over
   // `veryLargeArray`, preventing it from being garbage collected,
   // even if `myCounter` is the only reference.
   ```

3. **Forgetting to deregister event listeners:**
   ```javascript
   const myElement = document.getElementById('myButton');
   myElement.addEventListener('click', function() {
     // ... do something ...
   });

   // If `myElement` is removed from the DOM but the event listener
   // is not removed, the listener function (and any data it closes over)
   // might not be garbage collected, especially in older browsers or
   // environments with less sophisticated GC.
   ```

**Summary of `v8/src/heap/heap.cc` Functionality (Part 1):**

This part of `v8/src/heap/heap.cc` primarily focuses on the **fundamental setup and management of the V8 JavaScript heap**. It defines how the heap is structured into different memory spaces, provides mechanisms for allocating memory, and lays the groundwork for the garbage collection process by including and referencing components responsible for different GC algorithms. It also handles basic memory accounting and provides some initial debugging capabilities. The functions related to memory limits and growth are crucial for the engine's ability to adapt to different memory constraints.

### 提示词
```
这是目录为v8/src/heap/heap.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/heap.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/heap.h"

#include <atomic>
#include <cinttypes>
#include <iomanip>
#include <memory>
#include <optional>
#include <unordered_map>
#include <unordered_set>

#include "include/v8-locker.h"
#include "src/api/api-inl.h"
#include "src/base/bits.h"
#include "src/base/flags.h"
#include "src/base/logging.h"
#include "src/base/macros.h"
#include "src/base/once.h"
#include "src/base/platform/memory.h"
#include "src/base/platform/mutex.h"
#include "src/base/platform/time.h"
#include "src/base/utils/random-number-generator.h"
#include "src/builtins/accessors.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/compilation-cache.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/compiler-dispatcher/optimizing-compile-dispatcher.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/embedder-state.h"
#include "src/execution/isolate-utils-inl.h"
#include "src/execution/microtask-queue.h"
#include "src/execution/v8threads.h"
#include "src/execution/vm-state-inl.h"
#include "src/flags/flags.h"
#include "src/handles/global-handles-inl.h"
#include "src/handles/traced-handles.h"
#include "src/heap/allocation-observer.h"
#include "src/heap/array-buffer-sweeper.h"
#include "src/heap/base/stack.h"
#include "src/heap/base/worklist.h"
#include "src/heap/code-range.h"
#include "src/heap/code-stats.h"
#include "src/heap/collection-barrier.h"
#include "src/heap/combined-heap.h"
#include "src/heap/concurrent-marking.h"
#include "src/heap/cppgc-js/cpp-heap.h"
#include "src/heap/ephemeron-remembered-set.h"
#include "src/heap/evacuation-verifier-inl.h"
#include "src/heap/finalization-registry-cleanup-task.h"
#include "src/heap/gc-callbacks.h"
#include "src/heap/gc-tracer-inl.h"
#include "src/heap/gc-tracer.h"
#include "src/heap/heap-allocator.h"
#include "src/heap/heap-controller.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap-layout-tracer.h"
#include "src/heap/heap-utils-inl.h"
#include "src/heap/heap-visitor-inl.h"
#include "src/heap/heap-visitor.h"
#include "src/heap/heap-write-barrier-inl.h"
#include "src/heap/incremental-marking-inl.h"
#include "src/heap/incremental-marking.h"
#include "src/heap/large-spaces.h"
#include "src/heap/local-heap-inl.h"
#include "src/heap/mark-compact-inl.h"
#include "src/heap/mark-compact.h"
#include "src/heap/marking-barrier-inl.h"
#include "src/heap/marking-barrier.h"
#include "src/heap/marking-state-inl.h"
#include "src/heap/marking-state.h"
#include "src/heap/memory-balancer.h"
#include "src/heap/memory-chunk-layout.h"
#include "src/heap/memory-chunk-metadata.h"
#include "src/heap/memory-measurement.h"
#include "src/heap/memory-reducer.h"
#include "src/heap/minor-gc-job.h"
#include "src/heap/minor-mark-sweep.h"
#include "src/heap/mutable-page-metadata-inl.h"
#include "src/heap/new-spaces.h"
#include "src/heap/object-lock.h"
#include "src/heap/object-stats.h"
#include "src/heap/paged-spaces-inl.h"
#include "src/heap/parked-scope.h"
#include "src/heap/pretenuring-handler.h"
#include "src/heap/read-only-heap.h"
#include "src/heap/remembered-set.h"
#include "src/heap/safepoint.h"
#include "src/heap/scavenger-inl.h"
#include "src/heap/stress-scavenge-observer.h"
#include "src/heap/sweeper.h"
#include "src/heap/trusted-range.h"
#include "src/heap/visit-object.h"
#include "src/heap/zapping.h"
#include "src/init/bootstrapper.h"
#include "src/init/v8.h"
#include "src/interpreter/interpreter.h"
#include "src/logging/log.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/numbers/conversions.h"
#include "src/objects/data-handler.h"
#include "src/objects/free-space-inl.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/hash-table.h"
#include "src/objects/instance-type.h"
#include "src/objects/maybe-object.h"
#include "src/objects/objects.h"
#include "src/objects/slots-atomic-inl.h"
#include "src/objects/slots-inl.h"
#include "src/objects/slots.h"
#include "src/objects/visitors.h"
#include "src/profiler/heap-profiler.h"
#include "src/regexp/regexp.h"
#include "src/snapshot/embedded/embedded-data.h"
#include "src/snapshot/serializer-deserializer.h"
#include "src/snapshot/snapshot.h"
#include "src/strings/string-stream.h"
#include "src/strings/unicode-inl.h"
#include "src/tasks/cancelable-task.h"
#include "src/tracing/trace-event.h"
#include "src/utils/utils-inl.h"
#include "src/utils/utils.h"

#ifdef V8_ENABLE_CONSERVATIVE_STACK_SCANNING
#include "src/heap/conservative-stack-visitor.h"
#endif  // V8_ENABLE_CONSERVATIVE_STACK_SCANNING

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-engine.h"
#endif  // V8_ENABLE_WEBASSEMBLY

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8 {
namespace internal {

void Heap::SetConstructStubCreateDeoptPCOffset(int pc_offset) {
  DCHECK_EQ(Smi::zero(), construct_stub_create_deopt_pc_offset());
  set_construct_stub_create_deopt_pc_offset(Smi::FromInt(pc_offset));
}

void Heap::SetConstructStubInvokeDeoptPCOffset(int pc_offset) {
  DCHECK_EQ(Smi::zero(), construct_stub_invoke_deopt_pc_offset());
  set_construct_stub_invoke_deopt_pc_offset(Smi::FromInt(pc_offset));
}

void Heap::SetDeoptPCOffsetAfterAdaptShadowStack(int pc_offset) {
  DCHECK((Smi::zero() == deopt_pc_offset_after_adapt_shadow_stack()) ||
         (pc_offset == deopt_pc_offset_after_adapt_shadow_stack().value()));
  set_deopt_pc_offset_after_adapt_shadow_stack(Smi::FromInt(pc_offset));
}

void Heap::SetInterpreterEntryReturnPCOffset(int pc_offset) {
  DCHECK_EQ(Smi::zero(), interpreter_entry_return_pc_offset());
  set_interpreter_entry_return_pc_offset(Smi::FromInt(pc_offset));
}

void Heap::SetSerializedObjects(Tagged<HeapObject> objects) {
  DCHECK(isolate()->serializer_enabled());
  set_serialized_objects(objects);
}

void Heap::SetSerializedGlobalProxySizes(Tagged<FixedArray> sizes) {
  DCHECK(isolate()->serializer_enabled());
  set_serialized_global_proxy_sizes(sizes);
}

void Heap::SetBasicBlockProfilingData(DirectHandle<ArrayList> list) {
  set_basic_block_profiling_data(*list);
}

class ScheduleMinorGCTaskObserver final : public AllocationObserver {
 public:
  explicit ScheduleMinorGCTaskObserver(Heap* heap)
      : AllocationObserver(kNotUsingFixedStepSize), heap_(heap) {
    // Register GC callback for all atomic pause types.
    heap_->main_thread_local_heap()->AddGCEpilogueCallback(
        &GCEpilogueCallback, this, GCCallbacksInSafepoint::GCType::kLocal);
    AddToNewSpace();
  }
  ~ScheduleMinorGCTaskObserver() final {
    RemoveFromNewSpace();
    heap_->main_thread_local_heap()->RemoveGCEpilogueCallback(
        &GCEpilogueCallback, this);
  }

  intptr_t GetNextStepSize() final {
    size_t new_space_threshold =
        MinorGCJob::YoungGenerationTaskTriggerSize(heap_);
    size_t new_space_size = v8_flags.sticky_mark_bits
                                ? heap_->sticky_space()->young_objects_size()
                                : heap_->new_space()->Size();
    if (new_space_size < new_space_threshold) {
      return new_space_threshold - new_space_size;
    }
    // Force a step on next allocation.
    return 1;
  }

  void Step(int, Address, size_t) final {
    heap_->ScheduleMinorGCTaskIfNeeded();
    // Remove this observer. It will be re-added after a GC.
    DCHECK(was_added_to_space_);
    heap_->allocator()->new_space_allocator()->RemoveAllocationObserver(this);
    was_added_to_space_ = false;
  }

 protected:
  static void GCEpilogueCallback(void* observer) {
    reinterpret_cast<ScheduleMinorGCTaskObserver*>(observer)
        ->RemoveFromNewSpace();
    reinterpret_cast<ScheduleMinorGCTaskObserver*>(observer)->AddToNewSpace();
  }

  void AddToNewSpace() {
    DCHECK(!was_added_to_space_);
    DCHECK_IMPLIES(v8_flags.minor_ms,
                   !heap_->allocator()->new_space_allocator()->IsLabValid());
    heap_->allocator()->new_space_allocator()->AddAllocationObserver(this);
    was_added_to_space_ = true;
  }

  void RemoveFromNewSpace() {
    if (!was_added_to_space_) return;
    heap_->allocator()->new_space_allocator()->RemoveAllocationObserver(this);
    was_added_to_space_ = false;
  }

  Heap* heap_;
  bool was_added_to_space_ = false;
};

Heap::Heap()
    : isolate_(isolate()),
      memory_pressure_level_(MemoryPressureLevel::kNone),
      safepoint_(std::make_unique<IsolateSafepoint>(this)),
      external_string_table_(this),
      allocation_type_for_in_place_internalizable_strings_(
          isolate()->OwnsStringTables() ? AllocationType::kOld
                                        : AllocationType::kSharedOld),
      marking_state_(isolate_),
      non_atomic_marking_state_(isolate_),
      pretenuring_handler_(this) {
  // Ensure old_generation_size_ is a multiple of kPageSize.
  DCHECK_EQ(0, max_old_generation_size() & (PageMetadata::kPageSize - 1));

  max_regular_code_object_size_ = MemoryChunkLayout::MaxRegularCodeObjectSize();

  set_native_contexts_list(Smi::zero());

  // Put a dummy entry in the remembered pages so we can find the list the
  // minidump even if there are no real unmapped pages.
  RememberUnmappedPage(kNullAddress, false);
}

Heap::~Heap() = default;

size_t Heap::MaxReserved() const {
  const size_t kMaxNewLargeObjectSpaceSize = max_semi_space_size_;
  return static_cast<size_t>(
      (v8_flags.minor_ms ? 1 : 2) * max_semi_space_size_ +
      kMaxNewLargeObjectSpaceSize + max_old_generation_size());
}

size_t Heap::YoungGenerationSizeFromOldGenerationSize(size_t old_generation) {
  // Compute the semi space size and cap it.
  bool is_low_memory = old_generation <= kOldGenerationLowMemory;
  size_t semi_space;
  if (v8_flags.minor_ms && !is_low_memory) {
    semi_space = DefaultMaxSemiSpaceSize();
  } else {
    size_t ratio = is_low_memory ? OldGenerationToSemiSpaceRatioLowMemory()
                                 : OldGenerationToSemiSpaceRatio();
    semi_space = old_generation / ratio;
    semi_space = std::min({semi_space, DefaultMaxSemiSpaceSize()});
    semi_space = std::max({semi_space, DefaultMinSemiSpaceSize()});
    semi_space = RoundUp(semi_space, PageMetadata::kPageSize);
  }
  return YoungGenerationSizeFromSemiSpaceSize(semi_space);
}

size_t Heap::HeapSizeFromPhysicalMemory(uint64_t physical_memory) {
  // Compute the old generation size and cap it.
  uint64_t old_generation = physical_memory /
                            kPhysicalMemoryToOldGenerationRatio *
                            kHeapLimitMultiplier;
  old_generation =
      std::min(old_generation,
               static_cast<uint64_t>(MaxOldGenerationSize(physical_memory)));
  old_generation =
      std::max({old_generation, static_cast<uint64_t>(V8HeapTrait::kMinSize)});
  old_generation = RoundUp(old_generation, PageMetadata::kPageSize);

  size_t young_generation = YoungGenerationSizeFromOldGenerationSize(
      static_cast<size_t>(old_generation));
  return static_cast<size_t>(old_generation) + young_generation;
}

void Heap::GenerationSizesFromHeapSize(size_t heap_size,
                                       size_t* young_generation_size,
                                       size_t* old_generation_size) {
  // Initialize values for the case when the given heap size is too small.
  *young_generation_size = 0;
  *old_generation_size = 0;
  // Binary search for the largest old generation size that fits to the given
  // heap limit considering the correspondingly sized young generation.
  size_t lower = 0, upper = heap_size;
  while (lower + 1 < upper) {
    size_t old_generation = lower + (upper - lower) / 2;
    size_t young_generation =
        YoungGenerationSizeFromOldGenerationSize(old_generation);
    if (old_generation + young_generation <= heap_size) {
      // This size configuration fits into the given heap limit.
      *young_generation_size = young_generation;
      *old_generation_size = old_generation;
      lower = old_generation;
    } else {
      upper = old_generation;
    }
  }
}

size_t Heap::MinYoungGenerationSize() {
  return YoungGenerationSizeFromSemiSpaceSize(DefaultMinSemiSpaceSize());
}

size_t Heap::MinOldGenerationSize() {
  size_t paged_space_count =
      LAST_GROWABLE_PAGED_SPACE - FIRST_GROWABLE_PAGED_SPACE + 1;
  return paged_space_count * PageMetadata::kPageSize;
}

size_t Heap::AllocatorLimitOnMaxOldGenerationSize() {
#ifdef V8_COMPRESS_POINTERS
  // Isolate and the young generation are also allocated on the heap.
  return kPtrComprCageReservationSize -
         YoungGenerationSizeFromSemiSpaceSize(DefaultMaxSemiSpaceSize()) -
         RoundUp(sizeof(Isolate), size_t{1} << kPageSizeBits);
#else
  return std::numeric_limits<size_t>::max();
#endif
}

size_t Heap::MaxOldGenerationSize(uint64_t physical_memory) {
  size_t max_size = V8HeapTrait::kMaxSize;
  // Increase the heap size from 2GB to 4GB for 64-bit systems with physical
  // memory at least 16GB. The theshold is set to 15GB to accomodate for some
  // memory being reserved by the hardware.
#ifdef V8_HOST_ARCH_64_BIT
  if ((physical_memory / GB) >= 15) {
#if V8_OS_ANDROID
    // As of 2024, Android devices with 16GiB are shipping (for instance the
    // Pixel 9 Pro). However, a large fraction of their memory is not usable,
    // and there is no disk swap, so heaps are still smaller than on desktop for
    // now.
    DCHECK_EQ(max_size / GB, 1u);
#else
    DCHECK_EQ(max_size / GB, 2u);
#endif
    max_size *= 2;
  }
#endif  // V8_HOST_ARCH_64_BIT
  return std::min(max_size, AllocatorLimitOnMaxOldGenerationSize());
}

namespace {
int NumberOfSemiSpaces() { return v8_flags.minor_ms ? 1 : 2; }
}  // namespace

size_t Heap::YoungGenerationSizeFromSemiSpaceSize(size_t semi_space_size) {
  return semi_space_size *
         (NumberOfSemiSpaces() + kNewLargeObjectSpaceToSemiSpaceRatio);
}

size_t Heap::SemiSpaceSizeFromYoungGenerationSize(
    size_t young_generation_size) {
  return young_generation_size /
         (NumberOfSemiSpaces() + kNewLargeObjectSpaceToSemiSpaceRatio);
}

size_t Heap::Capacity() {
  if (!HasBeenSetUp()) {
    return 0;
  }
  return NewSpaceCapacity() + OldGenerationCapacity();
}

size_t Heap::OldGenerationCapacity() const {
  if (!HasBeenSetUp()) return 0;
  PagedSpaceIterator spaces(this);
  size_t total = 0;
  for (PagedSpace* space = spaces.Next(); space != nullptr;
       space = spaces.Next()) {
    total += space->Capacity();
  }
  if (shared_lo_space_) {
    total += shared_lo_space_->SizeOfObjects();
  }
  return total + lo_space_->SizeOfObjects() + code_lo_space_->SizeOfObjects() +
         trusted_lo_space_->SizeOfObjects();
}

size_t Heap::CommittedOldGenerationMemory() {
  if (!HasBeenSetUp()) return 0;

  PagedSpaceIterator spaces(this);
  size_t total = 0;
  for (PagedSpace* space = spaces.Next(); space != nullptr;
       space = spaces.Next()) {
    total += space->CommittedMemory();
  }
  if (shared_lo_space_) {
    total += shared_lo_space_->Size();
  }
  return total + lo_space_->Size() + code_lo_space_->Size() +
         trusted_lo_space_->Size();
}

size_t Heap::CommittedMemoryOfPool() {
  if (!HasBeenSetUp()) return 0;

  return memory_allocator()->pool()->CommittedBufferedMemory();
}

size_t Heap::CommittedMemory() {
  if (!HasBeenSetUp()) return 0;

  size_t new_space_committed = new_space_ ? new_space_->CommittedMemory() : 0;
  size_t new_lo_space_committed = new_lo_space_ ? new_lo_space_->Size() : 0;

  return new_space_committed + new_lo_space_committed +
         CommittedOldGenerationMemory();
}

size_t Heap::CommittedPhysicalMemory() {
  if (!HasBeenSetUp()) return 0;

  size_t total = 0;
  for (SpaceIterator it(this); it.HasNext();) {
    total += it.Next()->CommittedPhysicalMemory();
  }

  return total;
}

size_t Heap::CommittedMemoryExecutable() {
  if (!HasBeenSetUp()) return 0;

  return static_cast<size_t>(memory_allocator()->SizeExecutable());
}

void Heap::UpdateMaximumCommitted() {
  if (!HasBeenSetUp()) return;

  const size_t current_committed_memory = CommittedMemory();
  if (current_committed_memory > maximum_committed_) {
    maximum_committed_ = current_committed_memory;
  }
}

size_t Heap::Available() {
  if (!HasBeenSetUp()) return 0;

  size_t total = 0;

  for (SpaceIterator it(this); it.HasNext();) {
    total += it.Next()->Available();
  }

  total += memory_allocator()->Available();
  return total;
}

bool Heap::CanExpandOldGeneration(size_t size) const {
  if (force_oom_ || force_gc_on_next_allocation_) return false;
  if (OldGenerationCapacity() + size > max_old_generation_size()) return false;
  // Stay below `MaxReserved()` such that it is more likely that committing the
  // second semi space at the beginning of a GC succeeds.
  return memory_allocator()->Size() + size <= MaxReserved();
}

bool Heap::IsOldGenerationExpansionAllowed(
    size_t size, const base::MutexGuard& expansion_mutex_witness) const {
  return OldGenerationCapacity() + size <= max_old_generation_size();
}

bool Heap::CanPromoteYoungAndExpandOldGeneration(size_t size) const {
  size_t new_space_capacity = NewSpaceCapacity();
  size_t new_lo_space_capacity = new_lo_space_ ? new_lo_space_->Size() : 0;

  // Over-estimate the new space size using capacity to allow some slack.
  return CanExpandOldGeneration(size + new_space_capacity +
                                new_lo_space_capacity);
}

bool Heap::HasBeenSetUp() const {
  // We will always have an old space when the heap is set up.
  return old_space_ != nullptr;
}

bool Heap::ShouldUseBackgroundThreads() const {
  return !v8_flags.single_threaded_gc_in_background ||
         !isolate()->EfficiencyModeEnabled();
}

bool Heap::ShouldUseIncrementalMarking() const {
  if (v8_flags.single_threaded_gc_in_background &&
      isolate()->EfficiencyModeEnabled()) {
    return v8_flags.incremental_marking_for_gc_in_background;
  } else {
    return true;
  }
}

bool Heap::ShouldOptimizeForBattery() const {
  return v8_flags.optimize_gc_for_battery ||
         isolate()->BatterySaverModeEnabled();
}

GarbageCollector Heap::SelectGarbageCollector(AllocationSpace space,
                                              GarbageCollectionReason gc_reason,
                                              const char** reason) const {
  if (gc_reason == GarbageCollectionReason::kFinalizeConcurrentMinorMS) {
    DCHECK_NE(static_cast<bool>(new_space()),
              v8_flags.sticky_mark_bits.value());
    DCHECK(!ShouldReduceMemory());
    *reason = "Concurrent MinorMS needs finalization";
    return GarbageCollector::MINOR_MARK_SWEEPER;
  }

  // Is global GC requested?
  if (space != NEW_SPACE && space != NEW_LO_SPACE) {
    isolate_->counters()->gc_compactor_caused_by_request()->Increment();
    *reason = "GC in old space requested";
    return GarbageCollector::MARK_COMPACTOR;
  }

  if (v8_flags.gc_global || ShouldStressCompaction() || !use_new_space()) {
    *reason = "GC in old space forced by flags";
    return GarbageCollector::MARK_COMPACTOR;
  }

  if (v8_flags.separate_gc_phases && incremental_marking()->IsMajorMarking()) {
    // TODO(v8:12503): Remove next condition (allocation limit overshot) when
    // separate_gc_phases flag is enabled and removed.
    *reason = "Incremental marking forced finalization";
    return GarbageCollector::MARK_COMPACTOR;
  }

  if (incremental_marking()->IsMajorMarking() &&
      incremental_marking()->IsMajorMarkingComplete() &&
      AllocationLimitOvershotByLargeMargin()) {
    DCHECK(!v8_flags.minor_ms);
    *reason = "Incremental marking needs finalization";
    return GarbageCollector::MARK_COMPACTOR;
  }

  if (!CanPromoteYoungAndExpandOldGeneration(0)) {
    isolate_->counters()
        ->gc_compactor_caused_by_oldspace_exhaustion()
        ->Increment();
    *reason = "scavenge might not succeed";
    return GarbageCollector::MARK_COMPACTOR;
  }

  DCHECK(!v8_flags.single_generation);
  DCHECK(!v8_flags.gc_global);
  // Default
  *reason = nullptr;
  return YoungGenerationCollector();
}

void Heap::SetGCState(HeapState state) {
  gc_state_.store(state, std::memory_order_relaxed);
}

bool Heap::IsGCWithMainThreadStack() const {
  return embedder_stack_state_ == StackState::kMayContainHeapPointers;
}

bool Heap::IsGCWithStack() const {
  return IsGCWithMainThreadStack() || stack().HasBackgroundStacks();
}

bool Heap::CanShortcutStringsDuringGC(GarbageCollector collector) const {
  if (!v8_flags.shortcut_strings_with_stack && IsGCWithStack()) return false;

  switch (collector) {
    case GarbageCollector::MINOR_MARK_SWEEPER:
      if (!v8_flags.minor_ms_shortcut_strings) return false;

      DCHECK(!incremental_marking()->IsMajorMarking());

      // Minor MS cannot short cut strings during concurrent marking.
      if (incremental_marking()->IsMinorMarking()) return false;

      // Minor MS uses static roots to check for strings to shortcut.
      if (!V8_STATIC_ROOTS_BOOL) return false;

      break;
    case GarbageCollector::SCAVENGER:
      // Scavenger cannot short cut strings during incremental marking.
      if (incremental_marking()->IsMajorMarking()) return false;

      if (isolate()->has_shared_space() &&
          !isolate()->is_shared_space_isolate() &&
          isolate()
              ->shared_space_isolate()
              ->heap()
              ->incremental_marking()
              ->IsMarking()) {
        DCHECK(isolate()
                   ->shared_space_isolate()
                   ->heap()
                   ->incremental_marking()
                   ->IsMajorMarking());
        return false;
      }
      break;
    default:
      UNREACHABLE();
  }

  return true;
}

void Heap::PrintShortHeapStatistics() {
  if (!v8_flags.trace_gc_verbose) return;
  PrintIsolate(isolate_,
               "Memory allocator,       used: %6zu KB,"
               " available: %6zu KB\n",
               memory_allocator()->Size() / KB,
               memory_allocator()->Available() / KB);
  PrintIsolate(isolate_,
               "Read-only space,        used: %6zu KB"
               ", available: %6zu KB"
               ", committed: %6zu KB\n",
               read_only_space_->Size() / KB, size_t{0},
               read_only_space_->CommittedMemory() / KB);
  PrintIsolate(isolate_,
               "New space,              used: %6zu KB"
               ", available: %6zu KB%s"
               ", committed: %6zu KB\n",
               NewSpaceSize() / KB, new_space_->Available() / KB,
               (v8_flags.minor_ms && minor_sweeping_in_progress()) ? "*" : "",
               new_space_->CommittedMemory() / KB);
  PrintIsolate(isolate_,
               "New large object space, used: %6zu KB"
               ", available: %6zu KB"
               ", committed: %6zu KB\n",
               new_lo_space_->SizeOfObjects() / KB,
               new_lo_space_->Available() / KB,
               new_lo_space_->CommittedMemory() / KB);
  PrintIsolate(isolate_,
               "Old space,              used: %6zu KB"
               ", available: %6zu KB%s"
               ", committed: %6zu KB\n",
               old_space_->SizeOfObjects() / KB, old_space_->Available() / KB,
               major_sweeping_in_progress() ? "*" : "",
               old_space_->CommittedMemory() / KB);
  PrintIsolate(isolate_,
               "Code space,             used: %6zu KB"
               ", available: %6zu KB%s"
               ", committed: %6zu KB\n",
               code_space_->SizeOfObjects() / KB, code_space_->Available() / KB,
               major_sweeping_in_progress() ? "*" : "",
               code_space_->CommittedMemory() / KB);
  PrintIsolate(isolate_,
               "Large object space,     used: %6zu KB"
               ", available: %6zu KB"
               ", committed: %6zu KB\n",
               lo_space_->SizeOfObjects() / KB, lo_space_->Available() / KB,
               lo_space_->CommittedMemory() / KB);
  PrintIsolate(isolate_,
               "Code large object space,     used: %6zu KB"
               ", available: %6zu KB"
               ", committed: %6zu KB\n",
               code_lo_space_->SizeOfObjects() / KB,
               code_lo_space_->Available() / KB,
               code_lo_space_->CommittedMemory() / KB);
  PrintIsolate(isolate_,
               "Trusted space,              used: %6zu KB"
               ", available: %6zu KB%s"
               ", committed: %6zu KB\n",
               trusted_space_->SizeOfObjects() / KB,
               trusted_space_->Available() / KB,
               major_sweeping_in_progress() ? "*" : "",
               trusted_space_->CommittedMemory() / KB);
  PrintIsolate(isolate_,
               "Trusted large object space,     used: %6zu KB"
               ", available: %6zu KB"
               ", committed: %6zu KB\n",
               trusted_lo_space_->SizeOfObjects() / KB,
               trusted_lo_space_->Available() / KB,
               trusted_lo_space_->CommittedMemory() / KB);
  ReadOnlySpace* const ro_space = read_only_space_;
  PrintIsolate(isolate_,
               "All spaces,             used: %6zu KB"
               ", available: %6zu KB%s"
               ", committed: %6zu KB\n",
               (this->SizeOfObjects() + ro_space->Size()) / KB,
               (this->Available()) / KB, sweeping_in_progress() ? "*" : "",
               (this->CommittedMemory() + ro_space->CommittedMemory()) / KB);
  PrintIsolate(isolate_, "Pool buffering %zu chunks of committed: %6zu KB\n",
               memory_allocator()->pool()->NumberOfCommittedChunks(),
               CommittedMemoryOfPool() / KB);
  PrintIsolate(isolate_, "External memory reported: %6" PRId64 " KB\n",
               external_memory() / KB);
  PrintIsolate(isolate_, "Backing store memory: %6" PRIu64 " KB\n",
               backing_store_bytes() / KB);
  PrintIsolate(isolate_, "External memory global %zu KB\n",
               external_memory_callback_() / KB);
  PrintIsolate(isolate_, "Total time spent in GC  : %.1f ms\n",
               total_gc_time_ms_.InMillisecondsF());
  if (sweeping_in_progress()) {
    PrintIsolate(isolate_,
                 "(*) Sweeping is still in progress, making available sizes "
                 "inaccurate.\n");
  }
}

void Heap::PrintFreeListsStats() {
  DCHECK(v8_flags.trace_gc_freelists);

  if (v8_flags.trace_gc_freelists_verbose) {
    PrintIsolate(isolate_,
                 "Freelists statistics per Page: "
                 "[category: length || total free bytes]\n");
  }

  std::vector<int> categories_lengths(
      old_space()->free_list()->number_of_categories(), 0);
  std::vector<size_t> categories_sums(
      old_space()->free_list()->number_of_categories(), 0);
  unsigned int pageCnt = 0;

  // This loops computes freelists lengths and sum.
  // If v8_flags.trace_gc_freelists_verbose is enabled, it also prints
  // the stats of each FreeListCategory of each Page.
  for (PageMetadata* page : *old_space()) {
    std::ostringstream out_str;

    if (v8_flags.trace_gc_freelists_verbose) {
      out_str << "Page " << std::setw(4) << pageCnt;
    }

    for (int cat = kFirstCategory;
         cat <= old_space()->free_list()->last_category(); cat++) {
      FreeListCategory* free_list =
          page->free_list_category(static_cast<FreeListCategoryType>(cat));
      int length = free_list->FreeListLength();
      size_t sum = free_list->SumFreeList();

      if (v8_flags.trace_gc_freelists_verbose) {
        out_str << "[" << cat << ": " << std::setw(4) << length << " || "
                << std::setw(6) << sum << " ]"
                << (cat == old_space()->free_list()->last_category() ? "\n"
                                                                     : ", ");
      }
      categories_lengths[cat] += length;
      categories_sums[cat] += sum;
    }

    if (v8_flags.trace_gc_freelists_verbose) {
      PrintIsolate(isolate_, "%s", out_str.str().c_str());
    }

    pageCnt++;
  }

  // Print statistics about old_space (pages, free/wasted/used memory...).
  PrintIsolate(
      isolate_,
      "%d pages. Free space: %.1f MB (waste: %.2f). "
      "Usage: %.1f/%.1f (MB) -> %.2f%%.\n",
      pageCnt, static_cast<double>(old_space_->Available()) / MB,
      static_cast<double>(old_space_->Waste()) / MB,
      static_cast<double>(old_space_->Size()) / MB,
      static_cast<double>(old_space_->Capacity()) / MB,
      static_cast<double>(old_space_->Size()) / old_space_->Capacity() * 100);

  // Print global statistics of each FreeListCategory (length & sum).
  PrintIsolate(isolate_,
               "FreeLists global statistics: "
               "[category: length || total free KB]\n");
  std::ostringstream out_str;
  for (int cat = kFirstCategory;
       cat <= old_space()->free_list()->last_category(); cat++) {
    out_str << "[" << cat << ": " << categories_lengths[cat] << " || "
            << std::fixed << std::setprecision(2)
            << static_cast<double>(categories_sums[cat]) / KB << " KB]"
            << (cat == old_space()->free_list()->last_category() ? "\n" : ", ");
  }
  PrintIsolate(isolate_, "%s", out_str.str().c_str());
}

void Heap::DumpJSONHeapStatistics(std::stringstream& stream) {
  HeapStatistics stats;
  reinterpret_cast<v8::Isolate*>(isolate())->GetHeapStatistics(&stats);

// clang-format off
#define DICT(s) "{" << s << "}"
#define LIST(s) "[" << s << "]"
#define QUOTE(s) "\"" << s << "\""
#define MEMBER(s) QUOTE(s) << ":"

  auto SpaceStatistics = [this](int space_index) {
    HeapSpaceStatistics space_stats;
    reinterpret_cast<v8::Isolate*>(isolate())->GetHeapSpaceStatistics(
        &space_stats, space_index);
    std::stringstream stream;
    stream << DICT(
      MEMBER("name")
        << QUOTE(ToString(
              static_cast<AllocationSpace>(space_index)))
        << ","
      MEMBER("size") << space_stats.space_size() << ","
      MEMBER("used_size") << space_stats.space_used_size() << ","
      MEMBER("available_size") << space_stats.space_available_size() << ","
      MEMBER("physical_size") << space_stats.physical_space_size());
    return stream.str();
  };

  stream << DICT(
    MEMBER("isolate") << QUOTE(reinterpret_cast<void*>(isolate())) << ","
    MEMBER("id") << gc_count() << ","
    MEMBER("time_ms") << isolate()->time_millis_since_init() << ","
    MEMBER("total_heap_size") << stats.total_heap_size() << ","
    MEMBER("total_heap_size_executable")
      << stats.total_heap_size_executable() << ","
    MEMBER("total_physical_size") << stats.total_physical_size() << ","
    MEMBER("total_available_size") << stats.total_available_size() << ","
    MEMBER("used_heap_size") << stats.used_heap_size() << ","
    MEMBER("heap_size_limit") << stats.heap_size_limit() << ","
    MEMBER("malloced_memory") << stats.malloced_memory() << ","
    MEMBER("external_memory") << stats.external_memory() << ","
    MEMBER("peak_malloced_memory") << stats.peak_malloced_memory() << ","
    MEMBER("spaces") << LIST(
      SpaceStatistics(RO_SPACE)      << "," <<
      SpaceStatistics(NEW_SPACE)     << "," <<
      SpaceStatistics(OLD_SPACE)     << "," <<
      SpaceStatistics(CODE_SPACE)    << "," <<
      SpaceStatistics(LO_SPACE)      << "," <<
      SpaceStatistics(CODE_LO_SPACE) << "," <<
      SpaceStatistics(NEW_LO_SPACE)  << "," <<
      SpaceStatistics(TRUSTED_SPACE) << "," <<
      SpaceStatistics(TRUSTED_LO_SPACE)));

#undef DICT
#undef LIST
#undef QUOTE
#undef MEMBER
  // clang-format on
}

void Heap::ReportStatisticsAfterGC() {
  if (deferred_counters_.empty()) return;
  // Move the contents into a new SmallVector first, in case
  // {Isolate::CountUsage} puts the counters into {deferred_counters_} again.
  decltype(deferred_counters_) to_report = std::move(deferred_counters_);
  DCHECK(deferred_counters_.empty());
  isolate()->CountUsage(base::VectorOf(to_report));
}

class Heap::AllocationTrackerForDebugging final
    : public HeapObjectAllocationTracker {
 public:
  static bool IsNeeded() {
    return v8_flags.verify_predictable || v8_flags.fuzzer_gc_analysis ||
           (v8_flags.trace_allocation_stack_interval > 0);
  }

  explicit AllocationTrackerForDebugging(Heap* heap) : heap_(heap) {
    CHECK(IsNeeded());
    heap_->AddHeapObjectAllocationTracker(this);
  }

  ~AllocationTrackerForDebugging() final {
    heap_->RemoveHeapObjectAllocationTracker(this);
    if (v8_flags.verify_predictable || v8_flags.fuzzer_gc_analysis) {
      PrintAllocationsHash();
    }
  }

  void AllocationEvent(Address addr, int size) final {
    if (v8_flags.verify_predictable) {
      allocations_count_.fetch_add(1, std::memory_order_relaxed);
      // Advance synthetic time by making a time request.
      heap_->MonotonicallyIncreasingTimeInMs();
```