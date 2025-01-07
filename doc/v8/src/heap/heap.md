Response: The user wants a summary of the C++ source code file `v8/src/heap/heap.cc`. This is the first part of a larger file. I need to identify the main functionalities implemented in this section.

Based on the included headers and the code within this part, the primary focus seems to be the management of the V8 heap, including:

- **Heap initialization and setup:**  Defining initial and maximum heap sizes.
- **Memory accounting and tracking:** Tracking used, available, and committed memory.
- **Garbage collection (GC) infrastructure:** Defining GC types, selecting appropriate collectors, and managing GC state.
- **Allocation management:**  Observing and tracking object allocations.
- **Integration with other V8 components:**  Interacting with the isolate, memory allocator, and tracing infrastructure.

I need to provide a concise summary and illustrate the connection to JavaScript using a relevant example.
这是 V8 JavaScript 引擎中负责**堆内存管理**的核心部分。它定义了 `Heap` 类，该类是 V8 引擎中管理 JavaScript 对象内存的主要组件。

**主要功能包括：**

1. **堆的初始化和配置：**
   - 设置初始和最大堆大小。
   - 根据物理内存大小计算合适的堆大小。
   - 管理新生代和老年代的大小。

2. **内存分配和跟踪：**
   - 跟踪堆的使用情况，包括已用、可用和已提交的内存。
   - 提供了获取各种内存指标的方法（例如：`SizeOfObjects()`, `CommittedMemory()`, `Available()`）。
   - 支持分配观察者，用于在对象分配时执行特定操作。

3. **垃圾回收（GC）：**
   - 定义了不同的垃圾回收器（Scavenger, Mark-Compactor, Minor-Mark-Sweeper）。
   - 提供了选择合适的垃圾回收器的逻辑 (`SelectGarbageCollector`)。
   - 管理 GC 的状态和触发条件。
   - 包含了 GC 的序言（prologue）和尾声（epilogue）逻辑，用于执行 GC 前后的必要操作。
   - 支持并发和增量标记等 GC 技术。

4. **与 V8 引擎其他部分的集成：**
   - 与 `Isolate` 类关联，每个 V8 实例都有一个 `Isolate` 和一个 `Heap`。
   - 与内存分配器（`memory_allocator_`）交互，负责实际的内存分配和释放。
   - 与垃圾回收追踪器（`tracer()`）集成，用于记录 GC 的相关信息。

**与 JavaScript 的关系及示例：**

JavaScript 中的所有对象都分配在 V8 的堆内存中。`v8/src/heap/heap.cc` 中的代码直接影响 JavaScript 程序的内存管理和性能。例如，当 JavaScript 代码创建新对象时，V8 引擎会调用 `Heap` 类中的方法在堆上分配内存。垃圾回收机制则负责回收不再使用的 JavaScript 对象所占用的内存。

**JavaScript 示例：**

```javascript
// 创建一个 JavaScript 对象
let myObject = { name: "example", value: 123 };

// 创建一个包含大量元素的数组
let myArray = new Array(100000);

// 创建一个字符串
let myString = "This is a string";

// 这些 JavaScript 对象的内存都由 v8/src/heap/heap.cc 中的代码管理。

// 当这些对象不再被引用时，垃圾回收器会回收它们占用的内存。
myObject = null;
myArray = null;
myString = null;
```

在这个例子中，当 JavaScript 引擎执行这些代码时，`v8/src/heap/heap.cc` 中的 `Heap` 类会负责：

- 为 `myObject`、`myArray` 和 `myString` 分配内存。
- 跟踪这些对象的生命周期。
- 当这些对象被设置为 `null` 并且不再有其他引用时，垃圾回收器会识别到这些对象可以被回收，并释放它们占用的内存。

简而言之，`v8/src/heap/heap.cc` 是 V8 引擎管理 JavaScript 对象生命周期的核心，它确保了 JavaScript 程序的内存能够被有效地分配和回收。

Prompt: 
```
这是目录为v8/src/heap/heap.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共5部分，请归纳一下它的功能

"""
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

      UpdateAllocationsHash(HeapObject::FromAddress(addr));
      UpdateAllocationsHash(size);

      if (allocations_count_ % v8_flags.dump_allocations_digest_at_alloc == 0) {
        PrintAllocationsHash();
      }
    } else if (v8_flags.fuzzer_gc_analysis) {
      allocations_count_.fetch_add(1, std::memory_order_relaxed);
    } else if (v8_flags.trace_allocation_stack_interval > 0) {
      allocations_count_.fetch_add(1, std::memory_order_relaxed);
      if (allocations_count_ % v8_flags.trace_allocation_stack_interval == 0) {
        heap_->isolate()->PrintStack(stdout, Isolate::kPrintStackConcise);
      }
    }
  }

  void MoveEvent(Address source, Address target, int size) final {
    if (v8_flags.verify_predictable) {
      allocations_count_.fetch_add(1, std::memory_order_relaxed);
      // Advance synthetic time by making a time request.
      heap_->MonotonicallyIncreasingTimeInMs();

      UpdateAllocationsHash(HeapObject::FromAddress(source));
      UpdateAllocationsHash(HeapObject::FromAddress(target));
      UpdateAllocationsHash(size);

      if (allocations_count_ % v8_flags.dump_allocations_digest_at_alloc == 0) {
        PrintAllocationsHash();
      }
    } else if (v8_flags.fuzzer_gc_analysis) {
      allocations_count_.fetch_add(1, std::memory_order_relaxed);
    }
  }

  void UpdateObjectSizeEvent(Address, int) final {}

 private:
  void UpdateAllocationsHash(Tagged<HeapObject> object) {
    Address object_address = object.address();
    MemoryChunk* memory_chunk = MemoryChunk::FromAddress(object_address);
    AllocationSpace allocation_space =
        MutablePageMetadata::cast(memory_chunk->Metadata())->owner_identity();

    static_assert(kSpaceTagSize + kPageSizeBits <= 32);
    uint32_t value =
        static_cast<uint32_t>(memory_chunk->Offset(object_address)) |
        (static_cast<uint32_t>(allocation_space) << kPageSizeBits);

    UpdateAllocationsHash(value);
  }

  void UpdateAllocationsHash(uint32_t value) {
    const uint16_t c1 = static_cast<uint16_t>(value);
    const uint16_t c2 = static_cast<uint16_t>(value >> 16);
    raw_allocations_hash_ =
        StringHasher::AddCharacterCore(raw_allocations_hash_, c1);
    raw_allocations_hash_ =
        StringHasher::AddCharacterCore(raw_allocations_hash_, c2);
  }

  void PrintAllocationsHash() {
    uint32_t hash = StringHasher::GetHashCore(raw_allocations_hash_);
    PrintF("\n### Allocations = %zu, hash = 0x%08x\n",
           allocations_count_.load(std::memory_order_relaxed), hash);
  }

  Heap* const heap_;
  // Count of all allocations performed through C++ bottlenecks. This needs to
  // be atomic as objects are moved in parallel in the GC which counts as
  // allocations.
  std::atomic<size_t> allocations_count_{0};
  // Running hash over allocations performed.
  uint32_t raw_allocations_hash_ = 0;
};

void Heap::AddHeapObjectAllocationTracker(
    HeapObjectAllocationTracker* tracker) {
  if (allocation_trackers_.empty() && v8_flags.inline_new) {
    DisableInlineAllocation();
  }
  allocation_trackers_.push_back(tracker);
  if (allocation_trackers_.size() == 1) {
    isolate_->UpdateLogObjectRelocation();
  }
}

void Heap::RemoveHeapObjectAllocationTracker(
    HeapObjectAllocationTracker* tracker) {
  allocation_trackers_.erase(std::remove(allocation_trackers_.begin(),
                                         allocation_trackers_.end(), tracker),
                             allocation_trackers_.end());
  if (allocation_trackers_.empty()) {
    isolate_->UpdateLogObjectRelocation();
  }
  if (allocation_trackers_.empty() && v8_flags.inline_new) {
    EnableInlineAllocation();
  }
}

void UpdateRetainersMapAfterScavenge(
    UnorderedHeapObjectMap<Tagged<HeapObject>>* map) {
  // This is only used for Scavenger.
  DCHECK(!v8_flags.minor_ms);

  UnorderedHeapObjectMap<Tagged<HeapObject>> updated_map;

  for (auto pair : *map) {
    Tagged<HeapObject> object = pair.first;
    Tagged<HeapObject> retainer = pair.second;

    if (Heap::InFromPage(object)) {
      MapWord map_word = object->map_word(kRelaxedLoad);
      if (!map_word.IsForwardingAddress()) continue;
      object = map_word.ToForwardingAddress(object);
    }

    if (Heap::InFromPage(retainer)) {
      MapWord map_word = retainer->map_word(kRelaxedLoad);
      if (!map_word.IsForwardingAddress()) continue;
      retainer = map_word.ToForwardingAddress(retainer);
    }

    updated_map[object] = retainer;
  }

  *map = std::move(updated_map);
}

void Heap::IncrementDeferredCounts(
    base::Vector<const v8::Isolate::UseCounterFeature> features) {
  deferred_counters_.insert(deferred_counters_.end(), features.begin(),
                            features.end());
}

void Heap::GarbageCollectionPrologue(
    GarbageCollectionReason gc_reason,
    const v8::GCCallbackFlags gc_callback_flags) {
  TRACE_GC(tracer(), GCTracer::Scope::HEAP_PROLOGUE);

  is_current_gc_forced_ = gc_callback_flags & v8::kGCCallbackFlagForced ||
                          current_gc_flags_ & GCFlag::kForced ||
                          force_gc_on_next_allocation_;
  is_current_gc_for_heap_profiler_ =
      gc_reason == GarbageCollectionReason::kHeapProfiler;
  if (force_gc_on_next_allocation_) force_gc_on_next_allocation_ = false;

#ifdef V8_ENABLE_ALLOCATION_TIMEOUT
  heap_allocator_->UpdateAllocationTimeout();
#endif  // V8_ENABLE_ALLOCATION_TIMEOUT

  // There may be an allocation memento behind objects in new space. Upon
  // evacuation of a non-full new space (or if we are on the last page) there
  // may be uninitialized memory behind top. We fill the remainder of the page
  // with a filler.
  if (use_new_space()) {
    DCHECK_NOT_NULL(minor_gc_job());
    minor_gc_job()->CancelTaskIfScheduled();
  }

  // Reset GC statistics.
  promoted_objects_size_ = 0;
  previous_new_space_surviving_object_size_ = new_space_surviving_object_size_;
  new_space_surviving_object_size_ = 0;
  nodes_died_in_new_space_ = 0;
  nodes_copied_in_new_space_ = 0;
  nodes_promoted_ = 0;

  UpdateMaximumCommitted();

#ifdef DEBUG
  DCHECK(!AllowGarbageCollection::IsAllowed());
  DCHECK_EQ(gc_state(), NOT_IN_GC);

  if (v8_flags.gc_verbose) Print();
#endif  // DEBUG
}

void Heap::GarbageCollectionPrologueInSafepoint() {
  TRACE_GC(tracer(), GCTracer::Scope::HEAP_PROLOGUE_SAFEPOINT);
  gc_count_++;
  new_space_allocation_counter_ = NewSpaceAllocationCounter();
}

size_t Heap::NewSpaceAllocationCounter() const {
  size_t counter = new_space_allocation_counter_;
  if (new_space_) {
    DCHECK(!allocator()->new_space_allocator()->IsLabValid());
    counter += new_space()->AllocatedSinceLastGC();
  }
  return counter;
}

size_t Heap::SizeOfObjects() {
  size_t total = 0;

  for (SpaceIterator it(this); it.HasNext();) {
    total += it.Next()->SizeOfObjects();
  }
  return total;
}

size_t Heap::TotalGlobalHandlesSize() {
  return isolate_->global_handles()->TotalSize() +
         isolate_->traced_handles()->total_size_bytes();
}

size_t Heap::UsedGlobalHandlesSize() {
  return isolate_->global_handles()->UsedSize() +
         isolate_->traced_handles()->used_size_bytes();
}

void Heap::AddAllocationObserversToAllSpaces(
    AllocationObserver* observer, AllocationObserver* new_space_observer) {
  DCHECK(observer && new_space_observer);
  FreeMainThreadLinearAllocationAreas();
  allocator()->AddAllocationObserver(observer, new_space_observer);
}

void Heap::RemoveAllocationObserversFromAllSpaces(
    AllocationObserver* observer, AllocationObserver* new_space_observer) {
  DCHECK(observer && new_space_observer);
  allocator()->RemoveAllocationObserver(observer, new_space_observer);
}

void Heap::PublishMainThreadPendingAllocations() {
  allocator()->PublishPendingAllocations();
}

void Heap::DeoptMarkedAllocationSites() {
  // TODO(hpayer): If iterating over the allocation sites list becomes a
  // performance issue, use a cache data structure in heap instead.

  ForeachAllocationSite(
      allocation_sites_list(), [this](Tagged<AllocationSite> site) {
        if (site->deopt_dependent_code()) {
          DependentCode::MarkCodeForDeoptimization(
              isolate_, site,
              DependentCode::kAllocationSiteTenuringChangedGroup);
          site->set_deopt_dependent_code(false);
        }
      });

  Deoptimizer::DeoptimizeMarkedCode(isolate_);
}

static GCType GetGCTypeFromGarbageCollector(GarbageCollector collector) {
  switch (collector) {
    case GarbageCollector::MARK_COMPACTOR:
      return kGCTypeMarkSweepCompact;
    case GarbageCollector::SCAVENGER:
      return kGCTypeScavenge;
    case GarbageCollector::MINOR_MARK_SWEEPER:
      return kGCTypeMinorMarkSweep;
    default:
      UNREACHABLE();
  }
}

void Heap::GarbageCollectionEpilogueInSafepoint(GarbageCollector collector) {
  TRACE_GC(tracer(), GCTracer::Scope::HEAP_EPILOGUE_SAFEPOINT);

  {
    // Allows handle derefs for all threads/isolates from this thread.
    AllowHandleUsageOnAllThreads allow_all_handle_derefs;
    safepoint()->IterateLocalHeaps([](LocalHeap* local_heap) {
      local_heap->InvokeGCEpilogueCallbacksInSafepoint(
          GCCallbacksInSafepoint::GCType::kLocal);
    });

    if (collector == GarbageCollector::MARK_COMPACTOR &&
        isolate()->is_shared_space_isolate()) {
      isolate()->global_safepoint()->IterateClientIsolates([](Isolate* client) {
        client->heap()->safepoint()->IterateLocalHeaps(
            [](LocalHeap* local_heap) {
              local_heap->InvokeGCEpilogueCallbacksInSafepoint(
                  GCCallbacksInSafepoint::GCType::kShared);
            });
      });
    }
  }

#define UPDATE_COUNTERS_FOR_SPACE(space)                \
  isolate_->counters()->space##_bytes_available()->Set( \
      static_cast<int>(space()->Available()));          \
  isolate_->counters()->space##_bytes_committed()->Set( \
      static_cast<int>(space()->CommittedMemory()));    \
  isolate_->counters()->space##_bytes_used()->Set(      \
      static_cast<int>(space()->SizeOfObjects()));
#define UPDATE_FRAGMENTATION_FOR_SPACE(space)                          \
  if (space()->CommittedMemory() > 0) {                                \
    isolate_->counters()->external_fragmentation_##space()->AddSample( \
        static_cast<int>(100 - (space()->SizeOfObjects() * 100.0) /    \
                                   space()->CommittedMemory()));       \
  }
#define UPDATE_COUNTERS_AND_FRAGMENTATION_FOR_SPACE(space) \
  UPDATE_COUNTERS_FOR_SPACE(space)                         \
  UPDATE_FRAGMENTATION_FOR_SPACE(space)

  if (new_space()) {
    UPDATE_COUNTERS_FOR_SPACE(new_space)
  }

  UPDATE_COUNTERS_AND_FRAGMENTATION_FOR_SPACE(old_space)
  UPDATE_COUNTERS_AND_FRAGMENTATION_FOR_SPACE(code_space)

  UPDATE_COUNTERS_AND_FRAGMENTATION_FOR_SPACE(lo_space)
#undef UPDATE_COUNTERS_FOR_SPACE
#undef UPDATE_FRAGMENTATION_FOR_SPACE
#undef UPDATE_COUNTERS_AND_FRAGMENTATION_FOR_SPACE

#ifdef DEBUG
  if (v8_flags.print_global_handles) isolate_->global_handles()->Print();
  if (v8_flags.print_handles) PrintHandles();
  if (v8_flags.check_handle_count) CheckHandleCount();
#endif

  // Young generation GCs only run with  memory reducing flags during
  // interleaved GCs.
  DCHECK_IMPLIES(
      v8_flags.separate_gc_phases && IsYoungGenerationCollector(collector),
      !ShouldReduceMemory());
  if (collector == GarbageCollector::MARK_COMPACTOR) {
    memory_pressure_level_.store(MemoryPressureLevel::kNone,
                                 std::memory_order_relaxed);

    if (v8_flags.stress_marking > 0) {
      stress_marking_percentage_ = NextStressMarkingLimit();
    }
    // Discard memory if the GC was requested to reduce memory.
    if (ShouldReduceMemory()) {
      memory_allocator_->pool()->ReleasePooledChunks();
#if V8_ENABLE_WEBASSEMBLY
      isolate_->stack_pool().ReleaseFinishedStacks();
#endif
    }
  }

  // Remove CollectionRequested flag from main thread state, as the collection
  // was just performed.
  safepoint()->AssertActive();
  LocalHeap::ThreadState old_state =
      main_thread_local_heap()->state_.ClearCollectionRequested();

  CHECK(old_state.IsRunning());

  // Resume all threads waiting for the GC.
  collection_barrier_->ResumeThreadsAwaitingCollection();
}

void Heap::GarbageCollectionEpilogue(GarbageCollector collector) {
  TRACE_GC(tracer(), GCTracer::Scope::HEAP_EPILOGUE);
  AllowGarbageCollection for_the_rest_of_the_epilogue;

  UpdateMaximumCommitted();

  isolate_->counters()->alive_after_last_gc()->Set(
      static_cast<int>(SizeOfObjects()));

  if (CommittedMemory() > 0) {
    isolate_->counters()->external_fragmentation_total()->AddSample(
        static_cast<int>(100 - (SizeOfObjects() * 100.0) / CommittedMemory()));

    isolate_->counters()->heap_sample_total_committed()->AddSample(
        static_cast<int>(CommittedMemory() / KB));
    isolate_->counters()->heap_sample_total_used()->AddSample(
        static_cast<int>(SizeOfObjects() / KB));
    isolate_->counters()->heap_sample_code_space_committed()->AddSample(
        static_cast<int>(code_space()->CommittedMemory() / KB));

    isolate_->counters()->heap_sample_maximum_committed()->AddSample(
        static_cast<int>(MaximumCommittedMemory() / KB));
  }

#ifdef DEBUG
  ReportStatisticsAfterGC();
  if (v8_flags.code_stats) ReportCodeStatistics("After GC");
#endif  // DEBUG

  last_gc_time_ = MonotonicallyIncreasingTimeInMs();
}

GCCallbacksScope::GCCallbacksScope(Heap* heap) : heap_(heap) {
  heap_->gc_callbacks_depth_++;
}

GCCallbacksScope::~GCCallbacksScope() { heap_->gc_callbacks_depth_--; }

bool GCCallbacksScope::CheckReenter() const {
  return heap_->gc_callbacks_depth_ == 1;
}

void Heap::HandleGCRequest() {
  if (IsStressingScavenge() && stress_scavenge_observer_->HasRequestedGC()) {
    CollectGarbage(NEW_SPACE, GarbageCollectionReason::kTesting);
    stress_scavenge_observer_->RequestedGCDone();
  } else if (HighMemoryPressure()) {
    CheckMemoryPressure();
  } else if (CollectionRequested()) {
    CheckCollectionRequested();
  } else if (incremental_marking()->MajorCollectionRequested()) {
    CollectAllGarbage(current_gc_flags_,
                      GarbageCollectionReason::kFinalizeMarkingViaStackGuard,
                      current_gc_callback_flags_);
  } else if (minor_mark_sweep_collector()->gc_finalization_requsted()) {
    CollectGarbage(NEW_SPACE,
                   GarbageCollectionReason::kFinalizeConcurrentMinorMS);
  }
}

void Heap::ScheduleMinorGCTaskIfNeeded() {
  DCHECK_NOT_NULL(minor_gc_job_);
  minor_gc_job_->ScheduleTask();
}

namespace {
size_t MinorMSConcurrentMarkingTrigger(Heap* heap) {
  size_t young_capacity = 0;
  if (v8_flags.sticky_mark_bits) {
    // TODO(333906585): Adjust parameters.
    young_capacity = heap->sticky_space()->Capacity() -
                     heap->sticky_space()->old_objects_size();
  } else {
    young_capacity = heap->new_space()->TotalCapacity();
  }
  return young_capacity * v8_flags.minor_ms_concurrent_marking_trigger / 100;
}
}  // namespace

void Heap::StartMinorMSIncrementalMarkingIfNeeded() {
  if (incremental_marking()->IsMarking()) return;
  if (v8_flags.concurrent_minor_ms_marking && !IsTearingDown() &&
      incremental_marking()->CanAndShouldBeStarted() &&
      V8_LIKELY(!v8_flags.gc_global)) {
    size_t usable_capacity = 0;
    size_t new_space_size = 0;
    if (v8_flags.sticky_mark_bits) {
      // TODO(333906585): Adjust parameters.
      usable_capacity =
          sticky_space()->Capacity() - sticky_space()->old_objects_size();
      new_space_size = sticky_space()->young_objects_size();
    } else {
      usable_capacity = paged_new_space()->paged_space()->UsableCapacity();
      new_space_size = new_space()->Size();
    }
    if ((usable_capacity >=
         v8_flags.minor_ms_min_new_space_capacity_for_concurrent_marking_mb *
             MB) &&
        (new_space_size >= MinorMSConcurrentMarkingTrigger(this)) &&
        ShouldUseBackgroundThreads()) {
      StartIncrementalMarking(GCFlag::kNoFlags, GarbageCollectionReason::kTask,
                              kNoGCCallbackFlags,
                              GarbageCollector::MINOR_MARK_SWEEPER);
      // Schedule a task for finalizing the GC if needed.
      ScheduleMinorGCTaskIfNeeded();
    }
  }
}

void Heap::CollectAllGarbage(GCFlags gc_flags,
                             GarbageCollectionReason gc_reason,
                             const v8::GCCallbackFlags gc_callback_flags) {
  current_gc_flags_ = gc_flags;
  CollectGarbage(OLD_SPACE, gc_reason, gc_callback_flags);
  DCHECK_EQ(GCFlags(GCFlag::kNoFlags), current_gc_flags_);
}

namespace {

intptr_t CompareWords(int size, Tagged<HeapObject> a, Tagged<HeapObject> b) {
  int slots = size / kTaggedSize;
  DCHECK_EQ(a->Size(), size);
  DCHECK_EQ(b->Size(), size);
  Tagged_t* slot_a = reinterpret_cast<Tagged_t*>(a.address());
  Tagged_t* slot_b = reinterpret_cast<Tagged_t*>(b.address());
  for (int i = 0; i < slots; i++) {
    if (*slot_a != *slot_b) {
      return *slot_a - *slot_b;
    }
    slot_a++;
    slot_b++;
  }
  return 0;
}

void ReportDuplicates(int size, std::vector<Tagged<HeapObject>>* objects) {
  if (objects->empty()) return;

  sort(objects->begin(), objects->end(),
       [size](Tagged<HeapObject> a, Tagged<HeapObject> b) {
         intptr_t c = CompareWords(size, a, b);
         if (c != 0) return c < 0;
         return a < b;
       });

  std::vector<std::pair<int, Tagged<HeapObject>>> duplicates;
  Tagged<HeapObject> current = (*objects)[0];
  int count = 1;
  for (size_t i = 1; i < objects->size(); i++) {
    if (CompareWords(size, current, (*objects)[i]) == 0) {
      count++;
    } else {
      if (count > 1) {
        duplicates.push_back(std::make_pair(count - 1, current));
      }
      count = 1;
      current = (*objects)[i];
    }
  }
  if (count > 1) {
    duplicates.push_back(std::make_pair(count - 1, current));
  }

  int threshold = v8_flags.trace_duplicate_threshold_kb * KB;

  sort(duplicates.begin(), duplicates.end());
  for (auto it = duplicates.rbegin(); it != duplicates.rend(); ++it) {
    int duplicate_bytes = it->first * size;
    if (duplicate_bytes < threshold) break;
    PrintF("%d duplicates of size %d each (%dKB)\n", it->first, size,
           duplicate_bytes / KB);
    PrintF("Sample object: ");
    Print(it->second);
    PrintF("============================\n");
  }
}
}  // anonymous namespace

void Heap::CollectAllAvailableGarbage(GarbageCollectionReason gc_reason) {
  // Min and max number of attempts for GC. The method will continue with more
  // GCs until the root set is stable.
  static constexpr int kMaxNumberOfAttempts = 7;
  static constexpr int kMinNumberOfAttempts = 2;

  // Returns the number of roots. We assume stack layout is stable but global
  // roots could change between GCs due to finalizers and weak callbacks.
  const auto num_roots = [this]() {
    size_t js_roots = 0;
    js_roots += isolate()->global_handles()->handles_count();
    js_roots += isolate()->eternal_handles()->handles_count();
    size_t cpp_roots = 0;
    if (auto* cpp_heap = CppHeap::From(cpp_heap_)) {
      cpp_roots += cpp_heap->GetStrongPersistentRegion().NodesInUse();
      cpp_roots +=
          cpp_heap->GetStrongCrossThreadPersistentRegion().NodesInUse();
    }
    return js_roots + cpp_roots;
  };

  if (gc_reason == GarbageCollectionReason::kLastResort) {
    InvokeNearHeapLimitCallback();
  }
  RCS_SCOPE(isolate(), RuntimeCallCounterId::kGC_Custom_AllAvailableGarbage);

  // The optimizing compiler may be unnecessarily holding on to memory.
  isolate()->AbortConcurrentOptimization(BlockingBehavior::kDontBlock);
  isolate()->ClearSerializerData();
  isolate()->compilation_cache()->Clear();

  const GCFlags gc_flags =
      GCFlag::kReduceMemoryFootprint |
      (gc_reason == GarbageCollectionReason::kLowMemoryNotification
           ? GCFlag::kForced
           : GCFlag::kNoFlags);
  for (int attempt = 0; attempt < kMaxNumberOfAttempts; attempt++) {
    const size_t roots_before = num_roots();
    current_gc_flags_ = gc_flags;
    CollectGarbage(OLD_SPACE, gc_reason, kNoGCCallbackFlags);
    DCHECK_EQ(GCFlags(GCFlag::kNoFlags), current_gc_flags_);
    if ((roots_before == num_roots()) &&
        ((attempt + 1) >= kMinNumberOfAttempts)) {
      break;
    }
  }

  EagerlyFreeExternalMemoryAndWasmCode();

  if (v8_flags.trace_duplicate_threshold_kb) {
    std::map<int, std::vector<Tagged<HeapObject>>> objects_by_size;
    PagedSpaceIterator spaces(this);
    for (PagedSpace* space = spaces.Next(); space != nullptr;
         space = spaces.Next()) {
      PagedSpaceObjectIterator it(this, space);
      for (Tagged<HeapObject> obj = it.Next(); !obj.is_null();
           obj = it.Next()) {
        objects_by_size[obj->Size()].push_back(obj);
      }
    }
    {
      LargeObjectSpaceObjectIterator it(lo_space());
      for (Tagged<HeapObject> obj = it.Next(); !obj.is_null();
           obj = it.Next()) {
        objects_by_size[obj->Size()].push_back(obj);
      }
    }
    for (auto it = objects_by_size.rbegin(); it != objects_by_size.rend();
         ++it) {
      ReportDuplicates(it->first, &it->second);
    }
  }

  if (gc_reason == GarbageCollectionReason::kLastResort &&
      v8_flags.heap_snapshot_on_oom) {
    isolate()->heap_profiler()->WriteSnapshotToDiskAfterGC();
  }
}

void Heap::PreciseCollectAllGarbage(GCFlags gc_flags,
                                    GarbageCollectionReason gc_reason,
                                    const GCCallbackFlags gc_callback_flags) {
  if (!incremental_marking()->IsStopped()) {
    FinalizeIncrementalMarkingAtomically(gc_reason);
  }
  CollectAllGarbage(gc_flags, gc_reason, gc_callback_flags);
}

void Heap::HandleExternalMemoryInterrupt() {
  const GCCallbackFlags kGCCallbackFlagsForExternalMemory =
      static_cast<GCCallbackFlags>(
          kGCCallbackFlagSynchronousPhantomCallbackProcessing |
          kGCCallbackFlagCollectAllExternalMemory);
  uint64_t current = external_memory();
  if (current > external_memory_hard_limit()) {
    TRACE_EVENT2("devtools.timeline,v8", "V8.ExternalMemoryPressure",
                 "external_memory_mb", static_cast<int>((current) / MB),
                 "external_memory_hard_limit_mb",
                 static_cast<int>((external_memory_hard_limit()) / MB));
    CollectAllGarbage(
        GCFlag::kReduceMemoryFootprint,
        GarbageCollectionReason::kExternalMemoryPressure,
        static_cast<GCCallbackFlags>(kGCCallbackFlagCollectAllAvailableGarbage |
                                     kGCCallbackFlagsForExternalMemory));
    return;
  }
  if (v8_flags.external_memory_accounted_in_global_limit) {
    // Under `external_memory_accounted_in_global_limit`, external interrupt
    // only triggers a check to allocation limits.
    external_memory_.UpdateLimitForInterrupt(current);
    StartIncrementalMarkingIfAllocationLimitIsReached(
        main_thread_local_heap(), GCFlagsForIncrementalMarking(),
        kGCCallbackFlagsForExternalMemory);
    return;
  }
  uint64_t soft_limit = external_memory_.soft_limit();
  if (current <= soft_limit) {
    return;
  }
  TRACE_EVENT2("devtools.timeline,v8", "V8.ExternalMemoryPressure",
               "external_memory_mb", static_cast<int>((current) / MB),
               "external_memory_soft_limit_mb",
               static_cast<int>((soft_limit) / MB));
  if (incremental_marking()->IsStopped()) {
    if (incremental_marking()->CanAndShouldBeStarted()) {
      StartIncrementalMarking(GCFlagsForIncrementalMarking(),
                              GarbageCollectionReason::kExternalMemoryPressure,
                              kGCCallbackFlagsForExternalMemory);
    } else {
      CollectAllGarbage(i::GCFlag::kNoFlags,
                        GarbageCollectionReason::kExternalMemoryPressure,
                        kGCCallbackFlagsForExternalMemory);
    }
  } else {
    // Incremental marking is turned on and has already been started.
    current_gc_callback_flags_ = static_cast<GCCallbackFlags>(
        current_gc_callback_flags_ | kGCCallbackFlagsForExternalMemory);
    incremental_marking()->AdvanceAndFinalizeIfNecessary();
  }
}

uint64_t Heap::external_memory_limit_for_interrupt() {
  return external_memory_.limit_for_interrupt();
}

uint64_t Heap::external_memory_soft_limit() {
  return external_memory_.soft_limit();
}

Heap::DevToolsTraceEventScope::DevToolsTraceEventScope(Heap* heap,
                                                       const char* event_name,
                                                       const char* event_type)
    : heap_(heap), event_name_(event_name) {
  TRACE_EVENT_BEGIN2("devtools.timeline,v8", event_name_, "usedHeapSizeBefore",
                     heap_->SizeOfObjects(), "type", event_type);
}

Heap::DevToolsTraceEventScope::~DevToolsTraceEventScope() {
  TRACE_EVENT_END1("devtools.timeline,v8", event_name_, "usedHeapSizeAfter",
                   heap_->SizeOfObjects());
}

namespace {

template <typename Callback>
void InvokeExternalCallbacks(Isolate* isolate, Callback callback) {
  DCHECK(!AllowJavascriptExecution::IsAllowed(isolate));
  AllowGarbageCollection allow_gc;
  // Temporary override any embedder stack state as callbacks may create
  // their own state on the stack and recursively trigger GC.
  EmbedderStackStateScope embedder_scope(
      isolate->heap(), EmbedderStackStateOrigin::kExplicitInvocation,
      StackState::kMayContainHeapPointers);
  VMState<EXTERNAL> callback_state(isolate);

  callback();
}

size_t GlobalMemorySizeFromV8Size(size_t v8_size) {
  const size_t kGlobalMemoryToV8Ratio = 2;
  return std::min(static_cast<uint64_t>(std::numeric_limits<size_t>::max()),
                  static_cast<uint64_t>(v8_size) * kGlobalMemoryToV8Ratio);
}

}  // anonymous namespace

void Heap::SetOldGenerationAndGlobalMaximumSize(
    size_t max_old_generation_size) {
  max_old_generation_size_.store(max_old_generation_size,
                                 std::memory_order_relaxed);
  max_global_memory_size_ = GlobalMemorySizeFromV8Size(max_old_generation_size);
}

void Heap::SetOldGenerationAndGlobalAllocationLimit(
    size_t new_old_generation_allocation_limit,
    size_t new_global_allocation_limit) {
  CHECK_GE(new_global_allocation_limit, new_old_generation_allocation_limit);
#if defined(V8_USE_PERFETTO)
  TRACE_COUNTER(TRACE_DISABLED_BY_DEFAULT("v8.gc"), V8HeapTrait::kName,
                new_old_generation_allocation_limit);
  TRACE_COUNTER(TRACE_DISABLED_BY_DEFAULT("v8.gc"), GlobalMemoryTrait::kName,
                new_global_allocation_limit);
#endif
  old_generation_allocation_limit_.store(new_old_generation_allocation_limit,
                                         std::memory_order_relaxed);
  global_allocation_limit_.store(new_global_allocation_limit,
                                 std::memory_order_relaxed);
}

void Heap::ResetOldGenerationAndGlobalAllocationLimit() {
  SetOldGenerationAndGlobalAllocationLimit(
      initial_old_generation_size_,
      GlobalMemorySizeFromV8Size(initial_old_generation_size_));
  set_using_initial_limit(true);
}

void Heap::CollectGarbage(AllocationSpace space,
                          GarbageCollectionReason gc_reason,
                          const v8::GCCallbackFlags gc_callback_flags) {
  if (V8_UNLIKELY(!deserialization_complete_)) {
    // During isolate initialization heap always grows. GC is only requested
    // if a new page allocation fails. In such a case we should crash with
    // an out-of-memory instead of performing GC because the prologue/epilogue
    // callbacks may see objects that are not yet deserialized.
    CHECK(always_allocate());
    FatalProcessOutOfMemory("GC during deserialization");
  }

  // CollectGarbage consists of three parts:
  // 1. The prologue part which may execute callbacks. These callbacks may
  // allocate and trigger another garbage collection.
  // 2. The main garbage collection phase.
  // 3. The epilogue part which may execute callbacks. These callbacks may
  // allocate and trigger another garbage collection

  // Part 1: Invoke all callbacks which should happen before the actual garbage
  // collection is triggered. Note that these callbacks may trigger another
  // garbage collection since they may allocate.

  // JS execution is not allowed in any of the callbacks.
  DisallowJavascriptExecution no_js(isolate());

  DCHECK(AllowGarbageCollection::IsAllowed());
  // TODO(chromium:1523607): Ensure this for standalone cppgc as well.
  CHECK_IMPLIES(!v8_flags.allow_allocation_in_fast_api_call,
                !isolate()->InFastCCall());

  const char* collector_reason = nullptr;
  const GarbageCollector collector =
      SelectGarbageCollector(space, gc_reason, &collector_reason);
  current_or_last_garbage_collector_ = collector;
  DCHECK_IMPLIES(v8_flags.minor_ms && IsYoungGenerationCollector(collector),
                 !ShouldReduceMemory());

  if (collector == GarbageCollector::MARK_COMPACTOR &&
      incremental_marking()->IsMinorMarking()) {
    const GCFlags gc_flags = current_gc_flags_;
    // Minor GCs should not be memory reducing.
    current_gc_flags_ &= ~GCFlag::kReduceMemoryFootprint;
    CollectGarbage(NEW_SPACE,
                   GarbageCollectionReason::kFinalizeConcurrentMinorMS);
    current_gc_flags_ = gc_flags;
  }

  const GCType gc_type = GetGCTypeFromGarbageCollector(collector);

  // Prologue callbacks. These callbacks may trigger GC themselves and thus
  // cannot be related exactly to garbage collection cycles.
  //
  // GCTracer scopes are managed by callees.
  InvokeExternalCallbacks(isolate(), [this, gc_callback_flags, gc_type]() {
    // Ensure that all pending phantom callbacks are invoked.
    isolate()->global_handles()->InvokeSecondPassPhantomCallbacks();

    // Prologue callbacks registered with Heap.
    CallGCPrologueCallbacks(gc_type, gc_callback_flags,
                            GCTracer::Scope::HEAP_EXTERNAL_PROLOGUE);
  });

  // The main garbage collection phase.
  //
  // We need a stack marker at the top of all entry points to allow
  // deterministic passes over the stack. E.g., a verifier that should only
  // find a subset of references of the marker.
  //
  // TODO(chromium:1056170): Consider adding a component that keeps track
  // of relevant GC stack regions where interesting pointers can be found.
  stack().SetMarkerIfNeededAndCallback([this, collector, gc_reason,
                                        collector_reason, gc_callback_flags]() {
    DisallowGarbageCollection no_gc_during_gc;

    size_t committed_memory_before =
        collector == GarbageCollector::MARK_COMPACTOR
            ? CommittedOldGenerationMemory()
            : 0;

    tracer()->StartObservablePause(base::TimeTicks::Now());
    VMState<GC> state(isolate());
    DevToolsTraceEventScope devtools_trace_event_scope(
        this, IsYoungGenerationCollector(collector) ? "MinorGC" : "MajorGC",
        ToString(gc_reason));

    GarbageCollectionPrologue(gc_reason, gc_callback_flags);
    {
      GCTracer::RecordGCPhasesInfo record_gc_phases_info(this, collector,
                                                         gc_reason);
      std::optional<TimedHistogramScope> histogram_timer_scope;
      std::optional<OptionalTimedHistogramScope> histogram_timer_priority_scope;
      TRACE_EVENT0("v8", record_gc_phases_info.trace_event_name());
      if (record_gc_phases_info.type_timer()) {
        histogram_timer_scope.emplace(record_gc_phases_info.type_timer(),
                                      isolate_);
      }
      if (record_gc_phases_info.type_priority_timer()) {
        histogram_timer_priority_scope.emplace(
            record_gc_phases_info.type_priority_timer(), isolate_,
            OptionalTimedHistogramScopeMode::TAKE_TIME);
      }

      PerformGarbageCollection(collector, gc_reason, collector_reason);

      // Clear flags describing the current GC now that the current GC is
      // complete. Do this before GarbageCollectionEpilogue() since that could
      // trigger another unforced GC.
      is_current_gc_forced_ = false;
      is_current_gc_for_heap_profiler_ = false;

      if (collector == GarbageCollector::MARK_COMPACTOR ||
          collector == GarbageCollector::SCAVENGER) {
        tracer()->RecordGCPhasesHistograms(record_gc_phases_info.mode());
      }
      if ((collector == GarbageCollector::MARK_COMPACTOR ||
           collector == GarbageCollector::MINOR_MARK_SWEEPER) &&
          cpp_heap()) {
        CppHeap::From(cpp_heap())->FinishAtomicSweepingIfRunning();
      }
    }

    GarbageCollectionEpilogue(collector);
    if (collector == GarbageCollector::MARK_COMPACTOR &&
        v8_flags.track_detached_contexts) {
      isolate()->CheckDetachedContextsAfterGC();
    }

    if (collector == G
"""


```