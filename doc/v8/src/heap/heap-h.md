Response:
The user wants to understand the functionality of the `v8/src/heap/heap.h` file in the V8 JavaScript engine. They also have some specific questions about its nature (Torque source), relationship with JavaScript, code logic, and potential programming errors. Finally, they want a summary of its functions.

Here's a breakdown of how to address the request:

1. **Identify the file type:** Check if the filename ends with `.tq`. In this case, it ends with `.h`, so it's a C++ header file.
2. **General Functionality:** Analyze the included headers and the class declaration (`class Heap final`). The headers point to memory management, garbage collection, object representation, and interaction with the V8 API.
3. **Relationship with JavaScript:** Look for members, methods, or comments that connect to JavaScript concepts like objects, arrays, contexts, and garbage collection.
4. **Code Logic and Assumptions:**  Examine methods and their parameters to infer their purpose. Since it's a header file, detailed logic is limited, but we can deduce functionality from declarations. Make educated guesses about inputs and outputs.
5. **Common Programming Errors:**  Think about typical mistakes related to memory management, such as memory leaks, use-after-free, and incorrect object handling.
6. **Summarize Functionality:** Condense the identified functionalities into a concise summary.
```cpp
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_HEAP_HEAP_H_
#define V8_HEAP_HEAP_H_

#include <atomic>
#include <cmath>
#include <memory>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Clients of this interface shouldn't depend on lots of heap internals.
// Do not include anything from src/heap here!
#include "include/v8-callbacks.h"
#include "include/v8-embedder-heap.h"
#include "include/v8-internal.h"
#include "include/v8-isolate.h"
#include "src/base/atomic-utils.h"
#include "src/base/enum-set.h"
#include "src/base/platform/condition-variable.h"
#include "src/base/platform/mutex.h"
#include "src/base/small-vector.h"
#include "src/builtins/accessors.h"
#include "src/common/assert-scope.h"
#include "src/common/code-memory-access.h"
#include "src/common/globals.h"
#include "src/heap/allocation-observer.h"
#include "src/heap/allocation-result.h"
#include "src/heap/gc-callbacks.h"
#include "src/heap/heap-allocator.h"
#include "src/heap/marking-state.h"
#include "src/heap/minor-gc-job.h"
#include "src/heap/pretenuring-handler.h"
#include "src/heap/sweeper.h"
#include "src/init/heap-symbols.h"
#include "src/objects/allocation-site.h"
#include "src/objects/fixed-array.h"
#include "src/objects/hash-table.h"
#include "src/objects/heap-object.h"
#include "src/objects/js-array-buffer.h"
#include "src/objects/objects.h"
#include "src/objects/smi.h"
#include "src/objects/visitors.h"
#include "src/roots/roots.h"
#include "src/sandbox/code-pointer-table.h"
#include "src/sandbox/external-pointer-table.h"
#include "src/sandbox/js-dispatch-table.h"
#include "src/sandbox/trusted-pointer-table.h"
#include "src/utils/allocation.h"
#include "testing/gtest/include/gtest/gtest_prod.h"  // nogncheck

namespace cppgc::internal {
enum class HeapObjectNameForUnnamedObject : uint8_t;
class ClassNameAsHeapObjectNameScope;
}  // namespace cppgc::internal

namespace heap::base {
class Stack;
}  // namespace heap::base

namespace v8 {

namespace debug {
using OutOfMemoryCallback = void (*)(void* data);
}  // namespace debug

namespace internal {

namespace heap {
class HeapTester;
class TestMemoryAllocatorScope;
}  // namespace heap

class ArrayBufferCollector;
class ArrayBufferSweeper;
class BackingStore;
class MemoryChunkMetadata;
class Boolean;
class CodeLargeObjectSpace;
class CodeRange;
class CollectionBarrier;
class ConcurrentMarking;
class CppHeap;
class EphemeronRememberedSet;
class GCTracer;
class IncrementalMarking;
class IsolateSafepoint;
class HeapObjectAllocationTracker;
class HeapObjectsFilter;
class HeapStats;
class Isolate;
class JSArrayBuffer;
class JSFinalizationRegistry;
class JSPromise;
class LinearAllocationArea;
class LocalHeap;
class MemoryAllocator;
class MemoryBalancer;
class MutablePageMetadata;
class MemoryMeasurement;
class MemoryReducer;
class MinorMarkSweepCollector;
class NativeContext;
class NopRwxMemoryWriteScope;
class ObjectIterator;
class ObjectStats;
class PageMetadata;
class PagedSpace;
class PagedNewSpace;
class ReadOnlyHeap;
class RootVisitor;
class RwxMemoryWriteScope;
class SafepointScope;
class Scavenger;
class ScavengerCollector;
class SemiSpaceNewSpace;
class SharedLargeObjectSpace;
class SharedReadOnlySpace;
class SharedSpace;
class SharedTrustedLargeObjectSpace;
class SharedTrustedSpace;
class Space;
class StickySpace;
class StressScavengeObserver;
class TimedHistogram;
class TrustedLargeObjectSpace;
class TrustedRange;
class TrustedSpace;
class WeakObjectRetainer;

enum class ClearRecordedSlots { kYes, kNo };

enum class InvalidateRecordedSlots { kYes, kNo };

enum class InvalidateExternalPointerSlots { kYes, kNo };

enum class ClearFreedMemoryMode { kClearFreedMemory, kDontClearFreedMemory };

enum class SkipRoot {
  kExternalStringTable,
  kGlobalHandles,
  kTracedHandles,
  kOldGeneration,
  kStack,
  kMainThreadHandles,
  kUnserializable,
  kWeak,
  kConservativeStack,
  kReadOnlyBuiltins,
};

enum class EmbedderStackStateOrigin {
  kImplicitThroughTask,
  kExplicitInvocation,
};

class StrongRootsEntry final {
  explicit StrongRootsEntry(const char* label) : label(label) {}

  // Label that identifies the roots in tooling.
  const char* label;
  FullObjectSlot start;
  FullObjectSlot end;
  StrongRootsEntry* prev;
  StrongRootsEntry* next;

  friend class Heap;
};

// An alias for std::unordered_map<Tagged<HeapObject>, T> which also
// sets proper Hash and KeyEqual functions.
template <typename T>
using UnorderedHeapObjectMap =
    std::unordered_map<Tagged<HeapObject>, T, Object::Hasher,
                       Object::KeyEqualSafe>;

enum class GCFlag : uint8_t {
  kNoFlags = 0,
  kReduceMemoryFootprint = 1 << 0,
  // GCs that are forced, either through testing configurations (requiring
  // --expose-gc) or through DevTools (using LowMemoryNotification).
  kForced = 1 << 1,
};

using GCFlags = base::Flags<GCFlag, uint8_t>;
DEFINE_OPERATORS_FOR_FLAGS(GCFlags)

class Heap final {
 public:
  enum class HeapGrowingMode { kSlow, kConservative, kMinimal, kDefault };

  enum HeapState {
    NOT_IN_GC,
    SCAVENGE,
    MARK_COMPACT,
    MINOR_MARK_SWEEP,
    TEAR_DOWN
  };

  // Emits GC events for DevTools timeline.
  class V8_NODISCARD DevToolsTraceEventScope {
   public:
    DevToolsTraceEventScope(Heap* heap, const char* event_name,
                            const char* event_type);
    ~DevToolsTraceEventScope();

   private:
    Heap* heap_;
    const char* event_name_;
  };

  class ExternalMemoryAccounting {
   public:
    static constexpr size_t kExternalAllocationLimitForInterrupt = 128 * KB;

    uint64_t total() const { return total_.load(std::memory_order_relaxed); }
    uint64_t limit_for_interrupt() const {
      return limit_for_interrupt_.load(std::memory_order_relaxed);
    }
    uint64_t soft_limit() const {
      return low_since_mark_compact() + kExternalAllocationSoftLimit;
    }
    uint64_t low_since_mark_compact() const {
      return low_since_mark_compact_.load(std::memory_order_relaxed);
    }

    uint64_t UpdateAmount(int64_t delta) {
      const uint64_t amount_before =
          total_.fetch_add(delta, std::memory_order_relaxed);
      CHECK_GE(static_cast<int64_t>(amount_before), -delta);
      return amount_before + delta;
    }

    void UpdateLimitForInterrupt(uint64_t amount) {
      set_limit_for_interrupt(amount + kExternalAllocationLimitForInterrupt);
    }

    void UpdateLowSinceMarkCompact(uint64_t amount) {
      set_low_since_mark_compact(amount);
      UpdateLimitForInterrupt(amount);
    }

    uint64_t AllocatedSinceMarkCompact() const {
      uint64_t total_bytes = total();
      uint64_t low_since_mark_compact_bytes = low_since_mark_compact();

      if (total_bytes <= low_since_mark_compact_bytes) {
        return 0;
      }
      return total_bytes - low_since_mark_compact_bytes;
    }

   private:
    void set_total(uint64_t value) {
      total_.store(value, std::memory_order_relaxed);
    }

    void set_limit_for_interrupt(uint64_t value) {
      limit_for_interrupt_.store(value, std::memory_order_relaxed);
    }

    void set_low_since_mark_compact(uint64_t value) {
      low_since_mark_compact_.store(value, std::memory_order_relaxed);
    }

    // The amount of external memory registered through the API.
    std::atomic<uint64_t> total_{0};

    // The limit when to trigger memory pressure from the API.
    std::atomic<uint64_t> limit_for_interrupt_{
        kExternalAllocationLimitForInterrupt};

    // Caches the amount of external memory registered at the last MC.
    std::atomic<uint64_t> low_since_mark_compact_{0};
  };

  // Taking this mutex prevents the GC from entering a phase that relocates
  // object references.
  base::Mutex* relocation_mutex() { return &relocation_mutex_; }

  // Support for context snapshots. After calling this we have a linear
  // space to write objects in each space.
  struct Chunk {
    uint32_t size;
    Address start;
    Address end;
  };
  using Reservation = std::vector<Chunk>;

#if V8_OS_ANDROID
  // Don't apply pointer multiplier on Android since it has no swap space and
  // should instead adapt it's heap size based on available physical memory.
  static const int kPointerMultiplier = 1;
  static const int kHeapLimitMultiplier = 1;
#else
  static const int kPointerMultiplier = kTaggedSize / 4;
  // The heap limit needs to be computed based on the system pointer size
  // because we want a pointer-compressed heap to have larger limit than
  // an ordinary 32-bit which that is constrained by 2GB virtual address space.
  static const int kHeapLimitMultiplier = kSystemPointerSize / 4;
#endif

  static const size_t kMaxInitialOldGenerationSize =
      256 * MB * kHeapLimitMultiplier;

  // These constants control heap configuration based on the physical memory.
  static constexpr size_t kPhysicalMemoryToOldGenerationRatio = 4;
  static constexpr size_t kOldGenerationLowMemory =
      128 * MB * kHeapLimitMultiplier;
  static constexpr size_t kNewLargeObjectSpaceToSemiSpaceRatio = 1;

  static const int kTraceRingBufferSize = 512;
  static const int kStacktraceBufferSize = 512;

  // The minimum size of a HeapObject on the heap.
  static const int kMinObjectSizeInTaggedWords = 2;

  static size_t DefaultMinSemiSpaceSize();
  V8_EXPORT_PRIVATE static size_t DefaultMaxSemiSpaceSize();
  // Young generation size is the same for compressed heaps and 32-bit heaps.
  static size_t OldGenerationToSemiSpaceRatio();
  static size_t OldGenerationToSemiSpaceRatioLowMemory();

  // Calculates the maximum amount of filler that could be required by the
  // given alignment.
  V8_EXPORT_PRIVATE static int GetMaximumFillToAlign(
      AllocationAlignment alignment);
  // Calculates the actual amount of filler required for a given address at the
  // given alignment.
  V8_EXPORT_PRIVATE static int GetFillToAlign(Address address,
                                              AllocationAlignment alignment);

  // Returns the size of the initial area of a code-range, which is marked
  // writable and reserved to contain unwind information.
  static size_t GetCodeRangeReservedAreaSize();

  [[noreturn]] V8_EXPORT_PRIVATE void FatalProcessOutOfMemory(
      const char* location);

  // Checks whether the space is valid.
  static bool IsValidAllocationSpace(AllocationSpace space);

  static inline bool IsYoungGenerationCollector(GarbageCollector collector) {
    return collector == GarbageCollector::SCAVENGER ||
           collector == GarbageCollector::MINOR_MARK_SWEEPER;
  }

  V8_EXPORT_PRIVATE static bool IsFreeSpaceValid(FreeSpace object);

  static inline GarbageCollector YoungGenerationCollector() {
    return (v8_flags.minor_ms) ? GarbageCollector::MINOR_MARK_SWEEPER
                               : GarbageCollector::SCAVENGER;
  }

  // Copy block of memory from src to dst. Size of block should be aligned
  // by pointer size.
  static inline void CopyBlock(Address dst, Address src, int byte_size);

  EphemeronRememberedSet* ephemeron_remembered_set() {
    return ephemeron_remembered_set_.get();
  }

  // Notifies the heap that is ok to start marking or other activities that
  // should not happen during deserialization.
  void NotifyDeserializationComplete();

  // Weakens StrongDescriptorArray objects into regular DescriptorArray objects.
  //
  // Thread-safe.
  void WeakenDescriptorArrays(
      GlobalHandleVector<DescriptorArray> strong_descriptor_arrays);

  void NotifyBootstrapComplete();

  enum class OldGenerationExpansionNotificationOrigin {
    // Specifies that the notification is coming from the client heap.
    kFromClientHeap,
    // Specifies that the notification is done within the same heap.
    kFromSameHeap,
  };

  void NotifyOldGenerationExpansion(
      LocalHeap* local_heap, AllocationSpace space, MutablePageMetadata* chunk,
      OldGenerationExpansionNotificationOrigin =
          OldGenerationExpansionNotificationOrigin::kFromSameHeap);

  inline Address* NewSpaceAllocationTopAddress();
  inline Address* NewSpaceAllocationLimitAddress();
  inline Address* OldSpaceAllocationTopAddress();
  inline Address* OldSpaceAllocationLimitAddress();

  size_t NewSpaceSize();
  size_t NewSpaceCapacity() const;
  size_t NewSpaceTargetCapacity() const;

  // Move len non-weak tagged elements from src_slot to dst_slot of dst_object.
  // The source and destination memory ranges can overlap.
  V8_EXPORT_PRIVATE void MoveRange(Tagged<HeapObject> dst_object,
                                   ObjectSlot dst_slot, ObjectSlot src_slot,
                                   int len, WriteBarrierMode mode);

  // Copy len non-weak tagged elements from src_slot to dst_slot of dst_object.
  // The source and destination memory ranges must not overlap.
  template <typename TSlot>
  V8_EXPORT_PRIVATE void CopyRange(Tagged<HeapObject> dst_object,
                                   TSlot dst_slot, TSlot src_slot, int len,
                                   WriteBarrierMode mode);

  // Initialize a filler object to keep the ability to iterate over the heap
  // when introducing gaps within pages. This method will verify that no slots
  // are recorded in this free memory.
  V8_EXPORT_PRIVATE void CreateFillerObjectAt(
      Address addr, int size,
      ClearFreedMemoryMode clear_memory_mode =
          ClearFreedMemoryMode::kDontClearFreedMemory);

  // Initialize a filler object at a specific address. Unlike
  // `CreateFillerObjectAt` this method will not perform slot verification since
  // this would race on background threads.
  void CreateFillerObjectAtBackground(const WritableFreeSpace& free_space);

  bool CanMoveObjectStart(Tagged<HeapObject> object);

  bool IsImmovable(Tagged<HeapObject> object);

  V8_EXPORT_PRIVATE static bool IsLargeObject(Tagged<HeapObject> object);

  // Trim the given array from the left. Note that this relocates the object
  // start and hence is only valid if there is only a single reference to it.
  V8_EXPORT_PRIVATE Tagged<FixedArrayBase> LeftTrimFixedArray(
      Tagged<FixedArrayBase> obj, int elements_to_trim);

#define RIGHT_TRIMMABLE_ARRAY_LIST(V) \
  V(ArrayList)                        \
  V(ByteArray)                        \
  V(FixedArray)                       \
  V(FixedDoubleArray)                 \
  V(TransitionArray)                  \
  V(WeakFixedArray)

  // Trim the given array from the right.
  template <typename Array>
  void RightTrimArray(Tagged<Array> object, int new_capacity, int old_capacity);

  // Converts the given boolean condition to JavaScript boolean value.
  inline Tagged<Boolean> ToBoolean(bool condition);

  // Notify the heap that a context has been disposed. `has_dependent_context`
  // implies that a top-level context (no dependent contexts) has been disposed.
  V8_EXPORT_PRIVATE int NotifyContextDisposed(bool has_dependent_context);

  void set_native_contexts_list(Tagged<Object> object) {
    native_contexts_list_.store(object.ptr(), std::memory_order_release);
  }

  Tagged<Object> native_contexts_list() const {
    return Tagged<Object>(
        native_contexts_list_.load(std::memory_order_acquire));
  }

  void set_allocation_sites_list(Tagged<Object> object) {
    allocation_sites_list_ = object;
  }
  Tagged<Object> allocation_sites_list() { return allocation_sites_list_; }

  void set_dirty_js_finalization_registries_list(Tagged<Object> object) {
    dirty_js_finalization_registries_list_ = object;
  }
  Tagged<Object> dirty_js_finalization_registries_list() {
    return dirty_js_finalization_registries_list_;
  }
  void set_dirty_js_finalization_registries_list_tail(Tagged<Object> object) {
    dirty_js_finalization_registries_list_tail_ = object;
  }
  Tagged<Object> dirty_js_finalization_registries_list_tail() {
    return dirty_js_finalization_registries_list_tail_;
  }

  // Used in CreateAllocationSiteStub and the (de)serializer.
  Address allocation_sites_list_address() {
    return reinterpret_cast<Address>(&allocation_sites_list_);
  }

  // Traverse all the allocation_sites [nested_site and weak_next] in the list
  // and foreach call the visitor
  void ForeachAllocationSite(
      Tagged<Object> list,
      const std::function<void(Tagged<AllocationSite>)>& visitor);

  // Number of mark-sweeps.
  int ms_count() const { return ms_count_; }

  // Checks whether the given object is allowed to be migrated from its
  // current space into the given destination space. Used for debugging.
  bool AllowedToBeMigrated(Tagged<Map> map, Tagged<HeapObject> object,
                           AllocationSpace dest);

  void CheckHandleCount();

  // Print short heap statistics.
  void PrintShortHeapStatistics();

  // Print statistics of freelists of old_space:
  //  with v8_flags.trace_gc_freelists: summary of each FreeListCategory.
  //  with v8_flags.trace_gc_freelists_verbose: also prints the statistics of
  //  each FreeListCategory of each page.
  void PrintFreeListsStats();

  // Dump heap statistics in JSON format.
  void DumpJSONHeapStatistics(std::stringstream& stream);

  inline HeapState gc_state() const {
    return gc_state_.load(std::memory_order_relaxed);
  }
  V8_EXPORT_PRIVATE void SetGCState(HeapState state);
  bool IsTearingDown() const { return gc_state() == TEAR_DOWN; }
  bool IsInGC() const {
    // Load state only once and store it in local variable. Otherwise multiples
    // loads could return different states on background threads.
    HeapState state = gc_state();
    return state != NOT_IN_GC && state != TEAR_DOWN;
  }
  bool force_oom() const { return force_oom_; }

  bool ignore_local_gc_requests() const {
    return ignore_local_gc_requests_depth_ > 0;
  }

  bool IsAllocationObserverActive() const {
    return pause_allocation_observers_depth_ == 0;
  }

  bool IsGCWithMainThreadStack() const;

  // This method is only safe to use in a safepoint.
  bool IsGCWithStack() const;

  bool CanShortcutStringsDuringGC(GarbageCollector collector) const;

  // Performs GC after background allocation failure.
  void CollectGarbageForBackground(LocalHeap* local_heap);

  //
  // Support for the API.
  //

  void CreateReadOnlyApiObjects();
  void CreateMutableApiObjects();

  V8_EXPORT_PRIVATE void MemoryPressureNotification(
      v8::MemoryPressureLevel level, bool is_isolate_locked);
  void CheckMemoryPressure();

  V8_EXPORT_PRIVATE void AddNearHeapLimitCallback(v8::NearHeapLimitCallback,
                                                  void* data);
  V8_EXPORT_PRIVATE void RemoveNearHeapLimitCallback(
      v8::NearHeapLimitCallback callback, size_t heap_limit);
  V8_EXPORT_PRIVATE void AutomaticallyRestoreInitialHeapLimit(
      double threshold_percent);

  V8_EXPORT_PRIVATE void AppendArrayBufferExtension(
      Tagged<JSArrayBuffer> object, ArrayBufferExtension* extension);
  V8_EXPORT_PRIVATE void ResizeArrayBufferExtension(
      ArrayBufferExtension* extension, int64_t delta);
  void DetachArrayBufferExtension(ArrayBufferExtension* extension);

  IsolateSafepoint* safepoint() { return safepoint_.get(); }

  V8_EXPORT_PRIVATE double MonotonicallyIncreasingTimeInMs() const;

#if DEBUG
  void VerifyNewSpaceTop();
#endif  // DEBUG

  void RecordStats(HeapStats* stats, bool take_snapshot = false);

  bool MeasureMemory(std::unique_ptr<v8::MeasureMemoryDelegate> delegate,
                     v8::MeasureMemoryExecution execution);

  std::unique_ptr<v8::MeasureMemoryDelegate> CreateDefaultMeasureMemoryDelegate(
      v8::Local<v8::Context> context, v8::Local<v8::Promise::Resolver> promise,
      v8::MeasureMemoryMode mode);

  void VisitExternalResources(v8::ExternalResourceVisitor* visitor);

  void IncrementDeferredCounts(
      base::Vector<const v8::Isolate::UseCounterFeature> features);

  int NextScriptId();
  int NextDebuggingId();
  int NextStackTraceId();
  inline int GetNextTemplateSerialNumber();

  void SetSerializedObjects(Tagged<HeapObject> objects);
  void SetSerializedGlobalProxySizes(Tagged<FixedArray> sizes);

  void SetBasicBlockProfilingData(DirectHandle<ArrayList> list);

  // For post mortem debugging.
  void RememberUnmappedPage(Address page, bool compacted);

  uint64_t external_memory_hard_limit() {
    return external_memory_.low_since_mark_compact() +
           max_old_generation_size() / 2;
  }

  V8_INLINE uint64_t external_memory() const;
  V8_EXPORT_PRIVATE uint64_t external_memory_limit_for_interrupt();
  V8_EXPORT_PRIVATE uint64_t external_memory_soft_limit();
  uint64_t UpdateExternalMemory(int64_t delta);

  V8_EXPORT_PRIVATE size_t YoungArrayBufferBytes();
  V8_EXPORT_PRIVATE size_t OldArrayBufferBytes();

  uint64_t backing_store_bytes() const {
    return backing_store_bytes_.load(std::memory_order_relaxed);
  }

  void CompactWeakArrayLists();

  V8_EXPORT_PRIVATE void AddRetainedMaps(DirectHandle<NativeContext> context,
                                         GlobalHandleVector<Map> maps);

  // This event is triggered after object is moved to a new place.
  void OnMoveEvent(Tagged<HeapObject> source, Tagged<HeapObject> target,
                   int size_in_bytes);

  bool deserialization_complete() const { return deserialization_complete_; }

  // We can only invoke Safepoint() on the main thread local heap after
  // deserialization is complete. Before that, main_thread_local_heap_ might be
  // null.
  V8_INLINE bool CanSafepoint() const { return deserialization_complete(); }

  bool HasLowAllocationRate();
  bool HasHighFragmentation();

  void ActivateMemoryReducerIfNeeded();

  V8_EXPORT_PRIVATE bool ShouldOptimizeForMemoryUsage();

  // Returns true when GC should optimize for battery.
  V8_EXPORT_PRIVATE bool ShouldOptimizeForBattery() const;

  bool HighMemoryPressure() {
    return memory_pressure_level_.load(std::memory_order_relaxed) !=
           v8::MemoryPressureLevel::kNone;
  }

  bool CollectionRequested();

  void CheckCollectionRequested();

  void RestoreHeapLimit(size_t heap_limit) {
    // Do not set the limit lower than the live size + some slack.
    size_t min_limit = SizeOfObjects() + SizeOfObjects() / 4;
    SetOldGenerationAndGlobalMaximumSize(
        std::min(max_old_generation_size(), std::max(heap_limit, min_limit)));
  }

  // ===========================================================================
  // Initialization. ===========================================================
  // ===========================================================================

  void ConfigureHeap(const v8::ResourceConstraints& constraints,
                     v8::CppHeap* cpp_heap);
  void ConfigureHeapDefault();

  // Prepares the heap, setting up for deserialization.
  void SetUp(LocalHeap* main_thread_local_heap);

  // Sets read-only heap and space.
  void SetUpFromReadOnlyHeap(ReadOnlyHeap* ro_heap);

  void ReplaceReadOnlySpace(SharedReadOnlySpace* shared_ro_space);

  // Sets up the heap memory without creating any objects.
  void SetUpSpaces(LinearAllocationArea& new_allocation_info,
                   LinearAllocationArea& old_allocation_info);

  // Prepares the heap, setting up for deserialization.
  void InitializeMainThreadLocalHeap(LocalHeap* main_thread_local_heap);

  // (Re-)Initialize hash seed from flag or RNG.
  void InitializeHashSeed();

  // Invoked once for the process from V8::Initialize.
  static void InitializeOncePerProcess();

  // Bootstraps the object heap with the core set of objects required to run.
  // Returns whether it succeeded.
  bool CreateReadOnlyHeapObjects();
  bool CreateMutableHeapObjects();

  // Create ObjectStats if live_object_stats_ or dead_object_stats_ are nullptr.
  void CreateObjectStats();

  // Sets the TearDown state, so no new GC tasks get posted.
  void StartTearDown();

  // Destroys all data that might require the shared heap.
  void TearDownWithSharedHeap();

  // Destroys all memory allocated by the heap.
  void TearDown();

  // Returns whether SetUp has been called.
  bool HasBeenSetUp() const;

  // ===========================================================================
  // Getters for spaces. =======================================================
  // ===========================================================================

  V8_INLINE Address NewSpaceTop();
  V8_INLINE Address NewSpaceLimit();

  NewSpace* new_space() const { return new_space_; }
  inline PagedNewSpace* paged_new_space() const;
  inline SemiSpaceNewSpace* semi_space_new_space() const;
  OldSpace* old_space() const { return old_space_; }
  inline StickySpace* sticky_space() const;
  CodeSpace* code_space() const { return code_space_; }
  SharedSpace* shared_space() const { return shared_space_; }
  OldLargeObjectSpace* lo_space() const { return lo_space_; }
  CodeLargeObjectSpace* code_lo_space() const { return code_lo_space_; }
  SharedLargeObjectSpace* shared_lo_space() const { return shared_lo_space_; }
  NewLargeObjectSpace* new_lo_space() const { return new_lo_space_; }
  ReadOnlySpace* read_only_space() const { return read_only_space_; }
  TrustedSpace* trusted_space() const { return trusted_space_; }
  SharedTrustedSpace* shared_trusted_space() const {
    return shared_trusted_space_;
  }
  TrustedLargeObjectSpace* trusted_lo_space() const {
    return trusted_lo_space_;
  }
  SharedTrustedLargeObjectSpace* shared_trusted_lo_space() const {
    return shared_trusted_lo_space_;
  }

  PagedSpace* shared_allocation_space() const {
    return shared_allocation_space_;
  }
  OldLargeObjectSpace* shared_lo_allocation_space() const {
    return shared_lo_allocation_space_;
  }
  SharedTrustedSpace* shared_trusted_allocation_space() const {
    return shared_trusted_allocation_space_;
  }
  SharedTrustedLargeObjectSpace* shared_trusted_lo_allocation_space() const {
    return shared_trusted_lo_allocation_space_;
  }

  inline PagedSpace* paged_space(int idx) const;
  inline Space* space(int idx) const;

#ifdef V8_COMPRESS_POINTERS
  ExternalPointerTable::Space* young_external_pointer_space() {
    return &young_external_pointer_space_;
  }
  ExternalPointerTable::Space* old_external_pointer_space() {
    return &old_external_pointer_space_;
  }
  ExternalPointerTable::Space* read_only_external_pointer_space() {
    return &read_only_external_pointer_space_;
  }
  CppHeapPointerTable::Space* cpp_heap_pointer_space() {
    return &cpp_heap_pointer_space_;
  }
#endif  // V8_COMPRESS_POINTERS

#ifdef V8_ENABLE_SANDBOX
  TrustedPointerTable::Space* trusted_pointer_space() {
    return &trusted_pointer_space_;
  }

  CodePointerTable::Space* code_pointer_space() { return &code_pointer_space_; }

#endif  // V8_ENABLE_SANDBOX

#ifdef V8_ENABLE_LEAPTIERING
  JSDispatchTable::Space* js_dispatch_table_space() {
    return &js_dispatch_table_space_;
  }
#endif  // V8_ENABLE_LEAPTIERING

  // ===========================================================================
  // Getters to other components. ==============================================
  // ===========================================================================

  GCTracer* tracer() { return tracer_.get(); }

  MemoryAllocator* memory_allocator() { return memory_allocator_.get(); }
  const MemoryAllocator* memory_allocator() const {
    return memory_allocator_.get();
  }

  inline Isolate* isolate() const;

  // Check if we run on isolate's main thread.
  inline bool IsMainThread() const;

  MarkCompactCollector* mark_compact_collector() {
    return mark_compact_collector_.get();
  }

  MinorMarkSweepCollector* minor_mark_sweep_collector() {
    return minor_mark_sweep_collector_.get();
  }

  Sweeper* sweeper() { return sweeper_.get(); }

  ArrayBufferSweeper* array_buffer_sweeper() {
    return array_buffer_sweeper_.get();
  }

  // The potentially overreserved address space region reserved by the code
  // range if it exists or empty region otherwise.
  const base::AddressRegion& code_region();

  CodeRange* code_range() {
#ifdef V8_COMPRESS_POINTERS
    return code_range_;
#else
    return code_range_.get();
#endif
  }

  // The base of the code range if it exists or null address.
  inline Address code_range_base();

  LocalHeap* main_thread_local_heap() { return main_thread_local_heap_; }

  Heap* AsHeap() { return this; }

  // ===========================================================================
  // Root set access. ==========================================================
  // ===========================================================================

  // Shortcut to the roots
Prompt: 
```
这是目录为v8/src/heap/heap.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/heap.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_HEAP_HEAP_H_
#define V8_HEAP_HEAP_H_

#include <atomic>
#include <cmath>
#include <memory>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Clients of this interface shouldn't depend on lots of heap internals.
// Do not include anything from src/heap here!
#include "include/v8-callbacks.h"
#include "include/v8-embedder-heap.h"
#include "include/v8-internal.h"
#include "include/v8-isolate.h"
#include "src/base/atomic-utils.h"
#include "src/base/enum-set.h"
#include "src/base/platform/condition-variable.h"
#include "src/base/platform/mutex.h"
#include "src/base/small-vector.h"
#include "src/builtins/accessors.h"
#include "src/common/assert-scope.h"
#include "src/common/code-memory-access.h"
#include "src/common/globals.h"
#include "src/heap/allocation-observer.h"
#include "src/heap/allocation-result.h"
#include "src/heap/gc-callbacks.h"
#include "src/heap/heap-allocator.h"
#include "src/heap/marking-state.h"
#include "src/heap/minor-gc-job.h"
#include "src/heap/pretenuring-handler.h"
#include "src/heap/sweeper.h"
#include "src/init/heap-symbols.h"
#include "src/objects/allocation-site.h"
#include "src/objects/fixed-array.h"
#include "src/objects/hash-table.h"
#include "src/objects/heap-object.h"
#include "src/objects/js-array-buffer.h"
#include "src/objects/objects.h"
#include "src/objects/smi.h"
#include "src/objects/visitors.h"
#include "src/roots/roots.h"
#include "src/sandbox/code-pointer-table.h"
#include "src/sandbox/external-pointer-table.h"
#include "src/sandbox/js-dispatch-table.h"
#include "src/sandbox/trusted-pointer-table.h"
#include "src/utils/allocation.h"
#include "testing/gtest/include/gtest/gtest_prod.h"  // nogncheck

namespace cppgc::internal {
enum class HeapObjectNameForUnnamedObject : uint8_t;
class ClassNameAsHeapObjectNameScope;
}  // namespace cppgc::internal

namespace heap::base {
class Stack;
}  // namespace heap::base

namespace v8 {

namespace debug {
using OutOfMemoryCallback = void (*)(void* data);
}  // namespace debug

namespace internal {

namespace heap {
class HeapTester;
class TestMemoryAllocatorScope;
}  // namespace heap

class ArrayBufferCollector;
class ArrayBufferSweeper;
class BackingStore;
class MemoryChunkMetadata;
class Boolean;
class CodeLargeObjectSpace;
class CodeRange;
class CollectionBarrier;
class ConcurrentMarking;
class CppHeap;
class EphemeronRememberedSet;
class GCTracer;
class IncrementalMarking;
class IsolateSafepoint;
class HeapObjectAllocationTracker;
class HeapObjectsFilter;
class HeapStats;
class Isolate;
class JSArrayBuffer;
class JSFinalizationRegistry;
class JSPromise;
class LinearAllocationArea;
class LocalHeap;
class MemoryAllocator;
class MemoryBalancer;
class MutablePageMetadata;
class MemoryMeasurement;
class MemoryReducer;
class MinorMarkSweepCollector;
class NativeContext;
class NopRwxMemoryWriteScope;
class ObjectIterator;
class ObjectStats;
class PageMetadata;
class PagedSpace;
class PagedNewSpace;
class ReadOnlyHeap;
class RootVisitor;
class RwxMemoryWriteScope;
class SafepointScope;
class Scavenger;
class ScavengerCollector;
class SemiSpaceNewSpace;
class SharedLargeObjectSpace;
class SharedReadOnlySpace;
class SharedSpace;
class SharedTrustedLargeObjectSpace;
class SharedTrustedSpace;
class Space;
class StickySpace;
class StressScavengeObserver;
class TimedHistogram;
class TrustedLargeObjectSpace;
class TrustedRange;
class TrustedSpace;
class WeakObjectRetainer;

enum class ClearRecordedSlots { kYes, kNo };

enum class InvalidateRecordedSlots { kYes, kNo };

enum class InvalidateExternalPointerSlots { kYes, kNo };

enum class ClearFreedMemoryMode { kClearFreedMemory, kDontClearFreedMemory };

enum class SkipRoot {
  kExternalStringTable,
  kGlobalHandles,
  kTracedHandles,
  kOldGeneration,
  kStack,
  kMainThreadHandles,
  kUnserializable,
  kWeak,
  kConservativeStack,
  kReadOnlyBuiltins,
};

enum class EmbedderStackStateOrigin {
  kImplicitThroughTask,
  kExplicitInvocation,
};

class StrongRootsEntry final {
  explicit StrongRootsEntry(const char* label) : label(label) {}

  // Label that identifies the roots in tooling.
  const char* label;
  FullObjectSlot start;
  FullObjectSlot end;
  StrongRootsEntry* prev;
  StrongRootsEntry* next;

  friend class Heap;
};

// An alias for std::unordered_map<Tagged<HeapObject>, T> which also
// sets proper Hash and KeyEqual functions.
template <typename T>
using UnorderedHeapObjectMap =
    std::unordered_map<Tagged<HeapObject>, T, Object::Hasher,
                       Object::KeyEqualSafe>;

enum class GCFlag : uint8_t {
  kNoFlags = 0,
  kReduceMemoryFootprint = 1 << 0,
  // GCs that are forced, either through testing configurations (requiring
  // --expose-gc) or through DevTools (using LowMemoryNotification).
  kForced = 1 << 1,
};

using GCFlags = base::Flags<GCFlag, uint8_t>;
DEFINE_OPERATORS_FOR_FLAGS(GCFlags)

class Heap final {
 public:
  enum class HeapGrowingMode { kSlow, kConservative, kMinimal, kDefault };

  enum HeapState {
    NOT_IN_GC,
    SCAVENGE,
    MARK_COMPACT,
    MINOR_MARK_SWEEP,
    TEAR_DOWN
  };

  // Emits GC events for DevTools timeline.
  class V8_NODISCARD DevToolsTraceEventScope {
   public:
    DevToolsTraceEventScope(Heap* heap, const char* event_name,
                            const char* event_type);
    ~DevToolsTraceEventScope();

   private:
    Heap* heap_;
    const char* event_name_;
  };

  class ExternalMemoryAccounting {
   public:
    static constexpr size_t kExternalAllocationLimitForInterrupt = 128 * KB;

    uint64_t total() const { return total_.load(std::memory_order_relaxed); }
    uint64_t limit_for_interrupt() const {
      return limit_for_interrupt_.load(std::memory_order_relaxed);
    }
    uint64_t soft_limit() const {
      return low_since_mark_compact() + kExternalAllocationSoftLimit;
    }
    uint64_t low_since_mark_compact() const {
      return low_since_mark_compact_.load(std::memory_order_relaxed);
    }

    uint64_t UpdateAmount(int64_t delta) {
      const uint64_t amount_before =
          total_.fetch_add(delta, std::memory_order_relaxed);
      CHECK_GE(static_cast<int64_t>(amount_before), -delta);
      return amount_before + delta;
    }

    void UpdateLimitForInterrupt(uint64_t amount) {
      set_limit_for_interrupt(amount + kExternalAllocationLimitForInterrupt);
    }

    void UpdateLowSinceMarkCompact(uint64_t amount) {
      set_low_since_mark_compact(amount);
      UpdateLimitForInterrupt(amount);
    }

    uint64_t AllocatedSinceMarkCompact() const {
      uint64_t total_bytes = total();
      uint64_t low_since_mark_compact_bytes = low_since_mark_compact();

      if (total_bytes <= low_since_mark_compact_bytes) {
        return 0;
      }
      return total_bytes - low_since_mark_compact_bytes;
    }

   private:
    void set_total(uint64_t value) {
      total_.store(value, std::memory_order_relaxed);
    }

    void set_limit_for_interrupt(uint64_t value) {
      limit_for_interrupt_.store(value, std::memory_order_relaxed);
    }

    void set_low_since_mark_compact(uint64_t value) {
      low_since_mark_compact_.store(value, std::memory_order_relaxed);
    }

    // The amount of external memory registered through the API.
    std::atomic<uint64_t> total_{0};

    // The limit when to trigger memory pressure from the API.
    std::atomic<uint64_t> limit_for_interrupt_{
        kExternalAllocationLimitForInterrupt};

    // Caches the amount of external memory registered at the last MC.
    std::atomic<uint64_t> low_since_mark_compact_{0};
  };

  // Taking this mutex prevents the GC from entering a phase that relocates
  // object references.
  base::Mutex* relocation_mutex() { return &relocation_mutex_; }

  // Support for context snapshots.  After calling this we have a linear
  // space to write objects in each space.
  struct Chunk {
    uint32_t size;
    Address start;
    Address end;
  };
  using Reservation = std::vector<Chunk>;

#if V8_OS_ANDROID
  // Don't apply pointer multiplier on Android since it has no swap space and
  // should instead adapt it's heap size based on available physical memory.
  static const int kPointerMultiplier = 1;
  static const int kHeapLimitMultiplier = 1;
#else
  static const int kPointerMultiplier = kTaggedSize / 4;
  // The heap limit needs to be computed based on the system pointer size
  // because we want a pointer-compressed heap to have larger limit than
  // an ordinary 32-bit which that is constrained by 2GB virtual address space.
  static const int kHeapLimitMultiplier = kSystemPointerSize / 4;
#endif

  static const size_t kMaxInitialOldGenerationSize =
      256 * MB * kHeapLimitMultiplier;

  // These constants control heap configuration based on the physical memory.
  static constexpr size_t kPhysicalMemoryToOldGenerationRatio = 4;
  static constexpr size_t kOldGenerationLowMemory =
      128 * MB * kHeapLimitMultiplier;
  static constexpr size_t kNewLargeObjectSpaceToSemiSpaceRatio = 1;

  static const int kTraceRingBufferSize = 512;
  static const int kStacktraceBufferSize = 512;

  // The minimum size of a HeapObject on the heap.
  static const int kMinObjectSizeInTaggedWords = 2;

  static size_t DefaultMinSemiSpaceSize();
  V8_EXPORT_PRIVATE static size_t DefaultMaxSemiSpaceSize();
  // Young generation size is the same for compressed heaps and 32-bit heaps.
  static size_t OldGenerationToSemiSpaceRatio();
  static size_t OldGenerationToSemiSpaceRatioLowMemory();

  // Calculates the maximum amount of filler that could be required by the
  // given alignment.
  V8_EXPORT_PRIVATE static int GetMaximumFillToAlign(
      AllocationAlignment alignment);
  // Calculates the actual amount of filler required for a given address at the
  // given alignment.
  V8_EXPORT_PRIVATE static int GetFillToAlign(Address address,
                                              AllocationAlignment alignment);

  // Returns the size of the initial area of a code-range, which is marked
  // writable and reserved to contain unwind information.
  static size_t GetCodeRangeReservedAreaSize();

  [[noreturn]] V8_EXPORT_PRIVATE void FatalProcessOutOfMemory(
      const char* location);

  // Checks whether the space is valid.
  static bool IsValidAllocationSpace(AllocationSpace space);

  static inline bool IsYoungGenerationCollector(GarbageCollector collector) {
    return collector == GarbageCollector::SCAVENGER ||
           collector == GarbageCollector::MINOR_MARK_SWEEPER;
  }

  V8_EXPORT_PRIVATE static bool IsFreeSpaceValid(FreeSpace object);

  static inline GarbageCollector YoungGenerationCollector() {
    return (v8_flags.minor_ms) ? GarbageCollector::MINOR_MARK_SWEEPER
                               : GarbageCollector::SCAVENGER;
  }

  // Copy block of memory from src to dst. Size of block should be aligned
  // by pointer size.
  static inline void CopyBlock(Address dst, Address src, int byte_size);

  EphemeronRememberedSet* ephemeron_remembered_set() {
    return ephemeron_remembered_set_.get();
  }

  // Notifies the heap that is ok to start marking or other activities that
  // should not happen during deserialization.
  void NotifyDeserializationComplete();

  // Weakens StrongDescriptorArray objects into regular DescriptorArray objects.
  //
  // Thread-safe.
  void WeakenDescriptorArrays(
      GlobalHandleVector<DescriptorArray> strong_descriptor_arrays);

  void NotifyBootstrapComplete();

  enum class OldGenerationExpansionNotificationOrigin {
    // Specifies that the notification is coming from the client heap.
    kFromClientHeap,
    // Specifies that the notification is done within the same heap.
    kFromSameHeap,
  };

  void NotifyOldGenerationExpansion(
      LocalHeap* local_heap, AllocationSpace space, MutablePageMetadata* chunk,
      OldGenerationExpansionNotificationOrigin =
          OldGenerationExpansionNotificationOrigin::kFromSameHeap);

  inline Address* NewSpaceAllocationTopAddress();
  inline Address* NewSpaceAllocationLimitAddress();
  inline Address* OldSpaceAllocationTopAddress();
  inline Address* OldSpaceAllocationLimitAddress();

  size_t NewSpaceSize();
  size_t NewSpaceCapacity() const;
  size_t NewSpaceTargetCapacity() const;

  // Move len non-weak tagged elements from src_slot to dst_slot of dst_object.
  // The source and destination memory ranges can overlap.
  V8_EXPORT_PRIVATE void MoveRange(Tagged<HeapObject> dst_object,
                                   ObjectSlot dst_slot, ObjectSlot src_slot,
                                   int len, WriteBarrierMode mode);

  // Copy len non-weak tagged elements from src_slot to dst_slot of dst_object.
  // The source and destination memory ranges must not overlap.
  template <typename TSlot>
  V8_EXPORT_PRIVATE void CopyRange(Tagged<HeapObject> dst_object,
                                   TSlot dst_slot, TSlot src_slot, int len,
                                   WriteBarrierMode mode);

  // Initialize a filler object to keep the ability to iterate over the heap
  // when introducing gaps within pages. This method will verify that no slots
  // are recorded in this free memory.
  V8_EXPORT_PRIVATE void CreateFillerObjectAt(
      Address addr, int size,
      ClearFreedMemoryMode clear_memory_mode =
          ClearFreedMemoryMode::kDontClearFreedMemory);

  // Initialize a filler object at a specific address. Unlike
  // `CreateFillerObjectAt` this method will not perform slot verification since
  // this would race on background threads.
  void CreateFillerObjectAtBackground(const WritableFreeSpace& free_space);

  bool CanMoveObjectStart(Tagged<HeapObject> object);

  bool IsImmovable(Tagged<HeapObject> object);

  V8_EXPORT_PRIVATE static bool IsLargeObject(Tagged<HeapObject> object);

  // Trim the given array from the left. Note that this relocates the object
  // start and hence is only valid if there is only a single reference to it.
  V8_EXPORT_PRIVATE Tagged<FixedArrayBase> LeftTrimFixedArray(
      Tagged<FixedArrayBase> obj, int elements_to_trim);

#define RIGHT_TRIMMABLE_ARRAY_LIST(V) \
  V(ArrayList)                        \
  V(ByteArray)                        \
  V(FixedArray)                       \
  V(FixedDoubleArray)                 \
  V(TransitionArray)                  \
  V(WeakFixedArray)

  // Trim the given array from the right.
  template <typename Array>
  void RightTrimArray(Tagged<Array> object, int new_capacity, int old_capacity);

  // Converts the given boolean condition to JavaScript boolean value.
  inline Tagged<Boolean> ToBoolean(bool condition);

  // Notify the heap that a context has been disposed. `has_dependent_context`
  // implies that a top-level context (no dependent contexts) has been disposed.
  V8_EXPORT_PRIVATE int NotifyContextDisposed(bool has_dependent_context);

  void set_native_contexts_list(Tagged<Object> object) {
    native_contexts_list_.store(object.ptr(), std::memory_order_release);
  }

  Tagged<Object> native_contexts_list() const {
    return Tagged<Object>(
        native_contexts_list_.load(std::memory_order_acquire));
  }

  void set_allocation_sites_list(Tagged<Object> object) {
    allocation_sites_list_ = object;
  }
  Tagged<Object> allocation_sites_list() { return allocation_sites_list_; }

  void set_dirty_js_finalization_registries_list(Tagged<Object> object) {
    dirty_js_finalization_registries_list_ = object;
  }
  Tagged<Object> dirty_js_finalization_registries_list() {
    return dirty_js_finalization_registries_list_;
  }
  void set_dirty_js_finalization_registries_list_tail(Tagged<Object> object) {
    dirty_js_finalization_registries_list_tail_ = object;
  }
  Tagged<Object> dirty_js_finalization_registries_list_tail() {
    return dirty_js_finalization_registries_list_tail_;
  }

  // Used in CreateAllocationSiteStub and the (de)serializer.
  Address allocation_sites_list_address() {
    return reinterpret_cast<Address>(&allocation_sites_list_);
  }

  // Traverse all the allocation_sites [nested_site and weak_next] in the list
  // and foreach call the visitor
  void ForeachAllocationSite(
      Tagged<Object> list,
      const std::function<void(Tagged<AllocationSite>)>& visitor);

  // Number of mark-sweeps.
  int ms_count() const { return ms_count_; }

  // Checks whether the given object is allowed to be migrated from its
  // current space into the given destination space. Used for debugging.
  bool AllowedToBeMigrated(Tagged<Map> map, Tagged<HeapObject> object,
                           AllocationSpace dest);

  void CheckHandleCount();

  // Print short heap statistics.
  void PrintShortHeapStatistics();

  // Print statistics of freelists of old_space:
  //  with v8_flags.trace_gc_freelists: summary of each FreeListCategory.
  //  with v8_flags.trace_gc_freelists_verbose: also prints the statistics of
  //  each FreeListCategory of each page.
  void PrintFreeListsStats();

  // Dump heap statistics in JSON format.
  void DumpJSONHeapStatistics(std::stringstream& stream);

  inline HeapState gc_state() const {
    return gc_state_.load(std::memory_order_relaxed);
  }
  V8_EXPORT_PRIVATE void SetGCState(HeapState state);
  bool IsTearingDown() const { return gc_state() == TEAR_DOWN; }
  bool IsInGC() const {
    // Load state only once and store it in local variable. Otherwise multiples
    // loads could return different states on background threads.
    HeapState state = gc_state();
    return state != NOT_IN_GC && state != TEAR_DOWN;
  }
  bool force_oom() const { return force_oom_; }

  bool ignore_local_gc_requests() const {
    return ignore_local_gc_requests_depth_ > 0;
  }

  bool IsAllocationObserverActive() const {
    return pause_allocation_observers_depth_ == 0;
  }

  bool IsGCWithMainThreadStack() const;

  // This method is only safe to use in a safepoint.
  bool IsGCWithStack() const;

  bool CanShortcutStringsDuringGC(GarbageCollector collector) const;

  // Performs GC after background allocation failure.
  void CollectGarbageForBackground(LocalHeap* local_heap);

  //
  // Support for the API.
  //

  void CreateReadOnlyApiObjects();
  void CreateMutableApiObjects();

  V8_EXPORT_PRIVATE void MemoryPressureNotification(
      v8::MemoryPressureLevel level, bool is_isolate_locked);
  void CheckMemoryPressure();

  V8_EXPORT_PRIVATE void AddNearHeapLimitCallback(v8::NearHeapLimitCallback,
                                                  void* data);
  V8_EXPORT_PRIVATE void RemoveNearHeapLimitCallback(
      v8::NearHeapLimitCallback callback, size_t heap_limit);
  V8_EXPORT_PRIVATE void AutomaticallyRestoreInitialHeapLimit(
      double threshold_percent);

  V8_EXPORT_PRIVATE void AppendArrayBufferExtension(
      Tagged<JSArrayBuffer> object, ArrayBufferExtension* extension);
  V8_EXPORT_PRIVATE void ResizeArrayBufferExtension(
      ArrayBufferExtension* extension, int64_t delta);
  void DetachArrayBufferExtension(ArrayBufferExtension* extension);

  IsolateSafepoint* safepoint() { return safepoint_.get(); }

  V8_EXPORT_PRIVATE double MonotonicallyIncreasingTimeInMs() const;

#if DEBUG
  void VerifyNewSpaceTop();
#endif  // DEBUG

  void RecordStats(HeapStats* stats, bool take_snapshot = false);

  bool MeasureMemory(std::unique_ptr<v8::MeasureMemoryDelegate> delegate,
                     v8::MeasureMemoryExecution execution);

  std::unique_ptr<v8::MeasureMemoryDelegate> CreateDefaultMeasureMemoryDelegate(
      v8::Local<v8::Context> context, v8::Local<v8::Promise::Resolver> promise,
      v8::MeasureMemoryMode mode);

  void VisitExternalResources(v8::ExternalResourceVisitor* visitor);

  void IncrementDeferredCounts(
      base::Vector<const v8::Isolate::UseCounterFeature> features);

  int NextScriptId();
  int NextDebuggingId();
  int NextStackTraceId();
  inline int GetNextTemplateSerialNumber();

  void SetSerializedObjects(Tagged<HeapObject> objects);
  void SetSerializedGlobalProxySizes(Tagged<FixedArray> sizes);

  void SetBasicBlockProfilingData(DirectHandle<ArrayList> list);

  // For post mortem debugging.
  void RememberUnmappedPage(Address page, bool compacted);

  uint64_t external_memory_hard_limit() {
    return external_memory_.low_since_mark_compact() +
           max_old_generation_size() / 2;
  }

  V8_INLINE uint64_t external_memory() const;
  V8_EXPORT_PRIVATE uint64_t external_memory_limit_for_interrupt();
  V8_EXPORT_PRIVATE uint64_t external_memory_soft_limit();
  uint64_t UpdateExternalMemory(int64_t delta);

  V8_EXPORT_PRIVATE size_t YoungArrayBufferBytes();
  V8_EXPORT_PRIVATE size_t OldArrayBufferBytes();

  uint64_t backing_store_bytes() const {
    return backing_store_bytes_.load(std::memory_order_relaxed);
  }

  void CompactWeakArrayLists();

  V8_EXPORT_PRIVATE void AddRetainedMaps(DirectHandle<NativeContext> context,
                                         GlobalHandleVector<Map> maps);

  // This event is triggered after object is moved to a new place.
  void OnMoveEvent(Tagged<HeapObject> source, Tagged<HeapObject> target,
                   int size_in_bytes);

  bool deserialization_complete() const { return deserialization_complete_; }

  // We can only invoke Safepoint() on the main thread local heap after
  // deserialization is complete. Before that, main_thread_local_heap_ might be
  // null.
  V8_INLINE bool CanSafepoint() const { return deserialization_complete(); }

  bool HasLowAllocationRate();
  bool HasHighFragmentation();

  void ActivateMemoryReducerIfNeeded();

  V8_EXPORT_PRIVATE bool ShouldOptimizeForMemoryUsage();

  // Returns true when GC should optimize for battery.
  V8_EXPORT_PRIVATE bool ShouldOptimizeForBattery() const;

  bool HighMemoryPressure() {
    return memory_pressure_level_.load(std::memory_order_relaxed) !=
           v8::MemoryPressureLevel::kNone;
  }

  bool CollectionRequested();

  void CheckCollectionRequested();

  void RestoreHeapLimit(size_t heap_limit) {
    // Do not set the limit lower than the live size + some slack.
    size_t min_limit = SizeOfObjects() + SizeOfObjects() / 4;
    SetOldGenerationAndGlobalMaximumSize(
        std::min(max_old_generation_size(), std::max(heap_limit, min_limit)));
  }

  // ===========================================================================
  // Initialization. ===========================================================
  // ===========================================================================

  void ConfigureHeap(const v8::ResourceConstraints& constraints,
                     v8::CppHeap* cpp_heap);
  void ConfigureHeapDefault();

  // Prepares the heap, setting up for deserialization.
  void SetUp(LocalHeap* main_thread_local_heap);

  // Sets read-only heap and space.
  void SetUpFromReadOnlyHeap(ReadOnlyHeap* ro_heap);

  void ReplaceReadOnlySpace(SharedReadOnlySpace* shared_ro_space);

  // Sets up the heap memory without creating any objects.
  void SetUpSpaces(LinearAllocationArea& new_allocation_info,
                   LinearAllocationArea& old_allocation_info);

  // Prepares the heap, setting up for deserialization.
  void InitializeMainThreadLocalHeap(LocalHeap* main_thread_local_heap);

  // (Re-)Initialize hash seed from flag or RNG.
  void InitializeHashSeed();

  // Invoked once for the process from V8::Initialize.
  static void InitializeOncePerProcess();

  // Bootstraps the object heap with the core set of objects required to run.
  // Returns whether it succeeded.
  bool CreateReadOnlyHeapObjects();
  bool CreateMutableHeapObjects();

  // Create ObjectStats if live_object_stats_ or dead_object_stats_ are nullptr.
  void CreateObjectStats();

  // Sets the TearDown state, so no new GC tasks get posted.
  void StartTearDown();

  // Destroys all data that might require the shared heap.
  void TearDownWithSharedHeap();

  // Destroys all memory allocated by the heap.
  void TearDown();

  // Returns whether SetUp has been called.
  bool HasBeenSetUp() const;

  // ===========================================================================
  // Getters for spaces. =======================================================
  // ===========================================================================

  V8_INLINE Address NewSpaceTop();
  V8_INLINE Address NewSpaceLimit();

  NewSpace* new_space() const { return new_space_; }
  inline PagedNewSpace* paged_new_space() const;
  inline SemiSpaceNewSpace* semi_space_new_space() const;
  OldSpace* old_space() const { return old_space_; }
  inline StickySpace* sticky_space() const;
  CodeSpace* code_space() const { return code_space_; }
  SharedSpace* shared_space() const { return shared_space_; }
  OldLargeObjectSpace* lo_space() const { return lo_space_; }
  CodeLargeObjectSpace* code_lo_space() const { return code_lo_space_; }
  SharedLargeObjectSpace* shared_lo_space() const { return shared_lo_space_; }
  NewLargeObjectSpace* new_lo_space() const { return new_lo_space_; }
  ReadOnlySpace* read_only_space() const { return read_only_space_; }
  TrustedSpace* trusted_space() const { return trusted_space_; }
  SharedTrustedSpace* shared_trusted_space() const {
    return shared_trusted_space_;
  }
  TrustedLargeObjectSpace* trusted_lo_space() const {
    return trusted_lo_space_;
  }
  SharedTrustedLargeObjectSpace* shared_trusted_lo_space() const {
    return shared_trusted_lo_space_;
  }

  PagedSpace* shared_allocation_space() const {
    return shared_allocation_space_;
  }
  OldLargeObjectSpace* shared_lo_allocation_space() const {
    return shared_lo_allocation_space_;
  }
  SharedTrustedSpace* shared_trusted_allocation_space() const {
    return shared_trusted_allocation_space_;
  }
  SharedTrustedLargeObjectSpace* shared_trusted_lo_allocation_space() const {
    return shared_trusted_lo_allocation_space_;
  }

  inline PagedSpace* paged_space(int idx) const;
  inline Space* space(int idx) const;

#ifdef V8_COMPRESS_POINTERS
  ExternalPointerTable::Space* young_external_pointer_space() {
    return &young_external_pointer_space_;
  }
  ExternalPointerTable::Space* old_external_pointer_space() {
    return &old_external_pointer_space_;
  }
  ExternalPointerTable::Space* read_only_external_pointer_space() {
    return &read_only_external_pointer_space_;
  }
  CppHeapPointerTable::Space* cpp_heap_pointer_space() {
    return &cpp_heap_pointer_space_;
  }
#endif  // V8_COMPRESS_POINTERS

#ifdef V8_ENABLE_SANDBOX
  TrustedPointerTable::Space* trusted_pointer_space() {
    return &trusted_pointer_space_;
  }

  CodePointerTable::Space* code_pointer_space() { return &code_pointer_space_; }

#endif  // V8_ENABLE_SANDBOX

#ifdef V8_ENABLE_LEAPTIERING
  JSDispatchTable::Space* js_dispatch_table_space() {
    return &js_dispatch_table_space_;
  }
#endif  // V8_ENABLE_LEAPTIERING

  // ===========================================================================
  // Getters to other components. ==============================================
  // ===========================================================================

  GCTracer* tracer() { return tracer_.get(); }

  MemoryAllocator* memory_allocator() { return memory_allocator_.get(); }
  const MemoryAllocator* memory_allocator() const {
    return memory_allocator_.get();
  }

  inline Isolate* isolate() const;

  // Check if we run on isolate's main thread.
  inline bool IsMainThread() const;

  MarkCompactCollector* mark_compact_collector() {
    return mark_compact_collector_.get();
  }

  MinorMarkSweepCollector* minor_mark_sweep_collector() {
    return minor_mark_sweep_collector_.get();
  }

  Sweeper* sweeper() { return sweeper_.get(); }

  ArrayBufferSweeper* array_buffer_sweeper() {
    return array_buffer_sweeper_.get();
  }

  // The potentially overreserved address space region reserved by the code
  // range if it exists or empty region otherwise.
  const base::AddressRegion& code_region();

  CodeRange* code_range() {
#ifdef V8_COMPRESS_POINTERS
    return code_range_;
#else
    return code_range_.get();
#endif
  }

  // The base of the code range if it exists or null address.
  inline Address code_range_base();

  LocalHeap* main_thread_local_heap() { return main_thread_local_heap_; }

  Heap* AsHeap() { return this; }

  // ===========================================================================
  // Root set access. ==========================================================
  // ===========================================================================

  // Shortcut to the roots table stored in the Isolate.
  V8_INLINE RootsTable& roots_table();

// Heap root getters.
#define ROOT_ACCESSOR(type, name, CamelName) inline Tagged<type> name();
  MUTABLE_ROOT_LIST(ROOT_ACCESSOR)
#undef ROOT_ACCESSOR

  V8_INLINE Tagged<FixedArray> single_character_string_table();

  V8_INLINE void SetRootMaterializedObjects(Tagged<FixedArray> objects);
  V8_INLINE void SetRootScriptList(Tagged<Object> value);
  V8_INLINE void SetRootNoScriptSharedFunctionInfos(Tagged<Object> value);
  V8_INLINE void SetMessageListeners(Tagged<ArrayList> value);
  V8_INLINE void SetFunctionsMarkedForManualOptimization(
      Tagged<Object> bytecode);

#if V8_ENABLE_WEBASSEMBLY
  V8_INLINE void SetWasmCanonicalRttsAndJSToWasmWrappers(
      Tagged<WeakFixedArray> rtts, Tagged<WeakFixedArray> js_to_wasm_wrappers);
#endif

  StrongRootsEntry* RegisterStrongRoots(const char* label, FullObjectSlot start,
                                        FullObjectSlot end);
  void UnregisterStrongRoots(StrongRootsEntry* entry);
  void UpdateStrongRoots(StrongRootsEntry* entry, FullObjectSlot start,
                         FullObjectSlot end);

  void SetBuiltinsConstantsTable(Tagged<FixedArray> cache);
  void SetDetachedContexts(Tagged<WeakArrayList> detached_contexts);

  void EnqueueDirtyJSFinalizationRegistry(
      Tagged<JSFinalizationRegistry> finalization_registry,
      std::function<void(Tagged<HeapObject> object, ObjectSlot slot,
                         Tagged<Object> target)>
          gc_notify_updated_slot);

  MaybeHandle<JSFinalizationRegistry> DequeueDirtyJSFinalizationRegistry();

  // Called from Heap::NotifyContextDisposed to remove all
  // FinalizationRegistries with {context} from the dirty list when the context
  // e.g. navigates away or is detached. If the dirty list is empty afterwards,
  // the cleanup task is aborted if needed.
  void RemoveDirtyFinalizationRegistriesOnContext(
      Tagged<NativeContext> context);

  bool HasDirtyJSFinalizationRegistries();

  void PostFinalizationRegistryCleanupTaskIfNeeded();

  void set_is_finalization_registry_cleanup_task_posted(bool posted) {
    is_finalization_registry_cleanup_task_posted_ = posted;
  }

  bool is_finalization_registry_cleanup_task_posted() {
    return is_finalization_registry_cleanup_task_posted_;
  }

  V8_EXPORT_PRIVATE void KeepDuringJob(DirectHandle<HeapObject> target);
  void ClearKeptObjects();

  // ===========================================================================
  // Inline allocation. ========================================================
  // ===========================================================================

  // Switch whether inline bump-pointer allocation should be used.
  V8_EXPORT_PRIVATE void EnableInlineAllocation();
  V8_EXPORT_PRIVATE void DisableInlineAllocation();

  // ===========================================================================
  // Methods triggering GCs. ===================================================
  // ===========================================================================

  // Performs garbage collection operation.
  // Returns whether there is a chance that another major GC could
  // collect more garbage.
  V8_EXPORT_PRIVATE void CollectGarbage(
      AllocationSpace space, GarbageCollectionReason gc_reason,
      const GCCallbackFlags gc_callback_flags = kNoGCCallbackFlags);

  // Performs a full garbage collection.
  V8_EXPORT_PRIVATE void CollectAllGarbage(
      GCFlags gc_flags, GarbageCollectionReason gc_reason,
      const GCCallbackFlags gc_callback_flags = kNoGCCallbackFlags);

  // Last hope garbage collection. Will try to free as much memory as possible
  // with multiple rounds of garbage collection.
  V8_EXPORT_PRIVATE void CollectAllAvailableGarbage(
      GarbageCollectionReason gc_reason);

  // Precise garbage collection that potentially finalizes already running
  // incremental marking before performing an atomic garbage collection.
  // Only use if absolutely necessary or in tests to avoid floating garbage!
  V8_EXPORT_PRIVATE void PreciseCollectAllGarbage(
      GCFlags gc_flags, GarbageCollectionReason gc_reason,
      const GCCallbackFlags gc_
"""


```