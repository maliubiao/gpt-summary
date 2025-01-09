Response:
Let's break down the thought process to analyze the provided C++ code snippet.

**1. Initial Understanding of the Request:**

The request asks for a functional summary of the `v8/src/heap/sweeper.cc` file. Key constraints and points to address include:

* **Core Functionality:** What does this code *do*?
* **Torque Connection:** Is it related to Torque (indicated by a `.tq` extension)?  The file ends with `.cc`, so the answer is immediately no.
* **JavaScript Relation:**  How does this low-level C++ relate to higher-level JavaScript concepts? Examples are needed.
* **Logic Inference:**  Are there any clear input/output scenarios within the code itself?
* **Common Programming Errors:** What typical developer mistakes might this code prevent or handle?
* **Summary:**  A concise overall description of the file's purpose.

**2. Code Examination - High Level:**

The first step is to skim the code and identify key classes, functions, and data structures. The `#include` directives give a good initial overview of the modules this code interacts with:

* **`src/heap/*`:**  Strongly indicates this code is part of V8's garbage collection system. Terms like "heap," "sweeper," "page," "mark," "compact," "free-list" are prominent.
* **Concurrency Primitives:**  `<atomic>`, `std::mutex`, `src/base/atomic-utils.h` suggest this code handles concurrent operations.
* **`src/execution/vm-state-inl.h`:** Hints at interaction with the V8 virtual machine's execution state.
* **`src/flags/flags.h`:**  Indicates the behavior of this code can be influenced by command-line flags.
* **`src/objects/*`:** Shows interaction with V8's object model.

**3. Code Examination - Class Structure and Key Functions:**

Next, focus on the main class, `Sweeper`. Notice its nested classes: `ConcurrentMajorSweeper`, `ConcurrentMinorSweeper`, `MajorSweeperJob`, `MinorSweeperJob`, and `LocalSweeper`. This suggests a division of labor, likely between main thread operations and background/concurrent tasks.

* **`ConcurrentMajorSweeper` & `ConcurrentMinorSweeper`:** These classes clearly perform sweeping in parallel. They interact with `GetSweepingPageSafe` and `ParallelSweepPage`.
* **`MajorSweeperJob` & `MinorSweeperJob`:** These are `JobTask` subclasses, confirming that sweeping is done using V8's job scheduling mechanism. They delegate work to the concurrent sweepers.
* **`LocalSweeper`:**  Contains the core sweeping logic (`ParallelSweepPage`, `RawSweep`).

**4. Identifying Core Functionality - The "Sweep":**

The term "sweep" is central. The code iterates through memory pages and performs actions on them. The goal of sweeping in a garbage collector is to reclaim memory occupied by objects that are no longer reachable.

* **`GetSweepingPageSafe`:** This function is crucial. It likely retrieves pages that need to be swept. The "Safe" suffix probably indicates thread-safety.
* **`ParallelSweepPage`:** This is where the actual sweeping of a single page occurs. It takes a `PageMetadata` and an `AllocationSpace`.
* **`RawSweep`:** This is likely the low-level function that iterates through objects on a page and reclaims space.
* **`AddSweptPage`:**  After sweeping, pages are added to a list of swept pages.

**5. Connecting to JavaScript:**

How does this relate to JavaScript?  Garbage collection is fundamental to JavaScript's memory management. When JavaScript objects are no longer needed, the garbage collector reclaims their memory. The `Sweeper` class is a component of that process.

* **Example:**  Creating objects that become unreachable (e.g., local variables in a function that finishes) will eventually lead to the sweeper being invoked to free the memory they occupied.

**6. Logic Inference:**

Look for conditional logic and state management.

* **`SweepingState`:** This template class manages the state of major and minor sweeping (in progress, starting, stopping).
* **`v8_flags.concurrent_sweeping`:**  The code checks this flag, indicating that concurrent sweeping is an optional feature.
* **`ShouldYield()`:** Used by the `JobDelegate`, indicating a mechanism for cooperative multitasking.

**7. Common Programming Errors:**

Consider what problems this code helps solve at the JavaScript level.

* **Memory Leaks:** The primary goal of garbage collection is to prevent memory leaks, a common issue in languages without automatic memory management. The sweeper is crucial for identifying and reclaiming unused memory.

**8. Torque:**

The request specifically asks about Torque. The file extension (`.cc`) immediately indicates it's standard C++, not Torque (`.tq`).

**9. Structuring the Output:**

Organize the findings into the requested sections:

* **Functionality:** Clearly state the primary purpose (reclaiming memory).
* **Torque:**  Directly address the file extension.
* **JavaScript Relation:** Provide concrete examples of JavaScript code that would trigger the sweeper.
* **Logic Inference:** Present a simplified scenario with assumed input and output.
* **Common Errors:** Explain how the sweeper helps avoid memory leaks.
* **Summary:** Offer a brief concluding statement.

**Self-Correction/Refinement:**

* **Initial thought:** Maybe the sweeping is just about marking objects as free.
* **Correction:** The code mentions "free-list" and zapping. Sweeping likely involves actually modifying the memory layout to make the space available again.
* **Initial thought:** The JavaScript relation is too abstract.
* **Refinement:** Provide a specific code example showing object creation and potential garbage collection.

By following this systematic examination and iterative refinement, we arrive at a comprehensive and accurate description of the `v8/src/heap/sweeper.cc` file's functionality.
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/sweeper.h"

#include <algorithm>
#include <atomic>
#include <memory>
#include <optional>
#include <vector>

#include "src/base/atomic-utils.h"
#include "src/base/logging.h"
#include "src/common/globals.h"
#include "src/execution/vm-state-inl.h"
#include "src/flags/flags.h"
#include "src/heap/base/active-system-pages.h"
#include "src/heap/ephemeron-remembered-set.h"
#include "src/heap/free-list-inl.h"
#include "src/heap/gc-tracer-inl.h"
#include "src/heap/gc-tracer.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap.h"
#include "src/heap/live-object-range-inl.h"
#include "src/heap/mark-compact-inl.h"
#include "src/heap/mark-compact.h"
#include "src/heap/marking-inl.h"
#include "src/heap/marking-state.h"
#include "src/heap/memory-allocator.h"
#include "src/heap/memory-chunk-layout.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/heap/new-spaces.h"
#include "src/heap/page-metadata-inl.h"
#include "src/heap/paged-spaces.h"
#include "src/heap/pretenuring-handler-inl.h"
#include "src/heap/pretenuring-handler.h"
#include "src/heap/remembered-set.h"
#include "src/heap/slot-set.h"
#include "src/heap/zapping.h"
#include "src/objects/hash-table.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/map.h"
#include "src/objects/objects-inl.h"

namespace v8 {
namespace internal {

class Sweeper::ConcurrentMajorSweeper final {
 public:
  explicit ConcurrentMajorSweeper(Sweeper* sweeper)
      : sweeper_(sweeper), local_sweeper_(sweeper_) {}

  bool ConcurrentSweepSpace(AllocationSpace identity, JobDelegate* delegate) {
    DCHECK(IsValidSweepingSpace(identity));
    DCHECK_NE(NEW_SPACE, identity);
    while (!delegate->ShouldYield()) {
      PageMetadata* page = sweeper_->GetSweepingPageSafe(identity);
      if (page == nullptr) return true;
      local_sweeper_.ParallelSweepPage(page, identity,
                                       SweepingMode::kLazyOrConcurrent);
    }
    TRACE_GC_NOTE("Sweeper::ConcurrentMajorSweeper Preempted");
    return false;
  }

  // This method is expected by `SweepingState::FinishSweeping`.
  void Finalize() {}

 private:
  Sweeper* const sweeper_;
  LocalSweeper local_sweeper_;
};

static constexpr auto kNewSpace =
    v8_flags.sticky_mark_bits.value() ? OLD_SPACE : NEW_SPACE;

class Sweeper::ConcurrentMinorSweeper final {
 public:
  explicit ConcurrentMinorSweeper(Sweeper* sweeper)
      : sweeper_(sweeper), local_sweeper_(sweeper_) {}

  bool ConcurrentSweepSpace(JobDelegate* delegate) {
    DCHECK(IsValidSweepingSpace(kNewSpace));
    while (!delegate->ShouldYield()) {
      PageMetadata* page = sweeper_->GetSweepingPageSafe(kNewSpace);
      if (page == nullptr) return true;
      local_sweeper_.ParallelSweepPage(page, kNewSpace,
                                       SweepingMode::kLazyOrConcurrent);
    }
    TRACE_GC_NOTE("Sweeper::ConcurrentMinorSweeper Preempted");
    return false;
  }

  bool ConcurrentSweepPromotedPages(JobDelegate* delegate) {
    if (local_sweeper_.ParallelIteratePromotedPages(delegate)) return true;
    TRACE_GC_NOTE("Sweeper::ConcurrentMinorSweeper Preempted");
    return false;
  }

 private:
  Sweeper* const sweeper_;
  LocalSweeper local_sweeper_;
};

class Sweeper::MajorSweeperJob final : public JobTask {
 private:
  // Major sweeping jobs don't sweep new space.
  static constexpr int kNumberOfMajorSweepingSpaces =
      kNumberOfSweepingSpaces - 1;

 public:
  static constexpr int kMaxTasks = kNumberOfMajorSweepingSpaces;

  MajorSweeperJob(Isolate* isolate, Sweeper* sweeper)
      : sweeper_(sweeper),
        concurrent_sweepers(
            sweeper_->major_sweeping_state_.concurrent_sweepers()),
        tracer_(isolate->heap()->tracer()),
        trace_id_(sweeper_->major_sweeping_state_.background_trace_id()) {
    DCHECK_LE(concurrent_sweepers.size(), kMaxTasks);
  }

  ~MajorSweeperJob() override = default;

  MajorSweeperJob(const MajorSweeperJob&) = delete;
  MajorSweeperJob& operator=(const MajorSweeperJob&) = delete;

  void Run(JobDelegate* delegate) final {
    RunImpl(delegate, delegate->IsJoiningThread());
  }

  size_t GetMaxConcurrency(size_t worker_count) const override {
    static constexpr int kPagePerTask = 2;
    return std::min<size_t>(
        concurrent_sweepers.size(),
        worker_count +
            (sweeper_->ConcurrentMajorSweepingPageCount() + kPagePerTask - 1) /
                kPagePerTask);
  }

 private:
  void RunImpl(JobDelegate* delegate, bool is_joining_thread) {
    // In case multi-cage pointer compression mode is enabled ensure that
    // current thread's cage base values are properly initialized.
    PtrComprCageAccessScope ptr_compr_cage_access_scope(
        sweeper_->heap_->isolate());

    DCHECK(sweeper_->major_sweeping_in_progress());
    const int offset = delegate->GetTaskId();
    DCHECK_LT(offset, concurrent_sweepers.size());
    ConcurrentMajorSweeper& concurrent_sweeper = concurrent_sweepers[offset];
    TRACE_GC_EPOCH_WITH_FLOW(
        tracer_, sweeper_->GetTracingScope(OLD_SPACE, is_joining_thread),
        is_joining_thread ? ThreadKind::kMain : ThreadKind::kBackground,
        trace_id_, TRACE_EVENT_FLAG_FLOW_IN);
    for (int i = 0; i < kNumberOfMajorSweepingSpaces; i++) {
      const AllocationSpace space_id = static_cast<AllocationSpace>(
          FIRST_SWEEPABLE_SPACE + 1 +
          ((offset + i) % kNumberOfMajorSweepingSpaces));
      DCHECK_LE(FIRST_SWEEPABLE_SPACE, space_id);
      DCHECK_LE(space_id, LAST_SWEEPABLE_SPACE);
      DCHECK_NE(NEW_SPACE, space_id);
      if (!concurrent_sweeper.ConcurrentSweepSpace(space_id, delegate)) return;
    }
  }

  Sweeper* const sweeper_;
  std::vector<ConcurrentMajorSweeper>& concurrent_sweepers;
  GCTracer* const tracer_;
  const uint64_t trace_id_;
};

class Sweeper::MinorSweeperJob final : public JobTask {
 public:
  static constexpr int kMaxTasks = 1;

  MinorSweeperJob(Isolate* isolate, Sweeper* sweeper)
      : sweeper_(sweeper),
        concurrent_sweepers(
            sweeper_->minor_sweeping_state_.concurrent_sweepers()),
        tracer_(isolate->heap()->tracer()),
        trace_id_(sweeper_->minor_sweeping_state_.background_trace_id()) {
    DCHECK_LE(concurrent_sweepers.size(), kMaxTasks);
  }

  ~MinorSweeperJob() override = default;

  MinorSweeperJob(const MinorSweeperJob&) = delete;
  MinorSweeperJob& operator=(const MinorSweeperJob&) = delete;

  void Run(JobDelegate* delegate) final {
    RunImpl(delegate, delegate->IsJoiningThread());
  }

  size_t GetMaxConcurrency(size_t worker_count) const override {
    static constexpr int kPagePerTask = 2;
    return std::min<size_t>(
        concurrent_sweepers.size(),
        worker_count +
            (sweeper_->ConcurrentMinorSweepingPageCount() + kPagePerTask - 1) /
                kPagePerTask);
  }

 private:
  void RunImpl(JobDelegate* delegate, bool is_joining_thread) {
    DCHECK(sweeper_->minor_sweeping_in_progress());
    const int offset = delegate->GetTaskId();
    DCHECK_LT(offset, concurrent_sweepers.size());
    ConcurrentMinorSweeper& concurrent_sweeper = concurrent_sweepers[offset];
    TRACE_GC_EPOCH_WITH_FLOW(
        tracer_, sweeper_->GetTracingScope(NEW_SPACE, is_joining_thread),
        is_joining_thread ? ThreadKind::kMain : ThreadKind::kBackground,
        trace_id_, TRACE_EVENT_FLAG_FLOW_IN);
    // In case multi-cage pointer compression mode is enabled ensure that
    // current thread's cage base values are properly initialized.
    PtrComprCageAccessScope ptr_compr_cage_access_scope(
        sweeper_->heap_->isolate());

    if (!concurrent_sweeper.ConcurrentSweepSpace(delegate)) return;
    concurrent_sweeper.ConcurrentSweepPromotedPages(delegate);
  }

  Sweeper* const sweeper_;
  std::vector<ConcurrentMinorSweeper>& concurrent_sweepers;
  GCTracer* const tracer_;
  const uint64_t trace_id_;
};

template <Sweeper::SweepingScope scope>
Sweeper::SweepingState<scope>::SweepingState(Sweeper* sweeper)
    : sweeper_(sweeper) {}

template <Sweeper::SweepingScope scope>
Sweeper::SweepingState<scope>::~SweepingState() {
  DCHECK(!in_progress_);
  DCHECK(concurrent_sweepers_.empty());
  DCHECK(!HasValidJob());
}

template <Sweeper::SweepingScope scope>
bool Sweeper::SweepingState<scope>::HasValidJob() const {
  return job_handle_ && job_handle_->IsValid();
}

template <Sweeper::SweepingScope scope>
bool Sweeper::SweepingState<scope>::HasActiveJob() const {
  return HasValidJob() && job_handle_->IsActive();
}

template <Sweeper::SweepingScope scope>
void Sweeper::SweepingState<scope>::StopConcurrentSweeping() {
  if (HasValidJob()) job_handle_->Cancel();
}

template <Sweeper::SweepingScope scope>
void Sweeper::SweepingState<scope>::InitializeSweeping() {
  DCHECK(!HasValidJob());
  DCHECK(!in_progress_);
  DCHECK(concurrent_sweepers_.empty());
  DCHECK_IMPLIES(scope == Sweeper::SweepingScope::kMinor, v8_flags.minor_ms);
  DCHECK_IMPLIES(scope == Sweeper::SweepingScope::kMinor,
                 !sweeper_->heap_->ShouldReduceMemory());
  should_reduce_memory_ = (scope != Sweeper::SweepingScope::kMinor) &&
                          sweeper_->heap_->ShouldReduceMemory();
  trace_id_ =
      (reinterpret_cast<uint64_t>(sweeper_) ^
       sweeper_->heap_->tracer()->CurrentEpoch(
           scope == SweepingScope::kMajor ? GCTracer::Scope::MC_SWEEP
                                          : GCTracer::Scope::MINOR_MS_SWEEP))
      << 1;
  background_trace_id_ = trace_id_ + 1;
}

template <Sweeper::SweepingScope scope>
void Sweeper::SweepingState<scope>::StartSweeping() {
  DCHECK(!HasValidJob());
  DCHECK(!in_progress_);
  DCHECK(concurrent_sweepers_.empty());
  DCHECK_NE(0, trace_id_);
  DCHECK_NE(0, background_trace_id_);
  in_progress_ = true;
}

template <Sweeper::SweepingScope scope>
void Sweeper::SweepingState<scope>::StartConcurrentSweeping() {
  DCHECK(!HasValidJob());
  DCHECK(in_progress_);
  if (v8_flags.concurrent_sweeping &&
      !sweeper_->heap_->delay_sweeper_tasks_for_testing_) {
    auto job =
        std::make_unique<SweeperJob>(sweeper_->heap_->isolate(), sweeper_);
    GCTracer::Scope::ScopeId scope_id =
        scope == SweepingScope::kMinor
            ? GCTracer::Scope::MINOR_MS_SWEEP_START_JOBS
            : GCTracer::Scope::MC_SWEEP_START_JOBS;
    TRACE_GC_WITH_FLOW(sweeper_->heap_->tracer(), scope_id,
                       background_trace_id(), TRACE_EVENT_FLAG_FLOW_OUT);
    DCHECK_IMPLIES(v8_flags.minor_ms, concurrent_sweepers_.empty());
    int max_concurrent_sweeper_count =
        std::min(SweeperJob::kMaxTasks,
                 V8::GetCurrentPlatform()->NumberOfWorkerThreads() + 1);
    if (concurrent_sweepers_.empty()) {
      for (int i = 0; i < max_concurrent_sweeper_count; ++i) {
        concurrent_sweepers_.emplace_back(sweeper_);
      }
    }
    DCHECK_EQ(max_concurrent_sweeper_count, concurrent_sweepers_.size());
    job_handle_ = V8::GetCurrentPlatform()->PostJob(TaskPriority::kUserVisible,
                                                    std::move(job));
  }
}

template <Sweeper::SweepingScope scope>
void Sweeper::SweepingState<scope>::JoinSweeping() {
  DCHECK(in_progress_);
  if (HasValidJob()) job_handle_->Join();
}

template <Sweeper::SweepingScope scope>
void Sweeper::SweepingState<scope>::FinishSweeping() {
  DCHECK(in_progress_);
  // Sweeping jobs were already joined.
  DCHECK(!HasValidJob());

  concurrent_sweepers_.clear();
  in_progress_ = false;
}

template <Sweeper::SweepingScope scope>
void Sweeper::SweepingState<scope>::Pause() {
  if (!job_handle_ || !job_handle_->IsValid()) return;

  DCHECK(v8_flags.concurrent_sweeping);
  job_handle_->Cancel();
  job_handle_.reset();
}

template <Sweeper::SweepingScope scope>
void Sweeper::SweepingState<scope>::Resume() {
  DCHECK(in_progress_);
  job_handle_ = V8::GetCurrentPlatform()->PostJob(
      TaskPriority::kUserVisible,
      std::make_unique<SweeperJob>(sweeper_->heap_->isolate(), sweeper_));
}

bool Sweeper::LocalSweeper::ParallelSweepSpace(AllocationSpace identity,
                                               SweepingMode sweeping_mode,
                                               uint32_t max_pages) {
  uint32_t pages_swept = 0;
  bool found_usable_pages = false;
  PageMetadata* page = nullptr;
  while ((page = sweeper_->GetSweepingPageSafe(identity)) != nullptr) {
    ParallelSweepPage(page, identity, sweeping_mode);
    if (!page->Chunk()->IsFlagSet(MemoryChunk::NEVER_ALLOCATE_ON_PAGE)) {
      found_usable_pages = true;
#if DEBUG
    } else {
      // All remaining pages are also marked with NEVER_ALLOCATE_ON_PAGE.
      base::MutexGuard guard(&sweeper_->mutex_);
      int space_index = GetSweepSpaceIndex(identity);
      Sweeper::SweepingList& sweeping_list =
          sweeper_->sweeping_list_[space_index];
      DCHECK(std::all_of(sweeping_list.begin(), sweeping_list.end(),
                         [](const PageMetadata* p) {
                           return p->Chunk()->IsFlagSet(
                               MemoryChunk::NEVER_ALLOCATE_ON_PAGE);
                         }));
#endif  // DEBUG
    }
    if (++pages_swept >= max_pages) break;
  }
  return found_usable_pages;
}

void Sweeper::LocalSweeper::ParallelSweepPage(PageMetadata* page,
                                              AllocationSpace identity,
                                              SweepingMode sweeping_mode) {
  DCHECK(IsValidSweepingSpace(identity));

  // The Scavenger may add already swept pages back.
  if (page->SweepingDone()) return;

  {
    base::MutexGuard guard(page->mutex());
    DCHECK(!page->SweepingDone());
    DCHECK_EQ(PageMetadata::ConcurrentSweepingState::kPendingSweeping,
              page->concurrent_sweeping_state());
    page->set_concurrent_sweeping_state(
        PageMetadata::ConcurrentSweepingState::kInProgress);
    const FreeSpaceTreatmentMode free_space_treatment_mode =
        heap::ShouldZapGarbage() ? FreeSpaceTreatmentMode::kZapFreeSpace
                                 : FreeSpaceTreatmentMode::kIgnoreFreeSpace;
    DCHECK_IMPLIES(identity == NEW_SPACE,
                   !sweeper_->minor_sweeping_state_.should_reduce_memory());
    sweeper_->RawSweep(
        page, free_space_treatment_mode, sweeping_mode,
        identity == NEW_SPACE
            ? false
            : sweeper_->major_sweeping_state_.should_reduce_memory());
    sweeper_->AddSweptPage(page, identity);
    DCHECK(page->SweepingDone());
  }
}

bool Sweeper::LocalSweeper::ContributeAndWaitForPromotedPagesIteration(
    JobDelegate* delegate) {
  return ContributeAndWaitForPromotedPagesIterationImpl(
      [delegate]() { return delegate->ShouldYield(); });
}

bool Sweeper::LocalSweeper::ContributeAndWaitForPromotedPagesIteration() {
  return ContributeAndWaitForPromotedPagesIterationImpl([]() { return false; });
}

bool Sweeper::LocalSweeper::ParallelIteratePromotedPages(
    JobDelegate* delegate) {
  return ParallelIteratePromotedPagesImpl(
      [delegate]() { return delegate->ShouldYield(); });
}

bool Sweeper::LocalSweeper::ParallelIteratePromotedPages() {
  return ParallelIteratePromotedPagesImpl([]() { return false; });
}

namespace {
class PromotedPageRecordMigratedSlotVisitor final
    : public NewSpaceVisitor<PromotedPageRecordMigratedSlotVisitor> {
 public:
  explicit PromotedPageRecordMigratedSlotVisitor(MutablePageMetadata* host_page)
      : NewSpaceVisitor<PromotedPageRecordMigratedSlotVisitor>(
            host_page->heap()->isolate()),
        host_chunk_(host_page->Chunk()),
        host_page_(host_page),
        ephemeron_remembered_set_(
            host_page->heap()->ephemeron_remembered_set()) {
    DCHECK(host_page->owner_identity() == OLD_SPACE ||
           host_page->owner_identity() == LO_SPACE);
  }

  void Process(Tagged<HeapObject> object) {
    Tagged<Map> map = object->map(cage_base());
    if (Map::ObjectFieldsFrom(map->visitor_id()) == ObjectFields::kDataOnly) {
      return;
    }
    Visit(map, object);
  }

  // TODO(v8:13883): MakeExternal() right now allows to externalize a string in
  // the young generation (for testing) and on a promoted page that is currently
  // being swept. If we solve the testing cases and prohobit MakeExternal() on
  // page owned by the sweeper, this visitor can be simplified as there's no
  // more unsafe shape changes that happen concurrently.
  V8_INLINE static constexpr bool EnableConcurrentVisitation() { return true; }

  V8_INLINE void VisitMapPointer(Tagged<HeapObject> host) final {
    VerifyHost(host);
    VisitObjectImpl(host, host->map(cage_base()), host->map_slot().address());
  }

  V8_INLINE void VisitPointer(Tagged<HeapObject> host, ObjectSlot p) final {
    VisitPointersImpl(host, p, p + 1);
  }
  V8_INLINE void VisitPointer(Tagged<HeapObject> host,
                              MaybeObjectSlot p) final {
    VisitPointersImpl(host, p, p + 1);
  }
  V8_INLINE void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                               ObjectSlot end) final {
    VisitPointersImpl(host, start, end);
  }
  V8_INLINE void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                               MaybeObjectSlot end) final {
    VisitPointersImpl(host, start, end);
  }

  V8_INLINE size_t VisitJSArrayBuffer(Tagged<Map> map,
                                      Tagged<JSArrayBuffer> object,
                                      MaybeObjectSize maybe_object_size) {
    object->YoungMarkExtensionPromoted();
    return NewSpaceVisitor<PromotedPageRecordMigratedSlotVisitor>::
        VisitJSArrayBuffer(map, object, maybe_object_size);
  }

  V8_INLINE size_t VisitEphemeronHashTable(Tagged<Map> map,
                                           Tagged<EphemeronHashTable> table,
                                           MaybeObjectSize) {
    NewSpaceVisitor<PromotedPageRecordMigratedSlotVisitor>::
        VisitMapPointerIfNeeded<VisitorId::kVisitEphemeronHashTable>(table);
    EphemeronRememberedSet::IndicesSet indices;
    for (InternalIndex i : table->IterateEntries()) {
      ObjectSlot value_slot =
          table->RawFieldOfElementAt(EphemeronHashTable::EntryToValueIndex(i));
      VisitPointer(table, value_slot);
      ObjectSlot key_slot =
          table->RawFieldOfElementAt(EphemeronHashTable::EntryToIndex(i));
      Tagged<Object> key = key_slot.Acquire_Load();
      Tagged<HeapObject> key_object;
      if (!key.GetHeapObject(&key_object)) continue;
#ifdef THREAD_SANITIZER
      MemoryChunk::FromHeapObject(key_object)->SynchronizedLoad();
#endif  // THREAD_SANITIZER
      // With sticky mark-bits we don't need to update the remembered set for
      // just promoted objects, since everything is promoted.
      if (!v8_flags.sticky_mark_bits &&
          HeapLayout::InYoungGeneration(key_object)) {
        indices.insert(i.as_int());
      }
    }
    if (!indices.empty()) {
      ephemeron_remembered_set_->RecordEphemeronKeyWrites(table,
                                                          std::move(indices));
    }
    return EphemeronHashTable::BodyDescriptor::SizeOf(map, table);
  }

  // Entries that are skipped for recording.
  void VisitExternalReference(Tagged<InstructionStream> host,
                              RelocInfo* rinfo) final {}
  void VisitInternalReference(Tagged<InstructionStream> host,
                              RelocInfo* rinfo) final {}
  void VisitExternalPointer(Tagged<HeapObject> host,
                            ExternalPointerSlot slot) final {}

  // Maps can be shared, so we need to visit them to record old to shared slots.
  V8_INLINE static constexpr bool ShouldVisitMapPointer() { return true; }
  V8_INLINE static constexpr bool ShouldVisitReadOnlyMapPointer() {
    return false;
  }

 private:
  V8_INLINE void VerifyHost(Tagged<HeapObject> host) {
    DCHECK(!HeapLayout::InWritableSharedSpace(host));
    DCHECK(!HeapLayout::InYoungGeneration(host));
    DCHECK(!MutablePageMetadata::FromHeapObject(host)->SweepingDone());
    DCHECK_EQ(MutablePageMetadata::FromHeapObject(host), host_page_);
  }

  template <typename TObject>
  V8_INLINE void VisitObjectImpl(Tagged<HeapObject> host, TObject object,
                                 Address slot) {
    Tagged<HeapObject> value_heap_object;
    if (!object.GetHeapObject(&value_heap_object)) return;

    MemoryChunk* value_chunk = MemoryChunk::FromHeapObject(value_heap_object);
#ifdef THREAD_SANITIZER
    value_chunk->SynchronizedLoad();
#endif  // THREAD_SANITIZER
    // With sticky mark-bits we don't need to update the remembered set for
    // just promoted objects, since everything is promoted.
    if (!v8_flags.sticky_mark_bits && value_chunk->InYoungGeneration()) {
      RememberedSet<OLD_TO_NEW_BACKGROUND>::Insert<AccessMode::ATOMIC>(
          host_page_, host_chunk_->Offset(slot));
    } else if (value_chunk->InWritableSharedSpace()) {
      RememberedSet<OLD_TO_SHARED>::Insert<AccessMode::ATOMIC>(
          host_page_, host_chunk_->Offset(slot));
    }
  }

  template <typename TSlot>
  V8_INLINE void VisitPointersImpl(Tagged<HeapObject> host, TSlot start,
                                   TSlot end) {
    VerifyHost(host);
    for (TSlot slot = start; slot < end; ++slot) {
      typename TSlot::TObject target =
          slot.Relaxed_Load(ObjectVisitorWithCageBases::cage_base());
      VisitObjectImpl(host, target, slot.address());
    }
  }

  MemoryChunk* const host_chunk_;
  MutablePageMetadata* const host_page_;
  EphemeronRememberedSet* ephemeron_remembered_set_;
};

// Atomically zap the specified area.
V8_INLINE void AtomicZapBlock(Address addr, size_t size_in_bytes) {
  static_assert(sizeof(Tagged_t) == kTaggedSize);
  static constexpr Tagged_t kZapTagged = static_cast<Tagged_t>(kZapValue);
  DCHECK(IsAligned(addr, kTaggedSize));
  DCHECK(IsAligned(size_in_bytes, kTaggedSize));
  const size_t size_in_tagged = size_in_bytes / kTaggedSize;
  Tagged_t* current_addr = reinterpret_cast<Tagged_t*>(addr);
  for (size_t i = 0; i < size_in_tagged; ++i) {
    base::AsAtomicPtr(current_addr++)
        ->store(kZapTagged, std::memory_order_relaxed);
  }
}

void ZapDeadObjectsInRange(Heap* heap, Address dead_start, Address dead_end) {
  if (dead_end != dead_start) {
    size_t free_size = static_cast<size_t>(dead_end - dead_start);
    AtomicZapBlock(dead_start, free_size);
    WritableFreeSpace free_space =
        WritableFreeSpace::ForNonExecutableMemory(dead_start, free_size);
    heap->CreateFillerObjectAtBackground(free_space);
  }
}

void ZapDeadObjectsOnPage(Heap* heap, PageMetadata* p) {
  Address dead_start = p->area_start();
  // Iterate over the page using the live objects.
  for (auto [object, size] : LiveObjectRange(p)) {
    Address dead_end = object.address();
    ZapDeadObjectsInRange(heap, dead_start, dead_end);
    dead_start = dead_end + size;
  }
  ZapDeadObjectsInRange(heap, dead_start, p->area_end());
}

}  // namespace

void Sweeper::LocalSweeper::ParallelIteratePromotedPage(
    MutablePageMetadata* page) {
  DCHECK(v8_flags.minor_ms);
  DCHECK(!page->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));
  DCHECK_NOT_NULL(page);
  {
    base::MutexGuard guard(page->mutex());
    DCHECK(!page->SweepingDone());
    DCHECK_EQ(PageMetadata::ConcurrentSweeping
Prompt: 
```
这是目录为v8/src/heap/sweeper.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/sweeper.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/sweeper.h"

#include <algorithm>
#include <atomic>
#include <memory>
#include <optional>
#include <vector>

#include "src/base/atomic-utils.h"
#include "src/base/logging.h"
#include "src/common/globals.h"
#include "src/execution/vm-state-inl.h"
#include "src/flags/flags.h"
#include "src/heap/base/active-system-pages.h"
#include "src/heap/ephemeron-remembered-set.h"
#include "src/heap/free-list-inl.h"
#include "src/heap/gc-tracer-inl.h"
#include "src/heap/gc-tracer.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap.h"
#include "src/heap/live-object-range-inl.h"
#include "src/heap/mark-compact-inl.h"
#include "src/heap/mark-compact.h"
#include "src/heap/marking-inl.h"
#include "src/heap/marking-state.h"
#include "src/heap/memory-allocator.h"
#include "src/heap/memory-chunk-layout.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/heap/new-spaces.h"
#include "src/heap/page-metadata-inl.h"
#include "src/heap/paged-spaces.h"
#include "src/heap/pretenuring-handler-inl.h"
#include "src/heap/pretenuring-handler.h"
#include "src/heap/remembered-set.h"
#include "src/heap/slot-set.h"
#include "src/heap/zapping.h"
#include "src/objects/hash-table.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/map.h"
#include "src/objects/objects-inl.h"

namespace v8 {
namespace internal {

class Sweeper::ConcurrentMajorSweeper final {
 public:
  explicit ConcurrentMajorSweeper(Sweeper* sweeper)
      : sweeper_(sweeper), local_sweeper_(sweeper_) {}

  bool ConcurrentSweepSpace(AllocationSpace identity, JobDelegate* delegate) {
    DCHECK(IsValidSweepingSpace(identity));
    DCHECK_NE(NEW_SPACE, identity);
    while (!delegate->ShouldYield()) {
      PageMetadata* page = sweeper_->GetSweepingPageSafe(identity);
      if (page == nullptr) return true;
      local_sweeper_.ParallelSweepPage(page, identity,
                                       SweepingMode::kLazyOrConcurrent);
    }
    TRACE_GC_NOTE("Sweeper::ConcurrentMajorSweeper Preempted");
    return false;
  }

  // This method is expected by `SweepingState::FinishSweeping`.
  void Finalize() {}

 private:
  Sweeper* const sweeper_;
  LocalSweeper local_sweeper_;
};

static constexpr auto kNewSpace =
    v8_flags.sticky_mark_bits.value() ? OLD_SPACE : NEW_SPACE;

class Sweeper::ConcurrentMinorSweeper final {
 public:
  explicit ConcurrentMinorSweeper(Sweeper* sweeper)
      : sweeper_(sweeper), local_sweeper_(sweeper_) {}

  bool ConcurrentSweepSpace(JobDelegate* delegate) {
    DCHECK(IsValidSweepingSpace(kNewSpace));
    while (!delegate->ShouldYield()) {
      PageMetadata* page = sweeper_->GetSweepingPageSafe(kNewSpace);
      if (page == nullptr) return true;
      local_sweeper_.ParallelSweepPage(page, kNewSpace,
                                       SweepingMode::kLazyOrConcurrent);
    }
    TRACE_GC_NOTE("Sweeper::ConcurrentMinorSweeper Preempted");
    return false;
  }

  bool ConcurrentSweepPromotedPages(JobDelegate* delegate) {
    if (local_sweeper_.ParallelIteratePromotedPages(delegate)) return true;
    TRACE_GC_NOTE("Sweeper::ConcurrentMinorSweeper Preempted");
    return false;
  }

 private:
  Sweeper* const sweeper_;
  LocalSweeper local_sweeper_;
};

class Sweeper::MajorSweeperJob final : public JobTask {
 private:
  // Major sweeping jobs don't sweep new space.
  static constexpr int kNumberOfMajorSweepingSpaces =
      kNumberOfSweepingSpaces - 1;

 public:
  static constexpr int kMaxTasks = kNumberOfMajorSweepingSpaces;

  MajorSweeperJob(Isolate* isolate, Sweeper* sweeper)
      : sweeper_(sweeper),
        concurrent_sweepers(
            sweeper_->major_sweeping_state_.concurrent_sweepers()),
        tracer_(isolate->heap()->tracer()),
        trace_id_(sweeper_->major_sweeping_state_.background_trace_id()) {
    DCHECK_LE(concurrent_sweepers.size(), kMaxTasks);
  }

  ~MajorSweeperJob() override = default;

  MajorSweeperJob(const MajorSweeperJob&) = delete;
  MajorSweeperJob& operator=(const MajorSweeperJob&) = delete;

  void Run(JobDelegate* delegate) final {
    RunImpl(delegate, delegate->IsJoiningThread());
  }

  size_t GetMaxConcurrency(size_t worker_count) const override {
    static constexpr int kPagePerTask = 2;
    return std::min<size_t>(
        concurrent_sweepers.size(),
        worker_count +
            (sweeper_->ConcurrentMajorSweepingPageCount() + kPagePerTask - 1) /
                kPagePerTask);
  }

 private:
  void RunImpl(JobDelegate* delegate, bool is_joining_thread) {
    // In case multi-cage pointer compression mode is enabled ensure that
    // current thread's cage base values are properly initialized.
    PtrComprCageAccessScope ptr_compr_cage_access_scope(
        sweeper_->heap_->isolate());

    DCHECK(sweeper_->major_sweeping_in_progress());
    const int offset = delegate->GetTaskId();
    DCHECK_LT(offset, concurrent_sweepers.size());
    ConcurrentMajorSweeper& concurrent_sweeper = concurrent_sweepers[offset];
    TRACE_GC_EPOCH_WITH_FLOW(
        tracer_, sweeper_->GetTracingScope(OLD_SPACE, is_joining_thread),
        is_joining_thread ? ThreadKind::kMain : ThreadKind::kBackground,
        trace_id_, TRACE_EVENT_FLAG_FLOW_IN);
    for (int i = 0; i < kNumberOfMajorSweepingSpaces; i++) {
      const AllocationSpace space_id = static_cast<AllocationSpace>(
          FIRST_SWEEPABLE_SPACE + 1 +
          ((offset + i) % kNumberOfMajorSweepingSpaces));
      DCHECK_LE(FIRST_SWEEPABLE_SPACE, space_id);
      DCHECK_LE(space_id, LAST_SWEEPABLE_SPACE);
      DCHECK_NE(NEW_SPACE, space_id);
      if (!concurrent_sweeper.ConcurrentSweepSpace(space_id, delegate)) return;
    }
  }

  Sweeper* const sweeper_;
  std::vector<ConcurrentMajorSweeper>& concurrent_sweepers;
  GCTracer* const tracer_;
  const uint64_t trace_id_;
};

class Sweeper::MinorSweeperJob final : public JobTask {
 public:
  static constexpr int kMaxTasks = 1;

  MinorSweeperJob(Isolate* isolate, Sweeper* sweeper)
      : sweeper_(sweeper),
        concurrent_sweepers(
            sweeper_->minor_sweeping_state_.concurrent_sweepers()),
        tracer_(isolate->heap()->tracer()),
        trace_id_(sweeper_->minor_sweeping_state_.background_trace_id()) {
    DCHECK_LE(concurrent_sweepers.size(), kMaxTasks);
  }

  ~MinorSweeperJob() override = default;

  MinorSweeperJob(const MinorSweeperJob&) = delete;
  MinorSweeperJob& operator=(const MinorSweeperJob&) = delete;

  void Run(JobDelegate* delegate) final {
    RunImpl(delegate, delegate->IsJoiningThread());
  }

  size_t GetMaxConcurrency(size_t worker_count) const override {
    static constexpr int kPagePerTask = 2;
    return std::min<size_t>(
        concurrent_sweepers.size(),
        worker_count +
            (sweeper_->ConcurrentMinorSweepingPageCount() + kPagePerTask - 1) /
                kPagePerTask);
  }

 private:
  void RunImpl(JobDelegate* delegate, bool is_joining_thread) {
    DCHECK(sweeper_->minor_sweeping_in_progress());
    const int offset = delegate->GetTaskId();
    DCHECK_LT(offset, concurrent_sweepers.size());
    ConcurrentMinorSweeper& concurrent_sweeper = concurrent_sweepers[offset];
    TRACE_GC_EPOCH_WITH_FLOW(
        tracer_, sweeper_->GetTracingScope(NEW_SPACE, is_joining_thread),
        is_joining_thread ? ThreadKind::kMain : ThreadKind::kBackground,
        trace_id_, TRACE_EVENT_FLAG_FLOW_IN);
    // In case multi-cage pointer compression mode is enabled ensure that
    // current thread's cage base values are properly initialized.
    PtrComprCageAccessScope ptr_compr_cage_access_scope(
        sweeper_->heap_->isolate());

    if (!concurrent_sweeper.ConcurrentSweepSpace(delegate)) return;
    concurrent_sweeper.ConcurrentSweepPromotedPages(delegate);
  }

  Sweeper* const sweeper_;
  std::vector<ConcurrentMinorSweeper>& concurrent_sweepers;
  GCTracer* const tracer_;
  const uint64_t trace_id_;
};

template <Sweeper::SweepingScope scope>
Sweeper::SweepingState<scope>::SweepingState(Sweeper* sweeper)
    : sweeper_(sweeper) {}

template <Sweeper::SweepingScope scope>
Sweeper::SweepingState<scope>::~SweepingState() {
  DCHECK(!in_progress_);
  DCHECK(concurrent_sweepers_.empty());
  DCHECK(!HasValidJob());
}

template <Sweeper::SweepingScope scope>
bool Sweeper::SweepingState<scope>::HasValidJob() const {
  return job_handle_ && job_handle_->IsValid();
}

template <Sweeper::SweepingScope scope>
bool Sweeper::SweepingState<scope>::HasActiveJob() const {
  return HasValidJob() && job_handle_->IsActive();
}

template <Sweeper::SweepingScope scope>
void Sweeper::SweepingState<scope>::StopConcurrentSweeping() {
  if (HasValidJob()) job_handle_->Cancel();
}

template <Sweeper::SweepingScope scope>
void Sweeper::SweepingState<scope>::InitializeSweeping() {
  DCHECK(!HasValidJob());
  DCHECK(!in_progress_);
  DCHECK(concurrent_sweepers_.empty());
  DCHECK_IMPLIES(scope == Sweeper::SweepingScope::kMinor, v8_flags.minor_ms);
  DCHECK_IMPLIES(scope == Sweeper::SweepingScope::kMinor,
                 !sweeper_->heap_->ShouldReduceMemory());
  should_reduce_memory_ = (scope != Sweeper::SweepingScope::kMinor) &&
                          sweeper_->heap_->ShouldReduceMemory();
  trace_id_ =
      (reinterpret_cast<uint64_t>(sweeper_) ^
       sweeper_->heap_->tracer()->CurrentEpoch(
           scope == SweepingScope::kMajor ? GCTracer::Scope::MC_SWEEP
                                          : GCTracer::Scope::MINOR_MS_SWEEP))
      << 1;
  background_trace_id_ = trace_id_ + 1;
}

template <Sweeper::SweepingScope scope>
void Sweeper::SweepingState<scope>::StartSweeping() {
  DCHECK(!HasValidJob());
  DCHECK(!in_progress_);
  DCHECK(concurrent_sweepers_.empty());
  DCHECK_NE(0, trace_id_);
  DCHECK_NE(0, background_trace_id_);
  in_progress_ = true;
}

template <Sweeper::SweepingScope scope>
void Sweeper::SweepingState<scope>::StartConcurrentSweeping() {
  DCHECK(!HasValidJob());
  DCHECK(in_progress_);
  if (v8_flags.concurrent_sweeping &&
      !sweeper_->heap_->delay_sweeper_tasks_for_testing_) {
    auto job =
        std::make_unique<SweeperJob>(sweeper_->heap_->isolate(), sweeper_);
    GCTracer::Scope::ScopeId scope_id =
        scope == SweepingScope::kMinor
            ? GCTracer::Scope::MINOR_MS_SWEEP_START_JOBS
            : GCTracer::Scope::MC_SWEEP_START_JOBS;
    TRACE_GC_WITH_FLOW(sweeper_->heap_->tracer(), scope_id,
                       background_trace_id(), TRACE_EVENT_FLAG_FLOW_OUT);
    DCHECK_IMPLIES(v8_flags.minor_ms, concurrent_sweepers_.empty());
    int max_concurrent_sweeper_count =
        std::min(SweeperJob::kMaxTasks,
                 V8::GetCurrentPlatform()->NumberOfWorkerThreads() + 1);
    if (concurrent_sweepers_.empty()) {
      for (int i = 0; i < max_concurrent_sweeper_count; ++i) {
        concurrent_sweepers_.emplace_back(sweeper_);
      }
    }
    DCHECK_EQ(max_concurrent_sweeper_count, concurrent_sweepers_.size());
    job_handle_ = V8::GetCurrentPlatform()->PostJob(TaskPriority::kUserVisible,
                                                    std::move(job));
  }
}

template <Sweeper::SweepingScope scope>
void Sweeper::SweepingState<scope>::JoinSweeping() {
  DCHECK(in_progress_);
  if (HasValidJob()) job_handle_->Join();
}

template <Sweeper::SweepingScope scope>
void Sweeper::SweepingState<scope>::FinishSweeping() {
  DCHECK(in_progress_);
  // Sweeping jobs were already joined.
  DCHECK(!HasValidJob());

  concurrent_sweepers_.clear();
  in_progress_ = false;
}

template <Sweeper::SweepingScope scope>
void Sweeper::SweepingState<scope>::Pause() {
  if (!job_handle_ || !job_handle_->IsValid()) return;

  DCHECK(v8_flags.concurrent_sweeping);
  job_handle_->Cancel();
  job_handle_.reset();
}

template <Sweeper::SweepingScope scope>
void Sweeper::SweepingState<scope>::Resume() {
  DCHECK(in_progress_);
  job_handle_ = V8::GetCurrentPlatform()->PostJob(
      TaskPriority::kUserVisible,
      std::make_unique<SweeperJob>(sweeper_->heap_->isolate(), sweeper_));
}

bool Sweeper::LocalSweeper::ParallelSweepSpace(AllocationSpace identity,
                                               SweepingMode sweeping_mode,
                                               uint32_t max_pages) {
  uint32_t pages_swept = 0;
  bool found_usable_pages = false;
  PageMetadata* page = nullptr;
  while ((page = sweeper_->GetSweepingPageSafe(identity)) != nullptr) {
    ParallelSweepPage(page, identity, sweeping_mode);
    if (!page->Chunk()->IsFlagSet(MemoryChunk::NEVER_ALLOCATE_ON_PAGE)) {
      found_usable_pages = true;
#if DEBUG
    } else {
      // All remaining pages are also marked with NEVER_ALLOCATE_ON_PAGE.
      base::MutexGuard guard(&sweeper_->mutex_);
      int space_index = GetSweepSpaceIndex(identity);
      Sweeper::SweepingList& sweeping_list =
          sweeper_->sweeping_list_[space_index];
      DCHECK(std::all_of(sweeping_list.begin(), sweeping_list.end(),
                         [](const PageMetadata* p) {
                           return p->Chunk()->IsFlagSet(
                               MemoryChunk::NEVER_ALLOCATE_ON_PAGE);
                         }));
#endif  // DEBUG
    }
    if (++pages_swept >= max_pages) break;
  }
  return found_usable_pages;
}

void Sweeper::LocalSweeper::ParallelSweepPage(PageMetadata* page,
                                              AllocationSpace identity,
                                              SweepingMode sweeping_mode) {
  DCHECK(IsValidSweepingSpace(identity));

  // The Scavenger may add already swept pages back.
  if (page->SweepingDone()) return;

  {
    base::MutexGuard guard(page->mutex());
    DCHECK(!page->SweepingDone());
    DCHECK_EQ(PageMetadata::ConcurrentSweepingState::kPendingSweeping,
              page->concurrent_sweeping_state());
    page->set_concurrent_sweeping_state(
        PageMetadata::ConcurrentSweepingState::kInProgress);
    const FreeSpaceTreatmentMode free_space_treatment_mode =
        heap::ShouldZapGarbage() ? FreeSpaceTreatmentMode::kZapFreeSpace
                                 : FreeSpaceTreatmentMode::kIgnoreFreeSpace;
    DCHECK_IMPLIES(identity == NEW_SPACE,
                   !sweeper_->minor_sweeping_state_.should_reduce_memory());
    sweeper_->RawSweep(
        page, free_space_treatment_mode, sweeping_mode,
        identity == NEW_SPACE
            ? false
            : sweeper_->major_sweeping_state_.should_reduce_memory());
    sweeper_->AddSweptPage(page, identity);
    DCHECK(page->SweepingDone());
  }
}

bool Sweeper::LocalSweeper::ContributeAndWaitForPromotedPagesIteration(
    JobDelegate* delegate) {
  return ContributeAndWaitForPromotedPagesIterationImpl(
      [delegate]() { return delegate->ShouldYield(); });
}

bool Sweeper::LocalSweeper::ContributeAndWaitForPromotedPagesIteration() {
  return ContributeAndWaitForPromotedPagesIterationImpl([]() { return false; });
}

bool Sweeper::LocalSweeper::ParallelIteratePromotedPages(
    JobDelegate* delegate) {
  return ParallelIteratePromotedPagesImpl(
      [delegate]() { return delegate->ShouldYield(); });
}

bool Sweeper::LocalSweeper::ParallelIteratePromotedPages() {
  return ParallelIteratePromotedPagesImpl([]() { return false; });
}

namespace {
class PromotedPageRecordMigratedSlotVisitor final
    : public NewSpaceVisitor<PromotedPageRecordMigratedSlotVisitor> {
 public:
  explicit PromotedPageRecordMigratedSlotVisitor(MutablePageMetadata* host_page)
      : NewSpaceVisitor<PromotedPageRecordMigratedSlotVisitor>(
            host_page->heap()->isolate()),
        host_chunk_(host_page->Chunk()),
        host_page_(host_page),
        ephemeron_remembered_set_(
            host_page->heap()->ephemeron_remembered_set()) {
    DCHECK(host_page->owner_identity() == OLD_SPACE ||
           host_page->owner_identity() == LO_SPACE);
  }

  void Process(Tagged<HeapObject> object) {
    Tagged<Map> map = object->map(cage_base());
    if (Map::ObjectFieldsFrom(map->visitor_id()) == ObjectFields::kDataOnly) {
      return;
    }
    Visit(map, object);
  }

  // TODO(v8:13883): MakeExternal() right now allows to externalize a string in
  // the young generation (for testing) and on a promoted page that is currently
  // being swept. If we solve the testing cases and prohobit MakeExternal() on
  // page owned by the sweeper, this visitor can be simplified as there's no
  // more unsafe shape changes that happen concurrently.
  V8_INLINE static constexpr bool EnableConcurrentVisitation() { return true; }

  V8_INLINE void VisitMapPointer(Tagged<HeapObject> host) final {
    VerifyHost(host);
    VisitObjectImpl(host, host->map(cage_base()), host->map_slot().address());
  }

  V8_INLINE void VisitPointer(Tagged<HeapObject> host, ObjectSlot p) final {
    VisitPointersImpl(host, p, p + 1);
  }
  V8_INLINE void VisitPointer(Tagged<HeapObject> host,
                              MaybeObjectSlot p) final {
    VisitPointersImpl(host, p, p + 1);
  }
  V8_INLINE void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                               ObjectSlot end) final {
    VisitPointersImpl(host, start, end);
  }
  V8_INLINE void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                               MaybeObjectSlot end) final {
    VisitPointersImpl(host, start, end);
  }

  V8_INLINE size_t VisitJSArrayBuffer(Tagged<Map> map,
                                      Tagged<JSArrayBuffer> object,
                                      MaybeObjectSize maybe_object_size) {
    object->YoungMarkExtensionPromoted();
    return NewSpaceVisitor<PromotedPageRecordMigratedSlotVisitor>::
        VisitJSArrayBuffer(map, object, maybe_object_size);
  }

  V8_INLINE size_t VisitEphemeronHashTable(Tagged<Map> map,
                                           Tagged<EphemeronHashTable> table,
                                           MaybeObjectSize) {
    NewSpaceVisitor<PromotedPageRecordMigratedSlotVisitor>::
        VisitMapPointerIfNeeded<VisitorId::kVisitEphemeronHashTable>(table);
    EphemeronRememberedSet::IndicesSet indices;
    for (InternalIndex i : table->IterateEntries()) {
      ObjectSlot value_slot =
          table->RawFieldOfElementAt(EphemeronHashTable::EntryToValueIndex(i));
      VisitPointer(table, value_slot);
      ObjectSlot key_slot =
          table->RawFieldOfElementAt(EphemeronHashTable::EntryToIndex(i));
      Tagged<Object> key = key_slot.Acquire_Load();
      Tagged<HeapObject> key_object;
      if (!key.GetHeapObject(&key_object)) continue;
#ifdef THREAD_SANITIZER
      MemoryChunk::FromHeapObject(key_object)->SynchronizedLoad();
#endif  // THREAD_SANITIZER
      // With sticky mark-bits we don't need to update the remembered set for
      // just promoted objects, since everything is promoted.
      if (!v8_flags.sticky_mark_bits &&
          HeapLayout::InYoungGeneration(key_object)) {
        indices.insert(i.as_int());
      }
    }
    if (!indices.empty()) {
      ephemeron_remembered_set_->RecordEphemeronKeyWrites(table,
                                                          std::move(indices));
    }
    return EphemeronHashTable::BodyDescriptor::SizeOf(map, table);
  }

  // Entries that are skipped for recording.
  void VisitExternalReference(Tagged<InstructionStream> host,
                              RelocInfo* rinfo) final {}
  void VisitInternalReference(Tagged<InstructionStream> host,
                              RelocInfo* rinfo) final {}
  void VisitExternalPointer(Tagged<HeapObject> host,
                            ExternalPointerSlot slot) final {}

  // Maps can be shared, so we need to visit them to record old to shared slots.
  V8_INLINE static constexpr bool ShouldVisitMapPointer() { return true; }
  V8_INLINE static constexpr bool ShouldVisitReadOnlyMapPointer() {
    return false;
  }

 private:
  V8_INLINE void VerifyHost(Tagged<HeapObject> host) {
    DCHECK(!HeapLayout::InWritableSharedSpace(host));
    DCHECK(!HeapLayout::InYoungGeneration(host));
    DCHECK(!MutablePageMetadata::FromHeapObject(host)->SweepingDone());
    DCHECK_EQ(MutablePageMetadata::FromHeapObject(host), host_page_);
  }

  template <typename TObject>
  V8_INLINE void VisitObjectImpl(Tagged<HeapObject> host, TObject object,
                                 Address slot) {
    Tagged<HeapObject> value_heap_object;
    if (!object.GetHeapObject(&value_heap_object)) return;

    MemoryChunk* value_chunk = MemoryChunk::FromHeapObject(value_heap_object);
#ifdef THREAD_SANITIZER
    value_chunk->SynchronizedLoad();
#endif  // THREAD_SANITIZER
    // With sticky mark-bits we don't need to update the remembered set for
    // just promoted objects, since everything is promoted.
    if (!v8_flags.sticky_mark_bits && value_chunk->InYoungGeneration()) {
      RememberedSet<OLD_TO_NEW_BACKGROUND>::Insert<AccessMode::ATOMIC>(
          host_page_, host_chunk_->Offset(slot));
    } else if (value_chunk->InWritableSharedSpace()) {
      RememberedSet<OLD_TO_SHARED>::Insert<AccessMode::ATOMIC>(
          host_page_, host_chunk_->Offset(slot));
    }
  }

  template <typename TSlot>
  V8_INLINE void VisitPointersImpl(Tagged<HeapObject> host, TSlot start,
                                   TSlot end) {
    VerifyHost(host);
    for (TSlot slot = start; slot < end; ++slot) {
      typename TSlot::TObject target =
          slot.Relaxed_Load(ObjectVisitorWithCageBases::cage_base());
      VisitObjectImpl(host, target, slot.address());
    }
  }

  MemoryChunk* const host_chunk_;
  MutablePageMetadata* const host_page_;
  EphemeronRememberedSet* ephemeron_remembered_set_;
};

// Atomically zap the specified area.
V8_INLINE void AtomicZapBlock(Address addr, size_t size_in_bytes) {
  static_assert(sizeof(Tagged_t) == kTaggedSize);
  static constexpr Tagged_t kZapTagged = static_cast<Tagged_t>(kZapValue);
  DCHECK(IsAligned(addr, kTaggedSize));
  DCHECK(IsAligned(size_in_bytes, kTaggedSize));
  const size_t size_in_tagged = size_in_bytes / kTaggedSize;
  Tagged_t* current_addr = reinterpret_cast<Tagged_t*>(addr);
  for (size_t i = 0; i < size_in_tagged; ++i) {
    base::AsAtomicPtr(current_addr++)
        ->store(kZapTagged, std::memory_order_relaxed);
  }
}

void ZapDeadObjectsInRange(Heap* heap, Address dead_start, Address dead_end) {
  if (dead_end != dead_start) {
    size_t free_size = static_cast<size_t>(dead_end - dead_start);
    AtomicZapBlock(dead_start, free_size);
    WritableFreeSpace free_space =
        WritableFreeSpace::ForNonExecutableMemory(dead_start, free_size);
    heap->CreateFillerObjectAtBackground(free_space);
  }
}

void ZapDeadObjectsOnPage(Heap* heap, PageMetadata* p) {
  Address dead_start = p->area_start();
  // Iterate over the page using the live objects.
  for (auto [object, size] : LiveObjectRange(p)) {
    Address dead_end = object.address();
    ZapDeadObjectsInRange(heap, dead_start, dead_end);
    dead_start = dead_end + size;
  }
  ZapDeadObjectsInRange(heap, dead_start, p->area_end());
}

}  // namespace

void Sweeper::LocalSweeper::ParallelIteratePromotedPage(
    MutablePageMetadata* page) {
  DCHECK(v8_flags.minor_ms);
  DCHECK(!page->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));
  DCHECK_NOT_NULL(page);
  {
    base::MutexGuard guard(page->mutex());
    DCHECK(!page->SweepingDone());
    DCHECK_EQ(PageMetadata::ConcurrentSweepingState::kPendingIteration,
              page->concurrent_sweeping_state());
    page->set_concurrent_sweeping_state(
        PageMetadata::ConcurrentSweepingState::kInProgress);
    PromotedPageRecordMigratedSlotVisitor record_visitor(page);
    const bool is_large_page = page->Chunk()->IsLargePage();
    if (is_large_page) {
      DCHECK_EQ(LO_SPACE, page->owner_identity());
      record_visitor.Process(LargePageMetadata::cast(page)->GetObject());
      page->ReleaseSlotSet(SURVIVOR_TO_EXTERNAL_POINTER);
    } else {
      DCHECK_EQ(OLD_SPACE, page->owner_identity());
      DCHECK(!page->Chunk()->IsEvacuationCandidate());
      for (auto [object, _] :
           LiveObjectRange(static_cast<PageMetadata*>(page))) {
        record_visitor.Process(object);
      }
    }
    if (heap::ShouldZapGarbage() && !is_large_page) {
      ZapDeadObjectsOnPage(sweeper_->heap_, static_cast<PageMetadata*>(page));
    }
    page->ClearLiveness();
    sweeper_->NotifyPromotedPageIterationFinished(page);
    DCHECK(page->SweepingDone());
  }
}

Sweeper::Sweeper(Heap* heap)
    : heap_(heap),
      marking_state_(heap_->non_atomic_marking_state()),
      main_thread_local_sweeper_(this) {}

Sweeper::~Sweeper() = default;

void Sweeper::TearDown() {
  minor_sweeping_state_.StopConcurrentSweeping();
  major_sweeping_state_.StopConcurrentSweeping();
}

void Sweeper::InitializeMajorSweeping() {
  major_sweeping_state_.InitializeSweeping();
}

void Sweeper::InitializeMinorSweeping() {
  minor_sweeping_state_.InitializeSweeping();
}

namespace {
V8_INLINE bool ComparePagesForSweepingOrder(const PageMetadata* a,
                                            const PageMetadata* b) {
  // Prioritize pages that can be allocated on.
  if (a->Chunk()->IsFlagSet(MemoryChunk::NEVER_ALLOCATE_ON_PAGE) !=
      b->Chunk()->IsFlagSet(MemoryChunk::NEVER_ALLOCATE_ON_PAGE))
    return a->Chunk()->IsFlagSet(MemoryChunk::NEVER_ALLOCATE_ON_PAGE);
  // We sort in descending order of live bytes, i.e., ascending order of
  // free bytes, because GetSweepingPageSafe returns pages in reverse order.
  // This works automatically for black allocated pages, since we set live bytes
  // for them to the area size.
  return a->live_bytes() > b->live_bytes();
}
}  // namespace

void Sweeper::StartMajorSweeping() {
  DCHECK_EQ(GarbageCollector::MARK_COMPACTOR,
            heap_->tracer()->GetCurrentCollector());
  DCHECK(!minor_sweeping_in_progress());
  major_sweeping_state_.StartSweeping();
  ForAllSweepingSpaces([this](AllocationSpace space) {
    // Sorting is done in order to make compaction more efficient: by sweeping
    // pages with the most free bytes first, we make it more likely that when
    // evacuating a page, already swept pages will have enough free bytes to
    // hold the objects to move (and therefore, we won't need to wait for more
    // pages to be swept in order to move those objects).
    int space_index = GetSweepSpaceIndex(space);
    DCHECK_IMPLIES(space == NEW_SPACE, sweeping_list_[space_index].empty());
    std::sort(sweeping_list_[space_index].begin(),
              sweeping_list_[space_index].end(), ComparePagesForSweepingOrder);
  });
}

void Sweeper::StartMinorSweeping() {
  DCHECK_EQ(GarbageCollector::MINOR_MARK_SWEEPER,
            heap_->tracer()->GetCurrentCollector());
  minor_sweeping_state_.StartSweeping();
  int new_space_index = GetSweepSpaceIndex(kNewSpace);
  std::sort(sweeping_list_[new_space_index].begin(),
            sweeping_list_[new_space_index].end(),
            ComparePagesForSweepingOrder);
}

namespace {
bool ShouldUpdateRememberedSets(Heap* heap) {
  DCHECK_EQ(0, heap->new_lo_space()->Size());
  if (v8_flags.sticky_mark_bits) {
    // TODO(333906585): Update OLD_TO_SHARED remembered set for promoted
    // objects.
    return false;
  }
  if (heap->new_space()->Size() > 0) {
    // Keep track of OLD_TO_NEW slots
    return true;
  }
  // TODO(v8:12612): OLD_TO_SHARED is not really needed on the main isolate and
  // this condition should only apply to client isolates.
  if (heap->isolate()->has_shared_space()) {
    // Keep track of OLD_TO_SHARED slots
    return true;
  }
  return false;
}
}  // namespace

void Sweeper::StartMajorSweeperTasks() {
  DCHECK_IMPLIES(v8_flags.minor_ms, GarbageCollector::MARK_COMPACTOR ==
                                        heap_->tracer()->GetCurrentCollector());
  DCHECK(!minor_sweeping_in_progress());
  DCHECK(!promoted_page_iteration_in_progress_);
  DCHECK_EQ(0, promoted_pages_for_iteration_count_);
  major_sweeping_state_.StartConcurrentSweeping();
}

namespace {
void ClearPromotedPages(Heap* heap, std::vector<MutablePageMetadata*> pages) {
  DCHECK(v8_flags.minor_ms);
  for (auto* page : pages) {
    DCHECK(!page->SweepingDone());
    DCHECK_EQ(PageMetadata::ConcurrentSweepingState::kPendingIteration,
              page->concurrent_sweeping_state());
    if (heap::ShouldZapGarbage() && !page->Chunk()->IsLargePage()) {
      ZapDeadObjectsOnPage(heap, static_cast<PageMetadata*>(page));
    }
    page->ClearLiveness();
    page->set_concurrent_sweeping_state(
        PageMetadata::ConcurrentSweepingState::kDone);
  }
}
}  // namespace

void Sweeper::StartMinorSweeperTasks() {
  DCHECK(v8_flags.minor_ms);
  DCHECK_EQ(GarbageCollector::MINOR_MARK_SWEEPER,
            heap_->tracer()->GetCurrentCollector());
  DCHECK(!promoted_page_iteration_in_progress_);
  std::vector<MutablePageMetadata*> promoted_pages_for_clearing;
  if (promoted_pages_for_iteration_count_ > 0) {
    if (ShouldUpdateRememberedSets(heap_)) {
      promoted_page_iteration_in_progress_.store(true,
                                                 std::memory_order_release);
    } else {
      promoted_pages_for_clearing.swap(
          sweeping_list_for_promoted_page_iteration_);
      DCHECK(sweeping_list_for_promoted_page_iteration_.empty());
      promoted_pages_for_iteration_count_ = 0;
    }
  }
  minor_sweeping_state_.StartConcurrentSweeping();
  ClearPromotedPages(heap_, promoted_pages_for_clearing);
}

PageMetadata* Sweeper::GetSweptPageSafe(PagedSpaceBase* space) {
  base::MutexGuard guard(&mutex_);
  SweptList& list = swept_list_[GetSweepSpaceIndex(space->identity())];
  PageMetadata* page = nullptr;
  if (!list.empty()) {
    page = list.back();
    list.pop_back();
  }
  if (list.empty()) {
    has_swept_pages_[GetSweepSpaceIndex(space->identity())].store(
        false, std::memory_order_release);
  }
  return page;
}

Sweeper::SweptList Sweeper::GetAllSweptPagesSafe(PagedSpaceBase* space) {
  base::MutexGuard guard(&mutex_);
  SweptList list;
  list.swap(swept_list_[GetSweepSpaceIndex(space->identity())]);
  has_swept_pages_[GetSweepSpaceIndex(space->identity())].store(
      false, std::memory_order_release);
  return list;
}

void Sweeper::FinishMajorJobs() {
  if (!major_sweeping_in_progress()) return;

  ForAllSweepingSpaces([this](AllocationSpace space) {
    if (space == NEW_SPACE) return;
    main_thread_local_sweeper_.ParallelSweepSpace(
        space, SweepingMode::kLazyOrConcurrent);
  });

  // Join all concurrent tasks.
  major_sweeping_state_.JoinSweeping();
  // All jobs are done but we still remain in sweeping state here.
  DCHECK(major_sweeping_in_progress());

  ForAllSweepingSpaces([this](AllocationSpace space) {
    if (space == NEW_SPACE) return;
    CHECK(sweeping_list_[GetSweepSpaceIndex(space)].empty());
    DCHECK(IsSweepingDoneForSpace(space));
  });
}

void Sweeper::EnsureMajorCompleted() {
  DCHECK(heap_->IsMainThread());

  // If sweeping is not completed or not running at all, we try to complete it
  // here.

  if (minor_sweeping_in_progress()) {
    TRACE_GC_EPOCH_WITH_FLOW(
        heap_->tracer(), GCTracer::Scope::MINOR_MS_COMPLETE_SWEEPING,
        ThreadKind::kMain,
        GetTraceIdForFlowEvent(GCTracer::Scope::MINOR_MS_COMPLETE_SWEEPING),
        TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
    // TODO(40096225): When finalizing sweeping for a starting a new major GC,
    // OLD_TO_NEW is no longer needed. If this is the main isolate, we could
    // cancel promoted page iteration instead of finishing it.
    EnsureMinorCompleted();
  }

  if (major_sweeping_in_progress()) {
    TRACE_GC_EPOCH_WITH_FLOW(
        heap_->tracer(), GCTracer::Scope::MC_COMPLETE_SWEEPING,
        ThreadKind::kMain,
        GetTraceIdForFlowEvent(GCTracer::Scope::MC_COMPLETE_SWEEPING),
        TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
    // Discard all pooled pages on memory-reducing GCs.
    if (major_sweeping_state_.should_reduce_memory()) {
      heap_->memory_allocator()->pool()->ReleasePooledChunks();
    }
    FinishMajorJobs();
    major_sweeping_state_.FinishSweeping();
    // Sweeping should not add pages to the pool.
    DCHECK_IMPLIES(
        major_sweeping_state_.should_reduce_memory(),
        heap_->memory_allocator()->pool()->NumberOfCommittedChunks() == 0);
  }
}

void Sweeper::FinishMinorJobs() {
  if (!minor_sweeping_in_progress()) return;

  main_thread_local_sweeper_.ParallelSweepSpace(
      kNewSpace, SweepingMode::kLazyOrConcurrent);
  // Array buffer sweeper may have grabbed a page for iteration to contribute.
  // Wait until it has finished iterating.
  main_thread_local_sweeper_.ContributeAndWaitForPromotedPagesIteration();

  // Join all concurrent tasks.
  minor_sweeping_st
"""


```