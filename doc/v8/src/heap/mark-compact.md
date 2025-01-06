Response: The user wants a summary of the C++ code file `v8/src/heap/mark-compact.cc`.
This is part 1 of 4, so the summary should focus on the functionality present in this specific chunk of code.

Based on the included headers and the class name `MarkCompactCollector`, this file likely deals with the mark-compact garbage collection algorithm used in V8.

Here's a breakdown of what the code seems to be doing:

1. **Includes:**  It includes many V8 internal headers related to heap management, memory allocation, garbage collection, and object representation. This suggests it's a core component of the GC.
2. **Verifiers:**  It defines a `FullMarkingVerifier` class, which is likely used for debugging and testing the correctness of the marking phase of the garbage collector.
3. **MarkCompactCollector Class:** This is the main class in the file. It seems to handle the overall mark-compact process.
4. **Initialization and Teardown:**  It has methods like `TearDown` and a constructor/destructor, suggesting it manages resources during the GC cycle.
5. **Evacuation Candidates:** It has logic for identifying "evacuation candidates" (`AddEvacuationCandidate`, `CollectEvacuationCandidates`), which are pages that might be compacted to reduce fragmentation.
6. **Compaction:**  Methods like `StartCompaction` indicate it controls the process of compacting memory.
7. **Marking:**  It has methods like `StartMarking`, `MarkLiveObjects`, and uses a `MainMarkingVisitor` to traverse the heap and mark live objects.
8. **Concurrency:** It deals with concurrent marking (`MaybeEnableBackgroundThreadsInCycle`, `FinishConcurrentMarking`).
9. **Garbage Collection Cycle:** The `CollectGarbage` method orchestrates the main phases of the mark-compact cycle.
10. **Verification:** It includes `VerifyMarkbitsAreClean` and `VerifyMarking` for ensuring the integrity of the marking process.
11. **Evacuation Heuristics:** `ComputeEvacuationHeuristics` suggests it uses strategies to decide which pages to evacuate.
12. **Preparation and Finishing:**  `Prepare` and `Finish` methods handle the setup and finalization of the GC cycle.
13. **Sweeping:**  It interacts with a `Sweeper` class and performs sweeping of garbage objects (`Sweep`, `SweepArrayBufferExtensions`).
14. **Object Movement:** It includes logic for moving objects during compaction (`Evacuate`, `EvacuateVisitorBase`).
15. **Weak Object Handling:** It has logic related to weak objects and uses a `MarkCompactWeakObjectRetainer`.
16. **Remembered Sets:**  The code interacts with remembered sets (like `OLD_TO_OLD`, `OLD_TO_NEW`, `OLD_TO_SHARED`) to track inter-generational object references.

**Relationship to JavaScript:**

The mark-compact garbage collector is a fundamental part of the V8 JavaScript engine. It reclaims memory occupied by objects that are no longer reachable from the JavaScript code.

Here's how the code relates to JavaScript functionality:

* **Memory Management:**  When JavaScript code creates objects (e.g., `let obj = {}`), this code is responsible for allocating memory for those objects. When those objects are no longer used, the mark-compact collector identifies them and reclaims their memory.
* **Preventing Memory Leaks:**  Without a garbage collector like the one implemented here, JavaScript programs could suffer from memory leaks, where unused memory is never freed, eventually causing the program to slow down or crash.

**JavaScript Example:**

```javascript
function createObject() {
  let myObject = { data: "important" };
  return myObject;
}

let globalReference = createObject(); // `globalReference` keeps the object alive

// ... later in the code ...

globalReference = null; // The object created inside `createObject` is now eligible for garbage collection if there are no other references to it.

// When the mark-compact collector runs, it will identify the object
// that was previously referenced by `globalReference` as no longer reachable
// and reclaim its memory. The code in `mark-compact.cc` is responsible
// for this process.
```

**Summary for Part 1:**

This part of the `mark-compact.cc` file defines the core structure and initial phases of the mark-compact garbage collector in V8. It includes the `MarkCompactCollector` class, which manages the overall GC process, including identifying pages for potential compaction (evacuation candidates), starting the marking phase to find live objects, and setting up for concurrent marking if enabled. This code is directly responsible for the low-level memory management required to run JavaScript code efficiently by reclaiming memory no longer in use. It uses various helper classes and data structures for tracking object liveness and inter-object references.

这是 `v8/src/heap/mark-compact.cc` 文件的第一部分，主要定义了 **Mark-Compact 垃圾回收器** 的基本框架和一些核心功能。以下是其功能的归纳：

1. **定义了 `MarkCompactCollector` 类**:  这是实现 Mark-Compact 垃圾回收算法的核心类。它包含了垃圾回收的各个阶段的逻辑。
2. **实现了标记（Marking）阶段的初步工作**:
    * 包含了用于验证标记结果的 `FullMarkingVerifier` 类，用于调试和确保标记的正确性。
    * 实现了 `StartMarking` 方法，负责初始化标记过程，例如设置标记位、创建工作队列等。
    * 定义了 `MainMarkingVisitor` 类，用于在主线程上遍历堆并标记可达对象。
3. **实现了压缩（Compaction）阶段的初步工作**:
    * 包含了识别可疏散页面的逻辑 (`AddEvacuationCandidate`, `CollectEvacuationCandidates`)。可疏散页面是垃圾较多，适合移动其上的存活对象以减少内存碎片化的页面。
    * 实现了 `StartCompaction` 方法，用于判断是否需要进行压缩，并选择合适的页面作为疏散候选。
4. **处理并发标记**: 包含了管理并发标记的逻辑 (`MaybeEnableBackgroundThreadsInCycle`, `FinishConcurrentMarking`)，允许在后台线程进行标记以减少主线程的停顿时间。
5. **定义了垃圾回收的主流程**:  `CollectGarbage` 方法是垃圾回收的主要入口，它会协调标记、记录对象统计信息、清除非活动引用、扫描等阶段。
6. **包含了用于验证和调试的功能**: 例如 `VerifyMarkbitsAreClean` 和 `VerifyMarking`，用于在开发阶段检查标记位的状态和标记结果的正确性。
7. **实现了计算疏散启发式策略的功能**: `ComputeEvacuationHeuristics` 用于根据当前内存状态和性能指标，决定哪些页面应该被疏散。
8. **定义了准备和完成垃圾回收的方法**: `Prepare` 方法用于垃圾回收前的准备工作，`Finish` 方法用于垃圾回收后的清理工作。
9. **与 `Sweeper` 类交互**:  该部分代码与负责清除未标记对象的 `Sweeper` 类进行交互。
10. **处理 ArrayBuffer 扩展**: 包含了清理 ArrayBuffer 扩展的逻辑 (`SweepArrayBufferExtensions`)。
11. **定义了用于特殊根对象体标记的访问器**: `CustomRootBodyMarkingVisitor` 用于标记一些特殊的、通过根对象保持存活的对象。
12. **定义了用于处理共享堆对象的访问器**: `SharedHeapObjectVisitor` 用于在垃圾回收过程中处理共享堆中的对象。
13. **定义了清理字符串常量表的访问器**: `InternalizedStringTableCleaner` 用于清理字符串常量表中不再使用的字符串。
14. **定义了用于在外部字符串表中标记外部指针的访问器**: `MarkExternalPointerFromExternalStringTable` 用于处理外部字符串中引用的外部指针。
15. **定义了弱对象保留策略**: `MarkCompactWeakObjectRetainer` 决定了在垃圾回收过程中如何处理弱引用对象。
16. **定义了记录迁移槽位的访问器**: `RecordMigratedSlotVisitor` 用于记录在压缩过程中对象移动后，需要更新的指针槽位。
17. **定义了迁移观察者模式**: 包含 `MigrationObserver` 和 `ProfilingMigrationObserver` 类，用于在对象迁移时执行额外的操作，例如性能分析。
18. **定义了对象疏散的基础访问器**: `EvacuateVisitorBase` 是一个抽象基类，用于实现对象疏散的具体逻辑。
19. **定义了疏散新生代对象的访问器**: `EvacuateNewSpaceVisitor` 专门用于将新生代的对象移动到老生代或者其他空间。

**与 JavaScript 的关系及示例:**

Mark-Compact 垃圾回收器是 V8 JavaScript 引擎的核心组成部分，它负责回收不再被 JavaScript 代码引用的对象所占用的内存。

当 JavaScript 代码创建对象时，例如：

```javascript
let myObject = { key: 'value' };
```

V8 会在堆内存中分配空间来存储这个对象。`MarkCompactCollector` 的代码（尤其是这部分）就负责管理这块堆内存。

当 JavaScript 代码不再使用这个对象时，例如：

```javascript
myObject = null;
```

如果没有任何其他地方引用这个对象，它就成为了垃圾。在垃圾回收的 **标记** 阶段，`MainMarkingVisitor` 会遍历所有从根对象可达的对象，`myObject` 由于不再可达，会被标记为垃圾。

在垃圾回收的 **压缩** 阶段，如果 `myObject` 所在的页面被选为疏散候选，那么该页面上的存活对象会被移动到其他页面，从而整理内存碎片。`EvacuateNewSpaceVisitor` 可能就负责处理新生代中 `myObject` 的移动。

**总结来说，这部分代码定义了 Mark-Compact 垃圾回收器的核心结构和初步流程，为后续的垃圾回收阶段奠定了基础。它直接影响着 JavaScript 程序的内存管理和性能。**

Prompt: 
```
这是目录为v8/src/heap/mark-compact.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/mark-compact.h"

#include <algorithm>
#include <atomic>
#include <iterator>
#include <memory>
#include <optional>
#include <unordered_map>
#include <unordered_set>

#include "src/base/bits.h"
#include "src/base/logging.h"
#include "src/base/platform/mutex.h"
#include "src/base/platform/platform.h"
#include "src/base/utils/random-number-generator.h"
#include "src/codegen/compilation-cache.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/execution.h"
#include "src/execution/frames-inl.h"
#include "src/execution/isolate-utils-inl.h"
#include "src/execution/isolate-utils.h"
#include "src/execution/vm-state-inl.h"
#include "src/flags/flags.h"
#include "src/handles/global-handles.h"
#include "src/heap/array-buffer-sweeper.h"
#include "src/heap/base/basic-slot-set.h"
#include "src/heap/concurrent-marking.h"
#include "src/heap/ephemeron-remembered-set.h"
#include "src/heap/evacuation-allocator-inl.h"
#include "src/heap/evacuation-verifier-inl.h"
#include "src/heap/gc-tracer-inl.h"
#include "src/heap/gc-tracer.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap-utils-inl.h"
#include "src/heap/heap-visitor-inl.h"
#include "src/heap/heap.h"
#include "src/heap/incremental-marking-inl.h"
#include "src/heap/index-generator.h"
#include "src/heap/large-spaces.h"
#include "src/heap/live-object-range-inl.h"
#include "src/heap/mark-compact-inl.h"
#include "src/heap/mark-sweep-utilities.h"
#include "src/heap/marking-barrier.h"
#include "src/heap/marking-inl.h"
#include "src/heap/marking-state-inl.h"
#include "src/heap/marking-visitor-inl.h"
#include "src/heap/marking.h"
#include "src/heap/memory-allocator.h"
#include "src/heap/memory-chunk-layout.h"
#include "src/heap/memory-chunk-metadata.h"
#include "src/heap/memory-measurement-inl.h"
#include "src/heap/memory-measurement.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/heap/new-spaces.h"
#include "src/heap/object-stats.h"
#include "src/heap/page-metadata-inl.h"
#include "src/heap/page-metadata.h"
#include "src/heap/parallel-work-item.h"
#include "src/heap/pretenuring-handler-inl.h"
#include "src/heap/pretenuring-handler.h"
#include "src/heap/read-only-heap.h"
#include "src/heap/read-only-spaces.h"
#include "src/heap/remembered-set.h"
#include "src/heap/safepoint.h"
#include "src/heap/slot-set.h"
#include "src/heap/spaces-inl.h"
#include "src/heap/sweeper.h"
#include "src/heap/traced-handles-marking-visitor.h"
#include "src/heap/weak-object-worklists.h"
#include "src/heap/zapping.h"
#include "src/init/v8.h"
#include "src/logging/tracing-flags.h"
#include "src/objects/embedder-data-array-inl.h"
#include "src/objects/foreign.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/heap-object-inl.h"
#include "src/objects/heap-object.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-objects-inl.h"
#include "src/objects/maybe-object.h"
#include "src/objects/objects.h"
#include "src/objects/slots-inl.h"
#include "src/objects/smi.h"
#include "src/objects/string-forwarding-table-inl.h"
#include "src/objects/transitions-inl.h"
#include "src/objects/visitors.h"
#include "src/sandbox/indirect-pointer-tag.h"
#include "src/snapshot/shared-heap-serializer.h"
#include "src/tasks/cancelable-task.h"
#include "src/tracing/tracing-category-observer.h"
#include "src/utils/utils-inl.h"

#ifdef V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-code-pointer-table.h"
#endif

namespace v8 {
namespace internal {

// =============================================================================
// Verifiers
// =============================================================================

#ifdef VERIFY_HEAP
namespace {

class FullMarkingVerifier : public MarkingVerifierBase {
 public:
  explicit FullMarkingVerifier(Heap* heap)
      : MarkingVerifierBase(heap),
        marking_state_(heap->non_atomic_marking_state()) {}

  void Run() override {
    VerifyRoots();
    VerifyMarking(heap_->new_space());
    VerifyMarking(heap_->new_lo_space());
    VerifyMarking(heap_->old_space());
    VerifyMarking(heap_->code_space());
    if (heap_->shared_space()) VerifyMarking(heap_->shared_space());
    VerifyMarking(heap_->lo_space());
    VerifyMarking(heap_->code_lo_space());
    if (heap_->shared_lo_space()) VerifyMarking(heap_->shared_lo_space());
    VerifyMarking(heap_->trusted_space());
    VerifyMarking(heap_->trusted_lo_space());
  }

 protected:
  const MarkingBitmap* bitmap(const MutablePageMetadata* chunk) override {
    return chunk->marking_bitmap();
  }

  bool IsMarked(Tagged<HeapObject> object) override {
    return marking_state_->IsMarked(object);
  }

  void VerifyMap(Tagged<Map> map) override { VerifyHeapObjectImpl(map); }

  void VerifyPointers(ObjectSlot start, ObjectSlot end) override {
    VerifyPointersImpl(start, end);
  }

  void VerifyPointers(MaybeObjectSlot start, MaybeObjectSlot end) override {
    VerifyPointersImpl(start, end);
  }

  void VerifyCodePointer(InstructionStreamSlot slot) override {
    Tagged<Object> maybe_code = slot.load(code_cage_base());
    Tagged<HeapObject> code;
    // The slot might contain smi during Code creation, so skip it.
    if (maybe_code.GetHeapObject(&code)) {
      VerifyHeapObjectImpl(code);
    }
  }

  void VerifyRootPointers(FullObjectSlot start, FullObjectSlot end) override {
    VerifyPointersImpl(start, end);
  }

  void VisitCodeTarget(Tagged<InstructionStream> host,
                       RelocInfo* rinfo) override {
    Tagged<InstructionStream> target =
        InstructionStream::FromTargetAddress(rinfo->target_address());
    VerifyHeapObjectImpl(target);
  }

  void VisitEmbeddedPointer(Tagged<InstructionStream> host,
                            RelocInfo* rinfo) override {
    CHECK(RelocInfo::IsEmbeddedObjectMode(rinfo->rmode()));
    Tagged<HeapObject> target_object = rinfo->target_object(cage_base());
    Tagged<Code> code = UncheckedCast<Code>(host->raw_code(kAcquireLoad));
    if (!code->IsWeakObject(target_object)) {
      VerifyHeapObjectImpl(target_object);
    }
  }

 private:
  V8_INLINE void VerifyHeapObjectImpl(Tagged<HeapObject> heap_object) {
    if (!ShouldVerifyObject(heap_object)) return;

    if (heap_->MustBeInSharedOldSpace(heap_object)) {
      CHECK(heap_->SharedHeapContains(heap_object));
    }

    CHECK(HeapLayout::InReadOnlySpace(heap_object) ||
          (v8_flags.black_allocated_pages &&
           HeapLayout::InBlackAllocatedPage(heap_object)) ||
          marking_state_->IsMarked(heap_object));
  }

  V8_INLINE bool ShouldVerifyObject(Tagged<HeapObject> heap_object) {
    const bool in_shared_heap = HeapLayout::InWritableSharedSpace(heap_object);
    return heap_->isolate()->is_shared_space_isolate() ? true : !in_shared_heap;
  }

  template <typename TSlot>
  V8_INLINE void VerifyPointersImpl(TSlot start, TSlot end) {
    PtrComprCageBase cage_base =
        GetPtrComprCageBaseFromOnHeapAddress(start.address());
    for (TSlot slot = start; slot < end; ++slot) {
      typename TSlot::TObject object = slot.load(cage_base);
#ifdef V8_ENABLE_DIRECT_HANDLE
      if (object.ptr() == kTaggedNullAddress) continue;
#endif
      Tagged<HeapObject> heap_object;
      if (object.GetHeapObjectIfStrong(&heap_object)) {
        VerifyHeapObjectImpl(heap_object);
      }
    }
  }

  NonAtomicMarkingState* const marking_state_;
};

}  // namespace
#endif  // VERIFY_HEAP

// ==================================================================
// MarkCompactCollector
// ==================================================================

namespace {

int NumberOfAvailableCores() {
  static int num_cores = V8::GetCurrentPlatform()->NumberOfWorkerThreads() + 1;
  // This number of cores should be greater than zero and never change.
  DCHECK_GE(num_cores, 1);
  DCHECK_EQ(num_cores, V8::GetCurrentPlatform()->NumberOfWorkerThreads() + 1);
  return num_cores;
}

int NumberOfParallelCompactionTasks(Heap* heap) {
  int tasks = v8_flags.parallel_compaction ? NumberOfAvailableCores() : 1;
  if (!heap->CanPromoteYoungAndExpandOldGeneration(
          static_cast<size_t>(tasks * PageMetadata::kPageSize))) {
    // Optimize for memory usage near the heap limit.
    tasks = 1;
  }
  return tasks;
}

}  // namespace

// This visitor is used for marking on the main thread. It is cheaper than
// the concurrent marking visitor because it does not snapshot JSObjects.
class MainMarkingVisitor final
    : public FullMarkingVisitorBase<MainMarkingVisitor> {
 public:
  MainMarkingVisitor(MarkingWorklists::Local* local_marking_worklists,
                     WeakObjects::Local* local_weak_objects, Heap* heap,
                     unsigned mark_compact_epoch,
                     base::EnumSet<CodeFlushMode> code_flush_mode,
                     bool should_keep_ages_unchanged,
                     uint16_t code_flushing_increase)
      : FullMarkingVisitorBase<MainMarkingVisitor>(
            local_marking_worklists, local_weak_objects, heap,
            mark_compact_epoch, code_flush_mode, should_keep_ages_unchanged,
            code_flushing_increase) {}

 private:
  // Functions required by MarkingVisitorBase.

  template <typename TSlot>
  void RecordSlot(Tagged<HeapObject> object, TSlot slot,
                  Tagged<HeapObject> target) {
    MarkCompactCollector::RecordSlot(object, slot, target);
  }

  void RecordRelocSlot(Tagged<InstructionStream> host, RelocInfo* rinfo,
                       Tagged<HeapObject> target) {
    MarkCompactCollector::RecordRelocSlot(host, rinfo, target);
  }

  friend class MarkingVisitorBase<MainMarkingVisitor>;
};

MarkCompactCollector::MarkCompactCollector(Heap* heap)
    : heap_(heap),
#ifdef DEBUG
      state_(IDLE),
#endif
      uses_shared_heap_(heap_->isolate()->has_shared_space()),
      is_shared_space_isolate_(heap_->isolate()->is_shared_space_isolate()),
      marking_state_(heap_->marking_state()),
      non_atomic_marking_state_(heap_->non_atomic_marking_state()),
      sweeper_(heap_->sweeper()) {
}

MarkCompactCollector::~MarkCompactCollector() = default;

void MarkCompactCollector::TearDown() {
  if (heap_->incremental_marking()->IsMajorMarking()) {
    local_marking_worklists_->Publish();
    heap_->main_thread_local_heap_->marking_barrier()->PublishIfNeeded();
    // Marking barriers of LocalHeaps will be published in their destructors.
    marking_worklists_.Clear();
    local_weak_objects()->Publish();
    weak_objects()->Clear();
  }
}

void MarkCompactCollector::AddEvacuationCandidate(PageMetadata* p) {
  DCHECK(!p->Chunk()->NeverEvacuate());
  DCHECK(!p->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));

  if (v8_flags.trace_evacuation_candidates) {
    PrintIsolate(
        heap_->isolate(),
        "Evacuation candidate: Free bytes: %6zu. Free Lists length: %4d.\n",
        p->area_size() - p->allocated_bytes(), p->ComputeFreeListsLength());
  }

  p->MarkEvacuationCandidate();
  evacuation_candidates_.push_back(p);
}

static void TraceFragmentation(PagedSpace* space) {
  int number_of_pages = space->CountTotalPages();
  intptr_t reserved = (number_of_pages * space->AreaSize());
  intptr_t free = reserved - space->SizeOfObjects();
  PrintF("[%s]: %d pages, %d (%.1f%%) free\n", ToString(space->identity()),
         number_of_pages, static_cast<int>(free),
         static_cast<double>(free) * 100 / reserved);
}

bool MarkCompactCollector::StartCompaction(StartCompactionMode mode) {
  DCHECK(!compacting_);
  DCHECK(evacuation_candidates_.empty());

  // Bailouts for completely disabled compaction.
  if (!v8_flags.compact ||
      (mode == StartCompactionMode::kAtomic && heap_->IsGCWithStack() &&
       !v8_flags.compact_with_stack) ||
      (v8_flags.gc_experiment_less_compaction &&
       !heap_->ShouldReduceMemory()) ||
      heap_->isolate()->serializer_enabled()) {
    return false;
  }

  CollectEvacuationCandidates(heap_->old_space());

  // Don't compact shared space when CSS is enabled, since there may be
  // DirectHandles on stacks of client isolates.
  if (!v8_flags.conservative_stack_scanning && heap_->shared_space()) {
    CollectEvacuationCandidates(heap_->shared_space());
  }

  CollectEvacuationCandidates(heap_->trusted_space());

  if (heap_->isolate()->AllowsCodeCompaction() &&
      (!heap_->IsGCWithStack() || v8_flags.compact_code_space_with_stack)) {
    CollectEvacuationCandidates(heap_->code_space());
  } else if (v8_flags.trace_fragmentation) {
    TraceFragmentation(heap_->code_space());
  }

  compacting_ = !evacuation_candidates_.empty();
  return compacting_;
}

namespace {

// Helper function to get the bytecode flushing mode based on the flags. This
// is required because it is not safe to access flags in concurrent marker.
base::EnumSet<CodeFlushMode> GetCodeFlushMode(Isolate* isolate) {
  if (isolate->disable_bytecode_flushing()) {
    return base::EnumSet<CodeFlushMode>();
  }

  base::EnumSet<CodeFlushMode> code_flush_mode;
  if (v8_flags.flush_bytecode) {
    code_flush_mode.Add(CodeFlushMode::kFlushBytecode);
  }

  if (v8_flags.flush_baseline_code) {
    code_flush_mode.Add(CodeFlushMode::kFlushBaselineCode);
  }

  if (v8_flags.stress_flush_code) {
    // This is to check tests accidentally don't miss out on adding either flush
    // bytecode or flush code along with stress flush code. stress_flush_code
    // doesn't do anything if either one of them isn't enabled.
    DCHECK(v8_flags.fuzzing || v8_flags.flush_baseline_code ||
           v8_flags.flush_bytecode);
    code_flush_mode.Add(CodeFlushMode::kStressFlushCode);
  }

  return code_flush_mode;
}

}  // namespace

void MarkCompactCollector::StartMarking() {
  // The state for background thread is saved here and maintained for the whole
  // GC cycle. Both CppHeap and regular V8 heap will refer to this flag.
  use_background_threads_in_cycle_ = heap_->ShouldUseBackgroundThreads();

  if (v8_flags.sticky_mark_bits) {
    heap()->Unmark();
  }

#ifdef V8_COMPRESS_POINTERS
  heap_->young_external_pointer_space()->StartCompactingIfNeeded();
  heap_->old_external_pointer_space()->StartCompactingIfNeeded();
  heap_->cpp_heap_pointer_space()->StartCompactingIfNeeded();
#endif  // V8_COMPRESS_POINTERS

  // CppHeap's marker must be initialized before the V8 marker to allow
  // exchanging of worklists.
  if (heap_->cpp_heap()) {
    TRACE_GC(heap()->tracer(), GCTracer::Scope::MC_MARK_EMBEDDER_PROLOGUE);
    CppHeap::From(heap_->cpp_heap())
        ->InitializeMarking(CppHeap::CollectionType::kMajor);
  }

  std::vector<Address> contexts =
      heap_->memory_measurement()->StartProcessing();
  if (v8_flags.stress_per_context_marking_worklist) {
    contexts.clear();
    HandleScope handle_scope(heap_->isolate());
    for (auto context : heap_->FindAllNativeContexts()) {
      contexts.push_back(context->ptr());
    }
  }
  heap_->tracer()->NotifyMarkingStart();
  code_flush_mode_ = GetCodeFlushMode(heap_->isolate());
  marking_worklists_.CreateContextWorklists(contexts);
  auto* cpp_heap = CppHeap::From(heap_->cpp_heap_);
  local_marking_worklists_ = std::make_unique<MarkingWorklists::Local>(
      &marking_worklists_,
      cpp_heap ? cpp_heap->CreateCppMarkingStateForMutatorThread()
               : MarkingWorklists::Local::kNoCppMarkingState);
  local_weak_objects_ = std::make_unique<WeakObjects::Local>(weak_objects());
  marking_visitor_ = std::make_unique<MainMarkingVisitor>(
      local_marking_worklists_.get(), local_weak_objects_.get(), heap_, epoch(),
      code_flush_mode(), heap_->ShouldCurrentGCKeepAgesUnchanged(),
      heap_->tracer()->CodeFlushingIncrease());
  // This method evicts SFIs with flushed bytecode from the cache before
  // iterating the compilation cache as part of the root set. SFIs that get
  // flushed in this GC cycle will get evicted out of the cache in the next GC
  // cycle. The SFI will remain in the cache until then and may remain in the
  // cache even longer in case the SFI is re-compiled.
  heap_->isolate()->compilation_cache()->MarkCompactPrologue();
  // Marking bits are cleared by the sweeper or unmarker (if sticky mark-bits
  // are enabled).
#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) {
    VerifyMarkbitsAreClean();
  }
#endif  // VERIFY_HEAP
}

void MarkCompactCollector::MaybeEnableBackgroundThreadsInCycle(
    CallOrigin origin) {
  if (v8_flags.concurrent_marking && !use_background_threads_in_cycle_) {
    // With --parallel_pause_for_gc_in_background we force background threads in
    // the atomic pause.
    const bool force_background_threads =
        v8_flags.parallel_pause_for_gc_in_background &&
        origin == CallOrigin::kAtomicGC;
    use_background_threads_in_cycle_ =
        force_background_threads || heap()->ShouldUseBackgroundThreads();

    if (use_background_threads_in_cycle_) {
      heap_->concurrent_marking()->RescheduleJobIfNeeded(
          GarbageCollector::MARK_COMPACTOR);

      if (auto* cpp_heap = CppHeap::From(heap_->cpp_heap_)) {
        cpp_heap->ReEnableConcurrentMarking();
      }
    }
  }
}

void MarkCompactCollector::CollectGarbage() {
  // Make sure that Prepare() has been called. The individual steps below will
  // update the state as they proceed.
  DCHECK(state_ == PREPARE_GC);

  MaybeEnableBackgroundThreadsInCycle(CallOrigin::kAtomicGC);

  MarkLiveObjects();
  // This will walk dead object graphs and so requires that all references are
  // still intact.
  RecordObjectStats();
  ClearNonLiveReferences();
  VerifyMarking();

  if (auto* cpp_heap = CppHeap::From(heap_->cpp_heap_)) {
    cpp_heap->FinishMarkingAndProcessWeakness();
  }

  heap_->memory_measurement()->FinishProcessing(native_context_stats_);

  Sweep();
  Evacuate();
  Finish();
}

#ifdef VERIFY_HEAP

void MarkCompactCollector::VerifyMarkbitsAreClean(PagedSpaceBase* space) {
  for (PageMetadata* p : *space) {
    CHECK(p->marking_bitmap()->IsClean());
    CHECK_EQ(0, p->live_bytes());
  }
}

void MarkCompactCollector::VerifyMarkbitsAreClean(NewSpace* space) {
  if (!space) return;
  if (v8_flags.minor_ms) {
    VerifyMarkbitsAreClean(PagedNewSpace::From(space)->paged_space());
    return;
  }
  for (PageMetadata* p : *space) {
    CHECK(p->marking_bitmap()->IsClean());
    CHECK_EQ(0, p->live_bytes());
  }
}

void MarkCompactCollector::VerifyMarkbitsAreClean(LargeObjectSpace* space) {
  if (!space) return;
  LargeObjectSpaceObjectIterator it(space);
  for (Tagged<HeapObject> obj = it.Next(); !obj.is_null(); obj = it.Next()) {
    CHECK(non_atomic_marking_state_->IsUnmarked(obj));
    CHECK_EQ(0, MutablePageMetadata::FromHeapObject(obj)->live_bytes());
  }
}

void MarkCompactCollector::VerifyMarkbitsAreClean() {
  VerifyMarkbitsAreClean(heap_->old_space());
  VerifyMarkbitsAreClean(heap_->code_space());
  VerifyMarkbitsAreClean(heap_->new_space());
  VerifyMarkbitsAreClean(heap_->lo_space());
  VerifyMarkbitsAreClean(heap_->code_lo_space());
  VerifyMarkbitsAreClean(heap_->new_lo_space());
  VerifyMarkbitsAreClean(heap_->trusted_space());
  VerifyMarkbitsAreClean(heap_->trusted_lo_space());
}

#endif  // VERIFY_HEAP

void MarkCompactCollector::ComputeEvacuationHeuristics(
    size_t area_size, int* target_fragmentation_percent,
    size_t* max_evacuated_bytes) {
  // For memory reducing and optimize for memory mode we directly define both
  // constants.
  const int kTargetFragmentationPercentForReduceMemory = 20;
  const size_t kMaxEvacuatedBytesForReduceMemory = 12 * MB;
  const int kTargetFragmentationPercentForOptimizeMemory = 20;
  const size_t kMaxEvacuatedBytesForOptimizeMemory = 6 * MB;

  // For regular mode (which is latency critical) we define less aggressive
  // defaults to start and switch to a trace-based (using compaction speed)
  // approach as soon as we have enough samples.
  const int kTargetFragmentationPercent = 70;
  const size_t kMaxEvacuatedBytes = 4 * MB;
  // Time to take for a single area (=payload of page). Used as soon as there
  // exist enough compaction speed samples.
  const float kTargetMsPerArea = .5;

  if (heap_->ShouldReduceMemory()) {
    *target_fragmentation_percent = kTargetFragmentationPercentForReduceMemory;
    *max_evacuated_bytes = kMaxEvacuatedBytesForReduceMemory;
  } else if (heap_->ShouldOptimizeForMemoryUsage()) {
    *target_fragmentation_percent =
        kTargetFragmentationPercentForOptimizeMemory;
    *max_evacuated_bytes = kMaxEvacuatedBytesForOptimizeMemory;
  } else {
    const double estimated_compaction_speed =
        heap_->tracer()->CompactionSpeedInBytesPerMillisecond();
    if (estimated_compaction_speed != 0) {
      // Estimate the target fragmentation based on traced compaction speed
      // and a goal for a single page.
      const double estimated_ms_per_area =
          1 + area_size / estimated_compaction_speed;
      *target_fragmentation_percent = static_cast<int>(
          100 - 100 * kTargetMsPerArea / estimated_ms_per_area);
      if (*target_fragmentation_percent <
          kTargetFragmentationPercentForReduceMemory) {
        *target_fragmentation_percent =
            kTargetFragmentationPercentForReduceMemory;
      }
    } else {
      *target_fragmentation_percent = kTargetFragmentationPercent;
    }
    *max_evacuated_bytes = kMaxEvacuatedBytes;
  }
}

void MarkCompactCollector::CollectEvacuationCandidates(PagedSpace* space) {
  DCHECK(space->identity() == OLD_SPACE || space->identity() == CODE_SPACE ||
         space->identity() == SHARED_SPACE ||
         space->identity() == TRUSTED_SPACE);

  int number_of_pages = space->CountTotalPages();
  size_t area_size = space->AreaSize();

  const bool in_standard_path =
      !(v8_flags.manual_evacuation_candidates_selection ||
        v8_flags.stress_compaction_random || v8_flags.stress_compaction ||
        v8_flags.compact_on_every_full_gc);
  // Those variables will only be initialized if |in_standard_path|, and are not
  // used otherwise.
  size_t max_evacuated_bytes;
  int target_fragmentation_percent;
  size_t free_bytes_threshold;
  if (in_standard_path) {
    // We use two conditions to decide whether a page qualifies as an evacuation
    // candidate, or not:
    // * Target fragmentation: How fragmented is a page, i.e., how is the ratio
    //   between live bytes and capacity of this page (= area).
    // * Evacuation quota: A global quota determining how much bytes should be
    //   compacted.
    ComputeEvacuationHeuristics(area_size, &target_fragmentation_percent,
                                &max_evacuated_bytes);
    free_bytes_threshold = target_fragmentation_percent * (area_size / 100);
  }

  // Pairs of (live_bytes_in_page, page).
  using LiveBytesPagePair = std::pair<size_t, PageMetadata*>;
  std::vector<LiveBytesPagePair> pages;
  pages.reserve(number_of_pages);

  DCHECK(!sweeper_->sweeping_in_progress());
  for (PageMetadata* p : *space) {
    MemoryChunk* chunk = p->Chunk();
    if (chunk->NeverEvacuate() || !chunk->CanAllocate()) continue;

    if (chunk->IsPinned()) {
      DCHECK(!chunk->IsFlagSet(
          MemoryChunk::FORCE_EVACUATION_CANDIDATE_FOR_TESTING));
      continue;
    }

    // Invariant: Evacuation candidates are just created when marking is
    // started. This means that sweeping has finished. Furthermore, at the end
    // of a GC all evacuation candidates are cleared and their slot buffers are
    // released.
    CHECK(!chunk->IsEvacuationCandidate());
    CHECK_NULL(p->slot_set<OLD_TO_OLD>());
    CHECK_NULL(p->typed_slot_set<OLD_TO_OLD>());
    CHECK(p->SweepingDone());
    DCHECK(p->area_size() == area_size);
    if (in_standard_path) {
      // Only the pages with at more than |free_bytes_threshold| free bytes are
      // considered for evacuation.
      if (area_size - p->allocated_bytes() >= free_bytes_threshold) {
        pages.push_back(std::make_pair(p->allocated_bytes(), p));
      }
    } else {
      pages.push_back(std::make_pair(p->allocated_bytes(), p));
    }
  }

  int candidate_count = 0;
  size_t total_live_bytes = 0;

  const bool reduce_memory = heap_->ShouldReduceMemory();
  if (v8_flags.manual_evacuation_candidates_selection) {
    for (size_t i = 0; i < pages.size(); i++) {
      PageMetadata* p = pages[i].second;
      MemoryChunk* chunk = p->Chunk();
      if (chunk->IsFlagSet(
              MemoryChunk::FORCE_EVACUATION_CANDIDATE_FOR_TESTING)) {
        candidate_count++;
        total_live_bytes += pages[i].first;
        chunk->ClearFlagSlow(
            MemoryChunk::FORCE_EVACUATION_CANDIDATE_FOR_TESTING);
        AddEvacuationCandidate(p);
      }
    }
  } else if (v8_flags.stress_compaction_random) {
    double fraction = heap_->isolate()->fuzzer_rng()->NextDouble();
    size_t pages_to_mark_count =
        static_cast<size_t>(fraction * (pages.size() + 1));
    for (uint64_t i : heap_->isolate()->fuzzer_rng()->NextSample(
             pages.size(), pages_to_mark_count)) {
      candidate_count++;
      total_live_bytes += pages[i].first;
      AddEvacuationCandidate(pages[i].second);
    }
  } else if (v8_flags.stress_compaction) {
    for (size_t i = 0; i < pages.size(); i++) {
      PageMetadata* p = pages[i].second;
      if (i % 2 == 0) {
        candidate_count++;
        total_live_bytes += pages[i].first;
        AddEvacuationCandidate(p);
      }
    }
  } else {
    // The following approach determines the pages that should be evacuated.
    //
    // Sort pages from the most free to the least free, then select
    // the first n pages for evacuation such that:
    // - the total size of evacuated objects does not exceed the specified
    // limit.
    // - fragmentation of (n+1)-th page does not exceed the specified limit.
    std::sort(pages.begin(), pages.end(),
              [](const LiveBytesPagePair& a, const LiveBytesPagePair& b) {
                return a.first < b.first;
              });
    for (size_t i = 0; i < pages.size(); i++) {
      size_t live_bytes = pages[i].first;
      DCHECK_GE(area_size, live_bytes);
      if (v8_flags.compact_on_every_full_gc ||
          ((total_live_bytes + live_bytes) <= max_evacuated_bytes)) {
        candidate_count++;
        total_live_bytes += live_bytes;
      }
      if (v8_flags.trace_fragmentation_verbose) {
        PrintIsolate(heap_->isolate(),
                     "compaction-selection-page: space=%s free_bytes_page=%zu "
                     "fragmentation_limit_kb=%zu "
                     "fragmentation_limit_percent=%d sum_compaction_kb=%zu "
                     "compaction_limit_kb=%zu\n",
                     ToString(space->identity()), (area_size - live_bytes) / KB,
                     free_bytes_threshold / KB, target_fragmentation_percent,
                     total_live_bytes / KB, max_evacuated_bytes / KB);
      }
    }
    // How many pages we will allocated for the evacuated objects
    // in the worst case: ceil(total_live_bytes / area_size)
    int estimated_new_pages =
        static_cast<int>((total_live_bytes + area_size - 1) / area_size);
    DCHECK_LE(estimated_new_pages, candidate_count);
    int estimated_released_pages = candidate_count - estimated_new_pages;
    // Avoid (compact -> expand) cycles.
    if ((estimated_released_pages == 0) && !v8_flags.compact_on_every_full_gc) {
      candidate_count = 0;
    }
    for (int i = 0; i < candidate_count; i++) {
      AddEvacuationCandidate(pages[i].second);
    }
  }

  if (v8_flags.trace_fragmentation) {
    PrintIsolate(heap_->isolate(),
                 "compaction-selection: space=%s reduce_memory=%d pages=%d "
                 "total_live_bytes=%zu\n",
                 ToString(space->identity()), reduce_memory, candidate_count,
                 total_live_bytes / KB);
  }
}

void MarkCompactCollector::Prepare() {
#ifdef DEBUG
  DCHECK(state_ == IDLE);
  state_ = PREPARE_GC;
#endif

  DCHECK(!sweeper_->sweeping_in_progress());

  DCHECK_IMPLIES(heap_->incremental_marking()->IsMarking(),
                 heap_->incremental_marking()->IsMajorMarking());
  if (!heap_->incremental_marking()->IsMarking()) {
    StartCompaction(StartCompactionMode::kAtomic);
    StartMarking();
    if (heap_->cpp_heap_) {
      TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_MARK_EMBEDDER_PROLOGUE);
      // StartTracing immediately starts marking which requires V8 worklists to
      // be set up.
      CppHeap::From(heap_->cpp_heap_)->StartMarking();
    }
  }
  if (auto* new_space = heap_->new_space()) {
    new_space->GarbageCollectionPrologue();
  }
  if (heap_->use_new_space()) {
    DCHECK_EQ(
        heap_->allocator()->new_space_allocator()->top(),
        heap_->allocator()->new_space_allocator()->original_top_acquire());
  }
}

void MarkCompactCollector::FinishConcurrentMarking() {
  // FinishConcurrentMarking is called for both, concurrent and parallel,
  // marking. It is safe to call this function when tasks are already finished.
  DCHECK_EQ(heap_->concurrent_marking()->garbage_collector(),
            GarbageCollector::MARK_COMPACTOR);
  if (v8_flags.parallel_marking || v8_flags.concurrent_marking) {
    heap_->concurrent_marking()->Join();
    heap_->concurrent_marking()->FlushMemoryChunkData();
    heap_->concurrent_marking()->FlushNativeContexts(&native_context_stats_);
  }
  if (auto* cpp_heap = CppHeap::From(heap_->cpp_heap_)) {
    cpp_heap->FinishConcurrentMarkingIfNeeded();
  }
}

void MarkCompactCollector::VerifyMarking() {
  CHECK(local_marking_worklists_->IsEmpty());
  DCHECK(heap_->incremental_marking()->IsStopped());
#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_MARK_VERIFY);
    FullMarkingVerifier verifier(heap_);
    verifier.Run();
    heap_->old_space()->VerifyLiveBytes();
    heap_->code_space()->VerifyLiveBytes();
    if (heap_->shared_space()) heap_->shared_space()->VerifyLiveBytes();
    heap_->trusted_space()->VerifyLiveBytes();
    if (v8_flags.minor_ms && heap_->paged_new_space())
      heap_->paged_new_space()->paged_space()->VerifyLiveBytes();
  }
#endif  // VERIFY_HEAP
}

namespace {

void ShrinkPagesToObjectSizes(Heap* heap, OldLargeObjectSpace* space) {
  size_t surviving_object_size = 0;
  PtrComprCageBase cage_base(heap->isolate());
  for (auto it = space->begin(); it != space->end();) {
    LargePageMetadata* current = *(it++);
    Tagged<HeapObject> object = current->GetObject();
    const size_t object_size = static_cast<size_t>(object->Size(cage_base));
    space->ShrinkPageToObjectSize(current, object, object_size);
    surviving_object_size += object_size;
  }
  space->set_objects_size(surviving_object_size);
}

}  // namespace

void MarkCompactCollector::Finish() {
  {
    TRACE_GC_EPOCH_WITH_FLOW(
        heap_->tracer(), GCTracer::Scope::MC_SWEEP, ThreadKind::kMain,
        sweeper_->GetTraceIdForFlowEvent(GCTracer::Scope::MC_SWEEP),
        TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);

    // Delay releasing empty new space pages and dead new large object pages
    // until after pointer updating is done because dead old space objects may
    // have slots pointing to these pages and will need to be updated.
    DCHECK_IMPLIES(!v8_flags.minor_ms,
                   empty_new_space_pages_to_be_swept_.empty());
    if (!empty_new_space_pages_to_be_swept_.empty()) {
      GCTracer::Scope sweep_scope(
          heap_->tracer(), GCTracer::Scope::MC_SWEEP_NEW, ThreadKind::kMain);
      for (PageMetadata* p : empty_new_space_pages_to_be_swept_) {
        // Sweeping empty pages already relinks them to the freelist.
        sweeper_->SweepEmptyNewSpacePage(p);
      }
      empty_new_space_pages_to_be_swept_.clear();
    }

    if (heap_->new_lo_space()) {
      TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_SWEEP_NEW_LO);
      SweepLargeSpace(heap_->new_lo_space());
    }

#ifdef DEBUG
    heap_->VerifyCountersBeforeConcurrentSweeping(
        GarbageCollector::MARK_COMPACTOR);
#endif  // DEBUG
  }

  if (auto* new_space = heap_->new_space()) {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_EVACUATE);
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_EVACUATE_REBALANCE);
    // We rebalance first to be able to assume that from- and to-space have the
    // same size.
    //
    // TODO(365027679): Make growing/shrinking more flexible to avoid ensuring
    // the same capacity.
    if (!new_space->EnsureCurrentCapacity()) {
      heap_->FatalProcessOutOfMemory("NewSpace::EnsureCurrentCapacity");
    }
    // With Minor MS we have already set the mode at the beginning of sweeping
    // the young generation.
    if (!v8_flags.minor_ms) {
      DCHECK_EQ(Heap::ResizeNewSpaceMode::kNone, resize_new_space_);
      resize_new_space_ = heap_->ShouldResizeNewSpace();
    }
    switch (resize_new_space_) {
      case ResizeNewSpaceMode::kShrink:
        heap_->ReduceNewSpaceSize();
        break;
      case ResizeNewSpaceMode::kGrow:
        heap_->ExpandNewSpaceSize();
        break;
      case ResizeNewSpaceMode::kNone:
        break;
    }
    resize_new_space_ = ResizeNewSpaceMode::kNone;
  }

  TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_FINISH);

  if (heap_->new_space()) {
    DCHECK(!heap_->allocator()->new_space_allocator()->IsLabValid());
    heap_->new_space()->GarbageCollectionEpilogue();
  }

  auto* isolate = heap_->isolate();
  isolate->global_handles()->ClearListOfYoungNodes();

  SweepArrayBufferExtensions();

  marking_visitor_.reset();
  local_marking_worklists_.reset();
  marking_worklists_.ReleaseContextWorklists();
  native_context_stats_.Clear();

  CHECK(weak_objects_.current_ephemerons.IsEmpty());
  CHECK(weak_objects_.discovered_ephemerons.IsEmpty());
  local_weak_objects_->next_ephemerons_local.Publish();
  local_weak_objects_.reset();
  weak_objects_.next_ephemerons.Clear();

  sweeper_->StartMajorSweeperTasks();

  // Release empty pages now, when the pointer-update phase is done.
  heap_->memory_allocator()->ReleaseQueuedPages();

  // Shrink pages if possible after processing and filtering slots.
  ShrinkPagesToObjectSizes(heap_, heap_->lo_space());

#ifdef DEBUG
  DCHECK(state_ == SWEEP_SPACES || state_ == RELOCATE_OBJECTS);
  state_ = IDLE;
#endif

  if (have_code_to_deoptimize_) {
    // Some code objects were marked for deoptimization during the GC.
    Deoptimizer::DeoptimizeMarkedCode(isolate);
    have_code_to_deoptimize_ = false;
  }
}

void MarkCompactCollector::SweepArrayBufferExtensions() {
  DCHECK_IMPLIES(heap_->new_space(), heap_->new_space()->Size() == 0);
  DCHECK_IMPLIES(heap_->new_lo_space(), heap_->new_lo_space()->Size() == 0);
  heap_->array_buffer_sweeper()->RequestSweep(
      ArrayBufferSweeper::SweepingType::kFull,
      ArrayBufferSweeper::TreatAllYoungAsPromoted::kYes);
}

// This visitor is used to visit the body of special objects held alive by
// other roots.
//
// It is currently used for
// - InstructionStream held alive by the top optimized frame. This code cannot
// be deoptimized and thus have to be kept alive in an isolate way, i.e., it
// should not keep alive other code objects reachable through the weak list but
// they should keep alive its embedded pointers (which would otherwise be
// dropped).
// - Prefix of the string table.
// - If V8_ENABLE_SANDBOX, client Isolates' waiter queue node
// ExternalPointer_t in shared Isolates.
class MarkCompactCollector::CustomRootBodyMarkingVisitor final
    : public ObjectVisitorWithCageBases {
 public:
  explicit CustomRootBodyMarkingVisitor(MarkCompactCollector* collector)
      : ObjectVisitorWithCageBases(collector->heap_->isolate()),
        collector_(collector) {}

  void VisitPointer(Tagged<HeapObject> host, ObjectSlot p) final {
    MarkObject(host, p.load(cage_base()));
  }

  void VisitMapPointer(Tagged<HeapObject> host) final {
    MarkObject(host, host->map(cage_base()));
  }

  void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                     ObjectSlot end) final {
    for (ObjectSlot p = start; p < end; ++p) {
      // The map slot should be handled in VisitMapPointer.
      DCHECK_NE(host->map_slot(), p);
      DCHECK(!HasWeakHeapObjectTag(p.load(cage_base())));
      MarkObject(host, p.load(cage_base()));
    }
  }

  void VisitInstructionStreamPointer(Tagged<Code> host,
                                     InstructionStreamSlot slot) override {
    MarkObject(host, slot.load(code_cage_base()));
  }

  void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                     MaybeObjectSlot end) final {
    // At the moment, custom roots cannot contain weak pointers.
    UNREACHABLE();
  }

  void VisitCodeTarget(Tagged<InstructionStream> host,
                       RelocInfo* rinfo) override {
    Tagged<InstructionStream> target =
        InstructionStream::FromTargetAddress(rinfo->target_address());
    MarkObject(host, target);
  }

  void VisitEmbeddedPointer(Tagged<InstructionStream> host,
                            RelocInfo* rinfo) override {
    MarkObject(host, rinfo->target_object(cage_base()));
  }

 private:
  V8_INLINE void MarkObject(Tagged<HeapObject> host, Tagged<Object> object) {
    if (!IsHeapObject(object)) return;
    Tagged<HeapObject> heap_object = Cast<HeapObject>(object);
    const auto target_worklist =
        MarkingHelper::ShouldMarkObject(collector_->heap(), heap_object);
    if (!target_worklist) {
      return;
    }
    collector_->MarkObject(host, heap_object, target_worklist.value());
  }

  MarkCompactCollector* const collector_;
};

class MarkCompactCollector::SharedHeapObjectVisitor final
    : public HeapVisitor<MarkCompactCollector::SharedHeapObjectVisitor> {
 public:
  explicit SharedHeapObjectVisitor(MarkCompactCollector* collector)
      : HeapVisitor(collector->heap_->isolate()), collector_(collector) {}

  void VisitPointer(Tagged<HeapObject> host, ObjectSlot p) final {
    CheckForSharedObject(host, p, p.load(cage_base()));
  }

  void VisitPointer(Tagged<HeapObject> host, MaybeObjectSlot p) final {
    Tagged<MaybeObject> object = p.load(cage_base());
    Tagged<HeapObject> heap_object;
    if (object.GetHeapObject(&heap_object))
      CheckForSharedObject(host, ObjectSlot(p), heap_object);
  }

  void VisitMapPointer(Tagged<HeapObject> host) final {
    CheckForSharedObject(host, host->map_slot(), host->map(cage_base()));
  }

  void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                     ObjectSlot end) final {
    for (ObjectSlot p = start; p < end; ++p) {
      // The map slot should be handled in VisitMapPointer.
      DCHECK_NE(host->map_slot(), p);
      DCHECK(!HasWeakHeapObjectTag(p.load(cage_base())));
      CheckForSharedObject(host, p, p.load(cage_base()));
    }
  }

  void VisitInstructionStreamPointer(Tagged<Code> host,
                                     InstructionStreamSlot slot) override {
    UNREACHABLE();
  }

  void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                     MaybeObjectSlot end) final {
    for (MaybeObjectSlot p = start; p < end; ++p) {
      // The map slot should be handled in VisitMapPointer.
      DCHECK_NE(host->map_slot(), ObjectSlot(p));
      VisitPointer(host, p);
    }
  }

  void VisitCodeTarget(Tagged<InstructionStream> host,
                       RelocInfo* rinfo) override {
    UNREACHABLE();
  }

  void VisitEmbeddedPointer(Tagged<InstructionStream> host,
                            RelocInfo* rinfo) override {
    UNREACHABLE();
  }

 private:
  V8_INLINE void CheckForSharedObject(Tagged<HeapObject> host, ObjectSlot slot,
                                      Tagged<Object> object) {
    DCHECK(!HeapLayout::InAnySharedSpace(host));
    Tagged<HeapObject> heap_object;
    if (!object.GetHeapObject(&heap_object)) return;
    if (!HeapLayout::InWritableSharedSpace(heap_object)) return;
    DCHECK(HeapLayout::InWritableSharedSpace(heap_object));
    MemoryChunk* host_chunk = MemoryChunk::FromHeapObject(host);
    MutablePageMetadata* host_page_metadata =
        MutablePageMetadata::cast(host_chunk->Metadata());
    DCHECK(HeapLayout::InYoungGeneration(host));
    // Temporarily record new-to-shared slots in the old-to-shared remembered
    // set so we don't need to iterate the page again later for updating the
    // references.
    RememberedSet<OLD_TO_SHARED>::Insert<AccessMode::NON_ATOMIC>(
        host_page_metadata, host_chunk->Offset(slot.address()));
    if (MarkingHelper::ShouldMarkObject(collector_->heap(), heap_object)) {
      collector_->MarkRootObject(Root::kClientHeap, heap_object,
                                 MarkingHelper::WorklistTarget::kRegular);
    }
  }

  MarkCompactCollector* const collector_;
};

class InternalizedStringTableCleaner final : public RootVisitor {
 public:
  explicit InternalizedStringTableCleaner(Heap* heap) : heap_(heap) {}

  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    UNREACHABLE();
  }

  void VisitRootPointers(Root root, const char* description,
                         OffHeapObjectSlot start,
                         OffHeapObjectSlot end) override {
    DCHECK_EQ(root, Root::kStringTable);
    // Visit all HeapObject pointers in [start, end).
    Isolate* const isolate = heap_->isolate();
    for (OffHeapObjectSlot p = start; p < end; ++p) {
      Tagged<Object> o = p.load(isolate);
      if (IsHeapObject(o)) {
        Tagged<HeapObject> heap_object = Cast<HeapObject>(o);
        DCHECK(!HeapLayout::InYoungGeneration(heap_object));
        if (MarkingHelper::IsUnmarkedAndNotAlwaysLive(
                heap_, heap_->marking_state(), heap_object)) {
          pointers_removed_++;
          p.store(StringTable::deleted_element());
        }
      }
    }
  }

  int PointersRemoved() const { return pointers_removed_; }

 private:
  Heap* heap_;
  int pointers_removed_ = 0;
};

#ifdef V8_ENABLE_SANDBOX
class MarkExternalPointerFromExternalStringTable : public RootVisitor {
 public:
  explicit MarkExternalPointerFromExternalStringTable(
      ExternalPointerTable* shared_table, ExternalPointerTable::Space* space)
      : visitor(shared_table, space) {}

  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    // Visit all HeapObject pointers in [start, end).
    for (FullObjectSlot p = start; p < end; ++p) {
      Tagged<Object> o = *p;
      if (IsHeapObject(o)) {
        Tagged<HeapObject> heap_object = Cast<HeapObject>(o);
        if (IsExternalString(heap_object)) {
          Tagged<ExternalString> string = Cast<ExternalString>(heap_object);
          string->VisitExternalPointers(&visitor);
        } else {
          // The original external string may have been internalized.
          DCHECK(IsThinString(o));
        }
      }
    }
  }

 private:
  class MarkExternalPointerTableVisitor : public ObjectVisitor {
   public:
    explicit MarkExternalPointerTableVisitor(ExternalPointerTable* table,
                                             ExternalPointerTable::Space* space)
        : table_(table), space_(space) {}
    void VisitExternalPointer(Tagged<HeapObject> host,
                              ExternalPointerSlot slot) override {
      DCHECK_NE(slot.tag(), kExternalPointerNullTag);
      DCHECK(IsSharedExternalPointerType(slot.tag()));
      ExternalPointerHandle handle = slot.Relaxed_LoadHandle();
      table_->Mark(space_, handle, slot.address());
    }
    void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                       ObjectSlot end) override {
      UNREACHABLE();
    }
    void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                       MaybeObjectSlot end) override {
      UNREACHABLE();
    }
    void VisitInstructionStreamPointer(Tagged<Code> host,
                                       InstructionStreamSlot slot) override {
      UNREACHABLE();
    }
    void VisitCodeTarget(Tagged<InstructionStream> host,
                         RelocInfo* rinfo) override {
      UNREACHABLE();
    }
    void VisitEmbeddedPointer(Tagged<InstructionStream> host,
                              RelocInfo* rinfo) override {
      UNREACHABLE();
    }

   private:
    ExternalPointerTable* table_;
    ExternalPointerTable::Space* space_;
  };

  MarkExternalPointerTableVisitor visitor;
};
#endif  // V8_ENABLE_SANDBOX

// Implementation of WeakObjectRetainer for mark compact GCs. All marked objects
// are retained.
class MarkCompactWeakObjectRetainer : public WeakObjectRetainer {
 public:
  MarkCompactWeakObjectRetainer(Heap* heap, MarkingState* marking_state)
      : heap_(heap), marking_state_(marking_state) {}

  Tagged<Object> RetainAs(Tagged<Object> object) override {
    Tagged<HeapObject> heap_object = Cast<HeapObject>(object);
    if (MarkingHelper::IsMarkedOrAlwaysLive(heap_, marking_state_,
                                            heap_object)) {
      return object;
    } else if (IsAllocationSite(object) &&
               !Cast<AllocationSite>(object)->IsZombie()) {
      // "dead" AllocationSites need to live long enough for a traversal of new
      // space. These sites get a one-time reprieve.

      Tagged<Object> nested = object;
      while (IsAllocationSite(nested)) {
        Tagged<AllocationSite> current_site = Cast<AllocationSite>(nested);
        // MarkZombie will override the nested_site, read it first before
        // marking
        nested = current_site->nested_site();
        current_site->MarkZombie();
        marking_state_->TryMarkAndAccountLiveBytes(current_site);
      }

      return object;
    } else {
      return Smi::zero();
    }
  }

 private:
  Heap* const heap_;
  MarkingState* const marking_state_;
};

class RecordMigratedSlotVisitor
    : public HeapVisitor<RecordMigratedSlotVisitor> {
 public:
  explicit RecordMigratedSlotVisitor(Heap* heap)
      : HeapVisitor(heap->isolate()), heap_(heap) {}

  V8_INLINE static constexpr bool UsePrecomputedObjectSize() { return true; }

  inline void VisitPointer(Tagged<HeapObject> host, ObjectSlot p) final {
    DCHECK(!HasWeakHeapObjectTag(p.load(cage_base())));
    RecordMigratedSlot(host, p.load(cage_base()), p.address());
  }

  inline void VisitMapPointer(Tagged<HeapObject> host) final {
    VisitPointer(host, host->map_slot());
  }

  inline void VisitPointer(Tagged<HeapObject> host, MaybeObjectSlot p) final {
    DCHECK(!MapWord::IsPacked(p.Relaxed_Load(cage_base()).ptr()));
    RecordMigratedSlot(host, p.load(cage_base()), p.address());
  }

  inline void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                            ObjectSlot end) final {
    while (start < end) {
      VisitPointer(host, start);
      ++start;
    }
  }

  inline void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                            MaybeObjectSlot end) final {
    while (start < end) {
      VisitPointer(host, start);
      ++start;
    }
  }

  inline void VisitInstructionStreamPointer(Tagged<Code> host,
                                            InstructionStreamSlot slot) final {
    // This code is similar to the implementation of VisitPointer() modulo
    // new kind of slot.
    DCHECK(!HasWeakHeapObjectTag(slot.load(code_cage_base())));
    Tagged<Object> code = slot.load(code_cage_base());
    RecordMigratedSlot(host, code, slot.address());
  }

  inline void VisitEphemeron(Tagged<HeapObject> host, int index, ObjectSlot key,
                             ObjectSlot value) override {
    DCHECK(IsEphemeronHashTable(host));
    DCHECK(!HeapLayout::InYoungGeneration(host));

    // Simply record ephemeron keys in OLD_TO_NEW if it points into the young
    // generation instead of recording it in ephemeron_remembered_set here for
    // migrated objects. OLD_TO_NEW is per page and we can therefore easily
    // record in OLD_TO_NEW on different pages in parallel without merging. Both
    // sets are anyways guaranteed to be empty after a full GC.
    VisitPointer(host, key);
    VisitPointer(host, value);
  }

  inline void VisitCodeTarget(Tagged<InstructionStream> host,
                              RelocInfo* rinfo) override {
    DCHECK(RelocInfo::IsCodeTargetMode(rinfo->rmode()));
    Tagged<InstructionStream> target =
        InstructionStream::FromTargetAddress(rinfo->target_address());
    // The target is always in old space, we don't have to record the slot in
    // the old-to-new remembered set.
    DCHECK(!HeapLayout::InYoungGeneration(target));
    DCHECK(!HeapLayout::InWritableSharedSpace(target));
    heap_->mark_compact_collector()->RecordRelocSlot(host, rinfo, target);
  }

  inline void VisitEmbeddedPointer(Tagged<InstructionStream> host,
                                   RelocInfo* rinfo) override {
    DCHECK(RelocInfo::IsEmbeddedObjectMode(rinfo->rmode()));
    Tagged<HeapObject> object = rinfo->target_object(cage_base());
    WriteBarrier::GenerationalForRelocInfo(host, rinfo, object);
    WriteBarrier::SharedForRelocInfo(host, rinfo, object);
    heap_->mark_compact_collector()->RecordRelocSlot(host, rinfo, object);
  }

  // Entries that are skipped for recording.
  inline void VisitExternalReference(Tagged<InstructionStream> host,
                                     RelocInfo* rinfo) final {}
  inline void VisitInternalReference(Tagged<InstructionStream> host,
                                     RelocInfo* rinfo) final {}
  inline void VisitExternalPointer(Tagged<HeapObject> host,
                                   ExternalPointerSlot slot) final {}

  inline void VisitIndirectPointer(Tagged<HeapObject> host,
                                   IndirectPointerSlot slot,
                                   IndirectPointerMode mode) final {}

  inline void VisitTrustedPointerTableEntry(Tagged<HeapObject> host,
                                            IndirectPointerSlot slot) final {}

  inline void VisitProtectedPointer(Tagged<TrustedObject> host,
                                    ProtectedPointerSlot slot) final {
    RecordMigratedSlot(host, slot.load(), slot.address());
  }

 protected:
  inline void RecordMigratedSlot(Tagged<HeapObject> host,
                                 Tagged<MaybeObject> value, Address slot) {
    if (value.IsStrongOrWeak()) {
      MemoryChunk* value_chunk = MemoryChunk::FromAddress(value.ptr());
      MemoryChunk* host_chunk = MemoryChunk::FromHeapObject(host);
      if (HeapLayout::InYoungGeneration(value)) {
        MutablePageMetadata* host_metadata =
            MutablePageMetadata::cast(host_chunk->Metadata());
        DCHECK_IMPLIES(value_chunk->IsToPage(),
                       v8_flags.minor_ms || value_chunk->IsLargePage());
        DCHECK(host_metadata->SweepingDone());
        RememberedSet<OLD_TO_NEW>::Insert<AccessMode::NON_ATOMIC>(
            host_metadata, host_chunk->Offset(slot));
      } else if (value_chunk->IsEvacuationCandidate()) {
        MutablePageMetadata* host_metadata =
            MutablePageMetadata::cast(host_chunk->Metadata());
        if (value_chunk->IsFlagSet(MemoryChunk::IS_EXECUTABLE)) {
          // TODO(377724745): currently needed because flags are untrusted.
          SBXCHECK(!InsideSandbox(value_chunk->address()));
          RememberedSet<TRUSTED_TO_CODE>::Insert<AccessMode::NON_ATOMIC>(
              host_metadata, host_chunk->Offset(slot));
        } else if (value_chunk->IsFlagSet(MemoryChunk::IS_TRUSTED) &&
                   host_chunk->IsFlagSet(MemoryChunk::IS_TRUSTED)) {
          // When the sandbox is disabled, we use plain tagged pointers to
          // reference trusted objects from untrusted ones. However, for these
          // references we want to use the OLD_TO_OLD remembered set, so here
          // we need to check that both the value chunk and the host chunk are
          // trusted space chunks.
          // TODO(377724745): currently needed because flags are untrusted.
          SBXCHECK(!InsideSandbox(value_chunk->address()));
          if (value_chunk->InWritableSharedSpace()) {
            RememberedSet<TRUSTED_TO_SHARED_TRUSTED>::Insert<
                AccessMode::NON_ATOMIC>(host_metadata,
                                        host_chunk->Offset(slot));
          } else {
            RememberedSet<TRUSTED_TO_TRUSTED>::Insert<AccessMode::NON_ATOMIC>(
                host_metadata, host_chunk->Offset(slot));
          }
        } else {
          RememberedSet<OLD_TO_OLD>::Insert<AccessMode::NON_ATOMIC>(
              host_metadata, host_chunk->Offset(slot));
        }
      } else if (value_chunk->InWritableSharedSpace() &&
                 !HeapLayout::InWritableSharedSpace(host)) {
        MutablePageMetadata* host_metadata =
            MutablePageMetadata::cast(host_chunk->Metadata());
        if (value_chunk->IsFlagSet(MemoryChunk::IS_TRUSTED) &&
            host_chunk->IsFlagSet(MemoryChunk::IS_TRUSTED)) {
          RememberedSet<TRUSTED_TO_SHARED_TRUSTED>::Insert<
              AccessMode::NON_ATOMIC>(host_metadata, host_chunk->Offset(slot));
        } else {
          RememberedSet<OLD_TO_SHARED>::Insert<AccessMode::NON_ATOMIC>(
              host_metadata, host_chunk->Offset(slot));
        }
      }
    }
  }

  Heap* const heap_;
};

class MigrationObserver {
 public:
  explicit MigrationObserver(Heap* heap) : heap_(heap) {}

  virtual ~MigrationObserver() = default;
  virtual void Move(AllocationSpace dest, Tagged<HeapObject> src,
                    Tagged<HeapObject> dst, int size) = 0;

 protected:
  Heap* heap_;
};

class ProfilingMigrationObserver final : public MigrationObserver {
 public:
  explicit ProfilingMigrationObserver(Heap* heap) : MigrationObserver(heap) {}

  inline void Move(AllocationSpace dest, Tagged<HeapObject> src,
                   Tagged<HeapObject> dst, int size) final {
    // Note this method is called in a concurrent setting. The current object
    // (src and dst) is somewhat safe to access without precautions, but other
    // objects may be subject to concurrent modification.
    if (dest == CODE_SPACE) {
      PROFILE(heap_->isolate(), CodeMoveEvent(Cast<InstructionStream>(src),
                                              Cast<InstructionStream>(dst)));
    } else if ((dest == OLD_SPACE || dest == TRUSTED_SPACE) &&
               IsBytecodeArray(dst)) {
      // TODO(saelo): remove `dest == OLD_SPACE` once BytecodeArrays are
      // allocated in trusted space.
      PROFILE(heap_->isolate(), BytecodeMoveEvent(Cast<BytecodeArray>(src),
                                                  Cast<BytecodeArray>(dst)));
    }
    heap_->OnMoveEvent(src, dst, size);
  }
};

class HeapObjectVisitor {
 public:
  virtual ~HeapObjectVisitor() = default;
  virtual bool Visit(Tagged<HeapObject> object, int size) = 0;
};

class EvacuateVisitorBase : public HeapObjectVisitor {
 public:
  void AddObserver(MigrationObserver* observer) {
    migration_function_ = RawMigrateObject<MigrationMode::kObserved>;
    observers_.push_back(observer);
  }

#if DEBUG
  void DisableAbortEvacuationAtAddress(MutablePageMetadata* chunk) {
    abort_evacuation_at_address_ = chunk->area_end();
  }

  void SetUpAbortEvacuationAtAddress(MutablePageMetadata* chunk) {
    if (v8_flags.stress_compaction || v8_flags.stress_compaction_random) {
      // Stress aborting of evacuation by aborting ~5% of evacuation candidates
      // when stress testing.
      const double kFraction = 0.05;

      if (rng_->NextDouble() < kFraction) {
        const double abort_evacuation_percentage = rng_->NextDouble();
        abort_evacuation_at_address_ =
            chunk->area_start() +
            abort_evacuation_percentage * chunk->area_size();
        return;
      }
    }

    abort_evacuation_at_address_ = chunk->area_end();
  }
#endif  // DEBUG

 protected:
  enum MigrationMode { kFast, kObserved };

  PtrComprCageBase cage_base() {
#if V8_COMPRESS_POINTERS
    return PtrComprCageBase{heap_->isolate()};
#else
    return PtrComprCageBase{};
#endif  // V8_COMPRESS_POINTERS
  }

  using MigrateFunction = void (*)(EvacuateVisitorBase* base,
                                   Tagged<HeapObject> dst,
                                   Tagged<HeapObject> src, int size,
                                   AllocationSpace dest);

  template <MigrationMode mode>
  static void RawMigrateObject(EvacuateVisitorBase* base,
                               Tagged<HeapObject> dst, Tagged<HeapObject> src,
                               int size, AllocationSpace dest) {
    Address dst_addr = dst.address();
    Address src_addr = src.address();
    PtrComprCageBase cage_base = base->cage_base();
    DCHECK(base->heap_->AllowedToBeMigrated(src->map(cage_base), src, dest));
    DCHECK_NE(dest, LO_SPACE);
    DCHECK_NE(dest, CODE_LO_SPACE);
    DCHECK_NE(dest, TRUSTED_LO_SPACE);
    if (dest == OLD_SPACE) {
      DCHECK_OBJECT_SIZE(size);
      DCHECK(IsAligned(size, kTaggedSize));
      base->heap_->CopyBlock(dst_addr, src_addr, size);
      if (mode != MigrationMode::kFast) {
        base->ExecuteMigrationObservers(dest, src, dst, size);
      }
      // In case the object's map gets relocated during GC we load the old map
      // here. This is fine since they store the same content.
      base->record_visitor_->Visit(dst->map(cage_base), dst, size);
    } else if (dest == SHARED_SPACE) {
      DCHECK_OBJECT_SIZE(size);
      DCHECK(IsAligned(size, kTaggedSize));
      base->heap_->CopyBlock(dst_addr, src_addr, size);
      if (mode != MigrationMode::kFast) {
        base->ExecuteMigrationObservers(dest, src, dst, size);
      }
      base->record_visitor_->Visit(dst->map(cage_base), dst, size);
    } else if (dest == TRUSTED_SPACE) {
      DCHECK_OBJECT_SIZE(size);
      DCHECK(IsAligned(size, kTaggedSize));
      base->heap_->CopyBlock(dst_addr, src_addr, size);
      if (mode != MigrationMode::kFast) {
        base->ExecuteMigrationObservers(dest, src, dst, size);
      }
      // In case the object's map gets relocated during GC we load the old map
      // here. This is fine since they store the same content.
      base->record_visitor_->Visit(dst->map(cage_base), dst, size);
    } else if (dest == CODE_SPACE) {
      DCHECK_CODEOBJECT_SIZE(size);
      {
        WritableJitAllocation writable_allocation =
            ThreadIsolation::RegisterInstructionStreamAllocation(dst_addr,
                                                                 size);
        DCHECK_GT(size, InstructionStream::kHeaderSize);
        writable_allocation.CopyData(0, reinterpret_cast<uint8_t*>(src_addr),
                                     InstructionStream::kHeaderSize);
        writable_allocation.CopyCode(
            InstructionStream::kHeaderSize,
            reinterpret_cast<uint8_t*>(src_addr +
                                       InstructionStream::kHeaderSize),
            size - InstructionStream::kHeaderSize);
        Tagged<InstructionStream> istream = Cast<InstructionStream>(dst);
        istream->Relocate(writable_allocation, dst_addr - src_addr);
      }
      if (mode != MigrationMode::kFast) {
        base->ExecuteMigrationObservers(dest, src, dst, size);
      }
      // In case the object's map gets relocated during GC we load the old map
      // here. This is fine since they store the same content.
      base->record_visitor_->Visit(dst->map(cage_base), dst, size);
    } else {
      DCHECK_OBJECT_SIZE(size);
      DCHECK(dest == NEW_SPACE);
      base->heap_->CopyBlock(dst_addr, src_addr, size);
      if (mode != MigrationMode::kFast) {
        base->ExecuteMigrationObservers(dest, src, dst, size);
      }
    }

    if (dest == CODE_SPACE) {
      WritableJitAllocation jit_allocation =
          WritableJitAllocation::ForInstructionStream(
              Cast<InstructionStream>(src));
      jit_allocation.WriteHeaderSlot<MapWord, HeapObject::kMapOffset>(
          MapWord::FromForwardingAddress(src, dst));
    } else {
      src->set_map_word_forwarded(dst, kRelaxedStore);
    }
  }

  EvacuateVisitorBase(Heap* heap, EvacuationAllocator* local_allocator,
                      RecordMigratedSlotVisitor* record_visitor)
      : heap_(heap),
        local_allocator_(local_allocator),
        record_visitor_(record_visitor),
        shared_string_table_(v8_flags.shared_string_table &&
                             heap->isolate()->has_shared_space()) {
    migration_function_ = RawMigrateObject<MigrationMode::kFast>;
#if DEBUG
    rng_.emplace(heap_->isolate()->fuzzer_rng()->NextInt64());
#endif  // DEBUG
  }

  inline bool TryEvacuateObject(AllocationSpace target_space,
                                Tagged<HeapObject> object, int size,
                                Tagged<HeapObject>* target_object) {
#if DEBUG
    DCHECK_LE(abort_evacuation_at_address_,
              MutablePageMetadata::FromHeapObject(object)->area_end());
    DCHECK_GE(abort_evacuation_at_address_,
              MutablePageMetadata::FromHeapObject(object)->area_start());

    if (V8_UNLIKELY(object.address() >= abort_evacuation_at_address_)) {
      return false;
    }
#endif  // DEBUG

    Tagged<Map> map = object->map(cage_base());
    AllocationAlignment alignment = HeapObject::RequiredAlignment(map);
    AllocationResult allocation;
    if (target_space == OLD_SPACE && ShouldPromoteIntoSharedHeap(map)) {
      allocation = local_allocator_->Allocate(SHARED_SPACE, size, alignment);
    } else {
      allocation = local_allocator_->Allocate(target_space, size, alignment);
    }
    if (allocation.To(target_object)) {
      MigrateObject(*target_object, object, size, target_space);
      return true;
    }
    return false;
  }

  inline bool ShouldPromoteIntoSharedHeap(Tagged<Map> map) {
    if (shared_string_table_) {
      return String::IsInPlaceInternalizableExcludingExternal(
          map->instance_type());
    }
    return false;
  }

  inline void ExecuteMigrationObservers(AllocationSpace dest,
                                        Tagged<HeapObject> src,
                                        Tagged<HeapObject> dst, int size) {
    for (MigrationObserver* obs : observers_) {
      obs->Move(dest, src, dst, size);
    }
  }

  inline void MigrateObject(Tagged<HeapObject> dst, Tagged<HeapObject> src,
                            int size, AllocationSpace dest) {
    migration_function_(this, dst, src, size, dest);
  }

  Heap* heap_;
  EvacuationAllocator* local_allocator_;
  RecordMigratedSlotVisitor* record_visitor_;
  std::vector<MigrationObserver*> observers_;
  MigrateFunction migration_function_;
  const bool shared_string_table_;
#if DEBUG
  Address abort_evacuation_at_address_{kNullAddress};
#endif  // DEBUG
  std::optional<base::RandomNumberGenerator> rng_;
};

class EvacuateNewSpaceVisitor final : public EvacuateVisitorBase {
 public:
  explicit EvacuateNewSpaceVisitor(
      Heap* heap, EvacuationAllocator* local_allocator,
      RecordMigratedSlotVisitor* record_visitor,
      PretenuringHandler::PretenuringFeedbackMap* local_pretenuring_feedback)
      : EvacuateVisitorBase(heap, local_allocator, record_visitor),
        promoted_size_(0),
        semispace_copied_size_(0),
        pretenuring_handler_(heap_->pretenuring_handler()),
        local_pretenuring_feedback_(local_pretenuring_feedback),
        is_incremental_marking_(heap->incremental_marking()->IsMarking()),
        shortcut_strings_(!heap_->IsGCWithStack() ||
                          v8_flags.shortcut_strings_with_stack) {
    DCHECK_IMPLIES(is_incremental_marking_,
                   heap->incremental_marking()->IsMajorMarking());
  }

  inline bool Visit(Tagged<HeapObject> object, int size) override {
    if (TryEvacuateWithoutCopy(object)) return true;
    Tagged<HeapObject> target_object;

    PretenuringHandler::UpdateAllocationSite(heap_, object->map(), object, size,
                                             local_pretenuring_feedback_);

    if (!TryEvacuateObject(OLD_SPACE, object, size, &target_object)) {
      heap_->FatalProcessOutOfMemory(
          "MarkCompactCollector: young object promotion failed");
    }

    promoted_size_ += size;
    return true;
  }

  intptr_t promoted_size() { return promoted_size_; }
  intptr_t semispace_copied_size() { return semispace_copied_size_; }

 private:
  inline bool TryEvacuateWithoutCopy(Tagged<HeapObject> object) {
    DCHECK(!is_incremental_marking_);

    if (!shortcut_strings_) return false;

    Tagged<Map> map = object->map();

    // Some objects can be evacuated without creating a copy.
    if (map->visitor_id() == kVisitThinString) {
      Tagged<HeapObject> actual = Cast<ThinString>(object)->unchecked_actual();
      if (MarkCompactCollector::IsOnEvacuationCandidate(actual)) return false;
      object->set_map_word_forwarded(actual, kRelaxedStore);
      return true;
    }
    // TODO(mlippautz): Handle ConsString.

    return false;
  }

  inline AllocationSpace AllocateTargetObject(
      Tagged<HeapObject> old_object, int size,
      Tagged<HeapObject>* target_object) {
    AllocationAlignment alignment =
        HeapObject::RequiredAlignment(old_object->map());
    AllocationSpace space_allocated_in = NEW_SPACE;
    AllocationResult allocation =
        local_allocator_->Allocate(NEW_SPACE, size, alignment);
    if (allocation.IsFailure()) {
      allocation = AllocateInOldSpace(size, alignment);
      space_allocated_in = OLD_SPACE;
    }
    bool ok 
"""


```