Response:
My thought process to answer the request goes through these stages:

1. **Understanding the Core Request:** The user wants to understand the functionality of `v8/src/heap/mark-compact.cc`. They also provide specific constraints and questions about Torque, JavaScript relevance, logic, and common errors. The "part 1 of 8" implies this is an iterative process, so focusing on high-level functionality is key for this first part.

2. **Initial Code Scan (Headers):**  The `#include` directives at the top are the first clue. I'll quickly scan them, looking for keywords related to:
    * **Memory Management:** `heap`, `space`, `allocator`, `sweeper`, `garbage_collector`, `page`, `slot`, `bitmap`. These are heavily represented, confirming this file is about memory management within V8.
    * **Garbage Collection Phases:** `mark`, `compact`, `sweep`, `evacuate`. The filename itself points to mark-compact, so these are expected.
    * **Concurrency/Parallelism:** `atomic`, `concurrent`, `task`, `mutex`, `platform`. This suggests the mark-compact process might involve multiple threads.
    * **Code and Compilation:** `compilation-cache`, `deoptimizer`, `instruction-stream`, `code`. This implies the garbage collector interacts with compiled code.
    * **JavaScript Objects:** `objects`, `js-objects`, `js-array-buffer`. This confirms the GC's direct link to JavaScript data structures.
    * **Verification/Debugging:** `assert`, `verify`, `logging`, `tracing`. This suggests the code includes mechanisms for ensuring correctness.

3. **Identifying Key Structures and Classes:**  I'll look for class definitions within the provided snippet. The `FullMarkingVerifier` and `MarkCompactCollector` classes stand out immediately. The `MarkCompactCollector` class is clearly the central focus.

4. **Inferring Main Functionality (Based on Class Name and Headers):**  The name "MarkCompactCollector" is highly suggestive. Combined with the included headers, I can confidently infer its primary responsibility is implementing the mark-compact garbage collection algorithm. This involves:
    * **Marking:** Identifying live objects in the heap.
    * **Compacting:** Moving live objects to defragment memory.

5. **Addressing Specific Questions:**

    * **".tq" extension:** The code is `.cc`, not `.tq`. Therefore, it's C++, not Torque.
    * **JavaScript Relevance:**  The inclusion of headers related to JavaScript objects (`js-objects-inl.h`, etc.) clearly indicates a strong relationship. The GC's purpose is to manage the memory used by JavaScript objects. I can formulate a basic JavaScript example where garbage collection would be necessary (creating objects that become unreachable).
    * **Code Logic and I/O:**  At this stage, with only a header file, detailed logic is impossible to deduce. I can create a *hypothetical* scenario focusing on marking: assume an object is reachable, so it gets marked. If not reachable, it doesn't.
    * **Common Programming Errors:**  Memory leaks in JavaScript (forgetting to dereference objects) directly relate to the GC's purpose. I can provide a simple example.

6. **Summarizing Functionality for Part 1:**  Given it's the first part, a high-level summary focusing on the core mark-compact algorithm and its purpose within V8's memory management is appropriate. Mentioning the involvement of marking and compaction, and the goal of reclaiming memory, is crucial.

7. **Structuring the Answer:** I'll organize the answer into sections corresponding to the user's requests:
    * Core Functionality
    * Torque Source
    * JavaScript Relationship
    * Code Logic (Hypothetical)
    * Common Programming Errors
    * Summary

8. **Refinement and Language:** I'll ensure the language is clear, concise, and avoids overly technical jargon where possible. Using bullet points or numbered lists will improve readability. I'll also explicitly state assumptions or limitations (e.g., the hypothetical nature of the code logic based on the provided snippet).

By following these steps, I can generate a comprehensive and accurate answer to the user's request based on the provided C++ header file. The focus on the high-level functionality is important for the first part of a multi-part request.```
功能列举:

v8/src/heap/mark-compact.cc 文件是 V8 引擎中负责 **标记-压缩 (Mark-Compact)** 垃圾回收算法的核心实现。其主要功能包括：

1. **启动和协调标记-压缩 GC 过程:**  负责启动整个标记-压缩的垃圾回收流程，包括准备阶段、标记阶段、清理阶段和压缩阶段。
2. **标记活动对象:**  实现标记算法，遍历堆内存，标记所有可达的（live）对象。这包括从根对象开始，递归地访问所有被引用的对象。
3. **对象统计记录:**  在标记阶段记录各种对象的统计信息，用于性能分析和优化。
4. **清理非活动引用:**  处理弱引用、终结器等，清除指向非活动对象的引用。
5. **对象迁移 (Evacuation/Compaction):**  将活动对象移动到新的位置，以压缩堆内存，减少碎片。这包括选择需要迁移的页（evacuation candidates），以及实际的对象复制和指针更新。
6. **空闲列表管理:**  在压缩后，更新堆内存中的空闲列表，以便后续的对象分配。
7. **与并发标记协作:**  如果启用了并发标记，则与后台的并发标记器协同工作，完成标记任务。
8. **与垃圾回收器其他部分交互:**  与堆 (Heap)、空间 (Space)、清除器 (Sweeper) 等其他垃圾回收相关的模块进行交互。
9. **性能监控和追踪:**  提供用于监控和追踪标记-压缩 GC 性能的机制，例如记录时间和各种事件。
10. **堆验证:**  在开发和调试版本中，提供堆的验证功能，确保标记和压缩过程的正确性。

关于文件类型和 JavaScript 关系:

* **.tq 结尾:**  `v8/src/heap/mark-compact.cc` 文件名以 `.cc` 结尾，**不是** Torque 源代码。Torque 源代码的文件名通常以 `.tq` 结尾。
* **与 JavaScript 功能的关系:**  `v8/src/heap/mark-compact.cc` 与 JavaScript 的功能有**直接且重要的关系**。  标记-压缩垃圾回收是 V8 引擎管理 JavaScript 对象内存的关键机制。当 JavaScript 代码创建对象时，这些对象会被分配在堆内存中。当这些对象不再被引用时，标记-压缩 GC 会识别并回收这些内存，防止内存泄漏。

**JavaScript 举例说明:**

```javascript
function createObject() {
  let obj = { data: "这是一个对象" };
  return obj; // 对象被返回，仍然被引用
}

let myObject = createObject();
console.log(myObject.data); // 可以访问对象

myObject = null; // 对象不再被 `myObject` 引用，变得不可达，成为垃圾回收的候选者
```

在这个例子中，当 `myObject` 被赋值为 `null` 后，之前创建的对象 `{ data: "这是一个对象" }` 变得不可达。在后续的标记-压缩垃圾回收过程中，`v8/src/heap/mark-compact.cc` 中的代码会识别出这个对象不再被引用，并将其占用的内存回收。

代码逻辑推理 (假设输入与输出):

由于提供的代码是 C++ 头文件，它只包含声明，没有具体的函数实现逻辑。我们无法直接进行代码逻辑推理。不过，我们可以根据其功能推断其内部可能的逻辑：

**假设输入:**  堆内存中存在一些对象，其中一部分是活动的（被引用），一部分是非活动的（不再被引用）。

**可能的处理逻辑 (在 `MarkCompactCollector::MarkLiveObjects()` 函数中):**

1. **从根对象开始遍历:**  遍历全局变量、当前执行栈、CPU 寄存器等，找到所有根对象。
2. **递归标记:**  从根对象开始，递归地访问其引用的对象，并将这些对象标记为 "活动"。使用某种标记位或数据结构来记录对象的标记状态。
3. **处理特殊引用:**  处理弱引用、软引用等，根据其特性决定是否需要保留引用。
4. **处理 Remembered Set 和 Slot Set:**  增量或并发标记中，需要处理这些数据结构，以快速定位可能需要重新标记的对象。

**假设输出:**  所有活动对象都被正确标记，非活动对象未被标记。堆的标记位图 (marking bitmap) 或其他标记数据结构反映了对象的活动状态。

用户常见的编程错误举例说明:

与标记-压缩 GC 相关的常见编程错误通常会导致内存泄漏：

1. **忘记解除引用:**  创建了对象，并在不再使用时忘记将其引用设置为 `null`，导致对象一直保持可达状态，无法被回收。

   ```javascript
   function createLargeArray() {
     let arr = new Array(1000000); // 创建一个大数组
     return arr;
   }

   let myArray = createLargeArray();
   // ... 使用 myArray
   // 忘记设置 myArray = null;  // 导致内存泄漏
   ```

2. **闭包中的意外引用:**  闭包可能会意外地捕获外部作用域的变量，导致本应被回收的对象仍然被闭包引用。

   ```javascript
   function createCounter() {
     let count = 0;
     return function() {
       console.log(++count);
     };
   }

   let counter = createCounter();
   // counter 变量持有对闭包的引用，闭包又持有对 count 变量的引用。
   // 即使不再调用 counter，如果 counter 变量本身没有被设置为 null，count 变量也无法被回收。
   ```

3. **DOM 元素的循环引用:**  在 Web 开发中，JavaScript 对象和 DOM 元素之间可能存在循环引用，导致它们都无法被垃圾回收。

   ```javascript
   let element = document.getElementById('myElement');
   let obj = {};
   element.myRef = obj; // DOM 元素引用 JavaScript 对象
   obj.elementRef = element; // JavaScript 对象引用 DOM 元素

   // 即使将 element 和 obj 都设置为 null，由于循环引用，它们可能无法立即被回收。
   element = null;
   obj = null;
   ```

功能归纳 (第 1 部分):

`v8/src/heap/mark-compact.cc` 是 V8 引擎中实现标记-压缩垃圾回收算法的核心 C++ 源代码文件。它负责标记堆内存中的活动对象，并为后续的压缩操作做准备。这个文件直接关系到 JavaScript 的内存管理，确保不再使用的对象能够被回收，防止内存泄漏，从而保证 JavaScript 应用程序的稳定运行。它不是 Torque 源代码。
```
Prompt: 
```
这是目录为v8/src/heap/mark-compact.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/mark-compact.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共8部分，请归纳一下它的功能

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
      DCHECK_EQ(
"""


```