Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Initial Understanding - What is this?** The first line `// Copyright 2017 the V8 project authors.` immediately tells us this is part of the V8 JavaScript engine. The filename `sweeper.h` strongly suggests it's related to memory management, specifically the "sweeping" phase of garbage collection.

2. **Core Purpose - The "Sweeper":** The central class is `Sweeper`. The comments about "concurrent sweeping tasks," "preempted," and "resumed" hint at a mechanism to reclaim unused memory in a way that doesn't completely halt JavaScript execution. This is crucial for performance.

3. **Key Data Structures:** Scan through the class members and typedefs.
    * `SweepingList` and `SweptList`: These clearly manage lists of `PageMetadata*`, representing memory pages. The names suggest the progression of pages through the sweeping process.
    * `LocalSweeper`:  This nested class is intriguing. The comments about "local data structures," "multiple threads," and needing to be "finalized on the main thread" suggest a design for parallel sweeping.
    * `SweepingState`:  Another nested class, parameterized by `SweepingScope`. The `kMinor` and `kMajor` values point to different types of garbage collection (minor for the young generation, major for the old generation).

4. **Key Operations (Public Interface):**  Focus on the public methods of `Sweeper`:
    * `PauseMajorSweepingScope`:  A RAII-style class for temporarily pausing sweeping. This indicates operations that need exclusive access to the heap.
    * `ParallelSweepSpace`:  Confirms the parallel sweeping nature. The `AllocationSpace` enum suggests sweeping is done on different memory regions.
    * `AddPage`, `AddNewSpacePage`, `AddPromotedPage`:  Methods for registering pages for sweeping.
    * `EnsurePageIsSwept`, `WaitForPageToBeSwept`:  Methods to manage the completion of sweeping for specific pages, potentially for synchronization.
    * `StartMajorSweeping`, `StartMinorSweeping`, `Initialize...`:  Functions to initiate the sweeping process. The "major" and "minor" distinction is important.
    * `FinishMajorJobs`, `EnsureMajorCompleted`, `FinishMinorJobs`, `EnsureMinorCompleted`: Functions to finalize the sweeping process.
    * `GetSweptPageSafe`, `GetAllSweptPagesSafe`:  Methods for retrieving swept pages, suggesting a way to access the reclaimed memory.
    * `ContributeAndWaitForPromotedPagesIteration`:  This points to a specific optimization or phase dealing with objects moved between generations.

5. **Internal Mechanisms (Private Interface):** Examine the private methods:
    * `RawSweep`:  The core sweeping logic is likely here. The `FreeSpaceTreatmentMode` enum suggests different ways to handle freed memory.
    * `ZeroOrDiscardUnusedMemory`, `FreeAndProcessFreedMemory`:  Detailing how memory is reclaimed.
    * `CleanupRememberedSetEntriesForFreedMemory`, `CleanupTypedSlotsInFreeMemory`:  These methods relate to maintaining the integrity of pointers and object metadata during sweeping.
    * `ConcurrentMajorSweeper`, `ConcurrentMinorSweeper`, `MajorSweeperJob`, `MinorSweeperJob`: These nested classes confirm the multi-threaded/job-based implementation of sweeping.

6. **Flags and Configuration:** The `#include "src/flags/flags.h"` indicates that the sweeper's behavior can be influenced by command-line flags.

7. **Error Handling and Debugging:**  The `V8_NODISCARD` attribute on `PauseMajorSweepingScope` and the `#if DEBUG` block suggest attention to potential errors and debugging.

8. **Torque Consideration:** The prompt asks about `.tq` files. Recognize that Torque is a V8-specific language for generating C++ code. If the file *were* `.tq`, it would mean the sweeper logic is defined in Torque and then compiled to C++. Since it's `.h`, it's a standard C++ header.

9. **JavaScript Connection:**  Think about *why* this sweeper exists. It's to free up memory used by JavaScript objects that are no longer needed. This is fundamental to how garbage collection works. The JavaScript example should demonstrate the creation of objects that *would* eventually be targeted by the sweeper.

10. **Logic and Assumptions:**  Consider the flow of pages: added to a sweeping list, processed (swept), and then moved to a swept list. The parallel nature means synchronization is crucial. Assume the input to `RawSweep` is a `PageMetadata*` and the output is the modification of that page to reclaim free space.

11. **Common Errors:**  Relate the sweeper's function to common memory-related errors in JavaScript: memory leaks (if the sweeper fails), dangling pointers (if sweeping isn't done correctly).

12. **Structure and Refine:** Organize the findings into logical categories: Purpose, Functionality, Internal Implementation, etc. Use clear and concise language. Provide code examples where requested.

**Self-Correction/Refinement during the process:**

* Initially, I might focus too much on individual methods. I need to step back and see the bigger picture of how the sweeper fits into the garbage collection process.
* I might not immediately understand the purpose of `LocalSweeper`. Rereading the comments and looking at its methods helps clarify its role in parallelization.
*  The interaction between the main thread and background sweeper tasks needs careful consideration. The `PauseMajorSweepingScope` is a key indicator of this interaction.
*  Making sure the JavaScript example accurately reflects the *impact* of the sweeper, even though the sweeper itself is C++, is important. It's about showing *what* the sweeper manages.

By following this structured approach, combining code analysis with an understanding of garbage collection principles, we can effectively analyze and explain the functionality of the `sweeper.h` file.
## v8/src/heap/sweeper.h 的功能解析

这个头文件 `v8/src/heap/sweeper.h` 定义了 V8 JavaScript 引擎中负责 **垃圾回收（Garbage Collection，GC）的清扫（Sweeping）阶段** 的 `Sweeper` 类及其相关组件。

**主要功能概览:**

`Sweeper` 类的核心职责是 **回收被标记为不再使用的内存**。在垃圾回收的标记阶段之后，`Sweeper` 会遍历堆内存，找到那些没有被标记为存活的对象所占用的页面，并将这些页面上的空闲空间释放出来，以便后续的内存分配可以重用这些空间。

**更具体的功能点:**

* **管理待清扫的页面列表 (SweepingList):**  `Sweeper` 维护着一个或多个列表，用于存储待清扫的内存页面的元数据信息 (`PageMetadata*`)。这些页面是在标记阶段被确定为需要进行清扫的。
* **管理已清扫的页面列表 (SweptList):** `Sweeper` 也会维护已完成清扫的页面列表。这些页面上的空闲空间已经可以被重新使用。
* **并发清扫 (Concurrent Sweeping):**  `Sweeper` 支持并发地进行清扫工作，这意味着清扫过程可以与 JavaScript 代码的执行并行进行，从而减少 GC 造成的停顿时间。这通过使用后台任务 (`MajorSweeperJob`, `MinorSweeperJob`) 和局部清扫器 (`LocalSweeper`) 来实现。
* **区分 Major 和 Minor 清扫:**  `Sweeper` 区分 Major GC 和 Minor GC 的清扫过程。
    * **Major Sweeping:** 通常针对老生代（Old Generation）内存空间，回收长时间存活的对象所占用的空间。
    * **Minor Sweeping:** 通常针对新生代（New Generation）内存空间，回收短暂存活的对象所占用的空间。
* **暂停和恢复清扫 (PauseMajorSweepingScope):**  提供了一种机制来暂停主要的并发清扫任务，以便执行某些需要独占访问堆内存的操作。
* **处理已晋升的页面 (Promoted Pages):**  在 Minor GC 中，一些存活的对象会被晋升到老生代。`Sweeper` 需要处理这些已晋升的页面，确保它们被正确地纳入老生代的管理。
* **与内存分配器 (MemoryAllocator) 交互:**  `Sweeper` 需要与内存分配器协同工作，将清扫出来的空闲空间添加到空闲列表，以便内存分配器可以利用这些空间来分配新的对象。
* **处理跨页面的引用:** 清扫过程中需要考虑跨页面的引用，确保回收操作不会导致悬空指针。
* **性能追踪 (GCTracer):**  `Sweeper` 集成了性能追踪机制，可以记录清扫过程的各种指标，用于性能分析和优化。
* **处理空的新生代页面 (SweepEmptyNewSpacePage):**  专门处理完全空的新生代页面，可以进行更快速的回收。
* **内存释放 (ComputeDiscardMemoryArea):**  计算可以返还给操作系统的未使用内存区域。

**如果 `v8/src/heap/sweeper.h` 以 `.tq` 结尾:**

如果 `v8/src/heap/sweeper.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 自研的一种领域特定语言，用于生成高效的 C++ 代码。这意味着 `Sweeper` 类的部分或全部实现逻辑将使用 Torque 编写，然后被编译成 C++ 代码。

**与 Javascript 的功能关系 (及 Javascript 示例):**

`Sweeper` 的功能与 JavaScript 的内存管理息息相关。作为垃圾回收的关键组成部分，`Sweeper` 负责回收 JavaScript 中不再使用的对象所占用的内存，从而避免内存泄漏，并确保程序能够持续运行。

**Javascript 示例:**

```javascript
// 创建一些对象
let obj1 = { data: new Array(10000).fill(1) };
let obj2 = { name: "example" };
let obj3 = { value: 42 };

// obj1 不再被引用，可以被垃圾回收
obj1 = null;

// obj2 和 obj3 仍然被引用

// ... 一段时间后，垃圾回收器会运行，Sweeper 会回收 obj1 占用的内存
```

在这个例子中，当 `obj1` 被设置为 `null` 后，它变得不可达，成为了垃圾回收的候选对象。在垃圾回收的标记阶段，`obj1` 将不会被标记为存活。当清扫阶段开始时，`Sweeper` 会找到 `obj1` 曾经占用的内存空间并将其回收，使得这部分内存可以被重新用于分配新的 JavaScript 对象。

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

* `Sweeper` 接收到一个 `PageMetadata*` 指针，指向一个在标记阶段未被标记为存活的内存页面。
* 当前的清扫模式为 `kLazyOrConcurrent` (表示可以并发清扫)。

**代码逻辑推理:**

1. `Sweeper` 会检查该页面是否已经被添加到待清扫列表 (`sweeping_list_`)。
2. 如果未添加，则将该 `PageMetadata*` 添加到相应的待清扫列表（取决于页面的内存空间）。
3. 如果并发清扫任务正在运行，可能会唤醒一个空闲的清扫线程来处理这个页面。
4. 清扫线程 (`ConcurrentMajorSweeper` 或 `ConcurrentMinorSweeper`) 会获取该页面，遍历页面上的内存块。
5. 对于每个内存块，清扫线程会执行以下操作：
   * 如果该内存块曾被分配给一个对象，则确定该对象的大小。
   * 将该内存块标记为空闲。
   * 根据配置，可能会对该空闲内存进行填充 (zap)。
   * 将空闲内存块添加到页面的空闲列表，以便后续分配使用。
6. 清扫完成后，该 `PageMetadata*` 会从待清扫列表移动到已清扫列表 (`swept_list_`)。

**假设输出:**

* 该 `PageMetadata` 指向的内存页面上的所有不再使用的内存块都被标记为空闲，并添加到页面的空闲列表中。
* 该页面可以被内存分配器重新使用。
* 如果开启了填充选项，被释放的内存区域会被特定的模式填充。

**用户常见的编程错误 (与 `Sweeper` 功能相关):**

虽然用户不会直接与 `Sweeper` 类交互，但他们的编程错误会导致 `Sweeper` 需要执行更多的工作，或者在某些情况下，由于错误的使用导致内存无法被正确回收。

* **内存泄漏:**  用户创建了对象，但没有释放对这些对象的引用，导致这些对象一直存活，`Sweeper` 无法回收它们占用的内存。

   ```javascript
   function createLeakingObject() {
     global.leakedObject = { data: new Array(1000000).fill(1) }; // 将对象赋值给全局变量，导致一直被引用
   }

   createLeakingObject();
   // leakedObject 永远不会被垃圾回收，导致内存泄漏
   ```

* **意外的全局变量:**  不小心创建了全局变量，导致对象生命周期过长，增加了垃圾回收器的压力。

   ```javascript
   function accidentalGlobal() {
     notAGlobalVar = { data: "oops" }; // 忘记使用 var/let/const，意外创建了全局变量
   }

   accidentalGlobal();
   console.log(window.notAGlobalVar); // 可以访问到，说明是全局变量
   ```

* **闭包导致的意外引用:**  闭包可能会意外地持有对某些对象的引用，导致这些对象无法被回收。

   ```javascript
   function createClosure() {
     let largeData = new Array(1000000).fill(1);
     return function() {
       console.log(largeData.length); // 闭包持有对 largeData 的引用
     };
   }

   let myClosure = createClosure();
   // 即使 createClosure 函数执行完毕，myClosure 仍然持有对 largeData 的引用
   ```

总结来说，`v8/src/heap/sweeper.h` 定义的 `Sweeper` 类是 V8 垃圾回收机制中负责回收不再使用内存的关键组件。它通过管理待清扫和已清扫的页面列表，并支持并发清扫，有效地回收内存，为 JavaScript 程序的稳定运行提供了保障。用户编写的 JavaScript 代码中的内存管理错误会直接影响 `Sweeper` 的工作效率和效果。

### 提示词
```
这是目录为v8/src/heap/sweeper.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/sweeper.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_HEAP_SWEEPER_H_
#define V8_HEAP_SWEEPER_H_

#include <limits>
#include <map>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "src/base/platform/condition-variable.h"
#include "src/common/globals.h"
#include "src/flags/flags.h"
#include "src/heap/gc-tracer.h"
#include "src/heap/memory-allocator.h"
#include "src/heap/pretenuring-handler.h"
#include "src/heap/slot-set.h"
#include "src/tasks/cancelable-task.h"

namespace v8 {
namespace internal {

class MutablePageMetadata;
class NonAtomicMarkingState;
class PageMetadata;
class LargePageMetadata;
class PagedSpaceBase;
class Space;

enum class FreeSpaceTreatmentMode { kIgnoreFreeSpace, kZapFreeSpace };

class Sweeper {
 public:
  // When the scope is entered, the concurrent sweeping tasks
  // are preempted and are not looking at the heap objects, concurrent sweeping
  // is resumed when the scope is exited.
  class V8_NODISCARD PauseMajorSweepingScope {
   public:
    explicit PauseMajorSweepingScope(Sweeper* sweeper);
    ~PauseMajorSweepingScope();

   private:
    Sweeper* const sweeper_;
    const bool resume_on_exit_;
  };

  using SweepingList = std::vector<PageMetadata*>;
  using SweptList = std::vector<PageMetadata*>;

  enum class SweepingMode { kEagerDuringGC, kLazyOrConcurrent };

  // LocalSweeper holds local data structures required for sweeping and is used
  // to initiate sweeping and promoted page iteration on multiple threads. Each
  // thread should holds its own LocalSweeper. Once sweeping is done, all
  // LocalSweepers should be finalized on the main thread.
  //
  // LocalSweeper is not thread-safe and should not be concurrently by several
  // threads. The exceptions to this rule are allocations during parallel
  // evacuation and from concurrent allocators. In practice the data structures
  // in LocalSweeper are only actively used for new space sweeping. Since
  // parallel evacuators and concurrent allocators never try to allocate in new
  // space, they will never contribute to new space sweeping and thus can use
  // the main thread's local sweeper without risk of data races.
  class LocalSweeper final {
   public:
    explicit LocalSweeper(Sweeper* sweeper) : sweeper_(sweeper) {
      DCHECK_NOT_NULL(sweeper_);
    }
    ~LocalSweeper() = default;

    // Returns true if any swept pages can be allocated on.
    bool ParallelSweepSpace(
        AllocationSpace identity, SweepingMode sweeping_mode,
        uint32_t max_pages = std::numeric_limits<uint32_t>::max());
    // Intended to be called either with a JobDelegate from a job. Returns true
    // if iteration is finished.
    bool ContributeAndWaitForPromotedPagesIteration(JobDelegate* delegate);
    bool ContributeAndWaitForPromotedPagesIteration();

   private:
    void ParallelSweepPage(PageMetadata* page, AllocationSpace identity,
                           SweepingMode sweeping_mode);

    bool ParallelIteratePromotedPages(JobDelegate* delegate);
    bool ParallelIteratePromotedPages();
    void ParallelIteratePromotedPage(MutablePageMetadata* page);

    template <typename ShouldYieldCallback>
    bool ContributeAndWaitForPromotedPagesIterationImpl(
        ShouldYieldCallback should_yield_callback);
    template <typename ShouldYieldCallback>
    bool ParallelIteratePromotedPagesImpl(
        ShouldYieldCallback should_yield_callback);

    Sweeper* const sweeper_;

    friend class Sweeper;
  };

  explicit Sweeper(Heap* heap);
  ~Sweeper();

  bool major_sweeping_in_progress() const {
    return major_sweeping_state_.in_progress();
  }
  bool minor_sweeping_in_progress() const {
    return minor_sweeping_state_.in_progress();
  }
  bool sweeping_in_progress() const {
    return minor_sweeping_in_progress() || major_sweeping_in_progress();
  }
  bool sweeping_in_progress_for_space(AllocationSpace space) const {
    if (space == NEW_SPACE) return minor_sweeping_in_progress();
    return major_sweeping_in_progress();
  }

  void TearDown();

  void AddPage(AllocationSpace space, PageMetadata* page);
  void AddNewSpacePage(PageMetadata* page);
  void AddPromotedPage(MutablePageMetadata* chunk);

  // Returns true if any swept pages can be allocated on.
  bool ParallelSweepSpace(
      AllocationSpace identity, SweepingMode sweeping_mode,
      uint32_t max_pages = std::numeric_limits<uint32_t>::max());

  void EnsurePageIsSwept(PageMetadata* page);
  void WaitForPageToBeSwept(PageMetadata* page);

  // After calling this function sweeping is considered to be in progress
  // and the main thread can sweep lazily, but the background sweeper tasks
  // are not running yet.
  void StartMajorSweeping();
  void StartMinorSweeping();
  void InitializeMajorSweeping();
  void InitializeMinorSweeping();
  V8_EXPORT_PRIVATE void StartMajorSweeperTasks();
  V8_EXPORT_PRIVATE void StartMinorSweeperTasks();

  // Finishes all major sweeping tasks/work without changing the sweeping state.
  void FinishMajorJobs();
  // Finishes all major sweeping tasks/work and resets sweeping state to NOT in
  // progress.
  void EnsureMajorCompleted();

  // Finishes all minor sweeping tasks/work without changing the sweeping state.
  void FinishMinorJobs();
  // Finishes all minor sweeping tasks/work and resets sweeping state to NOT in
  // progress.
  void EnsureMinorCompleted();

  bool AreMinorSweeperTasksRunning() const;
  bool AreMajorSweeperTasksRunning() const;

  bool UsingMajorSweeperTasks() const;

  PageMetadata* GetSweptPageSafe(PagedSpaceBase* space);
  SweptList GetAllSweptPagesSafe(PagedSpaceBase* space);

  bool IsSweepingDoneForSpace(AllocationSpace space) const;

  GCTracer::Scope::ScopeId GetTracingScope(AllocationSpace space,
                                           bool is_joining_thread);

  bool IsIteratingPromotedPages() const;
  void ContributeAndWaitForPromotedPagesIteration();

  bool ShouldRefillFreelistForSpace(AllocationSpace space) const;

  void SweepEmptyNewSpacePage(PageMetadata* page);

  uint64_t GetTraceIdForFlowEvent(GCTracer::Scope::ScopeId scope_id) const;

#if DEBUG
  // Can only be called on the main thread when no tasks are running.
  bool HasUnsweptPagesForMajorSweeping() const;
#endif  // DEBUG

  // Computes OS page boundaries for unused memory.
  V8_EXPORT_PRIVATE static std::optional<base::AddressRegion>
  ComputeDiscardMemoryArea(Address start, Address end);

 private:
  NonAtomicMarkingState* marking_state() const { return marking_state_; }

  void RawSweep(PageMetadata* p,
                FreeSpaceTreatmentMode free_space_treatment_mode,
                SweepingMode sweeping_mode, bool should_reduce_memory);

  void ZeroOrDiscardUnusedMemory(PageMetadata* page, Address addr, size_t size);

  void AddPageImpl(AllocationSpace space, PageMetadata* page);

  class ConcurrentMajorSweeper;
  class ConcurrentMinorSweeper;

  class MajorSweeperJob;
  class MinorSweeperJob;

  static constexpr int kNumberOfSweepingSpaces =
      LAST_SWEEPABLE_SPACE - FIRST_SWEEPABLE_SPACE + 1;

  template <typename Callback>
  void ForAllSweepingSpaces(Callback callback) const {
    if (v8_flags.minor_ms) {
      callback(NEW_SPACE);
    }
    callback(OLD_SPACE);
    callback(CODE_SPACE);
    callback(SHARED_SPACE);
    callback(TRUSTED_SPACE);
  }

  // Helper function for RawSweep. Depending on the FreeListRebuildingMode and
  // FreeSpaceTreatmentMode this function may add the free memory to a free
  // list, make the memory iterable, clear it, and return the free memory to
  // the operating system.
  size_t FreeAndProcessFreedMemory(
      Address free_start, Address free_end, PageMetadata* page, Space* space,
      FreeSpaceTreatmentMode free_space_treatment_mode,
      bool should_reduce_memory);

  // Helper function for RawSweep. Handle remembered set entries in the freed
  // memory which require clearing.
  void CleanupRememberedSetEntriesForFreedMemory(
      Address free_start, Address free_end, PageMetadata* page,
      bool record_free_ranges, TypedSlotSet::FreeRangesMap* free_ranges_map,
      SweepingMode sweeping_mode);

  // Helper function for RawSweep. Clears invalid typed slots in the given free
  // ranges.
  void CleanupTypedSlotsInFreeMemory(
      PageMetadata* page, const TypedSlotSet::FreeRangesMap& free_ranges_map,
      SweepingMode sweeping_mode);

  // Helper function for RawSweep. Clears the mark bits and ensures consistency
  // of live bytes.
  void ClearMarkBitsAndHandleLivenessStatistics(PageMetadata* page,
                                                size_t live_bytes);

  size_t ConcurrentMinorSweepingPageCount();
  size_t ConcurrentMajorSweepingPageCount();

  PageMetadata* GetSweepingPageSafe(AllocationSpace space);
  MutablePageMetadata* GetPromotedPageSafe();
  bool TryRemoveSweepingPageSafe(AllocationSpace space, PageMetadata* page);
  bool TryRemovePromotedPageSafe(MutablePageMetadata* chunk);

  void PrepareToBeSweptPage(AllocationSpace space, PageMetadata* page);
  void PrepareToBeIteratedPromotedPage(PageMetadata* page);

  static bool IsValidSweepingSpace(AllocationSpace space) {
    return space >= FIRST_SWEEPABLE_SPACE && space <= LAST_SWEEPABLE_SPACE;
  }

  static int GetSweepSpaceIndex(AllocationSpace space) {
    DCHECK(IsValidSweepingSpace(space));
    return space - FIRST_SWEEPABLE_SPACE;
  }

  void NotifyPromotedPageIterationFinished(MutablePageMetadata* chunk);
  void NotifyPromotedPagesIterationFinished();

  void AddSweptPage(PageMetadata* page, AllocationSpace identity);

  enum class SweepingScope { kMinor, kMajor };
  template <SweepingScope scope>
  class SweepingState {
    using ConcurrentSweeper =
        typename std::conditional<scope == SweepingScope::kMinor,
                                  ConcurrentMinorSweeper,
                                  ConcurrentMajorSweeper>::type;
    using SweeperJob =
        typename std::conditional<scope == SweepingScope::kMinor,
                                  MinorSweeperJob, MajorSweeperJob>::type;

   public:
    explicit SweepingState(Sweeper* sweeper);
    ~SweepingState();

    void InitializeSweeping();
    void StartSweeping();
    void StartConcurrentSweeping();
    void StopConcurrentSweeping();
    void FinishSweeping();
    void JoinSweeping();

    bool HasValidJob() const;
    bool HasActiveJob() const;

    bool in_progress() const { return in_progress_; }
    bool should_reduce_memory() const { return should_reduce_memory_; }
    std::vector<ConcurrentSweeper>& concurrent_sweepers() {
      return concurrent_sweepers_;
    }

    void Pause();
    void Resume();

    uint64_t trace_id() const { return trace_id_; }
    uint64_t background_trace_id() const { return background_trace_id_; }

   private:
    Sweeper* sweeper_;
    // Main thread can finalize sweeping, while background threads allocation
    // slow path checks this flag to see whether it could support concurrent
    // sweeping.
    std::atomic<bool> in_progress_{false};
    std::unique_ptr<JobHandle> job_handle_;
    std::vector<ConcurrentSweeper> concurrent_sweepers_;
    uint64_t trace_id_ = 0;
    uint64_t background_trace_id_ = 0;
    bool should_reduce_memory_ = false;
  };

  Heap* const heap_;
  NonAtomicMarkingState* const marking_state_;
  base::Mutex mutex_;
  base::ConditionVariable cv_page_swept_;
  SweptList swept_list_[kNumberOfSweepingSpaces];
  SweepingList sweeping_list_[kNumberOfSweepingSpaces];
  std::atomic<bool> has_sweeping_work_[kNumberOfSweepingSpaces]{false};
  std::atomic<bool> has_swept_pages_[kNumberOfSweepingSpaces]{false};
  std::vector<MutablePageMetadata*> sweeping_list_for_promoted_page_iteration_;
  LocalSweeper main_thread_local_sweeper_;
  SweepingState<SweepingScope::kMajor> major_sweeping_state_{this};
  SweepingState<SweepingScope::kMinor> minor_sweeping_state_{this};

  // The following fields are used for maintaining an order between iterating
  // promoted pages and sweeping array buffer extensions.
  size_t promoted_pages_for_iteration_count_ = 0;
  std::atomic<size_t> iterated_promoted_pages_count_{0};
  base::Mutex promoted_pages_iteration_notification_mutex_;
  base::ConditionVariable promoted_pages_iteration_notification_variable_;
  std::atomic<bool> promoted_page_iteration_in_progress_{false};
};

template <typename ShouldYieldCallback>
bool Sweeper::LocalSweeper::ContributeAndWaitForPromotedPagesIterationImpl(
    ShouldYieldCallback should_yield_callback) {
  if (!sweeper_->sweeping_in_progress()) return true;
  if (!sweeper_->IsIteratingPromotedPages()) return true;
  if (!ParallelIteratePromotedPagesImpl(should_yield_callback)) return false;
  base::MutexGuard guard(
      &sweeper_->promoted_pages_iteration_notification_mutex_);
  // Check again that iteration is not yet finished.
  if (!sweeper_->IsIteratingPromotedPages()) return true;
  if (should_yield_callback()) {
    return false;
  }
  sweeper_->promoted_pages_iteration_notification_variable_.Wait(
      &sweeper_->promoted_pages_iteration_notification_mutex_);
  return true;
}

template <typename ShouldYieldCallback>
bool Sweeper::LocalSweeper::ParallelIteratePromotedPagesImpl(
    ShouldYieldCallback should_yield_callback) {
  while (!should_yield_callback()) {
    MutablePageMetadata* chunk = sweeper_->GetPromotedPageSafe();
    if (chunk == nullptr) return true;
    ParallelIteratePromotedPage(chunk);
  }
  return false;
}

}  // namespace internal
}  // namespace v8

#endif  // V8_HEAP_SWEEPER_H_
```