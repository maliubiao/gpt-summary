Response:
Let's break down the thought process for analyzing the `concurrent-marker.cc` file.

1. **Understand the Goal:** The primary request is to understand the *functionality* of this specific V8 source code file. Secondary requests are related to file extensions, JavaScript connections, logical reasoning, and common errors.

2. **Initial Scan for Keywords and Structure:**  Quickly look for prominent keywords like `class`, `namespace`, function names (especially those starting with `Start`, `Run`, `Process`, `Create`), and included headers. This gives a high-level overview.

    *  See `namespace cppgc::internal`. This immediately suggests it's part of the C++ garbage collection within V8.
    *  Notice `#include "src/heap/cppgc/..."`. This confirms it's related to `cppgc`, the C++ garbage collector.
    *  Spot the `ConcurrentMarkingTask` class, which inherits from `v8::JobTask`. This strongly implies asynchronous execution and interaction with V8's task scheduling.
    *  Find `ConcurrentMarkerBase`. This seems to be the core class managing the concurrent marking process.
    *  Identify key methods in `ConcurrentMarkingTask`: `Run`, `ProcessWorklists`. These are likely where the main work happens.
    *  Observe the use of `MarkingWorklists`, `ConcurrentMarkingState`, and `Visitor`. These are likely data structures and helpers for the marking process.

3. **Deconstruct the `ConcurrentMarkingTask::Run` Method:** This method is the entry point for the concurrent marking job. Analyze its steps:

    * **Stats Collection:** `StatsCollector::EnabledConcurrentScope`. It tracks statistics about the concurrent marking process.
    * **Work Check:** `HasWorkForConcurrentMarking`. Optimizes by skipping execution if there's nothing to do.
    * **State Initialization:** `ConcurrentMarkingState`. Sets up the state for this concurrent marking run.
    * **Visitor Creation:** `CreateConcurrentMarkingVisitor`. Creates the object responsible for traversing and marking.
    * **Work Processing:** `ProcessWorklists`. This is where the core marking logic resides.
    * **Stats Update:** `incremental_marking_schedule().AddConcurrentlyMarkedBytes`. Records the progress.
    * **State Publication:** `concurrent_marking_state.Publish()`. Makes the marking results visible.

4. **Examine `ConcurrentMarkingTask::ProcessWorklists`:** This method iteratively drains different worklists:

    * **`previously_not_fully_constructed_worklist()`:** Handles objects that weren't fully constructed in the previous GC cycle.
    * **`marking_worklist()`:**  The main worklist of objects to be marked.
    * **`write_barrier_worklist()`:**  Handles objects modified since the last marking cycle.
    * **`ephemeron_pairs_for_processing_worklist()`:** Processes weak references (ephemerons).
    * **`DrainWorklistWithYielding`:**  A template function that processes a worklist while periodically yielding to allow other tasks to run. This is crucial for concurrency and avoiding long pauses.

5. **Analyze `ConcurrentMarkerBase`:** This class manages the lifecycle of the concurrent marking task:

    * **Constructor:** Takes dependencies like `HeapBase`, `MarkingWorklists`, `IncrementalMarkingSchedule`, and `Platform`.
    * **`Start()`:**  Posts the `ConcurrentMarkingTask` to the platform's job queue.
    * **`Join()`:** Waits for the concurrent marking task to finish.
    * **`Cancel()`:** Attempts to stop the concurrent marking task.
    * **`IsActive()`:** Checks if the concurrent marking task is currently running.
    * **`NotifyIncrementalMutatorStepCompleted()` and `NotifyOfWorkIfNeeded()`:** Methods to inform the concurrent marker about mutator activity and potential new work, allowing it to adjust its priority.
    * **`IncreaseMarkingPriorityIfNeeded()`:** Dynamically increases the priority of the concurrent marker if it's not making sufficient progress.

6. **Identify Key Concepts:** Based on the code analysis, determine the core concepts involved:

    * **Concurrent Marking:** Performing garbage collection marking in parallel with the main program execution.
    * **Worklists:** Queues holding objects that need to be processed during marking.
    * **Marking Visitor:** An object that traverses the object graph and marks reachable objects.
    * **Incremental Marking:** Breaking down the marking process into smaller steps to reduce pause times.
    * **Write Barriers:** Mechanisms to track changes to objects during concurrent marking.
    * **Ephemerons:** Weak references that are handled specially during garbage collection.
    * **Task Scheduling:** Using V8's job scheduling infrastructure to run the concurrent marking task.

7. **Address the Specific Questions:**

    * **Functionality:** Summarize the identified key concepts and the purpose of the main classes and methods.
    * **`.tq` Extension:**  State that the file doesn't have that extension and therefore isn't Torque code.
    * **JavaScript Relationship:**  Explain that while this is C++ code, it directly supports JavaScript's garbage collection. Provide a simple JavaScript example of object creation to illustrate the need for garbage collection.
    * **Code Logic Reasoning:** Choose a relevant part of the code (like the worklist draining) and explain the input (worklist with objects), the process (marking), and the output (marked objects).
    * **Common Errors:** Think about potential problems related to concurrency and memory management in garbage collection. A good example is a dangling pointer scenario, though it's not directly *caused* by this code, it's a problem garbage collection aims to *prevent*. Also consider performance issues if marking isn't efficient.

8. **Refine and Organize:**  Structure the answer clearly with headings and bullet points. Use precise language and avoid jargon where possible, or explain it when necessary. Ensure all parts of the original request are addressed.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus only on the `Run` method. **Correction:** Realize that `ConcurrentMarkerBase` is the orchestrator, and understanding its methods like `Start`, `Join`, and priority adjustments is crucial.
* **Misinterpretation:**  Assume a direct mapping between this C++ code and a specific JavaScript feature. **Correction:**  Recognize that this is low-level infrastructure supporting *all* JavaScript garbage collection. The JavaScript example should be general.
* **Overcomplication:** Get bogged down in the details of every single line of code. **Correction:** Focus on the high-level purpose and flow, explaining the key mechanisms. Details can be mentioned briefly but not exhaustively.
* **Lack of concrete examples:**  Just describe the concepts abstractly. **Correction:**  Provide a simple JavaScript example and think about a hypothetical input/output scenario for the worklist processing.

By following these steps and incorporating self-correction, a comprehensive and accurate explanation of the `concurrent-marker.cc` file can be constructed.
好的，让我们来分析一下 `v8/src/heap/cppgc/concurrent-marker.cc` 这个 V8 源代码文件的功能。

**文件功能概述**

`concurrent-marker.cc` 文件实现了 cppgc（V8 的 C++ 垃圾回收器）的并发标记器。并发标记是指垃圾回收的标记阶段与 JavaScript 代码的执行（mutator）并发进行，以减少主线程的停顿时间。

**主要功能组成和作用**

1. **`ConcurrentMarkingTask` 类:**
   - 继承自 `v8::JobTask`，表示一个可以并发执行的任务。
   - `Run(JobDelegate* delegate)` 方法是并发标记任务的核心执行逻辑。它负责从各种工作队列中取出对象并进行标记。
   - `ProcessWorklists` 方法负责具体处理不同的工作队列，例如：
     - `previously_not_fully_constructed_worklist()`: 处理之前未完全构造的对象。
     - `marking_worklist()`: 主要的标记工作队列。
     - `write_barrier_worklist()`: 处理在并发标记期间被修改的对象。
     - `ephemeron_pairs_for_processing_worklist()`: 处理弱引用（ephemerons）。
   - `GetMaxConcurrency` 方法用于确定此任务可以使用的最大并发线程数。

2. **`ConcurrentMarkerBase` 类:**
   - 是并发标记器的基类。
   - 负责启动、停止、取消和管理并发标记任务。
   - `Start()` 方法创建一个 `ConcurrentMarkingTask` 并将其提交到 V8 的任务调度器。
   - `Join()` 方法等待并发标记任务完成。
   - `Cancel()` 方法尝试取消并发标记任务。
   - `IsActive()` 方法检查并发标记任务是否正在运行。
   - `NotifyIncrementalMutatorStepCompleted()` 方法在增量式垃圾回收的 mutator 步骤完成后被调用，用于通知并发标记器可能有更多的工作要做，并可能调整其优先级。
   - `NotifyOfWorkIfNeeded()` 方法用于通知并发标记器有新的工作需要处理，并可以更新其优先级。
   - `IncreaseMarkingPriorityIfNeeded()` 方法根据并发标记的进展情况动态调整其优先级，以确保垃圾回收能够及时完成。

3. **辅助函数和常量:**
   - `kMarkingScheduleRatioBeforeConcurrentPriorityIncrease`: 一个常量，定义了在增加并发标记优先级之前，并发标记任务预期完成的时间比例。
   - `kDefaultDeadlineCheckInterval`: 一个常量，定义了在处理工作列表时检查截止时间的默认间隔。
   - `DrainWorklistWithYielding()`: 一个模板函数，用于从工作列表中取出对象并执行回调，并在一定间隔后让出 CPU，以避免阻塞主线程。
   - `WorkSizeForConcurrentMarking()`: 计算当前标记工作队列的大小。
   - `HasWorkForConcurrentMarking()`: 检查是否还有并发标记的工作需要处理。

**关于文件扩展名和 Torque**

如果 `v8/src/heap/cppgc/concurrent-marker.cc` 以 `.tq` 结尾，那么它的确是一个 V8 Torque 源代码文件。Torque 是一种 V8 特有的类型安全语言，用于生成高效的 C++ 代码。然而，根据你提供的代码内容，这个文件是以 `.cc` 结尾的，所以它是一个标准的 C++ 源代码文件。

**与 JavaScript 的关系**

`concurrent-marker.cc` 中实现的并发标记器是 V8 垃圾回收机制的关键组成部分，直接影响着 JavaScript 的内存管理和性能。

**JavaScript 示例**

虽然 `concurrent-marker.cc` 是 C++ 代码，但它的功能是为了支持 JavaScript 的内存管理。当 JavaScript 代码创建对象时，V8 的垃圾回收器（包括并发标记器）负责识别和回收不再被使用的对象，从而防止内存泄漏。

```javascript
// JavaScript 代码示例

let largeObject = {};
for (let i = 0; i < 100000; i++) {
  largeObject['key' + i] = new Array(1000).fill(i);
}

// ... 一段时间后，largeObject 不再被需要

largeObject = null; // 解除对 largeObject 的引用

// 在后台，V8 的并发标记器会识别出之前 largeObject 指向的对象不再可达，
// 并在适当的时候将其标记为可回收。
```

在这个例子中，当 `largeObject` 被设置为 `null` 后，之前 `largeObject` 引用的对象就变得不可达了。V8 的并发标记器会在后台运行，检测到这些不可达的对象，并在垃圾回收的清除阶段将其回收，释放内存。

**代码逻辑推理：假设输入与输出**

假设我们有以下场景：

**假设输入:**

1. **`marking_worklist()` 中包含两个待标记的对象 `objectA` 和 `objectB`。** 这意味着在之前的垃圾回收阶段，这两个对象被认为是存活的，但它们的子对象可能还没有被完全标记。
2. **并发标记任务正在运行。**
3. **`objectA` 的标记回调会遍历 `objectA` 的所有子对象，并将它们添加到 `marking_worklist()` 中。**
4. **`objectB` 的标记回调也会做类似的操作。**

**代码逻辑推理 (基于 `ConcurrentMarkingTask::ProcessWorklists`):**

1. 并发标记任务会进入 `ProcessWorklists` 方法。
2. 它会首先尝试处理 `previously_not_fully_constructed_worklist()`，假设这里为空。
3. 接下来，它会处理 `marking_worklist()`。
4. `DrainWorklistWithYielding` 函数会被调用来处理 `marking_worklist()`。
5. **第一次循环:**
   - 从 `marking_worklist()` 中取出 `objectA`。
   - 加载 `objectA` 所在的页。
   - 调用与 `objectA` 关联的标记回调。
   - 假设 `objectA` 有两个子对象 `childA1` 和 `childA2`，它们会被添加到 `marking_worklist()` 中。
6. **第二次循环:**
   - 从 `marking_worklist()` 中取出 `objectB`。
   - 加载 `objectB` 所在的页。
   - 调用与 `objectB` 关联的标记回调。
   - 假设 `objectB` 有一个子对象 `childB1`，它会被添加到 `marking_worklist()` 中。
7. **后续循环:**
   - 并发标记任务会继续从 `marking_worklist()` 中取出 `childA1`, `childA2`, `childB1` 并进行标记，直到 `marking_worklist()` 为空。
8. 之后，如果 `write_barrier_worklist()` 或其他工作队列中有待处理的对象，也会被类似地处理。

**预期输出:**

- `objectA`、`objectB` 及其所有可达的子对象都被标记为存活。
- `marking_worklist()` 在处理完成后为空。
- 并发标记任务完成，为后续的垃圾回收清除阶段做准备。

**涉及用户常见的编程错误**

虽然 `concurrent-marker.cc` 是 V8 内部的实现，但它的存在是为了解决用户在 JavaScript 编程中可能遇到的内存管理问题，例如：

1. **内存泄漏:** 当对象不再被使用但仍然被引用时，会导致内存泄漏。并发标记器能够识别出这些不可达的对象并进行回收。
   ```javascript
   // 内存泄漏示例
   function createLeak() {
     let leakedData = {};
     window.leak = leakedData; // 将对象绑定到全局对象，即使不再使用也不会被回收
   }
   createLeak();
   ```
   在这种情况下，即使 `createLeak` 函数执行完毕，`leakedData` 对象仍然被全局对象 `window.leak` 引用，导致内存泄漏。V8 的垃圾回收器会尽力回收这些不再使用的对象，但过度依赖全局变量或其他长期存活的引用仍然可能导致问题。

2. **意外的对象存活:** 有时候，开发者可能无意中保持了对不再需要的对象的引用，导致这些对象无法被垃圾回收。
   ```javascript
   // 意外的对象存活示例
   function processData() {
     let largeData = new Array(1000000).fill(0);
     let callback = function() {
       // 闭包意外地引用了 largeData
       console.log('Data processed');
     };
     // ... 某些操作，但 callback 可能被长期持有
   }
   processData();
   ```
   在这个例子中，闭包 `callback` 可能会意外地捕获并保持对 `largeData` 的引用，即使 `processData` 函数已经执行完毕，`largeData` 也无法被回收。

**总结**

`v8/src/heap/cppgc/concurrent-marker.cc` 文件是 V8 中负责并发垃圾回收标记的关键组成部分。它通过创建和管理并发任务，异步地遍历对象图并标记存活对象，从而减少垃圾回收对 JavaScript 主线程执行的影响，提升应用性能。理解其功能有助于更深入地理解 V8 的内存管理机制。

### 提示词
```
这是目录为v8/src/heap/cppgc/concurrent-marker.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/cppgc/concurrent-marker.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/cppgc/concurrent-marker.h"

#include "include/cppgc/platform.h"
#include "src/heap/cppgc/heap-base.h"
#include "src/heap/cppgc/heap-object-header.h"
#include "src/heap/cppgc/marking-state.h"
#include "src/heap/cppgc/marking-visitor.h"
#include "src/heap/cppgc/stats-collector.h"

namespace cppgc {
namespace internal {

namespace {

static constexpr double kMarkingScheduleRatioBeforeConcurrentPriorityIncrease =
    0.5;

static constexpr size_t kDefaultDeadlineCheckInterval = 750u;

template <size_t kDeadlineCheckInterval = kDefaultDeadlineCheckInterval,
          typename WorklistLocal, typename Callback>
bool DrainWorklistWithYielding(
    JobDelegate* job_delegate, ConcurrentMarkingState& marking_state,
    heap::base::IncrementalMarkingSchedule& incremental_marking_schedule,
    WorklistLocal& worklist_local, Callback callback) {
  return DrainWorklistWithPredicate<kDeadlineCheckInterval>(
      [&incremental_marking_schedule, &marking_state, job_delegate]() {
        incremental_marking_schedule.AddConcurrentlyMarkedBytes(
            marking_state.RecentlyMarkedBytes());
        return job_delegate->ShouldYield();
      },
      worklist_local, callback);
}

size_t WorkSizeForConcurrentMarking(MarkingWorklists& marking_worklists) {
  return marking_worklists.marking_worklist()->Size() +
         marking_worklists.write_barrier_worklist()->Size() +
         marking_worklists.previously_not_fully_constructed_worklist()->Size();
}

// Checks whether worklists' global pools hold any segment a concurrent marker
// can steal. This is called before the concurrent marker holds any Locals, so
// no need to check local segments.
bool HasWorkForConcurrentMarking(MarkingWorklists& marking_worklists) {
  return !marking_worklists.marking_worklist()->IsEmpty() ||
         !marking_worklists.write_barrier_worklist()->IsEmpty() ||
         !marking_worklists.previously_not_fully_constructed_worklist()
              ->IsEmpty();
}

class ConcurrentMarkingTask final : public v8::JobTask {
 public:
  explicit ConcurrentMarkingTask(ConcurrentMarkerBase&);

  void Run(JobDelegate* delegate) final;

  size_t GetMaxConcurrency(size_t) const final;

 private:
  void ProcessWorklists(JobDelegate*, ConcurrentMarkingState&, Visitor&);

  const ConcurrentMarkerBase& concurrent_marker_;
};

ConcurrentMarkingTask::ConcurrentMarkingTask(
    ConcurrentMarkerBase& concurrent_marker)
    : concurrent_marker_(concurrent_marker) {}

void ConcurrentMarkingTask::Run(JobDelegate* job_delegate) {
  StatsCollector::EnabledConcurrentScope stats_scope(
      concurrent_marker_.heap().stats_collector(),
      StatsCollector::kConcurrentMark);
  if (!HasWorkForConcurrentMarking(concurrent_marker_.marking_worklists()))
    return;
  ConcurrentMarkingState concurrent_marking_state(
      concurrent_marker_.heap(), concurrent_marker_.marking_worklists(),
      concurrent_marker_.heap().compactor().compaction_worklists());
  std::unique_ptr<Visitor> concurrent_marking_visitor =
      concurrent_marker_.CreateConcurrentMarkingVisitor(
          concurrent_marking_state);
  ProcessWorklists(job_delegate, concurrent_marking_state,
                   *concurrent_marking_visitor);
  concurrent_marker_.incremental_marking_schedule().AddConcurrentlyMarkedBytes(
      concurrent_marking_state.RecentlyMarkedBytes());
  concurrent_marking_state.Publish();
}

size_t ConcurrentMarkingTask::GetMaxConcurrency(
    size_t current_worker_count) const {
  return WorkSizeForConcurrentMarking(concurrent_marker_.marking_worklists()) +
         current_worker_count;
}

void ConcurrentMarkingTask::ProcessWorklists(
    JobDelegate* job_delegate, ConcurrentMarkingState& concurrent_marking_state,
    Visitor& concurrent_marking_visitor) {
  do {
    if (!DrainWorklistWithYielding(
            job_delegate, concurrent_marking_state,
            concurrent_marker_.incremental_marking_schedule(),
            concurrent_marking_state
                .previously_not_fully_constructed_worklist(),
            [&concurrent_marking_state,
             &concurrent_marking_visitor](HeapObjectHeader* header) {
              BasePage::FromPayload(header)->SynchronizedLoad();
              concurrent_marking_state.AccountMarkedBytes(*header);
              DynamicallyTraceMarkedObject<AccessMode::kAtomic>(
                  concurrent_marking_visitor, *header);
            })) {
      return;
    }

    if (!DrainWorklistWithYielding(
            job_delegate, concurrent_marking_state,
            concurrent_marker_.incremental_marking_schedule(),
            concurrent_marking_state.marking_worklist(),
            [&concurrent_marking_state, &concurrent_marking_visitor](
                const MarkingWorklists::MarkingItem& item) {
              BasePage::FromPayload(item.base_object_payload)
                  ->SynchronizedLoad();
              const HeapObjectHeader& header =
                  HeapObjectHeader::FromObject(item.base_object_payload);
              DCHECK(!header.IsInConstruction<AccessMode::kAtomic>());
              DCHECK(header.IsMarked<AccessMode::kAtomic>());
              concurrent_marking_state.AccountMarkedBytes(header);
              item.callback(&concurrent_marking_visitor,
                            item.base_object_payload);
            })) {
      return;
    }

    if (!DrainWorklistWithYielding(
            job_delegate, concurrent_marking_state,
            concurrent_marker_.incremental_marking_schedule(),
            concurrent_marking_state.write_barrier_worklist(),
            [&concurrent_marking_state,
             &concurrent_marking_visitor](HeapObjectHeader* header) {
              BasePage::FromPayload(header)->SynchronizedLoad();
              concurrent_marking_state.AccountMarkedBytes(*header);
              DynamicallyTraceMarkedObject<AccessMode::kAtomic>(
                  concurrent_marking_visitor, *header);
            })) {
      return;
    }

    {
      StatsCollector::DisabledConcurrentScope stats_scope(
          concurrent_marker_.heap().stats_collector(),
          StatsCollector::kConcurrentMarkProcessEphemerons);
      if (!DrainWorklistWithYielding(
              job_delegate, concurrent_marking_state,
              concurrent_marker_.incremental_marking_schedule(),
              concurrent_marking_state
                  .ephemeron_pairs_for_processing_worklist(),
              [&concurrent_marking_state, &concurrent_marking_visitor](
                  const MarkingWorklists::EphemeronPairItem& item) {
                concurrent_marking_state.ProcessEphemeron(
                    item.key, item.value, item.value_desc,
                    concurrent_marking_visitor);
              })) {
        return;
      }
    }
  } while (
      !concurrent_marking_state.marking_worklist().IsLocalAndGlobalEmpty());
}

}  // namespace

ConcurrentMarkerBase::ConcurrentMarkerBase(
    HeapBase& heap, MarkingWorklists& marking_worklists,
    heap::base::IncrementalMarkingSchedule& incremental_marking_schedule,
    cppgc::Platform* platform)
    : heap_(heap),
      marking_worklists_(marking_worklists),
      incremental_marking_schedule_(incremental_marking_schedule),
      platform_(platform) {}

void ConcurrentMarkerBase::Start() {
  DCHECK(platform_);
  concurrent_marking_handle_ =
      platform_->PostJob(v8::TaskPriority::kUserVisible,
                         std::make_unique<ConcurrentMarkingTask>(*this));
}

bool ConcurrentMarkerBase::Join() {
  if (!concurrent_marking_handle_ || !concurrent_marking_handle_->IsValid())
    return false;

  concurrent_marking_handle_->Join();
  return true;
}

bool ConcurrentMarkerBase::Cancel() {
  if (!concurrent_marking_handle_ || !concurrent_marking_handle_->IsValid())
    return false;

  concurrent_marking_handle_->Cancel();
  return true;
}

bool ConcurrentMarkerBase::IsActive() const {
  return concurrent_marking_handle_ && concurrent_marking_handle_->IsValid();
}

ConcurrentMarkerBase::~ConcurrentMarkerBase() {
  CHECK_IMPLIES(concurrent_marking_handle_,
                !concurrent_marking_handle_->IsValid());
}

void ConcurrentMarkerBase::NotifyIncrementalMutatorStepCompleted() {
  DCHECK(concurrent_marking_handle_);
  if (HasWorkForConcurrentMarking(marking_worklists_)) {
    // Notifies the scheduler that max concurrency might have increased.
    // This will adjust the number of markers if necessary.
    IncreaseMarkingPriorityIfNeeded();
    concurrent_marking_handle_->NotifyConcurrencyIncrease();
  }
}

void ConcurrentMarkerBase::NotifyOfWorkIfNeeded(cppgc::TaskPriority priority) {
  if (HasWorkForConcurrentMarking(marking_worklists_)) {
    concurrent_marking_handle_->UpdatePriority(priority);
    concurrent_marking_handle_->NotifyConcurrencyIncrease();
  }
}

void ConcurrentMarkerBase::IncreaseMarkingPriorityIfNeeded() {
  if (!concurrent_marking_handle_->UpdatePriorityEnabled()) return;
  if (concurrent_marking_priority_increased_) return;
  // If concurrent tasks aren't executed, it might delay GC finalization.
  // As long as GC is active so is the write barrier, which incurs a
  // performance cost. Marking is estimated to take overall
  // |MarkingSchedulingOracle::kEstimatedMarkingTimeMs|. If
  // concurrent marking tasks have not reported any progress (i.e. the
  // concurrently marked bytes count as not changed) in over
  // |kMarkingScheduleRatioBeforeConcurrentPriorityIncrease| of
  // that expected duration, we increase the concurrent task priority
  // for the duration of the current GC. This is meant to prevent the
  // GC from exceeding it's expected end time.
  size_t current_concurrently_marked_bytes_ =
      incremental_marking_schedule_.GetConcurrentlyMarkedBytes();
  if (current_concurrently_marked_bytes_ > last_concurrently_marked_bytes_) {
    last_concurrently_marked_bytes_ = current_concurrently_marked_bytes_;
    last_concurrently_marked_bytes_update_ = v8::base::TimeTicks::Now();
  } else if ((v8::base::TimeTicks::Now() -
              last_concurrently_marked_bytes_update_)
                 .InMilliseconds() >
             kMarkingScheduleRatioBeforeConcurrentPriorityIncrease *
                 heap::base::IncrementalMarkingSchedule::kEstimatedMarkingTime
                     .InMillisecondsF()) {
    concurrent_marking_handle_->UpdatePriority(
        cppgc::TaskPriority::kUserBlocking);
    concurrent_marking_priority_increased_ = true;
  }
}

std::unique_ptr<Visitor> ConcurrentMarker::CreateConcurrentMarkingVisitor(
    ConcurrentMarkingState& marking_state) const {
  return std::make_unique<ConcurrentMarkingVisitor>(heap(), marking_state);
}

}  // namespace internal
}  // namespace cppgc
```