Response: Let's break down the thought process for analyzing the `main_thread_metrics_helper.cc` file and generating the response.

**1. Initial Understanding - What is the file about?**

The filename itself is highly descriptive: `main_thread_metrics_helper.cc`. This strongly suggests its purpose is to collect and report metrics related to the main thread. The directory `blink/renderer/platform/scheduler/main_thread/` reinforces this idea, placing it within the scheduling infrastructure for the main thread.

**2. Core Functionality Identification - The "What"**

I started reading through the code, looking for key classes, methods, and variables. I noticed:

* **`MainThreadMetricsHelper` class:** This is the central piece. Its constructor takes a `MainThreadSchedulerImpl` (indicating it interacts with the main thread scheduler), a flag for CPU timing, and an initial time. It also initializes `ThreadLoadTracker` instances.
* **`ThreadLoadTracker`:** Multiple instances exist (`main_thread_load_tracker_`, `background_main_thread_load_tracker_`, `foreground_main_thread_load_tracker_`). This suggests tracking load in different contexts (overall, background, foreground).
* **`RecordTaskMetrics`:** This method is clearly responsible for recording metrics for individual tasks. It takes a `Task` and `TaskTiming` as input.
* **`RecordMainThreadTaskLoad`, `RecordForegroundMainThreadTaskLoad`, `RecordBackgroundMainThreadTaskLoad`:** These methods are callbacks for the `ThreadLoadTracker` and are responsible for *actually recording* the aggregated load metrics using `UMA_HISTOGRAM_PERCENTAGE`.
* **`UMA_HISTOGRAM_PERCENTAGE`:**  This macro is a strong indicator of metric reporting. It's used to record data in histograms for analysis.
* **Queueing Delay Histograms:** The `queueing_delay_histograms_` array and the `QUEUEING_DELAY_HISTOGRAM_INIT` macro clearly indicate measurement of task queueing delays, categorized by priority.
* **Foreground/Background Logic:**  The `OnRendererForegrounded` and `OnRendererBackgrounded` methods, along with the separate load trackers, indicate the helper tracks and reports metrics differently based on the renderer's visibility.
* **`ReportLowThreadLoadForPageAlmostIdleSignal`:** This function sends an IPC message to the resource coordinator, indicating the main thread's load.

**3. Relationship to JavaScript, HTML, CSS - The "How does it relate?"**

Now, I considered *how* these metrics connect to web development concepts:

* **JavaScript Execution:** JavaScript heavily relies on the main thread. Long-running JavaScript can increase the main thread load. The metrics collected help identify performance bottlenecks caused by JavaScript.
* **HTML Parsing and DOM Manipulation:**  The parsing of HTML and the subsequent manipulation of the Document Object Model (DOM) also happen on the main thread. Inefficient or complex HTML structures can lead to higher main thread load.
* **CSS Processing and Layout/Paint:**  Applying CSS styles, calculating layouts, and painting the webpage are all main thread activities. Complex CSS or excessive layout thrashing can strain the main thread.

To provide concrete examples, I thought about scenarios where these connections become apparent:

* **JavaScript:** A long-running `for` loop or computationally expensive algorithm will directly increase the reported main thread load.
* **HTML:**  A deeply nested HTML structure or a table with thousands of rows will take longer to parse and render, increasing the load.
* **CSS:**  A complex CSS selector that matches a large number of elements, or animations that trigger frequent layout recalculations, will contribute to higher load.

**4. Logical Inference - Assumptions and Outputs**

To illustrate logical inference, I focused on the `RecordTaskMetrics` function and how it calculates and records queueing delays:

* **Assumption:** A task is enqueued at a specific time (`task.GetDesiredExecutionTime()`) and starts executing later (`task_timing.start_time()`).
* **Input:**  The `Task` object and its `TaskTiming` information.
* **Calculation:** The difference between the start time and the desired execution time (`task_timing.start_time() - task.GetDesiredExecutionTime()`).
* **Output:** This time difference (the queueing delay) is then recorded in the appropriate histogram based on the task's priority (`queue->GetQueuePriority()`).

**5. Common Usage Errors - The "What can go wrong?"**

Thinking about common errors requires considering how developers might interact with the system *indirectly* by writing code that affects the main thread:

* **Long-running JavaScript:**  This is a classic example. Unoptimized JavaScript code will block the main thread and be reflected in the load metrics.
* **Forced Synchronous Layout:**  Accessing layout properties (like `offsetWidth`, `offsetHeight`) in a loop can force the browser to perform layout calculations synchronously, leading to performance problems.
* **Excessive DOM Manipulation:**  Adding or removing large numbers of DOM elements at once can be expensive.
* **Inefficient CSS Selectors:**  As mentioned before, overly complex CSS selectors can slow down rendering.
* **Ignoring Performance Warnings:** Developers might not pay attention to performance warnings or profiling data that indicate main thread bottlenecks.

**6. Structuring the Response**

Finally, I organized the information into logical sections:

* **Functionality:** A concise summary of what the code does.
* **Relationship to Web Technologies:**  Explicitly connecting the metrics to JavaScript, HTML, and CSS with illustrative examples.
* **Logical Inference:**  Demonstrating how the code works with specific inputs and outputs.
* **Common Usage Errors:**  Providing practical examples of how developer actions can impact the metrics.

Throughout this process, I reread sections of the code to ensure accuracy and clarity. I also considered the audience for this explanation (likely someone familiar with software development but perhaps not deeply with Chromium internals) and aimed for a balance of technical detail and high-level understanding.
这个 `main_thread_metrics_helper.cc` 文件是 Chromium Blink 引擎中负责收集和记录主线程性能指标的辅助类。它的主要功能是监控主线程的繁忙程度、任务排队延迟等信息，并将这些数据以直方图的形式记录下来，用于性能分析和监控。

以下是它的具体功能分解以及与 JavaScript, HTML, CSS 的关系，逻辑推理和常见使用错误：

**主要功能：**

1. **追踪主线程负载 (Main Thread Load):**
   -  通过 `ThreadLoadTracker` 周期性地计算和记录主线程的繁忙程度（CPU 占用率）。
   -  区分前台和后台的主线程负载，分别进行记录。
   -  可以区分扩展程序的渲染进程的主线程负载。

2. **记录任务排队延迟 (Task Queueing Delay):**
   -  当主线程上的任务开始执行时，记录该任务从加入队列到开始执行所花费的时间。
   -  根据任务的优先级，将排队延迟记录到不同的直方图中，以便按优先级分析延迟情况。

3. **报告低负载状态 (Low Thread Load):**
   -  当主线程的负载低于某个阈值时，会通知 `RendererResourceCoordinator`，表明主线程相对空闲。这可以用于优化资源分配和管理。

4. **处理渲染器前后台切换:**
   -  当渲染器切换到前台或后台时，会暂停或恢复相应的前台/后台负载追踪器。

5. **处理渲染器关闭:**
   -  在渲染器关闭时，会记录最后的空闲时间，并停止负载追踪。

6. **子采样 (Subsampling) (用于测试):**
   -  提供禁用指标子采样的功能，主要用于测试目的，确保所有指标都被记录。

**与 JavaScript, HTML, CSS 的关系：**

主线程是执行 JavaScript 代码、解析 HTML 结构、应用 CSS 样式以及进行页面布局和渲染的关键线程。因此，`MainThreadMetricsHelper` 收集的指标直接反映了这些操作的性能表现。

* **JavaScript:**
    - 当 JavaScript 代码执行时间过长或存在性能问题时，会导致主线程负载升高，`MAIN_THREAD_LOAD_METRIC_NAME` 的值会增加。
    - JavaScript 代码执行前的排队时间会影响任务排队延迟指标。例如，如果一个高优先级的 JavaScript 回调函数由于主线程繁忙而延迟执行，对应的排队延迟直方图会记录这个延迟。
    - **举例说明:**  一个复杂的 JavaScript 动画或者一个计算量很大的循环可能会导致主线程长时间处于高负载状态。

* **HTML:**
    - HTML 的解析和 DOM 树的构建是在主线程上进行的。复杂的 HTML 结构或大型的 DOM 树可能会增加主线程的负担。
    - **举例说明:**  一个包含大量嵌套元素的页面在初始渲染时会占用较多主线程资源。

* **CSS:**
    - CSS 样式的计算、布局（layout）和绘制（paint）也发生在主线程上。复杂的 CSS 选择器、大量的样式规则或者频繁的布局变动都会影响主线程的性能。
    - **举例说明:**  一个复杂的 CSS 动画或者频繁触发 reflow/repaint 的操作会导致主线程负载升高。

**逻辑推理 (假设输入与输出):**

假设我们有以下场景：

**假设输入:**

1. **时间点 T0:** 用户点击了一个按钮，触发了一个 JavaScript 事件。
2. **时间点 T1:**  浏览器将与该事件相关的任务添加到主线程的任务队列中，优先级为 "High"。
3. **时间点 T2:** 主线程当前正在执行其他任务，直到 T2 时刻空闲。
4. **时间点 T3:**  主线程开始执行该 JavaScript 事件处理函数。
5. **时间点 T4:** JavaScript 事件处理函数执行完毕。

**输出:**

* **主线程负载:**  在 T0 到 T4 这段时间内，如果主线程一直处于忙碌状态，`MAIN_THREAD_LOAD_METRIC_NAME` 的值会较高。如果在 T2 到 T3 之间主线程有空闲，则会根据具体占用率记录。
* **任务排队延迟:**  `RecordTaskMetrics` 函数会被调用，计算排队延迟 `T3 - T1`，并将这个延迟记录到优先级为 "High" 的排队延迟直方图 (`queueing_delay_histograms_[5]`，因为 "High" 是列表中的第 6 个，索引为 5)。
* **低负载状态:** 如果在 T4 之后一段时间内，主线程的负载持续低于 `kMainThreadTaskLoadLowPercentage`，`ReportLowThreadLoadForPageAlmostIdleSignal` 函数会被调用，并通过 `RendererResourceCoordinator` 发送信号，表明主线程负载较低。

**常见使用错误 (对于开发者而言，会间接影响这些指标):**

开发者在使用 JavaScript, HTML, CSS 时的错误操作会导致主线程的性能问题，从而反映在这些指标上。

1. **长时间运行的同步 JavaScript 代码:**
   - **错误:**  编写了执行时间过长的同步 JavaScript 代码，例如在一个循环中进行大量的计算或 DOM 操作。
   - **结果:**  主线程会被阻塞，`MAIN_THREAD_LOAD_METRIC_NAME` 会持续处于高位，导致页面无响应。任务排队延迟也会增加，因为后续的任务需要等待当前任务执行完成。

2. **强制同步布局 (Forced Synchronous Layout):**
   - **错误:**  在 JavaScript 中，先读取会导致布局计算的属性（例如 `offsetWidth`），然后立即修改会触发布局的样式，导致浏览器被迫同步执行布局计算。
   - **结果:**  这会阻塞主线程，增加主线程负载，并可能导致帧率下降和卡顿。

3. **过度 DOM 操作:**
   - **错误:**  频繁地添加、删除或修改大量的 DOM 元素。
   - **结果:**  会导致浏览器进行大量的布局和绘制操作，增加主线程的负担。

4. **复杂的 CSS 选择器:**
   - **错误:**  使用过于复杂或低效的 CSS 选择器，例如通配符选择器或者深度嵌套的选择器。
   - **结果:**  浏览器需要花费更多的时间来匹配元素，影响样式计算和布局性能。

5. **没有优化事件监听器:**
   - **错误:**  在滚动或鼠标移动等频繁触发的事件上执行复杂的 JavaScript 操作，没有进行节流 (throttle) 或防抖 (debounce)。
   - **结果:**  会导致主线程在短时间内处理大量的任务，增加负载。

总而言之，`main_thread_metrics_helper.cc` 是一个底层的性能监控工具，它收集的数据能够帮助 Chromium 工程师分析和优化 Blink 引擎的性能。对于 Web 开发者来说，理解这些指标背后的含义，可以帮助他们编写更高效的 JavaScript, HTML 和 CSS 代码，从而提供更好的用户体验。

### 提示词
```
这是目录为blink/renderer/platform/scheduler/main_thread/main_thread_metrics_helper.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/scheduler/main_thread/main_thread_metrics_helper.h"

#include "base/functional/bind.h"
#include "base/metrics/histogram_macros.h"
#include "base/numerics/safe_conversions.h"
#include "third_party/blink/public/platform/scheduler/web_renderer_process_type.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/resource_coordinator/renderer_resource_coordinator.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/frame_scheduler_impl.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_scheduler.h"

namespace blink {
namespace scheduler {

#define MAIN_THREAD_LOAD_METRIC_NAME "RendererScheduler.RendererMainThreadLoad5"
#define EXTENSIONS_MAIN_THREAD_LOAD_METRIC_NAME \
  MAIN_THREAD_LOAD_METRIC_NAME ".Extension"

#define QUEUEING_DELAY_HISTOGRAM_INIT(name)                       \
  "RendererScheduler.QueueingDuration." name "Priority",          \
      kTimeBasedHistogramMinSample, kTimeBasedHistogramMaxSample, \
      kTimeBasedHistogramBucketCount

enum class MainThreadTaskLoadState { kLow, kHigh, kUnknown };

namespace {

constexpr base::TimeDelta kThreadLoadTrackerReportingInterval =
    base::Seconds(1);
constexpr base::TimeDelta kLongIdlePeriodDiscardingThreshold = base::Minutes(3);

// Main thread load percentage that is considered low.
constexpr int kMainThreadTaskLoadLowPercentage = 25;

}  // namespace

MainThreadMetricsHelper::MainThreadMetricsHelper(
    MainThreadSchedulerImpl* main_thread_scheduler,
    bool has_cpu_timing_for_each_task,
    base::TimeTicks now,
    bool renderer_backgrounded)
    : MetricsHelper(ThreadType::kMainThread, has_cpu_timing_for_each_task),
      main_thread_scheduler_(main_thread_scheduler),
      renderer_shutting_down_(false),
      main_thread_load_tracker_(
          now,
          base::BindRepeating(
              &MainThreadMetricsHelper::RecordMainThreadTaskLoad,
              base::Unretained(this)),
          kThreadLoadTrackerReportingInterval),
      background_main_thread_load_tracker_(
          now,
          base::BindRepeating(
              &MainThreadMetricsHelper::RecordBackgroundMainThreadTaskLoad,
              base::Unretained(this)),
          kThreadLoadTrackerReportingInterval),
      foreground_main_thread_load_tracker_(
          now,
          base::BindRepeating(
              &MainThreadMetricsHelper::RecordForegroundMainThreadTaskLoad,
              base::Unretained(this)),
          kThreadLoadTrackerReportingInterval),
      // Order here must match TaskPriority (in descending priority order).
      queueing_delay_histograms_{
          {QUEUEING_DELAY_HISTOGRAM_INIT("Control")},
          {QUEUEING_DELAY_HISTOGRAM_INIT("Highest")},
          {QUEUEING_DELAY_HISTOGRAM_INIT("ExtremelyHigh")},
          {QUEUEING_DELAY_HISTOGRAM_INIT("VeryHigh")},
          {QUEUEING_DELAY_HISTOGRAM_INIT("HighContinuation")},
          {QUEUEING_DELAY_HISTOGRAM_INIT("High")},
          {QUEUEING_DELAY_HISTOGRAM_INIT("NormalContinuation")},
          {QUEUEING_DELAY_HISTOGRAM_INIT("Normal")},
          {QUEUEING_DELAY_HISTOGRAM_INIT("LowContinuation")},
          {QUEUEING_DELAY_HISTOGRAM_INIT("Low")},
          {QUEUEING_DELAY_HISTOGRAM_INIT("BestEffort")}},
      main_thread_task_load_state_(MainThreadTaskLoadState::kUnknown) {
  main_thread_load_tracker_.Resume(now);
  if (renderer_backgrounded) {
    background_main_thread_load_tracker_.Resume(now);
  } else {
    foreground_main_thread_load_tracker_.Resume(now);
  }
}

MainThreadMetricsHelper::~MainThreadMetricsHelper() = default;

void MainThreadMetricsHelper::OnRendererForegrounded(base::TimeTicks now) {
  foreground_main_thread_load_tracker_.Resume(now);
  background_main_thread_load_tracker_.Pause(now);
}

void MainThreadMetricsHelper::OnRendererBackgrounded(base::TimeTicks now) {
  foreground_main_thread_load_tracker_.Pause(now);
  background_main_thread_load_tracker_.Resume(now);
}

void MainThreadMetricsHelper::OnRendererShutdown(base::TimeTicks now) {
  renderer_shutting_down_ = true;
  foreground_main_thread_load_tracker_.RecordIdle(now);
  background_main_thread_load_tracker_.RecordIdle(now);
  main_thread_load_tracker_.RecordIdle(now);
}

void MainThreadMetricsHelper::ResetForTest(base::TimeTicks now) {
  main_thread_load_tracker_ = ThreadLoadTracker(
      now,
      base::BindRepeating(&MainThreadMetricsHelper::RecordMainThreadTaskLoad,
                          base::Unretained(this)),
      kThreadLoadTrackerReportingInterval);

  background_main_thread_load_tracker_ = ThreadLoadTracker(
      now,
      base::BindRepeating(
          &MainThreadMetricsHelper::RecordBackgroundMainThreadTaskLoad,
          base::Unretained(this)),
      kThreadLoadTrackerReportingInterval);

  foreground_main_thread_load_tracker_ = ThreadLoadTracker(
      now,
      base::BindRepeating(
          &MainThreadMetricsHelper::RecordForegroundMainThreadTaskLoad,
          base::Unretained(this)),
      kThreadLoadTrackerReportingInterval);
}

void MainThreadMetricsHelper::DisableMetricsSubsamplingForTesting() {
  sampling_ratio_ = 1.;
}

void MainThreadMetricsHelper::RecordTaskMetrics(
    MainThreadTaskQueue* queue,
    const base::sequence_manager::Task& task,
    const base::sequence_manager::TaskQueue::TaskTiming& task_timing) {
  if (ShouldDiscardTask(task, task_timing))
    return;

  // Discard anomalously long idle periods.
  if (last_reported_task_ &&
      task_timing.start_time() - last_reported_task_.value() >
          kLongIdlePeriodDiscardingThreshold) {
    main_thread_load_tracker_.Reset(task_timing.end_time());
    foreground_main_thread_load_tracker_.Reset(task_timing.end_time());
    background_main_thread_load_tracker_.Reset(task_timing.end_time());
    return;
  }

  last_reported_task_ = task_timing.end_time();

  // We want to measure thread time here, but for efficiency reasons
  // we stick with wall time.
  main_thread_load_tracker_.RecordTaskTime(task_timing.start_time(),
                                           task_timing.end_time());
  foreground_main_thread_load_tracker_.RecordTaskTime(task_timing.start_time(),
                                                      task_timing.end_time());
  background_main_thread_load_tracker_.RecordTaskTime(task_timing.start_time(),
                                                      task_timing.end_time());

  if (queue && base::TimeTicks::IsHighResolution() &&
      metrics_subsampler_.ShouldSample(sampling_ratio_)) {
    base::TimeDelta elapsed =
        task_timing.start_time() - task.GetDesiredExecutionTime();
    queueing_delay_histograms_[static_cast<size_t>(queue->GetQueuePriority())]
        .CountMicroseconds(elapsed);
  }
}

void MainThreadMetricsHelper::RecordMainThreadTaskLoad(base::TimeTicks time,
                                                       double load) {
  int load_percentage = static_cast<int>(load * 100);
  DCHECK_LE(load_percentage, 100);

  ReportLowThreadLoadForPageAlmostIdleSignal(load_percentage);

  UMA_HISTOGRAM_PERCENTAGE(MAIN_THREAD_LOAD_METRIC_NAME, load_percentage);

  if (main_thread_scheduler_->main_thread_only().process_type ==
      WebRendererProcessType::kExtensionRenderer) {
    UMA_HISTOGRAM_PERCENTAGE(EXTENSIONS_MAIN_THREAD_LOAD_METRIC_NAME,
                             load_percentage);
  }

  TRACE_COUNTER1(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
                 "MainThreadScheduler.RendererMainThreadLoad", load_percentage);
}

void MainThreadMetricsHelper::RecordForegroundMainThreadTaskLoad(
    base::TimeTicks time,
    double load) {
  int load_percentage = static_cast<int>(load * 100);
  DCHECK_LE(load_percentage, 100);

  switch (main_thread_scheduler_->main_thread_only().process_type) {
    case WebRendererProcessType::kExtensionRenderer:
      UMA_HISTOGRAM_PERCENTAGE(EXTENSIONS_MAIN_THREAD_LOAD_METRIC_NAME
                               ".Foreground",
                               load_percentage);
      break;
    case WebRendererProcessType::kRenderer:
      UMA_HISTOGRAM_PERCENTAGE(MAIN_THREAD_LOAD_METRIC_NAME ".Foreground",
                               load_percentage);

      base::TimeDelta time_since_foregrounded =
          time - main_thread_scheduler_->main_thread_only()
                     .background_status_changed_at;
      if (time_since_foregrounded > base::Minutes(1)) {
        UMA_HISTOGRAM_PERCENTAGE(MAIN_THREAD_LOAD_METRIC_NAME
                                 ".Foreground.AfterFirstMinute",
                                 load_percentage);
      }
      break;
  }

  TRACE_COUNTER1(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
                 "MainThreadScheduler.RendererMainThreadLoad.Foreground",
                 load_percentage);
}

void MainThreadMetricsHelper::RecordBackgroundMainThreadTaskLoad(
    base::TimeTicks time,
    double load) {
  int load_percentage = static_cast<int>(load * 100);
  DCHECK_LE(load_percentage, 100);

  switch (main_thread_scheduler_->main_thread_only().process_type) {
    case WebRendererProcessType::kExtensionRenderer:
      UMA_HISTOGRAM_PERCENTAGE(EXTENSIONS_MAIN_THREAD_LOAD_METRIC_NAME
                               ".Background",
                               load_percentage);
      break;
    case WebRendererProcessType::kRenderer:
      UMA_HISTOGRAM_PERCENTAGE(MAIN_THREAD_LOAD_METRIC_NAME ".Background",
                               load_percentage);

      base::TimeDelta time_since_backgrounded =
          time - main_thread_scheduler_->main_thread_only()
                     .background_status_changed_at;
      if (time_since_backgrounded > base::Minutes(1)) {
        UMA_HISTOGRAM_PERCENTAGE(MAIN_THREAD_LOAD_METRIC_NAME
                                 ".Background.AfterFirstMinute",
                                 load_percentage);
      }
      if (time_since_backgrounded > base::Minutes(5)) {
        UMA_HISTOGRAM_PERCENTAGE(MAIN_THREAD_LOAD_METRIC_NAME
                                 ".Background.AfterFifthMinute",
                                 load_percentage);
      }
      if (time_since_backgrounded > base::Minutes(10)) {
        UMA_HISTOGRAM_PERCENTAGE(MAIN_THREAD_LOAD_METRIC_NAME
                                 ".Background.AfterTenthMinute",
                                 load_percentage);
      }
      break;
  }

  TRACE_COUNTER1(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
                 "MainThreadScheduler.RendererMainThreadLoad.Background",
                 load_percentage);
}

void MainThreadMetricsHelper::ReportLowThreadLoadForPageAlmostIdleSignal(
    int load_percentage) {
  // Avoid sending IPCs when the renderer is shutting down as this wreaks havoc
  // in test harnesses. These messages aren't needed in production code either
  // as the endpoint receiving them dies shortly after and does nothing with
  // them.
  if (renderer_shutting_down_)
    return;

  if (auto* renderer_resource_coordinator =
          RendererResourceCoordinator::Get()) {
    // Avoid sending duplicate IPCs when the state doesn't change.
    if (load_percentage <= kMainThreadTaskLoadLowPercentage &&
        main_thread_task_load_state_ != MainThreadTaskLoadState::kLow) {
      renderer_resource_coordinator->SetMainThreadTaskLoadIsLow(true);
      main_thread_task_load_state_ = MainThreadTaskLoadState::kLow;
    } else if (load_percentage > kMainThreadTaskLoadLowPercentage &&
               main_thread_task_load_state_ != MainThreadTaskLoadState::kHigh) {
      renderer_resource_coordinator->SetMainThreadTaskLoadIsLow(false);
      main_thread_task_load_state_ = MainThreadTaskLoadState::kHigh;
    }
  }
}

}  // namespace scheduler
}  // namespace blink
```