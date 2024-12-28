Response:
The user wants to understand the functionality of the provided C++ source code file `local_frame_ukm_aggregator.cc`. I need to analyze the code and identify its key responsibilities. Specifically, the request asks for:

1. **Listing the functionalities:** A comprehensive overview of what the code does.
2. **Relationship with web technologies (JavaScript, HTML, CSS):** If the code interacts with these technologies, provide concrete examples.
3. **Logical reasoning with input/output:** If the code performs calculations or transformations, describe the process with hypothetical input and expected output.
4. **Common usage errors:** Identify potential mistakes developers might make when using this code.

**Analysis of the code:**

The filename and class name (`LocalFrameUkmAggregator`) strongly suggest that this code is responsible for collecting and aggregating metrics related to a local frame within a web page, specifically for User-centric Key Metrics (UKM). It seems to track performance-related events and timings.

Key observations from the code:

* **UKM Recording:** The code uses `ukm::UkmRecorder` to record metrics. This confirms the primary purpose is UKM data collection.
* **Metrics Tracking:** It defines various metrics using enums (`MetricId`) and structures (`AbsoluteMetricRecord`, `PrimaryMetricRecord`). These metrics appear to cover different stages of the rendering pipeline (e.g., layout, style, paint, compositing).
* **Timers:**  The code uses `ScopedUkmHierarchicalTimer` and `ScopedForcedLayoutTimer` to measure the duration of specific operations.
* **First Contentful Paint (FCP):** The code explicitly tracks the FCP and differentiates metrics before and after FCP.
* **Main Frame Updates:**  It tracks activities within a main frame update cycle.
* **Forced Layout Measurement:** It includes logic to measure and potentially avoid unnecessary forced layout calculations.
* **UMA Integration:** It integrates with User Metrics Analysis (UMA) to record histograms of certain metrics.
* **Sampling:** It employs sampling techniques to reduce the volume of reported metrics, especially for frequently occurring events like Intersection Observer callbacks.
* **Document Update Reasons:**  It categorizes forced layout measurements based on the reason for the document update.
* **Interaction with Rendering Pipeline:** The tracked metrics (layout, style, paint, compositing) clearly indicate interaction with the Blink rendering engine.
* **Testing Support:**  It includes methods like `SetTickClockForTesting`, `ChooseNextFrameForTest`, and `DoNotChooseNextFrameForTest` suggesting it's designed for testability.

**Connecting to web technologies:**

* **JavaScript:** JavaScript interactions can trigger various rendering pipeline stages. For example, a JavaScript animation might cause style recalculation, layout, and paint. The `LocalFrameUkmAggregator` would measure the time spent in these stages triggered by the JavaScript.
* **HTML:** The structure of the HTML document influences the rendering process. Changes to the HTML (e.g., adding or removing elements) can trigger layout and paint. The aggregator would record the time taken for these updates.
* **CSS:** CSS styles directly impact the style calculation and layout phases. Changes to CSS or the application of different stylesheets would be reflected in the metrics collected by the aggregator.

**Logical Reasoning:**

Consider the `ScopedForcedLayoutTimer`. It measures the duration of a forced layout.

* **Input:**  A call to a JavaScript API (e.g., `offsetWidth`) that forces a synchronous layout.
* **Process:** The `ScopedForcedLayoutTimer` is instantiated at the beginning of the forced layout operation and its destructor is called at the end. The difference between the start and end times is recorded. The `DocumentUpdateReason` will indicate the source of the forced layout (e.g., `kJavaScript`).
* **Output:** The time taken for the forced layout, categorized by its reason. This data is then available for UKM reporting.

**Common Usage Errors:**

Developers working directly with this class are likely internal Chromium developers. Potential errors might involve:

* **Incorrect Metric ID:** Using the wrong `MetricId` when recording a sample.
* **Missing Timer Scope:**  Forgetting to use the scoped timer objects, leading to inaccurate or missing measurements.
* **Incorrect `DocumentUpdateReason`:**  Providing an inaccurate or generic `DocumentUpdateReason` when creating a `ScopedForcedLayoutTimer`.

**Plan for generating the response:**

1. **Functionalities:**  Summarize the core functionalities based on the analysis above, focusing on UKM aggregation, metric tracking, timer usage, FCP awareness, and UMA integration.
2. **Relationships with Web Technologies:** Provide examples linking the tracked metrics to JavaScript, HTML, and CSS actions.
3. **Logical Reasoning:**  Detail the `ScopedForcedLayoutTimer` example with clear input, process, and output.
4. **Common Usage Errors:** List potential mistakes developers might make when interacting with this class.
这是 `blink/renderer/core/frame/local_frame_ukm_aggregator.cc` 文件的功能列表：

1. **用户体验指标 (UKM) 聚合:**  该类的主要功能是收集和聚合与特定本地 frame 相关的用户体验指标 (UKM)。UKM 是一种匿名化的遥测技术，用于衡量用户的 Web 体验。

2. **性能指标跟踪:** 它跟踪各种性能相关的事件和持续时间，例如：
    * **主帧更新时间 (Main Frame Update Time):**  记录完成一个主帧更新所花费的时间。这是核心指标，并细分为多个子指标。
    * **子任务时间 (Sub-task Times):** 跟踪主帧更新过程中各个阶段所花费的时间，例如：
        * `CompositingCommit` (合成提交)
        * `CompositingInputs` (合成输入处理)
        * `ImplCompositorCommit` (Impl 线程合成提交)
        * `IntersectionObservation` (Intersection Observer 回调)
        * `Paint` (绘制)
        * `PrePaint` (预绘制)
        * `Style` (样式计算)
        * `Layout` (布局)
        * `ForcedStyleAndLayout` (强制样式计算和布局)
        * `HandleInputEvents` (处理输入事件)
        * `Animate` (动画)
        * `UpdateLayers` (更新图层)
        * `WaitForCommit` (等待提交)
        * 以及与 Intersection Observer 相关的更细粒度的指标 (例如 `DisplayLockIntersectionObserver`, `JavascriptIntersectionObserver`)
        * `VisualUpdateDelay` (视觉更新延迟)
        * 以及各种触发文档更新的原因 (例如 `UserDrivenDocumentUpdate`, `JavascriptDocumentUpdate`)
    * **强制布局时间 (Forced Layout Time):**  记录由 JavaScript 或其他操作触发的同步布局所花费的时间。它会根据触发强制布局的原因进行细分。

3. **First Contentful Paint (FCP) 感知:**  该类会跟踪 FCP 事件，并区分在 FCP 发生之前和之后记录的指标。这允许分析 FCP 对性能的影响。

4. **主帧更新周期跟踪:**  它能够区分在 `BeginMainFrame` 和 `EndForcedLayout` 之间发生的指标，用于更精确地分析主帧更新的性能。

5. **User Metrics Analysis (UMA) 集成:**  除了 UKM 之外，该类还会将某些关键指标记录到 UMA 中，用于更广泛的性能趋势分析。

6. **采样机制:**  为了控制 UKM 数据的量，它实现了一些采样机制，例如对 Intersection Observer 相关的指标进行降采样。

7. **分层计时器 (Hierarchical Timers):** 使用 `ScopedUkmHierarchicalTimer` 来方便地测量代码块的执行时间，并将其与特定的 UKM 指标关联起来。

8. **强制布局计时器 (Forced Layout Timer):** 使用 `ScopedForcedLayoutTimer` 来测量强制布局的持续时间，并记录触发强制布局的原因。

9. **测试支持:**  提供了 `SetTickClockForTesting` 等方法，允许在测试环境下控制时间，方便进行单元测试。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`LocalFrameUkmAggregator` 的功能与 JavaScript, HTML, CSS 密切相关，因为它度量的是渲染引擎处理这些 Web 技术时产生的性能开销。

* **JavaScript:**
    * **功能关系:** JavaScript 代码的执行可以触发 DOM 操作、样式修改、动画等，这些都会导致布局、样式计算和绘制等操作。`LocalFrameUkmAggregator` 会记录这些操作所花费的时间。
    * **举例:**
        * 当 JavaScript 代码修改了 DOM 结构 (例如使用 `document.createElement` 添加一个新元素) 时，可能会触发布局操作。`LocalFrameUkmAggregator` 会记录 `Layout` 指标的时间。
        * JavaScript 代码修改了元素的样式 (例如修改 `element.style.backgroundColor`) 时，会触发样式计算。`LocalFrameUkmAggregator` 会记录 `Style` 指标的时间。
        * 使用 `requestAnimationFrame` 创建的 JavaScript 动画会触发重绘和重排。`LocalFrameUkmAggregator` 会记录 `Animate`, `Layout`, `Paint` 等指标的时间。
        * 如果 JavaScript 代码中调用了会导致强制布局的属性或方法 (例如 `element.offsetWidth`)，`LocalFrameUkmAggregator` 会记录 `ForcedStyleAndLayout` 指标的时间，并且 `DocumentUpdateReason` 会是 `kJavaScriptDocumentUpdate`。
        * JavaScript 代码可以使用 Intersection Observer API 来监听元素是否进入或离开视口。`LocalFrameUkmAggregator` 会记录 `IntersectionObservation` 以及更细粒度的相关指标，例如 `JavascriptIntersectionObserver`。

* **HTML:**
    * **功能关系:** HTML 结构是网页的基础，其复杂程度和变化会直接影响渲染性能。
    * **举例:**
        * 加载一个包含大量 DOM 元素的 HTML 页面会导致更长的解析和布局时间。`LocalFrameUkmAggregator` 会记录 `Layout` 指标的时间。
        * HTML 中包含的图片、视频等资源加载会影响页面的渲染速度。虽然该文件本身不直接跟踪资源加载，但资源加载完成后的渲染更新会被记录。

* **CSS:**
    * **功能关系:** CSS 决定了网页的样式，复杂的 CSS 选择器和样式规则会导致更长的样式计算时间。
    * **举例:**
        * 当浏览器解析 CSS 样式表时，`LocalFrameUkmAggregator` 会记录 `ParseStyleSheet` 指标的时间。
        * 使用复杂的 CSS 选择器 (例如嵌套很深的组合选择器) 会增加样式计算的开销。`LocalFrameUkmAggregator` 会记录 `Style` 指标的时间。
        * CSS 动画和过渡效果会触发重绘和重排。`LocalFrameUkmAggregator` 会记录 `Animate`, `Layout`, `Paint` 等指标的时间。

**逻辑推理与假设输入输出:**

假设在一个主帧更新周期内，发生了以下事件：

**假设输入:**

1. `BeginMainFrame()` 被调用，标记主帧更新的开始。
2. JavaScript 代码执行，修改了一个 DOM 元素的样式，导致样式计算花费了 500 微秒。
3. JavaScript 代码触发了一个强制布局，花费了 1000 微秒，原因是用户交互 (`DocumentUpdateReason::kUserDrivenDocumentUpdate`)。
4. 浏览器进行布局计算，花费了 1500 微秒。
5. 浏览器进行绘制操作，花费了 2000 微秒。
6. `RecordEndOfFrameMetrics()` 被调用，标记主帧更新的结束，假设从开始到结束总共花费了 6000 微秒。

**逻辑推理与输出:**

*   当样式修改发生时，`ScopedUkmHierarchicalTimer` (或类似机制) 会记录样式计算的时间，最终 `absolute_metric_records_[kStyle].interval_count` 会增加 500。
*   当强制布局发生时，`ScopedForcedLayoutTimer` 会记录时间，`absolute_metric_records_[kForcedStyleAndLayout].interval_count` 会增加 1000，并且 `absolute_metric_records_[kUserDrivenDocumentUpdate].interval_count` 也会增加 1000。
*   当布局计算发生时，`ScopedUkmHierarchicalTimer` 会记录时间，`absolute_metric_records_[kLayout].interval_count` 会增加 1500。
*   当绘制操作发生时，`ScopedUkmHierarchicalTimer` 会记录时间，`absolute_metric_records_[kPaint].interval_count` 会增加 2000。
*   在 `RecordEndOfFrameMetrics()` 中，主帧更新的总时间会被记录，`primary_metric_.interval_count` 会是 6000。
*   如果 FCP 尚未发生，上述所有指标还会累加到对应的 `pre_fcp_aggregate` 字段中。
*   最终，当满足 UKM 上报条件时，这些数据会被组织成 `ukm::builders::Blink_UpdateTime` 事件并发送。

**涉及用户或编程常见的使用错误:**

由于 `LocalFrameUkmAggregator` 主要由 Blink 渲染引擎内部使用，普通 Web 开发者不会直接与其交互。但是，对于 Chromium 开发者来说，可能存在以下使用错误：

1. **忘记使用 Scoped Timer:**  如果手动测量时间而不使用 `ScopedUkmHierarchicalTimer` 或 `ScopedForcedLayoutTimer`，可能会导致代码更复杂，更容易出错，并且无法自动与 UKM 指标关联。

2. **使用错误的 MetricId:**  在调用 `RecordTimerSample` 或 `RecordCountSample` 时，如果使用了错误的 `MetricId`，会导致数据被记录到错误的指标下，影响分析结果。

3. **在错误的上下文调用方法:**  例如，在主帧更新之外调用 `RecordTimerSample` 记录与主帧相关的指标可能导致数据不准确。

4. **没有正确设置 DocumentUpdateReason:**  在使用 `ScopedForcedLayoutTimer` 时，如果提供的 `DocumentUpdateReason` 不准确，会导致强制布局的归因错误，影响性能分析。例如，将一个由 JavaScript 触发的强制布局标记为 `kUnknown`。

5. **过度或不足的采样配置:**  如果采样率配置不当，可能会导致收集到的数据量过大影响性能，或者数据量过小无法提供有意义的统计信息。

6. **在测试中没有正确 Mock 时间:**  如果需要进行时间相关的测试，但没有使用 `SetTickClockForTesting` 提供可控的时钟，可能会导致测试结果不稳定。

7. **修改了不应该修改的状态:**  直接修改 `LocalFrameUkmAggregator` 的内部状态，而不是通过提供的接口，可能会导致意想不到的行为和数据不一致。

Prompt: 
```
这是目录为blink/renderer/core/frame/local_frame_ukm_aggregator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/local_frame_ukm_aggregator.h"

#include <memory>

#include "base/feature_list.h"
#include "base/format_macros.h"
#include "base/metrics/histogram_functions.h"
#include "base/numerics/safe_conversions.h"
#include "base/rand_util.h"
#include "base/time/default_tick_clock.h"
#include "cc/metrics/begin_main_frame_metrics.h"
#include "services/metrics/public/cpp/metrics_utils.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "services/metrics/public/cpp/ukm_recorder.h"
#include "third_party/blink/public/common/metrics/document_update_reason.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace {

inline base::HistogramBase::Sample ToSample(int64_t value) {
  return base::saturated_cast<base::HistogramBase::Sample>(value);
}

inline int64_t ApplyBucket(int64_t value) {
  return ukm::GetExponentialBucketMinForCounts1000(value);
}

BASE_FEATURE(kAvoidUnnecessaryForcedLayoutMeasurements,
             "AvoidUnnecessaryForcedLayoutMeasurements",
             base::FEATURE_DISABLED_BY_DEFAULT);

}  // namespace

namespace blink {

int64_t LocalFrameUkmAggregator::ApplyBucketIfNecessary(int64_t value,
                                                        unsigned metric_id) {
  if (metric_id >= kIntersectionObservationInternalCount &&
      metric_id <= kIntersectionObservationJavascriptCount) {
    return ApplyBucket(value);
  }
  return value;
}

LocalFrameUkmAggregator::ScopedUkmHierarchicalTimer::ScopedUkmHierarchicalTimer(
    scoped_refptr<LocalFrameUkmAggregator> aggregator,
    size_t metric_index,
    const base::TickClock* clock)
    : aggregator_(aggregator),
      metric_index_(metric_index),
      clock_(clock),
      start_time_(aggregator && aggregator->ShouldMeasureMetric(metric_index)
                      ? clock_->NowTicks()
                      : base::TimeTicks()) {
  if (aggregator_ && !start_time_.is_null())
    TRACE_EVENT_BEGIN0("blink", aggregator_->metrics_data()[metric_index].name);
}

LocalFrameUkmAggregator::ScopedUkmHierarchicalTimer::ScopedUkmHierarchicalTimer(
    ScopedUkmHierarchicalTimer&& other)
    : aggregator_(other.aggregator_),
      metric_index_(other.metric_index_),
      clock_(other.clock_),
      start_time_(other.start_time_) {
  other.aggregator_ = nullptr;
}

LocalFrameUkmAggregator::ScopedUkmHierarchicalTimer::
    ~ScopedUkmHierarchicalTimer() {
  if (aggregator_ && !start_time_.is_null()) {
    if (base::TimeTicks::IsHighResolution()) {
      aggregator_->RecordTimerSample(metric_index_, start_time_,
                                     clock_->NowTicks());
    }
    TRACE_EVENT_END1("blink", aggregator_->metrics_data()[metric_index_].name,
                     "preFCP", aggregator_->fcp_state_ == kBeforeFCPSignal);
  }
}

LocalFrameUkmAggregator::IterativeTimer::IterativeTimer(
    LocalFrameUkmAggregator& aggregator)
    : aggregator_(base::TimeTicks::IsHighResolution() ? &aggregator : nullptr) {
}

LocalFrameUkmAggregator::IterativeTimer::~IterativeTimer() {
  if (aggregator_.get())
    Record(aggregator_->ShouldMeasureMetric(metric_index_), false);
}

void LocalFrameUkmAggregator::IterativeTimer::StartInterval(
    int64_t metric_index) {
  if (aggregator_.get() && metric_index != metric_index_) {
    bool should_record_prev_metric =
        aggregator_->ShouldMeasureMetric(metric_index_);
    bool should_record_next_metric =
        aggregator_->ShouldMeasureMetric(metric_index);
    Record(should_record_prev_metric, should_record_next_metric);
    if (should_record_next_metric)
      metric_index_ = metric_index;
  }
}

void LocalFrameUkmAggregator::IterativeTimer::Record(
    bool should_record_prev_metric,
    bool should_record_next_metric) {
  DCHECK(aggregator_.get());
  if (should_record_prev_metric || should_record_next_metric) {
    base::TimeTicks now = aggregator_->GetClock()->NowTicks();
    if (should_record_prev_metric) {
      aggregator_->RecordTimerSample(
          base::saturated_cast<size_t>(metric_index_), start_time_, now);
    }
    start_time_ = now;
  }
  metric_index_ = -1;
}

LocalFrameUkmAggregator::ScopedForcedLayoutTimer::ScopedForcedLayoutTimer(
    LocalFrameUkmAggregator& aggregator,
    DocumentUpdateReason update_reason,
    bool avoid_unnecessary_forced_layout_measurements,
    bool should_report_uma_this_frame,
    bool is_pre_fcp,
    bool record_ukm_for_current_frame)
    : aggregator_(&aggregator),
      update_reason_(update_reason),
      start_time_(!avoid_unnecessary_forced_layout_measurements ||
                          should_report_uma_this_frame || is_pre_fcp ||
                          record_ukm_for_current_frame
                      ? aggregator_->clock_->NowTicks()
                      : base::TimeTicks()),
      avoid_unnecessary_forced_layout_measurements_(
          avoid_unnecessary_forced_layout_measurements),
      should_report_uma_this_frame_(should_report_uma_this_frame),
      is_pre_fcp_(is_pre_fcp),
      record_ukm_for_current_frame_(record_ukm_for_current_frame) {
  aggregator_->BeginForcedLayout();
}

LocalFrameUkmAggregator::ScopedForcedLayoutTimer::~ScopedForcedLayoutTimer() {
  // aggregator_ will be null in a moved-from object.
  if (!aggregator_) {
    return;
  }

  aggregator_->EndForcedLayout(
      update_reason_,
      // start_time_ will be null if we don't need to measure this forced
      // layout, because it won't be reported.
      !start_time_.is_null() ? aggregator_->clock_->NowTicks() - start_time_
                             : base::TimeDelta(),
      avoid_unnecessary_forced_layout_measurements_,
      should_report_uma_this_frame_, is_pre_fcp_);
}

LocalFrameUkmAggregator::ScopedForcedLayoutTimer::ScopedForcedLayoutTimer(
    ScopedForcedLayoutTimer&&) = default;

LocalFrameUkmAggregator::ScopedForcedLayoutTimer&
LocalFrameUkmAggregator::ScopedForcedLayoutTimer::operator=(
    ScopedForcedLayoutTimer&&) = default;

void LocalFrameUkmAggregator::AbsoluteMetricRecord::reset() {
  interval_count = 0;
  main_frame_count = 0;
}

LocalFrameUkmAggregator::LocalFrameUkmAggregator()
    : clock_(base::DefaultTickClock::GetInstance()) {
  // All of these are assumed to have one entry per sub-metric.
  DCHECK_EQ(std::size(absolute_metric_records_), metrics_data().size());
  DCHECK_EQ(std::size(current_sample_.sub_metrics_counts),
            metrics_data().size());
  DCHECK_EQ(std::size(current_sample_.sub_main_frame_counts),
            metrics_data().size());

  // Record average and worst case for the primary metric.
  primary_metric_.reset();

  // Define the UMA for the primary metric.
  primary_metric_.pre_fcp_uma_counter = std::make_unique<CustomCountHistogram>(
      "Blink.MainFrame.UpdateTime.PreFCP", kTimeBasedHistogramMinSample,
      kTimeBasedHistogramMaxSample, kTimeBasedHistogramBucketCount);
  primary_metric_.post_fcp_uma_counter = std::make_unique<CustomCountHistogram>(
      "Blink.MainFrame.UpdateTime.PostFCP", kTimeBasedHistogramMinSample,
      kTimeBasedHistogramMaxSample, kTimeBasedHistogramBucketCount);
  primary_metric_.uma_aggregate_counter =
      std::make_unique<CustomCountHistogram>(
          "Blink.MainFrame.UpdateTime.AggregatedPreFCP",
          kTimeBasedHistogramMinSample, kTimeBasedHistogramMaxSample,
          kTimeBasedHistogramBucketCount);

  // Set up the substrings to create the UMA names
  const char* const uma_prefcp_postscript = ".PreFCP";
  const char* const uma_postfcp_postscript = ".PostFCP";
  const char* const uma_pre_fcp_aggregated_postscript = ".AggregatedPreFCP";

  // Populate all the sub-metrics.
  size_t metric_index = 0;
  for (const MetricInitializationData& metric_data : metrics_data()) {
    // Absolute records report the absolute time for each metric per frame.
    // They also aggregate the time spent in each stage between navigation
    // (LocalFrameView resets) and First Contentful Paint.
    // They have an associated UMA too that we own and allocate here.
    auto& absolute_record = absolute_metric_records_[metric_index];
    absolute_record.reset();
    absolute_record.pre_fcp_aggregate = 0;
    if (metric_data.has_uma) {
      StringBuilder pre_fcp_uma_name;
      pre_fcp_uma_name.Append(metric_data.name);
      pre_fcp_uma_name.Append(uma_prefcp_postscript);
      absolute_record.pre_fcp_uma_counter =
          std::make_unique<CustomCountHistogram>(
              pre_fcp_uma_name.ToString().Utf8().c_str(), 1, 10000000, 50);
      StringBuilder post_fcp_uma_name;
      post_fcp_uma_name.Append(metric_data.name);
      post_fcp_uma_name.Append(uma_postfcp_postscript);
      absolute_record.post_fcp_uma_counter =
          std::make_unique<CustomCountHistogram>(
              post_fcp_uma_name.ToString().Utf8().c_str(), 1, 10000000, 50);
      StringBuilder aggregated_uma_name;
      aggregated_uma_name.Append(metric_data.name);
      aggregated_uma_name.Append(uma_pre_fcp_aggregated_postscript);
      absolute_record.uma_aggregate_counter =
          std::make_unique<CustomCountHistogram>(
              aggregated_uma_name.ToString().Utf8().c_str(), 1, 10000000, 50);
    }

    metric_index++;
  }
}

LocalFrameUkmAggregator::~LocalFrameUkmAggregator() = default;

void LocalFrameUkmAggregator::TransmitFinalSample(int64_t source_id,
                                                  ukm::UkmRecorder* recorder,
                                                  bool is_for_main_frame) {
  ReportUpdateTimeEvent(source_id, recorder);
}

bool LocalFrameUkmAggregator::ShouldMeasureMetric(int64_t metric_id) const {
  if (metric_id < 0 || metric_id > kMainFrame)
    return false;

  // Downsample IntersectionObserver sub-categories. Note that
  // kIntersectionObservation, which measures a single aggregated time for all
  // IntersectionObserver-related work, is unaffected.
  if (metric_id >= kDisplayLockIntersectionObserver &&
      metric_id <= kUpdateViewportIntersection) {
    return frames_since_last_report_ % intersection_observer_sample_period_ ==
           0;
  }
  return true;
}

LocalFrameUkmAggregator::ScopedUkmHierarchicalTimer
LocalFrameUkmAggregator::GetScopedTimer(size_t metric_index) {
  return ScopedUkmHierarchicalTimer(this, metric_index, clock_);
}

LocalFrameUkmAggregator::ScopedForcedLayoutTimer
LocalFrameUkmAggregator::GetScopedForcedLayoutTimer(
    DocumentUpdateReason update_reason) {
  static const bool avoid_unnecessary_forced_layout_measurements =
      base::FeatureList::IsEnabled(kAvoidUnnecessaryForcedLayoutMeasurements);

  // Accumulate for UKM always, but only record the UMA for a subset of cases to
  // avoid overflowing the counters.
  bool should_report_uma_this_frame = !calls_to_next_forced_style_layout_uma_;
  if (should_report_uma_this_frame) {
    calls_to_next_forced_style_layout_uma_ =
        base::RandInt(0, mean_calls_between_forced_style_layout_uma_ * 2);
  } else {
    DCHECK_GT(calls_to_next_forced_style_layout_uma_, 0u);
    --calls_to_next_forced_style_layout_uma_;
  }

  bool is_pre_fcp = (fcp_state_ != kHavePassedFCP);

  return ScopedForcedLayoutTimer(
      *this, update_reason, avoid_unnecessary_forced_layout_measurements,
      should_report_uma_this_frame, is_pre_fcp, record_ukm_for_current_frame_);
}

void LocalFrameUkmAggregator::BeginMainFrame() {
  DCHECK(!in_main_frame_update_);
  in_main_frame_update_ = true;
  request_timestamp_for_current_frame_ = animation_request_timestamp_;
  animation_request_timestamp_.reset();
}

std::unique_ptr<cc::BeginMainFrameMetrics>
LocalFrameUkmAggregator::GetBeginMainFrameMetrics() {
  DCHECK(InMainFrameUpdate());

  // Use the main_frame_percentage_records_ because they are the ones that
  // only count time between the Begin and End of a main frame update.
  // Do not report hit testing because it is a sub-portion of the other
  // metrics and would result in double counting.
  std::unique_ptr<cc::BeginMainFrameMetrics> metrics_data =
      std::make_unique<cc::BeginMainFrameMetrics>();
  metrics_data->handle_input_events = base::Microseconds(
      absolute_metric_records_[static_cast<unsigned>(
                                   MetricId::kHandleInputEvents)]
          .main_frame_count);
  metrics_data->animate = base::Microseconds(
      absolute_metric_records_[static_cast<unsigned>(MetricId::kAnimate)]
          .main_frame_count);
  metrics_data->style_update = base::Microseconds(
      absolute_metric_records_[static_cast<unsigned>(MetricId::kStyle)]
          .main_frame_count);
  metrics_data->layout_update = base::Microseconds(
      absolute_metric_records_[static_cast<unsigned>(MetricId::kLayout)]
          .main_frame_count);
  metrics_data->accessibility = base::Microseconds(
      absolute_metric_records_[static_cast<unsigned>(MetricId::kAccessibility)]
          .main_frame_count);
  metrics_data->prepaint = base::Microseconds(
      absolute_metric_records_[static_cast<unsigned>(MetricId::kPrePaint)]
          .main_frame_count);
  metrics_data->compositing_inputs = base::Microseconds(
      absolute_metric_records_[static_cast<unsigned>(
                                   MetricId::kCompositingInputs)]
          .main_frame_count);
  metrics_data->paint = base::Microseconds(
      absolute_metric_records_[static_cast<unsigned>(MetricId::kPaint)]
          .main_frame_count);
  metrics_data->composite_commit = base::Microseconds(
      absolute_metric_records_[static_cast<unsigned>(
                                   MetricId::kCompositingCommit)]
          .main_frame_count);
  metrics_data->should_measure_smoothness =
      (fcp_state_ >= kThisFrameReachedFCP);
  return metrics_data;
}

void LocalFrameUkmAggregator::SetTickClockForTesting(
    const base::TickClock* clock) {
  clock_ = clock;
}

void LocalFrameUkmAggregator::DidReachFirstContentfulPaint() {
  if (fcp_state_ == kBeforeFCPSignal)
    fcp_state_ = kThisFrameReachedFCP;
}

void LocalFrameUkmAggregator::RecordTimerSample(size_t metric_index,
                                                base::TimeTicks start,
                                                base::TimeTicks end) {
  RecordCountSample(metric_index, (end - start).InMicroseconds());
}

void LocalFrameUkmAggregator::RecordCountSample(size_t metric_index,
                                                int64_t count) {
  // Always use EndForcedLayout for the kForcedStyleAndLayout metric id.
  DCHECK_NE(metric_index, static_cast<size_t>(kForcedStyleAndLayout));

  bool is_pre_fcp = (fcp_state_ != kHavePassedFCP);

  // Accumulate for UKM and record the UMA
  DCHECK_LT(metric_index, std::size(absolute_metric_records_));
  auto& record = absolute_metric_records_[metric_index];
  record.interval_count += count;
  if (in_main_frame_update_)
    record.main_frame_count += count;
  if (is_pre_fcp)
    record.pre_fcp_aggregate += count;

  // Subsampling these metrics reduced CPU utilization (crbug.com/1295441).
  if (!metrics_subsampler_.ShouldSample(0.001)) {
    return;
  }

  // Record the UMA
  // ForcedStyleAndLayout happen so frequently on some pages that we overflow
  // the signed 32 counter for number of events in a 30 minute period. So
  // randomly record with probability 1/1000.
  if (record.pre_fcp_uma_counter) {
    if (is_pre_fcp)
      record.pre_fcp_uma_counter->Count(ToSample(count));
    else
      record.post_fcp_uma_counter->Count(ToSample(count));
  }
}

void LocalFrameUkmAggregator::RecordEndOfFrameMetrics(
    base::TimeTicks start,
    base::TimeTicks end,
    cc::ActiveFrameSequenceTrackers trackers,
    int64_t source_id,
    ukm::UkmRecorder* recorder) {
  last_frame_request_timestamp_for_test_ =
      request_timestamp_for_current_frame_.value_or(base::TimeTicks());

  const int64_t count = (end - start).InMicroseconds();
  const bool have_valid_metrics =
      // Any of the early outs in LocalFrameView::UpdateLifecyclePhases() will
      // mean we are not in a main frame update. Recording is triggered higher
      // in the stack, so we cannot know to avoid calling this method.
      in_main_frame_update_ &&
      // In tests it's possible to reach here with zero duration.
      (count > 0);

  in_main_frame_update_ = false;
  if (!have_valid_metrics) {
    // Reset for the next frame to start the next recording period with
    // clear counters, even when we did not record anything this frame.
    ResetAllMetrics();
    return;
  }

  if (request_timestamp_for_current_frame_.has_value()) {
    RecordTimerSample(kVisualUpdateDelay,
                      request_timestamp_for_current_frame_.value(), start);
  }

  bool report_as_pre_fcp = (fcp_state_ != kHavePassedFCP);
  bool report_fcp_metrics = (fcp_state_ == kThisFrameReachedFCP);

  // Record UMA
  if (report_as_pre_fcp)
    primary_metric_.pre_fcp_uma_counter->Count(ToSample(count));
  else
    primary_metric_.post_fcp_uma_counter->Count(ToSample(count));

  // Record primary time information
  primary_metric_.interval_count = count;
  if (report_as_pre_fcp)
    primary_metric_.pre_fcp_aggregate += count;

  bool record_ukm_for_next_frame = false;
  UpdateEventTimeAndUpdateSampleIfNeeded(trackers, record_ukm_for_next_frame);

  // Report the FCP metrics, if necessary, after updating the sample so that
  // the sample has been recorded for the frame that produced FCP.
  if (report_fcp_metrics) {
    ReportPreFCPEvent(source_id, recorder);
    ReportUpdateTimeEvent(source_id, recorder);
    // Update the state to prevent future reporting.
    fcp_state_ = kHavePassedFCP;
  }

  // Reset for the next frame.
  ResetAllMetrics();

  record_ukm_for_current_frame_ = record_ukm_for_next_frame;
}

void LocalFrameUkmAggregator::UpdateEventTimeAndUpdateSampleIfNeeded(
    cc::ActiveFrameSequenceTrackers trackers,
    bool& record_ukm_for_next_frame) {
  // Regardless of test requests always capture the first frame, since
  // record_current_ukm_frame_ is initialized to true.
  if (record_ukm_for_current_frame_) {
    UpdateSample(trackers);
  }

  // Update the frame count first, because it must include this frame
  frames_since_last_report_++;

  // Exit if in testing and we do not want to update this frame
  if (next_frame_sample_control_for_test_ == kMustNotChooseNextFrame)
    return;

  // Update the sample with probability 1/frames_since_last_report_, or if
  // testing demand is.
  record_ukm_for_next_frame =
      (next_frame_sample_control_for_test_ == kMustChooseNextFrame) ||
      base::RandDouble() < 1 / static_cast<double>(frames_since_last_report_);
}

void LocalFrameUkmAggregator::UpdateSample(
    cc::ActiveFrameSequenceTrackers trackers) {
  current_sample_.primary_metric_count = primary_metric_.interval_count;
  for (size_t i = 0; i < metrics_data().size(); ++i) {
    current_sample_.sub_metrics_counts[i] =
        absolute_metric_records_[i].interval_count;
    current_sample_.sub_main_frame_counts[i] =
        absolute_metric_records_[i].main_frame_count;
  }
  current_sample_.trackers = trackers;
}

void LocalFrameUkmAggregator::ReportPreFCPEvent(int64_t source_id,
                                                ukm::UkmRecorder* recorder) {
#define RECORD_METRIC(name)                                         \
  {                                                                 \
    auto& absolute_record = absolute_metric_records_[k##name];      \
    if (absolute_record.uma_aggregate_counter) {                    \
      absolute_record.uma_aggregate_counter->Count(                 \
          ToSample(absolute_record.pre_fcp_aggregate));             \
    }                                                               \
    builder.Set##name(ToSample(absolute_record.pre_fcp_aggregate)); \
  }

#define RECORD_BUCKETED_METRIC(name)                               \
  {                                                                \
    auto& absolute_record = absolute_metric_records_[k##name];     \
    if (absolute_record.uma_aggregate_counter) {                   \
      absolute_record.uma_aggregate_counter->Count(                \
          ToSample(absolute_record.pre_fcp_aggregate));            \
    }                                                              \
    builder.Set##name(                                             \
        ToSample(ApplyBucket(absolute_record.pre_fcp_aggregate))); \
  }

  if (!recorder) {
    return;
  }
  ukm::builders::Blink_PageLoad builder(source_id);
  primary_metric_.uma_aggregate_counter->Count(
      ToSample(primary_metric_.pre_fcp_aggregate));
  builder.SetMainFrame(ToSample(primary_metric_.pre_fcp_aggregate));

  RECORD_METRIC(CompositingCommit);
  RECORD_METRIC(CompositingInputs);
  RECORD_METRIC(ImplCompositorCommit);
  RECORD_METRIC(IntersectionObservation);
  RECORD_BUCKETED_METRIC(IntersectionObservationInternalCount);
  RECORD_BUCKETED_METRIC(IntersectionObservationJavascriptCount);
  RECORD_METRIC(Paint);
  RECORD_METRIC(PrePaint);
  RECORD_METRIC(Style);
  RECORD_METRIC(Layout);
  RECORD_METRIC(ForcedStyleAndLayout);
  RECORD_METRIC(HandleInputEvents);
  RECORD_METRIC(Animate);
  RECORD_METRIC(UpdateLayers);
  RECORD_METRIC(WaitForCommit);
  RECORD_METRIC(DisplayLockIntersectionObserver);
  RECORD_METRIC(JavascriptIntersectionObserver);
  RECORD_METRIC(LazyLoadIntersectionObserver);
  RECORD_METRIC(MediaIntersectionObserver);
  RECORD_METRIC(PermissionElementIntersectionObserver);
  RECORD_METRIC(AnchorElementMetricsIntersectionObserver);
  RECORD_METRIC(UpdateViewportIntersection);
  RECORD_METRIC(VisualUpdateDelay);
  RECORD_METRIC(UserDrivenDocumentUpdate);
  RECORD_METRIC(ServiceDocumentUpdate);
  RECORD_METRIC(ContentDocumentUpdate);
  RECORD_METRIC(HitTestDocumentUpdate);
  RECORD_METRIC(JavascriptDocumentUpdate);
  RECORD_METRIC(ParseStyleSheet);
  RECORD_METRIC(Accessibility);
  RECORD_METRIC(PossibleSynchronizedScrollCount2);

  builder.Record(recorder);
#undef RECORD_METRIC
#undef RECORD_BUCKETED_METRIC
}

void LocalFrameUkmAggregator::ReportUpdateTimeEvent(
    int64_t source_id,
    ukm::UkmRecorder* recorder) {
  // Don't report if we haven't generated any samples.
  if (!recorder || !frames_since_last_report_) {
    return;
  }

#define RECORD_METRIC(name)                                      \
  builder.Set##name(current_sample_.sub_metrics_counts[k##name]) \
      .Set##name##BeginMainFrame(                                \
          current_sample_.sub_main_frame_counts[k##name]);

#define RECORD_BUCKETED_METRIC(name)                                          \
  builder.Set##name(ApplyBucket(current_sample_.sub_metrics_counts[k##name])) \
      .Set##name##BeginMainFrame(                                             \
          ApplyBucket(current_sample_.sub_main_frame_counts[k##name]));

  ukm::builders::Blink_UpdateTime builder(source_id);
  builder.SetMainFrame(current_sample_.primary_metric_count);
  builder.SetMainFrameIsBeforeFCP(fcp_state_ != kHavePassedFCP);
  builder.SetMainFrameReasons(current_sample_.trackers);
  RECORD_METRIC(CompositingCommit);
  RECORD_METRIC(CompositingInputs);
  RECORD_METRIC(ImplCompositorCommit);
  RECORD_METRIC(IntersectionObservation);
  RECORD_BUCKETED_METRIC(IntersectionObservationInternalCount);
  RECORD_BUCKETED_METRIC(IntersectionObservationJavascriptCount);
  RECORD_METRIC(Paint);
  RECORD_METRIC(PrePaint);
  RECORD_METRIC(Style);
  RECORD_METRIC(Layout);
  RECORD_METRIC(ForcedStyleAndLayout);
  RECORD_METRIC(HandleInputEvents);
  RECORD_METRIC(Animate);
  RECORD_METRIC(UpdateLayers);
  RECORD_METRIC(WaitForCommit);
  RECORD_METRIC(DisplayLockIntersectionObserver);
  RECORD_METRIC(JavascriptIntersectionObserver);
  RECORD_METRIC(LazyLoadIntersectionObserver);
  RECORD_METRIC(MediaIntersectionObserver);
  RECORD_METRIC(PermissionElementIntersectionObserver);
  RECORD_METRIC(AnchorElementMetricsIntersectionObserver);
  RECORD_METRIC(UpdateViewportIntersection);
  RECORD_METRIC(VisualUpdateDelay);
  RECORD_METRIC(UserDrivenDocumentUpdate);
  RECORD_METRIC(ServiceDocumentUpdate);
  RECORD_METRIC(ContentDocumentUpdate);
  RECORD_METRIC(HitTestDocumentUpdate);
  RECORD_METRIC(JavascriptDocumentUpdate);
  RECORD_METRIC(ParseStyleSheet);
  RECORD_METRIC(Accessibility);
  RECORD_METRIC(PossibleSynchronizedScrollCount2);

  builder.Record(recorder);
#undef RECORD_METRIC
#undef RECORD_BUCKETED_METRIC

  // Reset the frames since last report to ensure correct sampling.
  frames_since_last_report_ = 0;
}

void LocalFrameUkmAggregator::ResetAllMetrics() {
  primary_metric_.reset();
  for (auto& record : absolute_metric_records_)
    record.reset();
  request_timestamp_for_current_frame_.reset();
}

void LocalFrameUkmAggregator::BeginForcedLayout() {
  TRACE_EVENT_BEGIN0("blink", metrics_data()[kForcedStyleAndLayout].name);
}

void LocalFrameUkmAggregator::EndForcedLayout(
    DocumentUpdateReason reason,
    base::TimeDelta duration,
    bool avoid_unnecessary_forced_layout_measurements,
    bool should_report_uma_this_frame,
    bool is_pre_fcp) {
  TRACE_EVENT_END1("blink", metrics_data()[kForcedStyleAndLayout].name,
                   "preFCP", fcp_state_ == kBeforeFCPSignal);

  if (avoid_unnecessary_forced_layout_measurements &&
      !(should_report_uma_this_frame || is_pre_fcp ||
        record_ukm_for_current_frame_)) {
    return;
  }

  int64_t count = duration.InMicroseconds();

  auto& record =
      absolute_metric_records_[static_cast<size_t>(kForcedStyleAndLayout)];
  record.interval_count += count;
  if (in_main_frame_update_) {
    record.main_frame_count += count;
  }
  if (is_pre_fcp) {
    record.pre_fcp_aggregate += count;
  }

  if (should_report_uma_this_frame) {
    if (is_pre_fcp) {
      record.pre_fcp_uma_counter->Count(ToSample(count));
    } else {
      record.post_fcp_uma_counter->Count(ToSample(count));
    }
  }

  // Record a variety of DocumentUpdateReasons as distinct metrics
  // Figure out which sub-metric, if any, we wish to report for UKM.
  MetricId sub_metric = kCount;
  switch (reason) {
    case DocumentUpdateReason::kContextMenu:
    case DocumentUpdateReason::kDragImage:
    case DocumentUpdateReason::kEditing:
    case DocumentUpdateReason::kFindInPage:
    case DocumentUpdateReason::kFocus:
    case DocumentUpdateReason::kFocusgroup:
    case DocumentUpdateReason::kForm:
    case DocumentUpdateReason::kInput:
    case DocumentUpdateReason::kInspector:
    case DocumentUpdateReason::kPrinting:
    case DocumentUpdateReason::kScroll:
    case DocumentUpdateReason::kSelection:
    case DocumentUpdateReason::kSpatialNavigation:
    case DocumentUpdateReason::kTapHighlight:
      sub_metric = kUserDrivenDocumentUpdate;
      break;

    case DocumentUpdateReason::kAccessibility:
    case DocumentUpdateReason::kBaseColor:
    case DocumentUpdateReason::kComputedStyle:
    case DocumentUpdateReason::kDisplayLock:
    case DocumentUpdateReason::kViewTransition:
    case DocumentUpdateReason::kIntersectionObservation:
    case DocumentUpdateReason::kOverlay:
    case DocumentUpdateReason::kPagePopup:
    case DocumentUpdateReason::kPopover:
    case DocumentUpdateReason::kSizeChange:
    case DocumentUpdateReason::kSpellCheck:
    case DocumentUpdateReason::kSMILAnimation:
    case DocumentUpdateReason::kWebAnimation:
      sub_metric = kServiceDocumentUpdate;
      break;

    case DocumentUpdateReason::kCanvas:
    case DocumentUpdateReason::kPlugin:
    case DocumentUpdateReason::kSVGImage:
      sub_metric = kContentDocumentUpdate;
      break;

    case DocumentUpdateReason::kHitTest:
      sub_metric = kHitTestDocumentUpdate;
      break;

    case DocumentUpdateReason::kJavaScript:
      sub_metric = kJavascriptDocumentUpdate;
      break;

    // Do not report main frame because we have it already from
    // in_main_frame_update_ above.
    case DocumentUpdateReason::kBeginMainFrame:
    // No metrics from testing.
    case DocumentUpdateReason::kTest:
    // Don't report if we don't know why.
    case DocumentUpdateReason::kUnknown:
    // TODO(https://crbug.com/336963892): Give prerender a dedicated metric.
    case DocumentUpdateReason::kPrerender:
      break;
  }

  if (sub_metric != kCount) {
    auto& sub_record =
        absolute_metric_records_[static_cast<size_t>(sub_metric)];
    sub_record.interval_count += count;
    if (in_main_frame_update_) {
      sub_record.main_frame_count += count;
    }
    if (is_pre_fcp) {
      sub_record.pre_fcp_aggregate += count;
    }
    if (should_report_uma_this_frame) {
      if (is_pre_fcp) {
        sub_record.pre_fcp_uma_counter->Count(ToSample(count));
      } else {
        sub_record.post_fcp_uma_counter->Count(ToSample(count));
      }
    }
  }
}

void LocalFrameUkmAggregator::RecordImplCompositorSample(
    base::TimeTicks requested,
    base::TimeTicks started,
    base::TimeTicks completed) {
  // Record the time spent waiting for the commit based on requested
  // (which came from ProxyImpl::BeginMainFrame) and started as reported by
  // the impl thread. If started is zero, no time was spent
  // processing. This can only happen if the commit was aborted because there
  // was no change and we did not wait for the impl thread at all. Attribute
  // all time to the compositor commit so as to not imply that wait time was
  // consumed.
  if (started == base::TimeTicks()) {
    RecordTimerSample(kImplCompositorCommit, requested, completed);
  } else {
    RecordTimerSample(kWaitForCommit, requested, started);
    RecordTimerSample(kImplCompositorCommit, started, completed);
  }
}

void LocalFrameUkmAggregator::ChooseNextFrameForTest() {
  next_frame_sample_control_for_test_ = kMustChooseNextFrame;
}

void LocalFrameUkmAggregator::DoNotChooseNextFrameForTest() {
  next_frame_sample_control_for_test_ = kMustNotChooseNextFrame;
}

bool LocalFrameUkmAggregator::IsBeforeFCPForTesting() const {
  return fcp_state_ == kBeforeFCPSignal;
}

void LocalFrameUkmAggregator::OnCommitRequested() {
  // This can't be a DCHECK because this method can be called during the early
  // stages of cc::ProxyMain::BeginMainFrame, before
  // LocalFrameUkmAggregator::BeginMainFrame() has been invoked.
  if (!animation_request_timestamp_.has_value())
    animation_request_timestamp_.emplace(clock_->NowTicks());
}

}  // namespace blink

"""

```