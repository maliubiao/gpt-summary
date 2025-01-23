Response:
The user wants to understand the functionality of the `local_frame_ukm_aggregator_test.cc` file in the Chromium Blink engine. I need to analyze the code and provide a summary of its purpose, highlighting its relationship with web technologies like JavaScript, HTML, and CSS, and including examples of logical reasoning, user errors, and a concise overall function.

**Plan:**

1. **Identify the core purpose:** The file is a unit test for the `LocalFrameUkmAggregator` class.
2. **Explain UKM:** Briefly explain what UKM (User Keyed Metrics) is and how it's relevant to this test.
3. **Summarize tested functionalities:** List the key aspects of `LocalFrameUkmAggregator` being tested, focusing on how it collects and reports performance metrics.
4. **Relate to web technologies:** Explain how the tested functionalities relate to JavaScript, HTML, and CSS rendering and execution.
5. **Provide examples:** Give concrete examples of how the tests simulate scenarios involving these technologies.
6. **Illustrate logical reasoning:** Identify test cases that demonstrate logical deductions about metric reporting.
7. **Mention potential user errors:** Although not directly user-facing, consider developer errors or misconfigurations related to performance.
8. **Concisely summarize the file's function.**
这个文件 `local_frame_ukm_aggregator_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用于测试 `LocalFrameUkmAggregator` 类的功能。`LocalFrameUkmAggregator` 的主要职责是收集和聚合与特定本地帧（LocalFrame）相关的性能指标，并将这些指标通过 UKM (User Keyed Metrics) 系统上报。

**主要功能归纳:**

该测试文件的主要功能是验证 `LocalFrameUkmAggregator` 类是否能正确地：

1. **记录和聚合各种性能指标：** 包括页面加载、渲染过程中的各个阶段的耗时，例如样式计算、布局、绘制等。
2. **处理 pre-FCP (First Contentful Paint) 和 post-FCP 的指标：**  区分在首次内容绘制之前和之后发生的事件，并分别记录和上报。
3. **处理帧相关的指标：** 记录每一帧的性能数据，并根据一定的采样策略进行上报。
4. **处理由不同原因引起的强制布局 (Forced Layout)：**  区分用户驱动、服务驱动、内容驱动等多种原因导致的强制布局，并记录相应的指标。
5. **处理 Intersection Observer 相关的指标：** 记录内部和 JavaScript 创建的 Intersection Observer 的数量。
6. **正确地将聚合后的指标通过 UKM 系统上报。**

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`LocalFrameUkmAggregator` 收集的许多指标都直接关系到浏览器如何处理 JavaScript, HTML, 和 CSS：

*   **JavaScript 执行:**  JavaScript 的执行可能会触发样式计算、布局和绘制。测试中会模拟 JavaScript 引起的强制布局，例如通过 `DocumentUpdateReason::kJavaScript`。这会影响到例如 `GetMetricName(LocalFrameUkmAggregator::kJavascriptDocumentUpdate)` 对应的指标。
    *   **假设输入:** 一个 JavaScript 脚本修改了 DOM 结构或样式，导致强制布局。
    *   **预期输出:** UKM 系统中会记录到 `kJavascriptDocumentUpdate` 相关的指标，反映这次强制布局的耗时。

*   **HTML 解析和 DOM 构建:** HTML 的解析和 DOM 树的构建是页面加载的重要环节。虽然测试中没有直接模拟 HTML 解析，但通过模拟帧的开始和结束，可以间接测试与 DOM 构建完成相关的指标。

*   **CSS 样式计算和布局:** CSS 决定了页面的渲染外观。样式计算和布局是渲染流水线中的关键步骤。测试中会模拟样式计算和布局的耗时，例如通过 `SimulateFrame` 函数模拟各个渲染阶段的耗时。
    *   **假设输入:** CSS 规则被加载和应用，需要计算元素的最终样式和布局位置。
    *   **预期输出:** UKM 系统中会记录到 `kStyle` 和 `kLayout` 等指标的耗时。

*   **Intersection Observer:** Intersection Observer API 允许 JavaScript 异步地观察目标元素与其祖先元素或 viewport 的交叉状态。测试中会模拟创建和使用 Intersection Observer，并记录其数量。
    *   **假设输入:** JavaScript 代码创建了多个 Intersection Observer 来监听元素的可见性变化。
    *   **预期输出:** UKM 系统中会记录到 `Blink.IntersectionObservationInternalCount.UpdateTime.PreFCP` 和 `Blink.IntersectionObservationJavascriptCount.UpdateTime.PreFCP` 等指标，反映不同类型的 Intersection Observer 的数量。

**逻辑推理的假设输入与输出:**

*   **假设输入:**  连续调用 `SimulateFrame` 函数，模拟多个帧的渲染过程，并在其中某一帧调用 `aggregator().DidReachFirstContentfulPaint()` 标记 FCP。
*   **预期输出:** UKM 系统中会分别记录 pre-FCP 和 post-FCP 的性能指标，并且 pre-FCP 的指标会被聚合上报。可以通过 `VerifyUpdateEntry` 函数来验证 pre-FCP 和 post-FCP 指标的记录，通过 `VerifyAggregatedEntries` 函数验证 pre-FCP 指标的聚合。

**用户或编程常见的使用错误举例说明:**

虽然 `LocalFrameUkmAggregator` 是引擎内部的组件，普通用户不会直接使用，但编程错误可能导致性能数据收集不准确或上报错误。

*   **错误示例:** 在引擎开发过程中，如果错误地标记了 FCP 的时间点，可能会导致 pre-FCP 和 post-FCP 的指标划分错误，从而影响性能分析。测试用例 `TEST_F(LocalFrameUkmAggregatorTest, PreAndPostFCPAreRecorded)`  就旨在验证 FCP 标记后指标是否被正确处理。

**当前部分的功能归纳 (第1部分):**

这部分测试代码主要关注 `LocalFrameUkmAggregator` 在以下方面的功能：

1. **基本的指标记录：** 验证在没有事件发生或发生首次帧时，指标是否被正确记录。
2. **pre-FCP 指标的记录：** 验证在首次内容绘制之前发生的事件的指标是否被记录和上报。
3. **pre-FCP 指标的聚合：** 验证在 FCP 发生后，pre-FCP 期间收集的指标是否被正确聚合并上报。
4. **强制布局原因的区分和记录：** 验证不同原因引起的强制布局是否被正确识别并记录到相应的 UKM 指标中。
5. **延迟数据的填充：** 验证与帧开始时一些事件相关的延迟数据是否被正确填充。
6. **采样机制的验证：** 验证指标采样机制是否按预期工作，确保指标不会在每次帧都上报。
7. **IterativeTimer 的使用：**  验证 `IterativeTimer` 辅助类是否能正确记录多个间隔的时间。
8. **Intersection Observer 采样周期的影响：** 验证设置 Intersection Observer 采样周期后，指标上报是否符合预期。

总而言之，这部分测试用例覆盖了 `LocalFrameUkmAggregator` 核心的指标收集和聚合功能，并确保其在各种场景下都能正确工作，为后续的性能分析提供可靠的数据基础。

### 提示词
```
这是目录为blink/renderer/core/frame/local_frame_ukm_aggregator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/local_frame_ukm_aggregator.h"

#include "base/metrics/statistics_recorder.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/test_mock_time_task_runner.h"
#include "cc/metrics/begin_main_frame_metrics.h"
#include "components/ukm/test_ukm_recorder.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/metrics/document_update_reason.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_intersection_observer_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_document_element.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing.h"
#include "third_party/blink/renderer/core/testing/intersection_observer_test_helper.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support_with_mock_scheduler.h"

namespace blink {

class LocalFrameUkmAggregatorTest : public testing::Test {
 public:
  LocalFrameUkmAggregatorTest() = default;
  ~LocalFrameUkmAggregatorTest() override = default;

  void SetUp() override {
    test_task_runner_ = base::MakeRefCounted<base::TestMockTimeTaskRunner>(
        base::Time::UnixEpoch(), base::TimeTicks::Now());
    RestartAggregator();
  }

  void TearDown() override {
    aggregator_.reset();
  }

  int64_t source_id() const { return source_id_; }

  LocalFrameUkmAggregator& aggregator() {
    CHECK(aggregator_);
    return *aggregator_;
  }

  ukm::TestUkmRecorder& recorder() { return recorder_; }

  void ResetAggregator() {
    if (aggregator_) {
      aggregator_->TransmitFinalSample(source_id(), &recorder(),
                                       /* is_for_main_frame */ true);
      aggregator_.reset();
    }
  }

  void RestartAggregator() {
    source_id_ = ukm::UkmRecorder::GetNewSourceID();
    aggregator_ = base::MakeRefCounted<LocalFrameUkmAggregator>();
    aggregator_->SetTickClockForTesting(test_task_runner_->GetMockTickClock());
  }

  std::string GetPrimaryMetricName() {
    return LocalFrameUkmAggregator::primary_metric_name();
  }

  std::string GetMetricName(int index) {
    std::string name =
        LocalFrameUkmAggregator::metrics_data()[base::checked_cast<size_t>(
                                                    index)]
            .name;

    // If `name` is an UMA metric of the form Blink.[MetricName].UpdateTime, the
    // following code extracts out [MetricName] for building up the UKM metric.
    const char* const uma_postscript = ".UpdateTime";
    size_t postscript_pos = name.find(uma_postscript);
    if (postscript_pos) {
      const char* const uma_preamble = "Blink.";
      size_t preamble_length = strlen(uma_preamble);
      name = name.substr(preamble_length, postscript_pos - preamble_length);
    }
    return name;
  }

  std::string GetBeginMainFrameMetricName(int index) {
    return GetMetricName(index) + "BeginMainFrame";
  }

  int64_t GetIntervalCount(int index) {
    return aggregator_->absolute_metric_records_[index].interval_count;
  }

  void ChooseNextFrameForTest() { aggregator().ChooseNextFrameForTest(); }
  void DoNotChooseNextFrameForTest() {
    aggregator().DoNotChooseNextFrameForTest();
  }

  void SetIntersectionObserverSamplePeriodForTesting(size_t period) {
    aggregator_->SetIntersectionObserverSamplePeriodForTesting(period);
  }

  base::TimeTicks Now() { return test_task_runner_->NowTicks(); }

 protected:
  scoped_refptr<base::TestMockTimeTaskRunner> test_task_runner_;

  void VerifyUpdateEntry(unsigned index,
                         unsigned expected_primary_metric,
                         unsigned expected_sub_metric,
                         unsigned expected_begin_main_frame,
                         unsigned expected_reasons,
                         bool expected_before_fcp) {
    auto entries = recorder().GetEntriesByName("Blink.UpdateTime");
    EXPECT_GT(entries.size(), index);

    auto* entry = entries[index].get();
    EXPECT_TRUE(
        ukm::TestUkmRecorder::EntryHasMetric(entry, GetPrimaryMetricName()));
    const int64_t* primary_metric_value =
        ukm::TestUkmRecorder::GetEntryMetric(entry, GetPrimaryMetricName());
    EXPECT_NEAR(*primary_metric_value, expected_primary_metric * 1e3, 1);
    // All tests using this method check through kForcedStyleAndLayout because
    // kForcedStyleAndLayout and subsequent metrics report and record
    // differently.
    for (int i = 0; i < LocalFrameUkmAggregator::kForcedStyleAndLayout; ++i) {
      EXPECT_TRUE(
          ukm::TestUkmRecorder::EntryHasMetric(entry, GetMetricName(i)));
      const int64_t* metric_value =
          ukm::TestUkmRecorder::GetEntryMetric(entry, GetMetricName(i));
      EXPECT_NEAR(*metric_value,
                  LocalFrameUkmAggregator::ApplyBucketIfNecessary(
                      expected_sub_metric * 1e3, i),
                  1);

      EXPECT_TRUE(ukm::TestUkmRecorder::EntryHasMetric(
          entry, GetBeginMainFrameMetricName(i)));
      const int64_t* metric_begin_main_frame =
          ukm::TestUkmRecorder::GetEntryMetric(entry,
                                               GetBeginMainFrameMetricName(i));
      EXPECT_NEAR(*metric_begin_main_frame,
                  LocalFrameUkmAggregator::ApplyBucketIfNecessary(
                      expected_begin_main_frame * 1e3, i),
                  1);
    }
    EXPECT_TRUE(
        ukm::TestUkmRecorder::EntryHasMetric(entry, "MainFrameIsBeforeFCP"));
    EXPECT_EQ(expected_before_fcp, *ukm::TestUkmRecorder::GetEntryMetric(
                                       entry, "MainFrameIsBeforeFCP"));
    EXPECT_TRUE(
        ukm::TestUkmRecorder::EntryHasMetric(entry, "MainFrameReasons"));
    EXPECT_EQ(expected_reasons,
              *ukm::TestUkmRecorder::GetEntryMetric(entry, "MainFrameReasons"));
  }

  void VerifyAggregatedEntries(unsigned expected_num_entries,
                               unsigned expected_primary_metric,
                               unsigned expected_sub_metric) {
    auto entries = recorder().GetEntriesByName("Blink.PageLoad");

    EXPECT_EQ(entries.size(), expected_num_entries);
    for (const ukm::mojom::UkmEntry* entry : entries) {
      EXPECT_TRUE(
          ukm::TestUkmRecorder::EntryHasMetric(entry, GetPrimaryMetricName()));
      const int64_t* primary_metric_value =
          ukm::TestUkmRecorder::GetEntryMetric(entry, GetPrimaryMetricName());
      EXPECT_NEAR(*primary_metric_value, expected_primary_metric * 1e3, 1);
      // All tests using this method check through kForcedStyleAndLayout because
      // kForcedStyleAndLayout and subsequent metrics report and record
      // differently.
      for (int i = 0; i < LocalFrameUkmAggregator::kForcedStyleAndLayout; ++i) {
        EXPECT_TRUE(
            ukm::TestUkmRecorder::EntryHasMetric(entry, GetMetricName(i)));
        const int64_t* metric_value =
            ukm::TestUkmRecorder::GetEntryMetric(entry, GetMetricName(i));
        EXPECT_NEAR(*metric_value,
                    LocalFrameUkmAggregator::ApplyBucketIfNecessary(
                        expected_sub_metric * 1e3, i),
                    1);
      }
    }
  }

  void SimulateFrame(base::TimeTicks start_time,
                     unsigned millisecond_per_step,
                     cc::ActiveFrameSequenceTrackers trackers,
                     bool mark_fcp = false) {
    aggregator().BeginMainFrame();
    // All tests using this method run through kForcedStyleAndLayout because
    // kForcedStyleAndLayout is not reported using a ScopedTimer and the
    // subsequent metrics are reported as part of kForcedStyleAndLayout.
    for (int i = 0; i < LocalFrameUkmAggregator::kForcedStyleAndLayout; ++i) {
      auto timer = aggregator().GetScopedTimer(i);
      if (mark_fcp && i == static_cast<int>(LocalFrameUkmAggregator::kPaint))
        aggregator().DidReachFirstContentfulPaint();
      test_task_runner_->FastForwardBy(
          base::Milliseconds(millisecond_per_step));
    }
    aggregator().RecordEndOfFrameMetrics(start_time, Now(), trackers,
                                         source_id(), &recorder());
  }

  void SimulatePreFrame(unsigned millisecond_per_step) {
    // All tests using this method run through kForcedStyleAndLayout because
    // kForcedStyleAndLayout is not reported using a ScopedTimer and the
    // subsequent metrics are reported as part of kForcedStyleAndLayout.
    for (int i = 0; i < LocalFrameUkmAggregator::kForcedStyleAndLayout; ++i) {
      auto timer = aggregator().GetScopedTimer(i);
      test_task_runner_->FastForwardBy(
          base::Milliseconds(millisecond_per_step));
    }
  }

  void SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason reason,
      LocalFrameUkmAggregator::MetricId target_metric,
      unsigned expected_num_entries) {
    base::TimeTicks start_time = Now();
    aggregator().BeginMainFrame();
    {
      LocalFrameUkmAggregator::ScopedForcedLayoutTimer timer =
          aggregator().GetScopedForcedLayoutTimer(reason);
      test_task_runner_->FastForwardBy(base::Milliseconds(10));
    }
    aggregator().RecordEndOfFrameMetrics(start_time, Now(), 0, source_id(),
                                         &recorder());
    ResetAggregator();

    EXPECT_EQ(recorder().entries_count(), expected_num_entries);
    auto entries = recorder().GetEntriesByName("Blink.UpdateTime");
    EXPECT_GT(entries.size(), expected_num_entries - 1);
    auto* entry = entries[expected_num_entries - 1].get();

    EXPECT_TRUE(ukm::TestUkmRecorder::EntryHasMetric(
        entry, GetMetricName(LocalFrameUkmAggregator::kForcedStyleAndLayout)));
    const int64_t* metric_value = ukm::TestUkmRecorder::GetEntryMetric(
        entry, GetMetricName(LocalFrameUkmAggregator::kForcedStyleAndLayout));
    EXPECT_NEAR(*metric_value, 10000, 1);

    if (target_metric != LocalFrameUkmAggregator::kCount) {
      EXPECT_TRUE(ukm::TestUkmRecorder::EntryHasMetric(
          entry, GetMetricName(target_metric)));
      metric_value = ukm::TestUkmRecorder::GetEntryMetric(
          entry, GetMetricName(target_metric));
      EXPECT_NEAR(*metric_value, 10000, 1);
    }
    for (int i = LocalFrameUkmAggregator::kForcedStyleAndLayout + 1;
         i < LocalFrameUkmAggregator::kCount; ++i) {
      if (i != target_metric) {
        EXPECT_TRUE(
            ukm::TestUkmRecorder::EntryHasMetric(entry, GetMetricName(i)));
        metric_value =
            ukm::TestUkmRecorder::GetEntryMetric(entry, GetMetricName(i));
        EXPECT_EQ(*metric_value, 0);
      }
    }
    RestartAggregator();
  }

  bool SampleMatchesIteration(int64_t iteration_count) {
    return aggregator().current_sample_.sub_metrics_counts[0] / 1000 ==
           iteration_count;
  }

 private:
  // Deterministically record metrics in test.
  base::MetricsSubSampler::ScopedAlwaysSampleForTesting no_subsampling_;

  int64_t source_id_;
  scoped_refptr<LocalFrameUkmAggregator> aggregator_;
  ukm::TestUkmRecorder recorder_;
};

TEST_F(LocalFrameUkmAggregatorTest, EmptyEventsNotRecorded) {
  // Although the tests use a mock clock, the UKM aggregator checks if the
  // system has a high resolution clock before recording results. As a result,
  // the tests will fail if the system does not have a high resolution clock.
  if (!base::TimeTicks::IsHighResolution())
    return;

  // There is no BeginMainFrame, so no metrics get recorded.
  test_task_runner_->FastForwardBy(base::Seconds(10));
  ResetAggregator();

  EXPECT_EQ(recorder().sources_count(), 0u);
  EXPECT_EQ(recorder().entries_count(), 0u);
}

TEST_F(LocalFrameUkmAggregatorTest, FirstFrameIsRecorded) {
  // Verifies that we always get a sample when we report at least one frame.

  // Although the tests use a mock clock, the UKM aggregator checks if the
  // system has a high resolution clock before recording results. As a result,
  // the tests will fail if the system does not have a high resolution clock.
  if (!base::TimeTicks::IsHighResolution())
    return;

  // The initial interval is always zero, so we should see one set of metrics
  // for the initial frame, regardless of the initial interval.
  base::TimeTicks start_time = Now();
  unsigned millisecond_for_step = 1;
  SimulateFrame(start_time, millisecond_for_step, 12);

  // Metrics are not reported until destruction.
  EXPECT_EQ(recorder().entries_count(), 0u);

  // Reset the aggregator. Should record one pre-FCP metric.
  ResetAggregator();
  EXPECT_EQ(recorder().entries_count(), 1u);

  float expected_primary_metric =
      millisecond_for_step * LocalFrameUkmAggregator::kForcedStyleAndLayout;
  float expected_sub_metric = millisecond_for_step;
  float expected_begin_main_frame = millisecond_for_step;

  VerifyUpdateEntry(0u, expected_primary_metric, expected_sub_metric,
                    expected_begin_main_frame, 12, true);
}

TEST_F(LocalFrameUkmAggregatorTest, PreFrameWorkIsRecorded) {
  // Verifies that we correctly account for work done before the begin
  // main frame, and then within the begin main frame.

  // Although the tests use a mock clock, the UKM aggregator checks if the
  // system has a high resolution clock before recording results. As a result,
  // the tests will fail if the system does not have a high resolution clock.
  if (!base::TimeTicks::IsHighResolution())
    return;

  // The initial interval is always zero, so we should see one set of metrics
  // for the initial frame, regardless of the initial interval.
  unsigned millisecond_for_step = 1;
  base::TimeTicks start_time =
      Now() + base::Milliseconds(millisecond_for_step) *
                  LocalFrameUkmAggregator::kForcedStyleAndLayout;
  SimulatePreFrame(millisecond_for_step);
  SimulateFrame(start_time, millisecond_for_step, 12);

  // Metrics are not reported until destruction.
  EXPECT_EQ(recorder().entries_count(), 0u);

  // Reset the aggregator. Should record one pre-FCP metric.
  ResetAggregator();
  EXPECT_EQ(recorder().entries_count(), 1u);

  float expected_primary_metric =
      millisecond_for_step * LocalFrameUkmAggregator::kForcedStyleAndLayout;
  float expected_sub_metric = millisecond_for_step * 2;
  float expected_begin_main_frame = millisecond_for_step;

  VerifyUpdateEntry(0u, expected_primary_metric, expected_sub_metric,
                    expected_begin_main_frame, 12, true);
}

TEST_F(LocalFrameUkmAggregatorTest, PreAndPostFCPAreRecorded) {
  // Confirm that we get at least one frame pre-FCP and one post-FCP.

  // Although the tests use a mock clock, the UKM aggregator checks if the
  // system has a high resolution clock before recording results. As a result,
  // the tests will fail if the system does not have a high resolution clock.
  if (!base::TimeTicks::IsHighResolution())
    return;

  // The initial interval is always zero, so we should see one set of metrics
  // for the initial frame, regardless of the initial interval.
  base::TimeTicks start_time = Now();
  unsigned millisecond_per_step =
      50 / (LocalFrameUkmAggregator::kForcedStyleAndLayout + 1);
  SimulateFrame(start_time, millisecond_per_step, 4, true);

  // We marked FCP when we simulated, so we should report something. There
  // should be 2 entries because the aggregated pre-FCP metric also reported.
  EXPECT_EQ(recorder().entries_count(), 2u);

  float expected_primary_metric =
      millisecond_per_step * LocalFrameUkmAggregator::kForcedStyleAndLayout;
  float expected_sub_metric = millisecond_per_step;
  float expected_begin_main_frame = millisecond_per_step;

  VerifyUpdateEntry(0u, expected_primary_metric, expected_sub_metric,
                    expected_begin_main_frame, 4, true);

  // Take another step. Should reset the frame count and report the first post-
  // fcp frame. A failure here iundicates that we did not reset the frame,
  // or that we are incorrectly tracking pre/post fcp.
  unsigned millisecond_per_frame =
      millisecond_per_step * LocalFrameUkmAggregator::kForcedStyleAndLayout;

  start_time = Now();
  SimulateFrame(start_time, millisecond_per_step, 4);

  // Need to destruct to report
  ResetAggregator();

  // We should have a sample after the very first step, regardless of the
  // interval. The FirstFrameIsRecorded test above also tests this. There
  // should be 3 entries because the aggregated pre-fcp event has also
  // been recorded.
  EXPECT_EQ(recorder().entries_count(), 3u);

  VerifyUpdateEntry(1u, millisecond_per_frame, millisecond_per_step,
                    expected_begin_main_frame, 4, false);
}

TEST_F(LocalFrameUkmAggregatorTest, AggregatedPreFCPEventRecorded) {
  // Although the tests use a mock clock, the UKM aggregator checks if the
  // system has a high resolution clock before recording results. As a result,
  // the tests will fail if the system does not have a high resolution clock.
  if (!base::TimeTicks::IsHighResolution())
    return;

  SetIntersectionObserverSamplePeriodForTesting(1);

  // Be sure to not choose the next frame. We shouldn't need to record an
  // UpdateTime metric in order to record an aggregated metric.
  DoNotChooseNextFrameForTest();
  unsigned millisecond_per_step =
      50 / (LocalFrameUkmAggregator::kForcedStyleAndLayout + 1);
  unsigned millisecond_per_frame =
      millisecond_per_step * (LocalFrameUkmAggregator::kForcedStyleAndLayout);

  base::TimeTicks start_time = Now();
  SimulateFrame(start_time, millisecond_per_step, 3);

  // We should not have an aggregated metric yet because we have not reached
  // FCP. We shouldn't have any other kind of metric either.
  EXPECT_EQ(recorder().entries_count(), 0u);

  // Another step marking FCP this time.
  ChooseNextFrameForTest();
  start_time = Now();
  SimulateFrame(start_time, millisecond_per_step, 3, true);

  // Now we should have an aggregated metric, plus the pre-FCP update metric
  EXPECT_EQ(recorder().entries_count(), 2u);
  VerifyAggregatedEntries(1u, 2 * millisecond_per_frame,
                          2 * millisecond_per_step);
  ResetAggregator();
}

TEST_F(LocalFrameUkmAggregatorTest, ForcedLayoutReasonsReportOnlyMetric) {
  // Although the tests use a mock clock, the UKM aggregator checks if the
  // system has a high resolution clock before recording results. As a result,
  // the tests will fail if the system does not have a high resolution clock.
  if (!base::TimeTicks::IsHighResolution())
    return;

  // Test that every layout reason reports the expected UKM metric.
  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kContextMenu,
      LocalFrameUkmAggregator::kUserDrivenDocumentUpdate, 1u);
  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kEditing,
      LocalFrameUkmAggregator::kUserDrivenDocumentUpdate, 2u);
  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kEditing,
      LocalFrameUkmAggregator::kUserDrivenDocumentUpdate, 3u);
  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kFindInPage,
      LocalFrameUkmAggregator::kUserDrivenDocumentUpdate, 4u);
  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kFocus,
      LocalFrameUkmAggregator::kUserDrivenDocumentUpdate, 5u);
  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kForm,
      LocalFrameUkmAggregator::kUserDrivenDocumentUpdate, 6u);
  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kInput,
      LocalFrameUkmAggregator::kUserDrivenDocumentUpdate, 7u);
  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kInspector,
      LocalFrameUkmAggregator::kUserDrivenDocumentUpdate, 8u);
  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kPrinting,
      LocalFrameUkmAggregator::kUserDrivenDocumentUpdate, 9u);
  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kSelection,
      LocalFrameUkmAggregator::kUserDrivenDocumentUpdate, 10u);
  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kSpatialNavigation,
      LocalFrameUkmAggregator::kUserDrivenDocumentUpdate, 11u);
  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kTapHighlight,
      LocalFrameUkmAggregator::kUserDrivenDocumentUpdate, 12u);

  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kAccessibility,
      LocalFrameUkmAggregator::kServiceDocumentUpdate, 13u);
  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kBaseColor,
      LocalFrameUkmAggregator::kServiceDocumentUpdate, 14u);
  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kDisplayLock,
      LocalFrameUkmAggregator::kServiceDocumentUpdate, 15u);
  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kIntersectionObservation,
      LocalFrameUkmAggregator::kServiceDocumentUpdate, 16u);
  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kOverlay,
      LocalFrameUkmAggregator::kServiceDocumentUpdate, 17u);
  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kPagePopup,
      LocalFrameUkmAggregator::kServiceDocumentUpdate, 18u);
  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kSizeChange,
      LocalFrameUkmAggregator::kServiceDocumentUpdate, 19u);
  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kSpellCheck,
      LocalFrameUkmAggregator::kServiceDocumentUpdate, 20u);

  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kCanvas,
      LocalFrameUkmAggregator::kContentDocumentUpdate, 21u);
  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kPlugin,
      LocalFrameUkmAggregator::kContentDocumentUpdate, 22u);
  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kSVGImage,
      LocalFrameUkmAggregator::kContentDocumentUpdate, 23u);

  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kHitTest,
      LocalFrameUkmAggregator::kHitTestDocumentUpdate, 24u);

  SimulateAndVerifyForcedLayoutReason(
      DocumentUpdateReason::kJavaScript,
      LocalFrameUkmAggregator::kJavascriptDocumentUpdate, 25u);

  SimulateAndVerifyForcedLayoutReason(DocumentUpdateReason::kBeginMainFrame,
                                      LocalFrameUkmAggregator::kCount, 26u);
  SimulateAndVerifyForcedLayoutReason(DocumentUpdateReason::kTest,
                                      LocalFrameUkmAggregator::kCount, 27u);
  SimulateAndVerifyForcedLayoutReason(DocumentUpdateReason::kUnknown,
                                      LocalFrameUkmAggregator::kCount, 28u);
}

TEST_F(LocalFrameUkmAggregatorTest, LatencyDataIsPopulated) {
  // Although the tests use a mock clock, the UKM aggregator checks if the
  // system has a high resolution clock before recording results. As a result,
  // the tests will fail if the system does not have a high resolution clock.
  if (!base::TimeTicks::IsHighResolution())
    return;

  // We always record the first frame. Din't use the SimulateFrame method
  // because we need to populate before the end of the frame.
  unsigned millisecond_for_step = 1;
  aggregator().BeginMainFrame();
  for (int i = 0; i < LocalFrameUkmAggregator::kForcedStyleAndLayout; ++i) {
    auto timer = aggregator().GetScopedTimer(
        i % LocalFrameUkmAggregator::kForcedStyleAndLayout);
    test_task_runner_->FastForwardBy(base::Milliseconds(millisecond_for_step));
  }

  std::unique_ptr<cc::BeginMainFrameMetrics> metrics_data =
      aggregator().GetBeginMainFrameMetrics();
  EXPECT_EQ(metrics_data->handle_input_events.InMillisecondsF(),
            millisecond_for_step);
  EXPECT_EQ(metrics_data->animate.InMillisecondsF(), millisecond_for_step);
  EXPECT_EQ(metrics_data->style_update.InMillisecondsF(), millisecond_for_step);
  EXPECT_EQ(metrics_data->layout_update.InMillisecondsF(),
            millisecond_for_step);
  EXPECT_EQ(metrics_data->compositing_inputs.InMillisecondsF(),
            millisecond_for_step);
  EXPECT_EQ(metrics_data->prepaint.InMillisecondsF(), millisecond_for_step);
  EXPECT_EQ(metrics_data->paint.InMillisecondsF(), millisecond_for_step);
  EXPECT_EQ(metrics_data->composite_commit.InMillisecondsF(),
            millisecond_for_step);
  // Do not check the value in metrics_data.update_layers because it
  // is not set by the aggregator.
  ResetAggregator();
}

TEST_F(LocalFrameUkmAggregatorTest, SampleDoesChange) {
  // To write a test that the sample eventually changes we need to let it very
  // occasionally time out or fail. We'll go up to 100,000 tries for an update,
  // so this should not hit on average once every 100,000 test runs. One flake
  // in 100,000 seems acceptable.

  // Generate the first frame. We will look for a change from this frame.
  unsigned millisecond_for_step = 1;
  SimulateFrame(base::TimeTicks(), millisecond_for_step, 0);

  unsigned iteration_count = 2;
  bool new_sample = false;
  while (iteration_count < 100000u && !new_sample) {
    millisecond_for_step = iteration_count;
    SimulateFrame(base::TimeTicks(), millisecond_for_step, 0);
    new_sample = SampleMatchesIteration(static_cast<int64_t>(iteration_count));
    ++iteration_count;
  }
  EXPECT_LT(iteration_count, 100000u);
}

TEST_F(LocalFrameUkmAggregatorTest, IterativeTimer) {
  {
    LocalFrameUkmAggregator::IterativeTimer timer(aggregator());
    timer.StartInterval(LocalFrameUkmAggregator::kStyle);
    test_task_runner_->AdvanceMockTickClock(base::Microseconds(5));
    timer.StartInterval(LocalFrameUkmAggregator::kLayout);
    test_task_runner_->AdvanceMockTickClock(base::Microseconds(7));
    timer.StartInterval(LocalFrameUkmAggregator::kLayout);
    test_task_runner_->AdvanceMockTickClock(base::Microseconds(11));
    timer.StartInterval(LocalFrameUkmAggregator::kPrePaint);
    test_task_runner_->AdvanceMockTickClock(base::Microseconds(13));
  }
  EXPECT_EQ(GetIntervalCount(LocalFrameUkmAggregator::kStyle), 5);
  EXPECT_EQ(GetIntervalCount(LocalFrameUkmAggregator::kLayout), 18);
  EXPECT_EQ(GetIntervalCount(LocalFrameUkmAggregator::kPrePaint), 13);
}

TEST_F(LocalFrameUkmAggregatorTest, IntersectionObserverSamplePeriod) {
  if (!base::TimeTicks::IsHighResolution())
    return;
  SetIntersectionObserverSamplePeriodForTesting(2);
  cc::ActiveFrameSequenceTrackers trackers =
      1 << static_cast<unsigned>(
          cc::FrameSequenceTrackerType::kSETMainThreadAnimation);
  base::HistogramTester histogram_tester;

  // First main frame, everything gets recorded
  auto start_time = Now();
  aggregator().BeginMainFrame();
  {
    LocalFrameUkmAggregator::IterativeTimer timer(aggregator());
    timer.StartInterval(LocalFrameUkmAggregator::kLayout);
    test_task_runner_->FastForwardBy(base::Milliseconds(1));
    timer.StartInterval(
        LocalFrameUkmAggregator::kDisplayLockIntersectionObserver);
    test_task_runner_->FastForwardBy(base::Milliseconds(1));
  }
  aggregator().RecordEndOfFrameMetrics(start_time, Now(), trackers, source_id(),
                                       &recorder());
  histogram_tester.ExpectUniqueSample("Blink.Layout.UpdateTime.PreFCP", 1000,
                                      1);
  histogram_tester.ExpectUniqueSample(
      "Blink.DisplayLockIntersectionObserver.UpdateTime.PreFCP", 1000, 1);

  // Second main frame, IO metrics don't get recorded
  test_task_runner_->FastForwardBy(base::Milliseconds(1));
  start_time = Now();
  aggregator().BeginMainFrame();
  {
    LocalFrameUkmAggregator::IterativeTimer timer(aggregator());
    timer.StartInterval(LocalFrameUkmAggregator::kLayout);
    test_task_runner_->FastForwardBy(base::Milliseconds(1));
    timer.StartInterval(
        LocalFrameUkmAggregator::kDisplayLockIntersectionObserver);
    test_task_runner_->FastForwardBy(base::Milliseconds(1));
  }
  aggregator().RecordEndOfFrameMetrics(start_time, Now(), trackers, source_id(),
                                       &recorder());
  histogram_tester.ExpectUniqueSample("Blink.Layout.UpdateTime.PreFCP", 1000,
                                      2);
  histogram_tester.ExpectUniqueSample(
      "Blink.DisplayLockIntersectionObserver.UpdateTime.PreFCP", 1000, 1);

  // Third main frame, everything gets recorded
  test_task_runner_->FastForwardBy(base::Milliseconds(1));
  start_time = Now();
  aggregator().BeginMainFrame();
  {
    LocalFrameUkmAggregator::IterativeTimer timer(aggregator());
    timer.StartInterval(LocalFrameUkmAggregator::kLayout);
    test_task_runner_->FastForwardBy(base::Milliseconds(1));
    timer.StartInterval(
        LocalFrameUkmAggregator::kDisplayLockIntersectionObserver);
    test_task_runner_->FastForwardBy(base::Milliseconds(1));
  }
  aggregator().RecordEndOfFrameMetrics(start_time, Now(), trackers, source_id(),
                                       &recorder());
  histogram_tester.ExpectUniqueSample("Blink.Layout.UpdateTime.PreFCP", 1000,
                                      3);
  histogram_tester.ExpectUniqueSample(
      "Blink.DisplayLockIntersectionObserver.UpdateTime.PreFCP", 1000, 2);
}

class LocalFrameUkmAggregatorSimTest : public SimTest {
 protected:
  LocalFrameUkmAggregator& local_root_aggregator() {
    return *LocalFrameRoot().GetFrame()->View()->GetUkmAggregator();
  }

  void ChooseNextFrameForTest() {
    local_root_aggregator().ChooseNextFrameForTest();
  }

  bool IsBeforeFCPForTesting() {
    return local_root_aggregator().IsBeforeFCPForTesting();
  }

  void TestIntersectionObserverCounts(Document& document) {
    base::HistogramTester histogram_tester;

    Element* target1 = document.getElementById(AtomicString("target1"));
    Element* target2 = document.getElementById(AtomicString("target2"));

    // Create internal observer
    IntersectionObserverInit* observer_init =
        IntersectionObserverInit::Create();
    observer_init->setRoot(
        MakeGarbageCollected<V8UnionDocumentOrElement>(&document));
    TestIntersectionObserverDelegate* internal_delegate =
        MakeGarbageCollected<TestIntersectionObserverDelegate>(document);
    IntersectionObserver* internal_observer = IntersectionObserver::Create(
        observer_init, *internal_delegate,
        LocalFrameUkmAggregator::kLazyLoadIntersectionObserver);
    DCHECK(!Compositor().NeedsBeginFrame());
    internal_observer->observe(target1);
    internal_observer->observe(target2);
    Compositor().BeginFrame();
    EXPECT_EQ(
        histogram_tester.GetTotalSum(
            "Blink.IntersectionObservationInternalCount.UpdateTime.PreFCP"),
        2);
    EXPECT_EQ(
        histogram_tester.GetTotalSum(
            "Blink.IntersectionObservationJavascriptCount.UpdateTime.PreFCP"),
        0);

    TestIntersectionObserverDelegate* javascript_delegate =
        MakeGarbageCollected<TestIntersectionObserverDelegate>(document);
    IntersectionObserver* javascript_observer = IntersectionObserver::Create(
        observer_init, *javascript_delegate,
        LocalFrameUkmAggregator::kJavascriptIntersectionObserver);
    javascript_observer->observe(target1);
    javascript_observer->observe(target2);
    Compositor().BeginFrame();
    EXPECT_EQ(
        histogram_tester.GetTotalSum(
            "Blink.IntersectionObservationInternalCount.UpdateTime.PreFCP"),
        4);
    EXPECT_EQ(
        histogram_tester.GetTotalSum(
            "Blink.IntersectionObservationJavascriptCount.UpdateTime.PreFCP"),
        2);

    // Simulate the first contentful paint in the main frame.
    document.View()->GetUkmAggregator()->BeginMainFrame();
    PaintTiming::From(GetDocument()).MarkFirstContentfulPaint();
    Document* root_document = LocalFrameRoot().GetFrame()->GetDocument();
    document.View()->GetUkmAggregator()->RecordEndOfFrameMetrics(
        base::TimeTicks(), base::TimeTicks() + base::Microseconds(10), 0,
        root_document->UkmSourceID(), root_document->UkmRecorder());

    target1->setAttribute(html_names::kStyleAttr, AtomicString("height: 60px"));
    Compositor().BeginFrame();
    EXPECT_EQ(
        histogram_tester.GetTotalSum(
            "Blink.IntersectionObservationInternalCount.UpdateTime.PreFCP"),
        4);
    EXPECT_EQ(
        histogram_tester.GetTotalSum(
            "Blink.IntersectionObservationJavascriptCount.UpdateTime.PreFCP"),
        2);
    EXPECT_EQ(
        histogram_tester.GetTotalSum(
            "Blink.IntersectionObservationInternalCount.UpdateTime.PostFCP"),
        2);
    EXPECT_EQ(
        histogram_tester.GetTotalSum(
            "Blink.IntersectionObservationJavascriptCount.UpdateTime.PostFCP"),
        2);
  }

 pri
```