Response: Let's break down the thought process to analyze this C++ unittest file for `ContentToVisibleTimeReporter`.

1. **Identify the Core Purpose:** The filename `content_to_visible_time_reporter_unittest.cc` immediately suggests this file tests the functionality of a class named `ContentToVisibleTimeReporter`. The "unittest" suffix confirms it's a unit test.

2. **Examine Includes:**  The `#include` directives provide valuable clues about the class's dependencies and what it likely does:
    * `<string>`, `<utility>`, `<vector>`: Standard C++ for string manipulation, pairs/tuples, and dynamic arrays.
    * `"base/containers/contains.h"`, `"base/containers/extend.h"`:  Indicates usage of Chromium's base library for container utilities.
    * `"base/rand_util.h"`:  Potentially used for generating random data if needed, but not prominently used in this specific file.
    * `"base/strings/strcat.h"`, `"base/strings/stringprintf.h"`: String manipulation within Chromium's base library.
    * `"base/test/metrics/histogram_tester.h"`: This is a major indicator. It strongly suggests that the `ContentToVisibleTimeReporter` is involved in recording metrics, specifically histograms.
    * `"base/test/task_environment.h"`:  Used for controlling the execution environment in tests, especially important for time-sensitive operations.
    * `"components/viz/common/frame_timing_details.h"`: This points to interaction with the Viz component, which is responsible for rendering in Chrome. The `FrameTimingDetails` likely contains information about when frames are presented to the user.
    * `"testing/gtest/include/gtest/gtest.h"`:  Confirms the use of Google Test framework for writing the unit tests.
    * `"third_party/blink/public/common/page/content_to_visible_time_reporter.h"`:  This is the header file for the class being tested. It's crucial for understanding the class's public interface.

3. **Analyze Constants and Structures:**
    * `kBfcacheRestoreHistogram`: A string constant likely representing the name of a histogram related to Back/Forward Cache restores.
    * `kDuration`, `kOtherDuration`:  TimeDelta constants, clearly used for simulating time durations in the tests.
    * `TabStateParams`: A struct defining different states related to tabs (whether frames are saved, if the destination is loaded). The `histogram_suffix` suggests these states influence how metrics are reported.
    * `kTabStatesToTest`: An array of `TabStateParams`, indicating different scenarios being tested.

4. **Examine the Test Fixture (`ContentToVisibleTimeReporterTest`):**
    * Inheritance from `::testing::TestWithParam<TabStateParams>`: This signifies parameterized testing, where the same test logic is run with different `TabStateParams`.
    * `protected` members:
        * `task_environment_`:  As seen in the includes, used to control time.
        * `tab_switch_time_recorder_`: An instance of the class being tested. The name suggests it's involved in recording time related to tab switches.
        * `histogram_tester_`:  Used to assert the values recorded in histograms.
        * `tab_state_`: Holds the current `TabStateParams` for the parameterized test.
        * `duration_histograms_`, `incomplete_duration_histograms_`, `result_histograms_`: Vectors of strings likely holding the names of histograms being tested, dynamically generated based on `tab_state_`.
    * Helper methods:
        * `ExpectHistogramsEmptyExcept()`: Checks if certain histograms have no recorded samples.
        * `ExpectTotalSamples()`: Checks the total number of samples in specified histograms.
        * `ExpectTimeBucketCounts()`: Checks the number of samples within a specific time bucket of a histogram.
        * `ExpectResultBucketCounts()`: Checks the number of samples within a specific value bucket of a histogram (likely for enum-like results).

5. **Analyze Individual Test Cases (using `TEST_P`):**  The `TEST_P` macro indicates these are parameterized tests.
    * **`TimeIsRecorded`:**  Simulates a successful tab switch and verifies that the correct duration and result (success) are recorded in the expected histograms. The code within shows how the `ContentToVisibleTimeReporter`'s `TabWasShown` method is called and how the callback is executed with `FrameTimingDetails`.
    * **`HideBeforePresentFrame`:** Simulates a scenario where a tab is hidden before a frame is presented. It checks for the "incomplete" result and the time elapsed until the hide event. It also tests a subsequent successful tab switch.
    * **`MissingTabWasHidden`:**  Tests the case where `TabWasHidden` is not called. This checks for a "missed tab hide" result and records the time until the next `TabWasShown`.
    * **`BfcacheRestoreTimeIsRecorded`:** Specifically tests the recording of time for Back/Forward Cache restores.
    * **`TimeIsRecordedWithSavedFramesPlusBfcacheRestoreTimeIsRecorded`:**  Tests a combination of tab switching and bfcache restore, ensuring both sets of metrics are recorded.

6. **Infer Functionality:** Based on the test cases and the included headers, we can deduce the following about `ContentToVisibleTimeReporter`:
    * **Purpose:**  To record the time it takes for content to become visible to the user during various page transitions, specifically focusing on tab switching and back/forward cache restores.
    * **Key Methods:** `TabWasShown()` (likely called when a tab becomes visible or starts becoming visible) and `TabWasHidden()` (likely called when a tab becomes hidden).
    * **Metric Recording:**  It uses histograms to record these times and the success/failure status of the transitions.
    * **Tab State Awareness:** It considers different tab states (whether frames are saved, if the destination is loaded) when recording metrics.
    * **Reason Tracking:** It tracks the reason for showing the tab (tab switching, bfcache restore, etc.).

7. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * The "content to visible time" is directly related to the rendering of web pages. JavaScript, HTML, and CSS are all involved in creating the content that becomes visible.
    * **JavaScript:**  JavaScript can dynamically modify the DOM and trigger layout and paint operations. Long-running JavaScript tasks could delay the "content to visible" time.
    * **HTML:**  The structure of the HTML document and the resources it loads (images, scripts, stylesheets) directly impact how quickly content can be rendered.
    * **CSS:**  Complex CSS styles and layouts can also contribute to rendering delays.

8. **Consider Logic and Assumptions:**
    * **Assumption:** The tests assume that the `viz::FrameTimingDetails` accurately reflect when a frame is presented to the user.
    * **Logic:** The tests meticulously check that the correct histograms are updated with the expected values based on the simulated scenarios. The use of `task_environment_.FastForwardBy()` is key to controlling the timing.

9. **Identify Potential Usage Errors:**
    * **Forgetting to call `TabWasHidden()`:** The `MissingTabWasHidden` test highlights this. If `TabWasHidden` isn't called, the reporter might not accurately track the duration of a tab switch and could lead to incorrect "incomplete" reporting.
    * **Incorrectly setting the "show reason":**  The test cases demonstrate different "show reasons."  Incorrectly setting these flags could lead to metrics being recorded under the wrong histograms or with incorrect interpretations.
    * **Mismatched `TabWasShown` and callback execution:** The tests assume that the callback provided by `TabWasShown` is executed exactly once after a frame presentation. Errors in the calling code that lead to multiple or no callback executions would break the metric reporting.

This detailed breakdown, moving from the general purpose to specific code elements and then drawing connections and inferences, reflects a thorough approach to understanding the functionality of this unit test file.
这个文件是 Chromium Blink 引擎中的一个单元测试文件，专门用于测试 `blink::ContentToVisibleTimeReporter` 类的功能。`ContentToVisibleTimeReporter` 的主要职责是**记录页面内容变为可见的时间**，并将其上报为性能指标。这个测试文件通过模拟不同的场景来验证 `ContentToVisibleTimeReporter` 是否正确地记录了这些时间数据。

下面我们详细列举一下它的功能，并解释与 JavaScript, HTML, CSS 的关系，逻辑推理，以及可能的用户或编程错误：

**功能：**

1. **记录 Tab 切换的耗时：** 测试当用户切换标签页时，从导航开始到内容首次可见的时间。它会区分不同的标签页状态，例如是否有已保存的帧（用于快速返回）以及目标页面是否已加载。
2. **记录不完整的 Tab 切换耗时：** 测试当标签页被隐藏（例如切换到另一个标签页）在内容变得可见之前发生时，记录这段不完整的时间。
3. **处理 `TabWasHidden` 未调用的情况：** 测试当 `TabWasHidden` 方法没有被调用时，`ContentToVisibleTimeReporter` 如何处理并记录指标。
4. **记录 BFCache (Back/Forward Cache) 恢复的耗时：** 测试当页面从 BFCache 恢复时，从恢复开始到内容首次可见的时间。
5. **同时记录多种事件的耗时：** 测试在某些情况下，例如同时发生 Tab 切换和 BFCache 恢复时，是否能正确记录相关指标。

**与 JavaScript, HTML, CSS 的关系：**

`ContentToVisibleTimeReporter` 关注的是用户感知到的页面加载性能，这与 JavaScript, HTML, 和 CSS 息息相关：

* **HTML:** HTML 结构是页面内容的基础。`ContentToVisibleTimeReporter` 记录的是浏览器渲染 HTML 内容并使其对用户可见的时间。更复杂的 HTML 结构可能导致更长的渲染时间。
* **CSS:** CSS 负责页面的样式和布局。复杂的 CSS 规则和大量的样式计算会影响渲染性能，从而影响内容变为可见的时间。`ContentToVisibleTimeReporter` 会记录这些 CSS 处理带来的延迟。
* **JavaScript:** JavaScript 可以动态修改 DOM 结构和 CSS 样式，执行网络请求加载资源，等等。这些操作都可能延迟内容变为可见的时间。例如，一个阻塞渲染的 JavaScript 脚本会显著延迟 `ContentToVisibleTimeReporter` 记录的时间。

**举例说明：**

* **JavaScript:** 如果一个页面包含一个执行耗时操作的 JavaScript 脚本，并且该脚本阻止了页面的首次渲染，那么 `ContentToVisibleTimeReporter` 记录的 Tab 切换或 BFCache 恢复时间将会更长。
* **HTML:** 如果一个 HTML 页面包含大量的 `<img>` 标签，并且这些图片没有使用懒加载，浏览器会尝试立即加载所有图片。这会导致渲染阻塞，延长内容变为可见的时间，`ContentToVisibleTimeReporter` 会记录下这个延迟。
* **CSS:** 如果一个页面的 CSS 包含复杂的选择器和大量的样式规则，浏览器在计算样式时会花费更多时间。这会延迟首次渲染，从而被 `ContentToVisibleTimeReporter` 记录。

**逻辑推理 (假设输入与输出):**

假设我们进行一个简单的 Tab 切换测试：

**假设输入：**

1. **开始时间 (`start`)**: `T0`
2. **标签页状态 (`tab_state_`):** `has_saved_frames = true`, `destination_is_loaded = true` (对应 `WithSavedFrames` 后缀的 histogram)
3. **收到首帧展示反馈的时间 (`details.presentation_feedback.timestamp`)**: `T0 + kDuration`，其中 `kDuration` 为 42 毫秒。

**预期输出 (通过 histogram_tester_ 断言):**

* **`Browser.Tabs.TotalSwitchDuration3`**: 记录一个值为 42 毫秒的样本。
* **`Browser.Tabs.TotalSwitchDuration3.WithSavedFrames`**: 记录一个值为 42 毫秒的样本。
* **`Browser.Tabs.TabSwitchResult3`**: 记录一个值为 `ContentToVisibleTimeReporter::TabSwitchResult::kSuccess` 的样本。
* **`Browser.Tabs.TabSwitchResult3.WithSavedFrames`**: 记录一个值为 `ContentToVisibleTimeReporter::TabSwitchResult::kSuccess` 的样本。

**逻辑：** `ContentToVisibleTimeReporter::TabWasShown` 方法会记录开始时间，当收到首帧展示的反馈后，会计算时间差并记录到对应的 Histogram 中。由于 `destination_is_loaded` 为 true 且有 saved frames，所以会使用 `WithSavedFrames` 的后缀。

**用户或编程常见的使用错误举例：**

1. **忘记调用 `TabWasHidden()`:**  正如 `MissingTabWasHidden` 测试所验证的，如果在标签页切换过程中，前一个标签页的 `TabWasHidden()` 没有被调用，`ContentToVisibleTimeReporter` 会将这次切换标记为不完整 (`kMissedTabHide`)。这可能是因为在某些代码路径中，隐藏标签页的逻辑没有正确执行。
    * **例子：**  假设一个复杂的标签页管理系统中，在某些特定的异常情况下，切换标签页后，旧标签页的清理逻辑没有完全执行，导致 `TabWasHidden()` 遗漏。

2. **在没有实际展示内容前就报告了可见：**  `ContentToVisibleTimeReporter` 依赖于 `viz::FrameTimingDetails` 来确定内容何时可见。如果开发者错误地在内容尚未完全渲染完成时就发送了首帧展示的信号，那么记录的时间将不准确，可能会过早。
    * **例子：**  一个自定义的渲染流程中，开发者可能错误地在绘制了部分 UI 元素后就认为内容可见，而忽略了关键内容的加载和渲染。

3. **在不应该记录指标的时候记录了：**  `ContentToVisibleTimeReporter` 会根据传入的参数（例如 `show_reason_tab_switching`, `show_reason_bfcache_restore`）来判断是否应该记录指标。如果错误地设置了这些参数，可能会在不应该记录的情况下记录了数据，或者记录到了错误的 Histogram 中。
    * **例子：**  在某些内部的页面状态变化中，开发者可能错误地将 `show_reason_tab_switching` 设置为 true，即使这并不是一次用户发起的标签页切换。

4. **时间戳不一致导致计算错误：** `ContentToVisibleTimeReporter` 依赖于准确的时间戳。如果 `TabWasShown` 记录的开始时间与 `viz::FrameTimingDetails` 中的时间戳存在显著偏差，会导致计算出的时间差不准确。
    * **例子：**  系统时钟出现问题，或者在跨进程通信时，时间戳的传递和同步出现错误。

总而言之，`blink/common/page/content_to_visible_time_reporter_unittest.cc` 这个文件通过各种测试用例，确保 `ContentToVisibleTimeReporter` 能够准确地记录页面内容变为可见的时间，这对于监控和优化 Chromium 的性能至关重要。理解其功能和测试场景，有助于开发者在使用和维护相关代码时避免常见的错误。

Prompt: 
```
这是目录为blink/common/page/content_to_visible_time_reporter_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <utility>
#include <vector>

#include "base/containers/contains.h"
#include "base/containers/extend.h"
#include "base/rand_util.h"
#include "base/strings/strcat.h"
#include "base/strings/stringprintf.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/task_environment.h"
#include "components/viz/common/frame_timing_details.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/page/content_to_visible_time_reporter.h"

namespace blink {

constexpr char kBfcacheRestoreHistogram[] =
    "BackForwardCache.Restore.NavigationToFirstPaint";

constexpr base::TimeDelta kDuration = base::Milliseconds(42);
constexpr base::TimeDelta kOtherDuration = base::Milliseconds(4242);

// Combinations of tab states that log different histogram suffixes.
struct TabStateParams {
  bool has_saved_frames;
  bool destination_is_loaded;
  const char* histogram_suffix;
};

constexpr TabStateParams kTabStatesToTest[] = {
    // WithSavedFrames
    {
        .has_saved_frames = true,
        .destination_is_loaded = true,
        .histogram_suffix = "WithSavedFrames",
    },
    // NoSavedFrames_Loaded
    {
        .has_saved_frames = false,
        .destination_is_loaded = true,
        .histogram_suffix = "NoSavedFrames_Loaded",
    },
    // NoSavedFrames_NotLoaded
    {
        .has_saved_frames = false,
        .destination_is_loaded = false,
        .histogram_suffix = "NoSavedFrames_NotLoaded",
    },
};

class ContentToVisibleTimeReporterTest
    : public ::testing::TestWithParam<TabStateParams> {
 protected:
  ContentToVisibleTimeReporterTest() : tab_state_(GetParam()) {
    duration_histograms_.push_back("Browser.Tabs.TotalSwitchDuration3");
    duration_histograms_.push_back(base::StrCat(
        {"Browser.Tabs.TotalSwitchDuration3.", tab_state_.histogram_suffix}));

    incomplete_duration_histograms_.push_back(
        "Browser.Tabs.TotalIncompleteSwitchDuration3");
    incomplete_duration_histograms_.push_back(
        base::StrCat({"Browser.Tabs.TotalIncompleteSwitchDuration3.",
                      tab_state_.histogram_suffix}));

    result_histograms_.push_back("Browser.Tabs.TabSwitchResult3");
    result_histograms_.push_back(base::StrCat(
        {"Browser.Tabs.TabSwitchResult3.", tab_state_.histogram_suffix}));

    // Expect all histograms to be empty.
    ExpectHistogramsEmptyExcept({});
  }

  void ExpectHistogramsEmptyExcept(
      const std::vector<std::string>& histograms_with_values) {
    constexpr const char* kAllHistograms[] = {
        "Browser.Tabs.TotalSwitchDuration3",
        "Browser.Tabs.TotalSwitchDuration3.WithSavedFrames",
        "Browser.Tabs.TotalSwitchDuration3.NoSavedFrames_Loaded",
        "Browser.Tabs.TotalSwitchDuration3.NoSavedFrames_NotLoaded",
        "Browser.Tabs.TotalIncompleteSwitchDuration3",
        "Browser.Tabs.TotalIncompleteSwitchDuration3.WithSavedFrames",
        "Browser.Tabs.TotalIncompleteSwitchDuration3.NoSavedFrames_"
        "Loaded",
        "Browser.Tabs.TotalIncompleteSwitchDuration3.NoSavedFrames_"
        "NotLoaded",
        "Browser.Tabs.TabSwitchResult3",
        "Browser.Tabs.TabSwitchResult3.WithSavedFrames",
        "Browser.Tabs.TabSwitchResult3.NoSavedFrames_Loaded",
        "Browser.Tabs.TabSwitchResult3.NoSavedFrames_NotLoaded",
        // Non-tab switch.
        kBfcacheRestoreHistogram};
    std::vector<std::string> unexpected_histograms;
    for (const char* histogram : kAllHistograms) {
      if (!base::Contains(histograms_with_values, histogram))
        unexpected_histograms.push_back(histogram);
    }
    ExpectTotalSamples(unexpected_histograms, 0);
  }

  void ExpectTotalSamples(const std::vector<std::string>& histogram_names,
                          int expected_count) {
    for (const std::string& histogram_name : histogram_names) {
      SCOPED_TRACE(base::StringPrintf("Expect %d samples in %s.",
                                      expected_count, histogram_name.c_str()));
      EXPECT_EQ(static_cast<int>(
                    histogram_tester_.GetAllSamples(histogram_name).size()),
                expected_count);
    }
  }

  void ExpectTimeBucketCounts(const std::vector<std::string>& histogram_names,
                              base::TimeDelta value,
                              int count) {
    for (const std::string& histogram_name : histogram_names) {
      histogram_tester_.ExpectTimeBucketCount(histogram_name, value, count);
    }
  }

  void ExpectResultBucketCounts(
      const std::vector<std::string>& histogram_names,
      ContentToVisibleTimeReporter::TabSwitchResult value,
      int count) {
    for (const std::string& histogram_name : histogram_names) {
      histogram_tester_.ExpectBucketCount(histogram_name, value, count);
    }
  }

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  ContentToVisibleTimeReporter tab_switch_time_recorder_;
  base::HistogramTester histogram_tester_;
  TabStateParams tab_state_;

  // Expected histogram names to be logged for the given TabStateParams.
  std::vector<std::string> duration_histograms_;
  std::vector<std::string> incomplete_duration_histograms_;
  std::vector<std::string> result_histograms_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         ContentToVisibleTimeReporterTest,
                         ::testing::ValuesIn(kTabStatesToTest));

// Time is properly recorded to histogram if we have a proper matching
// TabWasShown and callback execution.
TEST_P(ContentToVisibleTimeReporterTest, TimeIsRecorded) {
  const auto start = base::TimeTicks::Now();
  auto callback = tab_switch_time_recorder_.TabWasShown(
      tab_state_.has_saved_frames,
      blink::mojom::RecordContentToVisibleTimeRequest::New(
          start, tab_state_.destination_is_loaded,
          /*show_reason_tab_switching=*/true,
          /*show_reason_bfcache_restore=*/false,
          /*show_reason_unfold=*/false));
  const auto end = start + kDuration;
  viz::FrameTimingDetails details;
  details.presentation_feedback.timestamp = end;
  std::move(callback).Run(details);

  std::vector<std::string> expected_histograms;
  base::Extend(expected_histograms, duration_histograms_);
  base::Extend(expected_histograms, result_histograms_);
  ExpectHistogramsEmptyExcept(expected_histograms);

  // Duration.
  ExpectTotalSamples(duration_histograms_, 1);
  ExpectTimeBucketCounts(duration_histograms_, kDuration, 1);

  // Result.
  ExpectTotalSamples(result_histograms_, 1);
  ExpectResultBucketCounts(
      result_histograms_,
      ContentToVisibleTimeReporter::TabSwitchResult::kSuccess, 1);
}

// An incomplete tab switch is reported when no frame is shown before a tab is
// hidden.
TEST_P(ContentToVisibleTimeReporterTest, HideBeforePresentFrame) {
  const auto start1 = base::TimeTicks::Now();
  auto callback1 = tab_switch_time_recorder_.TabWasShown(
      tab_state_.has_saved_frames,
      blink::mojom::RecordContentToVisibleTimeRequest::New(
          start1, tab_state_.destination_is_loaded,
          /*show_reason_tab_switching=*/true,
          /*show_reason_bfcache_restore=*/false,
          /*show_reason_unfold=*/false));

  task_environment_.FastForwardBy(kDuration);
  tab_switch_time_recorder_.TabWasHidden();

  std::vector<std::string> expected_histograms;
  base::Extend(expected_histograms, result_histograms_);
  base::Extend(expected_histograms, incomplete_duration_histograms_);
  ExpectHistogramsEmptyExcept(expected_histograms);

  // Duration.
  ExpectTotalSamples(incomplete_duration_histograms_, 1);
  ExpectTimeBucketCounts(incomplete_duration_histograms_, kDuration, 1);

  // Result.
  ExpectTotalSamples(result_histograms_, 1);
  ExpectResultBucketCounts(
      result_histograms_,
      ContentToVisibleTimeReporter::TabSwitchResult::kIncomplete, 1);

  const auto start2 = base::TimeTicks::Now();
  auto callback2 = tab_switch_time_recorder_.TabWasShown(
      tab_state_.has_saved_frames,
      blink::mojom::RecordContentToVisibleTimeRequest::New(
          start2, tab_state_.destination_is_loaded,
          /*show_reason_tab_switching=*/true,
          /*show_reason_bfcache_restore=*/false,
          /*show_reason_unfold=*/false));
  const auto end2 = start2 + kOtherDuration;
  viz::FrameTimingDetails details;
  details.presentation_feedback.timestamp = end2;
  std::move(callback2).Run(details);

  // Now the tab switch completes, and adds a duration histogram.
  base::Extend(expected_histograms, duration_histograms_);
  ExpectHistogramsEmptyExcept(expected_histograms);

  // Duration.
  ExpectTotalSamples(incomplete_duration_histograms_, 1);
  ExpectTimeBucketCounts(incomplete_duration_histograms_, kDuration, 1);
  ExpectTotalSamples(duration_histograms_, 1);
  ExpectTimeBucketCounts(duration_histograms_, kOtherDuration, 1);

  // Result.
  ExpectTotalSamples(result_histograms_, 2);
  ExpectResultBucketCounts(
      result_histograms_,
      ContentToVisibleTimeReporter::TabSwitchResult::kIncomplete, 1);
  ExpectResultBucketCounts(
      result_histograms_,
      ContentToVisibleTimeReporter::TabSwitchResult::kSuccess, 1);
}

// If TabWasHidden is not called an incomplete tab switch is reported.
// TODO(crbug.com/1289266): Find and remove all cases where TabWasHidden is not
// called.
TEST_P(ContentToVisibleTimeReporterTest, MissingTabWasHidden) {
  const auto start1 = base::TimeTicks::Now();
  auto callback1 = tab_switch_time_recorder_.TabWasShown(
      tab_state_.has_saved_frames,
      blink::mojom::RecordContentToVisibleTimeRequest::New(
          start1, tab_state_.destination_is_loaded,
          /*show_reason_tab_switching=*/true,
          /*show_reason_bfcache_restore=*/false,
          /*show_reason_unfold=*/false));

  task_environment_.FastForwardBy(kDuration);

  ExpectHistogramsEmptyExcept({});

  const auto start2 = base::TimeTicks::Now();
  auto callback2 = tab_switch_time_recorder_.TabWasShown(
      tab_state_.has_saved_frames,
      blink::mojom::RecordContentToVisibleTimeRequest::New(
          start2, tab_state_.destination_is_loaded,
          /*show_reason_tab_switching=*/true,
          /*show_reason_bfcache_restore=*/false,
          /*show_reason_unfold=*/false));
  const auto end2 = start2 + kOtherDuration;
  viz::FrameTimingDetails details;
  details.presentation_feedback.timestamp = end2;
  std::move(callback2).Run(details);

  // IncompleteDuration should be logged for the first TabWasShown, and Duration
  // for the second.
  std::vector<std::string> expected_histograms;
  base::Extend(expected_histograms, duration_histograms_);
  base::Extend(expected_histograms, result_histograms_);
  base::Extend(expected_histograms, incomplete_duration_histograms_);
  ExpectHistogramsEmptyExcept(expected_histograms);

  // Duration.
  ExpectTotalSamples({incomplete_duration_histograms_}, 1);
  ExpectTimeBucketCounts({incomplete_duration_histograms_}, kDuration, 1);
  ExpectTotalSamples({duration_histograms_}, 1);
  ExpectTimeBucketCounts({duration_histograms_}, kOtherDuration, 1);

  // Result.
  ExpectTotalSamples({result_histograms_}, 2);
  ExpectResultBucketCounts(
      {result_histograms_},
      ContentToVisibleTimeReporter::TabSwitchResult::kMissedTabHide, 1);
  ExpectResultBucketCounts(
      {result_histograms_},
      ContentToVisibleTimeReporter::TabSwitchResult::kSuccess, 1);
}

// Time is properly recorded to histogram when we have bfcache restore event.
TEST_P(ContentToVisibleTimeReporterTest, BfcacheRestoreTimeIsRecorded) {
  const auto start = base::TimeTicks::Now();
  auto callback = tab_switch_time_recorder_.TabWasShown(
      tab_state_.has_saved_frames,
      blink::mojom::RecordContentToVisibleTimeRequest::New(
          start, tab_state_.destination_is_loaded,
          /*show_reason_tab_switching=*/false,
          /*show_reason_bfcache_restore=*/true,
          /*show_reason_unfold=*/false));
  const auto end = start + kDuration;
  viz::FrameTimingDetails details;
  details.presentation_feedback.timestamp = end;
  std::move(callback).Run(details);

  ExpectHistogramsEmptyExcept({kBfcacheRestoreHistogram});

  // Bfcache restore.
  ExpectTotalSamples({kBfcacheRestoreHistogram}, 1);
  ExpectTimeBucketCounts({kBfcacheRestoreHistogram}, kDuration, 1);
}

// Time is properly recorded to histogram when we have unoccluded event
// and some other events too.
TEST_P(ContentToVisibleTimeReporterTest,
       TimeIsRecordedWithSavedFramesPlusBfcacheRestoreTimeIsRecorded) {
  const auto start = base::TimeTicks::Now();
  auto callback = tab_switch_time_recorder_.TabWasShown(
      tab_state_.has_saved_frames,
      blink::mojom::RecordContentToVisibleTimeRequest::New(
          start, tab_state_.destination_is_loaded,
          /*show_reason_tab_switching=*/true,
          /*show_reason_bfcache_restore=*/true,
          /*show_reason_unfold=*/false));
  const auto end = start + kDuration;
  viz::FrameTimingDetails details;
  details.presentation_feedback.timestamp = end;
  std::move(callback).Run(details);

  std::vector<std::string> expected_histograms{kBfcacheRestoreHistogram};
  base::Extend(expected_histograms, duration_histograms_);
  base::Extend(expected_histograms, result_histograms_);
  ExpectHistogramsEmptyExcept(expected_histograms);

  // Duration.
  ExpectTotalSamples(duration_histograms_, 1);
  ExpectTimeBucketCounts(duration_histograms_, kDuration, 1);

  // Result.
  ExpectTotalSamples(result_histograms_, 1);
  ExpectResultBucketCounts(
      result_histograms_,
      ContentToVisibleTimeReporter::TabSwitchResult::kSuccess, 1);

  // Bfcache restore.
  ExpectTotalSamples({kBfcacheRestoreHistogram}, 1);
  ExpectTimeBucketCounts({kBfcacheRestoreHistogram}, kDuration, 1);
}

}  // namespace blink

"""

```