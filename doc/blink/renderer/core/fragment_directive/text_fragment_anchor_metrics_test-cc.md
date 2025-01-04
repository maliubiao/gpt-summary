Response:
The user wants to understand the functionality of the `text_fragment_anchor_metrics_test.cc` file in the Chromium Blink engine.

Here's a breakdown of how to approach this:

1. **Identify the core purpose of the file:** The name itself suggests it's related to testing metrics for text fragment anchors. The `#include` statements confirm this by including headers related to testing, histograms, UKM (User Keyed Metrics), and text fragments.

2. **Analyze the test structure:** The file uses the `gtest` framework, indicated by `TEST_F` macros. Each `TEST_F` function likely focuses on testing a specific aspect of metric collection.

3. **Categorize the tested scenarios:**  Group the tests based on what they are verifying (e.g., UMA metrics, UKM events, use counters, different referrer types, success/failure cases, edge cases like invalid directives or force-load-at-top).

4. **Explain the relationship to web technologies:** Connect the tested features to JavaScript, HTML, and CSS where applicable. Text fragments themselves are triggered by URL fragments, which are directly related to how links are handled in HTML. The behavior being tested can influence how JavaScript interacts with the DOM. CSS is less directly involved, but the tests do use CSS to set up specific layout scenarios (e.g., scrolling).

5. **Provide examples and logical reasoning:** For each test category, explain the setup (input), the expected outcome (output), and the underlying logic. Use concrete examples of URLs and HTML content.

6. **Address potential user/programming errors:** Think about common mistakes developers or users might make that these tests implicitly cover (e.g., invalid URL formats, assuming text fragments always work, not understanding the impact of document policies).

7. **Structure the output clearly:** Organize the information into logical sections for easy understanding. Use bullet points and clear language.
这个文件 `text_fragment_anchor_metrics_test.cc` 是 Chromium Blink 引擎中用于测试 **文本片段锚点（Text Fragment Anchor）** 功能的 **指标（Metrics）** 收集的单元测试文件。 它的主要功能是验证在用户与包含文本片段的 URL 进行交互时，Blink 引擎是否正确地收集了各种性能和使用情况的指标。

以下是它更详细的功能说明，并结合 JavaScript、HTML 和 CSS 的关系进行解释：

**主要功能:**

1. **测试 UMA (User Metrics Analysis) 指标收集:**  该文件中的测试用例验证了在各种场景下，与文本片段锚点相关的 UMA 指标是否被正确记录。UMA 用于收集匿名的用户行为数据，以帮助 Chrome 团队了解功能的使用情况和性能。
    * **示例:** 测试用例 `UMAMetricsCollected` 模拟加载一个包含文本片段的 URL，并期望收集到诸如 "TextFragmentAnchor.Unknown.MatchRate" (匹配率), "TextFragmentAnchor.Unknown.AmbiguousMatch" (歧义匹配), "TextFragmentAnchor.Unknown.TimeToScrollIntoView" (滚动到视图的时间) 和 "TextFragmentAnchor.LinkOpenSource" (链接打开来源) 等 UMA 指标。

2. **测试 UKM (User Keyed Metrics) 事件记录:**  除了 UMA，该文件还测试了 UKM 事件的记录。UKM 允许记录与特定用户操作关联的更细粒度的指标。
    * **示例:**  `LinkOpenedSuccessUKM` 和 `LinkOpenedFailedUKM` 测试用例验证了当文本片段高亮成功或失败时，是否记录了 `SharedHighlights_LinkOpened` UKM 事件，并包含 "Success" 和 "Source" 等指标。

3. **测试不同来源的指标收集:**  测试用例会模拟从不同来源打开包含文本片段的链接，例如直接输入 URL、搜索引擎结果页等，并验证是否针对不同的来源记录了不同的 UMA 指标变体。
    * **示例:** `UMAMetricsCollectedSearchEngineReferrer` 模拟从搜索引擎打开链接，并期望收集到 "TextFragmentAnchor.SearchEngine.MatchRate" 等以 "SearchEngine" 为前缀的 UMA 指标。

4. **测试匹配成功和失败的指标收集:**  测试用例涵盖了文本片段在页面中成功找到匹配项和未能找到匹配项的情况，并验证了这两种情况下指标记录的差异。
    * **示例:** `NoMatchFoundWithUnknownSource` 和 `NoMatchFoundWithSearchEngineSource` 测试了在没有找到匹配的文本片段时，相应的匹配率和滚动时间等指标的记录情况。

5. **测试没有文本片段锚点的情况:**  文件中的测试用例也验证了在 URL 中没有指定文本片段时，是否不会收集相关的 UMA 指标。

6. **测试不同文本片段参数的指标收集:**  测试用例覆盖了精确文本匹配 (`text=`) 和范围文本匹配 (`text=start,end`) 以及各种上下文参数组合的情况，以确保所有可能的文本片段形式都能正确触发指标收集。

7. **测试无效文本片段指令的计数:**  `InvalidFragmentDirective` 测试用例检查了当 URL 中包含无效的文本片段指令时，是否正确地触发了 `WebFeature::kInvalidFragmentDirective` 的使用计数器。

8. **测试 `document.fragmentDirective` API 的使用计数:**  `TextFragmentAPIUseCounter` 测试用例验证了当 JavaScript 代码访问 `document.fragmentDirective` 属性时，是否触发了相应的特性使用计数器。这与 **JavaScript** 相关，因为 JavaScript 可以通过这个 API 获取和操作文本片段信息。

9. **测试 `ForceLoadAtTop` Document Policy 的影响:**  `ForceLoadAtTopUseCounter` 和 `TextFragmentBlockedByForceLoadAtTopUseCounter` 测试用例验证了当页面使用了 `force-load-at-top` 文档策略时，是否会阻止文本片段的滚动行为，并记录相应的特性使用计数器。这与 **HTML** 中的 `<meta>` 标签或者 HTTP 头部中的 `Document-Policy` 相关。

10. **测试 Shadow DOM 中的文本片段:** `ShadowDOMUseCounter` 测试用例验证了当文本片段的目标位于 Shadow DOM 中时，是否会记录 `WebFeature::kTextDirectiveInShadowDOM` 特性使用计数器。这与 **HTML** 和 **JavaScript** 创建和操作 Shadow DOM 的能力有关。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **HTML:**
    * **文本片段锚点本身就基于 URL 的片段标识符 (`#:~:text=`)，这是 HTML 链接机制的一部分。** 例如，`https://example.com/page.html#:~:text=some%20text`  就是一个包含文本片段的 URL。该测试文件模拟加载这样的 HTML 页面，并验证引擎对文本片段的处理和指标收集。
    * **`ForceLoadAtTop` Document Policy 是通过 HTML 的 `<meta>` 标签或 HTTP 头部指定的。**  测试用例会模拟加载包含该策略的 HTML 页面，并验证其对文本片段行为的影响。
    * **Shadow DOM 是 HTML 的一个特性，允许封装 DOM 结构。** 测试用例验证了在 Shadow DOM 中定位文本片段时的指标收集。

* **JavaScript:**
    * **`document.fragmentDirective` API 是一个 JavaScript API，允许开发者访问和操作当前页面的文本片段信息。** `TextFragmentAPIUseCounter` 测试用例验证了对该 API 的访问是否被正确计数。
    * **JavaScript 可以操作 DOM，并可能影响文本片段的查找和高亮。** 虽然这个测试文件主要关注指标收集，但它所测试的功能最终会影响 JavaScript 与 DOM 的交互。

* **CSS:**
    * **CSS 可以影响页面的布局和滚动行为。**  虽然该文件没有直接测试 CSS 的功能，但测试用例中使用了 CSS 来设置特定的页面布局（例如设置 `body` 的高度，使页面可以滚动），以便测试滚动到视图的指标。

**逻辑推理的假设输入与输出:**

**假设输入 (以 `UMAMetricsCollected` 测试用例为例):**

* **URL:** `https://example.com/test.html#:~:text=test&text=cat`
* **HTML 内容:**
  ```html
  <!DOCTYPE html>
  <style>
    body {
      height: 1200px;
    }
    p {
      position: absolute;
      top: 1000px;
    }
  </style>
  <p>This is a test page</p>
  <p>With ambiguous test content</p>
  ```

**预期输出:**

* `histogram_tester_.ExpectTotalCount("TextFragmentAnchor.Unknown.MatchRate", 1);`  // 匹配率指标被记录一次
* `histogram_tester_.ExpectUniqueSample("TextFragmentAnchor.Unknown.MatchRate", 50, 1);` // 匹配率为 50% (两个 "test" 中匹配到一个)
* `histogram_tester_.ExpectTotalCount("TextFragmentAnchor.Unknown.AmbiguousMatch", 1);` // 歧义匹配指标被记录一次
* `histogram_tester_.ExpectUniqueSample("TextFragmentAnchor.Unknown.AmbiguousMatch", 1, 1);` // 存在歧义匹配 (多个 "test")
* `histogram_tester_.ExpectTotalCount("TextFragmentAnchor.Unknown.TimeToScrollIntoView", 1);` // 滚动到视图的时间指标被记录一次
* `histogram_tester_.ExpectTotalCount("TextFragmentAnchor.LinkOpenSource", 1);` // 链接打开来源指标被记录一次
* `histogram_tester_.ExpectUniqueSample("TextFragmentAnchor.LinkOpenSource", 0, 1);` // 链接打开来源为未知 (0)

**涉及用户或编程常见的使用错误举例说明:**

1. **用户错误:**
    * **拼写错误或不准确的文本片段:** 用户在复制或输入包含文本片段的 URL 时，可能会出现拼写错误，导致文本片段无法匹配到页面内容。虽然这个测试文件不直接模拟用户输入错误，但其测试的指标收集功能会记录这种未匹配的情况。
    * **假设文本片段总是高亮:** 用户可能假设只要 URL 中包含文本片段，页面就会自动滚动并高亮匹配的文本。然而，某些因素（例如 `ForceLoadAtTop` 策略）可能会阻止这种行为。

2. **编程错误:**
    * **不正确的 `document.fragmentDirective` 使用:**  开发者可能错误地使用 `document.fragmentDirective` API，例如尝试设置或修改文本片段，而该 API 主要用于读取。测试用例 `TextFragmentAPIUseCounter` 验证了对该 API 的访问，间接地也覆盖了潜在的错误使用情况。
    * **在 Shadow DOM 中查找文本片段时未考虑 Shadow Root:** 开发者在 JavaScript 中查找文本片段时，如果目标位于 Shadow DOM 中，需要从 Shadow Root 开始查找，而不是直接从 `document` 开始。 `ShadowDOMUseCounter` 测试用例的存在表明了对这种场景的考虑。
    * **误解 `ForceLoadAtTop` 的影响:** 开发者可能没有意识到 `ForceLoadAtTop` 文档策略会阻止文本片段的自动滚动，从而导致用户体验不佳。 `TextFragmentBlockedByForceLoadAtTopUseCounter` 测试用例的存在提醒了这种策略的影响。

总而言之，`text_fragment_anchor_metrics_test.cc` 是一个关键的测试文件，用于确保 Chromium Blink 引擎能够准确地监控和分析文本片段锚点的使用情况和性能，这对于理解用户行为、优化功能以及排查潜在问题至关重要。

Prompt: 
```
这是目录为blink/renderer/core/fragment_directive/text_fragment_anchor_metrics_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fragment_directive/text_fragment_anchor_metrics.h"

#include "base/test/metrics/histogram_tester.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/test/task_environment.h"
#include "components/ukm/test_ukm_recorder.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/scroll/scroll_enums.mojom-blink.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/renderer/core/fragment_directive/text_fragment_anchor.h"
#include "third_party/blink/renderer/core/fragment_directive/text_fragment_test_util.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/scoped_fake_ukm_recorder.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

using test::RunPendingTasks;

const char kSuccessUkmMetric[] = "Success";
const char kSourceUkmMetric[] = "Source";

class TextFragmentAnchorMetricsTest : public TextFragmentAnchorTestBase {
 public:
  TextFragmentAnchorMetricsTest()
      : TextFragmentAnchorTestBase(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}
  void SimulateClick(int x, int y) {
    WebMouseEvent event(WebInputEvent::Type::kMouseDown, gfx::PointF(x, y),
                        gfx::PointF(x, y), WebPointerProperties::Button::kLeft,
                        0, WebInputEvent::Modifiers::kLeftButtonDown,
                        base::TimeTicks::Now());
    event.SetFrameScale(1);
    GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(event);
  }

 protected:
  ukm::TestUkmRecorder* ukm_recorder() {
    return scoped_fake_ukm_recorder_.recorder();
  }

  base::HistogramTester histogram_tester_;
  ScopedFakeUkmRecorder scoped_fake_ukm_recorder_;
};

// Test UMA metrics collection
TEST_F(TextFragmentAnchorMetricsTest, UMAMetricsCollected) {
  SimRequest request("https://example.com/test.html#:~:text=test&text=cat",
                     "text/html");
  LoadURL("https://example.com/test.html#:~:text=test&text=cat");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      p {
        position: absolute;
        top: 1000px;
      }
    </style>
    <p>This is a test page</p>
    <p>With ambiguous test content</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  histogram_tester_.ExpectTotalCount("TextFragmentAnchor.Unknown.MatchRate", 1);
  histogram_tester_.ExpectUniqueSample("TextFragmentAnchor.Unknown.MatchRate",
                                       50, 1);

  histogram_tester_.ExpectTotalCount(
      "TextFragmentAnchor.Unknown.AmbiguousMatch", 1);
  histogram_tester_.ExpectUniqueSample(
      "TextFragmentAnchor.Unknown.AmbiguousMatch", 1, 1);

  histogram_tester_.ExpectTotalCount(
      "TextFragmentAnchor.Unknown.TimeToScrollIntoView", 1);

  histogram_tester_.ExpectTotalCount("TextFragmentAnchor.LinkOpenSource", 1);
  histogram_tester_.ExpectUniqueSample("TextFragmentAnchor.LinkOpenSource", 0,
                                       1);
}

// Test UMA metrics collection with search engine referrer.
TEST_F(TextFragmentAnchorMetricsTest, UMAMetricsCollectedSearchEngineReferrer) {
  // Set the referrer to a known search engine URL. This should cause metrics
  // to be reported for the SearchEngine variant of histograms.
  SimRequest::Params params;
  params.requestor_origin = WebSecurityOrigin::CreateFromString(
      WebString::FromUTF8("https://www.bing.com"));
  SimRequest request("https://example.com/test.html#:~:text=test&text=cat",
                     "text/html", params);
  LoadURL("https://example.com/test.html#:~:text=test&text=cat");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      p {
        position: absolute;
        top: 1000px;
      }
    </style>
    <p>This is a test page</p>
    <p>With ambiguous test content</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  histogram_tester_.ExpectTotalCount(
      "TextFragmentAnchor.SearchEngine.MatchRate", 1);
  histogram_tester_.ExpectUniqueSample(
      "TextFragmentAnchor.SearchEngine.MatchRate", 50, 1);

  histogram_tester_.ExpectTotalCount(
      "TextFragmentAnchor.SearchEngine.AmbiguousMatch", 1);
  histogram_tester_.ExpectUniqueSample(
      "TextFragmentAnchor.SearchEngine.AmbiguousMatch", 1, 1);

  histogram_tester_.ExpectTotalCount(
      "TextFragmentAnchor.SearchEngine.TimeToScrollIntoView", 1);

  histogram_tester_.ExpectTotalCount("TextFragmentAnchor.LinkOpenSource", 1);
  histogram_tester_.ExpectUniqueSample("TextFragmentAnchor.LinkOpenSource", 1,
                                       1);
}

// Test UMA metrics collection when there is no match found with an unknown
// referrer.
TEST_F(TextFragmentAnchorMetricsTest, NoMatchFoundWithUnknownSource) {
  SimRequest request("https://example.com/test.html#:~:text=cat", "text/html");
  LoadURL("https://example.com/test.html#:~:text=cat");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      p {
        position: absolute;
        top: 1000px;
      }
    </style>
    <p>This is a test page</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  histogram_tester_.ExpectTotalCount("TextFragmentAnchor.Unknown.MatchRate", 1);
  histogram_tester_.ExpectUniqueSample("TextFragmentAnchor.Unknown.MatchRate",
                                       0, 1);

  histogram_tester_.ExpectTotalCount(
      "TextFragmentAnchor.Unknown.AmbiguousMatch", 1);
  histogram_tester_.ExpectUniqueSample(
      "TextFragmentAnchor.Unknown.AmbiguousMatch", 0, 1);

  histogram_tester_.ExpectTotalCount(
      "TextFragmentAnchor.Unknown.TimeToScrollIntoView", 0);

  histogram_tester_.ExpectTotalCount("TextFragmentAnchor.LinkOpenSource", 1);
  histogram_tester_.ExpectUniqueSample("TextFragmentAnchor.LinkOpenSource", 0,
                                       1);
}

// Test UMA metrics collection when there is no match found with a Search Engine
// referrer.
TEST_F(TextFragmentAnchorMetricsTest, NoMatchFoundWithSearchEngineSource) {
  // Set the referrer to a known search engine URL. This should cause metrics
  // to be reported for the SearchEngine variant of histograms.
  SimRequest::Params params;
  params.requestor_origin = WebSecurityOrigin::CreateFromString(
      WebString::FromUTF8("https://www.bing.com"));
  SimRequest request("https://example.com/test.html#:~:text=cat", "text/html",
                     params);
  LoadURL("https://example.com/test.html#:~:text=cat");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      p {
        position: absolute;
        top: 1000px;
      }
    </style>
    <p>This is a test page</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  histogram_tester_.ExpectTotalCount(
      "TextFragmentAnchor.SearchEngine.MatchRate", 1);
  histogram_tester_.ExpectUniqueSample(
      "TextFragmentAnchor.SearchEngine.MatchRate", 0, 1);

  histogram_tester_.ExpectTotalCount(
      "TextFragmentAnchor.SearchEngine.AmbiguousMatch", 1);
  histogram_tester_.ExpectUniqueSample(
      "TextFragmentAnchor.SearchEngine.AmbiguousMatch", 0, 1);

  histogram_tester_.ExpectTotalCount(
      "TextFragmentAnchor.SearchEngine.TimeToScrollIntoView", 0);

  histogram_tester_.ExpectTotalCount("TextFragmentAnchor.LinkOpenSource", 1);
  histogram_tester_.ExpectUniqueSample("TextFragmentAnchor.LinkOpenSource", 1,
                                       1);
}

// Test that we don't collect any metrics when there is no text directive
TEST_F(TextFragmentAnchorMetricsTest, NoTextFragmentAnchor) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p>This is a test page</p>
  )HTML");
  Compositor().BeginFrame();

  histogram_tester_.ExpectTotalCount("TextFragmentAnchor.Unknown.MatchRate", 0);

  histogram_tester_.ExpectTotalCount(
      "TextFragmentAnchor.Unknown.AmbiguousMatch", 0);

  histogram_tester_.ExpectTotalCount(
      "TextFragmentAnchor.Unknown.TimeToScrollIntoView", 0);

  histogram_tester_.ExpectTotalCount("TextFragmentAnchor.LinkOpenSource", 0);
}

// Test that the correct metrics are collected when we found a match but didn't
// need to scroll.
TEST_F(TextFragmentAnchorMetricsTest, MatchFoundNoScroll) {
  SimRequest request("https://example.com/test.html#:~:text=test", "text/html");
  LoadURL("https://example.com/test.html#:~:text=test");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p>This is a test page</p>
  )HTML");
  Compositor().BeginFrame();

  // The anchor should have been found and finalized.
  EXPECT_FALSE(GetDocument().GetFrame()->View()->GetFragmentAnchor());

  histogram_tester_.ExpectTotalCount("TextFragmentAnchor.Unknown.MatchRate", 1);
  histogram_tester_.ExpectUniqueSample("TextFragmentAnchor.Unknown.MatchRate",
                                       100, 1);

  histogram_tester_.ExpectTotalCount(
      "TextFragmentAnchor.Unknown.AmbiguousMatch", 1);
  histogram_tester_.ExpectUniqueSample(
      "TextFragmentAnchor.Unknown.AmbiguousMatch", 0, 1);

  histogram_tester_.ExpectTotalCount(
      "TextFragmentAnchor.Unknown.TimeToScrollIntoView", 1);

  histogram_tester_.ExpectTotalCount("TextFragmentAnchor.LinkOpenSource", 1);
  histogram_tester_.ExpectUniqueSample("TextFragmentAnchor.LinkOpenSource", 0,
                                       1);
}

// Test that the correct metrics are collected for all possible combinations of
// context terms on an exact text directive.
TEST_F(TextFragmentAnchorMetricsTest, ExactTextParameters) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=this&text=is-,a&text=test,-page&text=with-,some,-"
      "content",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=this&text=is-,a&text=test,-page&text=with-,some,-"
      "content");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p>This is a test page</p>
    <p>With some content</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  histogram_tester_.ExpectTotalCount("TextFragmentAnchor.Unknown.MatchRate", 1);
  histogram_tester_.ExpectUniqueSample("TextFragmentAnchor.Unknown.MatchRate",
                                       100, 1);

  histogram_tester_.ExpectTotalCount(
      "TextFragmentAnchor.Unknown.AmbiguousMatch", 1);
  histogram_tester_.ExpectUniqueSample(
      "TextFragmentAnchor.Unknown.AmbiguousMatch", 0, 1);

  histogram_tester_.ExpectTotalCount(
      "TextFragmentAnchor.Unknown.TimeToScrollIntoView", 1);

  histogram_tester_.ExpectTotalCount("TextFragmentAnchor.LinkOpenSource", 1);
  histogram_tester_.ExpectUniqueSample("TextFragmentAnchor.LinkOpenSource", 0,
                                       1);
}

// Test that the correct metrics are collected for all possible combinations of
// context terms on a range text directive.
TEST_F(TextFragmentAnchorMetricsTest, TextRangeParameters) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=this,is&text=a-,test,page&text=with,some,-content&"
      "text=about-,nothing,at,-all",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=this,is&text=a-,test,page&text=with,some,-content&"
      "text=about-,nothing,at,-all");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p>This is a test page</p>
    <p>With some content</p>
    <p>About nothing at all</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  histogram_tester_.ExpectTotalCount("TextFragmentAnchor.Unknown.MatchRate", 1);
  histogram_tester_.ExpectUniqueSample("TextFragmentAnchor.Unknown.MatchRate",
                                       100, 1);

  histogram_tester_.ExpectTotalCount(
      "TextFragmentAnchor.Unknown.AmbiguousMatch", 1);
  histogram_tester_.ExpectUniqueSample(
      "TextFragmentAnchor.Unknown.AmbiguousMatch", 0, 1);

  histogram_tester_.ExpectTotalCount(
      "TextFragmentAnchor.Unknown.TimeToScrollIntoView", 1);

  histogram_tester_.ExpectTotalCount("TextFragmentAnchor.LinkOpenSource", 1);
  histogram_tester_.ExpectUniqueSample("TextFragmentAnchor.LinkOpenSource", 0,
                                       1);
}

// Test counting cases where the fragment directive fails to parse.
TEST_F(TextFragmentAnchorMetricsTest, InvalidFragmentDirective) {
  const int kUncounted = 0;
  const int kCounted = 1;

  Vector<std::pair<String, int>> test_cases = {
      {"", kUncounted},
      {"#element", kUncounted},
      {"#doesntExist", kUncounted},
      {"#:~:element", kCounted},
      {"#element:~:", kCounted},
      {"#foo:~:bar", kCounted},
      {"#:~:utext=foo", kCounted},
      {"#:~:text=foo", kUncounted},
      {"#:~:text=foo&invalid", kUncounted},
      {"#foo:~:text=foo", kUncounted}};

  for (auto test_case : test_cases) {
    String url = "https://example.com/test.html" + test_case.first;
    SimRequest request(url, "text/html");
    LoadURL(url);
    request.Complete(R"HTML(
      <!DOCTYPE html>
      <p id="element">This is a test page</p>
    )HTML");
    if (GetDocument().GetFrame()->View()->GetFragmentAnchor()) {
      RunUntilTextFragmentFinalization();
    }

    bool is_use_counted =
        GetDocument().IsUseCounted(WebFeature::kInvalidFragmentDirective);
    if (test_case.second == kCounted) {
      EXPECT_TRUE(is_use_counted)
          << "Expected invalid directive in case: " << test_case.first;
    } else {
      EXPECT_FALSE(is_use_counted)
          << "Expected valid directive in case: " << test_case.first;
    }
  }
}

class TextFragmentRelatedMetricTest : public TextFragmentAnchorMetricsTest,
                                      public testing::WithParamInterface<bool> {
 public:
  TextFragmentRelatedMetricTest() : text_fragment_anchors_state_(GetParam()) {}

 private:
  ScopedTextFragmentIdentifiersForTest text_fragment_anchors_state_;
};

// These tests will run with and without the TextFragmentIdentifiers feature
// enabled to ensure we collect metrics correctly under both situations.
INSTANTIATE_TEST_SUITE_P(All,
                         TextFragmentRelatedMetricTest,
                         testing::Values(false, true));

// Test use counting the document.fragmentDirective API
TEST_P(TextFragmentRelatedMetricTest, TextFragmentAPIUseCounter) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <script>
      var textFragmentsSupported = typeof(document.fragmentDirective) == "object";
    </script>
    <p>This is a test page</p>
  )HTML");
  RunPendingTasks();
  Compositor().BeginFrame();

  bool text_fragments_enabled = GetParam();

  EXPECT_EQ(text_fragments_enabled,
            GetDocument().IsUseCounted(
                WebFeature::kV8Document_FragmentDirective_AttributeGetter));
}

// Test that simply activating a text fragment does not use count the API
TEST_P(TextFragmentRelatedMetricTest, TextFragmentActivationDoesNotCountAPI) {
  SimRequest request("https://example.com/test.html#:~:text=test", "text/html");
  LoadURL("https://example.com/test.html#:~:text=test");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p>This is a test page</p>
  )HTML");
  bool text_fragments_enabled = GetParam();
  if (text_fragments_enabled) {
    RunUntilTextFragmentFinalization();
  }

  EXPECT_EQ(text_fragments_enabled,
            GetDocument().IsUseCounted(WebFeature::kTextFragmentAnchor));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kV8Document_FragmentDirective_AttributeGetter));
}

// Tests that a LinkOpened UKM Event is recorded upon a successful fragment
// highlight.
TEST_F(TextFragmentAnchorMetricsTest, LinkOpenedSuccessUKM) {
  SimRequest request("https://example.com/test.html#:~:text=test%20page",
                     "text/html");
  LoadURL("https://example.com/test.html#:~:text=test%20page");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 2200px;
      }
      p {
        position: absolute;
        top: 1000px;
      }
    </style>
    <p>This is a test page</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  // Flush UKM logging mojo request.
  RunPendingTasks();

  auto entries = ukm_recorder()->GetEntriesByName(
      ukm::builders::SharedHighlights_LinkOpened::kEntryName);
  ASSERT_EQ(1u, entries.size());
  const ukm::mojom::UkmEntry* entry = entries[0];
  EXPECT_EQ(GetDocument().UkmSourceID(), entry->source_id);
  ukm_recorder()->ExpectEntryMetric(entry, kSuccessUkmMetric,
                                    /*expected_value=*/true);
  EXPECT_TRUE(ukm_recorder()->GetEntryMetric(entry, kSourceUkmMetric));
}

// Tests that a LinkOpened UKM Event is recorded upon a failed fragment
// highlight.
TEST_F(TextFragmentAnchorMetricsTest, LinkOpenedFailedUKM) {
  SimRequest request(
      "https://example.com/test.html#:~:text=not%20on%20the%20page",
      "text/html");
  LoadURL("https://example.com/test.html#:~:text=not%20on%20the%20page");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 2200px;
      }
      p {
        position: absolute;
        top: 1000px;
      }
    </style>
    <p>This is a test page</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  // Flush UKM logging mojo request.
  RunPendingTasks();

  auto entries = ukm_recorder()->GetEntriesByName(
      ukm::builders::SharedHighlights_LinkOpened::kEntryName);
  ASSERT_EQ(1u, entries.size());
  const ukm::mojom::UkmEntry* entry = entries[0];
  EXPECT_EQ(GetDocument().UkmSourceID(), entry->source_id);
  ukm_recorder()->ExpectEntryMetric(entry, kSuccessUkmMetric,
                                    /*expected_value=*/false);
  EXPECT_TRUE(ukm_recorder()->GetEntryMetric(entry, kSourceUkmMetric));
}

// Tests that loading a page that has a ForceLoadAtTop DocumentPolicy invokes
// the UseCounter.
TEST_F(TextFragmentAnchorMetricsTest, ForceLoadAtTopUseCounter) {
  SimRequest::Params params;
  params.response_http_headers.insert("Document-Policy", "force-load-at-top");
  SimRequest request("https://example.com/test.html", "text/html", params);
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p>This is a test page</p>
  )HTML");
  RunPendingTasks();
  Compositor().BeginFrame();

  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kForceLoadAtTop));
}

// Tests that loading a page that explicitly disables ForceLoadAtTop
// DocumentPolicy or has no DocumentPolicy doesn't invoke the UseCounter for
// ForceLoadAtTop.
TEST_F(TextFragmentAnchorMetricsTest, NoForceLoadAtTopUseCounter) {
  SimRequest::Params params;
  params.response_http_headers.insert("Document-Policy",
                                      "no-force-load-at-top");
  SimRequest request("https://example.com/test.html", "text/html", params);
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p>This is a test page</p>
  )HTML");
  RunPendingTasks();
  Compositor().BeginFrame();

  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kForceLoadAtTop));

  // Try without any DocumentPolicy headers.
  SimRequest request2("https://example.com/test2.html", "text/html");
  LoadURL("https://example.com/test2.html");
  request2.Complete(R"HTML(
    <!DOCTYPE html>
    <p>This is a different test page</p>
  )HTML");
  RunPendingTasks();
  Compositor().BeginFrame();

  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kForceLoadAtTop));
}

// Tests that we correctly record the "TextFragmentBlockedByForceLoadAtTop" use
// counter, that is, only when a text fragment appears and would otherwise have
// been invoked but was blocked by DocumentPolicy.
TEST_F(TextFragmentAnchorMetricsTest,
       TextFragmentBlockedByForceLoadAtTopUseCounter) {
  // ForceLoadAtTop is effective but TextFragmentBlocked isn't recorded because
  // there is no text fragment.
  {
    SimRequest::Params params;
    params.response_http_headers.insert("Document-Policy", "force-load-at-top");
    SimRequest request("https://example.com/test.html", "text/html", params);
    LoadURL("https://example.com/test.html");
    request.Complete(R"HTML(
      <!DOCTYPE html>
      <p>This is a test page</p>
    )HTML");
    RunPendingTasks();
    Compositor().BeginFrame();

    ASSERT_TRUE(GetDocument().IsUseCounted(WebFeature::kForceLoadAtTop));
    EXPECT_FALSE(GetDocument().IsUseCounted(
        WebFeature::kTextFragmentBlockedByForceLoadAtTop));
  }

  // This time there was a text fragment along with the DocumentPolicy so we
  // record TextFragmentBlocked.
  {
    SimRequest::Params params;
    params.response_http_headers.insert("Document-Policy", "force-load-at-top");
    SimRequest request("https://example.com/test2.html#:~:text=foo",
                       "text/html", params);
    LoadURL("https://example.com/test2.html#:~:text=foo");
    request.Complete(R"HTML(
      <!DOCTYPE html>
      <p>This is a test page</p>
    )HTML");
    RunUntilTextFragmentFinalization();

    ASSERT_TRUE(GetDocument().IsUseCounted(WebFeature::kForceLoadAtTop));
    EXPECT_TRUE(GetDocument().IsUseCounted(
        WebFeature::kTextFragmentBlockedByForceLoadAtTop));
  }

  // Ensure that an unblocked text fragment doesn't cause recording the
  // TextFragmentBlocked counter.
  {
    SimRequest request("https://example.com/test3.html#:~:text=foo",
                       "text/html");
    LoadURL("https://example.com/test3.html#:~:text=foo");
    request.Complete(R"HTML(
      <!DOCTYPE html>
      <p>This is a test page</p>
    )HTML");
    RunUntilTextFragmentFinalization();

    ASSERT_FALSE(GetDocument().IsUseCounted(WebFeature::kForceLoadAtTop));
    EXPECT_FALSE(GetDocument().IsUseCounted(
        WebFeature::kTextFragmentBlockedByForceLoadAtTop));
  }
}

TEST_F(TextFragmentAnchorMetricsTest, TextFragmentLinkOpenSource_GoogleDomain) {
  // Set the referrer to a google domain page.
  SimRequest::Params params;
  params.requestor_origin = WebSecurityOrigin::CreateFromString(
      WebString::FromUTF8("https://www.mail.google.com"));
  SimRequest request("https://example.com/test.html#:~:text=test&text=cat",
                     "text/html", params);
  LoadURL("https://example.com/test.html#:~:text=test&text=cat");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      p {
        position: absolute;
        top: 1000px;
      }
    </style>
    <p>This is a test page</p>
    <p>With ambiguous test content</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  // This should be recorded as coming from an unknown source (not search
  // engine).
  histogram_tester_.ExpectTotalCount("TextFragmentAnchor.LinkOpenSource", 1);
  histogram_tester_.ExpectUniqueSample("TextFragmentAnchor.LinkOpenSource", 0,
                                       1);
}

TEST_F(TextFragmentAnchorMetricsTest, ShadowDOMUseCounter) {
  {
    SimRequest request("https://example.com/test.html#:~:text=RegularDOM",
                       "text/html");
    LoadURL("https://example.com/test.html#:~:text=RegularDOM");
    request.Complete(R"HTML(
      <!DOCTYPE html>
      <p>This is RegularDOM</p>
    )HTML");
    RunUntilTextFragmentFinalization();

    EXPECT_FALSE(
        GetDocument().IsUseCounted(WebFeature::kTextDirectiveInShadowDOM));
  }

  {
    SimRequest request("https://example.com/shadowtest.html#:~:text=ShadowDOM",
                       "text/html");
    LoadURL("https://example.com/shadowtest.html#:~:text=ShadowDOM");
    request.Complete(R"HTML(
      <!DOCTYPE html>
      <p>This is RegularDOM</p>
      <p id="shadow-parent"></p>
      <script>
        let shadow = document.getElementById("shadow-parent").attachShadow({mode: 'open'});
        shadow.innerHTML = '<p id="shadow">This is ShadowDOM</p>';
      </script>
    )HTML");
    RunUntilTextFragmentFinalization();

    EXPECT_TRUE(
        GetDocument().IsUseCounted(WebFeature::kTextDirectiveInShadowDOM));
  }
}

}  // namespace blink

"""

```