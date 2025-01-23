Response:
The user is asking for a summary of the functionality of the provided C++ code. This is the second part of a two-part file. The code is a unit test file for `LocalFrameUkmAggregator` in the Chromium Blink rendering engine. It seems to test various scenarios related to UKM (User Keyed Metrics) recording and performance metrics within a local frame context, including interactions with iframes and JavaScript.

Here's a breakdown of how to approach the summarization:

1. **Identify the Core Class Under Test:** The filename and test class names (`LocalFrameUkmAggregatorSimTest`, `LocalFrameUkmAggregatorSyncScrollTest`) clearly indicate that the primary focus is testing the `LocalFrameUkmAggregator`.

2. **Analyze Individual Test Cases:** Go through each `TEST_F` block and understand what scenario it's setting up and verifying. Look for assertions (`EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `histogram_tester.ExpectTotalCount`, etc.) to understand the expected behavior.

3. **Group Test Cases by Functionality:**  Notice patterns in the test names and the operations performed. For example, several tests deal with `IntersectionObserverCounts`, and others with `PrePostFCPMetrics`.

4. **Connect to Web Technologies (JavaScript, HTML, CSS):** Observe how the tests manipulate the DOM (creating iframes, setting `innerHTML`, styling elements) and use simulated browser events (`Compositor().BeginFrame()`). Identify where JavaScript execution is involved and how it affects the metrics being tested.

5. **Identify Potential User/Programming Errors:**  Consider what incorrect usage or code patterns these tests might be designed to detect or ensure proper handling of. For example, the sync scroll tests seem to focus on potentially janky behavior caused by JavaScript interacting with scrolling.

6. **Address the "Assumptions and Outputs" Request:**  For tests involving logical reasoning (like the sync scroll heuristic), think about the conditions being tested (mutation of properties, access to scroll offset) and the expected outcome (whether a specific metric is recorded).

7. **Focus on the "Part 2" Aspect:** Since this is the second part, assume that the first part likely laid the groundwork and tested more basic functionalities. This part seems to delve into more specific and potentially complex scenarios.

8. **Structure the Summary:** Organize the findings into logical sections, covering the different types of tests and their implications.

**Mental Walkthrough of Key Test Cases:**

* **`GetUkmAggregator`:**  Verifies that the same `UkmAggregator` instance is shared between the main frame and its subframes. This relates to the hierarchical nature of web pages and how metrics are collected across frames.

* **`IntersectionObserverCounts` (both single and iframe):** Checks if the `UkmAggregator` correctly counts Intersection Observer notifications. This is directly related to a web API used for tracking element visibility, and likely informs performance metrics.

* **`LocalFrameRootPrePostFCPMetrics`:** Focuses on First Contentful Paint (FCP) within a local root frame (not the main frame). This is a key performance metric.

* **`PrePostFCPMetricsWithChildFrameFCP`:** Tests how FCP in a child frame affects the metrics recorded for the parent frame. This highlights the interaction between frames regarding performance measurements.

* **`VisualUpdateDelay`:** Measures the time delay between a request for an animation frame and its actual execution. This relates to rendering performance and responsiveness, often influenced by JavaScript.

* **`SVGImageMetricsAreNotRecorded`:** Ensures that certain metrics are not incorrectly recorded for SVG images, potentially to avoid noise in the data.

* **`LocalFrameUkmAggregatorSyncScrollTest`:** This is the most complex part, testing a heuristic for detecting "synchronized scrolling," where JavaScript logic tightly couples scrolling with visual updates, potentially causing jank. The different parameterizations of this test cover various JavaScript patterns and DOM manipulations.

By following these steps, I can construct a comprehensive summary that addresses all aspects of the user's request.
这是对 `blink/renderer/core/frame/local_frame_ukm_aggregator_test.cc` 文件功能的归纳，基于提供的第二部分代码。

**总而言之，这个代码文件是 Chromium Blink 引擎中 `LocalFrameUkmAggregator` 类的集成测试，旨在验证在各种模拟场景下，该类是否能正确地收集和记录用户关键指标 (UKM) 和其他性能相关的统计信息。**

**以下是更详细的归纳，并结合了可能的假设和关系：**

* **跨 Frame UKM 聚合测试:**  `GetUkmAggregator` 测试用例验证了在包含 iframe 的页面中，主框架和子框架是否共享同一个 `UkmAggregator` 实例。这表明 UKM 的聚合是跨越整个页面（包括其子框架）进行的。
    * **与 HTML 的关系:**  使用 `<iframe>` 元素创建子框架，测试 UKM 聚合在不同文档上下文中的行为。
    * **假设输入:** 一个包含 iframe 的 HTML 页面。
    * **预期输出:** 主框架和子框架的 `GetUkmAggregator()` 方法返回相同的指针。

* **Intersection Observer 指标统计测试:** `IntersectionObserverCounts` 和 `IntersectionObserverCountsInChildFrame` 测试用例验证了 `LocalFrameUkmAggregator` 是否能正确统计 `IntersectionObserver` 的通知次数。这对于衡量页面元素的可见性和性能至关重要。
    * **与 JavaScript 和 HTML 的关系:**  `IntersectionObserver` 是一个 JavaScript API，用于监听元素与其祖先元素或视口交叉状态的变化。测试用例中使用了 HTML 结构来创建需要观察的元素。CSS 用于设置元素的大小和位置，影响交叉状态。
    * **假设输入:** 包含设置了 `IntersectionObserver` 监听器的 HTML 页面，以及 CSS 样式定义元素的大小和布局。
    * **预期输出:** 相关的 UKM 或直方图（由 `TestIntersectionObserverCounts` 函数验证，代码中未提供具体实现）记录了正确的通知次数。

* **本地根框架 Pre-FCP 和 Post-FCP 指标测试:** `LocalFrameRootPrePostFCPMetrics` 测试用例验证了在本地根框架（非主框架）中，是否正确标记了首次内容绘制 (FCP) 前后的状态。
    * **与性能指标的关系:** FCP 是衡量页面加载性能的关键指标。这个测试确保了在非主框架中也能正确跟踪 FCP 的状态。

* **包含子框架 FCP 的 Pre-FCP 和 Post-FCP 指标测试:** `PrePostFCPMetricsWithChildFrameFCP` 测试用例验证了当子框架发生 FCP 时，主框架的 Pre-FCP 和 Post-FCP 指标的记录情况。
    * **与 HTML 和性能指标的关系:**  使用了 `<iframe>` 创建子框架，并模拟了子框架中元素的更新导致 FCP 的过程。测试了主框架在子框架 FCP 发生前后的指标记录。
    * **假设输入:**  一个包含 iframe 的 HTML 页面，子框架的内容在加载过程中会触发 FCP。
    * **预期输出:**  `Blink.MainFrame.UpdateTime.PreFCP` 和 `Blink.MainFrame.UpdateTime.PostFCP` 直方图记录了正确的次数，反映了主框架在子框架 FCP 前后的渲染更新。

* **视觉更新延迟测试:** `VisualUpdateDelay` 测试用例衡量了视觉更新的延迟，即从请求动画帧到实际执行的时间间隔。
    * **与 JavaScript 和性能指标的关系:** `requestAnimationFrame` 是 JavaScript 中用于执行动画的关键 API。这个测试衡量了由于各种原因导致的动画延迟，这直接影响用户体验的流畅度。
    * **假设输入:**  JavaScript 代码调用 `requestAnimationFrame`。
    * **预期输出:**  `Blink.VisualUpdateDelay.UpdateTime.PreFCP` 直方图记录了视觉更新的延迟时间。

* **SVG 图片指标排除测试:** `SVGImageMetricsAreNotRecorded` 测试用例验证了某些性能指标（例如样式计算和主帧更新时间）是否不会被错误地记录到 SVG 图片上。
    * **与 HTML 和性能指标的关系:**  测试用例加载了多个 SVG 图片，并验证了性能指标的记录次数，确保不会将 SVG 图片的渲染活动错误地计入主框架的指标。
    * **假设输入:**  HTML 页面中包含多个 SVG 图片。
    * **预期输出:**  `Blink.Style.UpdateTime.PreFCP` 和 `Blink.MainFrame.UpdateTime.PreFCP` 直方图记录的次数与预期相符，不包含对 SVG 图片的错误计数。

* **同步滚动启发式测试 (Sync Scroll Heuristic):** `LocalFrameUkmAggregatorSyncScrollTest` 是一系列参数化测试，用于验证一个启发式算法，该算法旨在检测可能导致性能问题的同步滚动行为。这种行为通常发生在 JavaScript 代码在滚动事件处理程序中直接修改 DOM 元素的位置或变换，导致浏览器在滚动过程中进行同步布局和绘制。
    * **与 JavaScript、HTML 和 CSS 的关系:**  这些测试用例通过 JavaScript 代码模拟了不同的滚动事件处理策略（例如，直接修改样式、使用 `requestAnimationFrame`），以及不同的 DOM 操作（修改 `top`、`transform`、`scrollTop`）。CSS 用于定义元素的样式和布局。
    * **假设输入:**  包含 JavaScript 代码的 HTML 页面，该代码可能会在滚动事件处理程序中修改 DOM 元素。滚动事件被触发。
    * **预期输出:**  `Blink.PossibleSynchronizedScrollCount2.UpdateTime.PreFCP` 和 `Blink.PossibleSynchronizedScrollCount2.UpdateTime.PostFCP` 直方图会根据是否触发了同步滚动启发式算法进行记录。`ShouldTriggerSyncScrollHeuristic()` 方法定义了触发的条件，主要基于是否在滚动处理程序中修改了元素的位置或偏移，并访问了滚动偏移量。

**用户或编程常见的错误示例 (在同步滚动启发式测试中体现):**

* **在滚动事件处理程序中同步修改元素位置或变换:**  这是同步滚动启发式试图检测的典型错误。例如：
    ```javascript
    document.addEventListener('scroll', (e) => {
      document.getElementById('myElement').style.top = window.scrollY + 'px';
    });
    ```
    这种做法会导致浏览器在滚动过程中被迫同步进行布局和绘制，可能导致卡顿和性能问题。

* **在滚动事件处理程序中不必要地读取或写入布局相关的属性:**  即使没有直接修改位置或变换，访问某些属性（如 `offsetWidth`、`offsetHeight`、`offsetTop` 等）也可能触发回流 (reflow)，影响性能。

**总结来说，这部分测试代码专注于验证 `LocalFrameUkmAggregator` 在更复杂和特定的场景下的行为，特别是涉及到 iframe、Intersection Observer、FCP 指标以及潜在的性能问题（如同步滚动）。它通过模拟真实的 Web 页面结构和 JavaScript 行为来确保指标收集的准确性和可靠性。**

### 提示词
```
这是目录为blink/renderer/core/frame/local_frame_ukm_aggregator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
vate:
  // Deterministically record metrics in test.
  base::MetricsSubSampler::ScopedAlwaysSampleForTesting no_subsampling_;
};

TEST_F(LocalFrameUkmAggregatorSimTest, GetUkmAggregator) {
  SimRequest main_resource("https://example.com/", "text/html");
  SimRequest frame_resource("https://example.com/frame.html", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete("<iframe id=frame src='frame.html'></iframe>");
  frame_resource.Complete("");

  auto* root_view = GetDocument().View();
  root_view->ResetUkmAggregatorForTesting();
  auto* subframe_view = To<HTMLFrameOwnerElement>(
                            GetDocument().getElementById(AtomicString("frame")))
                            ->contentDocument()
                            ->View();
  auto* aggregator_from_subframe = subframe_view->GetUkmAggregator();
  auto* aggregator_from_root = root_view->GetUkmAggregator();
  EXPECT_EQ(aggregator_from_root, aggregator_from_subframe);
  EXPECT_EQ(aggregator_from_root, subframe_view->GetUkmAggregator());
  EXPECT_EQ(aggregator_from_root, root_view->GetUkmAggregator());
}

TEST_F(LocalFrameUkmAggregatorSimTest, IntersectionObserverCounts) {
  std::unique_ptr<base::StatisticsRecorder> statistics_recorder =
      base::StatisticsRecorder::CreateTemporaryForTesting();
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
    .target { width: 50px; height: 50px; }
    .spacer { height: 1000px; }
    </style>
    <div id=target1 class=target></div>
    <div id=target2 class=target></div>
    <div class=spacer></div>
  )HTML");
  Compositor().BeginFrame();
  ChooseNextFrameForTest();
  TestIntersectionObserverCounts(GetDocument());
}

TEST_F(LocalFrameUkmAggregatorSimTest, IntersectionObserverCountsInChildFrame) {
  std::unique_ptr<base::StatisticsRecorder> statistics_recorder =
      base::StatisticsRecorder::CreateTemporaryForTesting();
  base::HistogramTester histogram_tester;
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  SimRequest frame_resource("https://example.com/frame.html", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete("<iframe id=frame src='frame.html'></iframe>");
  frame_resource.Complete(R"HTML(
    <style>
    .target { width: 50px; height: 50px; }
    .spacer { height: 1000px; }
    </style>
    <div id=target1 class=target></div>
    <div id=target2 class=target></div>
    <div class=spacer></div>
  )HTML");
  Compositor().BeginFrame();
  ChooseNextFrameForTest();
  TestIntersectionObserverCounts(
      *To<HTMLFrameOwnerElement>(
           GetDocument().getElementById(AtomicString("frame")))
           ->contentDocument());
}

TEST_F(LocalFrameUkmAggregatorSimTest, LocalFrameRootPrePostFCPMetrics) {
  InitializeRemote();
  LocalFrame& local_frame_root = *LocalFrameRoot().GetFrame();
  ASSERT_FALSE(local_frame_root.IsMainFrame());
  ASSERT_TRUE(local_frame_root.IsLocalRoot());

  EXPECT_TRUE(IsBeforeFCPForTesting());
  // Simulate the first contentful paint.
  PaintTiming::From(*local_frame_root.GetDocument()).MarkFirstContentfulPaint();
  EXPECT_FALSE(IsBeforeFCPForTesting());
}

TEST_F(LocalFrameUkmAggregatorSimTest, PrePostFCPMetricsWithChildFrameFCP) {
  base::HistogramTester histogram_tester;
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  SimRequest frame_resource("https://example.com/frame.html", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete("<iframe id=frame src='frame.html'></iframe>");
  frame_resource.Complete(R"HTML(<!doctype html>
    <div id=target></div>
  )HTML");

  // Do a pre-FCP frame.
  Compositor().BeginFrame();
  EXPECT_TRUE(IsBeforeFCPForTesting());
  histogram_tester.ExpectTotalCount("Blink.MainFrame.UpdateTime.PreFCP", 1);
  histogram_tester.ExpectTotalCount("Blink.MainFrame.UpdateTime.PostFCP", 0);

  // Make a change to the subframe that results in FCP for that subframe.
  auto* subframe_document =
      To<HTMLFrameOwnerElement>(
          GetDocument().getElementById(AtomicString("frame")))
          ->contentDocument();
  Element* target = subframe_document->getElementById(AtomicString("target"));
  target->setInnerHTML("test1");

  // Do a frame that reaches FCP.
  Compositor().BeginFrame();
  EXPECT_FALSE(IsBeforeFCPForTesting());
  histogram_tester.ExpectTotalCount("Blink.MainFrame.UpdateTime.PreFCP", 2);
  histogram_tester.ExpectTotalCount("Blink.MainFrame.UpdateTime.PostFCP", 0);

  // Make a change to the subframe that causes another frame.
  target->setInnerHTML("test2");

  // Do a post-FCP frame.
  Compositor().BeginFrame();
  EXPECT_FALSE(IsBeforeFCPForTesting());
  histogram_tester.ExpectTotalCount("Blink.MainFrame.UpdateTime.PreFCP", 2);
  histogram_tester.ExpectTotalCount("Blink.MainFrame.UpdateTime.PostFCP", 1);
}

TEST_F(LocalFrameUkmAggregatorSimTest, VisualUpdateDelay) {
  base::HistogramTester histogram_tester;

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <!doctype html>
    <div id=target></div>
  )HTML");

  // The first main frame will not record VisualUpdateDelay because it was
  // requested before the current document was installed.
  Compositor().BeginFrame();
  histogram_tester.ExpectTotalCount("Blink.VisualUpdateDelay.UpdateTime.PreFCP",
                                    0);

  // This is necessary to ensure that the invalidation timestamp is later than
  // the previous frame time.
  Compositor().ResetLastFrameTime();

  // This is the code path for a normal invalidation from blink
  WebView().MainFrameViewWidget()->RequestAnimationAfterDelay(
      base::TimeDelta());

  base::PlatformThread::Sleep(base::Microseconds(3000));

  // Service the frame; it should record a sample.
  Compositor().BeginFrame();
  histogram_tester.ExpectTotalCount("Blink.VisualUpdateDelay.UpdateTime.PreFCP",
                                    1);
  base::HistogramBase::Sample delay =
      base::saturated_cast<base::HistogramBase::Sample>(
          (Compositor().LastFrameTime() -
           local_root_aggregator().LastFrameRequestTimeForTest())
              .InMicroseconds());
  EXPECT_GT(delay, 3000);
  histogram_tester.ExpectUniqueSample(
      "Blink.VisualUpdateDelay.UpdateTime.PreFCP", delay, 1);
}

TEST_F(LocalFrameUkmAggregatorSimTest, SVGImageMetricsAreNotRecorded) {
  base::HistogramTester histogram_tester;

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <!doctype html>
    <img src="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'
        fill='red' width='10' height='10'><path d='M0 0 L8 0 L4 7 Z'/></svg>">
    <img src="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'
        fill='green' width='10' height='10'><path d='M0 0 L8 0 L4 7 Z'/></svg>">
    <img src="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'
        fill='blue' width='10' height='10'><path d='M0 0 L8 0 L4 7 Z'/></svg>">
  )HTML");

  // Do a pre-FCP frame.
  Compositor().BeginFrame();

  // Metrics should only be reported for the root frame, not for each svg image.
  histogram_tester.ExpectTotalCount("Blink.Style.UpdateTime.PreFCP", 1);
  histogram_tester.ExpectTotalCount("Blink.MainFrame.UpdateTime.PreFCP", 1);
}

enum SyncScrollMutation {
  kSyncScrollMutatesPosition,
  kSyncScrollMutatesTransform,
  kSyncScrollMutatesScrollOffset,
  kSyncScrollMutatesPositionBeforeAccess,
  kSyncScrollMutatesNothing,
};

enum SyncScrollPositionAccess {
  kSyncScrollAccessScrollOffset,
  kSyncScrollDoesNotAccessScrollOffset,
};

enum SyncScrollHandlerStrategy {
  kSyncScrollWithEventHandler,
  kSyncScrollWithEventHandlerSchedulingRAF,
  kSyncScrollNoEventHandlerWithRAF,
  kSyncScrollNoEventHandler,
};

using SyncScrollHeuristicTestConfig =
    ::testing::tuple<SyncScrollMutation,
                     SyncScrollPositionAccess,
                     SyncScrollHandlerStrategy>;

class LocalFrameUkmAggregatorSyncScrollTest
    : public LocalFrameUkmAggregatorSimTest,
      public ::testing::WithParamInterface<SyncScrollHeuristicTestConfig> {
 public:
  static std::string PrintTestName(
      const ::testing::TestParamInfo<SyncScrollHeuristicTestConfig>& info) {
    std::stringstream ss;
    switch (GetSyncScrollMutation(info.param)) {
      case SyncScrollMutation::kSyncScrollMutatesPosition:
        ss << "MutatesPosition";
        break;
      case SyncScrollMutation::kSyncScrollMutatesPositionBeforeAccess:
        ss << "MutatesPositionBeforeAccess";
        break;
      case SyncScrollMutation::kSyncScrollMutatesTransform:
        ss << "MutatesTransform";
        break;
      case SyncScrollMutation::kSyncScrollMutatesScrollOffset:
        ss << "MutatesScrollOffset";
        break;
      case SyncScrollMutation::kSyncScrollMutatesNothing:
        ss << "MutatesNothing";
        break;
    }
    ss << "_";
    switch (GetSyncScrollPositionAccess(info.param)) {
      case SyncScrollPositionAccess::kSyncScrollAccessScrollOffset:
        ss << "AccessScrollOffset";
        break;
      case SyncScrollPositionAccess::kSyncScrollDoesNotAccessScrollOffset:
        ss << "DoesNotAccessScrollOffset";
        break;
    }
    ss << "_";
    switch (GetSyncScrollHandlerStrategy(info.param)) {
      case SyncScrollHandlerStrategy::kSyncScrollWithEventHandler:
        ss << "WithEventHandler";
        break;
      case SyncScrollHandlerStrategy::kSyncScrollWithEventHandlerSchedulingRAF:
        ss << "WithEventHandlerSchedulingRAF";
        break;
      case SyncScrollHandlerStrategy::kSyncScrollNoEventHandler:
        ss << "NoEventHandler";
        break;
      case SyncScrollHandlerStrategy::kSyncScrollNoEventHandlerWithRAF:
        ss << "NoEventHandlerWithRAF";
        break;
    }
    return ss.str();
  }

 protected:
  static SyncScrollMutation GetSyncScrollMutation(
      const SyncScrollHeuristicTestConfig& config) {
    return ::testing::get<0>(config);
  }

  static SyncScrollPositionAccess GetSyncScrollPositionAccess(
      const SyncScrollHeuristicTestConfig& config) {
    return ::testing::get<1>(config);
  }

  static SyncScrollHandlerStrategy GetSyncScrollHandlerStrategy(
      const SyncScrollHeuristicTestConfig& config) {
    return ::testing::get<2>(config);
  }

  bool ShouldTriggerSyncScrollHeuristic() const {
    // We would only attempt to synchronize scrolling if we had a scroll handler
    // and, provided this is the case, we look for both mutating a property and
    // accessing scroll offset. Note: it's also ok to mutate via rAF, provided
    // that rAF was scheduled during the scroll handler.
    return GetSyncScrollMutation(GetParam()) !=
               SyncScrollMutation::kSyncScrollMutatesNothing &&
           GetSyncScrollMutation(GetParam()) !=
               SyncScrollMutation::kSyncScrollMutatesPositionBeforeAccess &&
           GetSyncScrollPositionAccess(GetParam()) ==
               SyncScrollPositionAccess::kSyncScrollAccessScrollOffset &&
           (GetSyncScrollHandlerStrategy(GetParam()) ==
                SyncScrollHandlerStrategy::kSyncScrollWithEventHandler ||
            GetSyncScrollHandlerStrategy(GetParam()) ==
                SyncScrollHandlerStrategy::
                    kSyncScrollWithEventHandlerSchedulingRAF);
  }

  std::string GenerateNewScrollPosition() {
    switch (GetSyncScrollPositionAccess(GetParam())) {
      case SyncScrollPositionAccess::kSyncScrollAccessScrollOffset:
        return "document.scrollingElement.scrollTop";
      case SyncScrollPositionAccess::kSyncScrollDoesNotAccessScrollOffset:
        return "100";
    }
    NOTREACHED();
  }

  std::string GenerateMutation() {
    std::string pos = GenerateNewScrollPosition();
    switch (GetSyncScrollMutation(GetParam())) {
      case SyncScrollMutation::kSyncScrollMutatesPosition:
        return base::StringPrintf("card.style.top = %s + 'px'", pos.c_str());
      case SyncScrollMutation::kSyncScrollMutatesTransform:
        return base::StringPrintf(
            "card.style.transform = 'translateY(' + %s + 'px)'", pos.c_str());
      case SyncScrollMutation::kSyncScrollMutatesScrollOffset:
        return base::StringPrintf("subscroller.scrollTop = %s + 'px'",
                                  pos.c_str());
      case SyncScrollMutation::kSyncScrollMutatesPositionBeforeAccess:
        return base::StringPrintf(
            "card.style.top = Math.floor(Math.random() * 100) + 'px'; var "
            "unused = %s",
            pos.c_str());
      case SyncScrollMutation::kSyncScrollMutatesNothing:
        return "";
    }
    NOTREACHED();
  }

  std::string GenerateScrollHandler() {
    switch (GetSyncScrollHandlerStrategy(GetParam())) {
      case SyncScrollHandlerStrategy::kSyncScrollWithEventHandler:
        return base::StringPrintf(R"HTML(
          document.addEventListener('scroll', (e) => {
            %s;
          });
        )HTML",
                                  GenerateMutation().c_str());
      case SyncScrollHandlerStrategy::kSyncScrollWithEventHandlerSchedulingRAF:
        return base::StringPrintf(R"HTML(
          document.addEventListener('scroll', (e) => {
            window.requestAnimationFrame((t) => { %s; });
          });
        )HTML",
                                  GenerateMutation().c_str());
      case SyncScrollHandlerStrategy::kSyncScrollNoEventHandlerWithRAF:
        return base::StringPrintf(R"HTML(
          function doSyncEffect(t) {
            %s;
            window.requestAnimationFrame(doSyncEffect);
          }
          window.requestAnimationFrame(doSyncEffect);
        )HTML",
                                  GenerateMutation().c_str());
      case SyncScrollHandlerStrategy::kSyncScrollNoEventHandler:
        return "";
    }
    NOTREACHED();
  }

  ScopedTestingPlatformSupport<TestingPlatformSupportWithMockScheduler>
      platform_;
};

TEST_P(LocalFrameUkmAggregatorSyncScrollTest, SyncScrollHeuristicRAFSetTop) {
  base::HistogramTester histogram_tester;
  const bool should_trigger = ShouldTriggerSyncScrollHeuristic();

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  std::string html = base::StringPrintf(R"HTML(
    <!DOCTYPE html>
    <style>
      #card {
        background: green;
        width: 100px;
        height: 100px;
        position: absolute;
      }
      #subscroller {
        width: 100px;
        height: 100px;
        position: fixed;
        top:0;
        overflow: scroll;
      }
    </style>
    <div id='card'></div>
    <div id='subscroller'>
      <div style='background:blue;width50px;height:10000px'></div>
    </div>
    <div style='background:orange;width:100px;height:10000px'></div>
    <script>
      %s
    </script>
  )HTML",
                                        GenerateScrollHandler().c_str());
  main_resource.Complete(html.c_str());

  // Wait until the script has had time to run.
  platform_->RunForPeriodSeconds(5.);
  base::RunLoop().RunUntilIdle();

  // Do a pre-FCP frame.
  Compositor().BeginFrame();

  // We haven't scrolled at this point, so we should never have a count.
  histogram_tester.ExpectTotalCount(
      "Blink.PossibleSynchronizedScrollCount2.UpdateTime.PreFCP", 0);

  // Cause a pre-FCP scroll.
  auto* scrolling_element =
      LocalFrameRoot().GetFrame()->GetDocument()->scrollingElement();
  scrolling_element->setScrollTop(100.0);

  // Do another pre-FCP frame.
  Compositor().BeginFrame();

  // Now that we'ev scrolled, we should have an update if triggering conditions
  // are met.
  histogram_tester.ExpectTotalCount(
      "Blink.PossibleSynchronizedScrollCount2.UpdateTime.PreFCP",
      should_trigger ? 1 : 0);

  // Cause FCP on the next frame.
  Element* target = GetDocument().getElementById(AtomicString("card"));
  target->setInnerHTML("hello world");

  Compositor().BeginFrame();

  EXPECT_FALSE(IsBeforeFCPForTesting());

  scrolling_element =
      LocalFrameRoot().GetFrame()->GetDocument()->scrollingElement();
  scrolling_element->setScrollTop(200.0);

  // Do another post-FCP frame.
  Compositor().BeginFrame();

  if (should_trigger) {
    // Should only have triggered for the one pre FCP scroll.
    EXPECT_THAT(
        histogram_tester.GetAllSamples("Blink.PossibleSynchronizedScrollCount2."
                                       "UpdateTime.AggregatedPreFCP"),
        base::BucketsAre(base::Bucket(1, 1)));
    // Should only have triggered for the one post FCP scroll.
    histogram_tester.ExpectTotalCount(
        "Blink.PossibleSynchronizedScrollCount2.UpdateTime.PostFCP", 1);
  } else {
    // Should never trigger.
    EXPECT_THAT(
        histogram_tester.GetAllSamples("Blink.PossibleSynchronizedScrollCount2."
                                       "UpdateTime.AggregatedPreFCP"),
        base::BucketsAre(base::Bucket(0, 1)));
    histogram_tester.ExpectTotalCount(
        "Blink.PossibleSynchronizedScrollCount2.UpdateTime.PostFCP", 0);
  }
}

INSTANTIATE_TEST_SUITE_P(
    P,
    LocalFrameUkmAggregatorSyncScrollTest,
    ::testing::Combine(
        ::testing::Values(
            SyncScrollMutation::kSyncScrollMutatesPosition,
            SyncScrollMutation::kSyncScrollMutatesTransform,
            SyncScrollMutation::kSyncScrollMutatesScrollOffset,
            SyncScrollMutation::kSyncScrollMutatesPositionBeforeAccess,
            SyncScrollMutation::kSyncScrollMutatesNothing),
        ::testing::Values(
            SyncScrollPositionAccess::kSyncScrollAccessScrollOffset,
            SyncScrollPositionAccess::kSyncScrollDoesNotAccessScrollOffset),
        ::testing::Values(
            SyncScrollHandlerStrategy::kSyncScrollWithEventHandler,
            SyncScrollHandlerStrategy::kSyncScrollWithEventHandlerSchedulingRAF,
            SyncScrollHandlerStrategy::kSyncScrollNoEventHandlerWithRAF,
            SyncScrollHandlerStrategy::kSyncScrollNoEventHandler)),
    LocalFrameUkmAggregatorSyncScrollTest::PrintTestName);

}  // namespace blink
```