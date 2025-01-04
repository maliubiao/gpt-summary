Response:
Let's break down the thought process for analyzing the `scroll_metrics_test.cc` file.

1. **Understand the Core Purpose:** The filename `scroll_metrics_test.cc` immediately suggests this is a test file related to scroll metrics. The `#include "third_party/blink/renderer/core/page/scrolling/scroll_metrics_test.cc"` confirms it's part of the Blink rendering engine, specifically within the scrolling functionality. The presence of `TEST_P` macros strongly indicates it uses Google Test framework for writing unit tests.

2. **Identify Key Components and Concepts:**  Scanning the includes reveals crucial information:
    * `base/test/metrics/histogram_tester.h`:  This indicates the test file is concerned with recording and verifying metrics, likely related to scrolling performance. Histograms are a common way to aggregate and analyze performance data.
    * `cc/input/main_thread_scrolling_reason.h`: This points to the core subject of the tests: *why* scrolling happens on the main thread. This header likely defines various reasons or conditions.
    * `third_party/blink/renderer/core/frame/...`:  These headers indicate interaction with the Blink rendering pipeline, particularly frames, views, and layout.
    * `third_party/blink/renderer/core/input/event_handler.h`:  This confirms interaction with input events, specifically scrolling-related events.
    * The `EXPECT_WHEEL_BUCKET`, `EXPECT_TOUCH_BUCKET`, etc. macros reinforce the idea of testing histogram buckets for specific scrolling reasons.

3. **Analyze the Test Structure:** The file defines a `ScrollMetricsTest` class inheriting from `PaintTestConfigurations` and `SimTest`. This setup provides a testing environment with simulated browser behavior and rendering capabilities. The `INSTANTIATE_PAINT_TEST_SUITE_P(ScrollMetricsTest);` line indicates this is a parameterized test suite, though the parameters aren't explicitly defined in this snippet.

4. **Examine Helper Functions and Classes:**
    * `ScrollBeginEventBuilder`, `ScrollUpdateEventBuilder`, `ScrollEndEventBuilder`: These classes are clearly designed to create simulated gesture events for testing scrolling. They encapsulate the details of creating these events, making the tests cleaner.
    * `BucketIndex`: This function likely maps the `MainThreadScrollingReason` enum values to the indices used in the histogram buckets.
    * `Scroll`: This is the central function for simulating a scroll action. It takes an element and a `WebGestureDevice` as input, constructs the appropriate gesture events, and dispatches them.
    * `SetUpHtml`: This function sets up the initial HTML structure for each test, providing a consistent testing environment. It handles loading the HTML and performing initial layout.
    * `UpdateAllLifecyclePhases`: This function forces the rendering pipeline to update, ensuring the state is consistent before and after simulating scrolling.

5. **Deconstruct Individual Tests:**  Each `TEST_P` function focuses on a specific scrolling scenario:
    * `TouchAndWheelGeneralTest`: Tests basic touch and wheel scrolling on a non-composited element, verifying the reasons for main thread scrolling.
    * `CompositedScrollableAreaTest`:  Tests the impact of making an element composited on scrolling behavior and the reported metrics.
    * `NotScrollableAreaTest`: Tests scrolling on an element with `overflow: hidden`, examining how the lack of scrollability affects the reported reasons.
    * `NestedScrollersTest`: Tests scrolling within nested scrollable areas, analyzing which scrollable element receives the scroll event and the corresponding metrics.

6. **Connect to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:** The tests use HTML snippets to create the elements being scrolled (divs with specific IDs and classes). The structure of the HTML directly influences how scrolling behaves.
    * **CSS:**  CSS properties like `overflow`, `width`, `height`, `border-radius`, `will-change`, and `-webkit-scrollbar` are central to the test scenarios. These properties determine scrollability, compositing behavior, and visual appearance. The tests directly manipulate CSS classes to change the rendering properties of elements.
    * **JavaScript (Indirectly):** While no explicit JavaScript code is present *in the test file*, the tests *simulate* user interactions that could be triggered by JavaScript (e.g., `element.scrollBy()`). The tests are designed to verify the underlying scrolling mechanism that JavaScript interacts with.

7. **Identify Logical Reasoning and Assumptions:** The tests operate under several assumptions:
    * The simulated input events accurately represent real user interactions.
    * The `MainThreadScrollingReason` enum and its associated logic correctly identify the causes of main thread scrolling.
    * The histogram recording mechanism is functioning correctly.
    * The testing environment (SimTest, PaintTestConfigurations) provides a reliable and representative rendering environment.
    * The meaning of being "composited" and its effect on scrolling is well-defined within Blink.

8. **Consider User and Programming Errors:**
    * **User Errors:** The tests implicitly cover scenarios where user actions (touch, wheel) might lead to main thread scrolling due to the way the webpage is structured (non-composited elements, etc.).
    * **Programming Errors:** The tests help identify potential bugs in Blink's scrolling implementation. For example, if a composited element *incorrectly* reports main thread scrolling, the tests would fail. Incorrectly classifying scrolling reasons would also lead to test failures.

9. **Trace User Operations (Debugging):**  To reach this code during debugging:
    1. **User Interaction:** A user interacts with a webpage by scrolling using a mouse wheel or touchscreen.
    2. **Event Handling:** The browser captures these input events (mouse wheel events, touch events).
    3. **Event Dispatch:** These events are dispatched through the Blink rendering engine's input handling mechanisms.
    4. **Hit Testing:** The engine determines which element the scroll interaction is targeting.
    5. **Scrolling Logic:** Based on the target element's properties (scrollability, compositing status, etc.), the engine decides how to handle the scroll. This involves the logic being tested in `scroll_metrics_test.cc`.
    6. **Metric Recording:**  During the scrolling process, the engine records metrics about why scrolling is happening on the main thread (or not). This is where the histograms being tested are populated.
    7. **Debugging Focus:**  A developer investigating scrolling performance or issues with main thread jank might look at these metrics and use `scroll_metrics_test.cc` to understand how different factors contribute to main thread scrolling. They might modify the tests or add new ones to reproduce and diagnose specific problems.

By following these steps, one can comprehensively understand the purpose, functionality, and context of the `scroll_metrics_test.cc` file within the Chromium Blink engine.
好的，让我们来详细分析一下 `blink/renderer/core/page/scrolling/scroll_metrics_test.cc` 这个文件。

**文件功能概述**

这个文件是一个 **C++ 单元测试文件**，属于 Chromium Blink 渲染引擎的一部分。它的主要功能是 **测试和验证 Blink 引擎在处理页面滚动时收集的各种指标 (metrics)**。 具体来说，它关注的是 **主线程 (main thread) 上发生的滚动行为以及其发生的原因**。

Blink 引擎会记录哪些操作导致了主线程上的滚动，这对于性能分析和优化至关重要。如果滚动操作能够在合成器线程 (compositor thread) 上处理，通常会更流畅，减少卡顿。此测试文件旨在确保 Blink 正确地识别和记录导致主线程滚动的各种情况。

**与 JavaScript, HTML, CSS 的关系及举例说明**

这个测试文件虽然是用 C++ 编写的，但它测试的行为直接与 JavaScript, HTML, 和 CSS 的功能息息相关，因为这些技术共同决定了网页的结构、样式和交互行为，包括滚动。

* **HTML:**  测试用例会创建不同的 HTML 结构，例如包含可滚动区域的 `div` 元素。HTML 结构定义了哪些部分可以滚动，以及嵌套关系。
    * **举例:**  `SetUpHtml` 函数中使用的 HTML 片段会创建带有 `overflow: scroll` 样式的 `div` 元素，从而使其成为可滚动的容器。

* **CSS:** CSS 样式直接影响元素的渲染和滚动行为。例如，`overflow` 属性决定了元素是否可滚动，`will-change` 属性可以影响元素是否会被合成。
    * **举例:**
        * 测试用例会使用 `overflow: scroll` 来创建可滚动区域。
        * 使用 `will-change: transform` 将元素标记为可能发生变换，这通常会导致元素被合成到单独的层，从而可以实现更流畅的合成器线程滚动。
        * 使用 `border-radius` 来测试某些情况下是否会阻止快速滚动 (fast scroll)。

* **JavaScript:**  虽然测试文件中没有直接的 JavaScript 代码，但它模拟了用户通过 JavaScript 可能触发的滚动行为。例如，`element->scrollBy(0, 1000)` 模拟了 JavaScript 代码调用 `scrollBy` 方法来滚动元素。 此外，用户与页面的交互（例如触摸滑动或鼠标滚轮）最终会被 Blink 转换为相应的事件并处理，这与 JavaScript 事件处理机制有关。
    * **举例:**  `Scroll(box, WebGestureDevice::kTouchpad)` 函数模拟了用户使用触摸板滚动 `box` 元素的操作，这和 JavaScript 中监听 `wheel` 或 `touchmove` 事件并进行处理是相关的。

**逻辑推理、假设输入与输出**

测试文件中的逻辑推理主要体现在对不同场景的假设和对预期输出的验证上。

* **假设输入:**  测试用例会模拟不同的用户输入（例如触摸滑动、鼠标滚轮）作用于不同的 HTML 结构和 CSS 样式的元素上。
    * **例1 (TouchAndWheelGeneralTest):**  假设有一个不可合成的、带有 `overflow: scroll` 的 `div` 元素。用户对其进行触摸和滚轮滚动。
    * **例2 (CompositedScrollableAreaTest):**  假设有一个初始状态不可合成的 `div`，然后通过修改其 class 属性使其变为可合成的。用户对其进行滚轮滚动。
    * **例3 (NestedScrollersTest):** 假设有嵌套的可滚动 `div` 元素，内部的 `div` 是合成的。用户滚动内部的 `div`。

* **预期输出:**  测试用例会验证在这些假设输入下，Blink 引擎是否记录了正确的滚动原因到相应的 histogram 中。这些 histogram 的 bucket 代表了不同的主线程滚动原因。
    * **例1 输出:**  预期会记录 `MainThreadScrollingReason::kMainThreadScrollHitTestRegion` (因为元素不可合成，需要主线程进行 hit test) 以及可能的 `MainThreadScrollingReason::kNotOpaqueForTextAndLCDText` (如果元素不透明度不足以进行快速滚动优化) 和 `MainThreadScrollingReason::kScrollingOnMainForAnyReason`。
    * **例2 输出:**  在元素不可合成时，输出与例 1 类似。在元素变为可合成后，预期会记录 `MainThreadScrollingReason::kNotScrollingOnMain`。
    * **例3 输出:**  当滚动合成的内部 `div` 时，预期会记录 `MainThreadScrollingReason::kNotScrollingOnMain`。当滚动到外部的非合成 `div` 时，预期会记录与例 1 类似的理由。

**用户或编程常见的使用错误举例**

虽然这个文件是测试代码，但它可以帮助揭示用户或开发者在构建网页时可能遇到的问题：

* **过度依赖主线程滚动:**  如果网页中存在大量不可合成的滚动区域，会导致滚动性能不佳。开发者应该尽量利用 CSS 的 `will-change` 属性或其他合成技术来将滚动操作转移到合成器线程。测试用例中 `CompositedScrollableAreaTest` 就展示了合成带来的好处。
* **不必要的重绘和重排:**  某些 CSS 属性或 JavaScript 操作可能会导致滚动过程中触发主线程的重绘和重排，从而影响性能。测试用例中验证的 metrics 可以帮助识别这些性能瓶颈。
* **不正确的 `overflow` 使用:**  如果开发者错误地使用了 `overflow: hidden`，可能会阻止用户滚动本应可滚动的内容。`NotScrollableAreaTest` 验证了这种情况下的 metric 记录。
* **hit test 性能问题:**  复杂的 DOM 结构和样式可能导致 hit test 过程耗时较长，迫使滚动在主线程上进行。测试用例中关于 `kMainThreadScrollHitTestRegion` 的验证就与此相关。

**用户操作如何一步步到达这里 (调试线索)**

要理解用户操作如何触发到这里所测试的代码，可以从以下步骤考虑：

1. **用户发起滚动:** 用户通过触摸屏滑动、鼠标滚轮滚动、或者使用键盘方向键等方式与网页进行交互，尝试滚动页面的某个区域。
2. **浏览器接收输入事件:** 用户的操作会被操作系统捕获，并传递给浏览器。浏览器会将这些操作转化为相应的输入事件，例如 `wheel` 事件、`touchstart`/`touchmove`/`touchend` 事件。
3. **事件分发到渲染引擎:** 浏览器将这些输入事件传递给 Blink 渲染引擎进行处理。
4. **事件处理和 hit test:** Blink 引擎的事件处理机制会确定哪个元素是滚动的目标元素。这个过程可能涉及到 hit test，即判断用户操作的点落在哪个元素上。
5. **滚动处理逻辑:**  根据目标元素的属性（例如 `overflow` 样式、是否被合成）以及滚动的类型，Blink 引擎会执行相应的滚动处理逻辑。
6. **主线程或合成器线程滚动:**  如果目标元素是合成的，并且滚动操作可以由合成器线程独立处理，则滚动会在合成器线程上进行。否则，滚动操作可能需要在主线程上执行。
7. **滚动指标记录:**  在滚动处理过程中，`scroll_metrics_test.cc` 所测试的代码会记录各种指标，判断滚动是否发生在主线程，并记录发生的原因。这些原因对应着 `cc::MainThreadScrollingReason` 枚举中的值。
8. **调试分析:**  当开发者遇到滚动性能问题时，他们可能会查看这些滚动指标的 histogram 数据，以了解哪些因素导致了主线程滚动。`scroll_metrics_test.cc` 中的测试用例可以帮助开发者理解这些指标的含义，并验证 Blink 引擎在不同场景下是否正确地记录了这些指标。开发者可能会修改测试用例来复现特定的问题场景，或者添加新的测试用例来覆盖更多的滚动情况。

总而言之，`scroll_metrics_test.cc` 是 Blink 引擎中一个非常重要的测试文件，它确保了 Blink 能够准确地监控和记录页面滚动行为，这对于性能优化和问题诊断至关重要。它测试的行为与网页的 HTML 结构、CSS 样式以及用户的交互方式都紧密相关。

Prompt: 
```
这是目录为blink/renderer/core/page/scrolling/scroll_metrics_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/metrics/histogram_tester.h"
#include "cc/base/features.h"
#include "cc/input/main_thread_scrolling_reason.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

#define EXPECT_WHEEL_BUCKET(index, count)                        \
  do {                                                           \
    SCOPED_TRACE("EXPECT_WHEEL_BUCKET");                         \
    histogram_tester->ExpectBucketCount(                         \
        "Renderer4.MainThreadWheelScrollReason2", index, count); \
  } while (false)

#define EXPECT_TOUCH_BUCKET(index, count)                          \
  do {                                                             \
    SCOPED_TRACE("EXPECT_TOUCH_BUCKET");                           \
    histogram_tester->ExpectBucketCount(                           \
        "Renderer4.MainThreadGestureScrollReason2", index, count); \
  } while (false)

#define EXPECT_WHEEL_TOTAL(count)                         \
  do {                                                    \
    SCOPED_TRACE("EXPECT_WHEEL_TOTAL");                   \
    histogram_tester->ExpectTotalCount(                   \
        "Renderer4.MainThreadWheelScrollReason2", count); \
  } while (false)

#define EXPECT_TOUCH_TOTAL(count)                           \
  do {                                                      \
    SCOPED_TRACE("EXPECT_TOUCH_TOTAL");                     \
    histogram_tester->ExpectTotalCount(                     \
        "Renderer4.MainThreadGestureScrollReason2", count); \
  } while (false)

namespace blink {

namespace {

class ScrollMetricsTest : public PaintTestConfigurations, public SimTest {
 public:
  void SetUpHtml(const char*);
  void Scroll(Element*, const WebGestureDevice);
  void UpdateAllLifecyclePhases() {
    GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  }
};

INSTANTIATE_PAINT_TEST_SUITE_P(ScrollMetricsTest);

class ScrollBeginEventBuilder : public WebGestureEvent {
 public:
  ScrollBeginEventBuilder(gfx::PointF position,
                          gfx::PointF delta,
                          WebGestureDevice device)
      : WebGestureEvent(WebInputEvent::Type::kGestureScrollBegin,
                        WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests(),
                        device) {
    SetPositionInWidget(position);
    SetPositionInScreen(position);
    data.scroll_begin.delta_y_hint = delta.y();
    frame_scale_ = 1;
  }
};

class ScrollUpdateEventBuilder : public WebGestureEvent {
 public:
  explicit ScrollUpdateEventBuilder(WebGestureDevice device)
      : WebGestureEvent(WebInputEvent::Type::kGestureScrollUpdate,
                        WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests(),
                        device) {
    data.scroll_update.delta_x = 0.0f;
    data.scroll_update.delta_y = -1.0f;
    frame_scale_ = 1;
  }
};

class ScrollEndEventBuilder : public WebGestureEvent {
 public:
  explicit ScrollEndEventBuilder(WebGestureDevice device)
      : WebGestureEvent(WebInputEvent::Type::kGestureScrollEnd,
                        WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests(),
                        device) {
    frame_scale_ = 1;
  }
};

int BucketIndex(uint32_t reason) {
  return cc::MainThreadScrollingReason::BucketIndexForTesting(reason);
}

void ScrollMetricsTest::Scroll(Element* element,
                               const WebGestureDevice device) {
  DCHECK(element);
  DCHECK(element->GetBoundingClientRect());
  DOMRect* rect = element->GetBoundingClientRect();
  ScrollBeginEventBuilder scroll_begin(
      gfx::PointF(rect->left() + rect->width() / 2,
                  rect->top() + rect->height() / 2),
      gfx::PointF(0.f, -1.f), device);
  ScrollUpdateEventBuilder scroll_update(device);
  ScrollEndEventBuilder scroll_end(device);
  GetWebFrameWidget().DispatchThroughCcInputHandler(scroll_begin);
  GetWebFrameWidget().DispatchThroughCcInputHandler(scroll_update);
  GetWebFrameWidget().DispatchThroughCcInputHandler(scroll_end);

  // Negative delta in the gesture event corresponds to positive delta to the
  // scroll offset (see CreateScrollStateForGesture).
  ASSERT_LT(scroll_update.DeltaYInRootFrame(), 0);
}

void ScrollMetricsTest::SetUpHtml(const char* html_content) {
  ResizeView(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(html_content);
  Compositor().BeginFrame();

  GetDocument().View()->SetParentVisible(true);
  GetDocument().View()->SetSelfVisible(true);
  UpdateAllLifecyclePhases();
}

TEST_P(ScrollMetricsTest, TouchAndWheelGeneralTest) {
  SetUpHtml(R"HTML(
    <style>
     .box { overflow:scroll; width: 100px; height: 100px;
            /* Make the box not opaque to hit test, so that not eligible for
               fast scroll hit test. */
            border-radius: 5px; }
     .spacer { height: 1000px; }
    </style>
    <div id='box' class='box'>
     <div class='spacer'></div>
    </div>
  )HTML");

  Element* box = GetDocument().getElementById(AtomicString("box"));
  std::optional<base::HistogramTester> histogram_tester;
  histogram_tester.emplace();

  // Test touch scroll.
  Scroll(box, WebGestureDevice::kTouchscreen);

  // The below reasons are reported because #box is not composited.
  EXPECT_TOUCH_BUCKET(
      BucketIndex(
          cc::MainThreadScrollingReason::kMainThreadScrollHitTestRegion),
      1);
  if (!RuntimeEnabledFeatures::RasterInducingScrollEnabled()) {
    EXPECT_TOUCH_BUCKET(
        BucketIndex(cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText),
        1);
  }
  EXPECT_TOUCH_BUCKET(
      cc::MainThreadScrollingReason::kScrollingOnMainForAnyReason, 1);
  EXPECT_TOUCH_TOTAL(RuntimeEnabledFeatures::RasterInducingScrollEnabled() ? 2
                                                                           : 3);

  // Reset histogram tester.
  histogram_tester.emplace();

  // Test wheel scroll.
  Scroll(box, WebGestureDevice::kTouchpad);

  // The below reasons are reported because #box is not composited.
  EXPECT_WHEEL_BUCKET(
      BucketIndex(
          cc::MainThreadScrollingReason::kMainThreadScrollHitTestRegion),
      1);
  if (!RuntimeEnabledFeatures::RasterInducingScrollEnabled()) {
    EXPECT_WHEEL_BUCKET(
        BucketIndex(cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText),
        1);
  }
  EXPECT_WHEEL_BUCKET(
      cc::MainThreadScrollingReason::kScrollingOnMainForAnyReason, 1);
  EXPECT_WHEEL_TOTAL(RuntimeEnabledFeatures::RasterInducingScrollEnabled() ? 2
                                                                           : 3);
}

TEST_P(ScrollMetricsTest, CompositedScrollableAreaTest) {
  SetUpHtml(R"HTML(
    <style>
     .box { overflow:scroll; width: 100px; height: 100px; }
     /* Make the box not opaque to hit test, so that not eligible for fast
        scroll hit test. */
     .border-radius { border-radius: 5px; }
     .composited { will-change: transform; border-radius: 0; }
     .spacer { height: 1000px; }
    </style>
    <div id='box' class='box border-radius'>
     <div class='spacer'></div>
    </div>
  )HTML");

  Element* box = GetDocument().getElementById(AtomicString("box"));
  std::optional<base::HistogramTester> histogram_tester;
  histogram_tester.emplace();

  Scroll(box, WebGestureDevice::kTouchpad);

  // The below reasons are reported because #box is not composited.
  EXPECT_WHEEL_BUCKET(
      BucketIndex(
          cc::MainThreadScrollingReason::kMainThreadScrollHitTestRegion),
      1);
  if (!RuntimeEnabledFeatures::RasterInducingScrollEnabled()) {
    EXPECT_WHEEL_BUCKET(
        BucketIndex(cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText),
        1);
  }
  EXPECT_WHEEL_BUCKET(
      cc::MainThreadScrollingReason::kScrollingOnMainForAnyReason, 1);
  EXPECT_WHEEL_TOTAL(RuntimeEnabledFeatures::RasterInducingScrollEnabled() ? 2
                                                                           : 3);

  // Reset histogram tester.
  histogram_tester.emplace();

  box->setAttribute(html_names::kClassAttr,
                    AtomicString("composited transform box"));
  Compositor().BeginFrame();
  Scroll(box, WebGestureDevice::kTouchpad);

  // Now that #box is composited, cc reports that we do not scroll on main.
  EXPECT_WHEEL_BUCKET(cc::MainThreadScrollingReason::kNotScrollingOnMain, 1);
  EXPECT_WHEEL_TOTAL(1);
}

TEST_P(ScrollMetricsTest, NotScrollableAreaTest) {
  SetUpHtml(R"HTML(
    <style>
     .box { overflow:scroll; width: 100px; height: 100px;
            /* Make the box not opaque to hit test, so that not eligible for
               fast scroll hit test. */
            border-radius: 5px; }
     .hidden { overflow: hidden; }
     .spacer { height: 1000px; }
    </style>
    <div id='box' class='box'>
     <div class='spacer'></div>
    </div>
  )HTML");

  Element* box = GetDocument().getElementById(AtomicString("box"));
  std::optional<base::HistogramTester> histogram_tester;
  histogram_tester.emplace();

  Scroll(box, WebGestureDevice::kTouchpad);

  // The below reasons are reported because #box is not composited.
  EXPECT_WHEEL_BUCKET(
      BucketIndex(
          cc::MainThreadScrollingReason::kMainThreadScrollHitTestRegion),
      1);
  if (!RuntimeEnabledFeatures::RasterInducingScrollEnabled()) {
    EXPECT_WHEEL_BUCKET(
        BucketIndex(cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText),
        1);
  }
  EXPECT_WHEEL_BUCKET(
      cc::MainThreadScrollingReason::kScrollingOnMainForAnyReason, 1);
  EXPECT_WHEEL_TOTAL(RuntimeEnabledFeatures::RasterInducingScrollEnabled() ? 2
                                                                           : 3);

  // Reset histogram tester.
  histogram_tester.emplace();

  box->setAttribute(html_names::kClassAttr,
                    AtomicString("hidden transform box"));
  UpdateAllLifecyclePhases();
  Scroll(box, WebGestureDevice::kTouchpad);

  // The overflow: hidden element is still a non-fast scroll region, so cc
  // reports the following for the second scroll:
  //   kMainThreadScrollHitTestRegion
  //   kScrollingOnMainForAnyReason
  //
  // Since #box is overflow: hidden, the hit test returns the viewport, and
  // so we do not log kNoScrollingLayer again.
  EXPECT_WHEEL_BUCKET(
      BucketIndex(
          cc::MainThreadScrollingReason::kMainThreadScrollHitTestRegion),
      1);
  EXPECT_WHEEL_BUCKET(
      cc::MainThreadScrollingReason::kScrollingOnMainForAnyReason, 1);
  EXPECT_WHEEL_TOTAL(2);
}

TEST_P(ScrollMetricsTest, NestedScrollersTest) {
  SetUpHtml(R"HTML(
    <style>
     .container { overflow:scroll; width: 200px; height: 200px; }
     .box { overflow:scroll; width: 100px; height: 100px; }
     /* to prevent the mock overlay scrollbar from affecting compositing. */
     .box::-webkit-scrollbar { display: none; }
     .spacer { height: 1000px; }
     .composited { will-change: transform; }
    </style>
    <div id='container' class='container with-border-radius'>
      <div class='box'>
        <div id='inner' class='composited box'>
          <div class='spacer'></div>
        </div>
        <div class='spacer'></div>
      </div>
      <div class='spacer'></div>
    </div>
  )HTML");

  Element* box = GetDocument().getElementById(AtomicString("inner"));
  std::optional<base::HistogramTester> histogram_tester;
  histogram_tester.emplace();

  Scroll(box, WebGestureDevice::kTouchpad);

  // The gesture latches to #inner, which is composited.
  EXPECT_WHEEL_BUCKET(cc::MainThreadScrollingReason::kNotScrollingOnMain, 1);
  EXPECT_WHEEL_TOTAL(1);

  histogram_tester.emplace();
  box->scrollBy(0, 1000);
  Compositor().BeginFrame();
  Scroll(box, WebGestureDevice::kTouchpad);

  // The second scroll latches to the non-composited parent.
  if (!RuntimeEnabledFeatures::RasterInducingScrollEnabled()) {
    EXPECT_WHEEL_BUCKET(
        BucketIndex(cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText),
        1);
    EXPECT_WHEEL_BUCKET(
        cc::MainThreadScrollingReason::kScrollingOnMainForAnyReason, 1);
    EXPECT_WHEEL_TOTAL(2);
  } else {
    EXPECT_WHEEL_BUCKET(cc::MainThreadScrollingReason::kNotScrollingOnMain, 1);
    EXPECT_WHEEL_TOTAL(1);
  }
}

}  // namespace

}  // namespace blink

"""

```