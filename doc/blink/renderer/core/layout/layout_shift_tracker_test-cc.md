Response:
The user wants a summary of the functionality of the provided C++ code file `layout_shift_tracker_test.cc`.

This file appears to be a unit test file for the `LayoutShiftTracker` class in the Chromium Blink engine. The goal of the tests is likely to verify that the `LayoutShiftTracker` correctly identifies and scores layout shifts, and that it correctly handles various edge cases and scenarios related to layout shifts.

Here's a breakdown of the types of tests present:

* **Ignoring shifts after input:** Tests that layout shifts happening after user input (like a mouse click) are ignored for CLS calculation.
* **Handling composited shifts:** Tests scenarios involving composited layers and how they impact CLS.
* **Ignoring shifts in SVG:** Verifies that changes within SVG elements are not counted as layout shifts.
* **Ignoring shifts after `change` events:** Checks that layout shifts triggered by `change` events (like in a `<select>` element) are excluded.
* **Subframe weighting:** Tests how layout shifts in iframes are weighted based on their visibility within the viewport.
* **Viewport size and zoom level changes:** Ensures that layout shifts caused by viewport resizing or zoom level changes are not counted.
* **Navigation:** Tests how layout shifts are handled during same-document navigations, considering whether the navigation was browser-initiated or renderer-initiated.
* **Pointer events:**  Examines the behavior of layout shift tracking with different pointer events (down, up, cancel, move), including scenarios involving dragging and scrolling.
* **Stable compositing changes:** Checks that certain compositing-related changes that don't visually shift content are not counted as layout shifts.
* **Composited overflow expansion:** Tests a specific scenario where expanding content causes a layout shift.
* **`content-visibility: auto`:** Investigates how the `content-visibility: auto` CSS property affects layout shift calculation, especially during initial paint and after scrolling.

I will now formulate a summary based on this analysis.
这是对 Chromium Blink 引擎中 `blink/renderer/core/layout/layout_shift_tracker_test.cc` 文件的功能归纳，该文件主要用于测试 `LayoutShiftTracker` 类的功能。`LayoutShiftTracker` 的主要目的是跟踪和计算页面布局的意外移动，这会影响用户体验，并作为 Cumulative Layout Shift (CLS) 指标的一部分被衡量。

**核心功能:**

该测试文件通过创建各种场景来验证 `LayoutShiftTracker` 的以下核心功能：

1. **准确检测布局偏移:** 测试各种情况下是否能正确识别出发生了布局偏移。
2. **计算布局偏移得分:** 验证在不同布局偏移场景下，`LayoutShiftTracker` 计算出的得分是否符合预期。
3. **区分用户预期和非预期的布局偏移:**  这是该类的关键功能。它需要区分由用户操作（如点击、输入）引起的布局变化，以及非用户操作引起的意外布局变化。用户操作后的布局变化通常不计入 CLS。
4. **处理各种类型的布局变化:** 包括由 CSS 属性变化、DOM 结构变化、iframe 加载、视口大小变化、缩放级别变化等引起的布局变化。
5. **处理复合（composited）层的布局变化:** 确保在涉及到硬件加速的复合层的情况下，布局偏移的计算仍然正确。
6. **处理 SVG 元素的布局变化:**  验证是否正确地忽略 SVG 元素内部的布局变化。
7. **处理不同类型的用户输入事件:** 测试在不同类型的用户输入（如鼠标点击、触摸事件）发生后，是否正确停止记录布局偏移。
8. **处理导航事件:**  测试在页面导航（包括同文档导航）发生时，布局偏移的计算和重置逻辑。
9. **考虑 iframe 的影响:** 测试子框架（iframe）中的布局偏移如何影响主框架的 CLS，并考虑 iframe 在视口中的可见性。
10. **处理 `content-visibility: auto` 属性:** 验证 `content-visibility: auto` 属性对布局偏移计算的影响，特别是在初始渲染和滚动后。

**与 Javascript, HTML, CSS 的关系及其举例说明:**

`LayoutShiftTracker` 的功能直接关联到 Web 前端的三大核心技术：

* **HTML:** HTML 结构定义了页面内容和元素，布局偏移通常涉及到 HTML 元素的移动或大小变化。
    * **举例:** 测试中通过 `SetBodyInnerHTML` 设置 HTML 内容，然后通过 JavaScript 修改元素的样式或属性，例如移动一个 `<div>` 元素的位置。
* **CSS:** CSS 控制元素的样式和布局，布局偏移通常是由 CSS 属性的变化引起的。
    * **举例:** 测试中会修改元素的 CSS 属性，例如 `position`, `top`, `left`, `width`, `height`，来模拟布局偏移。还会测试像 `will-change: transform` 和 `content-visibility: auto` 这样的 CSS 属性对布局偏移计算的影响。
* **Javascript:** Javascript 通常用于动态修改 DOM 结构和 CSS 样式，从而可能导致布局偏移。`LayoutShiftTracker` 需要能够捕捉到这些由 Javascript 触发的布局变化。
    * **举例:** 测试中使用了 Javascript 代码来监听事件（如 `mouseup`, `hashchange`, `pointerdown`, `pointermove`, `pointerup`），并在事件处理函数中修改元素的样式，模拟 Javascript 导致的布局偏移。

**逻辑推理的假设输入与输出:**

* **假设输入:** 一个 HTML 页面包含一个绝对定位的 `<div>` 元素。初始状态下，该元素的 `top` 属性为 `0px`。
* **操作:** 通过 Javascript 将该元素的 `top` 属性修改为 `100px`。
* **预期输出:** `LayoutShiftTracker` 应该检测到这个布局偏移，并计算出一个非零的 CLS 得分。得分的具体数值取决于元素的大小、移动距离以及视口大小。

* **假设输入:** 用户点击页面上的一个按钮，该按钮的点击事件处理函数会动态地向页面中插入一个新的 `<img>` 元素，导致下方的内容向下移动。
* **预期输出:** 在用户点击事件发生后的一段时间内，由于发生了用户交互，`LayoutShiftTracker` 应该忽略这个由插入图片导致的布局偏移，CLS 得分不应增加。

**涉及用户或者编程常见的使用错误:**

1. **未考虑异步加载资源的大小:**  开发者在编写 HTML 时，如果没有为图片或广告等异步加载的资源预留足够的空间，当这些资源加载完成后，可能会导致下方内容发生明显的布局偏移，这是常见的 CLS 问题。
    * **测试体现:** 测试中模拟了动态插入内容导致布局偏移的场景。
2. **在用户交互后仍然进行非必要的布局修改:**  开发者可能会在用户点击后，由于某些逻辑处理，仍然进行一些布局相关的修改，这些修改如果导致明显的视觉偏移，仍然会被计入 CLS。
    * **测试体现:**  测试了在 `mouseup` 事件处理函数中修改元素样式的情况，以验证是否正确忽略了用户交互后的布局偏移。
3. **不合理地使用动画或过渡效果:**  某些动画或过渡效果如果导致页面元素的意外移动，也会被计入 CLS。`LayoutShiftTracker` 需要区分平滑的过渡和突兀的布局偏移。
    * **测试体现:** 虽然当前代码没有直接测试动画或过渡，但 `LayoutShiftTracker` 的设计目标是捕捉所有类型的意外布局偏移，包括由动画引起的。
4. **在滚动处理中使用会导致布局变化的 Javascript 代码:** 例如在 `scroll` 事件监听器中修改元素的尺寸或位置。
    * **测试体现:**  测试中模拟了触摸滚动 (`TouchScrollingAction`) 的场景，验证了在这种情况下布局偏移的计算方式。

**归纳一下它的功能 (第 1 部分):**

`blink/renderer/core/layout/layout_shift_tracker_test.cc` 文件的主要功能是为 Chromium Blink 引擎的 `LayoutShiftTracker` 类提供全面的单元测试。 这些测试旨在验证 `LayoutShiftTracker` 能够准确地检测和计算各种场景下的布局偏移，并能够正确区分用户预期和非预期的布局变化。测试覆盖了由 HTML、CSS 和 Javascript 引起的各种布局变化，包括复合层、SVG 元素、iframe 以及不同类型的用户输入和导航事件。 此外，测试还涵盖了诸如视口大小变化、缩放级别变化以及 `content-visibility: auto` 等特定场景对布局偏移计算的影响。 这些测试帮助确保 `LayoutShiftTracker` 能够可靠地衡量 Cumulative Layout Shift (CLS) 指标，从而帮助开发者优化网页的用户体验。

### 提示词
```
这是目录为blink/renderer/core/layout/layout_shift_tracker_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/layout/layout_shift_tracker.h"

#include "third_party/blink/public/common/input/web_mouse_event.h"
#include "third_party/blink/renderer/core/dom/dom_token_list.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/performance_entry_names.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/core/timing/layout_shift.h"
#include "third_party/blink/renderer/core/timing/window_performance.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

class LayoutShiftTrackerTest : public RenderingTest {
 protected:
  void SetUp() override {
    EnableCompositing();
    RenderingTest::SetUp();
  }
  LocalFrameView& GetFrameView() { return *GetFrame().View(); }
  LayoutShiftTracker& GetLayoutShiftTracker() {
    return GetFrameView().GetLayoutShiftTracker();
  }

  void SimulateInput() {
    GetLayoutShiftTracker().NotifyInput(WebMouseEvent(
        WebInputEvent::Type::kMouseDown, gfx::PointF(), gfx::PointF(),
        WebPointerProperties::Button::kLeft, 0,
        WebInputEvent::Modifiers::kLeftButtonDown, base::TimeTicks::Now()));
  }
};

TEST_F(LayoutShiftTrackerTest, IgnoreAfterInput) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #j { position: relative; width: 300px; height: 100px; background: blue; }
    </style>
    <div id='j'></div>
  )HTML");
  GetElementById("j")->setAttribute(html_names::kStyleAttr,
                                    AtomicString("top: 60px"));
  SimulateInput();
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0.0, GetLayoutShiftTracker().Score());
  EXPECT_TRUE(GetLayoutShiftTracker().ObservedInputOrScroll());
  EXPECT_TRUE(GetLayoutShiftTracker()
                  .MostRecentInputTimestamp()
                  .since_origin()
                  .InSecondsF() > 0.0);
}

TEST_F(LayoutShiftTrackerTest, CompositedShiftBeforeFirstPaint) {
  // Tests that we don't crash if a new layer shifts during a second compositing
  // update before prepaint sets up property tree state.  See crbug.com/881735
  // (which invokes UpdateAllLifecyclePhasesExceptPaint through
  // accessibilityController.accessibleElementById).

  SetBodyInnerHTML(R"HTML(
    <style>
      .hide { display: none; }
      .tr { will-change: transform; }
      body { margin: 0; }
      div { height: 100px; background: blue; }
    </style>
    <div id="container">
      <div id="A">A</div>
      <div id="B" class="tr hide">B</div>
    </div>
  )HTML");

  GetElementById("B")->setAttribute(html_names::kClassAttr, AtomicString("tr"));
  GetFrameView().UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kTest);
  GetElementById("A")->setAttribute(html_names::kClassAttr,
                                    AtomicString("hide"));
  UpdateAllLifecyclePhasesForTest();
}

TEST_F(LayoutShiftTrackerTest, IgnoreSVG) {
  SetBodyInnerHTML(R"HTML(
    <svg>
      <circle cx="50" cy="50" r="40"
              stroke="black" stroke-width="3" fill="red" />
    </svg>
  )HTML");
  GetDocument()
      .QuerySelector(AtomicString("circle"))
      ->setAttribute(svg_names::kCxAttr, AtomicString("100"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());
}

TEST_F(LayoutShiftTrackerTest, IgnoreAfterChangeEvent) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #j { position: relative; width: 300px; height: 100px; background: blue; }
    </style>
    <div id='j'></div>
    <select id="sel" onchange="shift()">
      <option value="0">0</option>
      <option value="1">1</option>
    </select>
  )HTML");
  auto* select = To<HTMLSelectElement>(GetElementById("sel"));
  DCHECK(select);
  select->Focus();
  select->SelectOptionByPopup(1);
  GetElementById("j")->setAttribute(html_names::kStyleAttr,
                                    AtomicString("top: 60px"));

  UpdateAllLifecyclePhasesForTest();
  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());
}

class LayoutShiftTrackerSimTest : public SimTest {
 protected:
  void SetUp() override {
    SimTest::SetUp();
    WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  }
};

TEST_F(LayoutShiftTrackerSimTest, SubframeWeighting) {
  // TODO(crbug.com/943668): Test OOPIF path.
  SimRequest main_resource("https://example.com/", "text/html");
  SimRequest child_resource("https://example.com/sub.html", "text/html");

  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style> #i { border: 0; position: absolute; left: 0; top: 0; } </style>
    <iframe id=i width=400 height=300 src='sub.html'></iframe>
  )HTML");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  child_resource.Complete(R"HTML(
    <style>
      #j { position: relative; width: 300px; height: 100px; background: blue; }
    </style>
    <div id='j'></div>
  )HTML");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  WebLocalFrameImpl& child_frame =
      To<WebLocalFrameImpl>(*MainFrame().FirstChild());

  Element* div =
      child_frame.GetFrame()->GetDocument()->getElementById(AtomicString("j"));
  div->setAttribute(html_names::kStyleAttr, AtomicString("top: 60px"));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  // 300 * (100 + 60) * (60 / 400) / (default viewport size 800 * 600)
  LayoutShiftTracker& layout_shift_tracker =
      child_frame.GetFrameView()->GetLayoutShiftTracker();
  EXPECT_FLOAT_EQ(0.4 * (60.0 / 400.0), layout_shift_tracker.Score());
  EXPECT_FLOAT_EQ(0.1 * (60.0 / 400.0), layout_shift_tracker.WeightedScore());

  // Move subframe halfway outside the viewport.
  GetDocument()
      .getElementById(AtomicString("i"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("left: 600px"));

  div->removeAttribute(html_names::kStyleAttr);

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_FLOAT_EQ(0.8 * (60.0 / 400.0), layout_shift_tracker.Score());
  EXPECT_FLOAT_EQ(0.15 * (60.0 / 400.0), layout_shift_tracker.WeightedScore());
}

TEST_F(LayoutShiftTrackerSimTest, ViewportSizeChange) {
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
      body { margin: 0; }
      .square {
        display: inline-block;
        position: relative;
        width: 300px;
        height: 300px;
        background:yellow;
      }
    </style>
    <div class='square'></div>
    <div class='square'></div>
  )HTML");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  // Resize the viewport, making it 400px wide. This should cause the second div
  // to change position during block layout flow. Since it was the result of a
  // viewport size change, this position change should not affect the score.
  WebView().MainFrameViewWidget()->Resize(gfx::Size(400, 600));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  LayoutShiftTracker& layout_shift_tracker =
      MainFrame().GetFrameView()->GetLayoutShiftTracker();
  EXPECT_FLOAT_EQ(0.0, layout_shift_tracker.Score());
}

TEST_F(LayoutShiftTrackerSimTest, ZoomLevelChange) {
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
      body { margin: 0; }
      .square {
        display: inline-block;
        position: relative;
        width: 300px;
        height: 300px;
        background:yellow;
      }
    </style>
    <div class='square'></div>
    <div class='square'></div>
  )HTML");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  WebView().MainFrameViewWidget()->SetZoomLevelForTesting(1.0);

  Compositor().BeginFrame();
  test::RunPendingTasks();

  LayoutShiftTracker& layout_shift_tracker =
      MainFrame().GetFrameView()->GetLayoutShiftTracker();
  EXPECT_FLOAT_EQ(0.0, layout_shift_tracker.Score());
}

class LayoutShiftTrackerNavigationTest : public LayoutShiftTrackerSimTest {
 protected:
  void RunTest(bool is_browser_initiated);
};

void LayoutShiftTrackerNavigationTest::RunTest(bool is_browser_initiated) {
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
      body { margin: 0; height: 1500px; }
      #box {
        left: 0px;
        top: 0px;
        width: 400px;
        height: 600px;
        background: yellow;
        position: absolute;
      }
    </style>
    <div id="box"></div>
    <script>
      box.addEventListener("mouseup", (e) => {
        window.location.hash = '#a';
        e.preventDefault();
      });
      window.addEventListener('hashchange', () => {
        const shouldShow = window.location.hash === '#a';
        if (shouldShow)
          box.style.top = "100px";
        else
          box.style.top = "0px";
      });
    </script>
  )HTML");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  auto* main_frame = To<LocalFrame>(WebView().GetPage()->MainFrame());
  Persistent<HistoryItem> item1 =
      main_frame->Loader().GetDocumentLoader()->GetHistoryItem();

  WebMouseEvent event1(WebInputEvent::Type::kMouseDown, gfx::PointF(),
                       gfx::PointF(), WebPointerProperties::Button::kLeft, 0,
                       WebInputEvent::Modifiers::kLeftButtonDown,
                       base::TimeTicks::Now());
  WebMouseEvent event2(WebInputEvent::Type::kMouseUp, gfx::PointF(),
                       gfx::PointF(), WebPointerProperties::Button::kLeft, 1,
                       WebInputEvent::Modifiers::kLeftButtonDown,
                       base::TimeTicks::Now());

  // Coordinates inside #box.
  event1.SetPositionInWidget(50, 150);
  event2.SetPositionInWidget(50, 160);

  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event1, ui::LatencyInfo()));
  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event2, ui::LatencyInfo()));

  Compositor().BeginFrame();
  test::RunPendingTasks();
  LayoutShiftTracker& layout_shift_tracker =
      MainFrame().GetFrameView()->GetLayoutShiftTracker();
  layout_shift_tracker.ResetTimerForTesting();

  Persistent<HistoryItem> item2 =
      main_frame->Loader().GetDocumentLoader()->GetHistoryItem();

  main_frame->Loader().GetDocumentLoader()->CommitSameDocumentNavigation(
      item1->Url(), WebFrameLoadType::kBackForward, item1.Get(),
      ClientRedirectPolicy::kNotClientRedirect,
      /*has_transient_user_activation=*/false, /*initiator_origin=*/nullptr,
      /*is_synchronously_committed=*/false, /*source_element=*/nullptr,
      mojom::blink::TriggeringEventInfo::kNotFromEvent, is_browser_initiated,
      /*has_ua_visual_transition,=*/false,
      /*soft_navigation_heuristics_task_id=*/std::nullopt);

  Compositor().BeginFrame();
  test::RunPendingTasks();

  WindowPerformance& perf = *DOMWindowPerformance::performance(Window());
  auto entries =
      perf.getBufferedEntriesByType(performance_entry_names::kLayoutShift);
  EXPECT_EQ(1u, entries.size());
  LayoutShift* shift = static_cast<LayoutShift*>(entries.front().Get());
  // region fraction 50%, distance fraction 1/8
  const double expected_shift_value = 0.5 * 0.125;
  const double expected_cls_score =
      is_browser_initiated ? 0 : expected_shift_value;

  // Set hadRecentInput to be true for browser initiated history navigation,
  // and the layout shift score will be 0.
  EXPECT_EQ(is_browser_initiated, shift->hadRecentInput());
  EXPECT_FLOAT_EQ(expected_shift_value, shift->value());
  EXPECT_FLOAT_EQ(expected_cls_score, layout_shift_tracker.Score());
}

TEST_F(LayoutShiftTrackerNavigationTest,
       BrowserInitiatedSameDocumentHistoryNavigation) {
  RunTest(true /* is_browser_initiated */);
}

TEST_F(LayoutShiftTrackerNavigationTest,
       RendererInitiatedSameDocumentHistoryNavigation) {
  RunTest(false /* is_browser_initiated */);
}

class LayoutShiftTrackerPointerdownTest : public LayoutShiftTrackerSimTest {
 protected:
  void RunTest(WebInputEvent::Type completion_type, bool expect_exclusion);
};

void LayoutShiftTrackerPointerdownTest::RunTest(
    WebInputEvent::Type completion_type,
    bool expect_exclusion) {
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
      body { margin: 0; height: 1500px; }
      #box {
        left: 0px;
        top: 0px;
        width: 400px;
        height: 600px;
        background: yellow;
        position: relative;
      }
    </style>
    <div id="box"></div>
    <script>
      box.addEventListener("pointerdown", (e) => {
        box.style.top = "100px";
        e.preventDefault();
      });
    </script>
  )HTML");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  WebPointerProperties pointer_properties = WebPointerProperties(
      1 /* PointerId */, WebPointerProperties::PointerType::kTouch,
      WebPointerProperties::Button::kLeft);

  WebPointerEvent event1(WebInputEvent::Type::kPointerDown, pointer_properties,
                         5, 5);
  WebPointerEvent event2(completion_type, pointer_properties, 5, 5);

  // Coordinates inside #box.
  event1.SetPositionInWidget(50, 150);
  event2.SetPositionInWidget(50, 160);

  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event1, ui::LatencyInfo()));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  WindowPerformance& perf = *DOMWindowPerformance::performance(Window());
  auto& tracker = MainFrame().GetFrameView()->GetLayoutShiftTracker();

  EXPECT_EQ(0u,
            perf.getBufferedEntriesByType(performance_entry_names::kLayoutShift)
                .size());
  EXPECT_FLOAT_EQ(0.0, tracker.Score());

  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event2, ui::LatencyInfo()));

  // region fraction 50%, distance fraction 1/8
  const double expected_shift = 0.5 * 0.125;

  auto entries =
      perf.getBufferedEntriesByType(performance_entry_names::kLayoutShift);
  EXPECT_EQ(1u, entries.size());
  LayoutShift* shift = static_cast<LayoutShift*>(entries.front().Get());

  EXPECT_EQ(expect_exclusion, shift->hadRecentInput());
  EXPECT_FLOAT_EQ(expected_shift, shift->value());
  EXPECT_FLOAT_EQ(expect_exclusion ? 0.0 : expected_shift, tracker.Score());
}

TEST_F(LayoutShiftTrackerPointerdownTest, PointerdownBecomesTap) {
  RunTest(WebInputEvent::Type::kPointerUp, true /* expect_exclusion */);
}

TEST_F(LayoutShiftTrackerPointerdownTest, PointerdownCancelled) {
  RunTest(WebInputEvent::Type::kPointerCancel, false /* expect_exclusion */);
}

TEST_F(LayoutShiftTrackerPointerdownTest, PointerdownBecomesScroll) {
  RunTest(WebInputEvent::Type::kPointerCausedUaAction,
          false /* expect_exclusion */);
}

TEST_F(LayoutShiftTrackerSimTest, MouseMoveDraggingAction) {
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
      body { margin: 0; height: 1500px; }
      #box {
        left: 0px;
        top: 0px;
        width: 400px;
        height: 600px;
        background: yellow;
        position: absolute;
      }
    </style>
    <div id="box"></div>
    <script>
      box.addEventListener("mousemove", (e) => {
        box.style.top = "50px";
        e.preventDefault();
      });
      box.addEventListener("mouseup", (e) => {
        box.style.top = "100px";
        e.preventDefault();
      });
    </script>
  )HTML");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  WebMouseEvent event1(WebInputEvent::Type::kMouseDown, gfx::PointF(),
                       gfx::PointF(), WebPointerProperties::Button::kLeft, 0,
                       WebInputEvent::Modifiers::kLeftButtonDown,
                       base::TimeTicks::Now());
  WebMouseEvent event2(WebInputEvent::Type::kMouseMove, gfx::PointF(),
                       gfx::PointF(), WebPointerProperties::Button::kLeft, 1,
                       WebInputEvent::Modifiers::kLeftButtonDown,
                       base::TimeTicks::Now());
  WebMouseEvent event3(WebInputEvent::Type::kMouseUp, gfx::PointF(),
                       gfx::PointF(), WebPointerProperties::Button::kLeft, 1,
                       WebInputEvent::Modifiers::kLeftButtonDown,
                       base::TimeTicks::Now());

  // Coordinates inside #box.
  event1.SetPositionInWidget(50, 150);
  event2.SetPositionInWidget(50, 160);
  event3.SetPositionInWidget(50, 160);

  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event1, ui::LatencyInfo()));

  WindowPerformance& perf = *DOMWindowPerformance::performance(Window());
  auto& tracker = MainFrame().GetFrameView()->GetLayoutShiftTracker();
  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_EQ(0u,
            perf.getBufferedEntriesByType(performance_entry_names::kLayoutShift)
                .size());
  EXPECT_FLOAT_EQ(0.0, tracker.Score());

  tracker.ResetTimerForTesting();

  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event2, ui::LatencyInfo()));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_EQ(0u,
            perf.getBufferedEntriesByType(performance_entry_names::kLayoutShift)
                .size());
  EXPECT_FLOAT_EQ(0.0, tracker.Score());

  tracker.ResetTimerForTesting();

  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event3, ui::LatencyInfo()));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  auto entries =
      perf.getBufferedEntriesByType(performance_entry_names::kLayoutShift);
  EXPECT_EQ(2u, entries.size());
  LayoutShift* shift = static_cast<LayoutShift*>(entries.back().Get());

  EXPECT_TRUE(shift->hadRecentInput());
  EXPECT_GT(shift->value(), 0);
  EXPECT_FLOAT_EQ(0.0, tracker.Score());
}

TEST_F(LayoutShiftTrackerSimTest, TouchDraggingAction) {
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
      body { margin: 0; height: 1500px; }
      #box {
        left: 0px;
        top: 0px;
        width: 400px;
        height: 600px;
        background: yellow;
        position: absolute;
      }
    </style>
    <div id="box"></div>
    <script>
      box.addEventListener("pointermove", (e) => {
        box.style.top = "100px";
        e.preventDefault();
      });
    </script>
  )HTML");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  WebPointerProperties pointer_properties = WebPointerProperties(
      1 /* PointerId */, WebPointerProperties::PointerType::kTouch,
      WebPointerProperties::Button::kLeft);

  WebPointerEvent event1(WebInputEvent::Type::kPointerDown, pointer_properties,
                         5, 5);
  WebPointerEvent event2(WebInputEvent::Type::kPointerMove, pointer_properties,
                         5, 5);
  WebPointerEvent event3(WebInputEvent::Type::kPointerUp, pointer_properties, 5,
                         5);

  // Coordinates inside #box.
  event1.SetPositionInWidget(100, 160);
  event2.SetPositionInWidget(100, 180);
  event3.SetPositionInWidget(100, 180);

  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event1, ui::LatencyInfo()));

  WindowPerformance& perf = *DOMWindowPerformance::performance(Window());
  auto& tracker = MainFrame().GetFrameView()->GetLayoutShiftTracker();

  EXPECT_EQ(0u,
            perf.getBufferedEntriesByType(performance_entry_names::kLayoutShift)
                .size());
  EXPECT_FLOAT_EQ(0.0, tracker.Score());

  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event2, ui::LatencyInfo()));

  // Executes the BeginMainFrame processing steps and calls ReportShift in
  // LayoutShiftTracker to get the latest layout shift score.
  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_EQ(0u,
            perf.getBufferedEntriesByType(performance_entry_names::kLayoutShift)
                .size());
  EXPECT_FLOAT_EQ(0.0, tracker.Score());

  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event3, ui::LatencyInfo()));

  // region fraction 50%, distance fraction 1/8
  const double expected_shift = 0.5 * 0.125;

  auto entries =
      perf.getBufferedEntriesByType(performance_entry_names::kLayoutShift);
  EXPECT_EQ(1u, entries.size());
  LayoutShift* shift = static_cast<LayoutShift*>(entries.back().Get());

  EXPECT_TRUE(shift->hadRecentInput());
  EXPECT_FLOAT_EQ(expected_shift, shift->value());
  EXPECT_FLOAT_EQ(0.0, tracker.Score());
}

TEST_F(LayoutShiftTrackerSimTest, TouchScrollingAction) {
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
      body { margin: 0; height: 1500px; }
      #box {
        left: 0px;
        top: 0px;
        width: 400px;
        height: 600px;
        background: yellow;
        position: absolute;
      }
    </style>
    <div id="box"></div>
    <script>
      box.addEventListener("pointermove", (e) => {
        box.style.top = e.clientY;
        e.preventDefault();
      });
    </script>
  )HTML");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  WebPointerProperties pointer_properties = WebPointerProperties(
      1 /* PointerId */, WebPointerProperties::PointerType::kTouch,
      WebPointerProperties::Button::kLeft);

  WebPointerEvent event1(WebInputEvent::Type::kPointerDown, pointer_properties,
                         5, 5);
  WebPointerEvent event2(WebInputEvent::Type::kPointerMove, pointer_properties,
                         5, 5);
  WebPointerEvent event3(WebInputEvent::Type::kPointerCancel,
                         pointer_properties, 5, 5);
  WebPointerEvent event4(WebInputEvent::Type::kPointerMove, pointer_properties,
                         5, 5);

  // Coordinates inside #box.
  event1.SetPositionInWidget(80, 90);
  event2.SetPositionInWidget(80, 100);
  event3.SetPositionInWidget(80, 100);
  event4.SetPositionInWidget(80, 150);

  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event1, ui::LatencyInfo()));

  WindowPerformance& perf = *DOMWindowPerformance::performance(Window());
  auto& tracker = MainFrame().GetFrameView()->GetLayoutShiftTracker();

  EXPECT_EQ(0u,
            perf.getBufferedEntriesByType(performance_entry_names::kLayoutShift)
                .size());
  EXPECT_FLOAT_EQ(0.0, tracker.Score());

  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event2, ui::LatencyInfo()));

  // Executes the BeginMainFrame processing steps and calls ReportShift in
  // LayoutShiftTracker to get the latest layout shift score.
  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_EQ(0u,
            perf.getBufferedEntriesByType(performance_entry_names::kLayoutShift)
                .size());
  EXPECT_FLOAT_EQ(0, tracker.Score());

  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event3, ui::LatencyInfo()));

  // region fraction 50%, distance fraction 1/8
  const double expected_shift = 0.5 * 0.125;
  auto entries =
      perf.getBufferedEntriesByType(performance_entry_names::kLayoutShift);
  EXPECT_EQ(1u, entries.size());
  LayoutShift* shift = static_cast<LayoutShift*>(entries.back().Get());

  // For touch scroll, hasRecentInput is false, and the layout shift score is
  // reported when a PointerCancel event is received.
  EXPECT_FALSE(shift->hadRecentInput());
  EXPECT_FLOAT_EQ(expected_shift, shift->value());
  EXPECT_FLOAT_EQ(expected_shift, tracker.Score());

  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event4, ui::LatencyInfo()));

  // Executes the BeginMainFrame processing steps and calls ReportShift in
  // LayoutShiftTracker to get the latest layout shift score.
  Compositor().BeginFrame();
  test::RunPendingTasks();

  entries =
      perf.getBufferedEntriesByType(performance_entry_names::kLayoutShift);
  EXPECT_EQ(2u, entries.size());
  shift = static_cast<LayoutShift*>(entries.back().Get());

  EXPECT_FALSE(shift->hadRecentInput());
  EXPECT_GT(shift->value(), 0);
  EXPECT_GT(tracker.Score(), expected_shift);
}

TEST_F(LayoutShiftTrackerSimTest, MultiplePointerDownUps) {
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
      body { margin: 0; height: 1500px; }
      #box {
        left: 0px;
        top: 0px;
        width: 400px;
        height: 600px;
        background: yellow;
        position: absolute;
      }
    </style>
    <div id="box"></div>
    <script>
      box.addEventListener("pointerup", (e) => {
        box.style.top = "100px";
        e.preventDefault();
      });
    </script>
  )HTML");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  WebPointerProperties pointer_properties = WebPointerProperties(
      1 /* PointerId */, WebPointerProperties::PointerType::kTouch,
      WebPointerProperties::Button::kLeft);

  WebPointerEvent event1(WebInputEvent::Type::kPointerDown, pointer_properties,
                         5, 5);
  WebPointerEvent event2(WebInputEvent::Type::kPointerDown, pointer_properties,
                         5, 5);
  WebPointerEvent event3(WebInputEvent::Type::kPointerUp, pointer_properties, 5,
                         5);
  WebPointerEvent event4(WebInputEvent::Type::kPointerUp, pointer_properties, 5,
                         5);

  // Coordinates inside #box.
  event1.SetPositionInWidget(90, 110);
  event2.SetPositionInWidget(90, 110);
  event3.SetPositionInWidget(90, 110);
  event4.SetPositionInWidget(90, 110);

  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event1, ui::LatencyInfo()));

  WindowPerformance& perf = *DOMWindowPerformance::performance(Window());
  auto& tracker = MainFrame().GetFrameView()->GetLayoutShiftTracker();

  EXPECT_EQ(0u,
            perf.getBufferedEntriesByType(performance_entry_names::kLayoutShift)
                .size());
  EXPECT_FLOAT_EQ(0.0, tracker.Score());

  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event2, ui::LatencyInfo()));

  EXPECT_EQ(0u,
            perf.getBufferedEntriesByType(performance_entry_names::kLayoutShift)
                .size());
  EXPECT_FLOAT_EQ(0, tracker.Score());

  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event3, ui::LatencyInfo()));

  // Executes the BeginMainFrame processing steps and calls ReportShift in
  // LayoutShiftTracker to get the latest layout shift score.
  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_EQ(0u,
            perf.getBufferedEntriesByType(performance_entry_names::kLayoutShift)
                .size());
  EXPECT_FLOAT_EQ(0, tracker.Score());

  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event4, ui::LatencyInfo()));

  // region fraction 50%, distance fraction 1/8
  const double expected_shift = 0.5 * 0.125;
  auto entries =
      perf.getBufferedEntriesByType(performance_entry_names::kLayoutShift);
  EXPECT_EQ(1u, entries.size());
  LayoutShift* shift = static_cast<LayoutShift*>(entries.back().Get());

  EXPECT_TRUE(shift->hadRecentInput());
  EXPECT_FLOAT_EQ(expected_shift, shift->value());
  EXPECT_FLOAT_EQ(0.0, tracker.Score());
}

TEST_F(LayoutShiftTrackerTest, StableCompositingChanges) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #outer {
        margin-left: 50px;
        margin-top: 50px;
        width: 200px;
        height: 200px;
        background: #dde;
      }
      .tr {
        will-change: transform;
      }
      .pl {
        position: relative;
        z-index: 0;
        left: 0;
        top: 0;
      }
      #inner {
        display: inline-block;
        width: 100px;
        height: 100px;
        background: #666;
        margin-left: 50px;
        margin-top: 50px;
      }
    </style>
    <div id=outer><div id=inner></div></div>
  )HTML");

  Element* element = GetElementById("outer");
  size_t state = 0;
  auto advance = [this, element, &state]() -> bool {
    //
    // Test each of the following transitions:
    // - add/remove a PaintLayer
    // - add/remove a cc::Layer when there is already a PaintLayer
    // - add/remove a cc::Layer and a PaintLayer together

    static const char* states[] = {"", "pl", "pl tr", "pl", "", "tr", ""};
    element->setAttribute(html_names::kClassAttr, AtomicString(states[state]));
    UpdateAllLifecyclePhasesForTest();
    return ++state < sizeof states / sizeof *states;
  };
  while (advance()) {
  }
  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());
}

TEST_F(LayoutShiftTrackerTest, CompositedOverflowExpansion) {
  SetBodyInnerHTML(R"HTML(
    <style>

    html { will-change: transform; }
    body { height: 2000px; margin: 0; }
    #drop {
      position: absolute;
      width: 1px;
      height: 1px;
      left: -10000px;
      top: -1000px;
    }
    .pl {
      position: relative;
      background: #ddd;
      z-index: 0;
      width: 290px;
      height: 170px;
      left: 25px;
      top: 25px;
    }
    #comp {
      position: relative;
      width: 240px;
      height: 120px;
      background: #efe;
      will-change: transform;
      z-index: 0;
      left: 25px;
      top: 25px;
    }
    .sh {
      top: 515px !important;
    }

    </style>
    <div class="pl">
      <div id="comp"></div>
    </div>
    <div id="drop" style="display: none"></div>
  )HTML");

  Element* drop = GetElementById("drop");
  drop->removeAttribute(html_names::kStyleAttr);
  UpdateAllLifecyclePhasesForTest();

  drop->setAttribute(html_names::kStyleAttr, AtomicString("display: none"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());

  Element* comp = GetElementById("comp");
  comp->setAttribute(html_names::kClassAttr, AtomicString("sh"));
  drop->removeAttribute(html_names::kStyleAttr);
  UpdateAllLifecyclePhasesForTest();

  // old rect (240 * 120) / (800 * 600) = 0.06
  // new rect, 50% clipped by viewport (240 * 60) / (800 * 600) = 0.03
  // final score 0.06 + 0.03 = 0.09 * (490 move distance / 800)
  EXPECT_FLOAT_EQ(0.09 * (490.0 / 800.0), GetLayoutShiftTracker().Score());
}

TEST_F(LayoutShiftTrackerTest, ContentVisibilityAutoFirstPaint) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .auto {
        content-visibility: auto;
        contain-intrinsic-size: 1px;
        width: 100px;
      }
    </style>
    <div id=target class=auto>
      <div style="width: 100px; height: 100px; background: blue"></div>
    </div>
  )HTML");
  auto* target = To<LayoutBox>(GetLayoutObjectByElementId("target"));

  // Because it's on-screen on the first frame, #target renders at size
  // 100x100 on the first frame, via a synchronous second layout, and there is
  // no CLS impact.
  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());
  EXPECT_EQ(PhysicalSize(100, 100), target->Size());
}

TEST_F(LayoutShiftTrackerTest,
       ContentVisibilityAutoOffscreenAfterScrollFirstPaint) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .auto {
        content-visibility: auto;
        contain-intrinsic-size: 1px;
        width: 100px;
      }
    </style>
    <div id=target class=auto style="position: relative; top: 100000px">
      <div style="width: 100px; height: 100px; background: blue"></div>
    </div>
  )HTML");
  auto* target = To<LayoutBox>(GetLayoutObjectByElementId("target"));
  // #target starts offsceen, which doesn't count for CLS.
  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());
  EXPECT_EQ(PhysicalSize(100, 1), target->Size());

  // In the next frame, we scroll it onto the screen, but it still doesn't
  // count for CLS, and its subtree is not yet unskipped, because the
  // intersection observation takes effect on the subsequent frame.
  GetDocument().domWindow()->scrollTo(0, 100000);
  UpdateAllLifecyclePhas
```