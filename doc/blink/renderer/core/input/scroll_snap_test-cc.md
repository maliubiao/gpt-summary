Response:
The user wants to understand the functionality of the `scroll_snap_test.cc` file in the Chromium Blink engine. I need to analyze the code and explain:

1. **Its purpose**: What does this test file do?
2. **Relationship to web technologies**: How does it relate to JavaScript, HTML, and CSS? Provide examples.
3. **Logic and assumptions**: Are there any logical deductions in the tests?  If so, what are the assumed inputs and expected outputs?
4. **Potential errors**: What common user or programming errors could be related to the tested functionality? Give examples.
5. **Debugging context**: How does a user's interaction lead to this code being relevant during debugging?

**Analysis of the code:**

* **Includes:** The file includes headers related to DOM, frame, HTML elements, input events, layout, painting, and testing. This strongly suggests it's testing the behavior of scroll snapping.
* **`ScrollSnapTest` class:** This class inherits from `SimTest`, indicating it's a simulation-based test.
* **`SetUpForDiv()`:**  This method sets up a basic HTML structure with a scrollable `div` and nested elements, including elements with `scroll-snap-align`.
* **Gesture simulation methods:** `GestureScroll`, `ScrollBegin`, `ScrollUpdate`, `ScrollEnd` simulate user touch gestures for scrolling.
* **`SetInitialScrollOffset()`:** This method programmatically sets the initial scroll position of an element.
* **`TEST_F` macros:** These are Google Test macros defining individual test cases for different scroll snapping scenarios.
* **Test cases:**
    * `ScrollSnapOnX`: Tests snapping behavior when scrolling primarily horizontally.
    * `ScrollSnapOnY`: Tests snapping behavior when scrolling primarily vertically.
    * `ScrollSnapOnBoth`: Tests snapping when scrolling in both directions.
    * `AnimateFlingToArriveAtSnapPoint`: Tests animation behavior after a fling gesture towards a snap point.
    * `SnapWhenBodyViewportDefining`: Tests snapping when the `body` element is the viewport defining element.
    * `SnapWhenHtmlViewportDefining`: Tests snapping when the `html` element is the viewport defining element.
    * `SnapWhenBodyOverflowHtmlViewportDefining`: Tests snapping when both `body` and `html` are scrollable and the `html` is viewport defining.
    * `ResizeDuringGesture`: Tests how resizing the viewport during a scroll gesture affects snapping.

**Plan:**

1. Describe the primary function of the test file: verifying scroll snap behavior.
2. Explain the connection to CSS (`scroll-snap-type`, `scroll-snap-align`).
3. Show how the simulated gestures relate to user interactions.
4. For each test case, explain the setup, the simulated input (gesture), and the expected output (snapped scroll position). This will cover logical reasoning.
5. Provide examples of user errors related to incorrect CSS properties for scroll snapping or misunderstanding how it works.
6. Explain how a user experiencing unexpected scrolling behavior could lead a developer to investigate this test file.
这个文件 `scroll_snap_test.cc` 是 Chromium Blink 引擎中的一个测试文件，它的主要功能是 **测试 CSS Scroll Snap 功能的实现是否正确**。

具体来说，它模拟用户的滚动操作，并断言在应用了 `scroll-snap-type` 和 `scroll-snap-align` 等 CSS 属性后，滚动容器是否会按照预期的方式停止在指定的 "吸附点" 上。

**与 JavaScript, HTML, CSS 的功能关系：**

这个测试文件直接关联着 CSS 的 Scroll Snap 功能。

* **CSS:**  `scroll_snap_type` 和 `scroll-snap-align` 是 CSS 属性，用于控制滚动容器在滚动结束后如何调整滚动位置，使其停靠在特定的元素边缘。测试文件中的 HTML 代码片段就使用了这些属性：
    ```html
    <style>
    #scroller {
      width: 140px;
      height: 160px;
      overflow: scroll;
      scroll-snap-type: both mandatory;
      padding: 0px;
    }
    #area {
      position: relative;
      left: 200px;
      top: 200px;
      width: 100px;
      height: 100px;
      scroll-snap-align: start;
    }
    </style>
    ```
    - `scroll-snap-type: both mandatory;`  指定 `#scroller` 元素在水平和垂直方向上都强制执行滚动吸附。
    - `scroll-snap-align: start;` 指定 `#area` 元素的起始边缘应该作为 `#scroller` 的吸附点。

* **HTML:** 测试文件通过 HTML 构建了需要进行滚动吸附的场景。例如，创建了一个可滚动的容器 `#scroller`，并在其中放置了一个 `#area` 元素作为吸附目标。

* **JavaScript:**  虽然这个测试文件本身是用 C++ 编写的，但它测试的功能是可以通过 JavaScript 来观察和操作的。开发者可以使用 JavaScript 来获取和设置元素的滚动位置 (`scrollLeft`, `scrollTop`)，从而间接地验证滚动吸附的效果。例如，在测试完成后，JavaScript 代码可以用来检查 `#scroller.scrollLeft` 和 `#scroller.scrollTop` 的值是否符合预期。

**逻辑推理与假设输入/输出：**

测试文件中的每个 `TEST_F` 函数都包含特定的逻辑推理，基于不同的假设输入（模拟的滚动操作）来验证预期的输出（最终的滚动位置）。

**示例： `ScrollSnapOnX` 测试**

* **假设输入：**
    1. HTML 结构已设置好，包含一个可滚动的容器 `#scroller` 和一个吸附目标 `#area`。
    2. `#scroller` 的初始滚动位置设置为 `scrollLeft = 50`, `scrollTop = 150`。
    3. 模拟一个水平滚动手势 `GestureScroll(100, 100, -50, 0)`，表示在 (100, 100) 的位置开始一个向左的滚动。

* **逻辑推理：**
    - 由于 `#scroller` 设置了 `scroll-snap-type: both mandatory;`，并且 `#area` 设置了 `scroll-snap-align: start;`，当水平滚动结束后，`#scroller` 应该吸附到 `#area` 的左边缘。
    - `#area` 的 `left` 值为 200px，相对于 `#scroller` 的内容区域。

* **预期输出：**
    - `scroller->scrollLeft()` 的值应该等于 200，即 `#area` 的左边缘位置。
    - `scroller->scrollTop()` 的值应该保持不变，因为是水平滚动，并且垂直方向的吸附点没有被触发，所以仍然是初始值 150。

**示例： `AnimateFlingToArriveAtSnapPoint` 测试**

* **假设输入：**
    1. HTML 结构已设置好。
    2. `#scroller` 的初始滚动位置垂直对齐 `#area`，即 `scrollLeft = 0`, `scrollTop = 200`。
    3. 模拟一个包含惯性滚动的快速水平滚动手势，目标是 `#area` 的左边缘。

* **逻辑推理：**
    - 由于是惯性滚动，滚动结束后会有一个动画过程来平滑地过渡到吸附点。
    - 测试在动画的不同阶段检查滚动位置，最终验证是否能准确到达吸附点。

* **预期输出：**
    - 在动画过程中，`scroller->scrollLeft()` 的值会逐渐接近 200。
    - 动画结束后，`scroller->scrollLeft()` 的值应该等于 200，`scroller->scrollTop()` 保持 200。

**用户或编程常见的使用错误举例：**

1. **忘记设置 `overflow: scroll` 或 `overflow: auto`：** 如果滚动容器没有设置 `overflow` 属性为 `scroll` 或 `auto`，则无法滚动，滚动吸附功能也就不会生效。
    ```html
    <style>
    #scroller {
      width: 140px;
      height: 160px;
      /* 缺少 overflow 属性 */
      scroll-snap-type: both mandatory;
    }
    </style>
    ```
    **用户操作：** 用户尝试滚动该区域，但内容无法滚动。

2. **`scroll-snap-type` 的父元素没有足够的滚动空间：**  如果父元素没有超出其可视区域的内容，即使设置了 `scroll-snap-type`，也无法进行滚动吸附。
    ```html
    <div style="width: 100px; height: 100px; overflow: scroll; scroll-snap-type: y mandatory;">
      <div style="height: 80px; scroll-snap-align: start;">Item 1</div>
    </div>
    ```
    **用户操作：** 用户尝试垂直滚动，但由于内容高度小于容器高度，无法触发吸附。

3. **`scroll-snap-align` 的目标元素大小或位置不合理：** 如果吸附目标元素很小或者完全超出滚动容器的可视范围，可能会导致吸附行为不明显或无法触发。
    ```html
    <div id="scroller" style="width: 200px; height: 200px; overflow: scroll; scroll-snap-type: both mandatory;">
      <div style="width: 500px; height: 500px;">
        <div style="width: 10px; height: 10px; scroll-snap-align: start;">Snap Point</div>
      </div>
    </div>
    ```
    **用户操作：** 用户滚动时，可能会因为吸附目标太小而不容易注意到吸附效果。

4. **在 JavaScript 中直接设置滚动位置，绕过了吸附逻辑：**  如果开发者使用 JavaScript 直接修改 `scrollLeft` 或 `scrollTop`，可能会覆盖浏览器的滚动吸附行为。
    ```javascript
    const scroller = document.getElementById('scroller');
    scroller.scrollLeft = 100; // 直接设置，可能不会触发吸附
    ```
    **用户操作：** 用户可能看到滚动位置被立即改变，而不是平滑地吸附到某个点。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在使用网页时遇到了滚动吸附不生效或行为异常的问题，例如：

1. **用户滑动一个设置了滚动吸附的容器，但滚动并没有停留在预期的位置。**
2. **用户快速滑动（fling）后，滚动动画并没有平滑地过渡到吸附点。**
3. **在调整浏览器窗口大小后，滚动吸附的行为变得不正常。**

作为前端工程师，在接到用户的反馈后，可能会进行以下调试步骤：

1. **检查 CSS 属性：** 首先会检查相关的 CSS 属性 `scroll-snap-type` 和 `scroll-snap-align` 是否正确设置在相应的元素上。
2. **检查 HTML 结构：** 确保滚动容器和吸附目标元素之间的结构关系是正确的。
3. **使用开发者工具：** 使用浏览器的开发者工具（例如 Chrome DevTools）的 Elements 面板，查看元素的样式，以及 Computed 面板中是否正确应用了滚动吸附的属性。
4. **模拟用户操作：** 尝试在本地复现用户的操作，观察滚动行为。
5. **查看浏览器兼容性：** 确认用户使用的浏览器版本是否支持滚动吸附功能。

如果问题仍然存在，开发者可能会深入到浏览器引擎的层面进行调试，这时 `blink/renderer/core/input/scroll_snap_test.cc` 文件就成为了一个重要的参考：

* **理解实现细节：** 通过阅读测试代码，可以了解 Blink 引擎是如何实现滚动吸附的，以及它所考虑的各种场景和边界情况。
* **验证引擎行为：** 可以参考测试用例中的模拟滚动方式和断言逻辑，来验证在特定情况下，引擎的滚动吸附行为是否符合预期。
* **查找相关代码：**  测试文件通常会涉及到相关的核心代码模块，例如 `EventHandler`、`ScrollManager`、`LayoutBox` 等，可以帮助开发者定位到引擎中处理滚动吸附的具体代码。
* **添加新的测试用例：** 如果发现现有的测试用例没有覆盖到用户遇到的特定问题场景，开发者可能会添加新的测试用例来重现和修复 bug。

总而言之，`scroll_snap_test.cc` 文件是理解和调试 Chromium Blink 引擎中滚动吸附功能的关键资源，它可以帮助开发者验证实现的正确性，排查用户遇到的问题，并确保滚动吸附功能在各种场景下都能正常工作。

### 提示词
```
这是目录为blink/renderer/core/input/scroll_snap_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cc/base/features.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/input/scroll_manager.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/sim/sim_compositor.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"

namespace blink {

class ScrollSnapTest : public SimTest {
 protected:
  void SetUpForDiv();
  // The following x, y, hint_x, hint_y, delta_x, delta_y are represents
  // the pointer/finger's location on touch screen.
  void GestureScroll(double x,
                     double y,
                     double delta_x,
                     double delta_y,
                     bool composited = false);
  void ScrollBegin(double x, double y, double hint_x, double hint_y);
  void ScrollUpdate(double x,
                    double y,
                    double delta_x,
                    double delta_y,
                    bool is_in_inertial_phase = false);
  void ScrollEnd(double x, double y, bool is_in_inertial_phase = false);
  void SetInitialScrollOffset(double x, double y);
};

void ScrollSnapTest::SetUpForDiv() {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(400, 400));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    #scroller {
      width: 140px;
      height: 160px;
      overflow: scroll;
      scroll-snap-type: both mandatory;
      padding: 0px;
    }
    #container {
      margin: 0px;
      padding: 0px;
      width: 500px;
      height: 500px;
    }
    #area {
      position: relative;
      left: 200px;
      top: 200px;
      width: 100px;
      height: 100px;
      scroll-snap-align: start;
    }
    </style>
    <div id='scroller'>
      <div id='container'>
        <div id='area'></div>
      </div>
    </div>
  )HTML");

  Compositor().BeginFrame();
}

void ScrollSnapTest::GestureScroll(double x,
                                   double y,
                                   double delta_x,
                                   double delta_y,
                                   bool composited) {
  ScrollBegin(x, y, delta_x, delta_y);
  ScrollUpdate(x, y, delta_x, delta_y);
  ScrollEnd(x + delta_x, y + delta_y);

  // Wait for animation to finish.
  // Pass raster = true to reach LayerTreeHostImpl::UpdateAnimationState,
  // which will set start time and transition to KeyframeModel::RUNNING.
  Compositor().BeginFrame(0.016, true);
  Compositor().BeginFrame(0.3);
}

void ScrollSnapTest::ScrollBegin(double x,
                                 double y,
                                 double hint_x,
                                 double hint_y) {
  WebGestureEvent event(WebInputEvent::Type::kGestureScrollBegin,
                        WebInputEvent::kNoModifiers, base::TimeTicks::Now(),
                        WebGestureDevice::kTouchscreen);
  event.SetPositionInWidget(gfx::PointF(x, y));
  event.SetPositionInScreen(gfx::PointF(x, y));
  event.data.scroll_begin.delta_x_hint = hint_x;
  event.data.scroll_begin.delta_y_hint = hint_y;
  event.data.scroll_begin.pointer_count = 1;
  event.SetFrameScale(1);
  GetWebFrameWidget().DispatchThroughCcInputHandler(event);
}

void ScrollSnapTest::ScrollUpdate(double x,
                                  double y,
                                  double delta_x,
                                  double delta_y,
                                  bool is_in_inertial_phase) {
  WebGestureEvent event(WebInputEvent::Type::kGestureScrollUpdate,
                        WebInputEvent::kNoModifiers, base::TimeTicks::Now(),
                        WebGestureDevice::kTouchscreen);
  event.SetPositionInWidget(gfx::PointF(x, y));
  event.SetPositionInScreen(gfx::PointF(x, y));
  event.data.scroll_update.delta_x = delta_x;
  event.data.scroll_update.delta_y = delta_y;
  if (is_in_inertial_phase) {
    event.data.scroll_update.inertial_phase =
        WebGestureEvent::InertialPhaseState::kMomentum;
    event.SetTimeStamp(Compositor().LastFrameTime());
  }
  event.SetFrameScale(1);
  GetWebFrameWidget().DispatchThroughCcInputHandler(event);
}

void ScrollSnapTest::ScrollEnd(double x, double y, bool is_in_inertial_phase) {
  WebGestureEvent event(WebInputEvent::Type::kGestureScrollEnd,
                        WebInputEvent::kNoModifiers, base::TimeTicks::Now(),
                        WebGestureDevice::kTouchscreen);
  event.SetPositionInWidget(gfx::PointF(x, y));
  event.SetPositionInScreen(gfx::PointF(x, y));
  event.data.scroll_end.inertial_phase =
      is_in_inertial_phase ? WebGestureEvent::InertialPhaseState::kMomentum
                           : WebGestureEvent::InertialPhaseState::kNonMomentum;
  GetWebFrameWidget().DispatchThroughCcInputHandler(event);
}

void ScrollSnapTest::SetInitialScrollOffset(double x, double y) {
  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  scroller->GetLayoutBoxForScrolling()
      ->GetScrollableArea()
      ->ScrollToAbsolutePosition(gfx::PointF(x, y),
                                 mojom::blink::ScrollBehavior::kAuto);
  ASSERT_EQ(scroller->scrollLeft(), x);
  ASSERT_EQ(scroller->scrollTop(), y);
}

TEST_F(ScrollSnapTest, ScrollSnapOnX) {
  SetUpForDiv();
  SetInitialScrollOffset(50, 150);
  Compositor().BeginFrame();

  GestureScroll(100, 100, -50, 0);

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  // Snaps to align the area at start.
  ASSERT_EQ(scroller->scrollLeft(), 200);
  // An x-locked scroll ignores snap points on y.
  ASSERT_EQ(scroller->scrollTop(), 150);
}

TEST_F(ScrollSnapTest, ScrollSnapOnY) {
  SetUpForDiv();
  SetInitialScrollOffset(150, 50);
  Compositor().BeginFrame();

  GestureScroll(100, 100, 0, -50);

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  // A y-locked scroll ignores snap points on x.
  ASSERT_EQ(scroller->scrollLeft(), 150);
  // Snaps to align the area at start.
  ASSERT_EQ(scroller->scrollTop(), 200);
}

TEST_F(ScrollSnapTest, ScrollSnapOnBoth) {
  SetUpForDiv();
  SetInitialScrollOffset(50, 50);
  Compositor().BeginFrame();

  GestureScroll(100, 100, -50, -50);

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  // A scroll gesture that has move in both x and y would snap on both axes.
  ASSERT_EQ(scroller->scrollLeft(), 200);
  ASSERT_EQ(scroller->scrollTop(), 200);
}

TEST_F(ScrollSnapTest, AnimateFlingToArriveAtSnapPoint) {
  SetUpForDiv();
  // Vertically align with the area.
  SetInitialScrollOffset(0, 200);
  Compositor().BeginFrame();

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  ASSERT_EQ(scroller->scrollLeft(), 0);
  ASSERT_EQ(scroller->scrollTop(), 200);

  ScrollBegin(100, 100, -5, 0);
  // Starts with a non-inertial GSU.
  ScrollUpdate(100, 100, -5, 0);
  Compositor().BeginFrame();

  // Fling with an inertial GSU.
  ScrollUpdate(95, 100, -5, 0, true);
  ScrollEnd(90, 100);

  // Animate halfway through the fling.
  Compositor().BeginFrame(0.25);
  ASSERT_GT(scroller->scrollLeft(), 150);
  ASSERT_LT(scroller->scrollLeft(), 180);
  ASSERT_EQ(scroller->scrollTop(), 200);
  // Finish the animation.
  Compositor().BeginFrame(0.6);

  ASSERT_EQ(scroller->scrollLeft(), 200);
  ASSERT_EQ(scroller->scrollTop(), 200);
}

TEST_F(ScrollSnapTest, SnapWhenBodyViewportDefining) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(300, 300));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    html {
      scroll-snap-type: both mandatory;
    }
    body {
      overflow: scroll;
      height: 300px;
      width: 300px;
      margin: 0px;
    }
    #container {
      margin: 0px;
      padding: 0px;
      width: 500px;
      height: 500px;
    }
    #initial-area {
      position: relative;
      left: 0px;
      top: 0px;
      width: 100px;
      height: 100px;
      scroll-snap-align: start;
    }
    #area {
      position: relative;
      left: 200px;
      top: 200px;
      width: 100px;
      height: 100px;
      scroll-snap-align: start;
    }
    </style>
    <div id='container'>
      <div id='initial-area'></div>
      <div id='area'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  // The scroller snaps to the snap area that is closest to the origin (0,0) on
  // the initial layout.
  ASSERT_EQ(Window().scrollX(), 0);
  ASSERT_EQ(Window().scrollY(), 0);

  // The scroll delta needs to be large enough such that the closer snap area
  // will be the one at (200,200).
  // i.e. distance((200,200), (110,110)) <  distance((0,0), (110,110))
  GestureScroll(100, 100, -110, -110, true);

  // Sanity check that body is the viewport defining element
  ASSERT_EQ(GetDocument().body(), GetDocument().ViewportDefiningElement());

  // When body is viewport defining and overflows then any snap points on the
  // body element will be captured by layout view as the snap container.
  ASSERT_EQ(Window().scrollX(), 200);
  ASSERT_EQ(Window().scrollY(), 200);
}

TEST_F(ScrollSnapTest, SnapWhenHtmlViewportDefining) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(300, 300));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    :root {
      overflow: scroll;
      scroll-snap-type: both mandatory;
      height: 300px;
      width: 300px;
    }
    body {
      margin: 0px;
    }
    #container {
      margin: 0px;
      padding: 0px;
      width: 500px;
      height: 500px;
    }
    #initial-area {
      position: relative;
      left: 0px;
      top: 0px;
      width: 100px;
      height: 100px;
      scroll-snap-align: start;
    }
    #area {
      position: relative;
      left: 200px;
      top: 200px;
      width: 100px;
      height: 100px;
      scroll-snap-align: start;
    }
    </style>
    <div id='container'>
      <div id='initial-area'></div>
      <div id='area'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  // The scroller snaps to the snap area that is closest to the origin (0,0) on
  // the initial layout.
  ASSERT_EQ(Window().scrollX(), 0);
  ASSERT_EQ(Window().scrollY(), 0);

  // The scroll delta needs to be large enough such that the closer snap area
  // will be the one at (200,200).
  // i.e. distance((200,200), (110,110)) <  distance((0,0), (110,110))
  GestureScroll(100, 100, -110, -110, true);

  // Sanity check that document element is the viewport defining element
  ASSERT_EQ(GetDocument().documentElement(),
            GetDocument().ViewportDefiningElement());

  // When document is viewport defining and overflows then any snap ponts on the
  // document element will be captured by layout view as snap container.
  ASSERT_EQ(Window().scrollX(), 200);
  ASSERT_EQ(Window().scrollY(), 200);
}

TEST_F(ScrollSnapTest, SnapWhenBodyOverflowHtmlViewportDefining) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(300, 300));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    :root {
      overflow: scroll;
      height: 300px;
      width: 300px;
    }
    body {
      overflow: scroll;
      scroll-snap-type: both mandatory;
      height: 400px;
      width: 400px;
    }
    #container {
      margin: 0px;
      padding: 0px;
      width: 600px;
      height: 600px;
    }
    #initial-area {
      position: relative;
      left: 0px;
      top: 0px;
      width: 100px;
      height: 100px;
      scroll-snap-align: start;
    }
    #area {
      position: relative;
      left: 200px;
      top: 200px;
      width: 100px;
      height: 100px;
      scroll-snap-align: start;
    }
    </style>
    <div id='container'>
      <div id='initial-area'></div>
      <div id='area'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  // The scroller snaps to the snap area that is closest to the origin (0,0) on
  // the initial layout.
  Element* body = GetDocument().body();
  ASSERT_EQ(body->scrollLeft(), 0);
  ASSERT_EQ(body->scrollTop(), 0);

  // The scroll delta needs to be large enough such that the closer snap area
  // will be the one at (200,200).
  // i.e. distance((200,200), (110,110)) <  distance((0,0), (110,110))
  GestureScroll(100, 100, -110, -110);

  // Sanity check that document element is the viewport defining element
  ASSERT_EQ(GetDocument().documentElement(),
            GetDocument().ViewportDefiningElement());

  // When body and document elements are both scrollable then body element
  // should capture snap points defined on it as opposed to layout view.
  ASSERT_EQ(body->scrollLeft(), 200);
  ASSERT_EQ(body->scrollTop(), 200);
}

TEST_F(ScrollSnapTest, ResizeDuringGesture) {
  ResizeView(gfx::Size(400, 400));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    ::-webkit-scrollbar { display: none; }
    html { scroll-snap-type: both mandatory; }
    body { margin: 0; width: 600px; height: 600px; }
    #a1 { position: absolute; left: 0; top: 0; background: blue;
          width: 100px; height: 100px; scroll-snap-align: start; }
    #a2 { position: absolute; left: 400px; top: 400px; background: blue;
          width: 100px; height: 100px; scroll-snap-align: end; }
    </style>
    <div id='a1'></div>
    <div id='a2'></div>
  )HTML");

  Compositor().BeginFrame();

  Element* viewport = GetDocument().scrollingElement();
  ASSERT_EQ(viewport->scrollLeft(), 0);
  ASSERT_EQ(viewport->scrollTop(), 0);

  ScrollBegin(10, 10, -75, -75);
  ScrollUpdate(10, 10, -75, -75);

  Compositor().BeginFrame();

  ASSERT_EQ(viewport->scrollLeft(), 75);
  ASSERT_EQ(viewport->scrollTop(), 75);

  ResizeView(gfx::Size(450, 450));
  Compositor().BeginFrame();

  // After mid-gesture resize, we should still be at 75.
  ASSERT_EQ(viewport->scrollLeft(), 75);
  ASSERT_EQ(viewport->scrollTop(), 75);

  ScrollEnd(10, 10);

  // The scrollend is deferred for the snap animation in cc::InputHandler; wait
  // for the animation to finish.  (We pss raster = true to ensure that we call
  // LayerTreeHostImpl::UpdateAnimationState, which will set start time and
  // transition to KeyframeModel::RUNNING.)
  Compositor().BeginFrame(0.016, true);
  Compositor().BeginFrame(0.3);

  // Once the snap animation is finished, we run a deferred SnapAfterLayout.
  ASSERT_EQ(viewport->scrollLeft(), 50);
  ASSERT_EQ(viewport->scrollTop(), 50);
}

}  // namespace blink
```