Response:
My thought process for analyzing the C++ test file goes like this:

1. **Understand the Goal:** The file name `autoscroll_controller_test.cc` and the presence of `TEST_F` macros immediately tell me this is a unit test file for the `AutoscrollController` class in the Chromium Blink engine. The primary goal is to verify the correct behavior of the autoscroll functionality.

2. **Identify the Core Class Under Test:** The `#include "third_party/blink/renderer/core/page/autoscroll_controller.h"` confirms that the tests are focused on the `AutoscrollController` class.

3. **Examine the Test Fixture:** The `AutoscrollControllerTest` class inherits from `SimTest`. This is a common pattern in Blink unit tests. `SimTest` likely provides a simulated environment for testing Blink components, including a simplified document structure and event handling. The `GetAutoscrollController()` helper function provides easy access to the controller being tested.

4. **Analyze Individual Test Cases:**  I will go through each `TEST_F` block and break down its purpose and logic:

    * **`CrashWhenLayoutStopAnimationBeforeScheduleAnimation`:** The name suggests this test is designed to prevent a crash scenario. It sets up a scrollable element, starts autoscroll, then hides the element. The goal is to ensure that stopping the animation due to the element being hidden doesn't cause issues when the animation frame is processed. The `EXPECT_FALSE(controller.IsAutoscrolling())` confirms the autoscroll is correctly stopped. This relates to the rendering lifecycle and potential race conditions between layout and animation.

    * **`ContinueAutoscrollAfterMouseLeaveEvent`:** This test checks if autoscrolling continues even when the mouse leaves the window during a middle-click autoscroll. The logic involves starting middle-click autoscroll and then simulating a `MouseLeave` event. The `EXPECT_TRUE(controller.IsAutoscrolling())` confirms the intended behavior. This relates to user interaction and ensuring autoscroll isn't prematurely interrupted.

    * **`StopAutoscrollOnResize`:**  This test focuses on the behavior of autoscroll when the window is resized. It starts middle-click autoscroll and then resizes the window to a size where scrolling is no longer needed. It then verifies that autoscroll stops. It also checks that simply resizing back to a scrollable state doesn't restart autoscroll and that a new autoscroll can be initiated. This relates to responsiveness to changes in the viewport and scroll availability.

    * **`AutoscrollIsNotPropagated`:** This test checks how `overscroll-behavior: contain` affects middle-click autoscroll. It sets up nested scrollable elements and starts autoscroll on the inner element. The expectation is that the autoscroll will *not* propagate to the outer scrollable area due to the `overscroll-behavior: contain` style. The assertions about `horizontal_autoscroll_layout_box_` and `vertical_autoscroll_layout_box_` confirm this. This directly relates to CSS properties and their influence on scrolling behavior.

    * **`AutoscrollIsPropagatedInYDirection`:** This test is similar to the previous one but uses `overscroll-behavior-x: contain`. The expectation is that autoscroll *will* propagate vertically but not horizontally. The assertions confirm this. Again, this directly tests the interaction with CSS properties.

    * **`TextSelectionAutoScroll`:** This test focuses on autoscroll during text selection (dragging the mouse to select text). It sets up a scrollable div and simulates a mouse drag. It verifies that the `scroll` event is fired, the scroll position changes, and that autoscroll stops when the mouse button is released. It also checks that a text range is selected. This test is heavily related to user interaction (text selection), JavaScript event handling, and the DOM (creating a text range).

5. **Identify Relationships with Web Technologies:**

    * **JavaScript:** The `TextSelectionAutoScroll` test uses JavaScript to add event listeners and log events. This demonstrates how autoscroll interacts with JavaScript event handling, particularly `pointerdown` and `scroll` events.
    * **HTML:**  All tests use HTML to create the DOM structure, including scrollable elements and content. The structure of the HTML directly affects whether scrolling is possible and how autoscroll behaves.
    * **CSS:** The `CrashWhenLayoutStopAnimationBeforeScheduleAnimation`, `AutoscrollIsNotPropagated`, and `AutoscrollIsPropagatedInYDirection` tests directly use CSS properties like `overflow`, `width`, `height`, and `overscroll-behavior` to control the scrolling behavior being tested.

6. **Infer Logic and Assumptions:**  For each test, I consider the setup, the actions performed, and the expected outcome. This allows me to infer the assumptions made by the test authors about how autoscroll should work in different scenarios. For instance, the `StopAutoscrollOnResize` test assumes that autoscroll should intelligently stop when scrolling is no longer needed.

7. **Consider User/Developer Errors:** I think about common mistakes users or developers might make that could lead to the scenarios being tested. For example, a developer might accidentally hide a scrolling element while autoscroll is active, which is the scenario tested in `CrashWhenLayoutStopAnimationBeforeScheduleAnimation`.

8. **Trace User Actions:** I mentally reconstruct the sequence of user interactions that would lead to the autoscroll functionality being triggered. This typically involves mouse events (mouse down, mouse move with button pressed, middle-click).

By following these steps, I can thoroughly understand the purpose, logic, and implications of the test code, and effectively address the prompt's requirements. The key is to connect the C++ test code to the higher-level concepts of web technologies and user interactions.
这个C++源代码文件 `autoscroll_controller_test.cc` 是 Chromium Blink 渲染引擎的一部分，专门用于测试 `AutoscrollController` 类的功能。 `AutoscrollController` 负责处理页面中的自动滚动行为，例如在用户拖动鼠标进行文本选择或使用中键拖动时发生的滚动。

以下是该文件的功能列表：

**主要功能:**

1. **单元测试 `AutoscrollController`:**  该文件包含多个单元测试用例，用于验证 `AutoscrollController` 的各种功能和边缘情况。
2. **模拟环境搭建:**  使用 `SimTest` 基类创建了一个模拟的 Blink 渲染环境，以便在隔离的环境中测试 `AutoscrollController`，无需完整的浏览器环境。
3. **测试不同类型的自动滚动:** 测试了因鼠标拖动选择文本触发的自动滚动和因中键拖动触发的自动滚动。
4. **测试自动滚动的启动和停止:**  验证了在不同条件下，自动滚动能否正确启动和停止。
5. **测试与布局、事件处理的交互:**  测试了自动滚动与页面布局变化（例如元素隐藏）和鼠标事件处理之间的交互。
6. **测试 `overscroll-behavior` CSS 属性的影响:**  测试了 `overscroll-behavior` CSS 属性如何影响自动滚动的传播行为。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

该测试文件虽然是 C++ 代码，但它直接测试了与 JavaScript, HTML, CSS 交互的功能：

* **HTML:**
    * **创建可滚动元素:** 测试用例中会动态创建包含 `overflow: auto` 或类似属性的 HTML 元素，用于模拟需要自动滚动的场景。例如，在 `CrashWhenLayoutStopAnimationBeforeScheduleAnimation` 测试中，创建了一个 `div` 元素 `#scrollable`，并设置了 `overflow: auto`，使其可以滚动。
    * **元素内容影响滚动范围:** HTML 结构和元素的内容决定了可滚动区域的大小和范围，从而影响自动滚动的效果。

* **CSS:**
    * **`overflow` 属性:**  `AutoscrollController` 的核心功能之一是处理溢出内容的自动滚动，这与 CSS 的 `overflow` 属性密切相关。测试用例通过设置 `overflow: auto`、`overflow: scroll` 等属性来模拟需要自动滚动的场景。
    * **`overscroll-behavior` 属性:**  `AutoscrollIsNotPropagated` 和 `AutoscrollIsPropagatedInYDirection` 这两个测试用例专门测试了 CSS 的 `overscroll-behavior` 属性对中键自动滚动传播的影响。例如，设置 `overscroll-behavior: contain` 可以阻止滚动传播到父元素。
    * **元素尺寸影响滚动条出现:**  CSS 的 `width` 和 `height` 属性以及内容的大小共同决定了是否会出现滚动条，以及滚动条的可滚动范围，这直接影响了自动滚动的效果。

* **JavaScript:**
    * **事件监听和触发:**  虽然测试代码本身是 C++，但它模拟了用户在页面上进行的鼠标操作（例如 `kMouseDown`, `kMouseMove`, `kMouseUp`），这些操作通常会触发 JavaScript 事件。例如，`TextSelectionAutoScroll` 测试用例中，通过 JavaScript 添加了 `pointerdown` 和 `scroll` 事件监听器，用于验证自动滚动过程中是否触发了预期的事件。
    * **DOM 操作:** 测试用例中使用了 Blink 提供的 C++ API 来操作 DOM 结构，例如创建元素、设置属性等，这与 JavaScript 通过 DOM API 操作页面元素是类似的。在 `CrashWhenLayoutStopAnimationBeforeScheduleAnimation` 测试中，使用 `scrollable->SetInlineStyleProperty(CSSPropertyID::kDisplay, CSSValueID::kNone)` 模拟了 JavaScript 动态修改元素样式。
    * **性能 API:** `TextSelectionAutoScroll` 测试用例中使用了 `DOMWindowPerformance` API 来检查自动滚动是否处于激活状态，这与 JavaScript 中使用 `window.performance` API 类似。

**逻辑推理 (假设输入与输出):**

以下是一些测试用例中的逻辑推理示例：

* **`CrashWhenLayoutStopAnimationBeforeScheduleAnimation`:**
    * **假设输入:** 用户在可滚动元素上按下鼠标左键并开始拖动以进行文本选择，触发自动滚动。然后在自动滚动过程中，通过 JavaScript 或其他方式将该可滚动元素的 `display` 属性设置为 `none`。
    * **预期输出:** 自动滚动应该安全停止，而不会导致程序崩溃。`EXPECT_FALSE(controller.IsAutoscrolling())` 验证了这一点。

* **`ContinueAutoscrollAfterMouseLeaveEvent`:**
    * **假设输入:** 用户使用鼠标中键点击并拖动页面进行自动滚动，然后将鼠标移出浏览器窗口。
    * **预期输出:** 自动滚动应该继续进行，因为中键拖动通常不需要鼠标停留在特定元素上。`EXPECT_TRUE(controller.IsAutoscrolling())` 验证了这一点。

* **`StopAutoscrollOnResize`:**
    * **假设输入:** 用户使用鼠标中键点击并拖动一个内容超出视口的页面进行自动滚动，然后调整浏览器窗口大小，使得内容不再超出视口，不再需要滚动。
    * **预期输出:** 自动滚动应该自动停止，因为不再需要滚动。`EXPECT_FALSE(controller.IsAutoscrolling())` 验证了这一点。反之，如果窗口再次缩小，内容超出视口，用户再次尝试中键拖动，则应该可以重新启动自动滚动。

* **`AutoscrollIsNotPropagated`:**
    * **假设输入:**  页面中有一个设置了 `overscroll-behavior: contain` 的可滚动 `div` 元素，其内部也有内容可以滚动。用户在该 `div` 上使用鼠标中键拖动，试图超出其滚动边界。
    * **预期输出:** 自动滚动应该只在该 `div` 内部进行，不会传播到父元素的滚动区域。`EXPECT_TRUE(controller.horizontal_autoscroll_layout_box_)` 和 `EXPECT_FALSE(controller.vertical_autoscroll_layout_box_)` 验证了水平方向的滚动被限制，垂直方向也类似。

* **`TextSelectionAutoScroll`:**
    * **假设输入:** 用户在一个可滚动的 `div` 元素内部按下鼠标左键并拖动，以选择超出当前可见区域的文本。
    * **预期输出:** `AutoscrollController` 会启动自动滚动，使得用户能够选择到超出视野的文本。同时，会触发 `scroll` 事件，并且 `window.performance.isAutoscrollActive` 应该返回 `true`。释放鼠标后，自动滚动停止，`window.performance.isAutoscrollActive` 返回 `false`。

**用户或编程常见的使用错误 (举例说明):**

虽然这个文件是测试代码，但它间接反映了一些用户或开发者可能遇到的问题：

1. **意外停止自动滚动:**  开发者可能会在用户进行自动滚动时，意外地通过 JavaScript 修改了页面的布局或滚动相关的属性，导致自动滚动意外停止或行为异常。例如，在 `CrashWhenLayoutStopAnimationBeforeScheduleAnimation` 测试中，模拟了在自动滚动过程中隐藏滚动元素的情况。
2. **`overscroll-behavior` 理解不当:** 开发者可能不熟悉 `overscroll-behavior` 属性的作用，导致滚动行为与预期不符。例如，期望滚动传播到父元素，但因为设置了 `overscroll-behavior: contain` 而没有发生。
3. **事件处理冲突:**  开发者编写的 JavaScript 代码可能监听了与自动滚动相关的事件（如 `mousedown`, `mousemove`），并且在事件处理函数中执行了某些操作，干扰了 `AutoscrollController` 的正常工作。
4. **性能问题:**  如果页面结构复杂或 JavaScript 代码执行耗时，可能会影响自动滚动的流畅性。

**用户操作如何一步步到达这里 (作为调试线索):**

以下是一些可能导致 `AutoscrollController` 被调用的用户操作序列：

1. **文本选择自动滚动:**
   * 用户在一个内容超出可见区域的元素上按下鼠标左键。
   * 用户按住鼠标左键并拖动鼠标，尝试选择超出当前可见区域的文本。
   * `EventHandler` 接收到 `kMouseDown` 和 `kMouseMove` 事件。
   * `SelectionController` 判断用户正在进行文本选择，并且鼠标移动到了可滚动区域的边界之外。
   * `AutoscrollController::StartAutoscrollForSelection()` 被调用，开始自动滚动。
   * 在后续的帧中，`AutoscrollController::Animate()` 被调用，根据鼠标位置调整滚动偏移量。

2. **中键拖动自动滚动:**
   * 用户在一个页面上按下鼠标中键。
   * 用户按住鼠标中键并拖动鼠标。
   * `EventHandler` 接收到中键的 `kMouseDown` 事件。
   * `AutoscrollController::StartMiddleClickAutoscroll()` 被调用，开始中键自动滚动。
   * 在后续的帧中，`AutoscrollController::Animate()` 被调用，根据鼠标移动的距离和方向调整滚动偏移量。

**调试线索:**

当调试与自动滚动相关的问题时，可以关注以下几点：

* **鼠标事件:**  检查鼠标事件是否被正确触发和处理，特别是 `mousedown`, `mousemove`, `mouseup` 事件。
* **选择状态:**  如果是文本选择自动滚动，检查 `SelectionController` 的状态和选区是否正确。
* **滚动容器:**  确定触发自动滚动的元素及其祖先元素的滚动属性（例如 `overflow`）。
* **`overscroll-behavior`:**  检查相关元素的 `overscroll-behavior` 属性设置。
* **JavaScript 事件监听:**  检查是否有 JavaScript 代码监听了相关的鼠标或滚动事件，并可能干扰了自动滚动的行为。
* **Layout 和 Paint:**  观察页面的布局和绘制过程，特别是当自动滚动发生时，是否有不必要的或性能瓶颈的操作。
* **`AutoscrollController` 的状态:**  通过断点或日志输出，查看 `AutoscrollController` 的内部状态，例如 `IsAutoscrolling()` 的返回值，以及相关的成员变量。

总之，`autoscroll_controller_test.cc` 文件是理解和验证 Blink 引擎自动滚动功能的重要入口，它展示了自动滚动与 HTML、CSS 和 JavaScript 的交互，并为开发者提供了调试相关问题的线索。

Prompt: 
```
这是目录为blink/renderer/core/page/autoscroll_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/page/autoscroll_controller.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/script_evaluation_result.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/editing/dom_selection.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/selection_controller.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/scroll/scroll_animator_base.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"

namespace blink {

class AutoscrollControllerTest : public SimTest {
 public:
  AutoscrollController& GetAutoscrollController() {
    return WebView().GetPage()->GetAutoscrollController();
  }
};

// Ensure Autoscroll not crash by layout called in UpdateSelectionForMouseDrag.
TEST_F(AutoscrollControllerTest,
       CrashWhenLayoutStopAnimationBeforeScheduleAnimation) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  WebView().SetPageBaseBackgroundColor(SK_ColorTRANSPARENT);
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      #scrollable {
        overflow: auto;
        width: 10px;
        height: 10px;
      }
    </style>
    <div id='scrollable'>
      <p id='p'>Some text here for selection autoscroll.</p>
      <p>Some text here for selection autoscroll.</p>
      <p>Some text here for selection autoscroll.</p>
      <p>Some text here for selection autoscroll.</p>
      <p>Some text here for selection autoscroll.</p>
      <p>Some text here for selection autoscroll.</p>
      <p>Some text here for selection autoscroll.</p>
      <p>Some text here for selection autoscroll.</p>
    </div>
  )HTML");

  Compositor().BeginFrame();

  AutoscrollController& controller = GetAutoscrollController();
  Document& document = GetDocument();

  Element* scrollable = document.getElementById(AtomicString("scrollable"));
  DCHECK(scrollable);
  DCHECK(scrollable->GetLayoutObject());

  WebMouseEvent event(WebInputEvent::Type::kMouseDown, gfx::PointF(5, 5),
                      gfx::PointF(5, 5), WebPointerProperties::Button::kLeft, 0,
                      WebInputEvent::Modifiers::kLeftButtonDown,
                      base::TimeTicks::Now());
  event.SetFrameScale(1);

  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(event);

  controller.StartAutoscrollForSelection(scrollable->GetLayoutObject());

  DCHECK(controller.IsAutoscrolling());

  // Hide scrollable here will cause UpdateSelectionForMouseDrag stop animation.
  scrollable->SetInlineStyleProperty(CSSPropertyID::kDisplay,
                                     CSSValueID::kNone);

  // BeginFrame will call AutoscrollController::Animate.
  Compositor().BeginFrame();

  EXPECT_FALSE(controller.IsAutoscrolling());
}

// Ensure that autoscrolling continues when the MouseLeave event is fired.
TEST_F(AutoscrollControllerTest, ContinueAutoscrollAfterMouseLeaveEvent) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      #scrollable {
        width: 820px;
        height: 620px;
      }
    </style>
    <div id='scrollable'></div>
  )HTML");

  Compositor().BeginFrame();

  AutoscrollController& controller = GetAutoscrollController();

  EXPECT_FALSE(controller.IsAutoscrolling());

  LocalFrame* frame = GetDocument().GetFrame();
  Node* document_node = GetDocument().documentElement();
  controller.StartMiddleClickAutoscroll(
      frame, document_node->parentNode()->GetLayoutBox(), gfx::PointF(),
      gfx::PointF());

  EXPECT_TRUE(controller.IsAutoscrolling());

  WebMouseEvent mouse_leave_event(WebInputEvent::Type::kMouseLeave,
                                  WebInputEvent::kNoModifiers,
                                  base::TimeTicks::Now());
  mouse_leave_event.SetFrameScale(1);

  frame->GetEventHandler().HandleMouseLeaveEvent(mouse_leave_event);

  EXPECT_TRUE(controller.IsAutoscrolling());
}

// Ensure that autoscrolling stops when scrolling is no longer available.
TEST_F(AutoscrollControllerTest, StopAutoscrollOnResize) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      #scrollable {
        width: 820px;
        height: 620px;
      }
    </style>
    <div id='scrollable'></div>
  )HTML");

  Compositor().BeginFrame();

  AutoscrollController& controller = GetAutoscrollController();

  EXPECT_FALSE(controller.IsAutoscrolling());

  LocalFrame* frame = GetDocument().GetFrame();
  controller.StartMiddleClickAutoscroll(frame, GetDocument().GetLayoutView(),
                                        gfx::PointF(), gfx::PointF());

  EXPECT_TRUE(controller.IsAutoscrolling());

  // Confirm that it correctly stops autoscrolling when scrolling is no longer
  // possible
  WebView().MainFrameViewWidget()->Resize(gfx::Size(840, 640));

  WebMouseEvent mouse_move_event(WebInputEvent::Type::kMouseMove,
                                 WebInputEvent::kNoModifiers,
                                 base::TimeTicks::Now());

  frame->GetEventHandler().HandleMouseMoveEvent(
      mouse_move_event, Vector<WebMouseEvent>(), Vector<WebMouseEvent>());

  EXPECT_FALSE(controller.IsAutoscrolling());

  // Confirm that autoscrolling doesn't restart when scrolling is available
  // again
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));

  WebMouseEvent mouse_move_event2(WebInputEvent::Type::kMouseMove,
                                  WebInputEvent::kNoModifiers,
                                  base::TimeTicks::Now());

  frame->GetEventHandler().HandleMouseMoveEvent(
      mouse_move_event2, Vector<WebMouseEvent>(), Vector<WebMouseEvent>());

  EXPECT_FALSE(controller.IsAutoscrolling());

  // And finally confirm that autoscrolling can start again.
  controller.StartMiddleClickAutoscroll(frame, GetDocument().GetLayoutView(),
                                        gfx::PointF(), gfx::PointF());

  EXPECT_TRUE(controller.IsAutoscrolling());
}

// Ensure that middle click autoscroll is not propagated in a direction when
// propagation is not allowed.
TEST_F(AutoscrollControllerTest, AutoscrollIsNotPropagated) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <html>
      <head>
        <style>
          #scrollable {
            width: 820px;
            height: 620px;
            overflow: auto;
            overscroll-behavior: contain;
          }
          #inner {
            width: 2500px;
            background-color: aqua;
            height: 100px;
          }
        </style>
      </head>
      <body style='width: 3000px; height: 3000px;'>
        <div id="scrollable">
          <div id="inner"></div>
        </div>
      </body>
    </html>
  )HTML");

  Compositor().BeginFrame();

  AutoscrollController& controller = GetAutoscrollController();

  EXPECT_FALSE(controller.IsAutoscrolling());

  LocalFrame* frame = GetDocument().GetFrame();
  LayoutBox* scrollable =
      GetDocument().getElementById(AtomicString("scrollable"))->GetLayoutBox();

  controller.StartMiddleClickAutoscroll(
      frame, scrollable, gfx::PointF(15.0, 15.0), gfx::PointF(15.0, 15.0));

  EXPECT_TRUE(controller.IsAutoscrolling());
  EXPECT_TRUE(controller.horizontal_autoscroll_layout_box_);
  EXPECT_FALSE(controller.vertical_autoscroll_layout_box_);
}

// Ensure that middle click autoscroll is propagated in a direction when
// overscroll-behavior is set to auto for a that direction.
TEST_F(AutoscrollControllerTest, AutoscrollIsPropagatedInYDirection) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <html>
      <head>
        <style>
          #scrollable {
            width: 820px;
            height: 620px;
            overflow: auto;
            overscroll-behavior-x: contain;
          }
          #inner {
            width: 1000px;
            background-color: aqua;
            height: 100px;
          }
        </style>
      </head>
      <body style='width: 3000px; height: 3000px;'>
        <div id="scrollable">
          <div id="inner"></div>
        </div>
      </body>
    </html>
  )HTML");

  Compositor().BeginFrame();

  AutoscrollController& controller = GetAutoscrollController();

  EXPECT_FALSE(controller.IsAutoscrolling());

  LocalFrame* frame = GetDocument().GetFrame();
  LayoutBox* scrollable =
      GetDocument().getElementById(AtomicString("scrollable"))->GetLayoutBox();

  controller.StartMiddleClickAutoscroll(
      frame, scrollable, gfx::PointF(15.0, 15.0), gfx::PointF(15.0, 15.0));

  EXPECT_TRUE(controller.IsAutoscrolling());
  EXPECT_TRUE(controller.vertical_autoscroll_layout_box_);
  EXPECT_TRUE(controller.horizontal_autoscroll_layout_box_);
}

TEST_F(AutoscrollControllerTest, TextSelectionAutoScroll) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));

  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <style>
      #targetDiv {
          width: 200px;
          height: 200px;
          overflow: scroll;
      }

      #innerDiv {
          width: 4000px;
          height: 4000px;
      }
    </style>
    <body style='margin:0'>
      <div id='targetDiv'>
      <div id='innerDiv'>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
        <p>Test test test test test test...</p>
      </div>
      </div>
      <p id='log'></p>
  </body>
  )HTML");

  script->setInnerHTML(R"HTML(
    let eventCounts = {pointerdown: 0, scroll: 0};
    let target = document.getElementById('targetDiv');
    for (let evt in eventCounts) {
      target.addEventListener(evt, function(e) {
        eventCounts[e.type]++;
        let log = document.getElementById('log');
        log.innerText += " " + e.type;
       });
    }
  )HTML");
  GetDocument().body()->AppendChild(script);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  Compositor().BeginFrame();

  AutoscrollController& controller = GetAutoscrollController();
  Document& document = GetDocument();

  Element* scrollable = document.getElementById(AtomicString("targetDiv"));
  DCHECK(scrollable);
  DCHECK(scrollable->GetLayoutObject());

  WebMouseEvent event(WebInputEvent::Type::kMouseDown, gfx::PointF(10, 10),
                      gfx::PointF(10, 10), WebPointerProperties::Button::kLeft,
                      1, WebInputEvent::Modifiers::kLeftButtonDown,
                      base::TimeTicks::Now());
  event.SetFrameScale(1);
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(event);

  controller.StartAutoscrollForSelection(scrollable->GetLayoutObject());

  DCHECK(controller.IsAutoscrolling());

  WebMouseEvent mouse_event(
      WebInputEvent::Type::kMouseMove, gfx::PointF(50, 150),
      gfx::PointF(50, 150), WebPointerProperties::Button::kLeft, 1,
      WebInputEvent::Modifiers::kLeftButtonDown, base::TimeTicks::Now());
  GetDocument().GetFrame()->GetEventHandler().HandleMouseMoveEvent(
      mouse_event, Vector<WebMouseEvent>(), Vector<WebMouseEvent>());
  ScrollableArea* scrollable_area =
      scrollable->GetLayoutBox()->GetScrollableArea();

  controller.Animate();
  EXPECT_TRUE(controller.AutoscrollInProgress());

  Compositor().BeginFrame();

  mouse_event.SetPositionInWidget(100, 200);
  mouse_event.SetPositionInScreen(100, 200);
  GetDocument().GetFrame()->GetEventHandler().HandleMouseMoveEvent(
      mouse_event, Vector<WebMouseEvent>(), Vector<WebMouseEvent>());

  controller.Animate();
  LocalDOMWindow* current_window = GetDocument().GetFrame()->DomWindow();
  DCHECK(current_window);
  WindowPerformance* window_performance =
      DOMWindowPerformance::performance(*current_window);
  EXPECT_TRUE(controller.AutoscrollInProgress());
  EXPECT_GT(scrollable_area->GetScrollOffset().y(), 0);
  EXPECT_TRUE(window_performance->IsAutoscrollActive());

  Compositor().BeginFrame();
  EXPECT_GT(scrollable_area->GetScrollOffset().y(), 0);
  EXPECT_TRUE(window_performance->IsAutoscrollActive());

  mouse_event.SetType(blink::WebInputEvent::Type::kMouseUp);
  GetDocument().GetFrame()->GetEventHandler().HandleMouseReleaseEvent(
      mouse_event);

  Compositor().BeginFrame();
  EXPECT_FALSE(controller.AutoscrollInProgress());
  EXPECT_FALSE(window_performance->IsAutoscrollActive());

  WebElement element = GetDocument().getElementById(AtomicString("log"));
  EXPECT_EQ("pointerdown scroll", element.InnerHTML().Utf8());

  ASSERT_TRUE(
      GetDocument().GetFrame()->Selection().GetSelectionInDOMTree().IsRange());
  Range* range = CreateRange(EphemeralRange(
      GetDocument().GetFrame()->Selection().GetSelectionInDOMTree().Anchor(),
      GetDocument().GetFrame()->Selection().GetSelectionInDOMTree().Focus()));
  ASSERT_TRUE(range);
  EXPECT_GT(range->GetText().length(), 0u);
}

}  // namespace blink

"""

```