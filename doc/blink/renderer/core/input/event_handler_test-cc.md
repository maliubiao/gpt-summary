Response:
The user wants a summary of the functionality of the provided C++ code file, `event_handler_test.cc`, which is part of the Chromium Blink rendering engine. The summary should also cover:

1. **Relationship to web technologies:** How does this code interact with JavaScript, HTML, and CSS?
2. **Logic and assumptions:** If there's any logical deduction, provide examples with assumed inputs and outputs.
3. **Common user/programming errors:** Identify potential mistakes related to this code.
4. **User interaction leading to this code:** Explain how user actions might trigger the execution of this code.
5. **Overall purpose:** A concise summary of the file's function.

Based on the file content, it's clear this is a **unit test file** for the `EventHandler` class in Blink. Its main purpose is to verify the correct behavior of the event handling logic within the rendering engine. It achieves this by setting up various scenarios (using HTML and CSS), simulating user input events (like mouse clicks, moves, and gestures), and then asserting that the `EventHandler` produces the expected outcomes (like text selection, cursor changes, and drag-and-drop behavior).

Here's a breakdown of the thinking process to address each point:

* **Core Functionality:** The `#include` statements and the class name `EventHandlerTest` strongly suggest this file tests the `EventHandler` class. The tests themselves (`TEST_F`) demonstrate various input scenarios and their expected effects on the DOM, selection, and layout.

* **Relationship to Web Technologies:**
    * **HTML:** The tests manipulate the DOM using `SetHtmlInnerHTML`, which directly involves parsing and rendering HTML content.
    * **CSS:** The tests use CSS (within `<style>` tags) to control the layout and styling of elements, influencing how events are targeted and how selections behave (e.g., `user-select`).
    * **JavaScript:** While this specific test file doesn't directly execute JavaScript, the `EventHandler` class is responsible for dispatching events that can be handled by JavaScript event listeners. The tested functionality ensures these events are correctly routed and processed so that JavaScript can react to them.

* **Logic and Assumptions:**  The tests implicitly contain logical deductions. For instance, the `dragSelectionAfterScroll` test assumes that if a mouse drag starts after a scroll, the selection should correctly encompass the visible content. To illustrate, I can create an example with specific HTML, mouse coordinates, and expected selected text.

* **Common Errors:**  Considering the nature of event handling, common errors might involve:
    * **Incorrect event coordinates:** Simulating a click at the wrong position.
    * **Missing event modifiers:** Forgetting to set the Ctrl or Shift key state.
    * **Incorrect event order:** Sending events in an unexpected sequence.

* **User Interaction as a Debugging Clue:**  To reach this code, a developer would likely be debugging issues related to user input. Tracing the flow of events from the browser's input mechanisms to the Blink renderer and specifically to the `EventHandler` would lead them here. The steps involve a user action, the browser processing it, and then dispatching it to the renderer.

* **Summarization:**  Combining the above points, the file's primary function is to test the `EventHandler` in Blink, ensuring its robustness and correctness in handling various user interactions with web pages.
这是对 Chromium Blink 引擎中 `blink/renderer/core/input/event_handler_test.cc` 文件第一部分的分析和功能归纳。

**文件功能：**

这个文件 `event_handler_test.cc` 是一个 **单元测试文件**，专门用于测试 Blink 渲染引擎中 `EventHandler` 类的功能。`EventHandler` 类负责处理各种用户输入事件，例如鼠标事件、键盘事件、触摸事件和手势事件。

**与 JavaScript, HTML, CSS 的关系：**

这个测试文件通过模拟用户与网页的交互来验证 `EventHandler` 的行为，因此它与 JavaScript、HTML 和 CSS 有着密切的关系：

* **HTML:** 测试用例会加载和操作 HTML 结构。例如，`SetHtmlInnerHTML` 函数用于设置 HTML 内容，模拟网页的渲染。测试会检查在不同的 HTML 结构下，事件是否被正确处理，例如点击链接、选择文本等。
    * **举例说明:**  `TEST_F(EventHandlerTest, multiClickSelectionFromTap)` 测试用例设置了一个包含可编辑 `<span>` 元素的 HTML 结构，然后模拟了多次触摸事件，验证了在可编辑内容上多次点击是否能正确触发文本选择。

* **CSS:** 测试用例会使用 CSS 来控制元素的样式和布局，这会影响事件的触发和处理结果。例如，`user-select` 属性会影响文本是否可选，测试用例会验证 `EventHandler` 是否能正确处理这种情况。
    * **举例说明:** `TEST_F(EventHandlerTest, HitOnUserSelectNoneDoesNotShowIBeam)` 测试用例设置了一个 CSS 样式 `user-select: none`，然后验证当鼠标悬停在该元素上时，是否不会显示文本插入光标（I-Beam）。

* **JavaScript:** 虽然这个测试文件本身不直接执行 JavaScript 代码，但 `EventHandler` 的核心功能是接收并处理浏览器传递的输入事件，这些事件最终会触发 JavaScript 事件监听器。这个测试文件验证了 `EventHandler` 是否能正确地将这些底层事件转换为高层次的交互，从而使得 JavaScript 代码能够响应用户的操作。
    * **潜在关系举例:**  虽然本部分代码没有直接体现，但在 `EventHandler` 的实现中，会判断是否有 JavaScript 监听器注册了特定类型的事件，并调用 JavaScript 代码。此测试确保了事件正确传递给了 JavaScript 能够处理的阶段。

**逻辑推理和假设输入与输出：**

* **假设输入:** 用户在页面上进行拖拽选择操作，起始位置在 `Line 6` 的上方，结束位置在 `Line 2` 的下方。页面已经向下滚动了一部分。
* **测试用例:** `TEST_F(EventHandlerTest, dragSelectionAfterScroll)` 就是在模拟这种情况。
* **逻辑推理:**  测试假设在滚动后进行拖拽选择，`EventHandler` 应该能够正确计算鼠标在文档坐标系中的位置，并据此更新文本选择范围。
* **预期输出:** 选择范围应该包含 "Line 1" 和 "Line 2" 两行文本。

* **假设输入:** 用户在一个可编辑的 `<span>` 元素上进行单次、双次和三次触摸。
* **测试用例:** `TEST_F(EventHandlerTest, multiClickSelectionFromTap)` 就是在模拟这种情况。
* **逻辑推理:**  在可编辑元素上，单次触摸应该将光标定位到触摸点，双次触摸应该选中一个单词，三次触摸应该选中整行或整个元素。
* **预期输出:**
    * 单次触摸后，光标应该定位在 `One` 的起始位置。
    * 双次触摸后，应该选中 "One " 或 "One"（取决于是否启用选择尾随空格）。
    * 三次触摸后，应该选中 "One Two Three"。

**用户或编程常见的使用错误：**

* **事件坐标错误:** 在模拟事件时，如果提供的鼠标或触摸坐标不正确，可能会导致测试覆盖不到某些特定的代码路径，或者导致测试失败。例如，模拟点击事件时，坐标可能落在元素外部，导致事件没有被目标元素接收。
* **事件类型错误:** 错误地使用了事件类型，例如本应该使用 `kMouseUp` 却使用了 `kMouseDown`，会导致测试逻辑出现偏差。
* **缺少必要的事件属性:** 某些事件可能需要特定的属性才能被正确处理，例如鼠标事件的 `button` 属性，手势事件的 `tap_count` 属性。如果这些属性缺失或设置不正确，可能会导致测试失败。
* **HTML 结构设置不当:**  测试用例的 HTML 结构可能没有正确地模拟实际场景，导致测试无法有效地验证 `EventHandler` 的行为。例如，缺少必要的父元素或样式，可能影响事件的冒泡或目标元素的选择。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户操作:** 用户在浏览器中与网页进行交互，例如点击链接、拖拽文本、滚动页面、在输入框中输入文字等。
2. **浏览器事件捕获:** 浏览器的渲染进程（Renderer Process）捕获到用户的这些输入事件（例如，鼠标移动、按下、释放，键盘按下、释放，触摸开始、移动、结束等）。
3. **事件传递到 Blink:** 浏览器将这些底层的输入事件转换为 Blink 引擎能够理解的 WebInputEvent 对象（例如 `WebMouseEvent`, `WebKeyboardEvent`, `WebGestureEvent`）。
4. **事件路由:** 这些 `WebInputEvent` 对象被路由到 `LocalFrame` 的 `EventHandler` 对象。
5. **`EventHandler` 处理:** `EventHandler` 接收到事件后，会根据事件的类型和目标元素，执行相应的处理逻辑。例如，对于 `kMouseDown` 事件，它会进行 hit testing 找到被点击的元素，并根据元素类型和状态（是否可编辑，是否有链接等）采取不同的操作，例如启动文本选择、触发链接跳转等。
6. **测试文件的作用:**  `event_handler_test.cc` 文件中的测试用例模拟了上述步骤 2 和 3，直接创建 `WebInputEvent` 对象并调用 `EventHandler` 的相应处理函数（例如 `HandleMousePressEvent`, `HandleGestureEvent`），来验证 `EventHandler` 在各种场景下的行为是否符合预期。

**第一部分功能归纳：**

这部分代码定义了一些测试基础结构和几个针对 `EventHandler` 特定功能的测试用例：

* **测试基础设施:**  定义了 `EventHandlerTest` 和 `EventHandlerSimTest` 两个测试类，继承自 `PageTestBase` 和 `SimTest`，提供了创建和操作 Blink 渲染环境的辅助方法，例如设置 HTML 内容、创建 Shadow DOM、模拟鼠标和手势事件等。
* **拖拽选择测试 (`dragSelectionAfterScroll`):**  测试在页面滚动后进行鼠标拖拽选择是否能正确地选中目标文本。
* **多点触摸选择测试 (`multiClickSelectionFromTap` 和 `multiClickSelectionFromTapDisabledIfNotEditable`):** 测试在可编辑和不可编辑元素上进行多次触摸是否能正确触发文本选择。
* **拖拽位置测试 (`draggedInlinePositionTest` 和 `draggedSVGImagePositionTest`):**  测试拖拽元素时，拖拽数据传输的位置是否计算正确。
* **光标显示测试 (一系列 `HitOn...ShowsIBeam` 和 `HitOn...DoesNotShowIBeam` 测试):** 测试在不同类型的元素和不同的 `user-select` 样式下，鼠标悬停时是否应该显示文本插入光标。
* **光标类型测试 (一系列 `CursorFor...ResizableTextArea` 和其他光标测试):**  测试鼠标悬停在不同元素上时，光标的类型是否正确，例如链接上的手型光标，可调整大小的文本框上的调整大小光标。

总而言之，这部分代码主要关注 `EventHandler` 在处理鼠标事件、触摸事件和拖拽事件时，与文本选择、光标显示和拖拽位置计算相关的逻辑的正确性。

### 提示词
```
这是目录为blink/renderer/core/input/event_handler_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/input/event_handler.h"

#include <memory>

#include "base/test/scoped_feature_list.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/input/web_gesture_event.h"
#include "third_party/blink/public/common/input/web_keyboard_event.h"
#include "third_party/blink/public/common/input/web_mouse_wheel_event.h"
#include "third_party/blink/public/common/input/web_pointer_event.h"
#include "third_party/blink/public/mojom/input/focus_type.mojom-blink.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/editing/dom_selection.h"
#include "third_party/blink/renderer/core/editing/editing_behavior.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/selection_controller.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/testing/selection_sample.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/page/autoscroll_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scroll_animator_base.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/keyboard_codes.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "ui/base/cursor/cursor.h"
#include "ui/base/cursor/mojom/cursor_type.mojom-blink.h"
#include "ui/base/dragdrop/mojom/drag_drop_types.mojom-blink.h"
#include "ui/events/keycodes/dom/dom_code.h"
#include "ui/events/keycodes/dom/dom_key.h"

namespace blink {

class EventHandlerTest : public PageTestBase {
 protected:
  void SetUp() override;
  void SetHtmlInnerHTML(const char* html_content);
  ShadowRoot* SetShadowContent(const char* shadow_content, const char* host);
};

class EventHandlerSimTest : public SimTest {
 public:
  void InitializeMousePositionAndActivateView(float x, float y) {
    WebMouseEvent mouse_move_event(WebMouseEvent::Type::kMouseMove,
                                   gfx::PointF(x, y), gfx::PointF(x, y),
                                   WebPointerProperties::Button::kNoButton, 0,
                                   WebInputEvent::Modifiers::kNoModifiers,
                                   WebInputEvent::GetStaticTimeStampForTests());
    GetDocument().GetFrame()->GetEventHandler().HandleMouseMoveEvent(
        mouse_move_event, Vector<WebMouseEvent>(), Vector<WebMouseEvent>());

    WebView().MainFrameWidget()->SetFocus(true);
    WebView().SetIsActive(true);
  }

  void InjectScrollFromGestureEvents(cc::ElementId element_id,
                                     float delta_x,
                                     float delta_y) {
    WebGestureEvent gesture_scroll_begin{
        WebInputEvent::Type::kGestureScrollBegin, WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests()};
    gesture_scroll_begin.data.scroll_begin.delta_x_hint = 0;
    gesture_scroll_begin.data.scroll_begin.delta_y_hint = -delta_y;
    gesture_scroll_begin.data.scroll_begin.scrollable_area_element_id =
        element_id.GetInternalValue();
    WebView().MainFrameWidget()->HandleInputEvent(
        WebCoalescedInputEvent(gesture_scroll_begin, ui::LatencyInfo()));

    WebGestureEvent gesture_scroll_update{
        WebInputEvent::Type::kGestureScrollUpdate, WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests()};
    gesture_scroll_update.data.scroll_update.delta_x = delta_x;
    gesture_scroll_update.data.scroll_update.delta_y = -delta_y;
    WebView().MainFrameWidget()->HandleInputEvent(
        WebCoalescedInputEvent(gesture_scroll_update, ui::LatencyInfo()));

    WebGestureEvent gesture_scroll_end{
        WebInputEvent::Type::kGestureScrollEnd, WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests()};
    WebView().MainFrameWidget()->HandleInputEvent(
        WebCoalescedInputEvent(gesture_scroll_end, ui::LatencyInfo()));
  }

  void DispatchElementTargetedGestureScroll(
      const WebGestureEvent& gesture_event) {
    GetWebFrameWidget().DispatchThroughCcInputHandler(gesture_event);
  }
};

WebPointerEvent CreateMinimalTouchPointerEvent(WebInputEvent::Type type,
                                               gfx::PointF position) {
  WebPointerEvent event(
      type,
      WebPointerProperties(1, WebPointerProperties::PointerType::kTouch,
                           WebPointerProperties::Button::kLeft, position,
                           position),
      1, 1);
  event.SetFrameScale(1);
  return event;
}

WebGestureEvent CreateMinimalGestureEvent(WebInputEvent::Type type,
                                          gfx::PointF position) {
  WebGestureEvent event(type, WebInputEvent::kNoModifiers,
                        base::TimeTicks::Now(), WebGestureDevice::kTouchscreen);
  event.SetPositionInWidget(position);
  event.SetPositionInScreen(position);
  event.data.long_press.width = 5;
  event.data.long_press.height = 5;
  event.SetFrameScale(1);
  return event;
}

// TODO(mustaq): We no longer needs any of these Builder classes because the
// fields are publicly modifiable.

class TapEventBuilder : public WebGestureEvent {
 public:
  TapEventBuilder(gfx::PointF position, int tap_count)
      : WebGestureEvent(WebInputEvent::Type::kGestureTap,
                        WebInputEvent::kNoModifiers,
                        base::TimeTicks::Now(),
                        WebGestureDevice::kTouchscreen) {
    SetPositionInWidget(position);
    SetPositionInScreen(position);
    data.tap.tap_count = tap_count;
    data.tap.width = 5;
    data.tap.height = 5;
    frame_scale_ = 1;
  }
};

class TapDownEventBuilder : public WebGestureEvent {
 public:
  explicit TapDownEventBuilder(gfx::PointF position)
      : WebGestureEvent(WebInputEvent::Type::kGestureTapDown,
                        WebInputEvent::kNoModifiers,
                        base::TimeTicks::Now(),
                        WebGestureDevice::kTouchscreen) {
    SetPositionInWidget(position);
    SetPositionInScreen(position);
    data.tap_down.width = 5;
    data.tap_down.height = 5;
    frame_scale_ = 1;
  }
};

class ShowPressEventBuilder : public WebGestureEvent {
 public:
  explicit ShowPressEventBuilder(gfx::PointF position)
      : WebGestureEvent(WebInputEvent::Type::kGestureShowPress,
                        WebInputEvent::kNoModifiers,
                        base::TimeTicks::Now(),
                        WebGestureDevice::kTouchscreen) {
    SetPositionInWidget(position);
    SetPositionInScreen(position);
    data.show_press.width = 5;
    data.show_press.height = 5;
    frame_scale_ = 1;
  }
};

class LongPressEventBuilder : public WebGestureEvent {
 public:
  explicit LongPressEventBuilder(gfx::PointF position)
      : WebGestureEvent(WebInputEvent::Type::kGestureLongPress,
                        WebInputEvent::kNoModifiers,
                        base::TimeTicks::Now(),
                        WebGestureDevice::kTouchscreen) {
    SetPositionInWidget(position);
    SetPositionInScreen(position);
    data.long_press.width = 5;
    data.long_press.height = 5;
    frame_scale_ = 1;
  }
};

class MousePressEventBuilder : public WebMouseEvent {
 public:
  MousePressEventBuilder(gfx::Point position_param,
                         int click_count_param,
                         WebMouseEvent::Button button_param)
      : WebMouseEvent(WebInputEvent::Type::kMouseDown,
                      WebInputEvent::kNoModifiers,
                      base::TimeTicks::Now()) {
    click_count = click_count_param;
    button = button_param;
    SetPositionInWidget(position_param.x(), position_param.y());
    SetPositionInScreen(position_param.x(), position_param.y());
    frame_scale_ = 1;
  }
};

void EventHandlerTest::SetUp() {
  PageTestBase::SetUp(gfx::Size(300, 400));
}

void EventHandlerTest::SetHtmlInnerHTML(const char* html_content) {
  GetDocument().documentElement()->setInnerHTML(String::FromUTF8(html_content));
  UpdateAllLifecyclePhasesForTest();
}

ShadowRoot* EventHandlerTest::SetShadowContent(const char* shadow_content,
                                               const char* host) {
  ShadowRoot* shadow_root =
      EditingTestBase::CreateShadowRootForElementWithIDAndSetInnerHTML(
          GetDocument(), host, shadow_content);
  return shadow_root;
}

TEST_F(EventHandlerTest, dragSelectionAfterScroll) {
  SetHtmlInnerHTML(
      "<style> body { margin: 0px; } .upper { width: 300px; height: 400px; }"
      ".lower { margin: 0px; width: 300px; height: 400px; } .line { display: "
      "block; width: 300px; height: 30px; } </style>"
      "<div class='upper'></div>"
      "<div class='lower'>"
      "<span class='line'>Line 1</span><span class='line'>Line 2</span><span "
      "class='line'>Line 3</span><span class='line'>Line 4</span><span "
      "class='line'>Line 5</span>"
      "<span class='line'>Line 6</span><span class='line'>Line 7</span><span "
      "class='line'>Line 8</span><span class='line'>Line 9</span><span "
      "class='line'>Line 10</span>"
      "</div>");

  LocalFrameView* frame_view = GetDocument().View();
  frame_view->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 400), mojom::blink::ScrollType::kProgrammatic);

  WebMouseEvent mouse_down_event(WebInputEvent::Type::kMouseDown,
                                 gfx::PointF(0, 0), gfx::PointF(100, 200),
                                 WebPointerProperties::Button::kLeft, 1,
                                 WebInputEvent::Modifiers::kLeftButtonDown,
                                 WebInputEvent::GetStaticTimeStampForTests());
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
      mouse_down_event);

  ASSERT_TRUE(GetDocument()
                  .GetFrame()
                  ->GetEventHandler()
                  .GetSelectionController()
                  .MouseDownMayStartSelect());

  WebMouseEvent mouse_move_event(WebInputEvent::Type::kMouseMove,
                                 gfx::PointF(100, 50), gfx::PointF(200, 250),
                                 WebPointerProperties::Button::kLeft, 1,
                                 WebInputEvent::Modifiers::kLeftButtonDown,
                                 WebInputEvent::GetStaticTimeStampForTests());
  GetDocument().GetFrame()->GetEventHandler().HandleMouseMoveEvent(
      mouse_move_event, Vector<WebMouseEvent>(), Vector<WebMouseEvent>());

  GetPage().GetAutoscrollController().Animate();
  GetPage().Animator().ServiceScriptedAnimations(base::TimeTicks::Now());

  WebMouseEvent mouse_up_event(
      WebMouseEvent::Type::kMouseUp, gfx::PointF(100, 50),
      gfx::PointF(200, 250), WebPointerProperties::Button::kLeft, 1,
      WebInputEvent::kNoModifiers, WebInputEvent::GetStaticTimeStampForTests());
  GetDocument().GetFrame()->GetEventHandler().HandleMouseReleaseEvent(
      mouse_up_event);

  ASSERT_FALSE(GetDocument()
                   .GetFrame()
                   ->GetEventHandler()
                   .GetSelectionController()
                   .MouseDownMayStartSelect());

  ASSERT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  Range* range =
      CreateRange(EphemeralRange(Selection().GetSelectionInDOMTree().Anchor(),
                                 Selection().GetSelectionInDOMTree().Focus()));
  ASSERT_TRUE(range);
  EXPECT_EQ("Line 1\nLine 2", range->GetText());
}

TEST_F(EventHandlerTest, multiClickSelectionFromTap) {
  SetHtmlInnerHTML(
      "<style> body { margin: 0px; } .line { display: block; width: 300px; "
      "height: 30px; } </style>"
      "<body contenteditable='true'><span class='line' id='line'>One Two "
      "Three</span></body>");

  Node* line = GetDocument().getElementById(AtomicString("line"))->firstChild();

  TapEventBuilder single_tap_event(gfx::PointF(0, 0), 1);
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      single_tap_event);
  ASSERT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_EQ(Position(line, 0), Selection().GetSelectionInDOMTree().Anchor());

  // Multi-tap events on editable elements should trigger selection, just
  // like multi-click events.
  TapEventBuilder double_tap_event(gfx::PointF(0, 0), 2);
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      double_tap_event);
  ASSERT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_EQ(Position(line, 0), Selection().GetSelectionInDOMTree().Anchor());
  if (GetDocument()
          .GetFrame()
          ->GetEditor()
          .IsSelectTrailingWhitespaceEnabled()) {
    EXPECT_EQ(Position(line, 4), Selection().GetSelectionInDOMTree().Focus());
    EXPECT_EQ("One ", Selection().SelectedText().Utf8());
  } else {
    EXPECT_EQ(Position(line, 3), Selection().GetSelectionInDOMTree().Focus());
    EXPECT_EQ("One", Selection().SelectedText().Utf8());
  }

  TapEventBuilder triple_tap_event(gfx::PointF(0, 0), 3);
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      triple_tap_event);
  ASSERT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_EQ(Position(line, 0), Selection().GetSelectionInDOMTree().Anchor());
  EXPECT_EQ(Position(line, 13), Selection().GetSelectionInDOMTree().Focus());
  EXPECT_EQ("One Two Three", Selection().SelectedText().Utf8());
}

TEST_F(EventHandlerTest, multiClickSelectionFromTapDisabledIfNotEditable) {
  SetHtmlInnerHTML(
      "<style> body { margin: 0px; } .line { display: block; width: 300px; "
      "height: 30px; } </style>"
      "<span class='line' id='line'>One Two Three</span>");

  Node* line = GetDocument().getElementById(AtomicString("line"))->firstChild();

  TapEventBuilder single_tap_event(gfx::PointF(0, 0), 1);
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      single_tap_event);
  ASSERT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_EQ(Position(line, 0), Selection().GetSelectionInDOMTree().Anchor());

  // As the text is readonly, multi-tap events should not trigger selection.
  TapEventBuilder double_tap_event(gfx::PointF(0, 0), 2);
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      double_tap_event);
  ASSERT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_EQ(Position(line, 0), Selection().GetSelectionInDOMTree().Anchor());

  TapEventBuilder triple_tap_event(gfx::PointF(0, 0), 3);
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      triple_tap_event);
  ASSERT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_EQ(Position(line, 0), Selection().GetSelectionInDOMTree().Anchor());
}

TEST_F(EventHandlerTest, draggedInlinePositionTest) {
  SetHtmlInnerHTML(
      "<style>"
      "body { margin: 0px; }"
      ".line { font-family: sans-serif; background: blue; width: 300px; "
      "height: 30px; font-size: 40px; margin-left: 250px; }"
      "</style>"
      "<div style='width: 300px; height: 100px;'>"
      "<span class='line' draggable='true'>abcd</span>"
      "</div>");
  WebMouseEvent mouse_down_event(WebMouseEvent::Type::kMouseDown,
                                 gfx::PointF(262, 29), gfx::PointF(329, 67),
                                 WebPointerProperties::Button::kLeft, 1,
                                 WebInputEvent::Modifiers::kLeftButtonDown,
                                 WebInputEvent::GetStaticTimeStampForTests());
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
      mouse_down_event);

  WebMouseEvent mouse_move_event(WebMouseEvent::Type::kMouseMove,
                                 gfx::PointF(618, 298), gfx::PointF(685, 436),
                                 WebPointerProperties::Button::kLeft, 1,
                                 WebInputEvent::Modifiers::kLeftButtonDown,
                                 WebInputEvent::GetStaticTimeStampForTests());
  GetDocument().GetFrame()->GetEventHandler().HandleMouseMoveEvent(
      mouse_move_event, Vector<WebMouseEvent>(), Vector<WebMouseEvent>());

  EXPECT_EQ(gfx::Point(12, 29), GetDocument()
                                    .GetFrame()
                                    ->GetEventHandler()
                                    .DragDataTransferLocationForTesting());
}

TEST_F(EventHandlerTest, draggedSVGImagePositionTest) {
  SetHtmlInnerHTML(
      "<style>"
      "body { margin: 0px; }"
      "[draggable] {"
      "-webkit-user-select: none; user-select: none; -webkit-user-drag: "
      "element; }"
      "</style>"
      "<div style='width: 300px; height: 100px;'>"
      "<svg width='500' height='500'>"
      "<rect x='100' y='100' width='100px' height='100px' fill='blue' "
      "draggable='true'/>"
      "</svg>"
      "</div>");
  WebMouseEvent mouse_down_event(WebMouseEvent::Type::kMouseDown,
                                 gfx::PointF(145, 144), gfx::PointF(212, 282),
                                 WebPointerProperties::Button::kLeft, 1,
                                 WebInputEvent::Modifiers::kLeftButtonDown,
                                 WebInputEvent::GetStaticTimeStampForTests());
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
      mouse_down_event);

  WebMouseEvent mouse_move_event(WebMouseEvent::Type::kMouseMove,
                                 gfx::PointF(618, 298), gfx::PointF(685, 436),
                                 WebPointerProperties::Button::kLeft, 1,
                                 WebInputEvent::Modifiers::kLeftButtonDown,
                                 WebInputEvent::GetStaticTimeStampForTests());
  GetDocument().GetFrame()->GetEventHandler().HandleMouseMoveEvent(
      mouse_move_event, Vector<WebMouseEvent>(), Vector<WebMouseEvent>());

  EXPECT_EQ(gfx::Point(45, 44), GetDocument()
                                    .GetFrame()
                                    ->GetEventHandler()
                                    .DragDataTransferLocationForTesting());
}

TEST_F(EventHandlerTest, HitOnNothingDoesNotShowIBeam) {
  SetHtmlInnerHTML("");
  HitTestLocation location((PhysicalOffset(10, 10)));
  HitTestResult hit =
      GetDocument().GetFrame()->GetEventHandler().HitTestResultAtLocation(
          location);
  EXPECT_FALSE(
      GetDocument().GetFrame()->GetEventHandler().ShouldShowIBeamForNode(
          GetDocument().body(), hit));
}

TEST_F(EventHandlerTest, HitOnTextShowsIBeam) {
  SetHtmlInnerHTML("blabla");
  Node* const text = GetDocument().body()->firstChild();
  HitTestLocation location(
      text->GetLayoutObject()->AbsoluteBoundingBoxRect().CenterPoint());
  HitTestResult hit =
      GetDocument().GetFrame()->GetEventHandler().HitTestResultAtLocation(
          location);
  EXPECT_TRUE(text->CanStartSelection());
  EXPECT_TRUE(
      GetDocument().GetFrame()->GetEventHandler().ShouldShowIBeamForNode(text,
                                                                         hit));
}

TEST_F(EventHandlerTest, HitOnUserSelectNoneDoesNotShowIBeam) {
  SetHtmlInnerHTML("<span style='user-select: none'>blabla</span>");
  Node* const text = GetDocument().body()->firstChild()->firstChild();
  HitTestLocation location(
      text->GetLayoutObject()->AbsoluteBoundingBoxRect().CenterPoint());
  HitTestResult hit =
      GetDocument().GetFrame()->GetEventHandler().HitTestResultAtLocation(
          location);
  EXPECT_FALSE(text->CanStartSelection());
  EXPECT_FALSE(
      GetDocument().GetFrame()->GetEventHandler().ShouldShowIBeamForNode(text,
                                                                         hit));
}

TEST_F(EventHandlerTest, ShadowChildCanOverrideUserSelectNone) {
  SetHtmlInnerHTML("<p style='user-select: none' id='host'></p>");
  ShadowRoot* const shadow_root = SetShadowContent(
      "<span style='user-select: text' id='bla'>blabla</span>", "host");

  Node* const text =
      shadow_root->getElementById(AtomicString("bla"))->firstChild();
  HitTestLocation location(
      text->GetLayoutObject()->AbsoluteBoundingBoxRect().CenterPoint());
  HitTestResult hit =
      GetDocument().GetFrame()->GetEventHandler().HitTestResultAtLocation(
          location);
  EXPECT_TRUE(text->CanStartSelection());
  EXPECT_TRUE(
      GetDocument().GetFrame()->GetEventHandler().ShouldShowIBeamForNode(text,
                                                                         hit));
}

TEST_F(EventHandlerTest, UserSelectAllCanOverrideUserSelectNone) {
  SetHtmlInnerHTML(
      "<div style='user-select: none'>"
      "<span style='user-select: all'>blabla</span>"
      "</div>");
  Node* const text =
      GetDocument().body()->firstChild()->firstChild()->firstChild();
  HitTestLocation location(
      text->GetLayoutObject()->AbsoluteBoundingBoxRect().CenterPoint());
  HitTestResult hit =
      GetDocument().GetFrame()->GetEventHandler().HitTestResultAtLocation(
          location);
  EXPECT_TRUE(text->CanStartSelection());
  EXPECT_TRUE(
      GetDocument().GetFrame()->GetEventHandler().ShouldShowIBeamForNode(text,
                                                                         hit));
}

TEST_F(EventHandlerTest, UserSelectNoneCanOverrideUserSelectAll) {
  SetHtmlInnerHTML(
      "<div style='user-select: all'>"
      "<span style='user-select: none'>blabla</span>"
      "</div>");
  Node* const text =
      GetDocument().body()->firstChild()->firstChild()->firstChild();
  HitTestLocation location(
      text->GetLayoutObject()->AbsoluteBoundingBoxRect().CenterPoint());
  HitTestResult hit =
      GetDocument().GetFrame()->GetEventHandler().HitTestResultAtLocation(
          location);
  EXPECT_FALSE(text->CanStartSelection());
  EXPECT_FALSE(
      GetDocument().GetFrame()->GetEventHandler().ShouldShowIBeamForNode(text,
                                                                         hit));
}

TEST_F(EventHandlerTest, UserSelectTextCanOverrideUserSelectNone) {
  SetHtmlInnerHTML(
      "<div style='user-select: none'>"
      "<span style='user-select: text'>blabla</span>"
      "</div>");
  Node* const text =
      GetDocument().body()->firstChild()->firstChild()->firstChild();
  HitTestLocation location(
      text->GetLayoutObject()->AbsoluteBoundingBoxRect().CenterPoint());
  HitTestResult hit =
      GetDocument().GetFrame()->GetEventHandler().HitTestResultAtLocation(
          location);
  EXPECT_TRUE(text->CanStartSelection());
  EXPECT_TRUE(
      GetDocument().GetFrame()->GetEventHandler().ShouldShowIBeamForNode(text,
                                                                         hit));
}

TEST_F(EventHandlerTest, UserSelectNoneCanOverrideUserSelectText) {
  SetHtmlInnerHTML(
      "<div style='user-select: text'>"
      "<span style='user-select: none'>blabla</span>"
      "</div>");
  Node* const text = GetDocument().body()->firstChild()->firstChild()->firstChild();
  HitTestLocation location(
      text->GetLayoutObject()->AbsoluteBoundingBoxRect().CenterPoint());
  HitTestResult hit =
      GetDocument().GetFrame()->GetEventHandler().HitTestResultAtLocation(
          location);
  EXPECT_FALSE(text->CanStartSelection());
  EXPECT_FALSE(
      GetDocument().GetFrame()->GetEventHandler().ShouldShowIBeamForNode(text,
                                                                         hit));
}

TEST_F(EventHandlerTest, ShadowChildCanOverrideUserSelectText) {
  SetHtmlInnerHTML("<p style='user-select: text' id='host'></p>");
  ShadowRoot* const shadow_root = SetShadowContent(
      "<span style='user-select: none' id='bla'>blabla</span>", "host");

  Node* const text =
      shadow_root->getElementById(AtomicString("bla"))->firstChild();
  HitTestLocation location(
      text->GetLayoutObject()->AbsoluteBoundingBoxRect().CenterPoint());
  HitTestResult hit =
      GetDocument().GetFrame()->GetEventHandler().HitTestResultAtLocation(
          location);
  EXPECT_FALSE(text->CanStartSelection());
  EXPECT_FALSE(
      GetDocument().GetFrame()->GetEventHandler().ShouldShowIBeamForNode(text,
                                                                         hit));
}

TEST_F(EventHandlerTest, InputFieldsCanStartSelection) {
  SetHtmlInnerHTML("<input value='blabla'>");
  auto* const field = To<HTMLInputElement>(GetDocument().body()->firstChild());
  Element* const text = field->InnerEditorElement();
  HitTestLocation location(
      text->GetLayoutObject()->AbsoluteBoundingBoxRect().CenterPoint());
  HitTestResult hit =
      GetDocument().GetFrame()->GetEventHandler().HitTestResultAtLocation(
          location);
  EXPECT_TRUE(text->CanStartSelection());
  EXPECT_TRUE(
      GetDocument().GetFrame()->GetEventHandler().ShouldShowIBeamForNode(text,
                                                                         hit));
}

TEST_F(EventHandlerTest, ReadOnlyInputDoesNotInheritUserSelect) {
  SetHtmlInnerHTML(
      "<div style='user-select: none'>"
      "<input id='sample' readonly value='blabla'>"
      "</div>");
  auto* const input = To<HTMLInputElement>(
      GetDocument().getElementById(AtomicString("sample")));
  Node* const text = input->InnerEditorElement()->firstChild();

  HitTestLocation location(
      text->GetLayoutObject()->AbsoluteBoundingBoxRect().CenterPoint());
  HitTestResult hit =
      GetDocument().GetFrame()->GetEventHandler().HitTestResultAtLocation(
          location);
  EXPECT_TRUE(text->CanStartSelection());
  EXPECT_TRUE(
      GetDocument().GetFrame()->GetEventHandler().ShouldShowIBeamForNode(text,
                                                                         hit));
}

TEST_F(EventHandlerTest, ImagesCannotStartSelection) {
  SetHtmlInnerHTML("<img>");
  auto* const img = To<Element>(GetDocument().body()->firstChild());
  HitTestLocation location(
      img->GetLayoutObject()->AbsoluteBoundingBoxRect().CenterPoint());
  HitTestResult hit =
      GetDocument().GetFrame()->GetEventHandler().HitTestResultAtLocation(
          location);
  EXPECT_FALSE(img->CanStartSelection());
  EXPECT_FALSE(
      GetDocument().GetFrame()->GetEventHandler().ShouldShowIBeamForNode(img,
                                                                         hit));
}

TEST_F(EventHandlerTest, AnchorTextCannotStartSelection) {
  SetHtmlInnerHTML("<a href='bala'>link text</a>");
  Node* const link = GetDocument().body()->firstChild();
  HitTestLocation location(
      link->GetLayoutObject()->AbsoluteBoundingBoxRect().CenterPoint());
  HitTestResult result =
      GetDocument().GetFrame()->GetEventHandler().HitTestResultAtLocation(
          location);
  Node* const text = link->firstChild();
  EXPECT_FALSE(text->CanStartSelection());
  EXPECT_TRUE(result.IsOverLink());
  // ShouldShowIBeamForNode() returns |cursor: auto|'s value.
  // In https://github.com/w3c/csswg-drafts/issues/1598 it was decided that:
  // a { cursor: auto } /* gives I-beam over links */
  EXPECT_TRUE(
      GetDocument().GetFrame()->GetEventHandler().ShouldShowIBeamForNode(
          text, result));
  EXPECT_EQ(GetDocument()
                .GetFrame()
                ->GetEventHandler()
                .SelectCursor(location, result)
                .value()
                .type(),
            ui::mojom::blink::CursorType::kHand);  // A hand signals ability to
                                                   // navigate.
}

TEST_F(EventHandlerTest, EditableAnchorTextCanStartSelection) {
  SetHtmlInnerHTML("<a contenteditable='true' href='bala'>editable link</a>");
  Node* const link = GetDocument().body()->firstChild();
  HitTestLocation location(
      link->GetLayoutObject()->AbsoluteBoundingBoxRect().CenterPoint());
  HitTestResult result =
      GetDocument().GetFrame()->GetEventHandler().HitTestResultAtLocation(
          location);
  Node* const text = link->firstChild();
  EXPECT_TRUE(text->CanStartSelection());
  EXPECT_TRUE(result.IsOverLink());
  EXPECT_TRUE(
      GetDocument().GetFrame()->GetEventHandler().ShouldShowIBeamForNode(
          text, result));
  EXPECT_EQ(
      GetDocument()
          .GetFrame()
          ->GetEventHandler()
          .SelectCursor(location, result)
          .value()
          .type(),
      ui::mojom::blink::CursorType::kIBeam);  // An I-beam signals editability.
}

TEST_F(EventHandlerTest, CursorForVerticalResizableTextArea) {
  SetHtmlInnerHTML("<textarea style='resize:vertical'>vertical</textarea>");
  Node* const element = GetDocument().body()->firstChild();
  gfx::Point point =
      element->GetLayoutObject()->AbsoluteBoundingBoxRect().bottom_right();
  point.Offset(-5, -5);
  HitTestLocation location(point);
  HitTestResult result =
      GetDocument().GetFrame()->GetEventHandler().HitTestResultAtLocation(
          location);
  EXPECT_EQ(GetDocument()
                .GetFrame()
                ->GetEventHandler()
                .SelectCursor(location, result)
                .value()
                .type(),
            // A north-south resize signals vertical resizability.
            ui::mojom::blink::CursorType::kNorthSouthResize);
}

TEST_F(EventHandlerTest, CursorForHorizontalResizableTextArea) {
  SetHtmlInnerHTML("<textarea style='resize:horizontal'>horizontal</textarea>");
  Node* const element = GetDocument().body()->firstChild();
  gfx::Point point =
      element->GetLayoutObject()->AbsoluteBoundingBoxRect().bottom_right();
  point.Offset(-5, -5);
  HitTestLocation location(point);
  HitTestResult result =
      GetDocument().GetFrame()->GetEventHandler().HitTestResultAtLocation(
          location);
  EXPECT_EQ(GetDocument()
                .GetFrame()
                ->GetEventHandler()
                .SelectCursor(location, result)
                .value()
                .type(),
            // An east-west resize signals horizontal resizability.
            ui::mojom::blink::CursorType::kEastWestResize);
}

TEST_F(EventHandlerTest, CursorForResizableTextArea) {
  SetHtmlInnerHTML("<textarea style='resize:both'>both</textarea>");
  Node* const element = GetDocument().body()->firstChild();
  gfx::Point point =
      element->GetLayoutObject()->AbsoluteBoundingBoxRect().bottom_right();
  point.Offset(-5, -5);
  HitTestLocation location(point);
  HitTestResult result =
      GetDocument().GetFrame()->GetEventHandler().HitTestResultAtLocation(
          location);
  EXPECT_EQ(GetDocument()
                .GetFrame()
                ->GetEventHandler()
                .SelectCursor(location, result)
                .value()
                .type(),
            // An south-east resize signals both horizontal and
            // vertical resizability.
            ui::mojom::blink::CursorType::kSouthEastResize);
}

TEST_F(EventHandlerTest, CursorForRtlResizableTextArea) {
  SetHtmlInnerHTML(
      "<textarea style='resize:both;direction:rtl'>both</textarea>");
  Node* const element = GetDocument().body()->firstChild();
  gfx::Point point =
```