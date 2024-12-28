Response:
The user wants a summary of the provided C++ code file `web_input_event_conversion_test.cc`. The summary should cover:
1. **Functionality**: What does the code do?
2. **Relationship to web technologies**: How does it relate to JavaScript, HTML, and CSS?
3. **Logical inferences**: Are there any scenarios with inputs and expected outputs?
4. **Common user/programming errors**: Does it address potential mistakes?

This is the first part of a two-part request. For this part, I need to focus on summarizing the *functionality* of the code based on the included headers and the tests performed.

Looking at the `#include` statements:
- `web_input_event_conversion.h`: This suggests the file tests code responsible for converting between different representations of input events.
- `testing/gtest/include/gtest/gtest.h`:  Indicates this is a unit test file using the Google Test framework.
- Various headers for specific event types (`GestureEvent`, `KeyboardEvent`, `MouseEvent`, `TouchEvent`, `WheelEvent`): This confirms the file tests conversion of these input events.
- Headers related to frames and views (`WebFrame`, `WebSettings`, `WebViewImpl`, `LocalFrame`, `LocalFrameView`, `VisualViewport`):  Implies the conversion process considers the context of the web page's structure and viewport.

The tests themselves seem to focus on:
- **Keyboard event modifier flags**: Checking if modifier keys like keypad, left, and right are correctly identified during conversion.
- **Mouse event type**:  Verifying the conversion process can handle different mouse event types (although one test explicitly shows an undefined type when converting from a `TouchEvent`).
- **Input event scaling**:  Testing how input coordinates are transformed when the page has a zoom level (page scale factor) applied. This includes mouse events, gesture events (scroll, tap, long press), and pointer events.
- **Visual viewport offset**:  Confirming that the position of input events is correctly adjusted when the visible portion of the page is offset.
- **Elastic overscroll**:  Investigating how input event coordinates are affected by the browser's elastic overscroll behavior.

Based on these observations, the core functionality is about testing the correct conversion of various web input events (keyboard, mouse, touch, gesture, pointer) between internal Blink representations and external (likely platform-specific) representations, especially considering factors like page scale and viewport offsets.

Regarding the relationship to web technologies, the code directly deals with how user interactions within a web page (HTML structure) are interpreted and processed by the browser engine. JavaScript event listeners would receive these converted events. CSS can influence the layout and scaling of the page, which in turn affects how these conversions need to be handled.
这是一个名为 `web_input_event_conversion_test.cc` 的 C++ 文件，属于 Chromium Blink 引擎，其主要功能是**测试 web 输入事件的转换逻辑**。

具体来说，这个文件包含了一系列单元测试，用于验证 `blink::WebInputEventConversion` 命名空间下的相关函数是否能正确地将 Blink 内部的事件对象（如 `KeyboardEvent`, `MouseEvent`, `GestureEvent`, `TouchEvent`, `WheelEvent`, `WebPointerEvent`）转换为 `WebInputEvent` 结构体及其子类（如 `WebKeyboardEvent`, `WebMouseEvent`, `WebGestureEvent`, `WebPointerEvent`）。

以下是对其功能的更详细的解释，并尝试关联 JavaScript, HTML, CSS 的功能：

**1. 测试键盘事件转换 (WebKeyboardEventBuilder):**

*   **功能:** 测试将 Blink 内部的 `KeyboardEvent` 对象转换为 `WebKeyboardEvent` 的过程，特别是关注键盘按键位置 (location) 到 `WebInputEvent` 修饰符 (modifiers) 的转换。
*   **与 JavaScript, HTML, CSS 的关系:**
    *   **JavaScript:** 当用户在网页上按下键盘按键时，浏览器会创建一个 `KeyboardEvent` 对象并传递给 JavaScript 事件监听器。这个测试确保了 Blink 引擎能正确识别按下的键是否来自数字键盘或左右两侧的 Shift/Control 键等，并将这些信息编码到 `WebKeyboardEvent` 的修饰符中。JavaScript 可以通过 `event.location` 属性获取这些信息。
    *   **HTML:** HTML 结构定义了用户可以交互的元素（如输入框）。键盘事件通常与这些元素关联。
    *   **CSS:** CSS 可以通过 `:focus` 等伪类来改变获得焦点的元素的外观，而键盘事件通常发生在拥有焦点的元素上。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** 一个 `KeyboardEvent` 对象，其 `location` 属性设置为 `KeyboardEvent::kDomKeyLocationStandard` (标准位置的按键)。
    *   **预期输出:** 转换后的 `WebKeyboardEvent` 对象的 `modifiers` 不包含 `WebInputEvent::kIsKeyPad`, `WebInputEvent::kIsLeft`, `WebInputEvent::kIsRight` 标志。
    *   **假设输入:** 一个 `KeyboardEvent` 对象，其 `location` 属性设置为 `KeyboardEvent::kDomKeyLocationNumpad` (数字键盘上的按键)。
    *   **预期输出:** 转换后的 `WebKeyboardEvent` 对象的 `modifiers` 包含 `WebInputEvent::kIsKeyPad` 标志。
*   **用户或编程常见的使用错误:**
    *   JavaScript 开发者可能会依赖 `event.location` 来判断按键的来源，而 Blink 的转换逻辑需要正确地将这些信息传递下去。如果转换错误，可能会导致 JavaScript 代码无法正确区分例如左右 Shift 键的操作。

**2. 测试鼠标事件转换 (WebMouseEventBuilder):**

*   **功能:** 测试从 `TouchEvent` 创建 `WebMouseEventBuilder` 的情况。在这种特定测试中，它验证了当从非鼠标事件创建 `WebMouseEventBuilder` 时，其事件类型是未定义的。
*   **与 JavaScript, HTML, CSS 的关系:**
    *   **JavaScript:** JavaScript 通过鼠标事件监听器（如 `onclick`, `onmousemove`）处理用户的鼠标交互。
    *   **HTML:** HTML 元素是鼠标事件的目标。
    *   **CSS:** CSS 可以通过伪类（如 `:hover`, `:active`) 来响应鼠标事件改变元素样式。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** 一个 `TouchEvent` 对象。
    *   **预期输出:** 使用该 `TouchEvent` 创建的 `WebMouseEventBuilder` 对象的类型为 `WebInputEvent::Type::kUndefined`。
*   **用户或编程常见的使用错误:**  这个测试更多是关于 Blink 内部逻辑的正确性，而不是直接关于用户的错误。它确保了在不应该生成鼠标事件的情况下，不会意外地生成。

**3. 测试输入事件的缩放 (InputEventsScaling):**

*   **功能:** 测试在页面缩放 (page scale factor) 的情况下，鼠标事件、手势事件和指针事件的坐标转换是否正确。这包括事件在窗口中的位置 (`PositionInWidget`), 在屏幕中的位置 (`PositionInScreen`)，以及手势事件的 delta 值和 tap 区域大小。
*   **与 JavaScript, HTML, CSS 的关系:**
    *   **JavaScript:** JavaScript 事件监听器接收到的事件坐标应该根据页面的缩放进行调整，以对应到页面内容的正确位置。
    *   **HTML:** 页面的内容和布局会受到缩放的影响。
    *   **CSS:**  `zoom` 属性或视口 meta 标签会影响页面的缩放。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**  页面缩放因子为 3，一个 `WebMouseEvent` 对象，其 `PositionInWidget` 为 (15, 15)。
    *   **预期输出:** 转换后的 `WebMouseEvent` 对象的 `PositionInRootFrame` 接近 (5, 5) (15 / 3 = 5)。
    *   **假设输入:** 页面缩放因子为 3，一个 `WebGestureEvent` (类型为 `kGestureTap`) 对象，其 `data.tap.width` 为 15。
    *   **预期输出:** 转换后的 `WebGestureEvent` 对象的 `TapAreaInRootFrame` 的宽度接近 5 (15 / 3 = 5)。
*   **用户或编程常见的使用错误:**
    *   JavaScript 开发者可能会错误地使用未经缩放调整的事件坐标来操作页面元素，导致在缩放页面上出现定位错误。

**4. 测试输入事件的变换 (InputEventsTransform):**

*   **功能:** 类似于 "InputEventsScaling" 测试，但使用了不同的缩放因子 (2) 并且也测试了合并 (coalescing) 多个鼠标事件和指针事件的情况。
*   **与 JavaScript, HTML, CSS 的关系:** 同上。
*   **逻辑推理 (假设输入与输出):** 类似于 "InputEventsScaling" 测试，只是缩放因子不同。对于事件合并，测试了连续的鼠标移动和指针事件是否能正确地合并坐标和 delta 值。
*   **用户或编程常见的使用错误:** 同上。

**5. 测试输入事件的转换 (InputEventsConversions):**

*   **功能:** 测试手势事件到内部表示的转换，特别关注 `TapCount` 的正确性。
*   **与 JavaScript, HTML, CSS 的关系:** 同上。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** 一个 `WebGestureEvent` (类型为 `kGestureTap`) 对象，其 `data.tap.tap_count` 为 1。
    *   **预期输出:** 转换后的 `WebGestureEvent` 对象的 `TapCount()` 返回 1。
*   **用户或编程常见的使用错误:**  JavaScript 开发者可能会依赖 `event.detail` (对于鼠标事件) 或类似属性来判断点击次数，Blink 的转换需要保证这些信息的准确传递。

**6. 测试可视视口偏移 (VisualViewportOffset):**

*   **功能:** 测试当可视视口有偏移时 (用户滚动了页面)，鼠标事件、滚轮事件、手势事件和指针事件的坐标转换是否正确。
*   **与 JavaScript, HTML, CSS 的关系:**
    *   **JavaScript:** JavaScript 需要根据可视视口的偏移来计算事件发生的实际页面位置。
    *   **HTML:**  页面的内容可能超出视口范围，导致需要滚动。
    *   **CSS:** CSS 布局决定了页面的可滚动区域。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** 可视视口的偏移为 (35, 60)，一个 `WebMouseEvent` 对象，其 `PositionInWidget` 为 (10, 10)。
    *   **预期输出:** 转换后的 `WebMouseEvent` 对象的 `PositionInRootFrame` 接近 (5 + 35, 5 + 60) = (40, 65)。
*   **用户或编程常见的使用错误:**
    *   JavaScript 开发者可能会忘记考虑页面的滚动偏移，导致事件处理发生在错误的位置。

**7. 测试弹性拉伸 (ElasticOverscroll):**

*   **功能:** 测试在发生弹性拉伸效果时，鼠标事件的坐标转换是否正确。弹性拉伸是指在页面滚动到边缘时，继续拖动会出现一个临时的超出边界的效果。
*   **与 JavaScript, HTML, CSS 的关系:**
    *   **JavaScript:** JavaScript 可能会需要知道当前是否处于弹性拉伸状态。
    *   **HTML:** 页面的可滚动区域决定了是否可能发生弹性拉伸。
    *   **CSS:** CSS 的 `overflow` 属性会影响滚动行为。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** 弹性拉伸偏移为 (10, -20)，一个 `WebMouseEvent` 对象，其 `PositionInWidget` 为 (10, 50)。
    *   **预期输出:** 转换后的 `WebMouseEvent` 对象的 `PositionInRootFrame` 接近 (10 + 10, 50 - 20) = (20, 30)。
*   **用户或编程常见的使用错误:**  JavaScript 开发者可能需要在弹性拉伸发生时采取特殊的处理逻辑。

**总结这个文件的功能:**

总的来说，`web_input_event_conversion_test.cc` 文件的主要功能是**验证 Blink 引擎中负责将各种平台或内部的输入事件转换为统一的 `WebInputEvent` 及其子类的代码的正确性**。它通过一系列单元测试，覆盖了键盘事件的按键位置识别、鼠标/触摸/手势/指针事件的坐标转换（包括页面缩放和可视视口偏移的情况）、事件合并以及弹性拉伸的影响等关键场景，确保了 Blink 引擎能够准确地理解用户的输入，并将这些信息正确地传递到渲染管道和 JavaScript 环境中。这对于构建稳定可靠的 Web 应用程序至关重要。

Prompt: 
```
这是目录为blink/renderer/core/events/web_input_event_conversion_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/events/web_input_event_conversion.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/web/web_frame.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_keyboard_event_init.h"
#include "third_party/blink/renderer/core/events/gesture_event.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/events/touch_event.h"
#include "third_party/blink/renderer/core/events/wheel_event.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/input/touch.h"
#include "third_party/blink/renderer/core/input/touch_list.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "ui/gfx/geometry/point_conversions.h"
#include "ui/gfx/geometry/size.h"

namespace blink {

namespace {

KeyboardEvent* CreateKeyboardEventWithLocation(
    KeyboardEvent::KeyLocationCode location) {
  KeyboardEventInit* key_event_init = KeyboardEventInit::Create();
  key_event_init->setBubbles(true);
  key_event_init->setCancelable(true);
  key_event_init->setLocation(location);
  return MakeGarbageCollected<KeyboardEvent>(event_type_names::kKeydown,
                                             key_event_init);
}

int GetModifiersForKeyLocationCode(KeyboardEvent::KeyLocationCode location) {
  KeyboardEvent* event = CreateKeyboardEventWithLocation(location);
  WebKeyboardEventBuilder converted_event(*event);
  return converted_event.GetModifiers();
}

void RegisterMockedURL(const std::string& base_url,
                       const std::string& file_name) {
  url_test_helpers::RegisterMockedURLLoadFromBase(
      WebString::FromUTF8(base_url), test::CoreTestDataPath(),
      WebString::FromUTF8(file_name));
}

class WebInputEventConversionTest : public testing::Test {
 private:
  test::TaskEnvironment task_environment;
};

TEST_F(WebInputEventConversionTest, WebKeyboardEventBuilder) {
  // Test key location conversion.
  int modifiers =
      GetModifiersForKeyLocationCode(KeyboardEvent::kDomKeyLocationStandard);
  EXPECT_FALSE(modifiers & WebInputEvent::kIsKeyPad ||
               modifiers & WebInputEvent::kIsLeft ||
               modifiers & WebInputEvent::kIsRight);

  modifiers =
      GetModifiersForKeyLocationCode(KeyboardEvent::kDomKeyLocationLeft);
  EXPECT_TRUE(modifiers & WebInputEvent::kIsLeft);
  EXPECT_FALSE(modifiers & WebInputEvent::kIsKeyPad ||
               modifiers & WebInputEvent::kIsRight);

  modifiers =
      GetModifiersForKeyLocationCode(KeyboardEvent::kDomKeyLocationRight);
  EXPECT_TRUE(modifiers & WebInputEvent::kIsRight);
  EXPECT_FALSE(modifiers & WebInputEvent::kIsKeyPad ||
               modifiers & WebInputEvent::kIsLeft);

  modifiers =
      GetModifiersForKeyLocationCode(KeyboardEvent::kDomKeyLocationNumpad);
  EXPECT_TRUE(modifiers & WebInputEvent::kIsKeyPad);
  EXPECT_FALSE(modifiers & WebInputEvent::kIsLeft ||
               modifiers & WebInputEvent::kIsRight);
}

TEST_F(WebInputEventConversionTest, WebMouseEventBuilder) {
  TouchEvent* event = TouchEvent::Create();
  WebMouseEventBuilder mouse(nullptr, *event);
  EXPECT_EQ(WebInputEvent::Type::kUndefined, mouse.GetType());
}

TEST_F(WebInputEventConversionTest, InputEventsScaling) {
  const std::string base_url("http://www.test1.com/");
  const std::string file_name("fixed_layout.html");

  RegisterMockedURL(base_url, file_name);
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view =
      web_view_helper.InitializeAndLoad(base_url + file_name);
  web_view->GetSettings()->SetViewportEnabled(true);
  int page_width = 640;
  int page_height = 480;
  web_view->MainFrameViewWidget()->Resize(gfx::Size(page_width, page_height));
  web_view->MainFrameViewWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);

  web_view->SetPageScaleFactor(3);

  LocalFrameView* view =
      To<LocalFrame>(web_view->GetPage()->MainFrame())->View();

  {
    WebMouseEvent web_mouse_event(WebInputEvent::Type::kMouseMove,
                                  WebInputEvent::kNoModifiers,
                                  WebInputEvent::GetStaticTimeStampForTests());
    web_mouse_event.SetPositionInWidget(15, 15);
    web_mouse_event.SetPositionInScreen(15, 15);
    web_mouse_event.movement_x = 15;
    web_mouse_event.movement_y = 15;

    WebMouseEvent transformed_event =
        TransformWebMouseEvent(view, web_mouse_event);
    gfx::Point position =
        gfx::ToFlooredPoint(transformed_event.PositionInRootFrame());
    EXPECT_EQ(5, position.x());
    EXPECT_EQ(5, position.y());
    EXPECT_EQ(15, transformed_event.PositionInScreen().x());
    EXPECT_EQ(15, transformed_event.PositionInScreen().y());

    EXPECT_EQ(15, transformed_event.movement_x);
    EXPECT_EQ(15, transformed_event.movement_y);
  }

  {
    WebGestureEvent web_gesture_event(
        WebInputEvent::Type::kGestureScrollUpdate, WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests(),
        WebGestureDevice::kTouchscreen);
    web_gesture_event.SetPositionInWidget(gfx::PointF(15, 18));
    web_gesture_event.SetPositionInScreen(gfx::PointF(20, 22));
    web_gesture_event.data.scroll_update.delta_x = 45;
    web_gesture_event.data.scroll_update.delta_y = 48;
    web_gesture_event.data.scroll_update.inertial_phase =
        WebGestureEvent::InertialPhaseState::kMomentum;

    WebGestureEvent scaled_gesture_event =
        TransformWebGestureEvent(view, web_gesture_event);
    gfx::Point position =
        gfx::ToFlooredPoint(scaled_gesture_event.PositionInRootFrame());
    EXPECT_EQ(5, position.x());
    EXPECT_EQ(6, position.y());
    EXPECT_EQ(20, scaled_gesture_event.PositionInScreen().x());
    EXPECT_EQ(22, scaled_gesture_event.PositionInScreen().y());
    EXPECT_EQ(15, scaled_gesture_event.DeltaXInRootFrame());
    EXPECT_EQ(16, scaled_gesture_event.DeltaYInRootFrame());
    EXPECT_EQ(WebGestureEvent::InertialPhaseState::kMomentum,
              scaled_gesture_event.InertialPhase());
  }

  {
    WebGestureEvent web_gesture_event(
        WebInputEvent::Type::kGestureScrollEnd, WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests(),
        WebGestureDevice::kTouchscreen);
    web_gesture_event.SetPositionInWidget(gfx::PointF(15, 18));
    web_gesture_event.SetPositionInScreen(gfx::PointF(20, 22));

    WebGestureEvent scaled_gesture_event =
        TransformWebGestureEvent(view, web_gesture_event);
    gfx::Point position =
        gfx::ToFlooredPoint(scaled_gesture_event.PositionInRootFrame());
    EXPECT_EQ(5, position.x());
    EXPECT_EQ(6, position.y());
    EXPECT_EQ(20, scaled_gesture_event.PositionInScreen().x());
    EXPECT_EQ(22, scaled_gesture_event.PositionInScreen().y());
    EXPECT_EQ(WebGestureEvent::InertialPhaseState::kUnknownMomentum,
              scaled_gesture_event.InertialPhase());
  }

  {
    WebGestureEvent web_gesture_event(
        WebInputEvent::Type::kGestureTap, WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests(),
        WebGestureDevice::kTouchscreen);
    web_gesture_event.data.tap.width = 15;
    web_gesture_event.data.tap.height = 15;

    WebGestureEvent scaled_gesture_event =
        TransformWebGestureEvent(view, web_gesture_event);
    gfx::Size area =
        gfx::ToFlooredSize(scaled_gesture_event.TapAreaInRootFrame());
    EXPECT_EQ(5, area.width());
    EXPECT_EQ(5, area.height());
  }

  {
    WebGestureEvent web_gesture_event(
        WebInputEvent::Type::kGestureTapUnconfirmed,
        WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests(),
        WebGestureDevice::kTouchscreen);
    web_gesture_event.data.tap.width = 30;
    web_gesture_event.data.tap.height = 30;

    WebGestureEvent scaled_gesture_event =
        TransformWebGestureEvent(view, web_gesture_event);
    gfx::Size area =
        gfx::ToFlooredSize(scaled_gesture_event.TapAreaInRootFrame());
    EXPECT_EQ(10, area.width());
    EXPECT_EQ(10, area.height());
  }

  {
    WebGestureEvent web_gesture_event(
        WebInputEvent::Type::kGestureTapDown, WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests(),
        WebGestureDevice::kTouchscreen);
    web_gesture_event.data.tap_down.width = 9;
    web_gesture_event.data.tap_down.height = 9;

    WebGestureEvent scaled_gesture_event =
        TransformWebGestureEvent(view, web_gesture_event);
    gfx::Size area =
        gfx::ToFlooredSize(scaled_gesture_event.TapAreaInRootFrame());
    EXPECT_EQ(3, area.width());
    EXPECT_EQ(3, area.height());
  }

  {
    WebGestureEvent web_gesture_event(
        WebInputEvent::Type::kGestureShowPress, WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests(),
        WebGestureDevice::kTouchscreen);
    web_gesture_event.data.show_press.width = 18;
    web_gesture_event.data.show_press.height = 18;

    WebGestureEvent scaled_gesture_event =
        TransformWebGestureEvent(view, web_gesture_event);
    gfx::Size area =
        gfx::ToFlooredSize(scaled_gesture_event.TapAreaInRootFrame());
    EXPECT_EQ(6, area.width());
    EXPECT_EQ(6, area.height());
  }

  {
    WebGestureEvent web_gesture_event(
        WebInputEvent::Type::kGestureLongPress, WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests(),
        WebGestureDevice::kTouchscreen);
    web_gesture_event.data.long_press.width = 15;
    web_gesture_event.data.long_press.height = 15;

    WebGestureEvent scaled_gesture_event =
        TransformWebGestureEvent(view, web_gesture_event);
    gfx::Size area =
        gfx::ToFlooredSize(scaled_gesture_event.TapAreaInRootFrame());
    EXPECT_EQ(5, area.width());
    EXPECT_EQ(5, area.height());
  }

  {
    WebGestureEvent web_gesture_event(
        WebInputEvent::Type::kGestureTwoFingerTap, WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests(),
        WebGestureDevice::kTouchscreen);
    web_gesture_event.data.two_finger_tap.first_finger_width = 15;
    web_gesture_event.data.two_finger_tap.first_finger_height = 15;

    WebGestureEvent scaled_gesture_event =
        TransformWebGestureEvent(view, web_gesture_event);
    gfx::Size area =
        gfx::ToFlooredSize(scaled_gesture_event.TapAreaInRootFrame());
    EXPECT_EQ(5, area.width());
    EXPECT_EQ(5, area.height());
  }

  {
    WebPointerEvent web_pointer_event(
        WebInputEvent::Type::kPointerDown,
        WebPointerProperties(1, WebPointerProperties::PointerType::kTouch,
                             WebPointerProperties::Button::kLeft,
                             gfx::PointF(10.8f, 10.5f),
                             gfx::PointF(10.8f, 10.5f), 30, 30),
        6.6f, 9.9f);
    EXPECT_FLOAT_EQ(10.8f, web_pointer_event.PositionInScreen().x());
    EXPECT_FLOAT_EQ(10.5f, web_pointer_event.PositionInScreen().y());
    EXPECT_FLOAT_EQ(10.8f, web_pointer_event.PositionInWidget().x());
    EXPECT_FLOAT_EQ(10.5f, web_pointer_event.PositionInWidget().y());
    EXPECT_FLOAT_EQ(6.6f, web_pointer_event.width);
    EXPECT_FLOAT_EQ(9.9f, web_pointer_event.height);
    EXPECT_EQ(30, web_pointer_event.movement_x);
    EXPECT_EQ(30, web_pointer_event.movement_y);

    WebPointerEvent transformed_event =
        TransformWebPointerEvent(view, web_pointer_event)
            .WebPointerEventInRootFrame();
    EXPECT_FLOAT_EQ(10.8f, transformed_event.PositionInScreen().x());
    EXPECT_FLOAT_EQ(10.5f, transformed_event.PositionInScreen().y());
    EXPECT_FLOAT_EQ(3.6f, transformed_event.PositionInWidget().x());
    EXPECT_FLOAT_EQ(3.5f, transformed_event.PositionInWidget().y());
    EXPECT_FLOAT_EQ(2.2f, transformed_event.width);
    EXPECT_FLOAT_EQ(3.3f, transformed_event.height);
    EXPECT_EQ(30, transformed_event.movement_x);
    EXPECT_EQ(30, transformed_event.movement_y);
  }
}

TEST_F(WebInputEventConversionTest, InputEventsTransform) {
  const std::string base_url("http://www.test2.com/");
  const std::string file_name("fixed_layout.html");

  RegisterMockedURL(base_url, file_name);
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view =
      web_view_helper.InitializeAndLoad(base_url + file_name);
  web_view->GetSettings()->SetViewportEnabled(true);
  int page_width = 640;
  int page_height = 480;
  web_view->MainFrameViewWidget()->Resize(gfx::Size(page_width, page_height));
  web_view->MainFrameViewWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);

  web_view->SetPageScaleFactor(2);

  LocalFrameView* view =
      To<LocalFrame>(web_view->GetPage()->MainFrame())->View();

  {
    WebMouseEvent web_mouse_event(WebInputEvent::Type::kMouseMove,
                                  WebInputEvent::kNoModifiers,
                                  WebInputEvent::GetStaticTimeStampForTests());
    web_mouse_event.SetPositionInWidget(90, 90);
    web_mouse_event.SetPositionInScreen(90, 90);
    web_mouse_event.movement_x = 60;
    web_mouse_event.movement_y = 60;

    WebMouseEvent transformed_event =
        TransformWebMouseEvent(view, web_mouse_event);
    gfx::PointF position = transformed_event.PositionInRootFrame();

    EXPECT_FLOAT_EQ(45, position.x());
    EXPECT_FLOAT_EQ(45, position.y());
    EXPECT_EQ(90, transformed_event.PositionInScreen().x());
    EXPECT_EQ(90, transformed_event.PositionInScreen().y());
    EXPECT_EQ(60, transformed_event.movement_x);
    EXPECT_EQ(60, transformed_event.movement_y);
  }

  {
    auto web_mouse_event1 = std::make_unique<WebMouseEvent>(
        WebInputEvent::Type::kMouseMove, WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests());
    web_mouse_event1->SetPositionInWidget(90, 90);
    web_mouse_event1->SetPositionInScreen(90, 90);
    web_mouse_event1->movement_x = 60;
    web_mouse_event1->movement_y = 60;

    auto web_mouse_event2 = std::make_unique<WebMouseEvent>(*web_mouse_event1);
    web_mouse_event2->SetPositionInWidget(
        web_mouse_event1->PositionInWidget().x(), 120);
    web_mouse_event2->SetPositionInScreen(
        web_mouse_event1->PositionInScreen().x(), 120);
    web_mouse_event2->movement_y = 30;

    std::vector<std::unique_ptr<WebInputEvent>> events;
    events.push_back(std::move(web_mouse_event1));
    events.push_back(std::move(web_mouse_event2));

    Vector<WebMouseEvent> coalescedevents =
        TransformWebMouseEventVector(view, events);
    EXPECT_EQ(events.size(), coalescedevents.size());

    gfx::PointF position = coalescedevents[0].PositionInRootFrame();
    EXPECT_FLOAT_EQ(45, position.x());
    EXPECT_FLOAT_EQ(45, position.y());
    EXPECT_EQ(90, coalescedevents[0].PositionInScreen().x());
    EXPECT_EQ(90, coalescedevents[0].PositionInScreen().y());

    EXPECT_EQ(60, coalescedevents[0].movement_x);
    EXPECT_EQ(60, coalescedevents[0].movement_y);

    position = coalescedevents[1].PositionInRootFrame();
    EXPECT_FLOAT_EQ(45, position.x());
    EXPECT_FLOAT_EQ(60, position.y());
    EXPECT_EQ(90, coalescedevents[1].PositionInScreen().x());
    EXPECT_EQ(120, coalescedevents[1].PositionInScreen().y());

    EXPECT_EQ(60, coalescedevents[1].movement_x);
    EXPECT_EQ(30, coalescedevents[1].movement_y);
  }

  {
    WebGestureEvent web_gesture_event(
        WebInputEvent::Type::kGestureScrollUpdate, WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests(),
        WebGestureDevice::kTouchscreen);
    web_gesture_event.SetPositionInWidget(gfx::PointF(90, 90));
    web_gesture_event.SetPositionInScreen(gfx::PointF(90, 90));
    web_gesture_event.data.scroll_update.delta_x = 60;
    web_gesture_event.data.scroll_update.delta_y = 60;

    WebGestureEvent scaled_gesture_event =
        TransformWebGestureEvent(view, web_gesture_event);
    gfx::PointF position = scaled_gesture_event.PositionInRootFrame();

    EXPECT_FLOAT_EQ(45, position.x());
    EXPECT_FLOAT_EQ(45, position.y());
    EXPECT_EQ(90, scaled_gesture_event.PositionInScreen().x());
    EXPECT_EQ(90, scaled_gesture_event.PositionInScreen().y());
    EXPECT_EQ(30, scaled_gesture_event.DeltaXInRootFrame());
    EXPECT_EQ(30, scaled_gesture_event.DeltaYInRootFrame());
  }

  {
    WebGestureEvent web_gesture_event(
        WebInputEvent::Type::kGestureTap, WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests(),
        WebGestureDevice::kTouchscreen);
    web_gesture_event.data.tap.width = 30;
    web_gesture_event.data.tap.height = 30;

    WebGestureEvent scaled_gesture_event =
        TransformWebGestureEvent(view, web_gesture_event);
    gfx::Size area =
        gfx::ToFlooredSize(scaled_gesture_event.TapAreaInRootFrame());
    EXPECT_EQ(15, area.width());
    EXPECT_EQ(15, area.height());
  }

  {
    WebGestureEvent web_gesture_event(
        WebInputEvent::Type::kGestureTapUnconfirmed,
        WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests(),
        WebGestureDevice::kTouchscreen);
    web_gesture_event.data.tap.width = 30;
    web_gesture_event.data.tap.height = 30;

    WebGestureEvent scaled_gesture_event =
        TransformWebGestureEvent(view, web_gesture_event);
    gfx::Size area =
        gfx::ToFlooredSize(scaled_gesture_event.TapAreaInRootFrame());
    EXPECT_EQ(15, area.width());
    EXPECT_EQ(15, area.height());
  }

  {
    WebGestureEvent web_gesture_event(
        WebInputEvent::Type::kGestureTapDown, WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests(),
        WebGestureDevice::kTouchscreen);
    web_gesture_event.data.tap_down.width = 30;
    web_gesture_event.data.tap_down.height = 30;

    WebGestureEvent scaled_gesture_event =
        TransformWebGestureEvent(view, web_gesture_event);
    gfx::Size area =
        gfx::ToFlooredSize(scaled_gesture_event.TapAreaInRootFrame());
    EXPECT_EQ(15, area.width());
    EXPECT_EQ(15, area.height());
  }

  {
    WebGestureEvent web_gesture_event(
        WebInputEvent::Type::kGestureShowPress, WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests(),
        WebGestureDevice::kTouchscreen);
    web_gesture_event.data.show_press.width = 30;
    web_gesture_event.data.show_press.height = 30;

    WebGestureEvent scaled_gesture_event =
        TransformWebGestureEvent(view, web_gesture_event);
    gfx::Size area =
        gfx::ToFlooredSize(scaled_gesture_event.TapAreaInRootFrame());
    EXPECT_EQ(15, area.width());
    EXPECT_EQ(15, area.height());
  }

  {
    WebGestureEvent web_gesture_event(
        WebInputEvent::Type::kGestureLongPress, WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests(),
        WebGestureDevice::kTouchscreen);
    web_gesture_event.data.long_press.width = 30;
    web_gesture_event.data.long_press.height = 30;

    WebGestureEvent scaled_gesture_event =
        TransformWebGestureEvent(view, web_gesture_event);
    gfx::Size area =
        gfx::ToFlooredSize(scaled_gesture_event.TapAreaInRootFrame());
    EXPECT_EQ(15, area.width());
    EXPECT_EQ(15, area.height());
  }

  {
    WebGestureEvent web_gesture_event(
        WebInputEvent::Type::kGestureTwoFingerTap, WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests(),
        WebGestureDevice::kTouchscreen);
    web_gesture_event.data.two_finger_tap.first_finger_width = 30;
    web_gesture_event.data.two_finger_tap.first_finger_height = 30;

    WebGestureEvent scaled_gesture_event =
        TransformWebGestureEvent(view, web_gesture_event);
    gfx::Size area =
        gfx::ToFlooredSize(scaled_gesture_event.TapAreaInRootFrame());
    EXPECT_EQ(15, area.width());
    EXPECT_EQ(15, area.height());
  }

  {
    WebPointerEvent web_pointer_event(
        WebInputEvent::Type::kPointerDown,
        WebPointerProperties(1, WebPointerProperties::PointerType::kTouch,
                             WebPointerProperties::Button::kLeft,
                             gfx::PointF(90, 90), gfx::PointF(90, 90)),
        30, 30);

    WebPointerEvent transformed_event =
        TransformWebPointerEvent(view, web_pointer_event)
            .WebPointerEventInRootFrame();

    EXPECT_FLOAT_EQ(90, transformed_event.PositionInScreen().x());
    EXPECT_FLOAT_EQ(90, transformed_event.PositionInScreen().y());
    EXPECT_FLOAT_EQ(45, transformed_event.PositionInWidget().x());
    EXPECT_FLOAT_EQ(45, transformed_event.PositionInWidget().y());
    EXPECT_FLOAT_EQ(15, transformed_event.width);
    EXPECT_FLOAT_EQ(15, transformed_event.height);
  }

  {
    auto web_pointer_event1 = std::make_unique<WebPointerEvent>(
        WebInputEvent::Type::kPointerDown,
        WebPointerProperties(1, WebPointerProperties::PointerType::kTouch,
                             WebPointerProperties::Button::kLeft,
                             gfx::PointF(90, 90), gfx::PointF(90, 90)),
        30, 30);

    auto web_pointer_event2 = std::make_unique<WebPointerEvent>(
        WebInputEvent::Type::kPointerDown,
        WebPointerProperties(1, WebPointerProperties::PointerType::kTouch,
                             WebPointerProperties::Button::kLeft,
                             gfx::PointF(120, 90), gfx::PointF(120, 90)),
        60, 30);

    std::vector<std::unique_ptr<WebInputEvent>> events;
    events.push_back(std::move(web_pointer_event1));
    events.push_back(std::move(web_pointer_event2));

    Vector<WebPointerEvent> coalescedevents =
        TransformWebPointerEventVector(view, events);
    EXPECT_EQ(events.size(), coalescedevents.size());

    WebPointerEvent transformed_event =
        coalescedevents[0].WebPointerEventInRootFrame();
    EXPECT_FLOAT_EQ(90, transformed_event.PositionInScreen().x());
    EXPECT_FLOAT_EQ(90, transformed_event.PositionInScreen().y());
    EXPECT_FLOAT_EQ(45, transformed_event.PositionInWidget().x());
    EXPECT_FLOAT_EQ(45, transformed_event.PositionInWidget().y());
    EXPECT_FLOAT_EQ(15, transformed_event.width);
    EXPECT_FLOAT_EQ(15, transformed_event.height);

    transformed_event = coalescedevents[1].WebPointerEventInRootFrame();
    EXPECT_FLOAT_EQ(120, transformed_event.PositionInScreen().x());
    EXPECT_FLOAT_EQ(90, transformed_event.PositionInScreen().y());
    EXPECT_FLOAT_EQ(60, transformed_event.PositionInWidget().x());
    EXPECT_FLOAT_EQ(45, transformed_event.PositionInWidget().y());
    EXPECT_FLOAT_EQ(30, transformed_event.width);
    EXPECT_FLOAT_EQ(15, transformed_event.height);
  }
}

TEST_F(WebInputEventConversionTest, InputEventsConversions) {
  const std::string base_url("http://www.test3.com/");
  const std::string file_name("fixed_layout.html");

  RegisterMockedURL(base_url, file_name);
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view =
      web_view_helper.InitializeAndLoad(base_url + file_name);
  int page_width = 640;
  int page_height = 480;
  web_view->MainFrameViewWidget()->Resize(gfx::Size(page_width, page_height));
  web_view->MainFrameViewWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);

  LocalFrameView* view =
      To<LocalFrame>(web_view->GetPage()->MainFrame())->View();
  {
    WebGestureEvent web_gesture_event(
        WebInputEvent::Type::kGestureTap, WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests(),
        WebGestureDevice::kTouchscreen);
    web_gesture_event.SetPositionInWidget(gfx::PointF(10, 10));
    web_gesture_event.SetPositionInScreen(gfx::PointF(10, 10));
    web_gesture_event.data.tap.tap_count = 1;
    web_gesture_event.data.tap.width = 10;
    web_gesture_event.data.tap.height = 10;

    WebGestureEvent scaled_gesture_event =
        TransformWebGestureEvent(view, web_gesture_event);
    gfx::Point position =
        gfx::ToFlooredPoint(scaled_gesture_event.PositionInRootFrame());
    EXPECT_EQ(10.f, position.x());
    EXPECT_EQ(10.f, position.y());
    EXPECT_EQ(10.f, scaled_gesture_event.PositionInScreen().x());
    EXPECT_EQ(10.f, scaled_gesture_event.PositionInScreen().y());
    EXPECT_EQ(1, scaled_gesture_event.TapCount());
  }
}

TEST_F(WebInputEventConversionTest, VisualViewportOffset) {
  const std::string base_url("http://www.test4.com/");
  const std::string file_name("fixed_layout.html");

  RegisterMockedURL(base_url, file_name);
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view =
      web_view_helper.InitializeAndLoad(base_url + file_name);
  int page_width = 640;
  int page_height = 480;
  web_view->MainFrameViewWidget()->Resize(gfx::Size(page_width, page_height));
  web_view->MainFrameViewWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);

  web_view->SetPageScaleFactor(2);

  gfx::PointF visual_offset(35, 60);
  web_view->GetPage()->GetVisualViewport().SetLocation(visual_offset);

  LocalFrameView* view =
      To<LocalFrame>(web_view->GetPage()->MainFrame())->View();

  {
    WebMouseEvent web_mouse_event(WebInputEvent::Type::kMouseMove,
                                  WebInputEvent::kNoModifiers,
                                  WebInputEvent::GetStaticTimeStampForTests());
    web_mouse_event.SetPositionInWidget(10, 10);
    web_mouse_event.SetPositionInScreen(10, 10);

    WebMouseEvent transformed_mouse_event =
        TransformWebMouseEvent(view, web_mouse_event);
    gfx::Point position =
        gfx::ToFlooredPoint(transformed_mouse_event.PositionInRootFrame());
    EXPECT_EQ(5 + visual_offset.x(), position.x());
    EXPECT_EQ(5 + visual_offset.y(), position.y());
    EXPECT_EQ(10, transformed_mouse_event.PositionInScreen().x());
    EXPECT_EQ(10, transformed_mouse_event.PositionInScreen().y());
  }

  {
    WebMouseWheelEvent web_mouse_wheel_event(
        WebInputEvent::Type::kMouseWheel, WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests());
    web_mouse_wheel_event.SetPositionInWidget(10, 10);
    web_mouse_wheel_event.SetPositionInScreen(10, 10);

    WebMouseWheelEvent scaled_mouse_wheel_event =
        TransformWebMouseWheelEvent(view, web_mouse_wheel_event);
    gfx::Point position =
        gfx::ToFlooredPoint(scaled_mouse_wheel_event.PositionInRootFrame());
    EXPECT_EQ(5 + visual_offset.x(), position.x());
    EXPECT_EQ(5 + visual_offset.y(), position.y());
    EXPECT_EQ(10, scaled_mouse_wheel_event.PositionInScreen().x());
    EXPECT_EQ(10, scaled_mouse_wheel_event.PositionInScreen().y());
  }

  {
    WebGestureEvent web_gesture_event(
        WebInputEvent::Type::kGestureScrollUpdate, WebInputEvent::kNoModifiers,
        WebInputEvent::GetStaticTimeStampForTests(),
        WebGestureDevice::kTouchscreen);
    web_gesture_event.SetPositionInWidget(gfx::PointF(10, 10));
    web_gesture_event.SetPositionInScreen(gfx::PointF(10, 10));

    WebGestureEvent scaled_gesture_event =
        TransformWebGestureEvent(view, web_gesture_event);
    gfx::Point position =
        gfx::ToFlooredPoint(scaled_gesture_event.PositionInRootFrame());
    EXPECT_EQ(5 + visual_offset.x(), position.x());
    EXPECT_EQ(5 + visual_offset.y(), position.y());
    EXPECT_EQ(10, scaled_gesture_event.PositionInScreen().x());
    EXPECT_EQ(10, scaled_gesture_event.PositionInScreen().y());
  }

  {
    WebPointerEvent web_pointer_event(
        WebInputEvent::Type::kPointerDown,
        WebPointerProperties(1, WebPointerProperties::PointerType::kTouch,
                             WebPointerProperties::Button::kLeft,
                             gfx::PointF(10.6f, 10.4f),
                             gfx::PointF(10.6f, 10.4f)),
        10, 10);

    EXPECT_FLOAT_EQ(10.6f, web_pointer_event.PositionInScreen().x());
    EXPECT_FLOAT_EQ(10.4f, web_pointer_event.PositionInScreen().y());
    EXPECT_FLOAT_EQ(10.6f, web_pointer_event.PositionInWidget().x());
    EXPECT_FLOAT_EQ(10.4f, web_pointer_event.PositionInWidget().y());

    WebPointerEvent transformed_event =
        TransformWebPointerEvent(view, web_pointer_event)
            .WebPointerEventInRootFrame();
    EXPECT_FLOAT_EQ(10.6f, transformed_event.PositionInScreen().x());
    EXPECT_FLOAT_EQ(10.4f, transformed_event.PositionInScreen().y());
    EXPECT_FLOAT_EQ(5.3f + visual_offset.x(),
                    transformed_event.PositionInWidget().x());
    EXPECT_FLOAT_EQ(5.2f + visual_offset.y(),
                    transformed_event.PositionInWidget().y());
  }
}

TEST_F(WebInputEventConversionTest, ElasticOverscroll) {
  const std::string base_url("http://www.test5.com/");
  const std::string file_name("fixed_layout.html");

  RegisterMockedURL(base_url, file_name);
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view =
      web_view_helper.InitializeAndLoad(base_url + file_name);
  int page_width = 640;
  int page_height = 480;
  web_view->MainFrameViewWidget()->Resize(gfx::Size(page_width, page_height));
  web_view->MainFrameViewWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);

  LocalFrameView* view =
      To<LocalFrame>(web_view->GetPage()->MainFrame())->View();

  gfx::Vector2dF elastic_overscroll(10, -20);
  web_view->MainFrameViewWidget()->ApplyViewportChangesForTesting(
      {gfx::Vector2dF(), elastic_overscroll, 1.0f, false, 0.0f});

  // Just elastic overscroll.
  {
    WebMouseEvent web_mouse_event(WebInputEvent::Type::kMouseMove,
                                  WebInputEvent::kNoModifiers,
                                  WebInputEvent::GetStaticTimeStampForTests());
    web_mouse_event.SetPositionInWidget(10, 50);
    web_mouse_event.SetPositionInScreen(10, 50);

    WebMouseEvent transformed_mouse_event =
        TransformWebMouseEvent(view, web_mouse_event);
    gfx::Point position =
        gfx::ToFlooredPoint(transformed_mouse_event.PositionInRootFrame());

    EXPECT_EQ(web_mouse_event.PositionInWidget().x() + elastic_overscroll.x(),
              position.x());
    EXPECT_EQ(web_mouse_event.PositionInWidget().y() + elastic_overscroll.y(),
              position.y());
    EXPECT_EQ(web_mouse_event.PositionInScreen().x(),
              transformed_mouse_event.PositionInScreen().x());
    EXPECT_EQ(web_mouse_event.PositionInScreen().y(),
              transformed_mouse_event.PositionInScreen().y());
  }

  // Elastic overscroll and pinch-zoom (this doesn't actually ever happen,
  // but ensure that if it were to, the overscroll would be applied after the
  // pinch-zoom).
  float page_scale = 2;
  web_view->SetPageScaleFactor(page_scale);
  gfx::PointF visual_offset(35, 60);
  web_view->GetPage()->GetVisualViewport().SetLocation(visual_offset);
  {
    WebMouseEvent we
"""


```