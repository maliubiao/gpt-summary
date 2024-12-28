Response:
My thought process for analyzing the C++ code and generating the summary involved several steps:

1. **Understanding the Core Purpose:** I first read the file path and the initial comments to grasp the main function. The name "web_input_event_conversion.cc" and the comments about converting between different input event types strongly suggested its role: transforming low-level browser input events into a format usable within the Blink rendering engine.

2. **Identifying Key Data Structures and Classes:** I scanned the `#include` directives to identify the core classes involved. This revealed:
    * `WebInputEvent`, `WebMouseEvent`, `WebMouseWheelEvent`, `WebGestureEvent`, `WebKeyboardEvent`, `WebPointerEvent`: These are clearly the target output format, representing different kinds of web input events.
    * `MouseEvent`, `TouchEvent`, `KeyboardEvent`: These are the input sources, representing the platform-specific event data.
    * `LocalFrameView`, `LayoutObject`, `Page`, `ChromeClient`, `VisualViewport`: These classes suggest the context in which the conversion happens – within a web page's frame and layout.

3. **Analyzing the Functions:** I examined each function individually, focusing on its input parameters, actions, and return value. I looked for patterns and relationships between the functions.
    * **`FrameScale` and `FrameTranslation`:** These utility functions clearly calculate scaling and translation factors related to the frame view. This hints at handling zooming or scrolling.
    * **`UpdateWebMouseEventFromCoreMouseEvent`:** This function transfers common data (timestamp, modifiers, screen position) from a `MouseEvent` to a `WebMouseEvent`. The use of `AbsoluteToLocalPoint` points to coordinate system transformations.
    * **`ToWebInputEventModifierFrom`:**  This small function translates `WebMouseEvent::Button` enums to `WebInputEvent` modifier flags, suggesting the management of mouse button states.
    * **`TransformWebPointerEvent` (the simpler one):** This function directly applies the frame scale and translation, confirming the earlier observation.
    * **`TransformWebMouseEvent`, `TransformWebMouseWheelEvent`, `TransformWebGestureEvent`, `TransformWebPointerEvent` (the versions taking `LocalFrameView*`):**  These functions use `FrameScale` and `FrameTranslation` to apply the necessary transformations. This solidifies the understanding that these functions adapt events to the coordinate system of a specific frame.
    * **`WebMouseEventBuilder`, `WebKeyboardEventBuilder`:** These classes act as constructors or factories for `WebMouseEvent` and `WebKeyboardEvent`, taking the native event types as input and populating the `WebInputEvent` structure. The conditional logic within `WebMouseEventBuilder` (handling `touchstart`, `touchmove`, `touchend` to create synthetic mouse events) is a crucial detail.
    * **`TransformWebMouseEventVector`, `TransformWebPointerEventVector`:**  These functions handle batches of events, applying the transformations to each element.

4. **Identifying Relationships to Web Technologies:** Based on the identified input and output types and the context (Blink rendering engine), I could connect the functionality to JavaScript, HTML, and CSS:
    * **JavaScript:** JavaScript event listeners react to the `WebInputEvent` types *after* this conversion. The transformations ensure the coordinates and other properties are accurate within the context of the rendered page.
    * **HTML:** The structure of the HTML document creates the frame hierarchy that necessitates the coordinate transformations. The target of the event (determined by the layout) is crucial for deciding which frame's transformations to apply.
    * **CSS:** CSS styling, particularly transforms and viewport properties, influences the scaling and translation factors calculated by `FrameScale` and `FrameTranslation`.

5. **Inferring Logical Reasoning and Examples:** I considered the purpose of the transformations. The core reasoning is to convert device-specific, low-level input events into a standardized, browser-internal representation, accounting for factors like scrolling, zooming, and iframes. This led to the examples of:
    * **Scrolling:** Mouse wheel events needing translation.
    * **Zooming:** All events needing scaling.
    * **IFrames:** The need to adjust coordinates based on the iframe's position and scaling within the parent document.
    * **Touch Emulation:** The `WebMouseEventBuilder` handling touch events to generate mouse events for legacy plugins.

6. **Considering Potential User/Programming Errors:** I thought about how developers or the browser itself might misuse or encounter issues with this conversion process. This led to examples like:
    * Incorrectly assuming screen coordinates without considering frame transformations.
    * Developers of embedded content needing to be aware of the scaling and translation.
    * Potential for bugs in the transformation logic leading to incorrect event handling.

7. **Structuring the Output:** Finally, I organized my findings into a clear and structured format, addressing the prompt's specific requests: listing functionalities, explaining relationships with web technologies with examples, illustrating logical reasoning with input/output scenarios, and highlighting common errors. I used clear headings and bullet points for readability.

By following these steps, I was able to dissect the provided C++ code and generate a comprehensive explanation of its purpose and implications within the context of a web browser. The key was to move from the specific code details to the broader functional role and its connections to the wider web development ecosystem.
这个文件 `blink/renderer/core/events/web_input_event_conversion.cc` 的主要功能是 **将 Blink 内部使用的核心事件对象（例如 `MouseEvent`, `TouchEvent`, `KeyboardEvent`）转换为平台无关的 `WebInputEvent` 及其子类（例如 `WebMouseEvent`, `WebMouseWheelEvent`, `WebKeyboardEvent` 等）。**

这些 `WebInputEvent` 类是 Chromium 项目中定义的，用于在渲染进程（Blink）和浏览器进程之间传递输入事件。 这种转换过程确保了不同操作系统和硬件产生的输入事件能够被 Blink 统一处理。

以下是该文件更具体的功能分解：

**1. 事件类型转换:**

*   该文件包含多个函数，用于将不同类型的核心事件对象转换为对应的 `WebInputEvent` 子类。例如：
    *   `TransformWebMouseEvent`: 将 `MouseEvent` 转换为 `WebMouseEvent`。
    *   `TransformWebMouseWheelEvent`: 将鼠标滚轮事件转换为 `WebMouseWheelEvent`。
    *   `TransformWebGestureEvent`: 将手势事件转换为 `WebGestureEvent`。
    *   `TransformWebPointerEvent`: 将指针事件（可能是鼠标或触摸）转换为 `WebPointerEvent`。
*   `WebKeyboardEventBuilder`: 用于根据 `KeyboardEvent` 构建 `WebKeyboardEvent`。
*   `WebMouseEventBuilder`: 用于根据 `MouseEvent` 或 `TouchEvent` 构建 `WebMouseEvent`。 特别有趣的是，它能够将触摸事件合成为鼠标事件，这在一些不支持触摸的插件或场景中很有用。

**2. 坐标转换和缩放处理:**

*   考虑到网页可能存在缩放（例如用户手动缩放或页面本身设置的缩放）以及嵌入的 iframe，该文件中的函数会进行坐标转换，确保事件的坐标相对于正确的坐标系。
*   `FrameScale` 函数用于获取当前 `LocalFrameView` 的缩放因子。
*   `FrameTranslation` 函数用于获取当前 `LocalFrameView` 的偏移量，这通常与页面的滚动位置有关。
*   `TransformWebMouseEvent` 等函数会使用这些缩放因子和偏移量来调整 `WebInputEvent` 的位置信息 (`SetPositionInWidget`, `SetPositionInScreen`)。

**3. 状态和修饰符转换:**

*   将核心事件对象中的状态信息（例如鼠标按键状态、键盘修饰符）转换为 `WebInputEvent` 中对应的状态。
*   例如，`UpdateWebMouseEventFromCoreMouseEvent` 函数会设置 `WebMouseEvent` 的时间戳、修饰符和屏幕坐标。
*   `ToWebInputEventModifierFrom` 函数将 `WebMouseEvent::Button` 枚举转换为 `WebInputEvent` 的修饰符标志。

**与 JavaScript, HTML, CSS 的关系:**

这个文件直接影响到 JavaScript 如何接收和处理用户输入事件。

*   **JavaScript:** 当用户与网页交互时（例如点击鼠标、按下键盘、触摸屏幕），浏览器底层会生成相应的平台事件。Blink 接收到这些事件后，`web_input_event_conversion.cc` 中的代码会将它们转换为 `WebInputEvent`。最终，这些 `WebInputEvent` 会被传递到 JavaScript 引擎，触发 JavaScript 事件监听器。
    *   **举例:**  一个 JavaScript 监听器监听 `click` 事件。 当用户点击网页上的一个按钮时，操作系统会生成一个鼠标点击事件。 Blink 接收到这个事件后，`TransformWebMouseEvent` 会将其转换为 `WebMouseEvent`，并确保事件的坐标是相对于按钮的正确位置。然后，JavaScript 引擎会触发按钮上的 `click` 事件监听器，JavaScript 代码就可以获取到正确的点击位置等信息。
*   **HTML:** HTML 结构定义了网页的元素和布局，这直接影响了事件的目标元素和坐标系。
    *   **举例:** 如果一个按钮位于一个 `div` 元素内部，并且这个 `div` 元素设置了 `transform` 属性进行了平移，`web_input_event_conversion.cc` 中的坐标转换逻辑会考虑到这个 `transform`，确保鼠标点击事件的坐标相对于按钮自身是正确的，而不是相对于屏幕或父 `div` 的原始位置。
*   **CSS:** CSS 样式可以改变元素的大小、位置和缩放，这些都会影响事件坐标的计算。
    *   **举例:**  如果用户在浏览器中进行了页面缩放，`FrameScale` 函数会获取到这个缩放因子。当发生鼠标事件时，`TransformWebMouseEvent` 会使用这个缩放因子来调整事件的坐标，确保 JavaScript 代码获取到的坐标是相对于缩放后的页面的。

**逻辑推理和假设输入与输出:**

**假设输入 (MouseEvent):**

```
MouseEvent {
  type: "mousedown",
  timeStamp: 1678886400000, // 假设的时间戳
  screenX: 100,
  screenY: 200,
  clientX: 50,
  clientY: 60,
  button: 0, // 左键
  buttons: 1,
  ctrlKey: false,
  shiftKey: false,
  altKey: false,
  metaKey: false,
  target: <button id="myButton">Click Me</button>
}
```

**假设 `LocalFrameView` 的状态:**

*   页面缩放比例为 1.5
*   页面没有滚动，偏移量为 (0, 0)

**逻辑推理:**

`TransformWebMouseEvent` 函数会被调用。

1. `FrameScale` 函数会返回 1.5。
2. `FrameTranslation` 函数会返回 (0, 0)。
3. `UpdateWebMouseEventFromCoreMouseEvent` 会设置 `WebMouseEvent` 的 `time_stamp_`, `modifiers_`, 和屏幕坐标 (100, 200)。
4. `UpdateWebMouseEventFromCoreMouseEvent` 会将客户端坐标 (50, 60) 转换为相对于 `layout_object` 的本地坐标。假设 `myButton` 的绝对位置是 (x, y)，那么本地坐标将是 (50 - x, 60 - y)。
5. `WebMouseEvent` 的 `frame_scale` 会被设置为 1.5。
6. `WebMouseEvent` 的 `frame_translate` 会被设置为 (0, 0)。
7. 鼠标按钮状态会被转换为 `WebInputEvent::kLeftButtonDown` 修饰符。

**假设输出 (WebMouseEvent):**

```
WebMouseEvent {
  type_: WebInputEvent::Type::kMouseDown,
  time_stamp_: 1678886400000,
  modifiers_: 1, // WebInputEvent::kLeftButtonDown
  position_in_screen_: (100, 200),
  position_in_widget_: (50 - x, 60 - y), // 假设的本地坐标
  button_: WebMouseEvent::Button::kLeft,
  frame_scale_: 1.5,
  frame_translate_: (0, 0),
  // ... 其他属性
}
```

**涉及用户或编程常见的使用错误:**

1. **错误地假设事件坐标是绝对屏幕坐标:**  开发者可能会错误地认为 JavaScript 收到的事件坐标 (`event.clientX`, `event.clientY`) 始终是相对于屏幕左上角的绝对坐标。但实际上，这些坐标是相对于视口的，并且可能受到页面缩放和 iframe 的影响。`web_input_event_conversion.cc` 的存在就是为了处理这些复杂性。
    *   **例子:**  一个开发者在一个包含缩放的 iframe 中监听点击事件，并直接使用 `event.clientX` 和 `event.clientY` 来定位元素，而没有考虑到 iframe 的缩放比例，这会导致定位错误。
2. **在自定义事件处理中忽略 `frame_scale` 和 `frame_translate`:** 如果开发者在某些特殊情况下需要自己处理更底层的事件，可能会忽略 `WebInputEvent` 中的 `frame_scale` 和 `frame_translate` 属性，导致坐标计算错误。
3. **在插件开发中使用不兼容的事件类型:**  某些旧的浏览器插件可能只支持传统的鼠标事件，而无法处理触摸事件。`WebMouseEventBuilder` 将触摸事件合成为鼠标事件的功能可以作为一种兼容性处理，但如果插件本身存在更深层次的问题，这种转换可能无法完全解决。
4. **误解合成鼠标事件的行为:**  `WebMouseEventBuilder` 从触摸事件合成鼠标事件时，并非所有鼠标事件的属性都能完美映射。例如，hover 效果可能不会像真实的鼠标 hover 那样工作。开发者需要理解这种合成的局限性。

总而言之，`blink/renderer/core/events/web_input_event_conversion.cc` 是 Blink 引擎中处理用户输入的核心组件，它负责将底层的平台事件转换为浏览器内部统一的事件表示，并进行必要的坐标和状态转换，确保 JavaScript 和其他 Web 技术能够正确地处理用户交互。理解其功能对于理解浏览器事件处理机制至关重要。

Prompt: 
```
这是目录为blink/renderer/core/events/web_input_event_conversion.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
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

#include <array>

#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/core/events/gesture_event.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/events/touch_event.h"
#include "third_party/blink/renderer/core/events/wheel_event.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/input/touch.h"
#include "third_party/blink/renderer/core/input/touch_list.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/keyboard_codes.h"
#include "ui/gfx/geometry/point_conversions.h"

namespace blink {

namespace {
float FrameScale(const LocalFrameView* frame_view) {
  float scale = 1;
  if (frame_view) {
    LocalFrameView* root_view = frame_view->GetFrame().LocalFrameRoot().View();
    if (root_view)
      scale = root_view->InputEventsScaleFactor();
  }
  return scale;
}

gfx::Vector2dF FrameTranslation(const LocalFrameView* frame_view) {
  gfx::Point visual_viewport;
  gfx::Vector2dF overscroll_offset;
  if (frame_view) {
    LocalFrameView* root_view = frame_view->GetFrame().LocalFrameRoot().View();
    if (root_view) {
      visual_viewport = gfx::ToFlooredPoint(
          root_view->GetPage()->GetVisualViewport().VisibleRect().origin());
      overscroll_offset =
          root_view->GetPage()->GetChromeClient().ElasticOverscroll();
    }
  }
  return visual_viewport.OffsetFromOrigin() + overscroll_offset;
}

void UpdateWebMouseEventFromCoreMouseEvent(const MouseEvent& event,
                                           const LayoutObject* layout_object,
                                           WebMouseEvent& web_event) {
  web_event.SetTimeStamp(event.PlatformTimeStamp());
  web_event.SetModifiers(event.GetModifiers());
  web_event.SetPositionInScreen(event.screenX(), event.screenY());

  gfx::PointF local_point = layout_object->AbsoluteToLocalPoint(
      gfx::PointF(event.AbsoluteLocation()));
  web_event.SetPositionInWidget(local_point);
}

unsigned ToWebInputEventModifierFrom(WebMouseEvent::Button button) {
  if (button == WebMouseEvent::Button::kNoButton)
    return 0;

  constexpr auto web_mouse_button_to_platform_modifier = std::to_array<unsigned>(
      {WebInputEvent::kLeftButtonDown, WebInputEvent::kMiddleButtonDown,
       WebInputEvent::kRightButtonDown, WebInputEvent::kBackButtonDown,
       WebInputEvent::kForwardButtonDown});

  return web_mouse_button_to_platform_modifier[static_cast<int>(button)];
}

WebPointerEvent TransformWebPointerEvent(float frame_scale,
                                         gfx::Vector2dF frame_translate,
                                         const WebPointerEvent& event) {
  // frameScale is default initialized to 1.
  DCHECK_EQ(1, event.FrameScale());
  DCHECK_EQ(0, event.FrameTranslate().x());
  DCHECK_EQ(0, event.FrameTranslate().y());
  WebPointerEvent result = event;
  result.SetFrameScale(frame_scale);
  result.SetFrameTranslate(frame_translate);
  return result;
}

}  // namespace

WebMouseEvent TransformWebMouseEvent(LocalFrameView* frame_view,
                                     const WebMouseEvent& event) {
  WebMouseEvent result = event;

  // TODO(dtapuska): Perhaps the event should be constructed correctly?
  // crbug.com/686200
  if (event.GetType() == WebInputEvent::Type::kMouseUp) {
    result.SetModifiers(event.GetModifiers() &
                        ~ToWebInputEventModifierFrom(event.button));
  }
  result.SetFrameScale(FrameScale(frame_view));
  result.SetFrameTranslate(FrameTranslation(frame_view));
  return result;
}

WebMouseWheelEvent TransformWebMouseWheelEvent(
    LocalFrameView* frame_view,
    const WebMouseWheelEvent& event) {
  WebMouseWheelEvent result = event;
  result.SetFrameScale(FrameScale(frame_view));
  result.SetFrameTranslate(FrameTranslation(frame_view));
  return result;
}

WebGestureEvent TransformWebGestureEvent(LocalFrameView* frame_view,
                                         const WebGestureEvent& event) {
  WebGestureEvent result = event;
  result.SetFrameScale(FrameScale(frame_view));
  result.SetFrameTranslate(FrameTranslation(frame_view));
  return result;
}

WebPointerEvent TransformWebPointerEvent(LocalFrameView* frame_view,
                                         const WebPointerEvent& event) {
  return TransformWebPointerEvent(FrameScale(frame_view),
                                  FrameTranslation(frame_view), event);
}

WebMouseEventBuilder::WebMouseEventBuilder(const LayoutObject* layout_object,
                                           const MouseEvent& event) {
  // Code below here can be removed once OOPIF ships.
  // OOPIF will prevent synthetic events being dispatched into
  // other frames; but for now we allow the fallback to generate
  // WebMouseEvents from synthetic events.
  if (event.type() == event_type_names::kMousemove)
    type_ = WebInputEvent::Type::kMouseMove;
  else if (event.type() == event_type_names::kMouseout)
    type_ = WebInputEvent::Type::kMouseLeave;
  else if (event.type() == event_type_names::kMouseover)
    type_ = WebInputEvent::Type::kMouseEnter;
  else if (event.type() == event_type_names::kMousedown)
    type_ = WebInputEvent::Type::kMouseDown;
  else if (event.type() == event_type_names::kMouseup)
    type_ = WebInputEvent::Type::kMouseUp;
  else if (event.type() == event_type_names::kContextmenu)
    type_ = WebInputEvent::Type::kContextMenu;
  else
    return;  // Skip all other mouse events.

  time_stamp_ = event.PlatformTimeStamp();
  modifiers_ = event.GetModifiers();
  UpdateWebMouseEventFromCoreMouseEvent(event, layout_object, *this);

  switch (event.button()) {
    case int16_t(WebPointerProperties::Button::kLeft):
      button = WebMouseEvent::Button::kLeft;
      break;
    case int16_t(WebPointerProperties::Button::kMiddle):
      button = WebMouseEvent::Button::kMiddle;
      break;
    case int16_t(WebPointerProperties::Button::kRight):
      button = WebMouseEvent::Button::kRight;
      break;
    case int16_t(WebPointerProperties::Button::kBack):
      button = WebMouseEvent::Button::kBack;
      break;
    case int16_t(WebPointerProperties::Button::kForward):
      button = WebMouseEvent::Button::kForward;
      break;
  }
  if (event.ButtonDown()) {
    switch (event.button()) {
      case int16_t(WebPointerProperties::Button::kLeft):
        modifiers_ |= WebInputEvent::kLeftButtonDown;
        break;
      case int16_t(WebPointerProperties::Button::kMiddle):
        modifiers_ |= WebInputEvent::kMiddleButtonDown;
        break;
      case int16_t(WebPointerProperties::Button::kRight):
        modifiers_ |= WebInputEvent::kRightButtonDown;
        break;
      case int16_t(WebPointerProperties::Button::kBack):
        modifiers_ |= WebInputEvent::kBackButtonDown;
        break;
      case int16_t(WebPointerProperties::Button::kForward):
        modifiers_ |= WebInputEvent::kForwardButtonDown;
        break;
    }
  } else {
    button = WebMouseEvent::Button::kNoButton;
  }
  movement_x = event.movementX();
  movement_y = event.movementY();
  click_count = event.detail();

  pointer_type = WebPointerProperties::PointerType::kMouse;
}

// Generate a synthetic WebMouseEvent given a TouchEvent (eg. for emulating a
// mouse with touch input for plugins that don't support touch input).
WebMouseEventBuilder::WebMouseEventBuilder(const LayoutObject* layout_object,
                                           const TouchEvent& event) {
  if (!event.touches())
    return;
  if (event.touches()->length() != 1) {
    if (event.touches()->length() ||
        event.type() != event_type_names::kTouchend ||
        !event.changedTouches() || event.changedTouches()->length() != 1)
      return;
  }

  const Touch* touch = event.touches()->length() == 1
                           ? event.touches()->item(0)
                           : event.changedTouches()->item(0);
  if (touch->identifier())
    return;

  if (event.type() == event_type_names::kTouchstart)
    type_ = WebInputEvent::Type::kMouseDown;
  else if (event.type() == event_type_names::kTouchmove)
    type_ = WebInputEvent::Type::kMouseMove;
  else if (event.type() == event_type_names::kTouchend)
    type_ = WebInputEvent::Type::kMouseUp;
  else
    return;

  time_stamp_ = event.PlatformTimeStamp();
  modifiers_ = event.GetModifiers();
  frame_scale_ = 1;
  frame_translate_ = gfx::Vector2dF();

  // The mouse event co-ordinates should be generated from the co-ordinates of
  // the touch point.
  gfx::PointF screen_point = touch->ScreenLocation();
  SetPositionInScreen(screen_point.x(), screen_point.y());

  button = WebMouseEvent::Button::kLeft;
  modifiers_ |= WebInputEvent::kLeftButtonDown;
  click_count = (type_ == WebInputEvent::Type::kMouseDown ||
                 type_ == WebInputEvent::Type::kMouseUp);

  gfx::PointF local_point = layout_object->AbsoluteToLocalPoint(
      gfx::PointF(touch->AbsoluteLocation()));
  SetPositionInWidget(local_point);

  pointer_type = WebPointerProperties::PointerType::kTouch;
}

WebKeyboardEventBuilder::WebKeyboardEventBuilder(const KeyboardEvent& event) {
  if (const WebKeyboardEvent* web_event = event.KeyEvent()) {
    *static_cast<WebKeyboardEvent*>(this) = *web_event;
    return;
  }

  if (event.type() == event_type_names::kKeydown)
    type_ = WebInputEvent::Type::kKeyDown;
  else if (event.type() == event_type_names::kKeyup)
    type_ = WebInputEvent::Type::kKeyUp;
  else if (event.type() == event_type_names::kKeypress)
    type_ = WebInputEvent::Type::kChar;
  else
    return;  // Skip all other keyboard events.

  modifiers_ = event.GetModifiers();
  time_stamp_ = event.PlatformTimeStamp();
  windows_key_code = event.keyCode();
}

Vector<WebMouseEvent> TransformWebMouseEventVector(
    LocalFrameView* frame_view,
    const std::vector<std::unique_ptr<WebInputEvent>>& coalesced_events) {
  Vector<WebMouseEvent> result;
  for (const auto& event : coalesced_events) {
    DCHECK(WebInputEvent::IsMouseEventType(event->GetType()));
    result.push_back(TransformWebMouseEvent(
        frame_view, static_cast<const WebMouseEvent&>(*event)));
  }
  return result;
}

Vector<WebPointerEvent> TransformWebPointerEventVector(
    LocalFrameView* frame_view,
    const std::vector<std::unique_ptr<WebInputEvent>>& coalesced_events) {
  float scale = FrameScale(frame_view);
  gfx::Vector2dF translation = FrameTranslation(frame_view);
  Vector<WebPointerEvent> result;
  for (const auto& event : coalesced_events) {
    DCHECK(WebInputEvent::IsPointerEventType(event->GetType()));
    result.push_back(TransformWebPointerEvent(
        scale, translation, static_cast<const WebPointerEvent&>(*event)));
  }
  return result;
}

}  // namespace blink

"""

```