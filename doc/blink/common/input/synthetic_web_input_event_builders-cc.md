Response: Let's break down the thought process for analyzing this C++ code and generating the explanation.

1. **Understand the Goal:** The primary goal is to explain the functionality of the provided C++ source code file (`synthetic_web_input_event_builders.cc`) within the context of the Chromium Blink rendering engine. The explanation needs to connect the code to web technologies (JavaScript, HTML, CSS) where applicable, illustrate logic with examples, and point out potential usage errors.

2. **Initial Skim and Identify Core Concepts:**  A quick read reveals the file is about *building* synthetic web input events. The names of the classes (`SyntheticWebMouseEventBuilder`, `SyntheticWebMouseWheelEventBuilder`, `SyntheticWebGestureEventBuilder`, `SyntheticWebTouchEvent`) immediately suggest the types of events being constructed. The presence of `blink::WebInputEvent::Type` and related structures indicates this is dealing with the internal representation of user interactions.

3. **Analyze Each Builder Class Individually:**  The best approach is to examine each builder class separately.

    * **`SyntheticWebMouseEventBuilder`:**
        * **`Build(type)`:** Creates a basic mouse event with the specified type and default modifiers/time.
        * **`Build(type, x, y, modifiers, pointer_type)`:** Creates a more detailed mouse event with position, modifiers, and pointer type. The `DCHECK` suggests a safety check for the event type.
        * **Connection to Web Technologies:** Mouse events directly correspond to user interactions with the mouse in a web page. JavaScript event listeners (e.g., `onclick`, `onmousemove`) handle these. HTML elements are the targets of these events. CSS can change the appearance based on mouse states (e.g., `:hover`).

    * **`SyntheticWebMouseWheelEventBuilder`:**
        * **`Build(phase)`:** Creates a mouse wheel event related to scrolling phases.
        * **`Build(x, y, dx, dy, ...)` and `Build(x, y, global_x, global_y, dx, dy, ...)`:** Creates more detailed wheel events with delta values for scrolling, modifiers, and granularity.
        * **Connection to Web Technologies:**  Scroll events are essential for navigation in web pages. JavaScript can intercept and customize scrolling behavior (`onwheel`). CSS can be affected by scrolling (e.g., fixed positioning).

    * **`SyntheticWebGestureEventBuilder`:**
        * **`Build(type, source_device, modifiers)`:** Creates a general gesture event. Specific handling for `kGestureTap`, `kGestureTapUnconfirmed`, and `kGestureDoubleTap` is present.
        * **Specialized `Build...` methods (`BuildScrollBegin`, `BuildScrollUpdate`, `BuildScrollEnd`, `BuildPinchUpdate`, `BuildFling`):**  These methods create specific gesture events with relevant data (scroll deltas, pinch scale, fling velocities).
        * **Connection to Web Technologies:** Gesture events are crucial for touchscreens and trackpads. JavaScript event listeners (e.g., `touchstart`, `touchmove`, `touchend`, `gesturestart`, `gesturechange`, `gestureend`) handle these.

    * **`SyntheticWebTouchEvent`:** This class is slightly different. It manages a collection of touch points.
        * **`ResetPoints()`:** Resets the state of touch points.
        * **`PressPoint()`, `MovePoint()`, `ReleasePoint()`, `CancelPoint()`:**  Simulate the different phases of a touch interaction.
        * **`SetTimestamp()`:** Sets the event timestamp.
        * **`FirstFreeIndex()`:**  Finds an available slot for a new touch point.
        * **Connection to Web Technologies:** Touch events are fundamental for mobile and touch-enabled devices. JavaScript event listeners (`touchstart`, `touchmove`, `touchend`, `touchcancel`) process these.

4. **Identify Relationships to Web Technologies:**  For each builder, explicitly connect the generated events to the corresponding JavaScript event types and how they relate to HTML elements and CSS styling.

5. **Illustrate Logic with Examples:**  For methods with parameters, construct simple scenarios to show how inputs translate to the created event objects. Focus on demonstrating the key parameters and their effects. Use clear and concise examples. Think about common use cases for simulating these events (e.g., testing scrolling, simulating a tap).

6. **Consider Potential User/Programming Errors:**  Think about common mistakes developers might make when using these builders. This involves:
    * **Incorrect Event Type:** Passing the wrong `WebInputEvent::Type`.
    * **Missing or Incorrect Coordinates:**  Forgetting to set or providing wrong `x`, `y` values.
    * **Incorrect Modifiers:**  Misunderstanding or setting the wrong modifier flags.
    * **Touch Event Management:**  Incorrectly managing the state of touch points in `SyntheticWebTouchEvent`. Forgetting to call `ResetPoints()`.

7. **Structure the Explanation:**  Organize the information logically. Start with an overview of the file's purpose. Then, detail each builder class. Follow this with the connections to web technologies, examples, and potential errors. Use clear headings and bullet points for readability.

8. **Refine and Review:**  Read through the explanation to ensure clarity, accuracy, and completeness. Check for any ambiguities or missing information. Ensure the examples are easy to understand and effectively illustrate the concepts. For instance, initially, I might just say "creates a mouse event," but refining it would involve mentioning the specific types of mouse events and their parameters. Similarly, for errors, just saying "incorrect parameters" is less helpful than providing specific examples like "forgetting to set coordinates."

By following these steps,  a comprehensive and informative explanation of the C++ code can be generated, effectively connecting it to the broader context of web development.
这个文件 `blink/common/input/synthetic_web_input_event_builders.cc` 的主要功能是提供一组便捷的工具类，用于在 Chromium 的 Blink 渲染引擎中**创建合成的（即人为构造的）Web 输入事件**。 这些事件可以模拟用户与网页的交互，例如鼠标点击、滚动、手势和触摸操作。

**核心功能:**

1. **构建各种 Web 输入事件:**  它包含了多个构建器类，每个类负责创建特定类型的 Web 输入事件对象：
   - `SyntheticWebMouseEventBuilder`: 用于构建 `WebMouseEvent` 对象 (鼠标事件)。
   - `SyntheticWebMouseWheelEventBuilder`: 用于构建 `WebMouseWheelEvent` 对象 (鼠标滚轮事件)。
   - `SyntheticWebGestureEventBuilder`: 用于构建 `WebGestureEvent` 对象 (手势事件，如滑动、缩放)。
   - `SyntheticWebTouchEvent`: 用于构建 `WebTouchEvent` 对象 (触摸事件)。

2. **简化事件创建过程:** 这些构建器类提供了便捷的方法来设置事件的各种属性，例如事件类型、坐标、修饰键（Ctrl, Shift 等）、时间戳等，而无需手动创建和填充 `WebInputEvent` 及其子类的所有字段。

3. **用于测试和自动化:** 合成事件主要用于自动化测试、模拟用户行为、调试以及在某些特殊场景下触发网页的交互。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这些合成事件最终会被 Blink 引擎处理，就像它们是真实的用户输入一样，从而影响网页的行为和渲染。因此，它们与 JavaScript, HTML, 和 CSS 的功能有着密切的关系：

* **JavaScript:**  合成事件可以触发 JavaScript 事件监听器。例如，你可以创建一个合成的鼠标点击事件来模拟用户点击一个按钮，从而触发按钮上绑定的 `onclick` 事件处理函数。

   ```c++
   // 假设我们想模拟点击发生在坐标 (100, 100) 的事件
   WebMouseEvent click_event = SyntheticWebMouseEventBuilder::Build(
       blink::WebInputEvent::Type::kMouseDown, 100, 100,
       WebInputEvent::kNoModifiers,
       blink::WebPointerProperties::PointerType::kMouse);
   // ... 将这个事件发送到 Blink 引擎进行处理 ...

   WebMouseEvent release_event = SyntheticWebMouseEventBuilder::Build(
       blink::WebInputEvent::Type::kMouseUp, 100, 100,
       WebInputEvent::kNoModifiers,
       blink::WebPointerProperties::PointerType::kMouse);
   // ... 将这个事件发送到 Blink 引擎进行处理 ...
   ```

   在 JavaScript 中，你可能会有这样的代码：

   ```javascript
   document.getElementById('myButton').onclick = function() {
       console.log('按钮被点击了！');
   };
   ```

   上面 C++ 代码创建的合成点击事件就能触发这个 JavaScript 函数。

* **HTML:** 合成事件作用于 HTML 元素。例如，一个合成的鼠标移动事件可以触发一个元素上的 `mouseover` 或 `mouseout` 事件，改变元素的可见性或者触发其他基于鼠标悬停的效果。

   ```c++
   // 模拟鼠标移动到坐标 (200, 150)
   WebMouseEvent move_event = SyntheticWebMouseEventBuilder::Build(
       blink::WebInputEvent::Type::kMouseMove, 200, 150,
       WebInputEvent::kNoModifiers,
       blink::WebPointerProperties::PointerType::kMouse);
   // ... 发送事件 ...
   ```

   如果 HTML 中有这样的元素和 CSS：

   ```html
   <div id="myDiv">将鼠标悬停在我身上</div>
   ```

   ```css
   #myDiv {
       background-color: lightblue;
   }
   #myDiv:hover {
       background-color: yellow;
   }
   ```

   合成的 `kMouseMove` 事件可以触发 `:hover` 伪类，改变 `myDiv` 的背景颜色。

* **CSS:** 合成事件可以触发依赖于用户交互的 CSS 伪类和动画。例如，一个合成的触摸事件可以触发一个按钮的 `:active` 状态，应用按下时的样式。

   ```c++
   // 模拟触摸按下事件
   SyntheticWebTouchEvent touch_event;
   touch_event.PressPoint(50, 50, 0, 0, 0, 1.0f, 0, 0, 0);
   // ... 发送 touch_event ...
   ```

   如果 HTML 中有一个按钮，并且 CSS 定义了 `:active` 状态：

   ```html
   <button id="touchButton">触摸我</button>
   ```

   ```css
   #touchButton:active {
       transform: scale(0.9);
   }
   ```

   合成的触摸按下事件可以触发按钮的缩小动画。

**逻辑推理和假设输入与输出:**

以 `SyntheticWebMouseEventBuilder::Build` 方法为例：

**假设输入:**

* `type`: `blink::WebInputEvent::Type::kMouseDown` (鼠标按下事件)
* `window_x`: `100.0f` (窗口内的 X 坐标)
* `window_y`: `50.0f` (窗口内的 Y 坐标)
* `modifiers`: `WebInputEvent::kControlKey` (按下了 Ctrl 键)
* `pointer_type`: `blink::WebPointerProperties::PointerType::kMouse` (鼠标指针)

**逻辑推理:**

该方法会创建一个 `WebMouseEvent` 对象，并将传入的参数设置到该对象的相应属性上：

* `type_` 会被设置为 `blink::WebInputEvent::Type::kMouseDown`。
* 位置信息 (`position_in_widget_`, `position_in_screen_`) 会被设置为 `(100.0f, 50.0f)`。
* `modifiers_` 会被设置为 `WebInputEvent::kControlKey`。
* `pointer_type` 会被设置为 `blink::WebPointerProperties::PointerType::kMouse`。
* 其他属性如 `id` 和 `timestamp` 会被设置为默认值或当前时间。

**输出:**

一个 `WebMouseEvent` 对象，其主要属性被设置为：

```
WebMouseEvent {
  type_: kMouseDown,
  modifiers_: ControlKey,
  position_in_widget_: (100, 50),
  position_in_screen_: (100, 50),
  pointer_type: Mouse,
  id: 0, // 鼠标指针的 ID
  // ... 其他属性 ...
}
```

**用户或编程常见的使用错误举例说明:**

1. **事件类型不匹配:**  例如，使用 `SyntheticWebMouseEventBuilder` 构建了一个 `kMouseWheel` 类型的事件，但实际上希望模拟鼠标点击。这会导致事件处理逻辑无法正确触发。

   ```c++
   // 错误示例：尝试用鼠标事件构建器构建滚轮事件
   WebMouseEvent wheel_event = SyntheticWebMouseEventBuilder::Build(
       blink::WebInputEvent::Type::kMouseWheel, 100, 100,
       WebInputEvent::kNoModifiers,
       blink::WebPointerProperties::PointerType::kMouse);
   // 应该使用 SyntheticWebMouseWheelEventBuilder
   ```

2. **坐标错误:**  提供的坐标超出网页的可视区域，或者与预期的交互元素位置不符。这会导致事件作用在错误的目标上，或者没有目标接收到事件。

   ```c++
   // 错误示例：坐标设置为负数
   WebMouseEvent click_event = SyntheticWebMouseEventBuilder::Build(
       blink::WebInputEvent::Type::kMouseDown, -10, -5,
       WebInputEvent::kNoModifiers,
       blink::WebPointerProperties::PointerType::kMouse);
   ```

3. **修饰键使用不当:**  忘记设置必要的修饰键，或者错误地设置了修饰键。例如，希望模拟按住 Ctrl 键点击链接以在新标签页打开，但忘记设置 `WebInputEvent::kControlKey`。

   ```c++
   // 错误示例：忘记设置 Ctrl 键
   WebMouseEvent click_event = SyntheticWebMouseEventBuilder::Build(
       blink::WebInputEvent::Type::kMouseDown, 100, 100,
       WebInputEvent::kNoModifiers, // 应该包含 WebInputEvent::kControlKey
       blink::WebPointerProperties::PointerType::kMouse);
   ```

4. **触摸事件状态管理错误:** 在使用 `SyntheticWebTouchEvent` 时，没有正确管理触摸点的状态 (Pressed, Moved, Released, Cancelled)。例如，在模拟一个滑动操作时，忘记先调用 `PressPoint`，或者在滑动结束后没有调用 `ReleasePoint`。

   ```c++
   // 错误示例：直接移动触摸点而没有先按下
   SyntheticWebTouchEvent touch_event;
   // 缺少 PressPoint 调用
   touch_event.MovePoint(0, 150, 150, 0, 0, 0, 1.0f, 0, 0, 0); // 假设 index 0 存在，但实际可能未被初始化
   ```

5. **混淆窗口坐标和屏幕坐标:** 在某些情况下，区分窗口坐标和屏幕坐标很重要。如果混淆了这两种坐标，可能会导致事件作用在错误的位置。虽然这个文件中的构建器通常会将窗口坐标和屏幕坐标设置为相同的值，但在更复杂的场景下需要注意。

总而言之，`synthetic_web_input_event_builders.cc` 提供了一种在 Blink 引擎中创建模拟用户交互事件的机制，这对于测试、自动化和某些特殊功能的实现至关重要。理解其功能和正确使用方法对于开发者来说非常重要。

Prompt: 
```
这是目录为blink/common/input/synthetic_web_input_event_builders.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/input/synthetic_web_input_event_builders.h"

#include "base/check_op.h"
#include "ui/events/base_event_utils.h"

namespace blink {

WebMouseEvent SyntheticWebMouseEventBuilder::Build(
    blink::WebInputEvent::Type type) {
  return WebMouseEvent(type, WebInputEvent::kNoModifiers,
                       ui::EventTimeForNow());
}

WebMouseEvent SyntheticWebMouseEventBuilder::Build(
    blink::WebInputEvent::Type type,
    float window_x,
    float window_y,
    int modifiers,
    blink::WebPointerProperties::PointerType pointer_type) {
  DCHECK(WebInputEvent::IsMouseEventType(type));
  WebMouseEvent result(type, modifiers, ui::EventTimeForNow());
  result.SetPositionInWidget(window_x, window_y);
  result.SetPositionInScreen(window_x, window_y);
  result.SetModifiers(modifiers);
  result.pointer_type = pointer_type;
  result.id = WebMouseEvent::kMousePointerId;
  return result;
}

WebMouseWheelEvent SyntheticWebMouseWheelEventBuilder::Build(
    WebMouseWheelEvent::Phase phase) {
  WebMouseWheelEvent result(WebInputEvent::Type::kMouseWheel,
                            WebInputEvent::kNoModifiers, ui::EventTimeForNow());
  result.phase = phase;
  result.event_action =
      WebMouseWheelEvent::GetPlatformSpecificDefaultEventAction(result);
  return result;
}

WebMouseWheelEvent SyntheticWebMouseWheelEventBuilder::Build(
    float x,
    float y,
    float dx,
    float dy,
    int modifiers,
    ui::ScrollGranularity delta_units) {
  return Build(x, y, 0, 0, dx, dy, modifiers, delta_units);
}

WebMouseWheelEvent SyntheticWebMouseWheelEventBuilder::Build(
    float x,
    float y,
    float global_x,
    float global_y,
    float dx,
    float dy,
    int modifiers,
    ui::ScrollGranularity delta_units) {
  WebMouseWheelEvent result(WebInputEvent::Type::kMouseWheel, modifiers,
                            ui::EventTimeForNow());
  result.SetPositionInScreen(global_x, global_y);
  result.SetPositionInWidget(x, y);
  result.delta_units = delta_units;
  result.delta_x = dx;
  result.delta_y = dy;
  if (dx)
    result.wheel_ticks_x = dx > 0.0f ? 1.0f : -1.0f;
  if (dy)
    result.wheel_ticks_y = dy > 0.0f ? 1.0f : -1.0f;

  result.event_action =
      WebMouseWheelEvent::GetPlatformSpecificDefaultEventAction(result);
  return result;
}

WebGestureEvent SyntheticWebGestureEventBuilder::Build(
    WebInputEvent::Type type,
    blink::WebGestureDevice source_device,
    int modifiers) {
  DCHECK(WebInputEvent::IsGestureEventType(type));
  WebGestureEvent result(type, modifiers, ui::EventTimeForNow(), source_device);
  if (type == WebInputEvent::Type::kGestureTap ||
      type == WebInputEvent::Type::kGestureTapUnconfirmed ||
      type == WebInputEvent::Type::kGestureDoubleTap) {
    result.data.tap.tap_count = 1;
    result.data.tap.width = 10;
    result.data.tap.height = 10;
  }

  result.SetNeedsWheelEvent(result.IsTouchpadZoomEvent());

  return result;
}

WebGestureEvent SyntheticWebGestureEventBuilder::BuildScrollBegin(
    float dx_hint,
    float dy_hint,
    blink::WebGestureDevice source_device,
    int pointer_count) {
  WebGestureEvent result =
      Build(WebInputEvent::Type::kGestureScrollBegin, source_device);
  result.data.scroll_begin.delta_x_hint = dx_hint;
  result.data.scroll_begin.delta_y_hint = dy_hint;
  result.data.scroll_begin.pointer_count = pointer_count;
  return result;
}

WebGestureEvent SyntheticWebGestureEventBuilder::BuildScrollUpdate(
    float dx,
    float dy,
    int modifiers,
    blink::WebGestureDevice source_device) {
  WebGestureEvent result = Build(WebInputEvent::Type::kGestureScrollUpdate,
                                 source_device, modifiers);
  result.data.scroll_update.delta_x = dx;
  result.data.scroll_update.delta_y = dy;
  return result;
}

WebGestureEvent SyntheticWebGestureEventBuilder::BuildScrollEnd(
    blink::WebGestureDevice source_device) {
  WebGestureEvent result =
      Build(WebInputEvent::Type::kGestureScrollEnd, source_device);
  return result;
}

WebGestureEvent SyntheticWebGestureEventBuilder::BuildPinchUpdate(
    float scale,
    float anchor_x,
    float anchor_y,
    int modifiers,
    blink::WebGestureDevice source_device) {
  WebGestureEvent result =
      Build(WebInputEvent::Type::kGesturePinchUpdate, source_device, modifiers);
  result.data.pinch_update.scale = scale;
  result.SetPositionInWidget(gfx::PointF(anchor_x, anchor_y));
  result.SetPositionInScreen(gfx::PointF(anchor_x, anchor_y));
  return result;
}

WebGestureEvent SyntheticWebGestureEventBuilder::BuildFling(
    float velocity_x,
    float velocity_y,
    blink::WebGestureDevice source_device) {
  WebGestureEvent result =
      Build(WebInputEvent::Type::kGestureFlingStart, source_device);
  result.data.fling_start.velocity_x = velocity_x;
  result.data.fling_start.velocity_y = velocity_y;
  return result;
}

SyntheticWebTouchEvent::SyntheticWebTouchEvent() : WebTouchEvent() {
  unique_touch_event_id = ui::GetNextTouchEventId();
  SetTimestamp(ui::EventTimeForNow());
  pointer_id_ = 0;
}

void SyntheticWebTouchEvent::ResetPoints() {
  int activePointCount = 0;
  unsigned count = 0;
  for (unsigned int i = 0; i < kTouchesLengthCap; ++i) {
    switch (touches[i].state) {
      case WebTouchPoint::State::kStatePressed:
      case WebTouchPoint::State::kStateMoved:
      case WebTouchPoint::State::kStateStationary:
        touches[i].state = WebTouchPoint::State::kStateStationary;
        ++activePointCount;
        ++count;
        break;
      case WebTouchPoint::State::kStateReleased:
      case WebTouchPoint::State::kStateCancelled:
        touches[i] = WebTouchPoint();
        ++count;
        break;
      case WebTouchPoint::State::kStateUndefined:
        break;
    }
    if (count >= touches_length)
      break;
  }
  touches_length = activePointCount;
  type_ = WebInputEvent::Type::kUndefined;
  moved_beyond_slop_region = false;
  unique_touch_event_id = ui::GetNextTouchEventId();
}

int SyntheticWebTouchEvent::PressPoint(float x,
                                       float y,
                                       float radius_x,
                                       float radius_y,
                                       float rotation_angle,
                                       float force,
                                       float tangential_pressure,
                                       int tilt_x,
                                       int tilt_y) {
  int index = FirstFreeIndex();
  if (index == -1)
    return -1;
  WebTouchPoint& point = touches[index];
  point.id = pointer_id_++;
  point.SetPositionInWidget(x, y);
  point.SetPositionInScreen(x, y);
  point.state = WebTouchPoint::State::kStatePressed;
  point.radius_x = radius_x;
  point.radius_y = radius_y;
  point.rotation_angle = rotation_angle;
  point.force = force;
  point.tilt_x = tilt_x;
  point.tilt_y = tilt_y;
  point.twist = 0;
  point.tangential_pressure = tangential_pressure;
  point.pointer_type = blink::WebPointerProperties::PointerType::kTouch;
  ++touches_length;
  SetType(WebInputEvent::Type::kTouchStart);
  dispatch_type = WebInputEvent::DispatchType::kBlocking;
  return index;
}

void SyntheticWebTouchEvent::MovePoint(int index,
                                       float x,
                                       float y,
                                       float radius_x,
                                       float radius_y,
                                       float rotation_angle,
                                       float force,
                                       float tangential_pressure,
                                       int tilt_x,
                                       int tilt_y) {
  CHECK_GE(index, 0);
  CHECK_LT(index, kTouchesLengthCap);
  // Always set this bit to avoid otherwise unexpected touchmove suppression.
  // The caller can opt-out explicitly, if necessary.
  moved_beyond_slop_region = true;
  WebTouchPoint& point = touches[index];
  point.SetPositionInWidget(x, y);
  point.SetPositionInScreen(x, y);
  point.state = WebTouchPoint::State::kStateMoved;
  point.radius_x = radius_x;
  point.radius_y = radius_y;
  point.rotation_angle = rotation_angle;
  point.force = force;
  point.tilt_x = tilt_x;
  point.tilt_y = tilt_y;
  point.twist = 0;
  point.tangential_pressure = tangential_pressure;
  SetType(WebInputEvent::Type::kTouchMove);
  dispatch_type = WebInputEvent::DispatchType::kBlocking;
}

void SyntheticWebTouchEvent::ReleasePoint(int index) {
  CHECK_GE(index, 0);
  CHECK_LT(index, kTouchesLengthCap);
  touches[index].state = WebTouchPoint::State::kStateReleased;
  touches[index].force = 0.f;
  SetType(WebInputEvent::Type::kTouchEnd);
  dispatch_type = WebInputEvent::DispatchType::kBlocking;
}

void SyntheticWebTouchEvent::CancelPoint(int index) {
  CHECK_GE(index, 0);
  CHECK_LT(index, kTouchesLengthCap);
  touches[index].state = WebTouchPoint::State::kStateCancelled;
  SetType(WebInputEvent::Type::kTouchCancel);
  dispatch_type = WebInputEvent::DispatchType::kEventNonBlocking;
}

void SyntheticWebTouchEvent::SetTimestamp(base::TimeTicks timestamp) {
  SetTimeStamp(timestamp);
}

int SyntheticWebTouchEvent::FirstFreeIndex() {
  for (size_t i = 0; i < kTouchesLengthCap; ++i) {
    if (touches[i].state == WebTouchPoint::State::kStateUndefined)
      return i;
  }
  return -1;
}

}  // namespace blink

"""

```