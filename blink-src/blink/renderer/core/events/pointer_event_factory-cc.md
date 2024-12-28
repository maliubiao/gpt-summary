Response:
Let's break down the thought process for analyzing the `pointer_event_factory.cc` file.

1. **Understand the Goal:** The primary goal is to understand the *functionality* of this specific source code file within the Chromium Blink rendering engine. This includes identifying its purpose, how it interacts with other parts of the system (especially related to web technologies), and potential pitfalls for developers or users.

2. **Initial Scan and Keywords:** Quickly skim the code, looking for obvious keywords and patterns. Things that jump out:

    * `#include`: Immediately tells us dependencies and what other parts of Blink are involved. Notice things like `PointerEvent.h`, `WebPointerEvent.h`, `LocalDOMWindow.h`, etc. These point to the core domain of the file: handling pointer events within the rendering engine.
    * `namespace blink`: Confirms this is Blink-specific code.
    * `PointerEventFactory`: The central class. This is the main entity we need to understand.
    * Function names like `CreateEventSequence`, `ConvertIdTypeButtonsEvent`, `Create`, `CreatePointerCancelEvent`, etc. These directly hint at the factory's purpose: *creating* various types of pointer events.
    * Variables like `pointer_id_to_attributes_`, `pointer_incoming_id_mapping_`, `primary_id_`. These suggest the factory manages the state and identity of pointers.
    * Constants like `kMouseId`, `kInvalidId`. These provide specific values used in the factory's logic.
    * Mentions of `WebPointerProperties`, `PointerEventInit`. These are key data structures involved in representing pointer events.

3. **Deconstruct the Class (PointerEventFactory):**  Focus on the core class.

    * **Purpose:**  The name "factory" strongly suggests its main responsibility is creating `PointerEvent` objects.
    * **Input:**  The methods take `WebPointerEvent` as input. This tells us it's converting lower-level browser input events into Blink's `PointerEvent` objects.
    * **Output:** The methods return `PointerEvent*`. This confirms the creation aspect.
    * **Key Methods (and their likely functions):**
        * `Create()`:  The main creation method, likely orchestrating the process.
        * `ConvertIdTypeButtonsEvent()`:  Seems responsible for translating `WebPointerEvent` properties (ID, type, buttons) into the initial part of a `PointerEvent`.
        * `CreateEventSequence()`:  Handles coalesced and predicted events, indicating handling of batched or anticipated pointer movements.
        * `CreatePointerCancelEvent()`, `CreatePointerEventFrom()`, etc.:  Specific methods for creating different subtypes of pointer events.
        * `AddOrUpdateIdAndActiveButtons()`, `Remove()`: Methods for managing the internal state of pointer IDs and their attributes.
        * `GetPointerEventId()`:  For retrieving the Blink-internal ID based on the browser's event data.

4. **Identify Key Concepts and Relationships:**

    * **WebPointerEvent vs. PointerEvent:**  Recognize the distinction. `WebPointerEvent` is the lower-level representation from the browser, while `PointerEvent` is Blink's DOM event object that gets dispatched to JavaScript.
    * **Pointer IDs:** The factory manages unique IDs for each pointer. This is crucial for tracking individual touch points or mouse cursors.
    * **Pointer Types:**  Touch, mouse, pen, etc. The factory needs to handle these differently.
    * **Coalesced and Predicted Events:**  Understand these are optimizations for smoother pointer movement by batching and anticipating events.
    * **Event Initialization (`PointerEventInit`):**  Recognize this pattern for setting up the properties of the `PointerEvent` object.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):**

    * **JavaScript:**  Focus on *how* these `PointerEvent` objects are used in JavaScript. Think about the event listeners (`addEventListener('pointerdown', ...)`) and the properties of the `PointerEvent` object (e.g., `pointerId`, `pointerType`, `clientX`, `clientY`).
    * **HTML:**  Consider how pointer events interact with HTML elements. Think about event targets, capturing, and bubbling.
    * **CSS:**  Consider CSS properties that might be affected by pointer events (e.g., `:hover`, `:active`) and how these events trigger state changes.

6. **Look for Logic and Potential Issues:**

    * **ID Management:** The factory needs to ensure consistent and unique IDs. Think about what happens when a pointer goes down, moves, and goes up.
    * **Primary Pointer:** The concept of a "primary" pointer is important for touch interactions. The factory manages this state.
    * **Edge Cases:** Consider scenarios like multiple simultaneous touch points, stylus with eraser, and how the factory handles these. The comments in the code itself often highlight such edge cases (e.g., the TODO about hovering erasers).
    * **Common Errors:** Think from a developer's perspective. What are common mistakes when handling pointer events in JavaScript? (e.g., not checking `pointerType`, assuming mouse-like behavior for all pointers).

7. **Structure the Output:** Organize the findings into logical sections as requested:

    * **Functionality:** Provide a high-level overview and then delve into specific tasks.
    * **Relationship to Web Technologies:**  Give concrete examples linking the code to JavaScript, HTML, and CSS.
    * **Logic and Assumptions:** Explain the reasoning behind certain code sections and any underlying assumptions. Use "Hypothetical Input/Output" examples to illustrate the logic.
    * **Common Usage Errors:**  Focus on practical advice for developers using pointer events.

8. **Refine and Review:** Read through the generated explanation. Is it clear? Accurate? Does it address all aspects of the prompt?  Are the examples relevant and easy to understand?  (Self-correction is key here.) For instance, initially, I might just say "it creates pointer events." But then I'd refine that to be more specific: "It converts browser-level input events into Blink's DOM `PointerEvent` objects that are dispatched to JavaScript."

By following this systematic approach, breaking down the problem into smaller, manageable parts, and focusing on the key concepts and relationships within the code, we can effectively analyze the functionality of a complex source file like `pointer_event_factory.cc`.这个文件 `blink/renderer/core/events/pointer_event_factory.cc` 的主要功能是**创建和管理 PointerEvent 对象**。它是 Chromium Blink 渲染引擎中负责将底层输入事件（如鼠标、触摸、触控笔事件）转换为符合 Web 标准的 `PointerEvent` 对象的核心组件。这些 `PointerEvent` 对象最终会被分发到 JavaScript 代码中，供 Web 开发者使用。

以下是该文件更详细的功能分解：

**核心功能：**

1. **将 `WebPointerEvent` 转换为 `PointerEvent`:**
   - `WebPointerEvent` 是 Blink 引擎内部表示底层指针事件的数据结构。
   - `PointerEventFactory` 接收 `WebPointerEvent` 对象作为输入。
   - 它根据 `WebPointerEvent` 的属性（例如，类型、位置、按钮状态、压力、倾斜度等）创建一个或多个对应的 `PointerEvent` 对象。

2. **管理 Pointer ID:**
   - `PointerEvent` 具有一个唯一的 `pointerId` 属性，用于区分不同的指针（例如，不同的手指触摸点或不同的鼠标）。
   - `PointerEventFactory` 负责分配和管理这些 `pointerId`。它维护着一个内部映射 (`pointer_incoming_id_mapping_`, `pointer_id_to_attributes_`)，将底层的设备相关的 ID 映射到 Blink 内部的 `pointerId`。
   - 它跟踪哪些指针当前是活动的，并维护每个指针的属性（例如，是否按下按钮，是否悬停）。

3. **处理 Coalesced 和 Predicted 事件:**
   - 对于 `pointermove` 事件，为了提高性能和流畅度，浏览器可能会将多个连续的移动事件合并（coalesce）成一个事件，或者预测未来可能发生的移动事件。
   - `PointerEventFactory` 能够处理这些 coalesced 和 predicted 事件，并创建相应的 `PointerEvent` 对象序列。

4. **设置 `PointerEvent` 对象的属性:**
   - 它根据 `WebPointerEvent` 的信息，设置 `PointerEvent` 对象的各种属性，例如：
     - `type` (pointerdown, pointerup, pointermove, pointercancel, 等)
     - `pointerId`
     - `pointerType` (mouse, touch, pen, eraser)
     - `isPrimary` (是否是主要的指针)
     - 坐标 (`screenX`, `screenY`, `clientX`, `clientY`)
     - 按钮状态 (`button`, `buttons`)
     - 压力 (`pressure`)
     - 倾斜度 (`tiltX`, `tiltY`)
     - 海拔角和方位角 (`altitudeAngle`, `azimuthAngle`)
     - 切向压力 (`tangentialPressure`)
     - 旋转 (`twist`)
     - 视图 (`view`)
     - 修饰键状态 (Ctrl, Shift, Alt, Meta)
     - 是否可取消 (`cancelable`)
     - 是否冒泡 (`bubbles`)

5. **处理 Pointer Capture:**
   - `PointerEventFactory` 也参与处理 pointer capture 机制，创建 `gotpointercapture` 和 `lostpointercapture` 事件。

6. **处理 Pointer Boundary 事件:**
   - 创建 `pointerover`, `pointerout`, `pointerenter`, `pointerleave` 等边界事件。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **JavaScript:** `PointerEventFactory` 创建的 `PointerEvent` 对象最终会被传递给 JavaScript 事件处理程序。Web 开发者可以使用 JavaScript 来监听和处理这些事件，从而实现各种交互功能。

   ```javascript
   document.addEventListener('pointerdown', (event) => {
     console.log('Pointer down:', event.pointerId, event.pointerType, event.clientX, event.clientY);
     if (event.pointerType === 'touch') {
       console.log('Touch event!');
     }
   });

   document.addEventListener('pointermove', (event) => {
     // 根据 pointerId 追踪特定指针的移动
   });
   ```

* **HTML:** `PointerEvent` 可以发生在任何 HTML 元素上。`PointerEventFactory` 创建的事件会根据 DOM 树的结构进行冒泡或捕获，最终到达目标元素或其祖先元素的事件监听器。

   ```html
   <div id="myDiv" style="width: 100px; height: 100px; background-color: red;"></div>
   <script>
     document.getElementById('myDiv').addEventListener('pointerdown', (event) => {
       console.log('Pointer down on div');
     });
   </script>
   ```

* **CSS:**  CSS 可以通过伪类（例如 `:hover`, `:active`) 响应 pointer 事件的状态变化。虽然 `PointerEventFactory` 本身不直接操作 CSS，但它创建的事件会触发浏览器的渲染引擎更新元素的状态，从而应用相应的 CSS 样式。

   ```css
   #myDiv:hover {
     background-color: blue;
   }

   #myDiv:active {
     background-color: green;
   }
   ```
   当鼠标指针悬停在 `#myDiv` 上时，`PointerEventFactory` 会创建 `pointermove` 事件，并可能触发 `:hover` 状态的改变，从而使背景色变为蓝色。当鼠标按钮在 `#myDiv` 上按下时，会触发 `:active` 状态。

**逻辑推理和假设输入/输出：**

假设我们有一个触摸屏设备，用户用两根手指同时触摸屏幕。

**假设输入：**

1. **手指 1 按下：** `WebPointerEvent` 类型为 `kPointerDown`，`pointer_type` 为 `kTouch`，具有一个唯一的设备相关 ID（例如，10），屏幕坐标 (100, 100)。
2. **手指 2 按下：** `WebPointerEvent` 类型为 `kPointerDown`，`pointer_type` 为 `kTouch`，具有另一个唯一的设备相关 ID（例如，11），屏幕坐标 (200, 200)。
3. **手指 1 移动：** `WebPointerEvent` 类型为 `kPointerMove`，`pointer_type` 为 `kTouch`，设备相关 ID 为 10，新的屏幕坐标 (110, 110)。

**逻辑推理（`PointerEventFactory` 内部）：**

1. **手指 1 按下：**
   - `ConvertIdTypeButtonsEvent` 会为这个触摸点分配一个新的 `pointerId`（例如，1）。
   - 创建一个 `PointerEvent` 对象，`type` 为 `pointerdown`，`pointerId` 为 1，`pointerType` 为 `touch`，`clientX` 和 `clientY` 基于屏幕坐标计算得到。
   - 将设备相关 ID 10 映射到 `pointerId` 1。

2. **手指 2 按下：**
   - `ConvertIdTypeButtonsEvent` 会为这个触摸点分配一个新的 `pointerId`（例如，2）。
   - 创建一个 `PointerEvent` 对象，`type` 为 `pointerdown`，`pointerId` 为 2，`pointerType` 为 `touch`。
   - 将设备相关 ID 11 映射到 `pointerId` 2。

3. **手指 1 移动：**
   - `ConvertIdTypeButtonsEvent` 会根据设备相关 ID 10 查找到对应的 `pointerId` 1。
   - 创建一个 `PointerEvent` 对象，`type` 为 `pointermove`，`pointerId` 为 1，`pointerType` 为 `touch`，更新后的 `clientX` 和 `clientY`。

**假设输出（JavaScript 可以接收到的事件）：**

1. **手指 1 按下：** 一个 `PointerEvent` 对象，属性类似于：
   ```javascript
   { type: 'pointerdown', pointerId: 1, pointerType: 'touch', clientX: ..., clientY: ... }
   ```
2. **手指 2 按下：** 一个 `PointerEvent` 对象，属性类似于：
   ```javascript
   { type: 'pointerdown', pointerId: 2, pointerType: 'touch', clientX: ..., clientY: ... }
   ```
3. **手指 1 移动：** 一个 `PointerEvent` 对象，属性类似于：
   ```javascript
   { type: 'pointermove', pointerId: 1, pointerType: 'touch', clientX: ..., clientY: ... }
   ```

**用户或编程常见的使用错误：**

1. **假设所有 pointer 事件都是鼠标事件：**  Web 开发者可能会错误地假设所有 `pointerdown` 事件都来自鼠标，而忽略了 `pointerType` 属性。这会导致在触摸或触控笔设备上出现意外行为。

   ```javascript
   // 错误的做法：
   element.addEventListener('pointerdown', (event) => {
     // 假设 event.pointerType 总是 'mouse'
     console.log('Mouse button pressed!');
   });

   // 正确的做法：
   element.addEventListener('pointerdown', (event) => {
     if (event.pointerType === 'mouse') {
       console.log('Mouse button pressed!');
     } else if (event.pointerType === 'touch') {
       console.log('Touch event started!');
     }
   });
   ```

2. **没有正确处理 `pointerId` 来追踪多个触摸点：** 当用户使用多个手指触摸屏幕时，每个触摸点都会有不同的 `pointerId`。开发者需要利用 `pointerId` 来区分和追踪不同的触摸点。

   ```javascript
   const activeTouches = {};

   element.addEventListener('pointerdown', (event) => {
     activeTouches[event.pointerId] = { x: event.clientX, y: event.clientY };
     console.log('Touch started:', event.pointerId);
   });

   element.addEventListener('pointermove', (event) => {
     if (activeTouches[event.pointerId]) {
       console.log('Touch moved:', event.pointerId, event.clientX, event.clientY);
       // 更新触摸点的位置
       activeTouches[event.pointerId].x = event.clientX;
       activeTouches[event.pointerId].y = event.clientY;
     }
   });

   element.addEventListener('pointerup', (event) => {
     delete activeTouches[event.pointerId];
     console.log('Touch ended:', event.pointerId);
   });

   element.addEventListener('pointercancel', (event) => {
     delete activeTouches[event.pointerId];
     console.log('Touch cancelled:', event.pointerId);
   });
   ```

3. **忽略 `pointercancel` 事件：**  `pointercancel` 事件表示指针输入被取消（例如，由于触摸超出屏幕范围、浏览器决定接管输入等）。开发者应该监听并处理 `pointercancel` 事件，以清理状态并避免出现意外行为。

总而言之，`pointer_event_factory.cc` 是 Blink 引擎中一个至关重要的组件，它负责将底层的指针输入转化为 Web 标准的 `PointerEvent`，使得 Web 开发者能够以统一的方式处理来自不同输入设备的事件。理解它的功能对于深入了解浏览器事件处理机制和开发跨设备兼容的 Web 应用至关重要。

Prompt: 
```
这是目录为blink/renderer/core/events/pointer_event_factory.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/events/pointer_event_factory.h"

#include "base/trace_event/trace_event.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_pointer_event_init.h"
#include "third_party/blink/renderer/core/events/pointer_event_util.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/pointer_type_names.h"
#include "ui/gfx/geometry/size_f.h"

namespace blink {

namespace {

inline int ToInt(WebPointerProperties::PointerType t) {
  return static_cast<int>(t);
}

uint16_t ButtonToButtonsBitfield(WebPointerProperties::Button button) {
#define CASE_BUTTON_TO_BUTTONS(enumLabel)       \
  case WebPointerProperties::Button::enumLabel: \
    return static_cast<uint16_t>(WebPointerProperties::Buttons::enumLabel)

  switch (button) {
    CASE_BUTTON_TO_BUTTONS(kNoButton);
    CASE_BUTTON_TO_BUTTONS(kLeft);
    CASE_BUTTON_TO_BUTTONS(kRight);
    CASE_BUTTON_TO_BUTTONS(kMiddle);
    CASE_BUTTON_TO_BUTTONS(kBack);
    CASE_BUTTON_TO_BUTTONS(kForward);
    CASE_BUTTON_TO_BUTTONS(kEraser);
  }

#undef CASE_BUTTON_TO_BUTTONS

  NOTREACHED();
}

const AtomicString& PointerEventNameForEventType(WebInputEvent::Type type) {
  switch (type) {
    case WebInputEvent::Type::kPointerDown:
      return event_type_names::kPointerdown;
    case WebInputEvent::Type::kPointerUp:
      return event_type_names::kPointerup;
    case WebInputEvent::Type::kPointerMove:
      return event_type_names::kPointermove;
    case WebInputEvent::Type::kPointerRawUpdate:
      return event_type_names::kPointerrawupdate;
    case WebInputEvent::Type::kPointerCancel:
      return event_type_names::kPointercancel;
    default:
      NOTREACHED();
  }
}

float GetPointerEventPressure(float force, uint16_t buttons) {
  if (!buttons) {
    return 0;
  }
  if (std::isnan(force)) {
    return 0.5;
  }
  return force;
}

void UpdateCommonPointerEventInit(const WebPointerEvent& web_pointer_event,
                                  const gfx::PointF& last_global_position,
                                  LocalDOMWindow* dom_window,
                                  PointerEventInit* pointer_event_init) {
  // This function should not update attributes like pointerId, isPrimary,
  // and pointerType which is the same among the coalesced events and the
  // dispatched event.

  WebPointerEvent web_pointer_event_in_root_frame =
      web_pointer_event.WebPointerEventInRootFrame();

  MouseEvent::SetCoordinatesFromWebPointerProperties(
      web_pointer_event_in_root_frame, dom_window, pointer_event_init);
  if (!web_pointer_event.is_raw_movement_event &&
      (web_pointer_event.GetType() == WebInputEvent::Type::kPointerMove ||
       web_pointer_event.GetType() == WebInputEvent::Type::kPointerRawUpdate)) {
    float device_scale_factor = 1;

    // movementX/Y is type int for pointerevent, so we still need to truncated
    // the coordinates before calculate movement.
    pointer_event_init->setMovementX(
        base::saturated_cast<int>(web_pointer_event.PositionInScreen().x() *
                                  device_scale_factor) -
        base::saturated_cast<int>(last_global_position.x() *
                                  device_scale_factor));
    pointer_event_init->setMovementY(
        base::saturated_cast<int>(web_pointer_event.PositionInScreen().y() *
                                  device_scale_factor) -
        base::saturated_cast<int>(last_global_position.y() *
                                  device_scale_factor));
  }

  // If width/height is unknown we let PointerEventInit set it to 1.
  // See https://w3c.github.io/pointerevents/#dom-pointerevent-width
  //
  // For pointerup, even known width/height is ignored in favor of the default
  // value of 1.  See https://github.com/w3c/pointerevents/issues/225.
  if (web_pointer_event_in_root_frame.HasWidth() &&
      web_pointer_event_in_root_frame.HasHeight() &&
      web_pointer_event.GetType() != WebInputEvent::Type::kPointerUp) {
    float scale_factor = 1.0f;
    if (dom_window && dom_window->GetFrame()) {
      scale_factor = 1.0f / dom_window->GetFrame()->LayoutZoomFactor();
    }

    gfx::SizeF point_shape =
        gfx::ScaleSize(gfx::SizeF(web_pointer_event_in_root_frame.width,
                                  web_pointer_event_in_root_frame.height),
                       scale_factor);
    pointer_event_init->setWidth(point_shape.width());
    pointer_event_init->setHeight(point_shape.height());
  }
  pointer_event_init->setPressure(GetPointerEventPressure(
      web_pointer_event.force, pointer_event_init->buttons()));
  pointer_event_init->setTiltX(round(web_pointer_event.tilt_x));
  pointer_event_init->setTiltY(round(web_pointer_event.tilt_y));
  pointer_event_init->setAltitudeAngle(PointerEventUtil::AltitudeFromTilt(
      web_pointer_event.tilt_x, web_pointer_event.tilt_y));
  pointer_event_init->setAzimuthAngle(PointerEventUtil::AzimuthFromTilt(
      web_pointer_event.tilt_x, web_pointer_event.tilt_y));
  pointer_event_init->setTangentialPressure(
      web_pointer_event.tangential_pressure);
  pointer_event_init->setTwist(web_pointer_event.twist);
}

}  // namespace

// static
const AtomicString& PointerEventFactory::PointerTypeNameForWebPointPointerType(
    WebPointerProperties::PointerType type) {
  // TODO(mustaq): Fix when the spec starts supporting hovering erasers.
  // See spec https://github.com/w3c/pointerevents/issues/134
  switch (type) {
    case WebPointerProperties::PointerType::kUnknown:
      return g_empty_atom;
    case WebPointerProperties::PointerType::kTouch:
      return pointer_type_names::kTouch;
    case WebPointerProperties::PointerType::kPen:
      return pointer_type_names::kPen;
    case WebPointerProperties::PointerType::kMouse:
      return pointer_type_names::kMouse;
    default:
      DUMP_WILL_BE_NOTREACHED();
      return g_empty_atom;
  }
}

HeapVector<Member<PointerEvent>> PointerEventFactory::CreateEventSequence(
    const WebPointerEvent& web_pointer_event,
    const PointerEventInit* pointer_event_init,
    const Vector<WebPointerEvent>& event_list,
    LocalDOMWindow* view) {
  AtomicString type = PointerEventNameForEventType(web_pointer_event.GetType());
  HeapVector<Member<PointerEvent>> result;

  if (!event_list.empty()) {
    // Make a copy of LastPointerPosition so we can modify it after creating
    // each coalesced event.
    gfx::PointF last_global_position =
        GetLastPointerPosition(pointer_event_init->pointerId(),
                               event_list.front(), web_pointer_event.GetType());

    for (const auto& event : event_list) {
      DCHECK_EQ(web_pointer_event.id, event.id);
      DCHECK_EQ(web_pointer_event.GetType(), event.GetType());
      DCHECK_EQ(web_pointer_event.pointer_type, event.pointer_type);

      PointerEventInit* new_event_init = PointerEventInit::Create();
      if (pointer_event_init->hasButton()) {
        new_event_init->setButton(pointer_event_init->button());
      }
      if (pointer_event_init->hasButtons()) {
        new_event_init->setButtons(pointer_event_init->buttons());
      }
      if (pointer_event_init->hasIsPrimary()) {
        new_event_init->setIsPrimary(pointer_event_init->isPrimary());
      }
      if (pointer_event_init->hasPointerId()) {
        new_event_init->setPointerId(pointer_event_init->pointerId());
      }
      if (pointer_event_init->hasPointerType()) {
        new_event_init->setPointerType(pointer_event_init->pointerType());
      }
      if (pointer_event_init->hasView()) {
        new_event_init->setView(pointer_event_init->view());
      }

      new_event_init->setCancelable(false);
      new_event_init->setBubbles(false);
      UpdateCommonPointerEventInit(event, last_global_position, view,
                                   new_event_init);
      UIEventWithKeyState::SetFromWebInputEventModifiers(
          new_event_init,
          static_cast<WebInputEvent::Modifiers>(event.GetModifiers()));

      last_global_position = event.PositionInScreen();

      if (pointer_event_init->hasPersistentDeviceId()) {
        new_event_init->setPersistentDeviceId(
            pointer_event_init->persistentDeviceId());
      }

      PointerEvent* pointer_event =
          PointerEvent::Create(type, new_event_init, event.TimeStamp());
      // Set the trusted flag for these events at the creation time as oppose to
      // the normal events which is done at the dispatch time. This is because
      // we don't want to go over all these events at every dispatch and add the
      // implementation complexity while it has no sensible usecase at this
      // time.
      pointer_event->SetTrusted(true);
      result.push_back(pointer_event);
    }
  }
  return result;
}

const PointerId PointerEventFactory::kReservedNonPointerId = -1;
const PointerId PointerEventFactory::kInvalidId = 0;

// Mouse id is 1 to behave the same as MS Edge for compatibility reasons.
const PointerId PointerEventFactory::kMouseId = 1;

PointerEventInit* PointerEventFactory::ConvertIdTypeButtonsEvent(
    const WebPointerEvent& web_pointer_event) {
  WebPointerProperties::PointerType pointer_type =
      web_pointer_event.pointer_type;

  unsigned buttons;
  if (web_pointer_event.hovering) {
    buttons = MouseEvent::WebInputEventModifiersToButtons(
        static_cast<WebInputEvent::Modifiers>(
            web_pointer_event.GetModifiers()));
  } else {
    // TODO(crbug.com/816504): This is incorrect as we are assuming pointers
    // that don't hover have no other buttons except left which represents
    // touching the screen. This misconception comes from the touch devices and
    // is not correct for stylus.
    buttons = static_cast<unsigned>(
        (web_pointer_event.GetType() == WebInputEvent::Type::kPointerUp ||
         web_pointer_event.GetType() == WebInputEvent::Type::kPointerCancel)
            ? WebPointerProperties::Buttons::kNoButton
            : WebPointerProperties::Buttons::kLeft);
  }
  // Tweak the |buttons| to reflect pen eraser mode only if the pen is in
  // active buttons state w/o even considering the eraser button.
  // TODO(mustaq): Fix when the spec starts supporting hovering erasers.
  if (pointer_type == WebPointerProperties::PointerType::kEraser) {
    if (buttons != 0) {
      buttons |= static_cast<unsigned>(WebPointerProperties::Buttons::kEraser);
      buttons &= ~static_cast<unsigned>(WebPointerProperties::Buttons::kLeft);
    }
    pointer_type = WebPointerProperties::PointerType::kPen;
  }

  const IncomingId incoming_id(pointer_type, web_pointer_event.id);
  PointerId pointer_id = AddOrUpdateIdAndActiveButtons(
      incoming_id, buttons != 0, web_pointer_event.hovering,
      web_pointer_event.GetType(), web_pointer_event.unique_touch_event_id);
  if (pointer_id == kInvalidId) {
    return nullptr;
  }

  PointerEventInit* pointer_event_init = PointerEventInit::Create();
  pointer_event_init->setButtons(buttons);
  pointer_event_init->setPointerId(pointer_id);
  pointer_event_init->setPointerType(
      PointerTypeNameForWebPointPointerType(pointer_type));
  pointer_event_init->setIsPrimary(IsPrimary(pointer_id));

  return pointer_event_init;
}

void PointerEventFactory::SetEventSpecificFields(
    PointerEventInit* pointer_event_init,
    const AtomicString& type) {
  bool is_pointer_enter_or_leave = type == event_type_names::kPointerenter ||
                                   type == event_type_names::kPointerleave;
  pointer_event_init->setBubbles(!is_pointer_enter_or_leave);
  pointer_event_init->setCancelable(
      type != event_type_names::kPointerenter &&
      type != event_type_names::kPointerleave &&
      type != event_type_names::kPointercancel &&
      type != event_type_names::kPointerrawupdate &&
      type != event_type_names::kGotpointercapture &&
      type != event_type_names::kLostpointercapture);
  pointer_event_init->setComposed(!is_pointer_enter_or_leave);
  pointer_event_init->setDetail(0);
}

PointerEvent* PointerEventFactory::Create(
    const WebPointerEvent& web_pointer_event,
    const Vector<WebPointerEvent>& coalesced_events,
    const Vector<WebPointerEvent>& predicted_events,
    LocalDOMWindow* view) {
  const WebInputEvent::Type event_type = web_pointer_event.GetType();
  DCHECK(event_type == WebInputEvent::Type::kPointerDown ||
         event_type == WebInputEvent::Type::kPointerUp ||
         event_type == WebInputEvent::Type::kPointerMove ||
         event_type == WebInputEvent::Type::kPointerRawUpdate ||
         event_type == WebInputEvent::Type::kPointerCancel);

  PointerEventInit* pointer_event_init =
      ConvertIdTypeButtonsEvent(web_pointer_event);
  if (!pointer_event_init) {
    return nullptr;
  }

  AtomicString type = PointerEventNameForEventType(event_type);
  if (event_type == WebInputEvent::Type::kPointerDown ||
      event_type == WebInputEvent::Type::kPointerUp) {
    WebPointerProperties::Button button = web_pointer_event.button;
    // TODO(mustaq): Fix when the spec starts supporting hovering erasers.
    if (web_pointer_event.pointer_type ==
            WebPointerProperties::PointerType::kEraser &&
        button == WebPointerProperties::Button::kLeft) {
      button = WebPointerProperties::Button::kEraser;
    }
    pointer_event_init->setButton(static_cast<int>(button));

    // Make sure chorded buttons fire pointermove instead of pointerup/down.
    if ((event_type == WebInputEvent::Type::kPointerDown &&
         (pointer_event_init->buttons() & ~ButtonToButtonsBitfield(button)) !=
             0) ||
        (event_type == WebInputEvent::Type::kPointerUp &&
         pointer_event_init->buttons() != 0)) {
      type = event_type_names::kPointermove;
    }
  } else {
    pointer_event_init->setButton(
        static_cast<int16_t>(WebPointerProperties::Button::kNoButton));
  }

  pointer_event_init->setView(view);
  UpdateCommonPointerEventInit(
      web_pointer_event,
      GetLastPointerPosition(pointer_event_init->pointerId(), web_pointer_event,
                             event_type),
      view, pointer_event_init);

  UIEventWithKeyState::SetFromWebInputEventModifiers(
      pointer_event_init,
      static_cast<WebInputEvent::Modifiers>(web_pointer_event.GetModifiers()));

  SetEventSpecificFields(pointer_event_init, type);

  HeapVector<Member<PointerEvent>> coalesced_pointer_events,
      predicted_pointer_events;
  if (type == event_type_names::kPointermove ||
      type == event_type_names::kPointerrawupdate) {
    coalesced_pointer_events = CreateEventSequence(
        web_pointer_event, pointer_event_init, coalesced_events, view);
  }
  if (type == event_type_names::kPointermove) {
    predicted_pointer_events = CreateEventSequence(
        web_pointer_event, pointer_event_init, predicted_events, view);
  }
  pointer_event_init->setCoalescedEvents(coalesced_pointer_events);
  pointer_event_init->setPredictedEvents(predicted_pointer_events);

  SetLastPosition(pointer_event_init->pointerId(),
                  web_pointer_event.PositionInScreen(), event_type);

  pointer_event_init->setPersistentDeviceId(
      GetBlinkDeviceId(web_pointer_event));

  return PointerEvent::Create(
      type, pointer_event_init, web_pointer_event.TimeStamp(),
      MouseEvent::kRealOrIndistinguishable, kMenuSourceNone,
      web_pointer_event.GetPreventCountingAsInteraction());
}

void PointerEventFactory::SetLastPosition(int pointer_id,
                                          const gfx::PointF& position_in_screen,
                                          WebInputEvent::Type event_type) {
  PointerAttributes attributes = pointer_id_to_attributes_.Contains(pointer_id)
                                     ? pointer_id_to_attributes_.at(pointer_id)
                                     : PointerAttributes();

  if (event_type == WebInputEvent::Type::kPointerRawUpdate) {
    attributes.last_rawupdate_position = position_in_screen;
  } else {
    attributes.last_position = position_in_screen;
  }

  pointer_id_to_attributes_.Set(pointer_id, attributes);
}

void PointerEventFactory::RemoveLastPosition(const int pointer_id) {
  PointerAttributes attributes = pointer_id_to_attributes_.at(pointer_id);
  attributes.last_position.reset();
  attributes.last_rawupdate_position.reset();
  pointer_id_to_attributes_.Set(pointer_id, attributes);
}

gfx::PointF PointerEventFactory::GetLastPointerPosition(
    int pointer_id,
    const WebPointerProperties& event,
    WebInputEvent::Type event_type) const {
  if (event_type == WebInputEvent::Type::kPointerRawUpdate) {
    if (pointer_id_to_attributes_.Contains(pointer_id) &&
        pointer_id_to_attributes_.at(pointer_id)
            .last_rawupdate_position.has_value()) {
      return pointer_id_to_attributes_.at(pointer_id)
          .last_rawupdate_position.value();
    }
  } else {
    if (pointer_id_to_attributes_.Contains(pointer_id) &&
        pointer_id_to_attributes_.at(pointer_id).last_position.has_value()) {
      return pointer_id_to_attributes_.at(pointer_id).last_position.value();
    }
  }
  // If pointer_id is not in the map, returns the current position so the
  // movement will be zero.
  return event.PositionInScreen();
}

PointerEvent* PointerEventFactory::CreatePointerCancelEvent(
    const int pointer_id,
    base::TimeTicks platfrom_time_stamp,
    const int32_t device_id) {
  CHECK(pointer_id_to_attributes_.Contains(pointer_id));
  PointerAttributes attributes(pointer_id_to_attributes_.at(pointer_id));
  attributes.is_active_buttons = false;
  attributes.hovering = true;
  pointer_id_to_attributes_.Set(pointer_id, attributes);

  PointerEventInit* pointer_event_init = PointerEventInit::Create();

  pointer_event_init->setPointerId(pointer_id);
  pointer_event_init->setPointerType(PointerTypeNameForWebPointPointerType(
      pointer_id_to_attributes_.at(pointer_id).incoming_id.GetPointerType()));
  pointer_event_init->setIsPrimary(IsPrimary(pointer_id));

  SetEventSpecificFields(pointer_event_init, event_type_names::kPointercancel);

  pointer_event_init->setPersistentDeviceId(device_id);

  return PointerEvent::Create(event_type_names::kPointercancel,
                              pointer_event_init, platfrom_time_stamp);
}

PointerEvent* PointerEventFactory::CreatePointerEventFrom(
    PointerEvent* pointer_event,
    const AtomicString& type,
    EventTarget* related_target) {
  PointerEventInit* pointer_event_init = PointerEventInit::Create();

  pointer_event_init->setPointerId(pointer_event->pointerId());
  pointer_event_init->setPointerType(pointer_event->pointerType());
  pointer_event_init->setIsPrimary(pointer_event->isPrimary());
  pointer_event_init->setWidth(pointer_event->width());
  pointer_event_init->setHeight(pointer_event->height());
  pointer_event_init->setScreenX(pointer_event->screenX());
  pointer_event_init->setScreenY(pointer_event->screenY());
  pointer_event_init->setClientX(pointer_event->clientX());
  pointer_event_init->setClientY(pointer_event->clientY());
  pointer_event_init->setButton(pointer_event->button());
  pointer_event_init->setButtons(pointer_event->buttons());
  pointer_event_init->setPressure(pointer_event->pressure());
  pointer_event_init->setTiltX(pointer_event->tiltX());
  pointer_event_init->setTiltY(pointer_event->tiltY());
  pointer_event_init->setTangentialPressure(
      pointer_event->tangentialPressure());
  pointer_event_init->setTwist(pointer_event->twist());
  pointer_event_init->setView(pointer_event->view());
  pointer_event_init->setPersistentDeviceId(
      pointer_event->persistentDeviceId());

  SetEventSpecificFields(pointer_event_init, type);

  if (const UIEventWithKeyState* key_state_event =
          FindEventWithKeyState(pointer_event)) {
    UIEventWithKeyState::SetFromWebInputEventModifiers(
        pointer_event_init, key_state_event->GetModifiers());
  }

  if (related_target) {
    pointer_event_init->setRelatedTarget(related_target);
  }

  return PointerEvent::Create(type, pointer_event_init,
                              pointer_event->PlatformTimeStamp());
}

PointerEvent* PointerEventFactory::CreatePointerRawUpdateEvent(
    PointerEvent* pointer_event) {
  // This function is for creating pointerrawupdate event from a pointerdown/up
  // event that caused by chorded buttons and hence its type is changed to
  // pointermove.
  DCHECK(pointer_event->type() == event_type_names::kPointermove &&
         (pointer_event->buttons() &
          ~ButtonToButtonsBitfield(static_cast<WebPointerProperties::Button>(
              pointer_event->button()))) != 0 &&
         pointer_event->button() != 0);

  return CreatePointerEventFrom(pointer_event,
                                event_type_names::kPointerrawupdate,
                                pointer_event->relatedTarget());
}

PointerEvent* PointerEventFactory::CreatePointerCaptureEvent(
    PointerEvent* pointer_event,
    const AtomicString& type) {
  DCHECK(type == event_type_names::kGotpointercapture ||
         type == event_type_names::kLostpointercapture);

  return CreatePointerEventFrom(pointer_event, type,
                                pointer_event->relatedTarget());
}

PointerEvent* PointerEventFactory::CreatePointerBoundaryEvent(
    PointerEvent* pointer_event,
    const AtomicString& type,
    EventTarget* related_target) {
  DCHECK(type == event_type_names::kPointerout ||
         type == event_type_names::kPointerleave ||
         type == event_type_names::kPointerover ||
         type == event_type_names::kPointerenter);

  return CreatePointerEventFrom(pointer_event, type, related_target);
}

PointerEventFactory::PointerEventFactory() {
  Clear();
}

PointerEventFactory::~PointerEventFactory() {
  Clear();
}

void PointerEventFactory::Clear() {
  for (int type = 0;
       type <= ToInt(WebPointerProperties::PointerType::kMaxValue); type++) {
    primary_id_[type] = kInvalidId;
    id_count_[type] = 0;
  }
  pointer_incoming_id_mapping_.clear();
  pointer_id_to_attributes_.clear();
  recently_removed_pointers_.clear();

  device_id_browser_to_blink_mapping_.clear();

  // Always add mouse pointer in initialization and never remove it.
  // No need to add it to |pointer_incoming_id_mapping_| as it is not going to
  // be used with the existing APIs
  primary_id_[ToInt(WebPointerProperties::PointerType::kMouse)] = kMouseId;
  PointerAttributes attributes;
  attributes.incoming_id =
      IncomingId(WebPointerProperties::PointerType::kMouse, 0);
  pointer_id_to_attributes_.insert(kMouseId, attributes);

  current_id_ = PointerEventFactory::kMouseId + 1;
  current_device_id_ = 1;
  device_id_for_mouse_ = 0;
}

PointerId PointerEventFactory::AddOrUpdateIdAndActiveButtons(
    const IncomingId p,
    bool is_active_buttons,
    bool hovering,
    WebInputEvent::Type event_type,
    uint32_t unique_touch_event_id) {
  // Do not add extra mouse pointer as it was added in initialization.
  if (p.GetPointerType() == WebPointerProperties::PointerType::kMouse) {
    PointerAttributes attributes = pointer_id_to_attributes_.at(kMouseId);
    attributes.is_active_buttons = is_active_buttons;
    pointer_id_to_attributes_.Set(kMouseId, attributes);
    return kMouseId;
  }

  if (pointer_incoming_id_mapping_.Contains(p)) {
    PointerId mapped_id = pointer_incoming_id_mapping_.at(p);
    PointerAttributes attributes = pointer_id_to_attributes_.at(mapped_id);
    CHECK(attributes.incoming_id == p);
    attributes.is_active_buttons = is_active_buttons;
    attributes.hovering = hovering;
    pointer_id_to_attributes_.Set(mapped_id, attributes);
    return mapped_id;
  }

  // TODO(crbug.com/1141595): We should filter out bad pointercancel events
  // further upstream.
  if (event_type == WebInputEvent::Type::kPointerCancel) {
    return kInvalidId;
  }

  int type_int = p.PointerTypeInt();
  PointerId mapped_id = GetNextAvailablePointerid();
  if (!id_count_[type_int]) {
    primary_id_[type_int] = mapped_id;
  }
  id_count_[type_int]++;
  pointer_incoming_id_mapping_.insert(p, mapped_id);
  pointer_id_to_attributes_.insert(
      mapped_id,
      PointerAttributes(p, is_active_buttons, hovering, unique_touch_event_id,
                        /* last_position */ std::nullopt,
                        /* last_rawupdate_position */ std::nullopt));
  return mapped_id;
}

bool PointerEventFactory::Remove(const PointerId mapped_id) {
  // Do not remove mouse pointer id as it should always be there.
  if (mapped_id == kMouseId || !pointer_id_to_attributes_.Contains(mapped_id)) {
    return false;
  }

  IncomingId p = pointer_id_to_attributes_.at(mapped_id).incoming_id;
  int type_int = p.PointerTypeInt();
  PointerAttributes attributes = pointer_id_to_attributes_.Take(mapped_id);
  pointer_incoming_id_mapping_.erase(p);
  if (primary_id_[type_int] == mapped_id) {
    primary_id_[type_int] = kInvalidId;
  }
  id_count_[type_int]--;

  SaveRecentlyRemovedPointer(mapped_id, attributes);
  return true;
}

Vector<PointerId> PointerEventFactory::GetPointerIdsOfNonHoveringPointers()
    const {
  Vector<PointerId> mapped_ids;

  for (const auto& iter : pointer_id_to_attributes_) {
    if (!iter.value.hovering) {
      mapped_ids.push_back(static_cast<PointerId>(iter.key));
    }
  }

  // Sorting for a predictable ordering.
  std::sort(mapped_ids.begin(), mapped_ids.end());
  return mapped_ids;
}

bool PointerEventFactory::IsPrimary(PointerId mapped_id) const {
  if (!pointer_id_to_attributes_.Contains(mapped_id)) {
    return false;
  }

  IncomingId p = pointer_id_to_attributes_.at(mapped_id).incoming_id;
  return primary_id_[p.PointerTypeInt()] == mapped_id;
}

bool PointerEventFactory::IsActive(const PointerId pointer_id) const {
  return pointer_id_to_attributes_.Contains(pointer_id);
}

bool PointerEventFactory::IsPrimary(
    const WebPointerProperties& properties) const {
  // Mouse event is always primary.
  if (properties.pointer_type == WebPointerProperties::PointerType::kMouse) {
    return true;
  }

  // If !id_count, no pointer active, current WebPointerEvent will
  // be primary pointer when added to map.
  if (!id_count_[static_cast<int>(properties.pointer_type)]) {
    return true;
  }

  PointerId pointer_id = GetPointerEventId(properties);
  return (pointer_id != kInvalidId && IsPrimary(pointer_id));
}

bool PointerEventFactory::IsActiveButtonsState(
    const PointerId pointer_id) const {
  return pointer_id_to_attributes_.Contains(pointer_id) &&
         pointer_id_to_attributes_.at(pointer_id).is_active_buttons;
}

WebPointerProperties::PointerType PointerEventFactory::GetPointerType(
    PointerId pointer_id) const {
  if (!IsActive(pointer_id)) {
    return WebPointerProperties::PointerType::kUnknown;
  }
  return pointer_id_to_attributes_.at(pointer_id).incoming_id.GetPointerType();
}

PointerId PointerEventFactory::GetPointerEventId(
    const WebPointerProperties& properties) const {
  if (properties.pointer_type == WebPointerProperties::PointerType::kMouse) {
    return PointerEventFactory::kMouseId;
  }
  IncomingId incoming_id(properties.pointer_type, properties.id);
  if (pointer_incoming_id_mapping_.Contains(incoming_id)) {
    return pointer_incoming_id_mapping_.at(incoming_id);
  }
  return kInvalidId;
}

PointerId PointerEventFactory::GetPointerIdForTouchGesture(
    const uint32_t unique_touch_event_id) {
  const auto& unique_touch_id_matcher =
      [](const uint32_t unique_touch_event_id,
         const blink::PointerEventFactory::PointerAttributes attributes) {
        return attributes.incoming_id.GetPointerType() ==
                   WebPointerProperties::PointerType::kTouch &&
               attributes.unique_touch_event_id == unique_touch_event_id;
      };

  // First try currently active pointers.
  for (const auto& id : pointer_id_to_attributes_.Keys()) {
    if (unique_touch_id_matcher(unique_touch_event_id,
                                pointer_id_to_attributes_.at(id))) {
      return static_cast<PointerId>(id);
    }
  }

  // Then try recently removed pointers.
  for (const auto& id_attributes_pair : recently_removed_pointers_) {
    if (unique_touch_id_matcher(unique_touch_event_id,
                                id_attributes_pair.second)) {
      return static_cast<PointerId>(id_attributes_pair.first);
    }
  }

  // If the unique id is unseen, reserve a new pointer-id and save it as
  // recently removed.
  PointerId pointer_id = GetNextAvailablePointerid();
  PointerAttributes pointer_attributes;
  pointer_attributes.incoming_id =
      IncomingId(WebPointerProperties::PointerType::kTouch, kInvalidId);
  SaveRecentlyRemovedPointer(pointer_id, pointer_attributes);

  return pointer_id;
}

void PointerEventFactory::SaveRecentlyRemovedPointer(
    PointerId pointer_id,
    PointerAttributes pointer_attributes) {
  if (recently_removed_pointers_.size() == kRemovedPointersCapacity) {
    recently_removed_pointers_.pop_front();
  }
  recently_removed_pointers_.emplace_back(pointer_id, pointer_attributes);
}

int32_t PointerEventFactory::GetBlinkDeviceId(
    const WebPointerEvent& web_pointer_event) {
  if (web_pointer_event.pointer_type ==
      WebPointerProperties::PointerType::kMouse) {
    if (device_id_for_mouse_ == 0) {
      device_id_for_mouse_ = current_device_id_++;
    }
    return device_id_for_mouse_;
  }

  const int32_t incoming_id = web_pointer_event.device_id;
  // Invalid device id in browser is -1, however, an invalid uniqueId
  // is 0 as per the PointerEvent specification.
  if (incoming_id == -1) {
    return 0;
  }

  auto result = device_id_browser_to_blink_mapping_.insert(incoming_id, 0);
  if (result.is_new_entry) {
    result.stored_value->value = current_device_id_++;
  }
  TRACE_EVENT_INSTANT1("event", "PointerEventFactory::GetBlinkDeviceId",
                       TRACE_EVENT_SCOPE_THREAD, "id",
                       result.stored_value->value);
  return result.stored_value->value;
}

PointerId PointerEventFactory::GetNextAvailablePointerid() {
  // We do not handle the overflow of |current_id_| as it should be very rare.
  return current_id_++;
}

}  // namespace blink

"""

```