Response: Let's break down the thought process for analyzing this C++ code and fulfilling the prompt's requirements.

**1. Understanding the Core Purpose:**

The file name `web_coalesced_input_event_mojom_traits.cc` and the inclusion of `<memory>`, `base/time/time.h`, and headers from `third_party/blink/public/common/input` immediately suggest this code deals with *input events* within the Blink rendering engine. The "mojom_traits" part hints at a serialization/deserialization mechanism, likely related to Mojo, Chromium's inter-process communication system. "Coalesced" implies combining or merging related events.

Therefore, the primary function is likely to convert Blink's C++ input event objects (like `WebKeyboardEvent`, `WebMouseEvent`, `WebGestureEvent`) to and from a data format suitable for sending across process boundaries using Mojo.

**2. Identifying Key Data Structures and Operations:**

Scanning the code reveals several important elements:

* **`blink::WebCoalescedInputEvent`:** The central class being handled.
* **`blink::WebInputEvent` (and its subclasses):** The actual input events.
* **Mojo data structures (`blink::mojom::...Ptr`):**  Representations of the input events for IPC.
* **`StructTraits`:** The mechanism used by Mojo for custom serialization/deserialization.
* **`Read()` function:** Deserializes a Mojo representation back into a `WebCoalescedInputEvent`.
* **Static member functions (e.g., `key_data`, `pointer_data`, `gesture_data`, `touch_data`):** Serialize parts of the `WebCoalescedInputEvent` into Mojo data structures.
* **Helper functions (e.g., `PointerDataFromPointerProperties`, `PointerPropertiesFromPointerData`):**  Handle the conversion of common properties.

**3. Analyzing the `Read()` Function (Deserialization):**

This function is crucial for understanding how incoming Mojo messages are transformed into Blink's internal event objects. The logic follows a clear pattern:

* **Read the event type:**  Determines which specific event class to create.
* **Read common properties:** `timestamp`, `modifiers`.
* **Switch on event type:**  Handles the specific data associated with each event type (keyboard, gesture, mouse, touch).
* **Read event-specific data:** Uses `event.ReadKeyData`, `event.ReadGestureData`, etc., to extract the relevant information from the Mojo message.
* **Populate the Blink event object:** Sets the properties of the newly created `Web*Event` object based on the deserialized data.
* **Handle latency information:** Reads and sets `EventLatencyMetadata` and `LatencyInfo`.

**4. Analyzing the Static Member Functions (Serialization):**

These functions perform the reverse operation of `Read()`. They take a `WebCoalescedInputEvent` and extract its relevant data to populate the corresponding Mojo data structures. The structure mirrors the `Read()` function's switch statement.

**5. Connecting to JavaScript, HTML, and CSS:**

This is where the understanding of Blink's role comes in. Blink is the rendering engine responsible for interpreting HTML, CSS, and running JavaScript. Input events are the primary way users interact with web pages. Therefore, this code is *fundamental* to how user actions in the browser are conveyed to the web page.

* **JavaScript:**  JavaScript event listeners react to these events. The serialized data needs to accurately represent the user's actions so JavaScript can respond correctly.
* **HTML:** HTML elements are the targets of these events. The position of the mouse click, the target of a touch, etc., are crucial for determining which element receives the event.
* **CSS:** CSS can influence how elements react to events (e.g., `:hover` effects). While this code doesn't directly manipulate CSS, it provides the underlying event data that triggers CSS changes.

**6. Formulating Examples:**

Based on the understanding of the code's purpose and its relationship to web technologies, concrete examples can be created.

* **Keyboard:**  Pressing a key generates a `WebKeyboardEvent`. The `key_data` function serializes information like `dom_key` (the character) and `native_key_code` (hardware key). This is how JavaScript knows what key was pressed.
* **Mouse:** A mouse click generates a `WebMouseEvent`. The `pointer_data` function serializes the position, button pressed, and click count. This is how a button click on a web page is detected.
* **Touch:** Touching the screen generates a `WebTouchEvent`. The `touch_data` function serializes the position, pressure, and touch state of each touch point. This enables touch interactions on web pages.
* **Gesture:**  Swiping or pinching generates `WebGestureEvent`s. The `gesture_data` function serializes information about the type of gesture (scroll, pinch, tap) and its properties (delta, scale, etc.). This allows web pages to respond to complex touch gestures.

**7. Identifying Potential User/Programming Errors:**

Consider the constraints and the nature of the data being handled.

* **Incorrect Mojo definitions:** If the Mojo definitions in the `.mojom` file don't match the C++ structures, serialization/deserialization will fail.
* **Data loss during conversion:**  If information isn't properly mapped between the Blink event and the Mojo representation, data can be lost.
* **Incorrect type handling:**  If the `Read()` function doesn't correctly handle different event types, it could lead to crashes or unexpected behavior.
* **Array bounds:** The code uses fixed-size arrays for touch points and text. Not checking or handling potential overflows could lead to buffer overflows.

**8. Hypothetical Input/Output:**

Choose a specific event type and illustrate the serialization/deserialization process.

* **Input:** A `WebMouseEvent` representing a left-click at a specific position.
* **Mojo representation:** Show the corresponding `blink::mojom::EventDataPtr` and `blink::mojom::PointerDataPtr` with the relevant fields populated.
* **Output:** The deserialized `WebCoalescedInputEvent` containing a `WebMouseEvent` with the correct properties.

**Self-Correction/Refinement during the process:**

* Initially, I might focus too much on the low-level details of the Mojo serialization. I'd need to step back and remember the *purpose* of this code within the broader Blink architecture.
* I might initially miss the connection to specific web technologies. I'd need to think about *how* these events are used in web development.
* I'd need to ensure my examples are clear and illustrate the key data being transferred.
* I would double-check the code comments and copyright notice for additional clues about the code's context.

By following these steps, I can systematically analyze the C++ code and address all the requirements of the prompt, providing a comprehensive explanation of its functionality and its relevance to web technologies.
这个文件 `blink/common/input/web_coalesced_input_event_mojom_traits.cc` 的主要功能是 **定义了如何在 Blink 渲染引擎内部，将 `blink::WebCoalescedInputEvent` 对象及其包含的各种输入事件（如键盘事件、鼠标事件、触摸事件、手势事件）与 Mojo 中定义的相应数据结构 (`blink::mojom::EventDataView`) 之间进行序列化和反序列化。**

Mojo 是 Chromium 中用于跨进程通信的机制。这个文件充当了一个桥梁，使得输入事件数据可以在不同的进程之间安全有效地传递。

具体来说，这个文件做了以下事情：

1. **定义了 `StructTraits` 特化:**  `StructTraits` 是 Mojo 提供的一种机制，允许开发者为自定义的 C++ 类型指定如何进行序列化和反序列化。这个文件为 `blink::mojom::EventDataView` 和 `std::unique_ptr<blink::WebCoalescedInputEvent>` 提供了特化。

2. **实现 `Read` 函数 (反序列化):**  这个函数负责从 `blink::mojom::EventDataView` 中读取数据，并构建出一个 `std::unique_ptr<blink::WebCoalescedInputEvent>` 对象。它会根据事件的类型（键盘、鼠标、触摸、手势）读取不同的数据，并填充到对应的 `blink::WebInputEvent` 子类中。

3. **实现静态成员函数 (序列化):**  这些静态成员函数（如 `key_data`, `pointer_data`, `gesture_data`, `touch_data`）负责从 `blink::WebCoalescedInputEvent` 对象中提取不同类型的事件数据，并将其转换为相应的 Mojo 数据结构 (`blink::mojom::KeyDataPtr`, `blink::mojom::PointerDataPtr` 等)。

**与 JavaScript, HTML, CSS 的关系：**

这个文件虽然是用 C++ 编写的，并且直接处理的是 Blink 引擎内部的数据结构，但它与 JavaScript, HTML, CSS 的功能息息相关。

* **输入事件的传递桥梁:** 当用户在网页上进行操作时（例如，按下键盘按键、移动鼠标、触摸屏幕），浏览器会捕获这些事件。这些底层的操作系统事件会被转换为 Blink 引擎内部的 `WebInputEvent` 对象。  `web_coalesced_input_event_mojom_traits.cc` 中定义的序列化机制使得这些事件数据能够被传递到渲染进程中的其他组件，最终被 JavaScript 代码处理。

* **JavaScript 事件处理:** JavaScript 代码通过事件监听器来响应用户的输入。例如：
    ```javascript
    document.addEventListener('keydown', function(event) {
      console.log('按下了键盘按键:', event.key);
    });

    document.addEventListener('click', function(event) {
      console.log('点击了鼠标，位置:', event.clientX, event.clientY);
    });
    ```
    这些 JavaScript 事件对象（例如 `KeyboardEvent`, `MouseEvent`）的底层数据就是通过 `web_coalesced_input_event_mojom_traits.cc` 序列化和反序列化的信息构建出来的。例如，`event.key` 的值来源于反序列化后的 `WebKeyboardEvent` 中的 `dom_key` 字段。

* **HTML 元素的交互:**  HTML 元素定义了网页的结构，用户与之进行交互。`web_coalesced_input_event_mojom_traits.cc` 确保了当用户与特定的 HTML 元素交互时，正确的事件信息（例如，点击事件发生在哪里）能够被传递到 JavaScript 进行处理。

* **CSS 和事件相关的伪类:**  CSS 中存在一些与事件相关的伪类，例如 `:hover`, `:active`, `:focus`。当鼠标悬停在元素上、元素被点击时或元素获得焦点时，这些伪类的状态会发生改变，从而改变元素的样式。这些状态的改变依赖于底层的鼠标事件和焦点事件的正确传递，而 `web_coalesced_input_event_mojom_traits.cc` 在其中扮演了关键角色。

**逻辑推理与假设输入输出：**

**假设输入:**  一个渲染进程接收到一个来自浏览器进程的 Mojo 消息，其中包含一个 `blink::mojom::EventDataView`，该消息描述了一个按下 "A" 键的键盘事件。

**反序列化过程 (在 `Read` 函数中):**

1. **读取事件类型:** `ReadType` 读取到事件类型为 `blink::WebInputEvent::Type::kKeyDown`。
2. **读取时间戳和修饰符:** 读取到事件发生的时间和是否有 Shift、Ctrl 等修饰键按下。
3. **读取键盘数据:** `ReadKeyData` 读取到 `blink::mojom::KeyDataPtr`，其中包含：
   - `dom_key`: "a"
   - `dom_code`:  例如 "KeyA"
   - `windows_key_code`:  例如 65
   - `native_key_code`:  具体的硬件键码
   - `is_system_key`:  是否是系统按键
   - `is_browser_shortcut`: 是否是浏览器快捷键
   - `text`: "a"
   - `unmodified_text`: "a"
4. **创建 `WebKeyboardEvent`:**  创建一个 `blink::WebKeyboardEvent` 对象，并将读取到的数据填充进去。
5. **创建 `WebCoalescedInputEvent`:** 将创建的 `WebKeyboardEvent` 封装到 `WebCoalescedInputEvent` 中。

**输出:**  `Read` 函数返回一个 `std::unique_ptr<blink::WebCoalescedInputEvent>`，其中包含一个 `WebKeyboardEvent` 对象，该对象准确地描述了按下 "A" 键的事件。

**序列化过程 (例如在发送事件到其他进程时):**

**假设输入:**  一个 `WebCoalescedInputEvent` 对象，其中包含一个 `WebMouseEvent`，描述了在网页坐标 (100, 200) 处发生的鼠标左键点击事件。

**序列化过程 (例如在 `pointer_data` 函数中):**

1. **检查事件类型:** 确定是鼠标事件。
2. **提取鼠标数据:** 从 `WebMouseEvent` 中提取位置 (`PositionInWidget`, `PositionInScreen`)，按钮 (`button`)，点击次数 (`click_count`) 等信息。
3. **创建 `blink::mojom::PointerDataPtr`:** 创建一个 `blink::mojom::PointerDataPtr` 对象，并将提取到的鼠标信息填充进去。
4. **创建 `blink::mojom::MouseDataPtr`:** 创建一个 `blink::mojom::MouseDataPtr` 对象，包含点击次数等信息。
5. **返回 `blink::mojom::PointerDataPtr`:**  `pointer_data` 函数返回构建好的 `blink::mojom::PointerDataPtr`。
6. **`EventDataView` 的填充:**  在更高层的代码中，这个 `blink::mojom::PointerDataPtr` 会被写入到 `blink::mojom::EventDataView` 中，以便通过 Mojo 发送。

**输出:**  一个 `blink::mojom::EventDataView` 对象，其中包含了序列化后的鼠标事件数据，可以安全地通过 Mojo 发送。

**用户或编程常见的使用错误：**

1. **Mojo 定义不匹配:**  如果在 `.mojom` 文件中定义的 `EventDataView` 或其相关数据结构的字段与 `web_coalesced_input_event_mojom_traits.cc` 中的序列化/反序列化逻辑不一致，会导致数据丢失或程序崩溃。例如，如果在 Mojo 中添加了一个新的鼠标事件属性，但没有更新 `pointer_data` 函数来序列化它，那么这个属性的值在进程间传递时会丢失。

2. **类型转换错误:**  在 `Read` 函数中，需要根据事件类型正确地将 Mojo 数据转换为对应的 `WebInputEvent` 子类。如果类型判断或转换出现错误，可能会导致创建错误的事件对象或访问不存在的成员，引发运行时错误。

3. **数组越界访问:**  在处理触摸事件时，`WebTouchEvent` 有固定大小的数组来存储触摸点信息 (`touches`)。如果收到的触摸点数量超过了这个限制，并且代码中没有进行适当的检查，可能会发生数组越界访问，导致程序崩溃。例如，代码中使用 `i < blink::WebTouchEvent::kTouchesLengthCap` 来限制触摸点的数量，如果开发者错误地忽略了这个限制，就可能导致问题。

4. **忘记处理新的事件类型:**  当 Blink 中引入新的输入事件类型时，需要在 `Read` 函数和相应的序列化函数中添加对新类型的处理逻辑。如果忘记添加，新的事件类型将无法被正确地序列化和反序列化，导致相关功能失效。例如，如果添加了一个新的手势事件类型，需要在 `Read` 函数的 `IsGestureEventType` 分支中添加对应的处理代码，并在 `gesture_data` 函数中添加新的 case。

这个文件是 Blink 引擎处理输入事件的核心组成部分，它确保了用户在网页上的操作能够被准确地捕获、传递和处理，最终驱动 JavaScript 代码的执行和网页的交互行为。

### 提示词
```
这是目录为blink/common/input/web_coalesced_input_event_mojom_traits.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/input/web_coalesced_input_event_mojom_traits.h"

#include <memory>

#include "base/containers/contains.h"
#include "base/strings/string_util.h"
#include "base/time/time.h"
#include "mojo/public/cpp/base/time_mojom_traits.h"
#include "third_party/blink/public/common/input/web_gesture_event.h"
#include "third_party/blink/public/common/input/web_keyboard_event.h"
#include "third_party/blink/public/common/input/web_mouse_wheel_event.h"
#include "ui/events/mojom/event_latency_metadata_mojom_traits.h"
#include "ui/latency/mojom/latency_info_mojom_traits.h"

namespace mojo {
namespace {

blink::mojom::PointerDataPtr PointerDataFromPointerProperties(
    const blink::WebPointerProperties& pointer,
    blink::mojom::MouseDataPtr mouse_data) {
  return blink::mojom::PointerData::New(
      pointer.id, pointer.force, pointer.tilt_x, pointer.tilt_y,
      pointer.tangential_pressure, pointer.twist, pointer.button,
      pointer.pointer_type, pointer.movement_x, pointer.movement_y,
      pointer.is_raw_movement_event, pointer.PositionInWidget(),
      pointer.PositionInScreen(), std::move(mouse_data), pointer.device_id);
}

void PointerPropertiesFromPointerData(
    const blink::mojom::PointerDataPtr& pointer_data,
    blink::WebPointerProperties* pointer_properties) {
  pointer_properties->id = pointer_data->pointer_id;
  pointer_properties->force = pointer_data->force;
  pointer_properties->tilt_x = pointer_data->tilt_x;
  pointer_properties->tilt_y = pointer_data->tilt_y;
  pointer_properties->tangential_pressure = pointer_data->tangential_pressure;
  pointer_properties->twist = pointer_data->twist;
  pointer_properties->button = pointer_data->button;
  pointer_properties->pointer_type = pointer_data->pointer_type;
  pointer_properties->movement_x = pointer_data->movement_x;
  pointer_properties->movement_y = pointer_data->movement_y;
  pointer_properties->is_raw_movement_event =
      pointer_data->is_raw_movement_event;
  pointer_properties->device_id = pointer_data->device_id;
}

void TouchPointPropertiesFromPointerData(
    const blink::mojom::TouchPointPtr& mojo_touch_point,
    blink::WebTouchPoint* touch_point) {
  PointerPropertiesFromPointerData(mojo_touch_point->pointer_data, touch_point);
  touch_point->state = mojo_touch_point->state;
  touch_point->radius_x = mojo_touch_point->radius_x;
  touch_point->radius_y = mojo_touch_point->radius_y;
  touch_point->rotation_angle = mojo_touch_point->rotation_angle;
  touch_point->SetPositionInWidget(
      mojo_touch_point->pointer_data->widget_position.x(),
      mojo_touch_point->pointer_data->widget_position.y());
  touch_point->SetPositionInScreen(
      mojo_touch_point->pointer_data->screen_position.x(),
      mojo_touch_point->pointer_data->screen_position.y());
}

// TODO(dtapuska): Remove once SetPositionInXXX moves to WebPointerProperties.
void MouseEventPropertiesFromPointerData(
    const blink::mojom::PointerDataPtr& pointer_data,
    blink::WebMouseEvent* mouse_event) {
  PointerPropertiesFromPointerData(pointer_data, mouse_event);
  mouse_event->SetPositionInWidget(pointer_data->widget_position.x(),
                                   pointer_data->widget_position.y());
  mouse_event->SetPositionInScreen(pointer_data->screen_position.x(),
                                   pointer_data->screen_position.y());
}

}  // namespace

bool StructTraits<blink::mojom::EventDataView,
                  std::unique_ptr<blink::WebCoalescedInputEvent>>::
    Read(blink::mojom::EventDataView event,
         std::unique_ptr<blink::WebCoalescedInputEvent>* out) {
  DCHECK(!out->get());

  blink::WebInputEvent::Type type;
  if (!event.ReadType(&type))
    return false;

  base::TimeTicks timestamp;
  if (!event.ReadTimestamp(&timestamp))
    return false;

  std::unique_ptr<blink::WebInputEvent> input_event;
  if (blink::WebInputEvent::IsKeyboardEventType(type)) {
    blink::mojom::KeyDataPtr key_data;
    if (!event.ReadKeyData<blink::mojom::KeyDataPtr>(&key_data))
      return false;

    input_event = std::make_unique<blink::WebKeyboardEvent>(
        type, event.modifiers(), timestamp);

    blink::WebKeyboardEvent* key_event =
        static_cast<blink::WebKeyboardEvent*>(input_event.get());
    key_event->windows_key_code = key_data->windows_key_code;
    key_event->native_key_code = key_data->native_key_code;
    key_event->dom_code = key_data->dom_code;
    key_event->dom_key = key_data->dom_key;
    key_event->is_system_key = key_data->is_system_key;
    key_event->is_browser_shortcut = key_data->is_browser_shortcut;
    base::u16cstrlcpy(key_event->text.data(), key_data->text.c_str(),
                      blink::WebKeyboardEvent::kTextLengthCap);
    base::u16cstrlcpy(key_event->unmodified_text.data(),
                      key_data->unmodified_text.c_str(),
                      blink::WebKeyboardEvent::kTextLengthCap);
  } else if (blink::WebInputEvent::IsGestureEventType(type)) {
    blink::mojom::GestureDataPtr gesture_data;
    if (!event.ReadGestureData<blink::mojom::GestureDataPtr>(&gesture_data))
      return false;
    input_event = std::make_unique<blink::WebGestureEvent>(
        type, event.modifiers(), timestamp, gesture_data->source_device);

    blink::WebGestureEvent* gesture_event =
        static_cast<blink::WebGestureEvent*>(input_event.get());
    gesture_event->SetPositionInWidget(gesture_data->widget_position);
    gesture_event->SetPositionInScreen(gesture_data->screen_position);
    gesture_event->is_source_touch_event_set_blocking =
        gesture_data->is_source_touch_event_set_blocking;
    gesture_event->primary_pointer_type = gesture_data->primary_pointer_type;
    gesture_event->primary_unique_touch_event_id =
        gesture_data->primary_unique_touch_event_id;
    gesture_event->SetSourceDevice(gesture_data->source_device);
    gesture_event->unique_touch_event_id = gesture_data->unique_touch_event_id;

    if (gesture_data->contact_size) {
      switch (type) {
        default:
          break;
        case blink::WebInputEvent::Type::kGestureTapDown:
          gesture_event->data.tap_down.width =
              gesture_data->contact_size->width();
          gesture_event->data.tap_down.height =
              gesture_data->contact_size->height();
          break;
        case blink::WebInputEvent::Type::kGestureShowPress:
          gesture_event->data.show_press.width =
              gesture_data->contact_size->width();
          gesture_event->data.show_press.height =
              gesture_data->contact_size->height();
          break;
        case blink::WebInputEvent::Type::kGestureTap:
        case blink::WebInputEvent::Type::kGestureTapUnconfirmed:
        case blink::WebInputEvent::Type::kGestureDoubleTap:
          gesture_event->data.tap.width = gesture_data->contact_size->width();
          gesture_event->data.tap.height = gesture_data->contact_size->height();
          break;
        case blink::WebInputEvent::Type::kGestureShortPress:
        case blink::WebInputEvent::Type::kGestureLongPress:
        case blink::WebInputEvent::Type::kGestureLongTap:
          gesture_event->data.long_press.width =
              gesture_data->contact_size->width();
          gesture_event->data.long_press.height =
              gesture_data->contact_size->height();
          break;
        case blink::WebInputEvent::Type::kGestureTwoFingerTap:
          gesture_event->data.two_finger_tap.first_finger_width =
              gesture_data->contact_size->width();
          gesture_event->data.two_finger_tap.first_finger_height =
              gesture_data->contact_size->height();
          break;
      }
    }

    if (gesture_data->scroll_data) {
      switch (type) {
        default:
          break;
        case blink::WebInputEvent::Type::kGestureScrollBegin:
          gesture_event->data.scroll_begin.delta_x_hint =
              gesture_data->scroll_data->delta_x;
          gesture_event->data.scroll_begin.delta_y_hint =
              gesture_data->scroll_data->delta_y;
          gesture_event->data.scroll_begin.delta_hint_units =
              gesture_data->scroll_data->delta_units;
          gesture_event->data.scroll_begin.target_viewport =
              gesture_data->scroll_data->target_viewport;
          gesture_event->data.scroll_begin.inertial_phase =
              gesture_data->scroll_data->inertial_phase;
          gesture_event->data.scroll_begin.synthetic =
              gesture_data->scroll_data->synthetic;
          gesture_event->data.scroll_begin.pointer_count =
              gesture_data->scroll_data->pointer_count;
          gesture_event->data.scroll_begin.cursor_control =
              gesture_data->scroll_data->cursor_control;
          break;
        case blink::WebInputEvent::Type::kGestureScrollEnd:
          gesture_event->data.scroll_end.delta_units =
              gesture_data->scroll_data->delta_units;
          gesture_event->data.scroll_end.inertial_phase =
              gesture_data->scroll_data->inertial_phase;
          gesture_event->data.scroll_end.synthetic =
              gesture_data->scroll_data->synthetic;
          break;
        case blink::WebInputEvent::Type::kGestureScrollUpdate:
          gesture_event->data.scroll_update.delta_x =
              gesture_data->scroll_data->delta_x;
          gesture_event->data.scroll_update.delta_y =
              gesture_data->scroll_data->delta_y;
          gesture_event->data.scroll_update.delta_units =
              gesture_data->scroll_data->delta_units;
          gesture_event->data.scroll_update.inertial_phase =
              gesture_data->scroll_data->inertial_phase;
          break;
      }
    }

    if (gesture_data->pinch_begin_data &&
        type == blink::WebInputEvent::Type::kGesturePinchBegin) {
      gesture_event->data.pinch_begin.needs_wheel_event =
          gesture_data->pinch_begin_data->needs_wheel_event;
    }

    if (gesture_data->pinch_update_data &&
        type == blink::WebInputEvent::Type::kGesturePinchUpdate) {
      gesture_event->data.pinch_update.zoom_disabled =
          gesture_data->pinch_update_data->zoom_disabled;
      gesture_event->data.pinch_update.scale =
          gesture_data->pinch_update_data->scale;
      gesture_event->data.pinch_update.needs_wheel_event =
          gesture_data->pinch_update_data->needs_wheel_event;
    }

    if (gesture_data->pinch_end_data &&
        type == blink::WebInputEvent::Type::kGesturePinchEnd) {
      gesture_event->data.pinch_end.needs_wheel_event =
          gesture_data->pinch_end_data->needs_wheel_event;
    }

    if (gesture_data->tap_data) {
      switch (type) {
        default:
          break;
        case blink::WebInputEvent::Type::kGestureTap:
        case blink::WebInputEvent::Type::kGestureTapUnconfirmed:
        case blink::WebInputEvent::Type::kGestureDoubleTap:
          gesture_event->data.tap.tap_count = gesture_data->tap_data->tap_count;
          gesture_event->data.tap.needs_wheel_event =
              gesture_data->tap_data->needs_wheel_event;
          break;
      }
    }

    if (gesture_data->tap_down_data &&
        type == blink::WebInputEvent::Type::kGestureTapDown) {
      gesture_event->data.tap_down.tap_down_count =
          gesture_data->tap_down_data->tap_down_count;
    }

    if (gesture_data->fling_data) {
      switch (type) {
        default:
          break;
        case blink::WebInputEvent::Type::kGestureFlingStart:
          gesture_event->data.fling_start.velocity_x =
              gesture_data->fling_data->velocity_x;
          gesture_event->data.fling_start.velocity_y =
              gesture_data->fling_data->velocity_y;
          gesture_event->data.fling_start.target_viewport =
              gesture_data->fling_data->target_viewport;
          break;
        case blink::WebInputEvent::Type::kGestureFlingCancel:
          gesture_event->data.fling_cancel.target_viewport =
              gesture_data->fling_data->target_viewport;
          gesture_event->data.fling_cancel.prevent_boosting =
              gesture_data->fling_data->prevent_boosting;
          break;
      }
    }

  } else if (blink::WebInputEvent::IsTouchEventType(type)) {
    blink::mojom::TouchDataPtr touch_data;
    if (!event.ReadTouchData<blink::mojom::TouchDataPtr>(&touch_data))
      return false;

    input_event = std::make_unique<blink::WebTouchEvent>(
        type, event.modifiers(), timestamp);

    blink::WebTouchEvent* touch_event =
        static_cast<blink::WebTouchEvent*>(input_event.get());
    std::vector<blink::mojom::TouchPointPtr> touches;
    unsigned i;
    for (i = 0; i < touch_data->touches.size() &&
                i < blink::WebTouchEvent::kTouchesLengthCap;
         ++i) {
      blink::WebTouchPoint& touch_point = touch_event->touches[i];
      TouchPointPropertiesFromPointerData(touch_data->touches[i], &touch_point);
    }

    touch_event->touches_length = i;
    touch_event->dispatch_type = touch_data->cancelable;
    touch_event->moved_beyond_slop_region =
        touch_data->moved_beyond_slop_region;
    touch_event->hovering = touch_data->hovering;
    touch_event->touch_start_or_first_touch_move =
        touch_data->touch_start_or_first_move;
    touch_event->unique_touch_event_id = touch_data->unique_touch_event_id;
  } else if (blink::WebInputEvent::IsMouseEventType(type) ||
             type == blink::WebInputEvent::Type::kMouseWheel) {
    blink::mojom::PointerDataPtr pointer_data;
    if (!event.ReadPointerData<blink::mojom::PointerDataPtr>(&pointer_data))
      return false;

    if (blink::WebInputEvent::IsMouseEventType(type)) {
      input_event = std::make_unique<blink::WebMouseEvent>(
          type, event.modifiers(), timestamp);
    } else {
      input_event = std::make_unique<blink::WebMouseWheelEvent>(
          type, event.modifiers(), timestamp);
    }

    blink::WebMouseEvent* mouse_event =
        static_cast<blink::WebMouseEvent*>(input_event.get());

    MouseEventPropertiesFromPointerData(pointer_data, mouse_event);
    if (pointer_data->mouse_data) {
      mouse_event->click_count = pointer_data->mouse_data->click_count;

      if (type == blink::WebInputEvent::Type::kMouseWheel &&
          pointer_data->mouse_data->wheel_data) {
        blink::WebMouseWheelEvent* wheel_event =
            static_cast<blink::WebMouseWheelEvent*>(mouse_event);
        blink::mojom::WheelDataPtr& wheel_data =
            pointer_data->mouse_data->wheel_data;
        wheel_event->delta_x = wheel_data->delta_x;
        wheel_event->delta_y = wheel_data->delta_y;
        wheel_event->wheel_ticks_x = wheel_data->wheel_ticks_x;
        wheel_event->wheel_ticks_y = wheel_data->wheel_ticks_y;
        wheel_event->acceleration_ratio_x = wheel_data->acceleration_ratio_x;
        wheel_event->acceleration_ratio_y = wheel_data->acceleration_ratio_y;
        wheel_event->phase =
            static_cast<blink::WebMouseWheelEvent::Phase>(wheel_data->phase);
        wheel_event->momentum_phase =
            static_cast<blink::WebMouseWheelEvent::Phase>(
                wheel_data->momentum_phase);
        wheel_event->dispatch_type = wheel_data->cancelable;
        wheel_event->event_action =
            static_cast<blink::WebMouseWheelEvent::EventAction>(
                wheel_data->event_action);
        wheel_event->delta_units =
            static_cast<ui::ScrollGranularity>(wheel_data->delta_units);
      }
    }

  } else {
    return false;
  }

  ui::EventLatencyMetadata event_latency_metadata;
  if (!event.ReadEventLatencyMetadata(&event_latency_metadata)) {
    return false;
  }
  input_event->GetModifiableEventLatencyMetadata() =
      std::move(event_latency_metadata);
  ui::LatencyInfo latency_info;
  if (!event.ReadLatency(&latency_info))
    return false;
  *out = std::make_unique<blink::WebCoalescedInputEvent>(std::move(input_event),
                                                         latency_info);
  return true;
}

// static
blink::mojom::KeyDataPtr
StructTraits<blink::mojom::EventDataView,
             std::unique_ptr<blink::WebCoalescedInputEvent>>::
    key_data(const std::unique_ptr<blink::WebCoalescedInputEvent>& event) {
  if (!blink::WebInputEvent::IsKeyboardEventType(event->Event().GetType()))
    return nullptr;
  const blink::WebKeyboardEvent* key_event =
      static_cast<const blink::WebKeyboardEvent*>(event->EventPointer());
  // Assure std::array<char16_t, N> fields are nul-terminated before converting
  // them to std::u16string.
  CHECK(base::Contains(key_event->text, 0));
  CHECK(base::Contains(key_event->unmodified_text, 0));
  return blink::mojom::KeyData::New(
      key_event->dom_key, key_event->dom_code, key_event->windows_key_code,
      key_event->native_key_code, key_event->is_system_key,
      key_event->is_browser_shortcut, key_event->text.data(),
      key_event->unmodified_text.data());
}

// static
blink::mojom::PointerDataPtr
StructTraits<blink::mojom::EventDataView,
             std::unique_ptr<blink::WebCoalescedInputEvent>>::
    pointer_data(const std::unique_ptr<blink::WebCoalescedInputEvent>& event) {
  bool is_wheel_event =
      event->Event().GetType() == blink::WebInputEvent::Type::kMouseWheel;
  if (!blink::WebInputEvent::IsMouseEventType(event->Event().GetType()) &&
      !is_wheel_event) {
    return nullptr;
  }
  const blink::WebMouseEvent* mouse_event =
      static_cast<const blink::WebMouseEvent*>(event->EventPointer());

  blink::mojom::WheelDataPtr wheel_data;
  if (is_wheel_event) {
    const blink::WebMouseWheelEvent* wheel_event =
        static_cast<const blink::WebMouseWheelEvent*>(mouse_event);
    wheel_data = blink::mojom::WheelData::New(
        wheel_event->delta_x, wheel_event->delta_y, wheel_event->wheel_ticks_x,
        wheel_event->wheel_ticks_y, wheel_event->acceleration_ratio_x,
        wheel_event->acceleration_ratio_y, wheel_event->phase,
        wheel_event->momentum_phase, wheel_event->dispatch_type,
        static_cast<uint8_t>(wheel_event->event_action),
        static_cast<uint8_t>(wheel_event->delta_units));
  }

  return PointerDataFromPointerProperties(
      *mouse_event, blink::mojom::MouseData::New(mouse_event->click_count,
                                                 std::move(wheel_data)));
}

// static
blink::mojom::GestureDataPtr
StructTraits<blink::mojom::EventDataView,
             std::unique_ptr<blink::WebCoalescedInputEvent>>::
    gesture_data(const std::unique_ptr<blink::WebCoalescedInputEvent>& event) {
  if (!blink::WebInputEvent::IsGestureEventType(event->Event().GetType()))
    return nullptr;
  const blink::WebGestureEvent* gesture_event =
      static_cast<const blink::WebGestureEvent*>(event->EventPointer());
  auto gesture_data = blink::mojom::GestureData::New();
  gesture_data->screen_position = gesture_event->PositionInScreen();
  gesture_data->widget_position = gesture_event->PositionInWidget();
  gesture_data->source_device = gesture_event->SourceDevice();
  gesture_data->is_source_touch_event_set_blocking =
      gesture_event->is_source_touch_event_set_blocking;
  gesture_data->primary_pointer_type = gesture_event->primary_pointer_type;
  gesture_data->primary_unique_touch_event_id =
      gesture_event->primary_unique_touch_event_id;
  gesture_data->unique_touch_event_id = gesture_event->unique_touch_event_id;
  switch (gesture_event->GetType()) {
    default:
      break;
    case blink::WebInputEvent::Type::kGestureTapDown:
      gesture_data->contact_size =
          gfx::Size(gesture_event->data.tap_down.width,
                    gesture_event->data.tap_down.height);
      gesture_data->tap_down_data = blink::mojom::TapDownData::New(
          gesture_event->data.tap_down.tap_down_count);
      break;
    case blink::WebInputEvent::Type::kGestureShowPress:
      gesture_data->contact_size =
          gfx::Size(gesture_event->data.show_press.width,
                    gesture_event->data.show_press.height);
      break;
    case blink::WebInputEvent::Type::kGestureTap:
    case blink::WebInputEvent::Type::kGestureTapUnconfirmed:
    case blink::WebInputEvent::Type::kGestureDoubleTap:
      gesture_data->contact_size = gfx::Size(gesture_event->data.tap.width,
                                             gesture_event->data.tap.height);
      gesture_data->tap_data =
          blink::mojom::TapData::New(gesture_event->data.tap.tap_count,
                                     gesture_event->data.tap.needs_wheel_event);
      break;
    case blink::WebInputEvent::Type::kGestureShortPress:
    case blink::WebInputEvent::Type::kGestureLongPress:
    case blink::WebInputEvent::Type::kGestureLongTap:
      gesture_data->contact_size =
          gfx::Size(gesture_event->data.long_press.width,
                    gesture_event->data.long_press.height);
      break;

    case blink::WebInputEvent::Type::kGestureTwoFingerTap:
      gesture_data->contact_size =
          gfx::Size(gesture_event->data.two_finger_tap.first_finger_width,
                    gesture_event->data.two_finger_tap.first_finger_height);
      break;
    case blink::WebInputEvent::Type::kGestureScrollBegin:
      gesture_data->scroll_data = blink::mojom::ScrollData::New(
          gesture_event->data.scroll_begin.delta_x_hint,
          gesture_event->data.scroll_begin.delta_y_hint,
          gesture_event->data.scroll_begin.delta_hint_units,
          gesture_event->data.scroll_begin.target_viewport,
          gesture_event->data.scroll_begin.inertial_phase,
          gesture_event->data.scroll_begin.synthetic,
          gesture_event->data.scroll_begin.pointer_count,
          gesture_event->data.scroll_begin.cursor_control);
      break;
    case blink::WebInputEvent::Type::kGestureScrollEnd:
      gesture_data->scroll_data = blink::mojom::ScrollData::New(
          0, 0, gesture_event->data.scroll_end.delta_units, false,
          gesture_event->data.scroll_end.inertial_phase,
          gesture_event->data.scroll_end.synthetic, 0, false);
      break;
    case blink::WebInputEvent::Type::kGestureScrollUpdate:
      gesture_data->scroll_data = blink::mojom::ScrollData::New(
          gesture_event->data.scroll_update.delta_x,
          gesture_event->data.scroll_update.delta_y,
          gesture_event->data.scroll_update.delta_units, false,
          gesture_event->data.scroll_update.inertial_phase, false, 0, false);
      break;
    case blink::WebInputEvent::Type::kGestureFlingStart:
      gesture_data->fling_data = blink::mojom::FlingData::New(
          gesture_event->data.fling_start.velocity_x,
          gesture_event->data.fling_start.velocity_y,
          gesture_event->data.fling_start.target_viewport, false);
      break;
    case blink::WebInputEvent::Type::kGestureFlingCancel:
      gesture_data->fling_data = blink::mojom::FlingData::New(
          0, 0, gesture_event->data.fling_cancel.target_viewport,
          gesture_event->data.fling_cancel.prevent_boosting);
      break;
    case blink::WebInputEvent::Type::kGesturePinchBegin:
      gesture_data->pinch_begin_data = blink::mojom::PinchBeginData::New(
          gesture_event->data.pinch_begin.needs_wheel_event);
      break;
    case blink::WebInputEvent::Type::kGesturePinchUpdate:
      gesture_data->pinch_update_data = blink::mojom::PinchUpdateData::New(
          gesture_event->data.pinch_update.scale,
          gesture_event->data.pinch_update.zoom_disabled,
          gesture_event->data.pinch_update.needs_wheel_event);
      break;
    case blink::WebInputEvent::Type::kGesturePinchEnd:
      gesture_data->pinch_end_data = blink::mojom::PinchEndData::New(
          gesture_event->data.pinch_end.needs_wheel_event);
      break;
  }
  return gesture_data;
}

// static
blink::mojom::TouchDataPtr
StructTraits<blink::mojom::EventDataView,
             std::unique_ptr<blink::WebCoalescedInputEvent>>::
    touch_data(const std::unique_ptr<blink::WebCoalescedInputEvent>& event) {
  if (!blink::WebInputEvent::IsTouchEventType(event->Event().GetType()))
    return nullptr;

  const blink::WebTouchEvent* touch_event =
      static_cast<const blink::WebTouchEvent*>(event->EventPointer());
  auto touch_data = blink::mojom::TouchData::New(
      touch_event->dispatch_type, touch_event->moved_beyond_slop_region,
      touch_event->touch_start_or_first_touch_move, touch_event->hovering,
      touch_event->unique_touch_event_id,
      std::vector<blink::mojom::TouchPointPtr>());
  for (unsigned i = 0; i < touch_event->touches_length; ++i) {
    blink::mojom::PointerDataPtr pointer_data =
        PointerDataFromPointerProperties(touch_event->touches[i], nullptr);
    touch_data->touches.emplace_back(blink::mojom::TouchPoint::New(
        touch_event->touches[i].state, touch_event->touches[i].radius_x,
        touch_event->touches[i].radius_y,
        touch_event->touches[i].rotation_angle, std::move(pointer_data)));
  }
  return touch_data;
}

}  // namespace mojo
```