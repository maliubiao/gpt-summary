Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The primary goal is to explain the functionality of `widget_base_input_handler.cc` within the Chromium Blink rendering engine. This involves identifying its responsibilities, how it interacts with other parts of the system (especially JavaScript, HTML, and CSS), potential errors, and providing concrete examples.

2. **Initial Skim for Keywords and Structure:**  I'd start by quickly scanning the code for recognizable terms and patterns:
    * Includes:  Lots of `#include` statements give hints about dependencies. `WebInputEvent`, `WebMouseEvent`, `WebKeyboardEvent`, `WebGestureEvent`, `WidgetBase`, `WidgetBaseClient`, `LatencyInfo` are immediately relevant to input handling.
    * Namespaces:  The `blink` namespace confirms the code's location.
    * Class Name: `WidgetBaseInputHandler` suggests it manages input for a `WidgetBase`.
    * Function Names:  `HandleTouchEvent`, `HandleInputEvent`, `InjectScrollbarGestureScroll` are strong indicators of core functionalities.
    * Comments:  The copyright notice and other comments provide context.
    * Data Structures:  `HandlingState` looks like a helper class for managing state during event processing.
    * Conditional Compilation: `#if BUILDFLAG(IS_ANDROID)` shows platform-specific logic.
    * `UMA_HISTOGRAM_ENUMERATION`:  Indicates logging and metrics gathering.

3. **Focus on Key Functions:**  I'd then delve into the most prominent functions:

    * **`HandleInputEvent`:** This looks like the main entry point for handling various input events. I'd analyze its steps:
        * Creation of `HandlingState`: This suggests managing state during the handling process.
        * Platform-specific IME handling (`ImeEventGuard`).
        * Tracing (`TRACE_EVENT`).
        * Mouse event handling (cursor changes, virtual keyboard).
        * Keyboard event handling (especially for Android's DPAD_CENTER).
        * Gesture event handling.
        * Calling `widget_->client()->HandleInputEvent()`: This is crucial – it delegates the actual event processing to the `WidgetBaseClient`.
        * Logic for suppressing `char` events.
        * Handling injected scroll gestures.
        * Logging of passive listener behavior (`LogAllPassiveEventListenersUma`).
        * Calling the `callback`.
        * Showing the virtual keyboard.
        * Calling `widget_->client()->DidHandleKeyEvent()` and `FocusChangeComplete()`.

    * **`HandleTouchEvent`:**  Specifically for touch events. It iterates through touch points and converts them to pointer events.

    * **`InjectScrollbarGestureScroll` and `HandleInjectedScrollGestures`:** These deal with programmatically initiating scroll actions, often in response to user interactions with scrollbars. The logic for latency tracking within these functions is important.

4. **Identify Relationships with Web Technologies:**  Based on the function names and the types of events being handled, I'd start making connections to web technologies:

    * **JavaScript:** The handling of events directly relates to how JavaScript event listeners work in the browser. The concept of "prevent default" is central. The interaction with passive listeners is another key area.
    * **HTML:** Input elements (text fields, buttons) are the targets of many of these events. The focus changes and virtual keyboard interactions are directly related to HTML form elements.
    * **CSS:**  Cursor changes are a CSS feature. Scrolling, which this code heavily deals with, affects the layout and rendering of HTML content, which is influenced by CSS. Touch actions (`touch-action` CSS property) are explicitly mentioned.

5. **Look for Logical Inferences and Assumptions:**  As I understand the code, I'd start forming assumptions about how it works. For example:

    * The `WidgetBaseClient` is a crucial interface for interacting with the higher-level rendering logic.
    * The `LatencyInfo` objects are used to track the timing of events throughout the system.
    * The `HandlingState` class helps ensure that certain actions (like injecting scrolls) happen at the correct time during event processing.

6. **Consider User and Programming Errors:**  Knowing how input handling works, I'd think about common mistakes:

    * **Forgetting `preventDefault()` in JavaScript:** This is a classic issue that this code directly addresses.
    * **Incorrectly using passive listeners:** The logging of passive listener behavior suggests that developers need to be aware of their implications.
    * **Not understanding event ordering:** The handling of injected scrolls and the `HandlingState` highlights the complexities of managing asynchronous event processing.

7. **Structure the Explanation:**  Finally, I'd organize my findings into a clear and structured explanation, using the headings provided in the prompt:

    * **Functionality:** Summarize the core responsibilities of the class.
    * **Relationships with JavaScript, HTML, and CSS:** Provide concrete examples of how the code interacts with these technologies.
    * **Logical Inferences (Input/Output):** Create hypothetical scenarios to illustrate the flow of events and the code's behavior.
    * **User/Programming Errors:**  Give practical examples of mistakes related to input handling.

8. **Refine and Elaborate:** After the initial draft, I'd review and refine the explanation, adding more detail and clarity where needed. For example, explaining the purpose of `cc::EventMetrics` or the significance of the different `WebInputEvent` types. I'd also double-check the code to ensure my explanations are accurate. The initial skim helps identify the major components, and then deeper dives into specific sections reveal finer details. The presence of comments within the code itself is also a valuable resource during this refinement stage.
这个文件 `widget_base_input_handler.cc` 是 Chromium Blink 渲染引擎中处理各种用户输入事件的核心组件之一。它的主要功能是接收和处理来自浏览器进程的原始输入事件，并将这些事件分发到相应的 Blink 渲染对象进行处理。

以下是它的详细功能，以及它与 JavaScript、HTML 和 CSS 的关系，逻辑推理示例，以及可能的用户或编程错误：

**主要功能：**

1. **输入事件接收和分发:**
   - 接收来自浏览器进程的各种输入事件，例如鼠标事件 (Mouse Events)、键盘事件 (Keyboard Events)、触摸事件 (Touch Events) 和手势事件 (Gesture Events)。
   - 根据事件类型和目标元素，将这些事件分发到 Blink 渲染树中的相应 `WidgetBaseClient` 对象进行处理。`WidgetBaseClient` 通常由具体的渲染对象（例如 `RenderWidget`）实现。

2. **触摸事件处理和指针事件合成:**
   - 特别处理触摸事件 (`WebTouchEvent`)，并将其转换为更通用的指针事件 (`WebPointerEvent`)。这使得后续的处理逻辑更加统一。
   - 对于多点触摸，它会为每个活动的触摸点生成相应的指针事件。

3. **被动事件监听器 (Passive Event Listeners) 的处理和记录:**
   - 跟踪事件是否被被动监听器处理，并记录相关的统计信息（通过 `UMA_HISTOGRAM_ENUMERATION`）。
   - 被动监听器是非阻塞的，不会阻止浏览器的渲染更新。

4. **注入滚动 (Injected Scroll) 的管理:**
   - 支持在处理某些输入事件时注入额外的滚动事件，例如用户与滚动条交互时。
   - 管理这些注入的滚动事件的参数和执行。

5. **光标 (Cursor) 管理:**
   - 跟踪当前的光标状态，并在光标发生变化时通知客户端 (`WidgetBaseClient`)。

6. **触摸动作 (Touch Action) 处理:**
   - 处理通过 `setTouchAction` JavaScript API 设置的触摸动作，这些动作控制了元素的默认触摸行为（例如是否允许滚动）。

7. **虚拟键盘 (Virtual Keyboard) 的控制:**
   - 根据输入事件和焦点状态，控制虚拟键盘的显示和隐藏。

8. **事件确认 (Event Ack) 回调:**
   - 使用回调函数将事件处理结果（是否被处理）和相关的元数据（例如滚动偏移）发送回浏览器进程。

9. **延迟信息 (Latency Info) 跟踪:**
   - 使用 `LatencyInfo` 对象跟踪输入事件的延迟，从事件发生到被处理完成。

**与 JavaScript、HTML 和 CSS 的关系：**

* **JavaScript:**
    - **事件监听器:**  `WidgetBaseInputHandler` 处理的事件最终会触发 JavaScript 中注册的事件监听器。例如，当用户点击一个按钮时，`WidgetBaseInputHandler` 会处理鼠标按下和抬起事件，最终触发按钮的 `click` 事件监听器。
    - **`preventDefault()`:** JavaScript 可以调用 `event.preventDefault()` 来阻止浏览器对某些事件的默认行为。`WidgetBaseInputHandler` 中的逻辑会检查是否调用了 `preventDefault()`，并据此更新事件处理结果。
        ```javascript
        document.getElementById('myButton').addEventListener('click', function(event) {
          event.preventDefault(); // 阻止按钮的默认提交行为
          console.log('Button clicked!');
        });
        ```
    - **被动事件监听器:** JavaScript 可以通过添加 `{ passive: true }` 选项来注册被动事件监听器。`WidgetBaseInputHandler` 会区分处理主动和被动监听器，并记录相关信息。
        ```javascript
        document.addEventListener('touchstart', function(event) {
          console.log('Touch started (passive)');
        }, { passive: true });
        ```
    - **`setTouchAction`:** JavaScript 可以使用 CSS 属性 `touch-action` 或 JavaScript API `element.style.touchAction` 来控制元素的触摸行为。`WidgetBaseInputHandler::ProcessTouchAction` 函数负责处理这些设置。
        ```javascript
        document.getElementById('scrollableArea').style.touchAction = 'pan-y';
        ```

* **HTML:**
    - **交互元素:** HTML 中的各种交互元素（例如按钮、链接、输入框）是输入事件的目标。`WidgetBaseInputHandler` 负责将事件路由到与这些元素关联的渲染对象。
    - **表单:** 当用户与表单元素交互时，`WidgetBaseInputHandler` 会处理相关的输入事件，例如文本输入、按钮点击等。

* **CSS:**
    - **光标:** CSS 的 `cursor` 属性控制鼠标指针的样式。当鼠标移动到具有不同 `cursor` 样式的元素上时，`WidgetBaseInputHandler::DidChangeCursor` 会被调用以更新光标。
        ```css
        .clickable {
          cursor: pointer;
        }
        ```
    - **`touch-action`:** CSS 的 `touch-action` 属性直接影响 `WidgetBaseInputHandler` 对触摸事件的处理方式，决定是否允许滚动、缩放等默认行为。

**逻辑推理示例（假设输入与输出）：**

**假设输入：** 用户在屏幕上的一个按钮元素上按下触摸点。

**处理流程：**

1. **浏览器进程:** 操作系统捕获到触摸事件，并将其发送到浏览器进程。
2. **渲染器进程:** 浏览器进程将触摸事件（`WebTouchEvent`）传递给渲染器进程中的 `WidgetBaseInputHandler`。
3. **指针事件合成:** `WidgetBaseInputHandler::HandleTouchEvent` 将 `WebTouchEvent` 转换为一个或多个 `WebPointerEvent`。
4. **事件分发:** `WidgetBaseInputHandler` 确定触摸点所在的渲染对象（即按钮元素），并调用该对象的 `WidgetBaseClient::HandleInputEvent` 方法，将合成的 `WebPointerEvent` 传递过去。
5. **Blink 处理:**  按钮元素的渲染对象接收到事件，并可能触发相关的 JavaScript 事件监听器。
6. **事件确认:**  事件处理完成后，`WidgetBaseInputHandler` 通过回调函数将处理结果（例如是否调用了 `preventDefault()`）发送回浏览器进程。

**输出：**

* 如果 JavaScript 没有调用 `preventDefault()`，浏览器可能会执行按钮的默认行为（例如导航到一个新的页面，如果按钮在一个表单中）。
* 可能会触发按钮元素的 `touchstart`、`pointerdown` 等 JavaScript 事件。
* 如果 CSS 中设置了 `cursor: pointer`，鼠标悬停在按钮上时会显示手指光标。

**用户或编程常见的使用错误：**

1. **忘记在需要时调用 `preventDefault()`:**
   - **场景:** 用户点击一个链接，但 JavaScript 需要执行一些操作而不是立即跳转到链接的 URL。
   - **错误:** JavaScript 事件监听器中没有调用 `event.preventDefault()`。
   - **结果:** 浏览器会执行链接的默认行为，在 JavaScript 代码执行完成之前就跳转到新的页面。

2. **对被动事件监听器的行为理解不足:**
   - **场景:** 开发者尝试在 `touchstart` 或 `touchmove` 的被动监听器中调用 `preventDefault()` 来阻止滚动。
   - **错误:** 被动监听器不允许调用 `preventDefault()`，浏览器会忽略这个调用并在不等待 JavaScript 执行完成的情况下继续滚动。
   - **结果:** 页面仍然会滚动，开发者期望阻止滚动的代码没有生效。浏览器控制台可能会有警告信息。

3. **错误地使用 `touch-action` CSS 属性:**
   - **场景:** 开发者希望在某个区域禁用所有触摸交互，但错误地设置了 `touch-action: none`，导致一些预期的手势（例如双指缩放）也被禁用。
   - **错误:** 对 `touch-action` 的效果理解不准确。
   - **结果:** 用户无法进行预期的触摸操作。

4. **在输入事件处理期间执行耗时的同步操作:**
   - **场景:** 在鼠标移动事件的处理函数中执行大量的计算或 DOM 操作。
   - **错误:** 这会阻塞渲染主线程。
   - **结果:** 导致页面响应缓慢，甚至出现卡顿现象，影响用户体验。`WidgetBaseInputHandler` 尽管能快速分发事件，但下游的处理阻塞了流程。

5. **假设所有触摸事件都是鼠标事件:**
   - **场景:** 开发者只编写了鼠标事件的处理逻辑，没有考虑触摸设备。
   - **错误:** 没有处理触摸事件，或者假设触摸事件和鼠标事件的行为完全一致。
   - **结果:** 在触摸设备上，用户的交互可能无法正常工作。`WidgetBaseInputHandler` 负责合成指针事件来一定程度上缓解这个问题，但针对触摸的特定处理仍然可能需要。

总而言之，`widget_base_input_handler.cc` 是 Blink 渲染引擎中一个至关重要的组件，它连接了底层的输入事件和高层的 JavaScript、HTML 和 CSS 交互，确保用户输入能够被正确地处理和响应。理解其功能有助于开发者更好地理解浏览器的工作原理，并避免常见的输入事件处理错误。

### 提示词
```
这是目录为blink/renderer/platform/widget/input/widget_base_input_handler.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/widget/input/widget_base_input_handler.h"

#include <stddef.h>
#include <stdint.h>

#include <utility>

#include "base/memory/raw_ptr.h"
#include "base/metrics/histogram_macros.h"
#include "base/time/time.h"
#include "base/tracing/protos/chrome_track_event.pbzero.h"
#include "build/build_config.h"
#include "cc/metrics/event_metrics.h"
#include "cc/paint/element_id.h"
#include "cc/trees/latency_info_swap_promise_monitor.h"
#include "cc/trees/layer_tree_host.h"
#include "services/tracing/public/cpp/perfetto/macros.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/input/web_gesture_device.h"
#include "third_party/blink/public/common/input/web_gesture_event.h"
#include "third_party/blink/public/common/input/web_input_event_attribution.h"
#include "third_party/blink/public/common/input/web_keyboard_event.h"
#include "third_party/blink/public/common/input/web_mouse_wheel_event.h"
#include "third_party/blink/public/common/input/web_pointer_event.h"
#include "third_party/blink/public/common/input/web_touch_event.h"
#include "third_party/blink/public/mojom/input/input_event_result.mojom-shared.h"
#include "third_party/blink/public/platform/web_input_event_result.h"
#include "third_party/blink/renderer/platform/widget/input/ime_event_guard.h"
#include "third_party/blink/renderer/platform/widget/widget_base.h"
#include "third_party/blink/renderer/platform/widget/widget_base_client.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "ui/latency/latency_info.h"

#if BUILDFLAG(IS_ANDROID)
#include <android/keycodes.h>
#endif

using perfetto::protos::pbzero::TrackEvent;

namespace blink {

namespace {

void LogPassiveEventListenersUma(WebInputEventResult result,
                                 WebInputEvent::DispatchType dispatch_type) {
  // This enum is backing a histogram. Do not remove or reorder members.
  enum ListenerEnum {
    PASSIVE_LISTENER_UMA_ENUM_PASSIVE,
    PASSIVE_LISTENER_UMA_ENUM_UNCANCELABLE,
    PASSIVE_LISTENER_UMA_ENUM_SUPPRESSED,
    PASSIVE_LISTENER_UMA_ENUM_CANCELABLE,
    PASSIVE_LISTENER_UMA_ENUM_CANCELABLE_AND_CANCELED,
    PASSIVE_LISTENER_UMA_ENUM_FORCED_NON_BLOCKING_DUE_TO_FLING,
    PASSIVE_LISTENER_UMA_ENUM_FORCED_NON_BLOCKING_DUE_TO_MAIN_THREAD_RESPONSIVENESS_DEPRECATED,
    PASSIVE_LISTENER_UMA_ENUM_COUNT
  };

  ListenerEnum enum_value;
  switch (dispatch_type) {
    case WebInputEvent::DispatchType::kListenersForcedNonBlockingDueToFling:
      enum_value = PASSIVE_LISTENER_UMA_ENUM_FORCED_NON_BLOCKING_DUE_TO_FLING;
      break;
    case WebInputEvent::DispatchType::kListenersNonBlockingPassive:
      enum_value = PASSIVE_LISTENER_UMA_ENUM_PASSIVE;
      break;
    case WebInputEvent::DispatchType::kEventNonBlocking:
      enum_value = PASSIVE_LISTENER_UMA_ENUM_UNCANCELABLE;
      break;
    case WebInputEvent::DispatchType::kBlocking:
      if (result == WebInputEventResult::kHandledApplication)
        enum_value = PASSIVE_LISTENER_UMA_ENUM_CANCELABLE_AND_CANCELED;
      else if (result == WebInputEventResult::kHandledSuppressed)
        enum_value = PASSIVE_LISTENER_UMA_ENUM_SUPPRESSED;
      else
        enum_value = PASSIVE_LISTENER_UMA_ENUM_CANCELABLE;
      break;
    default:
      NOTREACHED();
  }

  UMA_HISTOGRAM_ENUMERATION("Event.PassiveListeners", enum_value,
                            PASSIVE_LISTENER_UMA_ENUM_COUNT);
}

void LogAllPassiveEventListenersUma(const WebInputEvent& input_event,
                                    WebInputEventResult result) {
  // TODO(dtapuska): Use the input_event.timeStampSeconds as the start
  // ideally this should be when the event was sent by the compositor to the
  // renderer. https://crbug.com/565348.
  if (input_event.GetType() == WebInputEvent::Type::kTouchStart ||
      input_event.GetType() == WebInputEvent::Type::kTouchMove ||
      input_event.GetType() == WebInputEvent::Type::kTouchEnd) {
    const WebTouchEvent& touch = static_cast<const WebTouchEvent&>(input_event);

    LogPassiveEventListenersUma(result, touch.dispatch_type);
  } else if (input_event.GetType() == WebInputEvent::Type::kMouseWheel) {
    LogPassiveEventListenersUma(
        result,
        static_cast<const WebMouseWheelEvent&>(input_event).dispatch_type);
  }
}

WebCoalescedInputEvent GetCoalescedWebPointerEventForTouch(
    const WebPointerEvent& pointer_event,
    const std::vector<std::unique_ptr<WebInputEvent>>& coalesced_events,
    const std::vector<std::unique_ptr<WebInputEvent>>& predicted_events,
    const ui::LatencyInfo& latency) {
  std::vector<std::unique_ptr<WebInputEvent>> related_pointer_events;
  for (const std::unique_ptr<WebInputEvent>& event : coalesced_events) {
    DCHECK(WebInputEvent::IsTouchEventType(event->GetType()));
    const WebTouchEvent& touch_event =
        static_cast<const WebTouchEvent&>(*event);
    for (unsigned i = 0; i < touch_event.touches_length; ++i) {
      if (touch_event.touches[i].id == pointer_event.id &&
          touch_event.touches[i].state !=
              WebTouchPoint::State::kStateStationary) {
        related_pointer_events.emplace_back(std::make_unique<WebPointerEvent>(
            touch_event, touch_event.touches[i]));
      }
    }
  }
  std::vector<std::unique_ptr<WebInputEvent>> predicted_pointer_events;
  for (const std::unique_ptr<WebInputEvent>& event : predicted_events) {
    DCHECK(WebInputEvent::IsTouchEventType(event->GetType()));
    const WebTouchEvent& touch_event =
        static_cast<const WebTouchEvent&>(*event);
    for (unsigned i = 0; i < touch_event.touches_length; ++i) {
      if (touch_event.touches[i].id == pointer_event.id &&
          touch_event.touches[i].state !=
              WebTouchPoint::State::kStateStationary) {
        predicted_pointer_events.emplace_back(std::make_unique<WebPointerEvent>(
            touch_event, touch_event.touches[i]));
      }
    }
  }

  return WebCoalescedInputEvent(pointer_event.Clone(),
                                std::move(related_pointer_events),
                                std::move(predicted_pointer_events), latency);
}

mojom::blink::InputEventResultState GetAckResult(
    WebInputEventResult processed) {
  return processed == WebInputEventResult::kNotHandled
             ? mojom::blink::InputEventResultState::kNotConsumed
             : mojom::blink::InputEventResultState::kConsumed;
}

bool IsGestureScroll(WebInputEvent::Type type) {
  switch (type) {
    case WebGestureEvent::Type::kGestureScrollBegin:
    case WebGestureEvent::Type::kGestureScrollUpdate:
    case WebGestureEvent::Type::kGestureScrollEnd:
      return true;
    default:
      return false;
  }
}

gfx::PointF PositionInWidgetFromInputEvent(const WebInputEvent& event) {
  if (WebInputEvent::IsMouseEventType(event.GetType())) {
    return static_cast<const WebMouseEvent&>(event).PositionInWidget();
  } else if (WebInputEvent::IsGestureEventType(event.GetType())) {
    return static_cast<const WebGestureEvent&>(event).PositionInWidget();
  } else {
    return gfx::PointF(0, 0);
  }
}

bool IsTouchStartOrMove(const WebInputEvent& event) {
  if (WebInputEvent::IsPointerEventType(event.GetType())) {
    return static_cast<const WebPointerEvent&>(event)
        .touch_start_or_first_touch_move;
  } else if (WebInputEvent::IsTouchEventType(event.GetType())) {
    return static_cast<const WebTouchEvent&>(event)
        .touch_start_or_first_touch_move;
  } else {
    return false;
  }
}

}  // namespace

// This class should be placed on the stack when handling an input event. It
// stores information from callbacks from blink while handling an input event
// and allows them to be returned in the InputEventAck result.
class WidgetBaseInputHandler::HandlingState {
 public:
  HandlingState(base::WeakPtr<WidgetBaseInputHandler> input_handler_param,
                bool is_touch_start_or_move)
      : touch_start_or_move_(is_touch_start_or_move),
        input_handler_(std::move(input_handler_param)) {
    previous_was_handling_input_ = input_handler_->handling_input_event_;
    previous_state_ = input_handler_->handling_input_state_;
    input_handler_->handling_input_event_ = true;
    input_handler_->handling_input_state_ = this;
  }

  ~HandlingState() {
    // Unwinding the HandlingState on the stack might result in an
    // input_handler_ that got destroyed. i.e. via a nested event loop.
    if (!input_handler_)
      return;
    input_handler_->handling_input_event_ = previous_was_handling_input_;
    DCHECK_EQ(input_handler_->handling_input_state_, this);
    input_handler_->handling_input_state_ = previous_state_;
  }

  std::unique_ptr<InputHandlerProxy::DidOverscrollParams>& event_overscroll() {
    return event_overscroll_;
  }
  void set_event_overscroll(
      std::unique_ptr<InputHandlerProxy::DidOverscrollParams> params) {
    event_overscroll_ = std::move(params);
  }

  std::optional<WebTouchAction>& touch_action() { return touch_action_; }

  Vector<WidgetBaseInputHandler::InjectScrollGestureParams>&
  injected_scroll_params() {
    return injected_scroll_params_;
  }

  bool touch_start_or_move() { return touch_start_or_move_; }

 private:
  // Used to intercept overscroll notifications while an event is being
  // handled. If the event causes overscroll, the overscroll metadata can be
  // bundled in the event ack, saving an IPC.  Note that we must continue
  // supporting overscroll IPC notifications due to fling animation updates.
  std::unique_ptr<InputHandlerProxy::DidOverscrollParams> event_overscroll_;

  std::optional<WebTouchAction> touch_action_;

  // Used to hold a sequence of parameters corresponding to scroll gesture
  // events that should be injected once the current input event is done
  // being processed.
  Vector<WidgetBaseInputHandler::InjectScrollGestureParams>
      injected_scroll_params_;

  // Whether the event we are handling is a touch start or move.
  bool touch_start_or_move_;

  raw_ptr<HandlingState> previous_state_;
  bool previous_was_handling_input_;
  base::WeakPtr<WidgetBaseInputHandler> input_handler_;
};

WidgetBaseInputHandler::WidgetBaseInputHandler(WidgetBase* widget)
    : widget_(widget),
      supports_buffered_touch_(
          widget_->client()->SupportsBufferedTouchEvents()) {}

WebInputEventResult WidgetBaseInputHandler::HandleTouchEvent(
    const WebCoalescedInputEvent& coalesced_event) {
  const WebInputEvent& input_event = coalesced_event.Event();

  if (input_event.GetType() == WebInputEvent::Type::kTouchScrollStarted) {
    WebPointerEvent pointer_event =
        WebPointerEvent::CreatePointerCausesUaActionEvent(
            WebPointerProperties::PointerType::kUnknown,
            input_event.TimeStamp());
    return widget_->client()->HandleInputEvent(
        WebCoalescedInputEvent(pointer_event, coalesced_event.latency_info()));
  }

  const WebTouchEvent touch_event =
      static_cast<const WebTouchEvent&>(input_event);
  for (unsigned i = 0; i < touch_event.touches_length; ++i) {
    const WebTouchPoint& touch_point = touch_event.touches[i];
    if (touch_point.state != WebTouchPoint::State::kStateStationary) {
      WebPointerEvent pointer_event = WebPointerEvent(touch_event, touch_point);
      // Copy queued timestamp from original WebInputEvent.
      pointer_event.SetQueuedTimeStamp(input_event.QueuedTimeStamp());
      const WebCoalescedInputEvent& coalesced_pointer_event =
          GetCoalescedWebPointerEventForTouch(
              pointer_event, coalesced_event.GetCoalescedEventsPointers(),
              coalesced_event.GetPredictedEventsPointers(),
              coalesced_event.latency_info());
      widget_->client()->HandleInputEvent(coalesced_pointer_event);
    }
  }
  return widget_->client()->DispatchBufferedTouchEvents();
}

void WidgetBaseInputHandler::HandleInputEvent(
    const WebCoalescedInputEvent& coalesced_event,
    std::unique_ptr<cc::EventMetrics> metrics,
    HandledEventCallback callback) {
  const WebInputEvent& input_event = coalesced_event.Event();

  // Keep a WeakPtr to this WidgetBaseInputHandler to detect if executing the
  // input event destroyed the associated RenderWidget (and this handler).
  base::WeakPtr<WidgetBaseInputHandler> weak_self =
      weak_ptr_factory_.GetWeakPtr();
  HandlingState handling_state(weak_self, IsTouchStartOrMove(input_event));

#if BUILDFLAG(IS_ANDROID)
  ImeEventGuard guard(widget_->GetWeakPtr());
#endif

  TRACE_EVENT1("renderer,benchmark,rail,input.scrolling",
               "WidgetBaseInputHandler::OnHandleInputEvent", "event",
               WebInputEvent::GetName(input_event.GetType()));
  int64_t trace_id = coalesced_event.latency_info().trace_id();
  TRACE_EVENT("input,benchmark,latencyInfo", "LatencyInfo.Flow",
              [&](perfetto::EventContext ctx) {
                base::TaskAnnotator::EmitTaskTimingDetails(ctx);
                ui::LatencyInfo::FillTraceEvent(
                    ctx, trace_id,
                    perfetto::protos::pbzero::ChromeLatencyInfo2::Step::
                        STEP_HANDLE_INPUT_EVENT_MAIN);
              });

  ui::LatencyInfo swap_latency_info(coalesced_event.latency_info());
  swap_latency_info.AddLatencyNumber(
      ui::LatencyComponentType::INPUT_EVENT_LATENCY_RENDERER_MAIN_COMPONENT);
  cc::LatencyInfoSwapPromiseMonitor latency_info_swap_promise_monitor(
      &swap_latency_info, widget_->LayerTreeHost()->GetSwapPromiseManager());
  std::unique_ptr<cc::EventMetrics> cloned_metrics;
  cc::EventsMetricsManager::ScopedMonitor::DoneCallback done_callback;
  if (metrics) {
    // Create a clone of `metrics` before moving it to the following callback.
    // This would later be useful in creating `cc::EventMetrics` objects for
    // injected scroll events.
    cloned_metrics = metrics->Clone();
    metrics->SetDispatchStageTimestamp(
        cc::EventMetrics::DispatchStage::kRendererMainStarted);
    done_callback = base::BindOnce(
        [](std::unique_ptr<cc::EventMetrics> metrics, bool handled) {
          metrics->SetDispatchStageTimestamp(
              cc::EventMetrics::DispatchStage::kRendererMainFinished);
          std::unique_ptr<cc::EventMetrics> result =
              handled ? std::move(metrics) : nullptr;
          return result;
        },
        std::move(metrics));
  }
  auto event_metrics_monitor =
      widget_->LayerTreeHost()->GetScopedEventMetricsMonitor(
          std::move(done_callback));

  bool prevent_default = false;
  bool show_virtual_keyboard_for_mouse = false;
  if (WebInputEvent::IsMouseEventType(input_event.GetType())) {
    const WebMouseEvent& mouse_event =
        static_cast<const WebMouseEvent&>(input_event);
    TRACE_EVENT2("renderer", "HandleMouseMove", "x",
                 mouse_event.PositionInWidget().x(), "y",
                 mouse_event.PositionInWidget().y());

    widget_->client()->WillHandleMouseEvent(mouse_event);

    // Reset the last known cursor if mouse has left this widget. So next
    // time that the mouse enters we always set the cursor accordingly.
    if (mouse_event.GetType() == WebInputEvent::Type::kMouseLeave)
      current_cursor_.reset();

    if (mouse_event.button == WebPointerProperties::Button::kLeft &&
        mouse_event.GetType() == WebInputEvent::Type::kMouseUp) {
      show_virtual_keyboard_for_mouse = true;
    }
  }

#if BUILDFLAG(IS_ANDROID)
  if (WebInputEvent::IsKeyboardEventType(input_event.GetType())) {
    // The DPAD_CENTER key on Android has a dual semantic: (1) in the general
    // case it should behave like a select key (i.e. causing a click if a button
    // is focused). However, if a text field is focused (2), its intended
    // behavior is to just show the IME and don't propagate the key.
    // A typical use case is a web form: the DPAD_CENTER should bring up the IME
    // when clicked on an input text field and cause the form submit if clicked
    // when the submit button is focused, but not vice-versa.
    // The UI layer takes care of translating DPAD_CENTER into a RETURN key,
    // but at this point we have to swallow the event for the scenario (2).
    const WebKeyboardEvent& key_event =
        static_cast<const WebKeyboardEvent&>(input_event);
    if (key_event.native_key_code == AKEYCODE_DPAD_CENTER &&
        widget_->client()->GetTextInputType() !=
            WebTextInputType::kWebTextInputTypeNone) {
      // Show the keyboard on keyup (not keydown) to match the behavior of
      // Android's TextView.
      if (key_event.GetType() == WebInputEvent::Type::kKeyUp)
        widget_->ShowVirtualKeyboardOnElementFocus();
      // Prevent default for both keydown and keyup (letting the keydown go
      // through to the web app would cause compatibility problems since
      // DPAD_CENTER is also used as a "confirm" button).
      prevent_default = true;
    }
  }
#endif

  if (WebInputEvent::IsGestureEventType(input_event.GetType())) {
    const WebGestureEvent& gesture_event =
        static_cast<const WebGestureEvent&>(input_event);
    bool suppress = false;
    widget_->client()->WillHandleGestureEvent(gesture_event, &suppress);
    prevent_default = prevent_default || suppress;
  }

  WebInputEventResult processed = prevent_default
                                      ? WebInputEventResult::kHandledSuppressed
                                      : WebInputEventResult::kNotHandled;
  if (input_event.GetType() != WebInputEvent::Type::kChar ||
      !suppress_next_char_events_) {
    suppress_next_char_events_ = false;
    if (processed == WebInputEventResult::kNotHandled) {
      if (supports_buffered_touch_ &&
          WebInputEvent::IsTouchEventType(input_event.GetType()))
        processed = HandleTouchEvent(coalesced_event);
      else
        processed = widget_->client()->HandleInputEvent(coalesced_event);
    }

    // The associated WidgetBase (and this WidgetBaseInputHandler) could
    // have been destroyed. If it was return early before accessing any more of
    // this class.
    if (!weak_self) {
      if (callback) {
        std::move(callback).Run(GetAckResult(processed), swap_latency_info,
                                std::move(handling_state.event_overscroll()),
                                std::move(handling_state.touch_action()));
      }
      return;
    }
  }

  // Handling |input_event| is finished and further down, we might start
  // handling injected scroll events. So, stop monitoring EventMetrics for
  // |input_event| to avoid nested monitors.
  event_metrics_monitor = nullptr;

  LogAllPassiveEventListenersUma(input_event, processed);

  // If this RawKeyDown event corresponds to a browser keyboard shortcut and
  // it's not processed by webkit, then we need to suppress the upcoming Char
  // events.
  bool is_keyboard_shortcut =
      input_event.GetType() == WebInputEvent::Type::kRawKeyDown &&
      static_cast<const WebKeyboardEvent&>(input_event).is_browser_shortcut;
  if (processed == WebInputEventResult::kNotHandled && is_keyboard_shortcut)
    suppress_next_char_events_ = true;

  // The handling of some input events on the main thread may require injecting
  // scroll gestures back into blink, e.g., a mousedown on a scrollbar. We
  // do this here so that we can attribute latency information from the mouse as
  // a scroll interaction, instead of just classifying as mouse input.
  if (handling_state.injected_scroll_params().size()) {
    HandleInjectedScrollGestures(
        std::move(handling_state.injected_scroll_params()), input_event,
        coalesced_event.latency_info(), cloned_metrics.get());
  }

  // Send gesture scroll events and their dispositions to the compositor thread,
  // so that they can be used to produce the elastic overscroll effect.
  if (input_event.GetType() == WebInputEvent::Type::kGestureScrollBegin ||
      input_event.GetType() == WebInputEvent::Type::kGestureScrollEnd ||
      input_event.GetType() == WebInputEvent::Type::kGestureScrollUpdate) {
    const WebGestureEvent& gesture_event =
        static_cast<const WebGestureEvent&>(input_event);
    if (gesture_event.SourceDevice() == WebGestureDevice::kTouchpad ||
        gesture_event.SourceDevice() == WebGestureDevice::kTouchscreen) {
      gfx::Vector2dF latest_overscroll_delta =
          handling_state.event_overscroll()
              ? handling_state.event_overscroll()->latest_overscroll_delta
              : gfx::Vector2dF();
      cc::OverscrollBehavior overscroll_behavior =
          handling_state.event_overscroll()
              ? handling_state.event_overscroll()->overscroll_behavior
              : cc::OverscrollBehavior();
      widget_->client()->ObserveGestureEventAndResult(
          gesture_event, latest_overscroll_delta, overscroll_behavior,
          processed != WebInputEventResult::kNotHandled);
    }
  }

  if (callback) {
    std::move(callback).Run(GetAckResult(processed), swap_latency_info,
                            std::move(handling_state.event_overscroll()),
                            std::move(handling_state.touch_action()));
  } else {
    DCHECK(!handling_state.event_overscroll())
        << "Unexpected overscroll for un-acked event";
  }

  // Show the virtual keyboard if enabled and a user gesture triggers a focus
  // change.
  if ((processed != WebInputEventResult::kNotHandled &&
       input_event.GetType() == WebInputEvent::Type::kTouchEnd) ||
      show_virtual_keyboard_for_mouse) {
    widget_->ShowVirtualKeyboard();
  }

  if (!prevent_default &&
      WebInputEvent::IsKeyboardEventType(input_event.GetType()))
    widget_->client()->DidHandleKeyEvent();

// TODO(rouslan): Fix ChromeOS and Windows 8 behavior of autofill popup with
// virtual keyboard.
#if !BUILDFLAG(IS_ANDROID)
  // Virtual keyboard is not supported, so react to focus change immediately.
  if ((processed != WebInputEventResult::kNotHandled &&
       input_event.GetType() == WebInputEvent::Type::kMouseDown) ||
      input_event.GetType() == WebInputEvent::Type::kGestureTap) {
    widget_->client()->FocusChangeComplete();
  }
#endif

  // Ensure all injected scrolls were handled or queue up - any remaining
  // injected scrolls at this point would not be processed.
  DCHECK(handling_state.injected_scroll_params().empty());
}

void WidgetBaseInputHandler::InjectScrollbarGestureScroll(
    const gfx::Vector2dF& delta,
    ui::ScrollGranularity granularity,
    cc::ElementId scrollable_area_element_id,
    WebInputEvent::Type injected_type) {
  DCHECK(IsGestureScroll(injected_type));
  // If we're currently handling an input event, cache the appropriate
  // parameters so we can dispatch the events directly once blink finishes
  // handling the event.
  // Otherwise, queue the event on the main thread event queue.
  // The latter may occur when scrollbar scrolls are injected due to
  // autoscroll timer - i.e. not within the handling of a mouse event.
  // We don't always just enqueue events, since events queued to the
  // MainThreadEventQueue in the middle of dispatch (which we are) won't
  // be dispatched until the next time the queue gets to run. The side effect
  // of that would be an extra frame of latency if we're injecting a scroll
  // during the handling of a rAF aligned input event, such as mouse move.
  if (handling_input_state_) {
    InjectScrollGestureParams params{delta, granularity,
                                     scrollable_area_element_id, injected_type};
    handling_input_state_->injected_scroll_params().push_back(params);
  } else {
    base::TimeTicks now = base::TimeTicks::Now();
    std::unique_ptr<WebGestureEvent> gesture_event =
        WebGestureEvent::GenerateInjectedScrollbarGestureScroll(
            injected_type, now, gfx::PointF(0, 0), delta, granularity);
    if (injected_type == WebInputEvent::Type::kGestureScrollBegin) {
      gesture_event->data.scroll_begin.scrollable_area_element_id =
          scrollable_area_element_id.GetInternalValue();
    }

    std::unique_ptr<WebCoalescedInputEvent> web_scoped_gesture_event =
        std::make_unique<WebCoalescedInputEvent>(std::move(gesture_event),
                                                 ui::LatencyInfo());
    widget_->QueueSyntheticEvent(std::move(web_scoped_gesture_event));
  }
}

void WidgetBaseInputHandler::HandleInjectedScrollGestures(
    Vector<InjectScrollGestureParams> injected_scroll_params,
    const WebInputEvent& input_event,
    const ui::LatencyInfo& original_latency_info,
    const cc::EventMetrics* original_metrics) {
  DCHECK(injected_scroll_params.size());

  base::TimeTicks original_timestamp;
  bool found_original_component = original_latency_info.FindLatency(
      ui::INPUT_EVENT_LATENCY_ORIGINAL_COMPONENT, &original_timestamp);
  DCHECK(found_original_component);

  gfx::PointF position = PositionInWidgetFromInputEvent(input_event);
  for (const InjectScrollGestureParams& params : injected_scroll_params) {
    // Set up a new `LatencyInfo` for the injected scroll - this is the original
    // `LatencyInfo` for the input event that was being handled when the scroll
    // was injected. This new `LatencyInfo` will have a modified type, and an
    // additional scroll update component. Also set up a
    // `LatencyInfoSwapPromiseMonitor` that will cause the `LatencyInfo` to be
    // sent up with the compositor frame, if the GSU causes a commit. This
    // allows end to end latency to be logged for the injected scroll, annotated
    // with the correct type.
    ui::LatencyInfo scrollbar_latency_info(original_latency_info);
    scrollbar_latency_info.AddLatencyNumber(
        ui::LatencyComponentType::INPUT_EVENT_LATENCY_RENDERER_MAIN_COMPONENT);

    std::unique_ptr<WebGestureEvent> gesture_event =
        WebGestureEvent::GenerateInjectedScrollbarGestureScroll(
            params.type, input_event.TimeStamp(), position, params.scroll_delta,
            params.granularity);

    std::unique_ptr<cc::EventMetrics> metrics;
    if (params.type == WebInputEvent::Type::kGestureScrollUpdate) {
      if (input_event.GetType() != WebInputEvent::Type::kGestureScrollUpdate) {
        scrollbar_latency_info.AddLatencyNumberWithTimestamp(
            last_injected_gesture_was_begin_
                ? ui::INPUT_EVENT_LATENCY_FIRST_SCROLL_UPDATE_ORIGINAL_COMPONENT
                : ui::INPUT_EVENT_LATENCY_SCROLL_UPDATE_ORIGINAL_COMPONENT,
            original_timestamp);
      } else {
        // If we're injecting a GSU in response to a GSU (touch drags of the
        // scrollbar thumb in Blink handles GSUs, and reverses them with
        // injected GSUs), the LatencyInfo will already have the appropriate
        // SCROLL_UPDATE component set.
        DCHECK(
            scrollbar_latency_info.FindLatency(
                ui::INPUT_EVENT_LATENCY_FIRST_SCROLL_UPDATE_ORIGINAL_COMPONENT,
                nullptr) ||
            scrollbar_latency_info.FindLatency(
                ui::INPUT_EVENT_LATENCY_SCROLL_UPDATE_ORIGINAL_COMPONENT,
                nullptr));
      }
      metrics = cc::ScrollUpdateEventMetrics::CreateFromExisting(
          gesture_event->GetTypeAsUiEventType(),
          ui::ScrollInputType::kScrollbar, /*is_inertial=*/false,
          last_injected_gesture_was_begin_
              ? cc::ScrollUpdateEventMetrics::ScrollUpdateType::kStarted
              : cc::ScrollUpdateEventMetrics::ScrollUpdateType::kContinued,
          params.scroll_delta.y(),
          cc::EventMetrics::DispatchStage::kRendererCompositorFinished,
          original_metrics);
    } else {
      metrics = cc::ScrollEventMetrics::CreateFromExisting(
          gesture_event->GetTypeAsUiEventType(),
          ui::ScrollInputType::kScrollbar, /*is_inertial=*/false,
          cc::EventMetrics::DispatchStage::kRendererCompositorFinished,
          original_metrics);
    }

    if (params.type == WebInputEvent::Type::kGestureScrollBegin) {
      gesture_event->data.scroll_begin.scrollable_area_element_id =
          params.scrollable_area_element_id.GetInternalValue();
      last_injected_gesture_was_begin_ = true;
    } else {
      last_injected_gesture_was_begin_ = false;
    }

    {
      cc::LatencyInfoSwapPromiseMonitor latency_info_swap_promise_monitor(
          &scrollbar_latency_info,
          widget_->LayerTreeHost()->GetSwapPromiseManager());
      cc::EventsMetricsManager::ScopedMonitor::DoneCallback done_callback;
      if (metrics) {
        metrics->SetDispatchStageTimestamp(
            cc::EventMetrics::DispatchStage::kRendererMainStarted);
        // Since we don't need `metrics` for this event beyond this point (i.e.
        // we don't intend to add further breakdowns to the metrics while
        // processing the event, at least for now), it is safe to move the
        // metrics object to the callback.
        done_callback = base::BindOnce(
            [](std::unique_ptr<cc::EventMetrics> metrics, bool handled) {
              metrics->SetDispatchStageTimestamp(
                  cc::EventMetrics::DispatchStage::kRendererMainFinished);
              std::unique_ptr<cc::EventMetrics> result =
                  handled ? std::move(metrics) : nullptr;
              return result;
            },
            std::move(metrics));
      }
      auto event_metrics_monitor =
          widget_->LayerTreeHost()->GetScopedEventMetricsMonitor(
              std::move(done_callback));
      widget_->client()->HandleInputEvent(
          WebCoalescedInputEvent(*gesture_event, scrollbar_latency_info));
    }
  }
}

bool WidgetBaseInputHandler::DidChangeCursor(const ui::Cursor& cursor) {
  if (current_cursor_.has_value() && current_cursor_.value() == cursor)
    return false;
  current_cursor_ = cursor;
  return true;
}

bool WidgetBaseInputHandler::ProcessTouchAction(WebTouchAction touch_action) {
  if (!handling_input_state_)
    return false;
  // Ignore setTouchAction calls that result from synthetic touch events (eg.
  // when blink is emulating touch with mouse).
  if (!handling_input_state_->touch_start_or_move())
    return false;
  handling_input_state_->touch_action() = touch_action;
  return true;
}

}  // namespace blink
```