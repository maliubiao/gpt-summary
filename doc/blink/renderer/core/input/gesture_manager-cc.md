Response:
Let's break down the thought process to analyze the `gesture_manager.cc` file and fulfill the request.

**1. Understanding the Core Function:**

The filename `gesture_manager.cc` immediately suggests this class is responsible for handling gestures within the Blink rendering engine. The includes confirm this, referencing `WebGestureEvent`, `GestureEvent`, and other related input and event handling components. The core function is to interpret low-level gesture events and translate them into higher-level actions or dispatch them as DOM events.

**2. Identifying Key Responsibilities:**

By skimming the code and looking at the method names, several key responsibilities emerge:

* **Gesture Event Handling:**  Methods like `HandleGestureTapDown`, `HandleGestureTap`, `HandleGestureLongPress`, etc., clearly indicate the handling of specific gesture types.
* **Integration with Mouse Events:** The code frequently creates "fake" mouse events (`WebMouseEvent`) from gesture events. This is crucial for compatibility and for triggering existing mouse-event-based logic.
* **Hit Testing:** The class uses `HitTestResult` to determine which element is the target of a gesture.
* **Dispatching DOM Events:**  The code creates and dispatches `GestureEvent` objects to JavaScript.
* **Context Menu Handling:**  Functions like `SendContextMenuEventForGesture` point to the management of context menu display.
* **Drag and Drop:**  The involvement of `mouse_event_manager_->HandleDragDropIfPossible` shows interaction with drag and drop functionality.
* **Text Selection:** The `selection_controller_` member indicates involvement in text selection triggered by gestures.
* **Unhandled Tap UI:**  The `ShowUnhandledTapUIIfNeeded` function suggests a mechanism for displaying UI when a tap isn't handled by the page.

**3. Analyzing Relationships with Web Technologies (JavaScript, HTML, CSS):**

With the responsibilities identified, the relationships with web technologies become clearer:

* **JavaScript:**  The dispatching of `GestureEvent` directly interacts with JavaScript event listeners. The creation of fake mouse events also triggers JavaScript event handlers expecting mouse events.
* **HTML:** The hit testing process is fundamental for targeting the correct HTML element. The actions taken (like opening context menus, triggering clicks, or initiating drag and drop) operate on HTML elements.
* **CSS:**  While not directly manipulating CSS, the hit testing process is affected by CSS layout and rendering. The `ShowUnhandledTapUIIfNeeded` functionality might involve displaying UI elements styled with CSS. Also, hover effects triggered by the simulated mousemove rely on CSS.

**4. Constructing Examples:**

Based on the identified relationships, specific examples can be constructed:

* **JavaScript Interaction:**  A JavaScript event listener for the `click` event being triggered by a `GestureTap`.
* **HTML Targeting:** A gesture on a link (`<a>` tag) leading to navigation.
* **CSS Impact:**  A gesture causing a `:hover` effect due to the simulated mousemove.

**5. Logical Inference and Input/Output:**

For logical inference, consider a specific gesture and trace its path:

* **Input:** A `WebGestureEvent` of type `kGestureTap` at coordinates (100, 100) on an `<a>` element.
* **Processing:**
    * Hit testing identifies the `<a>` element.
    * A fake `mousemove` is generated and dispatched.
    * A fake `mousedown` is generated and dispatched.
    * A fake `mouseup` is generated and dispatched.
    * A `click` event is generated and dispatched to the `<a>` element.
* **Output:** The browser navigates to the URL specified in the `href` attribute of the `<a>` tag.

**6. Identifying User/Programming Errors:**

Think about common mistakes related to gesture handling:

* **User Error:**  Unintentional long presses triggering context menus.
* **Programming Error:**  Not preventing default behavior in JavaScript gesture handlers, leading to unexpected default actions in addition to the custom logic. Incorrectly assuming that touch events and mouse events are mutually exclusive.

**7. Tracing User Operations:**

To understand how a user action reaches this code, follow the flow:

1. **User Interaction:** The user touches the screen (or uses a trackpad that generates gesture events).
2. **Platform Event:** The operating system or browser (at a lower level) recognizes this as a touch or gesture.
3. **Browser Process:** The browser process receives this platform event.
4. **Renderer Process:** The browser process sends the gesture information to the appropriate renderer process.
5. **Blink Input Handling:** Within the renderer, the input subsystem (likely involving the compositor thread) processes the raw input and generates a `WebGestureEvent`.
6. **Event Dispatch:** This `WebGestureEvent` is then passed to the `GestureManager` in the appropriate frame.
7. **`GestureManager` Processing:** The `HandleGestureEventInFrame` method and its related handlers are invoked to process the event.

**8. Iterative Refinement:**

After the initial analysis, reread the code and the requirements. Are there any missed details?  For example, the `suppress_mouse_events_from_gestures_` flag is important for preventing duplicate events. The specific conditions for enabling Touch Drag and Context Menu are also worth noting.

By following these steps, a comprehensive understanding of the `gesture_manager.cc` file and its role can be achieved, allowing for a detailed response to the prompt.
这个文件 `blink/renderer/core/input/gesture_manager.cc` 是 Chromium Blink 渲染引擎中负责处理手势事件的核心组件。它的主要功能是将底层的、平台特定的手势事件（如触摸、滑动、捏合等）转换为 Blink 引擎可以理解和处理的事件，并最终传递给 DOM 树中的相应元素进行处理。

以下是 `GestureManager` 的主要功能以及与 JavaScript、HTML、CSS 的关系：

**主要功能：**

1. **接收和解析手势事件:**  `GestureManager` 接收来自 Chromium 浏览器进程传递过来的 `WebGestureEvent`。这些事件包含了手势的类型（例如：`kGestureTapDown`, `kGestureTap`, `kGestureLongPress` 等）、发生的位置、触摸点信息等。

2. **手势类型识别和分发:**  根据接收到的 `WebGestureEvent` 的类型，`GestureManager` 将事件分发到相应的处理函数，例如 `HandleGestureTapDown` 处理按下事件，`HandleGestureTap` 处理点击事件，`HandleGestureLongPress` 处理长按事件等。

3. **模拟鼠标事件:**  对于某些手势，`GestureManager` 会模拟生成相应的鼠标事件 (`WebMouseEvent`)，例如 `mousedown`, `mouseup`, `click`, `mousemove`。这是为了保持与现有 Web 内容的兼容性，因为许多网页的交互逻辑是基于鼠标事件编写的。

4. **触发 DOM 事件:**  `GestureManager` 会创建和分发 `GestureEvent` DOM 事件给目标元素，使得 JavaScript 可以监听和处理这些手势。

5. **处理特定手势行为:**
    * **点击 (Tap):** 处理单击操作，包括模拟鼠标事件和触发 `click` 事件。
    * **长按 (Long Press/Long Tap):** 处理长按操作，通常用于触发上下文菜单。
    * **双指触摸 (Two Finger Tap):** 处理双指触摸操作，可能用于特定的上下文操作。
    * **拖拽 (Drag):**  与 `MouseEventManager` 协作，处理触摸拖拽操作。
    * **滚动 (Scroll):** 虽然这个文件本身不直接处理滚动，但它与 `ScrollManager` 交互，并且手势事件是触发滚动的基础。

6. **处理用户激活 (User Activation):**  在某些手势操作后，例如点击，会通知框架进行用户激活，这对于某些需要用户交互才能触发的功能是必要的。

7. **抑制不必要的事件:**  在某些情况下，为了避免重复或冲突，`GestureManager` 会抑制某些鼠标事件或选择操作。

8. **上下文菜单处理:**  负责在长按等手势后触发上下文菜单。

9. **未处理的点击提示 (Unhandled Tap UI):**  如果一个点击事件没有被页面处理，可以触发一个提示 UI，告知用户点击未生效。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **JavaScript:** `GestureManager` 的核心目标之一就是将手势事件传递给 JavaScript 进行处理。
    * **例子:**  一个网页上有一个按钮，开发者可以使用 JavaScript 监听 `click` 事件，当用户点击这个按钮时（无论是通过鼠标还是触摸），`GestureManager` 会模拟生成 `click` 事件并分发给按钮，JavaScript 监听器会被触发执行相应的逻辑。
    ```javascript
    const button = document.getElementById('myButton');
    button.addEventListener('click', () => {
      console.log('按钮被点击了！');
    });
    ```
    当用户触摸 `myButton` 时，`GestureManager` 会将触摸手势转换为 `click` 事件，从而触发 JavaScript 代码。

* **HTML:** `GestureManager` 需要确定手势事件的目标元素，这依赖于 HTML 结构。
    * **例子:**  用户触摸屏幕上的一个链接 (`<a>` 标签)，`GestureManager` 会通过命中测试 (`HitTestResult`) 确定触摸的目标是这个链接元素，然后模拟生成鼠标事件或分发 `click` 事件，最终导致浏览器导航到链接指向的 URL。

* **CSS:** CSS 可以影响元素的布局和渲染，这会影响 `GestureManager` 的命中测试结果。此外，`GestureManager` 模拟的鼠标事件可能会触发 CSS 的 `:hover`、`:active` 等伪类样式。
    * **例子:**  一个按钮元素定义了 `:hover` 样式，当用户触摸并按住按钮时，`GestureManager` 可能会模拟 `mousedown` 事件，这可能会导致按钮应用 `:active` 样式。在某些情况下，为了提供视觉反馈，`GestureManager` 甚至会模拟 `mousemove` 事件来触发 `:hover` 效果。

**逻辑推理和假设输入与输出：**

假设输入一个 `WebGestureEvent`，类型为 `kGestureTap`，发生在屏幕坐标 (100, 100) 的位置，没有按下任何修饰键。

* **假设输入:**
    ```
    WebGestureEvent {
      type = kGestureTap,
      x = 100,
      y = 100,
      modifiers = 0,
      ...
    }
    ```

* **逻辑推理:**
    1. `GestureManager` 接收到 `kGestureTap` 事件。
    2. 调用 `HandleGestureTap` 函数。
    3. 进行命中测试，确定屏幕坐标 (100, 100) 对应的 DOM 元素（假设是 `<div id="targetDiv">`）。
    4. 如果需要，模拟生成 `mousemove` 事件，更新悬停状态。
    5. 模拟生成 `mousedown` 事件，并分发给目标元素。
    6. 模拟生成 `mouseup` 事件，并分发给目标元素。
    7. 模拟生成 `click` 事件，并分发给目标元素。
    8. 如果有 JavaScript 监听了目标元素的 `click` 事件，则执行相应的 JavaScript 代码。

* **假设输出:**
    * 目标元素 `<div id="targetDiv">` 上触发了 `click` 事件。
    * 如果有 JavaScript 监听了 `click` 事件，则执行相应的处理逻辑。
    * 可能会有模拟的 `mousemove`、`mousedown` 和 `mouseup` 事件被分发。

**用户或编程常见的使用错误举例说明：**

* **用户错误:**  用户在移动设备上进行快速连续的点击，开发者可能没有考虑到这种场景，导致 JavaScript 代码中对于点击次数的处理逻辑出现错误。`GestureManager` 会尽力将这些操作转换为合适的鼠标或手势事件，但如果 JavaScript 代码没有正确处理，可能会出现意外行为。

* **编程错误:**
    * **没有阻止默认行为:**  开发者在处理手势事件时，如果没有调用 `event.preventDefault()` 阻止默认行为，可能会导致浏览器执行默认的操作，例如在链接上点击会导航到新的页面。
    * **错误地假设鼠标事件和触摸事件的互斥性:**  一些开发者可能会假设如果收到了触摸事件，就不会收到鼠标事件，反之亦然。但 `GestureManager` 为了兼容性会模拟鼠标事件，因此开发者需要在处理事件时考虑到这一点，避免重复处理逻辑。
    * **过度依赖特定的事件类型:**  开发者只监听 `touchstart` 和 `touchend` 事件，而忽略了 `GestureManager` 提供的更高级的手势事件 (如 `gesturestart`, `gesturechange`, `gestureend`)，可能会导致一些复杂的手势无法被正确识别和处理。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户触摸屏幕或使用触控板:**  用户与设备进行交互，产生触摸或手势操作。
2. **操作系统捕获输入事件:**  操作系统或设备驱动程序捕获到用户的输入事件。
3. **浏览器进程接收输入事件:**  Chromium 浏览器进程接收到操作系统传递过来的原始输入事件。
4. **浏览器进程识别为手势:**  浏览器进程中的手势识别器分析原始输入事件，判断是否构成一个手势。
5. **创建 `WebGestureEvent`:**  如果识别为一个手势，浏览器进程会创建一个 `WebGestureEvent` 对象，包含手势的类型、位置等信息。
6. **发送到渲染器进程:**  浏览器进程将 `WebGestureEvent` 发送到负责渲染网页的渲染器进程。
7. **到达 `GestureManager`:**  在渲染器进程中，`WebGestureEvent` 被传递给与特定 `LocalFrame` 关联的 `GestureManager` 实例。
8. **`HandleGestureEventInFrame` 处理:**  `GestureManager` 的 `HandleGestureEventInFrame` 方法接收到事件，并根据事件类型调用相应的处理函数（如 `HandleGestureTap`, `HandleGestureLongPress` 等）。
9. **命中测试:**  在处理函数中，通常会进行命中测试，确定手势的目标 DOM 元素。
10. **模拟鼠标事件或分发 DOM 事件:**  根据手势类型和需要，`GestureManager` 可能会模拟生成鼠标事件或创建并分发 `GestureEvent` DOM 事件。
11. **事件冒泡和捕获:**  DOM 事件按照标准的冒泡或捕获流程传递给 DOM 树中的元素。
12. **JavaScript 事件处理函数执行:**  如果目标元素或其父元素有注册了相应的事件监听器，JavaScript 代码会被执行。

**调试线索:**

* **查看 `WebGestureEvent` 的内容:**  在 Chromium 的调试工具中，可以查看传递给渲染器进程的 `WebGestureEvent` 的具体信息，包括类型、位置、触摸点等。这可以帮助确定浏览器进程是否正确识别了手势。
* **断点设置在 `GestureManager` 的关键方法:**  例如 `HandleGestureEventInFrame`、`HandleGestureTap` 等，可以跟踪手势事件的处理流程。
* **查看命中测试结果:**  可以查看命中测试的结果，确认手势事件是否定位到了正确的 DOM 元素。
* **监控 DOM 事件的触发:**  使用浏览器的开发者工具的事件监听器面板，可以监控哪些 DOM 事件被触发，以及触发的顺序和参数。
* **检查 JavaScript 代码:**  确认 JavaScript 代码中是否正确监听和处理了相关的鼠标或手势事件，以及是否阻止了默认行为。

总而言之，`blink/renderer/core/input/gesture_manager.cc` 是 Blink 引擎中至关重要的一个文件，它负责桥接底层的手势输入和上层的 Web 技术，使得用户可以通过触摸等方式与网页进行交互。理解它的功能和工作原理对于开发和调试涉及到手势交互的 Web 应用至关重要。

Prompt: 
```
这是目录为blink/renderer/core/input/gesture_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/input/gesture_manager.h"

#include "third_party/blink/public/common/input/web_input_event.h"
#include "third_party/blink/public/common/input/web_pointer_event.h"
#include "third_party/blink/public/mojom/frame/user_activation_notification_type.mojom-blink.h"
#include "third_party/blink/public/public_buildflags.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/editing/selection_controller.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/events/gesture_event.h"
#include "third_party/blink/renderer/core/events/pointer_event_factory.h"
#include "third_party/blink/renderer/core/fragment_directive/text_fragment_handler.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/input/context_menu_allowed_scope.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/input/event_handling_util.h"
#include "third_party/blink/renderer/core/input/input_device_capabilities.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "ui/gfx/geometry/point_conversions.h"

#if BUILDFLAG(ENABLE_UNHANDLED_TAP)
#include "third_party/blink/public/mojom/unhandled_tap_notifier/unhandled_tap_notifier.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/web/web_node.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#endif  // BUILDFLAG(ENABLE_UNHANDLED_TAP)

namespace blink {

namespace {

// The amount of drag (in pixels) that is considered to be within a slop region.
// This allows firing touch dragend contextmenu events for shaky fingers.
const int kTouchDragSlop = 8;

bool TouchDragAndContextMenuEnabled(const LocalFrame* frame) {
  return RuntimeEnabledFeatures::TouchDragAndContextMenuEnabled() &&
         frame->GetSettings() && !frame->GetSettings()->GetModalContextMenu();
}

}  // namespace

GestureManager::GestureManager(LocalFrame& frame,
                               ScrollManager& scroll_manager,
                               MouseEventManager& mouse_event_manager,
                               PointerEventManager& pointer_event_manager,
                               SelectionController& selection_controller)
    : frame_(frame),
      scroll_manager_(scroll_manager),
      mouse_event_manager_(mouse_event_manager),
      pointer_event_manager_(pointer_event_manager),
      selection_controller_(selection_controller) {
  Clear();
}

void GestureManager::Clear() {
  suppress_mouse_events_from_gestures_ = false;
  suppress_selection_on_repeated_tap_down_ = false;
  ResetLongTapContextMenuStates();
}

void GestureManager::ResetLongTapContextMenuStates() {
  gesture_context_menu_deferred_ = false;
  long_press_position_in_root_frame_ = gfx::PointF();
  drag_in_progress_ = false;
}

void GestureManager::Trace(Visitor* visitor) const {
  visitor->Trace(frame_);
  visitor->Trace(scroll_manager_);
  visitor->Trace(mouse_event_manager_);
  visitor->Trace(pointer_event_manager_);
  visitor->Trace(selection_controller_);
}

HitTestRequest::HitTestRequestType GestureManager::GetHitTypeForGestureType(
    WebInputEvent::Type type) {
  HitTestRequest::HitTestRequestType hit_type = HitTestRequest::kTouchEvent;
  switch (type) {
    case WebInputEvent::Type::kGestureShowPress:
    case WebInputEvent::Type::kGestureTapUnconfirmed:
      return hit_type | HitTestRequest::kActive;
    case WebInputEvent::Type::kGestureTapCancel:
      // A TapDownCancel received when no element is active shouldn't really be
      // changing hover state.
      if (!frame_->GetDocument()->GetActiveElement())
        hit_type |= HitTestRequest::kReadOnly;
      return hit_type | HitTestRequest::kRelease;
    case WebInputEvent::Type::kGestureTap:
      return hit_type | HitTestRequest::kRelease;
    case WebInputEvent::Type::kGestureTapDown:
    case WebInputEvent::Type::kGestureShortPress:
    case WebInputEvent::Type::kGestureLongPress:
    case WebInputEvent::Type::kGestureLongTap:
    case WebInputEvent::Type::kGestureTwoFingerTap:
      // FIXME: Shouldn't LongTap and TwoFingerTap clear the Active state?
      return hit_type | HitTestRequest::kActive | HitTestRequest::kReadOnly;
    default:
      NOTREACHED();
  }
}

WebInputEventResult GestureManager::HandleGestureEventInFrame(
    const GestureEventWithHitTestResults& targeted_event) {
  const HitTestResult& hit_test_result = targeted_event.GetHitTestResult();
  const WebGestureEvent& gesture_event = targeted_event.Event();
  DCHECK(!gesture_event.IsScrollEvent());

  if (Scrollbar* scrollbar = hit_test_result.GetScrollbar()) {
    if (scrollbar->HandleGestureTapOrPress(gesture_event)) {
      return WebInputEventResult::kHandledSuppressed;
    }
  }

  if (Node* event_target = hit_test_result.InnerNode()) {
    GestureEvent* gesture_dom_event = GestureEvent::Create(
        event_target->GetDocument().domWindow(), gesture_event);
    if (gesture_dom_event) {
      DispatchEventResult gesture_dom_event_result =
          event_target->DispatchEvent(*gesture_dom_event);
      if (gesture_dom_event_result != DispatchEventResult::kNotCanceled) {
        DCHECK(gesture_dom_event_result !=
               DispatchEventResult::kCanceledByEventHandler);
        return event_handling_util::ToWebInputEventResult(
            gesture_dom_event_result);
      }
    }
  }

  switch (gesture_event.GetType()) {
    case WebInputEvent::Type::kGestureTapDown:
      return HandleGestureTapDown(targeted_event);
    case WebInputEvent::Type::kGestureTap:
      return HandleGestureTap(targeted_event);
    case WebInputEvent::Type::kGestureShowPress:
      return HandleGestureShowPress();
    case WebInputEvent::Type::kGestureShortPress:
      return HandleGestureShortPress(targeted_event);
    case WebInputEvent::Type::kGestureLongPress:
      return HandleGestureLongPress(targeted_event);
    case WebInputEvent::Type::kGestureLongTap:
      return HandleGestureLongTap(targeted_event);
    case WebInputEvent::Type::kGestureTwoFingerTap:
      return HandleGestureTwoFingerTap(targeted_event);
    case WebInputEvent::Type::kGestureTapCancel:
    case WebInputEvent::Type::kGestureTapUnconfirmed:
      break;
    default:
      NOTREACHED();
  }

  return WebInputEventResult::kNotHandled;
}

bool GestureManager::GestureContextMenuDeferred() const {
  return gesture_context_menu_deferred_;
}

WebInputEventResult GestureManager::HandleGestureTapDown(
    const GestureEventWithHitTestResults& targeted_event) {
  const WebGestureEvent& gesture_event = targeted_event.Event();
  suppress_mouse_events_from_gestures_ =
      pointer_event_manager_->PrimaryPointerdownCanceled(
          gesture_event.unique_touch_event_id);

  if (!RuntimeEnabledFeatures::TouchTextEditingRedesignEnabled() ||
      suppress_mouse_events_from_gestures_ ||
      suppress_selection_on_repeated_tap_down_ ||
      gesture_event.TapDownCount() <= 1) {
    return WebInputEventResult::kNotHandled;
  }

  const WebMouseEvent fake_mouse_down(
      WebInputEvent::Type::kMouseDown, gesture_event,
      WebPointerProperties::Button::kLeft, gesture_event.TapDownCount(),
      static_cast<WebInputEvent::Modifiers>(
          gesture_event.GetModifiers() |
          WebInputEvent::Modifiers::kLeftButtonDown |
          WebInputEvent::Modifiers::kIsCompatibilityEventForTouch),
      gesture_event.TimeStamp());
  const HitTestResult& current_hit_test = targeted_event.GetHitTestResult();
  const HitTestLocation& current_hit_test_location =
      targeted_event.GetHitTestLocation();
  selection_controller_->HandleMousePressEvent(MouseEventWithHitTestResults(
      fake_mouse_down, current_hit_test_location, current_hit_test));

  return WebInputEventResult::kNotHandled;
}

WebInputEventResult GestureManager::HandleGestureTap(
    const GestureEventWithHitTestResults& targeted_event) {
  LocalFrameView* frame_view(frame_->View());
  const WebGestureEvent& gesture_event = targeted_event.Event();
  HitTestRequest::HitTestRequestType hit_type =
      GetHitTypeForGestureType(gesture_event.GetType());
  uint64_t pre_dispatch_dom_tree_version =
      frame_->GetDocument()->DomTreeVersion();
  uint64_t pre_dispatch_style_version = frame_->GetDocument()->StyleVersion();

  HitTestResult current_hit_test = targeted_event.GetHitTestResult();
  const HitTestLocation& current_hit_test_location =
      targeted_event.GetHitTestLocation();

  // We use the adjusted position so the application isn't surprised to see a
  // event with co-ordinates outside the target's bounds.
  gfx::Point adjusted_point = frame_view->ConvertFromRootFrame(
      gfx::ToFlooredPoint(gesture_event.PositionInRootFrame()));

  const unsigned modifiers = gesture_event.GetModifiers();

  if (!suppress_mouse_events_from_gestures_) {
    WebMouseEvent fake_mouse_move(
        WebInputEvent::Type::kMouseMove, gesture_event,
        WebPointerProperties::Button::kNoButton,
        /* clickCount */ 0,
        static_cast<WebInputEvent::Modifiers>(
            modifiers |
            WebInputEvent::Modifiers::kIsCompatibilityEventForTouch),
        gesture_event.TimeStamp());

    // This updates hover state to the location of the tap, but does NOT update
    // MouseEventManager::last_known_mouse_position_*. That's deliberate, since
    // we don't want the page to continue to act as if this point is hovered
    // (if the user scrolls for example).
    //
    // TODO(crbug.com/368256331): When we've applied a tap-based hover state, we
    // should actually suppress RecomputeMouseHoverState until the user moves
    // the mouse or navigates away.
    mouse_event_manager_->SetElementUnderMouseAndDispatchMouseEvent(
        current_hit_test.InnerElement(), event_type_names::kMousemove,
        fake_mouse_move);
  }

  // Do a new hit-test in case the mousemove event changed the DOM.
  // Note that if the original hit test wasn't over an element (eg. was over a
  // scrollbar) we don't want to re-hit-test because it may be in the wrong
  // frame (and there's no way the page could have seen the event anyway).  Also
  // note that the position of the frame may have changed, so we need to
  // recompute the content co-ordinates (updating layout/style as
  // hitTestResultAtPoint normally would).
  if (current_hit_test.InnerNode()) {
    LocalFrame& main_frame = frame_->LocalFrameRoot();
    if (!main_frame.View() ||
        !main_frame.View()->UpdateAllLifecyclePhasesExceptPaint(
            DocumentUpdateReason::kHitTest))
      return WebInputEventResult::kNotHandled;
    adjusted_point = frame_view->ConvertFromRootFrame(
        gfx::ToFlooredPoint(gesture_event.PositionInRootFrame()));
    current_hit_test = event_handling_util::HitTestResultInFrame(
        frame_, HitTestLocation(adjusted_point), hit_type);
  }

  // Capture data for showUnhandledTapUIIfNeeded.
  gfx::Point tapped_position =
      gfx::ToFlooredPoint(gesture_event.PositionInRootFrame());
  Node* tapped_node = current_hit_test.InnerNode();
  Element* tapped_element = current_hit_test.InnerElement();
  LocalFrame::NotifyUserActivation(
      tapped_node ? tapped_node->GetDocument().GetFrame() : nullptr,
      mojom::blink::UserActivationNotificationType::kInteraction);

  mouse_event_manager_->SetMouseDownElement(tapped_element);

  WebMouseEvent fake_mouse_down(
      WebInputEvent::Type::kMouseDown, gesture_event,
      WebPointerProperties::Button::kLeft, gesture_event.TapCount(),
      static_cast<WebInputEvent::Modifiers>(
          modifiers | WebInputEvent::Modifiers::kLeftButtonDown |
          WebInputEvent::Modifiers::kIsCompatibilityEventForTouch),
      gesture_event.TimeStamp());

  // TODO(mustaq): We suppress MEs plus all it's side effects. What would that
  // mean for for TEs?  What's the right balance here? crbug.com/617255
  WebInputEventResult mouse_down_event_result =
      WebInputEventResult::kHandledSuppressed;
  suppress_selection_on_repeated_tap_down_ = true;
  if (!suppress_mouse_events_from_gestures_) {
    mouse_event_manager_->SetClickCount(gesture_event.TapCount());

    mouse_down_event_result =
        mouse_event_manager_->SetElementUnderMouseAndDispatchMouseEvent(
            current_hit_test.InnerElement(), event_type_names::kMousedown,
            fake_mouse_down);
    selection_controller_->InitializeSelectionState();
    if (mouse_down_event_result == WebInputEventResult::kNotHandled) {
      mouse_down_event_result = mouse_event_manager_->HandleMouseFocus(
          current_hit_test,
          frame_->DomWindow()->GetInputDeviceCapabilities()->FiresTouchEvents(
              true));
    }
    if (mouse_down_event_result == WebInputEventResult::kNotHandled) {
      suppress_selection_on_repeated_tap_down_ = false;
      mouse_down_event_result = mouse_event_manager_->HandleMousePressEvent(
          MouseEventWithHitTestResults(
              fake_mouse_down, current_hit_test_location, current_hit_test));
    }
  }

  if (current_hit_test.InnerNode()) {
    DCHECK(gesture_event.GetType() == WebInputEvent::Type::kGestureTap);
    HitTestResult result = current_hit_test;
    result.SetToShadowHostIfInUAShadowRoot();
    frame_->GetChromeClient().OnMouseDown(*result.InnerNode());
  }

  if (current_hit_test.InnerNode()) {
    LocalFrame& main_frame = frame_->LocalFrameRoot();
    if (main_frame.View()) {
      main_frame.View()->UpdateAllLifecyclePhasesExceptPaint(
          DocumentUpdateReason::kHitTest);
    }
    adjusted_point = frame_view->ConvertFromRootFrame(tapped_position);
    current_hit_test = event_handling_util::HitTestResultInFrame(
        frame_, HitTestLocation(adjusted_point), hit_type);
  }

  WebMouseEvent fake_mouse_up(
      WebInputEvent::Type::kMouseUp, gesture_event,
      WebPointerProperties::Button::kLeft, gesture_event.TapCount(),
      static_cast<WebInputEvent::Modifiers>(
          modifiers | WebInputEvent::Modifiers::kIsCompatibilityEventForTouch),
      gesture_event.TimeStamp());
  WebInputEventResult mouse_up_event_result =
      suppress_mouse_events_from_gestures_
          ? WebInputEventResult::kHandledSuppressed
          : mouse_event_manager_->SetElementUnderMouseAndDispatchMouseEvent(
                current_hit_test.InnerElement(), event_type_names::kMouseup,
                fake_mouse_up);

  WebInputEventResult click_event_result = WebInputEventResult::kNotHandled;
  if (tapped_element) {
    if (current_hit_test.InnerNode()) {
      Node* click_target_node = current_hit_test.InnerNode()->CommonAncestor(
          *tapped_element, event_handling_util::ParentForClickEvent);
      auto* click_target_element = DynamicTo<Element>(click_target_node);
      fake_mouse_up.id = GetPointerIdFromWebGestureEvent(gesture_event);
      fake_mouse_up.pointer_type = gesture_event.primary_pointer_type;
      click_event_result =
          mouse_event_manager_->SetElementUnderMouseAndDispatchMouseEvent(
              click_target_element, event_type_names::kClick, fake_mouse_up);

      // Dispatching a JS event could have detached the frame.
      if (frame_->View())
        frame_->View()->RegisterTapEvent(tapped_element);
    }
    mouse_event_manager_->SetMouseDownElement(nullptr);
  }

  if (mouse_up_event_result == WebInputEventResult::kNotHandled) {
    mouse_up_event_result = mouse_event_manager_->HandleMouseReleaseEvent(
        MouseEventWithHitTestResults(fake_mouse_up, current_hit_test_location,
                                     current_hit_test));
  }
  mouse_event_manager_->ClearDragHeuristicState();

  WebInputEventResult event_result = event_handling_util::MergeEventResult(
      event_handling_util::MergeEventResult(mouse_down_event_result,
                                            mouse_up_event_result),
      click_event_result);

  if (RuntimeEnabledFeatures::TextFragmentTapOpensContextMenuEnabled() &&
      current_hit_test.InnerNodeFrame()) {
    current_hit_test.InnerNodeFrame()
        ->View()
        ->UpdateAllLifecyclePhasesExceptPaint(DocumentUpdateReason::kHitTest);
    current_hit_test = event_handling_util::HitTestResultInFrame(
        frame_, HitTestLocation(adjusted_point), hit_type);
    if (TextFragmentHandler::IsOverTextFragment(current_hit_test) &&
        event_result == WebInputEventResult::kNotHandled) {
      return SendContextMenuEventForGesture(targeted_event);
    }
  }

  // Default case when tap that is not handled.
  if (event_result == WebInputEventResult::kNotHandled && tapped_node &&
      frame_->GetPage()) {
    bool dom_tree_changed = pre_dispatch_dom_tree_version !=
                            frame_->GetDocument()->DomTreeVersion();
    bool style_changed =
        pre_dispatch_style_version != frame_->GetDocument()->StyleVersion();

    gfx::Point tapped_position_in_viewport =
        frame_->GetPage()->GetVisualViewport().RootFrameToViewport(
            tapped_position);
    ShowUnhandledTapUIIfNeeded(dom_tree_changed, style_changed, tapped_node,
                               tapped_position_in_viewport);
  }

  return event_result;
}

WebInputEventResult GestureManager::HandleGestureShortPress(
    const GestureEventWithHitTestResults& targeted_event) {
  drag_in_progress_ = false;
  // TODO(crbug.com/1299010): When TouchDragAndContextMenu is enabled, we want
  // to start drag here at short-press and open context-menu later at
  // long-press.  However, on Android an ACTION_CANCEL event is fired on
  // drag-start, and occcasionally that happens before long-press gesture
  // timeout which causes GestureRecognizer to suppress long-press detection.
  if (TouchDragAndContextMenuEnabled(frame_) &&
      RuntimeEnabledFeatures::TouchDragOnShortPressEnabled()) {
    drag_in_progress_ =
        mouse_event_manager_->HandleDragDropIfPossible(targeted_event);
  }
  return drag_in_progress_ ? WebInputEventResult::kHandledSystem
                           : WebInputEventResult::kNotHandled;
}

WebInputEventResult GestureManager::HandleGestureLongPress(
    const GestureEventWithHitTestResults& targeted_event) {
  const WebGestureEvent& gesture_event = targeted_event.Event();

  // FIXME: Ideally we should try to remove the extra mouse-specific hit-tests
  // here (re-using the supplied HitTestResult), but that will require some
  // overhaul of the touch drag-and-drop code and LongPress is such a special
  // scenario that it's unlikely to matter much in practice.

  long_press_position_in_root_frame_ = gesture_event.PositionInRootFrame();
  HitTestLocation location(frame_->View()->ConvertFromRootFrame(
      gfx::ToFlooredPoint(long_press_position_in_root_frame_)));
  HitTestResult hit_test_result =
      frame_->GetEventHandler().HitTestResultAtLocation(location);

  gesture_context_menu_deferred_ = false;

  if (TouchDragAndContextMenuEnabled(frame_)) {
    if (!RuntimeEnabledFeatures::TouchDragOnShortPressEnabled()) {
      drag_in_progress_ =
          mouse_event_manager_->HandleDragDropIfPossible(targeted_event);
    }
  } else if (frame_->GetSettings() &&
             frame_->GetSettings()->GetTouchDragDropEnabled() &&
             frame_->View()) {
    bool hit_test_contains_links =
        hit_test_result.URLElement() ||
        !hit_test_result.AbsoluteImageURL().IsNull() ||
        !hit_test_result.AbsoluteMediaURL().IsNull();
    if (!hit_test_contains_links &&
        mouse_event_manager_->HandleDragDropIfPossible(targeted_event)) {
      gesture_context_menu_deferred_ = true;
      return WebInputEventResult::kHandledSystem;
    }
  }

  Node* inner_node = hit_test_result.InnerNode();
  if (!drag_in_progress_ && inner_node && inner_node->GetLayoutObject() &&
      selection_controller_->HandleGestureLongPress(hit_test_result)) {
    mouse_event_manager_->FocusDocumentView();
  }

  if (frame_->GetSettings() &&
      frame_->GetSettings()->GetShowContextMenuOnMouseUp()) {
    // TODO(https://crbug.com/1290905): Prevent a contextmenu after a
    // finger-drag when TouchDragAndContextMenu is enabled.
    gesture_context_menu_deferred_ = true;
    return WebInputEventResult::kNotHandled;
  }

  LocalFrame::NotifyUserActivation(
      inner_node ? inner_node->GetDocument().GetFrame() : nullptr,
      mojom::blink::UserActivationNotificationType::kInteraction);
  return SendContextMenuEventForGesture(targeted_event);
}

WebInputEventResult GestureManager::HandleGestureLongTap(
    const GestureEventWithHitTestResults& targeted_event) {
  if (gesture_context_menu_deferred_) {
    gesture_context_menu_deferred_ = false;
    return SendContextMenuEventForGesture(targeted_event);
  }
  return WebInputEventResult::kNotHandled;
}

WebInputEventResult GestureManager::HandleGestureTwoFingerTap(
    const GestureEventWithHitTestResults& targeted_event) {
  Node* inner_node = targeted_event.GetHitTestResult().InnerNode();
  if (inner_node && inner_node->GetLayoutObject())
    selection_controller_->HandleGestureTwoFingerTap(targeted_event);
  return SendContextMenuEventForGesture(targeted_event);
}

void GestureManager::SendContextMenuEventTouchDragEnd(
    const WebMouseEvent& mouse_event) {
  if (!gesture_context_menu_deferred_ || suppress_mouse_events_from_gestures_) {
    return;
  }

  const gfx::PointF& positon_in_root_frame = mouse_event.PositionInWidget();

  // Don't send contextmenu event if tap position is not within a slop region.
  //
  // TODO(mustaq): We should be reusing gesture touch-slop region here but it
  // seems non-trivial because this code path is called at drag-end, and the
  // drag controller does not sync well with gesture recognizer.  See the
  // blocked-on bugs in https://crbug.com/1096189.
  if ((positon_in_root_frame - long_press_position_in_root_frame_).Length() >
      kTouchDragSlop)
    return;

  ContextMenuAllowedScope scope;
  frame_->GetEventHandler().SendContextMenuEvent(mouse_event);
  ResetLongTapContextMenuStates();
}

WebInputEventResult GestureManager::SendContextMenuEventForGesture(
    const GestureEventWithHitTestResults& targeted_event) {
  const WebGestureEvent& gesture_event = targeted_event.Event();
  unsigned modifiers = gesture_event.GetModifiers();

  if (!suppress_mouse_events_from_gestures_) {
    // Send MouseMove event prior to handling (https://crbug.com/485290).
    WebMouseEvent fake_mouse_move(
        WebInputEvent::Type::kMouseMove, gesture_event,
        WebPointerProperties::Button::kNoButton,
        /* clickCount */ 0,
        static_cast<WebInputEvent::Modifiers>(
            modifiers | WebInputEvent::kIsCompatibilityEventForTouch),
        gesture_event.TimeStamp());
    mouse_event_manager_->SetElementUnderMouseAndDispatchMouseEvent(
        targeted_event.GetHitTestResult().InnerElement(),
        event_type_names::kMousemove, fake_mouse_move);
  }

  WebInputEvent::Type event_type = WebInputEvent::Type::kMouseDown;
  if (frame_->GetSettings() &&
      frame_->GetSettings()->GetShowContextMenuOnMouseUp())
    event_type = WebInputEvent::Type::kMouseUp;

  WebMouseEvent mouse_event(
      event_type, gesture_event, WebPointerProperties::Button::kNoButton,
      /* clickCount */ 0,
      static_cast<WebInputEvent::Modifiers>(
          modifiers | WebInputEvent::kIsCompatibilityEventForTouch),
      gesture_event.TimeStamp());

  if (!suppress_mouse_events_from_gestures_ && frame_->View()) {
    HitTestRequest request(HitTestRequest::kActive);
    PhysicalOffset document_point(frame_->View()->ConvertFromRootFrame(
        gfx::ToFlooredPoint(targeted_event.Event().PositionInRootFrame())));
    MouseEventWithHitTestResults mev =
        frame_->GetDocument()->PerformMouseEventHitTest(request, document_point,
                                                        mouse_event);
    mouse_event_manager_->HandleMouseFocus(mev.GetHitTestResult(),
                                           frame_->GetDocument()
                                               ->domWindow()
                                               ->GetInputDeviceCapabilities()
                                               ->FiresTouchEvents(true));
  }
  mouse_event.id = GetPointerIdFromWebGestureEvent(gesture_event);
  mouse_event.pointer_type = gesture_event.primary_pointer_type;
  return frame_->GetEventHandler().SendContextMenuEvent(mouse_event);
}

WebInputEventResult GestureManager::HandleGestureShowPress() {
  LocalFrameView* view = frame_->View();
  if (!view)
    return WebInputEventResult::kNotHandled;
  for (auto& scrollable_area : view->ScrollableAreas().Values()) {
    if (scrollable_area->ScrollsOverflow())
      scrollable_area->CancelScrollAnimation();
  }
  return WebInputEventResult::kNotHandled;
}

void GestureManager::ShowUnhandledTapUIIfNeeded(
    bool dom_tree_changed,
    bool style_changed,
    Node* tapped_node,
    const gfx::Point& tapped_position_in_viewport) {
#if BUILDFLAG(ENABLE_UNHANDLED_TAP)
  WebNode web_node(tapped_node);
  bool should_trigger = !dom_tree_changed && !style_changed &&
                        tapped_node->IsTextNode() &&
                        !web_node.IsContentEditable() &&
                        !web_node.IsInsideFocusableElementOrARIAWidget();
  // Renderer-side trigger-filtering to minimize messaging.
  // The Browser may do additional trigger-filtering.
  if (should_trigger) {
    // Start setting up the Mojo interface connection.
    mojo::Remote<mojom::blink::UnhandledTapNotifier> provider;
    frame_->GetBrowserInterfaceBroker().GetInterface(
        provider.BindNewPipeAndPassReceiver());

    // Notify the Browser.
    auto tapped_info =
        mojom::blink::UnhandledTapInfo::New(tapped_position_in_viewport);
    provider->ShowUnhandledTapUIIfNeeded(std::move(tapped_info));
  }
#endif  // BUILDFLAG(ENABLE_UNHANDLED_TAP)
}

PointerId GestureManager::GetPointerIdFromWebGestureEvent(
    const WebGestureEvent& gesture_event) const {
  if (!frame_->IsLocalRoot()) {
    return frame_->LocalFrameRoot()
        .GetEventHandler()
        .GetGestureManager()
        .GetPointerIdFromWebGestureEvent(gesture_event);
  }

  // When tests send Tap, LongTap, LongPress, TwoFingerTap directly
  // (e.g. from eventSender) there is no primary_unique_touch_event_id
  // populated.
  if (gesture_event.primary_unique_touch_event_id == 0)
    return PointerEventFactory::kInvalidId;

  return pointer_event_manager_->GetPointerIdForTouchGesture(
      gesture_event.primary_unique_touch_event_id);
}

}  // namespace blink

"""

```