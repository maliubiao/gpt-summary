Response:
My thinking process to analyze the `touch_event_manager.cc` file and generate the comprehensive response involved several steps:

1. **Understand the Core Functionality:** I first read through the code to get a general idea of its purpose. The name "TouchEventManager" strongly suggests it's responsible for handling touch events within the Blink rendering engine. The imports confirmed this, showing interaction with `WebTouchEvent`, `WebPointerEvent`, `Touch`, `TouchEvent`, and DOM elements.

2. **Identify Key Data Structures:** I paid attention to the main data structures used:
    * `touch_attribute_map_`:  A `HashMap` storing information about individual touch points (fingers). This seemed crucial for tracking the state of each touch.
    * `touch_sequence_document_`:  A `Member<Document>` indicating the document that "owns" the current touch sequence. This is important for preventing cross-document event dispatch issues.
    * `last_coalesced_touch_event_`:  Stores the last combined touch event, useful for coalescing events.

3. **Trace the Event Flow (Conceptual):**  I mentally walked through the likely steps of a touch interaction:
    * A touch starts (pointerdown).
    * The touch moves (pointermove).
    * The touch ends (pointerup) or is canceled (pointercancel).
    * The manager needs to track these events, potentially combine them, and dispatch them to the appropriate JavaScript handlers.

4. **Analyze Individual Functions:** I then looked at the purpose of key functions:
    * `HandleTouchPoint()`:  Likely the entry point for processing incoming `WebPointerEvent`s.
    * `UpdateTouchAttributeMapsForPointerDown()`:  Handles the start of a touch, recording its details.
    * `DispatchTouchEventFromAccumulatdTouchPoints()`:  The core logic for constructing and dispatching `TouchEvent`s to JavaScript. This function seemed particularly important.
    * `GenerateWebCoalescedInputEvent()`:  Responsible for combining multiple individual touch updates into a single `WebTouchEvent`.
    * `FlushEvents()`:  The mechanism for actually triggering the dispatch of accumulated events and cleaning up state.
    * Helper functions like `CreateDomTouch()`, `TouchEventNameForPointerEventType()`, etc., which assist in constructing event objects.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Based on the understanding of the core functionality, I considered how this relates to web development:
    * **JavaScript:**  The manager's primary role is to deliver touch events that JavaScript can listen for (e.g., `touchstart`, `touchmove`, `touchend`, `touchcancel`).
    * **HTML:**  The target of touch events is an HTML element. The hit-testing logic (`GetTouchPointerNode()`) is key for determining which element receives the event.
    * **CSS:** The `touch-action` CSS property influences how the browser handles touch input for scrolling and panning. The code references `TouchAction` and interacts with the Chrome client to set this.

6. **Identify Logic and Assumptions:** I looked for places where the code made decisions based on input:
    * The logic for coalescing events (combining multiple touch updates).
    * The handling of `touch-action` and preventing default behavior.
    * The logic for managing the `touch_sequence_document_`.
    * The suppression of `touchmove` events within the "slop region" (a small distance threshold to avoid excessive event firing).

7. **Consider User/Programming Errors:**  I thought about common mistakes developers might make when dealing with touch events:
    * Forgetting to call `preventDefault()` to prevent default browser behavior (like scrolling).
    * Assuming single-touch interactions when multi-touch is possible.
    * Misunderstanding the difference between `touches`, `targetTouches`, and `changedTouches`.

8. **Trace User Interaction:** I visualized a user interacting with a webpage using touch:
    * Finger down -> `HandleTouchPoint` (pointerdown), `UpdateTouchAttributeMapsForPointerDown`.
    * Finger moves -> `HandleTouchPoint` (pointermove).
    * Frame rendering might trigger `FlushEvents` to dispatch accumulated moves.
    * Finger up -> `HandleTouchPoint` (pointerup).
    * `FlushEvents` would then dispatch the `touchend` event and clean up.

9. **Structure the Response:** Finally, I organized my findings into the requested categories:
    * **Functionality:**  A high-level overview of the file's purpose.
    * **Relationship to JavaScript, HTML, CSS:** Concrete examples demonstrating the interaction.
    * **Logic and Reasoning:**  Describing the conditional logic and data flow, including assumptions and examples.
    * **Common Errors:**  Illustrating potential pitfalls for developers.
    * **User Interaction and Debugging:**  Providing a step-by-step guide and debugging tips.

Throughout this process, I paid close attention to the specific wording in the code comments and variable names to ensure accuracy and clarity. For example, the comments about `touch_sequence_document_` preventing cross-document leaks directly informed that part of my analysis. The `#ifdef UNSAFE_BUFFERS_BUILD` comment, while not directly a functionality, was noted as a potential area for future code improvements.好的，让我们来分析一下 `blink/renderer/core/input/touch_event_manager.cc` 文件的功能。

**功能概述**

`TouchEventManager` 类在 Chromium Blink 渲染引擎中负责管理和处理触摸事件。它的主要职责包括：

1. **接收和记录触摸点信息:** 接收来自底层输入系统（通常是操作系统或浏览器进程）的原始触摸事件（以 `WebPointerEvent` 的形式），并维护当前活跃的触摸点状态和属性（例如，触摸点的 ID、位置、目标元素等）。
2. **合并（Coalesce）触摸事件:**  对于快速连续的触摸移动事件，可以将它们合并成一个 `WebTouchEvent`，以减少需要处理的事件数量，提高性能。
3. **确定触摸事件的目标元素:**  进行命中测试（Hit Test），找到触摸点下的 DOM 元素，作为事件的目标。
4. **创建和分发 `TouchEvent` 对象:**  根据记录的触摸点信息，创建符合 W3C 规范的 `TouchEvent` JavaScript 对象。这些对象包含了 `touches`（所有当前活跃的触摸点）、`targetTouches`（目标元素上的触摸点）和 `changedTouches`（本次事件中状态发生变化的触摸点）等属性。
5. **处理 `touch-action` CSS 属性:**  根据目标元素的 `touch-action` CSS 属性，决定是否允许浏览器执行默认的触摸行为，例如滚动或缩放。
6. **管理触摸序列:** 跟踪一个完整的触摸交互过程（从 `touchstart` 到 `touchend` 或 `touchcancel`），确保同一触摸序列的事件被发送到同一个文档，防止跨文档的节点泄漏。
7. **处理事件的阻止和被动监听器:** 考虑事件监听器是被动 (`passive`) 还是阻止默认行为 (`preventDefault`)。
8. **延迟应用 `touch-action`:** 在某些情况下，`touch-action` 的应用可能会延迟到 `touchstart` 事件被处理之后。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`TouchEventManager` 是连接底层触摸输入和 Web 前端技术（JavaScript, HTML, CSS）的关键桥梁。

* **JavaScript:**
    * **功能关系:**  `TouchEventManager` 创建的 `TouchEvent` 对象会被分发到 JavaScript 代码中注册的触摸事件监听器。开发者可以使用 JavaScript 来监听 `touchstart`, `touchmove`, `touchend`, `touchcancel` 等事件，并获取触摸点的坐标、目标元素等信息，从而实现交互功能。
    * **举例说明:**  一个网页上的按钮元素注册了 `touchstart` 事件监听器。当用户触摸按钮时，`TouchEventManager` 会识别到触摸事件，创建一个 `TouchEvent` 对象，并将其传递给按钮的 `touchstart` 监听器。JavaScript 代码可以获取触摸点的坐标，并执行相应的操作，例如改变按钮的样式或导航到另一个页面。

* **HTML:**
    * **功能关系:**  HTML 元素是触摸事件的目标。`TouchEventManager` 通过命中测试确定哪个 HTML 元素接收到触摸事件。
    * **举例说明:**  一个 `<div>` 元素覆盖了页面的某个区域。当用户触摸这个 `<div>` 元素时，`TouchEventManager` 会将该 `<div>` 元素识别为触摸事件的目标，并将 `TouchEvent` 对象分发给该元素上注册的监听器。

* **CSS:**
    * **功能关系:**  `TouchEventManager` 会读取和应用元素的 `touch-action` CSS 属性。`touch-action` 属性允许开发者控制浏览器的默认触摸行为，例如是否允许滚动、缩放等。
    * **举例说明:**  一个图片元素设置了 `touch-action: pan-y pinch-zoom`。当用户在这个图片上进行触摸操作时，`TouchEventManager` 会读取这个属性，并允许垂直方向的拖动（`pan-y`）和双指缩放（`pinch-zoom`），但可能会阻止水平方向的拖动。如果设置为 `touch-action: none`，则会阻止所有的默认触摸行为。

**逻辑推理及假设输入与输出**

假设用户在屏幕上进行一次简单的触摸并滑动操作：

**假设输入:**

1. **touchstart (WebPointerEvent):**  一个手指按下屏幕，包含触摸点的 ID、屏幕坐标、窗口坐标等信息。假设触摸点 ID 为 1。
2. **touchmove (WebPointerEvent):**  手指在屏幕上移动了一段距离，包含更新后的触摸点坐标。
3. **touchend (WebPointerEvent):**  手指离开屏幕。

**TouchEventManager 的内部处理逻辑 (简化):**

1. **接收 touchstart:** `HandleTouchPoint` 接收到 `touchstart` 事件，创建一个 `TouchPointAttributes` 对象存储触摸点 1 的信息，并进行命中测试确定目标元素。如果这是第一个触摸点，可能会设置 `touch_sequence_document_`。
2. **接收 touchmove:** `HandleTouchPoint` 接收到 `touchmove` 事件，更新触摸点 1 的 `TouchPointAttributes` 信息。可能会将这个 `touchmove` 事件与之前的事件合并到 `coalesced_events_` 中。
3. **FlushEvents:**  在合适的时机（例如，浏览器渲染帧之前），`FlushEvents` 被调用。
4. **GenerateWebCoalescedInputEvent:** `GenerateWebCoalescedInputEvent` 将累积的 `WebPointerEvent` 合并成一个 `WebTouchEvent` 对象。
5. **DispatchTouchEventFromAccumulatdTouchPoints:**
   * 创建 `Touch` 对象表示触摸点 1。
   * 创建 `TouchEvent` 对象，设置 `touches` (包含触摸点 1), `targetTouches` (如果目标元素没有变化，也包含触摸点 1), `changedTouches` (包含状态为 `moved` 的触摸点 1)。
   * 将 `TouchEvent` 分发到目标元素的事件监听器。
6. **接收 touchend:** `HandleTouchPoint` 接收到 `touchend` 事件，更新触摸点 1 的状态。
7. **FlushEvents (再次):**
   * 创建 `TouchEvent` 对象，设置 `changedTouches` (包含状态为 `released` 的触摸点 1)。
   * 分发 `touchend` 事件。
   * 清理 `touch_attribute_map_` 中关于触摸点 1 的信息。如果所有触摸点都已释放，则可能清理 `touch_sequence_document_`。

**输出 (传递给 JavaScript 的 TouchEvent 对象):**

1. **touchstart (TouchEvent):**
   * `touches`: 包含一个 `Touch` 对象，表示按下的触摸点。
   * `targetTouches`: 包含一个 `Touch` 对象，表示目标元素上的触摸点。
   * `changedTouches`: 包含一个 `Touch` 对象，表示状态变为 `pressed` 的触摸点。
2. **touchmove (TouchEvent):**
   * `touches`: 包含一个 `Touch` 对象，表示当前屏幕上的触摸点。
   * `targetTouches`: 包含一个 `Touch` 对象，表示目标元素上的触摸点。
   * `changedTouches`: 包含一个 `Touch` 对象，表示状态变为 `moved` 的触摸点。
3. **touchend (TouchEvent):**
   * `touches`: 空数组（因为触摸已结束）。
   * `targetTouches`: 空数组。
   * `changedTouches`: 包含一个 `Touch` 对象，表示状态变为 `released` 的触摸点。

**用户或编程常见的使用错误**

1. **忘记调用 `preventDefault()` 阻止默认行为:**
   * **场景:**  用户在一个可以滚动的 `div` 元素上触摸并滑动。
   * **错误:** JavaScript 的 `touchmove` 监听器没有调用 `event.preventDefault()`。
   * **结果:**  浏览器会同时触发 JavaScript 的触摸事件和执行默认的滚动行为，可能导致页面抖动或意外的滚动。
2. **误解 `touches`, `targetTouches`, `changedTouches` 的区别:**
   * **场景:**  用户使用两根手指进行触摸操作。
   * **错误:**  开发者错误地使用了 `touches` 而不是 `changedTouches` 来获取当前发生变化的那个触摸点的信息。
   * **结果:**  可能无法正确识别和处理多点触控的交互，例如缩放或旋转。
3. **在被动监听器中调用 `preventDefault()`:**
   * **场景:**  开发者为了性能优化，将触摸事件监听器设置为被动 (`{ passive: true }`)。
   * **错误:**  在监听器中尝试调用 `event.preventDefault()`。
   * **结果:**  浏览器会忽略 `preventDefault()` 的调用，并可能在控制台中发出警告，因为被动监听器不允许阻止默认行为。
4. **假设总是只有一个触摸点:**
   * **场景:**  代码只处理 `touches[0]`，没有考虑多点触控的情况。
   * **错误:**  没有正确处理用户使用多个手指进行操作的场景。
   * **结果:**  多点触控操作可能无法正常工作，或者只响应了第一个触摸点。

**用户操作如何一步步到达这里 (调试线索)**

当你在网页上进行触摸操作时，操作系统或浏览器进程会捕获这些输入事件，并将它们转换为浏览器可以理解的事件。以下是一个简化的流程，说明用户操作如何一步步到达 `TouchEventManager`：

1. **用户触摸屏幕:**  用户的手指接触到设备的触摸屏。
2. **操作系统捕获输入:** 操作系统检测到触摸事件，并生成相应的系统级别的触摸事件信息，例如触摸点的坐标、状态（按下、移动、释放）等。
3. **浏览器进程接收事件:** 操作系统将触摸事件传递给浏览器进程。
4. **浏览器进程路由事件:** 浏览器进程确定哪个渲染进程负责处理该触摸事件（通常基于触摸点下的窗口或标签页）。
5. **渲染进程接收 `WebTouchEvent` 或 `WebPointerEvent`:**  渲染进程接收到表示触摸事件的 `WebTouchEvent` 或更底层的 `WebPointerEvent` 对象。
6. **`LocalFrameView::ProcessInputEvent()`:** 渲染进程的 `LocalFrameView` 接收到输入事件。
7. **`EventHandler::HandleTouchEvent()` 或 `EventHandler::HandlePointerEvent()`:**  `EventHandler` 负责初步处理触摸或指针事件。
8. **`TouchEventManager::HandleTouchPoint()` (或相关的处理函数):**  对于触摸事件，最终会调用 `TouchEventManager` 的 `HandleTouchPoint` 方法，将 `WebPointerEvent` 的信息记录下来。
9. **后续处理和分发:**  `TouchEventManager` 会根据事件类型和状态进行后续的处理，例如合并事件、确定目标、创建 `TouchEvent` 对象，并将其分发到 JavaScript 代码。

**作为调试线索:**

* **断点:**  在 `TouchEventManager` 的关键方法（如 `HandleTouchPoint`, `DispatchTouchEventFromAccumulatdTouchPoints`, `FlushEvents`）设置断点，可以观察触摸事件的传递和处理过程。
* **日志输出:**  在 `TouchEventManager` 中添加日志输出，记录接收到的 `WebPointerEvent` 的信息、触摸点的状态变化、分发的 `TouchEvent` 的属性等，有助于理解事件处理流程。
* **DevTools 的事件监听器面板:**  Chrome DevTools 的 "Elements" 面板下的 "Event Listeners" 标签可以查看特定 DOM 元素上注册的触摸事件监听器，以及事件是否被阻止（preventDefault）。
* **DevTools 的性能面板:**  可以使用性能面板记录触摸交互过程，分析事件的触发频率和处理时间，找出性能瓶颈。
* **检查 `touch-action` 属性:**  使用 DevTools 的 "Elements" 面板检查目标元素的 `touch-action` CSS 属性，确认是否符合预期。

希望以上详细的解释能够帮助你理解 `TouchEventManager` 的功能和它在 Blink 渲染引擎中的作用。

### 提示词
```
这是目录为blink/renderer/core/input/touch_event_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/input/touch_event_manager.h"

#include <memory>

#include "base/ranges/algorithm.h"
#include "third_party/blink/public/common/input/web_coalesced_input_event.h"
#include "third_party/blink/public/common/input/web_touch_event.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/events/touch_event.h"
#include "third_party/blink/renderer/core/frame/event_handler_registry.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/input/event_handling_util.h"
#include "third_party/blink/renderer/core/input/touch_action_util.h"
#include "third_party/blink/renderer/core/layout/hit_test_canvas_result.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"

namespace blink {

namespace {

// Returns true if there are event listeners of |handler_class| on |touch_node|
// or any of its ancestors inside the document (including DOMWindow).
bool HasEventHandlerInAncestorPath(
    Node* touch_node,
    EventHandlerRegistry::EventHandlerClass handler_class) {
  Document& document = touch_node->GetDocument();
  const EventTargetSet* event_target_set =
      document.GetFrame()->GetEventHandlerRegistry().EventHandlerTargets(
          handler_class);

  if (event_target_set->Contains(document.domWindow()))
    return true;

  for (Node& ancestor : NodeTraversal::InclusiveAncestorsOf(*touch_node)) {
    if (event_target_set->Contains(&ancestor))
      return true;
  }

  return false;
}

bool HasTouchHandlers(const EventHandlerRegistry& registry) {
  return registry.HasEventHandlers(
             EventHandlerRegistry::kTouchStartOrMoveEventBlocking) ||
         registry.HasEventHandlers(
             EventHandlerRegistry::kTouchStartOrMoveEventBlockingLowLatency) ||
         registry.HasEventHandlers(
             EventHandlerRegistry::kTouchStartOrMoveEventPassive) ||
         registry.HasEventHandlers(
             EventHandlerRegistry::kTouchEndOrCancelEventBlocking) ||
         registry.HasEventHandlers(
             EventHandlerRegistry::kTouchEndOrCancelEventPassive);
}

const AtomicString& TouchEventNameForPointerEventType(
    WebInputEvent::Type type) {
  switch (type) {
    case WebInputEvent::Type::kPointerUp:
      return event_type_names::kTouchend;
    case WebInputEvent::Type::kPointerCancel:
      return event_type_names::kTouchcancel;
    case WebInputEvent::Type::kPointerDown:
      return event_type_names::kTouchstart;
    case WebInputEvent::Type::kPointerMove:
      return event_type_names::kTouchmove;
    default:
      NOTREACHED();
  }
}

WebTouchPoint::State TouchPointStateFromPointerEventType(
    WebInputEvent::Type type,
    bool stale) {
  if (stale)
    return WebTouchPoint::State::kStateStationary;
  switch (type) {
    case WebInputEvent::Type::kPointerUp:
      return WebTouchPoint::State::kStateReleased;
    case WebInputEvent::Type::kPointerCancel:
      return WebTouchPoint::State::kStateCancelled;
    case WebInputEvent::Type::kPointerDown:
      return WebTouchPoint::State::kStatePressed;
    case WebInputEvent::Type::kPointerMove:
      return WebTouchPoint::State::kStateMoved;
    default:
      NOTREACHED();
  }
}

WebTouchPoint CreateWebTouchPointFromWebPointerEvent(
    const WebPointerEvent& web_pointer_event,
    bool stale) {
  WebTouchPoint web_touch_point(web_pointer_event);
  web_touch_point.state =
      TouchPointStateFromPointerEventType(web_pointer_event.GetType(), stale);
  web_touch_point.radius_x = web_pointer_event.width / 2.f;
  web_touch_point.radius_y = web_pointer_event.height / 2.f;
  web_touch_point.rotation_angle = web_pointer_event.rotation_angle;
  return web_touch_point;
}

void SetWebTouchEventAttributesFromWebPointerEvent(
    WebTouchEvent* web_touch_event,
    const WebPointerEvent& web_pointer_event) {
  web_touch_event->dispatch_type = web_pointer_event.dispatch_type;
  web_touch_event->touch_start_or_first_touch_move =
      web_pointer_event.touch_start_or_first_touch_move;
  web_touch_event->moved_beyond_slop_region =
      web_pointer_event.moved_beyond_slop_region;
  web_touch_event->SetFrameScale(web_pointer_event.FrameScale());
  web_touch_event->SetFrameTranslate(web_pointer_event.FrameTranslate());
  web_touch_event->SetTimeStamp(web_pointer_event.TimeStamp());
  web_touch_event->SetModifiers(web_pointer_event.GetModifiers());
}

// Defining this class type local to
// DispatchTouchEventFromAccumulatdTouchPoints() and annotating
// it with STACK_ALLOCATED(), runs into MSVC(VS 2013)'s C4822 warning
// that the local class doesn't provide a local definition for 'operator new'.
// Which it intentionally doesn't and shouldn't.
//
// Work around such toolchain bugginess by lifting out the type, thereby
// taking it out of C4822's reach.
class ChangedTouches final {
  STACK_ALLOCATED();

 public:
  // The touches corresponding to the particular change state this struct
  // instance represents.
  TouchList* touches_ = nullptr;

  using EventTargetSet = HeapHashSet<Member<EventTarget>>;
  // Set of targets involved in m_touches.
  EventTargetSet targets_;
};

}  // namespace

TouchEventManager::TouchEventManager(LocalFrame& frame) : frame_(frame) {
  Clear();
}

void TouchEventManager::Clear() {
  touch_sequence_document_.Clear();
  touch_attribute_map_.clear();
  last_coalesced_touch_event_ = WebTouchEvent();
  suppressing_touchmoves_within_slop_ = false;
  current_touch_action_ = TouchAction::kAuto;
}

void TouchEventManager::Trace(Visitor* visitor) const {
  visitor->Trace(frame_);
  visitor->Trace(touch_sequence_document_);
  visitor->Trace(touch_attribute_map_);
}

Touch* TouchEventManager::CreateDomTouch(
    const TouchEventManager::TouchPointAttributes* point_attr,
    bool* known_target) {
  Node* touch_node = point_attr->target_;
  *known_target = false;

  LocalFrame* target_frame = nullptr;
  if (touch_node) {
    Document& doc = touch_node->GetDocument();
    // If the target node has moved to a new document while it was being
    // touched, we can't send events to the new document because that could
    // leak nodes from one document to another. See http://crbug.com/394339.
    if (&doc == touch_sequence_document_.Get()) {
      target_frame = doc.GetFrame();
      *known_target = true;
    }
  }
  if (!(*known_target)) {
    // If we don't have a target registered for the point it means we've
    // missed our opportunity to do a hit test for it (due to some
    // optimization that prevented blink from ever seeing the
    // touchstart), or that the touch started outside the active touch
    // sequence document. We should still include the touch in the
    // Touches list reported to the application (eg. so it can
    // differentiate between a one and two finger gesture), but we won't
    // actually dispatch any events for it. Set the target to the
    // Document so that there's some valid node here. Perhaps this
    // should really be LocalDOMWindow, but in all other cases the target of
    // a Touch is a Node so using the window could be a breaking change.
    // Since we know there was no handler invoked, the specific target
    // should be completely irrelevant to the application.
    touch_node = touch_sequence_document_;
    target_frame = touch_sequence_document_->GetFrame();
  }
  DCHECK(target_frame);

  WebPointerEvent transformed_event =
      point_attr->event_.WebPointerEventInRootFrame();
  float scale_factor = 1.0f / target_frame->LayoutZoomFactor();

  gfx::PointF document_point =
      gfx::ScalePoint(target_frame->View()->RootFrameToDocument(
                          transformed_event.PositionInWidget()),
                      scale_factor);
  gfx::SizeF adjusted_radius = gfx::ScaleSize(
      gfx::SizeF(transformed_event.width / 2.f, transformed_event.height / 2.f),
      scale_factor);

  return MakeGarbageCollected<Touch>(
      target_frame, touch_node, point_attr->event_.id,
      transformed_event.PositionInScreen(), document_point, adjusted_radius,
      transformed_event.rotation_angle, transformed_event.force);
}

WebCoalescedInputEvent TouchEventManager::GenerateWebCoalescedInputEvent() {
  DCHECK(!touch_attribute_map_.empty());

  auto event = std::make_unique<WebTouchEvent>();

  const auto& first_touch_pointer_event =
      touch_attribute_map_.begin()->value->event_;

  SetWebTouchEventAttributesFromWebPointerEvent(event.get(),
                                                first_touch_pointer_event);
  SetWebTouchEventAttributesFromWebPointerEvent(&last_coalesced_touch_event_,
                                                first_touch_pointer_event);
  WebInputEvent::Type touch_event_type = WebInputEvent::Type::kTouchMove;
  Vector<WebPointerEvent> all_coalesced_events;
  Vector<int> available_ids;
  WTF::CopyKeysToVector(touch_attribute_map_, available_ids);
  std::sort(available_ids.begin(), available_ids.end());
  for (const int& touch_point_id : available_ids) {
    auto* const touch_point_attribute = touch_attribute_map_.at(touch_point_id);
    const WebPointerEvent& touch_pointer_event = touch_point_attribute->event_;
    event->touches[event->touches_length++] =
        CreateWebTouchPointFromWebPointerEvent(touch_pointer_event,
                                               touch_point_attribute->stale_);
    if (!touch_point_attribute->stale_) {
      event->SetTimeStamp(std::max(event->TimeStamp(),
                                   touch_point_attribute->event_.TimeStamp()));
    }

    // Only change the touch event type from move. So if we have two pointers
    // in up and down state we just set the touch event type to the first one
    // we see.
    // TODO(crbug.com/732842): Note that event sender API allows sending any
    // mix of input and as long as we don't crash or anything we should be good
    // for now.
    if (touch_event_type == WebInputEvent::Type::kTouchMove) {
      if (touch_pointer_event.GetType() == WebInputEvent::Type::kPointerDown)
        touch_event_type = WebInputEvent::Type::kTouchStart;
      else if (touch_pointer_event.GetType() ==
               WebInputEvent::Type::kPointerCancel)
        touch_event_type = WebInputEvent::Type::kTouchCancel;
      else if (touch_pointer_event.GetType() == WebInputEvent::Type::kPointerUp)
        touch_event_type = WebInputEvent::Type::kTouchEnd;
    }

    for (const WebPointerEvent& coalesced_event :
         touch_point_attribute->coalesced_events_) {
      all_coalesced_events.push_back(coalesced_event);
    }
  }
  event->SetType(touch_event_type);
  last_coalesced_touch_event_.SetType(touch_event_type);

  // Create all coalesced touch events based on pointerevents
  struct {
    bool operator()(const WebPointerEvent& a, const WebPointerEvent& b) {
      return a.TimeStamp() < b.TimeStamp();
    }
  } timestamp_based_event_comparison;
  std::sort(all_coalesced_events.begin(), all_coalesced_events.end(),
            timestamp_based_event_comparison);
  WebCoalescedInputEvent result(std::move(event), {}, {}, ui::LatencyInfo());
  for (const auto& web_pointer_event : all_coalesced_events) {
    if (web_pointer_event.GetType() == WebInputEvent::Type::kPointerDown) {
      // TODO(crbug.com/732842): Technically we should never receive the
      // pointerdown twice for the same touch point. But event sender API allows
      // that. So we should handle it gracefully.
      WebTouchPoint web_touch_point(web_pointer_event);
      bool found_existing_id = false;
      for (unsigned i = 0; i < last_coalesced_touch_event_.touches_length;
           ++i) {
        if (last_coalesced_touch_event_.touches[i].id == web_pointer_event.id) {
          last_coalesced_touch_event_.touches[i] =
              CreateWebTouchPointFromWebPointerEvent(web_pointer_event, false);
          last_coalesced_touch_event_.SetTimeStamp(
              web_pointer_event.TimeStamp());
          found_existing_id = true;
          break;
        }
      }
      // If the pointerdown point didn't exist add a new point to the array.
      if (!found_existing_id) {
        last_coalesced_touch_event_
            .touches[last_coalesced_touch_event_.touches_length++] =
            CreateWebTouchPointFromWebPointerEvent(web_pointer_event, false);
      }
      struct {
        bool operator()(const WebTouchPoint& a, const WebTouchPoint& b) {
          return a.id < b.id;
        }
      } id_based_event_comparison;
      base::ranges::sort(base::span(last_coalesced_touch_event_.touches)
                             .first(last_coalesced_touch_event_.touches_length),
                         id_based_event_comparison);
      result.AddCoalescedEvent(last_coalesced_touch_event_);
    } else {
      for (unsigned i = 0; i < last_coalesced_touch_event_.touches_length;
           ++i) {
        if (last_coalesced_touch_event_.touches[i].id == web_pointer_event.id) {
          last_coalesced_touch_event_.touches[i] =
              CreateWebTouchPointFromWebPointerEvent(web_pointer_event, false);
          last_coalesced_touch_event_.SetTimeStamp(
              web_pointer_event.TimeStamp());
          result.AddCoalescedEvent(last_coalesced_touch_event_);

          // Remove up and canceled points.
          unsigned result_size = 0;
          for (unsigned j = 0; j < last_coalesced_touch_event_.touches_length;
               j++) {
            if (last_coalesced_touch_event_.touches[j].state !=
                    WebTouchPoint::State::kStateCancelled &&
                last_coalesced_touch_event_.touches[j].state !=
                    WebTouchPoint::State::kStateReleased) {
              last_coalesced_touch_event_.touches[result_size++] =
                  last_coalesced_touch_event_.touches[j];
            }
          }
          last_coalesced_touch_event_.touches_length = result_size;
          break;
        }
      }
    }
  }

  return result;
}

WebInputEventResult
TouchEventManager::DispatchTouchEventFromAccumulatdTouchPoints() {
  // Build up the lists to use for the |touches|, |targetTouches| and
  // |changedTouches| attributes in the JS event. See
  // http://www.w3.org/TR/touch-events/#touchevent-interface for how these
  // lists fit together.

  bool new_touch_point_since_last_dispatch = false;
  bool any_touch_canceled_or_ended = false;
  bool all_touch_points_pressed = true;

  for (const auto& attr : touch_attribute_map_.Values()) {
    if (!attr->stale_)
      new_touch_point_since_last_dispatch = true;
    if (attr->event_.GetType() == WebInputEvent::Type::kPointerUp ||
        attr->event_.GetType() == WebInputEvent::Type::kPointerCancel)
      any_touch_canceled_or_ended = true;
    if (attr->event_.GetType() != WebInputEvent::Type::kPointerDown)
      all_touch_points_pressed = false;
  }

  if (!new_touch_point_since_last_dispatch)
    return WebInputEventResult::kNotHandled;

  if (any_touch_canceled_or_ended || touch_attribute_map_.size() > 1)
    suppressing_touchmoves_within_slop_ = false;

  if (suppressing_touchmoves_within_slop_) {
    // There is exactly one touch point here otherwise
    // |suppressing_touchmoves_within_slop_| would have been false.
    DCHECK_EQ(1U, touch_attribute_map_.size());
    const auto& touch_point_attribute = touch_attribute_map_.begin()->value;
    if (touch_point_attribute->event_.GetType() ==
        WebInputEvent::Type::kPointerMove) {
      if (!touch_point_attribute->event_.moved_beyond_slop_region)
        return WebInputEventResult::kHandledSuppressed;
      suppressing_touchmoves_within_slop_ = false;
    }
  }

  // Holds the complete set of touches on the screen.
  TouchList* touches = TouchList::Create();

  // A different view on the 'touches' list above, filtered and grouped by
  // event target. Used for the |targetTouches| list in the JS event.
  using TargetTouchesHeapMap =
      HeapHashMap<Member<EventTarget>, Member<TouchList>>;
  TargetTouchesHeapMap touches_by_target;

  // Array of touches per state, used to assemble the |changedTouches| list.
  ChangedTouches
      changed_touches[static_cast<int>(WebInputEvent::Type::kPointerTypeLast) -
                      static_cast<int>(WebInputEvent::Type::kPointerTypeFirst) +
                      1];

  Vector<int> available_ids;
  for (const auto& id : touch_attribute_map_.Keys())
    available_ids.push_back(id);
  std::sort(available_ids.begin(), available_ids.end());
  for (const int& touch_point_id : available_ids) {
    auto* const touch_point_attribute = touch_attribute_map_.at(touch_point_id);
    WebInputEvent::Type event_type = touch_point_attribute->event_.GetType();
    bool known_target;

    Touch* touch = CreateDomTouch(touch_point_attribute, &known_target);
    EventTarget* touch_target = touch->target();

    // Ensure this target's touch list exists, even if it ends up empty, so
    // it can always be passed to TouchEvent::Create below.
    TargetTouchesHeapMap::iterator target_touches_iterator =
        touches_by_target.find(touch_target);
    if (target_touches_iterator == touches_by_target.end()) {
      touches_by_target.Set(touch_target, TouchList::Create());
      target_touches_iterator = touches_by_target.find(touch_target);
    }

    // |touches| and |targetTouches| should only contain information about
    // touches still on the screen, so if this point is released or
    // cancelled it will only appear in the |changedTouches| list.
    if (event_type != WebInputEvent::Type::kPointerUp &&
        event_type != WebInputEvent::Type::kPointerCancel) {
      touches->Append(touch);
      target_touches_iterator->value->Append(touch);
    }

    // Now build up the correct list for |changedTouches|.
    // Note that  any touches that are in the TouchStationary state (e.g. if
    // the user had several points touched but did not move them all) should
    // never be in the |changedTouches| list so we do not handle them
    // explicitly here. See https://bugs.webkit.org/show_bug.cgi?id=37609
    // for further discussion about the TouchStationary state.
    if (!touch_point_attribute->stale_ && known_target) {
      size_t event_type_idx =
          static_cast<int>(event_type) -
          static_cast<int>(WebInputEvent::Type::kPointerTypeFirst);
      if (!changed_touches[event_type_idx].touches_)
        changed_touches[event_type_idx].touches_ = TouchList::Create();
      changed_touches[event_type_idx].touches_->Append(touch);
      changed_touches[event_type_idx].targets_.insert(touch_target);
    }
  }

  WebInputEventResult event_result = WebInputEventResult::kNotHandled;

  // First we construct the webcoalescedinputevent containing all the coalesced
  // touch event.
  WebCoalescedInputEvent coalesced_event = GenerateWebCoalescedInputEvent();

  // Now iterate through the |changedTouches| list and |m_targets| within it,
  // sending TouchEvents to the targets as required.
  for (unsigned action =
           static_cast<int>(WebInputEvent::Type::kPointerTypeFirst);
       action <= static_cast<int>(WebInputEvent::Type::kPointerTypeLast);
       ++action) {
    size_t action_idx =
        action - static_cast<int>(WebInputEvent::Type::kPointerTypeFirst);
    if (!changed_touches[action_idx].touches_)
      continue;

    const AtomicString& event_name(TouchEventNameForPointerEventType(
        static_cast<WebInputEvent::Type>(action)));

    for (const auto& event_target : changed_touches[action_idx].targets_) {
      EventTarget* touch_event_target = event_target;
      TouchEvent* touch_event = TouchEvent::Create(
          coalesced_event, touches, touches_by_target.at(touch_event_target),
          changed_touches[action_idx].touches_, event_name,
          touch_event_target->ToNode()->GetDocument().domWindow(),
          current_touch_action_);

      DispatchEventResult dom_dispatch_result =
          touch_event_target->DispatchEvent(*touch_event);

      event_result = event_handling_util::MergeEventResult(
          event_result,
          event_handling_util::ToWebInputEventResult(dom_dispatch_result));
    }
  }

  if (should_enforce_vertical_scroll_)
    event_result = EnsureVerticalScrollIsPossible(event_result);

  // Suppress following touchmoves within the slop region if the touchstart is
  // not consumed.
  if (all_touch_points_pressed &&
      event_result == WebInputEventResult::kNotHandled) {
    suppressing_touchmoves_within_slop_ = true;
  }

  return event_result;
}

Node* TouchEventManager::GetTouchPointerNode(
    const WebPointerEvent& event,
    const event_handling_util::PointerEventTarget& pointer_event_target) {
  DCHECK(event.GetType() == WebInputEvent::Type::kPointerDown);

  Node* touch_pointer_node = pointer_event_target.target_element;

  if (touch_sequence_document_ &&
      (!touch_pointer_node ||
       &touch_pointer_node->GetDocument() != touch_sequence_document_)) {
    if (!touch_sequence_document_->GetFrame())
      return nullptr;

    HitTestLocation location(PhysicalOffset::FromPointFRound(
        touch_sequence_document_->GetFrame()->View()->ConvertFromRootFrame(
            event.PositionInWidget())));
    HitTestRequest::HitTestRequestType hit_type = HitTestRequest::kTouchEvent |
                                                  HitTestRequest::kReadOnly |
                                                  HitTestRequest::kActive;
    HitTestResult result = event_handling_util::HitTestResultInFrame(
        touch_sequence_document_->GetFrame(), location, hit_type);
    Node* node = result.InnerNode();
    if (!node)
      return nullptr;
    // Touch events should not go to text nodes.
    if (node->IsTextNode())
      node = FlatTreeTraversal::Parent(*node);
    touch_pointer_node = node;
  }

  return touch_pointer_node;
}

void TouchEventManager::UpdateTouchAttributeMapsForPointerDown(
    const WebPointerEvent& event,
    Node* touch_node,
    TouchAction effective_touch_action) {
  DCHECK(event.GetType() == WebInputEvent::Type::kPointerDown);
  DCHECK(touch_node);

  // Ideally we'd DCHECK(!touch_attribute_map_.Contains(event.id))
  // since we shouldn't get a touchstart for a touch that's already
  // down. However EventSender allows this to be violated and there's
  // some tests that take advantage of it. There may also be edge
  // cases in the browser where this happens.
  // See http://crbug.com/345372.
  touch_attribute_map_.Set(event.id,
                           MakeGarbageCollected<TouchPointAttributes>(event));

  if (!touch_sequence_document_) {
    // Keep track of which document should receive all touch events
    // in the active sequence. This must be a single document to
    // ensure we don't leak Nodes between documents.
    touch_sequence_document_ = &(touch_node->GetDocument());
    DCHECK(touch_sequence_document_->GetFrame()->View());
  }

  TouchPointAttributes* attributes = touch_attribute_map_.at(event.id);
  attributes->target_ = touch_node;

  should_enforce_vertical_scroll_ =
      touch_sequence_document_->IsVerticalScrollEnforced();
  if (should_enforce_vertical_scroll_ &&
      HasEventHandlerInAncestorPath(
          touch_node, EventHandlerRegistry::kTouchStartOrMoveEventBlocking)) {
    delayed_effective_touch_action_ =
        delayed_effective_touch_action_.value_or(TouchAction::kAuto) &
        effective_touch_action;
  }
  if (!delayed_effective_touch_action_) {
    frame_->GetPage()->GetChromeClient().SetTouchAction(frame_,
                                                        effective_touch_action);
  }
  // Combine the current touch action sequence with the touch action
  // for the current finger press.
  current_touch_action_ &= effective_touch_action;
}

void TouchEventManager::HandleTouchPoint(
    const WebPointerEvent& event,
    const Vector<WebPointerEvent>& coalesced_events,
    const event_handling_util::PointerEventTarget& pointer_event_target) {
  DCHECK_GE(event.GetType(), WebInputEvent::Type::kPointerTypeFirst);
  DCHECK_LE(event.GetType(), WebInputEvent::Type::kPointerTypeLast);
  DCHECK_NE(event.GetType(), WebInputEvent::Type::kPointerCausedUaAction);

  if (touch_attribute_map_.empty()) {
    // Ideally we'd DCHECK(!m_touchSequenceDocument) here since we should
    // have cleared the active document when we saw the last release. But we
    // have some tests that violate this, ClusterFuzz could trigger it, and
    // there may be cases where the browser doesn't reliably release all
    // touches. http://crbug.com/345372 tracks this.
    AllTouchesReleasedCleanup();
  }

  DCHECK(frame_->View());
  if (touch_sequence_document_ &&
      (!touch_sequence_document_->GetFrame() ||
       !touch_sequence_document_->GetFrame()->View())) {
    // If the active touch document has no frame or view, it's probably being
    // destroyed so we can't dispatch events.
    // Update the points so they get removed in flush when they are released.
    if (touch_attribute_map_.Contains(event.id)) {
      TouchPointAttributes* attributes = touch_attribute_map_.at(event.id);
      attributes->event_ = event;
    }
    return;
  }

  // We might not receive the down action for a touch point. In that case we
  // would have never added them to |touch_attribute_map_| or hit-tested
  // them. For those just keep them in the map with a null target. Later they
  // will be targeted at the |touch_sequence_document_|.
  if (!touch_attribute_map_.Contains(event.id)) {
    touch_attribute_map_.insert(
        event.id, MakeGarbageCollected<TouchPointAttributes>(event));
  }

  TouchPointAttributes* attributes = touch_attribute_map_.at(event.id);
  attributes->event_ = event;
  attributes->coalesced_events_ = coalesced_events;
  attributes->stale_ = false;
}

WebInputEventResult TouchEventManager::FlushEvents() {
  WebInputEventResult result = WebInputEventResult::kNotHandled;

  // If there's no document receiving touch events, or no handlers on the
  // document set to receive the events, then we can skip all the rest of
  // sending the event.
  if (touch_sequence_document_ && touch_sequence_document_->GetPage() &&
      HasTouchHandlers(
          touch_sequence_document_->GetFrame()->GetEventHandlerRegistry()) &&
      touch_sequence_document_->GetFrame()->View()) {
    result = DispatchTouchEventFromAccumulatdTouchPoints();
  }

  // Cleanup the |touch_attribute_map_| map from released and canceled
  // touch points.
  Vector<int> released_canceled_points;
  for (auto& attributes : touch_attribute_map_.Values()) {
    if (attributes->event_.GetType() == WebInputEvent::Type::kPointerUp ||
        attributes->event_.GetType() == WebInputEvent::Type::kPointerCancel) {
      released_canceled_points.push_back(attributes->event_.id);
    } else {
      attributes->stale_ = true;
      attributes->event_.movement_x = 0;
      attributes->event_.movement_y = 0;
      attributes->coalesced_events_.clear();
    }
  }
  touch_attribute_map_.RemoveAll(released_canceled_points);

  if (touch_attribute_map_.empty()) {
    AllTouchesReleasedCleanup();
  }

  return result;
}

void TouchEventManager::AllTouchesReleasedCleanup() {
  touch_sequence_document_.Clear();
  current_touch_action_ = TouchAction::kAuto;
  last_coalesced_touch_event_ = WebTouchEvent();
  // Ideally, we should have DCHECK(!delayed_effective_touch_action_) but we do
  // we do actually get here from HandleTouchPoint(). Supposedly, if there has
  // been a |touch_sequence_document_| and nothing in the |touch_attribute_map_|
  // we still get here and if |touch_sequence_document| was of the type which
  // cannot block scroll, then the flag is certainly set
  // (https://crbug.com/345372).
  delayed_effective_touch_action_ = std::nullopt;
  should_enforce_vertical_scroll_ = false;
}

bool TouchEventManager::IsAnyTouchActive() const {
  return !touch_attribute_map_.empty();
}

Element* TouchEventManager::CurrentTouchDownElement() {
  if (touch_attribute_map_.empty() || touch_attribute_map_.size() > 1)
    return nullptr;
  Node* touch_node = touch_attribute_map_.begin()->value->target_;
  return touch_node ? DynamicTo<Element>(*touch_node) : nullptr;
}

WebInputEventResult TouchEventManager::EnsureVerticalScrollIsPossible(
    WebInputEventResult event_result) {
  bool prevent_defaulted =
      event_result == WebInputEventResult::kHandledApplication;
  if (prevent_defaulted && delayed_effective_touch_action_) {
    // Make sure that only vertical scrolling is permitted.
    *delayed_effective_touch_action_ &= TouchAction::kPanY;
  }

  if (delayed_effective_touch_action_) {
    // If 'touchstart' is preventDefault()-ed then we can proceed with reporting
    // the effective 'touch-action'.
    // TODO(ekaramad): This does not block horizontal scroll after enforcing
    // vertical scrolling. We should ideally send the 'touch-action' to browser
    // after the first 'touchmove' event has been dispatched.
    // (https://crbug.com/844493).
    frame_->GetPage()->GetChromeClient().SetTouchAction(
        frame_, delayed_effective_touch_action_.value());
    delayed_effective_touch_action_ = std::nullopt;
  }

  // If the event was canceled the result is ignored to make sure vertical
  // scrolling is possible.
  return prevent_defaulted ? WebInputEventResult::kNotHandled : event_result;
}

}  // namespace blink
```