Response:
The user wants to understand the functionality of the `pointer_event_manager.cc` file in the Chromium Blink rendering engine. I need to:

1. **Summarize the file's core purpose.** This likely involves managing and dispatching pointer events.
2. **Explain its relationship to web technologies (JavaScript, HTML, CSS).**  Pointer events are fundamental for user interaction with web content.
3. **Provide illustrative examples.** These will clarify how the `PointerEventManager` interacts with web pages.
4. **Explain the logic involved.** This might include how the manager determines the target of an event or handles different pointer types. I'll need to provide hypothetical inputs and outputs.
5. **Identify common user/programming errors.** These could involve issues like incorrect event handling or assumptions about event order.
6. **Describe the user actions leading to this code.**  This will help understand the context of the `PointerEventManager`.
7. **Acknowledge that this is part 1 of 2 and focus on summarizing the functionalities.**

Based on the included code:

- The file manages pointer events (mouse, touch, pen).
- It handles event dispatching to the correct targets.
- It deals with pointer capture.
- It manages boundary events (pointerover, pointerout, etc.).
- It interacts with touch event handling.
- It considers factors like pointer lock and event filtering.
好的，根据你提供的 `blink/renderer/core/input/pointer_event_manager.cc` 代码片段，我可以归纳一下它的功能：

**核心功能：**

`PointerEventManager` 的主要职责是**管理和调度各种类型的指针事件**，例如鼠标、触摸和触控笔事件。它作为 Blink 渲染引擎中处理用户输入的核心组件之一，负责将底层的 WebInputEvent 转化为更高层次的 PointerEvent，并将其分发到正确的 DOM 元素上。

**更具体的功能点包括：**

1. **事件接收和初步处理：** 接收来自浏览器的底层 `WebInputEvent`，并将其转换为 Blink 内部使用的 `PointerEvent` 对象。
2. **目标确定：** 负责确定指针事件的目标 DOM 元素。这涉及到 hit-testing（命中测试），即判断指针位置下的哪个元素应该接收到事件。
3. **事件分发：** 将创建好的 `PointerEvent` 分发到目标元素，触发相应的事件监听器。
4. **指针捕获管理：**  处理指针捕获 (pointer capture) 机制，允许特定的元素独占后续的指针事件，即使指针移动到其他元素上方。
5. **边界事件处理：**  管理 `pointerover`、`pointerout`、`pointerenter` 和 `pointerleave` 等边界事件的触发，当指针在元素之间移动时发送这些事件。
6. **触摸事件集成：**  与 `TouchEventManager` 协同工作，处理触摸事件并将其转换为相应的指针事件。
7. **鼠标事件兼容：** 在某些情况下，为了兼容性，可能需要抑制或生成相应的鼠标事件。
8. **用户激活跟踪：**  参与用户激活的跟踪，例如，在 `pointerup` 事件时通知框架发生了用户交互。
9. **事件过滤和调整：**  根据特定条件（例如实验性功能）过滤或调整指针事件的行为，例如跳过触摸事件的过滤或者调整触摸和触控笔事件的坐标。
10. **处理用户代理行为引起的指针中断：**  响应用户代理的特定行为，例如取消所有非悬停指针的事件。
11. **处理滚动条和元素大小调整拖动：**  检测并处理用户与滚动条和可调整大小元素的交互。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **JavaScript:**
    * **关系：** JavaScript 代码可以通过添加事件监听器来响应 `PointerEventManager` 分发的指针事件。例如，使用 `element.addEventListener('pointerdown', function(event) { ... });` 来监听元素的 pointerdown 事件。
    * **举例：** 一个网页上有一个按钮元素 `<button id="myButton">Click Me</button>`。当用户点击这个按钮时，`PointerEventManager` 会接收到 `pointerdown` 和 `pointerup` 事件，并将其分发到该按钮元素。如果 JavaScript 代码为该按钮添加了 `pointerdown` 事件监听器，那么监听器中的代码就会被执行。
    * **假设输入与输出：**
        * **假设输入：** 用户使用鼠标点击了按钮 "myButton"。
        * **输出：** `PointerEventManager` 将创建一个 `PointerEvent` 对象，其 `target` 属性指向 "myButton" 元素，事件类型为 "pointerdown"，并将其分发到该元素，触发 JavaScript 监听器。
* **HTML:**
    * **关系：** HTML 结构定义了网页上的元素，这些元素是指针事件的目标。不同的 HTML 元素可能会有默认的指针事件处理行为。
    * **举例：** 一个可拖拽的 `<div>` 元素 `<div draggable="true">Drag Me</div>`。当用户在该元素上按下鼠标并移动时，`PointerEventManager` 会生成一系列的 `pointermove` 事件，这些事件可以被 JavaScript 监听并用于实现拖拽功能。`draggable` 属性会影响浏览器对指针事件的默认处理。
* **CSS:**
    * **关系：** CSS 可以影响元素的外观和交互行为，从而间接地影响指针事件的处理。例如，`pointer-events` CSS 属性可以控制元素是否可以成为指针事件的目标。
    * **举例：** 一个半透明的覆盖层元素 `<div style="opacity: 0.5; pointer-events: none;">Overlay</div>`。即使鼠标指针悬停在该覆盖层上方，由于 `pointer-events: none;` 的设置，该元素不会接收到指针事件，事件会穿透到下方的元素。

**逻辑推理举例：**

* **场景：** 用户在网页上的一个链接元素上按下鼠标。
* **假设输入：** `WebInputEvent` 类型为 `kPointerDown`，位置在链接元素的边界内。
* **逻辑推理：**
    1. `PointerEventManager` 接收到 `WebInputEvent`。
    2. 进行命中测试，确定链接元素是事件的目标。
    3. 创建一个 `PointerEvent` 对象，其 `target` 属性指向链接元素。
    4. 如果链接元素设置了指针捕获，则后续的指针事件会直接发送到该元素，否则继续进行命中测试。
    5. 分发 `pointerdown` 事件到链接元素。
* **输出：** 链接元素的 `pointerdown` 事件监听器被触发（如果存在），浏览器可能会开始跟踪鼠标移动以判断是否是拖拽操作。

**用户或编程常见的使用错误举例：**

* **错误：** 在 JavaScript 中错误地假设所有指针事件都是鼠标事件，直接使用 `event.clientX` 和 `event.clientY` 而没有考虑触摸或触控笔事件。
* **后果：** 在触摸设备上，这些属性可能不准确或未定义，导致程序行为不符合预期。应该使用 `event.pageX`, `event.pageY` 或者检查 `event.pointerType` 来更通用地处理不同类型的指针事件。
* **错误：**  忘记在需要独占指针输入的场景中使用 `element.setPointerCapture()`，导致在拖拽操作过程中，如果指针移出元素，拖拽就意外停止。

**用户操作到达这里的步骤 (调试线索)：**

1. **用户进行交互：** 用户使用鼠标、触摸屏或触控笔与网页进行交互，例如点击、触摸、滑动等。
2. **浏览器捕获底层事件：** 操作系统或硬件驱动程序会生成底层的输入事件，浏览器会捕获这些事件。
3. **传递到渲染进程：** 浏览器将这些底层输入事件（例如鼠标移动、触摸开始）传递给负责渲染网页的 Blink 渲染进程。
4. **转换为 `WebInputEvent`：** 渲染进程的输入处理模块将这些底层的事件转换为 Blink 内部的 `WebInputEvent` 对象。
5. **`PointerEventManager` 接收事件：**  `PointerEventManager` 作为输入事件处理管道的一部分，接收到这些 `WebInputEvent`。
6. **处理和分发：** `PointerEventManager` 根据事件类型和目标元素，创建 `PointerEvent` 对象并将其分发到相应的 DOM 元素，触发 JavaScript 事件监听器或浏览器的默认行为。

总而言之，`PointerEventManager` 是 Blink 引擎中处理用户与网页交互的关键组件，它负责将各种类型的指针输入转化为统一的事件模型，并确保这些事件能够正确地传递到网页的相应部分。

Prompt: 
```
这是目录为blink/renderer/core/input/pointer_event_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/input/pointer_event_manager.h"

#include "base/auto_reset.h"
#include "base/metrics/field_trial_params.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/frame/user_activation_notification_type.mojom-blink.h"
#include "third_party/blink/public/mojom/input/input_handler.mojom-blink.h"
#include "third_party/blink/renderer/core/dom/events/event_path.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/frame/event_handler_registry.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/html_dialog_element.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/input/event_handling_util.h"
#include "third_party/blink/renderer/core/input/mouse_event_manager.h"
#include "third_party/blink/renderer/core/input/touch_action_util.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/loader/anchor_element_interaction_tracker.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/pointer_lock_controller.h"
#include "third_party/blink/renderer/core/page/touch_adjustment.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/scroll/scrollbar.h"
#include "third_party/blink/renderer/core/timing/event_timing.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "ui/display/screen_info.h"

namespace blink {

namespace {

// Field trial name for skipping touch filtering
const char kSkipTouchEventFilterTrial[] = "SkipTouchEventFilter";
const char kSkipTouchEventFilterTrialProcessParamName[] =
    "skip_filtering_process";
const char kSkipTouchEventFilterTrialTypeParamName[] = "type";

// Width and height of area of rectangle to hit test for potentially important
// input fields to write into. This improves the chances of writing into the
// intended input if the user starts writing close to it.
const size_t kStylusWritableAdjustmentSizeDip = 30;

size_t ToPointerTypeIndex(WebPointerProperties::PointerType t) {
  return static_cast<size_t>(t);
}

bool HasPointerEventListener(const EventHandlerRegistry& registry) {
  return registry.HasEventHandlers(EventHandlerRegistry::kPointerEvent) ||
         registry.HasEventHandlers(
             EventHandlerRegistry::kPointerRawUpdateEvent);
}

const AtomicString& MouseEventNameForPointerEventInputType(
    const WebInputEvent::Type& event_type) {
  switch (event_type) {
    case WebInputEvent::Type::kPointerDown:
      return event_type_names::kMousedown;
    case WebInputEvent::Type::kPointerUp:
      return event_type_names::kMouseup;
    case WebInputEvent::Type::kPointerMove:
      return event_type_names::kMousemove;
    default:
      NOTREACHED();
  }
}

}  // namespace

PointerEventManager::PointerEventManager(LocalFrame& frame,
                                         MouseEventManager& mouse_event_manager)
    : frame_(frame),
      touch_event_manager_(MakeGarbageCollected<TouchEventManager>(frame)),
      mouse_event_manager_(mouse_event_manager) {
  Clear();
  if (RuntimeEnabledFeatures::SkipTouchEventFilterEnabled() &&
      base::GetFieldTrialParamValue(
          kSkipTouchEventFilterTrial,
          kSkipTouchEventFilterTrialProcessParamName) ==
          "browser_and_renderer") {
    skip_touch_filter_discrete_ = true;
    if (base::GetFieldTrialParamValue(
            kSkipTouchEventFilterTrial,
            kSkipTouchEventFilterTrialTypeParamName) == "all") {
      skip_touch_filter_all_ = true;
    }
  }
}

void PointerEventManager::Clear() {
  for (auto& entry : prevent_mouse_event_for_pointer_type_) {
    entry = false;
  }
  touch_event_manager_->Clear();
  mouse_event_manager_->Clear();
  non_hovering_pointers_canceled_ = false;
  pointer_event_factory_.Clear();
  touch_ids_for_canceled_pointerdowns_.clear();
  element_under_pointer_.clear();
  original_element_under_pointer_removed_.clear();
  pointer_capture_target_.clear();
  pending_pointer_capture_target_.clear();
  dispatching_pointer_id_ = 0;
  resize_scrollable_area_.Clear();
  offset_from_resize_corner_ = {};
  skip_touch_filter_discrete_ = false;
  skip_touch_filter_all_ = false;
  discarded_event_.target = kInvalidDOMNodeId;
  discarded_event_.time = base::TimeTicks();
  SetDocument(frame_->GetDocument());
}

void PointerEventManager::Trace(Visitor* visitor) const {
  visitor->Trace(frame_);
  visitor->Trace(element_under_pointer_);
  visitor->Trace(pointer_capture_target_);
  visitor->Trace(pending_pointer_capture_target_);
  visitor->Trace(touch_event_manager_);
  visitor->Trace(mouse_event_manager_);
  visitor->Trace(captured_scrollbar_);
  visitor->Trace(resize_scrollable_area_);
  SynchronousMutationObserver::Trace(visitor);
}

PointerEventManager::PointerEventBoundaryEventDispatcher::
    PointerEventBoundaryEventDispatcher(
        PointerEventManager* pointer_event_manager,
        PointerEvent* pointer_event)
    : BoundaryEventDispatcher(event_type_names::kPointerover,
                              event_type_names::kPointerout,
                              event_type_names::kPointerenter,
                              event_type_names::kPointerleave),
      pointer_event_manager_(pointer_event_manager),
      pointer_event_(pointer_event) {}

void PointerEventManager::PointerEventBoundaryEventDispatcher::Dispatch(
    EventTarget* target,
    EventTarget* related_target,
    const AtomicString& type,
    bool check_for_listener) {
  pointer_event_manager_->DispatchPointerEvent(
      target,
      pointer_event_manager_->pointer_event_factory_.CreatePointerBoundaryEvent(
          pointer_event_, type, related_target),
      check_for_listener);
}

WebInputEventResult PointerEventManager::DispatchPointerEvent(
    EventTarget* target,
    PointerEvent* pointer_event,
    bool check_for_listener) {
  if (!target)
    return WebInputEventResult::kNotHandled;

  const PointerId pointer_id = pointer_event->pointerId();
  const AtomicString& event_type = pointer_event->type();
  bool should_filter = ShouldFilterEvent(pointer_event);
  // We are about to dispatch this event. It has to be trusted at this point.
  pointer_event->SetTrusted(true);
  std::optional<EventTiming> event_timing;
  if (frame_ && frame_->DomWindow()) {
    event_timing =
        EventTiming::TryCreate(frame_->DomWindow(), *pointer_event, target);
  }

  if (event_type == event_type_names::kPointerdown ||
      event_type == event_type_names::kPointerover ||
      event_type == event_type_names::kPointerout) {
    AnchorElementInteractionTracker* tracker =
        frame_->GetDocument()->GetAnchorElementInteractionTracker();
    if (tracker) {
      tracker->OnPointerEvent(*target, *pointer_event);
    }
  }

  if (Node* target_node = target->ToNode()) {
    if (event_type == event_type_names::kPointerdown ||
        event_type == event_type_names::kPointerup) {
      // Per spec, run the popover light dismiss actions first, which will take
      // care of light dismissing popovers, including nested popovers. Then run
      // dialog light dismiss.
      HTMLElement::HandlePopoverLightDismiss(*pointer_event, *target_node);
      HTMLDialogElement::HandleDialogLightDismiss(*pointer_event, *target_node);
    }
  }

  if (should_filter &&
      !HasPointerEventListener(frame_->GetEventHandlerRegistry()))
    return WebInputEventResult::kNotHandled;

  if (event_type == event_type_names::kPointerdown) {
    auto* html_canvas_element = DynamicTo<HTMLCanvasElement>(target->ToNode());
    if (html_canvas_element &&
        html_canvas_element->NeedsUnbufferedInputEvents()) {
      frame_->GetChromeClient().RequestUnbufferedInputEvents(frame_);
    }
  }

  bool listeners_exist =
      !check_for_listener || target->HasEventListeners(event_type);
  if (listeners_exist) {
    UseCounter::Count(frame_->GetDocument(), WebFeature::kPointerEventDispatch);
    if (event_type == event_type_names::kPointerdown) {
      UseCounter::Count(frame_->GetDocument(),
                        WebFeature::kPointerEventDispatchPointerDown);
    }
  }

  if (!should_filter || listeners_exist) {
    DCHECK(!dispatching_pointer_id_);
    base::AutoReset<PointerId> dispatch_holder(&dispatching_pointer_id_,
                                               pointer_id);
    DispatchEventResult dispatch_result = target->DispatchEvent(*pointer_event);
    return event_handling_util::ToWebInputEventResult(dispatch_result);
  }
  return WebInputEventResult::kNotHandled;
}

Element* PointerEventManager::GetEffectiveTargetForPointerEvent(
    Element* target,
    PointerId pointer_id) {
  if (pointer_capture_target_.Contains(pointer_id)) {
    return pointer_capture_target_.at(pointer_id);
  }
  return target;
}

void PointerEventManager::SendMouseAndPointerBoundaryEvents(
    Element* entered_element,
    const WebMouseEvent& mouse_event) {
  // Mouse event type does not matter as this pointerevent will only be used
  // to create boundary pointer events and its type will be overridden in
  // `SendBoundaryEvents` function.
  const WebPointerEvent web_pointer_event(WebInputEvent::Type::kPointerMove,
                                          mouse_event);
  PointerEvent* dummy_pointer_event = pointer_event_factory_.Create(
      web_pointer_event, Vector<WebPointerEvent>(), Vector<WebPointerEvent>(),
      frame_->GetDocument()->domWindow());
  DCHECK(dummy_pointer_event);

  // TODO(crbug/545647): This state should reset with pointercancel too.
  // This function also gets called for compat mouse events of touch at this
  // stage. So if the event is not frame boundary transition it is only a
  // compatibility mouse event and we do not need to change pointer event
  // behavior regarding preventMouseEvent state in that case.
  if (dummy_pointer_event->buttons() == 0 && dummy_pointer_event->isPrimary()) {
    prevent_mouse_event_for_pointer_type_[ToPointerTypeIndex(
        mouse_event.pointer_type)] = false;
  }

  ProcessCaptureAndPositionOfPointerEvent(dummy_pointer_event, entered_element,
                                          &mouse_event);
}

void PointerEventManager::SendBoundaryEvents(
    EventTarget* exited_target,
    bool original_exited_target_removed,
    EventTarget* entered_target,
    PointerEvent* pointer_event) {
  PointerEventBoundaryEventDispatcher boundary_event_dispatcher(this,
                                                                pointer_event);
  boundary_event_dispatcher.SendBoundaryEvents(
      exited_target, original_exited_target_removed, entered_target);
}

void PointerEventManager::SetElementUnderPointer(PointerEvent* pointer_event,
                                                 Element* target) {
  const PointerId pointer_id = pointer_event->pointerId();

  CHECK(
      !original_element_under_pointer_removed_.Contains(pointer_id) ||
      RuntimeEnabledFeatures::BoundaryEventDispatchTracksNodeRemovalEnabled());

  Element* exited_target = element_under_pointer_.Contains(pointer_id)
                               ? element_under_pointer_.at(pointer_id)
                               : nullptr;
  bool original_exited_target_removed =
      original_element_under_pointer_removed_.Contains(pointer_id);

  if (exited_target) {
    if (!target) {
      element_under_pointer_.erase(pointer_id);
    } else if (target != exited_target) {
      element_under_pointer_.Set(pointer_id, target);
    }
  } else if (target) {
    element_under_pointer_.insert(pointer_id, target);
  }
  // Clear the "removed" state for the updated `element_under_pointer_`.
  original_element_under_pointer_removed_.erase(pointer_id);

  SendBoundaryEvents(exited_target, original_exited_target_removed, target,
                     pointer_event);
}

void PointerEventManager::NodeWillBeRemoved(Node& node_to_be_removed) {
  if (!RuntimeEnabledFeatures::
          BoundaryEventDispatchTracksNodeRemovalEnabled()) {
    return;
  }
  for (const auto& [pointer_id, element] : element_under_pointer_) {
    if (element &&
        node_to_be_removed.IsShadowIncludingInclusiveAncestorOf(*element)) {
      element_under_pointer_.Set(pointer_id,
                                 node_to_be_removed.parentElement());
      original_element_under_pointer_removed_.insert(pointer_id);
      // TODO(https://crbug.com/1496482): Do we need something similar to the
      // logic in EventPath::CalculatePath()?
    }
  }
}

void PointerEventManager::HandlePointerInterruption(
    const WebPointerEvent& web_pointer_event) {
  DCHECK(web_pointer_event.GetType() ==
         WebInputEvent::Type::kPointerCausedUaAction);

  HeapVector<Member<PointerEvent>> canceled_pointer_events;
  if (web_pointer_event.pointer_type ==
      WebPointerProperties::PointerType::kMouse) {
    canceled_pointer_events.push_back(
        pointer_event_factory_.CreatePointerCancelEvent(
            PointerEventFactory::kMouseId, web_pointer_event.TimeStamp(),
            web_pointer_event.device_id));
  } else {
    // TODO(nzolghadr): Maybe canceling all the non-hovering pointers is not
    // the best strategy here. See the github issue for more details:
    // https://github.com/w3c/pointerevents/issues/226

    // Cancel all non-hovering pointers if the pointer is not mouse.
    if (!non_hovering_pointers_canceled_) {
      Vector<PointerId> non_hovering_pointer_ids =
          pointer_event_factory_.GetPointerIdsOfNonHoveringPointers();

      for (PointerId pointer_id : non_hovering_pointer_ids) {
        canceled_pointer_events.push_back(
            pointer_event_factory_.CreatePointerCancelEvent(
                pointer_id, web_pointer_event.TimeStamp(),
                web_pointer_event.device_id));
      }

      non_hovering_pointers_canceled_ = true;
    }
  }

  for (auto pointer_event : canceled_pointer_events) {
    // If we are sending a pointercancel we have sent the pointerevent to some
    // target before.
    Element* target = nullptr;
    if (element_under_pointer_.Contains(pointer_event->pointerId()))
      target = element_under_pointer_.at(pointer_event->pointerId());

    DispatchPointerEvent(
        GetEffectiveTargetForPointerEvent(target, pointer_event->pointerId()),
        pointer_event);

    ReleasePointerCapture(pointer_event->pointerId());

    // Send the leave/out events and lostpointercapture if needed.
    // Note that for mouse due to the web compat we still don't send the
    // boundary events and for now only send lostpointercapture if needed.
    // Sending boundary events and possibly updating hover for mouse
    // in this case may cause some of the existing pages to break.
    if (web_pointer_event.pointer_type ==
        WebPointerProperties::PointerType::kMouse) {
      ProcessPendingPointerCapture(pointer_event);
    } else {
      ProcessCaptureAndPositionOfPointerEvent(pointer_event, nullptr);
    }

    RemovePointer(pointer_event);
  }
}

bool PointerEventManager::ShouldAdjustPointerEvent(
    const WebPointerEvent& pointer_event) const {
  return (pointer_event.pointer_type ==
              WebPointerProperties::PointerType::kTouch ||
          ShouldAdjustStylusPointerEvent(pointer_event)) &&
         pointer_event.GetType() == WebInputEvent::Type::kPointerDown &&
         pointer_event_factory_.IsPrimary(pointer_event);
}

bool PointerEventManager::ShouldAdjustStylusPointerEvent(
    const WebPointerEvent& pointer_event) const {
  return base::FeatureList::IsEnabled(
             blink::features::kStylusPointerAdjustment) &&
         (pointer_event.pointer_type ==
              WebPointerProperties::PointerType::kPen ||
          pointer_event.pointer_type ==
              WebPointerProperties::PointerType::kEraser);
}

void PointerEventManager::AdjustPointerEvent(WebPointerEvent& pointer_event) {
  DCHECK(
      pointer_event.pointer_type == WebPointerProperties::PointerType::kTouch ||
      pointer_event.pointer_type == WebPointerProperties::PointerType::kPen ||
      pointer_event.pointer_type == WebPointerProperties::PointerType::kEraser);

  Node* adjusted_node = nullptr;
  AdjustPointerEvent(pointer_event, adjusted_node);
}

void PointerEventManager::AdjustPointerEvent(WebPointerEvent& pointer_event,
                                             Node*& adjusted_node) {
  float adjustment_width = 0.0f;
  float adjustment_height = 0.0f;
  if (pointer_event.pointer_type == WebPointerProperties::PointerType::kTouch) {
    adjustment_width = pointer_event.width;
    adjustment_height = pointer_event.height;
  } else {
    // Calculate adjustment size for stylus tool types.
    ChromeClient& chrome_client = frame_->GetChromeClient();
    float device_scale_factor =
        chrome_client.GetScreenInfo(*frame_).device_scale_factor;

    float page_scale_factor = frame_->GetPage()->PageScaleFactor();
    adjustment_width = adjustment_height =
        kStylusWritableAdjustmentSizeDip *
        (device_scale_factor / page_scale_factor);
  }

  PhysicalSize hit_rect_size = GetHitTestRectForAdjustment(
      *frame_, PhysicalSize(LayoutUnit(adjustment_width),
                            LayoutUnit(adjustment_height)));

  if (hit_rect_size.IsEmpty())
    return;

  HitTestRequest::HitTestRequestType hit_type =
      HitTestRequest::kTouchEvent | HitTestRequest::kReadOnly |
      HitTestRequest::kActive | HitTestRequest::kListBased;
  LocalFrame& root_frame = frame_->LocalFrameRoot();
  // TODO(szager): Shouldn't this be PositionInScreen() ?
  PhysicalOffset hit_test_point =
      PhysicalOffset::FromPointFRound(pointer_event.PositionInWidget());
  hit_test_point -= PhysicalOffset(LayoutUnit(hit_rect_size.width * 0.5f),
                                   LayoutUnit(hit_rect_size.height * 0.5f));
  HitTestLocation location(PhysicalRect(hit_test_point, hit_rect_size));
  HitTestResult hit_test_result =
      root_frame.GetEventHandler().HitTestResultAtLocation(location, hit_type);
  gfx::Point adjusted_point;

  if (pointer_event.pointer_type == WebPointerProperties::PointerType::kTouch) {
    bool adjusted = frame_->GetEventHandler().BestNodeForHitTestResult(
        TouchAdjustmentCandidateType::kClickable, location, hit_test_result,
        adjusted_point, adjusted_node);

    if (adjusted)
      pointer_event.SetPositionInWidget(adjusted_point.x(), adjusted_point.y());

    frame_->GetEventHandler().CacheTouchAdjustmentResult(
        pointer_event.unique_touch_event_id, pointer_event.PositionInWidget());
  } else if (pointer_event.pointer_type ==
                 WebPointerProperties::PointerType::kPen ||
             pointer_event.pointer_type ==
                 WebPointerProperties::PointerType::kEraser) {
    // We don't cache the adjusted point for Stylus in EventHandler to avoid
    // taps being adjusted; this is intended only for stylus handwriting.
    bool adjusted = frame_->GetEventHandler().BestNodeForHitTestResult(
        TouchAdjustmentCandidateType::kStylusWritable, location,
        hit_test_result, adjusted_point, adjusted_node);

    if (adjusted)
      pointer_event.SetPositionInWidget(adjusted_point.x(), adjusted_point.y());
  }
}

bool PointerEventManager::ShouldFilterEvent(PointerEvent* pointer_event) {
  // Filter as normal if the experiment is disabled.
  if (!skip_touch_filter_discrete_)
    return true;

  // If the experiment is enabled and the event is pointer up/down, do not
  // filter.
  if (pointer_event->type() == event_type_names::kPointerdown ||
      pointer_event->type() == event_type_names::kPointerup) {
    return false;
  }
  // If the experiment is "all", do not filter pointermove.
  if (skip_touch_filter_all_ &&
      pointer_event->type() == event_type_names::kPointermove)
    return false;

  // Continue filtering other types of events, even thought the experiment is
  // enabled.
  return true;
}

event_handling_util::PointerEventTarget
PointerEventManager::ComputePointerEventTarget(
    const WebPointerEvent& web_pointer_event) {
  event_handling_util::PointerEventTarget pointer_event_target;

  PointerId pointer_id =
      pointer_event_factory_.GetPointerEventId(web_pointer_event);
  // Do the hit test either when the touch first starts or when the touch
  // is not captured. |m_pendingPointerCaptureTarget| indicates the target
  // that will be capturing this event. |m_pointerCaptureTarget| may not
  // have this target yet since the processing of that will be done right
  // before firing the event.
  if (web_pointer_event.GetType() == WebInputEvent::Type::kPointerDown ||
      !pending_pointer_capture_target_.Contains(pointer_id)) {
    HitTestRequest::HitTestRequestType hit_type = HitTestRequest::kTouchEvent |
                                                  HitTestRequest::kReadOnly |
                                                  HitTestRequest::kActive;
    HitTestLocation location(frame_->View()->ConvertFromRootFrame(
        PhysicalOffset::FromPointFRound(web_pointer_event.PositionInWidget())));
    HitTestResult hit_test_result =
        frame_->GetEventHandler().HitTestResultAtLocation(location, hit_type);
    Element* target = hit_test_result.InnerElement();
    if (target) {
      pointer_event_target.target_frame = target->GetDocument().GetFrame();
      pointer_event_target.target_element = target;
      pointer_event_target.scrollbar = hit_test_result.GetScrollbar();
    }
  } else {
    // Set the target of pointer event to the captured element as this
    // pointer is captured otherwise it would have gone to the |if| block
    // and perform a hit-test.
    pointer_event_target.target_element =
        pending_pointer_capture_target_.at(pointer_id);
    pointer_event_target.target_frame =
        pointer_event_target.target_element->GetDocument().GetFrame();
  }
  return pointer_event_target;
}

WebInputEventResult PointerEventManager::DispatchTouchPointerEvent(
    const WebPointerEvent& web_pointer_event,
    const Vector<WebPointerEvent>& coalesced_events,
    const Vector<WebPointerEvent>& predicted_events,
    const event_handling_util::PointerEventTarget& pointer_event_target) {
  DCHECK_NE(web_pointer_event.GetType(),
            WebInputEvent::Type::kPointerCausedUaAction);

  WebInputEventResult result = WebInputEventResult::kHandledSystem;
  if (pointer_event_target.target_element &&
      pointer_event_target.target_frame && !non_hovering_pointers_canceled_) {
    SetLastPointerPositionForFrameBoundary(web_pointer_event,
                                           pointer_event_target.target_element);

    PointerEvent* pointer_event = pointer_event_factory_.Create(
        web_pointer_event, coalesced_events, predicted_events,
        pointer_event_target.target_element
            ? pointer_event_target.target_element->GetDocument().domWindow()
            : nullptr);

    if (pointer_event) {
      result = SendTouchPointerEvent(pointer_event_target.target_element,
                                     pointer_event, web_pointer_event.hovering);
    } else {
      result = WebInputEventResult::kNotHandled;
    }

    // If a pointerdown has been canceled, queue the unique id to allow
    // suppressing mouse events from gesture events. For mouse events
    // fired from GestureTap & GestureLongPress (which are triggered by
    // single touches only), it is enough to queue the ids only for
    // primary pointers.
    // TODO(mustaq): What about other cases (e.g. GestureTwoFingerTap)?
    if (result != WebInputEventResult::kNotHandled &&
        pointer_event->type() == event_type_names::kPointerdown &&
        pointer_event->isPrimary()) {
      touch_ids_for_canceled_pointerdowns_.push_back(
          web_pointer_event.unique_touch_event_id);
    }
  }
  return result;
}

WebInputEventResult PointerEventManager::SendTouchPointerEvent(
    Element* target,
    PointerEvent* pointer_event,
    bool hovering) {
  if (non_hovering_pointers_canceled_)
    return WebInputEventResult::kNotHandled;

  ProcessCaptureAndPositionOfPointerEvent(pointer_event, target);

  // Setting the implicit capture for touch
  if (pointer_event->type() == event_type_names::kPointerdown) {
    SetPointerCapture(pointer_event->pointerId(), target,
                      /* explicit_capture */ false);
  }

  WebInputEventResult result = DispatchPointerEvent(
      GetEffectiveTargetForPointerEvent(target, pointer_event->pointerId()),
      pointer_event);

  if (pointer_event->type() == event_type_names::kPointerup ||
      pointer_event->type() == event_type_names::kPointercancel) {
    ReleasePointerCapture(pointer_event->pointerId());

    // If the pointer is not hovering it implies that pointerup also means
    // leaving the screen and the end of the stream for that pointer. So
    // we should send boundary events as well.
    if (!hovering) {
      // Sending the leave/out events and lostpointercapture because the next
      // touch event will have a different id.
      ProcessCaptureAndPositionOfPointerEvent(pointer_event, nullptr);

      RemovePointer(pointer_event);
    }
  }

  return result;
}

WebInputEventResult PointerEventManager::FlushEvents() {
  WebInputEventResult result = touch_event_manager_->FlushEvents();
  return result;
}

WebInputEventResult PointerEventManager::HandlePointerEvent(
    const WebPointerEvent& event,
    const Vector<WebPointerEvent>& coalesced_events,
    const Vector<WebPointerEvent>& predicted_events) {
  if (event.GetType() == WebInputEvent::Type::kPointerRawUpdate) {
    if (!frame_->GetEventHandlerRegistry().HasEventHandlers(
            EventHandlerRegistry::kPointerRawUpdateEvent))
      return WebInputEventResult::kHandledSystem;

    // If the page has pointer lock active and the event was from
    // mouse use the locked target as the target.
    // TODO(nzolghadr): Consideration for locked element might fit
    // better in ComputerPointerEventTarget but at this point it is
    // not quite possible as we haven't merged the locked event
    // dispatch with this path.
    Node* target;
    Element* pointer_locked_element =
        PointerLockController::GetPointerLockedElement(frame_);
    if (pointer_locked_element &&
        event.pointer_type == WebPointerProperties::PointerType::kMouse) {
      // The locked element could be in another frame. So we need to delegate
      // sending the event to that frame.
      LocalFrame* target_frame =
          pointer_locked_element->GetDocument().GetFrame();
      if (!target_frame)
        return WebInputEventResult::kHandledSystem;
      if (target_frame != frame_) {
        target_frame->GetEventHandler().HandlePointerEvent(
            event, coalesced_events, predicted_events);
        return WebInputEventResult::kHandledSystem;
      }
      target = pointer_locked_element;
    } else {
      target = ComputePointerEventTarget(event).target_element;
    }

    PointerEvent* pointer_event =
        pointer_event_factory_.Create(event, coalesced_events, predicted_events,
                                      frame_->GetDocument()->domWindow());
    // The conditional return below is deliberately placed after the Create()
    // call above because of some side-effects of Create() (in particular
    // SetLastPosition()) is needed even with the early return below.  See
    // crbug.com/1066544.
    //
    // Sometimes the Browser process tags events with kRelativeMotionEvent.
    // E.g. during pointer lock, it recenters cursor by warping so that cursor
    // does not hit the screen boundary.  Those fake events should not be
    // forwarded to the DOM.
    if (event.GetModifiers() & WebInputEvent::Modifiers::kRelativeMotionEvent)
      return WebInputEventResult::kHandledSuppressed;

    if (pointer_event) {
      // TODO(crbug.com/1141595): We should handle this case further upstream.
      DispatchPointerEvent(target, pointer_event);
    }
    return WebInputEventResult::kHandledSystem;
  }

  if (event.GetType() == WebInputEvent::Type::kPointerCausedUaAction) {
    HandlePointerInterruption(event);
    return WebInputEventResult::kHandledSystem;
  }

  // The rest of this function doesn't handle hovering (i.e. mouse like) events.

  WebPointerEvent pointer_event = event.WebPointerEventInRootFrame();
  if (ShouldAdjustPointerEvent(event))
    AdjustPointerEvent(pointer_event);
  event_handling_util::PointerEventTarget pointer_event_target =
      ComputePointerEventTarget(pointer_event);

  bool is_pointer_down = event.GetType() == WebInputEvent::Type::kPointerDown;
  if (is_pointer_down && discarded_event_.target != kInvalidDOMNodeId &&
      discarded_event_.target ==
          pointer_event_target.target_element->GetDomNodeId() &&
      pointer_event.TimeStamp() - discarded_event_.time <
          event_handling_util::kDiscardedEventMistakeInterval) {
    pointer_event_target.target_element->GetDocument().CountUse(
        WebFeature::kInputEventToRecentlyMovedIframeMistakenlyDiscarded);
  }
  bool discard = pointer_event_target.target_frame &&
                 event_handling_util::ShouldDiscardEventTargetingFrame(
                     event, *pointer_event_target.target_frame);
  if (discard) {
    if (is_pointer_down) {
      discarded_event_.target =
          pointer_event_target.target_element->GetDomNodeId();
      discarded_event_.time = pointer_event.TimeStamp();
    }
    PointerEvent* core_pointer_event = pointer_event_factory_.Create(
        event, coalesced_events, predicted_events,
        pointer_event_target.target_element
            ? pointer_event_target.target_element->GetDocument().domWindow()
            : nullptr);
    if (core_pointer_event) {
      // TODO(crbug.com/1141595): We should handle this case further upstream.
      SendTouchPointerEvent(
          pointer_event_target.target_element,
          pointer_event_factory_.CreatePointerCancelEvent(
              core_pointer_event->pointerId(), event.TimeStamp(),
              core_pointer_event->persistentDeviceId()),
          event.hovering);
    }

    WebPointerEvent pointer_cancel_event;
    pointer_cancel_event.pointer_type = event.pointer_type;
    pointer_cancel_event.SetTimeStamp(event.TimeStamp());
    pointer_cancel_event.SetType(WebInputEvent::Type::kPointerCancel);
    touch_event_manager_->HandleTouchPoint(
        pointer_cancel_event, coalesced_events, pointer_event_target);

    return WebInputEventResult::kHandledSuppressed;
  }

  if (is_pointer_down) {
    discarded_event_.target = kInvalidDOMNodeId;
    discarded_event_.time = base::TimeTicks();
  }

  if (HandleScrollbarTouchDrag(event, pointer_event_target.scrollbar))
    return WebInputEventResult::kHandledSuppressed;

  if (HandleResizerDrag(pointer_event, pointer_event_target))
    return WebInputEventResult::kHandledSuppressed;

  // Any finger lifting is a user gesture only when it wasn't associated with a
  // scroll.
  // https://docs.google.com/document/d/1oF1T3O7_E4t1PYHV6gyCwHxOi3ystm0eSL5xZu7nvOg/edit#
  //
  // For the rare case of multi-finger scenarios spanning documents, it
  // seems extremely unlikely to matter which document the gesture is
  // associated with so just pick the pointer event that comes.
  if (event.GetType() == WebInputEvent::Type::kPointerUp &&
      !non_hovering_pointers_canceled_ && pointer_event_target.target_frame) {
    LocalFrame::NotifyUserActivation(
        pointer_event_target.target_frame,
        mojom::blink::UserActivationNotificationType::kInteraction);
  }

  if (!event.hovering && !IsAnyTouchActive()) {
    non_hovering_pointers_canceled_ = false;
  }
  Node* pointerdown_node = nullptr;
  if (is_pointer_down) {
    pointerdown_node =
        touch_event_manager_->GetTouchPointerNode(event, pointer_event_target);
  }

  if (pointerdown_node) {
    TouchAction touch_action =
        touch_action_util::EffectiveTouchActionAtPointerDown(event,
                                  
"""


```