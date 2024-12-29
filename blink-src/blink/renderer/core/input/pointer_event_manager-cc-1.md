Response:
Let's break down the thought process for analyzing this code snippet. The request is to understand the functionality of `PointerEventManager`, its relationships with web technologies, infer logic, identify potential errors, and trace user interaction. Since this is the *second* part of the file, we also need to summarize the overall function.

**1. Initial Read and High-Level Understanding (Skimming):**

My first pass involves quickly reading through the code to get a sense of the main actions being performed. I look for keywords like "Handle," "Dispatch," "Create," "Set," "Get," "Process," and the different event types (e.g., `kPointerDown`, `kPointerMove`, `kPointerUp`). I notice interactions with `TouchEventManager`, `MouseEventManager`, `PointerEventFactory`, and concepts like "capture," "resize," and "scrollbar."  This gives me a general idea that this class is responsible for managing pointer events (mouse, touch, pen).

**2. Analyzing Individual Functions (Detailed Reading and Grouping):**

Next, I go through each function more carefully, trying to understand its specific purpose. I start grouping related functions together:

* **Event Handling:**  Functions like `HandleTouch`, `HandleScrollbarTouchDrag`, `HandleResizerDrag`, `CreateAndDispatchPointerEvent`, `DirectDispatchMousePointerEvent`, `SendMousePointerEvent`. These are clearly about processing different types of pointer interactions.
* **Pointer Capture:** Functions like `SetPointerCapture`, `ReleasePointerCapture`, `HasPointerCapture`, `ProcessPendingPointerCapture`, `GetPointerCaptureState`. This highlights the capture mechanism.
* **Positioning and Targeting:** `ProcessCaptureAndPositionOfPointerEvent`, `SetElementUnderPointer`, `GetEffectiveTargetForPointerEvent`. These deal with figuring out which element the pointer is interacting with.
* **State Management:** `IsActive`, `IsAnyTouchActive`, `IsPointerIdActiveOnFrame`. These functions track the state of pointers and touches.
* **Internal Utilities:** `RemovePointer`, `ElementRemoved`, `RemoveTargetFromPointerCapturingMapping`. These seem to be for internal cleanup and maintenance.
* **Specific Actions:** `SendEffectivePanActionAtPointer`, `SetLastPointerPositionForFrameBoundary`, `RemoveLastMousePosition`. These are for triggering specific browser behaviors.

**3. Identifying Relationships with Web Technologies (Connecting to the Outside World):**

As I read, I start thinking about how these functions relate to JavaScript, HTML, and CSS:

* **JavaScript Events:**  The names of the events (e.g., `pointerdown`, `pointermove`, `pointerup`, `gotpointercapture`, `lostpointercapture`) directly correspond to the Pointer Events API in JavaScript. The code is responsible for dispatching these events to the JavaScript layer.
* **HTML Elements:** The functions frequently manipulate `Element` objects. These represent the DOM elements in an HTML document. The targeting and capture mechanisms are all about interacting with specific elements.
* **CSS and Layout:**  The interaction with `LayoutObject` and `PaintLayer` in `HandleResizerDrag` suggests a connection to how CSS affects the visual layout and how resizable elements are handled. The `TouchAction` property, which can be set via CSS, is explicitly used.
* **Scrollbars:** `HandleScrollbarTouchDrag` directly interacts with `Scrollbar` objects, demonstrating the handling of interactions with browser UI elements.

**4. Inferring Logic and Providing Examples (Making Educated Guesses):**

Based on the function names and the operations performed, I start inferring the underlying logic and creating hypothetical input/output scenarios. For example, with `HandleTouch`, I can imagine a user touching the screen (input) and the function determining the target element and dispatching the appropriate pointer events (output). For `HandleResizerDrag`, I can imagine a user pressing down on a resizer handle, moving the mouse, and then releasing it, and how this translates into changes in the element's size.

**5. Identifying Potential Errors and User Mistakes (Thinking About Edge Cases):**

I consider common mistakes developers might make when working with pointer events:

* **Incorrect Capture Management:**  Forgetting to release capture, trying to capture on an element that can't be captured.
* **Assuming Mouse Events Always Follow Pointer Events:**  The code explicitly handles suppressing mouse events in certain scenarios, so developers need to be aware of this.
* **Not Handling Different Pointer Types:**  The code distinguishes between touch, mouse, and pen, and developers need to handle these appropriately in their JavaScript.

**6. Tracing User Operations (Following the Event Flow):**

I try to trace the path of a user interaction through the code. For example, for a simple click:

1. User touches the screen (touchdown).
2. The browser's input handling mechanism detects the touch.
3. This likely leads to a call to `HandleTouch` in `PointerEventManager`.
4. `HandleTouch` determines the target element.
5. It creates and dispatches `pointerdown` events.
6. If the user releases the touch, `HandleTouch` is called again.
7. It creates and dispatches `pointerup` and potentially `click` events.

**7. Addressing the "Part 2" Requirement (Summarizing):**

Since this is the second part, I need to look back at the functionality inferred from this snippet and summarize its role within the larger `PointerEventManager` class. It seems focused on the core dispatching and handling of various pointer event types, along with managing pointer capture and interactions with specific UI elements like scrollbars and resizers.

**8. Refinement and Organization:**

Finally, I organize my thoughts into a structured format, using clear headings and bullet points to present the information in a readable way. I double-check the code snippets and examples for accuracy and clarity. I try to use precise terminology related to web development and browser internals.

This iterative process of reading, analyzing, connecting, inferring, and organizing helps me understand the functionality of the code and provide a comprehensive answer to the prompt.
好的，这是对`blink/renderer/core/input/pointer_event_manager.cc`文件第二部分的分析和功能归纳。

**功能归纳 (基于提供的第二部分代码):**

这部分 `PointerEventManager` 的代码主要负责以下功能：

1. **处理非主触摸的拖动事件:** 专门处理滚动条上的触摸拖动事件 (`HandleScrollbarTouchDrag`)，允许用户通过触摸或笔在滚动条上进行交互。
2. **处理元素大小调整拖动:**  处理可调整大小元素的拖动事件 (`HandleResizerDrag`)，允许用户通过拖动特定控件来改变元素的大小。
3. **将鼠标事件转换为指针事件并分发:**  `CreateAndDispatchPointerEvent` 函数将接收到的鼠标事件（如 `mousedown`, `mousemove`, `mouseup`）转换为对应的指针事件，并分发到目标元素。
4. **直接分发鼠标指针事件:** `DirectDispatchMousePointerEvent` 函数用于直接分发鼠标指针事件，其中包含对相对运动事件的处理，并与 `MouseEventManager` 协同工作。
5. **发送有效的平移动作:** `SendEffectivePanActionAtPointer` 函数根据指针位置和目标元素的 `touch-action` CSS 属性，确定并设置有效的平移动作（例如，是否允许滚动、缩放或笔触输入）。
6. **发送鼠标指针事件 (核心分发逻辑):** `SendMousePointerEvent` 函数是处理鼠标输入并生成和分发相应指针事件的核心函数。它处理捕获、位置计算、兼容性鼠标事件的分发以及 `click` 事件的触发。
7. **管理指针捕获状态:**  `GetPointerCaptureState` 用于获取指定指针的捕获状态，包括当前捕获目标和等待捕获的目标。
8. **处理指针事件的捕获和位置:** `ProcessCaptureAndPositionOfPointerEvent` 函数在分发指针事件之前，处理指针捕获的变更，并设置指针下的元素。
9. **处理待处理的指针捕获:** `ProcessPendingPointerCapture` 函数处理 `setPointerCapture` 调用后，尚未生效的指针捕获请求，并在适当的时候分发 `gotpointercapture` 和 `lostpointercapture` 事件。
10. **从捕获映射中移除目标:** `RemoveTargetFromPointerCapturingMapping` 用于在元素被移除时，从指针捕获映射中清理相关的条目。
11. **移除指针:** `RemovePointer` 函数从内部状态中移除不再活动的指针。
12. **处理元素移除事件:** `ElementRemoved` 函数在DOM元素被移除时执行清理操作。
13. **设置指针捕获:** `SetPointerCapture` 函数允许元素请求捕获特定指针的后续事件。
14. **释放指针捕获:** `ReleasePointerCapture` 函数允许元素释放之前捕获的指针。
15. **释放鼠标指针捕获:** `ReleaseMousePointerCapture` 专门释放鼠标指针的捕获。
16. **检查是否拥有指针捕获:** `HasPointerCapture` 函数检查指定元素是否拥有特定指针的捕获。
17. **获取鼠标捕获目标:** `GetMouseCaptureTarget` 返回当前捕获鼠标事件的元素。
18. **检查指针是否活动:** `IsActive` 函数检查指定的指针ID是否处于活动状态。
19. **检查指针ID是否在指定帧上活动:** `IsPointerIdActiveOnFrame` 用于判断特定指针是否在一个给定的 `LocalFrame` 中活动。
20. **检查是否有任何触摸活动:** `IsAnyTouchActive` 函数检查当前是否有任何触摸事件正在进行。
21. **判断主指针按下是否被取消:** `PrimaryPointerdownCanceled` 用于判断由触摸事件触发的主指针按下事件是否被取消。
22. **设置帧边界的最后指针位置:** `SetLastPointerPositionForFrameBoundary` 在指针跨越iframe边界时更新指针的最后已知位置。
23. **移除最后的鼠标位置:** `RemoveLastMousePosition` 清除记录的最后鼠标位置。
24. **获取触摸手势的指针ID:** `GetPointerIdForTouchGesture` 获取与特定触摸手势关联的指针ID。
25. **获取当前触摸按下的元素:** `CurrentTouchDownElement` 返回当前被触摸按下的元素。

**与 Javascript, HTML, CSS 的关系举例说明:**

* **Javascript:**
    * **事件分发:** 当用户在屏幕上点击时，这个代码会创建并分发 `pointerdown`, `pointerup`, `click` 等 JavaScript 事件到相应的 DOM 元素上。例如，如果用户点击一个按钮，JavaScript 中注册的 `onclick` 或 `onpointerdown` 事件监听器会被触发。
    * **`setPointerCapture()` 和 `releasePointerCapture()`:**  JavaScript 可以调用元素的 `setPointerCapture()` 方法来请求捕获后续的指针事件，这个请求最终会调用到 `PointerEventManager::SetPointerCapture`。同样，`releasePointerCapture()` 会调用到 `PointerEventManager::ReleasePointerCapture`。
    * **Pointer Events API:**  这个类是 Blink 引擎中 Pointer Events API 的核心实现部分，它负责将底层的输入事件转化为符合标准的 Pointer Events，供 JavaScript 使用。

* **HTML:**
    * **目标元素:**  当鼠标移动到一个 HTML 元素上时，`PointerEventManager` 需要确定哪个元素是事件的目标，并将事件分发到该元素。这与 HTML 的 DOM 结构直接相关。
    * **可调整大小的元素:**  当用户拖动 HTML 中某个可调整大小的元素（可能通过 CSS 设置），`HandleResizerDrag` 负责处理这些拖动，最终改变该元素的尺寸，这会影响 HTML 的布局和渲染。

* **CSS:**
    * **`touch-action` 属性:** `SendEffectivePanActionAtPointer` 函数会读取目标元素的 `touch-action` CSS 属性，以确定允许的触摸交互类型（例如，是否允许垂直或水平滚动，是否允许缩放等）。这直接影响了浏览器如何处理触摸输入。例如，如果一个元素的 `touch-action: none;`，那么在该元素上的触摸操作将不会触发默认的滚动或缩放行为。

**逻辑推理的假设输入与输出:**

假设用户在一个启用了拖拽调整大小功能的 `<div>` 元素边缘进行操作：

**假设输入:**

1. **用户操作:** 用户使用鼠标按下（`mousedown`）该 `<div>` 元素右下角的调整大小手柄。
2. **WebMouseEvent:** 接收到一个 `WebMouseEvent`，其 `type` 为 `kMouseDown`，`positionInWidget` 指示了手柄的位置，`target` 指向该 `<div>` 元素。

**逻辑推理过程 (在 `HandleResizerDrag` 中):**

1. `event.GetType() == WebInputEvent::Type::kPointerDown` 条件成立。
2. 检查 `pointer_event_target.target_element` 是否是该 `<div>` 元素，并且它有布局对象和层。
3. 检查该元素的层是否可滚动。
4. 计算鼠标在元素坐标系中的位置 `p`。
5. 调用 `layer->GetScrollableArea()->IsAbsolutePointInResizeControl(p, kResizerForTouch)` 检查点击位置是否在调整大小的控制区域内。
6. 如果是，则将 `resize_scrollable_area_` 设置为该元素的可滚动区域，并设置进入调整大小模式。
7. 计算点击位置相对于调整大小角点的偏移量 `offset_from_resize_corner_`。
8. 函数返回 `true`，表示事件被处理。

**假设输出:**

1. `resize_scrollable_area_` 被设置为该 `<div>` 元素的滚动区域对象。
2. `resize_scrollable_area_->IsInResizeMode()` 返回 `true`。
3. `offset_from_resize_corner_` 存储了点击位置相对于调整大小角点的偏移量。
4. 浏览器可能会阻止默认的文本选择等行为。

**用户或编程常见的使用错误举例说明:**

* **错误地假设鼠标事件会始终触发指针事件:**  开发者可能会认为，只要有鼠标事件，就一定会有对应的指针事件。但实际上，浏览器为了兼容性或性能优化，可能会抑制某些鼠标事件的指针事件分发。例如，在触摸设备上模拟鼠标事件时，可能不会总是产生完全一致的指针事件序列。
* **在指针捕获期间未正确处理事件:**  如果一个元素通过 `setPointerCapture()` 捕获了指针，开发者可能会忘记在该元素被移除或不再需要捕获时释放捕获。这会导致后续的指针事件仍然被发送到该元素（即使它已经不在 DOM 中），从而导致意外的行为。
    * **示例:** 一个拖拽操作开始时捕获了指针，但如果用户在拖拽过程中将鼠标移出浏览器窗口，并且开发者没有正确处理 `pointercancel` 事件来释放捕获，那么当用户将鼠标移回时，可能会出现状态不同步的问题。
* **混淆鼠标事件和指针事件的坐标:**  鼠标事件和指针事件的坐标属性可能在某些情况下略有不同，例如在处理视口偏移或页面缩放时。开发者需要仔细理解这些差异，并根据具体需求使用正确的坐标。

**用户操作是如何一步步的到达这里，作为调试线索:**

以一个简单的鼠标点击操作为例，用户操作到达 `PointerEventManager` 的步骤可能如下：

1. **用户操作:** 用户使用鼠标点击网页上的一个链接或按钮。
2. **操作系统层:** 操作系统检测到鼠标硬件事件（鼠标按下）。
3. **浏览器进程 (Browser Process):** 操作系统将鼠标事件传递给浏览器进程。
4. **渲染器进程 (Renderer Process):** 浏览器进程将该事件传递给负责渲染当前网页的渲染器进程。
5. **输入处理 (Input Handling):** 渲染器进程的输入处理模块接收到该鼠标事件。
6. **WebContents:**  事件可能经过 `WebContents` 等中间层。
7. **LocalFrameView:**  事件被传递到与当前网页关联的 `LocalFrameView`。
8. **EventHandler:** `LocalFrameView` 的 `EventHandler` 负责处理各种输入事件。
9. **MouseEventManager:**  鼠标事件可能会先被 `MouseEventManager` 处理，进行一些预处理和过滤。
10. **PointerEventManager:**  `MouseEventManager` 最终会将相关的鼠标事件（例如 `mousedown`）传递给 `PointerEventManager` 的相关函数，例如 `SendMousePointerEvent` 或 `DirectDispatchMousePointerEvent`，以便创建和分发相应的指针事件。

**调试线索:**

* **断点:** 在 `PointerEventManager` 的关键函数（例如 `SendMousePointerEvent`, `DispatchPointerEvent`, `HandleTouch` 等）设置断点，可以观察事件是如何被创建、修改和分发的。
* **日志:**  可以在 `PointerEventManager` 中添加日志输出，记录接收到的 WebInputEvent 的类型、目标、坐标等信息，以及创建和分发的 PointerEvent 的属性。
* **DevTools 事件监听器:**  Chrome DevTools 的 "Event Listener Breakpoints" 功能可以让你在特定类型的事件被触发时暂停 JavaScript 执行，从而观察事件流。
* **`chrome://tracing`:**  可以使用 Chrome 的 tracing 工具来记录更底层的事件，包括输入事件的处理过程，这可以帮助理解事件在 Blink 引擎内部的传递路径。
* **检查事件属性:**  在 JavaScript 中打印事件对象的属性（例如 `event.pointerType`, `event.pointerId`, `event.target` 等），可以帮助理解浏览器识别到的输入类型和目标元素。

希望以上分析和说明能够帮助你理解 `PointerEventManager` 的这部分代码的功能。

Prompt: 
```
这是目录为blink/renderer/core/input/pointer_event_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
                           pointerdown_node);
    touch_event_manager_->UpdateTouchAttributeMapsForPointerDown(
        event, pointerdown_node, touch_action);
  }

  WebInputEventResult result = DispatchTouchPointerEvent(
      event, coalesced_events, predicted_events, pointer_event_target);

  touch_event_manager_->HandleTouchPoint(event, coalesced_events,
                                         pointer_event_target);

  return result;
}

bool PointerEventManager::HandleScrollbarTouchDrag(const WebPointerEvent& event,
                                                   Scrollbar* scrollbar) {
  if (!scrollbar ||
      (event.pointer_type != WebPointerProperties::PointerType::kTouch &&
       event.pointer_type != WebPointerProperties::PointerType::kPen)) {
    return false;
  }

  if (event.GetType() == WebInputEvent::Type::kPointerDown) {
    captured_scrollbar_ = scrollbar;
    frame_->GetPage()->GetChromeClient().SetTouchAction(frame_,
                                                        TouchAction::kNone);
  }

  if (!captured_scrollbar_)
    return false;

  bool handled = captured_scrollbar_->HandlePointerEvent(event);
  if (event.GetType() == WebInputEvent::Type::kPointerUp)
    captured_scrollbar_ = nullptr;

  return handled;
}

bool PointerEventManager::HandleResizerDrag(
    const WebPointerEvent& event,
    const event_handling_util::PointerEventTarget& pointer_event_target) {
  switch (event.GetType()) {
    case WebPointerEvent::Type::kPointerDown: {
      Node* node = pointer_event_target.target_element;
      if (!node || !node->GetLayoutObject() ||
          !node->GetLayoutObject()->EnclosingLayer())
        return false;

      PaintLayer* layer = node->GetLayoutObject()->EnclosingLayer();
      if (!layer->GetScrollableArea())
        return false;

      gfx::Point p =
          pointer_event_target.target_frame->View()->ConvertFromRootFrame(
              gfx::ToFlooredPoint(event.PositionInWidget()));
      if (layer->GetScrollableArea()->IsAbsolutePointInResizeControl(
              p, kResizerForTouch)) {
        resize_scrollable_area_ = layer->GetScrollableArea();
        resize_scrollable_area_->SetInResizeMode(true);
        frame_->GetPage()->GetChromeClient().SetTouchAction(frame_,
                                                            TouchAction::kNone);
        offset_from_resize_corner_ =
            resize_scrollable_area_->OffsetFromResizeCorner(p);
        return true;
      }
      break;
    }
    case WebInputEvent::Type::kPointerMove: {
      if (resize_scrollable_area_ && resize_scrollable_area_->Layer() &&
          resize_scrollable_area_->Layer()->GetLayoutBox() &&
          resize_scrollable_area_->InResizeMode()) {
        gfx::Point pos = gfx::ToRoundedPoint(event.PositionInWidget());
        resize_scrollable_area_->Resize(pos, offset_from_resize_corner_);
        return true;
      }
      break;
    }
    case WebInputEvent::Type::kPointerUp: {
      if (resize_scrollable_area_ && resize_scrollable_area_->InResizeMode()) {
        resize_scrollable_area_->SetInResizeMode(false);
        resize_scrollable_area_.Clear();
        offset_from_resize_corner_ = {};
        return true;
      }
      break;
    }
    default:
      return false;
  }
  return false;
}

WebInputEventResult PointerEventManager::CreateAndDispatchPointerEvent(
    Element* target,
    const AtomicString& mouse_event_name,
    const WebMouseEvent& mouse_event,
    const Vector<WebMouseEvent>& coalesced_events,
    const Vector<WebMouseEvent>& predicted_events) {
  WebInputEvent::Type event_type;
  // TODO(crbug.com/665924): The following ifs skip the mouseover/leave cases,
  // we should fixed them when further merge the code path.
  if (mouse_event_name == event_type_names::kMousemove)
    event_type = WebInputEvent::Type::kPointerMove;
  else if (mouse_event_name == event_type_names::kMousedown)
    event_type = WebInputEvent::Type::kPointerDown;
  else if (mouse_event_name == event_type_names::kMouseup)
    event_type = WebInputEvent::Type::kPointerUp;
  else
    return WebInputEventResult::kNotHandled;

  const WebPointerEvent web_pointer_event(event_type, mouse_event);
  Vector<WebPointerEvent> pointer_coalesced_events;
  for (const WebMouseEvent& e : coalesced_events)
    pointer_coalesced_events.push_back(WebPointerEvent(event_type, e));
  Vector<WebPointerEvent> pointer_predicted_events;
  for (const WebMouseEvent& e : predicted_events)
    pointer_predicted_events.push_back(WebPointerEvent(event_type, e));

  PointerEvent* pointer_event = pointer_event_factory_.Create(
      web_pointer_event, pointer_coalesced_events, pointer_predicted_events,
      target->GetDocument().domWindow());
  DCHECK(pointer_event);

  ProcessCaptureAndPositionOfPointerEvent(pointer_event, target, &mouse_event);

  return DispatchPointerEvent(target, pointer_event);
}

// TODO(crbug.com/665924): Because this code path might have boundary events,
// it is different from SendMousePointerEvent. We should merge them.
WebInputEventResult PointerEventManager::DirectDispatchMousePointerEvent(
    Element* target,
    const WebMouseEvent& event,
    const AtomicString& mouse_event_type,
    const Vector<WebMouseEvent>& coalesced_events,
    const Vector<WebMouseEvent>& predicted_events) {
  if (!(event.GetModifiers() &
        WebInputEvent::Modifiers::kRelativeMotionEvent)) {
    // Fetch the last_mouse_position for creating MouseEvent before
    // pointer_event_factory updates it.
    gfx::PointF last_mouse_position =
        pointer_event_factory_.GetLastPointerPosition(
            PointerEventFactory::kMouseId, event, event.GetType());

    WebInputEventResult result = CreateAndDispatchPointerEvent(
        target, mouse_event_type, event, coalesced_events, predicted_events);

    result = event_handling_util::MergeEventResult(
        result,
        mouse_event_manager_->DispatchMouseEvent(
            target, mouse_event_type, event, &last_mouse_position, nullptr));
    return result;
  }
  pointer_event_factory_.SetLastPosition(
      pointer_event_factory_.GetPointerEventId(event), event.PositionInScreen(),
      event.GetType());

  return WebInputEventResult::kHandledSuppressed;
}

void PointerEventManager::SendEffectivePanActionAtPointer(
    const WebPointerEvent& event,
    const Node* node_at_pointer) {
  if (IsAnyTouchActive())
    return;

  if (ShouldAdjustStylusPointerEvent(event)) {
    Node* adjusted_node = nullptr;
    // Check if node adjustment allows stylus writing. Use a cloned event to
    // avoid adjusting actual pointer's position.
    std::unique_ptr<WebInputEvent> cloned_event = event.Clone();
    WebPointerEvent& cloned_pointer_event =
        static_cast<WebPointerEvent&>(*cloned_event);
    AdjustPointerEvent(cloned_pointer_event, adjusted_node);
    if (adjusted_node) {
      node_at_pointer = adjusted_node;
    }
  }

  TouchAction effective_touch_action = TouchAction::kAuto;
  if (node_at_pointer) {
    effective_touch_action = touch_action_util::EffectiveTouchActionAtPointer(
        event, node_at_pointer);
  }

  mojom::blink::PanAction effective_pan_action;
  if ((effective_touch_action & TouchAction::kPan) == TouchAction::kNone) {
    // Stylus writing or move cursor are applicable only when touch action
    // allows panning in at least one direction.
    effective_pan_action = mojom::blink::PanAction::kNone;
  } else if ((effective_touch_action & TouchAction::kInternalNotWritable) !=
             TouchAction::kInternalNotWritable) {
    // kInternalNotWritable bit is re-enabled, if tool type is not stylus.
    // Hence, if this bit is not set, stylus writing is possible.
    effective_pan_action = mojom::blink::PanAction::kStylusWritable;
  } else if ((effective_touch_action & TouchAction::kInternalPanXScrolls) !=
             TouchAction::kInternalPanXScrolls) {
    effective_pan_action = mojom::blink::PanAction::kMoveCursorOrScroll;
  } else {
    effective_pan_action = mojom::blink::PanAction::kScroll;
  }

  frame_->GetChromeClient().SetPanAction(frame_, effective_pan_action);
}

namespace {

Element* NonDeletedElementTarget(Element* target,
                                 PointerEvent* dispatched_pointer_event) {
  // Event path could be null if the pointer event failed to get dispatched.
  bool has_event_path = dispatched_pointer_event->HasEventPath();

  if (!event_handling_util::IsInDocument(target) && has_event_path) {
    for (const auto& context :
         dispatched_pointer_event->GetEventPath().NodeEventContexts()) {
      auto* element = DynamicTo<Element>(&context.GetNode());
      if (element && event_handling_util::IsInDocument(element)) {
        return element;
      }
    }
  }
  return target;
}

}  // namespace

WebInputEventResult PointerEventManager::SendMousePointerEvent(
    Element* target,
    const WebInputEvent::Type event_type,
    const WebMouseEvent& mouse_event,
    const Vector<WebMouseEvent>& coalesced_events,
    const Vector<WebMouseEvent>& predicted_events,
    bool skip_click_dispatch) {
  DCHECK(event_type == WebInputEvent::Type::kPointerDown ||
         event_type == WebInputEvent::Type::kPointerMove ||
         event_type == WebInputEvent::Type::kPointerUp);

  const WebPointerEvent web_pointer_event(event_type, mouse_event);
  Vector<WebPointerEvent> pointer_coalesced_events;
  for (const WebMouseEvent& e : coalesced_events)
    pointer_coalesced_events.push_back(WebPointerEvent(event_type, e));
  Vector<WebPointerEvent> pointer_predicted_events;
  for (const WebMouseEvent& e : predicted_events)
    pointer_predicted_events.push_back(WebPointerEvent(event_type, e));

  // Fetch the last_mouse_position for creating MouseEvent before
  // pointer_event_factory updates it.
  gfx::PointF last_mouse_position =
      pointer_event_factory_.GetLastPointerPosition(
          pointer_event_factory_.GetPointerEventId(mouse_event), mouse_event,
          event_type);

  bool fake_event = (web_pointer_event.GetModifiers() &
                     WebInputEvent::Modifiers::kRelativeMotionEvent);

  // Fake events should only be move events.
  DCHECK(!fake_event || event_type == WebInputEvent::Type::kPointerMove);

  PointerEvent* pointer_event = pointer_event_factory_.Create(
      web_pointer_event, pointer_coalesced_events, pointer_predicted_events,
      frame_->GetDocument()->domWindow());
  DCHECK(pointer_event);

  // This is for when the mouse is released outside of the page.
  if (!fake_event && event_type == WebInputEvent::Type::kPointerMove &&
      !pointer_event->buttons()) {
    ReleasePointerCapture(pointer_event->pointerId());
    // Send got/lostpointercapture rightaway if necessary.
    ProcessPendingPointerCapture(pointer_event);

    if (pointer_event->isPrimary()) {
      prevent_mouse_event_for_pointer_type_[ToPointerTypeIndex(
          web_pointer_event.pointer_type)] = false;
    }
  }

  // TODO(https://crbug.com/1500354): We should not pass the `mouse_event`
  // parameter in the call below because we don't want to send the boundary
  // MouseEvents before dispatching the PointerEvent.  Otherwise, a DOM
  // modification through the PointerEvent handler gives a wrong sequence of
  // boundary MouseEvent.
  Element* effective_target = ProcessCaptureAndPositionOfPointerEvent(
      pointer_event, target, &mouse_event);

  // Don't send fake mouse event to the DOM.
  if (fake_event)
    return WebInputEventResult::kHandledSuppressed;

  if ((event_type == WebInputEvent::Type::kPointerDown ||
       event_type == WebInputEvent::Type::kPointerUp) &&
      pointer_event->type() == event_type_names::kPointermove &&
      frame_->GetEventHandlerRegistry().HasEventHandlers(
          EventHandlerRegistry::kPointerRawUpdateEvent)) {
    // This is a chorded button move event. We need to also send a
    // pointerrawupdate for it.
    DispatchPointerEvent(
        effective_target,
        pointer_event_factory_.CreatePointerRawUpdateEvent(pointer_event));
  }

  WebInputEventResult result =
      DispatchPointerEvent(effective_target, pointer_event);

  if (result != WebInputEventResult::kNotHandled &&
      pointer_event->type() == event_type_names::kPointerdown &&
      pointer_event->isPrimary()) {
    prevent_mouse_event_for_pointer_type_[ToPointerTypeIndex(
        mouse_event.pointer_type)] = true;
  }

  bool send_compat_mouse =
      pointer_event->isPrimary() &&
      !prevent_mouse_event_for_pointer_type_[ToPointerTypeIndex(
          mouse_event.pointer_type)];
  bool consider_click_dispatch = !skip_click_dispatch &&
                                 pointer_event->isPrimary() &&
                                 event_type == WebInputEvent::Type::kPointerUp;

  // Calculate mouse target if either compatibility mouse event or click event
  // or both should be sent.
  Element* mouse_target = nullptr;
  if (send_compat_mouse || consider_click_dispatch) {
    mouse_target =
        RuntimeEnabledFeatures::BoundaryEventDispatchTracksNodeRemovalEnabled()
            ? mouse_event_manager_->GetElementUnderMouse()
            : NonDeletedElementTarget(effective_target, pointer_event);
  }

  // Dispatch compat mouse events.
  if (send_compat_mouse) {
    result = event_handling_util::MergeEventResult(
        result,
        mouse_event_manager_->DispatchMouseEvent(
            mouse_target, MouseEventNameForPointerEventInputType(event_type),
            mouse_event, &last_mouse_position, nullptr));
  }

  if (!mouse_target) {
    consider_click_dispatch = false;
  }

  Element* captured_click_target = nullptr;
  if (consider_click_dispatch) {
    // Remember the capture target for the click dispatch later, if applicable.
    captured_click_target =
        GetEffectiveTargetForPointerEvent(nullptr, pointer_event->pointerId());
    // Dispatch the click event only when the flag is disabled.
    if (!RuntimeEnabledFeatures::ClickToCapturedPointerEnabled()) {
      mouse_event_manager_->DispatchMouseClickIfNeeded(
          mouse_target, captured_click_target, mouse_event,
          pointer_event->pointerId(), pointer_event->pointerType());
    }
  }

  if (pointer_event->type() == event_type_names::kPointerup ||
      pointer_event->type() == event_type_names::kPointercancel) {
    ReleasePointerCapture(pointer_event->pointerId());

    // Send got/lostpointercapture rightaway if necessary.
    if (pointer_event->type() == event_type_names::kPointerup) {
      // We also send boundary events here rightaway.  To find the new position
      // under the pointer, we perform a hit-test again if a pointer-capture is
      // going to be released now; otherwise we use the original hit-test target
      // (or its ancestor in the event-path if it has been removed from DOM).
      if (pointer_capture_target_.find(pointer_event->pointerId()) !=
          pointer_capture_target_.end()) {
        HitTestRequest::HitTestRequestType hit_type = HitTestRequest::kRelease;
        HitTestRequest request(hit_type);
        MouseEventWithHitTestResults mev =
            event_handling_util::PerformMouseEventHitTest(frame_, request,
                                                          mouse_event);
        target = mev.InnerElement();
      } else if (RuntimeEnabledFeatures::
                     BoundaryEventDispatchTracksNodeRemovalEnabled()) {
        target = NonDeletedElementTarget(target, pointer_event);
      }

      // Dispatch the click event if applicable, when the flag is enabled.
      if (consider_click_dispatch &&
          RuntimeEnabledFeatures::ClickToCapturedPointerEnabled()) {
        ProcessPendingPointerCapture(pointer_event);
        mouse_event_manager_->DispatchMouseClickIfNeeded(
            mouse_target, captured_click_target, mouse_event,
            pointer_event->pointerId(), pointer_event->pointerType());
        // TODO(https://crbug.com/40851596): The following call to
        // `ProcessCaptureAndPositionOfPointerEvent()` does not see any pending
        // capture.  Clean this up after the flag is enabled.
      }

      ProcessCaptureAndPositionOfPointerEvent(pointer_event, target,
                                              &mouse_event);
    } else {
      // Don't send boundary events in this case as it is a little tricky.
      // This case happens for the drag operation and currently we don't
      // let the page know that the pointer left the page while dragging.
      ProcessPendingPointerCapture(pointer_event);
    }

    if (pointer_event->isPrimary()) {
      prevent_mouse_event_for_pointer_type_[ToPointerTypeIndex(
          mouse_event.pointer_type)] = false;
    }
  }

  if (mouse_event.GetType() == WebInputEvent::Type::kMouseLeave &&
      mouse_event.pointer_type == WebPointerProperties::PointerType::kPen) {
    pointer_event_factory_.Remove(pointer_event->pointerId());
  }
  return result;
}

bool PointerEventManager::GetPointerCaptureState(
    PointerId pointer_id,
    Element** pointer_capture_target,
    Element** pending_pointer_capture_target) {
  DCHECK(pointer_capture_target);
  DCHECK(pending_pointer_capture_target);

  PointerCapturingMap::const_iterator it;

  it = pointer_capture_target_.find(pointer_id);
  Element* pointer_capture_target_temp =
      (it != pointer_capture_target_.end()) ? it->value : nullptr;
  it = pending_pointer_capture_target_.find(pointer_id);
  Element* pending_pointercapture_target_temp =
      (it != pending_pointer_capture_target_.end()) ? it->value : nullptr;

  *pointer_capture_target = pointer_capture_target_temp;
  *pending_pointer_capture_target = pending_pointercapture_target_temp;

  return pointer_capture_target_temp != pending_pointercapture_target_temp;
}

Element* PointerEventManager::ProcessCaptureAndPositionOfPointerEvent(
    PointerEvent* pointer_event,
    Element* hit_test_target,
    const WebMouseEvent* mouse_event) {
  ProcessPendingPointerCapture(pointer_event);

  Element* effective_target = GetEffectiveTargetForPointerEvent(
      hit_test_target, pointer_event->pointerId());

  SetElementUnderPointer(pointer_event, effective_target);
  if (mouse_event) {
    mouse_event_manager_->SetElementUnderMouse(effective_target, *mouse_event);
  }
  return effective_target;
}

void PointerEventManager::ProcessPendingPointerCapture(
    PointerEvent* pointer_event) {
  Element* pointer_capture_target = nullptr;
  Element* pending_pointer_capture_target = nullptr;

  const PointerId pointer_id = pointer_event->pointerId();
  const bool is_capture_changed = GetPointerCaptureState(
      pointer_id, &pointer_capture_target, &pending_pointer_capture_target);

  if (!is_capture_changed)
    return;

  // We have to check whether the pointerCaptureTarget is null or not because
  // we are checking whether it is still connected to its document or not.
  if (pointer_capture_target) {
    // Re-target lostpointercapture to the document when the element is
    // no longer participating in the tree.
    EventTarget* target = pointer_capture_target;
    if (!pointer_capture_target->isConnected()) {
      target = pointer_capture_target->ownerDocument();
    }
    pointer_capture_target_.erase(pointer_id);
    DispatchPointerEvent(
        target, pointer_event_factory_.CreatePointerCaptureEvent(
                    pointer_event, event_type_names::kLostpointercapture));
  }

  if (pending_pointer_capture_target &&
      pending_pointer_capture_target->isConnected()) {
    SetElementUnderPointer(pointer_event, pending_pointer_capture_target);
    DispatchPointerEvent(
        pending_pointer_capture_target,
        pointer_event_factory_.CreatePointerCaptureEvent(
            pointer_event, event_type_names::kGotpointercapture));
    if (pending_pointer_capture_target->isConnected()) {
      pointer_capture_target_.Set(pointer_id, pending_pointer_capture_target);
    } else {
      // As a result of dispatching gotpointercapture the capture node was
      // removed.
      DispatchPointerEvent(
          pending_pointer_capture_target->ownerDocument(),
          pointer_event_factory_.CreatePointerCaptureEvent(
              pointer_event, event_type_names::kLostpointercapture));
    }
  }
}

void PointerEventManager::RemoveTargetFromPointerCapturingMapping(
    PointerCapturingMap& map,
    const Element* target) {
  // We could have kept a reverse mapping to make this deletion possibly
  // faster but it adds some code complication which might not be worth of
  // the performance improvement considering there might not be a lot of
  // active pointer or pointer captures at the same time.
  PointerCapturingMap tmp = map;
  for (PointerCapturingMap::iterator it = tmp.begin(); it != tmp.end(); ++it) {
    if (it->value == target)
      map.erase(it->key);
  }
}

void PointerEventManager::RemovePointer(PointerEvent* pointer_event) {
  PointerId pointer_id = pointer_event->pointerId();
  if (pointer_event_factory_.Remove(pointer_id)) {
    pending_pointer_capture_target_.erase(pointer_id);
    pointer_capture_target_.erase(pointer_id);
    element_under_pointer_.erase(pointer_id);
    original_element_under_pointer_removed_.erase(pointer_id);
  }
}

void PointerEventManager::ElementRemoved(Element* target) {
  RemoveTargetFromPointerCapturingMapping(pending_pointer_capture_target_,
                                          target);
}

bool PointerEventManager::SetPointerCapture(PointerId pointer_id,
                                            Element* target,
                                            bool explicit_capture) {
  if (explicit_capture) {
    UseCounter::Count(frame_->GetDocument(),
                      WebFeature::kPointerEventSetCapture);
  }
  if (pointer_event_factory_.IsActiveButtonsState(pointer_id)) {
    if (pointer_id != dispatching_pointer_id_) {
      UseCounter::Count(frame_->GetDocument(),
                        WebFeature::kPointerEventSetCaptureOutsideDispatch);
    }
    pending_pointer_capture_target_.Set(pointer_id, target);
    return true;
  }
  return false;
}

bool PointerEventManager::ReleasePointerCapture(PointerId pointer_id,
                                                Element* target) {
  // Only the element that is going to get the next pointer event can release
  // the capture. Note that this might be different from
  // |m_pointercaptureTarget|. |m_pointercaptureTarget| holds the element
  // that had the capture until now and has been receiving the pointerevents
  // but |m_pendingPointerCaptureTarget| indicated the element that gets the
  // very next pointer event. They will be the same if there was no change in
  // capturing of a particular |pointerId|. See crbug.com/614481.
  if (HasPointerCapture(pointer_id, target)) {
    ReleasePointerCapture(pointer_id);
    return true;
  }
  return false;
}

void PointerEventManager::ReleaseMousePointerCapture() {
  ReleasePointerCapture(PointerEventFactory::kMouseId);
}

bool PointerEventManager::HasPointerCapture(PointerId pointer_id,
                                            const Element* target) const {
  const auto it = pending_pointer_capture_target_.find(pointer_id);
  return it != pending_pointer_capture_target_.end() && it->value == target;
}

void PointerEventManager::ReleasePointerCapture(PointerId pointer_id) {
  pending_pointer_capture_target_.erase(pointer_id);
}

Element* PointerEventManager::GetMouseCaptureTarget() {
  if (pending_pointer_capture_target_.Contains(PointerEventFactory::kMouseId))
    return pending_pointer_capture_target_.at(PointerEventFactory::kMouseId);
  return nullptr;
}

bool PointerEventManager::IsActive(const PointerId pointer_id) const {
  return pointer_event_factory_.IsActive(pointer_id);
}

// This function checks the type of the pointer event to be touch as touch
// pointer events are the only ones that are directly dispatched from the main
// page managers to their target (event if target is in an iframe) and only
// those managers will keep track of these pointer events.
bool PointerEventManager::IsPointerIdActiveOnFrame(PointerId pointer_id,
                                                   LocalFrame* frame) const {
  Element* last_element_receiving_event =
      element_under_pointer_.Contains(pointer_id)
          ? element_under_pointer_.at(pointer_id)
          : nullptr;
  return last_element_receiving_event &&
         last_element_receiving_event->GetDocument().GetFrame() == frame;
}

bool PointerEventManager::IsAnyTouchActive() const {
  // TODO(mustaq@chromium.org): Rely on PEF's states instead of TEM's.
  return touch_event_manager_->IsAnyTouchActive();
}

bool PointerEventManager::PrimaryPointerdownCanceled(
    uint32_t unique_touch_event_id) {
  // It's safe to assume that uniqueTouchEventIds won't wrap back to 0 from
  // 2^32-1 (>4.2 billion): even with a generous 100 unique ids per touch
  // sequence & one sequence per 10 second, it takes 13+ years to wrap back.
  while (!touch_ids_for_canceled_pointerdowns_.empty()) {
    uint32_t first_id = touch_ids_for_canceled_pointerdowns_.front();
    if (first_id > unique_touch_event_id)
      return false;
    touch_ids_for_canceled_pointerdowns_.TakeFirst();
    if (first_id == unique_touch_event_id)
      return true;
  }
  return false;
}

void PointerEventManager::SetLastPointerPositionForFrameBoundary(
    const WebPointerEvent& web_pointer_event,
    Element* new_target) {
  PointerId pointer_id =
      pointer_event_factory_.GetPointerEventId(web_pointer_event);
  Element* last_target = element_under_pointer_.Contains(pointer_id)
                             ? element_under_pointer_.at(pointer_id)
                             : nullptr;
  if (!new_target) {
    pointer_event_factory_.RemoveLastPosition(pointer_id);
  } else if (!last_target || new_target->GetDocument().GetFrame() !=
                                 last_target->GetDocument().GetFrame()) {
    pointer_event_factory_.SetLastPosition(pointer_id,
                                           web_pointer_event.PositionInScreen(),
                                           web_pointer_event.GetType());
  }
}

void PointerEventManager::RemoveLastMousePosition() {
  pointer_event_factory_.RemoveLastPosition(PointerEventFactory::kMouseId);
}

PointerId PointerEventManager::GetPointerIdForTouchGesture(
    const uint32_t unique_touch_event_id) {
  return pointer_event_factory_.GetPointerIdForTouchGesture(
      unique_touch_event_id);
}

Element* PointerEventManager::CurrentTouchDownElement() {
  return touch_event_manager_->CurrentTouchDownElement();
}

}  // namespace blink

"""


```