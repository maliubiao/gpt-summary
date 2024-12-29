Response:
The user wants to understand the functionality of the provided C++ code snippet from `blink/renderer/core/input/event_handler.cc`. This snippet seems to be responsible for handling mouse events and cursor changes.

Here's a breakdown of the thought process to answer the user's request:

1. **Identify the core functionality:** The code primarily deals with determining the appropriate cursor to display based on the context (e.g., resizing, text selection, waiting) and handling different mouse events (press, move, release, drag-and-drop).

2. **Analyze the `SelectCursor` function:** This function is a big `switch` statement that maps `ECursor` enum values to `ui::Cursor` objects. This clearly relates to CSS's `cursor` property.

3. **Analyze the `SelectAutoCursor` function:** This function decides whether to show an I-beam cursor, which is relevant for text input and editing, linking it to HTML's `<input>` and `<textarea>` elements.

4. **Examine the mouse event handlers:** The code has functions like `HandleMousePressEvent`, `HandleMouseMoveEvent`, `HandleMouseReleaseEvent`, `HandleMouseLeaveEvent`, and `UpdateDragAndDrop`. These correspond directly to JavaScript's mouse event listeners (`mousedown`, `mousemove`, `mouseup`, `mouseleave`, `dragenter`, `dragover`, `dragleave`, `drop`).

5. **Connect to HTML, CSS, and JavaScript:**
    * **HTML:** Mouse events happen on HTML elements. Drag-and-drop interacts with draggable attributes. The I-beam cursor is used for text input elements.
    * **CSS:** The `cursor` property in CSS allows developers to specify the cursor appearance. The `SelectCursor` function directly implements this.
    * **JavaScript:** JavaScript event listeners are used to react to mouse events. This code is the underlying implementation that triggers those events.

6. **Consider logical reasoning with input and output:**
    * **Input:** A specific `ECursor` value (e.g., `kResize`).
    * **Output:** The corresponding `ui::Cursor` object (e.g., a resize arrow).
    * **Input:** A mouse press event on a text input field.
    * **Output:** The `SelectAutoCursor` function might return an I-beam cursor.

7. **Think about common user/programming errors:**
    * **CSS `cursor` property errors:**  Using an invalid or misspelled cursor value in CSS will likely fall back to the default, but this code handles the mapping.
    * **JavaScript event listener errors:**  Incorrectly attaching or handling mouse event listeners in JavaScript might lead to unexpected behavior, but the underlying event dispatch mechanism in this code should still function correctly.

8. **Trace user interaction:**  Think about how user actions lead to these functions being called. A mouse movement triggers `HandleMouseMoveEvent`, a click triggers `HandleMousePressEvent` and `HandleMouseReleaseEvent`, dragging triggers `UpdateDragAndDrop`.

9. **Focus on the specific code snippet:** The provided code focuses heavily on cursor selection and the initial stages of handling mouse events (identifying targets, basic setup). It doesn't contain the full event dispatch logic but prepares the ground for it.

10. **Summarize the functionality:**  Combine the observations into a concise description of the code's purpose.

11. **Review and refine:** Ensure the explanation is clear, accurate, and addresses all parts of the user's request. Double-check the connections to HTML, CSS, and JavaScript with concrete examples.
这是 `blink/renderer/core/input/event_handler.cc` 文件的一部分，主要负责处理鼠标相关的事件和光标的显示。 基于提供的代码片段，我们可以归纳出以下功能：

**主要功能:**

* **光标选择 (Cursor Selection):**  根据不同的 `ECursor` 枚举值，返回对应的 `ui::Cursor` 对象。这直接控制了鼠标指针在网页上的外观。
* **自动光标选择 (Auto Cursor Selection):**  根据 `HitTestResult` 和目标节点 `Node` 的类型，决定是否显示文本输入的光标（I-beam）。

**与 Javascript, HTML, CSS 的关系:**

* **CSS:**
    * **功能关联:** CSS 的 `cursor` 属性允许开发者设置鼠标指针的样式。这段代码是浏览器引擎实现 CSS `cursor` 属性的基础。
    * **举例说明:**
        * 当 CSS 中设置 `cursor: pointer;` 时，浏览器会调用相应的逻辑，最终会映射到 `ECursor::kDefault`，这段代码会返回 `PointerCursor()`，从而显示一个手指形状的光标。
        * 当 CSS 中设置 `cursor: resize-nw-se;` 时，会映射到 `ECursor::kNwseResize`，这段代码会返回 `NorthWestSouthEastResizeCursor()`，显示一个西北到东南方向的双箭头，用于调整元素大小。
        * 当鼠标悬停在可编辑的文本区域（如 `<input>` 或 `<textarea>`）上时，`SelectAutoCursor` 函数会识别到这种情况，并返回 `i_beam`（文本输入光标）。

* **HTML:**
    * **功能关联:**  HTML 元素的不同状态和属性会影响光标的显示。例如，链接元素通常显示手指光标，可拖拽元素可能显示移动光标。
    * **举例说明:**
        * 当鼠标悬停在一个 `<a>` 标签上时，通常会显示手指光标。这是因为该元素的默认样式或者 CSS 样式设置了 `cursor: pointer;`，最终会通过 `SelectCursor` 函数进行处理。
        * 当鼠标悬停在一个设置了 `draggable="true"` 属性的元素上时，浏览器可能会根据平台默认行为显示一个移动相关的光标。

* **Javascript:**
    * **功能关联:** Javascript 可以动态地修改元素的 `cursor` 样式，从而改变鼠标指针的外观。这段代码是浏览器响应 Javascript 操作的基础。
    * **举例说明:**
        * Javascript 代码 `element.style.cursor = 'wait';` 会将元素的鼠标指针设置为等待状态的沙漏或转圈图标。这会映射到 `ECursor::kWait`，这段代码会返回 `WaitCursor()`。
        * Javascript 可以监听鼠标事件，并根据事件发生的位置和目标元素，动态地改变光标样式。例如，在一个自定义的滑块组件中，Javascript 可能会在鼠标按下时设置特定的拖拽光标。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  `ECursor::kText`
* **输出:** `i_beam` (文本输入光标的 `ui::Cursor` 对象)

* **假设输入:**  鼠标移动到一个设置了 `cursor: zoom-in;` 样式的元素上。
* **输出:** `SelectCursor` 函数根据 `ECursor::kZoomIn` 返回 `ZoomInCursor()`，浏览器会显示放大镜带加号的光标。

**用户或编程常见的使用错误:**

* **CSS `cursor` 属性拼写错误:**  如果 CSS 中 `cursor` 属性的值拼写错误（例如 `curson: pointer;`），浏览器将无法识别，通常会使用默认光标。这段代码负责解析已知的 `ECursor` 值，对于未知的输入，它会返回默认光标 (`PointerCursor()`)。
* **Javascript 设置了无效的 `cursor` 值:** 如果 Javascript 代码尝试设置一个浏览器不支持的 `cursor` 值，行为类似于 CSS 拼写错误，浏览器会回退到默认光标。

**用户操作是如何一步步到达这里 (调试线索):**

1. **用户移动鼠标:** 当用户移动鼠标时，操作系统会捕获到这个事件。
2. **操作系统通知浏览器:** 操作系统将鼠标移动事件传递给浏览器进程。
3. **浏览器进程传递给渲染进程:** 浏览器进程将事件转发给负责页面渲染的渲染进程。
4. **渲染进程的事件处理:**  渲染进程中的某个模块（通常是输入处理相关的模块）接收到鼠标移动事件。
5. **命中测试 (Hit Testing):** 渲染引擎会进行命中测试，确定鼠标指针当前位于哪个 HTML 元素之上。
6. **触发光标更新:** 根据命中测试的结果以及元素的样式（包括 CSS 的 `cursor` 属性），渲染引擎需要更新鼠标指针的显示。
7. **调用 `EventHandler::SelectCursor` 或 `EventHandler::SelectAutoCursor`:**  根据情况，会调用这两个函数之一来获取正确的 `ui::Cursor` 对象。
8. **设置系统光标:** 渲染引擎将获取到的 `ui::Cursor` 对象转换为操作系统能够理解的光标句柄，并设置系统的鼠标指针。

**功能归纳 (第2部分):**

这段代码片段主要负责 **根据当前上下文 (例如，鼠标悬停的元素、元素的 CSS 样式) 确定并返回要显示的鼠标光标样式**。 它是浏览器引擎中处理鼠标外观显示的核心部分，直接关联到 CSS 的 `cursor` 属性以及 HTML 元素的一些默认光标行为。  它确保用户在与网页交互时，鼠标指针能够提供直观的反馈，例如指示链接的可点击性、元素的可拖拽性、文本的可编辑性等等。

Prompt: 
```
这是目录为blink/renderer/core/input/event_handler.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能

"""
ursor::kNResize:
      return NorthResizeCursor();
    case ECursor::kSResize:
      return SouthResizeCursor();
    case ECursor::kNeResize:
      return NorthEastResizeCursor();
    case ECursor::kSwResize:
      return SouthWestResizeCursor();
    case ECursor::kNwResize:
      return NorthWestResizeCursor();
    case ECursor::kSeResize:
      return SouthEastResizeCursor();
    case ECursor::kNsResize:
      return NorthSouthResizeCursor();
    case ECursor::kEwResize:
      return EastWestResizeCursor();
    case ECursor::kNeswResize:
      return NorthEastSouthWestResizeCursor();
    case ECursor::kNwseResize:
      return NorthWestSouthEastResizeCursor();
    case ECursor::kColResize:
      return ColumnResizeCursor();
    case ECursor::kRowResize:
      return RowResizeCursor();
    case ECursor::kText:
      return i_beam;
    case ECursor::kWait:
      return WaitCursor();
    case ECursor::kHelp:
      return HelpCursor();
    case ECursor::kVerticalText:
      return VerticalTextCursor();
    case ECursor::kCell:
      return CellCursor();
    case ECursor::kContextMenu:
      return ContextMenuCursor();
    case ECursor::kProgress:
      return ProgressCursor();
    case ECursor::kNoDrop:
      return NoDropCursor();
    case ECursor::kAlias:
      return AliasCursor();
    case ECursor::kCopy:
      return CopyCursor();
    case ECursor::kNone:
      return NoneCursor();
    case ECursor::kNotAllowed:
      return NotAllowedCursor();
    case ECursor::kDefault:
      return PointerCursor();
    case ECursor::kZoomIn:
      return ZoomInCursor();
    case ECursor::kZoomOut:
      return ZoomOutCursor();
    case ECursor::kGrab:
      return GrabCursor();
    case ECursor::kGrabbing:
      return GrabbingCursor();
  }
  return PointerCursor();
}

std::optional<ui::Cursor> EventHandler::SelectAutoCursor(
    const HitTestResult& result,
    Node* node,
    const ui::Cursor& i_beam) {
  if (ShouldShowIBeamForNode(node, result))
    return i_beam;

  return PointerCursor();
}

WebInputEventResult EventHandler::DispatchBufferedTouchEvents() {
  return pointer_event_manager_->FlushEvents();
}

WebInputEventResult EventHandler::HandlePointerEvent(
    const WebPointerEvent& web_pointer_event,
    const Vector<WebPointerEvent>& coalesced_events,
    const Vector<WebPointerEvent>& predicted_events) {
  return pointer_event_manager_->HandlePointerEvent(
      web_pointer_event, coalesced_events, predicted_events);
}

WebInputEventResult EventHandler::HandleMousePressEvent(
    const WebMouseEvent& mouse_event) {
  TRACE_EVENT0("blink", "EventHandler::handleMousePressEvent");

  // For 4th/5th button in the mouse since Chrome does not yet send
  // button value to Blink but in some cases it does send the event.
  // This check is needed to suppress such an event (crbug.com/574959)
  if (mouse_event.button == WebPointerProperties::Button::kNoButton)
    return WebInputEventResult::kHandledSuppressed;

  capturing_mouse_events_element_ = nullptr;
  mouse_event_manager_->HandleMousePressEventUpdateStates(mouse_event);
  if (!frame_->View())
    return WebInputEventResult::kNotHandled;

  HitTestRequest request(HitTestRequest::kActive);
  // Save the document point we generate in case the window coordinate is
  // invalidated by what happens when we dispatch the event.
  PhysicalOffset document_point = frame_->View()->ConvertFromRootFrame(
      PhysicalOffset(gfx::ToFlooredPoint(mouse_event.PositionInRootFrame())));
  MouseEventWithHitTestResults mev = GetMouseEventTarget(request, mouse_event);
  if (!mev.InnerNode()) {
    // An anonymous box can be scrollable.
    if (PassMousePressEventToScrollbar(mev))
      return WebInputEventResult::kHandledSystem;

    mouse_event_manager_->InvalidateClick();
    return WebInputEventResult::kNotHandled;
  }

  mouse_event_manager_->SetMousePressNode(mev.InnerNode());
  frame_->GetDocument()->SetSequentialFocusNavigationStartingPoint(
      mev.InnerNode());

  LocalFrame* subframe = event_handling_util::GetTargetSubframe(mev);
  if (subframe) {
    WebInputEventResult result = PassMousePressEventToSubframe(mev, subframe);
    if (mouse_event_manager_->MousePressed()) {
      capturing_mouse_events_element_ = mev.InnerElement();
      capturing_subframe_element_ = mev.InnerElement();
    }

    mouse_event_manager_->InvalidateClick();
    return result;
  }

  if (discarded_events_.mouse_down_target != kInvalidDOMNodeId &&
      discarded_events_.mouse_down_target == mev.InnerNode()->GetDomNodeId() &&
      mouse_event.TimeStamp() - discarded_events_.mouse_down_time <
          event_handling_util::kDiscardedEventMistakeInterval) {
    mev.InnerNode()->GetDocument().CountUse(
        WebFeature::kInputEventToRecentlyMovedIframeMistakenlyDiscarded);
  }
  if (event_handling_util::ShouldDiscardEventTargetingFrame(mev.Event(),
                                                            *frame_)) {
    discarded_events_.mouse_down_target = mev.InnerNode()->GetDomNodeId();
    discarded_events_.mouse_down_time = mouse_event.TimeStamp();
    return WebInputEventResult::kHandledSuppressed;
  } else {
    discarded_events_.mouse_down_target = kInvalidDOMNodeId;
    discarded_events_.mouse_down_time = base::TimeTicks();
  }

  LocalFrame::NotifyUserActivation(
      frame_, mojom::blink::UserActivationNotificationType::kInteraction,
      RuntimeEnabledFeatures::BrowserVerifiedUserActivationMouseEnabled());

  if (RuntimeEnabledFeatures::MiddleClickAutoscrollEnabled()) {
    // We store whether middle click autoscroll is in progress before calling
    // stopAutoscroll() because it will set m_autoscrollType to NoAutoscroll on
    // return.
    bool is_middle_click_autoscroll_in_progress =
        scroll_manager_->MiddleClickAutoscrollInProgress();
    scroll_manager_->StopMiddleClickAutoscroll();
    if (is_middle_click_autoscroll_in_progress) {
      // We invalidate the click when exiting middle click auto scroll so that
      // we don't inadvertently navigate away from the current page (e.g. the
      // click was on a hyperlink). See <rdar://problem/6095023>.
      mouse_event_manager_->InvalidateClick();
      return WebInputEventResult::kHandledSuppressed;
    }
  }

  mouse_event_manager_->SetClickCount(mouse_event.click_count);
  mouse_event_manager_->SetMouseDownElement(mev.InnerElement());

  if (!mouse_event.FromTouch())
    frame_->Selection().SetCaretBlinkingSuspended(true);

  WebInputEventResult event_result = DispatchMousePointerEvent(
      WebInputEvent::Type::kPointerDown, mev.InnerElement(), mev.Event(),
      Vector<WebMouseEvent>(), Vector<WebMouseEvent>());

  // Disabled form controls still need to resize the scrollable area.
  if ((event_result == WebInputEventResult::kNotHandled ||
       event_result == WebInputEventResult::kHandledSuppressed) &&
      frame_->View()) {
    LocalFrameView* view = frame_->View();
    PaintLayer* layer =
        mev.InnerNode()->GetLayoutObject()
            ? mev.InnerNode()->GetLayoutObject()->EnclosingLayer()
            : nullptr;
    gfx::Point p = view->ConvertFromRootFrame(
        gfx::ToFlooredPoint(mouse_event.PositionInRootFrame()));
    if (layer && layer->GetScrollableArea() &&
        layer->GetScrollableArea()->IsAbsolutePointInResizeControl(
            p, kResizerForPointer)) {
      scroll_manager_->SetResizeScrollableArea(layer, p);
      return WebInputEventResult::kHandledSystem;
    }
  }

  // m_selectionInitiationState is initialized after dispatching mousedown
  // event in order not to keep the selection by DOM APIs because we can't
  // give the user the chance to handle the selection by user action like
  // dragging if we keep the selection in case of mousedown. FireFox also has
  // the same behavior and it's more compatible with other browsers.
  GetSelectionController().InitializeSelectionState();

  HitTestResult hit_test_result = event_handling_util::HitTestResultInFrame(
      frame_, HitTestLocation(document_point), HitTestRequest::kReadOnly);
  InputDeviceCapabilities* source_capabilities =
      frame_->DomWindow()->GetInputDeviceCapabilities()->FiresTouchEvents(
          mouse_event.FromTouch());

  if (event_result == WebInputEventResult::kNotHandled) {
    event_result = mouse_event_manager_->HandleMouseFocus(hit_test_result,
                                                          source_capabilities);
  }

  if (event_result == WebInputEventResult::kNotHandled || mev.GetScrollbar()) {
    // Outermost main frames don't implicitly capture mouse input on MouseDown,
    // all subframes do (regardless of whether local or remote or fenced).
    if (frame_->IsAttached() && !frame_->IsOutermostMainFrame())
      CaptureMouseEventsToWidget(true);
  }

  if (PassMousePressEventToScrollbar(mev))
    event_result = WebInputEventResult::kHandledSystem;

  if (event_result == WebInputEventResult::kNotHandled) {
    if (ShouldRefetchEventTarget(mev)) {
      HitTestRequest read_only_request(HitTestRequest::kReadOnly |
                                       HitTestRequest::kActive);
      mev = frame_->GetDocument()->PerformMouseEventHitTest(
          read_only_request, document_point, mouse_event);
    }
    event_result = mouse_event_manager_->HandleMousePressEvent(mev);
  }

  if (mev.GetHitTestResult().InnerNode() &&
      mouse_event.button == WebPointerProperties::Button::kLeft) {
    DCHECK_EQ(WebInputEvent::Type::kMouseDown, mouse_event.GetType());
    HitTestResult result = mev.GetHitTestResult();
    result.SetToShadowHostIfInUAShadowRoot();
    frame_->GetChromeClient().OnMouseDown(*result.InnerNode());
  }

  return event_result;
}

WebInputEventResult EventHandler::HandleMouseMoveEvent(
    const WebMouseEvent& event,
    const Vector<WebMouseEvent>& coalesced_events,
    const Vector<WebMouseEvent>& predicted_events) {
  TRACE_EVENT0("blink", "EventHandler::handleMouseMoveEvent");
  DCHECK(event.GetType() == WebInputEvent::Type::kMouseMove);
  HitTestResult hovered_node_result;
  HitTestLocation location;
  WebInputEventResult result =
      HandleMouseMoveOrLeaveEvent(event, coalesced_events, predicted_events,
                                  &hovered_node_result, &location);

  Page* page = frame_->GetPage();
  if (!page)
    return result;

  if (PaintLayer* layer =
          event_handling_util::LayerForNode(hovered_node_result.InnerNode())) {
    if (ScrollableArea* layer_scrollable_area =
            event_handling_util::AssociatedScrollableArea(layer))
      layer_scrollable_area->MouseMovedInContentArea();
  }

  // Should not convert the hit shadow element to its shadow host, so that
  // tooltips in the shadow tree appear correctly.
  if (!HasTitleAndNotSVGUseElement(hovered_node_result)) {
    hovered_node_result.SetToShadowHostIfInUAShadowRoot();
  }
  page->GetChromeClient().MouseDidMoveOverElement(*frame_, location,
                                                  hovered_node_result);

  return result;
}

void EventHandler::HandleMouseLeaveEvent(const WebMouseEvent& event) {
  TRACE_EVENT0("blink", "EventHandler::handleMouseLeaveEvent");
  DCHECK(event.GetType() == WebInputEvent::Type::kMouseLeave);

  Page* page = frame_->GetPage();
  if (page)
    page->GetChromeClient().ClearToolTip(*frame_);

  WebLinkPreviewTriggerer* triggerer =
      frame_->GetOrCreateLinkPreviewTriggerer();
  if (triggerer) {
    triggerer->MaybeChangedKeyEventModifier(WebInputEvent::kNoModifiers);
  }

  HandleMouseMoveOrLeaveEvent(event, Vector<WebMouseEvent>(),
                              Vector<WebMouseEvent>());
  pointer_event_manager_->RemoveLastMousePosition();
}

WebInputEventResult EventHandler::HandleMouseMoveOrLeaveEvent(
    const WebMouseEvent& mouse_event,
    const Vector<WebMouseEvent>& coalesced_events,
    const Vector<WebMouseEvent>& predicted_events,
    HitTestResult* hovered_node_result,
    HitTestLocation* hit_test_location) {
  DCHECK(frame_);
  DCHECK(frame_->View());
  DCHECK(mouse_event.GetType() == WebInputEvent::Type::kMouseMove ||
         mouse_event.GetType() == WebInputEvent::Type::kMouseLeave);
  mouse_event_manager_->SetLastKnownMousePosition(mouse_event);

  hover_timer_.Stop();
  cursor_update_timer_.Stop();

  mouse_event_manager_->HandleSvgPanIfNeeded(false);

  if (mouse_event.GetType() == WebInputEvent::Type::kMouseMove) {
    AnchorElementInteractionTracker* tracker =
        frame_->GetDocument()->GetAnchorElementInteractionTracker();
    if (tracker) {
      tracker->OnMouseMoveEvent(mouse_event);
    }
  }

  // Mouse states need to be reset when mouse move with no button down.
  // This is for popup/context_menu opened at mouse_down event and
  // mouse_release is not handled in page.
  // crbug.com/527582
  if (mouse_event.button == WebPointerProperties::Button::kNoButton &&
      !(mouse_event.GetModifiers() &
        WebInputEvent::Modifiers::kRelativeMotionEvent)) {
    mouse_event_manager_->ClearDragHeuristicState();
    capturing_mouse_events_element_ = nullptr;
    ReleaseMouseCaptureFromLocalRoot();

    // If the scrollbar still thinks it's being dragged, tell it to stop.
    // Can happen on Win if we lose focus (e.g. from Alt-Tab) mid-drag.
    if (last_scrollbar_under_mouse_ &&
        last_scrollbar_under_mouse_->PressedPart() != ScrollbarPart::kNoPart)
      last_scrollbar_under_mouse_->MouseUp(mouse_event);
  }

  if (RuntimeEnabledFeatures::MiddleClickAutoscrollEnabled()) {
    if (Page* page = frame_->GetPage()) {
      page->GetAutoscrollController().HandleMouseMoveForMiddleClickAutoscroll(
          frame_, mouse_event_manager_->LastKnownMouseScreenPosition(),
          mouse_event.button == WebPointerProperties::Button::kMiddle);
    }
  }

  if (frame_set_being_resized_) {
    return DispatchMousePointerEvent(
        WebInputEvent::Type::kPointerMove, frame_set_being_resized_.Get(),
        mouse_event, coalesced_events, predicted_events);
  }

  // Send events right to a scrollbar if the mouse is pressed.
  if (last_scrollbar_under_mouse_ && mouse_event_manager_->MousePressed()) {
    last_scrollbar_under_mouse_->MouseMoved(mouse_event);
    return WebInputEventResult::kHandledSystem;
  }

  // TODO(crbug.com/1519197): This crash key is set during the hit test if a
  // scroll corner is hit. It will be reported in the DumpWithoutCrashing that
  // occurs from GetComputedStyleFromScrollbar via the SelectCursor call below.
  // Clear it here to ensure we're using the value from this hit test if we do
  // end up calling DumpWithoutCrashing.
  base::debug::ClearCrashKeyString(CrashKeyForBug1519197());
  HitTestRequest::HitTestRequestType hit_type = HitTestRequest::kMove;
  if (mouse_event_manager_->MousePressed()) {
    hit_type |= HitTestRequest::kActive;
  }

  // Treat any mouse move events as readonly if the user is currently touching
  // the screen.
  if (pointer_event_manager_->IsAnyTouchActive() &&
      mouse_event.GetType() == WebInputEvent::Type::kMouseMove) {
    hit_type |= HitTestRequest::kActive | HitTestRequest::kReadOnly;
  }
  HitTestRequest request(hit_type);
  HitTestLocation out_location((PhysicalOffset()));
  MouseEventWithHitTestResults mev = MouseEventWithHitTestResults(
      mouse_event, out_location, HitTestResult(request, out_location));

  // We don't want to do a hit-test in MouseLeave scenarios because there
  // might actually be some other frame above this one at the specified
  // coordinate. So we avoid the hit test but still clear the hover/active
  // state.
  if (mouse_event.GetType() == WebInputEvent::Type::kMouseLeave) {
    frame_->GetDocument()->UpdateHoverActiveState(request.Active(),
                                                  /*update_active_chain=*/false,
                                                  nullptr);
  } else {
    mev = GetMouseEventTarget(request, mouse_event);
  }

  if (hovered_node_result)
    *hovered_node_result = mev.GetHitTestResult();

  if (hit_test_location)
    *hit_test_location = mev.GetHitTestLocation();

  Scrollbar* scrollbar = nullptr;

  if (scroll_manager_->InResizeMode()) {
    scroll_manager_->Resize(mev.Event());
  } else {
    scrollbar = mev.GetScrollbar();

    UpdateLastScrollbarUnderMouse(scrollbar,
                                  !mouse_event_manager_->MousePressed());
  }

  WebInputEventResult event_result = WebInputEventResult::kNotHandled;
  bool is_remote_frame = false;
  LocalFrame* current_subframe =
      event_handling_util::GetTargetSubframe(mev, &is_remote_frame);

  // We want mouseouts to happen first, from the inside out.  First send a
  // move event to the last subframe so that it will fire mouseouts.
  // TODO(lanwei): figure out here if we should call HandleMouseLeaveEvent on a
  // mouse move event.
  if (last_mouse_move_event_subframe_ &&
      last_mouse_move_event_subframe_->Tree().IsDescendantOf(frame_) &&
      last_mouse_move_event_subframe_ != current_subframe) {
    WebMouseEvent event = mev.Event();
    event.SetType(WebInputEvent::Type::kMouseLeave);
    last_mouse_move_event_subframe_->GetEventHandler().HandleMouseLeaveEvent(
        event);
    last_mouse_move_event_subframe_->GetEventHandler()
        .mouse_event_manager_->SetLastMousePositionAsUnknown();
  }

  if (current_subframe) {
    // Update over/out state before passing the event to the subframe.
    pointer_event_manager_->SendMouseAndPointerBoundaryEvents(
        EffectiveMouseEventTargetElement(mev.InnerElement()), mev.Event());

    // Event dispatch in sendMouseAndPointerBoundaryEvents may have caused the
    // subframe of the target node to be detached from its LocalFrameView, in
    // which case the event should not be passed.
    if (current_subframe->View()) {
      event_result =
          PassMouseMoveEventToSubframe(mev, coalesced_events, predicted_events,
                                       current_subframe, hovered_node_result);
    }
  } else {
    if (scrollbar && !mouse_event_manager_->MousePressed()) {
      // Handle hover effects on platforms that support visual feedback on
      // scrollbar hovering.
      scrollbar->MouseMoved(mev.Event());
    }

    // Set Effective pan action before Pointer cursor is updated.
    const WebPointerEvent web_pointer_event(WebInputEvent::Type::kPointerMove,
                                            mev.Event().FlattenTransform());
    pointer_event_manager_->SendEffectivePanActionAtPointer(web_pointer_event,
                                                            mev.InnerNode());

    LocalFrameView* view = frame_->View();
    if (!is_remote_frame && view) {
      std::optional<ui::Cursor> optional_cursor =
          SelectCursor(mev.GetHitTestLocation(), mev.GetHitTestResult());
      if (optional_cursor.has_value()) {
        view->SetCursor(optional_cursor.value());
      }
    }
  }

  base::debug::ClearCrashKeyString(CrashKeyForBug1519197());
  last_mouse_move_event_subframe_ = current_subframe;

  if (event_result != WebInputEventResult::kNotHandled) {
    return event_result;
  }

  event_result = DispatchMousePointerEvent(WebInputEvent::Type::kPointerMove,
                                           mev.InnerElement(), mev.Event(),
                                           coalesced_events, predicted_events);
  // Since there is no default action for the mousemove event, MouseEventManager
  // handles drag for text selection even when js cancels the mouse move event.
  // https://w3c.github.io/uievents/#event-type-mousemove
  if (event_result == WebInputEventResult::kNotHandled ||
      event_result == WebInputEventResult::kHandledApplication) {
    event_result = mouse_event_manager_->HandleMouseDraggedEvent(mev);
  }

  return event_result;
}

WebInputEventResult EventHandler::HandleMouseReleaseEvent(
    const WebMouseEvent& mouse_event) {
  TRACE_EVENT0("blink", "EventHandler::handleMouseReleaseEvent");

  // For 4th/5th button in the mouse since Chrome does not yet send
  // button value to Blink but in some cases it does send the event.
  // This check is needed to suppress such an event (crbug.com/574959)
  if (mouse_event.button == WebPointerProperties::Button::kNoButton)
    return WebInputEventResult::kHandledSuppressed;

  if (!mouse_event.FromTouch())
    frame_->Selection().SetCaretBlinkingSuspended(false);

  if (RuntimeEnabledFeatures::MiddleClickAutoscrollEnabled()) {
    if (Page* page = frame_->GetPage()) {
      page->GetAutoscrollController()
          .HandleMouseReleaseForMiddleClickAutoscroll(
              frame_,
              mouse_event.button == WebPointerProperties::Button::kMiddle);
    }
  }

  mouse_event_manager_->ReleaseMousePress();
  mouse_event_manager_->SetLastKnownMousePosition(mouse_event);
  mouse_event_manager_->HandleSvgPanIfNeeded(true);

  if (frame_set_being_resized_) {
    WebInputEventResult result =
        mouse_event_manager_->SetElementUnderMouseAndDispatchMouseEvent(
            EffectiveMouseEventTargetElement(frame_set_being_resized_.Get()),
            event_type_names::kMouseup, mouse_event);
    // crbug.com/1053385 release mouse capture only if there are no more mouse
    // buttons depressed
    if (MouseEvent::WebInputEventModifiersToButtons(
            mouse_event.GetModifiers()) == 0)
      ReleaseMouseCaptureFromLocalRoot();
    return result;
  }

  if (last_scrollbar_under_mouse_) {
    mouse_event_manager_->InvalidateClick();
    last_scrollbar_under_mouse_->MouseUp(mouse_event);
    // crbug.com/1053385 release mouse capture only if there are no more mouse
    // buttons depressed
    if (MouseEvent::WebInputEventModifiersToButtons(
            mouse_event.GetModifiers()) == 0) {
      ReleaseMouseCaptureFromLocalRoot();
    }
    return DispatchMousePointerEvent(
        WebInputEvent::Type::kPointerUp,
        mouse_event_manager_->GetElementUnderMouse(), mouse_event,
        Vector<WebMouseEvent>(), Vector<WebMouseEvent>());
  }

  // Mouse events simulated from touch should not hit-test again.
  DCHECK(!mouse_event.FromTouch());
  HitTestRequest::HitTestRequestType hit_type = HitTestRequest::kRelease;
  HitTestRequest request(hit_type);
  MouseEventWithHitTestResults mev = GetMouseEventTarget(request, mouse_event);
  LocalFrame* subframe = event_handling_util::GetTargetSubframe(mev);
  capturing_mouse_events_element_ = nullptr;
  if (subframe)
    return PassMouseReleaseEventToSubframe(mev, subframe);

  WebInputEventResult event_result = WebInputEventResult::kNotHandled;

  if (event_handling_util::ShouldDiscardEventTargetingFrame(mev.Event(),
                                                            *frame_)) {
    event_result = WebInputEventResult::kHandledSuppressed;
  } else {
    event_result = DispatchMousePointerEvent(
        WebInputEvent::Type::kPointerUp, mev.InnerElement(), mev.Event(),
        Vector<WebMouseEvent>(), Vector<WebMouseEvent>(),
        (GetSelectionController().HasExtendedSelection() &&
         IsSelectionOverLink(mev)));
  }
  scroll_manager_->ClearResizeScrollableArea(false);

  if (event_result == WebInputEventResult::kNotHandled)
    event_result = mouse_event_manager_->HandleMouseReleaseEvent(mev);

  mouse_event_manager_->HandleMouseReleaseEventUpdateStates();

  // crbug.com/1053385 release mouse capture only if there are no more mouse
  // buttons depressed
  if (MouseEvent::WebInputEventModifiersToButtons(mouse_event.GetModifiers()) ==
      0)
    ReleaseMouseCaptureFromLocalRoot();

  return event_result;
}

static LocalFrame* LocalFrameFromTargetNode(Node* target) {
  auto* html_frame_base_element = DynamicTo<HTMLFrameElementBase>(target);
  if (!html_frame_base_element)
    return nullptr;

  // Cross-process drag and drop is not yet supported.
  return DynamicTo<LocalFrame>(html_frame_base_element->ContentFrame());
}

WebInputEventResult EventHandler::UpdateDragAndDrop(
    const WebMouseEvent& event,
    DataTransfer* data_transfer) {
  WebInputEventResult event_result = WebInputEventResult::kNotHandled;

  if (!frame_->View())
    return event_result;

  HitTestRequest request(HitTestRequest::kReadOnly);
  MouseEventWithHitTestResults mev =
      event_handling_util::PerformMouseEventHitTest(frame_, request, event);

  // Drag events should never go to text nodes (following IE, and proper
  // mouseover/out dispatch)
  Node* new_target = mev.InnerElement();

  if (AutoscrollController* controller =
          scroll_manager_->GetAutoscrollController()) {
    controller->UpdateDragAndDrop(new_target, event.PositionInRootFrame(),
                                  event.TimeStamp());
  }

  if (drag_target_ != new_target) {
    // FIXME: this ordering was explicitly chosen to match WinIE. However,
    // it is sometimes incorrect when dragging within subframes, as seen with
    // web_tests/fast/events/drag-in-frames.html.
    //
    // Moreover, this ordering conforms to section 7.9.4 of the HTML 5 spec.
    // <http://dev.w3.org/html5/spec/Overview.html#drag-and-drop-processing-model>.
    if (auto* target_frame = LocalFrameFromTargetNode(new_target)) {
      event_result = target_frame->GetEventHandler().UpdateDragAndDrop(
          event, data_transfer);
    } else if (new_target) {
      // As per section 7.9.4 of the HTML 5 spec., we must always fire a drag
      // event before firing a dragenter, dragleave, or dragover event.
      if (mouse_event_manager_->GetDragState().drag_src_) {
        // For now we don't care if event handler cancels default behavior,
        // since there is none.
        mouse_event_manager_->DispatchDragSrcEvent(event_type_names::kDrag,
                                                   event);
      }
      event_result = mouse_event_manager_->DispatchDragEvent(
          event_type_names::kDragenter, new_target, drag_target_, event,
          data_transfer);
    }

    if (auto* target_frame = LocalFrameFromTargetNode(drag_target_.Get())) {
      event_result = target_frame->GetEventHandler().UpdateDragAndDrop(
          event, data_transfer);
    } else if (drag_target_) {
      mouse_event_manager_->DispatchDragEvent(event_type_names::kDragleave,
                                              drag_target_.Get(), new_target,
                                              event, data_transfer);
    }

    if (new_target) {
      // We do not explicitly call m_mouseEventManager->dispatchDragEvent here
      // because it could ultimately result in the appearance that two dragover
      // events fired. So, we mark that we should only fire a dragover event on
      // the next call to this function.
      should_only_fire_drag_over_event_ = true;
    }
  } else {
    if (auto* target_frame = LocalFrameFromTargetNode(new_target)) {
      event_result = target_frame->GetEventHandler().UpdateDragAndDrop(
          event, data_transfer);
    } else if (new_target) {
      // Note, when dealing with sub-frames, we may need to fire only a dragover
      // event as a drag event may have been fired earlier.
      if (!should_only_fire_drag_over_event_ &&
          mouse_event_manager_->GetDragState().drag_src_) {
        // For now we don't care if event handler cancels default behavior,
        // since there is none.
        mouse_event_manager_->DispatchDragSrcEvent(event_type_names::kDrag,
                                                   event);
      }
      event_result = mouse_event_manager_->DispatchDragEvent(
          event_type_names::kDragover, new_target, nullptr, event,
          data_transfer);
      should_only_fire_drag_over_event_ = false;
    }
  }
  drag_target_ = new_target;

  return event_result;
}

void EventHandler::CancelDragAndDrop(const WebMouseEvent& event,
                                     DataTransfer* data_transfer) {
  if (auto* target_frame = LocalFrameFromTargetNode(drag_target_.Get())) {
    target_frame->GetEventHandler().CancelDragAndDrop(event, data_transfer);
  } else if (drag_target_.Get()) {
    if (mouse_event_manager_->GetDragState().drag_src_) {
      mouse_event_manager_->DispatchDragSrcEvent(event_type_names::kDrag,
                                                 event);
    }
    mouse_event_manager_->DispatchDragEvent(event_type_names::kDragleave,
                                            drag_target_.Get(), nullptr, event,
                                            data_transfer);
  }
  ClearDragState();
}

WebInputEventResult EventHandler::PerformDragAndDrop(
    const WebMouseEvent& event,
    DataTransfer* data_transfer) {
  WebInputEventResult result = WebInputEventResult::kNotHandled;
  if (auto* target_frame = LocalFrameFromTargetNode(drag_target_.Get())) {
    result = target_frame->GetEventHandler().PerformDragAndDrop(event,
                                                                data_transfer);
  } else if (drag_target_.Get()) {
    result = mouse_event_manager_->DispatchDragEvent(
        event_type_names::kDrop, drag_target_.Get(), nullptr, event,
        data_transfer);
  }
  ClearDragState();
  return result;
}

void EventHandler::ClearDragState() {
  scroll_manager_->StopAutoscroll();
  drag_target_ = nullptr;
  capturing_mouse_events_element_ = nullptr;
  ReleaseMouseCaptureFromLocalRoot();
  should_only_fire_drag_over_event_ = false;
}

void EventHandler::RecomputeMouseHoverStateIfNeeded() {
  mouse_event_manager_->RecomputeMouseHoverStateIfNeeded();
}

void EventHandler::MarkHoverStateDirty() {
  mouse_event_manager_->MarkHoverStateDirty();
}

Element* EventHandler::EffectiveMouseEventTargetElement(
    Element* target_element) {
  Element* new_element_under_mouse = target_element;
  if (pointer_event_manager_->GetMouseCaptureTarget())
    new_element_under_mouse = pointer_event_manager_->GetMouseCaptureTarget();
  return new_element_under_mouse;
}

void EventHandler::OnScrollbarDestroyed(const Scrollbar& scrollbar) {
  if (last_scrollbar_under_mouse_ == &scrollbar) {
    last_scrollbar_under_mouse_ = nullptr;
  }
}

Element* EventHandler::GetElementUnderMouse() {
  return mouse_event_manager_->GetElementUnderMouse();
}

Element* EventHandler::CurrentTouchDownElement() {
  return pointer_event_manager_->CurrentTouchDownElement();
}

void EventHandler::SetDelayedNavigationTaskHandle(TaskHandle task_handle) {
  delayed_navigation_task_handle_ = std::move(task_handle);
}

TaskHandle& EventHandler::GetDelayedNavigationTaskHandle() {
  return delayed_navigation_task_handle_;
}

bool EventHandler::IsPointerIdActiveOnFrame(PointerId pointer_id,
                                            LocalFrame* frame) const {
  DCHECK(frame_ == &frame_->LocalFrameRoot() || frame_ == frame);
  return pointer_event_manager_->IsPointerIdActiveOnFrame(pointer_id, frame);
}

bool EventHandler::RootFrameTrackedActivePointerInCurrentFrame(
    PointerId pointer_id) const {
  return frame_ != &frame_->LocalFrameRoot() &&
         frame_->LocalFrameRoot().GetEventHandler().IsPointerIdActiveOnFrame(
             pointer_id, frame_);
}

bool EventHandler::IsPointerEventActive(PointerId pointer_id) {
  return pointer_event_manager_->IsActive(pointer_id) ||
         RootFrameTrackedActivePointerInCurrentFrame(pointer_id);
}

LocalFrame* EventHandler::DetermineActivePointerTrackerFrame(
    PointerId pointer_id) const {
  // If pointer_id is active on current |frame_|, pointer states are in
  // current frame's PEM; otherwise, check if it's a touch-like pointer that
  // have its active states in the local frame root's PEM.
  if (IsPointerIdActiveOnFrame(pointer_id, frame_))
    return frame_.Get();
  if (RootFrameTrackedActivePointerInCurrentFrame(pointer_id))
    return &frame_->LocalFrameRoot();
  return nullptr;
}

void EventHandler::SetPointerCapture(PointerId pointer_id,
                                     Element* target,
                                     bool explicit_capture) {
  // TODO(crbug.com/591387): This functionality should be per page not per
  // frame.
  LocalFrame* tracking_frame = DetermineActivePointerTrackerFrame(pointer_id);

  bool captured =
      tracking_frame && tracking_frame->GetEventHandler()
                            .pointer_event_manager_->SetPointerCapture(
                                pointer_id, target, explicit_capture);

  if (captured && pointer_id == PointerEventFactory::kMouseId) {
    CaptureMouseEventsToWidget(true);
  }
}

void EventHandler::ReleasePointerCapture(PointerId pointer_id,
                                         Element* target) {
  LocalFrame* tracking_frame = DetermineActivePointerTrackerFrame(pointer_id);

  bool released =
      tracking_frame &&
      tracking_frame->GetEventHandler()
          .pointer_event_manager_->ReleasePointerCapture(pointer_id, target);

  if (released && pointer_id == PointerEventFactory::kMouseId) {
    CaptureMouseEventsToWidget(false);
  }
}

void EventHandler::ReleaseMousePoin
"""


```