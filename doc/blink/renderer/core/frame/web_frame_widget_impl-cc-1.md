Response:
The user wants a summary of the functionalities of the provided C++ code snippet from Chromium's Blink rendering engine. I need to analyze the code and identify its main responsibilities. Specifically, I should look for interactions with JavaScript, HTML, and CSS, provide examples if any are found, identify logical reasoning with input/output examples, point out potential usage errors, and finally summarize the overall functionality as part 2 of a 7-part series.

Here's a breakdown of the code's functionality:

1. **Stylus Writing Gesture Handling:**  It receives and applies stylus writing gestures to focused elements.
2. **Background Color Control:** It can set the background to be opaque or transparent.
3. **Text Direction Setting:** It allows setting the text direction of the focused frame.
4. **Touch Action Inheritance:**  For subframes, it manages the inheritance of effective touch actions.
5. **Render Throttling for Subframes:** It updates the rendering throttling status for subframes.
6. **String Retrieval at a Point (macOS specific):** On macOS, it can retrieve an attributed string at a given point.
7. **Mojo Binding for Compositor:** It binds a Mojo receiver for the widget compositor.
8. **Mojo Binding for Input Target Client:** It binds a Mojo receiver for the input target client.
9. **Frame Sink ID Retrieval:** It can determine the FrameSinkId at a given point.
10. **Coordinate Space Conversions:** It provides utility functions to convert between DIPs (Device Independent Pixels) and Blink's internal coordinate space.
11. **Widget Activation:** It sets the active state of the widget.
12. **Key Event Handling:** It processes key events, including handling for popups, access keys, and context menus.
13. **Mouse Down Event Handling:** It handles mouse down events, including logic for closing popups and capturing mouse input for plugins.
14. **Mouse Leave Event Handling:** It handles mouse leave events.
15. **Context Menu Handling:** It manages the display of context menus.
16. **Mouse Up Event Handling:** It processes mouse up events.
17. **Gesture Event Handling:** It handles various gesture events, including taps, double-taps, long presses, and tap cancels, with specific logic for popups and link highlighting.
18. **Mouse Wheel Event Handling:** It processes mouse wheel events, including closing popups.
19. **Character Input Event Handling:** It manages character input events, taking into account access keys and system key presses.
20. **Drag and Drop Management:** It handles drag and drop operations, including starting drags and processing drag enter/over events.
21. **Overscroll Event Handling:** It sends overscroll events from the compositor thread.
22. **Scroll End Event Handling:** It sends scroll end events from the compositor thread.
23. **Scroll Snap Event Handling:** It manages scroll snap changing events.
24. **Compositor Scroll State Updates:** It updates the internal scroll state based on compositor data.
25. **Viewport Screenshot Requests:** It can request a screenshot of the viewport.
26. **Local Surface ID Requests:** It can request a new local surface ID.
27. **Active Input Method Controller Retrieval:** It gets the currently active input method controller.
28. **Disabling Drag and Drop:** It provides a way to disable drag and drop functionality.
29. **Coordinate Space Conversion (Viewport to Root Frame):**  It converts viewport coordinates to root frame coordinates.
30. **Access to Underlying Objects:** It provides access to `WebViewImpl`, `Page`, and the associated `FrameWidgetHost`.
31. **Image Decode Requests:** It can request the decoding of images.
32. **Tracing:**  It supports tracing for debugging and performance analysis.
33. **Raster Scale Recalculation:** It can trigger a recalculation of raster scales.
34. **Background Color Setting (Compositor):** It sets the background color on the compositor.
35. **Overscroll Behavior Setting (Compositor):** It sets the overscroll behavior on the compositor.
36. **Reduced Motion Preference Setting (Compositor):** It sets the preference for reduced motion on the compositor.
37. **Page Scale Animation:** It initiates page scale animations.
38. **Main Frame Begin Expectation:** It signals whether a main frame begin is expected.
```cpp
void WebFrameWidgetImpl::writingGestureResultCallback(
    mojom::blink::HandwritingGestureResult result) {
  std::move(pending_writing_gesture_callback_).Run(result);
}

void WebFrameWidgetImpl::HandleStylusWritingGesture(
    mojom::blink::StylusWritingGestureDataPtr gesture_data,
    HandleStylusWritingGestureCallback callback) {
  LocalFrame* focused_frame = FocusedLocalFrameInWidget();
  if (!focused_frame) {
    std::move(callback).Run(
        mojom::blink::HandwritingGestureResult::kNoFocusedFrame);
    return;
  }
  if (!gesture_data || gesture_data->strokes.empty()) {
    std::move(callback).Run(
        mojom::blink::HandwritingGestureResult::kFailed);
    return;
  }
  mojom::blink::HandwritingGestureResult result =
      StylusWritingGesture::ApplyGesture(focused_frame,
                                         std::move(gesture_data));
  std::move(callback).Run(result);
}

void WebFrameWidgetImpl::SetBackgroundOpaque(bool opaque) {
  View()->SetBaseBackgroundColorOverrideTransparent(!opaque);
}

void WebFrameWidgetImpl::SetTextDirection(base::i18n::TextDirection direction) {
  LocalFrame* focusedFrame = FocusedLocalFrameInWidget();
  if (focusedFrame)
    focusedFrame->SetTextDirection(direction);
}

void WebFrameWidgetImpl::SetInheritedEffectiveTouchActionForSubFrame(
    TouchAction touch_action) {
  DCHECK(ForSubframe());
  LocalRootImpl()->GetFrame()->SetInheritedEffectiveTouchAction(touch_action);
}

void WebFrameWidgetImpl::UpdateRenderThrottlingStatusForSubFrame(
    bool is_throttled,
    bool subtree_throttled,
    bool display_locked) {
  DCHECK(ForSubframe());
  // TODO(szager,vmpstr): The parent render process currently rolls up
  // display_locked into the value of subtree throttled here; display_locked
  // should be maintained as a separate bit and transmitted between render
  // processes.
  LocalRootImpl()->GetFrameView()->UpdateRenderThrottlingStatus(
      is_throttled, subtree_throttled, display_locked, /*recurse=*/true);
}

#if BUILDFLAG(IS_MAC)
void WebFrameWidgetImpl::GetStringAtPoint(const gfx::Point& point_in_local_root,
                                          GetStringAtPointCallback callback) {
  gfx::Point baseline_point;
  ui::mojom::blink::AttributedStringPtr attributed_string = nullptr;
  base::apple::ScopedCFTypeRef<CFAttributedStringRef> string =
      SubstringUtil::AttributedWordAtPoint(this, point_in_local_root,
                                           baseline_point);
  if (string) {
    attributed_string = ui::mojom::blink::AttributedString::From(string.get());
  }

  std::move(callback).Run(std::move(attributed_string), baseline_point);
}
#endif

void WebFrameWidgetImpl::BindWidgetCompositor(
    mojo::PendingReceiver<mojom::blink::WidgetCompositor> receiver) {
  widget_base_->BindWidgetCompositor(std::move(receiver));
}

void WebFrameWidgetImpl::BindInputTargetClient(
    mojo::PendingReceiver<viz::mojom::blink::InputTargetClient> receiver) {
  DCHECK(!input_target_receiver_.is_bound());
  input_target_receiver_.Bind(
      std::move(receiver),
      local_root_->GetTaskRunner(TaskType::kInternalInputBlocking));
}

void WebFrameWidgetImpl::FrameSinkIdAt(const gfx::PointF& point,
                                       const uint64_t trace_id,
                                       FrameSinkIdAtCallback callback) {
  TRACE_EVENT_WITH_FLOW1("viz,benchmark", "Event.Pipeline",
                         TRACE_ID_GLOBAL(trace_id),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT,
                         "step", "FrameSinkIdAt");

  gfx::PointF local_point;
  viz::FrameSinkId id = GetFrameSinkIdAtPoint(point, &local_point);
  std::move(callback).Run(id, local_point);
}

viz::FrameSinkId WebFrameWidgetImpl::GetFrameSinkIdAtPoint(
    const gfx::PointF& point_in_dips,
    gfx::PointF* local_point_in_dips) {
  HitTestResult result =
      CoreHitTestResultAt(widget_base_->DIPsToBlinkSpace(point_in_dips));

  Node* result_node = result.InnerNode();
  *local_point_in_dips = gfx::PointF(point_in_dips);

  // TODO(crbug.com/797828): When the node is null the caller may
  // need to do extra checks. Like maybe update the layout and then
  // call the hit-testing API. Either way it might be better to have
  // a DCHECK for the node rather than a null check here.
  if (!result_node) {
    return frame_sink_id_;
  }

  viz::FrameSinkId remote_frame_sink_id = GetRemoteFrameSinkId(result);
  if (remote_frame_sink_id.is_valid()) {
    gfx::PointF local_point(result.LocalPoint());
    LayoutObject* object = result_node->GetLayoutObject();
    if (auto* box = DynamicTo<LayoutBox>(object))
      local_point -= gfx::Vector2dF(box->PhysicalContentBoxOffset());

    *local_point_in_dips = widget_base_->BlinkSpaceToDIPs(local_point);
    return remote_frame_sink_id;
  }

  // Return the FrameSinkId for the current widget if the point did not hit
  // test to a remote frame, or the point is outside of the remote frame's
  // content box, or the remote frame doesn't have a valid FrameSinkId yet.
  return frame_sink_id_;
}

gfx::RectF WebFrameWidgetImpl::BlinkSpaceToDIPs(const gfx::RectF& rect) {
  return widget_base_->BlinkSpaceToDIPs(rect);
}

gfx::Rect WebFrameWidgetImpl::BlinkSpaceToEnclosedDIPs(const gfx::Rect& rect) {
  return widget_base_->BlinkSpaceToEnclosedDIPs(rect);
}

gfx::Size WebFrameWidgetImpl::BlinkSpaceToFlooredDIPs(const gfx::Size& size) {
  return widget_base_->BlinkSpaceToFlooredDIPs(size);
}

gfx::RectF WebFrameWidgetImpl::DIPsToBlinkSpace(const gfx::RectF& rect) {
  return widget_base_->DIPsToBlinkSpace(rect);
}

gfx::PointF WebFrameWidgetImpl::DIPsToBlinkSpace(const gfx::PointF& point) {
  return widget_base_->DIPsToBlinkSpace(point);
}

gfx::Point WebFrameWidgetImpl::DIPsToRoundedBlinkSpace(
    const gfx::Point& point) {
  return widget_base_->DIPsToRoundedBlinkSpace(point);
}

float WebFrameWidgetImpl::DIPsToBlinkSpace(float scalar) {
  return widget_base_->DIPsToBlinkSpace(scalar);
}

gfx::Size WebFrameWidgetImpl::DIPsToCeiledBlinkSpace(const gfx::Size& size) {
  return widget_base_->DIPsToCeiledBlinkSpace(size);
}

void WebFrameWidgetImpl::SetActive(bool active) {
  View()->SetIsActive(active);
}

WebInputEventResult WebFrameWidgetImpl::HandleKeyEvent(
    const WebKeyboardEvent& event) {
  DCHECK((event.GetType() == WebInputEvent::Type::kRawKeyDown) ||
         (event.GetType() == WebInputEvent::Type::kKeyDown) ||
         (event.GetType() == WebInputEvent::Type::kKeyUp));

  // Please refer to the comments explaining the m_suppressNextKeypressEvent
  // member.
  // The m_suppressNextKeypressEvent is set if the KeyDown is handled by
  // Webkit. A keyDown event is typically associated with a keyPress(char)
  // event and a keyUp event. We reset this flag here as this is a new keyDown
  // event.
  suppress_next_keypress_event_ = false;

  // If there is a popup open, it should be the one processing the event,
  // not the page.
  scoped_refptr<WebPagePopupImpl> page_popup = View()->GetPagePopup();
  if (page_popup) {
    page_popup->HandleKeyEvent(event);
    if (event.GetType() == WebInputEvent::Type::kRawKeyDown) {
      suppress_next_keypress_event_ = true;
    }
    return WebInputEventResult::kHandledSystem;
  }

  auto* frame = DynamicTo<LocalFrame>(FocusedCoreFrame());
  if (!frame)
    return WebInputEventResult::kNotHandled;

  WebInputEventResult result = frame->GetEventHandler().KeyEvent(event);
  // EventHandler may have detached the frame.
  if (!LocalRootImpl())
    return result;

  if (result != WebInputEventResult::kNotHandled) {
    if (WebInputEvent::Type::kRawKeyDown == event.GetType()) {
      // Suppress the next keypress event unless the focused node is a plugin
      // node. (Flash needs these keypress events to handle non-US keyboards.)
      Element* element = FocusedElement();
      if (element && element->GetLayoutObject() &&
          element->GetLayoutObject()->IsEmbeddedObject()) {
        if (event.windows_key_code == VKEY_TAB) {
          // If the plugin supports keyboard focus then we should not send a tab
          // keypress event.
          WebPluginContainerImpl* plugin_view =
              To<LayoutEmbeddedContent>(element->GetLayoutObject())->Plugin();
          if (plugin_view && plugin_view->SupportsKeyboardFocus()) {
            suppress_next_keypress_event_ = true;
          }
        }
      } else {
        suppress_next_keypress_event_ = true;
      }
    }
    return result;
  }

#if !BUILDFLAG(IS_MAC)
  const WebInputEvent::Type kContextMenuKeyTriggeringEventType =
#if BUILDFLAG(IS_WIN)
      WebInputEvent::Type::kKeyUp;
#else
      WebInputEvent::Type::kRawKeyDown;
#endif
  const WebInputEvent::Type kShiftF10TriggeringEventType =
      WebInputEvent::Type::kRawKeyDown;

  bool is_unmodified_menu_key =
      !(event.GetModifiers() & WebInputEvent::kInputModifiers) &&
      event.windows_key_code == VKEY_APPS;
  bool is_shift_f10 = (event.GetModifiers() & WebInputEvent::kInputModifiers) ==
                          WebInputEvent::kShiftKey &&
                      event.windows_key_code == VKEY_F10;
  if ((is_unmodified_menu_key &&
       event.GetType() == kContextMenuKeyTriggeringEventType) ||
      (is_shift_f10 && event.GetType() == kShiftF10TriggeringEventType)) {
    View()->SendContextMenuEvent();
    return WebInputEventResult::kHandledSystem;
  }
#endif  // !BUILDFLAG(IS_MAC)

  return WebInputEventResult::kNotHandled;
}

void WebFrameWidgetImpl::HandleMouseDown(LocalFrame& local_root,
                                         const WebMouseEvent& event) {
  WebViewImpl* view_impl = View();
  // If there is a popup open, close it as the user is clicking on the page
  // (outside of the popup). We also save it so we can prevent a click on an
  // element from immediately reopening the same popup.
  scoped_refptr<WebPagePopupImpl> page_popup;
  if (event.button == WebMouseEvent::Button::kLeft) {
    page_popup = view_impl->GetPagePopup();
    view_impl->CancelPagePopup();
  }

  // Take capture on a mouse down on a plugin so we can send it mouse events.
  // If the hit node is a plugin but a scrollbar is over it don't start mouse
  // capture because it will interfere with the scrollbar receiving events.
  PhysicalOffset point(LayoutUnit(event.PositionInWidget().x()),
                       LayoutUnit(event.PositionInWidget().y()));
  if (event.button == WebMouseEvent::Button::kLeft) {
    HitTestLocation location(
        LocalRootImpl()->GetFrameView()->ConvertFromRootFrame(point));
    HitTestResult result(
        LocalRootImpl()->GetFrame()->GetEventHandler().HitTestResultAtLocation(
            location));
    result.SetToShadowHostIfInUAShadowRoot();
    Node* hit_node = result.InnerNode();
    auto* html_element = DynamicTo<HTMLElement>(hit_node);
    if (!result.GetScrollbar() && hit_node && hit_node->GetLayoutObject() &&
        hit_node->GetLayoutObject()->IsEmbeddedObject() && html_element &&
        html_element->IsPluginElement()) {
      mouse_capture_element_ = To<HTMLPlugInElement>(hit_node);
      SetMouseCapture(true);
      TRACE_EVENT_NESTABLE_ASYNC_BEGIN0("input", "capturing mouse",
                                        TRACE_ID_LOCAL(this));
    }
  }

  WidgetEventHandler::HandleMouseDown(local_root, event);
  // WidgetEventHandler may have detached the frame.
  if (!LocalRootImpl())
    return;

  if (view_impl->GetPagePopup() && page_popup &&
      view_impl->GetPagePopup()->HasSamePopupClient(page_popup.get())) {
    // That click triggered a page popup that is the same as the one we just
    // closed. It needs to be closed.
    view_impl->CancelPagePopup();
  }

  // Dispatch the contextmenu event regardless of if the click was swallowed.
  if (!GetPage()->GetSettings().GetShowContextMenuOnMouseUp()) {
#if BUILDFLAG(IS_MAC)
    if (event.button == WebMouseEvent::Button::kRight ||
        (event.button == WebMouseEvent::Button::kLeft &&
         event.GetModifiers() & WebMouseEvent::kControlKey))
      MouseContextMenu(event);
#else
    if (event.button == WebMouseEvent::Button::kRight)
      MouseContextMenu(event);
#endif
  }
}

void WebFrameWidgetImpl::HandleMouseLeave(LocalFrame& local_root,
                                          const WebMouseEvent& event) {
  View()->SetMouseOverURL(WebURL());
  WidgetEventHandler::HandleMouseLeave(local_root, event);
  // WidgetEventHandler may have detached the frame.
}

void WebFrameWidgetImpl::MouseContextMenu(const WebMouseEvent& event) {
  GetPage()->GetContextMenuController().ClearContextMenu();

  WebMouseEvent transformed_event =
      TransformWebMouseEvent(LocalRootImpl()->GetFrameView(), event);
  transformed_event.menu_source_type = kMenuSourceMouse;
  transformed_event.id = PointerEventFactory::kMouseId;

  // Find the right target frame. See issue 1186900.
  HitTestResult result =
      HitTestResultForRootFramePos(transformed_event.PositionInRootFrame());
  Frame* target_frame;
  if (result.InnerNodeOrImageMapImage())
    target_frame = result.InnerNodeOrImageMapImage()->GetDocument().GetFrame();
  else
    target_frame = GetPage()->GetFocusController().FocusedOrMainFrame();

  // This will need to be changed to a nullptr check when focus control
  // is refactored, at which point focusedOrMainFrame will never return a
  // RemoteFrame.
  // See https://crbug.com/341918.
  LocalFrame* target_local_frame = DynamicTo<LocalFrame>(target_frame);
  if (!target_local_frame)
    return;

  {
    ContextMenuAllowedScope scope;
    target_local_frame->GetEventHandler().SendContextMenuEvent(
        transformed_event);
  }
  // Actually showing the context menu is handled by the ContextMenuClient
  // implementation...
}

WebInputEventResult WebFrameWidgetImpl::HandleMouseUp(
    LocalFrame& local_root,
    const WebMouseEvent& event) {
  WebInputEventResult result =
      WidgetEventHandler::HandleMouseUp(local_root, event);
  // WidgetEventHandler may have detached the frame.
  if (!LocalRootImpl())
    return result;

  if (GetPage()->GetSettings().GetShowContextMenuOnMouseUp()) {
    // Dispatch the contextmenu event regardless of if the click was swallowed.
    // On Mac/Linux, we handle it on mouse down, not up.
    if (event.button == WebMouseEvent::Button::kRight)
      MouseContextMenu(event);
  }
  return result;
}

WebInputEventResult WebFrameWidgetImpl::HandleGestureEvent(
    const WebGestureEvent& event) {
  WebInputEventResult event_result = WebInputEventResult::kNotHandled;

  // Fling and scroll events are not sent to the renderer main thread.
  CHECK(!event.IsScrollEvent());

  WebViewImpl* web_view = View();

  LocalFrame* frame = LocalRootImpl()->GetFrame();
  WebGestureEvent scaled_event = TransformWebGestureEvent(frame->View(), event);

  // Special handling for double tap and scroll events as we don't want to
  // hit test for them.
  switch (event.GetType()) {
    case WebInputEvent::Type::kGestureDoubleTap:
      if (web_view->SettingsImpl()->DoubleTapToZoomEnabled() &&
          web_view->MinimumPageScaleFactor() !=
              web_view->MaximumPageScaleFactor()) {
        gfx::Point pos_in_local_frame_root =
            gfx::ToFlooredPoint(scaled_event.PositionInRootFrame());
        auto block_bounds = ComputeBlockBound(pos_in_local_frame_root, false);

        if (ForMainFrame()) {
          web_view->AnimateDoubleTapZoom(pos_in_local_frame_root, block_bounds);
        } else {
          // This sends the tap point and bounds to the main frame renderer via
          // the browser, where their coordinates will be transformed into the
          // main frame's coordinate space.
          GetAssociatedFrameWidgetHost()->AnimateDoubleTapZoomInMainFrame(
              pos_in_local_frame_root, block_bounds);
        }
      }
      event_result = WebInputEventResult::kHandledSystem;
      DidHandleGestureEvent(event);
      return event_result;
    default:
      break;
  }

  // Hit test across all frames and do touch adjustment as necessary for the
  // event type.
  GestureEventWithHitTestResults targeted_event =
      frame->GetEventHandler().TargetGestureEvent(scaled_event);

  // Link highlight animations are only for the main frame.
  // TODO(bokan): This isn't intentional, see https://crbug.com/1344531.
  if (ForMainFrame()) {
    // Handle link highlighting outside the main switch to avoid getting lost in
    // the complicated set of cases handled below.
    switch (scaled_event.GetType()) {
      case WebInputEvent::Type::kGestureShowPress:
        // Queue a highlight animation, then hand off to regular handler.
        web_view->EnableTapHighlightAtPoint(targeted_event);
        break;
      case WebInputEvent::Type::kGestureShortPress:
      case WebInputEvent::Type::kGestureLongPress:
      case WebInputEvent::Type::kGestureTapCancel:
      case WebInputEvent::Type::kGestureTap:
        GetPage()->GetLinkHighlight().UpdateOpacityAndRequestAnimation();
        break;
      default:
        break;
    }
  }

  switch (scaled_event.GetType()) {
    case WebInputEvent::Type::kGestureTap: {
      {
        ContextMenuAllowedScope scope;
        event_result =
            frame->GetEventHandler().HandleGestureEvent(targeted_event);
      }

      if (web_view->GetPagePopup() && last_hidden_page_popup_ &&
          web_view->GetPagePopup()->HasSamePopupClient(
              last_hidden_page_popup_.get())) {
        // The tap triggered a page popup that is the same as the one we just
        // closed. It needs to be closed.
        web_view->CancelPagePopup();
      }
      // Don't have this value persist outside of a single tap gesture, plus
      // we're done with it now.
      last_hidden_page_popup_ = nullptr;
      break;
    }
    case WebInputEvent::Type::kGestureTwoFingerTap:
    case WebInputEvent::Type::kGestureLongPress:
    case WebInputEvent::Type::kGestureLongTap:
      if (scaled_event.GetType() == WebInputEvent::Type::kGestureLongTap) {
        if (LocalFrame* inner_frame =
                targeted_event.GetHitTestResult().InnerNodeFrame()) {
          if (!inner_frame->GetEventHandler().LongTapShouldInvokeContextMenu())
            break;
        } else if (!frame->GetEventHandler().LongTapShouldInvokeContextMenu()) {
          break;
        }
      }

      GetPage()->GetContextMenuController().ClearContextMenu();
      {
        ContextMenuAllowedScope scope;
        event_result =
            frame->GetEventHandler().HandleGestureEvent(targeted_event);
      }

      break;
    case WebInputEvent::Type::kGestureTapDown:
      // Touch pinch zoom and scroll on the page (outside of a popup) must hide
      // the popup. In case of a touch scroll or pinch zoom, this function is
      // called with GestureTapDown rather than a GSB/GSU/GSE or GPB/GPU/GPE.
      // When we close a popup because of a GestureTapDown, we also save it so
      // we can prevent the following GestureTap from immediately reopening the
      // same popup.
      // This value should not persist outside of a gesture, so is cleared by
      // GestureTap (where it is used) and by GestureCancel.
      last_hidden_page_popup_ = web_view->GetPagePopup();
      web_view->CancelPagePopup();
      event_result =
          frame->GetEventHandler().HandleGestureEvent(targeted_event);
      break;
    case WebInputEvent::Type::kGestureTapCancel:
      // Don't have this value persist outside of a single tap gesture.
      last_hidden_page_popup_ = nullptr;
      event_result =
          frame->GetEventHandler().HandleGestureEvent(targeted_event);
      break;
    case WebInputEvent::Type::kGestureShowPress:
    case WebInputEvent::Type::kGestureTapUnconfirmed:
    case WebInputEvent::Type::kGestureShortPress:
      event_result =
          frame->GetEventHandler().HandleGestureEvent(targeted_event);
      break;
    default:
      NOTREACHED();
  }
  DidHandleGestureEvent(event);
  return event_result;
}

WebInputEventResult WebFrameWidgetImpl::HandleMouseWheel(
    LocalFrame& frame,
    const WebMouseWheelEvent& event) {
  View()->CancelPagePopup();
  return WidgetEventHandler::HandleMouseWheel(frame, event);
  // WidgetEventHandler may have detached the frame.
}

WebInputEventResult WebFrameWidgetImpl::HandleCharEvent(
    const WebKeyboardEvent& event) {
  DCHECK_EQ(event.GetType(), WebInputEvent::Type::kChar);

  // Please refer to the comments explaining the m_suppressNextKeypressEvent
  // member. The m_suppressNextKeypressEvent is set if the KeyDown is
  // handled by Webkit. A keyDown event is typically associated with a
  // keyPress(char) event and a keyUp event. We reset this flag here as it
  // only applies to the current keyPress event.
  bool suppress = suppress_next_keypress_event_;
  suppress_next_keypress_event_ = false;

  // If there is a popup open, it should be the one processing the event,
  // not the page.
  scoped_refptr<WebPagePopupImpl> page_popup = View()->GetPagePopup();
  if (page_popup)
    return page_popup->HandleKeyEvent(event);

  LocalFrame* frame = To<LocalFrame>(FocusedCoreFrame());
  if (!frame) {
    return suppress ? WebInputEventResult::kHandledSuppressed
                    : WebInputEventResult::kNotHandled;
  }

  EventHandler& handler = frame->GetEventHandler();

  if (!event.IsCharacterKey())
    return WebInputEventResult::kHandledSuppressed;

  // Accesskeys are triggered by char events and can't be suppressed.
  // It is unclear whether a keypress should be dispatched as well
  // crbug.com/563507
  if (handler.HandleAccessKey(event))
    return WebInputEventResult::kHandledSystem;

  // Safari 3.1 does not pass off windows system key messages (WM_SYSCHAR) to
  // the eventHandler::keyEvent. We mimic this behavior on all platforms since
  // for now we are converting other platform's key events to windows key
  // events.
  if (event.is_system_key)
    return WebInputEventResult::kNotHandled;

  if (suppress)
    return WebInputEventResult::kHandledSuppressed;

  WebInputEventResult result = handler.KeyEvent(event);
  if (result != WebInputEventResult::kNotHandled)
    return result;

  return WebInputEventResult::kNotHandled;
}

void WebFrameWidgetImpl::CancelDrag() {
  drag_operation_ = DragController::Operation();
  current_drag_data_ = nullptr;
}

void WebFrameWidgetImpl::StartDragging(LocalFrame* source_frame,
                                       const WebDragData& drag_data,
                                       DragOperationsMask operations_allowed,
                                       const SkBitmap& drag_image,
                                       const gfx::Vector2d& cursor_offset,
                                       const gfx::Rect& drag_obj_rect) {
  if (doing_drag_and_drop_) {
    // TODO: crbug.com/330274075 - Root cause nested drag-start events, remove
    // once issue has been resolved.
    base::debug::DumpWithoutCrashing();
  }

  doing_drag_and_drop_ = true;
  if (drag_and_drop_disabled_) {
    DragSourceSystemDragEnded();
    return;
  }

  gfx::Vector2d offset_in_dips =
      widget_base_->BlinkSpaceToFlooredDIPs(gfx::Point() + cursor_offset)
          .OffsetFromOrigin();
  gfx::Rect drag_obj_rect_in_dips =
      gfx::Rect(widget_base_->BlinkSpaceToFlooredDIPs(drag_obj_rect.origin()),
                widget_base_->BlinkSpaceToFlooredDIPs(drag_obj_rect.size()));
  source_frame->GetLocalFrameHostRemote().StartDragging(
      drag_data, operations_allowed, drag_image, offset_in_dips,
      drag_obj_rect_in_dips, possible_drag_event_info_.Clone());
}

void WebFrameWidgetImpl::DragTargetDragEnterOrOver(
    const gfx::PointF& point_in_viewport,
    const gfx::PointF& screen_point,
    DragAction drag_action,
    uint32_t key_modifiers) {
  if (ShouldIgnoreInputEvents() || !current_drag_data_) {
    CancelDrag();
    return;
  }

  gfx::PointF point_in_root_frame = ViewportToRootFrame(point_in_viewport);

  current_drag_data_->SetModifiers(key_modifiers);
  DragData drag_data(current_drag_data_.Get(), point_in_root_frame,
                     screen_point, operations_allowed_,
                     /*force_default_action=*/false);

  drag_operation_ = GetPage()->GetDragController().DragEnteredOrUpdated(
      &drag_data, *local_root_->GetFrame());

  // Mask the drag operation against the drag source's allowed
  // operations.
  if (!(static_cast<int>(drag_operation_.operation) &
        drag_data.DraggingSourceOperationMask())) {
    drag_operation_ = DragController::Operation();
  }
}

void WebFrameWidgetImpl::SendOverscrollEventFromImplSide(
    const gfx::Vector2dF& overscroll_delta,
    cc::ElementId scroll_latched_element_id) {
  if (!RuntimeEnabledFeatures::OverscrollCustomizationEnabled())
    return;

  Node* target_node = View()->FindNodeFromScrollableCompositorElementId(
      scroll_latched_element_id);
  if (target_node) {
    target_node->GetDocument().EnqueueOverscrollEventForNode(
        target_node, overscroll_delta.x(), overscroll_delta.y());
  }
}

void WebFrameWidgetImpl::SendEndOfScrollEventsDeprecated(
    bool affects_outer_viewport,
    bool affects_inner_viewport,
    cc::ElementId scroll_latched_element_id) {
  Node* target_node = View()->FindNodeFromScrollableCompositorElementId(
      scroll_latched_element_id);
  if (!target_node) {
    return;
  }
  if (ScrollableArea* scrollable_area =
          ScrollableArea::GetForScrolling(target_node->GetLayoutBox())) {
    scrollable_area->UpdateSnappedTargetsAndEnqueueScrollSnapChange();
    scrollable_area->SetImplSnapStrategy(nullptr);
  }

  if (auto* viewport_position_tracker =
          AnchorElementViewportPositionTracker::MaybeGetOrCreateFor(
              target_node->GetDocument())) {
    viewport_position_tracker->OnScrollEnd();
  }

  if (RuntimeEnabledFeatures::ScrollEndEventsEnabled()) {
    Node* document_node = View()->MainFrameImpl()
                              ? View()->MainFrameImpl()->GetDocument()
                              
### 提示词
```
这是目录为blink/renderer/core/frame/web_frame_widget_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
writingGestureResult::kFailed);
    return;
  }
  mojom::blink::HandwritingGestureResult result =
      StylusWritingGesture::ApplyGesture(focused_frame,
                                         std::move(gesture_data));
  std::move(callback).Run(result);
}

void WebFrameWidgetImpl::SetBackgroundOpaque(bool opaque) {
  View()->SetBaseBackgroundColorOverrideTransparent(!opaque);
}

void WebFrameWidgetImpl::SetTextDirection(base::i18n::TextDirection direction) {
  LocalFrame* focusedFrame = FocusedLocalFrameInWidget();
  if (focusedFrame)
    focusedFrame->SetTextDirection(direction);
}

void WebFrameWidgetImpl::SetInheritedEffectiveTouchActionForSubFrame(
    TouchAction touch_action) {
  DCHECK(ForSubframe());
  LocalRootImpl()->GetFrame()->SetInheritedEffectiveTouchAction(touch_action);
}

void WebFrameWidgetImpl::UpdateRenderThrottlingStatusForSubFrame(
    bool is_throttled,
    bool subtree_throttled,
    bool display_locked) {
  DCHECK(ForSubframe());
  // TODO(szager,vmpstr): The parent render process currently rolls up
  // display_locked into the value of subtree throttled here; display_locked
  // should be maintained as a separate bit and transmitted between render
  // processes.
  LocalRootImpl()->GetFrameView()->UpdateRenderThrottlingStatus(
      is_throttled, subtree_throttled, display_locked, /*recurse=*/true);
}

#if BUILDFLAG(IS_MAC)
void WebFrameWidgetImpl::GetStringAtPoint(const gfx::Point& point_in_local_root,
                                          GetStringAtPointCallback callback) {
  gfx::Point baseline_point;
  ui::mojom::blink::AttributedStringPtr attributed_string = nullptr;
  base::apple::ScopedCFTypeRef<CFAttributedStringRef> string =
      SubstringUtil::AttributedWordAtPoint(this, point_in_local_root,
                                           baseline_point);
  if (string) {
    attributed_string = ui::mojom::blink::AttributedString::From(string.get());
  }

  std::move(callback).Run(std::move(attributed_string), baseline_point);
}
#endif

void WebFrameWidgetImpl::BindWidgetCompositor(
    mojo::PendingReceiver<mojom::blink::WidgetCompositor> receiver) {
  widget_base_->BindWidgetCompositor(std::move(receiver));
}

void WebFrameWidgetImpl::BindInputTargetClient(
    mojo::PendingReceiver<viz::mojom::blink::InputTargetClient> receiver) {
  DCHECK(!input_target_receiver_.is_bound());
  input_target_receiver_.Bind(
      std::move(receiver),
      local_root_->GetTaskRunner(TaskType::kInternalInputBlocking));
}

void WebFrameWidgetImpl::FrameSinkIdAt(const gfx::PointF& point,
                                       const uint64_t trace_id,
                                       FrameSinkIdAtCallback callback) {
  TRACE_EVENT_WITH_FLOW1("viz,benchmark", "Event.Pipeline",
                         TRACE_ID_GLOBAL(trace_id),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT,
                         "step", "FrameSinkIdAt");

  gfx::PointF local_point;
  viz::FrameSinkId id = GetFrameSinkIdAtPoint(point, &local_point);
  std::move(callback).Run(id, local_point);
}

viz::FrameSinkId WebFrameWidgetImpl::GetFrameSinkIdAtPoint(
    const gfx::PointF& point_in_dips,
    gfx::PointF* local_point_in_dips) {
  HitTestResult result =
      CoreHitTestResultAt(widget_base_->DIPsToBlinkSpace(point_in_dips));

  Node* result_node = result.InnerNode();
  *local_point_in_dips = gfx::PointF(point_in_dips);

  // TODO(crbug.com/797828): When the node is null the caller may
  // need to do extra checks. Like maybe update the layout and then
  // call the hit-testing API. Either way it might be better to have
  // a DCHECK for the node rather than a null check here.
  if (!result_node) {
    return frame_sink_id_;
  }

  viz::FrameSinkId remote_frame_sink_id = GetRemoteFrameSinkId(result);
  if (remote_frame_sink_id.is_valid()) {
    gfx::PointF local_point(result.LocalPoint());
    LayoutObject* object = result_node->GetLayoutObject();
    if (auto* box = DynamicTo<LayoutBox>(object))
      local_point -= gfx::Vector2dF(box->PhysicalContentBoxOffset());

    *local_point_in_dips = widget_base_->BlinkSpaceToDIPs(local_point);
    return remote_frame_sink_id;
  }

  // Return the FrameSinkId for the current widget if the point did not hit
  // test to a remote frame, or the point is outside of the remote frame's
  // content box, or the remote frame doesn't have a valid FrameSinkId yet.
  return frame_sink_id_;
}

gfx::RectF WebFrameWidgetImpl::BlinkSpaceToDIPs(const gfx::RectF& rect) {
  return widget_base_->BlinkSpaceToDIPs(rect);
}

gfx::Rect WebFrameWidgetImpl::BlinkSpaceToEnclosedDIPs(const gfx::Rect& rect) {
  return widget_base_->BlinkSpaceToEnclosedDIPs(rect);
}

gfx::Size WebFrameWidgetImpl::BlinkSpaceToFlooredDIPs(const gfx::Size& size) {
  return widget_base_->BlinkSpaceToFlooredDIPs(size);
}

gfx::RectF WebFrameWidgetImpl::DIPsToBlinkSpace(const gfx::RectF& rect) {
  return widget_base_->DIPsToBlinkSpace(rect);
}

gfx::PointF WebFrameWidgetImpl::DIPsToBlinkSpace(const gfx::PointF& point) {
  return widget_base_->DIPsToBlinkSpace(point);
}

gfx::Point WebFrameWidgetImpl::DIPsToRoundedBlinkSpace(
    const gfx::Point& point) {
  return widget_base_->DIPsToRoundedBlinkSpace(point);
}

float WebFrameWidgetImpl::DIPsToBlinkSpace(float scalar) {
  return widget_base_->DIPsToBlinkSpace(scalar);
}

gfx::Size WebFrameWidgetImpl::DIPsToCeiledBlinkSpace(const gfx::Size& size) {
  return widget_base_->DIPsToCeiledBlinkSpace(size);
}

void WebFrameWidgetImpl::SetActive(bool active) {
  View()->SetIsActive(active);
}

WebInputEventResult WebFrameWidgetImpl::HandleKeyEvent(
    const WebKeyboardEvent& event) {
  DCHECK((event.GetType() == WebInputEvent::Type::kRawKeyDown) ||
         (event.GetType() == WebInputEvent::Type::kKeyDown) ||
         (event.GetType() == WebInputEvent::Type::kKeyUp));

  // Please refer to the comments explaining the m_suppressNextKeypressEvent
  // member.
  // The m_suppressNextKeypressEvent is set if the KeyDown is handled by
  // Webkit. A keyDown event is typically associated with a keyPress(char)
  // event and a keyUp event. We reset this flag here as this is a new keyDown
  // event.
  suppress_next_keypress_event_ = false;

  // If there is a popup open, it should be the one processing the event,
  // not the page.
  scoped_refptr<WebPagePopupImpl> page_popup = View()->GetPagePopup();
  if (page_popup) {
    page_popup->HandleKeyEvent(event);
    if (event.GetType() == WebInputEvent::Type::kRawKeyDown) {
      suppress_next_keypress_event_ = true;
    }
    return WebInputEventResult::kHandledSystem;
  }

  auto* frame = DynamicTo<LocalFrame>(FocusedCoreFrame());
  if (!frame)
    return WebInputEventResult::kNotHandled;

  WebInputEventResult result = frame->GetEventHandler().KeyEvent(event);
  // EventHandler may have detached the frame.
  if (!LocalRootImpl())
    return result;

  if (result != WebInputEventResult::kNotHandled) {
    if (WebInputEvent::Type::kRawKeyDown == event.GetType()) {
      // Suppress the next keypress event unless the focused node is a plugin
      // node.  (Flash needs these keypress events to handle non-US keyboards.)
      Element* element = FocusedElement();
      if (element && element->GetLayoutObject() &&
          element->GetLayoutObject()->IsEmbeddedObject()) {
        if (event.windows_key_code == VKEY_TAB) {
          // If the plugin supports keyboard focus then we should not send a tab
          // keypress event.
          WebPluginContainerImpl* plugin_view =
              To<LayoutEmbeddedContent>(element->GetLayoutObject())->Plugin();
          if (plugin_view && plugin_view->SupportsKeyboardFocus()) {
            suppress_next_keypress_event_ = true;
          }
        }
      } else {
        suppress_next_keypress_event_ = true;
      }
    }
    return result;
  }

#if !BUILDFLAG(IS_MAC)
  const WebInputEvent::Type kContextMenuKeyTriggeringEventType =
#if BUILDFLAG(IS_WIN)
      WebInputEvent::Type::kKeyUp;
#else
      WebInputEvent::Type::kRawKeyDown;
#endif
  const WebInputEvent::Type kShiftF10TriggeringEventType =
      WebInputEvent::Type::kRawKeyDown;

  bool is_unmodified_menu_key =
      !(event.GetModifiers() & WebInputEvent::kInputModifiers) &&
      event.windows_key_code == VKEY_APPS;
  bool is_shift_f10 = (event.GetModifiers() & WebInputEvent::kInputModifiers) ==
                          WebInputEvent::kShiftKey &&
                      event.windows_key_code == VKEY_F10;
  if ((is_unmodified_menu_key &&
       event.GetType() == kContextMenuKeyTriggeringEventType) ||
      (is_shift_f10 && event.GetType() == kShiftF10TriggeringEventType)) {
    View()->SendContextMenuEvent();
    return WebInputEventResult::kHandledSystem;
  }
#endif  // !BUILDFLAG(IS_MAC)

  return WebInputEventResult::kNotHandled;
}

void WebFrameWidgetImpl::HandleMouseDown(LocalFrame& local_root,
                                         const WebMouseEvent& event) {
  WebViewImpl* view_impl = View();
  // If there is a popup open, close it as the user is clicking on the page
  // (outside of the popup). We also save it so we can prevent a click on an
  // element from immediately reopening the same popup.
  scoped_refptr<WebPagePopupImpl> page_popup;
  if (event.button == WebMouseEvent::Button::kLeft) {
    page_popup = view_impl->GetPagePopup();
    view_impl->CancelPagePopup();
  }

  // Take capture on a mouse down on a plugin so we can send it mouse events.
  // If the hit node is a plugin but a scrollbar is over it don't start mouse
  // capture because it will interfere with the scrollbar receiving events.
  PhysicalOffset point(LayoutUnit(event.PositionInWidget().x()),
                       LayoutUnit(event.PositionInWidget().y()));
  if (event.button == WebMouseEvent::Button::kLeft) {
    HitTestLocation location(
        LocalRootImpl()->GetFrameView()->ConvertFromRootFrame(point));
    HitTestResult result(
        LocalRootImpl()->GetFrame()->GetEventHandler().HitTestResultAtLocation(
            location));
    result.SetToShadowHostIfInUAShadowRoot();
    Node* hit_node = result.InnerNode();
    auto* html_element = DynamicTo<HTMLElement>(hit_node);
    if (!result.GetScrollbar() && hit_node && hit_node->GetLayoutObject() &&
        hit_node->GetLayoutObject()->IsEmbeddedObject() && html_element &&
        html_element->IsPluginElement()) {
      mouse_capture_element_ = To<HTMLPlugInElement>(hit_node);
      SetMouseCapture(true);
      TRACE_EVENT_NESTABLE_ASYNC_BEGIN0("input", "capturing mouse",
                                        TRACE_ID_LOCAL(this));
    }
  }

  WidgetEventHandler::HandleMouseDown(local_root, event);
  // WidgetEventHandler may have detached the frame.
  if (!LocalRootImpl())
    return;

  if (view_impl->GetPagePopup() && page_popup &&
      view_impl->GetPagePopup()->HasSamePopupClient(page_popup.get())) {
    // That click triggered a page popup that is the same as the one we just
    // closed.  It needs to be closed.
    view_impl->CancelPagePopup();
  }

  // Dispatch the contextmenu event regardless of if the click was swallowed.
  if (!GetPage()->GetSettings().GetShowContextMenuOnMouseUp()) {
#if BUILDFLAG(IS_MAC)
    if (event.button == WebMouseEvent::Button::kRight ||
        (event.button == WebMouseEvent::Button::kLeft &&
         event.GetModifiers() & WebMouseEvent::kControlKey))
      MouseContextMenu(event);
#else
    if (event.button == WebMouseEvent::Button::kRight)
      MouseContextMenu(event);
#endif
  }
}

void WebFrameWidgetImpl::HandleMouseLeave(LocalFrame& local_root,
                                          const WebMouseEvent& event) {
  View()->SetMouseOverURL(WebURL());
  WidgetEventHandler::HandleMouseLeave(local_root, event);
  // WidgetEventHandler may have detached the frame.
}

void WebFrameWidgetImpl::MouseContextMenu(const WebMouseEvent& event) {
  GetPage()->GetContextMenuController().ClearContextMenu();

  WebMouseEvent transformed_event =
      TransformWebMouseEvent(LocalRootImpl()->GetFrameView(), event);
  transformed_event.menu_source_type = kMenuSourceMouse;
  transformed_event.id = PointerEventFactory::kMouseId;

  // Find the right target frame. See issue 1186900.
  HitTestResult result =
      HitTestResultForRootFramePos(transformed_event.PositionInRootFrame());
  Frame* target_frame;
  if (result.InnerNodeOrImageMapImage())
    target_frame = result.InnerNodeOrImageMapImage()->GetDocument().GetFrame();
  else
    target_frame = GetPage()->GetFocusController().FocusedOrMainFrame();

  // This will need to be changed to a nullptr check when focus control
  // is refactored, at which point focusedOrMainFrame will never return a
  // RemoteFrame.
  // See https://crbug.com/341918.
  LocalFrame* target_local_frame = DynamicTo<LocalFrame>(target_frame);
  if (!target_local_frame)
    return;

  {
    ContextMenuAllowedScope scope;
    target_local_frame->GetEventHandler().SendContextMenuEvent(
        transformed_event);
  }
  // Actually showing the context menu is handled by the ContextMenuClient
  // implementation...
}

WebInputEventResult WebFrameWidgetImpl::HandleMouseUp(
    LocalFrame& local_root,
    const WebMouseEvent& event) {
  WebInputEventResult result =
      WidgetEventHandler::HandleMouseUp(local_root, event);
  // WidgetEventHandler may have detached the frame.
  if (!LocalRootImpl())
    return result;

  if (GetPage()->GetSettings().GetShowContextMenuOnMouseUp()) {
    // Dispatch the contextmenu event regardless of if the click was swallowed.
    // On Mac/Linux, we handle it on mouse down, not up.
    if (event.button == WebMouseEvent::Button::kRight)
      MouseContextMenu(event);
  }
  return result;
}

WebInputEventResult WebFrameWidgetImpl::HandleGestureEvent(
    const WebGestureEvent& event) {
  WebInputEventResult event_result = WebInputEventResult::kNotHandled;

  // Fling and scroll events are not sent to the renderer main thread.
  CHECK(!event.IsScrollEvent());

  WebViewImpl* web_view = View();

  LocalFrame* frame = LocalRootImpl()->GetFrame();
  WebGestureEvent scaled_event = TransformWebGestureEvent(frame->View(), event);

  // Special handling for double tap and scroll events as we don't want to
  // hit test for them.
  switch (event.GetType()) {
    case WebInputEvent::Type::kGestureDoubleTap:
      if (web_view->SettingsImpl()->DoubleTapToZoomEnabled() &&
          web_view->MinimumPageScaleFactor() !=
              web_view->MaximumPageScaleFactor()) {
        gfx::Point pos_in_local_frame_root =
            gfx::ToFlooredPoint(scaled_event.PositionInRootFrame());
        auto block_bounds = ComputeBlockBound(pos_in_local_frame_root, false);

        if (ForMainFrame()) {
          web_view->AnimateDoubleTapZoom(pos_in_local_frame_root, block_bounds);
        } else {
          // This sends the tap point and bounds to the main frame renderer via
          // the browser, where their coordinates will be transformed into the
          // main frame's coordinate space.
          GetAssociatedFrameWidgetHost()->AnimateDoubleTapZoomInMainFrame(
              pos_in_local_frame_root, block_bounds);
        }
      }
      event_result = WebInputEventResult::kHandledSystem;
      DidHandleGestureEvent(event);
      return event_result;
    default:
      break;
  }

  // Hit test across all frames and do touch adjustment as necessary for the
  // event type.
  GestureEventWithHitTestResults targeted_event =
      frame->GetEventHandler().TargetGestureEvent(scaled_event);

  // Link highlight animations are only for the main frame.
  // TODO(bokan): This isn't intentional, see https://crbug.com/1344531.
  if (ForMainFrame()) {
    // Handle link highlighting outside the main switch to avoid getting lost in
    // the complicated set of cases handled below.
    switch (scaled_event.GetType()) {
      case WebInputEvent::Type::kGestureShowPress:
        // Queue a highlight animation, then hand off to regular handler.
        web_view->EnableTapHighlightAtPoint(targeted_event);
        break;
      case WebInputEvent::Type::kGestureShortPress:
      case WebInputEvent::Type::kGestureLongPress:
      case WebInputEvent::Type::kGestureTapCancel:
      case WebInputEvent::Type::kGestureTap:
        GetPage()->GetLinkHighlight().UpdateOpacityAndRequestAnimation();
        break;
      default:
        break;
    }
  }

  switch (scaled_event.GetType()) {
    case WebInputEvent::Type::kGestureTap: {
      {
        ContextMenuAllowedScope scope;
        event_result =
            frame->GetEventHandler().HandleGestureEvent(targeted_event);
      }

      if (web_view->GetPagePopup() && last_hidden_page_popup_ &&
          web_view->GetPagePopup()->HasSamePopupClient(
              last_hidden_page_popup_.get())) {
        // The tap triggered a page popup that is the same as the one we just
        // closed. It needs to be closed.
        web_view->CancelPagePopup();
      }
      // Don't have this value persist outside of a single tap gesture, plus
      // we're done with it now.
      last_hidden_page_popup_ = nullptr;
      break;
    }
    case WebInputEvent::Type::kGestureTwoFingerTap:
    case WebInputEvent::Type::kGestureLongPress:
    case WebInputEvent::Type::kGestureLongTap:
      if (scaled_event.GetType() == WebInputEvent::Type::kGestureLongTap) {
        if (LocalFrame* inner_frame =
                targeted_event.GetHitTestResult().InnerNodeFrame()) {
          if (!inner_frame->GetEventHandler().LongTapShouldInvokeContextMenu())
            break;
        } else if (!frame->GetEventHandler().LongTapShouldInvokeContextMenu()) {
          break;
        }
      }

      GetPage()->GetContextMenuController().ClearContextMenu();
      {
        ContextMenuAllowedScope scope;
        event_result =
            frame->GetEventHandler().HandleGestureEvent(targeted_event);
      }

      break;
    case WebInputEvent::Type::kGestureTapDown:
      // Touch pinch zoom and scroll on the page (outside of a popup) must hide
      // the popup. In case of a touch scroll or pinch zoom, this function is
      // called with GestureTapDown rather than a GSB/GSU/GSE or GPB/GPU/GPE.
      // When we close a popup because of a GestureTapDown, we also save it so
      // we can prevent the following GestureTap from immediately reopening the
      // same popup.
      // This value should not persist outside of a gesture, so is cleared by
      // GestureTap (where it is used) and by GestureCancel.
      last_hidden_page_popup_ = web_view->GetPagePopup();
      web_view->CancelPagePopup();
      event_result =
          frame->GetEventHandler().HandleGestureEvent(targeted_event);
      break;
    case WebInputEvent::Type::kGestureTapCancel:
      // Don't have this value persist outside of a single tap gesture.
      last_hidden_page_popup_ = nullptr;
      event_result =
          frame->GetEventHandler().HandleGestureEvent(targeted_event);
      break;
    case WebInputEvent::Type::kGestureShowPress:
    case WebInputEvent::Type::kGestureTapUnconfirmed:
    case WebInputEvent::Type::kGestureShortPress:
      event_result =
          frame->GetEventHandler().HandleGestureEvent(targeted_event);
      break;
    default:
      NOTREACHED();
  }
  DidHandleGestureEvent(event);
  return event_result;
}

WebInputEventResult WebFrameWidgetImpl::HandleMouseWheel(
    LocalFrame& frame,
    const WebMouseWheelEvent& event) {
  View()->CancelPagePopup();
  return WidgetEventHandler::HandleMouseWheel(frame, event);
  // WidgetEventHandler may have detached the frame.
}

WebInputEventResult WebFrameWidgetImpl::HandleCharEvent(
    const WebKeyboardEvent& event) {
  DCHECK_EQ(event.GetType(), WebInputEvent::Type::kChar);

  // Please refer to the comments explaining the m_suppressNextKeypressEvent
  // member.  The m_suppressNextKeypressEvent is set if the KeyDown is
  // handled by Webkit. A keyDown event is typically associated with a
  // keyPress(char) event and a keyUp event. We reset this flag here as it
  // only applies to the current keyPress event.
  bool suppress = suppress_next_keypress_event_;
  suppress_next_keypress_event_ = false;

  // If there is a popup open, it should be the one processing the event,
  // not the page.
  scoped_refptr<WebPagePopupImpl> page_popup = View()->GetPagePopup();
  if (page_popup)
    return page_popup->HandleKeyEvent(event);

  LocalFrame* frame = To<LocalFrame>(FocusedCoreFrame());
  if (!frame) {
    return suppress ? WebInputEventResult::kHandledSuppressed
                    : WebInputEventResult::kNotHandled;
  }

  EventHandler& handler = frame->GetEventHandler();

  if (!event.IsCharacterKey())
    return WebInputEventResult::kHandledSuppressed;

  // Accesskeys are triggered by char events and can't be suppressed.
  // It is unclear whether a keypress should be dispatched as well
  // crbug.com/563507
  if (handler.HandleAccessKey(event))
    return WebInputEventResult::kHandledSystem;

  // Safari 3.1 does not pass off windows system key messages (WM_SYSCHAR) to
  // the eventHandler::keyEvent. We mimic this behavior on all platforms since
  // for now we are converting other platform's key events to windows key
  // events.
  if (event.is_system_key)
    return WebInputEventResult::kNotHandled;

  if (suppress)
    return WebInputEventResult::kHandledSuppressed;

  WebInputEventResult result = handler.KeyEvent(event);
  if (result != WebInputEventResult::kNotHandled)
    return result;

  return WebInputEventResult::kNotHandled;
}

void WebFrameWidgetImpl::CancelDrag() {
  drag_operation_ = DragController::Operation();
  current_drag_data_ = nullptr;
}

void WebFrameWidgetImpl::StartDragging(LocalFrame* source_frame,
                                       const WebDragData& drag_data,
                                       DragOperationsMask operations_allowed,
                                       const SkBitmap& drag_image,
                                       const gfx::Vector2d& cursor_offset,
                                       const gfx::Rect& drag_obj_rect) {
  if (doing_drag_and_drop_) {
    // TODO: crbug.com/330274075 - Root cause nested drag-start events, remove
    // once issue has been resolved.
    base::debug::DumpWithoutCrashing();
  }

  doing_drag_and_drop_ = true;
  if (drag_and_drop_disabled_) {
    DragSourceSystemDragEnded();
    return;
  }

  gfx::Vector2d offset_in_dips =
      widget_base_->BlinkSpaceToFlooredDIPs(gfx::Point() + cursor_offset)
          .OffsetFromOrigin();
  gfx::Rect drag_obj_rect_in_dips =
      gfx::Rect(widget_base_->BlinkSpaceToFlooredDIPs(drag_obj_rect.origin()),
                widget_base_->BlinkSpaceToFlooredDIPs(drag_obj_rect.size()));
  source_frame->GetLocalFrameHostRemote().StartDragging(
      drag_data, operations_allowed, drag_image, offset_in_dips,
      drag_obj_rect_in_dips, possible_drag_event_info_.Clone());
}

void WebFrameWidgetImpl::DragTargetDragEnterOrOver(
    const gfx::PointF& point_in_viewport,
    const gfx::PointF& screen_point,
    DragAction drag_action,
    uint32_t key_modifiers) {
  if (ShouldIgnoreInputEvents() || !current_drag_data_) {
    CancelDrag();
    return;
  }

  gfx::PointF point_in_root_frame = ViewportToRootFrame(point_in_viewport);

  current_drag_data_->SetModifiers(key_modifiers);
  DragData drag_data(current_drag_data_.Get(), point_in_root_frame,
                     screen_point, operations_allowed_,
                     /*force_default_action=*/false);

  drag_operation_ = GetPage()->GetDragController().DragEnteredOrUpdated(
      &drag_data, *local_root_->GetFrame());

  // Mask the drag operation against the drag source's allowed
  // operations.
  if (!(static_cast<int>(drag_operation_.operation) &
        drag_data.DraggingSourceOperationMask())) {
    drag_operation_ = DragController::Operation();
  }
}

void WebFrameWidgetImpl::SendOverscrollEventFromImplSide(
    const gfx::Vector2dF& overscroll_delta,
    cc::ElementId scroll_latched_element_id) {
  if (!RuntimeEnabledFeatures::OverscrollCustomizationEnabled())
    return;

  Node* target_node = View()->FindNodeFromScrollableCompositorElementId(
      scroll_latched_element_id);
  if (target_node) {
    target_node->GetDocument().EnqueueOverscrollEventForNode(
        target_node, overscroll_delta.x(), overscroll_delta.y());
  }
}

void WebFrameWidgetImpl::SendEndOfScrollEventsDeprecated(
    bool affects_outer_viewport,
    bool affects_inner_viewport,
    cc::ElementId scroll_latched_element_id) {
  Node* target_node = View()->FindNodeFromScrollableCompositorElementId(
      scroll_latched_element_id);
  if (!target_node) {
    return;
  }
  if (ScrollableArea* scrollable_area =
          ScrollableArea::GetForScrolling(target_node->GetLayoutBox())) {
    scrollable_area->UpdateSnappedTargetsAndEnqueueScrollSnapChange();
    scrollable_area->SetImplSnapStrategy(nullptr);
  }

  if (auto* viewport_position_tracker =
          AnchorElementViewportPositionTracker::MaybeGetOrCreateFor(
              target_node->GetDocument())) {
    viewport_position_tracker->OnScrollEnd();
  }

  if (RuntimeEnabledFeatures::ScrollEndEventsEnabled()) {
    Node* document_node = View()->MainFrameImpl()
                              ? View()->MainFrameImpl()->GetDocument()
                              : nullptr;
    if (affects_inner_viewport) {
      target_node->GetDocument().EnqueueVisualViewportScrollEndEvent();
    }
    // A scroll gesture that causes the browser controls to show/hide would be
    // associated with the document but may not have actually caused the
    // document/outer viewport to scroll. In this case the document should
    // not receive a scrollend event.
    if (affects_outer_viewport || target_node != document_node) {
      target_node->GetDocument().EnqueueScrollEndEventForNode(target_node);
    }
  }
}

void WebFrameWidgetImpl::SendEndOfScrollEvents(
    const cc::CompositorCommitData& commit_data) {
  HeapHashSet<Member<AnchorElementViewportPositionTracker>> handled_trackers;
  for (const cc::ElementId& id : commit_data.scroll_end_data.done_containers) {
    Node* target_node = View()->FindNodeFromScrollableCompositorElementId(id);
    if (!target_node) {
      continue;
    }

    if (auto* viewport_position_tracker =
            AnchorElementViewportPositionTracker::MaybeGetOrCreateFor(
                target_node->GetDocument())) {
      if (!handled_trackers.Contains(viewport_position_tracker)) {
        viewport_position_tracker->OnScrollEnd();
        handled_trackers.insert(viewport_position_tracker);
      }
    }

    if (ScrollableArea* scrollable_area =
            ScrollableArea::GetForScrolling(target_node->GetLayoutBox())) {
      scrollable_area->UpdateSnappedTargetsAndEnqueueScrollSnapChange();
      scrollable_area->SetImplSnapStrategy(nullptr);
    }

    if (RuntimeEnabledFeatures::ScrollEndEventsEnabled()) {
      if (GetPage()->GetVisualViewport().GetScrollElementId() == id) {
        target_node->GetDocument().EnqueueVisualViewportScrollEndEvent();
      } else {
        target_node->GetDocument().EnqueueScrollEndEventForNode(target_node);
      }
    }
  }
}

void WebFrameWidgetImpl::SendScrollSnapChangingEventIfNeeded(
    const cc::CompositorCommitData& commit_data) {
  Node* target_node = View()->FindNodeFromScrollableCompositorElementId(
      commit_data.scroll_latched_element_id);
  if (!target_node) {
    return;
  }
  if (ScrollableArea* scrollable_area =
          ScrollableArea::GetForScrolling(target_node->GetLayoutBox())) {
    scrollable_area->SetImplSnapStrategy(commit_data.snap_strategy->Clone());
    scrollable_area->EnqueueScrollSnapChangingEventFromImplIfNeeded();
  }
}

void WebFrameWidgetImpl::UpdateCompositorScrollState(
    const cc::CompositorCommitData& commit_data) {
  is_scroll_gesture_active_ = commit_data.is_scroll_active;
  if (WebDevToolsAgentImpl* devtools =
          LocalRootImpl()->DevToolsAgentImpl(/*create_if_necessary=*/false)) {
    devtools->SetPageIsScrolling(is_scroll_gesture_active_);
  }

  RecordManipulationTypeCounts(commit_data.manipulation_info);

  if (commit_data.scroll_latched_element_id != cc::ElementId()) {
    if (commit_data.snap_strategy) {
      SendScrollSnapChangingEventIfNeeded(commit_data);
    }
    if (!commit_data.overscroll_delta.IsZero()) {
      SendOverscrollEventFromImplSide(commit_data.overscroll_delta,
                                      commit_data.scroll_latched_element_id);
    }
  }

  // TODO(bokan): If a scroll ended and a new one began in the same Blink frame
  // (e.g. during a long running main thread task), this will erroneously
  // dispatch the scroll end to the latter (still-scrolling) element.
  // https://crbug.com/1116780.
  // With MultiImplyOnlyScrollAnimations support, a non-latched scroll
  // container might have finished its snap animation, so we don't check that we
  // have a latched id.
  if (::features::MultiImplOnlyScrollAnimationsSupported()) {
    if (commit_data.scroll_end_data.done_containers.size()) {
      SendEndOfScrollEvents(commit_data);
    }
  } else {
    if (commit_data.scroll_latched_element_id != cc::ElementId() &&
        commit_data.scroll_end_data.scroll_gesture_did_end) {
      SendEndOfScrollEventsDeprecated(
          commit_data.scroll_end_data.gesture_affects_outer_viewport_scroll,
          commit_data.scroll_end_data.gesture_affects_inner_viewport_scroll,
          commit_data.scroll_latched_element_id);
    }
  }
}

bool WebFrameWidgetImpl::IsScrollGestureActive() const {
  return is_scroll_gesture_active_;
}

void WebFrameWidgetImpl::RequestViewportScreenshot(
    const base::UnguessableToken& token) {
  LayerTreeHost()->RequestViewportScreenshot(token);
}

void WebFrameWidgetImpl::RequestNewLocalSurfaceId() {
  LayerTreeHost()->RequestNewLocalSurfaceId();
}

WebInputMethodController*
WebFrameWidgetImpl::GetActiveWebInputMethodController() const {
  WebLocalFrameImpl* local_frame =
      WebLocalFrameImpl::FromFrame(FocusedLocalFrameInWidget());
  return local_frame ? local_frame->GetInputMethodController() : nullptr;
}

void WebFrameWidgetImpl::DisableDragAndDrop() {
  drag_and_drop_disabled_ = true;
}

gfx::PointF WebFrameWidgetImpl::ViewportToRootFrame(
    const gfx::PointF& point_in_viewport) const {
  return GetPage()->GetVisualViewport().ViewportToRootFrame(point_in_viewport);
}

WebViewImpl* WebFrameWidgetImpl::View() const {
  return local_root_->ViewImpl();
}

Page* WebFrameWidgetImpl::GetPage() const {
  return View()->GetPage();
}

mojom::blink::FrameWidgetHost*
WebFrameWidgetImpl::GetAssociatedFrameWidgetHost() const {
  return frame_widget_host_.get();
}

void WebFrameWidgetImpl::RequestDecode(
    const PaintImage& image,
    base::OnceCallback<void(bool)> callback) {
  widget_base_->LayerTreeHost()->QueueImageDecode(image, std::move(callback));
}

void WebFrameWidgetImpl::Trace(Visitor* visitor) const {
  visitor->Trace(local_root_);
  visitor->Trace(current_drag_data_);
  visitor->Trace(frame_widget_host_);
  visitor->Trace(receiver_);
  visitor->Trace(input_target_receiver_);
#if BUILDFLAG(IS_ANDROID)
  visitor->Trace(ime_render_widget_host_);
#endif
  visitor->Trace(mouse_capture_element_);
  visitor->Trace(device_emulator_);
  visitor->Trace(animation_frame_timing_monitor_);
}

void WebFrameWidgetImpl::SetNeedsRecalculateRasterScales() {
  if (!View()->does_composite())
    return;
  widget_base_->LayerTreeHost()->SetNeedsRecalculateRasterScales();
}

void WebFrameWidgetImpl::SetBackgroundColor(SkColor color) {
  if (!View()->does_composite())
    return;
  // TODO(crbug/1308932): Remove FromColor and make all SkColor4f.
  widget_base_->LayerTreeHost()->set_background_color(
      SkColor4f::FromColor(color));
}

void WebFrameWidgetImpl::SetOverscrollBehavior(
    const cc::OverscrollBehavior& overscroll_behavior) {
  if (!View()->does_composite())
    return;
  widget_base_->LayerTreeHost()->SetOverscrollBehavior(overscroll_behavior);
}

void WebFrameWidgetImpl::SetPrefersReducedMotion(bool prefers_reduced_motion) {
  if (!View()->does_composite())
    return;
  widget_base_->LayerTreeHost()->SetPrefersReducedMotion(
      prefers_reduced_motion);
}

void WebFrameWidgetImpl::StartPageScaleAnimation(const gfx::Point& destination,
                                                 bool use_anchor,
                                                 float new_page_scale,
                                                 base::TimeDelta duration) {
  widget_base_->LayerTreeHost()->StartPageScaleAnimation(
      destination, use_anchor, new_page_scale, duration);
}

void WebFrameWidgetImpl::RequestBeginMainFrameNotExpected(bool request) {
  if (!View()->does_composite())
    return;
  widget_base_->LayerTreeHost()->RequestBeginMainFrameN
```