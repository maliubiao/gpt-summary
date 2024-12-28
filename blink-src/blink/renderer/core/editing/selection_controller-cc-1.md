Response:
The user wants a summary of the functionality of the provided C++ code snippet from `selection_controller.cc`. I need to identify the main purpose of the code, explain its relation to web technologies (JavaScript, HTML, CSS), illustrate its logic with input/output examples, point out common usage errors, describe user actions leading to this code, and finally, provide a concise overall summary.

**Plan:**

1. **Identify Core Functionality:** Analyze the methods and their interactions to determine the primary role of this code. It appears to handle mouse events related to text selection.
2. **Relate to Web Technologies:**  Think about how user interactions with HTML elements (especially text) and CSS styles for selection are processed by this C++ code. Consider how JavaScript might trigger or interact with selection mechanisms.
3. **Illustrate Logic:** For key functions, devise simple scenarios and trace the code's execution to show input and output. Focus on `SelectClosestWordFromMouseEvent` or similar functions.
4. **Identify Common Errors:** Consider mistakes users or developers might make that could lead to unexpected behavior in this code, like interfering with default selection behavior.
5. **Describe User Actions:**  Outline the steps a user would take in a browser that would trigger the execution of code within this snippet. Focus on mouse clicks and drags.
6. **Provide Overall Summary:** Concisely restate the main purpose and responsibilities of the `SelectionController`.
这是 blink 渲染引擎中 `selection_controller.cc` 文件的第二部分代码，延续了第一部分的功能，主要负责处理各种与用户在网页上进行文本选择相关的操作。以下是其功能的归纳：

**核心功能归纳：**

该代码片段延续了 `SelectionController` 类的职责，专注于处理各种鼠标事件（`mousedown`, `mousemove`, `mouseup`, `doubleclick`, `tripleclick`, `contextmenu`）和手势事件（`longpress`, `twofingertap`），以实现精确和符合用户预期的文本选择行为。其核心功能可以归纳为：

1. **基于鼠标事件进行文本选择和光标定位：**
    *   处理单次、双击和三击鼠标事件，以选择字符、单词或段落。
    *   处理鼠标拖动事件，动态调整选择范围。
    *   处理鼠标释放事件，可能清除选择或在可编辑区域放置光标。
    *   区分鼠标在链接上和非链接区域的行为。
    *   处理 Alt 键辅助的链接选择。
    *   处理 Shift 键辅助的扩展选择。

2. **处理特定类型的选择：**
    *   能够选择最接近鼠标点击位置的单词。
    *   能够选择最接近鼠标点击位置的拼写错误单词。
    *   处理用户长按手势以进行文本选择。
    *   处理双指轻击手势以定位光标。

3. **处理上下文菜单事件：**
    *   根据上下文菜单事件的位置和类型，可能触发单词或链接的选择。
    *   在上下文菜单点击在拼写错误的单词上时，会选择该单词。
    *   考虑用户是否已经进行了选择以及点击位置是否在已选区域内。

4. **维护和更新选择状态：**
    *   跟踪选择是否已经开始 (`mouse_down_may_start_select_`)。
    *   记录鼠标按下时是否是单次点击并且在已选区域内或在光标上。
    *   维护选择状态 (`selection_state_`)，例如未开始选择、已放置光标、已扩展选择。
    *   在选择发生变化时通知相关组件。

5. **与其他组件的交互：**
    *   与 `Frame` 和 `Document` 对象交互，获取布局信息和更新样式。
    *   与 `Editor` 对象交互，判断是否允许选择和处理粘贴操作。
    *   与 `SpellChecker` 交互，判断点击位置是否在拼写错误的单词上。
    *   与 `HitTestResult` 对象交互，获取鼠标点击位置的节点信息。
    *   与 `FrameSelection` 对象交互，获取和设置当前的文本选择。

**与 JavaScript, HTML, CSS 的关系举例：**

*   **HTML:** 用户在 HTML 文本节点或包含文本的元素上进行点击、拖动等操作，会触发这里的代码来更新浏览器的文本选择状态。例如，用户双击一个段落 `<p>` 元素中的一个单词，`SelectClosestWordFromMouseEvent` 方法会被调用，最终高亮显示该单词。
*   **CSS:**  CSS 的 `user-select` 属性会影响这里的选择行为。`ExpandSelectionToRespectUserSelectAll` 方法会考虑 `user-select: all` 的情况，选择包含该文本的整个元素。
*   **JavaScript:** JavaScript 可以通过 `document.getSelection()` API 获取当前的文本选择，这个 API 的底层实现就依赖于 `SelectionController` 所维护的状态。例如，一个 JavaScript 脚本监听了 `mouseup` 事件，并尝试获取用户选中的文本，它获取的就是 `SelectionController` 更新后的选择结果。

**逻辑推理举例（假设输入与输出）：**

**假设输入:** 用户在一个 `<p>` 元素内的文本 "This is a test." 上双击了 "test" 这个单词。

**处理流程:**

1. `HandleMousePressEvent` 被调用，`event.Event().click_count` 为 2。
2. `HandleDoubleClick` 被调用。
3. `SelectClosestWordFromMouseEvent` 被调用，传入鼠标事件和 HitTestResult。
4. `SelectClosestWordFromHitTestResult` 被调用，根据鼠标点击位置，找到 "test" 所在的文本节点和位置。
5. 代码会计算出 "test" 这个单词的起始和结束位置。
6. `UpdateSelectionForMouseDownDispatchingSelectStart` 被调用，使用计算出的位置创建一个新的 `SelectionInFlatTree` 对象，选中 "test" 这个单词。

**输出:** 浏览器界面上，"test" 这个单词会被高亮显示。

**用户或编程常见的使用错误举例：**

*   **用户错误:**  在 `user-select: none` 的元素上尝试进行文本选择，虽然鼠标事件会到达 `SelectionController`，但最终不会产生有效的文本选择。
*   **编程错误:**  JavaScript 代码过度干预默认的选择行为，例如在 `mousedown` 事件上阻止了默认行为，可能会导致 `SelectionController` 无法正常工作，用户无法进行文本选择。

**用户操作如何一步步到达这里（调试线索）：**

1. 用户在浏览器中打开一个网页。
2. 用户将鼠标指针移动到包含文本的元素上。
3. 用户按下鼠标左键（触发 `HandleMousePressEvent`）。
4. 如果用户是单击并按住鼠标拖动，则会触发 `HandleMouseDraggedEvent`。
5. 如果用户是双击，则会触发 `HandleDoubleClick`。
6. 如果用户是三击，则会触发 `HandleTripleClick`。
7. 用户释放鼠标左键（触发 `HandleMouseReleaseEvent`）。
8. 如果用户在文本上点击右键，则会触发 `UpdateSelectionForContextMenuEvent`。

通过在 `SelectionController` 的相关方法中设置断点，并按照上述用户操作流程操作浏览器，开发者可以逐步调试文本选择相关的 bug。

**总结：**

这部分代码是 Chromium Blink 引擎中负责处理用户在网页上进行文本选择操作的核心组件。它监听和处理各种鼠标和手势事件，根据事件类型和位置精确地更新浏览器的文本选择状态，并与渲染引擎的其他部分协同工作，以实现符合用户预期的文本选择体验。同时，它也考虑了 HTML 和 CSS 属性对选择行为的影响，并为 JavaScript 提供了操作和获取选择结果的底层支持。

Prompt: 
```
这是目录为blink/renderer/core/editing/selection_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
anularity(TextGranularity::kWord)
            .Build());
    return;
  }

  const PositionInFlatTree& marker_position =
      pos.GetPosition().ParentAnchoredEquivalent();
  const DocumentMarkerGroup* const marker_group =
      SpellCheckMarkerGroupAtPosition(inner_node->GetDocument().Markers(),
                                      marker_position);
  if (!marker_group) {
    UpdateSelectionForMouseDownDispatchingSelectStart(
        inner_node, SelectionInFlatTree(),
        SetSelectionOptions::Builder()
            .SetGranularity(TextGranularity::kWord)
            .Build());
    return;
  }

  const SelectionInFlatTree new_selection =
      CreateVisibleSelection(
          SelectionInFlatTree::Builder()
              .Collapse(marker_group->StartPositionInFlatTree())
              .Extend(marker_group->EndPositionInFlatTree())
              .Build())
          .AsSelection();
  const SelectionInFlatTree& adjusted_selection =
      append_trailing_whitespace == AppendTrailingWhitespace::kShouldAppend
          ? AdjustSelectionWithTrailingWhitespace(new_selection)
          : new_selection;
  UpdateSelectionForMouseDownDispatchingSelectStart(
      inner_node,
      ExpandSelectionToRespectUserSelectAll(inner_node, adjusted_selection),
      SetSelectionOptions::Builder()
          .SetGranularity(TextGranularity::kWord)
          .Build());
}

template <typename MouseEventObject>
bool SelectionController::SelectClosestWordFromMouseEvent(
    const MouseEventObject* mouse_event,
    const HitTestResult& result) {
  if (!mouse_down_may_start_select_)
    return false;

  AppendTrailingWhitespace append_trailing_whitespace =
      (mouse_event->ClickCount() == 2 &&
       frame_->GetEditor().IsSelectTrailingWhitespaceEnabled())
          ? AppendTrailingWhitespace::kShouldAppend
          : AppendTrailingWhitespace::kDontAppend;

  DCHECK(!frame_->GetDocument()->NeedsLayoutTreeUpdate());

  return SelectClosestWordFromHitTestResult(result, append_trailing_whitespace,
                                            mouse_event->FromTouch()
                                                ? SelectInputEventType::kTouch
                                                : SelectInputEventType::kMouse);
}

template <typename MouseEventObject>
void SelectionController::SelectClosestMisspellingFromMouseEvent(
    const MouseEventObject* mouse_event,
    const HitTestResult& hit_test_result) {
  if (!mouse_down_may_start_select_)
    return;

  SelectClosestMisspellingFromHitTestResult(
      hit_test_result, (mouse_event->ClickCount() == 2 &&
                        frame_->GetEditor().IsSelectTrailingWhitespaceEnabled())
                           ? AppendTrailingWhitespace::kShouldAppend
                           : AppendTrailingWhitespace::kDontAppend);
}

template <typename MouseEventObject>
void SelectionController::SelectClosestWordOrLinkFromMouseEvent(
    const MouseEventObject* mouse_event,
    const HitTestResult& hit_test_result) {
  if (!hit_test_result.IsLiveLink()) {
    SelectClosestWordFromMouseEvent(mouse_event, hit_test_result);
    return;
  }

  Node* const inner_node = hit_test_result.InnerNode();

  if (!inner_node || !inner_node->GetLayoutObject() ||
      !mouse_down_may_start_select_)
    return;

  Element* url_element = hit_test_result.URLElement();
  const PositionInFlatTreeWithAffinity pos =
      CreateVisiblePosition(
          PositionWithAffinityOfHitTestResult(hit_test_result))
          .ToPositionWithAffinity();
  const SelectionInFlatTree& new_selection =
      pos.IsNotNull() && pos.AnchorNode()->IsDescendantOf(url_element)
          ? SelectionInFlatTree::Builder()
                .SelectAllChildren(*url_element)
                .Build()
          : SelectionInFlatTree();

  UpdateSelectionForMouseDownDispatchingSelectStart(
      inner_node,
      ExpandSelectionToRespectUserSelectAll(inner_node, new_selection),
      SetSelectionOptions::Builder()
          .SetGranularity(TextGranularity::kWord)
          .Build());
}

// TODO(yosin): We should take |granularity| and |handleVisibility| from
// |newSelection|.
// We should rename this function to appropriate name because
// set_selection_options has selection directional value in few cases.
void SelectionController::SetNonDirectionalSelectionIfNeeded(
    const SelectionInFlatTree& new_selection,
    const SetSelectionOptions& set_selection_options,
    EndPointsAdjustmentMode endpoints_adjustment_mode) {
  DCHECK(!GetDocument().NeedsLayoutTreeUpdate());

  // TODO(editing-dev): We should use |PositionWithAffinity| to pass affinity
  // to |CreateVisiblePosition()| for |original_anchor|.
  const PositionInFlatTree& anchor_position =
      original_anchor_in_flat_tree_.GetPosition();
  const PositionInFlatTreeWithAffinity original_anchor =
      anchor_position.IsConnected()
          ? CreateVisiblePosition(anchor_position).ToPositionWithAffinity()
          : PositionInFlatTreeWithAffinity();
  const PositionInFlatTreeWithAffinity anchor =
      original_anchor.IsNotNull()
          ? original_anchor
          : CreateVisiblePosition(new_selection.Anchor())
                .ToPositionWithAffinity();
  const PositionInFlatTreeWithAffinity focus =
      CreateVisiblePosition(new_selection.Focus()).ToPositionWithAffinity();
  const SelectionInFlatTree& adjusted_selection =
      endpoints_adjustment_mode == kAdjustEndpointsAtBidiBoundary
          ? BidiAdjustment::AdjustForRangeSelection(anchor, focus)
          : SelectionInFlatTree::Builder()
                .SetBaseAndExtent(anchor.GetPosition(), focus.GetPosition())
                .Build();

  SelectionInFlatTree::Builder builder(new_selection);
  if (adjusted_selection.Anchor() != anchor.GetPosition() ||
      adjusted_selection.Focus() != focus.GetPosition()) {
    original_anchor_in_flat_tree_ = anchor;
    SetExecutionContext(frame_->DomWindow());
    builder.SetBaseAndExtent(adjusted_selection.Anchor(),
                             adjusted_selection.Focus());
  } else if (original_anchor.IsNotNull()) {
    if (CreateVisiblePosition(
            Selection().ComputeVisibleSelectionInFlatTree().Anchor())
            .DeepEquivalent() ==
        CreateVisiblePosition(new_selection.Anchor()).DeepEquivalent()) {
      builder.SetBaseAndExtent(original_anchor.GetPosition(),
                               new_selection.Focus());
    }
    original_anchor_in_flat_tree_ = PositionInFlatTreeWithAffinity();
  }

  const bool selection_is_directional =
      frame_->GetEditor().Behavior().ShouldConsiderSelectionAsDirectional() ||
      set_selection_options.IsDirectional();
  const SelectionInFlatTree& selection_in_flat_tree = builder.Build();

  const bool selection_remains_the_same =
      Selection().ComputeVisibleSelectionInFlatTree() ==
          CreateVisibleSelection(selection_in_flat_tree) &&
      Selection().IsHandleVisible() ==
          set_selection_options.ShouldShowHandle() &&
      selection_is_directional == Selection().IsDirectional();

  // If selection has not changed we do not clear editing style.
  if (selection_remains_the_same)
    return;
  Selection().SetSelection(
      ConvertToSelectionInDOMTree(selection_in_flat_tree),
      SetSelectionOptions::Builder(set_selection_options)
          .SetShouldCloseTyping(true)
          .SetShouldClearTypingStyle(true)
          .SetIsDirectional(selection_is_directional)
          .SetCursorAlignOnScroll(CursorAlignOnScroll::kIfNeeded)
          .Build());
}

void SelectionController::SetCaretAtHitTestResult(
    const HitTestResult& hit_test_result) {
  Node* inner_node = hit_test_result.InnerPossiblyPseudoNode();
  DCHECK(inner_node);
  const PositionInFlatTreeWithAffinity visible_hit_pos =
      CreateVisiblePosition(
          PositionWithAffinityOfHitTestResult(hit_test_result))
          .ToPositionWithAffinity();
  const PositionInFlatTreeWithAffinity visible_pos =
      visible_hit_pos.IsNull()
          ? CreateVisiblePosition(
                PositionInFlatTree::FirstPositionInOrBeforeNode(*inner_node))
                .ToPositionWithAffinity()
          : visible_hit_pos;

  if (visible_pos.IsNull()) {
    UpdateSelectionForMouseDownDispatchingSelectStart(
        inner_node, SelectionInFlatTree(),
        SetSelectionOptions::Builder().SetShouldShowHandle(true).Build());
    return;
  }
  UpdateSelectionForMouseDownDispatchingSelectStart(
      inner_node,
      ExpandSelectionToRespectUserSelectAll(
          inner_node,
          SelectionInFlatTree::Builder().Collapse(visible_pos).Build()),
      SetSelectionOptions::Builder().SetShouldShowHandle(true).Build());
}

bool SelectionController::HandleDoubleClick(
    const MouseEventWithHitTestResults& event) {
  TRACE_EVENT0("blink",
               "SelectionController::handleMousePressEventDoubleClick");

  if (!Selection().IsAvailable())
    return false;

  if (!mouse_down_allows_multi_click_)
    return HandleSingleClick(event);

  if (event.Event().button != WebPointerProperties::Button::kLeft)
    return false;

  if (Selection().ComputeVisibleSelectionInDOMTreeDeprecated().IsRange()) {
    // A double-click when range is already selected
    // should not change the selection.  So, do not call
    // SelectClosestWordFromMouseEvent, but do set
    // began_selecting_text_ to prevent HandleMouseReleaseEvent
    // from setting caret selection.
    selection_state_ = SelectionState::kExtendedSelection;
    return true;
  }
  if (!SelectClosestWordFromMouseEvent(&event.Event(),
                                       event.GetHitTestResult()))
    return true;
  if (!Selection().IsHandleVisible())
    return true;
  frame_->GetEventHandler().ShowNonLocatedContextMenu(nullptr,
                                                      kMenuSourceTouch);
  return true;
}

bool SelectionController::HandleTripleClick(
    const MouseEventWithHitTestResults& event) {
  TRACE_EVENT0("blink",
               "SelectionController::handleMousePressEventTripleClick");

  if (!Selection().IsAvailable()) {
    // editing/shadow/doubleclick-on-meter-in-shadow-crash.html reach here.
    return false;
  }

  if (!mouse_down_allows_multi_click_)
    return HandleSingleClick(event);

  if (event.Event().button != WebPointerProperties::Button::kLeft)
    return false;

  Node* const inner_node = event.InnerNode();
  Node* inner_pseudo = event.GetHitTestResult().InnerPossiblyPseudoNode();
  if (!(inner_node && inner_node->GetLayoutObject() && inner_pseudo &&
        inner_pseudo->GetLayoutObject() && mouse_down_may_start_select_))
    return false;

  const PositionInFlatTreeWithAffinity pos =
      CreateVisiblePosition(
          PositionWithAffinityOfHitTestResult(event.GetHitTestResult()))
          .ToPositionWithAffinity();
  const SelectionInFlatTree new_selection =
      pos.IsNotNull()
          ? ExpandWithGranularity(
                SelectionInFlatTree::Builder().Collapse(pos).Build(),
                TextGranularity::kParagraph)
          : SelectionInFlatTree();
  const SelectionInFlatTree adjusted_selection =
      AdjustSelectionByUserSelect(inner_node, new_selection);

  const bool is_handle_visible =
      event.Event().FromTouch() && new_selection.IsRange();

  const bool did_select = UpdateSelectionForMouseDownDispatchingSelectStart(
      inner_node, adjusted_selection,
      SetSelectionOptions::Builder()
          .SetGranularity(TextGranularity::kParagraph)
          .SetShouldShowHandle(is_handle_visible)
          .Build());
  if (!did_select)
    return false;

  if (!Selection().IsHandleVisible())
    return true;
  frame_->GetEventHandler().ShowNonLocatedContextMenu(nullptr,
                                                      kMenuSourceTouch);
  return true;
}

bool SelectionController::HandleMousePressEvent(
    const MouseEventWithHitTestResults& event) {
  TRACE_EVENT0("blink", "SelectionController::handleMousePressEvent");

  // If we got the event back, that must mean it wasn't prevented,
  // so it's allowed to start a drag or selection if it wasn't in a scrollbar.
  mouse_down_may_start_select_ = (CanMouseDownStartSelect(event.InnerNode()) ||
                                  IsSelectionOverLink(event)) &&
                                 !event.GetScrollbar();
  mouse_down_was_single_click_on_caret_ = false;
  mouse_down_was_single_click_in_selection_ = false;
  if (!Selection().IsAvailable()) {
    // "gesture-tap-frame-removed.html" reaches here.
    mouse_down_allows_multi_click_ = !event.Event().FromTouch();
  } else {
    // Avoid double-tap touch gesture confusion by restricting multi-click side
    // effects, e.g., word selection, to editable regions.
    mouse_down_allows_multi_click_ =
        !event.Event().FromTouch() ||
        IsEditablePosition(
            Selection().ComputeVisibleSelectionInDOMTreeDeprecated().Start());
  }

  if (event.Event().click_count >= 3)
    return HandleTripleClick(event);
  if (event.Event().click_count == 2)
    return HandleDoubleClick(event);
  return HandleSingleClick(event);
}

WebInputEventResult SelectionController::HandleMouseDraggedEvent(
    const MouseEventWithHitTestResults& event,
    const gfx::Point& mouse_down_pos,
    const PhysicalOffset& last_known_mouse_position) {
  TRACE_EVENT0("blink", "SelectionController::handleMouseDraggedEvent");

  if (!Selection().IsAvailable())
    return WebInputEventResult::kNotHandled;
  if (selection_state_ != SelectionState::kExtendedSelection) {
    HitTestRequest request(HitTestRequest::kReadOnly | HitTestRequest::kActive);
    HitTestLocation location(mouse_down_pos);
    HitTestResult result(request, location);
    frame_->GetDocument()->GetLayoutView()->HitTest(location, result);

    UpdateSelectionForMouseDrag(result, last_known_mouse_position);
  }
  return UpdateSelectionForMouseDrag(event.GetHitTestResult(),
                                     last_known_mouse_position);
}

void SelectionController::UpdateSelectionForMouseDrag(
    const PhysicalOffset& drag_start_pos_in_root_frame,
    const PhysicalOffset& last_known_mouse_position_in_root_frame) {
  LocalFrameView* view = frame_->View();
  if (!view)
    return;
  LayoutView* layout_view = frame_->ContentLayoutObject();
  if (!layout_view)
    return;

  HitTestRequest request(HitTestRequest::kReadOnly | HitTestRequest::kActive |
                         HitTestRequest::kMove);
  HitTestLocation location(
      view->ConvertFromRootFrame(last_known_mouse_position_in_root_frame));
  HitTestResult result(request, location);
  layout_view->HitTest(location, result);
  UpdateSelectionForMouseDrag(result, last_known_mouse_position_in_root_frame);
}

bool SelectionController::HandleMouseReleaseEvent(
    const MouseEventWithHitTestResults& event,
    const PhysicalOffset& drag_start_pos) {
  TRACE_EVENT0("blink", "SelectionController::handleMouseReleaseEvent");

  if (!Selection().IsAvailable())
    return false;

  bool handled = false;
  mouse_down_may_start_select_ = false;
  // Clear the selection if the mouse didn't move after the last mouse
  // press and it's not a context menu click.  We do this so when clicking
  // on the selection, the selection goes away.  However, if we are
  // editing, place the caret.
  if (mouse_down_was_single_click_in_selection_ &&
      selection_state_ != SelectionState::kExtendedSelection &&
      drag_start_pos == PhysicalOffset(gfx::ToFlooredPoint(
                            event.Event().PositionInRootFrame())) &&
      Selection().ComputeVisibleSelectionInDOMTreeDeprecated().IsRange() &&
      event.Event().button != WebPointerProperties::Button::kRight) {
    // TODO(editing-dev): Use of UpdateStyleAndLayout
    // needs to be audited.  See http://crbug.com/590369 for more details.
    frame_->GetDocument()->UpdateStyleAndLayout(
        DocumentUpdateReason::kSelection);

    SelectionInFlatTree::Builder builder;
    Node* node = event.InnerNode();
    if (node && node->GetLayoutObject() && IsEditable(*node)) {
      const PositionInFlatTreeWithAffinity pos =
          CreateVisiblePosition(
              PositionWithAffinityOfHitTestResult(event.GetHitTestResult()))
              .ToPositionWithAffinity();
      if (pos.IsNotNull())
        builder.Collapse(pos);
    }

    const SelectionInFlatTree new_selection = builder.Build();
    if (Selection().ComputeVisibleSelectionInFlatTree() !=
        CreateVisibleSelection(new_selection)) {
      Selection().SetSelectionAndEndTyping(
          ConvertToSelectionInDOMTree(new_selection));
    }

    handled = true;
  }

  Selection().NotifyTextControlOfSelectionChange(SetSelectionBy::kUser);

  Selection().SelectFrameElementInParentIfFullySelected();

  if (event.Event().button == WebPointerProperties::Button::kMiddle &&
      !event.IsOverLink()) {
    // Ignore handled, since we want to paste to where the caret was placed
    // anyway.
    handled = HandlePasteGlobalSelection(event.Event()) || handled;
  }

  return handled;
}

bool SelectionController::HandlePasteGlobalSelection(
    const WebMouseEvent& mouse_event) {
  // If the event was a middle click, attempt to copy global selection in after
  // the newly set caret position.
  //
  // This code is called from either the mouse up or mouse down handling. There
  // is some debate about when the global selection is pasted:
  //   xterm: pastes on up.
  //   GTK: pastes on down.
  //   Qt: pastes on up.
  //   Firefox: pastes on up.
  //   Chromium: pastes on up.
  //
  // There is something of a webcompat angle to this well, as highlighted by
  // crbug.com/14608. Pages can clear text boxes 'onclick' and, if we paste on
  // down then the text is pasted just before the onclick handler runs and
  // clears the text box. So it's important this happens after the event
  // handlers have been fired.
  if (mouse_event.GetType() != WebInputEvent::Type::kMouseUp)
    return false;

  if (!frame_->GetPage())
    return false;
  Frame* focus_frame =
      frame_->GetPage()->GetFocusController().FocusedOrMainFrame();
  // Do not paste here if the focus was moved somewhere else.
  if (frame_ == focus_frame)
    return frame_->GetEditor().ExecuteCommand("PasteGlobalSelection");

  return false;
}

bool SelectionController::HandleGestureLongPress(
    const HitTestResult& hit_test_result) {
  TRACE_EVENT0("blink", "SelectionController::handleGestureLongPress");

  if (!Selection().IsAvailable())
    return false;
  if (!RuntimeEnabledFeatures::LongPressLinkSelectTextEnabled() &&
      hit_test_result.IsLiveLink()) {
    return false;
  }

  Node* inner_node = hit_test_result.InnerPossiblyPseudoNode();
  inner_node->GetDocument().UpdateStyleAndLayoutTree();
  bool inner_node_is_selectable = IsEditable(*inner_node) ||
                                  inner_node->IsTextNode() ||
                                  inner_node->CanStartSelection();
  if (!inner_node_is_selectable)
    return false;

  if (SelectClosestWordFromHitTestResult(hit_test_result,
                                         AppendTrailingWhitespace::kDontAppend,
                                         SelectInputEventType::kTouch))
    return Selection().IsAvailable();

  if (!inner_node->isConnected() || !inner_node->GetLayoutObject())
    return false;
  SetCaretAtHitTestResult(hit_test_result);
  return false;
}

void SelectionController::HandleGestureTwoFingerTap(
    const GestureEventWithHitTestResults& targeted_event) {
  TRACE_EVENT0("blink", "SelectionController::handleGestureTwoFingerTap");

  SetCaretAtHitTestResult(targeted_event.GetHitTestResult());
}

static bool HitTestResultIsMisspelled(const HitTestResult& result) {
  PositionWithAffinity pos_with_affinity = result.GetPosition();
  if (pos_with_affinity.IsNull())
    return false;
  // TODO(xiaochengh): Don't use |ParentAnchoredEquivalent()|.
  const Position marker_position =
      pos_with_affinity.GetPosition().ParentAnchoredEquivalent();
  if (!SpellChecker::IsSpellCheckingEnabledAt(marker_position))
    return false;
  return SpellCheckMarkerGroupAtPosition(
      result.InnerPossiblyPseudoNode()->GetDocument().Markers(),
      ToPositionInFlatTree(marker_position));
}

template <typename MouseEventObject>
void SelectionController::UpdateSelectionForContextMenuEvent(
    const MouseEventObject* mouse_event,
    const HitTestResult& hit_test_result,
    const PhysicalOffset& position) {
  if (!Selection().IsAvailable())
    return;
  if (mouse_down_was_single_click_on_caret_ || Selection().Contains(position) ||
      hit_test_result.GetScrollbar() ||
      // FIXME: In the editable case, word selection sometimes selects content
      // that isn't underneath the mouse.
      // If the selection is non-editable, we do word selection to make it
      // easier to use the contextual menu items available for text selections.
      // But only if we're above text.
      !(Selection()
            .ComputeVisibleSelectionInDOMTreeDeprecated()
            .IsContentEditable() ||
        (hit_test_result.InnerNode() &&
         hit_test_result.InnerNode()->IsTextNode()))) {
    return;
  }

  // Context menu events are always allowed to perform a selection.
  base::AutoReset<bool> mouse_down_may_start_select_change(
      &mouse_down_may_start_select_, true);

  if (mouse_event->GetMenuSourceType() != kMenuSourceTouchHandle &&
      HitTestResultIsMisspelled(hit_test_result)) {
    return SelectClosestMisspellingFromMouseEvent(mouse_event, hit_test_result);
  }

  if (!frame_->GetEditor().Behavior().ShouldSelectOnContextualMenuClick())
    return;

  // Opening a context menu from an existing text fragment/highlight should not
  // select additional text.
  if (TextFragmentHandler::IsOverTextFragment(hit_test_result))
    return;

  // Opening the context menu, triggered by long press or keyboard, should not
  // change the selected text.
  if (mouse_event->GetMenuSourceType() == kMenuSourceLongPress ||
      mouse_event->GetMenuSourceType() == kMenuSourceKeyboard) {
    return;
  }

  SelectClosestWordOrLinkFromMouseEvent(mouse_event, hit_test_result);
}

void SelectionController::PassMousePressEventToSubframe(
    const MouseEventWithHitTestResults& mev) {
  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  frame_->GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kInput);

  // If we're clicking into a frame that is selected, the frame will appear
  // greyed out even though we're clicking on the selection.  This looks
  // really strange (having the whole frame be greyed out), so we deselect the
  // selection.
  PhysicalOffset p(frame_->View()->ConvertFromRootFrame(
      gfx::ToFlooredPoint(mev.Event().PositionInRootFrame())));
  if (!Selection().Contains(p))
    return;

  const PositionInFlatTreeWithAffinity visible_pos =
      CreateVisiblePosition(
          PositionWithAffinityOfHitTestResult(mev.GetHitTestResult()))
          .ToPositionWithAffinity();
  if (visible_pos.IsNull()) {
    Selection().SetSelectionAndEndTyping(SelectionInDOMTree());
    return;
  }
  Selection().SetSelectionAndEndTyping(ConvertToSelectionInDOMTree(
      SelectionInFlatTree::Builder().Collapse(visible_pos).Build()));
}

void SelectionController::InitializeSelectionState() {
  selection_state_ = SelectionState::kHaveNotStartedSelection;
}

void SelectionController::SetMouseDownMayStartSelect(bool may_start_select) {
  mouse_down_may_start_select_ = may_start_select;
}

bool SelectionController::MouseDownMayStartSelect() const {
  return mouse_down_may_start_select_;
}

bool SelectionController::MouseDownWasSingleClickInSelection() const {
  return mouse_down_was_single_click_in_selection_;
}

void SelectionController::NotifySelectionChanged() {
  // To avoid regression on speedometer benchmark[1] test, we should not
  // update layout tree in this code block.
  // [1] http://browserbench.org/Speedometer/
  DocumentLifecycle::DisallowTransitionScope disallow_transition(
      frame_->GetDocument()->Lifecycle());

  const SelectionInDOMTree& selection = Selection().GetSelectionInDOMTree();
  if (selection.IsNone()) {
    selection_state_ = SelectionState::kHaveNotStartedSelection;
    return;
  }
  if (selection.IsCaret()) {
    selection_state_ = SelectionState::kPlacedCaret;
    return;
  }
  DCHECK(selection.IsRange()) << selection;
  selection_state_ = SelectionState::kExtendedSelection;
}

FrameSelection& SelectionController::Selection() const {
  return frame_->Selection();
}

bool IsSelectionOverLink(const MouseEventWithHitTestResults& event) {
  return (event.Event().GetModifiers() & WebInputEvent::Modifiers::kAltKey) !=
             0 &&
         event.IsOverLink();
}

bool IsUserNodeDraggable(const MouseEventWithHitTestResults& event) {
  Node* inner_node = event.InnerNode();

  // TODO(huangdarwin): event.InnerNode() should never be nullptr, but unit
  // tests WebFrameTest.FrameWidgetTest and WebViewTest.ClientTapHandling fail
  // without a nullptr check, as they don't set the InnerNode() appropriately.
  // Remove the if statement nullptr check when those tests are fixed.
  if (!inner_node) {
    return false;
  }

  const ComputedStyle* style =
      inner_node->GetComputedStyleForElementOrLayoutObject();
  return style && style->UserDrag() == EUserDrag::kElement;
}

bool IsExtendingSelection(const MouseEventWithHitTestResults& event) {
  bool is_mouse_down_on_link_or_image =
      event.IsOverLink() || event.GetHitTestResult().GetImage();

  return (event.Event().GetModifiers() & WebInputEvent::Modifiers::kShiftKey) !=
             0 &&
         !is_mouse_down_on_link_or_image && !IsUserNodeDraggable(event);
}

template void SelectionController::UpdateSelectionForContextMenuEvent<
    MouseEvent>(const MouseEvent*, const HitTestResult&, const PhysicalOffset&);

}  // namespace blink

"""


```