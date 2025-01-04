Response:
The user wants a summary of the functionalities provided by the given C++ code snippet from `blink/renderer/core/editing/frame_selection.cc`. The summary should include connections to web technologies (JavaScript, HTML, CSS), logical reasoning with input/output examples, common user/programming errors, and debugging tips. Since this is part 2 of 2, the final output should focus on summarizing the functionalities covered in *this* specific snippet.

Here's a breakdown of the code's functionality:

1. **`SelectFrameElementInParentIfFullySelected()`**: Selects the iframe in the parent frame if the iframe's content is fully selected.
2. **`NonBoundaryShadowTreeRootNode()`**: Helper function to find the root node of a non-boundary shadow tree.
3. **`SelectAll()` (multiple overloads)**: Selects all content within the current frame or a specific element. It handles user-initiated and system-initiated selections, and integrates with `selectstart` events.
4. **`SelectSubString()`**: Selects a substring within an SVG text control element.
5. **`NotifyAccessibilityForSelectionChange()`**: Notifies accessibility features about changes in the selection.
6. **`NotifyCompositorForSelectionChange()`**: Notifies the compositor about selection changes for optimized rendering.
7. **`NotifyEventHandlerForSelectionChange()`**: Notifies the event handler about selection changes.
8. **`NotifyDisplayLockForSelectionChange()`**: Manages display locks related to selection changes, especially across documents.
9. **`FocusedOrActiveStateChanged()`**: Handles updates when the frame's focus or active state changes, affecting styling and caret visibility.
10. **`PageActivationChanged()`**:  A specific case of focus/active state change tied to page activation.
11. **`SetFrameIsFocused()`**: Sets the focused state of the frame.
12. **`FrameIsFocusedAndActive()`**: Checks if the frame is both focused and active.
13. **`CommitAppearanceIfNeeded()`**: Commits any pending visual updates related to the selection.
14. **`DidLayout()`**:  Handles actions after a layout operation, often triggering visual updates.
15. **`UpdateAppearance()`**: Updates the visual representation of the selection.
16. **`NotifyTextControlOfSelectionChange()`**: Informs text control elements about selection changes.
17. **`SetFocusedNodeIfNeeded()`**: Sets focus to an appropriate element based on the current selection.
18. **`ComputeRangeForSerialization()`**:  Prepares the selection range for serialization.
19. **`ExtractSelectedText()`**: Extracts the selected text content.
20. **`SelectedHTMLForClipboard()`**: Generates HTML markup for the selected content, suitable for the clipboard.
21. **`SelectedText()` (multiple overloads)**: Retrieves the selected text.
22. **`SelectedTextForClipboard()`**: Gets the selected text optimized for clipboard operations.
23. **`AbsoluteUnclippedBounds()`**: Calculates the absolute, unclipped bounding rectangle of the selection.
24. **`ComputeRectToScroll()`**: Determines the rectangle that needs to be scrolled to make the selection visible.
25. **`RevealSelection()`**: Scrolls the selection into view.
26. **`SetSelectionFromNone()`**: Sets an initial caret position when there's no existing selection.
27. **`ShowTreeForThis()` (debug function)**:  Displays the structure related to the current selection.
28. **`Trace()`**:  Used for debugging and memory management.
29. **`ScheduleVisualUpdate()`**:  Requests a visual update for the frame.
30. **`ScheduleVisualUpdateForVisualOverflowIfNeeded()`**: Requests a visual update specifically for visual overflow.
31. **`SelectWordAroundCaret()`**: Selects the word surrounding the caret.
32. **`SelectAroundCaret()`**: Selects text around the caret based on granularity (word or sentence).
33. **`GetWordSelectionRangeAroundCaret()`**: Gets the range of the word around the caret.
34. **`GetSelectionRangeAroundCaretForTesting()`**:  A testing variant for getting the range around the caret.
35. **`GetGranularityStrategy()`**:  Retrieves the strategy used for selection granularity.
36. **`MoveRangeSelectionExtent()`**:  Adjusts the extent of a range selection based on a point.
37. **`MoveRangeSelection()`**: Moves a range selection to a new base and extent point.
38. **`MoveRangeSelectionInternal()`**:  Internal implementation for moving range selections.
39. **`SetCaretEnabled()`**:  Enables or disables the caret.
40. **`SetCaretBlinkingSuspended()`**:  Suspends or resumes caret blinking.
41. **`IsCaretBlinkingSuspended()`**: Checks if caret blinking is suspended.
42. **`CacheRangeOfDocument()`**: Caches a range object.
43. **`DocumentCachedRange()`**: Retrieves the cached range object.
44. **`ClearDocumentCachedRange()`**: Clears the cached range object.
45. **`ComputeLayoutSelectionStatus()`**:  Determines the layout status of the selection.
46. **`ComputePaintingSelectionStateForCursor()`**: Gets the painting state for a cursor position within the selection.
47. **`IsDirectional()`**:  Indicates if the selection is directional.
48. **`MarkCacheDirty()`**: Marks the selection cache as needing an update.
49. **`GetSelectionRangeAroundCaret()`**: Retrieves the range around the caret based on granularity (word or sentence).
50. **`GetSelectionRangeAroundPosition()`**: Gets the selection range around a specific position.
这是 `blink/renderer/core/editing/frame_selection.cc` 源代码文件的第二部分，延续了第一部分的功能，主要负责管理和操作一个特定框架（`Frame`）内的文本或元素的选中状态。以下是这部分代码功能的归纳总结：

**核心功能总结：**

1. **跨框架选择支持 (有限):**
   - `SelectFrameElementInParentIfFullySelected()`:  当一个 iframe 的内容被完全选中时，尝试在父框架中选中这个 iframe 元素本身。**限制：** 注释明确指出此功能尚未为跨进程（OOPI - Out-of-Process Iframes）的框架关系实现。

2. **全选功能 (`SelectAll`)：**
   - 提供了多种 `SelectAll` 的实现，允许用户或系统触发全选操作。
   - 针对 `<select>` 元素有特殊处理，会调用其自身的 `SelectAll()` 方法。
   - 对于可编辑内容，全选操作会以最高级的可编辑根节点为范围。
   - 涉及到 `selectstart` 事件的派发，允许脚本取消全选操作。
   - 可以控制是否需要进行布局更新（`canonicalize_selection`）。
   - 完成全选操作后，可能会选中父框架中的框架元素。
   - 会通知相关的文本控件和显示上下文菜单（如果句柄可见）。

3. **子字符串选择 (`SelectSubString`)：**
   - `SelectSubString()` 方法允许在 SVG 文本控制元素中选择指定偏移量和长度的子字符串。

4. **通知机制 (Accessibility, Compositor, Event Handler, Display Lock):**
   - 提供了多个通知方法，当选择发生变化时，会通知不同的组件：
     - `NotifyAccessibilityForSelectionChange()`: 通知辅助功能模块。
     - `NotifyCompositorForSelectionChange()`: 通知合成器，用于优化渲染性能。
     - `NotifyEventHandlerForSelectionChange()`: 通知事件处理模块。
     - `NotifyDisplayLockForSelectionChange()`: 管理与选择相关的显示锁，尤其是在跨文档的情况下。

5. **焦点和激活状态管理：**
   - `FocusedOrActiveStateChanged()`: 当框架的焦点或激活状态改变时，会触发样式失效、重绘，并更新光标的显示。
   - `PageActivationChanged()`: 页面激活状态改变时的处理，本质上也是焦点/激活状态的改变。
   - `SetFrameIsFocused()`: 设置框架的焦点状态。
   - `FrameIsFocusedAndActive()`: 判断框架是否同时处于焦点和激活状态。

6. **视觉更新：**
   - `CommitAppearanceIfNeeded()`: 提交与选择相关的视觉外观更新。
   - `DidLayout()`: 在布局完成后触发视觉更新。
   - `UpdateAppearance()`: 更新选择的视觉表现。

7. **通知文本控件选择变化：**
   - `NotifyTextControlOfSelectionChange()`: 当选择发生变化时，通知包含该选择的文本控件元素。

8. **自动设置焦点节点：**
   - `SetFocusedNodeIfNeeded()`:  根据当前的选中状态，尝试将焦点设置到合适的元素上。会避免将焦点设置到子框架上。

9. **序列化和文本提取：**
   - `ComputeRangeForSerialization()`:  计算用于序列化的选择范围。
   - `ExtractSelectedText()`: 提取选中的纯文本内容。
   - `SelectedHTMLForClipboard()`:  生成用于剪贴板的选中内容的 HTML 代码。
   - `SelectedText()`: 获取选中的文本内容 (提供多种重载，可以指定文本迭代器的行为)。
   - `SelectedTextForClipboard()`:  获取适合剪贴板的选中文本，可以包含图片 alt 文本等。

10. **获取选择范围和边界：**
    - `AbsoluteUnclippedBounds()`: 获取选择的绝对、未裁剪的边界矩形。
    - `ComputeRectToScroll()`: 计算需要滚动才能使选择可见的矩形区域。

11. **滚动选择到可见区域：**
    - `RevealSelection()`:  根据指定的对齐方式将选择滚动到可见区域。

12. **从无选择状态设置初始光标：**
    - `SetSelectionFromNone()`: 当框架没有选择时，尝试在 body 元素内设置一个初始光标位置。

13. **调试辅助：**
    - `ShowTreeForThis()` (在 `DCHECK_IS_ON()` 宏下启用): 打印与当前选择相关的树结构，用于调试。

14. **追踪对象：**
    - `Trace()`: 用于追踪对象的生命周期，主要用于 Blink 的垃圾回收机制。

15. **触发视觉更新：**
    - `ScheduleVisualUpdate()`: 调度一个视觉更新。
    - `ScheduleVisualUpdateForVisualOverflowIfNeeded()`:  根据需要调度视觉溢出的更新。

16. **基于光标的选择：**
    - `SelectWordAroundCaret()`: 选中光标周围的单词。
    - `SelectAroundCaret()`: 根据指定的粒度（单词或句子）选中光标周围的文本。
    - `GetWordSelectionRangeAroundCaret()`: 获取光标周围单词的选择范围。
    - `GetSelectionRangeAroundCaretForTesting()`: 用于测试获取光标周围的选择范围。

17. **选择粒度策略：**
    - `GetGranularityStrategy()`: 获取当前使用的选择粒度策略（例如，按字符或按方向）。

18. **移动和调整选择范围：**
    - `MoveRangeSelectionExtent()`: 根据给定的屏幕坐标移动选择范围的终点。
    - `MoveRangeSelection()`: 根据给定的起始和终点屏幕坐标移动选择范围。
    - `MoveRangeSelectionInternal()`:  内部实现，用于移动选择范围。

19. **光标控制：**
    - `SetCaretEnabled()`: 启用或禁用光标。
    - `SetCaretBlinkingSuspended()`: 暂停或恢复光标闪烁。
    - `IsCaretBlinkingSuspended()`: 查询光标闪烁是否被暂停。

20. **缓存 Range 对象：**
    - `CacheRangeOfDocument()`: 缓存一个 `Range` 对象，可能用于性能优化。
    - `DocumentCachedRange()`: 获取缓存的 `Range` 对象。
    - `ClearDocumentCachedRange()`: 清除缓存的 `Range` 对象。

21. **布局和绘制状态：**
    - `ComputeLayoutSelectionStatus()`: 计算选择的布局状态。
    - `ComputePaintingSelectionStateForCursor()`: 计算光标位置的选择绘制状态。

22. **方向性选择：**
    - `IsDirectional()`:  指示选择是否是方向性的。

23. **标记缓存失效：**
    - `MarkCacheDirty()`: 标记选择相关的缓存为脏，需要更新。

24. **获取指定位置周围的选择范围：**
    - `GetSelectionRangeAroundCaret()`: 获取光标周围的单词或句子的选择范围。
    - `GetSelectionRangeAroundPosition()`: 获取指定位置周围的单词或句子的选择范围。

**与 JavaScript, HTML, CSS 的关系举例：**

* **JavaScript:**
    * 当用户在网页上进行选择操作时，JavaScript 可以通过监听 `selectionchange` 事件来感知到，而 `FrameSelection` 模块正是负责维护和更新这个选择状态。
    * JavaScript 可以调用 `window.getSelection()` API 来获取当前的选择对象，这个对象背后就关联着 `FrameSelection` 提供的数据和功能。
    * `SelectAll()` 功能可以响应 JavaScript 调用 `document.execCommand('selectAll')`。
    * `selectstart` 事件的派发允许 JavaScript 脚本在选择开始前进行干预，例如取消选择。

* **HTML:**
    * 用户在可编辑的 HTML 元素（例如 `<textarea>`, 带有 `contenteditable` 属性的元素）中进行选择操作时，`FrameSelection` 负责跟踪和管理这些选择。
    * `SelectFrameElementInParentIfFullySelected()` 与 `<iframe>` 和 `<frame>` 元素相关。
    * `<select>` 元素的全选操作有特殊的处理逻辑。

* **CSS:**
    * 选中文本的样式（例如背景色）是由浏览器的 CSS 样式规则控制的。当 `FrameSelection` 中的选择发生变化时，会触发浏览器的重绘流程，应用相应的 CSS 样式。
    * 焦点状态的改变（由 `FocusedOrActiveStateChanged()` 处理）会影响 `:focus` 等 CSS 伪类，从而改变元素的样式。

**逻辑推理的假设输入与输出举例：**

**假设输入：** 用户在一个 `contenteditable` 的 `<div>` 元素中双击了一个单词 "example"。

**`GetSelectionRangeAroundCaret()` 输出：** 将会返回包含 "example" 这个单词的 `EphemeralRange` 对象，起始和结束位置会包围这个单词。

**假设输入：** JavaScript 调用了 `document.execCommand('selectAll')`。

**`SelectAll(SetSelectionBy::kUser, false)` 输出：**  如果当前焦点在可编辑区域，则会选中该可编辑区域内的所有内容。如果焦点在整个文档上，则会选中整个文档的内容。

**用户或编程常见的使用错误举例：**

* **用户错误：**  用户可能在不希望被选中的元素上意外触发了全选操作。
* **编程错误：**  开发者在处理 `selectstart` 事件时，如果错误地修改了 DOM 结构，可能会导致 `FrameSelection` 的状态与实际 DOM 不一致，引发错误。例如，在 `selectstart` 事件处理中移除了正在被选择的节点。

**用户操作如何一步步到达这里 (作为调试线索)：**

1. **用户点击并拖拽鼠标：**  用户在页面上点击并拖动鼠标来选择文本。这会触发浏览器的鼠标事件，最终导致 `FrameSelection` 中的选择状态更新。
2. **用户双击或三击文本：**  用户双击会选中一个单词，三击会选中一行或一个段落。这些操作会调用 `FrameSelection` 中与基于光标的选择相关的方法（例如 `SelectWordAroundCaret()`）。
3. **用户按下 Ctrl+A (或 Cmd+A)：** 用户按下全选快捷键，会触发浏览器的键盘事件，最终调用 `FrameSelection::SelectAll()`。
4. **JavaScript 调用选择 API：**  JavaScript 代码可以通过 `window.getSelection()` 获取选择对象，并调用其方法（例如 `removeAllRanges()`, `addRange()`）来修改选择，这些操作会间接地调用 `FrameSelection` 的相关功能。
5. **在 iframe 中操作：** 用户在 `iframe` 内部进行选择操作，相关的事件和选择状态会传递到 `iframe` 的 `FrameSelection` 对象进行处理。如果涉及到跨框架的选择，则会涉及到父框架的 `FrameSelection` 对象。

总而言之，`FrameSelection` 是 Blink 引擎中负责管理和操作文本或元素选择的核心模块，它与用户的交互行为以及 JavaScript 和 CSS 的渲染紧密相关。这部分代码涵盖了从基本的选择操作到复杂的跨框架选择、事件通知和视觉更新等功能。

Prompt: 
```
这是目录为blink/renderer/core/editing/frame_selection.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
d()))
    return;

  // FIXME: This is not yet implemented for cross-process frame relationships.
  auto* parent_local_frame = DynamicTo<LocalFrame>(parent);
  if (!parent_local_frame)
    return;

  // Get to the <iframe> or <frame> (or even <object>) element in the parent
  // frame.
  // FIXME: Doesn't work for OOPI.
  HTMLFrameOwnerElement* owner_element = frame_->DeprecatedLocalOwner();
  if (!owner_element)
    return;
  ContainerNode* owner_element_parent = owner_element->parentNode();
  if (!owner_element_parent)
    return;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. See http://crbug.com/590369 for more details.
  owner_element_parent->GetDocument().UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  // This method's purpose is it to make it easier to select iframes (in order
  // to delete them).  Don't do anything if the iframe isn't deletable.
  if (!blink::IsEditable(*owner_element_parent))
    return;

  // Focus on the parent frame, and then select from before this element to
  // after.
  page->GetFocusController().SetFocusedFrame(parent);
  // SetFocusedFrame can dispatch synchronous focus/blur events.  The document
  // tree might be modified.
  if (!owner_element->isConnected() ||
      owner_element->GetDocument() != parent_local_frame->GetDocument())
    return;
  parent_local_frame->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position::BeforeNode(*owner_element),
                            Position::AfterNode(*owner_element))
          .Build(),
      SetSelectionOptions());
}

// Returns a shadow tree node for legacy shadow trees, a child of the
// ShadowRoot node for new shadow trees, or 0 for non-shadow trees.
static Node* NonBoundaryShadowTreeRootNode(const Position& position) {
  return position.AnchorNode() && !position.AnchorNode()->IsShadowRoot()
             ? position.AnchorNode()->NonBoundaryShadowTreeRootNode()
             : nullptr;
}

void FrameSelection::SelectAll(SetSelectionBy set_selection_by,
                               bool canonicalize_selection) {
  if (auto* select_element =
          DynamicTo<HTMLSelectElement>(GetDocument().FocusedElement())) {
    if (select_element->CanSelectAll()) {
      select_element->SelectAll();
      return;
    }
  }

  Node* root = nullptr;
  Node* select_start_target = nullptr;
  if (set_selection_by == SetSelectionBy::kUser && IsHidden()) {
    // Hidden selection appears as no selection to user, in which case user-
    // triggered SelectAll should act as if there is no selection.
    root = GetDocument().documentElement();
    select_start_target = GetDocument().body();
  } else if (ComputeVisibleSelectionInDOMTree().IsContentEditable()) {
    root = HighestEditableRoot(ComputeVisibleSelectionInDOMTree().Start());
    if (Node* shadow_root = NonBoundaryShadowTreeRootNode(
            ComputeVisibleSelectionInDOMTree().Start()))
      select_start_target = shadow_root->OwnerShadowHost();
    else
      select_start_target = root;
  } else {
    root = NonBoundaryShadowTreeRootNode(
        ComputeVisibleSelectionInDOMTree().Start());
    if (root) {
      select_start_target = root->OwnerShadowHost();
    } else {
      root = GetDocument().documentElement();
      select_start_target = GetDocument().body();
    }
  }
  if (!root || EditingIgnoresContent(*root))
    return;

  if (select_start_target) {
    const Document& expected_document = GetDocument();
    if (select_start_target->DispatchEvent(
            *Event::CreateCancelableBubble(event_type_names::kSelectstart)) !=
        DispatchEventResult::kNotCanceled)
      return;
    // The frame may be detached due to selectstart event.
    if (!IsAvailable()) {
      // Reached by editing/selection/selectstart_detach_frame.html
      return;
    }
    // |root| may be detached due to selectstart event.
    if (!root->isConnected() || expected_document != root->GetDocument())
      return;
  }

  const SelectionInDOMTree& dom_selection =
      SelectionInDOMTree::Builder().SelectAllChildren(*root).Build();
  if (canonicalize_selection) {
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  }
  SetSelection(canonicalize_selection
                   ? CreateVisibleSelection(dom_selection).AsSelection()
                   : dom_selection,
               SetSelectionOptions::Builder()
                   .SetShouldCloseTyping(true)
                   .SetShouldClearTypingStyle(true)
                   .SetShouldShowHandle(IsHandleVisible())
                   .Build());

  SelectFrameElementInParentIfFullySelected();
  // TODO(editing-dev): Should we pass in set_selection_by?
  NotifyTextControlOfSelectionChange(SetSelectionBy::kUser);
  if (IsHandleVisible()) {
    ContextMenuAllowedScope scope;
    frame_->GetEventHandler().ShowNonLocatedContextMenu(nullptr,
                                                        kMenuSourceTouch);
  }
}

void FrameSelection::SelectAll() {
  SelectAll(SetSelectionBy::kSystem, false);
}

// Implementation of |SVGTextControlElement::selectSubString()|
void FrameSelection::SelectSubString(const Element& element,
                                     int offset,
                                     int length) {
  // Find selection start
  VisiblePosition start = VisiblePosition::FirstPositionInNode(element);
  for (int i = 0; i < offset; ++i)
    start = NextPositionOf(start);
  if (start.IsNull())
    return;

  // Find selection end
  VisiblePosition end(start);
  for (int i = 0; i < length; ++i)
    end = NextPositionOf(end);
  if (end.IsNull())
    return;

  // TODO(editing-dev): We assume |start| and |end| are not null and we don't
  // known when |start| and |end| are null. Once we get a such case, we check
  // null for |start| and |end|.
  SetSelectionAndEndTyping(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(start.DeepEquivalent(), end.DeepEquivalent())
          .SetAffinity(start.Affinity())
          .Build());
}

void FrameSelection::NotifyAccessibilityForSelectionChange() {
  AXObjectCache* cache = GetDocument().ExistingAXObjectCache();
  if (!cache)
    return;
  Node* anchor = GetSelectionInDOMTree().Focus().ComputeContainerNode();
  if (anchor) {
    cache->SelectionChanged(anchor);
  } else {
    cache->SelectionChanged(RootEditableElementOrDocumentElement());
  }
}

void FrameSelection::NotifyCompositorForSelectionChange() {
  if (!RuntimeEnabledFeatures::CompositedSelectionUpdateEnabled())
    return;

  ScheduleVisualUpdate();
}

void FrameSelection::NotifyEventHandlerForSelectionChange() {
  frame_->GetEventHandler().GetSelectionController().NotifySelectionChanged();
}

void FrameSelection::NotifyDisplayLockForSelectionChange(
    Document& document,
    const SelectionInDOMTree& old_selection,
    const SelectionInDOMTree& new_selection) {
  if (DisplayLockUtilities::NeedsSelectionChangedUpdate(document) ||
      (!old_selection.IsNone() && old_selection.GetDocument() != document &&
       DisplayLockUtilities::NeedsSelectionChangedUpdate(
           *old_selection.GetDocument()))) {
    // The old selection might not be valid, and thus not iterable. If
    // that's the case, notify that all selection was removed and use an empty
    // range as the old selection.
    EphemeralRangeInFlatTree old_range;
    if (old_selection.IsValidFor(document)) {
      old_range = ToEphemeralRangeInFlatTree(old_selection.ComputeRange());
    } else {
      DisplayLockUtilities::SelectionRemovedFromDocument(document);
    }
    DisplayLockUtilities::SelectionChanged(
        old_range, ToEphemeralRangeInFlatTree(new_selection.ComputeRange()));
  }
}

void FrameSelection::FocusedOrActiveStateChanged() {
  bool active_and_focused = FrameIsFocusedAndActive();

  // Trigger style invalidation from the focused element. Even though
  // the focused element hasn't changed, the evaluation of focus pseudo
  // selectors are dependent on whether the frame is focused and active.
  if (Element* element = GetDocument().FocusedElement()) {
    element->FocusStateChanged();
  }

  // Selection style may depend on the active state of the document, so style
  // and paint must be invalidated when active status changes.
  if (GetDocument().GetLayoutView()) {
    layout_selection_->InvalidateStyleAndPaintForSelection();
  }
  GetDocument().UpdateStyleAndLayoutTree();

  // Caret appears in the active frame.
  if (active_and_focused) {
    SetSelectionFromNone();
  }
  frame_caret_->SetCaretEnabled(active_and_focused);

  // Update for caps lock state
  frame_->GetEventHandler().CapsLockStateMayHaveChanged();
}

void FrameSelection::PageActivationChanged() {
  FocusedOrActiveStateChanged();
}

void FrameSelection::SetFrameIsFocused(bool flag) {
  if (focused_ == flag)
    return;
  focused_ = flag;

  FocusedOrActiveStateChanged();
}

bool FrameSelection::FrameIsFocusedAndActive() const {
  return focused_ && frame_->GetPage() &&
         frame_->GetPage()->GetFocusController().IsActive();
}

void FrameSelection::CommitAppearanceIfNeeded() {
  return layout_selection_->Commit();
}

void FrameSelection::DidLayout() {
  UpdateAppearance();
}

void FrameSelection::UpdateAppearance() {
  DCHECK(frame_->ContentLayoutObject());
  frame_caret_->ScheduleVisualUpdateForPaintInvalidationIfNeeded();
  layout_selection_->SetHasPendingSelection();
}

void FrameSelection::NotifyTextControlOfSelectionChange(
    SetSelectionBy set_selection_by) {
  TextControlElement* text_control =
      EnclosingTextControl(GetSelectionInDOMTree().Anchor());
  if (!text_control)
    return;
  text_control->SelectionChanged(set_selection_by == SetSelectionBy::kUser);
}

// Helper function that tells whether a particular node is an element that has
// an entire LocalFrame and LocalFrameView, a <frame>, <iframe>, or <object>.
static bool IsFrameElement(const Node* n) {
  if (!n)
    return false;
  if (auto* embedded = DynamicTo<LayoutEmbeddedContent>(n->GetLayoutObject()))
    return embedded->ChildFrameView();
  return false;
}

void FrameSelection::SetFocusedNodeIfNeeded() {
  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);

  if (ComputeVisibleSelectionInDOMTree().IsNone() || !FrameIsFocused()) {
    return;
  }

  if (Element* target =
          ComputeVisibleSelectionInDOMTree().RootEditableElement()) {
    // Walk up the DOM tree to search for a node to focus.
    GetDocument().UpdateStyleAndLayoutTree();
    while (target) {
      // We don't want to set focus on a subframe when selecting in a parent
      // frame, so add the !isFrameElement check here. There's probably a better
      // way to make this work in the long term, but this is the safest fix at
      // this time.
      if (target->IsFocusable() && !IsFrameElement(target)) {
        frame_->GetPage()->GetFocusController().SetFocusedElement(target,
                                                                  frame_);
        return;
      }
      if (RuntimeEnabledFeatures::MouseFocusFlatTreeParentEnabled()) {
        target = FlatTreeTraversal::ParentElement(*target);
      } else {
        target = target->ParentOrShadowHostElement();
      }
    }
    GetDocument().ClearFocusedElement();
  }
}

static EphemeralRangeInFlatTree ComputeRangeForSerialization(
    const SelectionInDOMTree& selection_in_dom_tree) {
  const SelectionInFlatTree& selection =
      ConvertToSelectionInFlatTree(selection_in_dom_tree);
  // TODO(crbug.com/1019152): Once we know the root cause of having
  // seleciton with |Anchor().IsNull() != Focus().IsNull()|, we should get rid
  // of this if-statement.
  if (selection.Anchor().IsNull() || selection.Focus().IsNull()) {
    DCHECK(selection.IsNone());
    return EphemeralRangeInFlatTree();
  }
  const EphemeralRangeInFlatTree& range = selection.ComputeRange();
  const PositionInFlatTree& start =
      CreateVisiblePosition(range.StartPosition()).DeepEquivalent();
  const PositionInFlatTree& end =
      CreateVisiblePosition(range.EndPosition()).DeepEquivalent();
  if (start.IsNull() || end.IsNull() || start >= end)
    return EphemeralRangeInFlatTree();
  return NormalizeRange(EphemeralRangeInFlatTree(start, end));
}

static String ExtractSelectedText(const FrameSelection& selection,
                                  TextIteratorBehavior behavior) {
  const EphemeralRangeInFlatTree& range =
      ComputeRangeForSerialization(selection.GetSelectionInDOMTree());
  // We remove '\0' characters because they are not visibly rendered to the
  // user.
  return PlainText(range, behavior).Replace(0, "");
}

String FrameSelection::SelectedHTMLForClipboard() const {
  const EphemeralRangeInFlatTree& range =
      ComputeRangeForSerialization(GetSelectionInDOMTree());
  return CreateMarkup(range.StartPosition(), range.EndPosition(),
                      CreateMarkupOptions::Builder()
                          .SetShouldAnnotateForInterchange(true)
                          .SetShouldResolveURLs(kResolveNonLocalURLs)
                          .SetIgnoresCSSTextTransformsForRenderedText(true)
                          .Build());
}

String FrameSelection::SelectedText(
    const TextIteratorBehavior& behavior) const {
  return ExtractSelectedText(*this, behavior);
}

String FrameSelection::SelectedText() const {
  return SelectedText(TextIteratorBehavior());
}

String FrameSelection::SelectedTextForClipboard() const {
  return ExtractSelectedText(
      *this, TextIteratorBehavior::Builder()
                 .SetEmitsImageAltText(
                     frame_->GetSettings() &&
                     frame_->GetSettings()->GetSelectionIncludesAltImageText())
                 .SetSkipsUnselectableContent(true)
                 .SetEntersTextControls(true)
                 .SetIgnoresCSSTextTransforms(true)
                 .Build());
}

PhysicalRect FrameSelection::AbsoluteUnclippedBounds() const {
  LocalFrameView* view = frame_->View();
  LayoutView* layout_view = frame_->ContentLayoutObject();

  if (!view || !layout_view)
    return PhysicalRect();

  return PhysicalRect(layout_selection_->AbsoluteSelectionBounds());
}

gfx::Rect FrameSelection::ComputeRectToScroll(
    RevealExtentOption reveal_extent_option) {
  const VisibleSelection& selection = ComputeVisibleSelectionInDOMTree();
  if (selection.IsCaret())
    return AbsoluteCaretBounds();
  DCHECK(selection.IsRange());
  if (reveal_extent_option == kRevealExtent) {
    return AbsoluteCaretBoundsOf(
        CreateVisiblePosition(selection.Focus()).ToPositionWithAffinity());
  }
  layout_selection_->SetHasPendingSelection();
  return layout_selection_->AbsoluteSelectionBounds();
}

// TODO(editing-dev): This should be done in FlatTree world.
void FrameSelection::RevealSelection(
    const mojom::blink::ScrollAlignment& alignment,
    RevealExtentOption reveal_extent_option) {
  DCHECK(IsAvailable());

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  // Calculation of absolute caret bounds requires clean layout.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);

  const VisibleSelection& selection = ComputeVisibleSelectionInDOMTree();
  if (selection.IsNone())
    return;

  // FIXME: This code only handles scrolling the startContainer's layer, but
  // the selection rect could intersect more than just that.
  if (DocumentLoader* document_loader = frame_->Loader().GetDocumentLoader())
    document_loader->GetInitialScrollState().was_scrolled_by_user = true;
  const Position& start = selection.Start();
  DCHECK(start.AnchorNode());
  if (!start.AnchorNode()->GetLayoutObject()) {
    return;
  }

  // This function is needed to make sure that ComputeRectToScroll below has the
  // sticky offset info available before the computation.
  GetDocument().EnsurePaintLocationDataValidForNode(
      start.AnchorNode(), DocumentUpdateReason::kSelection);
  PhysicalRect selection_rect(ComputeRectToScroll(reveal_extent_option));
  if (selection_rect == PhysicalRect()) {
    return;
  }

  scroll_into_view_util::ScrollRectToVisible(
      *start.AnchorNode()->GetLayoutObject(), selection_rect,
      scroll_into_view_util::CreateScrollIntoViewParams(alignment, alignment));
  UpdateAppearance();
}

void FrameSelection::SetSelectionFromNone() {
  // Put a caret inside the body if the entire frame is editable (either the
  // entire WebView is editable or designMode is on for this document).

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);

  Document* document = frame_->GetDocument();
  if (!ComputeVisibleSelectionInDOMTree().IsNone() ||
      !(blink::IsEditable(*document))) {
    return;
  }

  Element* document_element = document->documentElement();
  if (!document_element)
    return;
  if (HTMLBodyElement* body =
          Traversal<HTMLBodyElement>::FirstChild(*document_element)) {
    SetSelection(SelectionInDOMTree::Builder()
                     .Collapse(FirstPositionInOrBeforeNode(*body))
                     .Build(),
                 SetSelectionOptions());
  }
}

#if DCHECK_IS_ON()

void FrameSelection::ShowTreeForThis() const {
  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);

  ComputeVisibleSelectionInDOMTree().ShowTreeForThis();
}

#endif

void FrameSelection::Trace(Visitor* visitor) const {
  visitor->Trace(frame_);
  visitor->Trace(layout_selection_);
  visitor->Trace(selection_editor_);
  visitor->Trace(frame_caret_);
  SynchronousMutationObserver::Trace(visitor);
}

void FrameSelection::ScheduleVisualUpdate() const {
  if (Page* page = frame_->GetPage())
    page->Animator().ScheduleVisualUpdate(&frame_->LocalFrameRoot());
}

void FrameSelection::ScheduleVisualUpdateForVisualOverflowIfNeeded() const {
  if (LocalFrameView* frame_view = frame_->View())
    frame_view->ScheduleVisualUpdateForVisualOverflowIfNeeded();
}

bool FrameSelection::SelectWordAroundCaret() {
  return SelectAroundCaret(TextGranularity::kWord,
                           HandleVisibility::kNotVisible,
                           ContextMenuVisibility::kNotVisible);
}

bool FrameSelection::SelectAroundCaret(
    TextGranularity text_granularity,
    HandleVisibility handle_visibility,
    ContextMenuVisibility context_menu_visibility) {
  CHECK(text_granularity == TextGranularity::kWord ||
        text_granularity == TextGranularity::kSentence)
      << "Only word and sentence granularities are supported for now";

  EphemeralRange selection_range =
      GetSelectionRangeAroundCaret(text_granularity);
  if (selection_range.IsNull()) {
    return false;
  }

  SetSelection(
      SelectionInDOMTree::Builder()
          .Collapse(selection_range.StartPosition())
          .Extend(selection_range.EndPosition())
          .Build(),
      SetSelectionOptions::Builder()
          .SetShouldCloseTyping(true)
          .SetShouldClearTypingStyle(true)
          .SetGranularity(text_granularity)
          .SetShouldShowHandle(handle_visibility == HandleVisibility::kVisible)
          .Build());

  if (context_menu_visibility == ContextMenuVisibility::kVisible) {
    ContextMenuAllowedScope scope;
    frame_->GetEventHandler().ShowNonLocatedContextMenu(
        /*override_target_element=*/nullptr, kMenuSourceTouch);
  }

  return true;
}

EphemeralRange FrameSelection::GetWordSelectionRangeAroundCaret() const {
  return GetSelectionRangeAroundCaret(TextGranularity::kWord);
}

EphemeralRange FrameSelection::GetSelectionRangeAroundCaretForTesting(
    TextGranularity text_granularity) const {
  return GetSelectionRangeAroundCaret(text_granularity);
}

GranularityStrategy* FrameSelection::GetGranularityStrategy() {
  // We do lazy initialization for granularity_strategy_, because if we
  // initialize it right in the constructor - the correct settings may not be
  // set yet.
  SelectionStrategy strategy_type = SelectionStrategy::kCharacter;
  Settings* settings = frame_ ? frame_->GetSettings() : nullptr;
  if (settings &&
      settings->GetSelectionStrategy() == SelectionStrategy::kDirection)
    strategy_type = SelectionStrategy::kDirection;

  if (granularity_strategy_ &&
      granularity_strategy_->GetType() == strategy_type)
    return granularity_strategy_.get();

  if (strategy_type == SelectionStrategy::kDirection)
    granularity_strategy_ = std::make_unique<DirectionGranularityStrategy>();
  else
    granularity_strategy_ = std::make_unique<CharacterGranularityStrategy>();
  return granularity_strategy_.get();
}

void FrameSelection::MoveRangeSelectionExtent(
    const gfx::Point& contents_point) {
  if (ComputeVisibleSelectionInDOMTree().IsNone())
    return;

  SetSelection(
      SelectionInDOMTree::Builder(
          GetGranularityStrategy()->UpdateExtent(contents_point, frame_))
          .Build(),
      SetSelectionOptions::Builder()
          .SetShouldCloseTyping(true)
          .SetShouldClearTypingStyle(true)
          .SetDoNotClearStrategy(true)
          .SetSetSelectionBy(SetSelectionBy::kUser)
          .SetShouldShowHandle(true)
          .Build());
}

void FrameSelection::MoveRangeSelection(const gfx::Point& base_point,
                                        const gfx::Point& extent_point,
                                        TextGranularity granularity) {
  const VisiblePosition& base_position =
      CreateVisiblePosition(PositionForContentsPointRespectingEditingBoundary(
          base_point, GetFrame()));
  const VisiblePosition& extent_position =
      CreateVisiblePosition(PositionForContentsPointRespectingEditingBoundary(
          extent_point, GetFrame()));
  MoveRangeSelectionInternal(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtentDeprecated(base_position.DeepEquivalent(),
                                      extent_position.DeepEquivalent())
          .SetAffinity(base_position.Affinity())
          .Build(),
      granularity);
}

void FrameSelection::MoveRangeSelectionInternal(
    const SelectionInDOMTree& new_selection,
    TextGranularity granularity) {
  if (new_selection.IsNone())
    return;

  const SelectionInDOMTree& selection =
      ExpandWithGranularity(new_selection, granularity);
  if (selection.IsNone())
    return;

  SetSelection(selection, SetSelectionOptions::Builder()
                              .SetShouldCloseTyping(true)
                              .SetShouldClearTypingStyle(true)
                              .SetGranularity(granularity)
                              .SetShouldShowHandle(IsHandleVisible())
                              .Build());
}

void FrameSelection::SetCaretEnabled(bool enabled) {
  frame_caret_->SetCaretEnabled(enabled);
}

void FrameSelection::SetCaretBlinkingSuspended(bool suspended) {
  frame_caret_->SetCaretBlinkingSuspended(suspended);
}

bool FrameSelection::IsCaretBlinkingSuspended() const {
  return frame_caret_->IsCaretBlinkingSuspended();
}

void FrameSelection::CacheRangeOfDocument(Range* range) {
  selection_editor_->CacheRangeOfDocument(range);
}

Range* FrameSelection::DocumentCachedRange() const {
  return selection_editor_->DocumentCachedRange();
}

void FrameSelection::ClearDocumentCachedRange() {
  selection_editor_->ClearDocumentCachedRange();
}

LayoutSelectionStatus FrameSelection::ComputeLayoutSelectionStatus(
    const InlineCursor& cursor) const {
  return layout_selection_->ComputeSelectionStatus(cursor);
}

SelectionState FrameSelection::ComputePaintingSelectionStateForCursor(
    const InlineCursorPosition& position) const {
  return layout_selection_->ComputePaintingSelectionStateForCursor(position);
}

bool FrameSelection::IsDirectional() const {
  return is_directional_;
}

void FrameSelection::MarkCacheDirty() {
  selection_editor_->MarkCacheDirty();
}

EphemeralRange FrameSelection::GetSelectionRangeAroundCaret(
    TextGranularity text_granularity) const {
  DCHECK(text_granularity == TextGranularity::kWord ||
         text_granularity == TextGranularity::kSentence)
      << "Only word and sentence granularities are supported for now";

  const VisibleSelection& selection = ComputeVisibleSelectionInDOMTree();
  // TODO(editing-dev): The use of VisibleSelection needs to be audited. See
  // http://crbug.com/657237 for more details.
  if (!selection.IsCaret()) {
    return EphemeralRange();
  }

  // Determine the selection range at each side of the caret, then prefer to set
  // a range that does not start with a separator character.
  const EphemeralRange next_range = GetSelectionRangeAroundPosition(
      text_granularity, selection.Start(), kNextWordIfOnBoundary);
  const String next_text = PlainText(next_range);
  if (!next_text.empty() && !IsSeparator(next_text.CharacterStartingAt(0))) {
    return next_range;
  }

  const EphemeralRange previous_range = GetSelectionRangeAroundPosition(
      text_granularity, selection.Start(), kPreviousWordIfOnBoundary);
  const String previous_text = PlainText(previous_range);
  if (!previous_text.empty() &&
      !IsSeparator(previous_text.CharacterStartingAt(0))) {
    return previous_range;
  }

  // Otherwise, select a range if it contains a non-separator character.
  if (!ContainsOnlySeparatorsOrEmpty(next_text)) {
    return next_range;
  } else if (!ContainsOnlySeparatorsOrEmpty(previous_text)) {
    return previous_range;
  }

  // Otherwise, don't select anything.
  return EphemeralRange();
}

EphemeralRange FrameSelection::GetSelectionRangeAroundPosition(
    TextGranularity text_granularity,
    Position position,
    WordSide word_side) const {
  Position start;
  Position end;
  // Use word granularity by default unless sentence granularity is explicitly
  // requested.
  if (text_granularity == TextGranularity::kSentence) {
    start = StartOfSentencePosition(position);
    end = EndOfSentence(position, SentenceTrailingSpaceBehavior::kOmitSpace)
              .GetPosition();
  } else {
    start = StartOfWordPosition(position, word_side);
    end = EndOfWordPosition(position, word_side);
  }

  // TODO(editing-dev): |StartOfWord()| and |EndOfWord()| should not make null
  // for non-null parameter. See http://crbug.com/872443.
  if (start.IsNull() || end.IsNull()) {
    return EphemeralRange();
  }

  if (start > end) {
    // Since word boundaries are computed on flat tree, they can be reversed
    // when mapped back to DOM.
    std::swap(start, end);
  }

  return EphemeralRange(start, end);
}

}  // namespace blink

#if DCHECK_IS_ON()

void ShowTree(const blink::FrameSelection& sel) {
  sel.ShowTreeForThis();
}

void ShowTree(const blink::FrameSelection* sel) {
  if (sel)
    sel->ShowTreeForThis();
  else
    LOG(INFO) << "Cannot showTree for <null> FrameSelection.";
}

#endif

"""


```