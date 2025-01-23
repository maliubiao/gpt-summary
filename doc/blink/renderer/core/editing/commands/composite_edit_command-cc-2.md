Response:
The user wants a summary of the `composite_edit_command.cc` file in the Chromium Blink engine. I need to extract the functionalities, explain its relation to web technologies (JavaScript, HTML, CSS), provide examples with hypothetical inputs and outputs for logical reasoning sections, illustrate common user/programming errors, describe user interactions leading to this code, and finally, summarize the file's overall purpose.

**Plan:**

1. **Identify core functionalities:** Go through the code and list the main actions and operations performed by the methods in this file.
2. **Relate to web technologies:**  Analyze how these functionalities affect the rendering and behavior of web pages, particularly concerning HTML structure, CSS styling, and potential JavaScript interactions.
3. **Logical reasoning examples:** For methods that involve conditional logic or transformations, create hypothetical scenarios with inputs and expected outputs.
4. **Common errors:**  Think about situations where incorrect usage or unexpected states could lead to issues in this code.
5. **User journey:**  Trace back typical user actions in a web browser that would trigger these editing commands.
6. **Summarize the purpose:** Condense the identified functionalities into a concise description of the file's role within the Blink rendering engine.
好的，这是对 `blink/renderer/core/editing/commands/composite_edit_command.cc` 文件功能的归纳总结：

**核心功能总结:**

`CompositeEditCommand` 类是 Blink 渲染引擎中用于执行一系列编辑操作的基础构建块。它允许将多个小的编辑命令组合成一个单一的、可撤销的、有意义的操作。这个文件中的代码主要负责以下功能：

1. **复合命令管理:**
   - 提供创建、执行和管理由多个子命令组成的复合编辑命令的机制。
   - 维护子命令的列表，并按照添加的顺序执行它们。
   - 跟踪命令的起始和结束选区状态，以便支持撤销/重做。

2. **文本和节点操作:**
   - **插入内容:**  处理各种插入文本、HTML片段的操作，包括处理样式、选择和段落移动等选项 (`ApplyCommandToComposite` 中 `ReplaceSelectionCommand`)。
   - **删除内容:** 虽然代码片段中没有直接的删除命令，但 `ReplaceSelectionCommand` 可以用于替换为空内容，实现删除效果。
   - **拆分和合并节点:** 提供拆分元素 (`SplitElement`) 和移除节点 (`RemoveNode`, `RemoveNodePreservingChildren`) 的功能，用于更精细地修改 DOM 结构。
   - **处理列表:** 专门处理在空列表项中换行的逻辑 (`BreakOutOfEmptyListItem`)，使其能够跳出列表层级或创建新的列表项。
   - **处理引用块:** 处理在空的邮件引用段落中删除操作的逻辑 (`BreakOutOfEmptyMailBlockquotedParagraph`)，使其能够取消引用。

3. **选区管理:**
   - 获取和设置命令执行前后的选区状态 (`SetStartingSelection`, `SetEndingSelection`)，这对于撤销/重做功能至关重要。
   - 提供方法根据偏移量创建选区范围 (`PlainTextRange::CreateRangeForSelection`).
   - 调整插入位置，避免在特定元素边界（例如链接）的边缘插入内容 (`PositionAvoidingSpecialElementBoundary`)。

4. **样式处理:**
   - 应用样式到指定选区 (`ApplyStyle`)。
   - 从空的段落恢复样式。
   - 合并输入样式。

5. **撤销/重做支持:**
   - 创建和管理 `UndoStep` 对象，用于记录命令执行前后的状态，以便支持撤销和重做操作。
   - 将子命令添加到 `UndoStep` 中。

6. **事件触发:**
   - 在编辑操作完成后，触发相应的事件，例如 `editablecontentchanged` 和 `input` 事件 (`AppliedEditing`)。

7. **布局更新:**
   - 在需要时更新文档的样式和布局 (`GetDocument().UpdateStyleAndLayout`)，以确保操作基于最新的 DOM 树和渲染结果。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    - **功能关系:**  `CompositeEditCommand` 的操作直接作用于 HTML 结构，例如插入新的 HTML 元素 (`MakeGarbageCollected<HTMLLIElement>(GetDocument())`)，删除元素，拆分元素等。
    - **举例:**  用户在富文本编辑器中点击“加粗”按钮，可能会触发一个 `CompositeEditCommand`，其中包含一个子命令，用于在选中的文本周围包裹 `<b>` 或 `<strong>` 标签。
* **CSS:**
    - **功能关系:**  该文件中的代码会考虑和修改元素的样式。例如，`ApplyStyle` 函数用于应用 CSS 样式到选区。`ReplaceSelectionCommand` 中可以配置是否保留样式或匹配目标样式。
    - **举例:** 用户在编辑器中选中一段文字并更改其颜色，这会调用 `ApplyStyle`，最终修改选中文字的 `style` 属性或应用相关的 CSS 类。
* **JavaScript:**
    - **功能关系:** JavaScript 可以通过 DOM API (如 `document.execCommand`) 或自定义的事件监听来触发各种编辑操作，这些操作最终会调用 Blink 引擎的编辑命令，包括 `CompositeEditCommand`。
    - **举例:**  一个基于 JavaScript 的富文本编辑器，当用户按下键盘上的某个键时，JavaScript 代码可能会创建一个插入字符的命令，这个命令会被封装在 `CompositeEditCommand` 中执行。

**逻辑推理的假设输入与输出:**

**示例 1: `BreakOutOfEmptyListItem`**

* **假设输入:** 用户在一个空的 `<li>` 标签内按下 Enter 键。当前 DOM 结构类似 `<ul><li><br></li></ul>`。
* **输出:**  DOM 结构会变成 `<ul></ul><div><br></div>` (如果列表是顶层) 或 `<ul><li></li></ul><ul><li><br></li></ul>` (如果列表后面还有兄弟节点)。光标会移动到新创建的 `<div>` 或新的 `<li>` 中。

**示例 2: `BreakOutOfEmptyMailBlockquotedParagraph`**

* **假设输入:** 用户光标位于一个空的 `<blockquote>` 标签内，并且前面没有其他引用内容。DOM 结构类似 `<div><blockquote><br></blockquote></div>`。用户按下 Delete 键。
* **输出:**  `<blockquote>` 标签会被移除，光标会移动到 `<blockquote>` 标签之前，并插入一个 `<br>` 标签。DOM 结构类似 `<div><br></div>`。

**用户或编程常见的使用错误:**

1. **手动操作 DOM 而不通过编辑命令:**  直接使用 JavaScript 修改 DOM 可能会导致 Blink 引擎的编辑状态不同步，从而引发不可预测的行为或撤销/重做功能失效。应该尽可能使用 Blink 提供的编辑命令来修改 DOM。
2. **在执行命令前没有正确更新布局:** 某些操作依赖于最新的布局信息。如果在执行命令前没有调用 `UpdateStyleAndLayout`，可能会导致基于过时信息的错误计算，例如计算选区范围。
3. **错误地假设选区状态:**  在编写涉及编辑命令的代码时，需要仔细考虑命令执行前后选区的变化。不正确的选区处理可能导致光标位置错误或后续命令失败。
4. **滥用 `document.execCommand`:** 虽然 `document.execCommand` 可以触发一些编辑操作，但它缺乏类型安全性和更细粒度的控制。直接使用 Blink 提供的编辑命令类通常是更可靠和推荐的方式。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在可编辑区域进行操作:** 用户在一个 `contenteditable` 属性设置为 `true` 的元素内进行任何编辑操作，例如输入文本、删除文本、粘贴内容、格式化文本等。
2. **浏览器捕获用户事件:** 浏览器会捕获用户的键盘事件、鼠标事件等。
3. **事件分发和处理:**  浏览器将这些事件分发给渲染引擎进行处理.
4. **编辑器或输入系统识别编辑操作:**  Blink 的编辑器或输入系统会识别用户的操作类型（例如，输入字符，删除字符，执行格式化命令）。
5. **创建并执行相应的编辑命令:**  根据用户的操作，Blink 会创建一个或多个编辑命令。对于复杂的操作，可能会创建一个 `CompositeEditCommand` 来包含多个子命令。
6. **`CompositeEditCommand` 的执行:**  `CompositeEditCommand` 会按顺序执行其包含的子命令，修改 DOM 结构和样式。
7. **更新选区和触发事件:**  命令执行完成后，会更新当前的选区状态，并触发相应的事件，通知页面内容已更改。

**例如，用户输入文本 "hello":**

1. 用户在可编辑区域按下 'h' 键。
2. 浏览器捕获 `keypress` 或 `textInput` 事件。
3. Blink 的输入系统识别到用户输入了一个字符。
4. 创建一个 `InsertTextCommand` (可能是包含在 `CompositeEditCommand` 中)。
5. `InsertTextCommand` 将 "h" 插入到当前光标位置。
6. 更新光标位置。
7. 触发 `input` 和 `editablecontentchanged` 事件。

**总结 `CompositeEditCommand` 的功能:**

`CompositeEditCommand` 在 Blink 渲染引擎中扮演着**组织和协调复杂编辑操作**的关键角色。它允许将多个独立的编辑步骤组合成一个原子性的、可撤销的操作，并负责管理这些操作的执行顺序、选区状态更新、样式处理以及事件触发。它是实现富文本编辑功能的基础架构，确保了编辑操作的一致性和可靠性，并为撤销/重做功能提供了必要的支持。

### 提示词
```
这是目录为blink/renderer/core/editing/commands/composite_edit_command.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
ep::From(destination_selection.AsSelection()));
  ReplaceSelectionCommand::CommandOptions options =
      ReplaceSelectionCommand::kSelectReplacement |
      ReplaceSelectionCommand::kMovingParagraph;
  if (should_preserve_style == kDoNotPreserveStyle)
    options |= ReplaceSelectionCommand::kMatchStyle;
  ApplyCommandToComposite(MakeGarbageCollected<ReplaceSelectionCommand>(
                              GetDocument(), fragment, options),
                          editing_state);
  if (editing_state->IsAborted())
    return;
  ABORT_EDITING_COMMAND_IF(!EndingSelection().IsValidFor(GetDocument()));

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  // If the selection is in an empty paragraph, restore styles from the old
  // empty paragraph to the new empty paragraph.
  bool selection_is_empty_paragraph =
      EndingSelection().IsCaret() &&
      IsStartOfParagraph(EndingVisibleSelection().VisibleStart()) &&
      IsEndOfParagraph(EndingVisibleSelection().VisibleStart());
  if (style_in_empty_paragraph && selection_is_empty_paragraph) {
    ApplyStyle(style_in_empty_paragraph, editing_state);
    if (editing_state->IsAborted())
      return;
  }

  if (should_preserve_selection == kDoNotPreserveSelection || start_index == -1)
    return;
  Element* document_element = GetDocument().documentElement();
  if (!document_element)
    return;

  // We need clean layout in order to compute plain-text ranges below.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  // Fragment creation (using createMarkup) incorrectly uses regular spaces
  // instead of nbsps for some spaces that were rendered (11475), which causes
  // spaces to be collapsed during the move operation. This results in a call
  // to rangeFromLocationAndLength with a location past the end of the
  // document (which will return null).
  EphemeralRange start_range = PlainTextRange(destination_index + start_index)
                                   .CreateRangeForSelection(*document_element);
  if (start_range.IsNull())
    return;
  EphemeralRange end_range = PlainTextRange(destination_index + end_index)
                                 .CreateRangeForSelection(*document_element);
  if (end_range.IsNull())
    return;
  const VisibleSelection& visible_selection =
      CreateVisibleSelection(SelectionInDOMTree::Builder()
                                 .Collapse(start_range.StartPosition())
                                 .Extend(end_range.StartPosition())
                                 .Build());
  SetEndingSelection(
      SelectionForUndoStep::From(visible_selection.AsSelection()));
}

// FIXME: Send an appropriate shouldDeleteRange call.
bool CompositeEditCommand::BreakOutOfEmptyListItem(
    EditingState* editing_state) {
  DCHECK(!GetDocument().NeedsLayoutTreeUpdate());
  Node* empty_list_item =
      EnclosingEmptyListItem(EndingVisibleSelection().VisibleStart());
  if (!empty_list_item)
    return false;

  EditingStyle* style =
      MakeGarbageCollected<EditingStyle>(EndingSelection().Start());
  style->MergeTypingStyle(&GetDocument());

  ContainerNode* list_node = empty_list_item->parentNode();
  // FIXME: Can't we do something better when the immediate parent wasn't a list
  // node?
  if (!list_node ||
      (!IsA<HTMLUListElement>(*list_node) &&
       !IsA<HTMLOListElement>(*list_node)) ||
      !IsEditable(*list_node) ||
      list_node == RootEditableElement(*empty_list_item))
    return false;

  HTMLElement* new_block = nullptr;
  if (ContainerNode* block_enclosing_list = list_node->parentNode()) {
    if (block_enclosing_list->HasTagName(
            html_names::kLiTag)) {  // listNode is inside another list item
      if (CreateVisiblePosition(PositionAfterNode(*block_enclosing_list))
              .DeepEquivalent() ==
          CreateVisiblePosition(PositionAfterNode(*list_node))
              .DeepEquivalent()) {
        // If listNode appears at the end of the outer list item, then move
        // listNode outside of this list item, e.g.
        //   <ul><li>hello <ul><li><br></li></ul> </li></ul>
        // should become
        //   <ul><li>hello</li> <ul><li><br></li></ul> </ul>
        // after this section.
        //
        // If listNode does NOT appear at the end, then we should consider it as
        // a regular paragraph, e.g.
        //   <ul><li> <ul><li><br></li></ul> hello</li></ul>
        // should become
        //   <ul><li> <div><br></div> hello</li></ul>
        // at the end
        SplitElement(To<Element>(block_enclosing_list), list_node);
        RemoveNodePreservingChildren(list_node->parentNode(), editing_state);
        if (editing_state->IsAborted())
          return false;
        new_block = MakeGarbageCollected<HTMLLIElement>(GetDocument());
      }
      // If listNode does NOT appear at the end of the outer list item, then
      // behave as if in a regular paragraph.
    } else if (block_enclosing_list->HasTagName(html_names::kOlTag) ||
               block_enclosing_list->HasTagName(html_names::kUlTag)) {
      new_block = MakeGarbageCollected<HTMLLIElement>(GetDocument());
    }
  }
  if (!new_block)
    new_block = CreateDefaultParagraphElement(GetDocument());

  Node* previous_list_node =
      empty_list_item->IsElementNode()
          ? ElementTraversal::PreviousSibling(*empty_list_item)
          : empty_list_item->previousSibling();
  Node* next_list_node = empty_list_item->IsElementNode()
                             ? ElementTraversal::NextSibling(*empty_list_item)
                             : empty_list_item->nextSibling();
  if (next_list_node && IsListElementTag(list_node)) {
    // If emptyListItem follows another list item or nested list, split the list
    // node.
    if (IsListItemTag(previous_list_node) ||
        IsHTMLListElement(previous_list_node)) {
      SplitElement(To<Element>(list_node), empty_list_item);
    }

    // If emptyListItem is followed by other list item or nested list, then
    // insert newBlock before the list node. Because we have split the
    // element, emptyListItem is the first element in the list node.
    // i.e. insert newBlock before ul or ol whose first element is emptyListItem
    InsertNodeBefore(new_block, list_node, editing_state);
    if (editing_state->IsAborted())
      return false;
    RemoveNode(empty_list_item, editing_state);
    if (editing_state->IsAborted())
      return false;
  } else {
    // When emptyListItem does not follow any list item or nested list, insert
    // newBlock after the enclosing list node. Remove the enclosing node if
    // emptyListItem is the only child; otherwise just remove emptyListItem.
    //   <ul>                             <ul>
    //     <li>                             <li>
    //       abc                              abc
    //       <ul>                             <ul>
    //         <li>def</li>                     <li>def</li>
    //         <li>{}<br></li>    ->          </ul>
    //       </ul>                            <div>{}<br></div>
    //       ghi                              ghi
    //     </li>                            </li>
    //   </ul>                            </ul>
    InsertNodeAfter(new_block, list_node, editing_state);
    if (editing_state->IsAborted())
      return false;
    RemoveNode(previous_list_node ? empty_list_item : list_node, editing_state);
    if (editing_state->IsAborted())
      return false;
  }

  AppendBlockPlaceholder(new_block, editing_state);
  if (editing_state->IsAborted())
    return false;

  SetEndingSelection(SelectionForUndoStep::From(
      SelectionInDOMTree::Builder()
          .Collapse(Position::FirstPositionInNode(*new_block))
          .Build()));

  style->PrepareToApplyAt(EndingSelection().Start());
  if (!style->IsEmpty()) {
    ApplyStyle(style, editing_state);
    if (editing_state->IsAborted())
      return false;
  }

  return true;
}

// If the caret is in an empty quoted paragraph, and either there is nothing
// before that paragraph, or what is before is unquoted, and the user presses
// delete, unquote that paragraph.
bool CompositeEditCommand::BreakOutOfEmptyMailBlockquotedParagraph(
    EditingState* editing_state) {
  if (!EndingSelection().IsCaret())
    return false;

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  VisiblePosition caret = EndingVisibleSelection().VisibleStart();
  auto* highest_blockquote = To<HTMLQuoteElement>(HighestEnclosingNodeOfType(
      caret.DeepEquivalent(), &IsMailHTMLBlockquoteElement));
  if (!highest_blockquote)
    return false;

  if (!IsStartOfParagraph(caret) || !IsEndOfParagraph(caret))
    return false;

  VisiblePosition previous =
      PreviousPositionOf(caret, kCannotCrossEditingBoundary);
  // Only move forward if there's nothing before the caret, or if there's
  // unquoted content before it.
  if (EnclosingNodeOfType(previous.DeepEquivalent(),
                          &IsMailHTMLBlockquoteElement))
    return false;

  auto* br = MakeGarbageCollected<HTMLBRElement>(GetDocument());
  // We want to replace this quoted paragraph with an unquoted one, so insert a
  // br to hold the caret before the highest blockquote.
  InsertNodeBefore(br, highest_blockquote, editing_state);
  if (editing_state->IsAborted())
    return false;

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  VisiblePosition at_br = VisiblePosition::BeforeNode(*br);
  // If the br we inserted collapsed, for example:
  //   foo<br><blockquote>...</blockquote>
  // insert a second one.
  if (!IsStartOfParagraph(at_br)) {
    InsertNodeBefore(MakeGarbageCollected<HTMLBRElement>(GetDocument()), br,
                     editing_state);
    if (editing_state->IsAborted())
      return false;
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  }
  SetEndingSelection(SelectionForUndoStep::From(
      SelectionInDOMTree::Builder()
          .Collapse(at_br.ToPositionWithAffinity())
          .Build()));

  // If this is an empty paragraph there must be a line break here.
  if (!LineBreakExistsAtVisiblePosition(caret))
    return false;

  Position caret_pos(MostForwardCaretPosition(caret.DeepEquivalent()));
  // A line break is either a br or a preserved newline.
  DCHECK(IsA<HTMLBRElement>(caret_pos.AnchorNode()) ||
         (caret_pos.AnchorNode()->IsTextNode() && caret_pos.AnchorNode()
                                                      ->GetLayoutObject()
                                                      ->Style()
                                                      ->ShouldPreserveBreaks()))
      << caret_pos;

  if (IsA<HTMLBRElement>(*caret_pos.AnchorNode())) {
    RemoveNodeAndPruneAncestors(caret_pos.AnchorNode(), editing_state);
    if (editing_state->IsAborted())
      return false;
  } else if (auto* text_node = DynamicTo<Text>(caret_pos.AnchorNode())) {
    DCHECK_EQ(caret_pos.ComputeOffsetInContainerNode(), 0);
    ContainerNode* parent_node = text_node->parentNode();
    // The preserved newline must be the first thing in the node, since
    // otherwise the previous paragraph would be quoted, and we verified that it
    // wasn't above.
    DeleteTextFromNode(text_node, 0, 1);
    Prune(parent_node, editing_state);
    if (editing_state->IsAborted())
      return false;
  }

  return true;
}

// Operations use this function to avoid inserting content into an anchor when
// at the start or the end of that anchor, as in NSTextView.
// FIXME: This is only an approximation of NSTextViews insertion behavior, which
// varies depending on how the caret was made.
Position CompositeEditCommand::PositionAvoidingSpecialElementBoundary(
    const Position& original,
    EditingState* editing_state) {
  if (original.IsNull())
    return original;

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  VisiblePosition visible_pos = CreateVisiblePosition(original);
  Element* enclosing_anchor = EnclosingAnchorElement(original);
  Position result = original;

  if (!enclosing_anchor)
    return result;

  // Don't avoid block level anchors, because that would insert content into the
  // wrong paragraph.
  if (enclosing_anchor && !IsEnclosingBlock(enclosing_anchor)) {
    VisiblePosition first_in_anchor =
        VisiblePosition::FirstPositionInNode(*enclosing_anchor);
    VisiblePosition last_in_anchor =
        VisiblePosition::LastPositionInNode(*enclosing_anchor);
    // If visually just after the anchor, insert *inside* the anchor unless it's
    // the last VisiblePosition in the document, to match NSTextView.
    if (visible_pos.DeepEquivalent() == last_in_anchor.DeepEquivalent()) {
      // Make sure anchors are pushed down before avoiding them so that we don't
      // also avoid structural elements like lists and blocks (5142012).
      Element* enclosing_block = EnclosingBlock(original.AnchorNode());
      if (enclosing_block &&
          enclosing_block->IsDescendantOf(enclosing_anchor)) {
        // Only push down anchor element if there are block elements inside it.
        PushAnchorElementDown(enclosing_anchor, editing_state);
        if (editing_state->IsAborted())
          return original;
        enclosing_anchor = EnclosingAnchorElement(original);
        if (!enclosing_anchor)
          return original;
      }

      GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

      // Don't insert outside an anchor if doing so would skip over a line
      // break.  It would probably be safe to move the line break so that we
      // could still avoid the anchor here.
      Position downstream(
          MostForwardCaretPosition(visible_pos.DeepEquivalent()));
      if (LineBreakExistsAtVisiblePosition(visible_pos) &&
          downstream.AnchorNode()->IsDescendantOf(enclosing_anchor))
        return original;

      result = Position::InParentAfterNode(*enclosing_anchor);
    }

    // If visually just before an anchor, insert *outside* the anchor unless
    // it's the first VisiblePosition in a paragraph, to match NSTextView.
    if (visible_pos.DeepEquivalent() == first_in_anchor.DeepEquivalent()) {
      // Make sure anchors are pushed down before avoiding them so that we don't
      // also avoid structural elements like lists and blocks (5142012).
      Element* enclosing_block = EnclosingBlock(original.AnchorNode());
      if (enclosing_block &&
          enclosing_block->IsDescendantOf(enclosing_anchor)) {
        // Only push down anchor element if there are block elements inside it.
        PushAnchorElementDown(enclosing_anchor, editing_state);
        if (editing_state->IsAborted())
          return original;
        enclosing_anchor = EnclosingAnchorElement(original);
      }
      if (!enclosing_anchor)
        return original;

      result = Position::InParentBeforeNode(*enclosing_anchor);
    }
  }

  if (result.IsNull() || !RootEditableElementOf(result))
    result = original;

  return result;
}

// Splits the tree parent by parent until we reach the specified ancestor. We
// use VisiblePositions to determine if the split is necessary. Returns the last
// split node.
Node* CompositeEditCommand::SplitTreeToNode(Node* start,
                                            Node* end,
                                            bool should_split_ancestor) {
  DCHECK(start);
  DCHECK(end);
  DCHECK_NE(start, end);

  if (should_split_ancestor && end->parentNode())
    end = end->parentNode();
  if (!start->IsDescendantOf(end))
    return end;

  Node* end_node = end;
  Node* node = nullptr;
  for (node = start; node->parentNode() != end_node;
       node = node->parentNode()) {
    Element* parent_element = node->parentElement();
    if (!parent_element)
      break;

    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

    // Do not split a node when doing so introduces an empty node.
    if (node->previousSibling()) {
      const Position& first_in_parent =
          Position::FirstPositionInNode(*parent_element);
      const Position& before_node =
          Position::BeforeNode(*node).ToOffsetInAnchor();
      if (MostBackwardCaretPosition(first_in_parent) !=
          MostBackwardCaretPosition(before_node))
        SplitElement(parent_element, node);
    }
  }

  return node;
}

void CompositeEditCommand::SetStartingSelection(
    const SelectionForUndoStep& selection) {
  for (CompositeEditCommand* command = this;; command = command->Parent()) {
    if (UndoStep* undo_step = command->GetUndoStep()) {
      DCHECK(command->IsTopLevelCommand());
      undo_step->SetStartingSelection(selection);
    }
    command->starting_selection_ = selection;
    if (!command->Parent() || command->Parent()->IsFirstCommand(command))
      break;
  }
}

void CompositeEditCommand::SetEndingSelection(
    const SelectionForUndoStep& selection) {
  for (CompositeEditCommand* command = this; command;
       command = command->Parent()) {
    if (UndoStep* undo_step = command->GetUndoStep()) {
      DCHECK(command->IsTopLevelCommand());
      undo_step->SetEndingSelection(selection);
    }
    command->ending_selection_ = selection;
  }
}

void CompositeEditCommand::SetParent(CompositeEditCommand* parent) {
  EditCommand::SetParent(parent);
  if (!parent)
    return;
  starting_selection_ = parent->ending_selection_;
  ending_selection_ = parent->ending_selection_;
}

// Determines whether a node is inside a range or visibly starts and ends at the
// boundaries of the range. Call this function to determine whether a node is
// visibly fit inside selectedRange
bool CompositeEditCommand::IsNodeVisiblyContainedWithin(
    Node& node,
    const EphemeralRange& selected_range) {
  DCHECK(!NeedsLayoutTreeUpdate(node));
  DocumentLifecycle::DisallowTransitionScope disallow_transition(
      node.GetDocument().Lifecycle());

  if (IsNodeFullyContained(selected_range, node))
    return true;

  bool start_is_visually_same =
      CreateVisiblePosition(PositionBeforeNode(node)).DeepEquivalent() ==
      CreateVisiblePosition(selected_range.StartPosition()).DeepEquivalent();
  if (start_is_visually_same &&
      ComparePositions(Position::InParentAfterNode(node),
                       selected_range.EndPosition()) < 0)
    return true;

  bool end_is_visually_same =
      CreateVisiblePosition(PositionAfterNode(node)).DeepEquivalent() ==
      CreateVisiblePosition(selected_range.EndPosition()).DeepEquivalent();
  if (end_is_visually_same &&
      ComparePositions(selected_range.StartPosition(),
                       Position::InParentBeforeNode(node)) < 0)
    return true;

  return start_is_visually_same && end_is_visually_same;
}

void CompositeEditCommand::Trace(Visitor* visitor) const {
  visitor->Trace(commands_);
  visitor->Trace(starting_selection_);
  visitor->Trace(ending_selection_);
  visitor->Trace(undo_step_);
  EditCommand::Trace(visitor);
}

void CompositeEditCommand::AppliedEditing() {
  DCHECK(!IsCommandGroupWrapper());
  EventQueueScope scope;

  const UndoStep& undo_step = *GetUndoStep();
  DispatchEditableContentChangedEvents(undo_step.StartingRootEditableElement(),
                                       undo_step.EndingRootEditableElement());
  LocalFrame* const frame = GetDocument().GetFrame();
  Editor& editor = frame->GetEditor();
  // TODO(editing-dev): Filter empty InputType after spec is finalized.
  DispatchInputEventEditableContentChanged(
      undo_step.StartingRootEditableElement(),
      undo_step.EndingRootEditableElement(), GetInputType(),
      TextDataForInputEvent(), IsComposingFromCommand(this));

  const SelectionInDOMTree& new_selection =
      CorrectedSelectionAfterCommand(EndingSelection(), &GetDocument());

  // Don't clear the typing style with this selection change. We do those things
  // elsewhere if necessary.
  ChangeSelectionAfterCommand(frame, new_selection,
                              SetSelectionOptions::Builder()
                                  .SetIsDirectional(SelectionIsDirectional())
                                  .Build());

  if (!PreservesTypingStyle())
    editor.ClearTypingStyle();

  CompositeEditCommand* const last_edit_command = editor.LastEditCommand();
  // Command will be equal to last edit command only in the case of typing
  if (last_edit_command == this) {
    DCHECK(IsTypingCommand());
  } else if (last_edit_command && last_edit_command->IsDragAndDropCommand() &&
             (GetInputType() == InputEvent::InputType::kDeleteByDrag ||
              GetInputType() == InputEvent::InputType::kInsertFromDrop)) {
    // Only register undo entry when combined with other commands.
    if (!last_edit_command->GetUndoStep()) {
      editor.GetUndoStack().RegisterUndoStep(
          last_edit_command->EnsureUndoStep());
    }
    last_edit_command->EnsureUndoStep()->SetEndingSelection(
        EnsureUndoStep()->EndingSelection());
    last_edit_command->GetUndoStep()->SetSelectionIsDirectional(
        GetUndoStep()->SelectionIsDirectional());
    editor.GetUndoStack().DidSetEndingSelection(
        last_edit_command->GetUndoStep());
    last_edit_command->AppendCommandToUndoStep(this);
  } else {
    // Only register a new undo command if the command passed in is
    // different from the last command
    editor.SetLastEditCommand(this);
    editor.GetUndoStack().RegisterUndoStep(EnsureUndoStep());
  }

  if (Element* element = undo_step.StartingRootEditableElement()) {
    if (element->GetDocument().IsPageVisible()) {
      element->GetDocument()
          .GetPage()
          ->GetChromeClient()
          .DidUserChangeContentEditableContent(*element);
    }
  }
  editor.RespondToChangedContents(new_selection.Anchor());

  if (auto* rc = GetDocument().GetResourceCoordinator()) {
    rc->SetHadUserEdits();
  }
}

}  // namespace blink
```