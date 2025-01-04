Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's Blink rendering engine. This code is part of the `composite_edit_command.cc` file, specifically the second part.

To address the request, I will:

1. **Summarize the functionality** of this code block, focusing on the core operations and goals.
2. **Identify connections to JavaScript, HTML, and CSS**: Explain how the code interacts with or influences these web technologies.
3. **Provide examples with hypothetical input and output**:  Illustrate the logic of specific functions.
4. **Highlight common user/programming errors**: Point out potential issues when using or interacting with this functionality.
5. **Explain user actions leading to this code**: Describe the sequence of user interactions that might trigger this code execution.
6. **Synthesize the overall function of this code snippet**.

**Mental Sandbox:**

*   **Whitespace Handling:** The code heavily manipulates whitespace, rebalancing it and replacing it with non-breaking spaces in specific scenarios. This is crucial for maintaining visual consistency in text editing.
*   **Node Manipulation:**  There are functions for inserting, appending, removing, and cloning nodes. This directly relates to the DOM structure (HTML).
*   **Paragraph Operations:**  The code deals with moving and cloning paragraphs, ensuring correct structure and styling.
*   **Selection Management:**  The code interacts with the current selection, updating it and using it as context for operations.
*   **Layout and Styling:**  The code frequently triggers layout updates and interacts with layout objects, indicating a strong connection to CSS and rendering.
*   **Error Handling and Assertions:** The presence of `DCHECK` and aborting mechanisms suggests a focus on maintaining data integrity and preventing unexpected behavior.

**Constraint Checklist & Confidence Score:**

1. List the functions? Yes.
2. Relationship to JS/HTML/CSS? Yes.
3. Examples with input/output? Yes.
4. Common errors? Yes.
5. User actions as debugging clues? Yes.
6. Summarize the function (part 2)? Yes.

Confidence Score: 5/5

**Strategizing complete.** I will now generate the response based on the analysis above.
这是 `blink/renderer/core/editing/commands/composite_edit_command.cc` 文件的一部分，主要负责实现复合编辑操作中的一系列底层操作。这是第二部分，主要集中在 **更复杂的文本和节点操作，以及一些针对特定场景的编辑逻辑**。

以下是这个代码块的主要功能归纳：

**核心功能：**

1. **空格处理 (Whitespace Handling):**
    *   `RebalanceWhitespaceAt`:  调整指定位置附近的空格，确保在段落开头或结尾正确显示。
    *   `PrepareWhitespaceAtPositionForSplit`: 在分割文本节点前，处理指定位置的空格，防止合并。
    *   `ReplaceCollapsibleWhitespaceWithNonBreakingSpaceIfNeeded`:  如果指定位置的字符是可折叠空格，则替换为非断行空格。
    *   `RebalanceWhitespace`: 对当前选区起始和结束位置的空格进行平衡处理。
    *   `DeleteInsignificantText`: 删除文本节点中不重要的文本内容（例如，仅包含空格或空字符串的文本节点）。

2. **占位符管理 (Placeholder Management):**
    *   `AppendBlockPlaceholder`: 在指定的容器末尾添加一个块级占位符 `<br>` 元素。
    *   `InsertBlockPlaceholder`: 在指定位置插入一个块级占位符 `<br>` 元素。
    *   `AddBlockPlaceholderIfNeeded`:  如果容器为空或者是一个空的列表项，则添加一个块级占位符。
    *   `RemovePlaceholderAt`: 移除指定位置的占位符（通常是一个 `<br>` 元素或一个换行符）。

3. **段落操作 (Paragraph Operations):**
    *   `InsertNewDefaultParagraphElementAt`: 在指定位置插入一个新的默认段落元素（通常包含一个 `<br>` 元素）。
    *   `MoveParagraphContentsToNewBlockIfNecessary`: 如果指定位置的段落没有完全包含在其自身的块级元素中，则创建一个新的块级元素，并将该段落的内容移动到新块中。
    *   `PushAnchorElementDown`: 将锚点元素 ( `<a>` ) 的子元素“下推”到新的位置，并移除原始的锚点元素（用于处理嵌套链接等场景）。
    *   `CloneParagraphUnderNewElement`:  克隆从 `start` 到 `end` 的段落，并将其添加到 `block_element` 下。
    *   `CleanupAfterDeletion`:  在删除操作后进行清理，移除可能残留的占位符，并清理空的或未渲染的父元素。
    *   `MoveParagraphWithClones`: 移动段落，并在目标位置创建克隆，用于保留原始样式。
    *   `MoveParagraphs` / `MoveParagraph`: 将一个或多个段落从一个位置移动到另一个位置。

**与 JavaScript, HTML, CSS 的关系：**

*   **HTML:** 这些函数直接操作 HTML 元素和节点。例如：
    *   创建和插入 `<br>` 元素作为占位符 (`AppendBlockPlaceholder`, `InsertBlockPlaceholder`).
    *   创建和插入新的段落元素 (`InsertNewDefaultParagraphElementAt`).
    *   移动和克隆 HTML 元素 (`MoveParagraphs`, `CloneParagraphUnderNewElement`).
    *   移除 HTML 元素 (`RemoveNode`, `RemoveNodeAndPruneAncestors`).
*   **CSS:**  这些函数间接地影响 CSS 的渲染效果。例如：
    *   空格处理会影响文本的布局和换行，这受到 CSS `white-space` 属性的影响。
    *   占位符 `<br>` 的存在会影响块级元素的最小高度，从而影响布局。
    *   `MoveParagraphContentsToNewBlockIfNecessary` 会创建新的块级元素，这会触发新的布局计算和样式应用。
    *   `CleanupAfterDeletion` 移除元素可能导致 CSS 样式的重新计算和渲染。
*   **JavaScript:** JavaScript 可以通过 DOM API 调用编辑命令，从而间接触发这些 C++ 代码的执行。例如：
    *   用户在 `contenteditable` 元素中输入文本、删除文本、粘贴内容等操作，最终会调用到 Blink 引擎的编辑命令。
    *   JavaScript 可以使用 `document.execCommand()` 方法执行预定义的编辑命令，这些命令最终会映射到 C++ 的 `CompositeEditCommand` 的方法。
    *   JavaScript 可以直接操作 DOM，但浏览器通常会将其转换为相应的编辑命令进行处理，以保证编辑操作的一致性和可撤销性。

**逻辑推理的假设输入与输出举例：**

**假设输入:** 用户在一个空的 `<div>` 元素中按下回车键。

**`AddBlockPlaceholderIfNeeded` 的执行:**

*   **输入:** `container` 指向空的 `<div>` 元素。
*   **内部逻辑:**  `block` 将指向 `<div>` 的布局对象，其高度为 0。`IsEmptyListItem` 返回 false。条件 `block->Size().height == 0` 为真。
*   **输出:** 调用 `AppendBlockPlaceholder`，在 `<div>` 中插入一个 `<br>` 元素。

**假设输入:** 用户选中一个段落并执行“左对齐”操作。

**`MoveParagraphContentsToNewBlockIfNecessary` 的执行 (可能被调用):**

*   **假设场景:** 选中的段落没有被包含在一个单独的块级元素中。
*   **输入:** `pos` 指向选中段落的某个位置。
*   **内部逻辑:**  函数会判断该段落是否需要被移动到一个新的块级元素中。如果需要，则创建一个新的默认段落元素，并将原始段落的内容移动到新段落中。
*   **输出:** 返回新创建的段落元素，或者返回 `nullptr` 如果不需要移动。

**用户或编程常见的使用错误举例：**

1. **手动操作 DOM 而不通过编辑命令:**  如果 JavaScript 代码直接使用 DOM API (例如 `appendChild`, `removeChild`) 修改 `contenteditable` 区域，可能会绕过 `CompositeEditCommand` 的逻辑，导致状态不一致或撤销/重做功能失效。
2. **错误的位置计算:** 在 JavaScript 中计算光标位置或选区范围时出现错误，可能导致传递给编辑命令的位置信息不正确，从而引发意外的编辑行为或崩溃。例如，尝试在只读节点中插入内容。
3. **在复杂的嵌套结构中进行编辑:**  在具有复杂的嵌套元素（例如，表格、列表）的 `contenteditable` 区域进行编辑时，可能会遇到一些边界情况，导致 `CompositeEditCommand` 的逻辑出现意外行为。开发者需要充分测试各种编辑场景。
4. **异步操作与编辑命令的冲突:**  如果在 JavaScript 中进行异步操作（例如，网络请求），并在回调函数中直接操作 DOM 或调用编辑命令，可能会导致竞争条件和状态不一致。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在 `contenteditable` 元素中进行编辑操作:**
    *   输入文本：可能会触发文本节点的插入或替换，调用 `ReplaceTextInNode` 等函数。
    *   删除文本：可能会触发 `DeleteTextFromNode` 或 `DeleteInsignificantText`。
    *   按下回车键：可能触发 `InsertNewDefaultParagraphElementAt` 或 `AppendBlockPlaceholder`。
    *   粘贴内容：会涉及到更复杂的操作，包括创建新的节点、移动节点等。
    *   使用格式化工具栏（例如，加粗、斜体、对齐）：可能会触发 `ApplyStyleCommand`，它可能会调用 `MoveParagraphContentsToNewBlockIfNecessary` 等函数来调整段落结构。
    *   拖拽内容：会涉及到节点的移动和插入。

2. **浏览器事件处理:** 浏览器的事件监听器会捕获用户的编辑操作，并将这些操作转换为相应的编辑命令。

3. **`Editor` 和 `EditCommand` 的调用:**  浏览器会将编辑操作传递给 `Editor` 对象，`Editor` 对象会根据操作类型创建相应的 `EditCommand` 对象，例如 `InsertTextCommand`，`DeleteCommand` 或 `CompositeEditCommand`。

4. **`CompositeEditCommand` 的执行:** 对于复杂的编辑操作，可能会创建 `CompositeEditCommand` 对象，它会将多个小的编辑操作组合成一个复合操作，以确保编辑的原子性和可撤销性。 这个代码块中的函数就是 `CompositeEditCommand` 执行过程中调用的底层操作。

**本代码块的功能归纳:**

总而言之，这个代码块 (`composite_edit_command.cc` 的第二部分) 提供了构建复杂编辑操作的更细粒度的构建块。它专注于处理文本内容中的空格、管理占位符元素、执行段落级别的移动和克隆操作，以及在删除操作后进行清理。这些功能是实现富文本编辑器的核心，确保用户在进行各种编辑操作时，内容能够正确地呈现和组织。它与 HTML 结构、CSS 渲染以及 JavaScript 通过 DOM API 进行的编辑操作都密切相关。

Prompt: 
```
这是目录为blink/renderer/core/editing/commands/composite_edit_command.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
he
  // current text node. However, if the next sibling node is a text node
  // (not empty, see http://crbug.com/632300), we should use a plain space.
  // See http://crbug.com/310149
  auto* next_text_node = DynamicTo<Text>(text_node->nextSibling());
  const bool next_sibling_is_text_node =
      next_text_node && next_text_node->data().length() &&
      !IsWhitespace(next_text_node->data()[0]);
  const bool should_emit_nbs_pbefore_end =
      (IsEndOfParagraph(visible_downstream_pos) ||
       (unsigned)downstream == text.length()) &&
      !next_sibling_is_text_node;
  String rebalanced_string = StringWithRebalancedWhitespace(
      string, IsStartOfParagraph(visible_upstream_pos) || !upstream,
      should_emit_nbs_pbefore_end);

  if (string != rebalanced_string)
    ReplaceTextInNode(text_node, upstream, length, rebalanced_string);
}

void CompositeEditCommand::PrepareWhitespaceAtPositionForSplit(
    Position& position) {
  if (!IsRichlyEditablePosition(position))
    return;

  auto* text_node = DynamicTo<Text>(position.AnchorNode());
  if (!text_node)
    return;

  if (text_node->length() == 0)
    return;
  LayoutText* layout_text = text_node->GetLayoutObject();
  if (layout_text && layout_text->Style()->ShouldPreserveWhiteSpaces()) {
    return;
  }

  // Delete collapsed whitespace so that inserting nbsps doesn't uncollapse it.
  Position upstream_pos = MostBackwardCaretPosition(position);
  RelocatablePosition* relocatable_upstream_pos =
      MakeGarbageCollected<RelocatablePosition>(upstream_pos);
  DeleteInsignificantText(upstream_pos, MostForwardCaretPosition(position));

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  position = MostForwardCaretPosition(relocatable_upstream_pos->GetPosition());
  VisiblePosition visible_pos = CreateVisiblePosition(position);
  VisiblePosition previous_visible_pos = PreviousPositionOf(visible_pos);
  ReplaceCollapsibleWhitespaceWithNonBreakingSpaceIfNeeded(
      previous_visible_pos);

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  ReplaceCollapsibleWhitespaceWithNonBreakingSpaceIfNeeded(
      CreateVisiblePosition(position));
}

void CompositeEditCommand::
    ReplaceCollapsibleWhitespaceWithNonBreakingSpaceIfNeeded(
        const VisiblePosition& visible_position) {
  if (!IsCollapsibleWhitespace(CharacterAfter(visible_position)))
    return;
  Position pos = MostForwardCaretPosition(visible_position.DeepEquivalent());
  auto* container_text_node = DynamicTo<Text>(pos.ComputeContainerNode());
  if (!container_text_node)
    return;
  ReplaceTextInNode(container_text_node, pos.OffsetInContainerNode(), 1,
                    NonBreakingSpaceString());
}

void CompositeEditCommand::RebalanceWhitespace() {
  VisibleSelection selection = EndingVisibleSelection();
  if (selection.IsNone())
    return;

  RebalanceWhitespaceAt(selection.Start());
  if (selection.IsRange())
    RebalanceWhitespaceAt(selection.End());
}

static bool IsInsignificantText(const LayoutText& layout_text) {
  if (layout_text.HasInlineFragments())
    return false;
  // Spaces causing line break don't have `FragmentItem` but it has
  // non-zero length. See http://crbug.com/1322746
  return !layout_text.ResolvedTextLength();
}

void CompositeEditCommand::DeleteInsignificantText(Text* text_node,
                                                   unsigned start,
                                                   unsigned end) {
  if (!text_node || start >= end)
    return;

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  LayoutText* text_layout_object = text_node->GetLayoutObject();
  if (!text_layout_object)
    return;

  if (IsInsignificantText(*text_layout_object)) {
    // whole text node is empty
    // Removing a Text node won't dispatch synchronous events.
    RemoveNode(text_node, ASSERT_NO_EDITING_ABORT);
    return;
  }
  unsigned length = text_node->length();
  if (start >= length || end > length)
    return;

  CHECK(text_layout_object->IsInLayoutNGInlineFormattingContext());
  const String string = PlainText(
      EphemeralRange(Position(*text_node, start), Position(*text_node, end)),
      TextIteratorBehavior::Builder().SetEmitsOriginalText(true).Build());
  if (string.empty()) {
    return DeleteTextFromNode(text_node, start, end - start);
  }
  // Replace the text between start and end with collapsed version.
  return ReplaceTextInNode(text_node, start, end - start, string);
}

void CompositeEditCommand::DeleteInsignificantText(const Position& start,
                                                   const Position& end) {
  if (start.IsNull() || end.IsNull())
    return;

  if (ComparePositions(start, end) >= 0)
    return;

  HeapVector<Member<Text>> nodes;
  for (Node& node : NodeTraversal::StartsAt(*start.AnchorNode())) {
    if (auto* text_node = DynamicTo<Text>(&node))
      nodes.push_back(text_node);
    if (&node == end.AnchorNode())
      break;
  }

  for (const auto& node : nodes) {
    Text* text_node = node;
    int start_offset = text_node == start.AnchorNode()
                           ? start.ComputeOffsetInContainerNode()
                           : 0;
    int end_offset = text_node == end.AnchorNode()
                         ? end.ComputeOffsetInContainerNode()
                         : static_cast<int>(text_node->length());
    DeleteInsignificantText(text_node, start_offset, end_offset);
  }
}

void CompositeEditCommand::DeleteInsignificantTextDownstream(
    const Position& pos) {
  DCHECK(!GetDocument().NeedsLayoutTreeUpdate());
  Position end = MostForwardCaretPosition(
      NextPositionOf(CreateVisiblePosition(pos)).DeepEquivalent());
  DeleteInsignificantText(pos, end);
}

HTMLBRElement* CompositeEditCommand::AppendBlockPlaceholder(
    Element* container,
    EditingState* editing_state) {
  if (!container)
    return nullptr;

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  // Should assert isLayoutBlockFlow || isInlineFlow when deletion improves. See
  // 4244964.
  // Note: When `container` is newly created <object> as fallback content, it
  // isn't associated to layout object. See http://crbug.com/1357082
  DCHECK(container->GetLayoutObject() ||
         Traversal<HTMLObjectElement>::FirstAncestor(*container))
      << container;

  auto* placeholder = MakeGarbageCollected<HTMLBRElement>(GetDocument());
  AppendNode(placeholder, container, editing_state);
  if (editing_state->IsAborted())
    return nullptr;
  return placeholder;
}

HTMLBRElement* CompositeEditCommand::InsertBlockPlaceholder(
    const Position& pos,
    EditingState* editing_state) {
  if (pos.IsNull())
    return nullptr;

  // Should assert isLayoutBlockFlow || isInlineFlow when deletion improves. See
  // 4244964.
  DCHECK(pos.AnchorNode()->GetLayoutObject()) << pos;

  auto* placeholder = MakeGarbageCollected<HTMLBRElement>(GetDocument());
  InsertNodeAt(placeholder, pos, editing_state);
  if (editing_state->IsAborted())
    return nullptr;
  return placeholder;
}

static bool IsEmptyListItem(const LayoutBlockFlow& block_flow) {
  if (block_flow.IsLayoutListItem()) {
    return !block_flow.FirstChild();
  }
  return false;
}

HTMLBRElement* CompositeEditCommand::AddBlockPlaceholderIfNeeded(
    Element* container,
    EditingState* editing_state) {
  if (!container)
    return nullptr;

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  auto* block = DynamicTo<LayoutBlockFlow>(container->GetLayoutObject());
  if (!block)
    return nullptr;

  // append the placeholder to make sure it follows
  // any unrendered blocks
  if (block->Size().height == 0 || IsEmptyListItem(*block)) {
    return AppendBlockPlaceholder(container, editing_state);
  }

  return nullptr;
}

// Assumes that the position is at a placeholder and does the removal without
// much checking.
void CompositeEditCommand::RemovePlaceholderAt(const Position& p) {
  DCHECK(LineBreakExistsAtPosition(p)) << p;

  // We are certain that the position is at a line break, but it may be a br or
  // a preserved newline.
  if (IsA<HTMLBRElement>(*p.AnchorNode())) {
    // Removing a BR element won't dispatch synchronous events.
    RemoveNode(p.AnchorNode(), ASSERT_NO_EDITING_ABORT);
    return;
  }

  DeleteTextFromNode(To<Text>(p.AnchorNode()), p.OffsetInContainerNode(), 1);
}

HTMLElement* CompositeEditCommand::InsertNewDefaultParagraphElementAt(
    const Position& position,
    EditingState* editing_state) {
  HTMLElement* paragraph_element = CreateDefaultParagraphElement(GetDocument());
  paragraph_element->AppendChild(
      MakeGarbageCollected<HTMLBRElement>(GetDocument()));
  InsertNodeAt(paragraph_element, position, editing_state);
  if (editing_state->IsAborted())
    return nullptr;
  return paragraph_element;
}

// If the paragraph is not entirely within it's own block, create one and move
// the paragraph into it, and return that block.  Otherwise return 0.
HTMLElement* CompositeEditCommand::MoveParagraphContentsToNewBlockIfNecessary(
    const Position& pos,
    EditingState* editing_state) {
  DCHECK(!GetDocument().NeedsLayoutTreeUpdate());
  DCHECK(IsEditablePosition(pos)) << pos;

  // It's strange that this function is responsible for verifying that pos has
  // not been invalidated by an earlier call to this function.  The caller,
  // applyBlockStyle, should do this.
  VisiblePosition visible_pos = CreateVisiblePosition(pos);
  if (visible_pos.IsNull()) {
    editing_state->Abort();
    return nullptr;
  }
  VisiblePosition visible_paragraph_start = StartOfParagraph(visible_pos);
  VisiblePosition visible_paragraph_end = EndOfParagraph(visible_pos);
  VisiblePosition next = NextPositionOf(visible_paragraph_end);
  VisiblePosition visible_end = next.IsNotNull() ? next : visible_paragraph_end;

  Position upstream_start =
      MostBackwardCaretPosition(visible_paragraph_start.DeepEquivalent());
  Position upstream_end =
      MostBackwardCaretPosition(visible_end.DeepEquivalent());

  // If there are no VisiblePositions in the same block as pos then
  // upstreamStart will be outside the paragraph
  if (ComparePositions(pos, upstream_start) < 0)
    return nullptr;

  // Perform some checks to see if we need to perform work in this function.
  if (IsEnclosingBlock(upstream_start.AnchorNode())) {
    // If the block is the root editable element, always move content to a new
    // block, since it is illegal to modify attributes on the root editable
    // element for editing.
    if (upstream_start.AnchorNode() == RootEditableElementOf(upstream_start)) {
      // If the block is the root editable element and it contains no visible
      // content, create a new block but don't try and move content into it,
      // since there's nothing for moveParagraphs to move.
      if (!HasRenderedNonAnonymousDescendantsWithHeight(
              upstream_start.AnchorNode()->GetLayoutObject()))
        return InsertNewDefaultParagraphElementAt(upstream_start,
                                                  editing_state);
    } else if (IsEnclosingBlock(upstream_end.AnchorNode())) {
      if (!upstream_end.AnchorNode()->IsDescendantOf(
              upstream_start.AnchorNode())) {
        // If the paragraph end is a descendant of paragraph start, then we need
        // to run the rest of this function. If not, we can bail here.
        return nullptr;
      }
    } else if (EnclosingBlock(upstream_end.AnchorNode()) !=
               upstream_start.AnchorNode()) {
      // It should be an ancestor of the paragraph start.
      // We can bail as we have a full block to work with.
      return nullptr;
    } else if (IsEndOfEditableOrNonEditableContent(visible_end)) {
      // At the end of the editable region. We can bail here as well.
      return nullptr;
    }
  }

  if (visible_paragraph_end.IsNull())
    return nullptr;

  HTMLElement* const new_block =
      InsertNewDefaultParagraphElementAt(upstream_start, editing_state);
  if (editing_state->IsAborted())
    return nullptr;
  DCHECK(new_block);

  bool end_was_br =
      IsA<HTMLBRElement>(*visible_paragraph_end.DeepEquivalent().AnchorNode());

  // Inserting default paragraph element can change visible position. We
  // should update visible positions before use them.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  const VisiblePosition& destination =
      VisiblePosition::FirstPositionInNode(*new_block);
  if (destination.IsNull()) {
    // Reached by CompositeEditingCommandTest
    //    .MoveParagraphContentsToNewBlockWithNonEditableStyle.
    editing_state->Abort();
    return nullptr;
  }

  visible_pos = CreateVisiblePosition(pos);
  if (visible_pos.IsNull()) {
    editing_state->Abort();
    return nullptr;
  }
  visible_paragraph_start = StartOfParagraph(visible_pos);
  visible_paragraph_end = EndOfParagraph(visible_pos);
  DCHECK_LE(visible_paragraph_start.DeepEquivalent(),
            visible_paragraph_end.DeepEquivalent());
  MoveParagraphs(visible_paragraph_start, visible_paragraph_end, destination,
                 editing_state);
  if (editing_state->IsAborted())
    return nullptr;

  if (new_block->lastChild() && IsA<HTMLBRElement>(*new_block->lastChild()) &&
      !end_was_br) {
    RemoveNode(new_block->lastChild(), editing_state);
    if (editing_state->IsAborted())
      return nullptr;
  }

  return new_block;
}

void CompositeEditCommand::PushAnchorElementDown(Element* anchor_node,
                                                 EditingState* editing_state) {
  if (!anchor_node)
    return;

  DCHECK(anchor_node->IsLink()) << anchor_node;

  const VisibleSelection& visible_selection = CreateVisibleSelection(
      SelectionInDOMTree::Builder().SelectAllChildren(*anchor_node).Build());
  SetEndingSelection(
      SelectionForUndoStep::From(visible_selection.AsSelection()));
  ApplyStyledElement(anchor_node, editing_state);
  if (editing_state->IsAborted())
    return;
  // Clones of anchorNode have been pushed down, now remove it.
  if (anchor_node->isConnected())
    RemoveNodePreservingChildren(anchor_node, editing_state);
}

// Clone the paragraph between start and end under blockElement,
// preserving the hierarchy up to outerNode.

void CompositeEditCommand::CloneParagraphUnderNewElement(
    const Position& start,
    const Position& end,
    Node* passed_outer_node,
    Element* block_element,
    EditingState* editing_state) {
  DCHECK_LE(start, end);
  DCHECK(passed_outer_node);
  DCHECK(block_element);

  // First we clone the outerNode
  Node* last_node = nullptr;
  Node* outer_node = passed_outer_node;

  if (IsRootEditableElement(*outer_node)) {
    last_node = block_element;
  } else {
    last_node = outer_node->cloneNode(IsDisplayInsideTable(outer_node));
    AppendNode(last_node, block_element, editing_state);
    if (editing_state->IsAborted())
      return;
  }

  if (start.AnchorNode() != outer_node && last_node->IsElementNode() &&
      start.AnchorNode()->IsDescendantOf(outer_node)) {
    HeapVector<Member<Node>> ancestors;

    // Insert each node from innerNode to outerNode (excluded) in a list.
    for (Node& runner :
         NodeTraversal::InclusiveAncestorsOf(*start.AnchorNode())) {
      if (runner == outer_node)
        break;
      ancestors.push_back(runner);
    }

    // Clone every node between start.anchorNode() and outerBlock.

    for (wtf_size_t i = ancestors.size(); i != 0; --i) {
      Node* item = ancestors[i - 1].Get();
      Node* child = item->cloneNode(IsDisplayInsideTable(item));
      AppendNode(child, To<Element>(last_node), editing_state);
      if (editing_state->IsAborted())
        return;
      last_node = child;
    }
  }

  // Scripts specified in javascript protocol may remove |outerNode|
  // during insertion, e.g. <iframe src="javascript:...">
  if (!outer_node->isConnected())
    return;

  // Handle the case of paragraphs with more than one node,
  // cloning all the siblings until end.anchorNode() is reached.

  if (start.AnchorNode() != end.AnchorNode() &&
      !start.AnchorNode()->IsDescendantOf(end.AnchorNode())) {
    // If end is not a descendant of outerNode we need to
    // find the first common ancestor to increase the scope
    // of our nextSibling traversal.
    while (outer_node && !end.AnchorNode()->IsDescendantOf(outer_node)) {
      outer_node = outer_node->parentNode();
    }

    if (!outer_node)
      return;

    Node* start_node = start.AnchorNode();
    for (Node* node =
             NodeTraversal::NextSkippingChildren(*start_node, outer_node);
         node; node = NodeTraversal::NextSkippingChildren(*node, outer_node)) {
      // Move lastNode up in the tree as much as node was moved up in the tree
      // by NodeTraversal::nextSkippingChildren, so that the relative depth
      // between node and the original start node is maintained in the clone.
      while (start_node && last_node &&
             start_node->parentNode() != node->parentNode()) {
        start_node = start_node->parentNode();
        last_node = last_node->parentNode();
      }

      if (!last_node || !last_node->parentNode())
        return;

      Node* cloned_node = node->cloneNode(true);
      InsertNodeAfter(cloned_node, last_node, editing_state);
      if (editing_state->IsAborted())
        return;
      last_node = cloned_node;
      if (node == end.AnchorNode() || end.AnchorNode()->IsDescendantOf(node))
        break;
    }
  }
}

// There are bugs in deletion when it removes a fully selected table/list.
// It expands and removes the entire table/list, but will let content
// before and after the table/list collapse onto one line.
// Deleting a paragraph will leave a placeholder. Remove it (and prune
// empty or unrendered parents).

void CompositeEditCommand::CleanupAfterDeletion(EditingState* editing_state) {
  CleanupAfterDeletion(editing_state, VisiblePosition());
}

void CompositeEditCommand::CleanupAfterDeletion(EditingState* editing_state,
                                                VisiblePosition destination) {
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  VisiblePosition caret_after_delete = EndingVisibleSelection().VisibleStart();
  Node* destination_node = destination.DeepEquivalent().AnchorNode();
  if (caret_after_delete.DeepEquivalent() != destination.DeepEquivalent() &&
      IsStartOfParagraph(caret_after_delete) &&
      IsEndOfParagraph(caret_after_delete)) {
    // Note: We want the rightmost candidate.
    Position position =
        MostForwardCaretPosition(caret_after_delete.DeepEquivalent());
    Node* node = position.AnchorNode();

    // InsertListCommandTest.CleanupNodeSameAsDestinationNode reaches here.
    ABORT_EDITING_COMMAND_IF(destination_node == node);
    // Bail if we'd remove an ancestor of our destination.
    if (destination_node && destination_node->IsDescendantOf(node))
      return;

    // Normally deletion will leave a br as a placeholder.
    if (IsA<HTMLBRElement>(*node)) {
      RemoveNodeAndPruneAncestors(node, editing_state, destination_node);

      // If the selection to move was empty and in an empty block that
      // doesn't require a placeholder to prop itself open (like a bordered
      // div or an li), remove it during the move (the list removal code
      // expects this behavior).
    } else if (IsEnclosingBlock(node)) {
      // If caret position after deletion and destination position coincides,
      // node should not be removed.
      if (!RendersInDifferentPosition(position, destination.DeepEquivalent())) {
        Prune(node, editing_state, destination_node);
        return;
      }
      RemoveNodeAndPruneAncestors(node, editing_state, destination_node);
    } else if (LineBreakExistsAtPosition(position)) {
      // There is a preserved '\n' at caretAfterDelete.
      // We can safely assume this is a text node.
      auto* text_node = To<Text>(node);
      if (text_node->length() == 1)
        RemoveNodeAndPruneAncestors(node, editing_state, destination_node);
      else
        DeleteTextFromNode(text_node, position.ComputeOffsetInContainerNode(),
                           1);
    }
  }
}

// This is a version of moveParagraph that preserves style by keeping the
// original markup. It is currently used only by IndentOutdentCommand but it is
// meant to be used in the future by several other commands such as InsertList
// and the align commands.
// The blockElement parameter is the element to move the paragraph to, outerNode
// is the top element of the paragraph hierarchy.

void CompositeEditCommand::MoveParagraphWithClones(
    const VisiblePosition& start_of_paragraph_to_move,
    const VisiblePosition& end_of_paragraph_to_move,
    HTMLElement* block_element,
    Node* outer_node,
    EditingState* editing_state) {
  // InsertListCommandTest.InsertListWithCollapsedVisibility reaches here.
  ABORT_EDITING_COMMAND_IF(start_of_paragraph_to_move.IsNull());
  ABORT_EDITING_COMMAND_IF(end_of_paragraph_to_move.IsNull());
  DCHECK(outer_node);
  DCHECK(block_element);

  RelocatablePosition* relocatable_before_paragraph =
      MakeGarbageCollected<RelocatablePosition>(
          PreviousPositionOf(start_of_paragraph_to_move).DeepEquivalent());
  RelocatablePosition* relocatable_after_paragraph =
      MakeGarbageCollected<RelocatablePosition>(
          NextPositionOf(end_of_paragraph_to_move).DeepEquivalent());

  // We upstream() the end and downstream() the start so that we don't include
  // collapsed whitespace in the move. When we paste a fragment, spaces after
  // the end and before the start are treated as though they were rendered.
  Position start =
      MostForwardCaretPosition(start_of_paragraph_to_move.DeepEquivalent());
  Position end = start_of_paragraph_to_move.DeepEquivalent() ==
                         end_of_paragraph_to_move.DeepEquivalent()
                     ? start
                     : MostBackwardCaretPosition(
                           end_of_paragraph_to_move.DeepEquivalent());
  if (ComparePositions(start, end) > 0)
    end = start;

  CloneParagraphUnderNewElement(start, end, outer_node, block_element,
                                editing_state);

  SetEndingSelection(SelectionForUndoStep::From(
      SelectionInDOMTree::Builder().Collapse(start).Extend(end).Build()));
  if (!DeleteSelection(
          editing_state,
          DeleteSelectionOptions::Builder().SetSanitizeMarkup(true).Build()))
    return;

  // There are bugs in deletion when it removes a fully selected table/list.
  // It expands and removes the entire table/list, but will let content
  // before and after the table/list collapse onto one line.

  CleanupAfterDeletion(editing_state);
  if (editing_state->IsAborted())
    return;

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  // Add a br if pruning an empty block level element caused a collapse.  For
  // example:
  // foo^
  // <div>bar</div>
  // baz
  // Imagine moving 'bar' to ^.  'bar' will be deleted and its div pruned.  That
  // would cause 'baz' to collapse onto the line with 'foobar' unless we insert
  // a br. Must recononicalize these two VisiblePositions after the pruning
  // above.
  const VisiblePosition& before_paragraph =
      CreateVisiblePosition(relocatable_before_paragraph->GetPosition());
  const VisiblePosition& after_paragraph =
      CreateVisiblePosition(relocatable_after_paragraph->GetPosition());

  if (before_paragraph.IsNotNull() &&
      !IsDisplayInsideTable(before_paragraph.DeepEquivalent().AnchorNode()) &&
      ((!IsEndOfParagraph(before_paragraph) &&
        !IsStartOfParagraph(before_paragraph)) ||
       before_paragraph.DeepEquivalent() == after_paragraph.DeepEquivalent())) {
    // FIXME: Trim text between beforeParagraph and afterParagraph if they
    // aren't equal.
    InsertNodeAt(MakeGarbageCollected<HTMLBRElement>(GetDocument()),
                 before_paragraph.DeepEquivalent(), editing_state);
  }
}

void CompositeEditCommand::MoveParagraph(
    const VisiblePosition& start_of_paragraph_to_move,
    const VisiblePosition& end_of_paragraph_to_move,
    const VisiblePosition& destination,
    EditingState* editing_state,
    ShouldPreserveSelection should_preserve_selection,
    ShouldPreserveStyle should_preserve_style,
    Node* constraining_ancestor) {
  DCHECK(!GetDocument().NeedsLayoutTreeUpdate());
  DCHECK(IsStartOfParagraph(start_of_paragraph_to_move))
      << start_of_paragraph_to_move;
  DCHECK(IsEndOfParagraph(end_of_paragraph_to_move))
      << end_of_paragraph_to_move;
  MoveParagraphs(start_of_paragraph_to_move, end_of_paragraph_to_move,
                 destination, editing_state, should_preserve_selection,
                 should_preserve_style, constraining_ancestor);
}

void CompositeEditCommand::MoveParagraphs(
    const VisiblePosition& start_of_paragraph_to_move,
    const VisiblePosition& end_of_paragraph_to_move,
    const VisiblePosition& destination,
    EditingState* editing_state,
    ShouldPreserveSelection should_preserve_selection,
    ShouldPreserveStyle should_preserve_style,
    Node* constraining_ancestor) {
  DCHECK(!GetDocument().NeedsLayoutTreeUpdate());
  DCHECK(start_of_paragraph_to_move.IsNotNull());
  DCHECK(end_of_paragraph_to_move.IsNotNull());
  DCHECK(destination.IsNotNull());

  if (start_of_paragraph_to_move.DeepEquivalent() ==
          destination.DeepEquivalent() ||
      start_of_paragraph_to_move.IsNull())
    return;

  // Can't move the range to a destination inside itself.
  if (destination.DeepEquivalent() >=
          start_of_paragraph_to_move.DeepEquivalent() &&
      destination.DeepEquivalent() <=
          end_of_paragraph_to_move.DeepEquivalent()) {
    // Reached by unit test TypingCommandTest.insertLineBreakWithIllFormedHTML
    // and ApplyStyleCommandTest.JustifyRightDetachesDestination
    editing_state->Abort();
    return;
  }

  int start_index = -1;
  int end_index = -1;
  int destination_index = -1;
  if (should_preserve_selection == kPreserveSelection &&
      !EndingSelection().IsNone()) {
    VisiblePosition visible_start = EndingVisibleSelection().VisibleStart();
    VisiblePosition visible_end = EndingVisibleSelection().VisibleEnd();

    bool start_after_paragraph =
        ComparePositions(visible_start, end_of_paragraph_to_move) > 0;
    bool end_before_paragraph =
        ComparePositions(visible_end, start_of_paragraph_to_move) < 0;

    if (!start_after_paragraph && !end_before_paragraph) {
      bool start_in_paragraph =
          ComparePositions(visible_start, start_of_paragraph_to_move) >= 0;
      bool end_in_paragraph =
          ComparePositions(visible_end, end_of_paragraph_to_move) <= 0;

      const TextIteratorBehavior behavior =
          TextIteratorBehavior::AllVisiblePositionsRangeLengthBehavior();

      start_index = 0;
      if (start_in_paragraph) {
        start_index = TextIterator::RangeLength(
            start_of_paragraph_to_move.ToParentAnchoredPosition(),
            visible_start.ToParentAnchoredPosition(), behavior);
      }

      end_index = 0;
      if (end_in_paragraph) {
        end_index = TextIterator::RangeLength(
            start_of_paragraph_to_move.ToParentAnchoredPosition(),
            visible_end.ToParentAnchoredPosition(), behavior);
      }
    }
  }

  RelocatablePosition* before_paragraph_position =
      MakeGarbageCollected<RelocatablePosition>(
          PreviousPositionOf(start_of_paragraph_to_move,
                             kCannotCrossEditingBoundary)
              .DeepEquivalent());
  RelocatablePosition* after_paragraph_position =
      MakeGarbageCollected<RelocatablePosition>(
          NextPositionOf(end_of_paragraph_to_move, kCannotCrossEditingBoundary)
              .DeepEquivalent());

  const Position& start_candidate = start_of_paragraph_to_move.DeepEquivalent();
  const Position& end_candidate = end_of_paragraph_to_move.DeepEquivalent();
  DCHECK_LE(start_candidate, end_candidate);

  // We upstream() the end and downstream() the start so that we don't include
  // collapsed whitespace in the move. When we paste a fragment, spaces after
  // the end and before the start are treated as though they were rendered.
  Position start = MostForwardCaretPosition(start_candidate);
  Position end = MostBackwardCaretPosition(end_candidate);
  if (end < start)
    end = start;

  // FIXME: This is an inefficient way to preserve style on nodes in the
  // paragraph to move. It shouldn't matter though, since moved paragraphs will
  // usually be quite small.
  DocumentFragment* fragment = nullptr;
  if (start_of_paragraph_to_move.DeepEquivalent() !=
      end_of_paragraph_to_move.DeepEquivalent()) {
    const String paragraphs_markup = CreateMarkup(
        start.ParentAnchoredEquivalent(), end.ParentAnchoredEquivalent(),
        CreateMarkupOptions::Builder()
            .SetShouldConvertBlocksToInlines(true)
            .SetConstrainingAncestor(constraining_ancestor)
            .Build());
    fragment = CreateStrictlyProcessedFragmentFromMarkupWithContext(
        GetDocument(), paragraphs_markup, 0, paragraphs_markup.length(), "");
  }

  // A non-empty paragraph's style is moved when we copy and move it.  We don't
  // move anything if we're given an empty paragraph, but an empty paragraph can
  // have style too, <div><b><br></b></div> for example.  Save it so that we can
  // preserve it later.
  EditingStyle* style_in_empty_paragraph = nullptr;
  if (start_of_paragraph_to_move.DeepEquivalent() ==
          end_of_paragraph_to_move.DeepEquivalent() &&
      should_preserve_style == kPreserveStyle) {
    style_in_empty_paragraph = MakeGarbageCollected<EditingStyle>(
        start_of_paragraph_to_move.DeepEquivalent());
    style_in_empty_paragraph->MergeTypingStyle(&GetDocument());
    // The moved paragraph should assume the block style of the destination.
    style_in_empty_paragraph->RemoveBlockProperties(
        GetDocument().GetExecutionContext());
  }

  // FIXME (5098931): We should add a new insert action
  // "WebViewInsertActionMoved" and call shouldInsertFragment here.

  DCHECK(!GetDocument().NeedsLayoutTreeUpdate());

  const VisibleSelection& selection_to_delete = CreateVisibleSelection(
      SelectionInDOMTree::Builder().Collapse(start).Extend(end).Build());
  SetEndingSelection(
      SelectionForUndoStep::From(selection_to_delete.AsSelection()));
  if (!DeleteSelection(
          editing_state,
          DeleteSelectionOptions::Builder().SetSanitizeMarkup(true).Build()))
    return;

  DCHECK(destination.DeepEquivalent().IsConnected()) << destination;
  CleanupAfterDeletion(editing_state, destination);
  if (editing_state->IsAborted())
    return;
  DCHECK(destination.DeepEquivalent().IsConnected()) << destination;

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  // Add a br if pruning an empty block level element caused a collapse. For
  // example:
  // foo^
  // <div>bar</div>
  // baz
  // Imagine moving 'bar' to ^. 'bar' will be deleted and its div pruned. That
  // would cause 'baz' to collapse onto the line with 'foobar' unless we insert
  // a br. Must recononicalize these two VisiblePositions after the pruning
  // above.
  VisiblePosition before_paragraph =
      CreateVisiblePosition(before_paragraph_position->GetPosition());
  VisiblePosition after_paragraph =
      CreateVisiblePosition(after_paragraph_position->GetPosition());
  if (before_paragraph.IsNotNull() &&
      ((!IsStartOfParagraph(before_paragraph) &&
        !IsEndOfParagraph(before_paragraph)) ||
       before_paragraph.DeepEquivalent() == after_paragraph.DeepEquivalent())) {
    // FIXME: Trim text between beforeParagraph and afterParagraph if they
    // aren't equal.
    InsertNodeAt(MakeGarbageCollected<HTMLBRElement>(GetDocument()),
                 before_paragraph.DeepEquivalent(), editing_state);
    if (editing_state->IsAborted())
      return;
  }

  // TextIterator::rangeLength requires clean layout.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  destination_index = TextIterator::RangeLength(
      Position::FirstPositionInNode(*GetDocument().documentElement()),
      destination.ToParentAnchoredPosition(),
      TextIteratorBehavior::AllVisiblePositionsRangeLengthBehavior());

  const VisibleSelection& destination_selection =
      CreateVisibleSelection(SelectionInDOMTree::Builder()
                                 .Collapse(destination.ToPositionWithAffinity())
                                 .Build());
  if (EndingSelection().IsNone()) {
    // We abort executing command since |destination| becomes invisible.
    editing_state->Abort();
    return;
  }
  SetEndingSelection(
      SelectionForUndoSt
"""


```