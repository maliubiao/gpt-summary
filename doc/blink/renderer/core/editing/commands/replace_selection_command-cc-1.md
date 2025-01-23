Response:
The user wants me to summarize the functionality of the provided C++ code snippet from the Chromium Blink engine. This is the second part of a three-part sequence. I need to identify the key actions and goals of this specific block of code within the broader `ReplaceSelectionCommand`.

Here's a breakdown of the code's functions:

1. **`RemoveUnrenderedTextNodesAtEnds(InsertedNodes& inserted_nodes)`**: Removes text nodes at the beginning or end of inserted content if they don't have visible layout. It avoids removing nodes inside `<select>` or `<script>` tags.

2. **`PositionAtEndOfInsertedContent()`**: Returns the visible position at the end of the inserted content, handling cases where the end is inside a `<select>` element.

3. **`PositionAtStartOfInsertedContent()`**: Returns the visible position at the start of the inserted content.

4. **`RemoveHeadContents(ReplacementFragment& fragment)`**: Removes specific HTML head elements (`base`, `link`, `meta`, `style`, `title`, `svg style`) from the replacement fragment.

5. **`FollowBlockElementStyle(const Node* node)`**: Determines if the style of a block element should be followed when inserting content into it. It handles special cases for list items, table cells, and pre elements, potentially considering a runtime feature flag.

6. **`HandleStyleSpansBeforeInsertion(ReplacementFragment& fragment, const Position& insertion_pos)`**: Optimizes by removing unnecessary style spans at the beginning of the fragment before insertion, especially when pasting into a block element. It avoids this optimization in certain scenarios like pasting into a mail blockquote.

7. **`MergeEndIfNeeded(EditingState* editing_state)`**: Merges the end of the inserted content with the content that follows it, potentially moving paragraphs to maintain block styles. It avoids infinite recursion and uses a placeholder node to handle edge cases.

8. **`EnclosingInline(Node* node)`**: Finds the nearest enclosing inline element of a given node.

9. **`IsInlineHTMLElementWithStyle(const Node* node)`**: Checks if a node is an inline HTML element with a style (specifically a styled span or HTML equivalent).

10. **`ElementToSplitToAvoidPastingIntoInlineElementsWithStyle(const Position& insertion_pos)`**: Determines if an inline element with style needs to be split to prevent pasting content directly into it.

11. **`SetUpStyle(const VisibleSelection& selection)`**: Initializes the insertion style based on the current selection, potentially disabling style matching for plain text selections.

12. **`InsertParagraphSeparatorIfNeeds(const VisibleSelection& selection, const ReplacementFragment& fragment, EditingState* editing_state)`**: Inserts paragraph separators before or after the inserted content based on the selection and the fragment's content. It handles cases where the selection spans multiple blocks and aims to prevent unnecessary nesting.

13. **`DoApply(EditingState* editing_state)`**: This is the main function where the insertion logic happens. It performs several steps:
    - Handles trivial replacements.
    - Sets up the insertion style.
    - Inserts paragraph separators if needed.
    - Breaks out of mail blockquotes if necessary.
    - Prepares whitespace for splitting.
    - Adjusts the insertion position to avoid nesting.
    - Removes head content from the fragment.
    - Avoids pasting into specific inline elements by splitting.
    - Inserts the nodes from the fragment.
    - Removes unrendered text nodes.
    - Makes inserted content round-trippable.
    - Removes redundant styles.
    - Sanitizes the markup if requested.
    - Sets the start and end positions of the inserted content.
    - Determines if merging at the start and end is needed.

The code interacts with the DOM (Document Object Model) extensively, manipulating nodes and their properties. It also considers styling and layout aspects.

Now, let's synthesize the summary.
This part of the `replace_selection_command.cc` file in the Chromium Blink engine primarily focuses on **manipulating and refining the content to be inserted** and **adjusting the insertion point** before the actual insertion takes place. It also handles merging the inserted content with the surrounding content after insertion.

Here's a breakdown of its key functionalities:

*   **Cleaning up inserted content:** It removes unrendered text nodes at the beginning and end of the content to be inserted, ensuring only visually relevant text is added. This avoids issues with whitespace or empty text nodes causing unexpected layout. It specifically avoids removing nodes within `<select>` and `<script>` tags.
*   **Determining insertion boundaries:** It calculates the start and end positions of the inserted content after it has been added to the DOM. This is crucial for subsequent operations like merging or selecting the inserted content. It handles edge cases like insertion within `<select>` elements.
*   **Removing irrelevant head elements:** When pasting content, it strips out elements typically found in the `<head>` section of an HTML document (like `<base>`, `<link>`, `<meta>`, `<style>`, `<title>`), preventing them from being inserted into the editable content.
*   **Handling styling:**
    *   It determines whether the styling of the surrounding block element should be adopted for the inserted content. This is important for maintaining visual consistency, especially when pasting into empty blocks or specific block-level elements like list items or table cells. A runtime flag can influence this behavior for certain elements.
    *   It optimizes the insertion process by removing unnecessary style spans at the beginning of the content if the surrounding block already provides the same styling. This avoids redundant markup.
    *   It sets up the styling for the inserted content based on the current selection, potentially inheriting or merging styles. It can skip this step for plain text selections.
*   **Managing paragraph breaks:** It strategically inserts paragraph separators (`<br>`) before and after the content being inserted, depending on the selection and the structure of the content. This prevents unwanted nesting of block-level elements and ensures proper paragraph breaks are maintained. It considers scenarios like pasting into empty paragraphs, across multiple blocks, or into mail blockquotes.
*   **Adjusting the insertion point:** It modifies the insertion position to avoid problems like:
    *   Nesting content within unintended block-level elements.
    *   Inserting content directly into inline elements that have their own styling, potentially splitting those elements.
    *   Inserting content at the very start or end of a link, moving the insertion point outside the link.
    *   Inserting content into tab spans, splitting the span.
*   **Merging inserted content:** It handles merging the newly inserted content with the content before and after it. This includes moving entire paragraphs if necessary to maintain the correct block structure and prevent visual breaks. It carefully considers the position of the selection and the inserted content to avoid infinite recursion and uses placeholder elements as needed.
*   **Core insertion logic (`DoApply`):** This is the main function in this part. It orchestrates the entire process:
    *   It performs a trivial replace if possible.
    *   Sets up the styling.
    *   Inserts paragraph separators as needed.
    *   Breaks out of mail blockquotes.
    *   Prepares whitespace.
    *   Adjusts the insertion position.
    *   Removes head content.
    *   Handles potential splitting of inline elements.
    *   Inserts the nodes from the replacement fragment.
    *   Removes unrendered text nodes.
    *   Makes the inserted content round-trippable (ensuring it can be serialized and deserialized without loss).
    *   Removes redundant styles.
    *   Optionally sanitizes the inserted markup.
    *   Sets the start and end points of the inserted content.
    *   Determines whether to merge at the start and end.

**Relationship to Javascript, HTML, and CSS:**

*   **HTML:** The code directly manipulates HTML elements and their structure. It creates, removes, and inserts nodes like `Text`, `Span`, `BR`, and other HTML elements. The code works with specific HTML tags like `<select>`, `<script>`, `<p>`, `<div>`, `<li>`, `<table>`, etc.
*   **CSS:** The code considers the styling of elements. It checks for block-level elements, inline elements, and attempts to maintain or avoid inheriting styles based on the context. The `EditingStyle` class and checks for style attributes are related to CSS.
*   **Javascript:** While this is C++ code, its actions are triggered by user interactions or Javascript commands that initiate editing operations. Javascript might call functions that eventually lead to the execution of `ReplaceSelectionCommand`. For example, `document.execCommand('insertHTML', ...)` or user typing could trigger this code.

**Examples Illustrating Relationships:**

*   **HTML:** When the code inserts a paragraph separator, it's essentially creating a `<br>` tag (or splitting blocks). When it removes head content, it's specifically targeting HTML elements like `<meta>` or `<style>`.
*   **CSS:** When `FollowBlockElementStyle` is true for a list item (`<li>`), and you paste content into an empty list item, the pasted content will likely inherit the list item's styling (e.g., bullet points). If it's false, the pasted content might retain its original styling.
*   **Javascript:** If a Javascript function uses `document.execCommand('insertText', 'Hello')`, this C++ code would be involved in inserting the "Hello" text into the DOM at the current selection, considering styling and potentially inserting paragraph breaks if necessary.

**Logical Reasoning with Assumptions:**

**Hypothetical Input:** User pastes the following HTML snippet into an empty `<p>` tag:

```html
<div>New Paragraph</div>
<p>Some text</p>
```

**Assumptions:**

1. The caret is within an empty `<p>` element.
2. `prevent_nesting_` is true.
3. The `<div>` and `<p>` have different default styles.

**Reasoning:**

1. `InsertParagraphSeparatorIfNeeds` will likely insert a `<br>` before and after the pasted content because `prevent_nesting_` is true and the pasted content contains block-level elements.
2. The code might call `FollowBlockElementStyle` to determine if the styling of the original empty `<p>` should be maintained.
3. The `<div>` and `<p>` will be inserted as separate block elements, not nested within the original `<p>`.

**Hypothetical Output (Conceptual DOM Structure):**

```html
<p><br></p>  <!-- Original empty paragraph with a BR added -->
<div>New Paragraph</div>
<p>Some text</p>
<p><br></p> <!-- Another paragraph break added after the pasted content -->
```

**User or Programming Errors:**

*   **Pasting invalid HTML:** If the user or script attempts to paste malformed HTML, this code might try to sanitize it, but in some cases, it could lead to unexpected DOM structures or even crashes if the parsing fails.
*   **Incorrectly setting editing state:** If the `EditingState` object passed to the functions is not correctly initialized or reflects an inconsistent state, it could lead to unexpected behavior or editing errors.
*   **Interfering with mutations:** If other scripts or code are concurrently modifying the DOM while this command is executing, it could lead to race conditions and unexpected outcomes, especially with the checks for node connectivity.

**Debugging Clues and User Actions:**

To reach this part of the code during debugging, a likely user action would be **pasting content** into an editable area. Here's a potential sequence:

1. User selects some text or places the caret in an editable HTML element (e.g., a `<div>` with `contenteditable="true"`).
2. User copies content from another source (could be text or rich text).
3. User presses `Ctrl+V` (or uses the "Paste" menu option).
4. The browser's event handling mechanism detects the paste event.
5. The browser's rendering engine (Blink in this case) initiates the `ReplaceSelectionCommand`.
6. The `ReplaceSelectionCommand::DoApply` function is called.
7. The code in this section is executed to preprocess the pasted content and determine the insertion point.

Debugging this code would involve setting breakpoints within the `DoApply` function and stepping through the various stages of content manipulation and insertion point adjustment. Examining the DOM structure before and after each step would be crucial to understanding the code's behavior.

**Summary of Functionality (Part 2):**

This part of `replace_selection_command.cc` focuses on **preparing and refining the content to be inserted** and **adjusting the insertion point** within the DOM. It involves cleaning up the content, handling styling considerations, managing paragraph breaks, and strategically modifying the insertion location to ensure proper DOM structure and visual consistency after the paste operation. It also handles merging the inserted content with its surroundings.

### 提示词
```
这是目录为blink/renderer/core/editing/commands/replace_selection_command.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
ed_nodes) {
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  auto* last_leaf_inserted = DynamicTo<Text>(inserted_nodes.LastLeafInserted());
  if (last_leaf_inserted && !NodeHasVisibleLayoutText(*last_leaf_inserted) &&
      !EnclosingElementWithTag(FirstPositionInOrBeforeNode(*last_leaf_inserted),
                               html_names::kSelectTag) &&
      !EnclosingElementWithTag(FirstPositionInOrBeforeNode(*last_leaf_inserted),
                               html_names::kScriptTag)) {
    inserted_nodes.WillRemoveNode(*last_leaf_inserted);
    // Removing a Text node won't dispatch synchronous events.
    RemoveNode(last_leaf_inserted, ASSERT_NO_EDITING_ABORT);
  }

  // We don't have to make sure that firstNodeInserted isn't inside a select or
  // script element, because it is a top level node in the fragment and the user
  // can't insert into those elements.
  auto* first_node_inserted =
      DynamicTo<Text>(inserted_nodes.FirstNodeInserted());
  if (first_node_inserted) {
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
    if (!NodeHasVisibleLayoutText(*first_node_inserted)) {
      inserted_nodes.WillRemoveNode(*first_node_inserted);
      // Removing a Text node won't dispatch synchronous events.
      RemoveNode(first_node_inserted, ASSERT_NO_EDITING_ABORT);
    }
  }
}

VisiblePosition ReplaceSelectionCommand::PositionAtEndOfInsertedContent()
    const {
  // TODO(editing-dev): Hoist the call and change it into a DCHECK.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  // TODO(yosin): We should set |end_of_inserted_content_| not in SELECT
  // element, since contents of SELECT elements, e.g. OPTION, OPTGROUP, are
  // not editable, or SELECT element is an atomic on editing.
  auto* enclosing_select = To<HTMLSelectElement>(EnclosingElementWithTag(
      end_of_inserted_content_, html_names::kSelectTag));
  if (enclosing_select) {
    return CreateVisiblePosition(LastPositionInOrAfterNode(*enclosing_select));
  }
  if (end_of_inserted_content_.IsOrphan())
    return VisiblePosition();
  return CreateVisiblePosition(end_of_inserted_content_);
}

VisiblePosition ReplaceSelectionCommand::PositionAtStartOfInsertedContent()
    const {
  // TODO(editing-dev): Hoist the call and change it into a DCHECK.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  if (start_of_inserted_content_.IsOrphan())
    return VisiblePosition();
  return CreateVisiblePosition(start_of_inserted_content_);
}

static void RemoveHeadContents(ReplacementFragment& fragment) {
  Node* next = nullptr;
  for (Node* node = fragment.FirstChild(); node; node = next) {
    if (IsA<HTMLBaseElement>(*node) || IsA<HTMLLinkElement>(*node) ||
        IsA<HTMLMetaElement>(*node) || IsA<HTMLStyleElement>(*node) ||
        IsA<HTMLTitleElement>(*node) || IsA<SVGStyleElement>(*node)) {
      next = NodeTraversal::NextSkippingChildren(*node);
      fragment.RemoveNode(node);
    } else {
      next = NodeTraversal::Next(*node);
    }
  }
}

static bool FollowBlockElementStyle(const Node* node) {
  const auto* element = DynamicTo<HTMLElement>(node);
  if (!element)
    return false;
  // When content is inserted into an empty block, use the original style
  // instead of the block style.
  if (!node->firstChild())
    return false;
  // A block with a placeholder BR appears the same as an empty block.
  if (node->firstChild() == node->lastChild() &&
      IsA<HTMLBRElement>(node->firstChild())) {
    return false;
  }

  bool should_follow_block_element_style =
  // TODO(https://crbug.com/352610616): Investigate preserving styles within
  // list elements in block merge scenarios.
      IsListItem(node) ||

      IsTableCell(node) ||

  // TODO(https://crbug.com/352038138): Investigate preserving styles within
  // pre elements in block merge scenarios.
      element->HasTagName(html_names::kPreTag);
  if (RuntimeEnabledFeatures::
          PreserveFollowingBlockStylesDuringBlockMergeEnabled()) {
    return should_follow_block_element_style;
  } else {
    return should_follow_block_element_style ||
           element->HasTagName(html_names::kH1Tag) ||
           element->HasTagName(html_names::kH2Tag) ||
           element->HasTagName(html_names::kH3Tag) ||
           element->HasTagName(html_names::kH4Tag) ||
           element->HasTagName(html_names::kH5Tag) ||
           element->HasTagName(html_names::kH6Tag);
  }
}

// Remove style spans before insertion if they are unnecessary.  It's faster
// because we'll avoid doing a layout.
void ReplaceSelectionCommand::HandleStyleSpansBeforeInsertion(
    ReplacementFragment& fragment,
    const Position& insertion_pos) {
  Node* top_node = fragment.FirstChild();
  if (!IsA<HTMLSpanElement>(top_node))
    return;

  // Handling the case where we are doing Paste as Quotation or pasting into
  // quoted content is more complicated (see handleStyleSpans) and doesn't
  // receive the optimization.
  if (EnclosingNodeOfType(FirstPositionInOrBeforeNode(*top_node),
                          IsMailHTMLBlockquoteElement,
                          kCanCrossEditingBoundary))
    return;

  // Remove style spans to follow the styles of parent block element when
  // |fragment| becomes a part of it. See bugs http://crbug.com/226941 and
  // http://crbug.com/335955.
  auto* wrapping_style_span = To<HTMLSpanElement>(top_node);
  const Node* node = insertion_pos.AnchorNode();
  // |node| can be an inline element like <br> under <li>
  // e.g.) editing/execCommand/switch-list-type.html
  //       editing/deleting/backspace-merge-into-block.html
  if (IsInlineNode(node)) {
    node = EnclosingBlock(insertion_pos.AnchorNode());
    if (!node)
      return;
  }

  if (GetInputType() != InputEvent::InputType::kInsertFromPaste &&
      FollowBlockElementStyle(node)) {
    fragment.RemoveNodePreservingChildren(wrapping_style_span);
    return;
  }

  EditingStyle* style_at_insertion_pos = MakeGarbageCollected<EditingStyle>(
      insertion_pos.ParentAnchoredEquivalent());
  String style_text = style_at_insertion_pos->Style()->AsText();

  // FIXME: This string comparison is a naive way of comparing two styles.
  // We should be taking the diff and check that the diff is empty.
  if (style_text != wrapping_style_span->getAttribute(html_names::kStyleAttr))
    return;

  fragment.RemoveNodePreservingChildren(wrapping_style_span);
}

void ReplaceSelectionCommand::MergeEndIfNeeded(EditingState* editing_state) {
  if (!should_merge_end_)
    return;

  VisiblePosition start_of_inserted_content(PositionAtStartOfInsertedContent());
  VisiblePosition end_of_inserted_content(PositionAtEndOfInsertedContent());

  // Bail to avoid infinite recursion.
  if (moving_paragraph_) {
    return;
  }

  // Merging two paragraphs will destroy the moved one's block styles.  Always
  // move the end of inserted forward to preserve the block style of the
  // paragraph already in the document, unless the paragraph to move would
  // include the what was the start of the selection that was pasted into, so
  // that we preserve that paragraph's block styles.
  bool merge_forward =
      !(InSameParagraph(start_of_inserted_content, end_of_inserted_content) &&
        !IsStartOfParagraph(start_of_inserted_content));

  VisiblePosition destination = merge_forward
                                    ? NextPositionOf(end_of_inserted_content)
                                    : end_of_inserted_content;
  // TODO(editing-dev): Stop storing VisiblePositions through mutations.
  // See crbug.com/648949 for details.
  VisiblePosition start_of_paragraph_to_move =
      merge_forward ? StartOfParagraph(end_of_inserted_content)
                    : NextPositionOf(end_of_inserted_content);

  // Merging forward could result in deleting the destination anchor node.
  // To avoid this, we add a placeholder node before the start of the paragraph.
  if (EndOfParagraph(start_of_paragraph_to_move).DeepEquivalent() ==
      destination.DeepEquivalent()) {
    auto* placeholder = MakeGarbageCollected<HTMLBRElement>(GetDocument());
    InsertNodeBefore(placeholder,
                     start_of_paragraph_to_move.DeepEquivalent().AnchorNode(),
                     editing_state);
    if (editing_state->IsAborted())
      return;

    // TODO(editing-dev): Use of UpdateStyleAndLayout()
    // needs to be audited.  See http://crbug.com/590369 for more details.
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

    destination = VisiblePosition::BeforeNode(*placeholder);
    start_of_paragraph_to_move = CreateVisiblePosition(
        start_of_paragraph_to_move.ToPositionWithAffinity());
  }

  MoveParagraph(start_of_paragraph_to_move,
                EndOfParagraph(start_of_paragraph_to_move), destination,
                editing_state);
  if (editing_state->IsAborted())
    return;

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  // Merging forward will remove end_of_inserted_content from the document.
  if (merge_forward) {
    const VisibleSelection& visible_selection = EndingVisibleSelection();
    if (start_of_inserted_content_.IsOrphan()) {
      start_of_inserted_content_ =
          visible_selection.VisibleStart().DeepEquivalent();
    }
    end_of_inserted_content_ = visible_selection.VisibleEnd().DeepEquivalent();
    // If we merged text nodes, end_of_inserted_content_ could be null. If
    // this is the case, we use start_of_inserted_content_.
    if (end_of_inserted_content_.IsNull())
      end_of_inserted_content_ = start_of_inserted_content_;
  }
}

static Node* EnclosingInline(Node* node) {
  while (ContainerNode* parent = node->parentNode()) {
    if (IsBlockFlowElement(*parent) || IsA<HTMLBodyElement>(*parent))
      return node;
    // Stop if any previous sibling is a block.
    for (Node* sibling = node->previousSibling(); sibling;
         sibling = sibling->previousSibling()) {
      if (IsBlockFlowElement(*sibling))
        return node;
    }
    node = parent;
  }
  return node;
}

static bool IsInlineHTMLElementWithStyle(const Node* node) {
  // We don't want to skip over any block elements.
  if (IsEnclosingBlock(node))
    return false;

  const auto* element = DynamicTo<HTMLElement>(node);
  if (!element)
    return false;

  // We can skip over elements whose class attribute is
  // one of our internal classes.
  return EditingStyle::ElementIsStyledSpanOrHTMLEquivalent(element);
}

static inline HTMLElement*
ElementToSplitToAvoidPastingIntoInlineElementsWithStyle(
    const Position& insertion_pos) {
  Element* containing_block =
      EnclosingBlock(insertion_pos.ComputeContainerNode());
  return To<HTMLElement>(HighestEnclosingNodeOfType(
      insertion_pos, IsInlineHTMLElementWithStyle, kCannotCrossEditingBoundary,
      containing_block));
}

void ReplaceSelectionCommand::SetUpStyle(const VisibleSelection& selection) {
  // We can skip matching the style if the selection is plain text.
  // TODO(editing-dev): Use IsEditablePosition instead of using UsedUserModify
  // directly.
  if ((selection.Start().AnchorNode()->GetLayoutObject() &&
       selection.Start()
               .AnchorNode()
               ->GetLayoutObject()
               ->Style()
               ->UsedUserModify() == EUserModify::kReadWritePlaintextOnly) &&
      (selection.End().AnchorNode()->GetLayoutObject() &&
       selection.End()
               .AnchorNode()
               ->GetLayoutObject()
               ->Style()
               ->UsedUserModify() == EUserModify::kReadWritePlaintextOnly))
    match_style_ = false;

  if (match_style_) {
    insertion_style_ = MakeGarbageCollected<EditingStyle>(selection.Start());
    insertion_style_->MergeTypingStyle(&GetDocument());
  }
}

void ReplaceSelectionCommand::InsertParagraphSeparatorIfNeeds(
    const VisibleSelection& selection,
    const ReplacementFragment& fragment,
    EditingState* editing_state) {
  const VisiblePosition visible_start = selection.VisibleStart();
  const VisiblePosition visible_end = selection.VisibleEnd();

  const bool selection_end_was_end_of_paragraph = IsEndOfParagraph(visible_end);
  const bool selection_start_was_start_of_paragraph =
      IsStartOfParagraph(visible_start);

  Element* const enclosing_block_of_visible_start =
      EnclosingBlock(visible_start.DeepEquivalent().AnchorNode());

  const bool start_is_inside_mail_blockquote = EnclosingNodeOfType(
      selection.Start(), IsMailHTMLBlockquoteElement, kCanCrossEditingBoundary);
  const bool selection_is_plain_text =
      !IsRichlyEditablePosition(selection.Anchor());
  Element* const current_root = selection.RootEditableElement();

  if ((selection_start_was_start_of_paragraph &&
       selection_end_was_end_of_paragraph &&
       !start_is_inside_mail_blockquote) ||
      enclosing_block_of_visible_start == current_root ||
      IsListItem(enclosing_block_of_visible_start) || selection_is_plain_text) {
    prevent_nesting_ = false;
  }

  if (selection.IsRange()) {
    // When the end of the selection being pasted into is at the end of a
    // paragraph, and that selection spans multiple blocks, not merging may
    // leave an empty line.
    // When the start of the selection being pasted into is at the start of a
    // block, not merging will leave hanging block(s).
    // Merge blocks if the start of the selection was in a Mail blockquote,
    // since we handle that case specially to prevent nesting.
    bool merge_blocks_after_delete = start_is_inside_mail_blockquote ||
                                     IsEndOfParagraph(visible_end) ||
                                     IsStartOfBlock(visible_start);
    // FIXME: We should only expand to include fully selected special elements
    // if we are copying a selection and pasting it on top of itself.
    if (!DeleteSelection(editing_state, DeleteSelectionOptions::Builder()
                                            .SetMergeBlocksAfterDelete(
                                                merge_blocks_after_delete)
                                            .SetSanitizeMarkup(true)
                                            .Build()))
      return;
    if (fragment.HasInterchangeNewlineAtStart()) {
      GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
      VisiblePosition start_after_delete =
          EndingVisibleSelection().VisibleStart();
      if (IsEndOfParagraph(start_after_delete) &&
          !IsStartOfParagraph(start_after_delete) &&
          !IsEndOfEditableOrNonEditableContent(start_after_delete)) {
        SetEndingSelection(SelectionForUndoStep::From(
            SelectionInDOMTree::Builder()
                .Collapse(NextPositionOf(start_after_delete).DeepEquivalent())
                .Build()));
      } else {
        InsertParagraphSeparator(editing_state);
      }
      if (editing_state->IsAborted())
        return;
    }
  } else {
    DCHECK(selection.IsCaret());
    if (fragment.HasInterchangeNewlineAtStart()) {
      const VisiblePosition next =
          NextPositionOf(visible_start, kCannotCrossEditingBoundary);
      if (IsEndOfParagraph(visible_start) &&
          !IsStartOfParagraph(visible_start) && next.IsNotNull()) {
        SetEndingSelection(
            SelectionForUndoStep::From(SelectionInDOMTree::Builder()
                                           .Collapse(next.DeepEquivalent())
                                           .Build()));
      } else {
        InsertParagraphSeparator(editing_state);
        if (editing_state->IsAborted())
          return;
        GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
      }
    }
    // We split the current paragraph in two to avoid nesting the blocks from
    // the fragment inside the current block.
    //
    // For example, paste
    //   <div>foo</div><div>bar</div><div>baz</div>
    // into
    //   <div>x^x</div>
    // where ^ is the caret.
    //
    // As long as the div styles are the same, visually you'd expect:
    //   <div>xbar</div><div>bar</div><div>bazx</div>
    // not
    //   <div>xbar<div>bar</div><div>bazx</div></div>
    // Don't do this if the selection started in a Mail blockquote.
    const VisiblePosition visible_start_position =
        EndingVisibleSelection().VisibleStart();
    if (prevent_nesting_ && !start_is_inside_mail_blockquote &&
        !IsEndOfParagraph(visible_start_position) &&
        !IsStartOfParagraph(visible_start_position)) {
      InsertParagraphSeparator(editing_state);
      if (editing_state->IsAborted())
        return;
      GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
      SetEndingSelection(SelectionForUndoStep::From(
          SelectionInDOMTree::Builder()
              .Collapse(
                  PreviousPositionOf(EndingVisibleSelection().VisibleStart())
                      .DeepEquivalent())
              .Build()));
    }
  }
}

void ReplaceSelectionCommand::DoApply(EditingState* editing_state) {
  TRACE_EVENT0("blink", "ReplaceSelectionCommand::doApply");
  const VisibleSelection& selection = EndingVisibleSelection();

  // ReplaceSelectionCommandTest.CrashWithNoSelection hits below abort
  // condition.
  ABORT_EDITING_COMMAND_IF(selection.IsNone());
  ABORT_EDITING_COMMAND_IF(!selection.IsValidFor(GetDocument()));

  if (!selection.RootEditableElement())
    return;

  ReplacementFragment fragment(&GetDocument(), document_fragment_.Get(),
                               selection);
  bool trivial_replace_result = PerformTrivialReplace(fragment, editing_state);
  if (editing_state->IsAborted())
    return;
  if (trivial_replace_result)
    return;

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  SetUpStyle(selection);
  Element* const current_root = selection.RootEditableElement();
  const bool start_is_inside_mail_blockquote = EnclosingNodeOfType(
      selection.Start(), IsMailHTMLBlockquoteElement, kCanCrossEditingBoundary);
  const bool selection_is_plain_text =
      !IsRichlyEditablePosition(selection.Anchor());
  const bool selection_end_was_end_of_paragraph =
      IsEndOfParagraph(selection.VisibleEnd());
  const bool selection_start_was_start_of_paragraph =
      IsStartOfParagraph(selection.VisibleStart());
  InsertParagraphSeparatorIfNeeds(selection, fragment, editing_state);
  if (editing_state->IsAborted())
    return;

  Position insertion_pos = EndingVisibleSelection().Start();
  Position placeholder;
  if (RuntimeEnabledFeatures::RemoveCollapsedPlaceholderEnabled()) {
    placeholder = ComputePlaceholderToCollapseAt(insertion_pos);
  }

  // We don't want any of the pasted content to end up nested in a Mail
  // blockquote, so first break out of any surrounding Mail blockquotes. Unless
  // we're inserting in a table, in which case breaking the blockquote will
  // prevent the content from actually being inserted in the table.
  if (EnclosingNodeOfType(insertion_pos, IsMailHTMLBlockquoteElement,
                          kCanCrossEditingBoundary) &&
      prevent_nesting_ &&
      !(EnclosingNodeOfType(insertion_pos, &IsTableStructureNode))) {
    ApplyCommandToComposite(
        MakeGarbageCollected<BreakBlockquoteCommand>(GetDocument()),
        editing_state);
    if (editing_state->IsAborted())
      return;
    // This will leave a br between the split.
    Node* br = EndingVisibleSelection().Start().AnchorNode();
    DCHECK(IsA<HTMLBRElement>(br)) << br;
    // Insert content between the two blockquotes, but remove the br (since it
    // was just a placeholder).
    insertion_pos = Position::InParentBeforeNode(*br);
    RemoveNode(br, editing_state);
    if (editing_state->IsAborted())
      return;
  }

  // Inserting content could cause whitespace to collapse, e.g. inserting
  // <div>foo</div> into hello^ world.
  PrepareWhitespaceAtPositionForSplit(insertion_pos);

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  // If the downstream node has been removed there's no point in continuing.
  if (!MostForwardCaretPosition(insertion_pos).AnchorNode())
    return;

  // NOTE: This would be an incorrect usage of downstream() if downstream() were
  // changed to mean the last position after p that maps to the same visible
  // position as p (since in the case where a br is at the end of a block and
  // collapsed away, there are positions after the br which map to the same
  // visible position as [br, 0]).
  auto* end_br = DynamicTo<HTMLBRElement>(
      *MostForwardCaretPosition(insertion_pos).AnchorNode());
  VisiblePosition original_vis_pos_before_end_br;
  if (end_br) {
    original_vis_pos_before_end_br =
        PreviousPositionOf(VisiblePosition::BeforeNode(*end_br));
  }

  Element* enclosing_block_of_insertion_pos =
      EnclosingBlock(insertion_pos.AnchorNode());

  // Adjust |enclosingBlockOfInsertionPos| to prevent nesting.
  // If the start was in a Mail blockquote, we will have already handled
  // adjusting |enclosingBlockOfInsertionPos| above.
  if (prevent_nesting_ && enclosing_block_of_insertion_pos &&
      enclosing_block_of_insertion_pos != current_root &&
      !IsTableCell(enclosing_block_of_insertion_pos) &&
      !start_is_inside_mail_blockquote) {
    VisiblePosition visible_insertion_pos =
        CreateVisiblePosition(insertion_pos);
    if (IsEndOfBlock(visible_insertion_pos) &&
        !(IsStartOfBlock(visible_insertion_pos) &&
          fragment.HasInterchangeNewlineAtEnd()))
      insertion_pos =
          Position::InParentAfterNode(*enclosing_block_of_insertion_pos);
    else if (IsStartOfBlock(visible_insertion_pos))
      insertion_pos =
          Position::InParentBeforeNode(*enclosing_block_of_insertion_pos);
  }

  // Paste at start or end of link goes outside of link.
  insertion_pos =
      PositionAvoidingSpecialElementBoundary(insertion_pos, editing_state);
  if (editing_state->IsAborted())
    return;

  // FIXME: Can this wait until after the operation has been performed?  There
  // doesn't seem to be any work performed after this that queries or uses the
  // typing style.
  if (LocalFrame* frame = GetDocument().GetFrame())
    frame->GetEditor().ClearTypingStyle();

  RemoveHeadContents(fragment);

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  // We don't want the destination to end up inside nodes that weren't selected.
  // To avoid that, we move the position forward without changing the visible
  // position so we're still at the same visible location, but outside of
  // preceding tags.
  insertion_pos = PositionAvoidingPrecedingNodes(insertion_pos);

  // Paste into run of tabs splits the tab span.
  insertion_pos = PositionOutsideTabSpan(insertion_pos);

  HandleStyleSpansBeforeInsertion(fragment, insertion_pos);

  // We're finished if there is nothing to add.
  if (fragment.IsEmpty() || !fragment.FirstChild())
    return;

  // If we are not trying to match the destination style we prefer a position
  // that is outside inline elements that provide style.
  // This way we can produce a less verbose markup.
  // We can skip this optimization for fragments not wrapped in one of
  // our style spans and for positions inside list items
  // since insertAsListItems already does the right thing.
  if (!match_style_ && !EnclosingList(insertion_pos.ComputeContainerNode())) {
    auto* text_node = DynamicTo<Text>(insertion_pos.ComputeContainerNode());
    if (text_node && insertion_pos.OffsetInContainerNode() &&
        !insertion_pos.AtLastEditingPositionForNode()) {
      SplitTextNode(text_node, insertion_pos.OffsetInContainerNode());
      insertion_pos =
          Position::FirstPositionInNode(*insertion_pos.ComputeContainerNode());
    }

    if (HTMLElement* element_to_split_to =
            ElementToSplitToAvoidPastingIntoInlineElementsWithStyle(
                insertion_pos)) {
      if (insertion_pos.ComputeContainerNode() !=
          element_to_split_to->parentNode()) {
        Node* split_start = insertion_pos.ComputeNodeAfterPosition();
        if (!split_start)
          split_start = insertion_pos.ComputeContainerNode();
        Node* node_to_split_to =
            SplitTreeToNode(split_start, element_to_split_to->parentNode());
        insertion_pos = Position::InParentBeforeNode(*node_to_split_to);
      }
    }
  }

  // FIXME: When pasting rich content we're often prevented from heading down
  // the fast path by style spans.  Try again here if they've been removed.

  // 1) Insert the content.
  // 2) Remove redundant styles and style tags, this inner <b> for example:
  // <b>foo <b>bar</b> baz</b>.
  // 3) Merge the start of the added content with the content before the
  //    position being pasted into.
  // 4) Do one of the following:
  //    a) expand the last br if the fragment ends with one and it collapsed,
  //    b) merge the last paragraph of the incoming fragment with the paragraph
  //       that contained the end of the selection that was pasted into, or
  //    c) handle an interchange newline at the end of the incoming fragment.
  // 5) Add spaces for smart replace.
  // 6) Select the replacement if requested, and match style if requested.

  InsertedNodes inserted_nodes;
  inserted_nodes.SetRefNode(fragment.FirstChild());
  DCHECK(inserted_nodes.RefNode());
  Node* node = inserted_nodes.RefNode()->nextSibling();

  fragment.RemoveNode(inserted_nodes.RefNode());

  Element* block_start = EnclosingBlock(insertion_pos.AnchorNode());
  if ((IsHTMLListElement(inserted_nodes.RefNode()) ||
       (IsHTMLListElement(inserted_nodes.RefNode()->firstChild()))) &&
      block_start && block_start->GetLayoutObject()->IsListItem() &&
      IsEditable(*block_start->parentNode())) {
    inserted_nodes.SetRefNode(InsertAsListItems(
        To<HTMLElement>(inserted_nodes.RefNode()), block_start, insertion_pos,
        inserted_nodes, editing_state));
    if (editing_state->IsAborted())
      return;
  } else {
    InsertNodeAt(inserted_nodes.RefNode(), insertion_pos, editing_state);
    if (editing_state->IsAborted())
      return;
    inserted_nodes.RespondToNodeInsertion(*inserted_nodes.RefNode());
  }

  // Mutation events (bug 22634) may have already removed the inserted content
  if (!inserted_nodes.RefNode()->isConnected())
    return;

  bool plain_text_fragment = IsPlainTextMarkup(inserted_nodes.RefNode());

  while (node) {
    Node* next = node->nextSibling();
    fragment.RemoveNode(node);
    InsertNodeAfter(node, inserted_nodes.RefNode(), editing_state);
    if (editing_state->IsAborted())
      return;
    inserted_nodes.RespondToNodeInsertion(*node);

    // Mutation events (bug 22634) may have already removed the inserted content
    if (!node->isConnected())
      return;

    inserted_nodes.SetRefNode(node);
    if (node && plain_text_fragment)
      plain_text_fragment = IsPlainTextMarkup(node);
    node = next;
  }

  if (IsRichlyEditablePosition(insertion_pos)) {
    RemoveUnrenderedTextNodesAtEnds(inserted_nodes);
    ABORT_EDITING_COMMAND_IF(!inserted_nodes.RefNode());
  }

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  // Mutation events (bug 20161) may have already removed the inserted content
  if (!inserted_nodes.FirstNodeInserted() ||
      !inserted_nodes.FirstNodeInserted()->isConnected())
    return;

  // Scripts specified in javascript protocol may remove
  // |enclosingBlockOfInsertionPos| during insertion, e.g. <iframe
  // src="javascript:...">
  if (enclosing_block_of_insertion_pos &&
      !enclosing_block_of_insertion_pos->isConnected())
    enclosing_block_of_insertion_pos = nullptr;

  VisiblePosition start_of_inserted_content = CreateVisiblePosition(
      FirstPositionInOrBeforeNode(*inserted_nodes.FirstNodeInserted()));

  // We inserted before the enclosingBlockOfInsertionPos to prevent nesting, and
  // the content before the enclosingBlockOfInsertionPos wasn't in its own block
  // and didn't have a br after it, so the inserted content ended up in the same
  // paragraph.
  if (!start_of_inserted_content.IsNull() && enclosing_block_of_insertion_pos &&
      insertion_pos.AnchorNode() ==
          enclosing_block_of_insertion_pos->parentNode() &&
      (unsigned)insertion_pos.ComputeEditingOffset() <
          enclosing_block_of_insertion_pos->NodeIndex() &&
      !IsStartOfParagraph(start_of_inserted_content)) {
    InsertNodeAt(MakeGarbageCollected<HTMLBRElement>(GetDocument()),
                 start_of_inserted_content.DeepEquivalent(), editing_state);
    if (editing_state->IsAborted())
      return;
  }

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  if (end_br &&
      (plain_text_fragment ||
       (ShouldRemoveEndBR(end_br, original_vis_pos_before_end_br) &&
        !(fragment.HasInterchangeNewlineAtEnd() && selection_is_plain_text)))) {
    ContainerNode* parent = end_br->parentNode();
    inserted_nodes.WillRemoveNode(*end_br);
    ABORT_EDITING_COMMAND_IF(!inserted_nodes.RefNode());
    RemoveNode(end_br, editing_state);
    if (editing_state->IsAborted())
      return;
    if (Node* node_to_remove = HighestNodeToRemoveInPruning(parent)) {
      inserted_nodes.WillRemoveNode(*node_to_remove);
      ABORT_EDITING_COMMAND_IF(!inserted_nodes.RefNode());
      RemoveNode(node_to_remove, editing_state);
      if (editing_state->IsAborted())
        return;
    }
  }

  MakeInsertedContentRoundTrippableWithHTMLTreeBuilder(inserted_nodes,
                                                       editing_state);
  if (editing_state->IsAborted())
    return;

  {
    // TODO(dominicc): refNode may not be connected, for example in
    // web_tests/editing/inserting/insert-table-in-paragraph-crash.html .
    // Refactor this so there's a relationship between the conditions
    // where refNode is dereferenced and refNode is connected.
    bool ref_node_was_connected = inserted_nodes.RefNode()->isConnected();
    RemoveRedundantStylesAndKeepStyleSpanInline(inserted_nodes, editing_state);
    if (editing_state->IsAborted())
      return;
    DCHECK_EQ(inserted_nodes.RefNode()->isConnected(), ref_node_was_connected)
        << inserted_nodes.RefNode();
  }

  if (sanitize_fragment_ && inserted_nodes.FirstNodeInserted()) {
    ApplyCommandToComposite(
        MakeGarbageCollected<SimplifyMarkupCommand>(
            GetDocument(), inserted_nodes.FirstNodeInserted(),
            inserted_nodes.PastLastLeaf()),
        editing_state);
    if (editing_state->IsAborted())
      return;
  }

  // Setup |start_of_inserted_content_| and |end_of_inserted_content_|.
  // This should be the last two lines of code that access insertedNodes.
  // TODO(editing-dev): The {First,Last}NodeInserted() nullptr checks may be
  // unnecessary. Investigate.
  start_of_inserted_content_ =
      inserted_nodes.FirstNodeInserted()
          ? FirstPositionInOrBeforeNode(*inserted_nodes.FirstNodeInserted())
          : Position();
  end_of_inserted_content_ =
      inserted_nodes.LastLeafInserted()
          ? LastPositionInOrAfterNode(*inserted_nodes.LastLeafInserted())
          : Position();

  // Determine whether or not we should merge the end of inserted content with
  // what's after it before we do the start merge so that the start merge
  // doesn't effect our decision.
  should_merge_end_ = ShouldMergeEnd(selection_end_was_end_of_paragraph);

  if (ShouldMergeStart(selection_start_was_start_of_paragraph,
                       fragment.HasInterchangeNewlineAtStart(),
                       start_is_inside_mail_blockquote)) {
    VisiblePosition start_of_paragraph_to_move =
        PositionAtStartOfInsertedContent();
    VisiblePosition destination =
        PreviousPositionOf(start_of_paragraph_to_move);

    // Helpers for making the VisiblePositions valid again after DOM changes.
    PositionWithAffinity start_of_paragraph_to_move_position =
        start_of_paragraph_to_move.ToPositionWithAffinity();
    PositionWithAffinity destination_position =
        destination.ToPositionWithAffinity();

    // We need to handle the case where we need to merge the end
    // but our destination node is inside an inline that is the last in the
    // block.
    // We insert a placeholder before the newly inserted content to avoid being
    // merged into the inline.
    Node* destination_node = destination.DeepEquivalent().AnchorNode();
    if (should_merge_end_ &&
        destination_node != EnclosingInline(destination_node) &&
        EnclosingInline(destination_node)->nextSibling()) {
      InsertNodeBefore(MakeGarbageCollected<HTMLBRElement>(GetDocument()),
                       inserted_nodes.RefNode(), editing_state);
      if (editing_state->IsAborted())
        return;
    }

    // Merging the the
```