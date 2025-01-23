Response:
The user wants to understand the functionality of the `ReplaceSelectionCommand` class in the Chromium Blink rendering engine, specifically looking at the code provided in the third part of the file.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core function:** The name "ReplaceSelectionCommand" strongly suggests its primary function is to replace the currently selected content in a document.

2. **Scan for key methods and variables:** Look for methods that perform actions and variables that hold important data related to the replacement process. The provided code snippet includes methods like `InsertAsListItems`, `UpdateNodesInserted`, `PerformTrivialReplace`, `CompleteHTMLReplacement`, `MergeTextNodesAroundPosition`, `AddSpacesForSmartReplace`, `ShouldPerformSmartReplace`, `ShouldRemoveEndBR`, and the main `Apply` method. Key variables include `start_of_inserted_content_`, `end_of_inserted_content_`, `insertion_style_`, `document_fragment_`, `start_of_inserted_range_`, and `end_of_inserted_range_`.

3. **Analyze the `Apply` method (the heart of the command):** This method orchestrates the replacement process. Note the conditional execution based on whether a trivial replace can be performed. Observe the steps involved in a non-trivial replace:
    * Creating an editing state for tracking changes.
    * Handling placeholder elements.
    * Inserting the provided fragment.
    * Handling special cases like inserting into lists.
    * Adjusting for paragraph breaks and formatting.
    * Applying styles.
    * Performing "smart replace" for adding spaces around inserted text.
    * Finalizing the replacement and setting the selection.

4. **Examine supporting methods:** Understand the purpose of the auxiliary methods:
    * `InsertAsListItems`: Handles inserting content into existing lists.
    * `UpdateNodesInserted`: Tracks the newly inserted nodes.
    * `PerformTrivialReplace`:  A fast-path optimization for simple text replacements.
    * `CompleteHTMLReplacement`:  Handles post-insertion tasks like whitespace rebalancing, style application, and merging text nodes.
    * `MergeTextNodesAroundPosition`: Optimizes by merging adjacent text nodes.
    * `AddSpacesForSmartReplace`:  Implements the "smart replace" feature.
    * `ShouldPerformSmartReplace`: Determines if smart replace should be applied.
    * `ShouldRemoveEndBR`:  Decides whether to remove a trailing `<br>` element.

5. **Identify relationships with web technologies:** Consider how the actions of this command relate to JavaScript, HTML, and CSS:
    * **HTML:** The command manipulates the DOM structure by inserting and removing elements and text nodes. It deals with specific HTML elements like `<br>`, `<li>`, `<ul>`, `<ol>`, and placeholder elements.
    * **CSS:** The command applies styles to the inserted content, inheriting or potentially overriding existing styles. The `insertion_style_` variable is relevant here.
    * **JavaScript:** While this C++ code doesn't directly execute JavaScript, it's triggered by user actions in the browser which are often initiated or handled by JavaScript. The results of this command (DOM changes) will be reflected in the browser's rendering and are accessible to JavaScript.

6. **Construct examples:** Create concrete examples to illustrate the functionality and the impact on HTML, CSS, and potential JavaScript interactions. Consider scenarios like pasting text, pasting lists, and the effect of smart replace.

7. **Consider potential errors and debugging:** Think about how a user might trigger this code and what could go wrong. This helps in providing debugging clues. The user's copy/paste or drag-and-drop actions are the primary triggers. Common issues might involve unexpected formatting, incorrect list nesting, or issues with the selection after the replacement.

8. **Summarize the overall function:** Concisely describe the main purpose of the `ReplaceSelectionCommand` based on the analysis.

9. **Organize the answer:** Structure the information logically with clear headings and examples. Address each aspect of the user's request: functionality, relationships with web technologies, logical reasoning (input/output), common errors, debugging, and summary.

10. **Refine and review:**  Read through the generated answer to ensure clarity, accuracy, and completeness. Ensure that the examples are relevant and the explanations are easy to understand. Specifically, pay attention to the "assumptions and outputs" and "common errors" sections to make sure they are well-reasoned and practical.
好的，这是对 `blink/renderer/core/editing/commands/replace_selection_command.cc` 文件第三部分的分析归纳：

**功能归纳**

`ReplaceSelectionCommand` 的主要功能是**替换当前选中的内容**。  第三部分的代码主要集中在以下几个方面，用于完成更复杂的替换操作，并处理各种边界情况和优化：

* **处理粘贴为列表项的情况 (`InsertAsListItems`)**:  当用户尝试将一个列表粘贴到另一个列表内部时，此方法会智能地将粘贴的内容作为新的列表项插入到现有列表中，而不是将列表嵌套进去。
* **更新已插入节点的范围 (`UpdateNodesInserted`)**:  在插入节点后，此方法会更新内部变量 `start_of_inserted_content_` 和 `end_of_inserted_content_`，以准确记录新插入内容的起始和结束位置。
* **执行简单的文本替换 (`PerformTrivialReplace`)**:  对于仅包含单个文本节点的简单替换场景，此方法提供了一个优化的快速路径，避免了复杂的 DOM 操作，提高了性能。它会直接将文本插入到选区所在的文本节点中。
* **判断是否需要移除尾部的 `<br>` 元素 (`ShouldRemoveEndBR`)**: 在某些情况下，替换操作后可能会留下多余的 `<br>` 元素，此方法用于判断是否需要移除这些冗余的换行符。
* **判断是否执行智能替换 (`ShouldPerformSmartReplace`)**:  根据上下文和用户设置，决定是否在替换前后添加空格，以改善文本的自然衔接。
* **添加智能替换所需的空格 (`AddSpacesForSmartReplace`)**:  如果启用了智能替换，此方法会在插入内容的开头或结尾添加空格（或 `&nbsp;`，取决于上下文），以避免单词粘连。
* **完成 HTML 替换 (`CompleteHTMLReplacement`)**:  在插入 HTML 片段后，此方法负责进行最后的调整，例如：
    * 平衡插入内容周围的空白字符。
    * 应用插入时携带的样式。
    * 合并相邻的文本节点。
    * 根据 `select_replacement_` 标志决定是否选中替换后的内容。
* **合并位置周围的文本节点 (`MergeTextNodesAroundPosition`)**:  在插入或删除节点后，此方法会尝试合并插入点或删除点周围的相邻文本节点，以优化 DOM 结构。
* **获取输入事件类型 (`GetInputType`)**:  返回与此替换操作相关的输入事件类型，例如粘贴、拖拽等。
* **判断是否是 ReplaceSelectionCommand (`IsReplaceSelectionCommand`)**:  一个简单的类型检查方法。
* **获取插入内容的范围 (`InsertedRange`)**: 返回一个表示已插入内容范围的 `EphemeralRange` 对象。

**与 JavaScript, HTML, CSS 的关系及举例说明**

1. **HTML:**
   * **插入和操作 HTML 元素：** `ReplaceSelectionCommand` 负责将 HTML 片段插入到 DOM 树中，创建、移动、删除各种 HTML 元素，例如 `<p>`, `<div>`, `<span>`, `<li>`, `<br>` 等。
     * **例子：** 当用户粘贴一段包含 `<ul><li>Item 1</li><li>Item 2</li></ul>` 的 HTML 代码时，`ReplaceSelectionCommand` 会创建这些元素并将它们插入到文档中。
   * **处理特定 HTML 元素：** 代码中针对 `<br>` 元素的特殊处理（`ShouldRemoveEndBR`）是为了解决特定场景下的排版问题。
     * **例子：** 在某些浏览器中，在某些块级元素末尾插入内容后可能会产生多余的 `<br>`，这个函数会尝试清理它。

2. **CSS:**
   * **应用样式 (`CompleteHTMLReplacement` 中的 `ApplyStyle`)：**  粘贴的内容可能携带样式信息，或者需要继承插入位置的样式。 `ReplaceSelectionCommand` 会处理这些样式应用。
     * **例子：**  用户复制了一段加粗的文本，粘贴后，新插入的文本也会被加粗。这涉及到 CSS 样式的应用和继承。
   * **考虑样式对 DOM 操作的影响：**  代码中多次调用 `GetDocument().UpdateStyleAndLayout()` 表明 DOM 的修改会影响布局和样式计算。
     * **例子：**  插入一个包含 `float: left` 样式的 `div` 可能会导致周围元素的布局发生变化，需要重新计算。

3. **JavaScript:**
   * **作为浏览器编辑功能的一部分：** 用户在浏览器中进行复制、粘贴、拖拽等操作，这些操作通常会触发浏览器的编辑功能，而 `ReplaceSelectionCommand` 就是这个功能的核心组件之一。JavaScript 代码可以通过 `document.execCommand()` 等 API 间接触发 `ReplaceSelectionCommand` 的执行。
     * **例子：** JavaScript 代码调用 `document.execCommand('paste')` 时，浏览器会获取剪贴板内容，并使用 `ReplaceSelectionCommand` 将其插入到当前选区。
   * **事件监听和处理：** JavaScript 可以监听 `input`、`beforeinput` 等事件，这些事件会在编辑操作前后触发。`ReplaceSelectionCommand` 的执行结果会反映在这些事件中。
     * **例子：** 当 `ReplaceSelectionCommand` 插入文本后，会触发一个 `input` 事件，JavaScript 可以监听这个事件并获取插入的文本内容。

**逻辑推理、假设输入与输出**

**场景：** 用户在一个空的 `<p>` 标签中粘贴了一段纯文本 "Hello World"。

**假设输入：**
* 当前选区：位于空 `<p></p>` 标签内部。
* 粘贴内容：纯文本 "Hello World"。
* `plain_text_fragment` 为 true (表示是纯文本粘贴)。

**逻辑推理（简化）：**

1. 由于是纯文本粘贴且简单，可能会尝试 `PerformTrivialReplace`。
2. `PerformTrivialReplace` 会创建一个文本节点包含 "Hello World"。
3. 将该文本节点插入到 `<p>` 标签内部。
4. 更新选区，使其覆盖新插入的文本。

**预期输出（DOM 结构变化）：**

```html
<p>Hello World</p>
```

**预期输出（选区变化）：**

选区会选中 "Hello World" 这段文本。

**涉及用户或编程常见的使用错误**

1. **粘贴格式混乱的内容：** 用户可能从其他应用程序复制了富文本内容，其中包含复杂的 HTML 结构和样式。`ReplaceSelectionCommand` 需要处理这些复杂情况，但如果 HTML 结构不规范或样式冲突，可能会导致粘贴结果与预期不符。
   * **例子：** 从 Word 文档复制带有复杂表格和自定义样式的文本，粘贴到网页编辑器中，可能导致样式丢失、表格错乱等问题。
2. **在不期望的位置触发粘贴：**  JavaScript 代码可能会错误地触发粘贴操作，导致内容被插入到错误的位置。
   * **例子：**  一个错误的事件监听器可能在用户点击按钮时意外执行粘贴操作。
3. **与浏览器的默认行为冲突：**  自定义的 JavaScript 代码可能会尝试干预浏览器的默认粘贴行为，与 `ReplaceSelectionCommand` 的逻辑产生冲突，导致不可预测的结果。
   * **例子：**  使用 JavaScript 阻止默认粘贴事件并尝试自定义粘贴逻辑，但自定义逻辑存在缺陷。
4. **错误地假设 `PerformTrivialReplace` 会被调用：**  开发者可能会错误地认为所有文本粘贴都会走快速路径 `PerformTrivialReplace`，但实际上只有非常简单的场景才会满足其条件。对于稍复杂的文本或包含 HTML 标记的粘贴，会走更复杂的处理流程。

**用户操作如何一步步到达这里（调试线索）**

1. **用户在可编辑区域中进行选择：** 用户首先需要在一个允许编辑的 HTML 元素（例如，设置了 `contenteditable="true"` 的 `div` 或 `<p>`，或者 `<textarea>` 等）中选中一部分内容。
2. **用户执行替换操作：** 用户可以通过以下几种方式触发替换操作：
   * **粘贴 (Ctrl+V 或右键粘贴)：** 用户复制了一些内容，然后在选区上执行粘贴操作。这是最常见的触发 `ReplaceSelectionCommand` 的方式。
   * **拖拽：** 用户将文本或 HTML 内容从一个位置拖拽到当前选区。
   * **使用 `document.execCommand('insertHTML', ...)` 或 `document.execCommand('paste', ...)` 等 JavaScript API：**  JavaScript 代码可以编程方式地触发替换操作。
   * **某些浏览器的自动替换功能：**  例如，拼写检查或自动更正功能可能会触发文本替换。
3. **浏览器引擎处理替换请求：** 浏览器引擎接收到替换请求后，会创建并执行 `ReplaceSelectionCommand` 对象。
4. **执行 `Apply()` 方法：**  `ReplaceSelectionCommand` 的 `Apply()` 方法被调用，开始执行替换的逻辑。根据粘贴内容的复杂程度和上下文，代码会执行不同的分支，例如 `PerformTrivialReplace` 或更复杂的 HTML 处理流程。

在调试时，如果怀疑 `ReplaceSelectionCommand` 存在问题，可以尝试以下步骤：

* **断点调试：** 在 Chromium 源代码中设置断点，例如在 `ReplaceSelectionCommand::Apply()`、`PerformTrivialReplace()`、`CompleteHTMLReplacement()` 等关键方法处，逐步跟踪代码执行流程，查看变量的值和 DOM 结构的变化。
* **查看剪贴板内容：**  确定粘贴的内容是什么格式（纯文本、HTML 等）。
* **检查选区状态：**  确认执行粘贴操作时的选区是否正确。
* **禁用 JavaScript：**  如果怀疑是 JavaScript 代码干扰了粘贴操作，可以尝试禁用 JavaScript 并重新测试。
* **比较不同浏览器的行为：**  在不同的浏览器中测试相同的粘贴操作，看是否存在差异，这有助于判断是特定浏览器的问题还是通用问题。

总而言之，`ReplaceSelectionCommand` 是 Blink 引擎中处理内容替换的核心类，它需要考虑各种复杂的场景和边界情况，以确保用户在进行编辑操作时获得一致且符合预期的结果。

### 提示词
```
这是目录为blink/renderer/core/editing/commands/replace_selection_command.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
first paragraph of inserted content with the content that
    // came before the selection that was pasted into would also move content
    // after the selection that was pasted into if: only one paragraph was being
    // pasted, and it was not wrapped in a block, the selection that was pasted
    // into ended at the end of a block and the next paragraph didn't start at
    // the start of a block.
    // Insert a line break just after the inserted content to separate it from
    // what comes after and prevent that from happening.
    VisiblePosition end_of_inserted_content = PositionAtEndOfInsertedContent();
    if (StartOfParagraph(end_of_inserted_content).DeepEquivalent() ==
        start_of_paragraph_to_move_position.GetPosition()) {
      InsertNodeAt(MakeGarbageCollected<HTMLBRElement>(GetDocument()),
                   end_of_inserted_content.DeepEquivalent(), editing_state);
      if (editing_state->IsAborted())
        return;
      // Mutation events (bug 22634) triggered by inserting the <br> might have
      // removed the content we're about to move
      if (!start_of_paragraph_to_move_position.IsConnected())
        return;
    }

    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

    // Making the two VisiblePositions valid again.
    start_of_paragraph_to_move =
        CreateVisiblePosition(start_of_paragraph_to_move_position);
    destination = CreateVisiblePosition(destination_position);

    // FIXME: Maintain positions for the start and end of inserted content
    // instead of keeping nodes.  The nodes are only ever used to create
    // positions where inserted content starts/ends.
    MoveParagraph(start_of_paragraph_to_move,
                  EndOfParagraph(start_of_paragraph_to_move), destination,
                  editing_state);
    if (editing_state->IsAborted())
      return;

    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
    const VisibleSelection& visible_selection_of_insterted_content =
        EndingVisibleSelection();
    start_of_inserted_content_ = MostForwardCaretPosition(
        visible_selection_of_insterted_content.VisibleStart().DeepEquivalent());
    if (end_of_inserted_content_.IsOrphan()) {
      end_of_inserted_content_ = MostBackwardCaretPosition(
          visible_selection_of_insterted_content.VisibleEnd().DeepEquivalent());
    }
  }

  Position last_position_to_select;
  if (fragment.HasInterchangeNewlineAtEnd()) {
    VisiblePosition end_of_inserted_content = PositionAtEndOfInsertedContent();
    VisiblePosition next =
        NextPositionOf(end_of_inserted_content, kCannotCrossEditingBoundary);

    if (selection_end_was_end_of_paragraph ||
        !IsEndOfParagraph(end_of_inserted_content) || next.IsNull()) {
      if (TextControlElement* text_control =
              EnclosingTextControl(current_root)) {
        if (!inserted_nodes.LastLeafInserted()->nextSibling()) {
          InsertNodeAfter(text_control->CreatePlaceholderBreakElement(),
                          inserted_nodes.LastLeafInserted(), editing_state);
          if (editing_state->IsAborted())
            return;
        }
        SetEndingSelection(SelectionForUndoStep::From(
            SelectionInDOMTree::Builder()
                .Collapse(
                    Position::AfterNode(*inserted_nodes.LastLeafInserted()))
                .Build()));
        // Select up to the paragraph separator that was added.
        last_position_to_select =
            EndingVisibleSelection().VisibleStart().DeepEquivalent();
      } else if (!IsStartOfParagraph(end_of_inserted_content)) {
        SetEndingSelection(SelectionForUndoStep::From(
            SelectionInDOMTree::Builder()
                .Collapse(end_of_inserted_content.DeepEquivalent())
                .Build()));
        Element* enclosing_block_element = EnclosingBlock(
            end_of_inserted_content.DeepEquivalent().AnchorNode());
        if (IsListItem(enclosing_block_element)) {
          auto* new_list_item =
              MakeGarbageCollected<HTMLLIElement>(GetDocument());
          InsertNodeAfter(new_list_item, enclosing_block_element,
                          editing_state);
          if (editing_state->IsAborted())
            return;
          SetEndingSelection(SelectionForUndoStep::From(
              SelectionInDOMTree::Builder()
                  .Collapse(Position::FirstPositionInNode(*new_list_item))
                  .Build()));
        } else {
          // Use a default paragraph element (a plain div) for the empty
          // paragraph, using the last paragraph block's style seems to annoy
          // users.
          InsertParagraphSeparator(
              editing_state, true,
              !start_is_inside_mail_blockquote &&
                  HighestEnclosingNodeOfType(
                      end_of_inserted_content.DeepEquivalent(),
                      IsMailHTMLBlockquoteElement, kCannotCrossEditingBoundary,
                      inserted_nodes.FirstNodeInserted()->parentNode()));
          if (editing_state->IsAborted())
            return;
        }

        GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

        // Select up to the paragraph separator that was added.
        last_position_to_select =
            EndingVisibleSelection().VisibleStart().DeepEquivalent();
        UpdateNodesInserted(last_position_to_select.AnchorNode());
      }
    } else {
      // Select up to the beginning of the next paragraph.
      last_position_to_select = MostForwardCaretPosition(next.DeepEquivalent());
    }
  } else {
    MergeEndIfNeeded(editing_state);
    if (editing_state->IsAborted())
      return;
  }

  if (ShouldPerformSmartReplace()) {
    AddSpacesForSmartReplace(editing_state);
    if (editing_state->IsAborted())
      return;
  }
  // If we are dealing with a fragment created from plain text
  // no style matching is necessary.
  if (plain_text_fragment)
    match_style_ = false;

  CompleteHTMLReplacement(last_position_to_select, editing_state);

  // Remove the placeholder after the replacement is complete
  if (placeholder.IsNotNull()) {
    RemovePlaceholderAt(placeholder);
  }
}

bool ReplaceSelectionCommand::ShouldRemoveEndBR(
    HTMLBRElement* end_br,
    const VisiblePosition& original_vis_pos_before_end_br) {
  if (!end_br || !end_br->isConnected())
    return false;

  VisiblePosition visible_pos = VisiblePosition::BeforeNode(*end_br);

  // Don't remove the br if nothing was inserted.
  if (PreviousPositionOf(visible_pos).DeepEquivalent() ==
      original_vis_pos_before_end_br.DeepEquivalent())
    return false;

  // Remove the br if it is collapsed away and so is unnecessary.
  if (!GetDocument().InNoQuirksMode() && IsEndOfBlock(visible_pos) &&
      !IsStartOfParagraph(visible_pos))
    return true;

  // A br that was originally holding a line open should be displaced by
  // inserted content or turned into a line break.
  // A br that was originally acting as a line break should still be acting as a
  // line break, not as a placeholder.
  return IsStartOfParagraph(visible_pos) && IsEndOfParagraph(visible_pos);
}

bool ReplaceSelectionCommand::ShouldPerformSmartReplace() const {
  if (!smart_replace_)
    return false;

  TextControlElement* text_control =
      EnclosingTextControl(PositionAtStartOfInsertedContent().DeepEquivalent());
  auto* html_input_element = DynamicTo<HTMLInputElement>(text_control);
  if (html_input_element && html_input_element->FormControlType() ==
                                FormControlType::kInputPassword) {
    return false;  // Disable smart replace for password fields.
  }

  return true;
}

static bool IsCharacterSmartReplaceExemptConsideringNonBreakingSpace(
    UChar32 character,
    bool previous_character) {
  return IsCharacterSmartReplaceExempt(
      character == kNoBreakSpaceCharacter ? ' ' : character,
      previous_character);
}

void ReplaceSelectionCommand::AddSpacesForSmartReplace(
    EditingState* editing_state) {
  VisiblePosition end_of_inserted_content = PositionAtEndOfInsertedContent();
  Position end_upstream =
      MostBackwardCaretPosition(end_of_inserted_content.DeepEquivalent());
  Node* end_node = end_upstream.ComputeNodeBeforePosition();
  auto* end_text_node = DynamicTo<Text>(end_node);
  int end_offset = end_text_node ? end_text_node->length() : 0;
  if (end_upstream.IsOffsetInAnchor()) {
    end_node = end_upstream.ComputeContainerNode();
    end_offset = end_upstream.OffsetInContainerNode();
  }

  bool needs_trailing_space =
      !IsEndOfParagraph(end_of_inserted_content) &&
      !IsCharacterSmartReplaceExemptConsideringNonBreakingSpace(
          CharacterAfter(end_of_inserted_content), false);
  if (needs_trailing_space && end_node) {
    bool collapse_white_space =
        !end_node->GetLayoutObject() ||
        end_node->GetLayoutObject()->Style()->ShouldCollapseWhiteSpaces();
    end_text_node = DynamicTo<Text>(end_node);
    if (end_text_node) {
      InsertTextIntoNode(end_text_node, end_offset,
                         collapse_white_space ? NonBreakingSpaceString() : " ");
      if (end_of_inserted_content_.ComputeContainerNode() == end_node)
        end_of_inserted_content_ = Position(
            end_node, end_of_inserted_content_.OffsetInContainerNode() + 1);
    } else {
      Text* node = GetDocument().CreateEditingTextNode(
          collapse_white_space ? NonBreakingSpaceString() : " ");
      InsertNodeAfter(node, end_node, editing_state);
      if (editing_state->IsAborted())
        return;
      // Make sure that |UpdateNodesInserted| does not change
      // |start_of_inserted_content|.
      DCHECK(start_of_inserted_content_.IsNotNull());
      UpdateNodesInserted(node);
    }
  }

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  VisiblePosition start_of_inserted_content =
      PositionAtStartOfInsertedContent();
  Position start_downstream =
      MostForwardCaretPosition(start_of_inserted_content.DeepEquivalent());
  Node* start_node = start_downstream.ComputeNodeAfterPosition();
  unsigned start_offset = 0;
  if (start_downstream.IsOffsetInAnchor()) {
    start_node = start_downstream.ComputeContainerNode();
    start_offset = start_downstream.OffsetInContainerNode();
  }

  bool needs_leading_space =
      !IsStartOfParagraph(start_of_inserted_content) &&
      !IsCharacterSmartReplaceExemptConsideringNonBreakingSpace(
          CharacterBefore(start_of_inserted_content), true);
  if (needs_leading_space && start_node) {
    bool collapse_white_space =
        !start_node->GetLayoutObject() ||
        start_node->GetLayoutObject()->Style()->ShouldCollapseWhiteSpaces();
    if (auto* start_text_node = DynamicTo<Text>(start_node)) {
      InsertTextIntoNode(start_text_node, start_offset,
                         collapse_white_space ? NonBreakingSpaceString() : " ");
      if (end_of_inserted_content_.ComputeContainerNode() == start_node &&
          end_of_inserted_content_.OffsetInContainerNode())
        end_of_inserted_content_ = Position(
            start_node, end_of_inserted_content_.OffsetInContainerNode() + 1);
    } else {
      Text* node = GetDocument().CreateEditingTextNode(
          collapse_white_space ? NonBreakingSpaceString() : " ");
      // Don't UpdateNodesInserted. Doing so would set end_of_inserted_content_
      // to be the node containing the leading space, but
      // end_of_inserted_content_ issupposed to mark the end of pasted content.
      InsertNodeBefore(node, start_node, editing_state);
      if (editing_state->IsAborted())
        return;
      start_of_inserted_content_ = Position::FirstPositionInNode(*node);
    }
  }
}

void ReplaceSelectionCommand::CompleteHTMLReplacement(
    const Position& last_position_to_select,
    EditingState* editing_state) {
  Position start = PositionAtStartOfInsertedContent().DeepEquivalent();
  Position end = PositionAtEndOfInsertedContent().DeepEquivalent();

  // Mutation events may have deleted start or end
  if (start.IsNotNull() && !start.IsOrphan() && end.IsNotNull() &&
      !end.IsOrphan()) {
    // FIXME (11475): Remove this and require that the creator of the fragment
    // to use nbsps.
    RebalanceWhitespaceAt(start);
    RebalanceWhitespaceAt(end);

    if (match_style_) {
      DCHECK(insertion_style_);
      // Since |ApplyStyle()| changes contents of anchor node of |start| and
      // |end|, we should relocate them.
      auto* const range =
          MakeGarbageCollected<Range>(GetDocument(), start, end);
      ApplyStyle(insertion_style_.Get(), start, end, editing_state);
      start = range->StartPosition();
      end = range->EndPosition();
      range->Dispose();
      if (editing_state->IsAborted())
        return;
    }

    if (last_position_to_select.IsNotNull())
      end = last_position_to_select;

    MergeTextNodesAroundPosition(start, end, editing_state);
    if (editing_state->IsAborted())
      return;
  } else if (last_position_to_select.IsNotNull()) {
    start = end = last_position_to_select;
  } else {
    return;
  }

  start_of_inserted_range_ = start;
  end_of_inserted_range_ = end;

  if (select_replacement_) {
    SetEndingSelection(SelectionForUndoStep::From(
        SelectionInDOMTree::Builder()
            .SetBaseAndExtentDeprecated(start, end)
            .Build()));
    return;
  }

  if (end.IsNotNull()) {
    SetEndingSelection(SelectionForUndoStep::From(
        SelectionInDOMTree::Builder()
            .Collapse(end)
            .Build()));
    return;
  }
  SetEndingSelection(SelectionForUndoStep());
}

void ReplaceSelectionCommand::MergeTextNodesAroundPosition(
    Position& position,
    Position& position_only_to_be_updated,
    EditingState* editing_state) {
  bool position_is_offset_in_anchor = position.IsOffsetInAnchor();
  bool position_only_to_be_updated_is_offset_in_anchor =
      position_only_to_be_updated.IsOffsetInAnchor();
  Text* text = nullptr;
  auto* container_text_node = DynamicTo<Text>(position.ComputeContainerNode());
  if (position_is_offset_in_anchor && container_text_node) {
    text = container_text_node;
  } else if (auto* before =
                 DynamicTo<Text>(position.ComputeNodeBeforePosition())) {
    text = before;
  } else if (auto* after =
                 DynamicTo<Text>(position.ComputeNodeAfterPosition())) {
    text = after;
  }

  if (!text)
    return;

  // Merging Text nodes causes an additional layout. We'd like to skip it if the
  // editable text is huge.
  // TODO(tkent): 1024 was chosen by my intuition.  We need data.
  const unsigned kMergeSizeLimit = 1024;
  bool has_incomplete_surrogate =
      text->data().length() >= 1 &&
      (U16_IS_TRAIL(text->data()[0]) ||
       U16_IS_LEAD(text->data()[text->data().length() - 1]));
  if (!has_incomplete_surrogate && text->data().length() > kMergeSizeLimit)
    return;
  if (auto* previous = DynamicTo<Text>(text->previousSibling())) {
    if (has_incomplete_surrogate ||
        previous->data().length() <= kMergeSizeLimit) {
      InsertTextIntoNode(text, 0, previous->data());

      if (position_is_offset_in_anchor) {
        position =
            Position(position.ComputeContainerNode(),
                     previous->length() + position.OffsetInContainerNode());
      } else {
        position = ComputePositionForNodeRemoval(position, *previous);
      }

      if (position_only_to_be_updated_is_offset_in_anchor) {
        if (position_only_to_be_updated.ComputeContainerNode() == text)
          position_only_to_be_updated = Position(
              text, previous->length() +
                        position_only_to_be_updated.OffsetInContainerNode());
        else if (position_only_to_be_updated.ComputeContainerNode() == previous)
          position_only_to_be_updated = Position(
              text, position_only_to_be_updated.OffsetInContainerNode());
      } else {
        position_only_to_be_updated = ComputePositionForNodeRemoval(
            position_only_to_be_updated, *previous);
      }

      RemoveNode(previous, editing_state);
      if (editing_state->IsAborted())
        return;
    }
  }
  if (auto* next = DynamicTo<Text>(text->nextSibling())) {
    if (!has_incomplete_surrogate && next->data().length() > kMergeSizeLimit)
      return;
    unsigned original_length = text->length();
    InsertTextIntoNode(text, original_length, next->data());

    if (!position_is_offset_in_anchor)
      position = ComputePositionForNodeRemoval(position, *next);

    if (position_only_to_be_updated_is_offset_in_anchor &&
        position_only_to_be_updated.ComputeContainerNode() == next) {
      position_only_to_be_updated = Position(
          text, original_length +
                    position_only_to_be_updated.OffsetInContainerNode());
    } else {
      position_only_to_be_updated =
          ComputePositionForNodeRemoval(position_only_to_be_updated, *next);
    }

    RemoveNode(next, editing_state);
    if (editing_state->IsAborted())
      return;
  }
}

InputEvent::InputType ReplaceSelectionCommand::GetInputType() const {
  // |ReplaceSelectionCommand| could be used with Paste, Drag&Drop,
  // InsertFragment and |TypingCommand|.
  // 1. Paste, Drag&Drop, InsertFragment should rely on correct |input_type_|.
  // 2. |TypingCommand| will supply the |GetInputType()|, so |input_type_| could
  //    default to |InputType::kNone|.
  return input_type_;
}

// If the user is inserting a list into an existing list, instead of nesting the
// list, we put the list items into the existing list.
Node* ReplaceSelectionCommand::InsertAsListItems(HTMLElement* list_element,
                                                 Element* insertion_block,
                                                 const Position& insert_pos,
                                                 InsertedNodes& inserted_nodes,
                                                 EditingState* editing_state) {
  while (list_element->HasOneChild() &&
         IsHTMLListElement(list_element->firstChild()))
    list_element = To<HTMLElement>(list_element->firstChild());

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  bool is_start = IsStartOfParagraph(CreateVisiblePosition(insert_pos));
  bool is_end = IsEndOfParagraph(CreateVisiblePosition(insert_pos));
  bool is_middle = !is_start && !is_end;
  Node* last_node = insertion_block;

  // If we're in the middle of a list item, we should split it into two separate
  // list items and insert these nodes between them.
  if (is_middle) {
    int text_node_offset = insert_pos.OffsetInContainerNode();
    auto* text_node = DynamicTo<Text>(insert_pos.AnchorNode());
    if (text_node && text_node_offset > 0)
      SplitTextNode(text_node, text_node_offset);
    SplitTreeToNode(insert_pos.AnchorNode(), last_node, true);
  }

  while (Node* list_item = list_element->firstChild()) {
    list_element->RemoveChild(list_item, ASSERT_NO_EXCEPTION);
    if (is_start || is_middle) {
      InsertNodeBefore(list_item, last_node, editing_state);
      if (editing_state->IsAborted())
        return nullptr;
      inserted_nodes.RespondToNodeInsertion(*list_item);
    } else if (is_end) {
      InsertNodeAfter(list_item, last_node, editing_state);
      if (editing_state->IsAborted())
        return nullptr;
      inserted_nodes.RespondToNodeInsertion(*list_item);
      last_node = list_item;
    } else {
      NOTREACHED();
    }
  }
  if (is_start || is_middle) {
    if (Node* node = last_node->previousSibling())
      return node;
  }
  return last_node;
}

void ReplaceSelectionCommand::UpdateNodesInserted(Node* node) {
  if (!node)
    return;

  if (start_of_inserted_content_.IsNull())
    start_of_inserted_content_ = FirstPositionInOrBeforeNode(*node);

  end_of_inserted_content_ =
      LastPositionInOrAfterNode(NodeTraversal::LastWithinOrSelf(*node));
}

// During simple pastes, where we're just pasting a text node into a run of
// text, we insert the text node directly into the text node that holds the
// selection.  This is much faster than the generalized code in
// ReplaceSelectionCommand, and works around
// <https://bugs.webkit.org/show_bug.cgi?id=6148> since we don't split text
// nodes.
bool ReplaceSelectionCommand::PerformTrivialReplace(
    const ReplacementFragment& fragment,
    EditingState* editing_state) {
  if (!fragment.FirstChild() || fragment.FirstChild() != fragment.LastChild() ||
      !fragment.FirstChild()->IsTextNode())
    return false;

  if (RuntimeEnabledFeatures::NonNullInputEventDataForTextAreaEnabled()) {
    // Save the text to set event data for input events.
    input_event_data_ = To<Text>(fragment.FirstChild())->data();
  }

  // FIXME: Would be nice to handle smart replace in the fast path.
  if (smart_replace_ || fragment.HasInterchangeNewlineAtStart() ||
      fragment.HasInterchangeNewlineAtEnd())
    return false;

  // e.g. when "bar" is inserted after "foo" in <div><u>foo</u></div>, "bar"
  // should not be underlined.
  if (ElementToSplitToAvoidPastingIntoInlineElementsWithStyle(
          EndingVisibleSelection().Start()))
    return false;

  // TODO(editing-dev): Use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  Node* node_after_insertion_pos =
      MostForwardCaretPosition(EndingSelection().End()).AnchorNode();
  auto* text_node = To<Text>(fragment.FirstChild());
  // Our fragment creation code handles tabs, spaces, and newlines, so we don't
  // have to worry about those here.

  Position start = EndingVisibleSelection().Start();
  Position end = ReplaceSelectedTextInNode(text_node->data());
  if (end.IsNull())
    return false;

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  if (node_after_insertion_pos && node_after_insertion_pos->parentNode() &&
      IsA<HTMLBRElement>(*node_after_insertion_pos) &&
      ShouldRemoveEndBR(
          To<HTMLBRElement>(node_after_insertion_pos),
          VisiblePosition::BeforeNode(*node_after_insertion_pos))) {
    RemoveNodeAndPruneAncestors(node_after_insertion_pos, editing_state);
    if (editing_state->IsAborted())
      return false;
  }


  start_of_inserted_range_ = start;
  end_of_inserted_range_ = end;

  SetEndingSelection(SelectionForUndoStep::From(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtentDeprecated(select_replacement_ ? start : end, end)
          .Build()));

  return true;
}

bool ReplaceSelectionCommand::IsReplaceSelectionCommand() const {
  return true;
}

EphemeralRange ReplaceSelectionCommand::InsertedRange() const {
  return EphemeralRange(start_of_inserted_range_, end_of_inserted_range_);
}

void ReplaceSelectionCommand::Trace(Visitor* visitor) const {
  visitor->Trace(start_of_inserted_content_);
  visitor->Trace(end_of_inserted_content_);
  visitor->Trace(insertion_style_);
  visitor->Trace(document_fragment_);
  visitor->Trace(start_of_inserted_range_);
  visitor->Trace(end_of_inserted_range_);
  CompositeEditCommand::Trace(visitor);
}

}  // namespace blink
```