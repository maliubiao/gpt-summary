Response:
Let's break down the thought process for analyzing the `ApplyBlockElementCommand.cc` file.

1. **Understand the Goal:** The primary goal is to explain what this C++ file does within the Chromium Blink rendering engine, particularly its relation to web technologies (JavaScript, HTML, CSS) and potential user interactions/errors. The prompt also asks for logical reasoning (input/output) and debugging clues.

2. **Identify Key Classes and Concepts:**  The filename itself (`apply_block_element_command.cc`) and the initial comments offer strong hints. The core idea is manipulating block-level elements. Scanning the `#include` directives reveals interaction with:
    * `Document`: Represents the HTML document.
    * `Node`, `Text`, `HTMLElement`, `HTMLBRElement`: DOM elements.
    * `ComputedStyle`:  Deals with CSS styles.
    * `EditingState`: Manages the editing context.
    * `VisiblePosition`, `VisibleSelection`:  Represent the user's selection on the screen.
    * `QualifiedName`:  Represents HTML tag names.
    * `AtomicString`:  Efficient storage for strings (often used for attributes).
    * `CompositeEditCommand`: Suggests this is part of a larger editing operation.

3. **Focus on the `ApplyBlockElementCommand` Class:** This is the central component. Notice its constructors:
    * One takes a `QualifiedName` (the tag name, like "blockquote") and an `AtomicString` (inline styles).
    * The other takes just the `QualifiedName`. This implies the command can create block elements with or without inline styles.

4. **Analyze the `DoApply` Method:** This is the main execution point of the command. Let's follow the logic step-by-step:
    * **Initial Checks:** It verifies the selection is within an editable area.
    * **Selection Handling:** It deals with edge cases where the selection ends at the start of a paragraph. The comment about "not obvious to the user" provides insight into UI considerations.
    * **Paragraph Iteration:** The code iterates through paragraphs within the selection. This is crucial because block elements are often applied to entire paragraphs.
    * **`FormatSelection`:** This is a key subroutine, handling the core logic of wrapping the selected content in the new block element.
    * **Updating Selection:** After the formatting, the selection might need to be adjusted.

5. **Deep Dive into `FormatSelection`:**  This function is the heart of the command.
    * **Unsplittable Elements:**  It handles cases where the caret is inside an element that cannot be split (like the root editable element or a table cell). It inserts the block element and a `<br>` tag for a new line.
    * **Paragraph-by-Paragraph Processing:**  The `while` loop suggests processing each paragraph individually.
    * **`RangeForParagraphSplittingTextNodesIfNeeded`:** This is a complex function that handles splitting text nodes at paragraph boundaries to ensure the block element is inserted correctly. The comments highlight edge cases with whitespace and newlines (`\n`).
    * **`FormatRange`:**  This function (not defined in this file but likely elsewhere) performs the actual insertion of the block element around a given range.
    * **Updating `blockquote_for_next_indent`:** This suggests handling nested block elements or applying the block element to consecutive paragraphs.

6. **Examine Helper Functions:**  Functions like `IsAtUnsplittableElement`, `IsNewLineAtPosition`, `ComputedStyleOfEnclosingTextNode`, and the various splitting functions play supporting roles in precisely manipulating the DOM. Understanding their purpose clarifies the overall logic.

7. **Connect to Web Technologies:**
    * **HTML:** The command directly creates and manipulates HTML elements. The `tag_name_` variable stores the HTML tag.
    * **CSS:** The `inline_style_` allows applying inline styles. The code also interacts with `ComputedStyle` to understand how whitespace and line breaks are handled.
    * **JavaScript:**  While this is C++ code, it's part of the rendering engine that responds to user actions triggered by JavaScript. For example, a JavaScript command to format text as a blockquote would eventually call this C++ code.

8. **Consider User Interactions and Errors:**  Think about how a user might trigger this code:
    * Selecting text and clicking a "Blockquote" button.
    * Using keyboard shortcuts for formatting.
    * Pasting content.

    Common errors could involve:
    * Trying to apply block formatting within a non-editable area.
    * Unexpected behavior with complex selections or nested elements.

9. **Infer Input/Output:** Based on the code's logic:
    * **Input:** A selection in an editable HTML document and a block element tag name (and optionally inline styles).
    * **Output:** The selected content wrapped in the specified block element.

10. **Formulate Debugging Clues:** Think about what conditions would lead to this code being executed and what data points would be helpful:
    * The current selection.
    * The target block element tag.
    * The DOM structure around the selection.

11. **Structure the Explanation:** Organize the findings logically, starting with the main function and then delving into the details. Use clear headings and examples to illustrate the concepts.

12. **Review and Refine:**  Read through the explanation to ensure clarity, accuracy, and completeness. Double-check the connection to web technologies and the examples provided. Ensure all parts of the prompt are addressed. For instance, ensure you've mentioned user actions that lead to this code being executed.

This methodical approach, combining code analysis with an understanding of web technologies and user interactions, allows for a comprehensive explanation of the `ApplyBlockElementCommand.cc` file.
好的，让我们来分析一下 `blink/renderer/core/editing/commands/apply_block_element_command.cc` 这个文件的功能。

**文件功能概述:**

`ApplyBlockElementCommand.cc` 文件定义了一个名为 `ApplyBlockElementCommand` 的 C++ 类，该类是 Chromium Blink 引擎中负责将选定的内容包裹在一个新的块级元素中的编辑命令。 简单来说，它的主要功能是：

* **将选中的文本或元素转换为指定的块级元素。** 例如，将选中的段落转换为 `<blockquote>`、`<div>`、`<h1>` 等块级元素。
* **处理各种复杂的编辑场景，** 包括跨段落、跨元素的选择，以及在不可分割元素（如表格单元格）内的操作。
* **支持应用内联样式** 到新创建的块级元素。

**与 JavaScript, HTML, CSS 的关系:**

这个 C++ 文件是 Blink 渲染引擎的核心组成部分，它直接影响着用户在浏览器中进行富文本编辑时的行为。它与 JavaScript、HTML 和 CSS 的关系如下：

* **HTML:** 该命令的主要作用是修改 HTML 结构，通过创建新的块级 HTML 元素并将选中的内容移动到其中来实现。 `tag_name_` 成员变量存储了要创建的 HTML 标签名称（例如 "blockquote", "div"）。
    * **举例:** 用户选中一段文字后，点击工具栏上的 "引用" 按钮（通常对应 `<blockquote>` 标签），JavaScript 会调用相应的编辑命令，最终会执行到 `ApplyBlockElementCommand`，将选中的文字包裹在 `<blockquote>` 标签中。
* **CSS:**  该命令可以选择性地应用内联 CSS 样式到新创建的块级元素。 `inline_style_` 成员变量存储了要应用的内联样式字符串。
    * **举例:**  一个富文本编辑器可能允许用户在将文本转换为 `<div>` 时，同时设置该 `<div>` 的背景颜色或边框样式。这些样式信息会作为 `inline_style_` 传递给 `ApplyBlockElementCommand`，最终以 HTML 属性 `style="..."` 的形式添加到新创建的元素中。
* **JavaScript:** JavaScript 通常负责触发这个命令的执行。当用户在网页上进行编辑操作（例如，通过工具栏按钮、快捷键或上下文菜单）时，JavaScript 代码会捕获这些事件，并调用 Blink 提供的编辑接口来执行相应的命令。
    * **举例:**  一个 JavaScript 函数可能会监听某个按钮的点击事件。当按钮被点击时，该函数会创建一个 `ApplyBlockElementCommand` 对象，指定要创建的块级元素类型（例如 "p"）并将当前选中的内容作为操作目标。

**逻辑推理 (假设输入与输出):**

**假设输入 1:**

* 用户在可编辑的 `<div>` 中选中了一段文字 "This is a paragraph."。
* 用户触发了一个操作，指示将选中的内容转换为 `<p>` 元素。

**输出 1:**

* HTML 结构变为： `<div><p>This is a paragraph.</p></div>`

**假设输入 2:**

* 用户选中了两个相邻的段落： `<p>First paragraph.</p><p>Second paragraph.</p>`
* 用户触发了一个操作，指示将选中的内容转换为 `<blockquote>` 元素。

**输出 2:**

* HTML 结构变为： `<blockquote><p>First paragraph.</p><p>Second paragraph.</p></blockquote>`

**假设输入 3:**

* 用户选中了一段文字 "Styled text."。
* 用户触发了一个操作，指示将选中的内容转换为 `<div>` 元素，并设置内联样式 `color: red;`。

**输出 3:**

* HTML 结构变为： `<div><div style="color: red;">Styled text.</div></div>` (注意：如果选择的是已经存在的块级元素，可能会有不同的处理逻辑，这里假设选择的是文本节点)。

**涉及用户或者编程常见的使用错误:**

1. **在非可编辑区域执行命令:**  如果用户尝试在 `contenteditable="false"` 的元素或者浏览器的非编辑区域执行此命令，该命令通常会无效，或者不会产生预期的结果。 代码中 `if (!RootEditableElementOf(EndingSelection().Anchor())) { return; }`  就处理了这种情况。

2. **尝试将块级元素嵌套到行内元素中:**  HTML 结构有其规则。例如，不能将 `<div>` 直接嵌套在 `<span>` 中。 渲染引擎通常会进行修正，但这种操作可能会导致意想不到的结构变化。

3. **在复杂的嵌套结构中操作:**  当选择跨越多个嵌套元素时，`ApplyBlockElementCommand` 的行为可能会比较复杂，理解其内部逻辑对于调试至关重要。例如，选择部分列表项，然后尝试将其转换为 `<blockquote>`。

4. **与撤销/重做机制的交互问题:**  不当的命令实现可能导致撤销/重做功能出现异常。 Blink 的编辑命令框架通常会处理这些问题，但开发者仍需注意命令的正确实现。

**用户操作是如何一步步的到达这里，作为调试线索:**

以下是一个用户操作流程，可能导致 `ApplyBlockElementCommand::DoApply` 被调用：

1. **用户在浏览器中打开一个支持富文本编辑的网页。**  该网页的某些区域（例如 `<div contenteditable="true">` 或 `<iframe>` 内的文档）是可编辑的。
2. **用户使用鼠标或键盘选中了网页上的部分文本或一些元素。** 选区的起始和结束位置会被记录下来。
3. **用户执行一个与应用块级元素相关的操作。** 这可以通过以下方式触发：
    * **点击富文本编辑器的工具栏按钮：** 例如，点击 "段落" 下拉菜单选择 "<p>"，或点击 "引用" 按钮。
    * **使用键盘快捷键：** 某些编辑器可能为应用块级元素定义了快捷键。
    * **通过浏览器的上下文菜单：**  在某些情况下，右键点击选区可能会出现格式化选项。
    * **通过 JavaScript 代码调用：** 网页上的 JavaScript 代码可能通过 `document.execCommand()` 或其他 Blink 提供的 API 来触发编辑命令。
4. **JavaScript 代码接收到用户的操作事件。**  例如，按钮的 `onclick` 事件被触发。
5. **JavaScript 代码构建并执行相应的编辑命令。**  这通常涉及到创建一个 `ApplyBlockElementCommand` 对象，并设置其参数，例如要创建的块级元素的标签名。
6. **Blink 渲染引擎接收到执行命令的请求。**  `ApplyBlockElementCommand` 对象的 `DoApply()` 方法会被调用。
7. **`DoApply()` 方法内部会进行一系列操作：**
    * 获取当前的选区信息 (`EndingVisibleSelection()`).
    * 确定操作的范围和上下文。
    * 创建新的块级 HTML 元素 (`CreateBlockElement()`).
    * 将选中的内容移动到新创建的元素中，可能涉及复杂的 DOM 操作，例如分割节点、移动子节点等。
    * 可选地应用内联样式。
    * 更新文档的 DOM 树。
    * 更新选区状态。
8. **浏览器重新渲染页面，** 用户可以看到应用了块级元素后的效果。

**调试线索:**

* **断点:** 在 `ApplyBlockElementCommand::DoApply` 方法的入口处设置断点，可以观察命令是否被执行以及执行时的上下文信息。
* **查看选区信息:**  在断点处检查 `EndingVisibleSelection()` 的值，了解用户选择了哪些内容。
* **检查 `tag_name_` 和 `inline_style_`:**  确认要创建的块级元素的标签名和内联样式是否正确。
* **单步执行:**  逐步跟踪 `DoApply()` 方法的执行流程，观察 DOM 树的变化。
* **日志输出:**  在关键步骤添加日志输出，例如在创建元素前后、移动节点前后输出相关信息。
* **使用 Chromium 的开发者工具:**  可以使用 "Elements" 面板查看 DOM 树的结构变化，以及 "Sources" 面板进行代码调试。

希望以上分析能够帮助你理解 `ApplyBlockElementCommand.cc` 文件的功能和它在 Blink 引擎中的作用。

### 提示词
```
这是目录为blink/renderer/core/editing/commands/apply_block_element_command.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2006, 2008 Apple Inc. All rights reserved.
 * Copyright (C) 2010 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/editing/commands/apply_block_element_command.h"

#include "third_party/blink/renderer/core/dom/node_computed_style.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/commands/editing_commands_utilities.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/relocatable_position.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

ApplyBlockElementCommand::ApplyBlockElementCommand(
    Document& document,
    const QualifiedName& tag_name,
    const AtomicString& inline_style)
    : CompositeEditCommand(document),
      tag_name_(tag_name),
      inline_style_(inline_style) {}

ApplyBlockElementCommand::ApplyBlockElementCommand(
    Document& document,
    const QualifiedName& tag_name)
    : CompositeEditCommand(document), tag_name_(tag_name) {}

void ApplyBlockElementCommand::DoApply(EditingState* editing_state) {
  // ApplyBlockElementCommands are only created directly by editor commands'
  // execution, which updates layout before entering doApply().
  DCHECK(!GetDocument().NeedsLayoutTreeUpdate());

  if (!RootEditableElementOf(EndingSelection().Anchor())) {
    return;
  }

  VisiblePosition visible_end = EndingVisibleSelection().VisibleEnd();
  VisiblePosition visible_start = EndingVisibleSelection().VisibleStart();
  if (visible_start.IsNull() || visible_start.IsOrphan() ||
      visible_end.IsNull() || visible_end.IsOrphan())
    return;

  // When a selection ends at the start of a paragraph, we rarely paint
  // the selection gap before that paragraph, because there often is no gap.
  // In a case like this, it's not obvious to the user that the selection
  // ends "inside" that paragraph, so it would be confusing if Indent/Outdent
  // operated on that paragraph.
  // FIXME: We paint the gap before some paragraphs that are indented with left
  // margin/padding, but not others.  We should make the gap painting more
  // consistent and then use a left margin/padding rule here.
  if (visible_end.DeepEquivalent() != visible_start.DeepEquivalent() &&
      IsStartOfParagraph(visible_end)) {
    const Position& new_end =
        PreviousPositionOf(visible_end, kCannotCrossEditingBoundary)
            .DeepEquivalent();
    SelectionInDOMTree::Builder builder;
    builder.Collapse(visible_start.ToPositionWithAffinity());
    if (new_end.IsNotNull())
      builder.Extend(new_end);
    SetEndingSelection(SelectionForUndoStep::From(builder.Build()));
    ABORT_EDITING_COMMAND_IF(EndingVisibleSelection().VisibleStart().IsNull());
    ABORT_EDITING_COMMAND_IF(EndingVisibleSelection().VisibleEnd().IsNull());
  }

  VisibleSelection selection =
      SelectionForParagraphIteration(EndingVisibleSelection());
  VisiblePosition start_of_selection = selection.VisibleStart();
  ABORT_EDITING_COMMAND_IF(start_of_selection.IsNull());
  VisiblePosition end_of_selection = selection.VisibleEnd();
  ABORT_EDITING_COMMAND_IF(end_of_selection.IsNull());
  ContainerNode* start_scope = nullptr;
  int start_index = IndexForVisiblePosition(start_of_selection, start_scope);
  ContainerNode* end_scope = nullptr;
  int end_index = IndexForVisiblePosition(end_of_selection, end_scope);

  // Due to visible position canonicalization, start and end positions could
  // move to different selection contexts one of which could be inside an
  // element that is not editable. e.g. <pre contenteditable>
  //   hello^
  // <svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">
  // <foreignObject x="20" y="20" width="80" height="80">
  //  L|orem
  // </foreignObject>
  // </svg>
  // </pre>
  if (!IsEditablePosition(start_of_selection.DeepEquivalent()) ||
      !IsEditablePosition(end_of_selection.DeepEquivalent())) {
    return;
  }

  FormatSelection(start_of_selection, end_of_selection, editing_state);
  if (editing_state->IsAborted())
    return;

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  DCHECK_EQ(start_scope, end_scope);
  DCHECK_GE(start_index, 0);
  DCHECK_LE(start_index, end_index);
  if (start_scope == end_scope && start_index >= 0 &&
      start_index <= end_index) {
    VisiblePosition start(VisiblePositionForIndex(start_index, start_scope));
    VisiblePosition end(VisiblePositionForIndex(end_index, end_scope));
    if (start.IsNotNull() && end.IsNotNull()) {
      SetEndingSelection(SelectionForUndoStep::From(
          SelectionInDOMTree::Builder()
              .Collapse(start.ToPositionWithAffinity())
              .Extend(end.DeepEquivalent())
              .Build()));
    }
  }
}

static bool IsAtUnsplittableElement(const Position& pos) {
  Node* node = pos.AnchorNode();
  return node == RootEditableElementOf(pos) ||
         node == EnclosingNodeOfType(pos, &IsTableCell);
}

void ApplyBlockElementCommand::FormatSelection(
    const VisiblePosition& start_of_selection,
    const VisiblePosition& end_of_selection,
    EditingState* editing_state) {
  // Special case empty unsplittable elements because there's nothing to split
  // and there's nothing to move.
  const Position& caret_position =
      MostForwardCaretPosition(start_of_selection.DeepEquivalent());
  if (IsAtUnsplittableElement(caret_position)) {
    HTMLElement* blockquote = CreateBlockElement();
    InsertNodeAt(blockquote, caret_position, editing_state);
    if (editing_state->IsAborted())
      return;
    auto* placeholder = MakeGarbageCollected<HTMLBRElement>(GetDocument());
    AppendNode(placeholder, blockquote, editing_state);
    if (editing_state->IsAborted())
      return;
    SetEndingSelection(SelectionForUndoStep::From(
        SelectionInDOMTree::Builder()
            .Collapse(Position::BeforeNode(*placeholder))
            .Build()));
    return;
  }

  HTMLElement* blockquote_for_next_indent = nullptr;
  VisiblePosition end_of_current_paragraph = EndOfParagraph(start_of_selection);
  const VisiblePosition& visible_end_of_last_paragraph =
      EndOfParagraph(end_of_selection);
  RelocatablePosition* end_of_next_last_paragraph =
      MakeGarbageCollected<RelocatablePosition>(
          EndOfParagraph(NextPositionOf(visible_end_of_last_paragraph))
              .DeepEquivalent());
  Position end_of_last_paragraph =
      visible_end_of_last_paragraph.DeepEquivalent();

  bool at_end = false;
  while (end_of_current_paragraph.DeepEquivalent() !=
             end_of_next_last_paragraph->GetPosition() &&
         !at_end) {
    if (end_of_current_paragraph.DeepEquivalent() == end_of_last_paragraph)
      at_end = true;

    Position start, end;
    RangeForParagraphSplittingTextNodesIfNeeded(
        end_of_current_paragraph, end_of_last_paragraph, start, end);
    end_of_current_paragraph = CreateVisiblePosition(end);

    Node* enclosing_cell = EnclosingNodeOfType(start, &IsTableCell);
    RelocatablePosition* relocatable_end_of_next_paragraph =
        MakeGarbageCollected<RelocatablePosition>(
            EndOfNextParagrahSplittingTextNodesIfNeeded(
                end_of_current_paragraph, end_of_last_paragraph, start, end)
                .DeepEquivalent());
    RelocatablePosition* relocatable_end =
        MakeGarbageCollected<RelocatablePosition>(end);

    VisiblePosition end_of_next_of_paragraph_to_move;
    FormatRange(start, end, end_of_last_paragraph, blockquote_for_next_indent,
                end_of_next_of_paragraph_to_move, editing_state);
    if (editing_state->IsAborted())
      return;

    // If `end_of_next_of_paragraph_to_move` is updated,
    // `relocatable_end_of_next_paragraph` should be also updated along with
    // it.
    if (end_of_next_of_paragraph_to_move.IsNotNull() &&
        end_of_next_of_paragraph_to_move.IsValidFor(GetDocument())) {
      DCHECK(RuntimeEnabledFeatures::
                 AdjustEndOfNextParagraphIfMovedParagraphIsUpdatedEnabled());
      relocatable_end_of_next_paragraph->SetPosition(
          end_of_next_of_paragraph_to_move.DeepEquivalent());
    }

    const Position& end_of_next_paragraph =
        relocatable_end_of_next_paragraph->GetPosition();

    // Sometimes FormatRange can format beyond end. If the relocated end is now
    // the equivalent to end_of_next_paragraph, abort to avoid redoing the same
    // work in the next step.
    if (relocatable_end->GetPosition().IsEquivalent(end_of_next_paragraph)) {
      break;
    }

    // Don't put the next paragraph in the blockquote we just created for this
    // paragraph unless the next paragraph is in the same cell.
    if (enclosing_cell &&
        enclosing_cell !=
            EnclosingNodeOfType(end_of_next_paragraph, &IsTableCell))
      blockquote_for_next_indent = nullptr;

    DCHECK(end_of_next_last_paragraph->GetPosition().IsNull() ||
           end_of_next_last_paragraph->GetPosition().IsConnected());
    DCHECK(end_of_next_paragraph.IsNull() ||
           end_of_next_paragraph.IsConnected());

    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
    end_of_current_paragraph = CreateVisiblePosition(end_of_next_paragraph);
  }
}

static bool IsNewLineAtPosition(const Position& position) {
  auto* text_node = DynamicTo<Text>(position.ComputeContainerNode());
  int offset = position.OffsetInContainerNode();
  if (!text_node || offset < 0 ||
      offset >= static_cast<int>(text_node->length()))
    return false;

  DummyExceptionStateForTesting exception_state;
  String text_at_position =
      text_node->substringData(offset, 1, exception_state);
  if (exception_state.HadException())
    return false;

  return text_at_position[0] == '\n';
}

static const ComputedStyle* ComputedStyleOfEnclosingTextNode(
    const Position& position) {
  if (!position.IsOffsetInAnchor() || !position.ComputeContainerNode() ||
      !position.ComputeContainerNode()->IsTextNode())
    return nullptr;
  return position.ComputeContainerNode()
      ->GetComputedStyleForElementOrLayoutObject();
}

void ApplyBlockElementCommand::RangeForParagraphSplittingTextNodesIfNeeded(
    const VisiblePosition& end_of_current_paragraph,
    Position& end_of_last_paragraph,
    Position& start,
    Position& end) {
  start = StartOfParagraph(end_of_current_paragraph).DeepEquivalent();
  end = end_of_current_paragraph.DeepEquivalent();

  bool is_start_and_end_on_same_node = false;
  if (const ComputedStyle* start_style =
          ComputedStyleOfEnclosingTextNode(start)) {
    is_start_and_end_on_same_node =
        ComputedStyleOfEnclosingTextNode(end) &&
        start.ComputeContainerNode() == end.ComputeContainerNode();
    bool is_start_and_end_of_last_paragraph_on_same_node =
        ComputedStyleOfEnclosingTextNode(end_of_last_paragraph) &&
        start.ComputeContainerNode() ==
            end_of_last_paragraph.ComputeContainerNode();

    // Avoid obtanining the start of next paragraph for start
    // TODO(yosin) We should use |PositionMoveType::CodePoint| for
    // |previousPositionOf()|.
    if (start_style->ShouldPreserveBreaks() && IsNewLineAtPosition(start) &&
        !IsNewLineAtPosition(
            PreviousPositionOf(start, PositionMoveType::kCodeUnit)) &&
        start.OffsetInContainerNode() > 0) {
      start = StartOfParagraph(CreateVisiblePosition(PreviousPositionOf(
                                   end, PositionMoveType::kCodeUnit)))
                  .DeepEquivalent();
    }

    // If start is in the middle of a text node, split.
    if (!start_style->ShouldCollapseWhiteSpaces() &&
        start.OffsetInContainerNode() > 0) {
      int start_offset = start.OffsetInContainerNode();
      auto* start_text = To<Text>(start.ComputeContainerNode());
      SplitTextNode(start_text, start_offset);
      GetDocument().UpdateStyleAndLayoutTree();

      start = Position::FirstPositionInNode(*start_text);
      if (is_start_and_end_on_same_node) {
        DCHECK_GE(end.OffsetInContainerNode(), start_offset);
        end = Position(start_text, end.OffsetInContainerNode() - start_offset);
      }
      if (is_start_and_end_of_last_paragraph_on_same_node) {
        DCHECK_GE(end_of_last_paragraph.OffsetInContainerNode(), start_offset);
        end_of_last_paragraph =
            Position(start_text, end_of_last_paragraph.OffsetInContainerNode() -
                                     start_offset);
      }
    }
  }

  if (const ComputedStyle* end_style = ComputedStyleOfEnclosingTextNode(end)) {
    bool is_end_and_end_of_last_paragraph_on_same_node =
        ComputedStyleOfEnclosingTextNode(end_of_last_paragraph) &&
        end.AnchorNode() == end_of_last_paragraph.AnchorNode();
    // Include \n at the end of line if we're at an empty paragraph
    if (end_style->ShouldPreserveBreaks() && start == end &&
        end.OffsetInContainerNode() <
            static_cast<int>(To<Text>(end.ComputeContainerNode())->length())) {
      if (!RuntimeEnabledFeatures::
              NoIncreasingEndOffsetOnSplittingTextNodesEnabled()) {
        int end_offset = end.OffsetInContainerNode();
        // TODO(yosin) We should use |PositionMoveType::CodePoint| for
        // |previousPositionOf()|.
        if (!IsNewLineAtPosition(
                PreviousPositionOf(end, PositionMoveType::kCodeUnit)) &&
            IsNewLineAtPosition(end)) {
          end = Position(end.ComputeContainerNode(), end_offset + 1);
        }
      }
      if (is_end_and_end_of_last_paragraph_on_same_node &&
          end.OffsetInContainerNode() >=
              end_of_last_paragraph.OffsetInContainerNode())
        end_of_last_paragraph = end;
    }

    // If end is in the middle of a text node, split.
    if (end_style->UsedUserModify() != EUserModify::kReadOnly &&
        end_style->ShouldPreserveWhiteSpaces() && end.OffsetInContainerNode() &&
        end.OffsetInContainerNode() <
            static_cast<int>(To<Text>(end.ComputeContainerNode())->length())) {
      auto* end_container = To<Text>(end.ComputeContainerNode());
      SplitTextNode(end_container, end.OffsetInContainerNode());
      GetDocument().UpdateStyleAndLayoutTree();

      const Node* const previous_sibling_of_end =
          end_container->previousSibling();
      DCHECK(previous_sibling_of_end);
      if (is_start_and_end_on_same_node) {
        start = FirstPositionInOrBeforeNode(*previous_sibling_of_end);
      }
      if (is_end_and_end_of_last_paragraph_on_same_node) {
        if (end_of_last_paragraph.OffsetInContainerNode() ==
            end.OffsetInContainerNode()) {
          end_of_last_paragraph =
              LastPositionInOrAfterNode(*previous_sibling_of_end);
        } else {
          end_of_last_paragraph = Position(
              end_container, end_of_last_paragraph.OffsetInContainerNode() -
                                 end.OffsetInContainerNode());
        }
      }
      end = Position::LastPositionInNode(*previous_sibling_of_end);
    }
  }
}

VisiblePosition
ApplyBlockElementCommand::EndOfNextParagrahSplittingTextNodesIfNeeded(
    VisiblePosition& end_of_current_paragraph,
    Position& end_of_last_paragraph,
    Position& start,
    Position& end) {
  const VisiblePosition& end_of_next_paragraph =
      EndOfParagraph(NextPositionOf(end_of_current_paragraph));
  const Position& end_of_next_paragraph_position =
      end_of_next_paragraph.DeepEquivalent();
  const ComputedStyle* style =
      ComputedStyleOfEnclosingTextNode(end_of_next_paragraph_position);
  if (!style)
    return end_of_next_paragraph;

  auto* const end_of_next_paragraph_text =
      To<Text>(end_of_next_paragraph_position.ComputeContainerNode());
  if (style->ShouldCollapseBreaks() ||
      !end_of_next_paragraph_position.OffsetInContainerNode() ||
      !IsNewLineAtPosition(
          Position::FirstPositionInNode(*end_of_next_paragraph_text))) {
    return end_of_next_paragraph;
  }

  // \n at the beginning of the text node immediately following the current
  // paragraph is trimmed by moveParagraphWithClones. If endOfNextParagraph was
  // pointing at this same text node, endOfNextParagraph will be shifted by one
  // paragraph. Avoid this by splitting "\n"
  if (end_of_next_paragraph_text->length() > 1) {
    // To avoid empty `Text` node, `end_of_next_paragraph_text` should be
    // longer than one. See http://crbug.com/1264470
    SplitTextNode(end_of_next_paragraph_text, 1);
  }
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  Text* const previous_text =
      DynamicTo<Text>(end_of_next_paragraph_text->previousSibling());
  if (end_of_next_paragraph_text == start.ComputeContainerNode() &&
      previous_text) {
    DCHECK_LT(start.OffsetInContainerNode(),
              end_of_next_paragraph_position.OffsetInContainerNode());
    start = Position(previous_text, start.OffsetInContainerNode());
  }
  if (end_of_next_paragraph_text == end.ComputeContainerNode() &&
      previous_text) {
    DCHECK_LT(end.OffsetInContainerNode(),
              end_of_next_paragraph_position.OffsetInContainerNode());
    end = Position(previous_text, end.OffsetInContainerNode());
  }
  if (end_of_next_paragraph_text ==
      end_of_last_paragraph.ComputeContainerNode()) {
    if (end_of_last_paragraph.OffsetInContainerNode() <
        end_of_next_paragraph_position.OffsetInContainerNode()) {
      // We can only fix endOfLastParagraph if the previous node was still text
      // and hasn't been modified by script.
      if (previous_text && static_cast<unsigned>(
                               end_of_last_paragraph.OffsetInContainerNode()) <=
                               previous_text->length()) {
        end_of_last_paragraph = Position(
            previous_text, end_of_last_paragraph.OffsetInContainerNode());
      }
    } else {
      end_of_last_paragraph =
          Position(end_of_next_paragraph_text,
                   end_of_last_paragraph.OffsetInContainerNode() - 1);
    }
  }

  return CreateVisiblePosition(
      Position(end_of_next_paragraph_text,
               end_of_next_paragraph_position.OffsetInContainerNode() - 1));
}

HTMLElement* ApplyBlockElementCommand::CreateBlockElement() const {
  HTMLElement* element = CreateHTMLElement(GetDocument(), tag_name_);
  if (inline_style_.length())
    element->setAttribute(html_names::kStyleAttr, inline_style_);
  return element;
}

}  // namespace blink
```