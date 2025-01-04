Response:
My goal is to analyze the provided C++ code snippet from Chromium's Blink rendering engine and extract its functionalities, relate them to web technologies, explain logical reasoning with examples, identify potential user errors, and outline user actions leading to this code. Since this is part 1 of 2, I need to summarize the functionalities covered in this part.

Here's a breakdown of the thinking process:

1. **Understand the Core Functionality:** The filename `insert_list_command.cc` strongly suggests this code deals with inserting HTML lists (ordered `<ol>` and unordered `<ul>`). The copyright notice and included headers reinforce this idea, pointing to DOM manipulation, editing commands, and HTML elements.

2. **Identify Key Classes and Functions:** I scanned the code for prominent class names (`InsertListCommand`) and function names (`DoApply`, `DoApplyForSingleParagraph`, `UnlistifyParagraph`, `ListifyParagraph`, `MergeWithNeighboringLists`, `FixOrphanedListChild`). These are the building blocks of the functionality.

3. **Analyze Individual Functions:** I examined each function to understand its purpose:
    * `FixOrphanedListChild`:  Handles cases where a list item exists outside a proper list, creating a new `<ul>` to contain it.
    * `MergeWithNeighboringLists`:  Merges adjacent lists of the same type.
    * `SelectionHasListOfType`: Checks if the current selection is entirely within a list of a specific type.
    * `DoApply`: The main function for inserting a list. It handles both single and multi-paragraph selections. It iterates through paragraphs and calls `DoApplyForSingleParagraph`.
    * `DoApplyForSingleParagraph`:  Handles list insertion or removal for a single paragraph. It checks if the paragraph is already in a list and either switches the list type, removes the list, or creates a new list.
    * `UnlistifyParagraph`: Removes a paragraph from a list.
    * `ListifyParagraph`: Encloses a paragraph within a new list item and potentially a new list.

4. **Relate to Web Technologies (HTML, CSS, JavaScript):** I considered how these C++ functions manifest in the browser's behavior.
    * **HTML:** The code directly manipulates HTML elements like `<ul>`, `<ol>`, and `<li>`. The functionality corresponds to user actions that create and modify lists in HTML.
    * **CSS:** While the code doesn't directly manipulate CSS, the creation and modification of list elements will inherently affect their rendering based on CSS rules (e.g., list markers, indentation).
    * **JavaScript:**  JavaScript can trigger these commands through the `document.execCommand()` method (e.g., `document.execCommand('insertUnorderedList')`). User interactions in rich text editors often translate to such JavaScript calls.

5. **Infer Logical Reasoning and Create Examples:** I looked for conditional logic and DOM manipulation steps within the functions. I then constructed hypothetical scenarios and predicted the output based on the code's behavior. For example, selecting text within an existing unordered list and triggering "insert ordered list" would lead to the list type being switched.

6. **Identify User/Programming Errors:** I considered common mistakes users or developers might make that would involve this code:
    * Selecting only part of a list item and trying to create a new list.
    * Nesting lists incorrectly through manual HTML editing.
    * JavaScript errors when interacting with the editing API.

7. **Trace User Actions (Debugging Clues):** I outlined the typical user interactions that would lead to the execution of this code, such as clicking the "bulleted list" or "numbered list" button in a rich text editor or using keyboard shortcuts.

8. **Focus on Part 1 Summary:** Since this is the first part, I concentrated on summarizing the functionalities covered so far. This includes creating lists, removing list formatting, and handling scenarios involving existing lists. I avoided speculating on functionalities that might be present in the next part.

9. **Review and Refine:** I reread my analysis to ensure accuracy, clarity, and completeness within the scope of Part 1. I checked for any inconsistencies or areas where further explanation might be needed. For example, I made sure to explicitly mention `document.execCommand()` as the JavaScript entry point. I also refined the examples to be more concrete.

By following these steps, I could systematically analyze the code and provide a comprehensive answer addressing all aspects of the prompt. The key was to connect the low-level C++ code to the higher-level concepts of web development.
这是对 `blink/renderer/core/editing/commands/insert_list_command.cc` 文件的第一部分分析，该文件是 Chromium Blink 引擎中负责处理插入列表操作的核心代码。

**功能归纳 (针对第一部分):**

总的来说，`InsertListCommand` 类的主要功能是**在可编辑的内容中插入或移除无序列表 (`<ul>`) 或有序列表 (`<ol>`)**。它能够智能地处理各种复杂的编辑场景，例如：

* **创建新列表:**  当选区不在任何现有列表中时，创建新的列表（`<ul>` 或 `<ol>`) 并将选中的段落转换为列表项 (`<li>`)。
* **切换列表类型:**  如果选区内的段落已存在于某种类型的列表中，则可以将该列表切换为另一种类型（例如，从无序列表切换为有序列表，反之亦然）。
* **移除列表格式 (取消列表化):**  将选区内的列表项从其所属的列表中移除，使其变回普通的段落。
* **合并相邻的列表:**  如果插入或移除列表操作导致相邻的两个列表具有相同的类型，则将它们合并为一个列表。
* **处理孤立的列表子节点:**  如果发现不属于任何列表的 `<li>` 元素，则创建一个新的 `<ul>` 元素来包含它。
* **处理单段落和多段落选择:**  `InsertListCommand` 可以处理用户选中单个段落或多个段落的情况。
* **与邻近列表合并:** 在插入新列表时，会检查前后是否有相同类型的列表，并尝试进行合并。

**与 JavaScript, HTML, CSS 的关系举例说明:**

1. **JavaScript:**
   - **触发命令:** 当用户在网页上使用富文本编辑器，并点击 "创建无序列表" 或 "创建有序列表" 的按钮时，通常会触发 JavaScript 代码调用 `document.execCommand('insertUnorderedList')` 或 `document.execCommand('insertOrderedList')`。 这些 JavaScript 命令最终会调用 Blink 引擎中对应的 C++ 代码，即 `InsertListCommand`。
   - **示例:** 用户在一个 `<div contenteditable="true">` 元素中选中一些文本，然后执行 JavaScript 代码 `document.execCommand('insertUnorderedList')`。 这将导致 `InsertListCommand` 被调用，并在选中的文本周围创建 `<ul>` 和 `<li>` 元素。

2. **HTML:**
   - **创建/修改 HTML 结构:** `InsertListCommand` 的核心功能就是创建和修改 HTML 结构，特别是 `<ul>`、`<ol>` 和 `<li>` 元素。
   - **示例:**
     - **假设输入:**  HTML 中有 `<p>第一行</p><p>第二行</p>`，用户选中这两行并执行 "创建有序列表" 操作。
     - **预期输出 (修改后的 HTML):** `<ol><li>第一行</li><li>第二行</li></ol>`
   - **取消列表化示例:**
     - **假设输入:** HTML 中有 `<ol><li>项目一</li></ol>`，用户选中 "项目一" 并执行 "取消列表化" 操作。
     - **预期输出 (修改后的 HTML):** `<p>项目一</p>`

3. **CSS:**
   - **间接影响样式:**  虽然 `InsertListCommand` 不直接操作 CSS，但它创建的 HTML 结构会受到 CSS 样式的影响。例如，浏览器会根据默认样式或开发者自定义的 CSS 规则来渲染 `<ul>` 和 `<ol>` 的列表标记、缩进等。
   - **示例:**  开发者可能使用 CSS 来改变列表标记的样式（例如，使用不同的符号作为无序列表的标记，或者自定义有序列表的编号方式）。`InsertListCommand` 创建的 `<ul>` 和 `<ol>` 元素会自动应用这些 CSS 样式。

**逻辑推理的假设输入与输出:**

* **假设输入:** 用户在一个空的 `<div contenteditable="true">` 中输入 "第一项"，然后按下 Enter 键，再输入 "第二项"。此时光标位于 "第二项" 所在的段落中。用户执行 "创建无序列表" 操作。
* **逻辑推理:**  `InsertListCommand` 会检测到光标所在的段落不在任何列表中。它会创建一个新的 `<ul>` 元素，并将 "第一项" 和 "第二项" 分别包裹在 `<li>` 元素中。
* **预期输出:**  HTML 结构变为 `<ul><li>第一项</li><li>第二项</li></ul>`。

**涉及用户或编程常见的使用错误举例说明:**

1. **用户错误:**
   - **只选中列表项的部分内容进行列表操作:** 用户可能只选中一个列表项中的一部分文字，然后尝试创建新的列表。`InsertListCommand` 会尝试将选中的部分文字从原列表中移除并放入新的列表中，这可能会导致列表结构混乱。
   - **在复杂的嵌套结构中进行列表操作:**  在包含表格、嵌套列表等复杂结构的 HTML 中进行列表操作，可能会导致意外的结构变化，用户可能不清楚操作的具体影响范围。

2. **编程错误:**
   - **不正确地使用 `document.execCommand`:** 开发者可能错误地调用 `document.execCommand('insertUnorderedList')` 或 `document.execCommand('insertOrderedList')`，例如在不可编辑的区域调用，或者在不恰当的时机调用，可能导致命令执行失败或产生预期之外的结果。
   - **手动修改 HTML 导致状态不一致:**  开发者可能使用 JavaScript 直接修改 DOM 结构，手动创建或修改列表，而没有通过编辑命令，这可能导致 Blink 引擎内部的状态与实际的 DOM 结构不一致，从而在后续的编辑操作中出现问题。

**用户操作是如何一步步到达这里的调试线索:**

1. **用户在支持富文本编辑的网页上进行操作:**  用户正在一个可以编辑的 HTML 元素（例如，设置了 `contenteditable="true"` 的 `div` 或 `textarea`）中进行编辑。
2. **用户触发插入列表的动作:**
   - **点击编辑器工具栏按钮:** 用户可能点击了富文本编辑器工具栏上的 "无序列表" 或 "有序列表" 按钮。
   - **使用键盘快捷键:**  某些编辑器可能支持使用键盘快捷键来插入列表（例如，某些编辑器中 `Ctrl+Shift+8` 或 `Ctrl+Shift+7` 用于插入列表）。
   - **通过 JavaScript 代码调用:** 网页的 JavaScript 代码可能响应用户的某些操作（例如，点击自定义按钮）而调用 `document.execCommand('insertUnorderedList')` 或 `document.execCommand('insertOrderedList')`。
3. **浏览器接收到插入列表的命令:** 用户的操作或 JavaScript 代码调用最终会触发浏览器内核 (Blink) 的相关处理逻辑。
4. **`document.execCommand` 处理:**  浏览器会接收到 `insertUnorderedList` 或 `insertOrderedList` 命令。
5. **命令路由到 `InsertListCommand`:**  Blink 引擎会根据接收到的命令类型，将处理流程路由到 `blink/renderer/core/editing/commands/insert_list_command.cc` 文件中的 `InsertListCommand` 类。
6. **`InsertListCommand::execute` (或其他入口点) 被调用:**  `InsertListCommand` 类的某个执行方法会被调用，开始执行插入列表的逻辑。这部分代码会获取当前的选区，判断是否在列表中，然后执行相应的 DOM 操作来创建、修改或移除列表。

总而言之，`InsertListCommand` 负责处理用户在网页上创建和修改列表的操作，它是连接用户界面交互、JavaScript 命令和底层 DOM 操作的关键组件。

Prompt: 
```
这是目录为blink/renderer/core/editing/commands/insert_list_command.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2006, 2010 Apple Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/editing/commands/insert_list_command.h"

#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/editing/commands/editing_commands_utilities.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/relocatable_position.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_li_element.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/html/html_ulist_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

static Node* EnclosingListChild(Node* node, Node* list_node) {
  Node* list_child = EnclosingListChild(node);
  while (list_child && EnclosingList(list_child) != list_node)
    list_child = EnclosingListChild(list_child->parentNode());
  return list_child;
}

HTMLUListElement* InsertListCommand::FixOrphanedListChild(
    Node* node,
    EditingState* editing_state) {
  auto* list_element = MakeGarbageCollected<HTMLUListElement>(GetDocument());
  InsertNodeBefore(list_element, node, editing_state);
  if (editing_state->IsAborted())
    return nullptr;
  RemoveNode(node, editing_state);
  if (editing_state->IsAborted())
    return nullptr;
  AppendNode(node, list_element, editing_state);
  if (editing_state->IsAborted())
    return nullptr;
  return list_element;
}

HTMLElement* InsertListCommand::MergeWithNeighboringLists(
    HTMLElement* passed_list,
    EditingState* editing_state) {
  DCHECK(passed_list);
  HTMLElement* list = passed_list;
  Element* previous_list = ElementTraversal::PreviousSibling(*list);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  if (previous_list && CanMergeLists(*previous_list, *list)) {
    MergeIdenticalElements(previous_list, list, editing_state);
    if (editing_state->IsAborted())
      return nullptr;
  }

  if (!list)
    return nullptr;

  Element* next_sibling = ElementTraversal::NextSibling(*list);
  auto* next_list = DynamicTo<HTMLElement>(next_sibling);
  if (!next_list)
    return list;

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  if (CanMergeLists(*list, *next_list)) {
    MergeIdenticalElements(list, next_list, editing_state);
    if (editing_state->IsAborted())
      return nullptr;
    return next_list;
  }
  return list;
}

bool InsertListCommand::SelectionHasListOfType(
    const Position& selection_start,
    const Position& selection_end,
    const HTMLQualifiedName& list_tag) {
  DCHECK_LE(selection_start, selection_end);
  DCHECK(!GetDocument().NeedsLayoutTreeUpdate());
  DocumentLifecycle::DisallowTransitionScope disallow_transition(
      GetDocument().Lifecycle());

  VisiblePosition start = CreateVisiblePosition(selection_start);

  if (!EnclosingList(start.DeepEquivalent().AnchorNode()))
    return false;

  VisiblePosition end = StartOfParagraph(CreateVisiblePosition(selection_end));
  while (start.IsNotNull() && start.DeepEquivalent() != end.DeepEquivalent()) {
    HTMLElement* list_element =
        EnclosingList(start.DeepEquivalent().AnchorNode());
    if (!list_element || !list_element->HasTagName(list_tag))
      return false;
    start = StartOfNextParagraph(start);
  }

  return true;
}

InsertListCommand::InsertListCommand(Document& document, Type type)
    : CompositeEditCommand(document), type_(type) {}

static bool InSameTreeAndOrdered(const Position& should_be_former,
                                 const Position& should_be_later) {
  // Input positions must be canonical positions.
  DCHECK_EQ(should_be_former,
            CreateVisiblePosition(should_be_former).DeepEquivalent())
      << should_be_former;
  DCHECK_EQ(should_be_later,
            CreateVisiblePosition(should_be_later).DeepEquivalent())
      << should_be_later;
  return Position::CommonAncestorTreeScope(should_be_former, should_be_later) &&
         ComparePositions(should_be_former, should_be_later) <= 0;
}

void InsertListCommand::DoApply(EditingState* editing_state) {
  // Only entry points are EditorCommand::execute and
  // IndentOutdentCommand::outdentParagraph, both of which ensure clean layout.
  DCHECK(!GetDocument().NeedsLayoutTreeUpdate());

  const VisibleSelection& visible_selection = EndingVisibleSelection();
  if (visible_selection.IsNone() || visible_selection.Start().IsOrphan() ||
      visible_selection.End().IsOrphan())
    return;

  if (!RootEditableElementOf(EndingSelection().Anchor())) {
    return;
  }

  VisiblePosition visible_end = visible_selection.VisibleEnd();
  VisiblePosition visible_start = visible_selection.VisibleStart();
  // When a selection ends at the start of a paragraph, we rarely paint
  // the selection gap before that paragraph, because there often is no gap.
  // In a case like this, it's not obvious to the user that the selection
  // ends "inside" that paragraph, so it would be confusing if
  // InsertUn{Ordered}List operated on that paragraph.
  // FIXME: We paint the gap before some paragraphs that are indented with left
  // margin/padding, but not others.  We should make the gap painting more
  // consistent and then use a left margin/padding rule here.
  if (visible_end.DeepEquivalent() != visible_start.DeepEquivalent() &&
      IsStartOfParagraph(visible_end, kCanSkipOverEditingBoundary)) {
    const VisiblePosition& new_end =
        PreviousPositionOf(visible_end, kCannotCrossEditingBoundary);
    SelectionInDOMTree::Builder builder;
    builder.Collapse(visible_start.ToPositionWithAffinity());
    if (new_end.IsNotNull())
      builder.Extend(new_end.DeepEquivalent());
    SetEndingSelection(SelectionForUndoStep::From(builder.Build()));
    if (!RootEditableElementOf(EndingSelection().Anchor())) {
      return;
    }
  }

  const HTMLQualifiedName& list_tag =
      (type_ == kOrderedList) ? html_names::kOlTag : html_names::kUlTag;
  if (!EndingVisibleSelection().IsRange()) {
    Range* const range =
        CreateRange(FirstEphemeralRangeOf(EndingVisibleSelection()));
    DCHECK(range);
    DoApplyForSingleParagraph(false, list_tag, *range, editing_state);
    return;
  }

  VisibleSelection selection =
      SelectionForParagraphIteration(EndingVisibleSelection());
  if (!selection.IsRange()) {
    Range* const range = CreateRange(FirstEphemeralRangeOf(selection));
    DCHECK(range);
    DoApplyForSingleParagraph(false, list_tag, *range, editing_state);
    return;
  }

  DCHECK(selection.IsRange());
  VisiblePosition visible_start_of_selection = selection.VisibleStart();
  VisiblePosition visible_end_of_selection = selection.VisibleEnd();
  PositionWithAffinity start_of_selection =
      visible_start_of_selection.ToPositionWithAffinity();
  PositionWithAffinity end_of_selection =
      visible_end_of_selection.ToPositionWithAffinity();
  Position start_of_last_paragraph =
      StartOfParagraph(visible_end_of_selection, kCanSkipOverEditingBoundary)
          .DeepEquivalent();
  bool force_list_creation = false;

  Range* current_selection =
      CreateRange(FirstEphemeralRangeOf(EndingVisibleSelection()));
  ContainerNode* scope_for_start_of_selection = nullptr;
  ContainerNode* scope_for_end_of_selection = nullptr;
  // FIXME: This is an inefficient way to keep selection alive because
  // indexForVisiblePosition walks from the beginning of the document to the
  // visibleEndOfSelection every time this code is executed. But not using
  // index is hard because there are so many ways we can lose selection inside
  // doApplyForSingleParagraph.
  int index_for_start_of_selection = IndexForVisiblePosition(
      visible_start_of_selection, scope_for_start_of_selection);
  int index_for_end_of_selection = IndexForVisiblePosition(
      visible_end_of_selection, scope_for_end_of_selection);

  if (!StartOfParagraph(visible_start_of_selection, kCanSkipOverEditingBoundary)
           .DeepEquivalent()
           .IsEquivalent(start_of_last_paragraph)) {
    force_list_creation =
        !SelectionHasListOfType(selection.Start(), selection.End(), list_tag);

    VisiblePosition start_of_current_paragraph = visible_start_of_selection;
    while (InSameTreeAndOrdered(start_of_current_paragraph.DeepEquivalent(),
                                start_of_last_paragraph) &&
           !InSameParagraph(start_of_current_paragraph,
                            CreateVisiblePosition(start_of_last_paragraph),
                            kCanCrossEditingBoundary)) {
      // doApply() may operate on and remove the last paragraph of the
      // selection from the document if it's in the same list item as
      // startOfCurrentParagraph. Return early to avoid an infinite loop and
      // because there is no more work to be done.
      // FIXME(<rdar://problem/5983974>): The endingSelection() may be
      // incorrect here.  Compute the new location of visibleEndOfSelection
      // and use it as the end of the new selection.
      if (!start_of_last_paragraph.IsConnected())
        return;
      SetEndingSelection(SelectionForUndoStep::From(
          SelectionInDOMTree::Builder()
              .Collapse(start_of_current_paragraph.DeepEquivalent())
              .Build()));

      // Save and restore visibleEndOfSelection and startOfLastParagraph when
      // necessary since moveParagraph and movePragraphWithClones can remove
      // nodes.
      bool single_paragraph_result = DoApplyForSingleParagraph(
          force_list_creation, list_tag, *current_selection, editing_state);
      if (editing_state->IsAborted())
        return;
      if (!single_paragraph_result)
        break;

      GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

      // Make |visibleEndOfSelection| valid again.
      if (!end_of_selection.IsConnected() ||
          !start_of_last_paragraph.IsConnected()) {
        visible_end_of_selection = VisiblePositionForIndex(
            index_for_end_of_selection, scope_for_end_of_selection);
        end_of_selection = visible_end_of_selection.ToPositionWithAffinity();
        // If visibleEndOfSelection is null, then some contents have been
        // deleted from the document. This should never happen and if it did,
        // exit early immediately because we've lost the loop invariant.
        DCHECK(visible_end_of_selection.IsNotNull());
        if (visible_end_of_selection.IsNull() ||
            !RootEditableElementOf(visible_end_of_selection.DeepEquivalent()))
          return;
        start_of_last_paragraph = StartOfParagraph(visible_end_of_selection,
                                                   kCanSkipOverEditingBoundary)
                                      .DeepEquivalent();
      } else {
        visible_end_of_selection = CreateVisiblePosition(end_of_selection);
      }

      start_of_current_paragraph =
          StartOfNextParagraph(EndingVisibleSelection().VisibleStart());
    }
    SetEndingSelection(SelectionForUndoStep::From(
        SelectionInDOMTree::Builder()
            .Collapse(visible_end_of_selection.DeepEquivalent())
            .Build()));
  }
  DoApplyForSingleParagraph(force_list_creation, list_tag, *current_selection,
                            editing_state);
  if (editing_state->IsAborted())
    return;

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  // Fetch the end of the selection, for the reason mentioned above.
  if (!end_of_selection.IsConnected()) {
    visible_end_of_selection = VisiblePositionForIndex(
        index_for_end_of_selection, scope_for_end_of_selection);
    if (visible_end_of_selection.IsNull())
      return;
  } else {
    visible_end_of_selection = CreateVisiblePosition(end_of_selection);
  }

  if (!start_of_selection.IsConnected()) {
    visible_start_of_selection = VisiblePositionForIndex(
        index_for_start_of_selection, scope_for_start_of_selection);
    if (visible_start_of_selection.IsNull())
      return;
  } else {
    visible_start_of_selection = CreateVisiblePosition(start_of_selection);
  }

  SetEndingSelection(SelectionForUndoStep::From(
      SelectionInDOMTree::Builder()
          .SetAffinity(visible_start_of_selection.Affinity())
          .SetBaseAndExtentDeprecated(
              visible_start_of_selection.DeepEquivalent(),
              visible_end_of_selection.DeepEquivalent())
          .Build()));
}

InputEvent::InputType InsertListCommand::GetInputType() const {
  return type_ == kOrderedList ? InputEvent::InputType::kInsertOrderedList
                               : InputEvent::InputType::kInsertUnorderedList;
}

bool InsertListCommand::DoApplyForSingleParagraph(
    bool force_create_list,
    const HTMLQualifiedName& list_tag,
    Range& current_selection,
    EditingState* editing_state) {
  // FIXME: This will produce unexpected results for a selection that starts
  // just before a table and ends inside the first cell,
  // selectionForParagraphIteration should probably be renamed and deployed
  // inside setEndingSelection().
  Node* selection_node = EndingVisibleSelection().Start().AnchorNode();
  Node* list_child_node = EnclosingListChild(selection_node);
  bool switch_list_type = false;
  if (list_child_node) {
    if (!IsEditable(*list_child_node->parentNode()))
      return false;
    // Remove the list child.
    HTMLElement* list_element = EnclosingList(list_child_node);
    if (list_element) {
      if (!IsEditable(*list_element)) {
        // Since, |listElement| is uneditable, we can't move |listChild|
        // out from |listElement|.
        return false;
      }
      if (!IsEditable(*list_element->parentNode())) {
        // Since parent of |listElement| is uneditable, we can not remove
        // |listElement| for switching list type neither unlistify.
        return false;
      }
    }
    if (!list_element) {
      list_element = FixOrphanedListChild(list_child_node, editing_state);
      if (editing_state->IsAborted())
        return false;
      list_element = MergeWithNeighboringLists(list_element, editing_state);
      if (editing_state->IsAborted())
        return false;
      GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
    }
    DCHECK(IsEditable(*list_element));
    DCHECK(IsEditable(*list_element->parentNode()));
    if (!list_element->HasTagName(list_tag)) {
      // |list_child_node| will be removed from the list and a list of type
      // |type_| will be created.
      switch_list_type = true;
    }

    // If the list is of the desired type, and we are not removing the list,
    // then exit early.
    if (!switch_list_type && force_create_list)
      return true;

    // If the entire list is selected, then convert the whole list.
    if (switch_list_type &&
        IsNodeVisiblyContainedWithin(*list_element,
                                     EphemeralRange(&current_selection))) {
      bool range_start_is_in_list =
          CreateVisiblePosition(PositionBeforeNode(*list_element))
              .DeepEquivalent() ==
          CreateVisiblePosition(current_selection.StartPosition())
              .DeepEquivalent();
      bool range_end_is_in_list =
          CreateVisiblePosition(PositionAfterNode(*list_element))
              .DeepEquivalent() ==
          CreateVisiblePosition(current_selection.EndPosition())
              .DeepEquivalent();

      HTMLElement* new_list = CreateHTMLElement(GetDocument(), list_tag);
      InsertNodeBefore(new_list, list_element, editing_state);
      if (editing_state->IsAborted())
        return false;

      GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
      Node* first_child_in_list =
          EnclosingListChild(VisiblePosition::FirstPositionInNode(*list_element)
                                 .DeepEquivalent()
                                 .AnchorNode(),
                             list_element);
      Element* outer_block =
          first_child_in_list && IsBlockFlowElement(*first_child_in_list)
              ? To<Element>(first_child_in_list)
              : list_element;

      MoveParagraphWithClones(
          VisiblePosition::FirstPositionInNode(*list_element),
          VisiblePosition::LastPositionInNode(*list_element), new_list,
          outer_block, editing_state);
      if (editing_state->IsAborted())
        return false;

      // Manually remove listNode because moveParagraphWithClones sometimes
      // leaves it behind in the document. See the bug 33668 and
      // editing/execCommand/insert-list-orphaned-item-with-nested-lists.html.
      // FIXME: This might be a bug in moveParagraphWithClones or
      // deleteSelection.
      if (list_element && list_element->isConnected()) {
        RemoveNode(list_element, editing_state);
        if (editing_state->IsAborted())
          return false;
      }

      new_list = MergeWithNeighboringLists(new_list, editing_state);
      if (editing_state->IsAborted())
        return false;

      // Restore the start and the end of current selection if they started
      // inside listNode because moveParagraphWithClones could have removed
      // them.
      if (range_start_is_in_list && new_list)
        current_selection.setStart(new_list, 0, IGNORE_EXCEPTION_FOR_TESTING);
      if (range_end_is_in_list && new_list) {
        current_selection.setEnd(new_list,
                                 Position::LastOffsetInNode(*new_list),
                                 IGNORE_EXCEPTION_FOR_TESTING);
      }

      SetEndingSelection(SelectionForUndoStep::From(
          SelectionInDOMTree::Builder()
              .Collapse(Position::FirstPositionInNode(*new_list))
              .Build()));

      return true;
    }

    UnlistifyParagraph(EndingVisibleSelection().VisibleStart(), list_element,
                       list_child_node, editing_state);
    if (editing_state->IsAborted())
      return false;
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  }

  if (!list_child_node || switch_list_type || force_create_list) {
    ListifyParagraph(EndingVisibleSelection().VisibleStart(), list_tag,
                     editing_state);
  }

  return true;
}

void InsertListCommand::UnlistifyParagraph(
    const VisiblePosition& original_start,
    HTMLElement* list_element,
    Node* list_child_node,
    EditingState* editing_state) {
  // Since, unlistify paragraph inserts nodes into parent and removes node
  // from parent, if parent of |listElement| should be editable.
  DCHECK(IsEditable(*list_element->parentNode()));
  Node* next_list_child;
  Node* previous_list_child;
  Position start;
  Position end;
  DCHECK(list_child_node);
  if (IsA<HTMLLIElement>(*list_child_node)) {
    start = Position::FirstPositionInNode(*list_child_node);
    end = Position::LastPositionInNode(*list_child_node);
    next_list_child = list_child_node->nextSibling();
    previous_list_child = list_child_node->previousSibling();
  } else {
    // A paragraph is visually a list item minus a list marker.  The paragraph
    // will be moved.
    const VisiblePosition& visible_start =
        StartOfParagraph(original_start, kCanSkipOverEditingBoundary);
    const VisiblePosition& visible_end =
        EndOfParagraph(visible_start, kCanSkipOverEditingBoundary);
    start = visible_start.DeepEquivalent();
    end = visible_end.DeepEquivalent();
    // InsertListCommandTest.UnlistifyParagraphCrashOnRemoveStyle reaches here.
    ABORT_EDITING_COMMAND_IF(start == end);
    Node* next = NextPositionOf(visible_end).DeepEquivalent().AnchorNode();
    DCHECK_NE(next, end.AnchorNode());
    next_list_child = EnclosingListChild(next, list_element);
    Node* previous =
        PreviousPositionOf(visible_start).DeepEquivalent().AnchorNode();
    DCHECK_NE(previous, start.AnchorNode());
    previous_list_child = EnclosingListChild(previous, list_element);
  }

  // When removing a list, we must always create a placeholder to act as a point
  // of insertion for the list content being removed.
  auto* placeholder = MakeGarbageCollected<HTMLBRElement>(GetDocument());
  HTMLElement* element_to_insert = placeholder;
  // If the content of the list item will be moved into another list, put it in
  // a list item so that we don't create an orphaned list child.
  if (EnclosingList(list_element)) {
    element_to_insert = MakeGarbageCollected<HTMLLIElement>(GetDocument());
    AppendNode(placeholder, element_to_insert, editing_state);
    if (editing_state->IsAborted())
      return;
  }

  if (next_list_child && previous_list_child) {
    // We want to pull listChildNode out of listNode, and place it before
    // nextListChild and after previousListChild, so we split listNode and
    // insert it between the two lists.
    // But to split listNode, we must first split ancestors of listChildNode
    // between it and listNode, if any exist.
    // FIXME: We appear to split at nextListChild as opposed to listChildNode so
    // that when we remove listChildNode below in moveParagraphs,
    // previousListChild will be removed along with it if it is unrendered. But
    // we ought to remove nextListChild too, if it is unrendered.
    SplitElement(list_element, SplitTreeToNode(next_list_child, list_element));
    InsertNodeBefore(element_to_insert, list_element, editing_state);
  } else if (next_list_child || list_child_node->parentNode() != list_element) {
    // Just because listChildNode has no previousListChild doesn't mean there
    // isn't any content in listNode that comes before listChildNode, as
    // listChildNode could have ancestors between it and listNode. So, we split
    // up to listNode before inserting the placeholder where we're about to move
    // listChildNode to.
    if (list_child_node->parentNode() != list_element)
      SplitElement(list_element,
                   SplitTreeToNode(list_child_node, list_element));
    InsertNodeBefore(element_to_insert, list_element, editing_state);
  } else {
    InsertNodeAfter(element_to_insert, list_element, editing_state);
  }
  if (editing_state->IsAborted())
    return;

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  VisiblePosition insertion_point = VisiblePosition::BeforeNode(*placeholder);
  VisiblePosition visible_start = CreateVisiblePosition(start);
  ABORT_EDITING_COMMAND_IF(visible_start.IsNull());
  VisiblePosition visible_end = CreateVisiblePosition(end);
  ABORT_EDITING_COMMAND_IF(visible_end.IsNull());
  DCHECK_LE(start, end);
  if (visible_end.DeepEquivalent() < visible_start.DeepEquivalent())
    visible_end = visible_start;
  MoveParagraphs(visible_start, visible_end, insertion_point, editing_state,
                 kPreserveSelection, kPreserveStyle, list_child_node);
}

static HTMLElement* AdjacentEnclosingList(const VisiblePosition& pos,
                                          const VisiblePosition& adjacent_pos,
                                          const HTMLQualifiedName& list_tag) {
  HTMLElement* list_element =
      OutermostEnclosingList(adjacent_pos.DeepEquivalent().AnchorNode());

  if (!list_element)
    return nullptr;

  Element* previous_cell = EnclosingTableCell(pos.DeepEquivalent());
  Element* current_cell = EnclosingTableCell(adjacent_pos.DeepEquivalent());

  if (!list_element->HasTagName(list_tag) ||
      list_element->contains(pos.DeepEquivalent().AnchorNode()) ||
      previous_cell != current_cell ||
      EnclosingList(list_element) !=
          EnclosingList(pos.DeepEquivalent().AnchorNode()))
    return nullptr;

  return list_element;
}

void InsertListCommand::ListifyParagraph(const VisiblePosition& original_start,
                                         const HTMLQualifiedName& list_tag,
                                         EditingState* editing_state) {
  const VisiblePosition& start =
      StartOfParagraph(original_start, kCanSkipOverEditingBoundary);
  const VisiblePosition& end =
      EndOfParagraph(start, kCanSkipOverEditingBoundary);

  if (start.IsNull() || end.IsNull())
    return;

  // If original_start is of type kOffsetInAnchor, then the offset can become
  // invalid when inserting the <li>. So use a RelocatablePosition.
  RelocatablePosition* relocatable_original_start =
      original_start.DeepEquivalent().IsOffsetInAnchor()
          ? MakeGarbageCollected<RelocatablePosition>(
                original_start.DeepEquivalent())
          : nullptr;

  // Check for adjoining lists.
  HTMLElement* const previous_list = AdjacentEnclosingList(
      start, PreviousPositionOf(start, kCannotCrossEditingBoundary), list_tag);
  HTMLElement* const next_list = AdjacentEnclosingList(
      start, NextPositionOf(end, kCannotCrossEditingBoundary), list_tag);
  if (previous_list || next_list) {
    // Place list item into adjoining lists.
    auto* list_item_element =
        MakeGarbageCollected<HTMLLIElement>(GetDocument());
    if (previous_list)
      AppendNode(list_item_element, previous_list, editing_state);
    else
      InsertNodeAt(list_item_element, Position::BeforeNode(*next_list),
                   editing_state);
    if (editing_state->IsAborted())
      return;

    MoveParagraphOverPositionIntoEmptyListItem(start, list_item_element,
                                               editing_state);
    if (editing_state->IsAborted())
      return;

    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
    if (previous_list && next_list && CanMergeLists(*previous_list, *next_list))
      MergeIdenticalElements(previous_list, next_list, editing_state);

    return;
  }

  // Create new list element.

  // Inserting the list into an empty paragraph that isn't held open
  // by a br or a '\n', will invalidate start and end.  Insert
  // a placeholder and then recompute start and end.
  Position start_pos = start.DeepEquivalent();
  if (start.DeepEquivalent() == end.DeepEquivalent() &&
      IsEnclosingBlock(start.DeepEquivalent().AnchorNode())) {
    HTMLBRElement* placeholder =
        InsertBlockPlaceholder(start_pos, editing_state);
    if (editing_state->IsAborted())
      return;
    start_pos = Position::BeforeNode(*placeholder);
  }

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  // Insert the list at a position visually equivalent to start of the
  // paragraph that is being moved into the list.
  // Try to avoid inserting it somewhere where it will be surrounded by
  // inline ancestors of start, since it is easier for editing to produce
  // clean markup when inline elements are pushed down as far as possible.
  Position insertion_pos(MostBackwardCaretPosition(start_pos));
  // Also avoid the temporary <span> element created by 'unlistifyParagraph'.
  // This element can be selected by mostBackwardCaretPosition when startPor
  // points to a element with previous siblings or ancestors with siblings.
  // |-A
  // | |-B
  // | +-C (insertion point)
  // |   |-D (*)
  if (IsA<HTMLSpanElement>(insertion_pos.AnchorNode())) {
    insertion_pos =
        Position::InParentBeforeNode(*insertion_pos.ComputeContainerNode());
  }
  // Also avoid the containing list item.
  Node* const list_child = EnclosingListChild(insertion_pos.AnchorNode());
  if (IsA<HTMLLIElement>(list_child))
    insertion_pos = Position::InParentBeforeNode(*list_child);

  HTMLElement* list_element = CreateHTMLElement(GetDocument(), list_tag);
  InsertNodeAt(list_element, insertion_pos, editing_state);
  if (editing_state->IsAborted())
    return;
  auto* list_item_element = MakeGarbageCollected<HTMLLIElement>(GetDocument());
  AppendNode(list_item_element, list_element, editing_state);
  if (editing_state->IsAborted())
    return;

  // We inserted the list at the start of the content we're about to move.
  // https://bugs.webkit.org/show_bug.cgi?id=19066: Update the start of content,
  // so we don't try to move the list into itself.
  // Layout is necessary since start's node's inline layoutObjects may have been
  // destroyed by the insertion The end of the content may have changed after
  // the insertion and layout so update it as well.
  if (insertion_pos != start_pos) {
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
    MoveParagraphOverPositionIntoEmptyListItem(
        CreateVisiblePosition(start_pos), list_item_element, editing_state);
  } else if (relocatable_original_start) {
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
    MoveParagraphOverPositionIntoEmptyListItem(
        CreateVisiblePosition(relocatable_original_start->GetPosition()),
        list_item_element, editing_state);
  } else {
    MoveParagraphOverPositionIntoEmptyListItem(
        original_start, list_item_element, editing_state);
  }
  if (editing_state->IsAborted())
    return;

  MergeWithNeighboringLists(list_element, editing_state);
}

// TODO(editing-dev): Stop storing VisiblePositions through mutations.
// See crbug.com/648949 for details.
void InsertListCommand::MoveParagraphOverPositionIntoEmptyListItem(
    const VisiblePosition& pos,
    HTMLLIElement* list_item_element,
    EditingState* editing_state) {
  DCHECK(!list_item_element->HasChildren());
  auto* placeholder = MakeGarbageCollected<HTMLBRElement>(GetDocument());
  AppendNode(placeholder, list_item_element, editing_state);
  if (editing_state->IsAborted())
    return;
  // Inserting list element and list item list may change start of pargraph
  // to move. We calculate start of paragraph again.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  const VisiblePosition& valid_pos =
      CreateVisiblePosition(pos.ToPositionWithAffinity());
  const VisiblePosition& start =
      StartOfParagraph(valid_pos, kCanSkipOverEditingBoundary);
  // InsertListCommandTest.InsertListOnEmptyHiddenElements reaches here.
  ABORT_EDITING_COMMAND_IF(start.IsNull());
  const VisiblePosition& end =
      EndOfParagraph(valid_pos, kCanSkipOverEditingBoundary);
  ABORT_EDITING_COMMAND_IF(end.IsNull());
  // Get the constraining ancestor so it doesn't cross the enclosing block.
  // This is useful to restrict the |HighestEnclosingNodeOfType| function to the
  // enclosing block node so we can get the "outer" block node without crossing
  // block boundaries as that function only breaks when the loop hits the
  // editable boundary or the parent element has an inline style(as we pass
  // |IsInlineElement| to it).
  Node* const constraining_ancestor =
      EnclosingBlock(start.DeepEquivalent().AnchorNode());
  Node* const outer_block = HighestEnclosingNodeOfType(
      start.DeepEquivalent(), &IsInlineElement, kCannotCrossEd
"""


```