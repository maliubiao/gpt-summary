Response:
Let's break down the thought process to analyze the `indent_outdent_command.cc` file.

1. **Understand the Goal:** The primary goal is to understand the functionality of this specific Chromium Blink source code file. We also need to identify its relationship to web technologies (JavaScript, HTML, CSS), provide examples, infer logic, highlight potential errors, and trace user interaction.

2. **Initial Scan and Keyword Identification:**  Quickly read through the file, paying attention to class names, function names, included headers, and comments. Keywords like "Indent," "Outdent," "Blockquote," "List," "Selection," "Paragraph," "DOM," and function names like `TryIndentingAsListItem`, `IndentIntoBlockquote`, `OutdentParagraph`, and `FormatSelection` immediately suggest the core functionality. The included headers (e.g., `document.h`, `element_traversal.h`, `editing_utilities.h`, `html_li_element.h`) confirm it's related to DOM manipulation and editing.

3. **Core Functionality Extraction:** Focus on the main class `IndentOutdentCommand`. The constructor takes an `IndentType` (indent or outdent), clearly indicating the file's dual purpose. The `FormatSelection` function seems like the entry point, branching to different logic based on the `type_of_action_`.

4. **Dissecting Key Functions:**

   * **`TryIndentingAsListItem`:**  The name is self-explanatory. It handles indentation when the selection is within a list item. Pay attention to its checks (inside a list, is a list item) and actions (creating a new list, moving paragraphs, merging lists). This connects directly to HTML list elements (`<ul>`, `<ol>`, `<li>`).

   * **`IndentIntoBlockquote`:** This function handles indenting by wrapping content in a `<blockquote>`. Note the logic for handling selections within tables and lists, and the splitting of the DOM tree. This is directly related to the HTML `<blockquote>` element and its default styling.

   * **`OutdentParagraph`:** This is responsible for removing indentation. It handles outdenting from lists (by using `InsertListCommand`) and blockquotes. The logic for removing the blockquote and handling nested blockquotes is crucial. It demonstrates how the command interacts with different HTML structures.

   * **`OutdentRegion`:** This function iterates through paragraphs within a selection and applies `OutdentParagraph` to each. This indicates the ability to outdent multiple paragraphs at once.

   * **`FormatSelection`:**  This acts as a dispatcher, choosing between indenting and outdenting.

   * **`FormatRange`:**  This function seems to handle the actual manipulation based on the start and end positions. It calls `TryIndentingAsListItem` first, and if that fails, calls `IndentIntoBlockquote`.

5. **Identifying Web Technology Relationships:**

   * **HTML:** The code heavily manipulates HTML elements like `<ul>`, `<ol>`, `<li>`, `<blockquote>`, `<br>`, `<div>`, `<span>`. The examples within the function comments and the code itself are excellent illustrations.

   * **CSS:**  The constructor for `IndentOutdentCommand` sets a default style for the `<blockquote>` (`margin`, `border`, `padding`). This shows the command's influence on the visual presentation. The comment mentioning checking the `list-style-type` property hints at CSS relevance for list rendering.

   * **JavaScript:** While this C++ code doesn't directly *contain* JavaScript, it's part of the Blink rendering engine. User actions in a web page (triggered by JavaScript events or browser UI) ultimately lead to the execution of this C++ code. For instance, a rich text editor implemented in JavaScript might call a browser API that eventually invokes this command.

6. **Inferring Logic and Providing Examples:**  Based on the function names and actions, deduce the expected behavior for different input scenarios. The comments in the code itself often provide "before" and "after" examples, which are invaluable. If there aren't explicit examples, create plausible scenarios. For instance, selecting text within a list item and pressing Tab (for indent) or Shift+Tab (for outdent) is a common user interaction.

7. **Identifying Potential Errors:** Look for conditions that could lead to unexpected behavior. Malformed HTML (e.g., list items not within a list), attempting to indent/outdent in non-editable areas, and edge cases in selection handling are potential sources of errors. The code includes `DCHECK` statements which are assertions that flag programming errors.

8. **Tracing User Interaction (Debugging Clues):** Think about how a user would trigger this code. Focus on common editing actions:

   * **Indenting:** Selecting text and pressing the Tab key (or a dedicated indent button in a rich text editor).
   * **Outdenting:** Selecting text and pressing Shift+Tab (or a dedicated outdent button).
   * **Context:** The user is likely interacting with an editable HTML element (`contenteditable="true"`).
   * **Selection:** The state of the user's selection (collapsed, range, within a list, within a blockquote) is crucial.

9. **Refining and Organizing:**  Structure the analysis logically. Start with a high-level overview of the file's purpose, then delve into the details of each function. Clearly separate the explanations related to JavaScript, HTML, and CSS. Use headings and bullet points to improve readability.

10. **Review and Iterate:**  Read through the analysis to ensure accuracy and completeness. Are the examples clear? Is the logic easy to follow?  Have all aspects of the request been addressed?  For instance, double-check if all the included headers are relevant to the explanations. Ensure the connection between user actions and the code execution is clearly stated.

By following this structured approach, we can effectively analyze and understand the functionality of a complex source code file like `indent_outdent_command.cc`. The combination of code examination, conceptual understanding of web technologies, and logical reasoning is key to achieving a comprehensive analysis.
好的，我们来详细分析一下 `blink/renderer/core/editing/commands/indent_outdent_command.cc` 这个文件。

**文件功能概述:**

`indent_outdent_command.cc` 文件定义了 Blink 渲染引擎中用于处理文本缩进和取消缩进操作的命令类 `IndentOutdentCommand`。它的主要功能是：

1. **缩进 (Indent):**  将选中的文本内容向内缩进，通常是通过在选中文本外包裹一个 `<blockquote>` 标签或者将其移动到现有的 `<blockquote>` 标签中来实现。对于列表项 (`<li>`)，缩进操作可能会将其转换为嵌套列表。
2. **取消缩进 (Outdent):** 将选中的文本内容取消缩进，即移除包裹选中文本的 `<blockquote>` 标签，或者将其从嵌套列表中移出。

**与 JavaScript, HTML, CSS 的关系及举例:**

这个文件位于 Blink 引擎的核心渲染部分，负责处理用户编辑操作，它与前端技术紧密相关：

* **HTML:**
    * **缩进:** 当执行缩进操作时，此代码可能会创建或操作 HTML 元素，最常见的是 `<blockquote>` 标签。例如，如果用户选中一段文本并执行缩进，该代码可能会将这段文本包裹在 `<blockquote>` 标签中：
        ```html
        <p>原始内容</p>
        ```
        执行缩进后可能变为：
        ```html
        <blockquote>
          <p>原始内容</p>
        </blockquote>
        ```
    * **列表缩进:** 如果选中的是列表项 (`<li>`)，缩进操作可能会将其变为子列表：
        ```html
        <ul>
          <li>第一项</li>
          <li>第二项</li>
        </ul>
        ```
        选中“第二项”并缩进后可能变为：
        ```html
        <ul>
          <li>第一项
            <ul>
              <li>第二项</li>
            </ul>
          </li>
        </ul>
        ```
    * **取消缩进:** 当执行取消缩进操作时，此代码会移除或解构相关的 HTML 标签。例如，如果选中的文本在一个 `<blockquote>` 中，取消缩进会移除这个 `<blockquote>` 标签：
        ```html
        <blockquote>
          <p>被缩进的内容</p>
        </blockquote>
        ```
        执行取消缩进后可能变为：
        ```html
        <p>被缩进的内容</p>
        ```
    * **列表取消缩进:** 如果选中的列表项是子列表的一部分，取消缩进会将其提升到父级列表的层级。

* **CSS:**
    * 默认情况下，`<blockquote>` 标签在浏览器中会有默认的缩进样式。`IndentOutdentCommand` 可能会直接创建带有特定内联样式的 `<blockquote>` 标签，例如：
      ```c++
      ApplyBlockElementCommand(
            document,
            html_names::kBlockquoteTag,
            AtomicString("margin: 0 0 0 40px; border: none; padding: 0px;"))
      ```
      这行代码展示了创建 `<blockquote>` 元素时，可能会设置 `margin-left` 来实现缩进效果。
    * 浏览器会根据 CSS 规则来渲染缩进后的效果。用户可以通过自定义 CSS 来修改 `<blockquote>` 或列表的缩进样式。

* **JavaScript:**
    * JavaScript 代码通常会触发缩进和取消缩进操作。例如，富文本编辑器可能会监听用户的键盘事件（如 Tab 键用于缩进，Shift + Tab 用于取消缩进）或按钮点击事件，然后调用相应的浏览器 API 来执行这些命令。
    * JavaScript 可以通过 `document.execCommand('indent')` 和 `document.execCommand('outdent')`  API 来直接触发这些命令。Blink 引擎的这个 C++ 文件就是这些 API 的底层实现。

**逻辑推理 (假设输入与输出):**

**假设输入 (缩进):**

1. **用户在一个空的 `<p>` 标签中输入了一些文本 "这是一段文字"。**
   ```html
   <p>这是一段文字</p>
   ```
2. **用户选中了这段文字。**
3. **用户触发了缩进操作 (例如，按下 Tab 键)。**

**预期输出 (缩进):**

```html
<blockquote>
  <p>这是一段文字</p>
</blockquote>
```

**假设输入 (取消缩进):**

1. **用户有一个被 `<blockquote>` 包裹的段落。**
   ```html
   <blockquote>
     <p>这是一段被缩进的文字</p>
   </blockquote>
   ```
2. **用户选中了这段文字。**
3. **用户触发了取消缩进操作 (例如，按下 Shift + Tab 键)。**

**预期输出 (取消缩进):**

```html
<p>这是一段被缩进的文字</p>
```

**涉及用户或编程常见的使用错误及举例:**

1. **在非可编辑区域尝试缩进/取消缩进:** 用户尝试在非 `contenteditable` 的元素或只读的输入框中进行缩进或取消缩进操作，这些操作将不会生效。
    ```html
    <div>这段文字不可编辑</div>
    <script>
      // 假设用户选中了 "这段文字不可编辑" 并尝试缩进
      document.execCommand('indent'); // 在这种情况下不会有效果
    </script>
    ```

2. **在复杂的嵌套结构中，缩进/取消缩进的行为可能不符合预期:** 例如，在一个深层嵌套的表格单元格内的列表项进行缩进/取消缩进，其行为可能取决于浏览器的具体实现和复杂的边界条件。

3. **编程错误：错误地使用 `document.execCommand`:** 开发者可能错误地调用 `document.execCommand('indent')` 或 `document.execCommand('outdent')`，例如在没有用户选区的情况下调用，或者在不支持这些命令的环境中调用。

4. **与 CSS 样式的冲突:** 用户或开发者自定义的 CSS 样式可能会覆盖或干扰浏览器默认的缩进行为，导致视觉效果与预期不符。例如，全局设置了 `blockquote { margin-left: 0; }` 可能会使缩进操作在视觉上没有效果。

**用户操作是如何一步步到达这里的，作为调试线索:**

1. **用户在可编辑的 HTML 元素中进行操作:**  用户首先需要在一个可以编辑的区域进行操作，这个区域通常是通过 HTML 元素的 `contenteditable` 属性设置为 `true` 来实现的。
2. **用户选中一段文本:**  用户通过鼠标拖拽或者键盘操作（Shift + 方向键）选中需要缩进或取消缩进的文本内容。
3. **用户触发缩进或取消缩进操作:**
    * **键盘快捷键:** 用户按下 Tab 键（通常用于缩进）或 Shift + Tab 键（通常用于取消缩进）。浏览器会监听这些键盘事件。
    * **富文本编辑器按钮:** 用户点击富文本编辑器界面上的“缩进”或“取消缩进”按钮。这些按钮通常会调用 JavaScript 代码来执行相应的命令。
    * **JavaScript 代码调用:** 网页上的 JavaScript 代码可能直接调用 `document.execCommand('indent')` 或 `document.execCommand('outdent')` 来触发这些操作。
4. **浏览器事件处理:** 浏览器接收到用户的操作事件（例如，键盘事件或鼠标点击事件）。
5. **命令路由:** 浏览器内部的事件处理机制会将这些编辑操作路由到相应的命令处理模块。对于缩进和取消缩进操作，事件会被传递到 Blink 引擎的编辑模块。
6. **`IndentOutdentCommand` 的执行:**  Blink 引擎的编辑模块会创建并执行 `IndentOutdentCommand` 类的实例。这个类会根据用户的操作类型（缩进或取消缩进）以及当前的 DOM 结构，执行相应的 DOM 操作，例如插入或删除 `<blockquote>` 标签，或者调整列表的嵌套结构。
7. **DOM 更新和渲染:** `IndentOutdentCommand` 修改 DOM 结构后，Blink 引擎会重新计算布局和样式，并重新渲染页面，用户才能看到缩进或取消缩进后的效果。

**调试线索:**

当调试缩进/取消缩进相关的问题时，可以考虑以下线索：

* **检查 `contenteditable` 属性:** 确保操作发生在可编辑的元素内。
* **查看选区 (Selection):**  确认用户是否正确选中了文本，以及选区的范围。
* **监听键盘事件:**  使用浏览器的开发者工具监听键盘事件，查看 Tab 和 Shift + Tab 事件是否被正确触发。
* **断点调试 JavaScript:** 如果是通过 JavaScript 触发的命令，可以在调用 `document.execCommand` 的地方设置断点，查看参数和执行流程。
* **Blink 渲染引擎调试:** 对于更深层次的问题，可能需要在 Blink 引擎的源代码中设置断点，例如在 `IndentOutdentCommand::FormatSelection` 或其他相关方法中，来跟踪命令的执行过程和 DOM 操作。
* **检查 CSS 样式:**  确认是否有自定义 CSS 样式干扰了默认的缩进行为。
* **查看 DOM 结构变化:** 使用浏览器的开发者工具观察执行缩进/取消缩进操作后 DOM 结构的变化，确认是否符合预期。

希望这个详细的分析能够帮助你理解 `blink/renderer/core/editing/commands/indent_outdent_command.cc` 文件的功能以及它与前端技术的联系。

Prompt: 
```
这是目录为blink/renderer/core/editing/commands/indent_outdent_command.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2006, 2008 Apple Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/editing/commands/indent_outdent_command.h"

#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/editing/commands/editing_commands_utilities.h"
#include "third_party/blink/renderer/core/editing/commands/insert_list_command.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/relocatable_position.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_li_element.h"
#include "third_party/blink/renderer/core/html/html_olist_element.h"
#include "third_party/blink/renderer/core/html/html_ulist_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

// Returns true if |node| is UL, OL, or BLOCKQUOTE with "display:block".
// "Outdent" command considers <BLOCKQUOTE style="display:inline"> makes
// indentation.
static bool IsHTMLListOrBlockquoteElement(const Node* node) {
  const auto* element = DynamicTo<HTMLElement>(node);
  if (!element)
    return false;
  if (!node->GetLayoutObject() || !node->GetLayoutObject()->IsLayoutBlock())
    return false;
  // TODO(yosin): We should check OL/UL element has "list-style-type" CSS
  // property to make sure they layout contents as list.
  return IsA<HTMLUListElement>(*element) || IsA<HTMLOListElement>(*element) ||
         element->HasTagName(html_names::kBlockquoteTag);
}

IndentOutdentCommand::IndentOutdentCommand(Document& document,
                                           IndentType type_of_action)
    : ApplyBlockElementCommand(
          document,
          html_names::kBlockquoteTag,
          AtomicString("margin: 0 0 0 40px; border: none; padding: 0px;")),
      type_of_action_(type_of_action) {}

bool IndentOutdentCommand::TryIndentingAsListItem(
    const Position& start,
    const Position& end,
    VisiblePosition& out_end_of_next_of_paragraph_to_move,
    EditingState* editing_state) {
  // If our selection is not inside a list, bail out.
  Node* last_node_in_selected_paragraph = start.AnchorNode();
  HTMLElement* list_element = EnclosingList(last_node_in_selected_paragraph);
  if (!list_element)
    return false;

  // Find the block that we want to indent.  If it's not a list item (e.g., a
  // div inside a list item), we bail out.
  Element* selected_list_item = EnclosingBlock(last_node_in_selected_paragraph);

  // FIXME: we need to deal with the case where there is no li (malformed HTML)
  if (!IsA<HTMLLIElement>(selected_list_item))
    return false;

  // FIXME: previousElementSibling does not ignore non-rendered content like
  // <span></span>.  Should we?
  Element* previous_list =
      ElementTraversal::PreviousSibling(*selected_list_item);
  Element* next_list = ElementTraversal::NextSibling(*selected_list_item);

  // We should calculate visible range in list item because inserting new
  // list element will change visibility of list item, e.g. :first-child
  // CSS selector.
  auto* new_list = To<HTMLElement>(GetDocument().CreateElement(
      list_element->TagQName(), CreateElementFlags::ByCloneNode(),
      g_null_atom));
  InsertNodeBefore(new_list, selected_list_item, editing_state);
  if (editing_state->IsAborted())
    return false;

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  // We should clone all the children of the list item for indenting purposes.
  // However, in case the current selection does not encompass all its children,
  // we need to explicitally handle the same. The original list item too would
  // require proper deletion in that case.
  const bool should_keep_selected_list =
      end.AnchorNode() == selected_list_item ||
      end.AnchorNode()->IsDescendantOf(selected_list_item->lastChild());

  const VisiblePosition& start_of_paragraph_to_move =
      CreateVisiblePosition(start);
  const VisiblePosition& end_of_paragraph_to_move =
      should_keep_selected_list
          ? CreateVisiblePosition(end)
          : VisiblePosition::AfterNode(*selected_list_item->lastChild());

  // The insertion of |newList| may change the computed style of other
  // elements, resulting in failure in visible canonicalization.
  if (start_of_paragraph_to_move.IsNull() ||
      end_of_paragraph_to_move.IsNull()) {
    editing_state->Abort();
    return false;
  }

  if (RuntimeEnabledFeatures::
          AdjustEndOfNextParagraphIfMovedParagraphIsUpdatedEnabled()) {
    // If `end_of_paragraph_to_move` is adjusted above since
    // `should_keep_selected_list` is false, before move the paragraphs below,
    // update the end of the next of the paragraph to move.
    if (!should_keep_selected_list) {
      out_end_of_next_of_paragraph_to_move =
          EndOfParagraph(NextPositionOf(end_of_paragraph_to_move));
    }
  }

  MoveParagraphWithClones(start_of_paragraph_to_move, end_of_paragraph_to_move,
                          new_list, selected_list_item, editing_state);
  if (editing_state->IsAborted())
    return false;

  if (!should_keep_selected_list) {
    RemoveNode(selected_list_item, editing_state);
    if (editing_state->IsAborted())
      return false;
  }

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  DCHECK(new_list);
  if (previous_list && CanMergeLists(*previous_list, *new_list)) {
    MergeIdenticalElements(previous_list, new_list, editing_state);
    if (editing_state->IsAborted())
      return false;
  }

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  if (next_list && CanMergeLists(*new_list, *next_list)) {
    MergeIdenticalElements(new_list, next_list, editing_state);
    if (editing_state->IsAborted())
      return false;
  }

  return true;
}

void IndentOutdentCommand::IndentIntoBlockquote(const Position& start,
                                                const Position& end,
                                                HTMLElement*& target_blockquote,
                                                EditingState* editing_state) {
  auto* enclosing_cell = To<Element>(EnclosingNodeOfType(start, &IsTableCell));
  Element* element_to_split_to;
  if (enclosing_cell)
    element_to_split_to = enclosing_cell;
  else if (EnclosingList(start.ComputeContainerNode()))
    element_to_split_to = EnclosingBlock(start.ComputeContainerNode());
  else
    element_to_split_to = RootEditableElementOf(start);

  if (!element_to_split_to)
    return;

  Node* outer_block =
      (start.ComputeContainerNode() == element_to_split_to)
          ? start.ComputeContainerNode()
          : SplitTreeToNode(start.ComputeContainerNode(), element_to_split_to);

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  // Before moving the paragraph under the new blockquote, make sure that there
  // aren't any nested paragraphs or line breaks under the outer_block. If there
  // are then split it into its own block so it doesn't copy multiple
  // paragraphs.
  Node* highest_inline_node = HighestEnclosingNodeOfType(
      end, IsInlineElement, kCannotCrossEditingBoundary, outer_block);
  if (highest_inline_node) {
    Position next_position = MostForwardCaretPosition(
        NextPositionOf(CreateVisiblePosition(end)).DeepEquivalent());
    if (IsStartOfParagraph(CreateVisiblePosition(next_position)) &&
        next_position.AnchorNode()->IsDescendantOf(highest_inline_node)) {
      // <div>Line                                 <blockquote>
      //                                             <div>
      //   <span> 1<div>Line 2</div></span>    ->      Line<span> 1</span>
      //                                             </div>
      // </div>                                    </blockquote>
      //                                           <div><span><div>Line
      //                                           2</div></span></div>
      //
      // <div>Line                                 <blockquote>
      //   <span> 1<br>Line 2</span>    ->           Line<span> 1</span>
      // </div>                                    </blockquote>
      //                                           <div><span>Line
      //                                           2</span></div>
      // The below steps are essentially trying to figure out where the split
      // needs to happen:
      // 1. If the next paragraph is enclosed with nested block level elements.
      // 2. If the next paragraph is enclosed with nested inline elements.
      // 3. If the next paragraph doesn't have any inline or block level
      // elements, but has elements like textarea/input/img etc.
      Node* split_point = HighestEnclosingNodeOfType(
          next_position, IsEnclosingBlock, kCannotCrossEditingBoundary,
          highest_inline_node);
      split_point = split_point
                        ? split_point
                        : HighestEnclosingNodeOfType(
                              next_position, IsInlineElement,
                              kCannotCrossEditingBoundary, highest_inline_node);
      split_point = split_point ? split_point : next_position.AnchorNode();
      // Split the element to separate the paragraphs.
      SplitElement(DynamicTo<Element>(highest_inline_node), split_point);
    }
  }
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  VisiblePosition start_of_contents = CreateVisiblePosition(start);
  if (!target_blockquote) {
    // Create a new blockquote and insert it as a child of the root editable
    // element. We accomplish this by splitting all parents of the current
    // paragraph up to that point.
    target_blockquote = CreateBlockElement();
    if (outer_block == start.ComputeContainerNode()) {
      if (outer_block->HasTagName(html_names::kBlockquoteTag)) {
        if (RuntimeEnabledFeatures::InsertBlockquoteBeforeOuterBlockEnabled()) {
          // Insert `target_blockquote` before `outer_block` so that
          // `start_of_contents` includes the start of deletion. See
          // https://crbug.com/327665597 for more details.
          InsertNodeBefore(target_blockquote, outer_block, editing_state);
        } else {
          // When we apply indent to an empty <blockquote>, we should call
          // InsertNodeAfter(). See http://crbug.com/625802 for more details.
          InsertNodeAfter(target_blockquote, outer_block, editing_state);
        }
      } else {
        InsertNodeAt(target_blockquote, start, editing_state);
      }
    } else
      InsertNodeBefore(target_blockquote, outer_block, editing_state);
    if (editing_state->IsAborted())
      return;
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
    start_of_contents = VisiblePosition::InParentAfterNode(*target_blockquote);
  }

  VisiblePosition end_of_contents = CreateVisiblePosition(end);
  if (start_of_contents.IsNull() || end_of_contents.IsNull())
    return;
  MoveParagraphWithClones(start_of_contents, end_of_contents, target_blockquote,
                          outer_block, editing_state);
}

void IndentOutdentCommand::OutdentParagraph(EditingState* editing_state) {
  VisiblePosition visible_start_of_paragraph =
      StartOfParagraph(EndingVisibleSelection().VisibleStart());
  VisiblePosition visible_end_of_paragraph =
      EndOfParagraph(visible_start_of_paragraph);

  auto* enclosing_element = To<HTMLElement>(
      EnclosingNodeOfType(visible_start_of_paragraph.DeepEquivalent(),
                          &IsHTMLListOrBlockquoteElement));
  // We can't outdent if there is no place to go!
  if (!enclosing_element || !IsEditable(*enclosing_element->parentNode()))
    return;

  // Use InsertListCommand to remove the selection from the list
  if (IsA<HTMLOListElement>(*enclosing_element)) {
    ApplyCommandToComposite(MakeGarbageCollected<InsertListCommand>(
                                GetDocument(), InsertListCommand::kOrderedList),
                            editing_state);
    return;
  }
  if (IsA<HTMLUListElement>(*enclosing_element)) {
    ApplyCommandToComposite(
        MakeGarbageCollected<InsertListCommand>(
            GetDocument(), InsertListCommand::kUnorderedList),
        editing_state);
    return;
  }

  // The selection is inside a blockquote i.e. enclosingNode is a blockquote
  VisiblePosition position_in_enclosing_block =
      VisiblePosition::FirstPositionInNode(*enclosing_element);
  // If the blockquote is inline, the start of the enclosing block coincides
  // with positionInEnclosingBlock.
  VisiblePosition start_of_enclosing_block =
      (enclosing_element->GetLayoutObject() &&
       enclosing_element->GetLayoutObject()->IsInline())
          ? position_in_enclosing_block
          : StartOfBlock(position_in_enclosing_block);
  VisiblePosition last_position_in_enclosing_block =
      VisiblePosition::LastPositionInNode(*enclosing_element);
  VisiblePosition end_of_enclosing_block =
      EndOfBlock(last_position_in_enclosing_block);
  RelocatablePosition* start_of_paragraph =
      MakeGarbageCollected<RelocatablePosition>(
          visible_start_of_paragraph.DeepEquivalent());
  RelocatablePosition* end_of_paragraph =
      MakeGarbageCollected<RelocatablePosition>(
          visible_end_of_paragraph.DeepEquivalent());
  if (visible_start_of_paragraph.DeepEquivalent() ==
          start_of_enclosing_block.DeepEquivalent() &&
      visible_end_of_paragraph.DeepEquivalent() ==
          end_of_enclosing_block.DeepEquivalent()) {
    // The blockquote doesn't contain anything outside the paragraph, so it can
    // be totally removed.
    // This procedure will make {start,end}_of_paragraph out of sync if the
    // blockquote has children, so store the first and last children.
    Node* first_child = enclosing_element->firstChild();
    Node* last_child = enclosing_element->lastChild();
    Node* split_point = enclosing_element->nextSibling();
    RemoveNodePreservingChildren(enclosing_element, editing_state);
    if (editing_state->IsAborted())
      return;
    // outdentRegion() assumes it is operating on the first paragraph of an
    // enclosing blockquote, but if there are multiply nested blockquotes and
    // we've just removed one, then this assumption isn't true. By splitting the
    // next containing blockquote after this node, we keep this assumption true
    if (split_point) {
      if (Element* split_point_parent = split_point->parentElement()) {
        // We can't outdent if there is no place to go!
        if (split_point_parent->HasTagName(html_names::kBlockquoteTag) &&
            !split_point->HasTagName(html_names::kBlockquoteTag) &&
            IsEditable(*split_point_parent->parentNode()))
          SplitElement(split_point_parent, split_point);
      }
    }

    // Re-canonicalize visible_start_of_paragraph, make it valid again after DOM
    // change. If enclosing_element had children, start_of_paragraph will be out
    // of sync, so use first_child instead.
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
    DCHECK(!first_child || first_child->isConnected());
    visible_start_of_paragraph =
        CreateVisiblePosition(first_child ? Position::BeforeNode(*first_child)
                                          : start_of_paragraph->GetPosition());
    if (visible_start_of_paragraph.IsNotNull() &&
        !IsStartOfParagraph(visible_start_of_paragraph)) {
      InsertNodeAt(MakeGarbageCollected<HTMLBRElement>(GetDocument()),
                   visible_start_of_paragraph.DeepEquivalent(), editing_state);
      if (editing_state->IsAborted())
        return;
    }

    // Re-canonicalize visible_end_of_paragraph, make it valid again after DOM
    // change. If enclosing_element had children, end_of_paragraph will be out
    // of sync, so use last_child instead.
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
    DCHECK(!last_child || last_child->isConnected());
    visible_end_of_paragraph =
        CreateVisiblePosition(last_child ? Position::AfterNode(*last_child)
                                         : end_of_paragraph->GetPosition());
    // Insert BR after the old paragraph end if it got merged into the next
    // paragraph. This happens if the original paragraph end is no longer a
    // paragraph end, or if it is followed by a BR.
    // TODO(editing-dev): This doesn't work if there is other unrendered nodes
    // (e.g., comments) between the old paragraph end and the BR.
    const bool should_insert_br =
        (visible_end_of_paragraph.IsNotNull() &&
         !IsEndOfParagraph(visible_end_of_paragraph)) ||
        IsA<HTMLBRElement>(split_point);
    if (should_insert_br) {
      InsertNodeAt(MakeGarbageCollected<HTMLBRElement>(GetDocument()),
                   visible_end_of_paragraph.DeepEquivalent(), editing_state);
    }
    return;
  }

  Node* split_blockquote_node = enclosing_element;
  if (Element* enclosing_block_flow = EnclosingBlock(
          visible_start_of_paragraph.DeepEquivalent().AnchorNode())) {
    if (enclosing_block_flow != enclosing_element) {
      // We should check if the blockquotes are nested, as nested blockquotes
      // may be at different indentations.
      const Position& previous_element =
          PreviousCandidate(visible_start_of_paragraph.DeepEquivalent());
      auto* const previous_element_is_blockquote =
          To<HTMLElement>(EnclosingNodeOfType(previous_element,
                                              &IsHTMLListOrBlockquoteElement));
      const bool is_previous_blockquote_same =
          !previous_element_is_blockquote ||
          (enclosing_element == previous_element_is_blockquote);
      const bool split_ancestor = true;
      if (is_previous_blockquote_same) {
        split_blockquote_node = SplitTreeToNode(
            enclosing_block_flow, enclosing_element, split_ancestor);
      } else {
        SplitTreeToNode(
            visible_start_of_paragraph.DeepEquivalent().AnchorNode(),
            enclosing_element, split_ancestor);
      }
    } else {
      if (RuntimeEnabledFeatures::NonEmptyBlockquotesOnOutdentingEnabled()) {
        // Insert BR after the previous sibling of `enclosing_element` if the
        // LayoutObject of sibling is 'inline-level' and it gets merged into the
        // splitted element below.
        if (enclosing_element->HasPreviousSibling()) {
          Node* previous_sibling = enclosing_element->previousSibling();
          if (IsInlineNode(previous_sibling) &&
              !IsA<HTMLBRElement>(previous_sibling)) {
            InsertNodeAt(MakeGarbageCollected<HTMLBRElement>(GetDocument()),
                         Position::AfterNode(*previous_sibling), editing_state);
          }
        }
      }
      // We split the blockquote at where we start outdenting.
      Node* highest_inline_node = HighestEnclosingNodeOfType(
          visible_start_of_paragraph.DeepEquivalent(), IsInlineElement,
          kCannotCrossEditingBoundary, enclosing_block_flow);
      SplitElement(
          enclosing_element,
          highest_inline_node
              ? highest_inline_node
              : visible_start_of_paragraph.DeepEquivalent().AnchorNode());
    }

    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

    // Re-canonicalize visible_{start,end}_of_paragraph, make them valid again
    // after DOM change.
    visible_start_of_paragraph =
        CreateVisiblePosition(start_of_paragraph->GetPosition());
    visible_end_of_paragraph =
        CreateVisiblePosition(end_of_paragraph->GetPosition());
  }

  VisiblePosition visible_start_of_paragraph_to_move =
      StartOfParagraph(visible_start_of_paragraph);
  VisiblePosition visible_end_of_paragraph_to_move =
      EndOfParagraph(visible_end_of_paragraph);
  if (visible_start_of_paragraph_to_move.IsNull() ||
      visible_end_of_paragraph_to_move.IsNull())
    return;
  RelocatablePosition* start_of_paragraph_to_move =
      MakeGarbageCollected<RelocatablePosition>(
          visible_start_of_paragraph_to_move.DeepEquivalent());
  RelocatablePosition* end_of_paragraph_to_move =
      MakeGarbageCollected<RelocatablePosition>(
          visible_end_of_paragraph_to_move.DeepEquivalent());
  auto* placeholder = MakeGarbageCollected<HTMLBRElement>(GetDocument());
  InsertNodeBefore(placeholder, split_blockquote_node, editing_state);
  if (editing_state->IsAborted())
    return;

  // Re-canonicalize visible_{start,end}_of_paragraph_to_move, make them valid
  // again after DOM change.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  visible_start_of_paragraph_to_move =
      CreateVisiblePosition(start_of_paragraph_to_move->GetPosition());
  visible_end_of_paragraph_to_move =
      CreateVisiblePosition(end_of_paragraph_to_move->GetPosition());
  MoveParagraph(visible_start_of_paragraph_to_move,
                visible_end_of_paragraph_to_move,
                VisiblePosition::BeforeNode(*placeholder), editing_state,
                kPreserveSelection);
}

// FIXME: We should merge this function with
// ApplyBlockElementCommand::formatSelection
void IndentOutdentCommand::OutdentRegion(
    const VisiblePosition& start_of_selection,
    const VisiblePosition& end_of_selection,
    EditingState* editing_state) {
  VisiblePosition end_of_current_paragraph = EndOfParagraph(start_of_selection);
  VisiblePosition end_of_last_paragraph = EndOfParagraph(end_of_selection);

  if (end_of_current_paragraph.DeepEquivalent() ==
      end_of_last_paragraph.DeepEquivalent()) {
    OutdentParagraph(editing_state);
    return;
  }

  Position original_selection_end = EndingVisibleSelection().End();
  Position end_after_selection =
      EndOfParagraph(NextPositionOf(end_of_last_paragraph)).DeepEquivalent();

  while (!end_of_current_paragraph.IsNull() &&
         end_of_current_paragraph.DeepEquivalent() != end_after_selection) {
    PositionWithAffinity end_of_next_paragraph =
        EndOfParagraph(NextPositionOf(end_of_current_paragraph))
            .ToPositionWithAffinity();
    if (end_of_current_paragraph.DeepEquivalent() ==
        end_of_last_paragraph.DeepEquivalent()) {
      SelectionInDOMTree::Builder builder;
      if (original_selection_end.IsNotNull())
        builder.Collapse(original_selection_end);
      SetEndingSelection(SelectionForUndoStep::From(builder.Build()));
    } else {
      SetEndingSelection(SelectionForUndoStep::From(
          SelectionInDOMTree::Builder()
              .Collapse(end_of_current_paragraph.DeepEquivalent())
              .Build()));
    }

    OutdentParagraph(editing_state);
    if (editing_state->IsAborted())
      return;

    // outdentParagraph could move more than one paragraph if the paragraph
    // is in a list item. As a result, endAfterSelection and endOfNextParagraph
    // could refer to positions no longer in the document.
    if (end_after_selection.IsNotNull() && !end_after_selection.IsConnected())
      break;

    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
    if (end_of_next_paragraph.IsNotNull() &&
        !end_of_next_paragraph.IsConnected()) {
      if (RuntimeEnabledFeatures::MoveEndingSelectionToListChildEnabled()) {
        // If the end of the current selection is in a list item, set the
        // selection to the last position in the list item since
        // OutdentParagraph() moves all children in a list item at once using
        // InsertListCommand.
        SetEndingSelectionToListChildIfListItem();
      }
      end_of_current_paragraph =
          CreateVisiblePosition(EndingVisibleSelection().End());
      end_of_next_paragraph =
          EndOfParagraph(NextPositionOf(end_of_current_paragraph))
              .ToPositionWithAffinity();
    }
    end_of_current_paragraph = CreateVisiblePosition(end_of_next_paragraph);
  }
}

void IndentOutdentCommand::SetEndingSelectionToListChildIfListItem() {
  Node* selection_node = EndingVisibleSelection().Start().AnchorNode();
  Node* list_child_node = EnclosingListChild(selection_node);
  if (list_child_node && IsA<HTMLLIElement>(*list_child_node)) {
    SetEndingSelection(SelectionForUndoStep::From(
        SelectionInDOMTree::Builder()
            .Collapse(Position::LastPositionInNode(*list_child_node))
            .Build()));
  }
}

void IndentOutdentCommand::FormatSelection(
    const VisiblePosition& start_of_selection,
    const VisiblePosition& end_of_selection,
    EditingState* editing_state) {
  if (type_of_action_ == kIndent)
    ApplyBlockElementCommand::FormatSelection(start_of_selection,
                                              end_of_selection, editing_state);
  else
    OutdentRegion(start_of_selection, end_of_selection, editing_state);
}

void IndentOutdentCommand::FormatRange(
    const Position& start,
    const Position& end,
    const Position&,
    HTMLElement*& blockquote_for_next_indent,
    VisiblePosition& out_end_of_next_of_paragraph_to_move,
    EditingState* editing_state) {
  bool indenting_as_list_item_result = TryIndentingAsListItem(
      start, end, out_end_of_next_of_paragraph_to_move, editing_state);
  if (editing_state->IsAborted())
    return;
  if (indenting_as_list_item_result)
    blockquote_for_next_indent = nullptr;
  else
    IndentIntoBlockquote(start, end, blockquote_for_next_indent, editing_state);
}

InputEvent::InputType IndentOutdentCommand::GetInputType() const {
  return type_of_action_ == kIndent ? InputEvent::InputType::kFormatIndent
                                    : InputEvent::InputType::kFormatOutdent;
}

}  // namespace blink

"""

```