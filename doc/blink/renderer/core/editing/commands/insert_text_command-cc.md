Response:
Let's break down the thought process for analyzing the `InsertTextCommand.cc` file.

**1. Understanding the Goal:**

The core request is to understand the *functionality* of this C++ file within the Chromium/Blink rendering engine. This involves identifying its purpose, its interactions with other parts of the system (like JavaScript, HTML, CSS), potential issues (like user errors), and how a user's action leads to this code being executed.

**2. Initial Scan and Key Terms:**

The first step is to quickly read through the code, looking for keywords and recognizable patterns. I'd be looking for:

* **Class name:** `InsertTextCommand` - immediately suggests this is about inserting text.
* **Inheritance:** `CompositeEditCommand` - indicates this is part of a larger editing command system.
* **Members:** `text_`, `rebalance_type_` - these are important data the command operates on.
* **Methods:** `DoApply`, `InsertTab`, `PerformTrivialReplace`, `PositionInsideTextNode`, etc. - these are the core actions.
* **Included headers:** `Document.h`, `Element.h`, `Text.h`, `editing/...` - these point to the areas of Blink the command interacts with (DOM manipulation, editing functionalities).
* **Namespace:** `blink` - confirms this is within the Blink rendering engine.
* **Copyright notice:**  Confirms the origin and licensing.

**3. Deeper Dive into Core Functionality (`DoApply`):**

The `DoApply` method is usually the heart of a command in this structure. I'd analyze it step by step:

* **Input Validation:** Checks for `IsNone()` or `!IsValidFor(GetDocument())` – essential for robustness.
* **Deletion of Existing Selection:** Handles the case where text is being inserted over a selection. It considers a "trivial replace" for simple cases and a more complex `DeleteSelection` for others. The comment about "blowing away the typing style" is a key detail.
* **Placeholder Handling:**  `ComputePlaceholderToCollapseAt` and `RemovePlaceholderAt` suggests the code interacts with placeholder elements.
* **Caret Positioning:** `MostBackwardCaretPosition`, `MostForwardCaretPosition`, `DeleteInsignificantText` reveal the logic for finding the correct insertion point, handling whitespace.
* **Whitespace Rebalancing:** The `RebalanceWhitespaceAt` and `RebalanceWhitespaceOnTextSubstring` functions are significant, indicating an awareness of whitespace normalization rules.
* **Insertion Logic:**  The `InsertTab` method is a special case. The standard text insertion uses `PositionInsideTextNode` to ensure a valid text node exists, and then `InsertTextIntoNode`.
* **Styling:**  The code interacts with `TypingStyle` and `ApplyStyle`, demonstrating how formatting is preserved or applied during insertion.
* **Ending Selection:**  The command updates the selection after the insertion.

**4. Identifying Relationships with Web Technologies:**

Now, connect the C++ logic to the user-facing web:

* **JavaScript:**  The act of typing or pasting text triggers JavaScript events (`keydown`, `keypress`, `textInput`, `paste`). These events can be intercepted by JavaScript code to modify behavior or prevent default actions. The `InsertTextCommand` is what *implements* the default text insertion behavior.
* **HTML:** The command directly manipulates the DOM (Document Object Model), which is the tree-like representation of the HTML structure. It creates and modifies `Text` nodes and potentially `HTMLSpanElement` for tabs.
* **CSS:**  The `TypingStyle` and `ApplyStyle` methods show how CSS styles are applied during text insertion. This includes inline styles and styles inherited from stylesheets. The whitespace rebalancing also has implications for how text is rendered according to CSS whitespace rules.

**5. Inferring Logic and Examples:**

Based on the code and the understanding of its purpose, formulate hypothetical inputs and outputs. For example:

* **Simple Text Insertion:** Typing "a" in an empty `<p>` element should result in a `Text` node containing "a" being inserted into the `<p>`.
* **Replacing Selection:** Selecting text and typing "b" should delete the selection and insert "b".
* **Tab Insertion:** Pressing the Tab key should insert a `<span class="tab-stop">` element.

**6. Identifying Potential Errors and Debugging:**

Consider scenarios where things might go wrong:

* **Inserting into Non-Text Nodes:** The `PositionInsideTextNode` function addresses this. If the insertion point isn't a text node, it creates one. A user error could be trying to insert text into a read-only element or a location where text insertion is not permitted.
* **Whitespace Issues:** The whitespace rebalancing is complex. Errors could arise if the rebalancing logic is flawed or doesn't cover all edge cases, leading to unexpected whitespace behavior.
* **Styling Conflicts:**  Applying styles during insertion can sometimes lead to unexpected results if the typing style conflicts with existing styles.

**7. Tracing User Actions:**

Think about the sequence of events that lead to the `InsertTextCommand` being executed. Typing is the most obvious one. Pasting is another. Using contenteditable attributes and programmatically manipulating the DOM via JavaScript can also lead to this code.

**8. Structuring the Answer:**

Finally, organize the information in a clear and structured way, using headings and bullet points. Start with a high-level summary of the file's purpose, then delve into specifics like interactions with web technologies, logical deductions, potential errors, and debugging steps. Use concrete examples to illustrate the concepts.

**Self-Correction/Refinement:**

During the process, I'd constantly review my understanding. If a piece of code doesn't make sense, I'd go back and re-examine it or look up related documentation. For instance, if I wasn't familiar with the concept of "whitespace rebalancing," I'd research that. Similarly, understanding the role of `EditingState` and `RelocatablePosition` would require further investigation if their purpose wasn't immediately clear.
好的，让我们来详细分析一下 `blink/renderer/core/editing/commands/insert_text_command.cc` 这个文件。

**功能概述:**

`InsertTextCommand` 类的主要功能是在 Blink 渲染引擎中实现文本的插入操作。当用户在可编辑的网页内容中输入文本时（例如，在 `<textarea>`、`contenteditable` 元素中），或者通过 JavaScript 代码进行文本插入操作时，这个类会被用来执行实际的插入逻辑。

**核心功能点:**

1. **处理不同类型的插入:**
   - 它可以处理普通文本的插入。
   - 它也处理制表符 (`\t`) 的插入，这在富文本编辑器中通常会创建特殊的制表符元素 (`<span class="tab-stop">`)。

2. **处理选区:**
   - 如果当前有选中的文本，`InsertTextCommand` 会先删除选中的文本，然后再插入新的文本。
   - 它会更新文档的选区，以便在插入操作完成后，光标位于新插入文本的末尾。

3. **Whitespace (空白字符) 处理:**
   - 文件中包含了 `RebalanceWhitespaceAt` 和 `RebalanceWhitespaceOnTextSubstring` 等函数，表明它会处理插入文本前后以及内部的空白字符，以确保文档的排版和渲染符合预期。这包括合并或调整相邻的空格、制表符和换行符。

4. **处理富文本编辑特性:**
   - 它会考虑当前的编辑样式 (Typing Style)，例如字体、颜色、粗体等，并将这些样式应用到新插入的文本上。
   - 对于制表符的插入，它会创建特定的 HTML 结构 (`<span class="tab-stop">`)，这与富文本编辑器的行为一致。

5. **优化插入操作:**
   - `PerformTrivialReplace` 函数尝试优化简单的替换操作，避免执行完整的删除和插入流程，提高性能。

6. **处理插入位置:**
   - `PositionInsideTextNode` 函数确保插入操作发生在文本节点内部。如果插入位置不是文本节点，它会创建一个新的文本节点。

7. **维护编辑历史 (Undo/Redo):**
   - 作为 `CompositeEditCommand` 的子类，`InsertTextCommand` 的操作可以被记录下来，以便支持撤销和重做功能。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

1. **JavaScript:**
   - **触发:** 当 JavaScript 代码使用 `document.execCommand('insertText', false, 'your text')` 或者通过修改 `textContent` 或 `innerHTML` 等属性来插入文本时，最终会触发 Blink 引擎内部的文本插入逻辑，`InsertTextCommand` 可能会被调用。
   - **示例:**
     ```javascript
     document.getElementById('editableDiv').addEventListener('input', function(event) {
       console.log('用户输入了:', event.data); // event.data 包含用户输入的文本
       // Blink 引擎会处理这个输入，最终可能调用 InsertTextCommand
     });

     // 或者通过 execCommand
     document.execCommand('insertText', false, 'Hello from JS!');
     ```

2. **HTML:**
   - **目标:** `InsertTextCommand` 操作的是 HTML 文档的 DOM 结构。它会在文本节点中插入或修改文本内容，或者创建新的 HTML 元素（如制表符的 `<span>` 元素）。
   - **上下文:** 只有在可编辑的 HTML 元素（如 `<textarea>` 或设置了 `contenteditable` 属性的元素）中进行文本插入操作时，`InsertTextCommand` 才会被激活。
   - **示例:**
     ```html
     <div id="editableDiv" contenteditable="true">这是一段可编辑的文本。</div>
     <textarea id="myTextArea"></textarea>
     ```
     当用户在上面的 `div` 或 `textarea` 中输入文本时，`InsertTextCommand` 会处理这些输入。

3. **CSS:**
   - **样式应用:** `InsertTextCommand` 在插入文本时会考虑当前的 CSS 样式。`TypingStyle` 会存储当前编辑位置的样式信息，并将其应用到新插入的文本上。
   - **空白符渲染:**  `InsertTextCommand` 对空白字符的处理也会影响最终的渲染结果。CSS 的 `white-space` 属性会决定如何渲染空格、制表符和换行符。
   - **示例:**
     ```html
     <style>
       #styledDiv {
         font-weight: bold;
         color: blue;
         white-space: pre-wrap; /* 保留空格和换行 */
       }
     </style>
     <div id="styledDiv" contenteditable="true"></div>
     ```
     如果在 `styledDiv` 中输入文本，`InsertTextCommand` 会尝试保留 `font-weight` 和 `color` 样式，并且由于 `white-space: pre-wrap;` 的设置，插入的空格和换行符会被保留。

**逻辑推理 (假设输入与输出):**

**假设输入 1:**
- 用户在一个空的 `<p contenteditable="true"></p>` 元素中输入字母 "a"。
- `EndingVisibleSelection()` 返回的选区是空的，位于 `<p>` 元素的起始位置。
- `text_` 成员变量的值为 "a"。

**输出 1:**
- `<p contenteditable="true">a</p>`
- 用户的光标位于 "a" 后面。
- `EndingSelection()` 会更新为指向新插入的文本 "a" 的末尾。

**假设输入 2:**
- 用户选中了 `<p contenteditable="true">old text</p>` 中的 "old "。
- 用户输入字母 "n"。
- `EndingVisibleSelection()` 返回的选区覆盖了 "old "。
- `text_` 成员变量的值为 "n"。

**输出 2:**
- `<p contenteditable="true">new text</p>`
- 用户的光标位于 "n" 后面。
- `EndingSelection()` 会更新为指向新插入的文本 "n" 的末尾。

**假设输入 3:**
- 用户在一个 `<div contenteditable="true"></div>` 元素中按下 Tab 键。
- `EndingVisibleSelection()` 返回的选区位于 `<div>` 元素的起始位置。
- `text_` 成员变量的值为 "\t"。

**输出 3:**
- `<div contenteditable="true"><span class="tab-stop">\t</span></div>` (具体的 HTML 结构可能略有不同，但会包含表示制表符的元素)
- 用户的光标位于制表符元素之后。

**用户或编程常见的使用错误及举例说明:**

1. **尝试在非可编辑区域插入文本:**
   - **用户操作:** 用户尝试在一个没有设置 `contenteditable` 属性的 `<div>` 或其他元素中输入文本。
   - **结果:** `InsertTextCommand` 不会被调用，或者即使被调用也会因为检查到目标位置不可编辑而提前返回，文本不会被插入。
   - **调试线索:** 检查事件监听器是否正确绑定到可编辑元素，以及目标元素是否具有 `contenteditable="true"` 属性。

2. **JavaScript 代码错误地传递参数:**
   - **编程错误:** JavaScript 代码在使用 `document.execCommand('insertText', ...)` 时，可能传递了错误的参数类型或值。
   - **结果:** `InsertTextCommand` 可能会收到意料之外的输入，导致插入行为异常或失败。
   - **调试线索:** 检查 `document.execCommand` 的调用参数是否正确，特别是第三个参数（要插入的文本）。

3. **富文本编辑器逻辑错误导致插入位置不正确:**
   - **用户操作:** 在复杂的富文本编辑器中，由于 JavaScript 代码处理光标位置或选区的逻辑错误，可能导致 `InsertTextCommand` 在错误的位置执行插入。
   - **结果:** 文本被插入到用户不期望的地方。
   - **调试线索:** 需要检查富文本编辑器的 JavaScript 代码中关于光标和选区管理的逻辑，以及在调用 `execCommand` 或修改 DOM 之前的准备工作。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在可编辑元素中获取焦点:** 用户点击或使用 Tab 键将焦点移动到一个设置了 `contenteditable="true"` 属性的 HTML 元素，或者一个 `<textarea>` 元素。

2. **用户触发文本输入事件:**
   - **键盘输入:** 用户按下键盘上的字符键（字母、数字、符号等）。这会触发 `keypress`, `textInput`, 和 `input` 等 DOM 事件。
   - **粘贴操作:** 用户使用 Ctrl+V 或鼠标右键粘贴文本。这会触发 `paste` 事件。
   - **输入法输入:** 用户使用输入法输入中文或其他非拉丁字符时，输入法的选择过程也会触发相应的事件。

3. **浏览器事件处理:** 浏览器接收到这些事件后，会进行一系列处理，包括：
   - **preventDefault() 判断:** 如果有 JavaScript 代码调用了 `event.preventDefault()` 阻止了默认行为，那么文本插入可能不会发生。
   - **`document.execCommand` 调用 (可选):**  如果 JavaScript 代码拦截了输入事件并调用了 `document.execCommand('insertText', ...)`，浏览器会执行相应的命令。

4. **Blink 引擎接收指令:**  无论是默认的文本输入行为还是 `execCommand` 的调用，Blink 渲染引擎会接收到插入文本的指令。

5. **创建 `InsertTextCommand` 对象:** Blink 引擎会创建一个 `InsertTextCommand` 对象，并将要插入的文本以及相关的上下文信息传递给它。

6. **执行 `DoApply` 方法:** `InsertTextCommand` 对象的 `DoApply` 方法会被调用，这是实际执行插入操作的地方，包括处理选区、插入文本、处理空白符、应用样式等。

7. **更新 DOM 和选区:** `DoApply` 方法会修改 DOM 树，将文本插入到正确的位置，并更新文档的选区，使得光标位于插入文本的末尾。

8. **触发后续渲染:**  DOM 的修改会触发浏览器的重新渲染流程，用户最终看到插入的文本。

**调试线索:**

- **事件监听器:** 检查是否有 JavaScript 代码监听了相关的键盘或粘贴事件，并可能阻止了默认行为。
- **`contenteditable` 属性:** 确认目标元素是否设置了 `contenteditable="true"` 或是一个 `<textarea>` 元素。
- **`document.execCommand` 调用:** 检查 JavaScript 代码中是否有 `document.execCommand('insertText', ...)` 的调用，并检查其参数。
- **断点调试:** 在 `blink/renderer/core/editing/commands/insert_text_command.cc` 文件的 `DoApply` 方法入口处设置断点，可以跟踪文本插入的具体执行过程，查看当前的选区状态、要插入的文本内容等。
- **日志输出:** 在 `InsertTextCommand` 的关键步骤添加日志输出，可以帮助理解代码的执行流程。
- **DOM 观察:** 使用浏览器的开发者工具观察 DOM 树的变化，可以确认文本是否被正确插入到预期的位置。

希望以上详细的分析能够帮助你理解 `InsertTextCommand.cc` 文件的功能和作用。

Prompt: 
```
这是目录为blink/renderer/core/editing/commands/insert_text_command.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2005 Apple Computer, Inc.  All rights reserved.
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

#include "third_party/blink/renderer/core/editing/commands/insert_text_command.h"

#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/commands/delete_selection_options.h"
#include "third_party/blink/renderer/core/editing/commands/editing_commands_utilities.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/relocatable_position.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"

namespace blink {

InsertTextCommand::InsertTextCommand(Document& document,
                                     const String& text,
                                     RebalanceType rebalance_type)
    : CompositeEditCommand(document),
      text_(text),
      rebalance_type_(rebalance_type) {}

String InsertTextCommand::TextDataForInputEvent() const {
  return text_;
}

Position InsertTextCommand::PositionInsideTextNode(
    const Position& p,
    EditingState* editing_state) {
  Position pos = p;
  if (IsTabHTMLSpanElementTextNode(pos.AnchorNode())) {
    Text* text_node = GetDocument().CreateEditingTextNode("");
    InsertNodeAtTabSpanPosition(text_node, pos, editing_state);
    if (editing_state->IsAborted())
      return Position();
    return Position::FirstPositionInNode(*text_node);
  }

  // Prepare for text input by looking at the specified position.
  // It may be necessary to insert a text node to receive characters.
  if (!pos.ComputeContainerNode()->IsTextNode()) {
    Text* text_node = GetDocument().CreateEditingTextNode("");
    InsertNodeAt(text_node, pos, editing_state);
    if (editing_state->IsAborted())
      return Position();
    return Position::FirstPositionInNode(*text_node);
  }

  return pos;
}

void InsertTextCommand::SetEndingSelectionWithoutValidation(
    const Position& start_position,
    const Position& end_position) {
  // We could have inserted a part of composed character sequence,
  // so we are basically treating ending selection as a range to avoid
  // validation. <http://bugs.webkit.org/show_bug.cgi?id=15781>
  SetEndingSelection(SelectionForUndoStep::From(
      SelectionInDOMTree::Builder()
          .Collapse(start_position)
          .Extend(end_position)
          .Build()));
}

// This avoids the expense of a full fledged delete operation, and avoids a
// layout that typically results from text removal.
bool InsertTextCommand::PerformTrivialReplace(const String& text) {
  // We may need to manipulate neighboring whitespace if we're deleting text.
  // This case is tested in
  // InsertTextCommandTest_InsertEmptyTextAfterWhitespaceThatNeedsFixup.
  if (text.empty())
    return false;

  if (!EndingSelection().IsRange())
    return false;

  if (text.Contains('\t') || text.Contains(' ') || text.Contains('\n'))
    return false;

  // Also if the text is surrounded by a hyperlink and all the contents of the
  // link are selected, then we shouldn't be retaining the link with just one
  // character because the user wouldn't be able to edit the link if it has only
  // one character.
  Position start = EndingVisibleSelection().Start();
  Element* enclosing_anchor = EnclosingAnchorElement(start);
  if (enclosing_anchor && text.length() <= 1) {
    VisiblePosition first_in_anchor =
        VisiblePosition::FirstPositionInNode(*enclosing_anchor);
    VisiblePosition last_in_anchor =
        VisiblePosition::LastPositionInNode(*enclosing_anchor);
    Position end = EndingVisibleSelection().End();
    if (first_in_anchor.DeepEquivalent() == start &&
        last_in_anchor.DeepEquivalent() == end)
      return false;
  }

  RelocatablePosition* relocatable_start =
      MakeGarbageCollected<RelocatablePosition>(start);
  Position end_position = ReplaceSelectedTextInNode(text);
  if (end_position.IsNull())
    return false;

  SetEndingSelectionWithoutValidation(relocatable_start->GetPosition(),
                                      end_position);
  SetEndingSelection(SelectionForUndoStep::From(
      SelectionInDOMTree::Builder()
          .Collapse(EndingVisibleSelection().End())
          .Build()));
  return true;
}

void InsertTextCommand::DoApply(EditingState* editing_state) {
  DCHECK_EQ(text_.find('\n'), kNotFound);

  // TODO(editing-dev): We shouldn't construct an InsertTextCommand with none or
  // invalid selection.
  const VisibleSelection& visible_selection = EndingVisibleSelection();
  if (visible_selection.IsNone() ||
      !visible_selection.IsValidFor(GetDocument()))
    return;

  // Delete the current selection.
  // FIXME: This delete operation blows away the typing style.
  if (EndingSelection().IsRange()) {
    if (PerformTrivialReplace(text_))
      return;
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
    bool end_of_selection_was_at_start_of_block =
        IsStartOfBlock(EndingVisibleSelection().VisibleEnd());
    if (!DeleteSelection(editing_state, DeleteSelectionOptions::Builder()
                                            .SetMergeBlocksAfterDelete(true)
                                            .Build()))
      return;
    // deleteSelection eventually makes a new endingSelection out of a Position.
    // If that Position doesn't have a layoutObject (e.g. it is on a <frameset>
    // in the DOM), the VisibleSelection cannot be canonicalized to anything
    // other than NoSelection. The rest of this function requires a real
    // endingSelection, so bail out.
    if (EndingSelection().IsNone())
      return;
    if (end_of_selection_was_at_start_of_block) {
      if (EditingStyle* typing_style =
              GetDocument().GetFrame()->GetEditor().TypingStyle()) {
        typing_style->RemoveBlockProperties(
            GetDocument().GetExecutionContext());
      }
    }
  }

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  // Reached by InsertTextCommandTest.NoVisibleSelectionAfterDeletingSelection
  ABORT_EDITING_COMMAND_IF(EndingVisibleSelection().IsNone());

  Position start_position(EndingVisibleSelection().Start());

  Position placeholder = ComputePlaceholderToCollapseAt(start_position);

  // Insert the character at the leftmost candidate.
  start_position = MostBackwardCaretPosition(start_position);

  // It is possible for the node that contains startPosition to contain only
  // unrendered whitespace, and so deleteInsignificantText could remove it.
  // Save the position before the node in case that happens.
  DCHECK(start_position.ComputeContainerNode()) << start_position;
  Position position_before_start_node(
      Position::InParentBeforeNode(*start_position.ComputeContainerNode()));
  DeleteInsignificantText(start_position,
                          MostForwardCaretPosition(start_position));

  // TODO(editing-dev): Use of UpdateStyleAndLayout()
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  if (!start_position.IsConnected())
    start_position = position_before_start_node;
  if (!IsVisuallyEquivalentCandidate(start_position))
    start_position = MostForwardCaretPosition(start_position);

  start_position =
      PositionAvoidingSpecialElementBoundary(start_position, editing_state);
  if (editing_state->IsAborted())
    return;

  Position end_position;

  if (text_ == "\t" && IsRichlyEditablePosition(start_position)) {
    end_position = InsertTab(start_position, editing_state);
    if (editing_state->IsAborted())
      return;
    start_position =
        PreviousPositionOf(end_position, PositionMoveType::kGraphemeCluster);
    if (placeholder.IsNotNull())
      RemovePlaceholderAt(placeholder);
  } else {
    // Make sure the document is set up to receive text_
    start_position = PositionInsideTextNode(start_position, editing_state);
    if (editing_state->IsAborted())
      return;
    DCHECK(start_position.IsOffsetInAnchor()) << start_position;
    DCHECK(start_position.ComputeContainerNode()) << start_position;
    DCHECK(start_position.ComputeContainerNode()->IsTextNode())
        << start_position;
    if (placeholder.IsNotNull())
      RemovePlaceholderAt(placeholder);
    auto* text_node = To<Text>(start_position.ComputeContainerNode());
    const unsigned offset = start_position.OffsetInContainerNode();

    InsertTextIntoNode(text_node, offset, text_);
    end_position = Position(text_node, offset + text_.length());

    if (rebalance_type_ == kRebalanceLeadingAndTrailingWhitespaces) {
      // The insertion may require adjusting adjacent whitespace, if it is
      // present.
      RebalanceWhitespaceAt(end_position);
      // Rebalancing on both sides isn't necessary if we've inserted only
      // spaces.
      if (!text_.ContainsOnlyWhitespaceOrEmpty())
        RebalanceWhitespaceAt(start_position);
    } else {
      DCHECK_EQ(rebalance_type_, kRebalanceAllWhitespaces);
      if (CanRebalance(start_position) && CanRebalance(end_position))
        RebalanceWhitespaceOnTextSubstring(
            text_node, start_position.OffsetInContainerNode(),
            end_position.OffsetInContainerNode());
    }
  }

  SetEndingSelectionWithoutValidation(start_position, end_position);

  // Handle the case where there is a typing style.
  if (EditingStyle* typing_style =
          GetDocument().GetFrame()->GetEditor().TypingStyle()) {
    typing_style->PrepareToApplyAt(end_position,
                                   EditingStyle::kPreserveWritingDirection);
    if (!typing_style->IsEmpty() && !EndingSelection().IsNone()) {
      ApplyStyle(typing_style, editing_state);
      if (editing_state->IsAborted())
        return;
    }
  }

  SelectionInDOMTree::Builder builder;
  const VisibleSelection& selection = EndingVisibleSelection();
  builder.SetAffinity(selection.Affinity());
  if (selection.End().IsNotNull())
    builder.Collapse(selection.End());
  SetEndingSelection(SelectionForUndoStep::From(builder.Build()));
}

Position InsertTextCommand::InsertTab(const Position& pos,
                                      EditingState* editing_state) {
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  Position insert_pos = CreateVisiblePosition(pos).DeepEquivalent();
  if (insert_pos.IsNull())
    return pos;

  Node* node = insert_pos.ComputeContainerNode();
  auto* text_node = DynamicTo<Text>(node);
  unsigned offset = text_node ? insert_pos.OffsetInContainerNode() : 0;

  // keep tabs coalesced in tab span
  if (IsTabHTMLSpanElementTextNode(node)) {
    InsertTextIntoNode(text_node, offset, "\t");
    return Position(text_node, offset + 1);
  }

  // create new tab span
  HTMLSpanElement* span_element = CreateTabSpanElement(GetDocument());

  // place it
  if (!text_node) {
    InsertNodeAt(span_element, insert_pos, editing_state);
  } else {
    if (offset >= text_node->length()) {
      InsertNodeAfter(span_element, text_node, editing_state);
    } else {
      // split node to make room for the span
      // NOTE: splitTextNode uses textNode for the
      // second node in the split, so we need to
      // insert the span before it.
      if (offset > 0)
        SplitTextNode(text_node, offset);
      InsertNodeBefore(span_element, text_node, editing_state);
    }
  }
  if (editing_state->IsAborted())
    return Position();

  // return the position following the new tab
  return Position::LastPositionInNode(*span_element);
}

}  // namespace blink

"""

```