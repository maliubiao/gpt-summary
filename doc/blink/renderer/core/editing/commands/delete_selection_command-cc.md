Response:
My thinking process to analyze the `delete_selection_command.cc` code goes through several stages:

1. **Understanding the Core Task:** The filename itself, `delete_selection_command.cc`, immediately signals the primary function: handling the deletion of selected content within the Chromium Blink rendering engine. This is the central theme around which all other functionalities revolve.

2. **Identifying Key Data Structures and Concepts:** I scanned the included headers and the class definition to identify the important data structures and concepts involved:
    * `DeleteSelectionCommand`: The main class responsible for the deletion operation.
    * `DeleteSelectionOptions`:  Configuration options that modify the deletion behavior (e.g., smart delete, merge blocks).
    * `SelectionForUndoStep`: Represents the selected content before the deletion, used for undo functionality.
    * `Position`: Represents a point within the DOM tree, crucial for defining the start and end of the selection.
    * `VisiblePosition`: A position concept that takes layout into account, making it suitable for user-facing selection.
    * `EditingState`:  Manages the state during the editing operation, allowing for abortion if necessary.
    * `EditingStyle`:  Deals with the styling of the deleted content and what style should be applied after deletion.
    * DOM Node Types (e.g., `Text`, `Element`, `HTMLBRElement`, `HTMLTableElement`):  The fundamental building blocks of the web page, and the code interacts heavily with them.
    * The inclusion of `editing_commands_utilities.h`, `editing_boundary.h`, `editing_utilities.h`, etc., points to the broader editing framework this command belongs to.

3. **Deconstructing the `DeleteSelectionCommand` Class:** I examined the constructor and the key methods within the class, paying attention to their names and arguments:
    * **Constructors:**  One takes a `Document` and `DeleteSelectionOptions`, the other a `SelectionForUndoStep` and `DeleteSelectionOptions`. This suggests two ways to initiate the deletion: either based on the current document state or a previously recorded selection.
    * **`InitializeStartEnd()`:**  Determines the exact start and end positions of the selection to be deleted, handling special cases like `<hr>` elements.
    * **`SetStartingSelectionOnSmartDelete()`:** Modifies the selection for "smart delete," which intelligently includes surrounding whitespace.
    * **`InitializePositionData()`:** Populates various `Position` members (e.g., `upstream_start_`, `downstream_end_`) used throughout the deletion process. This method also identifies relevant block and table row elements.
    * **`SaveTypingStyleState()`:**  Captures the styling information before the deletion, important for maintaining consistent styling after deletion.
    * **`HandleSpecialCaseBRDelete()`:**  Deals with the specific case of deleting `<br>` elements.
    * **`RemoveNode()`:**  Removes a given DOM node from the tree, with special handling for table structures and root editable elements.
    * **`RemoveCompletelySelectedNodes()`:** Efficiently removes nodes that are fully contained within the selection.
    * **`DeleteTextFromNode()`:** Removes a range of text from a `Text` node.
    * **`MakeStylingElementsDirectChildrenOfEditableRootToPreventStyleLoss()`:**  Ensures that `<style>` and `<link>` elements are correctly handled during deletion to prevent style issues.
    * **`HandleGeneralDelete()`:** The core logic for handling most deletion scenarios.

4. **Identifying Relationships with Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:** The code directly manipulates HTML elements (`HTMLBRElement`, `HTMLTableElement`, etc.). The concept of "selection" itself is fundamental to interacting with HTML content.
    * **CSS:**  The `EditingStyle` class and methods like `SaveTypingStyleState()` clearly indicate an interaction with CSS. The goal is to preserve or adjust styling during and after the deletion.
    * **JavaScript:** While the C++ code doesn't directly execute JavaScript, it's part of the browser's rendering engine. User actions in the browser (often triggered by JavaScript events) can lead to the execution of this code. For instance, a JavaScript event listener for a "keydown" event might trigger the deletion command when the "Delete" or "Backspace" key is pressed.

5. **Inferring Logic and Potential User Errors:** I considered the potential inputs and outputs of the functions and thought about situations where things might go wrong:
    * **Input:** A user selecting text or placing a caret and pressing the "Delete" key.
    * **Output:** The selected text is removed from the DOM, and the cursor is placed at the appropriate location. Styling might be adjusted.
    * **User Errors:**
        * Selecting across non-editable boundaries: The code handles this by potentially not deleting content outside editable regions.
        * Unexpected styling changes after deletion: The `SaveTypingStyleState()` and related logic aim to prevent this, but complex styling scenarios could lead to issues.
        * Issues with placeholder elements in empty cells: The code tries to ensure placeholders are inserted correctly.

6. **Tracing User Actions:**  I imagined a user interacting with a web page and how their actions might lead to this specific code being executed:
    * **Selection:** The user clicks and drags the mouse to select text.
    * **Deletion:** The user presses the "Delete" or "Backspace" key.
    * **Event Handling:** The browser's event handling mechanism captures the key press.
    * **Command Execution:** The browser determines that a deletion command needs to be executed and instantiates `DeleteSelectionCommand`.

7. **Synthesizing the Information for the Summary:**  Finally, I organized the information gathered into a concise summary, highlighting the key functionalities and their relationships to web technologies, potential issues, and debugging hints. I focused on explaining *what* the code does at a high level, rather than getting bogged down in the low-level implementation details. The instruction to focus on the first part of the file helped in limiting the scope of the initial summary.

By following these steps, I could generate a comprehensive understanding of the `delete_selection_command.cc` file and its role within the Blink rendering engine.
好的，这是对 `blink/renderer/core/editing/commands/delete_selection_command.cc` 文件第一部分的分析和功能归纳：

**文件功能概述:**

`delete_selection_command.cc` 文件定义了 `DeleteSelectionCommand` 类，这个类负责实现删除用户在网页上选中的内容（selection）。它是一个编辑命令，属于 Chromium Blink 渲染引擎编辑模块的核心部分。  其主要目标是安全、正确地从 DOM 树中移除选定的节点和文本，并维护文档的结构和样式。

**核心功能点 (基于提供的第一部分代码):**

1. **初始化和准备删除:**
   - 接收 `Document` 对象、`DeleteSelectionOptions` (包含诸如是否合并删除后的块级元素等选项)、`InputEvent::InputType` (输入事件类型) 以及可选的参考移动位置。
   - 可以基于现有的 `SelectionForUndoStep` 对象进行初始化，用于支持撤销操作。
   - `InitializeStartEnd()` 方法用于确定要删除的选区的精确起始和结束位置，并处理一些特殊情况，例如选中 `<hr>` 元素时的边界调整。
   - 可以通过 `SetStartingSelectionOnSmartDelete()` 方法调整选区，用于实现“智能删除”功能 (smart delete)，例如删除单词时包含前后的空格。

2. **处理选区边界和特殊元素:**
   -  代码会处理选区边界，特别是当选区包含特殊的 HTML 元素时，例如 `<hr>`。
   -  `InitializeStartEnd()` 中有逻辑来扩展或调整选区，以完整包含某些特殊的 HTML 元素。

3. **识别和处理空白字符:**
   - `TrailingWhitespacePosition()` 和 `LeadingCollapsibleWhitespacePosition()` 函数用于识别选区前后可能需要处理的空白字符。这是智能删除功能的基础。

4. **初始化位置数据 (`InitializePositionData()`):**
   -  计算选区的上游和下游的起始和结束位置 (`upstream_start_`, `downstream_start_`, `upstream_end_`, `downstream_end_`)，这些位置是进行删除操作的关键参考点。
   -  确定起始和结束位置的根可编辑元素 (`start_root_`, `end_root_`)。
   -  识别起始和结束位置所在的表格行 (`start_table_row_`, `end_table_row_`)，用于处理表格相关的删除逻辑。
   -  判断是否需要在删除后合并块级元素 (`merge_blocks_after_delete_`)，并根据一些条件（例如选区跨越表格单元格）进行调整。
   -  确定删除操作完成后光标应该放置的位置 (`ending_position_`)。
   -  处理包含完整段落和换行符的选区，避免不必要的引用级别变化。

5. **智能删除逻辑:**
   -  如果启用了智能删除 (`options_.IsSmartDelete()`)，代码会检查选区前后是否存在空白字符。
   -  如果存在，并且满足条件（例如选区不以空白开头或结尾），则会扩展选区以包含这些空白字符。

6. **确定起始和结束块级元素:**
   -  识别选区起始和结束位置所在的块级元素 (`start_block_`, `end_block_`)。这对于后续处理块级元素的合并等操作至关重要。

7. **保存排版样式状态 (`SaveTypingStyleState()`):**
   -  在执行删除操作之前，保存选区起始位置的排版样式 (`typing_style_`)。这对于在删除后保持文本的样式一致性非常重要。
   -  特殊处理删除到 Mail blockquote 的情况，保存结束位置的样式。

8. **处理 `<br>` 元素的特殊情况 (`HandleSpecialCaseBRDelete()`):**
   -  检测并处理一些涉及 `<br>` 元素的特殊删除情况，例如删除单独一行的 `<br>` 元素。
   -  识别以 `<br>` 开始的空行。

9. **移除节点 (`RemoveNode()`):**
   -  提供一个通用的移除 DOM 节点的方法。
   -  会考虑节点的编辑状态，只移除可编辑区域内的节点。
   -  对于表格结构节点和根可编辑元素，不会直接移除，而是移除其内容。
   -  更新 `ending_position_`, `leading_whitespace_`, `trailing_whitespace_` 等位置信息，以反映节点移除后的状态。
   -  在移除节点前，会判断是否需要在删除后插入占位符 (`need_placeholder_`)。

10. **移除完全选中的节点 (`RemoveCompletelySelectedNodes()`):**
    -  高效地移除完全包含在选区内的节点。
    -  与 `RemoveNode()` 类似，也会考虑编辑状态和表格结构。
    -  同样会更新位置信息和判断是否需要占位符。

11. **从节点中删除文本 (`DeleteTextFromNode()`):**
    -  从 `Text` 类型的节点中删除指定范围的文本。
    -  同步更新相关的 `ending_position_`, `leading_whitespace_`, `trailing_whitespace_`, `downstream_end_` 等位置信息。

12. **将样式元素移动到可编辑根元素的直接子节点 (`MakeStylingElementsDirectChildrenOfEditableRootToPreventStyleLoss()`):**
    -  在删除操作前，将 `<style>` 和 `<link>` 等样式元素移动到可编辑根元素的直接子节点，以避免删除操作导致样式丢失。

**与 JavaScript, HTML, CSS 的关系:**

* **HTML:** 该代码直接操作 HTML 元素，例如 `<hr>`, `<br>`, `<table>`, `<tr>`, `<td>` 等。删除操作的最终结果是修改网页的 HTML 结构。
    * **举例:**  当用户选中一段包含 `<p>Hello <b>World</b></p>` 的文本并删除时，这段代码会识别出 `<p>`, `<b>` 元素以及文本节点 "Hello " 和 "World"，并将其从 DOM 树中移除。

* **CSS:**  `EditingStyle` 类以及保存和计算样式状态的逻辑，都与 CSS 有关。删除操作需要考虑样式继承和样式应用的问题，以保证删除后的内容样式正确。
    * **举例:** 如果用户在一个加粗的文本区域中删除一部分字符，代码会确保删除后光标所在位置的后续输入仍然保持加粗样式（如果适用）。

* **JavaScript:**  虽然这段 C++ 代码本身不包含 JavaScript，但它是浏览器渲染引擎的一部分，与 JavaScript 交互密切。用户的 JavaScript 代码可以触发编辑操作，例如通过 `document.execCommand('delete')` 或监听键盘事件来调用浏览器的删除功能，最终会执行到这里的代码。
    * **举例:**  一个富文本编辑器可能使用 JavaScript 监听用户的 `keydown` 事件，当用户按下 "Delete" 键时，JavaScript 会调用相应的浏览器 API，最终触发 `DeleteSelectionCommand` 的执行。

**逻辑推理示例:**

**假设输入:** 用户选中了以下 HTML 片段中的 "World"：

```html
<p>Hello <b>World</b>!</p>
```

**操作:** 用户按下 "Delete" 键。

**`DeleteSelectionCommand` 的处理流程 (简化):**

1. **`InitializeStartEnd()`:**  确定选区的起始位置在 "World" 的 "W" 之前，结束位置在 "d" 之后。
2. **`InitializePositionData()`:** 计算出 `upstream_start_`, `downstream_end_` 等位置信息，识别出包含选区的 `<b>` 元素和 `<p>` 元素。
3. **`HandleGeneralDelete()`:** 由于选区跨越了 `<b>` 元素的内容，代码会进入处理一般删除的逻辑。
4. **节点移除/文本删除:**  代码会判断如何移除 "World" 这个文本节点，可能会直接删除 `<b>` 元素及其子节点 "World"，或者先删除文本节点 "World"。
5. **结果:**  DOM 树更新为 `<p>Hello !</p>`，光标会位于 "Hello " 和 "!" 之间。

**用户或编程常见的使用错误:**

* **错误地处理非可编辑区域:**  如果 JavaScript 代码尝试删除用户无法编辑的区域（例如只读元素内的内容），`DeleteSelectionCommand` 可能会因为权限或逻辑判断而无法执行删除操作，或者只会删除可编辑部分。
    * **举例:**  一个 `readonly` 的 `<textarea>` 元素，用户选中其中的文本并按下 "Delete"，`DeleteSelectionCommand` 不会删除其中的内容。
* **在复杂的嵌套结构中删除可能导致意外结果:**  在复杂的 HTML 结构中（例如嵌套的表格或列表），删除操作的边界和后续元素的处理可能会比较复杂，开发者可能需要仔细测试以避免意外的布局或内容变化。
* **与自定义 JavaScript 编辑逻辑冲突:**  如果网页使用了自定义的 JavaScript 代码来处理编辑操作，这些代码可能与浏览器的默认行为冲突，导致 `DeleteSelectionCommand` 的执行结果不符合预期。

**用户操作到达此处的步骤 (调试线索):**

1. **用户在网页上进行选择:** 用户通过鼠标拖拽、双击或使用键盘快捷键（如 Shift + 方向键）在网页的可编辑区域选中了一段内容。
2. **用户触发删除操作:** 用户按下 "Delete" 或 "Backspace" 键。
3. **浏览器事件监听:** 浏览器捕获到键盘事件。
4. **命令执行:** 浏览器识别到这是一个删除选区的操作，并创建 `DeleteSelectionCommand` 对象。
5. **命令初始化:**  `DeleteSelectionCommand` 对象接收当前文档和选区信息。
6. **执行删除逻辑:**  `InitializeStartEnd()`, `InitializePositionData()`, `HandleGeneralDelete()` 等方法会被依次调用，执行具体的删除操作。

**总结 (针对第一部分):**

`delete_selection_command.cc` 的第一部分主要负责 **初始化和准备删除选区**。它定义了命令的构造方式，确定了要删除的精确范围，处理了选区边界的特殊情况（如 `<hr>`），识别了选区周围的空白字符，并初始化了后续删除操作所需的位置数据。 此外，它还包含了智能删除的初步逻辑以及保存排版样式状态的功能，为后续的实际删除操作奠定了基础。

### 提示词
```
这是目录为blink/renderer/core/editing/commands/delete_selection_command.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
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

#include "third_party/blink/renderer/core/editing/commands/delete_selection_command.h"

#include "base/ranges/algorithm.h"
#include "build/build_config.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/commands/editing_commands_utilities.h"
#include "third_party/blink/renderer/core/editing/editing_boundary.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/local_caret_rect.h"
#include "third_party/blink/renderer/core/editing/relocatable_position.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/html/html_hr_element.h"
#include "third_party/blink/renderer/core/html/html_link_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/html/html_table_element.h"
#include "third_party/blink/renderer/core/html/html_table_row_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

static bool IsTableCellEmpty(Node* cell) {
  DCHECK(cell);
  DCHECK(IsTableCell(cell)) << cell;
  return VisiblePosition::FirstPositionInNode(*cell).DeepEquivalent() ==
         VisiblePosition::LastPositionInNode(*cell).DeepEquivalent();
}

static bool IsTableRowEmpty(Node* row) {
  if (!IsA<HTMLTableRowElement>(row))
    return false;

  row->GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  for (Node* child = row->firstChild(); child; child = child->nextSibling()) {
    if (IsTableCell(child) && !IsTableCellEmpty(child))
      return false;
  }
  return true;
}

static bool CanMergeListElements(Element* first_list, Element* second_list) {
  if (!first_list || !second_list || first_list == second_list)
    return false;

  return CanMergeLists(*first_list, *second_list);
}

DeleteSelectionCommand::DeleteSelectionCommand(
    Document& document,
    const DeleteSelectionOptions& options,
    InputEvent::InputType input_type,
    const Position& reference_move_position)
    : CompositeEditCommand(document),
      options_(options),
      has_selection_to_delete_(false),
      merge_blocks_after_delete_(options.IsMergeBlocksAfterDelete()),
      input_type_(input_type),
      reference_move_position_(reference_move_position) {}

DeleteSelectionCommand::DeleteSelectionCommand(
    const SelectionForUndoStep& selection,
    const DeleteSelectionOptions& options,
    InputEvent::InputType input_type)
    : CompositeEditCommand(*selection.Anchor().GetDocument()),
      options_(options),
      has_selection_to_delete_(true),
      merge_blocks_after_delete_(options.IsMergeBlocksAfterDelete()),
      input_type_(input_type),
      selection_to_delete_(selection) {}

void DeleteSelectionCommand::InitializeStartEnd(Position& start,
                                                Position& end) {
  DCHECK(!GetDocument().NeedsLayoutTreeUpdate());
  DocumentLifecycle::DisallowTransitionScope disallow_transition(
      GetDocument().Lifecycle());

  HTMLElement* start_special_container = nullptr;
  HTMLElement* end_special_container = nullptr;

  start = selection_to_delete_.Start();
  end = selection_to_delete_.End();

  // For HRs, we'll get a position at (HR,1) when hitting delete from the
  // beginning of the previous line, or (HR,0) when forward deleting, but in
  // these cases, we want to delete it, so manually expand the selection
  if (IsA<HTMLHRElement>(*start.AnchorNode()))
    start = Position::BeforeNode(*start.AnchorNode());
  else if (IsA<HTMLHRElement>(*end.AnchorNode()))
    end = Position::AfterNode(*end.AnchorNode());

  // FIXME: This is only used so that moveParagraphs can avoid the bugs in
  // special element expansion.
  if (!options_.IsExpandForSpecialElements())
    return;

  while (true) {
    start_special_container = nullptr;
    end_special_container = nullptr;

    Position s =
        PositionBeforeContainingSpecialElement(start, &start_special_container);
    Position e =
        PositionAfterContainingSpecialElement(end, &end_special_container);

    if (!start_special_container && !end_special_container)
      break;

    if (CreateVisiblePosition(start).DeepEquivalent() !=
            CreateVisiblePosition(selection_to_delete_.Start())
                .DeepEquivalent() ||
        CreateVisiblePosition(end).DeepEquivalent() !=
            CreateVisiblePosition(selection_to_delete_.End()).DeepEquivalent())
      break;

    // If we're going to expand to include the startSpecialContainer, it must be
    // fully selected.
    if (start_special_container && !end_special_container &&
        ComparePositions(Position::InParentAfterNode(*start_special_container),
                         end) > -1)
      break;

    // If we're going to expand to include the endSpecialContainer, it must be
    // fully selected.
    if (end_special_container && !start_special_container &&
        ComparePositions(
            start, Position::InParentBeforeNode(*end_special_container)) > -1)
      break;

    if (start_special_container &&
        start_special_container->IsDescendantOf(end_special_container)) {
      // Don't adjust the end yet, it is the end of a special element that
      // contains the start special element (which may or may not be fully
      // selected).
      start = s;
    } else if (end_special_container &&
               end_special_container->IsDescendantOf(start_special_container)) {
      // Don't adjust the start yet, it is the start of a special element that
      // contains the end special element (which may or may not be fully
      // selected).
      end = e;
    } else {
      start = s;
      end = e;
    }
  }
}

void DeleteSelectionCommand::SetStartingSelectionOnSmartDelete(
    const Position& start,
    const Position& end) {
  DCHECK(!GetDocument().NeedsLayoutTreeUpdate());
  DocumentLifecycle::DisallowTransitionScope disallow_transition(
      GetDocument().Lifecycle());

  const bool is_base_first = StartingSelection().IsAnchorFirst();
  // TODO(yosin): We should not call |createVisiblePosition()| here and use
  // |start| and |end| as base/extent since |VisibleSelection| also calls
  // |createVisiblePosition()| during construction.
  // Because of |newBase.affinity()| can be |Upstream|, we can't simply
  // use |start| and |end| here.
  VisiblePosition new_base = CreateVisiblePosition(is_base_first ? start : end);
  VisiblePosition new_extent =
      CreateVisiblePosition(is_base_first ? end : start);
  SelectionInDOMTree::Builder builder;
  builder.SetAffinity(new_base.Affinity())
      .SetBaseAndExtentDeprecated(new_base.DeepEquivalent(),
                                  new_extent.DeepEquivalent());
  const VisibleSelection& visible_selection =
      CreateVisibleSelection(builder.Build());
  SetStartingSelection(
      SelectionForUndoStep::From(visible_selection.AsSelection()));
}

// This assumes that it starts in editable content.
static Position TrailingWhitespacePosition(const Position& position,
                                           WhitespacePositionOption option) {
  DCHECK(!NeedsLayoutTreeUpdate(position));
  DCHECK(IsEditablePosition(position)) << position;
  if (position.IsNull())
    return Position();

  const VisiblePosition visible_position = CreateVisiblePosition(position);
  const UChar character_after_visible_position =
      CharacterAfter(visible_position);
  const bool is_space =
      option == kConsiderNonCollapsibleWhitespace
          ? (IsSpaceOrNewline(character_after_visible_position) ||
             character_after_visible_position == kNoBreakSpaceCharacter)
          : IsCollapsibleWhitespace(character_after_visible_position);
  // The space must not be in another paragraph and it must be editable.
  if (is_space && !IsEndOfParagraph(visible_position) &&
      NextPositionOf(visible_position, kCannotCrossEditingBoundary).IsNotNull())
    return position;
  return Position();
}

// Workaround: GCC fails to resolve overloaded template functions, passed as
// parameters of EnclosingNodeType. But it works wrapping that in a utility
// function.
#if defined(COMPILER_GCC)
static bool IsHTMLTableRowElement(const blink::Node* node) {
  return IsA<HTMLTableRowElement>(node);
}
#endif

void DeleteSelectionCommand::InitializePositionData(
    EditingState* editing_state) {
  DCHECK(!GetDocument().NeedsLayoutTreeUpdate());
  DocumentLifecycle::DisallowTransitionScope disallow_transition(
      GetDocument().Lifecycle());

  Position start, end;
  InitializeStartEnd(start, end);
  DCHECK(start.IsNotNull());
  DCHECK(end.IsNotNull());
  if (!IsEditablePosition(start)) {
    editing_state->Abort();
    return;
  }
  if (!IsEditablePosition(end) && !end.IsAfterAnchor() &&
      !Position::LastPositionInNode(*(end.AnchorNode())).IsEquivalent(end)) {
    Node* highest_root = HighestEditableRoot(start);
    DCHECK(highest_root);
    end = LastEditablePositionBeforePositionInRoot(end, *highest_root);
  }

  upstream_start_ = MostBackwardCaretPosition(start);
  downstream_start_ = MostForwardCaretPosition(start);
  upstream_end_ = MostBackwardCaretPosition(end);
  downstream_end_ = MostForwardCaretPosition(end);

  start_root_ = RootEditableElementOf(start);
  end_root_ = RootEditableElementOf(end);

#if defined(COMPILER_GCC)
  // Workaround. See declaration of IsHTMLTableRowElement
  start_table_row_ = To<HTMLTableRowElement>(
      EnclosingNodeOfType(start, &IsHTMLTableRowElement));
  end_table_row_ =
      To<HTMLTableRowElement>(EnclosingNodeOfType(end, &IsHTMLTableRowElement));
#else
  start_table_row_ = To<HTMLTableRowElement>(
      EnclosingNodeOfType(start, &IsA<HTMLTableRowElement>));
  end_table_row_ = To<HTMLTableRowElement>(
      EnclosingNodeOfType(end, &IsA<HTMLTableRowElement>));
#endif

  // Don't move content out of a table cell.
  // If the cell is non-editable, enclosingNodeOfType won't return it by
  // default, so tell that function that we don't care if it returns
  // non-editable nodes.
  Node* start_cell = EnclosingNodeOfType(upstream_start_, &IsTableCell,
                                         kCanCrossEditingBoundary);
  Node* end_cell = EnclosingNodeOfType(downstream_end_, &IsTableCell,
                                       kCanCrossEditingBoundary);
  // FIXME: This isn't right.  A borderless table with two rows and a single
  // column would appear as two paragraphs.
  if (end_cell && end_cell != start_cell)
    merge_blocks_after_delete_ = false;

  // Usually the start and the end of the selection to delete are pulled
  // together as a result of the deletion. Sometimes they aren't (like when no
  // merge is requested), so we must choose one position to hold the caret
  // and receive the placeholder after deletion.
  VisiblePosition visible_end = CreateVisiblePosition(downstream_end_);
  if (merge_blocks_after_delete_ && !IsEndOfParagraph(visible_end))
    ending_position_ = downstream_end_;
  else
    ending_position_ = downstream_start_;

  // We don't want to merge into a block if it will mean changing the quote
  // level of content after deleting selections that contain a whole number
  // paragraphs plus a line break, since it is unclear to most users that such a
  // selection actually ends at the start of the next paragraph. This matches
  // TextEdit behavior for indented paragraphs.
  // Only apply this rule if the endingSelection is a range selection.  If it is
  // a caret, then other operations have created the selection we're deleting
  // (like the process of creating a selection to delete during a backspace),
  // and the user isn't in the situation described above.
  if (NumEnclosingMailBlockquotes(start) != NumEnclosingMailBlockquotes(end) &&
      IsStartOfParagraph(visible_end) &&
      IsStartOfParagraph(CreateVisiblePosition(start)) &&
      EndingSelection().IsRange()) {
    merge_blocks_after_delete_ = false;
    prune_start_block_if_necessary_ = true;
  }

  // Handle leading and trailing whitespace, as well as smart delete adjustments
  // to the selection
  leading_whitespace_ = LeadingCollapsibleWhitespacePosition(
      upstream_start_, selection_to_delete_.Affinity());
  trailing_whitespace_ =
      IsEditablePosition(downstream_end_)
          ? TrailingWhitespacePosition(downstream_end_,
                                       kNotConsiderNonCollapsibleWhitespace)
          : Position();

  if (options_.IsSmartDelete()) {
    // skip smart delete if the selection to delete already starts or ends with
    // whitespace
    Position pos =
        CreateVisiblePosition(upstream_start_, selection_to_delete_.Affinity())
            .DeepEquivalent();
    bool skip_smart_delete =
        TrailingWhitespacePosition(pos, kConsiderNonCollapsibleWhitespace)
            .IsNotNull();
    if (!skip_smart_delete) {
      skip_smart_delete = LeadingCollapsibleWhitespacePosition(
                              downstream_end_, TextAffinity::kDefault,
                              kConsiderNonCollapsibleWhitespace)
                              .IsNotNull();
    }

    // extend selection upstream if there is whitespace there
    bool has_leading_whitespace_before_adjustment =
        LeadingCollapsibleWhitespacePosition(upstream_start_,
                                             selection_to_delete_.Affinity(),
                                             kConsiderNonCollapsibleWhitespace)
            .IsNotNull();
    if (!skip_smart_delete && has_leading_whitespace_before_adjustment) {
      VisiblePosition visible_pos =
          PreviousPositionOf(CreateVisiblePosition(upstream_start_));
      pos = visible_pos.DeepEquivalent();
      // Expand out one character upstream for smart delete and recalculate
      // positions based on this change.
      upstream_start_ = MostBackwardCaretPosition(pos);
      downstream_start_ = MostForwardCaretPosition(pos);
      leading_whitespace_ = LeadingCollapsibleWhitespacePosition(
          upstream_start_, visible_pos.Affinity());

      SetStartingSelectionOnSmartDelete(upstream_start_, upstream_end_);
    }

    // trailing whitespace is only considered for smart delete if there is no
    // leading whitespace, as in the case where you double-click the first word
    // of a paragraph.
    if (!skip_smart_delete && !has_leading_whitespace_before_adjustment &&
        TrailingWhitespacePosition(downstream_end_,
                                   kConsiderNonCollapsibleWhitespace)
            .IsNotNull()) {
      // Expand out one character downstream for smart delete and recalculate
      // positions based on this change.
      pos = NextPositionOf(CreateVisiblePosition(downstream_end_))
                .DeepEquivalent();
      upstream_end_ = MostBackwardCaretPosition(pos);
      downstream_end_ = MostForwardCaretPosition(pos);
      trailing_whitespace_ = TrailingWhitespacePosition(
          downstream_end_, kNotConsiderNonCollapsibleWhitespace);

      SetStartingSelectionOnSmartDelete(downstream_start_, downstream_end_);
    }
  }

  // We must pass call parentAnchoredEquivalent on the positions since some
  // editing positions that appear inside their nodes aren't really inside them.
  // [hr, 0] is one example.
  // FIXME: parentAnchoredEquivalent should eventually be moved into enclosing
  // element getters like the one below, since editing functions should
  // obviously accept editing positions.
  // FIXME: Passing false to enclosingNodeOfType tells it that it's OK to return
  // a non-editable node.  This was done to match existing behavior, but it
  // seems wrong.
  start_block_ =
      EnclosingNodeOfType(downstream_start_.ParentAnchoredEquivalent(),
                          &IsEnclosingBlock, kCanCrossEditingBoundary);
  end_block_ = EnclosingNodeOfType(upstream_end_.ParentAnchoredEquivalent(),
                                   &IsEnclosingBlock, kCanCrossEditingBoundary);
}

// We don't want to inherit style from an element which can't have contents.
static bool ShouldNotInheritStyleFrom(const Node& node) {
  return !node.CanContainRangeEndPoint();
}

void DeleteSelectionCommand::SaveTypingStyleState() {
  // A common case is deleting characters that are all from the same text node.
  // In that case, the style at the start of the selection before deletion will
  // be the same as the style at the start of the selection after deletion
  // (since those two positions will be identical). Therefore there is no need
  // to save the typing style at the start of the selection, nor is there a
  // reason to compute the style at the start of the selection after deletion
  // (see the early return in calculateTypingStyleAfterDelete).
  if (upstream_start_.AnchorNode() == downstream_end_.AnchorNode() &&
      upstream_start_.AnchorNode()->IsTextNode())
    return;

  if (ShouldNotInheritStyleFrom(*selection_to_delete_.Start().AnchorNode()))
    return;

  // Figure out the typing style in effect before the delete is done.
  typing_style_ = MakeGarbageCollected<EditingStyle>(
      selection_to_delete_.Start(), EditingStyle::kEditingPropertiesInEffect);
  typing_style_->RemoveStyleAddedByElement(
      EnclosingAnchorElement(selection_to_delete_.Start()));

  // If we're deleting into a Mail blockquote, save the style at end() instead
  // of start(). We'll use this later in computeTypingStyleAfterDelete if we end
  // up outside of a Mail blockquote
  if (EnclosingNodeOfType(selection_to_delete_.Start(),
                          IsMailHTMLBlockquoteElement)) {
    delete_into_blockquote_style_ =
        MakeGarbageCollected<EditingStyle>(selection_to_delete_.End());
    return;
  }
  delete_into_blockquote_style_ = nullptr;
}

bool DeleteSelectionCommand::HandleSpecialCaseBRDelete(
    EditingState* editing_state) {
  Node* node_after_upstream_start = upstream_start_.ComputeNodeAfterPosition();
  Node* node_after_downstream_start =
      downstream_start_.ComputeNodeAfterPosition();
  // Upstream end will appear before BR due to canonicalization
  Node* node_after_upstream_end = upstream_end_.ComputeNodeAfterPosition();

  if (!node_after_upstream_start || !node_after_downstream_start)
    return false;

  // Check for special-case where the selection contains only a BR on a line by
  // itself after another BR.
  bool upstream_start_is_br = IsA<HTMLBRElement>(*node_after_upstream_start);
  bool downstream_start_is_br =
      IsA<HTMLBRElement>(*node_after_downstream_start);
  bool is_br_on_line_by_itself =
      upstream_start_is_br && downstream_start_is_br &&
      node_after_downstream_start == node_after_upstream_end;
  if (is_br_on_line_by_itself) {
    RemoveNode(node_after_downstream_start, editing_state);
    return true;
  }

  // FIXME: This code doesn't belong in here.
  // We detect the case where the start is an empty line consisting of BR not
  // wrapped in a block element.
  if (upstream_start_is_br && downstream_start_is_br) {
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
    if (!(IsStartOfBlock(
              VisiblePosition::BeforeNode(*node_after_upstream_start)) &&
          IsEndOfBlock(
              VisiblePosition::AfterNode(*node_after_upstream_start)))) {
      starts_at_empty_line_ = true;
      ending_position_ = downstream_end_;
    }
  }

  return false;
}

static Position FirstEditablePositionInNode(Node* node) {
  DCHECK(node);
  Node* next = node;
  while (next && !IsEditable(*next))
    next = NodeTraversal::Next(*next, node);
  return next ? FirstPositionInOrBeforeNode(*next) : Position();
}

void DeleteSelectionCommand::RemoveNode(
    Node* node,
    EditingState* editing_state,
    ShouldAssumeContentIsAlwaysEditable
        should_assume_content_is_always_editable) {
  if (!node)
    return;

  if (start_root_ != end_root_ && !(node->IsDescendantOf(start_root_.Get()) &&
                                    node->IsDescendantOf(end_root_.Get()))) {
    // If a node is not in both the start and end editable roots, remove it only
    // if its inside an editable region.
    if (!IsEditable(*node->parentNode())) {
      // Don't remove non-editable atomic nodes.
      if (!node->hasChildren())
        return;
      // Search this non-editable region for editable regions to empty.
      // Don't remove editable regions that are inside non-editable ones, just
      // clear them.
      RemoveAllChildrenIfPossible(To<ContainerNode>(node), editing_state,
                                  should_assume_content_is_always_editable);
      return;
    }
  }

  if (IsTableStructureNode(node) || IsRootEditableElement(*node)) {
    // Do not remove an element of table structure; remove its contents.
    // Likewise for the root editable element.
    RemoveAllChildrenIfPossible(To<ContainerNode>(node), editing_state,
                                should_assume_content_is_always_editable);
    if (editing_state->IsAborted())
      return;

    // Make sure empty cell has some height, if a placeholder can be inserted.
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
    LayoutObject* r = node->GetLayoutObject();
    if (r && r->IsTableCell() && To<LayoutBox>(r)->ContentHeight() <= 0) {
      Position first_editable_position = FirstEditablePositionInNode(node);
      if (first_editable_position.IsNotNull())
        InsertBlockPlaceholder(first_editable_position, editing_state);
    }
    return;
  }

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  if (node == start_block_) {
    VisiblePosition previous = PreviousPositionOf(
        VisiblePosition::FirstPositionInNode(*start_block_.Get()));
    if (previous.IsNotNull() && !IsEndOfBlock(previous))
      need_placeholder_ = true;
  }
  if (node == end_block_) {
    VisiblePosition next =
        NextPositionOf(VisiblePosition::LastPositionInNode(*end_block_.Get()));
    if (next.IsNotNull() && !IsStartOfBlock(next))
      need_placeholder_ = true;
  }

  // FIXME: Update the endpoints of the range being deleted.
  ending_position_ = ComputePositionForNodeRemoval(ending_position_, *node);
  leading_whitespace_ =
      ComputePositionForNodeRemoval(leading_whitespace_, *node);
  trailing_whitespace_ =
      ComputePositionForNodeRemoval(trailing_whitespace_, *node);

  CompositeEditCommand::RemoveNode(node, editing_state,
                                   should_assume_content_is_always_editable);
}

void DeleteSelectionCommand::RemoveCompletelySelectedNodes(
    Node* start_node,
    EditingState* editing_state) {
  HeapVector<Member<Node>> nodes_to_be_removed;
  Node* node = start_node;

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  // Collecting nodes that can be removed from |start_node|.
  while (node && node != downstream_end_.AnchorNode()) {
    if (ComparePositions(FirstPositionInOrBeforeNode(*node), downstream_end_) >=
        0)
      break;

    if (!downstream_end_.AnchorNode()->IsDescendantOf(node)) {
      nodes_to_be_removed.push_back(node);
      node = NodeTraversal::NextSkippingChildren(*node);
      continue;
    }

    Node& last_within_or_self_node = NodeTraversal::LastWithinOrSelf(*node);
    if (downstream_end_.AnchorNode() == last_within_or_self_node &&
        downstream_end_.ComputeEditingOffset() >=
            CaretMaxOffset(&last_within_or_self_node)) {
      nodes_to_be_removed.push_back(node);
      break;
    }

    node = NodeTraversal::Next(*node);
  }

  // Update leading, trailing whitespace position.
  if (!nodes_to_be_removed.empty()) {
    leading_whitespace_ = ComputePositionForNodeRemoval(
        leading_whitespace_, *(nodes_to_be_removed[0].Get()));
    trailing_whitespace_ = ComputePositionForNodeRemoval(
        trailing_whitespace_,
        *(nodes_to_be_removed[nodes_to_be_removed.size() - 1].Get()));
  }

  // Check if place holder is needed before actually removing nodes because
  // this requires document.NeedsLayoutTreeUpdate() returning false.
  if (!need_placeholder_) {
    need_placeholder_ =
        base::ranges::any_of(nodes_to_be_removed, [&](Node* node) {
          if (node == start_block_) {
            VisiblePosition previous = PreviousPositionOf(
                VisiblePosition::FirstPositionInNode(*start_block_.Get()));
            if (previous.IsNotNull() && !IsEndOfBlock(previous))
              return true;
          }
          if (node == end_block_) {
            VisiblePosition next = NextPositionOf(
                VisiblePosition::LastPositionInNode(*end_block_.Get()));
            if (next.IsNotNull() && !IsStartOfBlock(next))
              return true;
          }
          return false;
        });
  }

  // Actually remove the nodes in |nodes_to_be_removed|.
  for (Node* node_to_be_removed : nodes_to_be_removed) {
    if (!downstream_end_.AnchorNode()->IsDescendantOf(node_to_be_removed)) {
      downstream_end_ =
          ComputePositionForNodeRemoval(downstream_end_, *(node_to_be_removed));
    }

    if (start_root_ != end_root_ &&
        !(node_to_be_removed->IsDescendantOf(start_root_.Get()) &&
          node_to_be_removed->IsDescendantOf(end_root_.Get()))) {
      // If a node is not in both the start and end editable roots, remove it
      // only if its inside an editable region.
      if (!IsEditable(*node_to_be_removed->parentNode())) {
        // Don't remove non-editable atomic nodes.
        if (!node_to_be_removed->hasChildren())
          continue;
        // Search this non-editable region for editable regions to empty.
        // Don't remove editable regions that are inside non-editable ones, just
        // clear them.
        RemoveAllChildrenIfPossible(To<ContainerNode>(node_to_be_removed),
                                    editing_state,
                                    kDoNotAssumeContentIsAlwaysEditable);
        if (editing_state->IsAborted())
          return;

        continue;
      }
    }

    if (IsTableStructureNode(node_to_be_removed) ||
        IsRootEditableElement(*node_to_be_removed)) {
      // Do not remove an element of table structure; remove its contents.
      // Likewise for the root editable element.
      RemoveAllChildrenIfPossible(To<ContainerNode>(node_to_be_removed),
                                  editing_state,
                                  kDoNotAssumeContentIsAlwaysEditable);
      if (editing_state->IsAborted())
        return;

      // Make sure empty cell has some height, if a placeholder can be inserted.
      GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
      LayoutObject* layout_obj = node_to_be_removed->GetLayoutObject();
      if (layout_obj && layout_obj->IsTableCell() &&
          To<LayoutBox>(layout_obj)->ContentHeight() <= 0) {
        Position first_editable_position =
            FirstEditablePositionInNode(node_to_be_removed);
        if (first_editable_position.IsNotNull())
          InsertBlockPlaceholder(first_editable_position, editing_state);
      }
      continue;
    }

    ending_position_ =
        ComputePositionForNodeRemoval(ending_position_, *node_to_be_removed);
    CompositeEditCommand::RemoveNode(node_to_be_removed, editing_state,
                                     kDoNotAssumeContentIsAlwaysEditable);
    if (editing_state->IsAborted())
      return;
  }
}

static void UpdatePositionForTextRemoval(Text* node,
                                         int offset,
                                         int count,
                                         Position& position) {
  if (!position.IsOffsetInAnchor() || position.ComputeContainerNode() != node)
    return;

  if (position.OffsetInContainerNode() > offset + count)
    position = Position(position.ComputeContainerNode(),
                        position.OffsetInContainerNode() - count);
  else if (position.OffsetInContainerNode() > offset)
    position = Position(position.ComputeContainerNode(), offset);
}

void DeleteSelectionCommand::DeleteTextFromNode(Text* node,
                                                unsigned offset,
                                                unsigned count) {
  // FIXME: Update the endpoints of the range being deleted.
  UpdatePositionForTextRemoval(node, offset, count, ending_position_);
  UpdatePositionForTextRemoval(node, offset, count, leading_whitespace_);
  UpdatePositionForTextRemoval(node, offset, count, trailing_whitespace_);
  UpdatePositionForTextRemoval(node, offset, count, downstream_end_);

  CompositeEditCommand::DeleteTextFromNode(node, offset, count);
}

void DeleteSelectionCommand::
    MakeStylingElementsDirectChildrenOfEditableRootToPreventStyleLoss(
        EditingState* editing_state) {
  Range* range = CreateRange(CreateVisibleSelection(selection_to_delete_)
                                 .ToNormalizedEphemeralRange());
  Node* node = range->FirstNode();
  while (node && node != range->PastLastNode()) {
    Node* next_node = NodeTraversal::Next(*node);
    if (IsA<HTMLStyleElement>(*node) || IsA<HTMLLinkElement>(*node)) {
      next_node = NodeTraversal::NextSkippingChildren(*node);
      Element* element = RootEditableElement(*node);
      if (element) {
        RemoveNode(node, editing_state);
        if (editing_state->IsAborted())
          return;
        AppendNode(node, element, editing_state);
        if (editing_state->IsAborted())
          return;
      }
    }
    node = next_node;
  }
}

void DeleteSelectionCommand::HandleGeneralDelete(EditingState* editing_state) {
  if (upstream_start_.IsNull())
    return;

  int start_offset = upstream_start_.ComputeEditingOffset();
  Node* start_node = upstream_start_.AnchorNode();
  DCHECK(start_node);

  MakeStylingElementsDirectChildrenOfEditableRootToPreventStyleLoss(
      editing_state);
  if (editing_state->IsAborted())
    return;

  // Never remove the start block unless it's a table, in which case we won't
  // merge content in.
  if (start_node == start_block_.Get() && !start_offset &&
      CanHaveChildrenForEditing(start_node) &&
      !IsA<HTMLTableElement>(*start_node)) {
    start_offset = 0;
    start_node = NodeTraversal::Next(*start_node);
    if (!start_node)
      return;
  }

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  auto* text = DynamicTo<Text>(start_node);
  if (start_offset >= CaretMaxOffset(start_node) && text) {
    if (text->length() > static_cast<unsigned>(CaretMaxOffset(start_node))) {
      DeleteTextFromNode(text, CaretMaxOffset(start_node),
                         text->length() - CaretMaxOffset(start_node
```