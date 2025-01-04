Response:
The user wants a summary of the functionality of the `composite_edit_command.cc` file in the Chromium Blink engine. I need to identify the main purpose of this class and its interactions with other parts of the engine, particularly regarding editing operations. I also need to address specific points about its relation to JavaScript, HTML, and CSS, provide examples with hypothetical inputs and outputs, discuss potential user errors, and explain how a user's actions can lead to this code being executed.

Here's a breakdown of how to approach this:

1. **Identify the core functionality:** The name "CompositeEditCommand" strongly suggests it's responsible for orchestrating multiple simpler edit operations. The included headers give clues about the types of commands it composes (e.g., `InsertNodeCommand`, `ApplyStyleCommand`, `DeleteSelectionCommand`).

2. **Explain the "composite" aspect:** Emphasize that this class acts as a container and manager for a sequence of smaller editing commands.

3. **Connect to the broader editing system:** Describe how it fits within the undo/redo mechanism and the overall editing workflow in Blink.

4. **Address JavaScript, HTML, and CSS:**
    * **HTML:** Composite commands directly manipulate the DOM structure (inserting/removing nodes, changing attributes).
    * **CSS:** They can apply and remove styles, affecting the visual presentation.
    * **JavaScript:**  JavaScript can trigger actions that ultimately result in the execution of composite edit commands (e.g., `document.execCommand`).

5. **Provide hypothetical examples:**  Imagine a user performing an action like bolding a selection or inserting a link. Outline the sequence of underlying commands that a `CompositeEditCommand` might manage for these actions.

6. **Discuss user errors:**  Think about scenarios where user input or actions might lead to unexpected or incorrect editing outcomes. This might involve invalid ranges, attempting to edit non-editable content, etc.

7. **Explain the user action to code execution path:** Trace a simple user action (e.g., typing) and explain the sequence of events and function calls that eventually lead to the execution of code within this file.

8. **Summarize the functionality:**  Provide a concise overview of the role and purpose of `CompositeEditCommand` based on the analysis.
这是 `blink/renderer/core/editing/commands/composite_edit_command.cc` 文件的第一部分，其主要功能是定义了 `CompositeEditCommand` 类。这个类在 Blink 渲染引擎的编辑模块中扮演着核心角色，用于**组合和管理多个更小的编辑操作**。可以将它视为一个事务管理器，确保一系列相关的编辑操作要么全部成功执行，要么全部回滚。

以下是该文件第一部分功能的详细归纳：

**核心功能：**

1. **作为编辑命令的容器：** `CompositeEditCommand` 继承自 `EditCommand`，它可以包含并管理多个其他的 `EditCommand` 子类的实例（例如 `InsertNodeCommand`, `ApplyStyleCommand`, `DeleteSelectionCommand` 等）。这允许将一个用户发起的逻辑编辑操作分解为一系列更细粒度的步骤，并作为一个整体进行处理。

2. **事务管理和原子性：**  `CompositeEditCommand` 负责确保其包含的所有子命令的执行具有原子性。这意味着要么所有命令都成功执行，并且对文档的更改被记录到撤销栈中，要么如果任何子命令失败，整个复合命令都会被视为失败，并且不会对文档产生永久性影响。这保证了编辑操作的一致性。

3. **管理撤销/重做栈：** `CompositeEditCommand` 与撤销栈 (`UndoStack`) 交互，负责创建一个 `UndoStep` 对象来记录自身的操作。每个 `CompositeEditCommand` 都会创建一个 `UndoStep`，用于在撤销操作时恢复文档到之前的状态。

4. **处理起始和结束选区：**  `CompositeEditCommand` 记录了编辑操作开始前的选区 (`starting_selection_`) 和操作完成后的选区 (`ending_selection_`)。这对于撤销/重做以及后续的编辑操作至关重要。

5. **应用子命令：** 提供了 `ApplyCommandToComposite` 方法，用于向当前 `CompositeEditCommand` 添加并执行子命令。

6. **提供便捷的辅助方法：**  定义了许多便捷的方法来创建和应用各种常见的编辑命令，例如 `ApplyStyle`, `InsertParagraphSeparator`, `InsertNodeBefore`, `RemoveNode` 等。这些方法简化了在复合命令中执行常见编辑操作的过程。

7. **处理可编辑性：** 在 `Apply` 方法中，会检查当前位置是否可编辑，并根据情况决定是否执行编辑操作。

8. **与辅助功能集成：** 使用 `ScopedBlinkAXEventIntent` 来通知辅助功能系统编辑操作的影响。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML:** `CompositeEditCommand` 的核心功能就是修改 HTML 文档结构。
    * **例子：** 用户在富文本编辑器中插入一个图片。这可能会触发一个 `CompositeEditCommand`，其中包含 `InsertNodeCommand` 来插入 `<img>` 元素。
    * **假设输入：** 用户在光标位置选择插入一个 `<img>` 元素，`src` 属性为 "image.png"。
    * **输出：**  `CompositeEditCommand` 执行后，会在文档中插入 `<img src="image.png">`。

* **CSS:** `CompositeEditCommand` 可以应用或移除 CSS 样式。
    * **例子：** 用户选中一段文本并点击 "加粗" 按钮。这可能会触发一个 `CompositeEditCommand`，其中包含 `ApplyStyleCommand` 来添加 `font-weight: bold` 样式。
    * **假设输入：** 用户选中 "hello"，然后点击加粗按钮。
    * **输出：** `CompositeEditCommand` 执行后，选中的文本可能会被包裹在 `<b>` 标签中，或者应用 `style="font-weight: bold;"` 属性。

* **JavaScript:** JavaScript 代码通常会触发 `CompositeEditCommand` 的执行。
    * **例子：**  一个富文本编辑器使用 JavaScript 的 `document.execCommand('bold')` API 来使选中文本加粗。这个 `execCommand` 最终会创建一个 `CompositeEditCommand` 来执行相应的操作。
    * **用户操作：** 用户在文本框中选中一段文字，然后点击编辑器工具栏上的 "加粗" 按钮。
    * **JavaScript 交互：**  按钮的点击事件触发 JavaScript 代码，调用 `document.execCommand('bold')`。
    * **`CompositeEditCommand` 的创建和执行：** Blink 引擎接收到 `bold` 命令，创建一个 `CompositeEditCommand` 实例，并添加 `ApplyStyleCommand` 来应用加粗样式。

**逻辑推理及假设输入与输出：**

* **假设输入：** 用户在一个空的 `<div contenteditable="true">` 元素中输入 "abc"。
* **逻辑推理：**  每次输入一个字符，可能会创建一个新的 `CompositeEditCommand` （或者添加到之前的 `TypingCommand` 中，但 `CompositeEditCommand` 可以包含它）。对于输入 "a"，`CompositeEditCommand` 可能包含一个 `InsertIntoTextNodeCommand`，将 "a" 插入到 `<div>` 内部新创建的文本节点中。接着输入 "b" 和 "c" 也会类似。
* **输出：**  `<div>abc</div>`

**用户或编程常见的使用错误：**

* **在不可编辑区域尝试编辑：** 如果用户或者程序尝试在 `contenteditable="false"` 的元素内部进行编辑操作，`CompositeEditCommand::Apply` 方法会检查可编辑性，并可能阻止编辑操作的执行。
    * **例子：** 用户尝试在被 `contenteditable="false"` 包裹的文本上点击并输入，相关的编辑命令将不会被执行。

* **不正确的选区操作：**  如果程序提供的起始和结束选区不合法（例如，结束位置在起始位置之前），可能会导致 `CompositeEditCommand` 的执行失败或者产生意想不到的结果。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户交互：** 用户在网页上进行编辑操作，例如：
    * 在 `contenteditable` 的元素中输入文本。
    * 选中一段文本并点击格式化按钮（例如，加粗、斜体）。
    * 使用键盘快捷键（例如，Ctrl+B 加粗）。
    * 粘贴文本。
    * 拖拽内容。

2. **事件触发：**  用户的操作会触发相应的浏览器事件（例如，`keypress`, `mouseup`, `paste`, `dragend`）。

3. **事件处理：**  Blink 引擎的事件处理机制会捕获这些事件，并将其传递给相应的处理函数。

4. **编辑命令创建：**  在处理编辑相关的事件时，Blink 引擎会根据用户的操作创建一个或多个 `EditCommand` 对象。对于复杂的编辑操作，会创建一个 `CompositeEditCommand` 来协调多个子命令。 例如，按下 "B" 键并同时按下 Ctrl 键可能会触发创建执行 "bold" 命令的 `CompositeEditCommand`。

5. **`CompositeEditCommand::Apply()` 调用：**  创建的 `CompositeEditCommand` 实例的 `Apply()` 方法会被调用，开始执行编辑操作。

6. **子命令执行：** `Apply()` 方法会依次执行 `CompositeEditCommand` 中包含的子命令，例如 `InsertIntoTextNodeCommand`、`ApplyStyleCommand` 等。

7. **DOM 更新：**  子命令会直接修改 DOM 树。

8. **撤销栈更新：**  `CompositeEditCommand` 会将此次编辑操作记录到撤销栈中，以便用户可以撤销。

**总结：**

`composite_edit_command.cc` 文件的第一部分定义了 `CompositeEditCommand` 类，它是 Blink 编辑模块中用于管理和执行一系列相关编辑操作的核心组件。它确保了编辑操作的原子性，并与撤销/重做机制紧密集成。它通过组合各种更小的编辑命令来实现复杂的编辑功能，并受到用户在网页上的编辑行为触发。理解 `CompositeEditCommand` 的工作原理是理解 Blink 编辑模块的关键。

Prompt: 
```
这是目录为blink/renderer/core/editing/commands/composite_edit_command.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2005, 2006, 2007, 2008 Apple Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/editing/commands/composite_edit_command.h"

#include <algorithm>

#include "third_party/blink/renderer/core/accessibility/blink_ax_event_intent.h"
#include "third_party/blink/renderer/core/accessibility/scoped_blink_ax_event_intent.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/scoped_event_queue.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/commands/append_node_command.h"
#include "third_party/blink/renderer/core/editing/commands/apply_style_command.h"
#include "third_party/blink/renderer/core/editing/commands/delete_from_text_node_command.h"
#include "third_party/blink/renderer/core/editing/commands/delete_selection_command.h"
#include "third_party/blink/renderer/core/editing/commands/editing_commands_utilities.h"
#include "third_party/blink/renderer/core/editing/commands/insert_into_text_node_command.h"
#include "third_party/blink/renderer/core/editing/commands/insert_line_break_command.h"
#include "third_party/blink/renderer/core/editing/commands/insert_node_before_command.h"
#include "third_party/blink/renderer/core/editing/commands/insert_paragraph_separator_command.h"
#include "third_party/blink/renderer/core/editing/commands/merge_identical_elements_command.h"
#include "third_party/blink/renderer/core/editing/commands/remove_css_property_command.h"
#include "third_party/blink/renderer/core/editing/commands/remove_node_command.h"
#include "third_party/blink/renderer/core/editing/commands/remove_node_preserving_children_command.h"
#include "third_party/blink/renderer/core/editing/commands/replace_node_with_span_command.h"
#include "third_party/blink/renderer/core/editing/commands/replace_selection_command.h"
#include "third_party/blink/renderer/core/editing/commands/set_character_data_command.h"
#include "third_party/blink/renderer/core/editing/commands/set_node_attribute_command.h"
#include "third_party/blink/renderer/core/editing/commands/split_element_command.h"
#include "third_party/blink/renderer/core/editing/commands/split_text_node_command.h"
#include "third_party/blink/renderer/core/editing/commands/split_text_node_containing_element_command.h"
#include "third_party/blink/renderer/core/editing/commands/undo_stack.h"
#include "third_party/blink/renderer/core/editing/commands/wrap_contents_in_dummy_span_command.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/plain_text_range.h"
#include "third_party/blink/renderer/core/editing/relocatable_position.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_li_element.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"
#include "third_party/blink/renderer/core/html/html_olist_element.h"
#include "third_party/blink/renderer/core/html/html_quote_element.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/html/html_ulist_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/collection_support/clear_collection_scope.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/resource_coordinator/document_resource_coordinator.h"

namespace blink {

namespace {

bool IsWhitespaceForRebalance(const Text& text_node, UChar character) {
  if (IsWhitespace(character)) {
    if (character == kNewlineCharacter &&
        RuntimeEnabledFeatures::InsertLineBreakIfPhrasingContentEnabled()) {
      return !text_node.GetLayoutObject() ||
             text_node.GetLayoutObject()->StyleRef().ShouldCollapseBreaks();
    }
    return true;
  }
  return false;
}

}  // namespace

CompositeEditCommand::CompositeEditCommand(Document& document)
    : EditCommand(document) {
  const VisibleSelection& visible_selection =
      document.GetFrame()
          ->Selection()
          .ComputeVisibleSelectionInDOMTreeDeprecated();
  SetStartingSelection(
      SelectionForUndoStep::From(visible_selection.AsSelection()));
  SetEndingSelection(starting_selection_);
}

CompositeEditCommand::~CompositeEditCommand() {
  DCHECK(IsTopLevelCommand() || !undo_step_);
}

VisibleSelection CompositeEditCommand::EndingVisibleSelection() const {
  // TODO(editing-dev): The use of
  // |Document::UpdateStyleAndLayout()|
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  return CreateVisibleSelection(ending_selection_);
}

bool CompositeEditCommand::Apply() {
  DCHECK(!IsCommandGroupWrapper());
  if (!IsRichlyEditablePosition(EndingVisibleSelection().Anchor())) {
    switch (GetInputType()) {
      case InputEvent::InputType::kInsertText:
      case InputEvent::InputType::kInsertLineBreak:
      case InputEvent::InputType::kInsertParagraph:
      case InputEvent::InputType::kInsertFromPaste:
      case InputEvent::InputType::kInsertFromDrop:
      case InputEvent::InputType::kInsertFromYank:
      case InputEvent::InputType::kInsertTranspose:
      case InputEvent::InputType::kInsertReplacementText:
      case InputEvent::InputType::kInsertCompositionText:
      case InputEvent::InputType::kInsertLink:
      case InputEvent::InputType::kDeleteWordBackward:
      case InputEvent::InputType::kDeleteWordForward:
      case InputEvent::InputType::kDeleteSoftLineBackward:
      case InputEvent::InputType::kDeleteSoftLineForward:
      case InputEvent::InputType::kDeleteHardLineBackward:
      case InputEvent::InputType::kDeleteHardLineForward:
      case InputEvent::InputType::kDeleteContentBackward:
      case InputEvent::InputType::kDeleteContentForward:
      case InputEvent::InputType::kDeleteByCut:
      case InputEvent::InputType::kDeleteByDrag:
      case InputEvent::InputType::kNone:
        break;
      default:
        return false;
    }
  }
  EnsureUndoStep();

  // Changes to the document may have been made since the last editing operation
  // that require a layout, as in <rdar://problem/5658603>. Low level
  // operations, like RemoveNodeCommand, don't require a layout because the high
  // level operations that use them perform one if one is necessary (like for
  // the creation of VisiblePositions).
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  LocalFrame* frame = GetDocument().GetFrame();
  DCHECK(frame);
  // directional is stored at the top level command, so that before and after
  // executing command same directional will be there.
  SetSelectionIsDirectional(frame->Selection().IsDirectional());
  GetUndoStep()->SetSelectionIsDirectional(SelectionIsDirectional());

  // Provides details to accessibility about any text change caused by applying
  // this command, throughout the current call stack.
  ScopedBlinkAXEventIntent scoped_blink_ax_event_intent(
      BlinkAXEventIntent::FromEditCommand(*this), &GetDocument());

  EditingState editing_state;
  EventQueueScope event_queue_scope;
  DoApply(&editing_state);

  // Only need to call appliedEditing for top-level commands, and TypingCommands
  // do it on their own (see TypingCommand::typingAddedToOpenCommand).
  if (!IsTypingCommand())
    AppliedEditing();
  return !editing_state.IsAborted();
}

UndoStep* CompositeEditCommand::EnsureUndoStep() {
  CompositeEditCommand* command = this;
  while (command && command->Parent())
    command = command->Parent();
  if (!command->undo_step_) {
    command->undo_step_ = MakeGarbageCollected<UndoStep>(
        &GetDocument(), StartingSelection(), EndingSelection());
  }
  return command->undo_step_.Get();
}

bool CompositeEditCommand::PreservesTypingStyle() const {
  return false;
}

bool CompositeEditCommand::IsTypingCommand() const {
  return false;
}

bool CompositeEditCommand::IsCommandGroupWrapper() const {
  return false;
}

bool CompositeEditCommand::IsDragAndDropCommand() const {
  return false;
}

bool CompositeEditCommand::IsReplaceSelectionCommand() const {
  return false;
}

//
// sugary-sweet convenience functions to help create and apply edit commands in
// composite commands
//
void CompositeEditCommand::ApplyCommandToComposite(
    EditCommand* command,
    EditingState* editing_state) {
  command->SetParent(this);
  command->SetSelectionIsDirectional(SelectionIsDirectional());
  command->DoApply(editing_state);
  if (editing_state->IsAborted()) {
    command->SetParent(nullptr);
    return;
  }
  if (auto* simple_edit_command = DynamicTo<SimpleEditCommand>(command)) {
    command->SetParent(nullptr);
    EnsureUndoStep()->Append(simple_edit_command);
  }
  commands_.push_back(command);
}

void CompositeEditCommand::AppendCommandToUndoStep(
    CompositeEditCommand* command) {
  EnsureUndoStep()->Append(command->EnsureUndoStep());
  command->undo_step_ = nullptr;
  command->SetParent(this);
  commands_.push_back(command);
}

void CompositeEditCommand::ApplyStyle(const EditingStyle* style,
                                      EditingState* editing_state) {
  ApplyCommandToComposite(
      MakeGarbageCollected<ApplyStyleCommand>(GetDocument(), style,
                                              InputEvent::InputType::kNone),
      editing_state);
}

void CompositeEditCommand::ApplyStyle(const EditingStyle* style,
                                      const Position& start,
                                      const Position& end,
                                      EditingState* editing_state) {
  ApplyCommandToComposite(
      MakeGarbageCollected<ApplyStyleCommand>(GetDocument(), style, start, end),
      editing_state);
}

void CompositeEditCommand::ApplyStyledElement(Element* element,
                                              EditingState* editing_state) {
  ApplyCommandToComposite(
      MakeGarbageCollected<ApplyStyleCommand>(element, false), editing_state);
}

void CompositeEditCommand::RemoveStyledElement(Element* element,
                                               EditingState* editing_state) {
  ApplyCommandToComposite(
      MakeGarbageCollected<ApplyStyleCommand>(element, true), editing_state);
}

void CompositeEditCommand::InsertParagraphSeparator(
    EditingState* editing_state,
    bool use_default_paragraph_element,
    bool paste_blockqutoe_into_unquoted_area) {
  ApplyCommandToComposite(MakeGarbageCollected<InsertParagraphSeparatorCommand>(
                              GetDocument(), use_default_paragraph_element,
                              paste_blockqutoe_into_unquoted_area),
                          editing_state);
}

bool CompositeEditCommand::IsRemovableBlock(const Node* node) {
  DCHECK(node);
  const auto* element = DynamicTo<HTMLDivElement>(node);
  if (!element)
    return false;

  ContainerNode* parent_node = element->parentNode();
  if (parent_node && parent_node->firstChild() != parent_node->lastChild())
    return false;

  if (!element->hasAttributes())
    return true;

  return false;
}

void CompositeEditCommand::InsertNodeBefore(
    Node* insert_child,
    Node* ref_child,
    EditingState* editing_state,
    ShouldAssumeContentIsAlwaysEditable
        should_assume_content_is_always_editable) {
  ABORT_EDITING_COMMAND_IF(GetDocument().body() == ref_child);
  ABORT_EDITING_COMMAND_IF(!ref_child->parentNode());
  // TODO(editing-dev): Use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  ABORT_EDITING_COMMAND_IF(!IsEditable(*ref_child->parentNode()) &&
                           ref_child->parentNode()->InActiveDocument());
  ApplyCommandToComposite(
      MakeGarbageCollected<InsertNodeBeforeCommand>(
          insert_child, ref_child, should_assume_content_is_always_editable),
      editing_state);
}

void CompositeEditCommand::InsertNodeAfter(Node* insert_child,
                                           Node* ref_child,
                                           EditingState* editing_state) {
  ABORT_EDITING_COMMAND_IF(!ref_child->parentNode());
  DCHECK(insert_child);
  DCHECK(ref_child);
  ABORT_EDITING_COMMAND_IF(GetDocument().body() == ref_child);
  ContainerNode* parent = ref_child->parentNode();
  DCHECK(parent);
  DCHECK(!parent->IsShadowRoot()) << parent;
  if (parent->lastChild() == ref_child) {
    AppendNode(insert_child, parent, editing_state);
  } else {
    DCHECK(ref_child->nextSibling()) << ref_child;
    InsertNodeBefore(insert_child, ref_child->nextSibling(), editing_state);
  }
}

void CompositeEditCommand::InsertNodeAt(Node* insert_child,
                                        const Position& editing_position,
                                        EditingState* editing_state) {
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  ABORT_EDITING_COMMAND_IF(!IsEditablePosition(editing_position));
  // For editing positions like [table, 0], insert before the table,
  // likewise for replaced elements, brs, etc.
  Position p = editing_position.ParentAnchoredEquivalent();
  Node* ref_child = p.AnchorNode();
  int offset = p.OffsetInContainerNode();

  auto* ref_child_text_node = DynamicTo<Text>(ref_child);
  if (CanHaveChildrenForEditing(ref_child)) {
    Node* child = ref_child->firstChild();
    for (int i = 0; child && i < offset; i++)
      child = child->nextSibling();
    if (child)
      InsertNodeBefore(insert_child, child, editing_state);
    else
      AppendNode(insert_child, To<ContainerNode>(ref_child), editing_state);
  } else if (CaretMinOffset(ref_child) >= offset) {
    InsertNodeBefore(insert_child, ref_child, editing_state);
  } else if (ref_child_text_node && CaretMaxOffset(ref_child) > offset) {
    SplitTextNode(ref_child_text_node, offset);

    // Mutation events (bug 22634) from the text node insertion may have
    // removed the refChild
    if (!ref_child->isConnected())
      return;
    InsertNodeBefore(insert_child, ref_child, editing_state);
  } else {
    InsertNodeAfter(insert_child, ref_child, editing_state);
  }
}

void CompositeEditCommand::AppendNode(Node* node,
                                      ContainerNode* parent,
                                      EditingState* editing_state) {
  // When cloneParagraphUnderNewElement() clones the fallback content
  // of an OBJECT element, the ASSERT below may fire since the return
  // value of canHaveChildrenForEditing is not reliable until the layout
  // object of the OBJECT is created. Hence we ignore this check for OBJECTs.
  // TODO(yosin): We should move following |ABORT_EDITING_COMMAND_IF|s to
  // |AppendNodeCommand|.
  // TODO(yosin): We should get rid of |canHaveChildrenForEditing()|, since
  // |cloneParagraphUnderNewElement()| attempt to clone non-well-formed HTML,
  // produced by JavaScript.
  auto* parent_element = DynamicTo<Element>(parent);
  ABORT_EDITING_COMMAND_IF(!CanHaveChildrenForEditing(parent) &&
                           !(parent_element && parent_element->TagQName() ==
                                                   html_names::kObjectTag));
  ABORT_EDITING_COMMAND_IF(!IsEditable(*parent) && parent->InActiveDocument());
  ApplyCommandToComposite(MakeGarbageCollected<AppendNodeCommand>(parent, node),
                          editing_state);
}

void CompositeEditCommand::RemoveAllChildrenIfPossible(
    ContainerNode* container,
    EditingState* editing_state,
    ShouldAssumeContentIsAlwaysEditable
        should_assume_content_is_always_editable) {
  Node* child = container->firstChild();
  while (child) {
    Node* const next = child->nextSibling();
    RemoveNode(child, editing_state, should_assume_content_is_always_editable);
    if (editing_state->IsAborted())
      return;
    if (next && next->parentNode() != container) {
      // |RemoveNode()| moves |next| outside |node|.
      return;
    }
    child = next;
  }
}

void CompositeEditCommand::RemoveChildrenInRange(Node* node,
                                                 unsigned from,
                                                 unsigned to,
                                                 EditingState* editing_state) {
  HeapVector<Member<Node>> children;
  Node* child = NodeTraversal::ChildAt(*node, from);
  for (unsigned i = from; child && i < to; i++, child = child->nextSibling())
    children.push_back(child);

  size_t size = children.size();
  for (wtf_size_t i = 0; i < size; ++i) {
    RemoveNode(children[i].Release(), editing_state);
    if (editing_state->IsAborted())
      return;
  }
}

void CompositeEditCommand::RemoveNode(
    Node* node,
    EditingState* editing_state,
    ShouldAssumeContentIsAlwaysEditable
        should_assume_content_is_always_editable) {
  if (!node || !node->NonShadowBoundaryParentNode())
    return;
  ABORT_EDITING_COMMAND_IF(!node->GetDocument().GetFrame());
  ApplyCommandToComposite(MakeGarbageCollected<RemoveNodeCommand>(
                              node, should_assume_content_is_always_editable),
                          editing_state);
}

void CompositeEditCommand::RemoveNodePreservingChildren(
    Node* node,
    EditingState* editing_state,
    ShouldAssumeContentIsAlwaysEditable
        should_assume_content_is_always_editable) {
  ABORT_EDITING_COMMAND_IF(!node->GetDocument().GetFrame());
  ApplyCommandToComposite(
      MakeGarbageCollected<RemoveNodePreservingChildrenCommand>(
          node, should_assume_content_is_always_editable),
      editing_state);
}

void CompositeEditCommand::RemoveNodeAndPruneAncestors(
    Node* node,
    EditingState* editing_state,
    Node* exclude_node) {
  DCHECK_NE(node, exclude_node);
  ContainerNode* parent = node->parentNode();
  RemoveNode(node, editing_state);
  if (editing_state->IsAborted())
    return;
  Prune(parent, editing_state, exclude_node);
}

void CompositeEditCommand::MoveRemainingSiblingsToNewParent(
    Node* node,
    Node* past_last_node_to_move,
    Element* new_parent,
    EditingState* editing_state) {
  NodeVector nodes_to_remove;

  for (; node && node != past_last_node_to_move; node = node->nextSibling())
    nodes_to_remove.push_back(node);

  for (unsigned i = 0; i < nodes_to_remove.size(); i++) {
    RemoveNode(nodes_to_remove[i], editing_state);
    if (editing_state->IsAborted())
      return;
    AppendNode(nodes_to_remove[i], new_parent, editing_state);
    if (editing_state->IsAborted())
      return;
  }
}

void CompositeEditCommand::UpdatePositionForNodeRemovalPreservingChildren(
    Position& position,
    Node& node) {
  int offset =
      position.IsOffsetInAnchor() ? position.OffsetInContainerNode() : 0;
  position = ComputePositionForNodeRemoval(position, node);
  if (offset == 0)
    return;
  position = Position::CreateWithoutValidationDeprecated(
      *position.ComputeContainerNode(), offset);
}

HTMLSpanElement*
CompositeEditCommand::ReplaceElementWithSpanPreservingChildrenAndAttributes(
    HTMLElement* node) {
  // It would also be possible to implement all of ReplaceNodeWithSpanCommand
  // as a series of existing smaller edit commands.  Someone who wanted to
  // reduce the number of edit commands could do so here.
  auto* command = MakeGarbageCollected<ReplaceNodeWithSpanCommand>(node);
  // ReplaceNodeWithSpanCommand is never aborted.
  ApplyCommandToComposite(command, ASSERT_NO_EDITING_ABORT);
  // Returning a raw pointer here is OK because the command is retained by
  // applyCommandToComposite (thus retaining the span), and the span is also
  // in the DOM tree, and thus alive whie it has a parent.
  DCHECK(command->SpanElement()->isConnected()) << command->SpanElement();
  return command->SpanElement();
}

void CompositeEditCommand::Prune(Node* node,
                                 EditingState* editing_state,
                                 Node* exclude_node) {
  if (Node* highest_node_to_remove =
          HighestNodeToRemoveInPruning(node, exclude_node))
    RemoveNode(highest_node_to_remove, editing_state);
}

void CompositeEditCommand::SplitTextNode(Text* node, unsigned offset) {
  // SplitTextNodeCommand is never aborted.
  ApplyCommandToComposite(
      MakeGarbageCollected<SplitTextNodeCommand>(node, offset),
      ASSERT_NO_EDITING_ABORT);
}

void CompositeEditCommand::SplitElement(Element* element, Node* at_child) {
  // SplitElementCommand is never aborted.
  ApplyCommandToComposite(
      MakeGarbageCollected<SplitElementCommand>(element, at_child),
      ASSERT_NO_EDITING_ABORT);
}

void CompositeEditCommand::MergeIdenticalElements(Element* first,
                                                  Element* second,
                                                  EditingState* editing_state) {
  DCHECK(!first->IsDescendantOf(second)) << first << " " << second;
  DCHECK_NE(second, first);
  if (first->nextSibling() != second) {
    RemoveNode(second, editing_state);
    if (editing_state->IsAborted())
      return;
    InsertNodeAfter(second, first, editing_state);
    if (editing_state->IsAborted())
      return;
  }
  ApplyCommandToComposite(
      MakeGarbageCollected<MergeIdenticalElementsCommand>(first, second),
      editing_state);
}

void CompositeEditCommand::WrapContentsInDummySpan(Element* element) {
  // WrapContentsInDummySpanCommand is never aborted.
  ApplyCommandToComposite(
      MakeGarbageCollected<WrapContentsInDummySpanCommand>(element),
      ASSERT_NO_EDITING_ABORT);
}

void CompositeEditCommand::SplitTextNodeContainingElement(Text* text,
                                                          unsigned offset) {
  // SplitTextNodeContainingElementCommand is never aborted.
  ApplyCommandToComposite(
      MakeGarbageCollected<SplitTextNodeContainingElementCommand>(text, offset),
      ASSERT_NO_EDITING_ABORT);
}

void CompositeEditCommand::InsertTextIntoNode(Text* node,
                                              unsigned offset,
                                              const String& text) {
  // InsertIntoTextNodeCommand is never aborted.
  if (!text.empty())
    ApplyCommandToComposite(
        MakeGarbageCollected<InsertIntoTextNodeCommand>(node, offset, text),
        ASSERT_NO_EDITING_ABORT);
}

void CompositeEditCommand::DeleteTextFromNode(Text* node,
                                              unsigned offset,
                                              unsigned count) {
  // DeleteFromTextNodeCommand is never aborted.
  ApplyCommandToComposite(
      MakeGarbageCollected<DeleteFromTextNodeCommand>(node, offset, count),
      ASSERT_NO_EDITING_ABORT);
}

void CompositeEditCommand::ReplaceTextInNode(Text* node,
                                             unsigned offset,
                                             unsigned count,
                                             const String& replacement_text) {
  // SetCharacterDataCommand is never aborted.
  ApplyCommandToComposite(MakeGarbageCollected<SetCharacterDataCommand>(
                              node, offset, count, replacement_text),
                          ASSERT_NO_EDITING_ABORT);
}

Position CompositeEditCommand::ReplaceSelectedTextInNode(const String& text) {
  const Position& start = EndingSelection().Start();
  const Position& end = EndingSelection().End();
  auto* text_node = DynamicTo<Text>(start.ComputeContainerNode());
  if (!text_node || text_node != end.ComputeContainerNode() ||
      IsTabHTMLSpanElementTextNode(text_node))
    return Position();

  ReplaceTextInNode(text_node, start.OffsetInContainerNode(),
                    end.OffsetInContainerNode() - start.OffsetInContainerNode(),
                    text);

  return Position(text_node, start.OffsetInContainerNode() + text.length());
}

Position CompositeEditCommand::PositionOutsideTabSpan(const Position& pos) {
  Node* anchor_node = pos.AnchorNode();
  if (!IsTabHTMLSpanElementTextNode(anchor_node)) {
    return pos;
  }

  switch (pos.AnchorType()) {
    case PositionAnchorType::kAfterChildren:
      NOTREACHED();
    case PositionAnchorType::kOffsetInAnchor:
      break;
    case PositionAnchorType::kBeforeAnchor:
      return Position::InParentBeforeNode(*anchor_node);
    case PositionAnchorType::kAfterAnchor:
      return Position::InParentAfterNode(*anchor_node);
  }

  HTMLSpanElement* tab_span = TabSpanElement(pos.ComputeContainerNode());
  DCHECK(tab_span);

  // TODO(editing-dev): Hoist this UpdateStyleAndLayout
  // to the callers. See crbug.com/590369 for details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  if (pos.OffsetInContainerNode() <= CaretMinOffset(pos.ComputeContainerNode()))
    return Position::InParentBeforeNode(*tab_span);

  if (pos.OffsetInContainerNode() >=
      CaretMaxOffset(pos.ComputeContainerNode())) {
    return anchor_node->HasNextSibling() &&
                   RuntimeEnabledFeatures::
                       PositionOutsideTabSpanCheckSiblingNodeEnabled()
               ? Position::InParentAfterNode(*anchor_node)
               : Position::InParentAfterNode(*tab_span);
  }

  SplitTextNodeContainingElement(To<Text>(pos.ComputeContainerNode()),
                                 pos.OffsetInContainerNode());
  return Position::InParentBeforeNode(*tab_span);
}

void CompositeEditCommand::InsertNodeAtTabSpanPosition(
    Node* node,
    const Position& pos,
    EditingState* editing_state) {
  // insert node before, after, or at split of tab span
  InsertNodeAt(node, PositionOutsideTabSpan(pos), editing_state);
}

bool CompositeEditCommand::DeleteSelection(
    EditingState* editing_state,
    const DeleteSelectionOptions& options) {
  if (!EndingSelection().IsRange())
    return true;

  ApplyCommandToComposite(
      MakeGarbageCollected<DeleteSelectionCommand>(GetDocument(), options),
      editing_state);
  if (editing_state->IsAborted())
    return false;

  if (!EndingSelection().IsValidFor(GetDocument())) {
    editing_state->Abort();
    return false;
  }
  return true;
}

void CompositeEditCommand::RemoveCSSProperty(Element* element,
                                             CSSPropertyID property) {
  // RemoveCSSPropertyCommand is never aborted.
  ApplyCommandToComposite(MakeGarbageCollected<RemoveCSSPropertyCommand>(
                              GetDocument(), element, property),
                          ASSERT_NO_EDITING_ABORT);
}

void CompositeEditCommand::RemoveElementAttribute(
    Element* element,
    const QualifiedName& attribute) {
  SetNodeAttribute(element, attribute, AtomicString());
}

void CompositeEditCommand::SetNodeAttribute(Element* element,
                                            const QualifiedName& attribute,
                                            const AtomicString& value) {
  // SetNodeAttributeCommand is never aborted.
  ApplyCommandToComposite(
      MakeGarbageCollected<SetNodeAttributeCommand>(element, attribute, value),
      ASSERT_NO_EDITING_ABORT);
}

bool CompositeEditCommand::CanRebalance(const Position& position) const {
  // TODO(editing-dev): Use of UpdateStyleAndLayout()
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  auto* text_node = DynamicTo<Text>(position.ComputeContainerNode());
  if (!position.IsOffsetInAnchor() || !text_node ||
      !IsRichlyEditable(*text_node)) {
    return false;
  }

  if (text_node->length() == 0)
    return false;

  LayoutText* layout_text = text_node->GetLayoutObject();
  if (layout_text && layout_text->Style()->ShouldPreserveWhiteSpaces()) {
    return false;
  }

  return true;
}

// FIXME: Doesn't go into text nodes that contribute adjacent text (siblings,
// cousins, etc).
void CompositeEditCommand::RebalanceWhitespaceAt(const Position& position) {
  Node* node = position.ComputeContainerNode();
  if (!CanRebalance(position))
    return;

  // If the rebalance is for the single offset, and neither text[offset] nor
  // text[offset - 1] are some form of whitespace, do nothing.
  int offset = position.ComputeOffsetInContainerNode();
  String text = To<Text>(node)->data();
  if (!IsWhitespace(text[offset])) {
    offset--;
    if (offset < 0 || !IsWhitespace(text[offset]))
      return;
  }

  RebalanceWhitespaceOnTextSubstring(To<Text>(node),
                                     position.OffsetInContainerNode(),
                                     position.OffsetInContainerNode());
}

void CompositeEditCommand::RebalanceWhitespaceOnTextSubstring(Text* text_node,
                                                              int start_offset,
                                                              int end_offset) {
  String text = text_node->data();
  DCHECK(!text.empty());

  // Set upstream and downstream to define the extent of the whitespace
  // surrounding text[offset].
  int upstream = start_offset;
  while (upstream > 0 &&
         IsWhitespaceForRebalance(*text_node, text[upstream - 1])) {
    upstream--;
  }

  int downstream = end_offset;
  while ((unsigned)downstream < text.length() &&
         IsWhitespaceForRebalance(*text_node, text[downstream])) {
    downstream++;
  }

  int length = downstream - upstream;
  if (!length)
    return;

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  VisiblePosition visible_upstream_pos =
      CreateVisiblePosition(Position(text_node, upstream));
  VisiblePosition visible_downstream_pos =
      CreateVisiblePosition(Position(text_node, downstream));

  String string = text.Substring(upstream, length);
  // FIXME: Because of the problem mentioned at the top of this function, we
  // must also use nbsps at the start/end of the string because this function
  // doesn't get all surrounding whitespace, just the whitespace in t
"""


```