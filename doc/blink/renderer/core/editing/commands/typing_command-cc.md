Response:
The user wants a summary of the functionality of the `typing_command.cc` file in the Chromium Blink engine. I need to:

1. **Identify the core purpose of the file:** Based on the name and included headers, it's likely responsible for handling text input and related editing operations.
2. **List key functionalities:**  This involves going through the code and identifying the main actions performed by the `TypingCommand` class and its related helper functions.
3. **Relate to web technologies:**  Explain how these functionalities connect to Javascript, HTML, and CSS.
4. **Provide examples with assumptions:** For complex logic, create hypothetical scenarios showing input and expected output.
5. **Illustrate common errors:**  Point out potential mistakes users or developers might make that could lead to the execution of this code.
6. **Describe user interaction flow:** Explain how user actions in a web browser can trigger the code in this file.
7. **Focus on the content provided in part 1:** Since this is part 1, I should only analyze the code snippet given.
```
这是目录为blink/renderer/core/editing/commands/typing_command.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

**blink/renderer/core/editing/commands/typing_command.cc 的功能 (第 1 部分归纳)**

该文件的主要功能是定义了 `TypingCommand` 类，这个类负责处理各种文本输入和编辑操作。它可以被认为是 Blink 引擎中处理用户在可编辑区域进行输入的核心机制。

**主要功能点（基于提供的代码片段）：**

1. **处理文本插入 (InsertText):**
   - 接收要插入的文本 (`text_to_insert_`)。
   - 区分普通文本插入和增量文本插入 (`is_incremental_insertion_`)，增量插入通常用于 IME 输入。
   - 触发 `BeforeTextInsertedEvent` 和 `TextInputEvent` 等事件，允许 Javascript 代码拦截和修改插入行为。
   - 考虑文本组合状态 (`composition_type_`)，处理输入法相关的操作。
   - 支持在插入后选中插入的文本 (`select_inserted_text_`)。
   - 将文本插入操作分解为不包含换行符的插入 (`InsertTextRunWithoutNewlines`)，并处理包含换行符的文本。

2. **处理删除操作 (DeleteSelection, DeleteKeyPressed, ForwardDeleteKeyPressed):**
   - 可以删除选定的文本。
   - 可以模拟按下 Delete 键和 Forward Delete 键的行为，并能按字符、单词等粒度删除。
   - 可以与“kill ring”功能关联 (`kill_ring_`)，用于实现剪切和粘贴的历史记录。

3. **处理换行和段落分隔 (InsertLineBreak, InsertParagraphSeparator, InsertParagraphSeparatorInQuotedContent):**
   - 插入换行符 (`<br>`)。
   - 插入段落分隔符（通常是 `<p>` 标签或类似的块级元素）。
   - 特殊处理引用内容中的段落分隔。

4. **管理连续的输入操作:**
   - 实现了 `LastTypingCommandIfStillOpenForTyping` 机制，用于判断是否可以延续之前的输入命令，将多个连续的输入操作合并到一个撤销步骤中。
   - `open_for_more_typing_` 标志用于控制是否允许继续向当前 `TypingCommand` 添加操作。
   - `CloseTyping` 用于显式关闭一个 `TypingCommand`。

5. **事件分发:**
   - 负责分发 `BeforeTextInsertedEvent` 和 `TextInputEvent` 事件，与 JavaScript 交互。

6. **处理 Undo/Redo:**
   - 作为 `CompositeEditCommand` 的子类，能够将一系列操作作为一个原子操作进行撤销/重做。

7. **获取输入类型 (GetInputType):**
   -  根据不同的命令类型和组合状态，确定对应的 `InputEvent::InputType`，用于更精细地描述输入事件。

**与 Javascript, HTML, CSS 的关系和举例:**

* **Javascript:**
    * **`BeforeTextInsertedEvent`:** 当用户输入文本时，会触发此事件。Javascript 可以监听这个事件，并在文本真正插入之前修改或阻止插入。
        * **例子:** 一个富文本编辑器可能使用此事件来实现自动补全或内容过滤功能。当用户输入 "@" 时，Javascript 可以监听此事件并弹出用户列表供选择，然后修改要插入的文本。
        * **假设输入:** 用户在可编辑的 `<div>` 中输入 "hel"，此时 Javascript 监听了 `beforetextinserted` 事件。
        * **假设输出:** Javascript 代码可能检查到用户可能想输入 "hello"，于是将事件的 `text` 属性修改为 "lo"，最终插入 "hello"。
    * **`TextInputEvent`:** 在文本插入之后触发，通知 Javascript 发生了文本输入。
        * **例子:**  一个实时搜索框可能会监听 `textinput` 事件，当用户输入时立即发起搜索请求。
        * **假设输入:** 用户在输入框中输入 "a"。
        * **假设输出:** Javascript 监听 `textinput` 事件，获取到文本 "a"，并使用此文本向服务器发送搜索请求。

* **HTML:**
    * `TypingCommand` 操作直接影响 HTML 文档结构和内容。例如，插入文本会向 DOM 树中添加文本节点或元素。插入换行符会创建 `<br>` 元素，插入段落分隔符会创建 `<p>` 元素。
    * **例子:**  用户在一个 `<div contenteditable="true">` 中输入 "Hello"，`TypingCommand` 会在 `div` 中创建一个文本节点包含 "Hello"。
    * **例子:** 用户在文本区域按下 Enter 键，`TypingCommand` 会根据上下文插入 `<br>` 或 `<p>` 标签。

* **CSS:**
    * CSS 影响可编辑区域的样式和布局，从而影响用户输入时的视觉呈现。`TypingCommand` 本身不直接操作 CSS，但 CSS 的样式会影响光标的位置、换行的行为等，而这些会影响 `TypingCommand` 的执行逻辑。
    * **例子:**  CSS 可能会设置 `white-space: pre-wrap;`，这会影响换行的处理方式，`TypingCommand` 在插入换行符时需要考虑这种样式的影响。

**用户或编程常见的使用错误举例:**

* **错误地阻止 `BeforeTextInsertedEvent` 的默认行为：**  如果 Javascript 代码在 `BeforeTextInsertedEvent` 处理器中错误地调用了 `preventDefault()`，可能会阻止文本插入，导致用户输入无效。
    * **假设输入:** 用户尝试输入字符 "a"。
    * **错误情景:**  一个错误的 Javascript 事件监听器捕获了 `beforetextinserted` 事件并调用了 `preventDefault()`。
    * **结果:** 字符 "a" 没有被插入到文档中。
* **在 `TextInputEvent` 处理过程中修改了文档结构导致异常：**  在 `TextInputEvent` 处理函数中执行了某些 DOM 操作，导致了 `TypingCommand` 执行过程中的某些假设不再成立，可能会引发错误或崩溃。
    * **假设输入:** 用户输入字符 "b"。
    * **错误情景:**  在 `textinput` 事件的处理函数中，Javascript 代码移除了当前输入焦点所在的元素。
    * **结果:**  `TypingCommand` 可能会因为找不到预期的 DOM 节点而失败。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户聚焦到可编辑元素：** 用户点击或使用 Tab 键将焦点移动到一个带有 `contenteditable="true"` 属性的 HTML 元素，或者是一个 `<textarea>` 或 `<input type="text">` 元素。
2. **用户进行输入操作：**
   - **键入字符：** 用户按下键盘上的字符键，例如字母、数字、符号。
   - **按下删除键：** 用户按下 Backspace 或 Delete 键。
   - **按下换行键：** 用户按下 Enter 键。
   - **使用输入法 (IME)：** 用户使用输入法输入非拉丁字符。
3. **浏览器事件触发：** 用户的输入操作会触发浏览器中的底层事件，例如 `keydown`, `keypress`, `keyup`, `textInput`, `compositionstart`, `compositionupdate`, `compositionend` 等。
4. **Blink 引擎处理事件：** Blink 引擎接收到这些事件，并根据事件类型和目标元素进行处理。对于可编辑元素的文本输入操作，会进入编辑模块。
5. **创建或重用 `TypingCommand`：**
   - 如果是新的输入序列，Blink 会创建一个新的 `TypingCommand` 对象。
   - 如果是连续的输入操作，可能会重用之前创建的 `TypingCommand` 对象 (通过 `LastTypingCommandIfStillOpenForTyping`)。
6. **执行 `TypingCommand` 的 `Apply()` 方法：**  `TypingCommand` 的 `Apply()` 方法会被调用，根据具体的命令类型（插入、删除、换行等）执行相应的操作。
7. **修改 DOM 树和 Selection：** `TypingCommand` 会修改底层的 DOM 树结构，插入或删除节点，并更新用户的光标位置（Selection）。
8. **触发相关事件：** 在 DOM 树发生变化前后，会触发 `BeforeTextInsertedEvent`, `TextInputEvent`, `input` 等事件。

**总结:**

`typing_command.cc` 中定义的 `TypingCommand` 类是 Blink 引擎中处理用户文本输入的核心组件。它负责接收用户的输入，将其转化为对 DOM 树的修改，并管理撤销/重做以及与 Javascript 的交互。理解 `TypingCommand` 的工作原理对于调试与文本编辑相关的 Bug 非常重要。
```
### 提示词
```
这是目录为blink/renderer/core/editing/commands/typing_command.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2005, 2006, 2007, 2008 Apple Inc.  All rights reserved.
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

#include "third_party/blink/renderer/core/editing/commands/typing_command.h"

#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/scoped_event_queue.h"
#include "third_party/blink/renderer/core/editing/commands/break_blockquote_command.h"
#include "third_party/blink/renderer/core/editing/commands/delete_selection_command.h"
#include "third_party/blink/renderer/core/editing/commands/delete_selection_options.h"
#include "third_party/blink/renderer/core/editing/commands/editing_commands_utilities.h"
#include "third_party/blink/renderer/core/editing/commands/insert_incremental_text_command.h"
#include "third_party/blink/renderer/core/editing/commands/insert_line_break_command.h"
#include "third_party/blink/renderer/core/editing/commands/insert_paragraph_separator_command.h"
#include "third_party/blink/renderer/core/editing/commands/insert_text_command.h"
#include "third_party/blink/renderer/core/editing/editing_behavior.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/plain_text_range.h"
#include "third_party/blink/renderer/core/editing/selection_modifier.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/events/before_text_inserted_event.h"
#include "third_party/blink/renderer/core/events/text_event.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

namespace {

bool IsValidDocument(const Document& document) {
  return document.GetFrame() && document.GetFrame()->GetDocument() == &document;
}

String DispatchBeforeTextInsertedEvent(const String& text,
                                       const SelectionInDOMTree& selection,
                                       EditingState* editing_state) {
  // We use SelectionForUndoStep because it is resilient to DOM
  // mutation.
  const SelectionForUndoStep& selection_as_undo_step =
      SelectionForUndoStep::From(selection);
  Node* start_node = selection_as_undo_step.Start().ComputeContainerNode();
  if (!start_node || !RootEditableElement(*start_node))
    return text;

  // Send BeforeTextInsertedEvent. The event handler will update text if
  // necessary.
  const Document& document = start_node->GetDocument();
  auto* evt = MakeGarbageCollected<BeforeTextInsertedEvent>(text);
  RootEditableElement(*start_node)->DefaultEventHandler(*evt);
  if (IsValidDocument(document) && selection_as_undo_step.IsValidFor(document))
    return evt->GetText();
  // editing/inserting/webkitBeforeTextInserted-removes-frame.html
  // and
  // editing/inserting/webkitBeforeTextInserted-disconnects-selection.html
  // reaches here.
  editing_state->Abort();
  return String();
}

DispatchEventResult DispatchTextInputEvent(LocalFrame* frame,
                                           const String& text,
                                           EditingState* editing_state) {
  const Document& document = *frame->GetDocument();
  Element* target = document.FocusedElement();
  if (!target)
    return DispatchEventResult::kCanceledBeforeDispatch;

  // Send TextInputEvent. Unlike BeforeTextInsertedEvent, there is no need to
  // update text for TextInputEvent as it doesn't have the API to modify text.
  TextEvent* event = TextEvent::Create(frame->DomWindow(), text,
                                       kTextEventInputIncrementalInsertion);
  event->SetUnderlyingEvent(nullptr);
  DispatchEventResult result = target->DispatchEvent(*event);
  if (IsValidDocument(document))
    return result;
  // editing/inserting/insert-text-remove-iframe-on-textInput-event.html
  // reaches here.
  editing_state->Abort();
  return result;
}

PlainTextRange GetSelectionOffsets(const SelectionInDOMTree& selection) {
  const EphemeralRange range = selection.ComputeRange();
  if (range.IsNull())
    return PlainTextRange();
  ContainerNode* const editable =
      RootEditableElementOrTreeScopeRootNodeOf(selection.Anchor());
  DCHECK(editable);
  return PlainTextRange::Create(*editable, range);
}

SelectionInDOMTree CreateSelection(const wtf_size_t start,
                                   const wtf_size_t end,
                                   Element* element) {
  const EphemeralRange& start_range =
      PlainTextRange(0, static_cast<int>(start)).CreateRange(*element);
  DCHECK(start_range.IsNotNull());
  const Position& start_position = start_range.EndPosition();

  const EphemeralRange& end_range =
      PlainTextRange(0, static_cast<int>(end)).CreateRange(*element);
  DCHECK(end_range.IsNotNull());
  const Position& end_position = end_range.EndPosition();

  const SelectionInDOMTree& selection =
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(start_position, end_position)
          .Build();
  return selection;
}

bool CanAppendNewLineFeedToSelection(const SelectionInDOMTree& selection,
                                     EditingState* editing_state) {
  // We use SelectionForUndoStep because it is resilient to DOM
  // mutation.
  const SelectionForUndoStep& selection_as_undo_step =
      SelectionForUndoStep::From(selection);
  Element* element = selection_as_undo_step.RootEditableElement();
  if (!element)
    return false;

  const Document& document = element->GetDocument();
  auto* event = MakeGarbageCollected<BeforeTextInsertedEvent>(String("\n"));
  element->DefaultEventHandler(*event);
  // event may invalidate frame or selection
  if (IsValidDocument(document) && selection_as_undo_step.IsValidFor(document))
    return event->GetText().length();
  // editing/inserting/webkitBeforeTextInserted-removes-frame.html
  // and
  // editing/inserting/webkitBeforeTextInserted-disconnects-selection.html
  // reaches here.
  editing_state->Abort();
  return false;
}

// Example: <div><img style="display:block">|<br></p>
// See "editing/deleting/delete_after_block_image.html"
Position AfterBlockIfBeforeAnonymousPlaceholder(const Position& position) {
  if (!position.IsBeforeAnchor())
    return Position();
  const LayoutObject* const layout_object =
      position.AnchorNode()->GetLayoutObject();
  if (!layout_object || !layout_object->IsBR() ||
      layout_object->NextSibling() || layout_object->PreviousSibling())
    return Position();
  const LayoutObject* const parent = layout_object->Parent();
  if (!parent || !parent->IsAnonymous())
    return Position();
  const LayoutObject* const previous = parent->PreviousSibling();
  if (!previous || !previous->NonPseudoNode())
    return Position();
  return Position::AfterNode(*previous->NonPseudoNode());
}

}  // anonymous namespace

TypingCommand::TypingCommand(Document& document,
                             CommandType command_type,
                             const String& text_to_insert,
                             Options options,
                             TextGranularity granularity,
                             TextCompositionType composition_type)
    : CompositeEditCommand(document),
      command_type_(command_type),
      text_to_insert_(text_to_insert),
      open_for_more_typing_(true),
      select_inserted_text_(options & kSelectInsertedText),
      smart_delete_(options & kSmartDelete),
      granularity_(granularity),
      composition_type_(composition_type),
      kill_ring_(options & kKillRing),
      opened_by_backward_delete_(false) {
  UpdatePreservesTypingStyle(command_type_);
}

void TypingCommand::DeleteSelection(Document& document, Options options) {
  LocalFrame* frame = document.GetFrame();
  DCHECK(frame);

  if (!frame->Selection().ComputeVisibleSelectionInDOMTree().IsRange()) {
    return;
  }

  if (TypingCommand* last_typing_command =
          LastTypingCommandIfStillOpenForTyping(frame)) {
    UpdateSelectionIfDifferentFromCurrentSelection(last_typing_command, frame);

    if (RuntimeEnabledFeatures::
            ResetInputTypeToNoneBeforeCharacterInputEnabled()) {
      last_typing_command->input_type_ = InputEvent::InputType::kNone;
    }
    // InputMethodController uses this function to delete composition
    // selection.  It won't be aborted.
    last_typing_command->DeleteSelection(options & kSmartDelete,
                                         ASSERT_NO_EDITING_ABORT);
    return;
  }

  MakeGarbageCollected<TypingCommand>(document, kDeleteSelection, "", options)
      ->Apply();
}

void TypingCommand::DeleteSelectionIfRange(
    const SelectionForUndoStep& selection,
    EditingState* editing_state) {
  if (!selection.IsRange())
    return;
  // Although the 'selection' to delete is indeed a Range, it may have been
  // built from a Caret selection; in that case we don't want to expand so that
  // the table structure is deleted as well.
  bool expand_for_special = EndingSelection().IsRange();
  ApplyCommandToComposite(
      MakeGarbageCollected<DeleteSelectionCommand>(
          selection, DeleteSelectionOptions::Builder()
                         .SetSmartDelete(smart_delete_)
                         .SetMergeBlocksAfterDelete(true)
                         .SetExpandForSpecialElements(expand_for_special)
                         .SetSanitizeMarkup(true)
                         .Build()),
      editing_state);
}

void TypingCommand::DeleteKeyPressed(Document& document,
                                     Options options,
                                     TextGranularity granularity) {
  if (granularity == TextGranularity::kCharacter) {
    LocalFrame* frame = document.GetFrame();
    if (TypingCommand* last_typing_command =
            LastTypingCommandIfStillOpenForTyping(frame)) {
      // If the last typing command is not Delete, open a new typing command.
      // We need to group continuous delete commands alone in a single typing
      // command.
      if (last_typing_command->CommandTypeOfOpenCommand() == kDeleteKey) {
        UpdateSelectionIfDifferentFromCurrentSelection(last_typing_command,
                                                       frame);
        EditingState editing_state;
        if (RuntimeEnabledFeatures::
                ResetInputTypeToNoneBeforeCharacterInputEnabled()) {
          last_typing_command->input_type_ = InputEvent::InputType::kNone;
        }
        last_typing_command->DeleteKeyPressed(granularity, options & kKillRing,
                                              &editing_state);
        return;
      }
    }
  }

  MakeGarbageCollected<TypingCommand>(document, kDeleteKey, "", options,
                                      granularity)
      ->Apply();
}

void TypingCommand::ForwardDeleteKeyPressed(Document& document,
                                            EditingState* editing_state,
                                            Options options,
                                            TextGranularity granularity) {
  // FIXME: Forward delete in TextEdit appears to open and close a new typing
  // command.
  if (granularity == TextGranularity::kCharacter) {
    LocalFrame* frame = document.GetFrame();
    if (TypingCommand* last_typing_command =
            LastTypingCommandIfStillOpenForTyping(frame)) {
      UpdateSelectionIfDifferentFromCurrentSelection(last_typing_command,
                                                     frame);
      // Reset the 'input_type_' to default value. The actual 'input_type_' will
      // be determined later in TypingCommand::GetInputType() based on the
      // 'command_type_'
      last_typing_command->input_type_ = InputEvent::InputType::kNone;
      last_typing_command->ForwardDeleteKeyPressed(
          granularity, options & kKillRing, editing_state);
      return;
    }
  }

  MakeGarbageCollected<TypingCommand>(document, kForwardDeleteKey, "", options,
                                      granularity)
      ->Apply();
}

String TypingCommand::TextDataForInputEvent() const {
  if (commands_.empty() || IsIncrementalInsertion())
    return text_to_insert_;
  return commands_.back()->TextDataForInputEvent();
}

void TypingCommand::UpdateSelectionIfDifferentFromCurrentSelection(
    TypingCommand* typing_command,
    LocalFrame* frame) {
  DCHECK(frame);
  const SelectionInDOMTree& current_selection =
      frame->Selection().GetSelectionInDOMTree();
  if (current_selection == typing_command->EndingSelection().AsSelection())
    return;

  typing_command->SetStartingSelection(
      SelectionForUndoStep::From(current_selection));
  typing_command->SetEndingSelection(
      SelectionForUndoStep::From(current_selection));
}

void TypingCommand::InsertText(Document& document,
                               const String& text,
                               Options options,
                               TextCompositionType composition,
                               const bool is_incremental_insertion) {
  LocalFrame* frame = document.GetFrame();
  DCHECK(frame);
  EditingState editing_state;
  InsertText(document, text, frame->Selection().GetSelectionInDOMTree(),
             options, &editing_state, composition, is_incremental_insertion);
}

void TypingCommand::AdjustSelectionAfterIncrementalInsertion(
    LocalFrame* frame,
    const wtf_size_t selection_start,
    const wtf_size_t text_length,
    EditingState* editing_state) {
  if (!IsIncrementalInsertion())
    return;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. see http://crbug.com/590369 for more details.
  frame->GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  Element* element = frame->Selection()
                         .ComputeVisibleSelectionInDOMTree()
                         .RootEditableElement();

  // TODO(editing-dev): The text insertion should probably always leave the
  // selection in an editable region, but we know of at least one case where it
  // doesn't (see test case in crbug.com/767599). Return early in this case to
  // avoid a crash.
  if (!element) {
    editing_state->Abort();
    return;
  }

  const wtf_size_t new_end = selection_start + text_length;
  const SelectionInDOMTree& selection =
      CreateSelection(new_end, new_end, element);
  SetEndingSelection(SelectionForUndoStep::From(selection));
}

// FIXME: We shouldn't need to take selectionForInsertion. It should be
// identical to FrameSelection's current selection.
void TypingCommand::InsertText(
    Document& document,
    const String& text,
    const SelectionInDOMTree& passed_selection_for_insertion,
    Options options,
    EditingState* editing_state,
    TextCompositionType composition_type,
    const bool is_incremental_insertion,
    InputEvent::InputType input_type) {
  DCHECK(!document.NeedsLayoutTreeUpdate());
  LocalFrame* frame = document.GetFrame();
  DCHECK(frame);

  // We use SelectionForUndoStep because it is resilient to DOM
  // mutation.
  const SelectionForUndoStep& passed_selection_for_insertion_as_undo_step =
      SelectionForUndoStep::From(passed_selection_for_insertion);

  String new_text = text;
  if (composition_type != kTextCompositionUpdate) {
    new_text = DispatchBeforeTextInsertedEvent(
        text, passed_selection_for_insertion, editing_state);
    if (editing_state->IsAborted())
      return;
    ABORT_EDITING_COMMAND_IF(
        !passed_selection_for_insertion_as_undo_step.IsValidFor(document));
  }

  if (composition_type == kTextCompositionConfirm) {
    if (DispatchTextInputEvent(frame, new_text, editing_state) !=
        DispatchEventResult::kNotCanceled)
      return;
    // event handler might destroy document.
    if (editing_state->IsAborted())
      return;
    // editing/inserting/insert-text-nodes-disconnect-on-textinput-event.html
    // hits true for ABORT_EDITING_COMMAND_IF macro.
    ABORT_EDITING_COMMAND_IF(
        !passed_selection_for_insertion_as_undo_step.IsValidFor(document));
  }

  // Do nothing if no need to delete and insert.
  if (passed_selection_for_insertion_as_undo_step.IsCaret() && new_text.empty())
    return;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. see http://crbug.com/590369 for more details.
  document.UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  const PlainTextRange selection_offsets = GetSelectionOffsets(
      passed_selection_for_insertion_as_undo_step.AsSelection());
  if (selection_offsets.IsNull())
    return;
  const wtf_size_t selection_start = selection_offsets.Start();

  frame->GetEditor().NotifyAccessibilityOfDeletionOrInsertionInTextField(
      passed_selection_for_insertion_as_undo_step, /* is_deletion*/ false);

  // Set the starting and ending selection appropriately if we are using a
  // selection that is different from the current selection.  In the future, we
  // should change EditCommand to deal with custom selections in a general way
  // that can be used by all of the commands.
  if (TypingCommand* last_typing_command =
          LastTypingCommandIfStillOpenForTyping(frame)) {
    if (last_typing_command->EndingSelection() !=
        passed_selection_for_insertion_as_undo_step) {
      last_typing_command->SetStartingSelection(
          passed_selection_for_insertion_as_undo_step);
      last_typing_command->SetEndingSelection(
          passed_selection_for_insertion_as_undo_step);
    }

    last_typing_command->SetCompositionType(composition_type);
    last_typing_command->is_incremental_insertion_ = is_incremental_insertion;
    last_typing_command->selection_start_ = selection_start;
    last_typing_command->input_type_ = input_type;

    EventQueueScope event_queue_scope;
    last_typing_command->InsertTextInternal(
        new_text, options & kSelectInsertedText, editing_state);
    return;
  }

  TypingCommand* command = MakeGarbageCollected<TypingCommand>(
      document, kInsertText, new_text, options, TextGranularity::kCharacter,
      composition_type);
  const SelectionInDOMTree& current_selection =
      frame->Selection().GetSelectionInDOMTree();
  bool change_selection =
      current_selection !=
      passed_selection_for_insertion_as_undo_step.AsSelection();
  if (change_selection) {
    command->SetStartingSelection(passed_selection_for_insertion_as_undo_step);
    command->SetEndingSelection(passed_selection_for_insertion_as_undo_step);
  }
  command->is_incremental_insertion_ = is_incremental_insertion;
  command->selection_start_ = selection_start;
  command->input_type_ = input_type;
  ABORT_EDITING_COMMAND_IF(!command->Apply());

  if (change_selection) {
    const SelectionInDOMTree& current_selection_as_dom =
        frame->Selection().GetSelectionInDOMTree();
    command->SetEndingSelection(
        SelectionForUndoStep::From(current_selection_as_dom));
    frame->Selection().SetSelection(
        current_selection_as_dom,
        SetSelectionOptions::Builder()
            .SetIsDirectional(frame->Selection().IsDirectional())
            .Build());
  }
}

bool TypingCommand::InsertLineBreak(Document& document) {
  if (TypingCommand* last_typing_command =
          LastTypingCommandIfStillOpenForTyping(document.GetFrame())) {
    EditingState editing_state;
    EventQueueScope event_queue_scope;
    if (RuntimeEnabledFeatures::
            ResetInputTypeToNoneBeforeCharacterInputEnabled()) {
      last_typing_command->input_type_ = InputEvent::InputType::kNone;
    }
    last_typing_command->InsertLineBreak(&editing_state);
    return !editing_state.IsAborted();
  }

  return MakeGarbageCollected<TypingCommand>(document, kInsertLineBreak, "", 0)
      ->Apply();
}

bool TypingCommand::InsertParagraphSeparatorInQuotedContent(
    Document& document) {
  if (TypingCommand* last_typing_command =
          LastTypingCommandIfStillOpenForTyping(document.GetFrame())) {
    EditingState editing_state;
    EventQueueScope event_queue_scope;
    if (RuntimeEnabledFeatures::
            ResetInputTypeToNoneBeforeCharacterInputEnabled()) {
      last_typing_command->input_type_ = InputEvent::InputType::kNone;
    }
    last_typing_command->InsertParagraphSeparatorInQuotedContent(
        &editing_state);
    return !editing_state.IsAborted();
  }

  return MakeGarbageCollected<TypingCommand>(
             document, kInsertParagraphSeparatorInQuotedContent)
      ->Apply();
}

bool TypingCommand::InsertParagraphSeparator(Document& document) {
  if (TypingCommand* last_typing_command =
          LastTypingCommandIfStillOpenForTyping(document.GetFrame())) {
    EditingState editing_state;
    EventQueueScope event_queue_scope;
    if (RuntimeEnabledFeatures::
            ResetInputTypeToNoneBeforeCharacterInputEnabled()) {
      last_typing_command->input_type_ = InputEvent::InputType::kNone;
    }
    last_typing_command->InsertParagraphSeparator(&editing_state);
    return !editing_state.IsAborted();
  }

  return MakeGarbageCollected<TypingCommand>(document,
                                             kInsertParagraphSeparator, "", 0)
      ->Apply();
}

TypingCommand* TypingCommand::LastTypingCommandIfStillOpenForTyping(
    LocalFrame* frame) {
  DCHECK(frame);

  CompositeEditCommand* last_edit_command =
      frame->GetEditor().LastEditCommand();
  if (!last_edit_command || !last_edit_command->IsTypingCommand() ||
      !static_cast<TypingCommand*>(last_edit_command)->IsOpenForMoreTyping())
    return nullptr;

  return static_cast<TypingCommand*>(last_edit_command);
}

void TypingCommand::CloseTyping(LocalFrame* frame) {
  if (TypingCommand* last_typing_command =
          LastTypingCommandIfStillOpenForTyping(frame))
    last_typing_command->CloseTyping();
}

void TypingCommand::CloseTypingIfNeeded(LocalFrame* frame) {
  if (frame->GetDocument()->IsRunningExecCommand() ||
      frame->GetInputMethodController().HasComposition())
    return;
  if (TypingCommand* last_typing_command =
          LastTypingCommandIfStillOpenForTyping(frame))
    last_typing_command->CloseTyping();
}

void TypingCommand::DoApply(EditingState* editing_state) {
  if (EndingSelection().IsNone() ||
      !EndingSelection().IsValidFor(GetDocument()))
    return;

  if (command_type_ == kDeleteKey) {
    if (commands_.empty())
      opened_by_backward_delete_ = true;
  }

  switch (command_type_) {
    case kDeleteSelection:
      DeleteSelection(smart_delete_, editing_state);
      return;
    case kDeleteKey:
      DeleteKeyPressed(granularity_, kill_ring_, editing_state);
      return;
    case kForwardDeleteKey:
      ForwardDeleteKeyPressed(granularity_, kill_ring_, editing_state);
      return;
    case kInsertLineBreak:
      InsertLineBreak(editing_state);
      return;
    case kInsertParagraphSeparator:
      InsertParagraphSeparator(editing_state);
      return;
    case kInsertParagraphSeparatorInQuotedContent:
      InsertParagraphSeparatorInQuotedContent(editing_state);
      return;
    case kInsertText:
      InsertTextInternal(text_to_insert_, select_inserted_text_, editing_state);
      return;
  }

  NOTREACHED();
}

InputEvent::InputType TypingCommand::GetInputType() const {
  using InputType = InputEvent::InputType;

  if (composition_type_ != kTextCompositionNone)
    return InputType::kInsertCompositionText;

  if (input_type_ != InputType::kNone)
    return input_type_;

  switch (command_type_) {
    // TODO(editing-dev): |DeleteSelection| is used by IME but we don't have
    // direction info.
    case kDeleteSelection:
      return InputType::kDeleteContentBackward;
    case kDeleteKey:
      return DeletionInputTypeFromTextGranularity(DeleteDirection::kBackward,
                                                  granularity_);
    case kForwardDeleteKey:
      return DeletionInputTypeFromTextGranularity(DeleteDirection::kForward,
                                                  granularity_);
    case kInsertText:
      return InputType::kInsertText;
    case kInsertLineBreak:
      return InputType::kInsertLineBreak;
    case kInsertParagraphSeparator:
    case kInsertParagraphSeparatorInQuotedContent:
      return InputType::kInsertParagraph;
    default:
      return InputType::kNone;
  }
}

void TypingCommand::TypingAddedToOpenCommand(
    CommandType command_type_for_added_typing) {
  LocalFrame* frame = GetDocument().GetFrame();
  if (!frame)
    return;

  UpdatePreservesTypingStyle(command_type_for_added_typing);
  UpdateCommandTypeOfOpenCommand(command_type_for_added_typing);

  AppliedEditing();
}

void TypingCommand::InsertTextInternal(const String& text,
                                       bool select_inserted_text,
                                       EditingState* editing_state) {
  text_to_insert_ = text;

  if (text.empty()) {
    InsertTextRunWithoutNewlines(text, editing_state);
    return;
  }
  wtf_size_t selection_start = selection_start_;
  unsigned offset = 0;
  wtf_size_t newline;
  while ((newline = text.find('\n', offset)) != kNotFound) {
    if (newline > offset) {
      const wtf_size_t insertion_length = newline - offset;
      InsertTextRunWithoutNewlines(text.Substring(offset, insertion_length),
                                   editing_state);
      if (editing_state->IsAborted())
        return;

      AdjustSelectionAfterIncrementalInsertion(GetDocument().GetFrame(),
                                               selection_start,
                                               insertion_length, editing_state);
      selection_start += insertion_length;
    }

    InsertParagraphSeparator(editing_state);
    if (editing_state->IsAborted())
      return;

    offset = newline + 1;
    ++selection_start;
  }

  if (text.length() > offset) {
    const wtf_size_t insertion_length = text.length() - offset;
    InsertTextRunWithoutNewlines(text.Substring(offset, insertion_length),
                                 editing_state);
    if (editing_state->IsAborted())
      return;

    AdjustSelectionAfterIncrementalInsertion(GetDocument().GetFrame(),
                                             selection_start, insertion_length,
                                             editing_state);
  }

  if (!select_inserted_text)
    return;

  // If the caller wants the newly-inserted text to be selected, we select from
  // the plain text offset corresponding to the beginning of the range (possibly
  // collapsed) being replaced by the text insert, to wherever the selection was
  // left after the final run of text was inserted.
  ContainerNode* const editable =
      RootEditableElementOrTreeScopeRootNodeOf(EndingSelection().Anchor());

  const EphemeralRange new_selection_start_collapsed_range =
      PlainTextRange(selection_start_, selection_start_).CreateRange(*editable);
  const Position current_selection_end = EndingSelection().End();

  const SelectionInDOMTree& new_selection =
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(new_selection_start_collapsed_range.StartPosition(),
                            current_selection_end)
          .Build();

  SetEndingSelection(SelectionForUndoStep::From(new_selection));
}

void TypingCommand::InsertTextRunWithoutNewlines(const String& text,
                                                 EditingState* editing_state) {
  CompositeEditCommand* command;
  if (IsIncrementalInsertion()) {
    command = MakeGarbageCollected<InsertIncrementalTextCommand>(
        GetDocument(), text,
        composition_type_ == kTextCompositionNone
            ? InsertIncrementalTextCommand::
                  kRebalanceLeadingAndTrailingWhitespaces
            : InsertIncrementalTextCommand::kRebalanceAllWhitespaces);
  } else {
    command = MakeGarbageCollected<InsertTextCommand>(
        GetDocument(), text,
        composition_type_ == kTextCompositionNone
            ? InsertTextCommand::kRebalanceLeadingAndTrailingWhitespaces
            : InsertTextCommand::kRebalanceAllWhitespaces);
  }

  command->SetStartingSelection(EndingSelection());
  command->SetEndingSelection(EndingSelection());
  ApplyCommandToComposite(command, editing_state);
  if (editing_state->IsAborted())
    return;

  TypingAddedToOpenCommand(kInsertText);
}

void TypingCommand::InsertLineBreak(EditingState* editing_state) {
  if (!CanAppendNewLineFeedToSelection(EndingSelection().AsSelection(),
                                       editing_state))
    return;

  ApplyCommandToComposite(
      MakeGarbageCollected<InsertLineBreakCommand>(GetDocument()),
      editing_state);
  if (editing_state->IsAborted())
    return;
  TypingAddedToOpenCommand(kInsertLineBreak);
}

void TypingCommand::InsertParagraphSeparator(EditingState* editing_state) {
  if (!CanAppendNewLineFeedToSelection(EndingSelection().AsSelection(),
                                       editing_state))
    return;

  ApplyCommandToComposite(
      MakeGarbageCollected<InsertParagraphSeparatorCommand>(GetDocument()),
      editing_state);
  if (editing_state->IsAborted())
    return;
  TypingAddedToOpenCommand(kInsertParagraphSeparator);
}

void TypingCommand::InsertParagraphSeparatorInQuotedContent(
    EditingState* editing_state) {
  // If the selection starts inside a table, just insert the paragraph separator
  // normally Breaking the blockquote would also break apart the table, which is
  // unecessary when inserting a newline
  if (EnclosingNodeOfType(EndingSelection().Start(), &IsTableStructureNode)) {
    InsertParagraphSeparator(editing_state);
    return;
  }

  ApplyCommandToComposite(
      MakeGarbageCollected<BreakBlockquoteCommand>(GetDocument()),
      editing_state);
  if (editing_state->IsAborted())
    return;
  TypingAddedToOpenCommand(kInsertParagraphSeparatorInQuotedContent);
}

bool TypingCommand::MakeEditableRootEmpty(EditingState* editing_state) {
  DCHECK(!GetDocument().NeedsLayoutTreeUpdate());
  Element* root = RootEditableElementOf(EndingSelection().Anchor());
  if (!root || !root->HasChildren())
    return false;

  if (root->firstChild() == root->lastChild()) {
    if (IsA<HTMLBRElement>(root->firstChild())) {
      // If there is a single child and it could be a placeholder, leave it
      // alone.
      if (root->GetLayoutObject() &&
          root->GetLayoutObject()->IsLayoutBlockFlow())
        return false;
    }
  }

  // The selection is updated prior to the removal of the element
  // that makes the node empty. (see crbug.com/40876506)
  if (RuntimeEnabledFeatures::
          HandleSelectionChangeOnDeletingEmptyElementEnabled()) {
    LocalFrame* const frame = GetDocument().GetFrame();
    const SelectionInDOMTree& new_selection =
        SelectionInDOMTree::Builder()
            .Colla
```