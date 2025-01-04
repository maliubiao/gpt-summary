Response:
The user wants a summary of the functionality of the `input_method_controller.cc` file in the Chromium Blink rendering engine. I need to identify the key responsibilities of this component based on the provided code snippet and its included headers.

Here's a breakdown of the apparent functionalities:

1. **IME (Input Method Engine) Handling:** The name of the file and the presence of terms like "composition," "ImeTextSpan," and inclusion of `CompositionEvent` strongly suggest that this file manages the interaction between the browser and input method editors used for languages like Chinese, Japanese, and Korean.

2. **Text Editing and Manipulation:**  The file includes headers related to editing commands (`DeleteSelectionCommand`, `TypingCommand`), selections (`FrameSelection`, `SelectionInDOMTree`), and text ranges (`EphemeralRange`, `PlainTextRange`). This indicates it plays a role in modifying the content of editable elements.

3. **Event Handling:** The inclusion of `EventDispatcher`, `ScopedEventQueue`, and the dispatching of `CompositionEvent` and `InputEvent` show its involvement in the browser's event system, particularly for input-related events.

4. **Integration with DOM:** The file interacts with DOM elements (`Element`, `Text`, `HTMLInputElement`, `HTMLTextAreaElement`) and their properties, including attributes related to input methods like `inputmode` and `enterkeyhint`.

5. **Spellchecking and Suggestions:**  The presence of `SpellChecker` and `SuggestionMarker` suggests involvement in providing spellchecking and suggestion functionalities.

6. **Focus Management:** The inclusion of `FocusController` indicates interaction with the browser's focus management system.

7. **Undo/Redo:** The inclusion of `UndoStack` suggests it's involved in supporting undo and redo operations for text editing.

8. **Virtual Keyboard:** The inclusion of `virtual_keyboard_policy` suggests managing the behavior of virtual keyboards.

**Relationship with Javascript, HTML, and CSS:**

*   **Javascript:** Javascript event listeners can react to the composition events dispatched by this controller. For example, a Javascript application might want to display the current composition string or handle the final commit of text.
*   **HTML:** The controller reads HTML attributes like `inputmode`, `enterkeyhint`, and `autocapitalize` to adjust its behavior and inform the underlying platform about the desired input method settings.
*   **CSS:** While less direct, CSS can influence the rendering of the text being composed. The controller might interact with layout objects that are styled by CSS.

**Hypothetical Input and Output (Logic Reasoning):**

*   **Input:** User presses keys on the keyboard while an IME is active.
*   **Output:** The `InputMethodController` receives information about the keystrokes, updates the composition string, and dispatches `compositionupdate` events. When the user confirms the composition, it dispatches `compositionend` and potentially inserts the composed text into the DOM.

**User/Programming Errors:**

*   A common user error could be incorrectly configuring the IME, leading to unexpected input.
*   A programming error might involve failing to handle composition events correctly in Javascript, leading to inconsistencies in the displayed text.

**User Operations Leading Here (Debugging Clues):**

1. User focuses on an editable element (e.g., an `<input>` or `<textarea>`).
2. User activates an Input Method Editor (IME) on their operating system.
3. User types characters that are part of a multi-character input sequence (e.g., typing the phonetic representation of a Chinese character).
4. The operating system sends IME-related events to the browser.
5. The browser's input handling mechanisms route these events to the `InputMethodController`.

**Summary of Functionality for Part 1:** Based on the code provided, the initial portion of `input_method_controller.cc` focuses on setting up the basic framework for handling IME input. This includes: managing the composition state (start, update, end), dispatching related events to Javascript, providing utilities for text manipulation within the context of composition, interacting with DOM elements to retrieve input method related attributes, and setting up basic data structures for tracking composition.
这是`blink/renderer/core/editing/ime/input_method_controller.cc`文件的第一部分，其主要功能是**管理浏览器中输入法编辑器（IME）的输入过程**。 它负责处理用户在使用IME输入时的各种事件和状态，并将这些输入转化为最终的文本内容插入到网页中。

以下是更详细的功能点归纳：

**核心功能:**

*   **管理输入法组合（Composition）状态:**
    *   跟踪当前是否存在正在进行的输入法组合 (`has_composition_`)。
    *   存储当前组合文本的范围 (`composition_range_`)。
    *   提供方法来判断是否存在组合 (`HasComposition()`)。
    *   提供方法来获取当前组合文本 (`ComposingText()`,  虽然这部分代码可能在后续部分)。
*   **处理组合事件:**
    *   派发 `compositionupdate` 事件给 Javascript，通知组合文本的更新。
    *   派发 `compositionend` 事件给 Javascript，通知组合的结束。
    *   派发 `beforeinput` 事件，通知即将进行的输入操作（例如插入组合文本）。
*   **文本插入和替换（在组合过程中）:**
    *   提供 `InsertTextDuringCompositionWithEvents` 方法，用于在组合过程中插入或替换文本，并触发相应的事件。
*   **清除组合状态:**
    *   提供 `Clear()` 方法，用于清除当前的组合状态和相关的标记。
*   **管理 IME 文本范围 (ImeTextSpan):**
    *   提供 `ClearImeTextSpansByType` 方法，用于清除指定类型的 IME 文本范围标记。
    *   后续部分很可能包含 `AddImeTextSpans` 用于添加这些标记。
*   **选择组合文本:**
    *   提供 `SelectComposition()` 方法，用于选中当前正在组合的文本，以便后续操作（如替换）。
*   **完成组合:**
    *   提供 `FinishComposingText()` 方法，用于结束当前的组合，并将组合文本提交到编辑器中。
*   **提交文本:**
    *   提供 `CommitText()` 方法，用于提交最终的文本，可能是在完成组合后或者直接输入的情况下。
*   **替换文本:**
    *   提供 `ReplaceTextAndMoveCaret()` 方法，用于替换指定范围的文本并移动光标。
    *   提供 `ReplaceComposition()` 方法，用于替换当前的组合文本。
*   **计算光标位置:**
    *   提供 `ComputeAbsoluteCaretPosition` 函数，用于计算基于相对位置的绝对光标位置。
*   **获取输入模式和键盘提示属性:**
    *   提供 `GetInputModeAttribute()` 和 `GetEnterKeyHintAttribute()` 函数，用于获取 HTML 元素的 `inputmode` 和 `enterkeyhint` 属性值。
*   **获取虚拟键盘策略属性:**
    *   提供 `GetVirtualKeyboardPolicyAttribute()` 函数，用于获取 HTML 元素的 `virtualkeyboardpolicy` 属性值。
*   **计算自动大写标志:**
    *   提供 `ComputeAutocapitalizeFlags()` 函数，用于根据 HTML 元素的 `autocapitalize` 属性计算自动大写标志。
*   **与拼写检查集成:**
    *   包含与 `SpellChecker` 交互的代码，可能用于在输入过程中提供拼写建议。
*   **处理撤销/重做:**
    *   虽然代码中没有直接展示，但它与 `UndoStack` 关联，意味着它的操作可能会被添加到撤销/重做堆栈中。

**与 javascript, html, css 的关系举例说明:**

*   **Javascript:**
    *   当用户使用IME输入时，`InputMethodController` 会触发 `compositionupdate` 事件。Javascript 可以监听这个事件，并实时显示用户正在输入的拼音或其他中间状态的文本。
        ```javascript
        document.getElementById('myInput').addEventListener('compositionupdate', function(event) {
          console.log('组合文本更新:', event.data);
          // 可以将 event.data 显示在某个地方
        });
        ```
    *   当用户完成输入（按下回车或选择候选词）时，`InputMethodController` 会触发 `compositionend` 事件。Javascript 可以监听这个事件，并处理最终的输入结果。
        ```javascript
        document.getElementById('myInput').addEventListener('compositionend', function(event) {
          console.log('组合结束，最终文本:', event.data);
          // 可以将 event.data 提交到服务器或进行其他处理
        });
        ```
*   **HTML:**
    *   `InputMethodController` 会读取 HTML 元素的 `inputmode` 属性来提示操作系统或浏览器应该使用哪种类型的键盘布局或输入法。例如，`<input type="text" inputmode="numeric">` 会提示用户输入数字。
    *   `InputMethodController` 会读取 HTML 元素的 `enterkeyhint` 属性来提示软键盘上的 Enter 键应该显示什么文本标签（例如 "完成", "发送", "搜索"）。
    *   `InputMethodController` 会读取 HTML 元素的 `autocapitalize` 属性来决定是否以及如何自动大写用户的输入。
*   **CSS:**
    *   虽然 `InputMethodController` 不直接操作 CSS，但 CSS 样式会影响文本的渲染，包括组合文本的下划线样式、颜色等。在后续部分的代码中，可以看到 `AddImeTextSpans` 方法可能会使用 CSS 相关的属性来标记组合文本。

**逻辑推理的假设输入与输出:**

*   **假设输入:** 用户在一个 `<input>` 元素中使用中文输入法输入 "你好"。当输入 "ni" 的时候，输入法候选框可能会显示 "你" 和其他选项。
*   **输出:**
    1. `InputMethodController` 会接收到 "n" 和 "i" 的按键事件。
    2. `InputMethodController` 会更新内部的组合文本为 "ni"。
    3. `InputMethodController` 会派发 `compositionupdate` 事件，`event.data` 可能为 "ni"。
    4. 当用户选择候选词 "你" 时，`InputMethodController` 会更新组合文本为 "你"。
    5. `InputMethodController` 会再次派发 `compositionupdate` 事件，`event.data` 可能为 "你"。
    6. 最后，当用户确认输入 "你好" 时，`InputMethodController` 会派发 `compositionend` 事件，`event.data` 为 "你好"，并将 "你好" 插入到 `<input>` 元素中。

**涉及用户或者编程常见的使用错误举例说明:**

*   **用户错误:** 用户可能在不支持输入法或者不需要输入法的场景下意外地激活了输入法，导致输入行为不符合预期。
*   **编程错误:** Javascript 开发者可能没有正确监听和处理 `compositionstart`, `compositionupdate`, `compositionend` 事件，导致组合输入过程中的状态显示不正确或者最终输入的结果丢失。例如，如果开发者在 `compositionupdate` 事件中直接将 `event.data` 插入到输入框，可能会导致最终输入时重复插入。

**说明用户操作是如何一步步的到达这里，作为调试线索。**

1. **用户聚焦可编辑元素:** 用户点击或使用 Tab 键等操作将焦点移动到一个可编辑的 HTML 元素上，例如 `<input type="text">` 或 `<textarea>`。
2. **用户激活输入法:** 用户通过操作系统提供的快捷键或输入法切换按钮激活了输入法编辑器。
3. **用户开始输入:** 用户开始在激活的输入法状态下输入字符，例如输入拼音、日文假名等。
4. **操作系统发送 IME 事件:** 操作系统会捕获用户的输入，并将其转化为特定的 IME 事件，例如 `WM_IME_STARTCOMPOSITION`, `WM_IME_COMPOSITION`, `WM_IME_ENDCOMPOSITION` (Windows 系统)。
5. **浏览器接收 IME 事件:** 浏览器内核会监听并接收来自操作系统的 IME 事件。
6. **事件路由到 InputMethodController:** 接收到的 IME 事件会被路由到负责处理输入法逻辑的 `InputMethodController` 实例。
7. **InputMethodController 处理事件:** `InputMethodController` 根据接收到的事件类型，更新内部的组合状态，生成并派发相应的 Javascript 事件（如 `compositionupdate`），并最终将组合完成的文本插入到 DOM 结构中。

在调试与 IME 相关的问题时，开发者可以关注以下线索：

*   **焦点是否正确:** 确认焦点是否在预期的可编辑元素上。
*   **操作系统 IME 状态:** 确认操作系统上的输入法是否已正确激活。
*   **Javascript 事件监听:** 检查 Javascript 代码是否正确监听了 `compositionstart`, `compositionupdate`, `compositionend` 等事件，以及事件处理逻辑是否正确。
*   **浏览器控制台输出:** 可以在 Javascript 事件处理函数中打印相关信息，例如 `event.data`，来查看组合过程中的文本变化。
*   **Blink 内部日志:** 在 Chromium 开发环境下，可以启用特定的日志输出选项来查看 `InputMethodController` 的内部运行状态和事件处理流程。

总而言之，`input_method_controller.cc` 的第一部分为 Blink 引擎处理复杂的输入法输入奠定了基础，它负责捕获和管理输入过程中的关键状态和事件，并作为浏览器和网页 Javascript 之间的桥梁。

Prompt: 
```
这是目录为blink/renderer/core/editing/ime/input_method_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2006, 2007, 2008, 2011 Apple Inc. All rights reserved.
 * Copyright (C) 2008 Nokia Corporation and/or its subsidiary(-ies)
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

#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"

#include <tuple>

#include "third_party/blink/public/mojom/input/focus_type.mojom-blink.h"
#include "third_party/blink/public/web/web_frame_widget.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatcher.h"
#include "third_party/blink/renderer/core/dom/events/scoped_event_queue.h"
#include "third_party/blink/renderer/core/dom/node_computed_style.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/commands/delete_selection_command.h"
#include "third_party/blink/renderer/core/editing/commands/undo_stack.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/edit_context.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/markers/suggestion_marker_properties.h"
#include "third_party/blink/renderer/core/editing/reveal_selection_scope.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/set_selection_options.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_checker.h"
#include "third_party/blink/renderer/core/editing/state_machines/backward_code_point_state_machine.h"
#include "third_party/blink/renderer/core/editing/state_machines/forward_code_point_state_machine.h"
#include "third_party/blink/renderer/core/events/composition_event.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/input/context_menu_allowed_scope.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/keywords.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"

namespace blink {

using mojom::blink::FormControlType;

namespace {

bool NeedsIncrementalInsertion(const LocalFrame& frame,
                               const String& new_text) {
  // No need to apply incremental insertion if it doesn't support formated text.
  if (!frame.GetEditor().CanEditRichly())
    return false;

  // No need to apply incremental insertion if the old text (text to be
  // replaced) or the new text (text to be inserted) is empty.
  if (frame.SelectedText().empty() || new_text.empty())
    return false;

  return true;
}

AtomicString GetInputModeAttribute(Element* element) {
  if (!element)
    return AtomicString();

  bool query_attribute = false;
  if (auto* input = DynamicTo<HTMLInputElement>(*element)) {
    query_attribute = input->SupportsInputModeAttribute();
  } else if (IsA<HTMLTextAreaElement>(*element)) {
    query_attribute = true;
  } else {
    element->GetDocument().UpdateStyleAndLayoutTree();
    if (IsEditable(*element))
      query_attribute = true;
  }

  if (!query_attribute)
    return AtomicString();

  // TODO(dtapuska): We may wish to restrict this to a yet to be proposed
  // <contenteditable> or <richtext> element Mozilla discussed at TPAC 2016.
  return element->FastGetAttribute(html_names::kInputmodeAttr).LowerASCII();
}

AtomicString GetEnterKeyHintAttribute(Element* element) {
  if (!element)
    return AtomicString();

  bool query_attribute = false;
  if (auto* input = DynamicTo<HTMLInputElement>(*element)) {
    query_attribute = input->SupportsInputModeAttribute();
  } else if (IsA<HTMLTextAreaElement>(*element)) {
    query_attribute = true;
  } else {
    element->GetDocument().UpdateStyleAndLayoutTree();
    if (IsEditable(*element))
      query_attribute = true;
  }

  if (!query_attribute)
    return AtomicString();

  return element->FastGetAttribute(html_names::kEnterkeyhintAttr).LowerASCII();
}

AtomicString GetVirtualKeyboardPolicyAttribute(Element* element) {
  if (!element)
    return AtomicString();

  if (!element->MayTriggerVirtualKeyboard())
    return g_null_atom;

  const AtomicString& virtual_keyboard_policy_value =
      element->FastGetAttribute(html_names::kVirtualkeyboardpolicyAttr);
  if (virtual_keyboard_policy_value.IsNull())
    return AtomicString();

  return virtual_keyboard_policy_value.LowerASCII();
}

constexpr int kInvalidDeletionLength = -1;
constexpr bool IsInvalidDeletionLength(const int length) {
  return length == kInvalidDeletionLength;
}

int CalculateBeforeDeletionLengthsInCodePoints(const String& text,
                                               int before_length_in_code_points,
                                               int selection_start) {
  DCHECK_GE(before_length_in_code_points, 0);
  DCHECK_GE(selection_start, 0);
  DCHECK_LE(selection_start, static_cast<int>(text.length()));

  base::span<const UChar> u_text = text.Span16();
  BackwardCodePointStateMachine backward_machine;
  int counter = before_length_in_code_points;
  int deletion_start = selection_start;
  while (counter > 0 && deletion_start > 0) {
    const TextSegmentationMachineState state =
        backward_machine.FeedPrecedingCodeUnit(
            u_text[static_cast<size_t>(deletion_start - 1)]);
    // According to Android's InputConnection spec, we should do nothing if
    // |text| has invalid surrogate pair in the deletion range.
    if (state == TextSegmentationMachineState::kInvalid)
      return kInvalidDeletionLength;

    if (backward_machine.AtCodePointBoundary())
      --counter;
    --deletion_start;
  }
  if (!backward_machine.AtCodePointBoundary())
    return kInvalidDeletionLength;

  const int offset = backward_machine.GetBoundaryOffset();
  DCHECK_EQ(-offset, selection_start - deletion_start);
  return -offset;
}

int CalculateAfterDeletionLengthsInCodePoints(const String& text,
                                              int after_length_in_code_points,
                                              int selection_end) {
  DCHECK_GE(after_length_in_code_points, 0);
  const auto end = base::checked_cast<wtf_size_t>(selection_end);
  const wtf_size_t length = text.length();
  DCHECK_LE(end, length);

  base::span<const UChar> u_text = text.Span16();
  ForwardCodePointStateMachine forward_machine;
  int counter = after_length_in_code_points;
  wtf_size_t deletion_end = end;
  while (counter > 0 && deletion_end < length) {
    const TextSegmentationMachineState state =
        forward_machine.FeedFollowingCodeUnit(u_text[deletion_end]);
    // According to Android's InputConnection spec, we should do nothing if
    // |text| has invalid surrogate pair in the deletion range.
    if (state == TextSegmentationMachineState::kInvalid)
      return kInvalidDeletionLength;

    if (forward_machine.AtCodePointBoundary())
      --counter;
    ++deletion_end;
  }
  if (!forward_machine.AtCodePointBoundary())
    return kInvalidDeletionLength;

  const int offset = forward_machine.GetBoundaryOffset();
  DCHECK_EQ(static_cast<wtf_size_t>(offset), deletion_end - end);
  return offset;
}

Element* RootEditableElementOfSelection(const FrameSelection& frame_selection) {
  const SelectionInDOMTree& selection = frame_selection.GetSelectionInDOMTree();
  if (selection.IsNone())
    return nullptr;
  // To avoid update layout, we attempt to get root editable element from
  // a position where script/user specified.
  if (Element* editable = RootEditableElementOf(selection.Anchor())) {
    return editable;
  }

  // This is work around for applications assumes a position before editable
  // element as editable[1]
  // [1] http://crbug.com/712761

  // TODO(editing-dev): Use of UpdateStyleAndLayout
  // needs to be audited. see http://crbug.com/590369 for more details.
  frame_selection.GetDocument().UpdateStyleAndLayout(
      DocumentUpdateReason::kEditing);
  const VisibleSelection& visibleSeleciton =
      frame_selection.ComputeVisibleSelectionInDOMTree();
  return RootEditableElementOf(visibleSeleciton.Start());
}

std::pair<ContainerNode*, PlainTextRange> PlainTextRangeForEphemeralRange(
    const EphemeralRange& range) {
  if (range.IsNull())
    return {};
  ContainerNode* const editable =
      RootEditableElementOrTreeScopeRootNodeOf(range.StartPosition());
  DCHECK(editable);
  return std::make_pair(editable, PlainTextRange::Create(*editable, range));
}

int ComputeAutocapitalizeFlags(const Element* element) {
  const auto* const html_element = DynamicTo<HTMLElement>(element);
  if (!html_element)
    return 0;

  // We set the autocapitalization flag corresponding to the "used
  // autocapitalization hint" for the focused element:
  // https://html.spec.whatwg.org/C/#used-autocapitalization-hint
  if (auto* input = DynamicTo<HTMLInputElement>(*html_element)) {
    FormControlType input_type = input->FormControlType();
    if (input_type == FormControlType::kInputEmail ||
        input_type == FormControlType::kInputUrl ||
        input_type == FormControlType::kInputPassword) {
      // The autocapitalize IDL attribute value is ignored for these input
      // types, so we set the None flag.
      return kWebTextInputFlagAutocapitalizeNone;
    }
  }

  int flags = 0;

  DEFINE_STATIC_LOCAL(const AtomicString, none, ("none"));
  DEFINE_STATIC_LOCAL(const AtomicString, characters, ("characters"));
  DEFINE_STATIC_LOCAL(const AtomicString, words, ("words"));
  DEFINE_STATIC_LOCAL(const AtomicString, sentences, ("sentences"));

  const AtomicString& autocapitalize = html_element->autocapitalize();
  if (autocapitalize == none) {
    flags |= kWebTextInputFlagAutocapitalizeNone;
  } else if (autocapitalize == characters) {
    flags |= kWebTextInputFlagAutocapitalizeCharacters;
  } else if (autocapitalize == words) {
    flags |= kWebTextInputFlagAutocapitalizeWords;
  } else if (autocapitalize == sentences) {
    flags |= kWebTextInputFlagAutocapitalizeSentences;
  } else if (autocapitalize == g_empty_atom) {
    // https://html.spec.whatwg.org/multipage/interaction.html#autocapitalization
    // If autocapitalize is empty, the UA can decide on an appropriate behavior
    // depending on context. We use the presence of the autocomplete attribute
    // with an email/url/password type as a hint to disable autocapitalization.
    if (auto* form_control = DynamicTo<HTMLFormControlElement>(html_element);
        form_control && form_control->IsAutocompleteEmailUrlOrPassword()) {
      flags |= kWebTextInputFlagAutocapitalizeNone;
    } else {
      flags |= kWebTextInputFlagAutocapitalizeSentences;
    }
  } else {
    NOTREACHED();
  }

  return flags;
}

SuggestionMarker::SuggestionType ConvertImeTextSpanType(
    ImeTextSpan::Type type) {
  switch (type) {
    case ImeTextSpan::Type::kAutocorrect:
      return SuggestionMarker::SuggestionType::kAutocorrect;
    case ImeTextSpan::Type::kGrammarSuggestion:
      return SuggestionMarker::SuggestionType::kGrammar;
    case ImeTextSpan::Type::kMisspellingSuggestion:
      return SuggestionMarker::SuggestionType::kMisspelling;
    case ImeTextSpan::Type::kComposition:
    case ImeTextSpan::Type::kSuggestion:
      return SuggestionMarker::SuggestionType::kNotMisspelling;
  }
}

ImeTextSpan::Type ConvertSuggestionMarkerType(
    SuggestionMarker::SuggestionType type) {
  switch (type) {
    case SuggestionMarker::SuggestionType::kAutocorrect:
      return ImeTextSpan::Type::kAutocorrect;
    case SuggestionMarker::SuggestionType::kGrammar:
      return ImeTextSpan::Type::kGrammarSuggestion;
    case SuggestionMarker::SuggestionType::kMisspelling:
      return ImeTextSpan::Type::kMisspellingSuggestion;
    case SuggestionMarker::SuggestionType::kNotMisspelling:
      return ImeTextSpan::Type::kSuggestion;
  }
}

// ImeTextSpans types that need to be provided to TextInputInfo can be added
// here.
bool ShouldGetImeTextSpans(ImeTextSpan::Type type) {
  return type == ImeTextSpan::Type::kAutocorrect ||
         type == ImeTextSpan::Type::kGrammarSuggestion;
}

}  // anonymous namespace

enum class InputMethodController::TypingContinuation { kContinue, kEnd };

InputMethodController::InputMethodController(LocalDOMWindow& window,
                                             LocalFrame& frame)
    : ExecutionContextLifecycleObserver(&window),
      frame_(frame),
      has_composition_(false),
      last_vk_visibility_request_(
          ui::mojom::VirtualKeyboardVisibilityRequest::NONE) {}

InputMethodController::~InputMethodController() = default;

bool InputMethodController::IsAvailable() const {
  return GetExecutionContext();
}

Document& InputMethodController::GetDocument() const {
  DCHECK(IsAvailable());
  return *To<LocalDOMWindow>(GetExecutionContext())->document();
}

bool InputMethodController::HasComposition() const {
  return has_composition_ && !composition_range_->collapsed() &&
         composition_range_->IsConnected();
}

inline Editor& InputMethodController::GetEditor() const {
  return GetFrame().GetEditor();
}

LocalFrame& InputMethodController::GetFrame() const {
  return *frame_;
}

void InputMethodController::DispatchCompositionUpdateEvent(LocalFrame& frame,
                                                           const String& text) {
  Element* target = frame.GetDocument()->FocusedElement();
  if (!target)
    return;

  auto* event = MakeGarbageCollected<CompositionEvent>(
      event_type_names::kCompositionupdate, frame.DomWindow(), text);
  target->DispatchEvent(*event);
}

void InputMethodController::DispatchCompositionEndEvent(LocalFrame& frame,
                                                        const String& text) {
  // Verify that the caller is using an EventQueueScope to suppress the input
  // event from being fired until the proper time (e.g. after applying an IME
  // selection update, if necessary).
  DCHECK(ScopedEventQueue::Instance()->ShouldQueueEvents());

  Element* target = frame.GetDocument()->FocusedElement();
  if (!target)
    return;

  auto* event = MakeGarbageCollected<CompositionEvent>(
      event_type_names::kCompositionend, frame.DomWindow(), text);
  EventDispatcher::DispatchScopedEvent(*target, *event);
}

void InputMethodController::DispatchBeforeInputFromComposition(
    EventTarget* target,
    InputEvent::InputType input_type,
    const String& data) {
  if (!target)
    return;
  // TODO(editing-dev): Pass appropriate |ranges| after it's defined on spec.
  // http://w3c.github.io/editing/input-events.html#dom-inputevent-inputtype
  const StaticRangeVector* ranges = nullptr;
  if (auto* node = target->ToNode())
    ranges = TargetRangesForInputEvent(*node);
  InputEvent* before_input_event = InputEvent::CreateBeforeInput(
      input_type, data, InputEvent::EventIsComposing::kIsComposing, ranges);
  target->DispatchEvent(*before_input_event);
}

// Used to insert/replace text during composition update and confirm
// composition.
// Procedure:
//   1. Fire 'beforeinput' event for (TODO(editing-dev): deleted composed text)
//      and inserted text
//   2. Fire 'compositionupdate' event
//   3. Fire TextEvent and modify DOM
//   4. Fire 'input' event; dispatched by Editor::AppliedEditing()
void InputMethodController::InsertTextDuringCompositionWithEvents(
    LocalFrame& frame,
    const String& text,
    TypingCommand::Options options,
    TypingCommand::TextCompositionType composition_type) {
  // Verify that the caller is using an EventQueueScope to suppress the input
  // event from being fired until the proper time (e.g. after applying an IME
  // selection update, if necessary).
  DCHECK(ScopedEventQueue::Instance()->ShouldQueueEvents());
  DCHECK(composition_type ==
             TypingCommand::TextCompositionType::kTextCompositionUpdate ||
         composition_type ==
             TypingCommand::TextCompositionType::kTextCompositionConfirm ||
         composition_type ==
             TypingCommand::TextCompositionType::kTextCompositionCancel)
      << "compositionType should be TextCompositionUpdate or "
         "TextCompositionConfirm  or TextCompositionCancel, but got "
      << static_cast<int>(composition_type);
  if (!frame.GetDocument())
    return;

  Element* target = frame.GetDocument()->FocusedElement();
  if (!target)
    return;

  DispatchCompositionUpdateEvent(frame, text);
  // 'compositionupdate' event handler may destroy document.
  if (!IsAvailable()) {
    return;
  }

  DispatchBeforeInputFromComposition(
      target, InputEvent::InputType::kInsertCompositionText, text);

  // 'beforeinput' event handler may destroy document.
  if (!IsAvailable())
    return;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. see http://crbug.com/590369 for more details.
  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kInput);

  const bool is_incremental_insertion = NeedsIncrementalInsertion(frame, text);

  switch (composition_type) {
    case TypingCommand::TextCompositionType::kTextCompositionUpdate:
    case TypingCommand::TextCompositionType::kTextCompositionConfirm:
      // Calling |TypingCommand::insertText()| with empty text will result in an
      // incorrect ending selection. We need to delete selection first.
      // https://crbug.com/693481
      if (text.empty())
        TypingCommand::DeleteSelection(*frame.GetDocument(), 0);
      frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
      TypingCommand::InsertText(*frame.GetDocument(), text, options,
                                composition_type, is_incremental_insertion);
      break;
    case TypingCommand::TextCompositionType::kTextCompositionCancel:
      // TODO(editing-dev): Use TypingCommand::insertText after TextEvent was
      // removed. (Removed from spec since 2012)
      // See text_event.idl.
      frame.GetEventHandler().HandleTextInputEvent(text, nullptr,
                                                   kTextEventInputComposition);
      break;
    default:
      NOTREACHED();
  }
}

void InputMethodController::Clear() {
  RemoveSuggestionMarkerInCompositionRange();

  has_composition_ = false;
  if (composition_range_) {
    composition_range_->setStart(&GetDocument(), 0);
    composition_range_->collapse(true);
  }
  GetDocument().Markers().RemoveMarkersOfTypes(
      DocumentMarker::MarkerTypes::Composition());
}

void InputMethodController::ClearImeTextSpansByType(ImeTextSpan::Type type,
                                                    unsigned text_start,
                                                    unsigned text_end) {
  Element* target = GetDocument().FocusedElement();
  if (!target)
    return;

  Element* editable = GetFrame()
                          .Selection()
                          .ComputeVisibleSelectionInDOMTree()
                          .RootEditableElement();
  if (!editable)
    return;

  const EphemeralRange range =
      PlainTextRange(text_start, text_end).CreateRange(*editable);
  if (range.IsNull() ||
      RootEditableElementOf(range.StartPosition()) != editable ||
      RootEditableElementOf(range.EndPosition()) != editable) {
    return;
  }

  switch (type) {
    case ImeTextSpan::Type::kAutocorrect:
    case ImeTextSpan::Type::kGrammarSuggestion:
    case ImeTextSpan::Type::kMisspellingSuggestion:
    case ImeTextSpan::Type::kSuggestion:
      GetDocument().Markers().RemoveSuggestionMarkerByType(
          ToEphemeralRangeInFlatTree(range), ConvertImeTextSpanType(type));
      break;
    case ImeTextSpan::Type::kComposition:
      GetDocument().Markers().RemoveMarkersInRange(
          range, DocumentMarker::MarkerTypes::Composition());
      break;
  }
}

void InputMethodController::ContextDestroyed() {
  Clear();
  composition_range_ = nullptr;
  active_edit_context_ = nullptr;
}

void InputMethodController::SelectComposition() const {
  const EphemeralRange range = CompositionEphemeralRange();
  if (range.IsNull())
    return;

  // When we select the composition (to be able to replace it), we must not
  // claim that the selection is the result of an input event, even though
  // the act of committing the composition _is_ an input event in itself.
  // Otherwise, X11 clients would interpret the selection as a command to
  // replace the primary selection (on the clipboard) with the contents
  // of the composition.
  bool old_handling_input_event = false;
  WebFrameWidget* widget = nullptr;
  if (GetFrame().Client() && GetFrame().Client()->GetWebFrame()) {
    widget = GetFrame().Client()->GetWebFrame()->FrameWidget();
  }
  if (widget) {
    old_handling_input_event = widget->HandlingInputEvent();
    widget->SetHandlingInputEvent(false);
  }

  // The composition can start inside a composed character sequence, so we have
  // to override checks. See <http://bugs.webkit.org/show_bug.cgi?id=15781>

  // The SetSelectionOptions() parameter is necessary because without it,
  // FrameSelection::SetSelection() will actually call
  // SetShouldClearTypingStyle(true), which will cause problems applying
  // formatting during composition. See https://crbug.com/803278.
  GetFrame().Selection().SetSelection(
      SelectionInDOMTree::Builder().SetBaseAndExtent(range).Build(),
      SetSelectionOptions());

  if (widget) {
    widget->SetHandlingInputEvent(old_handling_input_event);
  }
}

bool IsTextTooLongAt(const Position& position) {
  const Element* element = EnclosingTextControl(position);
  if (!element)
    return false;
  if (auto* input = DynamicTo<HTMLInputElement>(element))
    return input->TooLong();
  if (auto* textarea = DynamicTo<HTMLTextAreaElement>(element))
    return textarea->TooLong();
  return false;
}

bool InputMethodController::FinishComposingText(
    ConfirmCompositionBehavior confirm_behavior) {
  if (!HasComposition())
    return false;

  // If text is longer than maxlength, give input/textarea's handler a chance to
  // clamp the text by replacing the composition with the same value.
  const bool is_too_long = IsTextTooLongAt(composition_range_->StartPosition());

  // TODO(editing-dev): Use of UpdateStyleAndLayout
  // needs to be audited. see http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  const String& composing = ComposingText();

  // Suppress input event (if we hit the is_too_long case) and compositionend
  // event until after we restore the original selection (to avoid clobbering a
  // selection update applied by an event handler).
  EventQueueScope scope;

  if (confirm_behavior == kKeepSelection) {
    // Do not dismiss handles even if we are moving selection, because we will
    // eventually move back to the old selection offsets.
    const bool is_handle_visible = GetFrame().Selection().IsHandleVisible();

    // Maintain to direction of the original selection as it affects how the
    // selection can be extended.
    const PlainTextRange& old_offsets = GetSelectionOffsets();
    const bool is_forward_selection = GetFrame()
                                          .Selection()
                                          .ComputeVisibleSelectionInDOMTree()
                                          .IsAnchorFirst();
    RevealSelectionScope reveal_selection_scope(GetFrame());

    if (is_too_long) {
      std::ignore = ReplaceComposition(ComposingText());
    } else {
      Clear();
      DispatchCompositionEndEvent(GetFrame(), composing);
    }

    // TODO(editing-dev): Use of updateStyleAndLayout
    // needs to be audited. see http://crbug.com/590369 for more details.
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

    const EphemeralRange& old_selection_range =
        EphemeralRangeForOffsets(old_offsets);
    if (old_selection_range.IsNull())
      return false;
    const SelectionInDOMTree& selection =
        is_forward_selection ? SelectionInDOMTree::Builder()
                                   .SetAsForwardSelection(old_selection_range)
                                   .Build()
                             : SelectionInDOMTree::Builder()
                                   .SetAsBackwardSelection(old_selection_range)
                                   .Build();
    GetFrame().Selection().SetSelection(
        selection, SetSelectionOptions::Builder()
                       .SetShouldCloseTyping(true)
                       .SetShouldShowHandle(is_handle_visible)
                       .Build());
    return true;
  }

  PlainTextRange composition_range =
      PlainTextRangeForEphemeralRange(CompositionEphemeralRange()).second;
  if (composition_range.IsNull())
    return false;

  if (is_too_long) {
    // Don't move caret or dispatch compositionend event if
    // ReplaceComposition() fails.
    if (!ReplaceComposition(ComposingText()))
      return false;
  } else {
    Clear();
    DispatchCompositionEndEvent(GetFrame(), composing);
  }

  // Note: MoveCaret() occurs *before* the input and compositionend events are
  // dispatched, due to the use of ScopedEventQueue. This allows input and
  // compositionend event handlers to change the current selection without
  // it getting overwritten again.
  return MoveCaret(composition_range.End());
}

bool InputMethodController::CommitText(
    const String& text,
    const Vector<ImeTextSpan>& ime_text_spans,
    int relative_caret_position) {
  if (HasComposition()) {
    return ReplaceCompositionAndMoveCaret(text, relative_caret_position,
                                          ime_text_spans);
  }

  return InsertTextAndMoveCaret(text, relative_caret_position, ime_text_spans);
}

bool InputMethodController::ReplaceTextAndMoveCaret(
    const String& text,
    PlainTextRange range,
    MoveCaretBehavior move_caret_behavior) {
  EventQueueScope scope;
  const PlainTextRange old_selection(GetSelectionOffsets());
  if (!SetSelectionOffsets(range))
    return false;
  if (!InsertText(text))
    return false;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  see http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  switch (move_caret_behavior) {
    case MoveCaretBehavior::kMoveCaretAfterText: {
      wtf_size_t absolute_caret_position = range.Start() + text.length();
      return SetSelectionOffsets(
          {absolute_caret_position, absolute_caret_position});
    }
    case MoveCaretBehavior::kDoNotMove: {
      wtf_size_t selection_delta = text.length() - range.length();
      wtf_size_t start = old_selection.Start();
      wtf_size_t end = old_selection.End();
      return SetSelectionOffsets(
          {start >= range.End() ? start + selection_delta : start,
           end >= range.End() ? end + selection_delta : end});
    }
  }
}

bool InputMethodController::ReplaceComposition(const String& text) {
  // Verify that the caller is using an EventQueueScope to suppress the input
  // event from being fired until the proper time (e.g. after applying an IME
  // selection update, if necessary).
  DCHECK(ScopedEventQueue::Instance()->ShouldQueueEvents());

  if (!HasComposition())
    return false;

  // Select the text that will be deleted or replaced.
  SelectComposition();

  if (GetFrame().Selection().ComputeVisibleSelectionInDOMTree().IsNone()) {
    return false;
  }

  if (!IsAvailable())
    return false;

  Clear();

  InsertTextDuringCompositionWithEvents(
      GetFrame(), text, 0,
      TypingCommand::TextCompositionType::kTextCompositionConfirm);

  // textInput event handler might destroy document (input event is queued
  // until later).
  if (!IsAvailable())
    return false;

  // No DOM update after 'compositionend'.
  DispatchCompositionEndEvent(GetFrame(), text);

  return true;
}

// relativeCaretPosition is relative to the end of the text.
static int ComputeAbsoluteCaretPosition(int text_start,
                                        int text_length,
                                        int relative_caret_position) {
  return text_start + text_length + relative_caret_position;
}

void InputMethodController::AddImeTextSpans(
    const Vector<ImeTextSpan>& ime_text_spans,
    ContainerNode* base_element,
    unsigned offset_in_plain_chars) {
  for (const auto& ime_text_span : ime_text_spans) {
    wtf_size_t ime_text_span_start =
        offset_in_plain_chars + ime_text_span.StartOffset();
    wtf_size_t ime_text_span_end =
        offset_in_plain_chars + ime_text_span.EndOffset();

    EphemeralRange ephemeral_line_range =
        PlainTextRange(ime_text_span_start, ime_text_span_end)
            .CreateRange(*base_element);
    if (ephemeral_line_range.IsNull())
      continue;

    switch (ime_text_span.GetType()) {
      case ImeTextSpan::Type::kComposition: {
        ImeTextSpanUnderlineStyle underline_style =
            ime_text_span.InterimCharSelection()
                ? ImeTextSpanUnderlineStyle::kSolid
                : ime_text_span.UnderlineStyle();
        GetDocument().Markers().AddCompositionMarker(
            ephemeral_line_range, ime_text_span.UnderlineColor(),
            ime_text_span.Thickness(), underline_style,
            ime_text_span.TextColor(), ime_text_span.BackgroundColor());
        break;
      }
      case ImeTextSpan::Type::kAutocorrect:
      case ImeTextSpan::Type::kGrammarSuggestion:
      case ImeTextSpan::Type::kSuggestion:
      case ImeTextSpan::Type::kMisspellingSuggestion:
        const SuggestionMarker::SuggestionType suggestion_type =
            ConvertImeTextSpanType(ime_text_span.GetType());

        // If spell-checking is disabled for an element, we ignore suggestion
        // markers used to mark misspelled words, but allow other ones (e.g.,
        // markers added by an IME to allow picking between multiple possible
        // words, none of which is necessarily misspelled).
        if (suggestion_type == SuggestionMarker::SuggestionType::kMisspelling &&
            !SpellChecker::IsSpellCheckingEnabledAt(
                ephemeral_line_range.StartPosition()))
          continue;

        // Do not add the grammar marker if it overlaps with existing spellcheck
        // markers.
        if (suggestion_type == SuggestionMarker::SuggestionType::kGrammar &&
            !GetDocument()
                 .Markers()
                 .MarkersIntersectingRange(
                     ToEphemeralRangeInFlatTree(ephemeral_line_range),
            
"""


```