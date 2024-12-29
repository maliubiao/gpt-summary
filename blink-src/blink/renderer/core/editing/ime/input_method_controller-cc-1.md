Response:
The user wants a summary of the functionalities of the provided C++ code snippet from `input_method_controller.cc`. I need to identify the key actions and how they relate to text input, composition, and manipulation within the Chromium Blink rendering engine. Specifically, I should look for interactions with JavaScript, HTML, and CSS, illustrate logical reasoning with input/output examples, highlight potential user/programming errors, and trace the user operations leading to this code.

Here's a breakdown of the thought process for each requirement:

1. **List Functionalities:**  Scan the code for method names and the operations they perform. Focus on actions related to IME (Input Method Engine), text manipulation, selection, and composition.

2. **Relationship with Javascript, HTML, CSS:**
    * **JavaScript:** Look for methods that trigger or interact with JavaScript events (like `DispatchCompositionStartEvent`, `DispatchCompositionEndEvent`, `DispatchBeforeInputInsertText`). Also, consider how JavaScript might call methods in this class (though the provided snippet doesn't show that directly, understanding the context is important).
    * **HTML:** Identify how the code interacts with HTML elements, especially editable elements. The use of `Element* root_editable_element`, `PlainTextRange::Create(*root_editable_element, ...)`, and the manipulation of text within these elements are key.
    * **CSS:**  Look for calls to `GetDocument().UpdateStyleAndLayout()`. This indicates that changes in the input method can trigger layout and rendering updates based on CSS styles. The code also explicitly sets properties like `HighlightColor`, `UnderlineColor`, etc., which are visually represented based on CSS.

3. **Logical Reasoning (Input/Output):** Select a few key methods and illustrate their behavior with simple examples. For instance, `ReplaceCompositionAndMoveCaret` takes text, a relative caret position, and IME spans as input and replaces the existing composition while moving the caret. A simple example could involve replacing "Helo" with "Hello" and adjusting the caret.

4. **User/Programming Errors:** Consider common mistakes when using IME or when programming that might interact with this code. For example, an IME might send inconsistent data, or a developer might make assumptions about the state of composition. Think about error handling within the code.

5. **User Operations and Debugging:** Trace a typical user interaction, like typing with an IME, and how it leads to these functions being called. Start with the user pressing keys, the IME suggesting completions, and the final text being inserted.

6. **Part 2 Summary:** Since this is part 2 of 3, focus on summarizing the core responsibilities covered in *this* specific snippet. It seems to heavily involve the manipulation of existing composition text and the integration of IME suggestions and styling.

**Pre-computation/Analysis:**

* **Identify Core Methods:**  The snippet includes methods like `AddImeTextSpans`, `ReplaceCompositionAndMoveCaret`, `InsertText`, `InsertTextAndMoveCaret`, `CancelComposition`, `DispatchCompositionStartEvent`, `SetComposition`, `SetCompositionFromExistingText`, `AddImeTextSpansToExistingText`, `DeleteSelection`, `MoveCaret`, `ExtendSelectionAndDelete`, `DeleteSurroundingText`, `ExtendSelectionAndReplace`.
* **Group by Functionality:**  Group these methods into logical units:  composition management, text insertion/replacement, selection manipulation, IME specific actions, and event dispatching.
* **Note Key Data Structures:** Pay attention to `ImeTextSpan`, `PlainTextRange`, `EphemeralRange`, and how they represent text and positions within the document.
* **Trace Event Flow:**  Recognize the pattern of `DispatchBeforeInput...` events and the subsequent actions if the event is not canceled.

By following these steps, I can generate a comprehensive and accurate summary of the provided code snippet.
这是 `blink/renderer/core/editing/ime/input_method_controller.cc` 文件的第二部分，主要负责处理输入法编辑器（IME）相关的操作，特别是当存在未完成的组合文本时。以下是其功能的归纳总结：

**核心功能：管理和操作输入法组合文本 (Composition Text)**

这部分代码的核心职责是管理和操作用户通过输入法正在输入的、尚未最终确定的文本，即组合文本。它涉及以下几个关键方面：

1. **添加和更新 IME 文本跨度 (ImeTextSpan)：**  `AddImeTextSpans` 方法负责将 IME 提供的额外信息（例如，下划线、颜色、建议等）应用于组合文本的不同部分。这使得浏览器能够根据输入法的指示，高亮显示候选词、提供拼写建议等。

2. **替换组合文本并移动光标：** `ReplaceCompositionAndMoveCaret` 方法用于更新正在输入的组合文本。当用户选择了一个候选词或输入法引擎更新了组合文本时，此方法会被调用。它会替换当前的组合文本，并将光标移动到指定的新位置。

3. **插入文本并移动光标（与组合无关）：** `InsertTextAndMoveCaret` 方法用于在非组合状态下插入文本并移动光标。虽然与组合文本直接无关，但它处理了类似的文本插入和光标移动逻辑，也可能在完成组合后被调用。

4. **取消组合：** `CancelComposition` 方法用于取消当前正在进行的输入法组合。这通常发生在用户按下 Esc 键或执行其他取消操作时。它会清除组合状态并触发 `compositionend` 事件。

5. **触发组合事件：**
   - `DispatchCompositionStartEvent`:  在开始新的输入法组合时触发 `compositionstart` 事件。
   - `SetComposition`:  这是一个核心方法，用于设置或更新组合文本。它会根据情况触发 `compositionstart` 和 `compositionupdate` 事件。

6. **从现有文本设置组合：** `SetCompositionFromExistingText` 允许将文档中已存在的文本设置为组合文本，并应用相应的 IME 文本跨度。

7. **向现有文本添加 IME 文本跨度：** `AddImeTextSpansToExistingText`  可以在已有的文本上添加 IME 提供的样式信息，即使这些文本不是当前正在组合的。

8. **获取组合文本的相关信息：**
   - `CompositionEphemeralRange`: 返回当前组合文本的范围。
   - `ComposingText`: 返回当前组合文本的字符串。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**
    * **事件触发:**  `DispatchCompositionStartEvent` 和 `DispatchCompositionEndEvent` 方法直接与 JavaScript 中的 `compositionstart` 和 `compositionend` 事件相关联。当输入法状态发生变化时，这些事件会被触发，JavaScript 代码可以监听这些事件并执行相应的操作，例如更新 UI 或处理用户输入。
        * **假设输入：** 用户开始使用输入法输入 "你好"。
        * **输出：** `DispatchCompositionStartEvent("你")` 可能会被调用（具体文本取决于输入法实现），触发 JavaScript 中的 `compositionstart` 事件。
    * **`beforeinput` 事件:** `DispatchBeforeInputInsertText` 和 `DispatchBeforeInputEditorCommand` 用于在实际修改 DOM 之前通知 JavaScript，允许脚本取消操作。
        * **假设输入：** 用户在输入法中选择了候选词并按下确认键。
        * **输出：**  `DispatchBeforeInputInsertText("好")` 可能会被调用，触发 JavaScript 中的 `beforeinput` 事件，如果该事件未被取消，则继续插入文本。
* **HTML:**
    * **编辑元素:**  代码中大量使用了 `Element* root_editable_element`，这表明这些操作主要针对 HTML 中可编辑的元素（例如 `<input>`, `<textarea>` 或设置了 `contenteditable` 属性的元素）。
    * **文本范围:** `PlainTextRange` 和 `EphemeralRange` 等概念与 HTML 文本节点中的字符范围对应。
* **CSS:**
    * **样式更新:** `GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing)` 被频繁调用，表示输入法操作可能会触发浏览器的样式计算和布局更新。例如，当组合文本被高亮显示或添加下划线时，浏览器需要重新渲染这些样式。
    * **IME 文本跨度的样式:** `SuggestionMarkerProperties::Builder()` 中设置的 `HighlightColor`, `UnderlineColor`, `Thickness`, `UnderlineStyle`, `TextColor`, `BackgroundColor` 等属性最终会影响组合文本在页面上的视觉呈现，这些属性会与 CSS 样式规则相互作用。

**逻辑推理的假设输入与输出：**

* **假设输入 (ReplaceCompositionAndMoveCaret):**
    * 当前组合文本为 "你好"。
    * 用户选择了候选词 "世界"。
    * `text` 参数为 "世界"。
    * `relative_caret_position` 为 2 (假设光标移动到 "界" 字之后)。
    * `ime_text_spans` 可能包含 "世界" 的分词信息或建议信息。
* **输出 (ReplaceCompositionAndMoveCaret):**
    * 当前编辑区域的文本中，"你好" 被替换为 "世界"。
    * 光标移动到 "世界" 之后的位置。
    * 应用 `ime_text_spans` 中定义的样式，例如高亮显示 "世界"。

* **假设输入 (CancelComposition):** 用户在输入 "你好" 的过程中按下 Esc 键。
* **输出 (CancelComposition):**
    * 当前的组合文本 "你好" 被清除。
    * 触发 `compositionend` 事件，参数为空字符串。

**用户或编程常见的使用错误：**

* **用户操作:**
    * **IME 输入错误:** 用户可能错误地选择了候选词或输入了错误的拼音，导致组合文本不正确。这部分代码负责处理这些输入，但无法避免用户输入错误。
    * **在不支持 IME 的环境中使用 IME 功能:**  虽然这不太算是这部分代码的错误，但如果在某些特殊情况下（例如，某些特殊的富文本编辑器），IME 的行为可能不符合预期。
* **编程错误:**
    * **错误的 IME 文本跨度数据:** 如果输入法引擎提供的 `ime_text_spans` 数据不正确（例如，范围错误、样式属性错误），可能导致组合文本显示异常。
    * **在组合进行时进行非法的 DOM 操作:**  如果在组合文本存在时，JavaScript 代码直接修改了包含组合文本的 DOM 结构，可能会导致状态不一致或崩溃。Blink 引擎会尝试处理这种情况，但最佳实践是避免在组合进行时进行此类操作。
    * **未正确处理 `beforeinput` 事件:** 如果 JavaScript 代码错误地取消了 `beforeinput` 事件，可能会阻止正常的文本插入或删除。

**用户操作如何一步步的到达这里 (调试线索)：**

1. **用户聚焦到可编辑元素:** 用户点击或使用 Tab 键将焦点移动到一个可以输入文本的 HTML 元素上（例如，`<input type="text">`）。
2. **用户开始使用输入法输入:** 用户按下键盘上的按键，触发操作系统的输入法。
3. **输入法引擎发送组合更新:**  操作系统输入法引擎会向浏览器发送消息，告知当前正在组合的文本。这些消息会被传递到 Blink 引擎。
4. **`InputMethodController` 接收输入法事件:**  `InputMethodController` 监听来自操作系统的输入法事件。
5. **调用 `SetComposition` 或相关方法:**  当输入法状态发生变化（开始组合、更新组合、结束组合），`InputMethodController` 的相应方法会被调用，例如 `SetComposition` 用于更新组合文本。
6. **`ReplaceCompositionAndMoveCaret` 处理组合文本替换:** 当用户选择候选词或输入法自动完成时，`ReplaceCompositionAndMoveCaret` 会被调用来替换当前的组合文本。
7. **`AddImeTextSpans` 应用样式信息:**  在设置或更新组合文本时，`AddImeTextSpans` 会被调用来应用输入法提供的样式信息。
8. **`DispatchCompositionStartEvent`/`DispatchCompositionUpdateEvent`/`DispatchCompositionEndEvent` 触发 JavaScript 事件:** 在组合的不同阶段，会触发相应的 JavaScript 事件，允许网页脚本做出响应。
9. **完成组合或取消组合:** 用户按下 Enter 键完成输入，或者按下 Esc 键取消输入，分别会触发不同的处理路径，最终可能调用 `InsertText` 或 `CancelComposition`。

**总结：**

这部分 `InputMethodController` 代码是 Blink 引擎处理输入法组合文本的核心模块。它负责接收输入法引擎的指令，更新和渲染组合文本，并与 JavaScript 事件机制协同工作，为用户提供流畅的输入体验。其主要功能集中在管理组合文本的生命周期，包括开始、更新、替换、取消，并应用输入法提供的额外样式和信息。

Prompt: 
```
这是目录为blink/renderer/core/editing/ime/input_method_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
         DocumentMarker::MarkerTypes::Spelling())
                 .empty()) {
          continue;
        }

        GetDocument().Markers().AddSuggestionMarker(
            ephemeral_line_range,
            SuggestionMarkerProperties::Builder()
                .SetType(suggestion_type)
                .SetSuggestions(ime_text_span.Suggestions())
                .SetHighlightColor(ime_text_span.SuggestionHighlightColor())
                .SetUnderlineColor(ime_text_span.UnderlineColor())
                .SetThickness(ime_text_span.Thickness())
                .SetUnderlineStyle(ime_text_span.UnderlineStyle())
                .SetTextColor(ime_text_span.TextColor())
                .SetBackgroundColor(ime_text_span.BackgroundColor())
                .SetRemoveOnFinishComposing(
                    ime_text_span.NeedsRemovalOnFinishComposing())
                .Build());
        break;
    }
  }
}

bool InputMethodController::ReplaceCompositionAndMoveCaret(
    const String& text,
    int relative_caret_position,
    const Vector<ImeTextSpan>& ime_text_spans) {
  Element* root_editable_element = GetFrame()
                                       .Selection()
                                       .ComputeVisibleSelectionInDOMTree()
                                       .RootEditableElement();
  if (!root_editable_element)
    return false;
  DCHECK(HasComposition());
  PlainTextRange composition_range =
      PlainTextRange::Create(*root_editable_element, *composition_range_);
  if (composition_range.IsNull())
    return false;
  int text_start = composition_range.Start();

  // Suppress input and compositionend events until after we move the caret to
  // the new position.
  EventQueueScope scope;
  if (!ReplaceComposition(text))
    return false;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. see http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  AddImeTextSpans(ime_text_spans, root_editable_element, text_start);

  int absolute_caret_position = ComputeAbsoluteCaretPosition(
      text_start, text.length(), relative_caret_position);
  return MoveCaret(absolute_caret_position);
}

bool InputMethodController::InsertText(const String& text) {
  if (DispatchBeforeInputInsertText(GetDocument().FocusedElement(), text) !=
      DispatchEventResult::kNotCanceled)
    return false;
  if (!IsAvailable())
    return false;
  GetEditor().InsertText(text, nullptr);
  return true;
}

bool InputMethodController::InsertTextAndMoveCaret(
    const String& text,
    int relative_caret_position,
    const Vector<ImeTextSpan>& ime_text_spans) {
  PlainTextRange selection_range = GetSelectionOffsets();
  if (selection_range.IsNull())
    return false;
  int text_start = selection_range.Start();

  // Suppress input event until after we move the caret to the new position.
  EventQueueScope scope;

  // Don't fire events for a no-op operation.
  if (!text.empty() || selection_range.length() > 0) {
    if (!InsertText(text))
      return false;
  }

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. see http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  Element* root_editable_element = GetFrame()
                                       .Selection()
                                       .ComputeVisibleSelectionInDOMTree()
                                       .RootEditableElement();
  if (root_editable_element) {
    AddImeTextSpans(ime_text_spans, root_editable_element, text_start);
  }

  int absolute_caret_position = ComputeAbsoluteCaretPosition(
      text_start, text.length(), relative_caret_position);
  return MoveCaret(absolute_caret_position);
}

void InputMethodController::CancelComposition() {
  if (!HasComposition())
    return;

  // TODO(editing-dev): Use of UpdateStyleAndLayout
  // needs to be audited. see http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  RevealSelectionScope reveal_selection_scope(GetFrame());

  if (GetFrame().Selection().ComputeVisibleSelectionInDOMTree().IsNone()) {
    return;
  }

  Clear();

  InsertTextDuringCompositionWithEvents(
      GetFrame(), g_empty_string, 0,
      TypingCommand::TextCompositionType::kTextCompositionCancel);
  // Event handler might destroy document.
  if (!IsAvailable())
    return;

  // An open typing command that disagrees about current selection would cause
  // issues with typing later on.
  TypingCommand::CloseTyping(&GetFrame());

  // No DOM update after 'compositionend'.
  DispatchCompositionEndEvent(GetFrame(), g_empty_string);
}

bool InputMethodController::DispatchCompositionStartEvent(const String& text) {
  Element* target = GetDocument().FocusedElement();
  if (!target)
    return IsAvailable();

  auto* event = MakeGarbageCollected<CompositionEvent>(
      event_type_names::kCompositionstart, GetFrame().DomWindow(), text);
  target->DispatchEvent(*event);

  return IsAvailable();
}

void InputMethodController::SetComposition(
    const String& text,
    const Vector<ImeTextSpan>& ime_text_spans,
    int selection_start,
    int selection_end) {
  RevealSelectionScope reveal_selection_scope(GetFrame());

  // Updates styles before setting selection for composition to prevent
  // inserting the previous composition text into text nodes oddly.
  // See https://bugs.webkit.org/show_bug.cgi?id=46868
  GetDocument().UpdateStyleAndLayoutTree();

  SelectComposition();

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. see http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  if (GetFrame().Selection().ComputeVisibleSelectionInDOMTree().IsNone()) {
    return;
  }

  Element* target = GetDocument().FocusedElement();
  if (!target)
    return;

  PlainTextRange selected_range = CreateSelectionRangeForSetComposition(
      selection_start, selection_end, text.length());

  // Dispatch an appropriate composition event to the focused node.
  // We check the composition status and choose an appropriate composition event
  // since this function is used for three purposes:
  // 1. Starting a new composition.
  //    Send a compositionstart and a compositionupdate event when this function
  //    creates a new composition node, i.e. !hasComposition() &&
  //    !text.isEmpty().
  //    Sending a compositionupdate event at this time ensures that at least one
  //    compositionupdate event is dispatched.
  // 2. Updating the existing composition node.
  //    Send a compositionupdate event when this function updates the existing
  //    composition node, i.e. hasComposition() && !text.isEmpty().
  // 3. Canceling the ongoing composition.
  //    Send a compositionend event when function deletes the existing
  //    composition node, i.e. !hasComposition() && test.isEmpty().
  if (text.empty()) {
    // Suppress input and compositionend events until after we move the caret
    // to the new position.
    EventQueueScope scope;
    if (HasComposition()) {
      RevealSelectionScope inner_reveal_selection_scope(GetFrame());
      // Do not attempt to apply IME selection offsets if ReplaceComposition()
      // fails (we compute the new range assuming the replacement will succeed).
      if (!ReplaceComposition(g_empty_string))
        return;
    } else {
      // It's weird to call |setComposition()| with empty text outside
      // composition, however some IME (e.g. Japanese IBus-Anthy) did this, so
      // we simply delete selection without sending extra events.
      if (!DeleteSelection())
        return;
    }

    // TODO(editing-dev): Use of UpdateStyleAndLayout
    // needs to be audited. see http://crbug.com/590369 for more details.
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

    SetEditableSelectionOffsets(selected_range);
    return;
  }

  // We should send a 'compositionstart' event only when the given text is not
  // empty because this function doesn't create a composition node when the text
  // is empty.
  if (!HasComposition() &&
      !DispatchCompositionStartEvent(GetFrame().SelectedText())) {
    return;
  }

  DCHECK(!text.empty());

  Clear();

  // Suppress input event until after we move the caret to the new position.
  EventQueueScope scope;
  InsertTextDuringCompositionWithEvents(GetFrame(), text,
                                        TypingCommand::kSelectInsertedText,
                                        TypingCommand::kTextCompositionUpdate);
  // Event handlers might destroy document.
  if (!IsAvailable())
    return;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. see http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  // The undo stack could become empty if a JavaScript event handler calls
  // execCommand('undo') to pop elements off the stack. Or, the top element of
  // the stack could end up not corresponding to the TypingCommand. Make sure we
  // don't crash in these cases (it's unclear what the composition range should
  // be set to in these cases, so we don't worry too much about that).
  SelectionInDOMTree selection;
  if (GetEditor().GetUndoStack().CanUndo()) {
    const UndoStep* undo_step = *GetEditor().GetUndoStack().UndoSteps().begin();
    const SelectionForUndoStep& undo_selection = undo_step->EndingSelection();
    if (undo_selection.IsValidFor(GetDocument()))
      selection = undo_selection.AsSelection();
  }

  // Find out what node has the composition now.
  const Position anchor =
      MostForwardCaretPosition(selection.Anchor(), kCanSkipOverEditingBoundary);
  Node* anchor_node = anchor.AnchorNode();
  if (!anchor_node || !anchor_node->IsTextNode()) {
    return;
  }

  const Position focus = selection.Focus();
  Node* focus_node = focus.AnchorNode();

  unsigned focus_offset = focus.ComputeOffsetInContainerNode();
  unsigned anchor_offset = anchor.ComputeOffsetInContainerNode();

  has_composition_ = true;
  if (!composition_range_)
    composition_range_ = Range::Create(GetDocument());
  composition_range_->setStart(anchor_node, anchor_offset);
  composition_range_->setEnd(focus_node, focus_offset);

  if (anchor_node->GetLayoutObject()) {
    anchor_node->GetLayoutObject()->SetShouldDoFullPaintInvalidation();
  }

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. see http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  // We shouldn't close typing in the middle of setComposition.
  SetEditableSelectionOffsets(selected_range, TypingContinuation::kContinue);

  if (TypingCommand* const last_typing_command =
          TypingCommand::LastTypingCommandIfStillOpenForTyping(&GetFrame())) {
    // When we called InsertTextDuringCompositionWithEvents() with the
    // kSelectInsertedText flag, it set what is now the composition range as the
    // ending selection on the open TypingCommand. We now update it to the
    // current selection to fix two problems:
    //
    // 1. Certain operations, e.g. pressing enter on a physical keyboard on
    // Android, would otherwise incorrectly replace the composition range.
    //
    // 2. Using undo would cause text to be selected, even though we never
    // actually showed the selection to the user.
    TypingCommand::UpdateSelectionIfDifferentFromCurrentSelection(
        last_typing_command, &GetFrame());
  }

  // Even though we would've returned already if SetComposition() were called
  // with an empty string, the composition range could still be empty right now
  // due to Unicode grapheme cluster position normalization (e.g. if
  // SetComposition() were passed an extending character which doesn't allow a
  // grapheme cluster break immediately before.
  if (!HasComposition())
    return;

  if (ime_text_spans.empty()) {
    GetDocument().Markers().AddCompositionMarker(
        CompositionEphemeralRange(), Color::kTransparent,
        ui::mojom::ImeTextSpanThickness::kThin,
        ui::mojom::ImeTextSpanUnderlineStyle::kSolid, Color::kTransparent,
        LayoutTheme::GetTheme().PlatformDefaultCompositionBackgroundColor());
    return;
  }

  const std::pair<ContainerNode*, PlainTextRange>&
      root_element_and_plain_text_range =
          PlainTextRangeForEphemeralRange(CompositionEphemeralRange());
  AddImeTextSpans(ime_text_spans, root_element_and_plain_text_range.first,
                  root_element_and_plain_text_range.second.Start());
}

PlainTextRange InputMethodController::CreateSelectionRangeForSetComposition(
    int selection_start,
    int selection_end,
    size_t text_length) const {
  const int selection_offsets_start =
      static_cast<int>(GetSelectionOffsets().Start());
  const int start = selection_offsets_start + selection_start;
  const int end = selection_offsets_start + selection_end;
  return CreateRangeForSelection(start, end, text_length);
}

void InputMethodController::SetCompositionFromExistingText(
    const Vector<ImeTextSpan>& ime_text_spans,
    unsigned composition_start,
    unsigned composition_end) {
  Element* target = GetDocument().FocusedElement();
  if (!target)
    return;

  if (!HasComposition() && !DispatchCompositionStartEvent(""))
    return;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  see http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  Element* editable = GetFrame()
                          .Selection()
                          .ComputeVisibleSelectionInDOMTree()
                          .RootEditableElement();
  if (!editable)
    return;

  const EphemeralRange range =
      PlainTextRange(composition_start, composition_end).CreateRange(*editable);
  if (range.IsNull())
    return;

  const Position start = range.StartPosition();
  if (RootEditableElementOf(start) != editable)
    return;

  const Position end = range.EndPosition();
  if (RootEditableElementOf(end) != editable)
    return;

  Clear();

  AddImeTextSpans(ime_text_spans, editable, composition_start);

  has_composition_ = true;
  if (!composition_range_)
    composition_range_ = Range::Create(GetDocument());
  composition_range_->setStart(range.StartPosition());
  composition_range_->setEnd(range.EndPosition());

  DispatchCompositionUpdateEvent(GetFrame(), ComposingText());
}

void InputMethodController::AddImeTextSpansToExistingText(
    const Vector<ImeTextSpan>& ime_text_spans,
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

  AddImeTextSpans(ime_text_spans, editable, text_start);
}

EphemeralRange InputMethodController::CompositionEphemeralRange() const {
  if (!HasComposition())
    return EphemeralRange();
  return EphemeralRange(composition_range_.Get());
}

String InputMethodController::ComposingText() const {
  DocumentLifecycle::DisallowTransitionScope disallow_transition(
      GetDocument().Lifecycle());
  return PlainText(
      CompositionEphemeralRange(),
      TextIteratorBehavior::Builder().SetEmitsOriginalText(true).Build());
}

PlainTextRange InputMethodController::GetSelectionOffsets() const {
  const EphemeralRange range = FirstEphemeralRangeOf(
      GetFrame().Selection().ComputeVisibleSelectionInDOMTree());
  if (range.IsNull())
    return PlainTextRange();
  const ContainerNode& element =
      *RootEditableElementOrTreeScopeRootNodeOf(range.StartPosition());
  cached_text_input_info_.EnsureCached(element);
  return cached_text_input_info_.GetSelection(range);
}

EphemeralRange InputMethodController::EphemeralRangeForOffsets(
    const PlainTextRange& offsets) const {
  if (offsets.IsNull())
    return EphemeralRange();
  Element* root_editable_element = GetFrame()
                                       .Selection()
                                       .ComputeVisibleSelectionInDOMTree()
                                       .RootEditableElement();
  if (!root_editable_element)
    return EphemeralRange();

  return offsets.CreateRange(*root_editable_element);
}

bool InputMethodController::SetSelectionOffsets(
    const PlainTextRange& selection_offsets) {
  return SetSelectionOffsets(selection_offsets, TypingContinuation::kEnd,
                             /*show_handle=*/false,
                             /*show_context_menu=*/false);
}

bool InputMethodController::SetSelectionOffsets(
    const PlainTextRange& selection_offsets,
    TypingContinuation typing_continuation,
    bool show_handle,
    bool show_context_menu) {
  const EphemeralRange range = EphemeralRangeForOffsets(selection_offsets);
  if (range.IsNull())
    return false;

  GetFrame().Selection().SetSelection(
      SelectionInDOMTree::Builder().SetBaseAndExtent(range).Build(),
      SetSelectionOptions::Builder()
          .SetShouldCloseTyping(typing_continuation == TypingContinuation::kEnd)
          .SetShouldShowHandle(show_handle)
          .Build());

  if (show_context_menu) {
    ContextMenuAllowedScope scope;
    GetFrame().GetEventHandler().ShowNonLocatedContextMenu(
        /*override_target_element=*/nullptr, kMenuSourceTouch);
  }
  return true;
}

bool InputMethodController::SetEditableSelectionOffsets(
    const PlainTextRange& selection_offsets,
    bool show_handle,
    bool show_context_menu) {
  return SetEditableSelectionOffsets(selection_offsets,
                                     TypingContinuation::kEnd, show_handle,
                                     show_context_menu);
}

bool InputMethodController::SetEditableSelectionOffsets(
    const PlainTextRange& selection_offsets,
    TypingContinuation typing_continuation,
    bool show_handle,
    bool show_context_menu) {
  if (!GetEditor().CanEdit())
    return false;

  return SetSelectionOffsets(selection_offsets, typing_continuation,
                             show_handle, show_context_menu);
}

void InputMethodController::RemoveSuggestionMarkerInCompositionRange() {
  if (HasComposition()) {
    GetDocument().Markers().RemoveSuggestionMarkerInRangeOnFinish(
        EphemeralRangeInFlatTree(composition_range_.Get()));
  }
}

PlainTextRange InputMethodController::CreateRangeForSelection(
    int start,
    int end,
    size_t text_length) const {
  // In case of exceeding the left boundary.
  start = std::max(start, 0);
  end = std::max(end, start);

  Element* root_editable_element = GetFrame()
                                       .Selection()
                                       .ComputeVisibleSelectionInDOMTree()
                                       .RootEditableElement();
  if (!root_editable_element)
    return PlainTextRange();
  const EphemeralRange& range =
      EphemeralRange::RangeOfContents(*root_editable_element);
  if (range.IsNull())
    return PlainTextRange();

  const TextIteratorBehavior& behavior =
      TextIteratorBehavior::Builder()
          .SetEmitsObjectReplacementCharacter(true)
          .SetEmitsCharactersBetweenAllVisiblePositions(true)
          .Build();
  TextIterator it(range.StartPosition(), range.EndPosition(), behavior);

  int right_boundary = 0;
  for (; !it.AtEnd(); it.Advance())
    right_boundary += it.length();

  if (HasComposition())
    right_boundary -= composition_range_->GetText().length();

  right_boundary += text_length;

  // In case of exceeding the right boundary.
  start = std::min(start, right_boundary);
  end = std::min(end, right_boundary);

  return PlainTextRange(start, end);
}

bool InputMethodController::DeleteSelection() {
  if (!GetFrame().Selection().ComputeVisibleSelectionInDOMTree().IsRange())
    return true;

  Node* target = GetFrame().GetDocument()->FocusedElement();
  if (target) {
    DispatchBeforeInputEditorCommand(
        target, InputEvent::InputType::kDeleteContentBackward,
        TargetRangesForInputEvent(*target));

    // Frame could have been destroyed by the beforeinput event.
    if (!IsAvailable())
      return false;
  }

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  see http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  TypingCommand::DeleteSelection(GetDocument());

  // Frame could have been destroyed by the input event.
  return IsAvailable();
}

bool InputMethodController::DeleteSelectionWithoutAdjustment() {
  const SelectionInDOMTree& selection_in_dom_tree =
      GetFrame().Selection().GetSelectionInDOMTree();
  if (selection_in_dom_tree.IsCaret())
    return true;

  const SelectionForUndoStep& selection =
      SelectionForUndoStep::From(selection_in_dom_tree);

  Node* target = GetFrame().GetDocument()->FocusedElement();
  if (target) {
    DispatchBeforeInputEditorCommand(
        target, InputEvent::InputType::kDeleteContentBackward,
        TargetRangesForInputEvent(*target));
    // Frame could have been destroyed by the beforeinput event.
    if (!IsAvailable())
      return false;
  }

  if (TypingCommand* last_typing_command =
          TypingCommand::LastTypingCommandIfStillOpenForTyping(&GetFrame())) {
    TypingCommand::UpdateSelectionIfDifferentFromCurrentSelection(
        last_typing_command, &GetFrame());

    last_typing_command->DeleteSelection(true, ASSERT_NO_EDITING_ABORT);
    return true;
  }

  MakeGarbageCollected<DeleteSelectionCommand>(
      selection,
      DeleteSelectionOptions::Builder()
          .SetMergeBlocksAfterDelete(true)
          .SetSanitizeMarkup(true)
          .Build(),
      InputEvent::InputType::kDeleteContentBackward)
      ->Apply();

  // Frame could have been destroyed by the input event.
  return IsAvailable();
}

bool InputMethodController::MoveCaret(int new_caret_position) {
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  PlainTextRange selected_range =
      CreateRangeForSelection(new_caret_position, new_caret_position, 0);
  if (selected_range.IsNull())
    return false;
  return SetEditableSelectionOffsets(selected_range);
}

void InputMethodController::ExtendSelectionAndDelete(int before, int after) {
  if (!GetEditor().CanEdit())
    return;
  PlainTextRange selection_offsets(GetSelectionOffsets());
  if (selection_offsets.IsNull())
    return;

  // A common call of before=1 and after=0 will fail if the last character
  // is multi-code-word UTF-16, including both multi-16bit code-points and
  // Unicode combining character sequences of multiple single-16bit code-
  // points (officially called "compositions"). Try more until success.
  // http://crbug.com/355995
  //
  // FIXME: Note that this is not an ideal solution when this function is
  // called to implement "backspace". In that case, there should be some call
  // that will not delete a full multi-code-point composition but rather
  // only the last code-point so that it's possible for a user to correct
  // a composition without starting it from the beginning.
  // http://crbug.com/37993
  do {
    if (!SetSelectionOffsets(PlainTextRange(
            std::max(static_cast<int>(selection_offsets.Start()) - before, 0),
            selection_offsets.End() + after)))
      return;
    if (before == 0)
      break;
    ++before;
    // TODO(editing-dev): The use of UpdateStyleAndLayout
    // needs to be audited.  see http://crbug.com/590369 for more details.
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  } while (
      GetFrame().Selection().ComputeVisibleSelectionInDOMTree().Start() ==
          GetFrame().Selection().ComputeVisibleSelectionInDOMTree().End() &&
      before <= static_cast<int>(selection_offsets.Start()));
  // TODO(editing-dev): Find a way to distinguish Forward and Backward.
  std::ignore = DeleteSelection();
}

// TODO(ctzsm): We should reduce the number of selectionchange events.
// Ideally, we want to do the deletion without selection, however, there is no
// such editing command exists currently.
void InputMethodController::DeleteSurroundingText(int before, int after) {
  if (!GetEditor().CanEdit())
    return;
  const PlainTextRange selection_offsets(GetSelectionOffsets());
  if (selection_offsets.IsNull())
    return;
  Element* const root_editable_element = GetFrame()
                                             .Selection()
                                             .ComputeVisibleSelectionInDOMTree()
                                             .RootEditableElement();
  if (!root_editable_element)
    return;
  int selection_start = static_cast<int>(selection_offsets.Start());
  int selection_end = static_cast<int>(selection_offsets.End());

  // Select the text to be deleted before SelectionState::kStart.
  if (before > 0 && selection_start > 0) {
    // In case of exceeding the left boundary.
    const int start = std::max(selection_start - before, 0);
    const EphemeralRange& range =
        PlainTextRange(0, start).CreateRange(*root_editable_element);
    if (range.IsNull())
      return;
    if (!SetSelectionOffsets(PlainTextRange(start, selection_start)))
      return;
    if (!DeleteSelectionWithoutAdjustment())
      return;

    selection_end = selection_end - (selection_start - start);
    selection_start = start;
  }

  // Select the text to be deleted after SelectionState::kEnd.
  if (after > 0) {
    // Adjust the deleted range in case of exceeding the right boundary.
    const PlainTextRange range(0, selection_end + after);
    if (range.IsNull())
      return;
    const EphemeralRange& valid_range =
        range.CreateRange(*root_editable_element);
    if (valid_range.IsNull())
      return;
    const int end =
        PlainTextRange::Create(*root_editable_element, valid_range).End();

    // TODO(editing-dev): The use of UpdateStyleAndLayout
    // needs to be audited.  see http://crbug.com/590369 for more details.
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
    if (!SetSelectionOffsets(PlainTextRange(selection_end, end)))
      return;
    if (!DeleteSelectionWithoutAdjustment())
      return;
  }

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  see http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  SetSelectionOffsets(PlainTextRange(selection_start, selection_end));
}

void InputMethodController::DeleteSurroundingTextInCodePoints(int before,
                                                              int after) {
  DCHECK_GE(before, 0);
  DCHECK_GE(after, 0);
  if (!GetEditor().CanEdit())
    return;
  const PlainTextRange selection_offsets(GetSelectionOffsets());
  if (selection_offsets.IsNull())
    return;
  Element* const root_editable_element =
      GetFrame().Selection().RootEditableElementOrDocumentElement();
  if (!root_editable_element)
    return;

  const TextIteratorBehavior& behavior =
      TextIteratorBehavior::Builder()
          .SetEmitsObjectReplacementCharacter(true)
          .Build();
  const String& text = PlainText(
      EphemeralRange::RangeOfContents(*root_editable_element), behavior);

  // 8-bit characters are Latin-1 characters, so the deletion lengths are
  // trivial.
  if (text.Is8Bit())
    return DeleteSurroundingText(before, after);

  const int selection_start = static_cast<int>(selection_offsets.Start());
  const int selection_end = static_cast<int>(selection_offsets.End());

  const int before_length =
      CalculateBeforeDeletionLengthsInCodePoints(text, before, selection_start);
  if (IsInvalidDeletionLength(before_length))
    return;
  const int after_length =
      CalculateAfterDeletionLengthsInCodePoints(text, after, selection_end);
  if (IsInvalidDeletionLength(after_length))
    return;

  return DeleteSurroundingText(before_length, after_length);
}

void InputMethodController::ExtendSelectionAndReplace(
    int before,
    int after,
    const String& replacement_text) {
  const PlainTextRange selection_offsets(GetSelectionOffsets());
  if (selection_offsets.IsNull() || before < 0 || after < 0) {
    return;
  }

  ReplaceTextAndMoveCaret(
      replacement_text,
      PlainTextRange(
          std::max(static_cast<int>(selection_offsets.Start()) - before, 0),
          selection_offsets.End() + after),
      MoveCaretBehavior::kMoveCaretAfterText);
}

void InputMethodController::GetLayoutBounds(gfx::Rect* control_bounds,
                                            gfx::Rect* selection_bounds) {
  if (!IsAvailable())
    return;

  if (GetActiveEditContext()) {
    return GetActiveEditContext()->GetLayoutBounds(control_bounds,
                                                   selection_bounds);
  }
  if (!GetFrame().Selection().IsAvailable())
    return;
  Element* element = RootEditableElementOfSelection(GetFrame().Selection());
  if (!element)
    return;
  // Fetch the control bounds of the active editable element.
  // Selection bounds are currently populated only for EditContext.
  // For editable elements we use GetCompositionCharacterBounds to fetch the
  // selection bounds.
  *control_bounds = element->BoundsInWidget();
}

void InputMethodController::DidChangeVisibility(
    const LayoutObject& layout_object) {
  cached_text_input_info_.DidChangeVisibility(layout_object);
}

void InputMethodController::DidLayoutSubtree(
    const LayoutObject& layout_object) {
  cached_text_input_info_.DidLayoutSubtree(layout_object);
}

void InputMethodController::DidUpdateLayout(const LayoutObject& layout_object) {
  cached_text_input_info_.DidUpdateLayout(layout_object);
}

void InputMethodController::LayoutObjectWillBeDestroyed(
    const LayoutObject& layout_object) {
  cached_text_input_info_.LayoutObjectWillBeDestroyed(layout_object);
}

WebTextInputInfo InputMethodController::TextInputInfo() const {
  WebTextInputInfo info;
  if (!IsAvailable())
    return info;

  if (!GetFrame().Selection().IsAvailable()) {
    // plugins/mouse-capture-inside-shadow.html reaches here.
    return info;
  }
  Element* element = RootEditableElementOfSelection(GetFrame().Selection());
  if (!element)
    return info;

  info.node_id = NodeIdOfFocusedElement();
  info.action = InputActionOfFocusedElement();
  info.input_mode = InputModeOfFocusedElement();
  info.virtual_keyboard_policy = VirtualKeyboardPolicyOfFocusedElement();
  info.type = TextInputType();
  info.flags = TextInputFlags();
  if (info.type == kWebTextInputTypeNone)
    return info;

  if (!GetFrame().GetEditor().CanEdit())
    return info;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  see http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  const EphemeralRange& first_range = FirstEphemeralRangeOf(
      GetFrame().Selection().ComputeVisibleSelectionInDOMTree());

  DocumentLifecycle::DisallowTransitionScope disallow_transition(
      GetDocument().Lifecycle());

  if (const Node* start_node = first_range.StartPosition().AnchorNode()) {
    const ComputedStyle* style =
        start_node->GetComputedStyleForElementOrLayoutObject();
    if (style && !style->IsHorizontalWritingMode()) {
      info.flags |= kWebTextInputFlagVertical;
    }
  }

  cached_text_input_info_.EnsureCached(*element);

  // Emits an object replacement character for each replaced element so that
  // it is exposed to IME and thus could be deleted by IME on android.
  info.value = cached_text_input_info_.GetText();
  if (info.value.IsEmpty())
    return info;

  const PlainTextRange& selection_plain_text_range =
      cached_text_input_info_.GetSelection(first_range);
  if (selection_plain_text_range.IsNotNull()) {
    info.selection_start = selection_plain_text_range.Start();
    info.selection_end = selection_plain_text_range.End();
  }

  info.ime_text_spans = GetImeTextSpans();

  const EphemeralRange& range = CompositionEphemeralRange();
  const PlainTextRange& composition_plain_text_range =
      cached_text_input_info_.GetComposition(range);
  if (composition_plain_text_range.IsNotNull()) {
    info.composition_start = composition_plain_text_range.Star
"""


```