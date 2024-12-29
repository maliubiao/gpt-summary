Response:
The user wants a summary of the functionality of the provided C++ code snippet from `editor_command.cc`. This is the second part of a four-part code block. I need to focus on the functions defined in this specific section and infer their purpose within the context of a web browser's editing capabilities.

Here's a breakdown of the functions in this snippet:

- **Scrolling:** `ExecuteScrollLineUp`, `ExecuteScrollLineDown`, `ExecuteScrollToBeginningOfDocument`, `ExecuteScrollToEndOfDocument`. These likely handle scrolling the document viewport.
- **Selection Manipulation:** `ExecuteSelectAll`, `ExecuteSelectLine`, `ExecuteSelectParagraph`, `ExecuteSelectSentence`, `ExecuteSelectToMark`, `ExecuteSelectWord`. These functions seem to extend or modify the current text selection.
- **Mark Management:** `ExecuteSetMark`, `ExecuteSwapWithMark`. These suggest a "mark" feature, possibly for navigation or selection manipulation.
- **Text Transposition:** `ExecuteTranspose`. This likely swaps the positions of two characters.
- **Undo/Redo:** `ExecuteUndo`. This is a standard editing function.
- **Link Removal:** `ExecuteUnlink`. This suggests removing hyperlink formatting.
- **Selection Clearing:** `ExecuteUnselect`. This clears the current selection.
- **Yanking (Cut/Paste equivalent):** `ExecuteYank`, `ExecuteYankAndSelect`. These appear to interact with a "kill ring," a concept similar to a clipboard history.
- **Supporting and Enabling States:** `Supported`, `SupportedFromMenuOrKeyBinding`, `Enabled`, `EnabledVisibleSelection`, `EnabledVisibleSelectionAndMark`, `EnableCaretInEditableText`, `EnabledInEditableText`, `EnabledInEditableTextOrCaretBrowsing`, `EnabledDelete`, `EnabledInRichlyEditableText`, `EnabledRangeInEditableText`, `EnabledRangeInRichlyEditableText`, `EnabledRedo`, `EnabledUndo`, `EnabledUnselect`, `EnabledSelectAll`. These functions determine if a command is available or applicable in the current context.
- **State Checking:** `StateNone`, `StateOrderedList`, `StateUnorderedList`, `StateJustifyCenter`, `StateJustifyFull`, `StateJustifyLeft`, `StateJustifyRight`. These functions likely check the current state of formatting or selection.
- **Value Retrieval:** `ValueStateOrNull`, `ValueEmpty`, `ValueDefaultParagraphSeparator`, `ValueFormatBlock`. These retrieve values associated with commands, potentially for UI display or command logic.
- **Can Execute Check:** `CanNotExecuteWhenDisabled`. This seems like a guard condition.
- **Command Mapping:** The `InternalCommand` function appears to be a central lookup for associating command names with their corresponding execution, support, and state functions.

Now, let's consider the relationships to JavaScript, HTML, and CSS:

- **HTML:** Many of these commands directly manipulate the HTML structure and content (e.g., inserting elements, modifying text). The "mark" feature might be implemented using HTML elements or attributes. The `FormatBlock` command explicitly works with HTML block-level elements.
- **CSS:** Commands related to formatting (bold, italic, alignment, font, color) directly affect the CSS styles applied to the selected text or elements.
- **JavaScript:** JavaScript can trigger these editing commands using `document.execCommand()`. The "beforeinput" event handlers mentioned in the code are a mechanism for JavaScript to intercept and potentially modify or cancel editing actions.

Let's think about potential user actions and debugging:

- A user pressing the "Ctrl+A" (or equivalent) key combination would likely trigger the `ExecuteSelectAll` command.
- Clicking the "Bold" button in a text editor would call the `StyleCommands::ExecuteToggleBold` command.
- A user typing text would eventually lead to an `InsertCommands::ExecuteInsertText` call. If something goes wrong during text input, a debugger might be set in `ExecuteInsertText` or the related `DispatchBeforeInputInsertText` function to inspect the text being inserted and the current state.

Based on this analysis, I can now formulate the summary.
Based on the provided code snippet, here's a summary of the functionalities implemented in this part of `editor_command.cc`:

**Core Functionalities:**

This section of the code defines the execution logic and enabling conditions for a variety of editing commands related to **navigation, selection manipulation, marking, text transposition, undo/redo, link management, and clipboard interaction.**  It also includes functions to query the current state and values associated with certain commands.

**Specific Function Groups:**

* **Scrolling Commands:**
    * `ExecuteScrollLineUp`: Scrolls the viewport up by one line.
    * `ExecuteScrollLineDown`: Scrolls the viewport down by one line.
    * `ExecuteScrollToBeginningOfDocument`: Scrolls to the very top of the document.
    * `ExecuteScrollToEndOfDocument`: Scrolls to the very bottom of the document.

* **Selection Manipulation Commands:**
    * `ExecuteSelectAll`: Selects all content within the current frame.
    * `ExecuteSelectLine`: Expands the current selection to encompass the entire line.
    * `ExecuteSelectParagraph`: Expands the current selection to encompass the entire paragraph.
    * `ExecuteSelectSentence`: Expands the current selection to encompass the entire sentence.
    * `ExecuteSelectToMark`: Selects the content between the current selection and a previously set "mark".
    * `ExecuteSelectWord`: Expands the current selection to encompass the current word.
    * `ExecuteUnselect`: Clears the current selection.

* **Mark Management Commands:**
    * `ExecuteSetMark`: Sets a "mark" at the current cursor position or selection start.
    * `ExecuteSwapWithMark`: Swaps the current selection with the content at the "mark".

* **Text Transposition Command:**
    * `ExecuteTranspose`: Swaps the positions of the two characters surrounding the cursor.

* **Undo/Redo Command:**
    * `ExecuteUndo`: Reverts the last editing action.

* **Link Management Command:**
    * `ExecuteUnlink`: Removes the hyperlink from the currently selected link.

* **Clipboard Interaction Commands (Yanking - Emacs terminology):**
    * `ExecuteYank`: Inserts the most recently "killed" (cut or copied) text at the current cursor position.
    * `ExecuteYankAndSelect`: Inserts the most recently "killed" text and selects it.

* **Supporting and Enabling Condition Functions:**
    * Functions like `Supported`, `SupportedFromMenuOrKeyBinding`, `Enabled`, `EnabledVisibleSelection`, etc., define when a specific command is available and can be executed based on the current context (e.g., whether there's a selection, if the text is editable, if it's a rich text area).

* **State Query Functions:**
    * Functions like `StateNone`, `StateOrderedList`, `StateUnorderedList`, `StateJustifyCenter`, etc., determine the current state of formatting or list items at the selection.

* **Value Query Functions:**
    * Functions like `ValueStateOrNull`, `ValueEmpty`, `ValueDefaultParagraphSeparator`, `ValueFormatBlock` retrieve values associated with commands, such as the current paragraph separator or the tag name of a formatted block.

* **Command Mapping Function:**
    * `InternalCommand`: This function acts as a lookup table, associating command names (like "selectAll", "bold") with their corresponding internal execution and state functions.

**Relationship to JavaScript, HTML, and CSS:**

* **JavaScript:**
    * These commands are often triggered by JavaScript through methods like `document.execCommand()`. For example, `document.execCommand('selectAll')` would eventually call the `ExecuteSelectAll` function.
    * The code mentions `DispatchBeforeInputInsertText`, which is related to the "beforeinput" DOM event. JavaScript can listen to this event and potentially modify or cancel the text insertion before it happens. For instance, a JavaScript framework might want to sanitize user input before it's inserted.

* **HTML:**
    * Many of these commands directly manipulate the HTML structure and content. `ExecuteSelectAll` selects HTML elements. `ExecuteUnlink` modifies the HTML structure by removing the `<a>` tag. `ExecuteFormatBlock` changes the HTML tag surrounding a selection.

* **CSS:**
    * While not directly manipulating CSS in this snippet, the actions of some commands can result in CSS changes. For instance, commands like "bold" or "italic" might add or remove CSS styles (`font-weight: bold`, `font-style: italic`). The layout and rendering of the document, influenced by CSS, are considered by functions like the scrolling commands.

**Examples and Logical Reasoning:**

* **Assumption:** User presses "Ctrl+A" (or Command+A on macOS).
* **Input:** Keyboard event triggering the "selectAll" command.
* **Output:** The `ExecuteSelectAll` function is called, resulting in the selection of all content in the frame.

* **Assumption:** User is in a text field and presses the "Home" key (often mapped to "scrollToStartOfDocument").
* **Input:** Keyboard event triggering the "scrollToStartOfDocument" command.
* **Output:** The `ExecuteScrollToBeginningOfDocument` function is called, and the browser scrolls the document to the top.

**Common User or Programming Errors:**

* **Incorrectly assuming a command is always enabled:** A common error is trying to execute a command via JavaScript (using `document.execCommand()`) when it's not enabled in the current context. For example, trying to execute "bold" when no text is selected or when the selection is in a non-editable area will have no effect (or might throw an error, depending on the browser and the specific command). The `Enabled*` functions in this code are crucial for determining if a command is valid.

* **Not handling the "beforeinput" event correctly:** If JavaScript code listening to the "beforeinput" event cancels the event, the intended text modification (like inserting text after a "yank") will be prevented. Developers need to ensure their "beforeinput" handlers don't inadvertently block legitimate editing actions.

**User Operations and Debugging:**

Let's trace how a user action might lead to this code:

1. **User Action:** The user presses the "Ctrl+L" (or Command+L) keyboard shortcut, which is typically bound to the "selectLine" command in many text editors and browsers.
2. **Browser Interpretation:** The browser intercepts this keyboard event.
3. **Command Mapping:** The browser's input handling mechanism identifies this shortcut as corresponding to the "selectLine" editing command.
4. **`InternalCommand` Lookup:** The browser internally uses a mapping (likely involving `InternalCommand`) to find the function associated with "selectLine," which is `ExecuteSelectLine`.
5. **Execution:** The `ExecuteSelectLine` function is called.
6. **`ExpandSelectionToGranularity`:**  `ExecuteSelectLine` calls the `ExpandSelectionToGranularity` function (defined elsewhere but implied here) with `TextGranularity::kLine`.
7. **Selection Modification:** The `ExpandSelectionToGranularity` function manipulates the browser's internal selection model to encompass the entire line where the cursor is currently located.
8. **Visual Update:** The browser updates the visual representation of the selection on the screen.

**Debugging Clues:**

If the "Select Line" command isn't working as expected, a developer might:

* **Set a breakpoint in `ExecuteSelectLine`:** This allows inspecting the state of the `frame` object and the selection at the moment the command is executed.
* **Check the keyboard shortcut mapping:** Verify that "Ctrl+L" is indeed correctly mapped to the "selectLine" command in the browser's settings or code.
* **Investigate `ExpandSelectionToGranularity`:** If `ExecuteSelectLine` is being called but the selection isn't expanding correctly, the issue likely lies within the `ExpandSelectionToGranularity` function.
* **Examine the current selection:** Before pressing "Ctrl+L", inspect the current selection using browser developer tools to understand the starting point of the selection.

In summary, this code snippet is a crucial part of the Blink rendering engine, responsible for implementing a wide range of fundamental editing operations that users expect in web browsers. It interacts heavily with the browser's internal representation of the document (DOM) and can be influenced by and influence JavaScript, HTML, and CSS.

Prompt: 
```
这是目录为blink/renderer/core/editing/commands/editor_command.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能

"""
pIgnoringWritingMode,
      ui::ScrollGranularity::kScrollByLine);
}

static bool ExecuteScrollLineDown(LocalFrame& frame,
                                  Event*,
                                  EditorCommandSource,
                                  const String&) {
  return frame.GetEventHandler().BubblingScroll(
      mojom::blink::ScrollDirection::kScrollDownIgnoringWritingMode,
      ui::ScrollGranularity::kScrollByLine);
}

static bool ExecuteScrollToBeginningOfDocument(LocalFrame& frame,
                                               Event*,
                                               EditorCommandSource,
                                               const String&) {
  return frame.GetEventHandler().BubblingScroll(
      mojom::blink::ScrollDirection::kScrollBlockDirectionBackward,
      ui::ScrollGranularity::kScrollByDocument);
}

static bool ExecuteScrollToEndOfDocument(LocalFrame& frame,
                                         Event*,
                                         EditorCommandSource,
                                         const String&) {
  return frame.GetEventHandler().BubblingScroll(
      mojom::blink::ScrollDirection::kScrollBlockDirectionForward,
      ui::ScrollGranularity::kScrollByDocument);
}

static bool ExecuteSelectAll(LocalFrame& frame,
                             Event*,
                             EditorCommandSource source,
                             const String&) {
  const SetSelectionBy set_selection_by =
      source == EditorCommandSource::kMenuOrKeyBinding
          ? SetSelectionBy::kUser
          : SetSelectionBy::kSystem;
  frame.Selection().SelectAll(
      set_selection_by,
      /* canonicalize_selection */ RuntimeEnabledFeatures::
          RemoveVisibleSelectionInDOMSelectionEnabled());
  return true;
}

static bool ExecuteSelectLine(LocalFrame& frame,
                              Event*,
                              EditorCommandSource,
                              const String&) {
  return ExpandSelectionToGranularity(frame, TextGranularity::kLine);
}

static bool ExecuteSelectParagraph(LocalFrame& frame,
                                   Event*,
                                   EditorCommandSource,
                                   const String&) {
  return ExpandSelectionToGranularity(frame, TextGranularity::kParagraph);
}

static bool ExecuteSelectSentence(LocalFrame& frame,
                                  Event*,
                                  EditorCommandSource,
                                  const String&) {
  return ExpandSelectionToGranularity(frame, TextGranularity::kSentence);
}

static bool ExecuteSelectToMark(LocalFrame& frame,
                                Event*,
                                EditorCommandSource,
                                const String&) {
  const EphemeralRange mark =
      frame.GetEditor().Mark().ToNormalizedEphemeralRange();
  EphemeralRange selection = frame.GetEditor().SelectedRange();
  if (mark.IsNull() || selection.IsNull())
    return false;
  frame.Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(UnionEphemeralRanges(mark, selection))
          .Build(),
      SetSelectionOptions::Builder().SetShouldCloseTyping(true).Build());
  return true;
}

static bool ExecuteSelectWord(LocalFrame& frame,
                              Event*,
                              EditorCommandSource,
                              const String&) {
  return ExpandSelectionToGranularity(frame, TextGranularity::kWord);
}

static bool ExecuteSetMark(LocalFrame& frame,
                           Event*,
                           EditorCommandSource,
                           const String&) {
  frame.GetEditor().SetMark();
  return true;
}

static bool ExecuteSwapWithMark(LocalFrame& frame,
                                Event*,
                                EditorCommandSource,
                                const String&) {
  const VisibleSelection mark(frame.GetEditor().Mark());
  const VisibleSelection& selection =
      frame.Selection().ComputeVisibleSelectionInDOMTreeDeprecated();
  const bool mark_is_directional = frame.GetEditor().MarkIsDirectional();
  if (mark.IsNone() || selection.IsNone())
    return false;

  frame.GetEditor().SetMark();
  frame.Selection().SetSelection(mark.AsSelection(),
                                 SetSelectionOptions::Builder()
                                     .SetIsDirectional(mark_is_directional)
                                     .Build());
  return true;
}

static bool ExecuteTranspose(LocalFrame& frame,
                             Event*,
                             EditorCommandSource,
                             const String&) {
  Editor& editor = frame.GetEditor();
  if (!editor.CanEdit())
    return false;

  Document* const document = frame.GetDocument();

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  document->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  const EphemeralRange& range = ComputeRangeForTranspose(frame);
  if (range.IsNull())
    return false;

  // Transpose the two characters.
  const String& text = PlainText(range);
  if (text.length() != 2)
    return false;
  const String& transposed = text.Right(1) + text.Left(1);

  if (DispatchBeforeInputInsertText(EventTargetNodeForDocument(document),
                                    transposed,
                                    InputEvent::InputType::kInsertTranspose,
                                    MakeGarbageCollected<StaticRangeVector>(
                                        1, StaticRange::Create(range))) !=
      DispatchEventResult::kNotCanceled)
    return false;

  // 'beforeinput' event handler may destroy document->
  if (frame.GetDocument() != document)
    return false;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  document->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  // 'beforeinput' event handler may change selection, we need to re-calculate
  // range.
  const EphemeralRange& new_range = ComputeRangeForTranspose(frame);
  if (new_range.IsNull())
    return false;

  const String& new_text = PlainText(new_range);
  if (new_text.length() != 2)
    return false;
  const String& new_transposed = new_text.Right(1) + new_text.Left(1);

  const SelectionInDOMTree& new_selection =
      SelectionInDOMTree::Builder().SetBaseAndExtent(new_range).Build();

  // Select the two characters.
  if (CreateVisibleSelection(new_selection) !=
      frame.Selection().ComputeVisibleSelectionInDOMTree())
    frame.Selection().SetSelectionAndEndTyping(new_selection);

  // Insert the transposed characters.
  editor.ReplaceSelectionWithText(new_transposed, false, false,
                                  InputEvent::InputType::kInsertTranspose);
  return true;
}

static bool ExecuteUndo(LocalFrame& frame,
                        Event*,
                        EditorCommandSource,
                        const String&) {
  frame.GetEditor().Undo();
  return true;
}

static bool ExecuteUnlink(LocalFrame& frame,
                          Event*,
                          EditorCommandSource,
                          const String&) {
  DCHECK(frame.GetDocument());
  return MakeGarbageCollected<UnlinkCommand>(*frame.GetDocument())->Apply();
}

static bool ExecuteUnselect(LocalFrame& frame,
                            Event*,
                            EditorCommandSource,
                            const String&) {
  frame.Selection().Clear();
  return true;
}

static bool ExecuteYank(LocalFrame& frame,
                        Event*,
                        EditorCommandSource,
                        const String&) {
  const String& yank_string = frame.GetEditor().GetKillRing().Yank();
  if (DispatchBeforeInputInsertText(
          EventTargetNodeForDocument(frame.GetDocument()), yank_string,
          InputEvent::InputType::kInsertFromYank) !=
      DispatchEventResult::kNotCanceled)
    return true;

  // 'beforeinput' event handler may destroy document.
  if (frame.GetDocument()->GetFrame() != &frame)
    return false;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. see http://crbug.com/590369 for more details.
  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  frame.GetEditor().InsertTextWithoutSendingTextEvent(
      yank_string, false, nullptr, InputEvent::InputType::kInsertFromYank);
  frame.GetEditor().GetKillRing().SetToYankedState();
  return true;
}

static bool ExecuteYankAndSelect(LocalFrame& frame,
                                 Event*,
                                 EditorCommandSource,
                                 const String&) {
  const String& yank_string = frame.GetEditor().GetKillRing().Yank();
  if (DispatchBeforeInputInsertText(
          EventTargetNodeForDocument(frame.GetDocument()), yank_string,
          InputEvent::InputType::kInsertFromYank) !=
      DispatchEventResult::kNotCanceled)
    return true;

  // 'beforeinput' event handler may destroy document.
  if (frame.GetDocument()->GetFrame() != &frame)
    return false;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. see http://crbug.com/590369 for more details.
  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  frame.GetEditor().InsertTextWithoutSendingTextEvent(
      frame.GetEditor().GetKillRing().Yank(), true, nullptr,
      InputEvent::InputType::kInsertFromYank);
  frame.GetEditor().GetKillRing().SetToYankedState();
  return true;
}

// Supported functions

static bool Supported(LocalFrame*) {
  return true;
}

static bool SupportedFromMenuOrKeyBinding(LocalFrame*) {
  return false;
}

// Enabled functions

static bool Enabled(LocalFrame&, Event*, EditorCommandSource) {
  return true;
}

static bool EnabledVisibleSelection(LocalFrame& frame,
                                    Event* event,
                                    EditorCommandSource source) {
  if (source == EditorCommandSource::kDOM &&
      frame.GetInputMethodController().GetActiveEditContext()) {
    return false;
  }

  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  if (source == EditorCommandSource::kMenuOrKeyBinding &&
      !frame.Selection().SelectionHasFocus())
    return false;

  // The term "visible" here includes a caret in editable text, a range in any
  // text, or a caret in non-editable text when caret browsing is enabled.
  const VisibleSelection& selection =
      CreateVisibleSelection(frame.GetEditor().SelectionForCommand(event));
  return (selection.IsCaret() &&
          (selection.IsContentEditable() || frame.IsCaretBrowsingEnabled())) ||
         selection.IsRange();
}

static bool EnabledVisibleSelectionAndMark(LocalFrame& frame,
                                           Event* event,
                                           EditorCommandSource source) {
  if (source == EditorCommandSource::kDOM &&
      frame.GetInputMethodController().GetActiveEditContext()) {
    return false;
  }

  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  if (source == EditorCommandSource::kMenuOrKeyBinding &&
      !frame.Selection().SelectionHasFocus())
    return false;

  const VisibleSelection& selection =
      CreateVisibleSelection(frame.GetEditor().SelectionForCommand(event));
  return ((selection.IsCaret() &&
           (selection.IsContentEditable() || frame.IsCaretBrowsingEnabled())) ||
          selection.IsRange()) &&
         !frame.GetEditor().Mark().IsNone();
}

static bool EnableCaretInEditableText(LocalFrame& frame,
                                      Event* event,
                                      EditorCommandSource source) {
  if (source == EditorCommandSource::kDOM &&
      frame.GetInputMethodController().GetActiveEditContext()) {
    return false;
  }

  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  if (source == EditorCommandSource::kMenuOrKeyBinding &&
      !frame.Selection().SelectionHasFocus())
    return false;
  const VisibleSelection& selection =
      CreateVisibleSelection(frame.GetEditor().SelectionForCommand(event));
  return selection.IsCaret() && selection.IsContentEditable();
}

static bool EnabledInEditableText(LocalFrame& frame,
                                  Event* event,
                                  EditorCommandSource source) {
  if (frame.GetInputMethodController().GetActiveEditContext()) {
    if (source == EditorCommandSource::kDOM) {
      return false;
    } else if (source == EditorCommandSource::kMenuOrKeyBinding) {
      // If there's an active EditContext, always give the EditContext
      // a chance to handle menu or key binding commands regardless
      // of the selection position. This is important for the case
      // where the EditContext's associated element is a <canvas>,
      // which cannot contain selection; only focus.
      return true;
    }
  }

  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  if (source == EditorCommandSource::kMenuOrKeyBinding &&
      !frame.Selection().SelectionHasFocus())
    return false;
  const SelectionInDOMTree selection =
      frame.GetEditor().SelectionForCommand(event);
  return RootEditableElementOf(
      CreateVisiblePosition(selection.Anchor()).DeepEquivalent());
}

static bool EnabledInEditableTextOrCaretBrowsing(LocalFrame& frame,
                                                 Event* event,
                                                 EditorCommandSource source) {
  return frame.IsCaretBrowsingEnabled() ||
         EnabledInEditableText(frame, event, source);
}

static bool EnabledDelete(LocalFrame& frame,
                          Event* event,
                          EditorCommandSource source) {
  switch (source) {
    case EditorCommandSource::kMenuOrKeyBinding:
      return frame.Selection().SelectionHasFocus() &&
             frame.GetEditor().CanDelete();
    case EditorCommandSource::kDOM:
      // "Delete" from DOM is like delete/backspace keypress, affects selected
      // range if non-empty, otherwise removes a character
      return EnabledInEditableText(frame, event, source);
  }
  NOTREACHED();
}

static bool EnabledInRichlyEditableText(LocalFrame& frame,
                                        Event*,
                                        EditorCommandSource source) {
  if (source == EditorCommandSource::kDOM &&
      frame.GetInputMethodController().GetActiveEditContext()) {
    return false;
  }

  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  if (source == EditorCommandSource::kMenuOrKeyBinding &&
      !frame.Selection().SelectionHasFocus())
    return false;
  const VisibleSelection& selection =
      frame.Selection().ComputeVisibleSelectionInDOMTree();
  return !selection.IsNone() && IsRichlyEditablePosition(selection.Anchor()) &&
         selection.RootEditableElement();
}

static bool EnabledRangeInEditableText(LocalFrame& frame,
                                       Event*,
                                       EditorCommandSource source) {
  if (source == EditorCommandSource::kDOM &&
      frame.GetInputMethodController().GetActiveEditContext()) {
    return false;
  }

  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  if (source == EditorCommandSource::kMenuOrKeyBinding &&
      !frame.Selection().SelectionHasFocus())
    return false;
  return frame.Selection()
             .ComputeVisibleSelectionInDOMTreeDeprecated()
             .IsRange() &&
         frame.Selection()
             .ComputeVisibleSelectionInDOMTreeDeprecated()
             .IsContentEditable();
}

static bool EnabledRangeInRichlyEditableText(LocalFrame& frame,
                                             Event*,
                                             EditorCommandSource source) {
  if (source == EditorCommandSource::kDOM &&
      frame.GetInputMethodController().GetActiveEditContext()) {
    return false;
  }

  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  if (source == EditorCommandSource::kMenuOrKeyBinding &&
      !frame.Selection().SelectionHasFocus())
    return false;
  const VisibleSelection& selection =
      frame.Selection().ComputeVisibleSelectionInDOMTree();
  return selection.IsRange() && IsRichlyEditablePosition(selection.Anchor());
}

static bool EnabledRedo(LocalFrame& frame, Event*, EditorCommandSource) {
  return frame.GetEditor().CanRedo();
}

static bool EnabledUndo(LocalFrame& frame, Event*, EditorCommandSource) {
  return frame.GetEditor().CanUndo();
}

static bool EnabledUnselect(LocalFrame& frame,
                            Event* event,
                            EditorCommandSource source) {
  if (source == EditorCommandSource::kDOM &&
      frame.GetInputMethodController().GetActiveEditContext()) {
    return false;
  }

  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  // The term "visible" here includes a caret in editable text or a range in any
  // text.
  const VisibleSelection& selection =
      CreateVisibleSelection(frame.GetEditor().SelectionForCommand(event));
  return (selection.IsCaret() && selection.IsContentEditable()) ||
         selection.IsRange();
}

static bool EnabledSelectAll(LocalFrame& frame,
                             Event*,
                             EditorCommandSource source) {
  if (source == EditorCommandSource::kDOM &&
      frame.GetInputMethodController().GetActiveEditContext()) {
    return false;
  }

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  const VisibleSelection& selection =
      frame.Selection().ComputeVisibleSelectionInDOMTree();
  if (selection.IsNone())
    return true;
  // Hidden selection appears as no selection to users, in which case user-
  // triggered SelectAll should be enabled and act as if there is no selection.
  if (source == EditorCommandSource::kMenuOrKeyBinding &&
      frame.Selection().IsHidden())
    return true;
  if (Node* root = HighestEditableRoot(selection.Start())) {
    if (!root->hasChildren())
      return false;

    // When the editable appears as an empty line without any visible content,
    // allowing select-all confuses users.
    if (root->firstChild() == root->lastChild()) {
      if (IsA<HTMLBRElement>(root->firstChild())) {
        return false;
      }
      if (RuntimeEnabledFeatures::DisableSelectAllForEmptyTextEnabled()) {
        if (Text* text = DynamicTo<Text>(root->firstChild())) {
          LayoutText* layout_text = text->GetLayoutObject();
          if (!layout_text || !layout_text->HasNonCollapsedText()) {
            return false;
          }
        }
      }
    }

    // TODO(amaralp): Return false if already fully selected.
  }
  // TODO(amaralp): Address user-select handling.
  return true;
}

// State functions

static EditingTriState StateNone(LocalFrame&, Event*) {
  return EditingTriState::kFalse;
}

EditingTriState StateOrderedList(LocalFrame& frame, Event*) {
  return SelectionListState(frame, html_names::kOlTag);
}

static EditingTriState StateUnorderedList(LocalFrame& frame, Event*) {
  return SelectionListState(frame, html_names::kUlTag);
}

static EditingTriState StateJustifyCenter(LocalFrame& frame, Event*) {
  return StyleCommands::StateStyle(frame, CSSPropertyID::kTextAlign, "center");
}

static EditingTriState StateJustifyFull(LocalFrame& frame, Event*) {
  return StyleCommands::StateStyle(frame, CSSPropertyID::kTextAlign, "justify");
}

static EditingTriState StateJustifyLeft(LocalFrame& frame, Event*) {
  return StyleCommands::StateStyle(frame, CSSPropertyID::kTextAlign, "left");
}

static EditingTriState StateJustifyRight(LocalFrame& frame, Event*) {
  return StyleCommands::StateStyle(frame, CSSPropertyID::kTextAlign, "right");
}

// Value functions

static String ValueStateOrNull(const EditorInternalCommand& self,
                               LocalFrame& frame,
                               Event* triggering_event) {
  if (self.state == StateNone)
    return String();
  return self.state(frame, triggering_event) == EditingTriState::kTrue
             ? "true"
             : "false";
}

// The command has no value.
// https://w3c.github.io/editing/execCommand.html#querycommandvalue()
// > ... or has no value, return the empty string.
static String ValueEmpty(const EditorInternalCommand&, LocalFrame&, Event*) {
  return g_empty_string;
}

static String ValueDefaultParagraphSeparator(const EditorInternalCommand&,
                                             LocalFrame& frame,
                                             Event*) {
  switch (frame.GetEditor().DefaultParagraphSeparator()) {
    case EditorParagraphSeparator::kIsDiv:
      return html_names::kDivTag.LocalName();
    case EditorParagraphSeparator::kIsP:
      return html_names::kPTag.LocalName();
  }

  NOTREACHED();
}

static String ValueFormatBlock(const EditorInternalCommand&,
                               LocalFrame& frame,
                               Event*) {
  const VisibleSelection& selection =
      frame.Selection().ComputeVisibleSelectionInDOMTreeDeprecated();
  if (selection.IsNone() || !selection.IsValidFor(*(frame.GetDocument())) ||
      !selection.IsContentEditable())
    return "";
  Element* format_block_element =
      FormatBlockCommand::ElementForFormatBlockCommand(
          FirstEphemeralRangeOf(selection));
  if (!format_block_element)
    return "";
  return format_block_element->localName();
}

// CanExectue functions

static bool CanNotExecuteWhenDisabled(LocalFrame&, EditorCommandSource) {
  return false;
}

// Map of functions

static const EditorInternalCommand* InternalCommand(
    const String& command_name) {
  static const auto kEditorCommands = std::to_array<EditorInternalCommand>({
      // Lists all commands in blink::EditingCommandType.
      // Must be ordered by |commandType| for index lookup.
      // Covered by unit tests in editing_command_test.cc
      {EditingCommandType::kAlignJustified, ExecuteJustifyFull,
       SupportedFromMenuOrKeyBinding, EnabledInRichlyEditableText, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kAlignLeft, ExecuteJustifyLeft,
       SupportedFromMenuOrKeyBinding, EnabledInRichlyEditableText, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kAlignRight, ExecuteJustifyRight,
       SupportedFromMenuOrKeyBinding, EnabledInRichlyEditableText, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kBackColor, StyleCommands::ExecuteBackColor,
       Supported, EnabledInRichlyEditableText, StateNone,
       StyleCommands::ValueBackColor, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      // FIXME: remove BackwardDelete when Safari for Windows stops using it.
      {EditingCommandType::kBackwardDelete, ExecuteDeleteBackward,
       SupportedFromMenuOrKeyBinding, EnabledInEditableText, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kBold, StyleCommands::ExecuteToggleBold, Supported,
       EnabledInRichlyEditableText, StyleCommands::StateBold, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kCopy, ClipboardCommands::ExecuteCopy, Supported,
       ClipboardCommands::EnabledCopy, StateNone, ValueStateOrNull,
       kNotTextInsertion, ClipboardCommands::CanWriteClipboard},
      {EditingCommandType::kCreateLink, ExecuteCreateLink, Supported,
       EnabledInRichlyEditableText, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kCut, ClipboardCommands::ExecuteCut, Supported,
       ClipboardCommands::EnabledCut, StateNone, ValueStateOrNull,
       kNotTextInsertion, ClipboardCommands::CanWriteClipboard},
      {EditingCommandType::kDefaultParagraphSeparator,
       ExecuteDefaultParagraphSeparator, Supported, Enabled, StateNone,
       ValueDefaultParagraphSeparator, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kDelete, ExecuteDelete, Supported, EnabledDelete,
       StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kDeleteBackward, ExecuteDeleteBackward,
       SupportedFromMenuOrKeyBinding, EnabledInEditableText, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kDeleteBackwardByDecomposingPreviousCharacter,
       ExecuteDeleteBackwardByDecomposingPreviousCharacter,
       SupportedFromMenuOrKeyBinding, EnabledInEditableText, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kDeleteForward, ExecuteDeleteForward,
       SupportedFromMenuOrKeyBinding, EnabledInEditableText, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kDeleteToBeginningOfLine,
       ExecuteDeleteToBeginningOfLine, SupportedFromMenuOrKeyBinding,
       EnabledInEditableText, StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kDeleteToBeginningOfParagraph,
       ExecuteDeleteToBeginningOfParagraph, SupportedFromMenuOrKeyBinding,
       EnabledInEditableText, StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kDeleteToEndOfLine, ExecuteDeleteToEndOfLine,
       SupportedFromMenuOrKeyBinding, EnabledInEditableText, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kDeleteToEndOfParagraph,
       ExecuteDeleteToEndOfParagraph, SupportedFromMenuOrKeyBinding,
       EnabledInEditableText, StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kDeleteToMark, ExecuteDeleteToMark,
       SupportedFromMenuOrKeyBinding, EnabledInEditableText, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kDeleteWordBackward, ExecuteDeleteWordBackward,
       SupportedFromMenuOrKeyBinding, EnabledInEditableText, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kDeleteWordForward, ExecuteDeleteWordForward,
       SupportedFromMenuOrKeyBinding, EnabledInEditableText, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kFindString, ExecuteFindString, Supported, Enabled,
       StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kFontName, StyleCommands::ExecuteFontName, Supported,
       EnabledInRichlyEditableText, StateNone, StyleCommands::ValueFontName,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kFontSize, StyleCommands::ExecuteFontSize, Supported,
       EnabledInRichlyEditableText, StateNone, StyleCommands::ValueFontSize,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kFontSizeDelta, StyleCommands::ExecuteFontSizeDelta,
       Supported, EnabledInRichlyEditableText, StateNone,
       StyleCommands::ValueFontSizeDelta, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kForeColor, StyleCommands::ExecuteForeColor,
       Supported, EnabledInRichlyEditableText, StateNone,
       StyleCommands::ValueForeColor, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kFormatBlock, ExecuteFormatBlock, Supported,
       EnabledInRichlyEditableText, StateNone, ValueFormatBlock,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kForwardDelete, ExecuteForwardDelete, Supported,
       EnabledInEditableText, StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kHiliteColor, StyleCommands::ExecuteBackColor,
       Supported, EnabledInRichlyEditableText, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kIgnoreSpelling, ExecuteIgnoreSpelling,
       SupportedFromMenuOrKeyBinding, EnabledInEditableText, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kIndent, ExecuteIndent, Supported,
       EnabledInRichlyEditableText, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kInsertBacktab, InsertCommands::ExecuteInsertBacktab,
       SupportedFromMenuOrKeyBinding, EnabledInEditableText, StateNone,
       ValueStateOrNull, kIsTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kInsertHTML, InsertCommands::ExecuteInsertHTML,
       Supported, EnabledInEditableText, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kInsertHorizontalRule,
       InsertCommands::ExecuteInsertHorizontalRule, Supported,
       EnabledInRichlyEditableText, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kInsertImage, InsertCommands::ExecuteInsertImage,
       Supported, EnabledInRichlyEditableText, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kInsertLineBreak,
       InsertCommands::ExecuteInsertLineBreak, Supported, EnabledInEditableText,
       StateNone, ValueStateOrNull, kIsTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kInsertNewline, InsertCommands::ExecuteInsertNewline,
       SupportedFromMenuOrKeyBinding, EnabledInEditableText, StateNone,
       ValueStateOrNull, kIsTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kInsertNewlineInQuotedContent,
       InsertCommands::ExecuteInsertNewlineInQuotedContent, Supported,
       EnabledInRichlyEditableText, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kInsertOrderedList,
       InsertCommands::ExecuteInsertOrderedList, Supported,
       EnabledInRichlyEditableText, StateOrderedList, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kInsertParagraph,
       InsertCommands::ExecuteInsertParagraph, Supported, EnabledInEditableText,
       StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kInsertTab, InsertCommands::ExecuteInsertTab,
       SupportedFromMenuOrKeyBinding, EnabledInEditableText, StateNone,
       ValueStateOrNull, kIsTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kInsertText, InsertCommands::ExecuteInsertText,
       Supported, EnabledInEditableText, StateNone, ValueStateOrNull,
       kIsTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kInsertUnorderedList,
       InsertCommands::ExecuteInsertUnorderedList, Supported,
       EnabledInRichlyEditableText, StateUnorderedList, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kItalic, StyleCommands::ExecuteToggleItalic,
       Supported, EnabledInRichlyEditableText, StyleCommands::StateItalic,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kJustifyCenter, ExecuteJustifyCenter, Supported,
       EnabledInRichlyEditableText, StateJustifyCenter, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kJustifyFull, ExecuteJustifyFull, Supported,
       EnabledInRichlyEditableText, StateJustifyFull, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kJustifyLeft, ExecuteJustifyLeft, Supported,
       EnabledInRichlyEditableText, StateJustifyLeft, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kJustifyNone, ExecuteJustifyLeft, Supported,
       EnabledInRichlyEditableText, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kJustifyRight, ExecuteJustifyRight, Supported,
       EnabledInRichlyEditableText, StateJustifyRight, V
"""


```