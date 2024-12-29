Response:
My thought process to answer the request goes like this:

1. **Understand the Core Request:** The main goal is to analyze the provided C++ code snippet (`editor_command.cc`) and describe its functionality, relating it to web technologies (HTML, CSS, JavaScript) where applicable. The request also emphasizes identifying user errors, debugging hints, and a summary of its purpose.

2. **Initial Code Scan and Keyword Identification:** I first skimmed the code for immediately recognizable keywords and patterns:
    * `#include`: Indicates dependency on other files, giving clues about the module's scope (editing, commands, DOM).
    * `namespace blink`: Confirms this is part of the Blink rendering engine.
    * `EditingCommandType`:  Suggests a system for classifying editing actions.
    * `EditorCommandSource`: Indicates where the command originates (menu, keybinding, DOM).
    * Function names like `Execute...`, `Can...`, `State...`: These are key to understanding the actions the code performs and their status.
    * Inclusion of specific command files (e.g., `clipboard_commands.h`, `create_link_command.h`):  Highlights the different categories of editing commands.
    * References to HTML tags (`html_names::kUlTag`, `html_names::kOlTag`):  Direct connection to HTML.
    * References to CSS properties (`CSSPropertyID::kTextAlign`): Direct connection to CSS.
    *  `InputEvent::InputType`: Connection to the Input Events specification.

3. **Categorization of Functionality:** Based on the keywords and included files, I started mentally grouping the functionalities:
    * **Command Definition and Mapping:** The `kCommandNameEntries` array and `EditingCommandTypeFromCommandName` function clearly deal with associating string names with specific command types.
    * **Command Execution:** The `Execute...` functions are the core logic for performing different editing actions.
    * **Command State and Support:** The `is_enabled`, `is_supported_from_dom`, and `state` functions provide information about the current availability and state of commands.
    * **Text Manipulation:**  Functions related to deleting, inserting, and formatting text (bold, italic, lists, links).
    * **Navigation and Scrolling:** Functions for moving the cursor and scrolling the page.
    * **Clipboard Operations:**  Although the code snippet doesn't detail these, the inclusion of `clipboard_commands.h` indicates their involvement.
    * **Undo/Redo:** Explicit mention of `UndoStack` and `ExecuteUndo`, `ExecuteRedo`.
    * **Selection Management:**  Functions for getting and manipulating the current selection.

4. **Relating to Web Technologies:**  This is where I connect the C++ code to the user-facing aspects:
    * **HTML:**  Commands like `InsertOrderedList`, `InsertUnorderedList`, `CreateLink`, and `FormatBlock` directly manipulate the HTML structure. The code explicitly checks for HTML tag names.
    * **CSS:** Commands like `JustifyCenter`, `JustifyLeft`, etc., modify CSS properties. The code parses and applies CSS values.
    * **JavaScript:**  JavaScript code in a web page can trigger these commands using `document.execCommand()`. This is the primary entry point from the scripting world.

5. **Examples and Scenarios:** To illustrate the connections, I thought of common user actions and how they might lead to these commands:
    * **User Action:** Selecting text and clicking the "Bold" button.
    * **Connection:** This would likely trigger the `Bold` command.
    * **C++ Function:**  The `ExecuteBold` function (or a similar style command).
    * **Impact:**  The selected HTML elements would have the appropriate CSS style applied (`font-weight: bold`).

6. **Logical Reasoning (Input/Output):** I considered simple command examples:
    * **Input (Command):** "InsertText", "Hello"
    * **Output:** The text "Hello" would be inserted at the current cursor position.
    * **Input (Command):** "Bold" (with text selected)
    * **Output:** The selected text would be bolded (HTML might be wrapped in `<b>` or `<strong>`, or a CSS style applied).

7. **User/Programming Errors:** I thought about common mistakes developers or users might make:
    * **Incorrect Command Names:**  Using a misspelled or non-existent command name with `document.execCommand()`.
    * **Invalid Arguments:** Providing incorrect or missing arguments to commands that require them (e.g., an empty URL for `CreateLink`).
    * **Applying Commands in the Wrong Context:** Trying to apply formatting commands when there's no text selection.

8. **Debugging Hints (User Path):** I traced a simple user action:
    * User types in an input field.
    * This triggers input events.
    * The browser determines the appropriate `EditingCommandType` (e.g., `InsertText`).
    * The corresponding `Execute` function in `editor_command.cc` is called.

9. **Summarization:** Finally, I condensed the findings into a concise summary, highlighting the core responsibility of the file.

10. **Structure and Refinement:** I organized the information logically, using headings and bullet points for clarity. I reviewed the output to ensure it addressed all parts of the request and was easy to understand. I specifically made sure to label this as "Part 1" as requested.

By following these steps, I could systematically analyze the code and generate a comprehensive and informative response that addressed all the points in the original request.
```cpp
/*
 * Copyright (C) 2006, 2007, 2008 Apple Inc. All rights reserved.
 * Copyright (C) 2008 Nokia Corporation and/or its subsidiary(-ies)
 * Copyright (C) 2009 Igalia S.L.
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
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/editing/commands/editor_command.h"

#include <array>
#include <iterator>

#include "base/metrics/histogram_functions.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/tag_collection.h"
#include "third_party/blink/renderer/core/editing/commands/clipboard_commands.h"
#include "third_party/blink/renderer/core/editing/commands/create_link_command.h"
#include "third_party/blink/renderer/core/editing/commands/editing_command_type.h"
#include "third_party/blink/renderer/core/editing/commands/editing_commands_utilities.h"
#include "third_party/blink/renderer/core/editing/commands/editor_command_names.h"
#include "third_party/blink/renderer/core/editing/commands/format_block_command.h"
#include "third_party/blink/renderer/core/editing/commands/indent_outdent_command.h"
#include "third_party/blink/renderer/core/editing/commands/insert_commands.h"
#include "third_party/blink/renderer/core/editing/commands/move_commands.h"
#include "third_party/blink/renderer/core/editing/commands/remove_format_command.h"
#include "third_party/blink/renderer/core/editing/commands/style_commands.h"
#party/blink/renderer/core/editing/commands/typing_command.h"
#include "third_party/blink/renderer/core/editing/commands/undo_stack.h"
#include "third_party/blink/renderer/core/editing/commands/unlink_command.h"
#include "third_party/blink/renderer/core/editing/editing_tri_state.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/edit_context.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/kill_ring.h"
#include "third_party/blink/renderer/core/editing/selection_modifier.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/set_selection_options.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_checker.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/input/keyboard_shortcut_recorder.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/scroll/scrollbar.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"

namespace blink {

namespace {

struct CommandNameEntry {
  const char* name;
  EditingCommandType type;
};

const CommandNameEntry kCommandNameEntries[] = {
#define V(name) {#name, EditingCommandType::k##name},
    FOR_EACH_BLINK_EDITING_COMMAND_NAME(V)
#undef V
};
// Handles all commands except EditingCommandType::Invalid.
static_assert(
    std::size(kCommandNameEntries) + 1 ==
        static_cast<size_t>(EditingCommandType::kNumberOfCommandTypes),
    "must handle all valid EditingCommandType");

EditingCommandType EditingCommandTypeFromCommandName(
    const String& command_name) {
  const CommandNameEntry* result = std::lower_bound(
      std::begin(kCommandNameEntries), std::end(kCommandNameEntries),
      command_name, [](const CommandNameEntry& entry, const String& needle) {
        return CodeUnitCompareIgnoringASCIICase(needle, entry.name) > 0;
      });
  if (result != std::end(kCommandNameEntries) &&
      CodeUnitCompareIgnoringASCIICase(command_name, result->name) == 0)
    return result->type;
  return EditingCommandType::kInvalid;
}

// |frame| is only used for |InsertNewline| due to how |executeInsertNewline()|
// works.
InputEvent::InputType InputTypeFromCommandType(EditingCommandType command_type,
                                               LocalFrame& frame) {
  // We only handle InputType on spec for 'beforeinput'.
  // http://w3c.github.io/editing/input-events.html
  using CommandType = EditingCommandType;
  using InputType = InputEvent::InputType;

  // |executeInsertNewline()| could do two things but we have no other ways to
  // predict.
  if (command_type == CommandType::kInsertNewline)
    return frame.GetEditor().CanEditRichly() ? InputType::kInsertParagraph
                                             : InputType::kInsertLineBreak;

  switch (command_type) {
    // Insertion.
    case CommandType::kInsertBacktab:
    case CommandType::kInsertText:
      return InputType::kInsertText;
    case CommandType::kInsertLineBreak:
      return InputType::kInsertLineBreak;
    case CommandType::kInsertParagraph:
    case CommandType::kInsertNewlineInQuotedContent:
      return InputType::kInsertParagraph;
    case CommandType::kInsertHorizontalRule:
      return InputType::kInsertHorizontalRule;
    case CommandType::kInsertOrderedList:
      return InputType::kInsertOrderedList;
    case CommandType::kInsertUnorderedList:
      return InputType::kInsertUnorderedList;
    case CommandType::kCreateLink:
      return InputType::kInsertLink;

    // Deletion.
    case CommandType::kDelete:
    case CommandType::kDeleteBackward:
    case CommandType::kDeleteBackwardByDecomposingPreviousCharacter:
      return InputType::kDeleteContentBackward;
    case CommandType::kDeleteForward:
      return InputType::kDeleteContentForward;
    case CommandType::kDeleteToBeginningOfLine:
      return InputType::kDeleteSoftLineBackward;
    case CommandType::kDeleteToEndOfLine:
      return InputType::kDeleteSoftLineForward;
    case CommandType::kDeleteWordBackward:
      return InputType::kDeleteWordBackward;
    case CommandType::kDeleteWordForward:
      return InputType::kDeleteWordForward;
    case CommandType::kDeleteToBeginningOfParagraph:
      return InputType::kDeleteHardLineBackward;
    case CommandType::kDeleteToEndOfParagraph:
      return InputType::kDeleteHardLineForward;
    // TODO(editing-dev): Find appreciate InputType for following commands.
    case CommandType::kDeleteToMark:
      return InputType::kNone;

    // Command.
    case CommandType::kUndo:
      return InputType::kHistoryUndo;
    case CommandType::kRedo:
      return InputType::kHistoryRedo;
    // Cut and Paste will be handled in |Editor::dispatchCPPEvent()|.

    // Styling.
    case CommandType::kBold:
    case CommandType::kToggleBold:
      return InputType::kFormatBold;
    case CommandType::kItalic:
    case CommandType::kToggleItalic:
      return InputType::kFormatItalic;
    case CommandType::kUnderline:
    case CommandType::kToggleUnderline:
      return InputType::kFormatUnderline;
    case CommandType::kStrikethrough:
      return InputType::kFormatStrikeThrough;
    case CommandType::kSuperscript:
      return InputType::kFormatSuperscript;
    case CommandType::kSubscript:
      return InputType::kFormatSubscript;
    default:
      return InputType::kNone;
  }
}

StaticRangeVector* RangesFromCurrentSelectionOrExtendCaret(
    const LocalFrame& frame,
    SelectionModifyDirection direction,
    TextGranularity granularity) {
  // Due to interoperability differences in getTargetRanges() when deleting
  // content, we do not provide these ranges for EditContext. Developers are
  // expected to compute the ranges themselves based on selection position.
  // See https://github.com/w3c/input-events/issues/146.
  if (frame.GetInputMethodController().GetActiveEditContext()) {
    return nullptr;
  }

  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  SelectionModifier selection_modifier(
      frame, frame.Selection().GetSelectionInDOMTree());
  selection_modifier.SetSelectionIsDirectional(
      frame.Selection().IsDirectional());
  if (selection_modifier.Selection().IsCaret())
    selection_modifier.Modify(SelectionModifyAlteration::kExtend, direction,
                              granularity);
  StaticRangeVector* ranges = MakeGarbageCollected<StaticRangeVector>();
  // We only supports single selections.
  if (selection_modifier.Selection().IsNone())
    return ranges;
  ranges->push_back(StaticRange::Create(
      FirstEphemeralRangeOf(selection_modifier.Selection())));
  return ranges;
}

EphemeralRange ComputeRangeForTranspose(LocalFrame& frame) {
  const VisibleSelection& selection =
      frame.Selection().ComputeVisibleSelectionInDOMTree();
  if (!selection.IsCaret())
    return EphemeralRange();

  // Make a selection that goes back one character and forward two characters.
  const VisiblePosition& caret = selection.VisibleStart();
  const VisiblePosition& next =
      IsEndOfParagraph(caret) ? caret : NextPositionOf(caret);
  const VisiblePosition& previous = PreviousPositionOf(next);
  if (next.DeepEquivalent() == previous.DeepEquivalent())
    return EphemeralRange();
  const VisiblePosition& previous_of_previous = PreviousPositionOf(previous);
  if (!InSameParagraph(next, previous_of_previous))
    return EphemeralRange();
  return MakeRange(previous_of_previous, next);
}

}  // anonymous namespace

class EditorInternalCommand {
  STACK_ALLOCATED();

 public:
  EditingCommandType command_type;
  bool (*execute)(LocalFrame&, Event*, EditorCommandSource, const String&);
  bool (*is_supported_from_dom)(LocalFrame*);
  bool (*is_enabled)(LocalFrame&, Event*, EditorCommandSource);
  EditingTriState (*state)(LocalFrame&, Event*);
  String (*value)(const EditorInternalCommand&, LocalFrame&, Event*);
  bool is_text_insertion;
  bool (*can_execute)(LocalFrame&, EditorCommandSource);
};

static const bool kNotTextInsertion = false;
static const bool kIsTextInsertion = true;

static bool ExecuteApplyParagraphStyle(LocalFrame& frame,
                                       EditorCommandSource source,
                                       InputEvent::InputType input_type,
                                       CSSPropertyID property_id,
                                       const String& property_value) {
  auto* style =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode);
  style->ParseAndSetProperty(property_id, property_value, /* important */ false,
                             frame.DomWindow()->GetSecureContextMode());
  // FIXME: We don't call shouldApplyStyle when the source is DOM; is there a
  // good reason for that?
  switch (source) {
    case EditorCommandSource::kMenuOrKeyBinding:
      frame.GetEditor().ApplyParagraphStyleToSelection(style, input_type);
      return true;
    case EditorCommandSource::kDOM:
      frame.GetEditor().ApplyParagraphStyle(style, input_type);
      return true;
  }
  NOTREACHED();
}

bool ExpandSelectionToGranularity(LocalFrame& frame,
                                  TextGranularity granularity) {
  const SelectionInDOMTree& selection = ExpandWithGranularity(
      frame.Selection().ComputeVisibleSelectionInDOMTree().AsSelection(),
      granularity);
  const EphemeralRange& new_range = NormalizeRange(selection);
  if (new_range.IsNull())
    return false;
  if (new_range.IsCollapsed())
    return false;
  frame.Selection().SetSelection(
      SelectionInDOMTree::Builder().SetBaseAndExtent(new_range).Build(),
      SetSelectionOptions::Builder().SetShouldCloseTyping(true).Build());
  return true;
}

static bool HasChildTags(Element& element, const QualifiedName& tag_name) {
  return !element.getElementsByTagName(tag_name.LocalName())->IsEmpty();
}

static EditingTriState SelectionListState(LocalFrame& frame,
                                          const QualifiedName& tag_name) {
  if (frame.GetInputMethodController().GetActiveEditContext()) {
    return EditingTriState::kFalse;
  }

  const FrameSelection& selection = frame.Selection();
  if (selection.ComputeVisibleSelectionInDOMTreeDeprecated().IsCaret()) {
    if (EnclosingElementWithTag(
            selection.ComputeVisibleSelectionInDOMTreeDeprecated().Start(),
            tag_name))
      return EditingTriState::kTrue;
  } else if (selection.ComputeVisibleSelectionInDOMTreeDeprecated().IsRange()) {
    Element* start_element = EnclosingElementWithTag(
        selection.ComputeVisibleSelectionInDOMTreeDeprecated().Start(),
        tag_name);
    Element* end_element = EnclosingElementWithTag(
        selection.ComputeVisibleSelectionInDOMTreeDeprecated().End(), tag_name);

    if (start_element && end_element && start_element == end_element) {
      // If the selected list has the different type of list as child, return
      // |FalseTriState|.
      // See http://crbug.com/385374
      if (HasChildTags(*start_element, tag_name.Matches(html_names::kUlTag)
                                           ? html_names::kOlTag
                                           : html_names::kUlTag))
        return EditingTriState::kFalse;
      return EditingTriState::kTrue;
    }
  }

  return EditingTriState::kFalse;
}

static EphemeralRange UnionEphemeralRanges(const EphemeralRange& range1,
                                           const EphemeralRange& range2) {
  const Position start_position =
      range1.StartPosition().CompareTo(range2.StartPosition()) <= 0
          ? range1.StartPosition()
          : range2.StartPosition();
  const Position end_position =
      range1.EndPosition().CompareTo(range2.EndPosition()) <= 0
          ? range1.EndPosition()
          : range2.EndPosition();
  return EphemeralRange(start_position, end_position);
}

// Execute command functions

static bool CanSmartCopyOrDelete(LocalFrame& frame) {
  return frame.GetEditor().SmartInsertDeleteEnabled() &&
         frame.Selection().Granularity() == TextGranularity::kWord;
}

static bool ExecuteCreateLink(LocalFrame& frame,
                              Event*,
                              EditorCommandSource,
                              const String& value) {
  if (value.empty())
    return false;
  DCHECK(frame.GetDocument());
  return MakeGarbageCollected<CreateLinkCommand>(*frame.GetDocument(), value)
      ->Apply();
}

static bool ExecuteDefaultParagraphSeparator(LocalFrame& frame,
                                             Event*,
                                             EditorCommandSource,
                                             const String& value) {
  if (EqualIgnoringASCIICase(value, "div")) {
    frame.GetEditor().SetDefaultParagraphSeparator(
        EditorParagraphSeparator::kIsDiv);
    return true;
  }
  if (EqualIgnoringASCIICase(value, "p")) {
    frame.GetEditor().SetDefaultParagraphSeparator(
        EditorParagraphSeparator::kIsP);
  }
  return true;
}

static void PerformDelete(LocalFrame& frame) {
  if (!frame.GetEditor().CanDelete())
    return;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. See http://crbug.com/590369 for more details.
  // |SelectedRange| requires clean layout for visible selection normalization.
  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  frame.GetEditor().AddToKillRing(frame.GetEditor().SelectedRange());
  // TODO(editing-dev): |Editor::performDelete()| has no direction.
  // https://github.com/w3c/editing/issues/130
  frame.GetEditor().DeleteSelectionWithSmartDelete(
      CanSmartCopyOrDelete(frame) ? DeleteMode::kSmart : DeleteMode::kSimple,
      InputEvent::InputType::kDeleteContentBackward);

  // clear the "start new kill ring sequence" setting, because it was set to
  // true when the selection was updated by deleting the range
  frame.GetEditor().SetStartNewKillRingSequence(false);
}

static bool ExecuteDelete(LocalFrame& frame,
                          Event*,
                          EditorCommandSource source,
                          const String&) {
  switch (source) {
    case EditorCommandSource::kMenuOrKeyBinding: {
      // Doesn't modify the text if the current selection isn't a range.
      PerformDelete(frame);
      return true;
    }
    case EditorCommandSource::kDOM:
      // If the current selection is a caret, delete the preceding character. IE
      // performs forwardDelete, but we currently side with Firefox. Doesn't
      // scroll to make the selection visible, or modify the kill ring (this
      // time, siding with IE, not Firefox).
      DCHECK(frame.GetDocument());
      TypingCommand::DeleteKeyPressed(
          *frame.GetDocument(),
          frame.Selection().Granularity() == TextGranularity::kWord
              ? TypingCommand::kSmartDelete
              : 0);
      return true;
  }
  NOTREACHED();
}

static bool DeleteWithDirection(LocalFrame& frame,
                                DeleteDirection direction,
                                TextGranularity granularity,
                                bool kill_ring,
                                bool is_typing_action) {
  Editor& editor = frame.GetEditor();
  if (!editor.CanEdit())
    return false;

  if (frame.Selection()
          .ComputeVisibleSelectionInDOMTreeDeprecated()
          .IsRange() &&
      !is_typing_action) {
    if (kill_ring) {
      editor.AddToKillRing(editor.SelectedRange());
    }
    editor.DeleteSelectionWithSmartDelete(
        CanSmartCopyOrDelete(frame) ? DeleteMode::kSmart : DeleteMode::kSimple,
        DeletionInputTypeFromTextGranularity(direction, granularity));
    // Implicitly calls revealSelectionAfterEditingOperation().
  } else {
    EditingState editing_state;
    TypingCommand::Options options = 0;
    if (CanSmartCopyOrDelete(frame))
      options |= TypingCommand::kSmartDelete;
    if (kill_ring)
      options |= TypingCommand::kKillRing;
    DCHECK(frame.GetDocument());
    switch (direction) {
      case DeleteDirection::kForward:
        TypingCommand::ForwardDeleteKeyPressed(
            *frame.GetDocument(), &editing_state, options, granularity);
        if (editing_state.IsAborted())
          return false;
        break;
      case DeleteDirection::kBackward:
        TypingCommand::DeleteKeyPressed(*frame.GetDocument(), options,
                                        granularity);
        break;
    }
    editor.RevealSelectionAfterEditingOperation();
  }

  // FIXME: We should to move this down into deleteKeyPressed.
  // clear the "start new kill ring sequence" setting, because it was set to
  // true when the selection was updated by deleting the range
  if (kill_ring)
    editor.SetStartNewKillRingSequence(false);

  return true;
}

static bool ExecuteDeleteBackward(LocalFrame& frame,
                                  Event*,
                                  EditorCommandSource,
                                  const String&) {
  DeleteWithDirection(frame, DeleteDirection::kBackward,
                      TextGranularity::kCharacter, false, true);
  return true;
}

static bool ExecuteDeleteBackwardByDecomposingPreviousCharacter(
    LocalFrame& frame,
    Event*,
    EditorCommandSource,
    const String&) {
  DLOG(ERROR) << "DeleteBackwardByDecomposingPreviousCharacter is not "
                 "implemented, doing DeleteBackward instead";
  DeleteWithDirection(frame, DeleteDirection::kBackward,
                      TextGranularity::kCharacter, false, true);
  return true;
}

static bool ExecuteDeleteForward(LocalFrame& frame,
                                 Event*,
                                 EditorCommandSource,
                                 const String&) {
  DeleteWithDirection(frame, DeleteDirection::kForward,
                      TextGranularity::kCharacter, false, true);
  return true;
}

static bool ExecuteDeleteToBeginningOfLine(LocalFrame& frame,
                                           Event*,
                                           EditorCommandSource,
                                           const String&) {
#if BUILDFLAG(IS_ANDROID)
  RecordKeyboardShortcutForAndroid(KeyboardShortcut::kDeleteLine);
#endif  // BUILDFLAG(IS_ANDROID)

  DeleteWithDirection(frame, DeleteDirection::kBackward,
                      TextGranularity::kLineBoundary, true, false);
  return true;
}

static bool ExecuteDeleteToBeginningOfParagraph(LocalFrame& frame,
                                                Event*,
                                                EditorCommandSource,
                                                const String&) {
  DeleteWithDirection(frame, DeleteDirection::kBackward,
                      TextGranularity::kParagraphBoundary, true, false);
  return true;
}

static bool ExecuteDeleteToEndOfLine(LocalFrame& frame,
                                     Event*,
                                     EditorCommandSource,
                                     const String&) {
  // Despite its name, this command should delete the newline at the end of a
  // paragraph if you are at the end of a paragraph (like
  // DeleteToEndOfParagraph).
  DeleteWithDirection(frame, DeleteDirection::kForward,
                      TextGranularity::kLineBoundary, true, false);
  return true;
}

static bool ExecuteDeleteToEndOfParagraph(LocalFrame& frame,
                                          Event*,
                                          EditorCommandSource,
                                          const String&) {
  // Despite its name, this command should delete the newline at the end of
  // a paragraph if you are at the end of a paragraph.
  DeleteWithDirection(frame, DeleteDirection::kForward,
                      TextGranularity::kParagraphBoundary, true, false);
  return true;
}

static bool ExecuteDeleteToMark(LocalFrame& frame,
                                Event*,
                                EditorCommandSource,
                                const String&) {
  const EphemeralRange mark =
      frame.GetEditor().Mark().ToNormalizedEphemeralRange();
  if (mark.IsNotNull()) {
    frame.Selection().SetSelection(
        SelectionInDOMTree::Builder()
            .SetBaseAndExtent(
                UnionEphemeralRanges(mark, frame.GetEditor().SelectedRange()))
            .Build(),
        SetSelectionOptions::Builder().SetShouldCloseTyping(true).Build());
  }
  PerformDelete(frame);

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. See http://crbug.com/590369 for more details.
  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  frame.GetEditor().SetMark();
  return true;
}

static bool ExecuteDeleteWordBackward(LocalFrame& frame,
                                      Event*,
                                      EditorCommandSource,
                                      const String&) {
  DeleteWithDirection(frame, DeleteDirection::kBackward, TextGranularity::kWord,
                      true, false);
  return true;
}

static bool ExecuteDeleteWordForward(LocalFrame& frame,
                                     Event*,
                                     EditorCommandSource,
                                     const String&) {
  DeleteWithDirection(frame, DeleteDirection::kForward, TextGranularity::kWord,
                      true, false);
  return true;
}

static bool ExecuteFindString(LocalFrame& frame,
                              Event*,
                              EditorCommandSource,
                              const String& value) {
  return Editor::FindString(
      frame, value,
      FindOptions().SetCaseInsensitive(true).SetWrappingAround(true));
}

static bool ExecuteFormatBlock(LocalFrame& frame,
                               Event*,
                               EditorCommandSource,
                               const String& value) {
  String tag_name = value.DeprecatedLower();
  if (tag_name[0] == '<' && tag_name[tag_name.length() - 1] == '>')
    tag_name = tag_name.Substring(1, tag_name.length() - 2);

  AtomicString local_name, prefix;
  if (!Document::ParseQualifiedName(AtomicString(tag_name), prefix, local_name,
                                    IGNORE_EXCEPTION_FOR_TESTING))
    return false;
  QualifiedName qualified_tag_name(prefix, local_name,
                                   html_names::xhtmlNamespaceURI);

  DCHECK(frame.GetDocument());
  auto* command = MakeGarbageCollected<FormatBlockCommand>(*frame.GetDocument(),
                                                           qualified_tag_name);
  command->Apply();
  return command->DidApply();
}

static bool ExecuteForwardDelete(LocalFrame& frame,
                                 Event*,
                                 EditorCommandSource source,
                                 const String&) {
  EditingState editing_state;
  switch (source) {
    case EditorCommandSource::kMenuOrKeyBinding:
      DeleteWithDirection(frame, DeleteDirection::kForward,
                          TextGranularity::kCharacter, false, true);
      return true;
    case EditorCommandSource::kDOM:
      // Doesn't scroll to make the selection visible, or modify the kill
Prompt: 
```
这是目录为blink/renderer/core/editing/commands/editor_command.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2006, 2007, 2008 Apple Inc. All rights reserved.
 * Copyright (C) 2008 Nokia Corporation and/or its subsidiary(-ies)
 * Copyright (C) 2009 Igalia S.L.
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

#include "third_party/blink/renderer/core/editing/commands/editor_command.h"

#include <array>
#include <iterator>

#include "base/metrics/histogram_functions.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/tag_collection.h"
#include "third_party/blink/renderer/core/editing/commands/clipboard_commands.h"
#include "third_party/blink/renderer/core/editing/commands/create_link_command.h"
#include "third_party/blink/renderer/core/editing/commands/editing_command_type.h"
#include "third_party/blink/renderer/core/editing/commands/editing_commands_utilities.h"
#include "third_party/blink/renderer/core/editing/commands/editor_command_names.h"
#include "third_party/blink/renderer/core/editing/commands/format_block_command.h"
#include "third_party/blink/renderer/core/editing/commands/indent_outdent_command.h"
#include "third_party/blink/renderer/core/editing/commands/insert_commands.h"
#include "third_party/blink/renderer/core/editing/commands/move_commands.h"
#include "third_party/blink/renderer/core/editing/commands/remove_format_command.h"
#include "third_party/blink/renderer/core/editing/commands/style_commands.h"
#include "third_party/blink/renderer/core/editing/commands/typing_command.h"
#include "third_party/blink/renderer/core/editing/commands/undo_stack.h"
#include "third_party/blink/renderer/core/editing/commands/unlink_command.h"
#include "third_party/blink/renderer/core/editing/editing_tri_state.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/edit_context.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/kill_ring.h"
#include "third_party/blink/renderer/core/editing/selection_modifier.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/set_selection_options.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_checker.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/input/keyboard_shortcut_recorder.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/scroll/scrollbar.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"

namespace blink {

namespace {

struct CommandNameEntry {
  const char* name;
  EditingCommandType type;
};

const CommandNameEntry kCommandNameEntries[] = {
#define V(name) {#name, EditingCommandType::k##name},
    FOR_EACH_BLINK_EDITING_COMMAND_NAME(V)
#undef V
};
// Handles all commands except EditingCommandType::Invalid.
static_assert(
    std::size(kCommandNameEntries) + 1 ==
        static_cast<size_t>(EditingCommandType::kNumberOfCommandTypes),
    "must handle all valid EditingCommandType");

EditingCommandType EditingCommandTypeFromCommandName(
    const String& command_name) {
  const CommandNameEntry* result = std::lower_bound(
      std::begin(kCommandNameEntries), std::end(kCommandNameEntries),
      command_name, [](const CommandNameEntry& entry, const String& needle) {
        return CodeUnitCompareIgnoringASCIICase(needle, entry.name) > 0;
      });
  if (result != std::end(kCommandNameEntries) &&
      CodeUnitCompareIgnoringASCIICase(command_name, result->name) == 0)
    return result->type;
  return EditingCommandType::kInvalid;
}

// |frame| is only used for |InsertNewline| due to how |executeInsertNewline()|
// works.
InputEvent::InputType InputTypeFromCommandType(EditingCommandType command_type,
                                               LocalFrame& frame) {
  // We only handle InputType on spec for 'beforeinput'.
  // http://w3c.github.io/editing/input-events.html
  using CommandType = EditingCommandType;
  using InputType = InputEvent::InputType;

  // |executeInsertNewline()| could do two things but we have no other ways to
  // predict.
  if (command_type == CommandType::kInsertNewline)
    return frame.GetEditor().CanEditRichly() ? InputType::kInsertParagraph
                                             : InputType::kInsertLineBreak;

  switch (command_type) {
    // Insertion.
    case CommandType::kInsertBacktab:
    case CommandType::kInsertText:
      return InputType::kInsertText;
    case CommandType::kInsertLineBreak:
      return InputType::kInsertLineBreak;
    case CommandType::kInsertParagraph:
    case CommandType::kInsertNewlineInQuotedContent:
      return InputType::kInsertParagraph;
    case CommandType::kInsertHorizontalRule:
      return InputType::kInsertHorizontalRule;
    case CommandType::kInsertOrderedList:
      return InputType::kInsertOrderedList;
    case CommandType::kInsertUnorderedList:
      return InputType::kInsertUnorderedList;
    case CommandType::kCreateLink:
      return InputType::kInsertLink;

    // Deletion.
    case CommandType::kDelete:
    case CommandType::kDeleteBackward:
    case CommandType::kDeleteBackwardByDecomposingPreviousCharacter:
      return InputType::kDeleteContentBackward;
    case CommandType::kDeleteForward:
      return InputType::kDeleteContentForward;
    case CommandType::kDeleteToBeginningOfLine:
      return InputType::kDeleteSoftLineBackward;
    case CommandType::kDeleteToEndOfLine:
      return InputType::kDeleteSoftLineForward;
    case CommandType::kDeleteWordBackward:
      return InputType::kDeleteWordBackward;
    case CommandType::kDeleteWordForward:
      return InputType::kDeleteWordForward;
    case CommandType::kDeleteToBeginningOfParagraph:
      return InputType::kDeleteHardLineBackward;
    case CommandType::kDeleteToEndOfParagraph:
      return InputType::kDeleteHardLineForward;
    // TODO(editing-dev): Find appreciate InputType for following commands.
    case CommandType::kDeleteToMark:
      return InputType::kNone;

    // Command.
    case CommandType::kUndo:
      return InputType::kHistoryUndo;
    case CommandType::kRedo:
      return InputType::kHistoryRedo;
    // Cut and Paste will be handled in |Editor::dispatchCPPEvent()|.

    // Styling.
    case CommandType::kBold:
    case CommandType::kToggleBold:
      return InputType::kFormatBold;
    case CommandType::kItalic:
    case CommandType::kToggleItalic:
      return InputType::kFormatItalic;
    case CommandType::kUnderline:
    case CommandType::kToggleUnderline:
      return InputType::kFormatUnderline;
    case CommandType::kStrikethrough:
      return InputType::kFormatStrikeThrough;
    case CommandType::kSuperscript:
      return InputType::kFormatSuperscript;
    case CommandType::kSubscript:
      return InputType::kFormatSubscript;
    default:
      return InputType::kNone;
  }
}

StaticRangeVector* RangesFromCurrentSelectionOrExtendCaret(
    const LocalFrame& frame,
    SelectionModifyDirection direction,
    TextGranularity granularity) {
  // Due to interoperability differences in getTargetRanges() when deleting
  // content, we do not provide these ranges for EditContext. Developers are
  // expected to compute the ranges themselves based on selection position.
  // See https://github.com/w3c/input-events/issues/146.
  if (frame.GetInputMethodController().GetActiveEditContext()) {
    return nullptr;
  }

  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  SelectionModifier selection_modifier(
      frame, frame.Selection().GetSelectionInDOMTree());
  selection_modifier.SetSelectionIsDirectional(
      frame.Selection().IsDirectional());
  if (selection_modifier.Selection().IsCaret())
    selection_modifier.Modify(SelectionModifyAlteration::kExtend, direction,
                              granularity);
  StaticRangeVector* ranges = MakeGarbageCollected<StaticRangeVector>();
  // We only supports single selections.
  if (selection_modifier.Selection().IsNone())
    return ranges;
  ranges->push_back(StaticRange::Create(
      FirstEphemeralRangeOf(selection_modifier.Selection())));
  return ranges;
}

EphemeralRange ComputeRangeForTranspose(LocalFrame& frame) {
  const VisibleSelection& selection =
      frame.Selection().ComputeVisibleSelectionInDOMTree();
  if (!selection.IsCaret())
    return EphemeralRange();

  // Make a selection that goes back one character and forward two characters.
  const VisiblePosition& caret = selection.VisibleStart();
  const VisiblePosition& next =
      IsEndOfParagraph(caret) ? caret : NextPositionOf(caret);
  const VisiblePosition& previous = PreviousPositionOf(next);
  if (next.DeepEquivalent() == previous.DeepEquivalent())
    return EphemeralRange();
  const VisiblePosition& previous_of_previous = PreviousPositionOf(previous);
  if (!InSameParagraph(next, previous_of_previous))
    return EphemeralRange();
  return MakeRange(previous_of_previous, next);
}

}  // anonymous namespace

class EditorInternalCommand {
  STACK_ALLOCATED();

 public:
  EditingCommandType command_type;
  bool (*execute)(LocalFrame&, Event*, EditorCommandSource, const String&);
  bool (*is_supported_from_dom)(LocalFrame*);
  bool (*is_enabled)(LocalFrame&, Event*, EditorCommandSource);
  EditingTriState (*state)(LocalFrame&, Event*);
  String (*value)(const EditorInternalCommand&, LocalFrame&, Event*);
  bool is_text_insertion;
  bool (*can_execute)(LocalFrame&, EditorCommandSource);
};

static const bool kNotTextInsertion = false;
static const bool kIsTextInsertion = true;

static bool ExecuteApplyParagraphStyle(LocalFrame& frame,
                                       EditorCommandSource source,
                                       InputEvent::InputType input_type,
                                       CSSPropertyID property_id,
                                       const String& property_value) {
  auto* style =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode);
  style->ParseAndSetProperty(property_id, property_value, /* important */ false,
                             frame.DomWindow()->GetSecureContextMode());
  // FIXME: We don't call shouldApplyStyle when the source is DOM; is there a
  // good reason for that?
  switch (source) {
    case EditorCommandSource::kMenuOrKeyBinding:
      frame.GetEditor().ApplyParagraphStyleToSelection(style, input_type);
      return true;
    case EditorCommandSource::kDOM:
      frame.GetEditor().ApplyParagraphStyle(style, input_type);
      return true;
  }
  NOTREACHED();
}

bool ExpandSelectionToGranularity(LocalFrame& frame,
                                  TextGranularity granularity) {
  const SelectionInDOMTree& selection = ExpandWithGranularity(
      frame.Selection().ComputeVisibleSelectionInDOMTree().AsSelection(),
      granularity);
  const EphemeralRange& new_range = NormalizeRange(selection);
  if (new_range.IsNull())
    return false;
  if (new_range.IsCollapsed())
    return false;
  frame.Selection().SetSelection(
      SelectionInDOMTree::Builder().SetBaseAndExtent(new_range).Build(),
      SetSelectionOptions::Builder().SetShouldCloseTyping(true).Build());
  return true;
}

static bool HasChildTags(Element& element, const QualifiedName& tag_name) {
  return !element.getElementsByTagName(tag_name.LocalName())->IsEmpty();
}

static EditingTriState SelectionListState(LocalFrame& frame,
                                          const QualifiedName& tag_name) {
  if (frame.GetInputMethodController().GetActiveEditContext()) {
    return EditingTriState::kFalse;
  }

  const FrameSelection& selection = frame.Selection();
  if (selection.ComputeVisibleSelectionInDOMTreeDeprecated().IsCaret()) {
    if (EnclosingElementWithTag(
            selection.ComputeVisibleSelectionInDOMTreeDeprecated().Start(),
            tag_name))
      return EditingTriState::kTrue;
  } else if (selection.ComputeVisibleSelectionInDOMTreeDeprecated().IsRange()) {
    Element* start_element = EnclosingElementWithTag(
        selection.ComputeVisibleSelectionInDOMTreeDeprecated().Start(),
        tag_name);
    Element* end_element = EnclosingElementWithTag(
        selection.ComputeVisibleSelectionInDOMTreeDeprecated().End(), tag_name);

    if (start_element && end_element && start_element == end_element) {
      // If the selected list has the different type of list as child, return
      // |FalseTriState|.
      // See http://crbug.com/385374
      if (HasChildTags(*start_element, tag_name.Matches(html_names::kUlTag)
                                           ? html_names::kOlTag
                                           : html_names::kUlTag))
        return EditingTriState::kFalse;
      return EditingTriState::kTrue;
    }
  }

  return EditingTriState::kFalse;
}

static EphemeralRange UnionEphemeralRanges(const EphemeralRange& range1,
                                           const EphemeralRange& range2) {
  const Position start_position =
      range1.StartPosition().CompareTo(range2.StartPosition()) <= 0
          ? range1.StartPosition()
          : range2.StartPosition();
  const Position end_position =
      range1.EndPosition().CompareTo(range2.EndPosition()) <= 0
          ? range1.EndPosition()
          : range2.EndPosition();
  return EphemeralRange(start_position, end_position);
}

// Execute command functions

static bool CanSmartCopyOrDelete(LocalFrame& frame) {
  return frame.GetEditor().SmartInsertDeleteEnabled() &&
         frame.Selection().Granularity() == TextGranularity::kWord;
}

static bool ExecuteCreateLink(LocalFrame& frame,
                              Event*,
                              EditorCommandSource,
                              const String& value) {
  if (value.empty())
    return false;
  DCHECK(frame.GetDocument());
  return MakeGarbageCollected<CreateLinkCommand>(*frame.GetDocument(), value)
      ->Apply();
}

static bool ExecuteDefaultParagraphSeparator(LocalFrame& frame,
                                             Event*,
                                             EditorCommandSource,
                                             const String& value) {
  if (EqualIgnoringASCIICase(value, "div")) {
    frame.GetEditor().SetDefaultParagraphSeparator(
        EditorParagraphSeparator::kIsDiv);
    return true;
  }
  if (EqualIgnoringASCIICase(value, "p")) {
    frame.GetEditor().SetDefaultParagraphSeparator(
        EditorParagraphSeparator::kIsP);
  }
  return true;
}

static void PerformDelete(LocalFrame& frame) {
  if (!frame.GetEditor().CanDelete())
    return;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  // |SelectedRange| requires clean layout for visible selection normalization.
  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  frame.GetEditor().AddToKillRing(frame.GetEditor().SelectedRange());
  // TODO(editing-dev): |Editor::performDelete()| has no direction.
  // https://github.com/w3c/editing/issues/130
  frame.GetEditor().DeleteSelectionWithSmartDelete(
      CanSmartCopyOrDelete(frame) ? DeleteMode::kSmart : DeleteMode::kSimple,
      InputEvent::InputType::kDeleteContentBackward);

  // clear the "start new kill ring sequence" setting, because it was set to
  // true when the selection was updated by deleting the range
  frame.GetEditor().SetStartNewKillRingSequence(false);
}

static bool ExecuteDelete(LocalFrame& frame,
                          Event*,
                          EditorCommandSource source,
                          const String&) {
  switch (source) {
    case EditorCommandSource::kMenuOrKeyBinding: {
      // Doesn't modify the text if the current selection isn't a range.
      PerformDelete(frame);
      return true;
    }
    case EditorCommandSource::kDOM:
      // If the current selection is a caret, delete the preceding character. IE
      // performs forwardDelete, but we currently side with Firefox. Doesn't
      // scroll to make the selection visible, or modify the kill ring (this
      // time, siding with IE, not Firefox).
      DCHECK(frame.GetDocument());
      TypingCommand::DeleteKeyPressed(
          *frame.GetDocument(),
          frame.Selection().Granularity() == TextGranularity::kWord
              ? TypingCommand::kSmartDelete
              : 0);
      return true;
  }
  NOTREACHED();
}

static bool DeleteWithDirection(LocalFrame& frame,
                                DeleteDirection direction,
                                TextGranularity granularity,
                                bool kill_ring,
                                bool is_typing_action) {
  Editor& editor = frame.GetEditor();
  if (!editor.CanEdit())
    return false;

  if (frame.Selection()
          .ComputeVisibleSelectionInDOMTreeDeprecated()
          .IsRange() &&
      !is_typing_action) {
    if (kill_ring) {
      editor.AddToKillRing(editor.SelectedRange());
    }
    editor.DeleteSelectionWithSmartDelete(
        CanSmartCopyOrDelete(frame) ? DeleteMode::kSmart : DeleteMode::kSimple,
        DeletionInputTypeFromTextGranularity(direction, granularity));
    // Implicitly calls revealSelectionAfterEditingOperation().
  } else {
    EditingState editing_state;
    TypingCommand::Options options = 0;
    if (CanSmartCopyOrDelete(frame))
      options |= TypingCommand::kSmartDelete;
    if (kill_ring)
      options |= TypingCommand::kKillRing;
    DCHECK(frame.GetDocument());
    switch (direction) {
      case DeleteDirection::kForward:
        TypingCommand::ForwardDeleteKeyPressed(
            *frame.GetDocument(), &editing_state, options, granularity);
        if (editing_state.IsAborted())
          return false;
        break;
      case DeleteDirection::kBackward:
        TypingCommand::DeleteKeyPressed(*frame.GetDocument(), options,
                                        granularity);
        break;
    }
    editor.RevealSelectionAfterEditingOperation();
  }

  // FIXME: We should to move this down into deleteKeyPressed.
  // clear the "start new kill ring sequence" setting, because it was set to
  // true when the selection was updated by deleting the range
  if (kill_ring)
    editor.SetStartNewKillRingSequence(false);

  return true;
}

static bool ExecuteDeleteBackward(LocalFrame& frame,
                                  Event*,
                                  EditorCommandSource,
                                  const String&) {
  DeleteWithDirection(frame, DeleteDirection::kBackward,
                      TextGranularity::kCharacter, false, true);
  return true;
}

static bool ExecuteDeleteBackwardByDecomposingPreviousCharacter(
    LocalFrame& frame,
    Event*,
    EditorCommandSource,
    const String&) {
  DLOG(ERROR) << "DeleteBackwardByDecomposingPreviousCharacter is not "
                 "implemented, doing DeleteBackward instead";
  DeleteWithDirection(frame, DeleteDirection::kBackward,
                      TextGranularity::kCharacter, false, true);
  return true;
}

static bool ExecuteDeleteForward(LocalFrame& frame,
                                 Event*,
                                 EditorCommandSource,
                                 const String&) {
  DeleteWithDirection(frame, DeleteDirection::kForward,
                      TextGranularity::kCharacter, false, true);
  return true;
}

static bool ExecuteDeleteToBeginningOfLine(LocalFrame& frame,
                                           Event*,
                                           EditorCommandSource,
                                           const String&) {
#if BUILDFLAG(IS_ANDROID)
  RecordKeyboardShortcutForAndroid(KeyboardShortcut::kDeleteLine);
#endif  // BUILDFLAG(IS_ANDROID)

  DeleteWithDirection(frame, DeleteDirection::kBackward,
                      TextGranularity::kLineBoundary, true, false);
  return true;
}

static bool ExecuteDeleteToBeginningOfParagraph(LocalFrame& frame,
                                                Event*,
                                                EditorCommandSource,
                                                const String&) {
  DeleteWithDirection(frame, DeleteDirection::kBackward,
                      TextGranularity::kParagraphBoundary, true, false);
  return true;
}

static bool ExecuteDeleteToEndOfLine(LocalFrame& frame,
                                     Event*,
                                     EditorCommandSource,
                                     const String&) {
  // Despite its name, this command should delete the newline at the end of a
  // paragraph if you are at the end of a paragraph (like
  // DeleteToEndOfParagraph).
  DeleteWithDirection(frame, DeleteDirection::kForward,
                      TextGranularity::kLineBoundary, true, false);
  return true;
}

static bool ExecuteDeleteToEndOfParagraph(LocalFrame& frame,
                                          Event*,
                                          EditorCommandSource,
                                          const String&) {
  // Despite its name, this command should delete the newline at the end of
  // a paragraph if you are at the end of a paragraph.
  DeleteWithDirection(frame, DeleteDirection::kForward,
                      TextGranularity::kParagraphBoundary, true, false);
  return true;
}

static bool ExecuteDeleteToMark(LocalFrame& frame,
                                Event*,
                                EditorCommandSource,
                                const String&) {
  const EphemeralRange mark =
      frame.GetEditor().Mark().ToNormalizedEphemeralRange();
  if (mark.IsNotNull()) {
    frame.Selection().SetSelection(
        SelectionInDOMTree::Builder()
            .SetBaseAndExtent(
                UnionEphemeralRanges(mark, frame.GetEditor().SelectedRange()))
            .Build(),
        SetSelectionOptions::Builder().SetShouldCloseTyping(true).Build());
  }
  PerformDelete(frame);

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  frame.GetEditor().SetMark();
  return true;
}

static bool ExecuteDeleteWordBackward(LocalFrame& frame,
                                      Event*,
                                      EditorCommandSource,
                                      const String&) {
  DeleteWithDirection(frame, DeleteDirection::kBackward, TextGranularity::kWord,
                      true, false);
  return true;
}

static bool ExecuteDeleteWordForward(LocalFrame& frame,
                                     Event*,
                                     EditorCommandSource,
                                     const String&) {
  DeleteWithDirection(frame, DeleteDirection::kForward, TextGranularity::kWord,
                      true, false);
  return true;
}

static bool ExecuteFindString(LocalFrame& frame,
                              Event*,
                              EditorCommandSource,
                              const String& value) {
  return Editor::FindString(
      frame, value,
      FindOptions().SetCaseInsensitive(true).SetWrappingAround(true));
}

static bool ExecuteFormatBlock(LocalFrame& frame,
                               Event*,
                               EditorCommandSource,
                               const String& value) {
  String tag_name = value.DeprecatedLower();
  if (tag_name[0] == '<' && tag_name[tag_name.length() - 1] == '>')
    tag_name = tag_name.Substring(1, tag_name.length() - 2);

  AtomicString local_name, prefix;
  if (!Document::ParseQualifiedName(AtomicString(tag_name), prefix, local_name,
                                    IGNORE_EXCEPTION_FOR_TESTING))
    return false;
  QualifiedName qualified_tag_name(prefix, local_name,
                                   html_names::xhtmlNamespaceURI);

  DCHECK(frame.GetDocument());
  auto* command = MakeGarbageCollected<FormatBlockCommand>(*frame.GetDocument(),
                                                           qualified_tag_name);
  command->Apply();
  return command->DidApply();
}

static bool ExecuteForwardDelete(LocalFrame& frame,
                                 Event*,
                                 EditorCommandSource source,
                                 const String&) {
  EditingState editing_state;
  switch (source) {
    case EditorCommandSource::kMenuOrKeyBinding:
      DeleteWithDirection(frame, DeleteDirection::kForward,
                          TextGranularity::kCharacter, false, true);
      return true;
    case EditorCommandSource::kDOM:
      // Doesn't scroll to make the selection visible, or modify the kill ring.
      // ForwardDelete is not implemented in IE or Firefox, so this behavior is
      // only needed for backward compatibility with ourselves, and for
      // consistency with Delete.
      DCHECK(frame.GetDocument());
      TypingCommand::ForwardDeleteKeyPressed(*frame.GetDocument(),
                                             &editing_state);
      if (editing_state.IsAborted())
        return false;
      return true;
  }
  NOTREACHED();
}

static bool ExecuteIgnoreSpelling(LocalFrame& frame,
                                  Event*,
                                  EditorCommandSource,
                                  const String&) {
  frame.GetSpellChecker().IgnoreSpelling();
  return true;
}

static bool ExecuteIndent(LocalFrame& frame,
                          Event*,
                          EditorCommandSource,
                          const String&) {
  DCHECK(frame.GetDocument());
  return MakeGarbageCollected<IndentOutdentCommand>(
             *frame.GetDocument(), IndentOutdentCommand::kIndent)
      ->Apply();
}

static bool ExecuteJustifyCenter(LocalFrame& frame,
                                 Event*,
                                 EditorCommandSource source,
                                 const String&) {
  return ExecuteApplyParagraphStyle(frame, source,
                                    InputEvent::InputType::kFormatJustifyCenter,
                                    CSSPropertyID::kTextAlign, "center");
}

static bool ExecuteJustifyFull(LocalFrame& frame,
                               Event*,
                               EditorCommandSource source,
                               const String&) {
  return ExecuteApplyParagraphStyle(frame, source,
                                    InputEvent::InputType::kFormatJustifyFull,
                                    CSSPropertyID::kTextAlign, "justify");
}

static bool ExecuteJustifyLeft(LocalFrame& frame,
                               Event*,
                               EditorCommandSource source,
                               const String&) {
  return ExecuteApplyParagraphStyle(frame, source,
                                    InputEvent::InputType::kFormatJustifyLeft,
                                    CSSPropertyID::kTextAlign, "left");
}

static bool ExecuteJustifyRight(LocalFrame& frame,
                                Event*,
                                EditorCommandSource source,
                                const String&) {
  return ExecuteApplyParagraphStyle(frame, source,
                                    InputEvent::InputType::kFormatJustifyRight,
                                    CSSPropertyID::kTextAlign, "right");
}

static bool ExecuteOutdent(LocalFrame& frame,
                           Event*,
                           EditorCommandSource,
                           const String&) {
  DCHECK(frame.GetDocument());
  return MakeGarbageCollected<IndentOutdentCommand>(
             *frame.GetDocument(), IndentOutdentCommand::kOutdent)
      ->Apply();
}

static bool ExecuteToggleOverwrite(LocalFrame& frame,
                                   Event*,
                                   EditorCommandSource,
                                   const String&) {
  // Overwrite mode is not supported. See https://crbug.com/1030231.
  // We return false to match the expectation of the ExecCommand.
  return false;
}

static bool ExecutePrint(LocalFrame& frame,
                         Event*,
                         EditorCommandSource,
                         const String&) {
  Page* page = frame.GetPage();
  if (!page)
    return false;
  return page->GetChromeClient().Print(&frame);
}

static bool ExecuteRedo(LocalFrame& frame,
                        Event*,
                        EditorCommandSource,
                        const String&) {
  frame.GetEditor().Redo();
  return true;
}

static bool ExecuteRemoveFormat(LocalFrame& frame,
                                Event*,
                                EditorCommandSource,
                                const String&) {
  DCHECK(frame.GetDocument());
  MakeGarbageCollected<RemoveFormatCommand>(*frame.GetDocument())->Apply();

  return true;
}

static bool ExecuteScrollPageBackward(LocalFrame& frame,
                                      Event*,
                                      EditorCommandSource,
                                      const String&) {
  return frame.GetEventHandler().BubblingScroll(
      mojom::blink::ScrollDirection::kScrollBlockDirectionBackward,
      ui::ScrollGranularity::kScrollByPage);
}

static bool ExecuteScrollPageForward(LocalFrame& frame,
                                     Event*,
                                     EditorCommandSource,
                                     const String&) {
  return frame.GetEventHandler().BubblingScroll(
      mojom::blink::ScrollDirection::kScrollBlockDirectionForward,
      ui::ScrollGranularity::kScrollByPage);
}

static bool ExecuteScrollLineUp(LocalFrame& frame,
                                Event*,
                                EditorCommandSource,
                                const String&) {
  return frame.GetEventHandler().BubblingScroll(
      mojom::blink::ScrollDirection::kScrollU
"""


```