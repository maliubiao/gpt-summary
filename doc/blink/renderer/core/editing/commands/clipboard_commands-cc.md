Response:
Let's break down the thought process for analyzing this C++ file and generating the detailed response.

1. **Initial Scan and Identification of Key Areas:**

   The first step is to quickly read through the code, paying attention to the includes and the functions defined within the `blink` namespace. Keywords like "clipboard," "paste," "copy," "cut," "event," and "selection" immediately stand out. The included headers also give clues (e.g., `clipboard_utilities.h`, `data_transfer_access_policy.h`, `clipboard_event.h`).

2. **Understanding the Core Functionality:**

   The filename `clipboard_commands.cc` strongly suggests that this file implements actions related to clipboard operations. The functions like `ExecuteCopy`, `ExecuteCut`, `ExecutePaste`, `EnabledCopy`, `EnabledCut`, and `EnabledPaste` confirm this. The presence of `DispatchClipboardEvent` suggests an event mechanism is involved.

3. **Deconstructing Individual Functions:**

   Next, analyze each function individually:

   * **`CanReadClipboard`, `CanWriteClipboard`:** These clearly control whether clipboard access is permitted based on factors like user interaction, settings, and content security policies. This points to a security aspect.

   * **`IsExecutingCutOrCopy`, `IsExecutingPaste`:** These seem to track the current state of clipboard operations, likely to differentiate between user-initiated actions and programmatic ones.

   * **`CanSmartReplaceInClipboard`:** This suggests a feature where pasting can intelligently adjust spacing or formatting.

   * **`FindEventTargetForClipboardEvent`:**  This is crucial for understanding how clipboard events are dispatched in the DOM. It determines which element should receive the event. The logic involving selection and focus is important.

   * **`DispatchClipboardEvent`, `DispatchCopyOrCutEvent`, `DispatchPasteEvent`:** These functions are central to the event handling process for clipboard operations. They create `ClipboardEvent` objects and dispatch them to the appropriate targets. The interaction with `DataTransfer` is key here.

   * **`EnabledCopy`, `EnabledCut`, `EnabledPaste`:** These determine if the corresponding clipboard actions are available, often by checking permissions and dispatching "before" events.

   * **`WriteSelectionToClipboard`:**  This focuses on packaging the selected content (HTML and plain text) for writing to the system clipboard.

   * **`PasteSupported`:** A simple check for general paste capability.

   * **`ExecuteCopy`, `ExecuteCut`, `ExecutePaste`, `ExecutePasteGlobalSelection`, `ExecutePasteAndMatchStyle`, `ExecutePasteFromImageURL`:** These are the core command execution functions, handling the logic for each clipboard operation. They often involve dispatching events, checking permissions, interacting with the system clipboard, and manipulating the DOM. The differences between the `Paste` variations are significant.

   * **`PasteAsFragment`, `PasteAsPlainTextFromClipboard`:** These helper functions are used by the main `Paste` logic.

   * **`GetFragmentFromClipboard`:**  This function retrieves and parses data from the system clipboard, handling both HTML and plain text. The logic for image pasting is also present.

   * **`PasteFromClipboard`:**  A high-level paste function that decides whether to paste as HTML or plain text.

   * **`PasteImageResourceObserver`:** This class is important for understanding how pasting images from URLs works asynchronously. It handles the image loading and the subsequent paste operation.

   * **`PasteFromImageURL`:** This initiates the process of pasting an image from a URL, fetching the image and using the observer.

4. **Identifying Relationships with Web Technologies:**

   As each function is analyzed, consider its direct relevance to JavaScript, HTML, and CSS:

   * **JavaScript:**  The dispatching of `ClipboardEvent`s (`copy`, `cut`, `paste`, `beforecopy`, `beforecut`, `beforepaste`) directly relates to the JavaScript Clipboard API. The checks for JavaScript clipboard access settings are also relevant.
   * **HTML:** The interaction with `Element` objects, the handling of selections within the DOM, and the creation of `DocumentFragment`s for pasting are all related to HTML structure. The pasting of HTML content itself is a core function.
   * **CSS:** While not directly manipulating CSS, the `UpdateStyleAndLayout` calls indicate that the visual presentation might influence clipboard operations (e.g., ensuring layout is up-to-date before getting selection information). The `PasteAndMatchStyle` command explicitly addresses CSS-related aspects.

5. **Inferring Logical Reasoning and Input/Output:**

   For functions involving decisions or transformations, think about potential inputs and outputs:

   * **`CanReadClipboard`:** Input: `LocalFrame`, `EditorCommandSource`. Output: `true` or `false` (boolean indicating access). The reasoning involves checking settings and content security policies.
   * **`FindEventTargetForClipboardEvent`:** Input: `LocalFrame`, `EditorCommandSource`. Output: A pointer to an `Element`. The reasoning involves checking for selections, focus, and editability.
   * **`GetFragmentFromClipboard`:** Input: `LocalFrame`. Output: A `std::pair` containing a `DocumentFragment*` and a `bool`. The reasoning involves trying to read HTML, then images, then falling back to plain text.

6. **Considering User and Programming Errors:**

   Think about how developers or users might misuse these features:

   * **Security Errors:**  Attempting to access the clipboard without proper permissions. The code explicitly checks for these conditions.
   * **Logical Errors:**  Assuming clipboard operations will always succeed. For example, trying to cut when nothing is selected or when the selection is in a non-editable area.
   * **Event Handling Issues:**  Preventing default behavior of clipboard events in JavaScript and causing unexpected results.

7. **Tracing User Actions:**

   Work backward from the code to common user actions:

   * **Copy/Cut:** User selects text/content, then uses the context menu (right-click -> Copy/Cut), keyboard shortcuts (Ctrl+C/Ctrl+X), or JavaScript `document.execCommand('copy')`/`document.execCommand('cut')`.
   * **Paste:** User uses the context menu (right-click -> Paste), keyboard shortcuts (Ctrl+V), or JavaScript `document.execCommand('paste')`. Drag-and-drop could also trigger similar mechanisms.
   * **Pasting Images:** Copying an image from a website and pasting it, or using a "Paste from Image URL" feature.

8. **Structuring the Output:**

   Organize the findings into logical categories (Functionality, Relationship with Web Technologies, Logic and Input/Output, Usage Errors, Debugging). Use clear and concise language, providing examples where appropriate. Use headings and bullet points to improve readability.

9. **Refinement and Review:**

   Finally, reread the generated response to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that could be explained better. For instance, adding more detail about the `DataTransfer` object and its role would be beneficial.

By following these steps, you can systematically analyze a complex source code file and generate a comprehensive and informative explanation. The key is to break down the problem into smaller, manageable parts and to connect the code back to its real-world usage and the underlying web technologies.
This C++ source code file, `clipboard_commands.cc`, located within the Chromium Blink engine, is responsible for implementing the **core logic behind clipboard operations (copy, cut, paste)** within a web page. It handles how the browser interacts with the system clipboard based on user actions and JavaScript requests.

Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Command Execution:** It defines the actual execution logic for the `copy`, `cut`, and `paste` commands. This involves:
   - **Checking Permissions:** Determining if the current context (e.g., focused frame, user activation) allows reading from or writing to the clipboard.
   - **Dispatching Clipboard Events:** Sending `beforecopy`, `beforecut`, `copy`, `cut`, and `paste` events to the DOM (Document Object Model) to allow JavaScript to intercept and potentially modify the clipboard behavior.
   - **Interacting with the System Clipboard:**  Reading data from and writing data to the operating system's clipboard using the `SystemClipboard` interface.
   - **Manipulating the DOM:**  Deleting selected content during a "cut" operation and inserting pasted content into the document.
   - **Handling Different Paste Modes:** Supporting pasting as plain text or with rich formatting (HTML).
   - **Handling Image Pasting:** Specifically managing the pasting of images from URLs and image data.
   - **Smart Replace:** Implementing logic for "smart paste," which can adjust spacing and formatting during paste operations.

2. **Enabling/Disabling Commands:** It provides functions (`EnabledCopy`, `EnabledCut`, `EnabledPaste`) to determine if the clipboard commands are currently enabled, taking into account permissions, focus, and the results of "before" events.

3. **Event Target Determination:**  It figures out which DOM element should be the target of clipboard events. This is important for JavaScript event listeners to work correctly.

4. **Data Transfer Management:**  It uses the `DataTransfer` object to represent the data being copied or pasted, allowing for multiple data types and custom data.

5. **Security Considerations:**  It incorporates checks to prevent malicious scripts from abusing clipboard access.

**Relationship with JavaScript, HTML, and CSS:**

This C++ code is the **underlying engine** that makes the JavaScript Clipboard API work. When JavaScript code interacts with the clipboard, it ultimately calls into this C++ code.

* **JavaScript:**
    * **`document.execCommand('copy')`, `document.execCommand('cut')`, `document.execCommand('paste')`:** These JavaScript commands directly trigger the corresponding functions in `clipboard_commands.cc`.
    * **Clipboard Events (`copy`, `cut`, `paste`, `beforecopy`, `beforecut`, `beforepaste`):** This C++ code is responsible for dispatching these events, allowing JavaScript to:
        * **Prevent Default Behavior:**  `event.preventDefault()` in a clipboard event handler can stop the browser's default copy/cut/paste behavior.
        * **Access Clipboard Data:**  JavaScript can use the `ClipboardEvent`'s `clipboardData` property (backed by the `DataTransfer` object) to read or modify the data being copied/pasted.

    **Example:**
    ```javascript
    document.addEventListener('copy', function(e) {
      e.preventDefault(); // Prevent the default copy action
      e.clipboardData.setData('text/plain', 'This is custom copied text.');
    });
    ```
    When this JavaScript code runs and the user attempts to copy, `clipboard_commands.cc` will dispatch the 'copy' event. This JavaScript handler intercepts it, prevents the default behavior, and sets custom text data on the clipboard.

* **HTML:**
    * **User Selection:** The `FrameSelection` object (handled in other parts of Blink) determines which HTML content is being copied or cut. `clipboard_commands.cc` then uses this selection to extract the HTML and plain text representations.
    * **Pasting into Editable Elements:**  When pasting, this code interacts with the DOM to insert the content into elements that are marked as editable (e.g., `<textarea>`, elements with `contenteditable="true"`).

    **Example:** If a user selects text within a `<p>` tag and presses Ctrl+C, `clipboard_commands.cc` will be involved in extracting the HTML of that `<p>` tag and its content.

* **CSS:**
    * **`Paste and Match Style`:**  The `ExecutePasteAndMatchStyle` function aims to paste content while attempting to match the styling of the surrounding text at the insertion point. This implicitly interacts with CSS by considering the computed styles.
    * **Hidden Selections:** The code considers whether a selection is "hidden" (not visually apparent) when determining the event target. CSS can be used to hide selections.

**Logical Reasoning and Input/Output Examples:**

Let's consider the `ExecuteCopy` function:

* **Hypothetical Input:**
    * User selects the text "Hello" in a `<div>` element.
    * User presses Ctrl+C (or right-clicks and selects "Copy").
    * JavaScript 'copy' event listeners might or might not be present.

* **Logical Steps:**
    1. `ExecuteCopy` is called with `source` as `kMenuOrKeyBinding`.
    2. `DispatchCopyOrCutEvent` sends a 'beforecopy' event. If a JavaScript handler calls `preventDefault()`, the copy operation might be cancelled here.
    3. If not cancelled, `CanCopy()` is checked (internally checks if there's a valid selection).
    4. `UpdateStyleAndLayout` is called to ensure the DOM is up-to-date.
    5. The selected HTML (`<div>Hello</div>`) and plain text ("Hello") are extracted.
    6. `WriteSelectionToClipboard` writes this data to the system clipboard.
    7. A 'copy' event is dispatched to JavaScript.

* **Hypothetical Output (if no JavaScript prevents default):**
    * The text "Hello" is now available on the system clipboard.

**User and Programming Common Usage Errors:**

1. **Security Errors (User/Programmer):**
   * **JavaScript trying to access clipboard without user gesture:** Browsers generally restrict clipboard access from JavaScript unless initiated by a user action (like a button click). Trying to programmatically copy/paste without user interaction will likely be blocked due to security concerns. This C++ code enforces those restrictions.
   * **Websites trying to write arbitrary data to the clipboard without explicit user intent:**  Browsers also limit write access to the clipboard to prevent malicious websites from silently modifying the clipboard content.

2. **Logical Errors (Programmer):**
   * **Assuming `document.execCommand('copy')` will always work:** If there is no selection, or if the content is in a non-selectable area, `copy` might fail. Developers should check for a valid selection before attempting to copy.
   * **Not handling `preventDefault()` in clipboard event listeners:**  If a developer's JavaScript code calls `event.preventDefault()` in a `beforecopy` event, they need to ensure they handle the copy operation themselves (e.g., by using `clipboardData`). If they don't, the copy operation might silently fail.

3. **Incorrect Event Handling (Programmer):**
   * **Attaching clipboard event listeners to the wrong element:**  Clipboard events typically bubble up the DOM. Attaching the listener to the `document` or the specific editable element is usually correct.

**User Operation Steps as Debugging Clues:**

To understand how a user action reaches this code, consider a "copy" operation:

1. **User Selects Text:** The user uses their mouse or keyboard to select some text on the webpage. This selection information is managed by Blink's selection infrastructure.
2. **User Initiates Copy:**
   * **Keyboard Shortcut (Ctrl+C/Cmd+C):** The operating system intercepts the key combination and informs the browser.
   * **Context Menu (Right-Click -> Copy):** The browser's UI handles the right-click event and triggers the "Copy" command.
   * **JavaScript `document.execCommand('copy')`:** A script on the page explicitly calls this function.
3. **Browser Command Handling:** The browser's main process identifies the "Copy" command.
4. **Blink Command Routing:** The command is routed to the appropriate Blink component responsible for editing and clipboard operations.
5. **`ClipboardCommands::ExecuteCopy` is Called:** Based on the command, the `ExecuteCopy` function in this `clipboard_commands.cc` file is invoked.
6. **Event Dispatch and Clipboard Interaction:** As described in the "Logical Steps" above, the code dispatches events, interacts with the system clipboard, and potentially modifies the DOM.

**Debugging Clues:**

* **Breakpoints:** Setting breakpoints within functions like `ExecuteCopy`, `DispatchClipboardEvent`, and `WriteSelectionToClipboard` can help track the flow of execution.
* **Logging:** Adding `DLOG` or `VLOG` statements to log the state of variables (e.g., permissions, event targets, clipboard data) can provide insights.
* **Event Listener Inspection:** Using browser developer tools to inspect the event listeners attached to DOM elements can reveal if JavaScript is interfering with the default clipboard behavior.
* **Clipboard Content Inspection:** Tools that allow viewing the system clipboard content can help verify if the expected data is being written.

In summary, `clipboard_commands.cc` is a crucial component of the Blink rendering engine, acting as the bridge between user actions, JavaScript requests, and the operating system's clipboard. It ensures that copy, cut, and paste operations are handled correctly, securely, and in accordance with web standards.

Prompt: 
```
这是目录为blink/renderer/core/editing/commands/clipboard_commands.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

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

// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/commands/clipboard_commands.h"

#include "third_party/blink/public/platform/web_content_settings_client.h"
#include "third_party/blink/renderer/core/clipboard/clipboard_utilities.h"
#include "third_party/blink/renderer/core/clipboard/data_transfer_access_policy.h"
#include "third_party/blink/renderer/core/clipboard/paste_mode.h"
#include "third_party/blink/renderer/core/clipboard/system_clipboard.h"
#include "third_party/blink/renderer/core/editing/commands/editing_commands_utilities.h"
#include "third_party/blink/renderer/core/editing/editing_behavior.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/events/clipboard_event.h"
#include "third_party/blink/renderer/core/events/text_event.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource_content.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource_observer.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_parameters.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"

namespace blink {

namespace {

// This class holds some state relevant to current clipboard event dispatch. It
// helps `ClipboardCommands` to know whether a given `ExecutionContext` is
// currently handling a copy/paste command.
class ExecutionContextClipboardEventState
    : public GarbageCollected<ExecutionContextClipboardEventState>,
      public Supplement<ExecutionContext> {
 public:
  static constexpr char kSupplementName[] =
      "ExecutionContextClipboardEventState";

  static ExecutionContextClipboardEventState& From(
      ExecutionContext& execution_context) {
    {
      ExecutionContextClipboardEventState* supplement =
          Supplement<ExecutionContext>::From<
              ExecutionContextClipboardEventState>(execution_context);
      if (!supplement) {
        supplement = MakeGarbageCollected<ExecutionContextClipboardEventState>(
            execution_context);
        ProvideTo(execution_context, supplement);
      }
      return *supplement;
    }
  }

  ExecutionContextClipboardEventState(ExecutionContext& execution_context)
      : Supplement<ExecutionContext>(execution_context) {}
  virtual ~ExecutionContextClipboardEventState() = default;

  struct State {
    const AtomicString* event_type = nullptr;
    std::optional<EditorCommandSource> source;
  };

  base::AutoReset<State> SetState(const AtomicString& event_type,
                                  EditorCommandSource source) {
    State new_state;
    new_state.event_type = &event_type;
    new_state.source = source;
    return base::AutoReset<State>(&state_, new_state);
  }

  const State& GetState() const { return state_; }

 private:
  State state_;
};

}  // namespace

bool ClipboardCommands::CanReadClipboard(LocalFrame& frame,
                                         EditorCommandSource source) {
  if (source == EditorCommandSource::kMenuOrKeyBinding)
    return true;
  Settings* const settings = frame.GetSettings();
  if (settings && settings->GetJavaScriptCanAccessClipboard() &&
      settings->GetDOMPasteAllowed()) {
    return true;
  }
  return frame.GetContentSettingsClient() &&
         frame.GetContentSettingsClient()->AllowReadFromClipboard();
}

bool ClipboardCommands::CanWriteClipboard(LocalFrame& frame,
                                          EditorCommandSource source) {
  if (source == EditorCommandSource::kMenuOrKeyBinding)
    return true;
  Settings* const settings = frame.GetSettings();
  if ((settings && settings->GetJavaScriptCanAccessClipboard()) ||
      LocalFrame::HasTransientUserActivation(&frame)) {
    return true;
  }
  return frame.GetContentSettingsClient() &&
         frame.GetContentSettingsClient()->AllowWriteToClipboard();
}

bool ClipboardCommands::IsExecutingCutOrCopy(ExecutionContext& context) {
  const ExecutionContextClipboardEventState::State& event_state =
      ExecutionContextClipboardEventState::From(context).GetState();
  return (event_state.event_type == &event_type_names::kCopy ||
          event_state.event_type == &event_type_names::kCut) &&
         event_state.source == EditorCommandSource::kMenuOrKeyBinding;
}

bool ClipboardCommands::IsExecutingPaste(ExecutionContext& context) {
  const ExecutionContextClipboardEventState::State& event_state =
      ExecutionContextClipboardEventState::From(context).GetState();
  return event_state.event_type == &event_type_names::kPaste &&
         event_state.source == EditorCommandSource::kMenuOrKeyBinding;
}

bool ClipboardCommands::CanSmartReplaceInClipboard(LocalFrame& frame) {
  return frame.GetEditor().SmartInsertDeleteEnabled() &&
         frame.GetSystemClipboard()->IsFormatAvailable(
             blink::mojom::ClipboardFormat::kSmartPaste);
}

Element* ClipboardCommands::FindEventTargetForClipboardEvent(
    LocalFrame& frame,
    EditorCommandSource source) {
  // https://www.w3.org/TR/clipboard-apis/#fire-a-clipboard-event says:
  //  "Set target to be the element that contains the start of the selection in
  //   document order, or the body element if there is no selection or cursor."
  // We treat hidden selections as "no selection or cursor".
  //  "if the context is not editable, then set target to the focused node,
  //   or the body element if no node has focus."
  if (source == EditorCommandSource::kMenuOrKeyBinding &&
      frame.Selection().IsHidden()) {
    if (RuntimeEnabledFeatures::
            ClipboardEventTargetCanBeFocusedElementEnabled()) {
      Element* focusedElement = frame.GetDocument()->FocusedElement();
      if (focusedElement && !IsEditable(*focusedElement)) {
        return focusedElement;
      }
    }
    return frame.Selection().GetDocument().body();
  }

  return FindEventTargetFrom(
      frame, frame.Selection().ComputeVisibleSelectionInDOMTree());
}

// Returns true if Editor should continue with default processing.
bool ClipboardCommands::DispatchClipboardEvent(LocalFrame& frame,
                                               const AtomicString& event_type,
                                               DataTransferAccessPolicy policy,
                                               EditorCommandSource source,
                                               PasteMode paste_mode) {
  Element* const target = FindEventTargetForClipboardEvent(frame, source);
  if (!target)
    return true;

  SystemClipboard* system_clipboard = frame.GetSystemClipboard();
  DataTransfer* const data_transfer = DataTransfer::Create(
      DataTransfer::kCopyAndPaste, policy,
      policy == DataTransferAccessPolicy::kWritable
          ? DataObject::Create()
          : DataObject::CreateFromClipboard(target->GetExecutionContext(),
                                            system_clipboard, paste_mode));

  bool no_default_processing = false;
  {
    base::AutoReset<ExecutionContextClipboardEventState::State> reset =
        ExecutionContextClipboardEventState::From(
            *target->GetExecutionContext())
            .SetState(event_type, source);
    Event* const evt = ClipboardEvent::Create(event_type, data_transfer);
    target->DispatchEvent(*evt);
    no_default_processing = evt->defaultPrevented();
  }
  if (no_default_processing && policy == DataTransferAccessPolicy::kWritable) {
    frame.GetSystemClipboard()->WriteDataObject(data_transfer->GetDataObject());
    frame.GetSystemClipboard()->CommitWrite();
  }

  // Invalidate clipboard here for security.
  data_transfer->SetAccessPolicy(DataTransferAccessPolicy::kNumb);
  return !no_default_processing;
}

bool ClipboardCommands::DispatchCopyOrCutEvent(LocalFrame& frame,
                                               EditorCommandSource source,
                                               const AtomicString& event_type) {
  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  if (IsInPasswordField(
          frame.Selection().ComputeVisibleSelectionInDOMTree().Start()))
    return true;

  return DispatchClipboardEvent(frame, event_type,
                                DataTransferAccessPolicy::kWritable, source,
                                PasteMode::kAllMimeTypes);
}

bool ClipboardCommands::DispatchPasteEvent(LocalFrame& frame,
                                           PasteMode paste_mode,
                                           EditorCommandSource source) {
  return DispatchClipboardEvent(frame, event_type_names::kPaste,
                                DataTransferAccessPolicy::kReadable, source,
                                paste_mode);
}

// WinIE uses onbeforecut and onbeforepaste to enables the cut and paste menu
// items. They also send onbeforecopy, apparently for symmetry, but it doesn't
// affect the menu items. We need to use onbeforecopy as a real menu enabler
// because we allow elements that are not normally selectable to implement
// copy/paste (like divs, or a document body).

bool ClipboardCommands::EnabledCopy(LocalFrame& frame,
                                    Event*,
                                    EditorCommandSource source) {
  if (!CanWriteClipboard(frame, source))
    return false;
  return !DispatchCopyOrCutEvent(frame, source,
                                 event_type_names::kBeforecopy) ||
         frame.GetEditor().CanCopy();
}

bool ClipboardCommands::EnabledCut(LocalFrame& frame,
                                   Event*,
                                   EditorCommandSource source) {
  if (!CanWriteClipboard(frame, source))
    return false;
  if (source == EditorCommandSource::kMenuOrKeyBinding &&
      !frame.Selection().SelectionHasFocus())
    return false;
  return !DispatchCopyOrCutEvent(frame, source, event_type_names::kBeforecut) ||
         frame.GetEditor().CanCut();
}

bool ClipboardCommands::EnabledPaste(LocalFrame& frame,
                                     Event*,
                                     EditorCommandSource source) {
  if (!CanReadClipboard(frame, source))
    return false;
  if (source == EditorCommandSource::kMenuOrKeyBinding &&
      !frame.Selection().SelectionHasFocus())
    return false;
  return frame.GetEditor().CanPaste();
}

static SystemClipboard::SmartReplaceOption GetSmartReplaceOption(
    const LocalFrame& frame) {
  if (frame.GetEditor().SmartInsertDeleteEnabled() &&
      frame.Selection().Granularity() == TextGranularity::kWord)
    return SystemClipboard::kCanSmartReplace;
  return SystemClipboard::kCannotSmartReplace;
}

void ClipboardCommands::WriteSelectionToClipboard(LocalFrame& frame) {
  const KURL& url = frame.GetDocument()->Url();
  const String html = frame.Selection().SelectedHTMLForClipboard();
  String plain_text = frame.SelectedTextForClipboard();
  frame.GetSystemClipboard()->WriteHTML(html, url,
                                        GetSmartReplaceOption(frame));
  ReplaceNBSPWithSpace(plain_text);
  frame.GetSystemClipboard()->WritePlainText(plain_text,
                                             GetSmartReplaceOption(frame));
  frame.GetSystemClipboard()->CommitWrite();
}

bool ClipboardCommands::PasteSupported(LocalFrame* frame) {
  const Settings* const settings = frame->GetSettings();
  if (settings && settings->GetJavaScriptCanAccessClipboard() &&
      settings->GetDOMPasteAllowed()) {
    return true;
  }
  return frame->GetContentSettingsClient() &&
         frame->GetContentSettingsClient()->AllowReadFromClipboard();
}

bool ClipboardCommands::ExecuteCopy(LocalFrame& frame,
                                    Event*,
                                    EditorCommandSource source,
                                    const String&) {
  if (!DispatchCopyOrCutEvent(frame, source, event_type_names::kCopy))
    return true;
  if (!frame.GetEditor().CanCopy())
    return true;

  Document* const document = frame.GetDocument();

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  // A 'copy' event handler might have dirtied the layout so we need to update
  // before we obtain the selection.
  document->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  if (HTMLImageElement* image_element =
          ImageElementFromImageDocument(document)) {
    // In an image document, normally there isn't anything to select, and we
    // only want to copy the image itself.
    if (frame.Selection().ComputeVisibleSelectionInDOMTree().IsNone()) {
      WriteImageNodeToClipboard(*frame.GetSystemClipboard(), *image_element,
                                document->title());
      return true;
    }

    // Scripts may insert other contents into an image document. Falls through
    // when they are selected.
  }

  // Since copy is a read-only operation it succeeds anytime a selection
  // is *visible*. In contrast to cut or paste, the selection does not
  // need to be focused - being visible is enough.
  if (source == EditorCommandSource::kMenuOrKeyBinding &&
      frame.Selection().IsHidden())
    return true;

  if (EnclosingTextControl(
          frame.Selection().ComputeVisibleSelectionInDOMTree().Start())) {
    frame.GetSystemClipboard()->WritePlainText(frame.SelectedTextForClipboard(),
                                               GetSmartReplaceOption(frame));
    frame.GetSystemClipboard()->CommitWrite();
    return true;
  }
  WriteSelectionToClipboard(frame);
  return true;
}

bool ClipboardCommands::CanDeleteRange(const EphemeralRange& range) {
  if (range.IsCollapsed())
    return false;

  const Node& start_container = *range.StartPosition().ComputeContainerNode();
  const Node& end_container = *range.EndPosition().ComputeContainerNode();

  return IsEditable(start_container) && IsEditable(end_container);
}

static DeleteMode ConvertSmartReplaceOptionToDeleteMode(
    SystemClipboard::SmartReplaceOption smart_replace_option) {
  if (smart_replace_option == SystemClipboard::kCanSmartReplace)
    return DeleteMode::kSmart;
  DCHECK_EQ(smart_replace_option, SystemClipboard::kCannotSmartReplace);
  return DeleteMode::kSimple;
}

bool ClipboardCommands::ExecuteCut(LocalFrame& frame,
                                   Event*,
                                   EditorCommandSource source,
                                   const String&) {
  // document.execCommand("cut") is a no-op in EditContext
  if (source == EditorCommandSource::kDOM &&
      frame.GetInputMethodController().GetActiveEditContext()) {
    return true;
  }

  if (!DispatchCopyOrCutEvent(frame, source, event_type_names::kCut))
    return true;
  if (!frame.GetEditor().CanCut())
    return true;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  // A 'cut' event handler might have dirtied the layout so we need to update
  // before we obtain the selection.
  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  if (source == EditorCommandSource::kMenuOrKeyBinding &&
      !frame.Selection().SelectionHasFocus())
    return true;

  if (!CanDeleteRange(frame.GetEditor().SelectedRange()))
    return true;
  if (EnclosingTextControl(
          frame.Selection().ComputeVisibleSelectionInDOMTree().Start())) {
    const String plain_text = frame.SelectedTextForClipboard();
    frame.GetSystemClipboard()->WritePlainText(plain_text,
                                               GetSmartReplaceOption(frame));
    frame.GetSystemClipboard()->CommitWrite();
  } else {
    WriteSelectionToClipboard(frame);
  }

  if (source == EditorCommandSource::kMenuOrKeyBinding) {
    if (DispatchBeforeInputDataTransfer(
            FindEventTargetForClipboardEvent(frame, source),
            InputEvent::InputType::kDeleteByCut,
            nullptr) != DispatchEventResult::kNotCanceled)
      return true;
    // 'beforeinput' event handler may destroy target frame.
    if (frame.GetDocument()->GetFrame() != frame)
      return true;

    // No DOM mutation if EditContext is active.
    if (frame.GetInputMethodController().GetActiveEditContext())
      return true;
  }

  frame.GetEditor().DeleteSelectionWithSmartDelete(
      ConvertSmartReplaceOptionToDeleteMode(GetSmartReplaceOption(frame)),
      InputEvent::InputType::kDeleteByCut);

  return true;
}

void ClipboardCommands::PasteAsFragment(LocalFrame& frame,
                                        DocumentFragment* pasting_fragment,
                                        bool smart_replace,
                                        bool match_style,
                                        EditorCommandSource source) {
  Element* const target = FindEventTargetForClipboardEvent(frame, source);
  if (!target)
    return;
  target->DispatchEvent(*TextEvent::CreateForFragmentPaste(
      frame.DomWindow(), pasting_fragment, smart_replace, match_style));
}

void ClipboardCommands::PasteAsPlainTextFromClipboard(
    LocalFrame& frame,
    EditorCommandSource source) {
  Element* const target = FindEventTargetForClipboardEvent(frame, source);
  if (!target)
    return;
  target->DispatchEvent(*TextEvent::CreateForPlainTextPaste(
      frame.DomWindow(), frame.GetSystemClipboard()->ReadPlainText(),
      CanSmartReplaceInClipboard(frame)));
}

ClipboardCommands::FragmentAndPlainText
ClipboardCommands::GetFragmentFromClipboard(LocalFrame& frame) {
  DocumentFragment* fragment = nullptr;
  if (frame.GetSystemClipboard()->IsFormatAvailable(
          blink::mojom::ClipboardFormat::kHtml)) {
    unsigned fragment_start = 0;
    unsigned fragment_end = 0;
    KURL url;
    const String markup =
        frame.GetSystemClipboard()->ReadHTML(url, fragment_start, fragment_end);
    fragment = CreateStrictlyProcessedFragmentFromMarkupWithContext(
        *frame.GetDocument(), markup, fragment_start, fragment_end, url);
  }
  if (fragment)
    return std::make_pair(fragment, false);

  if (const String markup = frame.GetSystemClipboard()->ReadImageAsImageMarkup(
          mojom::blink::ClipboardBuffer::kStandard)) {
    fragment = CreateFragmentFromMarkup(*frame.GetDocument(), markup,
                                        /* base_url */ "",
                                        kDisallowScriptingAndPluginContent);
    DCHECK(fragment);
    return std::make_pair(fragment, false);
  }

  const String text = frame.GetSystemClipboard()->ReadPlainText();
  if (text.empty())
    return std::make_pair(fragment, false);

  // TODO(editing-dev): Use of UpdateStyleAndLayout
  // needs to be audited. See http://crbug.com/590369 for more details.
  // |SelectedRange| requires clean layout for visible selection
  // normalization.
  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  fragment = CreateFragmentFromText(frame.GetEditor().SelectedRange(), text);
  return std::make_pair(fragment, true);
}

void ClipboardCommands::PasteFromClipboard(LocalFrame& frame,
                                           EditorCommandSource source) {
  const ClipboardCommands::FragmentAndPlainText fragment_and_plain_text =
      GetFragmentFromClipboard(frame);

  if (!fragment_and_plain_text.first)
    return;
  PasteAsFragment(frame, fragment_and_plain_text.first,
                  CanSmartReplaceInClipboard(frame),
                  fragment_and_plain_text.second, source);
}

void ClipboardCommands::Paste(LocalFrame& frame, EditorCommandSource source) {
  DCHECK(frame.GetDocument());

  // document.execCommand("paste") is a no-op in EditContext
  if (source == EditorCommandSource::kDOM &&
      frame.GetInputMethodController().GetActiveEditContext()) {
    return;
  }

  // The code below makes multiple calls to SystemClipboard methods which
  // implies multiple IPC calls to the ClipboardHost in the browaser process.
  // SystemClipboard snapshotting tells SystemClipboard to cache results from
  // the ClipboardHost so that at most one IPC is made for each type.
  ScopedSystemClipboardSnapshot snapshot(*frame.GetSystemClipboard());

  if (!DispatchPasteEvent(frame, PasteMode::kAllMimeTypes, source))
    return;
  if (!frame.GetEditor().CanPaste())
    return;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  // A 'paste' event handler might have dirtied the layout so we need to update
  // before we obtain the selection.
  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  if (source == EditorCommandSource::kMenuOrKeyBinding &&
      !frame.Selection().SelectionHasFocus())
    return;

  ResourceFetcher* const loader = frame.GetDocument()->Fetcher();
  ResourceCacheValidationSuppressor validation_suppressor(loader);

  const PasteMode paste_mode = frame.GetEditor().CanEditRichly()
                                   ? PasteMode::kAllMimeTypes
                                   : PasteMode::kPlainTextOnly;

  if (source == EditorCommandSource::kMenuOrKeyBinding) {
    Element* const target = FindEventTargetForClipboardEvent(frame, source);

    DataTransfer* data_transfer = DataTransfer::Create(
        DataTransfer::kCopyAndPaste, DataTransferAccessPolicy::kReadable,
        DataObject::CreateFromClipboard(
            target ? target->GetExecutionContext() : nullptr,
            frame.GetSystemClipboard(), paste_mode));

    if (DispatchBeforeInputDataTransfer(
            target, InputEvent::InputType::kInsertFromPaste, data_transfer) !=
        DispatchEventResult::kNotCanceled) {
      return;
    }
    // 'beforeinput' event handler may destroy target frame.
    if (frame.GetDocument()->GetFrame() != frame)
      return;

    // No DOM mutation if EditContext is active.
    if (frame.GetInputMethodController().GetActiveEditContext())
      return;
  }

  if (paste_mode == PasteMode::kAllMimeTypes) {
    PasteFromClipboard(frame, source);
    return;
  }
  PasteAsPlainTextFromClipboard(frame, source);
}

class CORE_EXPORT PasteImageResourceObserver final
    : public GarbageCollected<PasteImageResourceObserver>,
      public ImageResourceObserver {
 public:
  PasteImageResourceObserver(LocalFrame* frame,
                             EditorCommandSource source,
                             const KURL& src)
      : frame_(frame), source_(source), src_(src) {
    DCHECK(frame);
    frame->GetEditor().AddImageResourceObserver(this);
  }

  void ImageNotifyFinished(ImageResourceContent* image_content) override {
    if (!frame_ || !frame_->GetDocument()) {
      return;
    }

    if (!image_content || !image_content->IsLoaded()) {
      return;
    }

    if (!DispatchClipboardEvent(image_content)) {
      return;
    }

    if (!frame_->GetEditor().CanPaste()) {
      return;
    }

    if (source_ == EditorCommandSource::kMenuOrKeyBinding &&
        !frame_->Selection().SelectionHasFocus()) {
      return;
    }

    if (!IsRichlyEditable(*(frame_->GetDocument()->FocusedElement()))) {
      return;
    }

    frame_->GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

    PasteAsFragment();

    frame_->GetEditor().RemoveImageResourceObserver(this);
  }

  String DebugName() const override { return "PasteImageResourceObserver"; }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(frame_);
    ImageResourceObserver::Trace(visitor);
  }

 private:
  Element* FindEventTargetForClipboardEvent() const {
    if (source_ == EditorCommandSource::kMenuOrKeyBinding &&
        frame_->Selection().IsHidden()) {
      return frame_->Selection().GetDocument().body();
    }
    return FindEventTargetFrom(
        *frame_, frame_->Selection().ComputeVisibleSelectionInDOMTree());
  }

  String BuildMarkup() const {
    return "<img src=\"" + src_.GetString() +
           "\" referrerpolicy=\"no-referrer\" />";
  }

  DocumentFragment* BuildFragment() const {
    unsigned fragment_start = 0;
    unsigned fragment_end = 0;

    return CreateStrictlyProcessedFragmentFromMarkupWithContext(
        *(frame_->GetDocument()), BuildMarkup(), fragment_start, fragment_end,
        String());
  }

  // Dispatches a paste event with the image; returns true if we need to
  // continue with default process.
  bool DispatchClipboardEvent(ImageResourceContent* image_content) {
    Element* const target = FindEventTargetForClipboardEvent();

    if (!target) {
      return true;
    }

    Image* image = image_content->GetImage();

    if (!image) {
      return true;
    }

    scoped_refptr<SharedBuffer> image_buffer = image->Data();

    if (!image_buffer || !image_buffer->size()) {
      return true;
    }

    DataObject* data_object = DataObject::Create();

    data_object->AddFileSharedBuffer(
        image_buffer, /*is_accessible_from_start_frame=*/true, src_,
        image->FilenameExtension(),
        image_content->GetResponse().HttpHeaderFields().Get(
            http_names::kContentDisposition));

    DataTransfer* const data_transfer =
        DataTransfer::Create(DataTransfer::kCopyAndPaste,
                             DataTransferAccessPolicy::kReadable, data_object);

    Event* const evt =
        ClipboardEvent::Create(event_type_names::kPaste, data_transfer);

    target->DispatchEvent(*evt);

    if (!evt->defaultPrevented()) {
      return true;
    }

    return false;
  }

  void PasteAsFragment() {
    Element* const target = FindEventTargetForClipboardEvent();

    if (!target) {
      return;
    }

    target->DispatchEvent(*TextEvent::CreateForFragmentPaste(
        frame_->DomWindow(), BuildFragment(), false, false));
  }

  WeakMember<LocalFrame> frame_;
  EditorCommandSource source_;
  const KURL src_;
};

void ClipboardCommands::PasteFromImageURL(LocalFrame& frame,
                                          EditorCommandSource source,
                                          const String src) {
  DCHECK(frame.GetDocument());

  Element* const target = FindEventTargetForClipboardEvent(frame, source);
  if (!target) {
    return;
  }

  ResourceRequest resource_request(src);
  resource_request.SetReferrerPolicy(network::mojom::ReferrerPolicy::kNever);

  ResourceLoaderOptions resource_loader_options(
      target->GetExecutionContext()->GetCurrentWorld());

  FetchParameters fetch_params(std::move(resource_request),
                               resource_loader_options);

  if (!fetch_params.Url().IsValid()) {
    return;
  }

  // Apply CORS checks (and use CredentialsMode::kOmit as a safer default) to
  // ensure the image content are safe to be exposed. The CORS checks are
  // expected to always pass given the expected URLs/use cases of this command.
  fetch_params.SetCrossOriginAccessControl(
      target->GetExecutionContext()->GetSecurityOrigin(),
      network::mojom::CredentialsMode::kOmit);

  ImageResourceContent* image_content = ImageResourceContent::Fetch(
      fetch_params, target->GetDocument().Fetcher());

  image_content->AddObserver(MakeGarbageCollected<PasteImageResourceObserver>(
      &frame, source, fetch_params.Url()));
}

bool ClipboardCommands::ExecutePaste(LocalFrame& frame,
                                     Event*,
                                     EditorCommandSource source,
                                     const String&) {
  Paste(frame, source);
  return true;
}

bool ClipboardCommands::ExecutePasteGlobalSelection(LocalFrame& frame,
                                                    Event*,
                                                    EditorCommandSource source,
                                                    const String&) {
  if (!frame.GetEditor().Behavior().SupportsGlobalSelection())
    return false;
  DCHECK_EQ(source, EditorCommandSource::kMenuOrKeyBinding);

  const bool old_selection_mode = frame.GetSystemClipboard()->IsSelectionMode();
  frame.GetSystemClipboard()->SetSelectionMode(true);
  Paste(frame, source);
  frame.GetSystemClipboard()->SetSelectionMode(old_selection_mode);
  return true;
}

bool ClipboardCommands::ExecutePasteAndMatchStyle(LocalFrame& frame,
                                                  Event*,
                                                  EditorCommandSource source,
                                                  const String&) {
  if (!DispatchPasteEvent(frame, PasteMode::kPlainTextOnly, source))
    return false;
  if (!frame.GetEditor().CanPaste())
    return false;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  // A 'paste' event handler might have dirtied the layout so we need to update
  // before we obtain the selection.
  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  if (source == EditorCommandSource::kMenuOrKeyBinding) {
    if (!frame.Selection().SelectionHasFocus())
      return false;

    Element* const target = FindEventTargetForClipboardEvent(frame, source);

    DataTransfer* data_transfer = DataTransfer::Create(
        DataTransfer::kCopyAndPaste, DataTransferAccessPolicy::kReadable,
        DataObject::CreateFromClipboard(
            target ? target->GetExecutionContext() : nullptr,
            frame.GetSystemClipboard(), PasteMode::kPlainTextOnly));
    if (DispatchBeforeInputDataTransfer(
            target, InputEvent::InputType::kInsertFromPaste, data_transfer) !=
        DispatchEventResult::kNotCanceled) {
      return true;
    }
    // 'beforeinput' event handler may destroy target frame.
    if (frame.GetDocument()->GetFrame() != frame)
      return true;

    // No DOM mutation if EditContext is active.
    if (frame.GetInputMethodController().GetActiveEditContext())
      return true;
  }

  PasteAsPlainTextFromClipboard(frame, source);
  return true;
}

bool ClipboardCommands::ExecutePasteFromImageURL(LocalFrame& frame,
                                                 Event*,
                                                 EditorCommandSource source,
                                                 const String& src) {
  PasteFromImageURL(frame, source, src);
  return true;
}

}  // namespace blink

"""

```