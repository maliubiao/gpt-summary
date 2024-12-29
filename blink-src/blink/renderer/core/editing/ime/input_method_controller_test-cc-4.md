Response:
Let's break down the thought process to arrive at the summary of the given C++ test file.

1. **Understand the Context:** The file name `input_method_controller_test.cc` immediately tells us this is a test file for the `InputMethodController` class within the Blink rendering engine. The `blink/renderer/core/editing/ime/` path further confirms its purpose related to Input Method Engines (IMEs) and text editing.

2. **High-Level Objective:**  The primary goal of the tests is to ensure the `InputMethodController` behaves correctly in various scenarios involving text input, especially when interacting with IMEs and JavaScript event handlers.

3. **Identify Key Test Areas:** Scan through the `TEST_F` definitions. These are the individual test cases. Group them thematically. Notice patterns:
    * Many tests involve `SetComposition` and `CommitText`. This points to testing IME composition functionality.
    * Several tests include JavaScript code within them using `addEventListener`. This suggests testing interactions between IME events and script execution.
    * Some tests manipulate the selection using `GetFrame().Selection().SetSelection()`. This indicates tests related to how IME actions affect and are affected by text selection.
    *  Tests like `AutocapitalizeTextInputFlags` and `VerticalTextInputFlags` focus on specific input flags.
    *  Tests like `FinishComposingTextTooLong...` deal with edge cases like exceeding `maxlength`.
    *  A few tests address specific scenarios like interacting with non-editable elements (`SetCompositionAfterNonEditableElement`), table cells (`SetCompositionInTableCell`), and specific character sets (Myanmar, Tibetan, Devanagari, Tamil).
    *  The `ExecCommandDuringComposition` test stands out, focusing on how editor commands interact with active compositions.
    *  The final test, `EditContextCanvasHasEditableType`, addresses a specialized case related to canvas elements.

4. **Analyze Individual Tests (Examples):**  Pick a few representative tests and understand their logic:
    * **`SetCompositionDeleteSelectionAndInputEventHandlerChangingSelection`:** The test sets a composition, deletes selected text, and then *JavaScript* modifies the selection in response to an `input` event. The core purpose is to see if the `InputMethodController` correctly handles these interleaved actions. The key assumption is that the JavaScript `input` handler will run *after* the initial `SetComposition`. The expectation (`EXPECT_EQ`) verifies the final cursor position.
    * **`DeleteSelectionAndBeforeInputEventHandlerChangingStyle`:** This test uses a `beforeinput` event handler to modify the element's style. The crucial point is that style changes can trigger layout updates, and the test confirms that the `InputMethodController` handles this correctly to avoid crashes.
    * **`FinishComposingTextTooLongKeepSelectionAndInputEventHandler`:**  This test focuses on the `maxlength` attribute of an `<input>` element. It simulates an IME input exceeding the limit and checks if the text is truncated and the JavaScript `input` event handler (which moves the cursor) still functions correctly.

5. **Identify Relationships to Web Technologies:**
    * **JavaScript:**  The frequent use of `addEventListener('input', ...)` etc., directly links the tests to JavaScript's event handling mechanism. The tests verify how the `InputMethodController` interacts with JavaScript code that modifies the DOM or selection during IME input.
    * **HTML:** The tests create and manipulate HTML elements (`<div>`, `<input>`, `<textarea>`, `<table>`, `<canvas>`). Attributes like `contenteditable`, `maxlength`, `autocapitalize`, and `virtualkeyboardpolicy` are explicitly tested. The tests ensure the `InputMethodController` respects these HTML attributes.
    * **CSS:** The `DeleteSelectionAndBeforeInputEventHandlerChangingStyle` test directly demonstrates the connection to CSS (via `style.transform`). It highlights how style changes triggered by IME-related events are handled.

6. **Infer User Actions and Debugging:**  Consider how a user might trigger these scenarios:
    * **Basic Input:** Typing characters using an IME.
    * **Selecting Text:** Using the mouse or keyboard to highlight text.
    * **IME Composition:** Starting to type in an IME, seeing the candidate characters, and then confirming the input.
    * **JavaScript Interaction:** Websites with dynamic behavior that respond to text input events.

    For debugging, these tests provide specific, reproducible steps. If an IME-related bug is suspected, running these tests can help pinpoint the exact scenarios where the `InputMethodController` is failing.

7. **Synthesize the Summary:** Combine the observations from the previous steps into a concise summary. Focus on the core responsibilities of the tests and the web technologies involved. Emphasize the testing of complex interactions and potential error scenarios.

8. **Review and Refine:**  Read through the summary to ensure clarity, accuracy, and completeness. Make sure it addresses all aspects of the prompt. For example, explicitly mention the types of user errors the tests help prevent.

Self-Correction during the process: Initially, I might focus too much on individual test cases. The key is to step back and identify the *broader themes* and *goals* of the tests. Also, explicitly connecting the test scenarios to real-world user actions and debugging is important for a comprehensive understanding. Realizing the significance of the JavaScript interaction is a crucial step in understanding the complexity being tested.
好的，这是对 `blink/renderer/core/editing/ime/input_method_controller_test.cc` 文件功能的归纳总结：

**功能归纳:**

`input_method_controller_test.cc` 文件是 Chromium Blink 引擎中用于测试 `InputMethodController` 类的单元测试文件。 `InputMethodController` 负责处理输入法编辑器 (IME) 的相关逻辑，例如：

* **管理文本输入过程:**  处理用户通过 IME 输入文本的各个阶段，包括 composition (组合输入) 和 commit (提交)。
* **与渲染引擎交互:**  更新屏幕上显示的文本，处理光标位置，以及与文档的选择 (selection) 进行交互。
* **处理 JavaScript 事件:**  确保在 IME 操作期间，JavaScript 事件 (如 `input`, `compositionstart`, `compositionupdate`, `compositionend`, `beforeinput`) 能被正确触发和处理，并能正确响应 JavaScript 代码对文档内容和选择的修改。
* **处理各种边界情况和异常情况:**  例如，在 composition 过程中执行编辑命令，处理超出 `maxlength` 限制的输入，以及处理与非可编辑元素或特定 HTML 结构 (如表格) 的交互。
* **测试特定输入法特性:**  例如，处理特定语言的字符输入，如缅甸语、藏语、梵文和泰米尔语的组合输入。
* **测试输入相关的标志 (Flags):**  验证 `InputMethodController` 能否正确处理与输入相关的各种标志，例如 `autocapitalize` 和 `writing-mode` 相关的标志。
* **测试虚拟键盘策略:**  验证能否正确获取焦点元素的虚拟键盘策略。
* **测试 EditContext API:**  验证 `EditContext` API 在 canvas 元素上的行为。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

该测试文件与 JavaScript, HTML, CSS 的功能有密切关系，因为它测试了 `InputMethodController` 在这些 Web 技术环境下的行为。

* **JavaScript:**
    * **事件监听和处理:**  很多测试用例使用了 JavaScript 的事件监听器 (`addEventListener`) 来模拟在 IME 操作期间 JavaScript 代码对文档的修改。例如，`SetCompositionDeleteSelectionAndInputEventHandlerChangingSelection` 测试用例中，JavaScript 的 `input` 事件处理函数会修改文档的选择。这验证了 `InputMethodController` 在处理 IME 事件和 JavaScript 事件时的同步和正确性。
    * **DOM 操作:**  JavaScript 代码会修改 DOM 树，例如改变元素的 `textContent` 或 `innerHTML`，或者修改元素的样式。测试用例验证了 `InputMethodController` 在这些 DOM 操作发生后，仍然能正确处理 IME 的后续操作。例如，`CommitTextWithOpenCompositionAndCompositionEndEventHandlerChangingText` 测试用例中，`compositionend` 事件处理函数会改变文本内容。
    * **选择 (Selection) API:** JavaScript 代码会使用 `getSelection()` API 来获取和修改文档的选择。测试用例验证了 `InputMethodController` 与 JavaScript 的选择操作之间的交互。

* **HTML:**
    * **`contenteditable` 属性:**  大部分测试用例都使用了 `contenteditable` 属性来使 HTML 元素可编辑，从而触发 `InputMethodController` 的相关逻辑。
    * **表单元素 (`<input>`, `<textarea>`)**:  部分测试用例使用了表单元素，并测试了 `maxlength` 等属性对 IME 输入的影响。例如，`FinishComposingTextTooLongKeepSelectionAndInputEventHandler` 测试用例测试了在 `input` 元素 `maxlength` 限制下 IME 的行为。
    * **`autocapitalize` 属性:**  `AutocapitalizeTextInputFlags` 测试用例专门测试了 `autocapitalize` 属性在不同 HTML 元素上的行为，验证了 `InputMethodController` 能否根据该属性设置正确的输入标志。
    * **`style` 属性和 `writing-mode` CSS 属性:** `VerticalTextInputFlags` 测试用例测试了 `writing-mode` CSS 属性对输入标志的影响。 `DeleteSelectionAndBeforeInputEventHandlerChangingStyle` 测试用例展示了 JavaScript 如何修改 `style` 属性并在 IME 操作过程中触发布局更新。
    * **`<canvas>` 元素和 `EditContext` API:** `EditContextCanvasHasEditableType` 测试用例测试了 `EditContext` API 在 `<canvas>` 元素上的行为，这涉及到 HTML 和 JavaScript 的交互。
    * **`virtualkeyboardpolicy` 属性:** `VirtualKeyboardPolicyOfFocusedElement` 测试用例测试了 HTML 元素的 `virtualkeyboardpolicy` 属性如何影响虚拟键盘的显示策略。

* **CSS:**
    *  虽然测试文件本身不直接涉及 CSS 代码，但像 `VerticalTextInputFlags` 这样的测试用例间接地验证了 CSS 的 `writing-mode` 属性如何影响 `InputMethodController` 的行为。 `DeleteSelectionAndBeforeInputEventHandlerChangingStyle`  演示了 JavaScript 修改 CSS 样式会触发布局更新，`InputMethodController` 需要正确处理。

**逻辑推理和假设输入/输出:**

以下是一些测试用例的逻辑推理和假设输入/输出的例子：

* **`SetCompositionDeleteSelectionAndInputEventHandlerChangingSelection`:**
    * **假设输入:** 用户在一个 `contenteditable` 的 `div` 中选中 "world"，然后通过 IME 输入操作（例如，通过输入法删除选中的文本并开始新的输入）。
    * **逻辑推理:** `SetComposition("")` 应该删除选中的文本 "world"。随后，JavaScript 的 `input` 事件处理函数会将光标移动到 "hello" 之后。
    * **期望输出:** 光标最终停留在 "hello" 之后的位置（偏移量为 5）。

* **`FinishComposingTextTooLongKeepSelectionAndInputEventHandler`:**
    * **假设输入:** 用户在一个 `maxlength` 为 2 的 `<input>` 元素中使用 IME 输入 "hello"。
    * **逻辑推理:** 由于 `maxlength` 的限制，实际能输入到 `<input>` 的只有 "he"。 `FinishComposingText` 会触发 `input` 事件，该事件处理函数会将光标移动到偏移量 1 的位置。
    * **期望输出:** `<input>` 元素的值为 "he"，并且光标位置在偏移量 1。

**用户或编程常见的使用错误及举例说明:**

该测试文件可以帮助发现和防止以下用户或编程常见的使用错误：

* **JavaScript 事件处理不当导致的错误:**  例如，在 IME composition 过程中，JavaScript 代码不正确地修改了 DOM 或选择，导致光标位置错误或程序崩溃。这些测试用例通过模拟这些场景来验证 `InputMethodController` 的鲁棒性。 例如，在 `SetCompositionDeleteSelectionAndInputEventHandlerChangingSelection` 中，如果 `InputMethodController` 没有正确处理 JavaScript 对选择的修改，光标位置可能会错误。
* **`maxlength` 属性处理不当:**  程序没有正确处理表单元素 `maxlength` 属性的限制，导致输入超出限制。测试用例如 `FinishComposingTextTooLong...` 验证了 `InputMethodController` 是否能正确截断输入并处理相关事件。
* **IME 和 JavaScript 状态同步问题:**  在 IME 输入过程中，IME 和 JavaScript 代码都可能修改文档的状态。如果两者之间的状态没有正确同步，可能会导致显示错误或功能异常。 这些测试用例旨在发现这类同步问题。
* **对非可编辑元素进行 IME 操作:**  虽然用户不能直接编辑 `contenteditable="false"` 的元素，但如果程序逻辑不当，可能会尝试在其内部进行 IME 操作，导致错误。 `SetCompositionAfterNonEditableElement` 测试用例验证了 `InputMethodController` 对这种情况的处理。

**用户操作如何一步步到达这里，作为调试线索:**

当开发者在调试与 IME 相关的问题时，可以根据以下用户操作步骤来复现问题，并利用这些测试用例作为调试线索：

1. **用户在可编辑区域输入文本:**  这是最基本的操作，会触发 `InputMethodController` 的核心逻辑。如果发现输入异常，可以查看涉及 `SetComposition` 和 `CommitText` 的基本测试用例。
2. **用户使用 IME 进行输入:**  当用户使用中文、日文、韩文等输入法时，会经历 composition 阶段。相关的测试用例 (如 `SetComposition...`, `CommitText...`) 可以帮助调试 composition 过程中的问题。
3. **用户在输入过程中与页面上的 JavaScript 交互:**  如果页面有 JavaScript 代码监听输入事件并修改 DOM 或选择，可以参考包含 JavaScript 事件处理的测试用例，例如 `SetCompositionDeleteSelectionAndInputEventHandlerChangingSelection`。
4. **用户在特定 HTML 结构中输入:**  例如，在表格 (`SetCompositionInTableCell`) 或带有 `maxlength` 限制的表单元素中输入，可以参考相应的测试用例。
5. **用户尝试在非可编辑区域进行输入:**  这通常是程序错误，但 `SetCompositionAfterNonEditableElement` 这样的测试用例可以帮助验证框架对此类情况的处理。
6. **用户在不同 `writing-mode` 的区域输入:** `VerticalTextInputFlags` 测试用例与此相关。

通过重现用户的操作步骤，并结合相关的测试用例，开发者可以更容易地定位 `InputMethodController` 中出现问题的具体场景和代码路径。例如，如果用户在使用中文输入法时，在输入一半的时候页面 JavaScript 修改了文本，导致输入错乱，开发者可以重点查看涉及 `SetComposition` 和 JavaScript `input` 事件的测试用例。

**总结 (作为第 5 部分):**

作为第五部分，我们可以总结 `input_method_controller_test.cc` 文件全面地测试了 `InputMethodController` 类的核心功能，涵盖了基本的文本输入、复杂的 IME composition 过程、与 JavaScript 和 HTML 的交互、各种边界情况以及特定语言的输入处理。 这些测试用例不仅验证了 `InputMethodController` 的正确性，也为开发者提供了宝贵的调试线索，帮助他们理解用户操作如何触发 IME 相关逻辑，并定位潜在的错误。 它们确保了 Blink 引擎在处理各种输入场景下的稳定性和可靠性。

Prompt: 
```
这是目录为blink/renderer/core/editing/ime/input_method_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共5部分，请归纳一下它的功能

"""
       .ComputeOffsetInContainerNode());
}

TEST_F(InputMethodControllerTest,
       SetCompositionDeleteSelectionAndInputEventHandlerChangingSelection) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>hello world</div>", "sample");

  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      "document.getElementById('sample').addEventListener('input', "
      "  event => {"
      "    const node = event.currentTarget;"
      "    const selection = getSelection();"
      "    selection.collapse(node.firstChild, 5);"
      "    selection.extend(node.firstChild, 5);"
      "});");
  GetDocument().body()->AppendChild(script);
  UpdateAllLifecyclePhasesForTest();

  // Select "world".
  GetFrame().Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(EphemeralRange(Position(div->firstChild(), 6),
                                           Position(div->firstChild(), 11)))
          .Build(),
      SetSelectionOptions());

  // Call SetComposition() passing the empty string to delete the selection
  // (so we end up with "hello ") and move the cursor to before "hello".
  // JavaScript will change the text and move the cursor after "hello", where
  // it should be left.
  Controller().SetComposition("", Vector<ImeTextSpan>(), -6, -6);

  EXPECT_EQ(5, GetFrame()
                   .Selection()
                   .GetSelectionInDOMTree()
                   .Anchor()
                   .ComputeOffsetInContainerNode());
}

TEST_F(InputMethodControllerTest,
       DeleteSelectionAndBeforeInputEventHandlerChangingStyle) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>hello world</div>", "sample");

  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      "document.getElementById('sample').addEventListener('beforeinput', "
      "  event => {"
      "    event.currentTarget.style.transform = 'rotate(7deg)';"
      "});");
  GetDocument().body()->AppendChild(script);
  UpdateAllLifecyclePhasesForTest();

  // Select "world".
  GetFrame().Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(EphemeralRange(Position(div->firstChild(), 6),
                                           Position(div->firstChild(), 11)))
          .Build(),
      SetSelectionOptions());

  // Call DeleteSelection() will fire beforeinput event before deleting
  // selection. The beforeinput event handler dirties the layout. We should
  // update layout again before calling |TypingCommand::DeleteSelection()| to
  // avoid crash.
  EXPECT_EQ(true, Controller().DeleteSelection());
}

TEST_F(InputMethodControllerTest,
       CommitTextWithOpenCompositionAndCompositionEndEventHandlerChangingText) {
  InsertHTMLElement("<div id='sample' contenteditable>hello</div>", "sample");

  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      "document.getElementById('sample').addEventListener('compositionend', "
      "  event => {"
      "    const node = event.currentTarget;"
      "    node.textContent = 'HELLO WORLD';"
      "    const selection = getSelection();"
      "    selection.collapse(node.firstChild, 11);"
      "    selection.extend(node.firstChild, 11);"
      "});");
  GetDocument().body()->AppendChild(script);
  UpdateAllLifecyclePhasesForTest();

  // Open composition on "hello".
  Controller().SetCompositionFromExistingText(Vector<ImeTextSpan>(), 0, 5);

  // Commit text, leaving the cursor at the end of the newly-inserted text.
  // JavaScript will make the text longer by changing it to "HELLO WORLD",
  // while trying to move the selection to the end of the string (where we
  // should leave it).
  Controller().CommitText("HELLO", Vector<ImeTextSpan>(), 0);

  EXPECT_EQ(11, GetFrame()
                    .Selection()
                    .GetSelectionInDOMTree()
                    .Anchor()
                    .ComputeOffsetInContainerNode());
}

TEST_F(
    InputMethodControllerTest,
    SetCompositionToEmptyStringWithOpenCompositionAndCompositionEndEventHandlerChangingText) {
  InsertHTMLElement("<div id='sample' contenteditable>hello world</div>",
                    "sample");

  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      "document.getElementById('sample').addEventListener('compositionend', "
      "  event => {"
      "    const node = event.currentTarget;"
      "    node.textContent = 'HI ';"
      "    const selection = getSelection();"
      "    selection.collapse(node.firstChild, 2);"
      "    selection.extend(node.firstChild, 2);"
      "});");
  GetDocument().body()->AppendChild(script);
  UpdateAllLifecyclePhasesForTest();

  // Open composition on "world".
  Controller().SetCompositionFromExistingText(Vector<ImeTextSpan>(), 6, 11);

  // Delete the composition range, leaving the cursor in place. JavaScript will
  // change the text and move the cursor after "HI", where it should be left.
  Controller().SetComposition("", Vector<ImeTextSpan>(), 0, 0);

  EXPECT_EQ(2, GetFrame()
                   .Selection()
                   .GetSelectionInDOMTree()
                   .Anchor()
                   .ComputeOffsetInContainerNode());
}

TEST_F(
    InputMethodControllerTest,
    SetCompositionToEmptyStringAndCompositionEndEventHandlerChangingSelection) {
  InsertHTMLElement("<div id='sample' contenteditable>hello world</div>",
                    "sample");

  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      "document.getElementById('sample').addEventListener('compositionend', "
      "  event => {"
      "    const node = event.currentTarget;"
      "    const selection = getSelection();"
      "    selection.collapse(node.firstChild, 5);"
      "    selection.extend(node.firstChild, 5);"
      "});");
  GetDocument().body()->AppendChild(script);
  UpdateAllLifecyclePhasesForTest();

  // Open composition on "world".
  Controller().SetCompositionFromExistingText(Vector<ImeTextSpan>(), 6, 11);

  // Change the composition text to the empty string (so we end up with
  // "hello ") and move the cursor to before "hello". JavaScript will change
  // the text and move the cursor after "hello", where it should be left.
  Controller().SetComposition("", Vector<ImeTextSpan>(), -6, -6);

  EXPECT_EQ(5, GetFrame()
                   .Selection()
                   .GetSelectionInDOMTree()
                   .Anchor()
                   .ComputeOffsetInContainerNode());
}

TEST_F(InputMethodControllerTest,
       FinishComposingTextDoNotKeepSelectionAndCompositionEndEventHandler) {
  InsertHTMLElement("<div id='sample' contenteditable>hello world</div>",
                    "sample");

  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      "document.getElementById('sample').addEventListener('compositionend', "
      "  event => {"
      "    const node = event.currentTarget;"
      "    const selection = getSelection();"
      "    selection.collapse(node.firstChild, 5);"
      "    selection.extend(node.firstChild, 5);"
      "});");
  GetDocument().body()->AppendChild(script);
  UpdateAllLifecyclePhasesForTest();

  // Open composition on "world".
  Controller().SetCompositionFromExistingText(Vector<ImeTextSpan>(), 6, 11);

  // JavaScript will change the text and move the cursor after "hello", where
  // it should be left.
  Controller().FinishComposingText(InputMethodController::kKeepSelection);

  EXPECT_EQ(5, GetFrame()
                   .Selection()
                   .GetSelectionInDOMTree()
                   .Anchor()
                   .ComputeOffsetInContainerNode());
}

TEST_F(InputMethodControllerTest,
       FinishComposingTextKeepSelectionAndCompositionEndEventHandler) {
  InsertHTMLElement("<div id='sample' contenteditable>hello world</div>",
                    "sample");

  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      "document.getElementById('sample').addEventListener('compositionend', "
      "  event => {"
      "    const node = event.currentTarget;"
      "    const selection = getSelection();"
      "    selection.collapse(node.firstChild, 5);"
      "    selection.extend(node.firstChild, 5);"
      "});");
  GetDocument().body()->AppendChild(script);
  UpdateAllLifecyclePhasesForTest();

  // Open composition on "world".
  Controller().SetCompositionFromExistingText(Vector<ImeTextSpan>(), 6, 11);

  // JavaScript will change the text and move the cursor after "hello", where
  // it should be left.
  Controller().FinishComposingText(InputMethodController::kDoNotKeepSelection);

  EXPECT_EQ(5, GetFrame()
                   .Selection()
                   .GetSelectionInDOMTree()
                   .Anchor()
                   .ComputeOffsetInContainerNode());
}

TEST_F(
    InputMethodControllerTest,
    SetCompositionFromExistingTextAndCompositionStartEventHandlerChangingStyle) {
  InsertHTMLElement("<div id='sample' contenteditable>hello world</div>",
                    "sample");

  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      "document.getElementById('sample').addEventListener('compositionstart', "
      "  event => {"
      "    event.currentTarget.style.transform = 'rotate(7deg)';"
      "});");
  GetDocument().body()->AppendChild(script);
  UpdateAllLifecyclePhasesForTest();

  // Call SetCompositionFromExistingText() will fire compositionstart event. The
  // compositionstart event handler dirties the layout. We should update layout
  // again before getting visible selection to avoid crash.
  Controller().SetCompositionFromExistingText(Vector<ImeTextSpan>(), 6, 11);
}

TEST_F(InputMethodControllerTest,
       FinishComposingTextTooLongKeepSelectionAndInputEventHandler) {
  auto* input = To<HTMLInputElement>(
      InsertHTMLElement("<input id='sample' maxlength='2'>", "sample"));

  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      "document.getElementById('sample').addEventListener('input', "
      "  event => {"
      "    const node = event.currentTarget;"
      "    node.setSelectionRange(1, 1);"
      "});");
  GetDocument().body()->AppendChild(script);
  UpdateAllLifecyclePhasesForTest();

  input->Focus();

  // Open a composition that's too long for the <input> element..
  Controller().SetComposition("hello", Vector<ImeTextSpan>(), 0, 0);

  // Close out the composition, triggering the input event handler.
  Controller().FinishComposingText(InputMethodController::kKeepSelection);
  EXPECT_EQ("he", input->Value());

  // Verify that the input handler was able to properly move the selection.
  EXPECT_EQ(1u, input->selectionStart());
  EXPECT_EQ(1u, input->selectionEnd());
}

TEST_F(InputMethodControllerTest,
       FinishComposingTextTooLongDoNotKeepSelectionAndInputEventHandler) {
  auto* input = To<HTMLInputElement>(
      InsertHTMLElement("<input id='sample' maxlength='2'>", "sample"));

  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      "document.getElementById('sample').addEventListener('input', "
      "  event => {"
      "    const node = event.currentTarget;"
      "    node.setSelectionRange(1, 1);"
      "});");
  GetDocument().body()->AppendChild(script);
  UpdateAllLifecyclePhasesForTest();

  input->Focus();

  // Open a composition that's too long for the <input> element..
  Controller().SetComposition("hello", Vector<ImeTextSpan>(), 0, 0);

  // Close out the composition, triggering the input event handler.
  Controller().FinishComposingText(InputMethodController::kDoNotKeepSelection);
  EXPECT_EQ("he", input->Value());

  // Verify that the input handler was able to properly move the selection.
  EXPECT_EQ(1u, input->selectionStart());
  EXPECT_EQ(1u, input->selectionEnd());
}

TEST_F(InputMethodControllerTest,
       FinishComposingTextTooLongKeepSelectionAndCompositionEndEventHandler) {
  auto* input = To<HTMLInputElement>(
      InsertHTMLElement("<input id='sample' maxlength='2'>", "sample"));

  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      "document.getElementById('sample').addEventListener('compositionend', "
      "  event => {"
      "    const node = event.currentTarget;"
      "    node.setSelectionRange(1, 1);"
      "});");
  GetDocument().body()->AppendChild(script);
  UpdateAllLifecyclePhasesForTest();

  input->Focus();

  // Open a composition that's too long for the <input> element..
  Controller().SetComposition("hello", Vector<ImeTextSpan>(), 0, 0);

  // Close out the composition, triggering the compositionend event handler.
  Controller().FinishComposingText(InputMethodController::kKeepSelection);
  EXPECT_EQ("he", input->Value());

  // Verify that the compositionend handler was able to properly move the
  // selection.
  EXPECT_EQ(1u, input->selectionStart());
  EXPECT_EQ(1u, input->selectionEnd());
}

TEST_F(
    InputMethodControllerTest,
    FinishComposingTextTooLongDoNotKeepSelectionAndCompositionEndEventHandler) {
  auto* input = To<HTMLInputElement>(
      InsertHTMLElement("<input id='sample' maxlength='2'>", "sample"));

  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      "document.getElementById('sample').addEventListener('compositionend', "
      "  event => {"
      "    const node = event.currentTarget;"
      "    node.setSelectionRange(1, 1);"
      "});");
  GetDocument().body()->AppendChild(script);
  UpdateAllLifecyclePhasesForTest();

  input->Focus();

  // Open a composition that's too long for the <input> element..
  Controller().SetComposition("hello", Vector<ImeTextSpan>(), 0, 0);

  // Close out the composition, triggering the compositionend event handler.
  Controller().FinishComposingText(InputMethodController::kDoNotKeepSelection);
  EXPECT_EQ("he", input->Value());

  // Verify that the compositionend handler was able to properly move the
  // selection.
  EXPECT_EQ(1u, input->selectionStart());
  EXPECT_EQ(1u, input->selectionEnd());
}

TEST_F(InputMethodControllerTest, AutocapitalizeTextInputFlags) {
  // This test assumes that the behavior tested in
  // web_tests/fast/forms/autocapitalize.html works properly and tests the
  // following:
  // - The autocapitalize IDL states map properly to WebTextInputFlags for
  //   <input> elements, <textarea> elements, and editable regions
  // - We ignore the value of the IDL attribute for password/email/URL inputs
  //   and always send None for this case.
  Vector<std::pair<String, int>> element_and_expected_flags_pairs = {
      {"<input type='text'>", kWebTextInputFlagAutocapitalizeSentences},
      {"<input type='text' autocapitalize='none'>",
       kWebTextInputFlagAutocapitalizeNone},
      {"<input type='text' autocapitalize='characters'>",
       kWebTextInputFlagAutocapitalizeCharacters},
      {"<input type='text' autocapitalize='sentences'>",
       kWebTextInputFlagAutocapitalizeSentences},
      {"<input type='text' autocapitalize='words'>",
       kWebTextInputFlagAutocapitalizeWords},

      {"<input type='search'>", kWebTextInputFlagAutocapitalizeSentences},
      {"<input type='search' autocapitalize='none'>",
       kWebTextInputFlagAutocapitalizeNone},
      {"<input type='search' autocapitalize='characters'>",
       kWebTextInputFlagAutocapitalizeCharacters},
      {"<input type='search' autocapitalize='sentences'>",
       kWebTextInputFlagAutocapitalizeSentences},
      {"<input type='search' autocapitalize='words'>",
       kWebTextInputFlagAutocapitalizeWords},

      {"<input type='email'>", kWebTextInputFlagAutocapitalizeNone},
      {"<input type='email' autocapitalize='none'>",
       kWebTextInputFlagAutocapitalizeNone},
      {"<input type='email' autocapitalize='characters'>",
       kWebTextInputFlagAutocapitalizeNone},
      {"<input type='email' autocapitalize='sentences'>",
       kWebTextInputFlagAutocapitalizeNone},
      {"<input type='email' autocapitalize='words'>",
       kWebTextInputFlagAutocapitalizeNone},

      {"<input type='url'>", kWebTextInputFlagAutocapitalizeNone},
      {"<input type='url' autocapitalize='none'>",
       kWebTextInputFlagAutocapitalizeNone},
      {"<input type='url' autocapitalize='characters'>",
       kWebTextInputFlagAutocapitalizeNone},
      {"<input type='url' autocapitalize='sentences'>",
       kWebTextInputFlagAutocapitalizeNone},
      {"<input type='url' autocapitalize='words'>",
       kWebTextInputFlagAutocapitalizeNone},

      {"<input type='password'>", kWebTextInputFlagAutocapitalizeNone},
      {"<input type='password' autocapitalize='none'>",
       kWebTextInputFlagAutocapitalizeNone},
      {"<input type='password' autocapitalize='characters'>",
       kWebTextInputFlagAutocapitalizeNone},
      {"<input type='password' autocapitalize='sentences'>",
       kWebTextInputFlagAutocapitalizeNone},
      {"<input type='password' autocapitalize='words'>",
       kWebTextInputFlagAutocapitalizeNone},

      {"<textarea></textarea>", kWebTextInputFlagAutocapitalizeSentences},
      {"<textarea autocapitalize='none'></textarea>",
       kWebTextInputFlagAutocapitalizeNone},
      {"<textarea autocapitalize='characters'></textarea>",
       kWebTextInputFlagAutocapitalizeCharacters},
      {"<textarea autocapitalize='sentences'></textarea>",
       kWebTextInputFlagAutocapitalizeSentences},
      {"<textarea autocapitalize='words'></textarea>",
       kWebTextInputFlagAutocapitalizeWords},

      {"<div contenteditable></div>", kWebTextInputFlagAutocapitalizeSentences},
      {"<div contenteditable autocapitalize='none'></div>",
       kWebTextInputFlagAutocapitalizeNone},
      {"<div contenteditable autocapitalize='characters'></div>",
       kWebTextInputFlagAutocapitalizeCharacters},
      {"<div contenteditable autocapitalize='sentences'></div>",
       kWebTextInputFlagAutocapitalizeSentences},
      {"<div contenteditable autocapitalize='words'></div>",
       kWebTextInputFlagAutocapitalizeWords},
  };

  const int autocapitalize_mask = kWebTextInputFlagAutocapitalizeNone |
                                  kWebTextInputFlagAutocapitalizeCharacters |
                                  kWebTextInputFlagAutocapitalizeWords |
                                  kWebTextInputFlagAutocapitalizeSentences;

  for (const std::pair<String, int>& element_and_expected_flags_pair :
       element_and_expected_flags_pairs) {
    const String& element = element_and_expected_flags_pair.first;
    const int expected_flags = element_and_expected_flags_pair.second;

    GetDocument().write(element);
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
    To<Element>(GetDocument().body()->lastChild())->Focus();

    EXPECT_EQ(expected_flags,
              Controller().TextInputInfo().flags & autocapitalize_mask);
  }
}

TEST_F(InputMethodControllerTest, VerticalTextInputFlags) {
  Vector<std::pair<String, int>> element_html_and_expected_flags = {
      {"<div contenteditable='true'></div>", 0},
      {"<div contenteditable='true' style='writing-mode:vertical-rl;'></div>",
       kWebTextInputFlagVertical},
      {"<div contenteditable='true' style='writing-mode:vertical-lr;'></div>",
       kWebTextInputFlagVertical},
  };

  for (const std::pair<String, int>& html_and_flags :
       element_html_and_expected_flags) {
    const String& element_html = html_and_flags.first;
    const int expected_flags = html_and_flags.second;

    GetDocument().write(element_html);
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
    To<Element>(GetDocument().body()->lastChild())->Focus();

    EXPECT_EQ(expected_flags,
              Controller().TextInputInfo().flags & kWebTextInputFlagVertical);
  }
}

TEST_F(InputMethodControllerTest, ExecCommandDuringComposition) {
  Element* div =
      InsertHTMLElement("<div id='sample' contenteditable></div>", "sample");

  // Open a composition.
  Controller().SetComposition(String::FromUTF8("hello"), Vector<ImeTextSpan>(),
                              5, 5);
  // Turn on bold formatting.
  GetDocument().execCommand("bold", false, "", ASSERT_NO_EXCEPTION);

  // Extend the composition with some more text.
  Controller().SetComposition(String::FromUTF8("helloworld"),
                              Vector<ImeTextSpan>(), 10, 10);

  // "world" should be bold.
  EXPECT_EQ("hello<b>world</b>", div->innerHTML());
}

TEST_F(InputMethodControllerTest, SetCompositionAfterNonEditableElement) {
  GetFrame().Selection().SetSelection(
      SetSelectionTextToBody("<div id='sample' contenteditable='true'>"
                             "<span contenteditable='false'>a</span>|b</div>"),
      SetSelectionOptions());
  Element* const div = GetDocument().getElementById(AtomicString("sample"));
  div->Focus();

  // Open a composition and insert some text.
  Controller().SetComposition(String::FromUTF8("c"), Vector<ImeTextSpan>(), 1,
                              1);

  // Add some more text to the composition.
  Controller().SetComposition(String::FromUTF8("cd"), Vector<ImeTextSpan>(), 2,
                              2);

  EXPECT_EQ(
      "<div contenteditable=\"true\" id=\"sample\">"
      "<span contenteditable=\"false\">a</span>^cd|b</div>",
      GetSelectionTextFromBody(
          SelectionInDOMTree::Builder()
              .SetBaseAndExtent(Controller().CompositionEphemeralRange())
              .Build()));
}

TEST_F(InputMethodControllerTest, SetCompositionInTableCell) {
  GetFrame().Selection().SetSelection(
      SetSelectionTextToBody(
          "<table id='sample' contenteditable><tr><td>a</td><td "
          "id='td2'>|</td></tr></table>"),
      SetSelectionOptions());
  Element* const table = GetDocument().getElementById(AtomicString("sample"));
  table->Focus();

  Controller().SetComposition(String::FromUTF8("c"), Vector<ImeTextSpan>(), 1,
                              1);

  Element* const td2 = GetDocument().getElementById(AtomicString("td2"));
  const Node* const text_node = td2->firstChild();

  Range* range = GetCompositionRange();
  EXPECT_EQ(text_node, range->startContainer());
  EXPECT_EQ(0u, range->startOffset());
  EXPECT_EQ(text_node, range->endContainer());
  EXPECT_EQ(1u, range->endOffset());
}

TEST_F(InputMethodControllerTest, SetCompositionInMyanmar) {
  Element* div =
      InsertHTMLElement("<div id='sample' contenteditable></div>", "sample");

  // Add character U+200C: 'kZeroWidthNonJoinerCharacter' and Myanmar vowel
  Controller().SetComposition(String::FromUTF8("\xE2\x80\x8C\xE1\x80\xB1"),
                              Vector<ImeTextSpan>(), 0, 0);

  EXPECT_EQ(1u, div->CountChildren());
  EXPECT_EQ(String::FromUTF8("\xE2\x80\x8C\xE1\x80\xB1"), div->innerHTML());

  Range* range = GetCompositionRange();
  EXPECT_EQ(0u, range->startOffset());
  EXPECT_EQ(2u, range->endOffset());
  Controller().CommitText(String::FromUTF8("\xE2\x80\x8C\xE1\x80\xB1"),
                          Vector<ImeTextSpan>(), 1);
  EXPECT_EQ(String::FromUTF8("\xE2\x80\x8C\xE1\x80\xB1"), div->innerHTML());

  // Add character U+200C: 'kZeroWidthNonJoinerCharacter' and Myanmar vowel
  Controller().SetComposition(String::FromUTF8("\xE2\x80\x8C\xE1\x80\xB1"),
                              Vector<ImeTextSpan>(), 2, 2);
  Controller().CommitText(String::FromUTF8("\xE2\x80\x8C\xE1\x80\xB1"),
                          Vector<ImeTextSpan>(), 1);
  EXPECT_EQ(
      String::FromUTF8("\xE2\x80\x8C\xE1\x80\xB1\xE2\x80\x8C\xE1\x80\xB1"),
      div->innerHTML());
}

TEST_F(InputMethodControllerTest, VirtualKeyboardPolicyOfFocusedElement) {
  EXPECT_EQ(ui::mojom::VirtualKeyboardPolicy::AUTO,
            Controller().VirtualKeyboardPolicyOfFocusedElement());
  InsertHTMLElement("<input id='a' virtualkeyboardpolicy='manual'>", "a")
      ->Focus();
  EXPECT_EQ(ui::mojom::VirtualKeyboardPolicy::MANUAL,
            Controller().VirtualKeyboardPolicyOfFocusedElement());
}

TEST_F(InputMethodControllerTest, SetCompositionInTibetan) {
  GetFrame().Selection().SetSelection(
      SetSelectionTextToBody("<div id='sample' contenteditable>|</div>"),
      SetSelectionOptions());
  Element* const div = GetDocument().getElementById(AtomicString("sample"));
  div->Focus();

  Vector<ImeTextSpan> ime_text_spans;
  Controller().SetComposition(String(Vector<UChar>{0xF56}), ime_text_spans, 1,
                              1);
  EXPECT_EQ("<div contenteditable id=\"sample\">\u0F56|</div>",
            GetSelectionTextFromBody());

  Controller().CommitText(String(Vector<UChar>{0xF56}), ime_text_spans, 0);
  EXPECT_EQ("<div contenteditable id=\"sample\">\u0F56|</div>",
            GetSelectionTextFromBody());

  Controller().SetComposition(String(Vector<UChar>{0xFB7}), ime_text_spans, 1,
                              1);
  EXPECT_EQ("<div contenteditable id=\"sample\">\u0F56\u0FB7|</div>",
            GetSelectionTextFromBody());

  // Attempt to replace part of grapheme cluster "\u0FB7" in composition
  Controller().CommitText(String(Vector<UChar>{0xFB7}), ime_text_spans, 0);
  EXPECT_EQ("<div contenteditable id=\"sample\">\u0F56\u0FB7|</div>",
            GetSelectionTextFromBody());

  Controller().SetComposition(String(Vector<UChar>{0xF74}), ime_text_spans, 1,
                              1);
  EXPECT_EQ("<div contenteditable id=\"sample\">\u0F56\u0FB7\u0F74|</div>",
            GetSelectionTextFromBody());
}

TEST_F(InputMethodControllerTest, SetCompositionInDevanagari) {
  GetFrame().Selection().SetSelection(
      SetSelectionTextToBody("<div id='sample' contenteditable>\u0958|</div>"),
      SetSelectionOptions());
  Element* const div = GetDocument().getElementById(AtomicString("sample"));
  div->Focus();

  Vector<ImeTextSpan> ime_text_spans;
  Controller().SetComposition(String(Vector<UChar>{0x94D}), ime_text_spans, 1,
                              1);
  EXPECT_EQ("<div contenteditable id=\"sample\">\u0958\u094D|</div>",
            GetSelectionTextFromBody());

  Controller().CommitText(String(Vector<UChar>{0x94D, 0x930}), ime_text_spans,
                          0);
  EXPECT_EQ("<div contenteditable id=\"sample\">\u0958\u094D\u0930|</div>",
            GetSelectionTextFromBody());
}

TEST_F(InputMethodControllerTest, SetCompositionTamil) {
  GetFrame().Selection().SetSelection(
      SetSelectionTextToBody("<div id='sample' contenteditable>|</div>"),
      SetSelectionOptions());
  Element* const div = GetDocument().getElementById(AtomicString("sample"));
  div->Focus();

  Vector<ImeTextSpan> ime_text_spans;
  // Note: region starts out with space.
  Controller().CommitText(String(Vector<UChar>{0xA0}), ime_text_spans, 0);
  // Add character U+0BB5: 'TAMIL LETTER VA'
  Controller().SetComposition(String(Vector<UChar>{0xBB5}), ime_text_spans, 0,
                              0);
  // Add character U+0BC7: 'TAMIL VOWEL SIGN EE'
  Controller().CommitText(String(Vector<UChar>{0xBB5, 0xBC7}), ime_text_spans,
                          1);
  EXPECT_EQ("<div contenteditable id=\"sample\">\u00A0\u0BB5\u0BC7|</div>",
            GetSelectionTextFromBody());
}

TEST_F(InputMethodControllerTest, EditContextCanvasHasEditableType) {
  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* noneditable_canvas = InsertHTMLElement(
      "<canvas id='noneditable-canvas'></canvas>", "noneditable-canvas");
  Element* editable_canvas = InsertHTMLElement(
      "<canvas id='editable-canvas'></canvas>", "editable-canvas");
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      "document.getElementById('editable-canvas').editContext = new "
      "EditContext()");
  GetDocument().body()->AppendChild(script);
  UpdateAllLifecyclePhasesForTest();

  noneditable_canvas->Focus();
  EXPECT_EQ(kWebTextInputTypeNone, Controller().TextInputType());

  editable_canvas->Focus();
  EXPECT_EQ(kWebTextInputTypeContentEditable, Controller().TextInputType());
}
}  // namespace blink

"""


```