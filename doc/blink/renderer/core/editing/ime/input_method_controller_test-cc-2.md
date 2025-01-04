Response:
The user wants a summary of the functionalities implemented in the provided C++ code snippet. The code is a part of a test file (`input_method_controller_test.cc`) for the Blink rendering engine. It tests the `InputMethodController` which handles interactions with Input Method Editors (IMEs).

Here's a breakdown of the thought process to analyze the code and generate the response:

1. **Identify the Core Class:** The filename and the `TEST_F` macros clearly indicate that the code tests the `InputMethodController` class.

2. **Recognize the Testing Framework:** The `TEST_F` macro is a strong indicator of a C++ testing framework, likely Google Test, used within the Chromium project. The structure `TEST_F(ClassName, TestName)` is a common pattern.

3. **Analyze Individual Test Cases:**  Go through each `TEST_F` function and determine what specific functionality it's testing. Look for keywords like `SetComposition`, `CommitText`, event names (e.g., `compositionend`, `beforeinput`, `input`), and assertions (`EXPECT_EQ`, `EXPECT_TRUE`, `ASSERT_EQ`).

4. **Group Related Tests:**  Notice patterns in the test names and the operations being performed. For example, several tests involve "CompositionInputEvent," indicating they are testing how the `InputMethodController` handles input events during composition. Similarly, tests with "Marker_" in their names are related to how the controller interacts with document markers.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):** Consider how the tested functionalities relate to web standards. IME interactions are fundamental for text input in web browsers. The tests involving event listeners (`CreateHTMLWith...`) directly connect to JavaScript event handling. The `ImeTextSpan` and its properties (color, underline) relate to how IME compositions can be styled, which has connections to CSS. The `contenteditable` attribute in HTML is crucial for enabling text editing.

6. **Identify Logic and Assumptions:** Some tests simulate specific sequences of actions and assert the expected outcome. For example, tests involving `SetComposition` followed by `CommitText` or further `SetComposition` calls demonstrate how the controller manages the composition state. The tests often set up an initial state (e.g., inserting an HTML element) and then perform actions.

7. **Spot Potential User/Programming Errors:** Consider what could go wrong when using or implementing IME handling. Issues like incorrect event firing, unexpected cursor movements, or improper handling of composition states are potential errors that these tests aim to prevent.

8. **Trace User Actions (Debugging):** Think about how a user's interaction might lead to these code paths. Typing in an input field, using an IME to select characters, deleting text, and focusing/blurring elements are all user actions that trigger the `InputMethodController`.

9. **Focus on the Current Snippet's Contribution (Part 3 of 5):**  Realize that the request asks for the functionalities demonstrated *within this specific code block*. While the overall file tests broader aspects of IME, this part focuses on specific scenarios.

10. **Synthesize the Summary:** Combine the observations into a concise description of the tested functionalities. Emphasize the key aspects like composition events, marker handling, and edge cases like whitespace.

11. **Structure the Output:** Organize the response logically, addressing each part of the user's request (functionality, relation to web tech, logic/assumptions, errors, user actions, and a final summary). Use clear language and examples where appropriate.

By following these steps, we can effectively analyze the C++ test code and provide a comprehensive and informative response that addresses the user's specific questions.
这是 `blink/renderer/core/editing/ime/input_method_controller_test.cc` 文件的第三部分，主要专注于测试 `InputMethodController` 在处理输入法编辑器（IME）composition 和 commit 操作时，与 JavaScript 事件、HTML 元素以及文档标记（markers）的交互行为。

**功能归纳 (针对第三部分):**

* **测试 Composition Input 事件:**
    * 验证在 `contenteditable` 元素中进行输入法 composition 时，是否正确触发 `beforeinput` 和 `input` 事件，并携带正确的 `data` 和 `targetRanges` 信息。
    * 测试在 composition 过程中删除已存在的 composition 时，触发的事件和携带的数据。
    * 测试在 composition 过程中插入新文本（有或无先前的 composition）时，触发的事件和携带的数据。
    * 测试在 composition 过程中插入空文本时，触发的事件和携带的数据。
* **测试 Composition End 事件:**
    * 验证当 composition 结束时，是否触发 `compositionend` 事件，并携带正确的 `data` 信息。
    * 测试在没有选区的情况下结束 composition，光标位置的变化。
* **测试焦点变化对 Composition 的影响:**
    * 验证当焦点从正在进行 composition 的元素移开时，composition 是否会自动结束。
* **测试 `CommitText` 操作:**
    * 验证 `CommitText` 方法在不同的场景下（例如，有选区、无选区）是否正确提交文本。
    * 测试 `CommitText` 提交空字符串时，是否会删除选区中的内容。
* **测试与文档标记 (Markers) 的交互:**
    * 验证在进行 composition 或 commit 操作时，与 `ImeTextSpan` 关联的标记是否被正确创建、更新和删除。
    * 测试在文本内容被修改时，不同类型的文档标记（内容相关型和内容无关型）如何被调整或移除。这包括：
        * 替换标记开始部分的内容。
        * 替换包含标记开始部分的内容。
        * 替换标记结束部分的内容。
        * 替换包含标记结束部分的内容。
        * 替换整个标记的内容。
        * 替换文本，标记位于文本的开头或结尾。
    * 特别关注在文本修改时，围绕文档标记的空格处理（`WhitespaceFixup`）。确保标记不会错误地包含或排除空格，尤其是在 `contenteditable` 元素中空格可能被转换为 `&nbsp;` 的情况下。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **JavaScript:**
    * **事件监听:** 代码中多次使用 `CreateHTMLWithCompositionInputEventListeners()` 和 `CreateHTMLWithCompositionEndEventListener()` 等函数，模拟在 JavaScript 中为 HTML 元素添加 `beforeinput`, `input`, `compositionstart`, `compositionupdate`, `compositionend` 等事件监听器。这些测试验证了当 IME 操作发生时，这些 JavaScript 事件是否被正确触发，以及事件对象中包含的数据是否正确。
        * **举例:**
            ```javascript
            // 在 JavaScript 中监听 compositionend 事件
            document.getElementById('editableDiv').addEventListener('compositionend', function(event) {
              console.log('compositionend data:', event.data);
            });
            ```
            测试代码通过设置 `GetDocument().title()` 来模拟 JavaScript 事件处理函数对事件数据的记录。例如，`EQ("compositionend.data:hello;", GetDocument().title());`  表示期望在 `compositionend` 事件触发后，JavaScript 代码记录的 `event.data` 值为 "hello"。
* **HTML:**
    * **`contenteditable` 属性:**  很多测试用例都使用了带有 `contenteditable` 属性的 `<div>` 元素，模拟用户可以在其中进行编辑的场景。IME 的输入和 composition 行为主要发生在这类元素中。
    * **`<input>` 和 `<textarea>` 元素:**  部分测试用例使用了 `<input>` 和 `<textarea>` 元素，验证在这些表单控件中 IME 的行为。
        * **举例:** `<div id='sample' contenteditable></div>`  表示一个可编辑的 HTML 元素，用户可以在其中输入文本，并触发 IME 相关的操作和事件。
* **CSS:**
    * **`ImeTextSpan` 的样式:** 代码中使用了 `ImeTextSpan` 来表示 composition 文本的样式，例如颜色、下划线等。虽然测试代码本身不直接涉及 CSS 样式规则的应用，但 `ImeTextSpan` 的属性最终会影响浏览器如何渲染 composition 中的文本，这与 CSS 的渲染机制相关。
        * **举例:** `ImeTextSpan(ImeTextSpan::Type::kComposition, 0, 5, Color(255, 0, 0), ...)`  定义了一个 composition 文本范围，并指定了颜色为红色。浏览器在渲染时会应用这些样式。

**逻辑推理与假设输入输出:**

* **测试 `CompositionInputEventForInsert`:**
    * **假设输入:** 用户在 `contenteditable` 的 div 中使用 IME 输入 "你好"，先输入 "你" (composition)，然后输入 "好" (commit)。
    * **预期输出:**  在 composition "你" 的过程中，会触发 `beforeinput` 和 `input` 事件，`data` 可能是拼音或候选字。当 commit "好" 时，会触发 `beforeinput` 和 `input` 事件，`data` 为 "好"，并且触发 `compositionend` 事件， `data` 为最终的 "你好"。测试代码通过 `GetDocument().setTitle()` 记录事件数据，并用 `EXPECT_EQ` 进行断言。
* **测试 `WhitespaceFixup`:**
    * **假设输入:** 用户在一个空的 `contenteditable` div 中输入两个空格。
    * **预期输出:**  由于 `contenteditable` 的特性，连续的空格会被浏览器处理，可能将第一个空格转换为 `&nbsp;` 以保持空格的显示。`InputMethodController` 需要确保它返回给 IME 的文本信息仍然是两个普通空格，而不是 `&nbsp;`。

**用户或编程常见的使用错误举例:**

* **JavaScript 事件监听错误:**  开发者可能错误地监听了错误的事件类型，或者在事件处理函数中错误地处理了事件数据，导致 IME 输入行为异常。例如，没有正确监听 `compositionend` 事件，导致 composition 结束后没有执行相应的清理或更新操作。
* **HTML 结构错误:**  `contenteditable` 属性没有正确设置，或者 HTML 结构嵌套复杂，可能导致 IME 的行为出现问题，例如光标位置错误、无法输入等。
* **编程错误导致 `InputMethodController` 状态不一致:**  在某些复杂的交互场景下，开发者可能错误地调用 `InputMethodController` 的方法，导致其内部状态与实际的 DOM 状态不一致，从而引发 IME 相关的问题。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中打开一个包含可编辑元素 (例如，`<div contenteditable>`, `<input>`, `<textarea>`) 的网页。**
2. **用户将光标放置在该可编辑元素中，使其获得焦点。**
3. **用户开始使用输入法 (IME) 输入文本。**
4. **当用户输入拼音或其他 промежуточные 字符时，会触发 compositionstart 和 compositionupdate 事件，`InputMethodController` 的 `SetComposition` 方法会被调用。** 测试代码中的 `Controller().SetComposition("hello", ime_text_spans, 5, 5);`  模拟了这个过程。
5. **当用户选择候选词或完成输入时，会触发 compositionend 事件，`InputMethodController` 的 `FinishComposingText` 或 `CommitText` 方法会被调用。** 测试代码中的 `Controller().FinishComposingText(...)` 和 `Controller().CommitText(...)`  模拟了这个过程。
6. **在整个输入过程中，`beforeinput` 和 `input` 事件会伴随发生，`InputMethodController` 负责处理这些事件，并更新文档内容和状态。**

**总结:**

这部分测试代码专注于验证 `InputMethodController` 在处理 IME 输入事件（特别是 composition 和 commit）时的核心逻辑，以及它与浏览器事件系统和文档模型 (Document Markers) 的正确交互。它确保了当用户通过 IME 输入时，相关的 JavaScript 事件能够被正确触发和携带正确的数据，同时保证了文档内容和标记的正确更新。这些测试覆盖了各种输入场景，包括插入、删除、替换文本，以及焦点变化等情况，旨在提高 Blink 引擎在处理 IME 输入时的稳定性和可靠性。

Prompt: 
```
这是目录为blink/renderer/core/editing/ime/input_method_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能

"""
EQ("compositionend.data:hello;", GetDocument().title());
}

TEST_F(InputMethodControllerTest, CompositionInputEventForDelete) {
  CreateHTMLWithCompositionInputEventListeners();

  // Simulate composition in the |contentEditable|.
  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 5, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));

  GetDocument().setTitle(g_empty_string);
  Controller().SetComposition("hello", ime_text_spans, 5, 5);
  EXPECT_EQ(
      "beforeinput.data:hello;beforeinput.targetRanges:0-0;input.data:hello;",
      GetDocument().title());

  // Delete the existing composition.
  GetDocument().setTitle(g_empty_string);
  Controller().SetComposition("", ime_text_spans, 0, 0);
  EXPECT_EQ(
      "beforeinput.data:;beforeinput.targetRanges:0-5;input.data:null;"
      "compositionend.data:;",
      GetDocument().title());
}

TEST_F(InputMethodControllerTest, CompositionInputEventForInsert) {
  CreateHTMLWithCompositionInputEventListeners();

  // Simulate composition in the |contentEditable|.
  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 5, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));

  // Insert new text without previous composition.
  GetDocument().setTitle(g_empty_string);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().CommitText("hello", ime_text_spans, 0);
  EXPECT_EQ(
      "beforeinput.data:hello;beforeinput.targetRanges:0-0;input.data:hello;",
      GetDocument().title());

  GetDocument().setTitle(g_empty_string);
  Controller().SetComposition("n", ime_text_spans, 1, 1);
  EXPECT_EQ("beforeinput.data:n;beforeinput.targetRanges:5-5;input.data:n;",
            GetDocument().title());

  // Insert new text with previous composition.
  GetDocument().setTitle(g_empty_string);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().CommitText("hello", ime_text_spans, 1);
  EXPECT_EQ(
      "beforeinput.data:hello;beforeinput.targetRanges:5-6;input.data:hello;"
      "compositionend.data:hello;",
      GetDocument().title());
}

TEST_F(InputMethodControllerTest, CompositionInputEventForInsertEmptyText) {
  CreateHTMLWithCompositionInputEventListeners();

  // Simulate composition in the |contentEditable|.
  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 5, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));

  // Insert empty text without previous composition.
  GetDocument().setTitle(g_empty_string);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().CommitText("", ime_text_spans, 0);
  EXPECT_EQ("", GetDocument().title().Utf8());

  GetDocument().setTitle(g_empty_string);
  Controller().SetComposition("n", ime_text_spans, 1, 1);
  EXPECT_EQ("beforeinput.data:n;beforeinput.targetRanges:0-0;input.data:n;",
            GetDocument().title());

  // Insert empty text with previous composition.
  GetDocument().setTitle(g_empty_string);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().CommitText("", ime_text_spans, 1);
  EXPECT_EQ(
      "beforeinput.data:;beforeinput.targetRanges:0-1;input.data:null;"
      "compositionend.data:;",
      GetDocument().title());
}

TEST_F(InputMethodControllerTest, CompositionEndEventWithNoSelection) {
  CreateHTMLWithCompositionEndEventListener(kNoSelection);

  // Simulate composition in the |contentEditable|.
  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 5, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));

  Controller().SetComposition("hello", ime_text_spans, 1, 1);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ(1u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(1u, Controller().GetSelectionOffsets().End());

  // Confirm the ongoing composition. Note that it moves the caret to the end of
  // text [5,5] before firing 'compositonend' event.
  Controller().FinishComposingText(InputMethodController::kDoNotKeepSelection);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_TRUE(Controller().GetSelectionOffsets().IsNull());
}

TEST_F(InputMethodControllerTest, FinishCompositionRemovedRange) {
  Element* input_a =
      InsertHTMLElement("<input id='a' /><br><input type='tel' id='b' />", "a");

  EXPECT_EQ(kWebTextInputTypeText, Controller().TextInputType());

  // The test requires non-empty composition.
  Controller().SetComposition("hello", Vector<ImeTextSpan>(), 5, 5);
  EXPECT_EQ(kWebTextInputTypeText, Controller().TextInputType());

  // Remove element 'a'.
  input_a->setOuterHTML("", ASSERT_NO_EXCEPTION);
  EXPECT_EQ(kWebTextInputTypeNone, Controller().TextInputType());

  GetDocument().getElementById(AtomicString("b"))->Focus();
  EXPECT_EQ(kWebTextInputTypeTelephone, Controller().TextInputType());

  Controller().FinishComposingText(InputMethodController::kKeepSelection);
  EXPECT_EQ(kWebTextInputTypeTelephone, Controller().TextInputType());
}

TEST_F(InputMethodControllerTest, ReflectsSpaceWithoutNbspMangling) {
  InsertHTMLElement("<div id='sample' contenteditable></div>", "sample");

  Vector<ImeTextSpan> ime_text_spans;
  Controller().CommitText(String("  "), ime_text_spans, 0);

  // In a contenteditable, multiple spaces or a space at the edge needs to be
  // nbsp to affect layout properly, but it confuses some IMEs (particularly
  // Vietnamese, see crbug.com/663880) to have their spaces reflected back to
  // them as nbsp.
  EXPECT_EQ(' ', Controller().TextInputInfo().value.Ascii()[0]);
  EXPECT_EQ(' ', Controller().TextInputInfo().value.Ascii()[1]);
}

TEST_F(InputMethodControllerTest, SetCompositionPlainTextWithIme_Text_Span) {
  InsertHTMLElement("<div id='sample' contenteditable></div>", "sample");

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 1, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));

  Controller().SetComposition(" ", ime_text_spans, 1, 1);

  ASSERT_EQ(1u, GetDocument().Markers().Markers().size());

  EXPECT_EQ(0u, GetDocument().Markers().Markers()[0]->StartOffset());
  EXPECT_EQ(1u, GetDocument().Markers().Markers()[0]->EndOffset());
}

TEST_F(InputMethodControllerTest,
       SetCompositionPlainTextWithIme_Text_Span_Interim_Char_Selection) {
  InsertHTMLElement("<div id='sample' contenteditable></div>", "sample");

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 1, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent, Color::kTransparent, false,
      true /*interim_char_selection*/));

  Controller().SetComposition("a", ime_text_spans, 0, 1);

  ASSERT_EQ(1u, GetDocument().Markers().Markers().size());

  auto* styleable_marker =
      DynamicTo<StyleableMarker>(GetDocument().Markers().Markers()[0].Get());
  EXPECT_EQ(ImeTextSpanUnderlineStyle::kSolid,
            styleable_marker->UnderlineStyle());
}

TEST_F(InputMethodControllerTest, CommitPlainTextWithIme_Text_SpanInsert) {
  InsertHTMLElement("<div id='sample' contenteditable>Initial text.</div>",
                    "sample");

  Vector<ImeTextSpan> ime_text_spans;

  Controller().SetEditableSelectionOffsets(PlainTextRange(8, 8));

  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 1, 11, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));

  Controller().CommitText(String("ime_text_spand"), ime_text_spans, 0);

  ASSERT_EQ(1u, GetDocument().Markers().Markers().size());

  EXPECT_EQ(9u, GetDocument().Markers().Markers()[0]->StartOffset());
  EXPECT_EQ(19u, GetDocument().Markers().Markers()[0]->EndOffset());
}

TEST_F(InputMethodControllerTest, CommitPlainTextWithIme_Text_SpanReplace) {
  InsertHTMLElement("<div id='sample' contenteditable>Initial text.</div>",
                    "sample");

  Vector<ImeTextSpan> ime_text_spans;

  Controller().SetCompositionFromExistingText(ime_text_spans, 8, 12);

  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 1, 11, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));

  Controller().CommitText(String("string"), ime_text_spans, 0);

  ASSERT_EQ(1u, GetDocument().Markers().Markers().size());

  EXPECT_EQ(9u, GetDocument().Markers().Markers()[0]->StartOffset());
  EXPECT_EQ(15u, GetDocument().Markers().Markers()[0]->EndOffset());
}

TEST_F(InputMethodControllerTest, ImeTextSpanAppearsCorrectlyAfterNewline) {
  Element* div =
      InsertHTMLElement("<div id='sample' contenteditable></div>", "sample");

  Vector<ImeTextSpan> ime_text_spans;
  Controller().SetComposition(String("hello"), ime_text_spans, 6, 6);
  Controller().FinishComposingText(InputMethodController::kKeepSelection);
  GetFrame().GetEditor().InsertLineBreak();

  Controller().SetCompositionFromExistingText(ime_text_spans, 8, 8);

  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 5, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  Controller().SetComposition(String("world"), ime_text_spans, 0, 0);
  ASSERT_EQ(1u, GetDocument().Markers().Markers().size());

  // Verify composition marker shows up on the second line, not the first
  const Position& first_line_position =
      PlainTextRange(2).CreateRange(*div).StartPosition();
  const Position& second_line_position =
      PlainTextRange(8).CreateRange(*div).StartPosition();
  ASSERT_EQ(
      0u, GetDocument()
              .Markers()
              .MarkersFor(To<Text>(*first_line_position.ComputeContainerNode()))
              .size());
  ASSERT_EQ(1u, GetDocument()
                    .Markers()
                    .MarkersFor(
                        To<Text>(*second_line_position.ComputeContainerNode()))
                    .size());

  // Verify marker has correct start/end offsets (measured from the beginning
  // of the node, which is the beginning of the line)
  EXPECT_EQ(0u, GetDocument().Markers().Markers()[0]->StartOffset());
  EXPECT_EQ(5u, GetDocument().Markers().Markers()[0]->EndOffset());
}

TEST_F(InputMethodControllerTest, SelectionWhenFocusChangeFinishesComposition) {
  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* editable =
      InsertHTMLElement("<div id='sample' contenteditable></div>", "sample");
  editable->Focus();

  // Simulate composition in the |contentEditable|.
  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 5, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  Controller().SetComposition("foo", ime_text_spans, 3, 3);

  EXPECT_TRUE(Controller().HasComposition());
  EXPECT_EQ(0u, GetCompositionRange()->startOffset());
  EXPECT_EQ(3u, GetCompositionRange()->endOffset());
  EXPECT_EQ(3, GetFrame()
                   .Selection()
                   .GetSelectionInDOMTree()
                   .Anchor()
                   .ComputeOffsetInContainerNode());

  // Insert 'test'.
  NonThrowableExceptionState exception_state;
  GetDocument().execCommand("insertText", false, "test", exception_state);

  EXPECT_TRUE(Controller().HasComposition());
  EXPECT_EQ(7, GetFrame()
                   .Selection()
                   .GetSelectionInDOMTree()
                   .Anchor()
                   .ComputeOffsetInContainerNode());

  // Focus change finishes composition.
  editable->blur();
  editable->Focus();

  // Make sure that caret is still at the end of the inserted text.
  EXPECT_FALSE(Controller().HasComposition());
  EXPECT_EQ(7, GetFrame()
                   .Selection()
                   .GetSelectionInDOMTree()
                   .Anchor()
                   .ComputeOffsetInContainerNode());
}

TEST_F(InputMethodControllerTest, SetEmptyCompositionShouldNotMoveCaret) {
  auto* textarea =
      To<HTMLTextAreaElement>(InsertHTMLElement("<textarea id='txt'>", "txt"));

  textarea->SetValue("abc\n");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(4, 4));

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 3, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  Controller().SetComposition(String("def"), ime_text_spans, 0, 3);
  Controller().SetComposition(String(""), ime_text_spans, 0, 3);
  Controller().CommitText(String("def"), ime_text_spans, 0);

  EXPECT_EQ("abc\ndef", textarea->Value());
}

TEST_F(InputMethodControllerTest, WhitespaceFixup) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>Initial text blah</div>", "sample");

  // Delete "Initial"
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 0, 7);
  Controller().CommitText(String(""), empty_ime_text_spans, 0);

  // The space at the beginning of the string should have been converted to an
  // nbsp
  EXPECT_EQ("&nbsp;text blah", div->innerHTML());

  // Delete "blah"
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 6, 10);
  Controller().CommitText(String(""), empty_ime_text_spans, 0);

  // The space at the end of the string should have been converted to an nbsp
  EXPECT_EQ("&nbsp;text&nbsp;", div->innerHTML());
}

TEST_F(InputMethodControllerTest, CommitEmptyTextDeletesSelection) {
  auto* input =
      To<HTMLInputElement>(InsertHTMLElement("<input id='sample'>", "sample"));

  input->SetValue("Abc Def Ghi");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetEditableSelectionOffsets(PlainTextRange(4, 8));
  Controller().CommitText(String(""), empty_ime_text_spans, 0);
  EXPECT_EQ("Abc Ghi", input->Value());

  Controller().SetEditableSelectionOffsets(PlainTextRange(4, 7));
  Controller().CommitText(String("1"), empty_ime_text_spans, 0);
  EXPECT_EQ("Abc 1", input->Value());
}

static String GetMarkedText(
    DocumentMarkerController& document_marker_controller,
    Node* node,
    int marker_index) {
  DocumentMarker* marker = document_marker_controller.Markers()[marker_index];
  return node->textContent().Substring(
      marker->StartOffset(), marker->EndOffset() - marker->StartOffset());
}

TEST_F(InputMethodControllerTest,
       Marker_WhitespaceFixupAroundContentIndependentMarkerNotContainingSpace) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>Initial text blah</div>", "sample");

  // Add marker under "text" (use TextMatch since Composition markers don't
  // persist across editing operations)
  EphemeralRange marker_range = PlainTextRange(8, 12).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kBlack, Color::kBlack);
  // Delete "Initial"
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 0, 7);
  Controller().CommitText(String(""), empty_ime_text_spans, 0);

  // Delete "blah"
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 6, 10);
  Controller().CommitText(String(""), empty_ime_text_spans, 0);

  // Check that the marker is still attached to "text" and doesn't include
  // either space around it
  EXPECT_EQ(
      1u,
      GetDocument().Markers().MarkersFor(To<Text>(*div->firstChild())).size());
  EXPECT_EQ("text",
            GetMarkedText(GetDocument().Markers(), div->firstChild(), 0));
}

TEST_F(InputMethodControllerTest,
       Marker_WhitespaceFixupAroundContentIndependentMarkerBeginningWithSpace) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>Initial text blah</div>", "sample");

  // Add marker under " text" (use TextMatch since Composition markers don't
  // persist across editing operations)
  EphemeralRange marker_range = PlainTextRange(7, 12).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kBlack, Color::kBlack);
  // Delete "Initial"
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 0, 7);
  Controller().CommitText(String(""), empty_ime_text_spans, 0);

  // Delete "blah"
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 6, 10);
  Controller().CommitText(String(""), empty_ime_text_spans, 0);

  // Check that the marker is still attached to " text" and includes the space
  // before "text" but not the space after
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
  ASSERT_EQ(
      "\xC2\xA0text",
      GetMarkedText(GetDocument().Markers(), div->firstChild(), 0).Utf8());
}

TEST_F(InputMethodControllerTest,
       Marker_WhitespaceFixupAroundContentIndependentMarkerEndingWithSpace) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>Initial text blah</div>", "sample");

  // Add marker under "text " (use TextMatch since Composition markers don't
  // persist across editing operations)
  EphemeralRange marker_range = PlainTextRange(8, 13).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kBlack, Color::kBlack);
  // Delete "Initial"
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 0, 7);
  Controller().CommitText(String(""), empty_ime_text_spans, 0);

  // Delete "blah"
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 6, 10);
  Controller().CommitText(String(""), empty_ime_text_spans, 0);

  // Check that the marker is still attached to "text " and includes the space
  // after "text" but not the space before
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
  ASSERT_EQ(
      "text\xC2\xA0",
      GetMarkedText(GetDocument().Markers(), div->firstChild(), 0).Utf8());
}

TEST_F(
    InputMethodControllerTest,
    Marker_WhitespaceFixupAroundContentIndependentMarkerBeginningAndEndingWithSpaces) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>Initial text blah</div>", "sample");

  // Add marker under " text " (use TextMatch since Composition markers don't
  // persist across editing operations)
  EphemeralRange marker_range = PlainTextRange(7, 13).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kBlack, Color::kBlack);

  // Delete "Initial"
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 0, 7);
  Controller().CommitText(String(""), empty_ime_text_spans, 0);

  // Delete "blah"
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 6, 10);
  Controller().CommitText(String(""), empty_ime_text_spans, 0);

  // Check that the marker is still attached to " text " and includes both the
  // space before "text" and the space after
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
  ASSERT_EQ(
      "\xC2\xA0text\xC2\xA0",
      GetMarkedText(GetDocument().Markers(), div->firstChild(), 0).Utf8());
}

TEST_F(InputMethodControllerTest, ContentDependentMarker_ReplaceStartOfMarker) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>Initial text</div>", "sample");

  // Add marker under "Initial text"
  EphemeralRange marker_range = PlainTextRange(0, 12).CreateRange(*div);
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  // Replace "Initial" with "Original"
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 0, 7);
  Controller().CommitText(String("Original"), empty_ime_text_spans, 0);

  // Verify marker was removed
  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());
}

TEST_F(InputMethodControllerTest,
       ContentIndependentMarker_ReplaceStartOfMarker) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>Initial text</div>", "sample");

  // Add marker under "Initial text"
  EphemeralRange marker_range = PlainTextRange(0, 12).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kBlack, Color::kBlack);

  // Replace "Initial" with "Original"
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 0, 7);
  Controller().CommitText(String("Original"), empty_ime_text_spans, 0);

  // Verify marker is under "Original text"
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
  ASSERT_EQ(
      "Original text",
      GetMarkedText(GetDocument().Markers(), div->firstChild(), 0).Utf8());
}

TEST_F(InputMethodControllerTest,
       ContentDependentMarker_ReplaceTextContainsStartOfMarker) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>This is some initial text</div>",
      "sample");

  // Add marker under "initial text"
  EphemeralRange marker_range = PlainTextRange(13, 25).CreateRange(*div);
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  // Replace "some initial" with "boring"
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 8, 20);
  Controller().CommitText(String("boring"), empty_ime_text_spans, 0);

  // Verify marker was removed
  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());
}

TEST_F(InputMethodControllerTest,
       ContentIndependentMarker_ReplaceTextContainsStartOfMarker) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>This is some initial text</div>",
      "sample");

  // Add marker under "initial text"
  EphemeralRange marker_range = PlainTextRange(13, 25).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kBlack, Color::kBlack);

  // Replace "some initial" with "boring"
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 8, 20);
  Controller().CommitText(String("boring"), empty_ime_text_spans, 0);

  // Verify marker is under " text"
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
  EXPECT_EQ(" text",
            GetMarkedText(GetDocument().Markers(), div->firstChild(), 0));
}

TEST_F(InputMethodControllerTest, ContentDependentMarker_ReplaceEndOfMarker) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>Initial text</div>", "sample");

  // Add marker under "Initial text"
  EphemeralRange marker_range = PlainTextRange(0, 12).CreateRange(*div);
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  // Replace "text" with "string"
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 8, 12);
  Controller().CommitText(String("string"), empty_ime_text_spans, 0);

  // Verify marker was removed
  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());
}

TEST_F(InputMethodControllerTest, ContentIndependentMarker_ReplaceEndOfMarker) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>Initial text</div>", "sample");

  // Add marker under "Initial text"
  EphemeralRange marker_range = PlainTextRange(0, 12).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kBlack, Color::kBlack);

  // Replace "text" with "string"
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 8, 12);
  Controller().CommitText(String("string"), empty_ime_text_spans, 0);

  // Verify marker is under "Initial string"
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
  ASSERT_EQ(
      "Initial string",
      GetMarkedText(GetDocument().Markers(), div->firstChild(), 0).Utf8());
}

TEST_F(InputMethodControllerTest,
       ContentDependentMarker_ReplaceTextContainsEndOfMarker) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>This is some initial text</div>",
      "sample");

  // Add marker under "some initial"
  EphemeralRange marker_range = PlainTextRange(8, 20).CreateRange(*div);
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  // Replace "initial text" with "content"
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 13, 25);
  Controller().CommitText(String("content"), empty_ime_text_spans, 0);

  EXPECT_EQ("This is some content", div->innerHTML());

  // Verify marker was removed
  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());
}

TEST_F(InputMethodControllerTest,
       ContentIndependentMarker_ReplaceTextContainsEndOfMarker) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>This is some initial text</div>",
      "sample");

  // Add marker under "some initial"
  EphemeralRange marker_range = PlainTextRange(8, 20).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kBlack, Color::kBlack);

  // Replace "initial text" with "content"
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 13, 25);
  Controller().CommitText(String("content"), empty_ime_text_spans, 0);

  EXPECT_EQ("This is some content", div->innerHTML());

  // Verify marker is under "some "
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
  ASSERT_EQ("some ",
            GetMarkedText(GetDocument().Markers(), div->firstChild(), 0));
}

TEST_F(InputMethodControllerTest, ContentDependentMarker_ReplaceEntireMarker) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>Initial text</div>", "sample");

  // Add marker under "text"
  EphemeralRange marker_range = PlainTextRange(8, 12).CreateRange(*div);
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  // Replace "text" with "string"
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 8, 12);
  Controller().CommitText(String("string"), empty_ime_text_spans, 0);

  // Verify marker was removed
  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());
}

TEST_F(InputMethodControllerTest,
       ContentIndependentMarker_ReplaceEntireMarker) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>Initial text</div>", "sample");

  // Add marker under "text"
  EphemeralRange marker_range = PlainTextRange(8, 12).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kBlack, Color::kBlack);

  // Replace "text" with "string"
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 8, 12);
  Controller().CommitText(String("string"), empty_ime_text_spans, 0);

  // Verify marker is under "string"
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
  ASSERT_EQ(
      "string",
      GetMarkedText(GetDocument().Markers(), div->firstChild(), 0).Utf8());
}

TEST_F(InputMethodControllerTest,
       ContentDependentMarker_ReplaceTextWithMarkerAtBeginning) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>Initial text</div>", "sample");

  // Add marker under "Initial"
  EphemeralRange marker_range = PlainTextRange(0, 7).CreateRange(*div);
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  // Replace "Initial text" with "New string"
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 0, 12);
  Controller().CommitText(String("New string"), empty_ime_text_spans, 0);

  // Verify marker was removed
  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());
}

TEST_F(InputMethodControllerTest,
       ContentIndependentMarker_ReplaceTextWithMarkerAtBeginning) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>Initial text</div>", "sample");

  // Add marker under "Initial"
  EphemeralRange marker_range = PlainTextRange(0, 7).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kBlack, Color::kBlack);

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  // Replace "Initial text" with "New string"
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 0, 12);
  Controller().CommitText(String("New string"), empty_ime_text_spans, 0);

  // Verify marker was removed
  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());
}

TEST_F(InputMethodControllerTest,
       ContentDependentMarker_ReplaceTextWithMarkerAtEnd) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>Initial text</div>", "sample");

  // Add marker under "text"
  EphemeralRange marker_range = PlainTextRange(8, 12).CreateRange(*div);
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  // Replace "Initial text" with "New string"
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 0, 12);
  Controller().CommitText(String("New string"), empty_ime_text_spans, 0);

  // Verify marker was removed
  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());
}

TEST_F(InputMethodControllerTest,
       ContentIndependentMarker_ReplaceTextWithMarkerAtEnd) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>Initial text</div>", "sample");

  // Add marker under "text"
  EphemeralRange marker_range = PlainTextRange(8, 12).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kBlack, Color::kBlack);

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  // Replace "Initial text" with "New string"
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 0, 12);
  Controller().CommitText(String("New string"), empty_ime_text_spans, 0);

  // Verify marker was removed
  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());
}

TEST_F(InputMethodControllerTest, ContentDependentMarker_Deletions) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>1111122222333334444455555</div>",
      "sample");

  EphemeralRange marker_range = PlainTextRange(0, 5).CreateRange(*div);
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus
"""


```