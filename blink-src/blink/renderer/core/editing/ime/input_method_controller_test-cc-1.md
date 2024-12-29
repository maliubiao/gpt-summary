Response:
The user wants me to summarize the functionality of the provided C++ code snippet, which is part of a larger test file for Chromium's Blink rendering engine. This particular part focuses on testing the `InputMethodController` class, specifically its text manipulation capabilities, especially when dealing with input method editors (IMEs) and complex characters.

Here's a breakdown of the code's functionality:

1. **`DeleteSurroundingText` tests:** These tests verify the behavior of deleting text surrounding the current selection, considering different scenarios:
    *   Deleting single characters.
    *   Deleting characters when multi-byte characters are present on either or both sides of the selection.
    *   Deleting within elements with nested contenteditable regions.
    *   Deleting composed characters (like accented characters).

2. **`DeleteSurroundingTextInCodePoints` tests:**  These tests are similar to the previous ones but focus on deleting text based on code points rather than byte offsets. This is important for handling Unicode correctly, especially for characters outside the Basic Multilingual Plane (BMP).

3. **`ReplaceTextAndDoNotChangeSelection` tests:**  These tests check if replacing text in a text field correctly updates the content without altering the existing selection.

4. **`ReplaceTextAndMoveCursorAfterTheReplacementText` tests:**  These tests ensure that after replacing text, the cursor is moved to the end of the newly inserted text.

5. **`SetCompositionForInputWithNewCaretPositions` and `SetCompositionForContentEditableWithNewCaretPositions` tests:** These tests examine how the input method controller handles setting composition text (the text being entered by an IME) and updating the cursor position during composition in both `<input>` elements and `contenteditable` elements. They specifically check boundary conditions for the caret position.

6. **`SetCompositionWithEmptyText` test:** This test verifies the behavior when setting an empty composition string, both with and without a prior composition.

7. **`InsertLineBreakWhileComposingText` and `InsertLineBreakAfterConfirmingText` tests:** These tests check how line breaks are inserted when an IME is actively composing text and after the text has been committed.

8. **Input Event Tests (`CompositionInputEventIsComposing`, `CompositionInputEventForReplace`, `CompositionInputEventForConfirm`):** These tests verify that the correct `beforeinput` and `input` events are fired with the correct `isComposing` flag and data when using an IME. They cover scenarios for starting a composition, replacing existing composition text, and confirming (committing) the composed text.

**Relationship to Javascript, HTML, CSS:**

The tests directly interact with HTML elements (`<input>`, `<div>`, `<b>`, `<i>`, `<script>`) and their properties (`value`, `innerText`, `contenteditable`). They also simulate user actions that would trigger JavaScript event listeners (`addEventListener`). While CSS isn't directly manipulated, the layout updates (`GetDocument().UpdateStyleAndLayout()`) suggest that rendering and layout calculations might be indirectly involved in some scenarios.

**Logic and Assumptions:**

The tests make assumptions about the expected behavior of the `InputMethodController` based on different input scenarios. For example, when `DeleteSurroundingText(1, 0)` is called, it's assumed that one character to the left of the cursor will be deleted. The tests cover various edge cases, like multi-byte characters and invalid surrogate pairs.

**User/Programming Errors:**

These tests help identify potential errors in the `InputMethodController` implementation. Common errors could include:

*   Incorrectly calculating text offsets when dealing with multi-byte characters.
*   Not updating the cursor position correctly during composition or after text replacement.
*   Incorrectly firing or populating input events.
*   Issues with handling invalid Unicode sequences.

**User Interaction and Debugging:**

A user interacting with a web page by typing into an input field or a contenteditable area using an IME would trigger these code paths. For debugging, developers might set breakpoints within the `InputMethodController` methods being tested to understand how the text manipulation and event handling are occurring.

**Summary of Part 2:**

This part of the test file focuses on rigorously testing the text manipulation capabilities of the `InputMethodController`, particularly in the context of IME usage and complex character handling. It verifies that deleting, replacing, and composing text works correctly under various conditions, including the presence of multi-byte characters, nested elements, and different cursor positions. It also ensures that the correct input events are fired during IME interactions.

这是 `blink/renderer/core/editing/ime/input_method_controller_test.cc` 文件的第二部分，主要的功能是 **测试 `InputMethodController` 类中与文本删除、替换和输入法组合相关的各种场景**。

具体来说，这部分测试涵盖了以下功能：

*   **`DeleteSurroundingText` 方法的各种情况:**
    *   删除光标周围的单个字符。
    *   处理光标左右存在多字节字符（例如 UTF-8 编码的星号、奖杯等）的情况，验证删除操作是否正确计算字符长度。
    *   在包含多个 `contenteditable` 元素的复杂结构中进行删除操作，验证是否能跨越不同的元素节点进行删除。
    *   删除由多个代码单元组成的字符（例如组合字符）。
*   **`DeleteSurroundingTextInCodePoints` 方法的各种情况:**
    *   与 `DeleteSurroundingText` 类似，但以 Unicode 代码点为单位进行删除，这对于正确处理 Unicode 字符至关重要。
    *   测试在包含多字节字符的文本中，按照代码点删除指定数量的字符。
    *   测试在包含 `<img>` 标签等非文本节点的 `contenteditable` 元素中进行代码点删除。
    *   测试当删除范围内存在无效的 surrogate pair 时，`DeleteSurroundingTextInCodePoints` 的行为。
*   **`ReplaceTextAndDoNotChangeSelection` 方法:**
    *   测试在替换文本后，光标或选区的位置是否保持不变。涵盖了替换范围与当前选区不重叠、完全重叠和部分重叠的情况。
*   **`ReplaceTextAndMoveCursorAfterTheReplacementText` 方法:**
    *   测试在替换文本后，光标是否被移动到新插入文本的末尾。同样涵盖了替换范围与当前选区不同位置关系的情况。
*   **`SetCompositionForInputWithNewCaretPositions` 和 `SetCompositionForContentEditableWithNewCaretPositions` 方法:**
    *   测试在使用输入法输入（组合）文本时，如何设置组合文本以及如何根据新的光标位置更新文本和光标。
    *   涵盖了在 `<input>` 元素和 `contenteditable` 元素中设置组合文本的不同情况，包括光标在组合文本之前、之后、内部以及超出边界的情况。
*   **`SetCompositionWithEmptyText` 方法:**
    *   测试设置空的组合文本的行为，包括在有和没有之前的组合文本的情况下。
*   **`InsertLineBreakWhileComposingText` 和 `InsertLineBreakAfterConfirmingText` 方法:**
    *   测试在输入法组合文本时插入换行符的行为。
    *   测试在输入法完成输入后插入换行符的行为。
*   **关于 InputEvent 的测试 (`CompositionInputEventIsComposing`, `CompositionInputEventForReplace`, `CompositionInputEventForConfirm`):**
    *   验证在使用输入法进行输入时，是否会触发正确的 `beforeinput` 和 `input` 事件，并且 `isComposing` 属性的值是否正确。
    *   测试在替换已有的组合文本时，`beforeinput` 和 `input` 事件的 `data` 和 `targetRanges` 属性是否正确。
    *   测试在确认（提交）组合文本时，`beforeinput` 和 `input` 事件的触发和属性值是否正确。

**与 Javascript, HTML, CSS 的关系：**

这部分测试直接操作和检查了 HTML 元素 (`<input>`, `<div>`, `<b>`, `<i>`, `<script>`) 的属性，例如 `value` (对于 `<input>`) 和 `innerText` (对于 `contenteditable` 的 `<div>`)。同时，部分测试也涉及到模拟用户操作，例如在 `contenteditable` 元素中输入，这会触发 JavaScript 的事件监听器。

**举例说明:**

*   **HTML:**  测试中使用了 `<input id='sample'>` 创建了一个输入框元素，并使用 `InsertHTMLElement` 函数将其插入到文档中。
*   **Javascript:**  在 `CompositionInputEventIsComposing` 测试中，通过插入 `<script>` 标签，添加了 `beforeinput` 和 `input` 事件的监听器，用于检查事件的 `isComposing` 属性。
*   **CSS:** 虽然这部分测试没有直接操作 CSS，但 `GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest)` 的调用表明，在进行文本操作后，可能会触发样式的更新和布局的重新计算。

**逻辑推理和假设输入输出:**

*   **假设输入:** 一个包含特定文本的 `<input>` 元素，光标位于某个位置。
*   **操作:** 调用 `Controller().DeleteSurroundingText(1, 0)`。
*   **预期输出:** 光标左边的一个字符被删除，`<input>` 元素的 `value` 属性更新。

*   **假设输入:** 一个 `contenteditable` 的 `<div>` 元素，其中包含文本 "hello"，光标位于 'l' 和 'o' 之间。
*   **操作:** 调用 `Controller().SetComposition("AB", ime_text_spans, 0, 2)`。
*   **预期输出:** `<div>` 的 `innerText` 变为 "heABllo"，光标移动到 'B' 和 'l' 之间。

**用户或编程常见的使用错误:**

*   **用户错误:** 用户在使用输入法时，可能会错误地输入或删除字符，导致文本内容不符合预期。这些测试覆盖了各种删除和输入场景，确保 `InputMethodController` 能正确处理这些情况。
*   **编程错误:** 开发人员在实现文本编辑功能时，可能会错误地计算字符偏移量，尤其是在处理多字节字符时。例如，错误地将一个多字节字符算作多个字符。这些测试通过针对多字节字符的测试用例，帮助发现这类错误。

**用户操作如何一步步的到达这里 (调试线索):**

1. 用户在一个网页上的 `<input>` 元素或 `contenteditable` 元素中点击，使该元素获得焦点。
2. 用户开始使用输入法输入文本，例如输入中文、日文等需要组合的字符。
3. 操作系统或输入法将用户的输入转换为组合文本，并通过 IPC (Inter-Process Communication) 将这些信息传递给浏览器渲染进程。
4. 渲染进程中的 `InputMethodController` 接收到输入法的事件，例如设置组合文本 (`SetComposition`)、提交文本 (`CommitText`) 等。
5. 当用户按下删除键 (Backspace 或 Delete) 时，或者选择一段文本并按下删除键时，会触发删除操作，最终调用到 `DeleteSurroundingText` 或 `DeleteSurroundingTextInCodePoints` 方法。
6. 当用户选中一段文本并直接输入新的字符时，可能会触发替换操作，最终调用到 `ReplaceTextAndMoveCursorAfterTheReplacementText` 等方法。
7. 在这些过程中，浏览器会触发 `beforeinput` 和 `input` 等事件，JavaScript 代码可以通过事件监听器捕获这些事件并进行处理。

**功能归纳:**

这部分测试代码主要用于验证 Chromium Blink 引擎中 `InputMethodController` 类在处理文本删除、替换和输入法组合输入时的正确性和鲁棒性。它覆盖了各种边界情况和复杂场景，确保了在不同情况下，文本操作和事件触发都能符合预期。这些测试对于保证浏览器的文本编辑功能（尤其是涉及到输入法输入时）的稳定性和用户体验至关重要。

Prompt: 
```
这是目录为blink/renderer/core/editing/ime/input_method_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能

"""
ut->Value());
  Controller().SetEditableSelectionOffsets(PlainTextRange(2, 2));
  Controller().DeleteSurroundingText(100, 100);
  EXPECT_EQ("", input->Value());

  input->SetValue("h");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("h", input->Value());
  Controller().SetEditableSelectionOffsets(PlainTextRange(1, 1));
  Controller().DeleteSurroundingText(1, 0);
  EXPECT_EQ("", input->Value());

  input->SetValue("h");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("h", input->Value());
  Controller().SetEditableSelectionOffsets(PlainTextRange(0, 0));
  Controller().DeleteSurroundingText(0, 1);
  EXPECT_EQ("", input->Value());
}

TEST_F(InputMethodControllerTest,
       DeleteSurroundingTextWithMultiCodeTextOnTheLeft) {
  auto* input =
      To<HTMLInputElement>(InsertHTMLElement("<input id='sample'>", "sample"));

  // U+2605 == "black star". It takes up 1 space.
  input->SetValue(String::FromUTF8("foo\xE2\x98\x85"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(4, 4));
  EXPECT_EQ("foo\xE2\x98\x85", input->Value().Utf8());
  Controller().DeleteSurroundingText(1, 0);
  EXPECT_EQ("foo", input->Value());

  // U+1F3C6 == "trophy". It takes up 2 space.
  input->SetValue(String::FromUTF8("foo\xF0\x9F\x8F\x86"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(5, 5));
  EXPECT_EQ("foo\xF0\x9F\x8F\x86", input->Value().Utf8());
  Controller().DeleteSurroundingText(1, 0);
  EXPECT_EQ("foo\xED\xA0\xBC", input->Value().Utf8());

  // composed U+0E01 "ka kai" + U+0E49 "mai tho". It takes up 2 space.
  input->SetValue(String::FromUTF8("foo\xE0\xB8\x81\xE0\xB9\x89"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(5, 5));
  EXPECT_EQ("foo\xE0\xB8\x81\xE0\xB9\x89", input->Value().Utf8());
  Controller().DeleteSurroundingText(1, 0);
  EXPECT_EQ("foo\xE0\xB8\x81", input->Value().Utf8());

  // "trophy" + "trophy".
  input->SetValue(String::FromUTF8("foo\xF0\x9F\x8F\x86\xF0\x9F\x8F\x86"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(7, 7));
  EXPECT_EQ("foo\xF0\x9F\x8F\x86\xF0\x9F\x8F\x86", input->Value().Utf8());
  Controller().DeleteSurroundingText(2, 0);
  EXPECT_EQ("foo\xF0\x9F\x8F\x86", input->Value().Utf8());

  // "trophy" + "trophy".
  input->SetValue(String::FromUTF8("foo\xF0\x9F\x8F\x86\xF0\x9F\x8F\x86"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(7, 7));
  EXPECT_EQ("foo\xF0\x9F\x8F\x86\xF0\x9F\x8F\x86", input->Value().Utf8());
  Controller().DeleteSurroundingText(3, 0);
  EXPECT_EQ("foo\xED\xA0\xBC", input->Value().Utf8());

  // "trophy" + "trophy".
  input->SetValue(String::FromUTF8("foo\xF0\x9F\x8F\x86\xF0\x9F\x8F\x86"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(7, 7));
  EXPECT_EQ("foo\xF0\x9F\x8F\x86\xF0\x9F\x8F\x86", input->Value().Utf8());
  Controller().DeleteSurroundingText(4, 0);
  EXPECT_EQ("foo", input->Value());

  // "trophy" + "trophy".
  input->SetValue(String::FromUTF8("foo\xF0\x9F\x8F\x86\xF0\x9F\x8F\x86"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(7, 7));
  EXPECT_EQ("foo\xF0\x9F\x8F\x86\xF0\x9F\x8F\x86", input->Value().Utf8());
  Controller().DeleteSurroundingText(5, 0);
  EXPECT_EQ("fo", input->Value());
}

TEST_F(InputMethodControllerTest,
       DeleteSurroundingTextWithMultiCodeTextOnTheRight) {
  auto* input =
      To<HTMLInputElement>(InsertHTMLElement("<input id='sample'>", "sample"));

  // U+2605 == "black star". It takes up 1 space.
  input->SetValue(String::FromUTF8("\xE2\x98\x85 foo"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(0, 0));
  EXPECT_EQ("\xE2\x98\x85 foo", input->Value().Utf8());
  Controller().DeleteSurroundingText(0, 1);
  EXPECT_EQ(" foo", input->Value());

  // U+1F3C6 == "trophy". It takes up 2 space.
  input->SetValue(String::FromUTF8("\xF0\x9F\x8F\x86 foo"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(0, 0));
  EXPECT_EQ("\xF0\x9F\x8F\x86 foo", input->Value().Utf8());
  Controller().DeleteSurroundingText(0, 1);
  EXPECT_EQ("\xED\xBF\x86 foo", input->Value().Utf8());

  // composed U+0E01 "ka kai" + U+0E49 "mai tho". It takes up 2 space.
  input->SetValue(String::FromUTF8("\xE0\xB8\x81\xE0\xB9\x89 foo"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(0, 0));
  EXPECT_EQ("\xE0\xB8\x81\xE0\xB9\x89 foo", input->Value().Utf8());
  Controller().DeleteSurroundingText(0, 1);
  EXPECT_EQ("\xE0\xB9\x89 foo", input->Value().Utf8());

  // "trophy" + "trophy".
  input->SetValue(String::FromUTF8("\xF0\x9F\x8F\x86\xF0\x9F\x8F\x86 foo"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(0, 0));
  EXPECT_EQ("\xF0\x9F\x8F\x86\xF0\x9F\x8F\x86 foo", input->Value().Utf8());
  Controller().DeleteSurroundingText(0, 2);
  EXPECT_EQ("\xF0\x9F\x8F\x86 foo", input->Value().Utf8());

  // "trophy" + "trophy".
  input->SetValue(String::FromUTF8("\xF0\x9F\x8F\x86\xF0\x9F\x8F\x86 foo"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(0, 0));
  EXPECT_EQ("\xF0\x9F\x8F\x86\xF0\x9F\x8F\x86 foo", input->Value().Utf8());
  Controller().DeleteSurroundingText(0, 3);
  EXPECT_EQ("\xED\xBF\x86 foo", input->Value().Utf8());

  // "trophy" + "trophy".
  input->SetValue(String::FromUTF8("\xF0\x9F\x8F\x86\xF0\x9F\x8F\x86 foo"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(0, 0));
  EXPECT_EQ("\xF0\x9F\x8F\x86\xF0\x9F\x8F\x86 foo", input->Value().Utf8());
  Controller().DeleteSurroundingText(0, 4);
  EXPECT_EQ(" foo", input->Value());

  // "trophy" + "trophy".
  input->SetValue(String::FromUTF8("\xF0\x9F\x8F\x86\xF0\x9F\x8F\x86 foo"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(0, 0));
  EXPECT_EQ("\xF0\x9F\x8F\x86\xF0\x9F\x8F\x86 foo", input->Value().Utf8());
  Controller().DeleteSurroundingText(0, 5);
  EXPECT_EQ("foo", input->Value());
}

TEST_F(InputMethodControllerTest,
       DeleteSurroundingTextWithMultiCodeTextOnBothSides) {
  auto* input =
      To<HTMLInputElement>(InsertHTMLElement("<input id='sample'>", "sample"));

  // "trophy" + "trophy".
  input->SetValue(String::FromUTF8("\xF0\x9F\x8F\x86\xF0\x9F\x8F\x86"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(2, 2));
  EXPECT_EQ("\xF0\x9F\x8F\x86\xF0\x9F\x8F\x86", input->Value().Utf8());
  Controller().DeleteSurroundingText(1, 1);
  // Deleted second half of the first trophy and the first half of the second
  // trophy, so we ended up with a complete trophy.
  EXPECT_EQ("\xF0\x9F\x8F\x86", input->Value().Utf8());
}

// This test comes from http://crbug.com/1024738. It is basically the same to
// composed text (U+0E01 "ka kai" + U+0E49 "mai tho"), but easier to understand.
TEST_F(InputMethodControllerTest, DeleteSurroundingTextForComposedCharacter) {
  auto* input =
      To<HTMLInputElement>(InsertHTMLElement("<input id='sample'>", "sample"));
  // p̂p̂ (U+0070 U+0302 U+0070 U+0302)
  input->SetValue(String::FromUTF8("\x70\xCC\x82\x70\xCC\x82"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(4, 4));
  EXPECT_EQ("\x70\xCC\x82\x70\xCC\x82", input->Value().Utf8());
  Controller().DeleteSurroundingText(1, 0);
  EXPECT_EQ("\x70\xCC\x82\x70", input->Value().Utf8());
  Controller().DeleteSurroundingText(1, 0);
  EXPECT_EQ("\x70\xCC\x82", input->Value().Utf8());
}

TEST_F(InputMethodControllerTest, DeleteSurroundingTextForMultipleNodes) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>aaa"
      "<div id='sample2' contenteditable>bbb"
      "<div id='sample3' contenteditable>ccc"
      "<div id='sample4' contenteditable>ddd"
      "<div id='sample5' contenteditable>eee"
      "</div></div></div></div></div>",
      "sample");

  Controller().SetEditableSelectionOffsets(PlainTextRange(8, 8));
  EXPECT_EQ("aaa\nbbb\nccc\nddd\neee", div->innerText());
  EXPECT_EQ(8u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(8u, Controller().GetSelectionOffsets().End());

  Controller().DeleteSurroundingText(1, 0);
  EXPECT_EQ("aaa\nbbbccc\nddd\neee", div->innerText());
  EXPECT_EQ(7u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(7u, Controller().GetSelectionOffsets().End());

  Controller().DeleteSurroundingText(0, 4);
  EXPECT_EQ("aaa\nbbbddd\neee", div->innerText());
  EXPECT_EQ(7u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(7u, Controller().GetSelectionOffsets().End());

  Controller().DeleteSurroundingText(5, 5);
  EXPECT_EQ("aaee", div->innerText());
  EXPECT_EQ(2u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(2u, Controller().GetSelectionOffsets().End());
}

TEST_F(InputMethodControllerTest,
       DeleteSurroundingTextInCodePointsWithMultiCodeTextOnTheLeft) {
  auto* input =
      To<HTMLInputElement>(InsertHTMLElement("<input id='sample'>", "sample"));

  // 'a' + "black star" + SPACE + "trophy" + SPACE + composed text (U+0E01
  // "ka kai" + U+0E49 "mai tho").
  // A "black star" is 1 grapheme cluster. It has 1 code point, and its length
  // is 1 (abbreviated as [1,1,1]). A "trophy": [1,1,2]. The composed text:
  // [1,2,2].
  input->SetValue(String::FromUTF8(
      "a\xE2\x98\x85 \xF0\x9F\x8F\x86 \xE0\xB8\x81\xE0\xB9\x89"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  // The cursor is at the end of the text.
  Controller().SetEditableSelectionOffsets(PlainTextRange(8, 8));

  Controller().DeleteSurroundingTextInCodePoints(2, 0);
  EXPECT_EQ("a\xE2\x98\x85 \xF0\x9F\x8F\x86 ", input->Value().Utf8());
  Controller().DeleteSurroundingTextInCodePoints(4, 0);
  EXPECT_EQ("a", input->Value());

  // 'a' + "black star" + SPACE + "trophy" + SPACE + composed text
  input->SetValue(String::FromUTF8(
      "a\xE2\x98\x85 \xF0\x9F\x8F\x86 \xE0\xB8\x81\xE0\xB9\x89"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  // The cursor is at the end of the text.
  Controller().SetEditableSelectionOffsets(PlainTextRange(8, 8));

  // We should only delete 1 code point.
  Controller().DeleteSurroundingTextInCodePoints(1, 0);
  EXPECT_EQ("a\xE2\x98\x85 \xF0\x9F\x8F\x86 \xE0\xB8\x81",
            input->Value().Utf8());
}

TEST_F(InputMethodControllerTest,
       DeleteSurroundingTextInCodePointsWithMultiCodeTextOnTheRight) {
  auto* input =
      To<HTMLInputElement>(InsertHTMLElement("<input id='sample'>", "sample"));

  // 'a' + "black star" + SPACE + "trophy" + SPACE + composed text
  input->SetValue(String::FromUTF8(
      "a\xE2\x98\x85 \xF0\x9F\x8F\x86 \xE0\xB8\x81\xE0\xB9\x89"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(0, 0));

  Controller().DeleteSurroundingTextInCodePoints(0, 5);
  EXPECT_EQ("\xE0\xB8\x81\xE0\xB9\x89", input->Value().Utf8());

  Controller().DeleteSurroundingTextInCodePoints(0, 1);
  // We should only delete 1 code point.
  EXPECT_EQ("\xE0\xB9\x89", input->Value().Utf8());
}

TEST_F(InputMethodControllerTest,
       DeleteSurroundingTextInCodePointsWithMultiCodeTextOnBothSides) {
  auto* input =
      To<HTMLInputElement>(InsertHTMLElement("<input id='sample'>", "sample"));

  // 'a' + "black star" + SPACE + "trophy" + SPACE + composed text
  input->SetValue(String::FromUTF8(
      "a\xE2\x98\x85 \xF0\x9F\x8F\x86 \xE0\xB8\x81\xE0\xB9\x89"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(3, 3));
  Controller().DeleteSurroundingTextInCodePoints(2, 2);
  EXPECT_EQ("a\xE0\xB8\x81\xE0\xB9\x89", input->Value().Utf8());
}

TEST_F(InputMethodControllerTest, DeleteSurroundingTextInCodePointsWithImage) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>aaa"
      "<img src='empty.png'>bbb</div>",
      "sample");

  Controller().SetEditableSelectionOffsets(PlainTextRange(4, 4));
  Controller().DeleteSurroundingTextInCodePoints(1, 1);
  EXPECT_EQ("aaabb", div->innerText());
  EXPECT_EQ(3u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(3u, Controller().GetSelectionOffsets().End());
}

TEST_F(InputMethodControllerTest,
       DeleteSurroundingTextInCodePointsWithInvalidSurrogatePair) {
  auto* input =
      To<HTMLInputElement>(InsertHTMLElement("<input id='sample'>", "sample"));

  // 'a' + high surrogate of "trophy" + "black star" + low surrogate of "trophy"
  // + SPACE
  const UChar kUText[] = {'a', 0xD83C, 0x2605, 0xDFC6, ' ', '\0'};
  const String& text = String(kUText);

  input->SetValue(text);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  // The invalid high surrogate is encoded as '\xED\xA0\xBC', and invalid low
  // surrogate is encoded as '\xED\xBF\x86'.
  EXPECT_EQ("a\xED\xA0\xBC\xE2\x98\x85\xED\xBF\x86 ", input->Value().Utf8());

  Controller().SetEditableSelectionOffsets(PlainTextRange(5, 5));
  // Delete a SPACE.
  Controller().DeleteSurroundingTextInCodePoints(1, 0);
  EXPECT_EQ("a\xED\xA0\xBC\xE2\x98\x85\xED\xBF\x86", input->Value().Utf8());
  // Do nothing since there is an invalid surrogate in the requested range.
  Controller().DeleteSurroundingTextInCodePoints(2, 0);
  EXPECT_EQ("a\xED\xA0\xBC\xE2\x98\x85\xED\xBF\x86", input->Value().Utf8());

  Controller().SetEditableSelectionOffsets(PlainTextRange(0, 0));
  // Delete 'a'.
  Controller().DeleteSurroundingTextInCodePoints(0, 1);
  EXPECT_EQ("\xED\xA0\xBC\xE2\x98\x85\xED\xBF\x86", input->Value().Utf8());
  // Do nothing since there is an invalid surrogate in the requested range.
  Controller().DeleteSurroundingTextInCodePoints(0, 2);
  EXPECT_EQ("\xED\xA0\xBC\xE2\x98\x85\xED\xBF\x86", input->Value().Utf8());
}

TEST_F(InputMethodControllerTest, ReplaceTextAndDoNotChangeSelection) {
  auto* input =
      To<HTMLInputElement>(InsertHTMLElement("<input id='sample'>", "sample"));

  // The replaced range does not overlap with the selection range.
  input->SetValue("Hello world!");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("Hello world!", input->Value());
  // Select "world!".
  Controller().SetEditableSelectionOffsets(PlainTextRange(6, 12));
  // Replace "Hello" with "Hi".
  Controller().ReplaceTextAndMoveCaret(
      "Hi", PlainTextRange(0, 5),
      InputMethodController::MoveCaretBehavior::kDoNotMove);
  EXPECT_EQ("Hi world!", input->Value());
  // The selection is still "world!".
  EXPECT_EQ(3u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(9u, Controller().GetSelectionOffsets().End());

  // The replaced range is the same as the selection range.
  input->SetValue("Hello world!");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("Hello world!", input->Value());
  // Select "Hello".
  Controller().SetEditableSelectionOffsets(PlainTextRange(0, 5));
  // Replace "Hello" with "Hi".
  Controller().ReplaceTextAndMoveCaret(
      "Hi", PlainTextRange(0, 5),
      InputMethodController::MoveCaretBehavior::kDoNotMove);
  EXPECT_EQ("Hi world!", input->Value());

  // The new selection is "Hi".
  EXPECT_EQ(0u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(2u, Controller().GetSelectionOffsets().End());

  // The replaced range partially overlaps with the selection range.
  input->SetValue("Hello world!");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("Hello world!", input->Value());
  // Select "Hello".
  Controller().SetEditableSelectionOffsets(PlainTextRange(0, 5));
  // Replace "He" with "Hi".
  Controller().ReplaceTextAndMoveCaret(
      "Hi", PlainTextRange(0, 2),
      InputMethodController::MoveCaretBehavior::kDoNotMove);
  EXPECT_EQ("Hillo world!", input->Value());
  // The selection is still "Hillo".
  EXPECT_EQ(0u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(5u, Controller().GetSelectionOffsets().End());
}

TEST_F(InputMethodControllerTest,
       ReplaceTextAndMoveCursorAfterTheReplacementText) {
  auto* input =
      To<HTMLInputElement>(InsertHTMLElement("<input id='sample'>", "sample"));

  // The caret should always move to the end of the replacement text no matter
  // where the current selection is.

  input->SetValue("Good morning!");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("Good morning!", input->Value());
  // Select "Good".
  Controller().SetEditableSelectionOffsets(PlainTextRange(0, 4));
  // Replace "morning" with "night". The replaced range does not overlap with
  // the selection range.
  Controller().ReplaceTextAndMoveCaret(
      "night", PlainTextRange(5, 12),
      InputMethodController::MoveCaretBehavior::kMoveCaretAfterText);
  EXPECT_EQ("Good night!", input->Value());
  // The caret should be after "night".
  EXPECT_EQ(10u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(10u, Controller().GetSelectionOffsets().End());

  input->SetValue("Good morning!");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("Good morning!", input->Value());
  // Select "morning".
  Controller().SetEditableSelectionOffsets(PlainTextRange(5, 12));
  // Replace "morning" with "night". The replaced range is the same as the
  // selection range.
  Controller().ReplaceTextAndMoveCaret(
      "night", PlainTextRange(5, 12),
      InputMethodController::MoveCaretBehavior::kMoveCaretAfterText);
  EXPECT_EQ("Good night!", input->Value());
  // The caret should be after "night".
  EXPECT_EQ(10u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(10u, Controller().GetSelectionOffsets().End());

  input->SetValue("Good morning!");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("Good morning!", input->Value());
  // Select "d mo".
  Controller().SetEditableSelectionOffsets(PlainTextRange(3, 7));
  // Replace "morning" with "night". The replaced range partially overlaps with
  // the selection range.
  Controller().ReplaceTextAndMoveCaret(
      "night", PlainTextRange(5, 12),
      InputMethodController::MoveCaretBehavior::kMoveCaretAfterText);
  EXPECT_EQ("Good night!", input->Value());
  // The caret should be after "night".
  EXPECT_EQ(10u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(10u, Controller().GetSelectionOffsets().End());
}

TEST_F(InputMethodControllerTest, SetCompositionForInputWithNewCaretPositions) {
  auto* input =
      To<HTMLInputElement>(InsertHTMLElement("<input id='sample'>", "sample"));

  input->SetValue("hello");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(2, 2));
  EXPECT_EQ("hello", input->Value());
  EXPECT_EQ(2u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(2u, Controller().GetSelectionOffsets().End());

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 2, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));

  // The caret exceeds left boundary.
  // "*heABllo", where * stands for caret.
  Controller().SetComposition("AB", ime_text_spans, -100, -100);
  EXPECT_EQ("heABllo", input->Value());
  EXPECT_EQ(0u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(0u, Controller().GetSelectionOffsets().End());

  // The caret is on left boundary.
  // "*heABllo".
  Controller().SetComposition("AB", ime_text_spans, -2, -2);
  EXPECT_EQ("heABllo", input->Value());
  EXPECT_EQ(0u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(0u, Controller().GetSelectionOffsets().End());

  // The caret is before the composing text.
  // "he*ABllo".
  Controller().SetComposition("AB", ime_text_spans, 0, 0);
  EXPECT_EQ("heABllo", input->Value());
  EXPECT_EQ(2u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(2u, Controller().GetSelectionOffsets().End());

  // The caret is after the composing text.
  // "heAB*llo".
  Controller().SetComposition("AB", ime_text_spans, 2, 2);
  EXPECT_EQ("heABllo", input->Value());
  EXPECT_EQ(4u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(4u, Controller().GetSelectionOffsets().End());

  // The caret is on right boundary.
  // "heABllo*".
  Controller().SetComposition("AB", ime_text_spans, 5, 5);
  EXPECT_EQ("heABllo", input->Value());
  EXPECT_EQ(7u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(7u, Controller().GetSelectionOffsets().End());

  // The caret exceeds right boundary.
  // "heABllo*".
  Controller().SetComposition("AB", ime_text_spans, 100, 100);
  EXPECT_EQ("heABllo", input->Value());
  EXPECT_EQ(7u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(7u, Controller().GetSelectionOffsets().End());
}

TEST_F(InputMethodControllerTest,
       SetCompositionForContentEditableWithNewCaretPositions) {
  // There are 7 nodes and 5+1+5+1+3+4+3 characters: "hello", '\n', "world",
  // "\n", "012", "3456", "789".
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>"
      "hello"
      "<div id='sample2' contenteditable>world"
      "<p>012<b>3456</b><i>789</i></p>"
      "</div>"
      "</div>",
      "sample");

  Controller().SetEditableSelectionOffsets(PlainTextRange(17, 17));
  EXPECT_EQ("hello\nworld\n\n0123456789", div->innerText());
  EXPECT_EQ(17u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(17u, Controller().GetSelectionOffsets().End());

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 2, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));

  // The caret exceeds left boundary.
  // "*hello\nworld\n\n01234AB56789", where * stands for caret.
  Controller().SetComposition("AB", ime_text_spans, -100, -100);
  EXPECT_EQ("hello\nworld\n\n01234AB56789", div->innerText());
  EXPECT_EQ(0u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(0u, Controller().GetSelectionOffsets().End());

  // The caret is on left boundary.
  // "*hello\nworld\n\n01234AB56789".
  Controller().SetComposition("AB", ime_text_spans, -17, -17);
  EXPECT_EQ("hello\nworld\n\n01234AB56789", div->innerText());
  EXPECT_EQ(0u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(0u, Controller().GetSelectionOffsets().End());

  // The caret is in the 1st node.
  // "he*llo\nworld\n\n01234AB56789".
  Controller().SetComposition("AB", ime_text_spans, -15, -15);
  EXPECT_EQ("hello\nworld\n\n01234AB56789", div->innerText());
  EXPECT_EQ(2u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(2u, Controller().GetSelectionOffsets().End());

  // The caret is on right boundary of the 1st node.
  // "hello*\nworld\n\n01234AB56789".
  Controller().SetComposition("AB", ime_text_spans, -12, -12);
  EXPECT_EQ("hello\nworld\n\n01234AB56789", div->innerText());
  EXPECT_EQ(5u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(5u, Controller().GetSelectionOffsets().End());

  // The caret is on right boundary of the 2nd node.
  // "hello\n*world\n\n01234AB56789".
  Controller().SetComposition("AB", ime_text_spans, -11, -11);
  EXPECT_EQ("hello\nworld\n\n01234AB56789", div->innerText());
  EXPECT_EQ(6u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(6u, Controller().GetSelectionOffsets().End());

  // The caret is on right boundary of the 3rd node.
  // "hello\nworld*\n01234AB56789".
  Controller().SetComposition("AB", ime_text_spans, -6, -6);
  EXPECT_EQ("hello\nworld\n\n01234AB56789", div->innerText());
  EXPECT_EQ(11u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(11u, Controller().GetSelectionOffsets().End());

  // The caret is on right boundary of the 4th node.
  // "hello\nworld\n*01234AB56789".
  Controller().SetComposition("AB", ime_text_spans, -5, -5);
  EXPECT_EQ("hello\nworld\n\n01234AB56789", div->innerText());
  EXPECT_EQ(12u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(12u, Controller().GetSelectionOffsets().End());

  // The caret is before the composing text.
  // "hello\nworld\n\n01234*AB56789".
  Controller().SetComposition("AB", ime_text_spans, 0, 0);
  EXPECT_EQ("hello\nworld\n\n01234AB56789", div->innerText());
  EXPECT_EQ(17u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(17u, Controller().GetSelectionOffsets().End());

  // The caret is after the composing text.
  // "hello\nworld\n\n01234AB*56789".
  Controller().SetComposition("AB", ime_text_spans, 2, 2);
  EXPECT_EQ("hello\nworld\n\n01234AB56789", div->innerText());
  EXPECT_EQ(19u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(19u, Controller().GetSelectionOffsets().End());

  // The caret is on right boundary.
  // "hello\nworld\n\n01234AB56789*".
  Controller().SetComposition("AB", ime_text_spans, 7, 7);
  EXPECT_EQ("hello\nworld\n\n01234AB56789", div->innerText());
  EXPECT_EQ(24u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(24u, Controller().GetSelectionOffsets().End());

  // The caret exceeds right boundary.
  // "hello\nworld\n\n01234AB56789*".
  Controller().SetComposition("AB", ime_text_spans, 100, 100);
  EXPECT_EQ("hello\nworld\n\n01234AB56789", div->innerText());
  EXPECT_EQ(24u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(24u, Controller().GetSelectionOffsets().End());
}

TEST_F(InputMethodControllerTest, SetCompositionWithEmptyText) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>hello</div>", "sample");

  Controller().SetEditableSelectionOffsets(PlainTextRange(2, 2));
  EXPECT_EQ("hello", div->innerText());
  EXPECT_EQ(2u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(2u, Controller().GetSelectionOffsets().End());

  Vector<ImeTextSpan> ime_text_spans0;
  ime_text_spans0.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 0, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  Vector<ImeTextSpan> ime_text_spans2;
  ime_text_spans2.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 2, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));

  Controller().SetComposition("AB", ime_text_spans2, 2, 2);
  // With previous composition.
  Controller().SetComposition("", ime_text_spans0, 2, 2);
  EXPECT_EQ("hello", div->innerText());
  EXPECT_EQ(4u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(4u, Controller().GetSelectionOffsets().End());

  // Without previous composition.
  Controller().SetComposition("", ime_text_spans0, -1, -1);
  EXPECT_EQ("hello", div->innerText());
  EXPECT_EQ(3u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(3u, Controller().GetSelectionOffsets().End());
}

TEST_F(InputMethodControllerTest, InsertLineBreakWhileComposingText) {
  Element* div =
      InsertHTMLElement("<div id='sample' contenteditable></div>", "sample");

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 5, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  Controller().SetComposition("hello", ime_text_spans, 5, 5);
  EXPECT_EQ("hello", div->innerText());
  EXPECT_EQ(5u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(5u, Controller().GetSelectionOffsets().End());

  GetFrame().GetEditor().InsertLineBreak();
  EXPECT_EQ("hello\n\n", div->innerText());
  EXPECT_EQ(6u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(6u, Controller().GetSelectionOffsets().End());
}

TEST_F(InputMethodControllerTest, InsertLineBreakAfterConfirmingText) {
  Element* div =
      InsertHTMLElement("<div id='sample' contenteditable></div>", "sample");

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 2, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  Controller().CommitText("hello", ime_text_spans, 0);
  EXPECT_EQ("hello", div->innerText());

  Controller().SetEditableSelectionOffsets(PlainTextRange(2, 2));
  EXPECT_EQ(2u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(2u, Controller().GetSelectionOffsets().End());

  GetFrame().GetEditor().InsertLineBreak();
  EXPECT_EQ("he\nllo", div->innerText());
  EXPECT_EQ(3u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(3u, Controller().GetSelectionOffsets().End());
}

TEST_F(InputMethodControllerTest, CompositionInputEventIsComposing) {
  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* editable =
      InsertHTMLElement("<div id='sample' contenteditable></div>", "sample");
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      "document.getElementById('sample').addEventListener('beforeinput', "
      "  event => document.title = "
      "  `beforeinput.isComposing:${event.isComposing};`);"
      "document.getElementById('sample').addEventListener('input', "
      "  event => document.title += "
      "  `input.isComposing:${event.isComposing};`);");
  GetDocument().body()->AppendChild(script);
  UpdateAllLifecyclePhasesForTest();

  // Simulate composition in the |contentEditable|.
  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 5, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  editable->Focus();

  GetDocument().setTitle(g_empty_string);
  Controller().SetComposition("foo", ime_text_spans, 0, 3);
  EXPECT_EQ("beforeinput.isComposing:true;input.isComposing:true;",
            GetDocument().title());

  GetDocument().setTitle(g_empty_string);
  Controller().CommitText("bar", ime_text_spans, 0);
  // Last pair of InputEvent should also be inside composition scope.
  EXPECT_EQ("beforeinput.isComposing:true;input.isComposing:true;",
            GetDocument().title());
}

TEST_F(InputMethodControllerTest, CompositionInputEventForReplace) {
  CreateHTMLWithCompositionInputEventListeners();

  // Simulate composition in the |contentEditable|.
  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 5, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));

  GetDocument().setTitle(g_empty_string);
  Controller().SetComposition("hell", ime_text_spans, 4, 4);
  EXPECT_EQ(
      "beforeinput.data:hell;beforeinput.targetRanges:0-0;input.data:hell;",
      GetDocument().title());

  // Replace the existing composition.
  GetDocument().setTitle(g_empty_string);
  Controller().SetComposition("hello", ime_text_spans, 0, 0);
  EXPECT_EQ(
      "beforeinput.data:hello;beforeinput.targetRanges:0-4;input.data:hello;",
      GetDocument().title());
}

TEST_F(InputMethodControllerTest, CompositionInputEventForConfirm) {
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

  // Confirm the ongoing composition.
  GetDocument().setTitle(g_empty_string);
  Controller().FinishComposingText(InputMethodController::kKeepSelection);
  EXPECT_
"""


```