Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a test file (`web_view_test.cc`) within the Chromium Blink engine.

I need to identify the key features being tested in this snippet and explain their relation to web technologies like JavaScript, HTML, and CSS if applicable.

For each test case, I will analyze the setup, actions, and assertions to understand what is being validated. I should also consider potential user errors, debugging steps, and any logical reasoning implied by the tests.

**Plan:**

1. Identify the main test fixture: `WebViewTest`.
2. Analyze each `TEST_F` function individually.
3. For each test:
    *   Determine the functionality being tested.
    *   Check for relationships with JavaScript, HTML, or CSS.
    *   If there's logical reasoning, identify assumptions and expected outcomes.
    *   Consider common user/programming errors.
    *   Outline how a user might reach this code path.
4. Synthesize a concise summary of the overall functionality.
这是 `blink/renderer/core/exported/web_view_test.cc` 文件的一部分，主要测试了 `WebInputMethodController` 的相关功能，特别是关于文本输入和编辑的各种场景。

**功能归纳：**

这部分代码主要测试了 `WebInputMethodController` 在以下方面的功能：

*   **`CommitText` (提交文本):** 测试在不同情况下，如何提交文本并更新光标位置。这包括在没有 composition 的情况下直接提交，以及在有 composition 的情况下提交文本。
*   **`FinishComposingText` (结束输入法组合):** 测试结束输入法组合时，是否会影响滚动位置，以确保不会因为结束输入法组合而意外滚动到输入框。
*   **`InsertNewLinePlacementAfterFinishComposingText` (在结束输入法组合后插入新行):** 测试在结束输入法组合后插入新行的行为，验证光标和文本的正确位置。
*   **`ExtendSelectionAndDelete` (扩展选择并删除):** 测试如何扩展选区并删除选中的文本。
*   **`DeleteSurroundingText` (删除周围文本):** 测试如何删除光标周围指定范围的文本。
*   **`SetCompositionFromExistingText` (从现有文本设置输入法组合):** 测试如何从已有的文本中设置输入法组合，并验证输入法组合的起始和结束位置。
*   **`SetEditableSelectionOffsetsKeepsComposition` (设置可编辑选区偏移时保留输入法组合):** 测试在设置新的选区偏移时，是否会保留当前的输入法组合状态。
*   **`IsSelectionAnchorFirst` (选区锚点是否在前):** 测试选区的锚点和焦点是否正确。
*   **`MoveFocusToNextFocusableElementForImeAndAutofillWithKeyEventListenersAndNonEditableElements` 和 `MoveFocusToNextFocusableElementForImeAndAutofillWithNonEditableNonFormControlElements` (移动焦点到下一个可聚焦元素):** 测试在复杂的表单结构中，如何通过输入法和自动填充功能移动焦点到下一个可聚焦元素，并考虑了键盘事件监听器和不可编辑元素的影响。

**与 JavaScript, HTML, CSS 的关系：**

这些测试都直接或间接地与用户在网页上与 HTML 表单元素进行交互有关。

*   **HTML:** 测试涉及到各种 HTML 元素，如 `<input>`, `<textarea>`, `contenteditable` 属性的元素，以及 `<button>` 等。测试会加载特定的 HTML 文件，模拟用户在这些元素上的输入行为。
    *   **举例:** `RegisterMockedHttpURLLoad("input_field_populated.html");` 这行代码表明测试依赖于一个包含 `<input>` 元素的 HTML 文件。
*   **JavaScript:** 虽然这段 C++ 代码本身不直接包含 JavaScript，但它测试的功能是 Web 浏览器处理用户输入的基础，而用户的输入行为往往会触发 JavaScript 事件监听器。例如，`MoveFocusToNextFocusableElementForImeAndAutofillWithKeyEventListenersAndNonEditableElements` 测试就考虑了键盘事件监听器的影响。
    *   **举例:** 测试中提到的 "key event listeners" 指的是在 JavaScript 中注册的监听键盘事件 (如 `keydown`, `keyup`) 的函数。
*   **CSS:** CSS 影响着网页元素的样式和布局，但在这个特定的测试文件中，CSS 的影响是间接的。例如，元素的滚动位置可能受到 CSS 样式的影响，而 `FinishCompositionDoesNotRevealSelection` 测试就关注了滚动位置。

**逻辑推理、假设输入与输出：**

以下是一些测试中蕴含的逻辑推理和假设输入输出的例子：

*   **`CommitText` 测试:**
    *   **假设输入:**  在一个空的 `<input>` 框中，依次提交文本 "abc" 和 "de"。
    *   **预期输出:** `<input>` 框的值为 "abcde"，光标在最后。
    *   **假设输入:** 在 `<input>` 框中已有文本 "abcdefghi"，光标在中间，提交 "jk"。
    *   **预期输出:** `<input>` 框的值为 "abcdefghijkl"，光标在最后。
*   **`CommitTextWhileComposing` 测试:**
    *   **假设输入:**  在 `<input>` 框中输入 "abc" 进入输入法组合状态，然后提交 "hello"，光标偏移为 -2。
    *   **预期输出:** 输入法组合被删除，插入 "hello"，光标向前移动两位。
*   **`FinishCompositionDoesNotRevealSelection` 测试:**
    *   **假设输入:** 在一个有文本的 `<input>` 框中，选中部分文本并开始输入法组合。然后滚动页面使输入框不可见。
    *   **预期输出:** 结束输入法组合后，页面不会滚动回输入框的位置。
*   **`MoveFocusToNextFocusableElementForImeAndAutofill...` 测试:**
    *   **假设输入:**  焦点位于表单中的第一个输入框。
    *   **预期输出:** 调用 `AdvanceFocusForIME(kForward)` 后，焦点会移动到表单中下一个可聚焦的元素。

**用户或编程常见的使用错误：**

*   **`CommitText` 光标位置错误:**  开发者可能错误地计算了光标偏移量，导致提交文本后光标位置不正确。测试用例验证了各种光标偏移的情况，帮助开发者避免这类错误。
*   **输入法状态管理错误:**  不正确地处理输入法组合状态可能导致文本输入混乱。例如，在有输入法组合时直接提交文本可能会产生意想不到的结果。`CommitTextWhileComposing` 测试就覆盖了这类场景。
*   **焦点管理错误:** 在复杂的表单中，如果焦点管理不当，用户可能会无法按照预期进行导航。`MoveFocusToNextFocusableElementForImeAndAutofill...` 测试旨在确保焦点在各种情况下都能正确移动。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户打开一个包含表单的网页。**
2. **用户点击表单中的一个可编辑元素 (如 `<input>` 或 `<textarea>`)，使该元素获得焦点。**
3. **用户开始通过键盘输入文本。**
4. **如果用户使用了输入法，那么在最终确认之前，会进入输入法组合状态。**  `SetComposition` 和 `FinishComposingText` 等方法就与这个状态相关。
5. **用户可能会使用方向键或鼠标来改变光标位置或选择文本。** `SetEditableSelectionOffsets` 和 `ExtendSelectionAndDelete` 等方法模拟了这些操作。
6. **用户可能会使用快捷键或输入法提供的功能来删除文本。** `DeleteSurroundingText` 模拟了删除操作。
7. **在某些情况下，浏览器可能需要自动将焦点移动到下一个可编辑元素 (例如，在输入法完成输入后)。** `MoveFocusToNextFocusableElementForImeAndAutofill...` 测试覆盖了这种情况。

作为调试线索，如果用户报告了输入法行为异常、光标位置错误、焦点跳转不正确等问题，开发者可以参考这些测试用例，理解 Blink 引擎是如何处理这些操作的，并检查相关的代码逻辑。

这部分测试主要关注 `WebInputMethodController` 的核心文本编辑功能，确保了在各种用户输入和编辑场景下，文本内容、光标位置和输入法状态的正确性。这些测试对于保证 Web 应用程序的文本输入体验至关重要。

### 提示词
```
这是目录为blink/renderer/core/exported/web_view_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
o.selection_end);
  EXPECT_EQ(-1, info.composition_start);
  EXPECT_EQ(-1, info.composition_end);

  // Caret exceeds the right boundary.
  active_input_method_controller->CommitText("jk", empty_ime_text_spans,
                                             WebRange(), 100);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("jkgcadefbhi", info.value.Utf8());
  EXPECT_EQ(11, info.selection_start);
  EXPECT_EQ(11, info.selection_end);
  EXPECT_EQ(-1, info.composition_start);
  EXPECT_EQ(-1, info.composition_end);
}

TEST_F(WebViewTest, CommitTextWhileComposing) {
  RegisterMockedHttpURLLoad("input_field_populated.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "input_field_populated.html");
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  WebInputMethodController* active_input_method_controller =
      web_view->MainFrameImpl()
          ->FrameWidget()
          ->GetActiveWebInputMethodController();

  WebVector<ui::ImeTextSpan> empty_ime_text_spans;
  active_input_method_controller->SetComposition(
      WebString::FromUTF8("abc"), empty_ime_text_spans, WebRange(), 0, 0);
  WebTextInputInfo info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("abc", info.value.Utf8());
  EXPECT_EQ(0, info.selection_start);
  EXPECT_EQ(0, info.selection_end);
  EXPECT_EQ(0, info.composition_start);
  EXPECT_EQ(3, info.composition_end);

  // Deletes ongoing composition, inserts the specified text and moves the
  // caret.
  active_input_method_controller->CommitText("hello", empty_ime_text_spans,
                                             WebRange(), -2);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("hello", info.value.Utf8());
  EXPECT_EQ(3, info.selection_start);
  EXPECT_EQ(3, info.selection_end);
  EXPECT_EQ(-1, info.composition_start);
  EXPECT_EQ(-1, info.composition_end);

  active_input_method_controller->SetComposition(
      WebString::FromUTF8("abc"), empty_ime_text_spans, WebRange(), 0, 0);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("helabclo", info.value.Utf8());
  EXPECT_EQ(3, info.selection_start);
  EXPECT_EQ(3, info.selection_end);
  EXPECT_EQ(3, info.composition_start);
  EXPECT_EQ(6, info.composition_end);

  // Deletes ongoing composition and moves the caret.
  active_input_method_controller->CommitText("", empty_ime_text_spans,
                                             WebRange(), 2);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("hello", info.value.Utf8());
  EXPECT_EQ(5, info.selection_start);
  EXPECT_EQ(5, info.selection_end);
  EXPECT_EQ(-1, info.composition_start);
  EXPECT_EQ(-1, info.composition_end);

  // Inserts the specified text and moves the caret.
  active_input_method_controller->CommitText("world", empty_ime_text_spans,
                                             WebRange(), -5);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("helloworld", info.value.Utf8());
  EXPECT_EQ(5, info.selection_start);
  EXPECT_EQ(5, info.selection_end);
  EXPECT_EQ(-1, info.composition_start);
  EXPECT_EQ(-1, info.composition_end);

  // Only moves the caret.
  active_input_method_controller->CommitText("", empty_ime_text_spans,
                                             WebRange(), 5);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("helloworld", info.value.Utf8());
  EXPECT_EQ(10, info.selection_start);
  EXPECT_EQ(10, info.selection_end);
  EXPECT_EQ(-1, info.composition_start);
  EXPECT_EQ(-1, info.composition_end);
}

TEST_F(WebViewTest, FinishCompositionDoesNotRevealSelection) {
  RegisterMockedHttpURLLoad("form_with_input.html");
  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + "form_with_input.html");
  web_view->MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  EXPECT_EQ(gfx::PointF(), web_view->MainFrameImpl()->GetScrollOffset());

  // Set up a composition from existing text that needs to be committed.
  Vector<ImeTextSpan> empty_ime_text_spans;
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  frame->GetFrame()->GetInputMethodController().SetCompositionFromExistingText(
      empty_ime_text_spans, 0, 3);

  // Scroll the input field out of the viewport.
  Element* element = static_cast<Element*>(
      web_view->MainFrameImpl()->GetDocument().GetElementById("btn"));
  element->scrollIntoView();
  float offset_height = web_view->MainFrameImpl()->GetScrollOffset().y();
  EXPECT_EQ(0, web_view->MainFrameImpl()->GetScrollOffset().x());
  EXPECT_LT(0, offset_height);

  WebTextInputInfo info = frame->GetInputMethodController()->TextInputInfo();
  EXPECT_EQ("hello", info.value.Utf8());

  // Verify that the input field is not scrolled back into the viewport.
  frame->FrameWidget()
      ->GetActiveWebInputMethodController()
      ->FinishComposingText(WebInputMethodController::kDoNotKeepSelection);
  EXPECT_EQ(0, web_view->MainFrameImpl()->GetScrollOffset().x());
  EXPECT_EQ(offset_height, web_view->MainFrameImpl()->GetScrollOffset().y());
}

TEST_F(WebViewTest, InsertNewLinePlacementAfterFinishComposingText) {
  RegisterMockedHttpURLLoad("text_area_populated.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "text_area_populated.html");
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);

  WebVector<ui::ImeTextSpan> empty_ime_text_spans;

  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  WebInputMethodController* active_input_method_controller =
      frame->GetInputMethodController();
  frame->SetEditableSelectionOffsets(4, 4);
  frame->SetCompositionFromExistingText(8, 12, empty_ime_text_spans);

  WebTextInputInfo info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("0123456789abcdefghijklmnopqrstuvwxyz", info.value.Utf8());
  EXPECT_EQ(4, info.selection_start);
  EXPECT_EQ(4, info.selection_end);
  EXPECT_EQ(8, info.composition_start);
  EXPECT_EQ(12, info.composition_end);

  active_input_method_controller->FinishComposingText(
      WebInputMethodController::kKeepSelection);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ(4, info.selection_start);
  EXPECT_EQ(4, info.selection_end);
  EXPECT_EQ(-1, info.composition_start);
  EXPECT_EQ(-1, info.composition_end);

  std::string composition_text("\n");
  active_input_method_controller->CommitText(
      WebString::FromUTF8(composition_text), empty_ime_text_spans, WebRange(),
      0);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ(5, info.selection_start);
  EXPECT_EQ(5, info.selection_end);
  EXPECT_EQ(-1, info.composition_start);
  EXPECT_EQ(-1, info.composition_end);
  EXPECT_EQ("0123\n456789abcdefghijklmnopqrstuvwxyz", info.value.Utf8());
}

TEST_F(WebViewTest, ExtendSelectionAndDelete) {
  RegisterMockedHttpURLLoad("input_field_populated.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "input_field_populated.html");
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  frame->SetEditableSelectionOffsets(10, 10);
  frame->ExtendSelectionAndDelete(5, 8);
  WebInputMethodController* active_input_method_controller =
      frame->GetInputMethodController();
  WebTextInputInfo info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("01234ijklmnopqrstuvwxyz", info.value.Utf8());
  EXPECT_EQ(5, info.selection_start);
  EXPECT_EQ(5, info.selection_end);
  frame->ExtendSelectionAndDelete(10, 0);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("ijklmnopqrstuvwxyz", info.value.Utf8());
}

TEST_F(WebViewTest, EditContextExtendSelectionAndDelete) {
  RegisterMockedHttpURLLoad("edit_context.html");
  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + "edit_context.html");
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  frame->SetEditableSelectionOffsets(10, 10);
  frame->ExtendSelectionAndDelete(5, 8);
  WebInputMethodController* active_input_method_controller =
      frame->GetInputMethodController();
  WebTextInputInfo info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("01234ijklmnopqrstuvwxyz", info.value.Utf8());
  EXPECT_EQ(5, info.selection_start);
  EXPECT_EQ(5, info.selection_end);
  frame->ExtendSelectionAndDelete(10, 0);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("ijklmnopqrstuvwxyz", info.value.Utf8());
}

TEST_F(WebViewTest, DeleteSurroundingText) {
  RegisterMockedHttpURLLoad("input_field_populated.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "input_field_populated.html");
  auto* frame = To<WebLocalFrameImpl>(web_view->MainFrame());
  WebInputMethodController* active_input_method_controller =
      frame->GetInputMethodController();
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);

  frame->SetEditableSelectionOffsets(10, 10);
  frame->DeleteSurroundingText(5, 8);
  WebTextInputInfo info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("01234ijklmnopqrstuvwxyz", info.value.Utf8());
  EXPECT_EQ(5, info.selection_start);
  EXPECT_EQ(5, info.selection_end);

  frame->SetEditableSelectionOffsets(5, 10);
  frame->DeleteSurroundingText(3, 5);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("01ijklmstuvwxyz", info.value.Utf8());
  EXPECT_EQ(2, info.selection_start);
  EXPECT_EQ(7, info.selection_end);

  frame->SetEditableSelectionOffsets(5, 5);
  frame->DeleteSurroundingText(10, 0);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("lmstuvwxyz", info.value.Utf8());
  EXPECT_EQ(0, info.selection_start);
  EXPECT_EQ(0, info.selection_end);

  frame->DeleteSurroundingText(0, 20);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("", info.value.Utf8());
  EXPECT_EQ(0, info.selection_start);
  EXPECT_EQ(0, info.selection_end);

  frame->DeleteSurroundingText(10, 10);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("", info.value.Utf8());
  EXPECT_EQ(0, info.selection_start);
  EXPECT_EQ(0, info.selection_end);
}

TEST_F(WebViewTest, SetCompositionFromExistingText) {
  RegisterMockedHttpURLLoad("input_field_populated.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "input_field_populated.html");
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  WebVector<ui::ImeTextSpan> ime_text_spans(static_cast<size_t>(1));
  ime_text_spans[0] =
      ui::ImeTextSpan(ui::ImeTextSpan::Type::kComposition, 0, 4,
                      ui::ImeTextSpan::Thickness::kThin,
                      ui::ImeTextSpan::UnderlineStyle::kSolid, 0, 0);
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  WebInputMethodController* active_input_method_controller =
      frame->GetInputMethodController();
  frame->SetEditableSelectionOffsets(4, 10);
  frame->SetCompositionFromExistingText(8, 12, ime_text_spans);
  WebTextInputInfo info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ(4, info.selection_start);
  EXPECT_EQ(10, info.selection_end);
  EXPECT_EQ(8, info.composition_start);
  EXPECT_EQ(12, info.composition_end);
  WebVector<ui::ImeTextSpan> empty_ime_text_spans;
  frame->SetCompositionFromExistingText(0, 0, empty_ime_text_spans);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ(4, info.selection_start);
  EXPECT_EQ(10, info.selection_end);
  EXPECT_EQ(-1, info.composition_start);
  EXPECT_EQ(-1, info.composition_end);
}

TEST_F(WebViewTest, SetCompositionFromExistingTextInTextArea) {
  RegisterMockedHttpURLLoad("text_area_populated.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "text_area_populated.html");
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  WebVector<ui::ImeTextSpan> ime_text_spans(static_cast<size_t>(1));
  ime_text_spans[0] =
      ui::ImeTextSpan(ui::ImeTextSpan::Type::kComposition, 0, 4,
                      ui::ImeTextSpan::Thickness::kThin,
                      ui::ImeTextSpan::UnderlineStyle::kSolid, 0, 0);
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  WebInputMethodController* active_input_method_controller =
      frame->FrameWidget()->GetActiveWebInputMethodController();
  frame->SetEditableSelectionOffsets(27, 27);
  std::string new_line_text("\n");
  WebVector<ui::ImeTextSpan> empty_ime_text_spans;
  active_input_method_controller->CommitText(
      WebString::FromUTF8(new_line_text), empty_ime_text_spans, WebRange(), 0);
  WebTextInputInfo info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("0123456789abcdefghijklmnopq\nrstuvwxyz", info.value.Utf8());

  frame->SetEditableSelectionOffsets(31, 31);
  frame->SetCompositionFromExistingText(30, 34, ime_text_spans);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("0123456789abcdefghijklmnopq\nrstuvwxyz", info.value.Utf8());
  EXPECT_EQ(31, info.selection_start);
  EXPECT_EQ(31, info.selection_end);
  EXPECT_EQ(30, info.composition_start);
  EXPECT_EQ(34, info.composition_end);

  std::string composition_text("yolo");
  active_input_method_controller->CommitText(
      WebString::FromUTF8(composition_text), empty_ime_text_spans, WebRange(),
      0);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("0123456789abcdefghijklmnopq\nrsyoloxyz", info.value.Utf8());
  EXPECT_EQ(34, info.selection_start);
  EXPECT_EQ(34, info.selection_end);
  EXPECT_EQ(-1, info.composition_start);
  EXPECT_EQ(-1, info.composition_end);
}

TEST_F(WebViewTest, SetCompositionFromExistingTextInRichText) {
  RegisterMockedHttpURLLoad("content_editable_rich_text.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "content_editable_rich_text.html");
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  WebVector<ui::ImeTextSpan> ime_text_spans(static_cast<size_t>(1));
  ime_text_spans[0] =
      ui::ImeTextSpan(ui::ImeTextSpan::Type::kComposition, 0, 4,
                      ui::ImeTextSpan::Thickness::kThin,
                      ui::ImeTextSpan::UnderlineStyle::kSolid, 0, 0);
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  frame->SetEditableSelectionOffsets(1, 1);
  WebDocument document = web_view->MainFrameImpl()->GetDocument();
  EXPECT_FALSE(document.GetElementById("bold").IsNull());
  frame->SetCompositionFromExistingText(0, 4, ime_text_spans);
  EXPECT_FALSE(document.GetElementById("bold").IsNull());
}

TEST_F(WebViewTest, SetEditableSelectionOffsetsKeepsComposition) {
  RegisterMockedHttpURLLoad("input_field_populated.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "input_field_populated.html");
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);

  std::string composition_text_first("hello ");
  std::string composition_text_second("world");
  WebVector<ui::ImeTextSpan> empty_ime_text_spans;
  WebInputMethodController* active_input_method_controller =
      web_view->MainFrameImpl()
          ->FrameWidget()
          ->GetActiveWebInputMethodController();
  active_input_method_controller->CommitText(
      WebString::FromUTF8(composition_text_first), empty_ime_text_spans,
      WebRange(), 0);
  active_input_method_controller->SetComposition(
      WebString::FromUTF8(composition_text_second), empty_ime_text_spans,
      WebRange(), 5, 5);

  WebTextInputInfo info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("hello world", info.value.Utf8());
  EXPECT_EQ(11, info.selection_start);
  EXPECT_EQ(11, info.selection_end);
  EXPECT_EQ(6, info.composition_start);
  EXPECT_EQ(11, info.composition_end);

  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  frame->SetEditableSelectionOffsets(6, 6);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("hello world", info.value.Utf8());
  EXPECT_EQ(6, info.selection_start);
  EXPECT_EQ(6, info.selection_end);
  EXPECT_EQ(6, info.composition_start);
  EXPECT_EQ(11, info.composition_end);

  frame->SetEditableSelectionOffsets(8, 8);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("hello world", info.value.Utf8());
  EXPECT_EQ(8, info.selection_start);
  EXPECT_EQ(8, info.selection_end);
  EXPECT_EQ(6, info.composition_start);
  EXPECT_EQ(11, info.composition_end);

  frame->SetEditableSelectionOffsets(11, 11);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("hello world", info.value.Utf8());
  EXPECT_EQ(11, info.selection_start);
  EXPECT_EQ(11, info.selection_end);
  EXPECT_EQ(6, info.composition_start);
  EXPECT_EQ(11, info.composition_end);

  frame->SetEditableSelectionOffsets(6, 11);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("hello world", info.value.Utf8());
  EXPECT_EQ(6, info.selection_start);
  EXPECT_EQ(11, info.selection_end);
  EXPECT_EQ(6, info.composition_start);
  EXPECT_EQ(11, info.composition_end);

  frame->SetEditableSelectionOffsets(2, 2);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("hello world", info.value.Utf8());
  EXPECT_EQ(2, info.selection_start);
  EXPECT_EQ(2, info.selection_end);
  // Composition range should be reset by browser process or keyboard apps.
  EXPECT_EQ(6, info.composition_start);
  EXPECT_EQ(11, info.composition_end);
}

TEST_F(WebViewTest, IsSelectionAnchorFirst) {
  // TODO(xidachen): crbug.com/1150389, Make this test work with the feature.
  if (RuntimeEnabledFeatures::FractionalScrollOffsetsEnabled())
    return;
  RegisterMockedHttpURLLoad("input_field_populated.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "input_field_populated.html");
  WebLocalFrame* frame = web_view->MainFrameImpl();

  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  frame->SetEditableSelectionOffsets(4, 10);
  EXPECT_TRUE(frame->IsSelectionAnchorFirst());
  gfx::Rect anchor;
  gfx::Rect focus;
  web_view->MainFrameViewWidget()->CalculateSelectionBounds(anchor, focus);
  frame->SelectRange(focus.origin(), anchor.origin());
  EXPECT_FALSE(frame->IsSelectionAnchorFirst());
}

TEST_F(
    WebViewTest,
    MoveFocusToNextFocusableElementForImeAndAutofillWithKeyEventListenersAndNonEditableElements) {
  const std::string test_file =
      "advance_focus_in_form_with_key_event_listeners.html";
  RegisterMockedHttpURLLoad(test_file);
  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + test_file);
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  Document* document = web_view->MainFrameImpl()->GetFrame()->GetDocument();
  WebInputMethodController* active_input_method_controller =
      web_view->MainFrameImpl()
          ->FrameWidget()
          ->GetActiveWebInputMethodController();
  const int default_text_input_flags = kWebTextInputFlagNone;

  struct FocusedElement {
    AtomicString element_id;
    int next_previous_flags;
  } focused_elements[] = {
      {AtomicString("input1"),
       default_text_input_flags | kWebTextInputFlagHaveNextFocusableElement},
      {AtomicString("contenteditable1"),
       kWebTextInputFlagHaveNextFocusableElement |
           kWebTextInputFlagHavePreviousFocusableElement},
      {AtomicString("input2"),
       default_text_input_flags | kWebTextInputFlagHaveNextFocusableElement |
           kWebTextInputFlagHavePreviousFocusableElement},
      {AtomicString("textarea1"),
       default_text_input_flags | kWebTextInputFlagHaveNextFocusableElement |
           kWebTextInputFlagHavePreviousFocusableElement},
      {AtomicString("input3"),
       default_text_input_flags | kWebTextInputFlagHaveNextFocusableElement |
           kWebTextInputFlagHavePreviousFocusableElement},
      {AtomicString("textarea2"),
       default_text_input_flags |
           kWebTextInputFlagHavePreviousFocusableElement},
  };

  // Forward Navigation in form1 with NEXT
  Element* input1 = document->getElementById(AtomicString("input1"));
  input1->Focus();
  Element* current_focus = nullptr;
  Element* next_focus = nullptr;
  int next_previous_flags;
  for (size_t i = 0; i < std::size(focused_elements); ++i) {
    current_focus = document->getElementById(focused_elements[i].element_id);
    EXPECT_EQ(current_focus, document->FocusedElement());
    next_previous_flags =
        active_input_method_controller->ComputeWebTextInputNextPreviousFlags();
    EXPECT_EQ(focused_elements[i].next_previous_flags, next_previous_flags);
    next_focus = document->GetPage()
                     ->GetFocusController()
                     .NextFocusableElementForImeAndAutofill(
                         current_focus, mojom::blink::FocusType::kForward);
    if (next_focus) {
      EXPECT_EQ(next_focus->GetIdAttribute(),
                focused_elements[i + 1].element_id);
    }
    web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
        mojom::blink::FocusType::kForward);
  }
  // Now focus will stay on previous focus itself, because it has no next
  // element.
  EXPECT_EQ(current_focus, document->FocusedElement());

  // Backward Navigation in form1 with PREVIOUS
  for (size_t i = std::size(focused_elements); i-- > 0;) {
    current_focus = document->getElementById(focused_elements[i].element_id);
    EXPECT_EQ(current_focus, document->FocusedElement());
    next_previous_flags =
        active_input_method_controller->ComputeWebTextInputNextPreviousFlags();
    EXPECT_EQ(focused_elements[i].next_previous_flags, next_previous_flags);
    next_focus = document->GetPage()
                     ->GetFocusController()
                     .NextFocusableElementForImeAndAutofill(
                         current_focus, mojom::blink::FocusType::kBackward);
    if (next_focus) {
      EXPECT_EQ(next_focus->GetIdAttribute(),
                focused_elements[i - 1].element_id);
    }
    web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
        mojom::blink::FocusType::kBackward);
  }
  // Now focus will stay on previous focus itself, because it has no previous
  // element.
  EXPECT_EQ(current_focus, document->FocusedElement());

  // Setting a non editable element as focus in form1, and ensuring editable
  // navigation is fine in forward and backward.
  Element* button1 = document->getElementById(AtomicString("button1"));
  button1->Focus();
  next_previous_flags =
      active_input_method_controller->ComputeWebTextInputNextPreviousFlags();
  EXPECT_EQ(kWebTextInputFlagHaveNextFocusableElement |
                kWebTextInputFlagHavePreviousFocusableElement,
            next_previous_flags);
  next_focus = document->GetPage()
                   ->GetFocusController()
                   .NextFocusableElementForImeAndAutofill(
                       button1, mojom::blink::FocusType::kForward);
  EXPECT_EQ(next_focus->GetIdAttribute(), "contenteditable1");
  web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
      mojom::blink::FocusType::kForward);
  Element* content_editable1 =
      document->getElementById(AtomicString("contenteditable1"));
  EXPECT_EQ(content_editable1, document->FocusedElement());
  button1->Focus();
  next_focus = document->GetPage()
                   ->GetFocusController()
                   .NextFocusableElementForImeAndAutofill(
                       button1, mojom::blink::FocusType::kBackward);
  EXPECT_EQ(next_focus->GetIdAttribute(), "input1");
  web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
      mojom::blink::FocusType::kBackward);
  EXPECT_EQ(input1, document->FocusedElement());

  Element* anchor1 = document->getElementById(AtomicString("anchor1"));
  anchor1->Focus();
  next_previous_flags =
      active_input_method_controller->ComputeWebTextInputNextPreviousFlags();
  // No Next/Previous element for elements outside form.
  EXPECT_EQ(0, next_previous_flags);
  next_focus = document->GetPage()
                   ->GetFocusController()
                   .NextFocusableElementForImeAndAutofill(
                       anchor1, mojom::blink::FocusType::kForward);
  EXPECT_EQ(next_focus, nullptr);
  web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
      mojom::blink::FocusType::kForward);
  // Since anchor is not a form control element, next/previous element will
  // be null, hence focus will stay same as it is.
  EXPECT_EQ(anchor1, document->FocusedElement());

  next_focus = document->GetPage()
                   ->GetFocusController()
                   .NextFocusableElementForImeAndAutofill(
                       anchor1, mojom::blink::FocusType::kBackward);
  EXPECT_EQ(next_focus, nullptr);
  web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
      mojom::blink::FocusType::kBackward);
  EXPECT_EQ(anchor1, document->FocusedElement());

  // Navigation of elements which are not a part of any forms. All these
  // elements compose a <form>less form.
  Element* text_area3 = document->getElementById(AtomicString("textarea3"));
  text_area3->Focus();
  next_previous_flags =
      active_input_method_controller->ComputeWebTextInputNextPreviousFlags();
  // Next/Previous elements for an element outside of a form are other
  // <form>less elements.
  EXPECT_EQ(kWebTextInputFlagHaveNextFocusableElement, next_previous_flags);
  next_focus = document->GetPage()
                   ->GetFocusController()
                   .NextFocusableElementForImeAndAutofill(
                       text_area3, mojom::blink::FocusType::kForward);
  Element* text_area4 = document->getElementById(AtomicString("textarea4"));
  Element* content_editable2 =
      document->getElementById(AtomicString("contenteditable2"));
  EXPECT_EQ(next_focus, content_editable2);
  web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
      mojom::blink::FocusType::kForward);
  EXPECT_EQ(content_editable2, document->FocusedElement());
  // No previous element to this <form>less element because there is no other
  // formless element before. Hence focus won't change wrt PREVIOUS.
  next_focus = document->GetPage()
                   ->GetFocusController()
                   .NextFocusableElementForImeAndAutofill(
                       text_area3, mojom::blink::FocusType::kBackward);
  EXPECT_EQ(next_focus, nullptr);
  web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
      mojom::blink::FocusType::kBackward);
  EXPECT_EQ(text_area3, document->FocusedElement());

  // Navigation from an element which is part of a form but not an editable
  // element.
  Element* button2 = document->getElementById(AtomicString("button2"));
  button2->Focus();
  next_previous_flags =
      active_input_method_controller->ComputeWebTextInputNextPreviousFlags();
  // No Next element for this element, due to last element outside the form.
  EXPECT_EQ(kWebTextInputFlagHavePreviousFocusableElement, next_previous_flags);
  next_focus = document->GetPage()
                   ->GetFocusController()
                   .NextFocusableElementForImeAndAutofill(
                       button2, mojom::blink::FocusType::kForward);
  EXPECT_EQ(next_focus, nullptr);
  web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
      mojom::blink::FocusType::kForward);
  // No Next element to this element within form1. Hence focus won't change wrt
  // NEXT.
  EXPECT_EQ(button2, document->FocusedElement());
  Element* text_area2 = document->getElementById(AtomicString("textarea2"));
  next_focus = document->GetPage()
                   ->GetFocusController()
                   .NextFocusableElementForImeAndAutofill(
                       button2, mojom::blink::FocusType::kBackward);
  EXPECT_EQ(next_focus, text_area2);
  web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
      mojom::blink::FocusType::kBackward);
  // Since button is a form control element from form1, ensuring focus is set
  // at correct position.
  EXPECT_EQ(text_area2, document->FocusedElement());

  document->SetFocusedElement(
      content_editable2, FocusParams(SelectionBehaviorOnFocus::kNone,
                                     mojom::blink::FocusType::kNone, nullptr));
  next_previous_flags =
      active_input_method_controller->ComputeWebTextInputNextPreviousFlags();
  // Next/Previous elements for an element outside of a form are other
  // <form>less elements before and after that element.
  EXPECT_EQ(kWebTextInputFlagHaveNextFocusableElement |
                kWebTextInputFlagHavePreviousFocusableElement,
            next_previous_flags);
  next_focus = document->GetPage()
                   ->GetFocusController()
                   .NextFocusableElementForImeAndAutofill(
                       content_editable2, mojom::blink::FocusType::kForward);
  EXPECT_EQ(next_focus, text_area4);
  web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
      mojom::blink::FocusType::kForward);
  EXPECT_EQ(text_area4, document->FocusedElement());
  next_focus = document->GetPage()
                   ->GetFocusController()
                   .NextFocusableElementForImeAndAutofill(
                       content_editable2, mojom::blink::FocusType::kBackward);
  document->SetFocusedElement(
      content_editable2, FocusParams(SelectionBehaviorOnFocus::kNone,
                                     mojom::blink::FocusType::kNone, nullptr));
  EXPECT_EQ(next_focus, text_area3);
  web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
      mojom::blink::FocusType::kBackward);
  EXPECT_EQ(text_area3, document->FocusedElement());

  // Navigation of elements which is having invalid form attribute and hence
  // is a part of the <form>less form.
  text_area4->Focus();
  next_previous_flags =
      active_input_method_controller->ComputeWebTextInputNextPreviousFlags();
  // No next element for an element outside of a form because it is the last
  // <form>less element.
  EXPECT_EQ(kWebTextInputFlagHavePreviousFocusableElement, next_previous_flags);
  next_focus = document->GetPage()
                   ->GetFocusController()
                   .NextFocusableElementForImeAndAutofill(
                       text_area4, mojom::blink::FocusType::kForward);
  EXPECT_EQ(next_focus, nullptr);
  web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
      mojom::blink::FocusType::kForward);
  // No next element. Hence focus won't change wrt NEXT.
  EXPECT_EQ(text_area4, document->FocusedElement());
  next_focus = document->GetPage()
                   ->GetFocusController()
                   .NextFocusableElementForImeAndAutofill(
                       text_area4, mojom::blink::FocusType::kBackward);
  // The previous element of a formless element is the previous formless
  // element.
  EXPECT_EQ(next_focus, content_editable2);
  web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
      mojom::blink::FocusType::kBackward);
  EXPECT_EQ(content_editable2, document->FocusedElement());

  web_view_helper_.Reset();
}

TEST_F(
    WebViewTest,
    MoveFocusToNextFocusableElementForImeAndAutofillWithNonEditableNonFormControlElements) {
  const std::string test_file =
      "advance_focus_in_form_with_key_event_listeners.html";
  RegisterMockedHttpURLLoad(test_file);
  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + test_file);
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  Document* document = web_view->MainFrameImpl()->GetFrame()->GetDocument();
  WebInputMethodController* active_input_method_controller =
      web_view->MainFrameImpl()
          ->FrameWidget()
          ->GetActiveWebInputMethodController();
  const int default_text_input_flags = kWebTextInputFlagNone;

  struct FocusedElement {
    const char* element_id;
    int next_previous_flags;
  } focused_elements[] = {
      {"textarea5",
       default_text_input_flags | kWebTextInputFlagHaveNextFocusableElement},
      {"input4", default_text_input_flags |
                     kWebTextInputFlagHaveNextFocusableElement |
                     kWebTextInputFlagHavePreviousFocusableElement},
      {"contenteditable3", kWebTextInputFlagHaveNextFocusableElement |
                               kWebTextInputFlagHavePreviousFocusableElement},
      {"input5", kWebTextInputFlagHavePreviousFocusableElement},
  };

  // Forward Navigation in form2 with NEXT
  Element* text_area5 = document->getElementById(AtomicString("textarea5"));
  text_area5->Focus();
  Element* current_focus = nullptr;
  Element* next_focus = nullptr;
  int next_previous_flags;
  for (size_t i = 0; i < std::size(focused_elements); ++i) {
    current_focus =
        document->getElementById(AtomicString(focused_e
```