Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is a part of the Chromium Blink engine. The code is a test file for `InputMethodController`. I need to identify the core functionalities being tested, whether these relate to JavaScript, HTML, or CSS, provide examples, detail any logical reasoning, point out common user errors, explain how a user might reach this code through interaction, and finally, give a general summary of the code's purpose within the larger context.

**Plan:**

1. **Identify Key Functionality:**  The tests primarily focus on how `InputMethodController` interacts with `DocumentMarker`s during text input and manipulation, specifically during IME composition and commit operations.
2. **Relate to Web Technologies:**  IME input is directly related to how users enter text, which is a fundamental part of HTML forms and editable content. JavaScript can trigger IME actions or manipulate content where IME is involved. CSS can style the visual representation of IME compositions or markers, although this test file doesn't directly test CSS.
3. **Provide Examples:** For each type of test (marker deletion, insertion, etc.), explain the scenario with a simple HTML example and the corresponding `InputMethodController` actions.
4. **Logical Reasoning (Input/Output):** For tests involving marker updates, describe the initial marker state and how it changes after an IME action.
5. **User Errors:** Consider common user actions that might trigger issues related to IME and markers.
6. **User Journey (Debugging):**  Describe the steps a user might take to arrive at a state where these tests would be relevant.
7. **Summarize Functionality:**  Provide a concise overview of what the code tests.
这是`blink/renderer/core/editing/ime/input_method_controller_test.cc`文件的第4部分，它主要关注以下功能：

**核心功能：测试 `InputMethodController` 对 `DocumentMarker` 的管理，尤其是在文本删除和插入操作中。**

这部分测试验证了 `InputMethodController` 在处理以下情况时，如何正确地更新和删除 `DocumentMarker`：

* **删除操作:**
    * 删除操作覆盖部分或全部的 `ContentDependentMarker` (例如 `TextMatchMarker`) 和 `ContentIndependentMarker` (例如 `ActiveSuggestionMarker`)。
    * 删除操作精确地覆盖整个 marker。
    * 删除操作在 marker 的内部。
* **插入操作:**
    * 在 marker 的内部插入文本。
    * 在两个 marker 之间插入文本。

**与 JavaScript, HTML, CSS 的关系：**

虽然此文件是 C++ 代码，但它测试的功能与用户在网页上的交互密切相关，这些交互通常涉及 JavaScript 和 HTML：

* **HTML:**  测试用例中使用了 `contenteditable` 属性的 `div` 元素和 `input` 元素，模拟用户在可编辑区域进行输入。 `DocumentMarker` 通常用于在这些可编辑区域中高亮显示文本（例如拼写错误、搜索匹配、输入法候选词等）。
    * **举例 (HTML):**  `<div id='sample' contenteditable>这是一个可以编辑的区域</div>`。用户在这个区域进行输入时，`InputMethodController` 会处理输入法事件并可能创建或修改 `DocumentMarker`。
* **JavaScript:** JavaScript 可以通过编程方式触发文本插入或删除操作，这些操作也会触发 `InputMethodController` 的逻辑，从而影响 `DocumentMarker` 的状态。 另外，`input` 事件监听器可以修改文本内容和选区，本部分代码也有测试用例覆盖了这种情况。
    * **举例 (JavaScript):**  `document.getElementById('sample').textContent = '新的文本';` 这样的 JavaScript 代码会改变 HTML 内容，`InputMethodController` 需要相应地更新 `DocumentMarker` 的位置。
* **CSS:** 虽然这个测试文件不直接涉及 CSS 的测试，但 `DocumentMarker` 的视觉呈现（例如下划线颜色、样式等）可以通过 CSS 来控制。`InputMethodController` 负责管理 marker 的创建和位置，而 CSS 负责其外观。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. 一个 `contenteditable` 的 `div` 元素包含文本 "1111122222333334444455555"。
2. 定义了多个 `DocumentMarker`，例如从偏移 0 到 5，5 到 10，等等。
3. 用户通过 IME 输入法选中了从偏移 8 到 17 的文本，并执行了删除操作。

**逻辑推理:**

*   `InputMethodController` 的 `SetCompositionFromExistingText` 方法会被调用，标记从 8 到 17 的文本为待删除状态。
*   `CommitText` 方法被调用，实际执行删除操作。
*   `InputMethodController` 会根据删除的文本范围，更新或删除受影响的 `DocumentMarker`。

**输出 (以 `ContentDependentMarker_Deletions` 测试为例):**

*   初始有 5 个 `TextMatchMarker`。
*   删除偏移 8 到 17 的文本后，原来偏移 5-10 的 marker 会变为 5-8，原来偏移 10-15 的 marker 会被删除，原来偏移 15-20 的 marker 会变为 11-16。
*   最终剩下 2 个 marker，范围分别是 0-5 和 11-16。

**用户或编程常见的使用错误:**

* **用户错误：** 在输入法激活时，不小心按了删除键，导致部分候选词或已输入的文本被删除，而相关的 marker 没有正确更新，导致显示异常。
* **编程错误：** 在使用 JavaScript 操作 DOM 时，直接修改文本内容而没有通知 `InputMethodController`，可能导致 marker 的位置和范围与实际文本不符。
    * **举例：** 使用 `element.innerHTML = '...'` 替换文本内容，而不是通过 `document.execCommand('insertText', false, '...')` 或类似的 API 进行文本操作，可能会导致 marker 管理出现问题。

**用户操作到达这里的步骤 (调试线索):**

1. **用户在一个启用了 IME 输入法的操作系统上打开一个网页。**
2. **网页中包含一个 `contenteditable` 的元素或一个 `input` / `textarea` 元素。**
3. **用户点击该可编辑区域，激活输入法。**
4. **用户开始使用输入法输入文本，例如输入拼音，选择候选词。** 在这个过程中，IME 会与浏览器进行通信，`InputMethodController` 负责处理这些事件，并可能创建临时的 composition marker 和 suggestion marker。
5. **用户可能在输入过程中进行删除操作 (backspace, delete)。**
6. **用户最终提交 (commit) 输入的文本。**
7. 在这些操作的每一步，`InputMethodController` 都会根据用户的输入和操作，更新 `DocumentMarker` 的状态和位置。 如果在这个过程中出现了 bug，例如 marker 没有被正确删除或更新，那么开发人员可能会通过调试 `blink/renderer/core/editing/ime/input_method_controller_test.cc` 中的相关测试用例来定位问题。

**功能归纳 (第4部分):**

这部分测试主要验证了 `blink::InputMethodController` 在处理文本删除和插入操作时，如何正确地维护和更新 `blink::DocumentMarker` 的状态。 这些测试覆盖了不同类型的 marker (content-dependent 和 content-independent) 以及不同的删除和插入场景（部分覆盖、完全覆盖、内部操作、边界操作）。  其目的是确保在用户进行文本编辑时，与输入法相关的标记（例如拼写错误、建议、搜索匹配等）能够保持与实际文本内容的一致性。

### 提示词
```
这是目录为blink/renderer/core/editing/ime/input_method_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
::kInactive);

  marker_range = PlainTextRange(5, 10).CreateRange(*div);
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  marker_range = PlainTextRange(10, 15).CreateRange(*div);
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  marker_range = PlainTextRange(15, 20).CreateRange(*div);
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  marker_range = PlainTextRange(20, 25).CreateRange(*div);
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  EXPECT_EQ(5u, GetDocument().Markers().Markers().size());

  // Delete third marker and portions of second and fourth
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 8, 17);
  Controller().CommitText(String(""), empty_ime_text_spans, 0);

  // Verify markers were updated correctly
  EXPECT_EQ(2u, GetDocument().Markers().Markers().size());

  EXPECT_EQ(0u, GetDocument().Markers().Markers()[0]->StartOffset());
  EXPECT_EQ(5u, GetDocument().Markers().Markers()[0]->EndOffset());

  EXPECT_EQ(11u, GetDocument().Markers().Markers()[1]->StartOffset());
  EXPECT_EQ(16u, GetDocument().Markers().Markers()[1]->EndOffset());
}

TEST_F(InputMethodControllerTest, ContentIndependentMarker_Deletions) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>1111122222333334444455555</div>",
      "sample");

  EphemeralRange marker_range = PlainTextRange(0, 5).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kBlack, Color::kBlack);

  marker_range = PlainTextRange(5, 10).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kBlack, Color::kBlack);

  marker_range = PlainTextRange(10, 15).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kBlack, Color::kBlack);

  marker_range = PlainTextRange(15, 20).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kBlack, Color::kBlack);

  marker_range = PlainTextRange(20, 25).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kBlack, Color::kBlack);

  EXPECT_EQ(5u, GetDocument().Markers().Markers().size());

  // Delete third marker and portions of second and fourth
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 8, 17);
  Controller().CommitText(String(""), empty_ime_text_spans, 0);

  // Verify markers were updated correctly
  EXPECT_EQ(4u, GetDocument().Markers().Markers().size());

  EXPECT_EQ(0u, GetDocument().Markers().Markers()[0]->StartOffset());
  EXPECT_EQ(5u, GetDocument().Markers().Markers()[0]->EndOffset());

  EXPECT_EQ(5u, GetDocument().Markers().Markers()[1]->StartOffset());
  EXPECT_EQ(8u, GetDocument().Markers().Markers()[1]->EndOffset());

  EXPECT_EQ(8u, GetDocument().Markers().Markers()[2]->StartOffset());
  EXPECT_EQ(11u, GetDocument().Markers().Markers()[2]->EndOffset());

  EXPECT_EQ(11u, GetDocument().Markers().Markers()[3]->StartOffset());
  EXPECT_EQ(16u, GetDocument().Markers().Markers()[3]->EndOffset());
}

TEST_F(InputMethodControllerTest,
       ContentDependentMarker_DeleteExactlyOnMarker) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>1111122222333334444455555</div>",
      "sample");

  EphemeralRange marker_range = PlainTextRange(5, 10).CreateRange(*div);
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  // Delete exactly on the marker
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 5, 10);
  Controller().CommitText(String(""), empty_ime_text_spans, 0);
  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());
}

TEST_F(InputMethodControllerTest,
       ContentIndependentMarker_DeleteExactlyOnMarker) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>1111122222333334444455555</div>",
      "sample");

  EphemeralRange marker_range = PlainTextRange(5, 10).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kTransparent, Color::kBlack);

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  // Delete exactly on the marker
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 5, 10);
  Controller().CommitText(String(""), empty_ime_text_spans, 0);
  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());
}

TEST_F(InputMethodControllerTest, ContentDependentMarker_DeleteMiddleOfMarker) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>1111122222333334444455555</div>",
      "sample");

  EphemeralRange marker_range = PlainTextRange(5, 10).CreateRange(*div);
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  // Delete middle of marker
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 6, 9);
  Controller().CommitText(String(""), empty_ime_text_spans, 0);

  // Verify marker was removed
  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());
}

TEST_F(InputMethodControllerTest,
       ContentIndependentMarker_DeleteMiddleOfMarker) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>1111122222333334444455555</div>",
      "sample");

  EphemeralRange marker_range = PlainTextRange(5, 10).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kTransparent, Color::kBlack);

  // Delete middle of marker
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetCompositionFromExistingText(empty_ime_text_spans, 6, 9);
  Controller().CommitText(String(""), empty_ime_text_spans, 0);

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  EXPECT_EQ(5u, GetDocument().Markers().Markers()[0]->StartOffset());
  EXPECT_EQ(7u, GetDocument().Markers().Markers()[0]->EndOffset());
}

TEST_F(InputMethodControllerTest,
       ContentDependentMarker_InsertInMarkerInterior) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>1111122222333334444455555</div>",
      "sample");

  EphemeralRange marker_range = PlainTextRange(0, 5).CreateRange(*div);
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  marker_range = PlainTextRange(5, 10).CreateRange(*div);
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  marker_range = PlainTextRange(10, 15).CreateRange(*div);
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  EXPECT_EQ(3u, GetDocument().Markers().Markers().size());

  // insert in middle of second marker
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetComposition("", empty_ime_text_spans, 7, 7);
  Controller().CommitText(String("66666"), empty_ime_text_spans, -7);

  EXPECT_EQ(2u, GetDocument().Markers().Markers().size());

  EXPECT_EQ(0u, GetDocument().Markers().Markers()[0]->StartOffset());
  EXPECT_EQ(5u, GetDocument().Markers().Markers()[0]->EndOffset());

  EXPECT_EQ(15u, GetDocument().Markers().Markers()[1]->StartOffset());
  EXPECT_EQ(20u, GetDocument().Markers().Markers()[1]->EndOffset());
}

TEST_F(InputMethodControllerTest,
       ContentIndependentMarker_InsertInMarkerInterior) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>1111122222333334444455555</div>",
      "sample");

  EphemeralRange marker_range = PlainTextRange(0, 5).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kTransparent, Color::kBlack);

  marker_range = PlainTextRange(5, 10).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kTransparent, Color::kBlack);

  marker_range = PlainTextRange(10, 15).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kTransparent, Color::kBlack);

  EXPECT_EQ(3u, GetDocument().Markers().Markers().size());

  // insert in middle of second marker
  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetComposition("", empty_ime_text_spans, 7, 7);
  Controller().CommitText(String("66666"), empty_ime_text_spans, -7);

  EXPECT_EQ(3u, GetDocument().Markers().Markers().size());

  EXPECT_EQ(0u, GetDocument().Markers().Markers()[0]->StartOffset());
  EXPECT_EQ(5u, GetDocument().Markers().Markers()[0]->EndOffset());

  EXPECT_EQ(5u, GetDocument().Markers().Markers()[1]->StartOffset());
  EXPECT_EQ(15u, GetDocument().Markers().Markers()[1]->EndOffset());

  EXPECT_EQ(15u, GetDocument().Markers().Markers()[2]->StartOffset());
  EXPECT_EQ(20u, GetDocument().Markers().Markers()[2]->EndOffset());
}

TEST_F(InputMethodControllerTest, ContentDependentMarker_InsertBetweenMarkers) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>1111122222333334444455555</div>",
      "sample");

  EphemeralRange marker_range = PlainTextRange(0, 5).CreateRange(*div);
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  marker_range = PlainTextRange(5, 15).CreateRange(*div);
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  marker_range = PlainTextRange(15, 20).CreateRange(*div);
  GetDocument().Markers().AddTextMatchMarker(
      marker_range, TextMatchMarker::MatchStatus::kInactive);

  EXPECT_EQ(3u, GetDocument().Markers().Markers().size());

  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetComposition("", empty_ime_text_spans, 5, 5);
  Controller().CommitText(String("77777"), empty_ime_text_spans, 0);

  EXPECT_EQ(3u, GetDocument().Markers().Markers().size());

  EXPECT_EQ(0u, GetDocument().Markers().Markers()[0]->StartOffset());
  EXPECT_EQ(5u, GetDocument().Markers().Markers()[0]->EndOffset());

  EXPECT_EQ(10u, GetDocument().Markers().Markers()[1]->StartOffset());
  EXPECT_EQ(20u, GetDocument().Markers().Markers()[1]->EndOffset());

  EXPECT_EQ(20u, GetDocument().Markers().Markers()[2]->StartOffset());
  EXPECT_EQ(25u, GetDocument().Markers().Markers()[2]->EndOffset());
}

TEST_F(InputMethodControllerTest,
       ContentIndependentMarker_InsertBetweenMarkers) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>1111122222333334444455555</div>",
      "sample");

  EphemeralRange marker_range = PlainTextRange(0, 5).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kTransparent, Color::kBlack);

  marker_range = PlainTextRange(5, 15).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kTransparent, Color::kBlack);

  marker_range = PlainTextRange(15, 20).CreateRange(*div);
  GetDocument().Markers().AddActiveSuggestionMarker(
      marker_range, Color::kBlack, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kTransparent, Color::kBlack);

  EXPECT_EQ(3u, GetDocument().Markers().Markers().size());

  Vector<ImeTextSpan> empty_ime_text_spans;
  Controller().SetComposition("", empty_ime_text_spans, 5, 5);
  Controller().CommitText(String("77777"), empty_ime_text_spans, 0);

  EXPECT_EQ(3u, GetDocument().Markers().Markers().size());

  EXPECT_EQ(0u, GetDocument().Markers().Markers()[0]->StartOffset());
  EXPECT_EQ(5u, GetDocument().Markers().Markers()[0]->EndOffset());

  EXPECT_EQ(10u, GetDocument().Markers().Markers()[1]->StartOffset());
  EXPECT_EQ(20u, GetDocument().Markers().Markers()[1]->EndOffset());

  EXPECT_EQ(20u, GetDocument().Markers().Markers()[2]->StartOffset());
  EXPECT_EQ(25u, GetDocument().Markers().Markers()[2]->EndOffset());
}

TEST_F(InputMethodControllerTest,
       CommitNotMisspellingSuggestionMarkerWithSpellCheckingDisabled) {
  InsertHTMLElement(
      "<div id='sample' contenteditable spellcheck='false'>text</div>",
      "sample");

  Vector<ImeTextSpan> ime_text_spans;
  // Try to commit a non-misspelling suggestion marker.
  ime_text_spans.push_back(
      ImeTextSpan(ImeTextSpan::Type::kSuggestion, 0, 5, Color::kTransparent,
                  ImeTextSpanThickness::kNone, ImeTextSpanUnderlineStyle::kNone,
                  Color::kTransparent, Color::kTransparent));
  Controller().CommitText("hello", ime_text_spans, 1);

  // The marker should have been added.
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
}

TEST_F(InputMethodControllerTest,
       CommitMisspellingSuggestionMarkerWithSpellCheckingDisabled) {
  InsertHTMLElement(
      "<div id='sample' contenteditable spellcheck='false'>text</div>",
      "sample");

  Vector<ImeTextSpan> ime_text_spans;
  // Try to commit a non-misspelling suggestion marker.
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kMisspellingSuggestion, 0, 5, Color::kTransparent,
      ImeTextSpanThickness::kNone, ImeTextSpanUnderlineStyle::kNone,
      Color::kTransparent, Color::kTransparent));
  Controller().CommitText("hello", ime_text_spans, 1);

  // The marker should not have been added since the div has spell checking
  // disabled.
  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());
}

TEST_F(InputMethodControllerTest, RemoveSuggestionMarkerInRangeOnFinish) {
  InsertHTMLElement(
      "<div id='sample' contenteditable spellcheck='true'>text</div>",
      "sample");

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kMisspellingSuggestion, 0, 5, Color::kTransparent,
      ImeTextSpanThickness::kNone, ImeTextSpanUnderlineStyle::kNone,
      Color::kTransparent, Color::kTransparent, Color ::kTransparent,
      /* remove_on_finish_composing */ true));

  // Case 1: SetComposition() -> FinishComposingText() removes the suggestion
  // marker when remove_on_finish_composing is true.
  Controller().SetComposition("hello", ime_text_spans, 0, 5);
  ASSERT_EQ(1u, GetDocument().Markers().Markers().size());
  ASSERT_TRUE(
      Controller().FinishComposingText(InputMethodController::kKeepSelection));

  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());

  // Case 2: SetComposition() -> CommitText() removes the suggestion marker when
  // remove_on_finish_composing is true.
  Controller().SetComposition("hello", ime_text_spans, 0, 5);
  ASSERT_EQ(1u, GetDocument().Markers().Markers().size());
  ASSERT_TRUE(Controller().CommitText("world", Vector<ImeTextSpan>(), 1));

  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());

  // Case 3: SetComposition() -> SetComposingText() removes the suggestion
  // marker when remove_on_finish_composing is true.
  Controller().SetComposition("hello", ime_text_spans, 0, 5);
  ASSERT_EQ(1u, GetDocument().Markers().Markers().size());
  Controller().SetComposition("helloworld", Vector<ImeTextSpan>(), 0, 10);

  // SetComposing() will add a composition marker.
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
  EXPECT_EQ(DocumentMarker::MarkerType::kComposition,
            GetDocument().Markers().Markers()[0]->GetType());
}

TEST_F(InputMethodControllerTest, ClearImeTextSpansByType) {
  InsertHTMLElement(
      "<div id='sample' contenteditable spellcheck='true'>hello</div>",
      "sample");
  ImeTextSpan::Type type = ImeTextSpan::Type::kAutocorrect;
  unsigned start = 0;
  unsigned end = 1;
  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      type, start, end, Color::kTransparent, ImeTextSpanThickness::kNone,
      ImeTextSpanUnderlineStyle::kNone, Color::kTransparent,
      Color::kTransparent, Color ::kTransparent));

  Controller().AddImeTextSpansToExistingText(ime_text_spans, start, end);
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  Controller().ClearImeTextSpansByType(type, start, end);
  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());
}

// For http://crbug.com/712761
TEST_F(InputMethodControllerTest, TextInputTypeAtBeforeEditable) {
  GetDocument().body()->setContentEditable("true", ASSERT_NO_EXCEPTION);
  GetDocument().body()->Focus();

  // Set selection before BODY(editable).
  GetFrame().Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .Collapse(Position(GetDocument().documentElement(), 0))
          .Build(),
      SetSelectionOptions());

  EXPECT_EQ(kWebTextInputTypeContentEditable, Controller().TextInputType());
}

// http://crbug.com/721666
TEST_F(InputMethodControllerTest, MaxLength) {
  auto* input = To<HTMLInputElement>(
      InsertHTMLElement("<input id='a' maxlength='4'/>", "a"));

  EXPECT_EQ(kWebTextInputTypeText, Controller().TextInputType());

  Controller().SetComposition("abcde", Vector<ImeTextSpan>(), 4, 4);
  EXPECT_EQ("abcde", input->Value());

  Controller().FinishComposingText(InputMethodController::kKeepSelection);
  EXPECT_EQ("abcd", input->Value());
}

TEST_F(InputMethodControllerTest, InputModeOfFocusedElement) {
  InsertHTMLElement("<input id='a' inputmode='decimal'>", "a")->Focus();
  EXPECT_EQ(kWebTextInputModeDecimal, Controller().InputModeOfFocusedElement());

  InsertHTMLElement("<input id='b' inputmode='foo'>", "b")->Focus();
  EXPECT_EQ(kWebTextInputModeDefault, Controller().InputModeOfFocusedElement());
}

TEST_F(InputMethodControllerTest, CompositionUnderlineSpansMultipleNodes) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable><b>t</b>est</div>", "sample");
  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 4, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  Controller().SetCompositionFromExistingText(Vector<ImeTextSpan>(), 0, 4);
  Controller().SetComposition("test", ime_text_spans, 0, 4);

  Node* b = div->firstChild();
  auto* text1 = To<Text>(b->firstChild());
  auto* text2 = To<Text>(b->nextSibling());

  const DocumentMarkerVector& text1_markers =
      GetDocument().Markers().MarkersFor(
          *text1, DocumentMarker::MarkerTypes::Composition());
  EXPECT_EQ(1u, text1_markers.size());
  EXPECT_EQ(0u, text1_markers[0]->StartOffset());
  EXPECT_EQ(1u, text1_markers[0]->EndOffset());

  const DocumentMarkerVector& text2_markers =
      GetDocument().Markers().MarkersFor(
          *text2, DocumentMarker::MarkerTypes::Composition());
  EXPECT_EQ(1u, text2_markers.size());
  EXPECT_EQ(0u, text2_markers[0]->StartOffset());
  EXPECT_EQ(3u, text2_markers[0]->EndOffset());
}

// The following tests are for http://crbug.com/766680.

TEST_F(InputMethodControllerTest, SetCompositionDeletesMarkupBeforeText) {
  Element* div = InsertHTMLElement(
      "<div id='div' contenteditable='true'><img />test</div>", "div");
  // Select the contents of the div element.
  GetFrame().Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(EphemeralRange::RangeOfContents(*div))
          .Build(),
      SetSelectionOptions());

  Controller().SetComposition("t", Vector<ImeTextSpan>(), 0, 1);

  EXPECT_EQ(1u, div->CountChildren());
  auto* text = To<Text>(div->firstChild());
  EXPECT_EQ("t", text->data());
}

TEST_F(InputMethodControllerTest, SetCompositionDeletesMarkupAfterText) {
  Element* div = InsertHTMLElement(
      "<div id='div' contenteditable='true'>test<img /></div>", "div");
  // Select the contents of the div element.
  GetFrame().Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(EphemeralRange::RangeOfContents(*div))
          .Build(),
      SetSelectionOptions());

  Controller().SetComposition("t", Vector<ImeTextSpan>(), 0, 1);

  EXPECT_EQ(1u, div->CountChildren());
  auto* text = To<Text>(div->firstChild());
  EXPECT_EQ("t", text->data());
}

TEST_F(InputMethodControllerTest,
       SetCompositionDeletesMarkupBeforeAndAfterText) {
  Element* div = InsertHTMLElement(
      "<div id='div' contenteditable='true'><img />test<img /></div>", "div");
  // Select the contents of the div element.
  GetFrame().Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(EphemeralRange::RangeOfContents(*div))
          .Build(),
      SetSelectionOptions());

  Controller().SetComposition("t", Vector<ImeTextSpan>(), 0, 1);

  EXPECT_EQ(1u, div->CountChildren());
  auto* text = To<Text>(div->firstChild());
  EXPECT_EQ("t", text->data());
}

TEST_F(InputMethodControllerTest,
       SetCompositionWithPartialGraphemeWithCompositionUnderlineDoesntCrash) {
  InsertHTMLElement("<div id='sample' contenteditable></div>", "sample");

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 1, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  Controller().CommitText(" ", ime_text_spans, 0);
  // Add character U+094D: 'DEVANAGARI SIGN VIRAMA'
  Controller().SetComposition(String::FromUTF8("\xE0\xA5\x8D"), ime_text_spans,
                              1, 1);
}

TEST_F(
    InputMethodControllerTest,
    SetCompositionWithPartialGraphemeWithoutCompositionUnderlineDoesntCrash) {
  InsertHTMLElement("<div id='sample' contenteditable></div>", "sample");

  Controller().CommitText(" ", Vector<ImeTextSpan>(), 0);
  // Add character U+094D: 'DEVANAGARI SIGN VIRAMA'
  Controller().SetComposition(String::FromUTF8("\xE0\xA5\x8D"),
                              Vector<ImeTextSpan>(), 1, 1);
}

TEST_F(InputMethodControllerTest, SetCompositionContainingNewline) {
  Element* div =
      InsertHTMLElement("<div id='sample' contenteditable></div>", "sample");
  Controller().SetComposition("Hello", Vector<ImeTextSpan>(), 5, 5);
  Controller().SetComposition("Hello\n", Vector<ImeTextSpan>(), 6, 6);

  EXPECT_EQ("Hello\n\n", PlainText(EphemeralRange(
                             Position(div, PositionAnchorType::kBeforeAnchor),
                             Position(div, PositionAnchorType::kAfterAnchor))));
}

TEST_F(InputMethodControllerTest, SetCompositionTamilVirama) {
  Element* div =
      InsertHTMLElement("<div id='sample' contenteditable></div>", "sample");

  // Commit TAMIL LETTER CA (U+0B9A) followed by TAMIL SIGN VIRAMA (U+U0BCD)
  Controller().CommitText(String::FromUTF8("\xE0\xAE\x9A\xE0\xAF\x8D"),
                          Vector<ImeTextSpan>(), 0);

  // Open composition with TAMIL LETTER CA (U+0B9A) followed by
  // TAMIL SIGN VIRAMA (U+U0BCD)
  Controller().SetComposition(String::FromUTF8("\xE0\xAE\x9A\xE0\xAF\x8D"),
                              Vector<ImeTextSpan>(), 2, 2);
  // Remove the TAMIL SIGN VIRAMA from the end of the composition
  Controller().SetComposition(String::FromUTF8("\xE0\xAE\x9A"),
                              Vector<ImeTextSpan>(), 1, 1);

  EXPECT_EQ(1u, div->CountChildren());
  auto* text = To<Text>(div->firstChild());
  EXPECT_EQ("\xE0\xAE\x9A\xE0\xAF\x8D\xE0\xAE\x9A", text->data().Utf8());

  Range* range = GetCompositionRange();
  EXPECT_EQ(2u, range->startOffset());
  EXPECT_EQ(3u, range->endOffset());
}

TEST_F(InputMethodControllerTest,
       CommitTextWithOpenCompositionAndInputEventHandlerChangingText) {
  InsertHTMLElement("<div id='sample' contenteditable>hello</div>", "sample");

  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      "document.getElementById('sample').addEventListener('input', "
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

TEST_F(InputMethodControllerTest,
       CommitTextWithoutCompositionAndInputEventHandlerChangingSelection) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>hello world</div>", "sample");

  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      "document.getElementById('sample').addEventListener('input', "
      "  event => {"
      "    const node = event.currentTarget;"
      "    const selection = getSelection();"
      "    selection.collapse(node.firstChild, 0);"
      "    selection.extend(node.firstChild, 0);"
      "});");
  GetDocument().body()->AppendChild(script);
  UpdateAllLifecyclePhasesForTest();

  // Select "hello".
  GetFrame().Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(EphemeralRange(Position(div->firstChild(), 0),
                                           Position(div->firstChild(), 5)))
          .Build(),
      SetSelectionOptions());

  // Commit text, leaving the cursor at the end of the newly-inserted text.
  // JavaScript will move the cursor back to the beginning of the
  // "HELLO world", where it should be left.
  Controller().CommitText("HELLO", Vector<ImeTextSpan>(), 0);

  EXPECT_EQ(0, GetFrame()
                   .Selection()
                   .GetSelectionInDOMTree()
                   .Anchor()
                   .ComputeOffsetInContainerNode());
}

TEST_F(
    InputMethodControllerTest,
    SetCompositionToEmptyStringWithOpenCompositionAndInputEventHandlerChangingText) {
  InsertHTMLElement("<div id='sample' contenteditable>hello world</div>",
                    "sample");

  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      "document.getElementById('sample').addEventListener('input', "
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

TEST_F(InputMethodControllerTest,
       SetCompositionWithOpenCompositionAndInputEventHandlerChangingText) {
  InsertHTMLElement("<div id='sample' contenteditable>hello world</div>",
                    "sample");

  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      "document.getElementById('sample').addEventListener('input', "
      "  event => {"
      "    const node = event.currentTarget;"
      "    node.textContent = 'HI WORLD';"
      "    const selection = getSelection();"
      "    selection.collapse(node.firstChild, 2);"
      "    selection.extend(node.firstChild, 2);"
      "});");
  GetDocument().body()->AppendChild(script);
  UpdateAllLifecyclePhasesForTest();

  // Open composition on "world".
  Controller().SetCompositionFromExistingText(Vector<ImeTextSpan>(), 6, 11);

  // Change the composition text, leaving the cursor at the end of the
  // composition. JavaScript will change the text and move the cursor after
  // "HI", where it should be left.
  Controller().SetComposition("WORLD", Vector<ImeTextSpan>(), 5, 5);

  EXPECT_EQ(2, GetFrame()
                   .Selection()
                   .GetSelectionInDOMTree()
                   .Anchor()
                   .ComputeOffsetInContainerNode());
}

TEST_F(InputMethodControllerTest,
       SetCompositionWithOpenCompositionAndInputEventHandlerChangingSelection) {
  InsertHTMLElement("<div id='sample' contenteditable>hello world</div>",
                    "sample");

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

  // Open composition on "world".
  Controller().SetCompositionFromExistingText(Vector<ImeTextSpan>(), 6, 11);

  // Change the composition text, leaving the cursor at the end of the
  // composition. JavaScript should move the cursor after "HELLO", where it
  // should be left.
  Controller().SetComposition("WORLD", Vector<ImeTextSpan>(), 5, 5);

  // The IME cursor update should have been ignored.
  EXPECT_EQ(5, GetFrame()
                   .Selection()
                   .GetSelectionInDOMTree()
                   .Anchor()
                   .ComputeOffsetInContainerNode());
}

TEST_F(InputMethodControllerTest,
       SetCompositionToEmptyStringAndInputEventHandlerChangingSelection) {
  InsertHTMLElement("<div id='sample' contenteditable>hello world</div>",
                    "sample");

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
```