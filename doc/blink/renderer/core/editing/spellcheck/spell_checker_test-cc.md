Response:
Let's break down the request and the provided code to generate a comprehensive response.

**1. Understanding the Core Request:**

The request asks for an analysis of the `spell_checker_test.cc` file within the Chromium Blink engine. The key aspects to address are:

* **Functionality:** What does this test file do?
* **Relationships (JavaScript, HTML, CSS):** How does the functionality relate to web technologies?
* **Logic and Reasoning (Hypothetical Inputs/Outputs):**  Illustrate the test scenarios with examples.
* **User/Programming Errors:** Identify common mistakes this testing helps prevent.
* **User Journey and Debugging:** Explain how a user interaction leads to this code and its relevance in debugging.

**2. Initial Code Scan and Interpretation:**

* **Headers:**  The `#include` statements reveal dependencies on various editing and core Blink components, including `SpellChecker`, `Editor`, `FrameSelection`, `DocumentMarkerController`, `HTMLInputElement`, etc. This immediately signals the file's purpose: testing the spellchecking functionality.
* **Test Fixture:** The `SpellCheckerTest` class inherits from `SpellCheckTestBase`, suggesting a testing setup with common functionalities.
* **Helper Functions:** `LayoutCount()`, `Page()`, and `ForceLayout()` are utility methods for interacting with the page and forcing layout updates. The `ForceLayout()` implementation is interesting – it slightly alters the frame rectangle to trigger a layout.
* **`TEST_F` Macros:** These indicate individual test cases. The names of the test cases are descriptive (e.g., `AdvanceToNextMisspellingWithEmptyInputNoCrash`).
* **Assertions and Expectations:**  `ASSERT_...` and `EXPECT_...` are standard testing macros used to verify conditions.
* **Focus and Selection:** Many tests involve focusing elements (`input->Focus()`, `div->Focus()`) and manipulating the selection (`Selection().SetSelection(...)`).
* **Document Markers:**  Tests interact with `DocumentMarkerController` to add and retrieve spelling markers.
* **`MarkAndReplaceFor`:**  This function is explicitly tested, suggesting it's a key part of the spellchecking mechanism.
* **`GetSpellCheckMarkerGroupUnderSelection`:**  Several tests focus on retrieving the spellcheck marker under various selection scenarios.
* **Input Type Handling:** The `PasswordFieldsAreIgnored` test verifies specific behavior related to password input fields.

**3. Deconstructing Each Test Case (Mental Walkthrough):**

For each test case, I mentally simulate the steps:

* **Setup:** What HTML is being created? Are elements being focused? Is text being entered? Are markers being added manually?
* **Action:** What is the core function being tested (e.g., `AdvanceToNextMisspelling`, `RespondToChangedSelection`, `GetSpellCheckMarkerGroupUnderSelection`)?
* **Assertion:** What is the expected outcome?  Is a crash prevented? Is the layout count unchanged? Is a marker found? Are marker offsets correct?

**4. Identifying Relationships with Web Technologies:**

* **HTML:**  The tests directly manipulate HTML elements (`<div>`, `<input>`, `<table>`, `<img>`). The spellchecker operates on the content of these elements.
* **JavaScript:** While this is a C++ test, the functionality being tested is triggered by user actions or browser logic that might originate from JavaScript. For instance, JavaScript could dynamically change the content of an editable div or the type of an input field.
* **CSS:**  Indirectly, CSS affects how text is rendered, and the spellchecker needs to operate on the underlying text content regardless of styling. The `ForceLayout()` method hints at the interplay between content and layout.

**5. Crafting Hypothetical Inputs and Outputs:**

For each test, I try to generalize the scenario:

* **Input:**  The HTML structure, the selection state, the existing markers.
* **Output:**  The presence or absence of a crash, the layout count, the retrieved marker, the description of a marker.

**6. Identifying User/Programming Errors:**

I think about what could go wrong if the spellchecker wasn't working correctly:

* Users see incorrect spellcheck suggestions or no suggestions at all.
* The spellchecker might interfere with user input or selection.
* The browser could crash in certain scenarios.
* Developers might not handle different input types (like passwords) correctly.

**7. Tracing the User Journey and Debugging:**

I consider how a user's actions lead to the execution of spellchecking code:

* Typing in a contenteditable div or a text input field.
* Right-clicking on a potentially misspelled word.
* Using keyboard shortcuts to navigate misspellings.

For debugging, this test file provides concrete examples and assertions to isolate and fix issues within the spellchecking logic.

**8. Structuring the Response:**

Finally, I organize the analysis into logical sections as requested by the prompt, providing specific examples and explanations for each point. I use clear and concise language to explain the technical concepts.

**Self-Correction/Refinement during the thought process:**

* Initially, I might focus too much on the C++ specifics. I need to consciously shift to the user-facing aspects and the relationship with web technologies.
* I need to avoid just listing the test names and provide a higher-level understanding of the tested functionality.
* Ensuring the hypothetical inputs and outputs are clear and directly related to the test being discussed is important.
*  The debugging aspect requires connecting the low-level test code back to the user's experience.
好的，让我们来分析一下 `blink/renderer/core/editing/spellcheck/spell_checker_test.cc` 这个文件。

**文件功能概述**

`spell_checker_test.cc` 是 Chromium Blink 引擎中用于测试 `SpellChecker` 类的单元测试文件。`SpellChecker` 类负责在用户编辑文本内容时进行拼写检查。  这个测试文件的主要目的是验证 `SpellChecker` 类的各种功能是否按预期工作，包括：

* **识别拼写错误:** 验证 `SpellChecker` 能否正确识别文本中的拼写错误。
* **提供拼写建议:**  验证 `SpellChecker` 能否为拼写错误的单词提供正确的替换建议。
* **处理各种编辑场景:** 验证 `SpellChecker` 在不同的编辑操作（例如，在空的输入框中，在包含图片的表格中，跨节点的文本中）下的行为是否稳定。
* **与选择交互:**  验证 `SpellChecker` 如何根据用户的选择（光标位置，选中文本）来定位和处理拼写错误。
* **忽略特定内容:** 验证 `SpellChecker` 能否忽略某些类型的输入（例如，密码字段）。
* **性能影响:**  验证拼写检查操作不会引起不必要的布局更新，从而影响性能。
* **Marker 管理:** 验证 `SpellChecker` 如何使用 `DocumentMarker` 来标记拼写错误，并如何提供替换建议作为 marker 的描述信息。

**与 JavaScript, HTML, CSS 的关系**

虽然 `spell_checker_test.cc` 是一个 C++ 文件，但它测试的功能直接与用户在网页上与 HTML 元素交互有关，并且这种交互可能受到 JavaScript 和 CSS 的影响。

* **HTML:**
    * **测试用例中创建和操作 HTML 元素:**  测试用例使用 `SetBodyContent()` 创建各种 HTML 结构，例如 `<input>` 元素、`<div>` 元素、`<table>` 元素等。
    * **`contenteditable` 属性:** 很多测试用例使用了 `contenteditable` 属性，使得 `<div>` 元素可编辑，这是用户在网页上进行文本编辑的常见方式。`SpellChecker` 的核心功能就是在可编辑区域中工作。
    * **`<input>` 元素:** 测试用例涉及到 `<input>` 元素，特别是测试了不同 `type` 属性（例如 `text` 和 `password`）对拼写检查的影响。

    **例子:** 用户在一个设置了 `contenteditable` 属性的 `<div>` 元素中输入 "spllchck"。`SpellChecker` 会识别 "spllchck" 是一个拼写错误，并在用户右键点击该词时，显示 "spellcheck" 等建议选项。

* **JavaScript:**
    * **JavaScript 可以动态修改 HTML 内容:**  JavaScript 代码可以动态地创建、修改 HTML 元素的内容，包括可编辑区域的文本。`SpellChecker` 需要能够处理这些动态变化。
    * **JavaScript 可以触发焦点和选择事件:** JavaScript 可以使用 `focus()` 方法将焦点移动到某个元素，也可以通过 `Selection` API 设置用户的选择范围。`SpellChecker` 的行为会受到焦点和选择的影响。

    **例子:** 一个网页上的 JavaScript 代码可能会在用户点击一个按钮后，向一个 `contenteditable` 的 `<div>` 中插入一段包含拼写错误的文本。`SpellChecker` 应该能够立即识别并标记这些错误。

* **CSS:**
    * **CSS 影响文本的渲染:** 虽然 `SpellChecker` 主要关注文本内容本身，但 CSS 样式会影响文本的显示方式（例如字体、颜色、大小）。测试用例中虽然没有直接测试 CSS，但确保拼写检查功能在不同 CSS 样式下都能正常工作是隐含的要求。
    * **布局的影响:** `ForceLayout()` 函数表明，测试中需要强制进行布局更新，这可能与 CSS 的渲染机制有关。测试用例 `SpellCheckDoesNotCauseUpdateLayout` 明确验证了拼写检查操作不应该引起不必要的布局更新，这对于保持页面性能非常重要。

    **例子:**  用户在一个应用了特定 CSS 样式的 `contenteditable` 的 `<div>` 中输入错误，拼写错误的下划线标记应该能够正确地显示，并且不应该因为拼写检查而导致页面布局发生不必要的变动。

**逻辑推理的假设输入与输出**

让我们以 `TEST_F(SpellCheckerTest, MarkAndReplaceForHandlesMultipleReplacements)` 这个测试用例为例进行逻辑推理：

**假设输入:**

1. **HTML 内容:**  `<div contenteditable>spllchck</div>`
2. **待检查范围:**  从 "spllchck" 的开头到结尾。
3. **拼写检查结果:**  识别出 "spllchck" 是拼写错误，并提供两个替换建议: "spellcheck" 和 "spillchuck"。

**预期输出:**

1. **文档中存在一个拼写错误的 Marker:** `GetDocument().Markers().Markers().size()` 的值为 1。
2. **该 Marker 的描述信息包含所有替换建议:**  Marker 的描述信息应该是 "spellcheck\nspillchuck"，即建议之间用换行符分隔。

**用户或编程常见的使用错误**

* **用户错误:**
    * **在密码字段中期望拼写检查:** 用户可能会期望在密码输入框中也进行拼写检查，但出于安全考虑，浏览器通常会禁用密码字段的拼写检查。`TEST_F(SpellCheckerTest, PasswordFieldsAreIgnored)` 就是为了防止开发者错误地在密码字段启用拼写检查。
    * **在不应该进行拼写检查的区域进行输入:**  有时，开发者可能会错误地将某些不应该进行拼写检查的区域（例如，代码编辑器的一部分）设置为 `contenteditable`，导致不必要的拼写检查。

* **编程错误:**
    * **未正确处理不同类型的 HTML 元素:**  开发者可能在实现拼写检查功能时，没有考虑到所有可能出现的可编辑 HTML 元素类型，例如 `<textarea>`、`<input>` 以及设置了 `contenteditable` 属性的元素。测试用例涵盖了 `<input>` 元素。
    * **拼写检查逻辑导致不必要的布局更新:** 如果拼写检查的实现不当，可能会在每次文本改变时都触发大量的布局计算，导致页面性能下降。`TEST_F(SpellCheckerTest, SpellCheckDoesNotCauseUpdateLayout)` 验证了这一点。
    * **处理选择范围时的错误:**  在处理用户的选择范围时，如果逻辑错误，可能会导致拼写检查功能无法正确识别选中文本中的错误，或者在用户进行选择时发生崩溃。许多测试用例都围绕着选择展开，例如 `GetSpellCheckMarkerUnderSelection_FirstCharSelected` 等。
    * **在异步操作中未正确处理回调:** 虽然这个测试文件没有直接体现，但在实际的拼写检查实现中，可能涉及到与外部服务进行异步通信获取拼写建议。如果回调处理不当，可能会导致内存泄漏或程序崩溃。

**用户操作如何一步步到达这里 (作为调试线索)**

以下是一个用户操作导致拼写检查功能运行，并可能触发 `spell_checker_test.cc` 中测试的场景的步骤：

1. **用户打开一个网页:** 用户在浏览器中打开一个包含可编辑区域的网页。这个可编辑区域可能是设置了 `contenteditable` 属性的 `<div>` 元素，或者是一个 `<textarea>` 或 `<input type="text">` 元素。
2. **用户开始输入文本:** 用户在可编辑区域中开始输入文本。
3. **输入包含拼写错误的单词:** 用户输入了一个拼写错误的单词，例如 "spllchck"。
4. **Blink 引擎触发拼写检查:**  当用户输入文本后，Blink 引擎的文本编辑模块会检测到文本内容的改变。
5. **调用 `SpellChecker`:**  Blink 引擎会调用 `SpellChecker` 类的相关方法，对用户输入的文本进行拼写检查。
6. **`SpellChecker` 识别拼写错误:** `SpellChecker` 内部的算法会识别出 "spllchck" 是一个拼写错误。
7. **标记拼写错误 (Document Markers):** `SpellChecker` 会在文档中创建一个 `SpellCheckMarker`，标记该拼写错误的位置。这对应于测试用例中 `GetDocument().Markers().AddSpellingMarker()` 的操作。
8. **显示拼写错误提示:** 浏览器通常会在拼写错误的单词下方显示一个波浪线。
9. **用户右键点击拼写错误的单词:** 用户可能会右键点击 "spllchck"。
10. **显示上下文菜单:** 浏览器会显示一个上下文菜单，其中包含拼写建议。
11. **`SpellChecker` 提供拼写建议:** `SpellChecker` 会提供可能的拼写建议，例如 "spellcheck"。这与测试用例 `MarkAndReplaceForHandlesMultipleReplacements` 中验证的提供替换建议的功能相关。
12. **用户选择一个建议:** 用户点击了 "spellcheck" 这个建议。
13. **替换文本:** 浏览器会将拼写错误的单词替换为用户选择的建议。

**调试线索:**

如果在上述任何一个步骤中出现问题，例如：

* **拼写错误没有被识别:** 这可能表明 `SpellChecker` 的核心拼写检查算法存在问题，相关的测试用例可能会失败。
* **没有显示拼写错误提示:** 这可能与 `DocumentMarker` 的创建或渲染有关，需要检查 `SpellCheckMarker` 相关的代码和测试。
* **提供的拼写建议不正确或缺失:** 这可能涉及到拼写建议生成算法的问题，需要检查 `SpellChecker` 如何获取和处理拼写建议。
* **在特定场景下发生崩溃:**  例如，在包含图片的表格中输入文本时崩溃，`TEST_F(SpellCheckerTest, AdvanceToNextMisspellingWithImageInTableNoCrash)` 就是为了防止这种情况。

通过查看 `spell_checker_test.cc` 中的各种测试用例，开发者可以了解 `SpellChecker` 在各种场景下的预期行为。当用户报告拼写检查相关的 bug 时，开发者可以根据 bug 的描述，找到相关的测试用例进行调试，或者编写新的测试用例来重现和修复 bug。例如，如果用户报告在包含特定 HTML 结构的页面上拼写检查崩溃，开发者可以编写一个类似的测试用例来复现并找到崩溃的原因。

总而言之，`spell_checker_test.cc` 是确保 Chromium Blink 引擎拼写检查功能正确、稳定运行的关键组成部分。它通过模拟各种用户操作和场景，验证了 `SpellChecker` 类的行为，并为开发者提供了调试和修复相关问题的线索。

### 提示词
```
这是目录为blink/renderer/core/editing/spellcheck/spell_checker_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/spellcheck/spell_checker.h"

#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/markers/spell_check_marker.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_check_requester.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_check_test_base.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/input_type_names.h"

namespace blink {

class SpellCheckerTest : public SpellCheckTestBase {
 protected:
  unsigned LayoutCount() const {
    return Page().GetFrameView().LayoutCountForTesting();
  }
  DummyPageHolder& Page() const { return GetDummyPageHolder(); }

  void ForceLayout();
};

void SpellCheckerTest::ForceLayout() {
  LocalFrameView& frame_view = Page().GetFrameView();
  gfx::Rect frame_rect = frame_view.FrameRect();
  frame_rect.set_width(frame_rect.width() + 1);
  frame_rect.set_height(frame_rect.height() + 1);
  Page().GetFrameView().SetFrameRect(frame_rect);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
}

TEST_F(SpellCheckerTest, AdvanceToNextMisspellingWithEmptyInputNoCrash) {
  SetBodyContent("<input placeholder='placeholder'>abc");
  UpdateAllLifecyclePhasesForTest();
  Element* input = GetDocument().QuerySelector(AtomicString("input"));
  input->Focus();
  // Do not crash in advanceToNextMisspelling.
  GetSpellChecker().AdvanceToNextMisspelling(false);
}

// Regression test for crbug.com/701309
TEST_F(SpellCheckerTest, AdvanceToNextMisspellingWithImageInTableNoCrash) {
  SetBodyContent(
      "<div contenteditable>"
      "<table><tr><td>"
      "<img src=foo.jpg>"
      "</td></tr></table>"
      "zz zz zz"
      "</div>");
  GetDocument().QuerySelector(AtomicString("div"))->Focus();
  UpdateAllLifecyclePhasesForTest();

  // Do not crash in advanceToNextMisspelling.
  GetSpellChecker().AdvanceToNextMisspelling(false);
}

// Regression test for crbug.com/728801
TEST_F(SpellCheckerTest, AdvancedToNextMisspellingWrapSearchNoCrash) {
  SetBodyContent("<div contenteditable>  zz zz zz  </div>");

  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  div->Focus();
  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .Collapse(Position::LastPositionInNode(*div))
                               .Build(),
                           SetSelectionOptions());
  UpdateAllLifecyclePhasesForTest();

  GetSpellChecker().AdvanceToNextMisspelling(false);
}

TEST_F(SpellCheckerTest, SpellCheckDoesNotCauseUpdateLayout) {
  SetBodyContent("<input>");
  auto* input =
      To<HTMLInputElement>(GetDocument().QuerySelector(AtomicString("input")));
  input->Focus();
  input->SetValue("Hello, input field");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  Position new_position(input->InnerEditorElement()->firstChild(), 3);
  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder().Collapse(new_position).Build(),
      SetSelectionOptions());
  ASSERT_EQ(3u, input->selectionStart());

  EXPECT_TRUE(GetSpellChecker().IsSpellCheckingEnabled());
  ForceLayout();
  unsigned start_count = LayoutCount();
  GetSpellChecker().RespondToChangedSelection();
  EXPECT_EQ(start_count, LayoutCount());
}

TEST_F(SpellCheckerTest, MarkAndReplaceForHandlesMultipleReplacements) {
  SetBodyContent(
      "<div contenteditable>"
      "spllchck"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();
  EphemeralRange range_to_check =
      EphemeralRange(Position(text, 0), Position(text, 8));

  SpellCheckRequest* request = SpellCheckRequest::Create(range_to_check, 0);

  TextCheckingResult result;
  result.decoration = TextDecorationType::kTextDecorationTypeSpelling;
  result.location = 0;
  result.length = 8;
  result.replacements = Vector<String>({"spellcheck", "spillchuck"});

  GetDocument().GetFrame()->GetSpellChecker().MarkAndReplaceFor(
      request, Vector<TextCheckingResult>({result}));

  ASSERT_EQ(1u, GetDocument().Markers().Markers().size());

  // The Spelling marker's description should be a newline-separated list of the
  // suggested replacements
  EXPECT_EQ("spellcheck\nspillchuck",
            To<SpellCheckMarker>(GetDocument().Markers().Markers()[0].Get())
                ->Description());
}

TEST_F(SpellCheckerTest, GetSpellCheckMarkerUnderSelection_FirstCharSelected) {
  SetBodyContent(
      "<div contenteditable>"
      "spllchck"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  GetDocument().Markers().AddSpellingMarker(
      EphemeralRange(Position(text, 0), Position(text, 8)));

  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 0), Position(text, 1))
          .Build(),
      SetSelectionOptions());

  DocumentMarkerGroup* result = GetDocument()
                                    .GetFrame()
                                    ->GetSpellChecker()
                                    .GetSpellCheckMarkerGroupUnderSelection();
  ASSERT_NE(nullptr, result);
  const DocumentMarker* marker = result->GetMarkerForText(To<Text>(text));
  ASSERT_NE(nullptr, marker);
  EXPECT_EQ(0u, marker->StartOffset());
  EXPECT_EQ(8u, marker->EndOffset());
}

TEST_F(SpellCheckerTest, GetSpellCheckMarkerUnderSelection_LastCharSelected) {
  SetBodyContent(
      "<div contenteditable>"
      "spllchck"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  GetDocument().Markers().AddSpellingMarker(
      EphemeralRange(Position(text, 0), Position(text, 8)));

  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 7), Position(text, 8))
          .Build(),
      SetSelectionOptions());

  DocumentMarkerGroup* result = GetDocument()
                                    .GetFrame()
                                    ->GetSpellChecker()
                                    .GetSpellCheckMarkerGroupUnderSelection();
  ASSERT_NE(nullptr, result);
  const DocumentMarker* marker = result->GetMarkerForText(To<Text>(text));
  ASSERT_NE(nullptr, marker);
  EXPECT_EQ(0u, marker->StartOffset());
  EXPECT_EQ(8u, marker->EndOffset());
}

TEST_F(SpellCheckerTest,
       GetSpellCheckMarkerUnderSelection_SingleCharWordSelected) {
  SetBodyContent(
      "<div contenteditable>"
      "s"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  GetDocument().Markers().AddSpellingMarker(
      EphemeralRange(Position(text, 0), Position(text, 1)));

  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 0), Position(text, 1))
          .Build(),
      SetSelectionOptions());

  DocumentMarkerGroup* result = GetDocument()
                                    .GetFrame()
                                    ->GetSpellChecker()
                                    .GetSpellCheckMarkerGroupUnderSelection();
  ASSERT_NE(nullptr, result);
  const DocumentMarker* marker = result->GetMarkerForText(To<Text>(text));
  ASSERT_NE(nullptr, marker);
  EXPECT_EQ(0u, marker->StartOffset());
  EXPECT_EQ(1u, marker->EndOffset());
}

TEST_F(SpellCheckerTest,
       GetSpellCheckMarkerUnderSelection_CaretLeftOfSingleCharWord) {
  SetBodyContent(
      "<div contenteditable>"
      "s"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  GetDocument().Markers().AddSpellingMarker(
      EphemeralRange(Position(text, 0), Position(text, 1)));

  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 0), Position(text, 0))
          .Build(),
      SetSelectionOptions());

  DocumentMarkerGroup* result = GetDocument()
                                    .GetFrame()
                                    ->GetSpellChecker()
                                    .GetSpellCheckMarkerGroupUnderSelection();
  ASSERT_NE(nullptr, result);
  const DocumentMarker* marker = result->GetMarkerForText(To<Text>(text));
  ASSERT_NE(nullptr, marker);
  EXPECT_EQ(0u, marker->StartOffset());
  EXPECT_EQ(1u, marker->EndOffset());
}

TEST_F(SpellCheckerTest,
       GetSpellCheckMarkerUnderSelection_CaretRightOfSingleCharWord) {
  SetBodyContent(
      "<div contenteditable>"
      "s"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  GetDocument().Markers().AddSpellingMarker(
      EphemeralRange(Position(text, 0), Position(text, 1)));

  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 1), Position(text, 1))
          .Build(),
      SetSelectionOptions());

  DocumentMarkerGroup* result = GetDocument()
                                    .GetFrame()
                                    ->GetSpellChecker()
                                    .GetSpellCheckMarkerGroupUnderSelection();
  ASSERT_NE(nullptr, result);
  const DocumentMarker* marker = result->GetMarkerForText(To<Text>(text));
  ASSERT_NE(nullptr, marker);
  EXPECT_EQ(0u, marker->StartOffset());
  EXPECT_EQ(1u, marker->EndOffset());
}

TEST_F(SpellCheckerTest,
       GetSpellCheckMarkerUnderSelection_CaretLeftOfMultiCharWord) {
  SetBodyContent(
      "<div contenteditable>"
      "spllchck"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  GetDocument().Markers().AddSpellingMarker(
      EphemeralRange(Position(text, 0), Position(text, 8)));

  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 0), Position(text, 0))
          .Build(),
      SetSelectionOptions());

  DocumentMarkerGroup* result = GetDocument()
                                    .GetFrame()
                                    ->GetSpellChecker()
                                    .GetSpellCheckMarkerGroupUnderSelection();
  ASSERT_NE(nullptr, result);
  const DocumentMarker* marker = result->GetMarkerForText(To<Text>(text));
  ASSERT_NE(nullptr, marker);
  EXPECT_EQ(0u, marker->StartOffset());
  EXPECT_EQ(8u, marker->EndOffset());
}

TEST_F(SpellCheckerTest,
       GetSpellCheckMarkerUnderSelection_CaretRightOfMultiCharWord) {
  SetBodyContent(
      "<div contenteditable>"
      "spllchck"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  GetDocument().Markers().AddSpellingMarker(
      EphemeralRange(Position(text, 0), Position(text, 8)));

  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 8), Position(text, 8))
          .Build(),
      SetSelectionOptions());

  DocumentMarkerGroup* result = GetDocument()
                                    .GetFrame()
                                    ->GetSpellChecker()
                                    .GetSpellCheckMarkerGroupUnderSelection();
  ASSERT_NE(nullptr, result);
  const DocumentMarker* marker = result->GetMarkerForText(To<Text>(text));
  ASSERT_NE(nullptr, marker);
  EXPECT_EQ(0u, marker->StartOffset());
  EXPECT_EQ(8u, marker->EndOffset());
}

TEST_F(SpellCheckerTest, GetSpellCheckMarkerUnderSelection_CaretMiddleOfWord) {
  SetBodyContent(
      "<div contenteditable>"
      "spllchck"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  GetDocument().Markers().AddSpellingMarker(
      EphemeralRange(Position(text, 0), Position(text, 8)));

  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 4), Position(text, 4))
          .Build(),
      SetSelectionOptions());

  DocumentMarkerGroup* result = GetDocument()
                                    .GetFrame()
                                    ->GetSpellChecker()
                                    .GetSpellCheckMarkerGroupUnderSelection();
  ASSERT_NE(nullptr, result);
  const DocumentMarker* marker = result->GetMarkerForText(To<Text>(text));
  ASSERT_NE(nullptr, marker);
  EXPECT_EQ(0u, marker->StartOffset());
  EXPECT_EQ(8u, marker->EndOffset());
}

TEST_F(SpellCheckerTest,
       GetSpellCheckMarkerUnderSelection_CaretOneCharLeftOfMisspelling) {
  SetBodyContent(
      "<div contenteditable>"
      "a spllchck"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  GetDocument().Markers().AddSpellingMarker(
      EphemeralRange(Position(text, 2), Position(text, 10)));

  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 1), Position(text, 1))
          .Build(),
      SetSelectionOptions());

  DocumentMarkerGroup* result = GetDocument()
                                    .GetFrame()
                                    ->GetSpellChecker()
                                    .GetSpellCheckMarkerGroupUnderSelection();
  EXPECT_EQ(nullptr, result);
}

TEST_F(SpellCheckerTest,
       GetSpellCheckMarkerUnderSelection_CaretOneCharRightOfMisspelling) {
  SetBodyContent(
      "<div contenteditable>"
      "spllchck a"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  GetDocument().Markers().AddSpellingMarker(
      EphemeralRange(Position(text, 0), Position(text, 8)));

  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 9), Position(text, 9))
          .Build(),
      SetSelectionOptions());

  DocumentMarkerGroup* result = GetDocument()
                                    .GetFrame()
                                    ->GetSpellChecker()
                                    .GetSpellCheckMarkerGroupUnderSelection();
  EXPECT_EQ(nullptr, result);
}

TEST_F(SpellCheckerTest, GetSpellCheckMarkerUnderSelection_MultiNodeMisspell) {
  SetBodyContent(
      "<div contenteditable>"
      "spl<b>lc</b>hck"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* first_text = div->firstChild();
  Node* second_text = first_text->nextSibling()->firstChild();
  Node* third_text = div->lastChild();

  GetDocument().Markers().AddSpellingMarker(
      EphemeralRange(Position(first_text, 0), Position(third_text, 3)));

  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(second_text, 1), Position(second_text, 1))
          .Build(),
      SetSelectionOptions());

  DocumentMarkerGroup* result = GetDocument()
                                    .GetFrame()
                                    ->GetSpellChecker()
                                    .GetSpellCheckMarkerGroupUnderSelection();
  ASSERT_NE(nullptr, result);
  const DocumentMarker* first_marker =
      result->GetMarkerForText(To<Text>(first_text));
  const DocumentMarker* second_marker =
      result->GetMarkerForText(To<Text>(second_text));
  const DocumentMarker* third_marker =
      result->GetMarkerForText(To<Text>(third_text));
  ASSERT_NE(nullptr, first_marker);
  EXPECT_EQ(0u, first_marker->StartOffset());
  EXPECT_EQ(3u, first_marker->EndOffset());
  ASSERT_NE(nullptr, second_marker);
  EXPECT_EQ(0u, second_marker->StartOffset());
  EXPECT_EQ(2u, second_marker->EndOffset());
  ASSERT_NE(nullptr, third_marker);
  EXPECT_EQ(0u, third_marker->StartOffset());
  EXPECT_EQ(3u, third_marker->EndOffset());
}

TEST_F(SpellCheckerTest, PasswordFieldsAreIgnored) {
  // Check that spellchecking is enabled for an input type="text".
  SetBodyContent("<input type=\"text\">");
  auto* input =
      To<HTMLInputElement>(GetDocument().QuerySelector(AtomicString("input")));
  input->Focus();
  input->SetValue("spllchck");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_TRUE(SpellChecker::IsSpellCheckingEnabledAt(
      Position(input->InnerEditorElement()->firstChild(), 0)));

  // But if this turns into a password field, this disables spellchecking.
  // input->setType(input_type_names::kPassword);
  input->setType(input_type_names::kPassword);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_FALSE(SpellChecker::IsSpellCheckingEnabledAt(
      Position(input->InnerEditorElement()->firstChild(), 0)));

  // Some websites toggle between <input type="password"> and
  // <input type="text"> via a reveal/hide button. In this case, spell
  // checking should remain disabled.
  input->setType(input_type_names::kText);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_FALSE(SpellChecker::IsSpellCheckingEnabledAt(
      Position(input->InnerEditorElement()->firstChild(), 0)));
}

}  // namespace blink
```