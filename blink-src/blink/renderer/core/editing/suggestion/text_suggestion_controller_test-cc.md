Response:
Let's break down the thought process for analyzing the provided C++ test file.

1. **Understand the Purpose of a Test File:**  The fundamental goal of a test file is to verify the functionality of a specific piece of code. In this case, the filename `text_suggestion_controller_test.cc` clearly indicates that it's testing the `TextSuggestionController` class.

2. **Identify the Tested Class:** The `#include` directive `third_party/blink/renderer/core/editing/suggestion/text_suggestion_controller.h` confirms the class under scrutiny.

3. **Examine the Test Fixture:** The line `class TextSuggestionControllerTest : public EditingTestBase {` establishes a test fixture. This fixture sets up the environment needed to run the tests. `EditingTestBase` likely provides common functionalities for testing editing-related features in Blink. The public methods within the fixture (`IsTextSuggestionHostAvailable`, `ShowSuggestionMenu`, `ComputeRangeSurroundingCaret`) offer helper functions specifically for testing the `TextSuggestionController`.

4. **Analyze Individual Test Cases (TEST_F):**  Each `TEST_F` macro defines an individual test. The naming convention (`ApplySpellCheckSuggestion`, `ApplyTextSuggestion`, etc.) gives strong hints about the specific feature being tested.

5. **Decipher Test Logic (Inside each `TEST_F`):**  The core of the analysis lies in understanding what each test case does:
    * **`SetBodyContent(...)`:** This likely sets up the HTML structure within the test environment, often including a `contenteditable` element to simulate user input.
    * **`GetDocument().QuerySelector(...)`:** Used to retrieve specific HTML elements.
    * **`GetDocument().Markers().Add...Marker(...)`:** These lines indicate the test is setting up markers (like spelling or suggestion markers) on the text. This is a key aspect of the `TextSuggestionController`'s functionality. Look for different marker types being used (e.g., `AddActiveSuggestionMarker`, `AddSuggestionMarker`, `AddSpellingMarker`).
    * **`GetDocument().GetFrame()->Selection().SetSelection(...)`:** This manipulates the text cursor (caret) position. The selection is often placed near the text being tested.
    * **`GetDocument().GetFrame()->GetTextSuggestionController().Apply...Suggestion(...)` or `DeleteActiveSuggestionRange()` or `HandlePotentialSuggestionTap()` or `OnNewWordAddedToDictionary()`:** These are the core methods of the `TextSuggestionController` being invoked and tested. Pay close attention to the arguments passed to these methods.
    * **`EXPECT_EQ(...)` or `EXPECT_TRUE(...)` or `EXPECT_FALSE(...)` or `EXPECT_NE(...)`:** These are assertion macros. They verify that the actual outcome of the test matches the expected outcome. Focus on *what* is being compared to *what*. For example, is it the `textContent` of a node, the size of a marker list, or the position of the cursor?

6. **Identify Connections to Web Technologies:** Look for keywords and concepts related to JavaScript, HTML, and CSS:
    * **HTML:**  The use of `<div>`, `<span>`, and the `contenteditable` attribute are direct HTML elements and attributes. The test manipulates the DOM structure.
    * **CSS:**  The `style='color: rgb(255, 0, 0);'` attribute shows the presence of inline CSS, although the test's primary focus isn't CSS styling itself.
    * **JavaScript:** While this is a C++ test, the *functionality being tested* is often triggered by user interactions in the browser, which are frequently handled by JavaScript. The test simulates these interactions on a lower level. The "suggestion menu" implies a UI element that would be typically controlled via JavaScript.

7. **Infer Logical Reasoning and Input/Output:**  For each test, try to understand:
    * **Input:** What is the initial state of the DOM, the position of the cursor, and the markers that have been set?
    * **Action:** Which method of the `TextSuggestionController` is being called, and with what arguments?
    * **Output:** What is the expected state of the DOM (text content, marker presence), and the cursor position *after* the action is performed?  The `EXPECT_*` macros define the expected output.

8. **Consider User/Programming Errors:** Think about what could go wrong from a user's perspective or how a developer might misuse the `TextSuggestionController`:
    * **User Errors:** Misspellings, accidentally triggering suggestions, wanting to delete suggested text. The tests often simulate these scenarios.
    * **Programming Errors:** Incorrectly setting up markers, passing wrong arguments to the controller's methods, not handling edge cases (like empty suggestions).

9. **Trace User Operations for Debugging:** Imagine a user interacting with a web page:
    * Typing text in a `contenteditable` area.
    * The browser's spellchecker identifying a misspelling.
    * The user right-clicking on the misspelling to see suggestions.
    * The user selecting a suggestion.
    * The user deleting a suggested word.

    The tests in this file are designed to exercise the code paths that are triggered by these user actions. Each test case can be seen as a simplified, programmatic way to simulate a specific user interaction.

10. **Iterative Refinement:**  The initial analysis might be high-level. Go back and examine the code more closely, paying attention to the details of the DOM manipulation and the assertions. For example, notice how the `ApplyTextSuggestion` test checks that *some* markers are cleared while *others* are not. This reveals a more nuanced aspect of the controller's behavior.

By following these steps, you can systematically dissect the test file and extract the information requested, building a comprehensive understanding of its purpose, functionality, and relationships to web technologies.
这个文件 `text_suggestion_controller_test.cc` 是 Chromium Blink 引擎中用于测试 `TextSuggestionController` 类的单元测试文件。 它的主要功能是验证 `TextSuggestionController` 类的各种方法是否按照预期工作。

**`TextSuggestionController` 的功能（通过测试用例推断）：**

* **应用拼写检查建议 (`ApplySpellCheckSuggestion`):**  当用户选择拼写检查建议时，负责替换文档中的错误拼写。
* **应用文本建议 (`ApplyTextSuggestion`):**  处理各种文本建议，不仅仅是拼写检查，例如自动完成或输入法提供的建议。 它需要能够正确替换文本并维护文档中的其他标记（markers）。
* **删除激活的建议范围 (`DeleteActiveSuggestionRange`):**  允许用户删除当前激活的建议范围，例如用户可能想删除输入法正在建议的词语。
* **处理添加新词到字典 (`OnNewWordAddedToDictionary`):** 当用户将新词添加到自定义字典时，`TextSuggestionController` 应该能够更新其状态，例如移除之前标记为拼写错误的词语的标记。
* **处理潜在的建议点击 (`HandlePotentialSuggestionTap`):**  当用户点击可能存在建议的位置时，`TextSuggestionController` 负责触发显示建议菜单的操作。
* **显示建议菜单 (`ShowSuggestionMenu`):** 负责向用户展示可用的文本建议。
* **管理建议相关的标记 (Markers):**  负责在文档中添加、删除和更新与文本建议相关的标记，例如高亮显示拼写错误或建议的文本。

**与 JavaScript, HTML, CSS 的关系：**

尽管这是一个 C++ 文件，它测试的功能直接与用户在网页上的交互有关，而这些交互通常涉及到 JavaScript, HTML 和 CSS。

* **HTML:**
    * 测试用例中使用了 `contenteditable` 属性，这使得 HTML 元素可以被用户编辑。`TextSuggestionController` 的核心功能就是在可编辑的内容中提供建议。
    * 测试用例会检查修改后的 HTML 结构和文本内容，例如 `EXPECT_EQ("spellcheck", text->textContent());`。
    * 涉及 DOM 节点的创建和查询，例如 `GetDocument().QuerySelector(AtomicString("div"));`。

    **举例说明:** 当用户在一个 `<div contenteditable>` 元素中输入错误单词时，JavaScript 可能会触发拼写检查。`TextSuggestionController` 负责处理拼写检查服务返回的建议，并在用户选择建议后更新该 `div` 元素的内容。

* **JavaScript:**
    * 虽然测试代码是 C++，但在浏览器中，`TextSuggestionController` 的很多功能会被 JavaScript 代码调用或触发。例如，用户右键点击拼写错误的单词可能会触发一个 JavaScript 事件，然后该事件会调用 Blink 引擎提供的接口来显示建议菜单。
    * 输入法编辑器（IME）通常使用 JavaScript 与浏览器进行通信，`TextSuggestionController` 负责处理来自 IME 的文本建议。

    **举例说明:**  当用户使用中文输入法输入拼音时，输入法会通过 JavaScript 向浏览器发送候选词。`TextSuggestionController` 接收这些候选词，并在用户选择后将其插入到 HTML 文档中。

* **CSS:**
    * `TextSuggestionController` 可能会涉及到使用 CSS 来高亮显示拼写错误的单词或建议的文本。虽然这个测试文件没有直接测试 CSS，但它测试的功能会影响最终渲染的样式。
    * 测试用例中可以看到与标记相关的颜色和下划线样式设置，这些最终会通过 CSS 渲染到页面上。

    **举例说明:**  拼写错误的单词可能会被 `TextSuggestionController` 加上一个带有红色波浪下划线的标记，这个下划线的样式就是通过 CSS 定义的。

**逻辑推理、假设输入与输出：**

**测试用例：`ApplySpellCheckSuggestion`**

* **假设输入:**
    * HTML 内容为 `<div contenteditable>spllchck</div>`
    * 光标位于 "spllchck" 前面 (偏移量为 0)。
    * 存在一个标记，指示 "spllchck" 是拼写错误的。
    * 用户选择了拼写检查建议 "spellcheck"。
* **动作:** 调用 `ApplySpellCheckSuggestion("spellcheck")`。
* **预期输出:**
    * HTML 内容变为 `<div contenteditable>spellcheck</div>`。
    * 光标位于 "spellcheck" 之后 (偏移量为 10)。

**测试用例：`ApplyTextSuggestion`**

* **假设输入:**
    * HTML 内容为 `<div contenteditable>word1 word2 word3 word4</div>`
    * 光标位于 "word2" 前面 (偏移量为 6)。
    * 存在多个建议标记，其中一个标记 (tag 3) 覆盖 "word2 word3"，其建议列表包含 "marker3"。
* **动作:** 调用 `ApplyTextSuggestion(3, 0)`，表示应用 tag 为 3 的标记的第 0 个建议。
* **预期输出:**
    * HTML 内容变为 `<div contenteditable>word1 marker3 word4</div>` (假设 "marker3" 就是 "word2 word3" 本身，测试代码里实际是替换成了原始文本)。
    * 光标位于 "marker3" 之后 (偏移量为 13)。
    * 与被替换文本重叠的标记被清除，不重叠的标记保留。

**用户或编程常见的使用错误：**

* **用户错误:**
    * **误触建议:** 用户可能不小心点击了错误的建议。测试用例没有直接模拟用户的触摸操作，但它测试了应用建议的功能，可以间接帮助发现由于误触导致的问题。
    * **在不期望的时候触发建议:**  例如，在用户正在输入一半的单词时，不应该显示拼写检查建议。`TextSuggestionController` 需要有合理的触发机制。

* **编程错误:**
    * **标记范围计算错误:**  如果标记的起始或结束位置计算错误，可能会导致应用建议时替换错误的文本范围，或者影响其他标记。
    * **建议列表为空时未做处理:**  `SuggestionMarkerWithEmptySuggestion` 测试用例检查了当建议列表为空时，是否会发生崩溃或其他未预期的行为。
    * **应用建议后光标位置错误:**  用户期望在应用建议后光标能定位到合理的位置，例如替换后的文本末尾。
    * **未正确清除旧的标记:**  在应用建议后，与被替换文本重叠的旧标记应该被清除，否则可能会导致 UI 显示异常。`ApplyTextSuggestion` 测试用例就覆盖了这种情况。
    * **在文档被销毁后回调:** `CallbackHappensAfterDocumentDestroyed` 测试用例检查了在文档被销毁后，是否还有回调函数被执行，这是一种常见的内存错误或资源泄漏场景。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户在 `contenteditable` 元素中输入文本。**  这是 `TextSuggestionController` 发挥作用的最常见场景。
2. **拼写检查器检测到拼写错误。** 浏览器内置的拼写检查功能（或操作系统提供的拼写检查服务）会识别出拼写错误的单词。
3. **浏览器在拼写错误的单词上添加标记 (通常是下划线)。**  `TextSuggestionController` 或相关的组件会添加视觉标记来指示错误。
4. **用户右键点击该拼写错误的单词（或使用其他触发建议的方式，如长按）。**  这会触发显示上下文菜单或建议菜单的操作。
5. **`TextSuggestionController` 的 `ShowSuggestionMenu` 方法被调用。**  该方法负责构建并显示可用的拼写建议。
6. **用户从建议菜单中选择一个正确的拼写。**
7. **`TextSuggestionController` 的 `ApplySpellCheckSuggestion` 方法被调用。**  该方法接收用户选择的建议，并更新文档中的文本。
8. **用户可能希望删除输入法正在建议的词语。**  用户可能会按下退格键或其他删除操作，这可能触发 `DeleteActiveSuggestionRange`。
9. **用户可能会将一个之前被标记为错误的词语添加到自定义字典。** 这会触发 `OnNewWordAddedToDictionary`，导致该词语的拼写错误标记被移除。

**调试线索:**

当开发者在 `TextSuggestionController` 相关的代码中遇到问题时，这些测试用例可以作为很好的调试线索：

* **如果应用拼写检查建议后文本没有正确替换，或者光标位置错误，可以查看 `ApplySpellCheckSuggestion` 测试用例。**
* **如果应用更通用的文本建议（例如输入法建议）后出现问题，可以参考 `ApplyTextSuggestion` 测试用例，特别是注意标记是否被正确维护。**
* **如果删除建议范围的功能出现问题，例如删除了错误的文本或者没有正确更新光标位置，可以查看 `DeleteActiveSuggestionRange` 的各种测试用例，这些用例覆盖了不同的删除场景。**
* **如果用户添加新词到字典后，拼写错误标记没有正确移除，可以参考 `OnNewWordAddedToDictionary` 测试用例。**

总之，`text_suggestion_controller_test.cc` 文件通过一系列细致的测试用例，确保 `TextSuggestionController` 能够可靠地处理各种文本建议相关的操作，并与浏览器的其他组件正确协作，从而为用户提供良好的编辑体验。

Prompt: 
```
这是目录为blink/renderer/core/editing/suggestion/text_suggestion_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/suggestion/text_suggestion_controller.h"

#include "build/build_config.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/markers/suggestion_marker_properties.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_checker.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"

using ui::mojom::ImeTextSpanThickness;
using ui::mojom::ImeTextSpanUnderlineStyle;

namespace blink {

class TextSuggestionControllerTest : public EditingTestBase {
 public:
  bool IsTextSuggestionHostAvailable() {
    return bool(GetDocument()
                    .GetFrame()
                    ->GetTextSuggestionController()
                    .text_suggestion_host_.is_bound());
  }

  void ShowSuggestionMenu(
      const HeapVector<std::pair<Member<const Text>, Member<DocumentMarker>>>&
          node_suggestion_marker_pairs,
      size_t max_number_of_suggestions) {
    GetDocument().GetFrame()->GetTextSuggestionController().ShowSuggestionMenu(
        node_suggestion_marker_pairs, max_number_of_suggestions);
  }

  EphemeralRangeInFlatTree ComputeRangeSurroundingCaret(
      const PositionInFlatTree& caret_position) {
    const Node* const position_node = caret_position.ComputeContainerNode();
    const unsigned position_offset_in_node =
        caret_position.ComputeOffsetInContainerNode();
    // See ComputeRangeSurroundingCaret() in TextSuggestionController.
    return EphemeralRangeInFlatTree(
        PositionInFlatTree(position_node, position_offset_in_node - 1),
        PositionInFlatTree(position_node, position_offset_in_node + 1));
  }
};

TEST_F(TextSuggestionControllerTest, ApplySpellCheckSuggestion) {
  SetBodyContent(
      "<div contenteditable>"
      "spllchck"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  GetDocument().Markers().AddActiveSuggestionMarker(
      EphemeralRange(Position(text, 0), Position(text, 8)), Color::kBlack,
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kBlack, Color::kBlack);
  // Select immediately before misspelling
  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 0), Position(text, 0))
          .Build(),
      SetSelectionOptions());
  GetDocument()
      .GetFrame()
      ->GetTextSuggestionController()
      .ApplySpellCheckSuggestion("spellcheck");

  EXPECT_EQ("spellcheck", text->textContent());

  // Cursor should be at end of replaced text
  const VisibleSelectionInFlatTree& selection =
      GetFrame().Selection().ComputeVisibleSelectionInFlatTree();
  EXPECT_EQ(text, selection.Start().ComputeContainerNode());
  EXPECT_EQ(10, selection.Start().ComputeOffsetInContainerNode());
  EXPECT_EQ(text, selection.End().ComputeContainerNode());
  EXPECT_EQ(10, selection.End().ComputeOffsetInContainerNode());
}

// Flaky on Android: http://crbug.com/1104700
#if BUILDFLAG(IS_ANDROID)
#define MAYBE_ApplyTextSuggestion DISABLED_ApplyTextSuggestion
#else
#define MAYBE_ApplyTextSuggestion ApplyTextSuggestion
#endif
TEST_F(TextSuggestionControllerTest, MAYBE_ApplyTextSuggestion) {
  SetBodyContent(
      "<div contenteditable>"
      "word1 word2 word3 word4"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  auto* text = To<Text>(div->firstChild());

  // Add marker on "word1". This marker should *not* be cleared by the
  // replace operation.
  GetDocument().Markers().AddSuggestionMarker(
      EphemeralRange(Position(text, 0), Position(text, 5)),
      SuggestionMarkerProperties::Builder()
          .SetSuggestions(Vector<String>({"marker1"}))
          .Build());

  // Add marker on "word1 word2 word3 word4". This marker should *not* be
  // cleared by the replace operation.
  GetDocument().Markers().AddSuggestionMarker(
      EphemeralRange(Position(text, 0), Position(text, 23)),
      SuggestionMarkerProperties::Builder()
          .SetSuggestions(Vector<String>({"marker2"}))
          .Build());

  // Add marker on "word2 word3". This marker should *not* be cleared by the
  // replace operation.
  GetDocument().Markers().AddSuggestionMarker(
      EphemeralRange(Position(text, 6), Position(text, 17)),
      SuggestionMarkerProperties::Builder()
          .SetSuggestions(Vector<String>({"marker3"}))
          .Build());

  // Add marker on "word4". This marker should *not* be cleared by the
  // replace operation.
  GetDocument().Markers().AddSuggestionMarker(
      EphemeralRange(Position(text, 18), Position(text, 23)),
      SuggestionMarkerProperties::Builder()
          .SetSuggestions(Vector<String>({"marker4"}))
          .Build());

  // Add marker on "word1 word2". This marker should be cleared by the
  // replace operation.
  GetDocument().Markers().AddSuggestionMarker(
      EphemeralRange(Position(text, 0), Position(text, 11)),
      SuggestionMarkerProperties::Builder()
          .SetSuggestions(Vector<String>({"marker5"}))
          .Build());

  // Add marker on "word3 word4". This marker should be cleared by the
  // replace operation.
  GetDocument().Markers().AddSuggestionMarker(
      EphemeralRange(Position(text, 12), Position(text, 23)),
      SuggestionMarkerProperties::Builder()
          .SetSuggestions(Vector<String>({"marker6"}))
          .Build());

  // Select immediately before word2.
  GetDocument().GetFrame()->Selection().SetSelectionAndEndTyping(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 6), Position(text, 6))
          .Build());

  // Replace "word2 word3" with "marker3" (marker should have tag 3; tags start
  // from 1, not 0).
  GetDocument().GetFrame()->GetTextSuggestionController().ApplyTextSuggestion(
      3, 0);

  // This returns the markers sorted by start offset; we need them sorted by
  // start *and* end offset, since we have multiple markers starting at 0.
  DocumentMarkerVector markers = GetDocument().Markers().MarkersFor(*text);
  std::sort(markers.begin(), markers.end(),
            [](const DocumentMarker* marker1, const DocumentMarker* marker2) {
              if (marker1->StartOffset() != marker2->StartOffset())
                return marker1->StartOffset() < marker2->StartOffset();
              return marker1->EndOffset() < marker2->EndOffset();
            });

  EXPECT_EQ(4u, markers.size());

  // marker1
  EXPECT_EQ(0u, markers[0]->StartOffset());
  EXPECT_EQ(5u, markers[0]->EndOffset());

  // marker2
  EXPECT_EQ(0u, markers[1]->StartOffset());
  EXPECT_EQ(19u, markers[1]->EndOffset());

  // marker3
  EXPECT_EQ(6u, markers[2]->StartOffset());
  EXPECT_EQ(13u, markers[2]->EndOffset());

  const auto* const suggestion_marker = To<SuggestionMarker>(markers[2].Get());
  EXPECT_EQ(1u, suggestion_marker->Suggestions().size());
  EXPECT_EQ(String("word2 word3"), suggestion_marker->Suggestions()[0]);

  // marker4
  EXPECT_EQ(14u, markers[3]->StartOffset());
  EXPECT_EQ(19u, markers[3]->EndOffset());

  // marker5 and marker6 should've been cleared

  // Cursor should be at end of replaced text
  const VisibleSelectionInFlatTree& selection =
      GetFrame().Selection().ComputeVisibleSelectionInFlatTree();
  EXPECT_EQ(text, selection.Start().ComputeContainerNode());
  EXPECT_EQ(13, selection.Start().ComputeOffsetInContainerNode());
  EXPECT_EQ(text, selection.End().ComputeContainerNode());
  EXPECT_EQ(13, selection.End().ComputeOffsetInContainerNode());
}

TEST_F(TextSuggestionControllerTest,
       ApplyingMisspellingTextSuggestionClearsMarker) {
  SetBodyContent(
      "<div contenteditable>"
      "mispelled"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  auto* text = To<Text>(div->firstChild());

  // Add marker on "mispelled". This marker should be cleared by the replace
  // operation.
  GetDocument().Markers().AddSuggestionMarker(
      EphemeralRange(Position(text, 0), Position(text, 9)),
      SuggestionMarkerProperties::Builder()
          .SetType(SuggestionMarker::SuggestionType::kMisspelling)
          .SetSuggestions(Vector<String>({"misspelled"}))
          .Build());

  // Check the tag for the marker that was just added (the current tag value is
  // not reset between test cases).
  int32_t marker_tag =
      To<SuggestionMarker>(GetDocument().Markers().MarkersFor(*text)[0].Get())
          ->Tag();

  // Select immediately before "mispelled".
  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 0), Position(text, 0))
          .Build(),
      SetSelectionOptions());

  // Replace "mispelled" with "misspelled".
  GetDocument().GetFrame()->GetTextSuggestionController().ApplyTextSuggestion(
      marker_tag, 0);

  EXPECT_EQ(0u, GetDocument().Markers().MarkersFor(*text).size());
  EXPECT_EQ("misspelled", text->textContent());
}

TEST_F(TextSuggestionControllerTest,
       ApplyingMisspellingTextSuggestionShouldNotChangeDOM) {
  SetBodyContent(
      "<div contenteditable>"
      "<span style='color: rgb(255, 0, 0);'>"
      "this is a mispelled."
      "</span>"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Element* span = To<Element>(div->firstChild());
  Text* text = To<Text>(span->firstChild());

  // Add marker on "mispelled". This marker should be cleared by the replace
  // operation.
  GetDocument().Markers().AddSuggestionMarker(
      EphemeralRange(Position(text, 10), Position(text, 19)),
      SuggestionMarkerProperties::Builder()
          .SetType(SuggestionMarker::SuggestionType::kMisspelling)
          .SetSuggestions(Vector<String>({"misspelled"}))
          .Build());

  // Check the tag for the marker that was just added (the current tag value is
  // not reset between test cases).
  int32_t marker_tag =
      To<SuggestionMarker>(GetDocument().Markers().MarkersFor(*text)[0].Get())
          ->Tag();

  // Select immediately before "mispelled".
  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 10), Position(text, 10))
          .Build(),
      SetSelectionOptions());

  // Replace "mispelled" with "misspelled".
  GetDocument().GetFrame()->GetTextSuggestionController().ApplyTextSuggestion(
      marker_tag, 0);

  EXPECT_EQ(0u, GetDocument().Markers().MarkersFor(*text).size());
  EXPECT_EQ(
      "<span style=\"color: rgb(255, 0, 0);\">this is a misspelled.</span>",
      div->innerHTML());
}

TEST_F(TextSuggestionControllerTest, DeleteActiveSuggestionRange_DeleteAtEnd) {
  SetBodyContent(
      "<div contenteditable>"
      "word1 word2"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  // Mark "word2" as the active suggestion range
  GetDocument().Markers().AddActiveSuggestionMarker(
      EphemeralRange(Position(text, 6), Position(text, 11)),
      Color::kTransparent, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kBlack, Color::kBlack);
  // Select immediately before word2
  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 6), Position(text, 6))
          .Build(),
      SetSelectionOptions());
  GetDocument()
      .GetFrame()
      ->GetTextSuggestionController()
      .DeleteActiveSuggestionRange();

  EXPECT_EQ("word1\xA0", text->textContent());
}

TEST_F(TextSuggestionControllerTest,
       DeleteActiveSuggestionRange_DeleteInMiddle) {
  SetBodyContent(
      "<div contenteditable>"
      "word1 word2 word3"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  // Mark "word2" as the active suggestion range
  GetDocument().Markers().AddActiveSuggestionMarker(
      EphemeralRange(Position(text, 6), Position(text, 11)),
      Color::kTransparent, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kBlack, Color::kBlack);
  // Select immediately before word2
  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 6), Position(text, 6))
          .Build(),
      SetSelectionOptions());
  GetDocument()
      .GetFrame()
      ->GetTextSuggestionController()
      .DeleteActiveSuggestionRange();

  // One of the extra spaces around "word2" should have been removed
  EXPECT_EQ("word1 word3", text->textContent());
}

TEST_F(TextSuggestionControllerTest,
       DeleteActiveSuggestionRange_DeleteAtBeginningWithSpaceAfter) {
  SetBodyContent(
      "<div contenteditable>"
      "word1 word2"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  // Mark "word1" as the active suggestion range
  GetDocument().Markers().AddActiveSuggestionMarker(
      EphemeralRange(Position(text, 0), Position(text, 5)), Color::kTransparent,
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kBlack, Color::kBlack);
  // Select immediately before word1
  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 0), Position(text, 0))
          .Build(),
      SetSelectionOptions());
  GetDocument()
      .GetFrame()
      ->GetTextSuggestionController()
      .DeleteActiveSuggestionRange();

  // The space after "word1" should have been removed (to avoid leaving an
  // empty space at the beginning of the composition)
  EXPECT_EQ("word2", text->textContent());
}

TEST_F(TextSuggestionControllerTest,
       DeleteActiveSuggestionRange_DeleteEntireRange) {
  SetBodyContent(
      "<div contenteditable>"
      "word1"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  // Mark "word1" as the active suggestion range
  GetDocument().Markers().AddActiveSuggestionMarker(
      EphemeralRange(Position(text, 0), Position(text, 5)), Color::kTransparent,
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kBlack, Color::kBlack);
  // Select immediately before word1
  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 0), Position(text, 0))
          .Build(),
      SetSelectionOptions());
  GetDocument()
      .GetFrame()
      ->GetTextSuggestionController()
      .DeleteActiveSuggestionRange();

  EXPECT_EQ("", text->textContent());
}

// The following two cases test situations that probably shouldn't occur in
// normal use (spell check/suggestoin markers not spanning a whole word), but
// are included anyway to verify that DeleteActiveSuggestionRange() is
// well-behaved in these cases

TEST_F(TextSuggestionControllerTest,
       DeleteActiveSuggestionRange_DeleteRangeWithTextBeforeAndSpaceAfter) {
  SetBodyContent(
      "<div contenteditable>"
      "word1word2 word3"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  // Mark "word2" as the active suggestion range
  GetDocument().Markers().AddActiveSuggestionMarker(
      EphemeralRange(Position(text, 5), Position(text, 10)),
      Color::kTransparent, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kBlack, Color::kBlack);
  // Select immediately before word2
  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 5), Position(text, 5))
          .Build(),
      SetSelectionOptions());
  GetDocument()
      .GetFrame()
      ->GetTextSuggestionController()
      .DeleteActiveSuggestionRange();

  EXPECT_EQ("word1 word3", text->textContent());
}

TEST_F(TextSuggestionControllerTest,
       DeleteActiveSuggestionRange_DeleteRangeWithSpaceBeforeAndTextAfter) {
  SetBodyContent(
      "<div contenteditable>"
      "word1 word2word3"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  // Mark "word2" as the active suggestion range
  GetDocument().Markers().AddActiveSuggestionMarker(
      EphemeralRange(Position(text, 6), Position(text, 11)),
      Color::kTransparent, ImeTextSpanThickness::kThin,
      ImeTextSpanUnderlineStyle::kSolid, Color::kBlack, Color::kBlack);
  // Select immediately before word2
  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 6), Position(text, 6))
          .Build(),
      SetSelectionOptions());
  GetDocument()
      .GetFrame()
      ->GetTextSuggestionController()
      .DeleteActiveSuggestionRange();

  EXPECT_EQ("word1 word3", text->textContent());
}

TEST_F(TextSuggestionControllerTest,
       DeleteActiveSuggestionRange_DeleteAtBeginningWithTextAfter) {
  SetBodyContent(
      "<div contenteditable>"
      "word1word2"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  // Mark "word1" as the active suggestion range
  GetDocument().Markers().AddActiveSuggestionMarker(
      EphemeralRange(Position(text, 0), Position(text, 5)), Color::kTransparent,
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kBlack, Color::kBlack);
  // Select immediately before word1
  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 0), Position(text, 0))
          .Build(),
      SetSelectionOptions());
  GetDocument()
      .GetFrame()
      ->GetTextSuggestionController()
      .DeleteActiveSuggestionRange();

  EXPECT_EQ("word2", text->textContent());
}

TEST_F(TextSuggestionControllerTest,
       DeleteActiveSuggestionRange_OnNewWordAddedToDictionary) {
  SetBodyContent(
      "<div contenteditable>"
      "embiggen"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  // Mark "embiggen" as misspelled
  GetDocument().Markers().AddSpellingMarker(
      EphemeralRange(Position(text, 0), Position(text, 8)));
  // Select inside before "embiggen"
  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 1), Position(text, 1))
          .Build(),
      SetSelectionOptions());

  // Add some other word to the dictionary
  GetDocument()
      .GetFrame()
      ->GetTextSuggestionController()
      .OnNewWordAddedToDictionary("cromulent");
  // Verify the spelling marker is still present
  EXPECT_NE(nullptr, GetDocument()
                         .GetFrame()
                         ->GetSpellChecker()
                         .GetSpellCheckMarkerGroupUnderSelection());

  // Add "embiggen" to the dictionary
  GetDocument()
      .GetFrame()
      ->GetTextSuggestionController()
      .OnNewWordAddedToDictionary("embiggen");
  // Verify the spelling marker is gone
  EXPECT_EQ(nullptr, GetDocument()
                         .GetFrame()
                         ->GetSpellChecker()
                         .GetSpellCheckMarkerGroupUnderSelection());
}

TEST_F(TextSuggestionControllerTest, CallbackHappensAfterDocumentDestroyed) {
  LocalFrame& frame = *GetDocument().GetFrame();
  frame.DomWindow()->FrameDestroyed();

  // Shouldn't crash
  frame.GetTextSuggestionController().SuggestionMenuTimeoutCallback(0);
}

TEST_F(TextSuggestionControllerTest, SuggestionMarkerWithEmptySuggestion) {
  SetBodyContent(
      "<div contenteditable>"
      "hello"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  auto* text = To<Text>(div->firstChild());

  // Set suggestion marker with empty suggestion list.
  GetDocument().Markers().AddSuggestionMarker(
      EphemeralRange(Position(text, 0), Position(text, 5)),
      SuggestionMarkerProperties::Builder()
          .SetSuggestions(Vector<String>())
          .Build());

  // Set the caret inside the word.
  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 3), Position(text, 3))
          .Build(),
      SetSelectionOptions());

  // Handle potential suggestion tap on the caret position.
  GetDocument()
      .GetFrame()
      ->GetTextSuggestionController()
      .HandlePotentialSuggestionTap(PositionInFlatTree(text, 3));

  // We don't trigger menu in this case so there shouldn't be any mojom
  // connection available.
  EXPECT_FALSE(IsTextSuggestionHostAvailable());

  const VisibleSelectionInFlatTree& selection =
      GetFrame().Selection().ComputeVisibleSelectionInFlatTree();
  EXPECT_FALSE(selection.IsNone());

  const EphemeralRangeInFlatTree& range_to_check =
      ComputeRangeSurroundingCaret(selection.Start());

  const HeapVector<std::pair<Member<const Text>, Member<DocumentMarker>>>&
      node_suggestion_marker_pairs =
          GetFrame().GetDocument()->Markers().MarkersIntersectingRange(
              range_to_check, DocumentMarker::MarkerTypes::Suggestion());
  EXPECT_FALSE(node_suggestion_marker_pairs.empty());

  // Calling ShowSuggestionMenu() shouldn't crash. See crbug.com/901135.
  // ShowSuggestionMenu() may still get called because of race condition.
  ShowSuggestionMenu(node_suggestion_marker_pairs, 3);
}

TEST_F(TextSuggestionControllerTest, SuggestionMarkerWithSuggestion) {
  SetBodyContent(
      "<div contenteditable>"
      "hello"
      "</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  auto* text = To<Text>(div->firstChild());

  // Set suggestion marker with two suggestions.
  GetDocument().Markers().AddSuggestionMarker(
      EphemeralRange(Position(text, 0), Position(text, 5)),
      SuggestionMarkerProperties::Builder()
          .SetSuggestions(Vector<String>({"marker1", "marker2"}))
          .Build());

  // Set the caret inside the word.
  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 3), Position(text, 3))
          .Build(),
      SetSelectionOptions());

  // Handle potential suggestion tap on the caret position.
  GetDocument()
      .GetFrame()
      ->GetTextSuggestionController()
      .HandlePotentialSuggestionTap(PositionInFlatTree(text, 3));

  EXPECT_TRUE(IsTextSuggestionHostAvailable());
}

}  // namespace blink

"""

```