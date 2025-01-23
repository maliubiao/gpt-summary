Response:
My thought process to analyze the code and generate the summary goes through these steps:

1. **Understand the Goal:** The request asks for a functional summary of the given C++ code file (`frame_selection_test.cc`), highlighting its relationship to web technologies (JavaScript, HTML, CSS), providing examples of logic, common errors, debugging clues, and a final summary for this first part of the file.

2. **Identify the Core Function:** The file name itself, `frame_selection_test.cc`, strongly suggests that this code is for testing the `FrameSelection` class in the Blink rendering engine. This immediately tells me the central theme.

3. **Scan for Key Classes and Methods:** I'll quickly scan the `#include` directives to see what other classes and components are being used. This provides context and reveals the scope of the testing. I see:
    * `FrameSelection`: The main subject of the tests.
    * `Document`, `Element`, `Text`: DOM-related classes, indicating tests involve manipulating the document structure.
    * `EphemeralRange`, `Position`, `VisiblePosition`: Classes related to tracking locations and ranges within the document.
    * `SelectionController`, `SelectionModifier`, `SelectionTemplate`, `SelectionInDOMTree`, `SelectionInFlatTree`: Classes involved in managing and representing selections.
    * `EditingTestBase`:  Indicates this is part of a testing framework.
    * `LocalFrameView`: Related to the frame's viewport and rendering.
    * `EventHandler`: Implies interaction and event handling tests might be present.
    * `ContextMenuController`: Suggests testing context menu integration with selections.
    * The presence of `FlatTreeTraversal` indicates testing scenarios involving Shadow DOM.

4. **Examine Test Fixture and Helper Functions:** The `FrameSelectionTest` class inherits from `EditingTestBase`, which likely provides setup and teardown functionality for the test environment. I'll look for helper functions within the test fixture:
    * `VisibleSelectionInDOMTree()`, `GetVisibleSelectionInFlatTree()`:  Return the current selection state in different DOM representations.
    * `AppendTextNode()`: A convenience function for adding text to the document.
    * `CaretPosition()`: Returns the current caret position.
    * `SelectWordAroundPosition()`, `SelectWordAroundCaret()`, `SelectSentenceAroundCaret()`: Functions that simulate selecting words or sentences.
    * `ResetAndPlaceCaret()`: Sets the caret to a specific position.
    * `HasContextMenu()`: Checks if a context menu is being displayed.
    * `MoveRangeSelectionInternal()`:  Programmatically moves the selection range.

5. **Analyze Individual Test Cases (Focus on the First Part):** I will go through the `TEST_F` blocks, which represent individual test cases. For each test, I'll try to understand:
    * **What is being set up?** (e.g., creating elements, setting content)
    * **What action is being performed?** (e.g., calling a `FrameSelection` method)
    * **What is being asserted?** (e.g., checking the selected text, caret position, visibility of handles/context menus).

6. **Relate to Web Technologies:**  As I analyze the test cases, I'll look for connections to HTML, CSS, and JavaScript:
    * **HTML:** Tests often manipulate HTML structure using methods like `SetBodyContent`, `AppendChild`, and querying elements by ID. The tests check how selections behave with different HTML elements (divs, spans, input fields, select elements).
    * **CSS:** Some tests involve setting CSS styles (e.g., `display: none`, `width`, `font-size`) and observing how these styles affect selection behavior.
    * **JavaScript:** While the test code is in C++, the functionality being tested directly relates to how users interact with web pages through JavaScript APIs for selection, like `window.getSelection()`. The tests implicitly verify how Blink's selection mechanism aligns with expected browser behavior that JavaScript would rely on.

7. **Identify Logic and Examples:** I'll look for tests that demonstrate specific selection behaviors or algorithms. For example, the `SelectWordAroundCaret` and `SelectSentenceAroundCaret` tests show how the engine determines word and sentence boundaries. I can then provide hypothetical inputs and expected outputs.

8. **Pinpoint Potential User/Programming Errors:** Based on the test cases, I can infer common errors:
    * Selecting across non-contiguous text (due to `display: none`).
    * Unexpected behavior at the beginning or end of text/sentences.
    * Issues with punctuation and whitespace in word/sentence selection.
    * Incorrectly assuming selection behavior in Shadow DOM mirrors regular DOM.

9. **Trace User Actions to the Code:** I'll consider how user interactions in a browser would trigger the code being tested:
    * **Mouse clicks and drags:**  Leading to range selections.
    * **Double-clicks and triple-clicks:** Triggering word and sentence selection.
    * **Keyboard navigation (Shift + arrow keys):** Extending selections.
    * **Context menu interactions:**  Showing the context menu based on the selection.
    * **`document.execCommand` calls:**  Triggering editing actions that might affect the selection.

10. **Synthesize the Summary for Part 1:**  Based on the analysis of the first part of the file, I'll summarize the overall purpose, the main functionalities being tested, and key observations.

**Self-Correction/Refinement during the Process:**

* **Initial Overgeneralization:** I might initially think every test is directly related to user interaction. However, some tests are more about internal logic and edge cases (like the Shadow DOM test or the test with an unselectable root). I need to refine my descriptions to reflect these nuances.
* **Focusing Too Much on Implementation Details:** I need to avoid explaining the C++ code itself too deeply. The focus is on the *functionality* being tested, not the implementation details.
* **Missing Connections to Web Technologies:** I need to actively make the connections to JavaScript, HTML, and CSS explicit. For example, saying "this test verifies how word selection works" is good, but explaining *how* this relates to what a JavaScript developer expects from `window.getSelection()` is better.
* **Ambiguous Examples:**  My examples of logic or errors should be clear and concrete. Instead of saying "selection might be wrong," I should provide a specific scenario and the expected vs. actual outcome.

By following these steps and iteratively refining my understanding, I can produce a comprehensive and accurate summary that addresses all parts of the request.
好的，让我们来分析一下 `blink/renderer/core/editing/frame_selection_test.cc` 这个文件的功能。

**文件功能归纳 (针对提供的第 1 部分):**

`frame_selection_test.cc` 文件是 Chromium Blink 引擎中用于测试 `FrameSelection` 类功能的单元测试文件。 `FrameSelection` 类负责管理和表示网页中用户选中的内容。这个测试文件通过编写一系列测试用例，来验证 `FrameSelection` 类的各种方法和功能是否按预期工作，包括：

* **基本选择操作:**  测试设置和获取选择，包括 DOM 树和 Flat 树两种表示形式。
* **光标操作:**  测试光标的位置和移动。
* **基于粒度的选择:** 测试以单词、句子为单位进行选择的功能 (`SelectWordAroundCaret`, `SelectSentenceAroundCaret`)。
* **选择范围的获取:** 测试获取光标周围单词或句子的选择范围 (`GetWordSelectionRangeAroundCaret`, `GetSelectionRangeAroundCaretForTesting`).
* **选择的修改:**  测试通过编程方式修改选择范围 (`Modify`).
* **范围选择:** 测试拖动鼠标产生的范围选择 (`MoveRangeSelectionInternal`).
* **`SelectAll` 操作:** 测试选中页面所有内容的功能。
* **处理选择句柄和上下文菜单:** 测试选择操作是否正确显示或隐藏选择句柄和上下文菜单。
* **在 Shadow DOM 中的选择:** 测试在 Shadow DOM 环境下的选择行为。
* **处理无效选择:**  测试在遇到无效位置时的选择行为，防止程序崩溃。
* **与编辑命令的交互:** 测试选择状态在执行编辑命令（如 "bold"）后的保持情况。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件虽然是用 C++ 编写的，但它测试的功能直接关系到用户在浏览器中与网页进行的交互，这些交互通常涉及到 JavaScript、HTML 和 CSS：

* **HTML:** `FrameSelection` 处理的是 HTML 结构中的文本和元素的选择。测试用例会创建和操作 HTML 元素，例如 `div`, `span`, `input`, `select`, `option` 等，来模拟不同的网页结构。
    * **举例:** `SetBodyContent("<div id=sample>0123456789</div>abc");`  这行代码模拟了在 HTML body 中创建了一个带有 id 的 `div` 元素和一个文本节点。测试会基于这个 HTML 结构进行选择操作。
* **CSS:** CSS 样式会影响元素的布局和渲染，从而影响用户的选择行为。测试用例会设置 CSS 样式，例如 `display: none`, `width`, `font-size`，来验证 `FrameSelection` 是否能正确处理这些情况。
    * **举例:** `sample->setAttribute(html_names::kStyleAttr, AtomicString("display:none"));` 这行代码设置了 `div` 元素的 `display` 样式为 `none`，测试会验证在这种情况下选择的行为是否符合预期。
* **JavaScript:**  JavaScript 代码可以通过 `window.getSelection()` API 获取和操作用户的选择。`FrameSelection` 的功能是 Blink 引擎提供给 JavaScript 选择 API 的底层实现。这个测试文件验证了 Blink 的实现是否与 JavaScript 的期望行为一致。
    * **举例:**  当用户在网页上双击一个单词时，浏览器内部会调用 `FrameSelection` 的相关方法来选中这个单词。`SelectWordAroundCaret` 这个测试用例就模拟了这种行为，验证了单词选择的逻辑是否正确。

**逻辑推理及假设输入与输出:**

许多测试用例都包含了逻辑推理，例如，测试 `SelectWordAroundCaret` 需要判断在光标的不同位置，哪个单词会被选中。

* **假设输入:** 光标位于文本 "Foo Bar  Baz," 中的 'o' 字母之后 (位置 2)。
* **预期输出:**  `SelectWordAroundPosition(Position(text, 2))` 应该返回 `true`，并且选中的文本应该是 "Foo"。

* **假设输入:** 光标位于文本 "This is a sentence." 的句号之后。
* **预期输出:** `SelectWordAroundCaret()` 应该返回 `false`，因为在句号之后没有可选择的单词。

**涉及用户或编程常见的使用错误:**

这个测试文件间接地反映了一些用户或编程中常见的与选择相关的错误：

* **选择隐藏内容:** 用户可能不期望选中 `display: none` 的元素内的文本。测试用例 `FirstEphemeralRangeOf` 验证了这种情况下的选择行为。
* **在非连续文本中选择:** 由于元素的浮动、定位等 CSS 属性，文本可能在视觉上不连续。开发者需要确保选择逻辑在这种情况下也能正常工作。
* **处理标点符号和空格:** 在单词和句子选择中，正确处理标点符号和空格的边界至关重要。测试用例 `SelectWordAroundCaret` 和 `SelectSentenceAroundCaret` 就包含了对这些情况的测试。
* **Shadow DOM 中的选择边界:** 开发者需要理解 Shadow DOM 如何影响选择的边界。`ModifyExtendWithFlatTree` 和 `CaretInShadowTree` 等测试用例覆盖了这些场景。
* **程序化修改选择的意外行为:** 开发者在通过 JavaScript 代码修改选择时，可能会遇到一些意想不到的结果，例如，选择范围不正确或导致错误。测试用例 `MoveRangeSelectionInternal` 帮助验证这些 API 的正确性。

**用户操作如何一步步到达这里 (作为调试线索):**

当开发者在调试与选择相关的问题时，可能会需要查看 `FrameSelection` 的行为。以下是一些可能导致代码执行到 `frame_selection_test.cc` 的用户操作路径：

1. **用户鼠标操作:**
   * **点击:**  将光标放置在特定位置。测试用例 `ResetAndPlaceCaret` 模拟了这种操作。
   * **双击/三击:** 选中单词或句子。测试用例 `SelectWordAroundCaret` 和 `SelectSentenceAroundCaret` 模拟了这些操作。
   * **拖动:** 创建一个范围选择。测试用例 `MoveRangeSelectionInternal` 模拟了这种操作。

2. **用户键盘操作:**
   * **方向键:** 移动光标。虽然测试文件中没有直接模拟方向键的测试，但光标的移动是选择的基础。
   * **Shift + 方向键:** 扩展或收缩选择范围。 `Selection().Modify()` 方法的测试用例模拟了这种行为。
   * **Ctrl/Cmd + A:** 选中所有内容。测试用例 `SelectAll` 模拟了这种操作。

3. **用户上下文菜单操作:**
   * **右键点击:**  显示上下文菜单。测试用例 `SelectAroundCaret_ShouldShowContextMenu` 验证了上下文菜单的显示逻辑。

4. **JavaScript 代码触发:**
   * 网页上的 JavaScript 代码调用 `window.getSelection()` 或其他选择相关的 API，最终会调用到 Blink 引擎的 `FrameSelection` 类。

当开发者发现网页上的选择行为不符合预期时，他们可能会通过以下步骤进行调试：

1. **重现问题:** 在浏览器中复现导致选择错误的步骤。
2. **查找相关代码:**  根据错误的现象，定位到可能负责处理选择的相关 Blink 引擎代码，`frame_selection.cc` 和 `frame_selection_test.cc` 是重要的起点。
3. **查看测试用例:**  在 `frame_selection_test.cc` 中查找是否存在类似的测试用例，这可以帮助理解预期的行为。
4. **编写新的测试用例:** 如果没有相关的测试用例，开发者可以编写新的测试用例来复现和验证 bug。
5. **单步调试:**  通过断点调试 `FrameSelection` 的代码，观察变量的值和执行流程，找出问题所在。

**总结 (针对第 1 部分):**

`frame_selection_test.cc` (提供的第 1 部分) 主要关注于测试 `FrameSelection` 类中与基本选择操作、基于粒度的选择、范围选择、`SelectAll` 功能以及处理选择句柄和上下文菜单相关的逻辑。这些测试用例覆盖了用户常见的选择操作场景，并验证了在不同 HTML 结构和 CSS 样式下选择行为的正确性。 它们也间接反映了在进行选择功能开发时需要注意的用户使用习惯和潜在的编程错误。 开发者可以通过分析这些测试用例，理解 `FrameSelection` 的工作原理，并在调试选择相关问题时找到线索。

### 提示词
```
这是目录为blink/renderer/core/editing/frame_selection_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/frame_selection.h"

#include <memory>
#include "base/memory/scoped_refptr.h"
#include "base/test/scoped_feature_list.h"
#include "testing/gmock/include/gmock/gmock-matchers.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/web/web_range.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_caret.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/selection_controller.h"
#include "third_party/blink/renderer/core/editing/selection_modifier.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/layout_block.h"
#include "third_party/blink/renderer/core/page/context_menu_controller.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/testing/fake_display_item_client.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/vector2d.h"

namespace blink {

using testing::IsNull;

class FrameSelectionTest : public EditingTestBase {
 public:
  FrameSelectionTest()
      : root_paint_property_client_(
            MakeGarbageCollected<FakeDisplayItemClient>("root")),
        root_paint_chunk_id_(root_paint_property_client_->Id(),
                             DisplayItem::kUninitializedType) {}
  Persistent<FakeDisplayItemClient> root_paint_property_client_;
  PaintChunk::Id root_paint_chunk_id_;

 protected:
  VisibleSelection VisibleSelectionInDOMTree() const {
    return Selection().ComputeVisibleSelectionInDOMTree();
  }
  VisibleSelectionInFlatTree GetVisibleSelectionInFlatTree() const {
    return Selection().ComputeVisibleSelectionInFlatTree();
  }

  Text* AppendTextNode(const String& data);

  PositionWithAffinity CaretPosition() const {
    return Selection().frame_caret_->CaretPosition();
  }

  Page& GetPage() const { return GetDummyPageHolder().GetPage(); }

  // Returns if a word is is selected.
  bool SelectWordAroundPosition(const Position&);

  // Returns whether the selection was accomplished.
  bool SelectWordAroundCaret();

  // Returns whether the selection was accomplished.
  bool SelectSentenceAroundCaret();

  // Places the caret on the |text| at |selection_index|.
  void ResetAndPlaceCaret(Text* text, size_t selection_index) {
    ASSERT_LE(selection_index,
              static_cast<size_t>(std::numeric_limits<int>::max()));
    Selection().SetSelection(
        SelectionInDOMTree::Builder()
            .Collapse(Position(text, static_cast<int>(selection_index)))
            .Build(),
        SetSelectionOptions());
  }

  // Returns whether a context menu is being displayed.
  bool HasContextMenu() {
    return GetDocument()
        .GetPage()
        ->GetContextMenuController()
        .ContextMenuNodeForFrame(GetDocument().GetFrame());
  }

  void MoveRangeSelectionInternal(const Position& base,
                                  const Position& extent,
                                  TextGranularity granularity) {
    Selection().MoveRangeSelectionInternal(
        SelectionInDOMTree::Builder().SetBaseAndExtent(base, extent).Build(),
        granularity);
  }

 private:
  Persistent<Text> text_node_;
};

Text* FrameSelectionTest::AppendTextNode(const String& data) {
  Text* text = GetDocument().createTextNode(data);
  GetDocument().body()->AppendChild(text);
  return text;
}

bool FrameSelectionTest::SelectWordAroundPosition(const Position& position) {
  Selection().SetSelection(
      SelectionInDOMTree::Builder().Collapse(position).Build(),
      SetSelectionOptions());
  return Selection().SelectWordAroundCaret();
}

bool FrameSelectionTest::SelectWordAroundCaret() {
  return Selection().SelectAroundCaret(TextGranularity::kWord,
                                       HandleVisibility::kNotVisible,
                                       ContextMenuVisibility::kNotVisible);
}

bool FrameSelectionTest::SelectSentenceAroundCaret() {
  return Selection().SelectAroundCaret(TextGranularity::kSentence,
                                       HandleVisibility::kNotVisible,
                                       ContextMenuVisibility::kNotVisible);
}

TEST_F(FrameSelectionTest, FirstEphemeralRangeOf) {
  SetBodyContent("<div id=sample>0123456789</div>abc");
  Element* const sample = GetDocument().getElementById(AtomicString("sample"));
  Node* const text = sample->firstChild();
  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .SetBaseAndExtent(EphemeralRange(
                                   Position(text, 3), Position(text, 6)))
                               .Build(),
                           SetSelectionOptions());
  sample->setAttribute(html_names::kStyleAttr, AtomicString("display:none"));
  // Move |VisibleSelection| before "abc".
  UpdateAllLifecyclePhasesForTest();
  const EphemeralRange& range =
      FirstEphemeralRangeOf(Selection().ComputeVisibleSelectionInDOMTree());
  EXPECT_EQ(Position(sample->nextSibling(), 0), range.StartPosition())
      << "firstRange() should return current selection value";
  EXPECT_EQ(Position(sample->nextSibling(), 0), range.EndPosition());
}

TEST_F(FrameSelectionTest, SetValidSelection) {
  Text* text = AppendTextNode("Hello, World!");
  UpdateAllLifecyclePhasesForTest();
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 0), Position(text, 5))
          .Build(),
      SetSelectionOptions());
  EXPECT_FALSE(Selection().ComputeVisibleSelectionInDOMTree().IsNone());
}

#define EXPECT_EQ_SELECTED_TEXT(text) \
  EXPECT_EQ(text, Selection().SelectedText().Utf8())

TEST_F(FrameSelectionTest, SelectWordAroundCaret) {
  // "Foo Bar  Baz,"
  Text* text = AppendTextNode("Foo Bar&nbsp;&nbsp;Baz,");
  UpdateAllLifecyclePhasesForTest();

  // "Fo|o Bar  Baz,"
  EXPECT_TRUE(SelectWordAroundPosition(Position(text, 2)));
  EXPECT_EQ_SELECTED_TEXT("Foo");
  // "Foo| Bar  Baz,"
  EXPECT_TRUE(SelectWordAroundPosition(Position(text, 3)));
  EXPECT_EQ_SELECTED_TEXT("Foo");
  // "Foo Bar | Baz,"
  EXPECT_FALSE(SelectWordAroundPosition(Position(text, 13)));
  // "Foo Bar  Baz|,"
  EXPECT_TRUE(SelectWordAroundPosition(Position(text, 22)));
  EXPECT_EQ_SELECTED_TEXT("Baz");
}

// crbug.com/657996
TEST_F(FrameSelectionTest, SelectWordAroundCaret2) {
  SetBodyContent(
      "<p style='width:70px; font-size:14px'>foo bar<em>+</em> baz</p>");
  // "foo bar
  //  b|az"
  Node* const baz = GetDocument().body()->firstChild()->lastChild();
  EXPECT_TRUE(SelectWordAroundPosition(Position(baz, 2)));
  EXPECT_EQ_SELECTED_TEXT("baz");
}

TEST_F(FrameSelectionTest, SelectAroundCaret_Word) {
  Text* text = AppendTextNode("This is a sentence.");
  UpdateAllLifecyclePhasesForTest();

  // Beginning of text: |This is a sentence.
  ResetAndPlaceCaret(text, strlen(""));
  EXPECT_TRUE(SelectWordAroundCaret());
  EXPECT_EQ_SELECTED_TEXT("This");

  // Beginning of a word: This |is a sentence.
  ResetAndPlaceCaret(text, strlen("This "));
  EXPECT_TRUE(SelectWordAroundCaret());
  EXPECT_EQ_SELECTED_TEXT("is");

  // Somewhere in a word: This is a s|entence.
  ResetAndPlaceCaret(text, strlen("This is a s"));
  EXPECT_TRUE(SelectWordAroundCaret());
  EXPECT_EQ_SELECTED_TEXT("sentence");

  // End a word: This| is a sentence.
  ResetAndPlaceCaret(text, strlen("This"));
  EXPECT_TRUE(SelectWordAroundCaret());
  EXPECT_EQ_SELECTED_TEXT("This");

  // End a word with punctuation: This is a sentence|.
  ResetAndPlaceCaret(text, strlen("This is a sentence"));
  EXPECT_TRUE(SelectWordAroundCaret());
  EXPECT_EQ_SELECTED_TEXT("sentence");

  // End a word after punctuation: This is a sentence.|
  ResetAndPlaceCaret(text, strlen("This is a sentence."));
  EXPECT_FALSE(SelectWordAroundCaret());
  EXPECT_EQ_SELECTED_TEXT("");

  // Beginning of a symbol: Some emojis |😀 🍀.
  text = AppendTextNode(String::FromUTF8("Some emojis 😀 🍀."));
  UpdateAllLifecyclePhasesForTest();
  ResetAndPlaceCaret(text, String::FromUTF8("Some emojis ").length());
  EXPECT_TRUE(SelectWordAroundCaret());
  EXPECT_EQ_SELECTED_TEXT(" 😀");

  // End of a symbol: Some emojis 😀| 🍀.
  ResetAndPlaceCaret(text, String::FromUTF8("Some emojis 😀").length());
  EXPECT_TRUE(SelectWordAroundCaret());
  EXPECT_EQ_SELECTED_TEXT("😀");
}

TEST_F(FrameSelectionTest, SelectAroundCaret_Sentence) {
  Text* text = AppendTextNode(
      "This is the first sentence. This is the second sentence. This is the "
      "last sentence.");
  UpdateAllLifecyclePhasesForTest();

  // This is the first sentence. Th|is is the second sentence. This is the last
  // sentence.
  ResetAndPlaceCaret(text, strlen("This is the first sentence. Th"));
  EXPECT_TRUE(SelectSentenceAroundCaret());
  EXPECT_EQ_SELECTED_TEXT("This is the second sentence.");

  // This is the first sentence|. This is the second sentence. This is the last
  // sentence.
  ResetAndPlaceCaret(text, strlen("This is the first sentence"));
  EXPECT_TRUE(SelectSentenceAroundCaret());
  EXPECT_EQ_SELECTED_TEXT("This is the first sentence.");

  // This is the first sentence.| This is the second sentence. This is the last
  // sentence.
  ResetAndPlaceCaret(text, strlen("This is the first sentence."));
  EXPECT_TRUE(SelectSentenceAroundCaret());
  EXPECT_EQ_SELECTED_TEXT(
      "This is the first sentence. This is the second sentence.");

  // This is the first sentence. |This is the second sentence. This is the last
  // sentence.
  ResetAndPlaceCaret(text, strlen("This is the first sentence. "));
  EXPECT_TRUE(SelectSentenceAroundCaret());
  EXPECT_EQ_SELECTED_TEXT(
      "This is the first sentence. This is the second sentence.");

  // This is the first sentence. T|his is the second sentence. This is the last
  // sentence.
  ResetAndPlaceCaret(text, strlen("This is the first sentence. T"));
  EXPECT_TRUE(SelectSentenceAroundCaret());
  EXPECT_EQ_SELECTED_TEXT("This is the second sentence.");
}

TEST_F(FrameSelectionTest, SelectAroundCaret_ShouldShowHandle) {
  Text* text = AppendTextNode("This is a sentence.");
  int selection_index = 12;  // This is a se|ntence.
  UpdateAllLifecyclePhasesForTest();

  // Test that handles are never visible if the the handle_visibility param is
  // set to not visible, regardless of the other params.
  ResetAndPlaceCaret(text, selection_index);
  EXPECT_TRUE(Selection().SelectAroundCaret(
      TextGranularity::kSentence, HandleVisibility::kNotVisible,
      ContextMenuVisibility::kNotVisible));
  EXPECT_FALSE(Selection().IsHandleVisible());

  ResetAndPlaceCaret(text, selection_index);
  EXPECT_TRUE(Selection().SelectAroundCaret(
      TextGranularity::kWord, HandleVisibility::kNotVisible,
      ContextMenuVisibility::kNotVisible));
  EXPECT_FALSE(Selection().IsHandleVisible());

  ResetAndPlaceCaret(text, selection_index);
  EXPECT_TRUE(Selection().SelectAroundCaret(TextGranularity::kSentence,
                                            HandleVisibility::kNotVisible,
                                            ContextMenuVisibility::kVisible));
  EXPECT_FALSE(Selection().IsHandleVisible());

  ResetAndPlaceCaret(text, selection_index);
  EXPECT_TRUE(Selection().SelectAroundCaret(TextGranularity::kWord,
                                            HandleVisibility::kNotVisible,
                                            ContextMenuVisibility::kVisible));
  EXPECT_FALSE(Selection().IsHandleVisible());

  // Make sure handles are always visible when the handle_visiblity param is
  // set to visible, regardless of the other parameters.
  ResetAndPlaceCaret(text, selection_index);
  EXPECT_TRUE(Selection().SelectAroundCaret(
      TextGranularity::kSentence, HandleVisibility::kVisible,
      ContextMenuVisibility::kNotVisible));
  EXPECT_TRUE(Selection().IsHandleVisible());

  ResetAndPlaceCaret(text, selection_index);
  EXPECT_TRUE(Selection().SelectAroundCaret(
      TextGranularity::kWord, HandleVisibility::kVisible,
      ContextMenuVisibility::kNotVisible));
  EXPECT_TRUE(Selection().IsHandleVisible());
}

TEST_F(FrameSelectionTest, SelectAroundCaret_ShouldShowContextMenu) {
  Text* text = AppendTextNode("This is a sentence.");
  int selection_index = 12;  // This is a se|ntence.
  UpdateAllLifecyclePhasesForTest();

  // Test that the context menu is never visible if the context_menu_visibility
  // param is set to not visible, regardless of the other params.
  ResetAndPlaceCaret(text, selection_index);
  EXPECT_TRUE(Selection().SelectAroundCaret(
      TextGranularity::kSentence, HandleVisibility::kNotVisible,
      ContextMenuVisibility::kNotVisible));
  EXPECT_FALSE(HasContextMenu());

  ResetAndPlaceCaret(text, selection_index);
  EXPECT_TRUE(Selection().SelectAroundCaret(
      TextGranularity::kSentence, HandleVisibility::kVisible,
      ContextMenuVisibility::kNotVisible));
  EXPECT_FALSE(HasContextMenu());

  ResetAndPlaceCaret(text, selection_index);
  EXPECT_TRUE(Selection().SelectAroundCaret(
      TextGranularity::kWord, HandleVisibility::kNotVisible,
      ContextMenuVisibility::kNotVisible));
  EXPECT_FALSE(HasContextMenu());

  ResetAndPlaceCaret(text, selection_index);
  EXPECT_TRUE(Selection().SelectAroundCaret(
      TextGranularity::kWord, HandleVisibility::kVisible,
      ContextMenuVisibility::kNotVisible));
  EXPECT_FALSE(HasContextMenu());

  // Make sure the context menu is always visible when the
  // context_menu_visibility param is set to visible, regardless of the other
  // parameters.
  ResetAndPlaceCaret(text, selection_index);
  EXPECT_TRUE(Selection().SelectAroundCaret(TextGranularity::kSentence,
                                            HandleVisibility::kNotVisible,
                                            ContextMenuVisibility::kVisible));
  EXPECT_TRUE(HasContextMenu());

  ResetAndPlaceCaret(text, selection_index);
  EXPECT_TRUE(Selection().SelectAroundCaret(TextGranularity::kSentence,
                                            HandleVisibility::kVisible,
                                            ContextMenuVisibility::kVisible));
  EXPECT_TRUE(HasContextMenu());

  ResetAndPlaceCaret(text, selection_index);
  EXPECT_TRUE(Selection().SelectAroundCaret(TextGranularity::kWord,
                                            HandleVisibility::kNotVisible,
                                            ContextMenuVisibility::kVisible));
  EXPECT_TRUE(HasContextMenu());

  ResetAndPlaceCaret(text, selection_index);
  EXPECT_TRUE(Selection().SelectAroundCaret(TextGranularity::kWord,
                                            HandleVisibility::kVisible,
                                            ContextMenuVisibility::kVisible));
  EXPECT_TRUE(HasContextMenu());
}

TEST_F(FrameSelectionTest, GetSelectionRangeAroundCaret_Word) {
  Text* text = AppendTextNode("This is a sentence.");
  UpdateAllLifecyclePhasesForTest();

  // Beginning of a text: |This is a sentence.
  ResetAndPlaceCaret(text, strlen(""));
  EphemeralRange range = Selection().GetWordSelectionRangeAroundCaret();
  EXPECT_EQ("This", PlainText(range));

  // Beginning of a word: This |is a sentence.
  ResetAndPlaceCaret(text, strlen("This "));
  range = Selection().GetWordSelectionRangeAroundCaret();
  EXPECT_EQ("is", PlainText(range));

  // Somewhere in a word: This is a s|entence.
  ResetAndPlaceCaret(text, strlen("This is a s"));
  range = Selection().GetWordSelectionRangeAroundCaret();
  EXPECT_EQ("sentence", PlainText(range));

  // End a word: This| is a sentence.
  ResetAndPlaceCaret(text, strlen("This"));
  range = Selection().GetWordSelectionRangeAroundCaret();
  EXPECT_EQ("This", PlainText(range));

  // End a word before punctuation: This is a sentence|.
  ResetAndPlaceCaret(text, strlen("This is a sentence"));
  range = Selection().GetWordSelectionRangeAroundCaret();
  EXPECT_EQ("sentence", PlainText(range));

  // End of text after punctuation (no selection): This is a sentence.|
  ResetAndPlaceCaret(text, strlen("This is a sentence."));
  range = Selection().GetWordSelectionRangeAroundCaret();
  EXPECT_EQ("", PlainText(range));

  // End of text without punctuation: This is a sentence|
  ResetAndPlaceCaret(text, strlen("This is a sentence"));
  range = Selection().GetWordSelectionRangeAroundCaret();
  EXPECT_EQ("sentence", PlainText(range));

  // After punctuation before whitespace (no selection): A word.| Another.
  text = AppendTextNode("A word. Another.");
  UpdateAllLifecyclePhasesForTest();
  ResetAndPlaceCaret(text, strlen("A word."));
  range = Selection().GetWordSelectionRangeAroundCaret();
  EXPECT_EQ("", PlainText(range));

  // Beginning of a symbol: Some emojis |😀 🍀.
  text = AppendTextNode(String::FromUTF8("Some emojis 😀 🍀."));
  UpdateAllLifecyclePhasesForTest();
  ResetAndPlaceCaret(text, String::FromUTF8("Some emojis ").length());
  range = Selection().GetWordSelectionRangeAroundCaret();
  EXPECT_EQ(String::FromUTF8(" 😀"), PlainText(range));

  // End of a symbol: Some emojis 😀| 🍀.
  ResetAndPlaceCaret(text, String::FromUTF8("Some emojis 😀").length());
  range = Selection().GetWordSelectionRangeAroundCaret();
  EXPECT_EQ(String::FromUTF8("😀"), PlainText(range));
}

TEST_F(FrameSelectionTest, GetSelectionRangeAroundCaret_Sentence) {
  Text* text = AppendTextNode(
      "This is the first sentence. This is the second sentence. This is the "
      "last sentence.");
  UpdateAllLifecyclePhasesForTest();

  // |This is the first sentence. This is the second sentence. This is the last
  // sentence.
  ResetAndPlaceCaret(text, strlen(""));
  EphemeralRange range = Selection().GetSelectionRangeAroundCaretForTesting(
      TextGranularity::kSentence);
  EXPECT_EQ("This is the first sentence.", PlainText(range));

  // This is the first sentence|. This is the second sentence. This is the last
  // sentence.
  ResetAndPlaceCaret(text, strlen("This is the first sentence"));
  range = Selection().GetSelectionRangeAroundCaretForTesting(
      TextGranularity::kSentence);
  EXPECT_EQ("This is the first sentence.", PlainText(range));

  // TODO(crbug.com/1273856): This should only select one sentence.
  // This is the first sentence.| This is the second sentence. This is the last
  // sentence.
  ResetAndPlaceCaret(text, strlen("This is the first sentence."));
  range = Selection().GetSelectionRangeAroundCaretForTesting(
      TextGranularity::kSentence);
  EXPECT_EQ("This is the first sentence. This is the second sentence.",
            PlainText(range));

  // TODO(crbug.com/1273856): This should only select one sentence.
  // This is the first sentence. |This is the second sentence. This is the last
  // sentence.
  ResetAndPlaceCaret(text, strlen("This is the first sentence. "));
  range = Selection().GetSelectionRangeAroundCaretForTesting(
      TextGranularity::kSentence);
  EXPECT_EQ("This is the first sentence. This is the second sentence.",
            PlainText(range));

  // This is the first sentence. Th|is is the second sentence. This is the last
  // sentence.
  ResetAndPlaceCaret(text, strlen("This is the first sentence. Th"));
  range = Selection().GetSelectionRangeAroundCaretForTesting(
      TextGranularity::kSentence);
  EXPECT_EQ("This is the second sentence.", PlainText(range));

  // This is the first sentence. This is the second sentence. This is the last
  // sentence|.
  ResetAndPlaceCaret(text,
                     strlen("This is the first sentence. This is the second "
                            "sentence. This is the last sentence"));
  range = Selection().GetSelectionRangeAroundCaretForTesting(
      TextGranularity::kSentence);
  EXPECT_EQ("This is the last sentence.", PlainText(range));

  // This is the first sentence. This is the second sentence. This is the last
  // sentence.|
  ResetAndPlaceCaret(text,
                     strlen("This is the first sentence. This is the second "
                            "sentence. This is the last sentence."));
  range = Selection().GetSelectionRangeAroundCaretForTesting(
      TextGranularity::kSentence);
  EXPECT_EQ("This is the last sentence.", PlainText(range));
}

TEST_F(FrameSelectionTest, ModifyExtendWithFlatTree) {
  SetBodyContent("<span id=host></span>one");
  SetShadowContent("two<slot></slot>", "host");
  Element* host = GetDocument().getElementById(AtomicString("host"));
  Node* const two = FlatTreeTraversal::FirstChild(*host);
  // Select "two" for selection in DOM tree
  // Select "twoone" for selection in Flat tree
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .Collapse(ToPositionInDOMTree(PositionInFlatTree(host, 0)))
          .Extend(
              ToPositionInDOMTree(PositionInFlatTree(GetDocument().body(), 2)))
          .Build(),
      SetSelectionOptions());
  Selection().Modify(SelectionModifyAlteration::kExtend,
                     SelectionModifyDirection::kForward, TextGranularity::kWord,
                     SetSelectionBy::kSystem);
  EXPECT_EQ(Position(two, 0), VisibleSelectionInDOMTree().Start());
  EXPECT_EQ(Position(two, 3), VisibleSelectionInDOMTree().End());
  EXPECT_EQ(PositionInFlatTree(two, 0),
            GetVisibleSelectionInFlatTree().Start());
  EXPECT_EQ(PositionInFlatTree(two, 3), GetVisibleSelectionInFlatTree().End());
}

TEST_F(FrameSelectionTest, ModifyWithUserTriggered) {
  SetBodyContent("<div id=sample>abc</div>");
  Element* sample = GetDocument().getElementById(AtomicString("sample"));
  const Position end_of_text(sample->firstChild(), 3);
  Selection().SetSelection(
      SelectionInDOMTree::Builder().Collapse(end_of_text).Build(),
      SetSelectionOptions());

  EXPECT_FALSE(Selection().Modify(
      SelectionModifyAlteration::kMove, SelectionModifyDirection::kForward,
      TextGranularity::kCharacter, SetSelectionBy::kSystem))
      << "Selection.modify() returns false for non-user-triggered call when "
         "selection isn't modified.";
  EXPECT_EQ(end_of_text, Selection().ComputeVisibleSelectionInDOMTree().Start())
      << "Selection isn't modified";

  EXPECT_TRUE(Selection().Modify(
      SelectionModifyAlteration::kMove, SelectionModifyDirection::kForward,
      TextGranularity::kCharacter, SetSelectionBy::kUser))
      << "Selection.modify() returns true for user-triggered call";
  EXPECT_EQ(end_of_text, Selection().ComputeVisibleSelectionInDOMTree().Start())
      << "Selection isn't modified";
}

TEST_F(FrameSelectionTest, MoveRangeSelectionTest) {
  // "Foo Bar Baz,"
  Text* text = AppendTextNode("Foo Bar Baz,");
  UpdateAllLifecyclePhasesForTest();

  // Itinitializes with "Foo B|a>r Baz," (| means start and > means end).
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 5), Position(text, 6))
          .Build(),
      SetSelectionOptions());
  EXPECT_EQ_SELECTED_TEXT("a");

  // "Foo B|ar B>az," with the Character granularity.
  MoveRangeSelectionInternal(Position(text, 5), Position(text, 9),
                             TextGranularity::kCharacter);
  EXPECT_EQ_SELECTED_TEXT("ar B");
  // "Foo B|ar B>az," with the Word granularity.
  MoveRangeSelectionInternal(Position(text, 5), Position(text, 9),
                             TextGranularity::kWord);
  EXPECT_EQ_SELECTED_TEXT("Bar Baz");
  // "Fo<o B|ar Baz," with the Character granularity.
  MoveRangeSelectionInternal(Position(text, 5), Position(text, 2),
                             TextGranularity::kCharacter);
  EXPECT_EQ_SELECTED_TEXT("o B");
  // "Fo<o B|ar Baz," with the Word granularity.
  MoveRangeSelectionInternal(Position(text, 5), Position(text, 2),
                             TextGranularity::kWord);
  EXPECT_EQ_SELECTED_TEXT("Foo Bar");
}

TEST_F(FrameSelectionTest, MoveRangeSelectionNoLiveness) {
  SetBodyContent("<span id=sample>xyz</span>");
  Element* const sample = GetDocument().getElementById(AtomicString("sample"));
  // Select as: <span id=sample>^xyz|</span>
  MoveRangeSelectionInternal(Position(sample->firstChild(), 1),
                             Position(sample->firstChild(), 1),
                             TextGranularity::kWord);
  EXPECT_EQ("xyz", Selection().SelectedText());
  sample->insertBefore(Text::Create(GetDocument(), "abc"),
                       sample->firstChild());
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  const VisibleSelection& selection =
      Selection().ComputeVisibleSelectionInDOMTree();
  // Inserting "abc" before "xyz" should not affect to selection.
  EXPECT_EQ(Position(sample->lastChild(), 0), selection.Start());
  EXPECT_EQ(Position(sample->lastChild(), 3), selection.End());
  EXPECT_EQ("xyz", Selection().SelectedText());
  EXPECT_EQ("abcxyz", sample->innerText());
}

// For http://crbug.com/695317
TEST_F(FrameSelectionTest, SelectAllWithInputElement) {
  SetBodyContent("<input>123");
  Element* const input = GetDocument().QuerySelector(AtomicString("input"));
  Node* const last_child = GetDocument().body()->lastChild();
  Selection().SelectAll();
  const SelectionInDOMTree& result_in_dom_tree =
      Selection().ComputeVisibleSelectionInDOMTree().AsSelection();
  const SelectionInFlatTree& result_in_flat_tree =
      Selection().ComputeVisibleSelectionInFlatTree().AsSelection();
  EXPECT_EQ(SelectionInDOMTree::Builder(result_in_dom_tree)
                .Collapse(Position::BeforeNode(*input))
                .Extend(Position(last_child, 3))
                .Build(),
            result_in_dom_tree);
  EXPECT_EQ(SelectionInFlatTree::Builder(result_in_flat_tree)
                .Collapse(PositionInFlatTree::BeforeNode(*input))
                .Extend(PositionInFlatTree(last_child, 3))
                .Build(),
            result_in_flat_tree);
}

TEST_F(FrameSelectionTest, SelectAllWithUnselectableRoot) {
  Element* select = GetDocument().CreateRawElement(html_names::kSelectTag);
  GetDocument().ReplaceChild(select, GetDocument().documentElement());
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Selection().SelectAll();
  EXPECT_TRUE(Selection().ComputeVisibleSelectionInDOMTree().IsNone())
      << "Nothing should be selected if the "
         "content of the documentElement is not "
         "selctable.";
}

TEST_F(FrameSelectionTest, SelectAllPreservesHandle) {
  SetBodyContent("<div id=sample>abc</div>");
  Element* sample = GetDocument().getElementById(AtomicString("sample"));
  const Position end_of_text(sample->firstChild(), 3);
  Selection().SetSelection(
      SelectionInDOMTree::Builder().Collapse(end_of_text).Build(),
      SetSelectionOptions());
  EXPECT_FALSE(Selection().IsHandleVisible());
  Selection().SelectAll();
  EXPECT_FALSE(Selection().IsHandleVisible())
      << "If handles weren't present before "
         "selectAll. Then they shouldn't be present "
         "after it.";

  Selection().SetSelection(
      SelectionInDOMTree::Builder().Collapse(end_of_text).Build(),
      SetSelectionOptions::Builder()
          .SetShouldCloseTyping(true)
          .SetShouldClearTypingStyle(true)
          .SetShouldShowHandle(true)
          .Build());
  EXPECT_TRUE(Selection().IsHandleVisible());
  Selection().SelectAll();
  EXPECT_TRUE(Selection().IsHandleVisible())
      << "If handles were present before "
         "selectAll. Then they should be present "
         "after it.";
}

TEST_F(FrameSelectionTest, BoldCommandPreservesHandle) {
  SetBodyContent("<div id=sample contenteditable>abc</div>");
  Element* sample = GetDocument().getElementById(AtomicString("sample"));
  const Position end_of_text(sample->firstChild(), 3);
  Selection().SetSelection(
      SelectionInDOMTree::Builder().Collapse(end_of_text).Build(),
      SetSelectionOptions());
  EXPECT_FALSE(Selection().IsHandleVisible());
  Selection().SelectAll();
  GetDocument().execCommand("bold", false, "", ASSERT_NO_EXCEPTION);
  EXPECT_FALSE(Selection().IsHandleVisible())
      << "If handles weren't present before "
         "bold command. Then they shouldn't "
         "be present after it.";

  Selection().SetSelection(
      SelectionInDOMTree::Builder().Collapse(end_of_text).Build(),
      SetSelectionOptions::Builder()
          .SetShouldCloseTyping(true)
          .SetShouldClearTypingStyle(true)
          .SetShouldShowHandle(true)
          .Build());
  EXPECT_TRUE(Selection().IsHandleVisible());
  Selection().SelectAll();
  GetDocument().execCommand("bold", false, "", ASSERT_NO_EXCEPTION);
  EXPECT_TRUE(Selection().IsHandleVisible())
      << "If handles were present before "
         "bold command. Then they should "
         "be present after it.";
}

TEST_F(FrameSelectionTest, SelectionOnRangeHidesHandles) {
  Text* text = AppendTextNode("Hello, World!");
  UpdateAllLifecyclePhasesForTest();
  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .SetBaseAndExtent(EphemeralRange(
                                   Position(text, 0), Position(text, 12)))
                               .Build(),
                           SetSelectionOptions());

  EXPECT_FALSE(Selection().IsHandleVisible())
      << "After SetSelection on Range, handles shouldn't be present.";

  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(text, 0), Position(text, 5))
          .Build(),
      SetSelectionOptions::Builder()
          .SetShouldCloseTyping(true)
          .SetShouldClearTypingStyle(true)
          .SetShouldShowHandle(true)
          .Build());

  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .SetBaseAndExtent(EphemeralRange(
                                   Position(text, 0), Position(text, 12)))
                               .Build(),
                           SetSelectionOptions());

  EXPECT_FALSE(Selection().IsHandleVisible())
      << "After SetSelection on Range, handles shouldn't be present.";
}

// Regression test for crbug.com/702756
// Test case excerpted from editing/undo/redo_correct_selection.html
TEST_F(FrameSelectionTest, SelectInvalidPositionInFlatTreeDoesntCrash) {
  SetBodyContent("foo<option><select></select></option>");
  Element* body = GetDocument().body();
  Element* select = GetDocument().QuerySelector(AtomicString("select"));
  Node* foo = body->firstChild();
  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .Collapse(Position(body, 0))
                               // SELECT@AfterAnchor is invalid in flat tree.
                               .Extend(Position::AfterNode(*select))
                               .Build(),
                           SetSelectionOptions());
  // Should not crash inside.
  const VisibleSelectionInFlatTree& selection =
      Selection().ComputeVisibleSelectionInFlatTree();

  // This only records the current behavior. It might be changed in the future.
  EXPECT_EQ(PositionInFlatTree(foo, 0), selection.Anchor());
  EXPECT_EQ(PositionInFlatTree(foo, 0), selection.Focus());
}

TEST_F(FrameSelectionTest, CaretInShadowTree) {
  SetBodyContent("<p id=host></p>bar");
  ShadowRoot* shadow_root =
      SetShadowContent("<div contenteditable id='ce'>foo</div>", "host");
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_FALSE(Selection().SelectionHasFocus());
  EXPECT_TRUE(Selection().IsHidden());

  Element* const ce = shadow_root->getElementById(AtomicString("ce"));
  ce->Focus();
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  EXPECT_TRUE(Selection().SelectionHasFocus());
  EXPECT_FALSE(Selection().IsHidden());

  ce->blur();  // Move focus to document body.
  EXPECT_TRUE(Selectio
```