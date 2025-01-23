Response:
The user wants me to summarize the functionality of the provided C++ code snippet, which is part of a test file for the Blink rendering engine.

Here's a breakdown of my thought process:

1. **Identify the core purpose:** The file name `layout_selection_test.cc` and the class names like `LayoutSelectionTest` and `NGLayoutSelectionTest` strongly suggest that this code tests the behavior of selection within the Blink layout engine. Specifically, it focuses on how the layout objects and the selection interact.

2. **Analyze the test structure:** The code uses the Google Test framework (`TEST_F`). Each `TEST_F` function represents a specific test case. The structure generally involves:
    * Setting up the DOM (Document Object Model) with specific HTML content.
    * Simulating a user selection (using markers like `^` and `|`).
    * Performing actions, often involving `Selection()` methods.
    * Assertions (`EXPECT_EQ`) to verify the expected state of the layout and selection. The `DumpSelectionInfo()` function seems crucial for inspecting the layout tree and selection status.

3. **Focus on `DumpSelectionInfo()`:** This function is called in almost every test. It appears to be a key utility for inspecting the state of the layout tree and how the selection interacts with it. The output format reveals information about nodes, their invalidation status, and the start and end offsets of the selection within text nodes.

4. **Examine individual test cases:**  By reviewing the names of the test cases and the HTML they set up, I can infer what specific scenarios they are testing. For example:
    * `MoveElement`: Tests how moving an element affects the selection and layout.
    * `InvalidateSlot`: Focuses on how selections work with Shadow DOM slots.
    * `SelectOnOneText`, `FirstLetterInAnotherBlockFlow`, `TwoNGBlockFlows`, etc.:  These tests explore selection behavior across different layout scenarios, including inline elements, block elements, and different rendering modes (like the "NG" prefix indicates the "Next Generation" layout engine).
    * `LineBreakBasic`, `LineBreakInlineBlock`, `LineBreakImage`, `BRStatus`, `WBRStatus`, `SoftHyphen*`:  These cases specifically target how line breaks, images, `<br>`, `<wbr>`, and soft hyphens interact with selection.

5. **Identify the relationship with web technologies:** The tests manipulate HTML elements and CSS properties (`style='white-space:pre'`, `:first-letter`, `display:inline-block`). This clearly shows a connection to HTML and CSS. The selection being tested is the same selection mechanism users interact with in a web browser, which is often manipulated via JavaScript.

6. **Look for logical reasoning and assumptions:**  The tests make assumptions about how the layout engine *should* behave for a given input. The assertions are the explicit statements of these expected outputs. The input is the HTML structure and the defined selection. The output is the information reported by `DumpSelectionInfo()` and the boolean results of functions like `IsFirstTextLineBreak`.

7. **Consider potential user errors:**  While the tests themselves don't directly demonstrate user errors, they are designed to *prevent* errors in the layout engine. If a test fails, it indicates a bug in how Blink handles selection in a particular scenario. This could lead to unexpected or incorrect selection behavior from a user's perspective. Common user errors that these tests implicitly address include issues like selecting across line breaks, selecting within shadow DOM, and handling special characters like `<br>` and soft hyphens.

8. **Trace user actions:**  To reach the code being tested, a user would typically:
    * Open a web page in a Chromium-based browser.
    * Interact with the page by selecting text or elements using their mouse or keyboard.
    * The browser's rendering engine (Blink) would then be responsible for updating the layout and the visual representation of the selection. The tests simulate these actions programmatically.

9. **Synthesize the information for the summary:** Based on the analysis above, I can now summarize the functionality of the code, highlight its relationship to web technologies, provide examples of logical reasoning, discuss potential user errors, and explain how user actions lead to the execution of this code.

10. **Address the "part 2" instruction:** The user explicitly mentions this is part 2. This means the previous part likely introduced the basic structure and purpose of the test file. Therefore, this part should focus on the specific test cases and the nuances they cover.

By following these steps, I can generate a comprehensive and accurate answer to the user's request.
这是对Blink引擎源代码文件 `blink/renderer/core/editing/layout_selection_test.cc` 的第二部分分析，延续了第一部分对该文件功能的探讨。

**归纳一下它的功能:**

这部分代码延续了第一部分的功能，主要集中在以下几个方面：

1. **更深入地测试LayoutSelection在不同布局场景下的行为:**  这部分包含了更多更具体的测试用例，涵盖了更复杂的HTML结构和CSS样式对选择的影响。例如，测试了浮动元素、多列布局、inline-block元素、图片、`<br>`、`<wbr>` 和软连字符等元素与选择的交互。

2. **引入了NGLayoutSelectionTest，专门测试LayoutNG下的选择行为:**  LayoutNG是Blink引擎的新一代布局引擎。这部分引入了一个专门的测试类 `NGLayoutSelectionTest`，用于验证在新布局引擎下选择的正确性。这表明Blink团队正在积极迁移到LayoutNG，并确保选择功能在新引擎下也能正常工作。

3. **更精细地检查选择状态:**  除了检查选择范围的开始和结束节点，这部分还引入了 `ComputeLayoutSelectionStatus` 和 `ComputePaintingSelectionStateForCursor` 等函数，用于更细致地检查选择在布局对象上的状态，例如是否跨越软换行符、选择的起始和结束状态（`kStart`, `kEnd`, `kStartAndEnd`, `kInside`, `kNone`）。

4. **关注特定Bug的修复:**  像 `// http://crbug.com/870734` 这样的注释表明，某些测试用例是专门为了复现和验证特定bug的修复而添加的。这体现了测试驱动开发的理念。

**与javascript, html, css的功能的关系及举例说明:**

* **HTML:**  所有的测试用例都依赖于HTML结构来构建测试场景。例如，`TEST_F(NGLayoutSelectionTest, TwoNGBlockFlows)` 中使用了 `<div>` 元素来创建两个块级元素，并测试跨越这两个块级元素的选择行为。
* **CSS:**  CSS样式直接影响布局，从而影响选择的行为。例如，`TEST_F(NGLayoutSelectionTest, FirstLetterInAnotherBlockFlow)` 使用了 CSS 的 `:first-letter` 伪类和 `float: right` 属性来创建特定的布局，并测试选择首字母时的状态。`TEST_F(NGLayoutSelectionTest, LineBreakBasic)` 中使用了 `style='font: Ahem; width: 2em'` 来控制文本的宽度，从而触发软换行，并测试选择是否跨越了软换行符。
* **Javascript:** 虽然这段代码本身是用 C++ 编写的测试代码，但它测试的选择功能是用户在浏览器中使用 Javascript 可以操作和监听的。例如，Javascript 可以使用 `window.getSelection()` 获取当前的选择，并监听 `selectionchange` 事件。这些 Javascript API 的正确行为依赖于 Blink 引擎中选择功能的正确实现。

**逻辑推理的假设输入与输出:**

例如，在 `TEST_F(NGLayoutSelectionTest, TwoNGBlockFlows)` 中：

* **假设输入:**  HTML 结构为 `<div>f^oo</div><div>ba|r</div>`，表示用户在第一个 `div` 的 "oo" 之间开始选择，并在第二个 `div` 的 "ba" 之间结束选择。
* **预期输出:** `DumpSelectionInfo()` 的输出会显示选择跨越了两个 `div` 元素，并且在第一个 `div` 的文本节点 "foo" 上是 "Start(1,3)" (从索引 1 到 3，即选中 "oo")，在第二个 `div` 的文本节点 "bar" 上是 "End(0,2)" (从索引 0 到 2，即选中 "ba")。`ComputeLayoutSelectionStatus` 和 `ComputePaintingSelectionStateForCursor` 会给出更精细的选择状态，例如第一个文本节点是 `kStart` 状态，第二个是 `kEnd` 状态。

**涉及用户或者编程常见的使用错误举例说明:**

虽然测试代码本身不是用户直接操作的代码，但它旨在防止用户在浏览器中进行选择时遇到错误。一些潜在的错误包括：

* **选择丢失或不准确:**  用户希望选中一段文本，但由于布局引擎的错误，实际选中的范围与预期不符。例如，在复杂的布局中，选择可能意外地扩展到不相关的元素。
* **选择渲染错误:**  即使选择的逻辑范围正确，但由于渲染错误，选择高亮的显示可能不正确，例如高亮区域偏移或不连续。
* **程序化操作选择失败:**  Javascript 代码尝试使用 API 设置或修改选择，但由于 Blink 引擎的错误，操作未能成功或产生了意外的结果。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中加载一个包含文本和各种HTML元素（例如 `<div>`, `<span>`, `<img>` 等）的网页。**
2. **用户使用鼠标或键盘进行选择操作。** 例如，用户点击并拖动鼠标来选中一段文本，或者使用 Shift 键和方向键进行选择。
3. **用户的选择操作会触发浏览器内核 (Blink) 中的选择机制。**
4. **Blink 引擎会根据当前的布局树 (Layout Tree) 和用户的操作，计算出选择的起始和结束位置。** 这涉及到遍历布局对象，确定哪些文本节点和元素被选中。
5. **`blink/renderer/core/editing/layout_selection_test.cc` 中的测试用例就是模拟了上述的用户操作和 Blink 引擎的处理过程。**  开发者编写这些测试用例来验证 Blink 引擎在各种布局场景下计算选择范围的逻辑是否正确。
6. **如果用户在浏览器中发现选择行为异常 (例如，选择不准确)，开发者可能会尝试编写一个新的测试用例来复现这个 bug。** 这个新的测试用例会模拟导致该 bug 的特定 HTML 结构和用户操作。
7. **通过运行这些测试用例，开发者可以诊断并修复 Blink 引擎中选择相关的错误。**  测试失败会提供关于哪里出了问题以及预期的行为是什么的线索。

总而言之，这部分代码继续深入测试了 Blink 引擎中选择功能在各种布局场景下的正确性，特别是针对新的 LayoutNG 引擎。它通过模拟用户操作和断言预期结果，确保了用户在浏览器中进行选择时的行为符合预期，并且关注了特定 bug 的修复。 这部分的测试更加细致，涉及到对选择状态的更精细的检查，并且覆盖了更多类型的 HTML 元素和 CSS 样式对选择的影响。

### 提示词
```
这是目录为blink/renderer/core/editing/layout_selection_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
1"));
  Node* div2 = GetDocument().QuerySelector(AtomicString("#div2"));
  div1->appendChild(div2);
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  DIV, None, NotInvalidate \n"
      "    DIV, <null LayoutObject> \n"
      "      'foo', <null LayoutObject> \n"
      "      B, <null LayoutObject> \n"
      "        'bar', <null LayoutObject> ",
      DumpSelectionInfo());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(
      "BODY, None, NotInvalidate \n"
      "  DIV, None, NotInvalidate \n"
      "    DIV, None, NotInvalidate \n"
      "      'foo', None, NotInvalidate \n"
      "      B, None, NotInvalidate \n"
      "        'bar', None, NotInvalidate ",
      DumpSelectionInfo());
}

// http://crbug.com/870734
TEST_F(LayoutSelectionTest, InvalidateSlot) {
  Selection().SetSelection(SetSelectionTextToBody("^<div>"
                                                  "<template data-mode=open>"
                                                  "<slot></slot>"
                                                  "</template>"
                                                  "foo"
                                                  "</div>|"),
                           SetSelectionOptions());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  DIV, Contain, NotInvalidate \n"
      "    #shadow-root \n"
      "      SLOT, <null LayoutObject> \n"
      "    'foo', StartAndEnd(0,3), NotInvalidate ",
      DumpSelectionInfo());

  Selection().Clear();
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, None, NotInvalidate \n"
      "  DIV, None, NotInvalidate \n"
      "    #shadow-root \n"
      "      SLOT, <null LayoutObject> \n"
      "    'foo', None, ShouldInvalidate ",
      DumpSelectionInfo());
}

class NGLayoutSelectionTest
    : public LayoutSelectionTestBase,
      private ScopedPaintUnderInvalidationCheckingForTest {
 public:
  NGLayoutSelectionTest() : ScopedPaintUnderInvalidationCheckingForTest(true) {}

 protected:
  const Text* GetFirstTextNode() {
    for (const Node& runner : NodeTraversal::StartsAt(*GetDocument().body())) {
      if (auto* text_node = DynamicTo<Text>(runner))
        return text_node;
    }
    NOTREACHED();
  }

  bool IsFirstTextLineBreak(const std::string& selection_text) {
    SetSelectionAndUpdateLayoutSelection(selection_text);
    const LayoutText& first_text = *GetFirstTextNode()->GetLayoutObject();
    const LayoutSelectionStatus& status =
        ComputeLayoutSelectionStatus(first_text);
    return status.line_break == SelectSoftLineBreak::kSelected;
  }

  LayoutSelectionStatus ComputeLayoutSelectionStatus(const Node& node) {
    return ComputeLayoutSelectionStatus(*node.GetLayoutObject());
  }

  LayoutSelectionStatus ComputeLayoutSelectionStatus(
      const LayoutObject& layout_object) const {
    DCHECK(layout_object.IsText());
    InlineCursor cursor(*layout_object.FragmentItemsContainer());
    cursor.MoveTo(layout_object);
    return Selection().ComputeLayoutSelectionStatus(cursor);
  }

  SelectionState ComputePaintingSelectionStateForCursor(
      const LayoutObject& layout_object) const {
    DCHECK(layout_object.IsText());
    InlineCursor cursor;
    cursor.MoveTo(layout_object);
    return Selection().ComputePaintingSelectionStateForCursor(cursor.Current());
  }

  void SetSelectionAndUpdateLayoutSelection(const std::string& selection_text) {
    const SelectionInDOMTree& selection =
        SetSelectionTextToBody(selection_text);
    Selection().SetSelection(selection, SetSelectionOptions());
    Selection().CommitAppearanceIfNeeded();
  }
};

std::ostream& operator<<(std::ostream& ostream,
                         const LayoutSelectionStatus& status) {
  const String line_break =
      (status.line_break == SelectSoftLineBreak::kSelected) ? "kSelected"
                                                            : "kNotSelected";
  return ostream << status.start << ", " << status.end << ", " << std::boolalpha
                 << line_break;
}

TEST_F(NGLayoutSelectionTest, SelectOnOneText) {
  SetSelectionAndUpdateLayoutSelection("foo<span>b^a|r</span>");
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  'foo', None, NotInvalidate \n"
      "  SPAN, Contain, NotInvalidate \n"
      "    'bar', StartAndEnd(1,2), ShouldInvalidate ",
      DumpSelectionInfo());
}

TEST_F(NGLayoutSelectionTest, FirstLetterInAnotherBlockFlow) {
  SetSelectionAndUpdateLayoutSelection(
      "<style>:first-letter { float: right}</style>^fo|o");
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  <style> \n"
      "  'foo', StartAndEnd(0,1), ShouldInvalidate \n"
      "    :first-letter, None(0,1), ShouldInvalidate ",
      DumpSelectionInfo());
}

TEST_F(NGLayoutSelectionTest, TwoNGBlockFlows) {
  SetSelectionAndUpdateLayoutSelection("<div>f^oo</div><div>ba|r</div>");
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  DIV, Contain, NotInvalidate \n"
      "    'foo', Start(1,3), ShouldInvalidate \n"
      "  DIV, Contain, NotInvalidate \n"
      "    'bar', End(0,2), ShouldInvalidate ",
      DumpSelectionInfo());
  LayoutObject* const foo =
      GetDocument().body()->firstChild()->firstChild()->GetLayoutObject();
  EXPECT_EQ(LayoutSelectionStatus(1u, 3u, SelectSoftLineBreak::kSelected),
            ComputeLayoutSelectionStatus(*foo));
  EXPECT_EQ(SelectionState::kStart,
            ComputePaintingSelectionStateForCursor(*foo));
  LayoutObject* const bar = GetDocument()
                                .body()
                                ->firstChild()
                                ->nextSibling()
                                ->firstChild()
                                ->GetLayoutObject();
  EXPECT_EQ(LayoutSelectionStatus(0u, 2u, SelectSoftLineBreak::kNotSelected),
            ComputeLayoutSelectionStatus(*bar));
  EXPECT_EQ(SelectionState::kEnd, ComputePaintingSelectionStateForCursor(*bar));
}

TEST_F(NGLayoutSelectionTest, StartAndEndState) {
  SetSelectionAndUpdateLayoutSelection("<div>f^oo|</div><div>bar</div>");
  LayoutObject* const foo =
      GetDocument().body()->firstChild()->firstChild()->GetLayoutObject();
  EXPECT_EQ(LayoutSelectionStatus(1u, 3u, SelectSoftLineBreak::kNotSelected),
            ComputeLayoutSelectionStatus(*foo));
  EXPECT_EQ(SelectionState::kStartAndEnd,
            ComputePaintingSelectionStateForCursor(*foo));
  LayoutObject* const bar = GetDocument()
                                .body()
                                ->firstChild()
                                ->nextSibling()
                                ->firstChild()
                                ->GetLayoutObject();
  EXPECT_EQ(LayoutSelectionStatus(0u, 0u, SelectSoftLineBreak::kNotSelected),
            ComputeLayoutSelectionStatus(*bar));
  EXPECT_EQ(SelectionState::kNone,
            ComputePaintingSelectionStateForCursor(*bar));
}

TEST_F(NGLayoutSelectionTest, UnpaintedStartAndEndState) {
  SetSelectionAndUpdateLayoutSelection(
      "<img width=10px height=10px>^<div>\n<span "
      "id=selected>foo</span>\n</div>|<img width=10px height=10px>"
      "<div id=trailing>bar</div>");
  LayoutObject* const foo =
      GetElementById("selected")->firstChild()->GetLayoutObject();
  EXPECT_EQ(LayoutSelectionStatus(0u, 3u, SelectSoftLineBreak::kSelected),
            ComputeLayoutSelectionStatus(*foo));
  EXPECT_EQ(SelectionState::kStartAndEnd,
            ComputePaintingSelectionStateForCursor(*foo));
  LayoutObject* const bar =
      GetElementById("trailing")->firstChild()->GetLayoutObject();
  EXPECT_EQ(LayoutSelectionStatus(0u, 0u, SelectSoftLineBreak::kNotSelected),
            ComputeLayoutSelectionStatus(*bar));
  EXPECT_EQ(SelectionState::kNone,
            ComputePaintingSelectionStateForCursor(*bar));
}

TEST_F(NGLayoutSelectionTest, StartAndEndMultilineState) {
  SetSelectionAndUpdateLayoutSelection(
      "<div style='white-space:pre'>f^oo\nbar\nba|z</div>");
  LayoutObject* const div_text =
      GetDocument().body()->firstChild()->firstChild()->GetLayoutObject();

  InlineCursor cursor(*(div_text->FragmentItemsContainer()));
  cursor.MoveTo(*div_text);
  EXPECT_EQ(LayoutSelectionStatus(1u, 3u, SelectSoftLineBreak::kNotSelected),
            Selection().ComputeLayoutSelectionStatus(cursor));
  EXPECT_EQ(
      SelectionState::kStart,
      Selection().ComputePaintingSelectionStateForCursor(cursor.Current()));

  // Move to 'bar' text.
  cursor.MoveToNext();
  cursor.MoveToNext();
  cursor.MoveToNext();
  EXPECT_EQ(LayoutSelectionStatus(4u, 7u, SelectSoftLineBreak::kNotSelected),
            Selection().ComputeLayoutSelectionStatus(cursor));
  EXPECT_EQ(
      SelectionState::kInside,
      Selection().ComputePaintingSelectionStateForCursor(cursor.Current()));

  // Move to 'baz' text.
  cursor.MoveToNext();
  cursor.MoveToNext();
  cursor.MoveToNext();
  EXPECT_EQ(LayoutSelectionStatus(8u, 10u, SelectSoftLineBreak::kNotSelected),
            Selection().ComputeLayoutSelectionStatus(cursor));
  EXPECT_EQ(
      SelectionState::kEnd,
      Selection().ComputePaintingSelectionStateForCursor(cursor.Current()));
}

TEST_F(NGLayoutSelectionTest, BeforeStartAndAfterEndMultilineState) {
  SetSelectionAndUpdateLayoutSelection(
      "<div style='white-space:pre'>foo\nba^r</div><div "
      "style='white-space:pre'>ba|z\nquu</div>");
  LayoutObject* const div_text =
      GetDocument().body()->firstChild()->firstChild()->GetLayoutObject();
  InlineCursor cursor(*(div_text->FragmentItemsContainer()));
  cursor.MoveTo(*div_text);
  EXPECT_EQ(LayoutSelectionStatus(3u, 3u, SelectSoftLineBreak::kNotSelected),
            Selection().ComputeLayoutSelectionStatus(cursor));
  EXPECT_EQ(
      SelectionState::kNone,
      Selection().ComputePaintingSelectionStateForCursor(cursor.Current()));

  // Move to 'bar' text.
  cursor.MoveToNext();
  cursor.MoveToNext();
  cursor.MoveToNext();
  EXPECT_EQ(LayoutSelectionStatus(6u, 7u, SelectSoftLineBreak::kSelected),
            Selection().ComputeLayoutSelectionStatus(cursor));
  EXPECT_EQ(
      SelectionState::kStart,
      Selection().ComputePaintingSelectionStateForCursor(cursor.Current()));

  LayoutObject* const second_div_text =
      GetDocument().body()->lastChild()->firstChild()->GetLayoutObject();
  InlineCursor second_cursor(*(second_div_text->FragmentItemsContainer()));
  second_cursor.MoveTo(*second_div_text);
  EXPECT_EQ(LayoutSelectionStatus(0u, 2u, SelectSoftLineBreak::kNotSelected),
            Selection().ComputeLayoutSelectionStatus(second_cursor));
  EXPECT_EQ(SelectionState::kEnd,
            Selection().ComputePaintingSelectionStateForCursor(
                second_cursor.Current()));

  // Move to 'quu' text.
  second_cursor.MoveToNext();
  second_cursor.MoveToNext();
  second_cursor.MoveToNext();
  EXPECT_EQ(LayoutSelectionStatus(4u, 4u, SelectSoftLineBreak::kNotSelected),
            Selection().ComputeLayoutSelectionStatus(second_cursor));
  EXPECT_EQ(SelectionState::kNone,
            Selection().ComputePaintingSelectionStateForCursor(
                second_cursor.Current()));
}

// TODO(editing-dev): Once LayoutNG supports editing, we should change this
// test to use LayoutNG tree.
TEST_F(NGLayoutSelectionTest, MixedBlockFlowsAsSibling) {
  SetSelectionAndUpdateLayoutSelection(
      "<div>f^oo</div>"
      "<div contenteditable>ba|r</div>");
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  DIV, Contain, NotInvalidate \n"
      "    'foo', Start(1,3), ShouldInvalidate \n"
      "  DIV, Contain, NotInvalidate \n"
      "    'bar', End(0,2), ShouldInvalidate ",
      DumpSelectionInfo());
}

// TODO(editing-dev): Once LayoutNG supports editing, we should change this
// test to use LayoutNG tree.
TEST_F(NGLayoutSelectionTest, MixedBlockFlowsAnscestor) {
  // Both "foo" and "bar" for DIV elements should be legacy LayoutBlock.
  SetSelectionAndUpdateLayoutSelection(
      "<div contenteditable>f^oo"
      "<div contenteditable=false>ba|r</div></div>");
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  DIV, Contain, NotInvalidate \n"
      "    'foo', Start(1,3), ShouldInvalidate \n"
      "    DIV, Contain, NotInvalidate \n"
      "      'bar', End(0,2), ShouldInvalidate ",
      DumpSelectionInfo());
}

// TODO(editing-dev): Once LayoutNG supports editing, we should change this
// test to use LayoutNG tree.
TEST_F(NGLayoutSelectionTest, MixedBlockFlowsDecendant) {
  SetSelectionAndUpdateLayoutSelection(
      "<div contenteditable=false>f^oo"
      "<div contenteditable>ba|r</div></div>");
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  DIV, Contain, NotInvalidate \n"
      "    'foo', Start(1,3), ShouldInvalidate \n"
      "    DIV, Contain, NotInvalidate \n"
      "      'bar', End(0,2), ShouldInvalidate ",
      DumpSelectionInfo());
}

TEST_F(NGLayoutSelectionTest, LineBreakBasic) {
  LoadAhem();
  EXPECT_FALSE(IsFirstTextLineBreak("<div>f^oo<br>ba|r</div>"));
  EXPECT_FALSE(IsFirstTextLineBreak("<div>^foo<br><br>|</div>"));
  EXPECT_TRUE(IsFirstTextLineBreak(
      "<div style='font: Ahem; width: 2em'>f^oo ba|r</div>"));
  EXPECT_TRUE(IsFirstTextLineBreak("<div>f^oo</div><div>b|ar</div>"));
  EXPECT_FALSE(IsFirstTextLineBreak("<div>f^oo |</div>"));
  EXPECT_FALSE(IsFirstTextLineBreak("<div>f^oo <!--|--></div>"));
  EXPECT_FALSE(IsFirstTextLineBreak("<div>f^oo </div>|"));
  EXPECT_FALSE(IsFirstTextLineBreak("<div>f^oo|</div>"));
  EXPECT_FALSE(IsFirstTextLineBreak("<div>f^oo<!--|--></div>"));
  EXPECT_FALSE(IsFirstTextLineBreak("<div>f^oo</div>|"));
}

TEST_F(NGLayoutSelectionTest, LineBreakInlineBlock) {
  LoadAhem();
  EXPECT_FALSE(
      IsFirstTextLineBreak("<div style='display:inline-block'>^x</div>y|"));
  EXPECT_FALSE(
      IsFirstTextLineBreak("<div style='display:inline-block'>f^oo</div>bar|"));
}

TEST_F(NGLayoutSelectionTest, LineBreakImage) {
  SetSelectionAndUpdateLayoutSelection(
      "<div>^<img id=img1 width=10px height=10px>foo<br>"
      "bar<img id=img2 width=10px height=10px>|</div>");
  Node* const foo =
      GetDocument().body()->firstChild()->firstChild()->nextSibling();
  EXPECT_EQ(SelectSoftLineBreak::kNotSelected,
            ComputeLayoutSelectionStatus(*foo).line_break);
  Node* const bar = foo->nextSibling()->nextSibling();
  EXPECT_EQ(SelectSoftLineBreak::kNotSelected,
            ComputeLayoutSelectionStatus(*bar).line_break);
}

TEST_F(NGLayoutSelectionTest, BRStatus) {
  const SelectionInDOMTree& selection =
      SetSelectionTextToBody("<div>foo<!--^--><br><!--|-->bar</div>");
  Selection().SetSelection(selection, SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  LayoutObject* const layout_br =
      GetDocument().QuerySelector(AtomicString("br"))->GetLayoutObject();
  CHECK(layout_br->IsBR());
  EXPECT_EQ(LayoutSelectionStatus(3u, 4u, SelectSoftLineBreak::kNotSelected),
            ComputeLayoutSelectionStatus(*layout_br));
  EXPECT_EQ(SelectionState::kStartAndEnd,
            ComputePaintingSelectionStateForCursor(*layout_br));
}

// https://crbug.com/907186
TEST_F(NGLayoutSelectionTest, WBRStatus) {
  SetSelectionAndUpdateLayoutSelection(
      "<div style=\"width:0\">^foo<wbr>bar|</div>");
  const LayoutObject* layout_wbr =
      GetDocument().QuerySelector(AtomicString("wbr"))->GetLayoutObject();
  EXPECT_EQ(LayoutSelectionStatus(3u, 4u, SelectSoftLineBreak::kSelected),
            ComputeLayoutSelectionStatus(*layout_wbr));
  EXPECT_EQ(SelectionState::kInside,
            ComputePaintingSelectionStateForCursor(*layout_wbr));
}

TEST_F(NGLayoutSelectionTest, SoftHyphen0to1) {
  SetSelectionAndUpdateLayoutSelection(
      "<div id='container' style='width:3ch'>^0|123&shy;456</div>");
  auto* element = GetElementById("container");
  auto* block_flow = To<LayoutBlockFlow>(element->GetLayoutObject());
  InlineCursor cursor(*block_flow);
  while (!cursor.Current()->IsLayoutGeneratedText())
    cursor.MoveToNext();
  auto status = Selection().ComputeLayoutSelectionStatus(cursor);
  EXPECT_FALSE(status.HasValidRange());
}

TEST_F(NGLayoutSelectionTest, SoftHyphen0to4) {
  SetSelectionAndUpdateLayoutSelection(
      "<div id='container' style='width:3ch'>^0123|&shy;456</div>");
  auto* element = GetElementById("container");
  auto* block_flow = To<LayoutBlockFlow>(element->GetLayoutObject());
  InlineCursor cursor(*block_flow);
  while (!cursor.Current()->IsLayoutGeneratedText())
    cursor.MoveToNext();
  auto status = Selection().ComputeLayoutSelectionStatus(cursor);
  EXPECT_FALSE(status.HasValidRange());
}

TEST_F(NGLayoutSelectionTest, SoftHyphen1to5) {
  SetSelectionAndUpdateLayoutSelection(
      "<div id='container' style='width:3ch'>0^123&shy;|456</div>");
  auto* element = GetElementById("container");
  auto* block_flow = To<LayoutBlockFlow>(element->GetLayoutObject());
  InlineCursor cursor(*block_flow);
  while (!cursor.Current()->IsLayoutGeneratedText())
    cursor.MoveToNext();
  auto status = Selection().ComputeLayoutSelectionStatus(cursor);
  EXPECT_TRUE(status.HasValidRange());
  EXPECT_EQ(LayoutSelectionStatus(0u, 1u, SelectSoftLineBreak::kNotSelected),
            status);
}

}  // namespace blink
```