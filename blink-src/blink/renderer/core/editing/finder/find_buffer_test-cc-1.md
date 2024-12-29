Response:
The user wants to understand the functionality of the `find_buffer_test.cc` file, specifically the second part of the file. I need to analyze the provided C++ code snippets and summarize their purpose. The tests focus on verifying the `FindBuffer` class's ability to find text within different HTML structures and with various Unicode characters.

Here's a breakdown of the tests:

1. **Finding special Unicode characters**: Tests if `FindBuffer` can locate the object replacement character (`\uFFFC`) and the maximum Unicode code point (`\U0010FFFF`) within text, even when the text includes `<img/>` and `<script></script>` tags. It also checks for finding non-character Unicode points.
2. **Excluding suggested values**: Verifies that the find functionality doesn't search within the suggested values of input fields but does search within the autofill values.
3. **Finding in tables**: Confirms that `FindBuffer` can find text content within HTML tables.
4. **Identifying uninterrupted text blocks**: Tests the `IsInSameUninterruptedBlock` method to determine if two nodes are within the same block of text, considering the presence of inline elements and input fields.
5. **Finding block-level ancestors**: Checks the `GetFirstBlockLevelAncestorInclusive` method to correctly identify the nearest block-level ancestor of a given node.
6. **Finding the first visible text node**: Tests the `ForwardVisibleTextNode` method to locate the first visible text node within a given starting node.
7. **Handling Ruby annotations**: A series of tests focusing on how `FindBuffer` handles `<ruby>` tags and their `<rt>` annotation elements. These tests cover various scenarios, including:
    - Finding text within base and annotation parts of ruby.
    - Handling ranges that end within ruby elements.
    - Ignoring content within `display: none` elements within ruby.
    - Dealing with missing or empty `<rt>` tags.
    - Handling `<ruby>` elements without children.
    - Processing annotations that are not direct children of `<ruby>`.
    - Considering `display: contents` on elements within ruby.
    - Respecting `visibility` settings on ruby and annotation elements.
    - Handling block-level ruby elements.
    - Performing actual searches within ruby text and annotations, including nested ruby structures.
8. **Determining position after a block**:  Tests the `PositionAfterBlock` method, particularly in scenarios involving ruby annotations within block elements.

Based on these observations, I can now formulate the summary.
这是 `blink/renderer/core/editing/finder/find_buffer_test.cc` 文件的第二部分，它主要专注于测试 `FindBuffer` 类在各种复杂 HTML 结构和特殊字符场景下的查找功能。以下是对这部分代码功能的归纳：

**主要功能归纳：**

这部分测试用例旨在验证 `FindBuffer` 类在处理以下情况时的查找匹配能力：

1. **特殊 Unicode 字符的处理：**
   - 测试查找对象替换字符 (`\uFFFC`) 和最大 Unicode 代码点 (`\U0010FFFF`) 的能力，即使在包含 `<img/>` 和 `<script></script>` 等替换元素的情况下也能正确查找。
   - 验证对于非字符 Unicode 代码点的处理。

2. **排除非内容元素的查找：**
   - **不搜索输入框的建议值 (Suggested Values)：**  确保搜索操作不会在 `<input>` 元素的 `suggestedValue` 属性中查找，但会在 `autofillValue` 中查找。这与用户在输入时看到的建议选项区分开来。

3. **在复杂 HTML 结构中查找：**
   - **在表格 (`<table>`) 中查找：** 验证能否正确地在表格的单元格内容中查找到目标字符串。

4. **判断节点是否在同一不可中断的块中：**
   - 测试 `IsInSameUninterruptedBlock` 方法，用于判断两个节点是否位于同一个连续的文本块内，这个判断会考虑到 `<div>`、`<span>`、`<input>` 和 `<table>` 等不同类型的元素。

5. **查找最近的块级祖先元素：**
   - 测试 `GetFirstBlockLevelAncestorInclusive` 方法，用于获取包含给定节点的最近的块级祖先元素。

6. **查找第一个可见文本节点：**
   - 测试 `ForwardVisibleTextNode` 方法，从给定的起始节点开始，向前查找第一个可见的文本节点。

7. **处理 Ruby 注音标签 (`<ruby>`)：**
   - **创建 Ruby 缓冲：** 测试在包含 `<ruby>` 和 `<rt>` 标签的文本中创建查找缓冲区的能力，分别针对基准文本和注音文本创建不同的缓冲区。
   - **处理 Ruby 标签内的边界情况：** 测试查找范围结束于 `<ruby>` 标签内的文本节点的情况。
   - **忽略隐藏的 Ruby 注音：** 测试当 Ruby 注音标签（`<rt>`) 或其内部文本被设置为 `display: none` 时，查找功能是否会忽略这些内容。
   - **处理各种 Ruby 标签的变体：**  测试当缺少 `<rt>` 标签、`<rt>` 标签为空、`<ruby>` 标签为空或者根本没有 `<ruby>` 标签但使用了 `display: ruby-text` 样式时的查找行为。
   - **处理非子元素的 Ruby 注音：** 测试当 `<rt>` 标签不是 `<ruby>` 标签的直接子元素时的情况。
   - **处理 `display: contents` 属性：** 测试当 `<ruby>` 标签内部的元素设置了 `display: contents` 时，如何处理查找缓冲区。
   - **考虑 `visibility` 属性：** 测试当 `<ruby>` 或 `<rt>` 标签设置了 `visibility: hidden` 或 `visibility: visible` 时，查找功能如何处理。
   - **处理块级 Ruby 元素：** 测试当 `<ruby>` 元素设置为 `display: block ruby` 时的情况。
   - **在 Ruby 文本中查找：** 验证能否在包含 Ruby 注音的文本中正确查找到基准文本、注音文本或者基准文本和注音文本的组合。这包括嵌套的 Ruby 标签和在注音文本中包含 Ruby 标签的情况。

8. **获取块元素后的位置：**
   - 测试 `PositionAfterBlock` 方法，用于获取在包含 `<ruby>` 标签的块元素之后的起始位置。

**与 JavaScript, HTML, CSS 的关系：**

这些测试直接关系到浏览器如何解析和渲染 HTML，以及如何通过 JavaScript 进行文本查找操作。

* **HTML:** 测试用例使用了各种 HTML 结构，例如 `<div>`、`<p>`、`<table>`、`<input>`、`<ruby>`、`<rt>` 等，来模拟实际网页中可能出现的文本组织方式。
* **CSS:** 测试用例涉及到 CSS 的 `display` 和 `visibility` 属性，特别是对 `display: none`、`display: ruby-text`、`display: block ruby` 和 `visibility: hidden` 的处理，验证查找功能是否正确地考虑了这些样式的影响。
* **JavaScript:** 虽然测试本身是用 C++ 写的，但 `FindBuffer` 的功能最终会服务于浏览器的查找功能，用户可以通过浏览器内置的查找功能 (通常通过 Ctrl+F 或 Cmd+F 触发) 或 JavaScript 的相关 API (例如 `window.find()`) 来触发查找操作。这些测试保证了底层的查找逻辑在各种 HTML 和 CSS 场景下的正确性。

**逻辑推理的假设输入与输出：**

以下是一些测试用例的假设输入和预期输出的例子：

* **假设输入:** HTML 字符串 `<p>Hello <b>World</b>!</p>`, 查找字符串 "World"
* **预期输出:** 查找到一个匹配项。

* **假设输入:** HTML 字符串 `<input type="text" name="search">`, 元素 `input` 的 `suggestedValue` 为 "example", 查找字符串 "example"
* **预期输出:** 没有匹配项 (因为不应该在 suggestedValue 中查找)。

* **假设输入:** HTML 字符串 `<ruby>漢字<rt>かんじ</rt></ruby>`, 查找字符串 "かんじ"
* **预期输出:** 查找到一个匹配项。

**用户或编程常见的使用错误：**

* **用户错误：** 用户可能在网页上使用浏览器的查找功能，期望能找到所有匹配的文本，包括 Ruby 注音。这些测试确保即使在复杂的 Ruby 标签结构中，查找功能也能按预期工作。
* **编程错误：** 开发者在使用 JavaScript 进行文本搜索时，可能会依赖浏览器的底层查找能力。如果 `FindBuffer` 的逻辑有错误，可能会导致 JavaScript 的查找 API 返回不正确的结果。例如，如果 `FindBuffer` 没有正确处理 `display: none` 的元素，JavaScript 的搜索可能会意外地找到隐藏的内容。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户打开一个包含复杂 HTML 结构的网页：**  例如，网页中包含表格、输入框、使用了 Ruby 注音的日文文本等。
2. **用户按下 Ctrl+F (或 Cmd+F) 打开浏览器的查找栏。**
3. **用户在查找栏中输入要查找的关键词。**
4. **浏览器调用 Blink 引擎的查找功能。**
5. **Blink 引擎的查找功能会创建 `FindBuffer` 对象，并根据当前文档的结构和用户输入的关键词进行查找。**
6. **`FindBuffer` 对象会遍历 DOM 树，并利用其内部的逻辑 (这些测试正在验证这些逻辑) 来定位匹配的文本。**
7. **如果网页包含 `<ruby>` 标签，`FindBuffer` 会根据其 Ruby 处理逻辑，分别在基准文本和注音文本中进行查找。**
8. **测试用例中的 `SetBodyContent` 函数模拟了加载不同 HTML 内容的步骤。**
9. **测试用例中的 `FindMatches` 函数模拟了用户发起查找操作。**
10. **断言 (例如 `ASSERT_EQ`, `EXPECT_EQ`) 用于验证 `FindBuffer` 的查找结果是否符合预期，从而确保查找功能的正确性。**

**总结来说，这部分 `find_buffer_test.cc` 文件的功能是全面测试 Blink 引擎中 `FindBuffer` 类在各种复杂的 HTML 结构和特殊情况下的文本查找能力，特别是针对包含替换元素、表单元素和 Ruby 注音标签的场景。这些测试对于确保浏览器查找功能的准确性和可靠性至关重要。**

Prompt: 
```
这是目录为blink/renderer/core/editing/finder/find_buffer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
t with <script></script> and \uFFFC (object replacement "
      "character)");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  const auto results = buffer.FindMatches(u"\uFFFC", FindOptions());
  ASSERT_EQ(1u, results.CountForTesting());
}

TEST_P(FindBufferParamTest,
       FindMaxCodepointWithReplacedElementAndMaxCodepointUTF32) {
  SetBodyContent(
      "some text with <img/> <script></script> and \U0010FFFF (max codepoint)");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  const auto results = buffer.FindMatches(u"\U0010FFFF", FindOptions());
  ASSERT_EQ(1u, results.CountForTesting());
}

TEST_P(FindBufferParamTest, FindMaxCodepointNormalTextUTF32) {
  SetBodyContent("some text");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  const auto results = buffer.FindMatches(u"\U0010FFFF", FindOptions());
  ASSERT_EQ(0u, results.CountForTesting());
}

TEST_P(FindBufferParamTest, FindMaxCodepointWithReplacedElementUTF32) {
  SetBodyContent("some text with <img/> <script></script>");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  const auto results = buffer.FindMatches(u"\U0010FFFF", FindOptions());
  ASSERT_EQ(0u, results.CountForTesting());
}

TEST_P(FindBufferParamTest,
       FindNonCharacterWithReplacedElementAndNonCharacterUTF16) {
  SetBodyContent(
      "some text with <img/> <scrip></script> and \uFFFF (non character)");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  const auto results = buffer.FindMatches(u"\uFFFF", FindOptions());
  ASSERT_EQ(1u, results.CountForTesting());
}

TEST_P(FindBufferParamTest, FindNonCharacterNormalTextUTF16) {
  SetBodyContent("some text");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  const auto results = buffer.FindMatches(u"\uFFFF", FindOptions());
  ASSERT_EQ(0u, results.CountForTesting());
}

TEST_P(FindBufferParamTest, FindNonCharacterWithReplacedElementUTF16) {
  SetBodyContent("some text with <img/> <script></script>");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  const auto results = buffer.FindMatches(u"\uFFFF", FindOptions());
  ASSERT_EQ(0u, results.CountForTesting());
}

// Tests that a suggested value is not found by searches.
TEST_P(FindBufferParamTest, DoNotSearchInSuggestedValues) {
  SetBodyContent("<input name='field' type='text'>");

  // The first node of the document should be the input field.
  Node* input_element = GetDocument().body()->firstChild();
  ASSERT_TRUE(IsA<TextControlElement>(*input_element));
  TextControlElement& text_control_element =
      To<TextControlElement>(*input_element);
  ASSERT_EQ(text_control_element.NameForAutofill(), "field");

  // The suggested value to a string that contains the search string.
  text_control_element.SetSuggestedValue("aba");
  ASSERT_EQ(text_control_element.SuggestedValue(), "aba");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  {
    // Apply a search for 'aba'.
    FindBuffer buffer(WholeDocumentRange(), GetParam());
    const auto results = buffer.FindMatches("aba", FindOptions());

    // There should be no result because the suggested value is not supposed to
    // be considered in a search.
    EXPECT_EQ(0U, results.CountForTesting());
  }
  // Convert the suggested value to an autofill value.
  text_control_element.SetAutofillValue(text_control_element.SuggestedValue());
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  {
    // Apply a search for 'aba' again.
    FindBuffer buffer(WholeDocumentRange(), GetParam());
    const auto results = buffer.FindMatches("aba", FindOptions());

    // This time, there should be a match.
    EXPECT_EQ(1U, results.CountForTesting());
  }
}

TEST_P(FindBufferParamTest, FindInTable) {
  SetBodyContent(
      "<table id='table'><tbody><tr id='row'><td id='c1'>c1 "
      "<i>i</i></td></tr></tbody></table>");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  const auto results = buffer.FindMatches("c1", FindOptions());
  ASSERT_EQ(1u, results.CountForTesting());
}

TEST_F(FindBufferTest, IsInSameUninterruptedBlock) {
  SetBodyContent(
      "<div id=outer>a<div id=inner>b</div><i id='styled'>i</i>c</div>");
  Node* text_node_a = GetElementById("outer")->firstChild();
  Node* styled = GetElementById("styled");
  Node* text_node_i = GetElementById("styled")->firstChild();
  Node* text_node_c = GetElementById("outer")->lastChild();
  Node* text_node_b = GetElementById("inner")->firstChild();

  ASSERT_TRUE(
      FindBuffer::IsInSameUninterruptedBlock(*text_node_i, *text_node_c));
  ASSERT_TRUE(FindBuffer::IsInSameUninterruptedBlock(*styled, *text_node_c));
  ASSERT_FALSE(
      FindBuffer::IsInSameUninterruptedBlock(*text_node_a, *text_node_c));
  ASSERT_FALSE(
      FindBuffer::IsInSameUninterruptedBlock(*text_node_a, *text_node_b));
}

TEST_F(FindBufferTest, IsInSameUninterruptedBlock_input) {
  SetBodyContent("<div id='outer'>a<input value='input' id='input'>b</div>");
  Node* text_node_a = GetElementById("outer")->firstChild();
  Node* text_node_b = GetElementById("outer")->lastChild();
  Node* input = GetElementById("input");
  Node* editable_div = FlatTreeTraversal::Next(*input);

  // input elements are followed by an editable div that contains the input
  // field value.
  ASSERT_EQ("input", editable_div->textContent());

  ASSERT_FALSE(
      FindBuffer::IsInSameUninterruptedBlock(*text_node_a, *text_node_b));
  ASSERT_FALSE(FindBuffer::IsInSameUninterruptedBlock(*text_node_a, *input));
  ASSERT_FALSE(
      FindBuffer::IsInSameUninterruptedBlock(*text_node_a, *editable_div));
}

TEST_F(FindBufferTest, IsInSameUninterruptedBlock_table) {
  SetBodyContent(
      "<table id='table'>"
      "<tbody>"
      "<tr id='row'>"
      "  <td id='c1'>c1</td>"
      "  <td id='c2'>c2</td>"
      "  <td id='c3'>c3</td>"
      "</tr>"
      "</tbody>"
      "</table>");
  Node* text_node_1 = GetElementById("c1")->firstChild();
  Node* text_node_3 = GetElementById("c3")->firstChild();

  ASSERT_FALSE(
      FindBuffer::IsInSameUninterruptedBlock(*text_node_1, *text_node_3));
}

TEST_F(FindBufferTest, IsInSameUninterruptedBlock_comment) {
  SetBodyContent(
      "<div id='text'><span id='span1'>abc</span><!--comment--><span "
      "id='span2'>def</span></div>");
  Node* span_1 = GetElementById("span1")->firstChild();
  Node* span_2 = GetElementById("span2")->firstChild();

  ASSERT_TRUE(FindBuffer::IsInSameUninterruptedBlock(*span_1, *span_2));
}

TEST_F(FindBufferTest, GetFirstBlockLevelAncestorInclusive) {
  SetBodyContent("<div id=outer>a<div id=inner>b</div>c</div>");
  Node* outer_div = GetElementById("outer");
  Node* text_node_a = GetElementById("outer")->firstChild();
  Node* text_node_c = GetElementById("outer")->lastChild();
  Node* inner_div = GetElementById("inner");
  Node* text_node_b = GetElementById("inner")->firstChild();

  ASSERT_EQ(outer_div,
            FindBuffer::GetFirstBlockLevelAncestorInclusive(*text_node_a));
  ASSERT_EQ(outer_div,
            FindBuffer::GetFirstBlockLevelAncestorInclusive(*text_node_c));
  ASSERT_EQ(inner_div,
            FindBuffer::GetFirstBlockLevelAncestorInclusive(*text_node_b));
}

TEST_F(FindBufferTest, ForwardVisibleTextNode) {
  SetBodyContent("\n<div>\n<p>a</p></div");
  Node* text = FindBuffer::ForwardVisibleTextNode(*GetDocument().body());
  ASSERT_TRUE(text);
  EXPECT_TRUE(IsA<Text>(*text));
  EXPECT_EQ(String("a"), To<Text>(text)->data());
}

static String ReplaceZero(const String& chars) {
  String result(chars);
  result.Replace(0, '_');
  return result;
}

TEST_F(FindBufferTest, RubyBuffersBasic) {
  SetBodyContent(
      "<p id=container>before <ruby id=r>base<rt>anno</ruby> after</p>");
  FindBuffer buffer(CreateRange(*GetElementById("r")->firstChild(), 2,
                                *GetElementById("r")->nextSibling(), 4),
                    RubySupport::kEnabledIfNecessary);
  auto buffer_list = buffer.BuffersForTesting();
  ASSERT_EQ(2u, buffer_list.size());
  EXPECT_EQ("se____ aft", ReplaceZero(buffer_list[0]));
  EXPECT_EQ("__anno aft", ReplaceZero(buffer_list[1]));
}

TEST_P(FindBufferParamTest, RubyBuffersEndAtTextInRuby) {
  SetBodyContent(
      "<p id=p>before <ruby id=r>base<rt id=rt>anno</rt>base2</ruby> "
      "after</p>");
  FindBuffer buffer(CreateRange(*GetElementById("p"), 0,
                                *GetElementById("rt")->firstChild(), 2),
                    GetParam());
  EXPECT_EQ(PositionInFlatTree::FirstPositionInNode(
                *GetElementById("rt")->nextSibling()),
            buffer.PositionAfterBlock());
}

TEST_P(FindBufferParamTest, RubyBuffersEndAtDisplayNoneTextInRuby) {
  SetBodyContent(
      "<p id=p>before <ruby id=r>base <span style='display:none' "
      "id=none>text</span> base<rt>anno</ruby> after</p>");
  FindBuffer buffer(CreateRange(*GetElementById("p"), 0,
                                *GetElementById("none")->firstChild(), 2),
                    GetParam());
  EXPECT_EQ(PositionInFlatTree::FirstPositionInNode(
                *GetElementById("none")->nextSibling()),
            buffer.PositionAfterBlock());
}

TEST_F(FindBufferTest, RubyBuffersNoRt) {
  SetBodyContent("<p>before <rub>base</ruby> after</p>");
  FindBuffer buffer(WholeDocumentRange(), RubySupport::kEnabledIfNecessary);
  auto buffer_list = buffer.BuffersForTesting();
  ASSERT_EQ(1u, buffer_list.size());
  EXPECT_EQ("before base after", ReplaceZero(buffer_list[0]));
}

TEST_F(FindBufferTest, RubyBuffersEmptyRt) {
  SetBodyContent("<p>before <ruby>base<rt></ruby> after</p>");
  FindBuffer buffer(WholeDocumentRange(), RubySupport::kEnabledIfNecessary);
  auto buffer_list = buffer.BuffersForTesting();
  ASSERT_EQ(1u, buffer_list.size());
  EXPECT_EQ("before base after", ReplaceZero(buffer_list[0]));
}

TEST_F(FindBufferTest, RubyBuffersEmptyRuby) {
  SetBodyContent("<p>before <ruby><rt>anno</ruby> after</p>");
  FindBuffer buffer(WholeDocumentRange(), RubySupport::kEnabledIfNecessary);
  auto buffer_list = buffer.BuffersForTesting();
  ASSERT_EQ(2u, buffer_list.size());
  EXPECT_EQ("before ____ after", ReplaceZero(buffer_list[0]));
  EXPECT_EQ("before anno after", ReplaceZero(buffer_list[1]));
}

TEST_F(FindBufferTest, RubyBuffersNoRuby) {
  SetBodyContent(
      "<p>before <span style='display:ruby-text'>anno</span> after</p>");
  FindBuffer buffer(WholeDocumentRange(), RubySupport::kEnabledIfNecessary);
  auto buffer_list = buffer.BuffersForTesting();
  ASSERT_EQ(2u, buffer_list.size());
  EXPECT_EQ("before ____ after", ReplaceZero(buffer_list[0]));
  EXPECT_EQ("before anno after", ReplaceZero(buffer_list[1]));
}

TEST_F(FindBufferTest, RubyBuffersNonChildRt) {
  SetBodyContent(
      "<p>before <ruby>base <b><span "
      "style='display:ruby-text'>anno</span></b></ruby> after</p>");
  FindBuffer buffer(WholeDocumentRange(), RubySupport::kEnabledIfNecessary);
  auto buffer_list = buffer.BuffersForTesting();
  ASSERT_EQ(2u, buffer_list.size());
  EXPECT_EQ("before base ____ after", ReplaceZero(buffer_list[0]));
  EXPECT_EQ("before base anno after", ReplaceZero(buffer_list[1]));
}

TEST_F(FindBufferTest, RubyBuffersDisplayContents) {
  SetBodyContent(
      "<p>before <ruby>base <b style='display:contents'><span "
      "style='display:ruby-text'>anno</span></b></ruby> after</p>");
  FindBuffer buffer(WholeDocumentRange(), RubySupport::kEnabledIfNecessary);
  auto buffer_list = buffer.BuffersForTesting();
  ASSERT_EQ(2u, buffer_list.size());
  EXPECT_EQ("before base ____ after", ReplaceZero(buffer_list[0]));
  EXPECT_EQ("before _____anno after", ReplaceZero(buffer_list[1]));
}

TEST_F(FindBufferTest, RubyBuffersVisibility) {
  SetBodyContent(
      "<p>before "
      "<ruby style='visibility:hidden'>base1<rt>anno1</ruby> "
      "<ruby>base2<rt style='visibility:hidden'>anno2</ruby> "
      "<ruby style='visibility:hidden'>base3"
      "<rt style='visibility:visible'>anno3</ruby> "
      "after</p>");
  FindBuffer buffer(WholeDocumentRange(), RubySupport::kEnabledIfNecessary);
  auto buffer_list = buffer.BuffersForTesting();
  ASSERT_EQ(2u, buffer_list.size());
  EXPECT_EQ("before  base2 _____ after", ReplaceZero(buffer_list[0]));
  EXPECT_EQ("before  _____ anno3 after", ReplaceZero(buffer_list[1]));
}

TEST_F(FindBufferTest, RubyBuffersBlockRuby) {
  SetBodyContent(
      "<p>before <ruby id=r style='display:block ruby'>base<rt>anno</ruby> "
      "after</p>");
  FindBuffer buffer(CreateRange(*GetElementById("r")->firstChild(), 2,
                                *GetElementById("r")->nextSibling(), 4),
                    RubySupport::kEnabledIfNecessary);
  auto buffer_list = buffer.BuffersForTesting();
  ASSERT_EQ(2u, buffer_list.size());
  // The range end position is in " after", but the FindBuffer should have an
  // IFC scope, which is <ruby> in this case.
  EXPECT_EQ("se____", ReplaceZero(buffer_list[0]));
  EXPECT_EQ("__anno", ReplaceZero(buffer_list[1]));
}

TEST_F(FindBufferTest, FindRuby) {
  SetBodyContent(
      "<p>残暑お<ruby>見<rt>み</ruby><ruby>舞<rt>ま</ruby>い"
      "申し上げます。</p>");
  {
    FindBuffer buffer(WholeDocumentRange(), RubySupport::kEnabledIfNecessary);
    const auto results = buffer.FindMatches(u"おみまい", FindOptions());
    EXPECT_EQ(1u, results.CountForTesting());
  }
  {
    FindBuffer buffer(WholeDocumentRange(), RubySupport::kEnabledIfNecessary);
    const auto results = buffer.FindMatches(u"お見舞い", FindOptions());
    EXPECT_EQ(1u, results.CountForTesting());
  }
  {
    FindBuffer buffer(WholeDocumentRange(), RubySupport::kEnabledIfNecessary);
    EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, u"お見まい"));
  }
}

TEST_F(FindBufferTest, FindRubyNested) {
  SetBodyContent(
      "<p>の<ruby><ruby>超電磁砲<rt>レールガン</ruby><rt>railgun</ruby></p>");
  {
    FindBuffer buffer(WholeDocumentRange(), RubySupport::kEnabledIfNecessary);
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"の超"));
  }
  {
    FindBuffer buffer(WholeDocumentRange(), RubySupport::kEnabledIfNecessary);
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"のれーる"));
  }
  {
    FindBuffer buffer(WholeDocumentRange(), RubySupport::kEnabledIfNecessary);
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"のRAIL"));
  }
}

TEST_F(FindBufferTest, FindRubyOnAnnotation) {
  SetBodyContent(
      "<p>の<ruby>超電磁砲<rt>レール<ruby>ガン<rt>gun</ruby></ruby></p>");
  {
    FindBuffer buffer(WholeDocumentRange(), RubySupport::kEnabledIfNecessary);
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"の超電磁砲"));
  }
  {
    FindBuffer buffer(WholeDocumentRange(), RubySupport::kEnabledIfNecessary);
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"のれーるガン"));
  }
  {
    FindBuffer buffer(WholeDocumentRange(), RubySupport::kEnabledIfNecessary);
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"のレールgun"));
  }
}

// crbug.com/376720481
TEST_P(FindBufferParamTest, PositionAfterBlock) {
  SetBodyContent("<div><p><ruby>境界面<rt>インターフェース</ruby></div>cw");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  FindResults results = buffer.FindMatches("cw", kCaseInsensitive);
  EXPECT_EQ(0u, results.CountForTesting());
  EXPECT_EQ(PositionInFlatTree::FirstPositionInNode(
                *GetDocument().body()->lastChild()),
            buffer.PositionAfterBlock());
}

}  // namespace blink

"""


```