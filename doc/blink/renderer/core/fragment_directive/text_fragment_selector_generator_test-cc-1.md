Response:
The user wants to understand the functionality of the provided C++ code snippet. This code is a test file for the `TextFragmentSelectorGenerator` class in the Chromium Blink engine.

Here's a plan to address the request:

1. **Identify the core purpose:**  The file tests the generation of Text Fragment Selectors.
2. **Explain the relationship to web technologies:** Text Fragment Selectors are a URL feature directly related to HTML content.
3. **Provide examples:** Demonstrate how the tests use HTML and verify the generated selectors.
4. **Explain logical reasoning:** Each test case represents a specific scenario with input (HTML structure and selection) and expected output (generated selector).
5. **Identify potential user errors:**  While the file is a test, user errors relate to how they might manually create or interpret these selectors.
6. **Summarize the functionality:** Condense the findings into a concise description of the file's purpose.
这个C++源代码文件 `text_fragment_selector_generator_test.cc` 的主要功能是**测试 blink 引擎中 `TextFragmentSelectorGenerator` 类的功能**。

`TextFragmentSelectorGenerator` 类的作用是**根据用户在网页上选择的文本范围生成一个 Text Fragment Selector 字符串**。这个字符串可以添加到 URL 的末尾，用于直接定位到网页上的特定文本内容。

以下是它与 javascript, html, css 功能的关系以及对应的举例说明：

**1. 与 HTML 的关系：**

* **功能描述：**  `TextFragmentSelectorGenerator` 的核心是处理 HTML 结构和内容。它接收一个 HTML 文档和用户选择的文本范围作为输入。
* **举例说明：**
    * 在每个 `TEST_F` 函数中，都会加载一个包含特定 HTML 结构的字符串，并将其解析为 DOM 树。例如：
      ```c++
      request.Complete(R"HTML(
        <!DOCTYPE html>
        <div>Test page</div>
        <p id='first'>First second third fourth fifth sixth text_text_text_text_text_text_text_text_text_and_last_text</p>
      )HTML");
      ```
    * 测试会获取 HTML 元素（如 `<p>` 标签）的节点，并模拟用户在该节点内的文本选择。
      ```c++
      Node* first_paragraph =
          GetDocument().getElementById(AtomicString("first"))->firstChild();
      const auto& selected_start = Position(first_paragraph, 0);
      const auto& selected_end = Position(first_paragraph, 116);
      ```

**2. 与 Javascript 的关系 (间接)：**

* **功能描述：** 虽然这个测试文件本身是用 C++ 编写的，但 `TextFragmentSelectorGenerator`  最终会被 Javascript 调用或使用，以便在用户进行文本选择时生成对应的 URL 片段。当用户在浏览器中进行文本选择并分享链接时，浏览器可能会使用类似的功能在后台生成 Text Fragment Selector。
* **举例说明：**  在浏览器内部，当用户在网页上选中一段文本后，浏览器可能使用 Javascript API (例如 `Selection` 对象和 `Range` 对象) 来获取选区的起始和结束位置，然后调用 blink 引擎的 C++ 代码（包括 `TextFragmentSelectorGenerator`）来生成 Text Fragment Selector。这个生成的 selector 随后会被添加到 URL 中。

**3. 与 CSS 的关系 (轻微)：**

* **功能描述：** CSS 的样式可能会影响文本的渲染和布局，这间接地影响了 `TextFragmentSelectorGenerator` 如何确定文本的边界和位置。例如，`display: inline-block` 可能会影响节点的边界计算。
* **举例说明：** 在 `StartsWithInlineBlockChild` 测试中，使用了 CSS 样式 `display: inline-block;` 来影响 `<li>` 元素的布局，并测试 `TextFragmentSelectorGenerator` 在这种布局下的工作方式。
  ```c++
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      li {
        display: inline-block;
      }
    </style>
    ...
  )HTML");
  ```

**逻辑推理的假设输入与输出：**

每个 `TEST_F` 函数都包含一个逻辑推理的例子。以下以 `RangeSelector_Simple` 测试为例：

* **假设输入：**
    * **HTML:**
      ```html
      <!DOCTYPE html>
      <div>Test page</div>
      <p id='first'>First second third fourth fifth sixth text_text_text_text_text_text_text_text_text_and_last_text</p>
      ```
    * **用户选择：**  从 `<p>` 元素的开头到 "text_text_text_text_and_last_text" 之前。
    * **对应的 `selected_start`:**  指向 `<p>` 元素第一个子节点（文本节点）的偏移量 0。
    * **对应的 `selected_end`:** 指向 `<p>` 元素第一个子节点（文本节点）的偏移量 116。

* **预期输出 (生成的 Text Fragment Selector)：**
   `"First%20second%20third,fifth%20sixth%20text_text_text_text_text_text_text_text_text_and_last_text"`

**用户或编程常见的使用错误 (与 Text Fragment Selectors 相关)：**

虽然这个文件是测试代码，但可以推断出与 Text Fragment Selectors 相关的用户或编程错误：

1. **手动创建错误的 Text Fragment Selector 格式：** 用户可能手动编辑 URL，导致 Text Fragment Selector 的语法不正确，例如缺少 `:~:text=` 前缀，或者分隔符使用错误。
   * **错误示例 URL:** `https://example.com/#First%20second%20third,fifth%20sixth` (缺少 `:~:text=`)
2. **选择的文本在页面上不存在或已更改：** 如果用户分享了一个包含 Text Fragment Selector 的链接，但目标网页的内容已经更新，导致选择的文本不再存在，那么浏览器将无法定位到该文本。
3. **假设 Text Fragment Selectors 在所有浏览器中都完全一致地工作：** 尽管 Text Fragment Selectors 是一个标准，但不同浏览器可能在实现细节上存在差异，导致某些复杂的选择在某些浏览器中无法正确高亮显示。
4. **对特殊字符的错误处理：**  用户在手动创建 selector 时，可能没有正确地 URL 编码特殊字符（如空格、逗号等），导致 selector 解析失败。

**归纳一下它的功能 (第2部分)：**

这部分代码主要测试了 `TextFragmentSelectorGenerator` 在处理各种**跨元素和包含特定 HTML 结构的文本选择**时的行为。具体来说，它涵盖了以下场景：

* **跨多个文本节点的复杂选择，并验证生成的 selector 是否包含了正确的 `prefix-`, `textStart`, `textEnd`, `-suffix` 信息。**
* **处理选择范围过长的情况，确保生成的 selector 不会超出字符限制。**
* **当选择范围的起始和结束部分重叠时，生成带有上下文的 selector。**
* **确保选择的文本范围被自动补全为完整的单词。**
* **处理选择起始或结束于非文本节点的情况 (例如 `<img>` 标签)。**
* **处理选择跨越块级元素边界的情况。**
* **测试当选择的起始节点是另一个节点的子节点时，生成器是否能正确回溯到上一个文本节点。**
* **测试短选择是否使用了范围选择器。**
* **验证是否使用了最小数量的单词作为上下文和范围。**
* **处理选择结束于非文本节点但该节点没有文本子节点的情况。**
* **测试当选择包含一个具有相同起始和结束位置的范围时的行为。**
* **处理跨表格单元格的选择。**
* **处理跨 `<input>` 元素的选择。**
* **处理跨越 shadow tree 的选择 (例如 `<input type='submit'>`)。**
* **验证生成的 selector 中特殊字符是否被正确转义。**
* **测试选择紧跟 shadow tree 后的文本时，是否能正确使用 shadow tree 的内容作为前缀。**
* **测试当范围起始于 shadow host 时的行为。**
* **处理多行段落中的选择。**
* **处理 `&nbsp;` (No-Break Space) 在前缀和后缀中的情况。**
* **测试在达到最大范围词数后，是否能正确添加上下文。**
* **测试获取前一个文本结束位置的各种情况，包括前一个兄弟节点、前一个文本节点和父节点。**

总而言之，这部分测试旨在确保 `TextFragmentSelectorGenerator` 在处理各种复杂的 HTML 结构和用户选择时，能够生成符合预期的、正确的 Text Fragment Selector 字符串。

Prompt: 
```
这是目录为blink/renderer/core/fragment_directive/text_fragment_selector_generator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
and_last_text</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 0);
  const auto& selected_end = Position(first_paragraph, 116);
  ASSERT_EQ(
      "First second third fourth fifth sixth text_text_text_text_\
text_text_text_text_text_text_text_text_text_and_last_text",
      PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "First%20second%20third,fifth%20sixth%20text_text_text_text_"
                 "text_text_text_text_text_text_text_text_text_and_last_text");
}

// The generator tries to include at least 3 words from the start and end of a
// range. This test ensures that the number of words used is reduced if there
// are fewer than 6 words in the selection, preventing the start and end
// overlaping.
TEST_F(TextFragmentSelectorGeneratorTest,
       RangeSelector_OverlapFailOnFirstAttempt) {
  ScopedExactTextMaxCharsOverride force_range_generation(10);
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>one two three four five</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 0);
  const auto& selected_end = Position(first_paragraph, 23);
  ASSERT_EQ("one two three four five",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end, "one%20two,four%20five");
}

// When range start and end overlap on second or later attempt it should stop
// adding range and start adding context.
TEST_F(TextFragmentSelectorGeneratorTest, RangeSelector_OverlapNeedsContext) {
  ScopedExactTextMaxCharsOverride force_range_generation(30);
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph text one two three four five six seven eight nine ten
    end of first paragraph</p>
    <p id='second'>Second paragraph text one two three four five six seven eight nine ten
    end of second paragraph</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 21);
  const auto& selected_end = Position(first_paragraph, 69);
  ASSERT_EQ("one two three four five six seven eight nine ten",
            PlainText(EphemeralRange(selected_start, selected_end)));
  VerifySelector(selected_start, selected_end,
                 "First%20paragraph%20text-,one%20two%20three%20four%20five,"
                 "six%20seven%20eight%20nine%20ten,-end%20of%20first");
}

// Selection should be autocompleted to contain full words.
TEST_F(TextFragmentSelectorGeneratorTest, WordLimit) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph text that is longer than 20 chars</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 7);
  const auto& selected_end = Position(first_paragraph, 33);
  ASSERT_EQ("aragraph text that is long",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "paragraph%20text%20that%20is%20longer");
}

// Selection should be autocompleted to contain full words. The autocompletion
// should work with extra spaces.
TEST_F(TextFragmentSelectorGeneratorTest, WordLimit_ExtraSpaces) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First
    paragraph text
    that is longer than 20 chars</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 11);
  const auto& selected_end = Position(first_paragraph, 41);
  ASSERT_EQ("aragraph text that is long",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "paragraph%20text%20that%20is%20longer");
}

// When selection starts at the end of a word, selection shouldn't be
// autocompleted to contain extra words.
TEST_F(TextFragmentSelectorGeneratorTest,
       WordLimit_SelectionStartsAndEndsAtWordLimit) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph text that is longer  than 20 chars</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 5);
  const auto& selected_end = Position(first_paragraph, 37);
  ASSERT_EQ(" paragraph text that is longer ",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "paragraph%20text%20that%20is%20longer");
}

// Check the case when selections starts with an non text node.
TEST_F(TextFragmentSelectorGeneratorTest, StartsWithImage) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <img id="img">
    <p id='first'>First paragraph text that is longer  than 20 chars</p>
  )HTML");
  Node* img = GetDocument().getElementById(AtomicString("img"));
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& start = Position(img, 0);
  const auto& end = Position(first_paragraph, 5);
  ASSERT_EQ("\nFirst", PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end, "Test%20page-,First,-paragraph%20text%20that");
}

// Check the case when selections starts with an non text node.
TEST_F(TextFragmentSelectorGeneratorTest, StartsWithBlockWithImage) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <div id="img_div">
      <img id="img">
    </div>
    <p id='first'>First paragraph text that is longer  than 20 chars</p>
  )HTML");
  Node* img = GetDocument().getElementById(AtomicString("img_div"));
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& start = Position(img, 0);
  const auto& end = Position(first_paragraph, 5);
  ASSERT_EQ("\nFirst", PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end, "Test%20page-,First,-paragraph%20text%20that");
}

// Check the case when selections starts with a node nested in "inline-block"
// node. crbug.com/1151474
TEST_F(TextFragmentSelectorGeneratorTest, StartsWithInlineBlockChild) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      li {
        display: inline-block;
      }
    </style>
    <div>Test page</div>
    <ul>
      <li>
        <a id="link1"/>
      </li>
      <li>
        <a id="link2"/>
      </li>
      <li>
        <a id="link3"/>
      </li>
    </ul>
    <p id='first'>First paragraph text that is longer  than 20 chars</p>
  )HTML");

  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  Node* img = GetDocument().getElementById(AtomicString("link1"));
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& start = Position::LastPositionInNode(*img);
  const auto& end = Position(first_paragraph, 5);
  ASSERT_EQ("  \nFirst", PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end, "Test%20page-,First,-paragraph%20text%20that");
}

// Check the case when selections ends with an non text node.
TEST_F(TextFragmentSelectorGeneratorTest, EndswithImage) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph text that is longer than 20 chars</p>
    <img id="img">
    </img>
  )HTML");
  Node* img = GetDocument().getElementById(AtomicString("img"));
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& start = Position(first_paragraph, 44);
  const auto& end = Position(img, 0);
  ASSERT_EQ("chars\n\n", PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end, "longer%20than%2020-,chars");
}

// Check the case when selections starts at the end of the previous block.
TEST_F(TextFragmentSelectorGeneratorTest, StartIsEndofPrevBlock) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='first'>First paragraph     </p>
    <p id='second'>Second paragraph</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  Node* second_paragraph =
      GetDocument().getElementById(AtomicString("second"))->firstChild();
  const auto& start = Position(first_paragraph, 18);
  const auto& end = Position(second_paragraph, 6);
  ASSERT_EQ("\nSecond", PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end, "First%20paragraph-,Second,-paragraph");
}

// Check the case when selections starts at the end of the previous block.
TEST_F(TextFragmentSelectorGeneratorTest, EndIsStartofNextBlock) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='first'>First paragraph</p>
    <p id='second'>     Second paragraph</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  Node* second_paragraph =
      GetDocument().getElementById(AtomicString("second"))->firstChild();
  const auto& start = Position(first_paragraph, 0);
  const auto& end = Position(second_paragraph, 2);
  ASSERT_EQ("First paragraph\n\n", PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end, "First%20paragraph,-Second%20paragraph");
}

// Check the case when parent of selection start is a sibling of a node where
// selection ends.
//   :root
//  /      \
// div      p
//  |       |
//  p      "]Second"
//  |
// "[First..."
// Where [] indicate selection. In this case, when the selection is adjusted, we
// want to ensure it correctly traverses the tree back to the previous text node
// and not to the <div>(sibling of second <p>).
// See crbug.com/1154308 for more context.
TEST_F(TextFragmentSelectorGeneratorTest, PrevNodeIsSiblingsChild) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");

  // HTML is intentionally not formatted. Adding new lines and indentation
  // creates empty text nodes which changes the dom tree.
  request.Complete(R"HTML(
    <!DOCTYPE html>
  <div><p id='start'>First paragraph</p></div><p id='end'>Second paragraph</p>
  )HTML");
  GetDocument().UpdateStyleAndLayoutTree();
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("start"))->firstChild();
  Node* second_paragraph = GetDocument().getElementById(AtomicString("end"));
  const auto& start = Position(first_paragraph, 0);
  const auto& end = Position(second_paragraph, 0);
  ASSERT_EQ("First paragraph\n\n", PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end, "First%20paragraph,-Second%20paragraph");
}

// Check the case when parent of selection start is a sibling of a node where
// selection ends.
//    :root
//  /    |     \
// div  div     p
//  |    |       \
//  p   "test"   "]Second"
//  |
//"[First..."
//
// Where [] indicate selection. In this case, when the selection is adjusted, we
// want to ensure it correctly traverses the tree back to the previous text by
// correctly skipping the invisible div but not skipping the second <p>.
// See crbug.com/1154308 for more context.
TEST_F(TextFragmentSelectorGeneratorTest, PrevPrevNodeIsSiblingsChild) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  // HTML is intentionally not formatted. Adding new lines and indentation
  // creates empty text nodes which changes the dom tree.
  request.Complete(R"HTML(
    <!DOCTYPE html>
  <div><p id='start'>First paragraph</p></div><div style='display:none'>test</div><p id='end'>Second paragraph</p>
  )HTML");
  GetDocument().UpdateStyleAndLayoutTree();
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("start"))->firstChild();
  Node* second_paragraph = GetDocument().getElementById(AtomicString("end"));
  const auto& start = Position(first_paragraph, 0);
  const auto& end = Position(second_paragraph, 0);
  ASSERT_EQ("First paragraph\n\n", PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end, "First%20paragraph,-Second%20paragraph");
}

// Checks that for short selection that have nested block element range selector
// is used.
TEST_F(TextFragmentSelectorGeneratorTest, RangeSelector_SameNode_Interrupted) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div id='first'>First <div>block text</div> paragraph text</div>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& start = Position(first_paragraph, 0);
  const auto& end = Position(first_paragraph->nextSibling()->nextSibling(), 10);
  ASSERT_EQ("First\nblock text\nparagraph",
            PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end, "First,paragraph");
}

// Check min number of words is used for context if possible.
TEST_F(TextFragmentSelectorGeneratorTest, MultiwordContext) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph text that is longer than 20 chars</p>
    <p id='second'>Second paragraph text that is short</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 6);
  const auto& selected_end = Position(first_paragraph, 28);
  ASSERT_EQ("paragraph text that is",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "First-,paragraph%20text%20that%20is,-longer%20than%2020");
}

// Check min number of words is used for range if possible.
TEST_F(TextFragmentSelectorGeneratorTest, MultiWordRangeSelector) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph text that is longer than 20 chars</p>
    <p id='second'>Second paragraph text</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  Node* second_paragraph =
      GetDocument().getElementById(AtomicString("second"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 0);
  const auto& selected_end = Position(second_paragraph, 6);
  ASSERT_EQ("First paragraph text that is longer than 20 chars\n\nSecond",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "First%20paragraph%20text,Second");
}

// Checks the case when selection end position is a non text node.
TEST_F(TextFragmentSelectorGeneratorTest, SelectionEndsWithNonText) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
  <!DOCTYPE html>
  <div id='div'>
    <p id='start'>First paragraph</p>
    <p id='second'>Second paragraph</p>
  </div>
  )HTML");
  GetDocument().UpdateStyleAndLayoutTree();
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("start"))->firstChild();
  Node* div = GetDocument().getElementById(AtomicString("div"));
  const auto& start = Position(first_paragraph, 0);
  const auto& end = Position(div, 2);
  ASSERT_EQ("First paragraph\n\n", PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end, "First%20paragraph,-Second%20paragraph");
}

// Checks the case when selection end position is a non text node which doesn't
// have text child node.
TEST_F(TextFragmentSelectorGeneratorTest,
       SelectionEndsWithNonTextWithNoTextChild) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
  <div id='div'><p id='start'>First paragraph</p><p id='second'>Second paragraph</p><img id="img">
  </div>
  )HTML");
  GetDocument().UpdateStyleAndLayoutTree();
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("start"))->firstChild();
  Node* div = GetDocument().getElementById(AtomicString("div"));
  const auto& start = Position(first_paragraph, 0);
  const auto& end =
      Position(div, 3);  // Points to the 3rd child of the div, which is <img>
  ASSERT_EQ("First paragraph\n\nSecond paragraph\n\n",
            PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end, "First%20paragraph,Second%20paragraph");
}

// Checks the case when selection end position is a non text node which doesn't
// have text child node.
TEST_F(TextFragmentSelectorGeneratorTest, SelectionEndsWithImageDiv) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
  <div id='div'><p id='start'>First paragraph</p><p id='second'>Second paragraph</p><div id='div_img'><img id="img"></div>
  </div>
  )HTML");
  GetDocument().UpdateStyleAndLayoutTree();
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("start"))->firstChild();
  Node* div = GetDocument().getElementById(AtomicString("div"));
  const auto& start = Position(first_paragraph, 0);
  const auto& end =
      Position(div, 3);  // Points to the 3rd child of the div, which is div_img
  ASSERT_EQ("First paragraph\n\nSecond paragraph\n\n",
            PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end, "First%20paragraph,Second%20paragraph");
}

// Checks the case when selected range contains a range with same start and end.
// The problematic case should have both range end and suffix.
TEST_F(TextFragmentSelectorGeneratorTest, OverlappingRange) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div id='first'>First <div>block text</div>text suffix</div>
  )HTML");
  GetDocument().UpdateStyleAndLayoutTree();
  Node* start_node =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  Node* end_node =
      GetDocument().getElementById(AtomicString("first"))->lastChild();
  const auto& start = Position(start_node, 0);
  const auto& end = Position(end_node, 4);
  ASSERT_EQ("First\nblock text\ntext", PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end, "First,text,-suffix");
}

// Checks selection across table cells.
TEST_F(TextFragmentSelectorGeneratorTest, Table) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
<table id='table'>
  <tbody>
    <tr>
      <td id='row1-col1'>row1 col1</td>
      <td id='row1-col2'>row1 col2</td>
      <td id='row1-col3'>row1 col3</td>
    </tr>
  </tbody>
</table>
  )HTML");
  GetDocument().UpdateStyleAndLayoutTree();
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("row1-col1"))->firstChild();
  Node* second_paragraph =
      GetDocument().getElementById(AtomicString("row1-col3"))->firstChild();
  const auto& start = Position(first_paragraph, 0);
  const auto& end = Position(second_paragraph, 9);
  ASSERT_EQ("row1 col1\trow1 col2\trow1 col3",
            PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end, "row1%20col1,row1%20col3");
}

// Checks selection across an input element.
TEST_F(TextFragmentSelectorGeneratorTest, Input) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
  <div id='div'>
    First paragraph<input type='text'> Second paragraph
  </div>
  )HTML");
  GetDocument().UpdateStyleAndLayoutTree();
  Node* div = GetDocument().getElementById(AtomicString("div"));
  const auto& start = Position(div->firstChild(), 0);
  const auto& end = Position(div->lastChild(), 7);
  ASSERT_EQ("First paragraph Second", PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end, "First%20paragraph,Second");
}

// Checks selection across a shadow tree. Input that has text value will create
// a shadow tree,
TEST_F(TextFragmentSelectorGeneratorTest, InputSubmit) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
  <div id='div'>
    First paragraph<input type='submit' value="button text"> Second paragraph
  </div>
  )HTML");
  GetDocument().UpdateStyleAndLayoutTree();
  Node* div = GetDocument().getElementById(AtomicString("div"));
  const auto& start = Position(div->firstChild(), 0);
  const auto& end = Position(div->lastChild(), 7);
  ASSERT_EQ("First paragraph Second", PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end, "First%20paragraph,Second");
}

// Checks that haphen, ampersand and comma in selector are escaped.
// crbug.com/1245669
TEST_F(TextFragmentSelectorGeneratorTest, EscapeSelectorSpecialChars) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
  <div id='div'>First paragraph with hyphen- ampersand& and comma,</div>
  )HTML");
  GetDocument().UpdateStyleAndLayoutTree();
  Node* div = GetDocument().getElementById(AtomicString("div"));
  const auto& start = Position(div->firstChild(), 0);
  const auto& end = Position(div->firstChild(), 50);
  ASSERT_EQ("First paragraph with hyphen- ampersand& and comma,",
            PlainText(EphemeralRange(start, end)));

  VerifySelector(
      start, end,
      "First%20paragraph%20with%20hyphen%2D%20ampersand%26%20and%20comma%2C");
}

// Checks selection right after a shadow tree will use the shadow tree for
// prefix. Input with text value will create a shadow tree.
TEST_F(TextFragmentSelectorGeneratorTest, InputSubmitPrefix) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
  <div id='div'>
    <input type='submit' value="button text"> paragraph text
  </div>
  )HTML");
  GetDocument().UpdateStyleAndLayoutTree();
  Node* div = GetDocument().getElementById(AtomicString("div"));
  const auto& start = Position(div->lastChild(), 0);
  const auto& end = Position(div->lastChild(), 10);
  ASSERT_EQ(" paragraph", PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end, "button%20text-,paragraph,-text");
}

// Checks selection right after a shadow tree will use the shadow tree for
// prefix. Input with text value will create a shadow tree.
TEST_F(TextFragmentSelectorGeneratorTest, InputSubmitOneWordPrefix) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
  <div id='div'>
    <input type='submit' value="button"> paragraph text
  </div>
  )HTML");
  GetDocument().UpdateStyleAndLayoutTree();
  Node* div = GetDocument().getElementById(AtomicString("div"));
  const auto& start = Position(div->lastChild(), 0);
  const auto& end = Position(div->lastChild(), 10);
  ASSERT_EQ(" paragraph", PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end, "button-,paragraph,-text");
}

// Ensure generation works correctly when the range begins anchored to a shadow
// host. The shadow root has more children than the shadow host so this ensures
// we're using flat tree node traversals.
TEST_F(TextFragmentSelectorGeneratorTest, RangeBeginsOnShadowHost) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
  <div id='host'></div>
  the quick brown fox jumped over the lazy dog.
  )HTML");

  Element* host = GetDocument().getElementById(AtomicString("host"));
  ShadowRoot& root = host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  root.appendChild(MakeGarbageCollected<HTMLDivElement>(root.GetDocument()));
  root.appendChild(MakeGarbageCollected<HTMLDivElement>(root.GetDocument()));

  Compositor().BeginFrame();

  const auto& start = Position(host, PositionAnchorType::kAfterChildren);
  const auto& end = Position(host->nextSibling(), 12);
  ASSERT_EQ("the quick", PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end, "the%20quick,-brown%20fox%20jumped");
}

// Checks selection in multiline paragraph.
TEST_F(TextFragmentSelectorGeneratorTest, Multiline_paragraph) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
  <p id ='p'>
  first paragraph line<br>second paragraph line
  </p>
  )HTML");
  Node* p = GetDocument().getElementById(AtomicString("p"));
  const auto& start = Position(p->firstChild(), 0);
  const auto& end = Position(p->lastChild(), 24);
  ASSERT_EQ("first paragraph line\nsecond paragraph line",
            PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end,
                 "first%20paragraph%20line%0Asecond%20paragraph%20line");
}

// Checks selection in multiline paragraph.
TEST_F(TextFragmentSelectorGeneratorTest, Nbsp_before_suffix) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
  <p id ='p1'>first paragraph line.&nbsp;</p>
  <p id ='p2'>&nbsp;second paragraph line.</p>
  )HTML");
  Node* p = GetDocument().getElementById(AtomicString("p1"));
  const auto& start = Position(p->firstChild(), 16);
  const auto& end = Position(p->firstChild(), 21);
  ASSERT_EQ("line.", PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end,
                 "first%20paragraph-,line.,-second%20paragraph%20line");
}

// Checks selection in multiline paragraph.
TEST_F(TextFragmentSelectorGeneratorTest, Nbsp_before_prefix) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
  <p id ='p1'>first paragraph line.&nbsp;    </p>
  <p id ='p2'>&nbsp;    second paragraph line.</p>
  )HTML");
  Node* p = GetDocument().getElementById(AtomicString("p2"));
  const auto& start = Position(p->firstChild(), 5);
  const auto& end = Position(p->firstChild(), 11);
  ASSERT_EQ("second", PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end,
                 "first%20paragraph%20line.-,second,-paragraph%20line.");
}

// Checks that after adding max number of range words it will correctly add
// context.
TEST_F(TextFragmentSelectorGeneratorTest, ContextAfterMaxRange) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
  <p>Eletelephony</p>
  <p id = 'p1'>There was an elephant who tried to use a_telephant</p>
  <p id = 'p2'>I mean an elephone who tried to use a_telephone</p>
  <p>There was an elephant who tried to use a_telephant</p>
  <p>I mean an elephone who tried to use a_telephone</p>
  )HTML");

  Node* p1 = GetDocument().getElementById(AtomicString("p1"));
  Node* p2 = GetDocument().getElementById(AtomicString("p2"));
  const auto& start = Position(p1->firstChild(), 0);
  const auto& end = Position(p2->firstChild(), 47);
  ASSERT_EQ(
      "There was an elephant who tried to use a_telephant\n\nI mean an "
      "elephone who tried to use a_telephone",
      PlainText(EphemeralRange(start, end)));

  VerifySelector(start, end,
                 "Eletelephony-,There%20was%20an%20elephant%20who%20tried%20to%"
                 "20use%20a_telephant,I%20mean%20an%20elephone%20who%20tried%"
                 "20to%20use%20a_telephone,-There%20was%20an");
}

// Check the case when available prefix is the text content of the previous
// block.
TEST_F(TextFragmentSelectorGeneratorTest, GetPreviousTextEndPosition_PrevNode) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='first'>First paragraph text</p>
    <p id='second'>Second paragraph text</p>
  )HTML");
  Node* second_paragraph =
      GetDocument().getElementById(AtomicString("second"))->firstChild();
  const auto& start = PositionInFlatTree(second_paragraph, 0);
  const auto& end = PositionInFlatTree(second_paragraph, 6);
  ASSERT_EQ("Second", PlainText(EphemeralRangeInFlatTree(start, end)));

  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& expected_position =
      ToPositionInFlatTree(Position::LastPositionInNode(*first_paragraph));
  EXPECT_EQ(expected_position,
            CreateGenerator()->GetPreviousTextEndPosition(start));
}

// Check the case when available prefix is a text node outside of selection
// block.
TEST_F(TextFragmentSelectorGeneratorTest,
       GetPreviousTextEndPosition_PrevTextNode) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    text<p id='first'>First paragraph text</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& start = PositionInFlatTree(first_paragraph, 0);
  const auto& end = PositionInFlatTree(first_paragraph, 5);
  ASSERT_EQ("First", PlainText(EphemeralRangeInFlatTree(start, end)));

  Node* node =
      GetDocument().getElementById(AtomicString("first"))->previousSibling();
  const auto& expected_position =
      ToPositionInFlatTree(Position::LastPositionInNode(*node));
  EXPECT_EQ(expected_position,
            CreateGenerator()->GetPreviousTextEndPosition(start));
}

// Check the case when available prefix is a parent node text content outside of
// selection block.
TEST_F(TextFragmentSelectorGeneratorTest,
       GetPreviousTextEndPosition_ParentNode) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div id='div'>nested<p id='first'>First paragraph text</p></div>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& start = PositionInFlatTree(first_paragraph, 0);
  const auto& end = PositionInFlatTree(first_paragraph, 5);
  ASSERT_EQ("First", PlainText(EphemeralRangeInFlatTree(start, end)));

  Node* node = GetDocument().getElementById(AtomicString("div"))->firstChild();
  const auto& expected_position =
      ToPositionInFlatTree(Position::LastPositionInNode(*node));
  EXPECT_EQ(expected_position,
            CreateGenerator()->GetPreviousTextEndPosition(start));
}

// Check the case when previous node is used for available prefix when sele
"""


```