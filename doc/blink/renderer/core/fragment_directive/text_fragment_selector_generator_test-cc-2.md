Response:
The user wants to understand the functionality of the C++ source code file `text_fragment_selector_generator_test.cc` within the Chromium Blink engine. Specifically, they're asking for:

1. **General functionality:** What does this file do?
2. **Relationship to web technologies:** How does it relate to JavaScript, HTML, and CSS?
3. **Logic and examples:**  If there's logical reasoning, provide examples with inputs and outputs.
4. **Common user errors:**  Point out common mistakes related to this functionality.
5. **Summary:** A concise overview of the file's purpose.

Given that this is part 3 of 3, the previous parts likely established the general concept of Text Fragment Selectors and potentially the core logic of the `TextFragmentSelectorGenerator`. This part focuses on *testing* that generator.

**Mental Model:** This file is a unit test suite for the `TextFragmentSelectorGenerator`. It contains various test cases that verify the generator's behavior under different HTML structures and selection scenarios.

**Step-by-step analysis of the provided code:**

1. **Includes:**  The file likely includes necessary headers for testing, DOM manipulation, and the `TextFragmentSelectorGenerator` itself. *Although not shown, this is a safe assumption.*
2. **Test Fixture:** The `TextFragmentSelectorGeneratorTest` class is a test fixture, providing setup and teardown for each test. It probably has a `CreateGenerator()` method to instantiate the object being tested.
3. **`GetPreviousTextEndPosition_*` Tests:** These test cases focus on verifying the logic for finding the end position of the text preceding a given selection. They cover scenarios like:
    * Spaces before the selection.
    * Invisible elements before the selection.
    * No preceding text.
    * Involving different HTML structures (paragraph, div).
4. **`GetNextTextStartPosition_*` Tests:** These test cases mirror the previous set, but for finding the starting position of text following a selection. They cover similar scenarios:
    * Next node.
    * Comments between the selection and the next node.
    * Text nodes outside the selection block.
    * Parent node text content.
    * Spaces after the selection.
    * Invisible blocks after the selection.
    * No following text.
5. **`BeforeAndAfterAnchor` Test:** This test case checks how the generator handles selections that are not within text nodes but at the boundaries of an element (before the opening tag or after the closing tag). It expects this to fail as it's an empty text selection.
6. **`GetPreviousTextEndPosition_ShouldSkipNodesWithNoLayoutObject` Test:** This tests a specific edge case involving Shadow DOM and elements that don't have a layout object. It verifies that the generator correctly skips such elements when looking for preceding text.
7. **`RemoveLayoutObjectAsync` Test:** This is a more complex test dealing with asynchronous operations and potential race conditions. It simulates a scenario where the layout of an element is changed (making it invisible) while the `TextFragmentSelectorGenerator` is in the middle of its processing. This test aims to ensure the generator handles such situations gracefully and doesn't crash or produce incorrect results.

**Connecting to Web Technologies:**

* **HTML:** The tests heavily rely on creating and manipulating HTML structures. The input for each test is an HTML snippet.
* **CSS:** The `display:none` style in some tests demonstrates the interaction between CSS and the generator's logic (handling invisible content).
* **JavaScript:**  While this specific C++ file doesn't *directly* involve JavaScript code, the functionality being tested is crucial for features that allow JavaScript to interact with and manipulate text fragments on a web page. For instance, JavaScript might use the generated Text Fragment Selector to scroll to a specific text snippet.

**Logical Reasoning and Examples:**

For each test case, we can define the *input* as the HTML structure and the selected text range (start and end positions). The *expected output* is the position returned by the generator (either a valid `PositionInFlatTree` or an empty one).

* **Example (GetPreviousTextEndPosition_SpacesBeforeSelection):**
    * **Input HTML:**
      ```html
      <p id='first'>First paragraph text</p>
      <p id='second'>
        Second paragraph text
      </p>
      ```
    * **Selected Range:** "Second" within the second paragraph.
    * **Expected Output:** The position after the last character of the text content in the first paragraph ("First paragraph text").

**Common User/Programming Errors:**

* **Selecting non-text nodes:**  The `BeforeAndAfterAnchor` test illustrates a potential error where a selection might target element boundaries instead of actual text content. The generator is designed to handle this by indicating an error (empty selection).
* **Assuming synchronous behavior:** The `RemoveLayoutObjectAsync` test highlights the importance of understanding that the generation process might involve asynchronous operations. Modifying the DOM while the generator is running could lead to unexpected behavior if not handled correctly by the generator (which this test verifies).

**Final Summary:**

This file, `text_fragment_selector_generator_test.cc`, is a critical component of the Chromium Blink engine's testing infrastructure. It specifically tests the `TextFragmentSelectorGenerator`, ensuring its correctness and robustness in identifying the appropriate context (prefix and suffix) for a given text selection within various HTML structures, including scenarios involving invisible elements, comments, and asynchronous DOM modifications. This functionality is essential for features like text fragment navigation (e.g., `#text=...` URLs) and is indirectly related to how JavaScript can interact with the content of web pages.
这是文件 `blink/renderer/core/fragment_directive/text_fragment_selector_generator_test.cc` 的第 3 部分，也是最后一部分。结合前两部分的内容，我们可以归纳出它的主要功能是：

**核心功能：测试 `TextFragmentSelectorGenerator` 类的功能。**

更具体地说，这个测试文件旨在验证 `TextFragmentSelectorGenerator` 类在生成文本片段选择器时，如何正确地识别和处理目标文本片段的上下文（前缀和后缀）。它通过一系列的单元测试来覆盖各种不同的 HTML 结构和文本选择场景，确保生成的选择器能够准确地定位到目标文本。

**具体测试的功能点包括：**

* **获取目标文本片段之前的文本位置 (`GetPreviousTextEndPosition`)：**
    * 测试了目标文本片段前面有空格的情况。
    * 测试了目标文本片段前面有不可见元素（`display:none`）的情况。
    * 测试了目标文本片段是所在块的第一个文本节点的情况（没有前缀）。
    * 测试了在 Shadow DOM 中，需要跳过没有布局对象的节点（EOL 节点）的情况。
* **获取目标文本片段之后的文本位置 (`GetNextTextStartPosition`)：**
    * 测试了目标文本片段后面是下一个兄弟文本节点的情况。
    * 测试了目标文本片段后面有 HTML 注释的情况。
    * 测试了目标文本片段后面是父节点的文本内容的情况。
    * 测试了目标文本片段后面有空格的情况。
    * 测试了目标文本片段后面有不可见元素的情况。
    * 测试了目标文本片段是所在块的最后一个文本节点的情况（没有后缀）。
* **处理锚点位置的选择 (`BeforeAndAfterAnchor`)：** 测试了当选择的不是文本节点，而是元素的前后锚点时，生成器是否会正确处理（预期会失败并返回 `LinkGenerationError::kEmptySelection`）。
* **处理异步操作和布局对象移除的情况 (`RemoveLayoutObjectAsync`)：** 这是一个比较复杂的测试，模拟了在 `TextFragmentSelectorGenerator` 执行异步操作期间，目标元素的布局对象被移除的情况。这个测试验证了生成器是否能够在这种情况下安全地完成操作，避免崩溃或产生错误的结果。

**与 JavaScript, HTML, CSS 的关系：**

虽然这个文件本身是用 C++ 编写的测试代码，但它直接测试了与 Web 技术息息相关的功能：

* **HTML:**  测试用例中使用了大量的 HTML 代码片段来模拟不同的网页结构。`TextFragmentSelectorGenerator` 的核心任务就是分析和理解 HTML 结构，以便找到目标文本片段的上下文。
* **CSS:**  测试用例中使用了 `style='display:none'` 来模拟不可见元素的情况。这表明 `TextFragmentSelectorGenerator` 需要考虑 CSS 的渲染效果，因为它会影响文本的可见性和位置。
* **JavaScript:**  虽然此文件没有直接的 JavaScript 代码，但 `TextFragmentSelectorGenerator` 生成的文本片段选择器（例如 `#text=prefix-,targetText,-suffix`）会被 JavaScript 使用。JavaScript 可以解析这些选择器，并在页面上滚动到或高亮显示特定的文本片段。例如，当用户点击包含文本片段选择器的链接时，浏览器会使用 `TextFragmentSelectorGenerator` 生成的选择器来定位页面上的目标文本。

**逻辑推理的假设输入与输出：**

以 `GetPreviousTextEndPosition_SpacesBeforeSelection` 测试为例：

* **假设输入 HTML:**
  ```html
  <!DOCTYPE html>
  <p id='first'>First paragraph text</p>
  <p id='second'>
    Second paragraph text
  </p>
  ```
* **选中文本范围:**  "Second" (从第二个 `<p>` 元素的第 6 个字符到第 12 个字符)
* **预期输出:**  `GetPreviousTextEndPosition` 应该返回第一个 `<p>` 元素中最后一个字符的位置（也就是 "t" 之后的位置）。

**涉及用户或编程常见的使用错误：**

* **选择非文本节点作为目标:**  `BeforeAndAfterAnchor` 测试模拟了这种情况。用户或程序可能错误地尝试选择元素标签的开头或结尾，而不是实际的文本内容。`TextFragmentSelectorGenerator` 会将这种选择视为无效的空选择。
* **假设选择器在 DOM 结构改变后仍然有效:**  `RemoveLayoutObjectAsync` 测试强调了 DOM 结构的动态性。如果在生成选择器后，页面的 DOM 结构发生了变化（例如元素被删除或隐藏），之前生成的选择器可能不再准确。开发者需要注意这种情况，并在必要时重新生成选择器。

**总结其功能:**

总而言之，`blink/renderer/core/fragment_directive/text_fragment_selector_generator_test.cc` 的主要功能是 **全面测试 `TextFragmentSelectorGenerator` 类的正确性和健壮性**。它通过大量的单元测试覆盖了各种边缘情况和复杂场景，确保该类能够准确地识别文本片段的上下文，并能够应对异步操作和 DOM 结构变化带来的挑战。这个测试文件对于保证 Chromium 浏览器中文本片段选择器功能的稳定性和可靠性至关重要。

### 提示词
```
这是目录为blink/renderer/core/fragment_directive/text_fragment_selector_generator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
ction
// is not at index=0 but there is only space before it.
TEST_F(TextFragmentSelectorGeneratorTest,
       GetPreviousTextEndPosition_SpacesBeforeSelection) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='first'>First paragraph text</p>
    <p id='second'>
      Second paragraph text
    </p>
  )HTML");
  Node* second_paragraph =
      GetDocument().getElementById(AtomicString("second"))->firstChild();
  const auto& start = PositionInFlatTree(second_paragraph, 6);
  const auto& end = PositionInFlatTree(second_paragraph, 13);
  ASSERT_EQ("Second", PlainText(EphemeralRangeInFlatTree(start, end)));

  Node* node =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& expected_position =
      ToPositionInFlatTree(Position::LastPositionInNode(*node));
  EXPECT_EQ(expected_position,
            CreateGenerator()->GetPreviousTextEndPosition(start));
}

// Check the case when previous node is used for available prefix when selection
// is not at index=0 but there is only invisible block.
TEST_F(TextFragmentSelectorGeneratorTest,
       GetPreviousTextEndPosition_InvisibleBeforeSelection) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='first'>First paragraph text</p>
    <div id='second'>
      <p id='invisible' style='display:none'>
        invisible text
      </p>
      Second paragraph text
    </div>
  )HTML");
  Node* second_paragraph =
      GetDocument().getElementById(AtomicString("invisible"))->nextSibling();
  const auto& start = PositionInFlatTree(second_paragraph, 6);
  const auto& end = PositionInFlatTree(second_paragraph, 13);
  ASSERT_EQ("Second", PlainText(EphemeralRangeInFlatTree(start, end)));

  Node* node =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& expected_position =
      ToPositionInFlatTree(Position::LastPositionInNode(*node));
  EXPECT_EQ(expected_position,
            CreateGenerator()->GetPreviousTextEndPosition(start));
}

// Check the case when available prefix complete text content of the previous
// block.
TEST_F(TextFragmentSelectorGeneratorTest,
       GetPreviousTextEndPosition_NoPrevious) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='first'>First paragraph text</p>
  )HTML");
  Node* second_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& start = PositionInFlatTree(second_paragraph, 0);
  const auto& end = PositionInFlatTree(second_paragraph, 5);
  ASSERT_EQ("First", PlainText(EphemeralRangeInFlatTree(start, end)));

  PositionInFlatTree expected_position;
  EXPECT_EQ(expected_position,
            CreateGenerator()->GetPreviousTextEndPosition(start));
}

// Similar test for suffix.

// Check the case when available suffix is complete text content of the next
// block.
TEST_F(TextFragmentSelectorGeneratorTest, GetNextTextStartPosition_NextNode) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='first'>First paragraph text</p>
    <p id='second'>Second paragraph text</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& start = PositionInFlatTree(first_paragraph, 0);
  const auto& end = PositionInFlatTree(first_paragraph, 20);
  ASSERT_EQ("First paragraph text",
            PlainText(EphemeralRangeInFlatTree(start, end)));

  Node* node =
      GetDocument().getElementById(AtomicString("second"))->firstChild();
  const auto& expected_position =
      ToPositionInFlatTree(Position::FirstPositionInNode(*node));
  EXPECT_EQ(expected_position,
            CreateGenerator()->GetNextTextStartPosition(end));
}

// Check the case when there is a commented block between selection and the
// available suffix.
TEST_F(TextFragmentSelectorGeneratorTest,
       GetNextTextStartPosition_NextNode_WithComment) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='first'>First paragraph text</p>
    <!--
      multiline comment that should be ignored.
    //-->
    <p id='second'>Second paragraph text</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& start = PositionInFlatTree(first_paragraph, 0);
  const auto& end = PositionInFlatTree(first_paragraph, 20);
  ASSERT_EQ("First paragraph text",
            PlainText(EphemeralRangeInFlatTree(start, end)));

  Node* node =
      GetDocument().getElementById(AtomicString("second"))->firstChild();
  const auto& expected_position =
      ToPositionInFlatTree(Position::FirstPositionInNode(*node));
  EXPECT_EQ(expected_position,
            CreateGenerator()->GetNextTextStartPosition(end));
}

// Check the case when available suffix is a text node outside of selection
// block.
TEST_F(TextFragmentSelectorGeneratorTest,
       GetNextTextStartPosition_NextTextNode) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='first'>First paragraph text</p>text
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& start = PositionInFlatTree(first_paragraph, 0);
  const auto& end = PositionInFlatTree(first_paragraph, 20);
  ASSERT_EQ("First paragraph text",
            PlainText(EphemeralRangeInFlatTree(start, end)));

  Node* node =
      GetDocument().getElementById(AtomicString("first"))->nextSibling();
  const auto& expected_position =
      ToPositionInFlatTree(Position::FirstPositionInNode(*node));
  EXPECT_EQ(expected_position,
            CreateGenerator()->GetNextTextStartPosition(end));
}

// Check the case when available suffix is a parent node text content outside of
// selection block.
TEST_F(TextFragmentSelectorGeneratorTest, GetNextTextStartPosition_ParentNode) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div id='div'><p id='first'>First paragraph text</p>nested</div>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& start = PositionInFlatTree(first_paragraph, 0);
  const auto& end = PositionInFlatTree(first_paragraph, 20);
  ASSERT_EQ("First paragraph text",
            PlainText(EphemeralRangeInFlatTree(start, end)));

  Node* node = GetDocument().getElementById(AtomicString("div"))->lastChild();
  const auto& expected_position =
      ToPositionInFlatTree(Position::FirstPositionInNode(*node));
  EXPECT_EQ(expected_position,
            CreateGenerator()->GetNextTextStartPosition(end));
}

// Check the case when next node is used for available suffix when selection is
// not at last index but there is only space after it.
TEST_F(TextFragmentSelectorGeneratorTest,
       GetNextTextStartPosition_SpacesAfterSelection) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='first'>
      First paragraph text
    </p>
    <p id='second'>Second paragraph text</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& start = PositionInFlatTree(first_paragraph, 23);
  const auto& end = PositionInFlatTree(first_paragraph, 27);
  ASSERT_EQ("text", PlainText(EphemeralRangeInFlatTree(start, end)));

  Node* node =
      GetDocument().getElementById(AtomicString("second"))->firstChild();
  const auto& expected_position =
      ToPositionInFlatTree(Position::FirstPositionInNode(*node));
  EXPECT_EQ(expected_position,
            CreateGenerator()->GetNextTextStartPosition(end));
}

// Check the case when next node is used for available suffix when selection is
// not at last index but there is only invisible block after it.
TEST_F(TextFragmentSelectorGeneratorTest,
       GetNextTextStartPosition_InvisibleAfterSelection) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div id='first'>
      First paragraph text
      <div id='invisible' style='display:none'>
        invisible text
      </div>
    </div>
    <p id='second'>Second paragraph text</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& start = PositionInFlatTree(first_paragraph, 23);
  const auto& end = PositionInFlatTree(first_paragraph, 27);
  ASSERT_EQ("text", PlainText(EphemeralRangeInFlatTree(start, end)));

  Node* node =
      GetDocument().getElementById(AtomicString("second"))->firstChild();
  const auto& expected_position =
      ToPositionInFlatTree(Position::FirstPositionInNode(*node));
  EXPECT_EQ(expected_position,
            CreateGenerator()->GetNextTextStartPosition(end));
}

// Check the case when available suffix is a text node outside of selection
// block.
TEST_F(TextFragmentSelectorGeneratorTest, GetNextTextStartPosition_NoNextNode) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='first'>First paragraph text</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& start = PositionInFlatTree(first_paragraph, 0);
  const auto& end = PositionInFlatTree(first_paragraph, 20);
  ASSERT_EQ("First paragraph text",
            PlainText(EphemeralRangeInFlatTree(start, end)));

  PositionInFlatTree expected_position;
  EXPECT_EQ(expected_position,
            CreateGenerator()->GetNextTextStartPosition(end));
}

TEST_F(TextFragmentSelectorGeneratorTest, BeforeAndAfterAnchor) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    Foo
    <div id="first">Hello World</div>
    Bar
  )HTML");

  Node* node = GetDocument().getElementById(AtomicString("first"));
  const auto& start = Position(node, PositionAnchorType::kBeforeAnchor);
  const auto& end = Position(node, PositionAnchorType::kAfterAnchor);
  VerifySelectorFails(start, end, LinkGenerationError::kEmptySelection);
}

// Check the case when GetPreviousTextBlock is an EOL node from Shadow Root.
TEST_F(TextFragmentSelectorGeneratorTest,
       GetPreviousTextEndPosition_ShouldSkipNodesWithNoLayoutObject) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div id="host1"></div>
  )HTML");
  ShadowRoot& shadow1 = GetDocument()
                            .getElementById(AtomicString("host1"))
                            ->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow1.setInnerHTML(R"HTML(
    <p id='p'>Right click the link below to experience a crash:</p>
    <style>
          :host {display: contents;}
    </style>
    <a href="/foo" id='first'>I crash</a>
  )HTML");
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(GetDocument().View()->NeedsLayout());
  Node* first_paragraph =
      shadow1.getElementById(AtomicString("first"))->firstChild();
  const auto& start = PositionInFlatTree(first_paragraph, 0);

  Node* node = shadow1.getElementById(AtomicString("p"))->firstChild();
  const auto& expected_position =
      ToPositionInFlatTree(Position::LastPositionInNode(*node));
  EXPECT_EQ(expected_position,
            CreateGenerator()->GetPreviousTextEndPosition(start));
}

// Tests that the generator fails gracefully if the layout subtree is removed
// while we're operating on it. Reproduction for https://crbug.com/1313253.
TEST_F(TextFragmentSelectorGeneratorTest, RemoveLayoutObjectAsync) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");

  // This test case relies on the initial try of 'p p p-,Foo,-s s s' being
  // non-unique. This forces the generator to try expanding the context after
  // the initial asynchronous search finishes. Before that happens, the current
  // node's LayoutObject is removed.
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p>p p p p</p>
    <p id='target'>Foo s s s p p p Foo s s s</p>
    <p>More text to so context expansion doesn't abort due to reaching end</p>
  )HTML");

  // Select the first instance of "Foo"
  Element* target = GetDocument().getElementById(AtomicString("target"));

  Node* text = target->firstChild();
  const auto& selected_start = Position(text, 0);
  const auto& selected_end = Position(text, 3);
  ASSERT_EQ("Foo", PlainText(EphemeralRange(selected_start, selected_end)));

  String selector;
  bool finished = false;
  auto lambda = [](bool& callback_called, String& selector,
                   const TextFragmentSelector& generated_selector,
                   shared_highlighting::LinkGenerationError error) {
    selector = generated_selector.ToString();
    callback_called = true;
  };
  auto callback = WTF::BindOnce(lambda, std::ref(finished), std::ref(selector));

  TextFragmentSelectorGenerator* generator = CreateGenerator();
  generator->Generate(*MakeGarbageCollected<RangeInFlatTree>(
                          ToPositionInFlatTree(selected_start),
                          ToPositionInFlatTree(selected_end)),
                      std::move(callback));

  // This test intends to test what happens when the layout tree is mutated
  // while the generator is waiting for the next asynchronous step. Thus, the
  // generator must still be running at this point for this test to be valid.
  ASSERT_FALSE(finished);

  // The TestCandidate state is the async break point in the generator, this
  // will post a task in AsyncFindBuffer to perform the text search on the
  // document. We'll mutate the layout tree while this task isn't run yet so
  // that when it run and returns to the generator we ensure neither touches
  // the removed layout tree.
  EXPECT_EQ(generator->state_,
            TextFragmentSelectorGenerator::SelectorState::kTestCandidate);

  generator->did_find_match_callback_for_testing_ = WTF::BindOnce(
      [](Element* target, bool is_unique) {
        EXPECT_FALSE(is_unique);

        // Set display:none should remove the layout object associated with the
        // range the generator is currently targeting.
        EXPECT_TRUE(target->GetLayoutObject());
        target->setAttribute(html_names::kStyleAttr,
                             AtomicString("display:none"));
        target->GetDocument().UpdateStyleAndLayoutTree();
        target->GetDocument().View()->UpdateStyleAndLayout();
        EXPECT_FALSE(target->GetLayoutObject());
      },
      WrapWeakPersistent(target));

  // Pump tasks to continue generator operation now.
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(finished);
}

}  // namespace blink
```