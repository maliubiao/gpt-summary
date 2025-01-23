Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is the second part of a test file for `PositionIterator` in the Chromium Blink engine.

Here's a breakdown of the thought process:

1. **Identify the Core Functionality:** The file is a test suite (`PositionIteratorTest`). This means its primary function is to verify the behavior of the `PositionIterator` class. The tests use `EXPECT_THAT` and `ElementsAre`, indicating that they are testing the sequence of positions visited by the iterator when moving forward or backward in the DOM tree.

2. **Analyze the Test Names:**  The test names provide clues about the specific scenarios being tested. Look for patterns and keywords:
    * "DecrementWith...": Tests the backward traversal.
    * "IncrementFrom...": Tests the forward traversal from different starting positions within specific elements.
    * Element names (TextArea, InputElement, ObjectElement, SelectElement): Indicate tests focused on how the iterator handles these specific HTML elements.
    * "WithCollapsedSpace", "WithComment...", "WithInlineElement":  These test the iterator's behavior when encountering specific DOM structures.
    * "NullPosition": Tests how the iterator handles invalid or null positions.
    * "InFlatTree": Tests the behavior of a specific iterator variant (`PositionIteratorInFlatTree`) which traverses the "flat tree" representation of the DOM.

3. **Examine the Test Structure:** Each test generally sets up a simple HTML structure using `SetBodyContent()`, then creates a starting `Position` (or `PositionInFlatTree`), and finally uses `ScanForward()` or `ScanBackward()` to iterate and compare the visited positions against an expected sequence defined using `ElementsAre()`.

4. **Infer the Purpose of `PositionIterator`:** Based on the tests, the `PositionIterator` is used to traverse the DOM tree (and its flat tree representation) in both forward and backward directions. It needs to handle different types of nodes (text nodes, element nodes, comment nodes) and the boundaries between them correctly.

5. **Identify Relationships to Web Technologies:**  Since it's part of the Blink engine, the `PositionIterator` is directly related to how web pages are represented and manipulated. It's essential for features like:
    * **Text Selection:** The names of some tests ("selection_text") and the focus on boundary conditions strongly suggest this.
    * **Caret Movement:** Moving the text cursor in a web page involves similar traversal logic.
    * **Accessibility:**  Navigating the DOM structure is crucial for assistive technologies.
    * **Content Editing:**  Operations like inserting or deleting text require precise knowledge of positions within the DOM.

6. **Look for Logical Inferences and Examples:**  The tests provide implicit logical inferences. For instance, tests starting "IncrementFromInputElementAfterChildren" imply that the iterator needs to correctly transition from the end of an input element to the following nodes. The test strings like `"-S-- #text \"XYZ\"@0 #text \"XYZ\"@offsetInAnchor[0]"` represent the state of the iterator (S for start, E for end, offsets, etc.) as it traverses. You can use these to illustrate the iterator's movement.

7. **Consider User/Programming Errors:**  The "NullPosition" test directly addresses a potential programming error – trying to use an iterator with an invalid position. Other potential errors might involve incorrect handling of boundary conditions or assumptions about the DOM structure.

8. **Trace User Actions:** To understand how a user might trigger this code, think about common browser interactions:
    * Selecting text with the mouse or keyboard.
    * Moving the text cursor using arrow keys.
    * Interacting with form elements (textareas, input fields, select menus).
    * Potentially, using browser developer tools to inspect or modify the DOM.

9. **Synthesize the Summary (for Part 2):** Since this is the second part, focus on summarizing the *additional* functionality demonstrated in this specific snippet, building upon the understanding gained from Part 1 (even though we don't have Part 1's content directly). The emphasis here is on testing specific HTML elements and edge cases.

By following these steps, we can arrive at a comprehensive summary like the example provided in the initial prompt. The key is to understand the context (a test file), the purpose of the class being tested (`PositionIterator`), and how the individual tests contribute to verifying its correct behavior in various scenarios.
这是 `blink/renderer/core/editing/position_iterator_test.cc` 文件的第二部分，延续了第一部分的功能，主要目的是**测试 `PositionIterator` 类的各种遍历场景，确保其在不同的 DOM 结构和元素类型中能够正确地向前和向后移动，并返回预期的位置信息。**

**归纳一下它的功能：**

这部分测试主要集中在以下几个方面：

1. **针对特定 HTML 元素的边界情况测试:**
   - **`<textarea>`:** 测试了在 `<textarea>` 元素边界进行前后遍历时的行为，包括从 `afterChildren` 往回遍历的情况。
   - **`<input>`:**  测试了从 `<input>` 元素的不同位置（`AfterChildren`, `AfterNode`, `BeforeNode`, 特定偏移量）向前遍历的行为。
   - **`<object>`:**  测试了从 `<object>` 元素的不同位置向前遍历的行为，特别关注了 `<object>` 元素内部可能包含的 `<slot>` 元素。
   - **`<select>`:** 测试了从 `<select>` 元素的不同位置向前遍历的行为，包括 `<select>` 元素内部的默认 `<div>` 和 `<slot>` 元素。

2. **处理特殊 DOM 结构的测试:**
   - **折叠的空格 (`IncrementWithCollapsedSpace`):** 测试了当遇到多个连续空格被折叠成一个空格时，迭代器是否能正确移动。
   - **注释节点 (`IncrementWithCommentEmpty`, `IncrementWithCommentNonEmpty`):**  测试了迭代器在遇到空注释和非空注释时的行为。
   - **行内元素 (`IncrementWithInlineElemnt`):** 测试了迭代器在包含嵌套行内元素的复杂结构中是否能正确移动。
   - **没有子节点的元素 (`IncrementWithNoChildren`):** 测试了迭代器在遇到没有子节点的元素（例如 `<br>`, `<img>`) 时的行为。

3. **针对特定场景的回归测试:**
   - 包含 `http://crbug.com/` 的测试用例表明这些测试是为了解决之前发现的 bug 而添加的，例如处理 `<input>` 和 `<textarea>` 元素时的特定问题。

4. **处理空位置的情况 (`nullPosition`):** 测试了当 `PositionIterator` 初始化为空位置时，其各种操作（`ComputePosition`, `DeprecatedComputePosition`, `Increment`, `Decrement`) 的行为，确保不会出现崩溃或其他未定义行为。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **HTML:**  所有测试都基于 HTML 结构。`SetBodyContent()` 函数会创建一个 HTML 文档片段，供测试用例分析。例如，测试 `<textarea>` 元素时，会创建包含 `<textarea>` 的 HTML 结构。
* **JavaScript:**  虽然这个测试文件是用 C++ 写的，但 `PositionIterator` 的功能直接影响到 JavaScript 中与 DOM 操作相关的 API。例如，JavaScript 中的 `Selection` API 和 `Range` API 内部会使用类似的位置迭代器来处理文本的选择和范围操作。当 JavaScript 代码尝试获取或修改特定位置的 DOM 节点时，`PositionIterator` 的正确性至关重要。
* **CSS:** CSS 影响 DOM 元素的渲染和布局，虽然 `PositionIterator` 主要关注 DOM 树的结构，但 CSS 的一些属性，比如 `contenteditable`，会影响元素的编辑状态，进而可能影响到位置迭代的逻辑。例如，测试用例中出现的 `DIV (editable)` 标签，就可能受到 CSS 的影响。

**逻辑推理的假设输入与输出:**

以 `TEST_F(PositionIteratorTest, DecrementWithTextArea)` 为例：

* **假设输入:**  一个包含 `<textarea id="target">123</textarea>` 的 HTML 结构，并且迭代器初始位置在 `<textarea>` 元素的 `afterChildren` 位置 (也就是文本 "123" 的末尾之后)。
* **预期输出:**  `ScanBackward` 函数应该返回一系列位置信息，描述了迭代器向后移动的路径，例如从文本 "123" 的末尾移动到开头，再移动到 `<textarea>` 元素的开头之前。输出结果通过 `ElementsAre` 定义，列出了预期的节点和偏移量信息。

**用户或编程常见的使用错误举例说明:**

* **用户操作错误:** 用户在网页上使用鼠标或键盘选择文本时，可能会跨越不同的 DOM 元素，甚至跨越 Shadow DOM 的边界。`PositionIterator` 的测试确保在这些复杂的选择场景下，引擎能够正确地追踪选区的起始和结束位置。如果 `PositionIterator` 的逻辑有错误，可能导致用户选择的文本范围与实际不符。
* **编程错误:**  在 Blink 引擎的开发中，如果某个模块需要遍历 DOM 树来执行操作（例如，实现 `document.execCommand` 中的编辑命令），不正确地使用或理解 `PositionIterator` 的行为可能导致逻辑错误，例如在错误的位置插入或删除内容。`nullPosition` 测试就预防了因为传入空位置而导致的程序崩溃。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设 `DecrementWithTextArea` 测试失败，调试线索可能如下：

1. **用户在包含 `<textarea>` 的网页中，用鼠标选中了 `<textarea>` 中的部分或全部文本。** 这会导致浏览器内部创建表示选区的 `Selection` 对象。
2. **用户可能按下退格键或删除键，尝试删除选中的文本。**  这个操作会触发 Blink 引擎的编辑代码。
3. **编辑代码内部会使用 `PositionIterator` 来确定选区的起始和结束位置，并计算需要删除的 DOM 节点和偏移量。**
4. **如果 `PositionIterator` 在向后遍历 `<textarea>` 元素时存在 bug，例如在边界处理上出错，那么可能会计算出错误的删除范围。**
5. **`DecrementWithTextArea` 测试正是为了验证这种向后遍历的场景是否正确。**  如果测试失败，说明 `PositionIterator` 在处理 `<textarea>` 元素的向后遍历时存在潜在的问题，需要检查相关的代码逻辑。

总而言之，这部分测试用例深入测试了 `PositionIterator` 在各种复杂的 DOM 结构和特定元素类型中的行为，确保其在 Blink 引擎中能够可靠地进行 DOM 遍历，从而支撑各种与 DOM 操作相关的核心功能。

### 提示词
```
这是目录为blink/renderer/core/editing/position_iterator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
d return
          // `SELECT@beforeAnchor`.
          "-S-E TEXTAREA id=\"target\"@0 TEXTAREA id=\"target\"@beforeAnchor "
          "TEXTAREA id=\"target\"@afterAnchor",
          "---- BODY BODY@offsetInAnchor[1]",
          "---E #text \"123\"@3 #text \"123\"@offsetInAnchor[3]",
          "---- #text \"123\"@2 #text \"123\"@offsetInAnchor[2]",
          "---- #text \"123\"@1 #text \"123\"@offsetInAnchor[1]",
          "-S-- #text \"123\"@0 #text \"123\"@offsetInAnchor[0]",
          "-S-- BODY BODY@offsetInAnchor[0]",
          "---- HTML HTML@offsetInAnchor[1]",
          "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
          "-S-- HTML HTML@offsetInAnchor[0]"));

  EXPECT_THAT(
      ScanBackwardInFlatTree(selection_text),
      ElementsAre(
          "---E BODY BODY@afterChildren",
          "---E TEXTAREA id=\"target\"@1 TEXTAREA id=\"target\"@afterAnchor",
          // Note: `DeprecatedComputePosition()` should return
          // `SELECT@beforeAnchor`.
          "-S-E TEXTAREA id=\"target\"@0 TEXTAREA id=\"target\"@beforeAnchor "
          "TEXTAREA id=\"target\"@afterAnchor",
          "---- BODY BODY@offsetInAnchor[1]",
          "---E #text \"123\"@3 #text \"123\"@offsetInAnchor[3]",
          "---- #text \"123\"@2 #text \"123\"@offsetInAnchor[2]",
          "---- #text \"123\"@1 #text \"123\"@offsetInAnchor[1]",
          "-S-- #text \"123\"@0 #text \"123\"@offsetInAnchor[0]",
          "-S-- BODY BODY@offsetInAnchor[0]",
          "---- HTML HTML@offsetInAnchor[1]",
          "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
          "-S-- HTML HTML@offsetInAnchor[0]"));
}

// http://crbug.com/1392758
TEST_F(PositionIteratorTest, DecrementWithTextAreaFromAfterChildren) {
  SetBodyContent("<textarea>abc</textarea>");
  const Element& body = *GetDocument().body();
  const auto expectation = ElementsAre(
      "---E BODY BODY@afterChildren", "---E TEXTAREA@1 TEXTAREA@afterAnchor",
      "-S-E TEXTAREA@0 TEXTAREA@beforeAnchor TEXTAREA@afterAnchor",
      "-S-- BODY BODY@offsetInAnchor[0]", "---- HTML HTML@offsetInAnchor[1]",
      "-S-E HEAD HEAD@beforeAnchor HEAD@offsetInAnchor[0]",
      "-S-- HTML HTML@offsetInAnchor[0]");

  EXPECT_THAT(ScanBackward(Position(body, 1)), expectation);
  EXPECT_THAT(ScanBackward(Position::LastPositionInNode(body)), expectation);
}

// ---

TEST_F(PositionIteratorTest, IncrementFromInputElementAfterChildren) {
  // FlatTree is "ABC" <input><div>123</div></input> "XYZ".
  SetBodyContent("ABC<input value=123>XYZ");
  const auto& input_element =
      *To<HTMLInputElement>(GetDocument().QuerySelector(AtomicString("input")));
  EXPECT_THAT(
      ScanForward(PositionInFlatTree::LastPositionInNode(input_element)),
      ElementsAre(
          "---E INPUT@1 INPUT@afterAnchor", "---- BODY BODY@offsetInAnchor[2]",
          "-S-- #text \"XYZ\"@0 #text \"XYZ\"@offsetInAnchor[0]",
          "---- #text \"XYZ\"@1 #text \"XYZ\"@offsetInAnchor[1]",
          "---- #text \"XYZ\"@2 #text \"XYZ\"@offsetInAnchor[2]",
          "---E #text \"XYZ\"@3 #text \"XYZ\"@offsetInAnchor[3]",
          "---E BODY BODY@afterChildren", "---E HTML HTML@afterChildren"));
}

TEST_F(PositionIteratorTest, IncrementFromInputElementAfterNode) {
  // FlatTree is "ABC" <input><div>123</div></input> "XYZ".
  SetBodyContent("ABC<input value=123>XYZ");
  const auto& input_element =
      *To<HTMLInputElement>(GetDocument().QuerySelector(AtomicString("input")));
  EXPECT_THAT(
      ScanForward(PositionInFlatTree::AfterNode(input_element)),
      ElementsAre(
          "---E INPUT@1 INPUT@afterAnchor", "---- BODY BODY@offsetInAnchor[2]",
          "-S-- #text \"XYZ\"@0 #text \"XYZ\"@offsetInAnchor[0]",
          "---- #text \"XYZ\"@1 #text \"XYZ\"@offsetInAnchor[1]",
          "---- #text \"XYZ\"@2 #text \"XYZ\"@offsetInAnchor[2]",
          "---E #text \"XYZ\"@3 #text \"XYZ\"@offsetInAnchor[3]",
          "---E BODY BODY@afterChildren", "---E HTML HTML@afterChildren"));
}

TEST_F(PositionIteratorTest, IncrementFromInputElementBeforeNode) {
  // FlatTree is "ABC" <input><div>123</div></input> "XYZ".
  SetBodyContent("ABC<input value=123>XYZ");
  const auto& input_element =
      *To<HTMLInputElement>(GetDocument().QuerySelector(AtomicString("input")));
  EXPECT_THAT(
      ScanForward(PositionInFlatTree::BeforeNode(input_element)),
      ElementsAre("-S-- INPUT@0 INPUT@offsetInAnchor[0] INPUT@beforeAnchor",
                  "-S-- DIV (editable) DIV (editable)@offsetInAnchor[0]",
                  "-S-- #text \"123\"@0 #text \"123\"@offsetInAnchor[0]",
                  "---- #text \"123\"@1 #text \"123\"@offsetInAnchor[1]",
                  "---- #text \"123\"@2 #text \"123\"@offsetInAnchor[2]",
                  "---E #text \"123\"@3 #text \"123\"@offsetInAnchor[3]",
                  "---E DIV (editable) DIV (editable)@afterChildren"));
}

TEST_F(PositionIteratorTest, IncrementFromInputElementOffset0) {
  // FlatTree is "ABC" <input><div>123</div></input> "XYZ".
  SetBodyContent("ABC<input value=123>XYZ");
  const auto& input_element =
      *To<HTMLInputElement>(GetDocument().QuerySelector(AtomicString("input")));
  EXPECT_THAT(
      ScanForward(PositionInFlatTree(input_element, 0)),
      ElementsAre("-S-- INPUT@0 INPUT@offsetInAnchor[0] INPUT@beforeAnchor",
                  "-S-- DIV (editable) DIV (editable)@offsetInAnchor[0]",
                  "-S-- #text \"123\"@0 #text \"123\"@offsetInAnchor[0]",
                  "---- #text \"123\"@1 #text \"123\"@offsetInAnchor[1]",
                  "---- #text \"123\"@2 #text \"123\"@offsetInAnchor[2]",
                  "---E #text \"123\"@3 #text \"123\"@offsetInAnchor[3]",
                  "---E DIV (editable) DIV (editable)@afterChildren"));
}

TEST_F(PositionIteratorTest, IncrementFromInputElementOffset1) {
  // FlatTree is "ABC" <input><div>123</div></input> "XYZ".
  SetBodyContent("ABC<input value=123>XYZ");
  const auto& input_element =
      *To<HTMLInputElement>(GetDocument().QuerySelector(AtomicString("input")));
  EXPECT_THAT(
      ScanForward(PositionInFlatTree(input_element, 1)),
      ElementsAre(
          "---E INPUT@1 INPUT@afterAnchor", "---- BODY BODY@offsetInAnchor[2]",
          "-S-- #text \"XYZ\"@0 #text \"XYZ\"@offsetInAnchor[0]",
          "---- #text \"XYZ\"@1 #text \"XYZ\"@offsetInAnchor[1]",
          "---- #text \"XYZ\"@2 #text \"XYZ\"@offsetInAnchor[2]",
          "---E #text \"XYZ\"@3 #text \"XYZ\"@offsetInAnchor[3]",
          "---E BODY BODY@afterChildren", "---E HTML HTML@afterChildren"));
}

TEST_F(PositionIteratorTest, IncrementFromObjectElementAfterChildren) {
  // FlatTree is "ABC" <object><slot></slot></object> "XYZ".
  SetBodyContent("ABC<object></object>XYZ");
  const auto& object_element = *To<HTMLObjectElement>(
      GetDocument().QuerySelector(AtomicString("object")));
  EXPECT_THAT(
      ScanForward(PositionInFlatTree::LastPositionInNode(object_element)),
      ElementsAre("---E OBJECT@1 OBJECT@afterAnchor",
                  "---- BODY BODY@offsetInAnchor[2]",
                  "-S-- #text \"XYZ\"@0 #text \"XYZ\"@offsetInAnchor[0]",
                  "---- #text \"XYZ\"@1 #text \"XYZ\"@offsetInAnchor[1]",
                  "---- #text \"XYZ\"@2 #text \"XYZ\"@offsetInAnchor[2]",
                  "---E #text \"XYZ\"@3 #text \"XYZ\"@offsetInAnchor[3]",
                  "---E BODY BODY@afterChildren",
                  "---E HTML HTML@afterChildren"));
}

TEST_F(PositionIteratorTest, IncrementFromObjectElementAfterNode) {
  // FlatTree is "ABC" <object><slot></slot></object> "XYZ".
  SetBodyContent("ABC<object></object>XYZ");
  const auto& object_element = *To<HTMLObjectElement>(
      GetDocument().QuerySelector(AtomicString("object")));
  EXPECT_THAT(
      ScanForward(PositionInFlatTree::AfterNode(object_element)),
      ElementsAre("---E OBJECT@1 OBJECT@afterAnchor",
                  "---- BODY BODY@offsetInAnchor[2]",
                  "-S-- #text \"XYZ\"@0 #text \"XYZ\"@offsetInAnchor[0]",
                  "---- #text \"XYZ\"@1 #text \"XYZ\"@offsetInAnchor[1]",
                  "---- #text \"XYZ\"@2 #text \"XYZ\"@offsetInAnchor[2]",
                  "---E #text \"XYZ\"@3 #text \"XYZ\"@offsetInAnchor[3]",
                  "---E BODY BODY@afterChildren",
                  "---E HTML HTML@afterChildren"));
}

TEST_F(PositionIteratorTest, IncrementFromObjectElementBeforeNode) {
  // FlatTree is "ABC" <object><slot></slot></object> "XYZ".
  SetBodyContent("ABC<object></object>XYZ");
  const auto& object_element = *To<HTMLObjectElement>(
      GetDocument().QuerySelector(AtomicString("object")));
  EXPECT_THAT(
      ScanForward(PositionInFlatTree::BeforeNode(object_element)),
      ElementsAre("-S-- OBJECT@0 OBJECT@offsetInAnchor[0] OBJECT@beforeAnchor",
                  "-S-E SLOT SLOT@beforeAnchor SLOT@offsetInAnchor[0]",
                  "---E OBJECT@1 OBJECT@afterAnchor",
                  "---- BODY BODY@offsetInAnchor[2]",
                  "-S-- #text \"XYZ\"@0 #text \"XYZ\"@offsetInAnchor[0]",
                  "---- #text \"XYZ\"@1 #text \"XYZ\"@offsetInAnchor[1]",
                  "---- #text \"XYZ\"@2 #text \"XYZ\"@offsetInAnchor[2]",
                  "---E #text \"XYZ\"@3 #text \"XYZ\"@offsetInAnchor[3]",
                  "---E BODY BODY@afterChildren",
                  "---E HTML HTML@afterChildren"));
}

TEST_F(PositionIteratorTest, IncrementFromObjectElementOffset0) {
  // FlatTree is "ABC" <object><slot></slot></object> "XYZ".
  SetBodyContent("ABC<object></object>XYZ");
  const auto& object_element = *To<HTMLObjectElement>(
      GetDocument().QuerySelector(AtomicString("object")));
  EXPECT_THAT(
      ScanForward(PositionInFlatTree(object_element, 0)),
      ElementsAre("-S-- OBJECT@0 OBJECT@offsetInAnchor[0] OBJECT@beforeAnchor",
                  "-S-E SLOT SLOT@beforeAnchor SLOT@offsetInAnchor[0]",
                  "---E OBJECT@1 OBJECT@afterAnchor",
                  "---- BODY BODY@offsetInAnchor[2]",
                  "-S-- #text \"XYZ\"@0 #text \"XYZ\"@offsetInAnchor[0]",
                  "---- #text \"XYZ\"@1 #text \"XYZ\"@offsetInAnchor[1]",
                  "---- #text \"XYZ\"@2 #text \"XYZ\"@offsetInAnchor[2]",
                  "---E #text \"XYZ\"@3 #text \"XYZ\"@offsetInAnchor[3]",
                  "---E BODY BODY@afterChildren",
                  "---E HTML HTML@afterChildren"));
}

TEST_F(PositionIteratorTest, IncrementFromObjectElementOffset1) {
  // FlatTree is "ABC" <object><slot></slot></object> "XYZ".
  SetBodyContent("ABC<object></object>XYZ");
  const auto& object_element = *To<HTMLObjectElement>(
      GetDocument().QuerySelector(AtomicString("object")));
  EXPECT_THAT(
      ScanForward(PositionInFlatTree(object_element, 1)),
      ElementsAre("---E OBJECT@1 OBJECT@afterAnchor",
                  "---- BODY BODY@offsetInAnchor[2]",
                  "-S-- #text \"XYZ\"@0 #text \"XYZ\"@offsetInAnchor[0]",
                  "---- #text \"XYZ\"@1 #text \"XYZ\"@offsetInAnchor[1]",
                  "---- #text \"XYZ\"@2 #text \"XYZ\"@offsetInAnchor[2]",
                  "---E #text \"XYZ\"@3 #text \"XYZ\"@offsetInAnchor[3]",
                  "---E BODY BODY@afterChildren",
                  "---E HTML HTML@afterChildren"));
}

TEST_F(PositionIteratorTest, IncrementFromSelectElementAfterChildren) {
  // FlatTree is "ABC"
  // <select><div>""</div><slot><option></option></slot></select> "XYZ".
  SetBodyContent("ABC<select><option></option></select>XYZ");
  const auto& select_element = *To<HTMLSelectElement>(
      GetDocument().QuerySelector(AtomicString("select")));
  EXPECT_THAT(
      ScanForward(PositionInFlatTree::LastPositionInNode(select_element)),
      ElementsAre("---E SELECT@1 SELECT@afterAnchor",
                  "---- BODY BODY@offsetInAnchor[2]",
                  "-S-- #text \"XYZ\"@0 #text \"XYZ\"@offsetInAnchor[0]",
                  "---- #text \"XYZ\"@1 #text \"XYZ\"@offsetInAnchor[1]",
                  "---- #text \"XYZ\"@2 #text \"XYZ\"@offsetInAnchor[2]",
                  "---E #text \"XYZ\"@3 #text \"XYZ\"@offsetInAnchor[3]",
                  "---E BODY BODY@afterChildren",
                  "---E HTML HTML@afterChildren"));
}

TEST_F(PositionIteratorTest, IncrementFromSelectElementAfterNode) {
  // FlatTree is "ABC"
  // <select><div>""</div><slot><option></option></slot></select> "XYZ".
  SetBodyContent("ABC<select><option></option></select>XYZ");
  const auto& select_element = *To<HTMLSelectElement>(
      GetDocument().QuerySelector(AtomicString("select")));
  EXPECT_THAT(
      ScanForward(PositionInFlatTree::AfterNode(select_element)),
      ElementsAre("---E SELECT@1 SELECT@afterAnchor",
                  "---- BODY BODY@offsetInAnchor[2]",
                  "-S-- #text \"XYZ\"@0 #text \"XYZ\"@offsetInAnchor[0]",
                  "---- #text \"XYZ\"@1 #text \"XYZ\"@offsetInAnchor[1]",
                  "---- #text \"XYZ\"@2 #text \"XYZ\"@offsetInAnchor[2]",
                  "---E #text \"XYZ\"@3 #text \"XYZ\"@offsetInAnchor[3]",
                  "---E BODY BODY@afterChildren",
                  "---E HTML HTML@afterChildren"));
}

TEST_F(PositionIteratorTest, IncrementFromSelectElementBeforeNode) {
  // FlatTree is "ABC"
  // <select><div>""</div><slot><option></option></slot></select> "XYZ".
  SetBodyContent("ABC<select><option></option></select>XYZ");
  const auto& select_element = *To<HTMLSelectElement>(
      GetDocument().QuerySelector(AtomicString("select")));
  EXPECT_THAT(
      ScanForward(PositionInFlatTree::BeforeNode(select_element)),
      ElementsAre("-S-- SELECT@0 SELECT@offsetInAnchor[0] SELECT@beforeAnchor",
                  "-S-- DIV DIV@offsetInAnchor[0]",
                  "-S-E #text \"\"@0 #text \"\"@offsetInAnchor[0]",
                  "---E DIV DIV@afterChildren"));
}

TEST_F(PositionIteratorTest, IncrementFromSelectElementOffset0) {
  // FlatTree is "ABC"
  // <select><div>""</div><slot><option></option></slot></select> "XYZ".
  SetBodyContent("ABC<select><option></option></select>XYZ");
  const auto& select_element = *To<HTMLSelectElement>(
      GetDocument().QuerySelector(AtomicString("select")));
  EXPECT_THAT(
      ScanForward(PositionInFlatTree(select_element, 0)),
      ElementsAre("-S-- SELECT@0 SELECT@offsetInAnchor[0] SELECT@beforeAnchor",
                  "-S-- DIV DIV@offsetInAnchor[0]",
                  "-S-E #text \"\"@0 #text \"\"@offsetInAnchor[0]",
                  "---E DIV DIV@afterChildren"));
}

TEST_F(PositionIteratorTest, IncrementFromSelectElementOffset1) {
  // FlatTree is "ABC"
  // <select><div>""</div><slot><option></option></slot></select> "XYZ".
  SetBodyContent("ABC<select><option></option></select>XYZ");
  const auto& select_element = *To<HTMLSelectElement>(
      GetDocument().QuerySelector(AtomicString("select")));
  EXPECT_THAT(
      ScanForward(PositionInFlatTree(select_element, 1)),
      ElementsAre("---- SELECT@1 SELECT@offsetInAnchor[1] SELECT@beforeAnchor",
                  "-S-- SLOT id=\"select-options\" SLOT "
                  "id=\"select-options\"@offsetInAnchor[0]",
                  "-S-- OPTION OPTION@offsetInAnchor[0]",
                  "-S-E SLOT SLOT@beforeAnchor SLOT@offsetInAnchor[0]",
                  "---E OPTION OPTION@afterChildren",
                  "---E SLOT id=\"select-options\" SLOT "
                  "id=\"select-options\"@afterChildren"));
}

TEST_F(PositionIteratorTest, IncrementWithCollapsedSpace) {
  const char* selection_text = "|<p> abc </p>";

  EXPECT_THAT(
      ScanForward(selection_text),
      ElementsAre("-S-- BODY BODY@offsetInAnchor[0]",
                  "-S-- P P@offsetInAnchor[0]",
                  "-S-- #text \" abc \"@0 #text \" abc \"@offsetInAnchor[0]",
                  "---- #text \" abc \"@1 #text \" abc \"@offsetInAnchor[1]",
                  "---- #text \" abc \"@2 #text \" abc \"@offsetInAnchor[2]",
                  "---- #text \" abc \"@3 #text \" abc \"@offsetInAnchor[3]",
                  "---- #text \" abc \"@4 #text \" abc \"@offsetInAnchor[4]",
                  "---E #text \" abc \"@5 #text \" abc \"@offsetInAnchor[5]",
                  "---E P P@afterChildren", "---E BODY BODY@afterChildren",
                  "---E HTML HTML@afterChildren"));
}

TEST_F(PositionIteratorTest, IncrementWithCommentEmpty) {
  const char* selection_text = "|<p>a<br>b<!---->c</p>";

  EXPECT_THAT(
      ScanForward(selection_text),
      ElementsAre(
          "-S-- BODY BODY@offsetInAnchor[0]", "-S-- P P@offsetInAnchor[0]",
          "-S-- #text \"a\"@0 #text \"a\"@offsetInAnchor[0]",
          "---E #text \"a\"@1 #text \"a\"@offsetInAnchor[1]",
          "---- P P@offsetInAnchor[1]", "-S-- BR@0 BR@beforeAnchor",
          "---E BR@1 BR@afterAnchor", "---- P P@offsetInAnchor[2]",
          "-S-- #text \"b\"@0 #text \"b\"@offsetInAnchor[0]",
          "---E #text \"b\"@1 #text \"b\"@offsetInAnchor[1]",
          "---- P P@offsetInAnchor[3]",
          // `At{Start,End}OfNode()` return false for empty comment.
          "-S-E #comment@0 #comment@beforeAnchor", "---- P P@offsetInAnchor[4]",
          "-S-- #text \"c\"@0 #text \"c\"@offsetInAnchor[0]",
          "---E #text \"c\"@1 #text \"c\"@offsetInAnchor[1]",
          "---E P P@afterChildren", "---E BODY BODY@afterChildren",
          "---E HTML HTML@afterChildren"));
}

TEST_F(PositionIteratorTest, IncrementWithCommentNonEmpty) {
  const char* selection_text = "|<p>a<br>b<!--XYZ-->c</p>";

  EXPECT_THAT(
      ScanForward(selection_text),
      ElementsAre(
          "-S-- BODY BODY@offsetInAnchor[0]", "-S-- P P@offsetInAnchor[0]",
          "-S-- #text \"a\"@0 #text \"a\"@offsetInAnchor[0]",
          "---E #text \"a\"@1 #text \"a\"@offsetInAnchor[1]",
          "---- P P@offsetInAnchor[1]", "-S-- BR@0 BR@beforeAnchor",
          "---E BR@1 BR@afterAnchor", "---- P P@offsetInAnchor[2]",
          "-S-- #text \"b\"@0 #text \"b\"@offsetInAnchor[0]",
          "---E #text \"b\"@1 #text \"b\"@offsetInAnchor[1]",
          "---- P P@offsetInAnchor[3]",
          // `AtEndOfNode()` returns false for not-empty comment.
          "-S-- #comment@0 #comment@beforeAnchor", "---- P P@offsetInAnchor[4]",
          "-S-- #text \"c\"@0 #text \"c\"@offsetInAnchor[0]",
          "---E #text \"c\"@1 #text \"c\"@offsetInAnchor[1]",
          "---E P P@afterChildren", "---E BODY BODY@afterChildren",
          "---E HTML HTML@afterChildren"));
}

TEST_F(PositionIteratorTest, IncrementWithInlineElemnt) {
  const char* selection_text = "|<p><a><b>ABC</b></a>DEF<i><s>GHI</s></i></p>";

  EXPECT_THAT(
      ScanForward(selection_text),
      ElementsAre("-S-- BODY BODY@offsetInAnchor[0]",
                  "-S-- P P@offsetInAnchor[0]", "-S-- A A@offsetInAnchor[0]",
                  "-S-- B B@offsetInAnchor[0]",
                  "-S-- #text \"ABC\"@0 #text \"ABC\"@offsetInAnchor[0]",
                  "---- #text \"ABC\"@1 #text \"ABC\"@offsetInAnchor[1]",
                  "---- #text \"ABC\"@2 #text \"ABC\"@offsetInAnchor[2]",
                  "---E #text \"ABC\"@3 #text \"ABC\"@offsetInAnchor[3]",
                  "---E B B@afterChildren", "---E A A@afterChildren",
                  "---- P P@offsetInAnchor[1]",
                  "-S-- #text \"DEF\"@0 #text \"DEF\"@offsetInAnchor[0]",
                  "---- #text \"DEF\"@1 #text \"DEF\"@offsetInAnchor[1]",
                  "---- #text \"DEF\"@2 #text \"DEF\"@offsetInAnchor[2]",
                  "---E #text \"DEF\"@3 #text \"DEF\"@offsetInAnchor[3]",
                  "---- P P@offsetInAnchor[2]", "-S-- I I@offsetInAnchor[0]",
                  "-S-- S S@offsetInAnchor[0]",
                  "-S-- #text \"GHI\"@0 #text \"GHI\"@offsetInAnchor[0]",
                  "---- #text \"GHI\"@1 #text \"GHI\"@offsetInAnchor[1]",
                  "---- #text \"GHI\"@2 #text \"GHI\"@offsetInAnchor[2]",
                  "---E #text \"GHI\"@3 #text \"GHI\"@offsetInAnchor[3]",
                  "---E S S@afterChildren", "---E I I@afterChildren",
                  "---E P P@afterChildren", "---E BODY BODY@afterChildren",
                  "---E HTML HTML@afterChildren"));
}

// For http://crbug.com/695317
TEST_F(PositionIteratorTest, incrementWithInputElement) {
  const char* selection_text = "|<input id=target value='abc'>123";

  EXPECT_THAT(
      ScanForward(selection_text),
      ElementsAre("-S-- BODY BODY@offsetInAnchor[0]",
                  "-S-- INPUT id=\"target\"@0 INPUT id=\"target\"@beforeAnchor",
                  "---E INPUT id=\"target\"@1 INPUT id=\"target\"@afterAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "-S-- #text \"123\"@0 #text \"123\"@offsetInAnchor[0]",
                  "---- #text \"123\"@1 #text \"123\"@offsetInAnchor[1]",
                  "---- #text \"123\"@2 #text \"123\"@offsetInAnchor[2]",
                  "---E #text \"123\"@3 #text \"123\"@offsetInAnchor[3]",
                  "---E BODY BODY@afterChildren",
                  "---E HTML HTML@afterChildren"));

  EXPECT_THAT(
      ScanForwardInFlatTree(selection_text),
      ElementsAre("-S-- BODY BODY@offsetInAnchor[0]",
                  // Note: `DeprecatedComputePosition()` should return
                  // `INPUT@beforeAnchor`.
                  "-S-E INPUT id=\"target\"@0 INPUT id=\"target\"@beforeAnchor "
                  "INPUT id=\"target\"@afterAnchor",
                  "---E INPUT id=\"target\"@1 INPUT id=\"target\"@afterAnchor",
                  "---- BODY BODY@offsetInAnchor[1]",
                  "-S-- #text \"123\"@0 #text \"123\"@offsetInAnchor[0]",
                  "---- #text \"123\"@1 #text \"123\"@offsetInAnchor[1]",
                  "---- #text \"123\"@2 #text \"123\"@offsetInAnchor[2]",
                  "---E #text \"123\"@3 #text \"123\"@offsetInAnchor[3]",
                  "---E BODY BODY@afterChildren",
                  "---E HTML HTML@afterChildren"));
}

TEST_F(PositionIteratorTest, IncrementWithNoChildren) {
  const char* const selection_text = "|abc<br>def<img><br>";
  EXPECT_THAT(
      ScanForward(selection_text),
      ElementsAre(
          "-S-- #text \"abc\"@0 #text \"abc\"@offsetInAnchor[0]",
          "---- #text \"abc\"@1 #text \"abc\"@offsetInAnchor[1]",
          "---- #text \"abc\"@2 #text \"abc\"@offsetInAnchor[2]",
          "---E #text \"abc\"@3 #text \"abc\"@offsetInAnchor[3]",
          "---- BODY BODY@offsetInAnchor[1]", "-S-- BR@0 BR@beforeAnchor",
          "---E BR@1 BR@afterAnchor", "---- BODY BODY@offsetInAnchor[2]",
          "-S-- #text \"def\"@0 #text \"def\"@offsetInAnchor[0]",
          "---- #text \"def\"@1 #text \"def\"@offsetInAnchor[1]",
          "---- #text \"def\"@2 #text \"def\"@offsetInAnchor[2]",
          "---E #text \"def\"@3 #text \"def\"@offsetInAnchor[3]",
          "---- BODY BODY@offsetInAnchor[3]", "-S-- IMG@0 IMG@beforeAnchor",
          "---E IMG@1 IMG@afterAnchor", "---- BODY BODY@offsetInAnchor[4]",
          "-S-- BR@0 BR@beforeAnchor", "---E BR@1 BR@afterAnchor",
          "---E BODY BODY@afterChildren", "---E HTML HTML@afterChildren"));
}

TEST_F(PositionIteratorTest, incrementWithSelectElement) {
  const char* selection_text =
      "|<select id=target><option>1</option><option>2</option></select>123";

  EXPECT_THAT(
      ScanForward(selection_text),
      ElementsAre(
          "-S-- BODY BODY@offsetInAnchor[0]",
          // Note: `DeprecatedComputePosition()` should return
          // `SELECT@beforeAnchor`.
          "-S-E SELECT id=\"target\"@0 SELECT id=\"target\"@beforeAnchor "
          "SELECT id=\"target\"@afterAnchor",
          "---E SELECT id=\"target\"@1 SELECT id=\"target\"@afterAnchor",
          "---- BODY BODY@offsetInAnchor[1]",
          "-S-- #text \"123\"@0 #text \"123\"@offsetInAnchor[0]",
          "---- #text \"123\"@1 #text \"123\"@offsetInAnchor[1]",
          "---- #text \"123\"@2 #text \"123\"@offsetInAnchor[2]",
          "---E #text \"123\"@3 #text \"123\"@offsetInAnchor[3]",
          "---E BODY BODY@afterChildren", "---E HTML HTML@afterChildren"));

  EXPECT_THAT(
      ScanForwardInFlatTree(selection_text),
      ElementsAre(
          "-S-- BODY BODY@offsetInAnchor[0]",
          // Note: `DeprecatedComputePosition()` should return
          // `SELECT@beforeAnchor`.
          "-S-E SELECT id=\"target\"@0 SELECT id=\"target\"@beforeAnchor "
          "SELECT id=\"target\"@afterAnchor",
          "---E SELECT id=\"target\"@1 SELECT id=\"target\"@afterAnchor",
          "---- BODY BODY@offsetInAnchor[1]",
          "-S-- #text \"123\"@0 #text \"123\"@offsetInAnchor[0]",
          "---- #text \"123\"@1 #text \"123\"@offsetInAnchor[1]",
          "---- #text \"123\"@2 #text \"123\"@offsetInAnchor[2]",
          "---E #text \"123\"@3 #text \"123\"@offsetInAnchor[3]",
          "---E BODY BODY@afterChildren", "---E HTML HTML@afterChildren"));
}

// For http://crbug.com/695317
TEST_F(PositionIteratorTest, incrementWithTextAreaElement) {
  const char* selection_text = "|<textarea id=target>123</textarea>456";

  EXPECT_THAT(
      ScanForward(selection_text),
      ElementsAre(
          "-S-- BODY BODY@offsetInAnchor[0]",
          // Note: `DeprecatedComputePosition()` should return
          // `TEXTAREA@beforeAnchor`.
          "-S-E TEXTAREA id=\"target\"@0 TEXTAREA id=\"target\"@beforeAnchor "
          "TEXTAREA id=\"target\"@afterAnchor",
          "---E TEXTAREA id=\"target\"@1 TEXTAREA id=\"target\"@afterAnchor",
          "---- BODY BODY@offsetInAnchor[1]",
          "-S-- #text \"456\"@0 #text \"456\"@offsetInAnchor[0]",
          "---- #text \"456\"@1 #text \"456\"@offsetInAnchor[1]",
          "---- #text \"456\"@2 #text \"456\"@offsetInAnchor[2]",
          "---E #text \"456\"@3 #text \"456\"@offsetInAnchor[3]",
          "---E BODY BODY@afterChildren", "---E HTML HTML@afterChildren"));

  EXPECT_THAT(
      ScanForwardInFlatTree(selection_text),
      ElementsAre(
          "-S-- BODY BODY@offsetInAnchor[0]",
          // Note: `DeprecatedComputePosition()` should return
          // `TEXTAREA@beforeAnchor`.
          "-S-E TEXTAREA id=\"target\"@0 TEXTAREA id=\"target\"@beforeAnchor "
          "TEXTAREA id=\"target\"@afterAnchor",
          "---E TEXTAREA id=\"target\"@1 TEXTAREA id=\"target\"@afterAnchor",
          "---- BODY BODY@offsetInAnchor[1]",
          "-S-- #text \"456\"@0 #text \"456\"@offsetInAnchor[0]",
          "---- #text \"456\"@1 #text \"456\"@offsetInAnchor[1]",
          "---- #text \"456\"@2 #text \"456\"@offsetInAnchor[2]",
          "---E #text \"456\"@3 #text \"456\"@offsetInAnchor[3]",
          "---E BODY BODY@afterChildren", "---E HTML HTML@afterChildren"));
}

// For http://crbug.com/1248744
TEST_F(PositionIteratorTest, nullPosition) {
  PositionIterator dom_iterator((Position()));
  PositionIteratorInFlatTree flat_iterator((PositionInFlatTree()));

  EXPECT_EQ(Position(), dom_iterator.ComputePosition());
  EXPECT_EQ(PositionInFlatTree(), flat_iterator.ComputePosition());

  EXPECT_EQ(Position(), dom_iterator.DeprecatedComputePosition());
  EXPECT_EQ(PositionInFlatTree(), flat_iterator.DeprecatedComputePosition());

  dom_iterator.Increment();
  flat_iterator.Increment();

  EXPECT_EQ(Position(), dom_iterator.ComputePosition());
  EXPECT_EQ(PositionInFlatTree(), flat_iterator.ComputePosition());

  dom_iterator.Decrement();
  flat_iterator.Decrement();

  EXPECT_EQ(Position(), dom_iterator.ComputePosition());
  EXPECT_EQ(PositionInFlatTree(), flat_iterator.ComputePosition());
}

}  // namespace blink
```