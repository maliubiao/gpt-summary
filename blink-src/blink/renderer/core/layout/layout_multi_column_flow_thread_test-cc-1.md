Response:
The user wants a summary of the provided C++ code, which is part of the Chromium Blink engine. The file `layout_multi_column_flow_thread_test.cc` seems to contain unit tests for the multi-column layout feature.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core functionality:** The filename and the content of the tests heavily suggest this file tests the behavior of multi-column layouts. Keywords like `MultiColumn`, `spanner`, `content`, `insert`, `remove`, and `ColumnSetSignature` are strong indicators.

2. **Recognize the testing framework:** The code uses `TEST_F`, indicating it's using Google Test, a common C++ testing framework. The setup likely involves creating a test fixture (`MultiColumnTreeModifyingTest`, `MultiColumnRenderingTest`).

3. **Analyze the test categories:**  The tests are grouped into two main fixtures:
    * `MultiColumnTreeModifyingTest`: Focuses on how changes to the DOM tree (inserting and removing elements) affect the structure of the multi-column layout.
    * `MultiColumnRenderingTest`: Focuses on how the multi-column layout renders elements, including continuations, inserting different types of elements, and potential crash scenarios.

4. **Understand the "ColumnSetSignature":** The consistent use of `ColumnSetSignature` suggests it's a helper function to represent the structure of the columns within the multi-column container. The letters 'c' and 's' likely represent content and spanners respectively.

5. **Infer the relationships with web technologies:** Multi-column layout is a CSS feature. Therefore, the tests are inherently related to CSS. The tests manipulate the DOM, which is the foundation of HTML. While JavaScript isn't directly used in the *test code*, the functionality being tested is triggered by browser rendering, which can be influenced by JavaScript manipulating the DOM and CSS.

6. **Identify test patterns:** Many tests follow a pattern:
    * Set up an initial HTML structure (`SetMulticolHTML`).
    * Perform a DOM manipulation (e.g., `ReparentLayoutObject`, `DestroyLayoutObject`).
    * Assert the expected `ColumnSetSignature`.

7. **Look for specific examples related to web technologies:**
    *  The use of HTML tags like `<div>`, `<span>`, `<video>`, `<iframe>` directly links to HTML.
    *  The `InsertStyleElement` function and setting `column-count` indicates interaction with CSS properties.
    *  The `normalize()` method is a JavaScript DOM API.

8. **Identify potential user/programming errors:** The tests involving "invalid spanners" (nested spanners) point to constraints or rules about how spanners can be used, which could be potential user errors.

9. **Synthesize the information into a structured summary:**  Organize the findings into categories like general functionality, relationships with web technologies, logical inferences, and user/programming errors.

10. **Address the "Part 2" instruction:** Since this is part 2, focus on summarizing the *specific* code provided in this segment, rather than repeating the general overview from part 1. Emphasize the tree modification tests and the rendering tests.

11. **Refine and elaborate:** Add more detail and clarity to each point, using examples from the code where appropriate. For instance, explain what "spanners" are in the context of multi-column layouts.

By following these steps, we can construct a comprehensive and accurate summary of the provided code.
这是`blink/renderer/core/layout/layout_multi_column_flow_thread_test.cc`文件的第二部分，延续了第一部分的功能，主要集中在测试多列布局中DOM树的修改以及渲染方面的行为。

**归纳一下它的功能：**

这部分代码主要测试了在多列布局容器中插入和删除元素（特别是spanner元素和普通内容元素）时，多列布局内部结构的变化，并通过 `ColumnSetSignature` 函数来验证这些变化是否符合预期。 此外，它还包含了一些渲染相关的测试，验证了在多列布局中插入不同类型的元素（如block和inline元素）以及列表项时的渲染结果。最后，它还包含一个用于检测潜在崩溃的测试用例。

**与javascript, html, css的功能的关系举例说明：**

* **HTML:** 测试用例通过 `SetMulticolHTML` 函数创建和操作HTML结构，例如：
    * `<div id='mc'>...</div>`：创建一个多列容器。
    * `<div class='s'></div>`：创建一个spanner元素 (通常通过CSS定义)。
    * `<div>content</div>`：在多列容器中添加内容。
* **CSS:** 虽然测试代码本身不直接写CSS，但它依赖于CSS来定义多列布局的行为。例如，spanner元素的行为是由CSS属性 `column-span: all;` 定义的。 `InsertStyleElement("#mc { column-count: 2}")` 这行代码直接在测试中插入CSS样式来定义多列容器的列数。
* **JavaScript:** 测试用例中使用了 `ReparentLayoutObject` 和 `DestroyLayoutObject` 等方法来模拟JavaScript对DOM树的修改。例如，JavaScript可以通过 `appendChild`、`insertBefore` 和 `removeChild` 等方法来移动或删除元素，这些操作会触发多列布局的重新计算和渲染。 `multicol.normalize()` 是一个 JavaScript DOM 方法，用于合并相邻的文本节点。

**逻辑推理的假设输入与输出举例:**

* **假设输入:**  一个包含多列容器 `#mc` 和一个内容元素 `#block` 的HTML结构。
* **操作:** 使用 `ReparentLayoutObject("mc", "block");` 将 `#block` 插入到 `#mc` 中。
* **预期输出:** `EXPECT_EQ(ColumnSetSignature("mc"), "cs");` (假设 `#block` 包含一个spanner元素，因此 `#mc` 的列集合签名变为 "内容-spanner") 或者 `EXPECT_EQ(ColumnSetSignature("mc"), "c");` (如果 `#block` 只是普通内容)。

* **假设输入:** 一个多列容器 `#mc` 初始为空。
* **操作:**  使用 JavaScript (在测试中模拟) 向 `#mc` 中插入一个包含文本 "x" 的 `<span>` 元素。
* **预期输出:**  渲染树会包含一个 `LayoutMultiColumnFlowThread` 和一个包含文本 "x" 的 `LayoutInline SPAN` 的匿名块。

**涉及用户或者编程常见的使用错误举例说明:**

* **嵌套 Spanner:**  测试用例 `InsertInvalidSpannerAndRemove` 和 `InsertSpannerWithInvalidSpannerAndRemove` 模拟了尝试在 Spanner 元素内部插入另一个 Spanner 元素的场景。这是一个不允许的操作，因为 Spanner 元素旨在跨越所有列。 用户可能会错误地尝试嵌套 Spanner，导致布局不符合预期。
* **在不合适的时机修改DOM:**  虽然测试代码模拟了DOM修改，但在实际编程中，如果JavaScript在布局计算或渲染过程中频繁且不当的修改DOM，可能会导致性能问题甚至渲染错误。 这些测试确保了引擎在DOM修改后能够正确地更新多列布局。

**总结这部分代码的功能：**

这部分测试代码深入验证了 Blink 引擎在处理多列布局时，针对 DOM 树的插入和删除操作，以及各种渲染场景下的正确性。它涵盖了以下几个关键方面：

1. **DOM 树修改对多列布局结构的影响:**  测试了在多列容器中插入和删除普通内容以及 spanner 元素时，内部列集合 (`ColumnSet`) 的结构变化是否符合预期。
2. **不同类型元素的渲染:**  测试了在多列布局中插入块级元素、内联元素和列表项时的渲染结果，包括匿名块的生成和元素的正确布局。
3. **连续内容的处理 (Continuation):**  测试了在多列容器中添加内容，以及在内容之间插入块级元素时，内容如何在不同的列集合中延续。
4. **错误使用 Spanner 的处理:**  测试了引擎如何处理不合法的 Spanner 嵌套，确保不会出现意外的布局错误。
5. **潜在崩溃的预防:**  包含了一个测试用例，旨在检测在特定场景下可能导致崩溃的情况，例如在多列布局中处理 `<iframe>` 元素。

总而言之，这部分测试是确保 Blink 引擎的多列布局功能稳定、可靠且符合规范的重要组成部分。 它通过模拟各种DOM操作和渲染场景，帮助开发者发现和修复潜在的bug，并保证了Web开发者能够正确地使用CSS多列布局特性。

Prompt: 
```
这是目录为blink/renderer/core/layout/layout_multi_column_flow_thread_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
re("mc"), "cs");
  DestroyLayoutObject("spanner");
  EXPECT_EQ(ColumnSetSignature("mc"), "c");
}

TEST_F(MultiColumnTreeModifyingTest, InsertSpannerBeforeContentAndRemove) {
  SetMulticolHTML(
      "<div id='spanner'></div><div id='mc'><div "
      "id='columnContent'></div></div>");
  ReparentLayoutObject("mc", "spanner", "columnContent");
  // We should now have a spanner placeholder, since we just moved a spanner
  // into the multicol container.
  EXPECT_EQ(ColumnSetSignature("mc"), "sc");
  DestroyLayoutObject("spanner");
  EXPECT_EQ(ColumnSetSignature("mc"), "c");
}

TEST_F(MultiColumnTreeModifyingTest, InsertSpannerBetweenContentAndRemove) {
  SetMulticolHTML(
      "<div id='spanner'></div><div id='mc'><div></div><div "
      "id='insertBefore'></div></div>");
  ReparentLayoutObject("mc", "spanner", "insertBefore");
  // Since the spanner was inserted in the middle of column content, what used
  // to be one column set had to be split in two, in order to get a spot to
  // insert the spanner placeholder.
  EXPECT_EQ(ColumnSetSignature("mc"), "csc");
  DestroyLayoutObject("spanner");
  // The spanner placeholder should be gone again now, and the two sets be
  // merged into one.
  EXPECT_EQ(ColumnSetSignature("mc"), "c");
}

TEST_F(MultiColumnTreeModifyingTest,
       InsertSubtreeWithContentAndSpannerAndRemove) {
  SetMulticolHTML(
      "<div id='block'>text<div id='spanner'></div>text</div><div "
      "id='mc'></div>");
  ReparentLayoutObject("mc", "block");
  EXPECT_EQ(ColumnSetSignature("mc"), "csc");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "");
}

TEST_F(MultiColumnTreeModifyingTest, InsertInsideSpannerAndRemove) {
  SetMulticolHTML(
      "<div id='block'>text</div><div id='mc'><div id='spanner'></div></div>");
  ReparentLayoutObject("spanner", "block");
  EXPECT_EQ(ColumnSetSignature("mc"), "s");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "s");
}

TEST_F(MultiColumnTreeModifyingTest,
       InsertSpannerInContentBeforeSpannerAndRemove) {
  SetMulticolHTML(
      "<div id='spanner'></div><div id='mc'><div></div><div "
      "id='insertBefore'></div><div class='s'></div></div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "cs");
  ReparentLayoutObject("mc", "spanner", "insertBefore");
  EXPECT_EQ(ColumnSetSignature("mc"), "cscs");
  DestroyLayoutObject("spanner");
  EXPECT_EQ(ColumnSetSignature("mc"), "cs");
}

TEST_F(MultiColumnTreeModifyingTest,
       InsertSpannerInContentAfterSpannerAndRemove) {
  SetMulticolHTML(
      "<div id='spanner'></div><div id='mc'><div "
      "class='s'></div><div></div><div id='insertBefore'></div></div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "sc");
  ReparentLayoutObject("mc", "spanner", "insertBefore");
  EXPECT_EQ(ColumnSetSignature("mc"), "scsc");
  DestroyLayoutObject("spanner");
  EXPECT_EQ(ColumnSetSignature("mc"), "sc");
}

TEST_F(MultiColumnTreeModifyingTest, InsertSpannerAfterSpannerAndRemove) {
  SetMulticolHTML(
      "<div id='spanner'></div><div id='mc'><div class='s'></div></div>");
  ReparentLayoutObject("mc", "spanner");
  EXPECT_EQ(ColumnSetSignature("mc"), "ss");
  DestroyLayoutObject("spanner");
  EXPECT_EQ(ColumnSetSignature("mc"), "s");
}

TEST_F(MultiColumnTreeModifyingTest, InsertSpannerBeforeSpannerAndRemove) {
  SetMulticolHTML(
      "<div id='spanner'></div><div id='mc'><div id='insertBefore' "
      "class='s'></div></div>");
  ReparentLayoutObject("mc", "spanner", "insertBefore");
  EXPECT_EQ(ColumnSetSignature("mc"), "ss");
  DestroyLayoutObject("spanner");
  EXPECT_EQ(ColumnSetSignature("mc"), "s");
}

TEST_F(MultiColumnTreeModifyingTest, InsertContentBeforeSpannerAndRemove) {
  SetMulticolHTML(
      "<div id='block'></div><div id='mc'><div id='insertBefore' "
      "class='s'></div></div>");
  ReparentLayoutObject("mc", "block", "insertBefore");
  EXPECT_EQ(ColumnSetSignature("mc"), "cs");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "s");
}

TEST_F(MultiColumnTreeModifyingTest,
       InsertContentAfterContentBeforeSpannerAndRemove) {
  SetMulticolHTML(
      "<div id='block'></div><div id='mc'>text<div id='insertBefore' "
      "class='s'></div></div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "cs");
  ReparentLayoutObject("mc", "block", "insertBefore");
  // There was already some content before the spanner prior to our insertion,
  // so no new set should be inserted.
  EXPECT_EQ(ColumnSetSignature("mc"), "cs");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "cs");
}

TEST_F(MultiColumnTreeModifyingTest,
       InsertContentAfterContentAndSpannerAndRemove) {
  SetMulticolHTML(
      "<div id='block'></div><div id='mc'>content<div class='s'></div></div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "cs");
  ReparentLayoutObject("mc", "block");
  EXPECT_EQ(ColumnSetSignature("mc"), "csc");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "cs");
}

TEST_F(MultiColumnTreeModifyingTest,
       InsertContentBeforeSpannerAndContentAndRemove) {
  SetMulticolHTML(
      "<div id='block'></div><div id='mc'><div id='insertBefore' "
      "class='s'></div>content</div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "sc");
  ReparentLayoutObject("mc", "block", "insertBefore");
  EXPECT_EQ(ColumnSetSignature("mc"), "csc");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "sc");
}

TEST_F(MultiColumnTreeModifyingTest,
       InsertSpannerIntoContentBeforeSpannerAndRemove) {
  SetMulticolHTML(
      "<div id='spanner'></div><div id='mc'><div></div><div "
      "id='insertBefore'></div><div class='s'></div><div "
      "class='s'></div><div></div></div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "cssc");
  ReparentLayoutObject("mc", "spanner", "insertBefore");
  EXPECT_EQ(ColumnSetSignature("mc"), "cscssc");
  DestroyLayoutObject("spanner");
  EXPECT_EQ(ColumnSetSignature("mc"), "cssc");
}

TEST_F(MultiColumnTreeModifyingTest,
       InsertSpannerIntoContentAfterSpannerAndRemove) {
  SetMulticolHTML(
      "<div id='spanner'></div><div id='mc'><div></div><div "
      "class='s'></div><div class='s'></div><div></div><div "
      "id='insertBefore'></div></div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "cssc");
  ReparentLayoutObject("mc", "spanner", "insertBefore");
  EXPECT_EQ(ColumnSetSignature("mc"), "csscsc");
  DestroyLayoutObject("spanner");
  EXPECT_EQ(ColumnSetSignature("mc"), "cssc");
}

TEST_F(MultiColumnTreeModifyingTest, InsertInvalidSpannerAndRemove) {
  SetMulticolHTML(
      "<div class='s' id='invalidSpanner'></div><div id='mc'><div "
      "id='spanner'></div></div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "s");
  ReparentLayoutObject("spanner", "invalidSpanner");
  // It's not allowed to nest spanners.
  EXPECT_EQ(ColumnSetSignature("mc"), "s");
  DestroyLayoutObject("invalidSpanner");
  EXPECT_EQ(ColumnSetSignature("mc"), "s");
}

TEST_F(MultiColumnTreeModifyingTest, InsertSpannerWithInvalidSpannerAndRemove) {
  SetMulticolHTML(
      "<div id='spanner'><div class='s' id='invalidSpanner'></div></div><div "
      "id='mc'></div>");
  ReparentLayoutObject("mc", "spanner");
  // It's not allowed to nest spanners.
  EXPECT_EQ(ColumnSetSignature("mc"), "s");
  DestroyLayoutObject("spanner");
  EXPECT_EQ(ColumnSetSignature("mc"), "");
}

TEST_F(MultiColumnTreeModifyingTest,
       InsertInvalidSpannerInSpannerBetweenContentAndRemove) {
  SetMulticolHTML(
      "<div class='s' id='invalidSpanner'></div><div id='mc'>text<div "
      "id='spanner'></div>text</div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "csc");
  ReparentLayoutObject("spanner", "invalidSpanner");
  EXPECT_EQ(ColumnSetSignature("mc"), "csc");
  DestroyLayoutObject("invalidSpanner");
  EXPECT_EQ(ColumnSetSignature("mc"), "csc");
}

TEST_F(MultiColumnTreeModifyingTest, InsertContentAndSpannerAndRemove) {
  SetMulticolHTML(
      "<div id='block'>text<div id='spanner'></div></div><div "
      "id='mc'>text</div>");
  ReparentLayoutObject("mc", "block");
  EXPECT_EQ(ColumnSetSignature("mc"), "cs");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "c");
}

TEST_F(MultiColumnTreeModifyingTest,
       InsertContentAndSpannerAndContentAndRemove) {
  SetMulticolHTML(
      "<div id='block'><div id='spanner'></div>text</div><div id='mc'></div>");
  ReparentLayoutObject("mc", "block");
  EXPECT_EQ(ColumnSetSignature("mc"), "csc");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "");
}

TEST_F(MultiColumnTreeModifyingTest, InsertSubtreeWithSpannerAndRemove) {
  SetMulticolHTML(
      "<div id='block'>text<div class='s'></div>text</div><div id='mc'></div>");
  ReparentLayoutObject("mc", "block");
  EXPECT_EQ(ColumnSetSignature("mc"), "csc");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "");
}

TEST_F(MultiColumnTreeModifyingTest,
       InsertSubtreeWithSpannerAfterContentAndRemove) {
  SetMulticolHTML(
      "<div id='block'>text<div class='s'></div>text</div><div id='mc'>column "
      "content</div>");
  ReparentLayoutObject("mc", "block");
  EXPECT_EQ(ColumnSetSignature("mc"), "csc");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "c");
}

TEST_F(MultiColumnTreeModifyingTest,
       InsertSubtreeWithSpannerBeforeContentAndRemove) {
  SetMulticolHTML(
      "<div id='block'>text<div class='s'></div>text</div><div id='mc'><div "
      "id='insertBefore'>column content</div></div>");
  ReparentLayoutObject("mc", "block", "insertBefore");
  EXPECT_EQ(ColumnSetSignature("mc"), "csc");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "c");
}

TEST_F(MultiColumnTreeModifyingTest,
       InsertSubtreeWithSpannerInsideContentAndRemove) {
  SetMulticolHTML(
      "<div id='block'>text<div class='s'></div>text</div><div id='mc'><div "
      "id='newParent'>outside<div id='insertBefore'>outside</div></div></div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "c");
  ReparentLayoutObject("newParent", "block", "insertBefore");
  EXPECT_EQ(ColumnSetSignature("mc"), "csc");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "c");
}

TEST_F(MultiColumnTreeModifyingTest,
       InsertSubtreeWithSpannerAfterSpannerAndRemove) {
  SetMulticolHTML(
      "<div id='block'>text<div class='s'></div>text</div><div id='mc'><div "
      "class='s'></div></div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "s");
  ReparentLayoutObject("mc", "block");
  EXPECT_EQ(ColumnSetSignature("mc"), "scsc");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "s");
}

TEST_F(MultiColumnTreeModifyingTest,
       InsertSubtreeWithSpannerBeforeSpannerAndRemove) {
  SetMulticolHTML(
      "<div id='block'>text<div class='s'></div>text</div><div id='mc'><div "
      "id='insertBefore' class='s'></div></div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "s");
  ReparentLayoutObject("mc", "block", "insertBefore");
  EXPECT_EQ(ColumnSetSignature("mc"), "cscs");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "s");
}

TEST_F(MultiColumnTreeModifyingTest, RemoveSpannerAndContent) {
  SetMulticolHTML(
      "<div id='mc'><div id='block'>text<div class='s'></div>text</div></div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "csc");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "");
}

TEST_F(MultiColumnTreeModifyingTest, RemoveSpannerAndSomeContentBefore) {
  SetMulticolHTML(
      "<div id='mc'>text<div id='block'>text<div class='s'></div></div></div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "cs");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "c");
}

TEST_F(MultiColumnTreeModifyingTest, RemoveSpannerAndAllContentBefore) {
  SetMulticolHTML(
      "<div id='mc'><div id='block'>text<div class='s'></div></div></div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "cs");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "");
}

TEST_F(MultiColumnTreeModifyingTest,
       RemoveSpannerAndAllContentBeforeWithContentAfter) {
  SetMulticolHTML(
      "<div id='mc'><div id='block'>text<div class='s'></div></div>text</div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "csc");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "c");
}

TEST_F(MultiColumnTreeModifyingTest, RemoveSpannerAndSomeContentAfter) {
  SetMulticolHTML(
      "<div id='mc'><div id='block'><div class='s'></div>text</div>text</div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "csc");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "c");
}

TEST_F(MultiColumnTreeModifyingTest, RemoveSpannerAndAllContentAfter) {
  SetMulticolHTML(
      "<div id='mc'><div id='block'><div class='s'></div>text</div></div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "csc");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "");
}

TEST_F(MultiColumnTreeModifyingTest,
       RemoveSpannerAndAllContentAfterWithContentBefore) {
  SetMulticolHTML(
      "<div id='mc'>text<div id='block'><div class='s'></div>text</div></div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "csc");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "c");
}

TEST_F(MultiColumnTreeModifyingTest, RemoveTwoSpannersBeforeContent) {
  SetMulticolHTML(
      "<div id='mc'><div id='block'><div class='s'></div><div "
      "class='s'></div></div>text</div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "cssc");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "c");
}

TEST_F(MultiColumnTreeModifyingTest, RemoveSpannerAndContentAndSpanner) {
  SetMulticolHTML(
      "<div id='mc'><div id='block'><div class='s'></div>text<div "
      "class='s'></div>text</div></div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "cscsc");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "");
}

TEST_F(MultiColumnTreeModifyingTest,
       RemoveSpannerAndContentAndSpannerBeforeContent) {
  SetMulticolHTML(
      "<div id='mc'><div id='block'><div class='s'></div>text<div "
      "class='s'></div></div>text</div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "cscsc");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "c");
}

TEST_F(MultiColumnTreeModifyingTest,
       RemoveSpannerAndContentAndSpannerAfterContent) {
  SetMulticolHTML(
      "<div id='mc'>text<div id='block'><div class='s'></div>text<div "
      "class='s'></div></div></div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "cscs");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "c");
}

TEST_F(MultiColumnTreeModifyingTest,
       RemoveInvalidSpannerInSpannerBetweenContent) {
  SetMulticolHTML(
      "<div id='mc'>text<div class='s'><div "
      "id='spanner'></div></div>text</div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "csc");
  DestroyLayoutObject("spanner");
  EXPECT_EQ(ColumnSetSignature("mc"), "csc");
}

TEST_F(MultiColumnTreeModifyingTest,
       RemoveSpannerWithInvalidSpannerBetweenContent) {
  SetMulticolHTML(
      "<div id='mc'>text<div id='spanner'><div "
      "class='s'></div></div>text</div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "csc");
  DestroyLayoutObject("spanner");
  EXPECT_EQ(ColumnSetSignature("mc"), "c");
}

TEST_F(MultiColumnRenderingTest, Continuation) {
  InsertStyleElement("#mc { column-count: 2}");
  SetBodyInnerHTML("<div id=mc><span>x<div id=inner></div>y</div>");
  auto& multicol = *GetElementById("mc");
  const auto& container = *To<LayoutBlockFlow>(multicol.GetLayoutObject());
  const auto& flow_thread = *container.MultiColumnFlowThread();

  ASSERT_TRUE(&flow_thread)
      << "We have flow thread even if container has no children.";

  // 1. Continuations should be in anonymous block in LayoutNG.
  EXPECT_FALSE(flow_thread.ChildrenInline());
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="mc"
  +--LayoutMultiColumnFlowThread (anonymous)
  |  +--LayoutBlockFlow (anonymous)
  |  |  +--LayoutInline SPAN
  |  |  |  +--LayoutText #text "x"
  |  |  |  +--LayoutBlockFlow (anonymous)
  |  |  |  |  +--LayoutBlockFlow DIV id="inner"
  |  |  |  +--LayoutText #text "y"
  +--LayoutMultiColumnSet (anonymous)
)DUMP",
            ToSimpleLayoutTree(container));

  // 2. Remove #inner to avoid continuation.
  GetElementById("inner")->remove();
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="mc"
  +--LayoutMultiColumnFlowThread (anonymous)
  |  +--LayoutBlockFlow (anonymous)
  |  |  +--LayoutInline SPAN
  |  |  |  +--LayoutText #text "x"
  |  |  |  +--LayoutText #text "y"
  +--LayoutMultiColumnSet (anonymous)
)DUMP",
            ToSimpleLayoutTree(container));

  // 3. Normalize to merge "x" and "y".
  // See http://crbug.com/1201508 for redundant |LayoutInline SPAN|.
  multicol.normalize();
  EXPECT_FALSE(flow_thread.ChildrenInline());
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="mc"
  +--LayoutMultiColumnFlowThread (anonymous)
  |  +--LayoutBlockFlow (anonymous)
  |  |  +--LayoutInline SPAN
  |  |  |  +--LayoutText #text "xy"
  +--LayoutMultiColumnSet (anonymous)
)DUMP",
            ToSimpleLayoutTree(container));
}

TEST_F(MultiColumnRenderingTest, InsertBlock) {
  InsertStyleElement("#mc { column-count: 3}");
  SetBodyInnerHTML("<div id=mc></div>");

  auto& multicol = *GetElementById("mc");
  const auto& container = *To<LayoutBlockFlow>(multicol.GetLayoutObject());
  const auto& flow_thread = *container.MultiColumnFlowThread();

  ASSERT_TRUE(&flow_thread)
      << "We have flow thread even if container has no children.";
  EXPECT_FALSE(flow_thread.ChildrenInline());
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="mc"
  +--LayoutMultiColumnFlowThread (anonymous)
)DUMP",
            ToSimpleLayoutTree(container));

  // 1. Add inline child
  multicol.appendChild(Text::Create(GetDocument(), "x"));
  RunDocumentLifecycle();
  EXPECT_FALSE(flow_thread.ChildrenInline());
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="mc"
  +--LayoutMultiColumnFlowThread (anonymous)
  |  +--LayoutBlockFlow (anonymous)
  |  |  +--LayoutText #text "x"
  +--LayoutMultiColumnSet (anonymous)
)DUMP",
            ToSimpleLayoutTree(container));

  // 2. Remove inline child
  multicol.removeChild(multicol.firstChild());
  RunDocumentLifecycle();

  EXPECT_FALSE(flow_thread.ChildrenInline());
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="mc"
  +--LayoutMultiColumnFlowThread (anonymous)
)DUMP",
            ToSimpleLayoutTree(container));

  // 3. Insert block
  multicol.insertBefore(MakeGarbageCollected<HTMLDivElement>(GetDocument()),
                        multicol.lastChild());
  RunDocumentLifecycle();
  EXPECT_FALSE(flow_thread.ChildrenInline());

  EXPECT_EQ(
      R"DUMP(
LayoutBlockFlow DIV id="mc"
  +--LayoutMultiColumnFlowThread (anonymous)
  |  +--LayoutBlockFlow DIV
  +--LayoutMultiColumnSet (anonymous)
)DUMP",
      ToSimpleLayoutTree(container));
}

TEST_F(MultiColumnRenderingTest, InsertInline) {
  InsertStyleElement("#mc { column-count: 3}");
  SetBodyInnerHTML("<div id=mc></div>");

  auto& multicol = *GetElementById("mc");
  const auto& container = *To<LayoutBlockFlow>(multicol.GetLayoutObject());
  const auto& flow_thread = *container.MultiColumnFlowThread();

  ASSERT_TRUE(&flow_thread)
      << "We have flow thread even if container has no children.";
  EXPECT_FALSE(flow_thread.ChildrenInline());
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="mc"
  +--LayoutMultiColumnFlowThread (anonymous)
)DUMP",
            ToSimpleLayoutTree(container));

  // 1. Add inline child
  multicol.appendChild(Text::Create(GetDocument(), "x"));
  RunDocumentLifecycle();
  EXPECT_FALSE(flow_thread.ChildrenInline());
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="mc"
  +--LayoutMultiColumnFlowThread (anonymous)
  |  +--LayoutBlockFlow (anonymous)
  |  |  +--LayoutText #text "x"
  +--LayoutMultiColumnSet (anonymous)
)DUMP",
            ToSimpleLayoutTree(container));

  // 2. Remove inline child
  multicol.removeChild(multicol.firstChild());
  RunDocumentLifecycle();

  EXPECT_FALSE(flow_thread.ChildrenInline());
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="mc"
  +--LayoutMultiColumnFlowThread (anonymous)
)DUMP",
            ToSimpleLayoutTree(container));

  // 3. Insert inline
  multicol.insertBefore(MakeGarbageCollected<HTMLSpanElement>(GetDocument()),
                        multicol.lastChild());
  RunDocumentLifecycle();
  EXPECT_FALSE(flow_thread.ChildrenInline());
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="mc"
  +--LayoutMultiColumnFlowThread (anonymous)
  |  +--LayoutBlockFlow (anonymous)
  |  |  +--LayoutInline SPAN
  +--LayoutMultiColumnSet (anonymous)
)DUMP",
            ToSimpleLayoutTree(container));
}

TEST_F(MultiColumnRenderingTest, ListItem) {
  InsertStyleElement("#mc { column-count: 3; display: list-item; }");
  SetBodyInnerHTML("<div id=mc></div>");

  auto& multicol = *GetElementById("mc");
  const auto& container = *To<LayoutBlockFlow>(multicol.GetLayoutObject());
  const auto& flow_thread = *container.MultiColumnFlowThread();

  EXPECT_FALSE(flow_thread.ChildrenInline());
  EXPECT_EQ(R"DUMP(
LayoutListItem DIV id="mc"
  +--LayoutMultiColumnFlowThread (anonymous)
  |  +--LayoutOutsideListMarker ::marker
  |  |  +--LayoutTextFragment (anonymous) ("\u2022 ")
  +--LayoutMultiColumnSet (anonymous)
)DUMP",
            ToSimpleLayoutTree(container));
}

TEST_F(MultiColumnRenderingTest, SplitInline) {
  InsertStyleElement("#mc { column-count: 3}");
  SetBodyInnerHTML("<div id=mc></div>");

  auto& multicol = *GetElementById("mc");
  const auto& container = *To<LayoutBlockFlow>(multicol.GetLayoutObject());
  const auto& flow_thread = *container.MultiColumnFlowThread();

  ASSERT_TRUE(&flow_thread)
      << "We have flow thread even if container has no children.";
  EXPECT_FALSE(flow_thread.ChildrenInline());
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="mc"
  +--LayoutMultiColumnFlowThread (anonymous)
)DUMP",
            ToSimpleLayoutTree(container));

  // 1. Add inline child
  multicol.appendChild(Text::Create(GetDocument(), "x"));
  RunDocumentLifecycle();

  EXPECT_FALSE(flow_thread.ChildrenInline());
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="mc"
  +--LayoutMultiColumnFlowThread (anonymous)
  |  +--LayoutBlockFlow (anonymous)
  |  |  +--LayoutText #text "x"
  +--LayoutMultiColumnSet (anonymous)
)DUMP",
            ToSimpleLayoutTree(container));

  // 2. Remove inline child
  multicol.removeChild(multicol.firstChild());
  RunDocumentLifecycle();
  EXPECT_FALSE(flow_thread.ChildrenInline());
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="mc"
  +--LayoutMultiColumnFlowThread (anonymous)
)DUMP",
            ToSimpleLayoutTree(container));

  // 3. Add inline child again
  multicol.appendChild(Text::Create(GetDocument(), "x"));
  RunDocumentLifecycle();
  EXPECT_FALSE(flow_thread.ChildrenInline());
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="mc"
  +--LayoutMultiColumnFlowThread (anonymous)
  |  +--LayoutBlockFlow (anonymous)
  |  |  +--LayoutText #text "x"
  +--LayoutMultiColumnSet (anonymous)
)DUMP",
            ToSimpleLayoutTree(container));

  // 4. Add inline child (one more)
  multicol.appendChild(Text::Create(GetDocument(), "y"));
  RunDocumentLifecycle();
  EXPECT_FALSE(flow_thread.ChildrenInline());
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="mc"
  +--LayoutMultiColumnFlowThread (anonymous)
  |  +--LayoutBlockFlow (anonymous)
  |  |  +--LayoutText #text "x"
  |  |  +--LayoutText #text "y"
  +--LayoutMultiColumnSet (anonymous)
)DUMP",
            ToSimpleLayoutTree(container));

  // 5. Add a block child to split inline children.
  multicol.insertBefore(MakeGarbageCollected<HTMLDivElement>(GetDocument()),
                        multicol.lastChild());
  RunDocumentLifecycle();
  EXPECT_FALSE(flow_thread.ChildrenInline());
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="mc"
  +--LayoutMultiColumnFlowThread (anonymous)
  |  +--LayoutBlockFlow (anonymous)
  |  |  +--LayoutText #text "x"
  |  +--LayoutBlockFlow DIV
  |  +--LayoutBlockFlow (anonymous)
  |  |  +--LayoutText #text "y"
  +--LayoutMultiColumnSet (anonymous)
)DUMP",
            ToSimpleLayoutTree(container));
}

TEST_F(MultiColumnRenderingTest, FlowThreadUpdateGeometryCrash) {
  SetBodyInnerHTML(R"HTML(
      <video width="64" height="64" controls>
      <iframe width=320 height=320></iframe>)HTML");
  UpdateAllLifecyclePhasesForTest();
  InsertStyleElement(R"CSS(
      body, html {
        column-count: 2;
        overflow: clip;
      })CSS");
  UpdateAllLifecyclePhasesForTest();
  // Pass if no crash in LayoutMultiColumnFlowThread::UpdateGeometry() call
  // from LayoutMedia::ComputePanelWidth().
}

}  // anonymous namespace

}  // namespace blink

"""


```