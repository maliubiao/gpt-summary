Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Understanding of the File's Purpose:**

* **Filename:** `layout_tree_builder_traversal_test.cc` immediately suggests this file is about testing the traversal mechanisms within the layout tree building process in Blink. "Traversal" implies moving between nodes in a tree structure. "Layout Tree Builder" points to the part of the engine responsible for creating the visual representation of the DOM.
* **Headers:**  The included headers provide clues:
    * `gtest/gtest.h`: This is the Google Test framework, confirming this is a test file.
    * `layout_tree_builder_traversal.h`: This is the *target* of the tests – the code being tested.
    * `core/dom/*`: Headers related to the Document Object Model (DOM), including `Element`, `Node`, `PseudoElement`, `Document`. This confirms the focus is on DOM interactions during layout.
    * `core/layout/*`:  `LayoutText` specifically suggests this involves the layout representation of text nodes.
    * `core/testing/*`:  Indicates the use of Blink's internal testing utilities.

**2. Examining the Test Fixture:**

* `class LayoutTreeBuilderTraversalTest : public RenderingTest`: This establishes a test fixture. `RenderingTest` (likely from `core_unit_test_helper.h`) probably provides a basic environment for setting up and rendering web content within the test. The `protected` section with `SetupSampleHTML` further supports this idea.

**3. Analyzing Individual Tests:**

For each `TEST_F` block, ask:

* **What is the test's name and what does it imply?**  (e.g., `emptySubTree` suggests testing traversal in a simple, empty structure).
* **What HTML is being set up?**  Look for `SetupSampleHTML` and the `kHtml` string.
* **What DOM elements are being retrieved?** Look for `GetDocument().QuerySelector()`.
* **What `LayoutTreeBuilderTraversal` functions are being called?** Identify the specific functions being tested (e.g., `FirstChild`, `NextSibling`, `Parent`).
* **What are the `EXPECT_EQ` or `EXPECT_TRUE`/`EXPECT_FALSE` assertions checking?** This reveals the expected behavior of the traversal functions in different scenarios.

**4. Identifying Relationships to Web Technologies (HTML, CSS, JavaScript):**

* **HTML:** The `kHtml` strings directly represent HTML structures. The tests explore how the layout tree is built from these structures.
* **CSS:** The `pseudos` test explicitly uses CSS to define pseudo-elements (`::marker`, `::before`, `::after`). The `display: contents` tests also relate directly to CSS properties.
* **JavaScript:** While the tests themselves are in C++, the DOM manipulation (using `QuerySelector`) and the concepts being tested are fundamental to how JavaScript interacts with the page structure. A JavaScript developer would expect similar traversal behavior when navigating the DOM.

**5. Inferring Logical Reasoning and Assumptions:**

* **Empty Subtree:** The test assumes that an element with no children will return `nullptr` for `FirstChild`, `NextSibling`, and `PreviousSibling`.
* **Pseudo-elements:** The test assumes that pseudo-elements are considered "children" in the layout tree traversal, and the order is consistent with the CSS specification.
* **`display: contents`:** The tests demonstrate the key behavior of `display: contents`:  it makes the element itself not generate a layout box, but its *children* act as if they were direct children of the parent. This requires careful traversal logic.
* **Limits:** This test assumes a mechanism exists to prevent infinite recursion when traversing potentially deeply nested structures.

**6. Considering User and Programming Errors:**

* **User Errors (related to `display: contents`):** A user might expect `display: contents` to completely remove the element from the layout, not realizing its children are promoted. This could lead to unexpected styling or positioning.
* **Programming Errors:**  A developer implementing traversal logic might incorrectly handle pseudo-elements or elements with `display: contents`, leading to incorrect ordering or missing elements during traversal. The tests are designed to catch such errors.

**7. Tracing User Actions to Code:**

This part requires more speculation, but the general idea is:

* **Loading a Webpage:** The user initiates loading a webpage in Chromium.
* **Parsing:** The HTML is parsed and a DOM tree is created.
* **Style Calculation:** CSS is parsed and applied, determining the `display` property and generating pseudo-elements.
* **Layout Tree Building:**  The `LayoutTreeBuilder` iterates through the DOM and, based on CSS, creates the layout tree. *This is where the code being tested is used.* The `LayoutTreeBuilderTraversal` functions are called to navigate and connect nodes in the layout tree.
* **Rendering:** The layout tree is used to paint the webpage.
* **Developer Tools/JavaScript Interaction:** A developer using JavaScript to traverse the DOM (e.g., `childNodes`, `nextSibling`) will indirectly rely on the correctness of the underlying layout tree structure. Errors in the `LayoutTreeBuilderTraversal` could lead to inconsistencies between the JavaScript DOM view and the actual rendered layout.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "Maybe this is just about basic DOM traversal."
* **Correction:**  The presence of `display: contents` and pseudo-elements indicates it's specifically about the *layout* tree traversal, which has special considerations beyond the raw DOM.
* **Initial thought:** "The `limits` test is about performance."
* **Correction:** While related to performance, the comment "Should not overrecurse" suggests it's primarily about preventing stack overflows or infinite loops in the traversal logic.

By following these steps, combining code analysis with knowledge of web technologies and the testing context, we can arrive at a comprehensive understanding of the purpose and functionality of the `layout_tree_builder_traversal_test.cc` file.
这个C++源代码文件 `layout_tree_builder_traversal_test.cc` 是 Chromium Blink 渲染引擎的一部分，它的主要功能是**测试 `LayoutTreeBuilderTraversal` 类中的各种用于遍历布局树的方法的正确性**。

简单来说，这个文件里的代码通过创建不同的HTML结构，然后使用 `LayoutTreeBuilderTraversal` 类提供的方法来检查节点之间的父子、兄弟关系，以及处理一些特殊的布局情况（例如 `display: contents` 和伪元素），确保布局树的遍历逻辑是正确的。

以下是对其功能的详细解释，并结合 JavaScript、HTML 和 CSS 的关系进行说明：

**1. 功能概述:**

* **测试布局树节点的遍历:**  `LayoutTreeBuilderTraversal` 类提供了一系列静态方法，用于在布局树中进行导航，例如获取第一个子节点、下一个兄弟节点、上一个兄弟节点和父节点。这个测试文件验证了这些方法在不同DOM结构下的正确行为。
* **测试伪元素的处理:** CSS 伪元素（如 `::before`, `::after`, `::marker`, `::column::scroll-marker` 等）在布局树中也有相应的表示。这个文件测试了遍历逻辑是否能正确地处理这些伪元素，将它们纳入遍历的顺序中。
* **测试 `display: contents` 的处理:** CSS 属性 `display: contents` 会使元素自身不生成布局框，但其子元素会如同直接是父元素的子元素一样参与布局。这个文件测试了遍历逻辑是否能正确地跳过 `display: contents` 元素，直接访问其子元素的布局对象。
* **限制遍历深度:**  为了防止无限循环或者性能问题，遍历操作可能会有深度限制。这个文件也测试了在指定遍历深度限制的情况下，遍历逻辑是否会正确停止。
* **测试列布局和滚动标记:**  涉及到 CSS 列布局和滚动标记的场景，测试遍历逻辑是否能正确处理列伪元素及其子伪元素（如 `::column::scroll-marker`）。

**2. 与 JavaScript, HTML, CSS 的关系:**

这个测试文件直接关联着浏览器如何根据 HTML 和 CSS 构建和遍历布局树，而这又是 JavaScript 操作 DOM 和获取元素布局信息的基础。

* **HTML:**  测试文件中通过 `SetupSampleHTML` 函数设置不同的 HTML 结构，例如包含 `<div>` 元素，设置不同的 `id` 属性等。这些 HTML 结构模拟了网页中可能出现的各种节点关系。
    * **例子:**  `<div id='top'></div>` 定义了一个带有 `id` 的 `div` 元素。
* **CSS:** 测试文件中会使用 CSS 来影响元素的布局行为，例如设置 `display: list-item` 创建标记伪元素，使用 `::before` 和 `::after` 创建内容伪元素，以及使用 `display: contents` 来改变元素的布局结构。
    * **例子:** `#top { display: list-item; } #top::marker { content: "baz"; }` 定义了元素的显示方式，并创建了一个标记伪元素。
* **JavaScript:** 虽然这个文件本身是 C++ 代码，但它测试的 `LayoutTreeBuilderTraversal` 功能是浏览器内部实现的关键部分，最终影响着 JavaScript 可以如何操作和查询 DOM。例如，当 JavaScript 代码使用 `element.firstChild`, `element.nextSibling` 等属性遍历 DOM 树时，底层的布局树结构和遍历逻辑必须是正确的。如果这里的遍历逻辑有误，JavaScript 获取到的元素关系可能就不正确。

**3. 逻辑推理与假设输入输出:**

* **假设输入 (对于 `emptySubTree` 测试):**
    ```html
    <div id='top'></div>
    ```
* **预期输出:**
    * `LayoutTreeBuilderTraversal::FirstChild(*top)` 应该返回 `nullptr`，因为该 `div` 元素没有子元素。
    * `LayoutTreeBuilderTraversal::NextSibling(*top)` 应该返回 `nullptr`，假设 `top` 元素是其父元素的唯一子元素或最后一个子元素。在这个测试中，`top` 的父元素是 `body`，所以下一个兄弟节点是 `nullptr`。
    * `LayoutTreeBuilderTraversal::PreviousSibling(*top)` 应该返回 `nullptr`，假设 `top` 元素是其父元素的唯一子元素或第一个子元素。
    * `LayoutTreeBuilderTraversal::Parent(*top)` 应该返回 `body` 元素。

* **假设输入 (对于 `pseudos` 测试):**
    ```html
    <style>
    #top { display: list-item; }
    #top::marker { content: "baz"; }
    #top::before { content: "foo"; }
    #top::after { content: "bar"; }
    </style>
    <div id='top'></div>
    ```
* **预期输出:**  遍历的顺序应该是：marker 伪元素 -> before 伪元素 -> after 伪元素。 相应的 `NextSibling` 和 `PreviousSibling` 方法应该返回预期的伪元素对象。

* **假设输入 (对于 `displayContentsChildren` 测试):**
    ```html
    <div></div>
    <div id='contents' style='display: contents'><div id='inner'></div></div>
    <div id='last'></div>
    ```
* **预期输出:** `LayoutTreeBuilderTraversal::NextSiblingLayoutObject(*first)` 应该直接返回 `inner` 元素的布局对象，跳过了 `contents` 元素，因为它的 `display` 属性是 `contents`。

**4. 用户或编程常见的使用错误:**

* **误解 `display: contents` 的行为:**  开发者可能会错误地认为设置了 `display: contents` 的元素完全不存在于布局树中，而忽略了其子元素会被提升。这可能导致 JavaScript 代码尝试访问该元素时遇到 `null` 或未定义的行为，或者在样式应用上产生意外的结果。
    * **例子:**  用户在 JavaScript 中使用 `document.getElementById('contents').children` 可能期望获取到 `inner` 元素，但实际上由于 `contents` 自身不生成布局框，直接访问其布局相关的属性可能会出现问题。
* **错误地假设伪元素是常规的 DOM 子节点:**  开发者可能会尝试使用常规的 DOM API（如 `element.children`）来访问伪元素，但伪元素不是真正的 DOM 子节点。需要使用特定的方法（如 `getComputedStyle` 或 `::before`, `::after` 选择器）来操作它们。这个测试确保了布局树的遍历逻辑能够正确地将伪元素纳入考虑，但开发者仍然需要理解伪元素与常规 DOM 元素的区别。
* **在复杂的布局结构中错误地预测兄弟节点关系:**  尤其是在使用 `float`, `position: absolute`, `display: contents` 等属性时，元素的视觉顺序和 DOM 树的结构顺序可能不同。开发者在进行 DOM 遍历时，需要考虑这些布局因素的影响。这个测试确保了 Blink 内部的遍历逻辑是正确的，可以作为开发者调试布局问题的参考。

**5. 用户操作如何一步步到达这里 (作为调试线索):**

当用户在浏览器中访问一个网页时，以下步骤可能涉及到 `LayoutTreeBuilderTraversal` 的代码：

1. **加载 HTML:** 浏览器下载 HTML 文档。
2. **解析 HTML:**  HTML 解析器将 HTML 标记转换为 DOM 树。
3. **计算样式:** 浏览器解析 CSS 样式表，并计算出每个元素的最终样式。
4. **构建布局树 (Layout Tree Building):**  这是一个关键步骤，`LayoutTreeBuilder` 遍历 DOM 树，并根据计算出的样式创建布局树。在构建布局树的过程中，会使用 `LayoutTreeBuilderTraversal` 类的方法来确定节点之间的父子和兄弟关系，特别是处理像 `display: contents` 和伪元素这样的特殊情况。
5. **布局 (Layout/Reflow):** 布局引擎遍历布局树，计算每个元素的位置和大小。
6. **绘制 (Painting):**  绘制引擎根据布局信息将元素绘制到屏幕上。

**作为调试线索，如果开发者遇到以下问题，可能会怀疑 `LayoutTreeBuilderTraversal` 的实现是否存在问题：**

* **JavaScript 代码遍历 DOM 时，获取到的元素关系与预期不符，尤其是在使用了 `display: contents` 或存在伪元素的情况下。** 例如，`element.nextSibling` 返回了错误的元素。
* **某些 CSS 样式没有正确应用，可能是因为布局树的结构不正确，导致样式选择器匹配错误。**
* **在性能分析中发现布局阶段耗时过长，可能与布局树的构建和遍历效率有关。**

**总结:**

`layout_tree_builder_traversal_test.cc` 文件是 Blink 渲染引擎中一个重要的测试文件，它专注于测试布局树遍历逻辑的正确性，确保浏览器能准确地理解和处理各种复杂的 HTML 和 CSS 结构，为 JavaScript 操作 DOM 和最终的页面渲染提供正确的基础。理解这个文件的功能有助于开发者深入理解浏览器的渲染原理，并在遇到布局问题时提供调试思路。

Prompt: 
```
这是目录为blink/renderer/core/dom/layout_tree_builder_traversal_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/dom/layout_tree_builder_traversal.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/column_pseudo_element.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"

namespace blink {

class LayoutTreeBuilderTraversalTest : public RenderingTest {
 protected:
  void SetupSampleHTML(const char* main_html);
};

void LayoutTreeBuilderTraversalTest::SetupSampleHTML(const char* main_html) {
  SetBodyInnerHTML(String::FromUTF8(main_html));
}

TEST_F(LayoutTreeBuilderTraversalTest, emptySubTree) {
  const char* const kHtml = "<div id='top'></div>";
  SetupSampleHTML(kHtml);

  Element* top = GetDocument().QuerySelector(AtomicString("#top"));
  Element* body = GetDocument().QuerySelector(AtomicString("body"));
  EXPECT_EQ(nullptr, LayoutTreeBuilderTraversal::FirstChild(*top));
  EXPECT_EQ(nullptr, LayoutTreeBuilderTraversal::NextSibling(*top));
  EXPECT_EQ(nullptr, LayoutTreeBuilderTraversal::PreviousSibling(*top));
  EXPECT_EQ(body, LayoutTreeBuilderTraversal::Parent(*top));
}

TEST_F(LayoutTreeBuilderTraversalTest, pseudos) {
  const char* const kHtml =
      "<style>"
      "#top { display: list-item; }"
      "#top::marker { content: \"baz\"; }"
      "#top::before { content: \"foo\"; }"
      "#top::after { content: \"bar\"; }"
      "</style>"
      "<div id='top'></div>";
  SetupSampleHTML(kHtml);

  Element* top = GetDocument().QuerySelector(AtomicString("#top"));
  Element* marker = top->GetPseudoElement(kPseudoIdMarker);
  Element* before = top->GetPseudoElement(kPseudoIdBefore);
  Element* after = top->GetPseudoElement(kPseudoIdAfter);
  EXPECT_EQ(marker, LayoutTreeBuilderTraversal::Next(*top, nullptr));
  EXPECT_EQ(before, LayoutTreeBuilderTraversal::NextSibling(*marker));
  EXPECT_EQ(after, LayoutTreeBuilderTraversal::NextSibling(*before));
  EXPECT_EQ(nullptr, LayoutTreeBuilderTraversal::NextSibling(*after));
  EXPECT_EQ(before, LayoutTreeBuilderTraversal::PreviousSibling(*after));
  EXPECT_EQ(marker, LayoutTreeBuilderTraversal::PreviousSibling(*before));
  EXPECT_EQ(nullptr, LayoutTreeBuilderTraversal::PreviousSibling(*marker));
  EXPECT_EQ(marker, LayoutTreeBuilderTraversal::FirstChild(*top));
  EXPECT_EQ(after, LayoutTreeBuilderTraversal::LastChild(*top));
}

TEST_F(LayoutTreeBuilderTraversalTest, emptyDisplayContents) {
  const char* const kHtml =
      "<div></div>"
      "<div style='display: contents'></div>"
      "<div id='last'></div>";
  SetupSampleHTML(kHtml);

  Element* first = GetDocument().QuerySelector(AtomicString("div"));
  Element* last = GetDocument().QuerySelector(AtomicString("#last"));

  EXPECT_TRUE(last->GetLayoutObject());
  EXPECT_EQ(last->GetLayoutObject(),
            LayoutTreeBuilderTraversal::NextSiblingLayoutObject(*first));
}

TEST_F(LayoutTreeBuilderTraversalTest, displayContentsChildren) {
  const char* const kHtml =
      "<div></div>"
      "<div id='contents' style='display: contents'><div "
      "id='inner'></div></div>"
      "<div id='last'></div>";
  SetupSampleHTML(kHtml);

  Element* first = GetDocument().QuerySelector(AtomicString("div"));
  Element* inner = GetDocument().QuerySelector(AtomicString("#inner"));
  Element* contents = GetDocument().QuerySelector(AtomicString("#contents"));
  Element* last = GetDocument().QuerySelector(AtomicString("#last"));

  EXPECT_TRUE(inner->GetLayoutObject());
  EXPECT_TRUE(last->GetLayoutObject());
  EXPECT_TRUE(first->GetLayoutObject());
  EXPECT_FALSE(contents->GetLayoutObject());

  EXPECT_EQ(inner->GetLayoutObject(),
            LayoutTreeBuilderTraversal::NextSiblingLayoutObject(*first));
  EXPECT_EQ(first->GetLayoutObject(),
            LayoutTreeBuilderTraversal::PreviousSiblingLayoutObject(*inner));

  EXPECT_EQ(last->GetLayoutObject(),
            LayoutTreeBuilderTraversal::NextSiblingLayoutObject(*inner));
  EXPECT_EQ(inner->GetLayoutObject(),
            LayoutTreeBuilderTraversal::PreviousSiblingLayoutObject(*last));
}

TEST_F(LayoutTreeBuilderTraversalTest, displayContentsChildrenNested) {
  const char* const kHtml =
      "<div></div>"
      "<div style='display: contents'>"
      "<div style='display: contents'>"
      "<div id='inner'></div>"
      "<div id='inner-sibling'></div>"
      "</div>"
      "</div>"
      "<div id='last'></div>";
  SetupSampleHTML(kHtml);

  Element* first = GetDocument().QuerySelector(AtomicString("div"));
  Element* inner = GetDocument().QuerySelector(AtomicString("#inner"));
  Element* sibling =
      GetDocument().QuerySelector(AtomicString("#inner-sibling"));
  Element* last = GetDocument().QuerySelector(AtomicString("#last"));

  EXPECT_TRUE(first->GetLayoutObject());
  EXPECT_TRUE(inner->GetLayoutObject());
  EXPECT_TRUE(sibling->GetLayoutObject());
  EXPECT_TRUE(last->GetLayoutObject());

  EXPECT_EQ(inner->GetLayoutObject(),
            LayoutTreeBuilderTraversal::NextSiblingLayoutObject(*first));
  EXPECT_EQ(first->GetLayoutObject(),
            LayoutTreeBuilderTraversal::PreviousSiblingLayoutObject(*inner));

  EXPECT_EQ(sibling->GetLayoutObject(),
            LayoutTreeBuilderTraversal::NextSiblingLayoutObject(*inner));
  EXPECT_EQ(inner->GetLayoutObject(),
            LayoutTreeBuilderTraversal::PreviousSiblingLayoutObject(*sibling));

  EXPECT_EQ(last->GetLayoutObject(),
            LayoutTreeBuilderTraversal::NextSiblingLayoutObject(*sibling));
  EXPECT_EQ(sibling->GetLayoutObject(),
            LayoutTreeBuilderTraversal::PreviousSiblingLayoutObject(*last));
}

TEST_F(LayoutTreeBuilderTraversalTest, limits) {
  const char* const kHtml =
      "<div></div>"
      "<div style='display: contents'></div>"
      "<div style='display: contents'>"
      "<div style='display: contents'>"
      "</div>"
      "</div>"
      "<div id='shouldNotBeFound'></div>";

  SetupSampleHTML(kHtml);

  Element* first = GetDocument().QuerySelector(AtomicString("div"));

  EXPECT_TRUE(first->GetLayoutObject());
  LayoutObject* next_sibling =
      LayoutTreeBuilderTraversal::NextSiblingLayoutObject(*first, 2);
  EXPECT_FALSE(next_sibling);  // Should not overrecurse
}

TEST_F(LayoutTreeBuilderTraversalTest, ColumnScrollMarkers) {
  SetupSampleHTML(R"(
      <style>
        #test {
          overflow: hidden;
          scroll-marker-group: before;
          columns: 1;
          height: 100px;
          width: 100px;
        }
        #test::scroll-marker-group {
          content: 'smg';
          display: flex;
          height: 100px;
          width: 100px;
        }
        #test::marker {
          content: 'm';
        }
        #test::column::scroll-marker {
          content: 'csm';
          height: 100px;
          width: 30px;
        }
        #test::before {
          content: 'b';
        }
        #test div {
          height: 100px;
          width: 100px;
        }
      </style>
      <li id='test'>
        <div></div>
        <div></div>
      </li>
      )");
  UpdateAllLifecyclePhasesForTest();

  Element* body = GetDocument().body();
  Element* test = body->QuerySelector(AtomicString("#test"));
  PseudoElement* before = test->GetPseudoElement(kPseudoIdBefore);
  PseudoElement* marker = test->GetPseudoElement(kPseudoIdMarker);
  PseudoElement* scroll_marker_group =
      test->GetPseudoElement(kPseudoIdScrollMarkerGroupBefore);
  PseudoElement* first_column = test->GetColumnPseudoElements()->front();
  PseudoElement* first_column_scroll_marker =
      first_column->GetPseudoElement(kPseudoIdScrollMarker);
  PseudoElement* second_column = test->GetColumnPseudoElements()->at(1u);
  PseudoElement* second_column_scroll_marker =
      second_column->GetPseudoElement(kPseudoIdScrollMarker);
  PseudoElement* third_column = test->GetColumnPseudoElements()->back();
  PseudoElement* third_column_scroll_marker =
      third_column->GetPseudoElement(kPseudoIdScrollMarker);
  EXPECT_EQ(test->GetColumnPseudoElements()->size(), 3u);

  EXPECT_EQ(scroll_marker_group, LayoutTreeBuilderTraversal::FirstChild(*test));
  EXPECT_EQ(marker,
            LayoutTreeBuilderTraversal::Next(*scroll_marker_group, nullptr));
  EXPECT_EQ(first_column, LayoutTreeBuilderTraversal::Next(*marker, nullptr));
  EXPECT_EQ(first_column_scroll_marker,
            LayoutTreeBuilderTraversal::Next(*first_column, nullptr));
  EXPECT_EQ(second_column, LayoutTreeBuilderTraversal::Next(
                               *first_column_scroll_marker, nullptr));
  EXPECT_EQ(second_column_scroll_marker,
            LayoutTreeBuilderTraversal::Next(*second_column, nullptr));
  EXPECT_EQ(third_column, LayoutTreeBuilderTraversal::Next(
                              *second_column_scroll_marker, nullptr));
  EXPECT_EQ(third_column_scroll_marker,
            LayoutTreeBuilderTraversal::Next(*third_column, nullptr));
  EXPECT_EQ(before, LayoutTreeBuilderTraversal::Next(
                        *third_column_scroll_marker, nullptr));

  EXPECT_EQ(third_column_scroll_marker,
            LayoutTreeBuilderTraversal::Previous(*before, nullptr));
  EXPECT_EQ(third_column, LayoutTreeBuilderTraversal::Previous(
                              *third_column_scroll_marker, nullptr));
  EXPECT_EQ(second_column_scroll_marker,
            LayoutTreeBuilderTraversal::Previous(*third_column, nullptr));
  EXPECT_EQ(second_column, LayoutTreeBuilderTraversal::Previous(
                               *second_column_scroll_marker, nullptr));
  EXPECT_EQ(first_column_scroll_marker,
            LayoutTreeBuilderTraversal::Previous(*second_column, nullptr));
  EXPECT_EQ(first_column, LayoutTreeBuilderTraversal::Previous(
                              *first_column_scroll_marker, nullptr));
  EXPECT_EQ(marker,
            LayoutTreeBuilderTraversal::Previous(*first_column, nullptr));
  EXPECT_EQ(scroll_marker_group,
            LayoutTreeBuilderTraversal::Previous(*marker, nullptr));
}

}  // namespace blink

"""

```