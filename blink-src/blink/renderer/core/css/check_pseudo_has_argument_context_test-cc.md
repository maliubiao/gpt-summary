Response:
The user wants me to analyze a C++ source code file related to CSS selectors in the Chromium Blink engine.

Here's a breakdown of the requested information and how to approach it:

1. **Functionality:**  The file name `check_pseudo_has_argument_context_test.cc` strongly suggests it's a unit test file. The `#include` directives confirm this by including `gtest/gtest.h`. The core functionality is likely testing the logic within `check_pseudo_has_argument_context.h`. This class probably determines the context in which the argument of the `:has()` CSS pseudo-class is evaluated.

2. **Relationship to JavaScript, HTML, CSS:**
    * **CSS:**  Directly related. The `:has()` pseudo-class is a CSS feature that allows selecting elements based on whether they have descendants matching a given selector. This file tests the implementation of this feature.
    * **HTML:** Indirectly related. The CSS selectors operate on the HTML structure of a document. The tests will likely involve creating HTML structures to verify the correctness of the `:has()` implementation.
    * **JavaScript:** Indirectly related. While this specific file is C++, the correct functioning of `:has()` impacts how CSS selectors work, which can be used in JavaScript for tasks like querying the DOM (e.g., `querySelectorAll`).

3. **Logical Reasoning (Assumptions, Inputs, Outputs):** The test file uses the Google Test framework. The `TEST_F` macros define individual test cases. The `TestArgumentContext` and `TestTraversalIteratorSteps` functions are helper functions within the test fixture.
    * **Assumption:** The core logic being tested is within the `CheckPseudoHasArgumentContext` class.
    * **Input:** CSS selector strings (e.g., `:has(.a)`, `:has(> .b)`).
    * **Output:**  The tests verify properties of the `CheckPseudoHasArgumentContext`, such as the leftmost relation, adjacent distance limit, depth limit, traversal scope, and whether to match in the shadow tree. The iterator tests verify the order and depth of traversal within the DOM based on the `:has()` selector.

4. **Common User/Programming Errors:**
    * **Incorrect CSS Syntax in `:has()`:** Users might write invalid selectors within the `:has()` pseudo-class, which the engine needs to handle correctly (potentially by not matching or throwing an error, although this test focuses on correct parsing and context).
    * **Misunderstanding `:has()` Scope:** Users might incorrectly assume the `:has()` selector operates in a way it doesn't (e.g., thinking it checks for ancestors instead of descendants).
    * **Performance Issues with Complex `:has()` Selectors:**  While not directly tested here, complex `:has()` selectors can be computationally expensive.

5. **User Operation to Reach Here (Debugging Clues):**
    * A web developer writes CSS using the `:has()` pseudo-class.
    * The browser's rendering engine (Blink in this case) processes the CSS.
    * If there's a bug in how `:has()` is implemented, it might lead to incorrect styling or behavior.
    * A developer investigating the issue might look at the Blink rendering engine source code, specifically the CSS selector matching logic, and might find this test file related to the `:has()` implementation. They might run these tests to understand if the basic logic is correct or to reproduce and debug a specific failure.

6. **Summary of Functionality (Part 1):** This C++ test file for the Blink rendering engine verifies the correct extraction of context information from the argument of the `:has()` CSS pseudo-class. It checks properties like the type of relationship within the `:has()` argument, depth and adjacency limits, and the scope of the search. It also tests the traversal order of elements when using `:has()`, ensuring the correct elements are visited during selector matching.

Now, let's generate the detailed answer incorporating these points.
这是文件 `blink/renderer/core/css/check_pseudo_has_argument_context_test.cc` 的功能概述：

**主要功能:**

这个文件包含了针对 `CheckPseudoHasArgumentContext` 类的单元测试。`CheckPseudoHasArgumentContext` 类（其定义在 `blink/renderer/core/css/check_pseudo_has_argument_context.h` 中）的主要目的是**分析 CSS `:has()` 伪类的参数选择器，并确定在选择器匹配过程中需要进行的 DOM 树遍历的范围和限制。** 换句话说，它负责理解 `:has()` 内部的选择器，并为后续的匹配操作提供必要的上下文信息。

**与 JavaScript, HTML, CSS 的关系:**

这个文件直接关联到 **CSS** 的功能，特别是 `:has()` 伪类。

* **CSS:** `:has()` 伪类允许你选择符合特定条件的父元素，这些条件是它包含匹配特定选择器的子元素。例如，`div:has(p.highlight)` 会选择所有包含类名为 `highlight` 的 `<p>` 元素的 `<div>` 元素。这个测试文件验证了 Blink 引擎如何理解和处理 `:has()` 伪类内部的参数选择器。

* **HTML:**  `:has()` 伪类操作的对象是 HTML 结构（DOM 树）。测试用例会创建虚拟的 HTML 结构，然后验证 `:has()` 伪类是否能够正确地根据其参数选择器在这些结构中进行匹配。

* **JavaScript:**  虽然这个文件是 C++ 代码，属于 Blink 引擎的实现细节，但 `:has()` 伪类的正确实现会影响到 JavaScript 中使用 CSS 选择器的 API (例如 `querySelectorAll`) 的行为。如果 `:has()` 的实现有误，JavaScript 中使用相关选择器的结果也会不正确。

**逻辑推理 (假设输入与输出):**

文件中的 `TestArgumentContext` 函数用于测试 `CheckPseudoHasArgumentContext` 类对 `:has()` 伪类参数的解析。

* **假设输入 (selector_text):** 各种不同的 `:has()` 伪类选择器字符串，例如：
    * `:has(.a)`
    * `:has(.a ~ .b)`
    * `:has(> .a)`
    * `:has(+ .a .b)`

* **预期输出:** 对于每个输入的 CSS 选择器，测试会验证 `CheckPseudoHasArgumentContext` 对象计算出的以下属性：
    * `expected_leftmost_relation`:  参数选择器最左侧的关系符类型（例如，后代选择器、子选择器、相邻兄弟选择器）。
    * `expected_adjacent_distance_limit`: 相邻兄弟选择器的最大距离限制。
    * `expected_depth_limit`:  后代选择器的最大深度限制。
    * `expected_traversal_scope`:  遍历 DOM 树的范围（例如，子树、所有后续兄弟节点、仅下一个兄弟节点）。
    * `match_in_shadow_tree`: 是否需要在 Shadow DOM 树中进行匹配。

例如，对于输入 `:has(.a ~ .b)`，预期的输出可能是：

* `expected_leftmost_relation`: `CSSSelector::kRelativeDescendant` (因为 `.a ~ .b` 隐含了一个后代关系)
* `expected_adjacent_distance_limit`: `0` (后代选择器没有相邻距离限制)
* `expected_depth_limit`: `kDepthMax` (后代选择器深度无限制)
* `expected_traversal_scope`: `kSubtree` (需要在子树中查找)

文件中的 `TestTraversalIteratorSteps` 函数用于测试在 `:has()` 上下文中，DOM 树的遍历迭代器的行为。

* **假设输入 (selector_text, HTML 结构):** 一个包含 `:has()` 伪类的 CSS 选择器和一个代表 DOM 树的 HTML 结构。

* **预期输出:**  对于给定的起始元素和 `:has()` 选择器，迭代器应该按照预期的顺序和深度遍历 DOM 树中的特定元素。测试会验证遍历到的元素的 ID 和深度是否与预期一致。

**涉及用户或者编程常见的使用错误 (举例说明):**

虽然这个测试文件本身不直接暴露用户或编程错误，但它所测试的功能与以下常见错误相关：

* **CSS 选择器语法错误:** 用户可能会在 `:has()` 内部编写无效的 CSS 选择器，例如 `:has((.a))`)。这个测试文件确保 Blink 引擎能够正确处理和分析合法的 `:has()` 选择器。
* **对 `:has()` 作用域的误解:** 用户可能错误地认为 `:has()` 会检查祖先元素，而不是后代元素。 例如，他们可能错误地认为 `p:has(div)` 会选择包含 `<p>` 元素的 `<div>` 元素。 这个测试文件通过验证遍历范围来确保 `:has()` 的行为符合规范。
* **性能问题:**  复杂的 `:has()` 选择器可能会导致性能问题，因为它们需要进行大量的 DOM 树遍历。虽然这个测试文件不直接测试性能，但它验证了遍历的正确性，这对于后续的性能优化至关重要。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写包含 `:has()` 的 CSS 样式规则。** 例如，用户可能写了 `body:has(.sidebar-open) main { margin-left: 250px; }`，希望在 `<body>` 元素包含类名为 `sidebar-open` 的子元素时，给 `main` 元素添加左边距。

2. **浏览器加载并解析 HTML 和 CSS。** Blink 引擎的 CSS 解析器会遇到 `:has()` 伪类。

3. **布局引擎需要确定哪些元素匹配这些样式规则。**  当引擎处理包含 `:has()` 的选择器时，会使用 `CheckPseudoHasArgumentContext` 类来分析 `:has()` 的参数选择器，并确定需要在 DOM 树中进行什么样的搜索。

4. **如果 `:has()` 的实现存在 bug，可能会导致样式规则没有正确应用。** 例如，如果 `CheckPseudoHasArgumentContext` 没有正确识别参数选择器中的关系符，可能导致遍历范围错误，从而匹配不到应该匹配的元素。

5. **开发者可能会使用浏览器的开发者工具检查元素的样式。** 如果样式没有按预期应用，开发者可能会查看“Computed”或“Styles”面板，发现相关的 `:has()` 选择器没有生效。

6. **为了调试这个问题，Blink 引擎的开发者可能会查看 `check_pseudo_has_argument_context_test.cc` 文件。**  他们可能会运行相关的测试用例，或者添加新的测试用例来重现和定位 bug。这个测试文件可以帮助他们验证 `CheckPseudoHasArgumentContext` 类是否正确地解析了各种 `:has()` 选择器，并生成了正确的遍历上下文信息。

**功能归纳 (第 1 部分):**

这个测试文件的主要功能是**验证 `CheckPseudoHasArgumentContext` 类能够正确地解析 CSS `:has()` 伪类的参数选择器，并提取出用于后续 DOM 树遍历和匹配的关键上下文信息。** 这包括确定参数选择器的关系类型、遍历的深度和范围，以及是否需要考虑 Shadow DOM。  它通过一系列单元测试，针对不同的 `:has()` 选择器场景，来确保 Blink 引擎对 `:has()` 伪类的理解和处理是正确的。

Prompt: 
```
这是目录为blink/renderer/core/css/check_pseudo_has_argument_context_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/css/check_pseudo_has_argument_context.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/css_selector_list.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"

namespace blink {

class CheckPseudoHasArgumentContextTest : public PageTestBase {
 protected:
  const int kDepthMax = CheckPseudoHasArgumentContext::kInfiniteDepth;
  const int kAdjacentMax =
      CheckPseudoHasArgumentContext::kInfiniteAdjacentDistance;

  void TestArgumentContext(
      const String& selector_text,
      CSSSelector::RelationType expected_leftmost_relation,
      int expected_adjacent_distance_limit,
      int expected_depth_limit,
      CheckPseudoHasArgumentTraversalScope expected_traversal_scope,
      bool match_in_shadow_tree = false) const {
    CSSSelectorList* selector_list =
        css_test_helpers::ParseSelectorList(selector_text);
    CheckPseudoHasArgumentContext context(
        selector_list->First()->SelectorList()->First(), match_in_shadow_tree);

    EXPECT_EQ(expected_leftmost_relation, context.LeftmostRelation())
        << "Failed : " << selector_text;
    EXPECT_EQ(expected_adjacent_distance_limit, context.AdjacentDistanceLimit())
        << "Failed : " << selector_text;
    EXPECT_EQ(expected_depth_limit, context.DepthLimit())
        << "Failed : " << selector_text;
    EXPECT_EQ(expected_traversal_scope, context.TraversalScope())
        << "Failed : " << selector_text;
    EXPECT_EQ(match_in_shadow_tree, context.MatchInShadowTree())
        << "Failed : " << selector_text;
  }

  struct ExpectedTraversalStep {
    const char* element_id;
    int depth;
  };

  void TestTraversalIteratorForEmptyRange(
      Document* document,
      const char* has_anchor_element_id,
      const char* selector_text,
      bool match_in_shadow_tree = false) const {
    Element* has_anchor_element =
        document->getElementById(AtomicString(has_anchor_element_id));
    if (!has_anchor_element) {
      ADD_FAILURE() << "Failed : test iterator on #" << has_anchor_element_id
                    << " (Cannot find element)";
      return;
    }

    unsigned i = 0;
    CSSSelectorList* selector_list =
        css_test_helpers::ParseSelectorList(selector_text);
    CheckPseudoHasArgumentContext argument_context(
        selector_list->First()->SelectorList()->First(), match_in_shadow_tree);
    for (CheckPseudoHasArgumentTraversalIterator iterator(*has_anchor_element,
                                                          argument_context);
         !iterator.AtEnd(); ++iterator, ++i) {
      AtomicString current_element_id =
          iterator.CurrentElement()
              ? iterator.CurrentElement()->GetIdAttribute()
              : g_null_atom;
      int current_depth = iterator.CurrentDepth();
      ADD_FAILURE() << "Iteration failed : exceeded expected iteration"
                    << " (selector: " << selector_text
                    << ", has_anchor_element: #" << has_anchor_element_id
                    << ", index: " << i
                    << ", current_element: " << current_element_id
                    << ", current_depth: " << current_depth << ")";
    }
  }

  CheckPseudoHasArgumentTraversalType GetTraversalType(
      const char* selector_text,
      bool match_in_shadow_tree = false) const {
    CSSSelectorList* selector_list =
        css_test_helpers::ParseSelectorList(selector_text);

    EXPECT_EQ(selector_list->First()->GetPseudoType(), CSSSelector::kPseudoHas);

    CheckPseudoHasArgumentContext context(
        selector_list->First()->SelectorList()->First(), match_in_shadow_tree);
    return context.TraversalType();
  }

  template <unsigned length>
  void TestTraversalIteratorSteps(
      Document* document,
      const char* has_anchor_element_id,
      const char* selector_text,
      const ExpectedTraversalStep (&expected_traversal_steps)[length],
      bool match_in_shadow_tree = false) const {
    Element* has_anchor_element =
        document->getElementById(AtomicString(has_anchor_element_id));
    if (!has_anchor_element) {
      ADD_FAILURE() << "Failed : test iterator on #" << has_anchor_element_id
                    << " (Cannot find element)";
      return;
    }
    EXPECT_EQ(has_anchor_element->GetIdAttribute(), has_anchor_element_id);

    unsigned i = 0;
    CSSSelectorList* selector_list =
        css_test_helpers::ParseSelectorList(selector_text);
    CheckPseudoHasArgumentContext argument_context(
        selector_list->First()->SelectorList()->First(), match_in_shadow_tree);
    for (CheckPseudoHasArgumentTraversalIterator iterator(*has_anchor_element,
                                                          argument_context);
         !iterator.AtEnd(); ++iterator, ++i) {
      AtomicString current_element_id =
          iterator.CurrentElement()
              ? iterator.CurrentElement()->GetIdAttribute()
              : g_null_atom;
      int current_depth = iterator.CurrentDepth();
      if (i >= length) {
        ADD_FAILURE() << "Iteration failed : exceeded expected iteration"
                      << " (selector: " << selector_text
                      << ", has_anchor_element: #" << has_anchor_element_id
                      << ", index: " << i
                      << ", current_element: " << current_element_id
                      << ", current_depth: " << current_depth << ")";
        continue;
      }
      EXPECT_EQ(expected_traversal_steps[i].element_id, current_element_id)
          << " (selector: " << selector_text << ", has_anchor_element: #"
          << has_anchor_element_id << ", index: " << i
          << ", expected: " << expected_traversal_steps[i].element_id
          << ", actual: " << current_element_id << ")";
      EXPECT_EQ(expected_traversal_steps[i].depth, current_depth)
          << " (selector: " << selector_text << ", has_anchor_element: #"
          << has_anchor_element_id << ", index: " << i
          << ", expected: " << expected_traversal_steps[i].depth
          << ", actual: " << current_depth << ")";
    }

    for (; i < length; i++) {
      ADD_FAILURE() << "Iteration failed : expected but not traversed"
                    << " (selector: " << selector_text
                    << ", has_anchor_element: #" << has_anchor_element_id
                    << ", index: " << i << ", expected_element: "
                    << expected_traversal_steps[i].element_id << ")";
      EXPECT_NE(document->getElementById(
                    AtomicString(expected_traversal_steps[i].element_id)),
                nullptr);
    }
  }
};

TEST_F(CheckPseudoHasArgumentContextTest, TestArgumentMatchContext) {
  TestArgumentContext(":has(.a)", CSSSelector::kRelativeDescendant,
                      /* expected_adjacent_distance_limit */ 0,
                      /* expected_depth_limit */ kDepthMax, kSubtree);
  TestArgumentContext(":has(.a ~ .b)", CSSSelector::kRelativeDescendant,
                      /* expected_adjacent_distance_limit */ 0,
                      /* expected_depth_limit */ kDepthMax, kSubtree);
  TestArgumentContext(":has(.a ~ .b > .c)", CSSSelector::kRelativeDescendant,
                      /* expected_adjacent_distance_limit */ 0,
                      /* expected_depth_limit */ kDepthMax, kSubtree);
  TestArgumentContext(":has(.a > .b)", CSSSelector::kRelativeDescendant,
                      /* expected_adjacent_distance_limit */ 0,
                      /* expected_depth_limit */ kDepthMax, kSubtree);
  TestArgumentContext(":has(.a + .b)", CSSSelector::kRelativeDescendant,
                      /* expected_adjacent_distance_limit */ 0,
                      /* expected_depth_limit */ kDepthMax, kSubtree);
  TestArgumentContext(":has(> .a .b)", CSSSelector::kRelativeChild,
                      /* expected_adjacent_distance_limit */ 0,
                      /* expected_depth_limit */ kDepthMax, kSubtree);
  TestArgumentContext(":has(> .a ~ .b .c)", CSSSelector::kRelativeChild,
                      /* expected_adjacent_distance_limit */ 0,
                      /* expected_depth_limit */ kDepthMax, kSubtree);
  TestArgumentContext(":has(> .a + .b .c)", CSSSelector::kRelativeChild,
                      /* expected_adjacent_distance_limit */ 0,
                      /* expected_depth_limit */ kDepthMax, kSubtree);
  TestArgumentContext(":has(> .a)", CSSSelector::kRelativeChild,
                      /* expected_adjacent_distance_limit */ 0,
                      /* expected_depth_limit */ 1, kFixedDepthDescendants);
  TestArgumentContext(":has(> .a > .b)", CSSSelector::kRelativeChild,
                      /* expected_adjacent_distance_limit */ 0,
                      /* expected_depth_limit */ 2, kFixedDepthDescendants);
  TestArgumentContext(":has(> .a + .b)", CSSSelector::kRelativeChild,
                      /* expected_adjacent_distance_limit */ 0,
                      /* expected_depth_limit */ 1, kFixedDepthDescendants);
  TestArgumentContext(":has(> .a ~ .b)", CSSSelector::kRelativeChild,
                      /* expected_adjacent_distance_limit */ 0,
                      /* expected_depth_limit */ 1, kFixedDepthDescendants);
  TestArgumentContext(":has(> .a ~ .b > .c)", CSSSelector::kRelativeChild,
                      /* expected_adjacent_distance_limit */ 0,
                      /* expected_depth_limit */ 2, kFixedDepthDescendants);
  TestArgumentContext(":has(~ .a .b)", CSSSelector::kRelativeIndirectAdjacent,
                      /* expected_adjacent_distance_limit */ kAdjacentMax,
                      /* expected_depth_limit */ kDepthMax,
                      kAllNextSiblingSubtrees);
  TestArgumentContext(
      ":has(~ .a + .b > .c ~ .d .e)", CSSSelector::kRelativeIndirectAdjacent,
      /* expected_adjacent_distance_limit */ kAdjacentMax,
      /* expected_depth_limit */ kDepthMax, kAllNextSiblingSubtrees);
  TestArgumentContext(":has(~ .a)", CSSSelector::kRelativeIndirectAdjacent,
                      /* expected_adjacent_distance_limit */ kAdjacentMax,
                      /* expected_depth_limit */ 0, kAllNextSiblings);
  TestArgumentContext(":has(~ .a ~ .b)", CSSSelector::kRelativeIndirectAdjacent,
                      /* expected_adjacent_distance_limit */ kAdjacentMax,
                      /* expected_depth_limit */ 0, kAllNextSiblings);
  TestArgumentContext(":has(~ .a + .b)", CSSSelector::kRelativeIndirectAdjacent,
                      /* expected_adjacent_distance_limit */ kAdjacentMax,
                      /* expected_depth_limit */ 0, kAllNextSiblings);
  TestArgumentContext(":has(~ .a + .b ~ .c)",
                      CSSSelector::kRelativeIndirectAdjacent,
                      /* expected_adjacent_distance_limit */ kAdjacentMax,
                      /* expected_depth_limit */ 0, kAllNextSiblings);
  TestArgumentContext(":has(~ .a > .b)", CSSSelector::kRelativeIndirectAdjacent,
                      /* expected_adjacent_distance_limit */ kAdjacentMax,
                      /* expected_depth_limit */ 1,
                      kAllNextSiblingsFixedDepthDescendants);
  TestArgumentContext(
      ":has(~ .a + .b > .c ~ .d > .e)", CSSSelector::kRelativeIndirectAdjacent,
      /* expected_adjacent_distance_limit */ kAdjacentMax,
      /* expected_depth_limit */ 2, kAllNextSiblingsFixedDepthDescendants);
  TestArgumentContext(
      ":has(+ .a ~ .b .c)", CSSSelector::kRelativeDirectAdjacent,
      /* expected_adjacent_distance_limit */ kAdjacentMax,
      /* expected_depth_limit */ kDepthMax, kAllNextSiblingSubtrees);
  TestArgumentContext(
      ":has(+ .a ~ .b > .c + .d .e)", CSSSelector::kRelativeDirectAdjacent,
      /* expected_adjacent_distance_limit */ kAdjacentMax,
      /* expected_depth_limit */ kDepthMax, kAllNextSiblingSubtrees);
  TestArgumentContext(":has(+ .a ~ .b)", CSSSelector::kRelativeDirectAdjacent,
                      /* expected_adjacent_distance_limit */ kAdjacentMax,
                      /* expected_depth_limit */ 0, kAllNextSiblings);
  TestArgumentContext(":has(+ .a + .b ~ .c)",
                      CSSSelector::kRelativeDirectAdjacent,
                      /* expected_adjacent_distance_limit */ kAdjacentMax,
                      /* expected_depth_limit */ 0, kAllNextSiblings);
  TestArgumentContext(
      ":has(+ .a ~ .b > .c)", CSSSelector::kRelativeDirectAdjacent,
      /* expected_adjacent_distance_limit */ kAdjacentMax,
      /* expected_depth_limit */ 1, kAllNextSiblingsFixedDepthDescendants);
  TestArgumentContext(
      ":has(+ .a ~ .b > .c + .d > .e)", CSSSelector::kRelativeDirectAdjacent,
      /* expected_adjacent_distance_limit */ kAdjacentMax,
      /* expected_depth_limit */ 2, kAllNextSiblingsFixedDepthDescendants);
  TestArgumentContext(":has(+ .a .b)", CSSSelector::kRelativeDirectAdjacent,
                      /* expected_adjacent_distance_limit */ 1,
                      /* expected_depth_limit */ kDepthMax,
                      kOneNextSiblingSubtree);
  TestArgumentContext(
      ":has(+ .a > .b .c)", CSSSelector::kRelativeDirectAdjacent,
      /* expected_adjacent_distance_limit */ 1,
      /* expected_depth_limit */ kDepthMax, kOneNextSiblingSubtree);
  TestArgumentContext(
      ":has(+ .a .b > .c)", CSSSelector::kRelativeDirectAdjacent,
      /* expected_adjacent_distance_limit */ 1,
      /* expected_depth_limit */ kDepthMax, kOneNextSiblingSubtree);
  TestArgumentContext(
      ":has(+ .a .b ~ .c)", CSSSelector::kRelativeDirectAdjacent,
      /* expected_adjacent_distance_limit */ 1,
      /* expected_depth_limit */ kDepthMax, kOneNextSiblingSubtree);
  TestArgumentContext(
      ":has(+ .a + .b .c)", CSSSelector::kRelativeDirectAdjacent,
      /* expected_adjacent_distance_limit */ 2,
      /* expected_depth_limit */ kDepthMax, kOneNextSiblingSubtree);
  TestArgumentContext(
      ":has(+ .a > .b + .c .d)", CSSSelector::kRelativeDirectAdjacent,
      /* expected_adjacent_distance_limit */ 1,
      /* expected_depth_limit */ kDepthMax, kOneNextSiblingSubtree);
  TestArgumentContext(
      ":has(+ .a + .b > .c .d)", CSSSelector::kRelativeDirectAdjacent,
      /* expected_adjacent_distance_limit */ 2,
      /* expected_depth_limit */ kDepthMax, kOneNextSiblingSubtree);
  TestArgumentContext(":has(+ .a)", CSSSelector::kRelativeDirectAdjacent,
                      /* expected_adjacent_distance_limit */ 1,
                      /* expected_depth_limit */ 0, kOneNextSibling);
  TestArgumentContext(":has(+ .a + .b)", CSSSelector::kRelativeDirectAdjacent,
                      /* expected_adjacent_distance_limit */ 2,
                      /* expected_depth_limit */ 0, kOneNextSibling);
  TestArgumentContext(":has(+ .a + .b + .c)",
                      CSSSelector::kRelativeDirectAdjacent,
                      /* expected_adjacent_distance_limit */ 3,
                      /* expected_depth_limit */ 0, kOneNextSibling);
  TestArgumentContext(":has(+ .a > .b)", CSSSelector::kRelativeDirectAdjacent,
                      /* expected_adjacent_distance_limit */ 1,
                      /* expected_depth_limit */ 1,
                      kOneNextSiblingFixedDepthDescendants);
  TestArgumentContext(
      ":has(+ .a > .b ~ .c)", CSSSelector::kRelativeDirectAdjacent,
      /* expected_adjacent_distance_limit */ 1,
      /* expected_depth_limit */ 1, kOneNextSiblingFixedDepthDescendants);
  TestArgumentContext(
      ":has(+ .a + .b > .c ~ .d > .e)", CSSSelector::kRelativeDirectAdjacent,
      /* expected_adjacent_distance_limit */ 2,
      /* expected_depth_limit */ 2, kOneNextSiblingFixedDepthDescendants);
  TestArgumentContext(":has(.a)", CSSSelector::kRelativeDescendant,
                      /* expected_adjacent_distance_limit */ 0,
                      /* expected_depth_limit */ kDepthMax, kShadowRootSubtree,
                      /* match_in_shadow_tree */ true);
  TestArgumentContext(":has(~ .a)", CSSSelector::kRelativeIndirectAdjacent,
                      /* expected_adjacent_distance_limit */ kAdjacentMax,
                      /* expected_depth_limit */ 0,
                      kInvalidShadowRootTraversalScope,
                      /* match_in_shadow_tree */ true);
  TestArgumentContext(":has(+ .a .b)", CSSSelector::kRelativeDirectAdjacent,
                      /* expected_adjacent_distance_limit */ 1,
                      /* expected_depth_limit */ kDepthMax,
                      kInvalidShadowRootTraversalScope,
                      /* match_in_shadow_tree */ true);
  TestArgumentContext(":has(~ .a .b)", CSSSelector::kRelativeIndirectAdjacent,
                      /* expected_adjacent_distance_limit */ kAdjacentMax,
                      /* expected_depth_limit */ kDepthMax,
                      kInvalidShadowRootTraversalScope,
                      /* match_in_shadow_tree */ true);
  TestArgumentContext(":has(+ .a)", CSSSelector::kRelativeDirectAdjacent,
                      /* expected_adjacent_distance_limit */ 1,
                      /* expected_depth_limit */ 0,
                      kInvalidShadowRootTraversalScope,
                      /* match_in_shadow_tree */ true);
  TestArgumentContext(":has(> .a)", CSSSelector::kRelativeChild,
                      /* expected_adjacent_distance_limit */ 0,
                      /* expected_depth_limit */ 1,
                      kShadowRootFixedDepthDescendants,
                      /* match_in_shadow_tree */ true);
  TestArgumentContext(":has(+ .a > .b)", CSSSelector::kRelativeDirectAdjacent,
                      /* expected_adjacent_distance_limit */ 1,
                      /* expected_depth_limit */ 1,
                      kInvalidShadowRootTraversalScope,
                      /* match_in_shadow_tree */ true);
  TestArgumentContext(":has(~ .a > .b)", CSSSelector::kRelativeIndirectAdjacent,
                      /* expected_adjacent_distance_limit */ kAdjacentMax,
                      /* expected_depth_limit */ 1,
                      kInvalidShadowRootTraversalScope,
                      /* match_in_shadow_tree */ true);
}

TEST_F(CheckPseudoHasArgumentContextTest, TestTraversalType) {
  CheckPseudoHasArgumentTraversalType traversal_type;

  // traversal scope: kSubtree
  // adjacent distance: 0
  // depth: Max
  traversal_type = GetTraversalType(":has(.a)");
  EXPECT_EQ(traversal_type, 0x00003fffu);
  EXPECT_EQ(GetTraversalType(":has(.a ~ .b)"), traversal_type);
  EXPECT_EQ(GetTraversalType(":has(.a ~ .b > .c)"), traversal_type);
  EXPECT_EQ(GetTraversalType(":has(.a > .b)"), traversal_type);
  EXPECT_EQ(GetTraversalType(":has(.a + .b)"), traversal_type);
  EXPECT_EQ(GetTraversalType(":has(> .a .b)"), traversal_type);
  EXPECT_EQ(GetTraversalType(":has(> .a ~ .b .c)"), traversal_type);
  EXPECT_EQ(GetTraversalType(":has(> .a + .b .c)"), traversal_type);

  // traversal scope: kAllNextSiblings
  // adjacent distance: Max
  // depth: 0
  traversal_type = GetTraversalType(":has(~ .a)");
  EXPECT_EQ(traversal_type, 0x1fffc000u);
  EXPECT_EQ(GetTraversalType(":has(~ .a ~ .b)"), traversal_type);
  EXPECT_EQ(GetTraversalType(":has(~ .a + .b)"), traversal_type);
  EXPECT_EQ(GetTraversalType(":has(~ .a + .b ~ .c)"), traversal_type);
  EXPECT_EQ(GetTraversalType(":has(+ .a ~ .b)"), traversal_type);
  EXPECT_EQ(GetTraversalType(":has(+ .a + .b ~ .c)"), traversal_type);

  // traversal scope: kOneNextSiblingSubtree
  // adjacent distance: 1
  // depth: Max
  traversal_type = GetTraversalType(":has(+ .a .b)");
  EXPECT_EQ(traversal_type, 0x20007fffu);
  EXPECT_EQ(GetTraversalType(":has(+ .a > .b .c)"), traversal_type);
  EXPECT_EQ(GetTraversalType(":has(+ .a .b > .c)"), traversal_type);
  EXPECT_EQ(GetTraversalType(":has(+ .a .b ~ .c)"), traversal_type);
  EXPECT_EQ(GetTraversalType(":has(+ .a > .b + .c .d)"), traversal_type);

  // traversal scope: kOneNextSiblingSubtree
  // adjacent distance: 2
  // depth: Max
  traversal_type = GetTraversalType(":has(+ .a + .b .c)");
  EXPECT_EQ(traversal_type, 0x2000bfffu);
  EXPECT_EQ(GetTraversalType(":has(+ .a + .b > .c .d)"), traversal_type);

  // traversal scope: kAllNextSiblingSubtrees
  // adjacent distance: Max
  // depth: Max
  traversal_type = GetTraversalType(":has(~ .a .b)");
  EXPECT_EQ(traversal_type, 0x3fffffffu);
  EXPECT_EQ(GetTraversalType(":has(~ .a + .b > .c ~ .d .e)"), traversal_type);
  EXPECT_EQ(GetTraversalType(":has(+ .a ~ .b .c)"), traversal_type);
  EXPECT_EQ(GetTraversalType(":has(+ .a ~ .b > .c + .d .e)"), traversal_type);

  // traversal scope: kOneNextSibling
  // adjacent distance: 1
  // depth: 0
  traversal_type = GetTraversalType(":has(+ .a)");
  EXPECT_EQ(traversal_type, 0x40004000u);

  // traversal scope: kOneNextSibling
  // adjacent distance: 2
  // depth: 0
  traversal_type = GetTraversalType(":has(+ .a + .b)");
  EXPECT_EQ(traversal_type, 0x40008000u);

  // traversal scope: kOneNextSibling
  // adjacent distance: 3
  // depth: 0
  traversal_type = GetTraversalType(":has(+ .a + .b + .c)");
  EXPECT_EQ(traversal_type, 0x4000c000u);

  // traversal scope: kFixedDepthDescendants
  // adjacent distance: 0
  // depth: 1
  traversal_type = GetTraversalType(":has(> .a)");
  EXPECT_EQ(traversal_type, 0x50000001u);
  EXPECT_EQ(GetTraversalType(":has(> .a + .b)"), traversal_type);
  EXPECT_EQ(GetTraversalType(":has(> .a ~ .b)"), traversal_type);

  // traversal scope: kFixedDepthDescendants
  // adjacent distance: 0
  // depth: 2
  traversal_type = GetTraversalType(":has(> .a > .b)");
  EXPECT_EQ(traversal_type, 0x50000002u);
  EXPECT_EQ(GetTraversalType(":has(> .a ~ .b > .c)"), traversal_type);

  // traversal scope: kOneNextSiblingFixedDepthDescendants
  // adjacent distance: 1
  // depth: 1
  traversal_type = GetTraversalType(":has(+ .a > .b)");
  EXPECT_EQ(traversal_type, 0x60004001u);
  EXPECT_EQ(GetTraversalType(":has(+ .a > .b ~ .c)"), traversal_type);

  // traversal scope: kOneNextSiblingFixedDepthDescendants
  // adjacent distance: 2
  // depth: 2
  traversal_type = GetTraversalType(":has(+ .a + .b > .c ~ .d > .e)");
  EXPECT_EQ(traversal_type, 0x60008002u);
  EXPECT_EQ(GetTraversalType(":has(+ .a + .b > .c ~ .d > .e ~ .f)"),
            traversal_type);

  // traversal scope: kAllNextSiblingsFixedDepthDescendants
  // adjacent distance: Max
  // depth: 1
  traversal_type = GetTraversalType(":has(~ .a > .b)");
  EXPECT_EQ(traversal_type, 0x7fffc001u);
  EXPECT_EQ(GetTraversalType(":has(+ .a ~ .b > .c)"), traversal_type);

  // traversal scope: kAllNextSiblingsFixedDepthDescendants
  // adjacent distance: Max
  // depth: 2
  traversal_type = GetTraversalType(":has(~ .a > .b > .c)");
  EXPECT_EQ(traversal_type, 0x7fffc002u);
  EXPECT_EQ(GetTraversalType(":has(+ .a ~ .b > .c + .d > .e)"), traversal_type);

  // traversal scope: kShadowRootSubtree
  // adjacent distance: 0
  // depth: Max
  traversal_type = GetTraversalType(":has(.a)",
                                    /* match_in_shadow_tree */ true);
  EXPECT_EQ(traversal_type, 0x80003fffu);

  // traversal scope: kInvalidShadowRootTraversalScope
  // adjacent distance: Max
  // depth: 0
  traversal_type = GetTraversalType(":has(~ .a)",
                                    /* match_in_shadow_tree */ true);
  EXPECT_EQ(traversal_type, 0xafffc000u);

  // traversal scope: kInvalidShadowRootTraversalScope
  // adjacent distance: 1
  // depth: Max
  traversal_type = GetTraversalType(":has(+ .a .b)",
                                    /* match_in_shadow_tree */ true);
  EXPECT_EQ(traversal_type, 0xa0007fffu);

  // traversal scope: kInvalidShadowRootTraversalScope
  // adjacent distance: Max
  // depth: Max
  traversal_type = GetTraversalType(":has(~ .a .b)",
                                    /* match_in_shadow_tree */ true);
  EXPECT_EQ(traversal_type, 0xafffffffu);

  // traversal scope: kInvalidShadowRootTraversalScope
  // adjacent distance: 1
  // depth: 0
  traversal_type = GetTraversalType(":has(+ .a)",
                                    /* match_in_shadow_tree */ true);
  EXPECT_EQ(traversal_type, 0xa0004000u);

  // traversal scope: kShadowRootFixedDepthDescendants
  // adjacent distance: 0
  // depth: 1
  traversal_type = GetTraversalType(":has(> .a)",
                                    /* match_in_shadow_tree */ true);
  EXPECT_EQ(traversal_type, 0x90000001u);

  // traversal scope: kInvalidShadowRootTraversalScope
  // adjacent distance: 1
  // depth: 1
  traversal_type = GetTraversalType(":has(+ .a > .b)",
                                    /* match_in_shadow_tree */ true);
  EXPECT_EQ(traversal_type, 0xa0004001u);

  // traversal scope: kInvalidShadowRootTraversalScope
  // adjacent distance: Max
  // depth: 1
  traversal_type = GetTraversalType(":has(~ .a > .b)",
                                    /* match_in_shadow_tree */ true);
  EXPECT_EQ(traversal_type, 0xafffc001u);
}

TEST_F(CheckPseudoHasArgumentContextTest, TestTraversalIteratorCase1) {
  // CheckPseudoHasArgumentTraversalScope::kSubtree

  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write(R"HTML(
    <!DOCTYPE html>
    <main id=main>
      <div id=div1>
        <div id=div11>
          <div id=div111></div>
        </div>
        <div id=div12>
          <div id=div121></div>
          <div id=div122>
            <div id=div1221></div>
            <div id=div1222></div>
            <div id=div1223></div>
          </div>
          <div id=div123></div>
        </div>
        <div id=div13></div>
      </div>
    </main>
  )HTML");

  TestTraversalIteratorSteps(document, "div1", ":has(.a)",
                             {{"div13", /* depth */ 1},
                              {"div123", /* depth */ 2},
                              {"div1223", /* depth */ 3},
                              {"div1222", /* depth */ 3},
                              {"div1221", /* depth */ 3},
                              {"div122", /* depth */ 2},
                              {"div121", /* depth */ 2},
                              {"div12", /* depth */ 1},
                              {"div111", /* depth */ 2},
                              {"div11", /* depth */ 1}});

  TestTraversalIteratorSteps(document, "div12", ":has(.a)",
                             {{"div123", /* depth */ 1},
                              {"div1223", /* depth */ 2},
                              {"div1222", /* depth */ 2},
                              {"div1221", /* depth */ 2},
                              {"div122", /* depth */ 1},
                              {"div121", /* depth */ 1}});

  TestTraversalIteratorSteps(document, "div122", ":has(.a)",
                             {{"div1223", /* depth */ 1},
                              {"div1222", /* depth */ 1},
                              {"div1221", /* depth */ 1}});

  TestTraversalIteratorSteps(document, "div11", ":has(.a)",
                             {{"div111", /* depth */ 1}});

  TestTraversalIteratorForEmptyRange(document, "div111", ":has(.a)");
}

TEST_F(CheckPseudoHasArgumentContextTest, TestTraversalIteratorCase2) {
  // CheckPseudoHasArgumentTraversalScope::kAllNextSiblings

  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write(R"HTML(
    <!DOCTYPE html>
    <main id=main>
      <div id=div1>
        <div id=div11></div>
      </div>
      <div id=div2>
        <div id=div21></div>
      </div>
      <div id=div3>
        <div id=div31></div>
      </div>
      <div id=div4>
        <div id=div41></div>
      </div>
    </main>
  )HTML");

  TestTraversalIteratorSteps(document, "div1", ":has(~ .a)",
                             {{"div4", /* depth */ 0},
                              {"div3", /* depth */ 0},
                              {"div2", /* depth */ 0}});

  TestTraversalIteratorSteps(document, "div3", ":has(~ .a)",
                             {{"div4", /* depth */ 0}});

  TestTraversalIteratorForEmptyRange(document, "div4", ":has(~ .a)");
}

TEST_F(CheckPseudoHasArgumentContextTest, TestTraversalIteratorCase3) {
  // CheckPseudoHasArgumentTraversalScope::kOneNextSiblingSubtree

  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write(R"HTML(
    <!DOCTYPE html>
    <main id=main>
      <div id=div1>
        <div id=div11></div>
      </div>
      <div id=div2>
        <div id=div21></div>
      </div>
      <div id=div3>
        <div id=div31>
          <div id=div311></div>
        </div>
        <div id=div32>
          <div id=div321></div>
        </div>
        <div id=div33></div>
        <div id=div34>
          <div id=div341>
            <div id=div3411></div>
          </div>
        </div>
      </div>
      <div id=div4>
        <div id=div41></div>
      </div>
    </main>
  )HTML");

  TestTraversalIteratorSteps(document, "div1", ":has(+ .a + .b .c)",
                             {{"div3411", /* depth */ 3},
                              {"div341", /* depth */ 2},
                              {"div34", /* depth */ 1},
                              {"div33", /* depth */ 1},
                              {"div321", /* depth */ 2},
                              {"div32", /* depth */ 1},
                              {"div311", /* depth */ 2},
                              {"div31", /* depth */ 1},
                              {"div3", /* depth */ 0},
                              {"div2", /* depth */ 0}});

  TestTraversalIteratorSteps(document, "div2", ":has(+ .a + .b .c)",
                             {{"div41", /* depth */ 1},
                              {"div4", /* depth */ 0},
                              {"div3", /* depth */ 0}});

  TestTraversalIteratorSteps(document, "div3", ":has(+ .a + .b .c)",
                             {{"div4", /* depth */ 0}});

  TestTraversalIteratorSteps(
      document, "div31", ":has(+ .a + .b .c)",
      {{"div33", /* depth */ 0}, {"div32", /* depth */ 0}});

  TestTraversalIteratorSteps(document, "div32", ":has(+ .a + .b .c)",
                             {{"div3411", /* depth */ 2},
                              {"div341", /* depth */ 1},
                              {"div34", /* depth */ 0},
                              {"div33", /* depth */ 0}});

  TestTraversalIteratorForEmptyRange(document, "div4", ":has(+ .a + .b .c)");
}

TEST_F(CheckPseudoHasArgumentContextTest, TestTraversalIteratorCase4) {
  // CheckPseudoHasArgumentTraversalScope::kAllNextSiblingSubtrees

  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write(R"HTML(
    <!DOCTYPE html>
    <main id=main>
      <div id=div1>
        <div id=div11></div>
      </div>
      <div id=div2>
        <div id=div21></div>
      </div>
      <div id=div3>
        <div id=div31>
          <div id=div311></div>
        </div>
        <div id=div32>
          <div id=div321></div>
        </div>
        <div id=div33></div>
        <div id=div34>
          <div id=div341>
            <div id=div3411></div>
          </div>
        </div>
      </div>
      <div id=div4>
        <div id=div41></div>
      </div>
      <div id=div5></div>
    </main>
  )HTML");

  TestTraversalIteratorSteps(document, "div2", ":has(~ .a .b)",
                             {{"div5", /* depth */ 0},
                              {"div41", /* depth */ 1},
                              {"div4", /* depth */ 0},
                              {"div3411", /* depth */ 3},
                              {"div341", /* depth */ 2},
                              {"div34", /* depth */ 1},
                              {"div33", /* depth */ 1},
                              {"div321", /* depth */ 2},
                              {"div32", /* depth */ 1},
                              {"div311", /* depth */ 2},
                              {"div31", /* depth */ 1},
                              {"div3", /* depth */ 0}});

  TestTraversalIteratorSteps(document, "div4", "
"""


```