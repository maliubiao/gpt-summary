Response:
The user is asking for a summary of the provided C++ code file, which is a unit test file for the `FlatTreeTraversal` functionality in the Chromium Blink engine.

Here's a breakdown of the thinking process to generate the summary:

1. **Identify the core purpose:** The filename `flat_tree_traversal_test.cc` immediately suggests that this file contains tests for the `FlatTreeTraversal` class.

2. **Examine the includes:** The included headers provide clues about the functionalities being tested:
    * `flat_tree_traversal.h`: This is the main file being tested.
    * `testing/gtest/include/gtest/gtest.h`: Indicates this is a Google Test based unit test file.
    * DOM-related headers (`document.h`, `element.h`, `node.h`, `node_traversal.h`, `shadow_root.h`): These signify that `FlatTreeTraversal` deals with traversing the Document Object Model (DOM), specifically in the context of shadow DOM.
    * HTML-related headers (`html_element.h`, `html_slot_element.h`):  Indicates interaction with HTML elements and slots, crucial for shadow DOM.
    * `page_test_base.h`: Points to a testing framework within Blink.

3. **Analyze the test structure:** The code defines a test fixture `FlatTreeTraversalTest` inheriting from `PageTestBase`. This structure is standard for Google Test. The `TEST_F` macros indicate individual test cases.

4. **Focus on the test case names and content:** The names of the test cases are highly informative:
    * `childAt`:  Likely tests accessing children at a specific index.
    * `DescendantsOf`: Tests iterating over descendants.
    * `StartsAtOrAfter`: Tests iterating from a specific node.
    * `ChildrenOf`: Tests iterating over direct children.
    * `commonAncestor`: Tests finding the common ancestor of two nodes.
    * `SkippingChildrenFunctions`: Tests traversal while skipping children.
    * `AncestorsOf`: Tests iterating over ancestors.
    * `InclusiveAncestorsOf`: Tests iterating over ancestors including the starting node.
    * `lastWithin`: Tests finding the last node within a subtree.
    * `previousPostOrder`: Tests post-order traversal in reverse.
    * `nextSiblingNotInDocumentFlatTree`: Tests handling of siblings not in the active flat tree.
    * `v1Simple`, `v1Redistribution`, `v1SlotInDocumentTree`, `v1FallbackContent`, `v1FallbackContentSkippedInTraversal`, `v1AllFallbackContent`: These tests with "v1" likely relate to Shadow DOM v1 concepts and functionalities like slotting, redistribution, and fallback content.

5. **Identify helper functions:** The `GatherFromTraversalRange`, `SetupSampleHTML`, `SetupDocumentTree`, and `AttachOpenShadowRoot` functions are setup utilities for creating test DOM structures. `TestCommonAncestor` is a helper for asserting common ancestor results.

6. **Infer functionality based on test cases:**  Based on the test case names and the setup code, infer the core functions of `FlatTreeTraversal`:
    * Accessing children (at index, first, last).
    * Iterating through descendants (inclusive and exclusive).
    * Iterating through ancestors (inclusive and exclusive).
    * Finding common ancestors.
    * Navigating siblings (next, previous).
    * Post-order traversal.
    * Handling shadow DOM concepts like slots and fallback content.

7. **Relate to web technologies (JavaScript, HTML, CSS):**  Consider how these functionalities relate to the browser's rendering and scripting:
    * **HTML:**  The tests manipulate HTML structures using strings, demonstrating how `FlatTreeTraversal` operates on the underlying HTML DOM.
    * **JavaScript:** JavaScript uses DOM APIs for traversal and manipulation. `FlatTreeTraversal` likely provides an efficient internal mechanism for these operations.
    * **CSS:** While not directly tested, shadow DOM, a key aspect of `FlatTreeTraversal`, influences CSS scoping and styling. The concept of slots directly impacts how CSS selectors work within shadow trees.

8. **Consider potential user/programming errors:**  Think about common mistakes developers might make when working with DOM traversal:
    * Incorrectly assuming the order of elements in the flat tree when shadow DOM is involved.
    * Expecting certain nodes to be siblings when they are in different shadow trees.
    * Not understanding how slots redistribute content.

9. **Think about debugging scenarios:** Imagine how a developer might end up looking at this test file:
    * Investigating bugs related to element ordering or visibility when shadow DOM is used.
    * Tracing the execution of JavaScript code that interacts with the DOM.
    * Understanding how Blink handles DOM traversal internally.

10. **Synthesize the information:** Combine the observations into a concise summary, addressing the user's request for functionality, relations to web technologies, logical inferences, common errors, and debugging context. Organize the information logically with clear headings.
好的，这是该文件的功能归纳：

**功能归纳：**

`blink/renderer/core/dom/flat_tree_traversal_test.cc` 是 Chromium Blink 引擎中的一个 C++ 单元测试文件，专门用于测试 `blink::FlatTreeTraversal` 类及其相关的功能。

**主要功能点包括：**

1. **测试扁平树遍历的核心功能：** 该文件测试了 `FlatTreeTraversal` 类提供的各种方法，用于在 DOM 树的扁平化表示上进行遍历。  扁平树是一种考虑了 Shadow DOM 投影（slotting）影响的 DOM 树结构，它反映了元素最终在页面上渲染时的逻辑顺序。

2. **测试各种遍历方向和策略：**  测试涵盖了前向和后向遍历、包括自身和不包括自身的遍历、遍历子节点、遍历祖先节点、跳过子节点的遍历等多种遍历方式。

3. **测试 Shadow DOM 的影响：**  该文件重点测试了 Shadow DOM 如何影响扁平树的结构和遍历结果。这包括：
    * **Slotting（插槽）：** 测试内容如何通过 `<slot>` 元素投影到 Shadow DOM 中。
    * **Redistribution（重新分发）：** 测试内容在多个 Shadow Host 之间如何被重新分发。
    * **Fallback Content（回退内容）：** 测试在没有内容投影到 slot 时，slot 中定义的回退内容如何被处理。

4. **测试特定的遍历方法：**  文件中包含了针对 `ChildAt`、`CountChildren`、`HasChildren`、`Index`、`IsDescendantOf`、`CommonAncestor`、`NextSkippingChildren`、`PreviousAbsoluteSibling`、`FirstChild`、`LastChild`、`NextSibling`、`PreviousSibling`、`DescendantsOf`、`InclusiveDescendantsOf`、`AncestorsOf`、`InclusiveAncestorsOf`、`LastWithin`、`LastWithinOrSelf`、`PreviousPostOrder`、`StartsAt`、`StartsAfter`、`ChildrenOf` 等多种 `FlatTreeTraversal` 类的方法的测试。

5. **使用 Google Test 框架：** 该文件使用了 Google Test 框架来组织和运行测试用例，确保代码的正确性。

**与 JavaScript, HTML, CSS 的关系：**

`FlatTreeTraversal` 的功能直接关系到浏览器如何解释和渲染 HTML 结构，以及 JavaScript 如何与之交互。

* **HTML:**  `FlatTreeTraversal` 负责理解 HTML 元素的层级关系，包括 Shadow DOM 引入的新的结构概念（如 Shadow Host, Shadow Root, Slot）。测试用例中通过创建各种 HTML 结构来验证遍历逻辑的正确性。

    * **举例：**  测试用例中会创建包含 `<slot>` 元素的 HTML 结构，然后断言通过 `FlatTreeTraversal` 遍历时，被分配到 slot 的节点会出现在 slot 元素的位置。

* **JavaScript:** JavaScript 可以通过 DOM API（如 `childNodes`, `firstChild`, `nextSibling`, `parentElement`, `querySelectorAll` 等）来遍历和操作 DOM 树。 `FlatTreeTraversal` 提供的功能是这些 JavaScript API 的底层实现基础。

    * **举例：** JavaScript 代码使用 `element.childNodes` 获取子元素时，浏览器内部会使用类似 `FlatTreeTraversal::ChildrenOf` 的逻辑来确定哪些节点是该元素的子节点，并考虑到 Shadow DOM 的影响。

* **CSS:** 虽然该测试文件本身不直接测试 CSS，但 `FlatTreeTraversal` 的结果会影响 CSS 样式的应用。例如，CSS 选择器依赖于 DOM 树的结构来匹配元素，而 Shadow DOM 引入的扁平树概念会影响选择器的匹配范围。

    * **举例：**  CSS 的包含选择器 (e.g., `div span`) 会受到 Shadow DOM 的影响。在 Shadow DOM 中，主树中的元素不会被视为 Shadow Root 内部元素的后代，除非它们被 slot 分发到 Shadow DOM 中。 `FlatTreeTraversal` 确保了在遍历时能正确反映这种关系，从而让 CSS 选择器能够正确工作。

**逻辑推理和假设输入/输出：**

测试用例通过设置特定的 HTML 结构（作为输入）并断言 `FlatTreeTraversal` 的方法返回预期的节点序列或结果（作为输出）来进行逻辑推理。

* **假设输入：**
    ```html
    <div id='host'>
      <slot></slot>
      <p id='fallback'>Fallback</p>
    </div>
    <script>
      const host = document.getElementById('host');
      const shadowRoot = host.attachShadow({mode: 'open'});
      shadowRoot.innerHTML = '<slot></slot>';
      const content = document.createElement('span');
      host.appendChild(content);
    </script>
    ```
* **预期输出 (基于 `FlatTreeTraversal` 的推断)：**
    对于 `FlatTreeTraversal::ChildrenOf(host)`，预期的顺序是：`<slot>` (shadowRoot 中的 slot), `<span>` (主树中的元素)。 Fallback content `<p>` 不会出现在扁平子节点列表中，因为它只有在没有内容被分配到 slot 时才会被渲染。

**用户或编程常见的使用错误：**

* **错误地假设 Shadow DOM 内部的节点是外部节点的子节点：** 在没有正确理解扁平树概念的情况下，开发者可能会错误地认为 Shadow Root 内部的节点可以通过主树的 DOM API 直接访问。 `FlatTreeTraversal` 的测试帮助确保了只有被 slot 分发的节点才会在扁平树中被视为父节点的子节点。

    * **举例：**  如果开发者尝试使用 `host.querySelector('#fallback')` 在上面的例子中访问 fallback content，会得到 `null`，因为 fallback content 不在 `host` 的主树子节点中。理解 `FlatTreeTraversal` 的行为有助于避免这种错误。

* **遍历 Shadow DOM 时没有考虑到 slot 的影响：** 开发者可能会错误地认为遍历一个 Shadow Host 的子节点会直接访问到 Shadow Root 内部的节点。 `FlatTreeTraversal` 的测试强调了需要理解 slot 如何将外部内容“投影”到 Shadow DOM 中，以及这如何影响遍历顺序。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器中访问一个包含 Shadow DOM 的网页。**
2. **页面渲染过程中，Blink 引擎需要构建和遍历 DOM 树，包括 Shadow DOM。**
3. **如果页面出现与元素层级、显示顺序或事件冒泡等相关的 Bug，开发者可能会使用浏览器开发者工具来检查 DOM 结构。**
4. **为了理解 Blink 引擎内部是如何处理 DOM 遍历的，或者为了修复 Blink 引擎本身的相关 Bug，开发者可能会查看 `blink/renderer/core/dom/flat_tree_traversal.cc` 这个测试文件。**
5. **开发者可以通过阅读测试用例来了解 `FlatTreeTraversal` 的各种功能和行为，从而更好地理解 Bug 的原因，或者验证代码修改的正确性。**

**总结：**

总而言之，`blink/renderer/core/dom/flat_tree_traversal_test.cc` 是一个至关重要的测试文件，用于确保 Blink 引擎中负责扁平树遍历的功能能够正确处理各种 DOM 结构，特别是涉及到 Shadow DOM 的情况。它对于保证浏览器正确渲染网页和执行 JavaScript 代码至关重要。

Prompt: 
```
这是目录为blink/renderer/core/dom/flat_tree_traversal_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"

#include <memory>
#include <string_view>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

// Gathers all the nodes in `traversal_range` and returns them as a
// `HeapVector`.
HeapVector<Member<Node>> GatherFromTraversalRange(auto traversal_range) {
  HeapVector<Member<Node>> result;
  for (Node& node : traversal_range) {
    result.push_back(&node);
  }
  return result;
}

class FlatTreeTraversalTest : public PageTestBase {
 public:
  FlatTreeTraversalTest() {}

 protected:
  // Sets `mainHTML` to BODY element with `innerHTML` property and attaches
  // shadow root to child with `shadowHTML`, then update distribution for
  // calling member functions in `FlatTreeTraversal`.
  void SetupSampleHTML(std::string_view main_html,
                       std::string_view shadow_html,
                       unsigned index);

  void SetupDocumentTree(std::string_view main_html);

  void AttachOpenShadowRoot(Element& shadow_host,
                            std::string_view shadow_inner_html);
};

void FlatTreeTraversalTest::SetupSampleHTML(std::string_view main_html,
                                            std::string_view shadow_html,
                                            unsigned index) {
  Element* body = GetDocument().body();
  body->setInnerHTML(String::FromUTF8(main_html));
  auto* shadow_host = To<Element>(NodeTraversal::ChildAt(*body, index));
  AttachOpenShadowRoot(*shadow_host, shadow_html);
}

void FlatTreeTraversalTest::SetupDocumentTree(std::string_view main_html) {
  Element* body = GetDocument().body();
  body->setInnerHTML(String::FromUTF8(main_html));
}

void FlatTreeTraversalTest::AttachOpenShadowRoot(
    Element& shadow_host,
    std::string_view shadow_inner_html) {
  ShadowRoot& shadow_root =
      shadow_host.AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML(String::FromUTF8(shadow_inner_html));
}

namespace {

void TestCommonAncestor(Node* expected_result,
                        const Node& node_a,
                        const Node& node_b) {
  Node* result1 = FlatTreeTraversal::CommonAncestor(node_a, node_b);
  EXPECT_EQ(expected_result, result1)
      << "commonAncestor(" << node_a.textContent() << ","
      << node_b.textContent() << ")";
  Node* result2 = FlatTreeTraversal::CommonAncestor(node_b, node_a);
  EXPECT_EQ(expected_result, result2)
      << "commonAncestor(" << node_b.textContent() << ","
      << node_a.textContent() << ")";
}

}  // namespace

// Test case for
//  - childAt
//  - countChildren
//  - hasChildren
//  - index
//  - isDescendantOf
TEST_F(FlatTreeTraversalTest, childAt) {
  const char* main_html =
      "<div id='m0'>"
      "<span slot='#m00' id='m00'>m00</span>"
      "<span slot='#m01' id='m01'>m01</span>"
      "</div>";
  const char* shadow_html =
      "<a id='s00'>s00</a>"
      "<slot name='#m01'></slot>"
      "<a id='s02'>s02</a>"
      "<a id='s03'><slot name='#m00'></slot></a>"
      "<a id='s04'>s04</a>";
  SetupSampleHTML(main_html, shadow_html, 0);

  Element* body = GetDocument().body();
  Element* m0 = body->QuerySelector(AtomicString("#m0"));
  Element* m00 = m0->QuerySelector(AtomicString("#m00"));
  Element* m01 = m0->QuerySelector(AtomicString("#m01"));

  Element* shadow_host = m0;
  ShadowRoot* shadow_root = shadow_host->OpenShadowRoot();
  Element* s00 = shadow_root->QuerySelector(AtomicString("#s00"));
  Element* s02 = shadow_root->QuerySelector(AtomicString("#s02"));
  Element* s03 = shadow_root->QuerySelector(AtomicString("#s03"));
  Element* s04 = shadow_root->QuerySelector(AtomicString("#s04"));

  const unsigned kNumberOfChildNodes = 5;
  Node* expected_child_nodes[5] = {s00, m01, s02, s03, s04};

  ASSERT_EQ(kNumberOfChildNodes,
            FlatTreeTraversal::CountChildren(*shadow_host));
  EXPECT_TRUE(FlatTreeTraversal::HasChildren(*shadow_host));

  for (unsigned index = 0; index < kNumberOfChildNodes; ++index) {
    Node* child = FlatTreeTraversal::ChildAt(*shadow_host, index);
    EXPECT_EQ(index, FlatTreeTraversal::Index(*child))
        << "FlatTreeTraversal::index(FlatTreeTraversal(*shadowHost, " << index
        << "))";
    EXPECT_TRUE(FlatTreeTraversal::IsDescendantOf(*child, *shadow_host))
        << "FlatTreeTraversal::isDescendantOf(*FlatTreeTraversal(*"
           "shadowHost, "
        << index << "), *shadowHost)";
    bool is_slot_element = IsA<HTMLSlotElement>(child);
    if (is_slot_element) {
      child = FlatTreeTraversal::FirstChild(*child);
    }
    EXPECT_EQ(expected_child_nodes[index], child)
        << "FlatTreeTraversal::childAt(*shadowHost, " << index << ")";
    EXPECT_EQ(is_slot_element ? 0 : index, FlatTreeTraversal::Index(*child))
        << "FlatTreeTraversal::index(FlatTreeTraversal(*shadowHost, " << index
        << "))";
  }
  EXPECT_EQ(nullptr,
            FlatTreeTraversal::ChildAt(*shadow_host, kNumberOfChildNodes + 1))
      << "Out of bounds childAt() returns nullptr.";

  // Distributed node |m00| is child of slot in shadow tree |s03|.
  EXPECT_EQ(
      m00, FlatTreeTraversal::FirstChild(*FlatTreeTraversal::FirstChild(*s03)));
}

TEST_F(FlatTreeTraversalTest, DescendantsOf) {
  std::string_view main_html =
      R"(<div id='m0'>
        <span slot='#m00' id='m00'>m00</span>
        <span slot='#m01' id='m01'>m01</span>
      </div>)";
  std::string_view shadow_html =
      R"(<a id='s00'>s00</a>
      <slot name='#m01'></slot>
      <a id='s02'>s02</a>
      <a id='s03'>
        <slot name='#m00'></slot>
      </a>
      <a id='s04'>s04</a>)";
  SetupSampleHTML(main_html, shadow_html, 0);

  Element* body = GetDocument().body();
  Element* m0 = body->QuerySelector(AtomicString("#m0"));
  Element* shadow_host = m0;
  ShadowRoot* shadow_root = shadow_host->OpenShadowRoot();
  Element* s03 = shadow_root->QuerySelector(AtomicString("#s03"));

  {
    HeapVector<Member<Node>> expected_nodes;
    for (Node* child = FlatTreeTraversal::FirstChild(*body); child;
         child = FlatTreeTraversal::Next(*child)) {
      expected_nodes.push_back(child);
    }
    EXPECT_EQ(expected_nodes, GatherFromTraversalRange(
                                  FlatTreeTraversal::DescendantsOf(*body)));

    expected_nodes.push_front(body);
    EXPECT_EQ(expected_nodes,
              GatherFromTraversalRange(
                  FlatTreeTraversal::InclusiveDescendantsOf(*body)));
  }

  // Traversal of descendants of a node that is not the root node stays within
  // the sub tree.
  {
    HeapVector<Member<Node>> expected_nodes;
    for (Node* child = FlatTreeTraversal::FirstChild(*s03); child;
         child = FlatTreeTraversal::Next(*child, /*stay_within=*/s03)) {
      expected_nodes.push_back(child);
    }
    EXPECT_EQ(expected_nodes,
              GatherFromTraversalRange(FlatTreeTraversal::DescendantsOf(*s03)));

    expected_nodes.push_front(s03);
    EXPECT_EQ(expected_nodes,
              GatherFromTraversalRange(
                  FlatTreeTraversal::InclusiveDescendantsOf(*s03)));
  }
}

TEST_F(FlatTreeTraversalTest, StartsAtOrAfter) {
  std::string_view main_html =
      R"(<div id='m0'>
        <span slot='#m00' id='m00'>m00</span>
        <span slot='#m01' id='m01'>m01</span>
      </div>)";
  std::string_view shadow_html =
      R"(<a id='s00'>s00</a>
      <slot name='#m01'></slot>
      <a id='s02'>s02</a>
      <a id='s03'>
        <slot name='#m00'></slot>
      </a>
      <a id='s04'>s04</a>)";
  SetupSampleHTML(main_html, shadow_html, 0);

  Element* body = GetDocument().body();
  Element* m0 = body->QuerySelector(AtomicString("#m0"));
  Element* shadow_host = m0;
  ShadowRoot* shadow_root = shadow_host->OpenShadowRoot();
  Element* s03 = shadow_root->QuerySelector(AtomicString("#s03"));

  HeapVector<Member<Node>> expected_nodes;
  for (Node* child = FlatTreeTraversal::Next(*s03); child;
       child = FlatTreeTraversal::Next(*child)) {
    expected_nodes.push_back(child);
  }
  EXPECT_EQ(expected_nodes,
            GatherFromTraversalRange(FlatTreeTraversal::StartsAfter(*s03)));

  expected_nodes.push_front(*s03);
  EXPECT_EQ(expected_nodes,
            GatherFromTraversalRange(FlatTreeTraversal::StartsAt(*s03)));
}

TEST_F(FlatTreeTraversalTest, ChildrenOf) {
  SetupSampleHTML(
      "<p id=sample>ZERO<span slot=three>three</b><span "
      "slot=one>one</b>FOUR</p>",
      "zero<slot name=one></slot>two<slot name=three></slot>four", 0);
  Element* const sample = GetDocument().getElementById(AtomicString("sample"));

  HeapVector<Member<Node>> expected_nodes;
  for (Node* runner = FlatTreeTraversal::FirstChild(*sample); runner;
       runner = FlatTreeTraversal::NextSibling(*runner)) {
    expected_nodes.push_back(runner);
  }

  HeapVector<Member<Node>> actual_nodes;
  for (Node& child : FlatTreeTraversal::ChildrenOf(*sample))
    actual_nodes.push_back(&child);

  EXPECT_EQ(expected_nodes, actual_nodes);
}

// Test case for
//  - commonAncestor
//  - isDescendantOf
TEST_F(FlatTreeTraversalTest, commonAncestor) {
  // We build following flat tree:
  //             ____BODY___
  //             |    |     |
  //            m0    m1    m2       m1 is shadow host having m10, m11, m12.
  //            _|_   |   __|__
  //           |   |  |   |    |
  //          m00 m01 |   m20 m21
  //             _____|_____________
  //             |  |   |    |     |
  //            s10 s11 s12 s13  s14
  //                         |
  //                       __|__
  //                |      |    |
  //                m12    m10 m11 <-- distributed
  // where: each symbol consists with prefix, child index, child-child index.
  //  prefix "m" means node in main tree,
  //  prefix "d" means node in main tree and distributed
  //  prefix "s" means node in shadow tree
  const char* main_html =
      "<a id='m0'><b id='m00'>m00</b><b id='m01'>m01</b></a>"
      "<div id='m1'>"
      "<b slot='#m10' id='m10'>m10</b>"
      "<b slot='#m11' id='m11'>m11</b>"
      "<b slot='#m12' id='m12'>m12</b>"
      "</div>"
      "<a id='m2'><b id='m20'>m20</b><b id='m21'>m21</b></a>";
  const char* shadow_html =
      "<a id='s10'>s10</a>"
      "<a id='s11'><slot name='#m12'></slot></a>"
      "<a id='s12'>s12</a>"
      "<a id='s13'>"
      "<slot name='#m10'></slot>"
      "<slot name='#m11'></slot>"
      "</a>"
      "<a id='s14'>s14</a>";
  SetupSampleHTML(main_html, shadow_html, 1);
  Element* body = GetDocument().body();
  Element* m0 = body->QuerySelector(AtomicString("#m0"));
  Element* m1 = body->QuerySelector(AtomicString("#m1"));
  Element* m2 = body->QuerySelector(AtomicString("#m2"));

  Element* m00 = body->QuerySelector(AtomicString("#m00"));
  Element* m01 = body->QuerySelector(AtomicString("#m01"));
  Element* m10 = body->QuerySelector(AtomicString("#m10"));
  Element* m11 = body->QuerySelector(AtomicString("#m11"));
  Element* m12 = body->QuerySelector(AtomicString("#m12"));
  Element* m20 = body->QuerySelector(AtomicString("#m20"));
  Element* m21 = body->QuerySelector(AtomicString("#m21"));

  ShadowRoot* shadow_root = m1->OpenShadowRoot();
  Element* s10 = shadow_root->QuerySelector(AtomicString("#s10"));
  Element* s11 = shadow_root->QuerySelector(AtomicString("#s11"));
  Element* s12 = shadow_root->QuerySelector(AtomicString("#s12"));
  Element* s13 = shadow_root->QuerySelector(AtomicString("#s13"));
  Element* s14 = shadow_root->QuerySelector(AtomicString("#s14"));

  TestCommonAncestor(body, *m0, *m1);
  TestCommonAncestor(body, *m1, *m2);
  TestCommonAncestor(body, *m1, *m20);
  TestCommonAncestor(body, *s14, *m21);

  TestCommonAncestor(m0, *m0, *m0);
  TestCommonAncestor(m0, *m00, *m01);

  TestCommonAncestor(m1, *m1, *m1);
  TestCommonAncestor(m1, *s10, *s14);
  TestCommonAncestor(m1, *s10, *m12);
  TestCommonAncestor(m1, *s12, *m12);
  TestCommonAncestor(m1, *m10, *m12);

  TestCommonAncestor(m01, *m01, *m01);
  TestCommonAncestor(s11, *s11, *m12);
  TestCommonAncestor(s13, *m10, *m11);

  s12->remove(ASSERT_NO_EXCEPTION);
  TestCommonAncestor(s12, *s12, *s12);
  TestCommonAncestor(nullptr, *s12, *s11);
  TestCommonAncestor(nullptr, *s12, *m01);
  TestCommonAncestor(nullptr, *s12, *m20);

  m20->remove(ASSERT_NO_EXCEPTION);
  TestCommonAncestor(m20, *m20, *m20);
  TestCommonAncestor(nullptr, *m20, *s12);
  TestCommonAncestor(nullptr, *m20, *m1);
}

// Test case for
//  - NextSkippingChildren
//  - PreviousAbsoluteSibling
TEST_F(FlatTreeTraversalTest, SkippingChildrenFunctions) {
  const char* main_html =
      "<div id='m0'>m0</div>"
      "<div id='m1'>"
      "<span slot='#m10' id='m10'>m10</span>"
      "<span slot='#m11' id='m11'>m11</span>"
      "</div>"
      "<div id='m2'>m2</div>";
  const char* shadow_html =
      "<slot name='#m11'></slot>"
      "<a id='s11'>s11</a>"
      "<a id='s12'>"
      "<b id='s120'>s120</b>"
      "<slot name='#m10'></slot>"
      "</a>";
  SetupSampleHTML(main_html, shadow_html, 1);

  Element* body = GetDocument().body();
  Element* m0 = body->QuerySelector(AtomicString("#m0"));
  Element* m1 = body->QuerySelector(AtomicString("#m1"));
  Element* m2 = body->QuerySelector(AtomicString("#m2"));

  Element* m10 = body->QuerySelector(AtomicString("#m10"));
  Element* m10_slot_parent = To<Element>(FlatTreeTraversal::Parent(*m10));
  Element* m11 = body->QuerySelector(AtomicString("#m11"));
  Element* m11_slot_parent = To<Element>(FlatTreeTraversal::Parent(*m11));

  ShadowRoot* shadow_root = m1->OpenShadowRoot();
  Element* s11 = shadow_root->QuerySelector(AtomicString("#s11"));
  Element* s12 = shadow_root->QuerySelector(AtomicString("#s12"));
  Element* s120 = shadow_root->QuerySelector(AtomicString("#s120"));

  // Main tree node to main tree node
  EXPECT_EQ(*m1, FlatTreeTraversal::NextSkippingChildren(*m0));
  EXPECT_EQ(*m0, FlatTreeTraversal::PreviousAbsoluteSibling(*m1));

  // Distribute node to main tree node
  EXPECT_EQ(*m2, FlatTreeTraversal::NextSkippingChildren(*m10));
  EXPECT_EQ(*m1, FlatTreeTraversal::PreviousAbsoluteSibling(*m2));

  // Distribute node to node in shadow tree
  EXPECT_EQ(*s11, FlatTreeTraversal::NextSkippingChildren(*m11));
  EXPECT_EQ(*m11_slot_parent, FlatTreeTraversal::PreviousAbsoluteSibling(*s11));

  // Node in shadow tree to distributed node
  EXPECT_EQ(*s11, FlatTreeTraversal::NextSkippingChildren(*m11));
  EXPECT_EQ(*m11_slot_parent, FlatTreeTraversal::PreviousAbsoluteSibling(*s11));

  EXPECT_EQ(*m10_slot_parent, FlatTreeTraversal::NextSkippingChildren(*s120));
  EXPECT_EQ(*s120, FlatTreeTraversal::PreviousAbsoluteSibling(*m10));

  // Node in shadow tree to main tree
  EXPECT_EQ(*m2, FlatTreeTraversal::NextSkippingChildren(*s12));
  EXPECT_EQ(*m1, FlatTreeTraversal::PreviousAbsoluteSibling(*m2));
}

TEST_F(FlatTreeTraversalTest, AncestorsOf) {
  SetupDocumentTree("<div><div><div id=sample></div></div></div>");
  Element* const sample = GetDocument().getElementById(AtomicString("sample"));

  HeapVector<Member<Node>> expected_nodes;
  for (Node* parent = FlatTreeTraversal::Parent(*sample); parent;
       parent = FlatTreeTraversal::Parent(*parent)) {
    expected_nodes.push_back(parent);
  }

  HeapVector<Member<Node>> actual_nodes;
  for (Node& ancestor : FlatTreeTraversal::AncestorsOf(*sample))
    actual_nodes.push_back(&ancestor);

  EXPECT_EQ(expected_nodes, actual_nodes);
}

TEST_F(FlatTreeTraversalTest, InclusiveAncestorsOf) {
  SetupDocumentTree("<div><div><div id=sample></div></div></div>");
  Element* const sample = GetDocument().getElementById(AtomicString("sample"));

  HeapVector<Member<Node>> expected_nodes;
  for (Node* parent = sample; parent;
       parent = FlatTreeTraversal::Parent(*parent)) {
    expected_nodes.push_back(parent);
  }

  HeapVector<Member<Node>> actual_nodes;
  for (Node& ancestor : FlatTreeTraversal::InclusiveAncestorsOf(*sample))
    actual_nodes.push_back(&ancestor);

  EXPECT_EQ(expected_nodes, actual_nodes);
}

// Test case for
//  - lastWithin
//  - lastWithinOrSelf
TEST_F(FlatTreeTraversalTest, lastWithin) {
  const char* main_html =
      "<div id='m0'>m0</div>"
      "<div id='m1'>"
      "<span slot='#m10' id='m10'>m10</span>"
      "<span slot='#m11' id='m11'>m11</span>"
      "<span id='m12'>m12</span>"  // #m12 is not distributed.
      "</div>"
      "<div id='m2'></div>";
  const char* shadow_html =
      "<slot name='#m11'></slot>"
      "<a id='s11'>s11</a>"
      "<a id='s12'>"
      "<slot name='#m10'></slot>"
      "</a>";
  SetupSampleHTML(main_html, shadow_html, 1);

  Element* body = GetDocument().body();
  Element* m0 = body->QuerySelector(AtomicString("#m0"));
  Element* m1 = body->QuerySelector(AtomicString("#m1"));
  Element* m2 = body->QuerySelector(AtomicString("#m2"));

  Element* m10 = body->QuerySelector(AtomicString("#m10"));

  ShadowRoot* shadow_root = m1->OpenShadowRoot();
  Element* s11 = shadow_root->QuerySelector(AtomicString("#s11"));
  Element* s12 = shadow_root->QuerySelector(AtomicString("#s12"));

  EXPECT_EQ(m0->firstChild(), FlatTreeTraversal::LastWithin(*m0));
  EXPECT_EQ(*m0->firstChild(), FlatTreeTraversal::LastWithinOrSelf(*m0));

  EXPECT_EQ(m10->firstChild(), FlatTreeTraversal::LastWithin(*m1));
  EXPECT_EQ(*m10->firstChild(), FlatTreeTraversal::LastWithinOrSelf(*m1));

  EXPECT_EQ(nullptr, FlatTreeTraversal::LastWithin(*m2));
  EXPECT_EQ(*m2, FlatTreeTraversal::LastWithinOrSelf(*m2));

  EXPECT_EQ(s11->firstChild(), FlatTreeTraversal::LastWithin(*s11));
  EXPECT_EQ(*s11->firstChild(), FlatTreeTraversal::LastWithinOrSelf(*s11));

  EXPECT_EQ(m10->firstChild(), FlatTreeTraversal::LastWithin(*s12));
  EXPECT_EQ(*m10->firstChild(), FlatTreeTraversal::LastWithinOrSelf(*s12));
}

TEST_F(FlatTreeTraversalTest, previousPostOrder) {
  const char* main_html =
      "<div id='m0'>m0</div>"
      "<div id='m1'>"
      "<span slot='#m10' id='m10'>m10</span>"
      "<span slot='#m11' id='m11'>m11</span>"
      "</div>"
      "<div id='m2'>m2</div>";
  const char* shadow_html =
      "<slot name='#m11'></slot>"
      "<a id='s11'>s11</a>"
      "<a id='s12'>"
      "<b id='s120'>s120</b>"
      "<slot name='#m10'></slot>"
      "</a>";
  SetupSampleHTML(main_html, shadow_html, 1);

  Element* body = GetDocument().body();
  Element* m0 = body->QuerySelector(AtomicString("#m0"));
  Element* m1 = body->QuerySelector(AtomicString("#m1"));
  Element* m2 = body->QuerySelector(AtomicString("#m2"));

  Element* m10 = body->QuerySelector(AtomicString("#m10"));
  Element* m10_slot_parent = To<Element>(FlatTreeTraversal::Parent(*m10));
  Element* m11 = body->QuerySelector(AtomicString("#m11"));

  ShadowRoot* shadow_root = m1->OpenShadowRoot();
  Element* s11 = shadow_root->QuerySelector(AtomicString("#s11"));
  Element* s12 = shadow_root->QuerySelector(AtomicString("#s12"));
  Element* s120 = shadow_root->QuerySelector(AtomicString("#s120"));

  EXPECT_EQ(*m0->firstChild(), FlatTreeTraversal::PreviousPostOrder(*m0));
  EXPECT_EQ(*s12, FlatTreeTraversal::PreviousPostOrder(*m1));
  EXPECT_EQ(*m10->firstChild(), FlatTreeTraversal::PreviousPostOrder(*m10));
  EXPECT_EQ(*s120, FlatTreeTraversal::PreviousPostOrder(*m10->firstChild()));
  EXPECT_EQ(*s120,
            FlatTreeTraversal::PreviousPostOrder(*m10->firstChild(), s12));
  EXPECT_EQ(*m11->firstChild(), FlatTreeTraversal::PreviousPostOrder(*m11));
  EXPECT_EQ(*m0, FlatTreeTraversal::PreviousPostOrder(*m11->firstChild()));
  EXPECT_EQ(nullptr,
            FlatTreeTraversal::PreviousPostOrder(*m11->firstChild(), m11));
  EXPECT_EQ(*m2->firstChild(), FlatTreeTraversal::PreviousPostOrder(*m2));

  EXPECT_EQ(*s11->firstChild(), FlatTreeTraversal::PreviousPostOrder(*s11));
  EXPECT_EQ(*m10_slot_parent, FlatTreeTraversal::PreviousPostOrder(*s12));
  EXPECT_EQ(*s120->firstChild(), FlatTreeTraversal::PreviousPostOrder(*s120));
  EXPECT_EQ(*s11, FlatTreeTraversal::PreviousPostOrder(*s120->firstChild()));
  EXPECT_EQ(nullptr,
            FlatTreeTraversal::PreviousPostOrder(*s120->firstChild(), s12));
}

TEST_F(FlatTreeTraversalTest, nextSiblingNotInDocumentFlatTree) {
  const char* main_html =
      "<div id='m0'>m0</div>"
      "<div id='m1'>"
      "<span id='m10'>m10</span>"
      "<span id='m11'>m11</span>"
      "</div>"
      "<div id='m2'>m2</div>";
  const char* shadow_html = "<content select='#m11'></content>";
  SetupSampleHTML(main_html, shadow_html, 1);

  Element* body = GetDocument().body();
  Element* m10 = body->QuerySelector(AtomicString("#m10"));

  EXPECT_EQ(nullptr, FlatTreeTraversal::NextSibling(*m10));
  EXPECT_EQ(nullptr, FlatTreeTraversal::PreviousSibling(*m10));
}


TEST_F(FlatTreeTraversalTest, v1Simple) {
  const char* main_html =
      "<div id='host'>"
      "<div id='child1' slot='slot1'></div>"
      "<div id='child2' slot='slot2'></div>"
      "</div>";
  const char* shadow_html =
      "<div id='shadow-child1'></div>"
      "<slot name='slot1'></slot>"
      "<slot name='slot2'></slot>"
      "<div id='shadow-child2'></div>";

  SetupDocumentTree(main_html);
  Element* body = GetDocument().body();
  Element* host = body->QuerySelector(AtomicString("#host"));
  Element* child1 = body->QuerySelector(AtomicString("#child1"));
  Element* child2 = body->QuerySelector(AtomicString("#child2"));

  AttachOpenShadowRoot(*host, shadow_html);
  ShadowRoot* shadow_root = host->OpenShadowRoot();
  Element* slot1 = shadow_root->QuerySelector(AtomicString("[name=slot1]"));
  Element* slot2 = shadow_root->QuerySelector(AtomicString("[name=slot2]"));
  Element* shadow_child1 =
      shadow_root->QuerySelector(AtomicString("#shadow-child1"));
  Element* shadow_child2 =
      shadow_root->QuerySelector(AtomicString("#shadow-child2"));

  EXPECT_TRUE(slot1);
  EXPECT_TRUE(slot2);
  EXPECT_EQ(shadow_child1, FlatTreeTraversal::FirstChild(*host));
  EXPECT_EQ(slot1, FlatTreeTraversal::NextSibling(*shadow_child1));
  EXPECT_EQ(nullptr, FlatTreeTraversal::NextSibling(*child1));
  EXPECT_EQ(nullptr, FlatTreeTraversal::NextSibling(*child2));
  EXPECT_EQ(slot2, FlatTreeTraversal::NextSibling(*slot1));
  EXPECT_EQ(shadow_child2, FlatTreeTraversal::NextSibling(*slot2));
}

TEST_F(FlatTreeTraversalTest, v1Redistribution) {
  // composed tree:
  // d1
  // ├──/shadow-root
  // │   └── d1-1
  // │       ├──/shadow-root
  // │       │   ├── d1-1-1
  // │       │   ├── slot name=d1-1-s1
  // │       │   ├── slot name=d1-1-s2
  // │       │   └── d1-1-2
  // │       ├── d1-2
  // │       ├── slot id=d1-s0
  // │       ├── slot name=d1-s1 slot=d1-1-s1
  // │       ├── slot name=d1-s2
  // │       ├── d1-3
  // │       └── d1-4 slot=d1-1-s1
  // ├── d2 slot=d1-s1
  // ├── d3 slot=d1-s2
  // ├── d4 slot=nonexistent
  // └── d5

  // flat tree:
  // d1
  // └── d1-1
  //     ├── d1-1-1
  //     ├── slot name=d1-1-s1
  //     │   ├── slot name=d1-s1 slot=d1-1-s1
  //     │   │   └── d2 slot=d1-s1
  //     │   └── d1-4 slot=d1-1-s1
  //     ├── slot name=d1-1-s2
  //     └── d1-1-2
  const char* main_html =
      "<div id='d1'>"
      "<div id='d2' slot='d1-s1'></div>"
      "<div id='d3' slot='d1-s2'></div>"
      "<div id='d4' slot='nonexistent'></div>"
      "<div id='d5'></div>"
      "</div>"
      "<div id='d6'></div>";
  const char* shadow_html1 =
      "<div id='d1-1'>"
      "<div id='d1-2'></div>"
      "<slot id='d1-s0'></slot>"
      "<slot name='d1-s1' slot='d1-1-s1'></slot>"
      "<slot name='d1-s2'></slot>"
      "<div id='d1-3'></div>"
      "<div id='d1-4' slot='d1-1-s1'></div>"
      "</div>";
  const char* shadow_html2 =
      "<div id='d1-1-1'></div>"
      "<slot name='d1-1-s1'></slot>"
      "<slot name='d1-1-s2'></slot>"
      "<div id='d1-1-2'></div>";

  SetupDocumentTree(main_html);

  Element* body = GetDocument().body();
  Element* d1 = body->QuerySelector(AtomicString("#d1"));
  Element* d2 = body->QuerySelector(AtomicString("#d2"));
  Element* d3 = body->QuerySelector(AtomicString("#d3"));
  Element* d4 = body->QuerySelector(AtomicString("#d4"));
  Element* d5 = body->QuerySelector(AtomicString("#d5"));
  Element* d6 = body->QuerySelector(AtomicString("#d6"));

  AttachOpenShadowRoot(*d1, shadow_html1);
  ShadowRoot* shadow_root1 = d1->OpenShadowRoot();
  Element* d11 = shadow_root1->QuerySelector(AtomicString("#d1-1"));
  Element* d12 = shadow_root1->QuerySelector(AtomicString("#d1-2"));
  Element* d13 = shadow_root1->QuerySelector(AtomicString("#d1-3"));
  Element* d14 = shadow_root1->QuerySelector(AtomicString("#d1-4"));
  Element* d1s0 = shadow_root1->QuerySelector(AtomicString("#d1-s0"));
  Element* d1s1 = shadow_root1->QuerySelector(AtomicString("[name=d1-s1]"));
  Element* d1s2 = shadow_root1->QuerySelector(AtomicString("[name=d1-s2]"));

  AttachOpenShadowRoot(*d11, shadow_html2);
  ShadowRoot* shadow_root2 = d11->OpenShadowRoot();
  Element* d111 = shadow_root2->QuerySelector(AtomicString("#d1-1-1"));
  Element* d112 = shadow_root2->QuerySelector(AtomicString("#d1-1-2"));
  Element* d11s1 = shadow_root2->QuerySelector(AtomicString("[name=d1-1-s1]"));
  Element* d11s2 = shadow_root2->QuerySelector(AtomicString("[name=d1-1-s2]"));

  EXPECT_TRUE(d5);
  EXPECT_TRUE(d12);
  EXPECT_TRUE(d13);
  EXPECT_TRUE(d1s0);
  EXPECT_TRUE(d1s1);
  EXPECT_TRUE(d1s2);
  EXPECT_TRUE(d11s1);
  EXPECT_TRUE(d11s2);

  EXPECT_EQ(d11, FlatTreeTraversal::Next(*d1));
  EXPECT_EQ(d111, FlatTreeTraversal::Next(*d11));
  EXPECT_EQ(d11s1, FlatTreeTraversal::Next(*d111));
  EXPECT_EQ(d1s1, FlatTreeTraversal::Next(*d11s1));
  EXPECT_EQ(d2, FlatTreeTraversal::Next(*d1s1));
  EXPECT_EQ(d14, FlatTreeTraversal::Next(*d2));
  EXPECT_EQ(d11s2, FlatTreeTraversal::Next(*d14));
  EXPECT_EQ(d112, FlatTreeTraversal::Next(*d11s2));
  EXPECT_EQ(d6, FlatTreeTraversal::Next(*d112));

  EXPECT_EQ(d112, FlatTreeTraversal::Previous(*d6));

  EXPECT_EQ(d11, FlatTreeTraversal::Parent(*d111));
  EXPECT_EQ(d11, FlatTreeTraversal::Parent(*d112));
  EXPECT_EQ(d1s1, FlatTreeTraversal::Parent(*d2));
  EXPECT_EQ(d11s1, FlatTreeTraversal::Parent(*d14));
  EXPECT_EQ(d1s2, FlatTreeTraversal::Parent(*d3));
  EXPECT_EQ(nullptr, FlatTreeTraversal::Parent(*d4));
}

TEST_F(FlatTreeTraversalTest, v1SlotInDocumentTree) {
  const char* main_html =
      "<div id='parent'>"
      "<slot>"
      "<div id='child1'></div>"
      "<div id='child2'></div>"
      "</slot>"
      "</div>";

  SetupDocumentTree(main_html);
  Element* body = GetDocument().body();
  Element* parent = body->QuerySelector(AtomicString("#parent"));
  Element* slot = body->QuerySelector(AtomicString("slot"));
  Element* child1 = body->QuerySelector(AtomicString("#child1"));
  Element* child2 = body->QuerySelector(AtomicString("#child2"));

  EXPECT_EQ(slot, FlatTreeTraversal::FirstChild(*parent));
  EXPECT_EQ(child1, FlatTreeTraversal::FirstChild(*slot));
  EXPECT_EQ(child2, FlatTreeTraversal::NextSibling(*child1));
  EXPECT_EQ(nullptr, FlatTreeTraversal::NextSibling(*child2));
  EXPECT_EQ(slot, FlatTreeTraversal::Parent(*child1));
  EXPECT_EQ(slot, FlatTreeTraversal::Parent(*child2));
  EXPECT_EQ(parent, FlatTreeTraversal::Parent(*slot));
}

TEST_F(FlatTreeTraversalTest, v1FallbackContent) {
  const char* main_html = "<div id='d1'></div>";
  const char* shadow_html =
      "<div id='before'></div>"
      "<slot><p>fallback content</p></slot>"
      "<div id='after'></div>";

  SetupDocumentTree(main_html);

  Element* body = GetDocument().body();
  Element* d1 = body->QuerySelector(AtomicString("#d1"));

  AttachOpenShadowRoot(*d1, shadow_html);
  ShadowRoot* shadow_root = d1->OpenShadowRoot();
  Element* before = shadow_root->QuerySelector(AtomicString("#before"));
  Element* after = shadow_root->QuerySelector(AtomicString("#after"));
  Element* fallback_content = shadow_root->QuerySelector(AtomicString("p"));
  Element* slot = shadow_root->QuerySelector(AtomicString("slot"));

  EXPECT_EQ(before, FlatTreeTraversal::FirstChild(*d1));
  EXPECT_EQ(after, FlatTreeTraversal::LastChild(*d1));
  EXPECT_EQ(slot, FlatTreeTraversal::Parent(*fallback_content));

  EXPECT_EQ(slot, FlatTreeTraversal::NextSibling(*before));
  EXPECT_EQ(after, FlatTreeTraversal::NextSibling(*slot));
  EXPECT_EQ(nullptr, FlatTreeTraversal::NextSibling(*fallback_content));
  EXPECT_EQ(nullptr, FlatTreeTraversal::NextSibling(*after));

  EXPECT_EQ(slot, FlatTreeTraversal::PreviousSibling(*after));
  EXPECT_EQ(before, FlatTreeTraversal::PreviousSibling(*slot));
  EXPECT_EQ(nullptr, FlatTreeTraversal::PreviousSibling(*fallback_content));
  EXPECT_EQ(nullptr, FlatTreeTraversal::PreviousSibling(*before));
}

TEST_F(FlatTreeTraversalTest, v1FallbackContentSkippedInTraversal) {
  const char* main_html = "<div id='d1'><span></span></div>";
  const char* shadow_html =
      "<div id='before'></div>"
      "<slot><p>fallback content</p></slot>"
      "<div id='after'></div>";

  SetupDocumentTree(main_html);

  Element* body = GetDocument().body();
  Element* d1 = body->QuerySelector(AtomicString("#d1"));
  Element* span = body->QuerySelector(AtomicString("span"));

  AttachOpenShadowRoot(*d1, shadow_html);
  ShadowRoot* shadow_root = d1->OpenShadowRoot();
  Element* before = shadow_root->QuerySelector(AtomicString("#before"));
  Element* after = shadow_root->QuerySelector(AtomicString("#after"));
  Element* fallback_content = shadow_root->QuerySelector(AtomicString("p"));
  Element* slot = shadow_root->QuerySelector(AtomicString("slot"));

  EXPECT_EQ(before, FlatTreeTraversal::FirstChild(*d1));
  EXPECT_EQ(after, FlatTreeTraversal::LastChild(*d1));
  EXPECT_EQ(slot, FlatTreeTraversal::Parent(*span));
  EXPECT_EQ(d1, FlatTreeTraversal::Parent(*slot));

  EXPECT_EQ(slot, FlatTreeTraversal::NextSibling(*before));
  EXPECT_EQ(after, FlatTreeTraversal::NextSibling(*slot));
  EXPECT_EQ(nullptr, FlatTreeTraversal::NextSibling(*after));

  EXPECT_EQ(slot, FlatTreeTraversal::PreviousSibling(*after));
  EXPECT_EQ(before, FlatTreeTraversal::PreviousSibling(*slot));
  EXPECT_EQ(nullptr, FlatTreeTraversal::PreviousSibling(*before));

  EXPECT_EQ(nullptr, FlatTreeTraversal::Parent(*fallback_content));
  EXPECT_EQ(nullptr, FlatTreeTraversal::NextSibling(*fallback_content));
  EXPECT_EQ(nullptr, FlatTreeTraversal::PreviousSibling(*fallback_content));
}

TEST_F(FlatTreeTraversalTest, v1AllFallbackContent) {
  const char* main_html = "<div id='d1'></div>";
  const char* shadow_html =
      "<slot name='a'><p id='x'>fallback content X</p></slot>"
      "<slot name='b'><p id='y'>fallback content Y</p></slot>"
      "<slot name='c'><p id='z'>fallback content Z</p></slot>";

  SetupDocumentTree(main_html);

  Element* body = GetDocument().body();
  Element* d1 = body->QuerySelector(AtomicString("#d1"));

  AttachOpenShadowRoot(*d1, shadow_html);
  ShadowRoot* shadow_root = d1->OpenShadowRoot();
  Element* slot_a = shadow_root->QuerySelector(AtomicString("slot[name=a]"));
  Element* slot_b = shadow_root->QuerySelector(AtomicString("slot[name=b]"));
  Element* slot_c = shadow_root->QuerySelector(AtomicString("slot[name=c]"));
  Element* fallback_x = shadow_root->QuerySelector(AtomicString("#x"));
  Element* fallback_y = shadow_root->QuerySelector(AtomicString("#y"));
  Element* fallback_z = shadow_root->QuerySelector(AtomicString("#z"));

  EXPECT_EQ(slot_a, FlatTreeTraversal::FirstChild(*d1));
  EXPECT_EQ(slot_c, FlatTreeTraversal::LastChild(*d1));

  EXPECT_EQ(fallback_x, FlatTreeTraversal::FirstChild(*slot_a));
  EXPECT_EQ(fallback_y, FlatTreeTraversal::FirstChild(*slot_b));
  EXPECT_EQ(fallback_z, FlatTreeTraversal::FirstChild(*slot_c));

  EXPECT_EQ(slot_a, FlatTreeTraversal::Parent(*fallback_x));
  EXPECT_EQ(slot_b, FlatTreeTraversal::Parent(*fallback_y));
  EXPECT_EQ(slot_c, FlatTreeTraversal::Parent(*fallback_z));
  EXPECT_EQ(d1, FlatTreeTraversal::Parent(*slot_a));

  EXPECT_EQ(nullptr, FlatTreeTraversal::NextSibling(*fallback_x));
  EXPECT_EQ(nullptr, FlatTreeTraversal::NextSibling(*fallbac
"""


```