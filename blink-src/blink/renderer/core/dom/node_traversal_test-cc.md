Response:
Let's break down the thought process to analyze the C++ test file.

1. **Understand the Goal:** The primary goal is to analyze the `node_traversal_test.cc` file and explain its purpose, its relation to web technologies (JavaScript, HTML, CSS), provide examples, discuss potential user errors, and outline debugging steps.

2. **Initial Skim for Overall Purpose:** Quickly read through the code to get a general idea. Keywords like `testing/gtest`, class names like `NodeTraversalTest`, and function names like `Next`, `Previous`, `CommonAncestor` immediately suggest it's a unit test file. The inclusion of headers like `core/dom/node_traversal.h`, `core/dom/element.h`, `core/dom/text.h`, etc., confirms it's testing DOM node traversal functionalities.

3. **Identify Core Functionality:**  The file tests functions within the `NodeTraversal` namespace. List out the functions being tested based on the test case names:
    * `NextFunctions`:  `Next`, `NextSkippingChildren`, `NextPostOrder`
    * `LastWithin`: `LastWithin`, `LastWithinOrSelf`
    * `PreviousFunctions`: `Previous`, `PreviousAbsoluteSibling`, `PreviousPostOrder`
    * `ChildAt`: `ChildAt`, `CountChildren`, `HasChildren`, `Index`, `IsDescendantOf`
    * `Siblings`: `FirstChild`, `LastChild`, `NextSibling`, `PreviousSibling`, `Parent`
    * `commonAncestor`: `CommonAncestor`
    * `AncestorsOf`: `AncestorsOf`
    * `InclusiveAncestorsOf`: `InclusiveAncestorsOf`
    * `ChildrenOf`: `ChildrenOf`
    * `DescendantsOf`: `DescendantsOf`
    * `InclusiveDescendantsOf`: `InclusiveDescendantsOf`

4. **Relate to Web Technologies (JavaScript, HTML, CSS):** Now connect these C++ functions to their counterparts or related concepts in web development:
    * **HTML:** The tests heavily rely on creating and traversing HTML structures. The `SetupSampleHTML` function confirms this. Think about how these traversals map to how JavaScript interacts with the DOM.
    * **JavaScript:**  JavaScript's DOM API has similar methods like `parentNode`, `childNodes`, `firstChild`, `nextSibling`, `previousSibling`, `getElementById`, `querySelector`, etc. The C++ tests are essentially verifying the underlying implementation of these concepts.
    * **CSS:** While the test file doesn't directly manipulate CSS, CSS selectors are used in JavaScript (and potentially internally in Blink) to target elements. The `QuerySelector` calls are a direct link to this. The order of elements, which traversal functions deal with, *can* indirectly influence how CSS rules are applied (e.g., adjacent sibling selectors).

5. **Provide Concrete Examples:** For each group of test cases (or individual functions if needed), create simple HTML snippets and explain how the tested functions would behave on those snippets. This makes the abstract C++ functions more tangible. Use the `SetupSampleHTML` logic as a basis for these examples.

6. **Logical Reasoning (Input/Output):** For each test case, consider the setup HTML and the specific function being tested. Predict the expected output based on the function's name and the structure of the HTML. The `EXPECT_EQ` calls in the test code provide strong clues about the intended behavior. Formalize this with "Assume input X, the function should return Y."

7. **Common Usage Errors:** Think about how a developer using JavaScript's DOM API might make mistakes related to node traversal. Common errors include:
    * Assuming a node *always* has a next/previous sibling.
    * Not handling cases where `firstChild` or `lastChild` might be null.
    * Incorrectly iterating through children.
    * Forgetting that the DOM tree can change dynamically.

8. **Debugging Steps (User Operations):**  Imagine a scenario where a web page isn't behaving as expected due to DOM manipulation issues. Trace the user's actions that might lead to the execution of the traversal logic being tested:
    * A user interacts with a button, triggering a JavaScript function.
    * This JavaScript function manipulates the DOM, perhaps by adding, removing, or reordering elements.
    * The Blink rendering engine (where this C++ code resides) then uses its internal node traversal logic to update the rendering tree.

9. **Structure and Refine:** Organize the information logically. Start with the overall function, then dive into specific functionalities, their relation to web technologies, examples, reasoning, errors, and debugging. Use clear headings and bullet points to improve readability. Ensure the language is clear and avoids overly technical jargon where possible.

10. **Review and Verify:** After drafting the explanation, review it for accuracy and completeness. Double-check the examples and the mapping to web technologies. Make sure the explanation addresses all aspects of the prompt. For instance, ensure the explanation explicitly mentions the `NodeTraversal` namespace and that these are *unit tests* for that functionality.

**Self-Correction Example During the Process:**

Initially, I might focus too heavily on the C++ implementation details. Then, I'd realize the prompt asks about the *relationship* to JavaScript, HTML, and CSS. This would prompt me to shift focus and provide more concrete examples in those technologies, rather than just explaining the C++ code. Similarly, if I initially missed some of the tested functions, a closer reading of the test case names would help me correct that. I might also initially forget to explicitly mention the purpose of the `RemoveWhiteSpaceOnlyTextNodes` function and would add that upon rereading the code.
这个文件 `blink/renderer/core/dom/node_traversal_test.cc` 是 Chromium Blink 渲染引擎中的一个 **单元测试文件**。它的主要功能是 **测试 `blink/renderer/core/dom/node_traversal.h` 中定义的关于 DOM 节点遍历的各种实用工具函数**。

**具体功能列举:**

这个文件包含了多个测试用例 (Test Case)，每个测试用例针对 `NodeTraversal` 类中的一个或多个静态成员函数进行测试。这些函数主要用于在 DOM 树中进行各种形式的节点遍历，例如：

* **向前遍历:**
    * `Next()`: 返回树中按照深度优先、先序遍历的下一个节点。
    * `NextSkippingChildren()`: 返回树中按照深度优先、先序遍历的下一个兄弟节点或祖先节点的下一个兄弟节点，跳过当前节点的子节点。
    * `NextPostOrder()`: 返回树中按照深度优先、后序遍历的下一个节点。
* **向后遍历:**
    * `Previous()`: 返回树中按照深度优先、先序遍历的上一个节点。
    * `PreviousAbsoluteSibling()`: 返回树中与当前节点拥有相同父节点的上一个兄弟节点，忽略文档顺序。
    * `PreviousPostOrder()`: 返回树中按照深度优先、后序遍历的上一个节点。
* **获取特定位置的子节点:**
    * `ChildAt()`: 返回指定索引位置的子节点。
* **获取节点的属性:**
    * `CountChildren()`: 返回子节点的数量。
    * `HasChildren()`: 判断是否有子节点。
    * `Index()`: 返回节点在其父节点中的索引。
* **判断节点关系:**
    * `IsDescendantOf()`: 判断一个节点是否是另一个节点的后代。
* **获取节点的亲属节点:**
    * `FirstChild()`: 返回第一个子节点。
    * `LastChild()`: 返回最后一个子节点。
    * `NextSibling()`: 返回下一个兄弟节点。
    * `PreviousSibling()`: 返回上一个兄弟节点。
    * `Parent()`: 返回父节点。
* **获取共同祖先:**
    * `CommonAncestor()`: 返回两个节点的最近公共祖先节点。
* **获取祖先/后代节点集合:**
    * `AncestorsOf()`: 返回一个迭代器，遍历给定节点的所有祖先节点（不包括自身）。
    * `InclusiveAncestorsOf()`: 返回一个迭代器，遍历给定节点的所有祖先节点（包括自身）。
    * `ChildrenOf()`: 返回一个迭代器，遍历给定节点的所有直接子节点。
    * `DescendantsOf()`: 返回一个迭代器，遍历给定节点的所有后代节点（不包括自身）。
    * `InclusiveDescendantsOf()`: 返回一个迭代器，遍历给定节点的所有后代节点（包括自身）。
* **获取指定范围内的最后一个节点:**
    * `LastWithin()`: 返回指定节点的后代中，文档顺序的最后一个节点（不包括自身）。
    * `LastWithinOrSelf()`: 返回指定节点的后代中，文档顺序的最后一个节点（包括自身）。

**与 JavaScript, HTML, CSS 的关系以及举例说明:**

这个测试文件直接关系到浏览器如何理解和操作 HTML 结构，这与 JavaScript 和 CSS 的功能紧密相关。

* **HTML:**  `node_traversal_test.cc` 通过 `SetupSampleHTML` 函数创建各种 HTML 结构，然后利用 `NodeTraversal` 中的函数在这些结构中进行导航。例如，测试 `Next()` 函数时，会创建一个包含多个 `div` 元素的 HTML 片段，然后断言从某个 `div` 元素调用 `Next()` 应该返回哪个 `div` 元素。

    ```html
    <div id='c0'>
        <div id='c00'></div>
        <div id='c01'></div>
    </div>
    <div id='c1'>
        <div id='c10'></div>
    </div>
    ```

    在 JavaScript 中，我们可以使用类似的 DOM API 进行节点遍历，例如 `element.nextElementSibling`, `element.firstChild`, `element.parentNode` 等。`NodeTraversal` 中的函数是这些 JavaScript DOM API 的底层实现逻辑的一部分。

* **JavaScript:** JavaScript 代码可以通过 DOM API 来访问和操作 HTML 文档的结构。`NodeTraversal` 中测试的函数为这些 API 提供了基础。例如，JavaScript 中的 `Node.parentNode` 方法的功能与 `NodeTraversal::Parent()` 类似。当 JavaScript 代码执行 `element.parentNode` 时，Blink 引擎内部可能会调用类似的底层遍历函数来找到父节点。

    ```javascript
    // JavaScript 示例
    const c00 = document.getElementById('c00');
    const c0 = c00.parentNode; // 相当于 NodeTraversal::Parent(*c00)
    const c01 = c00.nextElementSibling; // 相当于 NodeTraversal::NextSibling(*c00)
    ```

* **CSS:** 虽然这个测试文件不直接涉及 CSS 样式计算，但 DOM 结构的遍历对于 CSS 选择器的匹配至关重要。CSS 选择器（如后代选择器、相邻兄弟选择器等）的匹配过程依赖于在 DOM 树中进行遍历。例如，当浏览器需要判断某个元素是否匹配 `div > p` 选择器时，就需要遍历 `div` 元素的子节点来查找 `p` 元素。`NodeTraversal` 中的函数就参与了这个遍历过程。

**逻辑推理与假设输入输出:**

以 `CommonAncestor` 测试用例为例：

**假设输入:** 两个不同的 `Element` 节点，分别对应 HTML 结构中的 `#c000` 和 `#c01` 元素。

```html
<div id='c0'>
    <div id='c00'>
        <div id='c000'></div>
    </div>
    <div id='c01'></div>
</div>
```

**逻辑推理:**  `#c000` 的祖先是 `#c00` 和 `#c0`。 `#c01` 的祖先是 `#c0`。 因此，它们的最近公共祖先是 `#c0` 对应的 `Element` 节点。

**预期输出:** `NodeTraversal::CommonAncestor(*c000, *c01)` 应该返回指向 `#c0` 对应 `Element` 节点的指针。

测试代码中的 `TestCommonAncestor` 函数就是用来验证这种逻辑的：

```c++
void TestCommonAncestor(Node* expected_result,
                        const Node& node_a,
                        const Node& node_b) {
  Node* result1 = NodeTraversal::CommonAncestor(node_a, node_b);
  EXPECT_EQ(expected_result, result1)
      << "CommonAncestor(" << node_a.textContent() << ","
      << node_b.textContent() << ")";
  // ...
}

TEST_F(NodeTraversalTest, commonAncestor) {
  // ...
  TestCommonAncestor(c0, *c000, *c01);
  // ...
}
```

**用户或编程常见的使用错误举例:**

* **假设子节点总是存在:** 开发者在 JavaScript 中使用 `element.firstChild` 或 `element.lastChild` 时，如果没有检查返回值是否为 `null`，当元素没有子节点时就会导致错误。`NodeTraversal` 中的 `FirstChild` 和 `LastChild` 函数的实现需要正确处理这种情况。
* **错误的循环遍历:** 在 JavaScript 中使用循环遍历子节点时，可能会因为在循环中修改了 DOM 结构（例如添加或删除节点）而导致遍历错误或无限循环。`NodeTraversal` 中的迭代器（如 `ChildrenOf` 和 `DescendantsOf` 返回的迭代器）需要设计成能够安全地处理这种动态修改。
* **混淆不同类型的遍历:** 开发者可能会混淆先序遍历和后序遍历，导致在处理节点时的顺序不符合预期。例如，在某些需要先处理子节点再处理父节点的场景下，使用了先序遍历。`NodeTraversal` 提供了多种遍历方式，需要确保其实现的正确性，以便上层 API 可以根据需要选择合适的遍历方式。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户在浏览器中加载一个包含复杂 HTML 结构的网页。**
2. **网页上的 JavaScript 代码执行，例如响应用户的点击事件。**
3. **JavaScript 代码通过 DOM API 操作 DOM 结构，例如添加、删除、移动元素。**  例如，点击一个按钮可能会触发 JavaScript 代码创建一个新的 `div` 元素并将其插入到 DOM 树的某个位置。
4. **浏览器渲染引擎 (Blink) 需要更新渲染树以反映 DOM 的变化。**
5. **在更新渲染树的过程中，Blink 引擎会使用 `blink/renderer/core/dom/node_traversal.h` 中定义的函数来遍历 DOM 树，查找需要更新的节点，并确定它们的父节点、子节点、兄弟节点等关系。**  例如，当插入一个新的子节点时，引擎需要使用 `Parent()` 函数找到父节点，并可能使用 `CountChildren()` 和 `ChildAt()` 来更新父节点的子节点列表。
6. **如果在这个过程中，`NodeTraversal` 中的某个函数出现了 bug，例如返回了错误的下一个节点或父节点，就会导致渲染错误或 JavaScript 代码的行为异常。**
7. **作为调试线索，开发者可能会在 Blink 引擎的源代码中设置断点，例如在 `NodeTraversal::Next()` 函数内部，来跟踪 DOM 遍历的过程，查看在特定的用户操作下，遍历函数是如何被调用，以及返回了哪些节点，从而找到问题的根源。**  `node_traversal_test.cc` 中提供的单元测试可以帮助开发者在开发阶段就发现和修复这些潜在的 bug。

总而言之，`blink/renderer/core/dom/node_traversal_test.cc` 是确保 Blink 引擎正确理解和操作 DOM 结构的关键部分，它直接影响着网页的渲染和 JavaScript 代码的执行。通过详尽的单元测试，可以提高 Blink 引擎的稳定性和可靠性。

Prompt: 
```
这是目录为blink/renderer/core/dom/node_traversal_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/dom/node_traversal.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"

namespace blink {
namespace node_traversal_test {

namespace {

template <class T>
HeapVector<Member<Node>> CollectFromIterable(T iterable) {
  HeapVector<Member<Node>> nodes;
  for (auto& node : iterable)
    nodes.push_back(&node);
  return nodes;
}

void RemoveWhiteSpaceOnlyTextNodes(ContainerNode& container) {
  for (Node* descendant :
       CollectFromIterable(NodeTraversal::InclusiveDescendantsOf(container))) {
    if (auto* text = DynamicTo<Text>(descendant)) {
      if (text->ContainsOnlyWhitespaceOrEmpty())
        text->remove();
    }
  }
}

}  // namespace

class NodeTraversalTest : public PageTestBase {
 public:
  NodeTraversalTest() {}

 protected:
  void SetupSampleHTML(const char* html);
};

void NodeTraversalTest::SetupSampleHTML(const char* html) {
  Element* body = GetDocument().body();
  SetBodyInnerHTML(String::FromUTF8(html));
  RemoveWhiteSpaceOnlyTextNodes(*body);
}

namespace {

void TestCommonAncestor(Node* expected_result,
                        const Node& node_a,
                        const Node& node_b) {
  Node* result1 = NodeTraversal::CommonAncestor(node_a, node_b);
  EXPECT_EQ(expected_result, result1)
      << "CommonAncestor(" << node_a.textContent() << ","
      << node_b.textContent() << ")";
  Node* result2 = NodeTraversal::CommonAncestor(node_b, node_a);
  EXPECT_EQ(expected_result, result2)
      << "CommonAncestor(" << node_b.textContent() << ","
      << node_a.textContent() << ")";
}

}  // namespace

// Test case for
//  - Next
//  - NextSkippingChildren
//  - NextPostOrder
TEST_F(NodeTraversalTest, NextFunctions) {
  SetupSampleHTML(R"(
      <div id='c0'>
        <div id='c00'></div>
        <div id='c01'></div>
      </div>
      <div id='c1'>
        <div id='c10'></div>
      </div>)");

  Element* html = GetDocument().documentElement();
  Element* body = GetDocument().body();
  Element* c0 = body->QuerySelector(AtomicString("#c0"));
  Element* c1 = body->QuerySelector(AtomicString("#c1"));
  Element* c00 = body->QuerySelector(AtomicString("#c00"));
  Element* c01 = body->QuerySelector(AtomicString("#c01"));
  Element* c10 = body->QuerySelector(AtomicString("#c10"));

  EXPECT_EQ(c0, NodeTraversal::Next(*body));
  EXPECT_EQ(c00, NodeTraversal::Next(*c0));
  EXPECT_EQ(c01, NodeTraversal::Next(*c00));
  EXPECT_EQ(c1, NodeTraversal::Next(*c01));
  EXPECT_EQ(c10, NodeTraversal::Next(*c1));
  EXPECT_EQ(nullptr, NodeTraversal::Next(*c10));

  EXPECT_EQ(nullptr, NodeTraversal::NextSkippingChildren(*body));
  EXPECT_EQ(c1, NodeTraversal::NextSkippingChildren(*c0));
  EXPECT_EQ(c01, NodeTraversal::NextSkippingChildren(*c00));
  EXPECT_EQ(c1, NodeTraversal::NextSkippingChildren(*c01));
  EXPECT_EQ(nullptr, NodeTraversal::NextSkippingChildren(*c1));
  EXPECT_EQ(nullptr, NodeTraversal::Next(*c10));

  EXPECT_EQ(html, NodeTraversal::NextPostOrder(*body));
  EXPECT_EQ(c10, NodeTraversal::NextPostOrder(*c0));
  EXPECT_EQ(body, NodeTraversal::NextPostOrder(*c1));
  EXPECT_EQ(c01, NodeTraversal::NextPostOrder(*c00));
  EXPECT_EQ(c0, NodeTraversal::NextPostOrder(*c01));
  EXPECT_EQ(c1, NodeTraversal::NextPostOrder(*c10));
}

// Test case for
//  - LastWithin
//  - LastWithinOrSelf
TEST_F(NodeTraversalTest, LastWithin) {
  SetupSampleHTML(R"(
      <div id='c0'>
        <div id='c00'></div>
      </div>
      <div id='c1'></div>)");

  Element* body = GetDocument().body();
  Element* c0 = body->QuerySelector(AtomicString("#c0"));
  Element* c1 = body->QuerySelector(AtomicString("#c1"));
  Element* c00 = body->QuerySelector(AtomicString("#c00"));

  EXPECT_EQ(c1, NodeTraversal::LastWithin(*body));
  EXPECT_EQ(c1, NodeTraversal::LastWithinOrSelf(*body));

  EXPECT_EQ(c00, NodeTraversal::LastWithin(*c0));
  EXPECT_EQ(c00, NodeTraversal::LastWithinOrSelf(*c0));

  EXPECT_EQ(nullptr, NodeTraversal::LastWithin(*c1));
  EXPECT_EQ(c1, NodeTraversal::LastWithinOrSelf(*c1));
}

// Test case for
//  - Previous
//  - PreviousAbsoluteSibling
//  - PreviousPostOrder
TEST_F(NodeTraversalTest, PreviousFunctions) {
  SetupSampleHTML(R"(
      <div id='c0'>
        <div id='c00'></div>
        <div id='c01'></div>
      </div>
      <div id='c1'>
        <div id='c10'></div>
      </div>)");

  Element* html = GetDocument().documentElement();
  Element* head = GetDocument().head();
  Element* body = GetDocument().body();
  Element* c0 = body->QuerySelector(AtomicString("#c0"));
  Element* c1 = body->QuerySelector(AtomicString("#c1"));
  Element* c00 = body->QuerySelector(AtomicString("#c00"));
  Element* c01 = body->QuerySelector(AtomicString("#c01"));
  Element* c10 = body->QuerySelector(AtomicString("#c10"));

  EXPECT_EQ(head, NodeTraversal::Previous(*body));
  EXPECT_EQ(body, NodeTraversal::Previous(*c0));
  EXPECT_EQ(c0, NodeTraversal::Previous(*c00));
  EXPECT_EQ(c00, NodeTraversal::Previous(*c01));
  EXPECT_EQ(c01, NodeTraversal::Previous(*c1));
  EXPECT_EQ(c1, NodeTraversal::Previous(*c10));

  EXPECT_EQ(nullptr, NodeTraversal::PreviousAbsoluteSibling(*html));
  EXPECT_EQ(head, NodeTraversal::PreviousAbsoluteSibling(*body));
  EXPECT_EQ(head, NodeTraversal::PreviousAbsoluteSibling(*c0));
  EXPECT_EQ(head, NodeTraversal::PreviousAbsoluteSibling(*c00));
  EXPECT_EQ(c00, NodeTraversal::PreviousAbsoluteSibling(*c01));
  EXPECT_EQ(c0, NodeTraversal::PreviousAbsoluteSibling(*c1));
  EXPECT_EQ(c0, NodeTraversal::PreviousAbsoluteSibling(*c10));

  EXPECT_EQ(c1, NodeTraversal::PreviousPostOrder(*body));
  EXPECT_EQ(c01, NodeTraversal::PreviousPostOrder(*c0));
  EXPECT_EQ(c10, NodeTraversal::PreviousPostOrder(*c1));
  EXPECT_EQ(head, NodeTraversal::PreviousPostOrder(*c00));
  EXPECT_EQ(c00, NodeTraversal::PreviousPostOrder(*c01));
  EXPECT_EQ(c0, NodeTraversal::PreviousPostOrder(*c10));
}

// Test case for
//  - ChildAt
//  - CountChildren
//  - HasChildren
//  - Index
//  - IsDescendantOf
TEST_F(NodeTraversalTest, ChildAt) {
  SetupSampleHTML(R"(
      <div id='c0'>
        <span id='c00'>c00</span>
      </div>
      <div id='c1'></div>
      <div id='c2'></div>)");

  Element* body = GetDocument().body();
  Element* c0 = body->QuerySelector(AtomicString("#c0"));
  Element* c1 = body->QuerySelector(AtomicString("#c1"));
  Element* c2 = body->QuerySelector(AtomicString("#c2"));
  Element* c00 = body->QuerySelector(AtomicString("#c00"));

  const unsigned kNumberOfChildNodes = 3;
  Node* expected_child_nodes[3] = {c0, c1, c2};

  ASSERT_EQ(kNumberOfChildNodes, NodeTraversal::CountChildren(*body));
  EXPECT_TRUE(NodeTraversal::HasChildren(*body));

  for (unsigned index = 0; index < kNumberOfChildNodes; ++index) {
    Node* child = NodeTraversal::ChildAt(*body, index);
    EXPECT_EQ(index, NodeTraversal::Index(*child))
        << "NodeTraversal::index(NodeTraversal(*body, " << index << "))";
    EXPECT_TRUE(NodeTraversal::IsDescendantOf(*child, *body))
        << "NodeTraversal::isDescendantOf(*NodeTraversal(*body, " << index
        << "), *body)";
    EXPECT_EQ(expected_child_nodes[index], child)
        << "NodeTraversal::childAt(*body, " << index << ")";
  }
  EXPECT_EQ(nullptr, NodeTraversal::ChildAt(*body, kNumberOfChildNodes + 1))
      << "Out of bounds childAt() returns nullptr.";

  EXPECT_EQ(c00, NodeTraversal::FirstChild(*c0));
}

// Test case for
//  - FirstChild
//  - LastChild
//  - NextSibling
//  - PreviousSibling
//  - Parent
TEST_F(NodeTraversalTest, Siblings) {
  SetupSampleHTML(R"(
      <div id='c0'></div>
      <div id='c1'></div>
      <div id='c2'></div>)");

  Element* body = GetDocument().body();
  Element* c0 = body->QuerySelector(AtomicString("#c0"));
  Element* c1 = body->QuerySelector(AtomicString("#c1"));
  Element* c2 = body->QuerySelector(AtomicString("#c2"));

  EXPECT_EQ(c0, NodeTraversal::FirstChild(*body));
  EXPECT_EQ(c2, NodeTraversal::LastChild(*body));

  EXPECT_EQ(body, NodeTraversal::Parent(*c0));
  EXPECT_EQ(body, NodeTraversal::Parent(*c1));
  EXPECT_EQ(body, NodeTraversal::Parent(*c2));

  EXPECT_EQ(c1, NodeTraversal::NextSibling(*c0));
  EXPECT_EQ(c2, NodeTraversal::NextSibling(*c1));
  EXPECT_EQ(nullptr, NodeTraversal::NextSibling(*c2));

  EXPECT_EQ(c1, NodeTraversal::PreviousSibling(*c2));
  EXPECT_EQ(c0, NodeTraversal::PreviousSibling(*c1));
  EXPECT_EQ(nullptr, NodeTraversal::PreviousSibling(*c0));
}

TEST_F(NodeTraversalTest, commonAncestor) {
  SetupSampleHTML(R"(
      <div id='c0'>
        <div id='c00'>
          <div id='c000'></div>
        </div>
        <div id='c01'></div>
      </div>
      <div id='c1'>
        <div id='c10'></div>
      </div>
      <div id='c2'></div>)");

  Element* body = GetDocument().body();
  Element* c0 = body->QuerySelector(AtomicString("#c0"));
  Element* c1 = body->QuerySelector(AtomicString("#c1"));
  Element* c2 = body->QuerySelector(AtomicString("#c2"));

  Element* c00 = body->QuerySelector(AtomicString("#c00"));
  Element* c01 = body->QuerySelector(AtomicString("#c01"));
  Element* c10 = body->QuerySelector(AtomicString("#c10"));
  Element* c000 = body->QuerySelector(AtomicString("#c000"));

  TestCommonAncestor(body, *c0, *c1);
  TestCommonAncestor(body, *c1, *c2);
  TestCommonAncestor(body, *c00, *c10);
  TestCommonAncestor(body, *c01, *c10);
  TestCommonAncestor(body, *c2, *c10);
  TestCommonAncestor(body, *c2, *c000);

  TestCommonAncestor(c0, *c00, *c01);
  TestCommonAncestor(c0, *c000, *c01);
  TestCommonAncestor(c1, *c1, *c10);
}

TEST_F(NodeTraversalTest, AncestorsOf) {
  SetupSampleHTML(R"(
      <div>
        <div>
          <div id='child'></div>
        </div>
      </div>)");

  Element* child = GetDocument().getElementById(AtomicString("child"));

  HeapVector<Member<Node>> expected_nodes;
  for (Node* parent = NodeTraversal::Parent(*child); parent;
       parent = NodeTraversal::Parent(*parent)) {
    expected_nodes.push_back(parent);
  }

  HeapVector<Member<Node>> actual_nodes;
  for (Node& ancestor : NodeTraversal::AncestorsOf(*child))
    actual_nodes.push_back(&ancestor);

  EXPECT_EQ(expected_nodes, actual_nodes);
}

TEST_F(NodeTraversalTest, InclusiveAncestorsOf) {
  SetupSampleHTML(R"(
      <div>
        <div>
          <div id='child'></div>
        </div>
      </div>)");

  Element* child = GetDocument().getElementById(AtomicString("child"));

  HeapVector<Member<Node>> expected_nodes;
  for (Node* parent = child; parent; parent = NodeTraversal::Parent(*parent)) {
    expected_nodes.push_back(parent);
  }

  HeapVector<Member<Node>> actual_nodes;
  for (Node& ancestor : NodeTraversal::InclusiveAncestorsOf(*child))
    actual_nodes.push_back(&ancestor);

  EXPECT_EQ(expected_nodes, actual_nodes);
}

TEST_F(NodeTraversalTest, ChildrenOf) {
  SetupSampleHTML(R"(
      <div id='c0'></div>
      <div id='c1'></div>
      <div id='c2'></div>)");

  Element* body = GetDocument().body();

  HeapVector<Member<Node>> expected_nodes;
  for (Node* child = NodeTraversal::FirstChild(*body); child;
       child = NodeTraversal::NextSibling(*child)) {
    expected_nodes.push_back(child);
  }

  HeapVector<Member<Node>> actual_nodes;
  for (Node& child : NodeTraversal::ChildrenOf(*body))
    actual_nodes.push_back(&child);

  EXPECT_EQ(expected_nodes, actual_nodes);
}

TEST_F(NodeTraversalTest, DescendantsOf) {
  SetupSampleHTML(R"(
      <div id='c0'>
        <div id='c00'></div>
        <div id='c01'></div>
      </div>
      <div id='c1'>
        <div id='c10'></div>
      </div>)");

  Element* body = GetDocument().body();

  HeapVector<Member<Node>> expected_nodes;
  for (Node* child = NodeTraversal::FirstChild(*body); child;
       child = NodeTraversal::Next(*child)) {
    expected_nodes.push_back(child);
  }

  HeapVector<Member<Node>> actual_nodes;
  for (Node& descendant : NodeTraversal::DescendantsOf(*body))
    actual_nodes.push_back(&descendant);

  EXPECT_EQ(expected_nodes, actual_nodes);
}

TEST_F(NodeTraversalTest, InclusiveDescendantsOf) {
  SetupSampleHTML(R"(
      <div id='c0'>
        <div id='c00'></div>
        <div id='c01'></div>
      </div>
      <div id='c1'>
        <div id='c10'></div>
      </div>)");

  Element* body = GetDocument().body();

  HeapVector<Member<Node>> expected_nodes;
  for (Node* child = body; child; child = NodeTraversal::Next(*child)) {
    expected_nodes.push_back(child);
  }

  HeapVector<Member<Node>> actual_nodes;
  for (Node& descendant : NodeTraversal::InclusiveDescendantsOf(*body))
    actual_nodes.push_back(&descendant);

  EXPECT_EQ(expected_nodes, actual_nodes);
}

}  // namespace node_traversal_test
}  // namespace blink

"""

```