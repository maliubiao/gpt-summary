Response:
Let's break down the thought process for analyzing the `ephemeral_range_test.cc` file and generating the comprehensive answer.

1. **Understanding the Core Purpose:** The first step is to recognize the file name and the `#include` directives. `ephemeral_range_test.cc` strongly suggests this is a unit test file specifically for the `EphemeralRange` class. The includes for `<sstream>`, `"third_party/blink/renderer/core/dom/range.h"`, and `"third_party/blink/renderer/core/editing/testing/editing_test_base.h"` confirm this. The `EditingTestBase` inclusion hints at tests involving DOM manipulation.

2. **Identifying Key Classes and Concepts:**  The file heavily uses `EphemeralRange`, `Range`, `Position`, `Node`, `Element`, `Text`, and `ShadowRoot`. These are fundamental DOM-related concepts within Blink. The presence of `FlatTreeTraversal` indicates interaction with Shadow DOM.

3. **Analyzing the Test Structure:**  The `EphemeralRangeTest` class inherits from `EditingTestBase`, indicating a standard testing setup within Blink's editing framework. The `protected` members `TraverseRange` and `GetBodyRange` are helper functions for the tests. The `TEST_F` macros mark individual test cases.

4. **Deconstructing Each Test Case:** The most crucial part is to go through each `TEST_F` and understand what it's testing:

    * **`rangeTraversalDOM`:** This tests basic DOM traversal with `EphemeralRange`. It sets up a simple DOM structure and verifies that traversing using `EphemeralRange` yields the same sequence of nodes as a manual loop using `Range::FirstNode()` and `Traversal::Next()`. This confirms the fundamental iteration mechanism works correctly for the regular DOM tree. The direct relation to HTML structure is obvious here.

    * **`rangeShadowTraversal`:** This introduces Shadow DOM. It sets up a structure with a shadow host and slotted content. The test verifies that `EphemeralRangeInFlatTree` correctly traverses the *flattened* tree, including nodes within the shadow root and respecting slot distribution. The key here is understanding how Shadow DOM impacts node traversal.

    * **`rangeTraversalLimitedDOM`:** This tests the behavior of `EphemeralRange` when the underlying `Range` has specific start and end points, effectively limiting the traversal. It demonstrates how to create such ranges and verifies that the traversal is restricted as expected.

    * **`rangeTraversalLimitedFlatTree`:** Similar to the previous test, but focuses on `EphemeralRangeInFlatTree` with explicitly set start and end `PositionInFlatTree` within a Shadow DOM context. This reinforces the interaction of `EphemeralRangeInFlatTree` with Shadow DOM boundaries.

    * **`traversalEmptyRanges`:** This handles edge cases: an empty `EphemeralRange` and a collapsed range (where start and end are the same). It verifies that iteration does not occur in these scenarios, ensuring robustness.

    * **`commonAncesstorDOM`:** This tests the `CommonAncestorContainer()` method for a simple DOM structure. It confirms that the method correctly identifies the nearest common ancestor of the start and end positions.

    * **`commonAncesstorFlatTree`:**  Similar to the previous test, but within a Shadow DOM context. It validates that `CommonAncestorContainer()` on `EphemeralRangeInFlatTree` correctly identifies the common ancestor in the flattened tree.

    * **`EquivalentPositions`:** This delves into the concept of equivalent but not identical positions in the DOM (e.g., after one node and before the next). It checks that `EphemeralRange` handles these equivalent positions correctly, particularly for collapsed ranges.

5. **Identifying Connections to Web Technologies:** Throughout the analysis, the connections to HTML, JavaScript, and CSS become clear:

    * **HTML:** The test cases directly manipulate HTML structures using `SetBodyContent` and `SetShadowContent`. The node types (`<p>`, `<b>`, `<span>`, `#text`) are all HTML elements and text nodes.
    * **JavaScript:** While the tests are in C++, they are testing functionality that is often used and manipulated by JavaScript in a web browser. JavaScript's `document.createRange()`, `Selection` API, and DOM manipulation methods heavily rely on the underlying concepts being tested here (ranges and node traversal).
    * **CSS:** Although not directly tested *by this file*, CSS's influence is present through Shadow DOM's styling encapsulation. The way content is distributed through slots is affected by CSS selectors.

6. **Considering User and Programmer Errors:** Based on the tested scenarios, potential errors can be inferred:

    * **Incorrect Range Boundaries:**  Programmers might accidentally create `Range` objects with incorrect start or end points, leading to unexpected traversal results. This is precisely what the "Limited Range" tests address.
    * **Misunderstanding Shadow DOM Traversal:** Developers unfamiliar with Shadow DOM might expect regular DOM traversal to work within shadow trees, leading to incorrect assumptions about which elements are included in a range. The `rangeShadowTraversal` and `rangeTraversalLimitedFlatTree` tests highlight this.
    * **Assuming Non-Equivalent Positions are Always Different:** The `EquivalentPositions` test demonstrates that comparing positions directly might not be sufficient; using `IsEquivalent()` is crucial.

7. **Tracing User Actions (Debugging):** To illustrate how a user action might lead to this code, consider a text selection scenario:

    * **User Action:** A user drags their mouse across a portion of text on a web page. This selection might span across Shadow DOM boundaries.
    * **Browser Event:** The browser captures the `mouseup` event.
    * **Selection Object:**  The browser's selection object is updated, creating a `Range` object internally representing the selected text.
    * **EphemeralRange Usage (Internal):**  Blink's internal rendering and editing logic might use `EphemeralRange` (or its underlying mechanisms) to:
        * Iterate over the selected nodes to apply formatting.
        * Determine the common ancestor for applying styles.
        * Implement copy/paste functionality.
        * Handle drag-and-drop operations.

8. **Structuring the Answer:** Finally, the information needs to be organized clearly, following the prompt's requirements: listing functionalities, explaining relationships with web technologies, providing examples, outlining potential errors, and illustrating the debugging context. Using clear headings and bullet points improves readability.

By following these steps, combining code analysis with knowledge of web technologies and potential pitfalls, a comprehensive and accurate answer can be generated.
这个文件 `ephemeral_range_test.cc` 是 Chromium Blink 引擎中用于测试 `EphemeralRange` 类的单元测试文件。 `EphemeralRange` 是一个轻量级的、临时的 DOM 范围表示，它通常用于编辑操作中，避免频繁创建和销毁重量级的 `Range` 对象。

**主要功能:**

1. **测试 `EphemeralRange` 的基本创建和属性访问:**  虽然代码中没有显式地测试创建，但它通过使用 `EphemeralRange(GetBodyRange())` 等方式间接地测试了 `EphemeralRange` 的构造。它也测试了诸如 `IsCollapsed()`, `StartPosition()`, `EndPosition()`, `CommonAncestorContainer()` 等属性的访问。

2. **测试 `EphemeralRange` 的节点遍历功能:** 这是这个测试文件的核心功能。它验证了 `EphemeralRange` 提供的节点迭代器 (`Nodes()`) 能否正确地遍历指定范围内的所有节点，包括在 Shadow DOM 中的节点。

3. **测试不同类型的节点遍历:**
   - **DOM 树遍历:**  测试了在普通的 DOM 树结构中，`EphemeralRange` 能否按照预期的顺序遍历节点。
   - **Flat 树遍历 (Shadow DOM):** 测试了在包含 Shadow DOM 的结构中，`EphemeralRangeInFlatTree` 能否按照扁平树的顺序正确遍历节点，包括 Shadow Host、Shadow Root 和 Slot 分配的节点。

4. **测试有限范围的遍历:** 验证了当 `EphemeralRange` 基于一个有限的 `Range` 对象创建时，其节点遍历是否仅限于指定的起始和结束位置之间。

5. **测试空范围和单点范围:**  测试了当 `EphemeralRange` 表示一个空范围（起始和结束位置相同）或单点位置时，其节点遍历行为是否符合预期（不产生任何节点）。

6. **测试获取公共祖先容器:**  验证了 `EphemeralRange` 的 `CommonAncestorContainer()` 方法能否正确地找到指定范围内起始和结束位置的最近公共祖先容器。

7. **测试等效位置的处理:**  测试了当使用等效但不同的 `Position` 对象创建 `EphemeralRange` 时，其行为是否一致，特别是对于折叠的范围。

**与 JavaScript, HTML, CSS 的关系:**

`EphemeralRange` 本身是 Blink 引擎内部的 C++ 类，JavaScript、HTML 和 CSS 并不能直接操作它。然而，`EphemeralRange` 的功能是服务于浏览器中与这三者密切相关的操作，特别是编辑相关的操作。

* **HTML:**  测试用例中大量使用了 HTML 结构来创建测试场景，例如 `<p>`, `<b>`, `<span>` 元素，以及 `id` 属性。这些 HTML 结构是 `EphemeralRange` 进行节点遍历的基础。
    * **举例:** 在 `rangeTraversalDOM` 测试中，`SetBodyContent` 设置的 HTML 结构决定了 `EphemeralRange` 遍历的节点顺序和内容。

* **JavaScript:** JavaScript 可以通过 DOM API (如 `document.createRange()`, `Selection` API) 创建和操作 `Range` 对象。 `EphemeralRange` 通常作为这些 `Range` 对象的轻量级替代品在 Blink 内部使用，来优化性能。用户通过 JavaScript 操作 DOM 可能会间接地触发使用 `EphemeralRange` 的 Blink 内部逻辑。
    * **举例:** 当用户在网页上使用鼠标拖拽选中一段文本时，JavaScript 的 `Selection` API 会创建一个 `Range` 对象来表示选区。Blink 内部在处理这个选区时，可能会使用 `EphemeralRange` 来进行节点遍历或计算相关信息。

* **CSS:**  虽然 CSS 不直接操作 `EphemeralRange`，但 CSS 的 Shadow DOM 功能与 `EphemeralRangeInFlatTree` 的测试密切相关。 `EphemeralRangeInFlatTree` 需要正确处理 Shadow DOM 树的扁平化结构，这与 CSS 的 Shadow DOM 规范有关。
    * **举例:** 在 `rangeShadowTraversal` 测试中，`SetShadowContent` 创建了一个 Shadow DOM 结构，其中使用了 `<slot>` 元素进行内容分发。`EphemeralRangeInFlatTree` 需要按照扁平树的顺序遍历，这反映了 CSS Shadow DOM 的渲染结果。

**逻辑推理与假设输入输出:**

大多数测试用例通过设置特定的 HTML 结构，然后使用 `EphemeralRange` 进行遍历，并断言遍历结果与预期一致。

**假设输入 (以 `rangeTraversalDOM` 为例):**

```html
<p id='host'>
  <b id='zero'>0</b>
  <b id='one'>1</b>
  <b id='two'>22</b>
  <span id='three'>333</span>
</p>
```

**假设输出:**

`TraverseRange<>(GetBodyRange())` 或 `TraverseRange(EphemeralRange(GetBodyRange()))` 的输出应该为:

```
"[BODY][P id=\"host\"][B id=\"zero\"][#text \"0\"][B id=\"one\"][#text \"1\"][B id=\"two\"][#text \"22\"][SPAN id=\"three\"][#text \"333\"]"
```

这个输出字符串表示了 `EphemeralRange` 按照深度优先的顺序遍历了 `<body>` 元素及其所有子节点。

**用户或编程常见的使用错误:**

虽然用户或开发者不直接使用 `EphemeralRange`，但在使用 JavaScript DOM API 时，可能会遇到与之相关的概念性错误，导致 Blink 内部处理时出现问题。

1. **错误的 Range 边界:** 用户或开发者可能使用 JavaScript 创建了不正确的 `Range` 对象，例如起始位置在结束位置之后，或者起始/结束位置指向了不期望的节点。这会导致 Blink 内部基于这个错误的 `Range` 创建的 `EphemeralRange` 遍历出错误的结果。
    * **例子:**  一个 JavaScript 代码试图获取用户选中的文本，但由于逻辑错误，计算出的 `Range` 对象的起始位置超出了文本内容的范围。

2. **不理解 Shadow DOM 的遍历:**  在处理包含 Shadow DOM 的内容时，开发者可能期望使用传统的 DOM 遍历方式就能访问到 Shadow Root 中的节点。但实际上，需要使用特定的 API 或者像 `EphemeralRangeInFlatTree` 这样的机制才能正确遍历扁平树。
    * **例子:**  开发者尝试用 `firstChild` 和 `nextSibling` 来遍历一个包含 Shadow DOM 的组件，但无法访问到 Shadow Root 中的内容。

3. **误用等效位置:**  开发者可能没有意识到 DOM 中存在等效但不同的 `Position`，例如一个元素之后和一个元素的下一个兄弟节点之前是等效的。如果直接比较这些位置而不是使用 `isEquivalent()`，可能会导致逻辑错误。
    * **例子:**  一个 JavaScript 编辑器功能需要判断两个光标位置是否相同，但直接比较 `startContainer` 和 `startOffset`，而没有考虑等效位置的情况。

**用户操作如何一步步到达这里 (作为调试线索):**

`ephemeral_range_test.cc` 是一个单元测试文件，它主要由开发者在开发和调试 Blink 引擎时运行。普通用户操作不会直接触发这个测试文件。然而，用户的一些操作可能会触发 Blink 内部使用 `EphemeralRange` 的相关代码，如果这些代码存在 bug，开发者可能会编写或修改 `ephemeral_range_test.cc` 来复现和修复问题。

以下是一些可能导致需要调试 `EphemeralRange` 相关代码的用户操作场景：

1. **文本选择和复制/粘贴:** 当用户在网页上选择一段文本并执行复制操作时，Blink 引擎需要创建一个表示选区的 `Range` 对象，并遍历选区内的节点来获取文本内容。`EphemeralRange` 可能被用于这个遍历过程。如果复制的内容不完整或包含错误的格式，可能意味着 `EphemeralRange` 的遍历逻辑存在问题。

2. **富文本编辑:**  在富文本编辑器中，用户进行插入、删除、格式化等操作时，Blink 引擎需要维护光标位置和选区，并对 DOM 进行修改。`EphemeralRange` 可能被用于定位和操作编辑区域内的节点。如果编辑操作出现异常，例如光标跳转错误、格式丢失等，可能与 `EphemeralRange` 的使用有关。

3. **使用 Shadow DOM 的 Web Components:**  当网页使用了 Web Components 和 Shadow DOM 时，用户与组件的交互可能会触发 Blink 内部对 Shadow Tree 的遍历和操作。`EphemeralRangeInFlatTree` 的正确性直接影响到这些交互的准确性。例如，在 Shadow DOM 中选择文本或拖动元素时，如果 `EphemeralRangeInFlatTree` 的实现有 bug，可能会导致选择范围错误或拖动行为异常。

**调试线索:**

如果用户报告了与上述操作相关的 bug，Blink 开发者可能会采取以下步骤进行调试，并可能涉及到 `ephemeral_range_test.cc`:

1. **复现 Bug:** 开发者会尝试在本地环境中复现用户报告的 bug，例如在特定的网页上进行文本选择或富文本编辑操作。

2. **分析代码:** 开发者会查看 Blink 引擎中处理相关用户操作的代码，例如处理文本选择、剪贴板操作、富文本编辑命令的代码，以及 Shadow DOM 相关的代码。

3. **定位到 `EphemeralRange` 的使用:** 如果怀疑 bug 与范围或节点遍历有关，开发者会查找代码中 `EphemeralRange` 的使用位置。

4. **创建或修改单元测试:**  如果发现 `EphemeralRange` 的行为与预期不符，开发者可能会创建新的测试用例添加到 `ephemeral_range_test.cc` 中，或者修改现有的测试用例来复现 bug。这些测试用例会模拟导致 bug 的特定场景，例如特定的 HTML 结构和范围。

5. **运行测试:** 开发者会运行 `ephemeral_range_test.cc` 中的测试用例，以验证 `EphemeralRange` 的行为是否正确。

6. **修复 Bug:**  根据测试结果，开发者会修改 `EphemeralRange` 的实现代码，并重新运行测试，直到所有测试用例都通过。

7. **验证修复:** 修复完成后，开发者可能会再次手动测试之前出现 bug 的场景，以确保问题得到解决。

总而言之，`ephemeral_range_test.cc` 是 Blink 引擎中一个重要的测试文件，它确保了 `EphemeralRange` 这个用于编辑操作的关键组件能够正确地遍历和处理 DOM 节点，包括在复杂的 Shadow DOM 场景下。它的正确性直接影响到浏览器中许多与文本和 DOM 操作相关的功能的稳定性和可靠性。

### 提示词
```
这是目录为blink/renderer/core/editing/ephemeral_range_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/ephemeral_range.h"

#include <sstream>
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"

namespace blink {

class EphemeralRangeTest : public EditingTestBase {
 protected:
  template <typename Traversal = NodeTraversal>
  std::string TraverseRange(Range*) const;

  template <typename Strategy>
  std::string TraverseRange(const EphemeralRangeTemplate<Strategy>&) const;

  Range* GetBodyRange() const;
};

template <typename Traversal>
std::string EphemeralRangeTest::TraverseRange(Range* range) const {
  std::stringstream nodes_content;
  for (Node* node = range->FirstNode(); node != range->PastLastNode();
       node = Traversal::Next(*node)) {
    nodes_content << "[" << *node << "]";
  }

  return nodes_content.str();
}

template <typename Strategy>
std::string EphemeralRangeTest::TraverseRange(
    const EphemeralRangeTemplate<Strategy>& range) const {
  std::stringstream nodes_content;
  for (const Node& node : range.Nodes())
    nodes_content << "[" << node << "]";

  return nodes_content.str();
}

Range* EphemeralRangeTest::GetBodyRange() const {
  Range* range = Range::Create(GetDocument());
  range->selectNode(GetDocument().body());
  return range;
}

// Tests that |EphemeralRange::nodes()| will traverse the whole range exactly as
// |for (Node* n = firstNode(); n != pastLastNode(); n = Traversal::next(*n))|
// does.
TEST_F(EphemeralRangeTest, rangeTraversalDOM) {
  const char* body_content =
      "<p id='host'>"
      "<b id='zero'>0</b>"
      "<b id='one'>1</b>"
      "<b id='two'>22</b>"
      "<span id='three'>333</span>"
      "</p>";
  SetBodyContent(body_content);

  const std::string expected_nodes(
      "[BODY][P id=\"host\"][B id=\"zero\"][#text \"0\"][B id=\"one\"][#text "
      "\"1\"][B id=\"two\"][#text \"22\"][SPAN id=\"three\"][#text \"333\"]");

  // Check two ways to traverse.
  EXPECT_EQ(expected_nodes, TraverseRange<>(GetBodyRange()));
  EXPECT_EQ(TraverseRange<>(GetBodyRange()),
            TraverseRange(EphemeralRange(GetBodyRange())));

  EXPECT_EQ(expected_nodes, TraverseRange<FlatTreeTraversal>(GetBodyRange()));
  EXPECT_EQ(TraverseRange<FlatTreeTraversal>(GetBodyRange()),
            TraverseRange(EphemeralRangeInFlatTree(GetBodyRange())));
}

// Tests that |inRange| helper will traverse the whole range with shadow DOM.
TEST_F(EphemeralRangeTest, rangeShadowTraversal) {
  const char* body_content =
      "<b id='zero'>0</b>"
      "<p id='host'>"
      "<b slot='#one' id='one'>1</b>"
      "<b slot='#two' id='two'>22</b>"
      "<b id='three'>333</b>"
      "</p>"
      "<b id='four'>4444</b>";
  const char* shadow_content =
      "<p id='five'>55555</p>"
      "<slot name=#two></slot>"
      "<slot name=#one></slot>"
      "<span id='six'>666666</span>"
      "<p id='seven'>7777777</p>";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");

  const std::string expected_nodes(
      "[BODY][B id=\"zero\"][#text \"0\"][P id=\"host\"][P id=\"five\"][#text "
      "\"55555\"][SLOT][B id=\"two\"][#text \"22\"][SLOT][B id=\"one\"][#text "
      "\"1\"][SPAN id=\"six\"][#text \"666666\"][P id=\"seven\"][#text "
      "\"7777777\"][B id=\"four\"][#text \"4444\"]");

  EXPECT_EQ(expected_nodes, TraverseRange<FlatTreeTraversal>(GetBodyRange()));
  EXPECT_EQ(TraverseRange<FlatTreeTraversal>(GetBodyRange()),
            TraverseRange(EphemeralRangeInFlatTree(GetBodyRange())));
  // Node 'three' should not appear in FlatTreeTraversal.
  EXPECT_EQ(expected_nodes.find("three") == std::string::npos, true);
}

// Limit a range and check that it will be traversed correctly.
TEST_F(EphemeralRangeTest, rangeTraversalLimitedDOM) {
  const char* body_content =
      "<p id='host'>"
      "<b id='zero'>0</b>"
      "<b id='one'>1</b>"
      "<b id='two'>22</b>"
      "<span id='three'>333</span>"
      "</p>";
  SetBodyContent(body_content);

  Range* until_b = GetBodyRange();
  until_b->setEnd(GetDocument().getElementById(AtomicString("one")), 0,
                  IGNORE_EXCEPTION_FOR_TESTING);
  EXPECT_EQ("[BODY][P id=\"host\"][B id=\"zero\"][#text \"0\"][B id=\"one\"]",
            TraverseRange<>(until_b));
  EXPECT_EQ(TraverseRange<>(until_b), TraverseRange(EphemeralRange(until_b)));

  Range* from_b_to_span = GetBodyRange();
  from_b_to_span->setStart(GetDocument().getElementById(AtomicString("one")), 0,
                           IGNORE_EXCEPTION_FOR_TESTING);
  from_b_to_span->setEnd(GetDocument().getElementById(AtomicString("three")), 0,
                         IGNORE_EXCEPTION_FOR_TESTING);
  EXPECT_EQ("[#text \"1\"][B id=\"two\"][#text \"22\"][SPAN id=\"three\"]",
            TraverseRange<>(from_b_to_span));
  EXPECT_EQ(TraverseRange<>(from_b_to_span),
            TraverseRange(EphemeralRange(from_b_to_span)));
}

TEST_F(EphemeralRangeTest, rangeTraversalLimitedFlatTree) {
  const char* body_content =
      "<b id='zero'>0</b>"
      "<p id='host'>"
      "<b slot='#one' id='one'>1</b>"
      "<b slot='#two' id='two'>22</b>"
      "</p>"
      "<b id='three'>333</b>";
  const char* shadow_content =
      "<p id='four'>4444</p>"
      "<slot name=#two></slot>"
      "<slot name=#one></slot>"
      "<span id='five'>55555</span>"
      "<p id='six'>666666</p>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  const PositionInFlatTree start_position(
      GetDocument().getElementById(AtomicString("one")), 0);
  const PositionInFlatTree limit_position(
      shadow_root->getElementById(AtomicString("five")), 0);
  const PositionInFlatTree end_position(
      shadow_root->getElementById(AtomicString("six")), 0);
  const EphemeralRangeInFlatTree from_b_to_span(start_position, limit_position);
  EXPECT_EQ("[#text \"1\"][SPAN id=\"five\"]", TraverseRange(from_b_to_span));

  const EphemeralRangeInFlatTree from_span_to_end(limit_position, end_position);
  EXPECT_EQ("[#text \"55555\"][P id=\"six\"]", TraverseRange(from_span_to_end));
}

TEST_F(EphemeralRangeTest, traversalEmptyRanges) {
  const char* body_content =
      "<p id='host'>"
      "<b id='one'>1</b>"
      "</p>";
  SetBodyContent(body_content);

  // Expect no iterations in loop for an empty EphemeralRange.
  EXPECT_EQ(std::string(), TraverseRange(EphemeralRange()));

  auto iterable = EphemeralRange().Nodes();
  // Tree iterators have only |operator !=| ATM.
  EXPECT_FALSE(iterable.begin() != iterable.end());

  const EphemeralRange single_position_range(GetBodyRange()->StartPosition());
  EXPECT_FALSE(single_position_range.IsNull());
  EXPECT_EQ(std::string(), TraverseRange(single_position_range));
  EXPECT_EQ(single_position_range.StartPosition().NodeAsRangeFirstNode(),
            single_position_range.EndPosition().NodeAsRangePastLastNode());
}

TEST_F(EphemeralRangeTest, commonAncesstorDOM) {
  const char* body_content =
      "<p id='host'>00"
      "<b id='one'>11</b>"
      "<b id='two'>22</b>"
      "<b id='three'>33</b>"
      "</p>";
  SetBodyContent(body_content);

  const Position start_position(
      GetDocument().getElementById(AtomicString("one")), 0);
  const Position end_position(GetDocument().getElementById(AtomicString("two")),
                              0);
  const EphemeralRange range(start_position, end_position);
  EXPECT_EQ(GetDocument().getElementById(AtomicString("host")),
            range.CommonAncestorContainer());
}

TEST_F(EphemeralRangeTest, commonAncesstorFlatTree) {
  const char* body_content =
      "<b id='zero'>0</b>"
      "<p id='host'>"
      "<b slot='#one' id='one'>1</b>"
      "<b slot='#two' id='two'>22</b>"
      "</p>"
      "<b id='three'>333</b>";
  const char* shadow_content =
      "<p id='four'>4444</p>"
      "<slot name=#two></slot>"
      "<slot name=#one></slot>"
      "<p id='five'>55555</p>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  const PositionInFlatTree start_position(
      GetDocument().getElementById(AtomicString("one")), 0);
  const PositionInFlatTree end_position(
      shadow_root->getElementById(AtomicString("five")), 0);
  const EphemeralRangeInFlatTree range(start_position, end_position);
  EXPECT_EQ(GetDocument().getElementById(AtomicString("host")),
            range.CommonAncestorContainer());
}

TEST_F(EphemeralRangeTest, EquivalentPositions) {
  SetBodyContent(
      "<div id='first'></div>"
      "<div id='last'></div>");
  Element* first = GetDocument().getElementById(AtomicString("first"));
  Element* last = GetDocument().getElementById(AtomicString("last"));
  Position after_first = Position::AfterNode(*first);
  Position before_last = Position::BeforeNode(*last);

  // Test ranges created with different but equivalent positions.
  EXPECT_NE(after_first, before_last);
  EXPECT_TRUE(after_first.IsEquivalent(before_last));

  EphemeralRange range1(after_first, before_last);
  EXPECT_TRUE(range1.IsCollapsed());
  EXPECT_EQ(after_first, range1.StartPosition());
  EXPECT_EQ(after_first, range1.EndPosition());

  EphemeralRange range2(before_last, after_first);
  EXPECT_TRUE(range2.IsCollapsed());
  EXPECT_EQ(before_last, range2.StartPosition());
  EXPECT_EQ(before_last, range2.EndPosition());
}

}  // namespace blink
```