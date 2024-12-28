Response:
My thinking process to analyze the `range_test.cc` file and answer the request goes like this:

1. **Understand the Core Purpose:** The filename `range_test.cc` immediately tells me this file contains unit tests for the `Range` class in the Blink rendering engine. This is the central piece of information.

2. **Identify Key Includes:**  I scan the `#include` directives to understand the dependencies and the areas the tests touch. Key inclusions are:
    * `third_party/blink/renderer/core/dom/range.h`: Confirms the core subject is the `Range` class.
    * `testing/gmock/include/gmock/gmock.h` and `testing/gtest/include/gtest/gtest.h`: Indicate this is a unit test file using Google Test and Google Mock frameworks.
    * Includes from `third_party/blink/renderer/bindings/core/v8/`: Suggest interactions with JavaScript.
    * Includes from `third_party/blink/renderer/core/css/`: Hints at interactions with CSS (especially regarding layout and styling).
    * Includes from `third_party/blink/renderer/core/dom/`: Show interactions with various DOM nodes (Element, Text, etc.).
    * Includes from `third_party/blink/renderer/core/editing/`: Highlight tests related to text editing and selection.
    * Includes from `third_party/blink/renderer/core/html/`: Indicate tests involving HTML elements.

3. **Analyze the Test Structure:** I look for the test fixture declaration (`class RangeTest : public EditingTestBase {};`) and the `TEST_F` macros. This confirms the use of Google Test and shows that each `TEST_F` represents an individual test case for specific functionality of the `Range` class.

4. **Deconstruct Each Test Case:** I go through each `TEST_F` individually, trying to grasp its purpose:
    * **`extractContentsWithDOMMutationEvent`:**  Focuses on how `extractContents` interacts with DOM mutation events. It checks if the result is correct despite mutations triggered during the extraction process. This directly relates to JavaScript event handling.
    * **`IntersectsNode`:** Tests the `intersectsNode` method, verifying its accuracy in determining if a range overlaps with a given node. This is a core DOM manipulation function.
    * **`SplitTextNodeRangeWithinText` and `SplitTextNodeRangeOutsideText`:**  Examine how ranges are affected when `splitText` is called on a text node. This has implications for text editing and manipulation via JavaScript. The "within" and "outside" distinctions are important for understanding edge cases.
    * **`updateOwnerDocumentIfNeeded`:** Tests how the range's internal document reference is updated when nodes are moved between documents. This is relevant in more advanced JavaScript scenarios involving iframes or document fragments.
    * **`NotMarkedValidByIrrelevantTextInsert` and `NotMarkedValidByIrrelevantTextRemove`:** These are regression tests, meaning they were written to prevent bugs from reappearing. They test if unrelated text modifications invalidate the range unnecessarily.
    * **`ExpandNotCrash`:**  A simple test to ensure the `expand` method doesn't cause a crash, even with minimal setup.
    * **`ToPosition`:** Tests the conversion between `Range` and `Position` objects, which are fundamental for representing locations within the DOM.
    * **`BoundingRectMustIndependentFromSelection`:** Checks that the bounding rectangle of a range is calculated correctly and isn't affected by changes to the current selection. This is related to layout and visual representation.
    * **`BorderAndTextQuadsWithInputInBetween`:** Focuses on getting the correct bounding boxes (quads) for ranges that span across different types of nodes (text and input elements). This is important for rendering and selection highlighting.
    * **`GetBorderAndTextQuadsWithCombinedText`, `GetBorderAndTextQuadsWithFirstLetterOne`, `GetBorderAndTextQuadsWithFirstLetterThree`, `CollapsedRangeGetBorderAndTextQuadsWithFirstLetter`:** These tests delve into the specifics of how ranges and their bounding boxes are calculated in scenarios involving CSS features like `text-combine-upright` and `::first-letter`. This highlights the interaction between DOM ranges and CSS styling.
    * **`ContainerNodeRemoval` and `ContainerNodeRemovalWithSequentialFocusNavigationStartingPoint`:** Test how ranges behave when their containing nodes (or ancestor nodes like `document.body`) are removed. This is crucial for maintaining data integrity during DOM manipulation. The second test specifically checks the impact on focus navigation.

5. **Identify Relationships with Web Technologies:** Based on the analysis of the test cases, I connect them to JavaScript, HTML, and CSS functionalities:
    * **JavaScript:**  DOM manipulation (node creation, removal, modification, event handling), selection API.
    * **HTML:** Structure of the document, different HTML elements and their properties.
    * **CSS:** Styling, layout, and specific features like `::first-letter` and `text-combine-upright`.

6. **Formulate Examples and Scenarios:** For each connection, I create illustrative examples of how these functionalities might be used in web development and how the `Range` class plays a role. I try to make these examples concrete and easy to understand.

7. **Infer Assumptions, Inputs, and Outputs:** For tests involving logical reasoning (like how ranges are updated after node splitting), I try to deduce the assumptions made by the test and provide examples of input DOM structures and the expected range boundaries after the operation.

8. **Consider User Errors and Debugging:** I think about common mistakes developers might make when working with ranges (e.g., assuming a range remains valid after DOM changes) and how these tests can help in debugging such issues. I outline a hypothetical user action leading to these code paths.

9. **Structure the Answer:** Finally, I organize my findings into clear sections as requested in the prompt, addressing the functionality, relationships with web technologies, logical reasoning, user errors, and debugging aspects. I use clear language and provide specific examples to illustrate each point.

By following this systematic approach, I can thoroughly analyze the `range_test.cc` file and provide a comprehensive answer to the prompt.
这个文件 `blink/renderer/core/dom/range_test.cc` 是 Chromium Blink 渲染引擎中的一个 **单元测试文件**。它的主要功能是 **测试 `blink::Range` 类的各种功能和行为**。

`blink::Range` 类在 Blink 引擎中用于表示文档中的一个连续范围，可以跨越文本节点和元素边界。  理解 `Range` 的行为对于实现诸如文本选择、复制粘贴、富文本编辑等功能至关重要。

以下是该文件测试的主要功能点以及它们与 JavaScript, HTML, CSS 的关系：

**主要功能测试点:**

* **创建和操作 Range 对象:** 测试如何创建 `Range` 对象，例如通过指定起始和结束节点和偏移量。
* **修改 Range 的边界点:** 测试 `setStart`, `setEnd` 等方法，验证 Range 的边界是否正确更新。
* **判断 Range 的状态:** 测试 `BoundaryPointsValid`, `intersectsNode` 等方法，确保 Range 对象在各种 DOM 操作后能正确反映其有效性和与其他节点的关系。
* **提取 Range 内容:** 测试 `extractContents` 方法，验证它能否正确地从文档中移除 Range 包含的内容并返回一个文档片段。
* **Range 与 DOM 结构变化的交互:** 测试在 DOM 结构发生变化（例如节点插入、删除、分割）时，Range 对象是否能保持其边界点的有效性，并正确更新其位置。这是该文件重点测试的方面。
* **Range 的几何属性:** 测试 `getBoundingClientRect`, `getClientRects`, `getBorderAndTextQuads` 等方法，验证 Range 能否正确计算其在页面上的几何位置和形状。这与 CSS 渲染密切相关。
* **Range 的扩展和收缩:** 测试 `expand` 方法，验证 Range 是否能按字符、单词、句子等单位扩展。
* **Range 与 Selection 的关系:** 虽然这个文件主要测试 `Range` 本身，但有些测试也间接涉及到 `Selection` 对象，因为 `Selection` 通常由一个或多个 `Range` 组成。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

1. **与 JavaScript 的关系:**

   * **DOM 操作:** JavaScript 可以通过 DOM API 创建、修改和查询 HTML 元素。`Range` 对象是这些操作的核心组成部分。例如，用户在网页上选择一段文本，浏览器内部会创建一个或多个 `Range` 对象来表示这个选择。
     * **假设输入:** JavaScript 代码 `const range = document.createRange(); range.setStart(element1, 0); range.setEnd(element2, 1);`
     * **输出:** `RangeTest` 中的相关测试会验证这个新创建的 `range` 对象的 `startContainer`, `startOffset`, `endContainer`, `endOffset` 是否如预期。
   * **Selection API:** JavaScript 的 `Selection` API 允许开发者获取和修改用户在页面上选择的文本或元素。`Selection` 对象内部使用 `Range` 对象来表示选区。
     * **用户操作:** 用户使用鼠标拖拽在网页上选中一段文字。
     * **调试线索:** 当出现选择相关的 bug 时，开发者可能会断点到 `Range` 相关的代码，查看 `Selection` 对象包含的 `Range` 对象的边界是否正确。
   * **富文本编辑器:**  富文本编辑器大量使用 `Range` 对象来跟踪光标位置、选中文本，并执行诸如插入、删除、格式化等操作。
     * **用户操作:** 在富文本编辑器中选中一段文字并点击“加粗”按钮。
     * **调试线索:**  相关的 `Range` 测试会验证在这种操作后，`Range` 对象是否仍然指向正确的文本范围，并且操作是否正确应用。

2. **与 HTML 的关系:**

   * **HTML 结构是 `Range` 操作的基础:** `Range` 对象定义在 HTML 文档的节点和文本内容之上。不同的 HTML 结构会影响 `Range` 的行为。
     * **假设输入:**  一个包含嵌套 `<div>` 和 `<p>` 元素的 HTML 结构。
     * **输出:** `RangeTest` 中会创建跨越这些元素的 `Range` 对象，并测试其在不同操作下的行为，例如 `intersectsNode` 是否能正确判断 Range 是否与特定的 `<div>` 或 `<p>` 元素相交。
   * **`extractContents` 创建文档片段:** `extractContents` 方法返回的 `DocumentFragment` 是一个轻量级的 DOM 结构，它本身是 HTML 的一部分。
     * **用户操作:** 用户在网页上选中一段内容并执行“剪切”操作。
     * **调试线索:**  `Range` 的 `extractContents` 方法会被调用，开发者可能会检查返回的 `DocumentFragment` 是否包含了预期的 HTML 结构。

3. **与 CSS 的关系:**

   * **Range 的几何属性受到 CSS 影响:**  `getBoundingClientRect` 和 `getClientRects` 等方法返回的 `Range` 的边界框大小和位置，会受到 CSS 样式（例如 `font-size`, `line-height`, `padding`, `margin` 等）的影响。
     * **假设输入:**  一个包含一段文本的 `<div>` 元素，并应用了特定的 CSS 样式，例如 `font-size: 20px;`.
     * **输出:** `RangeTest` 中会创建一个覆盖这段文本的 `Range` 对象，并测试其 `getBoundingClientRect` 方法返回的矩形高度是否接近 20px。
   * **`::first-letter` 等伪元素:**  某些 CSS 伪元素会影响文本的布局和渲染。`RangeTest` 中包含了针对包含 `::first-letter` 伪元素的文本进行几何计算的测试。
     * **用户操作:** 用户选中一个包含 `::first-letter` 伪元素的段落的部分文本。
     * **调试线索:**  相关的 `Range` 测试会验证 `getBorderAndTextQuads` 方法是否能正确计算出伪元素部分的几何信息。

**逻辑推理的假设输入与输出 (以 `SplitTextNodeRangeWithinText` 为例):**

* **假设输入:**
    * HTML: `<body>1234</body>`
    * JavaScript (模拟 Blink 内部操作): 创建一个 `Range` 对象 `range04`，起始于文本节点 "1234" 的偏移量 0，结束于偏移量 4。然后，调用文本节点的 `splitText(2)` 方法。
* **输出:**
    * `range04` 的边界点仍然有效 (`BoundaryPointsValid()` 返回 true)。
    * `range04` 的起始容器仍然是原来的文本节点。
    * `range04` 的起始偏移量仍然是 0。
    * `range04` 的结束容器变成了新分割出来的文本节点。
    * `range04` 的结束偏移量变成了 2。

**用户或编程常见的使用错误举例说明:**

* **错误地假设 Range 在 DOM 变化后仍然有效且指向相同内容:**
    * **用户操作:** 用户使用 JavaScript 创建一个 `Range` 对象选中一段文本，然后通过 JavaScript 删除了这段文本所在的父元素。
    * **错误:**  开发者可能仍然持有之前的 `Range` 对象，并尝试使用它，但此时 `Range` 的边界点可能已经无效，或者指向了错误的节点。`RangeTest` 中的 `ContainerNodeRemoval` 等测试就是为了确保在这种情况下 `Range` 对象能正确更新其状态。
* **不理解 `extractContents` 的副作用:**
    * **用户操作:** 开发者使用 JavaScript 创建一个 `Range` 对象选中一段文本，并调用 `extractContents` 方法。
    * **错误:** 开发者可能没有意识到 `extractContents` 会从文档中移除选中的内容。`RangeTest` 中的 `extractContentsWithDOMMutationEvent` 测试确保即使在 `extractContents` 执行过程中有 DOM 变动，结果也是预期的。
* **在异步操作后使用过期的 Range 对象:**
    * **用户操作:** 用户发起一个异步请求，在请求完成的回调函数中使用了之前创建的 `Range` 对象。
    * **错误:** 在异步请求完成之前，DOM 结构可能已经发生变化，导致 `Range` 对象失效。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **开发者在 Blink 引擎的代码中修改了 `blink::Range` 类的相关逻辑。**
2. **为了验证修改的正确性，开发者需要运行相关的单元测试。**
3. **`range_test.cc` 文件包含了 `blink::Range` 类的各种功能的测试用例。**
4. **开发者会通过构建系统 (如 GN 和 Ninja) 编译并运行 `range_test.cc` 中的测试。**
5. **如果某个测试用例失败，开发者会查看测试代码，分析失败的原因，并通过调试工具（如 gdb）逐步执行代码，追踪 `Range` 对象的行为。**
6. **测试用例中的 HTML 结构、JavaScript 操作和期望的输出结果，就成为了调试的线索，帮助开发者理解问题所在，并修复代码。**

总而言之，`range_test.cc` 是 Blink 引擎中一个非常重要的测试文件，它通过大量的测试用例，确保了 `blink::Range` 类的功能正确性和鲁棒性，这对于保证浏览器的文本选择、编辑等核心功能的稳定运行至关重要。它与 JavaScript, HTML, CSS 都有着紧密的联系，因为 `Range` 对象是操作和表示 Web 页面内容的核心概念。

Prompt: 
```
这是目录为blink/renderer/core/dom/range_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/dom/range.h"

#include "base/memory/scoped_refptr.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_font_face_descriptors.h"
#include "third_party/blink/renderer/core/css/font_face_set_document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node_list.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "ui/gfx/geometry/quad_f.h"
#include "ui/gfx/geometry/rect_conversions.h"

namespace blink {

using ::testing::ElementsAre;

class RangeTest : public EditingTestBase {};

TEST_F(RangeTest, extractContentsWithDOMMutationEvent) {
  if (!RuntimeEnabledFeatures::MutationEventsEnabledByRuntimeFlag()) {
    // TODO(crbug.com/1446498) Remove this test when MutationEvents are disabled
    // for good. This is just a test of `DOMSubtreeModified` and ranges.
    return;
  }
  GetDocument().body()->setInnerHTML("<span><b>abc</b>def</span>");
  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* const script_element =
      GetDocument().CreateRawElement(html_names::kScriptTag);
  script_element->setTextContent(
      "let count = 0;"
      "const span = document.querySelector('span');"
      "span.addEventListener('DOMSubtreeModified', () => {"
      "  if (++count > 1) return;"
      "  span.firstChild.textContent = 'ABC';"
      "  span.lastChild.textContent = 'DEF';"
      "});");
  GetDocument().body()->AppendChild(script_element);

  Element* const span_element =
      GetDocument().QuerySelector(AtomicString("span"));
  auto* const range = MakeGarbageCollected<Range>(GetDocument(), span_element,
                                                  0, span_element, 1);
  Element* const result = GetDocument().CreateRawElement(html_names::kDivTag);
  result->AppendChild(range->extractContents(ASSERT_NO_EXCEPTION));

  EXPECT_EQ("<b>abc</b>", result->innerHTML())
      << "DOM mutation event handler should not affect result.";
  EXPECT_EQ("<span>DEF</span>", span_element->outerHTML())
      << "DOM mutation event handler should be executed.";
}

// http://crbug.com/822510
TEST_F(RangeTest, IntersectsNode) {
  SetBodyContent(
      "<div>"
      "<span id='s0'>s0</span>"
      "<span id='s1'>s1</span>"
      "<span id='s2'>s2</span>"
      "</div>");
  Element* const div = GetDocument().QuerySelector(AtomicString("div"));
  Element* const s0 = GetDocument().getElementById(AtomicString("s0"));
  Element* const s1 = GetDocument().getElementById(AtomicString("s1"));
  Element* const s2 = GetDocument().getElementById(AtomicString("s2"));
  Range& range = *Range::Create(GetDocument());

  // Range encloses s0
  range.setStart(div, 0);
  range.setEnd(div, 1);
  EXPECT_TRUE(range.intersectsNode(s0, ASSERT_NO_EXCEPTION));
  EXPECT_FALSE(range.intersectsNode(s1, ASSERT_NO_EXCEPTION));
  EXPECT_FALSE(range.intersectsNode(s2, ASSERT_NO_EXCEPTION));

  // Range encloses s1
  range.setStart(div, 1);
  range.setEnd(div, 2);
  EXPECT_FALSE(range.intersectsNode(s0, ASSERT_NO_EXCEPTION));
  EXPECT_TRUE(range.intersectsNode(s1, ASSERT_NO_EXCEPTION));
  EXPECT_FALSE(range.intersectsNode(s2, ASSERT_NO_EXCEPTION));

  // Range encloses s2
  range.setStart(div, 2);
  range.setEnd(div, 3);
  EXPECT_FALSE(range.intersectsNode(s0, ASSERT_NO_EXCEPTION));
  EXPECT_FALSE(range.intersectsNode(s1, ASSERT_NO_EXCEPTION));
  EXPECT_TRUE(range.intersectsNode(s2, ASSERT_NO_EXCEPTION));
}

TEST_F(RangeTest, SplitTextNodeRangeWithinText) {
  V8TestingScope scope;

  GetDocument().body()->setInnerHTML("1234");
  auto* old_text = To<Text>(GetDocument().body()->firstChild());

  auto* range04 =
      MakeGarbageCollected<Range>(GetDocument(), old_text, 0, old_text, 4);
  auto* range02 =
      MakeGarbageCollected<Range>(GetDocument(), old_text, 0, old_text, 2);
  auto* range22 =
      MakeGarbageCollected<Range>(GetDocument(), old_text, 2, old_text, 2);
  auto* range24 =
      MakeGarbageCollected<Range>(GetDocument(), old_text, 2, old_text, 4);

  old_text->splitText(2, ASSERT_NO_EXCEPTION);
  auto* new_text = To<Text>(old_text->nextSibling());

  EXPECT_TRUE(range04->BoundaryPointsValid());
  EXPECT_EQ(old_text, range04->startContainer());
  EXPECT_EQ(0u, range04->startOffset());
  EXPECT_EQ(new_text, range04->endContainer());
  EXPECT_EQ(2u, range04->endOffset());

  EXPECT_TRUE(range02->BoundaryPointsValid());
  EXPECT_EQ(old_text, range02->startContainer());
  EXPECT_EQ(0u, range02->startOffset());
  EXPECT_EQ(old_text, range02->endContainer());
  EXPECT_EQ(2u, range02->endOffset());

  // Our implementation always moves the boundary point at the separation point
  // to the end of the original text node.
  EXPECT_TRUE(range22->BoundaryPointsValid());
  EXPECT_EQ(old_text, range22->startContainer());
  EXPECT_EQ(2u, range22->startOffset());
  EXPECT_EQ(old_text, range22->endContainer());
  EXPECT_EQ(2u, range22->endOffset());

  EXPECT_TRUE(range24->BoundaryPointsValid());
  EXPECT_EQ(old_text, range24->startContainer());
  EXPECT_EQ(2u, range24->startOffset());
  EXPECT_EQ(new_text, range24->endContainer());
  EXPECT_EQ(2u, range24->endOffset());
}

TEST_F(RangeTest, SplitTextNodeRangeOutsideText) {
  V8TestingScope scope;

  GetDocument().body()->setInnerHTML(
      "<span id=\"outer\">0<span id=\"inner-left\">1</span>SPLITME<span "
      "id=\"inner-right\">2</span>3</span>");

  Element* outer =
      GetDocument().getElementById(AtomicString::FromUTF8("outer"));
  Element* inner_left =
      GetDocument().getElementById(AtomicString::FromUTF8("inner-left"));
  Element* inner_right =
      GetDocument().getElementById(AtomicString::FromUTF8("inner-right"));
  auto* old_text = To<Text>(outer->childNodes()->item(2));

  auto* range_outer_outside =
      MakeGarbageCollected<Range>(GetDocument(), outer, 0, outer, 5);
  auto* range_outer_inside =
      MakeGarbageCollected<Range>(GetDocument(), outer, 1, outer, 4);
  auto* range_outer_surrounding_text =
      MakeGarbageCollected<Range>(GetDocument(), outer, 2, outer, 3);
  auto* range_inner_left =
      MakeGarbageCollected<Range>(GetDocument(), inner_left, 0, inner_left, 1);
  auto* range_inner_right = MakeGarbageCollected<Range>(
      GetDocument(), inner_right, 0, inner_right, 1);
  auto* range_from_text_to_middle_of_element =
      MakeGarbageCollected<Range>(GetDocument(), old_text, 6, outer, 3);

  old_text->splitText(3, ASSERT_NO_EXCEPTION);
  auto* new_text = To<Text>(old_text->nextSibling());

  EXPECT_TRUE(range_outer_outside->BoundaryPointsValid());
  EXPECT_EQ(outer, range_outer_outside->startContainer());
  EXPECT_EQ(0u, range_outer_outside->startOffset());
  EXPECT_EQ(outer, range_outer_outside->endContainer());
  EXPECT_EQ(6u,
            range_outer_outside
                ->endOffset());  // Increased by 1 since a new node is inserted.

  EXPECT_TRUE(range_outer_inside->BoundaryPointsValid());
  EXPECT_EQ(outer, range_outer_inside->startContainer());
  EXPECT_EQ(1u, range_outer_inside->startOffset());
  EXPECT_EQ(outer, range_outer_inside->endContainer());
  EXPECT_EQ(5u, range_outer_inside->endOffset());

  EXPECT_TRUE(range_outer_surrounding_text->BoundaryPointsValid());
  EXPECT_EQ(outer, range_outer_surrounding_text->startContainer());
  EXPECT_EQ(2u, range_outer_surrounding_text->startOffset());
  EXPECT_EQ(outer, range_outer_surrounding_text->endContainer());
  EXPECT_EQ(4u, range_outer_surrounding_text->endOffset());

  EXPECT_TRUE(range_inner_left->BoundaryPointsValid());
  EXPECT_EQ(inner_left, range_inner_left->startContainer());
  EXPECT_EQ(0u, range_inner_left->startOffset());
  EXPECT_EQ(inner_left, range_inner_left->endContainer());
  EXPECT_EQ(1u, range_inner_left->endOffset());

  EXPECT_TRUE(range_inner_right->BoundaryPointsValid());
  EXPECT_EQ(inner_right, range_inner_right->startContainer());
  EXPECT_EQ(0u, range_inner_right->startOffset());
  EXPECT_EQ(inner_right, range_inner_right->endContainer());
  EXPECT_EQ(1u, range_inner_right->endOffset());

  EXPECT_TRUE(range_from_text_to_middle_of_element->BoundaryPointsValid());
  EXPECT_EQ(new_text, range_from_text_to_middle_of_element->startContainer());
  EXPECT_EQ(3u, range_from_text_to_middle_of_element->startOffset());
  EXPECT_EQ(outer, range_from_text_to_middle_of_element->endContainer());
  EXPECT_EQ(4u, range_from_text_to_middle_of_element->endOffset());
}

TEST_F(RangeTest, updateOwnerDocumentIfNeeded) {
  Element* foo = GetDocument().CreateElementForBinding(AtomicString("foo"));
  Element* bar = GetDocument().CreateElementForBinding(AtomicString("bar"));
  foo->AppendChild(bar);

  auto* range = MakeGarbageCollected<Range>(GetDocument(), Position(bar, 0),
                                            Position(foo, 1));

  ScopedNullExecutionContext execution_context;
  auto* another_document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  another_document->AppendChild(foo);

  EXPECT_EQ(bar, range->startContainer());
  EXPECT_EQ(0u, range->startOffset());
  EXPECT_EQ(foo, range->endContainer());
  EXPECT_EQ(1u, range->endOffset());
}

// Regression test for crbug.com/639184
TEST_F(RangeTest, NotMarkedValidByIrrelevantTextInsert) {
  GetDocument().body()->setInnerHTML(
      "<div><span id=span1>foo</span>bar<span id=span2>baz</span></div>");

  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Element* span1 = GetDocument().getElementById(AtomicString("span1"));
  Element* span2 = GetDocument().getElementById(AtomicString("span2"));
  auto* text = To<Text>(div->childNodes()->item(1));

  auto* range = MakeGarbageCollected<Range>(GetDocument(), span2, 0, div, 3);

  div->RemoveChild(span1);
  text->insertData(0, "bar", ASSERT_NO_EXCEPTION);

  EXPECT_TRUE(range->BoundaryPointsValid());
  EXPECT_EQ(span2, range->startContainer());
  EXPECT_EQ(0u, range->startOffset());
  EXPECT_EQ(div, range->endContainer());
  EXPECT_EQ(2u, range->endOffset());
}

// Regression test for crbug.com/639184
TEST_F(RangeTest, NotMarkedValidByIrrelevantTextRemove) {
  GetDocument().body()->setInnerHTML(
      "<div><span id=span1>foofoo</span>bar<span id=span2>baz</span></div>");

  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Element* span1 = GetDocument().getElementById(AtomicString("span1"));
  Element* span2 = GetDocument().getElementById(AtomicString("span2"));
  auto* text = To<Text>(div->childNodes()->item(1));

  auto* range = MakeGarbageCollected<Range>(GetDocument(), span2, 0, div, 3);

  div->RemoveChild(span1);
  text->deleteData(0, 3, ASSERT_NO_EXCEPTION);

  EXPECT_TRUE(range->BoundaryPointsValid());
  EXPECT_EQ(span2, range->startContainer());
  EXPECT_EQ(0u, range->startOffset());
  EXPECT_EQ(div, range->endContainer());
  EXPECT_EQ(2u, range->endOffset());
}

// Regression test for crbug.com/698123
TEST_F(RangeTest, ExpandNotCrash) {
  Range* range = Range::Create(GetDocument());
  auto* div = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  range->setStart(div, 0, ASSERT_NO_EXCEPTION);
  range->expand("", ASSERT_NO_EXCEPTION);
}

TEST_F(RangeTest, ToPosition) {
  auto& textarea = *MakeGarbageCollected<HTMLTextAreaElement>(GetDocument());
  Range& range = *Range::Create(GetDocument());
  const Position position = Position(&textarea, 0);
  range.setStart(position, ASSERT_NO_EXCEPTION);
  EXPECT_EQ(position, range.StartPosition());
  EXPECT_EQ(position, range.EndPosition());
}

TEST_F(RangeTest, BoundingRectMustIndependentFromSelection) {
  LoadAhem();
  GetDocument().body()->setInnerHTML(
      "<div style='font: Ahem; width: 2em;letter-spacing: 5px;'>xx xx </div>");
  Node* const div = GetDocument().QuerySelector(AtomicString("div"));
  // "x^x
  //  x|x "
  auto* const range = MakeGarbageCollected<Range>(
      GetDocument(), div->firstChild(), 1, div->firstChild(), 4);
  const gfx::RectF rect_before = range->BoundingRect();
  EXPECT_GT(rect_before.width(), 0);
  EXPECT_GT(rect_before.height(), 0);
  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .SetBaseAndExtent(EphemeralRange(range))
                               .Build(),
                           SetSelectionOptions());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(Selection().SelectedText(), "x x");
  const gfx::RectF rect_after = range->BoundingRect();
  EXPECT_EQ(rect_before, rect_after);
}

// Regression test for crbug.com/681536
TEST_F(RangeTest, BorderAndTextQuadsWithInputInBetween) {
  GetDocument().body()->setInnerHTML("<div>foo <u><input> bar</u></div>");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  Node* foo = GetDocument().QuerySelector(AtomicString("div"))->firstChild();
  Node* bar = GetDocument().QuerySelector(AtomicString("u"))->lastChild();
  auto* range = MakeGarbageCollected<Range>(GetDocument(), foo, 2, bar, 2);

  Vector<gfx::QuadF> quads;
  range->GetBorderAndTextQuads(quads);

  // Should get one quad for "o ", <input> and " b", respectively.
  ASSERT_EQ(3u, quads.size());
}

static Vector<gfx::QuadF> GetBorderAndTextQuads(const Position& start,
                                                const Position& end) {
  DCHECK_LE(start, end);
  auto* const range =
      MakeGarbageCollected<Range>(*start.GetDocument(), start, end);
  Vector<gfx::QuadF> quads;
  range->GetBorderAndTextQuads(quads);
  return quads;
}

static Vector<gfx::Size> ComputeSizesOfQuads(const Vector<gfx::QuadF>& quads) {
  Vector<gfx::Size> sizes;
  for (const auto& quad : quads)
    sizes.push_back(gfx::ToEnclosingRect(quad.BoundingBox()).size());
  return sizes;
}

// http://crbug.com/1240510
TEST_F(RangeTest, GetBorderAndTextQuadsWithCombinedText) {
  LoadAhem();
  InsertStyleElement(
      "body { font: 20px/25px Ahem; margin: 0px; }"
      "#sample { writing-mode: vertical-rl; }"
      "c { text-combine-upright: all; }");
  SetBodyInnerHTML(
      "<div id=sample>"
      "<c id=c1>M</c><c id=c2>MM</c><c id=c3>MMM</c><c id=c4>MMMM</c>"
      "</div>");
  const Text& text1 = *To<Text>(GetElementById("c1")->firstChild());
  const Text& text2 = *To<Text>(GetElementById("c2")->firstChild());
  const Text& text3 = *To<Text>(GetElementById("c3")->firstChild());
  const Text& text4 = *To<Text>(GetElementById("c4")->firstChild());

  EXPECT_THAT(GetBorderAndTextQuads(Position(text1, 0), Position(text1, 1)),
              ElementsAre(gfx::QuadF(gfx::RectF(3, 0, 20, 20))));
  EXPECT_THAT(GetBorderAndTextQuads(Position(text2, 0), Position(text2, 2)),
              ElementsAre(gfx::QuadF(gfx::RectF(2, 20, 22, 20))));
  EXPECT_THAT(GetBorderAndTextQuads(Position(text3, 0), Position(text3, 3)),
              ElementsAre(gfx::QuadF(gfx::RectF(2, 40, 22, 20))));
  EXPECT_THAT(GetBorderAndTextQuads(Position(text4, 0), Position(text4, 4)),
              ElementsAre(gfx::QuadF(gfx::RectF(2, 60, 22, 20))));
}

TEST_F(RangeTest, GetBorderAndTextQuadsWithFirstLetterOne) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { font-size: 20px; }
      #sample::first-letter { font-size: 500%; }
    </style>
    <p id=sample>abc</p>
    <p id=expected><span style='font-size: 500%'>a</span>bc</p>
  )HTML");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  Element* const expected =
      GetDocument().getElementById(AtomicString("expected"));
  Element* const sample = GetDocument().getElementById(AtomicString("sample"));

  const Vector<gfx::QuadF> expected_quads =
      GetBorderAndTextQuads(Position(expected, 0), Position(expected, 2));
  const Vector<gfx::QuadF> sample_quads =
      GetBorderAndTextQuads(Position(sample, 0), Position(sample, 1));
  ASSERT_EQ(2u, sample_quads.size());
  ASSERT_EQ(3u, expected_quads.size())
      << "expected_quads has SPAN, SPAN.firstChild and P.lastChild";
  EXPECT_EQ(gfx::ToEnclosingRect(expected_quads[0].BoundingBox()).size(),
            gfx::ToEnclosingRect(sample_quads[0].BoundingBox()).size())
      << "Check size of first-letter part";
  EXPECT_EQ(gfx::ToEnclosingRect(expected_quads[2].BoundingBox()).size(),
            gfx::ToEnclosingRect(sample_quads[1].BoundingBox()).size())
      << "Check size of first-letter part";

  EXPECT_EQ(ComputeSizesOfQuads(
                GetBorderAndTextQuads(Position(expected->firstChild(), 0),
                                      Position(expected->firstChild(), 1))),
            ComputeSizesOfQuads(
                GetBorderAndTextQuads(Position(sample->firstChild(), 0),
                                      Position(sample->firstChild(), 1))))
      << "All first-letter part";

  EXPECT_EQ(ComputeSizesOfQuads(
                GetBorderAndTextQuads(Position(expected->lastChild(), 0),
                                      Position(expected->lastChild(), 2))),
            ComputeSizesOfQuads(
                GetBorderAndTextQuads(Position(sample->firstChild(), 1),
                                      Position(sample->firstChild(), 3))))
      << "All remaining part";
}

TEST_F(RangeTest, GetBorderAndTextQuadsWithFirstLetterThree) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { font-size: 20px; }
      #sample::first-letter { font-size: 500%; }
    </style>
    <p id=sample>(a)bc</p>
    <p id=expected><span style='font-size: 500%'>(a)</span>bc</p>
  )HTML");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  Element* const expected =
      GetDocument().getElementById(AtomicString("expected"));
  Element* const sample = GetDocument().getElementById(AtomicString("sample"));

  const Vector<gfx::QuadF> expected_quads =
      GetBorderAndTextQuads(Position(expected, 0), Position(expected, 2));
  const Vector<gfx::QuadF> sample_quads =
      GetBorderAndTextQuads(Position(sample, 0), Position(sample, 1));
  ASSERT_EQ(2u, sample_quads.size());
  ASSERT_EQ(3u, expected_quads.size())
      << "expected_quads has SPAN, SPAN.firstChild and P.lastChild";
  EXPECT_EQ(gfx::ToEnclosingRect(expected_quads[0].BoundingBox()).size(),
            gfx::ToEnclosingRect(sample_quads[0].BoundingBox()).size())
      << "Check size of first-letter part";
  EXPECT_EQ(gfx::ToEnclosingRect(expected_quads[2].BoundingBox()).size(),
            gfx::ToEnclosingRect(sample_quads[1].BoundingBox()).size())
      << "Check size of first-letter part";

  EXPECT_EQ(ComputeSizesOfQuads(
                GetBorderAndTextQuads(Position(expected->firstChild(), 0),
                                      Position(expected->firstChild(), 1))),
            ComputeSizesOfQuads(
                GetBorderAndTextQuads(Position(sample->firstChild(), 0),
                                      Position(sample->firstChild(), 3))))
      << "All first-letter part";

  EXPECT_EQ(ComputeSizesOfQuads(
                GetBorderAndTextQuads(Position(expected->lastChild(), 0),
                                      Position(expected->lastChild(), 2))),
            ComputeSizesOfQuads(
                GetBorderAndTextQuads(Position(sample->firstChild(), 3),
                                      Position(sample->firstChild(), 5))))
      << "All remaining part";

  EXPECT_EQ(ComputeSizesOfQuads(GetBorderAndTextQuads(
                Position(expected->firstChild()->firstChild(), 1),
                Position(expected->firstChild()->firstChild(), 2))),
            ComputeSizesOfQuads(
                GetBorderAndTextQuads(Position(sample->firstChild(), 1),
                                      Position(sample->firstChild(), 2))))
      << "Partial first-letter part";

  EXPECT_EQ(ComputeSizesOfQuads(GetBorderAndTextQuads(
                Position(expected->firstChild()->firstChild(), 1),
                Position(expected->lastChild(), 1))),
            ComputeSizesOfQuads(
                GetBorderAndTextQuads(Position(sample->firstChild(), 1),
                                      Position(sample->firstChild(), 4))))
      << "Partial first-letter part and remaining part";
}

TEST_F(RangeTest, CollapsedRangeGetBorderAndTextQuadsWithFirstLetter) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { font-size: 20px; }
      #sample::first-letter { font-size: 500%; }
    </style>
    <p id=sample>abc</p>
    <p id=expected><span style='font-size: 500%'>a</span>bc</p>
  )HTML");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  Element* const expected =
      GetDocument().getElementById(AtomicString("expected"));
  Element* const sample = GetDocument().getElementById(AtomicString("sample"));

  const Vector<gfx::QuadF> expected_quads =
      GetBorderAndTextQuads(Position(expected, 0), Position(expected, 2));
  const Vector<gfx::QuadF> sample_quads =
      GetBorderAndTextQuads(Position(sample, 0), Position(sample, 1));
  ASSERT_EQ(2u, sample_quads.size());
  ASSERT_EQ(3u, expected_quads.size())
      << "expected_quads has SPAN, SPAN.firstChild and P.lastChild";
  EXPECT_EQ(gfx::ToEnclosingRect(expected_quads[0].BoundingBox()).size(),
            gfx::ToEnclosingRect(sample_quads[0].BoundingBox()).size())
      << "Check size of first-letter part";
  EXPECT_EQ(gfx::ToEnclosingRect(expected_quads[2].BoundingBox()).size(),
            gfx::ToEnclosingRect(sample_quads[1].BoundingBox()).size())
      << "Check size of first-letter part";

  EXPECT_EQ(ComputeSizesOfQuads(GetBorderAndTextQuads(
                Position(expected->firstChild()->firstChild(), 0),
                Position(expected->firstChild()->firstChild(), 0))),
            ComputeSizesOfQuads(
                GetBorderAndTextQuads(Position(sample->firstChild(), 0),
                                      Position(sample->firstChild(), 0))))
      << "Collapsed range before first-letter part";

  EXPECT_EQ(ComputeSizesOfQuads(GetBorderAndTextQuads(
                Position(expected->firstChild()->firstChild(), 1),
                Position(expected->firstChild()->firstChild(), 1))),
            ComputeSizesOfQuads(
                GetBorderAndTextQuads(Position(sample->firstChild(), 1),
                                      Position(sample->firstChild(), 1))))
      << "Collapsed range after first-letter part";

  EXPECT_EQ(ComputeSizesOfQuads(GetBorderAndTextQuads(
                Position(expected->firstChild()->nextSibling(), 1),
                Position(expected->firstChild()->nextSibling(), 1))),
            ComputeSizesOfQuads(
                GetBorderAndTextQuads(Position(sample->firstChild(), 2),
                                      Position(sample->firstChild(), 2))))
      << "Collapsed range in remaining text part";
}

TEST_F(RangeTest, ContainerNodeRemoval) {
  GetDocument().body()->setInnerHTML("<p>aaaa</p><p>bbbbbb</p>");
  auto* node_a = GetDocument().body()->firstChild();
  auto* node_b = node_a->nextSibling();
  auto* text_a = To<Text>(node_a->firstChild());
  auto* text_b = To<Text>(node_b->firstChild());

  auto* rangea0a2 =
      MakeGarbageCollected<Range>(GetDocument(), text_a, 0, text_a, 2);
  auto* rangea2a4 =
      MakeGarbageCollected<Range>(GetDocument(), text_a, 2, text_a, 4);
  auto* rangea2b2 =
      MakeGarbageCollected<Range>(GetDocument(), text_a, 0, text_b, 2);
  auto* rangeb2b6 =
      MakeGarbageCollected<Range>(GetDocument(), text_b, 2, text_b, 6);

  // remove children in node_a
  node_a->setTextContent("");

  EXPECT_TRUE(rangea0a2->BoundaryPointsValid());
  EXPECT_EQ(node_a, rangea0a2->startContainer());
  EXPECT_EQ(0u, rangea0a2->startOffset());
  EXPECT_EQ(node_a, rangea0a2->endContainer());
  EXPECT_EQ(0u, rangea0a2->endOffset());

  EXPECT_TRUE(rangea2a4->BoundaryPointsValid());
  EXPECT_EQ(node_a, rangea2a4->startContainer());
  EXPECT_EQ(0u, rangea2a4->startOffset());
  EXPECT_EQ(node_a, rangea2a4->endContainer());
  EXPECT_EQ(0u, rangea2a4->endOffset());

  EXPECT_TRUE(rangea2b2->BoundaryPointsValid());
  EXPECT_EQ(node_a, rangea2b2->startContainer());
  EXPECT_EQ(0u, rangea2b2->startOffset());
  EXPECT_EQ(text_b, rangea2b2->endContainer());
  EXPECT_EQ(2u, rangea2b2->endOffset());

  EXPECT_TRUE(rangeb2b6->BoundaryPointsValid());
  EXPECT_EQ(text_b, rangeb2b6->startContainer());
  EXPECT_EQ(2u, rangeb2b6->startOffset());
  EXPECT_EQ(text_b, rangeb2b6->endContainer());
  EXPECT_EQ(6u, rangeb2b6->endOffset());

  // remove children in body.
  GetDocument().body()->setTextContent("");

  EXPECT_TRUE(rangea0a2->BoundaryPointsValid());
  EXPECT_EQ(GetDocument().body(), rangea0a2->startContainer());
  EXPECT_EQ(0u, rangea0a2->startOffset());
  EXPECT_EQ(GetDocument().body(), rangea0a2->endContainer());
  EXPECT_EQ(0u, rangea0a2->endOffset());

  EXPECT_TRUE(rangea2a4->BoundaryPointsValid());
  EXPECT_EQ(GetDocument().body(), rangea2a4->startContainer());
  EXPECT_EQ(0u, rangea2a4->startOffset());
  EXPECT_EQ(GetDocument().body(), rangea2a4->endContainer());
  EXPECT_EQ(0u, rangea2a4->endOffset());

  EXPECT_TRUE(rangea2b2->BoundaryPointsValid());
  EXPECT_EQ(GetDocument().body(), rangea2b2->startContainer());
  EXPECT_EQ(0u, rangea2b2->startOffset());
  EXPECT_EQ(GetDocument().body(), rangea2b2->endContainer());
  EXPECT_EQ(0u, rangea2b2->endOffset());

  EXPECT_TRUE(rangeb2b6->BoundaryPointsValid());
  EXPECT_EQ(GetDocument().body(), rangeb2b6->startContainer());
  EXPECT_EQ(0u, rangeb2b6->startOffset());
  EXPECT_EQ(GetDocument().body(), rangeb2b6->endContainer());
  EXPECT_EQ(0u, rangeb2b6->endOffset());
}

TEST_F(RangeTest,
       ContainerNodeRemovalWithSequentialFocusNavigationStartingPoint) {
  SetBodyContent("<input value='text inside input'>");
  const auto& input =
      ToTextControl(*GetDocument().QuerySelector(AtomicString("input")));
  Node* text_inside_input = input.InnerEditorElement()->firstChild();
  GetDocument().SetSequentialFocusNavigationStartingPoint(text_inside_input);

  // Remove children in body.
  GetDocument().body()->setTextContent("");

  Range* sequential_focus_navigation_starting_point =
      GetDocument().sequential_focus_navigation_starting_point_;

  EXPECT_TRUE(
      sequential_focus_navigation_starting_point->BoundaryPointsValid());
  EXPECT_EQ(GetDocument().body(),
            sequential_focus_navigation_starting_point->startContainer());
  EXPECT_EQ(0u, sequential_focus_navigation_starting_point->startOffset());
  EXPECT_EQ(GetDocument().body(),
            sequential_focus_navigation_starting_point->endContainer());
  EXPECT_EQ(0u, sequential_focus_navigation_starting_point->endOffset());
}

}  // namespace blink

"""

```