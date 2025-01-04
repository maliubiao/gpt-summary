Response:
Let's break down the thought process to analyze the `character_iterator_test.cc` file.

1. **Understand the Core Purpose:** The file name itself, `character_iterator_test.cc`, strongly suggests that it's a test file. Specifically, it's testing the functionality of something called `CharacterIterator`. The location in the directory structure (`blink/renderer/core/editing/iterators/`) provides further context: it's related to text editing within the Blink rendering engine, and the `iterators` part suggests it deals with traversing text content.

2. **Examine the Includes:**  The included headers are crucial for understanding the dependencies and context:
    * `"third_party/blink/renderer/core/editing/iterators/character_iterator.h"`: This confirms the primary subject of the test is the `CharacterIterator` class.
    * `"third_party/blink/renderer/core/editing/ephemeral_range.h"`: This indicates that `CharacterIterator` likely operates on or is related to `EphemeralRange`, which represents a selection of content.
    * `"third_party/blink/renderer/core/editing/testing/editing_test_base.h"`: This is a strong signal that it's a unit test using a testing framework. `EditingTestBase` likely provides helper functions for setting up test environments (like creating DOM structures).
    * `"third_party/blink/renderer/core/frame/local_frame_view.h"`:  This suggests the tests might interact with the rendering frame, although its direct usage might be indirect through `EditingTestBase`.
    * `"third_party/blink/renderer/platform/heap/garbage_collected.h"`: This tells us that the objects involved are managed by Blink's garbage collector, which is important for memory management considerations in the actual implementation (though less directly relevant to understanding the *tests* themselves).

3. **Analyze the Test Structure:**  The file defines a test fixture (`CharacterIteratorTest`) that inherits from `EditingTestBase`. This reinforces the idea that it's a structured unit test. The `TEST_F` macros are the core of the tests. Each `TEST_F` block represents a distinct test case for a specific aspect of `CharacterIterator` functionality.

4. **Dissect Individual Test Cases:**  For each test case, identify the following:
    * **Setup (`SetBodyContent`):**  How is the initial DOM structure created for the test?  This often involves HTML strings. Pay attention to the elements and text content being created.
    * **Core Operation (Instantiating `CharacterIterator` and calling methods):**  What is the `CharacterIterator` being initialized with? What methods are being called on it (e.g., `Advance`, `GetPositionBefore`, `GetPositionAfter`, `StartPosition`, `EndPosition`, `AtEnd`)?
    * **Assertions (`EXPECT_EQ`, `ASSERT_FALSE`, `EXPECT_TRUE`):** What are the expected outcomes of the operations?  The assertions compare the actual results of the `CharacterIterator` methods with the expected values. This is where the specific behavior being tested is defined.

5. **Identify the Functionality Being Tested:** Based on the test cases, summarize what aspects of `CharacterIterator` are being exercised:
    * Traversal of text nodes.
    * Handling of different types of elements (images, divs, paragraphs, line breaks).
    * Handling of collapsed subranges (zero-length selections).
    * Behavior at the boundaries of elements.
    * Handling of whitespace and `white-space: pre`.
    * The `CalculateCharacterSubrange` function (though less extensively).

6. **Relate to Web Technologies (JavaScript, HTML, CSS):**  Think about how the tested functionality relates to these technologies:
    * **HTML:** The test cases directly manipulate HTML structures. The `CharacterIterator` is designed to work with the DOM that HTML creates.
    * **JavaScript:**  JavaScript can interact with the DOM and perform text selection and manipulation. The `CharacterIterator` provides a low-level mechanism that JavaScript's higher-level APIs might rely on. Consider how a JavaScript selection API might internally use similar concepts.
    * **CSS:** The "GetPositionWithCollapsedWhitespaces" and "GetPositionWithEmitChar16Before" tests explicitly involve CSS `white-space` properties, demonstrating the interaction between rendering and text iteration.

7. **Infer Logic and Assumptions:** For tests involving `Advance`, try to trace the movement of the iterator and the expected positions. Consider the underlying assumptions about how the iterator moves through the DOM tree. For example, it appears to treat certain elements (like `<div>` and `<p>`) as single "characters" when advancing across them.

8. **Identify Potential User/Programming Errors:** Think about how developers might misuse the `CharacterIterator` or make assumptions that these tests help to guard against. For instance, forgetting to check `AtEnd()` could lead to out-of-bounds access.

9. **Construct Debugging Scenarios:**  Imagine a user action in the browser that could lead to the execution of this code. For example, selecting text and then performing an operation on that selection is a prime candidate.

10. **Structure the Explanation:** Organize the findings logically, starting with the primary function of the file and then drilling down into specifics. Use clear language and examples to illustrate the concepts.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just a test file."  **Refinement:**  "It's testing a *specific* class related to text editing and iteration."
* **Initial thought:** "The includes are just standard stuff." **Refinement:** "No, the specific includes tell us *exactly* what dependencies are involved and provide important context."
* **While analyzing a test case:** "Why are there two `EXPECT_EQ` for `GetPositionBefore` and `GetPositionAfter` when they're the same?" **Realization:** This likely reflects the iterator's position *between* characters or nodes. It can be *before* or *after* a specific unit.
* **Struggling to understand a complex test:**  Draw a simple DOM tree diagram on paper to visualize the structure and the iterator's movement.

By following this systematic approach, combining code analysis with conceptual understanding of web technologies and potential use cases, we can arrive at a comprehensive explanation of the `character_iterator_test.cc` file.这个文件 `character_iterator_test.cc` 是 Chromium Blink 引擎中用于测试 `CharacterIterator` 类的单元测试文件。 `CharacterIterator` 类位于 `blink/renderer/core/editing/iterators/character_iterator.h`，它的主要功能是**遍历文档中的字符（或者更准确地说，用户可见的最小文本单元）**。

让我们详细列举一下它的功能以及与 Web 技术的关系，并进行逻辑推理和错误分析：

**1. 文件功能：**

* **测试 `CharacterIterator` 类的核心功能:**  该文件通过一系列的单元测试用例，验证 `CharacterIterator` 类的各种方法是否按预期工作。
* **测试字符级别的遍历:** 主要关注在不同的 DOM 结构中，`CharacterIterator` 如何正确地移动和定位到每个用户可见的字符。这包括处理文本节点、元素节点（如 `<div>`, `<p>`)、替换元素（如 `<img>`) 和换行符 (`<br>`)。
* **测试位置信息的获取:**  验证 `GetPositionBefore()`, `GetPositionAfter()`, `StartPosition()`, `EndPosition()` 等方法是否返回正确的 `Position` 对象，用于描述字符前后的位置。
* **测试子范围计算:**  验证 `CalculateCharacterSubrange()` 函数是否能够根据字符偏移量正确计算出一个新的 `EphemeralRange` 对象。
* **覆盖各种 DOM 结构场景:**  测试用例涵盖了包含文本、块级元素、内联元素、替换元素、空格等多种不同的 HTML 结构，确保 `CharacterIterator` 在各种情况下都能正确工作。

**2. 与 JavaScript, HTML, CSS 的关系：**

* **HTML:** `CharacterIterator` 直接作用于 HTML 构建的 DOM 树。测试用例通过设置不同的 `body_content` (HTML 字符串) 来创建不同的 DOM 结构，然后使用 `CharacterIterator` 遍历这些结构。例如，测试用例中使用了 `<div>`, `<img>`, `<p>`, `<br>` 等 HTML 元素，验证迭代器在遇到这些元素时的行为。
* **JavaScript:** JavaScript 可以通过 DOM API (如 `document.getElementById`, `childNodes`, `firstChild`, `lastChild` 等) 访问和操作 DOM 结构。`CharacterIterator` 提供的字符级别遍历能力，可以被 Blink 引擎内部用于实现一些与文本编辑相关的 JavaScript 功能，例如：
    * **光标移动和文本选择:** 当用户在浏览器中移动光标或选择文本时，Blink 引擎可能使用类似 `CharacterIterator` 的机制来确定光标或选区的精确位置。
    * **`Selection` API 的底层实现:** JavaScript 的 `Selection` 对象允许获取用户选中的文本范围。`CharacterIterator` 可以作为其底层实现的一部分，用于遍历和定位选区边界。
    * **`Range` API 的操作:** JavaScript 的 `Range` 对象代表文档中的一个片段。`CharacterIterator` 可以用于在 `Range` 上进行字符级别的操作，例如计算字符长度、截取子范围等。
* **CSS:** CSS 可以影响文本的渲染和布局，进而影响用户可见的字符。例如：
    * **`white-space` 属性:**  测试用例 `GetPositionWithCollapsedWhitespaces` 和 `GetPositionWithEmitChar16Before` 涉及到 `white-space` 属性。这个属性决定了如何处理元素中的空白符。`CharacterIterator` 需要理解 CSS 的渲染效果，以便正确地遍历用户可见的字符。例如，当 `white-space: normal` 时，连续的空格会被合并为一个，`CharacterIterator` 应该将其视为一个字符单元。当 `white-space: pre` 时，空格不会被合并，`CharacterIterator` 则应该分别处理每个空格。
    * **行内元素和块级元素:** 测试用例 `GetPositionWithBlock` 和 `GetPositionWithBlocks` 涉及到块级元素 (`<div>`, `<p>`)。`CharacterIterator` 需要处理跨越块级元素的边界。

**举例说明：**

* **HTML:** 在 `SubrangeWithReplacedElements` 测试中，HTML 字符串 `<div id='div' contenteditable='true'>1<img src='foo.png'>345</div>` 创建了一个包含文本和图片元素的 `div`。`CharacterIterator` 需要能够跳过 `<img>` 元素，将其作为一个单独的字符单元来处理。
* **JavaScript:** 假设一个 JavaScript 功能需要获取用户在一个 `contenteditable` 的 `div` 中选中的文本。Blink 引擎可能会使用 `CharacterIterator` 来遍历选区范围内的节点和文本，最终提取出用户选中的字符。
* **CSS:** 在 `GetPositionWithCollapsedWhitespaces` 测试中，HTML "a <div> b </div> c" 在渲染时，`a` 和 `<div>` 之间的空格会被折叠。`CharacterIterator` 在遍历时，需要将这个折叠后的空格视为一个字符单元。

**3. 逻辑推理 (假设输入与输出):**

* **假设输入 (for `CollapsedSubrange`):**
    * HTML: `<div id='div' contenteditable='true'>hello</div>`
    * 初始 Range:  包含 "ell" 这三个字符 (从 'h' 的索引 1 到 'o' 的索引 4)。
    * `CalculateCharacterSubrange` 的偏移量: `offset=2`, `length=0` (表示一个长度为 0 的子范围，即一个折叠的光标位置)。
* **逻辑:** `CalculateCharacterSubrange` 函数应该从初始 Range 的起始位置偏移 2 个字符，然后创建一个长度为 0 的子范围。
* **预期输出:** 一个新的 `EphemeralRange`，其 `StartPosition` 和 `EndPosition` 都指向 'l' 字符的末尾 (文本节点的偏移量 3)。 这与测试用例中的 `EXPECT_EQ(Position(text_node, 3), result.StartPosition());` 和 `EXPECT_EQ(Position(text_node, 3), result.EndPosition());` 一致。

**4. 用户或编程常见的使用错误：**

* **忘记处理替换元素:** 开发者在实现文本处理逻辑时，可能会错误地将替换元素（如 `<img>`) 视为普通文本节点，导致字符计数错误。`CharacterIterator` 的测试用例确保了 Blink 引擎能够正确地将替换元素作为一个单独的字符单元处理。
* **错误计算跨元素边界的字符偏移:**  在复杂的 DOM 结构中，计算从一个元素到另一个元素的字符偏移量可能会出错。`CharacterIterator` 提供了正确遍历和定位的方法，避免开发者手动进行复杂的 DOM 遍历。
* **忽略 `white-space` 属性的影响:**  开发者在处理文本内容时，可能会忘记考虑 CSS 的 `white-space` 属性对空白符的影响，导致字符计数或位置计算错误。`CharacterIterator` 的相关测试用例强调了这一点。

**5. 用户操作如何一步步地到达这里（调试线索）：**

以下是一些用户操作可能触发与 `CharacterIterator` 相关的代码执行的场景：

1. **在 `contenteditable` 元素中输入文本:**
   * 用户在一个可编辑的区域点击并开始输入字符。
   * Blink 引擎需要跟踪光标的位置，这可能涉及到 `CharacterIterator` 来确定插入点。
   * 当输入换行符、空格等特殊字符时，`CharacterIterator` 需要正确地处理这些字符。

2. **在 `contenteditable` 元素中进行文本选择:**
   * 用户拖动鼠标或使用键盘快捷键选择一段文本。
   * Blink 引擎需要计算选区的起始和结束位置，这可能依赖于 `CharacterIterator` 来遍历 DOM 树，找到选区边界对应的 `Position` 对象。

3. **复制和粘贴文本:**
   * 用户复制一段文本，然后在另一个位置粘贴。
   * Blink 引擎需要分析复制的文本内容和目标位置的 DOM 结构，这可能涉及 `CharacterIterator` 来定位插入点和处理粘贴的内容。

4. **使用浏览器的 "查找" 功能 (Ctrl+F 或 Cmd+F):**
   * 用户在页面上搜索特定的文本字符串。
   * Blink 引擎需要遍历页面的 DOM 树，查找匹配的文本，这可能会使用类似 `CharacterIterator` 的机制来逐个字符地比较。

5. **通过 JavaScript 操作 `Selection` 或 `Range` 对象:**
   * 开发者使用 JavaScript 的 `document.getSelection()` 获取用户选区，或创建 `Range` 对象来表示文档片段。
   * 这些 JavaScript API 的底层实现很可能会用到 `CharacterIterator` 来进行精细的文本定位和操作。

**作为调试线索，当你遇到与文本编辑相关的 bug 时，例如：**

* 光标在可编辑区域移动不正确。
* 文本选择范围错误。
* 复制粘贴的内容格式错乱。
* 浏览器 "查找" 功能找不到某些文本。

**你可以考虑以下调试步骤：**

1. **检查 DOM 结构:** 使用浏览器的开发者工具查看相关的 DOM 结构，确认是否存在异常的节点或属性。
2. **断点调试 Blink 渲染引擎的代码:**  在 Blink 引擎的源代码中，与文本编辑和 `CharacterIterator` 相关的代码处设置断点，例如 `blink/renderer/core/editing/`, `blink/renderer/core/editing/iterators/` 等目录下的文件。
3. **跟踪 `CharacterIterator` 的执行:** 观察 `CharacterIterator` 的创建、初始化和各个方法的调用过程，查看其返回的 `Position` 对象是否正确，以及在遍历过程中的行为是否符合预期。
4. **分析相关的测试用例:**  查看 `character_iterator_test.cc` 文件中是否有类似的测试用例覆盖了你遇到的场景，通过理解测试用例的逻辑，可以帮助你更好地理解 `CharacterIterator` 的工作原理，并找到 bug 的原因。

总而言之，`character_iterator_test.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎的 `CharacterIterator` 类能够可靠地进行字符级别的文档遍历，这是实现浏览器文本编辑和相关功能的基础。理解这个文件的功能和测试用例，对于深入理解 Blink 引擎的文本处理机制非常有帮助。

Prompt: 
```
这是目录为blink/renderer/core/editing/iterators/character_iterator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (c) 2013, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/editing/iterators/character_iterator.h"

#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

class CharacterIteratorTest : public EditingTestBase {};

TEST_F(CharacterIteratorTest, SubrangeWithReplacedElements) {
  static const char* body_content =
      "<div id='div' contenteditable='true'>1<img src='foo.png'>345</div>";
  SetBodyContent(body_content);
  UpdateAllLifecyclePhasesForTest();

  Node* div_node = GetDocument().getElementById(AtomicString("div"));
  auto* entire_range =
      MakeGarbageCollected<Range>(GetDocument(), div_node, 0, div_node, 3);

  EphemeralRange result =
      CalculateCharacterSubrange(EphemeralRange(entire_range), 2, 3);
  Node* text_node = div_node->lastChild();
  EXPECT_EQ(Position(text_node, 0), result.StartPosition());
  EXPECT_EQ(Position(text_node, 3), result.EndPosition());
}

TEST_F(CharacterIteratorTest, CollapsedSubrange) {
  static const char* body_content =
      "<div id='div' contenteditable='true'>hello</div>";
  SetBodyContent(body_content);
  UpdateAllLifecyclePhasesForTest();

  Node* text_node =
      GetDocument().getElementById(AtomicString("div"))->lastChild();
  auto* entire_range =
      MakeGarbageCollected<Range>(GetDocument(), text_node, 1, text_node, 4);
  EXPECT_EQ(1u, entire_range->startOffset());
  EXPECT_EQ(4u, entire_range->endOffset());

  const EphemeralRange& result =
      CalculateCharacterSubrange(EphemeralRange(entire_range), 2, 0);
  EXPECT_EQ(Position(text_node, 3), result.StartPosition());
  EXPECT_EQ(Position(text_node, 3), result.EndPosition());
}

TEST_F(CharacterIteratorTest, GetPositionWithBlock) {
  SetBodyContent("a<div>b</div>c");

  const Element& body = *GetDocument().body();
  CharacterIterator it(EphemeralRange::RangeOfContents(body));

  const Node& text_a = *body.firstChild();
  const Node& div = *text_a.nextSibling();
  const Node& text_b = *div.firstChild();
  const Node& text_c = *body.lastChild();

  EXPECT_EQ(Position(text_a, 0), it.GetPositionBefore());
  EXPECT_EQ(Position(text_a, 1), it.GetPositionAfter());
  EXPECT_EQ(Position(text_a, 0), it.StartPosition());
  EXPECT_EQ(Position(text_a, 1), it.EndPosition());

  ASSERT_FALSE(it.AtEnd());
  it.Advance(1);
  EXPECT_EQ(Position::BeforeNode(div), it.GetPositionBefore());
  EXPECT_EQ(Position::BeforeNode(div), it.GetPositionAfter());
  EXPECT_EQ(Position(body, 1), it.StartPosition());
  EXPECT_EQ(Position(body, 1), it.EndPosition());

  ASSERT_FALSE(it.AtEnd());
  it.Advance(1);
  EXPECT_EQ(Position(text_b, 0), it.GetPositionBefore());
  EXPECT_EQ(Position(text_b, 1), it.GetPositionAfter());
  EXPECT_EQ(Position(text_b, 0), it.StartPosition());
  EXPECT_EQ(Position(text_b, 1), it.EndPosition());

  ASSERT_FALSE(it.AtEnd());
  it.Advance(1);
  EXPECT_EQ(Position(text_b, 1), it.GetPositionBefore());
  EXPECT_EQ(Position(text_b, 1), it.GetPositionAfter());
  EXPECT_EQ(Position(div, 1), it.StartPosition());
  EXPECT_EQ(Position(div, 1), it.EndPosition());

  ASSERT_FALSE(it.AtEnd());
  it.Advance(1);
  EXPECT_EQ(Position(text_c, 0), it.GetPositionBefore());
  EXPECT_EQ(Position(text_c, 1), it.GetPositionAfter());
  EXPECT_EQ(Position(text_c, 0), it.StartPosition());
  EXPECT_EQ(Position(text_c, 1), it.EndPosition());

  ASSERT_FALSE(it.AtEnd());
  it.Advance(1);
  EXPECT_EQ(Position(body, 3), it.GetPositionBefore());
  EXPECT_EQ(Position(body, 3), it.GetPositionAfter());
  EXPECT_EQ(Position(body, 3), it.StartPosition());
  EXPECT_EQ(Position(body, 3), it.EndPosition());

  EXPECT_TRUE(it.AtEnd());
}

TEST_F(CharacterIteratorTest, GetPositionWithBlocks) {
  SetBodyContent("<p id=a>b</p><p id=c>d</p>");

  const Element& body = *GetDocument().body();
  CharacterIterator it(EphemeralRange::RangeOfContents(body));

  const Node& element_p_a = *GetDocument().getElementById(AtomicString("a"));
  const Node& text_b = *element_p_a.firstChild();
  const Node& element_p_c = *GetDocument().getElementById(AtomicString("c"));
  const Node& text_d = *element_p_c.firstChild();

  EXPECT_EQ(Position(text_b, 0), it.GetPositionBefore());
  EXPECT_EQ(Position(text_b, 1), it.GetPositionAfter());
  EXPECT_EQ(Position(text_b, 0), it.StartPosition());
  EXPECT_EQ(Position(text_b, 1), it.EndPosition());

  ASSERT_FALSE(it.AtEnd());
  it.Advance(1);
  EXPECT_EQ(Position(text_b, 1), it.GetPositionBefore());
  EXPECT_EQ(Position(text_b, 1), it.GetPositionAfter());
  EXPECT_EQ(Position(element_p_a, 1), it.StartPosition());
  EXPECT_EQ(Position(element_p_a, 1), it.EndPosition());

  ASSERT_FALSE(it.AtEnd());
  it.Advance(1);
  EXPECT_EQ(Position(text_b, 1), it.GetPositionBefore());
  EXPECT_EQ(Position(text_b, 1), it.GetPositionAfter());
  EXPECT_EQ(Position(element_p_a, 1), it.StartPosition());
  EXPECT_EQ(Position(element_p_a, 1), it.EndPosition());

  ASSERT_FALSE(it.AtEnd());
  it.Advance(1);
  EXPECT_EQ(Position(text_d, 0), it.GetPositionBefore());
  EXPECT_EQ(Position(text_d, 1), it.GetPositionAfter());
  EXPECT_EQ(Position(text_d, 0), it.StartPosition());
  EXPECT_EQ(Position(text_d, 1), it.EndPosition());

  ASSERT_FALSE(it.AtEnd());
  it.Advance(1);
  EXPECT_EQ(Position(body, 2), it.GetPositionBefore());
  EXPECT_EQ(Position(body, 2), it.GetPositionAfter());
  EXPECT_EQ(Position(body, 2), it.StartPosition());
  EXPECT_EQ(Position(body, 2), it.EndPosition());

  EXPECT_TRUE(it.AtEnd());
}

TEST_F(CharacterIteratorTest, GetPositionWithBR) {
  SetBodyContent("a<br>b");

  const Element& body = *GetDocument().body();
  CharacterIterator it(EphemeralRange::RangeOfContents(body));

  const Node& text_a = *body.firstChild();
  const Node& br = *GetDocument().QuerySelector(AtomicString("br"));
  const Node& text_b = *body.lastChild();

  EXPECT_EQ(Position(text_a, 0), it.GetPositionBefore());
  EXPECT_EQ(Position(text_a, 1), it.GetPositionAfter());
  EXPECT_EQ(Position(text_a, 0), it.StartPosition());
  EXPECT_EQ(Position(text_a, 1), it.EndPosition());

  ASSERT_FALSE(it.AtEnd());
  it.Advance(1);
  EXPECT_EQ(Position::BeforeNode(br), it.GetPositionBefore());
  EXPECT_EQ(Position::AfterNode(br), it.GetPositionAfter());
  EXPECT_EQ(Position(body, 1), it.StartPosition());
  EXPECT_EQ(Position(body, 2), it.EndPosition());

  ASSERT_FALSE(it.AtEnd());
  it.Advance(1);
  EXPECT_EQ(Position(text_b, 0), it.GetPositionBefore());
  EXPECT_EQ(Position(text_b, 1), it.GetPositionAfter());
  EXPECT_EQ(Position(text_b, 0), it.StartPosition());
  EXPECT_EQ(Position(text_b, 1), it.EndPosition());

  ASSERT_FALSE(it.AtEnd());
  it.Advance(1);
  EXPECT_EQ(Position(body, 3), it.GetPositionBefore());
  EXPECT_EQ(Position(body, 3), it.GetPositionAfter());
  EXPECT_EQ(Position(body, 3), it.StartPosition());
  EXPECT_EQ(Position(body, 3), it.EndPosition());

  EXPECT_TRUE(it.AtEnd());
}

TEST_F(CharacterIteratorTest, GetPositionWithCollapsedWhitespaces) {
  SetBodyContent("a <div> b </div> c");

  const Element& body = *GetDocument().body();
  CharacterIterator it(EphemeralRange::RangeOfContents(body));

  const Node& text_a = *body.firstChild();
  const Node& div = *text_a.nextSibling();
  const Node& text_b = *div.firstChild();
  const Node& text_c = *body.lastChild();

  EXPECT_EQ(Position(text_a, 0), it.GetPositionBefore());
  EXPECT_EQ(Position(text_a, 1), it.GetPositionAfter());
  EXPECT_EQ(Position(text_a, 0), it.StartPosition());
  EXPECT_EQ(Position(text_a, 1), it.EndPosition());

  ASSERT_FALSE(it.AtEnd());
  it.Advance(1);
  EXPECT_EQ(Position::BeforeNode(div), it.GetPositionBefore());
  EXPECT_EQ(Position::BeforeNode(div), it.GetPositionAfter());
  EXPECT_EQ(Position(body, 1), it.StartPosition());
  EXPECT_EQ(Position(body, 1), it.EndPosition());

  ASSERT_FALSE(it.AtEnd());
  it.Advance(1);
  EXPECT_EQ(Position(text_b, 1), it.GetPositionBefore());
  EXPECT_EQ(Position(text_b, 2), it.GetPositionAfter());
  EXPECT_EQ(Position(text_b, 1), it.StartPosition());
  EXPECT_EQ(Position(text_b, 2), it.EndPosition());

  ASSERT_FALSE(it.AtEnd());
  it.Advance(1);
  EXPECT_EQ(Position(text_b, 3), it.GetPositionBefore());
  EXPECT_EQ(Position(text_b, 3), it.GetPositionAfter());
  EXPECT_EQ(Position(div, 1), it.StartPosition());
  EXPECT_EQ(Position(div, 1), it.EndPosition());

  ASSERT_FALSE(it.AtEnd());
  it.Advance(1);
  EXPECT_EQ(Position(text_c, 1), it.GetPositionBefore());
  EXPECT_EQ(Position(text_c, 2), it.GetPositionAfter());
  EXPECT_EQ(Position(text_c, 1), it.StartPosition());
  EXPECT_EQ(Position(text_c, 2), it.EndPosition());

  ASSERT_FALSE(it.AtEnd());
  it.Advance(1);
  EXPECT_EQ(Position(body, 3), it.GetPositionBefore());
  EXPECT_EQ(Position(body, 3), it.GetPositionAfter());
  EXPECT_EQ(Position(body, 3), it.StartPosition());
  EXPECT_EQ(Position(body, 3), it.EndPosition());

  EXPECT_TRUE(it.AtEnd());
}

TEST_F(CharacterIteratorTest, GetPositionWithEmitChar16Before) {
  InsertStyleElement("b { white-space: pre; }");
  SetBodyContent("a   <b> c</b>");

  const Element& body = *GetDocument().body();
  CharacterIterator it(EphemeralRange::RangeOfContents(body));

  const Node& text_a = *body.firstChild();
  const Node& element_b = *text_a.nextSibling();
  const Node& text_c = *element_b.firstChild();

  EXPECT_EQ(Position(text_a, 0), it.GetPositionBefore());
  EXPECT_EQ(Position(text_a, 1), it.GetPositionAfter());
  EXPECT_EQ(Position(text_a, 0), it.StartPosition());
  EXPECT_EQ(Position(text_a, 1), it.EndPosition());

  ASSERT_FALSE(it.AtEnd());
  it.Advance(1);
  EXPECT_EQ(Position(text_a, 1), it.GetPositionBefore());
  EXPECT_EQ(Position(text_a, 2), it.GetPositionAfter());
  EXPECT_EQ(Position(text_a, 1), it.StartPosition());
  EXPECT_EQ(Position(text_a, 2), it.EndPosition());

  ASSERT_FALSE(it.AtEnd());
  it.Advance(1);
  EXPECT_EQ(Position(text_c, 0), it.GetPositionBefore());
  EXPECT_EQ(Position(text_c, 1), it.GetPositionAfter());
  EXPECT_EQ(Position(text_c, 0), it.StartPosition());
  EXPECT_EQ(Position(text_c, 1), it.EndPosition());

  ASSERT_FALSE(it.AtEnd());
  it.Advance(1);
  EXPECT_EQ(Position(text_c, 1), it.GetPositionBefore());
  EXPECT_EQ(Position(text_c, 2), it.GetPositionAfter());
  EXPECT_EQ(Position(text_c, 1), it.StartPosition());
  EXPECT_EQ(Position(text_c, 2), it.EndPosition());

  ASSERT_FALSE(it.AtEnd());
  it.Advance(1);
  EXPECT_EQ(Position(body, 2), it.GetPositionBefore());
  EXPECT_EQ(Position(body, 2), it.GetPositionAfter());
  EXPECT_EQ(Position(body, 2), it.StartPosition());
  EXPECT_EQ(Position(body, 2), it.EndPosition());

  EXPECT_TRUE(it.AtEnd());
}

}  // namespace blink

"""

```