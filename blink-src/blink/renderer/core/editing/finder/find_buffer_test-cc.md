Response:
The user wants a summary of the functionality of the `find_buffer_test.cc` file in the Chromium Blink engine. I need to analyze the code to understand its purpose, identify any relationships to web technologies like JavaScript, HTML, and CSS, and provide examples of its usage and potential errors.

**Plan:**

1. **Identify the core purpose:** The file name suggests it's testing the `FindBuffer` class.
2. **Analyze the test cases:**  Go through each `TEST_P` and `TEST_F` to understand what aspects of `FindBuffer` are being tested.
3. **Relate to web technologies:** Determine if the tests involve HTML structure, CSS styling, or interactions that might be triggered by JavaScript.
4. **Provide examples:** For each functionality, create hypothetical inputs and expected outputs.
5. **Identify potential errors:** Think about common mistakes developers or users might make related to finding text on a web page.
6. **Describe user actions:**  Outline how a user might interact with a web page to trigger the underlying find functionality.
7. **Summarize the functionality:**  Provide a high-level overview of the file's purpose.```
这是目录为blink/renderer/core/editing/finder/find_buffer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

**`blink/renderer/core/editing/finder/find_buffer_test.cc` 的功能 (第 1 部分):**

这个 C++ 文件是 Chromium Blink 引擎的一部分，专门用于测试 `FindBuffer` 类的功能。 `FindBuffer` 类很可能负责在网页文档的特定范围内缓存和搜索文本内容，以支持浏览器的查找（通常是 Ctrl+F 或 Cmd+F）功能。

以下是代码中测试的主要功能点：

1. **基本的文本查找:**
    *   测试在内联元素中查找文本，确保可以跨越不同的内联标签找到匹配项。
    *   测试 `RangeFromBufferIndex` 函数，该函数可以将 `FindBuffer` 内部的索引范围转换回文档中的 `EphemeralRangeInFlatTree` (表示文档中的一个选区)。这对于高亮显示找到的文本非常重要。
    *   测试在同一节点或不同节点内的特定文本范围内查找匹配项。
    *   测试查找时如何跳过不可见的节点 (例如，`display: none` 的元素)。
    *   测试 `FindMatchInRange` 函数，该函数在给定的范围内查找第一个匹配项，可以向前或向后查找。
    *   测试忽略 `inert` 属性和 `display: none` 样式的元素中的文本。

2. **处理块级元素:**
    *   测试当查找范围包含块级元素时，如何隔离块级元素前后的文本，以便进行独立的查找。这有助于避免跨越块级元素边界的错误匹配。

3. **处理分隔元素:**
    *   测试像 `<br>`, `<hr>` 等分隔元素的处理，通常这些元素会打断连续的文本流。

4. **处理空白符折叠:**
    *   测试不同 `white-space` CSS 属性值 (例如 `pre-wrap`, `pre`, `pre-line`) 对查找结果的影响，验证是否正确模拟了浏览器对空白符的处理方式。

5. **处理双向文本 (Bidi):**
    *   测试在包含从右到左文本的元素中查找文本的功能。

6. **处理日文假名:**
    *   测试查找功能是否能正确处理不同大小写、浊音、半角/全角等各种日文假名字符。

7. **处理整词匹配:**
    *   测试只匹配整个单词的功能。

8. **处理组合字符:**
    *   测试查找功能是否能正确处理由多个 Unicode 字符组成的字符 (例如，带附加符号的字符)。

9. **处理无效的 Unicode 字符:**
    *   测试查找功能是否能正确处理和忽略无效的 Unicode 字符序列。

10. **处理 `display: inline` 和 `display: contents`:**
    *   测试在 `display: inline` 和 `display: contents` 元素中可以跨元素查找到文本。

11. **处理 `<wbr>` (Word Break Opportunity):**
    *   测试 `<wbr>` 标签是否允许跨越该标签查找到文本。

12. **处理表单元素:**
    *   测试查找功能是否会跳过 `<input>` 元素的内容。
    *   测试在 `<select>` 元素中查找文本的行为，根据平台 (Android/iOS vs. 其他) 可能有不同的表现。

13. **处理空范围:**
    *   测试在空文档或特定情况下创建的空查找范围内查找文本的行为。

14. **处理对象替换字符:**
    *   初步提及了对对象替换字符的测试（代码被截断）。

**与 JavaScript, HTML, CSS 的关系举例说明:**

*   **HTML:** 大量的测试用例通过 `SetBodyContent` 或 `SetBodyInnerHTML` 方法设置 HTML 结构，用于模拟不同的网页布局和文本内容。 例如，测试内联元素查找时，会创建包含 `<span>` 和 `<b>` 标签的 HTML 片段。
    ```c++
    SetBodyContent(
        "<div id='container'>a<span id='span'>b</span><b id='b'>c</b></div>");
    ```
*   **CSS:**  测试用例会设置元素的 CSS 样式来验证查找功能对不同样式的影响。 例如，测试块级元素时，会设置 `display: block`，测试不可见元素时会设置 `display: none`，测试空白符处理时会设置 `white-space` 属性。
    ```c++
    SetBodyContent("<div id='block' style='display: block;'>block</div>");
    SetBodyContent("<div id='none' style='display:none'>d</div>");
    SetBodyContent("<span style='white-space: pre-wrap'> e  </span>");
    ```
*   **JavaScript:** 虽然这个测试文件本身是 C++ 代码，但它测试的 `FindBuffer` 功能是浏览器查找功能的核心，该功能可以通过 JavaScript 的 `window.find()` 方法触发。 用户在网页上按下 Ctrl+F 或 Cmd+F 后，浏览器内部的逻辑最终会使用到类似 `FindBuffer` 的机制来执行查找。

**逻辑推理的假设输入与输出:**

假设测试用例 `TEST_P(FindBufferParamTest, FindInline)`:

*   **假设输入 (HTML):**
    ```html
    <div id='container'>a<span id='span'>b</span><b id='b'>c</b><div
    id='none' style='display:none'>d</div><div id='inline-div'
    style='display: inline;'>e</div></div>
    ```
*   **假设输入 (查找字符串):** "abce"
*   **假设输入 (查找选项):**  `kCaseInsensitive` (不区分大小写)
*   **逻辑推理:** `FindBuffer` 会遍历文档，跳过 `display: none` 的元素，并将内联元素的文本连接起来进行查找。
*   **预期输出 (匹配数量):** 1
*   **预期输出 (匹配范围):**  从 "a" 的开始位置到 "e" 的结束位置，对应于 `EphemeralRangeInFlatTree(PositionFromParentId("container", 0), PositionFromParentId("inline-div", 1))`。

**用户或编程常见的使用错误举例说明:**

*   **用户错误:** 用户在查找时可能没有意识到某些内容由于 CSS 样式 (如 `display: none`) 而不可见，导致找不到期望的内容。
*   **编程错误 (在 Blink 引擎开发中):**  `FindBuffer` 的实现可能错误地跨越了块级元素的边界进行匹配，导致了不准确的查找结果。 例如，如果一个 `<div>` 包含 "foo"，另一个 `<div>` 包含 "bar"，错误的实现可能会将它们匹配成 "foobar"。 这个测试文件中的 `FindBlock` 测试用例就是为了防止这种错误。
*   **编程错误 (在 Blink 引擎开发中):**  没有正确处理不同 `white-space` 属性导致的空白符折叠，可能导致查找结果不符合预期。 例如，在 `white-space: pre` 的元素中，连续的空格和换行符不会被折叠，如果 `FindBuffer` 没有正确处理，就可能找不到用户期望的匹配。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户打开一个包含文本的网页。**
2. **用户按下 Ctrl+F (或 Cmd+F) 快捷键，调出浏览器的查找栏。**
3. **用户在查找栏中输入要查找的文本。**
4. **浏览器接收到用户的查找请求。**
5. **浏览器内部的渲染引擎 (Blink) 会创建一个 `FindBuffer` 对象，用于缓存需要搜索的文档内容。** 这个 `FindBuffer` 会根据当前的文档结构和样式，提取出可以用于搜索的文本内容。
6. **Blink 的查找算法 (可能使用了 ICU 库) 会在 `FindBuffer` 中查找用户输入的文本。**
7. **如果找到匹配项，Blink 会高亮显示匹配的文本，并可能将视口滚动到匹配的位置。**

如果在这个过程中出现查找功能异常 (例如，找不到应该找到的文本，或者错误地找到了不应该匹配的文本)，开发者可能会通过调试 Blink 引擎的代码，最终定位到 `FindBuffer` 相关的代码，并使用像 `find_buffer_test.cc` 这样的测试文件来验证修复后的代码是否正确工作。

**归纳一下它的功能 (第 1 部分):**

`find_buffer_test.cc` 的主要功能是全面测试 `FindBuffer` 类的各种文本查找能力，包括基本的文本匹配、处理不同类型的 HTML 元素 (内联、块级、分隔符)、CSS 样式影响 (可见性、空白符处理)、双向文本、特殊字符 (日文假名、组合字符)、整词匹配以及对错误输入的处理。 这些测试确保了 Blink 引擎的查找功能能够准确、可靠地在各种复杂的网页结构和样式下工作，为用户提供一致的查找体验。
```
Prompt: 
```
这是目录为blink/renderer/core/editing/finder/find_buffer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/finder/find_buffer.h"

#include "build/build_config.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/finder/find_results.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"

namespace blink {

class FindBufferTest : public EditingTestBase {
 protected:
  PositionInFlatTree LastPositionInDocument() {
    return GetDocument().documentElement()->lastChild()
               ? PositionInFlatTree::AfterNode(
                     *GetDocument().documentElement()->lastChild())
               : PositionInFlatTree::LastPositionInNode(
                     *GetDocument().documentElement());
  }

  EphemeralRangeInFlatTree WholeDocumentRange() {
    return EphemeralRangeInFlatTree(PositionInFlatTree::FirstPositionInNode(
                                        *GetDocument().documentElement()),
                                    LastPositionInDocument());
  }

  PositionInFlatTree PositionFromParentId(const char* id, unsigned offset) {
    return PositionInFlatTree(GetElementById(id)->firstChild(), offset);
  }

  EphemeralRangeInFlatTree CreateRange(const Node& start_node,
                                       int start_offset,
                                       const Node& end_node,
                                       int end_offset) {
    return EphemeralRangeInFlatTree(
        PositionInFlatTree(start_node, start_offset),
        PositionInFlatTree(end_node, end_offset));
  }

  std::string SerializeRange(const EphemeralRangeInFlatTree& range) {
    return GetSelectionTextInFlatTreeFromBody(
        SelectionInFlatTree::Builder().SetAsForwardSelection(range).Build());
  }

  static unsigned CaseInsensitiveMatchCount(FindBuffer& buffer,
                                            const String& query) {
    return buffer.FindMatches(query, kCaseInsensitive).CountForTesting();
  }

  static constexpr FindOptions kCaseInsensitive =
      FindOptions().SetCaseInsensitive(true);
};

// A test with an HTML data containing no <ruby> should use FindBufferParamTest,
// and should create a FindBuffer with GetParam().
class FindBufferParamTest : public FindBufferTest,
                            public testing::WithParamInterface<RubySupport> {};

INSTANTIATE_TEST_SUITE_P(,
                         FindBufferParamTest,
                         ::testing::Values(RubySupport::kDisabled,
                                           RubySupport::kEnabledForcefully));

TEST_P(FindBufferParamTest, FindInline) {
  SetBodyContent(
      "<div id='container'>a<span id='span'>b</span><b id='b'>c</b><div "
      "id='none' style='display:none'>d</div><div id='inline-div' "
      "style='display: inline;'>e</div></div>");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  EXPECT_TRUE(buffer.PositionAfterBlock().IsNull());
  FindResults results = buffer.FindMatches("abce", kCaseInsensitive);
  EXPECT_EQ(1u, results.CountForTesting());
  MatchResultICU match = *results.begin();
  EXPECT_EQ(0u, match.start);
  EXPECT_EQ(4u, match.length);
  EXPECT_EQ(
      EphemeralRangeInFlatTree(PositionFromParentId("container", 0),
                               PositionFromParentId("inline-div", 1)),
      buffer.RangeFromBufferIndex(match.start, match.start + match.length));
}

TEST_P(FindBufferParamTest, RangeFromBufferIndex) {
  SetBodyContent(
      "<div id='container'>a <span id='span'> b</span><b id='b'>cc</b><div "
      "id='none' style='display:none'>d</div><div id='inline-div' "
      "style='display: inline;'>e</div></div>");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  // Range for "a"
  EXPECT_EQ(EphemeralRangeInFlatTree(PositionFromParentId("container", 0),
                                     PositionFromParentId("container", 1)),
            buffer.RangeFromBufferIndex(0, 1));
  EXPECT_EQ(
      "<div id=\"container\">^a| <span id=\"span\"> b</span><b "
      "id=\"b\">cc</b><div id=\"none\" style=\"display:none\">d</div><div "
      "id=\"inline-div\" style=\"display: inline;\">e</div></div>",
      SerializeRange(buffer.RangeFromBufferIndex(0, 1)));
  // Range for "a "
  EXPECT_EQ(EphemeralRangeInFlatTree(PositionFromParentId("container", 0),
                                     PositionFromParentId("container", 2)),
            buffer.RangeFromBufferIndex(0, 2));
  EXPECT_EQ(
      "<div id=\"container\">^a |<span id=\"span\"> b</span><b "
      "id=\"b\">cc</b><div id=\"none\" style=\"display:none\">d</div><div "
      "id=\"inline-div\" style=\"display: inline;\">e</div></div>",
      SerializeRange(buffer.RangeFromBufferIndex(0, 2)));
  // Range for "a b"
  EXPECT_EQ(EphemeralRangeInFlatTree(PositionFromParentId("container", 0),
                                     PositionFromParentId("span", 2)),
            buffer.RangeFromBufferIndex(0, 3));
  EXPECT_EQ(
      "<div id=\"container\">^a <span id=\"span\"> b|</span><b "
      "id=\"b\">cc</b><div id=\"none\" style=\"display:none\">d</div><div "
      "id=\"inline-div\" style=\"display: inline;\">e</div></div>",
      SerializeRange(buffer.RangeFromBufferIndex(0, 3)));
  // Range for "a bc"
  EXPECT_EQ(EphemeralRangeInFlatTree(PositionFromParentId("container", 0),
                                     PositionFromParentId("b", 1)),
            buffer.RangeFromBufferIndex(0, 4));
  EXPECT_EQ(
      "<div id=\"container\">^a <span id=\"span\"> b</span><b "
      "id=\"b\">c|c</b><div id=\"none\" style=\"display:none\">d</div><div "
      "id=\"inline-div\" style=\"display: inline;\">e</div></div>",
      SerializeRange(buffer.RangeFromBufferIndex(0, 4)));
  // Range for "a bcc"
  EXPECT_EQ(EphemeralRangeInFlatTree(PositionFromParentId("container", 0),
                                     PositionFromParentId("b", 2)),
            buffer.RangeFromBufferIndex(0, 5));
  EXPECT_EQ(
      "<div id=\"container\">^a <span id=\"span\"> b</span><b "
      "id=\"b\">cc|</b><div id=\"none\" style=\"display:none\">d</div><div "
      "id=\"inline-div\" style=\"display: inline;\">e</div></div>",
      SerializeRange(buffer.RangeFromBufferIndex(0, 5)));
  // Range for "a bcce"
  EXPECT_EQ(EphemeralRangeInFlatTree(PositionFromParentId("container", 0),
                                     PositionFromParentId("inline-div", 1)),
            buffer.RangeFromBufferIndex(0, 6));
  EXPECT_EQ(
      "<div id=\"container\">^a <span id=\"span\"> b</span><b "
      "id=\"b\">cc</b><div id=\"none\" style=\"display:none\">d</div><div "
      "id=\"inline-div\" style=\"display: inline;\">e|</div></div>",
      SerializeRange(buffer.RangeFromBufferIndex(0, 6)));
  // Range for " b"
  EXPECT_EQ(EphemeralRangeInFlatTree(PositionFromParentId("container", 1),
                                     PositionFromParentId("span", 2)),
            buffer.RangeFromBufferIndex(1, 3));
  EXPECT_EQ(
      "<div id=\"container\">a^ <span id=\"span\"> b|</span><b "
      "id=\"b\">cc</b><div id=\"none\" style=\"display:none\">d</div><div "
      "id=\"inline-div\" style=\"display: inline;\">e</div></div>",
      SerializeRange(buffer.RangeFromBufferIndex(1, 3)));
  // Range for " bc"
  EXPECT_EQ(EphemeralRangeInFlatTree(PositionFromParentId("container", 1),
                                     PositionFromParentId("b", 1)),
            buffer.RangeFromBufferIndex(1, 4));
  EXPECT_EQ(
      "<div id=\"container\">a^ <span id=\"span\"> b</span><b "
      "id=\"b\">c|c</b><div id=\"none\" style=\"display:none\">d</div><div "
      "id=\"inline-div\" style=\"display: inline;\">e</div></div>",
      SerializeRange(buffer.RangeFromBufferIndex(1, 4)));
}

TEST_P(FindBufferParamTest, FindBetweenPositionsSameNode) {
  PositionInFlatTree start_position =
      ToPositionInFlatTree(SetCaretTextToBody("f|oofoo"));
  Node* node = start_position.ComputeContainerNode();
  // |end_position| = foofoo| (end of text).
  PositionInFlatTree end_position =
      PositionInFlatTree::LastPositionInNode(*node);
  {
    FindBuffer buffer(EphemeralRangeInFlatTree(start_position, end_position),
                      GetParam());
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "foo"));
    EXPECT_EQ(2u, CaseInsensitiveMatchCount(buffer, "oo"));
    EXPECT_EQ(4u, CaseInsensitiveMatchCount(buffer, "o"));
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "f"));
  }
  // |start_position| = fo|ofoo
  // |end_position| = foof|oo
  start_position = PositionInFlatTree(*node, 2u);
  end_position = PositionInFlatTree(*node, 4u);
  {
    FindBuffer buffer(EphemeralRangeInFlatTree(start_position, end_position),
                      GetParam());
    EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "foo"));
    EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "oo"));
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "o"));
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "f"));
  }
}

TEST_P(FindBufferParamTest, FindBetweenPositionsDifferentNodes) {
  SetBodyContent(
      "<div id='div'>foo<span id='span'>foof<b id='b'>oo</b></span></div>");
  Element* div = GetElementById("div");
  Element* span = GetElementById("span");
  Element* b = GetElementById("b");
  // <div>^foo<span>foof|<b>oo</b></span></div>
  // So buffer = "foofoof"
  {
    FindBuffer buffer(
        EphemeralRangeInFlatTree(
            PositionInFlatTree::FirstPositionInNode(*div->firstChild()),
            PositionInFlatTree::LastPositionInNode(*span->firstChild())),
        GetParam());
    EXPECT_EQ(2u, CaseInsensitiveMatchCount(buffer, "foo"));
    EXPECT_EQ(2u, CaseInsensitiveMatchCount(buffer, "fo"));
    EXPECT_EQ(2u, CaseInsensitiveMatchCount(buffer, "oof"));
    EXPECT_EQ(2u, CaseInsensitiveMatchCount(buffer, "oo"));
    EXPECT_EQ(4u, CaseInsensitiveMatchCount(buffer, "o"));
    EXPECT_EQ(3u, CaseInsensitiveMatchCount(buffer, "f"));
  }
  // <div>f^oo<span>foof<b>o|o</b></span></div>
  // So buffer = "oofoofo"
  {
    FindBuffer buffer(CreateRange(*div->firstChild(), 1, *b->firstChild(), 1),
                      GetParam());
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "foo"));
    EXPECT_EQ(2u, CaseInsensitiveMatchCount(buffer, "oof"));
    EXPECT_EQ(2u, CaseInsensitiveMatchCount(buffer, "fo"));
    EXPECT_EQ(2u, CaseInsensitiveMatchCount(buffer, "oo"));
    EXPECT_EQ(5u, CaseInsensitiveMatchCount(buffer, "o"));
    EXPECT_EQ(2u, CaseInsensitiveMatchCount(buffer, "f"));
  }
  // <div>foo<span>f^oof|<b>oo</b></span></div>
  // So buffer = "oof"
  {
    FindBuffer buffer(
        CreateRange(*span->firstChild(), 1, *span->firstChild(), 4),
        GetParam());
    EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "foo"));
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "oof"));
    EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "fo"));
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "oo"));
    EXPECT_EQ(2u, CaseInsensitiveMatchCount(buffer, "o"));
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "f"));
  }
  // <div>foo<span>foof^<b>oo|</b></span></div>
  // So buffer = "oo"
  FindBuffer buffer(CreateRange(*span->firstChild(), 4, *b->firstChild(), 2),
                    GetParam());
  EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "foo"));
  EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "oof"));
  EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "fo"));
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "oo"));
  EXPECT_EQ(2u, CaseInsensitiveMatchCount(buffer, "o"));
  EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "f"));
}

TEST_P(FindBufferParamTest, FindBetweenPositionsSkippedNodes) {
  SetBodyContent(
      "<div id='div'>foo<span id='span' style='display:none'>foof</span><b "
      "id='b'>oo</b><script id='script'>fo</script><a id='a'>o</o></div>");
  Element* div = GetElementById("div");
  Element* span = GetElementById("span");
  Element* b = GetElementById("b");
  Element* script = GetElementById("script");
  Element* a = GetElementById("a");

  // <div>^foo<span style='display:none;'>foo|f</span><b>oo</b>
  // <script>fo</script><a>o</a></div>
  // So buffer = "foo"
  {
    FindBuffer buffer(
        EphemeralRangeInFlatTree(
            PositionInFlatTree::FirstPositionInNode(*div->firstChild()),
            PositionInFlatTree(*span->firstChild(), 3)),
        GetParam());
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "foo"));
    EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "oof"));
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "fo"));
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "oo"));
    EXPECT_EQ(2u, CaseInsensitiveMatchCount(buffer, "o"));
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "f"));
  }
  // <div>foo<span style='display:none;'>f^oof</span><b>oo|</b>
  // <script>fo</script><a>o</a></div>
  // So buffer = "oo"
  {
    FindBuffer buffer(CreateRange(*span->firstChild(), 1, *b->firstChild(), 2),
                      GetParam());
    EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "foo"));
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "oo"));
    EXPECT_EQ(2u, CaseInsensitiveMatchCount(buffer, "o"));
    EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "f"));
  }
  // <div>foo<span style='display:none;'>f^oof</span><b>oo|</b>
  // <script>f|o</script><a>o</a></div>
  // So buffer = "oo"
  {
    FindBuffer buffer(
        CreateRange(*span->firstChild(), 1, *script->firstChild(), 2),
        GetParam());
    EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "foo"));
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "oo"));
    EXPECT_EQ(2u, CaseInsensitiveMatchCount(buffer, "o"));
    EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "f"));
  }
  // <div>foo<span style='display:none;'>foof</span><b>oo|</b>
  // <script>f^o</script><a>o|</a></div>
  // So buffer = "o"
  {
    FindBuffer buffer(
        CreateRange(*script->firstChild(), 1, *a->firstChild(), 1), GetParam());
    EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "foo"));
    EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "oo"));
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "o"));
    EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "f"));
  }
}

TEST_F(FindBufferTest, FindMatchInRange) {
  SetBodyContent("<div id='div'>foo<a id='a'>foof</a><b id='b'>oo</b></div>");
  Element* div = GetElementById("div");
  Element* a = GetElementById("a");
  Element* b = GetElementById("b");
  EphemeralRangeInFlatTree foo1 = EphemeralRangeInFlatTree(
      PositionInFlatTree::FirstPositionInNode(*div->firstChild()),
      PositionInFlatTree::LastPositionInNode(*div->firstChild()));
  EphemeralRangeInFlatTree foo2 = EphemeralRangeInFlatTree(
      PositionInFlatTree::FirstPositionInNode(*a->firstChild()),
      PositionInFlatTree(*a->firstChild(), 3));
  EphemeralRangeInFlatTree foo3 = EphemeralRangeInFlatTree(
      PositionInFlatTree(*a->firstChild(), 3),
      PositionInFlatTree::LastPositionInNode(*b->firstChild()));

  // <div>^foo<a>foof</a><b>oo|</b></div>, forwards
  EphemeralRangeInFlatTree match = FindBuffer::FindMatchInRange(
      WholeDocumentRange(), "foo", kCaseInsensitive);
  EXPECT_EQ(foo1, match);
  // <div>f^oo<a>foof</a><b>oo|</b></div>, forwards
  match = FindBuffer::FindMatchInRange(
      EphemeralRangeInFlatTree(PositionInFlatTree(*div->firstChild(), 1),
                               LastPositionInDocument()),
      "foo", kCaseInsensitive);
  EXPECT_EQ(foo2, match);
  // <div>foo<a>^foo|f</a><b>oo</b></div>, forwards
  match = FindBuffer::FindMatchInRange(foo2, "foo", kCaseInsensitive);
  EXPECT_EQ(foo2, match);
  // <div>foo<a>f^oof|</a><b>oo</b></div>, forwards
  match = FindBuffer::FindMatchInRange(
      EphemeralRangeInFlatTree(
          PositionInFlatTree(*a->firstChild(), 1),
          PositionInFlatTree::LastPositionInNode(*a->firstChild())),
      "foo", kCaseInsensitive);
  EXPECT_TRUE(match.IsNull());
  // <div>foo<a>f^oof</a><b>oo|</b></div>, forwards
  match = FindBuffer::FindMatchInRange(
      EphemeralRangeInFlatTree(PositionInFlatTree(*a->firstChild(), 1),
                               LastPositionInDocument()),
      "foo", kCaseInsensitive);
  EXPECT_EQ(foo3, match);

  constexpr FindOptions kCaseInsensitiveBackwards =
      FindOptions().SetCaseInsensitive(true).SetBackwards(true);

  // <div>^foo<a>foof</a><b>oo|</b></div>, backwards
  match = FindBuffer::FindMatchInRange(WholeDocumentRange(), "foo",
                                       kCaseInsensitiveBackwards);
  EXPECT_EQ(foo3, match);
  // <div>^foo<a>foof</a><b>o|o</b></div>, backwards
  match = FindBuffer::FindMatchInRange(
      EphemeralRangeInFlatTree(
          PositionInFlatTree::FirstPositionInNode(*div->firstChild()),
          PositionInFlatTree(*b->firstChild(), 1)),
      "foo", kCaseInsensitiveBackwards);
  EXPECT_EQ(foo2, match);
  // <div>foo<a>^foof</a><b>o|o</b></div>, backwards
  match = FindBuffer::FindMatchInRange(
      EphemeralRangeInFlatTree(
          PositionInFlatTree::FirstPositionInNode(*a->firstChild()),
          PositionInFlatTree(*b->firstChild(), 1)),
      "foo", kCaseInsensitiveBackwards);
  EXPECT_EQ(foo2, match);
  // <div>foo<a>foo^f</a><b>o|o</b></div>, backwards
  match = FindBuffer::FindMatchInRange(
      EphemeralRangeInFlatTree(PositionInFlatTree(*a->firstChild(), 3),
                               PositionInFlatTree(*b->firstChild(), 1)),
      "foo", kCaseInsensitiveBackwards);
  EXPECT_TRUE(match.IsNull());
  // <div>^foo<a>fo|of</a><b>oo</b></div>, backwards
  match = FindBuffer::FindMatchInRange(
      EphemeralRangeInFlatTree(
          PositionInFlatTree::FirstPositionInNode(*div->firstChild()),
          PositionInFlatTree(*a->firstChild(), 2)),
      "foo", kCaseInsensitiveBackwards);
  EXPECT_EQ(foo1, match);
}

// https://issues.chromium.org/issues/327017912
TEST_F(FindBufferTest, FindMatchInRangeIgnoreNonSearchable) {
  SetBodyContent(R"(
    <div inert>Do not find me!</div>
    <div style="display: none">Do not find me!</div>)");
  EphemeralRangeInFlatTree match = FindBuffer::FindMatchInRange(
      WholeDocumentRange(), "me", kCaseInsensitive);
  EXPECT_TRUE(match.IsNull());
}

class FindBufferBlockTest
    : public FindBufferTest,
      public testing::WithParamInterface<std::tuple<std::string, RubySupport>> {
};

std::string GenerateSuffix(
    const testing::TestParamInfo<FindBufferBlockTest::ParamType>& info) {
  auto [display, ruby_support] = info.param;
  auto it = display.find("-");
  if (it != std::string::npos) {
    display.replace(it, 1, "");
  }
  return display + "_" +
         (ruby_support == RubySupport::kDisabled ? "RubyDisabled"
                                                 : "RubyEnabled");
}

INSTANTIATE_TEST_SUITE_P(
    Blocks,
    FindBufferBlockTest,
    testing::Combine(testing::Values("block",
                                     "table",
                                     "flow-root",
                                     "grid",
                                     "flex",
                                     "list-item"),
                     testing::Values(RubySupport::kDisabled,
                                     RubySupport::kEnabledForcefully)),
    GenerateSuffix);

TEST_P(FindBufferBlockTest, FindBlock) {
  auto [display, ruby_support] = GetParam();
  SetBodyContent("text<div id='block' style='display: " + display +
                 ";'>block</div><span id='span'>span</span>");
  PositionInFlatTree position_after_block;
  {
    FindBuffer text_buffer(WholeDocumentRange(), ruby_support);
    EXPECT_EQ(GetElementById("block"),
              *text_buffer.PositionAfterBlock().ComputeContainerNode());
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(text_buffer, "text"));
    EXPECT_EQ(0u, CaseInsensitiveMatchCount(text_buffer, "textblock"));
    EXPECT_EQ(0u, CaseInsensitiveMatchCount(text_buffer, "text block"));
    position_after_block = text_buffer.PositionAfterBlock();
  }
  {
    FindBuffer block_buffer(EphemeralRangeInFlatTree(position_after_block,
                                                     LastPositionInDocument()),
                            ruby_support);
    EXPECT_EQ(GetElementById("span"),
              *block_buffer.PositionAfterBlock().ComputeContainerNode());
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(block_buffer, "block"));
    EXPECT_EQ(0u, CaseInsensitiveMatchCount(block_buffer, "textblock"));
    EXPECT_EQ(0u, CaseInsensitiveMatchCount(block_buffer, "text block"));
    EXPECT_EQ(0u, CaseInsensitiveMatchCount(block_buffer, "blockspan"));
    EXPECT_EQ(0u, CaseInsensitiveMatchCount(block_buffer, "block span"));
    position_after_block = block_buffer.PositionAfterBlock();
  }
  {
    FindBuffer span_buffer(EphemeralRangeInFlatTree(position_after_block,
                                                    LastPositionInDocument()),
                           ruby_support);
    EXPECT_TRUE(span_buffer.PositionAfterBlock().IsNull());
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(span_buffer, "span"));
    EXPECT_EQ(0u, CaseInsensitiveMatchCount(span_buffer, "blockspan"));
    EXPECT_EQ(0u, CaseInsensitiveMatchCount(span_buffer, "block span"));
  }
}

class FindBufferSeparatorTest
    : public FindBufferTest,
      public testing::WithParamInterface<std::string> {};

INSTANTIATE_TEST_SUITE_P(Separators,
                         FindBufferSeparatorTest,
                         testing::Values("br",
                                         "hr",
                                         "meter",
                                         "object",
                                         "progress",
                                         "select",
                                         "video"));

TEST_P(FindBufferSeparatorTest, FindSeparatedElements) {
  SetBodyContent("a<" + GetParam() + ">a</" + GetParam() + ">a");
  {
    FindBuffer buffer(WholeDocumentRange());
    EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "aa"));
  }

  {
    FindBuffer buffer(WholeDocumentRange(), RubySupport::kEnabledForcefully);
    EXPECT_EQ(0u, buffer.FindMatches("aa", kCaseInsensitive).CountForTesting());
  }
}

TEST_P(FindBufferSeparatorTest, FindBRSeparatedElements) {
  SetBodyContent("a<br>a");
  {
    FindBuffer buffer(WholeDocumentRange());
    EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "a\na"));
  }

  {
    FindBuffer buffer(WholeDocumentRange(), RubySupport::kEnabledForcefully);
    EXPECT_EQ(1u,
              buffer.FindMatches("a\na", kCaseInsensitive).CountForTesting());
  }
}

TEST_P(FindBufferParamTest, WhiteSpaceCollapsingPreWrap) {
  SetBodyContent(
      " a  \n   b  <b> c </b> d  <span style='white-space: pre-wrap'> e  "
      "</span>");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "a b c d  e  "));
}

TEST_P(FindBufferParamTest, WhiteSpaceCollapsingPre) {
  SetBodyContent("<div style='white-space: pre;'>a \n b</div>");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "a"));
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "b"));
  EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "ab"));
  EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "a b"));
  EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "a  b"));
  EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "a   b"));
  EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "a\n b"));
  EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "a \nb"));
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "a \n b"));
}

TEST_P(FindBufferParamTest, WhiteSpaceCollapsingPreLine) {
  SetBodyContent("<div style='white-space: pre-line;'>a \n b</div>");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "a"));
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "b"));
  EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "ab"));
  EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "a b"));
  EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "a  b"));
  EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "a   b"));
  EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "a \n b"));
  EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "a\n b"));
  EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, "a \nb"));
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "a\nb"));
}

TEST_P(FindBufferParamTest, BidiTest) {
  SetBodyContent("<bdo dir=rtl id=bdo>foo<span>bar</span></bdo>");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, "foobar"));
}

TEST_P(FindBufferParamTest, KanaSmallVsNormal) {
  SetBodyContent("や");  // Normal-sized や
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  // Should find normal-sized や
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"や"));
  // Should not find smalll-sized ゃ
  EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, u"ゃ"));
}

TEST_P(FindBufferParamTest, KanaDakuten) {
  SetBodyContent("びゃ");  // Hiragana bya
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  // Should find bi
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"び"));
  // Should find smalll-sized ゃ
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"ゃ"));
  // Should find bya
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"びゃ"));
  // Should not find hi
  EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, u"ひ"));
  // Should not find pi
  EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, u"ぴ"));
}

TEST_P(FindBufferParamTest, KanaHalfFull) {
  // Should treat hiragana, katakana, half width katakana as the same.
  // hiragana ra, half width katakana ki, full width katakana na
  SetBodyContent("らｷナ");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  // Should find katakana ra
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"ラ"));
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"ﾗ"));
  // Should find hiragana & katakana ki
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"き"));
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"キ"));
  // Should find hiragana & katakana na
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"な"));
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"ﾅ"));
  // Should find whole word
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"らきな"));
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"ﾗｷﾅ"));
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"ラキナ"));
}

TEST_P(FindBufferParamTest, WholeWordTest) {
  SetBodyContent("foo bar foobar 六本木");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  EXPECT_EQ(2u, CaseInsensitiveMatchCount(buffer, "foo"));
  constexpr FindOptions kCaseInsensitiveWholeWord =
      FindOptions().SetCaseInsensitive(true).SetWholeWord(true);
  EXPECT_EQ(
      1u,
      buffer.FindMatches("foo", kCaseInsensitiveWholeWord).CountForTesting());
  EXPECT_EQ(2u, CaseInsensitiveMatchCount(buffer, "bar"));
  EXPECT_EQ(
      1u,
      buffer.FindMatches("bar", kCaseInsensitiveWholeWord).CountForTesting());
  EXPECT_EQ(
      1u,
      buffer.FindMatches(u"六", kCaseInsensitiveWholeWord).CountForTesting());
  EXPECT_EQ(
      1u,
      buffer.FindMatches(u"本木", kCaseInsensitiveWholeWord).CountForTesting());
}

TEST_P(FindBufferParamTest, KanaDecomposed) {
  SetBodyContent("は　゛");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, u"ば"));
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"は　゛"));
  EXPECT_EQ(0u, CaseInsensitiveMatchCount(buffer, u"バ "));
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"ハ ゛"));
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"ﾊ ﾞ"));
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, u"ﾊ ゛"));
}

TEST_P(FindBufferParamTest, FindDecomposedKanaInComposed) {
  // Hiragana Ba, composed
  SetBodyInnerHTML(u"\u3070");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  // Hiragana Ba, decomposed
  EXPECT_EQ(1u, CaseInsensitiveMatchCount(buffer, String(u"\u306F\u3099")));
}

TEST_P(FindBufferParamTest, FindPlainTextInvalidTarget1) {
  static const char* body_content = "<div>foo bar test</div>";
  SetBodyContent(body_content);

  // A lone lead surrogate (0xDA0A) example taken from fuzz-58.
  static const UChar kInvalid1[] = {0x1461u, 0x2130u, 0x129bu, 0xd711u, 0xd6feu,
                                    0xccadu, 0x7064u, 0xd6a0u, 0x4e3bu, 0x03abu,
                                    0x17dcu, 0xb8b7u, 0xbf55u, 0xfca0u, 0x07fau,
                                    0x0427u, 0xda0au, 0};

  FindBuffer buffer(WholeDocumentRange(), GetParam());
  const auto results = buffer.FindMatches(String(kInvalid1), FindOptions());
  EXPECT_TRUE(results.IsEmpty());
}

TEST_P(FindBufferParamTest, FindPlainTextInvalidTarget2) {
  static const char* body_content = "<div>foo bar test</div>";
  SetBodyContent(body_content);

  // A lone trailing surrogate (U+DC01).
  static const UChar kInvalid2[] = {0x1461u, 0x2130u, 0x129bu, 0xdc01u,
                                    0xd6feu, 0xccadu, 0};

  FindBuffer buffer(WholeDocumentRange(), GetParam());
  const auto results = buffer.FindMatches(String(kInvalid2), FindOptions());
  EXPECT_TRUE(results.IsEmpty());
}

TEST_P(FindBufferParamTest, FindPlainTextInvalidTarget3) {
  static const char* body_content = "<div>foo bar test</div>";
  SetBodyContent(body_content);

  // A trailing surrogate followed by a lead surrogate (U+DC03 U+D901).
  static const UChar kInvalid3[] = {0xd800u, 0xdc00u, 0x0061u, 0xdc03u,
                                    0xd901u, 0xccadu, 0};
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  const auto results = buffer.FindMatches(String(kInvalid3), FindOptions());
  EXPECT_TRUE(results.IsEmpty());
}

TEST_P(FindBufferParamTest, DisplayInline) {
  SetBodyContent("<span>fi</span>nd");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  const auto results = buffer.FindMatches("find", FindOptions());
  ASSERT_EQ(1u, results.CountForTesting());
  EXPECT_EQ(MatchResultICU({0, 4}), results.front());
}

TEST_P(FindBufferParamTest, DisplayBlock) {
  SetBodyContent("<div>fi</div>nd");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  const auto results = buffer.FindMatches("find", FindOptions());
  ASSERT_EQ(0u, results.CountForTesting())
      << "We should not match across block.";
}

TEST_P(FindBufferParamTest, DisplayContents) {
  SetBodyContent("<div style='display: contents'>fi</div>nd");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  const auto results = buffer.FindMatches("find", FindOptions());
  ASSERT_EQ(1u, results.CountForTesting());
  EXPECT_EQ(MatchResultICU({0, 4}), results.front());
}

TEST_P(FindBufferParamTest, WBRTest) {
  SetBodyContent("fi<wbr>nd and fin<wbr>d");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  const auto results = buffer.FindMatches("find", FindOptions());
  ASSERT_EQ(2u, results.CountForTesting());
}

TEST_P(FindBufferParamTest, InputTest) {
  SetBodyContent("fi<input type='text' id=i1>nd and fin<input type='text'>d");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  const auto results = buffer.FindMatches("find", FindOptions());
  ASSERT_EQ(0u, results.CountForTesting());
  EXPECT_EQ(buffer.PositionAfterBlock(),
            PositionInFlatTree::FirstPositionInNode(*GetElementById("i1")));
}

TEST_P(FindBufferParamTest, SelectMultipleTest) {
  SetBodyContent("<select multiple><option>find me</option></select>");
  {
    FindBuffer buffer(WholeDocumentRange(), GetParam());
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
    EXPECT_EQ(0u, buffer.FindMatches("find", FindOptions()).CountForTesting());
#else
    EXPECT_EQ(1u, buffer.FindMatches("find", FindOptions()).CountForTesting());
#endif  // BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
  }
  SetBodyContent("<select size=2><option>find me</option></select>");
  {
    FindBuffer buffer(WholeDocumentRange(), GetParam());
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
    EXPECT_EQ(0u, buffer.FindMatches("find", FindOptions()).CountForTesting());
#else
    EXPECT_EQ(1u, buffer.FindMatches("find", FindOptions()).CountForTesting());
#endif  // BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
  }
  SetBodyContent("<select size=1><option>find me</option></select>");
  {
    FindBuffer buffer(WholeDocumentRange(), GetParam());
    EXPECT_EQ(0u, buffer.FindMatches("find", FindOptions()).CountForTesting());
  }
}

TEST_P(FindBufferParamTest, NullRange) {
  SetBodyContent("x<div></div>");
  FindBuffer buffer(WholeDocumentRange(), GetParam());
  EXPECT_EQ(0u, buffer.FindMatches("find", FindOptions()).CountForTesting());
}

TEST_P(FindBufferParamTest, FindObjectReplacementCharacter) {
  SetBodyContent(
      "some tex
"""


```