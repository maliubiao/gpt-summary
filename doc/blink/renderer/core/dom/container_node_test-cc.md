Response:
My thinking process to analyze the `container_node_test.cc` file goes through these stages:

1. **Understand the Purpose of a Test File:**  The filename `container_node_test.cc` immediately signals this is a unit test file. It's designed to verify the behavior of the `ContainerNode` class in Blink's rendering engine.

2. **Identify the Target Class:** The inclusion of `"third_party/blink/renderer/core/dom/container_node.h"` confirms that the tests are specifically for the `ContainerNode` class.

3. **Examine the Test Structure:**  The file uses the `TEST_F` macro, indicating it's using Google Test and inherits from `EditingTestBase`. This tells me that it's part of a larger testing framework within Blink and has access to utility functions for setting up DOM structures.

4. **Analyze Individual Tests:** I then go through each `TEST_F` function, focusing on:
    * **Test Name:** The name provides a clear indication of what aspect of `ContainerNode`'s functionality is being tested (e.g., `HasOnlyTextReturnsFalseForEmptySpan`).
    * **Setup (if any):**  The `SetBodyContent` function sets up the initial HTML structure for the test. This is crucial for understanding the input to the function being tested.
    * **Action:**  The core of the test involves calling a method of a `ContainerNode` object (usually obtained via `GetDocument().getElementById()`).
    * **Assertion:** `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, and `ASSERT_EQ` are used to verify the expected outcome of the action.

5. **Categorize Functionality Being Tested:** As I analyze the tests, I start grouping them by the functionality they are testing. I see tests for:
    * `HasOnlyText()`: Checking if a node contains only text (ignoring comments).
    * `FindTextInElementWith()`: Searching for text content within an element, potentially with a validation function.
    * `FindAllTextNodesMatchingRegex()`: Finding all text nodes within a document that match a given regular expression.

6. **Relate to Web Technologies (JavaScript, HTML, CSS):**  I consider how these `ContainerNode` functionalities relate to the web:
    * **HTML:** The `SetBodyContent` function directly deals with creating HTML structures. The tests operate on elements and their children, which are fundamental to HTML.
    * **JavaScript:**  JavaScript interacts heavily with the DOM (Document Object Model). The functionalities tested here (checking node content, finding text) are common operations performed by JavaScript when manipulating web pages. I look for patterns like getting elements by ID, which is a standard JavaScript DOM operation.
    * **CSS:** While this specific test file doesn't directly manipulate CSS, the underlying `ContainerNode` and its children (like `Text` nodes) are affected by CSS styling. I note this connection.

7. **Identify Potential User/Programming Errors:** I think about how developers might misuse or misunderstand the functionalities being tested. For example:
    * Expecting `HasOnlyText()` to return true when there are other elements or whitespace.
    * Using incorrect regular expressions with `FindAllTextNodesMatchingRegex()`.
    * Misunderstanding how `FindTextInElementWith()` behaves with nested elements or comments.

8. **Construct Logical Inferences/Examples:**  Based on the test cases, I can infer the behavior of the tested functions in different scenarios. I create hypothetical inputs and their expected outputs to illustrate these inferences.

9. **Trace User Operations for Debugging:** I consider how a user's actions on a web page might lead to the execution of the code being tested. This involves thinking about:
    * Page load and initial rendering (which builds the DOM).
    * User interactions that modify the DOM (e.g., typing in a text field, clicking buttons, dynamic updates via JavaScript).
    * Browser features like "find in page" which likely utilize similar text searching mechanisms.

10. **Refine and Organize:** Finally, I organize my findings into a clear and structured explanation, addressing all the points requested in the original prompt. I use clear headings and bullet points to make the information easy to understand. I also make sure to explicitly link the tests back to the specific functionalities of `ContainerNode`.

Essentially, I approach the analysis like reverse-engineering the code's behavior through its tests. The tests act as specifications and examples of how the `ContainerNode` class is intended to work.

这个文件 `container_node_test.cc` 是 Chromium Blink 引擎中用于测试 `ContainerNode` 类的单元测试文件。`ContainerNode` 是 DOM (Document Object Model) 中一个重要的基类，它代表了可以包含其他节点的节点，例如 `Element` 和 `Document`。

**功能列举:**

这个测试文件的主要功能是验证 `ContainerNode` 类及其相关方法的正确性。具体来说，它测试了以下几个方面：

1. **`HasOnlyText()` 方法:**
   - 检查一个容器节点是否只包含文本节点（并且忽略注释节点）。

2. **`FindTextInElementWith()` 方法:**
   - 在一个容器节点及其后代中查找特定的文本内容。
   - 允许提供一个验证函数，对找到的潜在文本进行额外的判断。
   - 能够处理只读的 `<input type="text">` 元素和 `<textarea>` 元素的值。
   - 能够区分大小写 (虽然这个测试文件中明确测试了忽略 ASCII 大小写的情况)。

3. **`FindAllTextNodesMatchingRegex()` 方法:**
   - 查找容器节点及其后代中所有匹配给定正则表达式的文本节点。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`ContainerNode` 是浏览器渲染引擎中处理 HTML 结构的核心部分，并且与 JavaScript 的 DOM 操作密切相关。虽然这个测试文件本身不直接涉及 CSS，但 `ContainerNode` 及其包含的元素会受到 CSS 样式的影响。

* **HTML:**
    - 测试用例通过 `SetBodyContent` 方法设置 HTML 内容，模拟真实的 HTML 结构。例如：
        ```html
        <body><span id="id"></span></body>
        ```
        这个 HTML 片段创建了一个 `<span>` 元素，测试用例会获取这个元素并进行相关测试。
    - 测试用例验证了 `ContainerNode` 如何处理不同类型的子节点，例如文本节点、元素节点和注释节点。

* **JavaScript:**
    - JavaScript 代码可以使用 DOM API 来获取和操作 `ContainerNode` 及其子节点。例如，`document.getElementById("id")` 在 JavaScript 中会返回一个 `Element` 对象，它继承自 `ContainerNode`。
    - 测试用例中模拟了 JavaScript 中常见的操作，例如查找包含特定文本的元素或查找所有匹配特定模式的文本节点。
    - **举例:** 如果 JavaScript 代码需要判断一个 `div` 元素是否只包含文本内容，它可能会间接地依赖于 `ContainerNode::HasOnlyText()` 这样的底层实现。

* **CSS:**
    - 虽然测试文件没有直接测试 CSS，但是 `ContainerNode` 所代表的元素会被 CSS 样式化。例如，一个 `<div>` 元素可能包含文本，而 CSS 可以改变文本的颜色、字体等。
    - **举例:**  如果一个 `<div>` 元素通过 CSS 设置了 `display: none;`，那么使用 JavaScript 查找该元素内的文本可能会受到影响（取决于具体的查找方式，但 `FindTextInElementWith` 似乎会找到）。

**逻辑推理、假设输入与输出:**

* **`HasOnlyText()`:**
    * **假设输入:**  一个 `<div>` 元素，其 HTML 结构为 `<div>Hello</div>`。
    * **预期输出:** `HasOnlyText()` 返回 `true`。
    * **假设输入:**  一个 `<span>` 元素，其 HTML 结构为 `<span>Hello<span>World</span></span>`。
    * **预期输出:** `HasOnlyText()` 返回 `false`，因为它包含了一个子元素 `<span>`。
    * **假设输入:**  一个 `<p>` 元素，其 HTML 结构为 `<p> Text <!-- comment --> </p>`。
    * **预期输出:** `HasOnlyText()` 返回 `true`，因为它只包含文本节点，注释节点被忽略。

* **`FindTextInElementWith()`:**
    * **假设输入:** 一个 `<div>` 元素，其 HTML 结构为 `<div id="target">Find me</div>`，并且调用 `FindTextInElementWith(AtomicString("me"), ...)`。
    * **预期输出:** 返回字符串 `"Find me"`。
    * **假设输入:** 一个 `<div>` 元素，其 HTML 结构为 `<div id="target">No match</div>`，并且调用 `FindTextInElementWith(AtomicString("found"), ...)`。
    * **预期输出:** 返回空字符串 `""`。
    * **假设输入:** 一个 `<input type="text" readonly value="Input text">` 元素，并且调用 `GetDocument().FindTextInElementWith(AtomicString("text"), ...)`。
    * **预期输出:** 返回字符串 `"Input text"`。

* **`FindAllTextNodesMatchingRegex()`:**
    * **假设输入:** 一个 `<div>` 元素，其 HTML 结构为 `<div>Text1<div>Text2</div></div>`，并且调用 `FindAllTextNodesMatchingRegex("Text\\d")`。
    * **预期输出:** 返回一个包含两个 `Text` 节点的 `StaticNodeList`，分别对应 "Text1" 和 "Text2"。
    * **假设输入:** 一个 `<span>` 元素，其 HTML 结构为 `<span></span>`，并且调用 `FindAllTextNodesMatchingRegex("(.)*")`。
    * **预期输出:** 返回一个空的 `StaticNodeList`，因为没有文本节点。

**用户或编程常见的使用错误举例:**

1. **错误地认为 `HasOnlyText()` 会考虑空格或换行符。**
   - **例子:** 用户创建一个 `<div>` 元素，内容为 `<div> Hello </div>` (包含空格)。虽然看起来像是只有文本，但实际的 DOM 结构可能包含多个文本节点（包括空格节点）。`HasOnlyText()` 可能会返回 `false`，如果空格被表示为独立的文本节点。

2. **在使用 `FindTextInElementWith()` 时，没有考虑到子元素的存在。**
   - **例子:** 用户期望在一个 `<div>` 中找到特定的文本，但是该文本实际上被包含在一个子元素中，例如 `<div><span>Target text</span></div>`。如果直接在 `<div>` 上查找 "Target text"，可能会失败，除非实现会递归搜索子节点。这个测试文件表明 `FindTextInElementWith` 确实会搜索后代节点。

3. **在使用 `FindAllTextNodesMatchingRegex()` 时，正则表达式写得不正确。**
   - **例子:** 用户想要找到所有包含数字的文本节点，但使用了错误的正则表达式，例如 `"\\d"` 而不是 `"\\d+"` (至少一个数字)。

4. **误解 `FindTextInElementWith()` 对只读输入框的处理。**
   - **例子:** 程序员可能忘记 `FindTextInElementWith()` 可以从只读的 `<input type="text">` 和 `<textarea>` 的 `value` 属性中查找文本，导致使用其他方法来获取输入框的值。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中加载一个包含复杂 DOM 结构的网页。**
2. **网页上的 JavaScript 代码需要查找或操作特定的文本内容。** 例如：
   - 用户在搜索框中输入关键词，JavaScript 使用 DOM API 来高亮显示匹配的文本。
   - 网页上的脚本需要提取某个 `div` 元素中的纯文本内容。
   - 自动化测试脚本需要验证页面上是否存在特定的文本。
3. **JavaScript 代码调用 DOM API，例如 `element.textContent` 或遍历子节点来查找文本。**
4. **Blink 引擎在处理这些 JavaScript 调用时，会调用底层的 C++ 代码，包括 `ContainerNode` 类及其方法。**
5. **如果程序存在 Bug，可能与 `ContainerNode` 的实现有关。** 例如，`HasOnlyText()` 返回了错误的结果，或者 `FindTextInElementWith()` 无法找到预期的文本。
6. **开发者在调试时，可能会需要查看 `container_node_test.cc` 中的测试用例，以理解 `ContainerNode` 的预期行为，并找到潜在的 Bug 所在。** 测试用例可以帮助开发者重现 Bug，并验证修复方案的正确性。
7. **开发者可以使用断点调试等工具，逐步跟踪代码执行流程，从 JavaScript 调用进入 Blink 引擎的 C++ 代码，最终定位到 `ContainerNode` 的相关方法。**

总而言之，`container_node_test.cc` 是确保 Blink 引擎中 `ContainerNode` 类功能正确性的关键组成部分，它直接关系到浏览器如何理解和操作 HTML 结构以及如何响应 JavaScript 的 DOM 操作。理解这些测试用例有助于开发者理解 Blink 引擎的内部工作原理，并排查与 DOM 操作相关的 Bug。

Prompt: 
```
这是目录为blink/renderer/core/dom/container_node_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/dom/container_node.h"

#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/platform/bindings/script_regexp.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

using ContainerNodeTest = EditingTestBase;

TEST_F(ContainerNodeTest, HasOnlyTextReturnsFalseForEmptySpan) {
  SetBodyContent(R"HTML(<body><span id="id"></span></body>)HTML");

  EXPECT_FALSE(GetDocument().getElementById(AtomicString("id"))->HasOnlyText());
}

TEST_F(ContainerNodeTest, HasOnlyTextReturnsFalseForNonTextChild) {
  SetBodyContent(R"HTML(
    <body><div id="id"><div>Nested</div></div></body>
  )HTML");

  EXPECT_FALSE(GetDocument().getElementById(AtomicString("id"))->HasOnlyText());
}

TEST_F(ContainerNodeTest, HasOnlyTextReturnsTrueForSomeText) {
  SetBodyContent(R"HTML(<body><p id="id"> Here is some text </p></body>)HTML");

  EXPECT_TRUE(GetDocument().getElementById(AtomicString("id"))->HasOnlyText());
}

TEST_F(ContainerNodeTest, HasOnlyTextIgnoresComments) {
  SetBodyContent(R"HTML(
    <body>
      <p id="id"> Here is some text
        <!-- This is a comment that should be ignored. -->
      </p>
    </body>
  )HTML");

  EXPECT_TRUE(GetDocument().getElementById(AtomicString("id"))->HasOnlyText());
}

TEST_F(ContainerNodeTest, CannotFindTextInElementWithoutDescendants) {
  SetBodyContent(R"HTML(<body><span id="id"></span></body>)HTML");

  String text = GetDocument().FindTextInElementWith(
      AtomicString("anything"), [](const String&) { return true; });

  EXPECT_TRUE(text.empty());
}

TEST_F(ContainerNodeTest, CannotFindTextNodesWithoutText) {
  SetBodyContent(R"HTML(<body><span id="id"></span></body>)HTML");

  StaticNodeList* nodes = GetDocument().FindAllTextNodesMatchingRegex("(.)*");

  EXPECT_EQ(nodes->length(), 0U);
}

TEST_F(ContainerNodeTest, CannotFindTextInElementWithNonTextDescendants) {
  SetBodyContent(R"HTML(<body><span id="id"> Hello
      <span></span> world! </span></body>)HTML");

  String text = GetDocument().FindTextInElementWith(
      AtomicString("Hello"), [](const String&) { return true; });

  EXPECT_TRUE(text.empty());
}

TEST_F(ContainerNodeTest, CanFindTextNodesWithBreakInBetween) {
  SetBodyContent(R"HTML(<body><span id="id"> Hello
      <span></span> world! </span></body>)HTML");

  StaticNodeList* nodes =
      GetDocument().FindAllTextNodesMatchingRegex("(.|\n)*");

  EXPECT_EQ(nodes->length(), 2U);
  EXPECT_EQ(nodes->item(0),
            GetDocument().getElementById(AtomicString("id"))->firstChild());
  EXPECT_EQ(nodes->item(1),
            GetDocument().getElementById(AtomicString("id"))->lastChild());
}

TEST_F(ContainerNodeTest, CanFindTextNodesWithCommentInBetween) {
  SetBodyContent(R"HTML(<body><span id="id"> Hello
      <!-- comment --> world! </span></body>)HTML");

  StaticNodeList* nodes =
      GetDocument().FindAllTextNodesMatchingRegex("(.|\n)*");

  EXPECT_EQ(nodes->length(), 2U);
  EXPECT_EQ(nodes->item(0),
            GetDocument().getElementById(AtomicString("id"))->firstChild());
  EXPECT_EQ(nodes->item(1),
            GetDocument().getElementById(AtomicString("id"))->lastChild());
}

TEST_F(ContainerNodeTest, CannotFindTextInElementWithoutMatchingSubtring) {
  SetBodyContent(R"HTML(<body><span id="id"> Hello </span></body>)HTML");

  String text = GetDocument().FindTextInElementWith(
      AtomicString("Goodbye"), [](const String&) { return true; });

  EXPECT_TRUE(text.empty());
}

TEST_F(ContainerNodeTest, CanFindTextInElementWithOnlyTextDescendants) {
  SetBodyContent(
      R"HTML(<body><span id="id"> Find me please </span></body>)HTML");

  String text = GetDocument().FindTextInElementWith(
      AtomicString("me"), [](const String&) { return true; });

  EXPECT_EQ(String(" Find me please "), text);
}

TEST_F(ContainerNodeTest, CanFindTextNodeWithOnlyText) {
  SetBodyContent(
      R"HTML(<body><span id="id"> Find me please </span></body>)HTML");

  StaticNodeList* nodes = GetDocument().FindAllTextNodesMatchingRegex("(.)*");

  ASSERT_EQ(nodes->length(), 1U);
  EXPECT_EQ(nodes->item(0),
            GetDocument().getElementById(AtomicString("id"))->firstChild());
}

TEST_F(ContainerNodeTest, CannotFindTextIfTheValidatorRejectsIt) {
  SetBodyContent(
      R"HTML(<body><span id="id"> Find me please </span></body>)HTML");

  String text = GetDocument().FindTextInElementWith(
      AtomicString("me"), [](const String&) { return false; });

  EXPECT_TRUE(text.empty());
}

TEST_F(ContainerNodeTest, CannotFindTextNodesIfTheMatcherRejectsIt) {
  SetBodyContent(
      R"HTML(<body><span id="id"> Don't find me please </span></body>)HTML");

  StaticNodeList* nodes =
      GetDocument().FindAllTextNodesMatchingRegex("not present");

  EXPECT_EQ(nodes->length(), 0U);
}

TEST_F(ContainerNodeTest, CanFindTextInElementWithManyDescendants) {
  SetBodyContent(R"HTML(
      <body>
        <div id="id">
          <div>
            No need to find this
          </div>
          <div>
            Something something here
            <div> Find me please </div>
            also over here
          </div>
          <div>
            And more information here
          </div>
        </div>
        <div>
          Hi
        </div>
      </body>
    )HTML");

  String text = GetDocument().FindTextInElementWith(
      AtomicString(" me "), [](const String&) { return true; });

  EXPECT_EQ(String(" Find me please "), text);
}

TEST_F(ContainerNodeTest, CanFindAllTextNodes) {
  SetBodyContent(R"HTML(
      <body>
        <div id="id">
          <div>
            Text number 1
          </div>
          <div>
            Text number 2
            <div> Text number 3</div>
            Text number 4
          </div>
          <div>
            Text number 5
          </div>
        </div>
        <div>
          Text number 6
        </div>
      </body>
    )HTML");

  StaticNodeList* nodes = GetDocument().FindAllTextNodesMatchingRegex(
      "(.|\n)*(Text number)(.|\n)*");

  ASSERT_EQ(nodes->length(), 6U);
  EXPECT_EQ(To<Text>(nodes->item(0))->data(),
            String("\n            Text number 1\n          "));
  EXPECT_EQ(To<Text>(nodes->item(1))->data(),
            String("\n            Text number 2\n            "));
  EXPECT_EQ(To<Text>(nodes->item(2))->data(), String(" Text number 3"));
  EXPECT_EQ(To<Text>(nodes->item(3))->data(),
            String("\n            Text number 4\n          "));
  EXPECT_EQ(To<Text>(nodes->item(4))->data(),
            String("\n            Text number 5\n          "));
  EXPECT_EQ(To<Text>(nodes->item(5))->data(),
            String("\n          Text number 6\n        "));
}

TEST_F(ContainerNodeTest, CanFindOnlyTextNodesThatMatch) {
  SetBodyContent(R"HTML(
      <body>
        <div id="id">
          <div>
            Text number 1
          </div>
          <div>
            Text number 2
            <div id="id_1"> Text number 3 </div>
            <div id="id_2"> Text number 4 </div>
            Text number 5
          </div>
          <div>
            Text number 6
          </div>
        </div>
        <div>
          Text number
        </div>
      </body>
    )HTML");

  StaticNodeList* nodes = GetDocument().FindAllTextNodesMatchingRegex(
      "(\\s|\n)*(Text number 3|Text number 4)(\\s|\n)*");
  ASSERT_EQ(nodes->length(), 2U);
  EXPECT_EQ(nodes->item(0),
            GetDocument().getElementById(AtomicString("id_1"))->firstChild());
  EXPECT_EQ(nodes->item(1),
            GetDocument().getElementById(AtomicString("id_2"))->firstChild());
}

TEST_F(ContainerNodeTest, FindTextInElementWithFirstMatch) {
  SetBodyContent(R"HTML(
      <body><div id="id">
        <div> Text match #1 </div>
        <div> Text match #2 </div>
      </div></body>
    )HTML");

  String text = GetDocument().FindTextInElementWith(
      AtomicString(" match "), [](const String&) { return true; });

  EXPECT_EQ(String(" Text match #1 "), text);
}

TEST_F(ContainerNodeTest, FindTextInElementWithValidatorApprovingTheSecond) {
  SetBodyContent(R"HTML(
      <body><div id="id">
        <div> Text match #1 </div>
        <div> Text match #2 </div>
      </div></body>
    )HTML");

  String text = GetDocument().FindTextInElementWith(
      AtomicString(" match "), [](const String& potential_match) {
        return potential_match == " Text match #2 ";
      });

  EXPECT_EQ(String(" Text match #2 "), text);
}

TEST_F(ContainerNodeTest, FindTextInElementWithSubstringIgnoresComments) {
  SetBodyContent(R"HTML(
    <body>
      <p id="id"> Before comment, <!-- The comment. --> after comment. </p>
    </body>
  )HTML");

  String text = GetDocument().FindTextInElementWith(
      AtomicString("comment"), [](const String&) { return true; });

  EXPECT_EQ(String(" Before comment,  after comment. "), text);
}

TEST_F(ContainerNodeTest, FindTextInElementWithSubstringIgnoresAsciiCase) {
  SetBodyContent(R"HTML(
    <body>
      <p id="id"> MaGiC RaInBoW. </p>
    </body>
  )HTML");

  String text = GetDocument().FindTextInElementWith(
      AtomicString("magic"), [](const String&) { return true; });

  EXPECT_EQ(String(" MaGiC RaInBoW. "), text);
}

TEST_F(ContainerNodeTest, CanFindTextInReadonlyTextInputElement) {
  SetBodyContent(R"HTML(
    <body>
      <p><input id="id" type="text" readonly="" value=" MaGiC RaInBoW. "></p>
    </body>
  )HTML");

  String text = GetDocument().FindTextInElementWith(
      AtomicString("magic"), [](const String&) { return true; });

  EXPECT_EQ(String(" MaGiC RaInBoW. "), text);
}

TEST_F(ContainerNodeTest, CannotFindTextInNonReadonlyTextInputElement) {
  SetBodyContent(R"HTML(
    <body>
      <p><input id="id" type="text" value=" MaGiC RaInBoW. "></p>
    </body>
  )HTML");

  String text = GetDocument().FindTextInElementWith(
      AtomicString("magic"), [](const String&) { return true; });

  EXPECT_TRUE(text.empty());
}

TEST_F(ContainerNodeTest, CannotFindTextInNonTextInputElement) {
  SetBodyContent(R"HTML(
    <body>
      <p><input id="id" type="url" readonly="" value=" MaGiC RaInBoW. "></p>
    </body>
  )HTML");

  String text = GetDocument().FindTextInElementWith(
      AtomicString("magic"), [](const String&) { return true; });

  EXPECT_TRUE(text.empty());
}

TEST_F(ContainerNodeTest, FindTextInTheValueOfTheReadonlyInputFirst) {
  SetBodyContent(R"HTML(
    <body>
      <p><input id="id" type="text" readonly="" value="lookup value">lookup
        text children</input></p>
    </body>
  )HTML");

  String text = GetDocument().FindTextInElementWith(
      AtomicString("lookup"), [](const String&) { return true; });

  EXPECT_EQ(String("lookup value"), text);
}

TEST_F(ContainerNodeTest, FindTextInTheValueOfTheReadonlyInputWithTypeTEXT) {
  SetBodyContent(R"HTML(
    <body>
      <p><input id="id" type="TEXT" readonly="" value="lookup value"></p>
    </body>
  )HTML");

  String text = GetDocument().FindTextInElementWith(
      AtomicString("lookup"), [](const String&) { return true; });

  EXPECT_EQ(String("lookup value"), text);
}

TEST_F(ContainerNodeTest, CanFindTextInTextarea) {
  SetBodyContent(R"HTML(
    <body>
      <p><textarea id="id">lookup text children</textarea></p>
    </body>
  )HTML");

  String text = GetDocument().FindTextInElementWith(
      AtomicString("lookup"), [](const String&) { return true; });

  EXPECT_EQ(String("lookup text children"), text);
}

}  // namespace blink

"""

```