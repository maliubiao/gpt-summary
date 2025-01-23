Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The file name `selection_sample_test.cc` immediately suggests that it's a test file related to `SelectionSample`. Looking at the includes, we see `selection_sample.h` and `editing_test_base.h`. This confirms that it's testing the functionality of `SelectionSample` within an editing context in the Blink rendering engine.

2. **Understand the Test Structure:** The code uses the `TEST_F` macro, which is part of the Google Test framework. This tells us it's a set of individual test cases grouped under a test fixture class `SelectionSampleTest`, which inherits from `EditingTestBase`. `EditingTestBase` likely provides helper functions for setting up and interacting with the DOM for testing.

3. **Analyze Individual Test Cases (Iterative):** Go through each `TEST_F` individually and try to understand its purpose:

    * **`GetSelectionTextFlatTree`:**  The name and the presence of `GetSelectionTextInFlatTree` strongly suggest this test verifies how selection text is retrieved in the "flat tree" (which is relevant for Shadow DOM). The input string contains `<template>` and `<slot>` elements, confirming the Shadow DOM aspect. The `EXPECT_EQ` compares the expected output of `GetSelectionTextInFlatTree` with a hardcoded string.

    * **`SetCommentInBody` and `SetCommentInElement`:** These tests clearly focus on how `SelectionSample::SetSelectionText` handles HTML comments within the body and within other elements. They check both the resulting HTML structure (`EXPECT_EQ(..., GetDocument().body()->innerHTML())`) and the resulting DOM selection (`EXPECT_EQ(..., selection)`).

    * **`SetEmpty1` and `SetEmpty2`:**  These are simple tests for handling empty selection markers (`|` and `^|`). They verify the resulting empty HTML and the selection at the beginning of the body.

    * **`SetElement`:** This checks setting a selection across HTML elements (`<a>` and `<b>`). It asserts that the text nodes representing the selection markers are removed and the selection spans the elements.

    * **`SetText`:** This tests setting selections within a text node, covering cases where the start and end markers (`^` and `|`) are at different positions within the text.

    * **`SerializeAttribute`:** This test explores how HTML attributes are serialized when getting the selection text. It checks for alphabetical ordering, handling of special characters, and namespace prefixes.

    * **`SerializeComment`:**  A straightforward test to ensure comments are serialized correctly.

    * **`SerializeElement`:**  Checks serialization of simple HTML elements.

    * **`SerializeEmpty`:** Verifies serialization of an empty selection.

    * **`SerializeNamespace`:** This test shows that `GetSelectionText` doesn't automatically include namespace declarations.

    * **`SerializeProcessingInstruction` and `SerializeProcessingInstruction2`:** These highlight how processing instructions are handled (often converted to comments by the HTML parser) and how they are serialized.

    * **`SerializeTable`:** This test focuses on the specific behavior of the HTML parser with `<table>` elements, including implicit `<tbody>` creation and how text nodes and comments are moved.

    * **`SerializeText`:** Basic test for serializing text with a selection.

    * **`SerializeVoidElement`:**  Tests how void elements (like `<br>` and `<img>`) are serialized, noting that they don't require closing tags.

    * **`SerializeVoidElementBR`:** This edge case demonstrates that if a `<br>` element has child nodes (which is invalid HTML), it's treated as a regular element during serialization.

    * **`ConvertTemplatesToShadowRoots` (and the variations):** These tests are about a specific function (`ConvertTemplatesToShadowRootsForTesring`) used for testing. They verify that `<template>` elements with `data-mode='open'` are correctly converted into Shadow DOM shadow roots.

    * **`TraverseShadowContent` and related tests:** These tests verify that the selection mechanism correctly handles selections that span across shadow DOM boundaries, including cases with slots.

4. **Identify Relationships to Web Technologies:**  As the tests involve manipulating HTML structures and selections, the connection to HTML is obvious. The tests involving `<template>` and `<slot>` directly relate to Shadow DOM, a key web component technology. While CSS isn't directly manipulated in *this* test file, the *effects* of selection might trigger CSS updates (e.g., `:focus`, `::selection` pseudo-elements). JavaScript is implicitly involved because the Blink engine, which these tests are part of, is the core of the rendering engine that executes JavaScript and interprets HTML and CSS. These tests ensure the underlying selection mechanisms that JavaScript APIs like `window.getSelection()` and methods on `Selection` objects rely on are working correctly.

5. **Infer Assumptions and Logic:**  The tests make assumptions about how the HTML parser and serializer work within Blink. For example, the `SerializeTable` test assumes the parser will move text nodes outside the table element to before it. The `SerializeAttribute` test assumes attributes will be alphabetized. These assumptions are based on the actual implementation of Blink's HTML parsing logic.

6. **Consider User/Programming Errors:**  The tests indirectly help prevent user errors. If the selection logic were flawed, users might experience incorrect text selection behavior on web pages. From a programming perspective, a common error might be incorrectly calculating the start and end positions of a selection, especially when dealing with complex DOM structures or Shadow DOM. The tests with comments also hint at potential issues with how developers might try to manipulate the DOM using comments as markers, which these tests demonstrate the system handles.

7. **Trace User Actions (Debugging Clues):**  To reach this code during debugging, a developer would likely be investigating issues related to:

    * **Text selection:**  Bugs where users can't select text correctly or the selection range is wrong.
    * **Copy/paste:**  Problems where the copied content doesn't match the visual selection.
    * **ContentEditable:**  Issues within editable regions where selection behavior is unexpected.
    * **Shadow DOM:**  Bugs related to selection across shadow boundaries or within slotted content.

    The developer might set breakpoints in `SelectionSample::SetSelectionText` or `SelectionSample::GetSelectionText` to trace how the selection is being set and retrieved. They might also examine the internal representation of the `SelectionInDOMTree` object. Understanding how the test cases construct these selections is crucial for replicating and debugging real-world scenarios.

8. **Refine and Organize:**  Finally, organize the information gathered into a clear and structured answer, covering each aspect of the prompt. Use examples to illustrate the relationships with web technologies and user errors.

This detailed thought process allows for a comprehensive understanding of the test file's purpose and its role in the broader context of the Blink rendering engine.
这个文件 `selection_sample_test.cc` 是 Chromium Blink 引擎中用于测试 `SelectionSample` 类的功能。 `SelectionSample` 类本身是一个测试辅助工具，用于在测试环境中方便地创建和获取 DOM 树中的文本内容和选择状态。

**功能列表:**

1. **设置和获取带有选择的文本:** 该文件中的测试用例主要验证了 `SelectionSample` 类的 `SetSelectionText` 和 `GetSelectionText` 方法。这些方法允许在一段文本中嵌入特殊的标记 (例如 `^` 和 `|`) 来表示选区的起始和结束位置，并根据这些标记在 DOM 树中创建相应的结构和选区。
2. **处理不同的 DOM 结构:** 测试用例覆盖了各种 DOM 结构，包括包含普通文本、HTML 元素、注释、Processing Instruction、以及包含 Shadow DOM 的场景。
3. **验证选择的正确性:** 每个测试用例都会设置一个带有选择标记的文本，然后断言生成的 DOM 结构和选择状态是否与预期一致。这包括选区的起始和结束位置、以及选区覆盖的节点和偏移量。
4. **测试 HTML 解析和序列化行为:** 一些测试用例，如 `SerializeAttribute`, `SerializeComment`, `SerializeElement` 等，间接地测试了 Blink 引擎的 HTML 解析器和序列化器的行为。通过设置带有特定 HTML 结构的文本并获取其序列化后的结果，可以验证解析器和序列化器是否按照预期工作，例如属性的顺序、特殊字符的处理等。
5. **测试 Shadow DOM 的处理:**  测试用例 `GetSelectionTextFlatTree`, `TraverseShadowContent`, `TraverseShadowContentWithSlot`, `TraverseMultipleShadowContents` 专门测试了在包含 Shadow DOM 的场景下，`SelectionSample` 如何正确地设置和获取选区，以及如何遍历 Shadow DOM 的内容。
6. **提供测试辅助功能:** `ConvertTemplatesToShadowRootsForTesring` 函数提供了一种在测试中将 `<template>` 元素转换为 Shadow Root 的机制，这使得测试与 Shadow DOM 相关的逻辑更加方便。

**与 JavaScript, HTML, CSS 的关系:**

虽然 `selection_sample_test.cc` 是 C++ 代码，但它直接测试了与 Web 前端技术密切相关的功能：

* **HTML:**  该文件大量使用了 HTML 结构来创建测试场景。例如，测试用例会设置包含 `<div>`, `<span>`, `<p>`, `<a>`, `<b>`, `<table>`, `<template>`, `<slot>` 等元素的文本，并验证 `SelectionSample` 能否正确处理这些元素及其属性。
    * **举例:**  `SetSelectionText(GetDocument().body(), "<p>^<a>0</a>|<b>1</b></p>");`  这行代码模拟了在包含 `<a>` 和 `<b>` 标签的 `<p>` 元素中设置选区。
* **JavaScript:**  Blink 引擎是 JavaScript 运行时的核心。`SelectionSample` 测试的功能最终会影响到 JavaScript 中与选区相关的 API，例如 `window.getSelection()` 和 `document.getSelection()`。这些 JavaScript API 依赖于底层 C++ 代码提供的选区管理功能。
    * **举例:**  当 JavaScript 代码调用 `window.getSelection()` 获取用户在页面上选中的文本时，Blink 引擎会使用类似于 `SelectionSample::GetSelectionText` 的机制来获取选区的文本内容和 DOM 位置信息。
* **CSS:** 虽然该文件没有直接操作 CSS，但选区的创建和修改会影响到浏览器的渲染，并可能触发 CSS 相关的行为，例如 `:focus` 伪类的应用或者 `::selection` 伪元素样式的显示。
    * **举例:**  用户在页面上选中一段文本后，浏览器可能会应用 `::selection` 伪元素定义的样式来高亮显示选中的文本。`SelectionSample` 测试确保了底层选区信息的正确性，这是实现 `::selection` 功能的基础。

**逻辑推理 (假设输入与输出):**

假设 `SelectionSample::SetSelectionText` 的输入是一个包含选择标记的字符串，例如 `"abc^def|ghi"`，并且该字符串被应用于一个空的 `<body>` 元素。

* **假设输入:** `"abc^def|ghi"`
* **隐含输入:** 一个空的 `<body>` 元素
* **逻辑:** `SetSelectionText` 会解析该字符串，创建一个包含文本节点 "abcdefghi" 的 DOM 树，并在该文本节点的偏移量 3 和 6 之间设置一个选区。
* **预期输出 (DOM 结构):** `<body>abcdefghi</body>`
* **预期输出 (选区):**  选区的起始位置是 `<body>` 元素的第一个子节点（文本节点 "abcdefghi"）的偏移量 3 (指向 'd' 字符之前)，选区的结束位置是该文本节点的偏移量 6 (指向 'g' 字符之前)。

**用户或编程常见的使用错误:**

* **错误地假设注释会被渲染:** 用户可能会尝试在注释中放置内容，期望它会被显示出来。`SetCommentInBody` 和 `SetCommentInElement` 测试用例展示了 `SelectionSample` 如何处理注释，以及最终渲染的 HTML 中注释会被移除。这是一个用户容易混淆的点。
* **在 `<table>` 元素中直接放置文本节点:**  用户可能直接在 `<table>` 标签内部放置文本内容，而没有放在 `<tr>` 或 `<td>` 等表格元素中。`SerializeTable` 测试用例展示了 HTML 解析器会将这些文本节点移动到 `<table>` 标签之前。这与用户直观的理解可能不符。
* **误解 void 元素的行为:** 用户可能尝试为 void 元素（如 `<br>` 或 `<img>`）添加子节点或闭合标签。`SerializeVoidElement` 和 `SerializeVoidElementBR` 测试用例展示了 Blink 如何处理这些情况，例如移除 void 元素的闭合标签或者当 void 元素有子节点时将其视为普通元素。
* **在 Shadow DOM 中操作选择时，没有考虑到 Shadow Root 的边界:** 开发者在操作包含 Shadow DOM 的页面上的选区时，需要理解选区的起始和结束位置可能位于不同的 Shadow Root 中。 `TraverseShadowContent` 等测试用例验证了 `SelectionSample` 正确处理了跨越 Shadow DOM 边界的选区。

**用户操作是如何一步步到达这里，作为调试线索:**

假设用户在 Chrome 浏览器中编辑一个富文本编辑器，并遇到了一个与文本选择相关的 bug，例如：

1. **用户操作:** 用户在编辑器中选中了一段包含 Shadow DOM 内容的文本。
2. **浏览器行为:** 浏览器尝试获取用户选中的文本范围，以便进行复制、粘贴或其他编辑操作。
3. **Blink 引擎内部:**  当浏览器需要获取选区信息时，会调用 Blink 引擎中与选区管理相关的 C++ 代码，其中可能涉及到类似于 `SelectionSample::GetSelectionTextInFlatTree` 的函数，尤其是在处理 Shadow DOM 的情况下。
4. **调试线索:**  如果开发者在调试这个 bug，他们可能会：
    * **设置断点:** 在 `selection_sample_test.cc` 文件中，特别是 `GetSelectionTextFlatTree` 和相关的 Shadow DOM 测试用例中设置断点，以便理解 Blink 引擎是如何处理包含 Shadow DOM 的选区的。
    * **查看测试用例:**  研究这些测试用例的输入和预期输出，了解在类似场景下 `SelectionSample` 应该如何工作。
    * **比对实际行为与预期:**  比较浏览器实际的行为（例如，通过 `window.getSelection()` 获取到的选区信息）与测试用例中定义的预期行为，从而找到 bug 的根源。

总而言之，`selection_sample_test.cc` 是一个重要的测试文件，它确保了 Blink 引擎中负责管理文本选择的核心功能能够正确处理各种复杂的 DOM 结构和用户操作，特别是涉及到 Shadow DOM 的情况。它为开发者提供了调试和理解选区行为的重要线索。

### 提示词
```
这是目录为blink/renderer/core/editing/testing/selection_sample_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/testing/selection_sample.h"

#include "third_party/blink/renderer/core/dom/processing_instruction.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"

namespace blink {

class SelectionSampleTest : public EditingTestBase {
 protected:
  std::string SetAndGetSelectionText(const std::string& sample_text) {
    return SelectionSample::GetSelectionText(
        *GetDocument().body(),
        SelectionSample::SetSelectionText(GetDocument().body(), sample_text));
  }
};

TEST_F(SelectionSampleTest, GetSelectionTextFlatTree) {
  const SelectionInDOMTree selection = SelectionSample::SetSelectionText(
      GetDocument().body(),
      "<p>"
      "  <template data-mode=open>"
      "    ze^ro <slot name=one></slot> <slot name=two></slot> three"
      "  </template>"
      "  <b slot=two>tw|o</b><b slot=one>one</b>"
      "</p>");
  EXPECT_EQ(
      "<p>"
      "    ze^ro <slot name=\"one\"><b slot=\"one\">one</b></slot> <slot "
      "name=\"two\"><b slot=\"two\">tw|o</b></slot> three  "
      "</p>",
      SelectionSample::GetSelectionTextInFlatTree(
          *GetDocument().body(), ConvertToSelectionInFlatTree(selection)));
}

TEST_F(SelectionSampleTest, SetCommentInBody) {
  const SelectionInDOMTree& selection = SelectionSample::SetSelectionText(
      GetDocument().body(), "<!--^-->foo<!--|-->");
  EXPECT_EQ("foo", GetDocument().body()->innerHTML());
  EXPECT_EQ(SelectionInDOMTree::Builder()
                .Collapse(Position(GetDocument().body(), 0))
                .Extend(Position(GetDocument().body(), 1))
                .Build(),
            selection);
}

TEST_F(SelectionSampleTest, SetCommentInElement) {
  const SelectionInDOMTree& selection = SelectionSample::SetSelectionText(
      GetDocument().body(), "<span id=sample><!--^-->foo<!--|--></span>");
  const Element* const sample =
      GetDocument().body()->getElementById(AtomicString("sample"));
  EXPECT_EQ("<span id=\"sample\">foo</span>",
            GetDocument().body()->innerHTML());
  EXPECT_EQ(SelectionInDOMTree::Builder()
                .Collapse(Position(sample, 0))
                .Extend(Position(sample, 1))
                .Build(),
            selection);
}

TEST_F(SelectionSampleTest, SetEmpty1) {
  const SelectionInDOMTree& selection =
      SelectionSample::SetSelectionText(GetDocument().body(), "|");
  EXPECT_EQ("", GetDocument().body()->innerHTML());
  EXPECT_EQ(0u, GetDocument().body()->CountChildren());
  EXPECT_EQ(SelectionInDOMTree::Builder()
                .Collapse(Position(GetDocument().body(), 0))
                .Build(),
            selection);
}

TEST_F(SelectionSampleTest, SetEmpty2) {
  const SelectionInDOMTree& selection =
      SelectionSample::SetSelectionText(GetDocument().body(), "^|");
  EXPECT_EQ("", GetDocument().body()->innerHTML());
  EXPECT_EQ(0u, GetDocument().body()->CountChildren());
  EXPECT_EQ(SelectionInDOMTree::Builder()
                .Collapse(Position(GetDocument().body(), 0))
                .Build(),
            selection);
}

TEST_F(SelectionSampleTest, SetElement) {
  const SelectionInDOMTree& selection = SelectionSample::SetSelectionText(
      GetDocument().body(), "<p>^<a>0</a>|<b>1</b></p>");
  const Element* const sample = GetDocument().QuerySelector(AtomicString("p"));
  EXPECT_EQ(2u, sample->CountChildren())
      << "We should remove Text node for '^' and '|'.";
  EXPECT_EQ(SelectionInDOMTree::Builder()
                .Collapse(Position(sample, 0))
                .Extend(Position(sample, 1))
                .Build(),
            selection);
}

TEST_F(SelectionSampleTest, SetText) {
  {
    const auto& selection =
        SelectionSample::SetSelectionText(GetDocument().body(), "^ab|c");
    EXPECT_EQ("abc", GetDocument().body()->innerHTML());
    EXPECT_EQ(SelectionInDOMTree::Builder()
                  .Collapse(Position(GetDocument().body()->firstChild(), 0))
                  .Extend(Position(GetDocument().body()->firstChild(), 2))
                  .Build(),
              selection);
  }
  {
    const auto& selection =
        SelectionSample::SetSelectionText(GetDocument().body(), "a^b|c");
    EXPECT_EQ("abc", GetDocument().body()->innerHTML());
    EXPECT_EQ(SelectionInDOMTree::Builder()
                  .Collapse(Position(GetDocument().body()->firstChild(), 1))
                  .Extend(Position(GetDocument().body()->firstChild(), 2))
                  .Build(),
              selection);
  }
  {
    const auto& selection =
        SelectionSample::SetSelectionText(GetDocument().body(), "ab^|c");
    EXPECT_EQ("abc", GetDocument().body()->innerHTML());
    EXPECT_EQ(SelectionInDOMTree::Builder()
                  .Collapse(Position(GetDocument().body()->firstChild(), 2))
                  .Build(),
              selection);
  }
  {
    const auto& selection =
        SelectionSample::SetSelectionText(GetDocument().body(), "ab|c^");
    EXPECT_EQ("abc", GetDocument().body()->innerHTML());
    EXPECT_EQ(SelectionInDOMTree::Builder()
                  .Collapse(Position(GetDocument().body()->firstChild(), 3))
                  .Extend(Position(GetDocument().body()->firstChild(), 2))
                  .Build(),
              selection);
  }
}

// Demonstrates attribute handling in HTML parser and serializer.
TEST_F(SelectionSampleTest, SerializeAttribute) {
  EXPECT_EQ("<a x=\"1\" y=\"2\" z=\"3\">b|ar</a>",
            SetAndGetSelectionText("<a z='3' x='1' y='2'>b|ar</a>"))
      << "Attributes are alphabetically ordered.";
  EXPECT_EQ("<a x=\"'\" y=\"&quot;\" z=\"&amp;\">f|o^o</a>",
            SetAndGetSelectionText("<a x=\"'\" y='\"' z=&>f|o^o</a>"))
      << "Attributes with character entity.";
  EXPECT_EQ(
      "<foo:a foo:x=\"1\" xmlns:foo=\"http://foo\">x|y</foo:a>",
      SetAndGetSelectionText("<foo:a foo:x=1 xmlns:foo=http://foo>x|y</foo:a>"))
      << "namespace prefix should be supported";
  EXPECT_EQ(
      "<foo:a foo:x=\"1\" xmlns:foo=\"http://foo\">x|y</foo:a>",
      SetAndGetSelectionText("<foo:a foo:x=1 xmlns:Foo=http://foo>x|y</foo:a>"))
      << "namespace prefix is converted to lowercase by HTML parrser";
  EXPECT_EQ("<foo:a foo:x=\"1\" x=\"2\" xmlns:foo=\"http://foo\">xy|z</foo:a>",
            SetAndGetSelectionText(
                "<Foo:a x=2 Foo:x=1 xmlns:foo='http://foo'>xy|z</a>"))
      << "namespace prefix affects attribute ordering";
}

TEST_F(SelectionSampleTest, SerializeComment) {
  EXPECT_EQ("<!-- f|oo -->", SetAndGetSelectionText("<!-- f|oo -->"));
}

TEST_F(SelectionSampleTest, SerializeElement) {
  EXPECT_EQ("<a>|</a>", SetAndGetSelectionText("<a>|</a>"));
  EXPECT_EQ("<a>^</a>|", SetAndGetSelectionText("<a>^</a>|"));
  EXPECT_EQ("<a>^foo</a><b>bar</b>|",
            SetAndGetSelectionText("<a>^foo</a><b>bar</b>|"));
}

TEST_F(SelectionSampleTest, SerializeEmpty) {
  EXPECT_EQ("|", SetAndGetSelectionText("|"));
  EXPECT_EQ("|", SetAndGetSelectionText("^|"));
  EXPECT_EQ("|", SetAndGetSelectionText("|^"));
}

TEST_F(SelectionSampleTest, SerializeNamespace) {
  SetBodyContent("<div xmlns:foo='http://xyz'><foo:bar></foo:bar>");
  auto& sample = *To<ContainerNode>(GetDocument().body()->firstChild());
  EXPECT_EQ("<foo:bar></foo:bar>",
            SelectionSample::GetSelectionText(sample, SelectionInDOMTree()))
      << "GetSelectionText() does not insert namespace declaration.";
}

TEST_F(SelectionSampleTest, SerializeProcessingInstruction) {
  EXPECT_EQ("<!--?foo ba|r ?-->", SetAndGetSelectionText("<?foo ba|r ?>"))
      << "HTML parser turns PI into comment";
}

TEST_F(SelectionSampleTest, SerializeProcessingInstruction2) {
  GetDocument().body()->appendChild(GetDocument().createProcessingInstruction(
      "foo", "bar", ASSERT_NO_EXCEPTION));

  // Note: PI ::= '<?' PITarget (S (Char* - (Char* '?>' Char*)))? '?>'
  EXPECT_EQ("<?foo bar?>", SelectionSample::GetSelectionText(
                               *GetDocument().body(), SelectionInDOMTree()))
      << "No space after 'bar'";
}

// Demonstrate magic TABLE element parsing.
TEST_F(SelectionSampleTest, SerializeTable) {
  EXPECT_EQ("|<table></table>", SetAndGetSelectionText("<table>|</table>"))
      << "Parser moves Text before TABLE.";
  EXPECT_EQ("<table>|</table>",
            SetAndGetSelectionText("<table><!--|--!></table>"))
      << "Parser does not inserts TBODY and comment is removed.";
  EXPECT_EQ(
      "|start^end<table><tbody><tr><td>a</td></tr></tbody></table>",
      SetAndGetSelectionText("<table>|start<tr><td>a</td></tr>^end</table>"))
      << "Parser moves |Text| nodes inside TABLE to before TABLE.";
  EXPECT_EQ(
      "<table>|<tbody><tr><td>a</td></tr></tbody>^</table>",
      SetAndGetSelectionText(
          "<table><!--|--><tbody><tr><td>a</td></tr></tbody><!--^--></table>"))
      << "We can use |Comment| node to put selection marker inside TABLE.";
  EXPECT_EQ("<table>|<tbody><tr><td>a</td></tr>^</tbody></table>",
            SetAndGetSelectionText(
                "<table><!--|--><tr><td>a</td></tr><!--^--></table>"))
      << "Parser inserts TBODY auto magically.";
}

TEST_F(SelectionSampleTest, SerializeText) {
  EXPECT_EQ("012^3456|789", SetAndGetSelectionText("012^3456|789"));
  EXPECT_EQ("012|3456^789", SetAndGetSelectionText("012|3456^789"));
}

TEST_F(SelectionSampleTest, SerializeVoidElement) {
  EXPECT_EQ("|<div></div>", SetAndGetSelectionText("|<div></div>"))
      << "DIV requires end tag.";
  EXPECT_EQ("|<br>", SetAndGetSelectionText("|<br>"))
      << "BR doesn't need to have end tag.";
  EXPECT_EQ("|<br>1<br>", SetAndGetSelectionText("|<br>1</br>"))
      << "Parser converts </br> to <br>.";
  EXPECT_EQ("|<img>", SetAndGetSelectionText("|<img>"))
      << "IMG doesn't need to have end tag.";
}

TEST_F(SelectionSampleTest, SerializeVoidElementBR) {
  Element* const br = GetDocument().CreateRawElement(html_names::kBrTag);
  br->appendChild(GetDocument().createTextNode("abc"));
  GetDocument().body()->appendChild(br);
  EXPECT_EQ(
      "<br>abc|</br>",
      SelectionSample::GetSelectionText(
          *GetDocument().body(),
          SelectionInDOMTree::Builder().Collapse(Position(br, 1)).Build()))
      << "When BR has child nodes, it is not void element.";
}

TEST_F(SelectionSampleTest, ConvertTemplatesToShadowRoots) {
  SetBodyContent(
      "<div id=host>"
        "<template data-mode='open'>"
          "<div>shadow_first</div>"
          "<div>shadow_second</div>"
        "</template>"
      "</div>");
  Element* body = GetDocument().body();
  Element* host = body->getElementById(AtomicString("host"));
  SelectionSample::ConvertTemplatesToShadowRootsForTesring(
      *(To<HTMLElement>(host)));
  ShadowRoot* shadow_root = host->GetShadowRoot();
  ASSERT_TRUE(shadow_root->IsShadowRoot());
  EXPECT_EQ("<div>shadow_first</div><div>shadow_second</div>",
            shadow_root->innerHTML());
}

TEST_F(SelectionSampleTest, ConvertTemplatesToShadowRootsNoTemplates) {
  SetBodyContent(
      "<div id=host>"
        "<div>first</div>"
        "<div>second</div>"
      "</div>");
  Element* body = GetDocument().body();
  Element* host = body->getElementById(AtomicString("host"));
  SelectionSample::ConvertTemplatesToShadowRootsForTesring(
      *(To<HTMLElement>(host)));
  EXPECT_FALSE(host->GetShadowRoot());
  EXPECT_EQ("<div>first</div><div>second</div>", host->innerHTML());
}

TEST_F(SelectionSampleTest, ConvertTemplatesToShadowRootsMultipleTemplates) {
  SetBodyContent(
      "<div id=host1>"
        "<template data-mode='open'>"
          "<div>shadow_first</div>"
          "<div>shadow_second</div>"
        "</template>"
      "</div>"
      "<div id=host2>"
        "<template data-mode='open'>"
          "<div>shadow_third</div>"
          "<div>shadow_forth</div>"
        "</template>"
      "</div>");
  Element* body = GetDocument().body();
  Element* host1 = body->getElementById(AtomicString("host1"));
  Element* host2 = body->getElementById(AtomicString("host2"));
  SelectionSample::ConvertTemplatesToShadowRootsForTesring(
      *(To<HTMLElement>(body)));
  ShadowRoot* shadow_root_1 = host1->GetShadowRoot();
  ShadowRoot* shadow_root_2 = host2->GetShadowRoot();

  EXPECT_TRUE(shadow_root_1->IsShadowRoot());
  EXPECT_EQ("<div>shadow_first</div><div>shadow_second</div>",
            shadow_root_1->innerHTML());
  EXPECT_TRUE(shadow_root_2->IsShadowRoot());
  EXPECT_EQ("<div>shadow_third</div><div>shadow_forth</div>",
            shadow_root_2->innerHTML());
}

TEST_F(SelectionSampleTest, TraverseShadowContent) {
  HTMLElement* body = GetDocument().body();
  const std::string content = "<div id=host>"
                                "<template data-mode='open'>"
                                  "<div id=shadow1>^shadow_first</div>"
                                  "<div id=shadow2>shadow_second|</div>"
                                "</template>"
                              "</div>";
  const SelectionInDOMTree& selection =
      SelectionSample::SetSelectionText(body, content);
  EXPECT_EQ("<div id=\"host\"></div>", body->innerHTML());

  Element* host = body->getElementById(AtomicString("host"));
  ShadowRoot* shadow_root = host->GetShadowRoot();
  EXPECT_TRUE(shadow_root->IsShadowRoot());
  EXPECT_EQ(
      "<div id=\"shadow1\">shadow_first</div>"
      "<div id=\"shadow2\">shadow_second</div>",
      shadow_root->innerHTML());

  EXPECT_EQ(
      Position(
          shadow_root->getElementById(AtomicString("shadow1"))->firstChild(),
          0),
      selection.Anchor());
  EXPECT_EQ(
      Position(
          shadow_root->getElementById(AtomicString("shadow2"))->firstChild(),
          13),
      selection.Focus());
}

TEST_F(SelectionSampleTest, TraverseShadowContentWithSlot) {
  HTMLElement* body = GetDocument().body();
  const std::string content = "<div id=host>^foo"
                                "<template data-mode='open'>"
                                  "<div id=shadow1>shadow_first</div>"
                                  "<slot name=slot1>slot|</slot>"
                                  "<div id=shadow2>shadow_second</div>"
                                "</template>"
                                "<span slot=slot1>bar</slot>"
                              "</div>";
  const SelectionInDOMTree& selection =
      SelectionSample::SetSelectionText(body, content);
  EXPECT_EQ("<div id=\"host\">foo<span slot=\"slot1\">bar</span></div>",
            body->innerHTML());

  Element* host = body->getElementById(AtomicString("host"));
  ShadowRoot* shadow_root = host->GetShadowRoot();
  EXPECT_TRUE(shadow_root->IsShadowRoot());
  EXPECT_EQ(
      "<div id=\"shadow1\">shadow_first</div>"
      "<slot name=\"slot1\">slot</slot>"
      "<div id=\"shadow2\">shadow_second</div>",
      shadow_root->innerHTML());

  EXPECT_EQ(
      Position(GetDocument().getElementById(AtomicString("host"))->firstChild(),
               0),
      selection.Anchor());
  EXPECT_EQ(Position(shadow_root->QuerySelector(AtomicString("[name=slot1]"))
                         ->firstChild(),
                     4),
            selection.Focus());
}

TEST_F(SelectionSampleTest, TraverseMultipleShadowContents) {
  HTMLElement* body = GetDocument().body();
  const std::string content = "<div id=host1>"
                                "<template data-mode='open'>"
                                  "<div id=shadow1>^shadow_first</div>"
                                  "<div id=shadow2>shadow_second</div>"
                                "</template>"
                              "</div>"
                            "<div id=host2>"
                              "<template data-mode='open'>"
                                "<div id=shadow3>shadow_third</div>"
                                "<div id=shadow4>shadow_forth|</div>"
                              "</template>"
                            "</div>";
  const SelectionInDOMTree& selection =
      SelectionSample::SetSelectionText(body, content);
  EXPECT_EQ("<div id=\"host1\"></div><div id=\"host2\"></div>",
            body->innerHTML());

  Element* host1 = body->getElementById(AtomicString("host1"));
  ShadowRoot* shadow_root1 = host1->GetShadowRoot();
  Element* host2 = body->getElementById(AtomicString("host2"));
  ShadowRoot* shadow_root2 = host2->GetShadowRoot();
  EXPECT_TRUE(shadow_root1->IsShadowRoot());
  EXPECT_TRUE(shadow_root2->IsShadowRoot());
  EXPECT_EQ(
      "<div id=\"shadow1\">shadow_first</div>"
      "<div id=\"shadow2\">shadow_second</div>",
      shadow_root1->innerHTML());
  EXPECT_EQ(
      "<div id=\"shadow3\">shadow_third</div>"
      "<div id=\"shadow4\">shadow_forth</div>",
      shadow_root2->innerHTML());

  EXPECT_EQ(
      Position(
          shadow_root1->getElementById(AtomicString("shadow1"))->firstChild(),
          0),
      selection.Anchor());
  EXPECT_EQ(
      Position(
          shadow_root2->getElementById(AtomicString("shadow4"))->firstChild(),
          12),
      selection.Focus());
}

}  // namespace blink
```