Response:
My thought process for analyzing the provided C++ test file goes like this:

1. **Understand the Core Purpose:** The file name `html_document_parser_fastpath_test.cc` immediately tells me this is a test file for the "fast path" of the HTML document parser in the Blink rendering engine. The term "fast path" suggests an optimized parsing route for common or simple HTML structures.

2. **Identify Key Components:** I scan the `#include` directives to understand the dependencies and what aspects of Blink are being tested. Notable includes are:
    * `html_document_parser_fastpath.h`: The header for the code being tested.
    * `testing/gtest/include/gtest/gtest.h`:  Indicates Google Test is the testing framework.
    * Various DOM and HTML element headers (`DocumentFragment.h`, `Text.h`, `HTMLDivElement.h`, etc.): Suggests the tests will involve creating and manipulating DOM structures.
    * `base/test/metrics/histogram_tester.h`: Implies the tests verify the recording of performance metrics (histograms).
    * `third_party/blink/renderer/bindings/core/v8/...`: Hints at interaction with JavaScript through the V8 engine, although this file seems focused on the parser itself.
    * `third_party/blink/renderer/core/html/parser/html_construction_site.h`:  Connects to the broader HTML parsing process.

3. **Analyze Test Structure:** I examine the `TEST()` macros. Each `TEST()` function represents an individual test case. I read the names of these tests to get a high-level understanding of what's being verified:
    * `SanityCheck`: A basic test to ensure the testing environment is working.
    * `SetInnerHTMLUsesFastPathSuccess/Failure`: Checks if the `setInnerHTML` method uses the fast path parser as expected in success and failure scenarios.
    * `LongTextIsSplit`: Verifies how the parser handles very long text nodes (splitting for performance).
    * `MaximumHTMLParserDOMTreeDepth`: Tests the parser's behavior when encountering deeply nested HTML structures.
    * `LogUnsupportedTags/ContextTag/Svg`: Checks that the parser correctly logs (via histograms) when it encounters unsupported HTML tags or tags in invalid contexts.
    * `HTMLInputElementCheckedState`: Focuses on how the fast path parser handles the `checked` attribute of input elements, potentially involving form state management.
    * `CharacterReferenceCases/HandlesCompleteCharacterReference`: Tests the parser's ability to correctly handle various HTML character references (e.g., `&nbsp;`, `&#160;`).
    * `FailsWithNestedLis/HandlesLi`: Specifically tests how the fast path handles `<li>` elements, including cases it can and cannot handle.
    * `NullMappedToReplacementChar`: Checks how the parser deals with null characters within HTML content.
    * `DomParserUsesFastPath`: Confirms that the `DOMParser` API also utilizes the fast path parser.
    * `BodyWithLeading/TrailingWhitespace`: Tests how whitespace around the `<body>` tag is handled during parsing.
    * `MixedEncoding/Escaped8BitText`:  Examines how the parser deals with different character encodings and escaped characters.

4. **Connect to Web Technologies (HTML, CSS, JavaScript):** Now I think about how these tests relate to core web technologies:
    * **HTML:**  The entire test suite revolves around parsing HTML. The tests exercise different HTML tags, attributes, and structures.
    * **CSS:** While not directly tested, the ability to parse HTML correctly is foundational for CSS to be applied. The DOM tree created by the parser is what CSS selectors target.
    * **JavaScript:**  The `setInnerHTML` method is a JavaScript API. The tests implicitly verify that when JavaScript uses this API to modify the DOM, the fast path parser is engaged when applicable. The `DOMParser` test explicitly checks a JavaScript API.

5. **Infer Logic and Examples:** Based on the test names and code, I can infer the logic being tested and create illustrative examples:
    * **Fast Path Success/Failure:** The tests likely insert simple, valid HTML (`<div>test</div>`) and more complex or invalid HTML (`<div`) to see if the fast path is used and whether it succeeds or falls back to a slower parser.
    * **Unsupported Tags:** The tests inject HTML containing elements the fast path doesn't support (like `<table>`, `<svg>`) to ensure these cases are detected and logged.
    * **Character References:** The tests use various character references to confirm correct decoding and handling.
    * **DOM Depth:** The test constructs a very deeply nested structure to verify the parser's limits and behavior when that limit is reached.

6. **Identify Potential User/Programming Errors:** The tests highlight scenarios that could lead to issues:
    * **Invalid HTML in `setInnerHTML`:**  Users providing malformed HTML will either cause parsing errors or force the use of a slower parser.
    * **Using unsupported HTML tags:** Developers might use tags that the fast path parser doesn't handle, potentially leading to performance differences.
    * **Deeply nested HTML:** While sometimes necessary, excessive nesting can impact performance and even trigger browser limits.
    * **Incorrect character references:** Misusing character references can lead to unexpected characters being displayed.

7. **Focus on Histograms:** The use of `HistogramTester` is significant. It means the tests are not just verifying functional correctness but also performance. They are checking whether the fast path is being used when expected and logging metrics about its usage and any encountered limitations.

By following these steps, I can dissect the test file and accurately describe its functionality, its relationship to web technologies, infer the logic, and identify potential errors. The key is to combine the information from the file name, includes, test names, and the code itself to build a comprehensive understanding.这个文件 `blink/renderer/core/html/parser/html_document_parser_fastpath_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用于测试 **HTML 文档解析器快速路径 (fast path)** 的功能。

**它的主要功能是：**

1. **验证快速路径解析器的正确性：**  通过创建各种 HTML 片段，并使用快速路径解析器解析，然后断言解析结果是否符合预期。
2. **测试快速路径解析器的覆盖范围：**  测试快速路径解析器能够处理的 HTML 结构和语法，并确保其在支持的范围内能够正确工作。
3. **监控快速路径解析器的性能指标：**  通过 `base::HistogramTester` 记录快速路径解析器的使用情况和遇到的不支持的特性，从而监控其性能和覆盖范围。

**与 JavaScript, HTML, CSS 的关系和举例说明：**

这个测试文件直接关联的是 **HTML** 的解析。快速路径解析器是 Blink 引擎解析 HTML 的一个优化手段，旨在加速常见和简单的 HTML 片段的解析过程。

* **HTML:** 测试用例中会创建各种 HTML 片段，例如 `<div>test</div>`, `<table></table>`, `<input checked='true'>` 等，来测试快速路径解析器对这些 HTML 结构的处理能力。

   * **例子:** `div->setInnerHTML("<div>test</div>");` 这行代码模拟了 JavaScript 中使用 `innerHTML` 设置一个简单的 div 元素的内容。测试会验证快速路径解析器能否正确地将这个字符串解析成 DOM 树。

* **JavaScript:** 虽然这个测试文件是用 C++ 编写的，但它测试的是 Blink 引擎中与 JavaScript API 密切相关的部分。例如，`setInnerHTML` 是一个常用的 JavaScript API，用于动态修改 HTML 内容。

   * **例子:** `div->setInnerHTML("<input checked='true'>");`  这个测试用例模拟了通过 JavaScript 设置一个带有 `checked` 属性的 input 元素。测试会验证快速路径解析器能否正确解析并设置 input 元素的 `checked` 状态，这直接影响到 JavaScript 代码对该元素状态的读取和操作。

* **CSS:**  虽然测试文件本身不直接涉及 CSS 解析，但 HTML 解析是 CSS 生效的基础。正确的 HTML 结构才能让 CSS 选择器准确匹配并应用样式。

   * **关系:**  快速路径解析器正确地解析 HTML 标签和属性，为后续的 CSS 解析和渲染提供了正确的 DOM 树基础。如果 HTML 解析错误，CSS 的应用也会出现问题。

**逻辑推理、假设输入与输出:**

许多测试用例都基于逻辑推理，测试快速路径解析器在特定输入下是否产生预期的输出。

* **假设输入:** HTML 字符串 `<div>test</div>`
* **预期输出:**  在被测试的 div 元素下创建一个 Text 节点，内容为 "test"。
* **测试代码:**
   ```c++
   div->setInnerHTML("<div>test</div>");
   Text* text_node = To<Text>(div->firstChild());
   ASSERT_TRUE(text_node);
   EXPECT_EQ(text_node->data(), String("test"));
   ```

* **假设输入:** HTML 字符串 `<table></table>`
* **预期输出:**  由于 `<table>` 标签通常不在快速路径解析器的支持范围内，因此快速路径解析器应该回退到完整的解析器，或者记录该标签为不支持。
* **测试代码:**
   ```c++
   div->setInnerHTML("<table></table>");
   histogram_tester.ExpectTotalCount(
       "Blink.HTMLFastPathParser.UnsupportedTag.CompositeMaskV2", 1);
   // ... 验证记录了不支持的标签
   ```

**用户或编程常见的使用错误举例说明:**

这个测试文件间接地反映了一些用户或编程中常见的 HTML 使用错误，以及快速路径解析器如何处理或记录这些情况。

* **使用快速路径不支持的标签:**  用户或开发者可能会在 `innerHTML` 中使用一些复杂的或不常见的 HTML 标签（如 `<svg>`, `<template>`, 表格相关标签等）。快速路径解析器会检测到这些不支持的标签，并记录相关信息。这提示开发者可能需要注意他们使用的 HTML 结构，以充分利用快速路径的性能优势。

   * **例子:**  `div->setInnerHTML("<table></table>");`  如果开发者在预期快速解析的场景下使用了 `<table>` 标签，这个测试用例模拟了这种情况，并验证了快速路径解析器会记录这个不支持的标签。

* **在不允许的上下文中使用标签:** 某些 HTML 标签只能在特定的父元素下使用。快速路径解析器可能会检测到这种错误的使用方式。

   * **例子:** `dl->setInnerHTML("some text");` 这里尝试在 `<textarea>` 元素（`HTMLTextAreaElement`）中设置纯文本内容。 `<textarea>` 通常用于包含文本输入，而不是直接包含其他 HTML 结构。这个测试用例验证了快速路径解析器会记录这种上下文错误。

* **HTML 结构错误:**  例如，嵌套的 `<li>` 标签 (`<li><li></li></li>`) 是一种 HTML 结构错误。快速路径解析器可能无法正确处理这种复杂的嵌套关系，并可能回退到完整的解析器。

   * **例子:** `div->setInnerHTML("<li><li></li></li>");` 这个测试用例验证了快速路径解析器在这种情况下可能无法成功解析，并通过检查生成的子节点数量来体现解析结果。

* **字符引用错误:** 虽然测试用例 `CharacterReferenceCases` 看起来是在测试正确的字符引用处理，但也暗示了如果用户使用了错误的或不完整的字符引用，可能会导致解析问题。

总而言之，`html_document_parser_fastpath_test.cc` 是一个关键的测试文件，它确保了 Blink 引擎的 HTML 快速路径解析器在处理常见 HTML 场景时的正确性和性能。它通过各种测试用例覆盖了快速路径解析器的支持范围，并监控了其在遇到不支持的 HTML 结构时的行为，从而帮助开发者了解快速路径解析器的局限性，并避免一些常见的 HTML 使用错误。

Prompt: 
```
这是目录为blink/renderer/core/html/parser/html_document_parser_fastpath_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/parser/html_document_parser_fastpath.h"

#include "base/test/metrics/histogram_tester.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_supported_type.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/html/forms/form_controller.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/parser/html_construction_site.h"
#include "third_party/blink/renderer/core/keywords.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/core/xml/dom_parser.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {
namespace {

TEST(HTMLDocumentParserFastpathTest, SanityCheck) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write("<body></body>");
  auto* div = MakeGarbageCollected<HTMLDivElement>(*document);
  document->body()->AppendChild(div);
  DocumentFragment* fragment = DocumentFragment::Create(*document);
  base::HistogramTester histogram_tester;
  EXPECT_TRUE(
      TryParsingHTMLFragment("<div>test</div>", *document, *fragment, *div,
                             ParserContentPolicy::kAllowScriptingContent, {}));
  histogram_tester.ExpectTotalCount(
      "Blink.HTMLFastPathParser.UnsupportedTagType.CompositeMaskV2", 0);
  histogram_tester.ExpectTotalCount(
      "Blink.HTMLFastPathParser.UnsupportedContextTag.CompositeMaskV2", 0);
}

TEST(HTMLDocumentParserFastpathTest, SetInnerHTMLUsesFastPathSuccess) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write("<body></body>");
  auto* div = MakeGarbageCollected<HTMLDivElement>(*document);

  base::HistogramTester histogram_tester;
  div->setInnerHTML("<div>test</div>");
  // This was html the fast path handled, so there should be one histogram with
  // success.
  histogram_tester.ExpectTotalCount("Blink.HTMLFastPathParser.ParseResult", 1);
  histogram_tester.ExpectUniqueSample("Blink.HTMLFastPathParser.ParseResult",
                                      HtmlFastPathResult::kSucceeded, 1);
}

TEST(HTMLDocumentParserFastpathTest, SetInnerHTMLUsesFastPathFailure) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write("<body></body>");
  auto* div = MakeGarbageCollected<HTMLDivElement>(*document);

  base::HistogramTester histogram_tester;
  div->setInnerHTML("<div");
  // The fast path should not have handled this, so there should be one
  // histogram with a value other then success.
  histogram_tester.ExpectTotalCount("Blink.HTMLFastPathParser.ParseResult", 1);
  histogram_tester.ExpectBucketCount("Blink.HTMLFastPathParser.ParseResult",
                                     HtmlFastPathResult::kSucceeded, 0);
}

TEST(HTMLDocumentParserFastpathTest, LongTextIsSplit) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write("<body></body>");
  auto* div = MakeGarbageCollected<HTMLDivElement>(*document);
  std::vector<LChar> chars(Text::kDefaultLengthLimit + 1, 'a');
  div->setInnerHTML(String(base::span(chars)));
  Text* text_node = To<Text>(div->firstChild());
  ASSERT_TRUE(text_node);
  // Text is split at 64k for performance. See
  // HTMLConstructionSite::FlushPendingText for more details.
  EXPECT_EQ(Text::kDefaultLengthLimit, text_node->length());
}

TEST(HTMLDocumentParserFastpathTest, MaximumHTMLParserDOMTreeDepth) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write("<body></body>");
  auto* div = MakeGarbageCollected<HTMLDivElement>(*document);
  StringBuilder string_builder;
  const unsigned depth =
      HTMLConstructionSite::kMaximumHTMLParserDOMTreeDepth + 2;
  // Create a very nested tree, with the deepest containing the id `deepest`.
  for (unsigned i = 0; i < depth - 1; ++i) {
    string_builder.Append("<div>");
  }
  string_builder.Append("<div id='deepest'>");
  string_builder.Append("</div>");
  for (unsigned i = 0; i < depth - 1; ++i) {
    string_builder.Append("</div>");
  }
  div->setInnerHTML(string_builder.ToString());

  // Because kMaximumHTMLParserDOMTreeDepth was encountered, the deepest
  // node should have siblings.
  Element* deepest = div->getElementById(AtomicString("deepest"));
  ASSERT_TRUE(deepest);
  EXPECT_EQ(deepest->parentNode()->CountChildren(), 3u);
}

TEST(HTMLDocumentParserFastpathTest, LogUnsupportedTags) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  auto* div = MakeGarbageCollected<HTMLDivElement>(*document);

  base::HistogramTester histogram_tester;
  div->setInnerHTML("<table></table>");
  histogram_tester.ExpectTotalCount(
      "Blink.HTMLFastPathParser.UnsupportedTag.CompositeMaskV2", 1);
  histogram_tester.ExpectBucketCount(
      "Blink.HTMLFastPathParser.UnsupportedTag.CompositeMaskV2", 2, 1);
  histogram_tester.ExpectTotalCount(
      "Blink.HTMLFastPathParser.UnsupportedTag.Mask0V2", 0);
  histogram_tester.ExpectTotalCount(
      "Blink.HTMLFastPathParser.UnsupportedTag.Mask1V2", 1);
  histogram_tester.ExpectTotalCount(
      "Blink.HTMLFastPathParser.UnsupportedTag.Mask2V2", 0);
}

TEST(HTMLDocumentParserFastpathTest, LogUnsupportedTagsWithValidTag) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  auto* div = MakeGarbageCollected<HTMLDivElement>(*document);

  base::HistogramTester histogram_tester;
  div->setInnerHTML("<div><table></table></div>");
  histogram_tester.ExpectTotalCount(
      "Blink.HTMLFastPathParser.UnsupportedTag.CompositeMaskV2", 1);
  // Table is in the second chunk of values, so 2 should be set.
  histogram_tester.ExpectBucketCount(
      "Blink.HTMLFastPathParser.UnsupportedTag.CompositeMaskV2", 2, 1);
  histogram_tester.ExpectTotalCount(
      "Blink.HTMLFastPathParser.UnsupportedTag.Mask0V2", 0);
  histogram_tester.ExpectTotalCount(
      "Blink.HTMLFastPathParser.UnsupportedTag.Mask1V2", 1);
  histogram_tester.ExpectTotalCount(
      "Blink.HTMLFastPathParser.UnsupportedTag.Mask2V2", 0);
}

TEST(HTMLDocumentParserFastpathTest, LogUnsupportedContextTag) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  auto* dl = MakeGarbageCollected<HTMLTextAreaElement>(*document);

  base::HistogramTester histogram_tester;
  dl->setInnerHTML("some text");
  histogram_tester.ExpectTotalCount(
      "Blink.HTMLFastPathParser.UnsupportedContextTag.CompositeMaskV2", 1);
  // Textarea is in the third chunk of values, so 3 should be set.
  histogram_tester.ExpectBucketCount(
      "Blink.HTMLFastPathParser.UnsupportedContextTag.CompositeMaskV2", 4, 1);
  histogram_tester.ExpectTotalCount(
      "Blink.HTMLFastPathParser.UnsupportedContextTag.Mask0V2", 0);
  histogram_tester.ExpectTotalCount(
      "Blink.HTMLFastPathParser.UnsupportedContextTag.Mask1V2", 0);
  histogram_tester.ExpectTotalCount(
      "Blink.HTMLFastPathParser.UnsupportedContextTag.Mask2V2", 1);
}

TEST(HTMLDocumentParserFastpathTest, LogSvg) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  auto* div = MakeGarbageCollected<HTMLDivElement>(*document);

  base::HistogramTester histogram_tester;
  div->setInnerHTML("<svg></svg>");
  histogram_tester.ExpectTotalCount(
      "Blink.HTMLFastPathParser.UnsupportedTag.CompositeMaskV2", 1);
  // Svg is in the third chunk of values, so 4 should be set.
  histogram_tester.ExpectBucketCount(
      "Blink.HTMLFastPathParser.UnsupportedTag.CompositeMaskV2", 4, 1);
  histogram_tester.ExpectTotalCount(
      "Blink.HTMLFastPathParser.UnsupportedTag.Mask0V2", 0);
  histogram_tester.ExpectTotalCount(
      "Blink.HTMLFastPathParser.UnsupportedTag.Mask1V2", 0);
  histogram_tester.ExpectTotalCount(
      "Blink.HTMLFastPathParser.UnsupportedTag.Mask2V2", 1);
}

TEST(HTMLDocumentParserFastpathTest, HTMLInputElementCheckedState) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write("<body></body>");
  auto* div1 = MakeGarbageCollected<HTMLDivElement>(*document);
  auto* div2 = MakeGarbageCollected<HTMLDivElement>(*document);
  document->body()->AppendChild(div1);
  document->body()->AppendChild(div2);

  // Set the state for new controls, which triggers a different code path in
  // HTMLInputElement::ParseAttribute.
  div1->setInnerHTML("<select form='ff'></select>");
  DocumentState* document_state = document->GetFormController().ControlStates();
  Vector<String> state1 = document_state->ToStateVector();
  document->GetFormController().SetStateForNewControls(state1);
  EXPECT_TRUE(document->GetFormController().HasControlStates());

  div2->setInnerHTML("<input checked='true'>");
  HTMLInputElement* input_element = To<HTMLInputElement>(div2->firstChild());
  ASSERT_TRUE(input_element);
  EXPECT_TRUE(input_element->Checked());
}

TEST(HTMLDocumentParserFastpathTest, CharacterReferenceCases) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  auto* div = MakeGarbageCollected<HTMLDivElement>(*document);

  // Various subtle cases of character references that have caused problems.
  // The assertions are handled by DCHECKs in the code, specifically in
  // serialization.cc.
  div->setInnerHTML("Genius Nicer Dicer Plus | 18&nbsp&hellip;");
  div->setInnerHTML("&nbsp&a");
  div->setInnerHTML("&nbsp&");
  div->setInnerHTML("&nbsp-");
}

TEST(HTMLDocumentParserFastpathTest, HandlesCompleteCharacterReference) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write("<body></body>");
  auto* div = MakeGarbageCollected<HTMLDivElement>(*document);

  base::HistogramTester histogram_tester;
  div->setInnerHTML("&cent;");
  Text* text_node = To<Text>(div->firstChild());
  ASSERT_TRUE(text_node);
  EXPECT_EQ(text_node->data(), String(u"\u00A2"));
  histogram_tester.ExpectTotalCount("Blink.HTMLFastPathParser.ParseResult", 1);
  histogram_tester.ExpectUniqueSample("Blink.HTMLFastPathParser.ParseResult",
                                      HtmlFastPathResult::kSucceeded, 1);
}

TEST(HTMLDocumentParserFastpathTest, FailsWithNestedLis) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write("<body></body>");
  auto* div = MakeGarbageCollected<HTMLDivElement>(*document);

  base::HistogramTester histogram_tester;
  div->setInnerHTML("<li><li></li></li>");
  // The html results in two children (nested <li>s implicitly close the open
  // <li>, resulting in two sibling <li>s, not one). The fast path parser does
  // not handle this case.
  EXPECT_EQ(2u, div->CountChildren());
  histogram_tester.ExpectTotalCount("Blink.HTMLFastPathParser.ParseResult", 1);
  histogram_tester.ExpectBucketCount("Blink.HTMLFastPathParser.ParseResult",
                                     HtmlFastPathResult::kSucceeded, 0);
}

TEST(HTMLDocumentParserFastpathTest, HandlesLi) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write("<body></body>");
  auto* div = MakeGarbageCollected<HTMLDivElement>(*document);

  base::HistogramTester histogram_tester;
  div->setInnerHTML("<div><li></li></div>");
  histogram_tester.ExpectTotalCount("Blink.HTMLFastPathParser.ParseResult", 1);
  histogram_tester.ExpectUniqueSample("Blink.HTMLFastPathParser.ParseResult",
                                      HtmlFastPathResult::kSucceeded, 1);
}

TEST(HTMLDocumentParserFastpathTest, NullMappedToReplacementChar) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write("<body></body>");
  auto* div = MakeGarbageCollected<HTMLDivElement>(*document);

  base::HistogramTester histogram_tester;
  // Constructor that takes a base::span is needed because of \0 in string.
  div->setInnerHTML(
      String(base::span_from_cstring("<div id='x' name='x\0y'></div>")));
  Element* new_div = div->getElementById(AtomicString("x"));
  ASSERT_TRUE(new_div);
  // Null chars are generally mapped to \uFFFD (at least this test should
  // trigger the replacement).
  EXPECT_EQ(AtomicString(String(u"x\uFFFDy")), new_div->GetNameAttribute());
}

// Verifies DOMParser uses the fast path parser.
TEST(HTMLDocumentParserFastpathTest, DomParserUsesFastPath) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* parser = DOMParser::Create(scope.GetScriptState());
  base::HistogramTester histogram_tester;
  parser->parseFromString("<strong>0</strong> items left",
                          V8SupportedType(V8SupportedType::Enum::kTextHtml));
  histogram_tester.ExpectTotalCount("Blink.HTMLFastPathParser.ParseResult", 1);
}

TEST(HTMLDocumentParserFastpathTest, BodyWithLeadingWhitespace) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* parser = DOMParser::Create(scope.GetScriptState());
  base::HistogramTester histogram_tester;
  Document* document = parser->parseFromString(
      "\n   <div></div>", V8SupportedType(V8SupportedType::Enum::kTextHtml));
  histogram_tester.ExpectTotalCount("Blink.HTMLFastPathParser.ParseResult", 1);
  EXPECT_EQ("<body><div></div></body>", CreateMarkup(document->body()));
  auto* first_child = document->body()->firstChild();
  ASSERT_TRUE(first_child);
}

TEST(HTMLDocumentParserFastpathTest, BodyWithLeadingAndTrailingWhitespace) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* parser = DOMParser::Create(scope.GetScriptState());
  base::HistogramTester histogram_tester;
  Document* document = parser->parseFromString(
      "\n   x<div></div>y ", V8SupportedType(V8SupportedType::Enum::kTextHtml));
  histogram_tester.ExpectTotalCount("Blink.HTMLFastPathParser.ParseResult", 1);
  EXPECT_EQ("<body>x<div></div>y </body>", CreateMarkup(document->body()));
  auto* first_child = document->body()->firstChild();
  ASSERT_TRUE(first_child);
}

TEST(HTMLDocumentParserFastpathTest, BodyWithLeadingAndTrailingWhitespace2) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* parser = DOMParser::Create(scope.GetScriptState());
  base::HistogramTester histogram_tester;
  Document* document = parser->parseFromString(
      "\n   x \n  <div></div>y \n   ",
      V8SupportedType(V8SupportedType::Enum::kTextHtml));
  histogram_tester.ExpectTotalCount("Blink.HTMLFastPathParser.ParseResult", 1);
  EXPECT_EQ("<body>x \n  <div></div>y \n   </body>",
            CreateMarkup(document->body()));
  auto* first_child = document->body()->firstChild();
  ASSERT_TRUE(first_child);
}

TEST(HTMLDocumentParserFastpathTest, MixedEncoding) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write("<body></body>");
  auto* div = MakeGarbageCollected<HTMLDivElement>(*document);
  div->setInnerHTML(u"Hello");
  Text* text_node = To<Text>(div->firstChild());
  ASSERT_TRUE(text_node);
  // Even though the supplied string was utf16, it only contained 8-bit chars,
  // so should end up as 8-bit.
  EXPECT_TRUE(text_node->data().Is8Bit());
}

TEST(HTMLDocumentParserFastpathTest, Escaped8BitText) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      HTMLDocument::CreateForTest(execution_context.GetExecutionContext());
  document->write("<body></body>");
  auto* div = MakeGarbageCollected<HTMLDivElement>(*document);

  div->setInnerHTML("&amp;");
  Text* text_node = To<Text>(div->firstChild());
  ASSERT_TRUE(text_node);
  // "&amp;" should be represented as 8-bit.
  EXPECT_TRUE(text_node->data().Is8Bit());
}

}  // namespace
}  // namespace blink

"""

```