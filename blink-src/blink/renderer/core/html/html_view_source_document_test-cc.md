Response:
My thinking process to analyze the provided C++ code and generate the response went through these stages:

1. **Understanding the Goal:** The request asks for an explanation of the provided C++ test file, focusing on its functionality, relationship to web technologies (HTML, CSS, JavaScript), logical deductions (input/output examples), and potential user/programming errors it might highlight.

2. **Initial Code Scan (High-Level):** I first scanned the code for keywords and structure. I noticed:
    * `#include` directives, indicating dependencies on testing frameworks (`gtest`), DOM elements, frames, and simulation utilities.
    * A test fixture class `HTMLViewSourceDocumentTest` inheriting from `SimTest`. This immediately suggests it's a unit test for a specific functionality.
    * `TEST_F` macros, confirming the presence of multiple test cases.
    * A `LoadMainResource` helper function, implying the tests involve loading HTML content.
    * `EXPECT_EQ` calls, which are the core assertions of the tests, comparing the `outerHTML` of the document with expected string outputs.
    * Raw string literals (`R"HTML(...)HTML"`), indicating the HTML content being tested.

3. **Identifying the Core Functionality:** The class name `HTMLViewSourceDocumentTest` and the use of `EnableViewSourceMode(true)` strongly suggest that this file tests the *view-source* functionality of the Blink rendering engine. The tests aim to verify how HTML is displayed when the browser is in "view source" mode.

4. **Analyzing Individual Test Cases:** I then examined each `TEST_F` block individually:
    * **Common Pattern:**  Each test loads a specific HTML snippet using `LoadMainResource` and then asserts the `outerHTML` of the resulting document. This `outerHTML` is the rendered view-source representation of the input HTML.
    * **Test Case Variations:** I noted the differences in the input HTML for each test:
        * `ViewSource1`: Simple HTML structure with tags and attributes.
        * `ViewSource2`: HTML containing `<script>`, `<style>`, `<xmp>`, and `<textarea>` tags, testing how these special elements are handled.
        * `ViewSource3` & `ViewSource4`: Testing the impact of `<base>` tags and case-insensitivity of HTML tags/attributes in view-source.
        * `ViewSource5`: Testing formatting with extra whitespace and newlines.
        * `ViewSource6`: Handling of large amounts of whitespace.
        * `ViewSource7`: Simple plain text content.
        * `ViewSource8`:  Testing the rendering of `<img>` tags with `src` and `srcset` attributes, including linkification.
        * `ViewSource9`: Testing the handling of special characters within `<script>` tags.
        * `IncompleteToken`, `UnfinishedTextarea`, `UnfinishedScript`: Testing how incomplete HTML structures are displayed in view-source.
        * `Linebreak`:  Testing how different types of line breaks are represented.
        * `DOMParts`: Testing the display of non-standard HTML constructs.

5. **Relating to Web Technologies:**  The core function of view-source directly relates to HTML. The tests demonstrate how the browser displays the raw HTML source code. I specifically looked for examples where the view-source output differed from the rendered output (which wouldn't be created in this test setup) and highlighted the syntax highlighting with CSS classes like `html-tag`, `html-attribute-name`, etc. The test involving the `<base>` tag demonstrated the relationship with how URLs are interpreted in HTML. The linkification of URLs in attributes like `href` and `srcset` further connects to HTML and how browsers handle links. While JavaScript itself isn't *executed* in view-source, the tests with `<script>` tags show how the script content is displayed as raw text. CSS is indirectly related as the syntax highlighting of the view-source page is achieved using CSS (although this test only verifies the HTML structure with the CSS classes).

6. **Identifying Logical Deductions (Input/Output):**  The `EXPECT_EQ` calls provide direct input/output examples. The input is the HTML passed to `LoadMainResource`, and the output is the expected `outerHTML` string. I chose a couple of illustrative examples to demonstrate this clearly.

7. **Considering User/Programming Errors:**  The tests with "IncompleteToken," "UnfinishedTextarea," and "UnfinishedScript" directly address how the view-source feature handles malformed or incomplete HTML. This is a common scenario for developers debugging web pages. I provided examples of these errors and how the view-source output would reveal them. Another common error is misunderstanding how whitespace and line breaks are handled, which is also covered by the tests.

8. **Structuring the Response:** I organized the information into clear sections: Functionality, Relationship to Web Technologies, Logical Deductions, and User/Programming Errors. Within each section, I used bullet points and specific examples from the code to support my explanations. I made sure to explicitly mention the assumptions made (e.g., the test setup simulates a browser environment).

9. **Refinement and Language:**  I reviewed the generated response for clarity, accuracy, and completeness. I used precise language and avoided jargon where possible, explaining technical terms when necessary. I made sure the examples were easy to understand and directly tied back to the code.

By following these steps, I could systematically analyze the provided C++ code and generate a comprehensive and informative response that addresses all aspects of the request.
好的，让我们来分析一下 `blink/renderer/core/html/html_view_source_document_test.cc` 这个文件。

**功能概要:**

这个 C++ 文件是一个单元测试文件，用于测试 Blink 渲染引擎中与 **"查看源代码" (View Source)** 功能相关的 `HTMLViewSourceDocument` 类的行为。 它的主要目的是验证当浏览器以“查看源代码”模式显示 HTML 文档时，`HTMLViewSourceDocument` 类是否能够正确地将原始 HTML 文本格式化并呈现出来。

**与 Javascript, HTML, CSS 的关系:**

这个测试文件主要关注 **HTML** 的处理，但也间接与 **CSS** 和 **Javascript** 有关：

* **HTML:** 这是测试的核心。每个测试用例都加载一段 HTML 字符串，然后断言 `HTMLViewSourceDocument` 生成的输出是否与预期的“查看源代码”格式一致。测试涵盖了各种 HTML 结构，包括：
    * 基础的 HTML 标签和属性。
    * 特殊标签如 `<script>`, `<style>`, `<xmp>`, `<textarea>`。
    * `<base>` 标签对 URL 解析的影响。
    * HTML 标签和属性的大小写。
    * 各种空白字符和换行符的处理。
    * 不完整的 HTML 结构。
    * 带有 `srcset` 属性的 `<img>` 标签。
    * HTML 注释（虽然在这个文件中没有显式测试，但 `HTMLViewSourceDocument` 需要能够正确显示它们）。
* **CSS:**  虽然没有直接测试 CSS 的执行，但从测试输出可以看出，`HTMLViewSourceDocument` 会为 HTML 标签、属性名、属性值等添加特定的 CSS 类 (例如 `html-tag`, `html-attribute-name`, `html-attribute-value`, `html-resource-link`)，以便在实际的“查看源代码”页面中进行语法高亮显示。测试间接验证了这些 CSS 类的添加是否正确。
* **Javascript:**  同样，Javascript 代码不会在“查看源代码”模式下执行。测试用例包含 `<script>` 标签，验证 `HTMLViewSourceDocument` 能否将 Javascript 代码作为纯文本正确地显示出来，包括一些特殊字符的处理。

**举例说明:**

* **HTML 关系:**
    * **假设输入:**  `<h1>Hello World</h1>`
    * **预期输出 (查看源代码):**
      ```html
      <html><head><meta name="color-scheme" content="light dark"></head><body><div class="line-gutter-backdrop"></div><form autocomplete="off"><label class="line-wrap-control"><input type="checkbox"></label></form><table><tbody><tr><td class="line-number" value="1"></td><td class="line-content"><span class="html-tag">&lt;h1&gt;</span>Hello World<span class="html-tag">&lt;/h1&gt;</span><span class="html-end-of-file"></span></td></tr></tbody></table></body></html>
      ```
    * 这个例子展示了 `HTMLViewSourceDocument` 如何将 HTML 标签用 `<span>` 标签包裹并添加 `html-tag` 类，以便进行高亮显示。

* **CSS 关系:**
    *  在上面的例子中，`<span class="html-tag">` 这个结构体现了与 CSS 的关系。浏览器会使用与 `html-tag` 类关联的 CSS 规则来渲染标签的样式（通常是不同的颜色）。虽然测试本身不验证 CSS 的效果，但它验证了 HTML 结构中 CSS 类的存在。

* **Javascript 关系:**
    * **假设输入:** `<script>console.log("Hello");</script>`
    * **预期输出 (查看源代码):**
      ```html
      <html><head><meta name="color-scheme" content="light dark"></head><body><div class="line-gutter-backdrop"></div><form autocomplete="off"><label class="line-wrap-control"><input type="checkbox"></label></form><table><tbody><tr><td class="line-number" value="1"></td><td class="line-content"><span class="html-tag">&lt;script&gt;</span>console.log("Hello");<span class="html-tag">&lt;/script&gt;</span><span class="html-end-of-file"></span></td></tr></tbody></table></body></html>
      ```
    *  `HTMLViewSourceDocument` 将 Javascript 代码视为普通文本，并使用 `<span>` 标签包裹 `<script>` 标签。

**逻辑推理 (假设输入与输出):**

许多测试用例都体现了逻辑推理。例如，`ViewSource3` 和 `ViewSource4` 测试了 `<base>` 标签的影响。

* **假设输入 (ViewSource3):**
  ```html
  <head><base href="http://example.org/foo/"></head>
  <body>
  <a href="bar">http://example.org/foo/bar</a><br>
  <a href="/bar">http://example.org/bar</a><br>
  <a href="http://example.org/foobar">http://example.org/foobar</a><br>
  <a href="bar?a&amp;b">http://example.org/foo/bar?a&b</a>
  </body>
  ```
* **预期输出 (部分):** 注意 `href` 属性的值被特殊处理，显示为可点击的链接，并根据 `<base>` 标签进行了正确的解析。
  ```html
  ...
  <span class="html-tag">&lt;a <span class="html-attribute-name">href</span>="<a class="html-attribute-value html-external-link" target="_blank" href="bar" rel="noreferrer noopener">bar</a>"&gt;</span>http://example.org/foo/bar<span class="html-tag">&lt;/a&gt;</span><span class="html-tag">&lt;br&gt;</span>
  ...
  <span class="html-tag">&lt;a <span class="html-attribute-name">href</span>="<a class="html-attribute-value html-external-link" target="_blank" href="/bar" rel="noreferrer noopener">/bar</a>"&gt;</span>http://example.org/bar<span class="html-tag">&lt;/a&gt;</span><span class="html-tag">&lt;br&gt;</span>
  ...
  ```
  这里，相对 URL `bar` 被解析为 `http://example.org/foo/bar`，而绝对 URL `/bar` 被解析为 `http://example.org/bar`。

**用户或编程常见的使用错误:**

这个测试文件主要关注 Blink 引擎内部的实现，但它也间接地覆盖了一些用户或编程中常见的 HTML 错误：

* **不完整的 HTML 结构:** `IncompleteToken`, `UnfinishedTextarea`, `UnfinishedScript` 这些测试用例模拟了 HTML 标签未闭合或不完整的情况。
    * **假设输入 (UnfinishedTextarea):** `<textarea>foobar in textarea` (缺少 `</textarea>`)
    * **预期输出:**  `HTMLViewSourceDocument` 仍然会尽力显示内容，但会按照原始文本输出，不会尝试补全标签。这有助于开发者识别这类错误。
      ```html
      <html><head><meta name="color-scheme" content="light dark"></head><body><div class="line-gutter-backdrop\"></div><form autocomplete="off"><label class="line-wrap-control"><input type="checkbox"></label></form><table><tbody><tr><td class="line-number" value="1"></td><td class="line-content"><span class="html-tag">&lt;textarea&gt;</span>foobar in textarea</td></tr><tr><td class="line-number" value="2"></td><td class="line-content">  <span class="html-end-of-file"></span></td></tr></tbody></table></body></html>
      ```
* **特殊字符处理错误:** `ViewSource9` 测试了 `<script>` 标签中包含类似 HTML 注释的字符串的情况 (`"<!--  --!><script>";`). 确保 `HTMLViewSourceDocument` 不会将这些字符串误解析为真正的 HTML 结构。
* **URL 解析错误 (与 `<base>` 标签相关):**  如果 `<base>` 标签的 `href` 属性设置不正确，可能会导致页面中的相对链接解析错误。 `ViewSource3` 和 `ViewSource4` 的测试确保了在“查看源代码”模式下，链接会根据 `<base>` 标签正确地显示出来，这有助于开发者调试 URL 相关的问题。
* **空白字符和换行符处理不当:** `ViewSource5` 和 `ViewSource6` 测试了各种空白字符和换行符的处理。 开发者可能会错误地假设多余的空格或换行不会影响 HTML 的渲染，但在“查看源代码”模式下，这些都会被清晰地展示出来。

**总结:**

`html_view_source_document_test.cc` 是一个关键的测试文件，它确保了 Blink 引擎的“查看源代码”功能能够正确地格式化和呈现各种 HTML 结构，帮助开发者理解网页的原始代码，并辅助调试 HTML 相关的错误。它虽然不直接测试 Javascript 或 CSS 的执行，但通过验证 HTML 结构中 CSS 类的存在以及对 `<script>` 标签的处理，间接地与它们相关联。

Prompt: 
```
这是目录为blink/renderer/core/html/html_view_source_document_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/html_view_source_document.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"

namespace blink {

class HTMLViewSourceDocumentTest : public SimTest {
 public:
  void LoadMainResource(const String& html) {
    SimRequest main_resource("https://example.com/", "text/html");
    LoadURL("https://example.com/");
    main_resource.Complete(html);
    Compositor().BeginFrame();
  }

  void SetUp() override {
    SimTest::SetUp();
    MainFrame().EnableViewSourceMode(true);
  }
};

TEST_F(HTMLViewSourceDocumentTest, ViewSource1) {
  LoadMainResource(R"HTML(
      <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
      "http://www.w3.org/TR/html4/strict.dtd">
      <hr noshade width=75%>
      <div align="center" title="" id="foo">
      <p>hello world</p>
      </div>
  )HTML");
  EXPECT_EQ(
      GetDocument().documentElement()->outerHTML(),
      "<html><head><meta name=\"color-scheme\" content=\"light "
      "dark\"></head><body><div class=\"line-gutter-backdrop\"></div><form "
      "autocomplete=\"off\"><label class=\"line-wrap-control\">"
      "<input type=\"checkbox\"></label>"
      "</form><table><tbody><tr><td class=\"line-number\" value=\"1\"></td><td "
      "class=\"line-content\"><br></td></tr><tr><td class=\"line-number\" "
      "value=\"2\"></td><td class=\"line-content\">      <span "
      "class=\"html-doctype\">&lt;!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML "
      "4.01//EN\"</span></td></tr><tr><td class=\"line-number\" "
      "value=\"3\"></td><td class=\"line-content\"><span "
      "class=\"html-doctype\">      "
      "\"http://www.w3.org/TR/html4/strict.dtd\"&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"4\"></td><td class=\"line-content\">      "
      "<span class=\"html-tag\">&lt;hr <span "
      "class=\"html-attribute-name\">noshade</span> <span "
      "class=\"html-attribute-name\">width</span>=<span "
      "class=\"html-attribute-value\">75%</span>&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"5\"></td><td class=\"line-content\">      "
      "<span class=\"html-tag\">&lt;div <span "
      "class=\"html-attribute-name\">align</span>=\"<span "
      "class=\"html-attribute-value\">center</span>\" <span "
      "class=\"html-attribute-name\">title</span>=\"\" <span "
      "class=\"html-attribute-name\">id</span>=\"<span "
      "class=\"html-attribute-value\">foo</span>\"&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"6\"></td><td class=\"line-content\">      "
      "<span class=\"html-tag\">&lt;p&gt;</span>hello world<span "
      "class=\"html-tag\">&lt;/p&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"7\"></td><td class=\"line-content\">      "
      "<span class=\"html-tag\">&lt;/div&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"8\"></td><td class=\"line-content\">  "
      "<span "
      "class=\"html-end-of-file\"></span></td></tr></tbody></table></body></"
      "html>");
}

TEST_F(HTMLViewSourceDocumentTest, ViewSource2) {
  LoadMainResource(R"HTML(
      <script>
      <testscript>
      </script>

      <style>
      <teststyle>
      </style>

      <xmp>
      <testxmp>
      </xmp>

      <textarea>
      <testtextarea>
      </textarea>
  )HTML");
  EXPECT_EQ(
      GetDocument().documentElement()->outerHTML(),
      "<html><head><meta name=\"color-scheme\" content=\"light "
      "dark\"></head><body><div class=\"line-gutter-backdrop\"></div><form "
      "autocomplete=\"off\"><label class=\"line-wrap-control\">"
      "<input type=\"checkbox\"></label>"
      "</form><table><tbody><tr><td class=\"line-number\" value=\"1\"></td><td "
      "class=\"line-content\"><br></td></tr><tr><td class=\"line-number\" "
      "value=\"2\"></td><td class=\"line-content\">      <span "
      "class=\"html-tag\">&lt;script&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"3\"></td><td class=\"line-content\">      "
      "&lt;testscript&gt;</td></tr><tr><td class=\"line-number\" "
      "value=\"4\"></td><td class=\"line-content\">      <span "
      "class=\"html-tag\">&lt;/script&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"5\"></td><td "
      "class=\"line-content\"><br></td></tr><tr><td class=\"line-number\" "
      "value=\"6\"></td><td class=\"line-content\">      <span "
      "class=\"html-tag\">&lt;style&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"7\"></td><td class=\"line-content\">      "
      "&lt;teststyle&gt;</td></tr><tr><td class=\"line-number\" "
      "value=\"8\"></td><td class=\"line-content\">      <span "
      "class=\"html-tag\">&lt;/style&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"9\"></td><td "
      "class=\"line-content\"><br></td></tr><tr><td class=\"line-number\" "
      "value=\"10\"></td><td class=\"line-content\">      <span "
      "class=\"html-tag\">&lt;xmp&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"11\"></td><td class=\"line-content\">     "
      " &lt;testxmp&gt;</td></tr><tr><td class=\"line-number\" "
      "value=\"12\"></td><td class=\"line-content\">      <span "
      "class=\"html-tag\">&lt;/xmp&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"13\"></td><td "
      "class=\"line-content\"><br></td></tr><tr><td class=\"line-number\" "
      "value=\"14\"></td><td class=\"line-content\">      <span "
      "class=\"html-tag\">&lt;textarea&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"15\"></td><td class=\"line-content\">     "
      " &lt;testtextarea&gt;</td></tr><tr><td class=\"line-number\" "
      "value=\"16\"></td><td class=\"line-content\">      <span "
      "class=\"html-tag\">&lt;/textarea&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"17\"></td><td class=\"line-content\">  "
      "<span "
      "class=\"html-end-of-file\"></span></td></tr></tbody></table></body></"
      "html>");
}

TEST_F(HTMLViewSourceDocumentTest, ViewSource3) {
  LoadMainResource(R"HTML(
      <head><base href="http://example.org/foo/"></head>
      <body>
      <a href="bar">http://example.org/foo/bar</a><br>
      <a href="/bar">http://example.org/bar</a><br>
      <a href="http://example.org/foobar">http://example.org/foobar</a><br>
      <a href="bar?a&amp;b">http://example.org/foo/bar?a&b</a>
      </body>
  )HTML");
  EXPECT_EQ(
      GetDocument().documentElement()->outerHTML(),
      "<html><head><meta name=\"color-scheme\" content=\"light "
      "dark\"></head><body><div class=\"line-gutter-backdrop\"></div><form "
      "autocomplete=\"off\"><label class=\"line-wrap-control\">"
      "<input type=\"checkbox\"></label>"
      "</form><table><tbody><tr><td class=\"line-number\" value=\"1\"></td><td "
      "class=\"line-content\"><br></td></tr><tr><td class=\"line-number\" "
      "value=\"2\"></td><td class=\"line-content\">      <span "
      "class=\"html-tag\">&lt;head&gt;</span><span class=\"html-tag\">&lt;base "
      "<span class=\"html-attribute-name\">href</span><base "
      "href=\"http://example.org/foo/\">=\"<a class=\"html-attribute-value "
      "html-resource-link\" target=\"_blank\" href=\"http://example.org/foo/\" "
      "rel=\"noreferrer "
      "noopener\">http://example.org/foo/</a>\"&gt;</span><span "
      "class=\"html-tag\">&lt;/head&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"3\"></td><td class=\"line-content\">      "
      "<span class=\"html-tag\">&lt;body&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"4\"></td><td class=\"line-content\">      "
      "<span class=\"html-tag\">&lt;a <span "
      "class=\"html-attribute-name\">href</span>=\"<a "
      "class=\"html-attribute-value html-external-link\" target=\"_blank\" "
      "href=\"bar\" rel=\"noreferrer "
      "noopener\">bar</a>\"&gt;</span>http://example.org/foo/bar<span "
      "class=\"html-tag\">&lt;/a&gt;</span><span "
      "class=\"html-tag\">&lt;br&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"5\"></td><td class=\"line-content\">      "
      "<span class=\"html-tag\">&lt;a <span "
      "class=\"html-attribute-name\">href</span>=\"<a "
      "class=\"html-attribute-value html-external-link\" target=\"_blank\" "
      "href=\"/bar\" rel=\"noreferrer "
      "noopener\">/bar</a>\"&gt;</span>http://example.org/bar<span "
      "class=\"html-tag\">&lt;/a&gt;</span><span "
      "class=\"html-tag\">&lt;br&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"6\"></td><td class=\"line-content\">      "
      "<span class=\"html-tag\">&lt;a <span "
      "class=\"html-attribute-name\">href</span>=\"<a "
      "class=\"html-attribute-value html-external-link\" target=\"_blank\" "
      "href=\"http://example.org/foobar\" rel=\"noreferrer "
      "noopener\">http://example.org/foobar</a>\"&gt;</span>http://example.org/"
      "foobar<span class=\"html-tag\">&lt;/a&gt;</span><span "
      "class=\"html-tag\">&lt;br&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"7\"></td><td class=\"line-content\">      "
      "<span class=\"html-tag\">&lt;a <span "
      "class=\"html-attribute-name\">href</span>=\"<a "
      "class=\"html-attribute-value html-external-link\" target=\"_blank\" "
      "href=\"bar?a&amp;b\" rel=\"noreferrer "
      "noopener\">bar?a&amp;amp;b</a>\"&gt;</span>http://example.org/foo/"
      "bar?a&amp;b<span class=\"html-tag\">&lt;/a&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"8\"></td><td class=\"line-content\">      "
      "<span class=\"html-tag\">&lt;/body&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"9\"></td><td class=\"line-content\">  "
      "<span "
      "class=\"html-end-of-file\"></span></td></tr></tbody></table></body></"
      "html>");
}

TEST_F(HTMLViewSourceDocumentTest, ViewSource4) {
  LoadMainResource(R"HTML(
      <HEAD><BASE HREF="http://example.org/foo/"></HEAD>
      <BODY>
      <A HREF="bar">http://example.org/foo/bar</A><BR>
      <A HREF="/bar">http://example.org/bar</A><BR>
      <A HREF="http://example.org/foobar">http://example.org/foobar</A><BR>
      <A HREF="bar?a&amp;b">http://example.org/foo/bar?a&b</A>
      </BODY>
  )HTML");
  EXPECT_EQ(
      GetDocument().documentElement()->outerHTML(),
      "<html><head><meta name=\"color-scheme\" content=\"light "
      "dark\"></head><body><div class=\"line-gutter-backdrop\"></div><form "
      "autocomplete=\"off\"><label class=\"line-wrap-control\">"
      "<input type=\"checkbox\"></label>"
      "</form><table><tbody><tr><td class=\"line-number\" value=\"1\"></td><td "
      "class=\"line-content\"><br></td></tr><tr><td class=\"line-number\" "
      "value=\"2\"></td><td class=\"line-content\">      <span "
      "class=\"html-tag\">&lt;HEAD&gt;</span><span class=\"html-tag\">&lt;BASE "
      "<span class=\"html-attribute-name\">HREF</span><base "
      "href=\"http://example.org/foo/\">=\"<a class=\"html-attribute-value "
      "html-resource-link\" target=\"_blank\" href=\"http://example.org/foo/\" "
      "rel=\"noreferrer "
      "noopener\">http://example.org/foo/</a>\"&gt;</span><span "
      "class=\"html-tag\">&lt;/HEAD&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"3\"></td><td class=\"line-content\">      "
      "<span class=\"html-tag\">&lt;BODY&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"4\"></td><td class=\"line-content\">      "
      "<span class=\"html-tag\">&lt;A <span "
      "class=\"html-attribute-name\">HREF</span>=\"<a "
      "class=\"html-attribute-value html-external-link\" target=\"_blank\" "
      "href=\"bar\" rel=\"noreferrer "
      "noopener\">bar</a>\"&gt;</span>http://example.org/foo/bar<span "
      "class=\"html-tag\">&lt;/A&gt;</span><span "
      "class=\"html-tag\">&lt;BR&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"5\"></td><td class=\"line-content\">      "
      "<span class=\"html-tag\">&lt;A <span "
      "class=\"html-attribute-name\">HREF</span>=\"<a "
      "class=\"html-attribute-value html-external-link\" target=\"_blank\" "
      "href=\"/bar\" rel=\"noreferrer "
      "noopener\">/bar</a>\"&gt;</span>http://example.org/bar<span "
      "class=\"html-tag\">&lt;/A&gt;</span><span "
      "class=\"html-tag\">&lt;BR&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"6\"></td><td class=\"line-content\">      "
      "<span class=\"html-tag\">&lt;A <span "
      "class=\"html-attribute-name\">HREF</span>=\"<a "
      "class=\"html-attribute-value html-external-link\" target=\"_blank\" "
      "href=\"http://example.org/foobar\" rel=\"noreferrer "
      "noopener\">http://example.org/foobar</a>\"&gt;</span>http://example.org/"
      "foobar<span class=\"html-tag\">&lt;/A&gt;</span><span "
      "class=\"html-tag\">&lt;BR&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"7\"></td><td class=\"line-content\">      "
      "<span class=\"html-tag\">&lt;A <span "
      "class=\"html-attribute-name\">HREF</span>=\"<a "
      "class=\"html-attribute-value html-external-link\" target=\"_blank\" "
      "href=\"bar?a&amp;b\" rel=\"noreferrer "
      "noopener\">bar?a&amp;amp;b</a>\"&gt;</span>http://example.org/foo/"
      "bar?a&amp;b<span class=\"html-tag\">&lt;/A&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"8\"></td><td class=\"line-content\">      "
      "<span class=\"html-tag\">&lt;/BODY&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"9\"></td><td class=\"line-content\">  "
      "<span "
      "class=\"html-end-of-file\"></span></td></tr></tbody></table></body></"
      "html>");
}

TEST_F(HTMLViewSourceDocumentTest, ViewSource5) {
  LoadMainResource(R"HTML(


      <p>

      <input


      type="text">
      </p>

  )HTML");
  EXPECT_EQ(
      GetDocument().documentElement()->outerHTML(),
      "<html><head><meta name=\"color-scheme\" content=\"light "
      "dark\"></head><body><div class=\"line-gutter-backdrop\"></div><form "
      "autocomplete=\"off\"><label class=\"line-wrap-control\">"
      "<input type=\"checkbox\"></label>"
      "</form><table><tbody><tr><td class=\"line-number\" value=\"1\"></td><td "
      "class=\"line-content\"><br></td></tr><tr><td class=\"line-number\" "
      "value=\"2\"></td><td class=\"line-content\"><br></td></tr><tr><td "
      "class=\"line-number\" value=\"3\"></td><td "
      "class=\"line-content\"><br></td></tr><tr><td class=\"line-number\" "
      "value=\"4\"></td><td class=\"line-content\">      <span "
      "class=\"html-tag\">&lt;p&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"5\"></td><td "
      "class=\"line-content\"><br></td></tr><tr><td class=\"line-number\" "
      "value=\"6\"></td><td class=\"line-content\">      <span "
      "class=\"html-tag\">&lt;input</span></td></tr><tr><td "
      "class=\"line-number\" value=\"7\"></td><td "
      "class=\"line-content\"><br></td></tr><tr><td class=\"line-number\" "
      "value=\"8\"></td><td class=\"line-content\"><br></td></tr><tr><td "
      "class=\"line-number\" value=\"9\"></td><td class=\"line-content\">      "
      "<span class=\"html-attribute-name\">type</span>=\"<span "
      "class=\"html-attribute-value\">text</span>\"&gt;</td></tr><tr><td "
      "class=\"line-number\" value=\"10\"></td><td class=\"line-content\">     "
      " <span class=\"html-tag\">&lt;/p&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"11\"></td><td "
      "class=\"line-content\"><br></td></tr><tr><td class=\"line-number\" "
      "value=\"12\"></td><td class=\"line-content\">  <span "
      "class=\"html-end-of-file\"></span></td></tr></tbody></table></body></"
      "html>");
}

TEST_F(HTMLViewSourceDocumentTest, ViewSource6) {
  std::string many_spaces(32760, ' ');
  LoadMainResource((many_spaces + std::string("       <b>A</b>  ")).c_str());
  std::string expected_beginning(
      "<html><head><meta name=\"color-scheme\" content=\"light "
      "dark\"></head><body><div class=\"line-gutter-backdrop\"></div><form "
      "autocomplete=\"off\"><label class=\"line-wrap-control\">"
      "<input type=\"checkbox\"></label>"
      "</form><table><tbody><tr><td class=\"line-number\" value=\"1\">"
      "</td><td class=\"line-content\">      ");
  std::string expected_ending(
      " <span class=\"html-tag\">&lt;b&gt;</span>A<span "
      "class=\"html-tag\">&lt;/b&gt;</span>  <span "
      "class=\"html-end-of-file\"></span></td></tr></tbody></table></body></"
      "html>");
  EXPECT_EQ(GetDocument().documentElement()->outerHTML(),
            (expected_beginning + many_spaces + expected_ending).c_str());
}

TEST_F(HTMLViewSourceDocumentTest, ViewSource7) {
  LoadMainResource("1234567");
  EXPECT_EQ(
      GetDocument().documentElement()->outerHTML(),
      "<html><head><meta name=\"color-scheme\" content=\"light "
      "dark\"></head><body><div class=\"line-gutter-backdrop\"></div><form "
      "autocomplete=\"off\"><label class=\"line-wrap-control\">"
      "<input type=\"checkbox\"></label>"
      "</form><table><tbody><tr><td class=\"line-number\" value=\"1\">"
      "</td><td class=\"line-content\">1234567<span "
      "class=\"html-end-of-file\"></span></td></tr></tbody></table></"
      "body></html>");
}

TEST_F(HTMLViewSourceDocumentTest, ViewSource8) {
  LoadMainResource(R"HTML(
      <!DOCTYPE html>
      <html>
      <body>
      <img src="img.png" />
      <img srcset="img.png, img2.png" />
      <img src="img.png" srcset="img.png 1x, img2.png 2x, img3.png 3x" />
      <img srcset="img.png 480w, img2.png 640w, img3.png 1024w" />
      </body>
      </html>
  )HTML");
  EXPECT_EQ(
      GetDocument().documentElement()->outerHTML(),
      "<html><head><meta name=\"color-scheme\" content=\"light "
      "dark\"></head><body><div class=\"line-gutter-backdrop\"></div><form "
      "autocomplete=\"off\"><label class=\"line-wrap-control\">"
      "<input type=\"checkbox\"></label>"
      "</form><table><tbody><tr><td class=\"line-number\" value=\"1\"></td><td "
      "class=\"line-content\"><br></td></tr><tr><td class=\"line-number\" "
      "value=\"2\"></td><td class=\"line-content\">      <span "
      "class=\"html-doctype\">&lt;!DOCTYPE html&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"3\"></td><td class=\"line-content\">      "
      "<span class=\"html-tag\">&lt;html&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"4\"></td><td class=\"line-content\">      "
      "<span class=\"html-tag\">&lt;body&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"5\"></td><td class=\"line-content\">      "
      "<span class=\"html-tag\">&lt;img <span "
      "class=\"html-attribute-name\">src</span>=\"<a "
      "class=\"html-attribute-value html-resource-link\" target=\"_blank\" "
      "href=\"img.png\" rel=\"noreferrer noopener\">img.png</a>\" "
      "/&gt;</span></td></tr><tr><td class=\"line-number\" "
      "value=\"6\"></td><td class=\"line-content\">      <span "
      "class=\"html-tag\">&lt;img <span "
      "class=\"html-attribute-name\">srcset</span>=\"<a "
      "class=\"html-attribute-value html-resource-link\" target=\"_blank\" "
      "href=\"img.png\" rel=\"noreferrer noopener\">img.png</a>,<a "
      "class=\"html-attribute-value html-resource-link\" target=\"_blank\" "
      "href=\"img2.png\" rel=\"noreferrer noopener\"> img2.png</a>\" "
      "/&gt;</span></td></tr><tr><td class=\"line-number\" "
      "value=\"7\"></td><td class=\"line-content\">      <span "
      "class=\"html-tag\">&lt;img <span "
      "class=\"html-attribute-name\">src</span>=\"<a "
      "class=\"html-attribute-value html-resource-link\" target=\"_blank\" "
      "href=\"img.png\" rel=\"noreferrer noopener\">img.png</a>\" <span "
      "class=\"html-attribute-name\">srcset</span>=\"<a "
      "class=\"html-attribute-value html-resource-link\" target=\"_blank\" "
      "href=\"img.png\" rel=\"noreferrer noopener\">img.png 1x</a>,<a "
      "class=\"html-attribute-value html-resource-link\" target=\"_blank\" "
      "href=\"img2.png\" rel=\"noreferrer noopener\"> img2.png 2x</a>,<a "
      "class=\"html-attribute-value html-resource-link\" target=\"_blank\" "
      "href=\"img3.png\" rel=\"noreferrer noopener\"> img3.png 3x</a>\" "
      "/&gt;</span></td></tr><tr><td class=\"line-number\" "
      "value=\"8\"></td><td class=\"line-content\">      <span "
      "class=\"html-tag\">&lt;img <span "
      "class=\"html-attribute-name\">srcset</span>=\"<a "
      "class=\"html-attribute-value html-resource-link\" target=\"_blank\" "
      "href=\"img.png\" rel=\"noreferrer noopener\">img.png 480w</a>,<a "
      "class=\"html-attribute-value html-resource-link\" target=\"_blank\" "
      "href=\"img2.png\" rel=\"noreferrer noopener\"> img2.png 640w</a>,<a "
      "class=\"html-attribute-value html-resource-link\" target=\"_blank\" "
      "href=\"img3.png\" rel=\"noreferrer noopener\"> img3.png 1024w</a>\" "
      "/&gt;</span></td></tr><tr><td class=\"line-number\" "
      "value=\"9\"></td><td class=\"line-content\">      <span "
      "class=\"html-tag\">&lt;/body&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"10\"></td><td class=\"line-content\">     "
      " <span class=\"html-tag\">&lt;/html&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"11\"></td><td class=\"line-content\">  "
      "<span "
      "class=\"html-end-of-file\"></span></td></tr></tbody></table></body></"
      "html>");
}

TEST_F(HTMLViewSourceDocumentTest, ViewSource9) {
  LoadMainResource(R"HTML(
      <!DOCTYPE html>
      <head>
      <title>Test</title>
      <script type="text/javascript">
      "<!--  --!><script>";
  )HTML");
  EXPECT_EQ(
      GetDocument().documentElement()->outerHTML(),
      "<html><head><meta name=\"color-scheme\" content=\"light "
      "dark\"></head><body><div class=\"line-gutter-backdrop\"></div><form "
      "autocomplete=\"off\"><label class=\"line-wrap-control\">"
      "<input type=\"checkbox\"></label>"
      "</form><table><tbody><tr><td class=\"line-number\" value=\"1\"></td><td "
      "class=\"line-content\"><br></td></tr><tr><td class=\"line-number\" "
      "value=\"2\"></td><td class=\"line-content\">      <span "
      "class=\"html-doctype\">&lt;!DOCTYPE html&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"3\"></td><td class=\"line-content\">      "
      "<span class=\"html-tag\">&lt;head&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"4\"></td><td class=\"line-content\">      "
      "<span class=\"html-tag\">&lt;title&gt;</span>Test<span "
      "class=\"html-tag\">&lt;/title&gt;</span></td></tr><tr><td "
      "class=\"line-number\" value=\"5\"></td><td class=\"line-content\">      "
      "<span class=\"html-tag\">&lt;script <span "
      "class=\"html-attribute-name\">type</span>=\"<span "
      "class=\"html-attribute-value\">text/javascript</span>\"&gt;</span></"
      "td></tr><tr><td class=\"line-number\" value=\"6\"></td><td "
      "class=\"line-content\">      \"&lt;!--  "
      "--!&gt;&lt;script&gt;\";</td></tr><tr><td class=\"line-number\" "
      "value=\"7\"></td><td class=\"line-content\">  <span "
      "class=\"html-end-of-file\"></span></td></tr></tbody></table></body></"
      "html>");
}

TEST_F(HTMLViewSourceDocumentTest, IncompleteToken) {
  LoadMainResource(R"HTML(
      Incomplete token test
      text <h1 there! This text will never make it into a token.
      But it should be in view-source.
  )HTML");
  EXPECT_EQ(
      GetDocument().documentElement()->outerHTML(),
      "<html><head><meta name=\"color-scheme\" content=\"light "
      "dark\"></head><body><div class=\"line-gutter-backdrop\"></div><form "
      "autocomplete=\"off\"><label class=\"line-wrap-control\">"
      "<input type=\"checkbox\"></label>"
      "</form><table><tbody><tr><td class=\"line-number\" value=\"1\"></td><td "
      "class=\"line-content\"><br></td></tr><tr><td class=\"line-number\" "
      "value=\"2\"></td><td class=\"line-content\">      Incomplete token "
      "test</td></tr><tr><td class=\"line-number\" value=\"3\"></td><td "
      "class=\"line-content\">      text <span "
      "class=\"html-end-of-file\">&lt;h1 there! This text will never make it "
      "into a token.</span></td></tr><tr><td class=\"line-number\" "
      "value=\"4\"></td><td class=\"line-content\"><span "
      "class=\"html-end-of-file\">      But it should be in "
      "view-source.</span></td></tr><tr><td class=\"line-number\" "
      "value=\"5\"></td><td class=\"line-content\"><span "
      "class=\"html-end-of-file\">  "
      "</span></td></tr></tbody></table></body></html>");
}

TEST_F(HTMLViewSourceDocumentTest, UnfinishedTextarea) {
  LoadMainResource(R"HTML(<textarea>foobar in textarea
  )HTML");
  EXPECT_EQ(
      GetDocument().documentElement()->outerHTML(),
      "<html><head><meta name=\"color-scheme\" content=\"light "
      "dark\"></head><body><div class=\"line-gutter-backdrop\"></div><form "
      "autocomplete=\"off\"><label class=\"line-wrap-control\">"
      "<input type=\"checkbox\"></label>"
      "</form><table><tbody><tr><td class=\"line-number\" value=\"1\"></td>"
      "<td class=\"line-content\"><span "
      "class=\"html-tag\">&lt;textarea&gt;</span>foobar in "
      "textarea</td></tr><tr><td class=\"line-number\" value=\"2\"></td><td "
      "class=\"line-content\">  <span "
      "class=\"html-end-of-file\"></span></td></tr></tbody></table></body></"
      "html>");
}

TEST_F(HTMLViewSourceDocumentTest, UnfinishedScript) {
  LoadMainResource(R"HTML(<script>foobar in script
  )HTML");
  EXPECT_EQ(
      GetDocument().documentElement()->outerHTML(),
      "<html><head><meta name=\"color-scheme\" content=\"light "
      "dark\"></head><body><div class=\"line-gutter-backdrop\"></div><form "
      "autocomplete=\"off\"><label class=\"line-wrap-control\">"
      "<input type=\"checkbox\"></label>"
      "</form><table><tbody><tr><td class=\"line-number\" value=\"1\"></td>"
      "<td class=\"line-content\"><span "
      "class=\"html-tag\">&lt;script&gt;</span>foobar in "
      "script</td></tr><tr><td class=\"line-number\" value=\"2\"></td><td "
      "class=\"line-content\">  <span "
      "class=\"html-end-of-file\"></span></td></tr></tbody></table></body></"
      "html>");
}

TEST_F(HTMLViewSourceDocumentTest, Linebreak) {
  LoadMainResource("<html>\nR\n\rN\n\nNR\n\n\rRN\n\r\n</html>");
  EXPECT_EQ(
      GetDocument().documentElement()->outerHTML(),
      "<html><head><meta name=\"color-scheme\" content=\"light dark\"></head>"
      "<body><div class=\"line-gutter-backdrop\"></div>"
      "<form autocomplete=\"off\"><label class=\"line-wrap-control\">"
      "<input type=\"checkbox\"></label></form>"
      "<table><tbody>"
      "<tr><td class=\"line-number\" value=\"1\"></td>"
      "<td class=\"line-content\">"
      "<span class=\"html-tag\">&lt;html&gt;</span></td></tr>"
      "<tr><td class=\"line-number\" value=\"2\"></td>"
      "<td class=\"line-content\">R</td></tr>"  // \r -> 1 linebreak
      "<tr><td class=\"line-number\" value=\"3\"></td>"
      "<td class=\"line-content\"><br></td></tr>"
      "<tr><td class=\"line-number\" value=\"4\"></td>"
      "<td class=\"line-content\">N</td></tr>"  // \n -> 1 linebraek
      "<tr><td class=\"line-number\" value=\"5\"></td>"
      "<td class=\"line-content\"><br></td></tr><tr>"
      "<td class=\"line-number\" value=\"6\"></td>"
      "<td class=\"line-content\">NR</td></tr>"  // \n\r -> 2 linebreaks
      "<tr><td class=\"line-number\" value=\"7\"></td>"
      "<td class=\"line-content\"><br></td></tr>"
      "<tr><td class=\"line-number\" value=\"8\"></td>"
      "<td class=\"line-content\"><br></td></tr>"
      "<tr><td class=\"line-number\" value=\"9\"></td>"
      "<td class=\"line-content\">RN</td></tr>"  // \r\n -> 1 linebreak
      "<tr><td class=\"line-number\" value=\"10\"></td>"
      "<td class=\"line-content\"><br></td></tr>"
      "<tr><td class=\"line-number\" value=\"11\"></td>"
      "<td class=\"line-content\">"
      "<span class=\"html-tag\">&lt;/html&gt;</span>"
      "<span class=\"html-end-of-file\"></span>"
      "</td></tr></tbody></table></body></html>");
}

TEST_F(HTMLViewSourceDocumentTest, DOMParts) {
  LoadMainResource(
      R"HTML(<div parseparts>{{#}}foo{{/}}<span {{}}>bar</span></div>)HTML");
  EXPECT_EQ(
      GetDocument().documentElement()->outerHTML(),
      "<html><head><meta name=\"color-scheme\" content=\"light "
      "dark\"></head><body><div class=\"line-gutter-backdrop\"></div><form "
      "autocomplete=\"off\"><label class=\"line-wrap-control\"><input "
      "type=\"checkbox\"></label></form><table><tbody><tr><td "
      "class=\"line-number\" value=\"1\"></td><td class=\"line-content\"><span "
      "class=\"html-tag\">&lt;div <span "
      "class=\"html-attribute-name\">parseparts</span>&gt;</span>{{#}}foo{{/"
      "}}<span class=\"html-tag\">&lt;span <span "
      "class=\"html-attribute-name\">{{}}</span>&gt;</span>bar<span "
      "class=\"html-tag\">&lt;/span&gt;</span><span "
      "class=\"html-tag\">&lt;/div&gt;</span><span "
      "class=\"html-end-of-file\"></span></td></tr></tbody></table></body></"
      "html>");
}

}  // namespace blink

"""

```