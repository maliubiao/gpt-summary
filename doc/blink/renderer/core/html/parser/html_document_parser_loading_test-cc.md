Response:
Let's break down the request and the provided code.

**1. Understanding the Goal:**

The request asks for an analysis of the `html_document_parser_loading_test.cc` file in the Chromium Blink engine. The key is to identify its purpose, its relationship to web technologies (HTML, CSS, JavaScript), illustrate logical reasoning with examples, and point out common usage errors.

**2. Initial Code Scan and Keyword Identification:**

I immediately scanned the code for relevant keywords and patterns:

* **`TEST_P` and `INSTANTIATE_TEST_SUITE_P`:**  This clearly indicates a Google Test-based test suite. The `_P` suffix suggests parameterized tests.
* **`HTMLDocumentParserLoadingTest`:**  The class name itself strongly suggests the file's purpose is to test the loading behavior of the HTML document parser.
* **`SimTest`, `SimRequest`, `SimSubresourceRequest`:**  These point to a simulation environment for testing network requests and responses.
* **`Document::SetForceSynchronousParsingForTesting`:** This hints at testing different parser synchronization modes.
* **`platform_->RunUntilIdle()`:**  This is a common pattern in asynchronous testing, allowing the simulated environment to process pending tasks.
* **`<link rel=stylesheet ...>`:**  This clearly relates to CSS loading.
* **`<script src="...">` and `<script>...</script>`:** These are obviously related to JavaScript execution.
* **`document.write(...)`:**  A JavaScript method used to modify the document during parsing.
* **`document.getElementById(...)`:** A JavaScript method to access elements.
* **`defer` attribute on `<script>`:**  Indicates deferred JavaScript execution.
* **`onload` attribute on `<iframe>`:**  JavaScript event handler.
* **`@import` in `<style>`:**  CSS import rule.

**3. Deeper Analysis of Individual Tests:**

I then examined each test case individually, focusing on its specific setup, actions, and assertions:

* **`PrefetchedDeferScriptDoesNotDeadlockParser`:**  This test seems designed to check for a specific deadlock scenario involving prefetched deferred scripts and parser-blocking scripts. The complex setup with `kPumpSize` and the manual chunking of the HTML strongly suggests a focus on the parser's incremental processing.
* **`IFrameDoesNotRenterParser`:** This test is simpler and aims to verify that processing an `<iframe>` doesn't cause re-entry into the main document's parser in a problematic way.
* **`ShouldPauseParsingForExternalStylesheetsInBody`:** This test verifies that the HTML parser pauses when it encounters an external stylesheet linked in the `<body>`.
* **`ShouldPauseParsingForExternalStylesheetsInBodyIncremental`:** This is a variation of the previous test, focusing on how the parser handles multiple stylesheets loaded incrementally.
* **`ShouldNotPauseParsingForExternalNonMatchingStylesheetsInBody`:** This confirms that stylesheets with a `type` attribute that doesn't match the content type (e.g., `type='print'`) don't block parsing.
* **`ShouldPauseParsingForExternalStylesheetsImportedInBody`:** This checks the pausing behavior for CSS stylesheets imported using the `@import` rule within a `<style>` tag.
* **`ShouldPauseParsingForExternalStylesheetsWrittenInBody`:** This test verifies that dynamically adding a stylesheet using `document.write()` also causes the parser to pause.
* **`ShouldNotPauseParsingForExternalStylesheetsAttachedInBody`:** This confirms that dynamically creating and attaching a stylesheet using JavaScript (without `document.write`) doesn't block the parser.

**4. Identifying Relationships to Web Technologies:**

Based on the analysis of the tests, the relationships to HTML, CSS, and JavaScript became clear:

* **HTML:** The tests heavily manipulate HTML structure using strings and verify the presence of elements created by the parser.
* **CSS:** Several tests explicitly focus on how the parser handles `<link rel="stylesheet">` tags, including external stylesheets and those added dynamically. The `@import` rule is also tested.
* **JavaScript:** The tests involve executing JavaScript code within `<script>` tags, including inline scripts, external scripts (normal and deferred), and the use of `document.write()` and DOM manipulation.

**5. Constructing Examples and Reasoning:**

For each identified relationship, I aimed to create simple, illustrative examples that demonstrate the tested behavior. The key was to show the input HTML/CSS/JS and the expected output (or observed behavior). I also focused on explaining *why* the parser behaves in a certain way.

**6. Identifying Potential User/Programming Errors:**

By understanding the parser's behavior, I could identify common mistakes developers might make, such as:

* **Unexpected parsing pauses:**  Not realizing that stylesheets in the `<body>` block rendering.
* **Deadlocks with deferred scripts:** The specific scenario the `PrefetchedDeferScriptDoesNotDeadlockParser` test addresses.
* **Misunderstanding `document.write()`:**  Its impact on parsing and rendering.
* **Incorrectly assuming asynchronous behavior:** Thinking that all dynamically added resources are non-blocking.

**7. Structuring the Output:**

Finally, I organized the information in a clear and structured way, addressing each part of the original request:

* **Functionality:** A high-level summary of the file's purpose.
* **Relationship to HTML, CSS, JavaScript:**  Detailed explanations with concrete examples.
* **Logical Reasoning:** Hypothetical input/output scenarios for key test cases.
* **Common Errors:** Examples of mistakes developers might make.

Essentially, my thought process involved:

1. **Decomposition:** Breaking down the code and the request into smaller, manageable parts.
2. **Pattern Recognition:** Identifying familiar testing patterns and web technology concepts.
3. **Inferential Reasoning:**  Deducing the purpose of each test case based on its code.
4. **Generalization:**  Extrapolating the tested behaviors to broader principles of HTML parsing and resource loading.
5. **Exemplification:** Creating concrete examples to illustrate the concepts.
6. **Synthesis:**  Combining all the findings into a comprehensive explanation.
这个文件 `html_document_parser_loading_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用于测试 **HTML 文档解析器在加载过程中的行为**。更具体地说，它测试了在文档加载和解析的不同阶段，解析器如何处理各种资源（如脚本和样式表），以及如何与这些资源的加载和执行进行同步。

以下是它的主要功能和与 HTML、CSS、JavaScript 关系的一些说明和示例：

**核心功能:**

1. **测试 HTML 解析器的加载和解析流程:**  该文件模拟各种 HTML 结构和资源加载场景，以验证 HTML 文档解析器在接收到 HTML 数据流时的正确行为。
2. **测试解析器对外部资源的处理:**  它测试了解析器如何处理外部 JavaScript 文件（通过 `<script src="...">` 引入）和外部 CSS 样式表文件（通过 `<link rel="stylesheet" href="...">` 引入）。
3. **测试解析器在遇到阻塞资源时的暂停和恢复机制:**  当解析器遇到需要加载和执行的脚本或样式表时，它可能会暂停解析，等待资源加载完成。该文件测试了这种暂停和恢复机制的正确性。
4. **测试不同解析同步策略的影响:**  通过 `ParserSynchronizationPolicy` 参数化测试，它可以测试在强制同步解析和允许延迟解析的情况下，解析器的行为差异。
5. **测试 `document.write()` 的影响:**  `document.write()` 可以在文档解析过程中动态插入内容，该文件测试了解析器如何处理这种情况。
6. **测试 `defer` 和 `async` 属性对脚本加载和执行的影响:** 虽然这个文件中没有直接涉及 `async`，但它测试了 `defer` 属性脚本的行为，即在文档解析完成后执行。
7. **防止特定类型的死锁和崩溃:**  一些测试用例是为了重现和防止之前发现的解析器死锁或崩溃问题（例如 `PrefetchedDeferScriptDoesNotDeadlockParser`）。

**与 JavaScript, HTML, CSS 的关系和举例说明:**

* **HTML:**
    * **功能关系:**  该文件直接测试 HTML 文档解析器的行为，其输入是各种 HTML 字符串片段。
    * **举例说明:**
        * 测试用例会构建包含不同 HTML 元素的字符串，例如 `<div>`, `<script>`, `<link>`, `<iframe>` 等。
        * 它会检查解析器是否正确地创建了这些 HTML 元素，例如通过 `GetDocument().getElementById(AtomicString("..."))` 来验证特定 ID 的元素是否被创建。
        * 例如，`ShouldPauseParsingForExternalStylesheetsInBody` 测试会插入 `<div id="before">` 和 `<div id="after">`，并验证在加载样式表的过程中，`before` 元素存在，而 `after` 元素可能不存在，以此来验证解析器的暂停行为。

* **JavaScript:**
    * **功能关系:**  该文件测试了解析器如何处理 JavaScript 代码的加载和执行，以及 JavaScript 代码对 DOM 的影响。
    * **举例说明:**
        * **阻塞脚本:**  `PrefetchedDeferScriptDoesNotDeadlockParser` 测试中使用了 `<script src="sync-script.js"></script>`，这是一个同步脚本，会阻塞解析器的解析。测试验证了解析器在遇到这种脚本时的行为。
        * **延迟脚本 (`defer`):** `PrefetchedDeferScriptDoesNotDeadlockParser` 测试了带有 `defer` 属性的脚本 `<script src="deferred-script.js" defer></script>`。测试验证了这种脚本会在文档解析完成后执行。
        * **`document.write()`:** `ShouldPauseParsingForExternalStylesheetsWrittenInBody` 测试使用了 `document.write('<link rel=stylesheet href=testBody.css>');`，测试了解析器在遇到 `document.write()` 动态插入阻塞资源时的行为。
        * **DOM 操作:**  测试用例中的 JavaScript 代码会操作 DOM，例如 `document.getElementById("internalDiv").innerHTML = "<div id='worldDiv'>hi</div>";`，测试会验证这些操作的结果。

* **CSS:**
    * **功能关系:** 该文件测试了解析器如何处理 CSS 样式表的加载，以及样式表加载对解析流程的影响。
    * **举例说明:**
        * **外部样式表:** `ShouldPauseParsingForExternalStylesheetsInBody` 和 `ShouldPauseParsingForExternalStylesheetsInBodyIncremental` 测试使用 `<link rel=stylesheet href=testBody.css>` 来引入外部样式表。测试验证了解析器在遇到这种标签时的暂停行为。
        * **`@import` 规则:** `ShouldPauseParsingForExternalStylesheetsImportedInBody` 测试使用了 `<style> @import 'testBody.css' </style>`，测试了解析器如何处理通过 `@import` 引入的样式表。
        * **非阻塞样式表:** `ShouldNotPauseParsingForExternalNonMatchingStylesheetsInBody` 测试使用了 `<link rel=stylesheet href=testBody.css type='print'>`，测试了当样式表的 `type` 属性不匹配时，解析器是否会暂停。

**逻辑推理的假设输入与输出:**

以 `ShouldPauseParsingForExternalStylesheetsInBody` 测试为例：

* **假设输入:**
    ```html
    <!DOCTYPE html>
    <html><head>
    <link rel=stylesheet href=testHead.css>
    </head><body>
    <div id="before"></div>
    <link rel=stylesheet href=testBody.css>
    <div id="after"></div>
    </body></html>
    ```
* **假设输出:**
    * 在 `testHead.css` 加载完成前，`GetDocument().getElementById(AtomicString("before"))` 返回 `true`。
    * 在 `testBody.css` 加载完成前，`GetDocument().getElementById(AtomicString("after"))` 返回 `false`。
    * 在 `testBody.css` 加载完成后，`GetDocument().getElementById(AtomicString("after"))` 返回 `true`。

**用户或编程常见的使用错误举例说明:**

1. **在 `<body>` 中引入阻塞的外部样式表，导致页面渲染延迟:**
   * **错误代码示例:**
     ```html
     <!DOCTYPE html>
     <html>
     <head>
       <title>My Page</title>
     </head>
     <body>
       <p>Some content before the stylesheet.</p>
       <link rel="stylesheet" href="very-large-style.css">
       <p>Some content after the stylesheet.</p>
     </body>
     </html>
     ```
   * **说明:**  在这个例子中，`very-large-style.css` 如果加载时间很长，会导致 "Some content after the stylesheet." 的渲染被延迟，用户会看到一个空白或样式错乱的页面，直到样式表加载完成。

2. **误解 `document.write()` 的行为，在异步加载的脚本中使用 `document.write()` 导致内容丢失或渲染异常:**
   * **错误代码示例:**
     ```html
     <!DOCTYPE html>
     <html>
     <head>
       <title>My Page</title>
     </head>
     <body>
       <div id="container">Initial Content</div>
       <script async src="async-script.js"></script>
     </body>
     </html>
     ```
     ```javascript
     // async-script.js
     document.write("<p>Content written by async script.</p>");
     ```
   * **说明:**  由于 `async` 脚本是异步加载和执行的，当 `async-script.js` 执行 `document.write()` 时，文档的解析可能已经完成。这会导致 `document.write()` 清空现有文档并写入新的内容，从而导致 "Initial Content" 丢失。

3. **不理解 `defer` 脚本的执行顺序，依赖于 `defer` 脚本的特定执行顺序，但实际顺序不符合预期:**
   * **错误代码示例:**
     ```html
     <!DOCTYPE html>
     <html>
     <head>
       <title>My Page</title>
       <script defer src="script1.js"></script>
       <script defer src="script2.js"></script>
     </head>
     <body>
       <div id="output"></div>
     </body>
     </html>
     ```
     ```javascript
     // script1.js
     window.data = "Data from script1";
     ```
     ```javascript
     // script2.js
     document.getElementById('output').innerText = window.data; // 假设依赖 script1.js 先执行
     ```
   * **说明:**  `defer` 脚本会按照它们在 HTML 中出现的顺序执行。但是，如果 `script2.js` 的执行依赖于 `script1.js` 中定义的全局变量 `window.data`，并且由于网络延迟等原因 `script2.js` 比 `script1.js` 更早加载完成，那么可能会出现 `window.data` 未定义的情况。

总而言之，`html_document_parser_loading_test.cc` 是一个关键的测试文件，用于确保 Blink 引擎的 HTML 文档解析器在各种加载场景下都能正确地工作，并且与 JavaScript 和 CSS 的交互符合预期，从而保证了网页的正确渲染和功能。

Prompt: 
```
这是目录为blink/renderer/core/html/parser/html_document_parser_loading_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/html/parser/html_document_parser.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support_with_mock_scheduler.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

class HTMLDocumentParserLoadingTest
    : public SimTest,
      public testing::WithParamInterface<ParserSynchronizationPolicy> {
 protected:
  HTMLDocumentParserLoadingTest() {
    Document::SetForceSynchronousParsingForTesting(GetParam() ==
                                                   kForceSynchronousParsing);
    platform_->SetAutoAdvanceNowToPendingTasks(false);
  }
  ScopedTestingPlatformSupport<TestingPlatformSupportWithMockScheduler>
      platform_;
};

INSTANTIATE_TEST_SUITE_P(HTMLDocumentParserLoadingTest,
                         HTMLDocumentParserLoadingTest,
                         testing::Values(kAllowDeferredParsing,
                                         kForceSynchronousParsing));

TEST_P(HTMLDocumentParserLoadingTest,
       PrefetchedDeferScriptDoesNotDeadlockParser) {
  // Maximum size string chunk to feed to the parser.
  constexpr unsigned kPumpSize = 2048;
  // <div>hello</div> is conveniently 16 chars in length.
  constexpr int kInitialDivCount = 1.5 * kPumpSize / 16;

  SimRequest::Params params;
  params.response_http_status = 200;

  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimRequest deferred_js("https://example.com/deferred-script.js",
                         "application/javascript", params);
  SimRequest sync_js("https://example.com/sync-script.js",
                     "application/javascript", params);
  LoadURL("https://example.com/test.html");
  // Building a big HTML document that the parser cannot handle in one go.
  // The idea is that we do
  //       PumpTokenizer PumpTokenizer  Insert PumpTokenizer PumpTokenizer ...
  // But _without_ calling Append, to replicate the deadlock situation
  // encountered in crbug.com/1132508. First, build some problematic input in a
  // StringBuilder.
  WTF::StringBuilder sb;
  sb.Append("<html>");
  sb.Append(R"HTML(
    <head>
        <meta charset="utf-8">
        <!-- Preload deferred-script.js so that a Client ends up backing
             the deferred_js SimRequest. -->
        <link rel="preload" href="deferred-script.js" as="script">
    </head><body>
  )HTML");
  for (int i = 0; i < kInitialDivCount; i++) {
    // Add a large blob of HTML to the parser to give it something to work with.
    // Must cross the first and second Append calls.
    sb.Append("<div>hello</div>");
  }
  // Next inject a synchronous, parser-blocking script and a div
  // for the defer script to work with.
  sb.Append(R"HTML(
    <script src="sync-script.js"></script>
    <div id="internalDiv"></div>
  )HTML");
  unsigned script_end = sb.length();
  for (int i = 0; i < kInitialDivCount; i++) {
    // Stress the parser more by requiring nested tokenization pumps.
    sb.Append("<script>document.write('hello');</script>");
  }
  // At the end of the document, add the deferred script.
  // When this runs, it'll add a worldDiv into the internalDiv created above.
  sb.Append(R"HTML(
    <script src="deferred-script.js" defer></script>
  )HTML");
  // Next, chop up the StringBuilder into realistic chunks.
  String s = sb.ToString();
  int testing_phase = 0;
  ASSERT_GT(s.length(), 1u);
  for (unsigned i = 0; i < s.length(); i += kPumpSize) {
    unsigned extent = kPumpSize - 1;
    if (i + extent > (s.length()) - 1) {
      extent = s.length() - 1 - i;
      ASSERT_LT(extent, kPumpSize);
    }
    String chunk(s.Span8().subspan(i, extent));
    main_resource.Write(chunk);
    if (i >= script_end) {
      // Simulate the deferred script arriving before the parser-blocking one.
      if (testing_phase == 1) {
        deferred_js.Complete(R"JS(
            document.getElementById("internalDiv").innerHTML = "<div id='worldDiv'>hi</div>";
          )JS");
      }
      testing_phase++;
      platform_->RunUntilIdle();
    }
  }
  // Everything's now Append()'d. Complete the main resource.
  ASSERT_GT(testing_phase, 2);
  main_resource.Complete();
  platform_->RunUntilIdle();  // Parse up until the parser blocking script.
  // Complete the parser blocking script.
  sync_js.Complete(R"JS(
    document.write("<div id='helloDiv'></div>");
  )JS");
  // Resume execution up until the parser-blocking script at the end.
  platform_->RunUntilIdle();
  // Expect both the element generated by the parser blocking script
  // and the element created by the deferred script to be present.
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("helloDiv")));
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("worldDiv")));
}

TEST_P(HTMLDocumentParserLoadingTest, IFrameDoesNotRenterParser) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimRequest::Params params;
  params.response_http_status = 200;
  SimSubresourceRequest js("https://example.com/non-existent.js",
                           "application/javascript", params);
  LoadURL("https://example.com/test.html");
  main_resource.Complete(R"HTML(
<script src="non-existent.js"></script>
<iframe onload="document.write('This test passes if it does not crash'); document.close();"></iframe>
  )HTML");
  platform_->RunUntilIdle();
  js.Complete("");
  platform_->RunUntilIdle();
}

TEST_P(HTMLDocumentParserLoadingTest,
       ShouldPauseParsingForExternalStylesheetsInBody) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimSubresourceRequest css_head_resource("https://example.com/testHead.css",
                                          "text/css");
  SimSubresourceRequest css_body_resource("https://example.com/testBody.css",
                                          "text/css");

  LoadURL("https://example.com/test.html");

  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <html><head>
    <link rel=stylesheet href=testHead.css>
    </head><body>
    <div id="before"></div>
    <link rel=stylesheet href=testBody.css>
    <div id="after"></div>
    </body></html>
  )HTML");

  platform_->RunUntilIdle();
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("before")));
  EXPECT_FALSE(GetDocument().getElementById(AtomicString("after")));

  // Completing the head css should progress parsing past #before.
  css_head_resource.Complete("");
  platform_->RunUntilIdle();
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("before")));
  EXPECT_FALSE(GetDocument().getElementById(AtomicString("after")));

  // Completing the body resource and pumping the tasks should continue parsing
  // and create the "after" div.
  css_body_resource.Complete("");
  platform_->RunUntilIdle();
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("before")));
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("after")));
}

TEST_P(HTMLDocumentParserLoadingTest,
       ShouldPauseParsingForExternalStylesheetsInBodyIncremental) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimSubresourceRequest css_head_resource("https://example.com/testHead.css",
                                          "text/css");
  SimSubresourceRequest css_body_resource1("https://example.com/testBody1.css",
                                           "text/css");
  SimSubresourceRequest css_body_resource2("https://example.com/testBody2.css",
                                           "text/css");
  SimSubresourceRequest css_body_resource3("https://example.com/testBody3.css",
                                           "text/css");

  LoadURL("https://example.com/test.html");

  main_resource.Write(R"HTML(
    <!DOCTYPE html>
    <html><head>
    <link rel=stylesheet href=testHead.css>
    </head><body>
    <div id="before"></div>
    <link rel=stylesheet href=testBody1.css>
    <div id="after1"></div>
  )HTML");

  platform_->RunUntilIdle();
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("before")));
  EXPECT_FALSE(GetDocument().getElementById(AtomicString("after1")));
  EXPECT_FALSE(GetDocument().getElementById(AtomicString("after2")));
  EXPECT_FALSE(GetDocument().getElementById(AtomicString("after3")));

  main_resource.Write(
      "<link rel=stylesheet href=testBody2.css>"
      "<div id=\"after2\"></div>");

  platform_->RunUntilIdle();
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("before")));
  EXPECT_FALSE(GetDocument().getElementById(AtomicString("after1")));
  EXPECT_FALSE(GetDocument().getElementById(AtomicString("after2")));
  EXPECT_FALSE(GetDocument().getElementById(AtomicString("after3")));

  main_resource.Complete(R"HTML(
    <link rel=stylesheet href=testBody3.css>
    <div id="after3"></div>
    </body></html>
  )HTML");

  platform_->RunUntilIdle();
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("before")));
  EXPECT_FALSE(GetDocument().getElementById(AtomicString("after1")));
  EXPECT_FALSE(GetDocument().getElementById(AtomicString("after2")));
  EXPECT_FALSE(GetDocument().getElementById(AtomicString("after3")));

  // Completing the head css shouldn't change anything.
  css_head_resource.Complete("");
  platform_->RunUntilIdle();
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("before")));
  EXPECT_FALSE(GetDocument().getElementById(AtomicString("after1")));
  EXPECT_FALSE(GetDocument().getElementById(AtomicString("after2")));
  EXPECT_FALSE(GetDocument().getElementById(AtomicString("after3")));

  // Completing the second css shouldn't change anything
  css_body_resource2.Complete("");
  platform_->RunUntilIdle();
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("before")));
  EXPECT_FALSE(GetDocument().getElementById(AtomicString("after1")));
  EXPECT_FALSE(GetDocument().getElementById(AtomicString("after2")));
  EXPECT_FALSE(GetDocument().getElementById(AtomicString("after3")));

  // Completing the first css should allow the parser to continue past it and
  // the second css which was already completed and then pause again before the
  // third css.
  css_body_resource1.Complete("");
  platform_->RunUntilIdle();
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("before")));
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("after1")));
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("after2")));
  EXPECT_FALSE(GetDocument().getElementById(AtomicString("after3")));

  // Completing the third css should let it continue to the end.
  css_body_resource3.Complete("");
  platform_->RunUntilIdle();
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("before")));
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("after1")));
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("after2")));
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("after3")));
}

TEST_P(HTMLDocumentParserLoadingTest,
       ShouldNotPauseParsingForExternalNonMatchingStylesheetsInBody) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimSubresourceRequest css_head_resource("https://example.com/testHead.css",
                                          "text/css");

  LoadURL("https://example.com/test.html");

  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <html><head>
    <link rel=stylesheet href=testHead.css>
    </head><body>
    <div id="before"></div>
    <link rel=stylesheet href=testBody.css type='print'>
    <div id="after"></div>
    </body></html>
  )HTML");

  platform_->RunUntilIdle();
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("before")));
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("after")));

  css_head_resource.Complete("");
  platform_->RunUntilIdle();
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("before")));
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("after")));
}

TEST_P(HTMLDocumentParserLoadingTest,
       ShouldPauseParsingForExternalStylesheetsImportedInBody) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimSubresourceRequest css_head_resource("https://example.com/testHead.css",
                                          "text/css");
  SimSubresourceRequest css_body_resource("https://example.com/testBody.css",
                                          "text/css");

  LoadURL("https://example.com/test.html");

  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <html><head>
    <link rel=stylesheet href=testHead.css>
    </head><body>
    <div id="before"></div>
    <style>
    @import 'testBody.css'
    </style>
    <div id="after"></div>
    </body></html>
  )HTML");

  platform_->RunUntilIdle();
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("before")));
  EXPECT_FALSE(GetDocument().getElementById(AtomicString("after")));

  // Completing the head css should progress parsing past #before.
  css_head_resource.Complete("");
  platform_->RunUntilIdle();
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("before")));
  EXPECT_FALSE(GetDocument().getElementById(AtomicString("after")));

  // Completing the body resource and pumping the tasks should continue parsing
  // and create the "after" div.
  css_body_resource.Complete("");
  platform_->RunUntilIdle();
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("before")));
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("after")));
}

TEST_P(HTMLDocumentParserLoadingTest,
       ShouldPauseParsingForExternalStylesheetsWrittenInBody) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimSubresourceRequest css_head_resource("https://example.com/testHead.css",
                                          "text/css");
  SimSubresourceRequest css_body_resource("https://example.com/testBody.css",
                                          "text/css");

  LoadURL("https://example.com/test.html");

  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <html><head>
    <link rel=stylesheet href=testHead.css>
    </head><body>
    <div id="before"></div>
    <script>
    document.write('<link rel=stylesheet href=testBody.css>');
    </script>
    <div id="after"></div>
    </body></html>
  )HTML");

  platform_->RunUntilIdle();
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("before")));
  EXPECT_FALSE(GetDocument().getElementById(AtomicString("after")));

  // Completing the head css should progress parsing past #before.
  css_head_resource.Complete("");
  platform_->RunUntilIdle();
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("before")));
  EXPECT_FALSE(GetDocument().getElementById(AtomicString("after")));

  // Completing the body resource and pumping the tasks should continue parsing
  // and create the "after" div.
  css_body_resource.Complete("");
  platform_->RunUntilIdle();
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("before")));
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("after")));
}

TEST_P(HTMLDocumentParserLoadingTest,
       ShouldNotPauseParsingForExternalStylesheetsAttachedInBody) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimSubresourceRequest css_async_resource("https://example.com/testAsync.css",
                                           "text/css");

  LoadURL("https://example.com/test.html");

  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <html><head>
    </head><body>
    <div id="before"></div>
    <script>
    var attach  = document.getElementsByTagName('script')[0];
    var link  = document.createElement('link');
    link.rel  = 'stylesheet';
    link.type = 'text/css';
    link.href = 'testAsync.css';
    link.media = 'all';
    attach.appendChild(link);
    </script>
    <div id="after"></div>
    </body></html>
  )HTML");

  platform_->RunUntilIdle();
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("before")));
  EXPECT_TRUE(GetDocument().getElementById(AtomicString("after")));

  css_async_resource.Complete("");
  platform_->RunUntilIdle();
}

}  // namespace blink

"""

```