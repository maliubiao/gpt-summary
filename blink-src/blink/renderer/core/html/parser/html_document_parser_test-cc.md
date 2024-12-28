Response:
Let's break down the thought process for analyzing the C++ test file and generating the detailed explanation.

1. **Understand the Goal:** The request asks for a functional description of the provided C++ test file (`html_document_parser_test.cc`), focusing on its relationship with HTML, JavaScript, and CSS, logical deductions, and common user/programming errors it might test.

2. **Identify the Core Class Under Test:** The file name itself (`html_document_parser_test.cc`) strongly suggests that the primary target of these tests is the `HTMLDocumentParser` class. The includes confirm this.

3. **Examine Includes:** The included headers provide valuable context:
    * `html_document_parser.h`:  Confirms the target class.
    * `html_document.h`, `html_iframe_element.h`:  Indicate that the parser deals with HTML documents and specific HTML elements like `<iframe>`.
    * `text_resource_decoder.h`, `text_resource_decoder_builder.h`: Suggest the parser handles decoding of HTML content.
    * `loader/no_state_prefetch_client.h`: Implies testing of prefetching behavior.
    * `testing/gtest/include/gtest/gtest.h`:  Confirms this is a unit test file using the Google Test framework.
    * Other includes relate to testing infrastructure and platform utilities.

4. **Analyze the Test Structure (Google Test):**  Look for key Google Test macros and patterns:
    * `namespace blink { namespace { ... } }`: Identifies the namespace.
    * Test fixtures (`class HTMLDocumentParserTest : public PageTestBase, public testing::WithParamInterface<ParserSynchronizationPolicy>`) are used to set up a common testing environment. The `WithParamInterface` indicates parameterized tests.
    * `INSTANTIATE_TEST_SUITE_P`: Shows how the parameterized tests are instantiated with different `ParserSynchronizationPolicy` values.
    * `TEST_P`:  Marks a parameterized test.
    * `TEST_F`: Marks a non-parameterized test within a fixture.
    * `EXPECT_*`:  Assertion macros used to check for expected outcomes.

5. **Deconstruct Individual Tests:** Go through each `TEST_P` or `TEST_F` function and understand its purpose:
    * **`StopThenPrepareToStopShouldNotCrash`:** Tests error handling when `StopParsing` and `PrepareToStopParsing` are called in sequence. This relates to lifecycle management of the parser.
    * **`HasNoPendingWorkAfterStopParsing`:** Checks if the parser correctly cleans up its state after stopping. This is important for preventing unexpected behavior.
    * **`HasNoPendingWorkAfterStopParsingThenAppend`:** Ensures that appending data after stopping doesn't restart the parser or leave pending work.
    * **`HasNoPendingWorkAfterDetach`:** Similar to the above, but checks the state after detaching the parser.
    * **`AppendPrefetch`:** Focuses on how the parser handles prefetch scenarios. It checks if data is correctly routed to the preload scanner and if parsing is deferred. This is relevant to optimizing page load performance.
    * **`AppendNoPrefetch`:**  Tests the normal parsing path when prefetching is not involved. It checks if the tokenizer is engaged.
    * **`TakeBackgroundScanCallback` (within `HTMLDocumentParserThreadedPreloadScannerTest`):**  Examines the threaded preload scanner functionality, verifying how inline scripts are processed in the background. This is related to optimizing script parsing.
    * **Tests within `HTMLDocumentParserProcessImmediatelyTest`:** These tests target a specific feature (`kProcessHtmlDataImmediately`) that controls whether the parser processes data in chunks immediately or defers it. They test different scenarios (first chunk, subsequent chunks, main frame, child frame). This is relevant to rendering performance and perceived page load speed.

6. **Identify Relationships with Web Technologies:**
    * **HTML:** The core function is parsing HTML. The tests directly manipulate HTML strings. Examples include testing how `<script>` tags are handled (prefetching, background scanning), how the parser recovers from incomplete tags (`<httttttt`), and how iframes are processed.
    * **JavaScript:** The tests involving the preload scanner and `HasInlineScriptStreamerForTesting` directly relate to how the parser identifies and handles JavaScript code within `<script>` tags. The `kPrecompileInlineScripts` feature flag also points to JavaScript processing.
    * **CSS:** While not explicitly tested in detail here, the presence of an HTML parser implies it will eventually encounter and handle CSS linked via `<link>` tags or embedded within `<style>` tags. The prefetch mechanism could also apply to CSS resources.

7. **Infer Logical Deductions and Assumptions:**
    * **Assumption:** The tests assume a controlled environment (`PageTestBase`, mock objects) to isolate the `HTMLDocumentParser`.
    * **Deduction:**  The tests with `ParserSynchronizationPolicy` demonstrate that the parser's behavior can change based on whether synchronous or deferred parsing is enabled.
    * **Deduction:** Tests involving prefetching show the parser distinguishes between normal loads and prefetch requests.

8. **Identify Potential User/Programming Errors:**
    * **Calling `StopParsing` and `PrepareToStopParsing` in quick succession:** This is an edge case that might occur during navigation aborts. The test ensures the parser handles this gracefully.
    * **Appending data after stopping the parser:**  A developer might mistakenly try to feed more data to a stopped parser. The tests verify that this doesn't lead to unexpected behavior.
    * **Incorrectly configuring prefetching:**  While not a direct user error with *this* code, the tests for prefetching highlight the importance of correctly signaling prefetch intent.

9. **Structure the Explanation:** Organize the findings into clear sections:
    * **File Functionality:** A high-level overview.
    * **Relationship to Web Technologies:**  Specifically address HTML, JavaScript, and CSS with examples from the code.
    * **Logical Deductions:** Explain the reasoning behind certain tests and what they reveal.
    * **Common Errors:** Provide concrete examples of mistakes the tests might help catch.

10. **Refine and Review:** Read through the explanation to ensure clarity, accuracy, and completeness. Check for any jargon that needs further explanation. Make sure the examples from the code directly support the claims made. For instance, when talking about JavaScript, point to the tests that specifically deal with `<script>` tags.
这个文件 `blink/renderer/core/html/parser/html_document_parser_test.cc` 是 Chromium Blink 引擎中用于测试 `HTMLDocumentParser` 类的单元测试文件。`HTMLDocumentParser` 的主要职责是将 HTML 文本解析成 DOM 树。因此，这个测试文件的功能是验证 `HTMLDocumentParser` 在各种场景下是否能正确地解析 HTML 代码，并处理各种边缘情况和错误。

下面列举一下它的具体功能，并说明与 JavaScript、HTML 和 CSS 的关系：

**主要功能:**

1. **测试 HTML 基本解析:** 验证 `HTMLDocumentParser` 能否正确解析基本的 HTML 结构，例如标签的开始和结束，属性的解析，文本内容的处理等。
2. **测试错误处理:** 测试解析器在遇到格式错误的 HTML 代码时，是否能按照规范进行容错处理，避免崩溃，并尽可能生成合理的 DOM 结构。
3. **测试异步/同步解析:**  测试不同解析策略（例如同步解析和延迟解析）下，解析器的行为是否符合预期。
4. **测试解析生命周期:**  测试解析器的启动、停止、中断和重新开始等生命周期管理功能是否正常工作。例如，测试在解析过程中停止解析后，是否能正确清理状态。
5. **测试预加载扫描器 (Preload Scanner):** 验证预加载扫描器能否正确地从 HTML 代码中提取需要预加载的资源（例如脚本、样式表），以优化页面加载性能。
6. **测试 `<iframe>` 的处理:**  测试解析器如何处理内嵌的 `<iframe>` 元素及其内部的文档解析。
7. **测试 `NoStatePrefetch`:** 测试在预取 (prefetch) 场景下，解析器的行为是否符合预期，例如是否会延迟执行某些操作。
8. **测试分块 (Chunked) 解析:**  测试解析器在接收到分块的 HTML 数据时，能否正确地进行解析。
9. **测试 `ProcessHtmlDataImmediately` 功能:** 验证是否可以配置解析器立即处理接收到的 HTML 数据块，以提高渲染性能。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:** 这是测试文件最直接相关的技术。所有的测试用例都涉及到对各种 HTML 代码片段的解析。
    * **例子 (假设输入与输出):**
        * **假设输入:** `<html><head><title>Test Page</title></head><body><h1>Hello</h1></body></html>`
        * **预期输出:**  DOM 树结构包含 `html` 元素，其下有 `head` 和 `body` 子元素，`head` 元素包含 `title` 元素，`body` 元素包含 `h1` 元素。
    * **例子 (错误处理):**
        * **假设输入:** `<html><head><title>Unclosed Title</head><body></body></html>`
        * **预期行为:** 解析器应该能容错处理，自动闭合 `title` 标签，并继续解析剩余的 HTML。

* **JavaScript:**  `HTMLDocumentParser` 需要识别并处理 HTML 中的 `<script>` 标签，并将其中的 JavaScript 代码传递给 JavaScript 引擎执行。预加载扫描器也需要识别 JavaScript 文件以便进行预加载。
    * **例子 (预加载扫描):**
        * **假设输入:** `<html><head><script src="script.js"></script></head><body></body></html>`
        * **预期行为:**  预加载扫描器应该能提取出 "script.js" 这个 URL，并触发预加载。
    * **例子 (内联脚本):**
        * **测试代码片段:** `parser->AppendDecodedData("<script>foo</script>", DocumentEncodingData());` 和 `EXPECT_TRUE(parser->HasInlineScriptStreamerForTesting("foo"));`
        * **说明:**  这段代码测试了当 HTML 中包含内联的 `<script>` 标签时，解析器是否能正确识别并处理。`HasInlineScriptStreamerForTesting` 可能是用于验证内联脚本是否被正确传递给后续的处理流程（例如编译）。

* **CSS:** `HTMLDocumentParser` 需要识别并处理 HTML 中的 `<link rel="stylesheet">` 标签和 `<style>` 标签，以便加载和解析 CSS 样式。预加载扫描器同样需要识别 CSS 文件以便进行预加载。
    * **例子 (预加载扫描):**
        * **假设输入:** `<html><head><link rel="stylesheet" href="style.css"></head><body></body></html>`
        * **预期行为:** 预加载扫描器应该能提取出 "style.css" 这个 URL，并触发预加载。

**逻辑推理的假设输入与输出 (已在 HTML 部分举例):**

上面的 "与 HTML 的关系及举例说明" 部分已经包含了逻辑推理的假设输入和输出的例子。测试代码本身也包含了大量的断言 (`EXPECT_*`)，这些断言就是基于对解析器行为的逻辑推理。

**涉及用户或者编程常见的使用错误及举例说明:**

这个测试文件主要关注的是 `HTMLDocumentParser` 内部的逻辑，但通过测试可以间接地发现一些用户或编程中常见的 HTML 使用错误，以及解析器如何处理这些错误。

* **未闭合的标签:**
    * **例子:**  `<p>This is a paragraph`
    * **测试目的:** 验证解析器是否能容错处理，自动闭合 `p` 标签。
* **错误的标签嵌套:**
    * **例子:** `<b><i>Bold and italic</b></i>`
    * **测试目的:** 验证解析器是否能按照 HTML 规范，调整 DOM 结构，使其符合正确的嵌套规则。
* **属性值缺少引号:**
    * **例子:** `<div id=main>`
    * **测试目的:** 验证解析器是否能正确解析没有引号的属性值。
* **在不应该出现的地方使用某些标签:**
    * **例子:** 在 `<head>` 标签内放置 `<body>` 标签。
    * **测试目的:** 验证解析器是否能忽略或正确处理这些不符合规范的标签。
* **在 JavaScript 或 CSS 中编写了不规范的代码:** 虽然这个测试文件不直接测试 JavaScript 和 CSS 的解析，但 `HTMLDocumentParser` 的正确性是后续 JavaScript 和 CSS 解析的基础。如果 HTML 解析错误，可能会导致 JavaScript 或 CSS 无法正确加载或执行。

**总结:**

`html_document_parser_test.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎能够可靠地解析各种各样的 HTML 文档，包括格式良好和包含错误的文档。它的测试覆盖了 HTML 解析的核心功能，并间接地关系到 JavaScript 和 CSS 的处理，因为正确的 HTML 解析是构建完整 Web 页面的基础。通过大量的测试用例，该文件可以帮助开发者发现和修复 `HTMLDocumentParser` 中的 bug，提高浏览器的稳定性和性能。

Prompt: 
```
这是目录为blink/renderer/core/html/parser/html_document_parser_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/parser/html_document_parser.h"

#include <memory>
#include <optional>

#include "base/test/scoped_feature_list.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html/parser/text_resource_decoder.h"
#include "third_party/blink/renderer/core/html/parser/text_resource_decoder_builder.h"
#include "third_party/blink/renderer/core/loader/no_state_prefetch_client.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"

namespace blink {

namespace {

class MockNoStatePrefetchClient : public NoStatePrefetchClient {
 public:
  MockNoStatePrefetchClient(Page& page, bool is_prefetch_only)
      : NoStatePrefetchClient(page, nullptr),
        is_prefetch_only_(is_prefetch_only) {}

 private:
  bool IsPrefetchOnly() override { return is_prefetch_only_; }

  bool is_prefetch_only_;
};

class HTMLDocumentParserTest
    : public PageTestBase,
      public testing::WithParamInterface<ParserSynchronizationPolicy> {
 protected:
  HTMLDocumentParserTest()
      : original_force_synchronous_parsing_for_testing_(
            Document::ForceSynchronousParsingForTesting()) {
    Document::SetForceSynchronousParsingForTesting(Policy() ==
                                                   kForceSynchronousParsing);
  }
  ~HTMLDocumentParserTest() override {
    // Finish the pending tasks which may require the runtime enabled flags,
    // before restoring the flags.
    base::RunLoop().RunUntilIdle();
    Document::SetForceSynchronousParsingForTesting(
        original_force_synchronous_parsing_for_testing_);
  }

  void SetUp() override {
    PageTestBase::SetUp();
    GetDocument().SetURL(KURL("https://example.test"));
  }

  HTMLDocumentParser* CreateParser(HTMLDocument& document) {
    auto* parser =
        MakeGarbageCollected<HTMLDocumentParser>(document, GetParam());
    std::unique_ptr<TextResourceDecoder> decoder(
        BuildTextResourceDecoder(document.GetFrame(), document.Url(),
                                 AtomicString("text/html"), g_null_atom));
    parser->SetDecoder(std::move(decoder));
    return parser;
  }

 private:
  ParserSynchronizationPolicy Policy() const { return GetParam(); }

  bool original_force_synchronous_parsing_for_testing_;
};

// Calls DocumentParser::Detach() in the destructor. Used to ensure detach is
// called, as otherwise some assertions may be triggered.
class ScopedParserDetacher {
 public:
  explicit ScopedParserDetacher(DocumentParser* parser) : parser_(parser) {}

  explicit ScopedParserDetacher(HTMLDocumentParser* parser)
      : ScopedParserDetacher(static_cast<DocumentParser*>(parser)) {}

  ~ScopedParserDetacher() { parser_->Detach(); }

 private:
  UntracedMember<DocumentParser> parser_;
};

}  // namespace

INSTANTIATE_TEST_SUITE_P(HTMLDocumentParserTest,
                         HTMLDocumentParserTest,
                         testing::Values(kForceSynchronousParsing,
                                         kAllowDeferredParsing));

TEST_P(HTMLDocumentParserTest, StopThenPrepareToStopShouldNotCrash) {
  auto& document = To<HTMLDocument>(GetDocument());
  DocumentParser* parser = CreateParser(document);
  ScopedParserDetacher detacher(parser);
  parser->AppendBytes(base::byte_span_from_cstring("<html>"));
  // These methods are not supposed to be called one after the other, but in
  // practice it can happen (e.g. if navigation is aborted).
  parser->StopParsing();
  parser->PrepareToStopParsing();
}

TEST_P(HTMLDocumentParserTest, HasNoPendingWorkAfterStopParsing) {
  auto& document = To<HTMLDocument>(GetDocument());
  HTMLDocumentParser* parser = CreateParser(document);
  DocumentParser* control_parser = static_cast<DocumentParser*>(parser);
  ScopedParserDetacher detacher(control_parser);
  control_parser->AppendBytes(base::byte_span_from_cstring("<html>"));
  control_parser->StopParsing();
  EXPECT_FALSE(parser->HasPendingWorkScheduledForTesting());
}

TEST_P(HTMLDocumentParserTest, HasNoPendingWorkAfterStopParsingThenAppend) {
  auto& document = To<HTMLDocument>(GetDocument());
  HTMLDocumentParser* parser = CreateParser(document);
  DocumentParser* control_parser = static_cast<DocumentParser*>(parser);
  ScopedParserDetacher detacher(control_parser);
  control_parser->AppendBytes(base::byte_span_from_cstring("<html>"));
  control_parser->StopParsing();
  control_parser->AppendBytes(base::byte_span_from_cstring("<head>"));
  EXPECT_FALSE(parser->HasPendingWorkScheduledForTesting());
}

TEST_P(HTMLDocumentParserTest, HasNoPendingWorkAfterDetach) {
  auto& document = To<HTMLDocument>(GetDocument());
  HTMLDocumentParser* parser = CreateParser(document);
  DocumentParser* control_parser = static_cast<DocumentParser*>(parser);
  control_parser->AppendBytes(base::byte_span_from_cstring("<html>"));
  control_parser->Detach();
  EXPECT_FALSE(parser->HasPendingWorkScheduledForTesting());
}

TEST_P(HTMLDocumentParserTest, AppendPrefetch) {
  auto& document = To<HTMLDocument>(GetDocument());
  ProvideNoStatePrefetchClientTo(
      *document.GetPage(), MakeGarbageCollected<MockNoStatePrefetchClient>(
                               *document.GetPage(), true));
  EXPECT_TRUE(document.IsPrefetchOnly());
  HTMLDocumentParser* parser = CreateParser(document);
  ScopedParserDetacher detacher(parser);

  parser->AppendBytes(base::byte_span_from_cstring("<httttttt"));
  // The bytes are forwarded to the preload scanner, not to the tokenizer.
  HTMLParserScriptRunnerHost* script_runner_host =
      parser->AsHTMLParserScriptRunnerHostForTesting();
  EXPECT_TRUE(script_runner_host->HasPreloadScanner());
  // Finishing should not cause parsing to start (verified via an internal
  // DCHECK).
  EXPECT_FALSE(parser->DidPumpTokenizerForTesting());
  static_cast<DocumentParser*>(parser)->Finish();
  EXPECT_FALSE(parser->DidPumpTokenizerForTesting());
  // Cancel any pending work to make sure that RuntimeFeatures DCHECKs do not
  // fire.
  static_cast<DocumentParser*>(parser)->StopParsing();
}

TEST_P(HTMLDocumentParserTest, AppendNoPrefetch) {
  auto& document = To<HTMLDocument>(GetDocument());
  EXPECT_FALSE(document.IsPrefetchOnly());
  // Use ForceSynchronousParsing to allow calling append().
  HTMLDocumentParser* parser = CreateParser(document);
  ScopedParserDetacher detacher(parser);

  parser->AppendBytes(base::byte_span_from_cstring("<htttttt"));
  test::RunPendingTasks();
  // The bytes are forwarded to the tokenizer.
  HTMLParserScriptRunnerHost* script_runner_host =
      parser->AsHTMLParserScriptRunnerHostForTesting();
  EXPECT_EQ(script_runner_host->HasPreloadScanner(),
            GetParam() == kAllowDeferredParsing);
  EXPECT_TRUE(parser->DidPumpTokenizerForTesting());
  // Cancel any pending work to make sure that RuntimeFeatures DCHECKs do not
  // fire.
  static_cast<DocumentParser*>(parser)->StopParsing();
}

class HTMLDocumentParserThreadedPreloadScannerTest : public PageTestBase {
 protected:
  HTMLDocumentParserThreadedPreloadScannerTest() {
    scoped_feature_list_.InitWithFeatures(
        {features::kThreadedPreloadScanner, features::kPrecompileInlineScripts},
        {});
    HTMLDocumentParser::ResetCachedFeaturesForTesting();
  }

  ~HTMLDocumentParserThreadedPreloadScannerTest() override {
    scoped_feature_list_.Reset();
    HTMLDocumentParser::ResetCachedFeaturesForTesting();
  }

  void SetUp() override {
    PageTestBase::SetUp();
    GetDocument().SetURL(KURL("https://example.test"));
  }

  HTMLDocumentParser* CreateParser(HTMLDocument& document) {
    return MakeGarbageCollected<HTMLDocumentParser>(document,
                                                    kAllowDeferredParsing);
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

TEST_F(HTMLDocumentParserThreadedPreloadScannerTest,
       TakeBackgroundScanCallback) {
  auto& document = To<HTMLDocument>(GetDocument());
  HTMLDocumentParser* parser = CreateParser(document);
  ScopedParserDetacher detacher(parser);

  // First append "foo" script which should be passed through to the scanner.
  parser->AppendDecodedData("<script>foo</script>", DocumentEncodingData());
  HTMLDocumentParser::FlushPreloadScannerThreadForTesting();
  EXPECT_TRUE(parser->HasInlineScriptStreamerForTesting("foo"));

  // Now take the callback.
  auto callback =
      static_cast<DocumentParser*>(parser)->TakeBackgroundScanCallback();

  // Append "bar" script which should not be passed to the scanner.
  parser->AppendDecodedData("<script>bar</script>", DocumentEncodingData());
  HTMLDocumentParser::FlushPreloadScannerThreadForTesting();
  EXPECT_FALSE(parser->HasInlineScriptStreamerForTesting("bar"));

  // Append "baz" script to the callback which should be passed to the scanner.
  callback.Run("<script>baz</script>");
  HTMLDocumentParser::FlushPreloadScannerThreadForTesting();
  EXPECT_TRUE(parser->HasInlineScriptStreamerForTesting("baz"));

  static_cast<DocumentParser*>(parser)->StopParsing();
}

class HTMLDocumentParserProcessImmediatelyTest : public PageTestBase {
 protected:
  void SetUp() override {
    PageTestBase::SetUp();
    GetDocument().SetURL(KURL("https://example.test"));
  }

  void TearDown() override {
    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
    PageTestBase::TearDown();
  }

  static HTMLDocumentParser* CreateParser(HTMLDocument& document) {
    auto* parser = MakeGarbageCollected<HTMLDocumentParser>(
        document, kAllowDeferredParsing);
    std::unique_ptr<TextResourceDecoder> decoder(
        BuildTextResourceDecoder(document.GetFrame(), document.Url(),
                                 AtomicString("text/html"), g_null_atom));
    parser->SetDecoder(std::move(decoder));
    return parser;
  }

  static HTMLDocumentParser* ConfigureWebViewHelperForChildFrameAndCreateParser(
      frame_test_helpers::WebViewHelper& web_view_helper) {
    std::string base_url = "http://internal.test/";
    url_test_helpers::RegisterMockedURLLoadFromBase(
        WebString::FromUTF8(base_url), test::CoreTestDataPath(),
        WebString::FromUTF8("visible_iframe.html"));
    url_test_helpers::RegisterMockedURLLoadFromBase(
        WebString::FromUTF8(base_url), test::CoreTestDataPath(),
        WebString::FromUTF8("single_iframe.html"));

    WebViewImpl* web_view_impl =
        web_view_helper.InitializeAndLoad(base_url + "single_iframe.html");

    web_view_impl->MainFrameWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);

    Document* top_doc =
        web_view_impl->MainFrameImpl()->GetFrame()->GetDocument();
    auto* iframe =
        To<HTMLIFrameElement>(top_doc->QuerySelector(AtomicString("iframe")));
    Document* child_document = iframe->contentDocument();
    return child_document ? CreateParser(To<HTMLDocument>(*child_document))
                          : nullptr;
  }
};

TEST_F(HTMLDocumentParserProcessImmediatelyTest, FirstChunk) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeatureWithParameters(
      features::kProcessHtmlDataImmediately,
      {{features::kProcessHtmlDataImmediatelyFirstChunk.name, "true"},
       {features::kProcessHtmlDataImmediatelyMainFrame.name, "true"}});
  auto& document = To<HTMLDocument>(GetDocument());
  HTMLDocumentParser* parser = CreateParser(document);
  ScopedParserDetacher detacher(parser);
  parser->AppendBytes(base::byte_span_from_cstring("<htttttt"));
  // Because kProcessHtmlDataImmediatelyFirstChunk is set,
  // DidPumpTokenizerForTesting() should be true.
  EXPECT_TRUE(parser->DidPumpTokenizerForTesting());
  // Cancel any pending work to make sure that RuntimeFeatures DCHECKs do not
  // fire.
  static_cast<DocumentParser*>(parser)->StopParsing();
}

TEST_F(HTMLDocumentParserProcessImmediatelyTest, SecondChunk) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeatureWithParameters(
      features::kProcessHtmlDataImmediately,
      {{features::kProcessHtmlDataImmediatelySubsequentChunks.name, "true"},
       {features::kProcessHtmlDataImmediatelyMainFrame.name, "true"}});
  auto& document = To<HTMLDocument>(GetDocument());
  HTMLDocumentParser* parser = CreateParser(document);
  ScopedParserDetacher detacher(parser);
  const auto kBytes = base::byte_span_from_cstring("<div><div><div>");
  parser->AppendBytes(kBytes);
  // The first chunk should not have been processed yet (it was scheduled).
  EXPECT_FALSE(parser->DidPumpTokenizerForTesting());
  test::RunPendingTasks();
  EXPECT_TRUE(parser->DidPumpTokenizerForTesting());
  EXPECT_EQ(1u, parser->GetChunkCountForTesting());
  parser->AppendBytes(kBytes);
  // As kProcessHtmlDataImmediatelySubsequentChunks is true, the second chunk
  // should be processed immediately.
  EXPECT_EQ(2u, parser->GetChunkCountForTesting());
  // Cancel any pending work to make sure that RuntimeFeatures DCHECKs do not
  // fire.
  static_cast<DocumentParser*>(parser)->StopParsing();
}

TEST_F(HTMLDocumentParserProcessImmediatelyTest, FirstChunkChildFrame) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeatureWithParameters(
      features::kProcessHtmlDataImmediately,
      {{features::kProcessHtmlDataImmediatelyChildFrame.name, "true"},
       {features::kProcessHtmlDataImmediatelyFirstChunk.name, "true"}});
  frame_test_helpers::WebViewHelper web_view_helper;
  HTMLDocumentParser* parser =
      ConfigureWebViewHelperForChildFrameAndCreateParser(web_view_helper);
  ASSERT_TRUE(parser);
  ScopedParserDetacher detacher(parser);
  parser->AppendBytes(base::byte_span_from_cstring("<div><div><div>"));
  // The first chunk should been processed.
  EXPECT_TRUE(parser->DidPumpTokenizerForTesting());

  // Cancel any pending work to make sure that RuntimeFeatures DCHECKs do not
  // fire.
  static_cast<DocumentParser*>(parser)->StopParsing();
}

TEST_F(HTMLDocumentParserProcessImmediatelyTest, FirstChunkDelayedChildFrame) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeatureWithParameters(
      features::kProcessHtmlDataImmediately,
      {{features::kProcessHtmlDataImmediatelyChildFrame.name, "true"},
       {features::kProcessHtmlDataImmediatelyFirstChunk.name, "false"}});
  frame_test_helpers::WebViewHelper web_view_helper;
  HTMLDocumentParser* parser =
      ConfigureWebViewHelperForChildFrameAndCreateParser(web_view_helper);
  ASSERT_TRUE(parser);
  ScopedParserDetacher detacher(parser);
  parser->AppendBytes(base::byte_span_from_cstring("<div><div><div>"));
  // The first chunk should not been processed.
  EXPECT_FALSE(parser->DidPumpTokenizerForTesting());

  // Cancel any pending work to make sure that RuntimeFeatures DCHECKs do not
  // fire.
  static_cast<DocumentParser*>(parser)->StopParsing();
}

}  // namespace blink

"""

```