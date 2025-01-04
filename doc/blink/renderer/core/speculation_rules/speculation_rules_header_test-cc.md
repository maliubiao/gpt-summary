Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The file name `speculation_rules_header_test.cc` immediately tells us this is a test file. The `speculation_rules_header` part strongly suggests it's testing the functionality related to processing the `Speculation-Rules` HTTP header.

2. **High-Level Structure:**  Glance through the code to understand its overall structure. We see `#include` directives, a namespace (`blink`), an anonymous namespace, and then a series of `TEST` macros. This is standard Google Test format.

3. **Key Classes and Functions:** Identify the primary classes and functions being tested. The core class seems to be `SpeculationRulesHeader`. The main function under test is likely `SpeculationRulesHeader::ProcessHeadersForDocumentResponse`.

4. **Test Cases - What are they doing?**  Go through each `TEST` function and summarize its goal. Look for patterns in setup, action, and assertion:
    * `NoMetricsWithoutHeader`: Checks behavior when the header is absent.
    * `UnparseableHeader`: Tests handling of an invalid header format.
    * `EmptyHeader`: Tests handling of an empty header.
    * `InvalidItem`: Checks how invalid items within the header are processed.
    * `ValidURL`: Verifies successful processing of a valid URL in the header.
    * `InvalidNvsHintError/Warning`: Tests handling of errors/warnings related to the `no-vary-search` hint.
    * `UsesResponseURLAsBaseURL`: Checks if relative URLs within the fetched rules are resolved correctly.
    * `InvalidStatusCode`: Tests handling of 404 responses when fetching the rules.
    * `NetError`: Tests handling of network errors during rules fetching.
    * `DocumentDetached`:  A more complex test involving document lifecycle and asynchronous operations.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):** Think about *why* this `Speculation-Rules` header exists. It's for telling the browser to proactively fetch resources. This connects directly to:
    * **HTML:** The header affects how the browser *loads* resources linked in the HTML.
    * **JavaScript:**  While not directly manipulated by JS in *this* code, the *effects* of speculation rules (faster page loads) will be seen by JS code. Also, JS might initiate navigations that benefit from prefetching.
    * **CSS:** CSS resources can be prefetched using speculation rules, leading to faster rendering.

6. **Logical Reasoning and Examples:** For each test, try to infer the logic being tested and create hypothetical inputs and outputs. For example:
    * **Input (UnparseableHeader):**  `Speculation-Rules: _: `
    * **Expected Output:**  Error message in the console, metric indicating parsing failure.
    * **Input (ValidURL):** `Speculation-Rules: "https://example.com/rules.json"` (assuming rules.json is valid)
    * **Expected Output:** Successful fetch, metric indicating success, potentially prefetching based on the rules.

7. **Common Errors:** Consider what could go wrong from a developer's perspective when using this feature:
    * **Incorrect Header Syntax:**  Typing errors in the header value.
    * **Invalid JSON:**  Providing malformed JSON in the linked rules file.
    * **Incorrect URLs:**  Linking to non-existent or incorrect rule files.
    * **CORS Issues:**  Trying to fetch rules from a different origin without proper CORS headers.

8. **Debugging Scenario:**  Think about how a developer would end up investigating this code:
    * **User reports a slow page load:** The developer might suspect speculation rules are failing.
    * **Console errors related to speculation rules:** This would be a direct indicator.
    * **Network tab showing failed requests for rule files:** Another clue.
    * **Developer explicitly trying to use the header:** They might be testing their implementation.

9. **Code Details (Helper Functions):** Pay attention to utility classes and functions used in the tests:
    * `ScopedRegisterMockedURLLoads`:  Crucial for simulating network requests without actually hitting the network. This makes testing isolated and fast.
    * `ConsoleCapturingChromeClient`:  Intercepts console messages, allowing tests to verify error reporting.
    * `DummyPageHolder`:  Provides a minimal page environment for testing Blink components.
    * `histogram_tester`:  Verifies that the correct metrics are being recorded.

10. **Review and Refine:**  Go back through the analysis and make sure it's clear, accurate, and covers the key aspects of the file. Ensure the examples are illustrative and the debugging scenario is plausible.

This step-by-step approach, combining understanding the purpose, analyzing the structure, and relating it to web technologies, helps in thoroughly understanding the functionality of a test file like this.
这个文件 `blink/renderer/core/speculation_rules/speculation_rules_header_test.cc` 是 Chromium Blink 引擎中用于测试 **HTTP `Speculation-Rules` 头部** 功能的单元测试文件。它主要验证了当服务器在 HTTP 响应头中包含 `Speculation-Rules` 头部时，Blink 引擎如何解析和处理该头部信息。

以下是该文件的功能列表：

1. **解析 `Speculation-Rules` 头部：** 测试各种格式的 `Speculation-Rules` 头部，包括有效的 URL、无效的 URL、空的头部、无法解析的头部以及包含多个条目的头部。

2. **触发预加载（Prefetching）：** 验证当 `Speculation-Rules` 头部包含指向有效的 JSON 规则文件的 URL 时，Blink 引擎是否会发起对该文件的异步请求，并根据规则文件中的内容进行预加载。

3. **处理规则文件：**  测试成功加载的规则文件是否被正确解析，并将规则应用于文档。例如，测试从头部加载的规则是否成功创建 `SpeculationRuleSet` 并包含预加载的 URL。

4. **记录指标（Metrics）：**  验证在处理 `Speculation-Rules` 头部时，是否记录了相关的性能指标，例如加载结果和加载时间。

5. **控制台错误报告：**  测试当 `Speculation-Rules` 头部或其指向的规则文件存在错误时，是否会在开发者控制台中输出相应的错误或警告信息。

6. **处理加载失败的情况：**  测试当规则文件加载失败（例如，HTTP 404 错误或网络错误）时，Blink 引擎的行为，包括记录指标和输出错误信息。

7. **处理重定向：** 测试当 `Speculation-Rules` 头部指向的 URL 发生重定向时，Blink 引擎是否能够正确处理并使用最终的 URL 作为基准 URL 来解析规则文件中的相对 URL。

8. **防止在文档卸载后继续处理：**  测试在文档卸载后，对于仍在加载的 `Speculation-Rules` 头部或规则文件的处理，防止出现崩溃或资源泄漏。

**与 Javascript, HTML, CSS 的关系：**

`Speculation-Rules` 头部是 Web 标准的一部分，旨在通过声明式的 HTTP 头部来指导浏览器进行推测性的预加载，以提高页面加载速度和用户体验。它与 Javascript, HTML, CSS 的关系如下：

* **HTML:**  `Speculation-Rules` 头部是 HTTP 头部，它在 HTML 文档加载时被浏览器解析。它可以作为 `<script type="speculationrules">` 标签的替代方案，提供了一种更简洁的方式来声明预加载规则，无需修改 HTML 内容。
    * **举例：** 服务器返回的 HTTP 响应头中包含 `Speculation-Rules: "https://example.com/prefetch_rules.json"`，浏览器会根据 `prefetch_rules.json` 文件中的规则预加载资源，这些资源可能是 HTML 页面、CSS 文件、Javascript 文件或图片等。

* **Javascript:**  虽然这个测试文件本身不涉及 Javascript 代码的执行，但 `Speculation-Rules` 头部最终会影响到 Javascript 的执行性能。通过预加载 Javascript 文件，可以减少用户导航到相关页面时加载和执行 Javascript 代码所需的时间。
    * **举例：**  `prefetch_rules.json` 中可能包含预加载特定 Javascript 文件的规则，当用户点击链接跳转到需要该 Javascript 文件的页面时，由于该文件已被预加载，Javascript 代码可以更快地执行。

* **CSS:** 类似于 Javascript，`Speculation-Rules` 头部可以用于预加载 CSS 文件。这可以加速页面的首次渲染，改善用户感知到的加载速度。
    * **举例：**  `prefetch_rules.json` 中可能包含预加载关键 CSS 文件的规则，这样当用户访问页面时，浏览器可以更快地应用样式，避免出现“无样式内容闪烁”（FOUC）。

**逻辑推理的假设输入与输出：**

**假设输入：**

1. **HTTP 响应头：**
   ```
   HTTP/1.1 200 OK
   Content-Type: text/html; charset=utf-8
   Speculation-Rules: "https://speculationrules.test/single_url_prefetch.json"
   ```
2. **`https://speculationrules.test/single_url_prefetch.json` 的内容：**
   ```json
   {
     "prefetch": [
       {
         "source": "document",
         "urls": ["/next_page.html"]
       }
     ]
   }
   ```

**预期输出：**

1. Blink 引擎会发起对 `https://speculationrules.test/single_url_prefetch.json` 的请求。
2. 请求成功后，Blink 引擎会解析 JSON 文件。
3. Blink 引擎会根据规则预加载 `/next_page.html` (相对于当前文档的 URL)。
4. `histogram_tester` 会记录 `Blink.SpeculationRules.LoadOutcome` 为成功。
5. 控制台不会输出任何错误信息。

**涉及用户或者编程常见的使用错误：**

1. **错误的头部语法：**  用户可能会在 `Speculation-Rules` 头部中提供无效的 URL 或格式不正确的字符串。
   * **举例：** `Speculation-Rules: invalid_url` 或 `Speculation-Rules: "not a json url"`。这会导致解析错误，控制台会输出错误信息。

2. **规则文件内容错误：**  用户提供的 JSON 规则文件可能包含语法错误或逻辑错误。
   * **举例：** JSON 文件中缺少必要的字段，或者 `urls` 字段不是字符串数组。这会导致规则解析失败，控制台会输出警告或错误信息。

3. **CORS 问题：**  如果 `Speculation-Rules` 头部指向的规则文件位于不同的源，并且没有配置正确的 CORS 头部，浏览器将阻止加载。
   * **举例：**  当前页面位于 `https://example.com`，而 `Speculation-Rules` 指向 `https://another-domain.com/rules.json`，但 `another-domain.com` 的服务器没有返回 `Access-Control-Allow-Origin` 头部。这会导致加载失败，控制台会输出 CORS 相关的错误信息。

4. **指向不存在的规则文件：**  `Speculation-Rules` 头部指向的 URL 可能返回 404 错误。
   * **举例：** `Speculation-Rules: "https://example.com/non_existent_rules.json"`。这会导致加载失败，控制台会输出 HTTP 404 相关的错误信息。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **开发者想要使用 HTTP `Speculation-Rules` 头部来优化其网站的加载性能。**
2. **开发者配置其 Web 服务器，使其在 HTTP 响应头中包含 `Speculation-Rules` 头部。** 例如，在 Apache 或 Nginx 的配置文件中添加相应的头部设置。
3. **用户通过浏览器访问该网站的页面。**
4. **浏览器接收到包含 `Speculation-Rules` 头的 HTTP 响应。**
5. **Blink 引擎开始解析该头部。**
6. **如果头部指向一个外部的 JSON 规则文件，Blink 引擎会发起一个异步请求来获取该文件。**
7. **在测试场景中，为了避免实际的网络请求，使用了 `ScopedRegisterMockedURLLoads` 来模拟网络请求。** 这允许测试在隔离的环境中验证 Blink 引擎对不同响应的处理。
8. **如果开发者在配置 `Speculation-Rules` 头部或规则文件时犯了错误，Blink 引擎可能会记录错误指标或在控制台中输出错误信息。**
9. **当开发者需要调试 `Speculation-Rules` 功能时，他们可能会查看浏览器的开发者工具的网络面板来检查规则文件的加载状态，或者查看控制台面板来查找相关的错误或警告信息。**
10. **如果开发者怀疑 Blink 引擎的实现有问题，他们可能会查看 Blink 的源代码，并可能运行相关的单元测试，例如 `speculation_rules_header_test.cc`，来验证其行为是否符合预期。**

总而言之，`speculation_rules_header_test.cc` 是一个关键的测试文件，用于确保 Blink 引擎能够正确地实现和处理 HTTP `Speculation-Rules` 头部，从而保证该功能能够可靠地工作，为用户带来更好的浏览体验。开发者可以通过查看这个测试文件来了解 Blink 引擎是如何解析和处理 `Speculation-Rules` 头部的各种情况，并作为他们自己实现和调试该功能的参考。

Prompt: 
```
这是目录为blink/renderer/core/speculation_rules/speculation_rules_header_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/speculation_rules/speculation_rules_header.h"

#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "net/base/net_errors.h"
#include "net/http/http_status_code.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/speculation_rules/document_speculation_rules.h"
#include "third_party/blink/renderer/core/speculation_rules/speculation_rules_metrics.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_response.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"

namespace blink {
namespace {

using ::testing::Contains;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::ResultOf;

class ScopedRegisterMockedURLLoads {
 public:
  ScopedRegisterMockedURLLoads() {
    url_test_helpers::RegisterMockedURLLoad(
        KURL("https://thirdparty-speculationrules.test/"
             "single_url_prefetch.json"),
        test::CoreTestDataPath("speculation_rules/single_url_prefetch.json"),
        "application/speculationrules+json");
    url_test_helpers::RegisterMockedURLLoad(
        KURL("https://thirdparty-speculationrules.test/"
             "single_url_prefetch_not_a_string_no_vary_search_hint.json"),
        test::CoreTestDataPath(
            "speculation_rules/"
            "single_url_prefetch_not_a_string_no_vary_search_hint.json"),
        "application/speculationrules+json");
    url_test_helpers::RegisterMockedURLLoad(
        KURL("https://thirdparty-speculationrules.test/"
             "single_url_prefetch_invalid_no_vary_search_hint.json"),
        test::CoreTestDataPath(
            "speculation_rules/"
            "single_url_prefetch_invalid_no_vary_search_hint.json"),
        "application/speculationrules+json");

    url_test_helpers::RegisterMockedURLLoad(
        KURL("https://speculationrules.test/"
             "single_url_prefetch_relative.json"),
        test::CoreTestDataPath(
            "speculation_rules/single_url_prefetch_relative.json"),
        "application/speculationrules+json");

    url_test_helpers::RegisterMockedURLLoad(
        KURL("https://speculationrules.test/document_rule_prefetch.json"),
        test::CoreTestDataPath("speculation_rules/document_rule_prefetch.json"),
        "application/speculationrules+json");

    KURL redirect_url(
        "https://speculationrules.test/"
        "redirect/single_url_prefetch_relative.json");
    ResourceResponse redirect(redirect_url);
    redirect.SetHttpStatusCode(net::HTTP_MOVED_PERMANENTLY);
    redirect.SetHttpHeaderField(
        http_names::kLocation,
        AtomicString("../single_url_prefetch_relative.json"));
    url_test_helpers::RegisterMockedURLLoadWithCustomResponse(
        redirect_url, "", WrappedResourceResponse(std::move(redirect)));

    KURL not_found_url("https://speculationrules.test/404");
    ResourceResponse not_found(not_found_url);
    not_found.SetHttpStatusCode(net::HTTP_NOT_FOUND);
    url_test_helpers::RegisterMockedURLLoadWithCustomResponse(
        not_found_url, "", WrappedResourceResponse(std::move(not_found)));

    KURL net_error_url("https://speculationrules.test/neterror");
    WebURLError error(net::ERR_INTERNET_DISCONNECTED, net_error_url);
    URLLoaderMockFactory::GetSingletonInstance()->RegisterErrorURL(
        net_error_url, WebURLResponse(), error);
  }

  ~ScopedRegisterMockedURLLoads() {
    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
  }
};

class ConsoleCapturingChromeClient : public EmptyChromeClient {
 public:
  void AddMessageToConsole(LocalFrame*,
                           mojom::ConsoleMessageSource,
                           mojom::ConsoleMessageLevel,
                           const String& message,
                           unsigned line_number,
                           const String& source_id,
                           const String& stack_trace) override {
    messages_.push_back(message);
  }

  const Vector<String>& ConsoleMessages() const { return messages_; }

 private:
  Vector<String> messages_;
};

TEST(SpeculationRulesHeaderTest, NoMetricsWithoutHeader) {
  test::TaskEnvironment task_environment;
  base::HistogramTester histogram_tester;
  auto* chrome_client = MakeGarbageCollected<ConsoleCapturingChromeClient>();
  DummyPageHolder page_holder(/*initial_view_size=*/{}, chrome_client);

  ResourceResponse document_response(KURL("https://speculation-rules.test/"));
  document_response.SetHttpStatusCode(200);
  document_response.SetMimeType(AtomicString("text/html"));
  document_response.SetTextEncodingName(AtomicString("UTF-8"));
  SpeculationRulesHeader::ProcessHeadersForDocumentResponse(
      document_response, *page_holder.GetFrame().DomWindow());

  EXPECT_FALSE(page_holder.GetDocument().IsUseCounted(
      WebFeature::kSpeculationRulesHeader));
  histogram_tester.ExpectTotalCount("Blink.SpeculationRules.LoadOutcome", 0);
  EXPECT_THAT(chrome_client->ConsoleMessages(),
              Not(Contains(ResultOf([](const auto& m) { return m.Utf8(); },
                                    HasSubstr("Speculation-Rules")))));
}

TEST(SpeculationRulesHeaderTest, UnparseableHeader) {
  test::TaskEnvironment task_environment;
  base::HistogramTester histogram_tester;
  auto* chrome_client = MakeGarbageCollected<ConsoleCapturingChromeClient>();
  DummyPageHolder page_holder(/*initial_view_size=*/{}, chrome_client);

  ResourceResponse document_response(KURL("https://speculation-rules.test/"));
  document_response.SetHttpStatusCode(200);
  document_response.SetMimeType(AtomicString("text/html"));
  document_response.SetTextEncodingName(AtomicString("UTF-8"));
  document_response.AddHttpHeaderField(http_names::kSpeculationRules,
                                       AtomicString("_:"));
  SpeculationRulesHeader::ProcessHeadersForDocumentResponse(
      document_response, *page_holder.GetFrame().DomWindow());

  EXPECT_TRUE(page_holder.GetDocument().IsUseCounted(
      WebFeature::kSpeculationRulesHeader));
  histogram_tester.ExpectUniqueSample(
      "Blink.SpeculationRules.LoadOutcome",
      SpeculationRulesLoadOutcome::kUnparseableSpeculationRulesHeader, 1);
  EXPECT_THAT(chrome_client->ConsoleMessages(),
              Contains(ResultOf([](const auto& m) { return m.Utf8(); },
                                HasSubstr("Speculation-Rules"))));
}

TEST(SpeculationRulesHeaderTest, EmptyHeader) {
  test::TaskEnvironment task_environment;
  base::HistogramTester histogram_tester;
  DummyPageHolder page_holder;

  ResourceResponse document_response(KURL("https://speculation-rules.test/"));
  document_response.SetHttpStatusCode(200);
  document_response.SetMimeType(AtomicString("text/html"));
  document_response.SetTextEncodingName(AtomicString("UTF-8"));
  document_response.AddHttpHeaderField(http_names::kSpeculationRules,
                                       g_empty_atom);
  SpeculationRulesHeader::ProcessHeadersForDocumentResponse(
      document_response, *page_holder.GetFrame().DomWindow());

  EXPECT_TRUE(page_holder.GetDocument().IsUseCounted(
      WebFeature::kSpeculationRulesHeader));
  histogram_tester.ExpectUniqueSample(
      "Blink.SpeculationRules.LoadOutcome",
      SpeculationRulesLoadOutcome::kEmptySpeculationRulesHeader, 1);
}

TEST(SpeculationRulesHeaderTest, InvalidItem) {
  test::TaskEnvironment task_environment;
  base::HistogramTester histogram_tester;
  auto* chrome_client = MakeGarbageCollected<ConsoleCapturingChromeClient>();
  DummyPageHolder page_holder(/*initial_view_size=*/{}, chrome_client);

  ResourceResponse document_response(KURL("https://speculation-rules.test/"));
  document_response.SetHttpStatusCode(200);
  document_response.SetMimeType(AtomicString("text/html"));
  document_response.SetTextEncodingName(AtomicString("UTF-8"));
  document_response.AddHttpHeaderField(
      http_names::kSpeculationRules,
      AtomicString("42, :aGVsbG8=:, ?1, \"://\""));
  SpeculationRulesHeader::ProcessHeadersForDocumentResponse(
      document_response, *page_holder.GetFrame().DomWindow());

  EXPECT_TRUE(page_holder.GetDocument().IsUseCounted(
      WebFeature::kSpeculationRulesHeader));
  histogram_tester.ExpectUniqueSample(
      "Blink.SpeculationRules.LoadOutcome",
      SpeculationRulesLoadOutcome::kInvalidSpeculationRulesHeaderItem, 4);
  EXPECT_THAT(chrome_client->ConsoleMessages(),
              Contains(ResultOf([](const auto& m) { return m.Utf8(); },
                                HasSubstr("Speculation-Rules")))
                  .Times(4));
}

TEST(SpeculationRulesHeaderTest, ValidURL) {
  test::TaskEnvironment task_environment;
  base::HistogramTester histogram_tester;
  auto* chrome_client = MakeGarbageCollected<ConsoleCapturingChromeClient>();
  DummyPageHolder page_holder(/*initial_view_size=*/{}, chrome_client);
  ScopedRegisterMockedURLLoads mock_url_loads;

  ResourceResponse document_response(KURL("https://speculation-rules.test/"));
  document_response.SetHttpStatusCode(200);
  document_response.SetMimeType(AtomicString("text/html"));
  document_response.SetTextEncodingName(AtomicString("UTF-8"));
  document_response.AddHttpHeaderField(
      http_names::kSpeculationRules,
      AtomicString("\"https://thirdparty-speculationrules.test/"
                   "single_url_prefetch.json\""));
  SpeculationRulesHeader::ProcessHeadersForDocumentResponse(
      document_response, *page_holder.GetFrame().DomWindow());
  url_test_helpers::ServeAsynchronousRequests();

  EXPECT_TRUE(page_holder.GetDocument().IsUseCounted(
      WebFeature::kSpeculationRulesHeader));
  histogram_tester.ExpectUniqueSample("Blink.SpeculationRules.LoadOutcome",
                                      SpeculationRulesLoadOutcome::kSuccess, 1);
  histogram_tester.ExpectTotalCount("Blink.SpeculationRules.FetchTime", 1);
  EXPECT_THAT(chrome_client->ConsoleMessages(),
              Not(Contains(ResultOf([](const auto& m) { return m.Utf8(); },
                                    HasSubstr("Speculation-Rules")))));
}

TEST(SpeculationRulesHeaderTest, InvalidNvsHintError) {
  test::TaskEnvironment task_environment;
  base::HistogramTester histogram_tester;
  auto* chrome_client = MakeGarbageCollected<ConsoleCapturingChromeClient>();
  DummyPageHolder page_holder(/*initial_view_size=*/{}, chrome_client);
  ScopedRegisterMockedURLLoads mock_url_loads;

  ResourceResponse document_response(KURL("https://speculation-rules.test/"));
  document_response.SetHttpStatusCode(200);
  document_response.SetMimeType(AtomicString("text/html"));
  document_response.SetTextEncodingName(AtomicString("UTF-8"));
  document_response.AddHttpHeaderField(
      http_names::kSpeculationRules,
      AtomicString(
          "\"https://thirdparty-speculationrules.test/"
          "single_url_prefetch_not_a_string_no_vary_search_hint.json\""));
  SpeculationRulesHeader::ProcessHeadersForDocumentResponse(
      document_response, *page_holder.GetFrame().DomWindow());
  url_test_helpers::ServeAsynchronousRequests();

  EXPECT_TRUE(page_holder.GetDocument().IsUseCounted(
      WebFeature::kSpeculationRulesHeader));
  histogram_tester.ExpectUniqueSample("Blink.SpeculationRules.LoadOutcome",
                                      SpeculationRulesLoadOutcome::kSuccess, 1);
  histogram_tester.ExpectTotalCount("Blink.SpeculationRules.FetchTime", 1);

  EXPECT_THAT(
      chrome_client->ConsoleMessages(),
      Contains(ResultOf(
          [](const auto& m) { return m.Utf8(); },
          HasSubstr("expects_no_vary_search's value must be a string"))));
}

TEST(SpeculationRulesHeaderTest, InvalidNvsHintWarning) {
  test::TaskEnvironment task_environment;
  base::HistogramTester histogram_tester;
  auto* chrome_client = MakeGarbageCollected<ConsoleCapturingChromeClient>();
  DummyPageHolder page_holder(/*initial_view_size=*/{}, chrome_client);
  ScopedRegisterMockedURLLoads mock_url_loads;

  ResourceResponse document_response(KURL("https://speculation-rules.test/"));
  document_response.SetHttpStatusCode(200);
  document_response.SetMimeType(AtomicString("text/html"));
  document_response.SetTextEncodingName(AtomicString("UTF-8"));
  document_response.AddHttpHeaderField(
      http_names::kSpeculationRules,
      AtomicString("\"https://thirdparty-speculationrules.test/"
                   "single_url_prefetch_invalid_no_vary_search_hint.json\""));
  SpeculationRulesHeader::ProcessHeadersForDocumentResponse(
      document_response, *page_holder.GetFrame().DomWindow());
  url_test_helpers::ServeAsynchronousRequests();

  EXPECT_TRUE(page_holder.GetDocument().IsUseCounted(
      WebFeature::kSpeculationRulesHeader));
  histogram_tester.ExpectUniqueSample("Blink.SpeculationRules.LoadOutcome",
                                      SpeculationRulesLoadOutcome::kSuccess, 1);
  histogram_tester.ExpectTotalCount("Blink.SpeculationRules.FetchTime", 1);

  EXPECT_THAT(chrome_client->ConsoleMessages(),
              Contains(ResultOf(
                  [](const auto& m) { return m.Utf8(); },
                  HasSubstr("contains a \"params\" dictionary value"
                            " that is not a list of strings or a boolean"))));
}

TEST(SpeculationRulesHeaderTest, UsesResponseURLAsBaseURL) {
  test::TaskEnvironment task_environment;
  base::HistogramTester histogram_tester;
  auto* chrome_client = MakeGarbageCollected<ConsoleCapturingChromeClient>();
  DummyPageHolder page_holder(/*initial_view_size=*/{}, chrome_client);
  ScopedRegisterMockedURLLoads mock_url_loads;

  ResourceResponse document_response(KURL("https://speculation-rules.test/"));
  document_response.SetHttpStatusCode(200);
  document_response.SetMimeType(AtomicString("text/html"));
  document_response.SetTextEncodingName(AtomicString("UTF-8"));
  document_response.AddHttpHeaderField(
      http_names::kSpeculationRules,
      AtomicString("\"https://speculationrules.test/"
                   "redirect/single_url_prefetch_relative.json\""));
  SpeculationRulesHeader::ProcessHeadersForDocumentResponse(
      document_response, *page_holder.GetFrame().DomWindow());
  url_test_helpers::ServeAsynchronousRequests();

  EXPECT_TRUE(page_holder.GetDocument().IsUseCounted(
      WebFeature::kSpeculationRulesHeader));
  histogram_tester.ExpectUniqueSample("Blink.SpeculationRules.LoadOutcome",
                                      SpeculationRulesLoadOutcome::kSuccess, 1);
  histogram_tester.ExpectTotalCount("Blink.SpeculationRules.FetchTime", 1);
  EXPECT_THAT(chrome_client->ConsoleMessages(),
              Not(Contains(ResultOf([](const auto& m) { return m.Utf8(); },
                                    HasSubstr("Speculation-Rules")))));

  SpeculationRuleSet* rule_set =
      DocumentSpeculationRules::From(page_holder.GetDocument()).rule_sets()[0];
  EXPECT_EQ(
      KURL("https://speculationrules.test/single_url_prefetch_relative.json"),
      rule_set->source()->GetBaseURL());
  EXPECT_THAT(
      rule_set->prefetch_rules()[0]->urls(),
      ::testing::ElementsAre(KURL("https://speculationrules.test/next.html")));
}

TEST(SpeculationRulesHeaderTest, InvalidStatusCode) {
  test::TaskEnvironment task_environment;
  base::HistogramTester histogram_tester;
  auto* chrome_client = MakeGarbageCollected<ConsoleCapturingChromeClient>();
  DummyPageHolder page_holder(/*initial_view_size=*/{}, chrome_client);
  ScopedRegisterMockedURLLoads mock_url_loads;

  ResourceResponse document_response(KURL("https://speculation-rules.test/"));
  document_response.SetHttpStatusCode(200);
  document_response.SetMimeType(AtomicString("text/html"));
  document_response.SetTextEncodingName(AtomicString("UTF-8"));
  document_response.AddHttpHeaderField(
      http_names::kSpeculationRules,
      AtomicString("\"https://speculationrules.test/404\""));
  SpeculationRulesHeader::ProcessHeadersForDocumentResponse(
      document_response, *page_holder.GetFrame().DomWindow());
  url_test_helpers::ServeAsynchronousRequests();

  EXPECT_TRUE(page_holder.GetDocument().IsUseCounted(
      WebFeature::kSpeculationRulesHeader));
  histogram_tester.ExpectUniqueSample(
      "Blink.SpeculationRules.LoadOutcome",
      SpeculationRulesLoadOutcome::kLoadFailedOrCanceled, 1);
  histogram_tester.ExpectTotalCount("Blink.SpeculationRules.FetchTime", 1);
  EXPECT_THAT(chrome_client->ConsoleMessages(),
              Contains(ResultOf(
                  [](const auto& m) { return m.Utf8(); },
                  AllOf(HasSubstr("Speculation-Rules"), HasSubstr("404")))));

  EXPECT_THAT(
      DocumentSpeculationRules::From(page_holder.GetDocument()).rule_sets(),
      ::testing::IsEmpty());
}

TEST(SpeculationRulesHeaderTest, NetError) {
  test::TaskEnvironment task_environment;
  base::HistogramTester histogram_tester;
  auto* chrome_client = MakeGarbageCollected<ConsoleCapturingChromeClient>();
  DummyPageHolder page_holder(/*initial_view_size=*/{}, chrome_client);
  ScopedRegisterMockedURLLoads mock_url_loads;

  ResourceResponse document_response(KURL("https://speculation-rules.test/"));
  document_response.SetHttpStatusCode(200);
  document_response.SetMimeType(AtomicString("text/html"));
  document_response.SetTextEncodingName(AtomicString("UTF-8"));
  document_response.AddHttpHeaderField(
      http_names::kSpeculationRules,
      AtomicString("\"https://speculationrules.test/neterror\""));
  SpeculationRulesHeader::ProcessHeadersForDocumentResponse(
      document_response, *page_holder.GetFrame().DomWindow());
  url_test_helpers::ServeAsynchronousRequests();

  EXPECT_TRUE(page_holder.GetDocument().IsUseCounted(
      WebFeature::kSpeculationRulesHeader));
  histogram_tester.ExpectUniqueSample(
      "Blink.SpeculationRules.LoadOutcome",
      SpeculationRulesLoadOutcome::kLoadFailedOrCanceled, 1);
  histogram_tester.ExpectTotalCount("Blink.SpeculationRules.FetchTime", 1);
  EXPECT_THAT(chrome_client->ConsoleMessages(),
              Contains(ResultOf([](const auto& m) { return m.Utf8(); },
                                AllOf(HasSubstr("Speculation-Rules"),
                                      HasSubstr("INTERNET_DISCONNECTED")))));

  EXPECT_THAT(
      DocumentSpeculationRules::From(page_holder.GetDocument()).rule_sets(),
      ::testing::IsEmpty());
}

// Regression test for crbug.com/356767669.
// Order of events:
// 1) The load of the speculation rules header completes
// 2) The document detaches
// 3) SpeculationRuleLoader::NotifyFinished is called
TEST(SpeculationRulesHeaderTest, DocumentDetached) {
  test::TaskEnvironment task_environment;
  base::HistogramTester histogram_tester;
  auto* chrome_client = MakeGarbageCollected<ConsoleCapturingChromeClient>();
  DummyPageHolder page_holder(/*initial_view_size=*/{}, chrome_client);
  ScopedRegisterMockedURLLoads mock_url_loads;

  ResourceResponse document_response(KURL("https://speculation-rules.test/"));
  document_response.SetHttpStatusCode(200);
  document_response.SetMimeType(AtomicString("text/html"));
  document_response.SetTextEncodingName(AtomicString("UTF-8"));
  document_response.AddHttpHeaderField(
      http_names::kSpeculationRules,
      AtomicString("\"https://speculationrules.test/"
                   "document_rule_prefetch.json\""));
  SpeculationRulesHeader::ProcessHeadersForDocumentResponse(
      document_response, *page_holder.GetFrame().DomWindow());

  page_holder.GetDocument()
      .GetTaskRunner(TaskType::kDOMManipulation)
      ->PostTask(FROM_HERE, base::BindLambdaForTesting([&]() {
                   page_holder.GetDocument().Shutdown();
                 }));
  url_test_helpers::ServeAsynchronousRequests();

  histogram_tester.ExpectUniqueSample("Blink.SpeculationRules.LoadOutcome",
                                      SpeculationRulesLoadOutcome::kSuccess, 0);
  histogram_tester.ExpectTotalCount("Blink.SpeculationRules.FetchTime", 1);
  EXPECT_THAT(chrome_client->ConsoleMessages(),
              Not(Contains(ResultOf([](const auto& m) { return m.Utf8(); },
                                    HasSubstr("Speculation-Rules")))));
}

}  // namespace
}  // namespace blink

"""

```