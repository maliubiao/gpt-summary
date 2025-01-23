Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The filename `allowed_by_nosniff_test.cc` and the included header `allowed_by_nosniff.h` immediately suggest the core functionality being tested: determining if a resource can be treated as a specific type (likely script or XML external entity) based on its MIME type and the "nosniff" header.

2. **Identify Key Components:** Scan the includes and the code itself for important classes and functions.
    * `AllowedByNosniff`:  This is the central class being tested. Its methods `MimeTypeAsScript` and `MimeTypeAsXMLExternalEntity` are the primary focus.
    * `ResourceResponse`:  Represents the HTTP response, crucial for inspecting headers like `Content-Type` and `X-Content-Type-Options`.
    * `UseCounter`:  Used for tracking feature usage. The tests use a mock to verify counting behavior.
    * `ConsoleLogger`: Used for logging warnings or errors. The tests use a mock to check for expected log messages.
    * `testing::TestWithParam`, `TEST_P`, `INSTANTIATE_TEST_SUITE_P`:  Indicates parameterized testing, where the same test logic is run with different input values (in this case, a boolean).
    * `RuntimeEnabledFeatures`, `ScopedStrictMimeTypesForWorkers`: Suggests that the behavior being tested might be influenced by feature flags.
    * `MockUseCounter`, `MockConsoleLogger`: These are test doubles used for controlled verification of interactions.

3. **Analyze the Tests Themselves:** Look at the structure and purpose of each `TEST_P` or `TEST` function.

    * **`AllowedOrNot`:** This test is clearly about checking different MIME types and whether `AllowedByNosniff::MimeTypeAsScript` considers them valid as scripts under different `MimeTypeCheck` modes (lax for elements, lax for workers, strict). The `data` array within the test provides a good set of example MIME types and their expected behavior.

    * **`Counters`:** This test focuses on the usage counting aspect. It checks which `WebFeature` enum values are recorded for different combinations of URLs, origins, MIME types, and response types. This reveals how Blink tracks the usage of script and related content loading in different scenarios.

    * **`AllTheSchemes`:** This test looks at how the URL scheme affects the decision, especially when the `Content-Type` is deliberately set to an invalid value and the `nosniff` header is present. This highlights cases where the URL scheme overrides the MIME type.

    * **`XMLExternalEntity`:** This test specifically focuses on the `AllowedByNosniff::MimeTypeAsXMLExternalEntity` function and how it interacts with the `Content-Type` and `X-Content-Type-Options` headers.

4. **Relate to Web Technologies:** Now connect the C++ code and its testing to the concepts of JavaScript, HTML, and CSS.

    * **JavaScript:** The `AllowedByNosniff::MimeTypeAsScript` function directly relates to determining if a resource *can* be executed as JavaScript. The test cases involving `text/javascript`, `application/javascript`, and similar MIME types are the core of this connection. The test also implicitly touches upon the security implications of misidentified scripts.

    * **HTML:** The test includes `text/html` as a MIME type. While not strictly a "script" MIME type, its handling (and potential blocking under strict modes) is relevant to how browsers interpret HTML documents, which often contain embedded scripts.

    * **CSS:** Although CSS MIME types aren't explicitly tested for the `MimeTypeAsScript` function (they are generally blocked), the existence of the `X-Content-Type-Options: nosniff` header, which is crucial for CSS as well, makes it indirectly related. The `XMLExternalEntity` test touches upon XML, which has connections to technologies used within HTML (like SVG).

5. **Consider Logic and Assumptions:** Examine the test cases for logical flow and implicit assumptions.

    * The `AllowedOrNot` test explicitly checks different "strictness" levels, controlled by the `StrictMimeTypesForWorkersEnabled` feature flag. This demonstrates how the system adapts to different security policies.
    * The `Counters` test makes assumptions about how cross-origin and same-origin requests are categorized and which features are counted in each case.

6. **Think About User/Developer Errors:** Based on the functionality and the test cases, consider potential mistakes.

    * Serving JavaScript with an incorrect `Content-Type` (e.g., `text/plain`) is a classic error that `nosniff` helps prevent.
    * Developers might misunderstand the effect of the `nosniff` header and its interaction with MIME types.
    * Incorrectly configuring a server to serve resources with the wrong MIME type is a common server-side issue.

7. **Structure the Output:** Organize the findings into clear categories (Functionality, Relation to Web Tech, Logic & Assumptions, Common Errors). Use examples from the code to illustrate each point. Be precise in describing the purpose of each test.

8. **Refine and Review:**  Read through the analysis to ensure clarity, accuracy, and completeness. Check for any misunderstandings or missed details. For example, initially, I might have focused too heavily on just JavaScript, but reviewing the `XMLExternalEntity` test broadened the scope to include XML-related content.

This iterative process of examining the code, understanding its purpose, connecting it to broader web concepts, and considering potential errors leads to a comprehensive analysis like the example provided in the initial prompt.
这个C++文件 `allowed_by_nosniff_test.cc` 是 Chromium Blink 引擎中用于测试 `AllowedByNosniff` 类的功能。`AllowedByNosniff` 类的主要职责是**判断一个网络资源的MIME类型是否被允许作为特定类型的内容（例如脚本）加载，尤其是在 `X-Content-Type-Options: nosniff` 头部存在的情况下**。

以下是该文件的功能详细列表以及与 JavaScript, HTML, CSS 的关系：

**主要功能:**

1. **测试 MIME 类型是否允许作为脚本:**  测试 `AllowedByNosniff::MimeTypeAsScript` 函数在不同 `MimeTypeCheck` 模式下的行为，判断给定的 MIME 类型是否被允许作为 JavaScript 代码执行。这包括：
    * **支持的 MIME 类型:** 例如 `text/javascript`, `application/javascript`, `text/ecmascript`。
    * **阻止的 MIME 类型:** 例如 `image/png`, `text/csv`, `video/mpeg`，这些类型不应被当作脚本执行。
    * **遗留的 MIME 类型:** 例如 `text/html`, `text/plain`, `application/xml`, `application/octet-stream`。在某些宽松模式下可能被允许，但在严格模式下可能被阻止。
    * **带有参数的 MIME 类型:** 例如 `text/javascript; charset=utf-8`。
    * **大小写不敏感的 MIME 类型:** 例如 `Text/html` 和 `text/HTML` 应该被视为相同。
    * **在启用 `StrictMimeTypesForWorkers` 特性时的不同行为。**

2. **测试 `X-Content-Type-Options: nosniff` 的影响:**  验证 `nosniff` 头部是否正确地阻止了某些 MIME 类型被当作脚本执行，即使它们的类型在某些情况下可能被解释为脚本（例如 `text/plain`）。

3. **测试不同 URL Scheme 的影响:** 验证不同的 URL scheme (例如 `http`, `https`, `file`, `chrome`, `ftp`) 如何影响资源是否被允许作为脚本加载，即使存在 `nosniff` 头部和错误的 `Content-Type`。

4. **测试 XML 外部实体:** 测试 `AllowedByNosniff::MimeTypeAsXMLExternalEntity` 函数，判断一个资源的 MIME 类型是否允许作为 XML 外部实体加载。这同样会受到 `X-Content-Type-Options: nosniff` 头部的影响。

5. **记录 UseCounter 指标:**  使用 `MockUseCounter` 模拟 UseCounter，验证在不同情况下是否记录了正确的 WebFeature 指标，用于跟踪浏览器特性的使用情况，例如：
    * `kCrossOriginTextScript`, `kCrossOriginTextPlain` (跨域文本脚本/纯文本)
    * `kSameOriginTextScript`, `kSameOriginTextPlain` (同源文本脚本/纯文本)
    * `kSameOriginJsonTypeForScript`, `kCrossOriginJsonTypeForScript` (同源/跨域 JSON 作为脚本)
    * 以及 `kStrictMimeTypeChecksWouldBlockWorker` 等。

6. **记录 Console 警告:** 使用 `MockConsoleLogger` 模拟 ConsoleLogger，验证在不应该被当作脚本加载的情况下，是否向控制台输出了相应的警告信息。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:** 该测试文件直接关系到浏览器如何安全地加载和执行 JavaScript 代码。`AllowedByNosniff` 机制是防止 MIME 类型混淆攻击的关键部分，确保只有被正确声明为 JavaScript 的资源才会被当作脚本执行。例如，如果一个服务器错误地将 JavaScript 文件以 `text/plain` 的 MIME 类型发送，并且没有 `nosniff` 头部，浏览器可能会尝试将其作为脚本执行。但是，如果存在 `nosniff` 头部，`AllowedByNosniff` 应该会阻止这种情况。

* **HTML:** 虽然 HTML 文件本身不是 JavaScript，但 HTML 文件中经常包含 `<script>` 标签来引入 JavaScript 代码。`AllowedByNosniff` 的严格模式可能会影响浏览器如何处理具有某些 MIME 类型的 HTML 文件中包含的脚本。此外，`text/html` 本身作为一个“遗留”类型被测试，因为它在某些情况下可能被视为可执行内容。

* **CSS:** 虽然这个测试文件主要关注脚本，但 `X-Content-Type-Options: nosniff` 头部对 CSS 的加载也至关重要。`nosniff` 头部可以防止浏览器错误地将某些文件（例如包含看似 CSS 内容的文本文件）当作 CSS 文件解析，从而避免安全风险。虽然 `MimeTypeAsScript` 并不直接测试 CSS，但 `XMLExternalEntity` 的测试以及 `nosniff` 头部的一般概念与 CSS 的安全加载有关。

**逻辑推理与假设输入输出：**

**假设输入：** 一个网络资源的 HTTP 响应，包含以下信息：

* **Content-Type 头部:** 例如 `"text/javascript"`, `"image/png"`, `"text/plain"`
* **X-Content-Type-Options 头部:** 可能为 `"nosniff"` 或不存在
* **URL Scheme:** 例如 `"http://"`, `"file://"`

**逻辑推理 (以 `AllowedByNosniff::MimeTypeAsScript` 和 `MimeTypeCheck::kStrict` 为例):**

* **输入:** `Content-Type: text/javascript`, `X-Content-Type-Options:` (不存在)
* **输出:** `true` (允许作为脚本)

* **输入:** `Content-Type: image/png`, `X-Content-Type-Options:` (不存在)
* **输出:** `false` (不允许作为脚本)

* **输入:** `Content-Type: text/plain`, `X-Content-Type-Options:` (不存在)
* **输出:** `false` (严格模式下通常不允许)

* **输入:** `Content-Type: text/plain`, `X-Content-Type-Options: nosniff`
* **输出:** `false` (`nosniff` 指示不要进行 MIME 类型猜测)

* **输入:** `Content-Type: application/octet-stream`, `X-Content-Type-Options:` (不存在)
* **输出:** `false` (严格模式下通常不允许)

* **输入:** `Content-Type: application/octet-stream`, `X-Content-Type-Options: nosniff`
* **输出:** `false`

* **输入:** `Content-Type: invalid`, `X-Content-Type-Options: nosniff`, `URL Scheme: file://`
* **输出:** `true` (对于 `file://` scheme，即使有 `nosniff` 也可能允许某些类型，具体取决于实现)

**用户或编程常见的使用错误举例：**

1. **服务器配置错误，发送错误的 Content-Type:**
   * **错误:**  服务器将一个 JavaScript 文件以 `Content-Type: text/plain` 发送。
   * **后果:**  如果客户端没有 `nosniff` 保护，可能会错误地将该文件当作纯文本处理，导致 JavaScript 代码无法执行。如果客户端有 `nosniff` 保护，`AllowedByNosniff` 会阻止将其作为脚本执行，并在控制台输出警告。

2. **误解 `X-Content-Type-Options: nosniff` 的作用:**
   * **错误:**  开发者认为设置了 `nosniff` 就可以随意设置 `Content-Type` 而不会有安全问题。
   * **后果:**  虽然 `nosniff` 可以阻止 MIME 类型嗅探，但它并不能神奇地将任何类型的文件变成可执行的脚本。例如，将一个图片设置为 `Content-Type: text/javascript` 并设置 `nosniff`，浏览器仍然不会将其作为 JavaScript 执行。

3. **在不应该使用的情况下依赖 MIME 类型嗅探:**
   * **错误:**  开发者依赖浏览器对未设置或设置错误的 `Content-Type` 的资源进行嗅探来决定其类型。
   * **后果:**  这可能导致安全漏洞。例如，攻击者可能会上传一个包含恶意 JavaScript 代码的图片，如果服务器没有正确设置 `Content-Type` 并且客户端允许嗅探，浏览器可能错误地将其当作脚本执行。`nosniff` 头部可以帮助避免这种情况。

4. **在需要脚本的地方使用了被阻止的 MIME 类型:**
   * **错误:**  开发者尝试使用一个 MIME 类型（例如 `text/csv`）的资源作为 `<script>` 标签的 `src`。
   * **后果:**  `AllowedByNosniff` 会阻止该资源作为脚本加载，并在控制台输出警告。开发者需要确保用于脚本的资源具有正确的 JavaScript MIME 类型。

总而言之，`allowed_by_nosniff_test.cc` 通过各种测试用例，确保 `AllowedByNosniff` 类能够正确地根据 MIME 类型和 `nosniff` 头部来判断资源是否可以作为脚本或 XML 外部实体加载，这对于浏览器的安全性和正确性至关重要。它直接关联到开发者在使用 JavaScript, HTML, CSS 时需要理解的关于资源类型声明和安全加载的重要概念。

### 提示词
```
这是目录为blink/renderer/platform/loader/allowed_by_nosniff_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/allowed_by_nosniff.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/public/mojom/use_counter/metrics/webdx_feature.mojom-blink.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/console_logger.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/loader/testing/test_loader_factory.h"
#include "third_party/blink/renderer/platform/loader/testing/test_resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {

namespace {

using MimeTypeCheck = AllowedByNosniff::MimeTypeCheck;
using WebFeature = mojom::WebFeature;
using WebDXFeature = mojom::blink::WebDXFeature;
using ::testing::_;

class MockUseCounter : public GarbageCollected<MockUseCounter>,
                       public UseCounter {
 public:
  static MockUseCounter* Create() {
    return MakeGarbageCollected<testing::StrictMock<MockUseCounter>>();
  }

  MOCK_METHOD1(CountUse, void(WebFeature));
  MOCK_METHOD1(CountWebDXFeature, void(WebDXFeature));
  MOCK_METHOD1(CountDeprecation, void(WebFeature));
};

class MockConsoleLogger : public GarbageCollected<MockConsoleLogger>,
                          public ConsoleLogger {
 public:
  MOCK_METHOD5(AddConsoleMessageImpl,
               void(mojom::ConsoleMessageSource,
                    mojom::ConsoleMessageLevel,
                    const String&,
                    bool,
                    std::optional<mojom::ConsoleMessageCategory>));
  MOCK_METHOD2(AddConsoleMessageImpl, void(ConsoleMessage*, bool));
};

}  // namespace

class AllowedByNosniffTest : public testing::TestWithParam<bool> {
 public:
};

INSTANTIATE_TEST_SUITE_P(All, AllowedByNosniffTest, ::testing::Bool());

TEST_P(AllowedByNosniffTest, AllowedOrNot) {
  RuntimeEnabledFeaturesTestHelpers::ScopedStrictMimeTypesForWorkers feature(
      GetParam());

  struct {
    const char* mimetype;
    bool allowed;
    bool strict_allowed;
  } data[] = {
      // Supported mimetypes:
      {"text/javascript", true, true},
      {"application/javascript", true, true},
      {"text/ecmascript", true, true},

      // Blocked mimetpyes:
      {"image/png", false, false},
      {"text/csv", false, false},
      {"video/mpeg", false, false},

      // Legacy mimetypes:
      {"text/html", true, false},
      {"text/plain", true, false},
      {"application/xml", true, false},
      {"application/octet-stream", true, false},

      // Potato mimetypes:
      {"text/potato", true, false},
      {"potato/text", true, false},
      {"aaa/aaa", true, false},
      {"zzz/zzz", true, false},

      // Parameterized mime types:
      {"text/javascript; charset=utf-8", true, true},
      {"text/javascript;charset=utf-8", true, true},
      {"text/javascript;bla;bla", true, true},
      {"text/csv; charset=utf-8", false, false},
      {"text/csv;charset=utf-8", false, false},
      {"text/csv;bla;bla", false, false},

      // Funky capitalization:
      {"text/html", true, false},
      {"Text/html", true, false},
      {"text/Html", true, false},
      {"TeXt/HtMl", true, false},
      {"TEXT/HTML", true, false},
  };

  for (auto& testcase : data) {
    SCOPED_TRACE(testing::Message()
                 << "\n  mime type: " << testcase.mimetype
                 << "\n  allowed: " << (testcase.allowed ? "true" : "false")
                 << "\n  strict_allowed: "
                 << (testcase.strict_allowed ? "true" : "false"));

    const KURL url("https://bla.com/");
    MockUseCounter* use_counter = MockUseCounter::Create();
    MockConsoleLogger* logger = MakeGarbageCollected<MockConsoleLogger>();
    ResourceResponse response(url);
    response.SetHttpHeaderField(http_names::kContentType,
                                AtomicString(testcase.mimetype));

    EXPECT_CALL(*use_counter, CountUse(_)).Times(::testing::AnyNumber());
    if (!testcase.allowed)
      EXPECT_CALL(*logger, AddConsoleMessageImpl(_, _, _, _, _));
    EXPECT_EQ(testcase.allowed, AllowedByNosniff::MimeTypeAsScript(
                                    *use_counter, logger, response,
                                    MimeTypeCheck::kLaxForElement));
    ::testing::Mock::VerifyAndClear(use_counter);

    EXPECT_CALL(*use_counter, CountUse(_)).Times(::testing::AnyNumber());
    bool expect_allowed =
        RuntimeEnabledFeatures::StrictMimeTypesForWorkersEnabled()
            ? testcase.strict_allowed
            : testcase.allowed;
    if (!expect_allowed)
      EXPECT_CALL(*logger, AddConsoleMessageImpl(_, _, _, _, _));
    EXPECT_EQ(expect_allowed,
              AllowedByNosniff::MimeTypeAsScript(*use_counter, logger, response,
                                                 MimeTypeCheck::kLaxForWorker));
    ::testing::Mock::VerifyAndClear(use_counter);

    EXPECT_CALL(*use_counter, CountUse(_)).Times(::testing::AnyNumber());
    if (!testcase.strict_allowed)
      EXPECT_CALL(*logger, AddConsoleMessageImpl(_, _, _, _, _));
    EXPECT_EQ(testcase.strict_allowed,
              AllowedByNosniff::MimeTypeAsScript(*use_counter, logger, response,
                                                 MimeTypeCheck::kStrict));
    ::testing::Mock::VerifyAndClear(use_counter);
  }
}

TEST_P(AllowedByNosniffTest, Counters) {
  RuntimeEnabledFeaturesTestHelpers::ScopedStrictMimeTypesForWorkers feature(
      GetParam());

  constexpr auto kBasic = network::mojom::FetchResponseType::kBasic;
  constexpr auto kOpaque = network::mojom::FetchResponseType::kOpaque;
  constexpr auto kCors = network::mojom::FetchResponseType::kCors;
  const char* bla = "https://bla.com";
  const char* blubb = "https://blubb.com";
  struct {
    const char* url;
    const char* origin;
    const char* mimetype;
    network::mojom::FetchResponseType response_type;
    WebFeature expected;
  } data[] = {
      // Test same- vs cross-origin cases.
      {bla, "", "text/plain", kOpaque, WebFeature::kCrossOriginTextScript},
      {bla, "", "text/plain", kCors, WebFeature::kCrossOriginTextPlain},
      {bla, blubb, "text/plain", kCors, WebFeature::kCrossOriginTextScript},
      {bla, blubb, "text/plain", kOpaque, WebFeature::kCrossOriginTextPlain},
      {bla, bla, "text/plain", kBasic, WebFeature::kSameOriginTextScript},
      {bla, bla, "text/plain", kBasic, WebFeature::kSameOriginTextPlain},
      {bla, bla, "text/json", kBasic, WebFeature::kSameOriginTextScript},

      // JSON
      {bla, bla, "text/json", kBasic, WebFeature::kSameOriginJsonTypeForScript},
      {bla, bla, "application/json", kBasic,
       WebFeature::kSameOriginJsonTypeForScript},
      {bla, blubb, "text/json", kOpaque,
       WebFeature::kCrossOriginJsonTypeForScript},
      {bla, blubb, "application/json", kOpaque,
       WebFeature::kCrossOriginJsonTypeForScript},

      // Test mime type and subtype handling.
      {bla, bla, "text/xml", kBasic, WebFeature::kSameOriginTextScript},
      {bla, bla, "text/xml", kBasic, WebFeature::kSameOriginTextXml},

      // Test mime types from crbug.com/765544, with random cross/same site
      // origins.
      {bla, bla, "text/plain", kBasic, WebFeature::kSameOriginTextPlain},
      {bla, bla, "text/xml", kOpaque, WebFeature::kCrossOriginTextXml},
      {blubb, blubb, "application/octet-stream", kBasic,
       WebFeature::kSameOriginApplicationOctetStream},
      {blubb, blubb, "application/xml", kCors,
       WebFeature::kCrossOriginApplicationXml},
      {bla, bla, "text/html", kBasic, WebFeature::kSameOriginTextHtml},

      // Unknown
      {bla, bla, "not/script", kBasic,
       WebFeature::kSameOriginStrictNosniffWouldBlock},
      {bla, blubb, "not/script", kOpaque,
       WebFeature::kCrossOriginStrictNosniffWouldBlock},
  };

  for (auto& testcase : data) {
    SCOPED_TRACE(testing::Message()
                 << "\n  url: " << testcase.url << "\n  origin: "
                 << testcase.origin << "\n  mime type: " << testcase.mimetype
                 << "\n response type: " << testcase.response_type
                 << "\n  webfeature: " << testcase.expected);
    MockUseCounter* use_counter = MockUseCounter::Create();
    MockConsoleLogger* logger = MakeGarbageCollected<MockConsoleLogger>();
    ResourceResponse response(KURL(testcase.url));
    response.SetType(testcase.response_type);
    response.SetHttpHeaderField(http_names::kContentType,
                                AtomicString(testcase.mimetype));

    EXPECT_CALL(*use_counter, CountUse(testcase.expected));
    EXPECT_CALL(*use_counter, CountUse(::testing::Ne(testcase.expected)))
        .Times(::testing::AnyNumber());
    AllowedByNosniff::MimeTypeAsScript(*use_counter, logger, response,
                                       MimeTypeCheck::kLaxForElement);
    ::testing::Mock::VerifyAndClear(use_counter);

    // kLaxForWorker should (by default) behave the same as kLaxForElement,
    // but should behave like kStrict if StrictMimeTypesForWorkersEnabled().
    // So in the strict case we'll expect the counter calls only if it's a
    // legitimate script.
    bool expect_worker_lax =
        (testcase.expected == WebFeature::kCrossOriginTextScript ||
         testcase.expected == WebFeature::kSameOriginTextScript) ||
        !RuntimeEnabledFeatures::StrictMimeTypesForWorkersEnabled();
    EXPECT_CALL(*use_counter, CountUse(testcase.expected))
        .Times(expect_worker_lax);
    EXPECT_CALL(*use_counter, CountUse(::testing::Ne(testcase.expected)))
        .Times(::testing::AnyNumber());
    AllowedByNosniff::MimeTypeAsScript(*use_counter, logger, response,
                                       MimeTypeCheck::kLaxForWorker);
    ::testing::Mock::VerifyAndClear(use_counter);

    // The kStrictMimeTypeChecksWouldBlockWorker counter should only be active
    // is "lax" checking for workers is enabled.
    EXPECT_CALL(*use_counter,
                CountUse(WebFeature::kStrictMimeTypeChecksWouldBlockWorker))
        .Times(!RuntimeEnabledFeatures::StrictMimeTypesForWorkersEnabled());
    EXPECT_CALL(*use_counter,
                CountUse(::testing::Ne(
                    WebFeature::kStrictMimeTypeChecksWouldBlockWorker)))
        .Times(::testing::AnyNumber());
    AllowedByNosniff::MimeTypeAsScript(*use_counter, logger, response,
                                       MimeTypeCheck::kLaxForWorker);
    ::testing::Mock::VerifyAndClear(use_counter);
  }
}

TEST_P(AllowedByNosniffTest, AllTheSchemes) {
  RuntimeEnabledFeaturesTestHelpers::ScopedStrictMimeTypesForWorkers feature(
      GetParam());

  // We test various URL schemes.
  // To force a decision based on the scheme, we give all responses an
  // invalid Content-Type plus a "nosniff" header. That way, all Content-Type
  // based checks are always denied and we can test for whether this is decided
  // based on the URL or not.
  struct {
    const char* url;
    bool allowed;
  } data[] = {
      {"http://example.com/bla.js", false},
      {"https://example.com/bla.js", false},
      {"file://etc/passwd.js", true},
      {"file://etc/passwd", false},
      {"chrome://dino/dino.js", true},
      {"chrome://dino/dino.css", false},
      {"ftp://example.com/bla.js", true},
      {"ftp://example.com/bla.txt", false},

      {"file://home/potato.txt", false},
      {"file://home/potato.js", true},
      {"file://home/potato.mjs", true},
      {"chrome://dino/dino.mjs", true},

      // `blob:` and `filesystem:` are excluded:
      {"blob:https://example.com/bla.js", true},
      {"blob:https://example.com/bla.txt", true},
      {"filesystem:https://example.com/temporary/bla.js", true},
      {"filesystem:https://example.com/temporary/bla.txt", true},
  };

  for (auto& testcase : data) {
    auto* use_counter = MockUseCounter::Create();
    MockConsoleLogger* logger = MakeGarbageCollected<MockConsoleLogger>();
    EXPECT_CALL(*logger, AddConsoleMessageImpl(_, _, _, _, _))
        .Times(::testing::AnyNumber());
    SCOPED_TRACE(testing::Message() << "\n  url: " << testcase.url
                                    << "\n  allowed: " << testcase.allowed);
    ResourceResponse response(KURL(testcase.url));
    response.SetHttpHeaderField(http_names::kContentType,
                                AtomicString("invalid"));
    response.SetHttpHeaderField(http_names::kXContentTypeOptions,
                                AtomicString("nosniff"));
    EXPECT_EQ(testcase.allowed,
              AllowedByNosniff::MimeTypeAsScript(*use_counter, logger, response,
                                                 MimeTypeCheck::kStrict));
    EXPECT_EQ(testcase.allowed, AllowedByNosniff::MimeTypeAsScript(
                                    *use_counter, logger, response,
                                    MimeTypeCheck::kLaxForElement));
    EXPECT_EQ(testcase.allowed,
              AllowedByNosniff::MimeTypeAsScript(*use_counter, logger, response,
                                                 MimeTypeCheck::kLaxForWorker));
  }
}

TEST(AllowedByNosniffTest, XMLExternalEntity) {
  MockConsoleLogger* logger = MakeGarbageCollected<MockConsoleLogger>();

  {
    ResourceResponse response(KURL("https://example.com/"));
    EXPECT_TRUE(
        AllowedByNosniff::MimeTypeAsXMLExternalEntity(logger, response));
  }

  {
    ResourceResponse response(KURL("https://example.com/"));
    response.SetHttpHeaderField(http_names::kContentType,
                                AtomicString("text/plain"));
    EXPECT_TRUE(
        AllowedByNosniff::MimeTypeAsXMLExternalEntity(logger, response));
  }

  {
    ResourceResponse response(KURL("https://example.com/"));
    response.SetHttpHeaderField(http_names::kXContentTypeOptions,
                                AtomicString("nosniff"));
    EXPECT_CALL(*logger, AddConsoleMessageImpl(_, _, _, _, _));
    EXPECT_FALSE(
        AllowedByNosniff::MimeTypeAsXMLExternalEntity(logger, response));
  }

  {
    ResourceResponse response(KURL("https://example.com/"));
    response.SetHttpHeaderField(http_names::kContentType,
                                AtomicString("text/plain"));
    response.SetHttpHeaderField(http_names::kXContentTypeOptions,
                                AtomicString("nosniff"));
    EXPECT_CALL(*logger, AddConsoleMessageImpl(_, _, _, _, _));
    EXPECT_FALSE(
        AllowedByNosniff::MimeTypeAsXMLExternalEntity(logger, response));
  }

  {
    ResourceResponse response(KURL("https://example.com/"));
    response.SetHttpHeaderField(
        http_names::kContentType,
        AtomicString("application/xml-external-parsed-entity"));
    response.SetHttpHeaderField(http_names::kXContentTypeOptions,
                                AtomicString("nosniff"));
    EXPECT_TRUE(
        AllowedByNosniff::MimeTypeAsXMLExternalEntity(logger, response));
  }

  {
    ResourceResponse response(KURL("https://example.com/"));
    response.SetHttpHeaderField(
        http_names::kContentType,
        AtomicString("text/xml-external-parsed-entity"));
    response.SetHttpHeaderField(http_names::kXContentTypeOptions,
                                AtomicString("nosniff"));
    EXPECT_TRUE(
        AllowedByNosniff::MimeTypeAsXMLExternalEntity(logger, response));
  }
}

}  // namespace blink
```