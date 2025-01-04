Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Initial Understanding - What is this?**

The first step is to recognize that this is a C++ file (`.cc`) located within the Chromium/Blink codebase. The path `blink/renderer/core/fetch/fetch_response_data_test.cc` gives a strong hint: it's a test file related to fetching and response data. The `_test.cc` suffix is a standard convention for test files.

**2. High-Level Purpose - Testing `FetchResponseData`**

The `#include "third_party/blink/renderer/core/fetch/fetch_response_data.h"` is the key. This tells us the file is designed to test the functionality of the `FetchResponseData` class.

**3. Dissecting the Test Structure - Google Test Framework**

The presence of `#include "testing/gtest/include/gtest/gtest.h"` immediately reveals that this uses the Google Test (gtest) framework. This means we should expect test fixtures (`TEST_F`), assertions (`EXPECT_EQ`, `ASSERT_TRUE`, `EXPECT_FALSE`), and a general structure for defining test cases.

**4. Analyzing Individual Tests - Identifying Functionality**

Now, the core work is to go through each `TEST_F` and understand what it's testing. For each test, ask:

* **What is being set up?** (e.g., creating a `FetchResponseData` object, setting headers)
* **What action is being performed?** (e.g., filtering the response, converting to `FetchAPIResponse`)
* **What is being asserted?** (e.g., checking header values, response types)

Let's walk through a few examples:

* **`HeaderList`:** This test creates a response, sets some headers, and then verifies that the `HeaderList` can correctly retrieve those header values. This directly tests the basic functionality of managing response headers.

* **`ToFetchAPIResponseDefaultType`:** This test demonstrates the conversion of `FetchResponseData` to a `mojom::blink::FetchAPIResponse` with the default response type. It also checks if the headers are correctly transferred. This links the internal representation to the external API used in Blink's communication.

* **`BasicFilter`, `CorsFilter`, `OpaqueFilter`, `OpaqueRedirectFilter`:** These tests focus on the different filtering mechanisms applied to responses. They examine which headers are retained or removed after filtering, reflecting the security policies and restrictions of different fetch modes. The setup involves creating an "internal" response and then applying a specific filter. The assertions then check the resulting headers.

* **`ToFetchAPIResponseCorsType`, `ToFetchAPIResponseOpaqueType`, `ToFetchAPIResponseOpaqueRedirectType`:** These tests verify that the filtering operations correctly set the `response_type` in the `FetchAPIResponse`.

* **`ContentSecurityPolicy`:** This test specifically checks how Content Security Policy headers are parsed and stored within the `FetchAPIResponse`.

* **`AuthChallengeInfo`:** This tests the handling of authentication challenges associated with the response.

**5. Connecting to Web Concepts (JavaScript, HTML, CSS)**

Now, the crucial step is to relate these internal C++ functionalities to the user-facing web technologies:

* **JavaScript `fetch()` API:**  The `FetchResponseData` is a core part of how Blink handles the results of `fetch()` requests. The filtering mechanisms directly influence what data is available to JavaScript.
* **HTTP Headers:**  The tests heavily involve HTTP headers. These headers are fundamental to how browsers and servers communicate, affecting caching, security (CORS, CSP), and other aspects of web functionality.
* **CORS (Cross-Origin Resource Sharing):** The `CorsFilter` tests directly relate to the browser's implementation of CORS, ensuring that cross-origin requests are handled securely according to the server's directives.
* **CSP (Content Security Policy):** The `ContentSecurityPolicy` test directly links to the browser's enforcement of CSP, which protects against various attacks.
* **Cookies:**  The manipulation of "set-cookie" headers in the filtering tests is relevant to how cookies are handled in cross-origin scenarios.

**6. Logical Reasoning (Input/Output)**

For the filtering tests, we can define simple input/output scenarios:

* **Input (Internal Response):** Headers: `set-cookie: foo`, `bar: bar`, `cache-control: no-cache`
* **Output (Basic Filter):** Headers: `bar: bar`, `cache-control: no-cache` (assuming `set-cookie` is filtered out).
* **Output (CORS Filter - no exposed headers):** Headers: `cache-control: no-cache` (assuming both `set-cookie` and `bar` are filtered).
* **Output (Opaque Filter):** No headers.

**7. User/Programming Errors**

Think about how a developer might misuse the `fetch()` API or misconfigure server responses:

* **Incorrect CORS configuration on the server:**  The `CorsFilter` tests highlight how Blink enforces CORS. A misconfigured server might not send the necessary `Access-Control-Allow-Origin` header, leading to a blocked request.
* **Misunderstanding opaque responses:** Developers might not realize that opaque responses have limited access to headers, leading to unexpected behavior in their JavaScript code.
* **Not handling authentication challenges:** The `AuthChallengeInfo` test relates to how browsers handle authentication. Developers might need to implement logic to respond to authentication challenges.

**8. Debugging Clues - User Actions**

Consider the user's perspective:

* **User clicks a link or submits a form:** This might trigger a navigation or a `fetch()` request in the background.
* **JavaScript code makes a `fetch()` call:** This is a direct way to initiate the fetching process.
* **Browser encounters a cross-origin resource:**  This will involve CORS checks and potentially the application of CORS filtering.

By tracing these user actions, you can see how they lead to the execution of the fetch logic within Blink, eventually involving the `FetchResponseData` and its filtering mechanisms.

**Self-Correction/Refinement during the process:**

* **Initially, I might have just listed the tests without fully explaining their purpose.**  The correction is to be more explicit about *what* each test is verifying.
* **I might have missed the connection to specific web concepts.** The refinement is to actively think about how these low-level C++ details manifest in the behavior of web pages.
* **The initial input/output scenarios might be too simplistic.**  The correction is to consider different filtering scenarios and the impact of headers like `Access-Control-Expose-Headers`.

This detailed breakdown demonstrates a systematic approach to understanding and explaining a C++ test file within a complex project like Chromium. It involves understanding the code itself, its purpose, and its connections to higher-level web technologies and user interactions.
这个C++文件 `fetch_response_data_test.cc` 是 Chromium Blink 引擎中用于测试 `FetchResponseData` 类的功能。`FetchResponseData` 类负责存储和处理从网络请求返回的响应数据。

以下是该文件的功能分解：

**核心功能：测试 `FetchResponseData` 类的各种方法和行为**

该文件包含多个使用 Google Test 框架编写的测试用例 (`TEST_F`)，每个测试用例针对 `FetchResponseData` 类的特定功能进行验证。

**具体测试的功能点包括：**

1. **`HeaderList`**:
   - **功能:** 测试 `FetchResponseData` 对象中存储的 HTTP 头部列表 (`FetchHeaderList`) 的基本操作，例如添加、获取头部信息。
   - **与 Web 功能的关系:**  HTTP 头部是 Web 交互的基础，例如 `set-cookie` 用于设置 Cookie，`cache-control` 用于控制缓存行为。
   - **假设输入与输出:**
     - **假设输入:** 创建一个 `FetchResponseData` 对象，并添加了 "set-cookie: foo", "bar: bar", "cache-control: no-cache" 这三个头部。
     - **预期输出:**  通过 `HeaderList()->Get()` 方法能够分别获取到 "foo", "bar", "no-cache" 这三个值。

2. **`ToFetchAPIResponseDefaultType`**:
   - **功能:** 测试将 `FetchResponseData` 对象转换为 `mojom::blink::FetchAPIResponse` 这种 IPC (Inter-Process Communication) 消息格式的过程，并且验证默认的响应类型 (`network::mojom::FetchResponseType::kDefault`) 是否正确设置。
   - **与 Web 功能的关系:** `FetchAPIResponse` 是 Blink 进程与网络进程之间传递响应数据的结构，包含了响应的状态码、头部、主体等信息。JavaScript 中的 `fetch()` API 返回的 Response 对象最终会基于这个结构构建。
   - **假设输入与输出:**
     - **假设输入:** 一个包含特定头部信息的 `FetchResponseData` 对象。
     - **预期输出:**  转换后的 `FetchAPIResponse` 对象的 `response_type` 字段为 `kDefault`，并且包含了原始的头部信息。

3. **各种过滤器的测试 (`BasicFilter`, `CorsFilter`, `OpaqueFilter`, `OpaqueRedirectFilter`)**:
   - **功能:** 测试不同类型的响应过滤器如何修改 `FetchResponseData` 对象中的头部信息。这些过滤器用于实现不同的安全策略和跨域访问控制 (CORS)。
   - **与 Web 功能的关系:**
     - **Basic Filter:** 用于处理同源的简单请求。
     - **CORS Filter:** 用于处理跨域请求，根据服务器返回的 CORS 头部决定哪些信息可以暴露给 JavaScript。
     - **Opaque Filter:**  用于处理某些安全场景下的响应，隐藏大部分头部信息。
     - **Opaque Redirect Filter:** 用于处理某些安全场景下的重定向响应，也隐藏大部分头部信息。
   - **假设输入与输出 (以 `BasicFilter` 为例):**
     - **假设输入:** 一个包含 "set-cookie", "bar", "cache-control" 头部的 `FetchResponseData` 对象。
     - **预期输出:** 经过 `CreateBasicFilteredResponse()` 过滤后，新的 `FetchResponseData` 对象不再包含 "set-cookie" 头部，但保留了 "bar" 和 "cache-control" 头部。

4. **`ToFetchAPIResponseBasicType`, `ToFetchAPIResponseCorsType`, `ToFetchAPIResponseOpaqueType`, `ToFetchAPIResponseOpaqueRedirectType`**:
   - **功能:** 测试将经过不同类型过滤器处理后的 `FetchResponseData` 对象转换为 `FetchAPIResponse` 时，`response_type` 字段是否被正确设置为对应的类型 (`kBasic`, `kCors`, `kOpaque`, `kOpaqueRedirect`)。
   - **与 Web 功能的关系:**  `response_type` 影响着 JavaScript 中 `Response` 对象的属性和行为，例如是否可以读取头部信息。

5. **`DefaultResponseTime`**:
   - **功能:** 验证 `FetchResponseData` 对象创建时，是否会设置一个默认的响应时间。
   - **与 Web 功能的关系:** 响应时间可以用于性能分析和监控。

6. **`ContentSecurityPolicy`**:
   - **功能:** 测试 `FetchResponseData` 对象如何解析和存储 Content Security Policy (CSP) 头部信息。
   - **与 Web 功能的关系:** CSP 是一种重要的安全机制，允许网站声明浏览器可以加载哪些来源的内容，从而防止跨站脚本攻击 (XSS) 等安全问题。
   - **假设输入与输出:**
     - **假设输入:**  一个包含 "content-security-policy: frame-ancestors 'none'" 和 "content-security-policy-report-only: frame-ancestors 'none'" 两个 CSP 头部的 `FetchResponseData` 对象。
     - **预期输出:** 转换后的 `FetchAPIResponse` 对象的 `parsed_headers->content_security_policy` 列表中包含两个 CSP 指令对象，分别对应 enforce 和 report-only 模式。

7. **`AuthChallengeInfo`**:
   - **功能:** 测试 `FetchResponseData` 对象如何存储和传递身份验证质询信息。
   - **与 Web 功能的关系:** 当服务器需要身份验证时，会发送包含质询信息的头部，浏览器需要处理这些信息并可能提示用户输入凭据。
   - **假设输入与输出:**
     - **假设输入:**  创建一个 `FetchResponseData` 对象，并设置了一个包含 `is_proxy = true` 和 `challenge = "foobar"` 的 `net::AuthChallengeInfo`。
     - **预期输出:** 转换后的 `FetchAPIResponse` 对象的 `auth_challenge_info` 字段包含了与输入相同的身份验证质询信息。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript `fetch()` API:** 当 JavaScript 代码使用 `fetch()` 发起网络请求时，Blink 引擎会创建 `FetchResponseData` 对象来存储服务器返回的响应数据。过滤器会影响 JavaScript 代码最终能访问到的响应头部。例如，如果是一个跨域请求且服务器没有正确设置 CORS 头部，`CorsFilter` 会移除一些头部信息，导致 JavaScript 代码无法通过 `response.headers.get()` 获取到这些头部。
* **HTML `<link>` 标签和 CSS:** 当浏览器解析 HTML 并遇到 `<link>` 标签加载 CSS 文件时，也会发起网络请求。`FetchResponseData` 同样用于处理 CSS 文件的响应。`cache-control` 头部会影响浏览器如何缓存 CSS 文件，从而影响页面的加载速度。CSP 头部则会限制 CSS 文件中可以使用哪些特性，例如是否允许使用 `unsafe-inline` 样式。
* **HTML `<img>` 标签和 JavaScript 图片加载:** 加载图片资源也涉及到网络请求和响应处理。`FetchResponseData` 用于存储图片资源的响应信息。CORS 头部会影响跨域图片资源是否可以被 Canvas 或 WebGL 使用。

**用户或编程常见的使用错误举例说明:**

* **CORS 错误:** 用户在一个域名的网页上尝试通过 JavaScript 的 `fetch()` API 请求另一个域名的资源，但服务器没有设置正确的 CORS 头部 (例如缺少 `Access-Control-Allow-Origin`)。这时，`CorsFilter` 会阻止 JavaScript 代码访问响应数据，开发者会在浏览器的控制台中看到 CORS 相关的错误信息。
  - **用户操作步骤:**
    1. 用户访问 `http://example.com` 的网页。
    2. 该网页的 JavaScript 代码尝试 `fetch('http://api.another-domain.com/data')`。
    3. 如果 `http://api.another-domain.com` 的服务器没有设置 `Access-Control-Allow-Origin: http://example.com` (或 `*`) 头部，`CorsFilter` 会阻止响应。
* **CSP 错误:**  网站设置了严格的 CSP 策略，例如禁止加载来自外部域名的脚本。如果用户安装了一个恶意浏览器插件，该插件尝试注入来自未知源的 JavaScript 代码，浏览器会根据 CSP 策略阻止该脚本的执行，并在控制台中报告 CSP 违规。
  - **用户操作步骤:**
    1. 用户访问一个设置了 CSP 的网页。
    2. 用户安装了一个恶意浏览器插件。
    3. 插件尝试注入 `<script src="http://malicious.com/evil.js"></script>` 到页面中。
    4. 如果页面的 CSP 策略中没有允许加载来自 `http://malicious.com` 的脚本，浏览器会阻止该脚本的加载。
* **缓存问题:** 开发者错误地设置了 `cache-control` 头部，导致资源被意外地缓存或无法缓存，影响用户体验。例如，设置了 `cache-control: no-cache` 但期望浏览器能够缓存资源。
  - **用户操作步骤:**
    1. 开发者将一个图片资源的 `cache-control` 头部设置为 `no-cache`。
    2. 用户第一次访问包含该图片的网页，浏览器下载图片。
    3. 用户刷新页面，浏览器仍然需要重新下载图片，而不是使用缓存，因为 `no-cache` 指示浏览器在使用缓存前需要向服务器验证。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入网址或点击链接：** 这会触发浏览器发起一个或多个网络请求。
2. **浏览器网络模块处理请求：**  网络模块会根据请求的 URL、头部等信息发送 HTTP 请求到服务器。
3. **服务器响应请求：** 服务器返回包含状态码、头部和响应体的 HTTP 响应。
4. **Blink 引擎接收响应：** Blink 引擎的网络层接收到服务器的响应数据。
5. **创建 `FetchResponseData` 对象：** Blink 引擎会创建一个 `FetchResponseData` 对象来存储接收到的响应数据，包括状态码、头部等。
6. **应用过滤器：** 根据请求的类型 (例如是否跨域)，会应用相应的过滤器 (例如 `CorsFilter`) 来处理响应头部。
7. **转换为 `FetchAPIResponse`：**  `FetchResponseData` 对象会被转换为 `mojom::blink::FetchAPIResponse` 消息，用于在 Blink 进程内部传递响应信息。
8. **传递给渲染进程：**  `FetchAPIResponse` 消息会被传递给渲染进程。
9. **创建 JavaScript `Response` 对象：** 渲染进程会基于 `FetchAPIResponse` 的信息创建一个 JavaScript 的 `Response` 对象，供网页的 JavaScript 代码使用。

**调试线索:**

如果在开发过程中遇到与网络请求响应相关的问题，例如：

* **JavaScript 代码无法获取到预期的响应头部:** 可以检查 `FetchResponseData` 的过滤逻辑，查看哪些头部被移除了。
* **CORS 错误:** 可以检查 `CorsFilter` 的实现，验证是否正确地根据服务器返回的 CORS 头部进行过滤。
* **CSP 违规:** 可以检查 `FetchResponseData` 中 CSP 头部的解析和存储逻辑，以及浏览器如何根据存储的 CSP 策略进行内容拦截。

因此，`fetch_response_data_test.cc` 文件通过全面的测试用例，确保了 `FetchResponseData` 类的正确性和可靠性，这对于 Blink 引擎处理网络请求和保障 Web 安全至关重要。它也为开发者提供了理解 Blink 内部工作原理和排查相关问题的线索。

Prompt: 
```
这是目录为blink/renderer/core/fetch/fetch_response_data_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fetch/fetch_response_data.h"

#include "base/test/scoped_feature_list.h"
#include "services/network/public/cpp/features.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_response.mojom-blink.h"
#include "third_party/blink/renderer/core/fetch/fetch_header_list.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

class FetchResponseDataTest : public testing::Test {
 public:
  FetchResponseData* CreateInternalResponse() {
    FetchResponseData* internal_response = FetchResponseData::Create();
    internal_response->SetStatus(200);
    Vector<KURL> url_list;
    url_list.push_back(KURL("http://www.example.com"));
    internal_response->SetURLList(url_list);
    internal_response->HeaderList()->Append("set-cookie", "foo");
    internal_response->HeaderList()->Append("bar", "bar");
    internal_response->HeaderList()->Append("cache-control", "no-cache");
    return internal_response;
  }

  void CheckHeaders(const mojom::blink::FetchAPIResponse& response) {
    EXPECT_EQ("foo", response.headers.at("set-cookie"));
    EXPECT_EQ("bar", response.headers.at("bar"));
    EXPECT_EQ("no-cache", response.headers.at("cache-control"));
  }
};

TEST_F(FetchResponseDataTest, HeaderList) {
  FetchResponseData* response_data = CreateInternalResponse();

  String set_cookie_value;
  ASSERT_TRUE(response_data->HeaderList()->Get("set-cookie", set_cookie_value));
  EXPECT_EQ("foo", set_cookie_value);

  String bar_value;
  ASSERT_TRUE(response_data->HeaderList()->Get("bar", bar_value));
  EXPECT_EQ("bar", bar_value);

  String cache_control_value;
  ASSERT_TRUE(
      response_data->HeaderList()->Get("cache-control", cache_control_value));
  EXPECT_EQ("no-cache", cache_control_value);
}

TEST_F(FetchResponseDataTest, ToFetchAPIResponseDefaultType) {
  FetchResponseData* internal_response = CreateInternalResponse();

  mojom::blink::FetchAPIResponsePtr fetch_api_response =
      internal_response->PopulateFetchAPIResponse(KURL());
  EXPECT_EQ(network::mojom::FetchResponseType::kDefault,
            fetch_api_response->response_type);
  CheckHeaders(*fetch_api_response);
}

TEST_F(FetchResponseDataTest, BasicFilter) {
  FetchResponseData* internal_response = CreateInternalResponse();
  FetchResponseData* basic_response_data =
      internal_response->CreateBasicFilteredResponse();

  EXPECT_EQ(internal_response, basic_response_data->InternalResponse());

  EXPECT_FALSE(basic_response_data->HeaderList()->Has("set-cookie"));

  String bar_value;
  ASSERT_TRUE(basic_response_data->HeaderList()->Get("bar", bar_value));
  EXPECT_EQ("bar", bar_value);

  String cache_control_value;
  ASSERT_TRUE(basic_response_data->HeaderList()->Get("cache-control",
                                                     cache_control_value));
  EXPECT_EQ("no-cache", cache_control_value);
}

TEST_F(FetchResponseDataTest, ToFetchAPIResponseBasicType) {
  FetchResponseData* internal_response = CreateInternalResponse();
  FetchResponseData* basic_response_data =
      internal_response->CreateBasicFilteredResponse();

  mojom::blink::FetchAPIResponsePtr fetch_api_response =
      basic_response_data->PopulateFetchAPIResponse(KURL());
  EXPECT_EQ(network::mojom::FetchResponseType::kBasic,
            fetch_api_response->response_type);
  CheckHeaders(*fetch_api_response);
}

TEST_F(FetchResponseDataTest, CorsFilter) {
  FetchResponseData* internal_response = CreateInternalResponse();
  FetchResponseData* cors_response_data =
      internal_response->CreateCorsFilteredResponse(HTTPHeaderSet());

  EXPECT_EQ(internal_response, cors_response_data->InternalResponse());

  EXPECT_FALSE(cors_response_data->HeaderList()->Has("set-cookie"));

  EXPECT_FALSE(cors_response_data->HeaderList()->Has("bar"));

  String cache_control_value;
  ASSERT_TRUE(cors_response_data->HeaderList()->Get("cache-control",
                                                    cache_control_value));
  EXPECT_EQ("no-cache", cache_control_value);
}

TEST_F(FetchResponseDataTest,
       CorsFilterOnResponseWithAccessControlExposeHeaders) {
  FetchResponseData* internal_response = CreateInternalResponse();
  internal_response->HeaderList()->Append("access-control-expose-headers",
                                          "set-cookie, bar");

  FetchResponseData* cors_response_data =
      internal_response->CreateCorsFilteredResponse({"set-cookie", "bar"});

  EXPECT_EQ(internal_response, cors_response_data->InternalResponse());

  EXPECT_FALSE(cors_response_data->HeaderList()->Has("set-cookie"));

  String bar_value;
  ASSERT_TRUE(cors_response_data->HeaderList()->Get("bar", bar_value));
  EXPECT_EQ("bar", bar_value);
}

TEST_F(FetchResponseDataTest, CorsFilterWithEmptyHeaderSet) {
  FetchResponseData* internal_response = CreateInternalResponse();
  FetchResponseData* cors_response_data =
      internal_response->CreateCorsFilteredResponse(HTTPHeaderSet());

  EXPECT_EQ(internal_response, cors_response_data->InternalResponse());

  EXPECT_FALSE(cors_response_data->HeaderList()->Has("set-cookie"));

  EXPECT_FALSE(cors_response_data->HeaderList()->Has("bar"));

  String cache_control_value;
  ASSERT_TRUE(cors_response_data->HeaderList()->Get("cache-control",
                                                    cache_control_value));
  EXPECT_EQ("no-cache", cache_control_value);
}

TEST_F(FetchResponseDataTest,
       CorsFilterWithEmptyHeaderSetOnResponseWithAccessControlExposeHeaders) {
  FetchResponseData* internal_response = CreateInternalResponse();
  internal_response->HeaderList()->Append("access-control-expose-headers",
                                          "set-cookie, bar");

  FetchResponseData* cors_response_data =
      internal_response->CreateCorsFilteredResponse(HTTPHeaderSet());

  EXPECT_EQ(internal_response, cors_response_data->InternalResponse());

  EXPECT_FALSE(cors_response_data->HeaderList()->Has("set-cookie"));

  EXPECT_FALSE(cors_response_data->HeaderList()->Has("bar"));

  String cache_control_value;
  ASSERT_TRUE(cors_response_data->HeaderList()->Get("cache-control",
                                                    cache_control_value));
  EXPECT_EQ("no-cache", cache_control_value);
}

TEST_F(FetchResponseDataTest, CorsFilterWithExplicitHeaderSet) {
  FetchResponseData* internal_response = CreateInternalResponse();
  HTTPHeaderSet exposed_headers;
  exposed_headers.insert("set-cookie");
  exposed_headers.insert("bar");

  FetchResponseData* cors_response_data =
      internal_response->CreateCorsFilteredResponse(exposed_headers);

  EXPECT_EQ(internal_response, cors_response_data->InternalResponse());

  EXPECT_FALSE(cors_response_data->HeaderList()->Has("set-cookie"));

  String bar_value;
  ASSERT_TRUE(cors_response_data->HeaderList()->Get("bar", bar_value));
  EXPECT_EQ("bar", bar_value);
}

TEST_F(FetchResponseDataTest, ToFetchAPIResponseCorsType) {
  FetchResponseData* internal_response = CreateInternalResponse();
  FetchResponseData* cors_response_data =
      internal_response->CreateCorsFilteredResponse(HTTPHeaderSet());

  mojom::blink::FetchAPIResponsePtr fetch_api_response =
      cors_response_data->PopulateFetchAPIResponse(KURL());
  EXPECT_EQ(network::mojom::FetchResponseType::kCors,
            fetch_api_response->response_type);
  CheckHeaders(*fetch_api_response);
}

TEST_F(FetchResponseDataTest, OpaqueFilter) {
  FetchResponseData* internal_response = CreateInternalResponse();
  FetchResponseData* opaque_response_data =
      internal_response->CreateOpaqueFilteredResponse();

  EXPECT_EQ(internal_response, opaque_response_data->InternalResponse());

  EXPECT_FALSE(opaque_response_data->HeaderList()->Has("set-cookie"));
  EXPECT_FALSE(opaque_response_data->HeaderList()->Has("bar"));
  EXPECT_FALSE(opaque_response_data->HeaderList()->Has("cache-control"));
}

TEST_F(FetchResponseDataTest, OpaqueRedirectFilter) {
  FetchResponseData* internal_response = CreateInternalResponse();
  FetchResponseData* opaque_response_data =
      internal_response->CreateOpaqueRedirectFilteredResponse();

  EXPECT_EQ(internal_response, opaque_response_data->InternalResponse());

  EXPECT_EQ(opaque_response_data->HeaderList()->size(), 0u);
  EXPECT_EQ(*opaque_response_data->Url(), *internal_response->Url());
}

TEST_F(FetchResponseDataTest,
       OpaqueFilterOnResponseWithAccessControlExposeHeaders) {
  FetchResponseData* internal_response = CreateInternalResponse();
  internal_response->HeaderList()->Append("access-control-expose-headers",
                                          "set-cookie, bar");

  FetchResponseData* opaque_response_data =
      internal_response->CreateOpaqueFilteredResponse();

  EXPECT_EQ(internal_response, opaque_response_data->InternalResponse());

  EXPECT_FALSE(opaque_response_data->HeaderList()->Has("set-cookie"));
  EXPECT_FALSE(opaque_response_data->HeaderList()->Has("bar"));
  EXPECT_FALSE(opaque_response_data->HeaderList()->Has("cache-control"));
}

TEST_F(FetchResponseDataTest, ToFetchAPIResponseOpaqueType) {
  FetchResponseData* internal_response = CreateInternalResponse();
  FetchResponseData* opaque_response_data =
      internal_response->CreateOpaqueFilteredResponse();

  mojom::blink::FetchAPIResponsePtr fetch_api_response =
      opaque_response_data->PopulateFetchAPIResponse(KURL());
  EXPECT_EQ(network::mojom::FetchResponseType::kOpaque,
            fetch_api_response->response_type);
  CheckHeaders(*fetch_api_response);
}

TEST_F(FetchResponseDataTest, ToFetchAPIResponseOpaqueRedirectType) {
  FetchResponseData* internal_response = CreateInternalResponse();
  FetchResponseData* opaque_redirect_response_data =
      internal_response->CreateOpaqueRedirectFilteredResponse();

  mojom::blink::FetchAPIResponsePtr fetch_api_response =
      opaque_redirect_response_data->PopulateFetchAPIResponse(KURL());
  EXPECT_EQ(network::mojom::FetchResponseType::kOpaqueRedirect,
            fetch_api_response->response_type);
  CheckHeaders(*fetch_api_response);
}

TEST_F(FetchResponseDataTest, DefaultResponseTime) {
  FetchResponseData* internal_response = CreateInternalResponse();
  EXPECT_FALSE(internal_response->ResponseTime().is_null());
}

TEST_F(FetchResponseDataTest, ContentSecurityPolicy) {
  base::test::ScopedFeatureList scoped_feature_list;
  FetchResponseData* internal_response = CreateInternalResponse();
  internal_response->HeaderList()->Append("content-security-policy",
                                          "frame-ancestors 'none'");
  internal_response->HeaderList()->Append("content-security-policy-report-only",
                                          "frame-ancestors 'none'");

  mojom::blink::FetchAPIResponsePtr fetch_api_response =
      internal_response->PopulateFetchAPIResponse(
          KURL("https://www.example.org"));
  auto& csp = fetch_api_response->parsed_headers->content_security_policy;

  EXPECT_EQ(csp.size(), 2U);
  EXPECT_EQ(csp[0]->header->type,
            network::mojom::ContentSecurityPolicyType::kEnforce);
  EXPECT_EQ(csp[1]->header->type,
            network::mojom::ContentSecurityPolicyType::kReport);
}

TEST_F(FetchResponseDataTest, AuthChallengeInfo) {
  FetchResponseData* internal_response = CreateInternalResponse();
  net::AuthChallengeInfo auth_challenge_info;
  auth_challenge_info.is_proxy = true;
  auth_challenge_info.challenge = "foobar";
  internal_response->SetAuthChallengeInfo(auth_challenge_info);

  mojom::blink::FetchAPIResponsePtr fetch_api_response =
      internal_response->PopulateFetchAPIResponse(KURL());
  ASSERT_TRUE(fetch_api_response->auth_challenge_info.has_value());
  EXPECT_TRUE(fetch_api_response->auth_challenge_info->is_proxy);
  EXPECT_EQ("foobar", fetch_api_response->auth_challenge_info->challenge);
}

}  // namespace blink

"""

```