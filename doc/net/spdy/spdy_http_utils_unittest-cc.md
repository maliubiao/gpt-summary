Response:
Let's break down the thought process for analyzing the `spdy_http_utils_unittest.cc` file.

1. **Understand the Goal:** The core request is to understand the *functionality* of this unit test file. This means looking at what it's *testing*. Unit tests generally target specific units of code, and the filename `spdy_http_utils_unittest.cc` strongly suggests it's testing `spdy_http_utils.h` (or a closely related source file).

2. **Identify the Tested Unit:**  The `#include "net/spdy/spdy_http_utils.h"` line confirms the target of the tests. So, the core function of this file is to verify the correctness of the functions and classes declared in `spdy_http_utils.h`.

3. **Scan for Test Cases:**  The file uses the Google Test framework (`TEST()`, `TEST_P()`, `INSTANTIATE_TEST_SUITE_P()`). Each `TEST()` block represents an individual test case, and `TEST_P()` indicates a parameterized test.

4. **Analyze Individual Test Cases (Mental Walkthrough):**  Go through each `TEST()` block and try to understand what it's doing. Look for:
    * **Setup:** What data is being created or prepared?  (e.g., `GURL`, `HttpRequestInfo`, `quiche::HttpHeaderBlock`).
    * **Action:** What function from `spdy_http_utils.h` is being called? (e.g., `ConvertRequestPriorityToSpdyPriority`, `CreateSpdyHeadersFromHttpRequest`, `SpdyHeadersToHttpResponse`).
    * **Assertion:** What is being checked using `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `ASSERT_OK_AND_ASSIGN`, `EXPECT_THAT`?  These assertions reveal the expected behavior of the tested function.

5. **Group Tests by Functionality:** As you analyze the tests, you'll notice patterns. Group the tests based on the function they are testing:
    * Priority conversions (`ConvertRequestPriorityToSpdyPriority`, `ConvertSpdyPriorityToRequestPriority`).
    * Creating SPDY headers from HTTP requests (`CreateSpdyHeadersFromHttpRequest`, `CreateSpdyHeadersFromHttpRequestForExtendedConnect`).
    * Converting SPDY headers to HTTP responses (`SpdyHeadersToHttpResponse`, `SpdyHeadersToHttpResponseHeaders`).

6. **Look for Parameterized Tests:**  `TEST_P()` indicates parameterized tests. Examine the `INSTANTIATE_TEST_SUITE_P()` calls to see what parameters are being used. This often indicates testing different scenarios or feature flags.

7. **Identify Relationships to JavaScript (or Lack Thereof):**  Consider if the tested functionality has any direct bearing on how JavaScript interacts with the network. In this case, SPDY/HTTP2 headers are related to how browsers communicate, which *indirectly* impacts JavaScript by affecting network performance and data received. However, the test file itself doesn't directly involve JavaScript code.

8. **Consider Logic and Assumptions:** For tests involving conversions or header creation, think about the underlying logic. What are the assumptions about input and expected output?  This leads to creating "Hypothetical Input/Output" examples.

9. **Identify Potential User/Programming Errors:** Think about how developers might misuse the functions being tested. For example, providing invalid priority values, incorrect header formats, or missing mandatory headers.

10. **Trace User Actions (Debugging):** Consider how a user action in the browser might eventually lead to this code being executed. Think about the network request lifecycle. This helps connect the low-level code to user-facing actions.

11. **Structure the Output:** Organize the findings in a clear and logical way, addressing each part of the original request:
    * Functionality description (grouping by tested function).
    * JavaScript relationship (and its indirect nature).
    * Logic/Assumptions (input/output examples).
    * User/programming errors.
    * User actions leading to the code.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This file tests SPDY functionality."  **Refinement:** Be more specific. It tests *utilities* related to SPDY and HTTP conversion within the networking stack.
* **Initial thought:** "Does this directly affect JavaScript?" **Refinement:** While JavaScript doesn't call these C++ functions directly, understanding these conversions is crucial for understanding how browser network requests work, which *does* affect JavaScript's network interactions. Emphasize the indirect relationship.
* **Missing details:** Initially, I might just list the test names. **Refinement:**  Go deeper into what each test *does* and *asserts*. This is key to understanding the functionality.
* **Clarity of Examples:**  Ensure the input/output examples are clear and directly relate to the tested functions.

By following this detailed analysis and refinement process, we can arrive at a comprehensive understanding of the `spdy_http_utils_unittest.cc` file's purpose and its place within the Chromium networking stack.
这个文件 `net/spdy/spdy_http_utils_unittest.cc` 是 Chromium 网络栈中用于测试 `net/spdy/spdy_http_utils.h` 中定义的工具函数的单元测试文件。它主要负责验证 SPDY（及其后续的 HTTP/2）协议与 HTTP 协议之间的转换和处理逻辑的正确性。

以下是该文件主要功能的详细列举：

**核心功能：测试 `net/spdy/spdy_http_utils.h` 中的工具函数，这些函数用于：**

1. **优先级转换:**
   - `ConvertRequestPriorityToSpdyPriority`: 将 Chromium 的请求优先级 (例如 `HIGHEST`, `MEDIUM`, `LOW` 等) 转换为 SPDY/3 的优先级值 (0-5)。
   - `ConvertSpdyPriorityToRequestPriority`: 将 SPDY/3 的优先级值转换回 Chromium 的请求优先级。
   - **测试用例:** `ConvertRequestPriorityToSpdy3Priority`, `ConvertSpdy3PriorityToRequestPriority`

2. **创建 SPDY/HTTP2 首部块 (Header Block) 来自 HTTP 请求信息:**
   - `CreateSpdyHeadersFromHttpRequest`: 根据 `HttpRequestInfo` 对象创建用于 SPDY/HTTP2 的首部块。这包括将 HTTP 方法、URL、首部等转换为 SPDY/HTTP2 的伪首部 (例如 `:method`, `:scheme`, `:authority`, `:path`) 和普通首部。
   - `CreateSpdyHeadersFromHttpRequestForExtendedConnect`:  专门为 HTTP 的 `CONNECT` 方法创建 SPDY/HTTP2 首部块，用于扩展 CONNECT 功能。
   - **测试用例:** `CreateSpdyHeadersFromHttpRequestHTTP2`, `CreateSpdyHeadersFromHttpRequestForExtendedConnect`, `CreateSpdyHeadersWithDefaultPriority`, `CreateSpdyHeadersWithExistingPriority`, `CreateSpdyHeadersFromHttpRequestConnectHTTP2`

3. **将 SPDY/HTTP2 首部块转换为 HTTP 响应头:**
   - `SpdyHeadersToHttpResponse`: 将 SPDY/HTTP2 的首部块转换为 `HttpResponseInfo` 对象，其中包含了 `HttpResponseHeaders`。
   - `SpdyHeadersToHttpResponseHeadersUsingRawString` 和 `SpdyHeadersToHttpResponseHeadersUsingBuilder` (通过参数化测试):  这两种方式将 SPDY/HTTP2 首部块转换为 `HttpResponseHeaders` 对象。它们可能代表了不同的实现方式或者性能优化策略。
   - **测试用例:** `SpdyHeadersToHttpResponseTest`, `SpdyHeadersToHttpResponseHeadersTest` (包括各种边缘情况，例如缺少 `:status`，多个 `Location` 首部，重复首部等)。

**与 JavaScript 的关系：**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它所测试的功能与 JavaScript 的网络请求息息相关。

* **浏览器发起请求:** 当 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起网络请求时，浏览器底层会根据协议 (HTTP/1.1, HTTP/2, QUIC) 将请求信息转换为相应的格式。对于 HTTP/2 连接，`CreateSpdyHeadersFromHttpRequest` 等函数就参与了这个转换过程，将 JavaScript 请求的信息转化为 SPDY/HTTP2 的首部块进行传输。
* **服务器响应:** 当浏览器接收到服务器的 HTTP/2 响应时，`SpdyHeadersToHttpResponse` 等函数会将 SPDY/HTTP2 的首部块转换回浏览器可以理解的 HTTP 响应头，这些头信息会被 JavaScript 通过 `Response` 对象访问。
* **优先级:** JavaScript 代码虽然不能直接设置 SPDY/HTTP2 的优先级，但浏览器会根据请求的类型和重要性（例如，图片、CSS、主文档）自动分配优先级。`ConvertRequestPriorityToSpdyPriority` 就负责将浏览器内部的优先级映射到 SPDY/HTTP2 的优先级值，影响网络资源的加载顺序。

**举例说明（与 JavaScript 的关系）：**

假设一个网页的 JavaScript 代码请求加载一个图片：

```javascript
fetch('https://example.com/image.png');
```

1. **请求发送阶段:** Chromium 的网络栈会创建一个 `HttpRequestInfo` 对象，包含请求方法 (GET)、URL (`https://example.com/image.png`) 等信息。`CreateSpdyHeadersFromHttpRequest` 函数会被调用，将这些信息转换为 SPDY/HTTP2 的首部块，例如：

   ```
   :method: GET
   :scheme: https
   :authority: example.com
   :path: /image.png
   ... 其他首部 ...
   ```

2. **响应接收阶段:** 服务器返回一个 HTTP/2 响应，其首部信息可能如下：

   ```
   :status: 200
   content-type: image/png
   cache-control: public, max-age=3600
   ... 其他首部 ...
   ```

   `SpdyHeadersToHttpResponse` 函数会被调用，将这些 SPDY/HTTP2 首部转换为 `HttpResponseHeaders` 对象，然后 JavaScript 可以通过 `Response` 对象访问这些头信息：

   ```javascript
   fetch('https://example.com/image.png')
     .then(response => {
       console.log(response.headers.get('content-type')); // 输出 "image/png"
       console.log(response.status); // 输出 200
     });
   ```

**逻辑推理（假设输入与输出）：**

**假设输入 (针对 `CreateSpdyHeadersFromHttpRequestHTTP2`):**

```c++
GURL url("https://www.example.com/path?query=value");
HttpRequestInfo request;
request.method = "POST";
request.url = url;
request.extra_headers.SetHeader("Content-Type", "application/json");
request.extra_headers.SetHeader("Custom-Header", "custom-value");
```

**期望输出 (转换后的 SPDY/HTTP2 首部块):**

```
:method: POST
:scheme: https
:authority: www.example.com
:path: /path?query=value
content-type: application/json
custom-header: custom-value
```

**假设输入 (针对 `SpdyHeadersToHttpResponse`):**

```c++
quiche::HttpHeaderBlock input;
input[spdy::kHttp2StatusHeader] = "404";
input["content-type"] = "text/plain";
input["server"] = "ExampleServer";
```

**期望输出 (`HttpResponseInfo` 对象的 `headers` 属性的字符串表示):**

```
HTTP/1.1 404
content-type: text/plain
server: ExampleServer
```

**用户或编程常见的使用错误：**

1. **在需要伪首部的地方使用了普通首部，或者反过来。** 例如，尝试在 HTTP/2 请求首部中直接设置 `Host` 首部，而不是使用 `:authority` 伪首部。`CreateSpdyHeadersFromHttpRequest` 的测试用例会验证这种转换的正确性。
2. **在 SPDY/HTTP2 响应中缺少 `:status` 伪首部。**  `SpdyHeadersToHttpResponseHeadersTest` 中的 `NoStatus` 测试用例就模拟了这种情况，并验证会返回 `ERR_INCOMPLETE_HTTP2_HEADERS` 错误。
3. **尝试在 SPDY/HTTP2 响应中设置多个 `Location` 首部。** HTTP 响应头通常只允许一个 `Location` 首部用于重定向。`SpdyHeadersToHttpResponseHeadersTest` 中的 `MultipleLocation` 测试用例验证了这种情况会返回 `ERR_RESPONSE_HEADERS_MULTIPLE_LOCATION` 错误。
4. **不理解 SPDY/HTTP2 的首部顺序要求。** 伪首部必须在普通首部之前。`CheckOrdering` 函数用于验证首部顺序的正确性。

**用户操作如何一步步到达这里（作为调试线索）：**

假设用户在浏览器中访问一个使用了 HTTP/2 协议的网站 `https://example.com/page`。

1. **用户在地址栏输入 URL 或点击链接。**
2. **浏览器解析 URL，确定需要建立到 `example.com` 的连接。**
3. **如果浏览器与 `example.com` 之间已经建立了 HTTP/2 连接，则复用该连接。否则，发起新的连接建立过程（包括 TLS 握手和 ALPN 协商，协商确定使用 HTTP/2）。**
4. **浏览器需要发送 HTTP 请求以获取 `/page` 资源。**
5. **在网络栈中，会创建一个 `HttpRequestInfo` 对象，包含请求方法 (GET)、URL (`https://example.com/page`) 等信息。**
6. **`net/spdy/spdy_http_utils.cc` 中 `CreateSpdyHeadersFromHttpRequest` 函数会被调用，将 `HttpRequestInfo` 对象转换为 SPDY/HTTP2 的首部块。**
7. **构建好的 SPDY/HTTP2 首部块会被封装成一个 HEADERS frame，并通过 HTTP/2 连接发送到服务器。**
8. **服务器处理请求，并返回一个 HTTP/2 响应，其中包含 SPDY/HTTP2 首部块。**
9. **浏览器接收到服务器的 HEADERS frame。**
10. **`net/spdy/spdy_http_utils.cc` 中的 `SpdyHeadersToHttpResponse` 或 `SpdyHeadersToHttpResponseHeaders` 函数会被调用，将接收到的 SPDY/HTTP2 首部块转换为 `HttpResponseInfo` 对象，其中包含了 HTTP 响应头。**
11. **浏览器处理响应头，并根据响应内容进行渲染或执行相应的操作（例如，将 HTML 内容渲染到页面上，将图片显示出来，执行 JavaScript 代码）。**

如果在这个过程中出现问题（例如，服务器返回了格式错误的 HTTP/2 首部），那么相关的测试用例 (`SpdyHeadersToHttpResponseHeadersTest` 中的各种情况) 可以帮助开发者定位问题所在，并确保 `spdy_http_utils.cc` 中的转换逻辑是正确的。开发者可能会在网络栈的调试日志中看到与首部转换相关的错误信息，并追踪到 `spdy_http_utils.cc` 中的代码。

总而言之，`net/spdy/spdy_http_utils_unittest.cc` 是确保 Chromium 网络栈能够正确处理 SPDY/HTTP2 协议与 HTTP 协议之间转换的关键测试文件，它保障了浏览器与支持 HTTP/2 的服务器之间的正常通信。

### 提示词
```
这是目录为net/spdy/spdy_http_utils_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/spdy/spdy_http_utils.h"

#include <stdint.h>

#include <limits>

#include "base/test/gmock_expected_support.h"
#include "base/test/scoped_feature_list.h"
#include "net/base/features.h"
#include "net/base/ip_endpoint.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_headers_test_util.h"
#include "net/http/http_response_info.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/third_party/quiche/src/quiche/http2/core/spdy_framer.h"
#include "net/third_party/quiche/src/quiche/http2/core/spdy_protocol.h"
#include "net/third_party/quiche/src/quiche/http2/test_tools/spdy_test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

using ::testing::Values;

// Check that the headers are ordered correctly, with pseudo-headers
// preceding HTTP headers per
// https://datatracker.ietf.org/doc/html/rfc9114#section-4.3
void CheckOrdering(const quiche::HttpHeaderBlock& headers) {
  bool seen_http_header = false;

  for (auto& header : headers) {
    const bool is_pseudo = header.first.starts_with(':');
    if (is_pseudo) {
      ASSERT_FALSE(seen_http_header) << "Header order is incorrect:\n"
                                     << headers.DebugString();
    } else {
      seen_http_header = true;
    }
  }
}

TEST(SpdyHttpUtilsTest, ConvertRequestPriorityToSpdy3Priority) {
  EXPECT_EQ(0, ConvertRequestPriorityToSpdyPriority(HIGHEST));
  EXPECT_EQ(1, ConvertRequestPriorityToSpdyPriority(MEDIUM));
  EXPECT_EQ(2, ConvertRequestPriorityToSpdyPriority(LOW));
  EXPECT_EQ(3, ConvertRequestPriorityToSpdyPriority(LOWEST));
  EXPECT_EQ(4, ConvertRequestPriorityToSpdyPriority(IDLE));
  EXPECT_EQ(5, ConvertRequestPriorityToSpdyPriority(THROTTLED));
}

TEST(SpdyHttpUtilsTest, ConvertSpdy3PriorityToRequestPriority) {
  EXPECT_EQ(HIGHEST, ConvertSpdyPriorityToRequestPriority(0));
  EXPECT_EQ(MEDIUM, ConvertSpdyPriorityToRequestPriority(1));
  EXPECT_EQ(LOW, ConvertSpdyPriorityToRequestPriority(2));
  EXPECT_EQ(LOWEST, ConvertSpdyPriorityToRequestPriority(3));
  EXPECT_EQ(IDLE, ConvertSpdyPriorityToRequestPriority(4));
  EXPECT_EQ(THROTTLED, ConvertSpdyPriorityToRequestPriority(5));
  // These are invalid values, but we should still handle them
  // gracefully.
  for (int i = 6; i < std::numeric_limits<uint8_t>::max(); ++i) {
    EXPECT_EQ(IDLE, ConvertSpdyPriorityToRequestPriority(i));
  }
}

TEST(SpdyHttpUtilsTest, CreateSpdyHeadersFromHttpRequestHTTP2) {
  GURL url("https://www.google.com/index.html");
  HttpRequestInfo request;
  request.method = "GET";
  request.url = url;
  request.priority_incremental = true;
  request.extra_headers.SetHeader(HttpRequestHeaders::kUserAgent, "Chrome/1.1");
  quiche::HttpHeaderBlock headers;
  CreateSpdyHeadersFromHttpRequest(request, RequestPriority::HIGHEST,
                                   request.extra_headers, &headers);
  CheckOrdering(headers);
  EXPECT_EQ("GET", headers[":method"]);
  EXPECT_EQ("https", headers[":scheme"]);
  EXPECT_EQ("www.google.com", headers[":authority"]);
  EXPECT_EQ("/index.html", headers[":path"]);
  EXPECT_EQ("u=0, i", headers[net::kHttp2PriorityHeader]);
  EXPECT_EQ(headers.end(), headers.find(":version"));
  EXPECT_EQ("Chrome/1.1", headers["user-agent"]);
}

TEST(SpdyHttpUtilsTest, CreateSpdyHeadersFromHttpRequestForExtendedConnect) {
  GURL url("https://www.google.com/index.html");
  HttpRequestInfo request;
  request.method = "CONNECT";
  request.url = url;
  request.priority_incremental = true;
  request.extra_headers.SetHeader(HttpRequestHeaders::kUserAgent, "Chrome/1.1");
  quiche::HttpHeaderBlock headers;
  CreateSpdyHeadersFromHttpRequestForExtendedConnect(
      request, RequestPriority::HIGHEST, "connect-ftp", request.extra_headers,
      &headers);
  CheckOrdering(headers);
  EXPECT_EQ("CONNECT", headers[":method"]);
  EXPECT_EQ("https", headers[":scheme"]);
  EXPECT_EQ("www.google.com", headers[":authority"]);
  EXPECT_EQ("connect-ftp", headers[":protocol"]);
  EXPECT_EQ("/index.html", headers[":path"]);
  EXPECT_EQ("u=0, i", headers[net::kHttp2PriorityHeader]);
  EXPECT_EQ("Chrome/1.1", headers["user-agent"]);
}

TEST(SpdyHttpUtilsTest, CreateSpdyHeadersWithDefaultPriority) {
  GURL url("https://www.google.com/index.html");
  HttpRequestInfo request;
  request.method = "GET";
  request.url = url;
  request.priority_incremental = false;
  request.extra_headers.SetHeader(HttpRequestHeaders::kUserAgent, "Chrome/1.1");
  quiche::HttpHeaderBlock headers;
  CreateSpdyHeadersFromHttpRequest(request, RequestPriority::DEFAULT_PRIORITY,
                                   request.extra_headers, &headers);
  CheckOrdering(headers);
  EXPECT_EQ("GET", headers[":method"]);
  EXPECT_EQ("https", headers[":scheme"]);
  EXPECT_EQ("www.google.com", headers[":authority"]);
  EXPECT_EQ("/index.html", headers[":path"]);
  EXPECT_FALSE(headers.contains(net::kHttp2PriorityHeader));
  EXPECT_FALSE(headers.contains(":version"));
  EXPECT_EQ("Chrome/1.1", headers["user-agent"]);
}

TEST(SpdyHttpUtilsTest, CreateSpdyHeadersWithExistingPriority) {
  GURL url("https://www.google.com/index.html");
  HttpRequestInfo request;
  request.method = "GET";
  request.url = url;
  request.priority_incremental = true;
  request.extra_headers.SetHeader(HttpRequestHeaders::kUserAgent, "Chrome/1.1");
  request.extra_headers.SetHeader(net::kHttp2PriorityHeader,
                                  "explicit-priority");
  quiche::HttpHeaderBlock headers;
  CreateSpdyHeadersFromHttpRequest(request, RequestPriority::HIGHEST,
                                   request.extra_headers, &headers);
  CheckOrdering(headers);
  EXPECT_EQ("GET", headers[":method"]);
  EXPECT_EQ("https", headers[":scheme"]);
  EXPECT_EQ("www.google.com", headers[":authority"]);
  EXPECT_EQ("/index.html", headers[":path"]);
  EXPECT_EQ("explicit-priority", headers[net::kHttp2PriorityHeader]);
  EXPECT_EQ(headers.end(), headers.find(":version"));
  EXPECT_EQ("Chrome/1.1", headers["user-agent"]);
}

TEST(SpdyHttpUtilsTest, CreateSpdyHeadersFromHttpRequestConnectHTTP2) {
  GURL url("https://www.google.com/index.html");
  HttpRequestInfo request;
  request.method = "CONNECT";
  request.url = url;
  request.extra_headers.SetHeader(HttpRequestHeaders::kUserAgent, "Chrome/1.1");
  quiche::HttpHeaderBlock headers;
  CreateSpdyHeadersFromHttpRequest(request, RequestPriority::DEFAULT_PRIORITY,
                                   request.extra_headers, &headers);
  CheckOrdering(headers);
  EXPECT_EQ("CONNECT", headers[":method"]);
  EXPECT_TRUE(headers.end() == headers.find(":scheme"));
  EXPECT_EQ("www.google.com:443", headers[":authority"]);
  EXPECT_EQ(headers.end(), headers.find(":path"));
  EXPECT_EQ(headers.end(), headers.find(":scheme"));
  EXPECT_TRUE(headers.end() == headers.find(":version"));
  EXPECT_EQ("Chrome/1.1", headers["user-agent"]);
}

constexpr auto ToSimpleString = test::HttpResponseHeadersToSimpleString;

enum class SpdyHeadersToHttpResponseHeadersFeatureConfig {
  kUseRawString,
  kUseBuilder
};

std::string PrintToString(
    SpdyHeadersToHttpResponseHeadersFeatureConfig config) {
  switch (config) {
    case SpdyHeadersToHttpResponseHeadersFeatureConfig::kUseRawString:
      return "RawString";

    case SpdyHeadersToHttpResponseHeadersFeatureConfig::kUseBuilder:
      return "UseBuilder";
  }
}

class SpdyHeadersToHttpResponseTest
    : public ::testing::TestWithParam<
          SpdyHeadersToHttpResponseHeadersFeatureConfig> {
 public:
  SpdyHeadersToHttpResponseTest() {
    switch (GetParam()) {
      case SpdyHeadersToHttpResponseHeadersFeatureConfig::kUseRawString:
        feature_list_.InitWithFeatures(
            {}, {features::kSpdyHeadersToHttpResponseUseBuilder});
        break;

      case SpdyHeadersToHttpResponseHeadersFeatureConfig::kUseBuilder:
        feature_list_.InitWithFeatures(
            {features::kSpdyHeadersToHttpResponseUseBuilder}, {});
        break;
    }
  }

 private:
  base::test::ScopedFeatureList feature_list_;
};

// This test behaves the same regardless of which features are enabled.
TEST_P(SpdyHeadersToHttpResponseTest, SpdyHeadersToHttpResponse) {
  constexpr char kExpectedSimpleString[] =
      "HTTP/1.1 200\n"
      "content-type: text/html\n"
      "cache-control: no-cache, no-store\n"
      "set-cookie: test_cookie=1234567890; Max-Age=3600; Secure; HttpOnly\n"
      "set-cookie: session_id=abcdefghijklmnopqrstuvwxyz; Path=/; HttpOnly\n";
  quiche::HttpHeaderBlock input;
  input[spdy::kHttp2StatusHeader] = "200";
  input["content-type"] = "text/html";
  input["cache-control"] = "no-cache, no-store";
  input.AppendValueOrAddHeader(
      "set-cookie", "test_cookie=1234567890; Max-Age=3600; Secure; HttpOnly");
  input.AppendValueOrAddHeader(
      "set-cookie", "session_id=abcdefghijklmnopqrstuvwxyz; Path=/; HttpOnly");

  net::HttpResponseInfo output;
  output.remote_endpoint = {{127, 0, 0, 1}, 80};

  EXPECT_EQ(OK, SpdyHeadersToHttpResponse(input, &output));

  // This should be set.
  EXPECT_TRUE(output.was_fetched_via_spdy);

  // This should be untouched.
  EXPECT_EQ(output.remote_endpoint, IPEndPoint({127, 0, 0, 1}, 80));

  EXPECT_EQ(kExpectedSimpleString, ToSimpleString(output.headers));
}

INSTANTIATE_TEST_SUITE_P(
    SpdyHttpUtils,
    SpdyHeadersToHttpResponseTest,
    Values(SpdyHeadersToHttpResponseHeadersFeatureConfig::kUseRawString,
           SpdyHeadersToHttpResponseHeadersFeatureConfig::kUseBuilder),
    ::testing::PrintToStringParamName());

// TODO(ricea): Once SpdyHeadersToHttpResponseHeadersUsingRawString has been
// removed, remove the parameterization and make these into
// SpdyHeadersToHttpResponse tests.

using SpdyHeadersToHttpResponseHeadersFunctionPtrType =
    base::expected<scoped_refptr<HttpResponseHeaders>, int> (*)(
        const quiche::HttpHeaderBlock&);

class SpdyHeadersToHttpResponseHeadersTest
    : public testing::TestWithParam<
          SpdyHeadersToHttpResponseHeadersFunctionPtrType> {
 public:
  base::expected<scoped_refptr<HttpResponseHeaders>, int> PerformConversion(
      const quiche::HttpHeaderBlock& headers) {
    return GetParam()(headers);
  }
};

TEST_P(SpdyHeadersToHttpResponseHeadersTest, NoStatus) {
  quiche::HttpHeaderBlock headers;
  EXPECT_THAT(PerformConversion(headers),
              base::test::ErrorIs(ERR_INCOMPLETE_HTTP2_HEADERS));
}

TEST_P(SpdyHeadersToHttpResponseHeadersTest, EmptyStatus) {
  constexpr char kRawHeaders[] = "HTTP/1.1 200\n";
  quiche::HttpHeaderBlock headers;
  headers[":status"] = "";
  ASSERT_OK_AND_ASSIGN(const auto output, PerformConversion(headers));
  EXPECT_EQ(kRawHeaders, ToSimpleString(output));
}

TEST_P(SpdyHeadersToHttpResponseHeadersTest, Plain200) {
  // ":status" does not appear as a header in the output.
  constexpr char kRawHeaders[] = "HTTP/1.1 200\n";
  quiche::HttpHeaderBlock headers;
  headers[spdy::kHttp2StatusHeader] = "200";
  ASSERT_OK_AND_ASSIGN(const auto output, PerformConversion(headers));
  EXPECT_EQ(kRawHeaders, ToSimpleString(output));
}

TEST_P(SpdyHeadersToHttpResponseHeadersTest, MultipleLocation) {
  quiche::HttpHeaderBlock headers;
  headers[spdy::kHttp2StatusHeader] = "304";
  headers["Location"] = "https://example.com/1";
  headers.AppendValueOrAddHeader("location", "https://example.com/2");
  EXPECT_THAT(PerformConversion(headers),
              base::test::ErrorIs(ERR_RESPONSE_HEADERS_MULTIPLE_LOCATION));
}

TEST_P(SpdyHeadersToHttpResponseHeadersTest, SpacesAmongValues) {
  constexpr char kRawHeaders[] =
      "HTTP/1.1 200\n"
      "spaces: foo  ,   bar\n";
  quiche::HttpHeaderBlock headers;
  headers[spdy::kHttp2StatusHeader] = "200";
  headers["spaces"] = "foo  ,   bar";
  ASSERT_OK_AND_ASSIGN(const auto output, PerformConversion(headers));
  EXPECT_EQ(kRawHeaders, ToSimpleString(output));
}

TEST_P(SpdyHeadersToHttpResponseHeadersTest, RepeatedHeader) {
  constexpr char kRawHeaders[] =
      "HTTP/1.1 200\n"
      "name: value1\n"
      "name: value2\n";
  quiche::HttpHeaderBlock headers;
  headers[spdy::kHttp2StatusHeader] = "200";
  headers.AppendValueOrAddHeader("name", "value1");
  headers.AppendValueOrAddHeader("name", "value2");
  ASSERT_OK_AND_ASSIGN(const auto output, PerformConversion(headers));
  EXPECT_EQ(kRawHeaders, ToSimpleString(output));
}

TEST_P(SpdyHeadersToHttpResponseHeadersTest, EmptyValue) {
  constexpr char kRawHeaders[] =
      "HTTP/1.1 200\n"
      "empty: \n";
  quiche::HttpHeaderBlock headers;
  headers[spdy::kHttp2StatusHeader] = "200";
  headers.AppendValueOrAddHeader("empty", "");
  ASSERT_OK_AND_ASSIGN(const auto output, PerformConversion(headers));
  EXPECT_EQ(kRawHeaders, ToSimpleString(output));
}

TEST_P(SpdyHeadersToHttpResponseHeadersTest, PseudoHeadersAreDropped) {
  constexpr char kRawHeaders[] =
      "HTTP/1.1 200\n"
      "Content-Length: 5\n";
  quiche::HttpHeaderBlock headers;
  headers[spdy::kHttp2StatusHeader] = "200";
  headers[spdy::kHttp2MethodHeader] = "GET";
  headers["Content-Length"] = "5";
  headers[":fake"] = "ignored";
  ASSERT_OK_AND_ASSIGN(const auto output, PerformConversion(headers));
  EXPECT_EQ(kRawHeaders, ToSimpleString(output));
}

TEST_P(SpdyHeadersToHttpResponseHeadersTest, DoubleEmptyLocationHeader) {
  constexpr char kRawHeaders[] =
      "HTTP/1.1 200\n"
      "location: \n"
      "location: \n";
  quiche::HttpHeaderBlock headers;
  headers[spdy::kHttp2StatusHeader] = "200";
  headers.AppendValueOrAddHeader("location", "");
  headers.AppendValueOrAddHeader("location", "");
  ASSERT_OK_AND_ASSIGN(const auto output, PerformConversion(headers));
  EXPECT_EQ(kRawHeaders, ToSimpleString(output));
}

TEST_P(SpdyHeadersToHttpResponseHeadersTest,
       DifferentLocationHeaderTriggersError) {
  quiche::HttpHeaderBlock headers;
  headers[spdy::kHttp2StatusHeader] = "200";
  headers.AppendValueOrAddHeader("location", "https://same/");
  headers.AppendValueOrAddHeader("location", "https://same/");
  headers.AppendValueOrAddHeader("location", "https://different/");
  EXPECT_THAT(PerformConversion(headers),
              base::test::ErrorIs(ERR_RESPONSE_HEADERS_MULTIPLE_LOCATION));
}

// TODO(ricea): Ensure that QUICHE will never send us header values with leading
// or trailing whitespace and remove this test.
TEST_P(SpdyHeadersToHttpResponseHeadersTest,
       LocationEquivalenceIgnoresSurroundingSpace) {
  constexpr char kRawHeaders[] =
      "HTTP/1.1 200\n"
      "location: https://same/\n"
      "location: https://same/\n";
  quiche::HttpHeaderBlock headers;
  headers[spdy::kHttp2StatusHeader] = "200";
  headers.AppendValueOrAddHeader("location", " https://same/");
  headers.AppendValueOrAddHeader("location", "https://same/ ");
  ASSERT_OK_AND_ASSIGN(const auto output, PerformConversion(headers));
  EXPECT_EQ(kRawHeaders, ToSimpleString(output));
}

INSTANTIATE_TEST_SUITE_P(
    SpdyHttpUtils,
    SpdyHeadersToHttpResponseHeadersTest,
    Values(SpdyHeadersToHttpResponseHeadersUsingRawString,
           SpdyHeadersToHttpResponseHeadersUsingBuilder),
    [](const testing::TestParamInfo<
        SpdyHeadersToHttpResponseHeadersTest::ParamType>& info) {
      return info.param == SpdyHeadersToHttpResponseHeadersUsingRawString
                 ? "SpdyHeadersToHttpResponseHeadersUsingRawString"
                 : "SpdyHeadersToHttpResponseHeadersUsingBuilder";
    });

}  // namespace

}  // namespace net
```