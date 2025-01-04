Response:
Let's break down the thought process for analyzing the `spdy_http_utils.cc` file.

1. **Understand the Purpose:** The file name `spdy_http_utils.cc` immediately suggests it's a utility file related to the SPDY protocol within the Chromium networking stack. The `#include "net/spdy/spdy_http_utils.h"` confirms this. Utilities typically involve helper functions for common tasks.

2. **Identify Key Data Structures:** Look for the core data structures being manipulated. The file heavily uses `quiche::HttpHeaderBlock`, `net::HttpRequestHeaders`, `net::HttpResponseHeaders`, `net::HttpRequestInfo`, and `net::HttpResponseInfo`. These are the primary inputs and outputs of the functions. Recognizing these structures and their relationships is crucial.

3. **Analyze Individual Functions:** Go through each function, one by one, and determine its role.

    * **`AddUniqueSpdyHeader`:**  Seems like a helper for adding headers to a `quiche::HttpHeaderBlock`, ensuring uniqueness. The `CHECK_EQ` suggests a precondition.

    * **`SpdyHeadersToHttpResponseHeadersUsingFeatures`:**  This looks like a factory function, deciding which implementation to use based on a feature flag. This hints at potential A/B testing or different approaches to header conversion.

    * **`SpdyHeadersToHttpResponse`:** This is a higher-level function that takes SPDY headers and populates a `HttpResponseInfo`. It internally calls the `UsingFeatures` version. It also marks the response as fetched via SPDY.

    * **`SpdyHeadersToHttpResponseHeadersUsingRawString`:** This is a key conversion function. It takes SPDY headers and converts them into an `HttpResponseHeaders` object using a raw string representation. Notice the handling of the `:status` header, pseudo-headers, and NUL-separated values. The multiple `location` header check is also important.

    * **`SpdyHeadersToHttpResponseHeadersUsingBuilder`:** This is the alternative implementation using a `HttpResponseHeaders::Builder`. It performs similar logic to the `RawString` version but constructs the headers in a more structured way. The handling of multiple `location` headers is done slightly differently here.

    * **`CreateSpdyHeadersFromHttpRequest`:** This function takes HTTP request information and headers and converts them into SPDY headers. It handles different HTTP methods (CONNECT vs. others), filters out certain headers, and adds the priority header.

    * **`CreateSpdyHeadersFromHttpRequestForExtendedConnect`:**  Specifically handles the "extended CONNECT" method, adding protocol information. It reuses `CreateSpdyHeadersFromHttpRequest`.

    * **`CreateSpdyHeadersFromHttpRequestForWebSocket`:** Handles WebSocket connections, setting specific headers like `CONNECT`, `Upgrade`, and `Connection`.

    * **`ConvertRequestPriorityToSpdyPriority`:** Converts Chromium's `RequestPriority` enum to SPDY's priority scheme.

    * **`ConvertSpdyPriorityToRequestPriority`:**  The reverse conversion, handling potentially invalid SPDY priority values.

    * **`ConvertHeaderBlockToHttpRequestHeaders`:** Converts SPDY headers back to `HttpRequestHeaders`. It handles pseudo-headers and NUL-separated values.

4. **Identify Connections to JavaScript:** Think about how networking interacts with the browser's JavaScript environment. Fetch API, XMLHttpRequest, and WebSocket API come to mind. SPDY/HTTP2 is an underlying transport mechanism, so its impact is often indirect. The key is that the headers processed here affect how the browser interprets the server's response, which in turn affects how the JavaScript code receives and processes data. Specifically, response headers like `Content-Type`, `Set-Cookie`, and `Location` are directly relevant to JavaScript's behavior.

5. **Look for Logic and Assumptions:**  Examine the code for conditional logic (`if` statements), loops (`for`, `while`), and assertions (`DCHECK`, `CHECK`). Identify any assumptions made about the input data (e.g., the presence of `:status`). The NUL-separated value handling is a notable piece of logic.

6. **Consider Potential Errors:**  Think about what could go wrong. Missing required headers, malformed headers, or security issues (like response smuggling with multiple `location` headers) are potential problems. Also, consider common mistakes developers might make when configuring their servers or using these APIs.

7. **Trace User Actions (Debugging Clues):**  Imagine a user interacting with a webpage. How might their actions lead to this code being executed?  Loading a page (especially over HTTPS), making API calls using `fetch`, or establishing a WebSocket connection are common scenarios. The debugging section should focus on how the browser initiates these requests and how the network stack processes the responses.

8. **Structure the Output:**  Organize the findings logically. Start with the overall purpose, then detail the function-by-function analysis. Separately address the JavaScript connection, logical reasoning, potential errors, and debugging hints. Use clear headings and examples.

9. **Refine and Review:**  Read through the analysis to ensure clarity, accuracy, and completeness. Check for any inconsistencies or missing information. For example, initially, I might have just said "converts headers," but then refined it to mention the specific formats (SPDY to HTTP and vice versa) and the different implementation strategies (`RawString` vs. `Builder`). I also made sure to explicitly link the functionality to user actions in the debugging section.
这个文件 `net/spdy/spdy_http_utils.cc` 是 Chromium 网络栈中专门用于处理 SPDY (以及后来的 HTTP/2，因为很多概念是共享的) 协议和 HTTP 协议之间转换和操作的工具函数集合。它主要负责在 SPDY 的数据格式和 Chromium 内部使用的 HTTP 数据结构之间进行转换。

以下是它的主要功能：

**1. SPDY Headers 到 HTTP Response Headers 的转换:**

*   **`SpdyHeadersToHttpResponse(const quiche::HttpHeaderBlock& headers, HttpResponseInfo* response)`:**  这是主要的入口函数，将 SPDY 格式的头部信息 `quiche::HttpHeaderBlock` 转换为 Chromium 内部使用的 `HttpResponseHeaders` 对象，并将其存储在 `HttpResponseInfo` 中。这个函数还会标记响应是经过 SPDY 获取的。
*   **`SpdyHeadersToHttpResponseHeadersUsingRawString(const quiche::HttpHeaderBlock& headers)`:**  一种实现方式，它将 SPDY 头部转换为一个原始的 HTTP 头部字符串，然后用这个字符串创建 `HttpResponseHeaders` 对象。
*   **`SpdyHeadersToHttpResponseHeadersUsingBuilder(const quiche::HttpHeaderBlock& headers)`:**  另一种实现方式，它使用 `HttpResponseHeaders::Builder` 类来更结构化地构建 `HttpResponseHeaders` 对象。这种方式可能在性能和可维护性上有所不同。

**2. HTTP Request 信息到 SPDY Headers 的转换:**

*   **`CreateSpdyHeadersFromHttpRequest(const HttpRequestInfo& info, std::optional<RequestPriority> priority, const HttpRequestHeaders& request_headers, quiche::HttpHeaderBlock* headers)`:**  将 `HttpRequestInfo` (包含请求方法、URL 等信息) 和 `HttpRequestHeaders` 转换为 SPDY 格式的头部信息。
*   **`CreateSpdyHeadersFromHttpRequestForExtendedConnect(...)`:**  专门处理 HTTP CONNECT 方法的扩展形式，会添加额外的头部信息。
*   **`CreateSpdyHeadersFromHttpRequestForWebSocket(...)`:**  专门为 WebSocket 连接创建 SPDY 头部，设置特定的方法、协议等。

**3. SPDY Priority 和 Chromium Request Priority 之间的转换:**

*   **`ConvertRequestPriorityToSpdyPriority(const RequestPriority priority)`:**  将 Chromium 的请求优先级 (`RequestPriority`) 转换为 SPDY 的优先级 (`SpdyPriority`)。
*   **`ConvertSpdyPriorityToRequestPriority(spdy::SpdyPriority priority)`:**  将 SPDY 的优先级转换回 Chromium 的请求优先级。

**4. 其他工具函数:**

*   **`ConvertHeaderBlockToHttpRequestHeaders(const quiche::HttpHeaderBlock& spdy_headers, HttpRequestHeaders* http_headers)`:**  将 SPDY 的头部块转换回 `HttpRequestHeaders` 对象。
*   内部的 `AddUniqueSpdyHeader` 函数用于向 SPDY 头部块中添加唯一的头部。

**与 JavaScript 的关系及举例说明:**

这个文件本身不包含任何 JavaScript 代码，但它的功能直接影响着浏览器中 JavaScript 代码的行为。当 JavaScript 代码发起网络请求时 (例如使用 `fetch` API 或 `XMLHttpRequest`)，Chromium 的网络栈会处理这些请求，并可能使用 SPDY 或 HTTP/2 协议进行传输。

*   **`fetch` API 或 `XMLHttpRequest` 获取响应:**
    *   JavaScript 代码使用 `fetch` 发起一个请求。
    *   如果服务器支持 SPDY/HTTP/2，浏览器可能会使用这些协议。
    *   服务器返回的 SPDY 格式的头部信息会被 `SpdyHeadersToHttpResponse` 函数转换为 `HttpResponseHeaders`。
    *   JavaScript 可以通过 `response.headers` 访问这些头部信息，例如 `response.headers.get('content-type')`。
    *   **假设输入:** 服务器返回的 SPDY 头部块 `quiche::HttpHeaderBlock` 包含 `{"content-type", "application/json"}` 和 `{"set-cookie", "sessionid=123"}`。
    *   **输出:** `SpdyHeadersToHttpResponse` 会创建一个 `HttpResponseHeaders` 对象，当 JavaScript 代码执行 `response.headers.get('content-type')` 时，会得到 `"application/json"`，执行 `response.headers.get('set-cookie')` 时，会得到 `"sessionid=123"`。

*   **WebSocket 连接:**
    *   JavaScript 代码使用 `new WebSocket('wss://example.com/socket')` 建立 WebSocket 连接。
    *   `CreateSpdyHeadersFromHttpRequestForWebSocket` 会为 WebSocket 的握手请求创建 SPDY 头部。
    *   这些头部信息会被发送到服务器，用于建立 SPDY over WebSocket 连接。

**逻辑推理及假设输入与输出:**

*   **假设输入 (针对 `SpdyHeadersToHttpResponseHeadersUsingRawString`)**:
    *   `headers`: `{{":status", "200"}, {"content-type", "text/html"}, {"set-cookie", "id=abc\0name=def"}}` (注意 `set-cookie` 头部包含 NUL 分隔的多个值)
*   **输出:**
    *   `raw_headers` 字符串会类似: `"HTTP/1.1 200\0content-type:text/html\0set-cookie:id=abc\0set-cookie:name=def\0"`
    *   创建的 `HttpResponseHeaders` 对象会包含两个 `Set-Cookie` 头部，分别是 `id=abc` 和 `name=def`。

*   **假设输入 (针对 `CreateSpdyHeadersFromHttpRequest`)**:
    *   `info.method`: "GET"
    *   `info.url`: `GURL("https://example.com/path?query")`
    *   `request_headers`: 包含 `{"User-Agent", "Chrome"}` 和 `{"Accept-Language", "en-US"}`
*   **输出:**
    *   `headers`: `{{":method", "GET"}, {":authority", "example.com"}, {":scheme", "https"}, {":path", "/path?query"}, {"user-agent", "Chrome"}, {"accept-language", "en-US"}}`

**用户或编程常见的使用错误及举例说明:**

*   **服务器返回不合法的 SPDY 头部:**
    *   **错误:** 服务器返回的 SPDY 头部缺少 `:status` 伪头部。
    *   **后果:** `SpdyHeadersToHttpResponseHeadersUsingRawString` 或 `SpdyHeadersToHttpResponseHeadersUsingBuilder` 会返回 `base::unexpected(ERR_INCOMPLETE_HTTP2_HEADERS)`，导致网络请求失败。
    *   **用户现象:** 网页加载失败，控制台显示网络错误。

*   **服务器返回多个 `Location` 头部 (潜在的响应走私攻击):**
    *   **错误:** 服务器返回了多个名为 `location` 的头部。
    *   **后果:** `SpdyHeadersToHttpResponseHeadersUsingRawString` 或 `SpdyHeadersToHttpResponseHeadersUsingBuilder` 会返回 `base::unexpected(ERR_RESPONSE_HEADERS_MULTIPLE_LOCATION)`。
    *   **用户现象:**  可能导致浏览器行为异常，例如重定向到错误的页面，或者安全漏洞。

*   **尝试在 `HttpRequestHeaders` 中设置 SPDY 保留的伪头部:**
    *   **错误:** JavaScript 代码或上层代码尝试在 `HttpRequestHeaders` 中设置以冒号 `:` 开头的头部 (例如 `":method": "POST"`)。
    *   **后果:** 在 `CreateSpdyHeadersFromHttpRequest` 中，这些伪头部会被跳过，不会包含在发送给服务器的 SPDY 头部中。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入 URL 并按下回车，或者点击了一个链接。**
2. **浏览器进程解析 URL，创建 `HttpRequestInfo` 对象，包含请求方法 (GET)、URL 等信息。**
3. **网络线程发起请求，如果判断可以使用 SPDY/HTTP/2 协议，则会调用 `CreateSpdyHeadersFromHttpRequest` 将 `HttpRequestInfo` 和相关的 `HttpRequestHeaders` 转换为 SPDY 格式的头部。**
4. **网络线程将 SPDY 头部和请求体发送到服务器。**
5. **服务器返回 SPDY 格式的响应头部和响应体。**
6. **网络线程接收到 SPDY 响应头部。**
7. **`SpdyFramer` (或其他 SPDY/HTTP/2 处理模块) 将接收到的 SPDY 帧解析为 `quiche::HttpHeaderBlock`。**
8. **`SpdyHeadersToHttpResponse` 函数被调用，将 `quiche::HttpHeaderBlock` 转换为 `HttpResponseHeaders`。**
9. **`HttpResponseHeaders` 被存储在 `HttpResponseInfo` 中，并传递给上层网络模块。**
10. **浏览器进程接收到响应，解析 `HttpResponseHeaders`，并将其中的信息 (例如 `Content-Type`) 用于渲染网页或传递给 JavaScript。**

**调试线索:**

*   如果在网络请求的早期阶段出现问题 (例如请求头信息不正确)，可以在 `CreateSpdyHeadersFromHttpRequest` 中设置断点，检查生成的 SPDY 头部是否符合预期。
*   如果在接收到响应后出现问题 (例如响应头解析错误)，可以在 `SpdyHeadersToHttpResponse` 及其相关的 `UsingRawString` 或 `UsingBuilder` 函数中设置断点，检查 `quiche::HttpHeaderBlock` 的内容以及转换过程。
*   可以使用 Chromium 的网络日志 (chrome://net-export/) 来捕获网络请求和响应的详细信息，包括 SPDY 帧的内容，帮助分析头部信息。
*   检查服务器的配置，确保其返回的 SPDY 头部符合规范，例如必须包含 `:status` 伪头部，且 `Location` 头部的使用符合要求。

总而言之，`net/spdy/spdy_http_utils.cc` 是 Chromium 网络栈中连接 SPDY/HTTP/2 协议和上层 HTTP 处理的关键桥梁，它确保了使用新协议的网络请求和响应能够被正确地处理和解释。

Prompt: 
```
这是目录为net/spdy/spdy_http_utils.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/spdy/spdy_http_utils.h"

#include <string>
#include <string_view>
#include <vector>

#include "base/check_op.h"
#include "base/feature_list.h"
#include "base/strings/strcat.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/types/expected.h"
#include "base/types/expected_macros.h"
#include "net/base/features.h"
#include "net/base/url_util.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/http/http_util.h"
#include "net/quic/quic_http_utils.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_stream_priority.h"

namespace net {

const char* const kHttp2PriorityHeader = "priority";

namespace {

// The number of bytes to reserve for the raw headers string to avoid having to
// do reallocations most of the time. Equal to the 99th percentile of header
// sizes in ricea@'s cache on 3 Aug 2023.
constexpr size_t kExpectedRawHeaderSize = 4035;

// Add header `name` with `value` to `headers`. `name` must not already exist in
// `headers`.
void AddUniqueSpdyHeader(std::string_view name,
                         std::string_view value,
                         quiche::HttpHeaderBlock* headers) {
  auto insert_result = headers->insert({name, value});
  CHECK_EQ(insert_result, quiche::HttpHeaderBlock::InsertResult::kInserted);
}

// Convert `headers` to an HttpResponseHeaders object based on the features
// enabled at runtime.
base::expected<scoped_refptr<HttpResponseHeaders>, int>
SpdyHeadersToHttpResponseHeadersUsingFeatures(
    const quiche::HttpHeaderBlock& headers) {
  if (base::FeatureList::IsEnabled(
          features::kSpdyHeadersToHttpResponseUseBuilder)) {
    return SpdyHeadersToHttpResponseHeadersUsingBuilder(headers);
  } else {
    return SpdyHeadersToHttpResponseHeadersUsingRawString(headers);
  }
}

}  // namespace

int SpdyHeadersToHttpResponse(const quiche::HttpHeaderBlock& headers,
                              HttpResponseInfo* response) {
  ASSIGN_OR_RETURN(response->headers,
                   SpdyHeadersToHttpResponseHeadersUsingFeatures(headers));
  response->was_fetched_via_spdy = true;
  return OK;
}

NET_EXPORT_PRIVATE base::expected<scoped_refptr<HttpResponseHeaders>, int>
SpdyHeadersToHttpResponseHeadersUsingRawString(
    const quiche::HttpHeaderBlock& headers) {
  // The ":status" header is required.
  quiche::HttpHeaderBlock::const_iterator it =
      headers.find(spdy::kHttp2StatusHeader);
  if (it == headers.end()) {
    return base::unexpected(ERR_INCOMPLETE_HTTP2_HEADERS);
  }

  const auto status = it->second;

  std::string raw_headers =
      base::StrCat({"HTTP/1.1 ", status, std::string_view("\0", 1)});
  raw_headers.reserve(kExpectedRawHeaderSize);
  for (const auto& [name, value] : headers) {
    DCHECK_GT(name.size(), 0u);
    if (name[0] == ':') {
      // https://tools.ietf.org/html/rfc7540#section-8.1.2.4
      // Skip pseudo headers.
      continue;
    }
    // For each value, if the server sends a NUL-separated
    // list of values, we separate that back out into
    // individual headers for each value in the list.
    // e.g.
    //    Set-Cookie "foo\0bar"
    // becomes
    //    Set-Cookie: foo\0
    //    Set-Cookie: bar\0
    size_t start = 0;
    size_t end = 0;
    do {
      end = value.find('\0', start);
      std::string_view tval;
      if (end != value.npos) {
        tval = value.substr(start, (end - start));
      } else {
        tval = value.substr(start);
      }
      base::StrAppend(&raw_headers,
                      {name, ":", tval, std::string_view("\0", 1)});
      start = end + 1;
    } while (end != value.npos);
  }

  auto response_headers =
      base::MakeRefCounted<HttpResponseHeaders>(raw_headers);

  // When there are multiple location headers the response is a potential
  // response smuggling attack.
  if (HttpUtil::HeadersContainMultipleCopiesOfField(*response_headers,
                                                    "location")) {
    return base::unexpected(ERR_RESPONSE_HEADERS_MULTIPLE_LOCATION);
  }

  return response_headers;
}

NET_EXPORT_PRIVATE base::expected<scoped_refptr<HttpResponseHeaders>, int>
SpdyHeadersToHttpResponseHeadersUsingBuilder(
    const quiche::HttpHeaderBlock& headers) {
  // The ":status" header is required.
  // TODO(ricea): The ":status" header should always come first. Skip this hash
  // lookup after we no longer need to be compatible with the old
  // implementation.
  quiche::HttpHeaderBlock::const_iterator it =
      headers.find(spdy::kHttp2StatusHeader);
  if (it == headers.end()) {
    return base::unexpected(ERR_INCOMPLETE_HTTP2_HEADERS);
  }

  const auto status = it->second;

  HttpResponseHeaders::Builder builder({1, 1}, status);

  for (const auto& [name, value] : headers) {
    DCHECK_GT(name.size(), 0u);
    if (name[0] == ':') {
      // https://tools.ietf.org/html/rfc7540#section-8.1.2.4
      // Skip pseudo headers.
      continue;
    }
    // For each value, if the server sends a NUL-separated
    // list of values, we separate that back out into
    // individual headers for each value in the list.
    // e.g.
    //    Set-Cookie "foo\0bar"
    // becomes
    //    Set-Cookie: foo\0
    //    Set-Cookie: bar\0
    size_t start = 0;
    size_t end = 0;
    std::optional<std::string_view> location_value;
    do {
      end = value.find('\0', start);
      std::string_view tval;
      if (end != value.npos) {
        tval = value.substr(start, (end - start));

        // TODO(ricea): Make this comparison case-sensitive when we are no
        // longer maintaining compatibility with the old version of the
        // function.
        if (base::EqualsCaseInsensitiveASCII(name, "location") &&
            !location_value.has_value()) {
          location_value = HttpUtil::TrimLWS(tval);
        }
      } else {
        tval = value.substr(start);
      }
      if (location_value.has_value() && start > 0) {
        DCHECK(base::EqualsCaseInsensitiveASCII(name, "location"));
        std::string_view trimmed_value = HttpUtil::TrimLWS(tval);
        if (trimmed_value != location_value.value()) {
          return base::unexpected(ERR_RESPONSE_HEADERS_MULTIPLE_LOCATION);
        }
      }
      builder.AddHeader(name, tval);
      start = end + 1;
    } while (end != value.npos);
  }

  return builder.Build();
}

void CreateSpdyHeadersFromHttpRequest(const HttpRequestInfo& info,
                                      std::optional<RequestPriority> priority,
                                      const HttpRequestHeaders& request_headers,
                                      quiche::HttpHeaderBlock* headers) {
  headers->insert({spdy::kHttp2MethodHeader, info.method});
  if (info.method == "CONNECT") {
    headers->insert({spdy::kHttp2AuthorityHeader, GetHostAndPort(info.url)});
  } else {
    headers->insert(
        {spdy::kHttp2AuthorityHeader, GetHostAndOptionalPort(info.url)});
    headers->insert({spdy::kHttp2SchemeHeader, info.url.scheme()});
    headers->insert({spdy::kHttp2PathHeader, info.url.PathForRequest()});
  }

  HttpRequestHeaders::Iterator it(request_headers);
  while (it.GetNext()) {
    std::string name = base::ToLowerASCII(it.name());
    if (name.empty() || name[0] == ':' || name == "connection" ||
        name == "proxy-connection" || name == "transfer-encoding" ||
        name == "host") {
      continue;
    }
    AddUniqueSpdyHeader(name, it.value(), headers);
  }

  // Add the priority header if there is not already one set. This uses the
  // quic helpers but the header values for HTTP extensible priorities are
  // independent of quic.
  if (priority &&
      headers->find(kHttp2PriorityHeader) == headers->end()) {
    uint8_t urgency = ConvertRequestPriorityToQuicPriority(priority.value());
    bool incremental = info.priority_incremental;
    quic::HttpStreamPriority quic_priority{urgency, incremental};
    std::string serialized_priority =
        quic::SerializePriorityFieldValue(quic_priority);
    if (!serialized_priority.empty()) {
      AddUniqueSpdyHeader(kHttp2PriorityHeader, serialized_priority, headers);
    }
  }
}

void CreateSpdyHeadersFromHttpRequestForExtendedConnect(
    const HttpRequestInfo& info,
    std::optional<RequestPriority> priority,
    const std::string& ext_connect_protocol,
    const HttpRequestHeaders& request_headers,
    quiche::HttpHeaderBlock* headers) {
  CHECK_EQ(info.method, "CONNECT");

  // Extended CONNECT, unlike CONNECT, requires scheme and path, and uses the
  // default port in the authority header.
  headers->insert({spdy::kHttp2SchemeHeader, info.url.scheme()});
  headers->insert({spdy::kHttp2PathHeader, info.url.PathForRequest()});
  headers->insert({spdy::kHttp2ProtocolHeader, ext_connect_protocol});

  CreateSpdyHeadersFromHttpRequest(info, priority, request_headers, headers);

  // Replace the existing `:authority` header. This will still be ordered
  // correctly, since the header was first added before any regular headers.
  headers->insert(
      {spdy::kHttp2AuthorityHeader, GetHostAndOptionalPort(info.url)});
}

void CreateSpdyHeadersFromHttpRequestForWebSocket(
    const GURL& url,
    const HttpRequestHeaders& request_headers,
    quiche::HttpHeaderBlock* headers) {
  headers->insert({spdy::kHttp2MethodHeader, "CONNECT"});
  headers->insert({spdy::kHttp2AuthorityHeader, GetHostAndOptionalPort(url)});
  headers->insert({spdy::kHttp2SchemeHeader, "https"});
  headers->insert({spdy::kHttp2PathHeader, url.PathForRequest()});
  headers->insert({spdy::kHttp2ProtocolHeader, "websocket"});

  HttpRequestHeaders::Iterator it(request_headers);
  while (it.GetNext()) {
    std::string name = base::ToLowerASCII(it.name());
    if (name.empty() || name[0] == ':' || name == "upgrade" ||
        name == "connection" || name == "proxy-connection" ||
        name == "transfer-encoding" || name == "host") {
      continue;
    }
    AddUniqueSpdyHeader(name, it.value(), headers);
  }
}

static_assert(HIGHEST - LOWEST < 4 && HIGHEST - MINIMUM_PRIORITY < 6,
              "request priority incompatible with spdy");

spdy::SpdyPriority ConvertRequestPriorityToSpdyPriority(
    const RequestPriority priority) {
  DCHECK_GE(priority, MINIMUM_PRIORITY);
  DCHECK_LE(priority, MAXIMUM_PRIORITY);
  return static_cast<spdy::SpdyPriority>(MAXIMUM_PRIORITY - priority +
                                         spdy::kV3HighestPriority);
}

NET_EXPORT_PRIVATE RequestPriority
ConvertSpdyPriorityToRequestPriority(spdy::SpdyPriority priority) {
  // Handle invalid values gracefully.
  return ((priority - spdy::kV3HighestPriority) >
          (MAXIMUM_PRIORITY - MINIMUM_PRIORITY))
             ? IDLE
             : static_cast<RequestPriority>(
                   MAXIMUM_PRIORITY - (priority - spdy::kV3HighestPriority));
}

NET_EXPORT_PRIVATE void ConvertHeaderBlockToHttpRequestHeaders(
    const quiche::HttpHeaderBlock& spdy_headers,
    HttpRequestHeaders* http_headers) {
  for (const auto& it : spdy_headers) {
    std::string_view key = it.first;
    if (key[0] == ':') {
      key.remove_prefix(1);
    }
    std::vector<std::string_view> values = base::SplitStringPiece(
        it.second, "\0", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
    for (const auto& value : values) {
      http_headers->SetHeader(key, value);
    }
  }
}

}  // namespace net

"""

```