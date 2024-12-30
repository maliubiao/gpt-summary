Response:
Let's break down the thought process for analyzing this `websocket_test_util.cc` file.

1. **Understand the Purpose:** The filename itself, `websocket_test_util.cc`, strongly suggests this file contains utility functions specifically for *testing* WebSocket functionality within the Chromium networking stack. The "util" part is key.

2. **Scan for Key Classes and Functions:** Quickly read through the code, looking for defined classes and functions. This gives a high-level overview of what capabilities are offered. I'd note down things like:
    * `LinearCongruentialGenerator`
    * `WebSocketExtraHeadersToString`
    * `WebSocketExtraHeadersToHttpRequestHeaders`
    * `WebSocketStandardRequest` (and its variant with cookies)
    * `WebSocketStandardResponse`
    * `WebSocketCommonTestHeaders`
    * `WebSocketHttp2Request`
    * `WebSocketHttp2Response`
    * `WebSocketMockClientSocketFactoryMaker`
    * `WebSocketTestURLRequestContextHost`
    * `DummyConnectDelegate`
    * `TestWebSocketStreamRequestAPI`

3. **Analyze Individual Components:** Now, dive deeper into each significant class or function identified in step 2. Ask "What does this do?" and "Why would this be needed for testing WebSockets?".

    * **`LinearCongruentialGenerator`:**  The name suggests random number generation. For testing, you might need predictable "randomness" to reproduce test scenarios, or to generate test data like WebSocket keys (though the code directly uses a fixed key elsewhere).

    * **Header Functions (`WebSocketExtraHeadersToString`, `WebSocketExtraHeadersToHttpRequestHeaders`):** These are clearly for manipulating WebSocket headers, converting between different representations. This is essential for constructing and verifying WebSocket handshake requests and responses.

    * **Request/Response Generators (`WebSocketStandardRequest`, `WebSocketStandardResponse`, `WebSocketHttp2Request`, `WebSocketHttp2Response`):**  These are *core* to testing. They provide convenient ways to create well-formed WebSocket handshake requests and expected successful responses (both for HTTP/1.1 and HTTP/2). Notice the hardcoded "Sec-WebSocket-Key" in the standard request – this is for deterministic testing.

    * **`WebSocketCommonTestHeaders`:** A helper to get a common set of headers, reducing code duplication in tests.

    * **`WebSocketMockClientSocketFactoryMaker`:** This is crucial for *mocking* network interactions. In unit tests, you don't want to make real network requests. This class allows you to specify what data the socket will "write" and what it will "read," enabling controlled testing of handshake logic.

    * **`WebSocketTestURLRequestContextHost`:** This provides a controlled `URLRequestContext` for testing. It integrates the `MockClientSocketFactory`, allowing tests to use the mocking framework. It also disables some features (like QUIC) which might interfere with specific WebSocket tests.

    * **`DummyConnectDelegate`:**  A placeholder implementation of a delegate. Useful when you need a delegate but don't care about its specific behavior in a particular test.

    * **`TestWebSocketStreamRequestAPI`:** This seems to be a hook for tests to interact with the WebSocket handshake stream creation process, potentially to set specific properties for testing.

4. **Identify Relationships to JavaScript:** Think about how JavaScript interacts with WebSockets in a browser. JavaScript uses the `WebSocket` API. This C++ code is *implementing* the underlying networking logic. Therefore, the connection points are:
    * **Handshake Requests/Responses:** The C++ code constructs and parses these, mirroring what a JavaScript `WebSocket` object would generate and expect. The headers, like `Upgrade`, `Connection`, `Sec-WebSocket-Key`, `Sec-WebSocket-Accept`, are all part of the standard WebSocket handshake that JavaScript initiates.
    * **Error Handling:**  While not explicitly detailed in *this* file, the testing utilities would be used to simulate server errors or incorrect responses that a JavaScript WebSocket would encounter (e.g., using `MockRead` to return HTTP error codes).

5. **Consider Logic and Assumptions:** For the request/response generators, note the assumptions made (e.g., HTTP/1.1 vs. HTTP/2, specific header values). Consider what inputs affect the outputs (path, host, origin, extra headers).

6. **Think About Usage and Common Errors:** How might a *developer writing tests* misuse these utilities?  Focus on things like:
    * **Incorrectly formatted expectations:**  Mismatching the expected written data with the actual request being generated.
    * **Not accounting for buffering:** The `kHttpStreamParserBufferSize` detail in `WebSocketMockClientSocketFactoryMaker` is a good example.
    * **Forgetting to set up mocks:**  If the mock factory isn't configured correctly, tests won't behave as expected.

7. **Trace User Actions (Debugging Context):** Imagine a user experiencing a WebSocket connection failure. How does that lead to debugging this code?
    * **JavaScript error:**  The user sees an error in their JavaScript console related to the WebSocket connection.
    * **Network inspection:** The developer uses browser developer tools to examine the WebSocket handshake request and response headers.
    * **Server-side logs:** The developer might check server logs to see how the server responded.
    * **Chromium internals:** For deeper debugging, a Chromium developer might look at network logs (net-internals) which would involve this C++ code. They might set breakpoints in the WebSocket handshake handling code, which could call functions from `websocket_test_util.cc` during testing or even in the actual implementation. The test utilities provide a simplified, controlled environment to reproduce and isolate issues found in real-world scenarios.

8. **Structure the Explanation:** Organize the findings logically, starting with the overall purpose, then detailing each component, the JavaScript connection, usage, and finally, the debugging perspective. Use clear headings and examples where possible.

By following this systematic approach, one can effectively understand the functionality of a complex utility file like `websocket_test_util.cc` and its role in the broader context of WebSocket implementation and testing.
这个文件 `net/websockets/websocket_test_util.cc` 是 Chromium 网络栈中专门为 WebSocket 功能编写的测试辅助工具库。它提供了一系列函数和类，用于简化 WebSocket 相关的单元测试和集成测试。

以下是它的主要功能：

**1. 生成和操作 WebSocket 握手请求和响应:**

* **`WebSocketStandardRequest` 和 `WebSocketStandardRequestWithCookies`:**  这两个函数用于生成标准的 HTTP/1.1 WebSocket 升级请求。它们允许你指定路径、主机、Origin、额外的请求头和 Cookie。这对于模拟客户端发起 WebSocket 连接请求非常有用。
* **`WebSocketStandardResponse`:** 生成标准的 HTTP/1.1 WebSocket 升级成功响应。你可以添加额外的响应头。这用于模拟服务器成功升级到 WebSocket 协议。
* **`WebSocketCommonTestHeaders`:** 返回一组常用的 WebSocket 请求头，方便在测试中复用。
* **`WebSocketExtraHeadersToString`:** 将 `WebSocketExtraHeaders` (一个 `std::vector<std::pair<std::string, std::string>>`) 转换为字符串形式，方便比较和日志记录。
* **`WebSocketExtraHeadersToHttpRequestHeaders`:** 将 `WebSocketExtraHeaders` 转换为 `HttpRequestHeaders` 对象，方便与 Chromium 的 HTTP 处理代码集成。
* **`WebSocketHttp2Request`:**  生成 HTTP/2 格式的 WebSocket CONNECT 请求。它使用 SPDY/HTTP2 的头部格式。
* **`WebSocketHttp2Response`:** 生成 HTTP/2 格式的 WebSocket 成功响应。

**2. 模拟网络连接:**

* **`WebSocketMockClientSocketFactoryMaker`:**  这是一个用于创建 `MockClientSocketFactory` 的辅助类。`MockClientSocketFactory` 允许你在测试中模拟底层的 TCP 连接。你可以预先设定客户端将要写入的数据（请求）以及服务端返回的数据（响应）。这使得在不实际建立网络连接的情况下测试 WebSocket 握手过程成为可能。
* **`WebSocketTestURLRequestContextHost`:**  创建一个用于测试的 `URLRequestContext` 环境。它使用 `WebSocketMockClientSocketFactoryMaker` 提供的 mock socket factory，并可以设置代理配置。这为运行网络相关的测试提供了一个隔离且可控的环境。
* **`AddRawExpectations` 和 `AddSSLSocketDataProvider` (在 `WebSocketMockClientSocketFactoryMaker` 和 `WebSocketTestURLRequestContextHost` 中):**  允许向 mock socket factory 添加期望的读写操作和 SSL 数据。

**3. 其他实用工具:**

* **`LinearCongruentialGenerator`:**  一个简单的线性同余随机数生成器，可能用于生成一些测试数据，但在这个文件中似乎没有直接使用。
* **`DummyConnectDelegate`:** 一个空的 `URLRequest::Delegate` 实现，用于在某些测试场景中提供一个占位符。
* **`TestWebSocketStreamRequestAPI`:** 提供了一些虚函数，可以在测试中被继承并重写，以在 WebSocket 握手流创建的不同阶段执行特定的操作。

**与 JavaScript 的关系及举例:**

这个文件本身是用 C++ 编写的，Chromium 的网络栈也是用 C++ 实现的。 然而，它的功能直接关系到 JavaScript 中 `WebSocket` API 的行为。

**举例说明:**

当 JavaScript 代码创建一个 `WebSocket` 对象并尝试连接到一个 WebSocket 服务器时，浏览器内部会执行一系列网络操作，最终会生成一个 HTTP 升级请求。 `WebSocketStandardRequest` 函数的功能就是模拟生成这样的请求。

假设 JavaScript 代码如下：

```javascript
const ws = new WebSocket('ws://example.com/chat');
```

在 Chromium 的内部测试中，可以使用 `WebSocketStandardRequest` 来模拟这个 JavaScript 代码生成的 HTTP 请求：

```c++
std::string request = WebSocketTestUtil::WebSocketStandardRequest(
    "/chat", "example.com", url::Origin::Create(GURL("http://localhost")), {}, {});

// request 变量将包含类似以下的字符串:
// "GET /chat HTTP/1.1\r\n"
// "Host: example.com\r\n"
// "Connection: Upgrade\r\n"
// "Pragma: no-cache\r\n"
// "Cache-Control: no-cache\r\n"
// "Upgrade: websocket\r\n"
// "Origin: http://localhost\r\n"
// "Sec-WebSocket-Version: 13\r\n"
// "User-Agent: ...\r\n"
// "Accept-Encoding: gzip, deflate\r\n"
// "Accept-Language: en-us,fr\r\n"
// "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
// "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
// "\r\n"
```

同样，当服务器响应一个成功的 WebSocket 握手时，浏览器会解析这个响应。 `WebSocketStandardResponse` 函数可以用来模拟这样的响应：

```c++
std::string response = WebSocketTestUtil::WebSocketStandardResponse("");

// response 变量将包含:
// "HTTP/1.1 101 Switching Protocols\r\n"
// "Upgrade: websocket\r\n"
// "Connection: Upgrade\r\n"
// "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
// "\r\n"
```

**逻辑推理的假设输入与输出:**

**假设输入 (对于 `WebSocketStandardRequest`):**

* `path`: "/mywebsocket"
* `host`: "test.example.org"
* `origin`:  `url::Origin::Create(GURL("https://myorigin.com"))`
* `send_additional_request_headers`: `{{"X-Custom-Header", "custom-value"}}`
* `extra_headers`: `{{"Sec-WebSocket-Protocol", "chat"}}`

**输出:**

```
GET /mywebsocket HTTP/1.1\r\n
Host: test.example.org\r\n
Connection: Upgrade\r\n
Pragma: no-cache\r\n
Cache-Control: no-cache\r\n
X-Custom-Header: custom-value\r\n
Upgrade: websocket\r\n
Origin: https://myorigin.com\r\n
Sec-WebSocket-Version: 13\r\n
User-Agent: \r\n
Accept-Encoding: gzip, deflate\r\n
Accept-Language: en-us,fr\r\n
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n
Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n
Sec-WebSocket-Protocol: chat\r\n
\r\n
```

**涉及用户或编程常见的使用错误举例:**

* **Mock 设置不正确:**  开发者在使用 `WebSocketMockClientSocketFactoryMaker` 时，可能设置了错误的 `expect_written` 或 `return_to_read`，导致模拟的握手过程与实际期望不符，测试失败。例如，期望写入的请求头中缺少了必要的 `Origin` 头。
* **忽略 HTTP/2 的差异:** 在测试 HTTP/2 的 WebSocket 连接时，使用了 `WebSocketStandardRequest` 和 `WebSocketStandardResponse` (针对 HTTP/1.1)，而不是 `WebSocketHttp2Request` 和 `WebSocketHttp2Response`，导致请求头的格式不正确。
* **忘记添加必要的 MockConnect 数据:**  在使用 `SequencedSocketData` 时，如果忘记设置 `connect_data`，会导致模拟连接失败，即使握手请求和响应都正确。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中访问一个使用 WebSocket 的网页。**
2. **网页的 JavaScript 代码创建了一个 `WebSocket` 对象，尝试连接到服务器。**
3. **浏览器网络栈开始执行 WebSocket 握手过程。**
4. **如果握手失败或出现异常行为，Chromium 开发者可能会需要调试网络栈的相关代码。**
5. **为了复现和隔离问题，开发者会编写单元测试或集成测试。**
6. **在这些测试中，`websocket_test_util.cc` 提供的工具会被使用：**
   * 使用 `WebSocketStandardRequest` 或 `WebSocketHttp2Request` 生成模拟的客户端请求。
   * 使用 `WebSocketMockClientSocketFactoryMaker` 设置模拟的网络连接，预定义期望写入的请求和读取的响应。
   * 验证实际发送的请求和接收的响应是否符合预期。
   * 模拟服务器返回错误响应，测试客户端的错误处理逻辑。

通过使用这些工具，开发者可以在一个可控的环境中测试 WebSocket 的各个方面，例如握手过程、协议升级、错误处理等，从而定位和修复用户在使用 WebSocket 时遇到的问题。 这些工具简化了测试的编写，避免了每次测试都需要手动构造复杂的请求和响应字符串。

Prompt: 
```
这是目录为net/websockets/websocket_test_util.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/websockets/websocket_test_util.h"

#include <stddef.h>

#include <algorithm>
#include <sstream>
#include <utility>

#include "base/check.h"
#include "base/containers/span.h"
#include "base/strings/strcat.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "net/base/net_errors.h"
#include "net/http/http_network_session.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/proxy_resolution/proxy_resolution_service.h"
#include "net/socket/socket_test_util.h"
#include "net/third_party/quiche/src/quiche/http2/core/spdy_protocol.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/websockets/websocket_basic_handshake_stream.h"
#include "url/origin.h"

namespace net {
class AuthChallengeInfo;
class AuthCredentials;
class HttpResponseHeaders;
class WebSocketHttp2HandshakeStream;
class WebSocketHttp3HandshakeStream;

namespace {

const uint64_t kA = (static_cast<uint64_t>(0x5851f42d) << 32) +
                    static_cast<uint64_t>(0x4c957f2d);
const uint64_t kC = 12345;
const uint64_t kM = static_cast<uint64_t>(1) << 48;

}  // namespace

LinearCongruentialGenerator::LinearCongruentialGenerator(uint32_t seed)
    : current_(seed) {}

uint32_t LinearCongruentialGenerator::Generate() {
  uint64_t result = current_;
  current_ = (current_ * kA + kC) % kM;
  return static_cast<uint32_t>(result >> 16);
}

std::string WebSocketExtraHeadersToString(
    const WebSocketExtraHeaders& headers) {
  std::string answer;
  for (const auto& header : headers) {
    base::StrAppend(&answer, {header.first, ": ", header.second, "\r\n"});
  }
  return answer;
}

HttpRequestHeaders WebSocketExtraHeadersToHttpRequestHeaders(
    const WebSocketExtraHeaders& headers) {
  HttpRequestHeaders headers_to_return;
  for (const auto& header : headers)
    headers_to_return.SetHeader(header.first, header.second);
  return headers_to_return;
}

std::string WebSocketStandardRequest(
    const std::string& path,
    const std::string& host,
    const url::Origin& origin,
    const WebSocketExtraHeaders& send_additional_request_headers,
    const WebSocketExtraHeaders& extra_headers) {
  return WebSocketStandardRequestWithCookies(path, host, origin, /*cookies=*/{},
                                             send_additional_request_headers,
                                             extra_headers);
}

std::string WebSocketStandardRequestWithCookies(
    const std::string& path,
    const std::string& host,
    const url::Origin& origin,
    const WebSocketExtraHeaders& cookies,
    const WebSocketExtraHeaders& send_additional_request_headers,
    const WebSocketExtraHeaders& extra_headers) {
  // Unrelated changes in net/http may change the order and default-values of
  // HTTP headers, causing WebSocket tests to fail. It is safe to update this
  // in that case.
  HttpRequestHeaders headers;
  std::stringstream request_headers;

  request_headers << base::StringPrintf("GET %s HTTP/1.1\r\n", path.c_str());
  headers.SetHeader("Host", host);
  headers.SetHeader("Connection", "Upgrade");
  headers.SetHeader("Pragma", "no-cache");
  headers.SetHeader("Cache-Control", "no-cache");
  for (const auto& [key, value] : send_additional_request_headers)
    headers.SetHeader(key, value);
  headers.SetHeader("Upgrade", "websocket");
  headers.SetHeader("Origin", origin.Serialize());
  headers.SetHeader("Sec-WebSocket-Version", "13");
  if (!headers.HasHeader("User-Agent"))
    headers.SetHeader("User-Agent", "");
  headers.SetHeader("Accept-Encoding", "gzip, deflate");
  headers.SetHeader("Accept-Language", "en-us,fr");
  for (const auto& [key, value] : cookies)
    headers.SetHeader(key, value);
  headers.SetHeader("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
  headers.SetHeader("Sec-WebSocket-Extensions",
                    "permessage-deflate; client_max_window_bits");
  for (const auto& [key, value] : extra_headers)
    headers.SetHeader(key, value);

  request_headers << headers.ToString();
  return request_headers.str();
}

std::string WebSocketStandardResponse(const std::string& extra_headers) {
  return base::StrCat(
      {"HTTP/1.1 101 Switching Protocols\r\n"
       "Upgrade: websocket\r\n"
       "Connection: Upgrade\r\n"
       "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
       extra_headers, "\r\n"});
}

HttpRequestHeaders WebSocketCommonTestHeaders() {
  HttpRequestHeaders request_headers;
  request_headers.SetHeader("Host", "www.example.org");
  request_headers.SetHeader("Connection", "Upgrade");
  request_headers.SetHeader("Pragma", "no-cache");
  request_headers.SetHeader("Cache-Control", "no-cache");
  request_headers.SetHeader("Upgrade", "websocket");
  request_headers.SetHeader("Origin", "http://origin.example.org");
  request_headers.SetHeader("Sec-WebSocket-Version", "13");
  request_headers.SetHeader("User-Agent", "");
  request_headers.SetHeader("Accept-Encoding", "gzip, deflate");
  request_headers.SetHeader("Accept-Language", "en-us,fr");
  return request_headers;
}

quiche::HttpHeaderBlock WebSocketHttp2Request(
    const std::string& path,
    const std::string& authority,
    const std::string& origin,
    const WebSocketExtraHeaders& extra_headers) {
  quiche::HttpHeaderBlock request_headers;
  request_headers[spdy::kHttp2MethodHeader] = "CONNECT";
  request_headers[spdy::kHttp2AuthorityHeader] = authority;
  request_headers[spdy::kHttp2SchemeHeader] = "https";
  request_headers[spdy::kHttp2PathHeader] = path;
  request_headers[spdy::kHttp2ProtocolHeader] = "websocket";
  request_headers["pragma"] = "no-cache";
  request_headers["cache-control"] = "no-cache";
  request_headers["origin"] = origin;
  request_headers["sec-websocket-version"] = "13";
  request_headers["user-agent"] = "";
  request_headers["accept-encoding"] = "gzip, deflate";
  request_headers["accept-language"] = "en-us,fr";
  request_headers["sec-websocket-extensions"] =
      "permessage-deflate; client_max_window_bits";
  for (const auto& header : extra_headers) {
    request_headers[base::ToLowerASCII(header.first)] = header.second;
  }
  return request_headers;
}

quiche::HttpHeaderBlock WebSocketHttp2Response(
    const WebSocketExtraHeaders& extra_headers) {
  quiche::HttpHeaderBlock response_headers;
  response_headers[spdy::kHttp2StatusHeader] = "200";
  for (const auto& header : extra_headers) {
    response_headers[base::ToLowerASCII(header.first)] = header.second;
  }
  return response_headers;
}

struct WebSocketMockClientSocketFactoryMaker::Detail {
  std::string expect_written;
  std::string return_to_read;
  std::vector<MockRead> reads;
  MockWrite write;
  std::vector<std::unique_ptr<SequencedSocketData>> socket_data_vector;
  std::vector<std::unique_ptr<SSLSocketDataProvider>> ssl_socket_data_vector;
  MockClientSocketFactory factory;
};

WebSocketMockClientSocketFactoryMaker::WebSocketMockClientSocketFactoryMaker()
    : detail_(std::make_unique<Detail>()) {}

WebSocketMockClientSocketFactoryMaker::
    ~WebSocketMockClientSocketFactoryMaker() = default;

MockClientSocketFactory* WebSocketMockClientSocketFactoryMaker::factory() {
  return &detail_->factory;
}

void WebSocketMockClientSocketFactoryMaker::SetExpectations(
    const std::string& expect_written,
    const std::string& return_to_read) {
  constexpr size_t kHttpStreamParserBufferSize = 4096;
  // We need to extend the lifetime of these strings.
  detail_->expect_written = expect_written;
  detail_->return_to_read = return_to_read;
  int sequence = 0;
  detail_->write = MockWrite(SYNCHRONOUS,
                             detail_->expect_written.data(),
                             detail_->expect_written.size(),
                             sequence++);
  // HttpStreamParser reads 4KB at a time. We need to take this implementation
  // detail into account if |return_to_read| is big enough.
  for (size_t place = 0; place < detail_->return_to_read.size();
       place += kHttpStreamParserBufferSize) {
    detail_->reads.emplace_back(SYNCHRONOUS,
                                detail_->return_to_read.data() + place,
                                std::min(detail_->return_to_read.size() - place,
                                         kHttpStreamParserBufferSize),
                                sequence++);
  }
  auto socket_data = std::make_unique<SequencedSocketData>(
      detail_->reads, base::make_span(&detail_->write, 1u));
  socket_data->set_connect_data(MockConnect(SYNCHRONOUS, OK));
  AddRawExpectations(std::move(socket_data));
}

void WebSocketMockClientSocketFactoryMaker::AddRawExpectations(
    std::unique_ptr<SequencedSocketData> socket_data) {
  detail_->factory.AddSocketDataProvider(socket_data.get());
  detail_->socket_data_vector.push_back(std::move(socket_data));
}

void WebSocketMockClientSocketFactoryMaker::AddSSLSocketDataProvider(
    std::unique_ptr<SSLSocketDataProvider> ssl_socket_data) {
  detail_->factory.AddSSLSocketDataProvider(ssl_socket_data.get());
  detail_->ssl_socket_data_vector.push_back(std::move(ssl_socket_data));
}

WebSocketTestURLRequestContextHost::WebSocketTestURLRequestContextHost()
    : url_request_context_builder_(CreateTestURLRequestContextBuilder()) {
  url_request_context_builder_->set_client_socket_factory_for_testing(
      maker_.factory());
  HttpNetworkSessionParams params;
  params.enable_spdy_ping_based_connection_checking = false;
  params.enable_quic = false;
  params.disable_idle_sockets_close_on_memory_pressure = false;
  url_request_context_builder_->set_http_network_session_params(params);
}

WebSocketTestURLRequestContextHost::~WebSocketTestURLRequestContextHost() =
    default;

void WebSocketTestURLRequestContextHost::AddRawExpectations(
    std::unique_ptr<SequencedSocketData> socket_data) {
  maker_.AddRawExpectations(std::move(socket_data));
}

void WebSocketTestURLRequestContextHost::AddSSLSocketDataProvider(
    std::unique_ptr<SSLSocketDataProvider> ssl_socket_data) {
  maker_.AddSSLSocketDataProvider(std::move(ssl_socket_data));
}

void WebSocketTestURLRequestContextHost::SetProxyConfig(
    const std::string& proxy_rules) {
  DCHECK(!url_request_context_);
  auto proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          proxy_rules, TRAFFIC_ANNOTATION_FOR_TESTS);
  url_request_context_builder_->set_proxy_resolution_service(
      std::move(proxy_resolution_service));
}

void DummyConnectDelegate::OnURLRequestConnected(URLRequest* request,
                                                 const TransportInfo& info) {}

int DummyConnectDelegate::OnAuthRequired(
    const AuthChallengeInfo& auth_info,
    scoped_refptr<HttpResponseHeaders> response_headers,
    const IPEndPoint& host_port_pair,
    base::OnceCallback<void(const AuthCredentials*)> callback,
    std::optional<AuthCredentials>* credentials) {
  return OK;
}

URLRequestContext* WebSocketTestURLRequestContextHost::GetURLRequestContext() {
  if (!url_request_context_) {
    url_request_context_builder_->set_network_delegate(
        std::make_unique<TestNetworkDelegate>());
    url_request_context_ = url_request_context_builder_->Build();
    url_request_context_builder_ = nullptr;
  }
  return url_request_context_.get();
}

void TestWebSocketStreamRequestAPI::OnBasicHandshakeStreamCreated(
    WebSocketBasicHandshakeStream* handshake_stream) {
  handshake_stream->SetWebSocketKeyForTesting("dGhlIHNhbXBsZSBub25jZQ==");
}

void TestWebSocketStreamRequestAPI::OnHttp2HandshakeStreamCreated(
    WebSocketHttp2HandshakeStream* handshake_stream) {}

void TestWebSocketStreamRequestAPI::OnHttp3HandshakeStreamCreated(
    WebSocketHttp3HandshakeStream* handshake_stream) {}
}  // namespace net

"""

```