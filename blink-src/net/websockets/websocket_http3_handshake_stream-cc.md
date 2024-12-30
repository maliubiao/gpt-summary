Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understand the Goal:** The primary goal is to understand the functionality of the `WebSocketHttp3HandshakeStream` class, its relationship to JavaScript (if any), its potential inputs and outputs, common user errors, and how a user's actions might lead to this code being executed.

2. **Identify the Core Functionality:** The class name itself is a big clue: "WebSocketHttp3HandshakeStream". This immediately suggests that it's involved in establishing a WebSocket connection over HTTP/3. The "handshake" part is crucial, indicating the initial negotiation phase.

3. **Analyze Class Members (High-Level):** Look at the member variables in the constructor. These tell us what the class needs to function:
    * `session_`: Likely a handle to the underlying HTTP/3 connection.
    * `connect_delegate_`:  A delegate for handling connection events.
    * `requested_sub_protocols_`, `requested_extensions_`: Data related to WebSocket sub-protocols and extensions.
    * `stream_request_`: An object to report the status of the request.
    * `dns_aliases_`:  Potentially for DNS-related information.

4. **Analyze Key Methods:**  Focus on the public methods and their roles in the handshake process:
    * `RegisterRequest()`:  Stores information about the initial HTTP request.
    * `InitializeStream()`:  Sets up the stream (though this implementation seems minimal).
    * `SendRequest()`:  The core of sending the WebSocket handshake request. It constructs headers, interacts with the `QuicChromiumClientSession`, and sets up a callback.
    * `ReadResponseHeaders()`: Handles receiving and validating the handshake response headers.
    * `ReadResponseBody()`:  Currently a placeholder, likely intended for reading the response body (though WebSocket handshakes don't typically have a significant body).
    * `Close()`:  Tears down the stream.
    * `Upgrade()`:  Crucial – this is where the handshake transitions to the actual WebSocket communication stream.
    * `OnHeadersSent()`, `OnHeadersReceived()`, `OnClose()`: These are callbacks from the underlying QUIC stream, indicating events during the handshake.
    * `ValidateResponse()`, `ValidateUpgradeResponse()`:  Logic to ensure the server's response is valid for a WebSocket handshake.
    * `OnFailure()`: Handles error reporting.

5. **Trace the Handshake Flow:**  Imagine the sequence of calls that would occur during a successful handshake:
    1. Constructor is called.
    2. `RegisterRequest()` is called.
    3. `InitializeStream()` is called.
    4. `SendRequest()` is called, sending the initial handshake request.
    5. The underlying QUIC stream sends the headers (`OnHeadersSent()`).
    6. The server responds with headers (`OnHeadersReceived()`).
    7. `ReadResponseHeaders()` is called to validate the headers.
    8. `Upgrade()` is called to create the `WebSocketBasicStream` (or `WebSocketDeflateStream`).

6. **Identify Interactions with Other Components:**  The code interacts with several other Chromium networking classes:
    * `QuicChromiumClientSession`: For managing the HTTP/3 connection.
    * `WebSocketStream::ConnectDelegate`: For notifying the higher layers about the handshake progress.
    * `HttpRequestInfo`, `HttpResponseInfo`, `HttpRequestHeaders`, `HttpResponseHeaders`:  Standard HTTP data structures.
    * `WebSocketQuicStreamAdapter`:  The bridge between the WebSocket handshake and the QUIC stream.
    * `WebSocketBasicStream`, `WebSocketDeflateStream`: The actual WebSocket data streams.

7. **Consider JavaScript Relevance:** Think about how a web page initiates a WebSocket connection. JavaScript's `WebSocket` API is the entry point. The browser's networking stack takes over from there. While this C++ code isn't *directly* interacting with JavaScript, it's the implementation behind the scenes that makes the JavaScript API work. The browser translates the JavaScript `new WebSocket(...)` call into the necessary network operations, eventually leading to this code.

8. **Look for Potential Errors:** Examine the validation logic and error handling:
    * Invalid HTTP status codes.
    * Failure to negotiate sub-protocols or extensions.
    * Connection closure.
    * Missing required headers in the request.

9. **Think About Debugging:**  How would a developer investigate issues in this code?  Logging (using `net_log_`) would be critical. Knowing the sequence of method calls and the state of the objects would be essential. Understanding how user actions (like clicking a button that triggers a WebSocket connection) translate into network requests helps in tracing the path to this code.

10. **Address the "TODO"s:** Notice the many `// TODO(momoka)` comments. This highlights areas where the implementation is incomplete or needs further work. This is valuable information about the current state of the code.

11. **Structure the Answer:** Organize the findings logically:
    * Functionality:  Start with the main purpose of the class.
    * JavaScript Relationship: Explain the connection through the browser's networking stack.
    * Logical Reasoning (Input/Output):  Describe the expected inputs and outputs of key methods, especially `SendRequest()` and `ReadResponseHeaders()`.
    * User/Programming Errors: Provide concrete examples of common mistakes.
    * User Actions/Debugging: Explain how a user's actions lead to this code and how to debug it.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** "This is just about sending and receiving HTTP headers."  **Correction:** Realize it's specifically about the *WebSocket handshake* over HTTP/3, which has specific requirements beyond regular HTTP.
* **Initial thought:** "JavaScript directly calls this C++ code." **Correction:** Understand the abstraction layers. JavaScript interacts with browser APIs, which then trigger the underlying networking code.
* **Realization about "TODO"s:** "These TODOs are important. They show the incomplete parts and potential future work."  Make sure to mention them in the analysis.
* **Clarity on Input/Output:**  Instead of just listing inputs/outputs generally, focus on the key methods like `SendRequest` (input: headers, output: initiates the stream) and `ReadResponseHeaders` (input: raw header data, output: validated headers or error).

By following these steps, and iteratively refining the understanding, we can arrive at a comprehensive analysis of the given C++ code snippet.
这个文件 `net/websockets/websocket_http3_handshake_stream.cc` 是 Chromium 网络栈中专门用于处理 **通过 HTTP/3 协议建立 WebSocket 连接的握手过程** 的核心组件。

以下是它的功能分解：

**核心功能:**

1. **管理 HTTP/3 WebSocket 握手流:**  这个类 `WebSocketHttp3HandshakeStream` 负责建立和管理用于 WebSocket 握手协商的 HTTP/3 流。它处理发送握手请求，接收和验证握手响应头，最终完成握手或报告错误。

2. **作为 `WebSocketStream` 的实现:**  它实现了 `WebSocketStream` 接口，提供了用于发起和管理 WebSocket 连接的通用抽象。具体而言，它是 HTTP/3 协议下 `WebSocketStream` 的一种实现方式。

3. **构建握手请求:**  它负责构建符合 WebSocket 握手规范的 HTTP/3 请求头。这包括设置 `Upgrade`、`Connection`、`Sec-WebSocket-Key`、`Sec-WebSocket-Protocol`、`Sec-WebSocket-Extensions` 等必要的头部。

4. **处理握手响应:**  接收并解析来自服务器的 HTTP/3 握手响应头。验证响应状态码（通常是 101 Switching Protocols），以及 `Upgrade`、`Connection`、`Sec-WebSocket-Accept` 等关键头部。

5. **协议和扩展协商:**  处理客户端请求的子协议 (`Sec-WebSocket-Protocol`) 和扩展 (`Sec-WebSocket-Extensions`)，并与服务器的响应进行比较，确定最终采用的协议和扩展。

6. **升级到 WebSocket 数据流:**  如果握手成功，它会创建并返回一个新的 `WebSocketBasicStream` 或 `WebSocketDeflateStream` 对象，用于实际的 WebSocket 数据传输。这个过程称为 "升级"。

7. **错误处理:**  处理握手过程中可能发生的各种错误，例如连接失败、无效的响应头、协议或扩展协商失败等。

8. **集成 QUIC:**  由于 HTTP/3 基于 QUIC 协议，这个类与 `QuicChromiumClientSession` 紧密集成，使用其提供的 API 来创建和管理 HTTP/3 流。

**与 JavaScript 的关系:**

虽然这个 C++ 代码本身不是 JavaScript，但它是 **浏览器中 JavaScript `WebSocket` API 的底层实现** 的一部分。

**举例说明:**

当 JavaScript 代码执行以下操作时，最终会触发这个 C++ 文件的代码执行：

```javascript
const websocket = new WebSocket("wss://example.com/socket");
```

1. **JavaScript `new WebSocket(...)` 调用:**  浏览器接收到这个调用，并开始建立 WebSocket 连接。
2. **请求创建 WebSocket 流:**  浏览器内部会根据 URL 中的协议（`wss://` 表示安全的 WebSocket over TLS，且通常会尝试 HTTP/3）选择合适的 `WebSocketStream` 实现。在这种情况下，如果支持 HTTP/3，可能会选择 `WebSocketHttp3HandshakeStream`。
3. **`WebSocketHttp3HandshakeStream` 的创建和初始化:**  这个 C++ 类会被创建，并使用相关的参数（例如请求的 URL、子协议、扩展等）进行初始化。
4. **发送握手请求:**  `SendRequest` 方法会被调用，构建并发送 HTTP/3 握手请求到服务器。请求头中包含了 JavaScript 代码中指定的子协议和扩展。
5. **接收握手响应:**  `ReadResponseHeaders` 方法被调用，等待并解析服务器返回的 HTTP/3 握手响应头。
6. **升级:**  如果握手成功（响应状态码为 101），`Upgrade` 方法会被调用，创建一个 `WebSocketBasicStream` 或 `WebSocketDeflateStream` 对象，用于后续的数据传输。
7. **WebSocket 连接建立完成:**  JavaScript 的 `websocket.onopen` 事件会被触发，表示 WebSocket 连接已成功建立。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* **`request_headers` (HttpRequestHeaders):** 包含 WebSocket 握手请求头的对象，例如：
    ```
    Upgrade: websocket
    Connection: Upgrade
    Sec-WebSocket-Version: 13
    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
    Origin: https://example.com
    Sec-WebSocket-Protocol: chat, superchat
    Sec-WebSocket-Extensions: permessage-deflate
    ```
* **服务器返回的 `response_headers` (quiche::HttpHeaderBlock):** 包含 WebSocket 握手响应头的对象，例如：
    ```
    :status: 101
    Upgrade: websocket
    Connection: Upgrade
    Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
    Sec-WebSocket-Protocol: chat
    Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover
    ```

**预期输出:**

* **`ValidateResponse()` 返回 `OK` (0):** 表示握手响应验证成功。
* **`Upgrade()` 返回一个指向 `WebSocketBasicStream` 或 `WebSocketDeflateStream` 的智能指针:**  取决于服务器是否接受了压缩扩展。
* **`sub_protocol_` 成员变量被设置为 "chat":**  因为服务器接受了 "chat" 子协议。
* **`extensions_` 成员变量包含 "permessage-deflate; server_no_context_takeover":** 因为服务器接受了 `permessage-deflate` 扩展并指定了参数。

**如果服务器返回错误的响应头 (例如状态码不是 101):**

* **`ValidateResponse()` 返回 `ERR_INVALID_RESPONSE` (-201):**  表示响应无效。
* **`OnFailure()` 方法会被调用:**  报告握手失败的原因。
* **`result_` 成员变量会被设置为 `HandshakeResult::HTTP3_INVALID_STATUS`:**  记录握手失败的具体原因。

**用户或编程常见的使用错误:**

1. **在 JavaScript 中请求了服务器不支持的子协议或扩展:**
   * **结果:**  握手可能会失败，`ValidateSubProtocol` 或 `ValidateExtensions` 会返回错误，导致 `OnFailure` 被调用。
   * **错误信息:**  类似于 "Error during WebSocket handshake: Server did not accept specified subprotocol." 或 "Error during WebSocket handshake: Server did not accept specified extension."

2. **服务器配置错误，没有正确响应 WebSocket 握手请求:**
   * **结果:**  握手失败，`ValidateStatus` 返回错误，导致 `OnFailure` 被调用。
   * **错误信息:**  类似于 "Error during WebSocket handshake: Unexpected response code: [错误状态码]"。

3. **网络问题导致连接中断:**
   * **结果:**  `OnClose` 方法会被调用，`stream_error_` 会被设置为相应的网络错误码（例如 `ERR_CONNECTION_RESET`）。
   * **错误信息:**  类似于 "Stream closed with error: ERR_CONNECTION_RESET"。

4. **在请求头中设置了不合法的 WebSocket 相关头部:**  尽管代码中做了检查 (`DCHECK` 断言)，但如果上层代码构建了错误的请求头，可能会导致不可预测的行为或握手失败。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在浏览器中访问了一个网页 `https://example.com`，该网页包含以下 JavaScript 代码：

1. **用户访问网页:** 用户在浏览器地址栏输入 `https://example.com` 并按下回车键。
2. **浏览器加载网页:** 浏览器发送 HTTP 请求获取网页内容。
3. **JavaScript 代码执行:** 浏览器解析并执行网页中的 JavaScript 代码。
4. **`new WebSocket("wss://example.com/socket")` 执行:**  JavaScript 尝试创建一个新的 WebSocket 连接。
5. **查找或创建 HTTP/3 连接:** 浏览器检查是否已经存在到 `example.com` 的 HTTP/3 连接。如果不存在，则会建立新的连接。
6. **创建 `WebSocketHttp3HandshakeStream`:**  网络栈根据 URL 的协议 (wss) 和支持的协议 (HTTP/3) 选择创建 `WebSocketHttp3HandshakeStream` 的实例。
7. **`RegisterRequest` 被调用:** 记录与此 WebSocket 连接请求相关的 HTTP 请求信息。
8. **`InitializeStream` 被调用:** 初始化流的一些基本属性。
9. **`SendRequest` 被调用:**
   * 构建包含 WebSocket 握手信息的 HTTP/3 请求头。
   * 使用底层的 QUIC 协议栈 (`QuicChromiumClientSession`) 发送请求到服务器。
10. **服务器响应:** 服务器处理请求并返回 HTTP/3 握手响应头。
11. **`OnHeadersReceived` 被调用:**  接收并解析服务器返回的 HTTP/3 响应头。
12. **`ReadResponseHeaders` 被调用:** 验证响应头的状态码和关键的 WebSocket 头部。
13. **`ValidateResponse` 被调用:**  执行更细致的握手响应验证，包括子协议和扩展的协商。
14. **如果握手成功，`Upgrade` 被调用:** 创建用于数据传输的 `WebSocketBasicStream` 或 `WebSocketDeflateStream`。
15. **通知上层连接已建立:** `connect_delegate_->OnConnect流Established()` (或其他类似方法) 会被调用，最终通知 JavaScript 的 `websocket.onopen` 事件。
16. **如果握手失败，`OnFailure` 被调用:**  报告错误信息，可能导致 JavaScript 的 `websocket.onerror` 事件被触发，或者连接直接关闭。

**调试线索:**

* **网络抓包 (如 Wireshark):**  可以查看实际发送和接收的 HTTP/3 数据包，包括握手请求和响应头，帮助分析握手失败的原因。
* **Chromium 的 `net-internals` 工具 (`chrome://net-internals/#events`):**  可以查看详细的网络事件日志，包括 WebSocket 连接的建立过程，可以看到 `WebSocketHttp3HandshakeStream` 的相关操作和状态。
* **日志输出:**  在 Chromium 的开发版本中，可以启用网络相关的日志输出，查看更详细的握手过程信息。
* **断点调试:**  在 `WebSocketHttp3HandshakeStream` 的关键方法中设置断点，例如 `SendRequest`、`OnHeadersReceived`、`ValidateResponse`，可以逐步跟踪握手过程，查看变量的值和执行流程。

总而言之，`net/websockets/websocket_http3_handshake_stream.cc` 是 Chromium 中实现 HTTP/3 WebSocket 连接的关键部分，负责处理握手协商的复杂逻辑，并将底层的 QUIC 连接升级为可用的 WebSocket 数据流。它与 JavaScript 的 `WebSocket` API 紧密相关，是实现浏览器 WebSocket 功能的幕后功臣。

Prompt: 
```
这是目录为net/websockets/websocket_http3_handshake_stream.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/websockets/websocket_http3_handshake_stream.h"

#include <string_view>
#include <utility>

#include "base/check.h"
#include "base/check_op.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/memory/scoped_refptr.h"
#include "base/strings/strcat.h"
#include "base/strings/stringprintf.h"
#include "base/time/time.h"
#include "net/base/ip_endpoint.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/http/http_status_code.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/websockets/websocket_basic_stream.h"
#include "net/websockets/websocket_deflate_predictor_impl.h"
#include "net/websockets/websocket_deflate_stream.h"
#include "net/websockets/websocket_handshake_constants.h"
#include "net/websockets/websocket_handshake_request_info.h"

namespace net {
struct AlternativeService;

namespace {

bool ValidateStatus(const HttpResponseHeaders* headers) {
  return headers->GetStatusLine() == "HTTP/1.1 200";
}

}  // namespace

WebSocketHttp3HandshakeStream::WebSocketHttp3HandshakeStream(
    std::unique_ptr<QuicChromiumClientSession::Handle> session,
    WebSocketStream::ConnectDelegate* connect_delegate,
    std::vector<std::string> requested_sub_protocols,
    std::vector<std::string> requested_extensions,
    WebSocketStreamRequestAPI* request,
    std::set<std::string> dns_aliases)
    : session_(std::move(session)),
      connect_delegate_(connect_delegate),
      requested_sub_protocols_(std::move(requested_sub_protocols)),
      requested_extensions_(std::move(requested_extensions)),
      stream_request_(request),
      dns_aliases_(std::move(dns_aliases)) {
  DCHECK(connect_delegate);
  DCHECK(request);
}

WebSocketHttp3HandshakeStream::~WebSocketHttp3HandshakeStream() {
  RecordHandshakeResult(result_);
}

void WebSocketHttp3HandshakeStream::RegisterRequest(
    const HttpRequestInfo* request_info) {
  DCHECK(request_info);
  DCHECK(request_info->traffic_annotation.is_valid());
  request_info_ = request_info;
}

int WebSocketHttp3HandshakeStream::InitializeStream(
    bool can_send_early,
    RequestPriority priority,
    const NetLogWithSource& net_log,
    CompletionOnceCallback callback) {
  priority_ = priority;
  net_log_ = net_log;
  request_time_ = base::Time::Now();
  return OK;
}

int WebSocketHttp3HandshakeStream::SendRequest(
    const HttpRequestHeaders& request_headers,
    HttpResponseInfo* response,
    CompletionOnceCallback callback) {
  DCHECK(!request_headers.HasHeader(websockets::kSecWebSocketKey));
  DCHECK(!request_headers.HasHeader(websockets::kSecWebSocketProtocol));
  DCHECK(!request_headers.HasHeader(websockets::kSecWebSocketExtensions));
  DCHECK(request_headers.HasHeader(HttpRequestHeaders::kOrigin));
  DCHECK(request_headers.HasHeader(websockets::kUpgrade));
  DCHECK(request_headers.HasHeader(HttpRequestHeaders::kConnection));
  DCHECK(request_headers.HasHeader(websockets::kSecWebSocketVersion));

  if (!session_) {
    constexpr int rv = ERR_CONNECTION_CLOSED;
    OnFailure("Connection closed before sending request.", rv, std::nullopt);
    return rv;
  }

  http_response_info_ = response;

  IPEndPoint address;
  int result = session_->GetPeerAddress(&address);
  if (result != OK) {
    OnFailure("Error getting IP address.", result, std::nullopt);
    return result;
  }
  http_response_info_->remote_endpoint = address;

  auto request = std::make_unique<WebSocketHandshakeRequestInfo>(
      request_info_->url, base::Time::Now());
  request->headers = request_headers;

  AddVectorHeaders(requested_extensions_, requested_sub_protocols_,
                   &request->headers);

  CreateSpdyHeadersFromHttpRequestForWebSocket(
      request_info_->url, request->headers, &http3_request_headers_);

  connect_delegate_->OnStartOpeningHandshake(std::move(request));

  callback_ = std::move(callback);

  std::unique_ptr<WebSocketQuicStreamAdapter> stream_adapter =
      session_->CreateWebSocketQuicStreamAdapter(
          this,
          base::BindOnce(
              &WebSocketHttp3HandshakeStream::ReceiveAdapterAndStartRequest,
              base::Unretained(this)),
          NetworkTrafficAnnotationTag(request_info_->traffic_annotation));
  if (!stream_adapter) {
    return ERR_IO_PENDING;
  }
  ReceiveAdapterAndStartRequest(std::move(stream_adapter));
  return OK;
}

int WebSocketHttp3HandshakeStream::ReadResponseHeaders(
    CompletionOnceCallback callback) {
  if (stream_closed_) {
    return stream_error_;
  }

  if (response_headers_complete_) {
    return ValidateResponse();
  }

  callback_ = std::move(callback);
  return ERR_IO_PENDING;
}

// TODO(momoka): Implement this.
int WebSocketHttp3HandshakeStream::ReadResponseBody(
    IOBuffer* buf,
    int buf_len,
    CompletionOnceCallback callback) {
  return OK;
}

void WebSocketHttp3HandshakeStream::Close(bool not_reusable) {
  if (stream_adapter_) {
    stream_adapter_->Disconnect();
    stream_closed_ = true;
    stream_error_ = ERR_CONNECTION_CLOSED;
  }
}

// TODO(momoka): Implement this.
bool WebSocketHttp3HandshakeStream::IsResponseBodyComplete() const {
  return false;
}

// TODO(momoka): Implement this.
bool WebSocketHttp3HandshakeStream::IsConnectionReused() const {
  return true;
}

// TODO(momoka): Implement this.
void WebSocketHttp3HandshakeStream::SetConnectionReused() {}

// TODO(momoka): Implement this.
bool WebSocketHttp3HandshakeStream::CanReuseConnection() const {
  return false;
}

// TODO(momoka): Implement this.
int64_t WebSocketHttp3HandshakeStream::GetTotalReceivedBytes() const {
  return 0;
}

// TODO(momoka): Implement this.
int64_t WebSocketHttp3HandshakeStream::GetTotalSentBytes() const {
  return 0;
}

// TODO(momoka): Implement this.
bool WebSocketHttp3HandshakeStream::GetAlternativeService(
    AlternativeService* alternative_service) const {
  return false;
}

// TODO(momoka): Implement this.
bool WebSocketHttp3HandshakeStream::GetLoadTimingInfo(
    LoadTimingInfo* load_timing_info) const {
  return false;
}

// TODO(momoka): Implement this.
void WebSocketHttp3HandshakeStream::GetSSLInfo(SSLInfo* ssl_info) {}

// TODO(momoka): Implement this.
int WebSocketHttp3HandshakeStream::GetRemoteEndpoint(IPEndPoint* endpoint) {
  return 0;
}

// TODO(momoka): Implement this.
void WebSocketHttp3HandshakeStream::Drain(HttpNetworkSession* session) {}

// TODO(momoka): Implement this.
void WebSocketHttp3HandshakeStream::SetPriority(RequestPriority priority) {}

// TODO(momoka): Implement this.
void WebSocketHttp3HandshakeStream::PopulateNetErrorDetails(
    NetErrorDetails* details) {}

// TODO(momoka): Implement this.
std::unique_ptr<HttpStream>
WebSocketHttp3HandshakeStream::RenewStreamForAuth() {
  return nullptr;
}

// TODO(momoka): Implement this.
const std::set<std::string>& WebSocketHttp3HandshakeStream::GetDnsAliases()
    const {
  return dns_aliases_;
}

// TODO(momoka): Implement this.
std::string_view WebSocketHttp3HandshakeStream::GetAcceptChViaAlps() const {
  return {};
}

// WebSocketHandshakeStreamBase methods.

// TODO(momoka): Implement this.
std::unique_ptr<WebSocketStream> WebSocketHttp3HandshakeStream::Upgrade() {
  DCHECK(extension_params_.get());

  stream_adapter_->clear_delegate();
  std::unique_ptr<WebSocketStream> basic_stream =
      std::make_unique<WebSocketBasicStream>(std::move(stream_adapter_),
                                             nullptr, sub_protocol_,
                                             extensions_, net_log_);

  if (!extension_params_->deflate_enabled) {
    return basic_stream;
  }

  return std::make_unique<WebSocketDeflateStream>(
      std::move(basic_stream), extension_params_->deflate_parameters,
      std::make_unique<WebSocketDeflatePredictorImpl>());
}

bool WebSocketHttp3HandshakeStream::CanReadFromStream() const {
  return stream_adapter_ && stream_adapter_->is_initialized();
}

base::WeakPtr<WebSocketHandshakeStreamBase>
WebSocketHttp3HandshakeStream::GetWeakPtr() {
  return weak_ptr_factory_.GetWeakPtr();
}

void WebSocketHttp3HandshakeStream::OnHeadersSent() {
  std::move(callback_).Run(OK);
}

void WebSocketHttp3HandshakeStream::OnHeadersReceived(
    const quiche::HttpHeaderBlock& response_headers) {
  DCHECK(!response_headers_complete_);
  DCHECK(http_response_info_);

  response_headers_complete_ = true;

  const int rv =
      SpdyHeadersToHttpResponse(response_headers, http_response_info_);
  DCHECK_NE(rv, ERR_INCOMPLETE_HTTP2_HEADERS);

  // Do not store SSLInfo in the response here, HttpNetworkTransaction will take
  // care of that part.
  http_response_info_->was_alpn_negotiated = true;
  http_response_info_->response_time =
      http_response_info_->original_response_time = base::Time::Now();
  http_response_info_->request_time = request_time_;
  http_response_info_->connection_info = HttpConnectionInfo::kHTTP2;
  http_response_info_->alpn_negotiated_protocol =
      HttpConnectionInfoToString(http_response_info_->connection_info);

  if (callback_) {
    std::move(callback_).Run(ValidateResponse());
  }
}

void WebSocketHttp3HandshakeStream::OnClose(int status) {
  DCHECK(stream_adapter_);
  DCHECK_GT(ERR_IO_PENDING, status);

  stream_closed_ = true;
  stream_error_ = status;

  stream_adapter_.reset();

  // If response headers have already been received,
  // then ValidateResponse() sets `result_`.
  if (!response_headers_complete_) {
    result_ = HandshakeResult::HTTP3_FAILED;
  }

  OnFailure(base::StrCat({"Stream closed with error: ", ErrorToString(status)}),
            status, std::nullopt);

  if (callback_) {
    std::move(callback_).Run(status);
  }
}

void WebSocketHttp3HandshakeStream::ReceiveAdapterAndStartRequest(
    std::unique_ptr<WebSocketQuicStreamAdapter> adapter) {
  stream_adapter_ = std::move(adapter);
  // WriteHeaders returns synchronously.
  stream_adapter_->WriteHeaders(std::move(http3_request_headers_), false);
}

int WebSocketHttp3HandshakeStream::ValidateResponse() {
  DCHECK(http_response_info_);
  const HttpResponseHeaders* headers = http_response_info_->headers.get();
  const int response_code = headers->response_code();
  switch (response_code) {
    case HTTP_OK:
      return ValidateUpgradeResponse(headers);

    // We need to pass these through for authentication to work.
    case HTTP_UNAUTHORIZED:
    case HTTP_PROXY_AUTHENTICATION_REQUIRED:
      return OK;

    // Other status codes are potentially risky (see the warnings in the
    // WHATWG WebSocket API spec) and so are dropped by default.
    default:
      OnFailure(
          base::StringPrintf(
              "Error during WebSocket handshake: Unexpected response code: %d",
              headers->response_code()),
          ERR_FAILED, headers->response_code());
      result_ = HandshakeResult::HTTP3_INVALID_STATUS;
      return ERR_INVALID_RESPONSE;
  }
}

int WebSocketHttp3HandshakeStream::ValidateUpgradeResponse(
    const HttpResponseHeaders* headers) {
  extension_params_ = std::make_unique<WebSocketExtensionParams>();
  std::string failure_message;
  if (!ValidateStatus(headers)) {
    result_ = HandshakeResult::HTTP3_INVALID_STATUS;
  } else if (!ValidateSubProtocol(headers, requested_sub_protocols_,
                                  &sub_protocol_, &failure_message)) {
    result_ = HandshakeResult::HTTP3_FAILED_SUBPROTO;
  } else if (!ValidateExtensions(headers, &extensions_, &failure_message,
                                 extension_params_.get())) {
    result_ = HandshakeResult::HTTP3_FAILED_EXTENSIONS;
  } else {
    result_ = HandshakeResult::HTTP3_CONNECTED;
    return OK;
  }

  const int rv = ERR_INVALID_RESPONSE;
  OnFailure("Error during WebSocket handshake: " + failure_message, rv,
            std::nullopt);
  return rv;
}

// TODO(momoka): Implement this.
void WebSocketHttp3HandshakeStream::OnFailure(
    const std::string& message,
    int net_error,
    std::optional<int> response_code) {
  stream_request_->OnFailure(message, net_error, response_code);
}

}  // namespace net

"""

```