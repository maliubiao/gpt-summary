Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

1. **Understand the Goal:** The primary goal is to analyze the provided C++ code (`websocket_stream.cc`) and explain its functionality, its relationship to JavaScript, potential errors, and debugging information.

2. **Initial Skim and Keyword Recognition:**  First, I'd quickly skim the code looking for familiar keywords and structures related to networking and WebSockets:
    * `#include`:  Indicates dependencies on other modules (like `net/base/`, `net/websockets/`, `net/url_request/`). This gives a general idea of the code's scope.
    * `namespace net`: Confirms it's part of the Chromium networking stack.
    * `WebSocketStream`, `WebSocketStreamRequest`, `ConnectDelegate`: These are the main classes, suggesting core functionality.
    * `URLRequest`, `URLRequestContext`:  Indicates interaction with the URL loading system.
    * `HttpRequestHeaders`, `HttpResponseHeaders`:  Confirms involvement in HTTP(S) interactions.
    * `kUpgrade`, `kWebSocketLowercase`, `kSecWebSocketVersion`: These constants relate to the WebSocket handshake process.
    * `OnConnected`, `OnResponseStarted`, `OnReadCompleted`: These are typical `URLRequest::Delegate` methods, showing how the code interacts with URL requests.
    * `base::BindOnce`, `base::OneShotTimer`:  Indicates asynchronous operations and timeouts.

3. **Identify Key Classes and Their Roles:** Based on the skim, I'd identify the core classes and their apparent roles:
    * `WebSocketStreamRequestImpl`:  This seems to be the central class responsible for initiating and managing the WebSocket connection handshake. The "Impl" suffix often signifies a concrete implementation.
    * `WebSocketStream`:  Likely an abstract base class or interface for WebSocket streams. The `CreateAndConnectStream` methods confirm its role in creating connections.
    * `ConnectDelegate`: An interface for handling events during the connection process (success, failure, authentication, etc.).
    * `Delegate`: A nested class implementing `URLRequest::Delegate`, responsible for handling events from the underlying `URLRequest`.

4. **Trace the Connection Flow:** I'd then try to trace the typical flow of a WebSocket connection based on the code:
    * **Initiation:** `WebSocketStream::CreateAndConnectStream` is called, creating a `WebSocketStreamRequestImpl`.
    * **Request Setup:** `WebSocketStreamRequestImpl` sets up a `URLRequest` with specific headers required for the WebSocket handshake (Upgrade, Connection, Origin, Sec-WebSocket-Version).
    * **Handshake Start:** `url_request_->Start()` is called, initiating the HTTP(S) request.
    * **URLRequest Delegate Events:** The `Delegate` class handles events from the `URLRequest`:
        * `OnConnected`:  Notifies the `ConnectDelegate` about the connection.
        * `OnResponseStarted`: This is crucial for checking the HTTP response code. A 101 (Switching Protocols) indicates success. Other codes might indicate authentication or errors.
        * `OnAuthRequired`: Handles HTTP authentication challenges.
        * `OnSSLCertificateError`: Handles SSL certificate errors.
    * **Handshake Stream Creation:**  The `WebSocketHandshakeStreamCreateHelper` (set as user data on the `URLRequest`) is likely responsible for creating the appropriate handshake stream (`WebSocketBasicHandshakeStream`, `WebSocketHttp2HandshakeStream`, `WebSocketHttp3HandshakeStream`) based on the protocol.
    * **Upgrade:** If the handshake is successful (101 response), `PerformUpgrade` is called, obtaining the underlying transport stream from the handshake stream and notifying the `ConnectDelegate` of success.
    * **Failure Handling:**  The `OnFailure` methods in `WebSocketStreamRequestImpl` handle various error scenarios (network errors, invalid responses, timeouts).

5. **Identify JavaScript Interaction Points:**  The key connection to JavaScript is the initiation of the WebSocket connection. JavaScript code uses the `WebSocket` API (e.g., `new WebSocket('wss://example.com')`) which triggers the browser's networking stack, eventually leading to the execution of this C++ code. The `origin` parameter is crucial here, as it's determined by the JavaScript code's context. The subprotocols are also specified in the JavaScript constructor.

6. **Look for Logic and Potential Issues:**
    * **Timeout:** The `kHandshakeTimeoutIntervalInSeconds` and the `base::OneShotTimer` are important for preventing indefinitely hanging connections.
    * **Error Handling:**  The code includes specific error messages for common problems like `ERR_TUNNEL_CONNECTION_FAILED`.
    * **Redirection Handling:** The `OnReceivedRedirect` method explicitly forbids external redirects, highlighting a security concern.
    * **Authentication:** The `OnAuthRequired` logic shows how the browser handles HTTP authentication for WebSocket connections.
    * **SSL Errors:** The `OnSSLCertificateError` method allows the `ConnectDelegate` to handle SSL certificate issues.

7. **Consider User Errors and Debugging:**  Think about common mistakes developers might make when using WebSockets in JavaScript and how those errors might manifest in this C++ code:
    * Incorrect WebSocket URL (`ws://` instead of `wss://`, wrong hostname).
    * Network connectivity problems.
    * Server-side issues preventing the handshake.
    * Authentication failures.
    * SSL certificate problems.

8. **Structure the Explanation:** Organize the information logically:
    * **Functionality Overview:** Start with a high-level summary of the file's purpose.
    * **Key Components:** Describe the important classes and their roles.
    * **JavaScript Relationship:** Explain how JavaScript interacts with this code.
    * **Logic and Assumptions:** Detail the decision-making within the code.
    * **Common Errors:** Provide examples of user/programming mistakes.
    * **Debugging:** Offer insights into how to trace execution to this point.

9. **Refine and Add Details:** Go back through the code and add specific details, such as the purpose of particular headers, the specific error codes handled, and the purpose of the histograms.

10. **Review and Verify:** Finally, review the explanation for accuracy and clarity. Ensure that the examples and assumptions are consistent with the code.

By following these steps, I can systematically analyze the C++ code and generate a comprehensive explanation that addresses all the points raised in the original request. The process involves understanding the code's structure, tracing its execution flow, identifying key interactions, and considering potential issues and debugging strategies.
这个文件 `net/websockets/websocket_stream.cc` 是 Chromium 网络栈中负责建立和管理 WebSocket 连接的核心组件之一。它处理了 WebSocket 握手过程，并负责在握手成功后建立实际的 WebSocket 数据流。

**功能列举:**

1. **WebSocket 连接的创建和发起:**  `WebSocketStream::CreateAndConnectStream` 函数是入口点，用于创建一个 `WebSocketStreamRequest` 对象并启动连接握手过程。它接收 WebSocket 的 URL、子协议、Origin、Cookie 设置、隔离信息、额外头信息等参数。
2. **构建和发送握手请求:**  `WebSocketStreamRequestImpl` 类负责构建 HTTP 请求，该请求包含升级到 WebSocket 协议所需的特定头部，例如 `Upgrade: websocket`, `Connection: Upgrade`, `Origin`, `Sec-WebSocket-Version` 等。
3. **处理服务器的握手响应:**  `Delegate` 类实现了 `URLRequest::Delegate` 接口，负责接收和解析服务器的 HTTP 响应。它检查响应状态码是否为 `101 Switching Protocols`，这是 WebSocket 握手成功的标志。
4. **处理重定向:**  `Delegate::OnReceivedRedirect` 方法处理服务器的重定向。出于安全考虑，WebSocket 连接不允许外部重定向，该方法会进行严格的检查。
5. **处理身份验证:**  `Delegate::OnAuthRequired` 方法处理服务器返回的 HTTP 身份验证挑战（例如 HTTP 401 或 407）。它会调用 `ConnectDelegate` 来获取凭据。
6. **处理 SSL 证书错误:** `Delegate::OnSSLCertificateError` 方法处理 SSL 证书相关的错误，允许用户或程序选择取消或继续连接。
7. **处理握手超时:**  `WebSocketStreamRequestImpl` 使用一个定时器来限制握手时间。如果超时，连接会被取消。
8. **创建不同类型的握手流:**  根据服务器的响应，可能会创建不同类型的握手流，例如 `WebSocketBasicHandshakeStream` (对于普通的 HTTP 升级), `WebSocketHttp2HandshakeStream` (对于 HTTP/2 连接), `WebSocketHttp3HandshakeStream` (对于 HTTP/3 连接)。这些流负责实际的握手细节。
9. **通知连接结果:**  `ConnectDelegate` 接口用于向调用者通知连接的成功或失败，并提供相关的握手信息。
10. **记录指标:**  使用 `base::UmaHistogramSparse` 记录 WebSocket 连接相关的错误码，用于统计和分析。

**与 JavaScript 的关系及举例说明:**

JavaScript 中使用 `WebSocket` API 来创建和管理 WebSocket 连接。当 JavaScript 代码执行 `new WebSocket('wss://example.com/socket')` 时，浏览器的网络栈会启动 WebSocket 连接过程，最终会调用到 `net/websockets/websocket_stream.cc` 中的代码。

**举例:**

假设 JavaScript 代码如下：

```javascript
const ws = new WebSocket('wss://example.com/chat', ['chat', 'superchat']);
```

1. **JavaScript 发起连接:**  JavaScript 的 `new WebSocket(...)` 调用触发浏览器发起 WebSocket 连接请求。
2. **传递参数到 C++:**  `'wss://example.com/chat'` 会作为 `socket_url` 传递给 C++ 的 `WebSocketStream::CreateAndConnectStream`。`['chat', 'superchat']` 会作为 `requested_subprotocols` 传递。浏览器的 Origin 信息也会被传递。
3. **C++ 构建请求:**  `WebSocketStreamRequestImpl` 会构建一个 HTTP 请求，其中包含以下关键头部：
    *   `Upgrade: websocket`
    *   `Connection: Upgrade`
    *   `Origin: <当前页面的 Origin>` (例如 `https://yourdomain.com`)
    *   `Sec-WebSocket-Protocol: chat, superchat`
    *   `Sec-WebSocket-Version: 13`
    *   `Sec-WebSocket-Key: ...` (一个随机的 Base64 编码的值)
4. **服务器响应:**  服务器如果接受连接，会返回一个 `101 Switching Protocols` 响应，其中包含 `Sec-WebSocket-Accept` 头部。
5. **C++ 处理响应:** `Delegate::OnResponseStarted` 检查状态码是否为 101。如果是，则调用 `PerformUpgrade`。
6. **通知 JavaScript:**  `PerformUpgrade` 会调用 `ConnectDelegate::OnSuccess`，最终会触发 JavaScript `WebSocket` 对象的 `open` 事件。

**逻辑推理 (假设输入与输出):**

**假设输入:**

*   `socket_url`: `wss://echo.websocket.org`
*   `requested_subprotocols`: `["json", "xml"]`
*   服务器返回的响应头:
    ```
    HTTP/1.1 101 Switching Protocols
    Upgrade: websocket
    Connection: Upgrade
    Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
    Sec-WebSocket-Protocol: json
    ```

**输出:**

*   `Delegate::OnResponseStarted` 会收到状态码 `200 OK` (假设在握手前有普通的 HTTP 请求)，然后接收到 `101 Switching Protocols` 响应。
*   `PerformUpgrade` 被调用。
*   `ConnectDelegate::OnSuccess` 被调用，传递一个表示 WebSocket 连接已建立的对象。
*   JavaScript 的 `WebSocket` 对象的 `open` 事件被触发。

**假设输入 (失败情况):**

*   `socket_url`: `wss://invalid-websocket-server.com`
*   服务器无响应或返回非 101 的状态码 (例如 404 Not Found)。

**输出:**

*   `Delegate::OnResponseStarted` 收到非 101 的状态码 (例如 404)。
*   `WebSocketStreamRequestImpl::ReportFailure` 被调用，传递相应的错误码和消息。
*   `ConnectDelegate::OnFailure` 被调用，通知连接失败。
*   JavaScript 的 `WebSocket` 对象的 `error` 事件被触发。

**用户或编程常见的使用错误及举例说明:**

1. **使用错误的 WebSocket URL:**  例如使用 `http://` 而不是 `ws://` 或 `https://` 而不是 `wss://`。这将导致握手请求失败。
    *   **例子:**  JavaScript 代码中使用 `new WebSocket('http://example.com/socket')`。这将导致浏览器尝试使用 HTTP 协议进行连接，服务器不会返回 `101 Switching Protocols`，最终连接失败。
2. **服务器不支持 WebSocket 协议:**  如果服务器没有实现 WebSocket 协议，它不会理解握手请求，也不会返回正确的响应。
    *   **例子:**  连接到一个普通的 HTTP 服务器，期望建立 WebSocket 连接。服务器会返回类似 `200 OK` 的响应，`Delegate::OnResponseStarted` 会处理这个非 `101` 的状态码并报告失败。
3. **网络问题或防火墙阻止连接:**  如果客户端和服务器之间的网络连接存在问题，握手请求可能无法到达服务器，或者服务器的响应无法到达客户端。这会导致超时或其他网络错误。
    *   **例子:**  客户端网络断开或者防火墙阻止了访问服务器的端口。`WebSocketStreamRequestImpl::OnTimeout` 可能会被调用，或者 `Delegate::OnResponseStarted` 会收到一个网络错误码。
4. **Origin 验证失败:**  某些 WebSocket 服务器会验证请求头中的 `Origin` 字段，如果与预期不符，则会拒绝连接。
    *   **例子:**  JavaScript 代码运行在 `https://malicious.com`，尝试连接到 `wss://example.com/socket`。如果 `example.com` 的服务器只允许来自 `https://example.com` 的连接，服务器可能会拒绝握手。
5. **子协议不匹配:**  客户端请求的子协议与服务器支持的子协议不匹配。
    *   **例子:**  JavaScript 请求子协议 `["chat"]`，但服务器只支持 `["notifications"]`。服务器可能返回 `101` 但不包含 `Sec-WebSocket-Protocol` 头，或者返回客户端未请求的子协议，导致连接后的数据处理出现问题。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中打开一个网页:**  例如 `https://yourdomain.com/chat.html`。
2. **网页中的 JavaScript 代码尝试建立 WebSocket 连接:**  `const ws = new WebSocket('wss://example.com/socket');` 被执行。
3. **浏览器解析 WebSocket URL:**  浏览器识别出这是一个 WebSocket 连接请求。
4. **浏览器网络栈开始处理连接请求:**  这涉及到 DNS 查询、TCP 连接建立 (如果是 `wss://` 还会涉及 TLS 握手)。
5. **调用到 `net/websockets/websocket_stream.cc`:**  `WebSocketStream::CreateAndConnectStream` 被调用，传入相关的连接参数。
6. **`WebSocketStreamRequestImpl` 创建 `URLRequest`:**  一个用于发送握手请求的 `URLRequest` 对象被创建，并设置了必要的头部信息。
7. **发送 HTTP 握手请求:**  `URLRequest` 发送包含 `Upgrade` 头部的 HTTP 请求到服务器。
8. **服务器响应被 `Delegate` 处理:**  服务器的 HTTP 响应被 `Delegate` 类的各个方法处理，例如 `OnResponseStarted`。
9. **根据响应结果执行后续操作:**
    *   **成功 (101):**  `PerformUpgrade` 被调用，建立 WebSocket 连接。
    *   **失败 (非 101):**  `ReportFailure` 被调用，通知连接失败。
    *   **需要身份验证 (401, 407):**  `OnAuthRequired` 被调用，尝试进行身份验证。
    *   **SSL 证书错误:** `OnSSLCertificateError` 被调用。

**作为调试线索:**

*   **查看浏览器的开发者工具 (Network 选项卡):**  可以查看 WebSocket 连接的握手请求和响应头，以及任何错误信息。
*   **使用 `chrome://net-internals/#events`:**  可以查看更底层的网络事件，包括 DNS 查询、TCP 连接、TLS 握手和 WebSocket 握手过程中的详细信息。
*   **设置网络日志:**  Chromium 提供了详细的网络日志功能，可以记录 WebSocket 连接的整个过程，包括 C++ 代码中的日志输出。
*   **断点调试:**  如果可以构建 Chromium，可以在 `net/websockets/websocket_stream.cc` 中设置断点，逐步跟踪代码的执行流程，查看各个变量的值，以定位问题所在。

理解 `net/websockets/websocket_stream.cc` 的功能对于调试 WebSocket 连接问题至关重要。通过查看网络请求、日志和代码执行流程，可以更好地理解连接建立的各个环节，并找出问题的原因。

### 提示词
```
这是目录为net/websockets/websocket_stream.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/websockets/websocket_stream.h"

#include <optional>
#include <ostream>
#include <utility>

#include "base/check.h"
#include "base/check_op.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/notreached.h"
#include "base/strings/strcat.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "net/base/auth.h"
#include "net/base/isolation_info.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/base/request_priority.h"
#include "net/base/url_util.h"
#include "net/cookies/cookie_util.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/http/http_status_code.h"
#include "net/storage_access_api/status.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/url_request/redirect_info.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/websocket_handshake_userdata_key.h"
#include "net/websockets/websocket_basic_handshake_stream.h"
#include "net/websockets/websocket_event_interface.h"
#include "net/websockets/websocket_handshake_constants.h"
#include "net/websockets/websocket_handshake_response_info.h"
#include "net/websockets/websocket_handshake_stream_base.h"
#include "net/websockets/websocket_handshake_stream_create_helper.h"
#include "net/websockets/websocket_http2_handshake_stream.h"
#include "net/websockets/websocket_http3_handshake_stream.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {
class SSLCertRequestInfo;
class SSLInfo;
class SiteForCookies;

namespace {

// The timeout duration of WebSocket handshake.
// It is defined as the same value as the TCP connection timeout value in
// net/socket/websocket_transport_client_socket_pool.cc to make it hard for
// JavaScript programs to recognize the timeout cause.
constexpr int kHandshakeTimeoutIntervalInSeconds = 240;

class WebSocketStreamRequestImpl;

class Delegate : public URLRequest::Delegate {
 public:
  explicit Delegate(WebSocketStreamRequestImpl* owner) : owner_(owner) {}
  ~Delegate() override = default;

  // Implementation of URLRequest::Delegate methods.
  int OnConnected(URLRequest* request,
                  const TransportInfo& info,
                  CompletionOnceCallback callback) override;

  void OnReceivedRedirect(URLRequest* request,
                          const RedirectInfo& redirect_info,
                          bool* defer_redirect) override;

  void OnResponseStarted(URLRequest* request, int net_error) override;

  void OnAuthRequired(URLRequest* request,
                      const AuthChallengeInfo& auth_info) override;

  void OnCertificateRequested(URLRequest* request,
                              SSLCertRequestInfo* cert_request_info) override;

  void OnSSLCertificateError(URLRequest* request,
                             int net_error,
                             const SSLInfo& ssl_info,
                             bool fatal) override;

  void OnReadCompleted(URLRequest* request, int bytes_read) override;

 private:
  void OnAuthRequiredComplete(URLRequest* request,
                              const AuthCredentials* auth_credentials);

  raw_ptr<WebSocketStreamRequestImpl> owner_;
};

class WebSocketStreamRequestImpl : public WebSocketStreamRequestAPI {
 public:
  WebSocketStreamRequestImpl(
      const GURL& url,
      const std::vector<std::string>& requested_subprotocols,
      const URLRequestContext* context,
      const url::Origin& origin,
      const SiteForCookies& site_for_cookies,
      StorageAccessApiStatus storage_access_api_status,
      const IsolationInfo& isolation_info,
      const HttpRequestHeaders& additional_headers,
      NetworkTrafficAnnotationTag traffic_annotation,
      std::unique_ptr<WebSocketStream::ConnectDelegate> connect_delegate,
      std::unique_ptr<WebSocketStreamRequestAPI> api_delegate)
      : delegate_(this),
        connect_delegate_(std::move(connect_delegate)),
        url_request_(context->CreateRequest(url,
                                            DEFAULT_PRIORITY,
                                            &delegate_,
                                            traffic_annotation,
                                            /*is_for_websockets=*/true)),
        api_delegate_(std::move(api_delegate)) {
    DCHECK_EQ(IsolationInfo::RequestType::kOther,
              isolation_info.request_type());

    HttpRequestHeaders headers = additional_headers;
    headers.SetHeader(websockets::kUpgrade, websockets::kWebSocketLowercase);
    headers.SetHeader(HttpRequestHeaders::kConnection, websockets::kUpgrade);
    headers.SetHeader(HttpRequestHeaders::kOrigin, origin.Serialize());
    headers.SetHeader(websockets::kSecWebSocketVersion,
                      websockets::kSupportedVersion);

    // Remove HTTP headers that are important to websocket connections: they
    // will be added later.
    headers.RemoveHeader(websockets::kSecWebSocketExtensions);
    headers.RemoveHeader(websockets::kSecWebSocketKey);
    headers.RemoveHeader(websockets::kSecWebSocketProtocol);

    url_request_->SetExtraRequestHeaders(headers);
    url_request_->set_initiator(origin);
    url_request_->set_site_for_cookies(site_for_cookies);
    url_request_->set_isolation_info(isolation_info);

    cookie_util::AddOrRemoveStorageAccessApiOverride(
        url, storage_access_api_status, url_request_->initiator(),
        url_request_->cookie_setting_overrides());

    auto create_helper = std::make_unique<WebSocketHandshakeStreamCreateHelper>(
        connect_delegate_.get(), requested_subprotocols, this);
    url_request_->SetUserData(kWebSocketHandshakeUserDataKey,
                              std::move(create_helper));
    url_request_->SetLoadFlags(LOAD_DISABLE_CACHE | LOAD_BYPASS_CACHE);
    connect_delegate_->OnCreateRequest(url_request_.get());
  }

  // Destroying this object destroys the URLRequest, which cancels the request
  // and so terminates the handshake if it is incomplete.
  ~WebSocketStreamRequestImpl() override {
    if (ws_upgrade_success_) {
      CHECK(url_request_);
      // "Cancel" the request with an error code indicating the upgrade
      // succeeded.
      url_request_->CancelWithError(ERR_WS_UPGRADE);
    }
  }

  void OnBasicHandshakeStreamCreated(
      WebSocketBasicHandshakeStream* handshake_stream) override {
    if (api_delegate_) {
      api_delegate_->OnBasicHandshakeStreamCreated(handshake_stream);
    }
    OnHandshakeStreamCreated(handshake_stream);
  }

  void OnHttp2HandshakeStreamCreated(
      WebSocketHttp2HandshakeStream* handshake_stream) override {
    if (api_delegate_) {
      api_delegate_->OnHttp2HandshakeStreamCreated(handshake_stream);
    }
    OnHandshakeStreamCreated(handshake_stream);
  }

  void OnHttp3HandshakeStreamCreated(
      WebSocketHttp3HandshakeStream* handshake_stream) override {
    if (api_delegate_) {
      api_delegate_->OnHttp3HandshakeStreamCreated(handshake_stream);
    }
    OnHandshakeStreamCreated(handshake_stream);
  }

  void OnFailure(const std::string& message,
                 int net_error,
                 std::optional<int> response_code) override {
    if (api_delegate_)
      api_delegate_->OnFailure(message, net_error, response_code);
    failure_message_ = message;
    failure_net_error_ = net_error;
    failure_response_code_ = response_code;
  }

  void Start(std::unique_ptr<base::OneShotTimer> timer) {
    DCHECK(timer);
    base::TimeDelta timeout(base::Seconds(kHandshakeTimeoutIntervalInSeconds));
    timer_ = std::move(timer);
    timer_->Start(FROM_HERE, timeout,
                  base::BindOnce(&WebSocketStreamRequestImpl::OnTimeout,
                                 base::Unretained(this)));
    url_request_->Start();
  }

  void PerformUpgrade() {
    DCHECK(timer_);
    DCHECK(connect_delegate_);

    timer_->Stop();

    if (!handshake_stream_) {
      ReportFailureWithMessage(
          "No handshake stream has been created or handshake stream is already "
          "destroyed.",
          ERR_FAILED, std::nullopt);
      return;
    }

    if (!handshake_stream_->CanReadFromStream()) {
      ReportFailureWithMessage("Handshake stream is not readable.",
                               ERR_CONNECTION_CLOSED, std::nullopt);
      return;
    }

    ws_upgrade_success_ = true;
    WebSocketHandshakeStreamBase* handshake_stream = handshake_stream_.get();
    handshake_stream_.reset();
    auto handshake_response_info =
        std::make_unique<WebSocketHandshakeResponseInfo>(
            url_request_->url(), url_request_->response_headers(),
            url_request_->GetResponseRemoteEndpoint(),
            url_request_->response_time());
    connect_delegate_->OnSuccess(handshake_stream->Upgrade(),
                                 std::move(handshake_response_info));
  }

  std::string FailureMessageFromNetError(int net_error) {
    if (net_error == ERR_TUNNEL_CONNECTION_FAILED) {
      // This error is common and confusing, so special-case it.
      // TODO(ricea): Include the HostPortPair of the selected proxy server in
      // the error message. This is not currently possible because it isn't set
      // in HttpResponseInfo when a ERR_TUNNEL_CONNECTION_FAILED error happens.
      return "Establishing a tunnel via proxy server failed.";
    } else {
      return base::StrCat(
          {"Error in connection establishment: ", ErrorToString(net_error)});
    }
  }

  void ReportFailure(int net_error, std::optional<int> response_code) {
    DCHECK(timer_);
    timer_->Stop();
    if (failure_message_.empty()) {
      switch (net_error) {
        case OK:
        case ERR_IO_PENDING:
          break;
        case ERR_ABORTED:
          failure_message_ = "WebSocket opening handshake was canceled";
          break;
        case ERR_TIMED_OUT:
          failure_message_ = "WebSocket opening handshake timed out";
          break;
        default:
          failure_message_ = FailureMessageFromNetError(net_error);
          break;
      }
    }

    ReportFailureWithMessage(
        failure_message_, failure_net_error_.value_or(net_error),
        failure_response_code_ ? failure_response_code_ : response_code);
  }

  void ReportFailureWithMessage(const std::string& failure_message,
                                int net_error,
                                std::optional<int> response_code) {
    connect_delegate_->OnFailure(failure_message, net_error, response_code);
  }

  WebSocketStream::ConnectDelegate* connect_delegate() const {
    return connect_delegate_.get();
  }

  void OnTimeout() {
    url_request_->CancelWithError(ERR_TIMED_OUT);
  }

 private:
  void OnHandshakeStreamCreated(
      WebSocketHandshakeStreamBase* handshake_stream) {
    DCHECK(handshake_stream);

    handshake_stream_ = handshake_stream->GetWeakPtr();
  }

  // |delegate_| needs to be declared before |url_request_| so that it gets
  // initialised first and destroyed second.
  Delegate delegate_;

  std::unique_ptr<WebSocketStream::ConnectDelegate> connect_delegate_;

  // Deleting the WebSocketStreamRequestImpl object deletes this URLRequest
  // object, cancelling the whole connection. Must be destroyed before
  // `delegate_`, since `url_request_` has a pointer to it, and before
  // `connect_delegate_`, because there may be a pointer to it further down the
  // stack.
  const std::unique_ptr<URLRequest> url_request_;

  // This is owned by the caller of
  // WebsocketHandshakeStreamCreateHelper::CreateBasicStream() or
  // CreateHttp2Stream() or CreateHttp3Stream().  Both the stream and this
  // object will be destroyed during the destruction of the URLRequest object
  // associated with the handshake. This is only guaranteed to be a valid
  // pointer if the handshake succeeded.
  base::WeakPtr<WebSocketHandshakeStreamBase> handshake_stream_;

  // The failure information supplied by WebSocketBasicHandshakeStream, if any.
  std::string failure_message_;
  std::optional<int> failure_net_error_;
  std::optional<int> failure_response_code_;

  // A timer for handshake timeout.
  std::unique_ptr<base::OneShotTimer> timer_;

  // Set to true if the websocket upgrade succeeded.
  bool ws_upgrade_success_ = false;

  // A delegate for On*HandshakeCreated and OnFailure calls.
  std::unique_ptr<WebSocketStreamRequestAPI> api_delegate_;
};

class SSLErrorCallbacks : public WebSocketEventInterface::SSLErrorCallbacks {
 public:
  explicit SSLErrorCallbacks(URLRequest* url_request)
      : url_request_(url_request->GetWeakPtr()) {}

  void CancelSSLRequest(int error, const SSLInfo* ssl_info) override {
    if (!url_request_)
      return;

    if (ssl_info) {
      url_request_->CancelWithSSLError(error, *ssl_info);
    } else {
      url_request_->CancelWithError(error);
    }
  }

  void ContinueSSLRequest() override {
    if (url_request_)
      url_request_->ContinueDespiteLastError();
  }

 private:
  base::WeakPtr<URLRequest> url_request_;
};

int Delegate::OnConnected(URLRequest* request,
                          const TransportInfo& info,
                          CompletionOnceCallback callback) {
  owner_->connect_delegate()->OnURLRequestConnected(request, info);
  return OK;
}

void Delegate::OnReceivedRedirect(URLRequest* request,
                                  const RedirectInfo& redirect_info,
                                  bool* defer_redirect) {
  // This code should never be reached for externally generated redirects,
  // as WebSocketBasicHandshakeStream is responsible for filtering out
  // all response codes besides 101, 401, and 407. As such, the URLRequest
  // should never see a redirect sent over the network. However, internal
  // redirects also result in this method being called, such as those
  // caused by HSTS.
  // Because it's security critical to prevent externally-generated
  // redirects in WebSockets, perform additional checks to ensure this
  // is only internal.
  GURL::Replacements replacements;
  replacements.SetSchemeStr("wss");
  GURL expected_url = request->original_url().ReplaceComponents(replacements);
  if (redirect_info.new_method != "GET" ||
      redirect_info.new_url != expected_url) {
    // This should not happen.
    DLOG(FATAL) << "Unauthorized WebSocket redirect to "
                << redirect_info.new_method << " "
                << redirect_info.new_url.spec();
    request->Cancel();
  }
}

void Delegate::OnResponseStarted(URLRequest* request, int net_error) {
  DCHECK_NE(ERR_IO_PENDING, net_error);

  const bool is_http2 =
      request->response_info().connection_info == HttpConnectionInfo::kHTTP2;

  // All error codes, including OK and ABORTED, as with
  // Net.ErrorCodesForMainFrame4
  base::UmaHistogramSparse("Net.WebSocket.ErrorCodes", -net_error);
  if (is_http2) {
    base::UmaHistogramSparse("Net.WebSocket.ErrorCodes.Http2", -net_error);
  }
  if (net::IsLocalhost(request->url())) {
    base::UmaHistogramSparse("Net.WebSocket.ErrorCodes_Localhost", -net_error);
  } else {
    base::UmaHistogramSparse("Net.WebSocket.ErrorCodes_NotLocalhost",
                             -net_error);
  }

  if (net_error != OK) {
    DVLOG(3) << "OnResponseStarted (request failed)";
    owner_->ReportFailure(net_error, std::nullopt);
    return;
  }
  const int response_code = request->GetResponseCode();
  DVLOG(3) << "OnResponseStarted (response code " << response_code << ")";

  if (is_http2) {
    if (response_code == HTTP_OK) {
      owner_->PerformUpgrade();
      return;
    }

    owner_->ReportFailure(net_error, std::nullopt);
    return;
  }

  switch (response_code) {
    case HTTP_SWITCHING_PROTOCOLS:
      owner_->PerformUpgrade();
      return;

    case HTTP_UNAUTHORIZED:
      owner_->ReportFailureWithMessage(
          "HTTP Authentication failed; no valid credentials available",
          net_error, response_code);
      return;

    case HTTP_PROXY_AUTHENTICATION_REQUIRED:
      owner_->ReportFailureWithMessage("Proxy authentication failed", net_error,
                                       response_code);
      return;

    default:
      owner_->ReportFailure(net_error, response_code);
  }
}

void Delegate::OnAuthRequired(URLRequest* request,
                              const AuthChallengeInfo& auth_info) {
  std::optional<AuthCredentials> credentials;
  // This base::Unretained(this) relies on an assumption that |callback| can
  // be called called during the opening handshake.
  int rv = owner_->connect_delegate()->OnAuthRequired(
      auth_info, request->response_headers(),
      request->GetResponseRemoteEndpoint(),
      base::BindOnce(&Delegate::OnAuthRequiredComplete, base::Unretained(this),
                     request),
      &credentials);
  request->LogBlockedBy("WebSocketStream::Delegate::OnAuthRequired");
  if (rv == ERR_IO_PENDING)
    return;
  if (rv != OK) {
    request->LogUnblocked();
    owner_->ReportFailure(rv, std::nullopt);
    return;
  }
  OnAuthRequiredComplete(request, nullptr);
}

void Delegate::OnAuthRequiredComplete(URLRequest* request,
                                      const AuthCredentials* credentials) {
  request->LogUnblocked();
  if (!credentials) {
    request->CancelAuth();
    return;
  }
  request->SetAuth(*credentials);
}

void Delegate::OnCertificateRequested(URLRequest* request,
                                      SSLCertRequestInfo* cert_request_info) {
  // This method is called when a client certificate is requested, and the
  // request context does not already contain a client certificate selection for
  // the endpoint. In this case, a main frame resource request would pop-up UI
  // to permit selection of a client certificate, but since WebSockets are
  // sub-resources they should not pop-up UI and so there is nothing more we can
  // do.
  request->Cancel();
}

void Delegate::OnSSLCertificateError(URLRequest* request,
                                     int net_error,
                                     const SSLInfo& ssl_info,
                                     bool fatal) {
  owner_->connect_delegate()->OnSSLCertificateError(
      std::make_unique<SSLErrorCallbacks>(request), net_error, ssl_info, fatal);
}

void Delegate::OnReadCompleted(URLRequest* request, int bytes_read) {
  NOTREACHED();
}

}  // namespace

WebSocketStreamRequest::~WebSocketStreamRequest() = default;

WebSocketStream::WebSocketStream() = default;
WebSocketStream::~WebSocketStream() = default;

WebSocketStream::ConnectDelegate::~ConnectDelegate() = default;

std::unique_ptr<WebSocketStreamRequest> WebSocketStream::CreateAndConnectStream(
    const GURL& socket_url,
    const std::vector<std::string>& requested_subprotocols,
    const url::Origin& origin,
    const SiteForCookies& site_for_cookies,
    StorageAccessApiStatus storage_access_api_status,
    const IsolationInfo& isolation_info,
    const HttpRequestHeaders& additional_headers,
    URLRequestContext* url_request_context,
    const NetLogWithSource& net_log,
    NetworkTrafficAnnotationTag traffic_annotation,
    std::unique_ptr<ConnectDelegate> connect_delegate) {
  auto request = std::make_unique<WebSocketStreamRequestImpl>(
      socket_url, requested_subprotocols, url_request_context, origin,
      site_for_cookies, storage_access_api_status, isolation_info,
      additional_headers, traffic_annotation, std::move(connect_delegate),
      nullptr);
  request->Start(std::make_unique<base::OneShotTimer>());
  return std::move(request);
}

std::unique_ptr<WebSocketStreamRequest>
WebSocketStream::CreateAndConnectStreamForTesting(
    const GURL& socket_url,
    const std::vector<std::string>& requested_subprotocols,
    const url::Origin& origin,
    const SiteForCookies& site_for_cookies,
    StorageAccessApiStatus storage_access_api_status,
    const IsolationInfo& isolation_info,
    const HttpRequestHeaders& additional_headers,
    URLRequestContext* url_request_context,
    const NetLogWithSource& net_log,
    NetworkTrafficAnnotationTag traffic_annotation,
    std::unique_ptr<WebSocketStream::ConnectDelegate> connect_delegate,
    std::unique_ptr<base::OneShotTimer> timer,
    std::unique_ptr<WebSocketStreamRequestAPI> api_delegate) {
  auto request = std::make_unique<WebSocketStreamRequestImpl>(
      socket_url, requested_subprotocols, url_request_context, origin,
      site_for_cookies, storage_access_api_status, isolation_info,
      additional_headers, traffic_annotation, std::move(connect_delegate),
      std::move(api_delegate));
  request->Start(std::move(timer));
  return std::move(request);
}

}  // namespace net
```