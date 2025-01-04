Response:
The user wants me to analyze a C++ source code file related to WebSocket testing in the Chromium project. I need to extract its functionality and look for connections to JavaScript, logical reasoning, potential user errors, and debugging information.

Here's a breakdown of the steps:

1. **Identify the main purpose of the file:** The file name and initial comments clearly indicate it's for end-to-end testing of the WebSocket functionality in Chromium's network stack.

2. **List the key functionalities:** This will involve looking at the classes and methods defined in the file. I should focus on what actions these components perform.

3. **Analyze the relationship with JavaScript:**  WebSockets are primarily used by JavaScript in web browsers. I need to identify how this C++ code interacts with or tests scenarios that would be initiated by JavaScript.

4. **Look for logical reasoning:**  Are there any conditional statements or algorithms that perform a specific type of logic? I should provide examples with hypothetical inputs and outputs.

5. **Identify potential user/programming errors:**  Based on the code's functionality, what mistakes could a developer or user make that would lead to issues tested here?

6. **Describe the user journey to reach this code:**  How does a user's action in a browser eventually lead to the execution of this C++ code during testing?

7. **Summarize the functionality:**  Provide a concise overview of the file's purpose based on the above analysis.

Let's go through the code section by section to extract this information.

*   **Includes:**  These indicate the dependencies and the types of operations the code performs (e.g., networking, files, strings, testing).
*   **`ConnectTestingEventInterface` class:** This class seems crucial. It acts as a listener for WebSocket events during the connection process and records the results.
*   **`WebSocketEndToEndTest` class:**  This is the main test fixture, setting up the testing environment and running various test cases. It utilizes `ConnectTestingEventInterface` to verify the outcomes.
*   **Individual `TEST_F` functions:** Each of these represents a specific test scenario for WebSocket functionality, including basic connectivity, message handling, proxy configurations, HSTS, and header processing.

Now, let's address each of the user's specific requests.
这是对 Chromium 网络栈中 `net/websockets/websocket_end_to_end_test.cc` 文件功能的归纳，涵盖了其主要作用和涉及的各个方面。

**功能归纳：**

`websocket_end_to_end_test.cc` 文件的主要功能是为 Chromium 的 WebSocket 实现进行端到端（end-to-end）的集成测试。这意味着它模拟了从客户端发起 WebSocket 连接到服务器响应的完整过程，以此来验证 WebSocket 功能的正确性和可靠性。

**具体功能点：**

1. **WebSocket 连接建立测试:**
    *   测试基本的 WebSocket 连接建立流程，包括握手过程。
    *   支持测试 HTTP 和 HTTPS 协议下的 WebSocket 连接（`ws://` 和 `wss://`）。
    *   可以模拟各种服务器响应情况，包括成功的握手和失败的握手。
    *   可以测试带有子协议和扩展的 WebSocket 连接。

2. **WebSocket 数据传输测试:**
    *   测试 WebSocket 连接建立后，客户端向服务器发送和接收数据的能力。
    *   可以发送和接收文本消息。

3. **代理服务器测试:**
    *   测试 WebSocket 连接在通过各种类型的代理服务器（如 HTTP 代理、HTTPS 代理、需要认证的代理）时的行为。
    *   验证代理配置是否被正确使用。

4. **HSTS (HTTP Strict Transport Security) 测试:**
    *   测试 HSTS 策略是否正确应用于 WebSocket 连接，例如，当站点设置了 HSTS 后，是否会将 `ws://` 连接升级为 `wss://`。

5. **HTTP 头处理测试:**
    *   测试 WebSocket 握手过程中对 HTTP 头的处理，例如，测试服务器响应头中是否正确处理了尾随空格和连续行。

6. **DNS 功能测试:**
    *   测试在接收到 DNS HTTPS 记录时，是否支持将 `ws://` 连接升级到 `wss://`。
    *   测试 `HostResolverEndpointResults` 功能在 WebSocket 连接中的使用。

7. **错误处理测试:**
    *   测试连接失败的情况，例如代理认证失败、服务器返回截断的响应等。

8. **使用嵌入式测试服务器:**
    *   利用 Chromium 的嵌入式测试服务器 (`EmbeddedTestServer`) 来模拟各种 WebSocket 服务器行为，方便进行本地测试，无需外部服务器依赖。

9. **模拟用户操作:**
    *   虽然代码本身是 C++ 测试代码，但它模拟了浏览器中 JavaScript 代码发起 WebSocket 连接的行为。

**与 JavaScript 的关系及举例：**

虽然这个 C++ 文件本身不是 JavaScript 代码，但它测试的是 JavaScript 在浏览器中使用的 WebSocket API 的底层实现。

**举例说明：**

*   当 JavaScript 代码执行 `new WebSocket('ws://example.com/socket')` 时，Chromium 的网络栈会开始建立 WebSocket 连接。 `websocket_end_to_end_test.cc` 中的测试用例会模拟这个过程，例如 `TEST_F(WebSocketEndToEndTest, BasicSmokeTest)` 就是测试这种最基本的连接场景。
*   JavaScript 代码可以使用子协议，例如 `new WebSocket('ws://example.com/socket', ['chat', 'superchat'])`。 `websocket_end_to_end_test.cc` 中的测试用例（虽然当前提供的代码片段中没有直接体现，但通常会有）会设置 `sub_protocols_` 成员变量来模拟这种情况，并验证服务器是否正确选择了子协议。
*   JavaScript 代码可以发送消息 `websocket.send('Hello')`。 `websocket_end_to_end_test.cc` 中的 `SendMessage` 方法模拟了这种发送行为，并通过 `ReceiveMessage` 验证服务器是否正确接收并可能回显了消息。

**逻辑推理的假设输入与输出：**

以下是一些基于代码逻辑的假设输入和输出的例子：

**假设 1：测试通过未认证的 HTTPS 代理连接 WebSocket 服务器**

*   **假设输入:**
    *   一个运行在本地的未认证 HTTPS 代理服务器。
    *   一个运行在本地的 WebSocket 服务器。
    *   测试代码配置 Chromium 使用该 HTTPS 代理连接 WebSocket 服务器。
*   **逻辑推理:**  根据 HTTP 代理的工作原理，即使连接的是 WebSocket 服务器，也需要先通过代理建立连接。对于未认证的 HTTPS 代理，连接应该可以正常建立。
*   **预期输出:**  `ConnectAndWait` 返回 `true`，表示连接成功。

**假设 2：测试通过需要认证的 HTTPS 代理连接 WebSocket 服务器**

*   **假设输入:**
    *   一个运行在本地的需要用户名和密码认证的 HTTPS 代理服务器。
    *   一个运行在本地的 WebSocket 服务器。
    *   测试代码配置 Chromium 使用该 HTTPS 代理连接 WebSocket 服务器，但未提供认证信息。
*   **逻辑推理:**  HTTPS 代理需要认证，如果未提供认证信息，连接将被代理服务器拒绝。
*   **预期输出:**  `ConnectAndWait` 返回 `false`，`event_interface_->failure_message()` 返回 "Proxy authentication failed"。

**用户或编程常见的使用错误及举例：**

1. **使用了错误的 WebSocket URL scheme：** 用户可能错误地使用了 `http://` 或 `https://` 而不是 `ws://` 或 `wss://` 来尝试建立 WebSocket 连接。测试用例可能会验证这种情况下的连接失败，并给出相应的错误信息。

2. **服务器未实现 WebSocket 协议：** 用户尝试连接到一个只支持 HTTP 的服务器，而不是 WebSocket 服务器。测试用例会模拟这种情况，验证握手失败。

3. **代理配置错误：** 用户在系统或浏览器中配置了错误的代理信息，导致 WebSocket 连接无法通过代理建立。相关的测试用例会模拟各种代理配置错误，并验证连接失败的情况。例如，`MAYBE_HttpsProxyUnauthedFails` 测试了当配置了 HTTPS 代理但未提供认证信息时的失败情况。

4. **HSTS 设置导致的连接问题：**  用户可能在某个域名下通过 HTTPS 访问过，并接收到了 HSTS 头，导致浏览器强制将该域名的 `ws://` 连接升级为 `wss://`。如果服务器只支持 `ws://`，则连接会失败。`HstsHttpsToWebSocket` 测试了这种情况。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入一个使用了 WebSocket 的网页地址，或者点击了一个触发 WebSocket 连接的链接或按钮。**

2. **网页中的 JavaScript 代码执行 `new WebSocket(url)`，其中 `url` 是 WebSocket 服务器的地址。**

3. **浏览器内核接收到 JavaScript 的 WebSocket 连接请求，并调用网络栈的相关接口。**

4. **网络栈开始进行 WebSocket 握手，构建 HTTP 请求头，并通过 TCP 连接发送到服务器。**

5. **服务器响应握手请求，网络栈解析服务器的响应头。**

6. **如果握手成功，WebSocket 连接建立，JavaScript 代码可以通过 `websocket.send()` 和 `websocket.onmessage` 进行数据传输。**

7. **在开发和测试阶段，为了验证 WebSocket 功能的正确性，Chromium 的开发者会运行 `websocket_end_to_end_test.cc` 中的测试用例。** 这些测试用例会模拟上述用户操作的各个环节，例如 `ConnectAndWait` 模拟了 JavaScript 发起连接，`SendMessage` 模拟了发送消息，而 `ConnectTestingEventInterface` 用于捕获和验证连接过程中的各种事件和状态。

**总结：**

`websocket_end_to_end_test.cc` 是一个关键的测试文件，用于全面验证 Chromium 网络栈中 WebSocket 功能的正确性和鲁棒性。它通过模拟各种客户端和服务端行为，以及不同的网络环境（如代理、HSTS），来确保 WebSocket 功能在各种场景下都能正常工作，为开发者提供调试和排错的依据。
Prompt: 
```
这是目录为net/websockets/websocket_end_to_end_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// End-to-end tests for WebSocket.
//
// A python server is (re)started for each test, which is moderately
// inefficient. However, it makes these tests a good fit for scenarios which
// require special server configurations.

#include <stdint.h>

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/containers/span.h"
#include "base/files/file_path.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/run_loop.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/test_future.h"
#include "build/build_config.h"
#include "net/base/auth.h"
#include "net/base/connection_endpoint_metadata.h"
#include "net/base/features.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/isolation_info.h"
#include "net/base/net_errors.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_delegate.h"
#include "net/base/request_priority.h"
#include "net/base/url_util.h"
#include "net/cookies/site_for_cookies.h"
#include "net/dns/host_resolver.h"
#include "net/dns/mock_host_resolver.h"
#include "net/dns/public/host_resolver_results.h"
#include "net/http/http_request_headers.h"
#include "net/log/net_log.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/proxy_resolution/proxy_bypass_rules.h"
#include "net/proxy_resolution/proxy_config.h"
#include "net/proxy_resolution/proxy_config_service.h"
#include "net/proxy_resolution/proxy_config_service_fixed.h"
#include "net/proxy_resolution/proxy_config_with_annotation.h"
#include "net/proxy_resolution/proxy_info.h"
#include "net/proxy_resolution/proxy_resolution_service.h"
#include "net/proxy_resolution/proxy_retry_info.h"
#include "net/ssl/ssl_server_config.h"
#include "net/storage_access_api/status.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/embedded_test_server/http_request.h"
#include "net/test/embedded_test_server/http_response.h"
#include "net/test/embedded_test_server/install_default_websocket_handlers.h"
#include "net/test/spawned_test_server/spawned_test_server.h"
#include "net/test/ssl_test_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_test_util.h"
#include "net/websockets/websocket_channel.h"
#include "net/websockets/websocket_event_interface.h"
#include "net/websockets/websocket_handshake_response_info.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "url/gurl.h"
#include "url/origin.h"
#include "url/url_constants.h"

namespace net {
class HttpResponseHeaders;
class ProxyServer;
class SSLInfo;
struct WebSocketHandshakeRequestInfo;

namespace {

using test_server::BasicHttpResponse;
using test_server::HttpRequest;
using test_server::HttpResponse;

static constexpr char kEchoServer[] = "echo-with-no-extension";

// Simplify changing URL schemes.
GURL ReplaceUrlScheme(const GURL& in_url, std::string_view scheme) {
  GURL::Replacements replacements;
  replacements.SetSchemeStr(scheme);
  return in_url.ReplaceComponents(replacements);
}

// An implementation of WebSocketEventInterface that waits for and records the
// results of the connect.
class ConnectTestingEventInterface : public WebSocketEventInterface {
 public:
  ConnectTestingEventInterface();

  ConnectTestingEventInterface(const ConnectTestingEventInterface&) = delete;
  ConnectTestingEventInterface& operator=(const ConnectTestingEventInterface&) =
      delete;

  void WaitForResponse();

  bool failed() const { return failed_; }

  const std::unique_ptr<WebSocketHandshakeResponseInfo>& response() const {
    return response_;
  }

  // Only set if the handshake failed, otherwise empty.
  std::string failure_message() const;

  std::string selected_subprotocol() const;

  std::string extensions() const;

  // Implementation of WebSocketEventInterface.
  void OnCreateURLRequest(URLRequest* request) override {}

  void OnURLRequestConnected(net::URLRequest* request,
                             const net::TransportInfo& info) override {}

  void OnAddChannelResponse(
      std::unique_ptr<WebSocketHandshakeResponseInfo> response,
      const std::string& selected_subprotocol,
      const std::string& extensions) override;

  void OnDataFrame(bool fin,
                   WebSocketMessageType type,
                   base::span<const char> payload) override;

  bool HasPendingDataFrames() override { return false; }

  void OnSendDataFrameDone() override;

  void OnClosingHandshake() override;

  void OnDropChannel(bool was_clean,
                     uint16_t code,
                     const std::string& reason) override;

  void OnFailChannel(const std::string& message,
                     int net_error,
                     std::optional<int> response_code) override;

  void OnStartOpeningHandshake(
      std::unique_ptr<WebSocketHandshakeRequestInfo> request) override;

  void OnSSLCertificateError(
      std::unique_ptr<SSLErrorCallbacks> ssl_error_callbacks,
      const GURL& url,
      int net_error,
      const SSLInfo& ssl_info,
      bool fatal) override;

  int OnAuthRequired(const AuthChallengeInfo& auth_info,
                     scoped_refptr<HttpResponseHeaders> response_headers,
                     const IPEndPoint& remote_endpoint,
                     base::OnceCallback<void(const AuthCredentials*)> callback,
                     std::optional<AuthCredentials>* credentials) override;

  std::string GetDataFramePayload();

  void WaitForDropChannel() { drop_channel_future_.Get(); }

 private:
  void QuitLoop();
  void RunNewLoop();
  void SetReceivedMessageFuture(std::string received_message);

  // failed_ is true if the handshake failed (ie. OnFailChannel was called).
  bool failed_ = false;
  std::unique_ptr<WebSocketHandshakeResponseInfo> response_;
  std::string selected_subprotocol_;
  std::string extensions_;
  std::string failure_message_;
  std::optional<base::RunLoop> run_loop_;

  base::test::TestFuture<std::string> received_message_future_;
  base::test::TestFuture<void> drop_channel_future_;
};

ConnectTestingEventInterface::ConnectTestingEventInterface() = default;

void ConnectTestingEventInterface::WaitForResponse() {
  RunNewLoop();
}

std::string ConnectTestingEventInterface::failure_message() const {
  return failure_message_;
}

std::string ConnectTestingEventInterface::selected_subprotocol() const {
  return selected_subprotocol_;
}

std::string ConnectTestingEventInterface::extensions() const {
  return extensions_;
}

void ConnectTestingEventInterface::OnAddChannelResponse(
    std::unique_ptr<WebSocketHandshakeResponseInfo> response,
    const std::string& selected_subprotocol,
    const std::string& extensions) {
  response_ = std::move(response);
  selected_subprotocol_ = selected_subprotocol;
  extensions_ = extensions;
  QuitLoop();
}

void ConnectTestingEventInterface::OnDataFrame(bool fin,
                                               WebSocketMessageType type,
                                               base::span<const char> payload) {
  DVLOG(3) << "Received WebSocket data frame with message:"
           << std::string(payload.begin(), payload.end());
  SetReceivedMessageFuture(std::string(base::as_string_view(payload)));
}

void ConnectTestingEventInterface::OnSendDataFrameDone() {}

void ConnectTestingEventInterface::OnClosingHandshake() {
  DVLOG(3) << "OnClosingHandeshake() invoked.";
}

void ConnectTestingEventInterface::OnDropChannel(bool was_clean,
                                                 uint16_t code,
                                                 const std::string& reason) {
  DVLOG(3) << "OnDropChannel() invoked, was_clean: " << was_clean
           << ", code: " << code << ", reason: " << reason;
  if (was_clean) {
    drop_channel_future_.SetValue();
  } else {
    DVLOG(1) << "OnDropChannel() did not receive a clean close.";
  }
}

void ConnectTestingEventInterface::OnFailChannel(
    const std::string& message,
    int net_error,
    std::optional<int> response_code) {
  DVLOG(3) << "OnFailChannel invoked with message: " << message;
  failed_ = true;
  failure_message_ = message;
  QuitLoop();
}

void ConnectTestingEventInterface::OnStartOpeningHandshake(
    std::unique_ptr<WebSocketHandshakeRequestInfo> request) {}

void ConnectTestingEventInterface::OnSSLCertificateError(
    std::unique_ptr<SSLErrorCallbacks> ssl_error_callbacks,
    const GURL& url,
    int net_error,
    const SSLInfo& ssl_info,
    bool fatal) {
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&SSLErrorCallbacks::CancelSSLRequest,
                                base::Owned(ssl_error_callbacks.release()),
                                ERR_SSL_PROTOCOL_ERROR, &ssl_info));
}

int ConnectTestingEventInterface::OnAuthRequired(
    const AuthChallengeInfo& auth_info,
    scoped_refptr<HttpResponseHeaders> response_headers,
    const IPEndPoint& remote_endpoint,
    base::OnceCallback<void(const AuthCredentials*)> callback,
    std::optional<AuthCredentials>* credentials) {
  *credentials = std::nullopt;
  return OK;
}

void ConnectTestingEventInterface::QuitLoop() {
  if (!run_loop_) {
    DVLOG(3) << "No active run loop to quit.";
    return;
  }
  run_loop_->Quit();
}

void ConnectTestingEventInterface::RunNewLoop() {
  run_loop_.emplace();
  run_loop_->Run();
}

void ConnectTestingEventInterface::SetReceivedMessageFuture(
    std::string received_message) {
  received_message_future_.SetValue(received_message);
}

std::string ConnectTestingEventInterface::GetDataFramePayload() {
  return received_message_future_.Get();
}

// A subclass of TestNetworkDelegate that additionally implements the
// OnResolveProxy callback and records the information passed to it.
class TestProxyDelegateWithProxyInfo : public ProxyDelegate {
 public:
  TestProxyDelegateWithProxyInfo() = default;

  TestProxyDelegateWithProxyInfo(const TestProxyDelegateWithProxyInfo&) =
      delete;
  TestProxyDelegateWithProxyInfo& operator=(
      const TestProxyDelegateWithProxyInfo&) = delete;

  struct ResolvedProxyInfo {
    GURL url;
    ProxyInfo proxy_info;
  };

  const ResolvedProxyInfo& resolved_proxy_info() const {
    return resolved_proxy_info_;
  }

 protected:
  void OnResolveProxy(const GURL& url,
                      const NetworkAnonymizationKey& network_anonymization_key,
                      const std::string& method,
                      const ProxyRetryInfoMap& proxy_retry_info,
                      ProxyInfo* result) override {
    resolved_proxy_info_.url = url;
    resolved_proxy_info_.proxy_info = *result;
  }

  void OnSuccessfulRequestAfterFailures(
      const ProxyRetryInfoMap& proxy_retry_info) override {}

  void OnFallback(const ProxyChain& bad_chain, int net_error) override {}

  Error OnBeforeTunnelRequest(const ProxyChain& proxy_chain,
                              size_t chain_index,
                              HttpRequestHeaders* extra_headers) override {
    return OK;
  }

  Error OnTunnelHeadersReceived(
      const ProxyChain& proxy_chain,
      size_t chain_index,
      const HttpResponseHeaders& response_headers) override {
    return OK;
  }

  void SetProxyResolutionService(
      ProxyResolutionService* proxy_resolution_service) override {}

 private:
  ResolvedProxyInfo resolved_proxy_info_;
};

class WebSocketEndToEndTest : public TestWithTaskEnvironment {
 protected:
  WebSocketEndToEndTest()
      : proxy_delegate_(std::make_unique<TestProxyDelegateWithProxyInfo>()),
        context_builder_(CreateTestURLRequestContextBuilder()) {}

  // Initialise the URLRequestContext. Normally done automatically by
  // ConnectAndWait(). This method is for the use of tests that need the
  // URLRequestContext initialised before calling ConnectAndWait().
  void InitialiseContext() {
    DCHECK(!context_);
    context_ = context_builder_->Build();
    context_->proxy_resolution_service()->SetProxyDelegate(
        proxy_delegate_.get());
  }

  // Send the connect request to |socket_url| and wait for a response. Returns
  // true if the handshake succeeded.
  bool ConnectAndWait(const GURL& socket_url) {
    if (!context_) {
      InitialiseContext();
    }
    url::Origin origin = url::Origin::Create(GURL("http://localhost"));
    net::SiteForCookies site_for_cookies =
        net::SiteForCookies::FromOrigin(origin);
    IsolationInfo isolation_info =
        IsolationInfo::Create(IsolationInfo::RequestType::kOther, origin,
                              origin, SiteForCookies::FromOrigin(origin));
    auto event_interface = std::make_unique<ConnectTestingEventInterface>();
    event_interface_ = event_interface.get();
    channel_ = std::make_unique<WebSocketChannel>(std::move(event_interface),
                                                  context_.get());
    channel_->SendAddChannelRequest(
        GURL(socket_url), sub_protocols_, origin, site_for_cookies,
        StorageAccessApiStatus::kNone, isolation_info, HttpRequestHeaders(),
        TRAFFIC_ANNOTATION_FOR_TESTS);
    event_interface_->WaitForResponse();
    return !event_interface_->failed();
  }

  [[nodiscard]] WebSocketChannel::ChannelState SendMessage(
      const std::string& message) {
    scoped_refptr<IOBufferWithSize> buffer =
        base::MakeRefCounted<IOBufferWithSize>(message.size());

    buffer->span().copy_from(base::as_byte_span(message));
    return channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeText, buffer,
                               message.size());
  }

  std::string ReceiveMessage() {
    auto channel_state = channel_->ReadFrames();
    if (channel_state != WebSocketChannel::ChannelState::CHANNEL_ALIVE) {
      ADD_FAILURE()
          << "WebSocket channel is no longer alive after reading frames. State:"
          << channel_state;
      return {};
    }
    return event_interface_->GetDataFramePayload();
  }

  void CloseWebSocket() {
    const uint16_t close_code = 1000;
    const std::string close_reason = "Closing connection";

    DVLOG(3) << "Sending close handshake with code: " << close_code
             << " and reason: " << close_reason;

    auto channel_state =
        channel_->StartClosingHandshake(close_code, close_reason);

    EXPECT_EQ(channel_state, WebSocketChannel::ChannelState::CHANNEL_ALIVE)
        << "WebSocket channel is no longer alive after sending the "
           "Close frame. State: "
        << channel_state;
  }

  void CloseWebSocketSuccessfully() {
    CloseWebSocket();
    event_interface_->WaitForDropChannel();
  }

  void RunEmbeddedBasicSmokeTest(net::EmbeddedTestServer::Type server_type) {
    test_server::EmbeddedTestServer embedded_test_server(server_type);

    test_server::InstallDefaultWebSocketHandlers(&embedded_test_server);

    ASSERT_TRUE(embedded_test_server.Start());

    GURL echo_url = test_server::ToWebSocketUrl(
        embedded_test_server.GetURL("/echo-with-no-extension"));
    EXPECT_TRUE(ConnectAndWait(echo_url));
  }

  raw_ptr<ConnectTestingEventInterface, DanglingUntriaged>
      event_interface_;  // owned by channel_
  std::unique_ptr<TestProxyDelegateWithProxyInfo> proxy_delegate_;
  std::unique_ptr<URLRequestContextBuilder> context_builder_;
  std::unique_ptr<URLRequestContext> context_;
  std::unique_ptr<WebSocketChannel> channel_;
  std::vector<std::string> sub_protocols_;
};

// Basic test of connectivity. If this test fails, nothing else can be expected
// to work.
TEST_F(WebSocketEndToEndTest, BasicSmokeTest) {
  SpawnedTestServer ws_server(SpawnedTestServer::TYPE_WS,
                              GetWebSocketTestDataDirectory());
  ASSERT_TRUE(ws_server.Start());
  EXPECT_TRUE(ConnectAndWait(ws_server.GetURL(kEchoServer)));
}

TEST_F(WebSocketEndToEndTest, EmbeddedBasicSmokeTest) {
  RunEmbeddedBasicSmokeTest(net::EmbeddedTestServer::TYPE_HTTP);
}

TEST_F(WebSocketEndToEndTest, EmbeddedBasicSmokeTestSSL) {
  RunEmbeddedBasicSmokeTest(net::EmbeddedTestServer::TYPE_HTTPS);
}

TEST_F(WebSocketEndToEndTest, WebSocketEchoHandlerTest) {
  test_server::EmbeddedTestServer embedded_test_server(
      test_server::EmbeddedTestServer::TYPE_HTTP);

  test_server::InstallDefaultWebSocketHandlers(&embedded_test_server);

  ASSERT_TRUE(embedded_test_server.Start());

  GURL echo_url = test_server::ToWebSocketUrl(
      embedded_test_server.GetURL("/echo-with-no-extension"));
  ASSERT_TRUE(ConnectAndWait(echo_url));

  const std::string test_message = "hello echo";

  auto channel_state = SendMessage(test_message);

  ASSERT_EQ(channel_state, WebSocketChannel::ChannelState::CHANNEL_ALIVE);

  std::string received_message = ReceiveMessage();

  EXPECT_EQ(test_message, received_message);
  CloseWebSocketSuccessfully();
}

// These test are not compatible with RemoteTestServer because RemoteTestServer
// doesn't support TYPE_BASIC_AUTH_PROXY.
// TODO(ricea): Make these tests work. See crbug.com/441711.
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_FUCHSIA)
#define MAYBE_HttpsProxyUnauthedFails DISABLED_HttpsProxyUnauthedFails
#define MAYBE_HttpsWssProxyUnauthedFails DISABLED_HttpsWssProxyUnauthedFails
#define MAYBE_HttpsProxyUsed DISABLED_HttpsProxyUsed
#else
#define MAYBE_HttpsProxyUnauthedFails HttpsProxyUnauthedFails
#define MAYBE_HttpsWssProxyUnauthedFails HttpsWssProxyUnauthedFails
#define MAYBE_HttpsProxyUsed HttpsProxyUsed
#endif

// Test for issue crbug.com/433695 "Unencrypted WebSocket connection via
// authenticated proxy times out".
TEST_F(WebSocketEndToEndTest, MAYBE_HttpsProxyUnauthedFails) {
  SpawnedTestServer proxy_server(SpawnedTestServer::TYPE_BASIC_AUTH_PROXY,
                                 base::FilePath());
  SpawnedTestServer ws_server(SpawnedTestServer::TYPE_WS,
                              GetWebSocketTestDataDirectory());
  ASSERT_TRUE(proxy_server.StartInBackground());
  ASSERT_TRUE(ws_server.StartInBackground());
  ASSERT_TRUE(proxy_server.BlockUntilStarted());
  ASSERT_TRUE(ws_server.BlockUntilStarted());
  ProxyConfig proxy_config;
  proxy_config.proxy_rules().ParseFromString(
      "https=" + proxy_server.host_port_pair().ToString());
  // TODO(crbug.com/40600992): Don't rely on proxying localhost.
  proxy_config.proxy_rules().bypass_rules.AddRulesToSubtractImplicit();

  std::unique_ptr<ProxyResolutionService> proxy_resolution_service(
      ConfiguredProxyResolutionService::CreateFixedForTest(
          ProxyConfigWithAnnotation(proxy_config,
                                    TRAFFIC_ANNOTATION_FOR_TESTS)));
  ASSERT_TRUE(proxy_resolution_service);
  context_builder_->set_proxy_resolution_service(
      std::move(proxy_resolution_service));

  EXPECT_FALSE(ConnectAndWait(ws_server.GetURL(kEchoServer)));
  EXPECT_EQ("Proxy authentication failed", event_interface_->failure_message());
}

TEST_F(WebSocketEndToEndTest, MAYBE_HttpsWssProxyUnauthedFails) {
  SpawnedTestServer proxy_server(SpawnedTestServer::TYPE_BASIC_AUTH_PROXY,
                                 base::FilePath());
  SpawnedTestServer wss_server(SpawnedTestServer::TYPE_WSS,
                               GetWebSocketTestDataDirectory());
  ASSERT_TRUE(proxy_server.StartInBackground());
  ASSERT_TRUE(wss_server.StartInBackground());
  ASSERT_TRUE(proxy_server.BlockUntilStarted());
  ASSERT_TRUE(wss_server.BlockUntilStarted());
  ProxyConfig proxy_config;
  proxy_config.proxy_rules().ParseFromString(
      "https=" + proxy_server.host_port_pair().ToString());
  // TODO(crbug.com/40600992): Don't rely on proxying localhost.
  proxy_config.proxy_rules().bypass_rules.AddRulesToSubtractImplicit();

  std::unique_ptr<ProxyResolutionService> proxy_resolution_service(
      ConfiguredProxyResolutionService::CreateFixedForTest(
          ProxyConfigWithAnnotation(proxy_config,
                                    TRAFFIC_ANNOTATION_FOR_TESTS)));
  ASSERT_TRUE(proxy_resolution_service);
  context_builder_->set_proxy_resolution_service(
      std::move(proxy_resolution_service));
  EXPECT_FALSE(ConnectAndWait(wss_server.GetURL(kEchoServer)));
  EXPECT_EQ("Proxy authentication failed", event_interface_->failure_message());
}

// Regression test for crbug.com/426736 "WebSocket connections not using
// configured system HTTPS Proxy".
TEST_F(WebSocketEndToEndTest, MAYBE_HttpsProxyUsed) {
  SpawnedTestServer proxy_server(SpawnedTestServer::TYPE_PROXY,
                                 base::FilePath());
  SpawnedTestServer ws_server(SpawnedTestServer::TYPE_WS,
                              GetWebSocketTestDataDirectory());
  ASSERT_TRUE(proxy_server.StartInBackground());
  ASSERT_TRUE(ws_server.StartInBackground());
  ASSERT_TRUE(proxy_server.BlockUntilStarted());
  ASSERT_TRUE(ws_server.BlockUntilStarted());
  ProxyConfig proxy_config;
  proxy_config.proxy_rules().ParseFromString(
      "https=" + proxy_server.host_port_pair().ToString() + ";" +
      "http=" + proxy_server.host_port_pair().ToString());
  // TODO(crbug.com/40600992): Don't rely on proxying localhost.
  proxy_config.proxy_rules().bypass_rules.AddRulesToSubtractImplicit();

  std::unique_ptr<ProxyResolutionService> proxy_resolution_service(
      ConfiguredProxyResolutionService::CreateFixedForTest(
          ProxyConfigWithAnnotation(proxy_config,
                                    TRAFFIC_ANNOTATION_FOR_TESTS)));
  context_builder_->set_proxy_resolution_service(
      std::move(proxy_resolution_service));
  InitialiseContext();

  GURL ws_url = ws_server.GetURL(kEchoServer);
  EXPECT_TRUE(ConnectAndWait(ws_url));
  const TestProxyDelegateWithProxyInfo::ResolvedProxyInfo& info =
      proxy_delegate_->resolved_proxy_info();
  EXPECT_EQ(ws_url, info.url);
  EXPECT_EQ(info.proxy_info.ToDebugString(),
            base::StrCat({"PROXY ", proxy_server.host_port_pair().ToString()}));
}

std::unique_ptr<HttpResponse> ProxyPacHandler(const HttpRequest& request) {
  GURL url = request.GetURL();
  EXPECT_EQ(url.path_piece(), "/proxy.pac");
  EXPECT_TRUE(url.has_query());
  std::string proxy;
  EXPECT_TRUE(GetValueForKeyInQuery(url, "proxy", &proxy));
  auto response = std::make_unique<BasicHttpResponse>();
  response->set_content_type("application/x-ns-proxy-autoconfig");
  response->set_content(
      base::StringPrintf("function FindProxyForURL(url, host) {\n"
                         "  return 'PROXY %s';\n"
                         "}\n",
                         proxy.c_str()));
  return response;
}

// This tests the proxy.pac resolver that is built into the system. This is not
// the one that Chrome normally uses. Chrome's normal implementation is defined
// as a mojo service. It is outside //net and we can't use it from here. This
// tests the alternative implementations that are selected when the
// --winhttp-proxy-resolver flag is provided to Chrome. These only exist on OS X
// and Windows.
// TODO(ricea): Remove this test if --winhttp-proxy-resolver flag is removed.
// See crbug.com/644030.

#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_APPLE)
#define MAYBE_ProxyPacUsed ProxyPacUsed
#else
#define MAYBE_ProxyPacUsed DISABLED_ProxyPacUsed
#endif

TEST_F(WebSocketEndToEndTest, MAYBE_ProxyPacUsed) {
  EmbeddedTestServer proxy_pac_server(net::EmbeddedTestServer::Type::TYPE_HTTP);
  SpawnedTestServer proxy_server(SpawnedTestServer::TYPE_PROXY,
                                 base::FilePath());
  SpawnedTestServer ws_server(SpawnedTestServer::TYPE_WS,
                              GetWebSocketTestDataDirectory());
  proxy_pac_server.RegisterRequestHandler(base::BindRepeating(ProxyPacHandler));
  proxy_server.set_redirect_connect_to_localhost(true);

  ASSERT_TRUE(proxy_pac_server.Start());
  ASSERT_TRUE(proxy_server.StartInBackground());
  ASSERT_TRUE(ws_server.StartInBackground());
  ASSERT_TRUE(proxy_server.BlockUntilStarted());
  ASSERT_TRUE(ws_server.BlockUntilStarted());

  ProxyConfig proxy_config =
      ProxyConfig::CreateFromCustomPacURL(proxy_pac_server.GetURL(base::StrCat(
          {"/proxy.pac?proxy=", proxy_server.host_port_pair().ToString()})));
  proxy_config.set_pac_mandatory(true);
  auto proxy_config_service = std::make_unique<ProxyConfigServiceFixed>(
      ProxyConfigWithAnnotation(proxy_config, TRAFFIC_ANNOTATION_FOR_TESTS));
  std::unique_ptr<ProxyResolutionService> proxy_resolution_service(
      ConfiguredProxyResolutionService::CreateUsingSystemProxyResolver(
          std::move(proxy_config_service), NetLog::Get(),
          /*quick_check_enabled=*/true));
  ASSERT_EQ(ws_server.host_port_pair().host(), "127.0.0.1");
  context_builder_->set_proxy_resolution_service(
      std::move(proxy_resolution_service));
  InitialiseContext();

  // Use a name other than localhost, since localhost implicitly bypasses the
  // use of proxy.pac.
  HostPortPair fake_ws_host_port_pair("stealth-localhost",
                                      ws_server.host_port_pair().port());

  GURL ws_url(base::StrCat(
      {"ws://", fake_ws_host_port_pair.ToString(), "/", kEchoServer}));
  EXPECT_TRUE(ConnectAndWait(ws_url));
  const auto& info = proxy_delegate_->resolved_proxy_info();
  EXPECT_EQ(ws_url, info.url);
  EXPECT_EQ(info.proxy_info.ToDebugString(),
            base::StrCat({"PROXY ", proxy_server.host_port_pair().ToString()}));
}

// This is a regression test for crbug.com/408061 Crash in
// net::WebSocketBasicHandshakeStream::Upgrade.
TEST_F(WebSocketEndToEndTest, TruncatedResponse) {
  SpawnedTestServer ws_server(SpawnedTestServer::TYPE_WS,
                              GetWebSocketTestDataDirectory());
  ASSERT_TRUE(ws_server.Start());
  InitialiseContext();

  GURL ws_url = ws_server.GetURL("truncated-headers");
  EXPECT_FALSE(ConnectAndWait(ws_url));
}

// Regression test for crbug.com/455215 "HSTS not applied to WebSocket"
TEST_F(WebSocketEndToEndTest, HstsHttpsToWebSocket) {
  EmbeddedTestServer https_server(net::EmbeddedTestServer::Type::TYPE_HTTPS);
  std::string test_server_hostname = "a.test";
  https_server.SetCertHostnames({test_server_hostname});
  https_server.ServeFilesFromSourceDirectory("net/data/url_request_unittest");

  SpawnedTestServer::SSLOptions ssl_options(
      SpawnedTestServer::SSLOptions::CERT_TEST_NAMES);
  SpawnedTestServer wss_server(SpawnedTestServer::TYPE_WSS, ssl_options,
                               GetWebSocketTestDataDirectory());

  ASSERT_TRUE(https_server.Start());
  ASSERT_TRUE(wss_server.Start());
  InitialiseContext();

  // Set HSTS via https:
  TestDelegate delegate;
  GURL https_page =
      https_server.GetURL(test_server_hostname, "/hsts-headers.html");
  std::unique_ptr<URLRequest> request(context_->CreateRequest(
      https_page, DEFAULT_PRIORITY, &delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  delegate.RunUntilComplete();
  EXPECT_EQ(OK, delegate.request_status());

  // Check HSTS with ws:
  // Change the scheme from wss: to ws: to verify that it is switched back.
  GURL ws_url = ReplaceUrlScheme(
      wss_server.GetURL(test_server_hostname, kEchoServer), "ws");
  EXPECT_TRUE(ConnectAndWait(ws_url));
}

TEST_F(WebSocketEndToEndTest, HstsWebSocketToHttps) {
  EmbeddedTestServer https_server(net::EmbeddedTestServer::Type::TYPE_HTTPS);
  std::string test_server_hostname = "a.test";
  https_server.SetCertHostnames({test_server_hostname});
  https_server.ServeFilesFromSourceDirectory("net/data/url_request_unittest");

  SpawnedTestServer::SSLOptions ssl_options(
      SpawnedTestServer::SSLOptions::CERT_TEST_NAMES);
  SpawnedTestServer wss_server(SpawnedTestServer::TYPE_WSS, ssl_options,
                               GetWebSocketTestDataDirectory());
  ASSERT_TRUE(https_server.Start());
  ASSERT_TRUE(wss_server.Start());
  InitialiseContext();
  // Set HSTS via wss:
  GURL wss_url = wss_server.GetURL(test_server_hostname, "set-hsts");
  EXPECT_TRUE(ConnectAndWait(wss_url));

  // Verify via http:
  TestDelegate delegate;
  GURL http_page = ReplaceUrlScheme(
      https_server.GetURL(test_server_hostname, "/simple.html"), "http");
  std::unique_ptr<URLRequest> request(context_->CreateRequest(
      http_page, DEFAULT_PRIORITY, &delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  delegate.RunUntilComplete();
  EXPECT_EQ(OK, delegate.request_status());
  EXPECT_TRUE(request->url().SchemeIs("https"));
}

TEST_F(WebSocketEndToEndTest, HstsWebSocketToWebSocket) {
  std::string test_server_hostname = "a.test";
  SpawnedTestServer::SSLOptions ssl_options(
      SpawnedTestServer::SSLOptions::CERT_TEST_NAMES);
  SpawnedTestServer wss_server(SpawnedTestServer::TYPE_WSS, ssl_options,
                               GetWebSocketTestDataDirectory());
  ASSERT_TRUE(wss_server.Start());
  InitialiseContext();
  // Set HSTS via wss:
  GURL wss_url = wss_server.GetURL(test_server_hostname, "set-hsts");
  EXPECT_TRUE(ConnectAndWait(wss_url));

  // Verify via ws:
  GURL ws_url = ReplaceUrlScheme(
      wss_server.GetURL(test_server_hostname, kEchoServer), "ws");
  EXPECT_TRUE(ConnectAndWait(ws_url));
}

// Regression test for crbug.com/180504 "WebSocket handshake fails when HTTP
// headers have trailing LWS".
TEST_F(WebSocketEndToEndTest, TrailingWhitespace) {
  SpawnedTestServer ws_server(SpawnedTestServer::TYPE_WS,
                              GetWebSocketTestDataDirectory());
  ASSERT_TRUE(ws_server.Start());

  GURL ws_url = ws_server.GetURL("trailing-whitespace");
  sub_protocols_.push_back("sip");
  EXPECT_TRUE(ConnectAndWait(ws_url));
  EXPECT_EQ("sip", event_interface_->selected_subprotocol());
}

// This is a regression test for crbug.com/169448 "WebSockets should support
// header continuations"
// TODO(ricea): HTTP continuation headers have been deprecated by RFC7230.  If
// support for continuation headers is removed from Chrome, then this test will
// break and should be removed.
TEST_F(WebSocketEndToEndTest, HeaderContinuations) {
  SpawnedTestServer ws_server(SpawnedTestServer::TYPE_WS,
                              GetWebSocketTestDataDirectory());
  ASSERT_TRUE(ws_server.Start());

  GURL ws_url = ws_server.GetURL("header-continuation");

  EXPECT_TRUE(ConnectAndWait(ws_url));
  EXPECT_EQ("permessage-deflate; server_max_window_bits=10",
            event_interface_->extensions());
}

// Test that ws->wss scheme upgrade is supported on receiving a DNS HTTPS
// record.
TEST_F(WebSocketEndToEndTest, DnsSchemeUpgradeSupported) {
  SpawnedTestServer wss_server(SpawnedTestServer::TYPE_WSS,
                               SpawnedTestServer::SSLOptions(base::FilePath(
                                   FILE_PATH_LITERAL("test_names.pem"))),
                               GetWebSocketTestDataDirectory());
  ASSERT_TRUE(wss_server.Start());

  GURL wss_url("wss://a.test:" +
               base::NumberToString(wss_server.host_port_pair().port()) + "/" +
               kEchoServer);
  GURL::Replacements replacements;
  replacements.SetSchemeStr(url::kWsScheme);
  GURL ws_url = wss_url.ReplaceComponents(replacements);

  // Note that due to socket pool behavior, HostResolver will see the ws/wss
  // requests as http/https.
  auto host_resolver = std::make_unique<MockHostResolver>();
  MockHostResolverBase::RuleResolver::RuleKey unencrypted_resolve_key;
  unencrypted_resolve_key.scheme = url::kHttpScheme;
  host_resolver->rules()->AddRule(std::move(unencrypted_resolve_key),
                                  ERR_DNS_NAME_HTTPS_ONLY);
  MockHostResolverBase::RuleResolver::RuleKey encrypted_resolve_key;
  encrypted_resolve_key.scheme = url::kHttpsScheme;
  host_resolver->rules()->AddRule(std::move(encrypted_resolve_key),
                                  "127.0.0.1");
  context_builder_->set_host_resolver(std::move(host_resolver));

  EXPECT_TRUE(ConnectAndWait(ws_url));

  // Expect request to have reached the server using the upgraded URL.
  EXPECT_EQ(event_interface_->response()->url, wss_url);
}

// Test that wss connections can use HostResolverEndpointResults from DNS.
TEST_F(WebSocketEndToEndTest, HostResolverEndpointResult) {
  base::test::ScopedFeatureList features;
  features.In
"""


```