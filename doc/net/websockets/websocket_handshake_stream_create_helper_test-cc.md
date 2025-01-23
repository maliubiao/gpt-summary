Response:
Let's break down the thought process for analyzing this C++ test file and generating the detailed explanation.

1. **Understand the Goal:** The primary request is to analyze the functionality of `websocket_handshake_stream_create_helper_test.cc`, focusing on its purpose, relationship to JavaScript, logic, potential errors, and how users might trigger it.

2. **Initial Scan for Clues:** Quickly read through the code, looking for keywords and patterns:
    * `#include "net/websockets/..."`:  This immediately tells us the file is about WebSocket functionality within Chromium's networking stack.
    * `TEST_P`, `TEST`, `EXPECT_...`: These are standard Google Test macros, indicating this is a test file.
    * `HandshakeStreamType`, `BASIC_HANDSHAKE_STREAM`, `HTTP2_HANDSHAKE_STREAM`, `HTTP3_HANDSHAKE_STREAM`:  This suggests the test covers different ways a WebSocket handshake can be established (basic, over HTTP/2, over HTTP/3).
    * `MockClientSocketHandleFactory`, `MockWebSocketStreamRequestAPI`:  The presence of "Mock" strongly indicates that this file uses mocking to simulate network interactions.
    * `CreateAndInitializeStream`: This function seems to be the core setup for the tests.

3. **Identify the Core Functionality:**  The filename itself, "handshake_stream_create_helper_test," gives a strong hint. The code tests the `WebSocketHandshakeStreamCreateHelper` class. This helper class's job is to *create* the appropriate type of WebSocket handshake stream.

4. **Determine the Scope of Testing:** The `INSTANTIATE_TEST_SUITE_P` macro reveals that the tests are parameterized based on `HandshakeStreamType`. This confirms the testing of different handshake mechanisms.

5. **Analyze `CreateAndInitializeStream`:** This function is crucial. Break down its steps:
    * It takes sub-protocols and extra headers as input.
    * It creates a `WebSocketHandshakeStreamCreateHelper`.
    * It uses a `switch` statement based on the test parameter (`GetParam()`) to select the specific handshake stream creation method (`CreateBasicStream`, `CreateHttp2Stream`, `CreateHttp3Stream`).
    * It sets up mock expectations using `EXPECT_CALL` on a `MockWebSocketStreamRequestAPI` object.
    * It simulates network communication using `MockClientSocketHandleFactory` (for basic) and `SequencedSocketData`/`MockRead`/`MockWrite` (for HTTP/2 and HTTP/3).
    * It initializes and sends a WebSocket handshake request.
    * It reads the response headers and checks for success (HTTP 101 for basic, HTTP 200 for others).
    * Finally, it calls `handshake->Upgrade()` which transitions the handshake stream to a regular `WebSocketStream`.

6. **Connect to JavaScript:**  Consider how WebSockets are used in JavaScript. The `WebSocket` API in browsers is the primary way JavaScript interacts with WebSockets. The concepts of sub-protocols and extensions are directly exposed through this API. The browser's networking stack, which includes this C++ code, handles the underlying handshake process initiated by the JavaScript `WebSocket` object.

7. **Illustrate with JavaScript Examples:** Provide concrete JavaScript code snippets demonstrating how sub-protocols and extensions are used when creating a `WebSocket` object. This clarifies the connection between the C++ testing and the JavaScript API.

8. **Deduce Logic and Assumptions:**
    * **Assumption:** The test assumes successful underlying socket connections for HTTP/2 and HTTP/3.
    * **Logic:** The `switch` statement in `CreateAndInitializeStream` is a core piece of logic for selecting the correct handshake stream creation method. The test verifies that the correct mock methods are called based on the `HandshakeStreamType`.

9. **Identify Potential User/Programming Errors:** Think about common mistakes developers make when working with WebSockets:
    * **Incorrect Sub-protocol:**  Specifying a sub-protocol not supported by the server.
    * **Mismatched Extensions:** Requesting an extension the server doesn't offer or configuring extension parameters incorrectly. This is what the specific tests like `Extensions` and `ExtensionParameters` are verifying.

10. **Trace User Operations (Debugging Clues):**  Think about the steps a user takes to initiate a WebSocket connection:
    * Opening a webpage with JavaScript.
    * The JavaScript code creating a `WebSocket` object.
    * The browser initiating the WebSocket handshake.
    * The C++ code being invoked as part of the browser's networking stack to handle the handshake.

11. **Structure the Explanation:** Organize the findings into logical sections:
    * Purpose of the file.
    * Relationship to JavaScript (with examples).
    * Logical deductions (assumptions, inputs, outputs).
    * Common errors.
    * User operation tracing.

12. **Refine and Elaborate:**  Go back through each section and add more detail. For example, explain the significance of the mock objects, the different handshake types, and the role of the `WebSocketHandshakeStreamCreateHelper`. Explain *why* the HTTP status codes differ (101 for basic upgrade, 200 for successful HTTP/2/3 connection leading to upgrade).

13. **Review for Clarity and Accuracy:** Ensure the explanation is easy to understand and accurately reflects the code's functionality. Check for any inconsistencies or areas that could be misinterpreted. Make sure the examples are clear and relevant.

By following these steps, we can systematically analyze the C++ test file and generate a comprehensive and informative explanation that addresses all aspects of the request.
这个文件 `websocket_handshake_stream_create_helper_test.cc` 是 Chromium 网络栈中的一个测试文件，专门用于测试 `net/websockets/websocket_handshake_stream_create_helper.h` 中定义的 `WebSocketHandshakeStreamCreateHelper` 类的功能。

**它的主要功能是验证 `WebSocketHandshakeStreamCreateHelper` 类能够正确地创建不同类型的 WebSocket 握手流 (handshake stream)。**

具体来说，它测试了以下几种情况：

1. **创建基本的 WebSocket 握手流 (Basic Handshake Stream):** 这是最初的 WebSocket 协议握手方式，直接在 TCP 连接上进行。
2. **创建基于 HTTP/2 的 WebSocket 握手流 (HTTP/2 Handshake Stream):**  WebSocket 连接可以复用已有的 HTTP/2 连接。
3. **创建基于 HTTP/3 的 WebSocket 握手流 (HTTP/3 Handshake Stream):**  WebSocket 连接也可以复用已有的 HTTP/3 (基于 QUIC) 连接。

**与 JavaScript 功能的关系:**

这个 C++ 文件测试的代码，是浏览器底层网络实现的一部分，它直接支持了 JavaScript 中 `WebSocket` API 的功能。当 JavaScript 代码创建一个 `WebSocket` 对象并尝试连接到服务器时，浏览器内部的网络栈会负责建立连接和进行握手。`WebSocketHandshakeStreamCreateHelper` 类在这个过程中起着关键作用，它根据当前的网络协议（例如 HTTP/1.1, HTTP/2, HTTP/3）选择合适的握手流类型。

**举例说明:**

假设你在 JavaScript 中创建了一个 WebSocket 连接：

```javascript
const websocket = new WebSocket('wss://example.com/socket');

websocket.onopen = function(event) {
  console.log("WebSocket connection opened");
};

websocket.onmessage = function(event) {
  console.log("Received message: " + event.data);
};
```

当这段 JavaScript 代码执行时，浏览器会执行以下（简化的）步骤，其中就涉及到 `WebSocketHandshakeStreamCreateHelper` 的工作：

1. **DNS 解析:**  浏览器会解析 `example.com` 的 IP 地址。
2. **建立 TCP 或 QUIC 连接:**  根据协议 (HTTPS 通常使用 TLS over TCP，或 HTTP/3 使用 QUIC)，浏览器会与服务器建立连接。
3. **WebSocket 握手:**  这就是 `WebSocketHandshakeStreamCreateHelper` 发挥作用的地方。
    * 如果是基本的 WebSocket 连接 (通常在 HTTP/1.1 上)，`CreateBasicStream` 方法会被调用。
    * 如果连接是基于 HTTP/2 的，`CreateHttp2Stream` 方法会被调用。
    * 如果连接是基于 HTTP/3 的，`CreateHttp3Stream` 方法会被调用。
4. **发送握手请求:**  创建的握手流会发送一个 HTTP 请求到服务器，请求将连接升级到 WebSocket 协议。
5. **接收握手响应:**  握手流会接收服务器的 HTTP 响应，验证握手是否成功。
6. **建立 WebSocket 连接:**  如果握手成功，底层的 TCP 或 QUIC 连接就被升级为 WebSocket 连接，JavaScript 中的 `onopen` 事件会被触发。

**逻辑推理、假设输入与输出:**

**假设输入 (以 HTTP/2 为例):**

* **输入:**  一个已经建立的、与服务器的 HTTP/2 连接的 SpdySession 对象。
* **输入:**  WebSocket 的目标 URL (`wss://example.com/socket`).
* **输入:**  期望的子协议 (sub-protocols) 列表。
* **输入:**  额外的请求头信息。

**逻辑推理:**

`WebSocketHandshakeStreamCreateHelper` 的 `CreateHttp2Stream` 方法会：

1. 创建一个 `WebSocketHttp2HandshakeStream` 对象。
2. 将传入的 SpdySession 对象与新创建的握手流关联起来。
3. 在后续的握手过程中，使用 SpdySession 发送和接收 HTTP/2 帧。
4. 当握手完成后，`Upgrade()` 方法会返回一个 `WebSocketStream` 对象，用于后续的 WebSocket 数据传输。

**假设输出 (HTTP/2):**

* **成功输出:**  一个指向 `WebSocketHttp2HandshakeStream` 对象的指针 (在握手阶段)。
* **成功输出:**  一个指向 `WebSocketStream` 对象的指针 (在握手成功并升级后)。
* **失败输出:**  如果创建失败，例如 SpdySession 无效，可能会抛出异常或返回错误代码。

**涉及用户或编程常见的使用错误:**

1. **服务器不支持 WebSocket 协议:**  用户尝试连接到一个不支持 WebSocket 的服务器，握手会失败。这会导致 JavaScript 中的 `onerror` 事件被触发。
2. **子协议不匹配:**  客户端请求的子协议与服务器支持的子协议不一致。测试代码中模拟了这种情况，验证了 `WebSocketStream` 能正确获取协商后的子协议。
3. **扩展不兼容:**  客户端请求的 WebSocket 扩展服务器不支持。测试代码中也验证了对扩展头的处理。
4. **网络问题:**  底层的 TCP 或 QUIC 连接无法建立或中断，导致握手失败。这不是 `WebSocketHandshakeStreamCreateHelper` 直接负责的，但会影响整个 WebSocket 连接过程。
5. **代理问题:**  某些代理服务器可能不支持 WebSocket 协议的升级，导致握手失败。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入一个 `wss://` 开头的 URL，或者点击一个包含 WebSocket 连接的链接。**
2. **网页加载，JavaScript 代码开始执行。**
3. **JavaScript 代码创建了一个 `WebSocket` 对象，例如 `new WebSocket('wss://example.com/socket')`。**
4. **浏览器网络栈开始处理这个 WebSocket 连接请求。**
5. **DNS 解析器查找目标服务器的 IP 地址。**
6. **根据协议，浏览器尝试与服务器建立 TCP (TLS) 或 QUIC 连接。**
7. **连接建立后，`WebSocketHandshakeStreamCreateHelper` 类会被调用，根据当前连接的协议类型 (HTTP/1.1, HTTP/2, HTTP/3) 创建相应的握手流对象。**
8. **创建的握手流会构造并发送 WebSocket 握手请求到服务器。**  对于 HTTP/2 和 HTTP/3，这会涉及到发送特定的 HTTP 帧。对于基本的握手，会发送一个 HTTP Upgrade 请求。
9. **浏览器等待服务器的握手响应。**
10. **如果握手成功，`WebSocketHandshakeStream` 会升级到底层的连接，创建一个 `WebSocketStream` 对象，并通知 JavaScript 连接已打开 (`onopen` 事件)。**
11. **如果握手失败，会通知 JavaScript 连接失败 (`onerror` 事件)。**

在调试 WebSocket 连接问题时，如果怀疑握手阶段有问题，可以关注网络请求，查看握手请求和响应的头信息。Chromium 的 `net-internals` 工具 (可以通过在浏览器地址栏输入 `chrome://net-internals/#/events` 打开) 可以提供非常详细的网络事件日志，包括 WebSocket 握手的过程，这对于定位问题非常有帮助。 开发者工具的网络面板通常也能显示 WebSocket 连接的握手信息。

### 提示词
```
这是目录为net/websockets/websocket_handshake_stream_create_helper_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/websockets/websocket_handshake_stream_create_helper.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "base/containers/span.h"
#include "base/functional/callback.h"
#include "base/memory/scoped_refptr.h"
#include "base/notreached.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/default_tick_clock.h"
#include "base/time/time.h"
#include "net/base/auth.h"
#include "net/base/completion_once_callback.h"
#include "net/base/connection_endpoint_metadata.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/network_handle.h"
#include "net/base/privacy_mode.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_server.h"
#include "net/base/request_priority.h"
#include "net/base/session_usage.h"
#include "net/base/test_completion_callback.h"
#include "net/cert/cert_verify_result.h"
#include "net/dns/public/host_resolver_results.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log.h"
#include "net/log/net_log_with_source.h"
#include "net/quic/address_utils.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/quic/mock_crypto_client_stream_factory.h"
#include "net/quic/mock_quic_data.h"
#include "net/quic/quic_chromium_alarm_factory.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "net/quic/quic_chromium_packet_reader.h"
#include "net/quic/quic_chromium_packet_writer.h"
#include "net/quic/quic_context.h"
#include "net/quic/quic_http_utils.h"
#include "net/quic/quic_server_info.h"
#include "net/quic/quic_session_alias_key.h"
#include "net/quic/quic_session_key.h"
#include "net/quic/quic_test_packet_maker.h"
#include "net/quic/test_quic_crypto_client_config_handle.h"
#include "net/quic/test_task_runner.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/client_socket_pool.h"
#include "net/socket/connect_job.h"
#include "net/socket/socket_tag.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/websocket_endpoint_lock_manager.h"
#include "net/spdy/multiplexed_session_creation_initiator.h"
#include "net/spdy/spdy_session_key.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/ssl/ssl_config_service_defaults.h"
#include "net/ssl/ssl_info.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/third_party/quiche/src/quiche/common/platform/api/quiche_flags.h"
#include "net/third_party/quiche/src/quiche/http2/core/spdy_protocol.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/quic_crypto_client_config.h"
#include "net/third_party/quiche/src/quiche/quic/core/qpack/qpack_decoder.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_connection.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_connection_id.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_error_codes.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_packets.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_time.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_socket_address.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/crypto_test_utils.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/mock_clock.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/mock_connection_id_generator.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/mock_random.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/qpack/qpack_test_utils.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_test_utils.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/websockets/websocket_basic_handshake_stream.h"
#include "net/websockets/websocket_event_interface.h"
#include "net/websockets/websocket_stream.h"
#include "net/websockets/websocket_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

namespace net {
class HttpNetworkSession;
class URLRequest;
class WebSocketHttp2HandshakeStream;
class WebSocketHttp3HandshakeStream;
class X509Certificate;
struct WebSocketHandshakeRequestInfo;
struct WebSocketHandshakeResponseInfo;
}  // namespace net

using ::net::test::IsError;
using ::net::test::IsOk;
using ::testing::_;
using ::testing::StrictMock;
using ::testing::TestWithParam;
using ::testing::Values;

namespace net {
namespace {

enum HandshakeStreamType {
  BASIC_HANDSHAKE_STREAM,
  HTTP2_HANDSHAKE_STREAM,
  HTTP3_HANDSHAKE_STREAM
};

// This class encapsulates the details of creating a mock ClientSocketHandle.
class MockClientSocketHandleFactory {
 public:
  MockClientSocketHandleFactory()
      : common_connect_job_params_(
            socket_factory_maker_.factory(),
            /*host_resolver=*/nullptr,
            /*http_auth_cache=*/nullptr,
            /*http_auth_handler_factory=*/nullptr,
            /*spdy_session_pool=*/nullptr,
            /*quic_supported_versions=*/nullptr,
            /*quic_session_pool=*/nullptr,
            /*proxy_delegate=*/nullptr,
            /*http_user_agent_settings=*/nullptr,
            /*ssl_client_context=*/nullptr,
            /*socket_performance_watcher_factory=*/nullptr,
            /*network_quality_estimator=*/nullptr,
            /*net_log=*/nullptr,
            /*websocket_endpoint_lock_manager=*/nullptr,
            /*http_server_properties=*/nullptr,
            /*alpn_protos=*/nullptr,
            /*application_settings=*/nullptr,
            /*ignore_certificate_errors=*/nullptr,
            /*early_data_enabled=*/nullptr),
        pool_(1, 1, &common_connect_job_params_) {}

  MockClientSocketHandleFactory(const MockClientSocketHandleFactory&) = delete;
  MockClientSocketHandleFactory& operator=(
      const MockClientSocketHandleFactory&) = delete;

  // The created socket expects |expect_written| to be written to the socket,
  // and will respond with |return_to_read|. The test will fail if the expected
  // text is not written, or if all the bytes are not read.
  std::unique_ptr<ClientSocketHandle> CreateClientSocketHandle(
      const std::string& expect_written,
      const std::string& return_to_read) {
    socket_factory_maker_.SetExpectations(expect_written, return_to_read);
    auto socket_handle = std::make_unique<ClientSocketHandle>();
    socket_handle->Init(
        ClientSocketPool::GroupId(
            url::SchemeHostPort(url::kHttpScheme, "a", 80),
            PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
            SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false),
        scoped_refptr<ClientSocketPool::SocketParams>(),
        std::nullopt /* proxy_annotation_tag */, MEDIUM, SocketTag(),
        ClientSocketPool::RespectLimits::ENABLED, CompletionOnceCallback(),
        ClientSocketPool::ProxyAuthCallback(), &pool_, NetLogWithSource());
    return socket_handle;
  }

 private:
  WebSocketMockClientSocketFactoryMaker socket_factory_maker_;
  const CommonConnectJobParams common_connect_job_params_;
  MockTransportClientSocketPool pool_;
};

class TestConnectDelegate : public WebSocketStream::ConnectDelegate {
 public:
  ~TestConnectDelegate() override = default;

  void OnCreateRequest(URLRequest* request) override {}
  void OnURLRequestConnected(URLRequest* request,
                             const TransportInfo& info) override {}
  void OnSuccess(
      std::unique_ptr<WebSocketStream> stream,
      std::unique_ptr<WebSocketHandshakeResponseInfo> response) override {}
  void OnFailure(const std::string& failure_message,
                 int net_error,
                 std::optional<int> response_code) override {}
  void OnStartOpeningHandshake(
      std::unique_ptr<WebSocketHandshakeRequestInfo> request) override {}
  void OnSSLCertificateError(
      std::unique_ptr<WebSocketEventInterface::SSLErrorCallbacks>
          ssl_error_callbacks,
      int net_error,
      const SSLInfo& ssl_info,
      bool fatal) override {}
  int OnAuthRequired(const AuthChallengeInfo& auth_info,
                     scoped_refptr<HttpResponseHeaders> response_headers,
                     const IPEndPoint& host_port_pair,
                     base::OnceCallback<void(const AuthCredentials*)> callback,
                     std::optional<AuthCredentials>* credentials) override {
    *credentials = std::nullopt;
    return OK;
  }
};

class MockWebSocketStreamRequestAPI : public WebSocketStreamRequestAPI {
 public:
  ~MockWebSocketStreamRequestAPI() override = default;

  MOCK_METHOD1(OnBasicHandshakeStreamCreated,
               void(WebSocketBasicHandshakeStream* handshake_stream));
  MOCK_METHOD1(OnHttp2HandshakeStreamCreated,
               void(WebSocketHttp2HandshakeStream* handshake_stream));
  MOCK_METHOD1(OnHttp3HandshakeStreamCreated,
               void(WebSocketHttp3HandshakeStream* handshake_stream));
  MOCK_METHOD3(OnFailure,
               void(const std::string& message,
                    int net_error,
                    std::optional<int> response_code));
};

class WebSocketHandshakeStreamCreateHelperTest
    : public TestWithParam<HandshakeStreamType>,
      public WithTaskEnvironment {
 protected:
  WebSocketHandshakeStreamCreateHelperTest()
      : quic_version_(quic::HandshakeProtocol::PROTOCOL_TLS1_3,
                      quic::QuicTransportVersion::QUIC_VERSION_IETF_RFC_V1),
        mock_quic_data_(quic_version_) {}
  std::unique_ptr<WebSocketStream> CreateAndInitializeStream(
      const std::vector<std::string>& sub_protocols,
      const WebSocketExtraHeaders& extra_request_headers,
      const WebSocketExtraHeaders& extra_response_headers) {
    constexpr char kPath[] = "/";
    constexpr char kOrigin[] = "http://origin.example.org";
    const GURL url("wss://www.example.org/");
    NetLogWithSource net_log;

    WebSocketHandshakeStreamCreateHelper create_helper(
        &connect_delegate_, sub_protocols, &stream_request_);

    switch (GetParam()) {
      case BASIC_HANDSHAKE_STREAM:
        EXPECT_CALL(stream_request_, OnBasicHandshakeStreamCreated(_)).Times(1);
        break;

      case HTTP2_HANDSHAKE_STREAM:
        EXPECT_CALL(stream_request_, OnHttp2HandshakeStreamCreated(_)).Times(1);
        break;

      case HTTP3_HANDSHAKE_STREAM:
        EXPECT_CALL(stream_request_, OnHttp3HandshakeStreamCreated(_)).Times(1);
        break;

      default:
        NOTREACHED();
    }

    EXPECT_CALL(stream_request_, OnFailure(_, _, _)).Times(0);

    HttpRequestInfo request_info;
    request_info.url = url;
    request_info.method = "GET";
    request_info.load_flags = LOAD_DISABLE_CACHE;
    request_info.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

    auto headers = WebSocketCommonTestHeaders();

    switch (GetParam()) {
      case BASIC_HANDSHAKE_STREAM: {
        std::unique_ptr<ClientSocketHandle> socket_handle =
            socket_handle_factory_.CreateClientSocketHandle(
                WebSocketStandardRequest(kPath, "www.example.org",
                                         url::Origin::Create(GURL(kOrigin)),
                                         /*send_additional_request_headers=*/{},
                                         extra_request_headers),
                WebSocketStandardResponse(
                    WebSocketExtraHeadersToString(extra_response_headers)));

        std::unique_ptr<WebSocketHandshakeStreamBase> handshake =
            create_helper.CreateBasicStream(std::move(socket_handle), false,
                                            &websocket_endpoint_lock_manager_);

        // If in future the implementation type returned by CreateBasicStream()
        // changes, this static_cast will be wrong. However, in that case the
        // test will fail and AddressSanitizer should identify the issue.
        static_cast<WebSocketBasicHandshakeStream*>(handshake.get())
            ->SetWebSocketKeyForTesting("dGhlIHNhbXBsZSBub25jZQ==");

        handshake->RegisterRequest(&request_info);
        int rv = handshake->InitializeStream(true, DEFAULT_PRIORITY, net_log,
                                             CompletionOnceCallback());
        EXPECT_THAT(rv, IsOk());

        HttpResponseInfo response;
        TestCompletionCallback request_callback;
        rv = handshake->SendRequest(headers, &response,
                                    request_callback.callback());
        EXPECT_THAT(rv, IsOk());

        TestCompletionCallback response_callback;
        rv = handshake->ReadResponseHeaders(response_callback.callback());
        EXPECT_THAT(rv, IsOk());
        EXPECT_EQ(101, response.headers->response_code());
        EXPECT_TRUE(response.headers->HasHeaderValue("Connection", "Upgrade"));
        EXPECT_TRUE(response.headers->HasHeaderValue("Upgrade", "websocket"));
        return handshake->Upgrade();
      }
      case HTTP2_HANDSHAKE_STREAM: {
        SpdyTestUtil spdy_util;
        quiche::HttpHeaderBlock request_header_block = WebSocketHttp2Request(
            kPath, "www.example.org", kOrigin, extra_request_headers);
        spdy::SpdySerializedFrame request_headers(
            spdy_util.ConstructSpdyHeaders(1, std::move(request_header_block),
                                           DEFAULT_PRIORITY, false));
        MockWrite writes[] = {CreateMockWrite(request_headers, 0)};

        quiche::HttpHeaderBlock response_header_block =
            WebSocketHttp2Response(extra_response_headers);
        spdy::SpdySerializedFrame response_headers(
            spdy_util.ConstructSpdyResponseHeaders(
                1, std::move(response_header_block), false));
        MockRead reads[] = {CreateMockRead(response_headers, 1),
                            MockRead(ASYNC, 0, 2)};

        SequencedSocketData data(reads, writes);

        SSLSocketDataProvider ssl(ASYNC, OK);
        ssl.ssl_info.cert =
            ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");

        SpdySessionDependencies session_deps;
        session_deps.socket_factory->AddSocketDataProvider(&data);
        session_deps.socket_factory->AddSSLSocketDataProvider(&ssl);

        std::unique_ptr<HttpNetworkSession> http_network_session =
            SpdySessionDependencies::SpdyCreateSession(&session_deps);
        const SpdySessionKey key(
            HostPortPair::FromURL(url), PRIVACY_MODE_DISABLED,
            ProxyChain::Direct(), SessionUsage::kDestination, SocketTag(),
            NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
            /*disable_cert_verification_network_fetches=*/false);
        base::WeakPtr<SpdySession> spdy_session =
            CreateSpdySession(http_network_session.get(), key, net_log);
        std::unique_ptr<WebSocketHandshakeStreamBase> handshake =
            create_helper.CreateHttp2Stream(spdy_session, {} /* dns_aliases */);

        handshake->RegisterRequest(&request_info);
        int rv = handshake->InitializeStream(true, DEFAULT_PRIORITY,
                                             NetLogWithSource(),
                                             CompletionOnceCallback());
        EXPECT_THAT(rv, IsOk());

        HttpResponseInfo response;
        TestCompletionCallback request_callback;
        rv = handshake->SendRequest(headers, &response,
                                    request_callback.callback());
        EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
        rv = request_callback.WaitForResult();
        EXPECT_THAT(rv, IsOk());

        TestCompletionCallback response_callback;
        rv = handshake->ReadResponseHeaders(response_callback.callback());
        EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
        rv = response_callback.WaitForResult();
        EXPECT_THAT(rv, IsOk());

        EXPECT_EQ(200, response.headers->response_code());
        return handshake->Upgrade();
      }
      case HTTP3_HANDSHAKE_STREAM: {
        const quic::QuicStreamId client_data_stream_id(
            quic::QuicUtils::GetFirstBidirectionalStreamId(
                quic_version_.transport_version, quic::Perspective::IS_CLIENT));
        quic::QuicCryptoClientConfig crypto_config(
            quic::test::crypto_test_utils::ProofVerifierForTesting());

        const quic::QuicConnectionId connection_id(
            quic::test::TestConnectionId(2));
        test::QuicTestPacketMaker client_maker(
            quic_version_, connection_id, &clock_, "mail.example.org",
            quic::Perspective::IS_CLIENT,
            /*client_headers_include_h2_stream_dependency_=*/false);
        test::QuicTestPacketMaker server_maker(
            quic_version_, connection_id, &clock_, "mail.example.org",
            quic::Perspective::IS_SERVER,
            /*client_headers_include_h2_stream_dependency_=*/false);
        IPEndPoint peer_addr(IPAddress(192, 0, 2, 23), 443);
        quic::test::MockConnectionIdGenerator connection_id_generator;

        testing::StrictMock<quic::test::MockQuicConnectionVisitor> visitor;
        ProofVerifyDetailsChromium verify_details;
        MockCryptoClientStreamFactory crypto_client_stream_factory;
        TransportSecurityState transport_security_state;
        SSLConfigServiceDefaults ssl_config_service;

        FLAGS_quic_enable_http3_grease_randomness = false;
        clock_.AdvanceTime(quic::QuicTime::Delta::FromMilliseconds(20));
        quic::QuicEnableVersion(quic_version_);
        quic::test::MockRandom random_generator{0};

        quiche::HttpHeaderBlock request_header_block = WebSocketHttp2Request(
            kPath, "www.example.org", kOrigin, extra_request_headers);

        int packet_number = 1;
        mock_quic_data_.AddWrite(
            SYNCHRONOUS,
            client_maker.MakeInitialSettingsPacket(packet_number++));

        mock_quic_data_.AddWrite(
            ASYNC,
            client_maker.MakeRequestHeadersPacket(
                packet_number++, client_data_stream_id,
                /*fin=*/false, ConvertRequestPriorityToQuicPriority(LOWEST),
                std::move(request_header_block), nullptr));

        quiche::HttpHeaderBlock response_header_block =
            WebSocketHttp2Response(extra_response_headers);

        mock_quic_data_.AddRead(
            ASYNC, server_maker.MakeResponseHeadersPacket(
                       /*packet_number=*/1, client_data_stream_id,
                       /*fin=*/false, std::move(response_header_block),
                       /*spdy_headers_frame_length=*/nullptr));

        mock_quic_data_.AddRead(SYNCHRONOUS, ERR_IO_PENDING);

        mock_quic_data_.AddWrite(
            SYNCHRONOUS,
            client_maker.Packet(packet_number++)
                .AddAckFrame(/*first_received=*/1, /*largest_received=*/1,
                             /*smallest_received=*/0)
                .AddStopSendingFrame(client_data_stream_id,
                                     quic::QUIC_STREAM_CANCELLED)
                .AddRstStreamFrame(client_data_stream_id,
                                   quic::QUIC_STREAM_CANCELLED)
                .Build());
        auto socket = std::make_unique<MockUDPClientSocket>(
            mock_quic_data_.InitializeAndGetSequencedSocketData(),
            NetLog::Get());
        socket->Connect(peer_addr);

        scoped_refptr<test::TestTaskRunner> runner =
            base::MakeRefCounted<test::TestTaskRunner>(&clock_);
        auto helper = std::make_unique<QuicChromiumConnectionHelper>(
            &clock_, &random_generator);
        auto alarm_factory =
            std::make_unique<QuicChromiumAlarmFactory>(runner.get(), &clock_);
        // Ownership of 'writer' is passed to 'QuicConnection'.
        QuicChromiumPacketWriter* writer = new QuicChromiumPacketWriter(
            socket.get(),
            base::SingleThreadTaskRunner::GetCurrentDefault().get());
        quic::QuicConnection* connection = new quic::QuicConnection(
            connection_id, quic::QuicSocketAddress(),
            net::ToQuicSocketAddress(peer_addr), helper.get(),
            alarm_factory.get(), writer, true /* owns_writer */,
            quic::Perspective::IS_CLIENT,
            quic::test::SupportedVersions(quic_version_),
            connection_id_generator);
        connection->set_visitor(&visitor);

        // Load a certificate that is valid for *.example.org
        scoped_refptr<X509Certificate> test_cert(
            ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
        EXPECT_TRUE(test_cert.get());

        verify_details.cert_verify_result.verified_cert = test_cert;
        verify_details.cert_verify_result.is_issued_by_known_root = true;
        crypto_client_stream_factory.AddProofVerifyDetails(&verify_details);

        base::TimeTicks dns_end = base::TimeTicks::Now();
        base::TimeTicks dns_start = dns_end - base::Milliseconds(1);

        session_ = std::make_unique<QuicChromiumClientSession>(
            connection, std::move(socket),
            /*stream_factory=*/nullptr, &crypto_client_stream_factory, &clock_,
            &transport_security_state, &ssl_config_service,
            /*server_info=*/nullptr,
            QuicSessionAliasKey(
                url::SchemeHostPort(),
                QuicSessionKey("mail.example.org", 80, PRIVACY_MODE_DISABLED,
                               ProxyChain::Direct(), SessionUsage::kDestination,
                               SocketTag(), NetworkAnonymizationKey(),
                               SecureDnsPolicy::kAllow,
                               /*require_dns_https_alpn=*/false)),
            /*require_confirmation=*/false,
            /*migrate_session_early_v2=*/false,
            /*migrate_session_on_network_change_v2=*/false,
            /*default_network=*/handles::kInvalidNetworkHandle,
            quic::QuicTime::Delta::FromMilliseconds(
                kDefaultRetransmittableOnWireTimeout.InMilliseconds()),
            /*migrate_idle_session=*/true, /*allow_port_migration=*/false,
            kDefaultIdleSessionMigrationPeriod,
            /*multi_port_probing_interval=*/0, kMaxTimeOnNonDefaultNetwork,
            kMaxMigrationsToNonDefaultNetworkOnWriteError,
            kMaxMigrationsToNonDefaultNetworkOnPathDegrading,
            kQuicYieldAfterPacketsRead,
            quic::QuicTime::Delta::FromMilliseconds(
                kQuicYieldAfterDurationMilliseconds),
            /*cert_verify_flags=*/0, quic::test::DefaultQuicConfig(),
            std::make_unique<TestQuicCryptoClientConfigHandle>(&crypto_config),
            "CONNECTION_UNKNOWN", dns_start, dns_end,
            base::DefaultTickClock::GetInstance(),
            base::SingleThreadTaskRunner::GetCurrentDefault().get(),
            /*socket_performance_watcher=*/nullptr,
            ConnectionEndpointMetadata(), /*report_ecn=*/true,
            /*enable_origin_frame=*/true,
            /*allow_server_preferred_address=*/true,
            MultiplexedSessionCreationInitiator::kUnknown,
            NetLogWithSource::Make(NetLogSourceType::NONE));

        session_->Initialize();

        // Blackhole QPACK decoder stream instead of constructing mock writes.
        session_->qpack_decoder()->set_qpack_stream_sender_delegate(
            &noop_qpack_stream_sender_delegate_);
        TestCompletionCallback callback;
        EXPECT_THAT(session_->CryptoConnect(callback.callback()), IsOk());
        EXPECT_TRUE(session_->OneRttKeysAvailable());
        std::unique_ptr<QuicChromiumClientSession::Handle> session_handle =
            session_->CreateHandle(
                url::SchemeHostPort(url::kHttpsScheme, "mail.example.org", 80));

        std::unique_ptr<WebSocketHandshakeStreamBase> handshake =
            create_helper.CreateHttp3Stream(std::move(session_handle),
                                            {} /* dns_aliases */);

        handshake->RegisterRequest(&request_info);
        int rv = handshake->InitializeStream(true, DEFAULT_PRIORITY, net_log,
                                             CompletionOnceCallback());
        EXPECT_THAT(rv, IsOk());

        HttpResponseInfo response;
        TestCompletionCallback request_callback;
        rv = handshake->SendRequest(headers, &response,
                                    request_callback.callback());
        EXPECT_THAT(rv, IsOk());

        session_->StartReading();

        TestCompletionCallback response_callback;
        rv = handshake->ReadResponseHeaders(response_callback.callback());
        EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
        rv = response_callback.WaitForResult();
        EXPECT_THAT(rv, IsOk());

        EXPECT_EQ(200, response.headers->response_code());

        return handshake->Upgrade();
      }
      default:
        NOTREACHED();
    }
  }

 private:
  MockClientSocketHandleFactory socket_handle_factory_;
  TestConnectDelegate connect_delegate_;
  StrictMock<MockWebSocketStreamRequestAPI> stream_request_;
  WebSocketEndpointLockManager websocket_endpoint_lock_manager_;

  // For HTTP3_HANDSHAKE_STREAM
  quic::ParsedQuicVersion quic_version_;
  quic::MockClock clock_;
  std::unique_ptr<QuicChromiumClientSession> session_;
  test::MockQuicData mock_quic_data_;
  quic::test::NoopQpackStreamSenderDelegate noop_qpack_stream_sender_delegate_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         WebSocketHandshakeStreamCreateHelperTest,
                         Values(BASIC_HANDSHAKE_STREAM,
                                HTTP2_HANDSHAKE_STREAM,
                                HTTP3_HANDSHAKE_STREAM));

// Confirm that the basic case works as expected.
TEST_P(WebSocketHandshakeStreamCreateHelperTest, BasicStream) {
  std::unique_ptr<WebSocketStream> stream =
      CreateAndInitializeStream({}, {}, {});
  EXPECT_EQ("", stream->GetExtensions());
  EXPECT_EQ("", stream->GetSubProtocol());
}

// Verify that the sub-protocols are passed through.
TEST_P(WebSocketHandshakeStreamCreateHelperTest, SubProtocols) {
  std::vector<std::string> sub_protocols;
  sub_protocols.push_back("chat");
  sub_protocols.push_back("superchat");
  std::unique_ptr<WebSocketStream> stream = CreateAndInitializeStream(
      sub_protocols, {{"Sec-WebSocket-Protocol", "chat, superchat"}},
      {{"Sec-WebSocket-Protocol", "superchat"}});
  EXPECT_EQ("superchat", stream->GetSubProtocol());
}

// Verify that extension name is available. Bad extension names are tested in
// websocket_stream_test.cc.
TEST_P(WebSocketHandshakeStreamCreateHelperTest, Extensions) {
  std::unique_ptr<WebSocketStream> stream = CreateAndInitializeStream(
      {}, {}, {{"Sec-WebSocket-Extensions", "permessage-deflate"}});
  EXPECT_EQ("permessage-deflate", stream->GetExtensions());
}

// Verify that extension parameters are available. Bad parameters are tested in
// websocket_stream_test.cc.
TEST_P(WebSocketHandshakeStreamCreateHelperTest, ExtensionParameters) {
  std::unique_ptr<WebSocketStream> stream = CreateAndInitializeStream(
      {}, {},
      {{"Sec-WebSocket-Extensions",
        "permessage-deflate;"
        " client_max_window_bits=14; server_max_window_bits=14;"
        " server_no_context_takeover; client_no_context_takeover"}});

  EXPECT_EQ(
      "permessage-deflate;"
      " client_max_window_bits=14; server_max_window_bits=14;"
      " server_no_context_takeover; client_no_context_takeover",
      stream->GetExtensions());
}

}  // namespace

}  // namespace net
```