Response:
My thought process to arrive at the summary of `websocket_basic_stream_adapters_test.cc` goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of the provided C++ test file. Key aspects to consider are its purpose, what it tests, and any connections to JavaScript (though the initial skimming suggests it's purely within the Chromium network stack).

2. **Identify the Core Class Under Test:** The filename `websocket_basic_stream_adapters_test.cc` strongly suggests that the code tests classes related to "websocket basic stream adapters."  The included headers confirm this, particularly `net/websockets/websocket_basic_stream_adapters.h`.

3. **Examine Included Headers:**  The headers provide valuable context:
    * `net/websockets/...`:  Confirms the focus on WebSockets.
    * `net/socket/...`: Indicates interaction with sockets, a fundamental network primitive.
    * `net/quic/...`:  Suggests testing scenarios involving the QUIC protocol (which is often used with WebSockets).
    * `net/spdy/...`: Similarly points to testing with the SPDY protocol (the predecessor to HTTP/2, also relevant to WebSockets).
    * `net/http/...`:  Highlights the HTTP layer involved in the WebSocket handshake and potentially initial connection setup.
    * `testing/gtest/...`:  Confirms this is a unit test file using Google Test.

4. **Scan the Test Class Names:** The provided code snippet includes two test classes:
    * `WebSocketClientSocketHandleAdapterTest`: This clearly tests the `WebSocketClientSocketHandleAdapter` class.
    * `WebSocketSpdyStreamAdapterTest`:  This targets the `WebSocketSpdyStreamAdapter` class.

5. **Analyze Individual Test Cases (High-Level):**  Within each test class, the `TEST_F` macros define individual test cases. Skimming these reveals the kinds of scenarios being tested:
    * **`WebSocketClientSocketHandleAdapterTest`:**  Focuses on the lifecycle and basic I/O operations (initialization, disconnection, reading, writing) of the socket handle adapter. The names are quite descriptive (e.g., `Uninitialized`, `IsInitialized`, `Disconnect`, `Read`, `Write`, `AsyncReadAndWrite`).
    * **`WebSocketSpdyStreamAdapterTest`:** Deals with the interaction of the adapter with SPDY streams. The test names here involve more complex scenarios, including:  handling disconnections at various stages (before/after sending headers, after receiving headers), server-initiated closes, and data transfer. The presence of `MockDelegate` suggests testing the adapter's interaction with its delegate interface.

6. **Identify Key Functionality Being Tested:** Based on the test cases, I can summarize the core functionalities being verified:
    * **`WebSocketClientSocketHandleAdapter`:**  Encapsulates a `ClientSocketHandle` and provides a simpler stream-like interface. The tests ensure it correctly manages the underlying socket's lifecycle and performs read/write operations.
    * **`WebSocketSpdyStreamAdapter`:** Wraps a SPDY stream and adapts it for WebSocket usage. The tests verify its behavior when sending/receiving headers, handling disconnections (both client and server-initiated), and transferring data. The delegate interaction is crucial for handling events like header sending/receiving and stream closure.

7. **Look for JavaScript Connections:** Carefully review the headers and test logic. While WebSockets *interact* with JavaScript in a browser context, this specific test file operates within the Chromium network stack's C++ codebase. There's no direct JavaScript code or testing within this file. The connection is conceptual – this code enables the underlying network communication for JavaScript WebSocket APIs.

8. **Consider Logical Reasoning, Assumptions, and Errors:**  The tests use mock objects and simulated network conditions. The assumptions are that the underlying socket and SPDY stream implementations behave as expected by the mock data. Common usage errors in this context would be incorrect handling of asynchronous operations (not waiting for callbacks), trying to read/write on a closed stream, or misinterpreting network error codes. However, these are tested *internally* by these unit tests, not demonstrated by user actions within *this* code.

9. **Debugging Perspective:**  The test file acts as a valuable debugging tool. If a WebSocket connection using SPDY has issues (e.g., dropped connections, incorrect data transfer), these tests provide a starting point to isolate the problem within the network stack. You'd examine the test setup, the mock data, and the expected behavior to pinpoint discrepancies.

10. **Structure the Summary:** Organize the findings into clear points addressing the prompt's requirements:
    * Main function of the test file.
    * Relationship to JavaScript (indirect).
    * Examples of logical reasoning (using mock data).
    * Common usage errors (from a developer perspective).
    * Debugging perspective.
    * Overall summarization of the first part.

By following this thought process, I can systematically analyze the code snippet and arrive at a comprehensive and accurate summary like the example provided in the prompt. The key is to understand the purpose of unit tests, the specific components being tested, and the scenarios covered by the test cases.
这是 Chromium 网络栈中 `net/websockets/websocket_basic_stream_adapters_test.cc` 文件的第一部分，其主要功能是**测试 WebSocket 的基础流适配器 (`WebSocketClientSocketHandleAdapter` 和 `WebSocketSpdyStreamAdapter`) 的功能**。

**功能归纳:**

该文件包含两个主要的测试套件，分别针对两种不同的 WebSocket 流适配器：

1. **`WebSocketClientSocketHandleAdapterTest`**:
   - **功能:** 测试 `WebSocketClientSocketHandleAdapter` 类的功能。这个适配器可能用于处理基于普通 TCP 或 TLS 连接的 WebSocket 连接。它封装了一个 `ClientSocketHandle`，并提供了更符合 WebSocket 流操作的接口。
   - **测试点:**
     - **初始化状态:** 验证适配器的初始化状态（是否已关联 `ClientSocketHandle`）。
     - **连接状态:** 测试适配器是否正确反映底层 `ClientSocketHandle` 的连接状态。
     - **断开连接:** 验证适配器是否能正确断开底层连接。
     - **读取操作:** 测试适配器的 `Read` 方法，包括同步和异步读取，以及读取到较小缓冲区的情况。
     - **写入操作:** 测试适配器的 `Write` 方法，包括同步和异步写入。
     - **异步读写并发:** 验证适配器是否能正确处理同时发生的异步读取和写入操作。

2. **`WebSocketSpdyStreamAdapterTest`**:
   - **功能:** 测试 `WebSocketSpdyStreamAdapter` 类的功能。这个适配器用于处理基于 SPDY 或 HTTP/2 连接的 WebSocket 连接。它封装了一个 `SpdyStream`，并将其适配为 WebSocket 流。
   - **测试点:**
     - **断开连接:** 测试在不同阶段断开连接的行为，例如在发送请求头之前、之后，或在接收到响应头之后。
     - **发送请求头:** 验证适配器是否能正确发送 WebSocket 请求头。
     - **接收响应头:** 测试适配器是否能正确接收 WebSocket 响应头，并通知代理 (`MockDelegate`)。
     - **服务器关闭连接:** 验证适配器是否能正确处理服务器主动关闭连接的情况。
     - **读取数据:** 测试适配器的 `Read` 方法，包括读取不同大小的数据块，以及处理服务器半关闭连接的情况。
     - **代理的解绑:** 测试在适配器生命周期中解绑代理 (`Delegate`) 的行为。
     - **`OnClose` 回调:** 确保在适当的时机调用代理的 `OnClose` 方法，即使在数据读取过程中连接被关闭。

**与 JavaScript 的关系及举例:**

该测试文件本身是用 C++ 编写的，不包含 JavaScript 代码。但是，它测试的 `WebSocketClientSocketHandleAdapter` 和 `WebSocketSpdyStreamAdapter` 类是 Chromium 网络栈实现 WebSocket 功能的关键组件。当 JavaScript 代码中使用 `WebSocket` API 时，Chromium 浏览器底层会使用这些适配器来建立和管理网络连接，并进行数据的收发。

**举例说明:**

假设以下 JavaScript 代码用于创建一个 WebSocket 连接：

```javascript
const websocket = new WebSocket('wss://www.example.org/');

websocket.onopen = () => {
  console.log('WebSocket connection opened');
  websocket.send('Hello from JavaScript!');
};

websocket.onmessage = (event) => {
  console.log('Message received:', event.data);
};

websocket.onclose = () => {
  console.log('WebSocket connection closed');
};
```

当这段 JavaScript 代码运行时，Chromium 浏览器的网络栈会执行以下操作：

1. **连接建立:** 根据 URL (`wss://www.example.org/`)，网络栈会尝试建立到服务器的连接。如果使用 SPDY 或 HTTP/2，则会使用 `WebSocketSpdyStreamAdapter` 来管理这个连接。如果使用普通的 TLS 连接，则可能使用 `WebSocketClientSocketHandleAdapter`。
2. **发送数据:** 当 JavaScript 调用 `websocket.send('Hello from JavaScript!')` 时，数据会通过相应的适配器（例如 `WebSocketSpdyStreamAdapter` 的写入方法）发送到服务器。
3. **接收数据:** 当服务器发送数据回来时，适配器（例如 `WebSocketSpdyStreamAdapter` 的读取方法）会接收数据，并将其传递给上层的 WebSocket API，最终触发 JavaScript 的 `onmessage` 事件。
4. **连接关闭:** 当连接关闭时（无论是客户端还是服务器发起），相应的适配器的断开连接逻辑会被调用，并触发 JavaScript 的 `onclose` 事件。

**逻辑推理、假设输入与输出:**

**示例 1: `WebSocketClientSocketHandleAdapterTest::Read`**

* **假设输入:** 底层 socket 接收到字符串 "foo" 和 "bar"。
* **操作:** 测试代码首先创建一个 `WebSocketClientSocketHandleAdapter` 并进行初始化。然后，它调用适配器的 `Read` 方法读取数据到大小为 1024 的缓冲区。接着再次调用 `Read` 方法，使用异步回调。
* **预期输出:** 第一次同步读取返回 3，缓冲区包含 "foo"。第二次异步读取完成时，返回 3，缓冲区包含 "bar"。

**示例 2: `WebSocketSpdyStreamAdapterTest::Disconnect`**

* **假设输入:**  一个已经建立的 SPDY 会话和一个关联的 SPDY 流。
* **操作:** 测试代码创建一个 `WebSocketSpdyStreamAdapter` 并关联该 SPDY 流。然后调用适配器的 `Disconnect` 方法。
* **预期输出:** 底层的 SPDY 流会被重置或关闭，后续尝试在该流上进行操作会失败。

**用户或编程常见的使用错误及举例:**

* **未初始化适配器:**  在没有关联有效的 `ClientSocketHandle` 或 `SpdyStream` 的情况下就尝试使用适配器进行读写操作。测试用例 `WebSocketClientSocketHandleAdapterTest::Uninitialized` 就是为了防止这种情况。
* **在连接断开后进行操作:** 尝试在 WebSocket 连接已经关闭后，通过适配器发送或接收数据。这会导致错误，例如在 `WebSocketSpdyStreamAdapterTest::Disconnect` 中，测试代码验证了断开连接后流不再可用。
* **不正确处理异步操作:**  在异步读取或写入操作未完成时就尝试使用缓冲区中的数据，或者过早地释放缓冲区。测试用例 `WebSocketClientSocketHandleAdapterTest::AsyncReadAndWrite` 验证了异步操作的正确处理。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中访问一个使用 WebSocket 的网站。**
2. **网站的 JavaScript 代码创建了一个 `WebSocket` 对象，并尝试连接到 WebSocket 服务器。**
3. **Chromium 浏览器接收到 JavaScript 的请求，网络栈开始建立 WebSocket 连接。**
4. **如果协商的结果是使用普通的 TCP 或 TLS 连接，则会创建一个 `ClientSocketHandle` 对象来管理底层的 socket 连接。**
5. **创建一个 `WebSocketClientSocketHandleAdapter` 对象，并将 `ClientSocketHandle` 对象关联到该适配器。**
6. **如果协商的结果是使用 SPDY 或 HTTP/2 连接，则会重用现有的 SPDY 会话，并创建一个新的 SPDY 流 (`SpdyStream`)。**
7. **创建一个 `WebSocketSpdyStreamAdapter` 对象，并将 `SpdyStream` 对象和相关的代理对象关联到该适配器。**
8. **JavaScript 代码通过 `WebSocket` 对象发送和接收数据，这些操作会最终调用到 `WebSocketClientSocketHandleAdapter` 或 `WebSocketSpdyStreamAdapter` 的 `Read` 和 `Write` 方法。**
9. **如果连接出现问题（例如网络中断、服务器关闭连接），适配器会检测到这些事件，并通过代理通知上层，最终可能触发 JavaScript 的 `onerror` 或 `onclose` 事件。**

在调试 WebSocket 相关问题时，开发者可能会在 Chromium 的网络栈代码中设置断点，例如在 `WebSocketClientSocketHandleAdapter::Read` 或 `WebSocketSpdyStreamAdapter::Disconnect` 等方法中，来观察数据流和连接状态的变化，从而定位问题。这个测试文件中的用例覆盖了这些关键方法和场景，可以帮助开发者理解适配器的行为和排查错误。

**该部分功能的总结:**

总而言之，`websocket_basic_stream_adapters_test.cc` 的第一部分主要负责测试 `WebSocketClientSocketHandleAdapter` 和 `WebSocketSpdyStreamAdapter` 这两个关键的 WebSocket 流适配器的基本功能，包括连接管理、数据读写以及与代理的交互。这些测试确保了 Chromium 网络栈能够正确地处理不同类型的 WebSocket 连接，并为上层的 JavaScript WebSocket API 提供可靠的基础。

### 提示词
```
这是目录为net/websockets/websocket_basic_stream_adapters_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/websockets/websocket_basic_stream_adapters.h"

#include <stdint.h>

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/run_loop.h"
#include "base/strings/strcat.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/default_tick_clock.h"
#include "base/time/time.h"
#include "net/base/host_port_pair.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/network_handle.h"
#include "net/base/privacy_mode.h"
#include "net/base/proxy_chain.h"
#include "net/base/request_priority.h"
#include "net/base/session_usage.h"
#include "net/base/test_completion_callback.h"
#include "net/cert/cert_verify_result.h"
#include "net/dns/public/host_resolver_results.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_network_session.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log.h"
#include "net/log/net_log_with_source.h"
#include "net/quic/address_utils.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/quic/mock_crypto_client_stream_factory.h"
#include "net/quic/mock_quic_data.h"
#include "net/quic/quic_chromium_alarm_factory.h"
#include "net/quic/quic_chromium_client_session.h"
#include "net/quic/quic_chromium_client_session_peer.h"
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
#include "net/socket/next_proto.h"
#include "net/socket/socket_tag.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/stream_socket.h"
#include "net/spdy/spdy_session_key.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/ssl/ssl_config.h"
#include "net/ssl/ssl_config_service_defaults.h"
#include "net/ssl/ssl_info.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/third_party/quiche/src/quiche/common/platform/api/quiche_flags.h"
#include "net/third_party/quiche/src/quiche/common/quiche_buffer_allocator.h"
#include "net/third_party/quiche/src/quiche/common/simple_buffer_allocator.h"
#include "net/third_party/quiche/src/quiche/http2/core/spdy_protocol.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/quic_crypto_client_config.h"
#include "net/third_party/quiche/src/quiche/quic/core/http/http_encoder.h"
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
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/websockets/websocket_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

namespace net {
class QuicChromiumClientStream;
class SpdySession;
class WebSocketEndpointLockManager;
class X509Certificate;
}  // namespace net

using testing::_;
using testing::AnyNumber;
using testing::Invoke;
using testing::Return;
using testing::StrictMock;
using testing::Test;

namespace net::test {

class WebSocketClientSocketHandleAdapterTest : public TestWithTaskEnvironment {
 protected:
  WebSocketClientSocketHandleAdapterTest()
      : network_session_(
            SpdySessionDependencies::SpdyCreateSession(&session_deps_)),
        websocket_endpoint_lock_manager_(
            network_session_->websocket_endpoint_lock_manager()) {}

  ~WebSocketClientSocketHandleAdapterTest() override = default;

  bool InitClientSocketHandle(ClientSocketHandle* connection) {
    scoped_refptr<ClientSocketPool::SocketParams> socks_params =
        base::MakeRefCounted<ClientSocketPool::SocketParams>(
            /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());
    TestCompletionCallback callback;
    int rv = connection->Init(
        ClientSocketPool::GroupId(
            url::SchemeHostPort(url::kHttpsScheme, "www.example.org", 443),
            PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
            SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false),
        socks_params, /*proxy_annotation_tag=*/TRAFFIC_ANNOTATION_FOR_TESTS,
        MEDIUM, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
        callback.callback(), ClientSocketPool::ProxyAuthCallback(),
        network_session_->GetSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL,
                                        ProxyChain::Direct()),
        NetLogWithSource());
    rv = callback.GetResult(rv);
    return rv == OK;
  }

  SpdySessionDependencies session_deps_;
  std::unique_ptr<HttpNetworkSession> network_session_;
  raw_ptr<WebSocketEndpointLockManager> websocket_endpoint_lock_manager_;
};

TEST_F(WebSocketClientSocketHandleAdapterTest, Uninitialized) {
  auto connection = std::make_unique<ClientSocketHandle>();
  WebSocketClientSocketHandleAdapter adapter(std::move(connection));
  EXPECT_FALSE(adapter.is_initialized());
}

TEST_F(WebSocketClientSocketHandleAdapterTest, IsInitialized) {
  StaticSocketDataProvider data;
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);

  auto connection = std::make_unique<ClientSocketHandle>();
  ClientSocketHandle* const connection_ptr = connection.get();

  WebSocketClientSocketHandleAdapter adapter(std::move(connection));
  EXPECT_FALSE(adapter.is_initialized());

  EXPECT_TRUE(InitClientSocketHandle(connection_ptr));

  EXPECT_TRUE(adapter.is_initialized());
}

TEST_F(WebSocketClientSocketHandleAdapterTest, Disconnect) {
  StaticSocketDataProvider data;
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);

  auto connection = std::make_unique<ClientSocketHandle>();
  EXPECT_TRUE(InitClientSocketHandle(connection.get()));

  StreamSocket* const socket = connection->socket();

  WebSocketClientSocketHandleAdapter adapter(std::move(connection));
  EXPECT_TRUE(adapter.is_initialized());

  EXPECT_TRUE(socket->IsConnected());
  adapter.Disconnect();
  EXPECT_FALSE(socket->IsConnected());
}

TEST_F(WebSocketClientSocketHandleAdapterTest, Read) {
  MockRead reads[] = {MockRead(SYNCHRONOUS, "foo"), MockRead("bar")};
  StaticSocketDataProvider data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);

  auto connection = std::make_unique<ClientSocketHandle>();
  EXPECT_TRUE(InitClientSocketHandle(connection.get()));

  WebSocketClientSocketHandleAdapter adapter(std::move(connection));
  EXPECT_TRUE(adapter.is_initialized());

  // Buffer larger than each MockRead.
  constexpr int kReadBufSize = 1024;
  auto read_buf = base::MakeRefCounted<IOBufferWithSize>(kReadBufSize);
  int rv = adapter.Read(read_buf.get(), kReadBufSize, CompletionOnceCallback());
  ASSERT_EQ(3, rv);
  EXPECT_EQ("foo", std::string_view(read_buf->data(), rv));

  TestCompletionCallback callback;
  rv = adapter.Read(read_buf.get(), kReadBufSize, callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  ASSERT_EQ(3, rv);
  EXPECT_EQ("bar", std::string_view(read_buf->data(), rv));

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(WebSocketClientSocketHandleAdapterTest, ReadIntoSmallBuffer) {
  MockRead reads[] = {MockRead(SYNCHRONOUS, "foo"), MockRead("bar")};
  StaticSocketDataProvider data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);

  auto connection = std::make_unique<ClientSocketHandle>();
  EXPECT_TRUE(InitClientSocketHandle(connection.get()));

  WebSocketClientSocketHandleAdapter adapter(std::move(connection));
  EXPECT_TRUE(adapter.is_initialized());

  // Buffer smaller than each MockRead.
  constexpr int kReadBufSize = 2;
  auto read_buf = base::MakeRefCounted<IOBufferWithSize>(kReadBufSize);
  int rv = adapter.Read(read_buf.get(), kReadBufSize, CompletionOnceCallback());
  ASSERT_EQ(2, rv);
  EXPECT_EQ("fo", std::string_view(read_buf->data(), rv));

  rv = adapter.Read(read_buf.get(), kReadBufSize, CompletionOnceCallback());
  ASSERT_EQ(1, rv);
  EXPECT_EQ("o", std::string_view(read_buf->data(), rv));

  TestCompletionCallback callback1;
  rv = adapter.Read(read_buf.get(), kReadBufSize, callback1.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback1.WaitForResult();
  ASSERT_EQ(2, rv);
  EXPECT_EQ("ba", std::string_view(read_buf->data(), rv));

  rv = adapter.Read(read_buf.get(), kReadBufSize, CompletionOnceCallback());
  ASSERT_EQ(1, rv);
  EXPECT_EQ("r", std::string_view(read_buf->data(), rv));

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(WebSocketClientSocketHandleAdapterTest, Write) {
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, "foo"), MockWrite("bar")};
  StaticSocketDataProvider data(base::span<MockRead>(), writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);

  auto connection = std::make_unique<ClientSocketHandle>();
  EXPECT_TRUE(InitClientSocketHandle(connection.get()));

  WebSocketClientSocketHandleAdapter adapter(std::move(connection));
  EXPECT_TRUE(adapter.is_initialized());

  auto write_buf1 = base::MakeRefCounted<StringIOBuffer>("foo");
  int rv =
      adapter.Write(write_buf1.get(), write_buf1->size(),
                    CompletionOnceCallback(), TRAFFIC_ANNOTATION_FOR_TESTS);
  ASSERT_EQ(3, rv);

  auto write_buf2 = base::MakeRefCounted<StringIOBuffer>("bar");
  TestCompletionCallback callback;
  rv = adapter.Write(write_buf2.get(), write_buf2->size(), callback.callback(),
                     TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  ASSERT_EQ(3, rv);

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

// Test that if both Read() and Write() returns asynchronously,
// the two callbacks are handled correctly.
TEST_F(WebSocketClientSocketHandleAdapterTest, AsyncReadAndWrite) {
  MockRead reads[] = {MockRead("foobar")};
  MockWrite writes[] = {MockWrite("baz")};
  StaticSocketDataProvider data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);

  auto connection = std::make_unique<ClientSocketHandle>();
  EXPECT_TRUE(InitClientSocketHandle(connection.get()));

  WebSocketClientSocketHandleAdapter adapter(std::move(connection));
  EXPECT_TRUE(adapter.is_initialized());

  constexpr int kReadBufSize = 1024;
  auto read_buf = base::MakeRefCounted<IOBufferWithSize>(kReadBufSize);
  TestCompletionCallback read_callback;
  int rv = adapter.Read(read_buf.get(), kReadBufSize, read_callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  auto write_buf = base::MakeRefCounted<StringIOBuffer>("baz");
  TestCompletionCallback write_callback;
  rv = adapter.Write(write_buf.get(), write_buf->size(),
                     write_callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = read_callback.WaitForResult();
  ASSERT_EQ(6, rv);
  EXPECT_EQ("foobar", std::string_view(read_buf->data(), rv));

  rv = write_callback.WaitForResult();
  ASSERT_EQ(3, rv);

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

class MockDelegate : public WebSocketSpdyStreamAdapter::Delegate {
 public:
  ~MockDelegate() override = default;
  MOCK_METHOD(void, OnHeadersSent, (), (override));
  MOCK_METHOD(void,
              OnHeadersReceived,
              (const quiche::HttpHeaderBlock&),
              (override));
  MOCK_METHOD(void, OnClose, (int), (override));
};

class WebSocketSpdyStreamAdapterTest : public TestWithTaskEnvironment {
 protected:
  WebSocketSpdyStreamAdapterTest()
      : url_("wss://www.example.org/"),
        key_(HostPortPair::FromURL(url_),
             PRIVACY_MODE_DISABLED,
             ProxyChain::Direct(),
             SessionUsage::kDestination,
             SocketTag(),
             NetworkAnonymizationKey(),
             SecureDnsPolicy::kAllow,
             /*disable_cert_verification_network_fetches=*/false),
        session_(SpdySessionDependencies::SpdyCreateSession(&session_deps_)),
        ssl_(SYNCHRONOUS, OK) {}

  ~WebSocketSpdyStreamAdapterTest() override = default;

  static quiche::HttpHeaderBlock RequestHeaders() {
    return WebSocketHttp2Request("/", "www.example.org:443",
                                 "http://www.example.org", {});
  }

  static quiche::HttpHeaderBlock ResponseHeaders() {
    return WebSocketHttp2Response({});
  }

  void AddSocketData(SocketDataProvider* data) {
    session_deps_.socket_factory->AddSocketDataProvider(data);
  }

  void AddSSLSocketData() {
    ssl_.ssl_info.cert =
        ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
    ASSERT_TRUE(ssl_.ssl_info.cert);
    session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_);
  }

  base::WeakPtr<SpdySession> CreateSpdySession() {
    return ::net::CreateSpdySession(session_.get(), key_, NetLogWithSource());
  }

  base::WeakPtr<SpdyStream> CreateSpdyStream(
      base::WeakPtr<SpdySession> session) {
    return CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session, url_,
                                     LOWEST, NetLogWithSource());
  }

  SpdyTestUtil spdy_util_;
  StrictMock<MockDelegate> mock_delegate_;

 private:
  const GURL url_;
  const SpdySessionKey key_;
  SpdySessionDependencies session_deps_;
  std::unique_ptr<HttpNetworkSession> session_;
  SSLSocketDataProvider ssl_;
};

TEST_F(WebSocketSpdyStreamAdapterTest, Disconnect) {
  MockRead reads[] = {MockRead(ASYNC, ERR_IO_PENDING, 0),
                      MockRead(ASYNC, 0, 1)};
  SequencedSocketData data(reads, base::span<MockWrite>());
  AddSocketData(&data);
  AddSSLSocketData();

  base::WeakPtr<SpdySession> session = CreateSpdySession();
  base::WeakPtr<SpdyStream> stream = CreateSpdyStream(session);
  WebSocketSpdyStreamAdapter adapter(stream, &mock_delegate_,
                                     NetLogWithSource());
  EXPECT_TRUE(adapter.is_initialized());

  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(stream);
  adapter.Disconnect();
  EXPECT_FALSE(stream);

  // Read EOF.
  EXPECT_TRUE(session);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session);

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(WebSocketSpdyStreamAdapterTest, SendRequestHeadersThenDisconnect) {
  MockRead reads[] = {MockRead(ASYNC, ERR_IO_PENDING, 0),
                      MockRead(ASYNC, 0, 3)};
  spdy::SpdySerializedFrame headers(spdy_util_.ConstructSpdyHeaders(
      1, RequestHeaders(), DEFAULT_PRIORITY, false));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
  MockWrite writes[] = {CreateMockWrite(headers, 1), CreateMockWrite(rst, 2)};
  SequencedSocketData data(reads, writes);
  AddSocketData(&data);
  AddSSLSocketData();

  base::WeakPtr<SpdySession> session = CreateSpdySession();
  base::WeakPtr<SpdyStream> stream = CreateSpdyStream(session);
  WebSocketSpdyStreamAdapter adapter(stream, &mock_delegate_,
                                     NetLogWithSource());
  EXPECT_TRUE(adapter.is_initialized());

  int rv = stream->SendRequestHeaders(RequestHeaders(), MORE_DATA_TO_SEND);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // First read is a pause and it has lower sequence number than first write.
  // Therefore writing headers does not complete while |data| is paused.
  base::RunLoop().RunUntilIdle();

  // Reset the stream before writing completes.
  // OnHeadersSent() will never be called.
  EXPECT_TRUE(stream);
  adapter.Disconnect();
  EXPECT_FALSE(stream);

  // Resume |data|, finish writing headers, and read EOF.
  EXPECT_TRUE(session);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session);

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(WebSocketSpdyStreamAdapterTest, OnHeadersSentThenDisconnect) {
  MockRead reads[] = {MockRead(ASYNC, 0, 2)};
  spdy::SpdySerializedFrame headers(spdy_util_.ConstructSpdyHeaders(
      1, RequestHeaders(), DEFAULT_PRIORITY, false));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
  MockWrite writes[] = {CreateMockWrite(headers, 0), CreateMockWrite(rst, 1)};
  SequencedSocketData data(reads, writes);
  AddSocketData(&data);
  AddSSLSocketData();

  EXPECT_CALL(mock_delegate_, OnHeadersSent());

  base::WeakPtr<SpdySession> session = CreateSpdySession();
  base::WeakPtr<SpdyStream> stream = CreateSpdyStream(session);
  WebSocketSpdyStreamAdapter adapter(stream, &mock_delegate_,
                                     NetLogWithSource());
  EXPECT_TRUE(adapter.is_initialized());

  int rv = stream->SendRequestHeaders(RequestHeaders(), MORE_DATA_TO_SEND);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Finish asynchronous write of headers.  This calls OnHeadersSent().
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(stream);
  adapter.Disconnect();
  EXPECT_FALSE(stream);

  // Read EOF.
  EXPECT_TRUE(session);
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session);

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(WebSocketSpdyStreamAdapterTest, OnHeadersReceivedThenDisconnect) {
  spdy::SpdySerializedFrame response_headers(
      spdy_util_.ConstructSpdyResponseHeaders(1, ResponseHeaders(), false));
  MockRead reads[] = {CreateMockRead(response_headers, 1),
                      MockRead(ASYNC, 0, 3)};
  spdy::SpdySerializedFrame request_headers(spdy_util_.ConstructSpdyHeaders(
      1, RequestHeaders(), DEFAULT_PRIORITY, false));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
  MockWrite writes[] = {CreateMockWrite(request_headers, 0),
                        CreateMockWrite(rst, 2)};
  SequencedSocketData data(reads, writes);
  AddSocketData(&data);
  AddSSLSocketData();

  EXPECT_CALL(mock_delegate_, OnHeadersSent());
  EXPECT_CALL(mock_delegate_, OnHeadersReceived(_));

  base::WeakPtr<SpdySession> session = CreateSpdySession();
  base::WeakPtr<SpdyStream> stream = CreateSpdyStream(session);
  WebSocketSpdyStreamAdapter adapter(stream, &mock_delegate_,
                                     NetLogWithSource());
  EXPECT_TRUE(adapter.is_initialized());

  int rv = stream->SendRequestHeaders(RequestHeaders(), MORE_DATA_TO_SEND);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(stream);
  adapter.Disconnect();
  EXPECT_FALSE(stream);

  // Read EOF.
  EXPECT_TRUE(session);
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session);

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(WebSocketSpdyStreamAdapterTest, ServerClosesConnection) {
  MockRead reads[] = {MockRead(ASYNC, 0, 0)};
  SequencedSocketData data(reads, base::span<MockWrite>());
  AddSocketData(&data);
  AddSSLSocketData();

  EXPECT_CALL(mock_delegate_, OnClose(ERR_CONNECTION_CLOSED));

  base::WeakPtr<SpdySession> session = CreateSpdySession();
  base::WeakPtr<SpdyStream> stream = CreateSpdyStream(session);
  WebSocketSpdyStreamAdapter adapter(stream, &mock_delegate_,
                                     NetLogWithSource());
  EXPECT_TRUE(adapter.is_initialized());

  EXPECT_TRUE(session);
  EXPECT_TRUE(stream);
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session);
  EXPECT_FALSE(stream);

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(WebSocketSpdyStreamAdapterTest,
       SendRequestHeadersThenServerClosesConnection) {
  MockRead reads[] = {MockRead(ASYNC, 0, 1)};
  spdy::SpdySerializedFrame headers(spdy_util_.ConstructSpdyHeaders(
      1, RequestHeaders(), DEFAULT_PRIORITY, false));
  MockWrite writes[] = {CreateMockWrite(headers, 0)};
  SequencedSocketData data(reads, writes);
  AddSocketData(&data);
  AddSSLSocketData();

  EXPECT_CALL(mock_delegate_, OnHeadersSent());
  EXPECT_CALL(mock_delegate_, OnClose(ERR_CONNECTION_CLOSED));

  base::WeakPtr<SpdySession> session = CreateSpdySession();
  base::WeakPtr<SpdyStream> stream = CreateSpdyStream(session);
  WebSocketSpdyStreamAdapter adapter(stream, &mock_delegate_,
                                     NetLogWithSource());
  EXPECT_TRUE(adapter.is_initialized());

  int rv = stream->SendRequestHeaders(RequestHeaders(), MORE_DATA_TO_SEND);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_TRUE(session);
  EXPECT_TRUE(stream);
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session);
  EXPECT_FALSE(stream);

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(WebSocketSpdyStreamAdapterTest,
       OnHeadersReceivedThenServerClosesConnection) {
  spdy::SpdySerializedFrame response_headers(
      spdy_util_.ConstructSpdyResponseHeaders(1, ResponseHeaders(), false));
  MockRead reads[] = {CreateMockRead(response_headers, 1),
                      MockRead(ASYNC, 0, 2)};
  spdy::SpdySerializedFrame request_headers(spdy_util_.ConstructSpdyHeaders(
      1, RequestHeaders(), DEFAULT_PRIORITY, false));
  MockWrite writes[] = {CreateMockWrite(request_headers, 0)};
  SequencedSocketData data(reads, writes);
  AddSocketData(&data);
  AddSSLSocketData();

  EXPECT_CALL(mock_delegate_, OnHeadersSent());
  EXPECT_CALL(mock_delegate_, OnHeadersReceived(_));
  EXPECT_CALL(mock_delegate_, OnClose(ERR_CONNECTION_CLOSED));

  base::WeakPtr<SpdySession> session = CreateSpdySession();
  base::WeakPtr<SpdyStream> stream = CreateSpdyStream(session);
  WebSocketSpdyStreamAdapter adapter(stream, &mock_delegate_,
                                     NetLogWithSource());
  EXPECT_TRUE(adapter.is_initialized());

  int rv = stream->SendRequestHeaders(RequestHeaders(), MORE_DATA_TO_SEND);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_TRUE(session);
  EXPECT_TRUE(stream);
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session);
  EXPECT_FALSE(stream);

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

// Previously we failed to detect a half-close by the server that indicated the
// stream should be closed. This test ensures a half-close is correctly
// detected. See https://crbug.com/1151393.
TEST_F(WebSocketSpdyStreamAdapterTest, OnHeadersReceivedThenStreamEnd) {
  spdy::SpdySerializedFrame response_headers(
      spdy_util_.ConstructSpdyResponseHeaders(1, ResponseHeaders(), false));
  spdy::SpdySerializedFrame stream_end(
      spdy_util_.ConstructSpdyDataFrame(1, "", true));
  MockRead reads[] = {CreateMockRead(response_headers, 1),
                      CreateMockRead(stream_end, 2),
                      MockRead(ASYNC, ERR_IO_PENDING, 3),  // pause here
                      MockRead(ASYNC, 0, 4)};
  spdy::SpdySerializedFrame request_headers(spdy_util_.ConstructSpdyHeaders(
      1, RequestHeaders(), DEFAULT_PRIORITY, /* fin = */ false));
  MockWrite writes[] = {CreateMockWrite(request_headers, 0)};
  SequencedSocketData data(reads, writes);
  AddSocketData(&data);
  AddSSLSocketData();

  EXPECT_CALL(mock_delegate_, OnHeadersSent());
  EXPECT_CALL(mock_delegate_, OnHeadersReceived(_));
  EXPECT_CALL(mock_delegate_, OnClose(ERR_CONNECTION_CLOSED));

  // Must create buffer before `adapter`, since `adapter` doesn't hold onto a
  // reference to it.
  constexpr int kReadBufSize = 1024;
  auto read_buf = base::MakeRefCounted<IOBufferWithSize>(kReadBufSize);

  base::WeakPtr<SpdySession> session = CreateSpdySession();
  base::WeakPtr<SpdyStream> stream = CreateSpdyStream(session);
  WebSocketSpdyStreamAdapter adapter(stream, &mock_delegate_,
                                     NetLogWithSource());
  EXPECT_TRUE(adapter.is_initialized());

  int rv = stream->SendRequestHeaders(RequestHeaders(), MORE_DATA_TO_SEND);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  TestCompletionCallback read_callback;
  rv = adapter.Read(read_buf.get(), kReadBufSize, read_callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_TRUE(session);
  EXPECT_TRUE(stream);
  rv = read_callback.WaitForResult();
  EXPECT_EQ(ERR_CONNECTION_CLOSED, rv);
  EXPECT_TRUE(session);
  EXPECT_FALSE(stream);

  // Close the session.
  data.Resume();

  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(WebSocketSpdyStreamAdapterTest, DetachDelegate) {
  spdy::SpdySerializedFrame response_headers(
      spdy_util_.ConstructSpdyResponseHeaders(1, ResponseHeaders(), false));
  MockRead reads[] = {CreateMockRead(response_headers, 1),
                      MockRead(ASYNC, 0, 2)};
  spdy::SpdySerializedFrame request_headers(spdy_util_.ConstructSpdyHeaders(
      1, RequestHeaders(), DEFAULT_PRIORITY, false));
  MockWrite writes[] = {CreateMockWrite(request_headers, 0)};
  SequencedSocketData data(reads, writes);
  AddSocketData(&data);
  AddSSLSocketData();

  base::WeakPtr<SpdySession> session = CreateSpdySession();
  base::WeakPtr<SpdyStream> stream = CreateSpdyStream(session);
  WebSocketSpdyStreamAdapter adapter(stream, &mock_delegate_,
                                     NetLogWithSource());
  EXPECT_TRUE(adapter.is_initialized());

  // No Delegate methods shall be called after this.
  adapter.DetachDelegate();

  int rv = stream->SendRequestHeaders(RequestHeaders(), MORE_DATA_TO_SEND);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_TRUE(session);
  EXPECT_TRUE(stream);
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session);
  EXPECT_FALSE(stream);

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(WebSocketSpdyStreamAdapterTest, Read) {
  spdy::SpdySerializedFrame response_headers(
      spdy_util_.ConstructSpdyResponseHeaders(1, ResponseHeaders(), false));
  // First read is the same size as the buffer, next is smaller, last is larger.
  spdy::SpdySerializedFrame data_frame1(
      spdy_util_.ConstructSpdyDataFrame(1, "foo", false));
  spdy::SpdySerializedFrame data_frame2(
      spdy_util_.ConstructSpdyDataFrame(1, "ba", false));
  spdy::SpdySerializedFrame data_frame3(
      spdy_util_.ConstructSpdyDataFrame(1, "rbaz", true));
  MockRead reads[] = {CreateMockRead(response_headers, 1),
                      CreateMockRead(data_frame1, 2),
                      CreateMockRead(data_frame2, 3),
                      CreateMockRead(data_frame3, 4), MockRead(ASYNC, 0, 5)};
  spdy::SpdySerializedFrame request_headers(spdy_util_.ConstructSpdyHeaders(
      1, RequestHeaders(), DEFAULT_PRIORITY, false));
  MockWrite writes[] = {CreateMockWrite(request_headers, 0)};
  SequencedSocketData data(reads, writes);
  AddSocketData(&data);
  AddSSLSocketData();

  EXPECT_CALL(mock_delegate_, OnHeadersSent());
  EXPECT_CALL(mock_delegate_, OnHeadersReceived(_));

  base::WeakPtr<SpdySession> session = CreateSpdySession();
  base::WeakPtr<SpdyStream> stream = CreateSpdyStream(session);
  WebSocketSpdyStreamAdapter adapter(stream, &mock_delegate_,
                                     NetLogWithSource());
  EXPECT_TRUE(adapter.is_initialized());

  int rv = stream->SendRequestHeaders(RequestHeaders(), MORE_DATA_TO_SEND);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  constexpr int kReadBufSize = 3;
  auto read_buf = base::MakeRefCounted<IOBufferWithSize>(kReadBufSize);
  TestCompletionCallback callback;
  rv = adapter.Read(read_buf.get(), kReadBufSize, callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  ASSERT_EQ(3, rv);
  EXPECT_EQ("foo", std::string_view(read_buf->data(), rv));

  // Read EOF to destroy the connection and the stream.
  // This calls SpdySession::Delegate::OnClose().
  EXPECT_TRUE(session);
  EXPECT_TRUE(stream);
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session);
  EXPECT_FALSE(stream);

  // Two socket reads are concatenated by WebSocketSpdyStreamAdapter.
  rv = adapter.Read(read_buf.get(), kReadBufSize, CompletionOnceCallback());
  ASSERT_EQ(3, rv);
  EXPECT_EQ("bar", std::string_view(read_buf->data(), rv));

  rv = adapter.Read(read_buf.get(), kReadBufSize, CompletionOnceCallback());
  ASSERT_EQ(3, rv);
  EXPECT_EQ("baz", std::string_view(read_buf->data(), rv));

  // Even though connection and stream are already closed,
  // WebSocketSpdyStreamAdapter::Delegate::OnClose() is only called after all
  // buffered data are read.
  EXPECT_CALL(mock_delegate_, OnClose(ERR_CONNECTION_CLOSED));

  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(WebSocketSpdyStreamAdapterTest, CallDelegateOnCloseShouldNotCrash) {
  spdy::SpdySerializedFrame response_headers(
      spdy_util_.ConstructSpdyResponseHeaders(1, ResponseHeaders(), false));
  spdy::SpdySerializedFrame data_frame1(
      spdy_util_.ConstructSpdyDataFrame(1, "foo", false));
  spdy::SpdySerializedFrame data_frame2(
      spdy_util_.ConstructSpdyDataFrame(1, "bar", false));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
  MockRead reads[] = {CreateMockRead(response_headers, 1),
                      CreateMockRead(data_frame1, 2),
                      CreateMockRead(data_frame2, 3), CreateMockRead(rst, 4),
                      MockRead(ASYNC, 0, 5)};
  spdy::SpdySerializedFrame request_headers(spdy_util_.ConstructSpdyHeaders(
      1, RequestHeaders(), DEFAULT_PRIORITY, false));
  MockWrite writes[] = {CreateMockWrite(request_headers, 0)};
  SequencedSocketData data(reads, writes);
  AddSocketData(&data);
  AddSSLSocketData();

  EXPECT_CALL(mock_delegate_, OnHeadersSent());
  EXPECT_CALL(mock_delegate_, OnHeadersReceived(_));

  base::WeakPtr<SpdySession> session = CreateSpdySession();
  base::WeakPtr<SpdyStream>
```