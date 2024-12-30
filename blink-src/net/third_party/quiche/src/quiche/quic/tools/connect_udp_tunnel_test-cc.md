Response:
Let's break down the thought process for analyzing the C++ test file.

1. **Understand the Goal:** The primary goal is to understand the functionality of `connect_udp_tunnel_test.cc`. This means figuring out what aspect of the Chromium networking stack it's testing. The filename itself provides a strong clue: "connect_udp_tunnel". This suggests it's testing a mechanism for establishing a UDP tunnel over an existing connection. The "test.cc" suffix confirms it's a unit test file.

2. **Identify Key Components:**  Scan the `#include` directives. These tell us what other parts of the codebase are being used. Key inclusions here are:
    * `connect_udp_tunnel.h`:  This is likely the header file for the class being tested.
    * Quiche-related headers (`quiche/quic/...`):  Indicates this is related to the QUIC protocol.
    * `quiche/common/masque/...`:  "masque" is a likely keyword for the UDP tunnel functionality.
    * Testing frameworks (`quiche/common/platform/api/quiche_test.h`, `testing/...`):  Confirms this is a unit test.

3. **Examine the Test Fixture:** The `ConnectUdpTunnelTest` class is the test fixture. Its `SetUp` method is crucial. What's happening here?
    * Socket initialization (`std::make_unique<StrictMock<MockSocket>>`). The use of `StrictMock` hints at careful control and expectation setting for interactions with the `MockSocket`.
    * Mocking dependencies (`NiceMock<MockQuicConnectionHelper>`, `NiceMock<MockAlarmFactory>`, etc.). This is standard practice in unit testing to isolate the unit under test.
    * Setting up expectations on the `MockSocketFactory`. This is how the test injects the mock socket into the `ConnectUdpTunnel`. The `ON_CALL` with `CreateConnectingUdpClientSocket` is a key point – it shows that the `ConnectUdpTunnel` uses a factory to create UDP sockets.
    * Instantiating the `ConnectUdpTunnel` under test.

4. **Analyze Individual Test Cases:** Each `TEST_F` function focuses on a specific scenario. Go through each one and understand what it's testing:
    * `OpenTunnel`: Tests the basic successful opening of a tunnel. Look for `EXPECT_CALL`s that verify the expected behavior (connecting the socket, receiving data, sending a specific response).
    * `OpenTunnelToIpv4LiteralTarget`, `OpenTunnelToIpv6LiteralTarget`:  Tests opening tunnels to specific IP address formats. This indicates that the tunnel supports both IPv4 and IPv6.
    * `OpenTunnelWithMalformedRequest`: Tests error handling when the request is invalid. The `TerminateStreamWithError` expectation is crucial here.
    * `OpenTunnelWithUnacceptableTarget`: Tests handling of attempts to connect to forbidden destinations. The expectation on `OnResponseBackendComplete` with a 403 status is key.
    * `ReceiveFromTarget`: Tests the scenario where data is received *from* the UDP tunnel and sent back to the client. The `SendHttp3Datagram` expectation is important.
    * `SendToTarget`: Tests sending data *to* the UDP tunnel. The `SendBlocking` expectation on the mock socket is key.

5. **Identify Mock Objects and Their Roles:** Notice the various `Mock...` classes. These are crucial for controlling the behavior of dependencies:
    * `MockStream`: Represents a QUIC stream used for communication.
    * `MockRequestHandler`:  Represents the server-side handler for the connection.
    * `MockSocketFactory`:  Responsible for creating client sockets.
    * `MockSocket`:  Represents the underlying UDP socket of the tunnel.

6. **Look for Connections to JavaScript (If Applicable):**  In this specific case, there's no direct JavaScript code within the C++ file. However, consider *why* this C++ code exists. It's part of the Chromium network stack, which *powers* web browsers. JavaScript running in a browser might initiate a request that eventually leads to this C++ code being executed. The "CONNECT" method with "connect-udp" protocol in the headers is a strong indicator that this is related to a web standard (like MASQUE) that allows JavaScript to create UDP tunnels via a proxy.

7. **Infer Logical Reasoning and Assumptions:** For each test case, consider the assumptions being made. For instance, in `OpenTunnel`, the test assumes that if the socket connects successfully and starts receiving, the tunnel is considered "open". The input is the `request_headers`, and the expected output is the side effect of the tunnel opening and the `OnResponseBackendComplete` call.

8. **Consider User and Programming Errors:** Think about how a user or a programmer might misuse this functionality. Incorrectly formatted request headers, trying to connect to blocked ports, or failing to handle the asynchronous nature of network operations are potential errors.

9. **Trace User Operations:**  How does a user's action in a browser lead to this code?  A user might be using an application or website that utilizes a proxy with MASQUE support to establish a UDP tunnel. This would involve JavaScript making a `CONNECT` request with the specific "connect-udp" protocol and target information.

10. **Structure the Explanation:** Organize the findings logically. Start with the core function, then delve into specific scenarios, connections to JavaScript (if any), logical reasoning, potential errors, and the user journey. Use clear and concise language. Highlight key aspects like the use of mocks and the purpose of each test case.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** "This looks like a simple socket test."
* **Correction:**  "No, the `CONNECT` method and `connect-udp` protocol suggest it's about establishing a tunnel over an existing connection, likely HTTP/3."
* **Initial thought:** "The mocks are just for basic dependency injection."
* **Refinement:** "The `StrictMock` indicates a high level of control and precise expectations about the interactions with these dependencies."
* **Initial thought:** "JavaScript isn't directly involved."
* **Refinement:** "While the code is C++, it's a *part* of the browser's networking stack. JavaScript would initiate the requests that trigger this code."

By following this detailed analysis process, and being willing to refine initial assumptions based on the code, a comprehensive understanding of the test file's functionality can be achieved.
这个文件 `net/third_party/quiche/src/quiche/quic/tools/connect_udp_tunnel_test.cc` 是 Chromium 网络栈中 QUIC 协议相关的一个测试文件。它的主要功能是 **测试 `ConnectUdpTunnel` 类的行为**。 `ConnectUdpTunnel` 类的作用是在一个现有的 QUIC 连接之上建立一个 UDP 隧道。这通常用于 MASQUE 协议，允许客户端通过 HTTP/3 连接到一个代理服务器，然后在该连接上创建和管理 UDP 连接到目标服务器。

**具体功能可以概括为：**

1. **测试隧道建立:** 验证 `ConnectUdpTunnel::OpenTunnel` 方法是否能正确处理客户端的 `CONNECT` 请求，并建立到目标服务器的 UDP 连接。这包括解析请求头，验证目标地址是否可接受，以及创建和连接底层的 UDP socket。
2. **测试数据转发 (接收):** 模拟从目标 UDP 服务器接收数据，并验证 `ConnectUdpTunnel` 是否能正确地将这些数据封装成 HTTP/3 Datagram 并发送回客户端。
3. **测试数据转发 (发送):** 模拟从客户端接收 HTTP/3 Datagram，并验证 `ConnectUdpTunnel` 是否能正确地解析这些数据，并将底层的 UDP 数据发送到目标服务器。
4. **测试错误处理:** 验证 `ConnectUdpTunnel` 在处理错误情况下的行为，例如：
    * 接收到格式错误的 `CONNECT` 请求。
    * 尝试连接到不可接受的目标地址。
    * 底层 UDP 连接失败。
5. **测试隧道关闭:** 验证当客户端流关闭时，`ConnectUdpTunnel` 是否能正确地关闭底层的 UDP 连接。

**与 JavaScript 功能的关系：**

这个 C++ 文件本身不包含 JavaScript 代码，但它测试的功能是 **JavaScript 可以触发的**。在 Web 浏览器中，JavaScript 代码可以通过 Fetch API 发起一个特殊的 `CONNECT` 请求，协议设置为 `connect-udp`，目标地址和端口信息编码在 URL 的路径部分。

**举例说明：**

假设一个使用 MASQUE 协议的 VPN 客户端（可能是一个浏览器扩展）想要连接到 `example.com:1234` 的 UDP 服务。客户端的 JavaScript 代码可能会发起如下的 `CONNECT` 请求：

```javascript
fetch('https://proxy.example/proxy/.well-known/masque/udp/example.com/1234/', {
  method: 'CONNECT',
  protocol: 'connect-udp'
}).then(async response => {
  if (response.status === 200) {
    // 隧道建立成功，可以通过 HTTP/3 Datagram 发送和接收 UDP 数据
    // ...
  } else {
    console.error('隧道建立失败:', response.status);
  }
});
```

当 Chromium 浏览器处理这个请求时，如果配置了相应的 MASQUE 代理，就会调用到 C++ 层面的 `ConnectUdpTunnel` 代码，该代码会尝试建立到 `example.com:1234` 的 UDP 连接。 `connect_udp_tunnel_test.cc` 这个测试文件就是用来验证这部分 C++ 代码的正确性。

**逻辑推理、假设输入与输出：**

**测试用例： `OpenTunnel`**

* **假设输入 (HTTP 请求头):**
  ```
  :method: CONNECT
  :protocol: connect-udp
  :authority: proxy.test
  :scheme: https
  :path: /.well-known/masque/udp/localhost/977/
  ```
* **逻辑推理:** `ConnectUdpTunnel` 会解析 `:path` 头，提取目标主机 `localhost` 和端口 `977`。它会创建一个 UDP socket 并尝试连接到该地址。如果连接成功，会向客户端发送一个 HTTP 响应，表示隧道已建立。
* **预期输出:**
    * 调用 `MockSocket::ConnectBlocking()` 并返回成功。
    * 调用 `MockSocket::ReceiveAsync()` 开始监听来自目标服务器的数据。
    * 调用 `MockRequestHandler::OnResponseBackendComplete`，传递一个包含状态码 200 和 `Capsule-Protocol: ?1` 头的 `QuicBackendResponse`。

**测试用例： `ReceiveFromTarget`**

* **假设输入 (HTTP 请求头):** (与 `OpenTunnel` 相同)
* **假设输入 (从目标 UDP 服务器接收到的数据):** `\x11\x22\x33\x44\x55`
* **逻辑推理:** `ConnectUdpTunnel` 接收到 UDP 数据后，会将其封装成 `ConnectUdpDatagramUdpPacketPayload` 格式，并通过 HTTP/3 Datagram 发送到客户端。
* **预期输出:**
    * 调用 `MockStream::SendHttp3Datagram`，参数为封装后的 UDP 数据。

**用户或编程常见的使用错误：**

1. **错误的 `CONNECT` 请求路径:** 用户或程序可能会构造错误的 URL 路径，例如：
   * 缺少 `/.well-known/masque/udp/` 前缀。
   * 目标主机或端口格式错误。
   * 例如：`/.well-known/masque/tcp/localhost/977/` (使用了 `tcp` 而不是 `udp`)。
   * 这会导致 `ConnectUdpTunnel` 解析失败，并可能返回 400 或 500 错误。测试用例 `OpenTunnelWithMalformedRequest` 就是测试这种情况。
2. **尝试连接到被阻止的目标:** 代理服务器可能配置了策略，阻止连接到某些特定的主机或端口。如果用户尝试连接到被阻止的目标，`ConnectUdpTunnel` 会返回一个 403 Forbidden 错误，并在 `Proxy-Status` 头中包含原因。测试用例 `OpenTunnelWithUnacceptableTarget` 就是测试这种情况。
3. **网络问题:** 底层的 UDP 连接可能因为网络故障而失败。这会导致隧道建立失败或中断。测试中会模拟 socket 连接失败的情况。
4. **服务端不支持 MASQUE 或 `connect-udp` 协议:** 如果代理服务器不支持 `connect-udp` 协议，它将无法处理 `CONNECT` 请求，可能会返回 400 或 501 错误。

**用户操作如何一步步到达这里 (作为调试线索)：**

1. **用户在浏览器中访问一个需要建立 UDP 连接的应用或网站。** 例如，一个使用 WebRTC over UDP 的应用，或者一个通过 MASQUE 代理访问外部 UDP 服务的应用。
2. **JavaScript 代码发起一个 `CONNECT` 请求，协议设置为 `connect-udp`。**  这通常发生在应用尝试建立 UDP 连接时。
3. **浏览器网络栈处理该 `CONNECT` 请求。**  它会识别出 `connect-udp` 协议，并查找相应的处理程序。
4. **Chromium 的 QUIC 实现会接收到该请求，并路由到处理 MASQUE 相关功能的代码。**
5. **`ConnectUdpTunnel` 类会被创建并负责处理该连接请求。** 它的构造函数会接收到与该连接相关的上下文信息。
6. **`ConnectUdpTunnel::OpenTunnel` 方法被调用。** 该方法会解析请求头，提取目标地址和端口。
7. **`ConnectUdpTunnel` 使用 `SocketFactory` 创建一个 UDP socket。**  在测试中，`MockSocketFactory` 会返回一个 `MockSocket` 实例。
8. **`MockSocket::ConnectBlocking()` 被调用，尝试连接到目标地址。**
9. **如果连接成功，`ConnectUdpTunnel` 会向客户端发送 200 响应。**
10. **之后，当需要发送或接收 UDP 数据时，会调用 `ConnectUdpTunnel::OnHttp3Datagram` 或 `ConnectUdpTunnel::ReceiveComplete` 方法。**

在调试时，如果怀疑 UDP 隧道建立或数据转发有问题，可以：

* **检查浏览器开发者工具的网络面板，查看 `CONNECT` 请求的状态和头部信息。** 确认请求是否成功发送，以及响应状态码是否为 200。
* **如果使用了 MASQUE 代理，检查代理服务器的日志，查看是否有相关的连接或错误信息。**
* **在 Chromium 源代码中设置断点，追踪 `ConnectUdpTunnel` 类的执行流程。** 可以关注 `OpenTunnel`、`OnHttp3Datagram` 和 `ReceiveComplete` 等关键方法。
* **使用网络抓包工具 (如 Wireshark) 捕获网络数据包，查看 HTTP/3 连接和 UDP 数据包的交互情况。**

`connect_udp_tunnel_test.cc` 作为一个单元测试文件，其存在的主要目的就是确保 `ConnectUdpTunnel` 类的这些步骤和逻辑是正确可靠的，从而保证基于 MASQUE 的 UDP 隧道功能在 Chromium 中的正常运作。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/tools/connect_udp_tunnel_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/connect_udp_tunnel.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/connecting_client_socket.h"
#include "quiche/quic/core/http/quic_spdy_stream.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/socket_factory.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/platform/api/quic_test_loopback.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/tools/quic_simple_server_backend.h"
#include "quiche/common/masque/connect_udp_datagram_payload.h"
#include "quiche/common/platform/api/quiche_googleurl.h"
#include "quiche/common/platform/api/quiche_mem_slice.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/platform/api/quiche_url_utils.h"

namespace quic::test {
namespace {

using ::testing::_;
using ::testing::AnyOf;
using ::testing::Eq;
using ::testing::Ge;
using ::testing::Gt;
using ::testing::HasSubstr;
using ::testing::InvokeWithoutArgs;
using ::testing::IsEmpty;
using ::testing::Matcher;
using ::testing::NiceMock;
using ::testing::Pair;
using ::testing::Property;
using ::testing::Return;
using ::testing::StrictMock;
using ::testing::UnorderedElementsAre;

constexpr QuicStreamId kStreamId = 100;

class MockStream : public QuicSpdyStream {
 public:
  explicit MockStream(QuicSpdySession* spdy_session)
      : QuicSpdyStream(kStreamId, spdy_session, BIDIRECTIONAL) {}

  void OnBodyAvailable() override {}

  MOCK_METHOD(MessageStatus, SendHttp3Datagram, (absl::string_view data),
              (override));
};

class MockRequestHandler : public QuicSimpleServerBackend::RequestHandler {
 public:
  QuicConnectionId connection_id() const override {
    return TestConnectionId(41212);
  }
  QuicStreamId stream_id() const override { return kStreamId; }
  std::string peer_host() const override { return "127.0.0.1"; }

  MOCK_METHOD(QuicSpdyStream*, GetStream, (), (override));
  MOCK_METHOD(void, OnResponseBackendComplete,
              (const QuicBackendResponse* response), (override));
  MOCK_METHOD(void, SendStreamData, (absl::string_view data, bool close_stream),
              (override));
  MOCK_METHOD(void, TerminateStreamWithError, (QuicResetStreamError error),
              (override));
};

class MockSocketFactory : public SocketFactory {
 public:
  MOCK_METHOD(std::unique_ptr<ConnectingClientSocket>, CreateTcpClientSocket,
              (const QuicSocketAddress& peer_address,
               QuicByteCount receive_buffer_size,
               QuicByteCount send_buffer_size,
               ConnectingClientSocket::AsyncVisitor* async_visitor),
              (override));
  MOCK_METHOD(std::unique_ptr<ConnectingClientSocket>,
              CreateConnectingUdpClientSocket,
              (const QuicSocketAddress& peer_address,
               QuicByteCount receive_buffer_size,
               QuicByteCount send_buffer_size,
               ConnectingClientSocket::AsyncVisitor* async_visitor),
              (override));
};

class MockSocket : public ConnectingClientSocket {
 public:
  MOCK_METHOD(absl::Status, ConnectBlocking, (), (override));
  MOCK_METHOD(void, ConnectAsync, (), (override));
  MOCK_METHOD(void, Disconnect, (), (override));
  MOCK_METHOD(absl::StatusOr<QuicSocketAddress>, GetLocalAddress, (),
              (override));
  MOCK_METHOD(absl::StatusOr<quiche::QuicheMemSlice>, ReceiveBlocking,
              (QuicByteCount max_size), (override));
  MOCK_METHOD(void, ReceiveAsync, (QuicByteCount max_size), (override));
  MOCK_METHOD(absl::Status, SendBlocking, (std::string data), (override));
  MOCK_METHOD(absl::Status, SendBlocking, (quiche::QuicheMemSlice data),
              (override));
  MOCK_METHOD(void, SendAsync, (std::string data), (override));
  MOCK_METHOD(void, SendAsync, (quiche::QuicheMemSlice data), (override));
};

class ConnectUdpTunnelTest : public quiche::test::QuicheTest {
 public:
  void SetUp() override {
#if defined(_WIN32)
    WSADATA wsa_data;
    const WORD version_required = MAKEWORD(2, 2);
    ASSERT_EQ(WSAStartup(version_required, &wsa_data), 0);
#endif
    auto socket = std::make_unique<StrictMock<MockSocket>>();
    socket_ = socket.get();
    ON_CALL(socket_factory_,
            CreateConnectingUdpClientSocket(
                AnyOf(QuicSocketAddress(TestLoopback4(), kAcceptablePort),
                      QuicSocketAddress(TestLoopback6(), kAcceptablePort)),
                _, _, &tunnel_))
        .WillByDefault(Return(ByMove(std::move(socket))));

    EXPECT_CALL(request_handler_, GetStream()).WillRepeatedly(Return(&stream_));
  }

 protected:
  static constexpr absl::string_view kAcceptableTarget = "localhost";
  static constexpr uint16_t kAcceptablePort = 977;

  NiceMock<MockQuicConnectionHelper> connection_helper_;
  NiceMock<MockAlarmFactory> alarm_factory_;
  NiceMock<MockQuicSpdySession> session_{new NiceMock<MockQuicConnection>(
      &connection_helper_, &alarm_factory_, Perspective::IS_SERVER)};
  StrictMock<MockStream> stream_{&session_};

  StrictMock<MockRequestHandler> request_handler_;
  NiceMock<MockSocketFactory> socket_factory_;
  StrictMock<MockSocket>* socket_;

  ConnectUdpTunnel tunnel_{
      &request_handler_,
      &socket_factory_,
      "server_label",
      /*acceptable_targets=*/
      {{std::string(kAcceptableTarget), kAcceptablePort},
       {TestLoopback4().ToString(), kAcceptablePort},
       {absl::StrCat("[", TestLoopback6().ToString(), "]"), kAcceptablePort}}};
};

TEST_F(ConnectUdpTunnelTest, OpenTunnel) {
  EXPECT_CALL(*socket_, ConnectBlocking()).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*socket_, ReceiveAsync(Gt(0)));
  EXPECT_CALL(*socket_, Disconnect()).WillOnce(InvokeWithoutArgs([this]() {
    tunnel_.ReceiveComplete(absl::CancelledError());
  }));

  EXPECT_CALL(
      request_handler_,
      OnResponseBackendComplete(
          AllOf(Property(&QuicBackendResponse::response_type,
                         QuicBackendResponse::INCOMPLETE_RESPONSE),
                Property(&QuicBackendResponse::headers,
                         UnorderedElementsAre(Pair(":status", "200"),
                                              Pair("Capsule-Protocol", "?1"))),
                Property(&QuicBackendResponse::trailers, IsEmpty()),
                Property(&QuicBackendResponse::body, IsEmpty()))));

  quiche::HttpHeaderBlock request_headers;
  request_headers[":method"] = "CONNECT";
  request_headers[":protocol"] = "connect-udp";
  request_headers[":authority"] = "proxy.test";
  request_headers[":scheme"] = "https";
  request_headers[":path"] = absl::StrCat(
      "/.well-known/masque/udp/", kAcceptableTarget, "/", kAcceptablePort, "/");

  tunnel_.OpenTunnel(request_headers);
  EXPECT_TRUE(tunnel_.IsTunnelOpenToTarget());
  tunnel_.OnClientStreamClose();
  EXPECT_FALSE(tunnel_.IsTunnelOpenToTarget());
}

TEST_F(ConnectUdpTunnelTest, OpenTunnelToIpv4LiteralTarget) {
  EXPECT_CALL(*socket_, ConnectBlocking()).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*socket_, ReceiveAsync(Gt(0)));
  EXPECT_CALL(*socket_, Disconnect()).WillOnce(InvokeWithoutArgs([this]() {
    tunnel_.ReceiveComplete(absl::CancelledError());
  }));

  EXPECT_CALL(
      request_handler_,
      OnResponseBackendComplete(
          AllOf(Property(&QuicBackendResponse::response_type,
                         QuicBackendResponse::INCOMPLETE_RESPONSE),
                Property(&QuicBackendResponse::headers,
                         UnorderedElementsAre(Pair(":status", "200"),
                                              Pair("Capsule-Protocol", "?1"))),
                Property(&QuicBackendResponse::trailers, IsEmpty()),
                Property(&QuicBackendResponse::body, IsEmpty()))));

  quiche::HttpHeaderBlock request_headers;
  request_headers[":method"] = "CONNECT";
  request_headers[":protocol"] = "connect-udp";
  request_headers[":authority"] = "proxy.test";
  request_headers[":scheme"] = "https";
  request_headers[":path"] =
      absl::StrCat("/.well-known/masque/udp/", TestLoopback4().ToString(), "/",
                   kAcceptablePort, "/");

  tunnel_.OpenTunnel(request_headers);
  EXPECT_TRUE(tunnel_.IsTunnelOpenToTarget());
  tunnel_.OnClientStreamClose();
  EXPECT_FALSE(tunnel_.IsTunnelOpenToTarget());
}

TEST_F(ConnectUdpTunnelTest, OpenTunnelToIpv6LiteralTarget) {
  EXPECT_CALL(*socket_, ConnectBlocking()).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*socket_, ReceiveAsync(Gt(0)));
  EXPECT_CALL(*socket_, Disconnect()).WillOnce(InvokeWithoutArgs([this]() {
    tunnel_.ReceiveComplete(absl::CancelledError());
  }));

  EXPECT_CALL(
      request_handler_,
      OnResponseBackendComplete(
          AllOf(Property(&QuicBackendResponse::response_type,
                         QuicBackendResponse::INCOMPLETE_RESPONSE),
                Property(&QuicBackendResponse::headers,
                         UnorderedElementsAre(Pair(":status", "200"),
                                              Pair("Capsule-Protocol", "?1"))),
                Property(&QuicBackendResponse::trailers, IsEmpty()),
                Property(&QuicBackendResponse::body, IsEmpty()))));

  std::string path;
  ASSERT_TRUE(quiche::ExpandURITemplate(
      "/.well-known/masque/udp/{target_host}/{target_port}/",
      {{"target_host", absl::StrCat("[", TestLoopback6().ToString(), "]")},
       {"target_port", absl::StrCat(kAcceptablePort)}},
      &path));

  quiche::HttpHeaderBlock request_headers;
  request_headers[":method"] = "CONNECT";
  request_headers[":protocol"] = "connect-udp";
  request_headers[":authority"] = "proxy.test";
  request_headers[":scheme"] = "https";
  request_headers[":path"] = path;

  tunnel_.OpenTunnel(request_headers);
  EXPECT_TRUE(tunnel_.IsTunnelOpenToTarget());
  tunnel_.OnClientStreamClose();
  EXPECT_FALSE(tunnel_.IsTunnelOpenToTarget());
}

TEST_F(ConnectUdpTunnelTest, OpenTunnelWithMalformedRequest) {
  EXPECT_CALL(request_handler_,
              TerminateStreamWithError(Property(
                  &QuicResetStreamError::ietf_application_code,
                  static_cast<uint64_t>(QuicHttp3ErrorCode::MESSAGE_ERROR))));

  quiche::HttpHeaderBlock request_headers;
  request_headers[":method"] = "CONNECT";
  request_headers[":protocol"] = "connect-udp";
  request_headers[":authority"] = "proxy.test";
  request_headers[":scheme"] = "https";
  // No ":path" header.

  tunnel_.OpenTunnel(request_headers);
  EXPECT_FALSE(tunnel_.IsTunnelOpenToTarget());
  tunnel_.OnClientStreamClose();
}

TEST_F(ConnectUdpTunnelTest, OpenTunnelWithUnacceptableTarget) {
  EXPECT_CALL(request_handler_,
              OnResponseBackendComplete(AllOf(
                  Property(&QuicBackendResponse::response_type,
                           QuicBackendResponse::REGULAR_RESPONSE),
                  Property(&QuicBackendResponse::headers,
                           UnorderedElementsAre(
                               Pair(":status", "403"),
                               Pair("Proxy-Status",
                                    HasSubstr("destination_ip_prohibited")))),
                  Property(&QuicBackendResponse::trailers, IsEmpty()))));

  quiche::HttpHeaderBlock request_headers;
  request_headers[":method"] = "CONNECT";
  request_headers[":protocol"] = "connect-udp";
  request_headers[":authority"] = "proxy.test";
  request_headers[":scheme"] = "https";
  request_headers[":path"] = "/.well-known/masque/udp/unacceptable.test/100/";

  tunnel_.OpenTunnel(request_headers);
  EXPECT_FALSE(tunnel_.IsTunnelOpenToTarget());
  tunnel_.OnClientStreamClose();
}

TEST_F(ConnectUdpTunnelTest, ReceiveFromTarget) {
  static constexpr absl::string_view kData = "\x11\x22\x33\x44\x55";

  EXPECT_CALL(*socket_, ConnectBlocking()).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*socket_, ReceiveAsync(Ge(kData.size()))).Times(2);
  EXPECT_CALL(*socket_, Disconnect()).WillOnce(InvokeWithoutArgs([this]() {
    tunnel_.ReceiveComplete(absl::CancelledError());
  }));

  EXPECT_CALL(request_handler_, OnResponseBackendComplete(_));

  EXPECT_CALL(
      stream_,
      SendHttp3Datagram(
          quiche::ConnectUdpDatagramUdpPacketPayload(kData).Serialize()))
      .WillOnce(Return(MESSAGE_STATUS_SUCCESS));

  quiche::HttpHeaderBlock request_headers;
  request_headers[":method"] = "CONNECT";
  request_headers[":protocol"] = "connect-udp";
  request_headers[":authority"] = "proxy.test";
  request_headers[":scheme"] = "https";
  request_headers[":path"] = absl::StrCat(
      "/.well-known/masque/udp/", kAcceptableTarget, "/", kAcceptablePort, "/");

  tunnel_.OpenTunnel(request_headers);

  // Simulate receiving `kData`.
  tunnel_.ReceiveComplete(MemSliceFromString(kData));

  tunnel_.OnClientStreamClose();
}

TEST_F(ConnectUdpTunnelTest, SendToTarget) {
  static constexpr absl::string_view kData = "\x11\x22\x33\x44\x55";

  EXPECT_CALL(*socket_, ConnectBlocking()).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*socket_, ReceiveAsync(Gt(0)));
  EXPECT_CALL(*socket_, SendBlocking(Matcher<std::string>(Eq(kData))))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*socket_, Disconnect()).WillOnce(InvokeWithoutArgs([this]() {
    tunnel_.ReceiveComplete(absl::CancelledError());
  }));

  EXPECT_CALL(request_handler_, OnResponseBackendComplete(_));

  quiche::HttpHeaderBlock request_headers;
  request_headers[":method"] = "CONNECT";
  request_headers[":protocol"] = "connect-udp";
  request_headers[":authority"] = "proxy.test";
  request_headers[":scheme"] = "https";
  request_headers[":path"] = absl::StrCat(
      "/.well-known/masque/udp/", kAcceptableTarget, "/", kAcceptablePort, "/");

  tunnel_.OpenTunnel(request_headers);
  tunnel_.OnHttp3Datagram(
      kStreamId, quiche::ConnectUdpDatagramUdpPacketPayload(kData).Serialize());
  tunnel_.OnClientStreamClose();
}

}  // namespace
}  // namespace quic::test

"""

```