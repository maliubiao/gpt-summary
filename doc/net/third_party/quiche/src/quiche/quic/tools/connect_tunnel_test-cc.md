Response:
Let's break down the thought process for analyzing the C++ test file.

1. **Understand the Goal:** The request asks for an analysis of a specific Chromium networking stack test file (`connect_tunnel_test.cc`). The focus is on its functionality, potential connections to JavaScript, logical inference with examples, common usage errors, and how a user might end up triggering this code.

2. **Initial File Scan (Keywords and Structure):**  Quickly scan the file for key terms and overall structure. I see:
    * `#include`: Standard C++ includes, including some `quiche` specific ones. This indicates it's part of the QUIC implementation.
    * `namespace quic::test`:  Confirms it's a test file within the QUIC library.
    * `TEST_F`:  Indicates Google Test framework usage. Each `TEST_F` defines an individual test case.
    * Class definitions like `MockRequestHandler`, `MockSocketFactory`, `MockSocket`, and `ConnectTunnelTest`. The "Mock" prefix suggests these are for creating controlled testing environments.
    * Specific function calls like `OpenTunnel`, `SendDataToDestination`, `ReceiveComplete`, and `OnClientStreamClose`. These likely represent the core functionality being tested.
    * Assertions and expectations using Google Mock (`EXPECT_CALL`).

3. **Identify the Core Class Under Test:** The `ConnectTunnelTest` class instantiates a `ConnectTunnel` object. This is the primary class being tested by this file.

4. **Infer `ConnectTunnel`'s Purpose:** Based on the test names and method calls within the tests, I can infer the `ConnectTunnel` class is responsible for handling "CONNECT" requests, which are a part of the HTTP protocol (specifically for establishing tunnels, often used with proxies). The tests involve opening a tunnel, sending and receiving data through it, and handling disconnections and errors.

5. **Analyze Individual Tests:** Go through each `TEST_F` to understand the specific scenarios being tested:
    * `OpenTunnel`: Tests the basic successful tunnel establishment.
    * `OpenTunnelToIpv4LiteralDestination`, `OpenTunnelToIpv6LiteralDestination`: Tests handling of different IP address formats in the target.
    * `OpenTunnelWithMalformedRequest`: Tests handling of invalid "CONNECT" requests (missing `:authority` header).
    * `OpenTunnelWithUnacceptableDestination`: Tests blocking connections to disallowed destinations.
    * `ReceiveFromDestination`: Tests receiving data from the tunneled connection.
    * `SendToDestination`: Tests sending data through the tunnel.
    * `DestinationDisconnect`: Tests handling a normal disconnection from the tunneled server.
    * `DestinationTcpConnectionError`: Tests handling errors when the tunneled connection fails.

6. **Consider JavaScript Relevance:**  Think about how "CONNECT" requests are used in web contexts. They are fundamental to:
    * **HTTPS Proxies:** Browsers use CONNECT to establish secure tunnels through proxies.
    * **WebSockets (over HTTP/2 or HTTP/3):** The initial handshake for WebSockets involves a "CONNECT" request (or an equivalent upgrade mechanism).
    * **General Tunneling:**  Other scenarios where a persistent bi-directional connection is needed.

7. **Construct JavaScript Examples:** Based on the identified relationships, create simple JavaScript examples that would lead to "CONNECT" requests:
    * Using `fetch` with `mode: 'cors'` and a proxy setting.
    * Establishing a WebSocket connection.

8. **Logical Inference (Input/Output):** For a core function like `OpenTunnel`, consider:
    * **Input:**  HTTP headers, particularly the `:method` and `:authority`.
    * **Output:**  Success (tunnel established, potentially sending a 200 response) or failure (terminating the stream with an error). The `IsConnectedToDestination()` method is a clear indicator of internal state.

9. **Identify Common User/Programming Errors:**  Think about what could go wrong when implementing or using this functionality:
    * Incorrectly formatted `:authority` header.
    * Trying to connect to a disallowed destination.
    * Issues with network connectivity on the underlying socket.

10. **Trace User Actions to Code:**  Imagine a user browsing the web:
    * User types a URL.
    * Browser determines it needs to use a proxy.
    * Browser sends a "CONNECT" request to the proxy.
    * The Chromium networking stack processes this request, potentially involving the `ConnectTunnel` class.
    * Similar thought process for WebSocket connections.

11. **Structure the Response:** Organize the gathered information into the requested sections: functionality, JavaScript connection, logical inference, common errors, and user actions. Use clear and concise language. Provide specific code snippets for examples.

12. **Review and Refine:** Read through the generated response to ensure accuracy, clarity, and completeness. Check for any logical inconsistencies or areas that could be explained better. For example, initially, I might just say "handles CONNECT requests," but refining it to specify *why* CONNECT requests are used (proxies, WebSockets) adds valuable context. Also, explicitly mentioning the role of mocking in testing is important for understanding the code.
这个文件 `net/third_party/quiche/src/quiche/quic/tools/connect_tunnel_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的测试文件。它专门测试 `ConnectTunnel` 类的功能。

**功能总结:**

该测试文件的主要目的是验证 `ConnectTunnel` 类的行为是否符合预期。`ConnectTunnel` 类的作用是处理 HTTP/3 或 HTTP/2 中的 `CONNECT` 方法请求，这种请求通常用于建立到目标服务器的隧道连接。  更具体地说，它测试了以下功能：

1. **成功建立隧道:**
   - 接收到合法的 `CONNECT` 请求后，能够成功连接到目标服务器。
   - 连接成功后，向客户端发送 `200` 状态码的响应。

2. **处理不同格式的目标地址:**
   - 能够处理主机名形式的目标地址 (例如 "localhost")。
   - 能够处理 IPv4 字面量形式的目标地址 (例如 "127.0.0.1")。
   - 能够处理 IPv6 字面量形式的目标地址 (例如 "[::1]")。

3. **处理错误的 `CONNECT` 请求:**
   - 当接收到格式错误的 `CONNECT` 请求 (例如缺少 `:authority` 头部) 时，能够正确地终止流并发送相应的错误码 (`QuicHttp3ErrorCode::MESSAGE_ERROR`)。

4. **拒绝连接到不允许的目标地址:**
   - 当接收到的 `CONNECT` 请求的目标地址不在允许的列表中时，能够正确地终止流并发送拒绝连接的错误码 (`QuicHttp3ErrorCode::REQUEST_REJECTED`)。

5. **在隧道中转发数据:**
   - 成功建立隧道后，能够将从客户端接收到的数据转发到目标服务器。
   - 能够将从目标服务器接收到的数据转发回客户端。

6. **处理隧道连接的断开:**
   - 当目标服务器断开连接时，能够通知客户端并关闭相应的流。

7. **处理建立隧道连接时的错误:**
   - 当建立到目标服务器的 TCP 连接失败时，能够通知客户端并发送连接错误的错误码 (`QuicHttp3ErrorCode::CONNECT_ERROR`)。

**与 Javascript 的功能关系：**

`ConnectTunnel` 的功能与 Javascript 在以下场景中存在间接关系：

1. **HTTPS 代理:**  当 Javascript 代码（例如在浏览器中运行）需要通过 HTTPS 代理访问某个网站时，浏览器会向代理服务器发送一个 `CONNECT` 请求。`ConnectTunnel` 的功能就相当于代理服务器端处理这种 `CONNECT` 请求的逻辑。

   **举例说明:**
   假设你的浏览器配置了 HTTPS 代理 `proxy.example.com:8080`。当你尝试访问 `https://www.google.com` 时，浏览器会先向代理服务器发送一个如下的 `CONNECT` 请求：

   ```
   CONNECT www.google.com:443 HTTP/1.1
   Host: proxy.example.com:8080
   ```

   代理服务器上的 `ConnectTunnel` 组件会解析这个请求，尝试连接到 `www.google.com:443`，如果连接成功，则会向浏览器返回 `HTTP/1.1 200 Connection Established`。之后，浏览器和 `www.google.com` 之间的所有流量都会通过这个隧道进行加密传输。

2. **WebSocket (通过 HTTP/2 或 HTTP/3):** 虽然 WebSocket 的握手通常使用 HTTP Upgrade 机制，但在 HTTP/2 或 HTTP/3 中，也可以使用 `CONNECT` 方法建立 WebSocket 连接。

   **举例说明:**
   一个 Javascript 应用可以使用 `WebSocket` API 连接到服务器：

   ```javascript
   const websocket = new WebSocket("wss://example.com/socket");
   ```

   在底层，浏览器可能会使用 `CONNECT` 请求来建立到 `example.com` 的连接，然后在这个连接上进行 WebSocket 握手和数据传输。虽然 Javascript 代码本身没有直接操作 `CONNECT` 请求，但浏览器的网络层可能会利用它。

**逻辑推理 (假设输入与输出):**

**场景 1: 成功建立到 "localhost:977" 的隧道**

* **假设输入 (HTTP 头部):**
  ```
  :method: CONNECT
  :authority: localhost:977
  ```

* **预期输出:**
  - 调用 `socket_factory_->CreateTcpClientSocket` 创建到 `localhost:977` 的 TCP 连接。
  - 调用 `socket_->ConnectBlocking()` 尝试连接。
  - 如果连接成功，调用 `request_handler_->OnResponseBackendComplete` 并传递一个包含 `":status": "200"` 的响应。
  - 调用 `socket_->ReceiveAsync` 开始接收来自目标服务器的数据。

**场景 2: 连接到不允许的地址 "unacceptable.test:100"**

* **假设输入 (HTTP 头部):**
  ```
  :method: CONNECT
  :authority: unacceptable.test:100
  ```

* **预期输出:**
  - 不会调用 `socket_factory_->CreateTcpClientSocket`。
  - 调用 `request_handler_->TerminateStreamWithError` 并传递一个包含 `QuicHttp3ErrorCode::REQUEST_REJECTED` 的错误信息。

**用户或编程常见的使用错误:**

1. **错误的 `:authority` 头部:** 用户或程序可能会发送格式错误的 `:authority` 头部，例如缺少端口号，或者主机名无法解析。这会导致 `ConnectTunnel` 无法确定连接目标，从而导致连接失败。

   **举例:** 发送 `:authority: localhost` 而不是 `:authority: localhost:80`。

2. **尝试连接到不允许的目标:**  如果服务器配置了允许连接的目标地址列表，用户或程序尝试连接到不在列表中的地址将会被拒绝。

   **举例:** 服务器只允许连接到 `allowed.example.com`，但用户尝试连接到 `forbidden.example.com`。

3. **网络连接问题:**  即使目标地址是合法的，底层的 TCP 连接也可能因为网络问题（例如防火墙阻止、路由不可达）而失败。`ConnectTunnel` 会处理这些连接错误并通知客户端。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中输入一个 HTTPS 网址:** 当用户在浏览器地址栏中输入 `https://example.com` 并回车时，浏览器会尝试与 `example.com` 的 443 端口建立安全连接。

2. **浏览器决定使用 HTTPS 代理 (如果已配置):**  如果用户的浏览器配置了 HTTPS 代理服务器，例如 `proxy.mycompany.com:8080`，浏览器不会直接连接到 `example.com`。

3. **浏览器发送 `CONNECT` 请求到代理服务器:** 浏览器会构造一个 `CONNECT` 请求并发送到代理服务器的地址：

   ```
   CONNECT example.com:443 HTTP/1.1
   Host: proxy.mycompany.com:8080
   ```

4. **代理服务器接收到 `CONNECT` 请求:** 代理服务器的网络栈接收到这个请求。

5. **代理服务器上的 QUIC 代码处理请求 (如果使用 HTTP/3):**  如果代理服务器和浏览器之间使用了 HTTP/3 (基于 QUIC 协议)，代理服务器的 QUIC 实现会解析这个请求。

6. **`ConnectTunnel` 类被调用:**  在代理服务器的 QUIC 实现中，负责处理 `CONNECT` 方法请求的组件，很可能就是 `ConnectTunnel` 类。它会解析请求中的 `:authority` 头部，提取目标地址 `example.com:443`。

7. **`ConnectTunnel` 尝试连接到目标服务器:**  `ConnectTunnel` 会使用 `SocketFactory` 创建一个到 `example.com` 443 端口的 TCP 连接。

8. **连接成功或失败，并返回响应:**
   - 如果连接成功，`ConnectTunnel` 会向浏览器发送 `HTTP/1.1 200 Connection Established` 响应，表示隧道建立成功。
   - 如果连接失败（例如目标服务器不可达），`ConnectTunnel` 会向浏览器发送一个错误响应（例如 `502 Bad Gateway`）并关闭连接。

9. **浏览器通过隧道与目标服务器通信:** 一旦隧道建立，浏览器就可以通过这个隧道与 `example.com` 进行加密通信，就像直接连接一样。

因此，当你在 Chromium 的网络栈中调试与 HTTPS 代理相关的 QUIC 连接问题时，你可能会需要查看 `ConnectTunnel` 类的代码以及它的测试文件，以了解代理服务器是如何处理 `CONNECT` 请求的。这个测试文件 `connect_tunnel_test.cc` 提供了一种验证 `ConnectTunnel` 功能是否正确的方式。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/tools/connect_tunnel_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/connect_tunnel.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/connecting_client_socket.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/socket_factory.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/platform/api/quic_test_loopback.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/tools/quic_backend_response.h"
#include "quiche/quic/tools/quic_simple_server_backend.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_mem_slice.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace quic::test {
namespace {

using ::testing::_;
using ::testing::AllOf;
using ::testing::AnyOf;
using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::Ge;
using ::testing::Gt;
using ::testing::InvokeWithoutArgs;
using ::testing::IsEmpty;
using ::testing::Matcher;
using ::testing::NiceMock;
using ::testing::Pair;
using ::testing::Property;
using ::testing::Return;
using ::testing::StrictMock;

class MockRequestHandler : public QuicSimpleServerBackend::RequestHandler {
 public:
  QuicConnectionId connection_id() const override {
    return TestConnectionId(41212);
  }
  QuicStreamId stream_id() const override { return 100; }
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
              (const quic::QuicSocketAddress& peer_address,
               QuicByteCount receive_buffer_size,
               QuicByteCount send_buffer_size,
               ConnectingClientSocket::AsyncVisitor* async_visitor),
              (override));
  MOCK_METHOD(std::unique_ptr<ConnectingClientSocket>,
              CreateConnectingUdpClientSocket,
              (const quic::QuicSocketAddress& peer_address,
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

class ConnectTunnelTest : public quiche::test::QuicheTest {
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
            CreateTcpClientSocket(
                AnyOf(QuicSocketAddress(TestLoopback4(), kAcceptablePort),
                      QuicSocketAddress(TestLoopback6(), kAcceptablePort)),
                _, _, &tunnel_))
        .WillByDefault(Return(ByMove(std::move(socket))));
  }

 protected:
  static constexpr absl::string_view kAcceptableDestination = "localhost";
  static constexpr uint16_t kAcceptablePort = 977;

  StrictMock<MockRequestHandler> request_handler_;
  NiceMock<MockSocketFactory> socket_factory_;
  StrictMock<MockSocket>* socket_;

  ConnectTunnel tunnel_{
      &request_handler_,
      &socket_factory_,
      /*acceptable_destinations=*/
      {{std::string(kAcceptableDestination), kAcceptablePort},
       {TestLoopback4().ToString(), kAcceptablePort},
       {absl::StrCat("[", TestLoopback6().ToString(), "]"), kAcceptablePort}}};
};

TEST_F(ConnectTunnelTest, OpenTunnel) {
  EXPECT_CALL(*socket_, ConnectBlocking()).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*socket_, ReceiveAsync(Gt(0)));
  EXPECT_CALL(*socket_, Disconnect()).WillOnce(InvokeWithoutArgs([this]() {
    tunnel_.ReceiveComplete(absl::CancelledError());
  }));

  quiche::HttpHeaderBlock expected_response_headers;
  expected_response_headers[":status"] = "200";
  QuicBackendResponse expected_response;
  expected_response.set_headers(std::move(expected_response_headers));
  expected_response.set_response_type(QuicBackendResponse::INCOMPLETE_RESPONSE);
  EXPECT_CALL(request_handler_,
              OnResponseBackendComplete(
                  AllOf(Property(&QuicBackendResponse::response_type,
                                 QuicBackendResponse::INCOMPLETE_RESPONSE),
                        Property(&QuicBackendResponse::headers,
                                 ElementsAre(Pair(":status", "200"))),
                        Property(&QuicBackendResponse::trailers, IsEmpty()),
                        Property(&QuicBackendResponse::body, IsEmpty()))));

  quiche::HttpHeaderBlock request_headers;
  request_headers[":method"] = "CONNECT";
  request_headers[":authority"] =
      absl::StrCat(kAcceptableDestination, ":", kAcceptablePort);

  tunnel_.OpenTunnel(request_headers);
  EXPECT_TRUE(tunnel_.IsConnectedToDestination());
  tunnel_.OnClientStreamClose();
  EXPECT_FALSE(tunnel_.IsConnectedToDestination());
}

TEST_F(ConnectTunnelTest, OpenTunnelToIpv4LiteralDestination) {
  EXPECT_CALL(*socket_, ConnectBlocking()).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*socket_, ReceiveAsync(Gt(0)));
  EXPECT_CALL(*socket_, Disconnect()).WillOnce(InvokeWithoutArgs([this]() {
    tunnel_.ReceiveComplete(absl::CancelledError());
  }));

  quiche::HttpHeaderBlock expected_response_headers;
  expected_response_headers[":status"] = "200";
  QuicBackendResponse expected_response;
  expected_response.set_headers(std::move(expected_response_headers));
  expected_response.set_response_type(QuicBackendResponse::INCOMPLETE_RESPONSE);
  EXPECT_CALL(request_handler_,
              OnResponseBackendComplete(
                  AllOf(Property(&QuicBackendResponse::response_type,
                                 QuicBackendResponse::INCOMPLETE_RESPONSE),
                        Property(&QuicBackendResponse::headers,
                                 ElementsAre(Pair(":status", "200"))),
                        Property(&QuicBackendResponse::trailers, IsEmpty()),
                        Property(&QuicBackendResponse::body, IsEmpty()))));

  quiche::HttpHeaderBlock request_headers;
  request_headers[":method"] = "CONNECT";
  request_headers[":authority"] =
      absl::StrCat(TestLoopback4().ToString(), ":", kAcceptablePort);

  tunnel_.OpenTunnel(request_headers);
  EXPECT_TRUE(tunnel_.IsConnectedToDestination());
  tunnel_.OnClientStreamClose();
  EXPECT_FALSE(tunnel_.IsConnectedToDestination());
}

TEST_F(ConnectTunnelTest, OpenTunnelToIpv6LiteralDestination) {
  EXPECT_CALL(*socket_, ConnectBlocking()).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*socket_, ReceiveAsync(Gt(0)));
  EXPECT_CALL(*socket_, Disconnect()).WillOnce(InvokeWithoutArgs([this]() {
    tunnel_.ReceiveComplete(absl::CancelledError());
  }));

  quiche::HttpHeaderBlock expected_response_headers;
  expected_response_headers[":status"] = "200";
  QuicBackendResponse expected_response;
  expected_response.set_headers(std::move(expected_response_headers));
  expected_response.set_response_type(QuicBackendResponse::INCOMPLETE_RESPONSE);
  EXPECT_CALL(request_handler_,
              OnResponseBackendComplete(
                  AllOf(Property(&QuicBackendResponse::response_type,
                                 QuicBackendResponse::INCOMPLETE_RESPONSE),
                        Property(&QuicBackendResponse::headers,
                                 ElementsAre(Pair(":status", "200"))),
                        Property(&QuicBackendResponse::trailers, IsEmpty()),
                        Property(&QuicBackendResponse::body, IsEmpty()))));

  quiche::HttpHeaderBlock request_headers;
  request_headers[":method"] = "CONNECT";
  request_headers[":authority"] =
      absl::StrCat("[", TestLoopback6().ToString(), "]:", kAcceptablePort);

  tunnel_.OpenTunnel(request_headers);
  EXPECT_TRUE(tunnel_.IsConnectedToDestination());
  tunnel_.OnClientStreamClose();
  EXPECT_FALSE(tunnel_.IsConnectedToDestination());
}

TEST_F(ConnectTunnelTest, OpenTunnelWithMalformedRequest) {
  EXPECT_CALL(request_handler_,
              TerminateStreamWithError(Property(
                  &QuicResetStreamError::ietf_application_code,
                  static_cast<uint64_t>(QuicHttp3ErrorCode::MESSAGE_ERROR))));

  quiche::HttpHeaderBlock request_headers;
  request_headers[":method"] = "CONNECT";
  // No ":authority" header.

  tunnel_.OpenTunnel(request_headers);
  EXPECT_FALSE(tunnel_.IsConnectedToDestination());
  tunnel_.OnClientStreamClose();
}

TEST_F(ConnectTunnelTest, OpenTunnelWithUnacceptableDestination) {
  EXPECT_CALL(
      request_handler_,
      TerminateStreamWithError(Property(
          &QuicResetStreamError::ietf_application_code,
          static_cast<uint64_t>(QuicHttp3ErrorCode::REQUEST_REJECTED))));

  quiche::HttpHeaderBlock request_headers;
  request_headers[":method"] = "CONNECT";
  request_headers[":authority"] = "unacceptable.test:100";

  tunnel_.OpenTunnel(request_headers);
  EXPECT_FALSE(tunnel_.IsConnectedToDestination());
  tunnel_.OnClientStreamClose();
}

TEST_F(ConnectTunnelTest, ReceiveFromDestination) {
  static constexpr absl::string_view kData = "\x11\x22\x33\x44\x55";

  EXPECT_CALL(*socket_, ConnectBlocking()).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*socket_, ReceiveAsync(Ge(kData.size()))).Times(2);
  EXPECT_CALL(*socket_, Disconnect()).WillOnce(InvokeWithoutArgs([this]() {
    tunnel_.ReceiveComplete(absl::CancelledError());
  }));

  EXPECT_CALL(request_handler_, OnResponseBackendComplete(_));

  EXPECT_CALL(request_handler_, SendStreamData(kData, /*close_stream=*/false));

  quiche::HttpHeaderBlock request_headers;
  request_headers[":method"] = "CONNECT";
  request_headers[":authority"] =
      absl::StrCat(kAcceptableDestination, ":", kAcceptablePort);

  tunnel_.OpenTunnel(request_headers);

  // Simulate receiving `kData`.
  tunnel_.ReceiveComplete(MemSliceFromString(kData));

  tunnel_.OnClientStreamClose();
}

TEST_F(ConnectTunnelTest, SendToDestination) {
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
  request_headers[":authority"] =
      absl::StrCat(kAcceptableDestination, ":", kAcceptablePort);

  tunnel_.OpenTunnel(request_headers);
  tunnel_.SendDataToDestination(kData);
  tunnel_.OnClientStreamClose();
}

TEST_F(ConnectTunnelTest, DestinationDisconnect) {
  EXPECT_CALL(*socket_, ConnectBlocking()).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*socket_, ReceiveAsync(Gt(0)));
  EXPECT_CALL(*socket_, Disconnect());

  EXPECT_CALL(request_handler_, OnResponseBackendComplete(_));
  EXPECT_CALL(request_handler_, SendStreamData("", /*close_stream=*/true));

  quiche::HttpHeaderBlock request_headers;
  request_headers[":method"] = "CONNECT";
  request_headers[":authority"] =
      absl::StrCat(kAcceptableDestination, ":", kAcceptablePort);

  tunnel_.OpenTunnel(request_headers);

  // Simulate receiving empty data.
  tunnel_.ReceiveComplete(quiche::QuicheMemSlice());

  EXPECT_FALSE(tunnel_.IsConnectedToDestination());

  tunnel_.OnClientStreamClose();
}

TEST_F(ConnectTunnelTest, DestinationTcpConnectionError) {
  EXPECT_CALL(*socket_, ConnectBlocking()).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*socket_, ReceiveAsync(Gt(0)));
  EXPECT_CALL(*socket_, Disconnect());

  EXPECT_CALL(request_handler_, OnResponseBackendComplete(_));
  EXPECT_CALL(request_handler_,
              TerminateStreamWithError(Property(
                  &QuicResetStreamError::ietf_application_code,
                  static_cast<uint64_t>(QuicHttp3ErrorCode::CONNECT_ERROR))));

  quiche::HttpHeaderBlock request_headers;
  request_headers[":method"] = "CONNECT";
  request_headers[":authority"] =
      absl::StrCat(kAcceptableDestination, ":", kAcceptablePort);

  tunnel_.OpenTunnel(request_headers);

  // Simulate receving error.
  tunnel_.ReceiveComplete(absl::UnknownError("error"));

  tunnel_.OnClientStreamClose();
}

}  // namespace
}  // namespace quic::test
```