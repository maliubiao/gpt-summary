Response:
Let's break down the thought process to analyze this C++ code for its functionality and potential connections to JavaScript.

1. **Initial Skim and High-Level Understanding:**  The first step is to quickly read through the code, paying attention to the includes and class names. I see things like "quic," "session," "stream," "datagram," "web_transport," "test," and "simulator."  This immediately tells me it's related to the QUIC protocol, specifically focusing on testing its "generic session" implementation, and involves WebTransport. The `#include` directives confirm the dependencies on various QUIC components and testing utilities.

2. **Identify the Core Class Under Test:** The filename `quic_generic_session_test.cc` and the initial comment block clearly indicate that the central focus is testing `QuicGenericSession`.

3. **Understand the Test Structure:**  I notice the `namespace quic::test` and the use of `TEST_F` from Google Test, signifying this is a unit/integration test file. The `QuicGenericSessionTest` class acts as the test fixture, setting up the environment for the individual test cases.

4. **Analyze the Test Fixture (`QuicGenericSessionTest`):**
    * **`CreateDefaultEndpoints`:**  This function creates client and server endpoints. The `ServerType` enum hints at different server behaviors (discard vs. echo). This is crucial for understanding the test scenarios.
    * **`WireUpEndpoints`:** This likely establishes the communication channels between the client and server within the simulator.
    * **`RunHandshake`:**  This simulates the QUIC handshake process. The `EXPECT_TRUE(client_->session_ready())` confirms a successful connection.
    * **`client_config_`, `server_config_`, `test_harness_`, `client_`, `server_`:** These are member variables holding configuration, the test simulator, and the client/server endpoint objects.

5. **Deconstruct Individual Test Cases:** Now, I go through each `TEST_F` function to understand its purpose:
    * **`SuccessfulHandshake`:** Basic check for a successful QUIC connection.
    * **`SendOutgoingStreams`:** Tests opening and closing unidirectional streams from the client to the server.
    * **`EchoBidirectionalStreams`:** Verifies that bidirectional streams can send data back and forth.
    * **`EchoUnidirectionalStreams`:** Tests unidirectional stream communication, including handling FIN.
    * **`EchoStreamsUsingPeekApi`:** Focuses on the `PeekNextReadableRegion` API for reading stream data without consuming it.
    * **`EchoDatagram`:** Checks the basic functionality of sending and receiving datagrams.
    * **`EchoALotOfDatagrams`:** Tests datagram handling under potential congestion by sending a large number of datagrams.
    * **`OutgoingStreamFlowControlBlocked`:**  Examines how stream limits affect the ability to create new streams.
    * **`ExpireDatagrams`:**  Tests the mechanism for datagram expiration.
    * **`LoseDatagrams`:** Simulates packet loss and observes its impact on datagram delivery.
    * **`WriteWhenBufferFull`:** Tests the behavior of writing to streams when the send buffer is full.

6. **Identify Key Classes and their Roles:** Based on the test cases, I can identify the core components being tested and their roles:
    * **`QuicGenericClientSession` and `QuicGenericServerSession`:**  The main classes under test, managing the QUIC connection and WebTransport functionality.
    * **`webtransport::Stream`:** Represents a WebTransport stream for sending and receiving data.
    * **`QuicDatagramQueue`:** Manages the sending and receiving of unreliable datagrams.
    * **`MockWebTransportSessionVisitor`:** A mock object used to observe and verify events on the WebTransport session.
    * **`simulator::Simulator` and `simulator::TestHarness`:**  Provide the testing environment, allowing simulation of network behavior (latency, loss, etc.).

7. **Look for JavaScript Connections:** This is where the "think like a developer" part comes in. WebTransport is explicitly mentioned. I know WebTransport is a browser technology allowing low-latency bidirectional communication, often used as an alternative to WebSockets. Therefore, the connection is direct. The C++ code tests the underlying QUIC implementation of WebTransport that a browser's JavaScript WebTransport API would rely on.

8. **Formulate JavaScript Examples:**  Based on the understanding of WebTransport and the C++ test cases, I can create corresponding JavaScript examples that illustrate the same concepts (opening streams, sending data, receiving data, handling datagrams).

9. **Consider Logic and Input/Output:**  For test cases that involve specific behaviors (like flow control or datagram expiration), I think about the inputs and expected outputs. For example, in `OutgoingStreamFlowControlBlocked`, the input is attempting to open more streams than allowed by the server's configuration. The expected output is that the client is initially blocked and then unblocked when the server acknowledges the closed streams.

10. **Identify Potential User Errors:**  Based on common networking pitfalls and the tested scenarios, I can deduce potential user errors. For instance, ignoring `CanWrite()` before writing to a stream can lead to data loss. Not handling incoming data or connection errors are other typical mistakes.

11. **Trace User Actions to the Code:**  To determine how a user might reach this code, I think about the user initiating a network connection in a browser (or a Node.js application using a WebTransport library). The browser then handles the underlying QUIC and WebTransport negotiation, eventually leading to the execution of the C++ QUIC stack within the browser's network process. Debugging would involve network inspection tools and potentially browser-specific debugging features.

12. **Refine and Organize the Explanation:**  Finally, I structure the information in a clear and organized manner, covering the requested aspects: functionality, JavaScript connections, logic/I/O, user errors, and debugging. Using headings and bullet points makes the explanation easier to read and understand.
好的，让我们来分析一下这个 C++ 文件 `net/third_party/quiche/src/quiche/quic/core/quic_generic_session_test.cc` 的功能。

**文件功能：**

这个文件是一个集成测试，用于验证 `QuicGenericSession` 客户端和服务器会话之间的交互。`QuicGenericSession` 是 QUIC 协议栈中一个通用的会话实现，它支持 WebTransport 协议。  这个测试文件主要覆盖以下几个方面的功能：

1. **基本的 QUIC 连接建立和握手：** 测试客户端和服务器之间能否成功建立 QUIC 连接并完成握手过程。
2. **WebTransport 流的创建和数据传输：**
   - 测试客户端可以创建单向和双向的 WebTransport 流。
   - 测试通过这些流进行数据发送和接收的功能。
   - 测试流的正常关闭（发送 FIN）。
3. **WebTransport Datagram 的发送和接收：** 测试客户端和服务器之间发送和接收不可靠的 WebTransport 数据报的功能。
4. **流量控制：** 测试 WebTransport 流的流量控制机制，例如当达到最大允许的单向流数量时，客户端是否能正确处理。
5. **数据报的过期和丢失：** 模拟网络丢包和数据报在队列中过期的情况，验证 `QuicGenericSession` 的处理行为。
6. **`Peek` API 的使用：** 测试使用 `PeekNextReadableRegion` API 在不消耗数据的情况下查看流中的数据。
7. **写入缓冲区满的情况：** 测试当发送缓冲区满时，写入流的行为以及如何处理。

**与 JavaScript 的关系：**

这个 C++ 文件测试的是 Chromium 网络栈中 QUIC 和 WebTransport 的底层实现。  WebTransport 是一种浏览器 API，允许 JavaScript 代码通过 HTTP/3 连接建立低延迟的双向通信。  因此，这个 C++ 测试直接关系到浏览器中 JavaScript WebTransport API 的功能。

**举例说明：**

假设你在 JavaScript 中使用了 WebTransport API：

```javascript
const transport = new WebTransport("https://example.com:443");

transport.ready.then(() => {
  console.log("连接已建立");

  // 创建一个单向流
  transport.createUnidirectionalStream().then(stream => {
    const writer = stream.getWriter();
    writer.write(new TextEncoder().encode("Hello from JavaScript!"));
    writer.close();
  });

  // 监听接收到的数据报
  transport.datagrams.readable.getReader().read().then(({ value, done }) => {
    if (!done) {
      const message = new TextDecoder().decode(value);
      console.log("接收到数据报:", message);
    }
  });

  // 监听接收到的单向流
  transport.incomingUnidirectionalStreams.getReader().read().then(({ value, done }) => {
    if (!done) {
      const reader = value.getReader();
      reader.read().then(({ value, done }) => {
        if (!done) {
          const message = new TextDecoder().decode(value);
          console.log("接收到单向流数据:", message);
        }
      });
    }
  });
});

transport.closed.then(() => {
  console.log("连接已关闭");
});
```

在这个 JavaScript 示例中，当你调用 `transport.createUnidirectionalStream()` 或者发送数据报时，浏览器底层的网络栈会使用 QUIC 和 WebTransport 协议进行通信。 `quic_generic_session_test.cc` 中测试的正是这部分底层 C++ 代码的功能，确保这些操作在各种场景下都能正确执行。 例如：

* **`SendOutgoingStreams` 测试** 验证了 JavaScript 中 `transport.createUnidirectionalStream()` 和 `writer.write()` 的基本发送功能。
* **`EchoDatagram` 测试** 验证了 JavaScript 中通过 `transport.send(data)` 发送数据报，并通过 `transport.datagrams.readable` 接收数据报的功能。
* **`SuccessfulHandshake` 测试**  验证了 JavaScript 中 `new WebTransport("...")` 连接建立的基础。

**逻辑推理，假设输入与输出：**

**测试用例：`EchoBidirectionalStreams`**

* **假设输入 (客户端操作):**
    1. 客户端成功建立 QUIC 连接。
    2. 客户端调用 `client_->session()->OpenOutgoingBidirectionalStream()` 创建一个双向流。
    3. 客户端通过该流写入字符串 "Hello!".
* **预期输出 (服务器和客户端行为):**
    1. 服务器接收到客户端发送的数据 "Hello!".
    2. 服务器的 `EchoWebTransportSessionVisitor` 将接收到的数据写回相同的流。
    3. 客户端在流上能够读取到服务器回显的数据 "Hello!".
    4. 客户端发送流结束信号 (FIN)。
    5. 服务器接收到 FIN 并关闭相应的流。

**测试用例：`ExpireDatagrams`**

* **假设输入 (客户端操作):**
    1. 客户端成功建立 QUIC 连接。
    2. 客户端设置数据报最大在队列时间为一个很短的值（例如，0.2 倍 RTT）。
    3. 客户端连续发送 1000 个数据报。
* **预期输出 (客户端行为):**
    1. 由于数据报过期时间很短，并且网络传输需要时间，客户端发送的大部分数据报在发送队列中就会过期。
    2. 客户端接收到的服务器回显的数据报数量会远小于 1000。
    3. 客户端的 `GetDatagramStats().expired_outgoing` 计数器会记录过期的数据报数量，并且 `接收到的数量 + 过期的数量` 应该接近 1000。

**用户或编程常见的使用错误：**

1. **未处理 `transport.ready` Promise：**  JavaScript 代码可能在 WebTransport 连接建立完成之前就尝试创建流或发送数据报，导致错误。

   ```javascript
   const transport = new WebTransport("https://example.com:443");
   transport.createUnidirectionalStream(); // 可能会在连接建立前执行
   ```

2. **流未关闭或读取完成导致资源泄露：**  如果 JavaScript 代码创建了 WebTransport 流但没有正确关闭写入端 (`writer.close()`) 或读取完成接收端的数据，可能会导致资源占用，甚至影响性能。

3. **数据报过大导致发送失败：**  WebTransport 数据报有大小限制。如果 JavaScript 代码尝试发送过大的数据报，可能会失败。开发者需要确保数据报大小在允许的范围内。

4. **错误处理不足：**  WebTransport 的各个操作都可能失败（例如，连接失败、流创建失败）。JavaScript 代码需要正确处理这些错误，例如监听 `transport.closed` 和 `transport.error` 事件，以及处理流的读取错误。

5. **在 `OnDatagramReceived` 中进行耗时操作：**  在 C++ 的测试中，`MockWebTransportSessionVisitor::OnDatagramReceived` 被调用来处理接收到的数据报。如果在 JavaScript 的 `transport.datagrams.readable` 处理程序中执行耗时操作，可能会阻塞事件循环。

**用户操作如何一步步的到达这里，作为调试线索：**

假设用户在浏览器中访问了一个使用了 WebTransport 的网页：

1. **用户在浏览器地址栏输入 URL 并访问该网页。**
2. **网页加载，其中包含使用 WebTransport API 的 JavaScript 代码。**
3. **JavaScript 代码创建 `WebTransport` 对象，例如 `new WebTransport("https://example.com:443")`。**  这一步会触发浏览器底层网络栈开始与服务器建立 HTTP/3 连接，并协商 WebTransport 协议。
4. **浏览器底层网络栈会使用 QUIC 协议进行握手。** 这部分逻辑对应于 `quic_generic_session_test.cc` 中的 `RunHandshake()` 和 `SuccessfulHandshake` 测试。
5. **JavaScript 代码在连接建立完成后，可能会调用 `transport.createUnidirectionalStream()` 或 `transport.send(data)` 发送数据。**  这些操作会调用到底层的 `QuicGenericSession` 的相关方法，例如打开新的 QUIC 流或者发送 QUIC 数据包。 这部分逻辑对应于 `SendOutgoingStreams` 和 `EchoDatagram` 等测试。
6. **服务器响应后，浏览器底层网络栈接收到数据或数据报，并触发 JavaScript 中相应的事件处理程序，例如 `transport.datagrams.readable` 或 `transport.incomingUnidirectionalStreams`。**

**调试线索:**

如果在使用 WebTransport 的网页中出现问题，例如连接失败、数据发送/接收异常，可以按照以下步骤进行调试，可能会涉及到 `quic_generic_session_test.cc` 中测试的代码：

1. **浏览器开发者工具 -> 网络 (Network) 面板：** 查看 HTTP/3 连接的状态，QUIC 连接的详细信息，以及 WebTransport 流和数据报的发送和接收情况。检查是否有连接错误、协议协商失败等问题。
2. **浏览器开发者工具 -> 控制台 (Console)：** 查看 JavaScript 代码中是否有错误信息，例如 WebTransport API 的异常。
3. **`chrome://webrtc-internals/`：** 这个 Chrome 特有的页面可以提供更底层的 WebRTC 和 WebTransport 连接信息，包括 QUIC 连接的细节，例如拥塞控制、丢包率等。这有助于诊断网络层面的问题。
4. **抓包工具 (如 Wireshark)：** 可以抓取网络数据包，分析 QUIC 握手过程、数据包的结构和内容，以排查更底层的协议问题。
5. **Chromium 源代码调试：**  如果怀疑是 Chromium 底层网络栈的问题，可以下载 Chromium 源代码，并设置断点在 `net/third_party/quiche/src/quiche/quic/core/` 目录下相关的 C++ 文件中，例如 `quic_generic_session.cc`，来跟踪代码执行流程，查看变量值，定位问题所在。  `quic_generic_session_test.cc` 中模拟的各种场景可以作为参考，编写类似的测试用例来复现问题。

总而言之，`quic_generic_session_test.cc` 是 Chromium 网络栈中 WebTransport 功能稳定性和正确性的重要保障，它测试了底层 QUIC 会话的关键交互和行为，直接影响着 JavaScript WebTransport API 的使用体验。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_generic_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// An integration test that covers interactions between QuicGenericSession
// client and server sessions.

#include "quiche/quic/core/quic_generic_session.h"

#include <cstddef>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/quic_compressed_certs_cache.h"
#include "quiche/quic/core/crypto/quic_crypto_client_config.h"
#include "quiche/quic/core/crypto/quic_crypto_server_config.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_datagram_queue.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_stream.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/web_transport_interface.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/quic_session_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/test_tools/simulator/simulator.h"
#include "quiche/quic/test_tools/simulator/test_harness.h"
#include "quiche/quic/test_tools/web_transport_test_tools.h"
#include "quiche/quic/tools/web_transport_test_visitors.h"
#include "quiche/common/quiche_stream.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "quiche/web_transport/web_transport.h"

namespace quic::test {
namespace {

enum ServerType { kDiscardServer, kEchoServer };

using quiche::test::StatusIs;
using simulator::Simulator;
using testing::_;
using testing::Assign;
using testing::AtMost;
using testing::Eq;

class CountingDatagramObserver : public QuicDatagramQueue::Observer {
 public:
  CountingDatagramObserver(int& total) : total_(total) {}
  void OnDatagramProcessed(std::optional<MessageStatus>) { ++total_; }

 private:
  int& total_;
};

class ClientEndpoint : public simulator::QuicEndpointWithConnection {
 public:
  ClientEndpoint(Simulator* simulator, const std::string& name,
                 const std::string& peer_name, const QuicConfig& config)
      : QuicEndpointWithConnection(simulator, name, peer_name,
                                   Perspective::IS_CLIENT,
                                   GetQuicVersionsForGenericSession()),
        crypto_config_(crypto_test_utils::ProofVerifierForTesting()),
        session_(connection_.get(), false, nullptr, config, "test.example.com",
                 443, "example_alpn", &visitor_, /*visitor_owned=*/false,
                 std::make_unique<CountingDatagramObserver>(
                     total_datagrams_processed_),
                 &crypto_config_) {
    session_.Initialize();
    session_.connection()->sent_packet_manager().SetSendAlgorithm(
        CongestionControlType::kBBRv2);
    EXPECT_CALL(visitor_, OnSessionReady())
        .Times(AtMost(1))
        .WillOnce(Assign(&session_ready_, true));
  }

  QuicGenericClientSession* session() { return &session_; }
  MockWebTransportSessionVisitor* visitor() { return &visitor_; }

  bool session_ready() const { return session_ready_; }
  int total_datagrams_processed() const { return total_datagrams_processed_; }

 private:
  QuicCryptoClientConfig crypto_config_;
  MockWebTransportSessionVisitor visitor_;
  QuicGenericClientSession session_;
  bool session_ready_ = false;
  int total_datagrams_processed_ = 0;
};

class ServerEndpoint : public simulator::QuicEndpointWithConnection {
 public:
  ServerEndpoint(Simulator* simulator, const std::string& name,
                 const std::string& peer_name, const QuicConfig& config,
                 ServerType type)
      : QuicEndpointWithConnection(simulator, name, peer_name,
                                   Perspective::IS_SERVER,
                                   GetQuicVersionsForGenericSession()),
        crypto_config_(QuicCryptoServerConfig::TESTING,
                       QuicRandom::GetInstance(),
                       crypto_test_utils::ProofSourceForTesting(),
                       KeyExchangeSource::Default()),
        compressed_certs_cache_(
            QuicCompressedCertsCache::kQuicCompressedCertsCacheSize),
        session_(connection_.get(), false, nullptr, config, "example_alpn",
                 type == kEchoServer
                     ? static_cast<webtransport::SessionVisitor*>(
                           new EchoWebTransportSessionVisitor(
                               &session_,
                               /*open_server_initiated_echo_stream=*/false))
                     : static_cast<webtransport::SessionVisitor*>(
                           new DiscardWebTransportSessionVisitor(&session_)),
                 /*owns_visitor=*/true,
                 /*datagram_observer=*/nullptr, &crypto_config_,
                 &compressed_certs_cache_) {
    session_.Initialize();
    session_.connection()->sent_packet_manager().SetSendAlgorithm(
        CongestionControlType::kBBRv2);
  }

  QuicGenericServerSession* session() { return &session_; }

 private:
  QuicCryptoServerConfig crypto_config_;
  QuicCompressedCertsCache compressed_certs_cache_;
  QuicGenericServerSession session_;
};

class QuicGenericSessionTest : public QuicTest {
 public:
  void CreateDefaultEndpoints(ServerType server_type) {
    client_ = std::make_unique<ClientEndpoint>(
        &test_harness_.simulator(), "Client", "Server", client_config_);
    server_ =
        std::make_unique<ServerEndpoint>(&test_harness_.simulator(), "Server",
                                         "Client", server_config_, server_type);
    test_harness_.set_client(client_.get());
    test_harness_.set_server(server_.get());
  }

  void WireUpEndpoints() { test_harness_.WireUpEndpoints(); }

  void RunHandshake() {
    client_->session()->CryptoConnect();
    bool result = test_harness_.RunUntilWithDefaultTimeout([this]() {
      return client_->session_ready() ||
             client_->session()->error() != QUIC_NO_ERROR;
    });
    EXPECT_TRUE(result);
  }

 protected:
  QuicConfig client_config_ = DefaultQuicConfig();
  QuicConfig server_config_ = DefaultQuicConfig();

  simulator::TestHarness test_harness_;

  std::unique_ptr<ClientEndpoint> client_;
  std::unique_ptr<ServerEndpoint> server_;
};

TEST_F(QuicGenericSessionTest, SuccessfulHandshake) {
  CreateDefaultEndpoints(kDiscardServer);
  WireUpEndpoints();
  RunHandshake();
  EXPECT_TRUE(client_->session_ready());
}

TEST_F(QuicGenericSessionTest, SendOutgoingStreams) {
  CreateDefaultEndpoints(kDiscardServer);
  WireUpEndpoints();
  RunHandshake();

  std::vector<webtransport::Stream*> streams;
  for (int i = 0; i < 10; i++) {
    webtransport::Stream* stream =
        client_->session()->OpenOutgoingUnidirectionalStream();
    ASSERT_TRUE(stream->Write("test"));
    streams.push_back(stream);
  }
  ASSERT_TRUE(test_harness_.RunUntilWithDefaultTimeout([this]() {
    return QuicSessionPeer::GetNumOpenDynamicStreams(server_->session()) == 10;
  }));

  for (webtransport::Stream* stream : streams) {
    ASSERT_TRUE(stream->SendFin());
  }
  ASSERT_TRUE(test_harness_.RunUntilWithDefaultTimeout([this]() {
    return QuicSessionPeer::GetNumOpenDynamicStreams(server_->session()) == 0;
  }));
}

TEST_F(QuicGenericSessionTest, EchoBidirectionalStreams) {
  CreateDefaultEndpoints(kEchoServer);
  WireUpEndpoints();
  RunHandshake();

  webtransport::Stream* stream =
      client_->session()->OpenOutgoingBidirectionalStream();
  EXPECT_TRUE(stream->Write("Hello!"));

  ASSERT_TRUE(test_harness_.RunUntilWithDefaultTimeout(
      [stream]() { return stream->ReadableBytes() == strlen("Hello!"); }));
  std::string received;
  WebTransportStream::ReadResult result = stream->Read(&received);
  EXPECT_EQ(result.bytes_read, strlen("Hello!"));
  EXPECT_FALSE(result.fin);
  EXPECT_EQ(received, "Hello!");

  EXPECT_TRUE(stream->SendFin());
  ASSERT_TRUE(test_harness_.RunUntilWithDefaultTimeout([this]() {
    return QuicSessionPeer::GetNumOpenDynamicStreams(server_->session()) == 0;
  }));
}

TEST_F(QuicGenericSessionTest, EchoUnidirectionalStreams) {
  CreateDefaultEndpoints(kEchoServer);
  WireUpEndpoints();
  RunHandshake();

  // Send two streams, but only send FIN on the second one.
  webtransport::Stream* stream1 =
      client_->session()->OpenOutgoingUnidirectionalStream();
  EXPECT_TRUE(stream1->Write("Stream One"));
  webtransport::Stream* stream2 =
      client_->session()->OpenOutgoingUnidirectionalStream();
  EXPECT_TRUE(stream2->Write("Stream Two"));
  EXPECT_TRUE(stream2->SendFin());

  // Wait until a stream is received.
  bool stream_received = false;
  EXPECT_CALL(*client_->visitor(), OnIncomingUnidirectionalStreamAvailable())
      .Times(2)
      .WillRepeatedly(Assign(&stream_received, true));
  ASSERT_TRUE(test_harness_.RunUntilWithDefaultTimeout(
      [&stream_received]() { return stream_received; }));

  // Receive a reply stream and expect it to be the second one.
  webtransport::Stream* reply =
      client_->session()->AcceptIncomingUnidirectionalStream();
  ASSERT_TRUE(reply != nullptr);
  std::string buffer;
  WebTransportStream::ReadResult result = reply->Read(&buffer);
  EXPECT_GT(result.bytes_read, 0u);
  EXPECT_TRUE(result.fin);
  EXPECT_EQ(buffer, "Stream Two");

  // Reset reply-related variables.
  stream_received = false;
  buffer = "";

  // Send FIN on the first stream, and expect to receive it back.
  EXPECT_TRUE(stream1->SendFin());
  ASSERT_TRUE(test_harness_.RunUntilWithDefaultTimeout(
      [&stream_received]() { return stream_received; }));
  reply = client_->session()->AcceptIncomingUnidirectionalStream();
  ASSERT_TRUE(reply != nullptr);
  result = reply->Read(&buffer);
  EXPECT_GT(result.bytes_read, 0u);
  EXPECT_TRUE(result.fin);
  EXPECT_EQ(buffer, "Stream One");
}

TEST_F(QuicGenericSessionTest, EchoStreamsUsingPeekApi) {
  CreateDefaultEndpoints(kEchoServer);
  WireUpEndpoints();
  RunHandshake();

  // Send two streams, a bidirectional and a unidirectional one, but only send
  // FIN on the second one.
  webtransport::Stream* stream1 =
      client_->session()->OpenOutgoingBidirectionalStream();
  EXPECT_TRUE(stream1->Write("Stream One"));
  webtransport::Stream* stream2 =
      client_->session()->OpenOutgoingUnidirectionalStream();
  EXPECT_TRUE(stream2->Write("Stream Two"));
  EXPECT_TRUE(stream2->SendFin());

  // Wait until the unidirectional stream is received back.
  bool stream_received_unidi = false;
  EXPECT_CALL(*client_->visitor(), OnIncomingUnidirectionalStreamAvailable())
      .WillOnce(Assign(&stream_received_unidi, true));
  ASSERT_TRUE(test_harness_.RunUntilWithDefaultTimeout(
      [&]() { return stream_received_unidi; }));

  // Receive the unidirectional echo reply.
  webtransport::Stream* reply =
      client_->session()->AcceptIncomingUnidirectionalStream();
  ASSERT_TRUE(reply != nullptr);
  std::string buffer;
  quiche::ReadStream::PeekResult peek_result = reply->PeekNextReadableRegion();
  EXPECT_EQ(peek_result.peeked_data, "Stream Two");
  EXPECT_EQ(peek_result.fin_next, false);
  EXPECT_EQ(peek_result.all_data_received, true);
  bool fin_received =
      quiche::ProcessAllReadableRegions(*reply, [&](absl::string_view chunk) {
        buffer.append(chunk.data(), chunk.size());
        return true;
      });
  EXPECT_TRUE(fin_received);
  EXPECT_EQ(buffer, "Stream Two");

  // Receive the bidirectional stream reply without a FIN.
  ASSERT_TRUE(test_harness_.RunUntilWithDefaultTimeout(
      [&]() { return stream1->PeekNextReadableRegion().has_data(); }));
  peek_result = stream1->PeekNextReadableRegion();
  EXPECT_EQ(peek_result.peeked_data, "Stream One");
  EXPECT_EQ(peek_result.fin_next, false);
  EXPECT_EQ(peek_result.all_data_received, false);
  fin_received = stream1->SkipBytes(strlen("Stream One"));
  EXPECT_FALSE(fin_received);
  peek_result = stream1->PeekNextReadableRegion();
  EXPECT_EQ(peek_result.peeked_data, "");
  EXPECT_EQ(peek_result.fin_next, false);
  EXPECT_EQ(peek_result.all_data_received, false);

  // Send FIN on the first stream, and expect to receive it back.
  EXPECT_TRUE(stream1->SendFin());
  ASSERT_TRUE(test_harness_.RunUntilWithDefaultTimeout(
      [&]() { return stream1->PeekNextReadableRegion().all_data_received; }));
  peek_result = stream1->PeekNextReadableRegion();
  EXPECT_EQ(peek_result.peeked_data, "");
  EXPECT_EQ(peek_result.fin_next, true);
  EXPECT_EQ(peek_result.all_data_received, true);

  // Read FIN and expect the stream to get garbage collected.
  webtransport::StreamId id = stream1->GetStreamId();
  EXPECT_TRUE(client_->session()->GetStreamById(id) != nullptr);
  fin_received = stream1->SkipBytes(0);
  EXPECT_TRUE(fin_received);
  EXPECT_TRUE(client_->session()->GetStreamById(id) == nullptr);
}

TEST_F(QuicGenericSessionTest, EchoDatagram) {
  CreateDefaultEndpoints(kEchoServer);
  WireUpEndpoints();
  RunHandshake();

  client_->session()->SendOrQueueDatagram("test");

  bool datagram_received = false;
  EXPECT_CALL(*client_->visitor(), OnDatagramReceived(Eq("test")))
      .WillOnce(Assign(&datagram_received, true));
  ASSERT_TRUE(test_harness_.RunUntilWithDefaultTimeout(
      [&datagram_received]() { return datagram_received; }));
}

// This test sets the datagram queue to an nearly-infinite queueing time, and
// then sends 1000 datagrams.  We expect to receive most of them back, since the
// datagrams would be paced out by the congestion controller.
TEST_F(QuicGenericSessionTest, EchoALotOfDatagrams) {
  CreateDefaultEndpoints(kEchoServer);
  WireUpEndpoints();
  RunHandshake();

  // Set the datagrams to effectively never expire.
  client_->session()->SetDatagramMaxTimeInQueue(
      (10000 * simulator::TestHarness::kRtt).ToAbsl());
  for (int i = 0; i < 1000; i++) {
    client_->session()->SendOrQueueDatagram(std::string(
        client_->session()->GetGuaranteedLargestMessagePayload(), 'a'));
  }

  size_t received = 0;
  EXPECT_CALL(*client_->visitor(), OnDatagramReceived(_))
      .WillRepeatedly(
          [&received](absl::string_view /*datagram*/) { received++; });
  ASSERT_TRUE(test_harness_.simulator().RunUntilOrTimeout(
      [this]() { return client_->total_datagrams_processed() >= 1000; },
      3 * simulator::TestHarness::kServerBandwidth.TransferTime(
              1000 * kMaxOutgoingPacketSize)));
  // Allow extra round-trips for the final flight of datagrams to arrive back.
  test_harness_.simulator().RunFor(2 * simulator::TestHarness::kRtt);

  EXPECT_GT(received, 500u);
  EXPECT_LT(received, 1000u);
}

TEST_F(QuicGenericSessionTest, OutgoingStreamFlowControlBlocked) {
  server_config_.SetMaxUnidirectionalStreamsToSend(4);
  CreateDefaultEndpoints(kDiscardServer);
  WireUpEndpoints();
  RunHandshake();

  webtransport::Stream* stream;
  for (int i = 0; i <= 3; i++) {
    ASSERT_TRUE(client_->session()->CanOpenNextOutgoingUnidirectionalStream());
    stream = client_->session()->OpenOutgoingUnidirectionalStream();
    ASSERT_TRUE(stream != nullptr);
    ASSERT_TRUE(stream->SendFin());
  }
  EXPECT_FALSE(client_->session()->CanOpenNextOutgoingUnidirectionalStream());

  // Receiving FINs for the streams we've just opened will cause the server to
  // let us open more streams.
  bool can_create_new_stream = false;
  EXPECT_CALL(*client_->visitor(), OnCanCreateNewOutgoingUnidirectionalStream())
      .WillOnce(Assign(&can_create_new_stream, true));
  ASSERT_TRUE(test_harness_.RunUntilWithDefaultTimeout(
      [&can_create_new_stream]() { return can_create_new_stream; }));
  EXPECT_TRUE(client_->session()->CanOpenNextOutgoingUnidirectionalStream());
}

TEST_F(QuicGenericSessionTest, ExpireDatagrams) {
  CreateDefaultEndpoints(kEchoServer);
  WireUpEndpoints();
  RunHandshake();

  // Set the datagrams to expire very soon.
  client_->session()->SetDatagramMaxTimeInQueue(
      (0.2 * simulator::TestHarness::kRtt).ToAbsl());
  for (int i = 0; i < 1000; i++) {
    client_->session()->SendOrQueueDatagram(std::string(
        client_->session()->GetGuaranteedLargestMessagePayload(), 'a'));
  }

  size_t received = 0;
  EXPECT_CALL(*client_->visitor(), OnDatagramReceived(_))
      .WillRepeatedly(
          [&received](absl::string_view /*datagram*/) { received++; });
  ASSERT_TRUE(test_harness_.simulator().RunUntilOrTimeout(
      [this]() { return client_->total_datagrams_processed() >= 1000; },
      3 * simulator::TestHarness::kServerBandwidth.TransferTime(
              1000 * kMaxOutgoingPacketSize)));
  // Allow extra round-trips for the final flight of datagrams to arrive back.
  test_harness_.simulator().RunFor(2 * simulator::TestHarness::kRtt);
  EXPECT_LT(received, 500);
  EXPECT_EQ(received + client_->session()->GetDatagramStats().expired_outgoing,
            1000);
}

TEST_F(QuicGenericSessionTest, LoseDatagrams) {
  CreateDefaultEndpoints(kEchoServer);
  test_harness_.WireUpEndpointsWithLoss(/*lose_every_n=*/4);
  RunHandshake();

  // Set the datagrams to effectively never expire.
  client_->session()->SetDatagramMaxTimeInQueue(
      (10000 * simulator::TestHarness::kRtt).ToAbsl());
  for (int i = 0; i < 1000; i++) {
    client_->session()->SendOrQueueDatagram(std::string(
        client_->session()->GetGuaranteedLargestMessagePayload(), 'a'));
  }

  size_t received = 0;
  EXPECT_CALL(*client_->visitor(), OnDatagramReceived(_))
      .WillRepeatedly(
          [&received](absl::string_view /*datagram*/) { received++; });
  ASSERT_TRUE(test_harness_.simulator().RunUntilOrTimeout(
      [this]() { return client_->total_datagrams_processed() >= 1000; },
      4 * simulator::TestHarness::kServerBandwidth.TransferTime(
              1000 * kMaxOutgoingPacketSize)));
  // Allow extra round-trips for the final flight of datagrams to arrive back.
  test_harness_.simulator().RunFor(16 * simulator::TestHarness::kRtt);

  QuicPacketCount client_lost =
      client_->session()->GetDatagramStats().lost_outgoing;
  QuicPacketCount server_lost =
      server_->session()->GetDatagramStats().lost_outgoing;
  EXPECT_LT(received, 800u);
  EXPECT_GT(client_lost, 100u);
  EXPECT_GT(server_lost, 100u);
  EXPECT_EQ(received + client_lost + server_lost, 1000u);
}

TEST_F(QuicGenericSessionTest, WriteWhenBufferFull) {
  CreateDefaultEndpoints(kEchoServer);
  WireUpEndpoints();
  RunHandshake();

  const std::string buffer(64 * 1024 + 1, 'q');
  webtransport::Stream* stream =
      client_->session()->OpenOutgoingBidirectionalStream();
  ASSERT_TRUE(stream != nullptr);

  ASSERT_TRUE(stream->CanWrite());
  absl::Status status = quiche::WriteIntoStream(*stream, buffer);
  QUICHE_EXPECT_OK(status);
  EXPECT_FALSE(stream->CanWrite());

  status = quiche::WriteIntoStream(*stream, buffer);
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kUnavailable));

  quiche::StreamWriteOptions options;
  options.set_buffer_unconditionally(true);
  options.set_send_fin(true);
  status = quiche::WriteIntoStream(*stream, buffer, options);
  QUICHE_EXPECT_OK(status);
  EXPECT_FALSE(stream->CanWrite());

  QuicByteCount total_received = 0;
  for (;;) {
    test_harness_.RunUntilWithDefaultTimeout(
        [&] { return stream->PeekNextReadableRegion().has_data(); });
    quiche::ReadStream::PeekResult result = stream->PeekNextReadableRegion();
    total_received += result.peeked_data.size();
    bool fin_consumed = stream->SkipBytes(result.peeked_data.size());
    if (fin_consumed) {
      break;
    }
  }
  EXPECT_EQ(total_received, 128u * 1024u + 2);
}

}  // namespace
}  // namespace quic::test
```