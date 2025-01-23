Response:
Let's break down the thought process to analyze the C++ test file.

1. **Understand the Goal:** The core request is to analyze a C++ test file (`event_loop_connecting_client_socket_test.cc`) within the Chromium networking stack. The analysis should cover functionality, potential JavaScript relevance, logical reasoning, common errors, and debugging context.

2. **Initial Scan for Keywords and Structure:**  Quickly scan the file for important keywords and the overall structure. I see `#include`, indicating dependencies. I see class definitions (`TestServerSocketRunner`, `EventLoopConnectingClientSocketTest`). I see `TEST_P`, `INSTANTIATE_TEST_SUITE_P`, suggesting parameterized tests. The file name itself is highly descriptive, pointing to testing a `ConnectingClientSocket` that uses an `EventLoop`.

3. **Identify the Tested Class:** The filename and the presence of `ConnectingClientSocket` in the includes strongly suggest that `EventLoopConnectingClientSocket` is the main class under test.

4. **Analyze `TestServerSocketRunner`:**  This looks like a helper class to simulate a server for the tests. I see it inherits from `quiche::QuicheThread`, implying it runs in a separate thread. The constructor takes a `SocketFd` and a `SocketBehavior` (a callback). There are specializations for TCP (`TestTcpServerSocketRunner`) and UDP (`TestUdpServerSocketRunner`). This tells me the tests will involve setting up server-side behavior.

5. **Analyze `EventLoopConnectingClientSocketTest`:** This is the main test fixture. Key observations:
    * It inherits from `quiche::test::QuicheTestWithParam`, confirming parameterized testing. The parameter is a tuple of `socket_api::SocketProtocol` and `QuicEventLoopFactory*`. This means the tests will run for different socket protocols (TCP, UDP) and potentially different event loop implementations.
    * It implements `ConnectingClientSocket::AsyncVisitor`. This interface is used for asynchronous callbacks, indicating that the tests cover asynchronous operations.
    * `SetUp` creates an `EventLoop`, a `SocketFactory`, and a listening server socket.
    * `TearDown` cleans up the server socket.
    * There are helper methods like `CreateSocket` and `CreateServerSocketRunner` to instantiate the client and server components.
    *  The test methods themselves (`ConnectBlocking`, `ConnectAsync`, `ReceiveBlocking`, `SendAsync`, etc.) directly correspond to the functionalities of a connecting client socket.

6. **Functionality Listing:** Based on the test methods, I can list the key functionalities being tested:
    * Blocking and asynchronous connection attempts.
    * Disconnection.
    * Retrieving the local address.
    * Blocking and asynchronous sending and receiving of data.
    * Cancellation of asynchronous operations upon disconnection.
    * Handling errors during connection.
    * Reconnection.

7. **JavaScript Relevance:**  Think about how these low-level socket operations relate to web browsers (where JavaScript runs). The key connection is that *browser networking relies on these underlying socket primitives*. JavaScript doesn't directly manipulate these sockets, but APIs like `fetch`, `XMLHttpRequest`, and WebSockets abstract over them. Therefore:
    * `Connect`:  Corresponds to initiating a network request.
    * `Send`: Sending data in a request body or WebSocket message.
    * `Receive`: Receiving the response to a request or a WebSocket message.
    * Errors and disconnections:  Manifest as network errors in JavaScript.

8. **Logical Reasoning (Hypothetical Scenarios):**  Consider what happens under different conditions. For example, what if the server isn't running?  What if the network is slow? The tests implicitly explore some of these scenarios. The explicit error tests (`ErrorBeforeConnectAsync`, `ErrorDuringConnectAsync`) provide concrete examples. To provide explicit input/output, I can choose a simple test case like `ConnectBlocking`:
    * *Hypothetical Input:*  A valid server address and port.
    * *Expected Output:* The `ConnectBlocking()` method returns successfully (an `absl::Status` indicating success).

9. **Common User/Programming Errors:** Think about mistakes developers might make when using networking APIs:
    * Forgetting to handle errors (e.g., connection refused).
    * Not closing sockets, leading to resource leaks.
    * Incorrectly handling asynchronous operations (e.g., not waiting for completion).
    * Sending or receiving data without establishing a connection.

10. **Debugging Clues (User Steps):** Imagine how a user might trigger the code being tested. This involves tracing back from a user-facing action:
    * User types a URL in the address bar and presses Enter.
    * JavaScript code in a web page initiates a `fetch` request.
    * The browser establishes a QUIC connection (which uses these underlying sockets).
    * A WebSocket connection is opened by JavaScript.

11. **Structure and Refine:** Organize the information logically. Start with a summary of the file's purpose, then detail the functionalities, JavaScript connections, logical reasoning, errors, and debugging. Use clear headings and bullet points for readability.

12. **Review and Enhance:** Read through the analysis. Are there any ambiguities? Can I provide more concrete examples?  Did I miss any key aspects of the code? For example, the use of `QuicEventLoop` is crucial for understanding the asynchronous nature of the tests. Emphasize that the test file is specifically for *connecting* client sockets.

This step-by-step process, combining code analysis, domain knowledge (networking), and logical deduction, helps create a comprehensive understanding of the C++ test file.
这个C++源代码文件 `event_loop_connecting_client_socket_test.cc` 的主要功能是为 Chromium 网络栈中的 `EventLoopConnectingClientSocket` 类编写单元测试。  `EventLoopConnectingClientSocket` 自身是 `ConnectingClientSocket` 的一个实现，它使用事件循环（`QuicEventLoop`) 来处理异步的连接、发送和接收操作。

更具体地说，这个测试文件旨在验证以下 `EventLoopConnectingClientSocket` 的功能：

**核心功能测试:**

* **连接 (Connect):**
    * **`ConnectBlocking()`:** 测试阻塞式的连接操作是否能成功建立连接。
    * **`ConnectAsync()`:** 测试异步连接操作是否能正确发起连接，并通过回调通知连接结果。
    * 测试在连接过程中或连接前发生错误时的处理。
    * 测试取消异步连接 (`DisconnectCancelsConnectAsync`)。
    * 测试连接后重新连接 (`ConnectAndReconnect`)。
* **断开连接 (Disconnect):** 测试断开连接操作是否能正常关闭连接。
* **获取本地地址 (GetLocalAddress):** 测试是否能正确获取连接建立后本地 socket 的地址。
* **接收数据 (Receive):**
    * **`ReceiveBlocking()`:** 测试阻塞式接收数据是否能正确接收服务器发送的数据。
    * **`ReceiveAsync()`:** 测试异步接收数据是否能正确接收服务器发送的数据并通过回调通知。
    * 测试取消异步接收 (`DisconnectCancelsReceiveAsync`)。
* **发送数据 (Send):**
    * **`SendBlocking()`:** 测试阻塞式发送数据是否能成功发送到服务器。
    * **`SendAsync()`:** 测试异步发送数据是否能正确发送到服务器并通过回调通知。
    * 测试取消异步发送 (`DisconnectCancelsSendAsync`)。

**辅助测试结构:**

* **`TestServerSocketRunner`:** 这是一个抽象基类，用于在独立的线程中模拟一个简单的 TCP 或 UDP 服务器。它负责监听连接（TCP）或等待数据（UDP），并执行预定义的操作。
    * **`TestTcpServerSocketRunner`:**  `TestServerSocketRunner` 的 TCP 版本，负责接受连接。
    * **`TestUdpServerSocketRunner`:** `TestServerSocketRunner` 的 UDP 版本，负责连接到客户端。
* **Parameterized Tests:** 使用 `testing::Combine` 和 `Values` 来进行参数化测试，针对不同的 `socket_api::SocketProtocol` (TCP 和 UDP) 以及不同的 `QuicEventLoopFactory` 实现进行测试。

**与 JavaScript 的关系 (间接):**

这个 C++ 文件本身不包含 JavaScript 代码，但它测试的网络底层功能对于 JavaScript 在浏览器中的网络操作至关重要。以下是一些关联：

* **`fetch` API:**  当 JavaScript 使用 `fetch` API 发起网络请求时，浏览器底层会使用类似的 socket 连接机制来与服务器建立连接和传输数据。 `EventLoopConnectingClientSocket` 提供的功能（连接、发送、接收）是 `fetch` API 的底层实现基础。
* **`XMLHttpRequest` (XHR):**  类似于 `fetch`，XHR 对象也依赖于底层的网络 socket 操作。
* **WebSockets:**  WebSockets 提供了一种在浏览器和服务器之间建立持久双向连接的方式。 `EventLoopConnectingClientSocket` 提供的异步连接和数据传输机制与 WebSocket 的实现原理类似。

**举例说明 (与 JavaScript `fetch` API 的联系):**

假设以下 JavaScript 代码使用 `fetch` 发起一个简单的 GET 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data))
  .catch(error => console.error('Error:', error));
```

当这段 JavaScript 代码执行时，浏览器底层可能会执行以下步骤（简化）：

1. **查找 DNS:** 浏览器首先需要将 `example.com` 解析为 IP 地址。
2. **建立连接:**  浏览器会使用类似 `EventLoopConnectingClientSocket` 的机制尝试与 `example.com` 的服务器建立 TCP 连接（通常是 HTTPS，所以是 TLS 上的 TCP）。 `ConnectAsync()` 方法会在这个阶段被调用。
3. **发送请求:** 连接建立后，浏览器会构造 HTTP GET 请求并使用类似 `SendAsync()` 的方法将请求数据发送到服务器。
4. **接收响应:** 服务器处理请求后，会发送 HTTP 响应。浏览器会使用类似 `ReceiveAsync()` 的方法接收响应数据。
5. **处理响应:** JavaScript 中的 `then` 回调函数会被调用，处理接收到的 JSON 数据。

**逻辑推理 (假设输入与输出):**

**测试用例:** `TEST_P(EventLoopConnectingClientSocketTest, ConnectBlocking)`

**假设输入:**

* `server_socket_address_`: 一个有效的服务器地址和端口，服务器正在监听连接（对于 TCP）。对于 UDP，服务器地址是客户端尝试连接的地址。

**预期输出:**

* `socket->ConnectBlocking()` 返回一个表示成功的 `absl::Status` 对象 (即 `ok()` 为 true)。
* 连接成功建立。

**测试用例:** `TEST_P(EventLoopConnectingClientSocketTest, ReceiveBlocking)`

**假设输入:**

* 连接已成功建立。
* 服务器端（由 `TestServerSocketRunner` 模拟）会向连接的 socket 发送一段数据，例如字符串 "Hello"。

**预期输出:**

* `socket->ReceiveBlocking(100)` 会返回一个 `absl::StatusOr<quiche::QuicheMemSlice>`，其中包含服务器发送的数据 "Hello"。
* 接收到的数据的长度和内容与发送的数据一致。

**用户或编程常见的使用错误 (以及测试如何覆盖):**

* **忘记处理连接错误:**  例如，服务器未启动或网络不可达。 `ErrorBeforeConnectAsync` 和 `ErrorDuringConnectAsync` 测试会覆盖这种情况，验证客户端是否能正确处理连接失败。
* **未正确关闭 socket 导致资源泄漏:** 虽然测试本身侧重于连接行为，但 `Disconnect()` 方法的测试间接验证了关闭 socket 的功能。在实际应用中，确保在不再需要 socket 时关闭它非常重要。
* **在连接未建立前尝试发送或接收数据:** 测试中通常先建立连接，再进行发送和接收操作，这模拟了正确的编程实践。如果在连接建立前尝试发送或接收，通常会导致错误。
* **阻塞式操作在事件循环线程中执行导致死锁:**  `EventLoopConnectingClientSocket` 的设计目的是在事件循环中进行非阻塞操作。测试 `ConnectBlocking`、`ReceiveBlocking` 和 `SendBlocking` 在非事件循环线程中的行为，验证了阻塞操作的正确性，并避免在事件循环线程中错误地使用阻塞操作。
* **没有正确处理异步操作的回调:** `ConnectAsync`、`ReceiveAsync` 和 `SendAsync` 测试验证了异步操作的回调机制是否正常工作，确保在操作完成时能收到通知。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入 URL 并按下 Enter，或者点击一个链接。**
2. **浏览器解析 URL，确定目标服务器的域名。**
3. **浏览器发起 DNS 查询，获取服务器的 IP 地址。**
4. **浏览器根据 URL 的协议 (例如 HTTPS)，决定使用 QUIC 或 TCP 进行连接。**
5. **如果使用 QUIC，Chromium 的 QUIC 栈会尝试与服务器建立连接。`EventLoopConnectingClientSocket` (或者类似的类) 会被创建用于管理这个连接。**
6. **`ConnectAsync()` 方法会被调用，尝试异步地建立连接。**
7. **底层的 socket API (例如 `connect()`) 会被调用。**
8. **事件循环 (`QuicEventLoop`) 会监听 socket 的状态变化。**
9. **一旦连接建立成功或失败，事件循环会通知 `EventLoopConnectingClientSocket`，然后 `ConnectComplete()` 回调函数会被调用。**

**在调试过程中，如果发现连接建立有问题，开发者可能会查看以下信息：**

* **网络日志:**  查看是否有连接超时、连接被拒绝等错误信息。
* **抓包 (如 Wireshark):**  分析网络数据包，查看握手过程是否正常。
* **Chromium 内部的网络事件:**  Chromium 提供了 `net-internals` 工具，可以查看详细的网络事件，包括 socket 的创建、连接尝试、数据发送和接收等。

这个测试文件 `event_loop_connecting_client_socket_test.cc` 的存在，确保了 `EventLoopConnectingClientSocket` 类的功能正确性，从而保证了 Chromium 浏览器底层网络连接的稳定性和可靠性，最终影响用户浏览网页的体验。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/io/event_loop_connecting_client_socket_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "quiche/quic/core/io/event_loop_connecting_client_socket.h"

#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>

#include "absl/functional/bind_front.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/connecting_client_socket.h"
#include "quiche/quic/core/io/event_loop_socket_factory.h"
#include "quiche/quic/core/io/quic_default_event_loop.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/test_tools/mock_clock.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_mem_slice.h"
#include "quiche/common/platform/api/quiche_mutex.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/platform/api/quiche_test_loopback.h"
#include "quiche/common/platform/api/quiche_thread.h"
#include "quiche/common/quiche_callbacks.h"
#include "quiche/common/simple_buffer_allocator.h"

namespace quic::test {
namespace {

using ::testing::Combine;
using ::testing::Values;
using ::testing::ValuesIn;

class TestServerSocketRunner : public quiche::QuicheThread {
 public:
  using SocketBehavior = quiche::MultiUseCallback<void(
      SocketFd connected_socket, socket_api::SocketProtocol protocol)>;

  TestServerSocketRunner(SocketFd server_socket_descriptor,
                         SocketBehavior behavior)
      : QuicheThread("TestServerSocketRunner"),
        server_socket_descriptor_(server_socket_descriptor),
        behavior_(std::move(behavior)) {}
  ~TestServerSocketRunner() override { WaitForCompletion(); }

  void WaitForCompletion() { completion_notification_.WaitForNotification(); }

 protected:
  SocketFd server_socket_descriptor() const {
    return server_socket_descriptor_;
  }

  const SocketBehavior& behavior() const { return behavior_; }

  quiche::QuicheNotification& completion_notification() {
    return completion_notification_;
  }

 private:
  const SocketFd server_socket_descriptor_;
  const SocketBehavior behavior_;

  quiche::QuicheNotification completion_notification_;
};

class TestTcpServerSocketRunner : public TestServerSocketRunner {
 public:
  // On construction, spins a separate thread to accept a connection from
  // `server_socket_descriptor`, runs `behavior` with that connection, and then
  // closes the accepted connection socket.
  TestTcpServerSocketRunner(SocketFd server_socket_descriptor,
                            SocketBehavior behavior)
      : TestServerSocketRunner(server_socket_descriptor, std::move(behavior)) {
    Start();
  }

  ~TestTcpServerSocketRunner() override { Join(); }

 protected:
  void Run() override {
    AcceptSocket();
    behavior()(connection_socket_descriptor_, socket_api::SocketProtocol::kTcp);
    CloseSocket();

    completion_notification().Notify();
  }

 private:
  void AcceptSocket() {
    absl::StatusOr<socket_api::AcceptResult> connection_socket =
        socket_api::Accept(server_socket_descriptor(), /*blocking=*/true);
    QUICHE_CHECK(connection_socket.ok());
    connection_socket_descriptor_ = connection_socket.value().fd;
  }

  void CloseSocket() {
    QUICHE_CHECK(socket_api::Close(connection_socket_descriptor_).ok());
    QUICHE_CHECK(socket_api::Close(server_socket_descriptor()).ok());
  }

  SocketFd connection_socket_descriptor_ = kInvalidSocketFd;
};

class TestUdpServerSocketRunner : public TestServerSocketRunner {
 public:
  // On construction, spins a separate thread to connect
  // `server_socket_descriptor` to `client_socket_address`, runs `behavior` with
  // that connection, and then disconnects the socket.
  TestUdpServerSocketRunner(SocketFd server_socket_descriptor,
                            SocketBehavior behavior,
                            QuicSocketAddress client_socket_address)
      : TestServerSocketRunner(server_socket_descriptor, std::move(behavior)),
        client_socket_address_(std::move(client_socket_address)) {
    Start();
  }

  ~TestUdpServerSocketRunner() override { Join(); }

 protected:
  void Run() override {
    ConnectSocket();
    behavior()(server_socket_descriptor(), socket_api::SocketProtocol::kUdp);
    DisconnectSocket();

    completion_notification().Notify();
  }

 private:
  void ConnectSocket() {
    QUICHE_CHECK(
        socket_api::Connect(server_socket_descriptor(), client_socket_address_)
            .ok());
  }

  void DisconnectSocket() {
    QUICHE_CHECK(socket_api::Close(server_socket_descriptor()).ok());
  }

  QuicSocketAddress client_socket_address_;
};

class EventLoopConnectingClientSocketTest
    : public quiche::test::QuicheTestWithParam<
          std::tuple<socket_api::SocketProtocol, QuicEventLoopFactory*>>,
      public ConnectingClientSocket::AsyncVisitor {
 public:
  void SetUp() override {
    QuicEventLoopFactory* event_loop_factory;
    std::tie(protocol_, event_loop_factory) = GetParam();

    event_loop_ = event_loop_factory->Create(&clock_);
    socket_factory_ = std::make_unique<EventLoopSocketFactory>(
        event_loop_.get(), quiche::SimpleBufferAllocator::Get());

    QUICHE_CHECK(CreateListeningServerSocket());
  }

  void TearDown() override {
    if (server_socket_descriptor_ != kInvalidSocketFd) {
      QUICHE_CHECK(socket_api::Close(server_socket_descriptor_).ok());
    }
  }

  void ConnectComplete(absl::Status status) override {
    QUICHE_CHECK(!connect_result_.has_value());
    connect_result_ = std::move(status);
  }

  void ReceiveComplete(absl::StatusOr<quiche::QuicheMemSlice> data) override {
    QUICHE_CHECK(!receive_result_.has_value());
    receive_result_ = std::move(data);
  }

  void SendComplete(absl::Status status) override {
    QUICHE_CHECK(!send_result_.has_value());
    send_result_ = std::move(status);
  }

 protected:
  std::unique_ptr<ConnectingClientSocket> CreateSocket(
      const quic::QuicSocketAddress& peer_address,
      ConnectingClientSocket::AsyncVisitor* async_visitor) {
    switch (protocol_) {
      case socket_api::SocketProtocol::kUdp:
        return socket_factory_->CreateConnectingUdpClientSocket(
            peer_address, /*receive_buffer_size=*/0, /*send_buffer_size=*/0,
            async_visitor);
      case socket_api::SocketProtocol::kTcp:
        return socket_factory_->CreateTcpClientSocket(
            peer_address, /*receive_buffer_size=*/0, /*send_buffer_size=*/0,
            async_visitor);
      default:
        // Unexpected protocol.
        QUICHE_NOTREACHED();
        return nullptr;
    }
  }

  std::unique_ptr<ConnectingClientSocket> CreateSocketToEncourageDelayedSend(
      const quic::QuicSocketAddress& peer_address,
      ConnectingClientSocket::AsyncVisitor* async_visitor) {
    switch (protocol_) {
      case socket_api::SocketProtocol::kUdp:
        // Nothing special for UDP since UDP does not gaurantee packets will be
        // sent once send buffers are full.
        return socket_factory_->CreateConnectingUdpClientSocket(
            peer_address, /*receive_buffer_size=*/0, /*send_buffer_size=*/0,
            async_visitor);
      case socket_api::SocketProtocol::kTcp:
        // For TCP, set a very small send buffer to encourage sends to be
        // delayed.
        return socket_factory_->CreateTcpClientSocket(
            peer_address, /*receive_buffer_size=*/0, /*send_buffer_size=*/4,
            async_visitor);
      default:
        // Unexpected protocol.
        QUICHE_NOTREACHED();
        return nullptr;
    }
  }

  bool CreateListeningServerSocket() {
    absl::StatusOr<SocketFd> socket = socket_api::CreateSocket(
        quiche::TestLoopback().address_family(), protocol_,
        /*blocking=*/true);
    QUICHE_CHECK(socket.ok());

    // For TCP, set an extremely small receive buffer size to increase the odds
    // of buffers filling up when testing asynchronous writes.
    if (protocol_ == socket_api::SocketProtocol::kTcp) {
      static const QuicByteCount kReceiveBufferSize = 2;
      absl::Status result =
          socket_api::SetReceiveBufferSize(socket.value(), kReceiveBufferSize);
      QUICHE_CHECK(result.ok());
    }

    QuicSocketAddress bind_address(quiche::TestLoopback(), /*port=*/0);
    absl::Status result = socket_api::Bind(socket.value(), bind_address);
    QUICHE_CHECK(result.ok());

    absl::StatusOr<QuicSocketAddress> socket_address =
        socket_api::GetSocketAddress(socket.value());
    QUICHE_CHECK(socket_address.ok());

    // TCP sockets need to listen for connections. UDP sockets are ready to
    // receive.
    if (protocol_ == socket_api::SocketProtocol::kTcp) {
      result = socket_api::Listen(socket.value(), /*backlog=*/1);
      QUICHE_CHECK(result.ok());
    }

    server_socket_descriptor_ = socket.value();
    server_socket_address_ = std::move(socket_address).value();
    return true;
  }

  std::unique_ptr<TestServerSocketRunner> CreateServerSocketRunner(
      TestServerSocketRunner::SocketBehavior behavior,
      ConnectingClientSocket* client_socket) {
    std::unique_ptr<TestServerSocketRunner> runner;
    switch (protocol_) {
      case socket_api::SocketProtocol::kUdp: {
        absl::StatusOr<QuicSocketAddress> client_socket_address =
            client_socket->GetLocalAddress();
        QUICHE_CHECK(client_socket_address.ok());
        runner = std::make_unique<TestUdpServerSocketRunner>(
            server_socket_descriptor_, std::move(behavior),
            std::move(client_socket_address).value());
        break;
      }
      case socket_api::SocketProtocol::kTcp:
        runner = std::make_unique<TestTcpServerSocketRunner>(
            server_socket_descriptor_, std::move(behavior));
        break;
      default:
        // Unexpected protocol.
        QUICHE_NOTREACHED();
    }

    // Runner takes responsibility for closing server socket.
    server_socket_descriptor_ = kInvalidSocketFd;

    return runner;
  }

  socket_api::SocketProtocol protocol_;

  SocketFd server_socket_descriptor_ = kInvalidSocketFd;
  QuicSocketAddress server_socket_address_;

  MockClock clock_;
  std::unique_ptr<QuicEventLoop> event_loop_;
  std::unique_ptr<EventLoopSocketFactory> socket_factory_;

  std::optional<absl::Status> connect_result_;
  std::optional<absl::StatusOr<quiche::QuicheMemSlice>> receive_result_;
  std::optional<absl::Status> send_result_;
};

std::string GetTestParamName(
    ::testing::TestParamInfo<
        std::tuple<socket_api::SocketProtocol, QuicEventLoopFactory*>>
        info) {
  auto [protocol, event_loop_factory] = info.param;

  return EscapeTestParamName(absl::StrCat(socket_api::GetProtocolName(protocol),
                                          "_", event_loop_factory->GetName()));
}

INSTANTIATE_TEST_SUITE_P(EventLoopConnectingClientSocketTests,
                         EventLoopConnectingClientSocketTest,
                         Combine(Values(socket_api::SocketProtocol::kUdp,
                                        socket_api::SocketProtocol::kTcp),
                                 ValuesIn(GetAllSupportedEventLoops())),
                         &GetTestParamName);

TEST_P(EventLoopConnectingClientSocketTest, ConnectBlocking) {
  std::unique_ptr<ConnectingClientSocket> socket =
      CreateSocket(server_socket_address_,
                   /*async_visitor=*/nullptr);

  // No socket runner to accept the connection for the server, but that is not
  // expected to be necessary for the connection to complete from the client for
  // TCP or UDP.
  EXPECT_TRUE(socket->ConnectBlocking().ok());

  socket->Disconnect();
}

TEST_P(EventLoopConnectingClientSocketTest, ConnectAsync) {
  std::unique_ptr<ConnectingClientSocket> socket =
      CreateSocket(server_socket_address_,
                   /*async_visitor=*/this);

  socket->ConnectAsync();

  // TCP connection typically completes asynchronously and UDP connection
  // typically completes before ConnectAsync returns, but there is no simple way
  // to ensure either behaves one way or the other. If connecting is
  // asynchronous, expect completion once signalled by the event loop.
  if (!connect_result_.has_value()) {
    event_loop_->RunEventLoopOnce(QuicTime::Delta::FromSeconds(1));
    ASSERT_TRUE(connect_result_.has_value());
  }
  EXPECT_TRUE(connect_result_.value().ok());

  connect_result_.reset();
  socket->Disconnect();
  EXPECT_FALSE(connect_result_.has_value());
}

TEST_P(EventLoopConnectingClientSocketTest, ErrorBeforeConnectAsync) {
  std::unique_ptr<ConnectingClientSocket> socket =
      CreateSocket(server_socket_address_,
                   /*async_visitor=*/this);

  // Close the server socket.
  EXPECT_TRUE(socket_api::Close(server_socket_descriptor_).ok());
  server_socket_descriptor_ = kInvalidSocketFd;

  socket->ConnectAsync();
  if (!connect_result_.has_value()) {
    event_loop_->RunEventLoopOnce(QuicTime::Delta::FromSeconds(1));
    ASSERT_TRUE(connect_result_.has_value());
  }

  switch (protocol_) {
    case socket_api::SocketProtocol::kTcp:
      // Expect an error because server socket was closed before connection.
      EXPECT_FALSE(connect_result_.value().ok());
      break;
    case socket_api::SocketProtocol::kUdp:
      // No error for UDP because UDP connection success does not rely on the
      // server.
      EXPECT_TRUE(connect_result_.value().ok());
      socket->Disconnect();
      break;
    default:
      // Unexpected protocol.
      FAIL();
  }
}

TEST_P(EventLoopConnectingClientSocketTest, ErrorDuringConnectAsync) {
  std::unique_ptr<ConnectingClientSocket> socket =
      CreateSocket(server_socket_address_,
                   /*async_visitor=*/this);

  socket->ConnectAsync();

  if (connect_result_.has_value()) {
    // UDP typically completes connection immediately before this test has a
    // chance to actually attempt the error. TCP typically completes
    // asynchronously, but no simple way to ensure that always happens.
    EXPECT_TRUE(connect_result_.value().ok());
    socket->Disconnect();
    return;
  }

  // Close the server socket.
  EXPECT_TRUE(socket_api::Close(server_socket_descriptor_).ok());
  server_socket_descriptor_ = kInvalidSocketFd;

  EXPECT_FALSE(connect_result_.has_value());
  event_loop_->RunEventLoopOnce(QuicTime::Delta::FromSeconds(1));
  ASSERT_TRUE(connect_result_.has_value());

  switch (protocol_) {
    case socket_api::SocketProtocol::kTcp:
      EXPECT_FALSE(connect_result_.value().ok());
      break;
    case socket_api::SocketProtocol::kUdp:
      // No error for UDP because UDP connection success does not rely on the
      // server.
      EXPECT_TRUE(connect_result_.value().ok());
      break;
    default:
      // Unexpected protocol.
      FAIL();
  }
}

TEST_P(EventLoopConnectingClientSocketTest, Disconnect) {
  std::unique_ptr<ConnectingClientSocket> socket =
      CreateSocket(server_socket_address_,
                   /*async_visitor=*/nullptr);

  ASSERT_TRUE(socket->ConnectBlocking().ok());
  socket->Disconnect();
}

TEST_P(EventLoopConnectingClientSocketTest, DisconnectCancelsConnectAsync) {
  std::unique_ptr<ConnectingClientSocket> socket =
      CreateSocket(server_socket_address_,
                   /*async_visitor=*/this);

  socket->ConnectAsync();

  bool expect_canceled = true;
  if (connect_result_.has_value()) {
    // UDP typically completes connection immediately before this test has a
    // chance to actually attempt the disconnect. TCP typically completes
    // asynchronously, but no simple way to ensure that always happens.
    EXPECT_TRUE(connect_result_.value().ok());
    expect_canceled = false;
  }

  socket->Disconnect();

  if (expect_canceled) {
    // Expect immediate cancelled error.
    ASSERT_TRUE(connect_result_.has_value());
    EXPECT_TRUE(absl::IsCancelled(connect_result_.value()));
  }
}

TEST_P(EventLoopConnectingClientSocketTest, ConnectAndReconnect) {
  std::unique_ptr<ConnectingClientSocket> socket =
      CreateSocket(server_socket_address_,
                   /*async_visitor=*/nullptr);

  ASSERT_TRUE(socket->ConnectBlocking().ok());
  socket->Disconnect();

  // Expect `socket` can reconnect now that it has been disconnected.
  EXPECT_TRUE(socket->ConnectBlocking().ok());
  socket->Disconnect();
}

TEST_P(EventLoopConnectingClientSocketTest, GetLocalAddress) {
  std::unique_ptr<ConnectingClientSocket> socket =
      CreateSocket(server_socket_address_,
                   /*async_visitor=*/nullptr);
  ASSERT_TRUE(socket->ConnectBlocking().ok());

  absl::StatusOr<QuicSocketAddress> address = socket->GetLocalAddress();
  ASSERT_TRUE(address.ok());
  EXPECT_TRUE(address.value().IsInitialized());

  socket->Disconnect();
}

void SendDataOnSocket(absl::string_view data, SocketFd connected_socket,
                      socket_api::SocketProtocol protocol) {
  QUICHE_CHECK(!data.empty());

  // May attempt to send in pieces for TCP. For UDP, expect failure if `data`
  // cannot be sent in a single packet.
  do {
    absl::StatusOr<absl::string_view> remainder =
        socket_api::Send(connected_socket, data);
    if (!remainder.ok()) {
      return;
    }
    data = remainder.value();
  } while (protocol == socket_api::SocketProtocol::kTcp && !data.empty());

  QUICHE_CHECK(data.empty());
}

TEST_P(EventLoopConnectingClientSocketTest, ReceiveBlocking) {
  std::unique_ptr<ConnectingClientSocket> socket =
      CreateSocket(server_socket_address_,
                   /*async_visitor=*/nullptr);
  ASSERT_TRUE(socket->ConnectBlocking().ok());

  std::string expected = {1, 2, 3, 4, 5, 6, 7, 8};
  std::unique_ptr<TestServerSocketRunner> runner = CreateServerSocketRunner(
      absl::bind_front(&SendDataOnSocket, expected), socket.get());

  std::string received;
  absl::StatusOr<quiche::QuicheMemSlice> data;

  // Expect exactly one packet for UDP, and at least two receives (data + FIN)
  // for TCP.
  do {
    data = socket->ReceiveBlocking(100);
    ASSERT_TRUE(data.ok());
    received.append(data.value().data(), data.value().length());
  } while (protocol_ == socket_api::SocketProtocol::kTcp &&
           !data.value().empty());

  EXPECT_EQ(received, expected);

  socket->Disconnect();
}

TEST_P(EventLoopConnectingClientSocketTest, ReceiveAsync) {
  std::unique_ptr<ConnectingClientSocket> socket =
      CreateSocket(server_socket_address_,
                   /*async_visitor=*/this);
  ASSERT_TRUE(socket->ConnectBlocking().ok());

  // Start an async receive.  Expect no immediate results because runner not
  // yet setup to send.
  socket->ReceiveAsync(100);
  EXPECT_FALSE(receive_result_.has_value());

  // Send data from server.
  std::string expected = {1, 2, 3, 4, 5, 6, 7, 8};
  std::unique_ptr<TestServerSocketRunner> runner = CreateServerSocketRunner(
      absl::bind_front(&SendDataOnSocket, expected), socket.get());

  EXPECT_FALSE(receive_result_.has_value());
  for (int i = 0; i < 5 && !receive_result_.has_value(); ++i) {
    event_loop_->RunEventLoopOnce(QuicTime::Delta::FromSeconds(1));
  }

  // Expect to receive at least some of the sent data.
  ASSERT_TRUE(receive_result_.has_value());
  ASSERT_TRUE(receive_result_.value().ok());
  EXPECT_FALSE(receive_result_.value().value().empty());
  std::string received(receive_result_.value().value().data(),
                       receive_result_.value().value().length());

  // For TCP, expect at least one more receive for the FIN.
  if (protocol_ == socket_api::SocketProtocol::kTcp) {
    absl::StatusOr<quiche::QuicheMemSlice> data;
    do {
      data = socket->ReceiveBlocking(100);
      ASSERT_TRUE(data.ok());
      received.append(data.value().data(), data.value().length());
    } while (!data.value().empty());
  }

  EXPECT_EQ(received, expected);

  receive_result_.reset();
  socket->Disconnect();
  EXPECT_FALSE(receive_result_.has_value());
}

TEST_P(EventLoopConnectingClientSocketTest, DisconnectCancelsReceiveAsync) {
  std::unique_ptr<ConnectingClientSocket> socket =
      CreateSocket(server_socket_address_,
                   /*async_visitor=*/this);

  ASSERT_TRUE(socket->ConnectBlocking().ok());

  // Start an asynchronous read, expecting no completion because server never
  // sends any data.
  socket->ReceiveAsync(100);
  EXPECT_FALSE(receive_result_.has_value());

  // Disconnect and expect an immediate cancelled error.
  socket->Disconnect();
  ASSERT_TRUE(receive_result_.has_value());
  ASSERT_FALSE(receive_result_.value().ok());
  EXPECT_TRUE(absl::IsCancelled(receive_result_.value().status()));
}

// Receive from `connected_socket` until connection is closed, writing
// received data to `out_received`.
void ReceiveDataFromSocket(std::string* out_received, SocketFd connected_socket,
                           socket_api::SocketProtocol protocol) {
  out_received->clear();

  std::string buffer(100, 0);
  absl::StatusOr<absl::Span<char>> received;

  // Expect exactly one packet for UDP, and at least two receives (data + FIN)
  // for TCP.
  do {
    received = socket_api::Receive(connected_socket, absl::MakeSpan(buffer));
    QUICHE_CHECK(received.ok());
    out_received->insert(out_received->end(), received.value().begin(),
                         received.value().end());
  } while (protocol == socket_api::SocketProtocol::kTcp &&
           !received.value().empty());
  QUICHE_CHECK(!out_received->empty());
}

TEST_P(EventLoopConnectingClientSocketTest, SendBlocking) {
  std::unique_ptr<ConnectingClientSocket> socket =
      CreateSocket(server_socket_address_,
                   /*async_visitor=*/nullptr);
  ASSERT_TRUE(socket->ConnectBlocking().ok());

  std::string sent;
  std::unique_ptr<TestServerSocketRunner> runner = CreateServerSocketRunner(
      absl::bind_front(&ReceiveDataFromSocket, &sent), socket.get());

  std::string expected = {1, 2, 3, 4, 5, 6, 7, 8};
  EXPECT_TRUE(socket->SendBlocking(expected).ok());
  socket->Disconnect();

  runner->WaitForCompletion();
  EXPECT_EQ(sent, expected);
}

TEST_P(EventLoopConnectingClientSocketTest, SendAsync) {
  std::unique_ptr<ConnectingClientSocket> socket =
      CreateSocketToEncourageDelayedSend(server_socket_address_,
                                         /*async_visitor=*/this);
  ASSERT_TRUE(socket->ConnectBlocking().ok());

  std::string data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  std::string expected;

  std::unique_ptr<TestServerSocketRunner> runner;
  std::string sent;
  switch (protocol_) {
    case socket_api::SocketProtocol::kTcp:
      // Repeatedly write to socket until it does not complete synchronously.
      do {
        expected.insert(expected.end(), data.begin(), data.end());
        send_result_.reset();
        socket->SendAsync(data);
        ASSERT_TRUE(!send_result_.has_value() || send_result_.value().ok());
      } while (send_result_.has_value());

      // Begin receiving from server and expect more data to send.
      runner = CreateServerSocketRunner(
          absl::bind_front(&ReceiveDataFromSocket, &sent), socket.get());
      EXPECT_FALSE(send_result_.has_value());
      for (int i = 0; i < 5 && !send_result_.has_value(); ++i) {
        event_loop_->RunEventLoopOnce(QuicTime::Delta::FromSeconds(1));
      }
      break;

    case socket_api::SocketProtocol::kUdp:
      // Expect UDP send to always send immediately.
      runner = CreateServerSocketRunner(
          absl::bind_front(&ReceiveDataFromSocket, &sent), socket.get());
      socket->SendAsync(data);
      expected = data;
      break;
    default:
      // Unexpected protocol.
      FAIL();
  }
  ASSERT_TRUE(send_result_.has_value());
  EXPECT_TRUE(send_result_.value().ok());

  send_result_.reset();
  socket->Disconnect();
  EXPECT_FALSE(send_result_.has_value());

  runner->WaitForCompletion();
  EXPECT_EQ(sent, expected);
}

TEST_P(EventLoopConnectingClientSocketTest, DisconnectCancelsSendAsync) {
  if (protocol_ == socket_api::SocketProtocol::kUdp) {
    // UDP sends are always immediate, so cannot disconect mid-send.
    return;
  }

  std::unique_ptr<ConnectingClientSocket> socket =
      CreateSocketToEncourageDelayedSend(server_socket_address_,
                                         /*async_visitor=*/this);
  ASSERT_TRUE(socket->ConnectBlocking().ok());

  std::string data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

  // Repeatedly write to socket until it does not complete synchronously.
  do {
    send_result_.reset();
    socket->SendAsync(data);
    ASSERT_TRUE(!send_result_.has_value() || send_result_.value().ok());
  } while (send_result_.has_value());

  // Disconnect and expect immediate cancelled error.
  socket->Disconnect();
  ASSERT_TRUE(send_result_.has_value());
  EXPECT_TRUE(absl::IsCancelled(send_result_.value()));
}

}  // namespace
}  // namespace quic::test
```