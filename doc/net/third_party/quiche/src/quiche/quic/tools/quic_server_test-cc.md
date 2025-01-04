Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Initial Understanding of the File's Purpose:**

The filename `quic_server_test.cc` immediately suggests this is a test file for a QUIC server implementation. The directory `net/third_party/quiche/src/quiche/quic/tools/` indicates this is likely part of a more complete QUIC library (Quiche) and within the "tools" subdirectory, implying it's testing a standalone server application or components.

**2. High-Level Code Examination:**

Skimming through the `#include` directives reveals key dependencies:

* **`quiche/quic/tools/quic_server.h`:**  This is the main subject under test, the actual `QuicServer` class.
* **QUIC core components:** Includes like `quic/core/crypto/`, `quic/core/io/`, `quic/core/`, `quic/platform/api/` point to the core QUIC protocol implementation within Quiche.
* **Testing frameworks:**  `quic/platform/api/quic_test.h` and `quic/test_tools/` indicate the use of a testing framework (likely Google Test) and helper utilities.
* **Specific test helpers:** `quic/test_tools/mock_quic_dispatcher.h`, `quic/test_tools/quic_server_peer.h`  show that mocking and internal access are used for testing.
* **Server backend:** `quic/tools/quic_memory_cache_backend.h`, `quic/tools/quic_simple_crypto_server_stream_helper.h` suggest the test server uses a simple in-memory backend and a basic crypto stream helper.

**3. Identifying Key Classes and Test Fixtures:**

The code defines several classes:

* **`MockQuicSimpleDispatcher`:** A mock implementation of `QuicSimpleDispatcher`. Mocks are crucial for isolating the `QuicServer`'s behavior and verifying interactions with its dependencies.
* **`TestQuicServer`:**  A test-specific subclass of `QuicServer`. This allows overriding methods and injecting mock dependencies (like the dispatcher).
* **`QuicServerEpollInTest`:** A test fixture specifically for testing `QuicServer`'s handling of EPOLLIN events (related to socket readiness for reading). The parameterized nature (`QuicTestWithParam<QuicEventLoopFactory*>`) suggests testing with different event loop implementations.
* **`QuicServerDispatchPacketTest`:**  A test fixture for testing the `DispatchPacket` functionality of the server.

**4. Analyzing Test Cases and Functionality:**

* **`ProcessBufferedCHLOsOnEpollin`:** This test case directly checks the server's behavior when client hello (CHLO) messages are buffered. It verifies that the server correctly processes these messages in multiple epoll events if necessary.
* **`DispatchPacket`:** A simple test to ensure that the server's `DispatchPacket` method correctly calls the dispatcher's `ProcessPacket` method. It includes the construction of a raw packet for testing.

**5. Identifying Core Functionalities (Based on Code and Test Cases):**

Based on the above analysis, the primary functions of the tested code are:

* **Server Initialization:** Setting up the server with necessary components (crypto config, version manager, event loop, dispatcher, etc.).
* **Handling Incoming Connections (CHLOs):** Managing the initial handshake process by buffering and processing Client Hello messages. The `ProcessBufferedCHLOsOnEpollin` test is a key indicator of this.
* **Packet Dispatching:** Receiving and routing incoming QUIC packets to the appropriate connection handler. The `DispatchPacket` test directly targets this.
* **Integration with Event Loops:** The use of `QuicEventLoop` and the `QuicServerEpollInTest` fixture highlight the server's reliance on an event-driven mechanism for handling I/O.

**6. Relating to JavaScript (If Applicable):**

Given that this is low-level networking code in C++, direct relationships with JavaScript are unlikely *within this specific file*. However, a broader understanding of QUIC is important. QUIC is often used in web contexts, where JavaScript running in a browser or Node.js server would be the *client* communicating with this C++ QUIC server. So, the connection is indirect but significant.

**7. Logic Inference and Input/Output:**

For `ProcessBufferedCHLOsOnEpollin`:

* **Hypothesized Input:** An incoming QUIC packet containing a Client Hello (CHLO).
* **Hypothesized Output:** The server buffers the CHLO. On subsequent epoll events (even without new packets), the server attempts to establish a connection based on the buffered CHLO. The test verifies the dispatcher's `ProcessBufferedChlos` method is called multiple times until all CHLOs are processed.

For `DispatchPacket`:

* **Hypothesized Input:** A raw, well-formed QUIC packet.
* **Hypothesized Output:** The server calls the dispatcher's `ProcessPacket` method, forwarding the packet for further handling.

**8. Common Usage Errors:**

The `ProcessBufferedCHLOsOnEpollin` test implicitly touches on a potential issue: if the server's event loop isn't configured correctly or if there are bugs in the CHLO processing logic, the server might fail to establish connections even after receiving valid client hellos. This could manifest as connection timeouts on the client side.

**9. Debugging Steps to Reach This Code:**

Imagine a scenario where a QUIC client is failing to connect to a server built using this codebase. A developer might:

1. **Start with Client-Side Errors:**  The client might report connection timeouts or handshake failures.
2. **Investigate Server Logs:** Server-side logs might show that incoming packets are being received but no connections are being established.
3. **Hypothesize Handshake Issues:** Suspect problems with the initial handshake (CHLO processing).
4. **Set Breakpoints in Server Code:** Place breakpoints in the `QuicServer`'s packet processing logic or the dispatcher's CHLO handling.
5. **Step Through the Code:** Trace the execution flow when a CHLO packet arrives.
6. **Arrive at `quic_server_test.cc`:**  To understand the intended behavior and potentially find bugs, a developer would look at the unit tests, including `quic_server_test.cc`, to see how the CHLO processing is supposed to work and to potentially reproduce the issue in a controlled test environment. They might run the `ProcessBufferedCHLOsOnEpollin` test specifically to confirm whether the buffering and processing of CHLOs are functioning as expected.

This detailed breakdown illustrates the thought process of understanding the provided C++ code by analyzing its structure, dependencies, test cases, and potential implications. It also connects the local scope of the file to the broader context of a QUIC server implementation and its interaction with clients (including those potentially using JavaScript).
这个文件 `net/third_party/quiche/src/quiche/quic/tools/quic_server_test.cc` 是 Chromium 网络栈中 QUIC 协议服务器端的单元测试代码。它主要用于测试 `quiche/quic/tools/quic_server.h` 中定义的 `QuicServer` 类的功能。

下面详细列举一下它的功能：

**1. `QuicServer` 类的单元测试:**

   -  **测试服务器的启动和监听:** 验证 `QuicServer` 是否能正确创建 UDP socket 并开始监听指定的地址和端口。
   -  **测试连接处理:**  模拟客户端发起连接请求（Client Hello，CHLO），验证服务器是否能正确接收和处理这些请求，包括创建新的 QUIC 连接。
   -  **测试数据包分发 (Dispatching):** 验证服务器接收到数据包后，能否正确地将其分发到相应的连接进行处理。
   -  **测试事件循环 (Event Loop) 集成:**  测试服务器如何与底层的事件循环机制（例如 Epoll）集成，以及如何响应 I/O 事件，例如接收到新的数据包。
   -  **测试加密配置 (Crypto Configuration):** 验证服务器使用的加密配置是否正确。

**2. 具体测试用例分析:**

   -  **`MockQuicSimpleDispatcher`:**  这是一个 Mock 类，用于模拟 `QuicSimpleDispatcher` 的行为。通过 Mock 对象，可以隔离 `QuicServer` 的测试，只关注其自身的逻辑，而不需要真正运行复杂的 Dispatcher 代码。它可以用来验证 `QuicServer` 是否正确地调用了 Dispatcher 的方法，例如 `OnCanWrite`， `ProcessBufferedChlos` 等。
   -  **`TestQuicServer`:** 这是一个继承自 `QuicServer` 的测试类，允许在测试环境中定制和控制服务器的行为，例如替换默认的 Dispatcher 实现。
   -  **`QuicServerEpollInTest`:**  这个测试套件主要测试服务器在接收到 EPOLLIN 事件时的行为，特别是处理缓存的 Client Hello (CHLO) 请求。
      -  **`ProcessBufferedCHLOsOnEpollin`:**  这个具体的测试用例模拟了服务器接收到包含 CHLO 的数据包，然后触发 EPOLLIN 事件。它验证了服务器是否会在 EPOLLIN 事件中尝试创建连接来处理这些缓存的 CHLO，并且如果还有未处理的 CHLO，是否会继续注册 EPOLLIN 事件。
   -  **`QuicServerDispatchPacketTest`:**  这个测试套件主要测试 `QuicServer` 的数据包分发功能。
      -  **`DispatchPacket`:**  这个测试用例构造了一个合法的 QUIC 数据包，并调用 `QuicServer` 的数据包分发方法。它验证了 `QuicServer` 是否正确地调用了 `MockQuicDispatcher` 的 `ProcessPacket` 方法。

**3. 与 JavaScript 的关系：**

   虽然这个 C++ 测试文件本身不包含 JavaScript 代码，但它测试的 QUIC 服务器是 Web 技术栈的重要组成部分，与 JavaScript 有着密切的关系。

   **举例说明：**

   -   当用户在 Chrome 浏览器（或其他支持 QUIC 的浏览器）中访问一个使用 QUIC 协议的网站时，浏览器中的 JavaScript 代码会发起 HTTP/3 请求，而底层的网络层会使用 QUIC 协议与服务器建立连接并传输数据。
   -   这个测试文件验证的 `QuicServer` 的功能，正是服务器端处理这些来自浏览器的 QUIC 连接和数据的基础。
   -   例如，当浏览器发送一个包含 HTTP/3 请求的 QUIC 数据包时，`QuicServer` 需要能够正确地接收、解密、并将其传递给更高层的 HTTP/3 处理逻辑。这个测试文件中的 `DispatchPacket` 测试用例就在模拟这个过程。

**4. 逻辑推理、假设输入与输出：**

   **`ProcessBufferedCHLOsOnEpollin` 测试用例：**

   -   **假设输入：**
      -   服务器已启动并监听。
      -   客户端发送一个包含 Client Hello (CHLO) 的 UDP 数据包到服务器。
      -   服务器的事件循环接收到 EPOLLIN 事件。
   -   **逻辑推理：**
      -   服务器接收到包含 CHLO 的数据包，但可能因为资源限制或其他原因暂时无法立即创建连接。
      -   CHLO 被缓存起来。
      -   EPOLLIN 事件触发，服务器应该检查是否有缓存的 CHLO 需要处理。
      -   服务器尝试处理缓存的 CHLO，如果成功创建一部分连接，但还有剩余的 CHLO 未处理。
      -   服务器应该继续注册 EPOLLIN 事件，以便在下一个事件循环中继续处理剩余的 CHLO。
   -   **假设输出：**
      -   `MockQuicSimpleDispatcher::ProcessBufferedChlos()` 方法会被调用多次，每次处理一部分 CHLO。
      -   `MockQuicSimpleDispatcher::HasChlosBuffered()` 方法在第一次调用后返回 `true`，表示还有缓存的 CHLO，第二次调用后返回 `false`，表示 CHLO 已全部处理完毕。

   **`DispatchPacket` 测试用例：**

   -   **假设输入：**
      -   服务器正在运行。
      -   接收到一个精心构造的、合法的 QUIC 数据包（例如示例中的 `valid_packet`）。
   -   **逻辑推理：**
      -   服务器需要识别数据包的目标连接（如果已建立连接）。
      -   如果尚未建立连接，则根据数据包的头部信息进行初步处理。
      -   最终，数据包应该被传递给负责处理该连接的组件。
   -   **假设输出：**
      -   `MockQuicDispatcher::ProcessPacket()` 方法会被调用一次，并将接收到的数据包作为参数传递进去。

**5. 涉及用户或编程常见的使用错误：**

   -   **服务器未正确绑定地址或端口：**  如果服务器的配置错误，例如监听了错误的 IP 地址或端口，客户端将无法连接。这个测试文件通过验证服务器的启动和监听功能，可以帮助发现这类错误。
   -   **防火墙阻止连接：**  尽管这不是代码错误，但部署环境中的防火墙可能会阻止客户端连接到服务器的 UDP 端口。调试时需要检查防火墙规则。
   -   **加密配置错误：**  QUIC 的握手过程涉及到加密协商。如果服务器的加密配置不正确（例如，缺少必要的证书），客户端可能无法完成握手。这个测试文件虽然使用了测试用的加密配置，但可以作为验证加密配置流程的基础。
   -   **资源限制导致无法创建连接：**  在高并发场景下，服务器可能因为资源耗尽（例如，达到最大连接数限制）而无法接受新的连接。`ProcessBufferedCHLOsOnEpollin` 测试用例间接测试了服务器处理连接请求的能力，可以帮助发现与资源管理相关的潜在问题。
   -   **事件循环配置错误：** 如果底层的事件循环机制配置不当，服务器可能无法及时响应 I/O 事件，导致连接建立延迟或数据传输中断。`QuicServerEpollInTest` 测试套件可以帮助验证事件循环的集成是否正确。

**6. 用户操作如何一步步地到达这里，作为调试线索：**

   假设用户在使用基于 Chromium 的浏览器访问一个使用 QUIC 协议的网站时遇到了连接问题，例如网页加载缓慢或连接中断。以下是一些可能的调试步骤，最终可能会引导开发人员查看 `quic_server_test.cc`：

   1. **用户报告问题：** 用户反馈网站访问异常。
   2. **初步排查网络：** 检查用户本地网络连接是否正常。
   3. **使用浏览器开发者工具：**  开发者可以通过 Chrome 的开发者工具 (F12) 的 "Network" 选项卡查看网络请求的详细信息，包括是否使用了 QUIC 协议，以及连接建立的时间和状态。
   4. **查看 Chrome 的内部 QUIC 信息：** 在 Chrome 浏览器中访问 `chrome://net-internals/#quic` 可以查看当前 QUIC 连接的状态、会话信息、以及发生的错误。
   5. **服务端日志分析：**  如果问题出在服务器端，需要查看服务器的日志，例如是否有连接错误、握手失败、或数据传输异常的记录。
   6. **代码调试 (如果拥有服务器代码)：**  如果开发者可以访问服务器的源代码，可能会设置断点来跟踪 QUIC 连接的建立过程，例如在 `QuicServer::ProcessPacket()` 或 `QuicSimpleDispatcher::ProcessBufferedChlos()` 等关键函数中。
   7. **查看单元测试：** 为了理解服务器的预期行为以及如何正确处理连接请求，开发者可能会查看 `quic_server_test.cc` 这样的单元测试文件。这可以帮助他们：
      -   理解 `QuicServer` 的核心功能和设计。
      -   查看测试用例如何模拟客户端请求。
      -   了解如何使用 Mock 对象来隔离和测试特定的功能。
      -   验证自己的代码修改是否符合预期行为，或者是否引入了新的错误。

总而言之，`net/third_party/quiche/src/quiche/quic/tools/quic_server_test.cc` 是 QUIC 服务器端的核心测试文件，用于确保服务器能够正确地处理连接、分发数据包，并与底层的网络和事件循环机制良好地集成。理解这个文件的内容对于开发和调试 QUIC 相关的应用至关重要。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/tools/quic_server_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quic_server.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/base/macros.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/deterministic_connection_id_generator.h"
#include "quiche/quic/core/io/quic_default_event_loop.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/quic_default_clock.h"
#include "quiche/quic/core/quic_default_connection_helper.h"
#include "quiche/quic/core/quic_default_packet_writer.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/platform/api/quic_test_loopback.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/mock_quic_dispatcher.h"
#include "quiche/quic/test_tools/quic_server_peer.h"
#include "quiche/quic/tools/quic_memory_cache_backend.h"
#include "quiche/quic/tools/quic_simple_crypto_server_stream_helper.h"

namespace quic {
namespace test {

using ::testing::_;

namespace {

class MockQuicSimpleDispatcher : public QuicSimpleDispatcher {
 public:
  MockQuicSimpleDispatcher(
      const QuicConfig* config, const QuicCryptoServerConfig* crypto_config,
      QuicVersionManager* version_manager,
      std::unique_ptr<QuicConnectionHelperInterface> helper,
      std::unique_ptr<QuicCryptoServerStreamBase::Helper> session_helper,
      std::unique_ptr<QuicAlarmFactory> alarm_factory,
      QuicSimpleServerBackend* quic_simple_server_backend,
      ConnectionIdGeneratorInterface& generator)
      : QuicSimpleDispatcher(config, crypto_config, version_manager,
                             std::move(helper), std::move(session_helper),
                             std::move(alarm_factory),
                             quic_simple_server_backend,
                             kQuicDefaultConnectionIdLength, generator) {}
  ~MockQuicSimpleDispatcher() override = default;

  MOCK_METHOD(void, OnCanWrite, (), (override));
  MOCK_METHOD(bool, HasPendingWrites, (), (const, override));
  MOCK_METHOD(bool, HasChlosBuffered, (), (const, override));
  MOCK_METHOD(void, ProcessBufferedChlos, (size_t), (override));
};

class TestQuicServer : public QuicServer {
 public:
  explicit TestQuicServer(QuicEventLoopFactory* event_loop_factory,
                          QuicMemoryCacheBackend* quic_simple_server_backend)
      : QuicServer(crypto_test_utils::ProofSourceForTesting(),
                   quic_simple_server_backend),
        quic_simple_server_backend_(quic_simple_server_backend),
        event_loop_factory_(event_loop_factory) {}

  ~TestQuicServer() override = default;

  MockQuicSimpleDispatcher* mock_dispatcher() { return mock_dispatcher_; }

 protected:
  QuicDispatcher* CreateQuicDispatcher() override {
    mock_dispatcher_ = new MockQuicSimpleDispatcher(
        &config(), &crypto_config(), version_manager(),
        std::make_unique<QuicDefaultConnectionHelper>(),
        std::unique_ptr<QuicCryptoServerStreamBase::Helper>(
            new QuicSimpleCryptoServerStreamHelper()),
        event_loop()->CreateAlarmFactory(), quic_simple_server_backend_,
        connection_id_generator());
    return mock_dispatcher_;
  }

  std::unique_ptr<QuicEventLoop> CreateEventLoop() override {
    return event_loop_factory_->Create(QuicDefaultClock::Get());
  }

  MockQuicSimpleDispatcher* mock_dispatcher_ = nullptr;
  QuicMemoryCacheBackend* quic_simple_server_backend_;
  QuicEventLoopFactory* event_loop_factory_;
};

class QuicServerEpollInTest : public QuicTestWithParam<QuicEventLoopFactory*> {
 public:
  QuicServerEpollInTest()
      : server_address_(TestLoopback(), 0),
        server_(GetParam(), &quic_simple_server_backend_) {}

  void StartListening() {
    server_.CreateUDPSocketAndListen(server_address_);
    server_address_ = QuicSocketAddress(server_address_.host(), server_.port());

    ASSERT_TRUE(QuicServerPeer::SetSmallSocket(&server_));

    if (!server_.overflow_supported()) {
      QUIC_LOG(WARNING) << "Overflow not supported.  Not testing.";
      return;
    }
  }

 protected:
  QuicSocketAddress server_address_;
  QuicMemoryCacheBackend quic_simple_server_backend_;
  TestQuicServer server_;
};

std::string GetTestParamName(
    ::testing::TestParamInfo<QuicEventLoopFactory*> info) {
  return EscapeTestParamName(info.param->GetName());
}

INSTANTIATE_TEST_SUITE_P(QuicServerEpollInTests, QuicServerEpollInTest,
                         ::testing::ValuesIn(GetAllSupportedEventLoops()),
                         GetTestParamName);

// Tests that if dispatcher has CHLOs waiting for connection creation, EPOLLIN
// event should try to create connections for them. And set epoll mask with
// EPOLLIN if there are still CHLOs remaining at the end of epoll event.
TEST_P(QuicServerEpollInTest, ProcessBufferedCHLOsOnEpollin) {
  // Given an EPOLLIN event, try to create session for buffered CHLOs. In first
  // event, dispatcher can't create session for all of CHLOs. So listener should
  // register another EPOLLIN event by itself. Even without new packet arrival,
  // the rest CHLOs should be process in next epoll event.
  StartListening();
  bool more_chlos = true;
  MockQuicSimpleDispatcher* dispatcher_ = server_.mock_dispatcher();
  QUICHE_DCHECK(dispatcher_ != nullptr);
  EXPECT_CALL(*dispatcher_, OnCanWrite()).Times(testing::AnyNumber());
  EXPECT_CALL(*dispatcher_, ProcessBufferedChlos(_)).Times(2);
  EXPECT_CALL(*dispatcher_, HasPendingWrites()).Times(testing::AnyNumber());
  // Expect there are still CHLOs buffered after 1st event. But not any more
  // after 2nd event.
  EXPECT_CALL(*dispatcher_, HasChlosBuffered())
      .WillOnce(testing::Return(true))
      .WillOnce(
          DoAll(testing::Assign(&more_chlos, false), testing::Return(false)));

  // Send a packet to trigger epoll event.
  QuicUdpSocketApi socket_api;
  SocketFd fd =
      socket_api.Create(server_address_.host().AddressFamilyToInt(),
                        /*receive_buffer_size =*/kDefaultSocketReceiveBuffer,
                        /*send_buffer_size =*/kDefaultSocketReceiveBuffer);
  ASSERT_NE(fd, kQuicInvalidSocketFd);

  char buf[1024];
  memset(buf, 0, ABSL_ARRAYSIZE(buf));
  QuicUdpPacketInfo packet_info;
  packet_info.SetPeerAddress(server_address_);
  WriteResult result =
      socket_api.WritePacket(fd, buf, sizeof(buf), packet_info);
  if (result.status != WRITE_STATUS_OK) {
    QUIC_LOG(ERROR) << "Write error for UDP packet: " << result.error_code;
  }

  while (more_chlos) {
    server_.WaitForEvents();
  }
}

class QuicServerDispatchPacketTest : public QuicTest {
 public:
  QuicServerDispatchPacketTest()
      : crypto_config_("blah", QuicRandom::GetInstance(),
                       crypto_test_utils::ProofSourceForTesting(),
                       KeyExchangeSource::Default()),
        version_manager_(AllSupportedVersions()),
        event_loop_(GetDefaultEventLoop()->Create(QuicDefaultClock::Get())),
        connection_id_generator_(kQuicDefaultConnectionIdLength),
        dispatcher_(&config_, &crypto_config_, &version_manager_,
                    std::make_unique<QuicDefaultConnectionHelper>(),
                    std::make_unique<QuicSimpleCryptoServerStreamHelper>(),
                    event_loop_->CreateAlarmFactory(),
                    &quic_simple_server_backend_, connection_id_generator_) {
    dispatcher_.InitializeWithWriter(new QuicDefaultPacketWriter(1234));
  }

  void DispatchPacket(const QuicReceivedPacket& packet) {
    QuicSocketAddress client_addr, server_addr;
    dispatcher_.ProcessPacket(server_addr, client_addr, packet);
  }

 protected:
  QuicConfig config_;
  QuicCryptoServerConfig crypto_config_;
  QuicVersionManager version_manager_;
  std::unique_ptr<QuicEventLoop> event_loop_;
  QuicMemoryCacheBackend quic_simple_server_backend_;
  DeterministicConnectionIdGenerator connection_id_generator_;
  MockQuicDispatcher dispatcher_;
};

TEST_F(QuicServerDispatchPacketTest, DispatchPacket) {
  // clang-format off
  unsigned char valid_packet[] = {
    // public flags (8 byte connection_id)
    0x3C,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // private flags
    0x00
  };
  // clang-format on
  QuicReceivedPacket encrypted_valid_packet(
      reinterpret_cast<char*>(valid_packet), ABSL_ARRAYSIZE(valid_packet),
      QuicTime::Zero(), false);

  EXPECT_CALL(dispatcher_, ProcessPacket(_, _, _)).Times(1);
  DispatchPacket(encrypted_valid_packet);
}

}  // namespace
}  // namespace test
}  // namespace quic

"""

```