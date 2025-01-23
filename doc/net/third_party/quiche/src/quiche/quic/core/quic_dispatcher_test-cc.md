Response:
The user wants to understand the functionality of the Chromium network stack source code file `net/third_party/quiche/src/quiche/quic/core/quic_dispatcher_test.cc`.

Here's a breakdown of how to address the user's request:

1. **Identify the core purpose of the file:**  The name `quic_dispatcher_test.cc` strongly suggests this file contains unit tests for the `QuicDispatcher` class.

2. **Analyze the included headers:** The headers provide clues about the functionalities being tested. Look for key classes and concepts related to the `QuicDispatcher`.

3. **Examine the test structure:** The file uses the Google Test framework. Identify the test fixtures (classes inheriting from `QuicTestWithParam`) and individual test cases (using `TEST_P`).

4. **Focus on the tests related to `QuicDispatcher` methods:**  Look for tests that directly interact with or verify the behavior of `QuicDispatcher`'s public methods.

5. **Consider the context of `QuicDispatcher`:**  Remember that the `QuicDispatcher` is responsible for handling incoming QUIC connections and dispatching packets to the appropriate sessions.

6. **Address the specific questions:**
    * **Functionality:** Summarize the main purpose of the tests.
    * **JavaScript relationship:**  While this C++ code is low-level, think about how QUIC as a protocol impacts JavaScript in web browsers (e.g., faster page loads).
    * **Logical reasoning (Input/Output):**  For specific test cases, infer the setup (input) and the expected behavior/assertions (output).
    * **User/programming errors:**  Think about common mistakes when configuring or using a QUIC server, and how these tests might catch such errors.
    * **User operation and debugging:** Describe a sequence of user actions that would lead to this code being executed and how a developer might use these tests for debugging.
    * **Summary of Part 1:** Condense the findings into a concise summary.

**Pre-computation/Analysis of the provided code snippet:**

* **Includes:** The headers reveal dependencies on core QUIC components like:
    * `QuicDispatcher`: The class being tested.
    * `QuicConnection`, `QuicSession`:  Representing individual QUIC connections.
    * `QuicCryptoServerConfig`, `QuicCryptoClientConfig`:  Handling cryptographic setup.
    * `QuicPacketWriter`:  Sending QUIC packets.
    * `QuicVersionManager`: Managing supported QUIC versions.
    * `QuicTimeWaitListManager`: Handling connection termination.
    * `ChloExtractor`: Extracting ClientHello messages.
    * Test utilities (`quic_test_utils.h`, `mock_...`).
* **Test Fixtures:** The code defines several test fixtures parameterized by QUIC versions (`QuicDispatcherTestAllVersions`, `QuicDispatcherTestOneVersion`). This indicates thorough testing across different versions.
* **Mocking:** The extensive use of `NiceMock` suggests that the tests isolate the `QuicDispatcher` by mocking its dependencies.
* **Key Mocked Methods (from the snippet):**
    * `CreateQuicSession`: Verifies the creation of new sessions.
    * `ProcessUdpPacket`: Simulates receiving UDP packets.
    * `ConnectionIdGenerator`: Tests the connection ID handling logic.
* **Specific Test Cases (from the snippet):**
    * `TlsClientHelloCreatesSession`: Tests successful session creation upon receiving a ClientHello.
    * `VariableServerConnectionIdLength`: Tests handling of variable-length connection IDs.
    * `TestTlsMultiPacketClientHello`:  Focuses on handling ClientHello messages that span multiple packets.

**Final Plan:**  Structure the answer by addressing each of the user's questions systematically, drawing on the analysis of the code snippet and the understanding of QUIC's architecture. Provide concrete examples and clear explanations.
这个文件 `net/third_party/quiche/src/quiche/quic/core/quic_dispatcher_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，其主要功能是 **测试 `QuicDispatcher` 类的各项功能**。`QuicDispatcher` 在 QUIC 服务器端扮演着核心角色，负责接收传入的 QUIC 连接请求，并将数据包分发到相应的 `QuicSession` 进行处理。

以下是根据提供的代码片段对该文件功能的详细列举：

**核心功能：测试 `QuicDispatcher` 的行为**

* **会话创建 (Session Creation):**
    * 测试 `QuicDispatcher` 能否在收到客户端的连接请求（例如，包含 TLS ClientHello 的数据包）时正确创建新的 `QuicSession` 对象。
    * 测试会话创建过程中是否使用了正确的配置（`QuicConfig`）、加密配置（`QuicCryptoServerConfig`）、连接 ID 生成器（`ConnectionIdGeneratorInterface`）等。
    * 针对不同的 QUIC 版本（通过 `QuicVersionManager` 管理）测试会话创建的兼容性。
* **数据包分发 (Packet Dispatching):**
    * 测试 `QuicDispatcher` 能否根据数据包中的连接 ID 正确地将接收到的数据包分发到已存在的 `QuicSession` 进行处理。
    * 测试当接收到属于新连接的数据包时，`QuicDispatcher` 能否识别并创建新的会话。
    * 测试对于无法解密的早期数据包（例如，Early Data），`QuicDispatcher` 的处理逻辑。
* **连接 ID 管理 (Connection ID Management):**
    * 测试 `QuicDispatcher` 如何处理和管理连接 ID，包括新连接 ID 的分配、连接 ID 的退休（Retire）、以及活动连接 ID 的跟踪。
    * 测试当服务器端发起连接 ID 变更时，`QuicDispatcher` 的行为。
    * 测试长连接 ID 和短连接 ID 的处理。
* **版本协商 (Version Negotiation):**
    * 测试当客户端提出的 QUIC 版本与服务器支持的版本不一致时，`QuicDispatcher` 是否能正确地发送版本协商数据包。
* **连接关闭 (Connection Closure):**
    * 测试当连接关闭时，`QuicDispatcher` 能否正确地清理资源，例如移除已关闭的会话。
    * 测试 Time Wait 状态的管理，确保在连接关闭后一段时间内不会接受使用相同连接 ID 的新连接。
* **数据包上下文 (Per-Packet Context):**
    * 测试 `QuicDispatcher` 如何管理和恢复每个数据包的上下文信息。
* **多数据包 ClientHello (Multi-Packet ClientHello):**
    * 测试 `QuicDispatcher` 能否正确处理跨越多个数据包的 TLS ClientHello 消息。
* **连接限制 (Connection Limits):**
    * 测试 `QuicDispatcher` 如何控制最大连接数，防止资源耗尽。
* **ALPN 处理 (ALPN Handling):**
    * 测试 `QuicDispatcher` 在会话创建时是否正确处理应用层协议协商（ALPN）。

**与 JavaScript 的关系：**

虽然此文件是 C++ 代码，直接与 JavaScript 无关，但 `QuicDispatcher` 作为 QUIC 服务器的核心组件，其功能直接影响到基于 QUIC 协议的 Web 应用的性能和稳定性，而这些 Web 应用通常通过浏览器中的 JavaScript 代码进行交互。

**举例说明：**

当用户在浏览器中访问一个使用 QUIC 协议的网站时：

1. **用户操作：** 用户在浏览器地址栏输入网址并回车。
2. **网络请求：** 浏览器发起一个 HTTP/3 (基于 QUIC) 的请求。
3. **连接建立：** 浏览器发送一个包含 ClientHello 的 QUIC 数据包到服务器。
4. **`QuicDispatcher` 的作用：** 服务器端的 `QuicDispatcher` 接收到这个数据包。
5. **测试中的验证：**  `TlsClientHelloCreatesSession` 测试用例模拟了这一过程，验证 `QuicDispatcher` 是否能正确解析 ClientHello，并创建一个新的 `QuicSession` 来处理这个连接。
6. **后续处理：**  `QuicDispatcher` 将后续属于该连接的数据包分发到创建的 `QuicSession` 进行处理，最终将服务器的响应数据返回给浏览器。

**逻辑推理（假设输入与输出）：**

* **假设输入：**
    * 接收到一个包含有效 TLS ClientHello 的 UDP 数据包，目标连接 ID 为 `TestConnectionId(1)`。
    * 服务器当前没有与 `TestConnectionId(1)` 关联的活跃会话。
    * 服务器支持客户端在 ClientHello 中声明的 QUIC 版本和 ALPN。
* **预期输出：**
    * `QuicDispatcher` 会调用 `CreateQuicSession` 方法创建一个新的 `QuicSession` 对象。
    * 创建的 `QuicSession` 会与接收到的连接 ID (`TestConnectionId(1)`) 关联。
    * 随后属于该连接的数据包会被路由到新创建的 `QuicSession` 进行处理。

**用户或编程常见的使用错误：**

* **服务器配置错误：**
    * **错误配置的证书或密钥：** 如果服务器的加密配置（`QuicCryptoServerConfig`）不正确，`QuicDispatcher` 在处理 ClientHello 时可能会失败，导致连接建立失败。 测试用例会验证这种情况下的行为。
    * **不支持的 QUIC 版本或 ALPN：** 如果服务器没有配置支持客户端请求的 QUIC 版本或应用层协议，`QuicDispatcher` 可能无法创建会话或会发送版本协商消息。 测试用例会覆盖这些情况。
* **连接 ID 冲突：**
    * 如果服务器端错误地分配了已被使用的连接 ID，可能会导致数据包路由错误或连接冲突。 连接 ID 管理相关的测试用例旨在发现这类问题。
* **资源限制不足：**
    * 如果服务器没有正确设置最大连接数限制，可能会导致 `QuicDispatcher` 尝试创建过多连接而耗尽资源。  虽然代码片段中没有直接体现资源限制的测试，但 `kMaxNumSessionsToCreate` 常量暗示了这方面的考虑。
* **网络问题：**
    * 数据包乱序或丢失可能会影响多数据包 ClientHello 的处理。 `TestTlsMultiPacketClientHello` 测试用例专门针对这种情况进行测试。

**用户操作如何一步步到达这里作为调试线索：**

假设一个开发者在调试一个 QUIC 服务器端的问题，例如，客户端无法连接到服务器。以下是可能的调试步骤：

1. **用户操作：** 客户端尝试连接服务器，但连接失败。
2. **服务器端日志：** 查看服务器端的日志，可能会发现与 `QuicDispatcher` 相关的错误信息，例如无法解析 ClientHello，或者找不到对应的会话。
3. **设置断点：** 开发者可能会在 `QuicDispatcher::ProcessPacket` 或 `QuicDispatcher::CreateQuicSession` 等关键方法上设置断点，以便观察数据包的处理流程和会话创建过程。
4. **运行测试：** 开发者可以运行 `quic_dispatcher_test.cc` 中的相关测试用例，例如 `TlsClientHelloCreatesSession`，来验证 `QuicDispatcher` 在正常情况下的行为。如果测试失败，可以帮助定位 `QuicDispatcher` 内部的 bug。
5. **单步调试：** 如果测试失败，开发者可以单步调试测试用例，例如 `ProcessFirstFlight` 函数，观察数据包是如何被构建、发送和接收的，以及 `QuicDispatcher` 是如何处理这些数据包的。
6. **分析变量：** 开发者可以检查 `QuicDispatcher` 内部的状态，例如活跃会话列表、连接 ID 映射等，来理解连接失败的原因。
7. **修改代码并重新测试：** 根据调试结果修改 `QuicDispatcher` 或相关代码，并重新运行测试用例，确保修复了问题。

**这是第1部分，共5部分，请归纳一下它的功能:**

这部分代码主要定义了用于测试 `QuicDispatcher` 类的基础架构和一些核心测试用例。

**主要功能归纳：**

* **测试环境搭建：**  定义了测试用的 `MockQuicConnectionHelper`、`MockAlarmFactory`、`MockPacketWriter` 等模拟对象，以及 `TestDispatcher` 继承自 `QuicDispatcher` 用于方便测试。
* **基础测试类：**  定义了 `QuicDispatcherTestBase` 作为所有 `QuicDispatcher` 测试用例的基类，提供了通用的测试辅助方法，例如创建和处理数据包、创建会话、验证数据包等。
* **版本兼容性测试：** 通过参数化测试框架（`QuicTestWithParam`）支持针对不同 QUIC 版本的测试。
* **核心功能测试用例示例：**  包含了 `TlsClientHelloCreatesSession` 和 `VariableServerConnectionIdLength` 等测试用例，用于验证 `QuicDispatcher` 在接收到 ClientHello 时创建会话以及处理变长连接 ID 的能力。

总而言之，这部分代码为后续更全面的 `QuicDispatcher` 功能测试奠定了基础，并展示了如何测试其核心功能，例如会话创建和连接 ID 处理。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_dispatcher_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_dispatcher.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>


#include "absl/base/macros.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/chlo_extractor.h"
#include "quiche/quic/core/connection_id_generator.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/crypto/quic_compressed_certs_cache.h"
#include "quiche/quic/core/crypto/quic_crypto_client_config.h"
#include "quiche/quic/core/crypto/quic_crypto_server_config.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/crypto/transport_parameters.h"
#include "quiche/quic/core/frames/quic_connection_close_frame.h"
#include "quiche/quic/core/http/quic_server_session_base.h"
#include "quiche/quic/core/http/quic_spdy_stream.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_crypto_server_stream_base.h"
#include "quiche/quic/core/quic_crypto_stream.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_packet_writer.h"
#include "quiche/quic/core/quic_packet_writer_wrapper.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_stream.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_time_wait_list_manager.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_version_manager.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/first_flight.h"
#include "quiche/quic/test_tools/mock_connection_id_generator.h"
#include "quiche/quic/test_tools/mock_quic_time_wait_list_manager.h"
#include "quiche/quic/test_tools/quic_buffered_packet_store_peer.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/quic/test_tools/quic_dispatcher_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/tools/quic_simple_crypto_server_stream_helper.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/test_tools/quiche_test_utils.h"

using testing::_;
using testing::AllOf;
using testing::ByMove;
using testing::ElementsAreArray;
using testing::Eq;
using testing::Field;
using testing::InSequence;
using testing::Invoke;
using testing::IsEmpty;
using testing::NiceMock;
using testing::Not;
using testing::Ref;
using testing::Return;
using testing::ReturnRef;
using testing::WithArg;
using testing::WithoutArgs;

static const size_t kDefaultMaxConnectionsInStore = 100;
static const size_t kMaxConnectionsWithoutCHLO =
    kDefaultMaxConnectionsInStore / 2;
static const int16_t kMaxNumSessionsToCreate = 16;

namespace quic {
namespace test {
namespace {

const QuicConnectionId kReturnConnectionId{
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}};

class TestQuicSpdyServerSession : public QuicServerSessionBase {
 public:
  TestQuicSpdyServerSession(const QuicConfig& config,
                            QuicConnection* connection,
                            const QuicCryptoServerConfig* crypto_config,
                            QuicCompressedCertsCache* compressed_certs_cache)
      : QuicServerSessionBase(config, CurrentSupportedVersions(), connection,
                              nullptr, nullptr, crypto_config,
                              compressed_certs_cache) {
    Initialize();
  }
  TestQuicSpdyServerSession(const TestQuicSpdyServerSession&) = delete;
  TestQuicSpdyServerSession& operator=(const TestQuicSpdyServerSession&) =
      delete;

  ~TestQuicSpdyServerSession() override { DeleteConnection(); }

  MOCK_METHOD(void, OnConnectionClosed,
              (const QuicConnectionCloseFrame& frame,
               ConnectionCloseSource source),
              (override));
  MOCK_METHOD(QuicSpdyStream*, CreateIncomingStream, (QuicStreamId id),
              (override));
  MOCK_METHOD(QuicSpdyStream*, CreateIncomingStream, (PendingStream*),
              (override));
  MOCK_METHOD(QuicSpdyStream*, CreateOutgoingBidirectionalStream, (),
              (override));
  MOCK_METHOD(QuicSpdyStream*, CreateOutgoingUnidirectionalStream, (),
              (override));

  std::unique_ptr<QuicCryptoServerStreamBase> CreateQuicCryptoServerStream(
      const QuicCryptoServerConfig* crypto_config,
      QuicCompressedCertsCache* compressed_certs_cache) override {
    return CreateCryptoServerStream(crypto_config, compressed_certs_cache, this,
                                    stream_helper());
  }

  QuicCryptoServerStreamBase::Helper* stream_helper() {
    return QuicServerSessionBase::stream_helper();
  }
};

class TestDispatcher : public QuicDispatcher {
 public:
  TestDispatcher(const QuicConfig* config,
                 const QuicCryptoServerConfig* crypto_config,
                 QuicVersionManager* version_manager, QuicRandom* random,
                 ConnectionIdGeneratorInterface& generator)
      : QuicDispatcher(config, crypto_config, version_manager,
                       std::make_unique<MockQuicConnectionHelper>(),
                       std::unique_ptr<QuicCryptoServerStreamBase::Helper>(
                           new QuicSimpleCryptoServerStreamHelper()),
                       std::make_unique<TestAlarmFactory>(),
                       kQuicDefaultConnectionIdLength, generator),
        random_(random) {
    EXPECT_CALL(*this, ConnectionIdGenerator())
        .WillRepeatedly(ReturnRef(generator));
  }

  MOCK_METHOD(std::unique_ptr<QuicSession>, CreateQuicSession,
              (QuicConnectionId connection_id,
               const QuicSocketAddress& self_address,
               const QuicSocketAddress& peer_address, absl::string_view alpn,
               const ParsedQuicVersion& version,
               const ParsedClientHello& parsed_chlo,
               ConnectionIdGeneratorInterface& connection_id_generator),
              (override));
  MOCK_METHOD(ConnectionIdGeneratorInterface&, ConnectionIdGenerator, (),
              (override));

  struct TestQuicPerPacketContext : public QuicPerPacketContext {
    std::string custom_packet_context;
  };

  std::unique_ptr<QuicPerPacketContext> GetPerPacketContext() const override {
    auto test_context = std::make_unique<TestQuicPerPacketContext>();
    test_context->custom_packet_context = custom_packet_context_;
    return std::move(test_context);
  }

  void RestorePerPacketContext(
      std::unique_ptr<QuicPerPacketContext> context) override {
    TestQuicPerPacketContext* test_context =
        static_cast<TestQuicPerPacketContext*>(context.get());
    custom_packet_context_ = test_context->custom_packet_context;
  }

  std::string custom_packet_context_;

  using QuicDispatcher::ConnectionIdGenerator;
  using QuicDispatcher::MaybeDispatchPacket;
  using QuicDispatcher::writer;

  QuicRandom* random_;
};

// A Connection class which unregisters the session from the dispatcher when
// sending connection close.
// It'd be slightly more realistic to do this from the Session but it would
// involve a lot more mocking.
class MockServerConnection : public MockQuicConnection {
 public:
  MockServerConnection(QuicConnectionId connection_id,
                       MockQuicConnectionHelper* helper,
                       MockAlarmFactory* alarm_factory,
                       QuicDispatcher* dispatcher)
      : MockQuicConnection(connection_id, helper, alarm_factory,
                           Perspective::IS_SERVER),
        dispatcher_(dispatcher),
        active_connection_ids_({connection_id}) {}

  void AddNewConnectionId(QuicConnectionId id) {
    if (!dispatcher_->TryAddNewConnectionId(active_connection_ids_.back(),
                                            id)) {
      return;
    }
    QuicConnectionPeer::SetServerConnectionId(this, id);
    active_connection_ids_.push_back(id);
  }

  void UnconditionallyAddNewConnectionIdForTest(QuicConnectionId id) {
    dispatcher_->TryAddNewConnectionId(active_connection_ids_.back(), id);
    active_connection_ids_.push_back(id);
  }

  void RetireConnectionId(QuicConnectionId id) {
    auto it = std::find(active_connection_ids_.begin(),
                        active_connection_ids_.end(), id);
    QUICHE_DCHECK(it != active_connection_ids_.end());
    dispatcher_->OnConnectionIdRetired(id);
    active_connection_ids_.erase(it);
  }

  std::vector<QuicConnectionId> GetActiveServerConnectionIds() const override {
    std::vector<QuicConnectionId> result;
    for (const auto& cid : active_connection_ids_) {
      result.push_back(cid);
    }
    auto original_connection_id = GetOriginalDestinationConnectionId();
    if (std::find(result.begin(), result.end(), original_connection_id) ==
        result.end()) {
      result.push_back(original_connection_id);
    }
    return result;
  }

  void UnregisterOnConnectionClosed() {
    QUIC_LOG(ERROR) << "Unregistering " << connection_id();
    dispatcher_->OnConnectionClosed(connection_id(), QUIC_NO_ERROR,
                                    "Unregistering.",
                                    ConnectionCloseSource::FROM_SELF);
  }

 private:
  QuicDispatcher* dispatcher_;
  std::vector<QuicConnectionId> active_connection_ids_;
};

class QuicDispatcherTestBase : public QuicTestWithParam<ParsedQuicVersion> {
 public:
  QuicDispatcherTestBase()
      : QuicDispatcherTestBase(crypto_test_utils::ProofSourceForTesting()) {}

  explicit QuicDispatcherTestBase(std::unique_ptr<ProofSource> proof_source)
      : QuicDispatcherTestBase(std::move(proof_source),
                               AllSupportedVersions()) {}

  explicit QuicDispatcherTestBase(
      const ParsedQuicVersionVector& supported_versions)
      : QuicDispatcherTestBase(crypto_test_utils::ProofSourceForTesting(),
                               supported_versions) {}

  explicit QuicDispatcherTestBase(
      std::unique_ptr<ProofSource> proof_source,
      const ParsedQuicVersionVector& supported_versions)
      : version_(GetParam()),
        version_manager_(supported_versions),
        crypto_config_(QuicCryptoServerConfig::TESTING,
                       QuicRandom::GetInstance(), std::move(proof_source),
                       KeyExchangeSource::Default()),
        server_address_(QuicIpAddress::Any4(), 5),
        dispatcher_(new NiceMock<TestDispatcher>(
            &config_, &crypto_config_, &version_manager_,
            mock_helper_.GetRandomGenerator(), connection_id_generator_)),
        time_wait_list_manager_(nullptr),
        session1_(nullptr),
        session2_(nullptr),
        store_(nullptr),
        connection_id_(1) {}

  void SetUp() override {
    dispatcher_->InitializeWithWriter(new NiceMock<MockPacketWriter>());
    // Set the counter to some value to start with.
    QuicDispatcherPeer::set_new_sessions_allowed_per_event_loop(
        dispatcher_.get(), kMaxNumSessionsToCreate);
  }

  MockQuicConnection* connection1() {
    if (session1_ == nullptr) {
      return nullptr;
    }
    return reinterpret_cast<MockQuicConnection*>(session1_->connection());
  }

  MockQuicConnection* connection2() {
    if (session2_ == nullptr) {
      return nullptr;
    }
    return reinterpret_cast<MockQuicConnection*>(session2_->connection());
  }

  // Process a packet with an 8 byte connection id,
  // 6 byte packet number, default path id, and packet number 1,
  // using the version under test.
  void ProcessPacket(QuicSocketAddress peer_address,
                     QuicConnectionId server_connection_id,
                     bool has_version_flag, const std::string& data) {
    ProcessPacket(peer_address, server_connection_id, has_version_flag, data,
                  CONNECTION_ID_PRESENT, PACKET_4BYTE_PACKET_NUMBER);
  }

  // Process a packet with a default path id, and packet number 1,
  // using the version under test.
  void ProcessPacket(QuicSocketAddress peer_address,
                     QuicConnectionId server_connection_id,
                     bool has_version_flag, const std::string& data,
                     QuicConnectionIdIncluded server_connection_id_included,
                     QuicPacketNumberLength packet_number_length) {
    ProcessPacket(peer_address, server_connection_id, has_version_flag, data,
                  server_connection_id_included, packet_number_length, 1);
  }

  // Process a packet using the version under test.
  void ProcessPacket(QuicSocketAddress peer_address,
                     QuicConnectionId server_connection_id,
                     bool has_version_flag, const std::string& data,
                     QuicConnectionIdIncluded server_connection_id_included,
                     QuicPacketNumberLength packet_number_length,
                     uint64_t packet_number) {
    ProcessPacket(peer_address, server_connection_id, has_version_flag,
                  version_, data, true, server_connection_id_included,
                  packet_number_length, packet_number);
  }

  // Processes a packet.
  void ProcessPacket(QuicSocketAddress peer_address,
                     QuicConnectionId server_connection_id,
                     bool has_version_flag, ParsedQuicVersion version,
                     const std::string& data, bool full_padding,
                     QuicConnectionIdIncluded server_connection_id_included,
                     QuicPacketNumberLength packet_number_length,
                     uint64_t packet_number) {
    ProcessPacket(peer_address, server_connection_id, EmptyQuicConnectionId(),
                  has_version_flag, version, data, full_padding,
                  server_connection_id_included, CONNECTION_ID_ABSENT,
                  packet_number_length, packet_number);
  }

  // Processes a packet.
  void ProcessPacket(QuicSocketAddress peer_address,
                     QuicConnectionId server_connection_id,
                     QuicConnectionId client_connection_id,
                     bool has_version_flag, ParsedQuicVersion version,
                     const std::string& data, bool full_padding,
                     QuicConnectionIdIncluded server_connection_id_included,
                     QuicConnectionIdIncluded client_connection_id_included,
                     QuicPacketNumberLength packet_number_length,
                     uint64_t packet_number) {
    ParsedQuicVersionVector versions(SupportedVersions(version));
    std::unique_ptr<QuicEncryptedPacket> packet(ConstructEncryptedPacket(
        server_connection_id, client_connection_id, has_version_flag, false,
        packet_number, data, full_padding, server_connection_id_included,
        client_connection_id_included, packet_number_length, &versions));
    std::unique_ptr<QuicReceivedPacket> received_packet(
        ConstructReceivedPacket(*packet, mock_helper_.GetClock()->Now()));
    // Call ConnectionIdLength if the packet clears the Long Header bit, or
    // if the test involves sending a connection ID that is too short
    if (!has_version_flag || !version.AllowsVariableLengthConnectionIds() ||
        server_connection_id.length() == 0 ||
        server_connection_id_included == CONNECTION_ID_ABSENT) {
      // Short headers will ask for the length
      EXPECT_CALL(connection_id_generator_, ConnectionIdLength(_))
          .WillRepeatedly(Return(generated_connection_id_.has_value()
                                     ? generated_connection_id_->length()
                                     : kQuicDefaultConnectionIdLength));
    }
    ProcessReceivedPacket(std::move(received_packet), peer_address, version,
                          server_connection_id);
  }

  void ProcessReceivedPacket(
      std::unique_ptr<QuicReceivedPacket> received_packet,
      const QuicSocketAddress& peer_address, const ParsedQuicVersion& version,
      const QuicConnectionId& server_connection_id) {
    if (version.UsesQuicCrypto() &&
        ChloExtractor::Extract(*received_packet, version, {}, nullptr,
                               server_connection_id.length())) {
      // Add CHLO packet to the beginning to be verified first, because it is
      // also processed first by new session.
      data_connection_map_[server_connection_id].push_front(
          std::string(received_packet->data(), received_packet->length()));
    } else {
      // For non-CHLO, always append to last.
      data_connection_map_[server_connection_id].push_back(
          std::string(received_packet->data(), received_packet->length()));
    }
    dispatcher_->ProcessPacket(server_address_, peer_address, *received_packet);
  }

  void ValidatePacket(QuicConnectionId conn_id,
                      const QuicEncryptedPacket& packet) {
    EXPECT_EQ(data_connection_map_[conn_id].front().length(),
              packet.AsStringPiece().length());
    EXPECT_EQ(data_connection_map_[conn_id].front(), packet.AsStringPiece());
    data_connection_map_[conn_id].pop_front();
  }

  std::unique_ptr<QuicSession> CreateSession(
      TestDispatcher* dispatcher, const QuicConfig& config,
      QuicConnectionId connection_id, const QuicSocketAddress& /*peer_address*/,
      MockQuicConnectionHelper* helper, MockAlarmFactory* alarm_factory,
      const QuicCryptoServerConfig* crypto_config,
      QuicCompressedCertsCache* compressed_certs_cache,
      TestQuicSpdyServerSession** session_ptr) {
    MockServerConnection* connection = new MockServerConnection(
        connection_id, helper, alarm_factory, dispatcher);
    connection->SetQuicPacketWriter(dispatcher->writer(),
                                    /*owns_writer=*/false);
    auto session = std::make_unique<TestQuicSpdyServerSession>(
        config, connection, crypto_config, compressed_certs_cache);
    *session_ptr = session.get();
    connection->set_visitor(session.get());
    ON_CALL(*connection, CloseConnection(_, _, _))
        .WillByDefault(WithoutArgs(Invoke(
            connection, &MockServerConnection::UnregisterOnConnectionClosed)));
    return session;
  }

  void CreateTimeWaitListManager() {
    time_wait_list_manager_ = new MockTimeWaitListManager(
        QuicDispatcherPeer::GetWriter(dispatcher_.get()), dispatcher_.get(),
        mock_helper_.GetClock(), &mock_alarm_factory_);
    // dispatcher_ takes the ownership of time_wait_list_manager_.
    QuicDispatcherPeer::SetTimeWaitListManager(dispatcher_.get(),
                                               time_wait_list_manager_);
  }

  std::string SerializeCHLO() {
    CryptoHandshakeMessage client_hello;
    client_hello.set_tag(kCHLO);
    client_hello.SetStringPiece(kALPN, ExpectedAlpn());
    return std::string(client_hello.GetSerialized().AsStringPiece());
  }

  void ProcessUndecryptableEarlyPacket(
      const QuicSocketAddress& peer_address,
      const QuicConnectionId& server_connection_id) {
    ProcessUndecryptableEarlyPacket(version_, peer_address,
                                    server_connection_id);
  }

  void ProcessUndecryptableEarlyPacket(
      const ParsedQuicVersion& version, const QuicSocketAddress& peer_address,
      const QuicConnectionId& server_connection_id) {
    std::unique_ptr<QuicEncryptedPacket> encrypted_packet =
        GetUndecryptableEarlyPacket(version, server_connection_id);
    std::unique_ptr<QuicReceivedPacket> received_packet(ConstructReceivedPacket(
        *encrypted_packet, mock_helper_.GetClock()->Now()));
    ProcessReceivedPacket(std::move(received_packet), peer_address, version,
                          server_connection_id);
  }

  void ProcessFirstFlight(const QuicSocketAddress& peer_address,
                          const QuicConnectionId& server_connection_id) {
    ProcessFirstFlight(version_, peer_address, server_connection_id);
  }

  void ProcessFirstFlight(const ParsedQuicVersion& version,
                          const QuicSocketAddress& peer_address,
                          const QuicConnectionId& server_connection_id) {
    ProcessFirstFlight(version, peer_address, server_connection_id,
                       EmptyQuicConnectionId());
  }

  void ProcessFirstFlight(const ParsedQuicVersion& version,
                          const QuicSocketAddress& peer_address,
                          const QuicConnectionId& server_connection_id,
                          const QuicConnectionId& client_connection_id) {
    ProcessFirstFlight(version, peer_address, server_connection_id,
                       client_connection_id, TestClientCryptoConfig());
  }

  void ProcessFirstFlight(
      const ParsedQuicVersion& version, const QuicSocketAddress& peer_address,
      const QuicConnectionId& server_connection_id,
      const QuicConnectionId& client_connection_id,
      std::unique_ptr<QuicCryptoClientConfig> client_crypto_config) {
    if (expect_generator_is_called_) {
      if (version.AllowsVariableLengthConnectionIds()) {
        EXPECT_CALL(connection_id_generator_,
                    MaybeReplaceConnectionId(server_connection_id, version))
            .WillOnce(Return(generated_connection_id_));
      } else {
        EXPECT_CALL(connection_id_generator_,
                    MaybeReplaceConnectionId(server_connection_id, version))
            .WillOnce(Return(std::nullopt));
      }
    }
    std::vector<std::unique_ptr<QuicReceivedPacket>> packets =
        GetFirstFlightOfPackets(version, DefaultQuicConfig(),
                                server_connection_id, client_connection_id,
                                std::move(client_crypto_config));
    for (auto&& packet : packets) {
      ProcessReceivedPacket(std::move(packet), peer_address, version,
                            server_connection_id);
    }
  }

  std::unique_ptr<QuicCryptoClientConfig> TestClientCryptoConfig() {
    auto client_crypto_config = std::make_unique<QuicCryptoClientConfig>(
        crypto_test_utils::ProofVerifierForTesting());
    if (address_token_.has_value()) {
      client_crypto_config->LookupOrCreate(TestServerId())
          ->set_source_address_token(*address_token_);
    }
    return client_crypto_config;
  }

  // If called, the first flight packets generated in |ProcessFirstFlight| will
  // contain the given |address_token|.
  void SetAddressToken(std::string address_token) {
    address_token_ = std::move(address_token);
  }

  std::string ExpectedAlpnForVersion(ParsedQuicVersion version) {
    return AlpnForVersion(version);
  }

  std::string ExpectedAlpn() { return ExpectedAlpnForVersion(version_); }

  auto MatchParsedClientHello() {
    if (version_.UsesQuicCrypto()) {
      return AllOf(
          Field(&ParsedClientHello::alpns, ElementsAreArray({ExpectedAlpn()})),
          Field(&ParsedClientHello::sni, Eq(TestHostname())),
          Field(&ParsedClientHello::supported_groups, IsEmpty()));
    }
    return AllOf(
        Field(&ParsedClientHello::alpns, ElementsAreArray({ExpectedAlpn()})),
        Field(&ParsedClientHello::sni, Eq(TestHostname())),
        Field(&ParsedClientHello::supported_groups, Not(IsEmpty())));
  }

  void MarkSession1Deleted() { session1_ = nullptr; }

  void VerifyVersionSupported(ParsedQuicVersion version) {
    expect_generator_is_called_ = true;
    QuicConnectionId connection_id = TestConnectionId(++connection_id_);
    QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
    EXPECT_CALL(*dispatcher_,
                CreateQuicSession(connection_id, _, client_address,
                                  Eq(ExpectedAlpnForVersion(version)), _, _, _))
        .WillOnce(Return(ByMove(CreateSession(
            dispatcher_.get(), config_, connection_id, client_address,
            &mock_helper_, &mock_alarm_factory_, &crypto_config_,
            QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
    EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
                ProcessUdpPacket(_, _, _))
        .WillOnce(WithArg<2>(
            Invoke([this, connection_id](const QuicEncryptedPacket& packet) {
              ValidatePacket(connection_id, packet);
            })));
    ProcessFirstFlight(version, client_address, connection_id);
  }

  void VerifyVersionNotSupported(ParsedQuicVersion version) {
    QuicConnectionId connection_id = TestConnectionId(++connection_id_);
    QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
    EXPECT_CALL(*dispatcher_,
                CreateQuicSession(connection_id, _, client_address, _, _, _, _))
        .Times(0);
    expect_generator_is_called_ = false;
    ProcessFirstFlight(version, client_address, connection_id);
  }

  void TestTlsMultiPacketClientHello(bool add_reordering,
                                     bool long_connection_id);

  void TestVersionNegotiationForUnknownVersionInvalidShortInitialConnectionId(
      const QuicConnectionId& server_connection_id,
      const QuicConnectionId& client_connection_id);

  TestAlarmFactory::TestAlarm* GetClearResetAddressesAlarm() {
    return reinterpret_cast<TestAlarmFactory::TestAlarm*>(
        QuicDispatcherPeer::GetClearResetAddressesAlarm(dispatcher_.get()));
  }

  ParsedQuicVersion version_;
  MockQuicConnectionHelper mock_helper_;
  MockAlarmFactory mock_alarm_factory_;
  QuicConfig config_;
  QuicVersionManager version_manager_;
  QuicCryptoServerConfig crypto_config_;
  QuicSocketAddress server_address_;
  // Set to false if the dispatcher won't create a session.
  bool expect_generator_is_called_ = true;
  // Set in conditions where the generator should return a different connection
  // ID.
  std::optional<QuicConnectionId> generated_connection_id_;
  MockConnectionIdGenerator connection_id_generator_;
  std::unique_ptr<NiceMock<TestDispatcher>> dispatcher_;
  MockTimeWaitListManager* time_wait_list_manager_;
  TestQuicSpdyServerSession* session1_;
  TestQuicSpdyServerSession* session2_;
  std::map<QuicConnectionId, std::list<std::string>> data_connection_map_;
  QuicBufferedPacketStore* store_;
  uint64_t connection_id_;
  std::optional<std::string> address_token_;
};

class QuicDispatcherTestAllVersions : public QuicDispatcherTestBase {};
class QuicDispatcherTestOneVersion : public QuicDispatcherTestBase {};

class QuicDispatcherTestNoVersions : public QuicDispatcherTestBase {
 public:
  QuicDispatcherTestNoVersions()
      : QuicDispatcherTestBase(ParsedQuicVersionVector{}) {}
};

INSTANTIATE_TEST_SUITE_P(QuicDispatcherTestsAllVersions,
                         QuicDispatcherTestAllVersions,
                         ::testing::ValuesIn(CurrentSupportedVersions()),
                         ::testing::PrintToStringParamName());

INSTANTIATE_TEST_SUITE_P(QuicDispatcherTestsOneVersion,
                         QuicDispatcherTestOneVersion,
                         ::testing::Values(CurrentSupportedVersions().front()),
                         ::testing::PrintToStringParamName());

INSTANTIATE_TEST_SUITE_P(QuicDispatcherTestsNoVersion,
                         QuicDispatcherTestNoVersions,
                         ::testing::ValuesIn(AllSupportedVersions()),
                         ::testing::PrintToStringParamName());

TEST_P(QuicDispatcherTestAllVersions, TlsClientHelloCreatesSession) {
  if (version_.UsesQuicCrypto()) {
    return;
  }
  SetAddressToken("hsdifghdsaifnasdpfjdsk");

  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);

  EXPECT_CALL(
      *dispatcher_,
      CreateQuicSession(TestConnectionId(1), _, client_address,
                        Eq(ExpectedAlpn()), _, MatchParsedClientHello(), _))
      .WillOnce(Return(ByMove(CreateSession(
          dispatcher_.get(), config_, TestConnectionId(1), client_address,
          &mock_helper_, &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .WillOnce(WithArg<2>(Invoke([this](const QuicEncryptedPacket& packet) {
        ValidatePacket(TestConnectionId(1), packet);
      })));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              OnParsedClientHelloInfo(MatchParsedClientHello()))
      .Times(1);

  ProcessFirstFlight(client_address, TestConnectionId(1));
}

TEST_P(QuicDispatcherTestAllVersions,
       TlsClientHelloCreatesSessionWithCorrectConnectionIdGenerator) {
  if (version_.UsesQuicCrypto()) {
    return;
  }
  SetAddressToken("hsdifghdsaifnasdpfjdsk");

  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  MockConnectionIdGenerator mock_connection_id_generator;
  EXPECT_CALL(*dispatcher_, ConnectionIdGenerator())
      .WillRepeatedly(ReturnRef(mock_connection_id_generator));
  ConnectionIdGeneratorInterface& expected_generator =
      mock_connection_id_generator;
  EXPECT_CALL(mock_connection_id_generator,
              MaybeReplaceConnectionId(TestConnectionId(1), version_))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(*dispatcher_,
              CreateQuicSession(TestConnectionId(1), _, client_address,
                                Eq(ExpectedAlpn()), _, MatchParsedClientHello(),
                                Ref(expected_generator)))
      .WillOnce(Return(ByMove(CreateSession(
          dispatcher_.get(), config_, TestConnectionId(1), client_address,
          &mock_helper_, &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
  expect_generator_is_called_ = false;
  ProcessFirstFlight(client_address, TestConnectionId(1));
}

TEST_P(QuicDispatcherTestAllVersions, VariableServerConnectionIdLength) {
  QuicConnectionId old_id = TestConnectionId(1);
  // Return a connection ID that is not expected_server_connection_id_length_
  // bytes long.
  if (version_.HasIetfQuicFrames()) {
    generated_connection_id_ =
        QuicConnectionId({0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                          0x09, 0x0a, 0x0b});
  }
  QuicConnectionId new_id =
      generated_connection_id_.has_value() ? *generated_connection_id_ : old_id;
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  EXPECT_CALL(*dispatcher_,
              CreateQuicSession(new_id, _, client_address, Eq(ExpectedAlpn()),
                                _, MatchParsedClientHello(), _))
      .WillOnce(Return(ByMove(CreateSession(
          dispatcher_.get(), config_, new_id, client_address, &mock_helper_,
          &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .WillOnce(WithArg<2>(Invoke([this](const QuicEncryptedPacket& packet) {
        ValidatePacket(TestConnectionId(1), packet);
      })));
  ProcessFirstFlight(client_address, old_id);

  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .Times(1);
  ProcessPacket(client_address, new_id, false, "foo");
}

void QuicDispatcherTestBase::TestTlsMultiPacketClientHello(
    bool add_reordering, bool long_connection_id) {
  if (!version_.UsesTls()) {
    return;
  }
  SetAddressToken("857293462398");

  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  QuicConnectionId original_connection_id, new_connection_id;
  if (long_connection_id) {
    original_connection_id = TestConnectionIdNineBytesLong(1);
    new_connection_id = kReturnConnectionId;
    EXPECT_CALL(connection_id_generator_,
                MaybeReplaceConnectionId(original_connection_id, version_))
        .WillOnce(Return(new_connection_id));

  } else {
    original_connection_id = TestConnectionId();
    new_connection_id = original_connection_id;
    EXPECT_CALL(connection_id_generator_,
                MaybeReplaceConnectionId(original_connection_id, version_))
        .WillOnce(Return(std::nullopt));
  }
  QuicConfig client_config = DefaultQuicConfig();
  // Add a 2000-byte custom parameter to increase the length of the CHLO.
  constexpr auto kCustomPara
```