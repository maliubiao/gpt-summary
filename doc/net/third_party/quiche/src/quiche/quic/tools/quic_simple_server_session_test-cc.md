Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The core request is to understand the *functionality* of `quic_simple_server_session_test.cc`. This means identifying what aspects of the server session are being tested. Since it's a test file, the functionality is revealed through the individual test cases.

2. **Identify Key Components:**  Start by looking at the `#include` directives. These tell you the primary classes involved:
    * `quiche/quic/tools/quic_simple_server_session.h`: The class being tested.
    * Test frameworks and utilities:  `quic_test.h`, `mock_quic_session_visitor.h`, `quic_connection_peer.h`, etc. These suggest this is a unit test.
    * Core QUIC components: `quic_connection.h`, `quic_crypto_server_stream.h`, `quic_versions.h`, etc. This shows the context of the tested class within the QUIC stack.

3. **Examine the Test Fixture:**  The `QuicSimpleServerSessionTest` class is crucial. Note its inheritance from `QuicTestWithParam`. This means the tests are parameterized, and you should look for `INSTANTIATE_TEST_SUITE_P` to see the parameter values (in this case, different QUIC versions). The fixture sets up the testing environment:
    * Creates `QuicCryptoServerConfig`, `QuicCompressedCertsCache`. These are related to the server's cryptographic setup.
    * Creates a `MockQuicConnectionWithSendStreamData` and a `MockQuicSimpleServerSession`. The "Mock" prefix indicates that these are controlled test doubles, allowing you to isolate the unit under test.
    * Initializes the session (`session_->Initialize();`).
    * Sets up default expectations on the mock objects (like handling control frames).

4. **Analyze Individual Test Cases:** Go through each `TEST_P` (parameterized test) function. For each one, ask:
    * **What is being tested?** Look at the sequence of actions and the `EXPECT_CALL` assertions. What specific methods or behaviors are being verified?
    * **What are the inputs (implicit or explicit)?** What data or events trigger the behavior being tested? This might involve creating and sending QUIC frames (`QuicStreamFrame`, `QuicRstStreamFrame`).
    * **What are the expected outputs/outcomes?** What are the assertions checking for? This could be changes in the session state (number of open streams), calls to mock objects, or connection closure.

5. **Connect Test Cases to Functionality:**  As you analyze the tests, group them thematically to understand the overall functionality being covered. For example:
    * Tests related to stream resets (`CloseStreamDueToReset`, `NeverOpenStreamDueToReset`, `AcceptClosedStream`).
    * Tests related to stream creation (`CreateIncomingStreamDisconnected`, `CreateIncomingStream`, `CreateOutgoingDynamicStreamDisconnected`, `CreateOutgoingDynamicStreamUnencrypted`).
    * Tests related to invalid stream IDs (`GetEvenIncomingError`).

6. **Address Specific Requirements of the Prompt:**
    * **Functionality Listing:** Summarize the identified themes of the tests into a concise list.
    * **Relationship to JavaScript:**  Consider where QUIC interacts with JavaScript in a browser. The primary connection is through the Fetch API and WebTransport. Focus on how the server behavior tested here would impact client-side JavaScript.
    * **Logical Reasoning (Input/Output):**  For a selected test case, explicitly state the setup, the action, and the expected outcome.
    * **User/Programming Errors:**  Think about how incorrect usage of the server or the QUIC API could lead to the tested scenarios.
    * **User Operations (Debugging):**  Trace back from the test to potential user actions that would trigger the server-side logic being tested.

7. **Refine and Organize:**  Structure the answer logically with clear headings and bullet points. Ensure the language is clear and avoids overly technical jargon where possible.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This file tests the server session's ability to handle streams."  **Refinement:** Be more specific. It tests handling of stream resets, creation of different types of streams, and errors related to stream IDs.
* **Initial thought:** "JavaScript doesn't interact with this directly." **Refinement:**  While not direct, consider the browser's Fetch API and WebTransport, which rely on the underlying QUIC connection. The server's behavior affects these APIs.
* **Struggling with Input/Output for a complex test:** Focus on a simpler test case first to illustrate the concept. Then, briefly mention how it could be extended to more complex scenarios.
* **Not sure about user operations:**  Think about common web browsing activities. A broken link or a server-side error could lead to stream resets. Opening multiple tabs or making many requests could trigger stream creation limits.

By following this structured approach, combining code analysis with an understanding of the testing framework and the broader context of QUIC, you can effectively analyze and explain the functionality of a test file like `quic_simple_server_session_test.cc`.
这个文件 `net/third_party/quiche/src/quiche/quic/tools/quic_simple_server_session_test.cc` 是 Chromium 网络栈中 QUIC 协议的一个测试文件。它专门用于测试 `QuicSimpleServerSession` 类的功能。`QuicSimpleServerSession` 是一个简单的 QUIC 服务器会话的实现。

以下是该文件测试的主要功能：

**1. 流的生命周期管理:**

* **关闭流 (Close Stream Due to Reset):** 测试当收到客户端发送的 RST_STREAM 帧时，服务器如何正确地关闭流，并且不再接受该流上的后续数据。
* **拒绝打开流 (Never Open Stream Due to Reset):** 测试当服务器收到客户端发送的 RST_STREAM 帧后，即使随后收到该流的数据帧，也不会再重新打开该流。
* **接受已关闭的流上的数据 (Accept Closed Stream):** 测试当服务器收到已关闭的流上的数据时，如何处理这种情况。虽然会丢弃这些数据，但不会影响其他流的正常处理。

**2. 流的创建:**

* **拒绝在断开连接时创建流入流 (Create Incoming Stream Disconnected):** 测试当连接断开时，服务器是否会拒绝创建新的客户端发起的流入流。
* **创建流入流 (Create Incoming Stream):** 测试服务器是否能够正确地创建客户端发起的流入流。
* **拒绝在断开连接时创建流出流 (Create Outgoing Dynamic Stream Disconnected):** 测试当连接断开时，服务器是否会拒绝创建新的服务器发起的流出流。
* **拒绝在未加密时创建流出流 (Create Outgoing Dynamic Stream Unencrypted):** 测试在 TLS 握手完成之前，加密尚未建立时，服务器是否会拒绝创建新的服务器发起的流出流。

**3. 错误处理:**

* **处理偶数 ID 的流入错误 (GetEvenIncomingError):** 测试当尝试获取或创建偶数 ID 的流入流（服务器发起的单向流）时，服务器是否会正确地关闭连接并报告错误。

**与 JavaScript 功能的关系：**

虽然这个 C++ 测试文件本身不包含 JavaScript 代码，但它测试的 QUIC 服务器会话功能直接影响基于浏览器的 JavaScript 应用的网络性能和行为。

* **Fetch API 和 WebTransport:**  现代浏览器使用 QUIC 协议来支持 Fetch API 和 WebTransport API。`QuicSimpleServerSession` 的正确实现对于这些 API 的稳定运行至关重要。
* **流的复用和优先级:** QUIC 的多路复用能力允许在单个连接上并行发送多个请求。该文件测试的流管理功能确保了服务器能够正确地处理和关闭这些并发的流，从而避免阻塞和提高性能。
* **错误处理:** 当服务器遇到错误（例如收到 RST_STREAM），正确的错误处理机制可以防止应用程序崩溃，并允许 JavaScript 代码捕获和处理这些错误，提供更好的用户体验。

**举例说明（假设输入与输出）：**

**测试用例：CloseStreamDueToReset**

* **假设输入:**
    1. 客户端向服务器发送一个包含数据的流帧 (STREAM frame)，流 ID 为 4。
    2. 服务器成功创建并处理了该流。
    3. 客户端向服务器发送一个 RST_STREAM 帧，指示要重置流 ID 为 4 的流。
    4. 客户端再次向服务器发送一个包含数据的流帧，流 ID 仍然为 4。

* **预期输出:**
    1. 服务器在收到第一个流帧后，会创建一个新的 `QuicSimpleServerStream` 对象。
    2. 服务器在收到 RST_STREAM 帧后，会关闭流 ID 为 4 的流，并可能发送一个 RST_STREAM_ACKNOWLEDGEMENT 帧作为回应（取决于 QUIC 版本）。
    3. 服务器在收到第二个流帧时，由于流已关闭，会忽略该数据，并且不会重新打开该流。`QuicSessionPeer::GetNumOpenDynamicStreams` 的值会从 1 变为 0，并且保持为 0。

**用户或编程常见的使用错误：**

* **客户端过早关闭流:** 客户端在服务器完全处理完请求之前发送 RST_STREAM，可能导致服务器端资源未正确释放或操作未完成。
* **服务器端逻辑错误导致流重置:** 服务器应用程序逻辑出现错误，例如尝试访问不存在的资源，可能导致服务器主动发送 RST_STREAM 关闭流。
* **不正确的流 ID 管理:** 客户端或服务器在发送数据时使用了错误的流 ID，可能导致数据被发送到错误的流或被服务器拒绝。  `GetEvenIncomingError` 测试就覆盖了服务器收到本应由客户端发起的流 ID 的情况。

**用户操作如何一步步到达这里（作为调试线索）：**

假设用户在浏览器中访问一个网站，该网站使用 QUIC 协议进行通信。

1. **用户在浏览器地址栏输入 URL 并按下回车键。**
2. **浏览器开始建立与服务器的 QUIC 连接。** 这涉及到 TLS 握手和 QUIC 特有的连接建立过程。
3. **浏览器（QUIC 客户端）向服务器发送 HTTP 请求。** 这通常通过一个或多个 QUIC 流进行。
4. **在服务器端，`QuicSimpleServerSession` 对象被创建来处理与该客户端的连接。**
5. **如果客户端在请求过程中遇到问题（例如，用户取消了请求，网络连接不稳定），客户端可能会发送 RST_STREAM 帧来中止相关的 QUIC 流。** 这就触发了 `CloseStreamDueToReset` 测试所模拟的场景。
6. **如果服务器端应用程序逻辑发生错误，例如请求的资源不存在，服务器可能会发送 RST_STREAM 帧来关闭相应的流。** 这也会涉及 `QuicSimpleServerSession` 的流管理逻辑。
7. **开发者在调试服务器端 QUIC 实现时，可能会遇到流创建失败的情况。** 例如，在连接建立完成之前尝试创建流，或者尝试创建了错误的流类型。`CreateIncomingStreamDisconnected` 和 `CreateOutgoingDynamicStreamUnencrypted` 等测试覆盖了这些场景。
8. **当开发者在实现服务器逻辑时，错误地使用了预留的流 ID（例如，服务器尝试处理偶数 ID 的流入流），就会触发 `GetEvenIncomingError` 测试所模拟的情况。**

通过这些测试，开发者可以确保 `QuicSimpleServerSession` 能够正确地处理各种流生命周期事件、创建流以及处理错误情况，从而保证基于 QUIC 的网络应用的稳定性和可靠性。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/tools/quic_simple_server_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quic_simple_server_session.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "absl/strings/str_cat.h"
#include "quiche/quic/core/crypto/null_encrypter.h"
#include "quiche/quic/core/crypto/quic_crypto_server_config.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/http/http_encoder.h"
#include "quiche/quic/core/proto/cached_network_parameters_proto.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_crypto_server_stream.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/core/tls_server_handshaker.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/mock_quic_session_visitor.h"
#include "quiche/quic/test_tools/quic_config_peer.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/quic/test_tools/quic_sent_packet_manager_peer.h"
#include "quiche/quic/test_tools/quic_session_peer.h"
#include "quiche/quic/test_tools/quic_spdy_session_peer.h"
#include "quiche/quic/test_tools/quic_stream_peer.h"
#include "quiche/quic/test_tools/quic_sustained_bandwidth_recorder_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/tools/quic_backend_response.h"
#include "quiche/quic/tools/quic_memory_cache_backend.h"
#include "quiche/quic/tools/quic_simple_server_stream.h"

using testing::_;
using testing::AtLeast;
using testing::InSequence;
using testing::Invoke;
using testing::Return;
using testing::StrictMock;

namespace quic {
namespace test {
namespace {

// Data to be sent on a request stream.  In Google QUIC, this is interpreted as
// DATA payload (there is no framing on request streams).  In IETF QUIC, this is
// interpreted as HEADERS frame (type 0x1) with payload length 122 ('z').  Since
// no payload is included, QPACK decoder will not be invoked.
const char* const kStreamData = "\1z";

}  // namespace

class QuicSimpleServerSessionPeer {
 public:
  static void SetCryptoStream(QuicSimpleServerSession* s,
                              QuicCryptoServerStreamBase* crypto_stream) {
    s->crypto_stream_.reset(crypto_stream);
  }

  static QuicSpdyStream* CreateIncomingStream(QuicSimpleServerSession* s,
                                              QuicStreamId id) {
    return s->CreateIncomingStream(id);
  }

  static QuicSimpleServerStream* CreateOutgoingUnidirectionalStream(
      QuicSimpleServerSession* s) {
    return s->CreateOutgoingUnidirectionalStream();
  }
};

namespace {

const size_t kMaxStreamsForTest = 10;

class MockQuicCryptoServerStream : public QuicCryptoServerStream {
 public:
  explicit MockQuicCryptoServerStream(
      const QuicCryptoServerConfig* crypto_config,
      QuicCompressedCertsCache* compressed_certs_cache, QuicSession* session,
      QuicCryptoServerStreamBase::Helper* helper)
      : QuicCryptoServerStream(crypto_config, compressed_certs_cache, session,
                               helper) {}
  MockQuicCryptoServerStream(const MockQuicCryptoServerStream&) = delete;
  MockQuicCryptoServerStream& operator=(const MockQuicCryptoServerStream&) =
      delete;
  ~MockQuicCryptoServerStream() override {}

  MOCK_METHOD(void, SendServerConfigUpdate, (const CachedNetworkParameters*),
              (override));

  bool encryption_established() const override { return true; }
};

class MockTlsServerHandshaker : public TlsServerHandshaker {
 public:
  explicit MockTlsServerHandshaker(QuicSession* session,
                                   const QuicCryptoServerConfig* crypto_config)
      : TlsServerHandshaker(session, crypto_config) {}
  MockTlsServerHandshaker(const MockTlsServerHandshaker&) = delete;
  MockTlsServerHandshaker& operator=(const MockTlsServerHandshaker&) = delete;
  ~MockTlsServerHandshaker() override {}

  MOCK_METHOD(void, SendServerConfigUpdate, (const CachedNetworkParameters*),
              (override));

  bool encryption_established() const override { return true; }
};

class MockQuicConnectionWithSendStreamData : public MockQuicConnection {
 public:
  MockQuicConnectionWithSendStreamData(
      MockQuicConnectionHelper* helper, MockAlarmFactory* alarm_factory,
      Perspective perspective,
      const ParsedQuicVersionVector& supported_versions)
      : MockQuicConnection(helper, alarm_factory, perspective,
                           supported_versions) {
    auto consume_all_data = [](QuicStreamId /*id*/, size_t write_length,
                               QuicStreamOffset /*offset*/,
                               StreamSendingState state) {
      return QuicConsumedData(write_length, state != NO_FIN);
    };
    ON_CALL(*this, SendStreamData(_, _, _, _))
        .WillByDefault(Invoke(consume_all_data));
  }

  MOCK_METHOD(QuicConsumedData, SendStreamData,
              (QuicStreamId id, size_t write_length, QuicStreamOffset offset,
               StreamSendingState state),
              (override));
};

class MockQuicSimpleServerSession : public QuicSimpleServerSession {
 public:
  MockQuicSimpleServerSession(
      const QuicConfig& config, QuicConnection* connection,
      QuicSession::Visitor* visitor, QuicCryptoServerStreamBase::Helper* helper,
      const QuicCryptoServerConfig* crypto_config,
      QuicCompressedCertsCache* compressed_certs_cache,
      QuicSimpleServerBackend* quic_simple_server_backend)
      : QuicSimpleServerSession(
            config, CurrentSupportedVersions(), connection, visitor, helper,
            crypto_config, compressed_certs_cache, quic_simple_server_backend) {
  }
  MOCK_METHOD(void, SendBlocked, (QuicStreamId, QuicStreamOffset), (override));
  MOCK_METHOD(bool, WriteControlFrame,
              (const QuicFrame& frame, TransmissionType type), (override));
};

class QuicSimpleServerSessionTest
    : public QuicTestWithParam<ParsedQuicVersion> {
 public:
  // The function ensures that A) the MAX_STREAMS frames get properly deleted
  // (since the test uses a 'did we leak memory' check ... if we just lose the
  // frame, the test fails) and B) returns true (instead of the default, false)
  // which ensures that the rest of the system thinks that the frame actually
  // was transmitted.
  bool ClearMaxStreamsControlFrame(const QuicFrame& frame) {
    if (frame.type == MAX_STREAMS_FRAME) {
      DeleteFrame(&const_cast<QuicFrame&>(frame));
      return true;
    }
    return false;
  }

 protected:
  QuicSimpleServerSessionTest()
      : crypto_config_(QuicCryptoServerConfig::TESTING,
                       QuicRandom::GetInstance(),
                       crypto_test_utils::ProofSourceForTesting(),
                       KeyExchangeSource::Default()),
        compressed_certs_cache_(
            QuicCompressedCertsCache::kQuicCompressedCertsCacheSize) {
    config_.SetMaxBidirectionalStreamsToSend(kMaxStreamsForTest);
    QuicConfigPeer::SetReceivedMaxBidirectionalStreams(&config_,
                                                       kMaxStreamsForTest);
    config_.SetMaxUnidirectionalStreamsToSend(kMaxStreamsForTest);

    config_.SetInitialStreamFlowControlWindowToSend(
        kInitialStreamFlowControlWindowForTest);
    config_.SetInitialMaxStreamDataBytesIncomingBidirectionalToSend(
        kInitialStreamFlowControlWindowForTest);
    config_.SetInitialMaxStreamDataBytesOutgoingBidirectionalToSend(
        kInitialStreamFlowControlWindowForTest);
    config_.SetInitialMaxStreamDataBytesUnidirectionalToSend(
        kInitialStreamFlowControlWindowForTest);
    config_.SetInitialSessionFlowControlWindowToSend(
        kInitialSessionFlowControlWindowForTest);
    if (VersionUsesHttp3(transport_version())) {
      QuicConfigPeer::SetReceivedMaxUnidirectionalStreams(
          &config_, kMaxStreamsForTest + 3);
    } else {
      QuicConfigPeer::SetReceivedMaxUnidirectionalStreams(&config_,
                                                          kMaxStreamsForTest);
    }

    ParsedQuicVersionVector supported_versions = SupportedVersions(version());
    connection_ = new StrictMock<MockQuicConnectionWithSendStreamData>(
        &helper_, &alarm_factory_, Perspective::IS_SERVER, supported_versions);
    connection_->AdvanceTime(QuicTime::Delta::FromSeconds(1));
    connection_->SetEncrypter(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<NullEncrypter>(connection_->perspective()));
    session_ = std::make_unique<MockQuicSimpleServerSession>(
        config_, connection_, &owner_, &stream_helper_, &crypto_config_,
        &compressed_certs_cache_, &memory_cache_backend_);
    MockClock clock;
    handshake_message_ = crypto_config_.AddDefaultConfig(
        QuicRandom::GetInstance(), &clock,
        QuicCryptoServerConfig::ConfigOptions());
    session_->Initialize();

    if (VersionHasIetfQuicFrames(transport_version())) {
      EXPECT_CALL(*session_, WriteControlFrame(_, _))
          .WillRepeatedly(Invoke(&ClearControlFrameWithTransmissionType));
    }
    session_->OnConfigNegotiated();
  }

  QuicStreamId GetNthClientInitiatedBidirectionalId(int n) {
    return GetNthClientInitiatedBidirectionalStreamId(transport_version(), n);
  }

  QuicStreamId GetNthServerInitiatedUnidirectionalId(int n) {
    return quic::test::GetNthServerInitiatedUnidirectionalStreamId(
        transport_version(), n);
  }

  ParsedQuicVersion version() const { return GetParam(); }

  QuicTransportVersion transport_version() const {
    return version().transport_version;
  }

  void InjectStopSending(QuicStreamId stream_id,
                         QuicRstStreamErrorCode rst_stream_code) {
    // Create and inject a STOP_SENDING frame. In GOOGLE QUIC, receiving a
    // RST_STREAM frame causes a two-way close. For IETF QUIC, RST_STREAM causes
    // a one-way close.
    if (!VersionHasIetfQuicFrames(transport_version())) {
      // Only needed for version 99/IETF QUIC.
      return;
    }
    EXPECT_CALL(owner_, OnStopSendingReceived(_)).Times(1);
    QuicStopSendingFrame stop_sending(kInvalidControlFrameId, stream_id,
                                      rst_stream_code);
    // Expect the RESET_STREAM that is generated in response to receiving a
    // STOP_SENDING.
    EXPECT_CALL(*connection_, OnStreamReset(stream_id, rst_stream_code));
    session_->OnStopSendingFrame(stop_sending);
  }

  StrictMock<MockQuicSessionVisitor> owner_;
  StrictMock<MockQuicCryptoServerStreamHelper> stream_helper_;
  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  StrictMock<MockQuicConnectionWithSendStreamData>* connection_;
  QuicConfig config_;
  QuicCryptoServerConfig crypto_config_;
  QuicCompressedCertsCache compressed_certs_cache_;
  QuicMemoryCacheBackend memory_cache_backend_;
  std::unique_ptr<MockQuicSimpleServerSession> session_;
  std::unique_ptr<CryptoHandshakeMessage> handshake_message_;
};

INSTANTIATE_TEST_SUITE_P(Tests, QuicSimpleServerSessionTest,
                         ::testing::ValuesIn(AllSupportedVersions()),
                         ::testing::PrintToStringParamName());

TEST_P(QuicSimpleServerSessionTest, CloseStreamDueToReset) {
  // Send some data open a stream, then reset it.
  QuicStreamFrame data1(GetNthClientInitiatedBidirectionalId(0), false, 0,
                        kStreamData);
  session_->OnStreamFrame(data1);
  EXPECT_EQ(1u, QuicSessionPeer::GetNumOpenDynamicStreams(session_.get()));

  // Receive a reset (and send a RST in response).
  QuicRstStreamFrame rst1(kInvalidControlFrameId,
                          GetNthClientInitiatedBidirectionalId(0),
                          QUIC_ERROR_PROCESSING_STREAM, 0);
  EXPECT_CALL(owner_, OnRstStreamReceived(_)).Times(1);
  EXPECT_CALL(*session_, WriteControlFrame(_, _));

  if (!VersionHasIetfQuicFrames(transport_version())) {
    // For version 99, this is covered in InjectStopSending()
    EXPECT_CALL(*connection_,
                OnStreamReset(GetNthClientInitiatedBidirectionalId(0),
                              QUIC_RST_ACKNOWLEDGEMENT));
  }
  session_->OnRstStream(rst1);
  // Create and inject a STOP_SENDING frame. In GOOGLE QUIC, receiving a
  // RST_STREAM frame causes a two-way close. For IETF QUIC, RST_STREAM causes
  // a one-way close.
  InjectStopSending(GetNthClientInitiatedBidirectionalId(0),
                    QUIC_ERROR_PROCESSING_STREAM);
  EXPECT_EQ(0u, QuicSessionPeer::GetNumOpenDynamicStreams(session_.get()));

  // Send the same two bytes of payload in a new packet.
  session_->OnStreamFrame(data1);

  // The stream should not be re-opened.
  EXPECT_EQ(0u, QuicSessionPeer::GetNumOpenDynamicStreams(session_.get()));
  EXPECT_TRUE(connection_->connected());
}

TEST_P(QuicSimpleServerSessionTest, NeverOpenStreamDueToReset) {
  // Send a reset (and expect the peer to send a RST in response).
  QuicRstStreamFrame rst1(kInvalidControlFrameId,
                          GetNthClientInitiatedBidirectionalId(0),
                          QUIC_ERROR_PROCESSING_STREAM, 0);
  EXPECT_CALL(owner_, OnRstStreamReceived(_)).Times(1);
  if (!VersionHasIetfQuicFrames(transport_version())) {
    EXPECT_CALL(*session_, WriteControlFrame(_, _));
    // For version 99, this is covered in InjectStopSending()
    EXPECT_CALL(*connection_,
                OnStreamReset(GetNthClientInitiatedBidirectionalId(0),
                              QUIC_RST_ACKNOWLEDGEMENT));
  }
  session_->OnRstStream(rst1);
  // Create and inject a STOP_SENDING frame. In GOOGLE QUIC, receiving a
  // RST_STREAM frame causes a two-way close. For IETF QUIC, RST_STREAM causes
  // a one-way close.
  InjectStopSending(GetNthClientInitiatedBidirectionalId(0),
                    QUIC_ERROR_PROCESSING_STREAM);

  EXPECT_EQ(0u, QuicSessionPeer::GetNumOpenDynamicStreams(session_.get()));

  QuicStreamFrame data1(GetNthClientInitiatedBidirectionalId(0), false, 0,
                        kStreamData);
  session_->OnStreamFrame(data1);

  // The stream should never be opened, now that the reset is received.
  EXPECT_EQ(0u, QuicSessionPeer::GetNumOpenDynamicStreams(session_.get()));
  EXPECT_TRUE(connection_->connected());
}

TEST_P(QuicSimpleServerSessionTest, AcceptClosedStream) {
  // Send some data to open two streams.
  QuicStreamFrame frame1(GetNthClientInitiatedBidirectionalId(0), false, 0,
                         kStreamData);
  QuicStreamFrame frame2(GetNthClientInitiatedBidirectionalId(1), false, 0,
                         kStreamData);
  session_->OnStreamFrame(frame1);
  session_->OnStreamFrame(frame2);
  EXPECT_EQ(2u, QuicSessionPeer::GetNumOpenDynamicStreams(session_.get()));

  // Send a reset (and expect the peer to send a RST in response).
  QuicRstStreamFrame rst(kInvalidControlFrameId,
                         GetNthClientInitiatedBidirectionalId(0),
                         QUIC_ERROR_PROCESSING_STREAM, 0);
  EXPECT_CALL(owner_, OnRstStreamReceived(_)).Times(1);
  if (!VersionHasIetfQuicFrames(transport_version())) {
    EXPECT_CALL(*session_, WriteControlFrame(_, _));
    // For version 99, this is covered in InjectStopSending()
    EXPECT_CALL(*connection_,
                OnStreamReset(GetNthClientInitiatedBidirectionalId(0),
                              QUIC_RST_ACKNOWLEDGEMENT));
  }
  session_->OnRstStream(rst);
  // Create and inject a STOP_SENDING frame. In GOOGLE QUIC, receiving a
  // RST_STREAM frame causes a two-way close. For IETF QUIC, RST_STREAM causes
  // a one-way close.
  InjectStopSending(GetNthClientInitiatedBidirectionalId(0),
                    QUIC_ERROR_PROCESSING_STREAM);

  // If we were tracking, we'd probably want to reject this because it's data
  // past the reset point of stream 3.  As it's a closed stream we just drop the
  // data on the floor, but accept the packet because it has data for stream 5.
  QuicStreamFrame frame3(GetNthClientInitiatedBidirectionalId(0), false, 2,
                         kStreamData);
  QuicStreamFrame frame4(GetNthClientInitiatedBidirectionalId(1), false, 2,
                         kStreamData);
  session_->OnStreamFrame(frame3);
  session_->OnStreamFrame(frame4);
  // The stream should never be opened, now that the reset is received.
  EXPECT_EQ(1u, QuicSessionPeer::GetNumOpenDynamicStreams(session_.get()));
  EXPECT_TRUE(connection_->connected());
}

TEST_P(QuicSimpleServerSessionTest, CreateIncomingStreamDisconnected) {
  // EXPECT_QUIC_BUG tests are expensive so only run one instance of them.
  if (version() != AllSupportedVersions()[0]) {
    return;
  }

  // Tests that incoming stream creation fails when connection is not connected.
  size_t initial_num_open_stream =
      QuicSessionPeer::GetNumOpenDynamicStreams(session_.get());
  QuicConnectionPeer::TearDownLocalConnectionState(connection_);
  EXPECT_QUIC_BUG(QuicSimpleServerSessionPeer::CreateIncomingStream(
                      session_.get(), GetNthClientInitiatedBidirectionalId(0)),
                  "ShouldCreateIncomingStream called when disconnected");
  EXPECT_EQ(initial_num_open_stream,
            QuicSessionPeer::GetNumOpenDynamicStreams(session_.get()));
}

TEST_P(QuicSimpleServerSessionTest, CreateIncomingStream) {
  QuicSpdyStream* stream = QuicSimpleServerSessionPeer::CreateIncomingStream(
      session_.get(), GetNthClientInitiatedBidirectionalId(0));
  EXPECT_NE(nullptr, stream);
  EXPECT_EQ(GetNthClientInitiatedBidirectionalId(0), stream->id());
}

TEST_P(QuicSimpleServerSessionTest, CreateOutgoingDynamicStreamDisconnected) {
  // EXPECT_QUIC_BUG tests are expensive so only run one instance of them.
  if (version() != AllSupportedVersions()[0]) {
    return;
  }

  // Tests that outgoing stream creation fails when connection is not connected.
  size_t initial_num_open_stream =
      QuicSessionPeer::GetNumOpenDynamicStreams(session_.get());
  QuicConnectionPeer::TearDownLocalConnectionState(connection_);
  EXPECT_QUIC_BUG(
      QuicSimpleServerSessionPeer::CreateOutgoingUnidirectionalStream(
          session_.get()),
      "ShouldCreateOutgoingUnidirectionalStream called when disconnected");

  EXPECT_EQ(initial_num_open_stream,
            QuicSessionPeer::GetNumOpenDynamicStreams(session_.get()));
}

TEST_P(QuicSimpleServerSessionTest, CreateOutgoingDynamicStreamUnencrypted) {
  // EXPECT_QUIC_BUG tests are expensive so only run one instance of them.
  if (version() != AllSupportedVersions()[0]) {
    return;
  }

  // Tests that outgoing stream creation fails when encryption has not yet been
  // established.
  size_t initial_num_open_stream =
      QuicSessionPeer::GetNumOpenDynamicStreams(session_.get());
  EXPECT_QUIC_BUG(
      QuicSimpleServerSessionPeer::CreateOutgoingUnidirectionalStream(
          session_.get()),
      "Encryption not established so no outgoing stream created.");
  EXPECT_EQ(initial_num_open_stream,
            QuicSessionPeer::GetNumOpenDynamicStreams(session_.get()));
}

// Tests that calling GetOrCreateStream() on an outgoing stream should result in
// the connection being closed.
TEST_P(QuicSimpleServerSessionTest, GetEvenIncomingError) {
  const size_t initial_num_open_stream =
      QuicSessionPeer::GetNumOpenDynamicStreams(session_.get());
  const QuicErrorCode expected_error = VersionUsesHttp3(transport_version())
                                           ? QUIC_HTTP_STREAM_WRONG_DIRECTION
                                           : QUIC_INVALID_STREAM_ID;
  EXPECT_CALL(*connection_, CloseConnection(expected_error,
                                            "Data for nonexistent stream", _));
  EXPECT_EQ(nullptr,
            QuicSessionPeer::GetOrCreateStream(
                session_.get(), GetNthServerInitiatedUnidirectionalId(3)));
  EXPECT_EQ(initial_num_open_stream,
            QuicSessionPeer::GetNumOpenDynamicStreams(session_.get()));
}

}  // namespace
}  // namespace test
}  // namespace quic
```