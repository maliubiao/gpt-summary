Response:
The user wants to understand the functionality of the `quic_session_test.cc` file in the Chromium network stack.

Here's a breakdown of how to address the request:

1. **Identify the core purpose:** The file name `quic_session_test.cc` strongly suggests it's a unit test file for the `QuicSession` class.

2. **Analyze the included headers:**  These headers provide clues about the functionalities being tested. Look for key Quic components like connection management, crypto, streams, frames, and configuration.

3. **Examine the test setup:**  Note the use of mock objects (`MockQuicConnection`, `MockQuicSessionVisitor`) and helper classes (`TestCryptoStream`, `TestStream`, `TestSession`). This indicates a focus on isolated testing.

4. **Identify key test functionalities:** Scan the code for patterns like `TEST_P`, `EXPECT_CALL`, `ASSERT_TRUE`, `EXPECT_EQ`, and the names of the test cases (e.g., `PeerAddress`, `OneRttKeysAvailable`). These reveal the specific aspects of `QuicSession` being tested.

5. **Look for JavaScript relevance:**  Consider how Quic sessions interact with web browsers and potentially JavaScript APIs. This might involve data transfer, connection management, or security aspects.

6. **Address logical reasoning and examples:**  If a test case involves specific input and expected output, try to extract that logic. For user/programming errors, think about common mistakes when interacting with Quic sessions.

7. **Trace user interaction:** Consider how a user's actions in a web browser could lead to the execution of Quic session logic.

8. **Summarize the functionality:** Based on the above analysis, create a concise summary of the file's purpose.这是Chromium网络栈中 QUIC 协议的 `quic_session_test.cc` 文件的第一部分。它的主要功能是为 `quic/core/quic_session.h` 中定义的 `QuicSession` 类提供单元测试。

**功能归纳:**

1. **测试 `QuicSession` 类的核心功能:** 该文件通过创建模拟环境和各种测试用例，验证 `QuicSession` 类的各项功能是否按预期工作。这包括但不限于：
    * 连接管理 (例如，peer 地址，self 地址)
    * 加密协商 (例如，1-RTT keys 是否可用)
    * 流管理 (例如，创建、关闭 stream，判断 stream 是否已关闭，可用 stream 的数量)
    * 流控 (虽然这部分代码中没有直接体现，但作为 session 的重要组成部分，测试中会涉及到)
    * 错误处理和连接关闭
    * 数据发送和接收 (通过模拟 `WritevData` 函数)
    * 帧处理 (例如，`SaveFrame` 函数用于保存和检查发送的帧)
    * Pending Stream 的处理
    * 对新 Outgoing Stream 的创建限制

2. **模拟 `QuicSession` 的依赖项:** 为了隔离测试 `QuicSession` 的逻辑，该文件使用了 mock 对象，例如 `MockQuicConnection` 和 `MockQuicSessionVisitor`。它还创建了自定义的类，如 `TestCryptoStream` 和 `TestStream`，来模拟 `QuicSession` 内部使用的组件。

3. **提供测试辅助工具:** 文件中定义了一些辅助类和函数，例如 `TestCryptoStream` 和 `TestStream`，以及 `IsFrame` matcher，用于简化测试用例的编写。

**与 JavaScript 功能的关系及举例:**

`quic_session_test.cc` 文件本身不直接包含任何 JavaScript 代码，因为它是一个 C++ 单元测试文件。然而，`QuicSession` 类是 QUIC 协议的核心组件，它负责管理一个 QUIC 连接的生命周期。当用户的 web 浏览器通过 QUIC 协议与服务器通信时，`QuicSession` 的功能是至关重要的。

以下是一些与 JavaScript 功能相关的间接联系和举例：

* **建立连接:** 当 JavaScript 代码发起一个 HTTPS 请求时，如果浏览器选择使用 QUIC，那么底层的 `QuicSession` 会负责建立与服务器的连接。这个文件的测试会验证连接建立的各个环节是否正确。
* **数据传输:**  JavaScript 通过 Fetch API 或 XMLHttpRequest 发送和接收数据。在 QUIC 连接上，`QuicSession` 负责将这些数据分割成 QUIC 数据包，并管理数据的可靠传输和流控。这个文件的测试会覆盖数据发送和接收的相关逻辑。
* **流管理:** QUIC 使用 stream 的概念来并行处理多个请求。JavaScript 可以发起多个请求，每个请求都会对应一个 QUIC stream。这个文件的测试会验证 stream 的创建、关闭和管理是否正确。
* **错误处理:** 如果 QUIC 连接遇到错误，`QuicSession` 会负责处理这些错误并通知上层。浏览器可能会将这些错误信息通过 JavaScript API 暴露给开发者。这个文件的测试会涵盖各种错误场景下的 `QuicSession` 行为。

**假设输入与输出 (逻辑推理):**

例如，对于 `TEST_P(QuicSessionTestServer, IsClosedBidirectionalStreamLocallyCreated)` 测试用例：

* **假设输入:**
    1. 一个已建立的 QUIC 会话 (`TestSession`)。
    2. 调用 `CreateOutgoingBidirectionalStream()` 创建两个本地发起的双向流。
    3. 分别调用 `CloseStream()` 关闭这两个流。
* **预期输出:**
    1. `IsClosedStream()` 方法对于这两个流的 ID 返回 `true`。
    2. 发送相应的 `RST_STREAM_FRAME` 和 `STOP_SENDING_FRAME` 控制帧到对端。
    3. 调用 `connection_->OnStreamReset()`。

**用户或编程常见的使用错误及举例:**

虽然这是一个测试文件，但它可以帮助理解 `QuicSession` 的使用方式。一些可能的用户或编程错误（发生在 `QuicSession` 的使用者，通常是 QUIC 实现的其他部分）包括：

* **尝试在连接未建立完成时发送数据:**  `QuicSession` 需要在握手完成后才能安全地发送应用数据。如果在握手完成前尝试发送，可能会导致错误。这个文件中的 `OneRttKeysAvailable` 测试验证了密钥协商的状态。
* **错误地管理 Stream ID:**  QUIC 的 Stream ID 有一定的分配规则。如果尝试使用不合法的 Stream ID，可能会导致连接错误。这个文件中的测试会验证 Stream ID 的分配和可用性。
* **超出流控限制:**  QUIC 具有流控机制，防止发送方过度发送数据。如果发送方忽略流控限制，可能会导致连接关闭。虽然这个文件没有直接测试流控，但 `QuicSession` 的流控功能会在实际应用中遇到这类问题。
* **未正确处理连接关闭事件:**  应用程序需要监听并正确处理 QUIC 连接关闭的事件。如果处理不当，可能会导致资源泄露或其他问题。这个文件中的测试会验证连接关闭的流程。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中输入 URL 并访问一个 HTTPS 网站。**
2. **浏览器检查是否支持 QUIC 协议，以及服务器是否也支持。**
3. **如果双方都支持 QUIC，浏览器会尝试与服务器建立 QUIC 连接。**
4. **在建立连接的过程中，会创建 `QuicSession` 对象来管理这个连接。**
5. **当网络出现问题或者需要调试 QUIC 连接的行为时，开发人员可能会需要查看 `QuicSession` 的内部状态和行为。**
6. **为了验证 `QuicSession` 的代码是否正确，开发者会运行像 `quic_session_test.cc` 这样的单元测试。**
7. **如果发现问题，开发者可能会在 `quic_session_test.cc` 中添加新的测试用例来重现和修复 bug。**
8. **在调试过程中，开发者可能会设置断点在 `QuicSession` 的相关代码中，跟踪用户操作引发的网络请求，一步步地查看 `QuicSession` 的状态变化。**

总而言之，`quic_session_test.cc` 是确保 `QuicSession` 类功能正确性的关键组成部分，它通过大量的测试用例覆盖了 `QuicSession` 的各种功能和场景，为 QUIC 协议的稳定性和可靠性提供了保障。虽然它本身不是 JavaScript 代码，但其测试的功能直接支撑着基于 QUIC 协议的 Web 应用的正常运行。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "quiche/quic/core/quic_session.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/macros.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/crypto/null_decrypter.h"
#include "quiche/quic/core/crypto/null_encrypter.h"
#include "quiche/quic/core/crypto/transport_parameters.h"
#include "quiche/quic/core/frames/quic_max_streams_frame.h"
#include "quiche/quic/core/frames/quic_reset_stream_at_frame.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_crypto_stream.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_stream.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/mock_quic_session_visitor.h"
#include "quiche/quic/test_tools/quic_config_peer.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/quic/test_tools/quic_flow_controller_peer.h"
#include "quiche/quic/test_tools/quic_session_peer.h"
#include "quiche/quic/test_tools/quic_stream_id_manager_peer.h"
#include "quiche/quic/test_tools/quic_stream_peer.h"
#include "quiche/quic/test_tools/quic_stream_send_buffer_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_mem_slice_storage.h"

using spdy::kV3HighestPriority;
using spdy::SpdyPriority;
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::AtLeast;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::StrictMock;
using ::testing::WithArg;

namespace quic {
namespace test {
namespace {

class TestCryptoStream : public QuicCryptoStream, public QuicCryptoHandshaker {
 public:
  explicit TestCryptoStream(QuicSession* session)
      : QuicCryptoStream(session),
        QuicCryptoHandshaker(this, session),
        encryption_established_(false),
        one_rtt_keys_available_(false),
        params_(new QuicCryptoNegotiatedParameters) {
    // Simulate a negotiated cipher_suite with a fake value.
    params_->cipher_suite = 1;
  }

  void EstablishZeroRttEncryption() {
    encryption_established_ = true;
    session()->connection()->SetEncrypter(
        ENCRYPTION_ZERO_RTT,
        std::make_unique<NullEncrypter>(session()->perspective()));
  }

  void OnHandshakeMessage(const CryptoHandshakeMessage& /*message*/) override {
    encryption_established_ = true;
    one_rtt_keys_available_ = true;
    QuicErrorCode error;
    std::string error_details;
    session()->config()->SetInitialStreamFlowControlWindowToSend(
        kInitialStreamFlowControlWindowForTest);
    session()->config()->SetInitialSessionFlowControlWindowToSend(
        kInitialSessionFlowControlWindowForTest);
    if (session()->version().UsesTls()) {
      if (session()->perspective() == Perspective::IS_CLIENT) {
        session()->config()->SetOriginalConnectionIdToSend(
            session()->connection()->connection_id());
        session()->config()->SetInitialSourceConnectionIdToSend(
            session()->connection()->connection_id());
      } else {
        session()->config()->SetInitialSourceConnectionIdToSend(
            session()->connection()->client_connection_id());
      }
      TransportParameters transport_parameters;
      EXPECT_TRUE(
          session()->config()->FillTransportParameters(&transport_parameters));
      error = session()->config()->ProcessTransportParameters(
          transport_parameters, /* is_resumption = */ false, &error_details);
    } else {
      CryptoHandshakeMessage msg;
      session()->config()->ToHandshakeMessage(&msg, transport_version());
      error =
          session()->config()->ProcessPeerHello(msg, CLIENT, &error_details);
    }
    EXPECT_THAT(error, IsQuicNoError());
    session()->OnNewEncryptionKeyAvailable(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<NullEncrypter>(session()->perspective()));
    session()->OnConfigNegotiated();
    if (session()->connection()->version().handshake_protocol ==
        PROTOCOL_TLS1_3) {
      session()->OnTlsHandshakeComplete();
    } else {
      session()->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    }
    session()->DiscardOldEncryptionKey(ENCRYPTION_INITIAL);
  }

  // QuicCryptoStream implementation
  ssl_early_data_reason_t EarlyDataReason() const override {
    return ssl_early_data_unknown;
  }
  bool encryption_established() const override {
    return encryption_established_;
  }
  bool one_rtt_keys_available() const override {
    return one_rtt_keys_available_;
  }
  const QuicCryptoNegotiatedParameters& crypto_negotiated_params()
      const override {
    return *params_;
  }
  CryptoMessageParser* crypto_message_parser() override {
    return QuicCryptoHandshaker::crypto_message_parser();
  }
  void OnPacketDecrypted(EncryptionLevel /*level*/) override {}
  void OnOneRttPacketAcknowledged() override {}
  void OnHandshakePacketSent() override {}
  void OnHandshakeDoneReceived() override {}
  void OnNewTokenReceived(absl::string_view /*token*/) override {}
  std::string GetAddressToken(
      const CachedNetworkParameters* /*cached_network_parameters*/)
      const override {
    return "";
  }
  bool ValidateAddressToken(absl::string_view /*token*/) const override {
    return true;
  }
  const CachedNetworkParameters* PreviousCachedNetworkParams() const override {
    return nullptr;
  }
  void SetPreviousCachedNetworkParams(
      CachedNetworkParameters /*cached_network_params*/) override {}
  HandshakeState GetHandshakeState() const override {
    return one_rtt_keys_available() ? HANDSHAKE_COMPLETE : HANDSHAKE_START;
  }
  void SetServerApplicationStateForResumption(
      std::unique_ptr<ApplicationState> /*application_state*/) override {}
  MOCK_METHOD(std::unique_ptr<QuicDecrypter>,
              AdvanceKeysAndCreateCurrentOneRttDecrypter, (), (override));
  MOCK_METHOD(std::unique_ptr<QuicEncrypter>, CreateCurrentOneRttEncrypter, (),
              (override));

  MOCK_METHOD(void, OnCanWrite, (), (override));
  bool HasPendingCryptoRetransmission() const override { return false; }

  MOCK_METHOD(bool, HasPendingRetransmission, (), (const, override));

  void OnConnectionClosed(const QuicConnectionCloseFrame& /*frame*/,
                          ConnectionCloseSource /*source*/) override {}

  bool ExportKeyingMaterial(absl::string_view /*label*/,
                            absl::string_view /*context*/,
                            size_t /*result_len*/,
                            std::string* /*result*/) override {
    return false;
  }

  SSL* GetSsl() const override { return nullptr; }

  bool IsCryptoFrameExpectedForEncryptionLevel(
      EncryptionLevel level) const override {
    return level != ENCRYPTION_ZERO_RTT;
  }

  EncryptionLevel GetEncryptionLevelToSendCryptoDataOfSpace(
      PacketNumberSpace space) const override {
    switch (space) {
      case INITIAL_DATA:
        return ENCRYPTION_INITIAL;
      case HANDSHAKE_DATA:
        return ENCRYPTION_HANDSHAKE;
      case APPLICATION_DATA:
        return ENCRYPTION_FORWARD_SECURE;
      default:
        QUICHE_DCHECK(false);
        return NUM_ENCRYPTION_LEVELS;
    }
  }

 private:
  using QuicCryptoStream::session;

  bool encryption_established_;
  bool one_rtt_keys_available_;
  quiche::QuicheReferenceCountedPointer<QuicCryptoNegotiatedParameters> params_;
};

class TestStream : public QuicStream {
 public:
  TestStream(QuicStreamId id, QuicSession* session, StreamType type)
      : TestStream(id, session, /*is_static=*/false, type) {}

  TestStream(QuicStreamId id, QuicSession* session, bool is_static,
             StreamType type)
      : QuicStream(id, session, is_static, type) {}

  TestStream(PendingStream* pending, QuicSession* session)
      : QuicStream(pending, session, /*is_static=*/false) {}

  using QuicStream::CloseWriteSide;
  using QuicStream::WriteMemSlices;

  void OnDataAvailable() override {}

  MOCK_METHOD(void, OnCanWrite, (), (override));
  MOCK_METHOD(bool, RetransmitStreamData,
              (QuicStreamOffset, QuicByteCount, bool, TransmissionType),
              (override));

  MOCK_METHOD(bool, HasPendingRetransmission, (), (const, override));
};

class TestSession : public QuicSession {
 public:
  explicit TestSession(QuicConnection* connection,
                       MockQuicSessionVisitor* session_visitor)
      : QuicSession(connection, session_visitor, DefaultQuicConfig(),
                    CurrentSupportedVersions(),
                    /*num_expected_unidirectional_static_streams = */ 0),
        crypto_stream_(this),
        writev_consumes_all_data_(false),
        uses_pending_streams_(false),
        num_incoming_streams_created_(0) {
    set_max_streams_accepted_per_loop(5);
    Initialize();
    this->connection()->SetEncrypter(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<NullEncrypter>(connection->perspective()));
    if (this->connection()->version().SupportsAntiAmplificationLimit()) {
      QuicConnectionPeer::SetAddressValidated(this->connection());
    }
  }

  ~TestSession() override { DeleteConnection(); }

  TestCryptoStream* GetMutableCryptoStream() override {
    return &crypto_stream_;
  }

  const TestCryptoStream* GetCryptoStream() const override {
    return &crypto_stream_;
  }

  TestStream* CreateOutgoingBidirectionalStream() {
    QuicStreamId id = GetNextOutgoingBidirectionalStreamId();
    if (id ==
        QuicUtils::GetInvalidStreamId(connection()->transport_version())) {
      return nullptr;
    }
    TestStream* stream = new TestStream(id, this, BIDIRECTIONAL);
    ActivateStream(absl::WrapUnique(stream));
    return stream;
  }

  TestStream* CreateOutgoingUnidirectionalStream() {
    TestStream* stream = new TestStream(GetNextOutgoingUnidirectionalStreamId(),
                                        this, WRITE_UNIDIRECTIONAL);
    ActivateStream(absl::WrapUnique(stream));
    return stream;
  }

  TestStream* CreateIncomingStream(QuicStreamId id) override {
    // Enforce the limit on the number of open streams.
    if (!VersionHasIetfQuicFrames(connection()->transport_version()) &&
        stream_id_manager().num_open_incoming_streams() + 1 >
            max_open_incoming_bidirectional_streams()) {
      // No need to do this test for version 99; it's done by
      // QuicSession::GetOrCreateStream.
      connection()->CloseConnection(
          QUIC_TOO_MANY_OPEN_STREAMS, "Too many streams!",
          ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
      return nullptr;
    }

    TestStream* stream = new TestStream(
        id, this,
        DetermineStreamType(id, connection()->version(), perspective(),
                            /*is_incoming=*/true, BIDIRECTIONAL));
    ActivateStream(absl::WrapUnique(stream));
    ++num_incoming_streams_created_;
    return stream;
  }

  TestStream* CreateIncomingStream(PendingStream* pending) override {
    TestStream* stream = new TestStream(pending, this);
    ActivateStream(absl::WrapUnique(stream));
    ++num_incoming_streams_created_;
    return stream;
  }

  // QuicSession doesn't do anything in these methods. So they are overridden
  // here to test that the session handles pending streams correctly in terms of
  // receiving stream frames.
  QuicStream* ProcessBidirectionalPendingStream(
      PendingStream* pending) override {
    return CreateIncomingStream(pending);
  }
  QuicStream* ProcessReadUnidirectionalPendingStream(
      PendingStream* pending) override {
    struct iovec iov;
    if (pending->sequencer()->GetReadableRegion(&iov)) {
      // Create TestStream once the first byte is received.
      return CreateIncomingStream(pending);
    }
    return nullptr;
  }

  bool IsClosedStream(QuicStreamId id) {
    return QuicSession::IsClosedStream(id);
  }

  QuicStream* GetOrCreateStream(QuicStreamId stream_id) {
    return QuicSession::GetOrCreateStream(stream_id);
  }

  bool ShouldKeepConnectionAlive() const override {
    return GetNumActiveStreams() > 0;
  }

  QuicConsumedData WritevData(QuicStreamId id, size_t write_length,
                              QuicStreamOffset offset, StreamSendingState state,
                              TransmissionType type,
                              EncryptionLevel level) override {
    bool fin = state != NO_FIN;
    QuicConsumedData consumed(write_length, fin);
    if (!writev_consumes_all_data_) {
      consumed =
          QuicSession::WritevData(id, write_length, offset, state, type, level);
    }
    QuicSessionPeer::GetWriteBlockedStreams(this)->UpdateBytesForStream(
        id, consumed.bytes_consumed);
    return consumed;
  }

  MOCK_METHOD(void, OnCanCreateNewOutgoingStream, (bool unidirectional),
              (override));

  void set_writev_consumes_all_data(bool val) {
    writev_consumes_all_data_ = val;
  }

  QuicConsumedData SendStreamData(QuicStream* stream) {
    if (!QuicUtils::IsCryptoStreamId(connection()->transport_version(),
                                     stream->id()) &&
        this->connection()->encryption_level() != ENCRYPTION_FORWARD_SECURE) {
      this->connection()->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    }
    QuicStreamPeer::SendBuffer(stream).SaveStreamData("not empty");
    QuicConsumedData consumed =
        WritevData(stream->id(), 9, 0, FIN, NOT_RETRANSMISSION,
                   GetEncryptionLevelToSendApplicationData());
    QuicStreamPeer::SendBuffer(stream).OnStreamDataConsumed(
        consumed.bytes_consumed);
    return consumed;
  }

  const QuicFrame& save_frame() { return save_frame_; }

  bool SaveFrame(const QuicFrame& frame) {
    save_frame_ = frame;
    DeleteFrame(&const_cast<QuicFrame&>(frame));
    return true;
  }

  QuicConsumedData SendLargeFakeData(QuicStream* stream, int bytes) {
    QUICHE_DCHECK(writev_consumes_all_data_);
    return WritevData(stream->id(), bytes, 0, FIN, NOT_RETRANSMISSION,
                      GetEncryptionLevelToSendApplicationData());
  }

  bool UsesPendingStreamForFrame(QuicFrameType type,
                                 QuicStreamId stream_id) const override {
    if (!uses_pending_streams_) {
      return false;
    }
    // Uses pending stream for STREAM/RST_STREAM frames with unidirectional read
    // stream and uses pending stream for
    // STREAM/RST_STREAM/STOP_SENDING/WINDOW_UPDATE frames with bidirectional
    // stream.
    bool is_incoming_stream = IsIncomingStream(stream_id);
    StreamType stream_type = QuicUtils::GetStreamType(
        stream_id, perspective(), is_incoming_stream, version());
    switch (type) {
      case STREAM_FRAME:
        ABSL_FALLTHROUGH_INTENDED;
      case RST_STREAM_FRAME:
        return is_incoming_stream;
      case STOP_SENDING_FRAME:
        ABSL_FALLTHROUGH_INTENDED;
      case WINDOW_UPDATE_FRAME:
        return stream_type == BIDIRECTIONAL;
      default:
        return false;
    }
  }

  void set_uses_pending_streams(bool uses_pending_streams) {
    uses_pending_streams_ = uses_pending_streams;
  }

  int num_incoming_streams_created() const {
    return num_incoming_streams_created_;
  }

  using QuicSession::ActivateStream;
  using QuicSession::CanOpenNextOutgoingBidirectionalStream;
  using QuicSession::CanOpenNextOutgoingUnidirectionalStream;
  using QuicSession::closed_streams;
  using QuicSession::GetNextOutgoingBidirectionalStreamId;
  using QuicSession::GetNextOutgoingUnidirectionalStreamId;

 private:
  StrictMock<TestCryptoStream> crypto_stream_;

  bool writev_consumes_all_data_;
  bool uses_pending_streams_;
  QuicFrame save_frame_;
  int num_incoming_streams_created_;
};

MATCHER_P(IsFrame, type, "") { return arg.type == type; }

class QuicSessionTestBase : public QuicTestWithParam<ParsedQuicVersion> {
 protected:
  QuicSessionTestBase(Perspective perspective, bool configure_session)
      : connection_(new StrictMock<MockQuicConnection>(
            &helper_, &alarm_factory_, perspective,
            SupportedVersions(GetParam()))),
        session_(connection_, &session_visitor_),
        configure_session_(configure_session) {
    session_.config()->SetInitialStreamFlowControlWindowToSend(
        kInitialStreamFlowControlWindowForTest);
    session_.config()->SetInitialSessionFlowControlWindowToSend(
        kInitialSessionFlowControlWindowForTest);

    if (configure_session) {
      if (VersionHasIetfQuicFrames(transport_version())) {
        EXPECT_CALL(session_, OnCanCreateNewOutgoingStream(false)).Times(1);
        EXPECT_CALL(session_, OnCanCreateNewOutgoingStream(true)).Times(1);
      }
      QuicConfigPeer::SetReceivedMaxBidirectionalStreams(
          session_.config(), kDefaultMaxStreamsPerConnection);
      QuicConfigPeer::SetReceivedMaxUnidirectionalStreams(
          session_.config(), kDefaultMaxStreamsPerConnection);
      QuicConfigPeer::SetReceivedInitialMaxStreamDataBytesUnidirectional(
          session_.config(), kMinimumFlowControlSendWindow);
      QuicConfigPeer::SetReceivedInitialMaxStreamDataBytesIncomingBidirectional(
          session_.config(), kMinimumFlowControlSendWindow);
      QuicConfigPeer::SetReceivedInitialMaxStreamDataBytesOutgoingBidirectional(
          session_.config(), kMinimumFlowControlSendWindow);
      QuicConfigPeer::SetReceivedInitialSessionFlowControlWindow(
          session_.config(), kMinimumFlowControlSendWindow);
      connection_->AdvanceTime(QuicTime::Delta::FromSeconds(1));
      session_.OnConfigNegotiated();
    }
    TestCryptoStream* crypto_stream = session_.GetMutableCryptoStream();
    EXPECT_CALL(*crypto_stream, HasPendingRetransmission())
        .Times(testing::AnyNumber());
    testing::Mock::VerifyAndClearExpectations(&session_);
  }

  ~QuicSessionTestBase() {
    if (configure_session_) {
      EXPECT_TRUE(session_.is_configured());
    }
  }

  void CheckClosedStreams() {
    QuicStreamId first_stream_id = QuicUtils::GetFirstBidirectionalStreamId(
        connection_->transport_version(), Perspective::IS_CLIENT);
    if (!QuicVersionUsesCryptoFrames(connection_->transport_version())) {
      first_stream_id =
          QuicUtils::GetCryptoStreamId(connection_->transport_version());
    }
    for (QuicStreamId i = first_stream_id; i < 100; i++) {
      if (closed_streams_.find(i) == closed_streams_.end()) {
        EXPECT_FALSE(session_.IsClosedStream(i)) << " stream id: " << i;
      } else {
        EXPECT_TRUE(session_.IsClosedStream(i)) << " stream id: " << i;
      }
    }
  }

  void CloseStream(QuicStreamId id) {
    if (VersionHasIetfQuicFrames(transport_version())) {
      if (QuicUtils::GetStreamType(
              id, session_.perspective(), session_.IsIncomingStream(id),
              connection_->version()) == READ_UNIDIRECTIONAL) {
        // Verify STOP_SENDING but no RST_STREAM is sent for
        // READ_UNIDIRECTIONAL streams.
        EXPECT_CALL(*connection_, SendControlFrame(IsFrame(STOP_SENDING_FRAME)))
            .Times(1)
            .WillOnce(Invoke(&ClearControlFrame));
        EXPECT_CALL(*connection_, OnStreamReset(id, _)).Times(1);
      } else if (QuicUtils::GetStreamType(
                     id, session_.perspective(), session_.IsIncomingStream(id),
                     connection_->version()) == WRITE_UNIDIRECTIONAL) {
        // Verify RST_STREAM but not STOP_SENDING is sent for write-only
        // stream.
        EXPECT_CALL(*connection_, SendControlFrame(IsFrame(RST_STREAM_FRAME)))
            .Times(1)
            .WillOnce(Invoke(&ClearControlFrame));
        EXPECT_CALL(*connection_, OnStreamReset(id, _));
      } else {
        // Verify RST_STREAM and STOP_SENDING are sent for BIDIRECTIONAL
        // streams.
        EXPECT_CALL(*connection_, SendControlFrame(IsFrame(RST_STREAM_FRAME)))
            .WillRepeatedly(Invoke(&ClearControlFrame));
        EXPECT_CALL(*connection_, SendControlFrame(IsFrame(STOP_SENDING_FRAME)))
            .WillRepeatedly(Invoke(&ClearControlFrame));
        EXPECT_CALL(*connection_, OnStreamReset(id, _));
      }
    } else {
      EXPECT_CALL(*connection_, SendControlFrame(_))
          .WillOnce(Invoke(&ClearControlFrame));
      EXPECT_CALL(*connection_, OnStreamReset(id, _));
    }
    session_.ResetStream(id, QUIC_STREAM_CANCELLED);
    closed_streams_.insert(id);
  }

  void CompleteHandshake() {
    CryptoHandshakeMessage msg;
    if (connection_->version().UsesTls() &&
        connection_->perspective() == Perspective::IS_SERVER) {
      // HANDSHAKE_DONE frame.
      EXPECT_CALL(*connection_, SendControlFrame(_))
          .WillOnce(Invoke(&ClearControlFrame));
    }
    session_.GetMutableCryptoStream()->OnHandshakeMessage(msg);
  }

  QuicTransportVersion transport_version() const {
    return connection_->transport_version();
  }

  QuicStreamId GetNthClientInitiatedBidirectionalId(int n) {
    return QuicUtils::GetFirstBidirectionalStreamId(
               connection_->transport_version(), Perspective::IS_CLIENT) +
           QuicUtils::StreamIdDelta(connection_->transport_version()) * n;
  }

  QuicStreamId GetNthClientInitiatedUnidirectionalId(int n) {
    return QuicUtils::GetFirstUnidirectionalStreamId(
               connection_->transport_version(), Perspective::IS_CLIENT) +
           QuicUtils::StreamIdDelta(connection_->transport_version()) * n;
  }

  QuicStreamId GetNthServerInitiatedBidirectionalId(int n) {
    return QuicUtils::GetFirstBidirectionalStreamId(
               connection_->transport_version(), Perspective::IS_SERVER) +
           QuicUtils::StreamIdDelta(connection_->transport_version()) * n;
  }

  QuicStreamId GetNthServerInitiatedUnidirectionalId(int n) {
    return QuicUtils::GetFirstUnidirectionalStreamId(
               connection_->transport_version(), Perspective::IS_SERVER) +
           QuicUtils::StreamIdDelta(connection_->transport_version()) * n;
  }

  QuicStreamId StreamCountToId(QuicStreamCount stream_count,
                               Perspective perspective, bool bidirectional) {
    // Calculate and build up stream ID rather than use
    // GetFirst... because tests that rely on this method
    // needs to do the stream count where #1 is 0/1/2/3, and not
    // take into account that stream 0 is special.
    QuicStreamId id =
        ((stream_count - 1) * QuicUtils::StreamIdDelta(transport_version()));
    if (!bidirectional) {
      id |= 0x2;
    }
    if (perspective == Perspective::IS_SERVER) {
      id |= 0x1;
    }
    return id;
  }

  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  NiceMock<MockQuicSessionVisitor> session_visitor_;
  StrictMock<MockQuicConnection>* connection_;
  TestSession session_;
  std::set<QuicStreamId> closed_streams_;
  bool configure_session_;
};

class QuicSessionTestServer : public QuicSessionTestBase {
 public:
  // CheckMultiPathResponse validates that a written packet
  // contains both expected path responses.
  WriteResult CheckMultiPathResponse(const char* buffer, size_t buf_len,
                                     const QuicIpAddress& /*self_address*/,
                                     const QuicSocketAddress& /*peer_address*/,
                                     PerPacketOptions* /*options*/) {
    QuicEncryptedPacket packet(buffer, buf_len);
    {
      InSequence s;
      EXPECT_CALL(framer_visitor_, OnPacket());
      EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
      EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
      EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_, _));
      EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
      EXPECT_CALL(framer_visitor_, OnPathResponseFrame(_))
          .WillOnce(
              WithArg<0>(Invoke([this](const QuicPathResponseFrame& frame) {
                EXPECT_EQ(path_frame_buffer1_, frame.data_buffer);
                return true;
              })));
      EXPECT_CALL(framer_visitor_, OnPathResponseFrame(_))
          .WillOnce(
              WithArg<0>(Invoke([this](const QuicPathResponseFrame& frame) {
                EXPECT_EQ(path_frame_buffer2_, frame.data_buffer);
                return true;
              })));
      EXPECT_CALL(framer_visitor_, OnPacketComplete());
    }
    client_framer_.ProcessPacket(packet);
    return WriteResult(WRITE_STATUS_OK, 0);
  }

 protected:
  QuicSessionTestServer()
      : QuicSessionTestBase(Perspective::IS_SERVER, /*configure_session=*/true),
        path_frame_buffer1_({0, 1, 2, 3, 4, 5, 6, 7}),
        path_frame_buffer2_({8, 9, 10, 11, 12, 13, 14, 15}),
        client_framer_(SupportedVersions(GetParam()), QuicTime::Zero(),
                       Perspective::IS_CLIENT, kQuicDefaultConnectionIdLength) {
    client_framer_.set_visitor(&framer_visitor_);
    client_framer_.SetInitialObfuscators(TestConnectionId());
    if (client_framer_.version().KnowsWhichDecrypterToUse()) {
      client_framer_.InstallDecrypter(
          ENCRYPTION_FORWARD_SECURE,
          std::make_unique<NullDecrypter>(Perspective::IS_CLIENT));
    }
  }

  QuicPathFrameBuffer path_frame_buffer1_;
  QuicPathFrameBuffer path_frame_buffer2_;
  StrictMock<MockFramerVisitor> framer_visitor_;
  // Framer used to process packets sent by server.
  QuicFramer client_framer_;
};

INSTANTIATE_TEST_SUITE_P(Tests, QuicSessionTestServer,
                         ::testing::ValuesIn(AllSupportedVersions()),
                         ::testing::PrintToStringParamName());

TEST_P(QuicSessionTestServer, PeerAddress) {
  EXPECT_EQ(QuicSocketAddress(QuicIpAddress::Loopback4(), kTestPort),
            session_.peer_address());
}

TEST_P(QuicSessionTestServer, SelfAddress) {
  EXPECT_TRUE(session_.self_address().IsInitialized());
}

TEST_P(QuicSessionTestServer, DontCallOnWriteBlockedForDisconnectedConnection) {
  EXPECT_CALL(*connection_, CloseConnection(_, _, _))
      .WillOnce(
          Invoke(connection_, &MockQuicConnection::ReallyCloseConnection));
  connection_->CloseConnection(QUIC_NO_ERROR, "Everything is fine.",
                               ConnectionCloseBehavior::SILENT_CLOSE);
  ASSERT_FALSE(connection_->connected());

  EXPECT_CALL(session_visitor_, OnWriteBlocked(_)).Times(0);
  session_.OnWriteBlocked();
}

TEST_P(QuicSessionTestServer, OneRttKeysAvailable) {
  EXPECT_FALSE(session_.OneRttKeysAvailable());
  CompleteHandshake();
  EXPECT_TRUE(session_.OneRttKeysAvailable());
}

TEST_P(QuicSessionTestServer, IsClosedStreamDefault) {
  // Ensure that no streams are initially closed.
  QuicStreamId first_stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      connection_->transport_version(), Perspective::IS_CLIENT);
  if (!QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    first_stream_id =
        QuicUtils::GetCryptoStreamId(connection_->transport_version());
  }
  for (QuicStreamId i = first_stream_id; i < 100; i++) {
    EXPECT_FALSE(session_.IsClosedStream(i)) << "stream id: " << i;
  }
}

TEST_P(QuicSessionTestServer, AvailableBidirectionalStreams) {
  ASSERT_TRUE(session_.GetOrCreateStream(
                  GetNthClientInitiatedBidirectionalId(3)) != nullptr);
  // Smaller bidirectional streams should be available.
  EXPECT_TRUE(QuicSessionPeer::IsStreamAvailable(
      &session_, GetNthClientInitiatedBidirectionalId(1)));
  EXPECT_TRUE(QuicSessionPeer::IsStreamAvailable(
      &session_, GetNthClientInitiatedBidirectionalId(2)));
  ASSERT_TRUE(session_.GetOrCreateStream(
                  GetNthClientInitiatedBidirectionalId(2)) != nullptr);
  ASSERT_TRUE(session_.GetOrCreateStream(
                  GetNthClientInitiatedBidirectionalId(1)) != nullptr);
}

TEST_P(QuicSessionTestServer, AvailableUnidirectionalStreams) {
  ASSERT_TRUE(session_.GetOrCreateStream(
                  GetNthClientInitiatedUnidirectionalId(3)) != nullptr);
  // Smaller unidirectional streams should be available.
  EXPECT_TRUE(QuicSessionPeer::IsStreamAvailable(
      &session_, GetNthClientInitiatedUnidirectionalId(1)));
  EXPECT_TRUE(QuicSessionPeer::IsStreamAvailable(
      &session_, GetNthClientInitiatedUnidirectionalId(2)));
  ASSERT_TRUE(session_.GetOrCreateStream(
                  GetNthClientInitiatedUnidirectionalId(2)) != nullptr);
  ASSERT_TRUE(session_.GetOrCreateStream(
                  GetNthClientInitiatedUnidirectionalId(1)) != nullptr);
}

TEST_P(QuicSessionTestServer, MaxAvailableBidirectionalStreams) {
  if (VersionHasIetfQuicFrames(transport_version())) {
    EXPECT_EQ(session_.max_open_incoming_bidirectional_streams(),
              session_.MaxAvailableBidirectionalStreams());
  } else {
    // The protocol specification requires that there can be at least 10 times
    // as many available streams as the connection's maximum open streams.
    EXPECT_EQ(session_.max_open_incoming_bidirectional_streams() *
                  kMaxAvailableStreamsMultiplier,
              session_.MaxAvailableBidirectionalStreams());
  }
}

TEST_P(QuicSessionTestServer, MaxAvailableUnidirectionalStreams) {
  if (VersionHasIetfQuicFrames(transport_version())) {
    EXPECT_EQ(session_.max_open_incoming_unidirectional_streams(),
              session_.MaxAvailableUnidirectionalStreams());
  } else {
    // The protocol specification requires that there can be at least 10 times
    // as many available streams as the connection's maximum open streams.
    EXPECT_EQ(session_.max_open_incoming_unidirectional_streams() *
                  kMaxAvailableStreamsMultiplier,
              session_.MaxAvailableUnidirectionalStreams());
  }
}

TEST_P(QuicSessionTestServer, IsClosedBidirectionalStreamLocallyCreated) {
  CompleteHandshake();
  TestStream* stream2 = session_.CreateOutgoingBidirectionalStream();
  EXPECT_EQ(GetNthServerInitiatedBidirectionalId(0), stream2->id());
  TestStream* stream4 = session_.CreateOutgoingBidirectionalStream();
  EXPECT_EQ(GetNthServerInitiatedBidirectionalId(1), stream4->id());

  CheckClosedStreams();
  CloseStream(GetNthServerInitiatedBidirectionalId(0));
  CheckClosedStreams();
  CloseStream(GetNthServerInitiatedBidirectionalId(1));
  CheckClosedStreams();
}

TEST_P(QuicSessionTestServer, IsClosedUnidirectionalStreamLocallyCreated) {
  CompleteHandshake();
  TestStream* stream2 = session_.CreateOutgoingUnidirectionalStream();
  EXPECT_EQ(GetNthServerInitiatedUnidirectionalId(0), stream2->id());
  TestStream* stream4 = session_.CreateOutgoingUnidirectionalStream();
  EXPECT_EQ(GetNthServerInitiatedUnidirectionalId(1), stream4->id());

  CheckClosedStreams();
  CloseStream(GetNthServerInitiatedUnidirectionalId(0));
  CheckClosedStreams();
  CloseStream(GetNthServerInitiatedUnidirectionalId(1));
  CheckClosedStreams();
}

TEST_P(QuicSessionTestServer, IsClosedBidirectionalStreamPeerCreated) {
  CompleteHandshake();
  QuicStreamId stream_id1 = GetNthClientInitiatedBidirectionalId(0);
  QuicStreamId stream_id2 = GetNthClientInitiatedBidirectionalId(1);
  session_.GetOrCreateStream(stream_id1);
  session_.GetOrCreateStream(stream_id2);

  CheckClosedStreams();
  CloseStream(stream_id1);
  CheckClosedStreams();
  CloseStream(stream_id2);
  // Create a stream, and make another available.
  QuicStream* stream3 = session_.GetOrCreateStream(
      stream_id2 +
      2 * QuicUtils::StreamIdDelta(connection_->transport_version()));
  CheckClosedStreams();
  // Close one, but make sure the other is still not closed
  CloseStream(stream3->id());
  CheckClosedStreams();
}

TEST_P(QuicSessionTestServer, IsClosedUnidirectionalStreamPeerCreated) {
  CompleteHandshake();
  QuicStreamId stream_id1 = GetNthClientInitiatedUnidirectionalId(0);
  QuicStreamId stream_id2 = GetNthClientInitiatedUnidirectionalId(1);
  session_.GetOrCreateStream(stream_id1);
  session_.GetOrCreateStream(stream_id2);

  CheckClosedStreams();
  CloseStream(stream_id1);
  CheckClosedStreams();
  CloseStream(stream_id2);
  // Create a stream, and make another available.
  QuicStream* stream3 = session_.GetOrCreateStream(
      stream_id2 +
      2 * QuicUtils::StreamIdDelta(connection_->transport_version()));
  CheckClosedStreams();
  // Close one, but make sure the other is still not closed
  CloseStream(stream3->id());
```