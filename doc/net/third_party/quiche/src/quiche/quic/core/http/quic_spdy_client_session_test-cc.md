Response:
The user wants a summary of the functionality of the provided C++ source code file. The file appears to be a test suite for `QuicSpdyClientSession` in the Chromium networking stack.

Here's a breakdown of how to address each point in the request:

1. **Functionality:**  Identify the main purpose of the file. It tests the behavior of the `QuicSpdyClientSession` class. This involves creating test scenarios and verifying expected outcomes.

2. **Relationship to Javascript:** Consider if any of the tested functionalities have direct parallels or implications for how QUIC works in a web browser environment where Javascript is present. This likely involves how the client session interacts with HTTP/3 (or SPDY) and how that affects web page loading or data transfer.

3. **Logical Reasoning (Hypothetical Input/Output):** Select a few representative test cases and describe the setup (input) and the expected outcome (output). This helps illustrate the testing methodology.

4. **Common User/Programming Errors:** Identify potential mistakes developers might make when using or interacting with `QuicSpdyClientSession` based on the tests.

5. **User Operation to Reach Here (Debugging):** Think about the steps a developer might take within the Chromium project that would lead them to examine this test file. This usually involves investigating network issues or making changes to the QUIC implementation.

6. **Summary of Functionality (Part 1):**  Provide a concise overview of the file's purpose based on the analysis of the first part of the code.

**Mental Sandbox:**

* **Scan the includes:**  The included headers point to core QUIC components like `QuicConnection`, `QuicCryptoClientConfig`, `QuicSpdyClientStream`, etc., reinforcing that this is about testing the client session. The `test_tools` directory indicates the presence of mocking and helper classes for testing.
* **Look at the test class name:** `QuicSpdyClientSessionTest` clearly names the class being tested.
* **Examine the individual tests (TEST_P):**  The tests cover areas like crypto handshake, stream creation limits, handling of GOAWAY frames, processing of invalid packets, and interaction with settings frames.
* **Think about Javascript interaction:**  The HTTP/3 settings, header handling, and stream management are relevant to how Javascript-initiated requests are handled over QUIC.
* **Consider user errors:** Misconfiguring the QUIC client, exceeding stream limits, or not handling connection errors properly are potential user errors.
* **Imagine debugging:** A developer investigating a QUIC connection issue or working on new QUIC features would likely examine these tests.

**Constraint Checklist & Confidence Score:**

* List functionality? Yes.
* Javascript relation? Yes.
* Examples of Javascript relation? Yes.
* Logical reasoning? Yes.
* Hypothetical input/output? Yes.
* Common user errors? Yes.
* Example of user errors? Yes.
* User operation for debugging? Yes.
* Summary of functionality (part 1)? Yes.

Confidence Score: 5/5

**Strategizing complete.** I will now proceed to generate the response based on the above analysis.

这个C++源代码文件 `quic_spdy_client_session_test.cc` 是 Chromium 网络栈中 QUIC 协议的客户端会话 (`QuicSpdyClientSession`) 的单元测试文件。它的主要功能是：

**功能列表:**

1. **测试客户端 QUIC 会话的生命周期管理:**  包括会话的创建、初始化、连接建立（加密握手）、关闭等过程。例如，`TEST_P(QuicSpdyClientSessionTest, CryptoConnect)` 测试了加密连接的建立。
2. **测试数据流的创建和管理:**  验证客户端能否正确创建和管理双向流 (`CreateOutgoingBidirectionalStream`) 以及接收服务端创建的单向流 (`CreateIncomingStream`)。例如，`TEST_P(QuicSpdyClientSessionTest, MaxNumStreamsWithNoFinOrRst)` 测试了在没有收到 FIN 或 RST 帧的情况下，最大流数量的限制。
3. **测试 QUIC 加密握手流程:**  涵盖了完整的加密握手过程，包括 0-RTT 连接的建立和回滚处理。例如，`TEST_P(QuicSpdyClientSessionTest, CryptoConnect)` 和 `TEST_P(QuicSpdyClientSessionTest, NoEncryptionAfterInitialEncryption)` 涉及到加密握手测试。
4. **测试流控制机制:**  验证客户端是否正确处理流控，包括最大流数量的限制 (`MaxNumStreamsWithNoFinOrRst`, `MaxNumStreamsWithRst`)。
5. **测试错误处理:**  模拟和验证客户端在接收到无效数据包、错误帧等情况下的行为，例如 `TEST_P(QuicSpdyClientSessionTest, InvalidPacketReceived)` 和 `TEST_P(QuicSpdyClientSessionTest, InvalidFramedPacketReceived)`。
6. **测试 GOAWAY 帧的处理:**  验证客户端在收到服务端发送的 GOAWAY 帧后，是否停止创建新的流。例如，`TEST_P(QuicSpdyClientSessionTest, GoAwayReceived)`。
7. **测试 RST_STREAM 帧的处理:**  验证客户端发送和接收 RST_STREAM 帧后的流状态变化，以及对后续创建流的影响。例如，`TEST_P(QuicSpdyClientSessionTest, MaxNumStreamsWithRst)` 和 `TEST_P(QuicSpdyClientSessionTest, ResetAndTrailers)`。
8. **测试 HTTP/3 特性 (如果启用):**  例如，测试对 SETTINGS 帧的处理 (`TEST_P(QuicSpdyClientSessionTest, OnSettingsFrame)`)，这与 HTTP/3 的配置有关。
9. **测试 0-RTT 连接:** 验证客户端在支持 0-RTT 的情况下，能否正确建立连接并处理 0-RTT 被拒绝的情况。例如，`TEST_P(QuicSpdyClientSessionTest, NoEncryptionAfterInitialEncryption)` 和 `TEST_P(QuicSpdyClientSessionTest, IetfZeroRttSetup)`。
10. **测试 Trailers (尾部 header) 的处理:** 验证客户端在发送 RST 后收到 Trailers 的处理逻辑。例如，`TEST_P(QuicSpdyClientSessionTest, ResetAndTrailers)` 和 `TEST_P(QuicSpdyClientSessionTest, ReceivedMalformedTrailersAfterSendingRst)`。

**与 Javascript 的关系 (举例说明):**

虽然此文件是 C++ 代码，直接在浏览器内核中运行，但它测试的功能直接影响到 Javascript 如何通过 QUIC 进行网络通信。

* **HTTP/3 SETTINGS 帧的处理:** Javascript 发起的请求最终会通过 QUIC 发送。服务端发送的 HTTP/3 SETTINGS 帧（例如 `SETTINGS_QPACK_MAX_TABLE_CAPACITY`，用于控制头部压缩）会影响浏览器如何编码和解码 HTTP 头部。如果测试中 `OnSettingsFrame` 功能不正确，可能导致 Javascript 发起的请求或响应头部信息丢失或解析错误。

   **假设输入:** 服务端发送一个包含 `SETTINGS_QPACK_MAX_TABLE_CAPACITY: 4096` 的 SETTINGS 帧。
   **预期输出:** 客户端会话存储这个值，并将其用于后续的 QPACK 编码/解码操作。这会影响 Javascript 中 `fetch()` API 获取响应的头部信息的方式。

* **最大流数量的限制:**  `MaxNumStreamsWithNoFinOrRst` 等测试确保客户端遵守服务端设置的最大并发流数量。如果客户端创建的流超过限制，服务端可能拒绝请求。这会直接影响 Javascript 中同时发起的多个网络请求的并发性能，例如页面加载时加载多个资源。

   **假设输入:** 服务端设置最大双向流数量为 1。 Javascript 代码尝试同时发起两个 `fetch()` 请求。
   **预期输出:** 第一个请求成功创建流并发送，第二个请求可能会被阻塞，直到第一个流关闭或收到服务端允许更多流的信号。这在 Javascript 层面可能体现为第二个 `fetch()` 的 Promise 延迟 resolve。

**逻辑推理 (假设输入与输出):**

* **测试 `MaxNumStreamsWithRst`:**
    * **假设输入:** 服务端允许的最大流数量为 1。 客户端创建一个流并发送请求。 客户端随后重置 (RST) 该流。 服务端也发送 RST 确认。
    * **预期输出:** 客户端应该能够创建一个新的流，因为之前的流已经被完全关闭。如果测试失败，可能导致客户端在应该可以创建新流的时候无法创建。

* **测试 `GoAwayReceived`:**
    * **假设输入:**  客户端已建立连接并正常通信。 服务端发送一个 GOAWAY 帧。
    * **预期输出:** 客户端应该不再允许创建新的 *出站* 流（由客户端发起的流）。 现有的流可以继续完成。 如果测试失败，客户端可能会继续尝试创建新流，导致连接不稳定或错误。

**用户或编程常见的使用错误 (举例说明):**

* **未正确处理连接关闭:** 开发者在网络应用中可能没有妥善处理 QUIC 连接被服务端关闭的情况（例如收到 GOAWAY）。`GoAwayReceived` 的测试保证了客户端在收到 GOAWAY 后不再创建新流，避免程序因此崩溃或出现不可预测的行为。
    * **错误示例 (Javascript):**  发起多个 `fetch()` 请求，但没有监听 `connection.close()` 事件或处理 `fetch()` 请求失败的情况，可能导致在服务端发送 GOAWAY 后，新的请求无法发出，并且没有错误提示。

* **超出服务端允许的最大流数量:**  开发者可能会在短时间内发起大量的并发请求，而没有考虑到服务端设置的最大流数量限制。 `MaxNumStreamsWithNoFinOrRst` 等测试确保了客户端遵守这些限制。
    * **错误示例 (Javascript):**  使用 `Promise.all()` 或类似的机制同时发起大量 `fetch()` 请求，而没有限制并发数量，可能导致部分请求被服务端拒绝。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设开发者遇到一个与 QUIC 客户端会话行为相关的 Bug，例如：

1. **用户报告网页加载缓慢或失败:** 用户在使用 Chrome 浏览器访问某个网站时，页面加载速度异常缓慢，或者部分资源加载失败。
2. **开发者检查网络请求:**  开发者使用 Chrome 的开发者工具 (F12) 的 Network 选项卡，发现某些请求的状态异常，例如长时间 Pending 或 Failed。
3. **怀疑 QUIC 连接问题:**  如果该网站使用了 QUIC 协议，开发者可能会怀疑是 QUIC 连接或会话的问题。
4. **查看 Chromium 源代码:**  开发者可能会查阅 Chromium 的网络栈源代码，特别是与 QUIC 协议相关的部分。
5. **定位到 `QuicSpdyClientSession`:**  通过搜索或代码导航，开发者可能会找到 `net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_client_session.h` 和 `.cc` 文件，了解客户端会话的实现细节。
6. **查看测试文件 `quic_spdy_client_session_test.cc`:** 为了理解客户端会话的预期行为和各种场景下的处理逻辑，开发者会查看对应的测试文件，例如这个 `quic_spdy_client_session_test.cc`。通过阅读测试用例，开发者可以了解在什么情况下会创建流、连接会如何关闭、如何处理错误等等。
7. **运行或调试测试:**  开发者可能会尝试运行这些测试用例，或者在本地环境中调试 QUIC 连接，以复现用户报告的问题，并验证其修复方案的正确性。

**归纳一下它的功能 (第1部分):**

这个文件的主要功能是提供了一套全面的单元测试，用于验证 Chromium 中 QUIC 客户端会话 (`QuicSpdyClientSession`) 的核心行为和功能是否符合预期。它涵盖了连接建立、流管理、错误处理、QUIC 协议的关键机制（如流控制、GOAWAY、RST_STREAM）以及 HTTP/3 特性的测试。这些测试对于确保 QUIC 客户端的稳定性和正确性至关重要，进而保障基于 QUIC 协议的网络应用的正常运行。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_client_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/http/quic_spdy_client_session.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/macros.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/null_decrypter.h"
#include "quiche/quic/core/crypto/null_encrypter.h"
#include "quiche/quic/core/http/http_constants.h"
#include "quiche/quic/core/http/http_frames.h"
#include "quiche/quic/core/http/quic_spdy_client_stream.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/core/tls_client_handshaker.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/mock_quic_spdy_client_stream.h"
#include "quiche/quic/test_tools/quic_config_peer.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/quic/test_tools/quic_framer_peer.h"
#include "quiche/quic/test_tools/quic_packet_creator_peer.h"
#include "quiche/quic/test_tools/quic_sent_packet_manager_peer.h"
#include "quiche/quic/test_tools/quic_session_peer.h"
#include "quiche/quic/test_tools/quic_spdy_session_peer.h"
#include "quiche/quic/test_tools/quic_stream_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/test_tools/simple_session_cache.h"
#include "quiche/common/http/http_header_block.h"

using quiche::HttpHeaderBlock;
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::AtLeast;
using ::testing::AtMost;
using ::testing::Invoke;
using ::testing::StrictMock;
using ::testing::Truly;

namespace quic {
namespace test {
namespace {

const char kServerHostname[] = "test.example.com";
const uint16_t kPort = 443;

class TestQuicSpdyClientSession : public QuicSpdyClientSession {
 public:
  explicit TestQuicSpdyClientSession(
      const QuicConfig& config,
      const ParsedQuicVersionVector& supported_versions,
      QuicConnection* connection, const QuicServerId& server_id,
      QuicCryptoClientConfig* crypto_config)
      : QuicSpdyClientSession(config, supported_versions, connection, server_id,
                              crypto_config) {}

  std::unique_ptr<QuicSpdyClientStream> CreateClientStream() override {
    return std::make_unique<MockQuicSpdyClientStream>(
        GetNextOutgoingBidirectionalStreamId(), this, BIDIRECTIONAL);
  }

  MockQuicSpdyClientStream* CreateIncomingStream(QuicStreamId id) override {
    if (!ShouldCreateIncomingStream(id)) {
      return nullptr;
    }
    MockQuicSpdyClientStream* stream =
        new MockQuicSpdyClientStream(id, this, READ_UNIDIRECTIONAL);
    ActivateStream(absl::WrapUnique(stream));
    return stream;
  }
};

class QuicSpdyClientSessionTest : public QuicTestWithParam<ParsedQuicVersion> {
 protected:
  QuicSpdyClientSessionTest() {
    auto client_cache = std::make_unique<test::SimpleSessionCache>();
    client_session_cache_ = client_cache.get();
    client_crypto_config_ = std::make_unique<QuicCryptoClientConfig>(
        crypto_test_utils::ProofVerifierForTesting(), std::move(client_cache));
    server_crypto_config_ = crypto_test_utils::CryptoServerConfigForTesting();
    Initialize();
    // Advance the time, because timers do not like uninitialized times.
    connection_->AdvanceTime(QuicTime::Delta::FromSeconds(1));
  }

  ~QuicSpdyClientSessionTest() override {
    session_.reset(nullptr);
  }

  void Initialize() {
    session_.reset();
    connection_ = new ::testing::NiceMock<PacketSavingConnection>(
        &helper_, &alarm_factory_, Perspective::IS_CLIENT,
        SupportedVersions(GetParam()));
    session_ = std::make_unique<TestQuicSpdyClientSession>(
        DefaultQuicConfig(), SupportedVersions(GetParam()), connection_,
        QuicServerId(kServerHostname, kPort), client_crypto_config_.get());
    session_->Initialize();
    connection_->SetEncrypter(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<NullEncrypter>(connection_->perspective()));
    crypto_stream_ = static_cast<QuicCryptoClientStream*>(
        session_->GetMutableCryptoStream());
  }

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

 public:
  bool ClearStreamsBlockedControlFrame(const QuicFrame& frame) {
    if (frame.type == STREAMS_BLOCKED_FRAME) {
      DeleteFrame(&const_cast<QuicFrame&>(frame));
      return true;
    }
    return false;
  }

 protected:
  void CompleteCryptoHandshake() {
    CompleteCryptoHandshake(kDefaultMaxStreamsPerConnection);
  }

  void CompleteCryptoHandshake(uint32_t server_max_incoming_streams) {
    if (VersionHasIetfQuicFrames(connection_->transport_version())) {
      EXPECT_CALL(*connection_, SendControlFrame(_))
          .Times(::testing::AnyNumber())
          .WillRepeatedly(Invoke(
              this, &QuicSpdyClientSessionTest::ClearMaxStreamsControlFrame));
    }
    session_->CryptoConnect();
    QuicConfig config = DefaultQuicConfig();
    if (VersionHasIetfQuicFrames(connection_->transport_version())) {
      config.SetMaxUnidirectionalStreamsToSend(server_max_incoming_streams);
      config.SetMaxBidirectionalStreamsToSend(server_max_incoming_streams);
    } else {
      config.SetMaxBidirectionalStreamsToSend(server_max_incoming_streams);
    }
    crypto_test_utils::HandshakeWithFakeServer(
        &config, server_crypto_config_.get(), &helper_, &alarm_factory_,
        connection_, crypto_stream_, AlpnForVersion(connection_->version()));
  }

  void CreateConnection() {
    connection_ = new ::testing::NiceMock<PacketSavingConnection>(
        &helper_, &alarm_factory_, Perspective::IS_CLIENT,
        SupportedVersions(GetParam()));
    // Advance the time, because timers do not like uninitialized times.
    connection_->AdvanceTime(QuicTime::Delta::FromSeconds(1));
    session_ = std::make_unique<TestQuicSpdyClientSession>(
        DefaultQuicConfig(), SupportedVersions(GetParam()), connection_,
        QuicServerId(kServerHostname, kPort), client_crypto_config_.get());
    session_->Initialize();
    crypto_stream_ = static_cast<QuicCryptoClientStream*>(
        session_->GetMutableCryptoStream());
  }

  void CompleteFirstConnection() {
    CompleteCryptoHandshake();
    EXPECT_FALSE(session_->GetCryptoStream()->IsResumption());
    if (session_->version().UsesHttp3()) {
      SettingsFrame settings;
      settings.values[SETTINGS_QPACK_MAX_TABLE_CAPACITY] = 2;
      settings.values[SETTINGS_MAX_FIELD_SECTION_SIZE] = 5;
      settings.values[256] = 4;  // unknown setting
      session_->OnSettingsFrame(settings);
    }
  }

  // Owned by |session_|.
  QuicCryptoClientStream* crypto_stream_;
  std::unique_ptr<QuicCryptoServerConfig> server_crypto_config_;
  std::unique_ptr<QuicCryptoClientConfig> client_crypto_config_;
  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  ::testing::NiceMock<PacketSavingConnection>* connection_;
  std::unique_ptr<TestQuicSpdyClientSession> session_;
  test::SimpleSessionCache* client_session_cache_;
};

std::string ParamNameFormatter(
    const testing::TestParamInfo<QuicSpdyClientSessionTest::ParamType>& info) {
  return ParsedQuicVersionToString(info.param);
}

INSTANTIATE_TEST_SUITE_P(Tests, QuicSpdyClientSessionTest,
                         ::testing::ValuesIn(AllSupportedVersions()),
                         ParamNameFormatter);

TEST_P(QuicSpdyClientSessionTest, GetSSLConfig) {
  EXPECT_EQ(session_->QuicSpdyClientSessionBase::GetSSLConfig(),
            QuicSSLConfig());
}

TEST_P(QuicSpdyClientSessionTest, CryptoConnect) { CompleteCryptoHandshake(); }

TEST_P(QuicSpdyClientSessionTest, NoEncryptionAfterInitialEncryption) {
  if (GetParam().handshake_protocol == PROTOCOL_TLS1_3) {
    // This test relies on resumption and is QUIC crypto specific, so it is
    // disabled for TLS.
    return;
  }
  // Complete a handshake in order to prime the crypto config for 0-RTT.
  CompleteCryptoHandshake();

  // Now create a second session using the same crypto config.
  Initialize();

  // Starting the handshake should move immediately to encryption
  // established and will allow streams to be created.
  session_->CryptoConnect();
  EXPECT_TRUE(session_->IsEncryptionEstablished());
  QuicSpdyClientStream* stream = session_->CreateOutgoingBidirectionalStream();
  ASSERT_TRUE(stream != nullptr);
  EXPECT_FALSE(QuicUtils::IsCryptoStreamId(connection_->transport_version(),
                                           stream->id()));

  // Process an "inchoate" REJ from the server which will cause
  // an inchoate CHLO to be sent and will leave the encryption level
  // at NONE.
  CryptoHandshakeMessage rej;
  crypto_test_utils::FillInDummyReject(&rej);
  EXPECT_TRUE(session_->IsEncryptionEstablished());
  crypto_test_utils::SendHandshakeMessageToStream(
      session_->GetMutableCryptoStream(), rej, Perspective::IS_CLIENT);
  EXPECT_FALSE(session_->IsEncryptionEstablished());
  EXPECT_EQ(ENCRYPTION_INITIAL,
            QuicPacketCreatorPeer::GetEncryptionLevel(
                QuicConnectionPeer::GetPacketCreator(connection_)));
  // Verify that no new streams may be created.
  EXPECT_TRUE(session_->CreateOutgoingBidirectionalStream() == nullptr);
  // Verify that no data may be send on existing streams.
  char data[] = "hello world";
  QuicConsumedData consumed =
      session_->WritevData(stream->id(), ABSL_ARRAYSIZE(data), 0, NO_FIN,
                           NOT_RETRANSMISSION, ENCRYPTION_INITIAL);
  EXPECT_EQ(0u, consumed.bytes_consumed);
  EXPECT_FALSE(consumed.fin_consumed);
}

TEST_P(QuicSpdyClientSessionTest, MaxNumStreamsWithNoFinOrRst) {
  uint32_t kServerMaxIncomingStreams = 1;
  CompleteCryptoHandshake(kServerMaxIncomingStreams);

  QuicSpdyClientStream* stream = session_->CreateOutgoingBidirectionalStream();
  ASSERT_TRUE(stream);
  EXPECT_FALSE(session_->CreateOutgoingBidirectionalStream());

  // Close the stream, but without having received a FIN or a RST_STREAM
  // or MAX_STREAMS (IETF QUIC) and check that a new one can not be created.
  session_->ResetStream(stream->id(), QUIC_STREAM_CANCELLED);
  EXPECT_EQ(1u, QuicSessionPeer::GetNumOpenDynamicStreams(session_.get()));

  stream = session_->CreateOutgoingBidirectionalStream();
  EXPECT_FALSE(stream);
}

TEST_P(QuicSpdyClientSessionTest, MaxNumStreamsWithRst) {
  uint32_t kServerMaxIncomingStreams = 1;
  CompleteCryptoHandshake(kServerMaxIncomingStreams);

  QuicSpdyClientStream* stream = session_->CreateOutgoingBidirectionalStream();
  ASSERT_NE(nullptr, stream);
  EXPECT_EQ(nullptr, session_->CreateOutgoingBidirectionalStream());

  // Close the stream and receive an RST frame to remove the unfinished stream
  session_->ResetStream(stream->id(), QUIC_STREAM_CANCELLED);
  session_->OnRstStream(QuicRstStreamFrame(kInvalidControlFrameId, stream->id(),
                                           QUIC_RST_ACKNOWLEDGEMENT, 0));
  // Check that a new one can be created.
  EXPECT_EQ(0u, QuicSessionPeer::GetNumOpenDynamicStreams(session_.get()));
  if (VersionHasIetfQuicFrames(GetParam().transport_version)) {
    // In IETF QUIC the stream limit increases only if we get a MAX_STREAMS
    // frame; pretend we got one.

    QuicMaxStreamsFrame frame(0, 2,
                              /*unidirectional=*/false);
    session_->OnMaxStreamsFrame(frame);
  }
  stream = session_->CreateOutgoingBidirectionalStream();
  EXPECT_NE(nullptr, stream);
  if (VersionHasIetfQuicFrames(GetParam().transport_version)) {
    // Ensure that we have 2 total streams, 1 open and 1 closed.
    QuicStreamCount expected_stream_count = 2;
    EXPECT_EQ(expected_stream_count,
              QuicSessionPeer::ietf_bidirectional_stream_id_manager(&*session_)
                  ->outgoing_stream_count());
  }
}

TEST_P(QuicSpdyClientSessionTest, ResetAndTrailers) {
  // Tests the situation in which the client sends a RST at the same time that
  // the server sends trailing headers (trailers). Receipt of the trailers by
  // the client should result in all outstanding stream state being tidied up
  // (including flow control, and number of available outgoing streams).
  uint32_t kServerMaxIncomingStreams = 1;
  CompleteCryptoHandshake(kServerMaxIncomingStreams);

  QuicSpdyClientStream* stream = session_->CreateOutgoingBidirectionalStream();
  ASSERT_NE(nullptr, stream);

  if (VersionHasIetfQuicFrames(GetParam().transport_version)) {
    // For IETF QUIC, trying to open a stream and failing due to lack
    // of stream ids will result in a STREAMS_BLOCKED. Make
    // sure we get one. Also clear out the frame because if it's
    // left sitting, the later SendRstStream will not actually
    // transmit the RST_STREAM because the connection will be in write-blocked
    // state. This means that the SendControlFrame that is expected w.r.t. the
    // RST_STREAM, below, will not be satisfied.
    EXPECT_CALL(*connection_, SendControlFrame(_))
        .WillOnce(Invoke(
            this, &QuicSpdyClientSessionTest::ClearStreamsBlockedControlFrame));
  }

  EXPECT_EQ(nullptr, session_->CreateOutgoingBidirectionalStream());

  QuicStreamId stream_id = stream->id();

  EXPECT_CALL(*connection_, SendControlFrame(_))
      .Times(AtLeast(1))
      .WillRepeatedly(Invoke(&ClearControlFrame));
  EXPECT_CALL(*connection_, OnStreamReset(_, _)).Times(1);
  session_->ResetStream(stream_id, QUIC_STREAM_PEER_GOING_AWAY);

  // A new stream cannot be created as the reset stream still counts as an open
  // outgoing stream until closed by the server.
  EXPECT_EQ(1u, QuicSessionPeer::GetNumOpenDynamicStreams(session_.get()));
  stream = session_->CreateOutgoingBidirectionalStream();
  EXPECT_EQ(nullptr, stream);

  // The stream receives trailers with final byte offset: this is one of three
  // ways that a peer can signal the end of a stream (the others being RST,
  // stream data + FIN).
  QuicHeaderList trailers;
  trailers.OnHeader(kFinalOffsetHeaderKey, "0");
  trailers.OnHeaderBlockEnd(0, 0);
  session_->OnStreamHeaderList(stream_id, /*fin=*/false, 0, trailers);

  // The stream is now complete from the client's perspective, and it should
  // be able to create a new outgoing stream.
  EXPECT_EQ(0u, QuicSessionPeer::GetNumOpenDynamicStreams(session_.get()));
  if (VersionHasIetfQuicFrames(GetParam().transport_version)) {
    QuicMaxStreamsFrame frame(0, 2,
                              /*unidirectional=*/false);

    session_->OnMaxStreamsFrame(frame);
  }
  stream = session_->CreateOutgoingBidirectionalStream();
  EXPECT_NE(nullptr, stream);
  if (VersionHasIetfQuicFrames(GetParam().transport_version)) {
    // Ensure that we have 2 open streams.
    QuicStreamCount expected_stream_count = 2;
    EXPECT_EQ(expected_stream_count,
              QuicSessionPeer::ietf_bidirectional_stream_id_manager(&*session_)
                  ->outgoing_stream_count());
  }
}

TEST_P(QuicSpdyClientSessionTest, ReceivedMalformedTrailersAfterSendingRst) {
  // Tests the situation where the client has sent a RST to the server, and has
  // received trailing headers with a malformed final byte offset value.
  CompleteCryptoHandshake();

  QuicSpdyClientStream* stream = session_->CreateOutgoingBidirectionalStream();
  ASSERT_NE(nullptr, stream);

  // Send the RST, which results in the stream being closed locally (but some
  // state remains while the client waits for a response from the server).
  QuicStreamId stream_id = stream->id();
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .Times(AtLeast(1))
      .WillRepeatedly(Invoke(&ClearControlFrame));
  EXPECT_CALL(*connection_, OnStreamReset(_, _)).Times(1);
  session_->ResetStream(stream_id, QUIC_STREAM_PEER_GOING_AWAY);

  // The stream receives trailers with final byte offset, but the header value
  // is non-numeric and should be treated as malformed.
  QuicHeaderList trailers;
  trailers.OnHeader(kFinalOffsetHeaderKey, "invalid non-numeric value");
  trailers.OnHeaderBlockEnd(0, 0);

  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(1);
  session_->OnStreamHeaderList(stream_id, /*fin=*/false, 0, trailers);
}

TEST_P(QuicSpdyClientSessionTest, OnStreamHeaderListWithStaticStream) {
  // Test situation where OnStreamHeaderList is called by stream with static id.
  CompleteCryptoHandshake();

  QuicHeaderList trailers;
  trailers.OnHeader(kFinalOffsetHeaderKey, "0");
  trailers.OnHeaderBlockEnd(0, 0);

  // Initialize H/3 control stream.
  QuicStreamId id;
  if (VersionUsesHttp3(connection_->transport_version())) {
    id = GetNthServerInitiatedUnidirectionalStreamId(
        connection_->transport_version(), 3);
    char type[] = {0x00};

    QuicStreamFrame data1(id, false, 0, absl::string_view(type, 1));
    session_->OnStreamFrame(data1);
  } else {
    id = QuicUtils::GetHeadersStreamId(connection_->transport_version());
  }

  EXPECT_CALL(*connection_, CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                                            "stream is static", _))
      .Times(1);
  session_->OnStreamHeaderList(id,
                               /*fin=*/false, 0, trailers);
}

TEST_P(QuicSpdyClientSessionTest, GoAwayReceived) {
  if (VersionHasIetfQuicFrames(connection_->transport_version())) {
    return;
  }
  CompleteCryptoHandshake();

  // After receiving a GoAway, I should no longer be able to create outgoing
  // streams.
  session_->connection()->OnGoAwayFrame(QuicGoAwayFrame(
      kInvalidControlFrameId, QUIC_PEER_GOING_AWAY, 1u, "Going away."));
  EXPECT_EQ(nullptr, session_->CreateOutgoingBidirectionalStream());
}

static bool CheckForDecryptionError(QuicFramer* framer) {
  return framer->error() == QUIC_DECRYPTION_FAILURE;
}

// Various sorts of invalid packets that should not cause a connection
// to be closed.
TEST_P(QuicSpdyClientSessionTest, InvalidPacketReceived) {
  QuicSocketAddress server_address(TestPeerIPAddress(), kTestPort);
  QuicSocketAddress client_address(TestPeerIPAddress(), kTestPort);

  EXPECT_CALL(*connection_, ProcessUdpPacket(server_address, client_address, _))
      .WillRepeatedly(Invoke(static_cast<MockQuicConnection*>(connection_),
                             &MockQuicConnection::ReallyProcessUdpPacket));
  EXPECT_CALL(*connection_, OnCanWrite()).Times(AnyNumber());
  EXPECT_CALL(*connection_, OnError(_)).Times(1);

  // Verify that empty packets don't close the connection.
  QuicReceivedPacket zero_length_packet(nullptr, 0, QuicTime::Zero(), false);
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  session_->ProcessUdpPacket(client_address, server_address,
                             zero_length_packet);

  // Verifiy that small, invalid packets don't close the connection.
  char buf[2] = {0x00, 0x01};
  QuicConnectionId connection_id = session_->connection()->connection_id();
  QuicReceivedPacket valid_packet(buf, 2, QuicTime::Zero(), false);
  // Close connection shouldn't be called.
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  EXPECT_CALL(*connection_, OnError(_)).Times(AtMost(1));
  session_->ProcessUdpPacket(client_address, server_address, valid_packet);

  // Verify that a non-decryptable packet doesn't close the connection.
  QuicFramerPeer::SetLastSerializedServerConnectionId(
      QuicConnectionPeer::GetFramer(connection_), connection_id);
  ParsedQuicVersionVector versions = SupportedVersions(GetParam());
  QuicConnectionId destination_connection_id = EmptyQuicConnectionId();
  QuicConnectionId source_connection_id = connection_id;
  std::unique_ptr<QuicEncryptedPacket> packet(ConstructEncryptedPacket(
      destination_connection_id, source_connection_id, false, false, 100,
      "data", true, CONNECTION_ID_ABSENT, CONNECTION_ID_ABSENT,
      PACKET_4BYTE_PACKET_NUMBER, &versions, Perspective::IS_SERVER));
  std::unique_ptr<QuicReceivedPacket> received(
      ConstructReceivedPacket(*packet, QuicTime::Zero()));
  // Change the last byte of the encrypted data.
  *(const_cast<char*>(received->data() + received->length() - 1)) += 1;
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  EXPECT_CALL(*connection_, OnError(Truly(CheckForDecryptionError))).Times(1);
  session_->ProcessUdpPacket(client_address, server_address, *received);
}

// A packet with invalid framing should cause a connection to be closed.
TEST_P(QuicSpdyClientSessionTest, InvalidFramedPacketReceived) {
  const ParsedQuicVersion version = GetParam();
  QuicSocketAddress server_address(TestPeerIPAddress(), kTestPort);
  QuicSocketAddress client_address(TestPeerIPAddress(), kTestPort);
  if (version.KnowsWhichDecrypterToUse()) {
    connection_->InstallDecrypter(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_FORWARD_SECURE));
  } else {
    connection_->SetAlternativeDecrypter(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_FORWARD_SECURE),
        false);
  }

  EXPECT_CALL(*connection_, ProcessUdpPacket(server_address, client_address, _))
      .WillRepeatedly(Invoke(static_cast<MockQuicConnection*>(connection_),
                             &MockQuicConnection::ReallyProcessUdpPacket));
  EXPECT_CALL(*connection_, OnError(_)).Times(1);

  // Verify that a decryptable packet with bad frames does close the connection.
  QuicConnectionId destination_connection_id =
      session_->connection()->connection_id();
  QuicConnectionId source_connection_id = destination_connection_id;
  QuicFramerPeer::SetLastSerializedServerConnectionId(
      QuicConnectionPeer::GetFramer(connection_), destination_connection_id);
  bool version_flag = true;
  QuicConnectionIdIncluded scid_included = CONNECTION_ID_PRESENT;
  std::unique_ptr<QuicEncryptedPacket> packet(ConstructMisFramedEncryptedPacket(
      destination_connection_id, source_connection_id, version_flag, false, 100,
      "data", CONNECTION_ID_ABSENT, scid_included, PACKET_4BYTE_PACKET_NUMBER,
      version, Perspective::IS_SERVER));
  std::unique_ptr<QuicReceivedPacket> received(
      ConstructReceivedPacket(*packet, QuicTime::Zero()));
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(1);
  session_->ProcessUdpPacket(client_address, server_address, *received);
}

TEST_P(QuicSpdyClientSessionTest,
       TryToCreateServerInitiatedBidirectionalStream) {
  if (VersionHasIetfQuicFrames(connection_->transport_version())) {
    EXPECT_CALL(
        *connection_,
        CloseConnection(QUIC_HTTP_SERVER_INITIATED_BIDIRECTIONAL_STREAM, _, _));
  } else {
    EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  }
  session_->GetOrCreateStream(GetNthServerInitiatedBidirectionalStreamId(
      connection_->transport_version(), 0));
}

// Test that upon receiving HTTP/3 SETTINGS, the settings are serialized and
// stored into client session cache.
TEST_P(QuicSpdyClientSessionTest, OnSettingsFrame) {
  // This feature is HTTP/3 only
  if (!VersionUsesHttp3(session_->transport_version())) {
    return;
  }
  CompleteCryptoHandshake();
  SettingsFrame settings;
  settings.values[SETTINGS_QPACK_MAX_TABLE_CAPACITY] = 2;
  settings.values[SETTINGS_MAX_FIELD_SECTION_SIZE] = 5;
  settings.values[256] = 4;   // unknown setting
  char application_state[] = {// type (SETTINGS)
                              0x04,
                              // length
                              0x07,
                              // identifier (SETTINGS_QPACK_MAX_TABLE_CAPACITY)
                              0x01,
                              // content
                              0x02,
                              // identifier (SETTINGS_MAX_FIELD_SECTION_SIZE)
                              0x06,
                              // content
                              0x05,
                              // identifier (256 in variable length integer)
                              0x40 + 0x01, 0x00,
                              // content
                              0x04};
  ApplicationState expected(std::begin(application_state),
                            std::end(application_state));
  session_->OnSettingsFrame(settings);
  EXPECT_EQ(expected, *client_session_cache_
                           ->Lookup(QuicServerId(kServerHostname, kPort),
                                    session_->GetClock()->WallNow(), nullptr)
                           ->application_state);
}

TEST_P(QuicSpdyClientSessionTest, IetfZeroRttSetup) {
  // This feature is TLS-only.
  if (session_->version().UsesQuicCrypto()) {
    return;
  }

  CompleteFirstConnection();

  CreateConnection();
  // Session configs should be in initial state.
  if (session_->version().UsesHttp3()) {
    EXPECT_EQ(0u, session_->flow_controller()->send_window_offset());
    EXPECT_EQ(std::numeric_limits<size_t>::max(),
              session_->max_outbound_header_list_size());
  } else {
    EXPECT_EQ(kMinimumFlowControlSendWindow,
              session_->flow_controller()->send_window_offset());
  }
  session_->CryptoConnect();
  EXPECT_TRUE(session_->IsEncryptionEstablished());
  EXPECT_EQ(ENCRYPTION_ZERO_RTT, session_->connection()->encryption_level());

  // The client session should have a basic setup ready before the handshake
  // succeeds.
  EXPECT_EQ(kInitialSessionFlowControlWindowForTest,
            session_->flow_controller()->send_window_offset());
  if (session_->version().UsesHttp3()) {
    auto* id_manager = QuicSessionPeer::ietf_streamid_manager(session_.get());
    EXPECT_EQ(kDefaultMaxStreamsPerConnection,
              id_manager->max_outgoing_bidirectional_streams());
    EXPECT_EQ(
        kDefaultMaxStreamsPerConnection + kHttp3StaticUnidirectionalStreamCount,
        id_manager->max_outgoing_unidirectional_streams());
    auto* control_stream =
        QuicSpdySessionPeer::GetSendControlStream(session_.get());
    EXPECT_EQ(kInitialStreamFlowControlWindowForTest,
              QuicStreamPeer::SendWindowOffset(control_stream));
    EXPECT_EQ(5u, session_->max_outbound_header_list_size());
  } else {
    auto* id_manager = QuicSessionPeer::GetStreamIdManager(session_.get());
    EXPECT_EQ(kDefaultMaxStreamsPerConnection,
              id_manager->max_open_outgoing_streams());
  }

  // Complete the handshake with a different config.
  QuicConfig config = DefaultQuicConfig();
  config.SetInitialMaxStreamDataBytesUnidirectionalToSend(
      kInitialStreamFlowControlWindowForTest + 1);
  config.SetInitialSessionFlowControlWindowToSend(
      kInitialSessionFlowControlWindowForTest + 1);
  config.SetMaxBidirectionalStreamsToSend(kDefaultMaxStreamsPerConnection + 1);
  config.SetMaxUnidirectionalStreamsToSend(kDefaultMaxStreamsPerConnection + 1);
  crypto_test_utils::HandshakeWithFakeServer(
      &config, server_crypto_config_.get(), &helper_, &alarm_factory_,
      connection_, crypto_stream_, AlpnForVersion(connection_->version()));

  EXPECT_TRUE(session_->GetCryptoStream()->IsResumption());
  EXPECT_EQ(kInitialSessionFlowControlWindowForTest + 1,
            session_->flow_controller()->send_window_offset());
  if (session_->version().UsesHttp3()) {
    auto* id_manager = QuicSessionPeer::ietf_streamid_manager(session_.get());
    auto* control_stream =
        QuicSpdySessionPeer::GetSendControlStream(session_.get());
    EXPECT_EQ(kDefaultMaxStreamsPerConnection + 1,
              id_manager->max_outgoing_bidirectional_streams());
    EXPECT_EQ(kDefaultMaxStreamsPerConnection +
                  kHttp3StaticUnidirectionalStreamCount + 1,
              id_manager->max_outgoing_unidirectional_streams());
    EXPECT_EQ(kInitialStreamFlowControlWindowForTest + 1,
              QuicStreamPeer::SendWindowOffset(control_stream));
  } else {
    auto* id_manager = QuicSessionPeer::GetStreamIdManager(session_.get());
    EXPECT_EQ(kDefaultMaxStreamsPerConnection + 1,
              id_manager->max_open_outgoing_streams());
  }

  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  // Let the session receive a new SETTINGS frame to complete the second
  // connection.
  if (session_->version().UsesHttp3()) {
    SettingsFrame settings;
    settings.values[SETTINGS_QPACK_MAX_TABLE_CAPACITY] = 2;
    settings.values[SETTINGS_MAX_FIELD_SECTION_SIZE] = 5;
    settings.values[256] = 4;  // unknown setting
    session_->OnSettingsFrame(settings);
  }
}

// Regression test for b/159168475
TEST_P(QuicSpdyClientSessionTest, RetransmitDataOnZeroRttReject) {
  // This feature is TLS-only.
  if (session_->version().UsesQuicCrypto()) {
    return;
  }

  CompleteFirstConnection();

  // Create a second connection, but disable 0-RTT on the server.
  CreateConnection();
  ON_CALL(*connection_, OnCanWrite())
      .WillByDefault(
          testing::Invoke(connection_, &MockQuicConnection::ReallyOnCanWrite));
  EXPECT_CALL(*connection_, OnCanWrite()).Times(0);

  QuicConfig config = DefaultQuicConfig();
  config.SetMaxUnidirectionalStreamsToSend(kDefaultMaxStreamsPerConnection);
  config.SetMaxBidirectionalStreamsToSend(kDefaultMaxStreamsPerConnection);
  SSL_CTX_set_early_data_enabled(server_crypto_config_->ssl_ctx(), false);

  // Packets will be written: CHLO, HTTP/3 SETTINGS (H/3 only), and request
  // data.
  EXPECT_CALL(*connection_,
              OnPacketSent(ENCRYPTION_INITIAL, NOT_RETRANSMISSION));
  EXPECT_CALL(*connection_,
              OnPacketSent(ENCRYPTION_ZERO_RTT, NOT_RETRANSMISSION))
      .Times(session_->version().UsesHttp3() ? 2 : 1);
  session_->CryptoConnect();
  EXPECT_TRUE(session_->IsEncryptionEstablished());
  EXPECT_EQ(ENCRYPTION_ZERO_RTT, session_->connection()->encryption_level());
  QuicSpdyClientStream* stream = session_->CreateOutgoingBidirectionalStream();
  ASSERT_TRUE(stream);
  stream->WriteOrBufferData("hello", true, nullptr);

  // When handshake is done, the client sends 2 packet: HANDSHAKE FINISHED, and
  // coalesced retransmission of HTTP/3 SETTINGS and request data.
  EXPECT_CALL(*connection_,
              OnPacketSent(ENCRYPTION_HANDSHAKE, NOT_RETRANSMISSION));
  // TODO(b/158027651): change transmission type to ALL_ZERO_RTT_RETRANSMISSION.
  EXPECT_CALL(*connection_,
              OnPacketSent(ENCRYPTION_FORWARD_SECURE, LOSS_RETRANSMISSION));
  crypto_test_utils::HandshakeWithFakeServer(
      &config, server_crypto_config_.get(), &helper_, &alarm_factory_,
      connection_, crypto_stream_, AlpnForVersion(connection_->version()));
  EXPECT_TRUE(session_->GetCryptoStream()->IsResumption());
}

// When IETF QUIC 0-RTT is rejected, a server-sent fresh transport params is
// available. If the new transport params reduces stream/flow control limit to
// lower than what the client has already used, connection will be closed.
TEST_P(QuicSpdyClientSessionTest, ZeroRttRejectReducesStreamLimitTooMuch) {
  // This feature is TLS-only.
  if (session_->version().UsesQuicCrypto()) {
    return;
  }

  CompleteFirstConnection();

  // Create a second connection, but disable 0-RTT on the server.
  CreateConnection();
  QuicConfig config = DefaultQuicConfig();
  // Server doesn't allow any bidirectional streams.
  config.SetMaxBidirectionalStreamsToSend(0);
  SSL_CTX_set_early_data_enabled(server_crypto_config_->ssl_ctx(), false);
  session_->CryptoConnect();
  EXPECT_TRUE(session_->IsEncryptionEstablished());
  QuicSpdyClientStream* stream = session_->CreateOutgoingBidirectionalStream();
  ASSERT_TRUE(stream);

  if (session_->version().UsesHttp3()) {
    EXPECT_CALL(
        *connection_,
        CloseConnection(
            QUIC_ZERO_RTT_UNRETRANSMITTABLE,
            "Server rejected 0-RTT, aborting because new bidirectional initial "
            "stream limit 0 is less than current open streams: 1",
            _))
        .WillOnce(testing::Invoke(connection_,
                                  &MockQuicConnection::ReallyCloseConnection));
  } else {
    EXPECT_CALL(
        *connection_,
        CloseConnection(QUIC_INTERNAL_ERROR,
                        "Server rejected 0-RTT,
```