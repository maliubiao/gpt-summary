Response:
My thinking process to arrive at the summary of the `quic_simple_server_stream_test.cc` file goes through these stages:

1. **Identify the Core Purpose:** The filename itself, `quic_simple_server_stream_test.cc`, strongly suggests that this file contains unit tests for the `QuicSimpleServerStream` class. The `.cc` extension confirms it's a C++ source file. The presence of "test" in the name is a key indicator.

2. **Scan for Keywords and Structures:** I look for common testing frameworks and patterns in the code. I see:
    * `#include "quiche/quic/platform/api/quic_test.h"`: This confirms the use of a QUIC testing framework, likely based on Google Test.
    * `namespace quic { namespace test { ... } }`:  This standard C++ structure encapsulates the test code.
    * `class QuicSimpleServerStreamTest : public QuicTestWithParam<ParsedQuicVersion>`: This establishes the main test fixture. The `WithParam` indicates parameterized testing, running the tests with different QUIC versions.
    * `TEST_P(QuicSimpleServerStreamTest, ...)`: This is the standard Google Test macro for defining parameterized test cases.
    * `MOCK_METHOD`: This suggests the use of a mocking framework (likely Google Mock) to isolate the `QuicSimpleServerStream` during testing.
    * Various setup within the `QuicSimpleServerStreamTest` constructor, creating mock objects for connections, sessions, etc. This indicates the tests are designed to simulate the environment in which `QuicSimpleServerStream` operates.

3. **Infer Functionality from Test Cases:** I examine the individual `TEST_P` functions to understand what aspects of `QuicSimpleServerStream` are being tested. I see tests related to:
    * **Framing:** `TestFraming`, `TestFramingOnePacket`, `TestFramingExtraData` - This indicates testing how the stream handles incoming data frames.
    * **Response Handling:** `SendResponseWithIllegalResponseStatus`, `SendResponseWithValidHeaders`, `SendResponseWithEarlyHints`, `SendResponseWithDelay`, `TestSendErrorResponse` - This shows tests for sending different types of server responses, including error scenarios and delayed responses.
    * **RST Stream:** `SendQuicRstStreamNoErrorInStopReading`, `DoNotSendQuicRstStreamNoErrorWithRstReceived` - Tests for the stream's behavior when resetting or stopping.
    * **Content Length Validation:** `InvalidMultipleContentLength`, `InvalidLeadingNullContentLength` - Tests for handling invalid `content-length` headers.
    * **Invalid Headers:** `InvalidHeadersWithFin` - Testing how the stream reacts to malformed headers.
    * **CONNECT Method:** `ConnectSendsIntermediateResponses` - Specific testing for handling HTTP CONNECT requests.

4. **Identify Key Dependencies and Mocking:** I notice the extensive use of mocking for classes like `MockQuicConnection`, `MockQuicSimpleServerSession`, and even creating a `TestStream` class that inherits from `QuicSimpleServerStream` to add mocking capabilities directly to the class under test. This reinforces that the focus is on testing the `QuicSimpleServerStream`'s internal logic and interactions with its immediate collaborators.

5. **Consider the Context (Server-Side):** The name "simple server stream" and the interaction with "backend" components (like `QuicMemoryCacheBackend`) tell me this is server-side code responsible for handling individual client requests within a QUIC connection.

6. **Synthesize the Summary:** Based on the above analysis, I formulate a summary that covers the following key points:
    * The file's purpose (unit testing `QuicSimpleServerStream`).
    * The core functionalities being tested (data framing, response generation, error handling, stream control).
    * The testing approach (using Google Test and Google Mock).
    * The focus on isolated testing of the stream's internal logic.
    * The parameterized nature of the tests (across different QUIC versions).
    * The simulation of a server environment with mock objects.

7. **Refine and Organize:** I structure the summary to be clear, concise, and easy to understand, using bullet points to highlight key aspects. I ensure the language accurately reflects the purpose and content of the file. I also make sure to address the specific request of summarizing for the first part of a two-part explanation.

This systematic approach, combining keyword analysis, pattern recognition, and understanding the context of the code, allows me to accurately summarize the functionality of the `quic_simple_server_stream_test.cc` file.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/tools/quic_simple_server_stream_test.cc` 文件的第一部分，主要功能是 **对 `QuicSimpleServerStream` 类进行单元测试**。

以下是根据代码内容归纳的其功能点：

**主要功能:**

* **测试 `QuicSimpleServerStream` 的数据帧处理:**  测试如何处理接收到的数据帧，包括头部和body，以及处理不完整或额外的数据。
* **测试 `QuicSimpleServerStream` 的响应发送机制:**  测试如何发送各种类型的响应，包括：
    * 成功响应 (200 OK)
    * 错误响应
    * 带有非法状态码的响应 (确保能正确处理并可能发送错误)
    * 带有 Early Hints 的响应 (103 状态码)
    * 延迟发送的响应 (模拟后端处理延迟)
* **测试 `QuicSimpleServerStream` 的流控制和错误处理:**
    * 测试如何处理接收到的 FIN (流结束标志)。
    * 测试在停止读取时发送 RST_STREAM (重置流)。
    * 测试接收到 RST_STREAM 时的行为，并避免重复发送 RST_STREAM。
    * 测试处理无效的 `content-length` 头部的情况。
    * 测试处理包含错误的头部的情况。
* **使用 Mock 对象进行隔离测试:**  为了专注于测试 `QuicSimpleServerStream` 的逻辑，使用了 Google Mock 框架来模拟其依赖的对象，例如 `QuicConnection` 和 `QuicSimpleServerSession`。
* **参数化测试 (Parameterized Testing):** 使用 `QuicTestWithParam<ParsedQuicVersion>` 来针对不同的 QUIC 版本运行相同的测试用例，确保代码在不同版本下的兼容性。
* **测试 HTTP CONNECT 方法的处理:**  专门测试了 `QuicSimpleServerStream` 如何处理 HTTP CONNECT 请求，包括发送中间响应。

**与 Javascript 的功能关系 (理论上可能存在，但此文件本身不涉及 Javascript 代码):**

虽然此 C++ 文件本身不包含 Javascript 代码，但它测试的网络协议 QUIC 是 Web 技术的基础。Javascript 代码通常通过浏览器或 Node.js 等环境发起 HTTP(S) 请求，这些请求在底层可能会使用 QUIC 协议。

* **浏览器中的 fetch API 或 XMLHttpRequest:**  如果浏览器支持 QUIC，当 Javascript 代码使用 `fetch()` 或 `XMLHttpRequest()` 发起 HTTPS 请求时，浏览器底层可能会使用 QUIC 协议与服务器建立连接和传输数据。此测试文件确保了服务器端 QUIC 实现的 `QuicSimpleServerStream` 组件能够正确处理这些请求。
* **Node.js 中的 HTTP/2 或 HTTP/3 模块:**  Node.js 提供了对 HTTP/2 和 HTTP/3 的支持，底层也可能使用 QUIC。此测试文件保证了 Node.js 服务器如果使用 QUIC 作为传输层，其流处理部分能够正常工作。

**举例说明 (假设的场景):**

假设一个使用 QUIC 的服务器，当 Javascript 代码发起一个带有特定头部（例如，包含 `content-length`）的 POST 请求时，`QuicSimpleServerStream` 需要正确解析这些头部，并根据 `content-length` 来判断请求 body 的完整性。 此测试文件中的 `TestFraming` 和 `TestFramingExtraData` 等测试用例，正是用来验证这种场景下 `QuicSimpleServerStream` 的行为是否符合预期。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  接收到一个 HTTP/3 数据帧，头部中 `content-length` 为 10，但实际接收到的 body 数据长度为 12。
* **预期输出:** `QuicSimpleServerStream` 应该检测到数据长度不匹配，可能会发送一个错误响应或者断开连接 (具体行为取决于服务器的实现和配置，但测试会验证其是否按照预期处理了这种异常情况)。

* **假设输入:** 接收到一个 HTTP/3 请求头部，包含 `content-length: 0`，并且随后接收到一个空的 body 数据帧 (FIN 标志设置为 true)。
* **预期输出:** `QuicSimpleServerStream` 应该成功处理该请求，并认为请求已完成。

**涉及用户或编程常见的使用错误 (可能触发此代码逻辑的情况):**

* **客户端发送错误的 `content-length` 头部:**  客户端在发送请求时，计算的 `content-length` 与实际发送的 body 大小不一致。`QuicSimpleServerStream` 需要能够检测并处理这种情况，避免数据解析错误或安全问题。测试用例 `TestFramingExtraData` 和 `InvalidMultipleContentLength` 就是为了覆盖这类情况。
* **客户端发送包含非法字符或格式错误的头部:**  客户端代码可能存在 bug，导致发送的 HTTP 头部不符合规范。`QuicSimpleServerStream` 需要具备一定的容错能力，能够拒绝不合法的头部，避免程序崩溃或安全漏洞。测试用例 `InvalidHeadersWithFin` 旨在测试处理这类错误的能力。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中访问一个启用了 QUIC 的网站 (例如，Google)。**
2. **浏览器发起一个 HTTP 请求 (例如，点击链接、提交表单等)。**
3. **如果网络条件允许，并且服务器支持，浏览器会尝试使用 QUIC 协议与服务器建立连接。**
4. **在 QUIC 连接建立后，浏览器会将 HTTP 请求的数据 (头部和 body) 打包成 QUIC 数据包发送给服务器。**
5. **服务器端的 QUIC 实现接收到这些数据包，并将其交给相应的 `QuicSimpleServerStream` 对象进行处理。**
6. **如果接收到的数据帧存在问题 (例如，`content-length` 不匹配，头部格式错误)，那么 `QuicSimpleServerStream` 内部的逻辑 (正是此测试文件所测试的内容) 将会被触发，以判断如何处理这些错误情况。**

**归纳一下它的功能 (针对第 1 部分):**

这个文件的第一部分主要集中在 **验证 `QuicSimpleServerStream` 类处理接收到的 HTTP 请求数据帧的正确性，以及它发送各种类型 HTTP 响应的能力**。它通过大量的单元测试用例，模拟了各种正常和异常的请求场景，并使用 Mock 对象隔离了被测类的依赖，确保了测试的 focused 和可靠性。同时，它也覆盖了在不同 QUIC 版本下的兼容性，并针对 HTTP CONNECT 方法进行了专门的测试。 简而言之，它是对 `QuicSimpleServerStream` 核心数据处理和响应发送逻辑的全面测试。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/tools/quic_simple_server_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quic_simple_server_stream.h"

#include <list>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/macros.h"
#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/null_encrypter.h"
#include "quiche/quic/core/http/http_encoder.h"
#include "quiche/quic/core/http/spdy_utils.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_default_clock.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/quic_config_peer.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/quic/test_tools/quic_session_peer.h"
#include "quiche/quic/test_tools/quic_spdy_session_peer.h"
#include "quiche/quic/test_tools/quic_stream_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/test_tools/simulator/simulator.h"
#include "quiche/quic/tools/quic_backend_response.h"
#include "quiche/quic/tools/quic_memory_cache_backend.h"
#include "quiche/quic/tools/quic_simple_server_backend.h"
#include "quiche/quic/tools/quic_simple_server_session.h"
#include "quiche/common/simple_buffer_allocator.h"

using testing::_;
using testing::AnyNumber;
using testing::InSequence;
using testing::Invoke;
using testing::StrictMock;

namespace quic {
namespace test {

const size_t kFakeFrameLen = 60;
const size_t kErrorLength = strlen(QuicSimpleServerStream::kErrorResponseBody);
const size_t kDataFrameHeaderLength = 2;

class TestStream : public QuicSimpleServerStream {
 public:
  TestStream(QuicStreamId stream_id, QuicSpdySession* session, StreamType type,
             QuicSimpleServerBackend* quic_simple_server_backend)
      : QuicSimpleServerStream(stream_id, session, type,
                               quic_simple_server_backend) {
    EXPECT_CALL(*this, WriteOrBufferBody(_, _))
        .Times(AnyNumber())
        .WillRepeatedly([this](absl::string_view data, bool fin) {
          this->QuicSimpleServerStream::WriteOrBufferBody(data, fin);
        });
  }

  ~TestStream() override = default;

  MOCK_METHOD(void, FireAlarmMock, (), ());
  MOCK_METHOD(void, WriteHeadersMock, (bool fin), ());
  MOCK_METHOD(void, WriteEarlyHintsHeadersMock, (bool fin), ());
  MOCK_METHOD(void, WriteOrBufferBody, (absl::string_view data, bool fin),
              (override));

  size_t WriteHeaders(
      quiche::HttpHeaderBlock header_block, bool fin,
      quiche::QuicheReferenceCountedPointer<QuicAckListenerInterface>
      /*ack_listener*/) override {
    if (header_block[":status"] == "103") {
      WriteEarlyHintsHeadersMock(fin);
    } else {
      WriteHeadersMock(fin);
    }
    return 0;
  }

  // Expose protected QuicSimpleServerStream methods.
  void DoSendResponse() { SendResponse(); }
  void DoSendErrorResponse() { QuicSimpleServerStream::SendErrorResponse(); }

  quiche::HttpHeaderBlock* mutable_headers() { return &request_headers_; }
  void set_body(std::string body) { body_ = std::move(body); }
  const std::string& body() const { return body_; }
  int content_length() const { return content_length_; }
  bool send_response_was_called() const { return send_response_was_called_; }
  bool send_error_response_was_called() const {
    return send_error_response_was_called_;
  }

  absl::string_view GetHeader(absl::string_view key) const {
    auto it = request_headers_.find(key);
    QUICHE_DCHECK(it != request_headers_.end());
    return it->second;
  }

  void ReplaceBackend(QuicSimpleServerBackend* backend) {
    set_quic_simple_server_backend_for_test(backend);
  }

 protected:
  void SendResponse() override {
    send_response_was_called_ = true;
    QuicSimpleServerStream::SendResponse();
  }

  void SendErrorResponse(int resp_code) override {
    send_error_response_was_called_ = true;
    QuicSimpleServerStream::SendErrorResponse(resp_code);
  }

 private:
  bool send_response_was_called_ = false;
  bool send_error_response_was_called_ = false;
};

namespace {

class MockQuicSimpleServerSession : public QuicSimpleServerSession {
 public:
  const size_t kMaxStreamsForTest = 100;

  MockQuicSimpleServerSession(
      QuicConnection* connection, MockQuicSessionVisitor* owner,
      MockQuicCryptoServerStreamHelper* helper,
      QuicCryptoServerConfig* crypto_config,
      QuicCompressedCertsCache* compressed_certs_cache,
      QuicSimpleServerBackend* quic_simple_server_backend)
      : QuicSimpleServerSession(DefaultQuicConfig(), CurrentSupportedVersions(),
                                connection, owner, helper, crypto_config,
                                compressed_certs_cache,
                                quic_simple_server_backend) {
    if (VersionHasIetfQuicFrames(connection->transport_version())) {
      QuicSessionPeer::SetMaxOpenIncomingUnidirectionalStreams(
          this, kMaxStreamsForTest);
      QuicSessionPeer::SetMaxOpenIncomingBidirectionalStreams(
          this, kMaxStreamsForTest);
    } else {
      QuicSessionPeer::SetMaxOpenIncomingStreams(this, kMaxStreamsForTest);
      QuicSessionPeer::SetMaxOpenOutgoingStreams(this, kMaxStreamsForTest);
    }
    ON_CALL(*this, WritevData(_, _, _, _, _, _))
        .WillByDefault(Invoke(this, &MockQuicSimpleServerSession::ConsumeData));
  }

  MockQuicSimpleServerSession(const MockQuicSimpleServerSession&) = delete;
  MockQuicSimpleServerSession& operator=(const MockQuicSimpleServerSession&) =
      delete;
  ~MockQuicSimpleServerSession() override = default;

  MOCK_METHOD(void, OnConnectionClosed,
              (const QuicConnectionCloseFrame& frame,
               ConnectionCloseSource source),
              (override));
  MOCK_METHOD(QuicSpdyStream*, CreateIncomingStream, (QuicStreamId id),
              (override));
  MOCK_METHOD(QuicConsumedData, WritevData,
              (QuicStreamId id, size_t write_length, QuicStreamOffset offset,
               StreamSendingState state, TransmissionType type,
               EncryptionLevel level),
              (override));
  MOCK_METHOD(void, OnStreamHeaderList,
              (QuicStreamId stream_id, bool fin, size_t frame_len,
               const QuicHeaderList& header_list),
              (override));
  MOCK_METHOD(void, OnStreamHeadersPriority,
              (QuicStreamId stream_id,
               const spdy::SpdyStreamPrecedence& precedence),
              (override));
  MOCK_METHOD(void, MaybeSendRstStreamFrame,
              (QuicStreamId stream_id, QuicResetStreamError error,
               QuicStreamOffset bytes_written),
              (override));
  MOCK_METHOD(void, MaybeSendStopSendingFrame,
              (QuicStreamId stream_id, QuicResetStreamError error), (override));

  using QuicSession::ActivateStream;

  QuicConsumedData ConsumeData(QuicStreamId id, size_t write_length,
                               QuicStreamOffset offset,
                               StreamSendingState state,
                               TransmissionType /*type*/,
                               std::optional<EncryptionLevel> /*level*/) {
    if (write_length > 0) {
      auto buf = std::make_unique<char[]>(write_length);
      QuicStream* stream = GetOrCreateStream(id);
      QUICHE_DCHECK(stream);
      QuicDataWriter writer(write_length, buf.get(), quiche::HOST_BYTE_ORDER);
      stream->WriteStreamData(offset, write_length, &writer);
    } else {
      QUICHE_DCHECK(state != NO_FIN);
    }
    return QuicConsumedData(write_length, state != NO_FIN);
  }

  quiche::HttpHeaderBlock original_request_headers_;
};

class QuicSimpleServerStreamTest : public QuicTestWithParam<ParsedQuicVersion> {
 public:
  QuicSimpleServerStreamTest()
      : connection_(new StrictMock<MockQuicConnection>(
            &simulator_, simulator_.GetAlarmFactory(), Perspective::IS_SERVER,
            SupportedVersions(GetParam()))),
        crypto_config_(new QuicCryptoServerConfig(
            QuicCryptoServerConfig::TESTING, QuicRandom::GetInstance(),
            crypto_test_utils::ProofSourceForTesting(),
            KeyExchangeSource::Default())),
        compressed_certs_cache_(
            QuicCompressedCertsCache::kQuicCompressedCertsCacheSize),
        session_(connection_, &session_owner_, &session_helper_,
                 crypto_config_.get(), &compressed_certs_cache_,
                 &memory_cache_backend_),
        quic_response_(new QuicBackendResponse),
        body_("hello world") {
    connection_->set_visitor(&session_);
    header_list_.OnHeader(":authority", "www.google.com");
    header_list_.OnHeader(":path", "/");
    header_list_.OnHeader(":method", "POST");
    header_list_.OnHeader(":scheme", "https");
    header_list_.OnHeader("content-length", "11");

    header_list_.OnHeaderBlockEnd(128, 128);

    // New streams rely on having the peer's flow control receive window
    // negotiated in the config.
    session_.config()->SetInitialStreamFlowControlWindowToSend(
        kInitialStreamFlowControlWindowForTest);
    session_.config()->SetInitialSessionFlowControlWindowToSend(
        kInitialSessionFlowControlWindowForTest);
    session_.Initialize();
    connection_->SetEncrypter(
        quic::ENCRYPTION_FORWARD_SECURE,
        std::make_unique<quic::NullEncrypter>(connection_->perspective()));
    if (connection_->version().SupportsAntiAmplificationLimit()) {
      QuicConnectionPeer::SetAddressValidated(connection_);
    }
    stream_ = new StrictMock<TestStream>(
        GetNthClientInitiatedBidirectionalStreamId(
            connection_->transport_version(), 0),
        &session_, BIDIRECTIONAL, &memory_cache_backend_);
    // Register stream_ in dynamic_stream_map_ and pass ownership to session_.
    session_.ActivateStream(absl::WrapUnique(stream_));
    QuicConfigPeer::SetReceivedInitialSessionFlowControlWindow(
        session_.config(), kMinimumFlowControlSendWindow);
    QuicConfigPeer::SetReceivedInitialMaxStreamDataBytesUnidirectional(
        session_.config(), kMinimumFlowControlSendWindow);
    QuicConfigPeer::SetReceivedInitialMaxStreamDataBytesIncomingBidirectional(
        session_.config(), kMinimumFlowControlSendWindow);
    QuicConfigPeer::SetReceivedInitialMaxStreamDataBytesOutgoingBidirectional(
        session_.config(), kMinimumFlowControlSendWindow);
    QuicConfigPeer::SetReceivedMaxUnidirectionalStreams(session_.config(), 10);
    session_.OnConfigNegotiated();
    simulator_.RunFor(QuicTime::Delta::FromSeconds(1));
  }

  const std::string& StreamBody() { return stream_->body(); }

  std::string StreamHeadersValue(const std::string& key) {
    return (*stream_->mutable_headers())[key].as_string();
  }

  bool UsesHttp3() const {
    return VersionUsesHttp3(connection_->transport_version());
  }

  void ReplaceBackend(std::unique_ptr<QuicSimpleServerBackend> backend) {
    replacement_backend_ = std::move(backend);
    stream_->ReplaceBackend(replacement_backend_.get());
  }

  quic::simulator::Simulator simulator_;
  quiche::HttpHeaderBlock response_headers_;
  MockQuicConnectionHelper helper_;
  StrictMock<MockQuicConnection>* connection_;
  StrictMock<MockQuicSessionVisitor> session_owner_;
  StrictMock<MockQuicCryptoServerStreamHelper> session_helper_;
  std::unique_ptr<QuicCryptoServerConfig> crypto_config_;
  QuicCompressedCertsCache compressed_certs_cache_;
  QuicMemoryCacheBackend memory_cache_backend_;
  std::unique_ptr<QuicSimpleServerBackend> replacement_backend_;
  StrictMock<MockQuicSimpleServerSession> session_;
  StrictMock<TestStream>* stream_;  // Owned by session_.
  std::unique_ptr<QuicBackendResponse> quic_response_;
  std::string body_;
  QuicHeaderList header_list_;
};

INSTANTIATE_TEST_SUITE_P(Tests, QuicSimpleServerStreamTest,
                         ::testing::ValuesIn(AllSupportedVersions()),
                         ::testing::PrintToStringParamName());

TEST_P(QuicSimpleServerStreamTest, TestFraming) {
  EXPECT_CALL(session_, WritevData(_, _, _, _, _, _))
      .WillRepeatedly(
          Invoke(&session_, &MockQuicSimpleServerSession::ConsumeData));
  stream_->OnStreamHeaderList(false, kFakeFrameLen, header_list_);
  quiche::QuicheBuffer header = HttpEncoder::SerializeDataFrameHeader(
      body_.length(), quiche::SimpleBufferAllocator::Get());
  std::string data =
      UsesHttp3() ? absl::StrCat(header.AsStringView(), body_) : body_;
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), /*fin=*/false, /*offset=*/0, data));
  EXPECT_EQ("11", StreamHeadersValue("content-length"));
  EXPECT_EQ("/", StreamHeadersValue(":path"));
  EXPECT_EQ("POST", StreamHeadersValue(":method"));
  EXPECT_EQ(body_, StreamBody());
}

TEST_P(QuicSimpleServerStreamTest, TestFramingOnePacket) {
  EXPECT_CALL(session_, WritevData(_, _, _, _, _, _))
      .WillRepeatedly(
          Invoke(&session_, &MockQuicSimpleServerSession::ConsumeData));

  stream_->OnStreamHeaderList(false, kFakeFrameLen, header_list_);
  quiche::QuicheBuffer header = HttpEncoder::SerializeDataFrameHeader(
      body_.length(), quiche::SimpleBufferAllocator::Get());
  std::string data =
      UsesHttp3() ? absl::StrCat(header.AsStringView(), body_) : body_;
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), /*fin=*/false, /*offset=*/0, data));
  EXPECT_EQ("11", StreamHeadersValue("content-length"));
  EXPECT_EQ("/", StreamHeadersValue(":path"));
  EXPECT_EQ("POST", StreamHeadersValue(":method"));
  EXPECT_EQ(body_, StreamBody());
}

TEST_P(QuicSimpleServerStreamTest, SendQuicRstStreamNoErrorInStopReading) {
  EXPECT_CALL(session_, WritevData(_, _, _, _, _, _))
      .WillRepeatedly(
          Invoke(&session_, &MockQuicSimpleServerSession::ConsumeData));

  EXPECT_FALSE(stream_->fin_received());
  EXPECT_FALSE(stream_->rst_received());

  QuicStreamPeer::SetFinSent(stream_);
  stream_->CloseWriteSide();

  if (session_.version().UsesHttp3()) {
    EXPECT_CALL(session_,
                MaybeSendStopSendingFrame(_, QuicResetStreamError::FromInternal(
                                                 QUIC_STREAM_NO_ERROR)))
        .Times(1);
  } else {
    EXPECT_CALL(
        session_,
        MaybeSendRstStreamFrame(
            _, QuicResetStreamError::FromInternal(QUIC_STREAM_NO_ERROR), _))
        .Times(1);
  }
  stream_->StopReading();
}

TEST_P(QuicSimpleServerStreamTest, TestFramingExtraData) {
  InSequence seq;
  std::string large_body = "hello world!!!!!!";

  // We'll automatically write out an error (headers + body)
  EXPECT_CALL(*stream_, WriteHeadersMock(false));
  if (UsesHttp3()) {
    EXPECT_CALL(session_,
                WritevData(_, kDataFrameHeaderLength, _, NO_FIN, _, _));
  }
  EXPECT_CALL(session_, WritevData(_, kErrorLength, _, FIN, _, _));

  stream_->OnStreamHeaderList(false, kFakeFrameLen, header_list_);
  quiche::QuicheBuffer header = HttpEncoder::SerializeDataFrameHeader(
      body_.length(), quiche::SimpleBufferAllocator::Get());
  std::string data =
      UsesHttp3() ? absl::StrCat(header.AsStringView(), body_) : body_;

  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), /*fin=*/false, /*offset=*/0, data));
  // Content length is still 11.  This will register as an error and we won't
  // accept the bytes.
  header = HttpEncoder::SerializeDataFrameHeader(
      large_body.length(), quiche::SimpleBufferAllocator::Get());
  std::string data2 = UsesHttp3()
                          ? absl::StrCat(header.AsStringView(), large_body)
                          : large_body;
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), /*fin=*/true, data.size(), data2));
  EXPECT_EQ("11", StreamHeadersValue("content-length"));
  EXPECT_EQ("/", StreamHeadersValue(":path"));
  EXPECT_EQ("POST", StreamHeadersValue(":method"));
}

TEST_P(QuicSimpleServerStreamTest, SendResponseWithIllegalResponseStatus) {
  // Send an illegal response with response status not supported by HTTP/2.
  quiche::HttpHeaderBlock* request_headers = stream_->mutable_headers();
  (*request_headers)[":path"] = "/bar";
  (*request_headers)[":authority"] = "www.google.com";
  (*request_headers)[":method"] = "GET";

  // HTTP/2 only supports integer responsecode, so "200 OK" is illegal.
  response_headers_[":status"] = "200 OK";
  response_headers_["content-length"] = "5";
  std::string body = "Yummm";
  quiche::QuicheBuffer header = HttpEncoder::SerializeDataFrameHeader(
      body.length(), quiche::SimpleBufferAllocator::Get());

  memory_cache_backend_.AddResponse("www.google.com", "/bar",
                                    std::move(response_headers_), body);

  QuicStreamPeer::SetFinReceived(stream_);

  InSequence s;
  EXPECT_CALL(*stream_, WriteHeadersMock(false));
  if (UsesHttp3()) {
    EXPECT_CALL(session_, WritevData(_, header.size(), _, NO_FIN, _, _));
  }
  EXPECT_CALL(session_, WritevData(_, kErrorLength, _, FIN, _, _));

  stream_->DoSendResponse();
  EXPECT_FALSE(QuicStreamPeer::read_side_closed(stream_));
  EXPECT_TRUE(stream_->write_side_closed());
}

TEST_P(QuicSimpleServerStreamTest, SendResponseWithIllegalResponseStatus2) {
  // Send an illegal response with response status not supported by HTTP/2.
  quiche::HttpHeaderBlock* request_headers = stream_->mutable_headers();
  (*request_headers)[":path"] = "/bar";
  (*request_headers)[":authority"] = "www.google.com";
  (*request_headers)[":method"] = "GET";

  // HTTP/2 only supports 3-digit-integer, so "+200" is illegal.
  response_headers_[":status"] = "+200";
  response_headers_["content-length"] = "5";
  std::string body = "Yummm";

  quiche::QuicheBuffer header = HttpEncoder::SerializeDataFrameHeader(
      body.length(), quiche::SimpleBufferAllocator::Get());

  memory_cache_backend_.AddResponse("www.google.com", "/bar",
                                    std::move(response_headers_), body);

  QuicStreamPeer::SetFinReceived(stream_);

  InSequence s;
  EXPECT_CALL(*stream_, WriteHeadersMock(false));
  if (UsesHttp3()) {
    EXPECT_CALL(session_, WritevData(_, header.size(), _, NO_FIN, _, _));
  }
  EXPECT_CALL(session_, WritevData(_, kErrorLength, _, FIN, _, _));

  stream_->DoSendResponse();
  EXPECT_FALSE(QuicStreamPeer::read_side_closed(stream_));
  EXPECT_TRUE(stream_->write_side_closed());
}

TEST_P(QuicSimpleServerStreamTest, SendResponseWithValidHeaders) {
  // Add a request and response with valid headers.
  quiche::HttpHeaderBlock* request_headers = stream_->mutable_headers();
  (*request_headers)[":path"] = "/bar";
  (*request_headers)[":authority"] = "www.google.com";
  (*request_headers)[":method"] = "GET";

  response_headers_[":status"] = "200";
  response_headers_["content-length"] = "5";
  std::string body = "Yummm";

  quiche::QuicheBuffer header = HttpEncoder::SerializeDataFrameHeader(
      body.length(), quiche::SimpleBufferAllocator::Get());

  memory_cache_backend_.AddResponse("www.google.com", "/bar",
                                    std::move(response_headers_), body);
  QuicStreamPeer::SetFinReceived(stream_);

  InSequence s;
  EXPECT_CALL(*stream_, WriteHeadersMock(false));
  if (UsesHttp3()) {
    EXPECT_CALL(session_, WritevData(_, header.size(), _, NO_FIN, _, _));
  }
  EXPECT_CALL(session_, WritevData(_, body.length(), _, FIN, _, _));

  stream_->DoSendResponse();
  EXPECT_FALSE(QuicStreamPeer::read_side_closed(stream_));
  EXPECT_TRUE(stream_->write_side_closed());
}

TEST_P(QuicSimpleServerStreamTest, SendResponseWithEarlyHints) {
  std::string host = "www.google.com";
  std::string request_path = "/foo";
  std::string body = "Yummm";

  // Add a request and response with early hints.
  quiche::HttpHeaderBlock* request_headers = stream_->mutable_headers();
  (*request_headers)[":path"] = request_path;
  (*request_headers)[":authority"] = host;
  (*request_headers)[":method"] = "GET";

  quiche::QuicheBuffer header = HttpEncoder::SerializeDataFrameHeader(
      body.length(), quiche::SimpleBufferAllocator::Get());
  std::vector<quiche::HttpHeaderBlock> early_hints;
  // Add two Early Hints.
  const size_t kNumEarlyHintsResponses = 2;
  for (size_t i = 0; i < kNumEarlyHintsResponses; ++i) {
    quiche::HttpHeaderBlock hints;
    hints["link"] = "</image.png>; rel=preload; as=image";
    early_hints.push_back(std::move(hints));
  }

  response_headers_[":status"] = "200";
  response_headers_["content-length"] = "5";
  memory_cache_backend_.AddResponseWithEarlyHints(
      host, request_path, std::move(response_headers_), body, early_hints);
  QuicStreamPeer::SetFinReceived(stream_);

  InSequence s;
  for (size_t i = 0; i < kNumEarlyHintsResponses; ++i) {
    EXPECT_CALL(*stream_, WriteEarlyHintsHeadersMock(false));
  }
  EXPECT_CALL(*stream_, WriteHeadersMock(false));
  if (UsesHttp3()) {
    EXPECT_CALL(session_, WritevData(_, header.size(), _, NO_FIN, _, _));
  }
  EXPECT_CALL(session_, WritevData(_, body.length(), _, FIN, _, _));

  stream_->DoSendResponse();
  EXPECT_FALSE(QuicStreamPeer::read_side_closed(stream_));
  EXPECT_TRUE(stream_->write_side_closed());
}

class AlarmTestDelegate : public QuicAlarm::DelegateWithoutContext {
 public:
  AlarmTestDelegate(TestStream* stream) : stream_(stream) {}

  void OnAlarm() override { stream_->FireAlarmMock(); }

 private:
  TestStream* stream_;
};

TEST_P(QuicSimpleServerStreamTest, SendResponseWithDelay) {
  // Add a request and response with valid headers.
  quiche::HttpHeaderBlock* request_headers = stream_->mutable_headers();
  std::string host = "www.google.com";
  std::string path = "/bar";
  (*request_headers)[":path"] = path;
  (*request_headers)[":authority"] = host;
  (*request_headers)[":method"] = "GET";

  response_headers_[":status"] = "200";
  response_headers_["content-length"] = "5";
  std::string body = "Yummm";
  QuicTime::Delta delay = QuicTime::Delta::FromMilliseconds(3000);

  quiche::QuicheBuffer header = HttpEncoder::SerializeDataFrameHeader(
      body.length(), quiche::SimpleBufferAllocator::Get());

  memory_cache_backend_.AddResponse(host, path, std::move(response_headers_),
                                    body);
  auto did_delay_succeed =
      memory_cache_backend_.SetResponseDelay(host, path, delay);
  EXPECT_TRUE(did_delay_succeed);
  auto did_invalid_delay_succeed =
      memory_cache_backend_.SetResponseDelay(host, "nonsense", delay);
  EXPECT_FALSE(did_invalid_delay_succeed);
  std::unique_ptr<QuicAlarm> alarm(connection_->alarm_factory()->CreateAlarm(
      new AlarmTestDelegate(stream_)));
  alarm->Set(connection_->clock()->Now() + delay);
  QuicStreamPeer::SetFinReceived(stream_);
  InSequence s;
  EXPECT_CALL(*stream_, FireAlarmMock());
  EXPECT_CALL(*stream_, WriteHeadersMock(false));

  if (UsesHttp3()) {
    EXPECT_CALL(session_, WritevData(_, header.size(), _, NO_FIN, _, _));
  }
  EXPECT_CALL(session_, WritevData(_, body.length(), _, FIN, _, _));

  stream_->DoSendResponse();
  simulator_.RunFor(delay);

  EXPECT_FALSE(QuicStreamPeer::read_side_closed(stream_));
  EXPECT_TRUE(stream_->write_side_closed());
}

TEST_P(QuicSimpleServerStreamTest, TestSendErrorResponse) {
  QuicStreamPeer::SetFinReceived(stream_);

  InSequence s;
  EXPECT_CALL(*stream_, WriteHeadersMock(false));
  if (UsesHttp3()) {
    EXPECT_CALL(session_,
                WritevData(_, kDataFrameHeaderLength, _, NO_FIN, _, _));
  }
  EXPECT_CALL(session_, WritevData(_, kErrorLength, _, FIN, _, _));

  stream_->DoSendErrorResponse();
  EXPECT_FALSE(QuicStreamPeer::read_side_closed(stream_));
  EXPECT_TRUE(stream_->write_side_closed());
}

TEST_P(QuicSimpleServerStreamTest, InvalidMultipleContentLength) {
  quiche::HttpHeaderBlock request_headers;
  // \000 is a way to write the null byte when followed by a literal digit.
  header_list_.OnHeader("content-length", absl::string_view("11\00012", 5));

  if (session_.version().UsesHttp3()) {
    EXPECT_CALL(session_,
                MaybeSendStopSendingFrame(_, QuicResetStreamError::FromInternal(
                                                 QUIC_STREAM_NO_ERROR)));
  }
  EXPECT_CALL(*stream_, WriteHeadersMock(false));
  EXPECT_CALL(session_, WritevData(_, _, _, _, _, _))
      .WillRepeatedly(
          Invoke(&session_, &MockQuicSimpleServerSession::ConsumeData));
  stream_->OnStreamHeaderList(true, kFakeFrameLen, header_list_);

  EXPECT_TRUE(QuicStreamPeer::read_side_closed(stream_));
  EXPECT_TRUE(stream_->reading_stopped());
  EXPECT_TRUE(stream_->write_side_closed());
}

TEST_P(QuicSimpleServerStreamTest, InvalidLeadingNullContentLength) {
  quiche::HttpHeaderBlock request_headers;
  // \000 is a way to write the null byte when followed by a literal digit.
  header_list_.OnHeader("content-length", absl::string_view("\00012", 3));

  if (session_.version().UsesHttp3()) {
    EXPECT_CALL(session_,
                MaybeSendStopSendingFrame(_, QuicResetStreamError::FromInternal(
                                                 QUIC_STREAM_NO_ERROR)));
  }
  EXPECT_CALL(*stream_, WriteHeadersMock(false));
  EXPECT_CALL(session_, WritevData(_, _, _, _, _, _))
      .WillRepeatedly(
          Invoke(&session_, &MockQuicSimpleServerSession::ConsumeData));
  stream_->OnStreamHeaderList(true, kFakeFrameLen, header_list_);

  EXPECT_TRUE(QuicStreamPeer::read_side_closed(stream_));
  EXPECT_TRUE(stream_->reading_stopped());
  EXPECT_TRUE(stream_->write_side_closed());
}

TEST_P(QuicSimpleServerStreamTest, InvalidMultipleContentLengthII) {
  quiche::HttpHeaderBlock request_headers;
  // \000 is a way to write the null byte when followed by a literal digit.
  header_list_.OnHeader("content-length", absl::string_view("11\00011", 5));

  if (session_.version().UsesHttp3()) {
    EXPECT_CALL(session_,
                MaybeSendStopSendingFrame(_, QuicResetStreamError::FromInternal(
                                                 QUIC_STREAM_NO_ERROR)));
    EXPECT_CALL(*stream_, WriteHeadersMock(false));
    EXPECT_CALL(session_, WritevData(_, _, _, _, _, _))
        .WillRepeatedly(
            Invoke(&session_, &MockQuicSimpleServerSession::ConsumeData));
  }

  stream_->OnStreamHeaderList(false, kFakeFrameLen, header_list_);

  if (session_.version().UsesHttp3()) {
    EXPECT_TRUE(QuicStreamPeer::read_side_closed(stream_));
    EXPECT_TRUE(stream_->reading_stopped());
    EXPECT_TRUE(stream_->write_side_closed());
  } else {
    EXPECT_EQ(11, stream_->content_length());
    EXPECT_FALSE(QuicStreamPeer::read_side_closed(stream_));
    EXPECT_FALSE(stream_->reading_stopped());
    EXPECT_FALSE(stream_->write_side_closed());
  }
}

TEST_P(QuicSimpleServerStreamTest,
       DoNotSendQuicRstStreamNoErrorWithRstReceived) {
  EXPECT_FALSE(stream_->reading_stopped());

  if (VersionUsesHttp3(connection_->transport_version())) {
    // Unidirectional stream type and then a Stream Cancellation instruction is
    // sent on the QPACK decoder stream.  Ignore these writes without any
    // assumption on their number or size.
    auto* qpack_decoder_stream =
        QuicSpdySessionPeer::GetQpackDecoderSendStream(&session_);
    EXPECT_CALL(session_, WritevData(qpack_decoder_stream->id(), _, _, _, _, _))
        .Times(AnyNumber());
  }

  EXPECT_CALL(
      session_,
      MaybeSendRstStreamFrame(
          _,
          session_.version().UsesHttp3()
              ? QuicResetStreamError::FromInternal(QUIC_STREAM_CANCELLED)
              : QuicResetStreamError::FromInternal(QUIC_RST_ACKNOWLEDGEMENT),
          _))
      .Times(1);
  QuicRstStreamFrame rst_frame(kInvalidControlFrameId, stream_->id(),
                               QUIC_STREAM_CANCELLED, 1234);
  stream_->OnStreamReset(rst_frame);
  if (VersionHasIetfQuicFrames(connection_->transport_version())) {
    EXPECT_CALL(session_owner_, OnStopSendingReceived(_));
    // Create and inject a STOP SENDING frame to complete the close
    // of the stream. This is only needed for version 99/IETF QUIC.
    QuicStopSendingFrame stop_sending(kInvalidControlFrameId, stream_->id(),
                                      QUIC_STREAM_CANCELLED);
    session_.OnStopSendingFrame(stop_sending);
  }
  EXPECT_TRUE(stream_->reading_stopped());
  EXPECT_TRUE(stream_->write_side_closed());
}

TEST_P(QuicSimpleServerStreamTest, InvalidHeadersWithFin) {
  char arr[] = {
      0x3a,   0x68, 0x6f, 0x73,  // :hos
      0x74,   0x00, 0x00, 0x00,  // t...
      0x00,   0x00, 0x00, 0x00,  // ....
      0x07,   0x3a, 0x6d, 0x65,  // .:me
      0x74,   0x68, 0x6f, 0x64,  // thod
      0x00,   0x00, 0x00, 0x03,  // ....
      0x47,   0x45, 0x54, 0x00,  // GET.
      0x00,   0x00, 0x05, 0x3a,  // ...:
      0x70,   0x61, 0x74, 0x68,  // path
      0x00,   0x00, 0x00, 0x04,  // ....
      0x2f,   0x66, 0x6f, 0x6f,  // /foo
      0x00,   0x00, 0x00, 0x07,  // ....
      0x3a,   0x73, 0x63, 0x68,  // :sch
      0x65,   0x6d, 0x65, 0x00,  // eme.
      0x00,   0x00, 0x00, 0x00,  // ....
      0x00,   0x00, 0x08, 0x3a,  // ...:
      0x76,   0x65, 0x72, 0x73,  // vers
      '\x96', 0x6f, 0x6e, 0x00,  // <i(69)>on.
      0x00,   0x00, 0x08, 0x48,  // ...H
      0x54,   0x54, 0x50, 0x2f,  // TTP/
      0x31,   0x2e, 0x31,        // 1.1
  };
  absl::string_view data(arr, ABSL_ARRAYSIZE(arr));
  QuicStreamFrame frame(stream_->id(), true, 0, data);
  // Verify that we don't crash when we get a invalid headers in stream frame.
  stream_->OnStreamFrame(frame);
}

// Basic QuicSimpleServerBackend that implements its behavior through mocking.
class TestQuicSimpleServerBackend : public QuicSimpleServerBackend {
 public:
  TestQuicSimpleServerBackend() = default;
  ~TestQuicSimpleServerBackend() override = default;

  // QuicSimpleServerBackend:
  bool InitializeBackend(const std::string& /*backend_url*/) override {
    return true;
  }
  bool IsBackendInitialized() const override { return true; }
  MOCK_METHOD(void, FetchResponseFromBackend,
              (const quiche::HttpHeaderBlock&, const std::string&,
               RequestHandler*),
              (override));
  MOCK_METHOD(void, HandleConnectHeaders,
              (const quiche::HttpHeaderBlock&, RequestHandler*), (override));
  MOCK_METHOD(void, HandleConnectData,
              (absl::string_view, bool, RequestHandler*), (override));
  void CloseBackendResponseStream(
      RequestHandler* /*request_handler*/) override {}
};

ACTION_P(SendHeadersResponse, response_ptr) {
  arg1->OnResponseBackendComplete(response_ptr);
}

ACTION_P(SendStreamData, data, close_stream) {
  arg2->SendStreamData(data, close_stream);
}

ACTION_P(TerminateStream, error) { arg1->TerminateStreamWithError(error); }

TEST_P(QuicSimpleServerStreamTest, ConnectSendsIntermediateResponses) {
  auto test_backend = std::make_unique<TestQuicSimpleServerBackend>();
  TestQuicSimpleServerBackend* test_backend_ptr = test_backend.get();
  ReplaceBackend(std::move(test_backend));

  constexpr absl::string_view kRequestBody = "\x11\x11";
  quiche::HttpHeaderBlock response_headers;
  response_headers[":status"] = "200";
  QuicBackendResponse headers_response;
  headers_response.set_headers(response_headers.Clone());
  headers_response.set_response_type(QuicBackendResponse::INCOMPLETE_RESPONSE);
  constexpr absl::string_view kBody1 = "\x22\x22";
  constexpr absl::string_view kBody2 = "\x33\x33";

  // Expect an initial headers-only request to result in a headers-only
  // incomplete response. Then a data frame without fin, resulting in stream
  // data. Then a data frame with fin, resulting in stream data with fin.
  InSequence s;
  EXPECT_CALL(*test_backend_ptr, HandleConnectHeaders(_, _))
      .WillOnce(SendHeadersResponse(&headers_response));
  EXPECT_CALL(*stream_, WriteHeadersMock(false));
  EXPECT_CALL(*test_backend_ptr, HandleConnectData(kRequestBody, false, _))
      .WillOnce(SendStreamData(kBody1,
                               /*close_stream=*/false));
  EXPECT_CALL(*stream_, WriteOrBufferBody(kBody1, false));
  EXPECT_CALL(*test_backend_ptr, HandleConnectData(kRequestBody, true, _))
      .WillOnce(SendStreamData(kBody2,
                               /*close_stream=*/true));
  EXPECT_CALL(*stream_, WriteOrBufferBody(kBody2, true));

  QuicHeaderList header_list;
  header_list.OnHeader(":authority", "www.google.com:4433");
  header_list.OnHeader(":method", "CONNECT");
  header_list.OnHeaderBlockEnd(128, 128);

  stream_->OnStreamHeaderList(/*fin=*/false, kFakeFrameLen, header_list);
  quiche::QuicheBuffer header = HttpEncoder::SerializeDataFrameHeader(
      kReque
"""


```