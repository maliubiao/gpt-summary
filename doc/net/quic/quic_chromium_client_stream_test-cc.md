Response:
The user wants to understand the functionality of the `quic_chromium_client_stream_test.cc` file in the Chromium network stack. They are particularly interested in:

1. **General functionality:** What does this file do?
2. **Relationship to JavaScript:** Does this file interact with JavaScript functionality? If so, how?
3. **Logical reasoning:** Can we provide examples of inputs and outputs based on the code?
4. **Common usage errors:** What mistakes might users or programmers make when interacting with this code?
5. **Debugging context:** How does a user's action lead to this code being executed?
6. **Summary of functionality:**  A concise summary of the file's purpose.

Based on the file name and the included headers, it seems like this file contains unit tests for `QuicChromiumClientStream`. It uses Google Test (`testing::*`) for writing the tests. It interacts with other QUIC components like `QuicSession`, `QuicConnection`, and `QuicCryptoStream`.

Let's break down each part of the request:

1. **Functionality:** The file tests the behavior of `QuicChromiumClientStream`, which is likely a class responsible for handling individual QUIC streams on the client side within Chromium. This involves testing how it handles sending and receiving data, headers, trailers, and errors.

2. **Relationship to JavaScript:**  QUIC is a transport protocol operating at a lower layer than JavaScript. While JavaScript in a browser might trigger network requests that eventually use QUIC, this specific test file is focused on the internal workings of the QUIC implementation in Chromium's network stack. There's no direct interaction with JavaScript *within this test file*. The connection is that higher-level browser features using JavaScript might eventually rely on this low-level QUIC functionality.

3. **Logical reasoning (Input/Output):** The tests simulate various scenarios. For example, a test might simulate sending data and verify that the correct `WritevData` calls are made on the session. Another might simulate receiving data and verify that the `Read` methods return the expected data.

4. **Common usage errors:**  Since this is a test file, the errors it might uncover are related to incorrect implementation of `QuicChromiumClientStream`. From a *user* perspective, common errors might be related to network connectivity or server-side issues, but those wouldn't be directly reflected in *this* test file. From a *programmer* perspective writing code that uses `QuicChromiumClientStream`, potential errors could involve incorrect usage of the API, such as calling methods in the wrong order, not handling asynchronous operations correctly, or misinterpreting error codes.

5. **User operation leading here:**  A user initiating a network request (e.g., clicking a link, loading a web page) in Chrome might lead to the browser establishing a QUIC connection with the server. The `QuicChromiumClientStream` objects would be created to handle the data flow for that request. While this specific test file is for internal development and testing, it reflects the underlying mechanics that happen when a user interacts with the browser.

6. **Summary of functionality:**  This file contains unit tests for the `QuicChromiumClientStream` class, which is a core component for handling client-side QUIC streams in Chromium. It verifies the correct behavior of the stream in various scenarios like sending and receiving data, handling headers and trailers, and managing errors.

Now, let's format the response based on these thoughts.
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_chromium_client_stream.h"

#include <string>
#include <string_view>

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/metrics/histogram_tester.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/quic/quic_chromium_client_session.h"
#include "net/quic/quic_context.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_client_session_base.h"
#include "net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_client_stream.h"
#include "net/third_party/quiche/src/quiche/quic/core/http/spdy_utils.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_server_id.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/crypto_test_utils.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_config_peer.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_connection_peer.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_spdy_session_peer.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_test_utils.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gmock/include/gmock/gmock.h"

using testing::_;
using testing::Return;

namespace net::test {
namespace {

class EstablishedCryptoStream : public quic::test::MockQuicCryptoStream {
 public:
  using quic::test::MockQuicCryptoStream::MockQuicCryptoStream;

  bool encryption_established() const override { return true; }
};

class MockQuicClientSessionBase : public quic::QuicSpdyClientSessionBase {
 public:
  explicit MockQuicClientSessionBase(quic::QuicConnection* connection);

  MockQuicClientSessionBase(const MockQuicClientSessionBase&) = delete;
  MockQuicClientSessionBase& operator=(const MockQuicClientSessionBase&) =
      delete;

  ~MockQuicClientSessionBase() override;

  const quic::QuicCryptoStream* GetCryptoStream() const override {
    return crypto_stream_.get();
  }

  quic::QuicCryptoStream* GetMutableCryptoStream() override {
    return crypto_stream_.get();
  }

  void SetCryptoStream(quic::QuicCryptoStream* crypto_stream) {
    crypto_stream_.reset(crypto_stream);
  }

  // From quic::QuicSession.
  MOCK_METHOD2(OnConnectionClosed,
               void(const quic::QuicConnectionCloseFrame& frame,
                    quic::ConnectionCloseSource source));
  MOCK_METHOD1(CreateIncomingStream,
               quic::QuicSpdyStream*(quic::QuicStreamId id));
  MOCK_METHOD1(CreateIncomingStream,
               quic::QuicSpdyStream*(quic::PendingStream* pending));
  MOCK_METHOD0(CreateOutgoingBidirectionalStream, QuicChromiumClientStream*());
  MOCK_METHOD0(CreateOutgoingUnidirectionalStream, QuicChromiumClientStream*());
  MOCK_METHOD6(WritevData,
               quic::QuicConsumedData(quic::QuicStreamId id,
                                      size_t write_length,
                                      quic::QuicStreamOffset offset,
                                      quic::StreamSendingState state,
                                      quic::TransmissionType type,
                                      quic::EncryptionLevel level));
  MOCK_METHOD2(WriteControlFrame,
               bool(const quic::QuicFrame&, quic::TransmissionType));
  MOCK_METHOD4(SendRstStream,
               void(quic::QuicStreamId stream_id,
                    quic::QuicRstStreamErrorCode error,
                    quic::QuicStreamOffset bytes_written,
                    bool send_rst_only));

  MOCK_METHOD2(OnStreamHeaders,
               void(quic::QuicStreamId stream_id,
                    std::string_view headers_data));
  MOCK_METHOD2(OnStreamHeadersPriority,
               void(quic::QuicStreamId stream_id,
                    const spdy::SpdyStreamPrecedence& precedence));
  MOCK_METHOD3(OnStreamHeadersComplete,
               void(quic::QuicStreamId stream_id, bool fin, size_t frame_len));
  MOCK_CONST_METHOD0(OneRttKeysAvailable, bool());
  // Methods taking non-copyable types like quiche::HttpHeaderBlock by value
  // cannot be mocked directly.
  size_t WriteHeadersOnHeadersStream(
      quic::QuicStreamId id,
      quiche::HttpHeaderBlock headers,
      bool fin,
      const spdy::SpdyStreamPrecedence& precedence,
      quiche::QuicheReferenceCountedPointer<quic::QuicAckListenerInterface>
          ack_listener) override {
    return WriteHeadersOnHeadersStreamMock(id, headers, fin, precedence,
                                           std::move(ack_listener));
  }
  MOCK_METHOD5(WriteHeadersOnHeadersStreamMock,
               size_t(quic::QuicStreamId id,
                      const quiche::HttpHeaderBlock& headers,
                      bool fin,
                      const spdy::SpdyStreamPrecedence& precedence,
                      const quiche::QuicheReferenceCountedPointer<
                          quic::QuicAckListenerInterface>& ack_listener));
  MOCK_METHOD1(OnHeadersHeadOfLineBlocking, void(quic::QuicTime::Delta delta));

  using quic::QuicSession::ActivateStream;

  // Returns a quic::QuicConsumedData that indicates all of |write_length| (and
  // |fin| if set) has been consumed.
  static quic::QuicConsumedData ConsumeAllData(
      quic::QuicStreamId id,
      size_t write_length,
      quic::QuicStreamOffset offset,
      bool fin,
      quic::QuicAckListenerInterface* ack_listener);

  void OnProofValid(
      const quic::QuicCryptoClientConfig::CachedState& cached) override {}
  void OnProofVerifyDetailsAvailable(
      const quic::ProofVerifyDetails& verify_details) override {}

 protected:
  MOCK_METHOD1(ShouldCreateIncomingStream, bool(quic::QuicStreamId id));
  MOCK_METHOD0(ShouldCreateOutgoingBidirectionalStream, bool());
  MOCK_METHOD0(ShouldCreateOutgoingUnidirectionalStream, bool());

 private:
  std::unique_ptr<quic::QuicCryptoStream> crypto_stream_;
};

MockQuicClientSessionBase::MockQuicClientSessionBase(
    quic::QuicConnection* connection)
    : quic::QuicSpdyClientSessionBase(connection,
                                      /*visitor=*/nullptr,
                                      quic::test::DefaultQuicConfig(),
                                      connection->supported_versions()) {
  crypto_stream_ = std::make_unique<quic::test::MockQuicCryptoStream>(this);
  Initialize();
  ON_CALL(*this, WritevData(_, _, _, _, _, _))
      .WillByDefault(testing::Return(quic::QuicConsumedData(0, false)));
}

MockQuicClientSessionBase::~MockQuicClientSessionBase() = default;

class QuicChromiumClientStreamTest
    : public ::testing::TestWithParam<quic::ParsedQuicVersion>,
      public WithTaskEnvironment {
 public:
  QuicChromiumClientStreamTest()
      : version_(GetParam()),
        crypto_config_(
            quic::test::crypto_test_utils::ProofVerifierForTesting()),
        session_(new quic::test::MockQuicConnection(
            &helper_,
            &alarm_factory_,
            quic::Perspective::IS_CLIENT,
            quic::test::SupportedVersions(version_))) {
    quic::test::QuicConfigPeer::SetReceivedInitialSessionFlowControlWindow(
        session_.config(), quic::kMinimumFlowControlSendWindow);
    quic::test::QuicConfigPeer::
        SetReceivedInitialMaxStreamDataBytesOutgoingBidirectional(
            session_.config(), quic::kMinimumFlowControlSendWindow);
    quic::test::QuicConfigPeer::SetReceivedMaxUnidirectionalStreams(
        session_.config(), 10);
    session_.OnConfigNegotiated();
    stream_ = new QuicChromiumClientStream(
        quic::test::GetNthClientInitiatedBidirectionalStreamId(
            version_.transport_version, 0),
        &session_, quic::QuicServerId(), quic::BIDIRECTIONAL,
        NetLogWithSource(), TRAFFIC_ANNOTATION_FOR_TESTS);
    session_.ActivateStream(base::WrapUnique(stream_.get()));
    handle_ = stream_->CreateHandle();
    helper_.AdvanceTime(quic::QuicTime::Delta::FromSeconds(1));
    session_.SetCryptoStream(new EstablishedCryptoStream(&session_));
    session_.connection()->SetEncrypter(
        quic::ENCRYPTION_FORWARD_SECURE,
        std::make_unique<quic::test::TaggingEncrypter>(
            quic::ENCRYPTION_FORWARD_SECURE));
  }

  void InitializeHeaders() {
    headers_[":host"] = "www.google.com";
    headers_[":path"] = "/index.hml";
    headers_[":scheme"] = "https";
    headers_[":status"] = "200";
    headers_["cookie"] =
        "__utma=208381060.1228362404.1372200928.1372200928.1372200928.1; "
        "__utmc=160408618; "
        "GX=DQAAAOEAAACWJYdewdE9rIrW6qw3PtVi2-d729qaa-74KqOsM1NVQblK4VhX"
        "hoALMsy6HOdDad2Sz0flUByv7etmo3mLMidGrBoljqO9hSVA40SLqpG_iuKKSHX"
        "RW3Np4bq0F0SDGDNsW0DSmTS9ufMRrlpARJDS7qAI6M3bghqJp4eABKZiRqebHT"
        "pMU-RXvTI5D5oCF1vYxYofH_l1Kviuiy3oQ1kS1enqWgbhJ2t61_SNdv-1XJIS0"
        "O3YeHLmVCs62O6zp89QwakfAWK9d3IDQvVSJzCQsvxvNIvaZFa567MawWlXg0Rh"
        "1zFMi5vzcns38-8_Sns; "
        "GA=v*2%2Fmem*57968640*47239936%2Fmem*57968640*47114716%2Fno-nm-"
        "yj*15%2Fno-cc-yj*5%2Fpc-ch*133685%2Fpc-s-cr*133947%2Fpc-s-t*1339"
        "47%2Fno-nm-yj*4%2Fno-cc-yj*1%2Fceft-as*1%2Fceft-nqas*0%2Fad-ra-c"
        "v_p%2Fad-nr-cv_p-f*1%2Fad-v-cv_p*859%2Fad-ns-cv_p-f*1%2Ffn-v-ad%"
        "2Fpc-t*250%2Fpc-cm*461%2Fpc-s-cr*722%2Fpc-s-t*722%2Fau_p*4"
        "SICAID=AJKiYcHdKgxum7KMXG0ei2t1-W4OD1uW-ecNsCqC0wDuAXiDGIcT_HA2o1"
        "3Rs1UKCuBAF9g8rWNOFbxt8PSNSHFuIhOo2t6bJAVpCsMU5Laa6lewuTMYI8MzdQP"
        "ARHKyW-koxuhMZHUnGBJAM1gJODe0cATO_KGoX4pbbFxxJ5IicRxOrWK_5rU3cdy6"
        "edlR9FsEdH6iujMcHkbE5l18ehJDwTWmBKBzVD87naobhMMrF6VvnDGxQVGp9Ir_b"
        "Rgj3RWUoPumQVCxtSOBdX0GlJOEcDTNCzQIm9BSfetog_eP_TfYubKudt5eMsXmN6"
        "QnyXHeGeK2UINUzJ-D30AFcpqYgH9_1BvYSpi7fc7_ydBU8TaD8ZRxvtnzXqj0RfG"
        "tuHghmv3aD-uzSYJ75XDdzKdizZ86IG6Fbn1XFhYZM-fbHhm3mVEXnyRW4ZuNOLFk"
        "Fas6LMcVC6Q8QLlHYbXBpdNFuGbuZGUnav5C-2I_-46lL0NGg3GewxGKGHvHEfoyn"
        "EFFlEYHsBQ98rXImL8ySDycdLEFvBPdtctPmWCfTxwmoSMLHU2SCVDhbqMWU5b0yr"
        "JBCScs_ejbKaqBDoB7ZGxTvqlrB__2ZmnHHjCr8RgMRtKNtIeuZAo ";
  }

  quiche::HttpHeaderBlock CreateResponseHeaders(
      const std::string& status_code) {
    quiche::HttpHeaderBlock headers;
    headers[":status"] = status_code;
    return headers;
  }

  void ReadData(std::string_view expected_data) {
    auto buffer =
        base::MakeRefCounted<IOBufferWithSize>(expected_data.length() + 1);
    EXPECT_EQ(static_cast<int>(expected_data.length()),
              stream_->Read(buffer.get(), expected_data.length() + 1));
    EXPECT_EQ(expected_data,
              std::string_view(buffer->data(), expected_data.length()));
  }

  quic::QuicHeaderList ProcessHeaders(const quiche::HttpHeaderBlock& headers) {
    quic::QuicHeaderList h = quic::test::AsHeaderList(headers);
    stream_->OnStreamHeaderList(false, h.uncompressed_header_bytes(), h);
    return h;
  }

  quic::QuicHeaderList ProcessTrailers(const quiche::HttpHeaderBlock& headers) {
    quic::QuicHeaderList h = quic::test::AsHeaderList(headers);
    stream_->OnStreamHeaderList(true, h.uncompressed_header_bytes(), h);
    return h;
  }

  quic::QuicHeaderList ProcessHeadersFull(
      const quiche::HttpHeaderBlock& headers) {
    quic::QuicHeaderList h = ProcessHeaders(headers);
    TestCompletionCallback callback;
    EXPECT_EQ(static_cast<int>(h.uncompressed_header_bytes()),
              handle_->ReadInitialHeaders(&headers_, callback.callback()));
    EXPECT_EQ(headers, headers_);
    EXPECT_TRUE(stream_->header_list().empty());
    return h;
  }

  quic::QuicStreamId GetNthClientInitiatedBidirectionalStreamId(int n) {
    return quic::test::GetNthClientInitiatedBidirectionalStreamId(
        session_.connection()->transport_version(), n);
  }

  quic::QuicStreamId GetNthServerInitiatedUnidirectionalStreamId(int n) {
    return quic::test::GetNthServerInitiatedUnidirectionalStreamId(
        session_.connection()->transport_version(), n);
  }

  void ResetStreamCallback(QuicChromiumClientStream* stream, int /*rv*/) {
    stream->Reset(quic::QUIC_STREAM_CANCELLED);
  }

  std::string ConstructDataHeader(size_t body_len) {
    quiche::QuicheBuffer buffer = quic::HttpEncoder::SerializeDataFrameHeader(
        body_len, quiche::SimpleBufferAllocator::Get());
    return std::string(buffer.data(), buffer.size());
  }

  const quic::ParsedQuicVersion version_;
  quic::QuicCryptoClientConfig crypto_config_;
  std::unique_ptr<QuicChromiumClientStream::Handle> handle_;
  std::unique_ptr<QuicChromiumClientStream::Handle> handle2_;
  quic::test::MockQuicConnectionHelper helper_;
  quic::test::MockAlarmFactory alarm_factory_;
  MockQuicClientSessionBase session_;
  raw_ptr<QuicChromiumClientStream> stream_;
  quiche::HttpHeaderBlock headers_;
  quiche::HttpHeaderBlock trailers_;
  base::HistogramTester histogram_tester_;
};

INSTANTIATE_TEST_SUITE_P(Version,
                         QuicChromiumClientStreamTest,
                         ::testing::ValuesIn(AllSupportedQuicVersions()),
                         ::testing::PrintToStringParamName());

TEST_P(QuicChromiumClientStreamTest, Handle) {
  testing::InSequence seq;
  EXPECT_TRUE(handle_->IsOpen());
  EXPECT_EQ(quic::test::GetNthClientInitiatedBidirectionalStreamId(
                version_.transport_version, 0),
            handle_->id());
  EXPECT_EQ(quic::QUIC_NO_ERROR, handle_->connection_error());
  EXPECT_EQ(quic::QUIC_STREAM_NO_ERROR, handle_->stream_error());
  EXPECT_TRUE(handle_->IsFirstStream());
  EXPECT_FALSE(handle_->IsDoneReading());
  EXPECT_FALSE(handle_->fin_sent());
  EXPECT_FALSE(handle_->fin_received());
  EXPECT_EQ(0u, handle_->stream_bytes_read());
  EXPECT_EQ(0u, handle_->stream_bytes_written());
  EXPECT_EQ(0u, handle_->NumBytesConsumed());

  InitializeHeaders();
  quic::QuicStreamOffset offset = 0;
  ProcessHeadersFull(headers_);
  quic::QuicStreamFrame frame2(
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      true, offset, std::string_view());
  stream_->OnStreamFrame(frame2);
  EXPECT_TRUE(handle_->fin_received());
  handle_->OnFinRead();

  const char kData1[] = "hello world";
  const size_t kDataLen = std::size(kData1);

  // All data written.
  std::string header = ConstructDataHeader(kDataLen);
  EXPECT_CALL(session_,
              WritevData(stream_->id(), _, _, _, quic::NOT_RETRANSMISSION, _))
      .WillOnce(Return(quic::QuicConsumedData(header.length(), false)));
  EXPECT_CALL(session_,
              WritevData(stream_->id(), _, _, _, quic::NOT_RETRANSMISSION, _))
      .WillOnce(Return(quic::QuicConsumedData(kDataLen, true)));
  TestCompletionCallback callback;
  EXPECT_EQ(OK, handle_->WriteStreamData(std::string_view(kData1, kDataLen),
                                         true, callback.callback()));

  EXPECT_FALSE(handle_->IsOpen());
  EXPECT_EQ(quic::test::GetNthClientInitiatedBidirectionalStreamId(
                version_.transport_version, 0),
            handle_->id());
  EXPECT_EQ(quic::QUIC_NO_ERROR, handle_->connection_error());
  EXPECT_EQ(quic::QUIC_STREAM_NO_ERROR, handle_->stream_error());
  EXPECT_TRUE(handle_->IsFirstStream());
  EXPECT_TRUE(handle_->IsDoneReading());
  EXPECT_TRUE(handle_->fin_sent());
  EXPECT_TRUE(handle_->fin_received());
  EXPECT_EQ(0u, handle_->stream_bytes_read());
  EXPECT_EQ(header.length() + kDataLen, handle_->stream_bytes_written());
  EXPECT_EQ(0u, handle_->NumBytesConsumed());

  EXPECT_EQ(ERR_CONNECTION_CLOSED,
            handle_->WriteStreamData(std::string_view(kData1, kDataLen), true,
                                     callback.callback()));

  std::vector<scoped_refptr<IOBuffer>> buffers = {
      base::MakeRefCounted<IOBufferWithSize>(10)};
  std::vector<int> lengths = {10};
  EXPECT_EQ(
      ERR_CONNECTION_CLOSED,
      handle_->WritevStreamData(buffers, lengths, true, callback.callback()));

  quiche::HttpHeaderBlock headers;
  EXPECT_EQ(0, handle_->WriteHeaders(std::move(headers), true, nullptr));
}

TEST_P(QuicChromiumClientStreamTest, HandleAfterConnectionClose) {
  quic::test::QuicConnectionPeer::TearDownLocalConnectionState(
      session_.connection());
  quic::QuicConnectionCloseFrame frame;
  frame.quic_error_code = quic::QUIC_INVALID_FRAME_DATA;
  stream_->OnConnectionClosed(frame, quic::ConnectionCloseSource::FROM_PEER);

  EXPECT_FALSE(handle_->IsOpen());
  EXPECT_EQ(quic::QUIC_INVALID_FRAME_DATA, handle_->connection_error());
}

TEST_P(QuicChromiumClientStreamTest, HandleAfterStreamReset) {
  // Make a STOP_SENDING frame and pass it to QUIC. We need both a REST_STREAM
  // and a STOP_SENDING to effect a closed stream.
  quic::QuicStopSendingFrame stop_sending_frame(
      quic::kInvalidControlFrameId,
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      quic::QUIC_STREAM_CANCELLED);
  session_.OnStopSendingFrame(stop_sending_frame);

  // Verify that the Handle still behaves correctly after the stream is reset.
  quic::QuicRstStreamFrame rst(
      quic::kInvalidControlFrameId,
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      quic::QUIC_STREAM_CANCELLED, 0);

  stream_->OnStreamReset(rst);
  EXPECT_FALSE(handle_->IsOpen());
  EXPECT_EQ(quic::QUIC_STREAM_CANCELLED, handle_->stream_error());
}

TEST_P(QuicChromiumClientStreamTest, OnFinRead) {
  InitializeHeaders();
  quic::QuicStreamOffset offset = 0;
  ProcessHeadersFull(headers_);
  quic::QuicStreamFrame frame2(
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      true, offset, std::string_view());
  stream_->OnStreamFrame(frame2);
}

TEST_P(QuicChromiumClientStreamTest, OnDataAvailable) {
  InitializeHeaders();
  ProcessHeadersFull(headers_);

  const char data[] = "hello world!";
  int data_len = strlen(data);
  size_t offset = 0;
  std::string header = ConstructDataHeader(data_len);
  stream_->OnStreamFrame(quic::QuicStreamFrame(
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      /*fin=*/false,
      /*offset=*/offset, header));
  offset += header.length();
  stream_->OnStreamFrame(quic::QuicStreamFrame(
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      /*fin=*/false,
      /*offset=*/offset, data));

  // Read the body and verify that it arrives correctly.
  TestCompletionCallback callback;
  auto buffer = base::MakeRefCounted<IOBufferWithSize>(2 * data_len);
  EXPECT_EQ(data_len,
            handle_->ReadBody(buffer.get(), 2 * data_len, callback.callback()));
  EXPECT_EQ(std::string_view(data), std::string_view(buffer->data(), data_len));
}

TEST_P(QuicChromiumClientStreamTest, OnDataAvailableAfterReadBody) {
  InitializeHeaders();
  ProcessHeadersFull(headers_);

  const char data[] = "hello world!";
  int data_len = strlen(data);

  // Start to read the body.
  TestCompletionCallback callback;
  auto buffer = base::MakeRefCounted<IOBufferWithSize>(2 * data_len);
  EXPECT_EQ(ERR_IO_PENDING,
            handle_->ReadBody(buffer.get(), 2 * data_len, callback.callback()));

  size_t offset = 0;
  std::string header = ConstructDataHeader(data_len);
  stream_->OnStreamFrame(quic::QuicStreamFrame(
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      /*fin=*/false,
      /*offset=*/offset, header));
  offset += header.length();

  stream_->OnStreamFrame(quic::QuicStreamFrame(
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      /*fin=*/false,
      /*offset=*/offset, data));

  EXPECT_EQ(data_len, callback.WaitForResult());
  EXPECT_EQ(std::string_view(data), std::string_view(buffer->data(), data_len));
  base::RunLoop().RunUntilIdle();
}

TEST_P(QuicChromiumClientStreamTest, ProcessHeadersWithError) {
  quiche::HttpHeaderBlock bad_headers;
  bad_headers["NAME"] = "...";

  EXPECT_CALL(
      *static_cast<quic::test::MockQuicConnection*>(session_.connection()),
      OnStreamReset(quic::test::GetNthClientInitiatedBidirectionalStreamId(
                        version_.transport_version, 0),
                    quic::QUIC_BAD_APPLICATION_PAYLOAD));

  auto headers = quic::test::AsHeaderList(bad_headers);
  stream_->OnStreamHeaderList(false, headers.uncompressed_header_bytes(),
                              headers);

  base::RunLoop().RunUntilIdle();
}

TEST_P(QuicChromiumClientStreamTest, OnDataAvailableWithError) {
  InitializeHeaders();
  auto headers = quic::test::AsHeaderList(headers_);
  ProcessHeadersFull(headers_);

  const char data[] = "hello world!";
  int data_len = strlen(data);

  // Start to read the body.
  TestCompletionCallback callback;
  auto buffer = base::MakeRefCounted<IOBufferWithSize>(2 * data_len);
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle_->ReadBody(
          buffer.get(), 2 * data_len,
          base::BindOnce(&QuicChromiumClientStreamTest::ResetStreamCallback,
                         base::Unretained(this), stream_)));

  EXPECT_CALL(
      *static_cast<quic::test::MockQuicConnection*>(session_.connection()),
      OnStreamReset(quic::test::GetNthClientInitiatedBidirectionalStreamId(
                        version_.transport_version, 0),
                    quic::QUIC_STREAM_CANCELLED));

  // Receive the data and close the stream during the callback.
  size_t offset = 0;
  std::string header = ConstructDataHeader(data_len);
  stream_->OnStreamFrame(quic::QuicStreamFrame(
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      /*fin=*/false,
      /*offset=*/offset, header));
  offset += header.length();
  stream_->OnStreamFrame(quic::QuicStreamFrame(
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      /*fin=*/false,
      /*offset=*/0, data));

  base::RunLoop().RunUntilIdle();
}

TEST_P(QuicChromiumClientStreamTest, OnError) {
  //  EXPECT_CALL(delegate_, OnError(ERR_INTERNET_DISCONNECTED)).Times(1);

  stream_->OnError(ERR_INTERNET_DISCONNECTED);
  stream_->OnError(ERR_INTERNET_DISCONNECTED);
}

TEST_P(QuicChromiumClientStreamTest, OnTrailers) {
  InitializeHeaders();
  ProcessHeadersFull(headers_);

  const char data[] = "hello world!";
  int data_len = strlen(data);
  size_t offset = 0;
  std::string header = ConstructDataHeader(data_len);
  stream_->OnStreamFrame(quic::QuicStreamFrame(
      quic::test
Prompt: 
```
这是目录为net/quic/quic_chromium_client_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_chromium_client_stream.h"

#include <string>
#include <string_view>

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/metrics/histogram_tester.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/quic/quic_chromium_client_session.h"
#include "net/quic/quic_context.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_client_session_base.h"
#include "net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_client_stream.h"
#include "net/third_party/quiche/src/quiche/quic/core/http/spdy_utils.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_server_id.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/crypto_test_utils.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_config_peer.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_connection_peer.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_spdy_session_peer.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_test_utils.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gmock/include/gmock/gmock.h"

using testing::_;
using testing::Return;

namespace net::test {
namespace {

class EstablishedCryptoStream : public quic::test::MockQuicCryptoStream {
 public:
  using quic::test::MockQuicCryptoStream::MockQuicCryptoStream;

  bool encryption_established() const override { return true; }
};

class MockQuicClientSessionBase : public quic::QuicSpdyClientSessionBase {
 public:
  explicit MockQuicClientSessionBase(quic::QuicConnection* connection);

  MockQuicClientSessionBase(const MockQuicClientSessionBase&) = delete;
  MockQuicClientSessionBase& operator=(const MockQuicClientSessionBase&) =
      delete;

  ~MockQuicClientSessionBase() override;

  const quic::QuicCryptoStream* GetCryptoStream() const override {
    return crypto_stream_.get();
  }

  quic::QuicCryptoStream* GetMutableCryptoStream() override {
    return crypto_stream_.get();
  }

  void SetCryptoStream(quic::QuicCryptoStream* crypto_stream) {
    crypto_stream_.reset(crypto_stream);
  }

  // From quic::QuicSession.
  MOCK_METHOD2(OnConnectionClosed,
               void(const quic::QuicConnectionCloseFrame& frame,
                    quic::ConnectionCloseSource source));
  MOCK_METHOD1(CreateIncomingStream,
               quic::QuicSpdyStream*(quic::QuicStreamId id));
  MOCK_METHOD1(CreateIncomingStream,
               quic::QuicSpdyStream*(quic::PendingStream* pending));
  MOCK_METHOD0(CreateOutgoingBidirectionalStream, QuicChromiumClientStream*());
  MOCK_METHOD0(CreateOutgoingUnidirectionalStream, QuicChromiumClientStream*());
  MOCK_METHOD6(WritevData,
               quic::QuicConsumedData(quic::QuicStreamId id,
                                      size_t write_length,
                                      quic::QuicStreamOffset offset,
                                      quic::StreamSendingState state,
                                      quic::TransmissionType type,
                                      quic::EncryptionLevel level));
  MOCK_METHOD2(WriteControlFrame,
               bool(const quic::QuicFrame&, quic::TransmissionType));
  MOCK_METHOD4(SendRstStream,
               void(quic::QuicStreamId stream_id,
                    quic::QuicRstStreamErrorCode error,
                    quic::QuicStreamOffset bytes_written,
                    bool send_rst_only));

  MOCK_METHOD2(OnStreamHeaders,
               void(quic::QuicStreamId stream_id,
                    std::string_view headers_data));
  MOCK_METHOD2(OnStreamHeadersPriority,
               void(quic::QuicStreamId stream_id,
                    const spdy::SpdyStreamPrecedence& precedence));
  MOCK_METHOD3(OnStreamHeadersComplete,
               void(quic::QuicStreamId stream_id, bool fin, size_t frame_len));
  MOCK_CONST_METHOD0(OneRttKeysAvailable, bool());
  // Methods taking non-copyable types like quiche::HttpHeaderBlock by value
  // cannot be mocked directly.
  size_t WriteHeadersOnHeadersStream(
      quic::QuicStreamId id,
      quiche::HttpHeaderBlock headers,
      bool fin,
      const spdy::SpdyStreamPrecedence& precedence,
      quiche::QuicheReferenceCountedPointer<quic::QuicAckListenerInterface>
          ack_listener) override {
    return WriteHeadersOnHeadersStreamMock(id, headers, fin, precedence,
                                           std::move(ack_listener));
  }
  MOCK_METHOD5(WriteHeadersOnHeadersStreamMock,
               size_t(quic::QuicStreamId id,
                      const quiche::HttpHeaderBlock& headers,
                      bool fin,
                      const spdy::SpdyStreamPrecedence& precedence,
                      const quiche::QuicheReferenceCountedPointer<
                          quic::QuicAckListenerInterface>& ack_listener));
  MOCK_METHOD1(OnHeadersHeadOfLineBlocking, void(quic::QuicTime::Delta delta));

  using quic::QuicSession::ActivateStream;

  // Returns a quic::QuicConsumedData that indicates all of |write_length| (and
  // |fin| if set) has been consumed.
  static quic::QuicConsumedData ConsumeAllData(
      quic::QuicStreamId id,
      size_t write_length,
      quic::QuicStreamOffset offset,
      bool fin,
      quic::QuicAckListenerInterface* ack_listener);

  void OnProofValid(
      const quic::QuicCryptoClientConfig::CachedState& cached) override {}
  void OnProofVerifyDetailsAvailable(
      const quic::ProofVerifyDetails& verify_details) override {}

 protected:
  MOCK_METHOD1(ShouldCreateIncomingStream, bool(quic::QuicStreamId id));
  MOCK_METHOD0(ShouldCreateOutgoingBidirectionalStream, bool());
  MOCK_METHOD0(ShouldCreateOutgoingUnidirectionalStream, bool());

 private:
  std::unique_ptr<quic::QuicCryptoStream> crypto_stream_;
};

MockQuicClientSessionBase::MockQuicClientSessionBase(
    quic::QuicConnection* connection)
    : quic::QuicSpdyClientSessionBase(connection,
                                      /*visitor=*/nullptr,
                                      quic::test::DefaultQuicConfig(),
                                      connection->supported_versions()) {
  crypto_stream_ = std::make_unique<quic::test::MockQuicCryptoStream>(this);
  Initialize();
  ON_CALL(*this, WritevData(_, _, _, _, _, _))
      .WillByDefault(testing::Return(quic::QuicConsumedData(0, false)));
}

MockQuicClientSessionBase::~MockQuicClientSessionBase() = default;

class QuicChromiumClientStreamTest
    : public ::testing::TestWithParam<quic::ParsedQuicVersion>,
      public WithTaskEnvironment {
 public:
  QuicChromiumClientStreamTest()
      : version_(GetParam()),
        crypto_config_(
            quic::test::crypto_test_utils::ProofVerifierForTesting()),
        session_(new quic::test::MockQuicConnection(
            &helper_,
            &alarm_factory_,
            quic::Perspective::IS_CLIENT,
            quic::test::SupportedVersions(version_))) {
    quic::test::QuicConfigPeer::SetReceivedInitialSessionFlowControlWindow(
        session_.config(), quic::kMinimumFlowControlSendWindow);
    quic::test::QuicConfigPeer::
        SetReceivedInitialMaxStreamDataBytesOutgoingBidirectional(
            session_.config(), quic::kMinimumFlowControlSendWindow);
    quic::test::QuicConfigPeer::SetReceivedMaxUnidirectionalStreams(
        session_.config(), 10);
    session_.OnConfigNegotiated();
    stream_ = new QuicChromiumClientStream(
        quic::test::GetNthClientInitiatedBidirectionalStreamId(
            version_.transport_version, 0),
        &session_, quic::QuicServerId(), quic::BIDIRECTIONAL,
        NetLogWithSource(), TRAFFIC_ANNOTATION_FOR_TESTS);
    session_.ActivateStream(base::WrapUnique(stream_.get()));
    handle_ = stream_->CreateHandle();
    helper_.AdvanceTime(quic::QuicTime::Delta::FromSeconds(1));
    session_.SetCryptoStream(new EstablishedCryptoStream(&session_));
    session_.connection()->SetEncrypter(
        quic::ENCRYPTION_FORWARD_SECURE,
        std::make_unique<quic::test::TaggingEncrypter>(
            quic::ENCRYPTION_FORWARD_SECURE));
  }

  void InitializeHeaders() {
    headers_[":host"] = "www.google.com";
    headers_[":path"] = "/index.hml";
    headers_[":scheme"] = "https";
    headers_[":status"] = "200";
    headers_["cookie"] =
        "__utma=208381060.1228362404.1372200928.1372200928.1372200928.1; "
        "__utmc=160408618; "
        "GX=DQAAAOEAAACWJYdewdE9rIrW6qw3PtVi2-d729qaa-74KqOsM1NVQblK4VhX"
        "hoALMsy6HOdDad2Sz0flUByv7etmo3mLMidGrBoljqO9hSVA40SLqpG_iuKKSHX"
        "RW3Np4bq0F0SDGDNsW0DSmTS9ufMRrlpARJDS7qAI6M3bghqJp4eABKZiRqebHT"
        "pMU-RXvTI5D5oCF1vYxYofH_l1Kviuiy3oQ1kS1enqWgbhJ2t61_SNdv-1XJIS0"
        "O3YeHLmVCs62O6zp89QwakfAWK9d3IDQvVSJzCQsvxvNIvaZFa567MawWlXg0Rh"
        "1zFMi5vzcns38-8_Sns; "
        "GA=v*2%2Fmem*57968640*47239936%2Fmem*57968640*47114716%2Fno-nm-"
        "yj*15%2Fno-cc-yj*5%2Fpc-ch*133685%2Fpc-s-cr*133947%2Fpc-s-t*1339"
        "47%2Fno-nm-yj*4%2Fno-cc-yj*1%2Fceft-as*1%2Fceft-nqas*0%2Fad-ra-c"
        "v_p%2Fad-nr-cv_p-f*1%2Fad-v-cv_p*859%2Fad-ns-cv_p-f*1%2Ffn-v-ad%"
        "2Fpc-t*250%2Fpc-cm*461%2Fpc-s-cr*722%2Fpc-s-t*722%2Fau_p*4"
        "SICAID=AJKiYcHdKgxum7KMXG0ei2t1-W4OD1uW-ecNsCqC0wDuAXiDGIcT_HA2o1"
        "3Rs1UKCuBAF9g8rWNOFbxt8PSNSHFuIhOo2t6bJAVpCsMU5Laa6lewuTMYI8MzdQP"
        "ARHKyW-koxuhMZHUnGBJAM1gJODe0cATO_KGoX4pbbFxxJ5IicRxOrWK_5rU3cdy6"
        "edlR9FsEdH6iujMcHkbE5l18ehJDwTWmBKBzVD87naobhMMrF6VvnDGxQVGp9Ir_b"
        "Rgj3RWUoPumQVCxtSOBdX0GlJOEcDTNCzQIm9BSfetog_eP_TfYubKudt5eMsXmN6"
        "QnyXHeGeK2UINUzJ-D30AFcpqYgH9_1BvYSpi7fc7_ydBU8TaD8ZRxvtnzXqj0RfG"
        "tuHghmv3aD-uzSYJ75XDdzKdizZ86IG6Fbn1XFhYZM-fbHhm3mVEXnyRW4ZuNOLFk"
        "Fas6LMcVC6Q8QLlHYbXBpdNFuGbuZGUnav5C-2I_-46lL0NGg3GewxGKGHvHEfoyn"
        "EFFlEYHsBQ98rXImL8ySDycdLEFvBPdtctPmWCfTxwmoSMLHU2SCVDhbqMWU5b0yr"
        "JBCScs_ejbKaqBDoB7ZGxTvqlrB__2ZmnHHjCr8RgMRtKNtIeuZAo ";
  }

  quiche::HttpHeaderBlock CreateResponseHeaders(
      const std::string& status_code) {
    quiche::HttpHeaderBlock headers;
    headers[":status"] = status_code;
    return headers;
  }

  void ReadData(std::string_view expected_data) {
    auto buffer =
        base::MakeRefCounted<IOBufferWithSize>(expected_data.length() + 1);
    EXPECT_EQ(static_cast<int>(expected_data.length()),
              stream_->Read(buffer.get(), expected_data.length() + 1));
    EXPECT_EQ(expected_data,
              std::string_view(buffer->data(), expected_data.length()));
  }

  quic::QuicHeaderList ProcessHeaders(const quiche::HttpHeaderBlock& headers) {
    quic::QuicHeaderList h = quic::test::AsHeaderList(headers);
    stream_->OnStreamHeaderList(false, h.uncompressed_header_bytes(), h);
    return h;
  }

  quic::QuicHeaderList ProcessTrailers(const quiche::HttpHeaderBlock& headers) {
    quic::QuicHeaderList h = quic::test::AsHeaderList(headers);
    stream_->OnStreamHeaderList(true, h.uncompressed_header_bytes(), h);
    return h;
  }

  quic::QuicHeaderList ProcessHeadersFull(
      const quiche::HttpHeaderBlock& headers) {
    quic::QuicHeaderList h = ProcessHeaders(headers);
    TestCompletionCallback callback;
    EXPECT_EQ(static_cast<int>(h.uncompressed_header_bytes()),
              handle_->ReadInitialHeaders(&headers_, callback.callback()));
    EXPECT_EQ(headers, headers_);
    EXPECT_TRUE(stream_->header_list().empty());
    return h;
  }

  quic::QuicStreamId GetNthClientInitiatedBidirectionalStreamId(int n) {
    return quic::test::GetNthClientInitiatedBidirectionalStreamId(
        session_.connection()->transport_version(), n);
  }

  quic::QuicStreamId GetNthServerInitiatedUnidirectionalStreamId(int n) {
    return quic::test::GetNthServerInitiatedUnidirectionalStreamId(
        session_.connection()->transport_version(), n);
  }

  void ResetStreamCallback(QuicChromiumClientStream* stream, int /*rv*/) {
    stream->Reset(quic::QUIC_STREAM_CANCELLED);
  }

  std::string ConstructDataHeader(size_t body_len) {
    quiche::QuicheBuffer buffer = quic::HttpEncoder::SerializeDataFrameHeader(
        body_len, quiche::SimpleBufferAllocator::Get());
    return std::string(buffer.data(), buffer.size());
  }

  const quic::ParsedQuicVersion version_;
  quic::QuicCryptoClientConfig crypto_config_;
  std::unique_ptr<QuicChromiumClientStream::Handle> handle_;
  std::unique_ptr<QuicChromiumClientStream::Handle> handle2_;
  quic::test::MockQuicConnectionHelper helper_;
  quic::test::MockAlarmFactory alarm_factory_;
  MockQuicClientSessionBase session_;
  raw_ptr<QuicChromiumClientStream> stream_;
  quiche::HttpHeaderBlock headers_;
  quiche::HttpHeaderBlock trailers_;
  base::HistogramTester histogram_tester_;
};

INSTANTIATE_TEST_SUITE_P(Version,
                         QuicChromiumClientStreamTest,
                         ::testing::ValuesIn(AllSupportedQuicVersions()),
                         ::testing::PrintToStringParamName());

TEST_P(QuicChromiumClientStreamTest, Handle) {
  testing::InSequence seq;
  EXPECT_TRUE(handle_->IsOpen());
  EXPECT_EQ(quic::test::GetNthClientInitiatedBidirectionalStreamId(
                version_.transport_version, 0),
            handle_->id());
  EXPECT_EQ(quic::QUIC_NO_ERROR, handle_->connection_error());
  EXPECT_EQ(quic::QUIC_STREAM_NO_ERROR, handle_->stream_error());
  EXPECT_TRUE(handle_->IsFirstStream());
  EXPECT_FALSE(handle_->IsDoneReading());
  EXPECT_FALSE(handle_->fin_sent());
  EXPECT_FALSE(handle_->fin_received());
  EXPECT_EQ(0u, handle_->stream_bytes_read());
  EXPECT_EQ(0u, handle_->stream_bytes_written());
  EXPECT_EQ(0u, handle_->NumBytesConsumed());

  InitializeHeaders();
  quic::QuicStreamOffset offset = 0;
  ProcessHeadersFull(headers_);
  quic::QuicStreamFrame frame2(
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      true, offset, std::string_view());
  stream_->OnStreamFrame(frame2);
  EXPECT_TRUE(handle_->fin_received());
  handle_->OnFinRead();

  const char kData1[] = "hello world";
  const size_t kDataLen = std::size(kData1);

  // All data written.
  std::string header = ConstructDataHeader(kDataLen);
  EXPECT_CALL(session_,
              WritevData(stream_->id(), _, _, _, quic::NOT_RETRANSMISSION, _))
      .WillOnce(Return(quic::QuicConsumedData(header.length(), false)));
  EXPECT_CALL(session_,
              WritevData(stream_->id(), _, _, _, quic::NOT_RETRANSMISSION, _))
      .WillOnce(Return(quic::QuicConsumedData(kDataLen, true)));
  TestCompletionCallback callback;
  EXPECT_EQ(OK, handle_->WriteStreamData(std::string_view(kData1, kDataLen),
                                         true, callback.callback()));

  EXPECT_FALSE(handle_->IsOpen());
  EXPECT_EQ(quic::test::GetNthClientInitiatedBidirectionalStreamId(
                version_.transport_version, 0),
            handle_->id());
  EXPECT_EQ(quic::QUIC_NO_ERROR, handle_->connection_error());
  EXPECT_EQ(quic::QUIC_STREAM_NO_ERROR, handle_->stream_error());
  EXPECT_TRUE(handle_->IsFirstStream());
  EXPECT_TRUE(handle_->IsDoneReading());
  EXPECT_TRUE(handle_->fin_sent());
  EXPECT_TRUE(handle_->fin_received());
  EXPECT_EQ(0u, handle_->stream_bytes_read());
  EXPECT_EQ(header.length() + kDataLen, handle_->stream_bytes_written());
  EXPECT_EQ(0u, handle_->NumBytesConsumed());

  EXPECT_EQ(ERR_CONNECTION_CLOSED,
            handle_->WriteStreamData(std::string_view(kData1, kDataLen), true,
                                     callback.callback()));

  std::vector<scoped_refptr<IOBuffer>> buffers = {
      base::MakeRefCounted<IOBufferWithSize>(10)};
  std::vector<int> lengths = {10};
  EXPECT_EQ(
      ERR_CONNECTION_CLOSED,
      handle_->WritevStreamData(buffers, lengths, true, callback.callback()));

  quiche::HttpHeaderBlock headers;
  EXPECT_EQ(0, handle_->WriteHeaders(std::move(headers), true, nullptr));
}

TEST_P(QuicChromiumClientStreamTest, HandleAfterConnectionClose) {
  quic::test::QuicConnectionPeer::TearDownLocalConnectionState(
      session_.connection());
  quic::QuicConnectionCloseFrame frame;
  frame.quic_error_code = quic::QUIC_INVALID_FRAME_DATA;
  stream_->OnConnectionClosed(frame, quic::ConnectionCloseSource::FROM_PEER);

  EXPECT_FALSE(handle_->IsOpen());
  EXPECT_EQ(quic::QUIC_INVALID_FRAME_DATA, handle_->connection_error());
}

TEST_P(QuicChromiumClientStreamTest, HandleAfterStreamReset) {
  // Make a STOP_SENDING frame and pass it to QUIC. We need both a REST_STREAM
  // and a STOP_SENDING to effect a closed stream.
  quic::QuicStopSendingFrame stop_sending_frame(
      quic::kInvalidControlFrameId,
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      quic::QUIC_STREAM_CANCELLED);
  session_.OnStopSendingFrame(stop_sending_frame);

  // Verify that the Handle still behaves correctly after the stream is reset.
  quic::QuicRstStreamFrame rst(
      quic::kInvalidControlFrameId,
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      quic::QUIC_STREAM_CANCELLED, 0);

  stream_->OnStreamReset(rst);
  EXPECT_FALSE(handle_->IsOpen());
  EXPECT_EQ(quic::QUIC_STREAM_CANCELLED, handle_->stream_error());
}

TEST_P(QuicChromiumClientStreamTest, OnFinRead) {
  InitializeHeaders();
  quic::QuicStreamOffset offset = 0;
  ProcessHeadersFull(headers_);
  quic::QuicStreamFrame frame2(
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      true, offset, std::string_view());
  stream_->OnStreamFrame(frame2);
}

TEST_P(QuicChromiumClientStreamTest, OnDataAvailable) {
  InitializeHeaders();
  ProcessHeadersFull(headers_);

  const char data[] = "hello world!";
  int data_len = strlen(data);
  size_t offset = 0;
  std::string header = ConstructDataHeader(data_len);
  stream_->OnStreamFrame(quic::QuicStreamFrame(
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      /*fin=*/false,
      /*offset=*/offset, header));
  offset += header.length();
  stream_->OnStreamFrame(quic::QuicStreamFrame(
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      /*fin=*/false,
      /*offset=*/offset, data));

  // Read the body and verify that it arrives correctly.
  TestCompletionCallback callback;
  auto buffer = base::MakeRefCounted<IOBufferWithSize>(2 * data_len);
  EXPECT_EQ(data_len,
            handle_->ReadBody(buffer.get(), 2 * data_len, callback.callback()));
  EXPECT_EQ(std::string_view(data), std::string_view(buffer->data(), data_len));
}

TEST_P(QuicChromiumClientStreamTest, OnDataAvailableAfterReadBody) {
  InitializeHeaders();
  ProcessHeadersFull(headers_);

  const char data[] = "hello world!";
  int data_len = strlen(data);

  // Start to read the body.
  TestCompletionCallback callback;
  auto buffer = base::MakeRefCounted<IOBufferWithSize>(2 * data_len);
  EXPECT_EQ(ERR_IO_PENDING,
            handle_->ReadBody(buffer.get(), 2 * data_len, callback.callback()));

  size_t offset = 0;
  std::string header = ConstructDataHeader(data_len);
  stream_->OnStreamFrame(quic::QuicStreamFrame(
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      /*fin=*/false,
      /*offset=*/offset, header));
  offset += header.length();

  stream_->OnStreamFrame(quic::QuicStreamFrame(
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      /*fin=*/false,
      /*offset=*/offset, data));

  EXPECT_EQ(data_len, callback.WaitForResult());
  EXPECT_EQ(std::string_view(data), std::string_view(buffer->data(), data_len));
  base::RunLoop().RunUntilIdle();
}

TEST_P(QuicChromiumClientStreamTest, ProcessHeadersWithError) {
  quiche::HttpHeaderBlock bad_headers;
  bad_headers["NAME"] = "...";

  EXPECT_CALL(
      *static_cast<quic::test::MockQuicConnection*>(session_.connection()),
      OnStreamReset(quic::test::GetNthClientInitiatedBidirectionalStreamId(
                        version_.transport_version, 0),
                    quic::QUIC_BAD_APPLICATION_PAYLOAD));

  auto headers = quic::test::AsHeaderList(bad_headers);
  stream_->OnStreamHeaderList(false, headers.uncompressed_header_bytes(),
                              headers);

  base::RunLoop().RunUntilIdle();
}

TEST_P(QuicChromiumClientStreamTest, OnDataAvailableWithError) {
  InitializeHeaders();
  auto headers = quic::test::AsHeaderList(headers_);
  ProcessHeadersFull(headers_);

  const char data[] = "hello world!";
  int data_len = strlen(data);

  // Start to read the body.
  TestCompletionCallback callback;
  auto buffer = base::MakeRefCounted<IOBufferWithSize>(2 * data_len);
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle_->ReadBody(
          buffer.get(), 2 * data_len,
          base::BindOnce(&QuicChromiumClientStreamTest::ResetStreamCallback,
                         base::Unretained(this), stream_)));

  EXPECT_CALL(
      *static_cast<quic::test::MockQuicConnection*>(session_.connection()),
      OnStreamReset(quic::test::GetNthClientInitiatedBidirectionalStreamId(
                        version_.transport_version, 0),
                    quic::QUIC_STREAM_CANCELLED));

  // Receive the data and close the stream during the callback.
  size_t offset = 0;
  std::string header = ConstructDataHeader(data_len);
  stream_->OnStreamFrame(quic::QuicStreamFrame(
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      /*fin=*/false,
      /*offset=*/offset, header));
  offset += header.length();
  stream_->OnStreamFrame(quic::QuicStreamFrame(
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      /*fin=*/false,
      /*offset=*/0, data));

  base::RunLoop().RunUntilIdle();
}

TEST_P(QuicChromiumClientStreamTest, OnError) {
  //  EXPECT_CALL(delegate_, OnError(ERR_INTERNET_DISCONNECTED)).Times(1);

  stream_->OnError(ERR_INTERNET_DISCONNECTED);
  stream_->OnError(ERR_INTERNET_DISCONNECTED);
}

TEST_P(QuicChromiumClientStreamTest, OnTrailers) {
  InitializeHeaders();
  ProcessHeadersFull(headers_);

  const char data[] = "hello world!";
  int data_len = strlen(data);
  size_t offset = 0;
  std::string header = ConstructDataHeader(data_len);
  stream_->OnStreamFrame(quic::QuicStreamFrame(
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      /*fin=*/false,
      /*offset=*/offset, header));
  offset += header.length();
  stream_->OnStreamFrame(quic::QuicStreamFrame(
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      /*fin=*/false,
      /*offset=*/offset, data));

  // Read the body and verify that it arrives correctly.
  TestCompletionCallback callback;
  auto buffer = base::MakeRefCounted<IOBufferWithSize>(2 * data_len);
  EXPECT_EQ(data_len,
            handle_->ReadBody(buffer.get(), 2 * data_len, callback.callback()));
  EXPECT_EQ(std::string_view(data), std::string_view(buffer->data(), data_len));

  quiche::HttpHeaderBlock trailers;
  trailers["bar"] = "foo";

  auto t = ProcessTrailers(trailers);

  TestCompletionCallback trailers_callback;
  EXPECT_EQ(
      static_cast<int>(t.uncompressed_header_bytes()),
      handle_->ReadTrailingHeaders(&trailers_, trailers_callback.callback()));

  // Read the body and verify that it arrives correctly.
  EXPECT_EQ(0,
            handle_->ReadBody(buffer.get(), 2 * data_len, callback.callback()));

  EXPECT_EQ(trailers, trailers_);
  base::RunLoop().RunUntilIdle();
}

// Tests that trailers are marked as consumed only before delegate is to be
// immediately notified about trailers.
TEST_P(QuicChromiumClientStreamTest, MarkTrailersConsumedWhenNotifyDelegate) {
  InitializeHeaders();
  ProcessHeadersFull(headers_);

  const char data[] = "hello world!";
  int data_len = strlen(data);
  size_t offset = 0;
  std::string header = ConstructDataHeader(data_len);
  stream_->OnStreamFrame(quic::QuicStreamFrame(
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      /*fin=*/false,
      /*offset=*/offset, header));
  offset += header.length();
  stream_->OnStreamFrame(quic::QuicStreamFrame(
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      /*fin=*/false,
      /*offset=*/offset, data));

  // Read the body and verify that it arrives correctly.
  TestCompletionCallback callback;
  auto buffer = base::MakeRefCounted<IOBufferWithSize>(2 * data_len);
  EXPECT_EQ(data_len,
            handle_->ReadBody(buffer.get(), 2 * data_len, callback.callback()));
  EXPECT_EQ(std::string_view(data), std::string_view(buffer->data(), data_len));

  // Read again, and it will be pending.
  EXPECT_THAT(
      handle_->ReadBody(buffer.get(), 2 * data_len, callback.callback()),
      IsError(ERR_IO_PENDING));

  quiche::HttpHeaderBlock trailers;
  trailers["bar"] = "foo";
  quic::QuicHeaderList t = ProcessTrailers(trailers);
  EXPECT_FALSE(stream_->IsDoneReading());

  EXPECT_EQ(static_cast<int>(t.uncompressed_header_bytes()),
            handle_->ReadTrailingHeaders(&trailers_, callback.callback()));

  // Read the body and verify that it arrives correctly.
  EXPECT_EQ(0, callback.WaitForResult());

  // Make sure the stream is properly closed since trailers and data are all
  // consumed.
  EXPECT_TRUE(stream_->IsDoneReading());
  EXPECT_EQ(trailers, trailers_);

  base::RunLoop().RunUntilIdle();
}

// Test that if Read() is called after response body is read and after trailers
// are received but not yet delivered, Read() will return ERR_IO_PENDING instead
// of 0 (EOF).
TEST_P(QuicChromiumClientStreamTest, ReadAfterTrailersReceivedButNotDelivered) {
  InitializeHeaders();
  ProcessHeadersFull(headers_);

  const char data[] = "hello world!";
  int data_len = strlen(data);
  size_t offset = 0;
  std::string header = ConstructDataHeader(data_len);
  stream_->OnStreamFrame(quic::QuicStreamFrame(
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      /*fin=*/false,
      /*offset=*/offset, header));
  offset += header.length();
  stream_->OnStreamFrame(quic::QuicStreamFrame(
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          version_.transport_version, 0),
      /*fin=*/false,
      /*offset=*/offset, data));

  // Read the body and verify that it arrives correctly.
  TestCompletionCallback callback;
  auto buffer = base::MakeRefCounted<IOBufferWithSize>(2 * data_len);
  EXPECT_EQ(data_len,
            handle_->ReadBody(buffer.get(), 2 * data_len, callback.callback()));
  EXPECT_EQ(std::string_view(data), std::string_view(buffer->data(), data_len));

  // Deliver trailers. Delegate notification is posted asynchronously.
  quiche::HttpHeaderBlock trailers;
  trailers["bar"] = "foo";

  quic::QuicHeaderList t = ProcessTrailers(trailers);

  EXPECT_FALSE(stream_->IsDoneReading());
  // Read again, it return ERR_IO_PENDING.
  EXPECT_THAT(
      handle_->ReadBody(buffer.get(), 2 * data_len, callback.callback()),
      IsError(ERR_IO_PENDING));

  // Trailers are not delivered
  EXPECT_FALSE(stream_->IsDoneReading());

  TestCompletionCallback callback2;
  EXPECT_EQ(static_cast<int>(t.uncompressed_header_bytes()),
            handle_->ReadTrailingHeaders(&trailers_, callback2.callback()));

  // Read the body and verify that it arrives correctly.
  // OnDataAvailable() should follow right after and Read() will return 0.
  EXPECT_EQ(0, callback.WaitForResult());

  // Make sure the stream is properly closed since trailers and data are all
  // consumed.
  EXPECT_TRUE(stream_->IsDoneReading());

  EXPECT_EQ(trailers, trailers_);

  base::RunLoop().RunUntilIdle();
}

TEST_P(QuicChromiumClientStreamTest, WriteStreamData) {
  testing::InSequence seq;
  const char kData1[] = "hello world";
  const size_t kDataLen = std::size(kData1);

  // All data written.
  std::string header = ConstructDataHeader(kDataLen);
  EXPECT_CALL(session_,
              WritevData(stream_->id(), _, _, _, quic::NOT_RETRANSMISSION, _))
      .WillOnce(Return(quic::QuicConsumedData(header.length(), false)));
  EXPECT_CALL(session_,
              WritevData(stream_->id(), _, _, _, quic::NOT_RETRANSMISSION, _))
      .WillOnce(Return(quic::QuicConsumedData(kDataLen, true)));
  TestCompletionCallback callback;
  EXPECT_EQ(OK, handle_->WriteStreamData(std::string_view(kData1, kDataLen),
                                         true, callback.callback()));
}

TEST_P(QuicChromiumClientStreamTest, WriteStreamDataAsync) {
  testing::InSequence seq;
  const char kData1[] = "hello world";
  const size_t kDataLen = std::size(kData1);

  // No data written.
  EXPECT_CALL(session_,
              WritevData(stream_->id(), _, _, _, quic::NOT_RETRANSMISSION, _))
      .WillOnce(Return(quic::QuicConsumedData(0, false)));
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_IO_PENDING,
            handle_->WriteStreamData(std::string_view(kData1, kDataLen), true,
                                     callback.callback()));
  ASSERT_FALSE(callback.have_result());

  // All data written.
  std::string header = ConstructDataHeader(kDataLen);
  EXPECT_CALL(session_,
              WritevData(stream_->id(), _, _, _, quic::NOT_RETRANSMISSION, _))
      .WillOnce(Return(quic::QuicConsumedData(header.length(), false)));
  EXPECT_CALL(session_,
              WritevData(stream_->id(), _, _, _, quic::NOT_RETRANSMISSION, _))
      .WillOnce(Return(quic::QuicConsumedData(kDataLen, true)));
  stream_->OnCanWrite();
  // Do 2 writes in version 99.
  stream_->OnCanWrite();
  ASSERT_TRUE(callback.have_result());
  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

TEST_P(QuicChromiumClientStreamTest, WritevStreamData) {
  testing::InSequence seq;
  scoped_refptr<StringIOBuffer> buf1 =
      base::MakeRefCounted<StringIOBuffer>("hello world!");
  scoped_refptr<StringIOBuffer> buf2 =
      base::MakeRefCounted<StringIOBuffer>("Just a small payload");

  // All data written.
  std::string header = ConstructDataHeader(buf1->size());
  EXPECT_CALL(session_,
              WritevData(stream_->id(), _, _, _, quic::NOT_RETRANSMISSION, _))
      .WillOnce(Return(quic::QuicConsumedData(header.length(), false)));
  EXPECT_CALL(session_,
              WritevData(stream_->id(), _, _, _, quic::NOT_RETRANSMISSION, _))
      .WillOnce(Return(quic::QuicConsumedData(buf1->size(), false)));
  header = ConstructDataHeader(buf2->size());
  EXPECT_CALL(session_,
              WritevData(stream_->id(), _, _, _, quic::NOT_RETRANSMISSION, _))
      .WillOnce(Return(quic::QuicConsumedData(header.length(), false)));
  EXPECT_CALL(session_,
              WritevData(stream_->id(), _, _, _, quic::NOT_RETRANSMISSION, _))
      .WillOnce(Return(quic::QuicConsumedData(buf2->size(), true)));
  TestCompletionCallback callback;
  EXPECT_EQ(
      OK, handle_->WritevStreamData({buf1, buf2}, {buf1->size(), buf2->size()},
                                    true, callback.callback()));
}

TEST_P(QuicChromiumClientStreamTest, WritevStreamDataAsync) {
  testing::InSequence seq;
  scoped_refptr<StringIOBuffer> buf1 =
      base::MakeRefCounted<StringIOBuffer>("hello world!");
  scoped_refptr<StringIOBuffer> buf2 =
      base::MakeRefCounted<StringIOBuffer>("Just a small payload");

  // Only a part of the data is written.
  std::string header = ConstructDataHeader(buf1->size());
  EXPECT_CALL(session_,
              WritevData(stream_->id(), _, _, _, quic::NOT_RETRANSMISSION, _))
      .WillOnce(Return(quic::QuicConsumedData(header.length(), false)));
  EXPECT_CALL(session_,
              WritevData(stream_->id(), _, _, _, quic::NOT_RETRANSMISSION, _))
      // First piece of data is written.
      .WillOnce(Return(quic::QuicConsumedData(buf1->size(), false)));
  // Second piece of data is queued.
  EXPECT_CALL(session_,
              WritevData(stream_->id(), _, _, _, quic::NOT_RETRANSMISSION, _))
      .WillOnce(Return(quic::QuicConsumedData(0, false)));
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_IO
"""


```