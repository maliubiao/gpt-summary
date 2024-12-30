Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The user wants to understand the functionality of the `net/spdy/spdy_stream_unittest.cc` file in Chromium's network stack. They also want to know its relation to JavaScript, see examples of logical reasoning, understand common usage errors, debugging information, and a general summary of the file's purpose.

2. **Initial File Scan and Keyword Identification:** I quickly scan the provided code, looking for keywords and patterns that reveal the file's purpose. I see:
    * `unittest`: This immediately tells me it's a testing file.
    * `SpdyStream`: This is the primary class being tested.
    * `MockRead`, `MockWrite`, `SequencedSocketData`: These indicate that the tests simulate network interactions.
    * `CreateStreamSynchronously`, `SendRequestHeaders`, `SetDelegate`, `WaitForClose`: These are methods of the `SpdyStream` class that are being tested.
    * `EXPECT_THAT`, `ASSERT_TRUE`, `EXPECT_EQ`: These are Google Test macros used for assertions in the tests.
    * Various test case names like `SendDataAfterOpen`, `BrokenConnectionDetectionSuccessfulRequest`, `Trailers`, `StreamError`, etc.: These give a good overview of the specific functionalities being tested.

3. **Identify the Target Class:** The core of the file is testing the `SpdyStream` class. I need to infer what this class does based on the tests. It clearly deals with:
    * Sending request headers and data.
    * Receiving response headers, data, and trailers.
    * Handling different stream types (bidirectional, request/response).
    * Managing stream errors.
    * Dealing with large data transfers.
    * Enforcing HTTP/2 protocol rules (header case, status presence, trailer usage).
    * Measuring timing information.
    * Supporting push streams.
    * Handling stream prioritization.
    * Managing receive window updates.
    * Dealing with stalling and unstalling.

4. **Relate to JavaScript (if applicable):** I consider how these functionalities relate to JavaScript in a web browser. JavaScript uses APIs like `fetch` or `XMLHttpRequest` to make network requests. While JavaScript doesn't directly interact with `SpdyStream`, the behavior and correctness of `SpdyStream` directly impact the reliability and performance of those JavaScript APIs when communicating over HTTP/2 (which SPDY evolved into). For instance, if `SpdyStream` incorrectly handles large data, it could lead to incomplete data being received in JavaScript. If it doesn't enforce protocol rules, it could lead to unexpected errors in JavaScript applications.

5. **Logical Reasoning Examples:** I select a few test cases and think about the assumptions, inputs, and expected outputs. For example, in `SendDataAfterOpen`:
    * **Assumption:** Sending data after the stream is open should succeed.
    * **Input:**  A POST request with a body.
    * **Output:** The server should receive the data, and the client should receive the server's response and the echoed data.

6. **Common Usage Errors:** I consider how a programmer using the `SpdyStream` class directly (though this is less common than using higher-level APIs) or how the underlying logic could be misused. For instance, forgetting to set a delegate, trying to send data after closing the stream, or mismanaging flow control could be potential errors.

7. **Debugging Information (User Actions):**  I imagine a user encountering a problem related to HTTP/2 networking. The steps to reach this unit test as a debugging aid would involve:
    * A user action triggering an HTTP/2 request (e.g., navigating to a website, loading a resource).
    * The browser's network stack selecting an existing or creating a new HTTP/2 connection.
    * The creation of a `SpdyStream` object to handle the specific request.
    * If issues arise (e.g., connection errors, incorrect data), developers might investigate the `SpdyStream` logic, potentially running these unit tests to isolate problems.

8. **Summarize Functionality (Part 1):** Based on the identified test cases and the purpose of unit tests, I summarize that the file focuses on testing the core functionalities of the `SpdyStream` class, covering sending requests, receiving responses, handling data and trailers, error scenarios, and protocol compliance.

9. **Structure the Answer:** I organize my thoughts into the requested categories, using clear headings and bullet points for readability. I provide specific examples and try to explain the concepts in a way that's understandable even without deep knowledge of the Chromium networking stack. I make sure to explicitly address each part of the user's request.

10. **Refine and Review:** I review my answer to ensure accuracy, completeness, and clarity. I double-check that the examples are relevant and that the language is precise. I make sure to acknowledge that this is only part 1 and focus the summary accordingly.
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/spdy/spdy_stream.h"

#include <stdint.h>

#include <algorithm>
#include <cstddef>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/functional/bind.h"
#include "base/memory/ref_counted.h"
#include "base/run_loop.h"
#include "base/time/time.h"
#include "net/base/request_priority.h"
#include "net/base/session_usage.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_request_info.h"
#include "net/log/net_log_event_type.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "net/socket/socket_tag.h"
#include "net/socket/socket_test_util.h"
#include "net/spdy/buffered_spdy_framer.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/spdy/spdy_session.h"
#include "net/spdy/spdy_session_pool.h"
#include "net/spdy/spdy_stream_test_util.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/third_party/quiche/src/quiche/http2/core/spdy_protocol.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

// TODO(ukai): factor out common part with spdy_http_stream_unittest.cc
//
namespace net::test {

namespace {

const char kPostBody[] = "\0hello!\xff";
const size_t kPostBodyLength = std::size(kPostBody);
const std::string_view kPostBodyStringPiece(kPostBody, kPostBodyLength);

// Creates a MockRead from the given serialized frame except for the last byte.
MockRead ReadFrameExceptForLastByte(const spdy::SpdySerializedFrame& frame) {
  CHECK_GE(frame.size(), 2u);
  return MockRead(ASYNC, frame.data(), frame.size() - 1);
}

// Creates a MockRead from the last byte of the given serialized frame.
MockRead LastByteOfReadFrame(const spdy::SpdySerializedFrame& frame) {
  CHECK_GE(frame.size(), 2u);
  return MockRead(ASYNC, frame.data() + frame.size() - 1, 1);
}

}  // namespace

class SpdyStreamTest : public ::testing::Test, public WithTaskEnvironment {
 protected:
  // A function that takes a SpdyStream and the number of bytes which
  // will unstall the next frame completely.
  typedef base::OnceCallback<void(const base::WeakPtr<SpdyStream>&, int32_t)>
      UnstallFunction;

  explicit SpdyStreamTest(base::test::TaskEnvironment::TimeSource time_source =
                              base::test::TaskEnvironment::TimeSource::DEFAULT)
      : WithTaskEnvironment(time_source),
        url_(kDefaultUrl),
        session_(SpdySessionDependencies::SpdyCreateSession(&session_deps_)),
        ssl_(SYNCHRONOUS, OK) {}

  ~SpdyStreamTest() override = default;

  base::WeakPtr<SpdySession> CreateDefaultSpdySession() {
    SpdySessionKey key(HostPortPair::FromURL(url_), PRIVACY_MODE_DISABLED,
                       ProxyChain::Direct(), SessionUsage::kDestination,
                       SocketTag(), NetworkAnonymizationKey(),
                       SecureDnsPolicy::kAllow,
                       /*disable_cert_verification_network_fetches=*/false);
    return CreateSpdySession(session_.get(), key, NetLogWithSource());
  }

  void TearDown() override { base::RunLoop().RunUntilIdle(); }

  void RunResumeAfterUnstallRequestResponseTest(
      UnstallFunction unstall_function);

  void RunResumeAfterUnstallBidirectionalTest(UnstallFunction unstall_function);

  // Add{Read,Write}() populates lists that are eventually passed to a
  // SocketData class. |frame| must live for the whole test.

  void AddRead(const spdy::SpdySerializedFrame& frame) {
    reads_.push_back(CreateMockRead(frame, offset_++));
  }

  void AddWrite(const spdy::SpdySerializedFrame& frame) {
    writes_.push_back(CreateMockWrite(frame, offset_++));
  }

  void AddMockRead(MockRead read) {
    read.sequence_number = offset_++;
    reads_.push_back(std::move(read));
  }

  void AddReadEOF() { reads_.emplace_back(ASYNC, 0, offset_++); }

  void AddWritePause() {
    writes_.emplace_back(ASYNC, ERR_IO_PENDING, offset_++);
  }

  void AddReadPause() { reads_.emplace_back(ASYNC, ERR_IO_PENDING, offset_++); }

  base::span<const MockRead> GetReads() { return reads_; }
  base::span<const MockWrite> GetWrites() { return writes_; }

  void ActivatePushStream(SpdySession* session, SpdyStream* stream) {
    std::unique_ptr<SpdyStream> activated =
        session->ActivateCreatedStream(stream);
    activated->set_stream_id(2);
    session->InsertActivatedStream(std::move(activated));
  }

  void AddSSLSocketData() {
    // Load a cert that is valid for
    // www.example.org, mail.example.org, and mail.example.com.
    ssl_.ssl_info.cert =
        ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
    ASSERT_TRUE(ssl_.ssl_info.cert);
    session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_);
  }

  int32_t unacked_recv_window_bytes(base::WeakPtr<SpdyStream> stream) {
    return stream->unacked_recv_window_bytes_;
  }

  static SpdySessionPool* spdy_session_pool(
      base::WeakPtr<SpdySession> session) {
    return session->pool_;
  }

  const GURL url_;
  SpdyTestUtil spdy_util_;
  SpdySessionDependencies session_deps_;
  std::unique_ptr<HttpNetworkSession> session_;

 private:
  // Used by Add{Read,Write}() above.
  std::vector<MockWrite> writes_;
  std::vector<MockRead> reads_;
  int offset_ = 0;
  SSLSocketDataProvider ssl_;
};

TEST_F(SpdyStreamTest, SendDataAfterOpen) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  AddRead(resp);

  spdy::SpdySerializedFrame msg(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, false));
  AddWrite(msg);

  spdy::SpdySerializedFrame echo(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, false));
  AddRead(echo);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  StreamDelegateSendImmediate delegate(stream, kPostBodyStringPiece);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate.send_headers_completed());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(spdy::kHttp2StatusHeader));
  EXPECT_EQ(std::string(kPostBody, kPostBodyLength),
            delegate.TakeReceivedData());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(SpdyStreamTest, BrokenConnectionDetectionSuccessfulRequest) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  AddRead(resp);

  spdy::SpdySerializedFrame msg(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, false));
  AddWrite(msg);

  spdy::SpdySerializedFrame echo(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, false));
  AddRead(echo);

  AddReadPause();
  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  ASSERT_FALSE(session->IsBrokenConnectionDetectionEnabled());
  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session, url_, LOWEST, NetLogWithSource(),
      true, base::Seconds(10));
  ASSERT_TRUE(stream);
  ASSERT_TRUE(session->IsBrokenConnectionDetectionEnabled());
  StreamDelegateSendImmediate delegate(stream, kPostBodyStringPiece);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));

  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(session->IsBrokenConnectionDetectionEnabled());

  data.Resume();
  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));
  ASSERT_FALSE(session->IsBrokenConnectionDetectionEnabled());
}

// Delegate that receives trailers.
class StreamDelegateWithTrailers : public test::StreamDelegateWithBody {
 public:
  StreamDelegateWithTrailers(const base::WeakPtr<SpdyStream>& stream,
                             std::string_view data)
      : StreamDelegateWithBody(stream, data) {}

  ~StreamDelegateWithTrailers() override = default;

  void OnTrailers(const quiche::HttpHeaderBlock& trailers) override {
    trailers_ = trailers.Clone();
  }

  const quiche::HttpHeaderBlock& trailers() const { return trailers_; }

 private:
  quiche::HttpHeaderBlock trailers_;
};

// Regression test for https://crbug.com/481033.
TEST_F(SpdyStreamTest, Trailers) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  spdy::SpdySerializedFrame msg(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, true));
  AddWrite(msg);

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  AddRead(resp);

  spdy::SpdySerializedFrame echo(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, false));
  AddRead(echo);

  quiche::HttpHeaderBlock late_headers;
  late_headers["foo"] = "bar";
  spdy::SpdySerializedFrame trailers(spdy_util_.ConstructSpdyResponseHeaders(
      1, std::move(late_headers), false));
  AddRead(trailers);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  StreamDelegateWithTrailers delegate(stream, kPostBodyStringPiece);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate.send_headers_completed());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(spdy::kHttp2StatusHeader));
  const quiche::HttpHeaderBlock& received_trailers = delegate.trailers();
  quiche::HttpHeaderBlock::const_iterator it = received_trailers.find("foo");
  EXPECT_EQ("bar", it->second);
  EXPECT_EQ(std::string(kPostBody, kPostBodyLength),
            delegate.TakeReceivedData());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(SpdyStreamTest, StreamError) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  AddRead(resp);

  spdy::SpdySerializedFrame msg(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, false));
  AddWrite(msg);

  spdy::SpdySerializedFrame echo(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, false));
  AddRead(echo);

  AddReadEOF();

  RecordingNetLogObserver net_log_observer;

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session, url_, LOWEST,
      NetLogWithSource::Make(NetLogSourceType::NONE));
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  StreamDelegateSendImmediate delegate(stream, kPostBodyStringPiece);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  const spdy::SpdyStreamId stream_id = delegate.stream_id();

  EXPECT_TRUE(delegate.send_headers_completed());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(spdy::kHttp2StatusHeader));
  EXPECT_EQ(std::string(kPostBody, kPostBodyLength),
            delegate.TakeReceivedData());
  EXPECT_TRUE(data.AllWriteDataConsumed());

  // Check that the NetLog was filled reasonably.
  auto entries = net_log_observer.GetEntries();
  EXPECT_LT(0u, entries.size());

  // Check that we logged SPDY_STREAM_ERROR correctly.
  int pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP2_STREAM_ERROR, NetLogEventPhase::NONE);

  EXPECT_EQ(static_cast<int>(stream_id),
            GetIntegerValueFromParams(entries[pos], "stream_id"));
}

// Make sure that large blocks of data are properly split up into frame-sized
// chunks for a request/response (i.e., an HTTP-like) stream.
TEST_F(SpdyStreamTest, SendLargeDataAfterOpenRequestResponse) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  std::string chunk_data(kMaxSpdyFrameChunkSize, 'x');
  spdy::SpdySerializedFrame chunk(
      spdy_util_.ConstructSpdyDataFrame(1, chunk_data, false));
  AddWrite(chunk);
  AddWrite(chunk);

  spdy::SpdySerializedFrame last_chunk(
      spdy_util_.ConstructSpdyDataFrame(1, chunk_data, true));
  AddWrite(last_chunk);

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  AddRead(resp);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  std::string body_data(3 * kMaxSpdyFrameChunkSize, 'x');
  StreamDelegateWithBody delegate(stream, body_data);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate.send_headers_completed());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(spdy::kHttp2StatusHeader));
  EXPECT_EQ(std::string(), delegate.TakeReceivedData());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

// Make sure that large blocks of data are properly split up into frame-sized
// chunks for a bidirectional (i.e., non-HTTP-like) stream.
TEST_F(SpdyStreamTest, SendLargeDataAfterOpenBidirectional) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  AddRead(resp);

  std::string chunk_data(kMaxSpdyFrameChunkSize, 'x');
  spdy::SpdySerializedFrame chunk(
      spdy_util_.ConstructSpdyDataFrame(1, chunk_data, false));
  AddWrite(chunk);
  AddWrite(chunk);
  AddWrite(chunk);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  std::string body_data(3 * kMaxSpdyFrameChunkSize, 'x');
  StreamDelegateSendImmediate delegate(stream, body_data);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate.send_headers_completed());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(spdy::kHttp2StatusHeader));
  EXPECT_EQ(std::string(), delegate.TakeReceivedData());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

// Receiving a header with uppercase ASCII should result in a protocol error.
TEST_F(SpdyStreamTest, UpperCaseHeaders) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  AddWrite(req);

  const char* const kExtraHeaders[] = {"X-UpperCase", "yes"};
  spdy::SpdySerializedFrame reply(spdy_util_.ConstructSpdyGetReply(
      kExtraHeaders, std::size(kExtraHeaders) / 2, 1));
  AddRead(reply);

  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_PROTOCOL_ERROR));
  AddWrite(rst);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_THAT(
      stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND),
      IsError(ERR_IO_PENDING));

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_HTTP2_PROTOCOL_ERROR));

  // Finish async network reads and writes.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

TEST_F(SpdyStreamTest, HeadersMustHaveStatus) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  AddWrite(req);

  // Response headers without ":status" header field: protocol error.
  quiche::HttpHeaderBlock header_block_without_status;
  header_block_without_status[spdy::kHttp2MethodHeader] = "GET";
  header_block_without_status[spdy::kHttp2AuthorityHeader] = "www.example.org";
  header_block_without_status[spdy::kHttp2SchemeHeader] = "https";
  header_block_without_status[spdy::kHttp2PathHeader] = "/";
  spdy::SpdySerializedFrame reply(
      spdy_util_.ConstructSpdyReply(1, std::move(header_block_without_status)));
  AddRead(reply);

  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_PROTOCOL_ERROR));
  AddWrite(rst);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_EQ(ERR_IO_PENDING, stream->SendRequestHeaders(std::move(headers),
                                                       NO_MORE_DATA_TO_SEND));

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_HTTP2_PROTOCOL_ERROR));

  // Finish async network reads and writes.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

TEST_F(SpdyStreamTest, TrailersMustNotFollowTrailers) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  AddWrite(req);

  spdy::SpdySerializedFrame reply(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  AddRead(reply);

  spdy::SpdySerializedFrame body(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, false));
  AddRead(body);

  quiche::HttpHeaderBlock trailers_block;
  trailers_block["foo"] = "bar";
  spdy::SpdySerializedFrame first_trailers(
      spdy_util_.ConstructSpdyResponseHeaders(1, std::move(trailers_block),
                                              false));
  AddRead(first_trailers);

  // Trailers following trailers: procotol error.
  spdy::SpdySerializedFrame second_trailers(
      spdy_util_.ConstructSpdyResponseHeaders(1, std::move(trailers_block),
                                              true));
  AddRead(second_trailers);

  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_PROTOCOL_ERROR));
  AddWrite(rst);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream
Prompt: 
```
这是目录为net/spdy/spdy_stream_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/spdy/spdy_stream.h"

#include <stdint.h>

#include <algorithm>
#include <cstddef>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/functional/bind.h"
#include "base/memory/ref_counted.h"
#include "base/run_loop.h"
#include "base/time/time.h"
#include "net/base/request_priority.h"
#include "net/base/session_usage.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_request_info.h"
#include "net/log/net_log_event_type.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "net/socket/socket_tag.h"
#include "net/socket/socket_test_util.h"
#include "net/spdy/buffered_spdy_framer.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/spdy/spdy_session.h"
#include "net/spdy/spdy_session_pool.h"
#include "net/spdy/spdy_stream_test_util.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/third_party/quiche/src/quiche/http2/core/spdy_protocol.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

// TODO(ukai): factor out common part with spdy_http_stream_unittest.cc
//
namespace net::test {

namespace {

const char kPostBody[] = "\0hello!\xff";
const size_t kPostBodyLength = std::size(kPostBody);
const std::string_view kPostBodyStringPiece(kPostBody, kPostBodyLength);

// Creates a MockRead from the given serialized frame except for the last byte.
MockRead ReadFrameExceptForLastByte(const spdy::SpdySerializedFrame& frame) {
  CHECK_GE(frame.size(), 2u);
  return MockRead(ASYNC, frame.data(), frame.size() - 1);
}

// Creates a MockRead from the last byte of the given serialized frame.
MockRead LastByteOfReadFrame(const spdy::SpdySerializedFrame& frame) {
  CHECK_GE(frame.size(), 2u);
  return MockRead(ASYNC, frame.data() + frame.size() - 1, 1);
}

}  // namespace

class SpdyStreamTest : public ::testing::Test, public WithTaskEnvironment {
 protected:
  // A function that takes a SpdyStream and the number of bytes which
  // will unstall the next frame completely.
  typedef base::OnceCallback<void(const base::WeakPtr<SpdyStream>&, int32_t)>
      UnstallFunction;

  explicit SpdyStreamTest(base::test::TaskEnvironment::TimeSource time_source =
                              base::test::TaskEnvironment::TimeSource::DEFAULT)
      : WithTaskEnvironment(time_source),
        url_(kDefaultUrl),
        session_(SpdySessionDependencies::SpdyCreateSession(&session_deps_)),
        ssl_(SYNCHRONOUS, OK) {}

  ~SpdyStreamTest() override = default;

  base::WeakPtr<SpdySession> CreateDefaultSpdySession() {
    SpdySessionKey key(HostPortPair::FromURL(url_), PRIVACY_MODE_DISABLED,
                       ProxyChain::Direct(), SessionUsage::kDestination,
                       SocketTag(), NetworkAnonymizationKey(),
                       SecureDnsPolicy::kAllow,
                       /*disable_cert_verification_network_fetches=*/false);
    return CreateSpdySession(session_.get(), key, NetLogWithSource());
  }

  void TearDown() override { base::RunLoop().RunUntilIdle(); }

  void RunResumeAfterUnstallRequestResponseTest(
      UnstallFunction unstall_function);

  void RunResumeAfterUnstallBidirectionalTest(UnstallFunction unstall_function);

  // Add{Read,Write}() populates lists that are eventually passed to a
  // SocketData class. |frame| must live for the whole test.

  void AddRead(const spdy::SpdySerializedFrame& frame) {
    reads_.push_back(CreateMockRead(frame, offset_++));
  }

  void AddWrite(const spdy::SpdySerializedFrame& frame) {
    writes_.push_back(CreateMockWrite(frame, offset_++));
  }

  void AddMockRead(MockRead read) {
    read.sequence_number = offset_++;
    reads_.push_back(std::move(read));
  }

  void AddReadEOF() { reads_.emplace_back(ASYNC, 0, offset_++); }

  void AddWritePause() {
    writes_.emplace_back(ASYNC, ERR_IO_PENDING, offset_++);
  }

  void AddReadPause() { reads_.emplace_back(ASYNC, ERR_IO_PENDING, offset_++); }

  base::span<const MockRead> GetReads() { return reads_; }
  base::span<const MockWrite> GetWrites() { return writes_; }

  void ActivatePushStream(SpdySession* session, SpdyStream* stream) {
    std::unique_ptr<SpdyStream> activated =
        session->ActivateCreatedStream(stream);
    activated->set_stream_id(2);
    session->InsertActivatedStream(std::move(activated));
  }

  void AddSSLSocketData() {
    // Load a cert that is valid for
    // www.example.org, mail.example.org, and mail.example.com.
    ssl_.ssl_info.cert =
        ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
    ASSERT_TRUE(ssl_.ssl_info.cert);
    session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_);
  }

  int32_t unacked_recv_window_bytes(base::WeakPtr<SpdyStream> stream) {
    return stream->unacked_recv_window_bytes_;
  }

  static SpdySessionPool* spdy_session_pool(
      base::WeakPtr<SpdySession> session) {
    return session->pool_;
  }

  const GURL url_;
  SpdyTestUtil spdy_util_;
  SpdySessionDependencies session_deps_;
  std::unique_ptr<HttpNetworkSession> session_;

 private:
  // Used by Add{Read,Write}() above.
  std::vector<MockWrite> writes_;
  std::vector<MockRead> reads_;
  int offset_ = 0;
  SSLSocketDataProvider ssl_;
};

TEST_F(SpdyStreamTest, SendDataAfterOpen) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  AddRead(resp);

  spdy::SpdySerializedFrame msg(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, false));
  AddWrite(msg);

  spdy::SpdySerializedFrame echo(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, false));
  AddRead(echo);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  StreamDelegateSendImmediate delegate(stream, kPostBodyStringPiece);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate.send_headers_completed());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(spdy::kHttp2StatusHeader));
  EXPECT_EQ(std::string(kPostBody, kPostBodyLength),
            delegate.TakeReceivedData());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(SpdyStreamTest, BrokenConnectionDetectionSuccessfulRequest) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  AddRead(resp);

  spdy::SpdySerializedFrame msg(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, false));
  AddWrite(msg);

  spdy::SpdySerializedFrame echo(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, false));
  AddRead(echo);

  AddReadPause();
  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  ASSERT_FALSE(session->IsBrokenConnectionDetectionEnabled());
  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session, url_, LOWEST, NetLogWithSource(),
      true, base::Seconds(10));
  ASSERT_TRUE(stream);
  ASSERT_TRUE(session->IsBrokenConnectionDetectionEnabled());
  StreamDelegateSendImmediate delegate(stream, kPostBodyStringPiece);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));

  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(session->IsBrokenConnectionDetectionEnabled());

  data.Resume();
  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));
  ASSERT_FALSE(session->IsBrokenConnectionDetectionEnabled());
}

// Delegate that receives trailers.
class StreamDelegateWithTrailers : public test::StreamDelegateWithBody {
 public:
  StreamDelegateWithTrailers(const base::WeakPtr<SpdyStream>& stream,
                             std::string_view data)
      : StreamDelegateWithBody(stream, data) {}

  ~StreamDelegateWithTrailers() override = default;

  void OnTrailers(const quiche::HttpHeaderBlock& trailers) override {
    trailers_ = trailers.Clone();
  }

  const quiche::HttpHeaderBlock& trailers() const { return trailers_; }

 private:
  quiche::HttpHeaderBlock trailers_;
};

// Regression test for https://crbug.com/481033.
TEST_F(SpdyStreamTest, Trailers) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  spdy::SpdySerializedFrame msg(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, true));
  AddWrite(msg);

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  AddRead(resp);

  spdy::SpdySerializedFrame echo(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, false));
  AddRead(echo);

  quiche::HttpHeaderBlock late_headers;
  late_headers["foo"] = "bar";
  spdy::SpdySerializedFrame trailers(spdy_util_.ConstructSpdyResponseHeaders(
      1, std::move(late_headers), false));
  AddRead(trailers);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  StreamDelegateWithTrailers delegate(stream, kPostBodyStringPiece);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate.send_headers_completed());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(spdy::kHttp2StatusHeader));
  const quiche::HttpHeaderBlock& received_trailers = delegate.trailers();
  quiche::HttpHeaderBlock::const_iterator it = received_trailers.find("foo");
  EXPECT_EQ("bar", it->second);
  EXPECT_EQ(std::string(kPostBody, kPostBodyLength),
            delegate.TakeReceivedData());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(SpdyStreamTest, StreamError) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  AddRead(resp);

  spdy::SpdySerializedFrame msg(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, false));
  AddWrite(msg);

  spdy::SpdySerializedFrame echo(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, false));
  AddRead(echo);

  AddReadEOF();

  RecordingNetLogObserver net_log_observer;

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session, url_, LOWEST,
      NetLogWithSource::Make(NetLogSourceType::NONE));
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  StreamDelegateSendImmediate delegate(stream, kPostBodyStringPiece);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  const spdy::SpdyStreamId stream_id = delegate.stream_id();

  EXPECT_TRUE(delegate.send_headers_completed());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(spdy::kHttp2StatusHeader));
  EXPECT_EQ(std::string(kPostBody, kPostBodyLength),
            delegate.TakeReceivedData());
  EXPECT_TRUE(data.AllWriteDataConsumed());

  // Check that the NetLog was filled reasonably.
  auto entries = net_log_observer.GetEntries();
  EXPECT_LT(0u, entries.size());

  // Check that we logged SPDY_STREAM_ERROR correctly.
  int pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP2_STREAM_ERROR, NetLogEventPhase::NONE);

  EXPECT_EQ(static_cast<int>(stream_id),
            GetIntegerValueFromParams(entries[pos], "stream_id"));
}

// Make sure that large blocks of data are properly split up into frame-sized
// chunks for a request/response (i.e., an HTTP-like) stream.
TEST_F(SpdyStreamTest, SendLargeDataAfterOpenRequestResponse) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  std::string chunk_data(kMaxSpdyFrameChunkSize, 'x');
  spdy::SpdySerializedFrame chunk(
      spdy_util_.ConstructSpdyDataFrame(1, chunk_data, false));
  AddWrite(chunk);
  AddWrite(chunk);

  spdy::SpdySerializedFrame last_chunk(
      spdy_util_.ConstructSpdyDataFrame(1, chunk_data, true));
  AddWrite(last_chunk);

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  AddRead(resp);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  std::string body_data(3 * kMaxSpdyFrameChunkSize, 'x');
  StreamDelegateWithBody delegate(stream, body_data);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate.send_headers_completed());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(spdy::kHttp2StatusHeader));
  EXPECT_EQ(std::string(), delegate.TakeReceivedData());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

// Make sure that large blocks of data are properly split up into frame-sized
// chunks for a bidirectional (i.e., non-HTTP-like) stream.
TEST_F(SpdyStreamTest, SendLargeDataAfterOpenBidirectional) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  AddRead(resp);

  std::string chunk_data(kMaxSpdyFrameChunkSize, 'x');
  spdy::SpdySerializedFrame chunk(
      spdy_util_.ConstructSpdyDataFrame(1, chunk_data, false));
  AddWrite(chunk);
  AddWrite(chunk);
  AddWrite(chunk);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  std::string body_data(3 * kMaxSpdyFrameChunkSize, 'x');
  StreamDelegateSendImmediate delegate(stream, body_data);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate.send_headers_completed());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(spdy::kHttp2StatusHeader));
  EXPECT_EQ(std::string(), delegate.TakeReceivedData());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

// Receiving a header with uppercase ASCII should result in a protocol error.
TEST_F(SpdyStreamTest, UpperCaseHeaders) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  AddWrite(req);

  const char* const kExtraHeaders[] = {"X-UpperCase", "yes"};
  spdy::SpdySerializedFrame reply(spdy_util_.ConstructSpdyGetReply(
      kExtraHeaders, std::size(kExtraHeaders) / 2, 1));
  AddRead(reply);

  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_PROTOCOL_ERROR));
  AddWrite(rst);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_THAT(
      stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND),
      IsError(ERR_IO_PENDING));

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_HTTP2_PROTOCOL_ERROR));

  // Finish async network reads and writes.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

TEST_F(SpdyStreamTest, HeadersMustHaveStatus) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  AddWrite(req);

  // Response headers without ":status" header field: protocol error.
  quiche::HttpHeaderBlock header_block_without_status;
  header_block_without_status[spdy::kHttp2MethodHeader] = "GET";
  header_block_without_status[spdy::kHttp2AuthorityHeader] = "www.example.org";
  header_block_without_status[spdy::kHttp2SchemeHeader] = "https";
  header_block_without_status[spdy::kHttp2PathHeader] = "/";
  spdy::SpdySerializedFrame reply(
      spdy_util_.ConstructSpdyReply(1, std::move(header_block_without_status)));
  AddRead(reply);

  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_PROTOCOL_ERROR));
  AddWrite(rst);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_EQ(ERR_IO_PENDING, stream->SendRequestHeaders(std::move(headers),
                                                       NO_MORE_DATA_TO_SEND));

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_HTTP2_PROTOCOL_ERROR));

  // Finish async network reads and writes.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

TEST_F(SpdyStreamTest, TrailersMustNotFollowTrailers) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  AddWrite(req);

  spdy::SpdySerializedFrame reply(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  AddRead(reply);

  spdy::SpdySerializedFrame body(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, false));
  AddRead(body);

  quiche::HttpHeaderBlock trailers_block;
  trailers_block["foo"] = "bar";
  spdy::SpdySerializedFrame first_trailers(
      spdy_util_.ConstructSpdyResponseHeaders(1, std::move(trailers_block),
                                              false));
  AddRead(first_trailers);

  // Trailers following trailers: procotol error.
  spdy::SpdySerializedFrame second_trailers(
      spdy_util_.ConstructSpdyResponseHeaders(1, std::move(trailers_block),
                                              true));
  AddRead(second_trailers);

  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_PROTOCOL_ERROR));
  AddWrite(rst);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_EQ(ERR_IO_PENDING, stream->SendRequestHeaders(std::move(headers),
                                                       NO_MORE_DATA_TO_SEND));

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_HTTP2_PROTOCOL_ERROR));

  // Finish async network reads and writes.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

TEST_F(SpdyStreamTest, DataMustNotFollowTrailers) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  AddWrite(req);

  spdy::SpdySerializedFrame reply(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  AddRead(reply);

  spdy::SpdySerializedFrame body(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, false));
  AddRead(body);

  quiche::HttpHeaderBlock trailers_block;
  trailers_block["foo"] = "bar";
  spdy::SpdySerializedFrame trailers(spdy_util_.ConstructSpdyResponseHeaders(
      1, std::move(trailers_block), false));
  AddRead(trailers);

  // DATA frame following trailers: protocol error.
  AddRead(body);

  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_PROTOCOL_ERROR));
  AddWrite(rst);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_EQ(ERR_IO_PENDING, stream->SendRequestHeaders(std::move(headers),
                                                       NO_MORE_DATA_TO_SEND));

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_HTTP2_PROTOCOL_ERROR));

  // Finish async network reads and writes.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

class SpdyStreamTestWithMockClock : public SpdyStreamTest {
 public:
  SpdyStreamTestWithMockClock()
      : SpdyStreamTest(base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}

  void Initialize() {
    // Set up the sequenced socket data.
    data_ = std::make_unique<SequencedSocketData>(GetReads(), GetWrites());
    MockConnect connect_data(SYNCHRONOUS, OK);
    data_->set_connect_data(connect_data);
    session_deps_.socket_factory->AddSocketDataProvider(data_.get());

    AddSSLSocketData();

    // Set up the SPDY stream.
    base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());
    stream_ = CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session,
                                        url_, LOWEST, NetLogWithSource());
    ASSERT_TRUE(stream_);
    EXPECT_EQ(kDefaultUrl, stream_->url().spec());

    DCHECK(!delegate_);
    delegate_ = std::make_unique<StreamDelegateDoNothing>(stream_);
    stream_->SetDelegate(delegate_.get());
  }

  void RunUntilNextPause() {
    if (data_->IsPaused())
      data_->Resume();
    data_->RunUntilPaused();
  }

  int RunUntilClose() {
    if (data_->IsPaused())
      data_->Resume();
    return delegate_->WaitForClose();
  }

  SequencedSocketData& data() { return *data_; }
  base::WeakPtr<SpdyStream> stream() { return stream_; }
  StreamDelegateDoNothing& delegate() { return *delegate_; }

 private:
  std::unique_ptr<SequencedSocketData> data_;
  base::WeakPtr<SpdyStream> stream_;
  std::unique_ptr<StreamDelegateDoNothing> delegate_;
};

// Test that the response start time is recorded for non-informational response.
TEST_F(SpdyStreamTestWithMockClock, NonInformationalResponseStart) {
  // Set up the request.
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  AddWrite(req);

  // Set up the response headers.
  spdy::SpdySerializedFrame reply(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  // Separate the headers into 2 fragments and add pauses between the fragments
  // so that the test runner can advance the mock clock to test timing
  // information.
  AddMockRead(ReadFrameExceptForLastByte(reply));
  AddReadPause();
  AddMockRead(LastByteOfReadFrame(reply));
  AddReadPause();

  // Set up the response body.
  spdy::SpdySerializedFrame body(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, true));
  AddRead(body);
  AddReadEOF();

  // Set up the sequenced socket data and the spdy stream.
  Initialize();

  // Send a request.
  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_EQ(ERR_IO_PENDING, stream()->SendRequestHeaders(std::move(headers),
                                                         NO_MORE_DATA_TO_SEND));
  AdvanceClock(base::Seconds(1));

  // The receive headers start time should be captured at this time.
  base::TimeTicks expected_receive_headers_start_time = base::TimeTicks::Now();

  // Read the first header fragment.
  RunUntilNextPause();
  AdvanceClock(base::Seconds(1));
  // Read the second header fragment.
  RunUntilNextPause();
  AdvanceClock(base::Seconds(1));
  EXPECT_EQ("200", delegate().GetResponseHeaderValue(spdy::kHttp2StatusHeader));

  // Read the response body.
  EXPECT_THAT(RunUntilClose(), IsOk());
  EXPECT_EQ(std::string(kPostBody, kPostBodyLength),
            delegate().TakeReceivedData());

  // Finish async network reads and writes.
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(data().AllWriteDataConsumed());
  EXPECT_TRUE(data().AllReadDataConsumed());

  // No informational responses were served. The response start time should be
  // equal to the non-informational response start time.
  const LoadTimingInfo& load_timing_info = delegate().GetLoadTimingInfo();
  EXPECT_EQ(load_timing_info.receive_headers_start,
            expected_receive_headers_start_time);
  EXPECT_EQ(load_timing_info.receive_non_informational_headers_start,
            expected_receive_headers_start_time);
}

TEST_F(SpdyStreamTestWithMockClock, InformationalHeaders) {
  // Set up the request.
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  AddWrite(req);

  // Set up the informational response headers.
  quiche::HttpHeaderBlock informational_headers;
  informational_headers[":status"] = "100";
  spdy::SpdySerializedFrame informational_response(
      spdy_util_.ConstructSpdyResponseHeaders(
          1, std::move(informational_headers), false));
  // Separate the headers into 2 fragments and add pauses between the fragments
  // so that the test runner can advance the mock clock to test timing
  // information.
  AddMockRead(ReadFrameExceptForLastByte(informational_response));
  AddReadPause();
  AddMockRead(LastByteOfReadFrame(informational_response));
  AddReadPause();

  // Set up the non-informational response headers and body.
  spdy::SpdySerializedFrame reply(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  AddRead(reply);
  AddReadPause();
  spdy::SpdySerializedFrame body(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, true));
  AddRead(body);
  AddReadEOF();

  // Set up the sequenced socket data and the spdy stream.
  Initialize();

  // Send a request.
  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_EQ(ERR_IO_PENDING, stream()->SendRequestHeaders(std::move(headers),
                                                         NO_MORE_DATA_TO_SEND));
  AdvanceClock(base::Seconds(1));

  // The receive headers start time should be captured at this time.
  base::TimeTicks expected_receive_headers_start_time = base::TimeTicks::Now();

  // Read the first header fragment of the informational response.
  RunUntilNextPause();
  AdvanceClock(base::Seconds(1));
  // Read the second header fragment of the informational response.
  RunUntilNextPause();
  AdvanceClock(base::Seconds(1));
  // We don't check the status code of the informational headers here because
  // SpdyStream doesn't propagate it to the delegate.

  // The receive non-informational headers start time should be captured at this
  // time.
  base::TimeTicks expected_receive_non_informational_headers_start_time =
      base::TimeTicks::Now();

  // Read the non-informational response headers.
  RunUntilNextPause();
  AdvanceClock(base::Seconds(1));
  EXPECT_EQ("200", delegate().GetResponseHeaderValue(spdy::kHttp2StatusHeader));

  // Read the response body.
  EXPECT_THAT(RunUntilClose(), IsOk());
  EXPECT_EQ(std::string(kPostBody, kPostBodyLength),
            delegate().TakeReceivedData());

  // Finish async network reads and writes.
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(data().AllWriteDataConsumed());
  EXPECT_TRUE(data().AllReadDataConsumed());

  const LoadTimingInfo& load_timing_info = delegate().GetLoadTimingInfo();
  // The response start time should be captured at the time the first header
  // fragment of the informational response is 
"""


```