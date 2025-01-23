Response:
The user wants to understand the functionality of the C++ source code file `nghttp2_adapter_test.cc`.

Here's a breakdown of the thought process to answer the request:

1. **Identify the core purpose of the file:** The file name ends in `_test.cc`, which strongly suggests it contains unit tests. The directory path includes `adapter`, indicating that the code under test is likely an adapter between different HTTP/2 implementations. `nghttp2` in the name further pinpoints the interaction with the `nghttp2` library.

2. **Scan the included headers:**  The included headers provide crucial clues about the file's functionality:
    * `"quiche/http2/adapter/nghttp2_adapter.h"`:  This is the header for the class being tested.
    * Other headers in `quiche/http2/adapter/`:  These likely define interfaces and utility classes used by the adapter and the tests (e.g., `Http2VisitorInterface`, `MockHttp2Visitor`, `TestFrameSequence`).
    * Standard C++ headers (`memory`, `string`, `vector`): Indicate basic data structures are used.
    * `"quiche/common/platform/api/quiche_test.h"`: Confirms this is a QUICHE test file.

3. **Examine the test structure:** The code uses the `TEST` macro from a testing framework (likely Google Test, given the Chromium context). Each `TEST` case focuses on a specific aspect of the `NgHttp2Adapter` class.

4. **Analyze individual test cases:**  Go through each test case and understand what it's verifying:
    * `ClientConstruction`: Checks if a client adapter can be created.
    * `ClientHandlesFrames`:  Tests the adapter's ability to process various HTTP/2 frames received from a server and send frames. This is a core test.
    * `QueuingWindowUpdateAffectsWindow`: Verifies that window updates are correctly tracked.
    * `AckOfSettingInitialWindowSizeAffectsWindow`: Checks how the adapter handles acknowledgements of initial window size settings.
    * Tests related to rejecting 100 (Early Hints) responses with various conditions (Fin, content, Content-Length): These test error handling and compliance with the HTTP/2 specification.
    * `ResponseCompleteBeforeRequestTest`:  Examines how the adapter handles responses received before the client has finished sending the request.
    * `ClientHandles204WithContent`: Tests the adapter's behavior when receiving a 204 No Content response with a body (which is invalid).

5. **Identify key functionalities based on the tests:** Based on the analyzed tests, the main functionalities of the adapter are:
    * Creating client HTTP/2 sessions.
    * Sending and receiving various HTTP/2 frames (HEADERS, DATA, SETTINGS, PING, WINDOW_UPDATE, RST_STREAM, GOAWAY).
    * Managing stream states and user data associated with streams.
    * Handling flow control (window updates).
    * Encoding and decoding HTTP headers (implicitly through interaction with `nghttp2`).
    * Enforcing HTTP/2 protocol rules (e.g., handling of 100 responses, 204 responses with content).
    * Interacting with a visitor interface to notify about events.

6. **Address the JavaScript relationship:** The file is C++ and directly interacts with the `nghttp2` library, which is also C. There's no direct JavaScript code within this file. However, HTTP/2 is a fundamental protocol for web communication. JavaScript running in a browser relies on the browser's network stack (which includes components like this adapter) to communicate with servers using HTTP/2. Examples would involve `fetch()` API calls or WebSocket connections that utilize HTTP/2.

7. **Consider logical reasoning (input/output):**  The tests often involve sending a sequence of bytes (representing HTTP/2 frames) as input to the `ProcessBytes` method and observing the calls made to the `MockHttp2Visitor` as output. Specific examples are provided in the detailed analysis of each test case.

8. **Think about user/programming errors:**  The tests that check rejection of 100 responses and 204 responses with content highlight potential server-side implementation errors that the adapter is designed to handle. A common user error might be a server sending invalid HTTP/2 frames.

9. **Outline user operation and debugging:**  The steps leading to this code being executed during debugging involve:
    * A network request being initiated in Chromium.
    * The network stack deciding to use HTTP/2.
    * The `NgHttp2Adapter` being used to manage the HTTP/2 connection.
    * If something goes wrong (e.g., a server sends an invalid frame), a developer might look at these tests to understand how the adapter *should* behave and potentially step through the adapter's code and the `nghttp2` library to diagnose the issue.

10. **Summarize the functionality (for part 1):** Focus on the core purpose of testing the client-side `NgHttp2Adapter`'s ability to handle basic connection setup and frame processing.

**(Self-correction/Refinement):** Initially, I might have focused too much on the low-level details of each test case. It's important to step back and synthesize the information to identify the broader functionalities being tested. Also,  it's crucial to explicitly state the lack of direct JavaScript interaction while explaining the indirect relationship through web browsers and HTTP.
```cpp
#include "quiche/http2/adapter/nghttp2_adapter.h"

#include <memory>
#include <string>
#include <vector>

#include "quiche/http2/adapter/http2_protocol.h"
#include "quiche/http2/adapter/http2_visitor_interface.h"
#include "quiche/http2/adapter/mock_http2_visitor.h"
#include "quiche/http2/adapter/nghttp2.h"
#include "quiche/http2/adapter/nghttp2_test_utils.h"
#include "quiche/http2/adapter/oghttp2_util.h"
#include "quiche/http2/adapter/test_frame_sequence.h"
#include "quiche/http2/adapter/test_utils.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace http2 {
namespace adapter {
namespace test {
namespace {

using ConnectionError = Http2VisitorInterface::ConnectionError;

using spdy::SpdyFrameType;
using testing::_;

enum FrameType {
  DATA,
  HEADERS,
  PRIORITY,
  RST_STREAM,
  SETTINGS,
  PUSH_PROMISE,
  PING,
  GOAWAY,
  WINDOW_UPDATE,
  CONTINUATION,
};

// This send callback assumes |source|'s pointer is a TestDataSource, and
// |user_data| is a Http2VisitorInterface.
int TestSendCallback(nghttp2_session*, nghttp2_frame* /*frame*/,
                     const uint8_t* framehd, size_t length,
                     nghttp2_data_source* source, void* user_data) {
  auto* visitor = static_cast<Http2VisitorInterface*>(user_data);
  // Send the frame header via the visitor.
  ssize_t result = visitor->OnReadyToSend(ToStringView(framehd, 9));
  if (result == 0) {
    return NGHTTP2_ERR_WOULDBLOCK;
  }
  auto* test_source = static_cast<TestDataSource*>(source->ptr);
  absl::string_view payload = test_source->ReadNext(length);
  // Send the frame payload via the visitor.
  visitor->OnReadyToSend(payload);
  return 0;
}

TEST(NgHttp2AdapterTest, ClientConstruction) {
  testing::StrictMock<MockHttp2Visitor> visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);
  ASSERT_NE(nullptr, adapter);
  EXPECT_TRUE(adapter->want_read());
  EXPECT_FALSE(adapter->want_write());
  EXPECT_FALSE(adapter->IsServerSession());
}

TEST(NgHttp2AdapterTest, ClientHandlesFrames) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              testing::StrEq(spdy::kHttp2ConnectionHeaderPrefix));
  visitor.Clear();

  EXPECT_EQ(0, adapter->GetHighestReceivedStreamId());

  const std::string initial_frames = TestFrameSequence()
                                         .ServerPreface()
                                         .Ping(42)
                                         .WindowUpdate(0, 1000)
                                         .Serialize();
  testing::InSequence s;

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(0, 8, PING, 0));
  EXPECT_CALL(visitor, OnPing(42, false));
  EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(0, 1000));

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), initial_result);

  EXPECT_EQ(adapter->GetSendWindowSize(), kInitialFlowControlWindowSize + 1000);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(PING, 0, 8, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(PING, 0, 8, 0x1, 0));

  result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::PING}));
  visitor.Clear();

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const std::vector<Header> headers2 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/two"}});

  const std::vector<Header> headers3 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/three"}});

  const char* kSentinel1 = "arbitrary pointer 1";
  const char* kSentinel3 = "arbitrary pointer 3";
  const int32_t stream_id1 = adapter->SubmitRequest(
      headers1, nullptr, true, const_cast<char*>(kSentinel1));
  ASSERT_GT(stream_id1, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id1;

  const int32_t stream_id2 =
      adapter->SubmitRequest(headers2, nullptr, true, nullptr);
  ASSERT_GT(stream_id2, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id2;

  const int32_t stream_id3 = adapter->SubmitRequest(
      headers3, nullptr, true, const_cast<char*>(kSentinel3));
  ASSERT_GT(stream_id3, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id3;

  const char* kSentinel2 = "arbitrary pointer 2";
  adapter->SetStreamUserData(stream_id2, const_cast<char*>(kSentinel2));
  adapter->SetStreamUserData(stream_id3, nullptr);

  // These requests did not include a body, so they do not have corresponding
  // DataFrameSources.
  EXPECT_EQ(adapter->sources_size(), 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id2, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id2, _, 0x5, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id3, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id3, _, 0x5, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::HEADERS, SpdyFrameType::HEADERS,
                            SpdyFrameType::HEADERS}));
  visitor.Clear();

  // All streams are active and have not yet received any data, so the receive
  // window should be at the initial value.
  EXPECT_EQ(kInitialFlowControlWindowSize,
            adapter->GetStreamReceiveWindowSize(stream_id1));
  EXPECT_EQ(kInitialFlowControlWindowSize,
            adapter->GetStreamReceiveWindowSize(stream_id2));
  EXPECT_EQ(kInitialFlowControlWindowSize,
            adapter->GetStreamReceiveWindowSize(stream_id3));

  // Upper bound on the flow control receive window should be the initial value.
  EXPECT_EQ(kInitialFlowControlWindowSize,
            adapter->GetStreamReceiveWindowLimit(stream_id1));

  // Connection has not yet received any data.
  EXPECT_EQ(kInitialFlowControlWindowSize, adapter->GetReceiveWindowSize());

  EXPECT_EQ(0, adapter->GetHighestReceivedStreamId());

  EXPECT_EQ(kSentinel1, adapter->GetStreamUserData(stream_id1));
  EXPECT_EQ(kSentinel2, adapter->GetStreamUserData(stream_id2));
  EXPECT_EQ(nullptr, adapter->GetStreamUserData(stream_id3));

  EXPECT_EQ(0, adapter->GetHpackDecoderDynamicTableSize());

  const std::string stream_frames =
      TestFrameSequence()
          .Headers(1,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Data(1, "This is the response body.")
          .RstStream(3, Http2ErrorCode::INTERNAL_ERROR)
          .GoAway(5, Http2ErrorCode::ENHANCE_YOUR_CALM, "calm down!!")
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "server", "my-fake-server"));
  EXPECT_CALL(visitor,
              OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, 26, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 26));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the response body."));
  EXPECT_CALL(visitor, OnFrameHeader(3, 4, RST_STREAM, 0));
  EXPECT_CALL(visitor, OnRstStream(3, Http2ErrorCode::INTERNAL_ERROR));
  EXPECT_CALL(visitor, OnCloseStream(3, Http2ErrorCode::INTERNAL_ERROR))
      .WillOnce(
          [&adapter](Http2StreamId stream_id, Http2ErrorCode /*error_code*/) {
            adapter->RemoveStream(stream_id);
            return true;
          });
  EXPECT_CALL(visitor, OnFrameHeader(0, 19, GOAWAY, 0));
  EXPECT_CALL(visitor,
              OnGoAway(5, Http2ErrorCode::ENHANCE_YOUR_CALM, "calm down!!"));
  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), stream_result);

  // First stream has received some data.
  EXPECT_GT(kInitialFlowControlWindowSize,
            adapter->GetStreamReceiveWindowSize(stream_id1));
  // Second stream was closed.
  EXPECT_EQ(-1, adapter->GetStreamReceiveWindowSize(stream_id2));
  // Third stream has not received any data.
  EXPECT_EQ(kInitialFlowControlWindowSize,
            adapter->GetStreamReceiveWindowSize(stream_id3));

  // Connection window should be the same as the first stream.
  EXPECT_EQ(adapter->GetReceiveWindowSize(),
            adapter->GetStreamReceiveWindowSize(stream_id1));

  // Upper bound on the flow control receive window should still be the initial
  // value.
  EXPECT_EQ(kInitialFlowControlWindowSize,
            adapter->GetStreamReceiveWindowLimit(stream_id1));

  EXPECT_GT(adapter->GetHpackDecoderDynamicTableSize(), 0);

  // Should be 3, but this method only works for server adapters.
  EXPECT_EQ(0, adapter->GetHighestReceivedStreamId());

  // Even though the client recieved a GOAWAY, streams 1 and 5 are still active.
  EXPECT_TRUE(adapter->want_read());

  EXPECT_CALL(visitor, OnFrameHeader(1, 0, DATA, 1));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 0));
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR))
      .WillOnce(
          [&adapter](Http2StreamId stream_id, Http2ErrorCode /*error_code*/) {
            adapter->RemoveStream(stream_id);
            return true;
          });
  EXPECT_CALL(visitor, OnFrameHeader(5, 4, RST_STREAM, 0));
  EXPECT_CALL(visitor, OnRstStream(5, Http2ErrorCode::REFUSED_STREAM));
  EXPECT_CALL(visitor, OnCloseStream(5, Http2ErrorCode::REFUSED_STREAM))
      .WillOnce(
          [&adapter](Http2StreamId stream_id, Http2ErrorCode /*error_code*/) {
            adapter->RemoveStream(stream_id);
            return true;
          });
  adapter->ProcessBytes(TestFrameSequence()
                            .Data(1, "", true)
                            .RstStream(5, Http2ErrorCode::REFUSED_STREAM)
                            .Serialize());

  // Should be 5, but this method only works for server adapters.
  EXPECT_EQ(0, adapter->GetHighestReceivedStreamId());

  // After receiving END_STREAM for 1 and RST_STREAM for 5, the session no
  // longer expects reads.
  EXPECT_FALSE(adapter->want_read());

  // Client will not have anything else to write.
  EXPECT_FALSE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), testing::IsEmpty());
}

TEST(NgHttp2AdapterTest, QueuingWindowUpdateAffectsWindow) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  EXPECT_EQ(adapter->GetReceiveWindowSize(), kInitialFlowControlWindowSize);
  adapter->SubmitWindowUpdate(0, 10000);
  EXPECT_EQ(adapter->GetReceiveWindowSize(),
            kInitialFlowControlWindowSize + 10000);

  const std::vector<Header> headers =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});
  const int32_t stream_id =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);

  EXPECT_CALL(visitor, OnBeforeFrameSent(WINDOW_UPDATE, 0, 4, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(WINDOW_UPDATE, 0, 4, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);

  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(stream_id),
            kInitialFlowControlWindowSize);
  adapter->SubmitWindowUpdate(1, 20000);
  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(stream_id),
            kInitialFlowControlWindowSize + 20000);
}

TEST(NgHttp2AdapterTest, AckOfSettingInitialWindowSizeAffectsWindow) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  testing::InSequence s;

  const std::vector<Header> headers =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});
  const int32_t stream_id1 =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);

  const std::string initial_frames =
      TestFrameSequence().ServerPreface().Serialize();
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0x0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  int64_t parse_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), static_cast<size_t>(parse_result));

  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(stream_id1),
            kInitialFlowControlWindowSize);
  adapter->SubmitSettings({{INITIAL_WINDOW_SIZE, 80000u}});
  // No update for the first stream, yet.
  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(stream_id1),
            kInitialFlowControlWindowSize);

  // Ack of server's initial settings.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  // Outbound SETTINGS containing INITIAL_WINDOW_SIZE.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);

  // Still no update, as a SETTINGS ack has not yet been received.
  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(stream_id1),
            kInitialFlowControlWindowSize);

  const std::string settings_ack =
      TestFrameSequence().SettingsAck().Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0x1));
  EXPECT_CALL(visitor, OnSettingsAck);

  parse_result = adapter->ProcessBytes(settings_ack);
  EXPECT_EQ(settings_ack.size(), static_cast<size_t>(parse_result));

  // Stream window has been updated.
  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(stream_id1), 80000);

  const std::vector<Header> headers2 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/two"}});
  const int32_t stream_id2 =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id2, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id2, _, 0x5, 0));
  result = adapter->Send();
  EXPECT_EQ(0, result);

  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(stream_id2), 80000);
}

TEST(NgHttp2AdapterTest, ClientRejects100HeadersWithFin) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, nullptr, true, nullptr);
  ASSERT_GT(stream_id1, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id1;

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1, {{":status", "100"}}, /*fin=*/false)
          .Headers(1, {{":status", "100"}}, /*fin=*/true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "100"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "100"));
  EXPECT_CALL(visitor,
              OnInvalidFrame(
                  1, Http2VisitorInterface::InvalidFrameError::kHttpMessaging));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(RST_STREAM, 1, _, 0x0, 1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::PROTOCOL_ERROR));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

TEST(NgHttp2AdapterTest, ClientRejectsFinFollowing100Headers) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, nullptr, true, nullptr);
  ASSERT_GT(stream_id1, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id1;

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(stream_id1, {{":status", "100"}}, /*fin=*/false)
          .Data(stream_id1, "", /*fin=*/true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(stream_id1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(stream_id1));
  EXPECT_CALL(visitor, OnHeaderForStream(stream_id1, ":status", "100"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(stream_id1));

  EXPECT_CALL(visitor, OnFrameHeader(stream_id1, _, DATA, 1));
  EXPECT_CALL(visitor, OnBeginDataForStream(stream_id1, _));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(RST_STREAM, 1, _, 0x0, 1));
  EXPECT_CALL(visitor,
              OnCloseStream(stream_id1, Http2ErrorCode::PROTOCOL_ERROR));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

TEST(NgHttp2AdapterTest, ClientRejects100HeadersWithContent) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, nullptr, true, nullptr);
  ASSERT_GT(stream_id1, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1, {{":status", "100"}},
                   /*fin=*/false)
          .Data(1, "We needed the final headers before data, whoops")
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "100"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT
### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/nghttp2_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
#include "quiche/http2/adapter/nghttp2_adapter.h"

#include <memory>
#include <string>
#include <vector>

#include "quiche/http2/adapter/http2_protocol.h"
#include "quiche/http2/adapter/http2_visitor_interface.h"
#include "quiche/http2/adapter/mock_http2_visitor.h"
#include "quiche/http2/adapter/nghttp2.h"
#include "quiche/http2/adapter/nghttp2_test_utils.h"
#include "quiche/http2/adapter/oghttp2_util.h"
#include "quiche/http2/adapter/test_frame_sequence.h"
#include "quiche/http2/adapter/test_utils.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace http2 {
namespace adapter {
namespace test {
namespace {

using ConnectionError = Http2VisitorInterface::ConnectionError;

using spdy::SpdyFrameType;
using testing::_;

enum FrameType {
  DATA,
  HEADERS,
  PRIORITY,
  RST_STREAM,
  SETTINGS,
  PUSH_PROMISE,
  PING,
  GOAWAY,
  WINDOW_UPDATE,
  CONTINUATION,
};

// This send callback assumes |source|'s pointer is a TestDataSource, and
// |user_data| is a Http2VisitorInterface.
int TestSendCallback(nghttp2_session*, nghttp2_frame* /*frame*/,
                     const uint8_t* framehd, size_t length,
                     nghttp2_data_source* source, void* user_data) {
  auto* visitor = static_cast<Http2VisitorInterface*>(user_data);
  // Send the frame header via the visitor.
  ssize_t result = visitor->OnReadyToSend(ToStringView(framehd, 9));
  if (result == 0) {
    return NGHTTP2_ERR_WOULDBLOCK;
  }
  auto* test_source = static_cast<TestDataSource*>(source->ptr);
  absl::string_view payload = test_source->ReadNext(length);
  // Send the frame payload via the visitor.
  visitor->OnReadyToSend(payload);
  return 0;
}

TEST(NgHttp2AdapterTest, ClientConstruction) {
  testing::StrictMock<MockHttp2Visitor> visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);
  ASSERT_NE(nullptr, adapter);
  EXPECT_TRUE(adapter->want_read());
  EXPECT_FALSE(adapter->want_write());
  EXPECT_FALSE(adapter->IsServerSession());
}

TEST(NgHttp2AdapterTest, ClientHandlesFrames) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              testing::StrEq(spdy::kHttp2ConnectionHeaderPrefix));
  visitor.Clear();

  EXPECT_EQ(0, adapter->GetHighestReceivedStreamId());

  const std::string initial_frames = TestFrameSequence()
                                         .ServerPreface()
                                         .Ping(42)
                                         .WindowUpdate(0, 1000)
                                         .Serialize();
  testing::InSequence s;

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(0, 8, PING, 0));
  EXPECT_CALL(visitor, OnPing(42, false));
  EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(0, 1000));

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), initial_result);

  EXPECT_EQ(adapter->GetSendWindowSize(), kInitialFlowControlWindowSize + 1000);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(PING, 0, 8, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(PING, 0, 8, 0x1, 0));

  result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::PING}));
  visitor.Clear();

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const std::vector<Header> headers2 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/two"}});

  const std::vector<Header> headers3 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/three"}});

  const char* kSentinel1 = "arbitrary pointer 1";
  const char* kSentinel3 = "arbitrary pointer 3";
  const int32_t stream_id1 = adapter->SubmitRequest(
      headers1, nullptr, true, const_cast<char*>(kSentinel1));
  ASSERT_GT(stream_id1, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id1;

  const int32_t stream_id2 =
      adapter->SubmitRequest(headers2, nullptr, true, nullptr);
  ASSERT_GT(stream_id2, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id2;

  const int32_t stream_id3 = adapter->SubmitRequest(
      headers3, nullptr, true, const_cast<char*>(kSentinel3));
  ASSERT_GT(stream_id3, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id3;

  const char* kSentinel2 = "arbitrary pointer 2";
  adapter->SetStreamUserData(stream_id2, const_cast<char*>(kSentinel2));
  adapter->SetStreamUserData(stream_id3, nullptr);

  // These requests did not include a body, so they do not have corresponding
  // DataFrameSources.
  EXPECT_EQ(adapter->sources_size(), 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id2, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id2, _, 0x5, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id3, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id3, _, 0x5, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::HEADERS, SpdyFrameType::HEADERS,
                            SpdyFrameType::HEADERS}));
  visitor.Clear();

  // All streams are active and have not yet received any data, so the receive
  // window should be at the initial value.
  EXPECT_EQ(kInitialFlowControlWindowSize,
            adapter->GetStreamReceiveWindowSize(stream_id1));
  EXPECT_EQ(kInitialFlowControlWindowSize,
            adapter->GetStreamReceiveWindowSize(stream_id2));
  EXPECT_EQ(kInitialFlowControlWindowSize,
            adapter->GetStreamReceiveWindowSize(stream_id3));

  // Upper bound on the flow control receive window should be the initial value.
  EXPECT_EQ(kInitialFlowControlWindowSize,
            adapter->GetStreamReceiveWindowLimit(stream_id1));

  // Connection has not yet received any data.
  EXPECT_EQ(kInitialFlowControlWindowSize, adapter->GetReceiveWindowSize());

  EXPECT_EQ(0, adapter->GetHighestReceivedStreamId());

  EXPECT_EQ(kSentinel1, adapter->GetStreamUserData(stream_id1));
  EXPECT_EQ(kSentinel2, adapter->GetStreamUserData(stream_id2));
  EXPECT_EQ(nullptr, adapter->GetStreamUserData(stream_id3));

  EXPECT_EQ(0, adapter->GetHpackDecoderDynamicTableSize());

  const std::string stream_frames =
      TestFrameSequence()
          .Headers(1,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Data(1, "This is the response body.")
          .RstStream(3, Http2ErrorCode::INTERNAL_ERROR)
          .GoAway(5, Http2ErrorCode::ENHANCE_YOUR_CALM, "calm down!!")
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "server", "my-fake-server"));
  EXPECT_CALL(visitor,
              OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, 26, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 26));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the response body."));
  EXPECT_CALL(visitor, OnFrameHeader(3, 4, RST_STREAM, 0));
  EXPECT_CALL(visitor, OnRstStream(3, Http2ErrorCode::INTERNAL_ERROR));
  EXPECT_CALL(visitor, OnCloseStream(3, Http2ErrorCode::INTERNAL_ERROR))
      .WillOnce(
          [&adapter](Http2StreamId stream_id, Http2ErrorCode /*error_code*/) {
            adapter->RemoveStream(stream_id);
            return true;
          });
  EXPECT_CALL(visitor, OnFrameHeader(0, 19, GOAWAY, 0));
  EXPECT_CALL(visitor,
              OnGoAway(5, Http2ErrorCode::ENHANCE_YOUR_CALM, "calm down!!"));
  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), stream_result);

  // First stream has received some data.
  EXPECT_GT(kInitialFlowControlWindowSize,
            adapter->GetStreamReceiveWindowSize(stream_id1));
  // Second stream was closed.
  EXPECT_EQ(-1, adapter->GetStreamReceiveWindowSize(stream_id2));
  // Third stream has not received any data.
  EXPECT_EQ(kInitialFlowControlWindowSize,
            adapter->GetStreamReceiveWindowSize(stream_id3));

  // Connection window should be the same as the first stream.
  EXPECT_EQ(adapter->GetReceiveWindowSize(),
            adapter->GetStreamReceiveWindowSize(stream_id1));

  // Upper bound on the flow control receive window should still be the initial
  // value.
  EXPECT_EQ(kInitialFlowControlWindowSize,
            adapter->GetStreamReceiveWindowLimit(stream_id1));

  EXPECT_GT(adapter->GetHpackDecoderDynamicTableSize(), 0);

  // Should be 3, but this method only works for server adapters.
  EXPECT_EQ(0, adapter->GetHighestReceivedStreamId());

  // Even though the client recieved a GOAWAY, streams 1 and 5 are still active.
  EXPECT_TRUE(adapter->want_read());

  EXPECT_CALL(visitor, OnFrameHeader(1, 0, DATA, 1));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 0));
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR))
      .WillOnce(
          [&adapter](Http2StreamId stream_id, Http2ErrorCode /*error_code*/) {
            adapter->RemoveStream(stream_id);
            return true;
          });
  EXPECT_CALL(visitor, OnFrameHeader(5, 4, RST_STREAM, 0));
  EXPECT_CALL(visitor, OnRstStream(5, Http2ErrorCode::REFUSED_STREAM));
  EXPECT_CALL(visitor, OnCloseStream(5, Http2ErrorCode::REFUSED_STREAM))
      .WillOnce(
          [&adapter](Http2StreamId stream_id, Http2ErrorCode /*error_code*/) {
            adapter->RemoveStream(stream_id);
            return true;
          });
  adapter->ProcessBytes(TestFrameSequence()
                            .Data(1, "", true)
                            .RstStream(5, Http2ErrorCode::REFUSED_STREAM)
                            .Serialize());

  // Should be 5, but this method only works for server adapters.
  EXPECT_EQ(0, adapter->GetHighestReceivedStreamId());

  // After receiving END_STREAM for 1 and RST_STREAM for 5, the session no
  // longer expects reads.
  EXPECT_FALSE(adapter->want_read());

  // Client will not have anything else to write.
  EXPECT_FALSE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), testing::IsEmpty());
}

TEST(NgHttp2AdapterTest, QueuingWindowUpdateAffectsWindow) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  EXPECT_EQ(adapter->GetReceiveWindowSize(), kInitialFlowControlWindowSize);
  adapter->SubmitWindowUpdate(0, 10000);
  EXPECT_EQ(adapter->GetReceiveWindowSize(),
            kInitialFlowControlWindowSize + 10000);

  const std::vector<Header> headers =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});
  const int32_t stream_id =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);

  EXPECT_CALL(visitor, OnBeforeFrameSent(WINDOW_UPDATE, 0, 4, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(WINDOW_UPDATE, 0, 4, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);

  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(stream_id),
            kInitialFlowControlWindowSize);
  adapter->SubmitWindowUpdate(1, 20000);
  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(stream_id),
            kInitialFlowControlWindowSize + 20000);
}

TEST(NgHttp2AdapterTest, AckOfSettingInitialWindowSizeAffectsWindow) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  testing::InSequence s;

  const std::vector<Header> headers =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});
  const int32_t stream_id1 =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);

  const std::string initial_frames =
      TestFrameSequence().ServerPreface().Serialize();
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0x0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  int64_t parse_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), static_cast<size_t>(parse_result));

  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(stream_id1),
            kInitialFlowControlWindowSize);
  adapter->SubmitSettings({{INITIAL_WINDOW_SIZE, 80000u}});
  // No update for the first stream, yet.
  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(stream_id1),
            kInitialFlowControlWindowSize);

  // Ack of server's initial settings.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  // Outbound SETTINGS containing INITIAL_WINDOW_SIZE.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);

  // Still no update, as a SETTINGS ack has not yet been received.
  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(stream_id1),
            kInitialFlowControlWindowSize);

  const std::string settings_ack =
      TestFrameSequence().SettingsAck().Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0x1));
  EXPECT_CALL(visitor, OnSettingsAck);

  parse_result = adapter->ProcessBytes(settings_ack);
  EXPECT_EQ(settings_ack.size(), static_cast<size_t>(parse_result));

  // Stream window has been updated.
  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(stream_id1), 80000);

  const std::vector<Header> headers2 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/two"}});
  const int32_t stream_id2 =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id2, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id2, _, 0x5, 0));
  result = adapter->Send();
  EXPECT_EQ(0, result);

  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(stream_id2), 80000);
}

TEST(NgHttp2AdapterTest, ClientRejects100HeadersWithFin) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, nullptr, true, nullptr);
  ASSERT_GT(stream_id1, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id1;

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1, {{":status", "100"}}, /*fin=*/false)
          .Headers(1, {{":status", "100"}}, /*fin=*/true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "100"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "100"));
  EXPECT_CALL(visitor,
              OnInvalidFrame(
                  1, Http2VisitorInterface::InvalidFrameError::kHttpMessaging));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(RST_STREAM, 1, _, 0x0, 1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::PROTOCOL_ERROR));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

TEST(NgHttp2AdapterTest, ClientRejectsFinFollowing100Headers) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, nullptr, true, nullptr);
  ASSERT_GT(stream_id1, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id1;

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(stream_id1, {{":status", "100"}}, /*fin=*/false)
          .Data(stream_id1, "", /*fin=*/true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(stream_id1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(stream_id1));
  EXPECT_CALL(visitor, OnHeaderForStream(stream_id1, ":status", "100"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(stream_id1));

  EXPECT_CALL(visitor, OnFrameHeader(stream_id1, _, DATA, 1));
  EXPECT_CALL(visitor, OnBeginDataForStream(stream_id1, _));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(RST_STREAM, 1, _, 0x0, 1));
  EXPECT_CALL(visitor,
              OnCloseStream(stream_id1, Http2ErrorCode::PROTOCOL_ERROR));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

TEST(NgHttp2AdapterTest, ClientRejects100HeadersWithContent) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, nullptr, true, nullptr);
  ASSERT_GT(stream_id1, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1, {{":status", "100"}},
                   /*fin=*/false)
          .Data(1, "We needed the final headers before data, whoops")
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "100"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::PROTOCOL_ERROR));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

TEST(NgHttp2AdapterTest, ClientRejects100HeadersWithContentLength) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, nullptr, true, nullptr);
  ASSERT_GT(stream_id1, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1, {{":status", "100"}, {"content-length", "42"}},
                   /*fin=*/false)
          .Headers(1,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "100"));
  EXPECT_CALL(
      visitor,
      OnErrorDebug("Invalid HTTP header field was received: frame type: 1, "
                   "stream: 1, name: [content-length], value: [42]"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(1, Http2VisitorInterface::InvalidFrameError::kHttpHeader));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::PROTOCOL_ERROR));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

class ResponseCompleteBeforeRequestTest
    : public quiche::test::QuicheTestWithParam<std::tuple<bool, bool>> {
 public:
  bool HasTrailers() const { return std::get<0>(GetParam()); }
  bool HasRstStream() const { return std::get<1>(GetParam()); }
};

INSTANTIATE_TEST_SUITE_P(TrailersAndRstStreamAllCombinations,
                         ResponseCompleteBeforeRequestTest,
                         testing::Combine(testing::Bool(), testing::Bool()));

TEST_P(ResponseCompleteBeforeRequestTest,
       ClientHandlesResponseBeforeRequestComplete) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "POST"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  adapter->SubmitSettings({});

  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);
  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, std::move(body1), false, nullptr);
  ASSERT_GT(stream_id1, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor,
              OnBeforeFrameSent(HEADERS, stream_id1, _, END_HEADERS_FLAG));
  EXPECT_CALL(visitor,
              OnFrameSent(HEADERS, stream_id1, _, END_HEADERS_FLAG, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  // * The server sends a complete response on stream 1 before the client has
  //   finished sending the request.
  //   * If HasTrailers(), the response ends with trailing HEADERS.
  //   * If HasRstStream(), the response is followed by a RST_STREAM NO_ERROR,
  //     as the HTTP/2 spec recommends.
  TestFrameSequence response;
  response.ServerPreface()
      .Headers(1, {{":status", "200"}, {"content-length", "2"}},
               /*fin=*/false)
      .Data(1, "hi", /*fin=*/!HasTrailers(), /*padding_length=*/10);
  if (HasTrailers()) {
    response.Headers(1, {{"my-weird-trailer", "has a value"}}, /*fin=*/true);
  }
  if (HasRstStream()) {
    response.RstStream(1, Http2ErrorCode::HTTP2_NO_ERROR);
  }
  const std::string stream_frames = response.Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  // HEADERS for stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "content-length", "2"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  // DATA frame with padding for stream 1
  EXPECT_CALL(visitor,
              OnFrameHeader(1, 2 + 10, DATA, HasTrailers() ? 0x8 : 0x9));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 2 + 10));
  EXPECT_CALL(visitor, OnDataForStream(1, "hi"));
  EXPECT_CALL(visitor, OnDataPaddingLength(1, 10));
  if (HasTrailers()) {
    // Trailers for stream 1
    EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
    EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
    EXPECT_CALL(visitor,
                OnHeaderForStream(1, "my-weird-trailer", "has a value"));
    EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  }
  // END_STREAM for stream 1
  EXPECT_CALL(visitor, OnEndStream(1));
  if (HasRstStream()) {
    EXPECT_CALL(visitor, OnFrameHeader(1, _, RST_STREAM, 0));
    EXPECT_CALL(visitor, OnRstStream(1, Http2ErrorCode::HTTP2_NO_ERROR));
    EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));
  }

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({
                                  SpdyFrameType::SETTINGS,
                              }));

  // Stream 1 is done in the request direction.
  if (!HasRstStream()) {
    visitor.AppendPayloadForStream(1, "final fragment");
  }
  visitor.SetEndData(1, true);
  adapter->ResumeStream(1);

  if (!HasRstStream()) {
    EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, END_STREAM_FLAG, 0));
    // The codec reports Stream 1 as closed.
    EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));
  }

  result = adapter->Send();
  EXPECT_EQ(0, result);
}

TEST(NgHttp2AdapterTest, ClientHandles204WithContent) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, nullptr, true, nullptr);
  ASSERT_GT(stream_id1, 0);

  const std::vector<Header> headers2 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/two"}});

  const int32_t stream_id2 =
      adapter->SubmitRequest(headers2, nullptr, true, nullptr);
  ASSERT_GT(stream_id2, stream_id1);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id2, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id2, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1, {{":status", "204"}, {"content-length", "2"}},
                   /*fin=*/false)
          .Data(1, "hi")
          .Headers(3, {{":status", "204"}}, /*fin=*/false)
          .Data(3, "hi")
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "204"));
  EXPECT_CALL(
      visitor,
      OnErrorDebug("Invalid HTTP header field was received: frame type: 1, "
                   "stream: 1, name: [content-length], value: [2]"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(1, Http2VisitorInterface::InvalidFrameError::kHttpHeader));
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":status", "204"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor, OnFrameHeader(3, _, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(3, 2));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(
```