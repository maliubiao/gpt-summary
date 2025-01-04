Response:
The user wants to understand the functionality of the provided C++ source code file.
This file appears to be a unit test for `OgHttp2Session`, which is likely an implementation of an HTTP/2 session adapter.

Here's a breakdown of the thought process to analyze the code:

1. **Identify the core class under test:** The file name and the `#include` statement clearly indicate that the tests are for the `OgHttp2Session` class.

2. **Recognize the testing framework:** The presence of `#include "quiche/common/platform/api/quiche_test.h"` and macros like `TEST` strongly suggest the use of Google Test (or a similar testing framework).

3. **Understand the test setup:**  Each `TEST` block sets up a test case. Common elements include:
    * Creating a `MockHttp2Visitor`: This suggests that `OgHttp2Session` interacts with a visitor pattern interface for handling HTTP/2 events. The `MockHttp2Visitor` allows for verifying the interactions.
    * Creating `OgHttp2Session` with different options: The `OgHttp2Session::Options` struct is used to configure the session (e.g., client or server perspective).

4. **Analyze individual tests:**  Each test focuses on specific aspects of `OgHttp2Session`'s behavior. For instance:
    * `ClientConstruction`: Verifies basic client session creation and initial state.
    * `ClientHandlesFrames`:  Tests how the client session processes incoming frames from the server. It uses `TestFrameSequence` to create realistic HTTP/2 frame sequences. `EXPECT_CALL` is used to assert that the `MockHttp2Visitor` receives the expected callbacks.
    * `ClientEnqueuesSettingsOnSend` and related tests: Focus on how the client session handles sending initial SETTINGS frames.
    * `ClientSubmitRequest`: Tests the client's ability to initiate requests.
    * `ServerConstruction` and `ServerHandlesFrames`: Mirror the client tests but for the server perspective.
    * `ServerSubmitResponse`: Tests the server's ability to send responses.

5. **Look for patterns and key functionalities:** The tests consistently check for things like:
    * Whether the session wants to read or write (`want_read()`, `want_write()`).
    * Flow control window sizes (`GetRemoteWindowSize()`, `GetReceiveWindowSize()`, `GetStreamReceiveWindowSize()`, `GetStreamSendWindowSize()`).
    * The highest received stream ID (`GetHighestReceivedStreamId()`).
    * HPACK dynamic table sizes (`GetHpackDecoderDynamicTableSize()`, `GetHpackEncoderDynamicTableSize()`).
    * User data associated with streams (`GetStreamUserData()`, `SetStreamUserData()`).
    * Correct serialization of frames when sending (`Send()` and checking `visitor.data()`).
    * Invocation of visitor methods for different frame types and events.

6. **Consider the relationship with JavaScript (as requested):**  HTTP/2 is the underlying protocol for many web interactions initiated by JavaScript. While this C++ code directly doesn't *run* in a JavaScript environment, it implements the protocol that JavaScript's `fetch` API or WebSocket API relies on.

7. **Think about logic and assumptions:** The tests often make assumptions about the order of events and the expected behavior of an HTTP/2 implementation. For example, the client sending a request involves sending HEADERS and potentially DATA frames.

8. **Identify potential user errors:**  The tests implicitly highlight potential user errors, such as not handling the `want_read()` and `want_write()` states correctly, or sending invalid frame sequences.

9. **Consider the debugging context:** The tests themselves provide a way to debug the `OgHttp2Session` implementation. By stepping through the tests and observing the interactions with the mock visitor, developers can understand the flow of execution.

10. **Synthesize the findings:**  Based on the analysis of the individual tests and the overall structure, summarize the key functionalities of the code. The focus is on handling different HTTP/2 frame types, managing session state (client/server, flow control), and interacting with the visitor interface.
This C++ source code file `oghttp2_session_test.cc` contains unit tests for the `OgHttp2Session` class in the Chromium network stack. `OgHttp2Session` appears to be an adapter that provides an interface to an underlying HTTP/2 implementation (likely the "oghttp2" part refers to the original or "vanilla" HTTP/2 implementation as opposed to QUIC's HTTP/3).

Here's a breakdown of its functionality based on the tests provided in this first part:

**Core Functionality being tested:**

* **Session Construction (Client & Server):**
    * Verifies the correct initialization of `OgHttp2Session` for both client and server perspectives.
    * Checks initial states like `want_read()`, `want_write()`, `GetRemoteWindowSize()`, `IsServerSession()`, `GetHighestReceivedStreamId()`, and `GetMaxOutboundConcurrentStreams()`.
    * Tests construction with custom `remote_max_concurrent_streams`.

* **Frame Handling (Client & Server):**
    * Tests how the session processes various incoming HTTP/2 frames (SETTINGS, PING, WINDOW_UPDATE, HEADERS, DATA, RST_STREAM, GOAWAY).
    * Uses `MockHttp2Visitor` to observe and verify the callbacks triggered by the session when processing frames (e.g., `OnFrameHeader`, `OnSettingsStart`, `OnPing`, `OnBeginHeadersForStream`, `OnDataForStream`, etc.).
    * Simulates receiving server and client prefaces.
    * Checks the impact of received frames on session state like `GetRemoteWindowSize()` and `GetHighestReceivedStreamId()`.
    * Verifies interaction with HPACK decoder (`GetHpackDecoderDynamicTableSize()`).

* **Submitting Requests (Client):**
    * Tests the `SubmitRequest` method for initiating HTTP/2 requests.
    * Checks the creation of new stream IDs.
    * Verifies that the appropriate HEADERS and DATA frames are enqueued for sending.
    * Examines the `want_write()` state after submitting requests.
    * Checks the management of stream-level user data using `GetStreamUserData()` and `SetStreamUserData()`.
    * Tests sending requests with and without a request body.
    * Simulates scenarios with large request payloads and checks if they fit within the `MAX_FRAME_SIZE`.
    * Tests scenarios where the request body source is read-blocked and how `ResumeStream()` is used.
    * Simulates write-blocking scenarios and verifies that frames are not sent until writing is possible.
    * Verifies interaction with HPACK encoder (`GetHpackEncoderDynamicTableSize()`).
    * Checks the `GetStreamSendWindowSize()` after sending data.

* **Sending Frames (Client & Server):**
    * Tests the `Send()` method for serializing and sending queued frames.
    * Verifies that initial SETTINGS frames are sent by both clients and servers.
    * Ensures that initial SETTINGS are sent before other frame types when `EnqueueFrame()` is called.
    * Checks that only one initial SETTINGS frame is sent.
    * Verifies the correct order of sent frames (e.g., SETTINGS before other frames).

* **Submitting Responses (Server):** (Potentially covered, though less detailed in this part)
    * Implied through the server-side frame handling tests, the session prepares to send responses based on received requests.

**Relationship with JavaScript:**

While this C++ code doesn't directly execute JavaScript, it's a crucial part of the network stack that enables HTTP/2 communication initiated by JavaScript code in a web browser or Node.js environment.

* **`fetch()` API:** When JavaScript uses the `fetch()` API to make a network request to an HTTP/2 server, the browser's network stack, including components like `OgHttp2Session`, handles the underlying HTTP/2 protocol negotiation, frame construction, and transmission.
* **WebSockets:** If a WebSocket connection is established over HTTP/2,  `OgHttp2Session` would manage the HTTP/2 connection on which the WebSocket frames are multiplexed.

**Example:**

Imagine a JavaScript `fetch()` call like this:

```javascript
fetch('https://example.com/data', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ key: 'value' })
})
.then(response => response.json())
.then(data => console.log(data));
```

When this code executes, the browser's network stack will:

1. **Establish an HTTP/2 connection** with `example.com` (if one doesn't exist).
2. **Create an HTTP/2 stream** for this request.
3. **Use a component like `OgHttp2Session` to:**
    * Construct and send a HEADERS frame containing the HTTP method (`POST`), URL path (`/data`), headers (`Content-Type`, etc.).
    * Construct and send DATA frames containing the JSON request body.
4. **On the server side, a corresponding `OgHttp2Session` instance will:**
    * Receive and process the HEADERS and DATA frames.
    * Trigger callbacks to the server application to handle the request.
5. **The server application will then generate a response.**
6. **The server's `OgHttp2Session` will:**
    * Construct and send a HEADERS frame containing the HTTP status code and response headers.
    * Construct and send DATA frames containing the response body.
7. **The client's `OgHttp2Session` will:**
    * Receive and process the response HEADERS and DATA frames.
    * Trigger callbacks to the browser's rendering engine, eventually resolving the JavaScript `Promise` returned by `fetch()`.

**Logical Reasoning (with assumptions):**

**Assumption:** A client wants to send a POST request with a small JSON payload.

**Input:**

* Client `OgHttp2Session` is in a state where it can send data (`want_write()` is true).
* The `SubmitRequest` method is called with headers and a `VisitorDataSource` providing the JSON payload:
  ```c++
  session.SubmitRequest(
      ToHeaders({{":method", "POST"},
                 {":scheme", "https"},
                 {":authority", "example.com"},
                 {":path", "/api/resource"},
                 {"content-type", "application/json"}}),
      std::make_unique<VisitorDataSource>(visitor, stream_id, "{\"key\":\"value\"}"),
      true, nullptr);
  ```

**Output (observed via `MockHttp2Visitor` callbacks when `Send()` is called):**

* `OnBeforeFrameSent(HEADERS, stream_id, _, 0x4)`:  Indicates a HEADERS frame is about to be sent for the new stream.
* `OnFrameSent(HEADERS, stream_id, _, 0x4, 0)`:  Verifies the HEADERS frame was sent.
* `OnBeforeFrameSent(DATA, stream_id, _, 0x1)`: Indicates a DATA frame with the end-of-stream flag is about to be sent.
* `OnFrameSent(DATA, stream_id, _, 0x1, 0)`: Verifies the DATA frame containing `{"key":"value"}` was sent with the FIN flag set.

**User/Programming Common Usage Errors:**

* **Not calling `Send()` when `want_write()` is true:**  The session might have frames queued to send, but if `Send()` is not called, the data won't be transmitted. This can lead to stalled communication.
    ```c++
    // Client submits a request
    session.SubmitRequest(...);
    EXPECT_TRUE(session.want_write());
    // Oops, forgot to call session.Send();
    ```

* **Processing incoming data without checking `want_read()`:** If the session isn't expecting more data, processing it might lead to unexpected behavior or errors.
    ```c++
    // ... server session ...
    std::string received_data = "...";
    // Incorrectly processing data without checking if the session wants to read
    session.ProcessBytes(received_data);
    ```

* **Submitting data on a stream that is not in a sendable state:** Trying to send data after the stream has been closed or reset will likely result in errors.

* **Incorrectly managing flow control:** Sending more data than the peer's advertised window size can lead to flow control violations and connection problems.

**User Operation Steps to Reach Here (Debugging Context):**

Let's imagine a scenario where a developer is debugging an issue with a client application making an HTTP/2 request.

1. **The user reports an issue:**  "My application is hanging when trying to upload a large file."
2. **The developer suspects an issue with HTTP/2 frame handling:**  They decide to investigate the network stack.
3. **They set breakpoints or logging in the code that initiates the `fetch()` request or equivalent network call in their application.**
4. **They trace the execution down into the Chromium network stack.**
5. **They might find themselves in code related to creating or using an `OgHttp2Session` instance.**
6. **To understand how frames are being constructed and sent, they might look at the unit tests for `OgHttp2Session` to see examples of how the class is intended to be used.**
7. **They might run these unit tests themselves to confirm the basic functionality of `OgHttp2Session` is correct.**
8. **Using a network inspection tool (like Chrome DevTools or Wireshark), they can examine the actual HTTP/2 frames being exchanged to compare with what they expect based on the `OgHttp2Session` logic and its unit tests.**
9. **If they suspect a bug within `OgHttp2Session`, they might step through the `ProcessBytes()` and `Send()` methods, observing the state of the session and the callbacks to the `Http2Visitor`.**
10. **The unit tests, like the ones in this file, provide a controlled environment to isolate and test specific aspects of `OgHttp2Session`'s behavior, making debugging more manageable.**  They can add logging or assertions within the tests to pinpoint the source of the issue.

**Summary of Part 1 Functionality:**

This first part of the `oghttp2_session_test.cc` file primarily focuses on testing the **fundamental setup and basic frame handling capabilities** of the `OgHttp2Session` class for both client and server roles. It verifies that sessions are constructed correctly, can process various standard HTTP/2 frames, and initiate client requests, including handling different payload sizes and read/write blocking scenarios. It also confirms the correct behavior of sending initial SETTINGS frames.

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/oghttp2_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
#include "quiche/http2/adapter/oghttp2_session.h"

#include <memory>
#include <string>
#include <utility>

#include "quiche/http2/adapter/mock_http2_visitor.h"
#include "quiche/http2/adapter/test_frame_sequence.h"
#include "quiche/http2/adapter/test_utils.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace http2 {
namespace adapter {
namespace test {
namespace {

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
};

}  // namespace

TEST(OgHttp2SessionTest, ClientConstruction) {
  testing::StrictMock<MockHttp2Visitor> visitor;
  OgHttp2Session::Options options;
  options.perspective = Perspective::kClient;
  OgHttp2Session session(visitor, options);
  EXPECT_TRUE(session.want_read());
  EXPECT_FALSE(session.want_write());
  EXPECT_EQ(session.GetRemoteWindowSize(), kInitialFlowControlWindowSize);
  EXPECT_FALSE(session.IsServerSession());
  EXPECT_EQ(0, session.GetHighestReceivedStreamId());
  EXPECT_EQ(100u, session.GetMaxOutboundConcurrentStreams());
}

TEST(OgHttp2SessionTest, ClientConstructionWithMaxStreams) {
  testing::StrictMock<MockHttp2Visitor> visitor;
  OgHttp2Session::Options options;
  options.perspective = Perspective::kClient;
  options.remote_max_concurrent_streams = 200u;
  OgHttp2Session session(visitor, options);
  EXPECT_EQ(200u, session.GetMaxOutboundConcurrentStreams());
}

TEST(OgHttp2SessionTest, ClientHandlesFrames) {
  TestVisitor visitor;
  OgHttp2Session::Options options;
  options.perspective = Perspective::kClient;
  OgHttp2Session session(visitor, options);

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

  const int64_t initial_result = session.ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), static_cast<size_t>(initial_result));

  EXPECT_EQ(session.GetRemoteWindowSize(),
            kInitialFlowControlWindowSize + 1000);
  EXPECT_EQ(0, session.GetHighestReceivedStreamId());

  // Connection has not yet received any data.
  EXPECT_EQ(kInitialFlowControlWindowSize, session.GetReceiveWindowSize());

  EXPECT_EQ(0, session.GetHpackDecoderDynamicTableSize());

  // Submit a request to ensure the first stream is created.
  const char* kSentinel1 = "arbitrary pointer 1";
  visitor.AppendPayloadForStream(1, "This is an example request body.");
  visitor.SetEndData(1, true);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);
  int stream_id = session.SubmitRequest(
      ToHeaders({{":method", "POST"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}}),
      std::move(body1), false, const_cast<char*>(kSentinel1));
  ASSERT_EQ(stream_id, 1);

  // Submit another request to ensure the next stream is created.
  int stream_id2 =
      session.SubmitRequest(ToHeaders({{":method", "GET"},
                                       {":scheme", "http"},
                                       {":authority", "example.com"},
                                       {":path", "/this/is/request/two"}}),
                            nullptr, true, nullptr);
  EXPECT_EQ(stream_id2, 3);

  const std::string stream_frames =
      TestFrameSequence()
          .Headers(stream_id,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Data(stream_id, "This is the response body.")
          .RstStream(stream_id2, Http2ErrorCode::INTERNAL_ERROR)
          .GoAway(5, Http2ErrorCode::ENHANCE_YOUR_CALM, "calm down!!")
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(stream_id, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(stream_id));
  EXPECT_CALL(visitor, OnHeaderForStream(stream_id, ":status", "200"));
  EXPECT_CALL(visitor,
              OnHeaderForStream(stream_id, "server", "my-fake-server"));
  EXPECT_CALL(visitor, OnHeaderForStream(stream_id, "date",
                                         "Tue, 6 Apr 2021 12:54:01 GMT"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(stream_id));
  EXPECT_CALL(visitor, OnFrameHeader(stream_id, 26, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(stream_id, 26));
  EXPECT_CALL(visitor,
              OnDataForStream(stream_id, "This is the response body."));
  EXPECT_CALL(visitor, OnFrameHeader(stream_id2, 4, RST_STREAM, 0));
  EXPECT_CALL(visitor, OnRstStream(stream_id2, Http2ErrorCode::INTERNAL_ERROR));
  EXPECT_CALL(visitor,
              OnCloseStream(stream_id2, Http2ErrorCode::INTERNAL_ERROR));
  EXPECT_CALL(visitor, OnFrameHeader(0, 19, GOAWAY, 0));
  EXPECT_CALL(visitor, OnGoAway(5, Http2ErrorCode::ENHANCE_YOUR_CALM, ""));
  const int64_t stream_result = session.ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));
  EXPECT_EQ(stream_id2, session.GetHighestReceivedStreamId());

  // The first stream is active and has received some data.
  EXPECT_GT(kInitialFlowControlWindowSize,
            session.GetStreamReceiveWindowSize(stream_id));
  // Connection receive window is equivalent to the first stream's.
  EXPECT_EQ(session.GetReceiveWindowSize(),
            session.GetStreamReceiveWindowSize(stream_id));
  // Receive window upper bound is still the initial value.
  EXPECT_EQ(kInitialFlowControlWindowSize,
            session.GetStreamReceiveWindowLimit(stream_id));

  EXPECT_GT(session.GetHpackDecoderDynamicTableSize(), 0);
}

// Verifies that a client session enqueues initial SETTINGS if Send() is called
// before any frames are explicitly queued.
TEST(OgHttp2SessionTest, ClientEnqueuesSettingsOnSend) {
  TestVisitor visitor;
  OgHttp2Session::Options options;
  options.perspective = Perspective::kClient;
  OgHttp2Session session(visitor, options);
  EXPECT_FALSE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));

  int result = session.Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized, EqualsFrames({SpdyFrameType::SETTINGS}));
}

// Verifies that a client session enqueues initial SETTINGS before whatever
// frame type is passed to the first invocation of EnqueueFrame().
TEST(OgHttp2SessionTest, ClientEnqueuesSettingsBeforeOtherFrame) {
  TestVisitor visitor;
  OgHttp2Session::Options options;
  options.perspective = Perspective::kClient;
  OgHttp2Session session(visitor, options);
  EXPECT_FALSE(session.want_write());
  session.EnqueueFrame(std::make_unique<spdy::SpdyPingIR>(42));
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(PING, 0, 8, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(PING, 0, 8, 0x0, 0));

  int result = session.Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::PING}));
}

// Verifies that if the first call to EnqueueFrame() passes a SETTINGS frame,
// the client session will not enqueue an additional SETTINGS frame.
TEST(OgHttp2SessionTest, ClientEnqueuesSettingsOnce) {
  TestVisitor visitor;
  OgHttp2Session::Options options;
  options.perspective = Perspective::kClient;
  OgHttp2Session session(visitor, options);
  EXPECT_FALSE(session.want_write());
  session.EnqueueFrame(std::make_unique<spdy::SpdySettingsIR>());
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));

  int result = session.Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized, EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2SessionTest, ClientSubmitRequest) {
  TestVisitor visitor;
  OgHttp2Session::Options options;
  options.perspective = Perspective::kClient;
  OgHttp2Session session(visitor, options);

  EXPECT_FALSE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));

  // Even though the user has not queued any frames for the session, it should
  // still send the connection preface.
  int result = session.Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  // Initial SETTINGS.
  EXPECT_THAT(serialized, EqualsFrames({SpdyFrameType::SETTINGS}));
  visitor.Clear();

  const std::string initial_frames =
      TestFrameSequence().ServerPreface().Serialize();
  testing::InSequence s;

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t initial_result = session.ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), static_cast<size_t>(initial_result));

  // Session will want to write a SETTINGS ack.
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  result = session.Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
  visitor.Clear();

  EXPECT_EQ(0, session.GetHpackEncoderDynamicTableSize());

  const char* kSentinel1 = "arbitrary pointer 1";
  visitor.AppendPayloadForStream(1, "This is an example request body.");
  visitor.SetEndData(1, true);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);
  int stream_id = session.SubmitRequest(
      ToHeaders({{":method", "POST"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}}),
      std::move(body1), false, const_cast<char*>(kSentinel1));
  ASSERT_EQ(stream_id, 1);
  EXPECT_TRUE(session.want_write());
  EXPECT_EQ(kSentinel1, session.GetStreamUserData(stream_id));

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, _, 0x1, 0));

  result = session.Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::HEADERS,
                                            spdy::SpdyFrameType::DATA}));
  visitor.Clear();
  EXPECT_FALSE(session.want_write());

  // Some data was sent, so the remaining send window size should be less than
  // the default.
  EXPECT_LT(session.GetStreamSendWindowSize(stream_id),
            kInitialFlowControlWindowSize);
  EXPECT_GT(session.GetStreamSendWindowSize(stream_id), 0);
  // Send window for a nonexistent stream is not available.
  EXPECT_EQ(-1, session.GetStreamSendWindowSize(stream_id + 2));

  EXPECT_GT(session.GetHpackEncoderDynamicTableSize(), 0);

  stream_id =
      session.SubmitRequest(ToHeaders({{":method", "POST"},
                                       {":scheme", "http"},
                                       {":authority", "example.com"},
                                       {":path", "/this/is/request/two"}}),
                            nullptr, true, nullptr);
  EXPECT_GT(stream_id, 0);
  EXPECT_TRUE(session.want_write());
  const char* kSentinel2 = "arbitrary pointer 2";
  EXPECT_EQ(nullptr, session.GetStreamUserData(stream_id));
  session.SetStreamUserData(stream_id, const_cast<char*>(kSentinel2));
  EXPECT_EQ(kSentinel2, session.GetStreamUserData(stream_id));

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x5, 0));

  result = session.Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::HEADERS}));

  // No data was sent (just HEADERS), so the remaining send window size should
  // still be the default.
  EXPECT_EQ(session.GetStreamSendWindowSize(stream_id),
            kInitialFlowControlWindowSize);
}

TEST(OgHttp2SessionTest, ClientSubmitRequestWithLargePayload) {
  TestVisitor visitor;
  OgHttp2Session::Options options;
  options.perspective = Perspective::kClient;
  OgHttp2Session session(visitor, options);

  EXPECT_FALSE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));

  // Even though the user has not queued any frames for the session, it should
  // still send the connection preface.
  int result = session.Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  // Initial SETTINGS.
  EXPECT_THAT(serialized, EqualsFrames({SpdyFrameType::SETTINGS}));
  visitor.Clear();

  const std::string initial_frames =
      TestFrameSequence()
          .ServerPreface(
              {Http2Setting{Http2KnownSettingsId::MAX_FRAME_SIZE, 32768u}})
          .Serialize();
  testing::InSequence s;

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSetting(Http2Setting{
                           Http2KnownSettingsId::MAX_FRAME_SIZE, 32768u}));
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t initial_result = session.ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), static_cast<size_t>(initial_result));

  // Session will want to write a SETTINGS ack.
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  result = session.Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
  visitor.Clear();

  visitor.AppendPayloadForStream(1, std::string(20000, 'a'));
  visitor.SetEndData(1, true);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);
  int stream_id =
      session.SubmitRequest(ToHeaders({{":method", "POST"},
                                       {":scheme", "http"},
                                       {":authority", "example.com"},
                                       {":path", "/this/is/request/one"}}),
                            std::move(body1), false, nullptr);
  ASSERT_EQ(stream_id, 1);
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x4, 0));
  // Single DATA frame with fin, indicating all 20k bytes fit in one frame.
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, _, 0x1, 0));

  result = session.Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::HEADERS,
                                            spdy::SpdyFrameType::DATA}));
  visitor.Clear();
  EXPECT_FALSE(session.want_write());
}

// This test exercises the case where the client request body source is read
// blocked.
TEST(OgHttp2SessionTest, ClientSubmitRequestWithReadBlock) {
  TestVisitor visitor;
  OgHttp2Session::Options options;
  options.perspective = Perspective::kClient;
  OgHttp2Session session(visitor, options);
  EXPECT_FALSE(session.want_write());

  const char* kSentinel1 = "arbitrary pointer 1";
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);
  int stream_id = session.SubmitRequest(
      ToHeaders({{":method", "POST"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}}),
      std::move(body1), false, const_cast<char*>(kSentinel1));
  EXPECT_GT(stream_id, 0);
  EXPECT_TRUE(session.want_write());
  EXPECT_EQ(kSentinel1, session.GetStreamUserData(stream_id));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x4, 0));

  int result = session.Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS}));
  // No data frame, as body1 was read blocked.
  visitor.Clear();
  EXPECT_FALSE(session.want_write());

  visitor.AppendPayloadForStream(1, "This is an example request body.");
  visitor.SetEndData(1, true);
  EXPECT_TRUE(session.ResumeStream(stream_id));
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, _, 0x1, 0));

  result = session.Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::DATA}));
  EXPECT_FALSE(session.want_write());

  // Stream data is done, so this stream cannot be resumed.
  EXPECT_FALSE(session.ResumeStream(stream_id));
  EXPECT_FALSE(session.want_write());
}

// This test exercises the case where the client request body source is read
// blocked, then ends with an empty DATA frame.
TEST(OgHttp2SessionTest, ClientSubmitRequestEmptyDataWithFin) {
  TestVisitor visitor;
  OgHttp2Session::Options options;
  options.perspective = Perspective::kClient;
  OgHttp2Session session(visitor, options);
  EXPECT_FALSE(session.want_write());

  const char* kSentinel1 = "arbitrary pointer 1";
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);
  int stream_id = session.SubmitRequest(
      ToHeaders({{":method", "POST"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}}),
      std::move(body1), false, const_cast<char*>(kSentinel1));
  EXPECT_GT(stream_id, 0);
  EXPECT_TRUE(session.want_write());
  EXPECT_EQ(kSentinel1, session.GetStreamUserData(stream_id));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x4, 0));

  int result = session.Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS}));
  // No data frame, as body1 was read blocked.
  visitor.Clear();
  EXPECT_FALSE(session.want_write());

  visitor.SetEndData(1, true);
  EXPECT_TRUE(session.ResumeStream(stream_id));
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, 0, 0x1, 0));

  result = session.Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::DATA}));
  EXPECT_FALSE(session.want_write());

  // Stream data is done, so this stream cannot be resumed.
  EXPECT_FALSE(session.ResumeStream(stream_id));
  EXPECT_FALSE(session.want_write());
}

// This test exercises the case where the connection to the peer is write
// blocked.
TEST(OgHttp2SessionTest, ClientSubmitRequestWithWriteBlock) {
  TestVisitor visitor;
  OgHttp2Session::Options options;
  options.perspective = Perspective::kClient;
  OgHttp2Session session(visitor, options);
  EXPECT_FALSE(session.want_write());

  const char* kSentinel1 = "arbitrary pointer 1";
  visitor.AppendPayloadForStream(1, "This is an example request body.");
  visitor.SetEndData(1, true);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);
  int stream_id = session.SubmitRequest(
      ToHeaders({{":method", "POST"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}}),
      std::move(body1), false, const_cast<char*>(kSentinel1));
  EXPECT_GT(stream_id, 0);
  EXPECT_TRUE(session.want_write());
  EXPECT_EQ(kSentinel1, session.GetStreamUserData(stream_id));
  visitor.set_is_write_blocked(true);
  int result = session.Send();
  EXPECT_EQ(0, result);

  EXPECT_THAT(visitor.data(), testing::IsEmpty());
  EXPECT_TRUE(session.want_write());
  visitor.set_is_write_blocked(false);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, _, 0x1, 0));

  result = session.Send();
  EXPECT_EQ(0, result);

  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS,
                            SpdyFrameType::DATA}));
  EXPECT_FALSE(session.want_write());
}

TEST(OgHttp2SessionTest, ServerConstruction) {
  testing::StrictMock<MockHttp2Visitor> visitor;
  OgHttp2Session::Options options;
  options.perspective = Perspective::kServer;
  OgHttp2Session session(visitor, options);
  EXPECT_TRUE(session.want_read());
  EXPECT_FALSE(session.want_write());
  EXPECT_EQ(session.GetRemoteWindowSize(), kInitialFlowControlWindowSize);
  EXPECT_TRUE(session.IsServerSession());
  EXPECT_EQ(0, session.GetHighestReceivedStreamId());
}

TEST(OgHttp2SessionTest, ServerHandlesFrames) {
  TestVisitor visitor;
  OgHttp2Session::Options options;
  options.perspective = Perspective::kServer;
  OgHttp2Session session(visitor, options);

  EXPECT_EQ(0, session.GetHpackDecoderDynamicTableSize());

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Ping(42)
                                 .WindowUpdate(0, 1000)
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/false)
                                 .WindowUpdate(1, 2000)
                                 .Data(1, "This is the request body.")
                                 .Headers(3,
                                          {{":method", "GET"},
                                           {":scheme", "http"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/two"}},
                                          /*fin=*/true)
                                 .RstStream(3, Http2ErrorCode::CANCEL)
                                 .Ping(47)
                                 .Serialize();
  testing::InSequence s;

  const char* kSentinel1 = "arbitrary pointer 1";

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(0, 8, PING, 0));
  EXPECT_CALL(visitor, OnPing(42, false));
  EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(0, 1000));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1))
      .WillOnce(testing::InvokeWithoutArgs([&session, kSentinel1]() {
        session.SetStreamUserData(1, const_cast<char*>(kSentinel1));
        return true;
      }));
  EXPECT_CALL(visitor, OnFrameHeader(1, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(1, 2000));
  EXPECT_CALL(visitor, OnFrameHeader(1, 25, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 25));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the request body."));
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":scheme", "http"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":path", "/this/is/request/two"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor, OnEndStream(3));
  EXPECT_CALL(visitor, OnFrameHeader(3, 4, RST_STREAM, 0));
  EXPECT_CALL(visitor, OnRstStream(3, Http2ErrorCode::CANCEL));
  EXPECT_CALL(visitor, OnCloseStream(3, Http2ErrorCode::CANCEL));
  EXPECT_CALL(visitor, OnFrameHeader(0, 8, PING, 0));
  EXPECT_CALL(visitor, OnPing(47, false));

  const int64_t result = session.ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  EXPECT_EQ(kSentinel1, session.GetStreamUserData(1));

  // The first stream is active and has received some data.
  EXPECT_GT(kInitialFlowControlWindowSize,
            session.GetStreamReceiveWindowSize(1));
  // Connection receive window is equivalent to the first stream's.
  EXPECT_EQ(session.GetReceiveWindowSize(),
            session.GetStreamReceiveWindowSize(1));
  // Receive window upper bound is still the initial value.
  EXPECT_EQ(kInitialFlowControlWindowSize,
            session.GetStreamReceiveWindowLimit(1));

  EXPECT_GT(session.GetHpackDecoderDynamicTableSize(), 0);

  // It should no longer be possible to set user data on a closed stream.
  const char* kSentinel3 = "another arbitrary pointer";
  session.SetStreamUserData(3, const_cast<char*>(kSentinel3));
  EXPECT_EQ(nullptr, session.GetStreamUserData(3));

  EXPECT_EQ(session.GetRemoteWindowSize(),
            kInitialFlowControlWindowSize + 1000);
  EXPECT_EQ(3, session.GetHighestReceivedStreamId());

  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(PING, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(PING, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(PING, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(PING, 0, _, 0x1, 0));

  // Some bytes should have been serialized.
  int send_result = session.Send();
  EXPECT_EQ(0, send_result);
  // Initial SETTINGS, SETTINGS ack, and PING acks (for PING IDs 42 and 47).
  EXPECT_THAT(visitor.data(),
              EqualsFrames(
                  {spdy::SpdyFrameType::SETTINGS, spdy::SpdyFrameType::SETTINGS,
                   spdy::SpdyFrameType::PING, spdy::SpdyFrameType::PING}));
}

// Verifies that a server session enqueues initial SETTINGS before whatever
// frame type is passed to the first invocation of EnqueueFrame().
TEST(OgHttp2SessionTest, ServerEnqueuesSettingsBeforeOtherFrame) {
  TestVisitor visitor;
  OgHttp2Session::Options options;
  options.perspective = Perspective::kServer;
  OgHttp2Session session(visitor, options);
  EXPECT_FALSE(session.want_write());
  session.EnqueueFrame(std::make_unique<spdy::SpdyPingIR>(42));
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(PING, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(PING, 0, _, 0x0, 0));

  int result = session.Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::PING}));
}

// Verifies that if the first call to EnqueueFrame() passes a SETTINGS frame,
// the server session will not enqueue an additional SETTINGS frame.
TEST(OgHttp2SessionTest, ServerEnqueuesSettingsOnce) {
  TestVisitor visitor;
  OgHttp2Session::Options options;
  options.perspective = Perspective::kServer;
  OgHttp2Session session(visitor, options);
  EXPECT_FALSE(session.want_write());
  session.EnqueueFrame(std::make_unique<spdy::SpdySettingsIR>());
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));

  int result = session.Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2SessionTest, ServerSubmitResponse) {
  TestVisitor visitor;
  OgHttp2Session::Options options;
  options.perspective = Perspective::kServer;
  OgHttp2Session session(visitor, options);

  EXPECT_FALSE(session.want_write());

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/true)
                                 .Serialize();
  testing::InSequence s;

  const char* kSentinel1 = "arbitrary pointer 1";

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1))
      .WillOnce(testing::InvokeWithoutArgs([&session, kSentinel1]() {
        session.SetStreamUserData(1, const_cast<char*>(kSentinel1));
        return true;
      }));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t result = session.ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  EXPECT_EQ(1, session.GetHighestReceivedStreamId());

  EXPECT_EQ(0, session.GetHpackEncoderDynamicTableSize());

  // Server will want to send initial SETTINGS, and a SETTINGS ack.
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(
"""


```