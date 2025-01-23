Response:
The user wants a summary of the provided C++ code, specifically focusing on its functionality within the Chromium networking stack. I need to identify the main actions performed by this code and explain its purpose. Since this is part 8 of 11, I should also consider what aspects of the `NgHttp2Adapter` are likely being tested in this section based on the function names and the overall structure of the tests.

Key observations from the code:

1. **Testing Focus:** The code consists of several test cases using the Google Test framework. Each test case focuses on a specific interaction or scenario involving the `NgHttp2Adapter`.

2. **`NgHttp2Adapter` Role:** The `NgHttp2Adapter` appears to be a component that adapts the `nghttp2` library for use within Chromium's HTTP/2 implementation. It handles the translation between Chromium's internal HTTP/2 representation and `nghttp2`'s API.

3. **`TestVisitor`:**  The `TestVisitor` class seems to act as a mock or spy object. It intercepts calls from the `NgHttp2Adapter` and allows the tests to verify the adapter's behavior, such as which frames are sent or received and the order of events.

4. **Frame Processing:** The tests extensively use `adapter->ProcessBytes()` to simulate receiving HTTP/2 frames from the network.

5. **Frame Sending:** The tests use `adapter->Send()` to trigger the sending of HTTP/2 frames.

6. **Scenarios Tested:** The tests cover a variety of scenarios:
    - Server sending a reset stream.
    - Server initiating a shutdown.
    - Server sending trailers (headers after the body).
    - Client sending continuation frames (for long headers).
    - Client sending metadata frames.
    - Handling repeated header names.
    - Server responding to requests with trailers.
    - Handling errors during response submission.
    - Handling complete and incomplete requests.
    - Handling multiple `Content-Length` headers (error case).
    - Attempting to send invalid trailers.
    - Handling new streams with IDs below a certain watermark.

7. **JavaScript Relevance:**  While the code itself is C++, the functionality it tests is directly related to the underlying HTTP/2 protocol, which is fundamental to web communication. JavaScript code running in a browser relies on a correctly functioning HTTP/2 implementation to fetch resources and interact with servers.

8. **User Errors:**  The tests implicitly cover potential user errors in server-side code, such as submitting invalid trailers or mishandling request bodies.

9. **Debugging:** The test structure provides clear steps to reproduce scenarios and inspect the behavior of the adapter.

**Hypothesized Input and Output (Example based on `ServerSendsShutdown`):**

* **Input:** A client preface followed by a HEADERS frame for stream 1.
* **Adapter Processing:** The adapter processes these bytes, calling methods on the `TestVisitor` to notify about received frames and headers.
* **Adapter Action:** `adapter->SubmitShutdownNotice()` is called, initiating a server shutdown.
* **Output:** When `adapter->Send()` is called, the adapter generates a SETTINGS frame (ACK) and a GOAWAY frame.

**Common Usage Errors:** The tests highlight potential server-side errors like sending invalid trailers or mishandling duplicate headers. These would typically manifest as server-side bugs.

**User Operations and Debugging:** A user might encounter issues tested here by:
    - Loading a web page that triggers a server shutdown during the connection.
    - Interacting with a server that sends trailers.
    - Making requests that have very large headers requiring continuation frames.

To debug, one would:
    1. **Network Inspection:** Use browser developer tools to inspect the raw HTTP/2 frames being exchanged.
    2. **Server-Side Logging:** Examine server logs for errors related to HTTP/2 frame processing.
    3. **Chromium Internals:** In deeper debugging scenarios, one might examine Chromium's netlog or step through the C++ code (like the file being analyzed) to understand how frames are being processed.

Based on these observations, I can now formulate the summary.Based on the provided code snippet and the file path `net/third_party/quiche/src/quiche/http2/adapter/nghttp2_adapter_test.cc`, this is a **test file for the `NgHttp2Adapter` class** within Chromium's network stack. The `NgHttp2Adapter` acts as an interface or adapter between Chromium's internal HTTP/2 implementation and the `nghttp2` library, a popular C library for handling HTTP/2 framing and state management.

Here's a breakdown of the functionalities demonstrated in this specific section of the test file:

**Core Functionalities Being Tested (Part 8):**

* **Server-Initiated Actions:**
    * **Sending RST_STREAM:** Tests how the adapter handles sending a `RST_STREAM` frame to abruptly close a stream, simulating a server-side cancellation. This includes verifying that associated resources (like data sources) are cleaned up and that further data intended for that stream is dropped.
    * **Sending Shutdown (GOAWAY):** Checks the adapter's behavior when the server decides to shut down the HTTP/2 connection gracefully. It verifies that the adapter sends the necessary `SETTINGS` (ACK) and `GOAWAY` frames.
    * **Sending Trailers:** Examines how the adapter handles sending trailing headers after the main response body. This verifies the correct framing and the interaction with the data source.
* **Client-Initiated Actions and Handling:**
    * **Sending Continuation Frames:** Tests the adapter's ability to correctly process headers that are too large to fit in a single `HEADERS` frame and are split into multiple `CONTINUATION` frames.
    * **Sending Metadata Frames (with Continuation):** Verifies the processing of custom `METADATA` frames, including scenarios where they are split across multiple frames using continuation.
    * **Sending Repeated Header Names:** Checks how the adapter handles requests with multiple headers having the same name (e.g., multiple `Accept` headers).
    * **Sending Trailers After Request Body:** Tests the scenario where the client sends trailing headers after the request body.
* **Error Handling and Edge Cases:**
    * **Server Submitting Response with Data Source Error:** Simulates a scenario where the server attempts to send a response but encounters an error while reading the data source. It verifies that the adapter sends a `RST_STREAM` frame to indicate the error.
    * **Handling Complete and Incomplete Requests with Server Response:** Tests how the adapter behaves when a server responds to a complete request (with `FIN` flag) versus an incomplete request.
    * **Handling Multiple `Content-Length` Headers:** Checks how the adapter reacts when receiving requests with multiple `Content-Length` headers, which is an HTTP/2 error condition.
    * **Server Sending Invalid Trailers:** Likely testing a scenario where the server attempts to send trailers that are not permitted or are incorrectly formatted.
    * **Handling New Streams Below a Watermark:** Tests the adapter's behavior when receiving a new stream ID that is lower than the expected next stream ID, which could indicate an error or out-of-order frame.

**Relationship to JavaScript:**

While this code is in C++, it directly underpins the HTTP/2 functionality that JavaScript code in a web browser relies on.

* **Fetching Resources:** When JavaScript uses `fetch()` or `XMLHttpRequest` to request resources, and the connection uses HTTP/2, this adapter is responsible for handling the underlying HTTP/2 framing. The parsing of headers, data streams, and trailers, as tested here, directly impacts how the browser interprets the server's response and makes it available to the JavaScript code.
* **Server-Sent Events (SSE) and WebSockets (over HTTP/2):** These technologies, often used with JavaScript, rely on persistent HTTP/2 connections. The adapter's ability to handle stream management, resets, and connection shutdown is crucial for their proper functioning.

**Examples with Assumptions and Logic:**

**Example 1: Server Sends RST_STREAM**

* **Assumption:** The server wants to cancel a request on stream ID 1.
* **Input (Simulated):** The `ProcessBytes` method is fed a raw HTTP/2 `RST_STREAM` frame targeting stream 1 with error code `CANCEL`.
* **Expected Output:**
    * The `TestVisitor` should receive calls to `OnFrameHeader`, `OnRstStream`, and `OnCloseStream` with the correct stream ID and error code.
    * Any data sources associated with stream 1 should be released (`adapter->sources_size()` should be 0).
    * Attempts to send further data for stream 1 should be dropped (verified by `EXPECT_CALL`s with `.Times(0)`).

**Example 2: Client Sends Continuation**

* **Assumption:** A client is sending a request with headers that exceed the maximum frame size.
* **Input (Simulated):** The `ProcessBytes` method is fed a `HEADERS` frame for stream 1, immediately followed by a `CONTINUATION` frame for the same stream.
* **Expected Output:**
    * The `TestVisitor` should receive `OnFrameHeader` and `OnBeginHeadersForStream` for the initial `HEADERS` frame.
    * It should then receive another `OnFrameHeader` for the `CONTINUATION` frame.
    * Importantly, the `OnHeaderForStream` calls should accumulate the headers from both frames, resulting in the complete set of headers being processed.

**User or Programming Common Usage Errors (and how these tests relate):**

* **Server sends trailers before the end of the body:** The tests involving trailers ensure the adapter correctly handles the framing and sequencing of headers, data, and trailers. A server sending them out of order would likely be flagged by the adapter or `nghttp2`.
* **Incorrectly setting the FIN flag:** The tests cover scenarios with and without the `FIN` flag, ensuring the adapter correctly interprets the end of a stream. A common error is not setting the `FIN` flag when the server has finished sending data, which can lead to hanging connections.
* **Sending invalid header names or values in trailers:** The test related to "Server Sends Invalid Trailers" directly addresses this. The adapter should ideally reject or handle such invalid trailers gracefully.
* **Client sending excessively large headers without using continuation:** While not explicitly shown in this snippet, the tests for continuation frames highlight the importance of using them for large headers. Not doing so would lead to frame size errors.

**User Operation Steps to Reach This Code (Debugging Context):**

Imagine a user encounters an issue while browsing a website:

1. **User Loads a Web Page:** The user types a URL or clicks a link in their browser.
2. **Browser Initiates HTTP/2 Connection:** If the server supports HTTP/2, the browser will attempt to establish an HTTP/2 connection.
3. **Frame Exchange:**  The browser and server exchange HTTP/2 frames (HEADERS, DATA, SETTINGS, etc.).
4. **Potential Issue:** Let's say the server is incorrectly implemented and sends a `RST_STREAM` for a valid request.
5. **Debugging:** A developer investigating this issue might:
    * **Use Browser Developer Tools:** Inspect the "Network" tab to see the `RST_STREAM` frame.
    * **Examine Server Logs:** Check the server-side logs for any errors that might have triggered the reset.
    * **Investigate Chromium Internals (Advanced):** If the issue seems to be within the browser's handling of HTTP/2, a Chromium developer might need to step through the C++ code. This is where `nghttp2_adapter_test.cc` becomes relevant. They might run specific tests in this file that simulate the problematic scenario to isolate the bug in the `NgHttp2Adapter` or the underlying `nghttp2` library.

**Summary of its Functionality (Part 8):**

This section of the `nghttp2_adapter_test.cc` file focuses on **testing various server-initiated actions and how the `NgHttp2Adapter` handles specific client behaviors and potential error conditions within an HTTP/2 connection.** It covers scenarios like server-side stream resets, connection shutdowns, sending trailers, and handling client-side continuation frames and metadata. It also explores error handling related to data sources and invalid header configurations, ensuring the adapter correctly translates `nghttp2` events and manages the HTTP/2 state within Chromium.

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/nghttp2_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
OnFrameHeader(1, 4, RST_STREAM, 0));
  EXPECT_CALL(visitor, OnRstStream(1, Http2ErrorCode::CANCEL));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::CANCEL))
      .WillOnce(
          [&adapter](Http2StreamId stream_id, Http2ErrorCode /*error_code*/) {
            adapter->RemoveStream(stream_id);
            return true;
          });
  const int64_t reset_result = adapter->ProcessBytes(reset);
  EXPECT_EQ(reset.size(), static_cast<size_t>(reset_result));

  // The stream's data source is dropped.
  EXPECT_EQ(adapter->sources_size(), 0);

  // Outbound HEADERS and DATA are dropped.
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, _)).Times(0);
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, _, _)).Times(0);
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, _, _)).Times(0);

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);

  EXPECT_THAT(visitor.data(), testing::IsEmpty());
}

// Should also test: client attempts shutdown, server attempts shutdown after an
// explicit GOAWAY.
TEST(NgHttp2AdapterTest, ServerSendsShutdown) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/false)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), result);

  adapter->SubmitShutdownNotice();

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(GOAWAY, 0, _, 0x0, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY}));
}

TEST_P(NgHttp2AdapterDataTest, ServerSendsTrailers) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);
  EXPECT_FALSE(adapter->want_write());

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
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), result);

  // Server will want to send a SETTINGS ack.
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
  visitor.Clear();

  EXPECT_FALSE(adapter->want_write());
  const absl::string_view kBody = "This is an example response body.";

  // The body source must indicate that the end of the body is not the end of
  // the stream.
  visitor.AppendPayloadForStream(1, kBody);
  visitor.SetEndData(1, false);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);
  int submit_result = adapter->SubmitResponse(
      1, ToHeaders({{":status", "200"}, {"x-comment", "Sure, sounds good."}}),
      GetParam() ? nullptr : std::move(body1), false);
  EXPECT_EQ(submit_result, 0);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::HEADERS, SpdyFrameType::DATA}));
  EXPECT_THAT(visitor.data(), testing::HasSubstr(kBody));
  visitor.Clear();
  EXPECT_FALSE(adapter->want_write());

  // The body source has been exhausted by the call to Send() above.
  int trailer_result = adapter->SubmitTrailer(
      1, ToHeaders({{"final-status", "a-ok"},
                    {"x-comment", "trailers sure are cool"}}));
  ASSERT_EQ(trailer_result, 0);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x5, 0));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::HEADERS}));
}

TEST(NgHttp2AdapterTest, ClientSendsContinuation) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);
  EXPECT_FALSE(adapter->want_write());

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/true,
                                          /*add_continuation=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 1));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, CONTINUATION, 4));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), result);
}

TEST(NgHttp2AdapterTest, ClientSendsMetadataWithContinuation) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);
  EXPECT_FALSE(adapter->want_write());

  const std::string frames =
      TestFrameSequence()
          .ClientPreface()
          .Metadata(0, "Example connection metadata in multiple frames", true)
          .Headers(1,
                   {{":method", "GET"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/one"}},
                   /*fin=*/false,
                   /*add_continuation=*/true)
          .Metadata(1,
                    "Some stream metadata that's also sent in multiple frames",
                    true)
          .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Metadata on stream 0
  EXPECT_CALL(visitor, OnFrameHeader(0, _, kMetadataFrameType, 0));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnFrameHeader(0, _, kMetadataFrameType, 4));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnMetadataEndForStream(0));

  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 0));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, CONTINUATION, 4));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  // Metadata on stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, kMetadataFrameType, 0));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, kMetadataFrameType, 4));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnMetadataEndForStream(1));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), result);
  EXPECT_EQ("Example connection metadata in multiple frames",
            absl::StrJoin(visitor.GetMetadata(0), ""));
  EXPECT_EQ("Some stream metadata that's also sent in multiple frames",
            absl::StrJoin(visitor.GetMetadata(1), ""));
}

TEST_P(NgHttp2AdapterDataTest, RepeatedHeaderNames) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);
  EXPECT_FALSE(adapter->want_write());

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"},
                                           {"accept", "text/plain"},
                                           {"accept", "text/html"}},
                                          /*fin=*/true)
                                 .Serialize();

  testing::InSequence s;

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
  EXPECT_CALL(visitor, OnHeaderForStream(1, "accept", "text/plain"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "accept", "text/html"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  const std::vector<Header> headers1 = ToHeaders(
      {{":status", "200"}, {"content-length", "10"}, {"content-length", "10"}});
  visitor.AppendPayloadForStream(1, "perfection");
  visitor.SetEndData(1, true);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);

  int submit_result = adapter->SubmitResponse(
      1, headers1, GetParam() ? nullptr : std::move(body1), false);
  ASSERT_EQ(0, submit_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, 10, 0x1, 0));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS,
                            SpdyFrameType::DATA}));
}

TEST_P(NgHttp2AdapterDataTest, ServerRespondsToRequestWithTrailers) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);
  EXPECT_FALSE(adapter->want_write());

  const std::string frames =
      TestFrameSequence()
          .ClientPreface()
          .Headers(1, {{":method", "GET"},
                       {":scheme", "https"},
                       {":authority", "example.com"},
                       {":path", "/this/is/request/one"}})
          .Data(1, "Example data, woohoo.")
          .Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _));
  EXPECT_CALL(visitor, OnDataForStream(1, _));

  int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  const std::vector<Header> headers1 = ToHeaders({{":status", "200"}});
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);

  int submit_result = adapter->SubmitResponse(
      1, headers1, GetParam() ? nullptr : std::move(body1), false);
  ASSERT_EQ(0, submit_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS}));
  visitor.Clear();

  const std::string more_frames =
      TestFrameSequence()
          .Headers(1, {{"extra-info", "Trailers are weird but good?"}},
                   /*fin=*/true)
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "extra-info",
                                         "Trailers are weird but good?"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  result = adapter->ProcessBytes(more_frames);
  EXPECT_EQ(more_frames.size(), static_cast<size_t>(result));

  visitor.SetEndData(1, true);
  EXPECT_EQ(true, adapter->ResumeStream(1));

  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::DATA}));
}

TEST_P(NgHttp2AdapterDataTest, ServerSubmitsResponseWithDataSourceError) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);
  EXPECT_FALSE(adapter->want_write());

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
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  visitor.SimulateError(1);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);

  int submit_result = adapter->SubmitResponse(
      1, ToHeaders({{":status", "200"}, {"x-comment", "Sure, sounds good."}}),
      GetParam() ? nullptr : std::move(body1), false);
  EXPECT_EQ(submit_result, 0);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(RST_STREAM, 1, _, 0x0, 2));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::INTERNAL_ERROR));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS,
                            SpdyFrameType::RST_STREAM}));
  visitor.Clear();
  EXPECT_FALSE(adapter->want_write());

  int trailer_result =
      adapter->SubmitTrailer(1, ToHeaders({{":final-status", "a-ok"}}));
  // The library does not object to the user queuing trailers, even through the
  // stream has already been closed.
  EXPECT_EQ(trailer_result, 0);
}

TEST(NgHttp2AdapterTest, CompleteRequestWithServerResponse) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);
  EXPECT_FALSE(adapter->want_write());

  const std::string frames =
      TestFrameSequence()
          .ClientPreface()
          .Headers(1,
                   {{":method", "GET"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/one"}},
                   /*fin=*/false)
          .Data(1, "This is the response body.", /*fin=*/true)
          .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 1));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _));
  EXPECT_CALL(visitor, OnDataForStream(1, _));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  int submit_result = adapter->SubmitResponse(
      1, ToHeaders({{":status", "200"}}), nullptr, true);
  EXPECT_EQ(submit_result, 0);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x5, 0));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS}));
  EXPECT_FALSE(adapter->want_write());
}

TEST(NgHttp2AdapterTest, IncompleteRequestWithServerResponse) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);
  EXPECT_FALSE(adapter->want_write());

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/false)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  int submit_result = adapter->SubmitResponse(
      1, ToHeaders({{":status", "200"}}), nullptr, true);
  EXPECT_EQ(submit_result, 0);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x5, 0));
  // BUG: Should send RST_STREAM NO_ERROR as well, but nghttp2 does not.

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS}));
  EXPECT_FALSE(adapter->want_write());
}

TEST(NgHttp2AdapterTest, ServerHandlesMultipleContentLength) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);
  EXPECT_FALSE(adapter->want_write());

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/1"},
                                           {"content-length", "7"},
                                           {"content-length", "7"}},
                                          /*fin=*/false)
                                 .Headers(3,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/3"},
                                           {"content-length", "11"},
                                           {"content-length", "13"}},
                                          /*fin=*/false)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/1"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "content-length", "7"));
  // nghttp2 does not like duplicate Content-Length headers.
  EXPECT_CALL(
      visitor,
      OnErrorDebug("Invalid HTTP header field was received: frame type: 1, "
                   "stream: 1, name: [content-length], value: [7]"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(1, Http2VisitorInterface::InvalidFrameError::kHttpHeader));
  // Stream 3
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":path", "/3"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, "content-length", "11"));
  EXPECT_CALL(
      visitor,
      OnErrorDebug("Invalid HTTP header field was received: frame type: 1, "
                   "stream: 3, name: [content-length], value: [13]"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(3, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));
}

TEST_P(NgHttp2AdapterDataTest, ServerSendsInvalidTrailers) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);
  EXPECT_FALSE(adapter->want_write());

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
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), result);

  const absl::string_view kBody = "This is an example response body.";

  // The body source must indicate that the end of the body is not the end of
  // the stream.
  visitor.AppendPayloadForStream(1, kBody);
  visitor.SetEndData(1, false);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);
  int submit_result = adapter->SubmitResponse(
      1, ToHeaders({{":status", "200"}, {"x-comment", "Sure, sounds good."}}),
      GetParam() ? nullptr : std::move(body1), false);
  EXPECT_EQ(submit_result, 0);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS,
                            SpdyFrameType::DATA}));
  EXPECT_THAT(visitor.data(), testing::HasSubstr(kBody));
  visitor.Clear();
  EXPECT_FALSE(adapter->want_write());

  // The body source has been exhausted by the call to Send() above.
  int trailer_result =
      adapter->SubmitTrailer(1, ToHeaders({{":final-status", "a-ok"}}));
  ASSERT_EQ(trailer_result, 0);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x5, 0));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::HEADERS}));
}

TEST(NgHttp2AdapterTest, ServerDropsNewStreamBelowWatermark) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  EXPECT_EQ(0, adapter->GetHighestReceivedStreamId());

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(3,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/false)
                                 .Data(3, "This is the request body.")
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "http"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/two"}},
                                          /*fin=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor, OnFrameHeader(3, 25, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(3, 25));
  EXPECT_CALL(visitor, OnDataForStream(3, "This is the request body."));

  // It looks like nghttp2 delivers the under-watermark frame header but
  // otherwise silently drops the rest of the frame without error.
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnInvalidFrame).Times(0);
  EXPECT_CALL(visitor, OnConnectionError).Times(0);

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), result);

  EXPECT_EQ(3, adapter->GetHighestReceivedStreamId());

  EXPEC
```