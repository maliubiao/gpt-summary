Response:
Let's break down the thought process for analyzing this code snippet and generating the detailed explanation.

1. **Understand the Goal:** The request asks for an analysis of a C++ test file for an HTTP/2 session implementation. The analysis should cover functionality, relationship to JavaScript (if any), logical reasoning with examples, common user/programming errors, debugging hints, and a summary.

2. **Identify the Core Component:** The file name `oghttp2_session_test.cc` and the namespace `quiche::http2::adapter` clearly indicate this is a C++ test file for the `OgHttp2Session` class, which seems to be an HTTP/2 session adapter. The presence of `TestVisitor` suggests a mock object for testing interactions with the underlying HTTP/2 implementation.

3. **High-Level Functionality:**  Scanning through the code, the tests are structured using Google Test (`TEST`). Each test method sets up an `OgHttp2Session`, feeds it input (HTTP/2 frames), and verifies the session's behavior by checking the actions performed on the `TestVisitor`. The primary function of this file is to *test the different scenarios of an HTTP/2 session*.

4. **Break Down Individual Tests:**  Go through each `TEST` function to understand what specific aspect of the session is being tested:
    * `ServerSendsInitialSettings`: Tests the server sending initial SETTINGS frames.
    * `ServerReceivesClientSettings`: Tests the server receiving and acknowledging client SETTINGS frames.
    * `ServerReceivesHeaders`: Tests the server receiving and processing a HEADERS frame from the client.
    * `ServerReceivesData`: Tests the server receiving and processing a DATA frame from the client.
    * `ServerSendsResponse`: Tests the server sending a basic HTTP response (HEADERS and DATA).
    * `ServerSendsTrailers`: Tests the server sending trailers after the response body.
    * `ServerQueuesTrailersWithResponse`: Tests the server queuing trailers immediately after the response.
    * `ServerSeesErrorOnEndStream`: Tests the server handling an error when processing the end of a stream.

5. **Look for JavaScript Connections:** Actively consider where JavaScript might be involved. HTTP/2 is a transport protocol often used by web browsers (which run JavaScript) to communicate with servers. The key connection is that the *behavior being tested here directly impacts how JavaScript applications running in a browser interact with servers*.

6. **Construct Logical Reasoning Examples:** For each test case, think about:
    * **Input:** What HTTP/2 frames are being fed to the `OgHttp2Session`?  Represent this concisely (e.g., "Client sends a GET request").
    * **Output/Behavior:** What actions is the `OgHttp2Session` expected to take (verified through `TestVisitor` calls)?  (e.g., "Server sends initial SETTINGS, then sends a response").

7. **Identify Potential Errors:** Consider common mistakes users (developers integrating this library or programmers writing HTTP/2 applications) might make:
    * **Incorrect Frame Sequencing:** Sending frames in the wrong order.
    * **Missing Mandatory Headers:** Forgetting required headers like `:status` in a response.
    * **Flow Control Issues:** Sending more data than the peer allows.
    * **Incorrect Trailer Usage:** Sending trailers before the body, or not signaling the end of the body correctly.

8. **Trace User Actions for Debugging:**  Imagine a user interacting with a web browser. How does that interaction lead to this code being executed?  Think in terms of browser actions and the underlying network stack:
    * User types a URL or clicks a link.
    * Browser resolves the domain name.
    * Browser establishes a TCP connection.
    * Browser initiates an HTTP/2 handshake.
    * Browser sends HTTP/2 requests.
    * The server processes the requests using code similar to what's being tested here.

9. **Summarize the Functionality:**  Condense the findings into a concise summary. Focus on the purpose of the file and the scope of the tests.

10. **Refine and Organize:** Structure the explanation logically with clear headings and bullet points. Use precise terminology (e.g., "HEADERS frame," "SETTINGS frame"). Ensure the examples are easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just about testing the C++ code."  **Correction:**  Recognize the higher-level impact on web interactions and JavaScript.
* **Early description of tests:** "It tests sending data." **Refinement:** Be more specific – "Tests the server sending a response with headers and data."
* **Vague error example:** "User sends bad data." **Refinement:**  Provide concrete examples like "sending trailers before the response body is complete."
* **Missing debugging context:** Initially focus only on the C++ code. **Correction:**  Think about the broader user experience and how to trace issues back to this level.

By following this structured approach and constantly refining the analysis, we arrive at the detailed and informative explanation provided earlier.
这是对 Chromium 网络栈中 `net/third_party/quiche/src/quiche/http2/adapter/oghttp2_session_test.cc` 文件功能的总结，基于你提供的第二部分内容。

**文件功能归纳（基于第二部分）：**

此测试文件的主要功能是测试 `OgHttp2Session` 类在作为 HTTP/2 **服务端**时的各种行为和状态转换。具体来说，这部分测试集中在以下几个方面：

* **发送响应数据流:** 测试服务端如何构建并发送包含头部和数据的 HTTP 响应。涵盖了设置流用户数据、检查发送窗口大小等。
* **发送尾部 (Trailers):**  详细测试了服务端在数据发送完毕后，如何发送尾部帧 (HEADERS 帧，但设置了 END_STREAM 标志)。包括在数据发送后立即发送尾部，以及在响应头部和数据还未发送时就先提交尾部的情况。
* **处理 `OnEndStream` 回调中的错误:** 测试了当服务端在接收到客户端发送的 END_STREAM 标志后，其 `OnEndStream` 回调返回错误时，会发生什么。这包括服务端发送 GOAWAY 帧并关闭连接。

**与 JavaScript 的关系举例说明：**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的 HTTP/2 协议是现代 Web 应用中 JavaScript 与服务器通信的基础。以下是与 JavaScript 功能相关的举例说明：

* **发送响应体 (ServerSendsResponse):**  当 JavaScript 通过 `fetch` API 或 `XMLHttpRequest` 发起一个请求时，服务器端（由 `OgHttp2Session` 处理）会构建包含响应状态码、头部和响应体的 HTTP/2 响应。JavaScript 接收到这些数据后，才能在浏览器中渲染页面或进行其他操作。
    * **例如：** JavaScript 使用 `fetch('/api/data')` 发起请求，服务器端 `OgHttp2Session` 处理该请求，并发送一个包含 JSON 数据的响应。JavaScript 接收到响应后，使用 `response.json()` 解析 JSON 数据并在页面上显示。
* **发送尾部 (ServerSendsTrailers):** HTTP/2 的尾部帧允许服务器在发送完主要的响应体后，发送额外的头部信息。这对于发送校验和、签名或动态生成但需要在响应末尾才能确定的信息非常有用。JavaScript 的 `fetch` API 可以访问这些尾部信息。
    * **例如：** 服务器在发送完一个大文件后，使用尾部帧发送文件的 SHA256 校验和。JavaScript 可以通过 `response.trailers` 属性来获取并验证这个校验和，确保文件传输的完整性。

**逻辑推理的假设输入与输出：**

**测试用例：ServerSendsResponse**

* **假设输入:**
    * 客户端发送一个带有stream ID 1的 HEADERS 帧，请求 `/this/is/request/one`。
* **逻辑推理:**
    * 服务端接收到 HEADERS 帧，调用 `OnBeginHeadersForStream` 和 `OnHeaderForStream` 等回调。
    * 服务端调用 `SubmitResponse` 提交一个状态码为 404 的响应，并提供响应体数据。
    * 服务端调用 `Send` 方法发送响应。
* **预期输出:**
    * `TestVisitor` 会记录以下事件（通过 `EXPECT_CALL` 断言）：
        * `OnBeforeFrameSent(SETTINGS, 0, _, 0x0)` 和 `OnFrameSent`：发送初始 SETTINGS 帧。
        * `OnBeforeFrameSent(SETTINGS, 0, _, 0x1)` 和 `OnFrameSent`：发送 SETTINGS ACK 帧。
        * `OnBeforeFrameSent(HEADERS, 1, _, 0x4)` 和 `OnFrameSent`：发送响应头部帧。
        * `OnFrameSent(DATA, 1, _, 0x0, 0)`：发送响应数据帧。
    * `visitor.data()` 中包含正确的 SETTINGS 和 HEADERS/DATA 帧序列。
    * `session.want_write()` 的状态在适当的时候为 `true` 和 `false`。

**涉及用户或编程常见的使用错误举例说明：**

* **不正确地处理 `OnEndStream` 的返回值 (ServerSeesErrorOnEndStream):**
    * **错误场景:** 开发者在实现 `Http2VisitorInterface` 时，错误地在 `OnEndStream` 回调中返回 `false`，即使流没有错误。
    * **后果:** `OgHttp2Session` 会将此视为解析错误，并发送 GOAWAY 帧关闭连接。
    * **用户操作导致:** 这通常不会直接由用户操作触发，而是由于服务器端代码的错误实现。
* **在发送响应前尝试发送尾部 (ServerQueuesTrailersWithResponse):**
    * **错误场景:** 开发者在调用 `SubmitResponse` 后，但在第一次 `Send()` 之前，就调用了 `SubmitTrailer`。虽然这个测试用例演示了这种用法是可行的，但在某些实现中，过早地提交尾部可能会导致问题，或者逻辑上不太清晰。
    * **用户操作导致:**  这同样是服务器端编程错误，而非直接的用户操作。

**用户操作如何一步步的到达这里，作为调试线索：**

假设用户在浏览器中访问一个网站，导致了 `ServerSendsResponse` 测试用例中模拟的场景：

1. **用户在浏览器地址栏输入 URL 并回车，或者点击一个链接。** 例如：`https://example.com/this/is/request/one`。
2. **浏览器解析 URL，并确定需要建立与 `example.com` 的 HTTPS 连接。**
3. **浏览器与服务器建立 TCP 连接，并进行 TLS 握手。**
4. **浏览器发送 HTTP/2 连接序言 (Client Preface)，其中包括一个空的 SETTINGS 帧。** 这对应了测试用例中 `TestFrameSequence().ClientPreface()` 的部分。
5. **浏览器发送一个 HEADERS 帧，包含请求方法（GET）、路径 (`/this/is/request/one`) 等信息。** 这对应了测试用例中的 `.Headers(1, ...)`。
6. **服务器接收到这些 HTTP/2 帧，`OgHttp2Session` 的 `ProcessBytes` 方法被调用，解析并处理这些帧。** 这就进入了测试用例中模拟的服务器端逻辑。
7. **服务器端应用逻辑判断该请求对应的资源不存在，并调用 `OgHttp2Session` 的 `SubmitResponse` 方法，设置状态码为 404，并提供错误信息。**
8. **服务器端调用 `OgHttp2Session` 的 `Send` 方法，将响应帧发送回客户端。** 这对应了测试用例中对 `visitor` 的 `EXPECT_CALL`。

如果在调试过程中，服务器端对于特定请求返回了意外的 404 状态码，可以检查服务器端的日志和 HTTP/2 帧的交互情况。如果怀疑是 HTTP/2 协议实现的问题，可以查看类似 `oghttp2_session_test.cc` 这样的测试用例，了解 `OgHttp2Session` 在处理类似场景时的预期行为，从而缩小问题范围。

**总结第二部分功能：**

总而言之，`oghttp2_session_test.cc` 的第二部分专注于测试 `OgHttp2Session` 作为 HTTP/2 服务端时，如何正确地构建和发送 HTTP 响应，包括处理尾部帧以及在处理流结束时遇到错误的情况。这些测试用例验证了服务端在各种场景下的行为是否符合 HTTP/2 协议的预期，确保了网络通信的可靠性和正确性。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/oghttp2_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  int send_result = session.Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS}));
  visitor.Clear();

  EXPECT_FALSE(session.want_write());
  // A data fin is not sent so that the stream remains open, and the flow
  // control state can be verified.
  visitor.AppendPayloadForStream(1, "This is an example response body.");
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);
  int submit_result = session.SubmitResponse(
      1,
      ToHeaders({{":status", "404"},
                 {"x-comment", "I have no idea what you're talking about."}}),
      std::move(body1), false);
  EXPECT_EQ(submit_result, 0);
  EXPECT_TRUE(session.want_write());

  // Stream user data should have been set successfully after receiving headers.
  EXPECT_EQ(kSentinel1, session.GetStreamUserData(1));
  session.SetStreamUserData(1, nullptr);
  EXPECT_EQ(nullptr, session.GetStreamUserData(1));

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0));

  send_result = session.Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::HEADERS, SpdyFrameType::DATA}));
  EXPECT_FALSE(session.want_write());

  // Some data was sent, so the remaining send window size should be less than
  // the default.
  EXPECT_LT(session.GetStreamSendWindowSize(1), kInitialFlowControlWindowSize);
  EXPECT_GT(session.GetStreamSendWindowSize(1), 0);
  // Send window for a nonexistent stream is not available.
  EXPECT_EQ(session.GetStreamSendWindowSize(3), -1);

  EXPECT_GT(session.GetHpackEncoderDynamicTableSize(), 0);
}

// Tests the case where the server queues trailers after the data stream is
// exhausted.
TEST(OgHttp2SessionTest, ServerSendsTrailers) {
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

  const int64_t result = session.ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  // Server will want to send initial SETTINGS, and a SETTINGS ack.
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  int send_result = session.Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS}));
  visitor.Clear();

  EXPECT_FALSE(session.want_write());

  // The body source must indicate that the end of the body is not the end of
  // the stream.
  visitor.AppendPayloadForStream(1, "This is an example response body.");
  visitor.SetEndData(1, false);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);
  int submit_result = session.SubmitResponse(
      1, ToHeaders({{":status", "200"}, {"x-comment", "Sure, sounds good."}}),
      std::move(body1), false);
  EXPECT_EQ(submit_result, 0);
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0));

  send_result = session.Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::HEADERS, SpdyFrameType::DATA}));
  visitor.Clear();
  EXPECT_FALSE(session.want_write());

  // The body source has been exhausted by the call to Send() above.
  int trailer_result = session.SubmitTrailer(
      1, ToHeaders({{"final-status", "a-ok"},
                    {"x-comment", "trailers sure are cool"}}));
  ASSERT_EQ(trailer_result, 0);
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x5, 0));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  send_result = session.Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::HEADERS}));
}

// Tests the case where the server queues trailers immediately after headers and
// data, and before any writes have taken place.
TEST(OgHttp2SessionTest, ServerQueuesTrailersWithResponse) {
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

  const int64_t result = session.ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  // Server will want to send initial SETTINGS, and a SETTINGS ack.
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  int send_result = session.Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS}));
  visitor.Clear();

  EXPECT_FALSE(session.want_write());

  // The body source must indicate that the end of the body is not the end of
  // the stream.
  visitor.AppendPayloadForStream(1, "This is an example response body.");
  visitor.SetEndData(1, false);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);
  int submit_result = session.SubmitResponse(
      1, ToHeaders({{":status", "200"}, {"x-comment", "Sure, sounds good."}}),
      std::move(body1), false);
  EXPECT_EQ(submit_result, 0);
  EXPECT_TRUE(session.want_write());
  // There has not been a call to Send() yet, so neither headers nor body have
  // been written.
  int trailer_result = session.SubmitTrailer(
      1, ToHeaders({{"final-status", "a-ok"},
                    {"x-comment", "trailers sure are cool"}}));
  ASSERT_EQ(trailer_result, 0);
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0));

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x5, 0));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  send_result = session.Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::HEADERS, SpdyFrameType::DATA,
                            SpdyFrameType::HEADERS}));
}

TEST(OgHttp2SessionTest, ServerSeesErrorOnEndStream) {
  TestVisitor visitor;
  OgHttp2Session::Options options;
  options.perspective = Perspective::kServer;
  OgHttp2Session session(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/"}},
                                          /*fin=*/false)
                                 .Data(1, "Request body", true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 0x4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));

  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0x1));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _));
  EXPECT_CALL(visitor, OnDataForStream(1, "Request body"));
  EXPECT_CALL(visitor, OnEndStream(1)).WillOnce(testing::Return(false));
  EXPECT_CALL(
      visitor,
      OnConnectionError(Http2VisitorInterface::ConnectionError::kParseError));

  const int64_t result = session.ProcessBytes(frames);
  EXPECT_EQ(/*NGHTTP2_ERR_CALLBACK_FAILURE=*/-902, result);

  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(
      visitor,
      OnFrameSent(GOAWAY, 0, _, 0x0,
                  static_cast<int>(
                      Http2VisitorInterface::ConnectionError::kParseError)));

  int send_result = session.Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY}));
  visitor.Clear();

  EXPECT_FALSE(session.want_write());
}

}  // namespace test
}  // namespace adapter
}  // namespace http2

"""


```