Response:
My thinking process to analyze the given code snippet and fulfill the request goes like this:

1. **Understand the Core Functionality:** The filename `oghttp2_adapter_test.cc` immediately suggests this is a unit test file for a component named `OgHttp2Adapter`. The "http2" part points to HTTP/2 protocol handling. The "adapter" part implies this component acts as an intermediary, likely between a lower-level HTTP/2 implementation and a higher-level interface (the "visitor").

2. **Identify Key Classes and Methods:**  The code heavily uses `TestVisitor`, `OgHttp2Adapter`, `OgHttp2Adapter::Options`, and `TestFrameSequence`. The `ProcessBytes()` and `Send()` methods of `OgHttp2Adapter` are central to processing and generating HTTP/2 frames. The `EXPECT_CALL` macros indicate interactions with the `TestVisitor` mock object.

3. **Analyze Individual Test Cases:** Each `TEST` function focuses on a specific scenario. I need to break down what each test is verifying:
    * **`ClientSendsInvalidPreface`:** Checks how the adapter handles an invalid HTTP/2 client preface. It expects a connection error and a GOAWAY frame to be sent.
    * **`ServerVisitorRejectsHeaders`:**  Tests how the server adapter reacts when the visitor signals it wants to reject specific headers in a request. It expects a RST_STREAM frame.
    * **`ServerSubmitsResponseWithDataSourceError`:** Examines the server's behavior when providing a response body that encounters an error during data retrieval. It anticipates a RST_STREAM frame.
    * **`CompleteRequestWithServerResponse`:** Tests a successful, complete request-response cycle where the server immediately sends the full response.
    * **`IncompleteRequestWithServerResponse`:**  Similar to the previous test but the client request is incomplete (no final DATA frame). It checks if the server can still respond and if a RST_STREAM is *not* sent by default.
    * **`IncompleteRequestWithServerResponseRstStreamEnabled`:**  Tests the same scenario as above but with a specific option enabled to send a RST_STREAM for incomplete requests.
    * **`ServerHandlesMultipleContentLength`:** Verifies the server's handling of requests with multiple `Content-Length` headers. It expects an `OnInvalidFrame` callback.
    * **`ServerSendsInvalidTrailers`:** Checks how the server responds when trailers are submitted after the data source has been exhausted.
    * **`ServerHandlesDataWithPadding`:**  Tests the server's ability to process DATA frames with padding.
    * **`ServerHandlesHostHeader`:**  Examines the server's handling of the `Host` header and its interaction with the `:authority` pseudo-header. It expects an error if they don't match (by default).
    * **`ServerHandlesHostHeaderWithLaxValidation`:**  Tests the same `Host` header scenario but with an option to allow discrepancies between `Host` and `:authority`.
    * **`ServerSubmitsTrailersWhileDataDeferred`:**  Tests the scenario where trailers are submitted while the response body is still being sent.

4. **Infer Functionality from Tests:** Based on the individual test cases, I can deduce the overall functionality of `OgHttp2Adapter`:
    * HTTP/2 frame processing (parsing and serialization).
    * Handling client and server perspectives.
    * Managing HTTP/2 streams.
    * Header processing and validation.
    * Data transfer management.
    * Error handling and reporting.
    * Support for HTTP/2 features like padding and trailers.
    * Configuration options to control behavior.

5. **Identify Relationships with JavaScript:**  While the C++ code itself isn't directly JavaScript, it's part of Chromium's networking stack, which *powers* the network communication for web browsers and thus interacts heavily with JavaScript running in web pages. The key connection is the underlying HTTP/2 implementation that facilitates network requests made by JavaScript code.

6. **Construct Examples for JavaScript Interaction:**  Think about common JavaScript APIs that use HTTP/2 and how the scenarios in the tests could manifest in the browser:
    * `fetch()` API: Making a simple GET or POST request.
    * Streaming responses: Using `ReadableStream` with `fetch()`.
    * Invalid responses: How a JavaScript application might handle a server sending a GOAWAY or RST_STREAM.
    * Header manipulation: Although JavaScript can't directly *forge* certain headers, understanding header validation is relevant.

7. **Develop Hypothesis for Input and Output:**  For each test, consider the HTTP/2 frames being fed into `ProcessBytes()` (the "input") and the expected actions on the `visitor` mock (the "output"). This often involves visualizing the sequence of HTTP/2 frames.

8. **Identify User/Programming Errors:** Consider what mistakes a developer or a user's browser configuration could lead to the tested scenarios:
    * Incorrectly formatted HTTP requests (leading to parsing errors).
    * Server-side errors during response generation.
    * Mismatched headers.
    * Unexpected connection closures.

9. **Trace User Operations (Debugging):** Imagine how a user's actions in a browser could trigger the network requests that lead to these code paths. This involves understanding the basic flow of a web request.

10. **Summarize Functionality (Part 7 of 12):**  Given that this is part 7 of a larger set of tests, consider what aspects of the adapter's functionality might be covered in this specific section. It seems to focus on server-side behavior, error handling, and specific HTTP/2 features.

11. **Refine and Structure the Answer:** Organize the information logically, using clear headings and bullet points. Provide specific code examples and explanations. Ensure the language is clear and concise.

By following this systematic approach, I can effectively analyze the provided code snippet, understand its purpose, identify its connections to other technologies (like JavaScript), and provide a comprehensive and informative answer to the user's request.
This is part 7 of a 12-part series of unit tests for `oghttp2_adapter_test.cc`. Based on the provided code, this specific part focuses heavily on testing the **server-side behavior** of the `OgHttp2Adapter`. It explores various scenarios related to how the adapter handles incoming client requests and prepares server responses, including error conditions and specific HTTP/2 features.

Here's a breakdown of its functions:

**Core Functionality Demonstrated in This Section:**

* **Handling Invalid Client Requests:** Tests how the server adapter reacts to malformed client HTTP/2 prefaces (e.g., `ClientSendsInvalidPreface`). It verifies the adapter detects the error and initiates a clean shutdown using a `GOAWAY` frame.
* **Server-Side Header Processing and Rejection:** Examines how the server adapter, via the `Http2VisitorInterface`, can reject specific headers in a client request (`ServerVisitorRejectsHeaders`). It checks if the adapter correctly sends a `RST_STREAM` frame for the rejected stream.
* **Handling Errors During Response Body Generation:** Tests the scenario where an error occurs while the server is trying to provide the response body (`ServerSubmitsResponseWithDataSourceError`). It verifies the adapter handles this gracefully, likely sending a `RST_STREAM`.
* **Successful Request-Response Cycle:**  Demonstrates the basic flow of a complete HTTP/2 request and server response, both with and without a response body (`CompleteRequestWithServerResponse`, `IncompleteRequestWithServerResponse`). It validates the correct sequence of visitor callbacks and frame generation.
* **Handling Incomplete Requests:**  Specifically tests how the server adapter behaves when it receives a request without the final data frame (`IncompleteRequestWithServerResponse`, `IncompleteRequestWithServerResponseRstStreamEnabled`). It shows how the `rst_stream_no_error_when_incomplete` option controls whether a `RST_STREAM` is sent in this case.
* **Handling Duplicate Headers:**  Tests how the server adapter reacts to receiving multiple `Content-Length` headers in a request (`ServerHandlesMultipleContentLength`). It verifies that the adapter detects this as an invalid frame.
* **Handling Trailers:**  Examines the server's ability to send HTTP/2 trailers, especially when the response body is streamed (`ServerSendsInvalidTrailers`, `ServerSubmitsTrailersWhileDataDeferred`). It covers scenarios where trailers might be submitted after the body data source is exhausted or while data is still being sent.
* **Handling Data Padding:**  Tests the server's ability to process incoming data frames that include padding (`ServerHandlesDataWithPadding`).
* **Handling `Host` Header:**  Focuses on how the server adapter processes the `Host` header in client requests, and its relationship with the `:authority` pseudo-header (`ServerHandlesHostHeader`, `ServerHandlesHostHeaderWithLaxValidation`). It shows how the `allow_different_host_and_authority` option affects validation.

**Relationship with JavaScript:**

While the code is in C++, it directly impacts the behavior of web browsers and, consequently, JavaScript code running in those browsers. Here's how:

* **`fetch()` API and Network Requests:** When JavaScript uses the `fetch()` API (or older mechanisms like `XMLHttpRequest`) to make network requests, Chromium's network stack (including this `OgHttp2Adapter`) handles the underlying HTTP/2 protocol negotiation, frame construction, and parsing.
* **Server Push:** Although not explicitly shown in this snippet, the correct server-side HTTP/2 implementation is crucial for features like server push, where the server proactively sends resources to the client, potentially improving JavaScript application loading times.
* **Error Handling in JavaScript:** The error conditions tested here (invalid preface, rejected headers, data source errors) can manifest as network errors or specific HTTP status codes that JavaScript code needs to handle. For example, a `GOAWAY` frame might indicate a server-initiated connection closure that a JavaScript application would need to be aware of and potentially retry requests.
* **Streaming Responses:** The tests involving trailers demonstrate a part of the infrastructure that enables efficient streaming responses, which JavaScript can consume using `ReadableStream` objects obtained from `fetch()`.

**Examples of JavaScript Interaction and Manifestation of Tested Scenarios:**

1. **Invalid Client Preface:**
   * **Scenario:** A buggy JavaScript library attempts to establish an HTTP/2 connection but sends an incorrectly formatted initial handshake.
   * **JavaScript Manifestation:** The `fetch()` call might fail with a generic network error or a more specific error related to protocol negotiation. The browser's developer console might show errors related to the HTTP/2 connection.

2. **Server Rejects Headers:**
   * **Scenario:** A JavaScript application sends a request with a custom header that the server is configured to reject based on its value.
   * **JavaScript Manifestation:** The `fetch()` call might result in a specific HTTP error code (e.g., 400 Bad Request) or a custom error code defined by the server. The server might provide more details in the response body or headers.

3. **Server Data Source Error:**
   * **Scenario:** A JavaScript application requests a resource, and the server encounters an error while trying to read the data for the response (e.g., a file is missing).
   * **JavaScript Manifestation:** The `fetch()` call might result in a 500 Internal Server Error. If the server attempts to stream the response, the `ReadableStream` might encounter an error during reading.

4. **Handling `Host` Header Mismatch:**
   * **Scenario:** A JavaScript application makes a request where the `Host` header in the request doesn't match the `:authority` pseudo-header (this is usually handled automatically by the browser).
   * **JavaScript Manifestation:** The browser might prevent such a request from being sent. If it does get sent and the server enforces strict validation, the `fetch()` call could result in a 400 Bad Request or a similar error indicating a protocol violation.

**Hypothetical Input and Output:**

Let's take the `ServerVisitorRejectsHeaders` test as an example:

* **Hypothetical Input:** A sequence of HTTP/2 frames representing a client request, including a HEADERS frame with multiple headers and a CONTINUATION frame. The header "header2" will trigger the visitor to return `HEADER_RST_STREAM`.
* **Hypothetical Output:**
    * The `OgHttp2Adapter` will call the `TestVisitor`'s methods in a specific sequence to process the frames.
    * When processing the "header2" header, the `TestVisitor`'s mock will return `Http2VisitorInterface::HEADER_RST_STREAM`.
    * The `OgHttp2Adapter` will then generate and send a `RST_STREAM` frame for stream 1.
    * The `TestVisitor`'s `OnBeforeFrameSent` and `OnFrameSent` methods will be called with the details of the generated `RST_STREAM` frame.

**User or Programming Common Usage Errors:**

1. **Incorrectly Formatting HTTP Requests:** A programmer might manually construct an HTTP request with invalid headers or an incorrect structure, leading to parsing errors on the server-side (tested in scenarios like `ClientSendsInvalidPreface`).
2. **Server-Side Logic Errors:** A server-side application might have bugs in its response generation logic, leading to data source errors or invalid responses.
3. **Misunderstanding HTTP/2 Semantics:** Developers might incorrectly use HTTP/2 features like trailers or padding, causing interoperability issues.
4. **Incorrectly Configuring Load Balancers or Proxies:** Misconfigured intermediary servers might modify or corrupt HTTP/2 frames, leading to unexpected errors.

**User Operation Steps to Reach This Code (Debugging Clues):**

Imagine a user browsing a website:

1. **User types a URL or clicks a link:** This initiates a network request from the browser.
2. **Browser performs DNS lookup:**  The browser resolves the domain name to an IP address.
3. **Browser establishes a TCP connection:** A connection is made to the server's IP address and port (usually 443 for HTTPS).
4. **TLS Handshake (for HTTPS):** The browser and server negotiate encryption.
5. **HTTP/2 Negotiation:** The browser and server negotiate the use of the HTTP/2 protocol (often done via ALPN during the TLS handshake).
6. **Browser sends HTTP/2 frames:**  The browser constructs and sends HTTP/2 frames representing the request headers, and potentially data. This is where the code being tested comes into play on the server-side.
7. **Server processes the frames:** The `OgHttp2Adapter` on the server receives and parses these frames, invoking callbacks on the `Http2VisitorInterface`.
8. **Server generates response frames:** Based on the request, the server constructs HTTP/2 frames for the response headers and body.
9. **Server sends response frames:** The `OgHttp2Adapter` serializes and sends these frames back to the browser.
10. **Browser processes response frames:** The browser receives and parses the response frames, ultimately rendering the web page or providing data to the JavaScript application.

If there's an error at any stage (e.g., an invalid frame, a header the server rejects, an error generating the response), the code in these tests would be involved in handling and potentially reporting that error. Debugging tools like network inspectors in browsers (e.g., Chrome DevTools) can capture the actual HTTP/2 frames being exchanged, which can be invaluable in pinpointing issues related to the scenarios tested here.

**Summary of Functionality (Part 7):**

In summary, this part of the `oghttp2_adapter_test.cc` file specifically focuses on rigorously testing the **server-side logic** of the `OgHttp2Adapter`. It covers a wide range of scenarios, from handling malformed client requests and rejecting specific headers to managing response generation errors and correctly implementing various HTTP/2 features like trailers and padding. It ensures the server-side adapter is robust and correctly implements the HTTP/2 protocol.

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/oghttp2_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共12部分，请归纳一下它的功能

"""
  .Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor,
              OnFrameHeader(1, _, HEADERS, END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kParseError));

  int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(result), frames.size());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::COMPRESSION_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, ServerVisitorRejectsHeaders) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  EXPECT_FALSE(adapter->want_write());

  const std::string frames =
      TestFrameSequence()
          .ClientPreface()
          .Headers(1,
                   {{":method", "GET"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/one"},
                    {"header1", "ok"},
                    {"header2", "rejected"},
                    {"header3", "not processed"},  // CONTINUATION starts here
                    {"header4", "not processed"},
                    {"header5", "not processed"},
                    {"header6", "not processed"},
                    {"header7", "not processed"},
                    {"header8", "not processed"}},
                   /*fin=*/false, /*add_continuation=*/true)
          .Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 0x0));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(5);
  EXPECT_CALL(visitor, OnHeaderForStream(1, "header2", _))
      .WillOnce(testing::Return(Http2VisitorInterface::HEADER_RST_STREAM));
  // The CONTINUATION frame header and header fields are not processed.

  int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(result), frames.size());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, _, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::RST_STREAM}));
}

TEST_P(OgHttp2AdapterDataTest, ServerSubmitsResponseWithDataSourceError) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);
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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));
  // TODO(birenroy): Send RST_STREAM INTERNAL_ERROR to the client as well.
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::INTERNAL_ERROR));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::HEADERS}));
  visitor.Clear();
  EXPECT_FALSE(adapter->want_write());

  // Since the stream has been closed, it is not possible to submit trailers for
  // the stream.
  int trailer_result =
      adapter->SubmitTrailer(1, ToHeaders({{":final-status", "a-ok"}}));
  ASSERT_LT(trailer_result, 0);
  EXPECT_FALSE(adapter->want_write());
}

TEST(OgHttp2AdapterTest, CompleteRequestWithServerResponse) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);
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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::HEADERS}));
  EXPECT_FALSE(adapter->want_write());
}

TEST(OgHttp2AdapterTest, IncompleteRequestWithServerResponse) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);
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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));
  // RST_STREAM NO_ERROR option is disabled.

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::HEADERS}));
  EXPECT_FALSE(adapter->want_write());
}

TEST(OgHttp2AdapterTest, IncompleteRequestWithServerResponseRstStreamEnabled) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  options.rst_stream_no_error_when_incomplete = true;
  auto adapter = OgHttp2Adapter::Create(visitor, options);
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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, 4, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(RST_STREAM, 1, 4, 0x0, 0));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(
      visitor.data(),
      EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                    SpdyFrameType::HEADERS, SpdyFrameType::RST_STREAM}));
  EXPECT_FALSE(adapter->want_write());
}

TEST(OgHttp2AdapterTest, ServerHandlesMultipleContentLength) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);
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
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
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
      OnInvalidFrame(3, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));
}

TEST_P(OgHttp2AdapterDataTest, ServerSendsInvalidTrailers) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);
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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::HEADERS, SpdyFrameType::DATA}));
  EXPECT_THAT(visitor.data(), testing::HasSubstr(kBody));
  visitor.Clear();
  EXPECT_FALSE(adapter->want_write());

  // The body source has been exhausted by the call to Send() above.
  int trailer_result =
      adapter->SubmitTrailer(1, ToHeaders({{":final-status", "a-ok"}}));
  ASSERT_EQ(trailer_result, 0);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::HEADERS}));
}

TEST(OgHttp2AdapterTest, ServerHandlesDataWithPadding) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/false)
                                 .Data(1, "This is the request body.",
                                       /*fin=*/true, /*padding_length=*/39)
                                 .Headers(3,
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

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, 25 + 39, DATA, 0x9));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 25 + 39));
  // Note: oghttp2 passes padding information before the actual data.
  EXPECT_CALL(visitor, OnDataPaddingLength(1, 39));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the request body."));
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor, OnEndStream(3));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<int64_t>(frames.size()), result);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2AdapterTest, ServerHandlesHostHeader) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":path", "/this/is/request/one"},
                                           {"host", "example.com"}},
                                          /*fin=*/true)
                                 .Headers(3,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"},
                                           {"host", "example.com"}},
                                          /*fin=*/true)
                                 .Headers(5,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "foo.com"},
                                           {":path", "/this/is/request/one"},
                                           {"host", "bar.com"}},
                                          /*fin=*/true)
                                 .Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, _, _)).Times(5);
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor, OnEndStream(3));

  EXPECT_CALL(visitor, OnFrameHeader(5, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(5));
  EXPECT_CALL(visitor, OnHeaderForStream(5, _, _)).Times(4);
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(5, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 5, 4, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 5, 4, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(5, Http2ErrorCode::HTTP2_NO_ERROR));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  visitor.Clear();
}

TEST(OgHttp2AdapterTest, ServerHandlesHostHeaderWithLaxValidation) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  options.allow_different_host_and_authority = true;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":path", "/this/is/request/one"},
                                           {"host", "example.com"}},
                                          /*fin=*/true)
                                 .Headers(3,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"},
                                           {"host", "example.com"}},
                                          /*fin=*/true)
                                 .Headers(5,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "foo.com"},
                                           {":path", "/this/is/request/one"},
                                           {"host", "bar.com"}},
                                          /*fin=*/true)
                                 .Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, _, _)).Times(5);
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor, OnEndStream(3));

  EXPECT_CALL(visitor, OnFrameHeader(5, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(5));
  EXPECT_CALL(visitor, OnHeaderForStream(5, _, _)).Times(5);
  // No error, because the option is set to allow different host and authority
  // values.
  EXPECT_CALL(visitor, OnEndHeadersForStream(5));
  EXPECT_CALL(visitor, OnEndStream(5));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  visitor.Clear();
}

// Tests the case where the response body is in the progress of being sent while
// trailers are queued.
TEST_P(OgHttp2AdapterDataTest, ServerSubmitsTrailersWhileDataDeferred) {
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  for (const bool add_more_body_data : {true, false}) {
    TestVisitor visitor;
    auto adapter = OgHttp2Adapter::Create(visitor, options);

    const std::string frames = TestFrameSequence()
                                   .ClientPreface()
                                   .Headers(1,
                                            {{":method", "POST"},
                                             {":scheme", "https"},
                                             {":authority", "example.com"},
                                             {":path", "/this/is/request/one"}},
                                            /*fin=*/false)
                                   .WindowUpdate(1, 2000)
                                   .Data(1, "This is the request body.")
                                   .WindowUpdate(0, 2000)
                                   .Serialize();
    testing::InSequence s;

    // Client preface (empty SETTINGS)
    EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
    EXPECT_CALL(visitor, OnSettingsStart());
    EXPECT_CALL(visitor, OnSettingsEnd());

    EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
    EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
    EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
    EXPECT_CALL(visitor, OnEndHeadersForStream(1));
    EXPECT_CALL(visitor, OnFrameHeader(1, 4, WINDOW_UPDATE, 0));
    EXPECT_CALL(visitor, OnWindowUpdate(1, 2000));
    EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0));
    EXPECT_CALL(visitor, OnBeginDataForStream(1, _));
    EXPECT_CALL(visitor, OnDataForStream(1, "This is the request body."));
    EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
    EXPECT_CALL(visitor, OnWindowUpdate(0, 2000));

    const int64_t result = adapter->ProcessBytes(frames);
    EXPECT_EQ(frames.size(), static_cast<size_t>(result));

    EXPECT_TRUE(adapter->want_write());

    EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
    EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
    EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS
"""


```