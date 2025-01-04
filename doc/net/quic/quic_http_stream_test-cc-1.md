Response:
The user wants to understand the functionality of the provided C++ code snippet from `net/quic/quic_http_stream_test.cc`. This is the second part of a three-part request. I need to analyze the provided code, which consists of several test cases for the `QuicHttpStream` class.

Here's a breakdown of the tasks:

1. **Summarize Functionality:** Describe the overall purpose of the code.
2. **JavaScript Relationship:** Identify if any part of the code directly interacts with or relates to JavaScript functionality.
3. **Logical Reasoning (with examples):**  If any test cases demonstrate logical flow based on inputs and expected outputs, provide examples. This involves identifying test case setup, actions performed, and verifications.
4. **User/Programming Errors:** Point out common mistakes users or programmers might make that could lead to the execution of this code or expose issues it tests.
5. **Debugging Path:** Describe the steps a user might take in a browser or application that would eventually lead to this code being executed during debugging.
6. **Part Summary:**  Provide a concise summary of the functionality covered in this specific code segment (Part 2).

**Code Analysis Strategy:**

* **Iterate through each `TEST_P` function:** Each `TEST_P` represents a specific scenario being tested. Analyze what each test is setting up, the actions it performs (e.g., sending requests, processing packets), and the assertions it makes (using `EXPECT_*`).
* **Identify key class interactions:**  Note the interactions with `QuicHttpStream`, `QuicSession`, and other related classes.
* **Focus on the tested aspects:**  Determine what specific behaviors of `QuicHttpStream` are being verified in each test.

**Pre-computation/Pre-analysis:**

* **Recognize testing framework elements:**  Understand that `TEST_P` is part of a parameterized testing framework (likely Google Test).
* **Identify common patterns:** Notice the repeated setup of requests, responses, and packet processing.
* **Infer class responsibilities:** Deduce the role of `QuicHttpStream` in handling HTTP requests over QUIC.
这是对 Chromium 网络栈中 `net/quic/quic_http_stream_test.cc` 文件的一部分代码的分析。这部分代码主要包含了一系列针对 `QuicHttpStream` 类的单元测试，用于验证其在处理 HTTP 请求和响应时的各种行为和边缘情况。

**功能归纳:**

这部分代码主要测试了 `QuicHttpStream` 在以下场景下的功能：

* **处理连续的请求和响应:** 验证了在同一连接上发送多个请求并接收响应的能力，包括会话复用 (session reuse) 的情况。
* **处理带有 Trailer 的响应:** 确认 `QuicHttpStream` 可以正确地忽略接收到的 HTTP Trailer 帧。
* **NetLog 中 Header 的处理:** 测试了在不同的 NetLog 捕获模式下，敏感的 Header 信息是否会被正确地剥离或包含。
* **处理大型响应 Header:** 验证了 `QuicHttpStream` 可以处理包含较大 Header 的响应。
* **会话在发送请求前关闭:** 测试了当 QUIC 会话在发送 HTTP 请求之前被关闭时，`QuicHttpStream` 的行为。
* **会话关闭后获取 SSL 信息:** 验证了即使在 QUIC 会话关闭后，仍然可以获取到有效的 SSL 信息。
* **获取 Alternative Service 信息:** 测试了 `QuicHttpStream` 是否能正确返回 Alternative Service 信息。
* **记录详细的 QUIC 连接错误:** 验证了当 QUIC 连接发生错误时，相关的错误信息能够被记录下来，并能通过 `PopulateNetErrorDetails` 方法获取。
* **握手未完成时记录详细的 QUIC 错误:**  测试了在 QUIC 握手尚未完成时连接关闭，是否能记录详细错误信息。
* **会话在读取响应 Header 前关闭:** 测试了当 QUIC 会话在接收响应 Header 之前被关闭时，`QuicHttpStream` 的行为。
* **发送 POST 请求:** 验证了 `QuicHttpStream` 发送带有请求体的 POST 请求的能力。
* **发送 POST 请求并接收单独的 FIN 帧:**  测试了在接收完响应体后，服务端发送单独的 FIN 帧时的处理。
* **发送分块的 POST 请求:** 验证了 `QuicHttpStream` 发送 HTTP 分块请求的能力。
* **发送分块的 POST 请求并带有最终的空数据包:** 测试了分块请求以一个空的 Data 帧结尾的情况。

**与 Javascript 的关系:**

这段 C++ 代码本身不直接涉及 JavaScript 的功能。它属于 Chromium 的网络栈部分，负责处理底层的网络通信。然而，JavaScript 在浏览器中可以通过 `fetch` API 或 `XMLHttpRequest` 等方式发起 HTTP 请求，这些请求最终会由 Chromium 的网络栈处理，其中包括 `QuicHttpStream`。

**举例说明:**

假设一个 JavaScript 代码使用 `fetch` API 发送一个带有请求体的 POST 请求：

```javascript
fetch('https://www.example.org/', {
  method: 'POST',
  body: 'This is the request body.'
})
.then(response => response.text())
.then(data => console.log(data));
```

当这个请求被发送时，Chromium 的网络栈会创建 `QuicHttpStream` 对象来处理这个请求，其中一个测试用例 `SendPostRequest` 就是在模拟和验证这种场景下的行为，例如正确发送请求头和请求体，并接收和处理响应头和响应体。

**逻辑推理 (假设输入与输出):**

以 `TEST_P(QuicHttpStreamTest, GetRequestWithTrailers)` 为例：

**假设输入:**

* 一个 "GET" 请求发送到 "https://www.example.org/"。
* 服务器响应包含状态码 200，ContentType 为 "text/plain"，以及一个包含 "Hello world!" 的响应体。
* 服务器还发送了一个包含 Trailer 的帧，其中包含 "foo: bar"。

**预期输出:**

* `ReadResponseHeaders` 成功返回，响应头中的状态码为 200，ContentType 为 "text/plain"。
* `ReadResponseBody` 第一次调用返回 "Hello world!" 的长度。
* `ReadResponseBody` 第二次调用返回 0，表示响应体已结束。
* `IsResponseBodyComplete()` 返回 `true`。
* `GetTotalReceivedBytes()` 的值会包含请求头、响应头、响应体和 Trailer 的长度，但 `QuicHttpStream` 会忽略 Trailer 的内容。

**用户或编程常见的使用错误:**

* **未正确处理异步操作:** 程序员可能会忘记 `ReadResponseHeaders` 和 `ReadResponseBody` 是异步操作，需要使用回调函数或 Promise 来处理结果。如果同步地调用这些方法并期望立即得到结果，会导致程序逻辑错误。
* **错误地期望可以读取 Trailer:**  用户或开发者可能期望 `QuicHttpStream` 能像 HTTP/2 或 HTTP/3 那样处理 Trailer，并在 `response_.headers` 中访问 Trailer 信息。然而，测试用例 `GetRequestWithTrailers` 表明 `QuicHttpStream` 目前会忽略 Trailer。
* **在会话关闭后继续操作 Stream:** 开发者可能会在 QUIC 会话已经关闭后，尝试调用 `SendRequest`、`ReadResponseHeaders` 或 `ReadResponseBody` 等方法，这会导致错误，如 `SessionClosedBeforeSendRequest` 和 `SessionClosedBeforeReadResponseHeaders` 测试用例所示。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 `https://www.example.org/` 并按下回车，或者点击了一个指向该链接的超链接。**
2. **浏览器解析 URL，确定需要建立 HTTPS 连接。**
3. **浏览器检查是否可以使用 QUIC 协议与 `www.example.org` 通信。** 这可能基于本地缓存的 ALTSVC 信息或通过 DNS 查询获取。
4. **如果可以使用 QUIC，浏览器会尝试与服务器建立 QUIC 连接。**
5. **连接建立成功后，浏览器会创建一个 `QuicHttpStream` 对象来处理这个 HTTP 请求。**
6. **`QuicHttpStream` 对象会将 HTTP 请求转换为 QUIC 帧并发送给服务器。** 这部分逻辑对应于测试用例中 `SendRequest` 的调用和模拟的包发送 (`ProcessPacket`)。
7. **服务器响应后，`QuicHttpStream` 对象会接收并解析 QUIC 帧，提取 HTTP 响应头和响应体。** 这部分对应于测试用例中 `ProcessPacket` 接收响应头和响应体的模拟。
8. **如果需要调试网络请求，开发者可以使用 Chrome DevTools 的 Network 面板。** 在 Network 面板中查看请求的详细信息，可能会发现使用了 QUIC 协议。
9. **如果需要更底层的调试，开发者可能会查看 Chromium 的 NetLog。** NetLog 会记录详细的网络事件，包括 QUIC 连接和流的信息。测试用例 `ElideHeadersInNetLog` 验证了 NetLog 中敏感信息的处理。
10. **如果开发者怀疑 `QuicHttpStream` 的行为有问题，可能会查看或运行相关的单元测试，例如 `net/quic/quic_http_stream_test.cc` 中的测试用例。** 这些测试用例模拟了各种场景，帮助开发者理解和验证 `QuicHttpStream` 的行为。

**功能归纳 (Part 2):**

总而言之，这部分 `quic_http_stream_test.cc` 的代码主要集中在测试 `QuicHttpStream` 类在处理各种 HTTP 请求和响应场景下的正确性，包括处理连续请求、忽略 Trailer、NetLog 中 Header 的处理、处理大型 Header、以及在连接生命周期的不同阶段（连接建立前后、发送请求前后、接收响应前后）的行为。此外，还测试了发送不同类型的 POST 请求（普通 POST 和分块 POST）的功能。

Prompt: 
```
这是目录为net/quic/quic_http_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
r_frame_length;
  SetResponse("200", string());
  ProcessPacket(InnerConstructResponseHeadersPacket(
      2, GetNthClientInitiatedBidirectionalStreamId(0), kFin,
      &spdy_response_header_frame_length));

  // Now that the headers have been processed, the callback will return.
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_EQ(200, response_.headers->response_code());

  // There is no body, so this should return immediately.
  EXPECT_EQ(0,
            stream_->ReadResponseBody(read_buffer_.get(), read_buffer_->size(),
                                      callback_.callback()));
  EXPECT_TRUE(stream_->IsResponseBodyComplete());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(stream_->GetLoadTimingInfo(&load_timing_info));
  ExpectLoadTimingValid(load_timing_info, /*session_reused=*/false);

  // SetResponse() again for second request as |response_headers_| was moved.
  SetResponse("200", string());
  EXPECT_THAT(stream2.ReadResponseHeaders(callback2.callback()),
              IsError(ERR_IO_PENDING));

  ProcessPacket(InnerConstructResponseHeadersPacket(
      3, GetNthClientInitiatedBidirectionalStreamId(1), kFin,
      &spdy_response_header_frame_length));

  EXPECT_THAT(callback2.WaitForResult(), IsOk());

  // There is no body, so this should return immediately.
  EXPECT_EQ(0,
            stream2.ReadResponseBody(read_buffer_.get(), read_buffer_->size(),
                                     callback2.callback()));
  EXPECT_TRUE(stream2.IsResponseBodyComplete());

  LoadTimingInfo load_timing_info2;
  EXPECT_TRUE(stream2.GetLoadTimingInfo(&load_timing_info2));
  ExpectLoadTimingValid(load_timing_info2, /*session_reused=*/true);
}

// QuicHttpStream does not currently support trailers. It should ignore
// trailers upon receiving them.
TEST_P(QuicHttpStreamTest, GetRequestWithTrailers) {
  SetRequest("GET", "/", DEFAULT_PRIORITY);
  size_t spdy_request_header_frame_length;
  int packet_number = 1;
  AddWrite(ConstructInitialSettingsPacket(packet_number++));
  AddWrite(InnerConstructRequestHeadersPacket(
      packet_number++, GetNthClientInitiatedBidirectionalStreamId(0), kFin,
      DEFAULT_PRIORITY, &spdy_request_header_frame_length));
  AddWrite(
      ConstructClientAckPacket(packet_number++, 3, 1));  // Ack the data packet.

  Initialize();

  request_.method = "GET";
  request_.url = GURL("https://www.example.org/");
  stream_->RegisterRequest(&request_);
  EXPECT_EQ(OK, stream_->InitializeStream(true, DEFAULT_PRIORITY,
                                          net_log_with_source_,
                                          callback_.callback()));

  EXPECT_EQ(OK,
            stream_->SendRequest(headers_, &response_, callback_.callback()));
  // Ack the request.
  ProcessPacket(ConstructServerAckPacket(1, 1, 1, 1));

  EXPECT_THAT(stream_->ReadResponseHeaders(callback_.callback()),
              IsError(ERR_IO_PENDING));

  SetResponse("200", string());

  // Send the response headers.
  size_t spdy_response_header_frame_length;
  ProcessPacket(ConstructResponseHeadersPacket(
      2, !kFin, &spdy_response_header_frame_length));
  // Now that the headers have been processed, the callback will return.
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  ASSERT_TRUE(response_.headers.get());
  EXPECT_EQ(200, response_.headers->response_code());
  EXPECT_TRUE(response_.headers->HasHeaderValue("Content-Type", "text/plain"));
  EXPECT_FALSE(response_.response_time.is_null());
  EXPECT_FALSE(response_.request_time.is_null());

  // Send the response body.
  const char kResponseBody[] = "Hello world!";
  std::string header = ConstructDataHeader(strlen(kResponseBody));
  ProcessPacket(ConstructServerDataPacket(3, !kFin, header + kResponseBody));
  quiche::HttpHeaderBlock trailers;
  size_t spdy_trailers_frame_length;
  trailers["foo"] = "bar";
  ProcessPacket(ConstructResponseTrailersPacket(4, kFin, std::move(trailers),
                                                &spdy_trailers_frame_length));

  // Make sure trailers are processed.
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(static_cast<int>(strlen(kResponseBody)),
            stream_->ReadResponseBody(read_buffer_.get(), read_buffer_->size(),
                                      callback_.callback()));
  EXPECT_TRUE(stream_->IsResponseBodyComplete());

  EXPECT_EQ(OK,
            stream_->ReadResponseBody(read_buffer_.get(), read_buffer_->size(),
                                      callback_.callback()));

  EXPECT_TRUE(stream_->IsResponseBodyComplete());
  EXPECT_TRUE(AtEof());

  // QuicHttpStream::GetTotalSent/ReceivedBytes currently only includes the
  // headers and payload.
  EXPECT_EQ(static_cast<int64_t>(spdy_request_header_frame_length),
            stream_->GetTotalSentBytes());
  EXPECT_EQ(static_cast<int64_t>(spdy_response_header_frame_length +
                                 strlen(kResponseBody) + header.length() +
                                 +spdy_trailers_frame_length),
            stream_->GetTotalReceivedBytes());
  // Check that NetLog was filled as expected.
  auto entries = net_log_observer_.GetEntries();
  size_t pos = ExpectLogContainsSomewhere(
      entries, /*min_offset=*/0,
      NetLogEventType::QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS,
      NetLogEventPhase::NONE);
  pos = ExpectLogContainsSomewhere(
      entries, /*min_offset=*/pos,
      NetLogEventType::QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS,
      NetLogEventPhase::NONE);
  ExpectLogContainsSomewhere(
      entries, /*min_offset=*/pos,
      NetLogEventType::QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS,
      NetLogEventPhase::NONE);
}

TEST_P(QuicHttpStreamTest, ElideHeadersInNetLog) {
  Initialize();

  net_log_observer_.SetObserverCaptureMode(NetLogCaptureMode::kDefault);

  // Send first request.
  SetRequest("GET", "/", DEFAULT_PRIORITY);
  request_.method = "GET";
  request_.url = GURL("https://www.example.org/");
  headers_.SetHeader(HttpRequestHeaders::kCookie, "secret");

  size_t spdy_request_header_frame_length;
  int outgoing_packet_number = 1;
  AddWrite(ConstructInitialSettingsPacket(outgoing_packet_number++));
  AddWrite(InnerConstructRequestHeadersPacket(
      outgoing_packet_number++, stream_id_, kFin, DEFAULT_PRIORITY,
      &spdy_request_header_frame_length));

  stream_->RegisterRequest(&request_);
  EXPECT_THAT(
      stream_->InitializeStream(true, DEFAULT_PRIORITY, net_log_with_source_,
                                callback_.callback()),
      IsOk());
  EXPECT_THAT(stream_->SendRequest(headers_, &response_, callback_.callback()),
              IsOk());
  int incoming_packet_number = 1;
  ProcessPacket(ConstructServerAckPacket(incoming_packet_number++, 1, 1,
                                         1));  // Ack the request.

  // Process first response.
  SetResponse("200", string());
  response_headers_["set-cookie"] = "secret";
  size_t spdy_response_header_frame_length;
  ProcessPacket(ConstructResponseHeadersPacket(
      incoming_packet_number++, kFin, &spdy_response_header_frame_length));
  EXPECT_THAT(stream_->ReadResponseHeaders(callback_.callback()), IsOk());

  ASSERT_TRUE(response_.headers.get());
  EXPECT_EQ(200, response_.headers->response_code());
  EXPECT_TRUE(response_.headers->HasHeaderValue("Content-Type", "text/plain"));
  EXPECT_TRUE(response_.headers->HasHeaderValue("set-cookie", "secret"));

  net_log_observer_.SetObserverCaptureMode(
      NetLogCaptureMode::kIncludeSensitive);

  // Send second request.
  quic::QuicStreamId stream_id = GetNthClientInitiatedBidirectionalStreamId(1);
  request_.url = GURL("https://www.example.org/foo");

  AddWrite(InnerConstructRequestHeadersPacket(
      outgoing_packet_number++, stream_id, kFin, DEFAULT_PRIORITY,
      &spdy_request_header_frame_length));

  auto stream = std::make_unique<QuicHttpStream>(
      session_->CreateHandle(
          url::SchemeHostPort(url::kHttpsScheme, "www.example.org/foo", 443)),
      /*dns_aliases=*/std::set<std::string>());
  stream->RegisterRequest(&request_);
  EXPECT_THAT(
      stream->InitializeStream(true, DEFAULT_PRIORITY, net_log_with_source_,
                               callback_.callback()),
      IsOk());
  EXPECT_THAT(stream->SendRequest(headers_, &response_, callback_.callback()),
              IsOk());
  ProcessPacket(ConstructServerAckPacket(incoming_packet_number++, 1, 1,
                                         1));  // Ack the request.

  // Process second response.
  SetResponse("200", string());
  response_headers_["set-cookie"] = "secret";
  ProcessPacket(InnerConstructResponseHeadersPacket(
      incoming_packet_number++, stream_id, kFin,
      &spdy_response_header_frame_length));
  EXPECT_THAT(stream->ReadResponseHeaders(callback_.callback()), IsOk());

  ASSERT_TRUE(response_.headers.get());
  EXPECT_EQ(200, response_.headers->response_code());
  EXPECT_TRUE(response_.headers->HasHeaderValue("Content-Type", "text/plain"));
  EXPECT_TRUE(response_.headers->HasHeaderValue("set-cookie", "secret"));

  EXPECT_TRUE(AtEof());

  // Check that sensitive header value were stripped
  // for the first transaction (logged with NetLogCaptureMode::kDefault)
  // but not for the second (logged with NetLogCaptureMode::kIncludeSensitive).
  auto entries =
      net_log_observer_.GetEntriesWithType(NetLogEventType::HTTP3_HEADERS_SENT);
  ASSERT_EQ(2u, entries.size());
  EXPECT_TRUE(
      CheckHeader(entries[0].params, "cookie", "[6 bytes were stripped]"));
  EXPECT_TRUE(CheckHeader(entries[1].params, "cookie", "secret"));

  entries = net_log_observer_.GetEntriesWithType(
      NetLogEventType::HTTP3_HEADERS_DECODED);
  ASSERT_EQ(2u, entries.size());
  EXPECT_TRUE(
      CheckHeader(entries[0].params, "set-cookie", "[6 bytes were stripped]"));
  EXPECT_TRUE(CheckHeader(entries[1].params, "set-cookie", "secret"));
}

// Regression test for http://crbug.com/288128
TEST_P(QuicHttpStreamTest, GetRequestLargeResponse) {
  SetRequest("GET", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  int packet_number = 1;
  AddWrite(ConstructInitialSettingsPacket(packet_number++));
  AddWrite(InnerConstructRequestHeadersPacket(
      packet_number++, GetNthClientInitiatedBidirectionalStreamId(0), kFin,
      DEFAULT_PRIORITY, &spdy_request_headers_frame_length));
  Initialize();

  request_.method = "GET";
  request_.url = GURL("https://www.example.org/");

  stream_->RegisterRequest(&request_);
  EXPECT_EQ(OK, stream_->InitializeStream(true, DEFAULT_PRIORITY,
                                          net_log_with_source_,
                                          callback_.callback()));
  EXPECT_EQ(OK,
            stream_->SendRequest(headers_, &response_, callback_.callback()));

  // Ack the request.
  ProcessPacket(ConstructServerAckPacket(1, 1, 1, 1));

  EXPECT_THAT(stream_->ReadResponseHeaders(callback_.callback()),
              IsError(ERR_IO_PENDING));

  response_headers_[":status"] = "200";
  response_headers_[":version"] = "HTTP/1.1";
  response_headers_["content-type"] = "text/plain";
  response_headers_["big6"] = string(1000, 'x');  // Lots of x's.

  size_t spdy_response_headers_frame_length;
  ProcessPacket(ConstructResponseHeadersPacket(
      2, kFin, &spdy_response_headers_frame_length));

  // Now that the headers have been processed, the callback will return.
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  ASSERT_TRUE(response_.headers.get());
  EXPECT_EQ(200, response_.headers->response_code());
  EXPECT_TRUE(response_.headers->HasHeaderValue("Content-Type", "text/plain"));

  // There is no body, so this should return immediately.
  EXPECT_EQ(0,
            stream_->ReadResponseBody(read_buffer_.get(), read_buffer_->size(),
                                      callback_.callback()));
  EXPECT_TRUE(stream_->IsResponseBodyComplete());
  EXPECT_TRUE(AtEof());

  // QuicHttpStream::GetTotalSent/ReceivedBytes currently only includes the
  // headers and payload.
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length),
            stream_->GetTotalSentBytes());
  EXPECT_EQ(static_cast<int64_t>(spdy_response_headers_frame_length),
            stream_->GetTotalReceivedBytes());
}

// Regression test for http://crbug.com/409101
TEST_P(QuicHttpStreamTest, SessionClosedBeforeSendRequest) {
  SetRequest("GET", "/", DEFAULT_PRIORITY);
  Initialize();

  request_.method = "GET";
  request_.url = GURL("https://www.example.org/");

  stream_->RegisterRequest(&request_);
  EXPECT_EQ(OK, stream_->InitializeStream(true, DEFAULT_PRIORITY,
                                          net_log_with_source_,
                                          callback_.callback()));

  session_->connection()->CloseConnection(
      quic::QUIC_NO_ERROR, "test", quic::ConnectionCloseBehavior::SILENT_CLOSE);

  EXPECT_EQ(ERR_CONNECTION_CLOSED,
            stream_->SendRequest(headers_, &response_, callback_.callback()));

  EXPECT_EQ(0, stream_->GetTotalSentBytes());
  EXPECT_EQ(0, stream_->GetTotalReceivedBytes());
}

// Regression test for http://crbug.com/584441
TEST_P(QuicHttpStreamTest, GetSSLInfoAfterSessionClosed) {
  SetRequest("GET", "/", DEFAULT_PRIORITY);
  Initialize();

  request_.method = "GET";
  request_.url = GURL("https://www.example.org/");

  stream_->RegisterRequest(&request_);
  EXPECT_EQ(OK, stream_->InitializeStream(true, DEFAULT_PRIORITY,
                                          net_log_with_source_,
                                          callback_.callback()));

  SSLInfo ssl_info;
  EXPECT_FALSE(ssl_info.is_valid());
  stream_->GetSSLInfo(&ssl_info);
  EXPECT_TRUE(ssl_info.is_valid());

  session_->connection()->CloseConnection(
      quic::QUIC_NO_ERROR, "test", quic::ConnectionCloseBehavior::SILENT_CLOSE);

  SSLInfo ssl_info2;
  stream_->GetSSLInfo(&ssl_info2);
  EXPECT_TRUE(ssl_info2.is_valid());
}

TEST_P(QuicHttpStreamTest, GetAlternativeService) {
  SetRequest("GET", "/", DEFAULT_PRIORITY);
  Initialize();

  request_.method = "GET";
  request_.url = GURL("https://www.example.org/");

  stream_->RegisterRequest(&request_);
  EXPECT_EQ(OK, stream_->InitializeStream(true, DEFAULT_PRIORITY,
                                          net_log_with_source_,
                                          callback_.callback()));

  AlternativeService alternative_service;
  EXPECT_TRUE(stream_->GetAlternativeService(&alternative_service));
  EXPECT_EQ(AlternativeService(kProtoQUIC, "www.example.org", 443),
            alternative_service);

  session_->connection()->CloseConnection(
      quic::QUIC_NO_ERROR, "test", quic::ConnectionCloseBehavior::SILENT_CLOSE);

  AlternativeService alternative_service2;
  EXPECT_TRUE(stream_->GetAlternativeService(&alternative_service2));
  EXPECT_EQ(AlternativeService(kProtoQUIC, "www.example.org", 443),
            alternative_service2);
}

TEST_P(QuicHttpStreamTest, LogGranularQuicConnectionError) {
  SetRequest("GET", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  int packet_number = 1;
  AddWrite(ConstructInitialSettingsPacket(packet_number++));
  AddWrite(InnerConstructRequestHeadersPacket(
      packet_number++, GetNthClientInitiatedBidirectionalStreamId(0), kFin,
      DEFAULT_PRIORITY, &spdy_request_headers_frame_length));
  AddWrite(ConstructAckAndRstStreamPacket(3));
  Initialize();

  request_.method = "GET";
  request_.url = GURL("https://www.example.org/");

  stream_->RegisterRequest(&request_);
  EXPECT_EQ(OK, stream_->InitializeStream(true, DEFAULT_PRIORITY,
                                          net_log_with_source_,
                                          callback_.callback()));
  EXPECT_EQ(OK,
            stream_->SendRequest(headers_, &response_, callback_.callback()));

  // Ack the request.
  ProcessPacket(ConstructServerAckPacket(1, 1, 1, 1));
  EXPECT_THAT(stream_->ReadResponseHeaders(callback_.callback()),
              IsError(ERR_IO_PENDING));

  quic::QuicConnectionCloseFrame frame;
  frame.quic_error_code = quic::QUIC_PEER_GOING_AWAY;
  session_->connection()->OnConnectionCloseFrame(frame);

  NetErrorDetails details;
  EXPECT_EQ(quic::QUIC_NO_ERROR, details.quic_connection_error);
  stream_->PopulateNetErrorDetails(&details);
  EXPECT_EQ(quic::QUIC_PEER_GOING_AWAY, details.quic_connection_error);
}

TEST_P(QuicHttpStreamTest, LogGranularQuicErrorIfHandshakeNotConfirmed) {
  // By default the test setup defaults handshake to be confirmed. Manually set
  // it to be not confirmed.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);

  SetRequest("GET", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  int packet_number = 1;
  AddWrite(ConstructInitialSettingsPacket(packet_number++));
  AddWrite(InnerConstructRequestHeadersPacket(
      packet_number++, GetNthClientInitiatedBidirectionalStreamId(0), kFin,
      DEFAULT_PRIORITY, &spdy_request_headers_frame_length));
  Initialize();

  request_.method = "GET";
  request_.url = GURL("https://www.example.org/");

  stream_->RegisterRequest(&request_);
  EXPECT_EQ(OK, stream_->InitializeStream(true, DEFAULT_PRIORITY,
                                          net_log_with_source_,
                                          callback_.callback()));
  EXPECT_EQ(OK,
            stream_->SendRequest(headers_, &response_, callback_.callback()));

  // Ack the request.
  ProcessPacket(ConstructServerAckPacket(1, 1, 1, 1));
  EXPECT_THAT(stream_->ReadResponseHeaders(callback_.callback()),
              IsError(ERR_IO_PENDING));

  quic::QuicConnectionCloseFrame frame;
  frame.quic_error_code = quic::QUIC_PEER_GOING_AWAY;
  session_->connection()->OnConnectionCloseFrame(frame);

  NetErrorDetails details;
  stream_->PopulateNetErrorDetails(&details);
  EXPECT_EQ(quic::QUIC_PEER_GOING_AWAY, details.quic_connection_error);
}

// Regression test for http://crbug.com/409871
TEST_P(QuicHttpStreamTest, SessionClosedBeforeReadResponseHeaders) {
  SetRequest("GET", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  int packet_number = 1;
  AddWrite(ConstructInitialSettingsPacket(packet_number++));
  AddWrite(InnerConstructRequestHeadersPacket(
      packet_number++, GetNthClientInitiatedBidirectionalStreamId(0), kFin,
      DEFAULT_PRIORITY, &spdy_request_headers_frame_length));
  Initialize();

  request_.method = "GET";
  request_.url = GURL("https://www.example.org/");

  stream_->RegisterRequest(&request_);
  EXPECT_EQ(OK, stream_->InitializeStream(true, DEFAULT_PRIORITY,
                                          net_log_with_source_,
                                          callback_.callback()));

  EXPECT_EQ(OK,
            stream_->SendRequest(headers_, &response_, callback_.callback()));

  session_->connection()->CloseConnection(
      quic::QUIC_NO_ERROR, "test", quic::ConnectionCloseBehavior::SILENT_CLOSE);

  EXPECT_NE(OK, stream_->ReadResponseHeaders(callback_.callback()));

  // QuicHttpStream::GetTotalSent/ReceivedBytes currently only includes the
  // headers and payload.
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length),
            stream_->GetTotalSentBytes());
  EXPECT_EQ(0, stream_->GetTotalReceivedBytes());
}

TEST_P(QuicHttpStreamTest, SendPostRequest) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  int packet_number = 1;
  AddWrite(ConstructInitialSettingsPacket(packet_number++));

  std::string header = ConstructDataHeader(strlen(kUploadData));
  AddWrite(ConstructRequestHeadersAndDataFramesPacket(
      packet_number++, GetNthClientInitiatedBidirectionalStreamId(0), kFin,
      DEFAULT_PRIORITY, &spdy_request_headers_frame_length,
      {header, kUploadData}));

  AddWrite(ConstructClientAckPacket(packet_number++, 3, 1));

  Initialize();

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring(kUploadData)));
  upload_data_stream_ =
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers), 0);
  request_.method = "POST";
  request_.url = GURL("https://www.example.org/");
  request_.upload_data_stream = upload_data_stream_.get();
  ASSERT_THAT(request_.upload_data_stream->Init(CompletionOnceCallback(),
                                                NetLogWithSource()),
              IsOk());

  stream_->RegisterRequest(&request_);
  EXPECT_EQ(OK, stream_->InitializeStream(false, DEFAULT_PRIORITY,
                                          net_log_with_source_,
                                          callback_.callback()));
  EXPECT_EQ(OK,
            stream_->SendRequest(headers_, &response_, callback_.callback()));

  // Ack both packets in the request.
  ProcessPacket(ConstructServerAckPacket(1, 1, 1, 1));

  // Send the response headers (but not the body).
  SetResponse("200", string());
  size_t spdy_response_headers_frame_length;
  ProcessPacket(ConstructResponseHeadersPacket(
      2, !kFin, &spdy_response_headers_frame_length));

  // The headers have already arrived.
  EXPECT_THAT(stream_->ReadResponseHeaders(callback_.callback()), IsOk());
  ASSERT_TRUE(response_.headers.get());
  EXPECT_EQ(200, response_.headers->response_code());
  EXPECT_TRUE(response_.headers->HasHeaderValue("Content-Type", "text/plain"));

  // Send the response body.
  const char kResponseBody[] = "Hello world!";
  std::string header2 = ConstructDataHeader(strlen(kResponseBody));
  ProcessPacket(ConstructServerDataPacket(3, kFin, header2 + kResponseBody));
  // Since the body has already arrived, this should return immediately.
  EXPECT_EQ(static_cast<int>(strlen(kResponseBody)),
            stream_->ReadResponseBody(read_buffer_.get(), read_buffer_->size(),
                                      callback_.callback()));
  EXPECT_EQ(0,
            stream_->ReadResponseBody(read_buffer_.get(), read_buffer_->size(),
                                      callback_.callback()));

  EXPECT_TRUE(stream_->IsResponseBodyComplete());
  EXPECT_TRUE(AtEof());

  // QuicHttpStream::GetTotalSent/ReceivedBytes currently only includes the
  // headers and payload.
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length +
                                 strlen(kUploadData) + header.length()),
            stream_->GetTotalSentBytes());
  EXPECT_EQ(static_cast<int64_t>(spdy_response_headers_frame_length +
                                 strlen(kResponseBody) + header2.length()),
            stream_->GetTotalReceivedBytes());
}

TEST_P(QuicHttpStreamTest, SendPostRequestAndReceiveSoloFin) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  int packet_number = 1;
  AddWrite(ConstructInitialSettingsPacket(packet_number++));
  std::string header = ConstructDataHeader(strlen(kUploadData));
  AddWrite(ConstructRequestHeadersAndDataFramesPacket(
      packet_number++, GetNthClientInitiatedBidirectionalStreamId(0), kFin,
      DEFAULT_PRIORITY, &spdy_request_headers_frame_length,
      {header, kUploadData}));

  AddWrite(ConstructClientAckPacket(packet_number++, 3, 1));

  Initialize();

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring(kUploadData)));
  upload_data_stream_ =
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers), 0);
  request_.method = "POST";
  request_.url = GURL("https://www.example.org/");
  request_.upload_data_stream = upload_data_stream_.get();
  ASSERT_THAT(request_.upload_data_stream->Init(CompletionOnceCallback(),
                                                NetLogWithSource()),
              IsOk());

  stream_->RegisterRequest(&request_);
  EXPECT_EQ(OK, stream_->InitializeStream(false, DEFAULT_PRIORITY,
                                          net_log_with_source_,
                                          callback_.callback()));
  EXPECT_EQ(OK,
            stream_->SendRequest(headers_, &response_, callback_.callback()));

  // Ack both packets in the request.
  ProcessPacket(ConstructServerAckPacket(1, 1, 1, 1));

  // Send the response headers (but not the body).
  SetResponse("200", string());
  size_t spdy_response_headers_frame_length;
  ProcessPacket(ConstructResponseHeadersPacket(
      2, !kFin, &spdy_response_headers_frame_length));

  // The headers have already arrived.
  EXPECT_THAT(stream_->ReadResponseHeaders(callback_.callback()), IsOk());
  ASSERT_TRUE(response_.headers.get());
  EXPECT_EQ(200, response_.headers->response_code());
  EXPECT_TRUE(response_.headers->HasHeaderValue("Content-Type", "text/plain"));

  // Send the response body.
  const char kResponseBody[] = "Hello world!";
  std::string header2 = ConstructDataHeader(strlen(kResponseBody));
  ProcessPacket(ConstructServerDataPacket(3, !kFin, header2 + kResponseBody));
  // Since the body has already arrived, this should return immediately.
  EXPECT_EQ(static_cast<int>(strlen(kResponseBody)),
            stream_->ReadResponseBody(read_buffer_.get(), read_buffer_->size(),
                                      callback_.callback()));
  ProcessPacket(ConstructServerDataPacket(4, kFin, ""));
  EXPECT_EQ(0,
            stream_->ReadResponseBody(read_buffer_.get(), read_buffer_->size(),
                                      callback_.callback()));

  EXPECT_TRUE(stream_->IsResponseBodyComplete());
  EXPECT_TRUE(AtEof());

  // QuicHttpStream::GetTotalSent/ReceivedBytes currently only includes the
  // headers and payload.
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length +
                                 strlen(kUploadData) + header.length()),
            stream_->GetTotalSentBytes());
  EXPECT_EQ(static_cast<int64_t>(spdy_response_headers_frame_length +
                                 strlen(kResponseBody) + header2.length()),
            stream_->GetTotalReceivedBytes());
}

TEST_P(QuicHttpStreamTest, SendChunkedPostRequest) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t chunk_size = strlen(kUploadData);
  size_t spdy_request_headers_frame_length;
  int packet_number = 1;
  AddWrite(ConstructInitialSettingsPacket(packet_number++));
  std::string header = ConstructDataHeader(chunk_size);
  AddWrite(ConstructRequestHeadersAndDataFramesPacket(
      packet_number++, GetNthClientInitiatedBidirectionalStreamId(0), !kFin,
      DEFAULT_PRIORITY, &spdy_request_headers_frame_length,
      {header, kUploadData}));
  AddWrite(
      ConstructClientDataPacket(packet_number++, kFin, {header + kUploadData}));

  AddWrite(ConstructClientAckPacket(packet_number++, 3, 1));
  Initialize();

  upload_data_stream_ = std::make_unique<ChunkedUploadDataStream>(0);
  auto* chunked_upload_stream =
      static_cast<ChunkedUploadDataStream*>(upload_data_stream_.get());
  chunked_upload_stream->AppendData(base::byte_span_from_cstring(kUploadData),
                                    false);

  request_.method = "POST";
  request_.url = GURL("https://www.example.org/");
  request_.upload_data_stream = upload_data_stream_.get();
  ASSERT_EQ(OK, request_.upload_data_stream->Init(
                    TestCompletionCallback().callback(), NetLogWithSource()));

  stream_->RegisterRequest(&request_);
  ASSERT_EQ(OK, stream_->InitializeStream(false, DEFAULT_PRIORITY,
                                          net_log_with_source_,
                                          callback_.callback()));
  ASSERT_EQ(ERR_IO_PENDING,
            stream_->SendRequest(headers_, &response_, callback_.callback()));

  chunked_upload_stream->AppendData(base::byte_span_from_cstring(kUploadData),
                                    true);
  EXPECT_THAT(callback_.WaitForResult(), IsOk());

  // Ack both packets in the request.
  ProcessPacket(ConstructServerAckPacket(1, 1, 1, 1));

  // Send the response headers (but not the body).
  SetResponse("200", string());
  size_t spdy_response_headers_frame_length;
  ProcessPacket(ConstructResponseHeadersPacket(
      2, !kFin, &spdy_response_headers_frame_length));

  // The headers have already arrived.
  EXPECT_THAT(stream_->ReadResponseHeaders(callback_.callback()), IsOk());
  ASSERT_TRUE(response_.headers.get());
  EXPECT_EQ(200, response_.headers->response_code());
  EXPECT_TRUE(response_.headers->HasHeaderValue("Content-Type", "text/plain"));

  // Send the response body.
  const char kResponseBody[] = "Hello world!";
  std::string header2 = ConstructDataHeader(strlen(kResponseBody));
  ProcessPacket(ConstructServerDataPacket(3, kFin, header2 + kResponseBody));

  // Since the body has already arrived, this should return immediately.
  ASSERT_EQ(static_cast<int>(strlen(kResponseBody)),
            stream_->ReadResponseBody(read_buffer_.get(), read_buffer_->size(),
                                      callback_.callback()));

  EXPECT_TRUE(stream_->IsResponseBodyComplete());
  EXPECT_TRUE(AtEof());

  // QuicHttpStream::GetTotalSent/ReceivedBytes currently only includes the
  // headers and payload.
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length +
                                 strlen(kUploadData) * 2 + header.length() * 2),
            stream_->GetTotalSentBytes());
  EXPECT_EQ(static_cast<int64_t>(spdy_response_headers_frame_length +
                                 strlen(kResponseBody) + header2.length()),
            stream_->GetTotalReceivedBytes());
}

TEST_P(QuicHttpStreamTest, SendChunkedPostRequestWithFinalEmptyDataPacket) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t chunk_size = strlen(kUploadData);
  size_t spdy_request_headers_frame_length;
  int packet_number = 1;
  AddWrite(ConstructInitialSettingsPacket(packet_number++));
  std::string header = ConstructDataHeader(chunk_size);

  AddWrite(ConstructRequestHeadersAndDataFramesPacket(
      packet_number++, GetNthClientInitiatedBidirectionalStreamId(0), !kFin,
      DEFAULT_PRIORITY, &spdy_request_headers_frame_length,
      {header, kUploadData}));
  AddWrite(ConstructClientDataPacket(packet_number++, kFin, ""));
  AddWrite(ConstructClientAckPacket(packet_number++, 3, 1));
  Initialize();

  upload_data_stream_ = std::make_unique<ChunkedUploadDataStream>(0);
  auto* chunked_upload_stream =
      static_cast<ChunkedUploadDataStream*>(upload_data_stream_.get());
  chunked_upload_stream->AppendData(base::byte_span_from_cstring(kUploadData),
                                    false);

  request_.method = "POST";
  request_.url = GURL("https://www.example.org/");
  request_.upload_data_stream = upload_data_stream_.get();
  ASSERT_EQ(OK, request_.upload_data_stream->Init(
                    TestCompletionCallback().callback(), NetLogWithSource()));

  stream_->RegisterRequest(&request_);
  ASSERT_EQ(OK, stream_->InitializeStream(false, DEFAULT_PRIORITY,
                                          net_log_with_source_,
                                          callback_.callback()));
  ASSERT_EQ(ERR_IO_PENDING,
            stream_->SendRequest(headers_, &response_, callback_.callback()));

  chunked_upload_stream->AppendData(base::byte_span_from_cstring(""), true);
  EXPECT_THAT(callback_.WaitForResult(), IsOk());

  ProcessPacket(ConstructServerAckPacket(1, 1, 1, 1));

  // Send the response headers (but not the body).
  SetResponse("200", string());
  size_t spdy_response_headers_frame_length;
  ProcessPacket(ConstructResponseHeadersPacket(
      2, !kFin, &spdy_response_headers_frame_length));

  // The headers have already arrived.
  EXPECT_THAT(stream_->ReadResponseHeaders(callback_.callback()), IsOk());
  ASSERT_TRUE(response_.headers.get());
  EXPECT_EQ(200, response_.headers->response_code());
  EXPECT_TRUE(response_.headers->HasHeaderValue("Content-Type", "text/plain"));

  // Send the response body.
  const char kResponseBody[] = "Hello world!";
  std::string header2 = ConstructDataHeader(strlen(kResponseBody));
  ProcessPacket(ConstructServerDataPacket(3, kFin, header2 + kResponseBody));

  // The body has arrived, but it is delivered asynchronously
  ASSERT_EQ(static_cast<int>(strlen(kResponseBody)),
            stream_->ReadResponseBody(read_buffer_.get(), read_buffer_->size(),
                                      callback_.callback()));
  EXPECT_TRUE(stream_->IsResponseBodyComplete());
  EXPECT_TRUE(AtEof());

  // QuicHttpStream::GetTotalSent/ReceivedBytes currently only includes the
  // headers and payload.
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length +
                                 strlen(kUploadData) + header.length()),
            stream_->GetTotalSentBytes());
  EXPECT_EQ(static_cast<int64_t>(spdy_response_headers_fr
"""


```