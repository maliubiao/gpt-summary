Response:
The user wants to understand the functionality of the provided C++ code snippet from `net/quic/quic_http_stream_test.cc`. This is the third part of a three-part request, so I need to focus on summarizing the overall purpose of the file, considering the information likely provided in the previous parts.

**Plan:**

1. **Identify the Core Functionality:**  The file name and the `TEST_P` macros clearly indicate that this file contains unit tests for `QuicHttpStream`.
2. **Analyze Test Cases:** Briefly review the names of the test cases to grasp the range of functionalities being tested. Look for common patterns and categories of tests.
3. **Summarize the Functionality:** Based on the test cases, articulate the main goal of the `QuicHttpStream` class and the purpose of these tests.
4. **Address Specific Questions:**  Since this is part 3, and the previous parts might have covered details about JavaScript interaction, logical reasoning, and common errors, I will briefly reiterate the overall findings regarding these aspects based on *this* snippet, while acknowledging the possibility of more information in previous parts.
5. **User Actions and Debugging:** Briefly discuss how a developer might end up in this specific test file during debugging.
这是 Chromium 网络栈中 `net/quic/quic_http_stream_test.cc` 文件的第三部分，其主要功能是**测试 `QuicHttpStream` 类的各种行为和功能**。

**归纳一下它的功能：**

总的来说，这个文件通过一系列的单元测试，验证了 `QuicHttpStream` 类在不同场景下的正确性和健壮性。 这些测试涵盖了以下主要方面：

*   **发送带 Chunked 编码的 POST 请求:** 测试了分块上传数据流的各种情况，包括只有一个空数据包的情况以及被 `RST_STREAM` 帧中止的情况。
*   **提前销毁 Stream:** 测试了在请求处理过程中，`QuicHttpStream` 对象被提前销毁的情况，以及对已发送和接收字节数的统计。
*   **设置优先级:** 验证了 `QuicHttpStream` 可以正确处理和传递请求的优先级。
*   **会话关闭的情况:**  详细测试了在请求的不同阶段（发送 Headers 前、发送 Body 前、发送 Body 过程中）会话被关闭的情况，以及 `QuicHttpStream` 如何处理这些异常。
*   **数据读取错误:**  测试了在读取上传数据时发生同步或异步错误的情况下，`QuicHttpStream` 的行为，包括发送 `RST_STREAM` 帧。
*   **接收 Accept-CH Via ALPS:** 验证了 `QuicHttpStream` 能否正确处理通过 ALPS 接收到的 `Accept-CH` 信息。
*   **统计发送和接收的字节数:**  许多测试用例都验证了 `GetTotalSentBytes()` 和 `GetTotalReceivedBytes()` 方法的返回值是否正确。

**与 JavaScript 的功能关系：**

在这个代码片段中，并没有直接体现与 JavaScript 功能的关联。`QuicHttpStream` 主要负责在 C++ 网络栈中处理 QUIC 协议上的 HTTP 流。JavaScript 通常通过浏览器提供的 API（例如 `fetch`）与底层网络栈交互，但 `QuicHttpStream` 的具体实现细节对 JavaScript 是透明的。

**逻辑推理（假设输入与输出）：**

考虑 `TEST_P(QuicHttpStreamTest, SendChunkedPostRequestWithOneEmptyDataPacket)` 这个测试用例：

*   **假设输入:**
    *   一个 "POST" 请求到 "/" 路径。
    *   一个空的 Chunked 上传数据流。
    *   服务端返回 "200 OK" 状态码和 "text/plain" 的 Content-Type。
    *   服务端返回 "Hello world!" 的响应体。
*   **预期输出:**
    *   客户端成功发送请求头和一个空的 data 帧。
    *   客户端成功接收到响应头，状态码为 200，Content-Type 为 "text/plain"。
    *   客户端成功接收到响应体 "Hello world!"。
    *   `stream_->IsResponseBodyComplete()` 返回 true。
    *   `AtEof()` 返回 true。
    *   `stream_->GetTotalSentBytes()` 等于请求头的大小。
    *   `stream_->GetTotalReceivedBytes()` 等于响应头大小加上响应体大小。

**用户或编程常见的使用错误：**

*   **过早地结束 Chunked 上传流:**  如果用户在应该发送更多数据时就调用 `AppendData` 并设置 `true` (表示结束)，服务端可能会因为接收到不完整的请求体而报错。例如，如果用户期望发送 100KB 的数据，但在发送 50KB 后就结束了流。
*   **未正确处理异步操作:** `QuicHttpStream` 的很多操作是异步的，例如 `SendRequest` 和 `ReadResponseBody`。如果用户没有正确使用回调函数等待操作完成，可能会导致程序逻辑错误或数据丢失。
*   **在 Stream 销毁后尝试操作:**  如果在 `QuicHttpStream` 对象被销毁后尝试调用其方法（例如 `ReadResponseHeaders`），会导致程序崩溃或未定义的行为。`TEST_P(QuicHttpStreamTest, DestroyedEarly)` 就是为了测试这种情况。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户在浏览器中发起一个 HTTP/3 请求:** 用户在浏览器地址栏输入 URL 或点击链接，浏览器协商使用 QUIC 协议。
2. **请求经过网络栈:**  浏览器的网络模块将请求传递到操作系统的网络栈。
3. **QUIC 会话建立:**  如果与服务器的 QUIC 会话尚未建立，则会进行握手。
4. **创建 `QuicHttpStream` 对象:**  一旦会话建立，网络栈会创建一个 `QuicHttpStream` 对象来处理该 HTTP 请求。
5. **发送请求头和 Body (如果存在):**  `QuicHttpStream` 负责将请求头和 Body 数据（根据需要进行分块）封装成 QUIC 数据包发送给服务器。
6. **接收响应头和 Body:** `QuicHttpStream` 接收来自服务器的 QUIC 数据包，并解析出响应头和 Body。
7. **在开发或测试过程中遇到问题:**  开发者在测试或调试基于 QUIC 的 HTTP 应用时，可能会遇到连接问题、数据传输错误、或者响应解析错误。
8. **查看网络日志或进行代码调试:**  开发者可能会启用 Chrome 的网络日志 (chrome://net-export/) 来查看 QUIC 连接的详细信息。如果需要深入了解 `QuicHttpStream` 的行为，他们可能会查看 `net/quic` 目录下的源代码，包括 `quic_http_stream_test.cc`，来理解其内部实现和测试用例。
9. **运行或阅读单元测试:** 开发者可能会运行 `quic_http_stream_test.cc` 中的特定测试用例，或者阅读代码来理解在特定场景下 `QuicHttpStream` 的预期行为，例如，当他们怀疑 Chunked POST 请求处理有问题时，可能会关注 `SendChunkedPostRequestWithOneEmptyDataPacket` 或 `SendChunkedPostRequestAbortedByResetStream` 这类测试。

总而言之，`net/quic/quic_http_stream_test.cc` 是一个至关重要的测试文件，用于确保 Chromium 网络栈中 `QuicHttpStream` 类的正确性和可靠性，涵盖了各种正常的和异常的场景。 开发者可以通过阅读和运行这些测试用例来理解 `QuicHttpStream` 的工作原理，并在遇到问题时作为调试的参考。

### 提示词
```
这是目录为net/quic/quic_http_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
ame_length +
                                 strlen(kResponseBody) + header2.length()),
            stream_->GetTotalReceivedBytes());
}

TEST_P(QuicHttpStreamTest, SendChunkedPostRequestWithOneEmptyDataPacket) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  int packet_number = 1;
  AddWrite(ConstructInitialSettingsPacket(packet_number++));
  AddWrite(InnerConstructRequestHeadersPacket(
      packet_number++, GetNthClientInitiatedBidirectionalStreamId(0), !kFin,
      DEFAULT_PRIORITY, &spdy_request_headers_frame_length));
  AddWrite(ConstructClientDataPacket(packet_number++, kFin, ""));
  AddWrite(ConstructClientAckPacket(packet_number++, 3, 1));
  Initialize();

  upload_data_stream_ = std::make_unique<ChunkedUploadDataStream>(0);
  auto* chunked_upload_stream =
      static_cast<ChunkedUploadDataStream*>(upload_data_stream_.get());

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
  std::string header = ConstructDataHeader(strlen(kResponseBody));
  ProcessPacket(ConstructServerDataPacket(3, kFin, header + kResponseBody));

  // The body has arrived, but it is delivered asynchronously
  ASSERT_EQ(static_cast<int>(strlen(kResponseBody)),
            stream_->ReadResponseBody(read_buffer_.get(), read_buffer_->size(),
                                      callback_.callback()));

  EXPECT_TRUE(stream_->IsResponseBodyComplete());
  EXPECT_TRUE(AtEof());

  // QuicHttpStream::GetTotalSent/ReceivedBytes currently only includes the
  // headers and payload.
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length),
            stream_->GetTotalSentBytes());
  EXPECT_EQ(static_cast<int64_t>(spdy_response_headers_frame_length +
                                 strlen(kResponseBody) + header.length()),
            stream_->GetTotalReceivedBytes());
}

TEST_P(QuicHttpStreamTest, SendChunkedPostRequestAbortedByResetStream) {
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
  AddWrite(ConstructClientAckPacket(packet_number++, 3, 1));
  AddWrite(client_maker_.Packet(packet_number++)
               .AddAckFrame(/*first_received=*/1, /*largest_received=*/4,
                            /*smallest_received=*/1)
               .AddRstStreamFrame(stream_id_, quic::QUIC_STREAM_NO_ERROR)
               .Build());

  Initialize();

  upload_data_stream_ = std::make_unique<ChunkedUploadDataStream>(0);
  auto* chunked_upload_stream =
      static_cast<ChunkedUploadDataStream*>(upload_data_stream_.get());
  chunked_upload_stream->AppendData(base::byte_span_from_cstring(kUploadData),
                                    false);

  request_.method = "POST";
  request_.url = GURL("https://www.example.org/");
  request_.upload_data_stream = upload_data_stream_.get();
  ASSERT_THAT(request_.upload_data_stream->Init(
                  TestCompletionCallback().callback(), NetLogWithSource()),
              IsOk());
  stream_->RegisterRequest(&request_);
  ASSERT_THAT(
      stream_->InitializeStream(false, DEFAULT_PRIORITY, net_log_with_source_,
                                callback_.callback()),
      IsOk());
  ASSERT_THAT(stream_->SendRequest(headers_, &response_, callback_.callback()),
              IsError(ERR_IO_PENDING));

  // Ack both packets in the request.
  ProcessPacket(ConstructServerAckPacket(1, 1, 1, 1));

  // Send the response headers (but not the body).
  SetResponse("200", string());
  size_t spdy_response_headers_frame_length;
  ProcessPacket(ConstructResponseHeadersPacket(
      2, !kFin, &spdy_response_headers_frame_length));

  // Send the response body.
  const char kResponseBody[] = "Hello world!";
  std::string header2 = ConstructDataHeader(strlen(kResponseBody));
  ProcessPacket(ConstructServerDataPacket(3, kFin, header2 + kResponseBody));

  // The server uses a STOP_SENDING frame to notify the client that it does not
  // need any further data to fully process the request.
  ProcessPacket(server_maker_.Packet(4)
                    .AddStopSendingFrame(stream_id_, quic::QUIC_STREAM_NO_ERROR)
                    .Build());

  // Finish feeding request body to QuicHttpStream.  Data will be discarded.
  chunked_upload_stream->AppendData(base::byte_span_from_cstring(kUploadData),
                                    true);
  EXPECT_THAT(callback_.WaitForResult(), IsOk());

  // Verify response.
  EXPECT_THAT(stream_->ReadResponseHeaders(callback_.callback()), IsOk());
  ASSERT_TRUE(response_.headers.get());
  EXPECT_EQ(200, response_.headers->response_code());
  EXPECT_TRUE(response_.headers->HasHeaderValue("Content-Type", "text/plain"));
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
  EXPECT_EQ(static_cast<int64_t>(spdy_response_headers_frame_length +
                                 strlen(kResponseBody) + header2.length()),
            stream_->GetTotalReceivedBytes());
}

TEST_P(QuicHttpStreamTest, DestroyedEarly) {
  SetRequest("GET", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  int packet_number = 1;
  AddWrite(ConstructInitialSettingsPacket(packet_number++));
  AddWrite(InnerConstructRequestHeadersPacket(
      packet_number++, GetNthClientInitiatedBidirectionalStreamId(0), kFin,
      DEFAULT_PRIORITY, &spdy_request_headers_frame_length));
  AddWrite(ConstructAckAndRstStreamPacket(packet_number++));
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
  EXPECT_THAT(stream_->ReadResponseHeaders(
                  base::BindOnce(&QuicHttpStreamTest::CloseStream,
                                 base::Unretained(this), stream_.get())),
              IsError(ERR_IO_PENDING));

  // Send the response with a body.
  SetResponse("404", "hello world!");
  // In the course of processing this packet, the QuicHttpStream close itself.
  size_t response_size = 0;
  ProcessPacket(ConstructResponseHeadersPacket(2, !kFin, &response_size));

  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(AtEof());

  // QuicHttpStream::GetTotalSent/ReceivedBytes currently only includes the
  // headers and payload.
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length),
            stream_->GetTotalSentBytes());
  // The stream was closed after receiving the headers.
  EXPECT_EQ(static_cast<int64_t>(response_size),
            stream_->GetTotalReceivedBytes());
}

TEST_P(QuicHttpStreamTest, Priority) {
  SetRequest("GET", "/", MEDIUM);
  size_t spdy_request_headers_frame_length;
  int packet_number = 1;
  AddWrite(ConstructInitialSettingsPacket(packet_number++));
  AddWrite(InnerConstructRequestHeadersPacket(
      packet_number++, GetNthClientInitiatedBidirectionalStreamId(0), kFin,
      MEDIUM, &spdy_request_headers_frame_length));
  Initialize();

  request_.method = "GET";
  request_.url = GURL("https://www.example.org/");

  stream_->RegisterRequest(&request_);
  EXPECT_EQ(OK, stream_->InitializeStream(true, MEDIUM, net_log_with_source_,
                                          callback_.callback()));

  EXPECT_EQ(OK,
            stream_->SendRequest(headers_, &response_, callback_.callback()));

  // Ack the request.
  ProcessPacket(ConstructServerAckPacket(1, 1, 1, 1));
  EXPECT_THAT(stream_->ReadResponseHeaders(callback_.callback()),
              IsError(ERR_IO_PENDING));

  // Send the response with a body.
  SetResponse("404", "hello world!");
  size_t response_size = 0;
  ProcessPacket(ConstructResponseHeadersPacket(2, kFin, &response_size));

  EXPECT_EQ(OK, callback_.WaitForResult());

  EXPECT_TRUE(AtEof());

  // QuicHttpStream::GetTotalSent/ReceivedBytes currently only includes the
  // headers and payload.
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length),
            stream_->GetTotalSentBytes());
  EXPECT_EQ(static_cast<int64_t>(response_size),
            stream_->GetTotalReceivedBytes());
}

TEST_P(QuicHttpStreamTest, SessionClosedDuringDoLoop) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  int packet_number = 1;
  AddWrite(ConstructInitialSettingsPacket(packet_number++));
  std::string header = ConstructDataHeader(strlen(kUploadData));
  AddWrite(ConstructRequestHeadersAndDataFramesPacket(
      packet_number++, GetNthClientInitiatedBidirectionalStreamId(0), !kFin,
      DEFAULT_PRIORITY, &spdy_request_headers_frame_length,
      {header, kUploadData}));

  // Second data write will result in a synchronous failure which will close
  // the session.
  AddWrite(SYNCHRONOUS, ERR_FAILED);
  Initialize();

  upload_data_stream_ = std::make_unique<ChunkedUploadDataStream>(0);
  auto* chunked_upload_stream =
      static_cast<ChunkedUploadDataStream*>(upload_data_stream_.get());

  request_.method = "POST";
  request_.url = GURL("https://www.example.org/");
  request_.upload_data_stream = upload_data_stream_.get();
  ASSERT_EQ(OK, request_.upload_data_stream->Init(
                    TestCompletionCallback().callback(), NetLogWithSource()));

  chunked_upload_stream->AppendData(base::byte_span_from_cstring(kUploadData),
                                    false);
  stream_->RegisterRequest(&request_);
  ASSERT_EQ(OK, stream_->InitializeStream(false, DEFAULT_PRIORITY,
                                          net_log_with_source_,
                                          callback_.callback()));
  QuicHttpStream* stream = stream_.get();
  DeleteStreamCallback delete_stream_callback(std::move(stream_));
  // SendRequest() completes asynchronously after the final chunk is added.
  // Error does not surface yet since packet write is triggered by a packet
  // flusher that tries to bundle request body writes.
  ASSERT_EQ(ERR_IO_PENDING,
            stream->SendRequest(headers_, &response_, callback_.callback()));
  chunked_upload_stream->AppendData(base::byte_span_from_cstring(kUploadData),
                                    true);
  int rv = callback_.WaitForResult();
  EXPECT_EQ(OK, rv);
  // Error will be surfaced once an attempt to read the response occurs.
  ASSERT_EQ(ERR_QUIC_PROTOCOL_ERROR,
            stream->ReadResponseHeaders(callback_.callback()));
}

TEST_P(QuicHttpStreamTest, SessionClosedBeforeSendHeadersComplete) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  AddWrite(ConstructInitialSettingsPacket());
  AddWrite(SYNCHRONOUS, ERR_FAILED);
  Initialize();

  upload_data_stream_ = std::make_unique<ChunkedUploadDataStream>(0);
  auto* chunked_upload_stream =
      static_cast<ChunkedUploadDataStream*>(upload_data_stream_.get());

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

  // Error will be surfaced once |upload_data_stream| triggers the next write.
  chunked_upload_stream->AppendData(base::byte_span_from_cstring(kUploadData),
                                    true);
  ASSERT_EQ(ERR_QUIC_PROTOCOL_ERROR, callback_.WaitForResult());

  EXPECT_LE(0, stream_->GetTotalSentBytes());
  EXPECT_EQ(0, stream_->GetTotalReceivedBytes());
}

TEST_P(QuicHttpStreamTest, SessionClosedBeforeSendHeadersCompleteReadResponse) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  AddWrite(ConstructInitialSettingsPacket());
  AddWrite(SYNCHRONOUS, ERR_FAILED);
  Initialize();

  upload_data_stream_ = std::make_unique<ChunkedUploadDataStream>(0);
  auto* chunked_upload_stream =
      static_cast<ChunkedUploadDataStream*>(upload_data_stream_.get());

  request_.method = "POST";
  request_.url = GURL("https://www.example.org/");
  request_.upload_data_stream = upload_data_stream_.get();

  chunked_upload_stream->AppendData(base::byte_span_from_cstring(kUploadData),
                                    true);

  ASSERT_EQ(OK, request_.upload_data_stream->Init(
                    TestCompletionCallback().callback(), NetLogWithSource()));

  stream_->RegisterRequest(&request_);
  ASSERT_EQ(OK, stream_->InitializeStream(false, DEFAULT_PRIORITY,
                                          net_log_with_source_,
                                          callback_.callback()));
  ASSERT_EQ(OK,
            stream_->SendRequest(headers_, &response_, callback_.callback()));

  // Error will be surfaced once an attempt to read the response occurs.
  ASSERT_EQ(ERR_QUIC_PROTOCOL_ERROR,
            stream_->ReadResponseHeaders(callback_.callback()));

  EXPECT_LE(0, stream_->GetTotalSentBytes());
  EXPECT_EQ(0, stream_->GetTotalReceivedBytes());
}

TEST_P(QuicHttpStreamTest, SessionClosedBeforeSendBodyComplete) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  int packet_number = 1;
  AddWrite(ConstructInitialSettingsPacket(packet_number++));
  AddWrite(InnerConstructRequestHeadersPacket(
      packet_number++, GetNthClientInitiatedBidirectionalStreamId(0), !kFin,
      DEFAULT_PRIORITY, &spdy_request_headers_frame_length));
  AddWrite(SYNCHRONOUS, ERR_FAILED);
  Initialize();

  upload_data_stream_ = std::make_unique<ChunkedUploadDataStream>(0);
  auto* chunked_upload_stream =
      static_cast<ChunkedUploadDataStream*>(upload_data_stream_.get());

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
  // Error does not surface yet since packet write is triggered by a packet
  // flusher that tries to bundle request body writes.
  ASSERT_EQ(OK, callback_.WaitForResult());
  // Error will be surfaced once an attempt to read the response occurs.
  ASSERT_EQ(ERR_QUIC_PROTOCOL_ERROR,
            stream_->ReadResponseHeaders(callback_.callback()));

  EXPECT_LE(0, stream_->GetTotalSentBytes());
  EXPECT_EQ(0, stream_->GetTotalReceivedBytes());
}

TEST_P(QuicHttpStreamTest, SessionClosedBeforeSendBundledBodyComplete) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  int packet_number = 1;
  AddWrite(ConstructInitialSettingsPacket(packet_number++));
  std::string header = ConstructDataHeader(strlen(kUploadData));
  AddWrite(ConstructRequestHeadersAndDataFramesPacket(
      packet_number++, GetNthClientInitiatedBidirectionalStreamId(0), !kFin,
      DEFAULT_PRIORITY, &spdy_request_headers_frame_length,
      {header, kUploadData}));

  AddWrite(SYNCHRONOUS, ERR_FAILED);
  Initialize();

  upload_data_stream_ = std::make_unique<ChunkedUploadDataStream>(0);
  auto* chunked_upload_stream =
      static_cast<ChunkedUploadDataStream*>(upload_data_stream_.get());

  request_.method = "POST";
  request_.url = GURL("https://www.example.org/");
  request_.upload_data_stream = upload_data_stream_.get();

  chunked_upload_stream->AppendData(base::byte_span_from_cstring(kUploadData),
                                    false);

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

  // Error does not surface yet since packet write is triggered by a packet
  // flusher that tries to bundle request body writes.
  ASSERT_EQ(OK, callback_.WaitForResult());
  // Error will be surfaced once an attempt to read the response occurs.
  ASSERT_EQ(ERR_QUIC_PROTOCOL_ERROR,
            stream_->ReadResponseHeaders(callback_.callback()));

  EXPECT_LE(0, stream_->GetTotalSentBytes());
  EXPECT_EQ(0, stream_->GetTotalReceivedBytes());
}

TEST_P(QuicHttpStreamTest, DataReadErrorSynchronous) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  int packet_number = 1;
  AddWrite(ConstructInitialSettingsPacket(packet_number++));
  AddWrite(ConstructRequestAndRstPacket(
      packet_number++, GetNthClientInitiatedBidirectionalStreamId(0), !kFin,
      DEFAULT_PRIORITY, &spdy_request_headers_frame_length,
      quic::QUIC_ERROR_PROCESSING_STREAM));

  Initialize();

  upload_data_stream_ = std::make_unique<ReadErrorUploadDataStream>(
      ReadErrorUploadDataStream::FailureMode::SYNC);
  request_.method = "POST";
  request_.url = GURL("https://www.example.org/");
  request_.upload_data_stream = upload_data_stream_.get();
  ASSERT_EQ(OK, request_.upload_data_stream->Init(
                    TestCompletionCallback().callback(), NetLogWithSource()));

  stream_->RegisterRequest(&request_);
  EXPECT_EQ(OK, stream_->InitializeStream(false, DEFAULT_PRIORITY,
                                          net_log_with_source_,
                                          callback_.callback()));

  int result = stream_->SendRequest(headers_, &response_, callback_.callback());
  EXPECT_THAT(result, IsError(ERR_FAILED));

  EXPECT_TRUE(AtEof());

  // QuicHttpStream::GetTotalSent/ReceivedBytes includes only headers.
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length),
            stream_->GetTotalSentBytes());
  EXPECT_EQ(0, stream_->GetTotalReceivedBytes());
}

TEST_P(QuicHttpStreamTest, DataReadErrorAsynchronous) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  int packet_number = 1;
  AddWrite(ConstructInitialSettingsPacket(packet_number++));
  AddWrite(InnerConstructRequestHeadersPacket(
      packet_number++, GetNthClientInitiatedBidirectionalStreamId(0), !kFin,
      DEFAULT_PRIORITY, &spdy_request_headers_frame_length));
  AddWrite(ConstructClientRstStreamErrorPacket(packet_number++));

  Initialize();

  upload_data_stream_ = std::make_unique<ReadErrorUploadDataStream>(
      ReadErrorUploadDataStream::FailureMode::ASYNC);
  request_.method = "POST";
  request_.url = GURL("https://www.example.org/");
  request_.upload_data_stream = upload_data_stream_.get();
  ASSERT_EQ(OK, request_.upload_data_stream->Init(
                    TestCompletionCallback().callback(), NetLogWithSource()));

  stream_->RegisterRequest(&request_);
  EXPECT_EQ(OK, stream_->InitializeStream(false, DEFAULT_PRIORITY,
                                          net_log_with_source_,
                                          callback_.callback()));

  int result = stream_->SendRequest(headers_, &response_, callback_.callback());

  ProcessPacket(ConstructServerAckPacket(1, 1, 1, 1));
  SetResponse("200", string());

  EXPECT_THAT(result, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback_.GetResult(result), IsError(ERR_FAILED));

  EXPECT_TRUE(AtEof());

  // QuicHttpStream::GetTotalSent/ReceivedBytes includes only headers.
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length),
            stream_->GetTotalSentBytes());
  EXPECT_EQ(0, stream_->GetTotalReceivedBytes());
}

TEST_P(QuicHttpStreamTest, GetAcceptChViaAlps) {
  AddWrite(ConstructInitialSettingsPacket());
  Initialize();

  base::HistogramTester histogram_tester;

  session_->OnAcceptChFrameReceivedViaAlps(
      {{{"https://www.example.org", "Sec-CH-UA-Platform"}}});

  request_.method = "GET";
  request_.url = GURL("https://www.example.org/foo");

  stream_->RegisterRequest(&request_);
  EXPECT_EQ(OK, stream_->InitializeStream(true, DEFAULT_PRIORITY,
                                          net_log_with_source_,
                                          callback_.callback()));
  EXPECT_EQ("Sec-CH-UA-Platform", stream_->GetAcceptChViaAlps());
  EXPECT_TRUE(AtEof());

  histogram_tester.ExpectBucketCount(
      "Net.QuicSession.AcceptChFrameReceivedViaAlps", 1, 1);
  histogram_tester.ExpectTotalCount(
      "Net.QuicSession.AcceptChFrameReceivedViaAlps", 1);
  histogram_tester.ExpectBucketCount("Net.QuicSession.AcceptChForOrigin", 1, 1);
  histogram_tester.ExpectTotalCount("Net.QuicSession.AcceptChForOrigin", 1);
}

}  // namespace net::test
```