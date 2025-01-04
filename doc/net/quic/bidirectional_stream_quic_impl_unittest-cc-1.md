Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a unit test file for Chromium's network stack, specifically related to bidirectional QUIC streams. I need to analyze the test cases in this snippet and extract their core purpose.

**Plan:**

1. Identify individual test cases within the provided code.
2. For each test case, determine the main scenario being tested. This involves analyzing the `AddWrite` calls (client actions) and `ProcessPacket` calls (simulated server responses).
3. Group similar test cases to avoid redundancy in the summary.
4. Address specific requirements from the prompt:
    *   **Functionality:** Describe what the tests are verifying.
    *   **JavaScript relation:**  Although the code is C++, if any tests simulate scenarios relevant to web browsers and JavaScript (like fetching resources), I should mention it conceptually. No direct JavaScript interaction is expected in these low-level network tests.
    *   **Logic reasoning (input/output):**  For some tests, I can infer the expected input (client request) and output (server response) based on the packet construction.
    *   **User/programming errors:** Identify potential mistakes developers might make that these tests cover.
    *   **User operation leading to this code:** Describe a high-level user action that would trigger this QUIC stream interaction.
5. Synthesize a concise summary of the overall functionality covered by this code snippet.
这是 `net/quic/bidirectional_stream_quic_impl_unittest.cc` 文件的一部分，主要功能是测试 `BidirectionalStreamQuicImpl` 类的各种场景。`BidirectionalStreamQuicImpl` 是 Chromium 中处理双向 QUIC 流的实现。

**归纳一下这部分代码的功能：**

这部分代码主要测试了以下关于双向 QUIC 流的场景：

1. **服务器确认请求后的数据传输流程：** 测试了客户端发送请求头后，服务器确认请求，然后发送响应头、响应数据和尾部的完整流程。验证了 `OnHeadersReceived`，`ReadData`，`OnTrailersReceived` 等回调的正确触发，以及接收到的数据、尾部是否正确。同时还检查了网络日志记录是否符合预期。
2. **两个并发请求的 Load Timing 信息：** 测试了在同一个 QUIC 连接上发起两个并发请求时，`LoadTimingInfo` 的记录是否正确，尤其是关于会话复用的信息。
3. **数据包合并（不包含头部）：** 测试了当请求头部没有延迟发送时，客户端如何将多个数据缓冲区合并成一个 QUIC 数据包发送。验证了 `SendvData` 方法的合并行为。
4. **数据包合并（包含头部）：** 测试了当请求头部被延迟发送时，调用 `SendData` 或 `SendvData` 是否会将请求头部和数据缓冲区合并成一个 QUIC 数据包发送。
5. **数据发送失败场景下的处理：** 测试了当延迟发送的请求头部由于写入错误而失败时，流是否会正常处理，避免崩溃。
6. **POST 请求的完整流程：** 测试了客户端发送带有请求体的 POST 请求，并接收服务器的响应头、响应数据和尾部的完整流程。
7. **允许 Early Data Override 的请求：** 测试了允许 Early Data Override 的请求场景下的流程，类似于普通的 GET 请求，但可能会涉及到 0-RTT 数据。
8. **交错读取数据和发送数据：** 测试了客户端在接收服务器数据的同时，也向服务器发送数据的情况，验证了读写操作的交错执行是否正常。

**与 JavaScript 功能的关系：**

虽然这段代码是 C++，但它所测试的功能直接关系到 Web 浏览器（包括运行 JavaScript 的环境）的网络请求行为。例如：

*   **资源加载:** 当 JavaScript 发起一个 `fetch` 请求（例如 `fetch('https://example.com')`）时，如果底层使用了 QUIC 协议，这段代码测试的逻辑就可能被触发。
*   **POST 请求上传数据:** 当 JavaScript 使用 `fetch` 发送 POST 请求并携带 `body` 数据时，例如 `fetch('https://example.com', { method: 'POST', body: 'some data' })`，  `PostRequest` 这个测试场景就模拟了这种行为。
*   **获取响应头和数据:** JavaScript 的 `fetch` API 允许开发者访问响应头和读取响应体，这段代码测试了 `OnHeadersReceived` 和 `ReadData` 的回调，模拟了浏览器处理这些响应信息的过程。
*   **并发请求:**  JavaScript 可以发起多个并发的 `fetch` 请求，`LoadTimingTwoRequests` 这个测试场景就模拟了这种情况，并关注性能相关的指标。

**逻辑推理（假设输入与输出）：**

以 `Server acks the request` 这个测试场景为例：

*   **假设输入（客户端操作）：**
    1. 客户端发送包含请求头的 QUIC 包。
    2. 客户端调用 `ReadData` 方法准备接收数据。
*   **预期输出（服务器响应和客户端行为）：**
    1. 服务器发送 ACK 包确认收到请求头。
    2. 服务器发送包含响应头的 QUIC 包。
    3. 客户端触发 `OnHeadersReceived` 回调，解析响应头。
    4. 服务器发送包含响应数据的 QUIC 包。
    5. 客户端的 `ReadData` 调用成功接收到数据。
    6. 服务器发送包含尾部的 QUIC 包。
    7. 客户端触发 `OnTrailersReceived` 回调，解析尾部。

**用户或编程常见的使用错误：**

*   **没有正确处理 `ReadData` 返回的错误码:**  例如，在数据未到达时 `ReadData` 会返回 `ERR_IO_PENDING`，开发者需要使用异步方式等待数据到达。这段测试用例使用了 `TestCompletionCallback` 来模拟这种等待。如果开发者同步调用 `ReadData` 并期望立即返回数据，就会出错。
*   **过早关闭流:**  如果在数据传输完成前就关闭了双向流，可能会导致数据丢失或连接错误。虽然这段代码没有直接测试关闭流的错误，但其测试的正常流程是建立在正确管理流的生命周期之上的。
*   **错误地假设请求头会立即发送:**  在需要优化性能的场景下，QUIC 允许延迟发送请求头，以便将其与首个数据包合并发送。如果开发者假设请求头会立即发送并进行某些依赖于此的操作，可能会出现时序问题。 `SendDataCoalesceDataBufferAndHeaderFrame` 和 `SendvDataCoalesceDataBuffersAndHeaderFrame` 这两个测试用例覆盖了这种场景。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入 URL 或点击链接：** 这是发起网络请求的起点。
2. **浏览器解析 URL 并确定使用 QUIC 协议：**  如果服务器支持 QUIC 且浏览器启用了 QUIC，则会尝试使用 QUIC 连接。
3. **浏览器建立与服务器的 QUIC 连接：**  包括握手等过程。
4. **浏览器创建一个 `BidirectionalStreamQuicImpl` 实例来处理本次 HTTP 请求：**  这个类负责管理与服务器的 QUIC 流。
5. **如果请求是 GET 请求，并且 `end_stream_on_headers` 为 true（例如，没有请求体）：**  会发送一个包含请求头的 QUIC 包，对应 `Server acks the request` 这样的测试场景。
6. **如果请求是 POST 请求，并且有请求体：** 可能会先发送请求头，然后发送数据，对应 `PostRequest` 这样的测试场景。
7. **如果为了优化，浏览器决定延迟发送请求头，并将它和部分请求体数据合并发送：**  对应 `SendDataCoalesceDataBufferAndHeaderFrame` 或 `SendvDataCoalesceDataBuffersAndHeaderFrame` 这样的测试场景。
8. **在数据传输过程中，用户可能还在与页面进行交互，JavaScript 代码可能也在执行网络请求或接收数据：** 这就可能触发类似 `InterleaveReadDataAndSendData` 这样的场景。

当开发者调试与 QUIC 相关的网络问题时，例如请求卡住、数据接收不完整、连接错误等，就可能需要深入到 `BidirectionalStreamQuicImpl` 的代码中进行分析，而这些单元测试用例就是理解其工作原理的重要参考。 通过查看这些测试用例，开发者可以了解在各种场景下 `BidirectionalStreamQuicImpl` 的预期行为，从而更好地定位问题。

Prompt: 
```
这是目录为net/quic/bidirectional_stream_quic_impl_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
Server acks the request.
  ProcessPacket(ConstructServerAckPacket(1, 1, 1, 1));

  // Server sends the response headers.
  quiche::HttpHeaderBlock response_headers = ConstructResponseHeaders("200");

  size_t spdy_response_headers_frame_length;
  ProcessPacket(
      ConstructResponseHeadersPacket(2, !kFin, std::move(response_headers),
                                     &spdy_response_headers_frame_length));

  delegate->WaitUntilNextCallback(kOnHeadersReceived);
  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(delegate->GetLoadTimingInfo(&load_timing_info));
  ExpectLoadTimingValid(load_timing_info, /*session_reused=*/false);
  TestCompletionCallback cb;
  int rv = delegate->ReadData(cb.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);
  const char kResponseBody[] = "Hello world!";
  // Server sends data.
  std::string header = ConstructDataHeader(strlen(kResponseBody));
  ProcessPacket(ConstructServerDataPacket(3, !kFin, header + kResponseBody));
  EXPECT_EQ(12, cb.WaitForResult());

  EXPECT_EQ(std::string(kResponseBody), delegate->data_received());
  TestCompletionCallback cb2;
  EXPECT_THAT(delegate->ReadData(cb2.callback()), IsError(ERR_IO_PENDING));

  quiche::HttpHeaderBlock trailers;
  size_t spdy_trailers_frame_length;
  trailers["foo"] = "bar";
  // Server sends trailers.
  ProcessPacket(ConstructResponseTrailersPacket(4, kFin, trailers.Clone(),
                                                &spdy_trailers_frame_length));

  delegate->WaitUntilNextCallback(kOnTrailersReceived);
  EXPECT_THAT(cb2.WaitForResult(), IsOk());
  EXPECT_EQ(trailers, delegate->trailers());

  EXPECT_THAT(delegate->ReadData(cb2.callback()), IsOk());
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(2, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoQUIC, delegate->GetProtocol());
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(static_cast<int64_t>(spdy_response_headers_frame_length +
                                 strlen(kResponseBody) + header.length() +
                                 spdy_trailers_frame_length),
            delegate->GetTotalReceivedBytes());
  // Check that NetLog was filled as expected.
  auto entries = net_log_observer().GetEntries();
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

TEST_P(BidirectionalStreamQuicImplTest, LoadTimingTwoRequests) {
  SetRequest("GET", "/", DEFAULT_PRIORITY);
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  AddWrite(ConstructInitialSettingsPacket());
  AddWrite(ConstructRequestHeadersPacketInner(
      GetNthClientInitiatedBidirectionalStreamId(0), kFin, DEFAULT_PRIORITY,
      nullptr));
  // SetRequest() again for second request as |request_headers_| was moved.
  SetRequest("GET", "/", DEFAULT_PRIORITY);
  AddWrite(ConstructRequestHeadersPacketInner(
      GetNthClientInitiatedBidirectionalStreamId(1), kFin, DEFAULT_PRIORITY,
      nullptr));
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  AddWrite(ConstructClientAckPacket(3, 1));
  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = true;
  request.priority = DEFAULT_PRIORITY;

  // Start first request.
  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate =
      std::make_unique<TestDelegateBase>(read_buffer.get(), kReadBufferSize);
  delegate->Start(&request, net_log_with_source(),
                  session()->CreateHandle(destination_));

  // Start second request.
  auto read_buffer2 = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate2 =
      std::make_unique<TestDelegateBase>(read_buffer2.get(), kReadBufferSize);
  delegate2->Start(&request, net_log_with_source(),
                   session()->CreateHandle(destination_));

  delegate->WaitUntilNextCallback(kOnStreamReady);
  delegate2->WaitUntilNextCallback(kOnStreamReady);

  ConfirmHandshake();
  // Server acks the request.
  ProcessPacket(ConstructServerAckPacket(1, 1, 1, 1));

  // Server sends the response headers.
  ProcessPacket(ConstructResponseHeadersPacketInner(
      2, GetNthClientInitiatedBidirectionalStreamId(0), kFin,
      ConstructResponseHeaders("200"), nullptr));

  ProcessPacket(ConstructResponseHeadersPacketInner(
      3, GetNthClientInitiatedBidirectionalStreamId(1), kFin,
      ConstructResponseHeaders("200"), nullptr));

  delegate->WaitUntilNextCallback(kOnHeadersReceived);
  delegate2->WaitUntilNextCallback(kOnHeadersReceived);

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(delegate->GetLoadTimingInfo(&load_timing_info));
  LoadTimingInfo load_timing_info2;
  EXPECT_TRUE(delegate2->GetLoadTimingInfo(&load_timing_info2));
  ExpectLoadTimingValid(load_timing_info, /*session_reused=*/false);
  ExpectLoadTimingValid(load_timing_info2, /*session_reused=*/true);
  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);
  EXPECT_EQ("200", delegate2->response_headers().find(":status")->second);
  // No response body. ReadData() should return OK synchronously.
  TestCompletionCallback dummy_callback;
  EXPECT_EQ(OK, delegate->ReadData(dummy_callback.callback()));
  EXPECT_EQ(OK, delegate2->ReadData(dummy_callback.callback()));
}

// Tests that when request headers are not delayed, only data buffers are
// coalesced.
TEST_P(BidirectionalStreamQuicImplTest, CoalesceDataBuffersNotHeadersFrame) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  AddWrite(ConstructInitialSettingsPacket());
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  const std::string kBody1 = "here are some data";
  const std::string kBody2 = "data keep coming";
  std::string header = ConstructDataHeader(kBody1.length());
  std::string header2 = ConstructDataHeader(kBody2.length());
  std::vector<std::string> two_writes = {kBody1, kBody2};
  AddWrite(ConstructRequestHeadersPacketInner(
      GetNthClientInitiatedBidirectionalStreamId(0), !kFin, DEFAULT_PRIORITY,
      &spdy_request_headers_frame_length));
  AddWrite(
      ConstructClientDataPacket(!kFin, header + kBody1 + header2 + kBody2));

  // Ack server's data packet.
  AddWrite(ConstructClientAckPacket(3, 1));
  const std::string kBody3 = "hello there";
  const std::string kBody4 = "another piece of small data";
  const std::string kBody5 = "really small";
  std::string header3 = ConstructDataHeader(kBody3.length());
  std::string header4 = ConstructDataHeader(kBody4.length());
  std::string header5 = ConstructDataHeader(kBody5.length());
  AddWrite(ConstructClientDataPacket(
      kFin, header3 + kBody3 + header4 + kBody4 + header5 + kBody5));

  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = false;
  request.priority = DEFAULT_PRIORITY;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate =
      std::make_unique<TestDelegateBase>(read_buffer.get(), kReadBufferSize);
  delegate->DoNotSendRequestHeadersAutomatically();
  delegate->Start(&request, net_log_with_source(),
                  session()->CreateHandle(destination_));
  EXPECT_FALSE(delegate->is_ready());
  ConfirmHandshake();
  delegate->WaitUntilNextCallback(kOnStreamReady);
  EXPECT_TRUE(delegate->is_ready());

  // Sends request headers separately, which causes them to be sent in a
  // separate packet.
  delegate->SendRequestHeaders();
  // Send a Data packet.
  scoped_refptr<StringIOBuffer> buf1 =
      base::MakeRefCounted<StringIOBuffer>(kBody1);
  scoped_refptr<StringIOBuffer> buf2 =
      base::MakeRefCounted<StringIOBuffer>(kBody2);

  std::vector<int> lengths = {buf1->size(), buf2->size()};
  delegate->SendvData({buf1, buf2}, lengths, !kFin);
  delegate->WaitUntilNextCallback(kOnDataSent);

  // Server acks the request.
  ProcessPacket(ConstructServerAckPacket(1, 1, 1, 1));

  // Server sends the response headers.
  quiche::HttpHeaderBlock response_headers = ConstructResponseHeaders("200");
  size_t spdy_response_headers_frame_length;
  ProcessPacket(
      ConstructResponseHeadersPacket(2, !kFin, std::move(response_headers),
                                     &spdy_response_headers_frame_length));

  delegate->WaitUntilNextCallback(kOnHeadersReceived);
  TestCompletionCallback cb;
  int rv = delegate->ReadData(cb.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);
  const char kResponseBody[] = "Hello world!";
  std::string header6 = ConstructDataHeader(strlen(kResponseBody));
  // Server sends data.
  ProcessPacket(ConstructServerDataPacket(3, !kFin, header6 + kResponseBody));

  EXPECT_EQ(static_cast<int>(strlen(kResponseBody)), cb.WaitForResult());

  // Send a second Data packet.
  scoped_refptr<StringIOBuffer> buf3 =
      base::MakeRefCounted<StringIOBuffer>(kBody3);
  scoped_refptr<StringIOBuffer> buf4 =
      base::MakeRefCounted<StringIOBuffer>(kBody4);
  scoped_refptr<StringIOBuffer> buf5 =
      base::MakeRefCounted<StringIOBuffer>(kBody5);

  delegate->SendvData({buf3, buf4, buf5},
                      {buf3->size(), buf4->size(), buf5->size()}, kFin);
  delegate->WaitUntilNextCallback(kOnDataSent);

  size_t spdy_trailers_frame_length;
  quiche::HttpHeaderBlock trailers;
  trailers["foo"] = "bar";
  // Server sends trailers.
  ProcessPacket(ConstructResponseTrailersPacket(4, kFin, trailers.Clone(),
                                                &spdy_trailers_frame_length));

  delegate->WaitUntilNextCallback(kOnTrailersReceived);
  EXPECT_EQ(trailers, delegate->trailers());
  EXPECT_THAT(delegate->ReadData(cb.callback()), IsOk());

  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(2, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoQUIC, delegate->GetProtocol());
  EXPECT_EQ(static_cast<int64_t>(
                spdy_request_headers_frame_length + kBody1.length() +
                kBody2.length() + kBody3.length() + kBody4.length() +
                kBody5.length() + header.length() + header2.length() +
                header3.length() + header4.length() + header5.length()),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(static_cast<int64_t>(spdy_response_headers_frame_length +
                                 strlen(kResponseBody) + header6.length() +
                                 spdy_trailers_frame_length),
            delegate->GetTotalReceivedBytes());
}

// Tests that when request headers are delayed, SendData triggers coalescing of
// request headers with data buffers.
TEST_P(BidirectionalStreamQuicImplTest,
       SendDataCoalesceDataBufferAndHeaderFrame) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  AddWrite(ConstructInitialSettingsPacket());
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  const char kBody1[] = "here are some data";
  std::string header = ConstructDataHeader(strlen(kBody1));
  AddWrite(ConstructRequestHeadersAndMultipleDataFramesPacket(
      !kFin, DEFAULT_PRIORITY, &spdy_request_headers_frame_length,
      {header, kBody1}));

  // Ack server's data packet.
  AddWrite(ConstructClientAckPacket(3, 1));
  const char kBody2[] = "really small";
  std::string header2 = ConstructDataHeader(strlen(kBody2));
  AddWrite(ConstructClientDataPacket(kFin, header2 + std::string(kBody2)));

  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = false;
  request.priority = DEFAULT_PRIORITY;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate =
      std::make_unique<TestDelegateBase>(read_buffer.get(), kReadBufferSize);
  delegate->DoNotSendRequestHeadersAutomatically();
  delegate->Start(&request, net_log_with_source(),
                  session()->CreateHandle(destination_));
  ConfirmHandshake();
  delegate->WaitUntilNextCallback(kOnStreamReady);

  // Send a Data packet.
  scoped_refptr<StringIOBuffer> buf1 =
      base::MakeRefCounted<StringIOBuffer>(kBody1);

  delegate->SendData(buf1, buf1->size(), false);
  delegate->WaitUntilNextCallback(kOnDataSent);

  // Server acks the request.
  ProcessPacket(ConstructServerAckPacket(1, 1, 1, 1));

  // Server sends the response headers.
  quiche::HttpHeaderBlock response_headers = ConstructResponseHeaders("200");
  size_t spdy_response_headers_frame_length;
  ProcessPacket(
      ConstructResponseHeadersPacket(2, !kFin, std::move(response_headers),
                                     &spdy_response_headers_frame_length));

  delegate->WaitUntilNextCallback(kOnHeadersReceived);
  TestCompletionCallback cb;
  int rv = delegate->ReadData(cb.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);
  const char kResponseBody[] = "Hello world!";
  // Server sends data.
  std::string header3 = ConstructDataHeader(strlen(kResponseBody));
  ProcessPacket(ConstructServerDataPacket(3, !kFin, header3 + kResponseBody));

  EXPECT_EQ(static_cast<int>(strlen(kResponseBody)), cb.WaitForResult());

  // Send a second Data packet.
  scoped_refptr<StringIOBuffer> buf2 =
      base::MakeRefCounted<StringIOBuffer>(kBody2);

  delegate->SendData(buf2, buf2->size(), true);
  delegate->WaitUntilNextCallback(kOnDataSent);

  size_t spdy_trailers_frame_length;
  quiche::HttpHeaderBlock trailers;
  trailers["foo"] = "bar";
  // Server sends trailers.
  ProcessPacket(ConstructResponseTrailersPacket(4, kFin, trailers.Clone(),
                                                &spdy_trailers_frame_length));

  delegate->WaitUntilNextCallback(kOnTrailersReceived);
  EXPECT_EQ(trailers, delegate->trailers());
  EXPECT_THAT(delegate->ReadData(cb.callback()), IsOk());

  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(2, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoQUIC, delegate->GetProtocol());
  EXPECT_EQ(
      static_cast<int64_t>(spdy_request_headers_frame_length + strlen(kBody1) +
                           strlen(kBody2) + header.length() + header2.length()),
      delegate->GetTotalSentBytes());
  EXPECT_EQ(static_cast<int64_t>(spdy_response_headers_frame_length +
                                 strlen(kResponseBody) + header3.length() +
                                 spdy_trailers_frame_length),
            delegate->GetTotalReceivedBytes());
}

// Tests that when request headers are delayed, SendvData triggers coalescing of
// request headers with data buffers.
TEST_P(BidirectionalStreamQuicImplTest,
       SendvDataCoalesceDataBuffersAndHeaderFrame) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  AddWrite(ConstructInitialSettingsPacket());
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  const std::string kBody1 = "here are some data";
  const std::string kBody2 = "data keep coming";
  std::string header = ConstructDataHeader(kBody1.length());
  std::string header2 = ConstructDataHeader(kBody2.length());

  AddWrite(ConstructRequestHeadersAndMultipleDataFramesPacket(
      !kFin, DEFAULT_PRIORITY, &spdy_request_headers_frame_length,
      {header + kBody1 + header2 + kBody2}));

  // Ack server's data packet.
  AddWrite(ConstructClientAckPacket(3, 1));
  const std::string kBody3 = "hello there";
  const std::string kBody4 = "another piece of small data";
  const std::string kBody5 = "really small";
  std::string header3 = ConstructDataHeader(kBody3.length());
  std::string header4 = ConstructDataHeader(kBody4.length());
  std::string header5 = ConstructDataHeader(kBody5.length());
  AddWrite(ConstructClientDataPacket(
      kFin, header3 + kBody3 + header4 + kBody4 + header5 + kBody5));

  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = false;
  request.priority = DEFAULT_PRIORITY;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate =
      std::make_unique<TestDelegateBase>(read_buffer.get(), kReadBufferSize);
  delegate->DoNotSendRequestHeadersAutomatically();
  delegate->Start(&request, net_log_with_source(),
                  session()->CreateHandle(destination_));
  ConfirmHandshake();
  delegate->WaitUntilNextCallback(kOnStreamReady);

  // Send a Data packet.
  scoped_refptr<StringIOBuffer> buf1 =
      base::MakeRefCounted<StringIOBuffer>(kBody1);
  scoped_refptr<StringIOBuffer> buf2 =
      base::MakeRefCounted<StringIOBuffer>(kBody2);

  std::vector<int> lengths = {buf1->size(), buf2->size()};
  delegate->SendvData({buf1, buf2}, lengths, !kFin);
  delegate->WaitUntilNextCallback(kOnDataSent);

  // Server acks the request.
  ProcessPacket(ConstructServerAckPacket(1, 1, 1, 1));

  // Server sends the response headers.
  quiche::HttpHeaderBlock response_headers = ConstructResponseHeaders("200");
  size_t spdy_response_headers_frame_length;
  ProcessPacket(
      ConstructResponseHeadersPacket(2, !kFin, std::move(response_headers),
                                     &spdy_response_headers_frame_length));

  delegate->WaitUntilNextCallback(kOnHeadersReceived);
  TestCompletionCallback cb;
  int rv = delegate->ReadData(cb.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);
  const char kResponseBody[] = "Hello world!";
  std::string header6 = ConstructDataHeader(strlen(kResponseBody));
  // Server sends data.
  ProcessPacket(ConstructServerDataPacket(3, !kFin, header6 + kResponseBody));

  EXPECT_EQ(static_cast<int>(strlen(kResponseBody)), cb.WaitForResult());

  // Send a second Data packet.
  scoped_refptr<StringIOBuffer> buf3 =
      base::MakeRefCounted<StringIOBuffer>(kBody3);
  scoped_refptr<StringIOBuffer> buf4 =
      base::MakeRefCounted<StringIOBuffer>(kBody4);
  scoped_refptr<StringIOBuffer> buf5 =
      base::MakeRefCounted<StringIOBuffer>(kBody5);

  delegate->SendvData({buf3, buf4, buf5},
                      {buf3->size(), buf4->size(), buf5->size()}, kFin);
  delegate->WaitUntilNextCallback(kOnDataSent);

  size_t spdy_trailers_frame_length;
  quiche::HttpHeaderBlock trailers;
  trailers["foo"] = "bar";
  // Server sends trailers.
  ProcessPacket(ConstructResponseTrailersPacket(4, kFin, trailers.Clone(),
                                                &spdy_trailers_frame_length));

  delegate->WaitUntilNextCallback(kOnTrailersReceived);
  EXPECT_EQ(trailers, delegate->trailers());
  EXPECT_THAT(delegate->ReadData(cb.callback()), IsOk());

  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(2, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoQUIC, delegate->GetProtocol());
  EXPECT_EQ(static_cast<int64_t>(
                spdy_request_headers_frame_length + kBody1.length() +
                kBody2.length() + kBody3.length() + kBody4.length() +
                kBody5.length() + header.length() + header2.length() +
                header3.length() + header4.length() + header5.length()),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(static_cast<int64_t>(spdy_response_headers_frame_length +
                                 strlen(kResponseBody) + header6.length() +
                                 spdy_trailers_frame_length),
            delegate->GetTotalReceivedBytes());
}

// Tests that when request headers are delayed and SendData triggers the
// headers to be sent, if that write fails the stream does not crash.
TEST_P(BidirectionalStreamQuicImplTest,
       SendDataWriteErrorCoalesceDataBufferAndHeaderFrame) {
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  AddWrite(ConstructInitialSettingsPacket());
  AddWriteError(SYNCHRONOUS, ERR_CONNECTION_REFUSED);

  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = false;
  request.priority = DEFAULT_PRIORITY;
  request.extra_headers.SetHeader("cookie", std::string(2048, 'A'));

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate = std::make_unique<DeleteStreamDelegate>(
      read_buffer.get(), kReadBufferSize, DeleteStreamDelegate::ON_FAILED);
  delegate->DoNotSendRequestHeadersAutomatically();
  delegate->Start(&request, net_log_with_source(),
                  session()->CreateHandle(destination_));
  ConfirmHandshake();
  delegate->WaitUntilNextCallback(kOnStreamReady);

  // Attempt to send the headers and data.
  const char kBody1[] = "here are some data";
  scoped_refptr<StringIOBuffer> buf1 =
      base::MakeRefCounted<StringIOBuffer>(kBody1);
  delegate->SendData(buf1, buf1->size(), !kFin);

  delegate->WaitUntilNextCallback(kOnFailed);
}

// Tests that when request headers are delayed and SendvData triggers the
// headers to be sent, if that write fails the stream does not crash.
TEST_P(BidirectionalStreamQuicImplTest,
       SendvDataWriteErrorCoalesceDataBufferAndHeaderFrame) {
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  AddWrite(ConstructInitialSettingsPacket());
  AddWriteError(SYNCHRONOUS, ERR_CONNECTION_REFUSED);

  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = false;
  request.priority = DEFAULT_PRIORITY;
  request.extra_headers.SetHeader("cookie", std::string(2048, 'A'));

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate = std::make_unique<DeleteStreamDelegate>(
      read_buffer.get(), kReadBufferSize, DeleteStreamDelegate::ON_FAILED);
  delegate->DoNotSendRequestHeadersAutomatically();
  delegate->Start(&request, net_log_with_source(),
                  session()->CreateHandle(destination_));
  ConfirmHandshake();
  delegate->WaitUntilNextCallback(kOnStreamReady);

  // Attempt to send the headers and data.
  const char kBody1[] = "here are some data";
  const char kBody2[] = "data keep coming";
  scoped_refptr<StringIOBuffer> buf1 =
      base::MakeRefCounted<StringIOBuffer>(kBody1);
  scoped_refptr<StringIOBuffer> buf2 =
      base::MakeRefCounted<StringIOBuffer>(kBody2);
  std::vector<int> lengths = {buf1->size(), buf2->size()};
  delegate->SendvData({buf1, buf2}, lengths, !kFin);

  delegate->WaitUntilNextCallback(kOnFailed);
}

TEST_P(BidirectionalStreamQuicImplTest, PostRequest) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  AddWrite(ConstructInitialSettingsPacket());
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  AddWrite(ConstructRequestHeadersPacketInner(
      GetNthClientInitiatedBidirectionalStreamId(0), !kFin, DEFAULT_PRIORITY,
      &spdy_request_headers_frame_length));
  std::string header = ConstructDataHeader(strlen(kUploadData));
  AddWrite(ConstructClientDataPacket(kFin, header + std::string(kUploadData)));

  AddWrite(ConstructClientAckPacket(3, 1));

  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = false;
  request.priority = DEFAULT_PRIORITY;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate =
      std::make_unique<TestDelegateBase>(read_buffer.get(), kReadBufferSize);
  delegate->Start(&request, net_log_with_source(),
                  session()->CreateHandle(destination_));
  ConfirmHandshake();
  delegate->WaitUntilNextCallback(kOnStreamReady);

  // Send a DATA frame.
  scoped_refptr<StringIOBuffer> buf =
      base::MakeRefCounted<StringIOBuffer>(kUploadData);

  delegate->SendData(buf, buf->size(), true);
  delegate->WaitUntilNextCallback(kOnDataSent);

  // Server acks the request.
  ProcessPacket(ConstructServerAckPacket(1, 1, 1, 1));

  // Server sends the response headers.
  quiche::HttpHeaderBlock response_headers = ConstructResponseHeaders("200");
  size_t spdy_response_headers_frame_length;
  ProcessPacket(
      ConstructResponseHeadersPacket(2, !kFin, std::move(response_headers),
                                     &spdy_response_headers_frame_length));

  delegate->WaitUntilNextCallback(kOnHeadersReceived);
  TestCompletionCallback cb;
  int rv = delegate->ReadData(cb.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);
  const char kResponseBody[] = "Hello world!";
  std::string header2 = ConstructDataHeader(strlen(kResponseBody));
  // Server sends data.
  ProcessPacket(ConstructServerDataPacket(3, !kFin, header2 + kResponseBody));

  EXPECT_EQ(static_cast<int>(strlen(kResponseBody)), cb.WaitForResult());

  size_t spdy_trailers_frame_length;
  quiche::HttpHeaderBlock trailers;
  trailers["foo"] = "bar";
  // Server sends trailers.
  ProcessPacket(ConstructResponseTrailersPacket(4, kFin, trailers.Clone(),
                                                &spdy_trailers_frame_length));

  delegate->WaitUntilNextCallback(kOnTrailersReceived);
  EXPECT_EQ(trailers, delegate->trailers());
  EXPECT_THAT(delegate->ReadData(cb.callback()), IsOk());

  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(1, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoQUIC, delegate->GetProtocol());
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length +
                                 strlen(kUploadData) + header.length()),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(static_cast<int64_t>(spdy_response_headers_frame_length +
                                 strlen(kResponseBody) + header2.length() +
                                 spdy_trailers_frame_length),
            delegate->GetTotalReceivedBytes());
}

TEST_P(BidirectionalStreamQuicImplTest, EarlyDataOverrideRequest) {
  SetRequest("PUT", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  AddWrite(ConstructInitialSettingsPacket());
  AddWrite(ConstructRequestHeadersPacketInner(
      GetNthClientInitiatedBidirectionalStreamId(0), kFin, DEFAULT_PRIORITY,
      &spdy_request_headers_frame_length));
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  AddWrite(ConstructClientAckPacket(3, 1));

  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "PUT";
  request.allow_early_data_override = true;
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = true;
  request.priority = DEFAULT_PRIORITY;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate =
      std::make_unique<TestDelegateBase>(read_buffer.get(), kReadBufferSize);
  delegate->set_trailers_expected(true);
  delegate->Start(&request, net_log_with_source(),
                  session()->CreateHandle(destination_));
  delegate->WaitUntilNextCallback(kOnStreamReady);
  ConfirmHandshake();

  // Server acks the request.
  ProcessPacket(ConstructServerAckPacket(1, 1, 1, 1));

  // Server sends the response headers.
  quiche::HttpHeaderBlock response_headers = ConstructResponseHeaders("200");

  size_t spdy_response_headers_frame_length;
  ProcessPacket(
      ConstructResponseHeadersPacket(2, !kFin, std::move(response_headers),
                                     &spdy_response_headers_frame_length));

  delegate->WaitUntilNextCallback(kOnHeadersReceived);
  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(delegate->GetLoadTimingInfo(&load_timing_info));
  ExpectLoadTimingValid(load_timing_info, /*session_reused=*/false);
  TestCompletionCallback cb;
  int rv = delegate->ReadData(cb.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);
  const char kResponseBody[] = "Hello world!";
  // Server sends data.
  std::string header = ConstructDataHeader(strlen(kResponseBody));
  ProcessPacket(ConstructServerDataPacket(3, !kFin, header + kResponseBody));
  EXPECT_EQ(12, cb.WaitForResult());

  EXPECT_EQ(std::string(kResponseBody), delegate->data_received());
  TestCompletionCallback cb2;
  EXPECT_THAT(delegate->ReadData(cb2.callback()), IsError(ERR_IO_PENDING));

  quiche::HttpHeaderBlock trailers;
  size_t spdy_trailers_frame_length;
  trailers["foo"] = "bar";
  // Server sends trailers.
  ProcessPacket(ConstructResponseTrailersPacket(4, kFin, trailers.Clone(),
                                                &spdy_trailers_frame_length));

  delegate->WaitUntilNextCallback(kOnTrailersReceived);
  EXPECT_THAT(cb2.WaitForResult(), IsOk());
  EXPECT_EQ(trailers, delegate->trailers());

  EXPECT_THAT(delegate->ReadData(cb2.callback()), IsOk());
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(2, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoQUIC, delegate->GetProtocol());
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(static_cast<int64_t>(spdy_response_headers_frame_length +
                                 strlen(kResponseBody) + header.length() +
                                 spdy_trailers_frame_length),
            delegate->GetTotalReceivedBytes());
  // Check that NetLog was filled as expected.
  auto entries = net_log_observer().GetEntries();
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

TEST_P(BidirectionalStreamQuicImplTest, InterleaveReadDataAndSendData) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  AddWrite(ConstructInitialSettingsPacket());
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  AddWrite(ConstructRequestHeadersPacketInner(
      GetNthClientInitiatedBidirectionalStreamId(0), !kFin, DEFAULT_PRIORITY,
      &spdy_request_headers_frame_length));

  std::string header = ConstructDataHeader(strlen(kUploadData));
  AddWrite(ConstructAckAndDataPacket(++packet_number_, 2, 1, !kFin,
                                     header + std::string(kUploadData),
                                     &client_maker_));
  AddWrite(ConstructAckAndDataPacket(++packet_number_, 3, 3, kFin,
                                     header + std::string(kUploadData),
                                     &client_maker_));
  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = false;
  request.priority = DEFAULT_PRIORITY;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate =
      std::make_unique<TestDelegateBase>(read_buffer.get(), kReadBufferSize);
  delegate->Start(&request, net_log_with_source(),
                  session()->CreateHandle(destination_));
  ConfirmHandshake();
  delegate->WaitUntilNextCallback(kOnStreamReady);

  // Server acks the request.
  ProcessPacket(ConstructServerAckPacket(1, 1, 1, 1));

  // Server sends the response headers.
  quiche::HttpHeaderBlock response_headers = ConstructResponseHeaders("200");
  size_t spdy_response_headers_frame_length;
  Proce
"""


```