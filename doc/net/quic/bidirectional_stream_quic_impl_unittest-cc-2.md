Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack. This is the third part of a larger file, and I need to summarize the overall functionality.

Here's a breakdown of the thought process to address the request:

1. **Identify the Core Class Under Test:** The test suite name `BidirectionalStreamQuicImplTest` clearly indicates that the focus is on the `BidirectionalStreamQuicImpl` class. This class likely implements a bidirectional QUIC stream within Chromium.

2. **Analyze the Test Cases:**  Each `TEST_P` macro defines an individual test case. I need to go through each test and determine what specific aspect of `BidirectionalStreamQuicImpl`'s functionality it is testing. I'll look for patterns in the setup, actions, and assertions within each test.

3. **Group Similar Tests:**  I can group tests based on the type of scenario they are simulating (e.g., successful data transfer, server-initiated resets, session closures, stream deletions). This will help in summarizing the functionality in a structured way.

4. **Look for Specific Function Calls and Events:** Pay attention to function calls like `SendData`, `ReadData`, `ProcessPacket`, and callbacks like `OnHeadersReceived`, `OnDataSent`, `OnDataRead`, `OnFailed`, `OnStreamReady`, `OnTrailersReceived`. These provide clues about the interaction between `BidirectionalStreamQuicImpl` and other components.

5. **Consider the Test Fixture (`BidirectionalStreamQuicImplTest`):** The setup within the test fixture (like `SetRequest`, `AddWrite`, `Initialize`) provides context about how the tests are being run and the initial state.

6. **Infer High-Level Functionality:** Based on the test cases, I can infer the core responsibilities of `BidirectionalStreamQuicImpl`. It likely handles:
    * Establishing a bidirectional QUIC stream.
    * Sending and receiving data.
    * Handling HTTP headers and trailers.
    * Managing stream lifecycle (opening, closing, resetting).
    * Interacting with the underlying QUIC session.
    * Handling error conditions.

7. **Address Specific Questions:**
    * **Functionality:** Summarize the inferred core responsibilities.
    * **Relationship to JavaScript:**  Consider how these network operations relate to web browsers and how JavaScript might trigger them (e.g., `fetch` API).
    * **Logical Reasoning (Hypothetical Input/Output):** For tests involving data transfer, identify the data being sent and received.
    * **User/Programming Errors:** Look for tests that simulate incorrect usage or error scenarios (e.g., closing a session prematurely).
    * **User Actions (Debugging Clues):**  Think about the user actions that would lead to these network requests (e.g., clicking a link, submitting a form).

8. **Synthesize the Summary for Part 3:**  Since this is part 3, it's important to consolidate the findings from this specific snippet and relate it to the broader context of the unit tests for `BidirectionalStreamQuicImpl`.

**Detailed Analysis of Each Test Case (Leading to the Summary):**

* **`ServerSendsRstAfterHeaders`:** Tests the scenario where the server sends a reset (RST) after the client has sent headers but before sending data. This checks how the client handles abrupt stream termination.
* **`ServerSendsRstAfterReadData`:** Tests the scenario where the server sends a reset after the client has started reading data. This checks handling of mid-stream resets.
* **`SessionClosedBeforeReadData`:** Tests the case where the underlying QUIC session is closed before the client can read data. This verifies proper handling of session-level closures.
* **`SessionClosedBeforeStartConfirmed`:** Tests session closure before the stream is fully established.
* **`SessionClosedBeforeStartNotConfirmed`:** Similar to the above, but focuses on the handshake not being confirmed.
* **`SessionCloseDuringOnStreamReady`:**  Tests session closure during the `OnStreamReady` callback.
* **`DeleteStreamDuringOnStreamReady`:** Tests the explicit deletion of the stream within the `OnStreamReady` callback.
* **`DeleteStreamAfterReadData`:** Tests deleting the stream after initiating a read operation.
* **`DeleteStreamDuringOnHeadersReceived`:** Tests deleting the stream during the header reception callback.
* **`DeleteStreamDuringOnDataRead`:** Tests deleting the stream during a data read callback.
* **`AsyncFinRead`:** Tests the scenario where the server sends a data packet with the FIN flag set, indicating the end of the stream. This verifies asynchronous completion of the read operation.
* **`DeleteStreamDuringOnTrailersReceived`:** Tests deleting the stream during the trailers reception callback.
* **`ReleaseStreamFails`:** Tests a scenario where releasing the stream fails due to the underlying session being closed. This is a regression test for a specific bug.

By analyzing these tests, I can identify the key functionalities and the error handling scenarios being covered. This forms the basis for the summary.
这是对 `net/quic/bidirectional_stream_quic_impl_unittest.cc` 文件中剩余部分功能的归纳。

**功能归纳（基于提供的代码片段）：**

这部分代码主要集中在测试 `BidirectionalStreamQuicImpl` 类在各种异常和边缘情况下的行为，特别是关于流的取消、会话关闭以及在不同回调阶段删除流的场景。  它验证了 `BidirectionalStreamQuicImpl` 如何正确处理以下情况：

* **服务器发送 RST_STREAM 帧：** 测试了在客户端发送请求头之后以及在客户端开始读取数据之后，服务器发送 `RST_STREAM` 帧的情况，验证了客户端能够正确识别并处理这类错误，停止读取数据。
* **QUIC 会话提前关闭：** 测试了在客户端尝试读取数据之前、在流启动确认之前（无论是否完成握手）关闭 QUIC 会话的情况，验证了客户端能够捕获到会话关闭事件，并通知上层（通过 `OnFailed` 回调）。
* **在不同的回调阶段删除流：**  详细测试了在 `OnStreamReady`、`OnHeadersReceived`、`OnDataRead` 和 `OnTrailersReceived` 等回调函数执行期间删除 `BidirectionalStreamQuicImpl` 对象（或其关联的流）的情况。这主要用于验证在这些关键时刻删除流不会导致崩溃或其他内存错误，确保资源清理的正确性。
* **异步 FIN 读取：** 测试了当服务器发送带有 FIN 标志的数据包时，客户端如何异步地完成读取操作，并正确地结束流。
* **`ReleaseStream` 调用失败：**  这是一个回归测试，验证了在 `OnStreamReady` 回调之后但在 `QuicChromiumClientSession::Handle::ReleaseStream()` 调用之前，如果底层的 QUIC 会话被关闭，不会发生崩溃。

**与 JavaScript 的关系：**

尽管这些测试用例直接在 C++ 中模拟网络行为，但它们反映了底层网络栈如何响应来自 JavaScript 的网络请求。

* **`fetch` API 和流的取消:** 当 JavaScript 使用 `fetch` API 发起一个请求，并且在响应完全到达之前调用 `abort()` 方法时，浏览器底层可能会向服务器发送一个取消请求（例如，通过发送 `RST_STREAM` 帧）。  `ServerSendsRstAfterHeaders` 和 `ServerSendsRstAfterReadData` 这两个测试用例模拟了服务器在接收到这类取消请求后的行为。
* **会话关闭导致网络请求失败:**  如果用户在浏览器中导航到另一个页面，或者网络连接中断，底层的 QUIC 会话可能会被关闭。 `SessionClosedBeforeReadData`、`SessionClosedBeforeStartConfirmed` 和 `SessionClosedBeforeStartNotConfirmed` 这些测试用例模拟了这种情况，确保 JavaScript 发起的网络请求能够正确地失败，并通知给开发者。
* **在不同阶段取消请求:** 用户可能在请求的不同阶段取消请求，例如在等待响应头到达之前或在接收部分数据之后。 `DeleteStreamDuringOnStreamReady`、`DeleteStreamAfterReadData`、`DeleteStreamDuringOnHeadersReceived` 和 `DeleteStreamDuringOnDataRead` 这些测试用例模拟了这种用户行为导致的底层流的删除。
* **接收到带 FIN 标志的数据:** 当服务器发送完所有数据时，会设置 FIN 标志。`AsyncFinRead` 测试确保了即使数据和 FIN 标志是异步到达的，客户端也能正确处理，通知 JavaScript 请求已完成。

**逻辑推理 (假设输入与输出):**

以下以 `ServerSendsRstAfterHeaders` 为例进行说明：

**假设输入:**

1. 客户端发起一个 GET 请求，发送请求头（不带 FIN）。
2. 服务器接收到请求头。
3. 服务器决定取消请求，发送一个 `RST_STREAM` 帧。

**预期输出:**

1. 客户端的 `BidirectionalStreamQuicImpl` 对象接收到 `RST_STREAM` 帧。
2. 客户端的 `OnFailed` 回调函数被调用，错误码为 `ERR_QUIC_PROTOCOL_ERROR`。
3. 客户端尝试读取数据会返回错误 `ERR_QUIC_PROTOCOL_ERROR`。
4. 客户端没有接收到任何响应数据。

**用户或编程常见的使用错误举例说明:**

* **过早关闭会话:** 程序员可能在请求尚未完成时，由于错误的逻辑或资源管理，过早地关闭了 QUIC 会话。 `SessionClosedBeforeReadData` 和相关的测试用例模拟了这种情况，强调了正确管理 QUIC 会话生命周期的重要性。
* **在不合适的时间删除流对象:**  在网络请求的关键阶段（例如，在收到响应头或正在接收数据时）不恰当地销毁 `BidirectionalStreamQuicImpl` 对象或其关联的流可能导致崩溃或不可预测的行为。`DeleteStreamDuringOnStreamReady`、`DeleteStreamAfterReadData` 等测试用例旨在发现和防止这类错误。  例如，如果开发者在 `OnHeadersReceived` 回调中直接 `delete this` (假设 `this` 指向 `BidirectionalStreamQuicImpl` 相关的对象)，可能会导致后续操作访问已释放的内存。

**用户操作如何一步步到达这里 (调试线索):**

以下以 `ServerSendsRstAfterHeaders` 为例进行说明：

1. **用户在浏览器中输入 URL 并回车 (GET 请求):** 这是最常见的场景，用户发起一个简单的网页浏览请求。
2. **浏览器网络栈创建 `BidirectionalStreamQuicImpl` 对象:**  根据协议协商结果，如果使用 QUIC，会创建此对象来处理请求。
3. **客户端发送请求头:** `BidirectionalStreamQuicImpl` 将构造并发送 HTTP 请求头到服务器。
4. **服务器端逻辑判断需要取消请求:**  这可能是由于服务器过载、请求的资源不存在、或者服务器端的安全策略阻止了该请求等原因。
5. **服务器发送 RST_STREAM 帧:** 服务器决定终止这个流，并发送一个 `RST_STREAM` 帧到客户端。
6. **`BidirectionalStreamQuicImpl` 接收到 RST_STREAM 帧:**  底层 QUIC 库解析并传递该帧到 `BidirectionalStreamQuicImpl`。
7. **`BidirectionalStreamQuicImpl` 调用 `OnFailed` 回调:**  该对象识别到流已被重置，通知上层网络栈请求失败。
8. **浏览器显示错误页面或触发 `fetch` API 的 `reject` 回调:**  最终，用户会看到一个错误提示，或者 JavaScript 代码会捕获到请求失败的事件。

通过查看网络日志，开发者可以追踪到发送的请求头和接收到的 `RST_STREAM` 帧，从而定位问题的原因。这些单元测试覆盖了这些关键步骤，确保在各种异常情况下，客户端的行为是可预测且正确的。

### 提示词
```
这是目录为net/quic/bidirectional_stream_quic_impl_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
ssPacket(
      ConstructResponseHeadersPacket(2, !kFin, std::move(response_headers),
                                     &spdy_response_headers_frame_length));

  delegate->WaitUntilNextCallback(kOnHeadersReceived);
  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);

  // Client sends a data packet.
  scoped_refptr<StringIOBuffer> buf =
      base::MakeRefCounted<StringIOBuffer>(kUploadData);

  delegate->SendData(buf, buf->size(), false);
  delegate->WaitUntilNextCallback(kOnDataSent);

  TestCompletionCallback cb;
  int rv = delegate->ReadData(cb.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  const char kResponseBody[] = "Hello world!";

  std::string header2 = ConstructDataHeader(strlen(kResponseBody));
  // Server sends a data packet
  int server_ack = 2;
  ProcessPacket(ConstructAckAndDataPacket(
      3, server_ack++, 1, !kFin, header2 + kResponseBody, &server_maker_));

  EXPECT_EQ(static_cast<int64_t>(strlen(kResponseBody)), cb.WaitForResult());
  EXPECT_EQ(std::string(kResponseBody), delegate->data_received());

  // Client sends a data packet.
  delegate->SendData(buf, buf->size(), true);
  delegate->WaitUntilNextCallback(kOnDataSent);

  TestCompletionCallback cb2;
  rv = delegate->ReadData(cb2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  ProcessPacket(ConstructAckAndDataPacket(4, server_ack++, 1, kFin,

                                          header2 + kResponseBody,
                                          &server_maker_));

  EXPECT_EQ(static_cast<int64_t>(strlen(kResponseBody)), cb2.WaitForResult());

  std::string expected_body(kResponseBody);
  expected_body.append(kResponseBody);
  EXPECT_EQ(expected_body, delegate->data_received());

  EXPECT_THAT(delegate->ReadData(cb.callback()), IsOk());
  EXPECT_EQ(2, delegate->on_data_read_count());
  EXPECT_EQ(2, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoQUIC, delegate->GetProtocol());
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length +
                                 2 * strlen(kUploadData) + 2 * header.length()),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(
      static_cast<int64_t>(spdy_response_headers_frame_length +
                           2 * strlen(kResponseBody) + 2 * header2.length()),
      delegate->GetTotalReceivedBytes());
}

TEST_P(BidirectionalStreamQuicImplTest, ServerSendsRstAfterHeaders) {
  SetRequest("GET", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  AddWrite(ConstructInitialSettingsPacket());
  AddWrite(ConstructRequestHeadersPacketInner(
      GetNthClientInitiatedBidirectionalStreamId(0), kFin, DEFAULT_PRIORITY,
      &spdy_request_headers_frame_length));
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = true;
  request.priority = DEFAULT_PRIORITY;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate =
      std::make_unique<TestDelegateBase>(read_buffer.get(), kReadBufferSize);
  delegate->Start(&request, net_log_with_source(),
                  session()->CreateHandle(destination_));
  delegate->WaitUntilNextCallback(kOnStreamReady);
  ConfirmHandshake();

  // Server sends a Rst. Since the stream has sent fin, the rst is one way in
  // IETF QUIC.
  ProcessPacket(
      server_maker_.Packet(1)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_STREAM_CANCELLED)
          .Build());

  delegate->WaitUntilNextCallback(kOnFailed);

  TestCompletionCallback cb;
  EXPECT_THAT(delegate->ReadData(cb.callback()),
              IsError(ERR_QUIC_PROTOCOL_ERROR));

  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(delegate->error(), IsError(ERR_QUIC_PROTOCOL_ERROR));
  EXPECT_EQ(0, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(0, delegate->GetTotalReceivedBytes());
}

TEST_P(BidirectionalStreamQuicImplTest, ServerSendsRstAfterReadData) {
  SetRequest("GET", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  AddWrite(ConstructInitialSettingsPacket());
  AddWrite(ConstructRequestHeadersPacketInner(
      GetNthClientInitiatedBidirectionalStreamId(0), kFin, DEFAULT_PRIORITY,
      &spdy_request_headers_frame_length));
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  // Why does QUIC ack Rst? Is this expected?
  AddWrite(ConstructClientAckPacket(3, 1));

  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = true;
  request.priority = DEFAULT_PRIORITY;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate =
      std::make_unique<TestDelegateBase>(read_buffer.get(), kReadBufferSize);
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
  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);

  TestCompletionCallback cb;
  int rv = delegate->ReadData(cb.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Server sends a Rst. Since the stream has sent fin, the rst is one way in
  // IETF QUIC.
  ProcessPacket(
      server_maker_.Packet(3)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_STREAM_CANCELLED)
          .Build());

  delegate->WaitUntilNextCallback(kOnFailed);

  EXPECT_THAT(delegate->ReadData(cb.callback()),
              IsError(ERR_QUIC_PROTOCOL_ERROR));
  EXPECT_THAT(delegate->error(), IsError(ERR_QUIC_PROTOCOL_ERROR));
  EXPECT_EQ(0, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(static_cast<int64_t>(spdy_response_headers_frame_length),
            delegate->GetTotalReceivedBytes());
}

TEST_P(BidirectionalStreamQuicImplTest, SessionClosedBeforeReadData) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  AddWrite(ConstructInitialSettingsPacket());
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  AddWrite(ConstructRequestHeadersPacketInner(
      GetNthClientInitiatedBidirectionalStreamId(0), !kFin, DEFAULT_PRIORITY,
      &spdy_request_headers_frame_length));
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
  ProcessPacket(
      ConstructResponseHeadersPacket(2, !kFin, std::move(response_headers),
                                     &spdy_response_headers_frame_length));

  delegate->WaitUntilNextCallback(kOnHeadersReceived);
  TestCompletionCallback cb;
  int rv = delegate->ReadData(cb.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  session()->connection()->CloseConnection(
      quic::QUIC_NO_ERROR, "test", quic::ConnectionCloseBehavior::SILENT_CLOSE);
  delegate->WaitUntilNextCallback(kOnFailed);

  // Try to send data after OnFailed(), should not get called back.
  scoped_refptr<StringIOBuffer> buf =
      base::MakeRefCounted<StringIOBuffer>(kUploadData);
  delegate->SendData(buf, buf->size(), false);

  EXPECT_THAT(delegate->ReadData(cb.callback()),
              IsError(ERR_QUIC_PROTOCOL_ERROR));
  EXPECT_THAT(delegate->error(), IsError(ERR_QUIC_PROTOCOL_ERROR));
  EXPECT_EQ(0, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoQUIC, delegate->GetProtocol());
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(static_cast<int64_t>(spdy_response_headers_frame_length),
            delegate->GetTotalReceivedBytes());
}

TEST_P(BidirectionalStreamQuicImplTest, SessionClosedBeforeStartConfirmed) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = false;
  request.priority = DEFAULT_PRIORITY;

  ConfirmHandshake();
  session()->connection()->CloseConnection(
      quic::QUIC_NO_ERROR, "test", quic::ConnectionCloseBehavior::SILENT_CLOSE);

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate =
      std::make_unique<TestDelegateBase>(read_buffer.get(), kReadBufferSize);
  delegate->Start(&request, net_log_with_source(),
                  session()->CreateHandle(destination_));
  delegate->WaitUntilNextCallback(kOnFailed);
  EXPECT_TRUE(delegate->on_failed_called());
  EXPECT_THAT(delegate->error(), IsError(ERR_CONNECTION_CLOSED));
}

TEST_P(BidirectionalStreamQuicImplTest, SessionClosedBeforeStartNotConfirmed) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  Initialize();

  session()->connection()->CloseConnection(
      quic::QUIC_NO_ERROR, "test", quic::ConnectionCloseBehavior::SILENT_CLOSE);

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
  delegate->WaitUntilNextCallback(kOnFailed);
  EXPECT_TRUE(delegate->on_failed_called());
  EXPECT_THAT(delegate->error(), IsError(ERR_QUIC_HANDSHAKE_FAILED));
}

TEST_P(BidirectionalStreamQuicImplTest, SessionCloseDuringOnStreamReady) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  AddWrite(ConstructInitialSettingsPacket());
  AddWriteError(SYNCHRONOUS, ERR_CONNECTION_REFUSED);

  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = false;
  request.priority = DEFAULT_PRIORITY;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate = std::make_unique<DeleteStreamDelegate>(
      read_buffer.get(), kReadBufferSize, DeleteStreamDelegate::ON_FAILED);
  delegate->Start(&request, net_log_with_source(),
                  session()->CreateHandle(destination_));
  ConfirmHandshake();
  delegate->WaitUntilNextCallback(kOnFailed);

  EXPECT_EQ(0, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
}

TEST_P(BidirectionalStreamQuicImplTest, DeleteStreamDuringOnStreamReady) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  AddWrite(ConstructInitialSettingsPacket());
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  AddWrite(ConstructRequestHeadersPacketInner(
      GetNthClientInitiatedBidirectionalStreamId(0), !kFin, DEFAULT_PRIORITY,
      &spdy_request_headers_frame_length));
  AddWrite(ConstructClientEarlyRstStreamPacket());

  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = false;
  request.priority = DEFAULT_PRIORITY;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate = std::make_unique<DeleteStreamDelegate>(
      read_buffer.get(), kReadBufferSize,
      DeleteStreamDelegate::ON_STREAM_READY);
  delegate->Start(&request, net_log_with_source(),
                  session()->CreateHandle(destination_));
  ConfirmHandshake();
  delegate->WaitUntilNextCallback(kOnStreamReady);

  EXPECT_EQ(0, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
}

TEST_P(BidirectionalStreamQuicImplTest, DeleteStreamAfterReadData) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  AddWrite(ConstructInitialSettingsPacket());
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  AddWrite(ConstructRequestHeadersPacketInner(
      GetNthClientInitiatedBidirectionalStreamId(0), !kFin, DEFAULT_PRIORITY,
      &spdy_request_headers_frame_length));
  AddWrite(ConstructClientAckAndRstStreamPacket(2, 1));

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
  ProcessPacket(
      ConstructResponseHeadersPacket(2, !kFin, std::move(response_headers),
                                     &spdy_response_headers_frame_length));

  delegate->WaitUntilNextCallback(kOnHeadersReceived);
  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);

  // Cancel the stream after ReadData returns ERR_IO_PENDING.
  TestCompletionCallback cb;
  EXPECT_THAT(delegate->ReadData(cb.callback()), IsError(ERR_IO_PENDING));
  delegate->DeleteStream();

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(0, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoQUIC, delegate->GetProtocol());
  EXPECT_EQ(static_cast<int64_t>(spdy_request_headers_frame_length),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(static_cast<int64_t>(spdy_response_headers_frame_length),
            delegate->GetTotalReceivedBytes());
}

TEST_P(BidirectionalStreamQuicImplTest, DeleteStreamDuringOnHeadersReceived) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  AddWrite(ConstructInitialSettingsPacket());
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  AddWrite(ConstructRequestHeadersPacketInner(
      GetNthClientInitiatedBidirectionalStreamId(0), !kFin, DEFAULT_PRIORITY,
      &spdy_request_headers_frame_length));
  AddWrite(ConstructClientAckAndRstStreamPacket(2, 1));

  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = false;
  request.priority = DEFAULT_PRIORITY;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate = std::make_unique<DeleteStreamDelegate>(
      read_buffer.get(), kReadBufferSize,
      DeleteStreamDelegate::ON_HEADERS_RECEIVED);
  delegate->Start(&request, net_log_with_source(),
                  session()->CreateHandle(destination_));
  ConfirmHandshake();
  delegate->WaitUntilNextCallback(kOnStreamReady);

  // Server acks the request.
  ProcessPacket(ConstructServerAckPacket(1, 1, 1, 1));

  // Server sends the response headers.
  quiche::HttpHeaderBlock response_headers = ConstructResponseHeaders("200");

  size_t spdy_response_headers_frame_length;
  ProcessPacket(
      ConstructResponseHeadersPacket(2, !kFin, std::move(response_headers),
                                     &spdy_response_headers_frame_length));

  delegate->WaitUntilNextCallback(kOnHeadersReceived);
  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(0, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
}

TEST_P(BidirectionalStreamQuicImplTest, DeleteStreamDuringOnDataRead) {
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  AddWrite(ConstructInitialSettingsPacket());
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  AddWrite(ConstructRequestHeadersPacketInner(
      GetNthClientInitiatedBidirectionalStreamId(0), !kFin, DEFAULT_PRIORITY,
      &spdy_request_headers_frame_length));
  AddWrite(ConstructClientAckPacket(3, 1));
  AddWrite(ConstructClientRstStreamPacket());

  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = false;
  request.priority = DEFAULT_PRIORITY;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate = std::make_unique<DeleteStreamDelegate>(
      read_buffer.get(), kReadBufferSize, DeleteStreamDelegate::ON_DATA_READ);
  delegate->Start(&request, net_log_with_source(),
                  session()->CreateHandle(destination_));
  ConfirmHandshake();
  delegate->WaitUntilNextCallback(kOnStreamReady);

  // Server acks the request.
  ProcessPacket(ConstructServerAckPacket(1, 1, 1, 1));

  // Server sends the response headers.
  quiche::HttpHeaderBlock response_headers = ConstructResponseHeaders("200");

  size_t spdy_response_headers_frame_length;
  ProcessPacket(
      ConstructResponseHeadersPacket(2, !kFin, std::move(response_headers),
                                     &spdy_response_headers_frame_length));

  delegate->WaitUntilNextCallback(kOnHeadersReceived);

  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);

  TestCompletionCallback cb;
  int rv = delegate->ReadData(cb.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  const char kResponseBody[] = "Hello world!";
  std::string header = ConstructDataHeader(strlen(kResponseBody));
  // Server sends data.
  ProcessPacket(ConstructServerDataPacket(3, !kFin, header + kResponseBody));
  EXPECT_EQ(static_cast<int64_t>(strlen(kResponseBody)), cb.WaitForResult());

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
}

TEST_P(BidirectionalStreamQuicImplTest, AsyncFinRead) {
  const char kBody[] = "here is some data";
  SetRequest("POST", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  AddWrite(ConstructInitialSettingsPacket());
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  AddWrite(ConstructRequestHeadersPacketInner(
      GetNthClientInitiatedBidirectionalStreamId(0), !kFin, DEFAULT_PRIORITY,
      &spdy_request_headers_frame_length));
  std::string header = ConstructDataHeader(strlen(kBody));
  AddWrite(ConstructClientDataPacket(kFin, header + kBody));
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

  // Send a Data packet with fin set.
  scoped_refptr<StringIOBuffer> buf1 =
      base::MakeRefCounted<StringIOBuffer>(kBody);
  delegate->SendData(buf1, buf1->size(), /*fin*/ true);
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

  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);

  // Read the body, which will complete asynchronously.
  TestCompletionCallback cb;
  int rv = delegate->ReadData(cb.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  const char kResponseBody[] = "Hello world!";
  std::string header2 = ConstructDataHeader(strlen(kResponseBody));

  // Server sends data with the fin set, which should result in the stream
  // being closed and hence no RST_STREAM will be sent.
  ProcessPacket(ConstructServerDataPacket(3, kFin, header2 + kResponseBody));
  EXPECT_EQ(static_cast<int64_t>(strlen(kResponseBody)), cb.WaitForResult());

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(1, delegate->on_data_sent_count());
}

TEST_P(BidirectionalStreamQuicImplTest, DeleteStreamDuringOnTrailersReceived) {
  SetRequest("GET", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  AddWrite(ConstructInitialSettingsPacket());
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  AddWrite(ConstructRequestHeadersPacket(kFin, DEFAULT_PRIORITY,
                                         &spdy_request_headers_frame_length));
  AddWrite(ConstructClientAckPacket(3, 1));  // Ack the data packet
  AddWrite(ConstructClientAckAndRstStreamPacket(4, 4));

  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = true;
  request.priority = DEFAULT_PRIORITY;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate = std::make_unique<DeleteStreamDelegate>(
      read_buffer.get(), kReadBufferSize,
      DeleteStreamDelegate::ON_TRAILERS_RECEIVED);
  delegate->Start(&request, net_log_with_source(),
                  session()->CreateHandle(destination_));
  ConfirmHandshake();
  delegate->WaitUntilNextCallback(kOnStreamReady);

  // Server acks the request.
  ProcessPacket(ConstructServerAckPacket(1, 1, 1, 1));

  // Server sends the response headers.
  quiche::HttpHeaderBlock response_headers = ConstructResponseHeaders("200");

  size_t spdy_response_headers_frame_length;
  ProcessPacket(
      ConstructResponseHeadersPacket(2, !kFin, std::move(response_headers),
                                     &spdy_response_headers_frame_length));

  delegate->WaitUntilNextCallback(kOnHeadersReceived);

  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);

  TestCompletionCallback cb;
  int rv = delegate->ReadData(cb.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  const char kResponseBody[] = "Hello world!";

  // Server sends data.
  std::string header = ConstructDataHeader(strlen(kResponseBody));
  ProcessPacket(ConstructServerDataPacket(3, !kFin, header + kResponseBody));

  EXPECT_EQ(static_cast<int64_t>(strlen(kResponseBody)), cb.WaitForResult());
  EXPECT_EQ(std::string(kResponseBody), delegate->data_received());

  size_t spdy_trailers_frame_length;
  quiche::HttpHeaderBlock trailers;
  trailers["foo"] = "bar";
  // Server sends trailers.
  ProcessPacket(ConstructResponseTrailersPacket(4, kFin, trailers.Clone(),
                                                &spdy_trailers_frame_length));

  delegate->WaitUntilNextCallback(kOnTrailersReceived);
  EXPECT_EQ(trailers, delegate->trailers());

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
}

// Tests that if QuicChromiumClientSession is closed after
// BidirectionalStreamQuicImpl::OnStreamReady() but before
// QuicChromiumClientSession::Handle::ReleaseStream() is called, there is no
// crash. Regression test for crbug.com/754823.
TEST_P(BidirectionalStreamQuicImplTest, ReleaseStreamFails) {
  SetRequest("GET", "/", DEFAULT_PRIORITY);
  Initialize();

  ConfirmHandshake();

  BidirectionalStreamRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = true;
  request.priority = DEFAULT_PRIORITY;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate =
      std::make_unique<TestDelegateBase>(read_buffer.get(), kReadBufferSize);
  delegate->set_trailers_expected(true);
  // QuicChromiumClientSession::Handle::RequestStream() returns OK synchronously
  // because Initialize() has established a Session.
  delegate->Start(&request, net_log_with_source(),
                  session()->CreateHandle(destination_));
  // Now closes the underlying session.
  session_->CloseSessionOnError(ERR_ABORTED, quic::QUIC_INTERNAL_ERROR,
                                quic::ConnectionCloseBehavior::SILENT_CLOSE);
  delegate->WaitUntilNextCallback(kOnFailed);

  EXPECT_THAT(delegate->error(), IsError(ERR_CONNECTION_CLOSED));
}

}  // namespace net::test
```