Response:
The user wants me to analyze a C++ source code file for the Chromium network stack, specifically `net/http/bidirectional_stream_unittest.cc`. This is the second part of a three-part request, and I need to summarize the functionality covered in this specific snippet.

Here's a breakdown of the tasks:

1. **Understand the code:** Read through the provided C++ test code to determine the features of the `BidirectionalStream` being tested.
2. **Identify functionalities:** List the specific scenarios and edge cases being tested by these unit tests.
3. **Check for JavaScript relation:** Determine if any of the tested functionalities have a direct equivalent or interaction point with JavaScript in a web browser context.
4. **Analyze logic and provide examples:** For tests involving logical flow, describe the setup, expected input, and output.
5. **Identify common user/programming errors:**  Based on the tests, deduce potential mistakes developers might make when using the `BidirectionalStream` API.
6. **Explain user steps to reach the code:** Describe how a user's actions in a browser might lead to the execution of this code.
7. **Summarize the functionality of this part:**  Provide a concise overview of the features covered in the provided code snippet.

**Mental Walkthrough of the Code:**

The provided code contains numerous test cases (using the `TEST_F` macro, which indicates a gtest framework). Each test case focuses on a specific aspect of the `BidirectionalStream` functionality. I can see tests for:

- **Interleaving read and send data:**  Verifying correct handling when sending data while simultaneously receiving data.
- **Coalescing small data buffers:** Checking if the stream efficiently combines small data chunks before sending.
- **Completing asynchronous reads:** Testing if reads are correctly finalized even if the remote end closes the connection.
- **Buffering of received data:** Examining how the stream handles and delivers multiple incoming data frames.
- **Buffering with trailers:**  Testing the handling of HTTP trailers (metadata sent after the main response body).
- **Deleting the stream at various points:** Testing the robustness of the stream when it's explicitly closed by the client during different phases (after sending, during reading, during callback functions).
- **Handling protocol errors:** Verifying that the stream correctly propagates errors like invalid headers.
- **Deleting the stream within callbacks:**  Ensuring that deleting the stream from within a callback function works as expected.
- **Honoring alternative service headers:** Checking if the stream correctly processes `alt-svc` headers.

**Connecting to JavaScript (if applicable):**

JavaScript's `fetch` API and `XMLHttpRequest` can initiate network requests that might internally utilize `BidirectionalStream` for HTTP/2 connections. Specifically, the ability to stream data (both sending and receiving) is a key feature exposed to JavaScript.

**Logical Reasoning Examples:**

For tests like `TestInterleaveReadDataAndSendData`, I can deduce the expected behavior based on the mock read/write setup and delegate interactions.

**Common Errors:**

Based on the "delete stream" tests, a common error might be attempting to use the stream after it has been explicitly deleted.

**User Steps:**

A user browsing a website that uses HTTP/2 and streams data (e.g., for live updates or large file uploads) would be interacting with code paths that could lead to this `BidirectionalStream` implementation.

**Summary of Part 2:**

This section of the unit tests focuses on the data transfer and stream lifecycle management aspects of `BidirectionalStream`, including interleaving send and receive, efficient data handling, proper closing and error handling, and interactions with HTTP/2 features like trailers.

Now, I will generate the structured response based on these observations.
好的，让我们来分析一下 `net/http/bidirectional_stream_unittest.cc` 文件的第 2 部分代码的功能。

**功能列举:**

这部分代码主要测试了 `BidirectionalStream` 在各种数据传输场景下的行为，以及在生命周期管理方面的功能，特别是涉及到数据发送、接收、缓冲以及在不同阶段删除流的情况。

具体来说，测试了以下功能：

1. **交错读取和发送数据 (`TestInterleaveReadDataAndSendData`)**: 验证在同时进行数据读取和发送时，`BidirectionalStream` 是否能正确处理。
2. **合并小数据块 (`TestCoalesceSmallDataBuffers`)**: 测试当发送多个小的数据块时，`BidirectionalStream` 是否能将它们合并成一个较大的数据帧发送，以提高效率。
3. **完成异步读取 (`TestCompleteAsyncRead`)**: 验证即使读取操作是异步的，并且在读取完成前连接关闭，`BidirectionalStream` 是否能正确完成读取操作。
4. **数据缓冲 (`TestBuffering`)**: 测试当接收到多个数据帧时，`BidirectionalStream` 是否能够将它们缓冲起来，并在适当的时候一次性传递给上层。
5. **带尾部的数据缓冲 (`TestBufferingWithTrailers`)**: 类似于数据缓冲，但增加了对 HTTP 尾部 (Trailers) 的测试，验证在接收到尾部时，`BidirectionalStream` 的处理逻辑。
6. **发送数据后删除流 (`DeleteStreamAfterSendData`)**: 测试在发送部分数据后立即删除 `BidirectionalStream` 的行为，验证资源是否被正确释放，并且不会发生崩溃。
7. **读取数据期间删除流 (`DeleteStreamDuringReadData`)**: 测试在调用 `ReadData` 并且尚未返回结果（`ERR_IO_PENDING`）时删除 `BidirectionalStream` 的行为。
8. **处理协议错误 (`PropagateProtocolError`)**: 验证当接收到违反协议的响应头（例如，包含大写字母的 header）时，`BidirectionalStream` 是否能正确检测并通知上层。
9. **在接收到响应头时删除流 (`DeleteStreamDuringOnHeadersReceived`)**: 测试在接收到响应头并且回调 `OnHeadersReceived` 方法时删除 `BidirectionalStream` 的行为。
10. **在读取到数据时删除流 (`DeleteStreamDuringOnDataRead`)**: 测试在成功读取到部分数据并且回调 `OnDataRead` 方法时删除 `BidirectionalStream` 的行为。
11. **在接收到尾部时删除流 (`DeleteStreamDuringOnTrailersReceived`)**: 测试在接收到响应尾部并且回调 `OnTrailersReceived` 方法时删除 `BidirectionalStream` 的行为。
12. **在发生错误时删除流 (`DeleteStreamDuringOnFailed`)**: 测试在发生网络错误并且回调 `OnFailed` 方法时删除 `BidirectionalStream` 的行为。
13. **处理备用服务头部 (`TestHonorAlternativeServiceHeader`)**: 测试 `BidirectionalStream` 是否能正确解析和处理 `alt-svc` 头部。

**与 JavaScript 的关系及举例说明:**

`BidirectionalStream` 是 Chromium 网络栈中处理 HTTP/2 双向流的核心组件。在 JavaScript 中，可以通过 `fetch` API 或 `XMLHttpRequest` 发起网络请求。当浏览器与支持 HTTP/2 的服务器建立连接时，底层的网络栈可能会使用 `BidirectionalStream` 来处理请求和响应。

**举例说明:**

假设一个 JavaScript 应用程序需要通过 HTTP/2 与服务器建立持久连接，进行实时数据推送和接收。

```javascript
// JavaScript 代码示例 (使用 fetch API 的 ReadableStream)
fetch('/data-stream', {
  method: 'GET',
  headers: {
    'Accept': 'text/event-stream' // 或者其他适合流式传输的 Content-Type
  }
}).then(response => {
  const reader = response.body.getReader();
  let partialChunk = '';

  return new ReadableStream({
    start(controller) {
      function push() {
        reader.read().then(({ done, value }) => {
          if (done) {
            controller.close();
            return;
          }
          // 处理接收到的数据块
          partialChunk += new TextDecoder().decode(value);
          // ... (解析 partialChunk 并将其推送到 controller)
          controller.enqueue(value); // 示例：直接将原始数据推送到流
          push();
        });
      }
      push();
    }
  });
}).then(stream => {
  // 使用 stream 处理数据
  const textReader = stream.getReader();
  function read() {
    textReader.read().then(({ done, value }) => {
      if (done) {
        console.log('Stream finished');
        return;
      }
      console.log('Received chunk:', new TextDecoder().decode(value));
      read();
    });
  }
  read();
}).catch(error => {
  console.error('Error during stream:', error);
});
```

在这个例子中，当 `fetch` 发起 `/data-stream` 请求时，如果服务器支持 HTTP/2，并且协商使用了 HTTP/2 协议，那么 Chromium 的网络栈会创建 `BidirectionalStream` 来处理这个请求。  `bidirectional_stream_unittest.cc` 中的测试用例，例如 `TestInterleaveReadDataAndSendData` 和 `TestBuffering`，就模拟了这种场景下 `BidirectionalStream` 的行为。

**逻辑推理、假设输入与输出:**

**示例：`TestInterleaveReadDataAndSendData`**

**假设输入:**

- **客户端发送:** 一个 POST 请求头，然后交错发送三个数据帧 (每个 `kBodyDataSize` 大小)。
- **服务器接收:** 接收到请求头后，立即发送一个响应头，然后交错发送两个数据帧（没有具体内容），并在第二个数据帧中设置 `FIN` 标志表示结束。

**预期输出:**

- **客户端 (TestDelegateBase):**
    - 成功发送所有请求数据。
    - 成功接收到响应头，状态码为 "200"。
    - `on_data_read_count()` 被调用两次，对应接收到的两个数据帧。
    - `on_data_sent_count()` 被调用三次，对应发送的三个数据帧。
    - `ReadData()` 最终返回 `OK`，表示读取完成。
    - `GetProtocol()` 返回 `kProtoHTTP2`。
    - `GetTotalSentBytes()` 和 `GetTotalReceivedBytes()` 返回正确的字节数。

**常见的使用错误及举例说明:**

1. **在流被删除后尝试发送或接收数据:**  `BidirectionalStream` 被删除后，任何尝试在其上进行操作都会导致错误。例如，在 `DeleteStreamAfterSendData` 测试中，如果在 `delegate->DeleteStream()` 之后仍然尝试调用 `delegate->SendData()` 或 `delegate->ReadData()`，就会发生错误。

   ```c++
   // 错误示例 (假设在 DeleteStreamDelegate 中)
   void OnHeadersReceived(const spdy::SpdyHeaderBlock& response_headers) override {
     delegate_->DeleteStream();
     // 错误：此时流已经被删除
     scoped_refptr<net::StringIOBuffer> buf =
         base::MakeRefCounted<net::StringIOBuffer>("some data");
     delegate_->SendData(buf, buf->size(), true);
   }
   ```

2. **没有正确处理 `ReadData()` 返回的 `ERR_IO_PENDING`:**  当 `ReadData()` 返回 `ERR_IO_PENDING` 时，意味着数据尚未就绪，需要等待异步通知。如果程序没有正确处理这种情况，可能会导致程序卡死或数据丢失。

   ```c++
   // 错误示例
   int rv = delegate_->ReadData();
   if (rv < 0) { // 仅检查错误
     // ... 错误处理
   } else {
     // 假设数据已就绪，但实际上可能是 ERR_IO_PENDING
     // ... 处理读取到的数据
   }
   ```

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入一个 HTTPS URL 并访问，该服务器支持 HTTP/2。**
2. **浏览器与服务器建立 TCP 连接，并进行 TLS 握手。**
3. **在 TLS 握手过程中，浏览器和服务器通过 ALPN (Application-Layer Protocol Negotiation) 协商使用 HTTP/2 协议。**
4. **当需要发送 HTTP 请求时（例如，用户点击链接、提交表单，或者 JavaScript 发起 `fetch` 请求），Chromium 网络栈会创建一个 `HttpStreamFactory::Job` 来处理该请求。**
5. **对于 HTTP/2 请求，`HttpStreamFactory::Job` 可能会创建一个 `BidirectionalStreamSpdyImpl` 实例，它实现了 `BidirectionalStream` 接口。**
6. **当 JavaScript 代码调用 `fetch` API 发起一个需要流式传输的请求时（例如，设置了特定的 `Accept` 头部），或者当服务器推送 (push) 内容时，`BidirectionalStream` 的数据发送和接收方法会被调用，这就会触发 `bidirectional_stream_unittest.cc` 中测试的各种场景。**
7. **如果发生网络错误，或者服务器发送了违反 HTTP/2 协议的数据，`BidirectionalStream` 的错误处理逻辑会被触发，例如 `PropagateProtocolError` 测试中模拟的情况。**
8. **用户关闭网页或取消请求可能会导致 `BidirectionalStream` 被删除，这对应了 `DeleteStreamAfterSendData` 和 `DeleteStreamDuringReadData` 等测试场景。**

**归纳一下它的功能 (第 2 部分):**

这部分代码主要集中测试了 `BidirectionalStream` 组件在各种数据传输和生命周期管理场景下的正确性和健壮性。它涵盖了数据交错发送和接收、小数据块的合并优化、异步读取的完成、数据缓冲机制、HTTP 尾部的处理，以及在不同阶段删除流的安全性。此外，还测试了对协议错误的识别和处理，以及对备用服务头部的支持。总而言之，这部分测试旨在确保 `BidirectionalStream` 能够可靠高效地处理 HTTP/2 双向数据流。

Prompt: 
```
这是目录为net/http/bidirectional_stream_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
ogEventPhase::NONE);
  EXPECT_EQ(NetLogSourceType::BIDIRECTIONAL_STREAM, entries[index].source.type);
  // Received bytes for synchronous read.
  index = ExpectLogContainsSomewhere(
      entries, index, NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_RECEIVED,
      NetLogEventPhase::NONE);
  EXPECT_EQ(NetLogSourceType::BIDIRECTIONAL_STREAM, entries[index].source.type);
  ExpectLogContainsSomewhere(entries, index,
                             NetLogEventType::BIDIRECTIONAL_STREAM_ALIVE,
                             NetLogEventPhase::END);
}

TEST_F(BidirectionalStreamTest, TestInterleaveReadDataAndSendData) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize * 3, LOWEST, nullptr, 0));
  spdy::SpdySerializedFrame data_frame1(
      spdy_util_.ConstructSpdyDataFrame(1, kBodyDataString, /*fin=*/false));
  spdy::SpdySerializedFrame data_frame2(
      spdy_util_.ConstructSpdyDataFrame(1, kBodyDataString, /*fin=*/false));
  spdy::SpdySerializedFrame data_frame3(
      spdy_util_.ConstructSpdyDataFrame(1, kBodyDataString, /*fin=*/true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(data_frame1, 3),
      CreateMockWrite(data_frame2, 6), CreateMockWrite(data_frame3, 9),
  };

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame response_body_frame1(
      spdy_util_.ConstructSpdyDataFrame(1, false));
  spdy::SpdySerializedFrame response_body_frame2(
      spdy_util_.ConstructSpdyDataFrame(1, true));

  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a pause.
      CreateMockRead(response_body_frame1, 4),
      MockRead(ASYNC, ERR_IO_PENDING, 5),  // Force a pause.
      CreateMockRead(response_body_frame2, 7),
      MockRead(ASYNC, ERR_IO_PENDING, 8),  // Force a pause.
      MockRead(ASYNC, 0, 10),
  };

  InitSession(reads, writes, SocketTag());

  auto request_info = std::make_unique<BidirectionalStreamRequestInfo>();
  request_info->method = "POST";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->extra_headers.SetHeader(
      HttpRequestHeaders::kContentLength,
      base::NumberToString(kBodyDataSize * 3));

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto timer = std::make_unique<MockTimer>();
  MockTimer* timer_ptr = timer.get();
  auto delegate = std::make_unique<TestDelegateBase>(
      read_buffer.get(), kReadBufferSize, std::move(timer));
  delegate->set_do_not_start_read(true);
  delegate->Start(std::move(request_info), http_session_.get());
  // Send the request and receive response headers.
  sequenced_data_->RunUntilPaused();
  EXPECT_FALSE(timer_ptr->IsRunning());

  // Send a DATA frame.
  scoped_refptr<StringIOBuffer> buf =
      base::MakeRefCounted<StringIOBuffer>(kBodyDataString);

  // Send a DATA frame.
  delegate->SendData(buf, buf->size(), false);
  // ReadData and it should return asynchronously because no data is buffered.
  int rv = delegate->ReadData();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Deliver a DATA frame, and fire the timer.
  sequenced_data_->Resume();
  sequenced_data_->RunUntilPaused();
  timer_ptr->Fire();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, delegate->on_data_sent_count());
  EXPECT_EQ(1, delegate->on_data_read_count());

  // Send a DATA frame.
  delegate->SendData(buf, buf->size(), false);
  // ReadData and it should return asynchronously because no data is buffered.
  rv = delegate->ReadData();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Deliver a DATA frame, and fire the timer.
  sequenced_data_->Resume();
  sequenced_data_->RunUntilPaused();
  timer_ptr->Fire();
  base::RunLoop().RunUntilIdle();
  // Last DATA frame is read. Server half closes.
  EXPECT_EQ(2, delegate->on_data_read_count());
  EXPECT_EQ(2, delegate->on_data_sent_count());

  // Send the last body frame. Client half closes.
  delegate->SendData(buf, buf->size(), true);
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(3, delegate->on_data_sent_count());

  // OnClose is invoked since both sides are closed.
  rv = delegate->ReadData();
  EXPECT_THAT(rv, IsOk());

  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);
  EXPECT_EQ(2, delegate->on_data_read_count());
  EXPECT_EQ(3, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  EXPECT_EQ(CountWriteBytes(writes), delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), delegate->GetTotalReceivedBytes());
}

TEST_F(BidirectionalStreamTest, TestCoalesceSmallDataBuffers) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize * 1, LOWEST, nullptr, 0));
  std::string body_data = "some really long piece of data";
  spdy::SpdySerializedFrame data_frame1(
      spdy_util_.ConstructSpdyDataFrame(1, body_data, /*fin=*/true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(data_frame1, 1),
  };

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame response_body_frame1(
      spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 2),
      MockRead(ASYNC, ERR_IO_PENDING, 3),  // Force a pause.
      CreateMockRead(response_body_frame1, 4), MockRead(ASYNC, 0, 5),
  };

  InitSession(reads, writes, SocketTag());

  auto request_info = std::make_unique<BidirectionalStreamRequestInfo>();
  request_info->method = "POST";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->extra_headers.SetHeader(
      HttpRequestHeaders::kContentLength,
      base::NumberToString(kBodyDataSize * 1));

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto timer = std::make_unique<MockTimer>();
  auto delegate = std::make_unique<TestDelegateBase>(
      read_buffer.get(), kReadBufferSize, std::move(timer));
  delegate->set_do_not_start_read(true);
  TestCompletionCallback callback;
  delegate->Start(std::move(request_info), http_session_.get(),
                  callback.callback());
  // Wait until the stream is ready.
  callback.WaitForResult();
  // Send a DATA frame.
  scoped_refptr<StringIOBuffer> buf =
      base::MakeRefCounted<StringIOBuffer>(body_data.substr(0, 5));
  scoped_refptr<StringIOBuffer> buf2 = base::MakeRefCounted<StringIOBuffer>(
      body_data.substr(5, body_data.size() - 5));
  delegate->SendvData({buf, buf2.get()}, {buf->size(), buf2->size()}, true);
  sequenced_data_->RunUntilPaused();  // OnHeadersReceived.
  // ReadData and it should return asynchronously because no data is buffered.
  EXPECT_THAT(delegate->ReadData(), IsError(ERR_IO_PENDING));
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, delegate->on_data_sent_count());
  EXPECT_EQ(1, delegate->on_data_read_count());

  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);
  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(1, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  EXPECT_EQ(CountWriteBytes(writes), delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), delegate->GetTotalReceivedBytes());

  auto entries = net_log_observer_.GetEntries();
  size_t index = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::BIDIRECTIONAL_STREAM_SENDV_DATA,
      NetLogEventPhase::NONE);
  EXPECT_EQ(2, GetIntegerValueFromParams(entries[index], "num_buffers"));

  index = ExpectLogContainsSomewhereAfter(
      entries, index,
      NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_SENT_COALESCED,
      NetLogEventPhase::BEGIN);
  EXPECT_EQ(2,
            GetIntegerValueFromParams(entries[index], "num_buffers_coalesced"));

  index = ExpectLogContainsSomewhereAfter(
      entries, index, NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_SENT,
      NetLogEventPhase::NONE);
  EXPECT_EQ(buf->size(),
            GetIntegerValueFromParams(entries[index], "byte_count"));

  index = ExpectLogContainsSomewhereAfter(
      entries, index + 1, NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_SENT,
      NetLogEventPhase::NONE);
  EXPECT_EQ(buf2->size(),
            GetIntegerValueFromParams(entries[index], "byte_count"));

  ExpectLogContainsSomewhere(
      entries, index,
      NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_SENT_COALESCED,
      NetLogEventPhase::END);
}

// Tests that BidirectionalStreamSpdyImpl::OnClose will complete any remaining
// read even if the read queue is empty.
TEST_F(BidirectionalStreamTest, TestCompleteAsyncRead) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(kDefaultUrl, 1, LOWEST));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  spdy::SpdySerializedFrame response_body_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "", true));

  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a pause.
      CreateMockRead(response_body_frame, 3), MockRead(SYNCHRONOUS, 0, 4),
  };

  InitSession(reads, writes, SocketTag());

  auto request_info = std::make_unique<BidirectionalStreamRequestInfo>();
  request_info->method = "GET";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->end_stream_on_headers = true;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto timer = std::make_unique<MockTimer>();
  MockTimer* timer_ptr = timer.get();
  auto delegate = std::make_unique<TestDelegateBase>(
      read_buffer.get(), kReadBufferSize, std::move(timer));
  delegate->set_do_not_start_read(true);
  delegate->Start(std::move(request_info), http_session_.get());
  // Write request, and deliver response headers.
  sequenced_data_->RunUntilPaused();
  EXPECT_FALSE(timer_ptr->IsRunning());

  // ReadData should return asynchronously because no data is buffered.
  int rv = delegate->ReadData();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Deliver END_STREAM.
  // OnClose should trigger completion of the remaining read.
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);
  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(0u, delegate->data_received().size());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  EXPECT_EQ(CountWriteBytes(writes), delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), delegate->GetTotalReceivedBytes());
}

TEST_F(BidirectionalStreamTest, TestBuffering) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(kDefaultUrl, 1, LOWEST));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  const char* const kExtraResponseHeaders[] = {"header-name", "header-value"};
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(kExtraResponseHeaders, 1, 1));

  spdy::SpdySerializedFrame body_frame(
      spdy_util_.ConstructSpdyDataFrame(1, false));
  // Last body frame has END_STREAM flag set.
  spdy::SpdySerializedFrame last_body_frame(
      spdy_util_.ConstructSpdyDataFrame(1, true));

  MockRead reads[] = {
      CreateMockRead(resp, 1),
      CreateMockRead(body_frame, 2),
      CreateMockRead(body_frame, 3),
      MockRead(ASYNC, ERR_IO_PENDING, 4),  // Force a pause.
      CreateMockRead(last_body_frame, 5),
      MockRead(SYNCHRONOUS, 0, 6),
  };

  InitSession(reads, writes, SocketTag());

  auto request_info = std::make_unique<BidirectionalStreamRequestInfo>();
  request_info->method = "GET";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->end_stream_on_headers = true;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto timer = std::make_unique<MockTimer>();
  MockTimer* timer_ptr = timer.get();
  auto delegate = std::make_unique<TestDelegateBase>(
      read_buffer.get(), kReadBufferSize, std::move(timer));
  delegate->Start(std::move(request_info), http_session_.get());
  // Deliver two DATA frames together.
  sequenced_data_->RunUntilPaused();
  EXPECT_TRUE(timer_ptr->IsRunning());
  timer_ptr->Fire();
  base::RunLoop().RunUntilIdle();
  // This should trigger |more_read_data_pending_| to execute the task at a
  // later time, and Delegate::OnReadComplete should not have been called.
  EXPECT_TRUE(timer_ptr->IsRunning());
  EXPECT_EQ(0, delegate->on_data_read_count());

  // Fire the timer now, the two DATA frame should be combined into one
  // single Delegate::OnReadComplete callback.
  timer_ptr->Fire();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(kUploadDataSize * 2,
            static_cast<int>(delegate->data_received().size()));

  // Deliver last DATA frame and EOF. There will be an additional
  // Delegate::OnReadComplete callback.
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(2, delegate->on_data_read_count());
  EXPECT_EQ(kUploadDataSize * 3,
            static_cast<int>(delegate->data_received().size()));

  const quiche::HttpHeaderBlock& response_headers =
      delegate->response_headers();
  EXPECT_EQ("200", response_headers.find(":status")->second);
  EXPECT_EQ("header-value", response_headers.find("header-name")->second);
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  EXPECT_EQ(CountWriteBytes(writes), delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), delegate->GetTotalReceivedBytes());
}

TEST_F(BidirectionalStreamTest, TestBufferingWithTrailers) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(kDefaultUrl, 1, LOWEST));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  const char* const kExtraResponseHeaders[] = {"header-name", "header-value"};
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(kExtraResponseHeaders, 1, 1));

  spdy::SpdySerializedFrame body_frame(
      spdy_util_.ConstructSpdyDataFrame(1, false));

  quiche::HttpHeaderBlock trailers;
  trailers["foo"] = "bar";
  spdy::SpdySerializedFrame response_trailers(
      spdy_util_.ConstructSpdyResponseHeaders(1, std::move(trailers), true));

  MockRead reads[] = {
      CreateMockRead(resp, 1),
      CreateMockRead(body_frame, 2),
      CreateMockRead(body_frame, 3),
      CreateMockRead(body_frame, 4),
      MockRead(ASYNC, ERR_IO_PENDING, 5),  // Force a pause.
      CreateMockRead(response_trailers, 6),
      MockRead(SYNCHRONOUS, 0, 7),
  };

  InitSession(reads, writes, SocketTag());

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto timer = std::make_unique<MockTimer>();
  MockTimer* timer_ptr = timer.get();
  auto delegate = std::make_unique<TestDelegateBase>(
      read_buffer.get(), kReadBufferSize, std::move(timer));

  auto request_info = std::make_unique<BidirectionalStreamRequestInfo>();
  request_info->method = "GET";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->end_stream_on_headers = true;

  delegate->Start(std::move(request_info), http_session_.get());
  // Deliver all three DATA frames together.
  sequenced_data_->RunUntilPaused();
  EXPECT_TRUE(timer_ptr->IsRunning());
  timer_ptr->Fire();
  base::RunLoop().RunUntilIdle();
  // This should trigger |more_read_data_pending_| to execute the task at a
  // later time, and Delegate::OnReadComplete should not have been called.
  EXPECT_TRUE(timer_ptr->IsRunning());
  EXPECT_EQ(0, delegate->on_data_read_count());

  // Deliver trailers. Remaining read should be completed, since OnClose is
  // called right after OnTrailersReceived. The three DATA frames should be
  // delivered in a single OnReadCompleted callback.
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(kUploadDataSize * 3,
            static_cast<int>(delegate->data_received().size()));
  const quiche::HttpHeaderBlock& response_headers =
      delegate->response_headers();
  EXPECT_EQ("200", response_headers.find(":status")->second);
  EXPECT_EQ("header-value", response_headers.find("header-name")->second);
  EXPECT_EQ("bar", delegate->trailers().find("foo")->second);
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  EXPECT_EQ(CountWriteBytes(writes), delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), delegate->GetTotalReceivedBytes());
}

TEST_F(BidirectionalStreamTest, DeleteStreamAfterSendData) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize * 3, LOWEST, nullptr, 0));
  spdy::SpdySerializedFrame data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, kBodyDataString, /*fin=*/false));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));

  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(data_frame, 3),
      CreateMockWrite(rst, 5),
  };

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a pause.
      MockRead(ASYNC, ERR_IO_PENDING, 4),  // Force a pause.
      MockRead(ASYNC, 0, 6),
  };

  InitSession(reads, writes, SocketTag());

  auto request_info = std::make_unique<BidirectionalStreamRequestInfo>();
  request_info->method = "POST";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->extra_headers.SetHeader(
      HttpRequestHeaders::kContentLength,
      base::NumberToString(kBodyDataSize * 3));

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate =
      std::make_unique<TestDelegateBase>(read_buffer.get(), kReadBufferSize);
  delegate->set_do_not_start_read(true);
  delegate->Start(std::move(request_info), http_session_.get());
  // Send the request and receive response headers.
  sequenced_data_->RunUntilPaused();
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());

  // Send a DATA frame.
  scoped_refptr<StringIOBuffer> buf =
      base::MakeRefCounted<StringIOBuffer>(kBodyDataString);
  delegate->SendData(buf, buf->size(), false);
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();

  delegate->DeleteStream();
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);
  EXPECT_EQ(0, delegate->on_data_read_count());
  // OnDataSent may or may not have been invoked.
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  // Bytes sent excludes the RST frame.
  EXPECT_EQ(
      CountWriteBytes(base::make_span(writes).first(std::size(writes) - 1)),
      delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), delegate->GetTotalReceivedBytes());
}

TEST_F(BidirectionalStreamTest, DeleteStreamDuringReadData) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize * 3, LOWEST, nullptr, 0));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));

  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 4),
  };

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame response_body_frame(
      spdy_util_.ConstructSpdyDataFrame(1, false));

  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a pause.
      CreateMockRead(response_body_frame, 3), MockRead(ASYNC, 0, 5),
  };

  InitSession(reads, writes, SocketTag());

  auto request_info = std::make_unique<BidirectionalStreamRequestInfo>();
  request_info->method = "POST";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->extra_headers.SetHeader(
      HttpRequestHeaders::kContentLength,
      base::NumberToString(kBodyDataSize * 3));

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate =
      std::make_unique<TestDelegateBase>(read_buffer.get(), kReadBufferSize);
  delegate->set_do_not_start_read(true);
  delegate->Start(std::move(request_info), http_session_.get());
  // Send the request and receive response headers.
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);
  // Delete the stream after ReadData returns ERR_IO_PENDING.
  int rv = delegate->ReadData();
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  delegate->DeleteStream();
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(0, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  // Bytes sent excludes the RST frame.
  EXPECT_EQ(
      CountWriteBytes(base::make_span(writes).first(std::size(writes) - 1)),
      delegate->GetTotalSentBytes());
  // Response body frame isn't read becase stream is deleted once read returns
  // ERR_IO_PENDING.
  EXPECT_EQ(CountReadBytes(base::make_span(reads).first(std::size(reads) - 2)),
            delegate->GetTotalReceivedBytes());
}

// Receiving a header with uppercase ASCII will result in a protocol error,
// which should be propagated via Delegate::OnFailed.
TEST_F(BidirectionalStreamTest, PropagateProtocolError) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize * 3, LOW, nullptr, 0));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_PROTOCOL_ERROR));

  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 2),
  };

  const char* const kExtraHeaders[] = {"X-UpperCase", "yes"};
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(kExtraHeaders, 1, 1));

  MockRead reads[] = {
      CreateMockRead(resp, 1), MockRead(ASYNC, 0, 3),
  };

  InitSession(reads, writes, SocketTag());

  auto request_info = std::make_unique<BidirectionalStreamRequestInfo>();
  request_info->method = "POST";
  request_info->url = default_url_;
  request_info->extra_headers.SetHeader(
      HttpRequestHeaders::kContentLength,
      base::NumberToString(kBodyDataSize * 3));

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate =
      std::make_unique<TestDelegateBase>(read_buffer.get(), kReadBufferSize);
  delegate->SetRunUntilCompletion(true);
  delegate->Start(std::move(request_info), http_session_.get());

  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(delegate->error(), IsError(ERR_HTTP2_PROTOCOL_ERROR));
  EXPECT_EQ(delegate->response_headers().end(),
            delegate->response_headers().find(":status"));
  EXPECT_EQ(0, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  // BidirectionalStreamSpdyStreamJob does not count the bytes sent for |rst|
  // because it is sent after SpdyStream::Delegate::OnClose is called.
  EXPECT_EQ(CountWriteBytes(base::make_span(writes, 1u)),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(0, delegate->GetTotalReceivedBytes());

  auto entries = net_log_observer_.GetEntries();

  size_t index = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::BIDIRECTIONAL_STREAM_READY,
      NetLogEventPhase::NONE);
  EXPECT_TRUE(
      GetBooleanValueFromParams(entries[index], "request_headers_sent"));

  index = ExpectLogContainsSomewhere(
      entries, index, NetLogEventType::BIDIRECTIONAL_STREAM_FAILED,
      NetLogEventPhase::NONE);
  EXPECT_EQ(ERR_HTTP2_PROTOCOL_ERROR,
            GetNetErrorCodeFromParams(entries[index]));
}

TEST_F(BidirectionalStreamTest, DeleteStreamDuringOnHeadersReceived) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(kDefaultUrl, 1, LOWEST));

  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 2),
  };

  const char* const kExtraResponseHeaders[] = {"header-name", "header-value"};
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(kExtraResponseHeaders, 1, 1));

  MockRead reads[] = {
      CreateMockRead(resp, 1), MockRead(ASYNC, 0, 3),
  };

  InitSession(reads, writes, SocketTag());

  auto request_info = std::make_unique<BidirectionalStreamRequestInfo>();
  request_info->method = "GET";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->end_stream_on_headers = true;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate = std::make_unique<DeleteStreamDelegate>(
      read_buffer.get(), kReadBufferSize,
      DeleteStreamDelegate::Phase::ON_HEADERS_RECEIVED);
  delegate->SetRunUntilCompletion(true);
  delegate->Start(std::move(request_info), http_session_.get());
  // Makes sure delegate does not get called.
  base::RunLoop().RunUntilIdle();
  const quiche::HttpHeaderBlock& response_headers =
      delegate->response_headers();
  EXPECT_EQ("200", response_headers.find(":status")->second);
  EXPECT_EQ("header-value", response_headers.find("header-name")->second);
  EXPECT_EQ(0u, delegate->data_received().size());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(0, delegate->on_data_read_count());

  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  // Bytes sent excludes the RST frame.
  EXPECT_EQ(
      CountWriteBytes(base::make_span(writes).first(std::size(writes) - 1)),
      delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), delegate->GetTotalReceivedBytes());
}

TEST_F(BidirectionalStreamTest, DeleteStreamDuringOnDataRead) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(kDefaultUrl, 1, LOWEST));

  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 3),
  };

  const char* const kExtraResponseHeaders[] = {"header-name", "header-value"};
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(kExtraResponseHeaders, 1, 1));

  spdy::SpdySerializedFrame response_body_frame(
      spdy_util_.ConstructSpdyDataFrame(1, false));

  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(response_body_frame, 2),
      MockRead(ASYNC, 0, 4),
  };

  InitSession(reads, writes, SocketTag());

  auto request_info = std::make_unique<BidirectionalStreamRequestInfo>();
  request_info->method = "GET";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->end_stream_on_headers = true;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate = std::make_unique<DeleteStreamDelegate>(
      read_buffer.get(), kReadBufferSize,
      DeleteStreamDelegate::Phase::ON_DATA_READ);
  delegate->SetRunUntilCompletion(true);
  delegate->Start(std::move(request_info), http_session_.get());
  // Makes sure delegate does not get called.
  base::RunLoop().RunUntilIdle();
  const quiche::HttpHeaderBlock& response_headers =
      delegate->response_headers();
  EXPECT_EQ("200", response_headers.find(":status")->second);
  EXPECT_EQ("header-value", response_headers.find("header-name")->second);
  EXPECT_EQ(kUploadDataSize * 1,
            static_cast<int>(delegate->data_received().size()));
  EXPECT_EQ(0, delegate->on_data_sent_count());

  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  // Bytes sent excludes the RST frame.
  EXPECT_EQ(
      CountWriteBytes(base::make_span(writes).first(std::size(writes) - 1)),
      delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), delegate->GetTotalReceivedBytes());
}

TEST_F(BidirectionalStreamTest, DeleteStreamDuringOnTrailersReceived) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(kDefaultUrl, 1, LOWEST));

  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 4),
  };

  const char* const kExtraResponseHeaders[] = {"header-name", "header-value"};
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(kExtraResponseHeaders, 1, 1));

  spdy::SpdySerializedFrame response_body_frame(
      spdy_util_.ConstructSpdyDataFrame(1, false));

  quiche::HttpHeaderBlock trailers;
  trailers["foo"] = "bar";
  spdy::SpdySerializedFrame response_trailers(
      spdy_util_.ConstructSpdyResponseHeaders(1, std::move(trailers), true));

  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(response_body_frame, 2),
      CreateMockRead(response_trailers, 3), MockRead(ASYNC, 0, 5),
  };

  InitSession(reads, writes, SocketTag());

  auto request_info = std::make_unique<BidirectionalStreamRequestInfo>();
  request_info->method = "GET";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->end_stream_on_headers = true;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate = std::make_unique<DeleteStreamDelegate>(
      read_buffer.get(), kReadBufferSize,
      DeleteStreamDelegate::Phase::ON_TRAILERS_RECEIVED);
  delegate->SetRunUntilCompletion(true);
  delegate->Start(std::move(request_info), http_session_.get());
  // Makes sure delegate does not get called.
  base::RunLoop().RunUntilIdle();
  const quiche::HttpHeaderBlock& response_headers =
      delegate->response_headers();
  EXPECT_EQ("200", response_headers.find(":status")->second);
  EXPECT_EQ("header-value", response_headers.find("header-name")->second);
  EXPECT_EQ("bar", delegate->trailers().find("foo")->second);
  EXPECT_EQ(0, delegate->on_data_sent_count());
  // OnDataRead may or may not have been fired before the stream is
  // deleted.
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  // Bytes sent excludes the RST frame.
  EXPECT_EQ(
      CountWriteBytes(base::make_span(writes).first(std::size(writes) - 1)),
      delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), delegate->GetTotalReceivedBytes());
}

TEST_F(BidirectionalStreamTest, DeleteStreamDuringOnFailed) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(kDefaultUrl, 1, LOWEST));

  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_PROTOCOL_ERROR));

  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 2),
  };

  const char* const kExtraHeaders[] = {"X-UpperCase", "yes"};
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(kExtraHeaders, 1, 1));

  MockRead reads[] = {
      CreateMockRead(resp, 1), MockRead(ASYNC, 0, 3),
  };

  InitSession(reads, writes, SocketTag());

  auto request_info = std::make_unique<BidirectionalStreamRequestInfo>();
  request_info->method = "GET";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->end_stream_on_headers = true;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate = std::make_unique<DeleteStreamDelegate>(
      read_buffer.get(), kReadBufferSize,
      DeleteStreamDelegate::Phase::ON_FAILED);
  delegate->SetRunUntilCompletion(true);
  delegate->Start(std::move(request_info), http_session_.get());
  // Makes sure delegate does not get called.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(delegate->response_headers().end(),
            delegate->response_headers().find(":status"));
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(0, delegate->on_data_read_count());
  EXPECT_THAT(delegate->error(), IsError(ERR_HTTP2_PROTOCOL_ERROR));

  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  // Bytes sent excludes the RST frame.
  EXPECT_EQ(
      CountWriteBytes(base::make_span(writes).first(std::size(writes) - 1)),
      delegate->GetTotalSentBytes());
  EXPECT_EQ(0, delegate->GetTotalReceivedBytes());
}

TEST_F(BidirectionalStreamTest, TestHonorAlternativeServiceHeader) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(kDefaultUrl, 1, LOWEST));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  std::string alt_svc_header_value =
      quic::AlpnForVersion(DefaultSupportedQuicVersions().front());
  alt_svc_header_value.append("=\"www.example.org:443\"");
  const char* const kExtraResponseHeaders[] = {"alt-svc",
                  
"""


```