Response:
The user wants a summary of the functionality of the provided C++ code, which is part of Chromium's network stack and specifically focuses on testing the `WebSocketSpdyStreamAdapter` and `WebSocketQuicStreamAdapter`.

Here's a breakdown of the thought process:

1. **Identify the Core Components:** The code primarily tests two classes: `WebSocketSpdyStreamAdapter` and `WebSocketQuicStreamAdapter`. These adapters likely bridge the gap between the generic WebSocket API and the underlying SPDY/HTTP/2 and QUIC protocols, respectively.

2. **Recognize the Testing Context:**  The code uses the `testing` framework (likely Google Test) and defines various test fixtures (e.g., `WebSocketSpdyStreamAdapterTest`, `WebSocketQuicStreamAdapterTest`). This indicates it's a unit testing file.

3. **Analyze `WebSocketSpdyStreamAdapterTest`:**  The tests within this fixture cover scenarios like:
    * **Basic Read:** Reading data from the underlying SPDY stream. It tests handling of buffered data, stream closure (RST_STREAM), and detached delegates.
    * **Basic Write:** Writing data to the underlying SPDY stream.
    * **Asynchronous Read and Write:**  Testing concurrent read and write operations.
    * **Adapter Destruction in Callbacks:** Checking for crashes when the `WebSocketSpdyStreamAdapter` is destroyed within read or write completion callbacks.
    * **Error Handling:** Specifically testing the translation of a clean SPDY stream closure (RST_STREAM with NO_ERROR) into a `ERR_CONNECTION_CLOSED` error for the WebSocket.

4. **Analyze `WebSocketQuicStreamAdapterTest`:** This fixture tests the QUIC-based adapter. Key test scenarios include:
    * **Disconnection:** Testing the `Disconnect` method.
    * **Asynchronous Adapter Creation:**  Verifying that adapter creation handles stream limits correctly and works asynchronously.
    * **Headers and Disconnect:** Testing scenarios where headers are sent and then the connection is disconnected.
    * **Headers Received then Disconnect:** Testing interaction between header reception and disconnection.
    * **Basic Read:**  Reading data from the underlying QUIC stream. It includes scenarios with different buffer sizes.

5. **Look for JavaScript Relevance:**  While the core of this code is C++, it deals with WebSockets, a technology heavily used in web browsers and JavaScript. The `WebSocketSpdyStreamAdapter` and `WebSocketQuicStreamAdapter` are the underlying mechanisms that handle WebSocket communication for Chromium. Therefore, the tests implicitly demonstrate how Chromium's network stack handles WebSocket data transfer initiated by JavaScript.

6. **Infer Logic and Scenarios:**  Based on the test names and assertions, deduce the expected behavior and the underlying logic being tested. For instance, the "Read RST_STREAM to destroy the stream" test shows how the adapter handles server-initiated stream closure.

7. **Identify Potential User/Programming Errors:**  The tests focusing on destroying the adapter in callbacks highlight potential issues with resource management and lifetime management that a programmer might encounter when working with similar asynchronous network APIs.

8. **Consider the User Journey:**  Think about how a user action in a browser (e.g., opening a WebSocket connection in a web page) would lead to this code being executed. The sequence involves DNS resolution, establishing a connection (potentially over SPDY or QUIC), negotiating the WebSocket handshake, and then data transfer.

9. **Structure the Summary:** Organize the findings into clear categories (general functionality, JavaScript relevance, logic examples, error examples, user journey). For Part 2, focus on summarizing the functionality covered in the provided code snippet.

10. **Refine and Elaborate:** Ensure the explanation is accurate, concise, and addresses all aspects of the prompt. Provide specific examples and clarify technical terms where necessary. For the "Part 2" summary, synthesize the core actions being tested in the provided code.
这是chromium网络栈的源代码文件`net/websockets/websocket_basic_stream_adapters_test.cc`的第二部分，主要功能是测试 `WebSocketSpdyStreamAdapter` 和 `WebSocketQuicStreamAdapter` 这两个类在网络通信中的行为，特别是关于数据读取、写入、连接关闭以及异步操作的处理。

**功能归纳:**

这部分代码主要测试了以下 `WebSocketSpdyStreamAdapter` 和 `WebSocketQuicStreamAdapter` 的功能：

* **`WebSocketSpdyStreamAdapter` 的功能：**
    * **读取数据 (Read):**  测试从底层的 `SpdyStream` 读取数据的功能，包括读取大于底层数据块的数据，以及读取在流被 RST_STREAM 关闭后的剩余缓冲数据。
    * **写入数据 (Write):** 测试向底层的 `SpdyStream` 写入数据的功能。
    * **异步读写 (AsyncReadAndWrite):** 测试同时进行异步读取和写入操作，并确保回调函数被正确处理。
    * **回调中销毁适配器 (ReadCallbackDestroysAdapter, WriteCallbackDestroysAdapter):** 测试在读取或写入的回调函数中销毁 `WebSocketSpdyStreamAdapter` 对象是否会导致崩溃，以确保资源管理的安全性。
    * **连接关闭处理 (OnCloseOkShouldBeTranslatedToConnectionClose):** 测试当底层的 `SpdyStream` 以 `OK` 状态关闭时，`WebSocketSpdyStreamAdapter` 是否将其转换为 `ERR_CONNECTION_CLOSED` 错误。

* **`WebSocketQuicStreamAdapter` 的功能：**
    * **断开连接 (Disconnect):** 测试 `WebSocketQuicStreamAdapter` 的 `Disconnect` 方法。
    * **异步适配器创建 (AsyncAdapterCreation):** 测试在 QUIC 会话流数量受限的情况下，异步创建 `WebSocketQuicStreamAdapter` 的行为，以及在会话允许创建更多流后，创建是否能够成功。
    * **发送请求头后断开连接 (SendRequestHeadersThenDisconnect):** 测试发送请求头之后立即断开连接的情况。
    * **接收到头信息后断开连接 (OnHeadersReceivedThenDisconnect):** 测试在接收到服务器的头信息之后断开连接的情况。
    * **读取数据 (Read):** 测试从底层的 QUIC 流读取数据的功能，包括读取不同大小的数据块。
    * **读取到小缓冲区 (ReadIntoSmallBuffer):** 测试当读取的数据量大于提供的缓冲区大小时的行为。

**与 JavaScript 的关系举例说明：**

虽然这段 C++ 代码本身不包含 JavaScript，但它所测试的 `WebSocketSpdyStreamAdapter` 和 `WebSocketQuicStreamAdapter` 是 Chromium 中处理 WebSocket 连接的关键组件。当 JavaScript 代码在浏览器中创建一个 WebSocket 连接时 (例如使用 `new WebSocket('ws://example.com')`)，Chromium 的网络栈最终会使用这些适配器来与服务器进行通信。

**举例：**

1. **JavaScript 发送数据:**  当 JavaScript 使用 `websocket.send('hello')` 发送数据时，这些数据会通过 `WebSocketSpdyStreamAdapter::Write` 或 `WebSocketQuicStreamAdapter::Write` 被写入到底层的网络连接中。
2. **JavaScript 接收数据:** 当服务器向客户端发送数据时，数据会通过底层的网络连接被接收，并通过 `WebSocketSpdyStreamAdapter::Read` 或 `WebSocketQuicStreamAdapter::Read` 读取到缓冲区，最终传递给 JavaScript 的 `websocket.onmessage` 事件处理函数。
3. **JavaScript 关闭连接:** 当 JavaScript 使用 `websocket.close()` 关闭连接时，可能会触发 `WebSocketSpdyStreamAdapter::Disconnect` 或 `WebSocketQuicStreamAdapter::Disconnect` 来关闭底层的网络连接。

**逻辑推理 (假设输入与输出):**

**`WebSocketSpdyStreamAdapterTest.Read` 测试用例：**

* **假设输入:**
    * 底层 `SpdyStream` 接收到包含 "foo" 和 "bar" 两部分数据的 SPDY DATA 帧。
    * `WebSocketSpdyStreamAdapter` 初始化完成。
    * 先调用一次 `Read`，请求读取 1024 字节的数据。
    * 随后底层 `SpdyStream` 接收到一个 RST_STREAM 帧，表示流被关闭。
    * 再次调用 `Read`。
* **预期输出:**
    * 第一次 `Read` 调用返回 3，读取到 "foo"。
    * 第二次 `Read` 调用返回 3，读取到 "bar"（因为数据已经被缓冲）。

**`WebSocketQuicStreamAdapterTest.Read` 测试用例：**

* **假设输入:**
    * 底层 QUIC 连接接收到包含 "foo" 和 "hogehoge" 两部分数据的 QUIC 数据包。
    * `WebSocketQuicStreamAdapter` 初始化完成。
    * 先调用一次 `Read`，请求读取 1024 字节的数据。
* **预期输出:**
    * 第一次 `Read` 调用返回 `ERR_IO_PENDING`，表示操作正在进行中。
    * 当底层数据到达后，`Read` 操作完成，返回 3，读取到 "foo"。
    * 再次调用 `Read`，返回 8，读取到 "hogehoge"。

**用户或编程常见的使用错误举例说明：**

* **在回调函数中错误地销毁适配器:**  程序员可能会在 `Read` 或 `Write` 的回调函数中直接删除 `WebSocketSpdyStreamAdapter` 或 `WebSocketQuicStreamAdapter` 对象，而没有考虑到其他异步操作可能仍在进行中，这可能导致 use-after-free 的错误。这些测试用例 (`ReadCallbackDestroysAdapter`, `WriteCallbackDestroysAdapter`) 就是为了验证这种情况下的安全性。

* **没有正确处理连接关闭:** 用户或者程序可能没有正确监听 WebSocket 的关闭事件，或者没有处理 `ERR_CONNECTION_CLOSED` 错误，导致程序在连接意外关闭时出现异常。 `WebSocketSpdyStreamAdapterTest.OnCloseOkShouldBeTranslatedToConnectionClose` 测试了当底层连接正常关闭时，上层是否能正确收到关闭通知。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器中打开一个网页，该网页包含使用 WebSocket 的 JavaScript 代码。**
2. **JavaScript 代码执行 `new WebSocket('ws://example.com')`，尝试建立 WebSocket 连接。**
3. **Chromium 浏览器解析 URL，确定需要建立网络连接。**
4. **如果使用 SPDY/HTTP/2 协议:**
    * Chromium 网络栈会查找或建立到服务器的 SPDY 会话 (`SpdySession`)。
    * 创建一个新的 SPDY 流 (`SpdyStream`) 用于 WebSocket 连接。
    * 创建一个 `WebSocketSpdyStreamAdapter` 对象，将 `SpdyStream` 封装起来，提供 WebSocket 的读写接口。
    * 这部分测试代码模拟了 `WebSocketSpdyStreamAdapter` 在此过程中的行为，例如发送请求头、接收响应头、读写数据以及处理连接关闭。
5. **如果使用 QUIC 协议:**
    * Chromium 网络栈会查找或建立到服务器的 QUIC 会话 (`QuicChromiumClientSession`)。
    * 创建一个新的 QUIC 流 (`QuicChromiumClientStream`) 用于 WebSocket 连接。
    * 创建一个 `WebSocketQuicStreamAdapter` 对象，将 QUIC 流封装起来。
    * 这部分测试代码模拟了 `WebSocketQuicStreamAdapter` 在此过程中的行为，包括异步创建适配器、发送请求头、接收响应头、读写数据以及断开连接。
6. **当 JavaScript 调用 `websocket.send()` 或接收到消息时，会触发 `WebSocketSpdyStreamAdapter` 或 `WebSocketQuicStreamAdapter` 的相应读写方法。**
7. **当 JavaScript 调用 `websocket.close()` 或连接意外关闭时，会触发 `WebSocketSpdyStreamAdapter` 或 `WebSocketQuicStreamAdapter` 的断开连接方法。**

作为调试线索，当开发者在 Chromium 中调试 WebSocket 相关问题时，可以查看 `WebSocketSpdyStreamAdapter` 和 `WebSocketQuicStreamAdapter` 的代码，了解数据是如何在网络层传输和处理的。这些测试用例提供了各种场景的示例，可以帮助理解代码的预期行为和潜在问题。

Prompt: 
```
这是目录为net/websockets/websocket_basic_stream_adapters_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
stream = CreateSpdyStream(session);
  WebSocketSpdyStreamAdapter adapter(stream, &mock_delegate_,
                                     NetLogWithSource());
  EXPECT_TRUE(adapter.is_initialized());

  int rv = stream->SendRequestHeaders(RequestHeaders(), MORE_DATA_TO_SEND);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Buffer larger than each MockRead.
  constexpr int kReadBufSize = 1024;
  auto read_buf = base::MakeRefCounted<IOBufferWithSize>(kReadBufSize);
  TestCompletionCallback callback;
  rv = adapter.Read(read_buf.get(), kReadBufSize, callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  ASSERT_EQ(3, rv);
  EXPECT_EQ("foo", std::string_view(read_buf->data(), rv));

  // Read RST_STREAM to destroy the stream.
  // This calls SpdySession::Delegate::OnClose().
  EXPECT_TRUE(session);
  EXPECT_TRUE(stream);
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session);
  EXPECT_FALSE(stream);

  // Read remaining buffered data.  This will PostTask CallDelegateOnClose().
  rv = adapter.Read(read_buf.get(), kReadBufSize, CompletionOnceCallback());
  ASSERT_EQ(3, rv);
  EXPECT_EQ("bar", std::string_view(read_buf->data(), rv));

  adapter.DetachDelegate();

  // Run CallDelegateOnClose(), which should not crash
  // even if |delegate_| is null.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(WebSocketSpdyStreamAdapterTest, Write) {
  spdy::SpdySerializedFrame response_headers(
      spdy_util_.ConstructSpdyResponseHeaders(1, ResponseHeaders(), false));
  MockRead reads[] = {CreateMockRead(response_headers, 1),
                      MockRead(ASYNC, 0, 3)};
  spdy::SpdySerializedFrame request_headers(spdy_util_.ConstructSpdyHeaders(
      1, RequestHeaders(), DEFAULT_PRIORITY, false));
  spdy::SpdySerializedFrame data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "foo", false));
  MockWrite writes[] = {CreateMockWrite(request_headers, 0),
                        CreateMockWrite(data_frame, 2)};
  SequencedSocketData data(reads, writes);
  AddSocketData(&data);
  AddSSLSocketData();

  base::WeakPtr<SpdySession> session = CreateSpdySession();
  base::WeakPtr<SpdyStream> stream = CreateSpdyStream(session);
  WebSocketSpdyStreamAdapter adapter(stream, nullptr, NetLogWithSource());
  EXPECT_TRUE(adapter.is_initialized());

  int rv = stream->SendRequestHeaders(RequestHeaders(), MORE_DATA_TO_SEND);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  base::RunLoop().RunUntilIdle();

  auto write_buf = base::MakeRefCounted<StringIOBuffer>("foo");
  TestCompletionCallback callback;
  rv = adapter.Write(write_buf.get(), write_buf->size(), callback.callback(),
                     TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  ASSERT_EQ(3, rv);

  // Read EOF.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

// Test that if both Read() and Write() returns asynchronously,
// the two callbacks are handled correctly.
TEST_F(WebSocketSpdyStreamAdapterTest, AsyncReadAndWrite) {
  spdy::SpdySerializedFrame response_headers(
      spdy_util_.ConstructSpdyResponseHeaders(1, ResponseHeaders(), false));
  spdy::SpdySerializedFrame read_data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "foobar", true));
  MockRead reads[] = {CreateMockRead(response_headers, 1),
                      CreateMockRead(read_data_frame, 3),
                      MockRead(ASYNC, 0, 4)};
  spdy::SpdySerializedFrame request_headers(spdy_util_.ConstructSpdyHeaders(
      1, RequestHeaders(), DEFAULT_PRIORITY, false));
  spdy::SpdySerializedFrame write_data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "baz", false));
  MockWrite writes[] = {CreateMockWrite(request_headers, 0),
                        CreateMockWrite(write_data_frame, 2)};
  SequencedSocketData data(reads, writes);
  AddSocketData(&data);
  AddSSLSocketData();

  base::WeakPtr<SpdySession> session = CreateSpdySession();
  base::WeakPtr<SpdyStream> stream = CreateSpdyStream(session);
  WebSocketSpdyStreamAdapter adapter(stream, nullptr, NetLogWithSource());
  EXPECT_TRUE(adapter.is_initialized());

  int rv = stream->SendRequestHeaders(RequestHeaders(), MORE_DATA_TO_SEND);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  base::RunLoop().RunUntilIdle();

  constexpr int kReadBufSize = 1024;
  auto read_buf = base::MakeRefCounted<IOBufferWithSize>(kReadBufSize);
  TestCompletionCallback read_callback;
  rv = adapter.Read(read_buf.get(), kReadBufSize, read_callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  auto write_buf = base::MakeRefCounted<StringIOBuffer>("baz");
  TestCompletionCallback write_callback;
  rv = adapter.Write(write_buf.get(), write_buf->size(),
                     write_callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = read_callback.WaitForResult();
  ASSERT_EQ(6, rv);
  EXPECT_EQ("foobar", std::string_view(read_buf->data(), rv));

  rv = write_callback.WaitForResult();
  ASSERT_EQ(3, rv);

  // Read EOF.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

// A helper class that will delete |adapter| when the callback is invoked.
class KillerCallback : public TestCompletionCallbackBase {
 public:
  explicit KillerCallback(std::unique_ptr<WebSocketSpdyStreamAdapter> adapter)
      : adapter_(std::move(adapter)) {}

  ~KillerCallback() override = default;

  CompletionOnceCallback callback() {
    return base::BindOnce(&KillerCallback::OnComplete, base::Unretained(this));
  }

 private:
  void OnComplete(int result) {
    adapter_.reset();
    SetResult(result);
  }

  std::unique_ptr<WebSocketSpdyStreamAdapter> adapter_;
};

TEST_F(WebSocketSpdyStreamAdapterTest, ReadCallbackDestroysAdapter) {
  spdy::SpdySerializedFrame response_headers(
      spdy_util_.ConstructSpdyResponseHeaders(1, ResponseHeaders(), false));
  MockRead reads[] = {CreateMockRead(response_headers, 1),
                      MockRead(ASYNC, ERR_IO_PENDING, 2),
                      MockRead(ASYNC, 0, 3)};
  spdy::SpdySerializedFrame request_headers(spdy_util_.ConstructSpdyHeaders(
      1, RequestHeaders(), DEFAULT_PRIORITY, false));
  MockWrite writes[] = {CreateMockWrite(request_headers, 0)};
  SequencedSocketData data(reads, writes);
  AddSocketData(&data);
  AddSSLSocketData();

  EXPECT_CALL(mock_delegate_, OnHeadersSent());
  EXPECT_CALL(mock_delegate_, OnHeadersReceived(_));

  base::WeakPtr<SpdySession> session = CreateSpdySession();
  base::WeakPtr<SpdyStream> stream = CreateSpdyStream(session);
  auto adapter = std::make_unique<WebSocketSpdyStreamAdapter>(
      stream, &mock_delegate_, NetLogWithSource());
  EXPECT_TRUE(adapter->is_initialized());

  int rv = stream->SendRequestHeaders(RequestHeaders(), MORE_DATA_TO_SEND);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Send headers.
  base::RunLoop().RunUntilIdle();

  WebSocketSpdyStreamAdapter* adapter_raw = adapter.get();
  KillerCallback callback(std::move(adapter));

  constexpr int kReadBufSize = 1024;
  auto read_buf = base::MakeRefCounted<IOBufferWithSize>(kReadBufSize);
  rv = adapter_raw->Read(read_buf.get(), kReadBufSize, callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Read EOF while read is pending.  WebSocketSpdyStreamAdapter::OnClose()
  // should not crash if read callback destroys |adapter|.
  data.Resume();
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_CLOSED));

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session);
  EXPECT_FALSE(stream);

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(WebSocketSpdyStreamAdapterTest, WriteCallbackDestroysAdapter) {
  spdy::SpdySerializedFrame response_headers(
      spdy_util_.ConstructSpdyResponseHeaders(1, ResponseHeaders(), false));
  MockRead reads[] = {CreateMockRead(response_headers, 1),
                      MockRead(ASYNC, ERR_IO_PENDING, 2),
                      MockRead(ASYNC, 0, 3)};
  spdy::SpdySerializedFrame request_headers(spdy_util_.ConstructSpdyHeaders(
      1, RequestHeaders(), DEFAULT_PRIORITY, false));
  MockWrite writes[] = {CreateMockWrite(request_headers, 0)};
  SequencedSocketData data(reads, writes);
  AddSocketData(&data);
  AddSSLSocketData();

  EXPECT_CALL(mock_delegate_, OnHeadersSent());
  EXPECT_CALL(mock_delegate_, OnHeadersReceived(_));

  base::WeakPtr<SpdySession> session = CreateSpdySession();
  base::WeakPtr<SpdyStream> stream = CreateSpdyStream(session);
  auto adapter = std::make_unique<WebSocketSpdyStreamAdapter>(
      stream, &mock_delegate_, NetLogWithSource());
  EXPECT_TRUE(adapter->is_initialized());

  int rv = stream->SendRequestHeaders(RequestHeaders(), MORE_DATA_TO_SEND);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Send headers.
  base::RunLoop().RunUntilIdle();

  WebSocketSpdyStreamAdapter* adapter_raw = adapter.get();
  KillerCallback callback(std::move(adapter));

  auto write_buf = base::MakeRefCounted<StringIOBuffer>("foo");
  rv = adapter_raw->Write(write_buf.get(), write_buf->size(),
                          callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Read EOF while write is pending.  WebSocketSpdyStreamAdapter::OnClose()
  // should not crash if write callback destroys |adapter|.
  data.Resume();
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_CLOSED));

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session);
  EXPECT_FALSE(stream);

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(WebSocketSpdyStreamAdapterTest,
       OnCloseOkShouldBeTranslatedToConnectionClose) {
  spdy::SpdySerializedFrame response_headers(
      spdy_util_.ConstructSpdyResponseHeaders(1, ResponseHeaders(), false));
  spdy::SpdySerializedFrame close(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_NO_ERROR));
  MockRead reads[] = {CreateMockRead(response_headers, 1),
                      CreateMockRead(close, 2), MockRead(ASYNC, 0, 3)};
  spdy::SpdySerializedFrame request_headers(spdy_util_.ConstructSpdyHeaders(
      1, RequestHeaders(), DEFAULT_PRIORITY, false));
  MockWrite writes[] = {CreateMockWrite(request_headers, 0)};
  SequencedSocketData data(reads, writes);
  AddSocketData(&data);
  AddSSLSocketData();

  EXPECT_CALL(mock_delegate_, OnHeadersSent());
  EXPECT_CALL(mock_delegate_, OnHeadersReceived(_));

  // Must create buffer before `adapter`, since `adapter` doesn't hold onto a
  // reference to it.
  constexpr int kReadBufSize = 1024;
  auto read_buf = base::MakeRefCounted<IOBufferWithSize>(kReadBufSize);

  base::WeakPtr<SpdySession> session = CreateSpdySession();
  base::WeakPtr<SpdyStream> stream = CreateSpdyStream(session);
  WebSocketSpdyStreamAdapter adapter(stream, &mock_delegate_,
                                     NetLogWithSource());
  EXPECT_TRUE(adapter.is_initialized());

  EXPECT_CALL(mock_delegate_, OnClose(ERR_CONNECTION_CLOSED));

  int rv = stream->SendRequestHeaders(RequestHeaders(), MORE_DATA_TO_SEND);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  TestCompletionCallback callback;
  rv = adapter.Read(read_buf.get(), kReadBufSize, callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  ASSERT_EQ(ERR_CONNECTION_CLOSED, rv);
}

class MockQuicDelegate : public WebSocketQuicStreamAdapter::Delegate {
 public:
  ~MockQuicDelegate() override = default;
  MOCK_METHOD(void, OnHeadersSent, (), (override));
  MOCK_METHOD(void,
              OnHeadersReceived,
              (const quiche::HttpHeaderBlock&),
              (override));
  MOCK_METHOD(void, OnClose, (int), (override));
};

class WebSocketQuicStreamAdapterTest
    : public TestWithTaskEnvironment,
      public ::testing::WithParamInterface<quic::ParsedQuicVersion> {
 protected:
  static quiche::HttpHeaderBlock RequestHeaders() {
    return WebSocketHttp2Request("/", "www.example.org:443",
                                 "http://www.example.org", {});
  }
  WebSocketQuicStreamAdapterTest()
      : version_(GetParam()),
        mock_quic_data_(version_),
        client_data_stream_id1_(quic::QuicUtils::GetFirstBidirectionalStreamId(
            version_.transport_version,
            quic::Perspective::IS_CLIENT)),
        crypto_config_(
            quic::test::crypto_test_utils::ProofVerifierForTesting()),
        connection_id_(quic::test::TestConnectionId(2)),
        client_maker_(version_,
                      connection_id_,
                      &clock_,
                      "mail.example.org",
                      quic::Perspective::IS_CLIENT),
        server_maker_(version_,
                      connection_id_,
                      &clock_,
                      "mail.example.org",
                      quic::Perspective::IS_SERVER),
        peer_addr_(IPAddress(192, 0, 2, 23), 443),
        destination_endpoint_(url::kHttpsScheme, "mail.example.org", 80) {}

  ~WebSocketQuicStreamAdapterTest() override = default;

  void SetUp() override {
    FLAGS_quic_enable_http3_grease_randomness = false;
    clock_.AdvanceTime(quic::QuicTime::Delta::FromMilliseconds(20));
    quic::QuicEnableVersion(version_);
  }

  void TearDown() override {
    EXPECT_TRUE(mock_quic_data_.AllReadDataConsumed());
    EXPECT_TRUE(mock_quic_data_.AllWriteDataConsumed());
  }

  net::QuicChromiumClientSession::Handle* GetQuicSessionHandle() {
    return session_handle_.get();
  }

  // Helper functions for constructing packets sent by the client

  std::unique_ptr<quic::QuicReceivedPacket> ConstructSettingsPacket(
      uint64_t packet_number) {
    return client_maker_.MakeInitialSettingsPacket(packet_number);
  }

  std::unique_ptr<quic::QuicReceivedPacket> ConstructServerDataPacket(
      uint64_t packet_number,
      std::string_view data) {
    quiche::QuicheBuffer buffer = quic::HttpEncoder::SerializeDataFrameHeader(
        data.size(), quiche::SimpleBufferAllocator::Get());
    return server_maker_.Packet(packet_number)
        .AddStreamFrame(
            client_data_stream_id1_, /*fin=*/false,
            base::StrCat(
                {std::string_view(buffer.data(), buffer.size()), data}))
        .Build();
  }

  std::unique_ptr<quic::QuicReceivedPacket> ConstructRstPacket(
      uint64_t packet_number,
      quic::QuicRstStreamErrorCode error_code) {
    return client_maker_.Packet(packet_number)
        .AddStopSendingFrame(client_data_stream_id1_, error_code)
        .AddRstStreamFrame(client_data_stream_id1_, error_code)
        .Build();
  }

  std::unique_ptr<quic::QuicEncryptedPacket> ConstructClientAckPacket(
      uint64_t packet_number,
      uint64_t largest_received,
      uint64_t smallest_received) {
    return client_maker_.Packet(packet_number)
        .AddAckFrame(1, largest_received, smallest_received)
        .Build();
  }

  std::unique_ptr<quic::QuicReceivedPacket> ConstructAckAndRstPacket(
      uint64_t packet_number,
      quic::QuicRstStreamErrorCode error_code,
      uint64_t largest_received,
      uint64_t smallest_received) {
    return client_maker_.Packet(packet_number)
        .AddAckFrame(/*first_received=*/1, largest_received, smallest_received)
        .AddStopSendingFrame(client_data_stream_id1_, error_code)
        .AddRstStreamFrame(client_data_stream_id1_, error_code)
        .Build();
  }

  void Initialize() {
    auto socket = std::make_unique<MockUDPClientSocket>(
        mock_quic_data_.InitializeAndGetSequencedSocketData(), NetLog::Get());
    socket->Connect(peer_addr_);

    runner_ = base::MakeRefCounted<TestTaskRunner>(&clock_);
    helper_ = std::make_unique<QuicChromiumConnectionHelper>(
        &clock_, &random_generator_);
    alarm_factory_ =
        std::make_unique<QuicChromiumAlarmFactory>(runner_.get(), &clock_);
    // Ownership of 'writer' is passed to 'QuicConnection'.
    QuicChromiumPacketWriter* writer = new QuicChromiumPacketWriter(
        socket.get(), base::SingleThreadTaskRunner::GetCurrentDefault().get());
    quic::QuicConnection* connection = new quic::QuicConnection(
        connection_id_, quic::QuicSocketAddress(),
        net::ToQuicSocketAddress(peer_addr_), helper_.get(),
        alarm_factory_.get(), writer, true /* owns_writer */,
        quic::Perspective::IS_CLIENT, quic::test::SupportedVersions(version_),
        connection_id_generator_);
    connection->set_visitor(&visitor_);

    // Load a certificate that is valid for *.example.org
    scoped_refptr<X509Certificate> test_cert(
        ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
    EXPECT_TRUE(test_cert.get());

    verify_details_.cert_verify_result.verified_cert = test_cert;
    verify_details_.cert_verify_result.is_issued_by_known_root = true;
    crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details_);

    base::TimeTicks dns_end = base::TimeTicks::Now();
    base::TimeTicks dns_start = dns_end - base::Milliseconds(1);

    session_ = std::make_unique<QuicChromiumClientSession>(
        connection, std::move(socket),
        /*stream_factory=*/nullptr, &crypto_client_stream_factory_, &clock_,
        &transport_security_state_, &ssl_config_service_,
        /*server_info=*/nullptr,
        QuicSessionAliasKey(
            url::SchemeHostPort(),
            QuicSessionKey("mail.example.org", 80, PRIVACY_MODE_DISABLED,
                           ProxyChain::Direct(), SessionUsage::kDestination,
                           SocketTag(), NetworkAnonymizationKey(),
                           SecureDnsPolicy::kAllow,
                           /*require_dns_https_alpn=*/false)),
        /*require_confirmation=*/false,
        /*migrate_session_early_v2=*/false,
        /*migrate_session_on_network_change_v2=*/false,
        /*default_network=*/handles::kInvalidNetworkHandle,
        quic::QuicTime::Delta::FromMilliseconds(
            kDefaultRetransmittableOnWireTimeout.InMilliseconds()),
        /*migrate_idle_session=*/true, /*allow_port_migration=*/false,
        kDefaultIdleSessionMigrationPeriod, /*multi_port_probing_interval=*/0,
        kMaxTimeOnNonDefaultNetwork,
        kMaxMigrationsToNonDefaultNetworkOnWriteError,
        kMaxMigrationsToNonDefaultNetworkOnPathDegrading,
        kQuicYieldAfterPacketsRead,
        quic::QuicTime::Delta::FromMilliseconds(
            kQuicYieldAfterDurationMilliseconds),
        /*cert_verify_flags=*/0, quic::test::DefaultQuicConfig(),
        std::make_unique<TestQuicCryptoClientConfigHandle>(&crypto_config_),
        "CONNECTION_UNKNOWN", dns_start, dns_end,
        base::DefaultTickClock::GetInstance(),
        base::SingleThreadTaskRunner::GetCurrentDefault().get(),
        /*socket_performance_watcher=*/nullptr, ConnectionEndpointMetadata(),
        /*report_ecn=*/true, /*enable_origin_frame=*/true,
        /*allow_server_preferred_address=*/true,
        MultiplexedSessionCreationInitiator::kUnknown,
        NetLogWithSource::Make(NetLogSourceType::NONE));

    session_->Initialize();

    // Blackhole QPACK decoder stream instead of constructing mock writes.
    session_->qpack_decoder()->set_qpack_stream_sender_delegate(
        &noop_qpack_stream_sender_delegate_);
    TestCompletionCallback callback;
    EXPECT_THAT(session_->CryptoConnect(callback.callback()), IsOk());
    EXPECT_TRUE(session_->OneRttKeysAvailable());
    session_handle_ = session_->CreateHandle(
        url::SchemeHostPort(url::kHttpsScheme, "mail.example.org", 80));
  }

  const quic::ParsedQuicVersion version_;
  MockQuicData mock_quic_data_;
  StrictMock<MockQuicDelegate> mock_delegate_;
  const quic::QuicStreamId client_data_stream_id1_;

 private:
  quic::QuicCryptoClientConfig crypto_config_;
  const quic::QuicConnectionId connection_id_;

 protected:
  QuicTestPacketMaker client_maker_;
  QuicTestPacketMaker server_maker_;
  std::unique_ptr<QuicChromiumClientSession> session_;

 private:
  quic::MockClock clock_;
  std::unique_ptr<QuicChromiumClientSession::Handle> session_handle_;
  scoped_refptr<TestTaskRunner> runner_;
  ProofVerifyDetailsChromium verify_details_;
  MockCryptoClientStreamFactory crypto_client_stream_factory_;
  SSLConfigServiceDefaults ssl_config_service_;
  quic::test::MockConnectionIdGenerator connection_id_generator_;
  std::unique_ptr<QuicChromiumConnectionHelper> helper_;
  std::unique_ptr<QuicChromiumAlarmFactory> alarm_factory_;
  testing::StrictMock<quic::test::MockQuicConnectionVisitor> visitor_;
  TransportSecurityState transport_security_state_;
  IPAddress ip_;
  IPEndPoint peer_addr_;
  quic::test::MockRandom random_generator_{0};
  url::SchemeHostPort destination_endpoint_;
  quic::test::NoopQpackStreamSenderDelegate noop_qpack_stream_sender_delegate_;
};

// Like net::TestCompletionCallback, but for a callback that takes an unbound
// parameter of type WebSocketQuicStreamAdapter.
struct WebSocketQuicStreamAdapterIsPendingHelper {
  bool operator()(
      const std::unique_ptr<WebSocketQuicStreamAdapter>& adapter) const {
    return !adapter;
  }
};

using TestWebSocketQuicStreamAdapterCompletionCallbackBase =
    net::internal::TestCompletionCallbackTemplate<
        std::unique_ptr<WebSocketQuicStreamAdapter>,
        WebSocketQuicStreamAdapterIsPendingHelper>;

class TestWebSocketQuicStreamAdapterCompletionCallback
    : public TestWebSocketQuicStreamAdapterCompletionCallbackBase {
 public:
  base::OnceCallback<void(std::unique_ptr<WebSocketQuicStreamAdapter>)>
  callback();
};

base::OnceCallback<void(std::unique_ptr<WebSocketQuicStreamAdapter>)>
TestWebSocketQuicStreamAdapterCompletionCallback::callback() {
  return base::BindOnce(
      &TestWebSocketQuicStreamAdapterCompletionCallback::SetResult,
      base::Unretained(this));
}

INSTANTIATE_TEST_SUITE_P(QuicVersion,
                         WebSocketQuicStreamAdapterTest,
                         ::testing::ValuesIn(AllSupportedQuicVersions()),
                         ::testing::PrintToStringParamName());

TEST_P(WebSocketQuicStreamAdapterTest, Disconnect) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));

  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      ConstructRstPacket(packet_number++, quic::QUIC_STREAM_CANCELLED));

  Initialize();

  net::QuicChromiumClientSession::Handle* session_handle =
      GetQuicSessionHandle();
  ASSERT_TRUE(session_handle);

  TestWebSocketQuicStreamAdapterCompletionCallback callback;
  std::unique_ptr<WebSocketQuicStreamAdapter> adapter =
      session_handle->CreateWebSocketQuicStreamAdapter(
          &mock_delegate_, callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS);
  ASSERT_TRUE(adapter);
  EXPECT_TRUE(adapter->is_initialized());
  adapter->Disconnect();
  // TODO(momoka): Add tests to test both destruction orders.
}

TEST_P(WebSocketQuicStreamAdapterTest, AsyncAdapterCreation) {
  constexpr size_t kMaxOpenStreams = 50;

  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));

  mock_quic_data_.AddWrite(
      SYNCHRONOUS, client_maker_.Packet(packet_number++)
                       .AddStreamsBlockedFrame(/*control_frame_id=*/1,
                                               /*stream_count=*/kMaxOpenStreams,
                                               /* unidirectional = */ false)
                       .Build());

  mock_quic_data_.AddRead(
      ASYNC, server_maker_.Packet(1)
                 .AddMaxStreamsFrame(/*control_frame_id=*/1,
                                     /*stream_count=*/kMaxOpenStreams + 2,
                                     /* unidirectional = */ false)
                 .Build());

  mock_quic_data_.AddRead(ASYNC, ERR_IO_PENDING);
  mock_quic_data_.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  Initialize();

  std::vector<QuicChromiumClientStream*> streams;

  for (size_t i = 0; i < kMaxOpenStreams; i++) {
    QuicChromiumClientStream* stream =
        QuicChromiumClientSessionPeer::CreateOutgoingStream(session_.get());
    ASSERT_TRUE(stream);
    streams.push_back(stream);
    EXPECT_EQ(i + 1, session_->GetNumActiveStreams());
  }

  net::QuicChromiumClientSession::Handle* session_handle =
      GetQuicSessionHandle();
  ASSERT_TRUE(session_handle);

  // Creating an adapter should fail because of the stream limit.
  TestWebSocketQuicStreamAdapterCompletionCallback callback;
  std::unique_ptr<WebSocketQuicStreamAdapter> adapter =
      session_handle->CreateWebSocketQuicStreamAdapter(
          &mock_delegate_, callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS);
  ASSERT_EQ(adapter, nullptr);
  EXPECT_FALSE(callback.have_result());
  EXPECT_EQ(kMaxOpenStreams, session_->GetNumActiveStreams());

  // Read MAX_STREAMS frame that makes it possible to open WebSocket stream.
  session_->StartReading();
  callback.WaitForResult();
  EXPECT_EQ(kMaxOpenStreams + 1, session_->GetNumActiveStreams());

  // Close connection.
  mock_quic_data_.Resume();
  base::RunLoop().RunUntilIdle();
}

TEST_P(WebSocketQuicStreamAdapterTest, SendRequestHeadersThenDisconnect) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  SpdyTestUtil spdy_util;
  quiche::HttpHeaderBlock request_header_block = WebSocketHttp2Request(
      "/", "www.example.org:443", "http://www.example.org", {});
  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      client_maker_.MakeRequestHeadersPacket(
          packet_number++, client_data_stream_id1_,
          /*fin=*/false, ConvertRequestPriorityToQuicPriority(LOWEST),
          std::move(request_header_block), nullptr));

  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      ConstructRstPacket(packet_number++, quic::QUIC_STREAM_CANCELLED));

  Initialize();

  net::QuicChromiumClientSession::Handle* session_handle =
      GetQuicSessionHandle();
  ASSERT_TRUE(session_handle);
  TestWebSocketQuicStreamAdapterCompletionCallback callback;
  std::unique_ptr<WebSocketQuicStreamAdapter> adapter =
      session_handle->CreateWebSocketQuicStreamAdapter(
          &mock_delegate_, callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS);
  ASSERT_TRUE(adapter);
  EXPECT_TRUE(adapter->is_initialized());

  adapter->WriteHeaders(RequestHeaders(), false);

  adapter->Disconnect();
}

TEST_P(WebSocketQuicStreamAdapterTest, OnHeadersReceivedThenDisconnect) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));

  SpdyTestUtil spdy_util;
  quiche::HttpHeaderBlock request_header_block = WebSocketHttp2Request(
      "/", "www.example.org:443", "http://www.example.org", {});
  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      client_maker_.MakeRequestHeadersPacket(
          packet_number++, client_data_stream_id1_,
          /*fin=*/false, ConvertRequestPriorityToQuicPriority(LOWEST),
          std::move(request_header_block), nullptr));

  quiche::HttpHeaderBlock response_header_block = WebSocketHttp2Response({});
  mock_quic_data_.AddRead(
      ASYNC, server_maker_.MakeResponseHeadersPacket(
                 /*packet_number=*/1, client_data_stream_id1_, /*fin=*/false,
                 std::move(response_header_block),
                 /*spdy_headers_frame_length=*/nullptr));
  mock_quic_data_.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(packet_number++,
                                            quic::QUIC_STREAM_CANCELLED, 1, 0));
  base::RunLoop run_loop;
  auto quit_closure = run_loop.QuitClosure();
  EXPECT_CALL(mock_delegate_, OnHeadersReceived(_)).WillOnce(Invoke([&]() {
    std::move(quit_closure).Run();
  }));

  Initialize();

  net::QuicChromiumClientSession::Handle* session_handle =
      GetQuicSessionHandle();
  ASSERT_TRUE(session_handle);

  TestWebSocketQuicStreamAdapterCompletionCallback callback;
  std::unique_ptr<WebSocketQuicStreamAdapter> adapter =
      session_handle->CreateWebSocketQuicStreamAdapter(
          &mock_delegate_, callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS);
  ASSERT_TRUE(adapter);
  EXPECT_TRUE(adapter->is_initialized());

  adapter->WriteHeaders(RequestHeaders(), false);

  session_->StartReading();
  run_loop.Run();

  adapter->Disconnect();
}

TEST_P(WebSocketQuicStreamAdapterTest, Read) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));

  SpdyTestUtil spdy_util;
  quiche::HttpHeaderBlock request_header_block = WebSocketHttp2Request(
      "/", "www.example.org:443", "http://www.example.org", {});
  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      client_maker_.MakeRequestHeadersPacket(
          packet_number++, client_data_stream_id1_,
          /*fin=*/false, ConvertRequestPriorityToQuicPriority(LOWEST),
          std::move(request_header_block), nullptr));

  quiche::HttpHeaderBlock response_header_block = WebSocketHttp2Response({});
  mock_quic_data_.AddRead(
      ASYNC, server_maker_.MakeResponseHeadersPacket(
                 /*packet_number=*/1, client_data_stream_id1_, /*fin=*/false,
                 std::move(response_header_block),
                 /*spdy_headers_frame_length=*/nullptr));
  mock_quic_data_.AddRead(ASYNC, ERR_IO_PENDING);

  mock_quic_data_.AddRead(ASYNC, ConstructServerDataPacket(2, "foo"));
  mock_quic_data_.AddRead(SYNCHRONOUS,
                          ConstructServerDataPacket(3, "hogehoge"));
  mock_quic_data_.AddRead(SYNCHRONOUS, ERR_IO_PENDING);

  mock_quic_data_.AddWrite(ASYNC,
                           ConstructClientAckPacket(packet_number++, 2, 0));
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(packet_number++,
                                            quic::QUIC_STREAM_CANCELLED, 3, 0));

  base::RunLoop run_loop;
  EXPECT_CALL(mock_delegate_, OnHeadersReceived(_)).WillOnce(Invoke([&]() {
    run_loop.Quit();
  }));

  Initialize();

  net::QuicChromiumClientSession::Handle* session_handle =
      GetQuicSessionHandle();
  ASSERT_TRUE(session_handle);

  TestWebSocketQuicStreamAdapterCompletionCallback callback;
  std::unique_ptr<WebSocketQuicStreamAdapter> adapter =
      session_handle->CreateWebSocketQuicStreamAdapter(
          &mock_delegate_, callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS);
  ASSERT_TRUE(adapter);
  EXPECT_TRUE(adapter->is_initialized());

  adapter->WriteHeaders(RequestHeaders(), false);

  session_->StartReading();
  run_loop.Run();

  // Buffer larger than each MockRead.
  constexpr int kReadBufSize = 1024;
  auto read_buf = base::MakeRefCounted<IOBufferWithSize>(kReadBufSize);
  TestCompletionCallback read_callback;

  int rv =
      adapter->Read(read_buf.get(), kReadBufSize, read_callback.callback());

  ASSERT_EQ(ERR_IO_PENDING, rv);

  mock_quic_data_.Resume();
  base::RunLoop().RunUntilIdle();

  rv = read_callback.WaitForResult();
  ASSERT_EQ(3, rv);
  EXPECT_EQ("foo", std::string_view(read_buf->data(), rv));

  rv = adapter->Read(read_buf.get(), kReadBufSize, CompletionOnceCallback());
  ASSERT_EQ(8, rv);
  EXPECT_EQ("hogehoge", std::string_view(read_buf->data(), rv));

  adapter->Disconnect();

  EXPECT_TRUE(mock_quic_data_.AllReadDataConsumed());
  EXPECT_TRUE(mock_quic_data_.AllWriteDataConsumed());
}

TEST_P(WebSocketQuicStreamAdapterTest, ReadIntoSmallBuffer) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));

  SpdyTestUtil spdy_util;
  quiche::HttpHeaderBlock request_header_block = WebSocketHttp2Request(
      "/", "www.example.org:443", "http://www.example.org", {});
  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      client_maker_.MakeRequestHeadersPacket(
          packet_number++, client_data_stream_id1_,
          /*fin=*/false, ConvertRequestPriorityToQuicPriority(LOWEST),
          std::move(request_header_block), nullptr));

  quiche::HttpHeaderBlock response_header_block = WebSocketHttp2Response({});
  mock_quic_data_.AddRead(
      ASYNC, server_maker_.MakeResponseHeadersPacket(
                 /*packet_number=*/1, client_data_stream_id1_, /*fin=*/false,
                 std::move(response_header_block),
                 /*spdy_headers_frame_length=*/nullptr));
  mock_quic_data_.AddRead(ASYNC, ERR_IO_PENDING);
  // First read is the same size as the buffer, next is smaller, last is larger.
  mock_quic_data_.AddRead(ASYNC, ConstructServerDataPacket(2, "abc"));
  mock_quic_data_.AddRead(SYNCHRONOUS, ConstructServerDa
"""


```