Response:
The user wants a summary of the functionality of the provided C++ code snippet from `net/http/http_stream_parser_unittest.cc`. This is part 2 of a 3-part request. I need to focus on the tests defined in this specific section.

The code defines several test cases for the `HttpStreamParser` class. These tests verify various aspects of how the parser handles HTTP requests and responses, especially concerning chunked uploads, truncated headers, WebSocket handshakes, and accurate tracking of received bytes.

Here's a breakdown of the functionalities demonstrated in the code:

1. **Chunked Uploads:** Tests asynchronous and synchronous chunked uploads, including scenarios with multiple chunks and empty final chunks.
2. **Truncated Headers:** Tests how the parser handles responses with truncated headers at different points. It checks for the correct error codes (`ERR_CONNECTION_CLOSED` for HTTP and `ERR_RESPONSE_HEADERS_TRUNCATED` for HTTPS).
3. **WebSocket Handshake:** Verifies that the parser correctly handles a 101 Switching Protocols response for WebSocket handshakes, leaving the subsequent WebSocket frame data in the read buffer.
4. **HTTP/0.9 Handling:** Tests that HTTP/0.9 responses are correctly parsed on default HTTP/S ports but result in errors on non-standard ports (except for Shoutcast responses).
5. **Shoutcast Detection:** Checks that the parser correctly identifies Shoutcast responses.
6. **Informational Responses (100 Continue):** Confirms that the parser ignores informational responses and proceeds to parse the next response.
7. **Handling Null Characters in Headers:** Ensures that null characters within HTTP headers are correctly identified as errors.
8. **Accurate Received Bytes Tracking:**  Multiple tests verify that `parser.received_bytes()` correctly tracks the bytes received for the current response, excluding data from subsequent responses or extra data on the socket. This includes scenarios with single and multiple reads, asynchronous reads, and data pre-loaded into the read buffer.

Regarding the relationship with JavaScript: While this is C++ code and doesn't directly interact with JavaScript, the functionality it tests is crucial for web browsers and applications that use HTTP. JavaScript running in a browser relies on the underlying network stack (which includes components like `HttpStreamParser`) to correctly fetch resources and communicate with servers. For example, if the `HttpStreamParser` incorrectly handles chunked uploads, JavaScript code might not receive the complete data from a server.

For logic and assumptions, the tests use `MockRead` and `MockWrite` to simulate network interactions. The tests make assumptions about the expected byte sequences for different HTTP scenarios.

Examples of user/programming errors tested implicitly include:
*   Servers sending truncated headers.
*   Servers sending invalid HTTP responses (e.g., with null characters in headers).

To reach this point in debugging, a developer might be investigating issues related to:
1. Failed chunked uploads in the browser.
2. Errors when receiving responses with specific header structures.
3. Problems establishing WebSocket connections.
4. Incorrect reporting of downloaded data sizes.

The developer would likely set breakpoints within the `HttpStreamParser` code or the test framework used here to step through the execution and understand how the parser is handling different input scenarios.这是`net/http/http_stream_parser_unittest.cc` 文件的第二部分，主要包含了一系列针对 `HttpStreamParser` 类的单元测试。 这些测试旨在验证 `HttpStreamParser` 在处理各种 HTTP 请求和响应场景时的正确性。

**主要功能归纳：**

*   **测试异步分块上传 (Async Chunked Upload):**  验证 `HttpStreamParser` 在异步接收分块数据上传时的处理逻辑，包括发送请求头和多个数据块，并确保状态机不会因为写入操作的延迟而混乱。
*   **测试异步空分块上传 (Async Empty Chunked Upload):** 验证当只有一个 0 字节的 "chunk" 且在请求头发送成功后才从 `UploadStream` 接收时，`HttpStreamParser` 的处理逻辑。
*   **测试同步空分块上传 (Sync Empty Chunked Upload):** 验证当只有一个 0 字节的 "chunk" 且在请求开始前就已经添加到 `UploadStream` 时，`HttpStreamParser` 的处理逻辑。
*   **测试头部截断 (Truncated Headers):**  模拟各种头部被截断的情况，包括状态行、头部字段名、头部字段值以及最终空行被截断的情况，并验证 `HttpStreamParser` 能否正确检测并处理这些错误。针对 HTTP 和 HTTPS 协议，处理方式略有不同。
*   **测试 WebSocket 101 响应 (WebSocket101Response):** 验证 `HttpStreamParser` 能否正确解析 HTTP 101 状态码的响应（用于 WebSocket 握手），并保持后续的数据在读取缓冲区中。
*   **提供辅助类进行 GET 请求测试 (SimpleGetRunner):**  定义了一个名为 `SimpleGetRunner` 的辅助类，用于简化创建 `HttpStreamParser` 实例和执行 GET 请求的流程。
*   **测试 HTTP/0.9 端口特性 (Http09PortTests):** 验证 `HttpStreamParser` 在不同端口上处理 HTTP/0.9 响应的行为，包括标准端口和非标准端口，以及对 Shoutcast 响应的特殊处理。
*   **测试带有 Body 的 100 Continue 响应 (ContinueWithBody):**  验证 `HttpStreamParser` 是否能正确处理带有消息体的 100 Continue 响应（尽管通常 100 Continue 不应有消息体）。
*   **测试空字符处理 (NullFails):**  验证当 HTTP 头部中包含空字符时，`HttpStreamParser` 能否正确识别并报错。
*   **测试 Shoutcast 头部识别 (ShoutcastSingleByteReads, ShoutcastWeirdHeader):** 验证 `HttpStreamParser` 能否正确识别 Shoutcast 的头部，即使头部以单字节读取或格式不完全符合 HTTP 标准。
*   **测试 HTTP/0.9 截断头部端口特性 (Http09TruncatedHeaderPortTest):** 验证在非标准端口上，HTTP/0.9 的截断头部会被正确识别为错误。
*   **测试 `received_bytes` 的计算 (ReceivedBytesNormal, ReceivedBytesExcludesNextResponse, ReceivedBytesMultiReadExcludesNextResponse, ReceivedBytesMultiReadExcludesExtraData, ReceivedBytesAsyncMultiReadExcludesExtraData, ReceivedBytesExcludesExtraDataLargeBuffer, ReceivedBytesExcludesExtraDataSmallBuffer, ReceivedBytesFromReadBufExcludesNextResponse, ReceivedBytesUseReadBuf):**  一系列测试用于验证 `HttpStreamParser` 的 `received_bytes()` 方法是否能正确计算当前响应接收的字节数，并且排除下一个响应的数据或者多余的数据。涵盖了单次读取、多次读取、异步读取以及从预先加载的缓冲区读取数据的情况。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不直接与 JavaScript 交互，但 `HttpStreamParser` 是 Chromium 网络栈的关键组件，负责解析 HTTP 数据流。  JavaScript 在浏览器中发起网络请求时，底层的网络栈（包括 `HttpStreamParser`）会处理与服务器的通信。

**举例说明：**

*   **分块上传：** 当 JavaScript 使用 `fetch` API 或 `XMLHttpRequest` 发起带有 `Transfer-Encoding: chunked` 的 POST 请求时，`HttpStreamParser` 负责将 JavaScript 发送的数据分块编码并通过 socket 发送给服务器。如果 `HttpStreamParser` 的分块上传逻辑有误，JavaScript 发送的数据可能会不完整或格式错误，导致服务器无法正确处理。
*   **WebSocket：** 当 JavaScript 代码尝试建立 WebSocket 连接时，浏览器会发送一个 HTTP Upgrade 请求。服务器返回 101 Switching Protocols 响应后，后续的数据将不再是标准的 HTTP 格式。`HttpStreamParser` 需要正确识别 101 响应，并将后续的 WebSocket 帧数据传递给 WebSocket 处理模块。如果 `HttpStreamParser` 的 WebSocket 处理逻辑有误，JavaScript 的 WebSocket 连接将无法建立或通信异常。

**逻辑推理、假设输入与输出：**

以 **Truncated Headers** 中的一个测试为例：

*   **假设输入 (MockRead):**  `MockRead(SYNCHRONOUS, 1, "HTTP/1.1 20"), MockRead(SYNCHRONOUS, 0, 2)`  模拟接收到的响应头被截断，只接收到 "HTTP/1.1 20"，然后连接关闭。
*   **假设行为:**  `parser.ReadResponseHeaders(callback.callback())` 将尝试读取响应头。
*   **预期输出:**
    *   对于 HTTP 协议 (`protocol == HTTP`)，预期返回错误 `ERR_CONNECTION_CLOSED`，因为连接意外关闭。`response_info.headers` 应该不为空，因为已经解析了一部分头部信息。`parser.received_bytes()` 应该等于读取的字节数。
    *   对于 HTTPS 协议 (`protocol == HTTPS`)，预期返回错误 `ERR_RESPONSE_HEADERS_TRUNCATED`，因为安全协议下头部截断被视为安全风险。 `response_info.headers` 应该为空，因为无法安全地解析不完整的头部。 `parser.received_bytes()` 应该为 0，表示没有成功接收到完整的头部。

**用户或编程常见的使用错误：**

*   **服务器端配置错误：** 服务器可能错误地配置了 chunked 上传，导致发送的 chunk 格式不正确，这可以通过测试 `AsyncMultiChunkedUpload` 来发现。
*   **网络不稳定导致的头部截断：** 虽然不是用户直接的编程错误，但网络不稳定可能导致响应头在传输过程中被截断，测试 `TruncatedHeaders` 能够验证在这种情况下 `HttpStreamParser` 的处理是否符合预期。
*   **不正确的 WebSocket 握手实现：** 如果服务器返回的 101 响应格式不正确，测试 `WebSocket101Response` 可以帮助识别这类问题。
*   **在不支持 HTTP/0.9 的端口上使用了 HTTP/0.9：** 虽然现在很少见，但测试 `Http09PortTests` 可以确保 `HttpStreamParser` 在不应使用 HTTP/0.9 的情况下拒绝它。

**用户操作如何一步步到达这里（调试线索）：**

假设用户在使用浏览器时遇到了网页加载失败或 WebSocket 连接错误。作为调试线索，可以考虑以下步骤：

1. **用户尝试访问一个网页或建立 WebSocket 连接。**
2. **浏览器发起 HTTP 请求。** 如果是 POST 请求且数据量较大，可能会使用 chunked 上传。如果是 WebSocket 连接，则会发送 Upgrade 请求。
3. **网络层建立 TCP 连接，并开始发送和接收数据。**
4. **`HttpStreamParser` 开始解析接收到的数据流。**
5. **如果服务器发送的响应头部被截断，或者 WebSocket 握手响应格式错误，或者 chunked 上传的数据格式不正确，`HttpStreamParser` 可能会检测到这些错误。**  相关的测试用例（例如 `TruncatedHeaders`、`WebSocket101Response`、`AsyncMultiChunkedUpload`) 就是模拟这些场景。
6. **`HttpStreamParser` 将错误信息传递给上层网络模块。**
7. **浏览器最终向用户显示网页加载失败或 WebSocket 连接错误的提示。**

在调试这类问题时，开发者可能会使用网络抓包工具（如 Wireshark）来查看实际的网络数据包，并结合 Chromium 的网络日志（可以使用 `chrome://net-export/` 生成）来分析 `HttpStreamParser` 的行为，从而定位问题所在。 此处的单元测试正是为了在开发阶段尽早发现和修复 `HttpStreamParser` 中可能存在的各种缺陷。

### 提示词
```
这是目录为net/http/http_stream_parser_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
pload_stream,
                          read_buffer.get(), NetLogWithSource());

  HttpRequestHeaders request_headers;
  request_headers.SetHeader("Transfer-Encoding", "chunked");

  HttpResponseInfo response_info;
  TestCompletionCallback callback;
  // This will attempt to Write() the initial request and headers, which will
  // complete asynchronously.
  ASSERT_EQ(ERR_IO_PENDING,
            parser.SendRequest("GET /one.html HTTP/1.1\r\n", request_headers,
                               TRAFFIC_ANNOTATION_FOR_TESTS, &response_info,
                               callback.callback()));
  ASSERT_FALSE(callback.have_result());

  // Sending the request and the first chunk completes.
  base::RunLoop().RunUntilIdle();
  ASSERT_FALSE(callback.have_result());

  // Now append another chunk.
  upload_stream.AppendData(base::byte_span_from_cstring(kChunk2), false);
  ASSERT_FALSE(callback.have_result());

  // Add the final chunk, while the write for the second is still pending,
  // which should not confuse the state machine.
  upload_stream.AppendData(base::byte_span_from_cstring(kChunk3), true);
  ASSERT_FALSE(callback.have_result());

  // Wait for writes to complete.
  ASSERT_THAT(callback.WaitForResult(), IsOk());

  // Attempt to read the response status and the response headers.
  ASSERT_THAT(parser.ReadResponseHeaders(callback.callback()),
              IsError(ERR_IO_PENDING));
  ASSERT_THAT(callback.WaitForResult(), IsOk());

  // Finally, attempt to read the response body.
  auto body_buffer = base::MakeRefCounted<IOBufferWithSize>(kBodySize);
  ASSERT_EQ(ERR_IO_PENDING,
            parser.ReadResponseBody(body_buffer.get(), kBodySize,
                                    callback.callback()));
  ASSERT_EQ(kBodySize, callback.WaitForResult());

  EXPECT_EQ(CountWriteBytes(writes), parser.sent_bytes());
  EXPECT_EQ(CountReadBytes(reads), parser.received_bytes());
}

// Test to ensure the HttpStreamParser state machine does not get confused
// when there's only one "chunk" with 0 bytes, and is received from the
// UploadStream only after sending the request headers successfully.
TEST(HttpStreamParser, AsyncEmptyChunkedUpload) {
  base::test::TaskEnvironment task_environment;

  MockWrite writes[] = {
      MockWrite(ASYNC, 0,
                "GET /one.html HTTP/1.1\r\n"
                "Transfer-Encoding: chunked\r\n\r\n"),
      MockWrite(ASYNC, 1, "0\r\n\r\n"),
  };

  // The size of the response body, as reflected in the Content-Length of the
  // MockRead below.
  const int kBodySize = 8;

  MockRead reads[] = {
      MockRead(ASYNC, 2, "HTTP/1.1 200 OK\r\n"),
      MockRead(ASYNC, 3, "Content-Length: 8\r\n\r\n"),
      MockRead(ASYNC, 4, "one.html"),
      MockRead(SYNCHRONOUS, 0, 5),  // EOF
  };

  ChunkedUploadDataStream upload_stream(0);
  ASSERT_THAT(upload_stream.Init(TestCompletionCallback().callback(),
                                 NetLogWithSource()),
              IsOk());

  SequencedSocketData data(reads, writes);
  std::unique_ptr<StreamSocket> stream_socket = CreateConnectedSocket(&data);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://localhost");
  request_info.upload_data_stream = &upload_stream;

  scoped_refptr<GrowableIOBuffer> read_buffer =
      base::MakeRefCounted<GrowableIOBuffer>();
  HttpStreamParser parser(stream_socket.get(), false /* is_reused */,
                          GURL("http://localhost"), "GET", &upload_stream,
                          read_buffer.get(), NetLogWithSource());

  HttpRequestHeaders request_headers;
  request_headers.SetHeader("Transfer-Encoding", "chunked");

  HttpResponseInfo response_info;
  TestCompletionCallback callback;
  // This will attempt to Write() the initial request and headers, which will
  // complete asynchronously.
  ASSERT_EQ(ERR_IO_PENDING,
            parser.SendRequest("GET /one.html HTTP/1.1\r\n", request_headers,
                               TRAFFIC_ANNOTATION_FOR_TESTS, &response_info,
                               callback.callback()));

  // Now append the terminal 0-byte "chunk".
  upload_stream.AppendData(base::byte_span_from_cstring(""), true);
  ASSERT_FALSE(callback.have_result());

  ASSERT_THAT(callback.WaitForResult(), IsOk());

  // Attempt to read the response status and the response headers.
  ASSERT_THAT(parser.ReadResponseHeaders(callback.callback()),
              IsError(ERR_IO_PENDING));
  ASSERT_THAT(callback.WaitForResult(), IsOk());

  // Finally, attempt to read the response body.
  auto body_buffer = base::MakeRefCounted<IOBufferWithSize>(kBodySize);
  ASSERT_EQ(ERR_IO_PENDING,
            parser.ReadResponseBody(body_buffer.get(), kBodySize,
                                    callback.callback()));
  ASSERT_EQ(kBodySize, callback.WaitForResult());

  EXPECT_EQ(CountWriteBytes(writes), parser.sent_bytes());
  EXPECT_EQ(CountReadBytes(reads), parser.received_bytes());
}

// Test to ensure the HttpStreamParser state machine does not get confused
// when there's only one "chunk" with 0 bytes, which was already appended before
// the request was started.
TEST(HttpStreamParser, SyncEmptyChunkedUpload) {
  base::test::TaskEnvironment task_environment;

  MockWrite writes[] = {
      MockWrite(ASYNC, 0,
                "GET /one.html HTTP/1.1\r\n"
                "Transfer-Encoding: chunked\r\n\r\n"),
      MockWrite(ASYNC, 1, "0\r\n\r\n"),
  };

  // The size of the response body, as reflected in the Content-Length of the
  // MockRead below.
  const int kBodySize = 8;

  MockRead reads[] = {
      MockRead(ASYNC, 2, "HTTP/1.1 200 OK\r\n"),
      MockRead(ASYNC, 3, "Content-Length: 8\r\n\r\n"),
      MockRead(ASYNC, 4, "one.html"),
      MockRead(SYNCHRONOUS, 0, 5),  // EOF
  };

  ChunkedUploadDataStream upload_stream(0);
  ASSERT_THAT(upload_stream.Init(TestCompletionCallback().callback(),
                                 NetLogWithSource()),
              IsOk());
  // Append final empty chunk.
  upload_stream.AppendData(base::byte_span_from_cstring(""), true);

  SequencedSocketData data(reads, writes);
  std::unique_ptr<StreamSocket> stream_socket = CreateConnectedSocket(&data);

  scoped_refptr<GrowableIOBuffer> read_buffer =
      base::MakeRefCounted<GrowableIOBuffer>();
  HttpStreamParser parser(stream_socket.get(), false /* is_reused */,
                          GURL("http://localhost"), "GET", &upload_stream,
                          read_buffer.get(), NetLogWithSource());

  HttpRequestHeaders request_headers;
  request_headers.SetHeader("Transfer-Encoding", "chunked");

  HttpResponseInfo response_info;
  TestCompletionCallback callback;
  // This will attempt to Write() the initial request and headers, which will
  // complete asynchronously.
  ASSERT_EQ(ERR_IO_PENDING,
            parser.SendRequest("GET /one.html HTTP/1.1\r\n", request_headers,
                               TRAFFIC_ANNOTATION_FOR_TESTS, &response_info,
                               callback.callback()));

  // Complete writing the request headers and body.
  ASSERT_THAT(callback.WaitForResult(), IsOk());

  // Attempt to read the response status and the response headers.
  ASSERT_THAT(parser.ReadResponseHeaders(callback.callback()),
              IsError(ERR_IO_PENDING));
  ASSERT_THAT(callback.WaitForResult(), IsOk());

  // Finally, attempt to read the response body.
  auto body_buffer = base::MakeRefCounted<IOBufferWithSize>(kBodySize);
  ASSERT_EQ(ERR_IO_PENDING,
            parser.ReadResponseBody(body_buffer.get(), kBodySize,
                                    callback.callback()));
  ASSERT_EQ(kBodySize, callback.WaitForResult());

  EXPECT_EQ(CountWriteBytes(writes), parser.sent_bytes());
  EXPECT_EQ(CountReadBytes(reads), parser.received_bytes());
}

TEST(HttpStreamParser, TruncatedHeaders) {
  MockRead truncated_status_reads[] = {
    MockRead(SYNCHRONOUS, 1, "HTTP/1.1 20"),
    MockRead(SYNCHRONOUS, 0, 2),  // EOF
  };

  MockRead truncated_after_status_reads[] = {
    MockRead(SYNCHRONOUS, 1, "HTTP/1.1 200 Ok\r\n"),
    MockRead(SYNCHRONOUS, 0, 2),  // EOF
  };

  MockRead truncated_in_header_reads[] = {
    MockRead(SYNCHRONOUS, 1, "HTTP/1.1 200 Ok\r\nHead"),
    MockRead(SYNCHRONOUS, 0, 2),  // EOF
  };

  MockRead truncated_after_header_reads[] = {
    MockRead(SYNCHRONOUS, 1, "HTTP/1.1 200 Ok\r\nHeader: foo\r\n"),
    MockRead(SYNCHRONOUS, 0, 2),  // EOF
  };

  MockRead truncated_after_final_newline_reads[] = {
    MockRead(SYNCHRONOUS, 1, "HTTP/1.1 200 Ok\r\nHeader: foo\r\n\r"),
    MockRead(SYNCHRONOUS, 0, 2),  // EOF
  };

  MockRead not_truncated_reads[] = {
    MockRead(SYNCHRONOUS, 1, "HTTP/1.1 200 Ok\r\nHeader: foo\r\n\r\n"),
    MockRead(SYNCHRONOUS, 0, 2),  // EOF
  };

  base::span<MockRead> reads[] = {
      truncated_status_reads,
      truncated_after_status_reads,
      truncated_in_header_reads,
      truncated_after_header_reads,
      truncated_after_final_newline_reads,
      not_truncated_reads,
  };

  MockWrite writes[] = {
    MockWrite(SYNCHRONOUS, 0, "GET / HTTP/1.1\r\n\r\n"),
  };

  enum {
    HTTP = 0,
    HTTPS,
    NUM_PROTOCOLS,
  };

  for (size_t protocol = 0; protocol < NUM_PROTOCOLS; protocol++) {
    SCOPED_TRACE(protocol);

    for (size_t i = 0; i < std::size(reads); i++) {
      SCOPED_TRACE(i);
      SequencedSocketData data(reads[i], writes);
      std::unique_ptr<StreamSocket> stream_socket(CreateConnectedSocket(&data));

      GURL url;
      if (protocol == HTTP) {
        url = GURL("http://localhost");
      } else {
        url = GURL("https://localhost");
      }

      scoped_refptr<GrowableIOBuffer> read_buffer =
          base::MakeRefCounted<GrowableIOBuffer>();
      HttpStreamParser parser(stream_socket.get(), false /* is_reused */, url,
                              "GET", /*upload_data_stream=*/nullptr,
                              read_buffer.get(), NetLogWithSource());

      HttpRequestHeaders request_headers;
      HttpResponseInfo response_info;
      TestCompletionCallback callback;
      ASSERT_EQ(OK, parser.SendRequest("GET / HTTP/1.1\r\n", request_headers,
                                       TRAFFIC_ANNOTATION_FOR_TESTS,
                                       &response_info, callback.callback()));

      int rv = parser.ReadResponseHeaders(callback.callback());
      EXPECT_EQ(CountWriteBytes(writes), parser.sent_bytes());
      if (i == std::size(reads) - 1) {
        EXPECT_THAT(rv, IsOk());
        EXPECT_TRUE(response_info.headers.get());
        EXPECT_EQ(CountReadBytes(reads[i]), parser.received_bytes());
      } else {
        if (protocol == HTTP) {
          EXPECT_THAT(rv, IsError(ERR_CONNECTION_CLOSED));
          EXPECT_TRUE(response_info.headers.get());
          EXPECT_EQ(CountReadBytes(reads[i]), parser.received_bytes());
        } else {
          EXPECT_THAT(rv, IsError(ERR_RESPONSE_HEADERS_TRUNCATED));
          EXPECT_FALSE(response_info.headers.get());
          EXPECT_EQ(0, parser.received_bytes());
        }
      }
    }
  }
}

// Confirm that on 101 response, the headers are parsed but the data that
// follows remains in the buffer.
TEST(HttpStreamParser, WebSocket101Response) {
  MockRead reads[] = {
    MockRead(SYNCHRONOUS, 1,
             "HTTP/1.1 101 Switching Protocols\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "\r\n"
             "a fake websocket frame"),
  };

  MockWrite writes[] = {
    MockWrite(SYNCHRONOUS, 0, "GET / HTTP/1.1\r\n\r\n"),
  };

  SequencedSocketData data(reads, writes);
  std::unique_ptr<StreamSocket> stream_socket = CreateConnectedSocket(&data);

  scoped_refptr<GrowableIOBuffer> read_buffer =
      base::MakeRefCounted<GrowableIOBuffer>();
  HttpStreamParser parser(stream_socket.get(), false /* is_reused */,
                          GURL("http://localhost"), "GET",
                          /*upload_data_stream=*/nullptr, read_buffer.get(),
                          NetLogWithSource());

  HttpRequestHeaders request_headers;
  HttpResponseInfo response_info;
  TestCompletionCallback callback;
  ASSERT_EQ(OK, parser.SendRequest("GET / HTTP/1.1\r\n", request_headers,
                                   TRAFFIC_ANNOTATION_FOR_TESTS, &response_info,
                                   callback.callback()));

  EXPECT_THAT(parser.ReadResponseHeaders(callback.callback()), IsOk());
  ASSERT_TRUE(response_info.headers.get());
  EXPECT_EQ(101, response_info.headers->response_code());
  EXPECT_TRUE(response_info.headers->HasHeaderValue("Connection", "Upgrade"));
  EXPECT_TRUE(response_info.headers->HasHeaderValue("Upgrade", "websocket"));
  EXPECT_EQ(read_buffer->capacity(), read_buffer->offset());
  EXPECT_EQ("a fake websocket frame",
            base::as_string_view(read_buffer->everything()));

  EXPECT_EQ(CountWriteBytes(writes), parser.sent_bytes());
  EXPECT_EQ(CountReadBytes(reads) -
                static_cast<int64_t>(strlen("a fake websocket frame")),
            parser.received_bytes());
}

// Helper class for constructing HttpStreamParser and running GET requests.
class SimpleGetRunner {
 public:
  SimpleGetRunner()
      : url_("http://localhost"),
        read_buffer_(base::MakeRefCounted<GrowableIOBuffer>()) {
    writes_.emplace_back(
        MockWrite(SYNCHRONOUS, sequence_number_++, "GET / HTTP/1.1\r\n\r\n"));
  }

  void set_url(const GURL& url) { url_ = url; }

  HttpStreamParser* parser() { return parser_.get(); }
  GrowableIOBuffer* read_buffer() { return read_buffer_.get(); }
  HttpResponseInfo* response_info() { return &response_info_; }

  void AddInitialData(const std::string& data) {
    int offset = read_buffer_->offset();
    read_buffer_->SetCapacity(offset + data.size());
    auto span = base::as_byte_span(data);
    read_buffer_->everything()
        .subspan(base::checked_cast<size_t>(offset), span.size())
        .copy_from(span);
    read_buffer_->set_offset(offset + span.size());
  }

  // The data used to back |string_piece| must stay alive until all mock data
  // has been read.
  void AddRead(std::string_view string_piece) {
    reads_.emplace_back(SYNCHRONOUS, string_piece.data(), string_piece.length(),
                        sequence_number_++);
  }

  void AddAsyncRead(std::string_view string_piece) {
    reads_.emplace_back(ASYNC, string_piece.data(), string_piece.length(),
                        sequence_number_++);
  }

  void SetupParserAndSendRequest() {
    reads_.emplace_back(SYNCHRONOUS, 0, sequence_number_++);  // EOF

    data_ = std::make_unique<SequencedSocketData>(reads_, writes_);
    stream_socket_ = CreateConnectedSocket(data_.get());

    parser_ = std::make_unique<HttpStreamParser>(
        stream_socket_.get(), false /* is_reused */, url_, "GET",
        /*upload_data_stream=*/nullptr, read_buffer(), NetLogWithSource());

    TestCompletionCallback callback;
    ASSERT_EQ(OK, parser_->SendRequest("GET / HTTP/1.1\r\n", request_headers_,
                                       TRAFFIC_ANNOTATION_FOR_TESTS,
                                       &response_info_, callback.callback()));
  }

  void ReadHeadersExpectingError(Error error) {
    TestCompletionCallback callback;
    EXPECT_THAT(parser_->ReadResponseHeaders(callback.callback()),
                IsError(error));
  }

  void ReadHeaders() { ReadHeadersExpectingError(OK); }

  std::string ReadBody(int user_buf_len, int* read_lengths) {
    TestCompletionCallback callback;
    auto buffer = base::MakeRefCounted<IOBufferWithSize>(user_buf_len);
    int rv;
    int i = 0;
    std::string body;
    while (true) {
      rv = parser_->ReadResponseBody(
          buffer.get(), user_buf_len, callback.callback());
      EXPECT_EQ(read_lengths[i], rv);
      if (rv == ERR_IO_PENDING) {
        rv = callback.WaitForResult();
        i++;
        EXPECT_EQ(read_lengths[i], rv);
      }
      if (rv > 0)
        body.append(buffer->data(), rv);
      i++;
      if (rv <= 0)
        return body;
    }
  }

 private:
  GURL url_;

  HttpRequestHeaders request_headers_;
  HttpResponseInfo response_info_;
  scoped_refptr<GrowableIOBuffer> read_buffer_;
  std::vector<MockRead> reads_;
  std::vector<MockWrite> writes_;
  std::unique_ptr<StreamSocket> stream_socket_;
  std::unique_ptr<SequencedSocketData> data_;
  std::unique_ptr<HttpStreamParser> parser_;
  int sequence_number_ = 0;
};

// Test that HTTP/0.9 works as expected, only on ports where it should be
// enabled.
TEST(HttpStreamParser, Http09PortTests) {
  struct TestCase {
    const char* url;

    // Expected result when trying to read headers and response is an HTTP/0.9
    // non-Shoutcast response.
    Error expected_09_header_error;

    // Expected result when trying to read headers for a shoutcast response.
    Error expected_shoutcast_header_error;
  };

  const TestCase kTestCases[] = {
      // Default ports should work for HTTP/0.9, regardless of whether the port
      // is explicitly specified or not.
      {"http://foo.com/", OK, OK},
      {"http://foo.com:80/", OK, OK},
      {"https://foo.com/", OK, OK},
      {"https://foo.com:443/", OK, OK},

      // Non-standard ports should not support HTTP/0.9, by default.
      {"http://foo.com:8080/", ERR_INVALID_HTTP_RESPONSE, OK},
      {"https://foo.com:8080/", ERR_INVALID_HTTP_RESPONSE,
       ERR_INVALID_HTTP_RESPONSE},
      {"http://foo.com:443/", ERR_INVALID_HTTP_RESPONSE, OK},
      {"https://foo.com:80/", ERR_INVALID_HTTP_RESPONSE,
       ERR_INVALID_HTTP_RESPONSE},
  };

  const std::string kResponse = "hello\r\nworld\r\n";

  for (const auto& test_case : kTestCases) {
    SimpleGetRunner get_runner;
    get_runner.set_url(GURL(test_case.url));
    get_runner.AddRead(kResponse);
    get_runner.SetupParserAndSendRequest();

    get_runner.ReadHeadersExpectingError(test_case.expected_09_header_error);
    if (test_case.expected_09_header_error != OK)
      continue;

    ASSERT_TRUE(get_runner.response_info()->headers);
    EXPECT_EQ("HTTP/0.9 200 OK",
              get_runner.response_info()->headers->GetStatusLine());

    EXPECT_EQ(0, get_runner.parser()->received_bytes());
    int read_lengths[] = {static_cast<int>(kResponse.size()), 0};
    get_runner.ReadBody(kResponse.size(), read_lengths);
    EXPECT_EQ(kResponse.size(),
              static_cast<size_t>(get_runner.parser()->received_bytes()));
    EXPECT_EQ(HttpConnectionInfo::kHTTP0_9,
              get_runner.response_info()->connection_info);
  }

  const std::string kShoutcastResponse = "ICY 200 blah\r\n\r\n";
  for (const auto& test_case : kTestCases) {
    SimpleGetRunner get_runner;
    get_runner.set_url(GURL(test_case.url));
    get_runner.AddRead(kShoutcastResponse);
    get_runner.SetupParserAndSendRequest();

    get_runner.ReadHeadersExpectingError(
        test_case.expected_shoutcast_header_error);
    if (test_case.expected_shoutcast_header_error != OK)
      continue;

    ASSERT_TRUE(get_runner.response_info()->headers);
    EXPECT_EQ("HTTP/0.9 200 OK",
              get_runner.response_info()->headers->GetStatusLine());

    EXPECT_EQ(0, get_runner.parser()->received_bytes());
    int read_lengths[] = {static_cast<int>(kShoutcastResponse.size()), 0};
    get_runner.ReadBody(kShoutcastResponse.size(), read_lengths);
    EXPECT_EQ(kShoutcastResponse.size(),
              static_cast<size_t>(get_runner.parser()->received_bytes()));
    EXPECT_EQ(HttpConnectionInfo::kHTTP0_9,
              get_runner.response_info()->connection_info);
  }
}

TEST(HttpStreamParser, ContinueWithBody) {
  const std::string kResponse =
      "HTTP/1.1 100 Continue\r\n\r\nhello\r\nworld\r\n";

  SimpleGetRunner get_runner;
  get_runner.set_url(GURL("http://foo.com/"));
  get_runner.AddRead(kResponse);
  get_runner.SetupParserAndSendRequest();

  get_runner.ReadHeadersExpectingError(OK);
  ASSERT_TRUE(get_runner.response_info()->headers);
  EXPECT_EQ("HTTP/1.1 100 Continue",
            get_runner.response_info()->headers->GetStatusLine());

  // We ignore informational responses and start reading the next response in
  // the stream. This simulates the behavior.
  get_runner.ReadHeadersExpectingError(ERR_INVALID_HTTP_RESPONSE);
}

TEST(HttpStreamParser, NullFails) {
  const char kTestHeaders[] =
      "HTTP/1.1 200 OK\r\n"
      "Foo: Bar\r\n"
      "Content-Length: 4\r\n\r\n";

  // Try inserting a null at each position in kTestHeaders. Every location
  // should result in an error.
  //
  // Need to start at 4 because HttpStreamParser will treat the response as
  // HTTP/0.9 if it doesn't see "HTTP", and need to end at -1 because "\r\n\r"
  // is currently treated as a valid end of header marker.
  for (size_t i = 4; i < std::size(kTestHeaders) - 1; ++i) {
    std::string read_data(kTestHeaders);
    read_data.insert(i, 1, '\0');
    read_data.append("body");
    SimpleGetRunner get_runner;
    get_runner.set_url(GURL("http://foo.test/"));
    get_runner.AddRead(read_data);
    get_runner.SetupParserAndSendRequest();

    get_runner.ReadHeadersExpectingError(ERR_INVALID_HTTP_RESPONSE);
  }
}

// Make sure that Shoutcast is recognized when receiving one byte at a time.
TEST(HttpStreamParser, ShoutcastSingleByteReads) {
  SimpleGetRunner get_runner;
  get_runner.set_url(GURL("http://foo.com:8080/"));
  get_runner.AddRead("i");
  get_runner.AddRead("c");
  get_runner.AddRead("Y");
  // Needed because HttpStreamParser::Read returns ERR_CONNECTION_CLOSED on
  // small response headers, which HttpNetworkTransaction replaces with OK.
  // TODO(mmenke): Can we just change that behavior?
  get_runner.AddRead(" Extra stuff");
  get_runner.SetupParserAndSendRequest();

  get_runner.ReadHeadersExpectingError(OK);
  EXPECT_EQ("HTTP/0.9 200 OK",
            get_runner.response_info()->headers->GetStatusLine());
}

// Make sure that Shoutcast is recognized when receiving any string starting
// with "ICY", regardless of capitalization, and without a space following it
// (The latter behavior is just to match HTTP detection).
TEST(HttpStreamParser, ShoutcastWeirdHeader) {
  SimpleGetRunner get_runner;
  get_runner.set_url(GURL("http://foo.com:8080/"));
  get_runner.AddRead("iCyCreamSundae");
  get_runner.SetupParserAndSendRequest();

  get_runner.ReadHeadersExpectingError(OK);
  EXPECT_EQ("HTTP/0.9 200 OK",
            get_runner.response_info()->headers->GetStatusLine());
}

// Make sure that HTTP/0.9 isn't allowed in the truncated header case on a weird
// port.
TEST(HttpStreamParser, Http09TruncatedHeaderPortTest) {
  SimpleGetRunner get_runner;
  get_runner.set_url(GURL("http://foo.com:8080/"));
  std::string response = "HT";
  get_runner.AddRead(response);
  get_runner.SetupParserAndSendRequest();

  get_runner.ReadHeadersExpectingError(ERR_INVALID_HTTP_RESPONSE);
}

// Test basic case where there is no keep-alive or extra data from the socket,
// and the entire response is received in a single read.
TEST(HttpStreamParser, ReceivedBytesNormal) {
  std::string headers =
      "HTTP/1.0 200 OK\r\n"
      "Content-Length: 7\r\n\r\n";
  std::string body = "content";
  std::string response = headers + body;

  SimpleGetRunner get_runner;
  get_runner.AddRead(response);
  get_runner.SetupParserAndSendRequest();
  get_runner.ReadHeaders();
  int64_t headers_size = headers.size();
  EXPECT_EQ(headers_size, get_runner.parser()->received_bytes());
  int body_size = body.size();
  int read_lengths[] = {body_size, 0};
  get_runner.ReadBody(body_size, read_lengths);
  int64_t response_size = response.size();
  EXPECT_EQ(response_size, get_runner.parser()->received_bytes());
  EXPECT_EQ(HttpConnectionInfo::kHTTP1_0,
            get_runner.response_info()->connection_info);
}

// Test that bytes that represent "next" response are not counted
// as current response "received_bytes".
TEST(HttpStreamParser, ReceivedBytesExcludesNextResponse) {
  std::string headers = "HTTP/1.1 200 OK\r\n"
      "Content-Length:  8\r\n\r\n";
  std::string body = "content8";
  std::string response = headers + body;
  std::string next_response = "HTTP/1.1 200 OK\r\n\r\nFOO";
  std::string data = response + next_response;

  SimpleGetRunner get_runner;
  get_runner.AddRead(data);
  get_runner.SetupParserAndSendRequest();
  get_runner.ReadHeaders();
  EXPECT_EQ(39, get_runner.parser()->received_bytes());
  int64_t headers_size = headers.size();
  EXPECT_EQ(headers_size, get_runner.parser()->received_bytes());
  int body_size = body.size();
  int read_lengths[] = {body_size, 0};
  get_runner.ReadBody(body_size, read_lengths);
  int64_t response_size = response.size();
  EXPECT_EQ(response_size, get_runner.parser()->received_bytes());
  EXPECT_EQ(0, get_runner.read_buffer()->offset());
  EXPECT_EQ(HttpConnectionInfo::kHTTP1_1,
            get_runner.response_info()->connection_info);
}

// Test that "received_bytes" calculation works fine when last read
// contains more data than requested by user.
// We send data in two reads:
// 1) Headers + beginning of response
// 2) remaining part of response + next response start
// We setup user read buffer so it fully accepts the beginning of response
// body, but it is larger than remaining part of body.
TEST(HttpStreamParser, ReceivedBytesMultiReadExcludesNextResponse) {
  std::string headers = "HTTP/1.1 200 OK\r\n"
      "Content-Length: 36\r\n\r\n";
  int64_t user_buf_len = 32;
  std::string body_start = std::string(user_buf_len, '#');
  int body_start_size = body_start.size();
  EXPECT_EQ(user_buf_len, body_start_size);
  std::string response_start = headers + body_start;
  std::string body_end = "abcd";
  std::string next_response = "HTTP/1.1 200 OK\r\n\r\nFOO";
  std::string response_end = body_end + next_response;

  SimpleGetRunner get_runner;
  get_runner.AddRead(response_start);
  get_runner.AddRead(response_end);
  get_runner.SetupParserAndSendRequest();
  get_runner.ReadHeaders();
  int64_t headers_size = headers.size();
  EXPECT_EQ(headers_size, get_runner.parser()->received_bytes());
  int body_end_size = body_end.size();
  int read_lengths[] = {body_start_size, body_end_size, 0};
  get_runner.ReadBody(body_start_size, read_lengths);
  int64_t response_size = response_start.size() + body_end_size;
  EXPECT_EQ(response_size, get_runner.parser()->received_bytes());
  EXPECT_EQ(0, get_runner.read_buffer()->offset());
  EXPECT_FALSE(get_runner.parser()->CanReuseConnection());
}

TEST(HttpStreamParser, ReceivedBytesMultiReadExcludesExtraData) {
  const std::string headers =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 36\r\n\r\n";
  const int64_t user_buf_len = 32;
  const std::string body_start = std::string(user_buf_len, '#');
  const int body_start_size = body_start.size();
  EXPECT_EQ(user_buf_len, body_start_size);
  const std::string body_end = "abcd";
  const int body_end_size = body_end.size();
  const std::string body = body_start + body_end;
  const int body_size = body.size();
  const std::string extra_data = "HTTP/1.1 200 OK\r\n\r\nFOO";
  const std::string read_data = body + extra_data;

  SimpleGetRunner get_runner;
  get_runner.AddRead(headers);
  get_runner.AddRead(read_data);
  get_runner.SetupParserAndSendRequest();
  get_runner.ReadHeaders();
  const int headers_size = headers.size();
  EXPECT_EQ(headers_size, get_runner.parser()->received_bytes());
  int read_lengths[] = {body_start_size, body_end_size, 0};
  get_runner.ReadBody(body_start_size, read_lengths);
  const int response_size = headers_size + body_size;
  EXPECT_EQ(response_size, get_runner.parser()->received_bytes());
  EXPECT_EQ(0, get_runner.read_buffer()->offset());
  EXPECT_FALSE(get_runner.parser()->CanReuseConnection());
}

TEST(HttpStreamParser, ReceivedBytesAsyncMultiReadExcludesExtraData) {
  base::test::SingleThreadTaskEnvironment task_environment;

  const std::string headers =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 36\r\n\r\n";
  const int64_t user_buf_len = 32;
  const std::string body_start = std::string(user_buf_len, '#');
  const int body_start_size = body_start.size();
  EXPECT_EQ(user_buf_len, body_start_size);
  const std::string body_end = "abcd";
  const int body_end_size = body_end.size();
  const std::string body = body_start + body_end;
  const int body_size = body.size();
  const std::string extra_data = "HTTP/1.1 200 OK\r\n\r\nFOO";
  const std::string read_data = body_end + extra_data;

  SimpleGetRunner get_runner;
  get_runner.AddRead(headers);
  get_runner.AddRead(body_start);
  get_runner.AddAsyncRead(read_data);
  get_runner.SetupParserAndSendRequest();
  get_runner.ReadHeaders();
  const int headers_size = headers.size();
  EXPECT_EQ(headers_size, get_runner.parser()->received_bytes());
  int read_lengths[] = {body_start_size, -1, body_end_size, 0};
  get_runner.ReadBody(body_start_size, read_lengths);
  const int response_size = headers_size + body_size;
  EXPECT_EQ(response_size, get_runner.parser()->received_bytes());
  EXPECT_EQ(0, get_runner.read_buffer()->offset());
  EXPECT_FALSE(get_runner.parser()->CanReuseConnection());
}

TEST(HttpStreamParser, ReceivedBytesExcludesExtraDataLargeBuffer) {
  const std::string headers =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 36\r\n\r\n";
  const std::string body = std::string(36, '#');
  const int body_size = body.size();
  const std::string extra_data = std::string(14, '!');
  const std::string response = headers + body + extra_data;
  const int response_size = response.size();

  SimpleGetRunner get_runner;
  get_runner.AddRead(response);
  get_runner.SetupParserAndSendRequest();
  get_runner.ReadHeaders();
  const int headers_size = headers.size();
  EXPECT_EQ(headers_size, get_runner.parser()->received_bytes());
  int read_lengths[] = {body_size, 0};
  get_runner.ReadBody(response_size, read_lengths);
  const int actual_response_size = headers_size + body_size;
  EXPECT_EQ(actual_response_size, get_runner.parser()->received_bytes());
  EXPECT_EQ(0, get_runner.read_buffer()->offset());
  EXPECT_FALSE(get_runner.parser()->CanReuseConnection());
}

TEST(HttpStreamParser, ReceivedBytesExcludesExtraDataSmallBuffer) {
  const std::string headers =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 36\r\n\r\n";
  const std::string body = std::string(36, '#');
  const int body_size = body.size();
  const std::string extra_data = std::string(14, '!');
  const std::string response = headers + body + extra_data;

  SimpleGetRunner get_runner;
  get_runner.AddRead(response);
  get_runner.SetupParserAndSendRequest();
  get_runner.ReadHeaders();
  const int headers_size = headers.size();
  EXPECT_EQ(headers_size, get_runner.parser()->received_bytes());
  int read_lengths[] = {10, 10, 10, 6, 0};
  get_runner.ReadBody(10, read_lengths);
  const int actual_response_size = headers_size + body_size;
  EXPECT_EQ(actual_response_size, get_runner.parser()->received_bytes());
  EXPECT_EQ(0, get_runner.read_buffer()->offset());
  EXPECT_FALSE(get_runner.parser()->CanReuseConnection());
}

// Test that "received_bytes" calculation works fine when there is no
// network activity at all; that is when all data is read from read buffer.
// In this case read buffer contains two responses. We expect that only
// bytes that correspond to the first one are taken into account.
TEST(HttpStreamParser, ReceivedBytesFromReadBufExcludesNextResponse) {
  std::string headers = "HTTP/1.1 200 OK\r\n"
      "Content-Length: 7\r\n\r\n";
  std::string body = "content";
  std::string response = headers + body;
  std::string next_response = "HTTP/1.1 200 OK\r\n\r\nFOO";
  std::string data = response + next_response;

  SimpleGetRunner get_runner;
  get_runner.AddInitialData(data);
  get_runner.SetupParserAndSendRequest();
  get_runner.ReadHeaders();
  int64_t headers_size = headers.size();
  EXPECT_EQ(headers_size, get_runner.parser()->received_bytes());
  int body_size = body.size();
  int read_lengths[] = {body_size, 0};
  get_runner.ReadBody(body_size, read_lengths);
  int64_t response_size = response.size();
  EXPECT_EQ(response_size, get_runner.parser()->received_bytes());
  EXPECT_EQ(0, get_runner.read_buffer()->offset());
  EXPECT_FALSE(get_runner.parser()->CanReuseConnection());
}

// Test calculating "received_bytes" when part of request has been already
// loaded and placed to read buffer by previous stream parser.
TEST(HttpStreamParser, ReceivedBytesUseReadBuf) {
  std::string buffer = "HTTP/1.1 200 OK\r\n";
  std::string remaining_headers = "Content-Length: 7\r\n\r\n";
  int64_t headers_size = buffer.size() + remaining_headers.size();
  std::string body = "content";
  std::string response = remaining_headers + body;

  SimpleGetRunner get_runner;
  get_runner.AddInitialData(buffer);
  get_runner.AddRead(response);
  get_runner.SetupParserAndSendRequest();
  get_runner.ReadHeaders();
  EXPECT_EQ(headers_size, get_runner.parser()->received_bytes());
  int body_size = body.size();
```