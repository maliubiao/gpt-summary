Response:
The user wants a summary of the provided C++ code, specifically the `net/http/http_stream_parser_unittest.cc` file from Chromium's network stack. They are asking for:

1. **Functionality:** What does this code do?
2. **Relationship to Javascript:** Does it interact with Javascript in any way?
3. **Logic and Examples:** If there's logical reasoning, provide input/output examples.
4. **Common Errors:**  Illustrate common user/programming mistakes.
5. **Debugging:** How does a user end up here during debugging?
6. **Summary:** A concise overview of the code's purpose.

Let's break down the code snippets provided. Each `TEST` function seems to be testing a specific aspect of the `HttpStreamParser` class. The `SimpleGetRunner` class is a test fixture for simplifying the process of setting up and running tests.

* **`ReceivedBytesContentLength`:** Tests that `received_bytes()` correctly reflects the total received data when `Content-Length` is used.
* **`ReceivedBytesChunkedTransferExcludesNextResponse`:** Verifies that `received_bytes()` accurately counts data for a chunked transfer, excluding any subsequent response data.
* **`ReceivedBytesMultipleReads`:** Checks that `received_bytes()` works correctly even when data is received in multiple smaller reads.
* **`NonInformationalResponseStart`:** Tests the timing information (`first_response_start_time`, `non_informational_response_start_time`) for a response without informational (1xx) headers.
* **`NonInformationalResponseStartWithoutBody`:** Similar to the previous test, but for responses with no body.
* **`ReceivedBytesIncludesContinueHeader`:** Ensures that the size of "100 Continue" headers is included in `received_bytes()`.
* **`EarlyHints`:** Tests that the size of "103 Early Hints" headers is included in `received_bytes()` and checks the timing of the first early hints.
* **`MixedResponseHeaders`:** Checks the timing information when informational and non-informational headers are received in the same data chunk.
* **`ReadAfterUnownedObjectsDestroyed`:** Tests that the parser can still function after the objects that own it and its associated data structures are destroyed. This is relevant to scenarios like using `ResponseBodyDrainer`.
* **`ReceiveOneByteAtATime`:** Tests the parser's robustness when receiving data one byte at a time.

**Relationship to Javascript:** This C++ code is part of the browser's network stack. While it doesn't directly *execute* Javascript, it's crucial for fetching resources that Javascript code might request (e.g., through `fetch` or `XMLHttpRequest`).

**Logic and Examples:** The logic revolves around simulating network reads and verifying the state of the `HttpStreamParser`. The examples are mostly within the test cases themselves, showing how input data affects the parser's internal state and output.

**Common Errors:**  The tests implicitly highlight potential error scenarios, like miscalculating content length, not handling chunked encoding correctly, or mishandling multiple reads.

**Debugging:**  A developer might end up here while debugging network-related issues, such as incorrect data reception, timing problems with responses, or crashes related to resource management.

**Summary:** This file contains unit tests for the `HttpStreamParser` class. It thoroughly checks various aspects of HTTP response parsing, including counting received bytes, handling different transfer encodings, managing timing information for informational and non-informational responses, and ensuring robustness in edge cases like byte-by-byte reception and resource cleanup.

Based on this analysis, I can now generate the requested output.
这是文件 `net/http/http_stream_parser_unittest.cc` 的第三部分，其主要功能是**测试 `HttpStreamParser` 类的各种功能和边界情况**。`HttpStreamParser` 负责解析从网络连接中读取的 HTTP 数据流。

**归纳一下它的功能：**

这部分测试主要集中在以下几个方面：

1. **`received_bytes()` 的精确计算：** 测试在各种场景下，`HttpStreamParser` 记录的已接收字节数 (`received_bytes()`) 是否准确，包括：
    * 使用 `Content-Length` 时的完整大小。
    * 使用 `chunked` 传输编码时，排除后续响应数据。
    * 数据分多次读取时的情况。
    * 包含 "100 Continue" 头部时。
    * 包含 "103 Early Hints" 头部时。

2. **响应时间信息：** 测试 `HttpStreamParser` 如何记录和返回响应的起始时间 (`first_response_start_time`, `non_informational_response_start_time`, `first_early_hints_time`)，特别是在处理包含 1xx 状态码（如 "100 Continue" 或 "103 Early Hints"）的响应时。

3. **资源管理和生命周期：** 测试在拥有 `HttpStreamParser` 的对象及其相关数据结构被销毁后，是否仍然可以从 `HttpStreamParser` 中读取数据。这模拟了像 `ResponseBodyDrainer` 这样的场景。

4. **数据读取的鲁棒性：** 测试当以非常小的块（例如，每次一个字节）接收数据时，`HttpStreamParser` 是否能够正确解析 HTTP 响应。

**与 Javascript 的功能关系：**

`HttpStreamParser` 本身是 C++ 代码，不直接与 Javascript 交互。但是，它是浏览器网络栈的核心组件，负责解析从服务器接收到的 HTTP 响应。当 Javascript 代码（例如，使用 `fetch` API 或 `XMLHttpRequest`）发起网络请求时，浏览器底层会使用 `HttpStreamParser` 来处理服务器返回的数据。

**举例说明：**

假设一个 Javascript 程序使用 `fetch` 来请求一个资源：

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

在这个过程中：

1. Javascript 代码调用 `fetch`。
2. 浏览器网络栈建立与 `example.com` 的连接。
3. 浏览器发送 HTTP 请求。
4. 服务器返回 HTTP 响应，响应数据流会到达 `HttpStreamParser`。
5. `HttpStreamParser` 解析响应头（例如 `Content-Type: application/json`）和响应体。
6. 解析后的响应数据被传递给 Javascript，`response.json()` 方法会进一步解析 JSON 数据。

**逻辑推理的假设输入与输出：**

**场景：测试 `ReceivedBytesContentLength`**

* **假设输入:**
    * HTTP 响应头: `"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n"` (长度为 31)
    * HTTP 响应体: `"Hello World"` (长度为 11)
* **预期输出:**
    * `get_runner.parser()->received_bytes()` 应该等于 31 + 11 = 42。

**场景：测试 `ReceivedBytesChunkedTransferExcludesNextResponse`**

* **假设输入:**
    * HTTP 响应 (chunked): `"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\nChunk 1\r\n8\r\nChunky 2\r\n6\r\nTest 3\r\n0\r\n\r\n"` (长度为 61)
    * 后续数据: `"foo bar\r\n"` (长度为 10)
* **预期输出:**
    * 在读取完第一个响应后，`get_runner.parser()->received_bytes()` 应该等于 61。
    * `get_runner.read_buffer()->offset()` 应该等于 10，指向后续数据的起始位置。

**涉及用户或者编程常见的使用错误，并举例说明：**

1. **错误地假设 `received_bytes()` 包含了所有 socket 上的数据：** 用户可能会认为 `received_bytes()` 会返回 socket 上所有接收到的字节，即使这些字节属于下一个 HTTP 响应。`ReceivedBytesChunkedTransferExcludesNextResponse` 测试就验证了 `HttpStreamParser` 只计算当前响应的字节数。

2. **在读取响应体之前错误地判断响应是否完成：** 用户可能会在 `ReadResponseHeaders` 返回 OK 后，就认为整个响应已接收完毕。但实际上，响应体可能还没有读取。测试用例中多次使用 `ReadBody` 方法来演示如何逐步读取响应体。

3. **未处理分块传输的情况：** 用户编写的网络代码可能只考虑了 `Content-Length` 的情况，而忽略了 `chunked` 传输编码。`ReceivedBytesChunkedTransferExcludesNextResponse` 测试强调了 `HttpStreamParser` 正确处理了这种情况。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在浏览器中访问一个网页，该网页的加载过程遇到问题，例如：

1. **页面加载缓慢或卡住：** 用户可能会注意到页面内容加载不完整或者非常慢。
2. **开发者工具显示网络错误：** 用户打开浏览器的开发者工具 (通常按 F12)，切换到 "Network" (网络) 标签，可能会看到请求的状态码异常，或者请求一直处于 "Pending" (等待) 状态。
3. **检查请求详情：** 用户点击有问题的请求，查看 "Headers" (头部) 和 "Response" (响应) 信息。如果响应头部不完整，或者响应体数据有问题，可能就需要深入分析数据接收过程。
4. **底层网络调试：** 开发者可能需要使用更底层的网络调试工具（例如 `tcpdump` 或 Chrome 的 `net-internals`）来查看原始的网络数据包。
5. **定位到 `HttpStreamParser`：** 如果怀疑是 HTTP 解析过程出了问题，开发者可能会查看 Chromium 的网络栈源代码，搜索与 HTTP 解析相关的代码，例如 `HttpStreamParser`。单元测试文件 `http_stream_parser_unittest.cc` 可以帮助开发者理解 `HttpStreamParser` 的工作原理和可能出现的错误。

**总结一下这部分的功能：**

这部分 `http_stream_parser_unittest.cc` 文件专注于测试 `HttpStreamParser` 类在处理各种 HTTP 响应场景时的正确性和精确性，特别是关于已接收字节数的计算和响应时间信息的记录。它涵盖了常见的 HTTP 特性（如 `Content-Length` 和 `chunked` 传输编码）以及一些边缘情况（如接收到 1xx 状态码）。这些测试确保了 `HttpStreamParser` 能够可靠地解析 HTTP 数据流，为浏览器提供正确的网络数据。

Prompt: 
```
这是目录为net/http/http_stream_parser_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
 int read_lengths[] = {body_size, 0};
  get_runner.ReadBody(body_size, read_lengths);
  EXPECT_EQ(headers_size + body_size, get_runner.parser()->received_bytes());
  EXPECT_EQ(0, get_runner.read_buffer()->offset());
}

// Test the case when the resulting read_buf contains both unused bytes and
// bytes ejected by chunked-encoding filter.
TEST(HttpStreamParser, ReceivedBytesChunkedTransferExcludesNextResponse) {
  std::string response = "HTTP/1.1 200 OK\r\n"
      "Transfer-Encoding: chunked\r\n\r\n"
      "7\r\nChunk 1\r\n"
      "8\r\nChunky 2\r\n"
      "6\r\nTest 3\r\n"
      "0\r\n\r\n";
  std::string next_response = "foo bar\r\n";
  std::string data = response + next_response;

  SimpleGetRunner get_runner;
  get_runner.AddInitialData(data);
  get_runner.SetupParserAndSendRequest();
  get_runner.ReadHeaders();
  int read_lengths[] = {4, 3, 6, 2, 6, 0};
  get_runner.ReadBody(7, read_lengths);
  int64_t response_size = response.size();
  EXPECT_EQ(response_size, get_runner.parser()->received_bytes());
  int64_t next_response_size = next_response.size();
  EXPECT_EQ(next_response_size, get_runner.read_buffer()->offset());
}

// Test that data transfered in multiple reads is correctly processed.
// We feed data into 4-bytes reads. Also we set length of read
// buffer to 5-bytes to test all possible buffer misaligments.
TEST(HttpStreamParser, ReceivedBytesMultipleReads) {
  std::string headers = "HTTP/1.1 200 OK\r\n"
      "Content-Length: 33\r\n\r\n";
  std::string body = "foo bar baz\r\n"
      "sputnik mir babushka";
  std::string response = headers + body;

  size_t receive_length = 4;
  std::vector<std::string> blocks;
  for (size_t i = 0; i < response.size(); i += receive_length) {
    size_t length = std::min(receive_length, response.size() - i);
    blocks.push_back(response.substr(i, length));
  }

  SimpleGetRunner get_runner;
  for (const auto& block : blocks)
    get_runner.AddRead(block);
  get_runner.SetupParserAndSendRequest();
  get_runner.ReadHeaders();
  int64_t headers_size = headers.size();
  EXPECT_EQ(headers_size, get_runner.parser()->received_bytes());
  int read_lengths[] = {1, 4, 4, 4, 4, 4, 4, 4, 4, 0};
  get_runner.ReadBody(receive_length + 1, read_lengths);
  int64_t response_size = response.size();
  EXPECT_EQ(response_size, get_runner.parser()->received_bytes());
}

// Test timing information of responses that don't have informational (1xx)
// response headers.
TEST(HttpStreamParser, NonInformationalResponseStart) {
  base::test::TaskEnvironment task_environment(
      base::test::TaskEnvironment::TimeSource::MOCK_TIME);

  std::string response_headers1 = "HTTP/1.1 200 OK\r\n";
  std::string response_headers2 = "Content-Length: 7\r\n\r\n";
  int64_t response_headers_size =
      response_headers1.size() + response_headers2.size();

  std::string response_body = "content";
  int64_t response_size = response_headers_size + response_body.size();

  MockWrite writes[] = {MockWrite(SYNCHRONOUS, 0, "GET / HTTP/1.1\r\n\r\n")};

  MockRead reads[] = {
      // Add pauses between header fragments so that the test runner can advance
      // the mock clock to test timing information.
      MockRead(ASYNC, 1, response_headers1.c_str()),
      MockRead(ASYNC, ERR_IO_PENDING, 2),
      MockRead(ASYNC, 3, response_headers2.c_str()),
      MockRead(ASYNC, 4, response_body.c_str()),
  };

  // Set up the sequenced socket data.
  SequencedSocketData sequenced_socket_data(reads, writes);
  std::unique_ptr<StreamSocket> stream_socket =
      CreateConnectedSocket(&sequenced_socket_data);

  // Set up the http stream parser.
  auto read_buffer = base::MakeRefCounted<GrowableIOBuffer>();
  HttpStreamParser parser(stream_socket.get(), /*connection_is_reused=*/false,
                          GURL("http://localhost"), "GET",
                          /*upload_data_stream=*/nullptr, read_buffer.get(),
                          NetLogWithSource());

  // Send a request.
  HttpResponseInfo response;
  TestCompletionCallback callback;
  EXPECT_THAT(parser.SendRequest("GET / HTTP/1.1\r\n", HttpRequestHeaders(),
                                 TRAFFIC_ANNOTATION_FOR_TESTS, &response,
                                 callback.callback()),
              IsOk());

  EXPECT_THAT(parser.ReadResponseHeaders(callback.callback()),
              IsError(ERR_IO_PENDING));
  task_environment.AdvanceClock(base::Seconds(1));

  // [seq=1 --> seq=2] The parser reads the first fragment of the response
  // headers and then pauses to advance the mock clock.
  base::TimeTicks first_response_start_time = task_environment.NowTicks();
  sequenced_socket_data.RunUntilPaused();
  task_environment.AdvanceClock(base::Seconds(1));

  // [seq=3] The parser reads the second fragment of the response headers.
  sequenced_socket_data.Resume();
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  // Check the received headers.
  EXPECT_EQ(200, response.headers->response_code());
  EXPECT_EQ(response_headers_size, parser.received_bytes());

  // No informational responses were served. The first response start time
  // should be equal to the non-informational response start time.
  EXPECT_EQ(parser.first_response_start_time(), first_response_start_time);
  EXPECT_EQ(parser.non_informational_response_start_time(),
            first_response_start_time);

  // [seq=4] The parser reads the response body.
  auto body_buffer =
      base::MakeRefCounted<IOBufferWithSize>(response_body.size());
  int result = parser.ReadResponseBody(body_buffer.get(), response_body.size(),
                                       callback.callback());
  EXPECT_THAT(callback.GetResult(result), response_body.size());

  // Check the received body.
  EXPECT_EQ(response_size, parser.received_bytes());
}

// Test timing information of responses that don't have informational (1xx)
// response headers, and have no response body.
TEST(HttpStreamParser, NonInformationalResponseStartWithoutBody) {
  base::test::TaskEnvironment task_environment(
      base::test::TaskEnvironment::TimeSource::MOCK_TIME);

  std::string response_headers1 = "HTTP/1.1 200 OK\r\n";
  std::string response_headers2 = "Content-Length: 0\r\n\r\n";
  int64_t response_size = response_headers1.size() + response_headers2.size();

  MockWrite writes[] = {MockWrite(SYNCHRONOUS, 0, "GET / HTTP/1.1\r\n\r\n")};

  MockRead reads[] = {
      // Add pauses between header fragments so that the test runner can advance
      // the mock clock to test timing information.
      MockRead(ASYNC, 1, response_headers1.c_str()),
      MockRead(ASYNC, ERR_IO_PENDING, 2),
      MockRead(ASYNC, 3, response_headers2.c_str()),
  };

  // Set up the sequenced socket data.
  SequencedSocketData sequenced_socket_data(reads, writes);
  std::unique_ptr<StreamSocket> stream_socket =
      CreateConnectedSocket(&sequenced_socket_data);

  // Set up the http stream parser.
  auto read_buffer = base::MakeRefCounted<GrowableIOBuffer>();
  HttpStreamParser parser(stream_socket.get(), /*connection_is_reused=*/false,
                          GURL("http://localhost"), "GET",
                          /*upload_data_stream=*/nullptr, read_buffer.get(),
                          NetLogWithSource());

  // Send a request.
  HttpResponseInfo response;
  TestCompletionCallback callback;
  EXPECT_THAT(parser.SendRequest("GET / HTTP/1.1\r\n", HttpRequestHeaders(),
                                 TRAFFIC_ANNOTATION_FOR_TESTS, &response,
                                 callback.callback()),
              IsOk());

  EXPECT_THAT(parser.ReadResponseHeaders(callback.callback()),
              IsError(ERR_IO_PENDING));
  task_environment.AdvanceClock(base::Seconds(1));

  // [seq=1 --> seq=2] The parser reads the first fragment of the response
  // headers and then pauses to advance the mock clock.
  base::TimeTicks first_response_start_time = task_environment.NowTicks();
  sequenced_socket_data.RunUntilPaused();
  task_environment.AdvanceClock(base::Seconds(1));

  // [seq=3] The parser reads the second fragment of the response headers.
  sequenced_socket_data.Resume();
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  // Check the received headers.
  EXPECT_EQ(200, response.headers->response_code());
  EXPECT_EQ(response_size, parser.received_bytes());

  // No informational responses were served. The first response start time
  // should be equal to the non-informational response start time.
  EXPECT_EQ(parser.first_response_start_time(), first_response_start_time);
  EXPECT_EQ(parser.non_informational_response_start_time(),
            first_response_start_time);

  // [seq=4] The parser reads the response body.
  auto body_buffer = base::MakeRefCounted<IOBufferWithSize>(10);
  int result = parser.ReadResponseBody(body_buffer.get(), body_buffer->size(),
                                       callback.callback());
  EXPECT_THAT(callback.GetResult(result), IsError(OK));
}

// Test that "continue" HTTP header is counted as "received_bytes".
TEST(HttpStreamParser, ReceivedBytesIncludesContinueHeader) {
  base::test::TaskEnvironment task_environment(
      base::test::TaskEnvironment::TimeSource::MOCK_TIME);

  std::string status100_response_headers1 = "HTTP/1.1 100 ";
  std::string status100_response_headers2 = "Continue\r\n\r\n";
  int64_t status100_response_headers_size =
      status100_response_headers1.size() + status100_response_headers2.size();

  std::string response_headers1 = "HTTP/1.1 200 OK\r\n";
  std::string response_headers2 = "Content-Length: 7\r\n\r\n";
  int64_t response_headers_size =
      response_headers1.size() + response_headers2.size();

  std::string response_body = "content";
  int64_t response_size = status100_response_headers_size +
                          response_headers_size + response_body.size();

  MockWrite writes[] = {MockWrite(SYNCHRONOUS, 0, "GET / HTTP/1.1\r\n\r\n")};

  MockRead reads[] = {
      // Add pauses between header fragments so that the test runner can advance
      // the mock clock to test timing information.

      // 100 response headers.
      MockRead(ASYNC, 1, status100_response_headers1.c_str()),
      MockRead(ASYNC, ERR_IO_PENDING, 2),
      MockRead(ASYNC, 3, status100_response_headers2.c_str()),
      MockRead(ASYNC, ERR_IO_PENDING, 4),

      // 200 response headers and body.
      MockRead(ASYNC, 5, response_headers1.c_str()),
      MockRead(ASYNC, ERR_IO_PENDING, 6),
      MockRead(ASYNC, 7, response_headers2.c_str()),
      MockRead(ASYNC, 8, response_body.c_str()),
  };

  // Set up the sequenced socket data.
  SequencedSocketData sequenced_socket_data(reads, writes);
  std::unique_ptr<StreamSocket> stream_socket =
      CreateConnectedSocket(&sequenced_socket_data);

  // Set up the http stream parser.
  auto read_buffer = base::MakeRefCounted<GrowableIOBuffer>();
  HttpStreamParser parser(stream_socket.get(), /*connection_is_reused=*/false,
                          GURL("http://localhost"), "GET",
                          /*upload_data_stream=*/nullptr, read_buffer.get(),
                          NetLogWithSource());

  // Send a request.
  HttpResponseInfo response;
  TestCompletionCallback callback;
  EXPECT_THAT(parser.SendRequest("GET / HTTP/1.1\r\n", HttpRequestHeaders(),
                                 TRAFFIC_ANNOTATION_FOR_TESTS, &response,
                                 callback.callback()),
              IsOk());

  EXPECT_THAT(parser.ReadResponseHeaders(callback.callback()),
              IsError(ERR_IO_PENDING));

  // [seq=1 --> seq=2] The parser reads the first fragment of the informational
  // response headers and then pauses to advance the mock clock.
  base::TimeTicks first_response_start_time = task_environment.NowTicks();
  sequenced_socket_data.RunUntilPaused();
  task_environment.AdvanceClock(base::Seconds(1));

  // [seq=3] The parser reads the second fragment of the informational response
  // headers.
  sequenced_socket_data.Resume();
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  // Check the received headers.
  EXPECT_EQ(100, response.headers->response_code());
  EXPECT_EQ(status100_response_headers_size, parser.received_bytes());

  EXPECT_THAT(parser.ReadResponseHeaders(callback.callback()),
              IsError(ERR_IO_PENDING));

  // [seq=4] The parser pauses to advance the clock.
  sequenced_socket_data.RunUntilPaused();
  task_environment.AdvanceClock(base::Seconds(1));

  // [seq=5 --> seq=6] The parser reads the first fragment of the
  // non-informational response headers and then pauses to advance the mock
  // clock.
  base::TimeTicks non_informational_response_start_time =
      task_environment.NowTicks();
  sequenced_socket_data.Resume();
  sequenced_socket_data.RunUntilPaused();
  task_environment.AdvanceClock(base::Seconds(1));

  // [seq=7] The parser reads the second fragment of the non-informational
  // response headers.
  sequenced_socket_data.Resume();
  EXPECT_THAT(callback.WaitForResult(), IsOk());
  task_environment.AdvanceClock(base::Seconds(1));

  // Check the received headers.
  EXPECT_EQ(200, response.headers->response_code());
  EXPECT_EQ(status100_response_headers_size + response_headers_size,
            parser.received_bytes());

  // The first response start time should be captured at the time the first
  // fragment of the informational response headers is received.
  EXPECT_EQ(parser.first_response_start_time(), first_response_start_time);
  // The non-informational response start time should be captured at the time
  // the first fragment of the non-informational response headers is received.
  EXPECT_EQ(parser.non_informational_response_start_time(),
            non_informational_response_start_time);
  // The first response start time should be earlier than the non-informational
  // response start time.
  EXPECT_LT(parser.first_response_start_time(),
            parser.non_informational_response_start_time());

  // [seq=8] The parser reads the non-informational response body.
  auto body_buffer =
      base::MakeRefCounted<IOBufferWithSize>(response_body.size());
  int result = parser.ReadResponseBody(body_buffer.get(), response_body.size(),
                                       callback.callback());
  EXPECT_THAT(callback.GetResult(result), response_body.size());

  // Check the received body.
  EXPECT_EQ(response_size, parser.received_bytes());
}

// Test that "early hints" HTTP header is counted as "received_bytes".
// 103 Early Hints hasn't been implemented yet and should be ignored, but we
// collect timing information for the experiment (https://crbug.com/1093693).
TEST(HttpStreamParser, EarlyHints) {
  base::test::TaskEnvironment task_environment(
      base::test::TaskEnvironment::TimeSource::MOCK_TIME);

  std::string status103_response_headers1 = "HTTP/1.1 103 Early Hints\r\n";
  std::string status103_response_headers2 =
      "Link: </style.css>; rel=preload; as=style\r\n";
  std::string status103_response_headers3 =
      "Link: </script.js>; rel=preload; as=script\r\n\r\n";
  int64_t status103_response_headers_size = status103_response_headers1.size() +
                                            status103_response_headers2.size() +
                                            status103_response_headers3.size();

  std::string response_headers1 = "HTTP/1.1 200 OK\r\n";
  std::string response_headers2 = "Content-Length: 7\r\n\r\n";
  int64_t response_headers_size =
      response_headers1.size() + response_headers2.size();

  std::string response_body = "content";
  int64_t response_size = status103_response_headers_size +
                          response_headers_size + response_body.size();

  MockWrite writes[] = {MockWrite(SYNCHRONOUS, 0, "GET / HTTP/1.1\r\n\r\n")};

  MockRead reads[] = {
      // Add pauses between header fragments so that the test runner can advance
      // the mock clock to test timing information.

      // 103 Early Hints response headers.
      MockRead(ASYNC, 1, status103_response_headers1.c_str()),
      MockRead(ASYNC, ERR_IO_PENDING, 2),
      MockRead(ASYNC, 3, status103_response_headers2.c_str()),
      MockRead(ASYNC, ERR_IO_PENDING, 4),
      MockRead(ASYNC, 5, status103_response_headers3.c_str()),
      MockRead(ASYNC, ERR_IO_PENDING, 6),

      // 200 response headers and body.
      MockRead(ASYNC, 7, response_headers1.c_str()),
      MockRead(ASYNC, ERR_IO_PENDING, 8),
      MockRead(ASYNC, 9, response_headers2.c_str()),
      MockRead(ASYNC, 10, response_body.c_str()),
  };

  // Set up the sequenced socket data.
  SequencedSocketData sequenced_socket_data(reads, writes);
  std::unique_ptr<StreamSocket> stream_socket =
      CreateConnectedSocket(&sequenced_socket_data);

  // Set up the http stream parser.
  auto read_buffer = base::MakeRefCounted<GrowableIOBuffer>();
  HttpStreamParser parser(stream_socket.get(), /*connection_is_reused=*/false,
                          GURL("http://localhost"), "GET",
                          /*upload_data_stream=*/nullptr, read_buffer.get(),
                          NetLogWithSource());

  // Send a request.
  HttpResponseInfo response;
  TestCompletionCallback callback;
  EXPECT_THAT(parser.SendRequest("GET / HTTP/1.1\r\n", HttpRequestHeaders(),
                                 TRAFFIC_ANNOTATION_FOR_TESTS, &response,
                                 callback.callback()),
              IsOk());

  EXPECT_THAT(parser.ReadResponseHeaders(callback.callback()),
              IsError(ERR_IO_PENDING));

  // [seq=1 --> seq=2] The parser reads the first fragment of the informational
  // response headers and then pauses to advance the mock clock.
  base::TimeTicks first_response_start_time = task_environment.NowTicks();
  sequenced_socket_data.RunUntilPaused();
  task_environment.AdvanceClock(base::Seconds(1));

  // [seq=3 --> seq=4] The parser reads the second fragment of the informational
  // response headers and then pauses to advance the mock clock.
  sequenced_socket_data.Resume();
  sequenced_socket_data.RunUntilPaused();
  task_environment.AdvanceClock(base::Seconds(1));

  // [seq=5] The parser reads the third fragment of the informational response
  // headers.
  sequenced_socket_data.Resume();
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  // Check the received headers.
  EXPECT_EQ(103, response.headers->response_code());
  EXPECT_EQ(status103_response_headers_size, parser.received_bytes());

  EXPECT_THAT(parser.ReadResponseHeaders(callback.callback()),
              IsError(ERR_IO_PENDING));

  // [seq=6] The parser pauses to advance the clock.
  sequenced_socket_data.RunUntilPaused();
  task_environment.AdvanceClock(base::Seconds(1));

  // [seq=7 --> seq=8] The parser reads the first fragment of the
  // non-informational response headers and then pauses to advance the mock
  // clock.
  base::TimeTicks non_informational_response_start_time =
      task_environment.NowTicks();
  sequenced_socket_data.Resume();
  sequenced_socket_data.RunUntilPaused();
  task_environment.AdvanceClock(base::Seconds(1));

  // [seq=9] The parser reads the second fragment of the non-informational
  // response headers.
  sequenced_socket_data.Resume();
  EXPECT_THAT(callback.WaitForResult(), IsOk());
  task_environment.AdvanceClock(base::Seconds(1));

  // Check the received headers.
  EXPECT_EQ(200, response.headers->response_code());
  EXPECT_EQ(status103_response_headers_size + response_headers_size,
            parser.received_bytes());

  // The first response start time and first early hints time should be captured
  // at the time the first fragment of the informational response headers is
  // received.
  EXPECT_EQ(parser.first_response_start_time(), first_response_start_time);
  EXPECT_EQ(parser.first_early_hints_time(), first_response_start_time);
  // The non-informational response start time should be captured at the time
  // the first fragment of the non-informational response headers is received.
  EXPECT_EQ(parser.non_informational_response_start_time(),
            non_informational_response_start_time);
  // The first response start time should be earlier than the non-informational
  // response start time.
  EXPECT_LT(parser.first_response_start_time(),
            parser.non_informational_response_start_time());

  // [seq=10] The parser reads the non-informational response body.
  auto body_buffer =
      base::MakeRefCounted<IOBufferWithSize>(response_body.size());
  int result = parser.ReadResponseBody(body_buffer.get(), response_body.size(),
                                       callback.callback());
  EXPECT_THAT(callback.GetResult(result), response_body.size());

  // Check the received body.
  EXPECT_EQ(response_size, parser.received_bytes());
}

// Test the case where informational response headers and non-informational
// response headers are packed in the same fragment.
TEST(HttpStreamParser, MixedResponseHeaders) {
  base::test::TaskEnvironment task_environment(
      base::test::TaskEnvironment::TimeSource::MOCK_TIME);

  std::string status100_response_headers = "HTTP/1.1 100 ";
  std::string mixed_response_headers = "Continue\r\n\r\nHTTP/1.1 200 OK\r\n";
  std::string response_headers = "Content-Length: 7\r\n\r\n";
  int64_t status100_response_headers_size =
      status100_response_headers.size() + 12;
  int64_t response_headers_size = response_headers.size() + 17;

  std::string response_body = "content";
  int64_t response_size = status100_response_headers_size +
                          response_headers_size + response_body.size();

  MockWrite writes[] = {MockWrite(SYNCHRONOUS, 0, "GET / HTTP/1.1\r\n\r\n")};

  MockRead reads[] = {
      // Add pauses between header fragments so that the test runner can advance
      // the mock clock to test timing information.

      // 100 response headers.
      MockRead(ASYNC, 1, status100_response_headers.c_str()),
      MockRead(ASYNC, ERR_IO_PENDING, 2),

      // Mixed response headers.
      MockRead(ASYNC, 3, mixed_response_headers.c_str()),
      MockRead(ASYNC, ERR_IO_PENDING, 4),

      // 200 response headers and body.
      MockRead(ASYNC, 5, response_headers.c_str()),
      MockRead(ASYNC, 6, response_body.c_str()),
  };

  // Set up the sequenced socket data.
  SequencedSocketData sequenced_socket_data(reads, writes);
  std::unique_ptr<StreamSocket> stream_socket =
      CreateConnectedSocket(&sequenced_socket_data);

  // Set up the http stream parser.
  auto read_buffer = base::MakeRefCounted<GrowableIOBuffer>();
  HttpStreamParser parser(stream_socket.get(), /*connection_is_reused=*/false,
                          GURL("http://localhost"), "GET",
                          /*upload_data_stream=*/nullptr, read_buffer.get(),
                          NetLogWithSource());

  // Send a request.
  HttpResponseInfo response;
  TestCompletionCallback callback;
  EXPECT_THAT(parser.SendRequest("GET / HTTP/1.1\r\n", HttpRequestHeaders(),
                                 TRAFFIC_ANNOTATION_FOR_TESTS, &response,
                                 callback.callback()),
              IsOk());

  EXPECT_THAT(parser.ReadResponseHeaders(callback.callback()),
              IsError(ERR_IO_PENDING));

  // [seq=1 --> seq=2] The parser reads the first fragment of the informational
  // response headers and then pauses to advance the mock clock.
  base::TimeTicks first_response_start_time = task_environment.NowTicks();
  sequenced_socket_data.RunUntilPaused();
  task_environment.AdvanceClock(base::Seconds(1));

  // [seq=3] The parser reads the second fragment of the informational response
  // headers.
  sequenced_socket_data.Resume();
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  // Check the received headers.
  EXPECT_EQ(100, response.headers->response_code());
  EXPECT_EQ(status100_response_headers_size, parser.received_bytes());

  EXPECT_THAT(parser.ReadResponseHeaders(callback.callback()),
              IsError(ERR_IO_PENDING));

  // [seq=3 --> seq=4] The parser reads the first fragment of the
  // non-informational response headers and then pauses to advance the mock
  // clock.
  base::TimeTicks non_informational_response_start_time =
      task_environment.NowTicks();
  sequenced_socket_data.RunUntilPaused();
  task_environment.AdvanceClock(base::Seconds(1));

  // [seq=5] The parser reads the second fragment of the non-informational
  // response headers.
  sequenced_socket_data.Resume();
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  // Check the received headers.
  EXPECT_EQ(200, response.headers->response_code());
  EXPECT_EQ(status100_response_headers_size + response_headers_size,
            parser.received_bytes());

  // The first response start time should be captured at the time the first
  // fragment of the informational response headers is received.
  EXPECT_EQ(parser.first_response_start_time(), first_response_start_time);
  // The non-informational response start time should be captured at the time
  // the first fragment of the non-informational response headers is received.
  EXPECT_EQ(parser.non_informational_response_start_time(),
            non_informational_response_start_time);
  // The first response start time should be earlier than the non-informational
  // response start time.
  EXPECT_LT(parser.first_response_start_time(),
            parser.non_informational_response_start_time());

  // [seq=6] The parser reads the non-informational response body.
  auto body_buffer =
      base::MakeRefCounted<IOBufferWithSize>(response_body.size());
  int result = parser.ReadResponseBody(body_buffer.get(), response_body.size(),
                                       callback.callback());
  EXPECT_THAT(callback.GetResult(result), response_body.size());

  // Check the received body.
  EXPECT_EQ(response_size, parser.received_bytes());
}

// Test that an HttpStreamParser can be read from after it's received headers
// and data structures owned by its owner have been deleted.  This happens
// when a ResponseBodyDrainer is used.
// Test that an HttpStreamParser can be read from after it's received headers
// and data structures owned by its owner have been deleted.  This happens
// when a ResponseBodyDrainer is used.
TEST(HttpStreamParser, ReadAfterUnownedObjectsDestroyed) {
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, 0,
                "GET /foo.html HTTP/1.1\r\n"
                "Content-Length: 3\r\n\r\n"
                "123"),
  };

  const int kBodySize = 1;
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, 1, "HTTP/1.1 200 OK\r\n"),
      MockRead(SYNCHRONOUS, 2, "Content-Length: 1\r\n"),
      MockRead(SYNCHRONOUS, 3, "Connection: Keep-Alive\r\n\r\n"),
      MockRead(SYNCHRONOUS, 4, "1"),
      MockRead(SYNCHRONOUS, 0, 5),  // EOF
  };

  SequencedSocketData data(reads, writes);
  std::unique_ptr<StreamSocket> stream_socket = CreateConnectedSocket(&data);

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("123")));
  auto upload_data_stream =
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers), 0);
  ASSERT_THAT(upload_data_stream->Init(TestCompletionCallback().callback(),
                                       NetLogWithSource()),
              IsOk());

  scoped_refptr<GrowableIOBuffer> read_buffer =
      base::MakeRefCounted<GrowableIOBuffer>();
  HttpStreamParser parser(stream_socket.get(), false /* is_reused */,
                          GURL("http://somewhere/foo.html"), "POST",
                          upload_data_stream.get(), read_buffer.get(),
                          NetLogWithSource());

  auto request_headers = std::make_unique<HttpRequestHeaders>();
  request_headers->SetHeader("Content-Length", "3");

  auto response_info = std::make_unique<HttpResponseInfo>();
  TestCompletionCallback callback;
  ASSERT_EQ(
      OK, parser.SendRequest("GET /foo.html HTTP/1.1\r\n", *request_headers,
                             TRAFFIC_ANNOTATION_FOR_TESTS, response_info.get(),
                             callback.callback()));
  ASSERT_THAT(parser.ReadResponseHeaders(callback.callback()), IsOk());

  // If the object that owns the HttpStreamParser is deleted, it takes the
  // objects passed to the HttpStreamParser with it.
  upload_data_stream.reset();
  request_headers.reset();
  response_info.reset();

  auto body_buffer = base::MakeRefCounted<IOBufferWithSize>(kBodySize);
  ASSERT_EQ(kBodySize, parser.ReadResponseBody(body_buffer.get(), kBodySize,
                                               callback.callback()));

  EXPECT_EQ(CountWriteBytes(writes), parser.sent_bytes());
  EXPECT_EQ(CountReadBytes(reads), parser.received_bytes());
}

// Case where one byte is received at a time.
TEST(HttpStreamParser, ReceiveOneByteAtATime) {
  constexpr std::string_view kResponseHeaders =
      "HTTP/1.0 200 OK\r\n"
      "Foo: Bar\r\n\r\n";
  constexpr std::string_view kResponseBody = "hi";

  SimpleGetRunner get_runner;
  for (size_t i = 0; i < kResponseHeaders.length(); ++i) {
    get_runner.AddRead(kResponseHeaders.substr(i, 1));
  }
  for (size_t i = 0; i < kResponseBody.length(); ++i) {
    get_runner.AddRead(kResponseBody.substr(i, 1));
  }
  // EOF
  get_runner.AddRead("");

  get_runner.SetupParserAndSendRequest();
  get_runner.ReadHeaders();
  EXPECT_EQ(get_runner.response_info()->headers->GetNormalizedHeader("Foo"),
            "Bar");
  int read_lengths[] = {1, 1, 0};
  EXPECT_EQ(kResponseBody,
            get_runner.ReadBody(kResponseBody.size(), read_lengths));
}

}  // namespace

}  // namespace net

"""


```