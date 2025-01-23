Response:
The user wants a summary of the functionality of the provided C++ code snippet from Chromium's network stack. I need to analyze the code, identify its main purposes, and if applicable, relate it to JavaScript functionality, provide examples of logical reasoning with inputs and outputs, highlight common user/programming errors, and describe the user actions that lead to this code.

**Overall Functionality:**

The code snippet consists of unit tests for the `HttpNetworkTransaction` class in Chromium. These tests verify various aspects of how HTTP requests and responses are handled, including:

*   Basic request/response flow.
*   Handling of intermediate 100 Continue responses.
*   Measurement of time-to-first-byte (TTFB).
*   Handling of connection errors and retries.
*   Interaction with keep-alive connections.
*   Behavior with pre-connected sockets.
*   Handling of non-keep-alive connections and EOF.
*   Handling of early connection closures.

**Relationship to JavaScript:**

While the C++ code itself isn't directly written in JavaScript, it underpins the network functionality that JavaScript uses in web browsers. When a JavaScript application (e.g., using `fetch` or `XMLHttpRequest`) makes an HTTP request, the browser's network stack, including the `HttpNetworkTransaction` class being tested here, handles the underlying communication.

**Logical Reasoning Examples:**

I will create examples based on the tests in the code.

**User/Programming Errors:**

I will identify common issues related to HTTP requests that these tests might be designed to catch.

**User Actions and Debugging:**

I will describe the steps a user might take in a browser that would lead to this network code being executed and how these tests could be used for debugging.
这是对 `net/http/http_network_transaction_unittest.cc` 文件中 `HttpNetworkTransactionTest` 测试类的第 3 部分代码的分析。这部分代码主要集中在测试 `HttpNetworkTransaction` 类在处理各种 HTTP 响应场景下的行为，特别是与时间和连接管理相关的方面。

**主要功能归纳:**

1. **处理非指定状态码的 102 响应:** 测试了当服务器发送一个包含 102 状态码的响应，然后紧接着发送实际的 200 OK 响应时，`HttpNetworkTransaction` 能否正确处理并返回最终的响应数据。
2. **获取已接收的 Body 字节数:** 验证了 `GetReceivedBodyBytes()` 方法能够正确返回已接收的响应体字节数，在多次读取操作后能正确累加。
3. **测量 HTTP 的首字节到达时间 (TTFB):**  测试了在 HTTP 请求中，`HttpNetworkTransaction` 能否准确测量从连接建立完成到接收到第一个响应字节的时间。这个测试还模拟了延迟，以确保延迟不会被错误地计入 TTFB。
4. **测量带有 1XX 响应的 TTFB:**  测试了当服务器发送 100 Continue 这类信息性响应后，再发送最终的 200 OK 响应时，TTFB 的计算是否基于第一个信息性响应，而不是最终的成功响应。同时测试了 HTTP/1.1 和 HTTP/2 (SPDY) 协议下的情况。
5. **处理不完整的 100 响应后连接关闭:** 测试了当服务器发送一个不完整的 100 Continue 响应后关闭连接时，`HttpNetworkTransaction` 的处理行为。
6. **处理空响应:** 测试了当服务器发送一个没有响应体的响应时，`HttpNetworkTransaction` 是否会返回 `ERR_EMPTY_RESPONSE` 错误。
7. **Keep-Alive 连接重发请求 (错误场景):**  测试了在 Keep-Alive 连接上发送请求时，如果连接在写入或读取数据过程中发生错误（例如连接断开），`HttpNetworkTransaction` 是否能够正确地重新发起请求。测试了 `ERR_SOCKET_NOT_CONNECTED` 和 `ERR_CONNECTION_RESET` 以及 EOF 的情况。
8. **预连接错误重发请求:** 测试了当使用预连接的 socket 发送请求时，如果预连接的 socket 在使用过程中发生错误，`HttpNetworkTransaction` 是否能使用新的连接重试请求。同时测试了 HTTP/1.1 和 HTTP/2 (SPDY) 协议以及分块上传的情况。
9. **有限次数重试 IO 错误:** 测试了当遇到某些特定的 IO 错误（如 HTTP/2 的 `GOAWAY` 帧）时，`HttpNetworkTransaction` 是否会进行有限次数的重试，而不是无限重试。
10. **非 Keep-Alive 连接中断:** 测试了当服务器在非 Keep-Alive 连接上发送数据过程中断开连接时，`HttpNetworkTransaction` 是否会返回 `ERR_CONNECTION_RESET` 错误。
11. **非 Keep-Alive 连接过早关闭 (EOF):** 测试了当服务器在非 Keep-Alive 连接上没有发送任何响应头或响应体就关闭连接时，`HttpNetworkTransaction` 是否会返回 `ERR_EMPTY_RESPONSE` 错误。
12. **Keep-Alive 连接过早关闭 (回归测试):**  测试了在接收到部分响应后，服务器在 Keep-Alive 连接上过早关闭连接的情况，确保 `HttpNetworkTransaction` 不会因此挂起。

**与 JavaScript 的关系:**

虽然这段代码是 C++ 写的，但它直接影响了 JavaScript 中网络请求的行为。当 JavaScript 通过 `fetch` API 或 `XMLHttpRequest` 发起 HTTP 请求时，Chromium 的网络栈（包括这里的 `HttpNetworkTransaction`）负责处理底层的网络通信。

*   **示例:** 当 JavaScript 代码使用 `fetch('http://example.com')` 发起请求时，Chromium 的网络栈会创建 `HttpNetworkTransaction` 对象来处理这个请求。这里的测试确保了当服务器返回各种类型的响应（例如 102 响应，或者连接意外关闭）时，`HttpNetworkTransaction` 能够正确处理，并将最终结果（成功或错误）返回给 JavaScript。
*   **TTFB 对性能的影响:**  `LoadTimingMeasuresTimeToFirstByteForHttp` 和 `Check100ResponseTiming` 测试直接关系到网页性能的指标。JavaScript 可以通过 Performance API 获取到 TTFB 等信息，帮助开发者分析和优化网页加载速度。

**逻辑推理示例 (假设输入与输出):**

**示例 1: 处理非指定状态码的 102 响应**

*   **假设输入:** 服务器先发送 "HTTP/1.1 102 Unspecified status code\r\n\r\n"，然后发送 "HTTP/1.1 200 OK\r\n\r\nhello world"。
*   **预期输出:** `HttpNetworkTransaction::Start()` 返回 `OK`，`GetResponseInfo()->headers->GetStatusLine()` 返回 "HTTP/1.1 200 OK"，`ReadTransaction()` 返回 "hello world"。

**示例 2: Keep-Alive 连接重发请求 (连接重置)**

*   **假设输入:** 第一次请求发送后，服务器发送部分响应头，然后连接被重置 (模拟 `ERR_CONNECTION_RESET`)。第二次请求发送成功，返回 "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nworld"。
*   **预期输出:** 第一次请求的 `WaitForResult()` 返回错误，但第二次请求的 `WaitForResult()` 返回 `OK`，且 `ReadTransaction()` 返回 "world"。

**用户或编程常见的使用错误 (调试线索):**

1. **服务器配置错误导致发送非标准的 1XX 响应:**  `MeasuresTimeToFirst100ResponseForHttp` 和 `MeasuresTimeToFirst100ResponseForSpdy` 这类测试可以帮助发现服务器端在处理 1XX 响应时存在的问题，例如发送了不符合规范的响应头。用户可能在浏览器中看到加载缓慢或者请求卡住。
2. **服务器过早关闭 Keep-Alive 连接:** `KeepAliveEarlyClose` 和 `KeepAliveEarlyClose2` 这类测试可以帮助开发者调试服务器端 Keep-Alive 连接管理的问题。如果服务器在没有发送完整响应就关闭连接，可能会导致客户端出现数据不完整或者连接错误。用户可能会看到页面加载不完整或遇到连接错误。
3. **网络不稳定导致连接中断:** `KeepAliveConnectionReset` 和 `NonKeepAliveConnectionReset` 这类测试模拟了网络连接中断的情况。虽然不是编程错误，但在调试网络问题时，了解客户端在这种情况下的行为至关重要。用户可能会看到连接超时的错误提示。
4. **错误地假设所有请求都会成功并立刻返回数据:**  异步的 `MockRead` 和 `MockWrite` 以及 `ERR_IO_PENDING` 的使用强调了网络操作的异步性。开发者需要正确处理异步操作完成的回调，而不是阻塞等待。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入 URL 并回车，或者点击一个链接。** 这会触发浏览器发起一个 HTTP 请求。
2. **浏览器首先会进行 DNS 解析，建立 TCP 连接，如果是 HTTPS，还会进行 TLS 握手。** 这些操作在 `HttpNetworkTransaction` 的 `Start` 方法被调用之前完成。
3. **`HttpNetworkTransaction` 对象被创建，用于处理这个特定的 HTTP 请求。**
4. **`Start` 方法被调用，开始发送请求头。**
5. **如果服务器发送 100 Continue 响应，`HttpNetworkTransaction` 会进行处理（如 `MeasuresTimeToFirst100ResponseForHttp` 测试所涵盖的）。**
6. **`HttpNetworkTransaction` 接收服务器的响应头和响应体数据。**  `GetReceivedBodyBytes` 测试确保了接收的数据量被正确追踪。
7. **如果在接收数据过程中发生网络错误（如连接重置），`KeepAliveConnectionReset` 或 `NonKeepAliveConnectionReset` 测试所涵盖的逻辑会被触发。**
8. **如果连接是 Keep-Alive 的，并且在发送后续请求时连接出现问题，`KeepAliveConnectionResendRequestTest` 涵盖的重试逻辑会被执行。**
9. **最终，`HttpNetworkTransaction` 将接收到的数据或错误信息传递给上层（例如网络模块或渲染引擎）。**

**调试线索:**

*   **网络日志 (netlog):** Chromium 提供了强大的网络日志功能，可以记录每个网络请求的详细信息，包括 `HttpNetworkTransaction` 的生命周期、socket 的使用情况、以及发生的错误。开发者可以通过 `chrome://net-export/` 导出网络日志进行分析。
*   **断点调试:** 开发者可以在 `net/http/http_network_transaction.cc` 中设置断点，逐步跟踪代码的执行流程，查看变量的值，理解在各种网络场景下 `HttpNetworkTransaction` 的行为。
*   **单元测试:**  这里的单元测试本身就是很好的调试工具。当遇到特定的网络问题时，可以尝试编写类似的单元测试来复现问题，并验证修复方案的正确性。

总而言之，这部分代码专注于测试 `HttpNetworkTransaction` 在各种复杂的 HTTP 场景下的健壮性和正确性，特别是涉及到时间和连接管理的关键方面，这对于确保 Chromium 浏览器网络功能的稳定性和性能至关重要。

### 提示词
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共34部分，请归纳一下它的功能
```

### 源代码
```cpp
get());

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 102 Unspecified status code\r\n\r\n"
               "HTTP/1.1 200 OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);
}

TEST_P(HttpNetworkTransactionTest, GetReceivedBodyBytes) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.com/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::vector<MockWrite> data_writes = {
      MockWrite(ASYNC, 0,
                "GET / HTTP/1.1\r\n"
                "Host: www.example.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  static constexpr char chunk1[] = "hello ";
  static constexpr char chunk2[] = "world";

  MockRead data_reads[] = {
      MockRead(ASYNC, 1, "HTTP/1.0 200 OK\r\n\r\n"),
      MockRead(ASYNC, 2, chunk1),
      MockRead(ASYNC, 3, chunk2),
      MockRead(ASYNC, OK, 4),
  };
  SequencedSocketData data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback start_cb;
  EXPECT_THAT(start_cb.GetResult(trans.Start(&request, start_cb.callback(),
                                             NetLogWithSource())),
              IsOk());

  const size_t kBufferSize = 256;

  auto buf = base::MakeRefCounted<IOBufferWithSize>(kBufferSize);
  EXPECT_THAT(trans.GetReceivedBodyBytes(), 0);

  TestCompletionCallback read_cb1;
  EXPECT_THAT(read_cb1.GetResult(
                  trans.Read(buf.get(), kBufferSize, read_cb1.callback())),
              strlen(chunk1));

  EXPECT_THAT(trans.GetReceivedBodyBytes(), strlen(chunk1));

  TestCompletionCallback read_cb2;
  EXPECT_THAT(read_cb2.GetResult(
                  trans.Read(buf.get(), kBufferSize, read_cb2.callback())),
              strlen(chunk2));

  EXPECT_THAT(trans.GetReceivedBodyBytes(), strlen(chunk1) + strlen(chunk2));

  TestCompletionCallback read_cb3;
  EXPECT_THAT(read_cb3.GetResult(
                  trans.Read(buf.get(), kBufferSize, read_cb3.callback())),
              IsOk());
  EXPECT_THAT(trans.GetReceivedBodyBytes(), strlen(chunk1) + strlen(chunk2));
}

TEST_P(HttpNetworkTransactionTest, LoadTimingMeasuresTimeToFirstByteForHttp) {
  static const base::TimeDelta kDelayAfterFirstByte = base::Milliseconds(10);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.foo.com/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::vector<MockWrite> data_writes = {
      MockWrite(ASYNC, 0,
                "GET / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  std::vector<MockRead> data_reads = {
      // Write one byte of the status line, followed by a pause.
      MockRead(ASYNC, 1, "H"),
      MockRead(ASYNC, ERR_IO_PENDING, 2),
      MockRead(ASYNC, 3, "TTP/1.1 200 OK\r\n\r\n"),
      MockRead(ASYNC, 4, "hello world"),
      MockRead(SYNCHRONOUS, OK, 5),
  };

  SequencedSocketData data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  data.RunUntilPaused();
  ASSERT_TRUE(data.IsPaused());
  FastForwardBy(kDelayAfterFirstByte);
  data.Resume();

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  EXPECT_FALSE(load_timing_info.receive_headers_start.is_null());
  EXPECT_FALSE(load_timing_info.connect_timing.connect_end.is_null());
  // Ensure we didn't include the delay in the TTFB time.
  EXPECT_EQ(load_timing_info.receive_headers_start,
            load_timing_info.connect_timing.connect_end);
  // Ensure that the mock clock advanced at all.
  EXPECT_EQ(base::TimeTicks::Now() - load_timing_info.receive_headers_start,
            kDelayAfterFirstByte);

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);
}

// Tests that the time-to-first-byte reported in a transaction's load timing
// info uses the first response, even if 1XX/informational.
void HttpNetworkTransactionTestBase::Check100ResponseTiming(bool use_spdy) {
  static const base::TimeDelta kDelayAfter100Response = base::Milliseconds(10);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.foo.com/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  std::vector<MockWrite> data_writes;
  std::vector<MockRead> data_reads;

  spdy::SpdySerializedFrame spdy_req(
      spdy_util_.ConstructSpdyGet(request.url.spec().c_str(), 1, LOWEST));

  quiche::HttpHeaderBlock spdy_resp1_headers;
  spdy_resp1_headers[spdy::kHttp2StatusHeader] = "100";
  spdy::SpdySerializedFrame spdy_resp1(
      spdy_util_.ConstructSpdyReply(1, spdy_resp1_headers.Clone()));
  spdy::SpdySerializedFrame spdy_resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame spdy_data(
      spdy_util_.ConstructSpdyDataFrame(1, "hello world", true));

  if (use_spdy) {
    ssl.next_proto = kProtoHTTP2;

    data_writes = {CreateMockWrite(spdy_req, 0)};

    data_reads = {
        CreateMockRead(spdy_resp1, 1), MockRead(ASYNC, ERR_IO_PENDING, 2),
        CreateMockRead(spdy_resp2, 3), CreateMockRead(spdy_data, 4),
        MockRead(SYNCHRONOUS, OK, 5),
    };
  } else {
    data_writes = {
        MockWrite(ASYNC, 0,
                  "GET / HTTP/1.1\r\n"
                  "Host: www.foo.com\r\n"
                  "Connection: keep-alive\r\n\r\n"),
    };

    data_reads = {
        MockRead(ASYNC, 1, "HTTP/1.1 100 Continue\r\n\r\n"),
        MockRead(ASYNC, ERR_IO_PENDING, 2),

        MockRead(ASYNC, 3, "HTTP/1.1 200 OK\r\n\r\n"),
        MockRead(ASYNC, 4, "hello world"),
        MockRead(SYNCHRONOUS, OK, 5),
    };
  }

  SequencedSocketData data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  data.RunUntilPaused();
  // We should now have parsed the 100 response and hit ERR_IO_PENDING. Insert
  // the delay before parsing the 200 response.
  ASSERT_TRUE(data.IsPaused());
  FastForwardBy(kDelayAfter100Response);
  data.Resume();

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  EXPECT_FALSE(load_timing_info.receive_headers_start.is_null());
  EXPECT_FALSE(load_timing_info.connect_timing.connect_end.is_null());
  // Ensure we didn't include the delay in the TTFB time.
  EXPECT_EQ(load_timing_info.receive_headers_start,
            load_timing_info.connect_timing.connect_end);
  // Ensure that the mock clock advanced at all.
  EXPECT_EQ(base::TimeTicks::Now() - load_timing_info.receive_headers_start,
            kDelayAfter100Response);

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);
}

TEST_P(HttpNetworkTransactionTest, MeasuresTimeToFirst100ResponseForHttp) {
  Check100ResponseTiming(false /* use_spdy */);
}

TEST_P(HttpNetworkTransactionTest, MeasuresTimeToFirst100ResponseForSpdy) {
  Check100ResponseTiming(true /* use_spdy */);
}

TEST_P(HttpNetworkTransactionTest, Incomplete100ThenEOF) {
  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.foo.com/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
      MockRead(SYNCHRONOUS, "HTTP/1.0 100 Continue\r\n"),
      MockRead(ASYNC, 0),
  };
  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("", response_data);
}

TEST_P(HttpNetworkTransactionTest, EmptyResponse) {
  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.foo.com/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
      MockRead(ASYNC, 0),
  };
  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_EMPTY_RESPONSE));
}

void HttpNetworkTransactionTestBase::KeepAliveConnectionResendRequestTest(
    const MockWrite* write_failure,
    const MockRead* read_failure) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.foo.com/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Written data for successfully sending both requests.
  MockWrite data1_writes[] = {MockWrite("GET / HTTP/1.1\r\n"
                                        "Host: www.foo.com\r\n"
                                        "Connection: keep-alive\r\n\r\n"),
                              MockWrite("GET / HTTP/1.1\r\n"
                                        "Host: www.foo.com\r\n"
                                        "Connection: keep-alive\r\n\r\n")};

  // Read results for the first request.
  MockRead data1_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"),
      MockRead("hello"),
      MockRead(ASYNC, OK),
  };

  if (write_failure) {
    ASSERT_FALSE(read_failure);
    data1_writes[1] = *write_failure;
  } else {
    ASSERT_TRUE(read_failure);
    data1_reads[2] = *read_failure;
  }

  StaticSocketDataProvider data1(data1_reads, data1_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  MockRead data2_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"),
      MockRead("world"),
      MockRead(ASYNC, OK),
  };
  StaticSocketDataProvider data2(data2_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  const char* const kExpectedResponseData[] = {"hello", "world"};

  uint32_t first_socket_log_id = NetLogSource::kInvalidId;
  for (int i = 0; i < 2; ++i) {
    TestCompletionCallback callback;

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    LoadTimingInfo load_timing_info;
    EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
    TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_DNS_TIMES);
    if (i == 0) {
      first_socket_log_id = load_timing_info.socket_log_id;
    } else {
      // The second request should be using a new socket.
      EXPECT_NE(first_socket_log_id, load_timing_info.socket_log_id);
    }

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);

    EXPECT_TRUE(response->headers);
    EXPECT_TRUE(response->proxy_chain.is_direct());
    EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

    std::string response_data;
    rv = ReadTransaction(&trans, &response_data);
    EXPECT_THAT(rv, IsOk());
    EXPECT_EQ(kExpectedResponseData[i], response_data);
  }
}

void HttpNetworkTransactionTestBase::PreconnectErrorResendRequestTest(
    const MockWrite* write_failure,
    const MockRead* read_failure,
    bool use_spdy,
    bool chunked_upload) {
  SpdyTestUtil spdy_util(/*use_priority_header=*/true);
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.foo.com/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  ChunkedUploadDataStream upload_data_stream(0);
  if (chunked_upload) {
    request.method = "POST";
    upload_data_stream.AppendData(base::byte_span_from_cstring("foobar"), true);
    request.upload_data_stream = &upload_data_stream;
  }

  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  SSLSocketDataProvider ssl1(ASYNC, OK);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  if (use_spdy) {
    ssl1.next_proto = kProtoHTTP2;
    ssl2.next_proto = kProtoHTTP2;
  }
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  // SPDY versions of the request and response.

  quiche::HttpHeaderBlock spdy_post_header_block;
  spdy_post_header_block[spdy::kHttp2MethodHeader] = "POST";
  spdy_util.AddUrlToHeaderBlock(request.url.spec(), &spdy_post_header_block);
  spdy::SpdySerializedFrame spdy_request(
      chunked_upload
          ? spdy_util.ConstructSpdyHeaders(1, std::move(spdy_post_header_block),
                                           DEFAULT_PRIORITY, false)
          : spdy_util.ConstructSpdyGet(request.url.spec().c_str(), 1,
                                       DEFAULT_PRIORITY));

  spdy::SpdySerializedFrame spdy_request_body(
      spdy_util.ConstructSpdyDataFrame(1, "foobar", true));
  spdy::SpdySerializedFrame spdy_response(
      spdy_util.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame spdy_data(
      spdy_util.ConstructSpdyDataFrame(1, "hello", true));

  // HTTP/1.1 versions of the request and response.
  const std::string http_request =
      std::string(chunked_upload ? "POST" : "GET") +
      " / HTTP/1.1\r\n"
      "Host: www.foo.com\r\n"
      "Connection: keep-alive\r\n" +
      (chunked_upload ? "Transfer-Encoding: chunked\r\n\r\n" : "\r\n");
  const char* kHttpRequest = http_request.c_str();
  const char kHttpResponse[] = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
  const char kHttpData[] = "hello";

  std::vector<MockRead> data1_reads;
  std::vector<MockWrite> data1_writes;
  if (write_failure) {
    ASSERT_FALSE(read_failure);
    data1_writes.push_back(*write_failure);
    data1_reads.emplace_back(ASYNC, OK);
  } else {
    ASSERT_TRUE(read_failure);
    if (use_spdy) {
      data1_writes.push_back(CreateMockWrite(spdy_request));
      if (chunked_upload) {
        data1_writes.push_back(CreateMockWrite(spdy_request_body));
      }
    } else {
      data1_writes.emplace_back(kHttpRequest);
      if (chunked_upload) {
        data1_writes.emplace_back("6\r\nfoobar\r\n");
        data1_writes.emplace_back("0\r\n\r\n");
      }
    }
    data1_reads.push_back(*read_failure);
  }

  StaticSocketDataProvider data1(data1_reads, data1_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  std::vector<MockRead> data2_reads;
  std::vector<MockWrite> data2_writes;

  if (use_spdy) {
    int seq = 0;
    data2_writes.push_back(CreateMockWrite(spdy_request, seq++, ASYNC));
    if (chunked_upload) {
      data2_writes.push_back(CreateMockWrite(spdy_request_body, seq++, ASYNC));
    }
    data2_reads.push_back(CreateMockRead(spdy_response, seq++, ASYNC));
    data2_reads.push_back(CreateMockRead(spdy_data, seq++, ASYNC));
    data2_reads.emplace_back(ASYNC, OK, seq++);
  } else {
    int seq = 0;
    data2_writes.emplace_back(ASYNC, kHttpRequest, strlen(kHttpRequest), seq++);
    if (chunked_upload) {
      data2_writes.emplace_back(ASYNC, "6\r\nfoobar\r\n", 11, seq++);
      data2_writes.emplace_back(ASYNC, "0\r\n\r\n", 5, seq++);
    }
    data2_reads.emplace_back(ASYNC, kHttpResponse, strlen(kHttpResponse),
                             seq++);
    data2_reads.emplace_back(ASYNC, kHttpData, strlen(kHttpData), seq++);
    data2_reads.emplace_back(ASYNC, OK, seq++);
  }
  SequencedSocketData data2(data2_reads, data2_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  // Preconnect a socket.
  session->http_stream_factory()->PreconnectStreams(1, request);
  // Wait for the preconnect to complete.
  // TODO(davidben): Some way to wait for an idle socket count might be handy.
  base::RunLoop().RunUntilIdle();
  if (use_spdy && base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    // When the HappyEyeballsV3 feature is enabled, we immediately create a SPDY
    // session, but it becomes unavailable after getting an error.
    EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));
    SpdySessionKey spdy_sesion_key(
        HostPortPair::FromURL(request.url), PRIVACY_MODE_DISABLED,
        ProxyChain::Direct(), SessionUsage::kDestination, SocketTag(),
        NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
        /*disable_cert_verification_network_fetches=*/false);
    EXPECT_FALSE(HasSpdySession(session->spdy_session_pool(), spdy_sesion_key));
  } else {
    EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));
  }

  // Make the request.
  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_DNS_TIMES |
                                                CONNECT_TIMING_HAS_SSL_TIMES);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  if (response->was_fetched_via_spdy) {
    EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  } else {
    EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  }

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ(kHttpData, response_data);
}

// Test that we do not retry indefinitely when a server sends an error like
// ERR_HTTP2_PING_FAILED, ERR_HTTP2_SERVER_REFUSED_STREAM,
// ERR_QUIC_HANDSHAKE_FAILED or ERR_QUIC_PROTOCOL_ERROR.
TEST_P(HttpNetworkTransactionTest, FiniteRetriesOnIOError) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.foo.com/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Check whether we give up after the third try.

  // Construct an HTTP2 request and a "Go away" response.
  spdy::SpdySerializedFrame spdy_request(spdy_util_.ConstructSpdyGet(
      request.url.spec().c_str(), 1, DEFAULT_PRIORITY));
  spdy::SpdySerializedFrame spdy_response_go_away(
      spdy_util_.ConstructSpdyGoAway(0));
  MockRead data_read1[] = {CreateMockRead(spdy_response_go_away)};
  MockWrite data_write[] = {CreateMockWrite(spdy_request, 0)};

  // Three go away responses.
  StaticSocketDataProvider data1(data_read1, data_write);
  StaticSocketDataProvider data2(data_read1, data_write);
  StaticSocketDataProvider data3(data_read1, data_write);

  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  AddSSLSocketData();
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  AddSSLSocketData();
  session_deps_.socket_factory->AddSocketDataProvider(&data3);
  AddSSLSocketData();

  TestCompletionCallback callback;
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_HTTP2_SERVER_REFUSED_STREAM));
}

TEST_P(HttpNetworkTransactionTest, RetryTwiceOnIOError) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.foo.com/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Check whether we try atleast thrice before giving up.

  // Construct an HTTP2 request and a "Go away" response.
  spdy::SpdySerializedFrame spdy_request(spdy_util_.ConstructSpdyGet(
      request.url.spec().c_str(), 1, DEFAULT_PRIORITY));
  spdy::SpdySerializedFrame spdy_response_go_away(
      spdy_util_.ConstructSpdyGoAway(0));
  MockRead data_read1[] = {CreateMockRead(spdy_response_go_away)};
  MockWrite data_write[] = {CreateMockWrite(spdy_request, 0)};

  // Construct a non error HTTP2 response.
  spdy::SpdySerializedFrame spdy_response_no_error(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame spdy_data(
      spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead data_read2[] = {CreateMockRead(spdy_response_no_error, 1),
                           CreateMockRead(spdy_data, 2)};

  // Two error responses.
  StaticSocketDataProvider data1(data_read1, data_write);
  StaticSocketDataProvider data2(data_read1, data_write);
  // Followed by a success response.
  SequencedSocketData data3(data_read2, data_write);

  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  AddSSLSocketData();
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  AddSSLSocketData();
  session_deps_.socket_factory->AddSocketDataProvider(&data3);
  AddSSLSocketData();

  TestCompletionCallback callback;
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
}

TEST_P(HttpNetworkTransactionTest, KeepAliveConnectionNotConnectedOnWrite) {
  MockWrite write_failure(ASYNC, ERR_SOCKET_NOT_CONNECTED);
  KeepAliveConnectionResendRequestTest(&write_failure, nullptr);
}

TEST_P(HttpNetworkTransactionTest, KeepAliveConnectionReset) {
  MockRead read_failure(ASYNC, ERR_CONNECTION_RESET);
  KeepAliveConnectionResendRequestTest(nullptr, &read_failure);
}

TEST_P(HttpNetworkTransactionTest, KeepAliveConnectionEOF) {
  MockRead read_failure(SYNCHRONOUS, OK);  // EOF
  KeepAliveConnectionResendRequestTest(nullptr, &read_failure);
}

// Make sure that on a 408 response (Request Timeout), the request is retried,
// if the socket was a reused keep alive socket.
TEST_P(HttpNetworkTransactionTest, KeepAlive408) {
  MockRead read_failure(SYNCHRONOUS,
                        "HTTP/1.1 408 Request Timeout\r\n"
                        "Connection: Keep-Alive\r\n"
                        "Content-Length: 6\r\n\r\n"
                        "Pickle");
  KeepAliveConnectionResendRequestTest(nullptr, &read_failure);
}

TEST_P(HttpNetworkTransactionTest, PreconnectErrorNotConnectedOnWrite) {
  MockWrite write_failure(ASYNC, ERR_SOCKET_NOT_CONNECTED);
  PreconnectErrorResendRequestTest(&write_failure, nullptr,
                                   false /* use_spdy */);
  PreconnectErrorResendRequestTest(
      &write_failure, nullptr, false /* use_spdy */, true /* chunked_upload */);
}

TEST_P(HttpNetworkTransactionTest, PreconnectErrorReset) {
  MockRead read_failure(ASYNC, ERR_CONNECTION_RESET);
  PreconnectErrorResendRequestTest(nullptr, &read_failure,
                                   false /* use_spdy */);
  PreconnectErrorResendRequestTest(nullptr, &read_failure, false /* use_spdy */,
                                   true /* chunked_upload */);
}

TEST_P(HttpNetworkTransactionTest, PreconnectErrorEOF) {
  MockRead read_failure(SYNCHRONOUS, OK);  // EOF
  PreconnectErrorResendRequestTest(nullptr, &read_failure,
                                   false /* use_spdy */);
  PreconnectErrorResendRequestTest(nullptr, &read_failure, false /* use_spdy */,
                                   true /* chunked_upload */);
}

TEST_P(HttpNetworkTransactionTest, PreconnectErrorAsyncEOF) {
  MockRead read_failure(ASYNC, OK);  // EOF
  PreconnectErrorResendRequestTest(nullptr, &read_failure,
                                   false /* use_spdy */);
  PreconnectErrorResendRequestTest(nullptr, &read_failure, false /* use_spdy */,
                                   true /* chunked_upload */);
}

// Make sure that on a 408 response (Request Timeout), the request is retried,
// if the socket was a preconnected (UNUSED_IDLE) socket.
TEST_P(HttpNetworkTransactionTest, RetryOnIdle408) {
  MockRead read_failure(SYNCHRONOUS,
                        "HTTP/1.1 408 Request Timeout\r\n"
                        "Connection: Keep-Alive\r\n"
                        "Content-Length: 6\r\n\r\n"
                        "Pickle");
  KeepAliveConnectionResendRequestTest(nullptr, &read_failure);
  PreconnectErrorResendRequestTest(nullptr, &read_failure,
                                   false /* use_spdy */);
  PreconnectErrorResendRequestTest(nullptr, &read_failure, false /* use_spdy */,
                                   true /* chunked_upload */);
}

TEST_P(HttpNetworkTransactionTest, SpdyPreconnectErrorNotConnectedOnWrite) {
  MockWrite write_failure(ASYNC, ERR_SOCKET_NOT_CONNECTED);
  PreconnectErrorResendRequestTest(&write_failure, nullptr,
                                   true /* use_spdy */);
  PreconnectErrorResendRequestTest(&write_failure, nullptr, true /* use_spdy */,
                                   true /* chunked_upload */);
}

TEST_P(HttpNetworkTransactionTest, SpdyPreconnectErrorReset) {
  MockRead read_failure(ASYNC, ERR_CONNECTION_RESET);
  PreconnectErrorResendRequestTest(nullptr, &read_failure, true /* use_spdy */);
  PreconnectErrorResendRequestTest(nullptr, &read_failure, true /* use_spdy */,
                                   true /* chunked_upload */);
}

TEST_P(HttpNetworkTransactionTest, SpdyPreconnectErrorEOF) {
  MockRead read_failure(SYNCHRONOUS, OK);  // EOF
  PreconnectErrorResendRequestTest(nullptr, &read_failure, true /* use_spdy */);
  PreconnectErrorResendRequestTest(nullptr, &read_failure, true /* use_spdy */,
                                   true /* chunked_upload */);
}

TEST_P(HttpNetworkTransactionTest, SpdyPreconnectErrorAsyncEOF) {
  MockRead read_failure(ASYNC, OK);  // EOF
  PreconnectErrorResendRequestTest(nullptr, &read_failure, true /* use_spdy */);
  PreconnectErrorResendRequestTest(nullptr, &read_failure, true /* use_spdy */,
                                   true /* chunked_upload */);
}

TEST_P(HttpNetworkTransactionTest, NonKeepAliveConnectionReset) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
      MockRead(ASYNC, ERR_CONNECTION_RESET),
      MockRead("HTTP/1.0 200 OK\r\n\r\n"),  // Should not be used
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));

  IPEndPoint endpoint;
  EXPECT_TRUE(trans.GetRemoteEndpoint(&endpoint));
  EXPECT_LT(0u, endpoint.address().size());
}

// What do various browsers do when the server closes a non-keepalive
// connection without sending any response header or body?
//
// IE7: error page
// Safari 3.1.2 (Windows): error page
// Firefox 3.0.1: blank page
// Opera 9.52: after five attempts, blank page
// Us with WinHTTP: error page (ERR_INVALID_RESPONSE)
// Us: error page (EMPTY_RESPONSE)
TEST_P(HttpNetworkTransactionTest, NonKeepAliveConnectionEOF) {
  MockRead data_reads[] = {
      MockRead(SYNCHRONOUS, OK),            // EOF
      MockRead("HTTP/1.0 200 OK\r\n\r\n"),  // Should not be used
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads);
  EXPECT_THAT(out.rv, IsError(ERR_EMPTY_RESPONSE));
}

// Next 2 cases (KeepAliveEarlyClose and KeepAliveEarlyClose2) are regression
// tests. There was a bug causing HttpNetworkTransaction to hang in the
// destructor in such situations.
// See http://crbug.com/154712 and http://crbug.com/156609.
TEST_P(HttpNetworkTransactionTest, KeepAliveEarlyClose) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Connection: keep-alive\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead("hello"),
      MockRead(SYNCHRONOUS, 0),
  };
  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  scoped_refptr<IOBufferWithSize> io_buf =
      base::MakeRefCounted<IOBufferWithSize>(100);
  rv = trans->Read(io_buf.get(), io_buf->size(), callback.callback());
  if (rv == ERR_IO_PENDING) {
    rv = callback.WaitForResult();
  }
  EXPECT_EQ(5, rv);
  rv = trans->Read(io_buf.get(), io_buf->size(), callback.callback());
  EXPECT_THAT(rv, IsError(ERR_CONTENT_LENGTH_MISMATCH));

  trans.reset();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));
}

TEST_P(HttpNetworkTransactionTest, KeepAliveEarlyClose2) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> sess
```