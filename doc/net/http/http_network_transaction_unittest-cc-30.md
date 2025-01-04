Response:
The user wants a summary of the functionality of the provided C++ code snippet from `http_network_transaction_unittest.cc`. They are also interested in:

1. **Relationship to JavaScript:** Does this code interact with or relate to JavaScript functionality?
2. **Logical Inferences (with examples):** If the code performs logical operations, provide examples of inputs and expected outputs.
3. **Common User/Programming Errors (with examples):** Identify potential mistakes users or developers might make when interacting with this code or the system it tests.
4. **User Actions as Debugging Clues:** Explain how a user's actions might lead to the execution of this code, aiding in debugging.
5. **Overall Functionality (Part 31/34):**  Summarize the primary purpose of this specific code block, considering its context within the larger file.

**Analysis of the Code Snippet:**

The code snippet consists of several C++ unit tests using the Google Test framework. These tests are designed to verify the behavior of `HttpNetworkTransaction` in various scenarios, particularly related to:

* **Network Error Logging (NEL):**  A test case specifically checks if a network error is correctly reported by the `NetworkErrorLoggingService`.
* **Cache Interactions:** A test verifies that requests intended to load only from the cache correctly fail if the resource isn't present.
* **TLS Zero Round Trip Time (0-RTT):** Several tests focus on the behavior of 0-RTT connections, including:
    *  Verifying that `ConfirmHandshake` is not called unnecessarily.
    *  Testing different combinations of synchronous and asynchronous operations during the 0-RTT handshake.
    *  Handling 0-RTT rejection scenarios and subsequent retries.
    *  Testing error conditions during the 0-RTT confirmation.
* **Authentication (TLS Client Certificates and HTTP Auth):**  Tests simulate complex authentication scenarios involving both proxy and origin servers requesting TLS client certificates and HTTP authentication, including cases where connections are closed after authentication challenges.

**Planning the Response:**

1. **Summarize Functionality:** Focus on the main themes of the tests: NEL, cache, 0-RTT, and authentication.
2. **JavaScript Relationship:** Explain that while this C++ code is part of the Chromium network stack, it doesn't directly execute JavaScript. However, its proper functioning is crucial for web browsing and therefore indirectly affects how JavaScript executes within web pages. Provide an example of how a JavaScript fetch request might rely on the underlying network mechanisms tested here.
3. **Logical Inferences:**  For the 0-RTT tests, describe how the success or failure of `ConfirmHandshake` influences the timing and whether early data is used. For the authentication tests, outline the flow of challenges and responses. Provide hypothetical scenarios with clear inputs (e.g., server responses, client configurations) and outputs (e.g., transaction success/failure, specific error codes).
4. **User/Programming Errors:**  Focus on common misconfigurations or incorrect usage of networking APIs or test setups. Examples include incorrect mock data, failing to handle asynchronous operations correctly, or misinterpreting error codes related to caching or authentication.
5. **User Actions as Debugging Clues:**  Relate user actions (e.g., visiting a website, submitting a form) to the underlying network requests and how these tests could help diagnose issues.
6. **Overall Functionality (Part 31/34):** Emphasize that this part of the test suite is specifically focused on testing the robustness and correctness of `HttpNetworkTransaction` in advanced scenarios like 0-RTT and complex authentication flows.
这个C++源代码文件 `http_network_transaction_unittest.cc` 的主要功能是**对 Chromium 网络栈中的 `HttpNetworkTransaction` 类进行单元测试**。 `HttpNetworkTransaction` 是 Chromium 中处理 HTTP 网络请求的核心类之一。

这个文件中的具体代码片段（第31部分）侧重于测试 `HttpNetworkTransaction` 在以下几个方面的行为：

1. **网络错误日志 (Network Error Logging - NEL)：**
   - 测试当请求过程中发生错误并触发 NEL 报告时，`HttpNetworkTransaction` 是否能正确记录错误信息，包括错误码和发生时间。
   - **假设输入与输出：**
     - **假设输入：** 一个 HTTP 请求被发送，并且在接收响应头后、接收响应体之前，模拟了一个网络延迟（`kSleepDuration`）。服务器最终返回 200 OK 和一些数据。
     - **输出：** NEL 服务会记录一个错误报告，其中包含状态码 200（因为收到了响应头），错误码 OK（因为最终成功接收数据），以及 `elapsed_time` 接近模拟的延迟 `kSleepDuration`。

2. **缓存 (Cache) 的使用：**
   - 测试当请求的 `load_flags` 被设置为 `LOAD_ONLY_FROM_CACHE` 时，如果缓存中不存在对应的资源，`HttpNetworkTransaction` 是否会返回 `ERR_CACHE_MISS` 错误。
   - **假设输入与输出：**
     - **假设输入：** 创建一个 `HttpRequestInfo` 对象，设置 `load_flags` 为 `LOAD_ONLY_FROM_CACHE`，并请求一个已知不在缓存中的 URL。
     - **输出：** `trans->Start()` 方法会返回 `ERR_CACHE_MISS` 错误。

3. **TLS 零往返时间 (0-RTT)：**
   - 测试 `HttpNetworkTransaction` 在 TLS 0-RTT 场景下的行为，包括：
     - **不确认 (Doesn't Confirm)：** 验证在某些情况下（例如，GET 请求），即使启用了 0-RTT，也不会调用 `ConfirmHandshake`。
     - **同步确认和同步写入 (Sync Confirm Sync Write)：** 测试在 0-RTT 中，当 `ConfirmHandshake` 和请求体写入都是同步操作时，请求是否能正确完成。
     - **同步确认和异步写入 (Sync Confirm Async Write)：** 测试当 `ConfirmHandshake` 是同步的，但请求体写入是异步的时，请求是否能正确完成。
     - **异步确认和同步写入 (Async Confirm Sync Write)：** 测试当 `ConfirmHandshake` 是异步的，但请求体写入是同步的时，请求是否能正确完成。
     - **异步确认和异步写入 (Async Confirm Async Write)：** 测试当 `ConfirmHandshake` 和请求体写入都是异步操作时，请求是否能正确完成。
     - **0-RTT 拒绝 (Reject)：** 测试当服务器拒绝 0-RTT 连接时（例如，发送 `ERR_EARLY_DATA_REJECTED`），`HttpNetworkTransaction` 是否能正确处理并尝试重试。
       - **假设输入与输出：**
         - **假设输入：** 发送一个启用 0-RTT 的请求，模拟服务器在读取或写入早期数据时返回 `ERR_EARLY_DATA_REJECTED`。
         - **输出：** 第一次请求会失败，但 `HttpNetworkTransaction` 会自动发起一个新的、非 0-RTT 的请求，并且这个新的请求会成功。
     - **确认错误 (Confirm Error)：** 测试当 `ConfirmHandshake` 返回错误时（同步或异步），`HttpNetworkTransaction` 是否会返回相应的错误。
       - **假设输入与输出：**
         - **假设输入：** 发送一个启用 0-RTT 的请求，并模拟 `ConfirmHandshake` 同步或异步地返回 `ERR_SSL_PROTOCOL_ERROR`。
         - **输出：** `trans->Start()` 方法最终会返回 `ERR_SSL_PROTOCOL_ERROR` 错误。

4. **复杂的身份验证场景 (Authentication)：**
   - 测试当代理服务器和源服务器都需要 TLS 客户端证书和 HTTP 身份验证时，`HttpNetworkTransaction` 是否能正确处理所有身份验证挑战。
   - 测试在身份验证过程中连接被关闭的情况。
   - **假设输入与输出：**
     - **假设输入：** 发送一个 HTTPS 请求，经过需要客户端证书和 HTTP Basic 认证的代理，最终访问一个也需要客户端证书和 HTTP Basic 认证的源服务器。提供相应的证书和用户名密码。
     - **输出：** `HttpNetworkTransaction` 会多次返回需要证书或身份验证的错误码，开发者通过 `RestartWithCertificate` 和 `RestartWithAuth` 方法提供证书和凭据，最终请求成功并返回 200 OK。

**与 JavaScript 的关系：**

`HttpNetworkTransaction` 类本身是用 C++ 编写的，直接运行在 Chromium 的网络进程中，**不直接执行 JavaScript 代码**。然而，它的功能对于 JavaScript 发起的网络请求至关重要。

**举例说明：**

当网页中的 JavaScript 代码使用 `fetch()` API 发起一个 HTTP 请求时，Chromium 浏览器内部会创建并使用一个 `HttpNetworkTransaction` 对象来处理这个请求。`HttpNetworkTransaction` 负责建立连接、发送请求头、处理重定向、处理身份验证、接收响应等。如果 `HttpNetworkTransaction` 的行为不正确（例如，在 0-RTT 场景下出错，或者无法正确处理身份验证），那么 JavaScript 的 `fetch()` 调用最终会失败或返回错误的结果，影响网页的功能。

**用户操作如何到达这里（作为调试线索）：**

用户操作导致执行到 `HttpNetworkTransaction` 的场景非常广泛，几乎所有涉及网络请求的操作都可能触发。以下是一些例子：

1. **在地址栏中输入网址并回车：** 这会创建一个新的导航请求，并可能导致 `HttpNetworkTransaction` 处理主文档的请求。
2. **点击网页上的链接：** 类似于地址栏输入，也会发起新的请求。
3. **网页中的 JavaScript 代码发起 `fetch()` 或 `XMLHttpRequest` 调用：** 这是最常见的触发场景，例如加载图片、AJAX 请求等。
4. **浏览器后台进行的网络操作：** 例如同步书签、更新扩展、安全检查等。
5. **在需要客户端证书的网站进行身份验证：** 这会触发与客户端证书相关的测试用例。
6. **访问需要 HTTP 身份验证的网站或资源：** 这会触发与 HTTP 身份验证相关的测试用例。
7. **访问启用了 TLS 1.3 和 0-RTT 的网站：** 这会触发与 0-RTT 相关的测试用例。
8. **通过配置了代理服务器的网络环境访问 HTTPS 网站：** 这会触发涉及代理身份验证和客户端证书的测试用例。

**作为调试线索，如果开发者遇到以下问题，可以考虑 `HttpNetworkTransaction` 的行为：**

* **网络请求失败或超时。**
* **TLS 连接建立失败或出现错误。**
* **客户端证书选择或使用出现问题。**
* **HTTP 身份验证失败或循环重定向。**
* **在支持 0-RTT 的环境下，请求性能不如预期或出现连接错误。**

**第 31 部分的功能归纳：**

这个代码片段（第31部分）主要专注于测试 `HttpNetworkTransaction` 类在处理 **NEL 报告、缓存策略、TLS 0-RTT 机制以及复杂的身份验证流程**时的正确性和健壮性。它覆盖了 0-RTT 的不同操作模式、拒绝场景和错误处理，以及涉及代理和源服务器的双重客户端证书和 HTTP 身份验证的复杂情况。 这些测试用例旨在确保 `HttpNetworkTransaction` 能够可靠地处理各种复杂的网络场景，为上层应用（包括 JavaScript 代码发起的请求）提供稳定的网络服务。

Prompt: 
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第31部分，共34部分，请归纳一下它的功能

"""
ckRead> data_reads = {
      // Write one byte of the status line, followed by a pause.
      MockRead(ASYNC, 2, "H"),
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      MockRead(ASYNC, 4, "TTP/1.1 200 OK\r\n\r\n"),
      MockRead(ASYNC, 5, "hello world"),
      MockRead(SYNCHRONOUS, OK, 6),
  };

  SequencedSocketData data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;

  int rv = trans->Start(&request_, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  data.RunUntilPaused();
  ASSERT_TRUE(data.IsPaused());
  FastForwardBy(kSleepDuration);
  data.Resume();

  EXPECT_THAT(callback.GetResult(rv), IsOk());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  trans.reset();

  ASSERT_EQ(1u, network_error_logging_service()->errors().size());

  CheckReport(0 /* index */, 200 /* status_code */, OK);

  const NetworkErrorLoggingService::RequestDetails& error =
      network_error_logging_service()->errors()[0];

  // Sanity-check elapsed time in error report
  EXPECT_EQ(kSleepDuration, error.elapsed_time);
}

#endif  // BUILDFLAG(ENABLE_REPORTING)

TEST_P(HttpNetworkTransactionTest, AlwaysFailRequestToCache) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://example.org/");

  request.load_flags = LOAD_ONLY_FROM_CACHE;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback1;
  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());

  EXPECT_THAT(rv, IsError(ERR_CACHE_MISS));
}

TEST_P(HttpNetworkTransactionTest, ZeroRTTDoesntConfirm) {
  static const base::TimeDelta kDelay = base::Milliseconds(10);
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 1\r\n\r\n"),
      MockRead(SYNCHRONOUS, "1"),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(SYNCHRONOUS, OK);
  ssl.connect_callback = FastForwardByCallback(kDelay);
  ssl.confirm = MockConfirm(SYNCHRONOUS, OK);
  ssl.confirm_callback = FastForwardByCallback(kDelay);
  session_deps_.enable_early_data = true;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  TestCompletionCallback callback;
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  base::TimeTicks start_time = base::TimeTicks::Now();
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(1, response->headers->GetContentLength());

  // Check that ConfirmHandshake wasn't called.
  ASSERT_FALSE(ssl.ConfirmDataConsumed());
  ASSERT_TRUE(ssl.WriteBeforeConfirm());

  // The handshake time should include the time it took to run Connect(), but
  // not ConfirmHandshake().
  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
  EXPECT_EQ(load_timing_info.connect_timing.connect_start, start_time);
  EXPECT_EQ(load_timing_info.connect_timing.ssl_start, start_time);
  EXPECT_EQ(load_timing_info.connect_timing.ssl_end, start_time + kDelay);
  EXPECT_EQ(load_timing_info.connect_timing.connect_end, start_time + kDelay);

  trans.reset();

  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

TEST_P(HttpNetworkTransactionTest, ZeroRTTSyncConfirmSyncWrite) {
  static const base::TimeDelta kDelay = base::Milliseconds(10);
  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite data_writes[] = {
      MockWrite(SYNCHRONOUS,
                "POST / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 0\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 1\r\n\r\n"),
      MockRead(SYNCHRONOUS, "1"),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(SYNCHRONOUS, OK);
  ssl.connect_callback = FastForwardByCallback(kDelay);
  ssl.confirm = MockConfirm(SYNCHRONOUS, OK);
  ssl.confirm_callback = FastForwardByCallback(kDelay);
  session_deps_.enable_early_data = true;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  TestCompletionCallback callback;
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  base::TimeTicks start_time = base::TimeTicks::Now();
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(1, response->headers->GetContentLength());

  // Check that the Write didn't get called before ConfirmHandshake completed.
  ASSERT_FALSE(ssl.WriteBeforeConfirm());

  // The handshake time should include the time it took to run Connect(), but
  // not ConfirmHandshake(). If ConfirmHandshake() returns synchronously, we
  // assume the connection did not negotiate 0-RTT or the handshake was already
  // confirmed.
  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
  EXPECT_EQ(load_timing_info.connect_timing.connect_start, start_time);
  EXPECT_EQ(load_timing_info.connect_timing.ssl_start, start_time);
  EXPECT_EQ(load_timing_info.connect_timing.ssl_end, start_time + kDelay);
  EXPECT_EQ(load_timing_info.connect_timing.connect_end, start_time + kDelay);

  trans.reset();

  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

TEST_P(HttpNetworkTransactionTest, ZeroRTTSyncConfirmAsyncWrite) {
  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite data_writes[] = {
      MockWrite(ASYNC,
                "POST / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 0\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 1\r\n\r\n"),
      MockRead(SYNCHRONOUS, "1"),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(SYNCHRONOUS, OK);
  ssl.confirm = MockConfirm(SYNCHRONOUS, OK);
  session_deps_.enable_early_data = true;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  TestCompletionCallback callback;
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(1, response->headers->GetContentLength());

  // Check that the Write didn't get called before ConfirmHandshake completed.
  ASSERT_FALSE(ssl.WriteBeforeConfirm());

  trans.reset();

  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

TEST_P(HttpNetworkTransactionTest, ZeroRTTAsyncConfirmSyncWrite) {
  static const base::TimeDelta kDelay = base::Milliseconds(10);
  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite data_writes[] = {
      MockWrite(SYNCHRONOUS,
                "POST / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 0\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 1\r\n\r\n"),
      MockRead(SYNCHRONOUS, "1"),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(SYNCHRONOUS, OK);
  ssl.connect_callback = FastForwardByCallback(kDelay);
  ssl.confirm = MockConfirm(ASYNC, OK);
  ssl.confirm_callback = FastForwardByCallback(kDelay);
  session_deps_.enable_early_data = true;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  TestCompletionCallback callback;
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  base::TimeTicks start_time = base::TimeTicks::Now();
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(1, response->headers->GetContentLength());

  // Check that the Write didn't get called before ConfirmHandshake completed.
  ASSERT_FALSE(ssl.WriteBeforeConfirm());

  // The handshake time should include the time it took to run Connect() and
  // ConfirmHandshake().
  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
  EXPECT_EQ(load_timing_info.connect_timing.connect_start, start_time);
  EXPECT_EQ(load_timing_info.connect_timing.ssl_start, start_time);
  EXPECT_EQ(load_timing_info.connect_timing.ssl_end, start_time + 2 * kDelay);
  EXPECT_EQ(load_timing_info.connect_timing.connect_end,
            start_time + 2 * kDelay);

  trans.reset();

  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

TEST_P(HttpNetworkTransactionTest, ZeroRTTAsyncConfirmAsyncWrite) {
  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite data_writes[] = {
      MockWrite(ASYNC,
                "POST / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 0\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 1\r\n\r\n"),
      MockRead(SYNCHRONOUS, "1"),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(SYNCHRONOUS, OK);
  ssl.confirm = MockConfirm(ASYNC, OK);
  session_deps_.enable_early_data = true;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  TestCompletionCallback callback;
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(1, response->headers->GetContentLength());

  // Check that the Write didn't get called before ConfirmHandshake completed.
  ASSERT_FALSE(ssl.WriteBeforeConfirm());

  trans.reset();

  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

// 0-RTT rejects are handled at HttpNetworkTransaction.
TEST_P(HttpNetworkTransactionTest, ZeroRTTReject) {
  enum class RejectType {
    kRead,
    kWrite,
    kConfirm,
  };

  for (RejectType type :
       {RejectType::kRead, RejectType::kWrite, RejectType::kConfirm}) {
    SCOPED_TRACE(static_cast<int>(type));
    for (Error reject_error :
         {ERR_EARLY_DATA_REJECTED, ERR_WRONG_VERSION_ON_EARLY_DATA}) {
      SCOPED_TRACE(reject_error);
      session_deps_.socket_factory =
          std::make_unique<MockClientSocketFactory>();

      HttpRequestInfo request;
      request.method = type == RejectType::kConfirm ? "POST" : "GET";
      request.url = GURL("https://www.example.org/");
      request.traffic_annotation =
          MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

      // The first request fails.
      std::vector<MockWrite> data1_writes;
      std::vector<MockRead> data1_reads;
      SSLSocketDataProvider ssl1(SYNCHRONOUS, OK);
      switch (type) {
        case RejectType::kRead:
          data1_writes.emplace_back(
              "GET / HTTP/1.1\r\n"
              "Host: www.example.org\r\n"
              "Connection: keep-alive\r\n\r\n");
          data1_reads.emplace_back(ASYNC, reject_error);
          // Cause ConfirmHandshake to hang (it should not be called).
          ssl1.confirm = MockConfirm(SYNCHRONOUS, ERR_IO_PENDING);
          break;
        case RejectType::kWrite:
          data1_writes.emplace_back(ASYNC, reject_error);
          // Cause ConfirmHandshake to hang (it should not be called).
          ssl1.confirm = MockConfirm(SYNCHRONOUS, ERR_IO_PENDING);
          break;
        case RejectType::kConfirm:
          // The request never gets far enough to read or write.
          ssl1.confirm = MockConfirm(ASYNC, reject_error);
          break;
      }

      StaticSocketDataProvider data1(data1_reads, data1_writes);
      session_deps_.socket_factory->AddSocketDataProvider(&data1);
      session_deps_.enable_early_data = true;
      session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);

      // The retry succeeds.
      //
      // TODO(crbug.com/41451775): If |reject_error| is
      // ERR_EARLY_DATA_REJECTED, the retry should happen over the same socket.
      MockWrite data2_writes[] = {
          request.method == "POST"
              ? MockWrite("POST / HTTP/1.1\r\n"
                          "Host: www.example.org\r\n"
                          "Connection: keep-alive\r\n"
                          "Content-Length: 0\r\n\r\n")
              : MockWrite("GET / HTTP/1.1\r\n"
                          "Host: www.example.org\r\n"
                          "Connection: keep-alive\r\n\r\n"),
      };

      MockRead data2_reads[] = {
          MockRead("HTTP/1.1 200 OK\r\n"),
          MockRead("Content-Length: 1\r\n\r\n"),
          MockRead(SYNCHRONOUS, "1"),
      };

      StaticSocketDataProvider data2(data2_reads, data2_writes);
      session_deps_.socket_factory->AddSocketDataProvider(&data2);
      SSLSocketDataProvider ssl2(SYNCHRONOUS, OK);
      ssl2.confirm = MockConfirm(ASYNC, OK);
      session_deps_.enable_early_data = true;
      session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

      std::unique_ptr<HttpNetworkSession> session(
          CreateSession(&session_deps_));

      TestCompletionCallback callback;
      auto trans = std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY,
                                                            session.get());

      EXPECT_THAT(callback.GetResult(trans->Start(&request, callback.callback(),
                                                  NetLogWithSource())),
                  IsOk());

      const HttpResponseInfo* response = trans->GetResponseInfo();
      ASSERT_TRUE(response);
      ASSERT_TRUE(response->headers);
      EXPECT_EQ(200, response->headers->response_code());
      EXPECT_EQ(1, response->headers->GetContentLength());
    }
  }
}

TEST_P(HttpNetworkTransactionTest, ZeroRTTConfirmErrorSync) {
  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 0\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 1\r\n\r\n"),
      MockRead(SYNCHRONOUS, "1"),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(SYNCHRONOUS, OK);
  ssl.confirm = MockConfirm(SYNCHRONOUS, ERR_SSL_PROTOCOL_ERROR);
  session_deps_.enable_early_data = true;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  TestCompletionCallback callback;
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_SSL_PROTOCOL_ERROR));

  // Check that the Write didn't get called before ConfirmHandshake completed.
  ASSERT_FALSE(ssl.WriteBeforeConfirm());

  trans.reset();

  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

TEST_P(HttpNetworkTransactionTest, ZeroRTTConfirmErrorAsync) {
  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 0\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 1\r\n\r\n"),
      MockRead(SYNCHRONOUS, "1"),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(SYNCHRONOUS, OK);
  ssl.confirm = MockConfirm(ASYNC, ERR_SSL_PROTOCOL_ERROR);
  session_deps_.enable_early_data = true;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  TestCompletionCallback callback;
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_SSL_PROTOCOL_ERROR));

  // Check that the Write didn't get called before ConfirmHandshake completed.
  ASSERT_FALSE(ssl.WriteBeforeConfirm());

  trans.reset();

  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

// Test the proxy and origin server each requesting both TLS client certificates
// and HTTP auth. This is a regression test for https://crbug.com/946406.
TEST_P(HttpNetworkTransactionTest, AuthEverything) {
  // Note these hosts must match the CheckBasic*Auth() functions.
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);

  auto cert_request_info_proxy = base::MakeRefCounted<SSLCertRequestInfo>();
  cert_request_info_proxy->host_and_port = HostPortPair("myproxy", 70);

  std::unique_ptr<FakeClientCertIdentity> identity_proxy =
      FakeClientCertIdentity::CreateFromCertAndKeyFiles(
          GetTestCertsDirectory(), "client_1.pem", "client_1.pk8");
  ASSERT_TRUE(identity_proxy);

  auto cert_request_info_origin = base::MakeRefCounted<SSLCertRequestInfo>();
  cert_request_info_origin->host_and_port =
      HostPortPair("www.example.org", 443);

  std::unique_ptr<FakeClientCertIdentity> identity_origin =
      FakeClientCertIdentity::CreateFromCertAndKeyFiles(
          GetTestCertsDirectory(), "client_2.pem", "client_2.pk8");
  ASSERT_TRUE(identity_origin);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // First, the client connects to the proxy, which requests a client
  // certificate.
  SSLSocketDataProvider ssl_proxy1(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  ssl_proxy1.cert_request_info = cert_request_info_proxy;
  ssl_proxy1.expected_send_client_cert = false;
  StaticSocketDataProvider data1;
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_proxy1);

  // The client responds with a certificate on a new connection. The handshake
  // succeeds.
  SSLSocketDataProvider ssl_proxy2(ASYNC, OK);
  ssl_proxy2.expected_send_client_cert = true;
  ssl_proxy2.expected_client_cert = identity_proxy->certificate();
  // The client attempts an HTTP CONNECT, but the proxy requests basic auth.
  std::vector<MockWrite> mock_writes2;
  std::vector<MockRead> mock_reads2;
  mock_writes2.emplace_back(
      "CONNECT www.example.org:443 HTTP/1.1\r\n"
      "Host: www.example.org:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n\r\n");
  mock_reads2.emplace_back(
      "HTTP/1.1 407 Proxy Authentication Required\r\n"
      "Content-Length: 0\r\n"
      "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n\r\n");
  // The client retries with credentials.
  mock_writes2.emplace_back(
      "CONNECT www.example.org:443 HTTP/1.1\r\n"
      "Host: www.example.org:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n"
      // Authenticate as proxyuser:proxypass.
      "Proxy-Authorization: Basic cHJveHl1c2VyOnByb3h5cGFzcw==\r\n\r\n");
  mock_reads2.emplace_back("HTTP/1.1 200 Connection Established\r\n\r\n");
  // The origin requests client certificates.
  SSLSocketDataProvider ssl_origin2(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  ssl_origin2.cert_request_info = cert_request_info_origin;
  StaticSocketDataProvider data2(mock_reads2, mock_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_proxy2);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_origin2);

  // The client responds to the origin client certificate request on a new
  // connection.
  SSLSocketDataProvider ssl_proxy3(ASYNC, OK);
  ssl_proxy3.expected_send_client_cert = true;
  ssl_proxy3.expected_client_cert = identity_proxy->certificate();
  std::vector<MockWrite> mock_writes3;
  std::vector<MockRead> mock_reads3;
  mock_writes3.emplace_back(
      "CONNECT www.example.org:443 HTTP/1.1\r\n"
      "Host: www.example.org:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n"
      // Authenticate as proxyuser:proxypass.
      "Proxy-Authorization: Basic cHJveHl1c2VyOnByb3h5cGFzcw==\r\n\r\n");
  mock_reads3.emplace_back("HTTP/1.1 200 Connection Established\r\n\r\n");
  SSLSocketDataProvider ssl_origin3(ASYNC, OK);
  ssl_origin3.expected_send_client_cert = true;
  ssl_origin3.expected_client_cert = identity_origin->certificate();
  // The client sends the origin HTTP request, which results in another HTTP
  // auth request.
  mock_writes3.emplace_back(
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n\r\n");
  mock_reads3.emplace_back(
      "HTTP/1.1 401 Unauthorized\r\n"
      "WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"
      "Content-Length: 0\r\n\r\n");
  // The client retries with credentials, and the request finally succeeds.
  mock_writes3.emplace_back(
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n"
      // Authenticate as user:pass.
      "Authorization: Basic dXNlcjpwYXNz\r\n\r\n");
  mock_reads3.emplace_back(
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 0\r\n\r\n");
  // The client makes another request. This should reuse the socket with all
  // credentials cached.
  mock_writes3.emplace_back(
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n"
      // Authenticate as user:pass.
      "Authorization: Basic dXNlcjpwYXNz\r\n\r\n");
  mock_reads3.emplace_back(
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 0\r\n\r\n");
  StaticSocketDataProvider data3(mock_reads3, mock_writes3);
  session_deps_.socket_factory->AddSocketDataProvider(&data3);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_proxy3);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_origin3);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Start the request.
  TestCompletionCallback callback;
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = callback.GetResult(
      trans->Start(&request, callback.callback(), NetLogWithSource()));

  // Handle the proxy client certificate challenge.
  ASSERT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));
  SSLCertRequestInfo* cert_request_info =
      trans->GetResponseInfo()->cert_request_info.get();
  ASSERT_TRUE(cert_request_info);
  EXPECT_TRUE(cert_request_info->is_proxy);
  EXPECT_EQ(cert_request_info->host_and_port,
            cert_request_info_proxy->host_and_port);
  rv = callback.GetResult(trans->RestartWithCertificate(
      identity_proxy->certificate(), identity_proxy->ssl_private_key(),
      callback.callback()));

  // Handle the proxy HTTP auth challenge.
  ASSERT_THAT(rv, IsOk());
  EXPECT_EQ(407, trans->GetResponseInfo()->headers->response_code());
  EXPECT_TRUE(
      CheckBasicSecureProxyAuth(trans->GetResponseInfo()->auth_challenge));
  rv = callback.GetResult(trans->RestartWithAuth(
      AuthCredentials(u"proxyuser", u"proxypass"), callback.callback()));

  // Handle the origin client certificate challenge.
  ASSERT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));
  cert_request_info = trans->GetResponseInfo()->cert_request_info.get();
  ASSERT_TRUE(cert_request_info);
  EXPECT_FALSE(cert_request_info->is_proxy);
  EXPECT_EQ(cert_request_info->host_and_port,
            cert_request_info_origin->host_and_port);
  rv = callback.GetResult(trans->RestartWithCertificate(
      identity_origin->certificate(), identity_origin->ssl_private_key(),
      callback.callback()));

  // Handle the origin HTTP auth challenge.
  ASSERT_THAT(rv, IsOk());
  EXPECT_EQ(401, trans->GetResponseInfo()->headers->response_code());
  EXPECT_TRUE(
      CheckBasicSecureServerAuth(trans->GetResponseInfo()->auth_challenge));
  rv = callback.GetResult(trans->RestartWithAuth(
      AuthCredentials(u"user", u"pass"), callback.callback()));

  // The request completes.
  ASSERT_THAT(rv, IsOk());
  EXPECT_EQ(200, trans->GetResponseInfo()->headers->response_code());

  // Make a second request. This time all credentials are cached.
  trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  ASSERT_THAT(callback.GetResult(trans->Start(&request, callback.callback(),
                                              NetLogWithSource())),
              IsOk());
  EXPECT_EQ(200, trans->GetResponseInfo()->headers->response_code());
}

// Test the proxy and origin server each requesting both TLS client certificates
// and HTTP auth and each HTTP auth closing the connection. This is a regression
// test for https://crbug.com/946406.
TEST_P(HttpNetworkTransactionTest, AuthEverythingWithConnectClose) {
  // Note these hosts must match the CheckBasic*Auth() functions.
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);

  auto cert_request_info_proxy = base::MakeRefCounted<SSLCertRequestInfo>();
  cert_request_info_proxy->host_and_port = HostPortPair("myproxy", 70);

  std::unique_ptr<FakeClientCertIdentity> identity_proxy =
      FakeClientCertIdentity::CreateFromCertAndKeyFiles(
          GetTestCertsDirectory(), "client_1.pem", "client_1.pk8");
  ASSERT_TRUE(identity_proxy);

  auto cert_request_info_origin = base::MakeRefCounted<SSLCertRequestInfo>();
  cert_request_info_origin->host_and_port =
      HostPortPair("www.example.org", 443);

  std::unique_ptr<FakeClientCertIdentity> identity_origin =
      FakeClientCertIdentity::CreateFromCertAndKeyFiles(
          GetTestCertsDirectory(), "client_2.pem", "client_2.pk8");
  ASSERT_TRUE(identity_origin);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // First, the client connects to the proxy, which requests a client
  // certificate.
  SSLSocketDataProvider ssl_proxy1(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  ssl_proxy1.cert_request_info = cert_request_info_proxy;
  ssl_proxy1.expected_send_client_cert = false;
  StaticSocketDataProvider data1;
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_proxy1);

  // The client responds with a certificate on a new connection. The handshake
  // succeeds.
  SSLSocketDataProvider ssl_proxy2(ASYNC, OK);
  ssl_proxy2.expected_send_client_cert = true;
  ssl_proxy2.expected_client_cert = identity_proxy->certificate();
  // The client attempts an HTTP CONNECT, but the proxy requests basic auth.
  std::vector<MockWrite> mock_writes2;
  std::vector<MockRead> mock_reads2;
  mock_writes2.emplace_back(
      "CONNECT www.example.org:443 HTTP/1.1\r\n"
      "Host: www.example.org:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n\r\n");
  mock_reads2.emplace_back(
      "HTTP/1.1 407 Proxy Authentication Required\r\n"
      "Content-Length: 0\r\n"
      "Proxy-Connection: close\r\n"
      "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n\r\n");
  StaticSocketDataProvider data2(mock_reads2, mock_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_proxy2);

  // The client retries with credentials on a new connection.
  SSLSocketDataProvider ssl_proxy3(ASYNC, OK);
  ssl_proxy3.expected_send_client_cert = true;
  ssl_proxy3.expected_client_cert = identity_proxy->certificate();
  std::vector<MockWrite> mock_writes3;
  std::vector<MockRead> mock_reads3;
  mock_writes3.emplace_back(
      "CONNECT www.example.org:443 HTTP/1.1\r\n"
      "Host: www.example.org:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n"
      // Authenticate as proxyuser:proxypass.
      "Proxy-Authorization: Basic cHJveHl1c2VyOnByb3h5cGFzcw==\r\n\r\n");
  mock_reads3.emplace_back("HTTP/1.1 200 Connection Established\r\n\r\n");
  // The origin requests client certificates.
  SSLSocketDataProvider ssl_origin3(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  ssl_origin3.cert_request_info = cert_request_info_origin;
 
"""


```