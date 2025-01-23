Response:
The user wants me to analyze a C++ source code file related to network transactions in Chromium.
I need to extract the functionalities demonstrated in the provided code snippet and explain them.
If there are connections to Javascript, I need to illustrate them.
For any logical deductions, I need to provide hypothetical inputs and outputs.
I should highlight common user or programming errors with examples.
I also need to explain how a user action can lead to this code being executed, serving as a debugging clue.
Finally, I need to summarize the overall functionality of this code snippet, considering it's part 2 of 34.

Let's break down the code snippet:

1. **`CheckNTLMProxyAuth` function**: This seems to be a helper function to verify NTLM proxy authentication challenges. It checks if the `AuthChallengeInfo` matches the expected parameters for an NTLM proxy authentication.

2. **`TEST_P(HttpNetworkTransactionTest, Basic)`**: This is a basic test case that creates an `HttpNetworkSession` and an `HttpNetworkTransaction`. It doesn't perform any actual network operations.

3. **`TEST_P(HttpNetworkTransactionTest, SimpleGET)`**: This test simulates a simple GET request with a successful response. It checks the received status line and response data.

4. **`TEST_P(HttpNetworkTransactionTest, SimpleGETNoHeaders)`**: This tests a GET request where the server response doesn't include a status line. It expects a default status line.

5. **`TEST_P(HttpNetworkTransactionTest, SimpleGETNoHeadersWeirdPort)`**: This is similar to the previous test but with a non-standard port. It expects the transaction to fail.

6. **`TEST_P(HttpNetworkTransactionTest, SimpleGETNoReadDestroyRequestInfo)`**: This test verifies that the `HttpRequestInfo` can be safely destroyed after the headers have been processed.

7. **`TEST_P(HttpNetworkTransactionTest, SimpleGETHostResolutionFailure)`**: This test simulates a failure during hostname resolution and checks if the error is correctly reported.

8. **`TEST_P(HttpNetworkTransactionTest, ConnectedCallbackNeverCalled)`**: This tests that a "connected" callback is not invoked if the transaction fails before connecting.

9. **`TEST_P(HttpNetworkTransactionTest, ConnectedCallbackFailure)`**: This test checks that if the "connected" callback returns an error, the entire transaction fails.

10. **`TEST_P(HttpNetworkTransactionTest, ConnectedCallbackFailureAllowsSocketReuse)`**: This verifies that even if the "connected" callback fails, the underlying socket can be reused.

11. **`TEST_P(HttpNetworkTransactionTest, ConnectedCallbackCalledOnce)`**: This confirms that the "connected" callback is called once for a successful request.

12. **`TEST_P(HttpNetworkTransactionTest, ConnectedCallbackCalledOnEachAuthChallenge)`**: This checks that the "connected" callback is invoked again upon receiving an authentication challenge.

13. **`TEST_P(HttpNetworkTransactionTest, ConnectedCallbackCalledOnEachRetry)`**: This verifies that the "connected" callback is called for each retry attempt.

14. **`TEST_P(HttpNetworkTransactionTest, ConnectedCallbackCalledAsync)`**: This tests the asynchronous behavior of the "connected" callback.

15. **`TEST_P(HttpNetworkTransactionTest, ConnectedCallbackCalledAsyncError)`**: This tests the asynchronous behavior of the "connected" callback when it returns an error.

16. **`TEST_P(HttpNetworkTransactionTest, StatusLineJunk3Bytes)` and `TEST_P(HttpNetworkTransactionTest, StatusLineJunk4Bytes)`**: These tests verify that the HTTP parser can tolerate a small amount of junk data before the status line.

17. **`TEST_P(HttpNetworkTransactionTest, StatusLineJunk5Bytes)`**: This checks that if there's too much junk before the status line, the parsing might fail or interpret it differently.

18. **`TEST_P(HttpNetworkTransactionTest, StatusLineJunk4Bytes_Slow)`**: Similar to `StatusLineJunk4Bytes`, but the data is received in smaller chunks.

19. **`TEST_P(HttpNetworkTransactionTest, StatusLinePartial)`**: This tests the scenario where the connection is closed before the complete status line is received.

20. **`TEST_P(HttpNetworkTransactionTest, StopsReading204)`**: This verifies that the transaction stops reading the response body when a 204 No Content status is received.

21. **`TEST_P(HttpNetworkTransactionTest, ChunkedEncoding)`**: This tests handling of chunked transfer encoding.

22. **Tests related to multiple Content-Length headers (`MultipleContentLengthHeadersNoTransferEncoding`, `DuplicateContentLengthHeadersNoTransferEncoding`, `ComplexContentLengthHeadersNoTransferEncoding`, `MultipleContentLengthHeadersTransferEncoding`)**: These tests verify how the transaction handles responses with multiple or duplicate Content-Length headers, with and without Transfer-Encoding.

23. **Tests related to Content-Disposition headers (`SingleContentDispositionHeader`, `TwoIdenticalContentDispositionHeaders`, `TwoDistinctContentDispositionHeaders`)**: These check the handling of single and multiple Content-Disposition headers.

24. **Tests related to Location headers (`TwoIdenticalLocationHeaders`, `TwoDistinctLocationHeaders`)**: These tests the handling of single and multiple Location headers in redirects.

25. **`TEST_P(HttpNetworkTransactionTest, Head)`**: This tests a HEAD request and verifies that no response body is read.

26. **`TEST_P(HttpNetworkTransactionTest, ReuseConnection)`**: This test checks if an HTTP connection can be reused for multiple requests.

27. **`TEST_P(HttpNetworkTransactionTest, Ignores100)`**: This verifies that 100 Continue responses are correctly ignored.

28. **`TEST_P(HttpNetworkTransactionTest, Ignores1xx)`**: This extends the previous test to other 1xx informational responses.
This part of the `http_network_transaction_unittest.cc` file in Chromium's network stack focuses on **testing the core functionality of the `HttpNetworkTransaction` class**, which is responsible for handling individual HTTP requests and responses. It covers various scenarios, including:

**Key Functionalities Demonstrated:**

* **Basic Request and Response Handling:**
    * Sending simple GET requests and receiving successful responses.
    * Handling responses without a status line (older HTTP versions).
    * Handling responses with junk data before the status line.
    * Dealing with incomplete status lines.
    * Handling responses with `Content-Length` to determine the body size.
    * Handling chunked transfer encoding.
    * Correctly processing 204 No Content responses (no body expected).
    * Reusing connections for multiple requests.
    * Ignoring 1xx informational responses like 100 Continue.

* **Error Handling and Edge Cases:**
    * Handling hostname resolution failures.
    * Handling invalid HTTP responses (e.g., missing status line on a specific port).
    * Detecting and reporting errors for multiple or conflicting `Content-Length` headers.
    * Detecting and reporting errors for multiple `Content-Disposition` headers.
    * Detecting and reporting errors for multiple `Location` headers in redirects.

* **Callbacks and Asynchronous Operations:**
    * Testing the `ConnectedCallback`, which is invoked when a connection is established.
    * Verifying the `ConnectedCallback` is called at appropriate times (initial connection, authentication challenges, retries).
    * Testing asynchronous behavior of the `ConnectedCallback` and its error handling.

* **Request Method Specifics:**
    * Handling `HEAD` requests, which should not have a response body.

* **Resource Management:**
    * Ensuring `HttpRequestInfo` can be destroyed after the headers are processed.

* **Authentication:**
    * Testing a helper function to check for NTLM proxy authentication challenges.

**Relationship with JavaScript:**

While this C++ code directly handles the network communication, it's crucial for the functionality exposed to JavaScript in a web browser. Here are examples of how these functionalities relate to JavaScript:

* **`SimpleGET` and similar tests:** When JavaScript code in a web page makes a simple `fetch()` request (or uses `XMLHttpRequest`), the underlying network stack, including `HttpNetworkTransaction`, will perform the actions tested here. A successful response leads to the JavaScript `Promise` resolving with the response data.
    * **Example:**
        ```javascript
        fetch('http://example.com/data.txt')
          .then(response => response.text())
          .then(data => console.log(data));
        ```
        The `SimpleGET` test verifies the C++ code's ability to handle the HTTP response that will eventually be processed by the JavaScript `fetch` API.

* **`SimpleGETHostResolutionFailure`:** If the hostname in the JavaScript `fetch()` call cannot be resolved, the `HttpNetworkTransaction` will encounter this failure. This translates to a rejection of the `fetch()` `Promise` in JavaScript, often with a `TypeError`.
    * **Example:**
        ```javascript
        fetch('http://invalid-hostname-that-does-not-exist.com')
          .catch(error => console.error('Fetch error:', error)); // This catch block will likely be triggered.
        ```

* **`ConnectedCallback` tests:** While JavaScript doesn't directly interact with this callback, it represents crucial stages in the network request lifecycle. These tests ensure the underlying connection management works correctly, which impacts the performance and reliability of JavaScript network requests.

* **Multiple Content-Length/Content-Disposition/Location header tests:** These tests ensure the browser correctly interprets and handles (or flags as errors) responses with malformed headers. This prevents unexpected behavior or security vulnerabilities that could be exploited by serving malicious responses. The JavaScript `Response` object's `headers` property would reflect the parsed (or error state) of these headers.

* **`Head` request test:**  If JavaScript uses `fetch()` with the `method: 'HEAD'` option, the `HttpNetworkTransaction` will execute the logic tested in the `Head` test. JavaScript can then access the response headers without downloading the body.
    * **Example:**
        ```javascript
        fetch('http://example.com/large-file.zip', { method: 'HEAD' })
          .then(response => {
            console.log('Content-Length:', response.headers.get('Content-Length'));
          });
        ```

* **`ReuseConnection` test:** This ensures that subsequent `fetch()` calls to the same domain can reuse existing connections, improving page load times and reducing latency for JavaScript applications.

* **`Ignores100` test:** When a JavaScript `fetch()` with a body is sent, the browser might receive a `100 Continue` response before the actual response. This test verifies the C++ layer correctly handles this intermediary response, ensuring the JavaScript receives the final, meaningful response.

**Logical Deduction with Hypothetical Input and Output:**

**Test Case:** `TEST_P(HttpNetworkTransactionTest, SimpleGETNoHeadersWeirdPort)`

* **Hypothetical Input:**
    * JavaScript code makes a `fetch()` request to `http://www.example.com:2000/`.
    * The server at `www.example.com:2000` responds with `"hello world"` and then closes the connection.

* **Logical Deduction:**  The `HttpNetworkTransaction` detects the missing status line and the non-standard port. Due to default settings (as indicated by the test setup), this combination is considered an invalid HTTP response.

* **Hypothetical Output:**
    * The `HttpNetworkTransaction::Start()` method returns an error code: `ERR_INVALID_HTTP_RESPONSE`.
    * In JavaScript, the `fetch()` `Promise` would be rejected with a `TypeError` or a similar error indicating a network problem or invalid response.

**User or Programming Common Usage Errors:**

* **Incorrectly assuming all servers send a status line:**  While common, older HTTP/0.9 servers might not send a status line. Developers relying on the presence of a status line might encounter issues when interacting with such servers. The `SimpleGETNoHeaders` test highlights this.
* **Not handling `fetch()` promise rejections:** If a network request fails (like in `SimpleGETHostResolutionFailure`), and the JavaScript code doesn't have a `.catch()` block, the error might go unhandled, leading to unexpected application behavior.
* **Misinterpreting response headers:** Developers might incorrectly assume the presence of a single `Content-Length` header. The tests for multiple `Content-Length` headers show how the browser handles these cases, and developers need to be aware of these nuances when parsing headers in JavaScript if they are doing so manually (though the `fetch` API handles this for them).
* **Not understanding the implications of `HEAD` requests:**  Developers might use `HEAD` requests expecting to get the response body, which is not the intended behavior. The `Head` test clarifies this.

**User Operation to Reach This Code (Debugging Clue):**

1. **User types a URL in the browser address bar and presses Enter.**  If the URL points to a website that requires a standard HTTP GET request, the browser will initiate a network request.
2. **JavaScript code on a web page makes a `fetch()` call or uses `XMLHttpRequest`.** This is the most common way JavaScript interacts with the network. Any of the scenarios tested in this file could be triggered depending on the specifics of the `fetch()` call (URL, method, headers, etc.) and the server's response.
3. **A browser extension makes an HTTP request.** Extensions can also use the browser's network stack to perform HTTP requests.
4. **The browser's own internal processes make network requests.** For example, checking for updates or fetching resources.

**As a debugging clue, if you're seeing network errors or unexpected behavior in your web application:**

* **Check the browser's developer console for network errors.** These errors often correspond to the error codes tested in this C++ file (e.g., `ERR_NAME_NOT_RESOLVED`, indicating a hostname resolution failure).
* **Examine the HTTP request and response headers in the network tab of the developer console.** This can help identify issues like missing status lines, multiple `Content-Length` headers, or incorrect transfer encodings, which are directly tested in this code.
* **If using `fetch()`, ensure you have proper error handling (`.catch()` blocks).**
* **Consider if the server is behaving as expected.** The tests often simulate specific server behaviors (e.g., sending a 100 Continue).

**Summary of Functionality (Part 2 of 34):**

This section of the `http_network_transaction_unittest.cc` file thoroughly tests the fundamental aspects of the `HttpNetworkTransaction` class in Chromium's network stack. It focuses on ensuring the correct handling of basic HTTP request/response cycles, various error conditions, different response formats, connection management, and the interaction of the transaction with callbacks for asynchronous operations. It lays the groundwork for more complex scenarios that will likely be covered in subsequent parts of the test suite. It validates the core logic that underpins how the browser retrieves web resources, a process often initiated by JavaScript code.

### 提示词
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共34部分，请归纳一下它的功能
```

### 源代码
```cpp
heckNTLMProxyAuth(
    const std::optional<AuthChallengeInfo>& auth_challenge) {
  if (!auth_challenge) {
    return false;
  }
  EXPECT_TRUE(auth_challenge->is_proxy);
  EXPECT_EQ("http://server", auth_challenge->challenger.Serialize());
  EXPECT_EQ(std::string(), auth_challenge->realm);
  EXPECT_EQ(kNtlmAuthScheme, auth_challenge->scheme);
  return true;
}
#endif  // defined(NTLM_PORTABLE)

}  // namespace

TEST_P(HttpNetworkTransactionTest, Basic) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
}

TEST_P(HttpNetworkTransactionTest, SimpleGET) {
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.0 200 OK", out.status_line);
  EXPECT_EQ("hello world", out.response_data);
  int64_t reads_size = CountReadBytes(data_reads);
  EXPECT_EQ(reads_size, out.total_received_bytes);
  EXPECT_EQ(0u, out.connection_attempts.size());

  EXPECT_FALSE(out.remote_endpoint_after_start.address().empty());
}

// Response with no status line.
TEST_P(HttpNetworkTransactionTest, SimpleGETNoHeaders) {
  MockRead data_reads[] = {
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/0.9 200 OK", out.status_line);
  EXPECT_EQ("hello world", out.response_data);
  int64_t reads_size = CountReadBytes(data_reads);
  EXPECT_EQ(reads_size, out.total_received_bytes);
}

// Response with no status line, and a weird port.  Should fail by default.
TEST_P(HttpNetworkTransactionTest, SimpleGETNoHeadersWeirdPort) {
  MockRead data_reads[] = {
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpRequestInfo request;
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  request.method = "GET";
  request.url = GURL("http://www.example.com:2000/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_INVALID_HTTP_RESPONSE));
}

// Tests that request info can be destroyed after the headers phase is complete.
TEST_P(HttpNetworkTransactionTest, SimpleGETNoReadDestroyRequestInfo) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Connection: keep-alive\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, 0),
  };
  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  {
    auto request = std::make_unique<HttpRequestInfo>();
    request->method = "GET";
    request->url = GURL("http://www.example.org/");
    request->traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

    int rv =
        trans->Start(request.get(), callback.callback(), NetLogWithSource());

    EXPECT_THAT(callback.GetResult(rv), IsOk());
  }  // Let request info be destroyed.

  trans.reset();
}

// Test that a failure in resolving the hostname is retrievable.
TEST_P(HttpNetworkTransactionTest, SimpleGETHostResolutionFailure) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto resolver = std::make_unique<MockHostResolver>();
  resolver->rules()->AddSimulatedTimeoutFailure("www.example.org");
  session_deps_.net_log = NetLog::Get();
  session_deps_.host_resolver = std::move(resolver);
  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_NAME_NOT_RESOLVED));

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_THAT(response->resolve_error_info.error, IsError(ERR_DNS_TIMED_OUT));
}

// This test verifies that if the transaction fails before even connecting to a
// remote endpoint, the ConnectedCallback is never called.
TEST_P(HttpNetworkTransactionTest, ConnectedCallbackNeverCalled) {
  auto resolver = std::make_unique<MockHostResolver>();
  resolver->rules()->AddSimulatedTimeoutFailure("bar.test");
  session_deps_.host_resolver = std::move(resolver);

  ConnectedHandler connected_handler;
  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

  auto request = DefaultRequestInfo();
  request.url = GURL("http://bar.test");

  HttpNetworkTransaction transaction(DEFAULT_PRIORITY, session.get());
  transaction.SetConnectedCallback(connected_handler.Callback());

  TestCompletionCallback callback;
  transaction.Start(&request, callback.callback(), NetLogWithSource());
  callback.WaitForResult();

  EXPECT_THAT(connected_handler.transports(), IsEmpty());
}

// This test verifies that if the ConnectedCallback returns an error, the
// entire transaction fails with that error.
TEST_P(HttpNetworkTransactionTest, ConnectedCallbackFailure) {
  // The exact error code does not matter, as long as it is the same one
  // returned by the transaction overall.
  ConnectedHandler connected_handler;
  connected_handler.set_result(ERR_NOT_IMPLEMENTED);

  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);
  auto request = DefaultRequestInfo();
  HttpNetworkTransaction transaction(DEFAULT_PRIORITY, session.get());
  transaction.SetConnectedCallback(connected_handler.Callback());

  // We never get to writing any data, but we still need a socket.
  StaticSocketDataProvider data;
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;
  EXPECT_THAT(
      transaction.Start(&request, callback.callback(), NetLogWithSource()),
      IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_NOT_IMPLEMENTED));

  EXPECT_THAT(connected_handler.transports(),
              ElementsAre(EmbeddedHttpServerTransportInfo()));
}

// This test verifies that if the ConnectedCallback returns an error, the
// underlying socket is not closed and can be reused by the next transaction.
TEST_P(HttpNetworkTransactionTest, ConnectedCallbackFailureAllowsSocketReuse) {
  ConnectedHandler connected_handler;
  connected_handler.set_result(ERR_NOT_IMPLEMENTED);

  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);
  auto request = DefaultRequestInfo();

  // A single socket should be opened and used for both transactions. Data
  // providers are matched to sockets at most once.
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("X-Test-Header: foo\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  {
    HttpNetworkTransaction transaction(DEFAULT_PRIORITY, session.get());
    transaction.SetConnectedCallback(connected_handler.Callback());

    TestCompletionCallback callback;
    EXPECT_THAT(
        transaction.Start(&request, callback.callback(), NetLogWithSource()),
        IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsError(ERR_NOT_IMPLEMENTED));
  }

  // The data provider should still be linked to a socket.
  EXPECT_TRUE(data.socket());
  auto* socket = data.socket();

  {
    HttpNetworkTransaction transaction(DEFAULT_PRIORITY, session.get());

    TestCompletionCallback callback;
    EXPECT_THAT(
        transaction.Start(&request, callback.callback(), NetLogWithSource()),
        IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsOk());

    EXPECT_TRUE(transaction.GetResponseInfo()->headers->HasHeaderValue(
        "X-Test-Header", "foo"));

    // Still linked to the same socket.
    EXPECT_EQ(data.socket(), socket);
  }
}

// This test verifies that the ConnectedCallback is called once in the case of
// simple requests.
TEST_P(HttpNetworkTransactionTest, ConnectedCallbackCalledOnce) {
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  ConnectedHandler connected_handler;
  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);
  auto request = DefaultRequestInfo();
  HttpNetworkTransaction transaction(DEFAULT_PRIORITY, session.get());
  transaction.SetConnectedCallback(connected_handler.Callback());

  TestCompletionCallback callback;
  EXPECT_THAT(
      transaction.Start(&request, callback.callback(), NetLogWithSource()),
      IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  EXPECT_THAT(connected_handler.transports(),
              ElementsAre(EmbeddedHttpServerTransportInfo()));
}

// This test verifies that the ConnectedCallback is called once more per
// authentication challenge.
TEST_P(HttpNetworkTransactionTest, ConnectedCallbackCalledOnEachAuthChallenge) {
  ConnectedHandler connected_handler;
  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);
  auto request = DefaultRequestInfo();
  HttpNetworkTransaction transaction(DEFAULT_PRIORITY, session.get());
  transaction.SetConnectedCallback(connected_handler.Callback());

  // First request receives an auth challenge.
  MockRead data_reads1[] = {
      MockRead("HTTP/1.0 401 Unauthorized\r\n"),
      MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_FAILED),
  };
  StaticSocketDataProvider data1(data_reads1, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  // Second request is allowed through.
  MockRead data_reads2[] = {
      MockRead("HTTP/1.0 200 OK\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data2(data_reads2, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  // First request, connects once.
  TestCompletionCallback callback1;
  EXPECT_THAT(
      transaction.Start(&request, callback1.callback(), NetLogWithSource()),
      IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback1.WaitForResult(), IsOk());

  EXPECT_THAT(connected_handler.transports(),
              ElementsAre(EmbeddedHttpServerTransportInfo()));

  // Second request, connects again.
  TestCompletionCallback callback2;
  EXPECT_THAT(transaction.RestartWithAuth(AuthCredentials(kFoo, kBar),
                                          callback2.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback2.WaitForResult(), IsOk());

  EXPECT_THAT(connected_handler.transports(),
              ElementsAre(EmbeddedHttpServerTransportInfo(),
                          EmbeddedHttpServerTransportInfo()));
}

// This test verifies that the ConnectedCallback is called once more per retry.
TEST_P(HttpNetworkTransactionTest, ConnectedCallbackCalledOnEachRetry) {
  ConnectedHandler connected_handler;
  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);
  auto request = DefaultRequestInfo();
  HttpNetworkTransaction transaction(DEFAULT_PRIORITY, session.get());
  transaction.SetConnectedCallback(connected_handler.Callback());

  // First request receives a retryable error.
  MockRead data_reads1[] = {
      MockRead(SYNCHRONOUS, ERR_HTTP2_SERVER_REFUSED_STREAM),
  };
  StaticSocketDataProvider data1(data_reads1, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  // Second request is allowed through.
  MockRead data_reads2[] = {
      MockRead("HTTP/1.0 200 OK\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data2(data_reads2, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback1;
  EXPECT_THAT(
      transaction.Start(&request, callback1.callback(), NetLogWithSource()),
      IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback1.WaitForResult(), IsOk());

  EXPECT_THAT(connected_handler.transports(),
              ElementsAre(EmbeddedHttpServerTransportInfo(),
                          EmbeddedHttpServerTransportInfo()));
}

TEST_P(HttpNetworkTransactionTest, ConnectedCallbackCalledAsync) {
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  ConnectedHandler connected_handler;
  connected_handler.set_run_callback(true);
  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);
  auto request = DefaultRequestInfo();
  HttpNetworkTransaction transaction(DEFAULT_PRIORITY, session.get());
  transaction.SetConnectedCallback(connected_handler.Callback());

  TestCompletionCallback callback;
  EXPECT_THAT(
      transaction.Start(&request, callback.callback(), NetLogWithSource()),
      IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  EXPECT_THAT(connected_handler.transports(),
              ElementsAre(EmbeddedHttpServerTransportInfo()));
}

TEST_P(HttpNetworkTransactionTest, ConnectedCallbackCalledAsyncError) {
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  ConnectedHandler connected_handler;
  connected_handler.set_run_callback(true);
  connected_handler.set_result(ERR_FAILED);
  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);
  auto request = DefaultRequestInfo();
  HttpNetworkTransaction transaction(DEFAULT_PRIORITY, session.get());
  transaction.SetConnectedCallback(connected_handler.Callback());

  TestCompletionCallback callback;
  EXPECT_THAT(
      transaction.Start(&request, callback.callback(), NetLogWithSource()),
      IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_FAILED));

  EXPECT_THAT(connected_handler.transports(),
              ElementsAre(EmbeddedHttpServerTransportInfo()));
}

// Allow up to 4 bytes of junk to precede status line.
TEST_P(HttpNetworkTransactionTest, StatusLineJunk3Bytes) {
  MockRead data_reads[] = {
      MockRead("xxxHTTP/1.0 404 Not Found\nServer: blah\n\nDATA"),
      MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.0 404 Not Found", out.status_line);
  EXPECT_EQ("DATA", out.response_data);
  int64_t reads_size = CountReadBytes(data_reads);
  EXPECT_EQ(reads_size, out.total_received_bytes);
}

// Allow up to 4 bytes of junk to precede status line.
TEST_P(HttpNetworkTransactionTest, StatusLineJunk4Bytes) {
  MockRead data_reads[] = {
      MockRead("\n\nQJHTTP/1.0 404 Not Found\nServer: blah\n\nDATA"),
      MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.0 404 Not Found", out.status_line);
  EXPECT_EQ("DATA", out.response_data);
  int64_t reads_size = CountReadBytes(data_reads);
  EXPECT_EQ(reads_size, out.total_received_bytes);
}

// Beyond 4 bytes of slop and it should fail to find a status line.
TEST_P(HttpNetworkTransactionTest, StatusLineJunk5Bytes) {
  MockRead data_reads[] = {
      MockRead("xxxxxHTTP/1.1 404 Not Found\nServer: blah"),
      MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/0.9 200 OK", out.status_line);
  EXPECT_EQ("xxxxxHTTP/1.1 404 Not Found\nServer: blah", out.response_data);
  int64_t reads_size = CountReadBytes(data_reads);
  EXPECT_EQ(reads_size, out.total_received_bytes);
}

// Same as StatusLineJunk4Bytes, except the read chunks are smaller.
TEST_P(HttpNetworkTransactionTest, StatusLineJunk4Bytes_Slow) {
  MockRead data_reads[] = {
      MockRead("\n"),
      MockRead("\n"),
      MockRead("Q"),
      MockRead("J"),
      MockRead("HTTP/1.0 404 Not Found\nServer: blah\n\nDATA"),
      MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.0 404 Not Found", out.status_line);
  EXPECT_EQ("DATA", out.response_data);
  int64_t reads_size = CountReadBytes(data_reads);
  EXPECT_EQ(reads_size, out.total_received_bytes);
}

// Close the connection before enough bytes to have a status line.
TEST_P(HttpNetworkTransactionTest, StatusLinePartial) {
  MockRead data_reads[] = {
      MockRead("HTT"),
      MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/0.9 200 OK", out.status_line);
  EXPECT_EQ("HTT", out.response_data);
  int64_t reads_size = CountReadBytes(data_reads);
  EXPECT_EQ(reads_size, out.total_received_bytes);
}

// Simulate a 204 response, lacking a Content-Length header, sent over a
// persistent connection.  The response should still terminate since a 204
// cannot have a response body.
TEST_P(HttpNetworkTransactionTest, StopsReading204) {
  char junk[] = "junk";
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 204 No Content\r\n\r\n"),
      MockRead(junk),  // Should not be read!!
      MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 204 No Content", out.status_line);
  EXPECT_EQ("", out.response_data);
  int64_t reads_size = CountReadBytes(data_reads);
  int64_t response_size = reads_size - strlen(junk);
  EXPECT_EQ(response_size, out.total_received_bytes);
}

// A simple request using chunked encoding with some extra data after.
TEST_P(HttpNetworkTransactionTest, ChunkedEncoding) {
  std::string final_chunk = "0\r\n\r\n";
  std::string extra_data = "HTTP/1.1 200 OK\r\n";
  std::string last_read = final_chunk + extra_data;
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"),
      MockRead("5\r\nHello\r\n"),
      MockRead("1\r\n"),
      MockRead(" \r\n"),
      MockRead("5\r\nworld\r\n"),
      MockRead(last_read.data()),
      MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200 OK", out.status_line);
  EXPECT_EQ("Hello world", out.response_data);
  int64_t reads_size = CountReadBytes(data_reads);
  int64_t response_size = reads_size - extra_data.size();
  EXPECT_EQ(response_size, out.total_received_bytes);
}

// Next tests deal with http://crbug.com/56344.

TEST_P(HttpNetworkTransactionTest,
       MultipleContentLengthHeadersNoTransferEncoding) {
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 10\r\n"),
      MockRead("Content-Length: 5\r\n\r\n"),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads);
  EXPECT_THAT(out.rv, IsError(ERR_RESPONSE_HEADERS_MULTIPLE_CONTENT_LENGTH));
}

TEST_P(HttpNetworkTransactionTest,
       DuplicateContentLengthHeadersNoTransferEncoding) {
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 5\r\n"),
      MockRead("Content-Length: 5\r\n\r\n"),
      MockRead("Hello"),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200 OK", out.status_line);
  EXPECT_EQ("Hello", out.response_data);
}

TEST_P(HttpNetworkTransactionTest,
       ComplexContentLengthHeadersNoTransferEncoding) {
  // More than 2 dupes.
  {
    MockRead data_reads[] = {
        MockRead("HTTP/1.1 200 OK\r\n"),
        MockRead("Content-Length: 5\r\n"),
        MockRead("Content-Length: 5\r\n"),
        MockRead("Content-Length: 5\r\n\r\n"),
        MockRead("Hello"),
    };
    SimpleGetHelperResult out = SimpleGetHelper(data_reads);
    EXPECT_THAT(out.rv, IsOk());
    EXPECT_EQ("HTTP/1.1 200 OK", out.status_line);
    EXPECT_EQ("Hello", out.response_data);
  }
  // HTTP/1.0
  {
    MockRead data_reads[] = {
        MockRead("HTTP/1.0 200 OK\r\n"),
        MockRead("Content-Length: 5\r\n"),
        MockRead("Content-Length: 5\r\n"),
        MockRead("Content-Length: 5\r\n\r\n"),
        MockRead("Hello"),
    };
    SimpleGetHelperResult out = SimpleGetHelper(data_reads);
    EXPECT_THAT(out.rv, IsOk());
    EXPECT_EQ("HTTP/1.0 200 OK", out.status_line);
    EXPECT_EQ("Hello", out.response_data);
  }
  // 2 dupes and one mismatched.
  {
    MockRead data_reads[] = {
        MockRead("HTTP/1.1 200 OK\r\n"),
        MockRead("Content-Length: 10\r\n"),
        MockRead("Content-Length: 10\r\n"),
        MockRead("Content-Length: 5\r\n\r\n"),
    };
    SimpleGetHelperResult out = SimpleGetHelper(data_reads);
    EXPECT_THAT(out.rv, IsError(ERR_RESPONSE_HEADERS_MULTIPLE_CONTENT_LENGTH));
  }
}

TEST_P(HttpNetworkTransactionTest,
       MultipleContentLengthHeadersTransferEncoding) {
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 666\r\n"),
      MockRead("Content-Length: 1337\r\n"),
      MockRead("Transfer-Encoding: chunked\r\n\r\n"),
      MockRead("5\r\nHello\r\n"),
      MockRead("1\r\n"),
      MockRead(" \r\n"),
      MockRead("5\r\nworld\r\n"),
      MockRead("0\r\n\r\nHTTP/1.1 200 OK\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200 OK", out.status_line);
  EXPECT_EQ("Hello world", out.response_data);
}

// Next tests deal with http://crbug.com/98895.

// Checks that a single Content-Disposition header results in no error.
TEST_P(HttpNetworkTransactionTest, SingleContentDispositionHeader) {
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(
          "Content-Disposition: attachment;filename=\"salutations.txt\"r\n"),
      MockRead("Content-Length: 5\r\n\r\n"),
      MockRead("Hello"),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200 OK", out.status_line);
  EXPECT_EQ("Hello", out.response_data);
}

// Checks that two identical Content-Disposition headers result in no error.
TEST_P(HttpNetworkTransactionTest, TwoIdenticalContentDispositionHeaders) {
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Disposition: attachment;filename=\"greetings.txt\"r\n"),
      MockRead("Content-Disposition: attachment;filename=\"greetings.txt\"r\n"),
      MockRead("Content-Length: 5\r\n\r\n"),
      MockRead("Hello"),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200 OK", out.status_line);
  EXPECT_EQ("Hello", out.response_data);
}

// Checks that two distinct Content-Disposition headers result in an error.
TEST_P(HttpNetworkTransactionTest, TwoDistinctContentDispositionHeaders) {
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Disposition: attachment;filename=\"greetings.txt\"r\n"),
      MockRead("Content-Disposition: attachment;filename=\"hi.txt\"r\n"),
      MockRead("Content-Length: 5\r\n\r\n"),
      MockRead("Hello"),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads);
  EXPECT_THAT(out.rv,
              IsError(ERR_RESPONSE_HEADERS_MULTIPLE_CONTENT_DISPOSITION));
}

// Checks that two identical Location headers result in no error.
// Also tests Location header behavior.
TEST_P(HttpNetworkTransactionTest, TwoIdenticalLocationHeaders) {
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 302 Redirect\r\n"),
      MockRead("Location: http://good.com/\r\n"),
      MockRead("Location: http://good.com/\r\n"),
      MockRead("Content-Length: 0\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://redirect.com/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 302 Redirect", response->headers->GetStatusLine());
  std::string url;
  EXPECT_TRUE(response->headers->IsRedirect(&url));
  EXPECT_EQ("http://good.com/", url);
  EXPECT_TRUE(response->proxy_chain.is_direct());
}

// Checks that two distinct Location headers result in an error.
TEST_P(HttpNetworkTransactionTest, TwoDistinctLocationHeaders) {
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 302 Redirect\r\n"),
      MockRead("Location: http://good.com/\r\n"),
      MockRead("Location: http://evil.com/\r\n"),
      MockRead("Content-Length: 0\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads);
  EXPECT_THAT(out.rv, IsError(ERR_RESPONSE_HEADERS_MULTIPLE_LOCATION));
}

// Do a request using the HEAD method. Verify that we don't try to read the
// message body (since HEAD has none).
TEST_P(HttpNetworkTransactionTest, Head) {
  HttpRequestInfo request;
  request.method = "HEAD";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  ConnectedHandler connected_handler;
  trans.SetConnectedCallback(connected_handler.Callback());

  MockWrite data_writes1[] = {
      MockWrite("HEAD / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 404 Not Found\r\n"),
      MockRead("Server: Blah\r\n"),
      MockRead("Content-Length: 1234\r\n\r\n"),

      // No response body because the test stops reading here.
      MockRead(SYNCHRONOUS, ERR_UNEXPECTED),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  TestCompletionCallback callback1;

  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  // Check that the headers got parsed.
  EXPECT_TRUE(response->headers);
  EXPECT_EQ(1234, response->headers->GetContentLength());
  EXPECT_EQ("HTTP/1.1 404 Not Found", response->headers->GetStatusLine());
  EXPECT_TRUE(response->proxy_chain.is_direct());
  EXPECT_THAT(connected_handler.transports(),
              ElementsAre(EmbeddedHttpServerTransportInfo()));

  std::string server_header;
  size_t iter = 0;
  bool has_server_header =
      response->headers->EnumerateHeader(&iter, "Server", &server_header);
  EXPECT_TRUE(has_server_header);
  EXPECT_EQ("Blah", server_header);

  // Reading should give EOF right away, since there is no message body
  // (despite non-zero content-length).
  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("", response_data);
}

TEST_P(HttpNetworkTransactionTest, ReuseConnection) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"),
      MockRead("hello"),
      MockRead("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"),
      MockRead("world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  const char* const kExpectedResponseData[] = {"hello", "world"};

  for (const auto* expected_response_data : kExpectedResponseData) {
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL("http://www.example.org/");
    request.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    TestCompletionCallback callback;

    int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);

    EXPECT_TRUE(response->headers);
    EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
    EXPECT_TRUE(response->proxy_chain.is_direct());

    std::string response_data;
    rv = ReadTransaction(&trans, &response_data);
    EXPECT_THAT(rv, IsOk());
    EXPECT_EQ(expected_response_data, response_data);
  }
}

TEST_P(HttpNetworkTransactionTest, Ignores100) {
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("foo")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.foo.com/");
  request.upload_data_stream = &upload_data_stream;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Check the upload progress returned before initialization is correct.
  UploadProgress progress = request.upload_data_stream->GetUploadProgress();
  EXPECT_EQ(0u, progress.size());
  EXPECT_EQ(0u, progress.position());

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 100 Continue\r\n\r\n"),
      MockRead("HTTP/1.0 200 OK\r\n\r\n"),
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
  EXPECT_EQ("HTTP/1.0 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);
}

// This test is almost the same as Ignores100 above, but the response contains
// a 102 instead of a 100. Also, instead of HTTP/1.0 the response is
// HTTP/1.1 and the two status headers are read in one read.
TEST_P(HttpNetworkTransactionTest, Ignores1xx) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.foo.com/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.
```