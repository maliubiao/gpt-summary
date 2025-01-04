Response:
The user wants a summary of the functionality of the C++ file `net/http/http_network_transaction_unittest.cc` in the Chromium project. They also want to know if the code interacts with JavaScript and examples of this interaction, any logical deductions with example input and output, common user or programming errors, how a user might reach this code (debugging clues), and a final concise summary of the file's purpose.

Here's a breakdown of the thought process to address each of these points:

1. **Overall Functionality:**  The file name `http_network_transaction_unittest.cc` strongly suggests that it contains unit tests for the `HttpNetworkTransaction` class. Skimming the code confirms this. It sets up various scenarios involving HTTP and HTTPS requests, including different HTTP methods (GET, POST), error conditions (connection reset), SSL/TLS, and WebSockets. The tests verify the correct behavior of `HttpNetworkTransaction` under these conditions.

2. **Relationship with JavaScript:**  HTTP is the underlying protocol for web communication, so there's an *indirect* relationship with JavaScript. When a JavaScript application makes a network request (e.g., using `fetch` or `XMLHttpRequest`), the browser's network stack, which includes components like `HttpNetworkTransaction`, handles the actual communication. The key is to identify where the C++ code emulates or tests the *boundaries* of the network stack that JavaScript would interact with. Specifically, look for tests that simulate responses that JavaScript would receive.

3. **Logical Deductions (Input/Output):** Unit tests inherently involve logical deductions. The *input* is the setup of the test case (e.g., defining mock network responses, request parameters). The *output* is the assertion that verifies the expected behavior (e.g., checking the received response data, status code, or error code). I need to select a representative test case and detail its setup and assertions.

4. **User/Programming Errors:**  Think about common mistakes developers make when working with HTTP. This includes incorrect URLs, missing headers, issues with POST requests (like incorrect `Content-Length`), and problems related to SSL/TLS. The tests in this file often cover scenarios that could arise from these errors.

5. **User Journey/Debugging:** How does a user's action in the browser lead to this C++ code being executed?  It's important to connect user actions to the underlying network requests. Typing a URL, clicking a link, or JavaScript making an API call all trigger network requests handled by this code. Debugging would involve tools like network inspectors in the browser's developer tools or potentially lower-level network debugging tools.

6. **Concise Summary:** After analyzing the details, I need to distill the core purpose of the file into a brief statement.

**Pre-computation/Analysis of the Code Snippet (the provided section):**

* **Focus:** This specific section focuses on testing the behavior of `HttpNetworkTransaction` when dealing with socket pool limits and connection reuse, particularly when an SSL connection is established but might not be immediately needed due to existing HTTP requests filling the pool. It also tests how the transaction handles `ERR_CONNECTION_RESET` during POST requests, including scenarios with and without '100 Continue' responses. Finally, it includes tests for establishing WebSocket connections, both secure and insecure, including scenarios with proxy authentication.
* **Key Classes/Components:** `HttpNetworkTransaction`, `HttpNetworkSession`, `ClientSocketPoolManager`, `MockWrite`, `MockRead`, `StaticSocketDataProvider`, `SSLSocketDataProvider`, `HttpRequestInfo`, `TestCompletionCallback`, `HttpStreamFactory`, `ChunkedUploadDataStream`, `ElementsUploadDataStream`, `HttpRequestHeaders`, `ConfiguredProxyResolutionService`.
* **Key Scenarios:**
    * Stalling HTTP requests when SSL connections are established and the socket pool is full.
    * Closing idle SSL sockets to allow HTTP requests to proceed.
    * Handling `ERR_CONNECTION_RESET` during POST requests and ensuring correct error responses (and ignoring non-error responses).
    * Establishing WebSocket handshakes, including proxy scenarios.

**Drafting the Response (Iterative Process):**

* **Initial Summary:** Start with the most obvious: it's a unit test file for `HttpNetworkTransaction`.
* **JavaScript Connection:** Explain the indirect link via browser network requests. Provide examples of JavaScript APIs that trigger these requests.
* **Logical Deduction Example:** Select a relatively simple test case (e.g., the first one in the snippet demonstrating socket pool stalling). Describe the setup (SSL and HTTP requests), the expected stalling, and the eventual completion.
* **Common Errors:** Brainstorm typical HTTP-related developer errors and relate them to the test scenarios.
* **User Journey:** Explain the user actions and the browser components involved.
* **Detailed Breakdown of the Snippet:**  Go through the test cases in the provided code, summarizing the purpose of each test (socket pool limits, connection reset in POST, WebSockets).
* **Final Concise Summary:** Reiterate the main purpose of the file.

**Self-Correction/Refinement during Drafting:**

* **Clarity:** Ensure the explanations are clear and avoid overly technical jargon.
* **Specificity:** Provide concrete examples instead of general statements.
* **Accuracy:** Double-check the understanding of the code and the relationships between different components. For instance, be precise about *how* JavaScript interacts (indirectly through browser APIs).
* **Completeness:** Address all aspects of the user's request. Make sure to connect the test scenarios to potential user/developer issues.

By following these steps,  I can construct a comprehensive and informative response that accurately describes the functionality of the given C++ source file and its relationship to other parts of the web development process.
```cpp
T_POOL, 1);
  ClientSocketPoolManager::set_max_sockets_per_pool(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);

  // Set up SSL request.

  HttpRequestInfo ssl_request;
  ssl_request.method = "GET";
  ssl_request.url = GURL("https://www.example.org/");
  ssl_request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite ssl_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  MockRead ssl_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 11\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider ssl_data(ssl_reads, ssl_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&ssl_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  // Set up HTTP request.

  HttpRequestInfo http_request;
  http_request.method = "GET";
  http_request.url = GURL("http://www.example.org/");
  http_request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite http_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 7\r\n\r\n"),
      MockRead("falafel"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider http_data(http_reads, http_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&http_data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    session->http_stream_pool()->set_max_stream_sockets_per_group_for_testing(
        1u);
    session->http_stream_pool()->set_max_stream_sockets_per_pool_for_testing(
        1u);
  }

  // Start the SSL request.
  TestCompletionCallback ssl_callback;
  HttpNetworkTransaction ssl_trans(DEFAULT_PRIORITY, session.get());
  ASSERT_EQ(ERR_IO_PENDING,
            ssl_trans.Start(&ssl_request, ssl_callback.callback(),
                            NetLogWithSource()));

  // Start the HTTP request. Pool should stall.
  TestCompletionCallback http_callback;
  HttpNetworkTransaction http_trans(DEFAULT_PRIORITY, session.get());
  ASSERT_EQ(ERR_IO_PENDING,
            http_trans.Start(&http_request, http_callback.callback(),
                             NetLogWithSource()));
  EXPECT_TRUE(IsTransportSocketPoolStalled(session.get()));

  // Wait for response from SSL request.
  ASSERT_THAT(ssl_callback.WaitForResult(), IsOk());
  std::string response_data;
  ASSERT_THAT(ReadTransaction(&ssl_trans, &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  // The SSL socket should automatically be closed, so the HTTP request can
  // start.
  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));
  ASSERT_FALSE(IsTransportSocketPoolStalled(session.get()));

  // The HTTP request can now complete.
  ASSERT_THAT(http_callback.WaitForResult(), IsOk());
  ASSERT_THAT(ReadTransaction(&http_trans, &response_data), IsOk());
  EXPECT_EQ("falafel", response_data);

  EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));
}

// Tests that when a SSL connection is established but there's no corresponding
// request that needs it, the new socket is closed if the transport socket pool
// is stalled on the global socket limit.
TEST_P(HttpNetworkTransactionTest, CloseSSLSocketOnIdleForHttpRequest2) {
  ClientSocketPoolManager::set_max_sockets_per_group(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);
  ClientSocketPoolManager::set_max_sockets_per_pool(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);

  // Set up an ssl request.

  HttpRequestInfo ssl_request;
  ssl_request.method = "GET";
  ssl_request.url = GURL("https://www.foopy.com/");
  ssl_request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // No data will be sent on the SSL socket.
  StaticSocketDataProvider ssl_data;
  MockConnectCompleter ssl_connect_completer;
  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    // When the HappyEyeballsV3 flag is enabled, the idle socket created by the
    // following preconnect would be reused immedialy after the transaction is
    // started when we don't delay Connect(). Use MockConnectCompleter to block
    // Connect().
    ssl_data.set_connect_data(MockConnect(&ssl_connect_completer));
  }
  session_deps_.socket_factory->AddSocketDataProvider(&ssl_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  // Set up HTTP request.

  HttpRequestInfo http_request;
  http_request.method = "GET";
  http_request.url = GURL("http://www.example.org/");
  http_request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite http_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 7\r\n\r\n"),
      MockRead("falafel"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider http_data(http_reads, http_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&http_data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    session->http_stream_pool()->set_max_stream_sockets_per_group_for_testing(
        1u);
    session->http_stream_pool()->set_max_stream_sockets_per_pool_for_testing(
        1u);
  }

  // Preconnect an SSL socket. A preconnect is needed because connect jobs are
  // cancelled when a normal transaction is cancelled.
  HttpStreamFactory* http_stream_factory = session->http_stream_factory();
  http_stream_factory->PreconnectStreams(1, ssl_request);
  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));

  // Start the HTTP request. Pool should stall.
  TestCompletionCallback http_callback;
  HttpNetworkTransaction http_trans(DEFAULT_PRIORITY, session.get());
  ASSERT_EQ(ERR_IO_PENDING,
            http_trans.Start(&http_request, http_callback.callback(),
                             NetLogWithSource()));
  EXPECT_TRUE(IsTransportSocketPoolStalled(session.get()));

  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    ssl_connect_completer.Complete(OK);
  }

  // The SSL connection will automatically be closed once the connection is
  // established, to let the HTTP request start.
  ASSERT_THAT(http_callback.WaitForResult(), IsOk());
  std::string response_data;
  ASSERT_THAT(ReadTransaction(&http_trans, &response_data), IsOk());
  EXPECT_EQ("falafel", response_data);

  EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));
}

TEST_P(HttpNetworkTransactionTest, PostReadsErrorResponseAfterReset) {
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

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 3\r\n\r\n"),
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 400 Not OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.0 400 Not OK", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);
}

// This test makes sure the retry logic doesn't trigger when reading an error
// response from a server that rejected a POST with a CONNECTION_RESET.
TEST_P(HttpNetworkTransactionTest,
       PostReadsErrorResponseAfterResetOnReusedSocket) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 3\r\n\r\n"),
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 Peachy\r\n"
               "Content-Length: 14\r\n\r\n"),
      MockRead("first response"),
      MockRead("HTTP/1.1 400 Not OK\r\n"
               "Content-Length: 15\r\n\r\n"),
      MockRead("second response"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("http://www.foo.com/");
  request1.load_flags = 0;
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto trans1 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans1->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response1 = trans1->GetResponseInfo();
  ASSERT_TRUE(response1);

  EXPECT_TRUE(response1->headers);
  EXPECT_EQ("HTTP/1.1 200 Peachy", response1->headers->GetStatusLine());

  std::string response_data1;
  rv = ReadTransaction(trans1.get(), &response_data1);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("first response", response_data1);
  // Delete the transaction to release the socket back into the socket pool.
  trans1.reset();

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("foo")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request2;
  request2.method = "POST";
  request2.url = GURL("http://www.foo.com/");
  request2.upload_data_stream = &upload_data_stream;
  request2.load_flags = 0;
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());
  rv = trans2.Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response2 = trans2.GetResponseInfo();
  ASSERT_TRUE(response2);

  EXPECT_TRUE(response2->headers);
  EXPECT_EQ("HTTP/1.1 400 Not OK", response2->headers->GetStatusLine());

  std::string response_data2;
  rv = ReadTransaction(&trans2, &response_data2);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("second response", response_data2);
}

TEST_P(HttpNetworkTransactionTest,
       PostReadsErrorResponseAfterResetPartialBodySent) {
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

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 3\r\n\r\n"
                "fo"),
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 400 Not OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.0 400 Not OK", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);
}

// This tests the more common case than the previous test, where headers and
// body are not merged into a single request.
TEST_P(HttpNetworkTransactionTest, ChunkedPostReadsErrorResponseAfterReset) {
  ChunkedUploadDataStream upload_data_stream(0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.foo.com/");
  request.upload_data_stream = &upload_data_stream;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Transfer-Encoding: chunked\r\n\r\n"),
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 400 Not OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Make sure the headers are sent before adding a chunk. This ensures that
  // they can't be merged with the body in a single send. Not currently
  // necessary since a chunked body is never merged with headers, but this makes
  // the test more future proof.
  base::RunLoop().RunUntilIdle();

  upload_data_stream.AppendData(base::byte_span_from_cstring("last chunk"),
                                true);

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.0 400 Not OK", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);
}

TEST_P(HttpNetworkTransactionTest, PostReadsErrorResponseAfterResetAnd100) {
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

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 3\r\n\r\n"),
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 100 Continue\r\n\r\n"),
      MockRead("HTTP/1.0 400 Not OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.0 400 Not OK", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);
}

TEST_P(HttpNetworkTransactionTest, PostIgnoresNonErrorResponseAfterReset) {
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

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 3\r\n\r\n"),
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 Just Dandy\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));
}

TEST_P(HttpNetworkTransactionTest,
       PostIgnoresNonErrorResponseAfterResetAnd100) {
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

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 3\r\n\r\n"),
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 100 Continue\r\n\r\n"),
      MockRead("HTTP/1.0 302 Redirect\r\n"),
      MockRead("Location: http://somewhere-else.com/\r\n"),
      MockRead("Content-Length: 0\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));
}

TEST_P(HttpNetworkTransactionTest, PostIgnoresHttp09ResponseAfterReset) {
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

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 3\r\n\r\n"),
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
      MockRead("HTTP 0.9 rocks!"),
      MockRead(SYNCHRONOUS, OK),

Prompt: 
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第28部分，共34部分，请归纳一下它的功能

"""
T_POOL, 1);
  ClientSocketPoolManager::set_max_sockets_per_pool(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);

  // Set up SSL request.

  HttpRequestInfo ssl_request;
  ssl_request.method = "GET";
  ssl_request.url = GURL("https://www.example.org/");
  ssl_request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite ssl_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  MockRead ssl_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 11\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider ssl_data(ssl_reads, ssl_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&ssl_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  // Set up HTTP request.

  HttpRequestInfo http_request;
  http_request.method = "GET";
  http_request.url = GURL("http://www.example.org/");
  http_request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite http_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 7\r\n\r\n"),
      MockRead("falafel"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider http_data(http_reads, http_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&http_data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    session->http_stream_pool()->set_max_stream_sockets_per_group_for_testing(
        1u);
    session->http_stream_pool()->set_max_stream_sockets_per_pool_for_testing(
        1u);
  }

  // Start the SSL request.
  TestCompletionCallback ssl_callback;
  HttpNetworkTransaction ssl_trans(DEFAULT_PRIORITY, session.get());
  ASSERT_EQ(ERR_IO_PENDING,
            ssl_trans.Start(&ssl_request, ssl_callback.callback(),
                            NetLogWithSource()));

  // Start the HTTP request.  Pool should stall.
  TestCompletionCallback http_callback;
  HttpNetworkTransaction http_trans(DEFAULT_PRIORITY, session.get());
  ASSERT_EQ(ERR_IO_PENDING,
            http_trans.Start(&http_request, http_callback.callback(),
                             NetLogWithSource()));
  EXPECT_TRUE(IsTransportSocketPoolStalled(session.get()));

  // Wait for response from SSL request.
  ASSERT_THAT(ssl_callback.WaitForResult(), IsOk());
  std::string response_data;
  ASSERT_THAT(ReadTransaction(&ssl_trans, &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  // The SSL socket should automatically be closed, so the HTTP request can
  // start.
  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));
  ASSERT_FALSE(IsTransportSocketPoolStalled(session.get()));

  // The HTTP request can now complete.
  ASSERT_THAT(http_callback.WaitForResult(), IsOk());
  ASSERT_THAT(ReadTransaction(&http_trans, &response_data), IsOk());
  EXPECT_EQ("falafel", response_data);

  EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));
}

// Tests that when a SSL connection is established but there's no corresponding
// request that needs it, the new socket is closed if the transport socket pool
// is stalled on the global socket limit.
TEST_P(HttpNetworkTransactionTest, CloseSSLSocketOnIdleForHttpRequest2) {
  ClientSocketPoolManager::set_max_sockets_per_group(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);
  ClientSocketPoolManager::set_max_sockets_per_pool(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);

  // Set up an ssl request.

  HttpRequestInfo ssl_request;
  ssl_request.method = "GET";
  ssl_request.url = GURL("https://www.foopy.com/");
  ssl_request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // No data will be sent on the SSL socket.
  StaticSocketDataProvider ssl_data;
  MockConnectCompleter ssl_connect_completer;
  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    // When the HappyEyeballsV3 flag is enabled, the idle socket created by the
    // following preconnect would be reused immedialy after the transaction is
    // started when we don't delay Connect(). Use MockConnectCompleter to block
    // Connect().
    ssl_data.set_connect_data(MockConnect(&ssl_connect_completer));
  }
  session_deps_.socket_factory->AddSocketDataProvider(&ssl_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  // Set up HTTP request.

  HttpRequestInfo http_request;
  http_request.method = "GET";
  http_request.url = GURL("http://www.example.org/");
  http_request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite http_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 7\r\n\r\n"),
      MockRead("falafel"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider http_data(http_reads, http_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&http_data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    session->http_stream_pool()->set_max_stream_sockets_per_group_for_testing(
        1u);
    session->http_stream_pool()->set_max_stream_sockets_per_pool_for_testing(
        1u);
  }

  // Preconnect an SSL socket.  A preconnect is needed because connect jobs are
  // cancelled when a normal transaction is cancelled.
  HttpStreamFactory* http_stream_factory = session->http_stream_factory();
  http_stream_factory->PreconnectStreams(1, ssl_request);
  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));

  // Start the HTTP request.  Pool should stall.
  TestCompletionCallback http_callback;
  HttpNetworkTransaction http_trans(DEFAULT_PRIORITY, session.get());
  ASSERT_EQ(ERR_IO_PENDING,
            http_trans.Start(&http_request, http_callback.callback(),
                             NetLogWithSource()));
  EXPECT_TRUE(IsTransportSocketPoolStalled(session.get()));

  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    ssl_connect_completer.Complete(OK);
  }

  // The SSL connection will automatically be closed once the connection is
  // established, to let the HTTP request start.
  ASSERT_THAT(http_callback.WaitForResult(), IsOk());
  std::string response_data;
  ASSERT_THAT(ReadTransaction(&http_trans, &response_data), IsOk());
  EXPECT_EQ("falafel", response_data);

  EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));
}

TEST_P(HttpNetworkTransactionTest, PostReadsErrorResponseAfterReset) {
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

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 3\r\n\r\n"),
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 400 Not OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.0 400 Not OK", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);
}

// This test makes sure the retry logic doesn't trigger when reading an error
// response from a server that rejected a POST with a CONNECTION_RESET.
TEST_P(HttpNetworkTransactionTest,
       PostReadsErrorResponseAfterResetOnReusedSocket) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 3\r\n\r\n"),
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 Peachy\r\n"
               "Content-Length: 14\r\n\r\n"),
      MockRead("first response"),
      MockRead("HTTP/1.1 400 Not OK\r\n"
               "Content-Length: 15\r\n\r\n"),
      MockRead("second response"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("http://www.foo.com/");
  request1.load_flags = 0;
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto trans1 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans1->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response1 = trans1->GetResponseInfo();
  ASSERT_TRUE(response1);

  EXPECT_TRUE(response1->headers);
  EXPECT_EQ("HTTP/1.1 200 Peachy", response1->headers->GetStatusLine());

  std::string response_data1;
  rv = ReadTransaction(trans1.get(), &response_data1);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("first response", response_data1);
  // Delete the transaction to release the socket back into the socket pool.
  trans1.reset();

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("foo")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request2;
  request2.method = "POST";
  request2.url = GURL("http://www.foo.com/");
  request2.upload_data_stream = &upload_data_stream;
  request2.load_flags = 0;
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());
  rv = trans2.Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response2 = trans2.GetResponseInfo();
  ASSERT_TRUE(response2);

  EXPECT_TRUE(response2->headers);
  EXPECT_EQ("HTTP/1.1 400 Not OK", response2->headers->GetStatusLine());

  std::string response_data2;
  rv = ReadTransaction(&trans2, &response_data2);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("second response", response_data2);
}

TEST_P(HttpNetworkTransactionTest,
       PostReadsErrorResponseAfterResetPartialBodySent) {
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

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 3\r\n\r\n"
                "fo"),
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 400 Not OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.0 400 Not OK", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);
}

// This tests the more common case than the previous test, where headers and
// body are not merged into a single request.
TEST_P(HttpNetworkTransactionTest, ChunkedPostReadsErrorResponseAfterReset) {
  ChunkedUploadDataStream upload_data_stream(0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.foo.com/");
  request.upload_data_stream = &upload_data_stream;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Transfer-Encoding: chunked\r\n\r\n"),
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 400 Not OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Make sure the headers are sent before adding a chunk.  This ensures that
  // they can't be merged with the body in a single send.  Not currently
  // necessary since a chunked body is never merged with headers, but this makes
  // the test more future proof.
  base::RunLoop().RunUntilIdle();

  upload_data_stream.AppendData(base::byte_span_from_cstring("last chunk"),
                                true);

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.0 400 Not OK", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);
}

TEST_P(HttpNetworkTransactionTest, PostReadsErrorResponseAfterResetAnd100) {
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

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 3\r\n\r\n"),
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 100 Continue\r\n\r\n"),
      MockRead("HTTP/1.0 400 Not OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.0 400 Not OK", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);
}

TEST_P(HttpNetworkTransactionTest, PostIgnoresNonErrorResponseAfterReset) {
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

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 3\r\n\r\n"),
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 Just Dandy\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));
}

TEST_P(HttpNetworkTransactionTest,
       PostIgnoresNonErrorResponseAfterResetAnd100) {
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

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 3\r\n\r\n"),
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 100 Continue\r\n\r\n"),
      MockRead("HTTP/1.0 302 Redirect\r\n"),
      MockRead("Location: http://somewhere-else.com/\r\n"),
      MockRead("Content-Length: 0\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));
}

TEST_P(HttpNetworkTransactionTest, PostIgnoresHttp09ResponseAfterReset) {
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

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 3\r\n\r\n"),
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
      MockRead("HTTP 0.9 rocks!"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));
}

TEST_P(HttpNetworkTransactionTest, PostIgnoresPartial400HeadersAfterReset) {
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

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 3\r\n\r\n"),
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 400 Not a Full Response\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));
}

#if BUILDFLAG(ENABLE_WEBSOCKETS)

namespace {

void AddWebSocketHeaders(HttpRequestHeaders* headers) {
  headers->SetHeader("Connection", "Upgrade");
  headers->SetHeader("Upgrade", "websocket");
  headers->SetHeader("Origin", "http://www.example.org");
  headers->SetHeader("Sec-WebSocket-Version", "13");
}

}  // namespace

TEST_P(HttpNetworkTransactionTest, CreateWebSocketHandshakeStream) {
  for (bool secure : {true, false}) {
    MockWrite data_writes[] = {
        MockWrite("GET / HTTP/1.1\r\n"
                  "Host: www.example.org\r\n"
                  "Connection: Upgrade\r\n"
                  "Upgrade: websocket\r\n"
                  "Origin: http://www.example.org\r\n"
                  "Sec-WebSocket-Version: 13\r\n"
                  "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                  "Sec-WebSocket-Extensions: permessage-deflate; "
                  "client_max_window_bits\r\n\r\n")};

    MockRead data_reads[] = {
        MockRead("HTTP/1.1 101 Switching Protocols\r\n"
                 "Upgrade: websocket\r\n"
                 "Connection: Upgrade\r\n"
                 "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")};

    StaticSocketDataProvider data(data_reads, data_writes);
    session_deps_.socket_factory->AddSocketDataProvider(&data);
    SSLSocketDataProvider ssl(ASYNC, OK);
    if (secure) {
      session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
    }

    HttpRequestInfo request;
    request.method = "GET";
    request.url =
        GURL(secure ? "ws://www.example.org/" : "wss://www.example.org/");
    AddWebSocketHeaders(&request.extra_headers);
    request.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

    TestWebSocketHandshakeStreamCreateHelper
        websocket_handshake_stream_create_helper;

    std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
    HttpNetworkTransaction trans(LOW, session.get());
    trans.SetWebSocketHandshakeStreamCreateHelper(
        &websocket_handshake_stream_create_helper);

    TestCompletionCallback callback;
    int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    const HttpStreamRequest* stream_request = trans.stream_request_.get();
    ASSERT_TRUE(stream_request);
    EXPECT_EQ(&websocket_handshake_stream_create_helper,
              stream_request->websocket_handshake_stream_create_helper());

    rv = callback.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    EXPECT_TRUE(data.AllReadDataConsumed());
    EXPECT_TRUE(data.AllWriteDataConsumed());
  }
}

// Verify that proxy headers are not sent to the destination server when
// establishing a tunnel for a secure WebSocket connection.
TEST_P(HttpNetworkTransactionTest, ProxyHeadersNotSentOverWssTunnel) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("wss://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  AddWebSocketHeaders(&request.extra_headers);

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "PROXY myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since a proxy is configured, try to establish a tunnel.
  MockWrite data_writes[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),

      // After calling trans->RestartWithAuth(), this is the request we should
      // be issuing -- the final header line contains the credentials.
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),

      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: Upgrade\r\n"
                "Upgrade: websocket\r\n"
                "Origin: http://www.example.org\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Extensions: permessage-deflate; "
                "client_max_window_bits\r\n\r\n")};

  // The proxy responds to the connect with a 407, using a persistent
  // connection.
  MockRead data_reads[] = {
      // No credentials.
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"
               "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"
               "Content-Length: 0\r\n"
               "Proxy-Connection: keep-alive\r\n"
               "User-Agent: test-ua\r\n\r\n"),

      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),

      MockRead("HTTP/1.1 101 Switching Protocols\r\n"
               "Upgrade: websocket\r\n"
               "Connection: Upgrade\r\n"
               "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")};

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestWebSocketHandshakeStreamCreateHelper websocket_stream_create_helper;

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  trans->SetWebSocketHandshakeStreamCreateHelper(
      &websocket_stream_create_helper);

  {
    TestCompletionCallback callback;

    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback.WaitForResult();
    EXPECT_THAT(rv, IsOk());
  }

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());

  {
    TestCompletionCallback callback;

    int rv = trans->RestartWithAuth(AuthCredentials(kFoo, kBar),
                                    callback.callback());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback.WaitForResult();
    EXPECT_THAT(rv, IsOk());
  }

  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);

  EXPECT_EQ(101, response->headers->response_code());

  trans.reset();
  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

// Verify that proxy headers are not sent to the destination server when
// establishing a tunnel for an insecure WebSocket connection.
// This requires the authentication info to be injected into the auth cache
// due to crbug.com/395064
// TODO(ricea): Change to use a 407 response once issue 395064 is fixed.
TEST_P(HttpNetworkTransactionTest, ProxyHeadersNotSentOverWsTunnel) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("ws://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  AddWebSocketHeaders(&request.extra_headers);

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "PROXY myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  MockWrite data_writes[] = {
      // Try to establish a tunnel for the WebSocket connection, with
      // credentials. Because WebSockets have a separate set of socket pools,
      // they cannot and will not use the same TCP/IP connection as the
      // preflight HTTP request.
      MockWrite("CONNECT www.example.org:80 HTTP/1.1\r\n"
                "Host: www.example.org:80\r\n"
                "Proxy-Connection: keep-alive\r\n"
           
"""


```