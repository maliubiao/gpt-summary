Response:
Let's break down the thought process for analyzing this code snippet and generating the detailed response.

**1. Understanding the Goal:**

The primary goal is to analyze a specific C++ source file (`http_network_transaction_unittest.cc`) from Chromium's network stack. The request asks for a breakdown of its functionality, connections to JavaScript, input/output examples, common usage errors, debugging guidance, and a summary of the provided excerpt.

**2. Initial Code Scan & Keyword Spotting:**

The first step is to quickly scan the code for recurring patterns and keywords. This helps establish the general context:

* **`TEST_P`**: Immediately signals that this is a parameterized unit test file.
* **`HttpNetworkTransactionTest`**:  Indicates that the tests are focused on the `HttpNetworkTransaction` class.
* **`session_deps_`**: Suggests dependency injection or setup for the network session.
* **`MockWrite`, `MockRead`, `SequencedSocketData`**:  Clearly points to mocking of network socket interactions for testing.
* **`spdy::SpdySerializedFrame`**:  Highlights the involvement of the SPDY/HTTP/2 protocol.
* **`HttpRequestInfo`**:  Represents the structure holding request details.
* **`HttpResponseInfo`**:  Represents the structure holding response details.
* **`TestCompletionCallback`**:  A common pattern for asynchronous testing.
* **`GURL`**:  Represents URLs.
* **`EXPECT_THAT`, `ASSERT_THAT`, `EXPECT_EQ`**:  Standard Google Test assertions.
* **`RetryWithoutConnectionPooling`, `ReturnHTTP421OnRetry`, `UseIPConnectionPoolingWithHostCacheExpiration`, `DoNotUseSpdySessionForHttp`, `AlternativeServiceNotOnHttp11`, `FailedAlternativeServiceIsNotUserVisible`**: These are descriptive test case names providing specific insights into the scenarios being tested.
* **`ERR_IO_PENDING`, `OK`, `ERR_CONNECTION_REFUSED`, `ERR_ALPN_NEGOTIATION_FAILED`**: Network error codes.
* **`NetLog`, `NetLogWithSource`, `RecordingNetLogObserver`**: Indicate the use of Chromium's network logging framework.
* **`ChunkedUploadDataStream`**:  Suggests testing of chunked HTTP requests.
* **`HostPortPair`, `NetworkAnonymizationKey`, `AlternativeService`**:  Concepts related to network configuration and optimization.

**3. Analyzing Individual Test Cases:**

The next step is to examine individual test cases to understand their specific purpose. For example:

* **`RetryWithoutConnectionPooling`**: The test simulates a "421 Misdirected Request" response and verifies that the transaction retries without connection pooling. It involves setting up two connections and specific read/write patterns.
* **`ReturnHTTP421OnRetry`**:  Similar to the previous one, but checks that the 421 error is correctly returned to the caller even on the retry attempt.
* **`UseIPConnectionPoolingWithHostCacheExpiration`**:  Focuses on how connection pooling interacts with host cache invalidation.
* **`DoNotUseSpdySessionForHttp`**:  Verifies that an existing HTTP/2 session isn't used for plain HTTP requests.
* **`AlternativeServiceNotOnHttp11`**: Tests the scenario where an alternative service requires HTTP/2, but the negotiation results in HTTP/1.1.
* **`FailedAlternativeServiceIsNotUserVisible`**:  Checks that a failed alternative service connection doesn't disrupt a successful connection to the origin server.

**4. Identifying Key Functionalities:**

Based on the test cases, we can deduce the main functionalities being tested:

* **Basic HTTP/2 request/response handling.**
* **Handling of the 421 "Misdirected Request" status code and retries.**
* **Connection pooling behavior (with and without IP pooling).**
* **Interaction with the host cache and DNS resolution.**
* **Alternative service functionality and its interaction with protocol negotiation.**
* **Ensuring HTTP/2 sessions are not used for HTTP requests.**
* **Handling chunked uploads.**

**5. Connecting to JavaScript (or Lack Thereof):**

A crucial part of the request is to identify connections to JavaScript. By analyzing the code, it becomes clear that this is a *unit test* file for the *network stack*. Unit tests typically focus on isolated components and don't directly interact with the browser's rendering engine or JavaScript execution environment. Therefore, the connection to JavaScript is indirect – the tested code is *used by* the browser when handling network requests initiated by JavaScript (e.g., `fetch`, `XMLHttpRequest`). This indirect relationship needs to be clearly explained.

**6. Input/Output and Logic Inference:**

For each test case, try to infer the intended input and expected output. This involves looking at:

* **`HttpRequestInfo`**: The input to the `HttpNetworkTransaction::Start` method.
* **`MockWrite`**: The simulated data sent by the client.
* **`MockRead`**: The simulated data received from the server.
* **`EXPECT_THAT(rv, IsOk())` or `EXPECT_THAT(rv, IsError(...))`**:  Verifies the overall success or failure of the transaction.
* **`trans.GetResponseInfo()`**:  Accesses the response details.
* **`ReadTransaction(&trans, &response_data)`**:  Reads the response body.

The logic inference comes from understanding the sequence of mocked network interactions and how the `HttpNetworkTransaction` class is expected to behave in those scenarios.

**7. Common Usage Errors and Debugging:**

Think about how developers using the `HttpNetworkTransaction` class might make mistakes. This often involves:

* **Incorrectly setting up `HttpRequestInfo` (e.g., wrong URL, method, headers).**
* **Mismatched read/write expectations in mock setups.**
* **Not handling asynchronous operations correctly (e.g., forgetting to wait for callbacks).**
* **Misunderstanding the behavior of connection pooling or alternative services.**

For debugging, emphasize the use of network logging (`chrome://net-export/`), which the tests themselves utilize. Explain how to trace user actions leading to network requests.

**8. Summarizing the Excerpt:**

Focus on the main themes demonstrated by the provided code snippet. In this case, it's heavily focused on:

* **Testing HTTP/2 interactions.**
* **Testing error handling, specifically the 421 status code.**
* **Testing connection pooling and its nuances.**
* **Testing alternative service behavior.**

**9. Structuring the Response:**

Organize the information logically with clear headings and bullet points. This makes the response easier to read and understand. Start with a high-level overview and then delve into specifics.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file tests HTTP requests."
* **Refinement:** "More specifically, it unit tests the `HttpNetworkTransaction` class, focusing on HTTP/2, error handling (like 421), connection pooling, and alternative services."
* **Initial thought:** "It's related to JavaScript because it handles network requests."
* **Refinement:** "The relationship is indirect. JavaScript in the browser uses the underlying network stack, which includes `HttpNetworkTransaction`. This file tests that component in isolation."
* **Consider edge cases:** "What happens if the retry for a 421 also fails? The tests cover that." "How does host cache invalidation affect connection pooling? There's a test for that too."

By following this structured thought process, including detailed code analysis and iterative refinement, we can generate a comprehensive and accurate response to the given prompt.
这是位于 `net/http/http_network_transaction_unittest.cc` 的 Chromium 网络栈源代码文件的一部分，主要功能是 **对 `HttpNetworkTransaction` 类进行单元测试**。`HttpNetworkTransaction` 是 Chromium 网络栈中负责执行 HTTP 请求的核心类之一。

**功能列举:**

这部分代码主要测试了 `HttpNetworkTransaction` 在以下场景下的行为：

1. **重试机制 (Retry):** 测试在收到 HTTP 421 "Misdirected Request" 响应时，`HttpNetworkTransaction` 能否正确地重试请求，并且在重试时不再尝试连接池化。
2. **HTTP 421 错误处理:** 测试当重试请求仍然收到 421 错误时，`HttpNetworkTransaction` 能否将该错误正确地返回给调用者，而不会进入无限循环或丢失部分响应数据。
3. **处理带流式 Body 的 421 响应:**  测试当收到带有流式请求体 (Chunked Upload) 的请求的 421 响应时，`HttpNetworkTransaction` 的处理逻辑，包括 `upload_data_stream` 的 `has_null_source` 为 true 和 false 两种情况。
4. **IP 连接池化与 Host Cache 过期:** 测试 IP 连接池化在 Host Cache 条目过期后的行为，确保在 Host Cache 过期后能正确建立新的连接。
5. **避免对 HTTP 请求使用 SPDY 会话:** 确保已建立的 SPDY 会话不会被用于处理普通的 HTTP 请求。
6. **替代服务 (Alternative Service) 的处理:**
    * 测试当替代服务需要 HTTP/2 但实际协商的是 HTTP/1.1 时，连接不会被使用。
    * 测试当与原始服务器连接成功时，即使与替代服务的连接失败（例如因为协议不匹配），请求仍然成功，并且失败的替代服务会被标记为 broken。

**与 Javascript 的关系及举例说明:**

`HttpNetworkTransaction` 本身是用 C++ 实现的，不直接与 Javascript 代码交互。但是，它的功能是支撑浏览器中由 Javascript 发起的网络请求的。

**举例说明:**

当 Javascript 代码使用 `fetch()` API 或 `XMLHttpRequest` 对象发起一个 HTTP 请求时，浏览器底层会使用 Chromium 的网络栈来处理这个请求。`HttpNetworkTransaction` 就是这个处理流程中的一个关键环节。

例如，以下 Javascript 代码：

```javascript
fetch('https://www.example.org/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当执行这段代码时，浏览器会创建并使用一个 `HttpNetworkTransaction` 实例来执行对 `https://www.example.org/data` 的 GET 请求。如果服务器返回 421 错误，并且代码逻辑符合测试用例 `RetryWithoutConnectionPooling` 的场景，那么 `HttpNetworkTransaction` 就会按照测试中验证的逻辑进行重试。

**逻辑推理 (假设输入与输出):**

**场景: `RetryWithoutConnectionPooling`**

**假设输入:**

1. 两个域名 `www.example.org` 和 `mail.example.org` 解析到相同的 IP 地址。
2. 发起对 `https://www.example.org` 的请求 (trans1)，服务器返回 200 OK。
3. 发起对 `https://mail.example.org` 的请求 (trans2)，服务器返回 421 Misdirected Request。

**预期输出:**

1. `trans1` 请求成功，返回 200 OK 响应。
2. `trans2` 请求会因为收到 421 而触发重试。
3. 重试时，会建立一个新的连接，而不是尝试重用之前的连接。
4. 重试成功，`trans2` 请求最终返回 200 OK 响应。
5. NetLog 中会包含 `HTTP_TRANSACTION_RESTART_MISDIRECTED_REQUEST` 事件。

**常见的使用错误及举例说明:**

虽然用户不直接操作 `HttpNetworkTransaction`，但编程人员在使用 Chromium 的网络库进行嵌入式开发或测试时，可能会遇到以下错误：

1. **错误地配置 Mock 数据:** 在测试中，如果 `MockRead` 和 `MockWrite` 的数据与实际预期的网络交互不符，会导致测试失败。
    *   **例子:**  `spdy_writes` 定义了发送的请求帧，如果请求的 URL 或头部信息错误，服务器可能不会返回预期的响应，导致测试断言失败。
2. **未正确处理异步完成回调:** `HttpNetworkTransaction::Start` 是异步的，如果忘记等待 `TestCompletionCallback` 的结果，就可能在事务完成前就检查结果，导致程序行为不确定。
    *   **例子:**  如果在 `callback1.WaitForResult()` 之前就去访问 `trans1.GetResponseInfo()`，可能会得到空指针或未完成的数据。
3. **对连接池化行为的误解:**  开发者可能错误地假设连接总是会被重用，而忽略了像 421 错误这样的场景会导致连接不再被池化。
    *   **例子:**  在测试 `RetryWithoutConnectionPooling` 中，如果开发者错误地认为第二个请求会重用第一个请求的连接，他们可能会配置错误的 `MockRead` 和 `MockWrite` 数据，导致测试失败。

**用户操作到达这里的步骤 (作为调试线索):**

通常，用户不会直接触发 `HttpNetworkTransaction` 的执行。以下是一个简化的用户操作流程，最终会导致代码执行到这里（假设正在调试 Chromium 浏览器）：

1. **用户在浏览器地址栏输入 URL 并回车，或点击一个链接。**
2. **浏览器进程接收到请求。**
3. **浏览器进程调用网络服务进程 (Network Service)。**
4. **网络服务进程中的 URLRequestContext 会创建一个 HttpNetworkTransaction 对象。**
5. **`HttpNetworkTransaction::Start()` 方法被调用，开始处理请求。**
6. **如果请求的服务器返回 421 错误，`HttpNetworkTransaction` 会根据内部逻辑进行重试，这部分逻辑就在上述代码的测试用例中被覆盖。**
7. **调试时，开发者可以在 `HttpNetworkTransaction::Start()` 或处理 421 响应的相关代码处设置断点，来观察程序的执行流程。**
8. **查看 NetLog (`chrome://net-export/`) 可以更详细地了解网络请求的生命周期，包括是否发生重试，以及连接池化的使用情况。**

**功能归纳 (基于第 26 部分，共 34 部分):**

这部分测试代码主要集中在 **`HttpNetworkTransaction` 对 HTTP/2 协议下特定场景的处理，特别是与连接管理和错误恢复相关的逻辑**。它深入测试了在收到 421 错误时，`HttpNetworkTransaction` 如何进行重试，以及如何与连接池化、Host Cache 和替代服务等机制进行交互。这表明 `HttpNetworkTransaction` 的一个重要职责是确保网络请求的可靠性和效率，即使在遇到特定的服务器错误或网络配置时也能正常工作。这部分测试也覆盖了在存在替代服务的情况下，`HttpNetworkTransaction` 如何选择合适的连接方式，并处理协议不匹配的情况。

总而言之，这部分代码通过单元测试确保了 `HttpNetworkTransaction` 在处理复杂的 HTTP/2 场景下的正确行为，保证了 Chromium 浏览器的网络功能的稳定性和可靠性。

### 提示词
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第26部分，共34部分，请归纳一下它的功能
```

### 源代码
```cpp
ssion_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet("http://request1.test/", 1, LOWEST));
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame data(spdy_util_.ConstructSpdyDataFrame(1, true));

  MockWrite spdy_writes[] = {CreateMockWrite(req, 0)};

  MockRead spdy_reads[] = {CreateMockRead(resp, 1), CreateMockRead(data, 2),
                           // Pause reads so that the socket will remain open
                           // (so we can see whether it gets re-used below).
                           MockRead(ASYNC, ERR_IO_PENDING, 3),
                           MockRead(ASYNC, 0, 4)};

  IPEndPoint peer_addr(IPAddress::IPv4Localhost(), 443);
  MockConnect connect(ASYNC, OK, peer_addr);
  SequencedSocketData spdy_data(connect, spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  AddSSLSocketData();

  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("http://request1.test/");
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, session.get());

  int rv = trans1.Start(&request1, callback1.callback(),
                        NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans1.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans1, &response_data), IsOk());
  EXPECT_EQ(kUploadData, response_data);

  proxy_delegate->set_proxy_chain(kProxyServer2Chain);

  SpdyTestUtil req2_spdy_util(/*use_priority_header=*/true);
  spdy::SpdySerializedFrame req2(
      req2_spdy_util.ConstructSpdyGet("http://request2.test/", 1, LOWEST));

  spdy::SpdySerializedFrame resp2(
      req2_spdy_util.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame data2(
      req2_spdy_util.ConstructSpdyDataFrame(1, true));

  MockWrite spdy_writes2[] = {CreateMockWrite(req2, 0)};

  MockRead spdy_reads2[] = {
      CreateMockRead(resp2, 1),
      CreateMockRead(data2, 2),
      MockRead(ASYNC, 0, 3),
  };

  SequencedSocketData spdy_data2(connect, spdy_reads2, spdy_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data2);

  AddSSLSocketData();

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("http://request2.test/");
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  TestCompletionCallback callback2;

  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());

  rv = trans2.Start(&request2, callback2.callback(),
                    NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  response = trans2.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
}

// Regression test for https://crbug.com/546991.
// The server might not be able to serve an IP pooled request, and might send a
// 421 Misdirected Request response status to indicate this.
// HttpNetworkTransaction should reset the request and retry without IP pooling.
TEST_P(HttpNetworkTransactionTest, RetryWithoutConnectionPooling) {
  // Two hosts resolve to the same IP address.
  const std::string ip_addr = "1.2.3.4";
  IPAddress ip;
  ASSERT_TRUE(ip.AssignFromIPLiteral(ip_addr));
  IPEndPoint peer_addr = IPEndPoint(ip, 443);

  session_deps_.host_resolver = std::make_unique<MockCachingHostResolver>();
  session_deps_.host_resolver->rules()->AddRule("www.example.org", ip_addr);
  session_deps_.host_resolver->rules()->AddRule("mail.example.org", ip_addr);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Two requests on the first connection.
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet("https://www.example.org", 1, LOWEST));
  spdy_util_.UpdateWithStreamDestruction(1);
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet("https://mail.example.org", 3, LOWEST));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(3, spdy::ERROR_CODE_CANCEL));
  MockWrite writes1[] = {
      CreateMockWrite(req1, 0),
      CreateMockWrite(req2, 3),
      CreateMockWrite(rst, 6),
  };

  // The first one succeeds, the second gets error 421 Misdirected Request.
  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  quiche::HttpHeaderBlock response_headers;
  response_headers[spdy::kHttp2StatusHeader] = "421";
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyReply(3, std::move(response_headers)));
  MockRead reads1[] = {CreateMockRead(resp1, 1), CreateMockRead(body1, 2),
                       CreateMockRead(resp2, 4), MockRead(ASYNC, 0, 5)};

  MockConnect connect1(ASYNC, OK, peer_addr);
  SequencedSocketData data1(connect1, reads1, writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  AddSSLSocketData();

  // Retry the second request on a second connection.
  SpdyTestUtil spdy_util2(/*use_priority_header=*/true);
  spdy::SpdySerializedFrame req3(
      spdy_util2.ConstructSpdyGet("https://mail.example.org", 1, LOWEST));
  MockWrite writes2[] = {
      CreateMockWrite(req3, 0),
  };

  spdy::SpdySerializedFrame resp3(
      spdy_util2.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body3(spdy_util2.ConstructSpdyDataFrame(1, true));
  MockRead reads2[] = {CreateMockRead(resp3, 1), CreateMockRead(body3, 2),
                       MockRead(ASYNC, 0, 3)};

  MockConnect connect2(ASYNC, OK, peer_addr);
  SequencedSocketData data2(connect2, reads2, writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  AddSSLSocketData();

  // Preload mail.example.org into HostCache.
  int rv = session_deps_.host_resolver->LoadIntoCache(
      HostPortPair("mail.example.org", 443), NetworkAnonymizationKey(),
      std::nullopt);
  EXPECT_THAT(rv, IsOk());

  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org/");
  request1.load_flags = 0;
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  rv = trans1.Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans1.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans1, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://mail.example.org/");
  request2.load_flags = 0;
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());

  RecordingNetLogObserver net_log_observer;
  rv = trans2.Start(&request2, callback.callback(),
                    NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans2.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  ASSERT_THAT(ReadTransaction(&trans2, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);

  auto entries = net_log_observer.GetEntries();
  ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP_TRANSACTION_RESTART_MISDIRECTED_REQUEST,
      NetLogEventPhase::NONE);
}

// Test that HTTP 421 responses are properly returned to the caller if received
// on the retry as well. HttpNetworkTransaction should not infinite loop or lose
// portions of the response.
TEST_P(HttpNetworkTransactionTest, ReturnHTTP421OnRetry) {
  // Two hosts resolve to the same IP address.
  const std::string ip_addr = "1.2.3.4";
  IPAddress ip;
  ASSERT_TRUE(ip.AssignFromIPLiteral(ip_addr));
  IPEndPoint peer_addr = IPEndPoint(ip, 443);

  session_deps_.host_resolver = std::make_unique<MockCachingHostResolver>();
  session_deps_.host_resolver->rules()->AddRule("www.example.org", ip_addr);
  session_deps_.host_resolver->rules()->AddRule("mail.example.org", ip_addr);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Two requests on the first connection.
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet("https://www.example.org", 1, LOWEST));
  spdy_util_.UpdateWithStreamDestruction(1);
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet("https://mail.example.org", 3, LOWEST));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(3, spdy::ERROR_CODE_CANCEL));
  MockWrite writes1[] = {
      CreateMockWrite(req1, 0),
      CreateMockWrite(req2, 3),
      CreateMockWrite(rst, 6),
  };

  // The first one succeeds, the second gets error 421 Misdirected Request.
  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  quiche::HttpHeaderBlock response_headers;
  response_headers[spdy::kHttp2StatusHeader] = "421";
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyReply(3, response_headers.Clone()));
  MockRead reads1[] = {CreateMockRead(resp1, 1), CreateMockRead(body1, 2),
                       CreateMockRead(resp2, 4), MockRead(ASYNC, 0, 5)};

  MockConnect connect1(ASYNC, OK, peer_addr);
  SequencedSocketData data1(connect1, reads1, writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  AddSSLSocketData();

  // Retry the second request on a second connection. It returns 421 Misdirected
  // Retry again.
  SpdyTestUtil spdy_util2(/*use_priority_header=*/true);
  spdy::SpdySerializedFrame req3(
      spdy_util2.ConstructSpdyGet("https://mail.example.org", 1, LOWEST));
  MockWrite writes2[] = {
      CreateMockWrite(req3, 0),
  };

  spdy::SpdySerializedFrame resp3(
      spdy_util2.ConstructSpdyReply(1, std::move(response_headers)));
  spdy::SpdySerializedFrame body3(spdy_util2.ConstructSpdyDataFrame(1, true));
  MockRead reads2[] = {CreateMockRead(resp3, 1), CreateMockRead(body3, 2),
                       MockRead(ASYNC, 0, 3)};

  MockConnect connect2(ASYNC, OK, peer_addr);
  SequencedSocketData data2(connect2, reads2, writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  AddSSLSocketData();

  // Preload mail.example.org into HostCache.
  int rv = session_deps_.host_resolver->LoadIntoCache(
      HostPortPair("mail.example.org", 443), NetworkAnonymizationKey(),
      std::nullopt);
  EXPECT_THAT(rv, IsOk());

  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org/");
  request1.load_flags = 0;
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  rv = trans1.Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans1.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans1, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://mail.example.org/");
  request2.load_flags = 0;
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());

  rv = trans2.Start(&request2, callback.callback(),
                    NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  // After a retry, the 421 Misdirected Request is reported back up to the
  // caller.
  response = trans2.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 421", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  EXPECT_TRUE(response->ssl_info.cert);
  ASSERT_THAT(ReadTransaction(&trans2, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
}

TEST_P(HttpNetworkTransactionTest,
       Response421WithStreamingBodyWithNonNullSource) {
  const std::string ip_addr = "1.2.3.4";
  IPAddress ip;
  ASSERT_TRUE(ip.AssignFromIPLiteral(ip_addr));
  IPEndPoint peer_addr = IPEndPoint(ip, 443);

  session_deps_.host_resolver = std::make_unique<MockCachingHostResolver>();
  session_deps_.host_resolver->rules()->AddRule("www.example.org", ip_addr);
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  const std::string request_body = "hello";
  spdy::SpdySerializedFrame req1 = spdy_util_.ConstructChunkedSpdyPost({}, 0);
  spdy::SpdySerializedFrame req1_body =
      spdy_util_.ConstructSpdyDataFrame(1, request_body, /*fin=*/true);
  spdy::SpdySerializedFrame rst =
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL);
  MockWrite writes1[] = {
      CreateMockWrite(req1, 0),
      CreateMockWrite(req1_body, 1),
      CreateMockWrite(rst, 4),
  };

  quiche::HttpHeaderBlock response_headers;
  response_headers[spdy::kHttp2StatusHeader] = "421";
  spdy::SpdySerializedFrame resp1 =
      spdy_util_.ConstructSpdyReply(1, std::move(response_headers));
  MockRead reads1[] = {CreateMockRead(resp1, 2), MockRead(ASYNC, 0, 3)};

  MockConnect connect1(ASYNC, OK, peer_addr);
  SequencedSocketData data1(connect1, reads1, writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  AddSSLSocketData();

  SpdyTestUtil spdy_util2(/*use_priority_header=*/true);
  spdy::SpdySerializedFrame req2 = spdy_util2.ConstructChunkedSpdyPost({}, 0);
  spdy::SpdySerializedFrame req2_body =
      spdy_util2.ConstructSpdyDataFrame(1, request_body, /*fin=*/true);
  MockWrite writes2[] = {
      CreateMockWrite(req2, 0),
      CreateMockWrite(req2_body, 1),
  };

  quiche::HttpHeaderBlock resp2_headers;
  resp2_headers[spdy::kHttp2StatusHeader] = "200";
  spdy::SpdySerializedFrame resp2 =
      spdy_util2.ConstructSpdyReply(1, std::move(resp2_headers));
  spdy::SpdySerializedFrame resp2_body(
      spdy_util2.ConstructSpdyDataFrame(1, true));
  MockRead reads2[] = {CreateMockRead(resp2, 2), CreateMockRead(resp2_body, 3),
                       MockRead(ASYNC, 0, 4)};

  MockConnect connect2(ASYNC, OK, peer_addr);
  SequencedSocketData data2(connect2, reads2, writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  AddSSLSocketData();

  TestCompletionCallback callback;
  HttpRequestInfo request;
  ChunkedUploadDataStream upload_data_stream(0, /*has_null_source=*/false);
  upload_data_stream.AppendData(base::as_byte_span(request_body),
                                /*is_done=*/true);
  request.method = "POST";
  request.url = GURL("https://www.example.org");
  request.load_flags = 0;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  request.upload_data_stream = &upload_data_stream;
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  std::string response_data;
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  EXPECT_TRUE(response->ssl_info.cert);
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
}

TEST_P(HttpNetworkTransactionTest, Response421WithStreamingBodyWithNullSource) {
  const std::string ip_addr = "1.2.3.4";
  IPAddress ip;
  ASSERT_TRUE(ip.AssignFromIPLiteral(ip_addr));
  IPEndPoint peer_addr = IPEndPoint(ip, 443);

  session_deps_.host_resolver = std::make_unique<MockCachingHostResolver>();
  session_deps_.host_resolver->rules()->AddRule("www.example.org", ip_addr);
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  const std::string request_body = "hello";
  spdy::SpdySerializedFrame req1 = spdy_util_.ConstructChunkedSpdyPost({}, 0);
  spdy::SpdySerializedFrame req1_body =
      spdy_util_.ConstructSpdyDataFrame(1, request_body, /*fin=*/true);
  spdy::SpdySerializedFrame rst =
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL);
  MockWrite writes1[] = {
      CreateMockWrite(req1, 0),
      CreateMockWrite(req1_body, 1),
      CreateMockWrite(rst, 5),
  };

  quiche::HttpHeaderBlock response_headers;
  response_headers[spdy::kHttp2StatusHeader] = "421";
  spdy::SpdySerializedFrame resp1 =
      spdy_util_.ConstructSpdyReply(1, std::move(response_headers));
  spdy::SpdySerializedFrame resp1_body(
      spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads1[] = {CreateMockRead(resp1, 2), CreateMockRead(resp1_body, 3),
                       MockRead(ASYNC, 0, 4)};

  MockConnect connect1(ASYNC, OK, peer_addr);
  SequencedSocketData data1(connect1, reads1, writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  AddSSLSocketData();

  TestCompletionCallback callback;
  HttpRequestInfo request;
  ChunkedUploadDataStream upload_data_stream(0, /*has_null_source=*/true);
  upload_data_stream.AppendData(base::as_byte_span(request_body),
                                /*is_done=*/true);
  request.method = "POST";
  request.url = GURL("https://www.example.org");
  request.load_flags = 0;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  request.upload_data_stream = &upload_data_stream;
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  std::string response_data;
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 421", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  EXPECT_TRUE(response->ssl_info.cert);
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
}

TEST_P(HttpNetworkTransactionTest,
       UseIPConnectionPoolingWithHostCacheExpiration) {
  // Set up HostResolver to invalidate cached entries after 1 cached resolve.
  session_deps_.host_resolver =
      std::make_unique<MockCachingHostResolver>(1 /* cache_invalidation_num */);
  session_deps_.host_resolver->rules()->AddRule("www.example.org", "1.2.3.4");
  session_deps_.host_resolver->rules()->AddRule("mail.example.com", "1.2.3.4");
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  AddSSLSocketData();

  spdy::SpdySerializedFrame host1_req(
      spdy_util_.ConstructSpdyGet("https://www.example.org", 1, LOWEST));
  spdy_util_.UpdateWithStreamDestruction(1);
  spdy::SpdySerializedFrame host2_req(
      spdy_util_.ConstructSpdyGet("https://mail.example.com", 3, LOWEST));
  MockWrite spdy_writes[] = {
      CreateMockWrite(host1_req, 0),
      CreateMockWrite(host2_req, 3),
  };
  spdy::SpdySerializedFrame host1_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame host1_resp_body(
      spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame host2_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame host2_resp_body(
      spdy_util_.ConstructSpdyDataFrame(3, true));
  MockRead spdy_reads[] = {
      CreateMockRead(host1_resp, 1), CreateMockRead(host1_resp_body, 2),
      CreateMockRead(host2_resp, 4), CreateMockRead(host2_resp_body, 5),
      MockRead(ASYNC, 0, 6),
  };

  IPEndPoint peer_addr(IPAddress::IPv4Localhost(), 443);
  MockConnect connect(ASYNC, OK, peer_addr);
  SequencedSocketData spdy_data(connect, spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  TestCompletionCallback callback;
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org/");
  request1.load_flags = 0;
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, session.get());

  int rv = trans1.Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans1.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans1, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);

  // Preload cache entries into HostCache.
  rv = session_deps_.host_resolver->LoadIntoCache(
      HostPortPair("mail.example.com", 443), NetworkAnonymizationKey(),
      std::nullopt);
  EXPECT_THAT(rv, IsOk());

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://mail.example.com/");
  request2.load_flags = 0;
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());

  rv = trans2.Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  response = trans2.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  ASSERT_THAT(ReadTransaction(&trans2, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
}

TEST_P(HttpNetworkTransactionTest, DoNotUseSpdySessionForHttp) {
  const std::string https_url = "https://www.example.org:8080/";
  const std::string http_url = "http://www.example.org:8080/";

  // SPDY GET for HTTPS URL
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(https_url.c_str(), 1, LOWEST));

  MockWrite writes1[] = {
      CreateMockWrite(req1, 0),
  };

  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads1[] = {CreateMockRead(resp1, 1), CreateMockRead(body1, 2),
                       MockRead(SYNCHRONOUS, ERR_IO_PENDING, 3)};

  SequencedSocketData data1(reads1, writes1);
  MockConnect connect_data1(ASYNC, OK);
  data1.set_connect_data(connect_data1);

  // HTTP GET for the HTTP URL
  MockWrite writes2[] = {
      MockWrite(ASYNC, 0,
                "GET / HTTP/1.1\r\n"
                "Host: www.example.org:8080\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead reads2[] = {
      MockRead(ASYNC, 1, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"),
      MockRead(ASYNC, 2, "hello"),
      MockRead(ASYNC, OK, 3),
  };

  SequencedSocketData data2(reads2, writes2);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Start the first transaction to set up the SpdySession
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL(https_url);
  request1.load_flags = 0;
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpNetworkTransaction trans1(LOWEST, session.get());
  TestCompletionCallback callback1;
  EXPECT_EQ(ERR_IO_PENDING,
            trans1.Start(&request1, callback1.callback(), NetLogWithSource()));
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_TRUE(trans1.GetResponseInfo()->was_fetched_via_spdy);

  // Now, start the HTTP request
  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL(http_url);
  request2.load_flags = 0;
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpNetworkTransaction trans2(MEDIUM, session.get());
  TestCompletionCallback callback2;
  EXPECT_EQ(ERR_IO_PENDING,
            trans2.Start(&request2, callback2.callback(), NetLogWithSource()));
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_FALSE(trans2.GetResponseInfo()->was_fetched_via_spdy);
}

// Alternative service requires HTTP/2 (or SPDY), but HTTP/1.1 is negotiated
// with the alternative server.  That connection should not be used.
TEST_P(HttpNetworkTransactionTest, AlternativeServiceNotOnHttp11) {
  url::SchemeHostPort server("https", "www.example.org", 443);
  HostPortPair alternative("www.example.org", 444);

  // Negotiate HTTP/1.1 with alternative.
  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  // No data should be read from the alternative, because HTTP/1.1 is
  // negotiated.
  StaticSocketDataProvider data;
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  // This test documents that an alternate Job should not be used if HTTP/1.1 is
  // negotiated.  In order to test this, a failed connection to the server is
  // mocked.  This way the request relies on the alternate Job.
  StaticSocketDataProvider data_refused;
  data_refused.set_connect_data(MockConnect(ASYNC, ERR_CONNECTION_REFUSED));
  session_deps_.socket_factory->AddSocketDataProvider(&data_refused);

  // Set up alternative service for server.
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  AlternativeService alternative_service(kProtoHTTP2, alternative);
  base::Time expiration = base::Time::Now() + base::Days(1);
  http_server_properties->SetHttp2AlternativeService(
      server, NetworkAnonymizationKey(), alternative_service, expiration);

  HttpRequestInfo request;
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  request.method = "GET";
  request.url = GURL("https://www.example.org:443");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  TestCompletionCallback callback;

  // HTTP/2 (or SPDY) is required for alternative service, if HTTP/1.1 is
  // negotiated, the alternate Job should fail with ERR_ALPN_NEGOTIATION_FAILED.
  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_ALPN_NEGOTIATION_FAILED));
}

// A request to a server with an alternative service fires two Jobs: one to the
// server, and an alternate one to the alternative server.  If the former
// succeeds, the request should succeed,  even if the latter fails because
// HTTP/1.1 is negotiated which is insufficient for alternative service.
TEST_P(HttpNetworkTransactionTest, FailedAlternativeServiceIsNotUserVisible) {
  url::SchemeHostPort server("https", "www.example.org", 443);
  HostPortPair alternative("www.example.org", 444);

  // Negotiate HTTP/1.1 with alternative.
  SSLSocketDataProvider alternative_ssl(ASYNC, OK);
  alternative_ssl.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&alternative_ssl);

  // No data should be read from the alternative, because HTTP/1.1 is
  // negotiated.
  StaticSocketDataProvider data;
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  // Negotiate HTTP/1.1 with server.
  SSLSocketDataProvider origin_ssl(ASYNC, OK);
  origin_ssl.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&origin_ssl);

  MockWrite http_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
      MockWrite("GET /second HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html\r\n"),
      MockRead("Content-Length: 6\r\n\r\n"),
      MockRead("foobar"),
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html\r\n"),
      MockRead("Content-Length: 7\r\n\r\n"),
      MockRead("another"),
  };
  StaticSocketDataProvider http_data(http_reads, http_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&http_data);

  // Set up alternative service for server.
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  AlternativeService alternative_service(kProtoHTTP2, alternative);
  base::Time expiration = base::Time::Now() + base::Days(1);
  http_server_properties->SetHttp2AlternativeService(
      server, NetworkAnonymizationKey(), alternative_service, expiration);

  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, session.get());
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org:443");
  request1.load_flags = 0;
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  TestCompletionCallback callback1;

  int rv = trans1.Start(&request1, callback1.callback(), NetLogWithSource());
  rv = callback1.GetResult(rv);
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response1 = trans1.GetResponseInfo();
  ASSERT_TRUE(response1);
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response1->headers->GetStatusLine());

  std::string response_data1;
  ASSERT_THAT(ReadTransaction(&trans1, &response_data1), IsOk());
  EXPECT_EQ("foobar", response_data1);

  // Alternative should be marked as broken, because HTTP/1.1 is not sufficient
  // for alternative service.
  EXPECT_TRUE(http_server_properties->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));

  // Since |alternative_service| is broken, a second transaction to server
  // should not start an alternate Job.  It should pool to existing connection
  // to server.
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());
  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://www.example.org:443/second");
  request2.load_flags = 0;
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  TestCompletionCallback callback2;

  rv = trans2.Start(&request2, callback2.callback(), NetLog
```