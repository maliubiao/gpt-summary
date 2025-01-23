Response:
My thought process for analyzing the provided code snippet and generating the summary involved several steps:

1. **Understanding the Context:** I first noted the introductory sentence indicating the file's location (`net/http/http_network_transaction_unittest.cc`) and its purpose (testing the Chromium network stack). The mention of it being part 6 of 34 also gives a sense of the larger scope and the likelihood of it focusing on a specific area within network transactions.

2. **Identifying Key Classes and Concepts:**  I quickly scanned the code for recurring class names and concepts. The most prominent were:
    * `HttpNetworkTransaction`: This is clearly the central class being tested.
    * `HttpNetworkSession`:  Transactions operate within a session.
    * `HttpRequestInfo`:  Represents the details of an HTTP request.
    * `HttpResponseInfo`: Represents the details of an HTTP response.
    * `MockWrite`, `MockRead`, `SequencedSocketData`, `StaticSocketDataProvider`, `SSLSocketDataProvider`: These are all mocking utilities for simulating network interactions.
    * `ConfiguredProxyResolutionService`:  Deals with proxy settings.
    * `AuthCredentials`:  Represents authentication credentials.
    * `HttpAuthCache`:  Stores cached authentication information.
    * `NetworkAnonymizationKey`, `NetworkIsolationKey`:  Related to network partitioning for privacy and security.
    * `TEST_P`: Indicates parameterized tests, likely testing different scenarios.
    * `EXPECT_THAT`, `EXPECT_EQ`, `ASSERT_TRUE`, `ASSERT_FALSE`:  Google Test assertion macros.
    * `NetLog`, `RecordingNetLogObserver`: For logging network events.

3. **Analyzing Individual Test Cases:** I then looked at each `TEST_P` block individually to understand the specific scenario being tested. I focused on:
    * **Test Name:**  The name often gives a high-level indication of the test's purpose (e.g., `BasicAuthProxyKeepAliveExtraData`, `BasicAuthProxyCancelTunnel`).
    * **Setup:** How is the `HttpRequestInfo` configured? Are proxies being used? What kind of authentication is involved?  What are the expected socket interactions (mock reads and writes)?
    * **Actions:** What methods are called on the `HttpNetworkTransaction` object (e.g., `Start`, `RestartWithAuth`)?
    * **Assertions:** What are the expected outcomes based on the assertions?  Are response codes correct? Are headers as expected? Is authentication happening correctly?  Are cached credentials being used appropriately?

4. **Identifying Functional Themes:** As I analyzed the individual tests, I started to see recurring themes:
    * **Proxy Authentication:** A significant portion of the tests focuses on basic authentication in the context of HTTP proxies.
    * **Keep-Alive Connections:** Several tests deal with persistent connections and how authentication retries interact with them.
    * **Tunneling (HTTPS through a proxy):** Some tests specifically address the `CONNECT` method for establishing SSL tunnels via a proxy.
    * **Authentication Retries:** The tests explore scenarios where the server or proxy requires authentication, and the client needs to retry with credentials.
    * **Caching of Authentication Credentials:**  Tests verify that authentication credentials are being cached and reused correctly.
    * **Network Anonymization Key (NAK) and Network Isolation Key (NIK):**  Several tests examine how these keys affect the caching and reuse of authentication credentials, particularly server credentials.
    * **Handling Errors and Edge Cases:** Tests like `BasicAuthProxyKeepAliveHangupDuringBody` and `BasicAuthProxyCancelTunnel` explore how the transaction handles unexpected server behavior or user cancellation.

5. **Synthesizing the Functionality:** Based on the identified themes, I started to formulate a summary of the file's functionality. I aimed for a concise description covering the core areas being tested. I specifically noted the focus on proxy authentication, keep-alive, tunneling, error handling, and the impact of NAK/NIK.

6. **Considering Relationships with JavaScript:** I thought about how these network stack components might relate to JavaScript in a browser environment. JavaScript's `fetch` API or `XMLHttpRequest` ultimately relies on these underlying network mechanisms. Authentication challenges, proxy settings, and connection management are all relevant to how web requests are handled.

7. **Constructing Examples and Use Cases:** For the logical reasoning and user error sections, I tried to create concrete examples based on the test scenarios. This involved imagining specific user actions or coding mistakes that would lead to the tested situations.

8. **Tracing User Operations:**  For the debugging section, I considered the typical flow of a user interaction that would trigger these network requests, such as clicking a link or submitting a form.

9. **Structuring the Output:** Finally, I organized the information into the requested categories (功能, 与JavaScript的关系, 逻辑推理, 用户或编程常见的使用错误, 用户操作步骤, 功能归纳), using clear and concise language. I made sure to address each point in the prompt.

Essentially, my process involved a combination of code reading, pattern recognition, conceptual understanding of networking principles, and the ability to connect low-level code to higher-level user interactions and programming practices. The fact that the code was test code was crucial, as it explicitly demonstrated the intended behavior and edge cases.
好的，让我们来分析一下这个代码文件 `net/http/http_network_transaction_unittest.cc` 的第 6 部分 (共 34 部分) 的功能。

**功能归纳 (第6部分):**

这部分代码主要集中在 **HTTP 代理身份验证 (Proxy Authentication)** 的各种测试场景，特别是 **Basic 身份验证**，并且深入探讨了在保持连接 (Keep-Alive) 和使用 SSL 隧道 (HTTPS) 的情况下，身份验证的重试机制和错误处理。此外，它还涉及了 **Network Anonymization Key (NAK)** 对身份验证凭据缓存的影响。

**更详细的功能点:**

1. **基本的代理身份验证流程 (Basic Proxy Authentication):**
   - 测试了在没有提供凭据的情况下，服务器返回 `407 Proxy Authentication Required` 响应，客户端收到质询 (challenge) 的情况。
   - 测试了客户端在收到质询后，使用正确的凭据重新发送请求并成功建立连接的情况。
   - 测试了当代理服务器在发送 `407` 响应后，连接被关闭的情况。

2. **保持连接 (Keep-Alive) 与代理身份验证:**
   - 测试了在代理服务器支持 Keep-Alive 的情况下，客户端如何处理 `407` 响应并进行身份验证重试。
   - 测试了代理服务器在发送 `407` 响应后发送额外数据，导致连接无法重用的情况。
   - 测试了在接收到 `407` 响应的 Body 过程中，代理服务器断开连接的情况。

3. **SSL 隧道 (HTTPS) 与代理身份验证:**
   - 测试了在使用代理访问 HTTPS 网站时，建立 SSL 隧道的过程中，代理服务器返回 `407` 响应，客户端进行身份验证重试的情况。
   - 测试了在建立 SSL 隧道时，用户取消代理身份验证尝试的情况。

4. **无隧道 HTTP 身份验证:**
   - 测试了在不建立隧道的情况下，直接与代理服务器进行 HTTP 身份验证的场景。
   - 重点测试了当代理服务器和目标服务器的域名和 Realm 相同，但需要不同的用户名/密码时，客户端如何正确处理并缓存凭据。

5. **Network Anonymization Key (NAK) 对身份验证的影响:**
   - 深入测试了 NAK 如何影响 HTTP 代理和服务器身份验证凭据的缓存。
   - 验证了代理身份验证凭据在不同的 NAK 下可以共享，而服务器身份验证凭据则根据 NAK 进行隔离缓存。
   - 同时测试了有隧道和无隧道两种情况下 NAK 的影响。

**与 JavaScript 的关系:**

这些测试直接关系到浏览器中 JavaScript 发起网络请求时的行为。当 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起请求，并且需要通过代理服务器进行身份验证时，底层的网络栈就会执行这些测试中涉及的逻辑。

**举例说明:**

假设一个网站部署在一个需要身份验证的内部网络中，用户通过配置了代理服务器的浏览器访问该网站。

1. **场景一：首次访问需要代理身份验证的 HTTPS 网站 (对应 `BasicAuthProxyKeepAliveExtraData` 等测试):**
   - **用户操作:** 用户在浏览器地址栏输入 `https://internal.example.com` 并回车。
   - **JavaScript 行为:**  页面可能没有显式的 JavaScript 代码直接参与首次身份验证，但浏览器的网络层会发起请求。
   - **底层行为 (测试覆盖):**  `HttpNetworkTransaction` 会尝试通过代理建立 SSL 隧道 (CONNECT 请求)。代理返回 `407`，浏览器会提示用户输入代理用户名和密码。用户输入后，`HttpNetworkTransaction` 会使用提供的凭据重新发送 CONNECT 请求。

2. **场景二：JavaScript 使用 `fetch` 访问需要代理身份验证的 HTTP 网站 (对应 `BasicAuthProxyMatchesServerAuthNoTunnel` 等测试):**
   - **用户操作:**  用户访问一个网页，该网页的 JavaScript 代码使用 `fetch('http://internal.example.com/api')` 发起请求。
   - **JavaScript 行为:** `fetch` API 发起请求。
   - **底层行为 (测试覆盖):** `HttpNetworkTransaction` 发起对代理服务器的请求。如果代理返回 `407`，且需要服务器身份验证 (例如返回 `401`)，则会涉及多次重试，可能需要用户提供代理和服务器的凭据。测试会验证凭据是否被正确缓存和用于后续请求。

**逻辑推理与假设输入输出:**

**测试场景:** `BasicAuthProxyCancelTunnel`

**假设输入:**

- `HttpRequestInfo`: 请求方法为 "GET"，URL 为 "https://www.example.org/"，配置了代理服务器 "myproxy:70"。
- `MockWrite`: 模拟发送到代理服务器的 CONNECT 请求头。
- `MockRead`: 模拟代理服务器返回的 `407 Proxy Authentication Required` 响应头，包含 Content-Length 和部分响应体数据。

**逻辑推理:**

1. `HttpNetworkTransaction` 发起 CONNECT 请求。
2. 接收到 `407` 响应，表明需要代理身份验证。
3. 测试用例中没有调用 `RestartWithAuth` 提供凭据，模拟用户可能取消了身份验证的场景。
4. 尝试读取响应体数据。

**预期输出:**

- `Start` 方法返回 `ERR_IO_PENDING`。
- `callback.WaitForResult()` 返回 `OK` (表示初始连接尝试完成，即使需要身份验证)。
- `GetResponseInfo()->headers->response_code()` 为 `407`。
- `ReadTransaction` 方法返回 `ERR_TUNNEL_CONNECTION_FAILED`，因为隧道建立失败，并且没有提供有效的身份验证。

**用户或编程常见的使用错误:**

1. **未正确处理 `407` 响应:** 程序员在实现 HTTP 客户端时，如果没有正确处理 `407` 状态码，并提示用户输入代理凭据或自动重试，会导致请求失败。
   - **例子:** JavaScript 代码使用 `XMLHttpRequest` 发起请求，但没有监听 `readyState` 和 `status` 来处理 `407` 状态，导致请求停滞。

2. **缓存凭据管理不当:** 浏览器或应用程序在缓存代理或服务器身份验证凭据时出现错误，可能导致重复的身份验证提示或访问被拒绝。
   - **例子:** 错误地清空了凭据缓存，导致用户需要重新输入凭据。

3. **Network Anonymization Key 使用不当:**  在需要区分不同用户或上下文的场景下，如果 NAK 的使用不当，可能导致凭据混淆或意外的身份验证行为。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户尝试访问一个需要通过代理服务器才能访问的 HTTPS 网站。** 浏览器的网络配置中设置了代理服务器。
2. **浏览器发起对目标网站的请求。** 由于配置了代理，浏览器会先尝试与代理服务器建立连接。
3. **对于 HTTPS 网站，浏览器会先向代理服务器发送 `CONNECT` 请求，尝试建立 SSL 隧道。**
4. **代理服务器返回 `407 Proxy Authentication Required` 响应，指示需要代理身份验证。**
5. **如果浏览器配置了自动填充凭据的功能，可能会尝试使用缓存的凭据进行重试。**  相关的测试用例会模拟这种重试行为。
6. **如果用户没有配置自动填充，或者缓存的凭据无效，浏览器会提示用户输入代理服务器的用户名和密码。**
7. **用户输入凭据后，浏览器会使用这些凭据重新发送 `CONNECT` 请求。**
8. **如果凭据正确，代理服务器会返回 `200 Connection Established`，表示隧道建立成功。**
9. **浏览器通过建立的隧道，向目标 HTTPS 网站发送实际的请求。**

如果在上述过程中出现问题，例如代理服务器配置错误、凭据错误、代理服务器行为异常等，相关的测试用例可以帮助开发者理解和调试这些场景。例如，`BasicAuthProxyKeepAliveHangupDuringBody` 模拟了代理服务器在身份验证过程中意外断开连接的情况，这可以帮助开发者理解在这种情况下 Chromium 的处理方式。

总而言之，这部分代码专注于测试 Chromium 网络栈在处理 HTTP 代理身份验证时的各种复杂场景，确保在不同的网络配置和服务器行为下，身份验证流程能够正确、安全地进行。 这对于保证用户的网络访问体验至关重要。

### 提示词
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共34部分，请归纳一下它的功能
```

### 源代码
```cpp
// Flush the idle socket before the NetLog and HttpNetworkTransaction go
    // out of scope.
    session->CloseAllConnections(ERR_FAILED, "Very good reason");
  }
}

// Test the request-challenge-retry sequence for basic auth, over a keep-alive
// proxy connection with HTTP/1.1 responses, when setting up an SSL tunnel, in
// the case the server sends extra data on the original socket, so it can't be
// reused.
TEST_P(HttpNetworkTransactionTest, BasicAuthProxyKeepAliveExtraData) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  // when the no authentication data flag is set.
  request.privacy_mode = PRIVACY_MODE_ENABLED;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "PROXY myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  RecordingNetLogObserver net_log_observer;
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite(ASYNC, 0,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407, using a persistent, but sends
  // extra data, so the socket cannot be reused.
  MockRead data_reads1[] = {
      // No credentials.
      MockRead(ASYNC, 1,
               "HTTP/1.1 407 Proxy Authentication Required\r\n"
               "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"
               "Content-Length: 10\r\n\r\n"),
      MockRead(SYNCHRONOUS, 2, "0123456789"),
      MockRead(SYNCHRONOUS, 3, "I'm broken!"),
  };

  MockWrite data_writes2[] = {
      // After calling trans->RestartWithAuth(), this is the request we should
      // be issuing -- the final header line contains the credentials.
      MockWrite(ASYNC, 0,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),

      MockWrite(ASYNC, 2,
                "GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead(ASYNC, 1, "HTTP/1.1 200 Connection Established\r\n\r\n"),

      MockRead(ASYNC, 3,
               "HTTP/1.1 200 OK\r\n"
               "Content-Type: text/html; charset=iso-8859-1\r\n"
               "Content-Length: 5\r\n\r\n"),
      // No response body because the test stops reading here.
      MockRead(SYNCHRONOUS, ERR_UNEXPECTED, 4),
  };

  SequencedSocketData data1(data_reads1, data_writes1);
  data1.set_busy_before_sync_reads(true);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SequencedSocketData data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans->Start(&request, callback1.callback(),
                        NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(callback1.GetResult(rv), IsOk());

  auto entries = net_log_observer.GetEntries();
  size_t pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_TUNNEL_HEADERS,
      NetLogEventPhase::NONE);
  ExpectLogContainsSomewhere(
      entries, pos,
      NetLogEventType::HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS,
      NetLogEventPhase::NONE);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge));

  LoadTimingInfo load_timing_info;
  // CONNECT requests and responses are handled at the connect job level, so
  // the transaction does not yet have a connection.
  EXPECT_FALSE(trans->GetLoadTimingInfo(&load_timing_info));

  TestCompletionCallback callback2;

  rv =
      trans->RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(callback2.GetResult(rv), IsOk());

  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(5, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge.has_value());

  EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);

  trans.reset();
  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

// Test the case a proxy closes a socket while the challenge body is being
// drained.
TEST_P(HttpNetworkTransactionTest, BasicAuthProxyKeepAliveHangupDuringBody) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  // Ensure that proxy authentication is attempted even
  // when the no authentication data flag is set.
  request.privacy_mode = PRIVACY_MODE_ENABLED;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407, using a persistent
  // connection.
  MockRead data_reads1[] = {
      // No credentials.
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Content-Length: 10\r\n\r\n"),
      MockRead("spam!"),
      // Server hands up in the middle of the body.
      MockRead(ASYNC, ERR_CONNECTION_CLOSED),
  };

  MockWrite data_writes2[] = {
      // After calling trans.RestartWithAuth(), this is the request we should
      // be issuing -- the final header line contains the credentials.
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),

      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),

      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 5\r\n\r\n"),
      MockRead(SYNCHRONOUS, "hello"),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge));

  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  std::string body;
  EXPECT_THAT(ReadTransaction(&trans, &body), IsOk());
  EXPECT_EQ("hello", body);
}

// Test that we don't read the response body when we fail to establish a tunnel,
// even if the user cancels the proxy's auth attempt.
TEST_P(HttpNetworkTransactionTest, BasicAuthProxyCancelTunnel) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407.
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Content-Length: 10\r\n\r\n"),
      MockRead("0123456789"),
      MockRead(SYNCHRONOUS, ERR_UNEXPECTED),
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
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsError(ERR_TUNNEL_CONNECTION_FAILED));

  // Flush the idle socket before the HttpNetworkTransaction goes out of scope.
  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

// Test the no-tunnel HTTP auth case where proxy and server origins and realms
// are the same, but the user/passwords are different. Serves to verify
// credentials are correctly separated based on HttpAuth::Target.
TEST_P(HttpNetworkTransactionTest, BasicAuthProxyMatchesServerAuthNoTunnel) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://myproxy:70/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Proxy matches request URL.
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "PROXY myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  NetLogWithSource net_log_with_source =
      NetLogWithSource::Make(NetLogSourceType::NONE);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  MockWrite data_writes[] = {
      // Initial request gets a proxy auth challenge. The user-agent from
      // `session_deps_` does not appear because this is a GET request to the
      // proxy but containing headers for the destination.
      MockWrite("GET http://myproxy:70/ HTTP/1.1\r\n"
                "Host: myproxy:70\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
      // Retry with proxy auth credentials, which will result in a server auth
      // challenge.
      MockWrite("GET http://myproxy:70/ HTTP/1.1\r\n"
                "Host: myproxy:70\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
      // Retry with proxy and server auth credentials, which gets a response.
      MockWrite("GET http://myproxy:70/ HTTP/1.1\r\n"
                "Host: myproxy:70\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n"
                "Authorization: Basic Zm9vMjpiYXIy\r\n\r\n"),
      // A second request should preemptively send the correct proxy and server
      // auth headers.
      MockWrite("GET http://myproxy:70/ HTTP/1.1\r\n"
                "Host: myproxy:70\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n"
                "Authorization: Basic Zm9vMjpiYXIy\r\n\r\n"),
  };

  MockRead data_reads[] = {
      // Proxy auth challenge.
      MockRead("HTTP/1.0 407 Proxy Authentication Required\r\n"
               "Proxy-Connection: keep-alive\r\n"
               "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"
               "Content-Length: 0\r\n\r\n"),
      // Server auth challenge.
      MockRead("HTTP/1.0 401 Authentication Required\r\n"
               "Proxy-Connection: keep-alive\r\n"
               "WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"
               "Content-Length: 0\r\n\r\n"),
      // Response.
      MockRead("HTTP/1.1 200 OK\r\n"
               "Proxy-Connection: keep-alive\r\n"
               "Content-Length: 5\r\n\r\n"
               "hello"),
      // Response to second request.
      MockRead("HTTP/1.1 200 OK\r\n"
               "Proxy-Connection: keep-alive\r\n"
               "Content-Length: 2\r\n\r\n"
               "hi"),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans->Start(&request, callback.callback(), net_log_with_source);
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge));

  rv = trans->RestartWithAuth(AuthCredentials(kFoo, kBar), callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_EQ(401, response->headers->response_code());
  EXPECT_FALSE(response->auth_challenge->is_proxy);
  EXPECT_EQ("http://myproxy:70",
            response->auth_challenge->challenger.Serialize());
  EXPECT_EQ("MyRealm1", response->auth_challenge->realm);
  EXPECT_EQ(kBasicAuthScheme, response->auth_challenge->scheme);

  rv = trans->RestartWithAuth(AuthCredentials(kFoo2, kBar2),
                              callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_EQ(200, response->headers->response_code());
  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge.has_value());

  std::string response_data;
  EXPECT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello", response_data);

  // Check that the credentials were cached correctly.
  HttpAuthCache::Entry* entry = session->http_auth_cache()->Lookup(
      url::SchemeHostPort(url::SchemeHostPort(GURL("http://myproxy:70"))),
      HttpAuth::AUTH_PROXY, "MyRealm1", HttpAuth::AUTH_SCHEME_BASIC,
      NetworkAnonymizationKey());
  ASSERT_TRUE(entry);
  ASSERT_EQ(kFoo, entry->credentials().username());
  ASSERT_EQ(kBar, entry->credentials().password());
  entry = session->http_auth_cache()->Lookup(
      url::SchemeHostPort(url::SchemeHostPort(GURL("http://myproxy:70"))),
      HttpAuth::AUTH_SERVER, "MyRealm1", HttpAuth::AUTH_SCHEME_BASIC,
      NetworkAnonymizationKey());
  ASSERT_TRUE(entry);
  ASSERT_EQ(kFoo2, entry->credentials().username());
  ASSERT_EQ(kBar2, entry->credentials().password());

  // Make another request, which should automatically send the correct proxy and
  // server auth credentials and get another response.
  trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans->Start(&request, callback.callback(), net_log_with_source);
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_EQ(200, response->headers->response_code());
  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge.has_value());

  EXPECT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hi", response_data);

  trans.reset();
  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

// Test the no-tunnel HTTP auth case where proxy and server origins and realms
// are the same, but the user/passwords are different, and with different
// NetworkAnonymizationKeys. Sends one request with a NAK, response to both
// proxy and auth challenges, sends another request with another NAK, expecting
// only the proxy credentials to be cached, and thus sees only a server auth
// challenge. Then sends a request with the original NAK, expecting cached proxy
// and auth credentials that match the ones used in the first request.
//
// Serves to verify credentials are correctly separated based on
// HttpAuth::Target and NetworkAnonymizationKeys, but NetworkAnonymizationKey
// only affects server credentials, not proxy credentials.
TEST_P(HttpNetworkTransactionTest,
       BasicAuthProxyMatchesServerAuthWithNetworkAnonymizationKeyNoTunnel) {
  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const NetworkIsolationKey kNetworkIsolationKey1(kSite1, kSite1);
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);
  const NetworkIsolationKey kNetworkIsolationKey2(kSite2, kSite2);

  // This test would need to use a single socket without this option enabled.
  // Best to use this option when it would affect a test, as it will eventually
  // become the default behavior.
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  // Proxy matches request URL.
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "PROXY myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  NetLogWithSource net_log_with_source =
      NetLogWithSource::Make(NetLogSourceType::NONE);

  session_deps_.net_log = NetLog::Get();
  session_deps_.key_auth_cache_server_entries_by_network_anonymization_key =
      true;
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  MockWrite data_writes[] = {
      // Initial request gets a proxy auth challenge.
      MockWrite("GET http://myproxy:70/ HTTP/1.1\r\n"
                "Host: myproxy:70\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
      // Retry with proxy auth credentials, which will result in a server auth
      // challenge.
      MockWrite("GET http://myproxy:70/ HTTP/1.1\r\n"
                "Host: myproxy:70\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
      // Retry with proxy and server auth credentials, which gets a response.
      MockWrite("GET http://myproxy:70/ HTTP/1.1\r\n"
                "Host: myproxy:70\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n"
                "Authorization: Basic Zm9vMjpiYXIy\r\n\r\n"),
      // Another request to the same server and using the same NAK should
      // preemptively send the correct cached proxy and server
      // auth headers.
      MockWrite("GET http://myproxy:70/ HTTP/1.1\r\n"
                "Host: myproxy:70\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n"
                "Authorization: Basic Zm9vMjpiYXIy\r\n\r\n"),
  };

  MockRead data_reads[] = {
      // Proxy auth challenge.
      MockRead("HTTP/1.0 407 Proxy Authentication Required\r\n"
               "Proxy-Connection: keep-alive\r\n"
               "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"
               "Content-Length: 0\r\n\r\n"),
      // Server auth challenge.
      MockRead("HTTP/1.0 401 Authentication Required\r\n"
               "Proxy-Connection: keep-alive\r\n"
               "WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"
               "Content-Length: 0\r\n\r\n"),
      // Response.
      MockRead("HTTP/1.1 200 OK\r\n"
               "Proxy-Connection: keep-alive\r\n"
               "Content-Length: 5\r\n\r\n"
               "hello"),
      // Response to second request.
      MockRead("HTTP/1.1 200 OK\r\n"
               "Proxy-Connection: keep-alive\r\n"
               "Content-Length: 2\r\n\r\n"
               "hi"),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  MockWrite data_writes2[] = {
      // Initial request using a different NetworkAnonymizationKey includes the
      // cached proxy credentials, but not server credentials.
      MockWrite("GET http://myproxy:70/ HTTP/1.1\r\n"
                "Host: myproxy:70\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
      // Retry with proxy and new server auth credentials, which gets a
      // response.
      MockWrite("GET http://myproxy:70/ HTTP/1.1\r\n"
                "Host: myproxy:70\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n"
                "Authorization: Basic Zm9vMzpiYXIz\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      // Server auth challenge.
      MockRead("HTTP/1.0 401 Authentication Required\r\n"
               "Proxy-Connection: keep-alive\r\n"
               "WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"
               "Content-Length: 0\r\n\r\n"),
      // Response.
      MockRead("HTTP/1.1 200 OK\r\n"
               "Proxy-Connection: keep-alive\r\n"
               "Content-Length: 9\r\n\r\n"
               "greetings"),
  };

  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback;

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://myproxy:70/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  request.network_isolation_key = kNetworkIsolationKey1;
  request.network_anonymization_key = kNetworkAnonymizationKey1;

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans->Start(&request, callback.callback(), net_log_with_source);
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge));

  rv = trans->RestartWithAuth(AuthCredentials(kFoo, kBar), callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_EQ(401, response->headers->response_code());
  EXPECT_FALSE(response->auth_challenge->is_proxy);
  EXPECT_EQ("http://myproxy:70",
            response->auth_challenge->challenger.Serialize());
  EXPECT_EQ("MyRealm1", response->auth_challenge->realm);
  EXPECT_EQ(kBasicAuthScheme, response->auth_challenge->scheme);

  rv = trans->RestartWithAuth(AuthCredentials(kFoo2, kBar2),
                              callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_EQ(200, response->headers->response_code());
  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge.has_value());
  std::string response_data;
  EXPECT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello", response_data);

  // Check that the proxy credentials were cached correctly. The should be
  // accessible with any NetworkAnonymizationKey.
  HttpAuthCache::Entry* entry = session->http_auth_cache()->Lookup(
      url::SchemeHostPort(url::SchemeHostPort(GURL("http://myproxy:70"))),
      HttpAuth::AUTH_PROXY, "MyRealm1", HttpAuth::AUTH_SCHEME_BASIC,
      kNetworkAnonymizationKey1);
  ASSERT_TRUE(entry);
  ASSERT_EQ(kFoo, entry->credentials().username());
  ASSERT_EQ(kBar, entry->credentials().password());
  EXPECT_EQ(entry, session->http_auth_cache()->Lookup(
                       url::SchemeHostPort(GURL("http://myproxy:70")),
                       HttpAuth::AUTH_PROXY, "MyRealm1",
                       HttpAuth::AUTH_SCHEME_BASIC, kNetworkAnonymizationKey2));

  // Check that the server credentials were cached correctly. The should be
  // accessible with only kNetworkAnonymizationKey1.
  entry = session->http_auth_cache()->Lookup(
      url::SchemeHostPort(GURL("http://myproxy:70")), HttpAuth::AUTH_SERVER,
      "MyRealm1", HttpAuth::AUTH_SCHEME_BASIC, kNetworkAnonymizationKey1);
  ASSERT_TRUE(entry);
  ASSERT_EQ(kFoo2, entry->credentials().username());
  ASSERT_EQ(kBar2, entry->credentials().password());
  // Looking up the server entry with another NetworkAnonymizationKey should
  // fail.
  EXPECT_FALSE(session->http_auth_cache()->Lookup(
      url::SchemeHostPort(GURL("http://myproxy:70")), HttpAuth::AUTH_SERVER,
      "MyRealm1", HttpAuth::AUTH_SCHEME_BASIC, kNetworkAnonymizationKey2));

  // Make another request with a different NetworkAnonymizationKey. It should
  // use another socket, reuse the cached proxy credentials, but result in a
  // server auth challenge.
  request.network_isolation_key = kNetworkIsolationKey2;
  request.network_anonymization_key = kNetworkAnonymizationKey2;

  trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans->Start(&request, callback.callback(), net_log_with_source);
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_EQ(401, response->headers->response_code());
  EXPECT_FALSE(response->auth_challenge->is_proxy);
  EXPECT_EQ("http://myproxy:70",
            response->auth_challenge->challenger.Serialize());
  EXPECT_EQ("MyRealm1", response->auth_challenge->realm);
  EXPECT_EQ(kBasicAuthScheme, response->auth_challenge->scheme);

  rv = trans->RestartWithAuth(AuthCredentials(kFoo3, kBar3),
                              callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_EQ(200, response->headers->response_code());
  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge.has_value());
  EXPECT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("greetings", response_data);

  // Check that the proxy credentials are still cached.
  entry = session->http_auth_cache()->Lookup(
      url::SchemeHostPort(GURL("http://myproxy:70")), HttpAuth::AUTH_PROXY,
      "MyRealm1", HttpAuth::AUTH_SCHEME_BASIC, kNetworkAnonymizationKey1);
  ASSERT_TRUE(entry);
  ASSERT_EQ(kFoo, entry->credentials().username());
  ASSERT_EQ(kBar, entry->credentials().password());
  EXPECT_EQ(entry, session->http_auth_cache()->Lookup(
                       url::SchemeHostPort(GURL("http://myproxy:70")),
                       HttpAuth::AUTH_PROXY, "MyRealm1",
                       HttpAuth::AUTH_SCHEME_BASIC, kNetworkAnonymizationKey2));

  // Check that the correct server credentials are cached for each
  // NetworkAnonymizationKey.
  entry = session->http_auth_cache()->Lookup(
      url::SchemeHostPort(GURL("http://myproxy:70")), HttpAuth::AUTH_SERVER,
      "MyRealm1", HttpAuth::AUTH_SCHEME_BASIC, kNetworkAnonymizationKey1);
  ASSERT_TRUE(entry);
  ASSERT_EQ(kFoo2, entry->credentials().username());
  ASSERT_EQ(kBar2, entry->credentials().password());
  entry = session->http_auth_cache()->Lookup(
      url::SchemeHostPort(GURL("http://myproxy:70")), HttpAuth::AUTH_SERVER,
      "MyRealm1", HttpAuth::AUTH_SCHEME_BASIC, kNetworkAnonymizationKey2);
  ASSERT_TRUE(entry);
  ASSERT_EQ(kFoo3, entry->credentials().username());
  ASSERT_EQ(kBar3, entry->credentials().password());

  // Make a request with the original NetworkAnonymizationKey. It should reuse
  // the first socket, and the proxy credentials sent on the first socket.
  request.network_isolation_key = kNetworkIsolationKey1;
  request.network_anonymization_key = kNetworkAnonymizationKey1;
  trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans->Start(&request, callback.callback(), net_log_with_source);
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_EQ(200, response->headers->response_code());
  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge.has_value());
  EXPECT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hi", response_data);

  trans.reset();
  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

// Much like the test above, but uses tunnelled connections.
TEST_P(HttpNetworkTransactionTest,
       BasicAuthProxyMatchesServerAuthWithNetworkAnonymizationKeyWithTunnel) {
  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const NetworkIsolationKey kNetworkIsolationKey1(kSite1, kSite1);
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);
  const NetworkIsolationKey kNetworkIsolationKey2(kSite2, kSite2);

  // This test would need to use a single socket without this option enabled.
  // Best to use this option when it would affect a test, as it will eventually
  // become the default behavior.
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  // Proxy matches request URL.
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "HTTPS myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  NetLogWithSource net_log_with_source =
      NetLogWithSource::Make(NetLogSourceType::NONE);
  session_deps_.net_log = NetLog::Get();
  session_deps_.key_auth_cache_server_entries_by_network_anonymization_key =
      true;
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  MockWrite data_writes[] = {
      // Initial tunnel request gets a proxy auth challenge.
      MockWrite("CONNECT myproxy:70 HTTP/1.1\r\n"
                "Host: myproxy:70\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
      // Retry with proxy auth credentials, which will result in establishing a
      // tunnel.
      MockWrite("CONNECT myproxy:70 HTTP/1.1\r\n"
                "Host: myproxy:70\r\n"
                "Proxy-Con
```