Response:
The user wants to understand the functionality of a specific C++ source code file (`net/http/http_network_transaction_unittest.cc`) within the Chromium project. They've provided a snippet of the code and are asking for:

1. **Functionality:** A summary of what the code does.
2. **Relationship to JavaScript:**  If and how the code interacts with JavaScript.
3. **Logic and Examples:**  Scenarios with hypothetical inputs and outputs to illustrate the code's behavior.
4. **Common User/Programming Errors:** Examples of mistakes that can lead to this code being executed.
5. **User Operation to Reach Here:** A sequence of user actions that might trigger the execution of this code (for debugging purposes).
6. **Summary:**  A concise overview of the functionality based on the provided snippet.

Let's break down the code snippet and address each point.

**Code Analysis (Provided Snippet):**

The snippet primarily consists of test cases (using `TEST_P`) for the `HttpNetworkTransaction` class, focusing on scenarios involving HTTP Basic Authentication. Key functionalities being tested include:

* **Successful Basic Authentication:**  Testing the flow where the server challenges the client for credentials, and the client successfully authenticates on a retry.
* **Keep-Alive Connections:** Verifying that authentication works correctly over persistent HTTP connections.
* **No Response Body/Large Response Body:**  Testing how the transaction handles authentication challenges with and without response bodies to drain.
* **Impatient Server:**  Simulating a server closing the connection during the authentication process.
* **Proxy Authentication:**  Testing Basic Authentication with a proxy server, including scenarios requiring a tunnel setup (`CONNECT` requests).
* **HTTP/1.0 and HTTP/1.1 Proxies:**  Testing proxy authentication with different HTTP versions.
* **Incorrect Credentials:**  Demonstrating how the transaction handles retries with wrong credentials.
* **Load Timing Information:**  Checking the timing details associated with successful and reused connections.
* **NetLog Integration:** Observing network events logged during the transaction.

**Addressing Each Point:**

1. **Functionality:** The code tests the `HttpNetworkTransaction` class's ability to handle HTTP Basic Authentication in various scenarios, including direct connections and connections through proxies, with and without keep-alive, and with different server behaviors. It also tests the recording of load timing information.

2. **Relationship to JavaScript:**  While this specific C++ code doesn't directly execute JavaScript, it plays a crucial role in the underlying network stack that supports web browsing and JavaScript execution in a browser. When a JavaScript application makes an HTTP request that requires authentication (like accessing a resource protected by Basic Auth), this C++ code is responsible for handling the authentication handshake with the server. The JavaScript `fetch` API or `XMLHttpRequest` might trigger this process indirectly.

3. **Logic and Examples:**

   * **Scenario: Successful Basic Authentication (No Keep-Alive)**
     * **Hypothetical Input:** A user navigates to `http://example.com/protected` which requires Basic Auth. The server responds with a `401 Unauthorized` and a `WWW-Authenticate` header. The user enters "user" and "password" in the browser's authentication dialog.
     * **Internal Steps (Simplified):**
       1. `HttpNetworkTransaction` starts the request without credentials.
       2. Receives `401`. Parses `WWW-Authenticate`.
       3. The browser (or a higher-level networking component) provides the credentials.
       4. `RestartWithAuth` is called.
       5. `HttpNetworkTransaction` retries the request with the `Authorization` header.
       6. Server responds with `200 OK`.
     * **Hypothetical Output (from the test):** `callback2.GetResult(rv)` would be `IsOk()`, the second `LoadTimingInfo` would show a reused connection, and `response->auth_challenge` would be empty.

   * **Scenario: Proxy Authentication (HTTP/1.1)**
     * **Hypothetical Input:** A user with a configured proxy navigates to `https://secure.example.com`. The proxy requires authentication.
     * **Internal Steps (Simplified):**
       1. `HttpNetworkTransaction` attempts a `CONNECT` request to the proxy without credentials.
       2. Proxy responds with `407 Proxy Authentication Required` and `Proxy-Authenticate`.
       3. The browser prompts for proxy credentials.
       4. `RestartWithAuth` is called.
       5. `HttpNetworkTransaction` retries the `CONNECT` with the `Proxy-Authorization` header.
       6. Proxy responds with `200 Connection Established`.
       7. The original request to `https://secure.example.com` is sent through the tunnel.
     * **Hypothetical Output (from the test):**  `connected_handler.transports()` would contain information about the proxy connection, and the final response would be `200 OK`.

4. **Common User/Programming Errors:**

   * **Incorrect Credentials:** If the user enters the wrong username or password in the authentication dialog, the `RestartWithAuth` call would be made, but the subsequent server response might still be a `401` or `407`. The tests simulate this with `BasicAuthProxyKeepAliveHttp10` and `BasicAuthProxyKeepAliveHttp11`.
   * **Misconfigured Proxy:** If the proxy settings are incorrect, the initial `CONNECT` request might fail entirely (different error code than authentication required), and this code wouldn't be exercising the authentication retry logic.
   * **Server Not Implementing Basic Auth Correctly:** If the server doesn't send the correct `WWW-Authenticate` header, or if the realm is unexpected, the authentication process might fail. While the tests assume a compliant server, real-world scenarios can have issues here.
   * **Programming Error in the Browser:** A bug in the browser's authentication handling logic might prevent the correct credentials from being passed to the `RestartWithAuth` function.

5. **User Operation to Reach Here (Debugging):**

   1. **User navigates to a website requiring HTTP Basic Authentication:** The user types a URL into the address bar or clicks a link that leads to a resource protected by Basic Auth (e.g., a `.htaccess` protected directory on a web server).
   2. **Server responds with a 401 Unauthorized:** The web server sends an HTTP response with the status code `401` and a `WWW-Authenticate` header.
   3. **Browser displays an authentication dialog:** The browser intercepts the `401` response and presents a dialog box to the user, prompting for a username and password.
   4. **User enters credentials and clicks "OK":** The user provides their username and password and submits the dialog.
   5. **Browser calls `RestartWithAuth` internally:** The browser's networking code (which includes the `HttpNetworkTransaction` class) takes the provided credentials and uses them to retry the request. This is where the code in the provided snippet is relevant, as it tests the behavior of `RestartWithAuth`.
   6. **If a proxy is involved:** The process is similar, but the initial `407 Proxy Authentication Required` from the proxy triggers a prompt for proxy credentials, leading to a `RestartWithAuth` call for the proxy tunnel.

6. **Summary of Functionality (Based on Snippet):** This section of the `http_network_transaction_unittest.cc` file focuses on testing the correct implementation of HTTP Basic Authentication within the Chromium network stack's `HttpNetworkTransaction` class. It covers various scenarios, including successful authentication, retries after challenges, handling of keep-alive connections, interactions with proxy servers (both HTTP/1.0 and HTTP/1.1), and error conditions like incorrect credentials. The tests verify that the `HttpNetworkTransaction` correctly sends authentication headers, handles server challenges, and manages connection reuse in different authentication contexts.

好的，这是对`net/http/http_network_transaction_unittest.cc` 文件中第5部分代码的功能归纳和解释：

**功能归纳:**

这部分代码主要针对 `HttpNetworkTransaction` 类中处理 **HTTP 基本身份验证 (Basic Authentication)** 的功能进行单元测试。测试覆盖了以下场景：

* **成功的身份验证流程:**  测试当服务器返回 `401 Unauthorized` 并带有 `WWW-Authenticate` 头部时，`HttpNetworkTransaction` 能否正确处理，并在调用 `RestartWithAuth` 后，使用提供的凭据重新发送请求，最终成功获取资源。
* **Keep-Alive 连接下的身份验证:**  验证在保持连接活跃的情况下，身份验证流程是否正常工作，并且连接能够被复用。
* **有无响应体的身份验证挑战:** 测试当服务器返回 `401` 状态码时，无论是否有响应体数据，身份验证流程都能正确处理。
* **服务器过早关闭连接的情况:** 模拟服务器在收到认证重试请求后关闭连接的情况，验证 `HttpNetworkTransaction` 的处理逻辑。
* **通过代理服务器进行身份验证:**  测试在通过代理服务器建立 SSL 隧道时，处理代理身份验证 (`407 Proxy Authentication Required`) 的流程，包括 HTTP/1.0 和 HTTP/1.1 协议的代理。
* **使用错误凭据的情况:** 测试当提供错误的用户名或密码时，`HttpNetworkTransaction` 的行为。
* **负载时间信息 (Load Timing Info):**  验证在身份验证过程中，负载时间信息是否被正确记录，并且在连接复用时能够反映出来。
* **NetLog 日志记录:**  检查在身份验证过程中，相关的网络事件是否被正确地记录到 NetLog 中。

**与 Javascript 的关系及举例:**

虽然这段 C++ 代码本身不直接运行 Javascript，但它是 Chromium 浏览器网络栈的核心组成部分。当 Javascript 代码发起一个需要 HTTP 基本身份验证的请求时（例如使用 `fetch` API 或 `XMLHttpRequest`），最终会调用到 `HttpNetworkTransaction` 的相关功能来处理身份验证。

**举例说明:**

假设一个 Javascript 应用尝试访问一个受基本身份验证保护的 API 端点 `http://example.com/api/data`。

1. **Javascript 发起请求:**
   ```javascript
   fetch('http://example.com/api/data')
     .then(response => response.json())
     .then(data => console.log(data));
   ```

2. **服务器返回 401:** 如果服务器要求身份验证，它会返回一个 `401 Unauthorized` 响应，并在头部包含 `WWW-Authenticate: Basic realm="MyRealm"`。

3. **浏览器处理 401:** 浏览器接收到 `401` 响应，会提示用户输入用户名和密码。

4. **用户输入凭据:** 用户在弹出的对话框中输入用户名 "user" 和密码 "password"。

5. **`RestartWithAuth` 被调用 (内部):** 浏览器内部的网络栈会将用户的凭据 (user, password) 传递给 `HttpNetworkTransaction` 的 `RestartWithAuth` 方法，并重新发送请求，这次请求的头部会包含 `Authorization: Basic dXNlcjpwYXNzd29yZA==`。

6. **服务器验证并返回 200:** 如果凭据正确，服务器会返回 `200 OK` 响应，以及请求的数据。

**逻辑推理、假设输入与输出:**

**测试用例: `BasicAuthKeepAliveNoBody`**

* **假设输入:**
    * 一个针对 `http://www.example.org/` 的 GET 请求。
    * 服务器第一次响应 `401 Unauthorized`，`WWW-Authenticate: Basic realm="MyRealm1"`，`Content-Length: 0` (没有响应体)。
    * 服务器第二次响应 `200 OK`，`Content-Length: 5`，响应体为 "hello"。
* **逻辑推理:** `HttpNetworkTransaction` 应该在收到 `401` 后，调用 `RestartWithAuth`，然后重新发送带有 `Authorization` 头部的请求。由于是 Keep-Alive 连接，连接应该被复用。
* **预期输出:**
    * `callback1.GetResult(rv)` 为成功 (认证挑战)。
    * `response->auth_challenge` 包含认证信息。
    * `callback2.GetResult(rv)` 为成功 (认证通过)。
    * `response->auth_challenge` 为空。
    * `response->headers->GetContentLength()` 为 5。

**用户或编程常见的使用错误及举例:**

* **用户输入错误的用户名或密码:**  例如在 `BasicAuthProxyKeepAliveHttp10` 和 `BasicAuthProxyKeepAliveHttp11` 测试中，使用了错误的密码 `kBaz`，会导致认证再次失败。
* **代理配置错误:** 如果用户配置了错误的代理服务器地址或端口，可能会导致连接失败，而不是进入身份验证流程。
* **服务端未正确配置 Basic Auth:** 如果服务端没有发送正确的 `WWW-Authenticate` 头部，客户端可能无法正确触发身份验证流程。
* **在代码中错误地处理认证信息:** 开发者可能会错误地缓存或处理认证信息，导致后续请求无法正确进行身份验证。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户访问需要基本身份验证的网站:** 用户在浏览器地址栏输入一个 URL，或者点击一个链接，该资源需要用户提供用户名和密码才能访问。
2. **服务器返回 401 响应:** 服务器接收到用户的初始请求，发现未提供有效的凭据，因此返回 HTTP 状态码 `401 Unauthorized`。
3. **浏览器接收到 401 响应:** Chromium 浏览器的网络栈接收到这个 `401` 响应。
4. **浏览器解析 `WWW-Authenticate` 头部:** 网络栈解析响应头中的 `WWW-Authenticate` 头部，确定需要进行基本身份验证，并提取认证域 (realm) 等信息。
5. **浏览器弹出身份验证对话框:**  浏览器根据接收到的信息，弹出一个模态对话框，提示用户输入用户名和密码。
6. **用户输入用户名和密码并点击“确定”:** 用户在对话框中输入他们的凭据。
7. **浏览器调用 `HttpNetworkTransaction::RestartWithAuth`:**  浏览器将用户输入的凭据传递给 `HttpNetworkTransaction` 对象，调用其 `RestartWithAuth` 方法，并重新发送带有 `Authorization` 头部的请求。 这就是这段测试代码所要验证的核心流程。

**本部分功能总结 (第 5 部分):**

这部分单元测试主要集中在验证 `HttpNetworkTransaction` 类处理 HTTP 基本身份验证的各种场景，包括成功的认证、Keep-Alive 连接下的认证、通过代理的认证，以及处理错误凭据和服务器异常情况。这些测试确保了 Chromium 网络栈在处理需要用户凭据才能访问的资源时，能够按照 HTTP 协议规范正确地完成身份验证流程。

### 提示词
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共34部分，请归纳一下它的功能
```

### 源代码
```cpp
ERT_THAT(callback1.GetResult(rv), IsOk());

    LoadTimingInfo load_timing_info1;
    EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info1));
    TestLoadTimingNotReused(load_timing_info1, CONNECT_TIMING_HAS_DNS_TIMES);

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge));

    TestCompletionCallback callback2;

    rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar),
                               callback2.callback());
    ASSERT_THAT(callback2.GetResult(rv), IsOk());

    LoadTimingInfo load_timing_info2;
    EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info2));
    TestLoadTimingReused(load_timing_info2);
    // The load timing after restart should have the same socket ID, and times
    // those of the first load timing.
    EXPECT_LE(load_timing_info1.receive_headers_end,
              load_timing_info2.send_start);
    EXPECT_EQ(load_timing_info1.socket_log_id, load_timing_info2.socket_log_id);

    response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_FALSE(response->auth_challenge.has_value());
    EXPECT_EQ(5, response->headers->GetContentLength());

    std::string response_data;
    EXPECT_THAT(ReadTransaction(&trans, &response_data), IsOk());

    int64_t writes_size = CountWriteBytes(data_writes);
    EXPECT_EQ(writes_size, trans.GetTotalSentBytes());
    int64_t reads_size = CountReadBytes(data_reads);
    EXPECT_EQ(reads_size, trans.GetTotalReceivedBytes());
  }
}

// Test the request-challenge-retry sequence for basic auth, over a keep-alive
// connection and with no response body to drain.
TEST_P(HttpNetworkTransactionTest, BasicAuthKeepAliveNoBody) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),

      // After calling trans.RestartWithAuth(), this is the request we should
      // be issuing -- the final header line contains the credentials.
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 401 Unauthorized\r\n"),
      MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Content-Length: 0\r\n\r\n"),  // No response body.

      // Lastly, the server responds with the actual content.
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 5\r\n\r\n"),
      MockRead("hello"),
  };

  // An incorrect reconnect would cause this to be read.
  MockRead data_reads2[] = {
      MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  StaticSocketDataProvider data2(data_reads2, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge));

  TestCompletionCallback callback2;

  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge.has_value());
  EXPECT_EQ(5, response->headers->GetContentLength());
}

// Test the request-challenge-retry sequence for basic auth, over a keep-alive
// connection and with a large response body to drain.
TEST_P(HttpNetworkTransactionTest, BasicAuthKeepAliveLargeBody) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),

      // After calling trans.RestartWithAuth(), this is the request we should
      // be issuing -- the final header line contains the credentials.
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  // Respond with 5 kb of response body.
  std::string large_body_string("Unauthorized");
  large_body_string.append(5 * 1024, ' ');
  large_body_string.append("\r\n");

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 401 Unauthorized\r\n"),
      MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      // 5134 = 12 + 5 * 1024 + 2
      MockRead("Content-Length: 5134\r\n\r\n"),
      MockRead(ASYNC, large_body_string.data(), large_body_string.size()),

      // Lastly, the server responds with the actual content.
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 5\r\n\r\n"),
      MockRead("hello"),
  };

  // An incorrect reconnect would cause this to be read.
  MockRead data_reads2[] = {
      MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  StaticSocketDataProvider data2(data_reads2, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge));

  TestCompletionCallback callback2;

  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge.has_value());
  EXPECT_EQ(5, response->headers->GetContentLength());
}

// Test the request-challenge-retry sequence for basic auth, over a keep-alive
// connection, but the server gets impatient and closes the connection.
TEST_P(HttpNetworkTransactionTest, BasicAuthKeepAliveImpatientServer) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
      // This simulates the seemingly successful write to a closed connection
      // if the bug is not fixed.
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 401 Unauthorized\r\n"),
      MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 14\r\n\r\n"),
      // Tell MockTCPClientSocket to simulate the server closing the connection.
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead("Unauthorized\r\n"),
      MockRead(SYNCHRONOUS, OK),  // The server closes the connection.
  };

  // After calling trans.RestartWithAuth(), this is the request we should
  // be issuing -- the final header line contains the credentials.
  MockWrite data_writes2[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 5\r\n\r\n"),
      MockRead("hello"),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge));

  TestCompletionCallback callback2;

  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge.has_value());
  EXPECT_EQ(5, response->headers->GetContentLength());
}

// Test the request-challenge-retry sequence for basic auth, over a connection
// that requires a restart when setting up an SSL tunnel.
TEST_P(HttpNetworkTransactionTest, BasicAuthProxyNoKeepAliveHttp10) {
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
  NetLogWithSource net_log_with_source =
      NetLogWithSource::Make(NetLogSourceType::NONE);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407, using a non-persistent
  // connection.
  MockRead data_reads1[] = {
      // No credentials.
      MockRead("HTTP/1.0 407 Proxy Authentication Required\r\n"),
      MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n\r\n"),
  };

  // Since the first connection couldn't be reused, need to establish another
  // once given credentials.
  MockWrite data_writes2[] = {
      // After calling trans->RestartWithAuth(), this is the request we should
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
      MockRead("HTTP/1.0 200 Connection Established\r\n\r\n"),

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

  TestCompletionCallback callback1;
  ConnectedHandler connected_handler;

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  trans->SetConnectedCallback(connected_handler.Callback());

  int rv = trans->Start(&request, callback1.callback(), net_log_with_source);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  auto entries = net_log_observer.GetEntries();
  size_t pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_TUNNEL_HEADERS,
      NetLogEventPhase::NONE);
  ExpectLogContainsSomewhere(
      entries, pos,
      NetLogEventType::HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS,
      NetLogEventPhase::NONE);

  // TODO(crbug.com/40637204): Fix handling of OnConnected() when proxy
  // authentication is required. We should notify the callback that a connection
  // was established, even though the stream might not be ready for us to send
  // data through it.
  EXPECT_THAT(connected_handler.transports(), IsEmpty());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->headers->IsKeepAlive());
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 0) == response->headers->GetHttpVersion());
  EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge));

  LoadTimingInfo load_timing_info;
  // CONNECT requests and responses are handled at the connect job level, so
  // the transaction does not yet have a connection.
  EXPECT_FALSE(trans->GetLoadTimingInfo(&load_timing_info));

  TestCompletionCallback callback2;

  rv =
      trans->RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(5, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  TransportInfo expected_transport;
  expected_transport.type = TransportType::kProxied;
  expected_transport.endpoint = IPEndPoint(IPAddress::IPv4Localhost(), 70);
  expected_transport.negotiated_protocol = kProtoUnknown;
  EXPECT_THAT(connected_handler.transports(), ElementsAre(expected_transport));

  // Check that credentials were successfully cached, with the right target.
  HttpAuthCache::Entry* entry = session->http_auth_cache()->Lookup(
      url::SchemeHostPort(url::SchemeHostPort(GURL("http://myproxy:70"))),
      HttpAuth::AUTH_PROXY, "MyRealm1", HttpAuth::AUTH_SCHEME_BASIC,
      NetworkAnonymizationKey());
  ASSERT_TRUE(entry);
  ASSERT_EQ(kFoo, entry->credentials().username());
  ASSERT_EQ(kBar, entry->credentials().password());

  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge.has_value());

  EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);

  trans.reset();
  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

// Test the request-challenge-retry sequence for basic auth, over a connection
// that requires a restart when setting up an SSL tunnel.
TEST_P(HttpNetworkTransactionTest, BasicAuthProxyNoKeepAliveHttp11) {
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
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407, using a non-persistent
  // connection.
  MockRead data_reads1[] = {
      // No credentials.
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Proxy-Connection: close\r\n\r\n"),
  };

  MockWrite data_writes2[] = {
      // After calling trans->RestartWithAuth(), this is the request we should
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

  ConnectedHandler connected_handler;
  TestCompletionCallback callback1;

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  trans->SetConnectedCallback(connected_handler.Callback());

  int rv = trans->Start(&request, callback1.callback(),
                        NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());
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
  EXPECT_FALSE(response->headers->IsKeepAlive());
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge));
  EXPECT_EQ(PacResultElementToProxyChain("PROXY myproxy:70"),
            response->proxy_chain);

  // TODO(crbug.com/40637204): Fix handling of OnConnected() when proxy
  // authentication is required. We should notify the callback that a connection
  // was established, even though the stream might not be ready for us to send
  // data through it.
  EXPECT_THAT(connected_handler.transports(), IsEmpty());

  LoadTimingInfo load_timing_info;
  // CONNECT requests and responses are handled at the connect job level, so
  // the transaction does not yet have a connection.
  EXPECT_FALSE(trans->GetLoadTimingInfo(&load_timing_info));

  TestCompletionCallback callback2;

  rv =
      trans->RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(5, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_EQ(PacResultElementToProxyChain("PROXY myproxy:70"),
            response->proxy_chain);

  TransportInfo expected_transport;
  expected_transport.type = TransportType::kProxied;
  expected_transport.endpoint = IPEndPoint(IPAddress::IPv4Localhost(), 70);
  expected_transport.negotiated_protocol = kProtoUnknown;
  EXPECT_THAT(connected_handler.transports(), ElementsAre(expected_transport));

  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge.has_value());

  EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);

  trans.reset();
  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

// Test the request-challenge-retry sequence for basic auth, over a keep-alive
// proxy connection with HTTP/1.0 responses, when setting up an SSL tunnel.
TEST_P(HttpNetworkTransactionTest, BasicAuthProxyKeepAliveHttp10) {
  // On the second pass, the body read of the auth challenge is synchronous, so
  // IsConnectedAndIdle returns false.  The socket should still be drained and
  // reused.  See http://crbug.com/544255.
  for (int i = 0; i < 2; ++i) {
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
    RecordingNetLogObserver net_log_observer;
    session_deps_.net_log = NetLog::Get();
    std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    // Since we have proxy, should try to establish tunnel.
    MockWrite data_writes1[] = {
        MockWrite(ASYNC, 0,
                  "CONNECT www.example.org:443 HTTP/1.1\r\n"
                  "Host: www.example.org:443\r\n"
                  "Proxy-Connection: keep-alive\r\n"
                  "User-Agent: test-ua\r\n\r\n"),

        // After calling trans.RestartWithAuth(), this is the request we should
        // be issuing -- the final header line contains the credentials.
        MockWrite(ASYNC, 3,
                  "CONNECT www.example.org:443 HTTP/1.1\r\n"
                  "Host: www.example.org:443\r\n"
                  "Proxy-Connection: keep-alive\r\n"
                  "User-Agent: test-ua\r\n"
                  "Proxy-Authorization: Basic Zm9vOmJheg==\r\n\r\n"),
    };

    // The proxy responds to the connect with a 407, using a persistent
    // connection. (Since it's HTTP/1.0, keep-alive has to be explicit.)
    MockRead data_reads1[] = {
        // No credentials.
        MockRead(ASYNC, 1,
                 "HTTP/1.0 407 Proxy Authentication Required\r\n"
                 "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"
                 "Proxy-Connection: keep-alive\r\n"
                 "User-Agent: test-ua\r\n"
                 "Content-Length: 10\r\n\r\n"),
        MockRead(i == 0 ? ASYNC : SYNCHRONOUS, 2, "0123456789"),

        // Wrong credentials (wrong password).
        MockRead(ASYNC, 4,
                 "HTTP/1.0 407 Proxy Authentication Required\r\n"
                 "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"
                 "Proxy-Connection: keep-alive\r\n"
                 "User-Agent: test-ua\r\n"
                 "Content-Length: 10\r\n\r\n"),
        // No response body because the test stops reading here.
        MockRead(SYNCHRONOUS, ERR_UNEXPECTED, 5),
    };

    SequencedSocketData data1(data_reads1, data_writes1);
    data1.set_busy_before_sync_reads(true);
    session_deps_.socket_factory->AddSocketDataProvider(&data1);

    TestCompletionCallback callback1;

    int rv = trans.Start(&request, callback1.callback(),
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

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    ASSERT_TRUE(response->headers);
    EXPECT_TRUE(response->headers->IsKeepAlive());
    EXPECT_EQ(407, response->headers->response_code());
    EXPECT_EQ(10, response->headers->GetContentLength());
    EXPECT_TRUE(HttpVersion(1, 0) == response->headers->GetHttpVersion());
    EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge));

    TestCompletionCallback callback2;

    // Wrong password (should be "bar").
    rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBaz),
                               callback2.callback());
    EXPECT_THAT(callback2.GetResult(rv), IsOk());

    response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    ASSERT_TRUE(response->headers);
    EXPECT_TRUE(response->headers->IsKeepAlive());
    EXPECT_EQ(407, response->headers->response_code());
    EXPECT_EQ(10, response->headers->GetContentLength());
    EXPECT_TRUE(HttpVersion(1, 0) == response->headers->GetHttpVersion());
    EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge));

    // Flush the idle socket before the NetLog and HttpNetworkTransaction go
    // out of scope.
    session->CloseAllConnections(ERR_FAILED, "Very good reason");
  }
}

// Test the request-challenge-retry sequence for basic auth, over a keep-alive
// proxy connection with HTTP/1.1 responses, when setting up an SSL tunnel.
TEST_P(HttpNetworkTransactionTest, BasicAuthProxyKeepAliveHttp11) {
  // On the second pass, the body read of the auth challenge is synchronous, so
  // IsConnectedAndIdle returns false.  The socket should still be drained and
  // reused.  See http://crbug.com/544255.
  for (int i = 0; i < 2; ++i) {
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
    RecordingNetLogObserver net_log_observer;
    session_deps_.net_log = NetLog::Get();
    std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    // Since we have proxy, should try to establish tunnel.
    MockWrite data_writes1[] = {
        MockWrite(ASYNC, 0,
                  "CONNECT www.example.org:443 HTTP/1.1\r\n"
                  "Host: www.example.org:443\r\n"
                  "Proxy-Connection: keep-alive\r\n"
                  "User-Agent: test-ua\r\n\r\n"),

        // After calling trans.RestartWithAuth(), this is the request we should
        // be issuing -- the final header line contains the credentials.
        MockWrite(ASYNC, 3,
                  "CONNECT www.example.org:443 HTTP/1.1\r\n"
                  "Host: www.example.org:443\r\n"
                  "Proxy-Connection: keep-alive\r\n"
                  "User-Agent: test-ua\r\n"
                  "Proxy-Authorization: Basic Zm9vOmJheg==\r\n\r\n"),
    };

    // The proxy responds to the connect with a 407, using a persistent
    // connection. (Since it's HTTP/1.0, keep-alive has to be explicit.)
    MockRead data_reads1[] = {
        // No credentials.
        MockRead(ASYNC, 1,
                 "HTTP/1.1 407 Proxy Authentication Required\r\n"
                 "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"
                 "Content-Length: 10\r\n\r\n"),
        MockRead(i == 0 ? ASYNC : SYNCHRONOUS, 2, "0123456789"),

        // Wrong credentials (wrong password).
        MockRead(ASYNC, 4,
                 "HTTP/1.1 407 Proxy Authentication Required\r\n"
                 "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"
                 "Content-Length: 10\r\n\r\n"),
        // No response body because the test stops reading here.
        MockRead(SYNCHRONOUS, ERR_UNEXPECTED, 5),
    };

    SequencedSocketData data1(data_reads1, data_writes1);
    data1.set_busy_before_sync_reads(true);
    session_deps_.socket_factory->AddSocketDataProvider(&data1);

    TestCompletionCallback callback1;

    int rv = trans.Start(&request, callback1.callback(),
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

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    ASSERT_TRUE(response->headers);
    EXPECT_TRUE(response->headers->IsKeepAlive());
    EXPECT_EQ(407, response->headers->response_code());
    EXPECT_EQ(10, response->headers->GetContentLength());
    EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
    EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge));
    EXPECT_FALSE(response->did_use_http_auth);
    EXPECT_EQ(PacResultElementToProxyChain("PROXY myproxy:70"),
              response->proxy_chain);

    TestCompletionCallback callback2;

    // Wrong password (should be "bar").
    rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBaz),
                               callback2.callback());
    EXPECT_THAT(callback2.GetResult(rv), IsOk());

    response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    ASSERT_TRUE(response->headers);
    EXPECT_TRUE(response->headers->IsKeepAlive());
    EXPECT_EQ(407, response->headers->response_code());
    EXPECT_EQ(10, response->headers->GetContentLength());
    EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
    EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge));
    EXPECT_TRUE(response->did_use_http_auth);
    EXPECT_EQ(PacResultElementToProxyChain("PROXY myproxy:70"),
              response->proxy_chain);
```