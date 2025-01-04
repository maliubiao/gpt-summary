Response:
The user wants to understand the functionality of the `http_network_transaction_unittest.cc` file in the Chromium network stack. They are particularly interested in:

1. **General functionality:** What does this file test?
2. **Relationship to JavaScript:** Does this code interact with JavaScript in any way?
3. **Logical reasoning:** Can we infer input and output based on the code?
4. **Common user/programming errors:** What mistakes might users or programmers make related to this code?
5. **Debugging:** How does a user end up interacting with this part of the code, providing debugging clues?
6. **Summary of functionality:**  A concise description of the file's purpose, considering this is part 7 of 34.

Let's analyze the provided code snippet to address these points.

**Code Analysis:**

The code snippet is a C++ unit test for `HttpNetworkTransaction`, a core class in Chromium's network stack responsible for handling HTTP requests. The tests primarily focus on:

* **Proxy authentication:**  The scenarios involve requests going through a proxy server that requires authentication (both Basic proxy authentication and server authentication after the tunnel is established).
* **Caching of authentication credentials:** The tests verify that proxy and server credentials are correctly cached and reused based on the `NetworkAnonymizationKey`.
* **Handling of `407 Proxy Authentication Required` responses:** The tests cover scenarios where the proxy challenges for authentication and how the transaction retries with credentials.
* **Sanitization of proxy authentication headers:**  Ensuring that extraneous headers from the proxy's 407 response are not passed to the caller.
* **Handling of unexpected `407` responses from the server:**  Verifying that receiving a proxy authentication challenge from a non-proxy server results in an error.
* **Scenarios with `CONNECT` tunnels:** Testing authentication flows when establishing a secure tunnel through a proxy.
* **Handling connection closures during authentication:**  Simulating cases where the proxy closes the connection at different stages of the authentication process.
* **Use of `NetworkAnonymizationKey`:**  Testing how authentication caching behaves with different anonymization keys.

**Addressing the User's Questions:**

1. **Functionality:** This file contains unit tests for the `HttpNetworkTransaction` class, specifically focusing on its behavior when dealing with proxy authentication, including secure tunnels (`CONNECT` requests), credential caching, and handling various server responses.

2. **Relationship to JavaScript:** While this C++ code doesn't directly execute JavaScript, the functionality it tests is crucial for web browsers, which heavily rely on JavaScript. For example, if a website hosted on an HTTPS server behind an authenticating proxy is accessed by JavaScript code (e.g., using `fetch` or `XMLHttpRequest`), the underlying network requests will be handled by classes like `HttpNetworkTransaction`.

    * **Example:**  A JavaScript application on a corporate network might try to fetch data from an external API. If the corporate network uses an authenticating proxy, this C++ code ensures that the browser correctly handles the proxy authentication challenge and retries the request with the appropriate credentials.

3. **Logical Reasoning (Input/Output):**

    * **Hypothetical Input:**
        * A `HttpRequestInfo` object representing a `GET` request to an HTTPS URL.
        * Network configuration that includes an authenticating proxy.
        * Mock socket data simulating a proxy returning a `407 Proxy Authentication Required` response.
    * **Expected Output:**
        * The `HttpNetworkTransaction` should return an error initially, indicating the need for authentication.
        * After providing valid proxy credentials via `RestartWithAuth`, the transaction should successfully establish a tunnel and proceed with the request to the target server.
        * If invalid credentials are provided, the transaction might return another error or receive another authentication challenge.

4. **Common User/Programming Errors:**

    * **Incorrect proxy configuration:** Users might enter the wrong proxy server address or port in their browser settings or environment variables. This would lead to connection errors or authentication failures.
    * **Missing proxy credentials:**  Forgetting to provide the username and password required by the proxy server.
    * **Website issues:**  While this code focuses on proxy behavior, issues on the target website (e.g., server authentication requirements) can also lead to similar authentication flows.
    * **Programming errors:**  When developing applications that make HTTP requests, developers might not handle proxy authentication challenges correctly, leading to failed requests. For example, not implementing the logic to retry with credentials after receiving a `407` response.

5. **User Operation and Debugging Clues:**

    A user might reach this part of the code in the following scenario:

    1. **User is on a network with an authenticating proxy server.**
    2. **User attempts to access a website (e.g., `https://www.example.org`) in their browser.**
    3. **The browser detects the need to use a proxy based on network configuration.**
    4. **The browser initiates a `CONNECT` request to the proxy to establish a secure tunnel.**
    5. **The proxy responds with a `407 Proxy Authentication Required` status code.**
    6. **The browser's network stack (including `HttpNetworkTransaction`) receives this response.**
    7. **The browser prompts the user for proxy credentials (if not already cached).**
    8. **The `HttpNetworkTransaction` uses the provided credentials to retry the `CONNECT` request.**

    **Debugging Clues:**

    * **Network errors in the browser's developer tools:**  "net::ERR_PROXY_AUTHENTICATION_REQUIRED" or similar errors indicate a problem with proxy authentication.
    * **Browser prompting for proxy credentials:** This is a direct sign that the proxy requires authentication.
    * **Net logs:** Chromium's net logs provide detailed information about network events, including proxy interactions and authentication challenges. Looking at the logs for events related to `HttpNetworkTransaction`, socket connections, and authentication challenges can help diagnose issues.

6. **Summary of Functionality (Part 7 of 34):**

    This specific part of the `http_network_transaction_unittest.cc` file focuses on testing the `HttpNetworkTransaction`'s ability to handle **proxy authentication scenarios**, particularly when establishing secure tunnels using the `CONNECT` method. It verifies the correct handling of `407` responses, the caching and reuse of proxy and server authentication credentials (considering `NetworkAnonymizationKey`), and the resilience of the transaction to connection closures during the authentication process. It builds upon the foundational HTTP request handling logic and starts to delve into the complexities of interacting with proxy servers.

好的，让我们来分析一下 `net/http/http_network_transaction_unittest.cc` 文件的这段代码片段的功能。

**功能归纳:**

这段代码是 `HttpNetworkTransaction` 类的单元测试的一部分，主要测试了以下功能：

* **通过需要身份验证的代理服务器进行 HTTPS 连接:**  测试了在需要代理身份验证的情况下，如何建立 HTTPS 连接（通过 CONNECT 隧道）。
* **代理身份验证和服务器身份验证的交互:**  测试了当既需要代理身份验证，又需要服务器身份验证时，`HttpNetworkTransaction` 如何处理身份验证流程，包括接收代理质询、提供代理凭据、建立隧道、接收服务器质询、提供服务器凭据。
* **身份验证凭据的缓存和重用 (考虑 NetworkAnonymizationKey):**  重点测试了代理和服务器的身份验证凭据如何根据 `NetworkAnonymizationKey` 进行缓存和重用。不同的 `NetworkAnonymizationKey` 应该使用不同的缓存凭据。
* **代理身份验证头的清理:**  测试了在代理服务器返回 407 错误时，如何清理掉不应该传递给客户端的额外头部信息（例如 `X-Foo`, `Set-Cookie`）。
* **意外的代理身份验证质询:** 测试了当一个非代理服务器返回 407 错误时，`HttpNetworkTransaction` 如何处理，应该返回 `ERR_UNEXPECTED_PROXY_AUTH` 错误。
* **允许默认凭据的代理身份验证方案:** 测试了当代理身份验证方案允许发送默认凭据（空用户名和密码）时，`HttpNetworkTransaction` 的行为。
* **代理服务器在身份验证过程中关闭连接的处理:** 测试了在身份验证的不同阶段，代理服务器关闭连接时，`HttpNetworkTransaction` 的重试机制和错误处理。

**与 JavaScript 的关系:**

这段 C++ 代码本身不直接执行 JavaScript，但它测试的网络功能是浏览器执行 JavaScript 代码（例如使用 `fetch` 或 `XMLHttpRequest` 发起网络请求）的基础。

**举例说明:**

假设一个使用 `fetch` API 的 JavaScript 应用尝试访问一个位于需要身份验证的代理服务器后面的 HTTPS 网站。

1. **JavaScript 发起请求:**  JavaScript 代码调用 `fetch('https://example.com')`。
2. **浏览器网络栈处理:** 浏览器的网络栈会根据配置判断需要通过代理服务器。`HttpNetworkTransaction` 类会负责处理这个请求。
3. **代理身份验证:** 如果代理服务器需要身份验证，`HttpNetworkTransaction` 会先发送一个 `CONNECT` 请求到代理服务器，尝试建立隧道。
4. **代理返回 407:** 代理服务器返回 `407 Proxy Authentication Required`。这段测试代码就是为了验证 `HttpNetworkTransaction` 是否正确处理这种情况。
5. **浏览器提示用户输入凭据:** 浏览器会提示用户输入代理服务器的用户名和密码。
6. **`HttpNetworkTransaction` 重试:**  用户输入凭据后，`HttpNetworkTransaction` 会使用这些凭据再次发送 `CONNECT` 请求，这次请求头中会包含 `Proxy-Authorization` 头部。
7. **建立隧道:**  如果凭据正确，代理服务器返回 `200 Connection Established`，隧道建立成功。
8. **请求目标网站:**  `HttpNetworkTransaction` 会通过建立的隧道发送对 `https://example.com` 的实际请求。
9. **服务器身份验证 (如果需要):** 如果目标服务器也需要身份验证，可能会返回 `401 Authentication Required`，`HttpNetworkTransaction` 会再次处理身份验证流程。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* `HttpRequestInfo` 对象，`url` 为 `https://myproxy:70/`， 需要通过代理。
* 模拟的 Socket 数据，先返回代理身份验证质询 (`407 Proxy Authentication Required`)，然后返回隧道建立成功 (`200 Connection Established`)，接着返回服务器身份验证质询 (`401 Authentication Required`)，最后返回成功响应 (`200 OK`)。
* 模拟的 Socket 数据用于不同的 `NetworkAnonymizationKey` 的请求。

**预期输出:**

* 第一次 `trans->Start()` 调用后，`GetResponseInfo()->headers->response_code()` 应该为 `407`。
* 第一次 `trans->RestartWithAuth()` (使用代理凭据) 调用后，`GetResponseInfo()->headers->response_code()` 应该为 `401`。
* 第二次 `trans->RestartWithAuth()` (使用服务器凭据) 调用后，`GetResponseInfo()->headers->response_code()` 应该为 `200`，并且可以成功读取响应数据。
* 身份验证凭据应该根据 `NetworkAnonymizationKey` 被正确缓存。

**用户或编程常见的使用错误:**

* **错误的代理配置:** 用户在浏览器或操作系统中配置了错误的代理服务器地址或端口。
* **未提供代理凭据:** 用户没有配置或输入正确的代理服务器用户名和密码。
* **服务端配置错误:**  虽然这段代码主要测试代理，但服务端配置错误（例如错误的身份验证配置）也可能导致类似的问题。
* **程序代码未处理代理身份验证:**  开发者在使用 `fetch` 或 `XMLHttpRequest` 时，可能没有正确处理代理服务器返回的 407 错误，导致请求失败。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在公司或学校网络中浏览网页:** 这些网络通常使用代理服务器进行访问控制和安全管理。
2. **用户尝试访问 HTTPS 网站:** 由于是 HTTPS，需要通过 CONNECT 隧道与代理服务器建立安全连接。
3. **代理服务器需要身份验证:**  代理服务器配置为需要用户提供用户名和密码才能建立连接。
4. **浏览器发起 CONNECT 请求:** 浏览器会向代理服务器发送一个 CONNECT 请求。
5. **代理服务器返回 407:** 代理服务器拒绝连接，并返回 407 状态码，要求提供身份验证信息。
6. **浏览器接收到 407 响应:** `HttpNetworkTransaction` 类会处理这个响应。
7. **浏览器提示用户输入代理凭据:** 浏览器界面会弹出一个对话框，要求用户输入用户名和密码。
8. **用户输入凭据:** 用户输入正确的用户名和密码。
9. **浏览器使用凭据重试 CONNECT 请求:** `HttpNetworkTransaction` 会使用用户提供的凭据重新发送 CONNECT 请求，请求头中包含 `Proxy-Authorization` 头部。

作为调试线索，如果用户报告无法访问某些 HTTPS 网站，并且提示需要代理身份验证，那么很有可能涉及到这段代码测试的逻辑。开发者可以通过查看浏览器的网络日志 (chrome://net-export/)，或者使用抓包工具 (如 Wireshark) 来分析网络请求和响应，确认是否是代理身份验证的问题。

**第 7 部分，共 34 部分的功能归纳:**

作为系列测试的第 7 部分，这段代码深入测试了 `HttpNetworkTransaction` 在 **代理身份验证** 方面的核心功能，特别是针对 **HTTPS 连接和 CONNECT 隧道** 的场景。它验证了身份验证流程的正确性，凭据缓存的机制，以及对各种错误情况的处理。可以推断，前面的部分可能测试了更基础的 HTTP 请求处理，而后面的部分可能会涉及更复杂的功能，例如 HTTP/2, QUIC, 或更高级的缓存策略等。 这部分专注于代理交互，是网络栈中一个重要的组成部分。

Prompt: 
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共34部分，请归纳一下它的功能

"""
nection: keep-alive\r\n"
                "User-Agent: test-ua\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
      // Request over the tunnel, which gets a server auth challenge.
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: myproxy:70\r\n"
                "Connection: keep-alive\r\n\r\n"),
      // Retry with server auth credentials, which gets a response.
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: myproxy:70\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: Basic Zm9vMjpiYXIy\r\n\r\n"),
      // Another request to the same server and using the same NAK should
      // preemptively send the correct cached server
      // auth header. Since a tunnel was already established, the proxy headers
      // won't be sent again except when establishing another tunnel.
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: myproxy:70\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: Basic Zm9vMjpiYXIy\r\n\r\n"),
  };

  MockRead data_reads[] = {
      // Proxy auth challenge.
      MockRead("HTTP/1.0 407 Proxy Authentication Required\r\n"
               "Proxy-Connection: keep-alive\r\n"
               "User-Agent: test-ua\r\n"
               "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"
               "Content-Length: 0\r\n\r\n"),
      // Tunnel success
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),
      // Server auth challenge.
      MockRead("HTTP/1.0 401 Authentication Required\r\n"
               "Connection: keep-alive\r\n"
               "WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"
               "Content-Length: 0\r\n\r\n"),
      // Response.
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Content-Length: 5\r\n\r\n"
               "hello"),
      // Response to second request.
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Content-Length: 2\r\n\r\n"
               "hi"),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  // One for the proxy connection, one of the server connection.
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  MockWrite data_writes2[] = {
      // Initial request using a different NetworkAnonymizationKey includes the
      // cached proxy credentials when establishing a tunnel.
      MockWrite("CONNECT myproxy:70 HTTP/1.1\r\n"
                "Host: myproxy:70\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
      // Request over the tunnel, which gets a server auth challenge. Cached
      // credentials cannot be used, since the NAK is different.
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: myproxy:70\r\n"
                "Connection: keep-alive\r\n\r\n"),
      // Retry with server auth credentials, which gets a response.
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: myproxy:70\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: Basic Zm9vMzpiYXIz\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      // Tunnel success
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),
      // Server auth challenge.
      MockRead("HTTP/1.0 401 Authentication Required\r\n"
               "Connection: keep-alive\r\n"
               "WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"
               "Content-Length: 0\r\n\r\n"),
      // Response.
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Content-Length: 9\r\n\r\n"
               "greetings"),
  };

  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  // One for the proxy connection, one of the server connection.
  SSLSocketDataProvider ssl3(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl3);
  SSLSocketDataProvider ssl4(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl4);

  TestCompletionCallback callback;

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://myproxy:70/");
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
  EXPECT_TRUE(CheckBasicSecureProxyAuth(response->auth_challenge));

  rv = trans->RestartWithAuth(AuthCredentials(kFoo, kBar), callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_EQ(401, response->headers->response_code());
  EXPECT_FALSE(response->auth_challenge->is_proxy);
  EXPECT_EQ("https://myproxy:70",
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
      url::SchemeHostPort(url::SchemeHostPort(GURL("https://myproxy:70"))),
      HttpAuth::AUTH_PROXY, "MyRealm1", HttpAuth::AUTH_SCHEME_BASIC,
      kNetworkAnonymizationKey1);
  ASSERT_TRUE(entry);
  ASSERT_EQ(kFoo, entry->credentials().username());
  ASSERT_EQ(kBar, entry->credentials().password());
  EXPECT_EQ(entry, session->http_auth_cache()->Lookup(
                       url::SchemeHostPort(GURL("https://myproxy:70")),
                       HttpAuth::AUTH_PROXY, "MyRealm1",
                       HttpAuth::AUTH_SCHEME_BASIC, kNetworkAnonymizationKey2));

  // Check that the server credentials were cached correctly. The should be
  // accessible with only kNetworkAnonymizationKey1.
  entry = session->http_auth_cache()->Lookup(
      url::SchemeHostPort(GURL("https://myproxy:70")), HttpAuth::AUTH_SERVER,
      "MyRealm1", HttpAuth::AUTH_SCHEME_BASIC, kNetworkAnonymizationKey1);
  ASSERT_TRUE(entry);
  ASSERT_EQ(kFoo2, entry->credentials().username());
  ASSERT_EQ(kBar2, entry->credentials().password());
  // Looking up the server entry with another NetworkAnonymiationKey should
  // fail.
  EXPECT_FALSE(session->http_auth_cache()->Lookup(
      url::SchemeHostPort(GURL("https://myproxy:70")), HttpAuth::AUTH_SERVER,
      "MyRealm1", HttpAuth::AUTH_SCHEME_BASIC, kNetworkAnonymizationKey2));

  // Make another request with a different NetworkAnonymiationKey. It should use
  // another socket, reuse the cached proxy credentials, but result in a server
  // auth challenge.
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
  EXPECT_EQ("https://myproxy:70",
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
      url::SchemeHostPort(GURL("https://myproxy:70")), HttpAuth::AUTH_PROXY,
      "MyRealm1", HttpAuth::AUTH_SCHEME_BASIC, kNetworkAnonymizationKey1);
  ASSERT_TRUE(entry);
  ASSERT_EQ(kFoo, entry->credentials().username());
  ASSERT_EQ(kBar, entry->credentials().password());
  EXPECT_EQ(entry, session->http_auth_cache()->Lookup(
                       url::SchemeHostPort(GURL("https://myproxy:70")),
                       HttpAuth::AUTH_PROXY, "MyRealm1",
                       HttpAuth::AUTH_SCHEME_BASIC, kNetworkAnonymizationKey2));

  // Check that the correct server credentials are cached for each
  // NetworkAnonymiationKey.
  entry = session->http_auth_cache()->Lookup(
      url::SchemeHostPort(GURL("https://myproxy:70")), HttpAuth::AUTH_SERVER,
      "MyRealm1", HttpAuth::AUTH_SCHEME_BASIC, kNetworkAnonymizationKey1);
  ASSERT_TRUE(entry);
  ASSERT_EQ(kFoo2, entry->credentials().username());
  ASSERT_EQ(kBar2, entry->credentials().password());
  entry = session->http_auth_cache()->Lookup(
      url::SchemeHostPort(GURL("https://myproxy:70")), HttpAuth::AUTH_SERVER,
      "MyRealm1", HttpAuth::AUTH_SCHEME_BASIC, kNetworkAnonymizationKey2);
  ASSERT_TRUE(entry);
  ASSERT_EQ(kFoo3, entry->credentials().username());
  ASSERT_EQ(kBar3, entry->credentials().password());

  // Make a request with the original NetworkAnonymiationKey. It should reuse
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

// Test that we don't pass extraneous headers from the proxy's response to the
// caller when the proxy responds to CONNECT with 407.
TEST_P(HttpNetworkTransactionTest, SanitizeProxyAuthHeaders) {
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
      MockRead("X-Foo: bar\r\n"),
      MockRead("Set-Cookie: foo=bar\r\n"),
      MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Content-Length: 10\r\n\r\n"),
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
  EXPECT_FALSE(response->headers->HasHeader("X-Foo"));
  EXPECT_FALSE(response->headers->HasHeader("Set-Cookie"));

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsError(ERR_TUNNEL_CONNECTION_FAILED));

  // Flush the idle socket before the HttpNetworkTransaction goes out of scope.
  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

// Test when a server (non-proxy) returns a 407 (proxy-authenticate).
// The request should fail with ERR_UNEXPECTED_PROXY_AUTH.
TEST_P(HttpNetworkTransactionTest, UnexpectedProxyAuth) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // We are using a DIRECT connection (i.e. no proxy) for this session.
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.0 407 Proxy Auth required\r\n"),
      MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      // Large content-length -- won't matter, as connection will be reset.
      MockRead("Content-Length: 10000\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_UNEXPECTED_PROXY_AUTH));
}

// Tests when an HTTPS server (non-proxy) returns a 407 (proxy-authentication)
// through a non-authenticating proxy. The request should fail with
// ERR_UNEXPECTED_PROXY_AUTH.
// Note that it is impossible to detect if an HTTP server returns a 407 through
// a non-authenticating proxy - there is nothing to indicate whether the
// response came from the proxy or the server, so it is treated as if the proxy
// issued the challenge.
TEST_P(HttpNetworkTransactionTest, HttpsServerRequestsProxyAuthThroughProxy) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  RecordingNetLogObserver net_log_observer;
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),

      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),

      MockRead("HTTP/1.1 407 Unauthorized\r\n"),
      MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_UNEXPECTED_PROXY_AUTH));
  auto entries = net_log_observer.GetEntries();
  size_t pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_TUNNEL_HEADERS,
      NetLogEventPhase::NONE);
  ExpectLogContainsSomewhere(
      entries, pos,
      NetLogEventType::HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS,
      NetLogEventPhase::NONE);
}

// Test a proxy auth scheme that allows default credentials and a proxy server
// that uses non-persistent connections.
TEST_P(HttpNetworkTransactionTest,
       AuthAllowsDefaultCredentialsTunnelConnectionClose) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "PROXY myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);

  auto auth_handler_factory = std::make_unique<HttpAuthHandlerMock::Factory>();
  auth_handler_factory->set_do_init_from_challenge(true);
  auto mock_handler = std::make_unique<HttpAuthHandlerMock>();
  mock_handler->set_allows_default_credentials(true);
  auth_handler_factory->AddMockHandler(std::move(mock_handler),
                                       HttpAuth::AUTH_PROXY);
  session_deps_.http_auth_handler_factory = std::move(auth_handler_factory);

  // Add NetLog just so can verify load timing information gets a NetLog ID.
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

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
      MockRead("Proxy-Authenticate: Mock\r\n"),
      MockRead("Proxy-Connection: close\r\n\r\n"),
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
                "Proxy-Authorization: auth_token\r\n\r\n"),

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

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_FALSE(response->headers->IsKeepAlive());
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(trans->IsReadyToRestartForAuth());
  EXPECT_FALSE(response->auth_challenge.has_value());

  LoadTimingInfo load_timing_info;
  // CONNECT requests and responses are handled at the connect job level, so
  // the transaction does not yet have a connection.
  EXPECT_FALSE(trans->GetLoadTimingInfo(&load_timing_info));

  rv = trans->RestartWithAuth(AuthCredentials(), callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
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

// Test a proxy auth scheme that allows default credentials and a proxy server
// that hangs up when credentials are initially sent.
TEST_P(HttpNetworkTransactionTest,
       AuthAllowsDefaultCredentialsTunnelServerClosesConnection) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "PROXY myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);

  auto auth_handler_factory = std::make_unique<HttpAuthHandlerMock::Factory>();
  auth_handler_factory->set_do_init_from_challenge(true);
  auto mock_handler = std::make_unique<HttpAuthHandlerMock>();
  mock_handler->set_allows_default_credentials(true);
  auth_handler_factory->AddMockHandler(std::move(mock_handler),
                                       HttpAuth::AUTH_PROXY);
  session_deps_.http_auth_handler_factory = std::move(auth_handler_factory);

  // Add NetLog just so can verify load timing information gets a NetLog ID.
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

  // Should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),

      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n"
                "Proxy-Authorization: auth_token\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407, using a non-persistent
  // connection.
  MockRead data_reads1[] = {
      // No credentials.
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("Proxy-Authenticate: Mock\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_CONNECTION_CLOSED),
  };

  // Since the first connection was closed, need to establish another once given
  // credentials.
  MockWrite data_writes2[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n"
                "Proxy-Authorization: auth_token\r\n\r\n"),

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

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(trans->IsReadyToRestartForAuth());
  EXPECT_FALSE(response->auth_challenge.has_value());

  LoadTimingInfo load_timing_info;
  // CONNECT requests and responses are handled at the connect job level, so
  // the transaction does not yet have a connection.
  EXPECT_FALSE(trans->GetLoadTimingInfo(&load_timing_info));

  rv = trans->RestartWithAuth(AuthCredentials(), callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
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

// Test a proxy auth scheme that allows default credentials and a proxy server
// that hangs up when credentials are initially sent, and hangs up again when
// they are retried.
TEST_P(HttpNetworkTransactionTest,
       AuthAllowsDefaultCredentialsTunnelServerClosesConnectionTwice) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "PROXY myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);

  auto auth_handler_factory = std::make_unique<HttpAuthHandlerMock::Factory>();
  auth_handler_factory->set_do_init_from_challenge(true);
  auto mock_handler = std::make_unique<HttpAuthHandlerMock>();
  mock_handler->set_allows_default_credentials(true);
  auth_handler_factory->AddMockHandler(std::move(mock_handler),
                                       HttpAuth::AUTH_PROXY);
  session_deps_.http_auth_handler_factory = std::move(auth_handler_factory);

  // Add NetLog just so can verify load timing information gets a NetLog ID.
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

  // Should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),

      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n"
                "Proxy-Authorization: auth_token\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407, and then hangs up after the
  // second request is sent.
  MockRead data_reads1[] = {
      // No credentials.
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("Content-Length: 0\r\n"),
      MockRead("Proxy-Connection: keep-alive\r\n"
               "User-Agent: test-ua\r\n"),
      MockRead("Proxy-Authenticate: Mock\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_CONNECTION_CLOSED),
  };

  // HttpNetworkTransaction sees a reused connection that was closed with
  // ERR_CONNECTION_CLOSED, realized it might have been a race, so retries the
  // request.
  MockWrite data_writes2[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
  };

  // The proxy, having had more than enough of us, just hangs up.
  MockRead data_reads2[] = {
      // No credentials.
      MockRead(SYNCHRONOUS, ERR_CONNECTION_CLOSED),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(trans->IsReadyToRestartForAuth());
  EXPECT_FALSE(response->auth_challenge.has_value());

  LoadTimingInfo load_timing_info;
  EXPECT_FALSE(trans->GetLoadTimingInfo(&load_timing_info));

  rv = trans->RestartWithAuth(AuthCredentials(), callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_EMPTY_RESPONSE));

  trans.reset();
  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

// This test exercises an odd edge case where the proxy closes the connection
// after the authentication handshake is complete. Presumably this technique is
// used in lieu of returning a 403 or 5xx status code when the authentication
// succeeds, but the user is not authorized to connect to the destination
// server. There's no standard for what a proxy should do to indicate a blocked
// site.
TEST_P(HttpNetworkTransactionTest,
       AuthAllowsDefaultCredentialsTunnelConnectionClosesBeforeBody
"""


```