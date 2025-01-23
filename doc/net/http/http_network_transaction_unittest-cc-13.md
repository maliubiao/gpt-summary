Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The user wants to understand the functionality of a specific Chromium source code file (`net/http/http_network_transaction_unittest.cc`), its relationship with JavaScript, examples of its logic, common usage errors, debugging steps, and a summary of its purpose. The user also specifies that this is part 14 of 34.

2. **Initial Analysis of the File Name:** The name "http_network_transaction_unittest.cc" immediately suggests that this file contains unit tests for the `HttpNetworkTransaction` class. This class is likely responsible for managing the lifecycle of an HTTP request within the Chromium network stack. The "unittest" suffix is a strong indicator.

3. **Scan the Code for Key Patterns and Functionality:** I'll read through the provided code snippet, looking for:
    * **Test Macros:** `TEST_P`, `TEST_F`, `EXPECT_THAT`, `EXPECT_EQ`, etc. These confirm it's a testing file.
    * **Class Instantiation:**  Instances of `HttpNetworkTransaction`, `HttpNetworkSession`, `HttpRequestInfo`, `HttpResponseInfo`, `MockWrite`, `MockRead`, `StaticSocketDataProvider`, `SSLSocketDataProvider`, `TestCompletionCallback`, etc. These reveal the components being tested and mocked.
    * **Specific HTTP Scenarios:** Look for patterns like proxy authentication (407 responses, `Proxy-Authenticate` headers, `Proxy-Authorization` headers), different HTTP status codes in CONNECT requests, retries with authentication, and changes in proxy configurations.
    * **Focus Areas:** The code heavily revolves around testing different proxy authentication scenarios (basic auth, HTTPS proxy, proxy changes) and how the `HttpNetworkTransaction` handles these situations, including retries and header manipulation. It also includes tests for how different HTTP status codes are handled during a CONNECT request.

4. **Address Each Point of the Request Systematically:**

    * **Functionality:** Based on the code scan, the primary functions are:
        * **Testing Proxy Authentication:**  Covering various scenarios like initial requests without credentials, challenge-response cycles, successful authentication, and changes in proxy configuration.
        * **Testing CONNECT Method and Status Codes:** Verifying how `HttpNetworkTransaction` reacts to different HTTP status codes received during a CONNECT request for establishing an HTTPS tunnel through a proxy.

    * **Relationship with JavaScript:**  This is a bit indirect. JavaScript running in a web page uses the browser's network stack to make HTTP requests. The `HttpNetworkTransaction` is a core part of that stack. When JavaScript makes a fetch request or an XMLHttpRequest that goes through a proxy requiring authentication, the logic tested in this file comes into play. The examples should illustrate this.

    * **Logical Reasoning (Hypothetical Input/Output):** Choose a simple test case, like the HTTPS proxy authentication retry. Explain the input (an initial request without auth) and the expected output (a 407 response, followed by a retry with credentials, and finally a 200 OK).

    * **User/Programming Errors:** Think about common mistakes users or developers might make that would lead to this code being executed or revealing issues. Incorrect proxy settings, forgetting credentials, or issues with proxy server configuration are good examples.

    * **User Steps to Reach Here (Debugging Clues):**  Trace the user's actions. A user trying to access a website that requires proxy authentication is the most direct path. Explain the steps the browser takes behind the scenes.

    * **Summary of Functionality (Given it's Part 14/34):** Synthesize the key findings. Emphasize the focus on testing the core logic of handling HTTP transactions, particularly around proxy authentication and CONNECT. Acknowledge its place within a larger testing suite.

5. **Refine and Organize the Answer:** Structure the answer clearly, using headings and bullet points to address each part of the request. Provide specific code snippets or references to the provided text when illustrating points. Ensure the language is clear and concise. For example, when explaining the JavaScript relationship, avoid overly technical jargon and focus on the user-facing implications.

6. **Self-Correction/Review:**  Read through the generated answer. Does it accurately reflect the functionality of the code? Are the examples clear and relevant? Is the explanation of the JavaScript relationship accurate?  Are the debugging steps logical?  Is the summary concise and informative?  For instance, initially, I might focus too much on the technical details of the `HttpNetworkTransaction` class. I'd then step back and make sure the explanation is accessible to someone who might not be a networking expert. I'd also ensure that the examples directly relate to the provided code snippet and not just general networking concepts.好的，我们来分析一下 `net/http/http_network_transaction_unittest.cc` 文件的第 14 部分（共 34 部分）。

**功能列举:**

从提供的代码片段来看，这部分 `HttpNetworkTransactionTest` 主要关注以下功能测试：

1. **HTTPS 代理认证重试机制 (Keep-Alive 和非 Keep-Alive)：**
   - 测试了通过 HTTPS 代理服务器访问资源时，如果代理服务器返回 407 Proxy Authentication Required 状态码，`HttpNetworkTransaction` 如何处理认证挑战，并使用提供的凭据进行重试。
   - 分别测试了代理连接保持活跃 (`Proxy-Connection: keep-alive`) 和不保持活跃 (`Proxy-Connection: close`) 两种情况下的重试流程。

2. **HTTPS 代理认证重试并更换代理服务器：**
   - 测试了在代理认证重试过程中，代理服务器发生变化的情况，`HttpNetworkTransaction` 如何处理并连接到新的代理服务器。

3. **HTTPS 代理认证重试并切换到直连：**
   - 测试了在代理认证重试过程中，切换为直连（不使用代理）的情况，`HttpNetworkTransaction` 如何处理并直接连接到目标服务器。

4. **测试 CONNECT 方法的不同状态码：**
   - 通过 `ConnectStatusHelper` 函数，测试了当使用代理进行 HTTPS 连接时，代理服务器在 CONNECT 请求返回不同的 HTTP 状态码时，`HttpNetworkTransaction` 的行为。这些状态码涵盖了 1xx (信息性状态码), 2xx (成功状态码), 3xx (重定向状态码), 4xx (客户端错误状态码) 和 5xx (服务器错误状态码)。
   - 预期大部分非 200 状态码都会导致 `ERR_TUNNEL_CONNECTION_FAILED` 错误。

5. **基本认证：代理服务器后接源服务器认证：**
   - 测试了需要两级认证的场景：先通过代理服务器的 Basic 认证，然后再通过源服务器的 Basic 认证。`HttpNetworkTransaction` 需要进行两次 `RestartWithAuth` 调用来完成整个认证流程。

6. **NTLM 认证测试 (部分)：**
   - 提供了 NTLM 认证的测试用例，展示了在遇到 401 认证挑战时，如何通过 `RestartWithAuth` 发送包含协商消息（Type 1）的请求头。

**与 JavaScript 的关系及举例说明:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的网络栈功能是 JavaScript 发起网络请求的基础。当 JavaScript 代码（例如通过 `fetch` API 或 `XMLHttpRequest`）向需要代理认证的 HTTPS 网站发送请求时，底层的 `HttpNetworkTransaction` 就会执行这里测试的逻辑。

**举例说明:**

假设一个 JavaScript 应用程序尝试访问 `http://www.example.org/`，并且浏览器配置了使用 HTTPS 代理 `https://myproxy:70`，该代理需要 Basic 认证。

1. **JavaScript 发起请求：**
   ```javascript
   fetch('http://www.example.org/')
     .then(response => response.text())
     .then(data => console.log(data));
   ```

2. **`HttpNetworkTransaction` 的初始请求 (对应 `data_writes1`):**
   浏览器会发送一个不带认证信息的请求到代理服务器：
   ```
   GET http://www.example.org/ HTTP/1.1
   Host: www.example.org
   Proxy-Connection: keep-alive
   ```

3. **代理服务器返回 407 (对应 `data_reads1`):**
   代理服务器返回 407 状态码，并告知需要 Basic 认证：
   ```
   HTTP/1.1 407 Proxy Authentication Required
   Proxy-Authenticate: Basic realm="MyRealm1"
   Proxy-Connection: keep-alive
   Content-Length: 0
   ```

4. **浏览器提示用户输入凭据 (假设用户输入了 "foo" 和 "bar")。**

5. **`HttpNetworkTransaction` 调用 `RestartWithAuth` 并发送带认证信息的请求 (对应 `data_writes1` 的第二个 MockWrite):**
   浏览器使用用户提供的凭据重新发送请求：
   ```
   GET http://www.example.org/ HTTP/1.1
   Host: www.example.org
   Proxy-Connection: keep-alive
   Proxy-Authorization: Basic Zm9vOmJhcg==
   ```

6. **代理服务器验证凭据并转发请求，最终返回 200 OK (对应 `data_reads1` 的后续 MockRead):**
   ```
   HTTP/1.1 200 OK
   Content-Type: text/html; charset=iso-8859-1
   Content-Length: 100
   ```

7. **JavaScript 接收到响应数据并处理。**

**逻辑推理 (假设输入与输出):**

**场景：HTTPS 代理认证重试 (非 Keep-Alive)**

**假设输入：**

- `HttpRequestInfo`: 请求方法为 "GET"，URL 为 "http://www.example.org/"，需要通过 HTTPS 代理 "https://myproxy:70"。
- 初始请求不包含代理认证信息。
- 代理服务器返回 407 状态码，`Proxy-Authenticate: Basic realm="MyRealm1"`，`Proxy-Connection: close`。
- 用户提供的凭据为 "foo" 和 "bar"。
- 第二次请求的代理服务器返回 200 OK。

**预期输出：**

- 第一次请求完成时，`HttpResponseInfo` 的 `response_code` 为 407，`auth_challenge` 包含 Basic 认证信息，`did_use_http_auth` 为 false。
- 调用 `RestartWithAuth` 后，会发送包含 `Proxy-Authorization` 头的第二次请求。
- 第二次请求完成时，`HttpResponseInfo` 的 `response_code` 为 200，`did_use_http_auth` 为 true。

**用户或编程常见的使用错误及举例说明:**

1. **用户配置了错误的代理服务器地址或端口：** 这会导致连接失败，可能触发与代理相关的错误处理逻辑，但不会直接到达这里的认证重试逻辑。

2. **用户忘记提供代理服务器所需的用户名和密码：** 这会导致初始请求被代理服务器拒绝（返回 407），然后浏览器会提示用户输入凭据。如果用户取消输入，`RestartWithAuth` 就不会被调用。

3. **编程错误：在 JavaScript 中错误处理 `fetch` 或 `XMLHttpRequest` 的错误响应：**  例如，没有正确处理 407 状态码，导致无法引导用户进行身份验证。

4. **编程错误：在 C++ 代码中，`HttpNetworkTransaction` 的使用者没有正确调用 `RestartWithAuth` 方法来处理认证挑战：** 这会导致认证流程无法完成。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中输入一个网址，例如 `http://www.example.org/`。**
2. **浏览器根据系统或用户配置的代理设置，确定需要使用代理服务器，例如 `https://myproxy:70`。**
3. **`HttpNetworkTransaction` 发起到代理服务器的连接。**
4. **`HttpNetworkTransaction` 构建并发送初始的 HTTP 请求，不包含代理认证信息。**
5. **代理服务器返回 407 Proxy Authentication Required 状态码。**
6. **`HttpNetworkTransaction` 解析响应头，识别出需要代理认证。**
7. **浏览器 UI 可能会提示用户输入代理服务器的用户名和密码。**
8. **用户输入用户名和密码并确认。**
9. **`HttpNetworkTransaction` 使用用户提供的凭据调用 `RestartWithAuth` 方法。**
10. **`HttpNetworkTransaction` 构建并发送带有 `Proxy-Authorization` 头的新的 HTTP 请求。**
11. **代理服务器验证凭据，如果成功，则将请求转发到目标服务器，并将目标服务器的响应返回给浏览器。**

在调试时，可以关注网络请求的 header 信息，查看是否收到了 407 响应，以及后续请求是否包含了 `Proxy-Authorization` 头。也可以断点调试 `HttpNetworkTransaction` 的相关代码，查看认证流程的执行情况。

**功能归纳 (作为第 14 部分):**

这部分 `http_network_transaction_unittest.cc` 的主要功能是**详尽地测试 `HttpNetworkTransaction` 类在处理需要 HTTPS 代理认证的场景下的各种情况，包括认证重试机制、代理服务器变更以及 CONNECT 方法对不同状态码的处理。** 它确保了网络栈在复杂的代理认证流程中能够正确地处理认证挑战、管理连接，并最终成功完成请求。作为 34 个测试部分中的一部分，它专注于代理认证相关的特定功能点，验证了这些关键网络交互的正确性。

### 提示词
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第14部分，共34部分，请归纳一下它的功能
```

### 源代码
```cpp
TION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since we have proxy, should use full url
  MockWrite data_writes1[] = {
      MockWrite("GET http://www.example.org/ HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),

      // After calling trans.RestartWithAuth(), this is the request we should
      // be issuing -- the final header line contains the credentials.
      MockWrite("GET http://www.example.org/ HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  // The proxy responds to the GET with a 407, using a persistent
  // connection.
  MockRead data_reads1[] = {
      // No credentials.
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Proxy-Connection: keep-alive\r\n"),
      MockRead("Content-Length: 0\r\n\r\n"),

      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info,
                          CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(CheckBasicSecureProxyAuth(response->auth_challenge));
  EXPECT_FALSE(response->did_use_http_auth);
  EXPECT_EQ(PacResultElementToProxyChain("HTTPS myproxy:70"),
            response->proxy_chain);

  TestCompletionCallback callback2;

  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  load_timing_info = LoadTimingInfo();
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  // Retrying with HTTP AUTH is considered to be reusing a socket.
  TestLoadTimingReused(load_timing_info);

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(100, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(response->did_use_http_auth);
  EXPECT_EQ(PacResultElementToProxyChain("HTTPS myproxy:70"),
            response->proxy_chain);

  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge.has_value());
}

// Test the challenge-response-retry sequence through an HTTPS Proxy over a
// connection that requires a restart.
TEST_P(HttpNetworkTransactionTest, HttpsProxyAuthRetryNoKeepAlive) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  // when the no authentication data flag is set.
  request.privacy_mode = PRIVACY_MODE_ENABLED;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against https proxy server "myproxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since we have proxy, should use full url
  MockWrite data_writes1[] = {
      MockWrite("GET http://www.example.org/ HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  // The proxy responds to the GET with a 407, using a non-persistent
  // connection.
  MockRead data_reads1[] = {
      // No credentials.
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Proxy-Connection: close\r\n"),
      MockRead("Content-Length: 0\r\n\r\n"),
  };

  MockWrite data_writes2[] = {
      // After calling trans.RestartWithAuth(), this is the request we should
      // be issuing -- the final header line contains the credentials.
      MockWrite("GET http://www.example.org/ HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  // One per each proxy connection.
  SSLSocketDataProvider ssl1(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info,
                          CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(CheckBasicSecureProxyAuth(response->auth_challenge));
  EXPECT_FALSE(response->did_use_http_auth);
  EXPECT_EQ(PacResultElementToProxyChain("HTTPS myproxy:70"),
            response->proxy_chain);

  TestCompletionCallback callback2;

  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  load_timing_info = LoadTimingInfo();
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info,
                          CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(100, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(response->did_use_http_auth);
  EXPECT_EQ(PacResultElementToProxyChain("HTTPS myproxy:70"),
            response->proxy_chain);

  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge.has_value());
}

// Test the challenge-response-retry sequence through an HTTPS Proxy over a
// connection that requires a restart, with a proxy change occurring over the
// restart.
TEST_P(HttpNetworkTransactionTest, HttpsProxyAuthRetryNoKeepAliveChangeProxy) {
  const auto proxy_chain1 = PacResultElementToProxyChain("HTTPS myproxy:70");
  const auto proxy_chain2 = PacResultElementToProxyChain("HTTPS myproxy2:70");

  session_deps_.proxy_delegate = std::make_unique<TestProxyDelegate>();
  auto* proxy_delegate =
      static_cast<TestProxyDelegate*>(session_deps_.proxy_delegate.get());
  proxy_delegate->set_proxy_chain(proxy_chain1);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  // when the no authentication data flag is set.
  request.privacy_mode = PRIVACY_MODE_ENABLED;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against https proxy server "myproxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.proxy_resolution_service->SetProxyDelegate(proxy_delegate);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since we have proxy, should use full url
  MockWrite data_writes1[] = {
      MockWrite("GET http://www.example.org/ HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  // The proxy responds to the GET with a 407, using a non-persistent
  // connection.
  MockRead data_reads1[] = {
      // No credentials.
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Proxy-Connection: close\r\n"),
      MockRead("Content-Length: 0\r\n\r\n"),
  };

  MockWrite data_writes2[] = {
      // After calling trans.RestartWithAuth(), this is the request we should
      // be issuing -- the final header line contains the credentials.
      MockWrite("GET http://www.example.org/ HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  // One per each proxy connection.
  SSLSocketDataProvider ssl1(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info,
                          CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(CheckBasicSecureProxyAuth(response->auth_challenge));
  EXPECT_FALSE(response->did_use_http_auth);
  EXPECT_EQ(proxy_chain1, response->proxy_chain);

  TestCompletionCallback callback2;

  // Configure against https proxy server "myproxy2:70".
  proxy_delegate->set_proxy_chain(proxy_chain2);

  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  load_timing_info = LoadTimingInfo();
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info,
                          CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(100, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(response->did_use_http_auth);
  EXPECT_EQ(proxy_chain2, response->proxy_chain);

  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge.has_value());
}

// Test the challenge-response-retry sequence through an HTTPS Proxy over a
// connection that requires a restart, with a change to a direct connection
// occurring over the restart.
TEST_P(HttpNetworkTransactionTest,
       HttpsProxyAuthRetryNoKeepAliveChangeToDirect) {
  const auto proxy_chain = PacResultElementToProxyChain("HTTPS myproxy:70");
  const auto direct = ProxyChain::Direct();

  session_deps_.proxy_delegate = std::make_unique<TestProxyDelegate>();
  auto* proxy_delegate =
      static_cast<TestProxyDelegate*>(session_deps_.proxy_delegate.get());
  proxy_delegate->set_proxy_chain(proxy_chain);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  // when the no authentication data flag is set.
  request.privacy_mode = PRIVACY_MODE_ENABLED;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against https proxy server "myproxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.proxy_resolution_service->SetProxyDelegate(proxy_delegate);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since we have proxy, should use full url
  MockWrite data_writes1[] = {
      MockWrite("GET http://www.example.org/ HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  // The proxy responds to the GET with a 407, using a non-persistent
  // connection.
  MockRead data_reads1[] = {
      // No credentials.
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Proxy-Connection: close\r\n"),
      MockRead("Content-Length: 0\r\n\r\n"),
  };

  MockWrite data_writes2[] = {
      // After calling trans.RestartWithAuth(), this is the request we should
      // be issuing.
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  // One per each connection.
  SSLSocketDataProvider ssl1(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info,
                          CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(CheckBasicSecureProxyAuth(response->auth_challenge));
  EXPECT_FALSE(response->did_use_http_auth);
  EXPECT_EQ(proxy_chain, response->proxy_chain);

  TestCompletionCallback callback2;

  // Configure to use a direct connection.
  proxy_delegate->set_proxy_chain(direct);

  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  load_timing_info = LoadTimingInfo();
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_DNS_TIMES);

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(100, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_FALSE(response->did_use_http_auth);
  EXPECT_EQ(direct, response->proxy_chain);

  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge.has_value());
}

void HttpNetworkTransactionTestBase::ConnectStatusHelperWithExpectedStatus(
    const MockRead& status,
    int expected_status) {
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

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
  };

  MockRead data_reads[] = {
      status,
      MockRead("Content-Length: 10\r\n\r\n"),
      // No response body because the test stops reading here.
      MockRead(SYNCHRONOUS, ERR_UNEXPECTED),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_EQ(expected_status, rv);
}

void HttpNetworkTransactionTestBase::ConnectStatusHelper(
    const MockRead& status) {
  ConnectStatusHelperWithExpectedStatus(status, ERR_TUNNEL_CONNECTION_FAILED);
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus100) {
  ConnectStatusHelper(MockRead("HTTP/1.1 100 Continue\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus101) {
  ConnectStatusHelper(MockRead("HTTP/1.1 101 Switching Protocols\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus201) {
  ConnectStatusHelper(MockRead("HTTP/1.1 201 Created\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus202) {
  ConnectStatusHelper(MockRead("HTTP/1.1 202 Accepted\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus203) {
  ConnectStatusHelper(
      MockRead("HTTP/1.1 203 Non-Authoritative Information\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus204) {
  ConnectStatusHelper(MockRead("HTTP/1.1 204 No Content\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus205) {
  ConnectStatusHelper(MockRead("HTTP/1.1 205 Reset Content\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus206) {
  ConnectStatusHelper(MockRead("HTTP/1.1 206 Partial Content\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus300) {
  ConnectStatusHelper(MockRead("HTTP/1.1 300 Multiple Choices\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus301) {
  ConnectStatusHelper(MockRead("HTTP/1.1 301 Moved Permanently\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus302) {
  ConnectStatusHelper(MockRead("HTTP/1.1 302 Found\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus303) {
  ConnectStatusHelper(MockRead("HTTP/1.1 303 See Other\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus304) {
  ConnectStatusHelper(MockRead("HTTP/1.1 304 Not Modified\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus305) {
  ConnectStatusHelper(MockRead("HTTP/1.1 305 Use Proxy\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus306) {
  ConnectStatusHelper(MockRead("HTTP/1.1 306\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus307) {
  ConnectStatusHelper(MockRead("HTTP/1.1 307 Temporary Redirect\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus308) {
  ConnectStatusHelper(MockRead("HTTP/1.1 308 Permanent Redirect\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus400) {
  ConnectStatusHelper(MockRead("HTTP/1.1 400 Bad Request\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus401) {
  ConnectStatusHelper(MockRead("HTTP/1.1 401 Unauthorized\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus402) {
  ConnectStatusHelper(MockRead("HTTP/1.1 402 Payment Required\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus403) {
  ConnectStatusHelper(MockRead("HTTP/1.1 403 Forbidden\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus404) {
  ConnectStatusHelper(MockRead("HTTP/1.1 404 Not Found\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus405) {
  ConnectStatusHelper(MockRead("HTTP/1.1 405 Method Not Allowed\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus406) {
  ConnectStatusHelper(MockRead("HTTP/1.1 406 Not Acceptable\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus407) {
  ConnectStatusHelperWithExpectedStatus(
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      ERR_PROXY_AUTH_UNSUPPORTED);
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus408) {
  ConnectStatusHelper(MockRead("HTTP/1.1 408 Request Timeout\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus409) {
  ConnectStatusHelper(MockRead("HTTP/1.1 409 Conflict\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus410) {
  ConnectStatusHelper(MockRead("HTTP/1.1 410 Gone\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus411) {
  ConnectStatusHelper(MockRead("HTTP/1.1 411 Length Required\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus412) {
  ConnectStatusHelper(MockRead("HTTP/1.1 412 Precondition Failed\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus413) {
  ConnectStatusHelper(MockRead("HTTP/1.1 413 Request Entity Too Large\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus414) {
  ConnectStatusHelper(MockRead("HTTP/1.1 414 Request-URI Too Long\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus415) {
  ConnectStatusHelper(MockRead("HTTP/1.1 415 Unsupported Media Type\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus416) {
  ConnectStatusHelper(
      MockRead("HTTP/1.1 416 Requested Range Not Satisfiable\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus417) {
  ConnectStatusHelper(MockRead("HTTP/1.1 417 Expectation Failed\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus500) {
  ConnectStatusHelper(MockRead("HTTP/1.1 500 Internal Server Error\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus501) {
  ConnectStatusHelper(MockRead("HTTP/1.1 501 Not Implemented\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus502) {
  ConnectStatusHelper(MockRead("HTTP/1.1 502 Bad Gateway\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus503) {
  ConnectStatusHelper(MockRead("HTTP/1.1 503 Service Unavailable\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus504) {
  ConnectStatusHelper(MockRead("HTTP/1.1 504 Gateway Timeout\r\n"));
}

TEST_P(HttpNetworkTransactionTest, ConnectStatus505) {
  ConnectStatusHelper(MockRead("HTTP/1.1 505 HTTP Version Not Supported\r\n"));
}

// Test the flow when both the proxy server AND origin server require
// authentication. Again, this uses basic auth for both since that is
// the simplest to mock.
TEST_P(HttpNetworkTransactionTest, BasicAuthProxyThenServer) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes1[] = {
      MockWrite("GET http://www.example.org/ HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.0 407 Unauthorized\r\n"),
      // Give a couple authenticate options (only the middle one is actually
      // supported).
      MockRead("Proxy-Authenticate: Basic invalid\r\n"),  // Malformed.
      MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Proxy-Authenticate: UNSUPPORTED realm=\"FOO\"\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      // Large content-length -- won't matter, as connection will be reset.
      MockRead("Content-Length: 10000\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  // After calling trans.RestartWithAuth() the first time, this is the
  // request we should be issuing -- the final header line contains the
  // proxy's credentials.
  MockWrite data_writes2[] = {
      MockWrite("GET http://www.example.org/ HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  // Now the proxy server lets the request pass through to origin server.
  // The origin server responds with a 401.
  MockRead data_reads2[] = {
      MockRead("HTTP/1.0 401 Unauthorized\r\n"),
      // Note: We are using the same realm-name as the proxy server. This is
      // completely valid, as realms are unique across hosts.
      MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 2000\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_FAILED),  // Won't be reached.
  };

  // After calling trans.RestartWithAuth() the second time, we should send
  // the credentials for both the proxy and origin server.
  MockWrite data_writes3[] = {
      MockWrite("GET http://www.example.org/ HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n"
                "Authorization: Basic Zm9vMjpiYXIy\r\n\r\n"),
  };

  // Lastly we get the desired content.
  MockRead data_reads3[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  StaticSocketDataProvider data2(data_reads2, data_writes2);
  StaticSocketDataProvider data3(data_reads3, data_writes3);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  session_deps_.socket_factory->AddSocketDataProvider(&data3);

  TestCompletionCallback callback1;

  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge));

  TestCompletionCallback callback2;

  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge));

  TestCompletionCallback callback3;

  rv = trans.RestartWithAuth(AuthCredentials(kFoo2, kBar2),
                             callback3.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback3.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans.GetResponseInfo();
  EXPECT_FALSE(response->auth_challenge.has_value());
  EXPECT_EQ(100, response->headers->GetContentLength());
}

// For the NTLM implementation using SSPI, we skip the NTLM tests since we
// can't hook into its internals to cause it to generate predictable NTLM
// authorization headers.
#if defined(NTLM_PORTABLE)
// The NTLM authentication unit tests are based on known test data from the
// [MS-NLMP] Specification [1]. These tests are primarily of the authentication
// flow rather than the implementation of the NTLM protocol. See net/ntlm
// for the implementation and testing of the protocol.
//
// [1] https://msdn.microsoft.com/en-us/library/cc236621.aspx

// Enter the correct password and authenticate successfully.
TEST_P(HttpNetworkTransactionTest, NTLMAuthV2) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://server/kids/login.aspx");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Ensure load is not disrupted by flags which suppress behaviour specific
  // to other auth schemes.
  request.load_flags = LOAD_DO_NOT_USE_EMBEDDED_IDENTITY;

  HttpAuthNtlmMechanism::ScopedProcSetter proc_setter(
      MockGetMSTime, MockGenerateRandom, MockGetHostName);
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Generate the NTLM messages based on known test data.
  std::string negotiate_msg = base::Base64Encode(std::string_view(
      reinterpret_cast<const char*>(ntlm::test::kExpectedNegotiateMsg),
      std::size(ntlm::test::kExpectedNegotiateMsg)));
  std::string challenge_msg = base::Base64Encode(std::string_view(
      reinterpret_cast<const char*>(ntlm::test::kChallengeMsgFromSpecV2),
      std::size(ntlm::test::kChallengeMsgFromSpecV2)));
  std::string authenticate_msg = base::Base64Encode(std::string_view(
      reinterpret_cast<const char*>(
          ntlm::test::kExpectedAuthenticateMsgEmptyChannelBindingsV2),
      std::size(ntlm::test::kExpectedAuthenticateMsgEmptyChannelBindingsV2)));

  MockWrite data_writes1[] = {
      MockWrite("GET /kids/login.aspx HTTP/1.1\r\n"
                "Host: server\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 401 Access Denied\r\n"),
      // Negotiate and NTLM are often requested together.  However, we only want
      // to test NTLM. Since Negotiate is preferred over NTLM, we have to skip
      // the header that requests Negotiate for this test.
      MockRead("WWW-Authenticate: NTLM\r\n"), MockRead("Connection: close\r\n"),
      MockRead("Content-Length: 42\r\n"),
      MockRead("Content-Type: text/html\r\n\r\n"),
      // Missing content -- won't matter, as connection will be reset.
  };

  MockWrite data_writes2[] = {
      // After restarting with a null identity, this is the
      // request we should be issuing -- the final header line contains a Type
      // 1 message.
      MockWrite("GET /kids/login.aspx HTTP/1.1\r\n"
```