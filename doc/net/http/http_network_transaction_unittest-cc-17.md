Response:
The user wants a summary of the functionality of the provided C++ code snippet from Chromium's networking stack. They are also interested in the following aspects:

1. **Relationship to JavaScript:**  How does this code interact with JavaScript?
2. **Logical Reasoning:** If the code performs logical operations, what are example inputs and outputs?
3. **Common Usage Errors:** What are typical mistakes users or programmers might make when interacting with this code or related network functionalities?
4. **User Operation for Debugging:** How can a user's actions lead to this code being executed, and how can it be used for debugging?
5. **Overall Functionality:** A concise summary of what the code does.

The provided code is part 18 of 34, suggesting a larger file. The focus of the snippet is on testing the `HttpNetworkTransaction` class, particularly its behavior in various scenarios involving HTTPS, proxies (HTTP and HTTPS), authentication, and bad certificates.

**Plan:**

1. Summarize the core functionality of the code based on the test cases present.
2. Address the JavaScript relationship (likely indirect through browser behavior).
3. Provide examples of logical flow within the test cases.
4. Illustrate common user/programmer errors.
5. Describe user actions leading to this code and its use in debugging.
6. Concisely summarize the functionality.
基于提供的代码片段，该文件 `net/http/http_network_transaction_unittest.cc` 的主要功能是**测试 `HttpNetworkTransaction` 类的各种网络请求场景的行为**。 具体来说，它涵盖了以下方面的测试：

**主要功能归纳:**

1. **状态重置 (`ResetStateForRestart`)：** 测试 `ResetStateForRestart()` 方法是否能正确清除 `HttpNetworkTransaction` 对象在请求过程中产生的状态，例如读缓冲区、请求头、响应信息等。
2. **HTTPS连接与证书错误 (`HTTPSBadCertificate`)：** 测试当连接到具有无效证书的HTTPS站点时，`HttpNetworkTransaction` 如何处理错误，以及是否能够通过调用 `RestartIgnoringLastError()` 忽略错误并继续请求。
3. **通过HTTP代理的HTTPS连接与证书错误 (`HTTPSBadCertificateViaProxy`)：** 测试在通过HTTP代理连接到具有无效证书的HTTPS站点时，`HttpNetworkTransaction` 的行为，同样包括错误处理和 `RestartIgnoringLastError()` 的使用。
4. **通过HTTPS代理的HTTPS连接 (`HTTPSViaHttpsProxy`)：** 测试通过HTTPS代理建立HTTPS连接的流程，包括发送 `CONNECT` 请求，以及验证响应头信息。
5. **HTTPS代理对CONNECT请求的重定向限制 (`RedirectOfHttpsConnectViaHttpsProxy`, `RedirectOfHttpsConnectSubresourceViaHttpsProxy`, `RedirectOfHttpsConnectViaAutoDetectedHttpsProxy`, `RedirectOfHttpsConnectViaSpdyProxy`)：** 测试HTTPS代理是否能重定向针对主框架或子资源的 `CONNECT` 请求，预期结果是连接失败。
6. **HTTPS代理对CONNECT请求的错误响应处理 (`ErrorResponseToHttpsConnectViaHttpsProxy`, `ErrorResponseToHttpsConnectViaSpdyProxy`)：** 测试当HTTPS代理对 `CONNECT` 请求返回错误状态码时，`HttpNetworkTransaction` 如何处理。
7. **SPDY代理下的基本认证 (`BasicAuthSpdyProxy`)：** 测试通过SPDY代理进行基本认证的流程，包括接收 407 代理认证请求，然后使用正确的凭据重新发起请求。
8. **通过HTTPS代理的HTTPS连接与证书错误 (`HTTPSBadCertificateViaHttpsProxy`)：**  再次测试通过HTTPS代理连接到具有无效证书的HTTPS站点的情况，与之前的测试类似，但更专注于HTTPS代理场景。
9. **自定义User-Agent头 (`BuildRequest_UserAgent`, `BuildRequest_UserAgentOverTunnel`)：** 测试如何设置和发送自定义的 `User-Agent` 请求头，包括直接设置和通过代理隧道发送的情况。

**与JavaScript的功能关系：**

该文件本身是用 C++ 编写的单元测试，直接与 JavaScript 没有代码级别的联系。 然而，`HttpNetworkTransaction` 类是 Chromium 网络栈的核心组件，负责处理实际的网络请求。 当 JavaScript 代码在浏览器中发起网络请求（例如，通过 `fetch` API 或 `XMLHttpRequest`），Chromium 的渲染进程会通过 IPC (进程间通信) 将请求传递给网络进程。 网络进程中的 `HttpNetworkTransaction` 对象就负责处理这些请求，包括建立连接、发送请求头、接收响应等。

**举例说明：**

假设一个网页的 JavaScript 代码使用 `fetch` API 请求一个 HTTPS 资源：

```javascript
fetch('https://www.example.org/')
  .then(response => response.text())
  .then(data => console.log(data));
```

当这个请求发出时，网络进程中可能会创建一个 `HttpNetworkTransaction` 对象来处理该请求。 如果 `www.example.org` 的证书无效，那么在 `net/http/http_network_transaction_unittest.cc` 中的 `HTTPSBadCertificate` 测试所覆盖的逻辑就会被执行（尽管测试代码本身并不直接处理这个 JavaScript 请求）。  测试的目的是验证 `HttpNetworkTransaction` 在这种情况下是否会返回 `ERR_CERT_AUTHORITY_INVALID` 错误，这最终会影响到 JavaScript 代码中的 `fetch` API 的 Promise 被 rejected。

**逻辑推理与假设输入/输出：**

**例子： `ResetStateForRestart` 测试**

*   **假设输入：**  一个 `HttpNetworkTransaction` 对象 `trans`，其内部状态已被部分设置，例如 `trans.read_buf_` 指向一个 IO 缓冲区，`trans.read_buf_len_` 为 15，`trans.request_headers_` 包含一个 "Authorization" 头，以及 `trans.response_` 包含一些响应信息。
*   **预期输出：** 在调用 `trans.ResetStateForRestart()` 后，`trans.read_buf_` 应该为 `nullptr`， `trans.read_buf_len_` 应该为 0， `trans.request_headers_` 应该为空， `trans.response_.auth_challenge` 应该为 `std::nullopt`， `trans.response_.headers` 应该为 `nullptr`， `trans.response_.was_cached` 应该为 `false`， `trans.response_.ssl_info.cert_status` 应该为 0。

**例子： `HTTPSBadCertificate` 测试**

*   **假设输入：** 一个针对 `https://www.example.org/` 的 GET 请求，并且模拟的 socket 数据提供了一个无效的 SSL 证书。
*   **预期输出：**  `trans.Start()` 初始返回 `ERR_IO_PENDING`，等待回调后返回 `ERR_CERT_AUTHORITY_INVALID`。  调用 `trans.RestartIgnoringLastError()` 后，请求会再次尝试，这次模拟的 socket 数据提供有效的响应，最终回调返回 `OK`，并且 `trans.GetResponseInfo()` 返回包含状态码 200 和 Content-Length 为 100 的响应信息。

**用户或编程常见的使用错误：**

1. **未处理证书错误：**  在开发需要处理 HTTPS 请求的应用时，如果用户的代码没有正确处理证书验证失败的情况（例如，忽略了 `ERR_CERT_AUTHORITY_INVALID` 错误），可能会导致应用出现安全漏洞或无法正常工作。
2. **错误的代理配置：** 用户在操作系统或浏览器中配置了错误的代理服务器地址或端口，导致 `HttpNetworkTransaction` 尝试连接到不存在或无法正常工作的代理，从而导致连接错误。
3. **在HTTPS代理场景下错误地假设连接已安全：**  程序员可能会错误地认为通过 HTTPS 代理发送的请求天然是安全的，而忽略了与代理服务器本身建立安全连接的重要性。如果与 HTTPS 代理的连接没有使用 HTTPS，那么请求仍然可能被窃听。
4. **不正确的认证处理：**  在需要认证的场景下，用户或程序员可能没有提供正确的用户名和密码，或者没有按照服务器要求的认证方式进行处理，导致请求被拒绝。

**用户操作到达此处的调试线索：**

当用户在浏览器中进行以下操作时，可能会触发与 `HttpNetworkTransaction` 相关的代码执行，并且在出现问题时，开发人员可能会使用这些线索进行调试：

1. **浏览 HTTPS 网站：** 用户访问一个 HTTPS 网站，如果该网站的证书存在问题（例如过期、自签名、域名不匹配），Chromium 的证书验证机制会失败，并可能导致 `HttpNetworkTransaction` 返回证书相关的错误。调试时，可以检查浏览器的网络日志 (`chrome://net-export/`) 或开发者工具的 Network 面板，查看证书错误信息。
2. **使用代理服务器：** 用户配置了代理服务器（HTTP 或 HTTPS），当浏览器尝试通过代理服务器访问网站时，`HttpNetworkTransaction` 会处理与代理服务器的连接，包括发送 `CONNECT` 请求（对于 HTTPS 网站）。 如果代理服务器配置错误或响应异常，可以在网络日志中找到相关信息。
3. **访问需要认证的网站：** 用户尝试访问需要身份验证的网站或代理服务器，`HttpNetworkTransaction` 会处理认证相关的流程，例如接收 401 或 407 状态码，并可能提示用户输入用户名和密码。调试时，可以检查请求头中是否包含认证信息，以及服务器返回的认证质询。
4. **网络连接问题：**  用户的网络连接不稳定或存在问题，导致连接超时、DNS 解析失败等，这些问题也会影响 `HttpNetworkTransaction` 的行为。网络日志可以提供连接失败的详细原因。

**作为调试线索：**

*   **网络日志 (chrome://net-export/)：**  可以记录详细的网络事件，包括 `HttpNetworkTransaction` 的创建、状态变化、发送和接收的数据等。通过分析网络日志，可以追踪请求的整个生命周期，定位问题发生的环节。
*   **开发者工具 (F12) 的 Network 面板：**  可以查看请求的详细信息，包括请求头、响应头、状态码、耗时等。在出现网络问题时，Network 面板可以提供初步的线索。
*   **断点调试：**  对于 Chromium 的开发者，可以在 `net/http/http_network_transaction.cc` 文件的相关代码处设置断点，例如在 `Start()`、`RestartIgnoringLastError()` 等方法中，以便更深入地了解代码的执行流程和变量状态。

总而言之，`net/http/http_network_transaction_unittest.cc` 文件通过各种测试用例，确保 `HttpNetworkTransaction` 类在不同的网络场景下能够正确地处理请求、错误和认证等，是保证 Chromium 网络栈稳定性和可靠性的重要组成部分。 虽然它本身是测试代码，但它所测试的逻辑直接影响着浏览器处理网络请求的行为，并间接地与 JavaScript 发起的网络操作相关联。

### 提示词
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第18部分，共34部分，请归纳一下它的功能
```

### 源代码
```cpp
etup some state (which we expect ResetStateForRestart() will clear).
  trans.read_buf_ = base::MakeRefCounted<IOBufferWithSize>(15);
  trans.read_buf_len_ = 15;
  trans.request_headers_.SetHeader("Authorization", "NTLM");

  // Setup state in response_
  HttpResponseInfo* response = &trans.response_;
  response->auth_challenge = std::nullopt;
  response->ssl_info.cert_status = static_cast<CertStatus>(-1);  // Nonsensical.
  response->response_time = base::Time::Now();
  response->was_cached = true;  // (Wouldn't ever actually be true...)

  // Cause the above state to be reset.
  trans.ResetStateForRestart();

  // Verify that the state that needed to be reset, has been reset.
  EXPECT_FALSE(trans.read_buf_);
  EXPECT_EQ(0, trans.read_buf_len_);
  EXPECT_TRUE(trans.request_headers_.IsEmpty());
  EXPECT_FALSE(response->auth_challenge.has_value());
  EXPECT_FALSE(response->headers);
  EXPECT_FALSE(response->was_cached);
  EXPECT_EQ(0U, response->ssl_info.cert_status);
}

// Test HTTPS connections to a site with a bad certificate
TEST_P(HttpNetworkTransactionTest, HTTPSBadCertificate) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider ssl_bad_certificate;
  StaticSocketDataProvider data(data_reads, data_writes);
  SSLSocketDataProvider ssl_bad(ASYNC, ERR_CERT_AUTHORITY_INVALID);
  SSLSocketDataProvider ssl(ASYNC, OK);

  session_deps_.socket_factory->AddSocketDataProvider(&ssl_bad_certificate);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_bad);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CERT_AUTHORITY_INVALID));

  rv = trans.RestartIgnoringLastError(callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();

  ASSERT_TRUE(response);
  EXPECT_EQ(100, response->headers->GetContentLength());
}

// Test HTTPS connections to a site with a bad certificate, going through a
// proxy
TEST_P(HttpNetworkTransactionTest, HTTPSBadCertificateViaProxy) {
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite proxy_writes[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
  };

  MockRead proxy_reads[] = {MockRead("HTTP/1.0 200 Connected\r\n\r\n"),
                            MockRead(SYNCHRONOUS, OK)};

  MockWrite data_writes[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 Connected\r\n\r\n"),
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider ssl_bad_certificate(proxy_reads, proxy_writes);
  StaticSocketDataProvider data(data_reads, data_writes);
  SSLSocketDataProvider ssl_bad(ASYNC, ERR_CERT_AUTHORITY_INVALID);
  SSLSocketDataProvider ssl(ASYNC, OK);

  session_deps_.socket_factory->AddSocketDataProvider(&ssl_bad_certificate);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_bad);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  for (int i = 0; i < 2; i++) {
    session_deps_.socket_factory->ResetNextMockIndexes();

    std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback.WaitForResult();
    EXPECT_THAT(rv, IsError(ERR_CERT_AUTHORITY_INVALID));

    rv = trans.RestartIgnoringLastError(callback.callback());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    const HttpResponseInfo* response = trans.GetResponseInfo();

    ASSERT_TRUE(response);
    EXPECT_EQ(100, response->headers->GetContentLength());
  }
}

// Test HTTPS connections to a site, going through an HTTPS proxy
TEST_P(HttpNetworkTransactionTest, HTTPSViaHttpsProxy) {
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "HTTPS proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite data_writes[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 Connected\r\n\r\n"),
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  SSLSocketDataProvider proxy_ssl(ASYNC, OK);   // SSL to the proxy
  SSLSocketDataProvider tunnel_ssl(ASYNC, OK);  // SSL through the tunnel

  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&proxy_ssl);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&tunnel_ssl);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  const HttpResponseInfo* response = trans.GetResponseInfo();

  ASSERT_TRUE(response);

  ASSERT_EQ(1u, response->proxy_chain.length());
  EXPECT_TRUE(response->proxy_chain.GetProxyServer(0).is_https());
  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(100, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);
}

// Test that an HTTPS Proxy cannot redirect a CONNECT request for main frames.
TEST_P(HttpNetworkTransactionTest, RedirectOfHttpsConnectViaHttpsProxy) {
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "HTTPS proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();

  const base::TimeDelta kTimeIncrement = base::Seconds(4);
  session_deps_.host_resolver->set_ondemand_mode(true);

  HttpRequestInfo request;
  request.load_flags = LOAD_MAIN_FRAME_DEPRECATED;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite data_writes[] = {
      MockWrite(ASYNC, 0,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
  };

  MockRead data_reads[] = {
      // Pause on first read.
      MockRead(ASYNC, ERR_IO_PENDING, 1),
      MockRead(ASYNC, 2, "HTTP/1.1 302 Redirect\r\n"),
      MockRead(ASYNC, 3, "Location: http://login.example.com/\r\n"),
      MockRead(ASYNC, 4, "Content-Length: 0\r\n\r\n"),
  };

  SequencedSocketData data(MockConnect(ASYNC, OK), data_reads, data_writes);
  SSLSocketDataProvider proxy_ssl(ASYNC, OK);  // SSL to the proxy

  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&proxy_ssl);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_TRUE(session_deps_.host_resolver->has_pending_requests());

  // Host resolution takes |kTimeIncrement|.
  FastForwardBy(kTimeIncrement);
  // Resolving the current request with |ResolveNow| will cause the pending
  // request to instantly complete, and the async connect will start as well.
  session_deps_.host_resolver->ResolveOnlyRequestNow();

  // Connecting takes |kTimeIncrement|.
  FastForwardBy(kTimeIncrement);
  data.RunUntilPaused();

  // The server takes |kTimeIncrement| to respond.
  FastForwardBy(kTimeIncrement);
  data.Resume();

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_TUNNEL_CONNECTION_FAILED));
}

// Test that an HTTPS Proxy cannot redirect a CONNECT request for subresources.
TEST_P(HttpNetworkTransactionTest,
       RedirectOfHttpsConnectSubresourceViaHttpsProxy) {
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "HTTPS proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite data_writes[] = {
      MockWrite(ASYNC, 0,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead(ASYNC, 1, "HTTP/1.1 302 Redirect\r\n"),
      MockRead(ASYNC, 2, "Location: http://login.example.com/\r\n"),
      MockRead(ASYNC, 3, "Content-Length: 0\r\n\r\n"),
  };

  SequencedSocketData data(MockConnect(ASYNC, OK), data_reads, data_writes);
  SSLSocketDataProvider proxy_ssl(ASYNC, OK);  // SSL to the proxy

  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&proxy_ssl);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_TUNNEL_CONNECTION_FAILED));
}

// Test that an HTTPS Proxy which was auto-detected cannot redirect a CONNECT
// request for main frames.
TEST_P(HttpNetworkTransactionTest,
       RedirectOfHttpsConnectViaAutoDetectedHttpsProxy) {
  session_deps_.proxy_resolution_service = ConfiguredProxyResolutionService::
      CreateFixedFromAutoDetectedPacResultForTest("HTTPS proxy:70",
                                                  TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();

  HttpRequestInfo request;
  request.load_flags = LOAD_MAIN_FRAME_DEPRECATED;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite data_writes[] = {
      MockWrite(ASYNC, 0,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead(ASYNC, 1, "HTTP/1.1 302 Redirect\r\n"),
      MockRead(ASYNC, 2, "Location: http://login.example.com/\r\n"),
      MockRead(ASYNC, 3, "Content-Length: 0\r\n\r\n"),
  };

  SequencedSocketData data(MockConnect(ASYNC, OK), data_reads, data_writes);
  SSLSocketDataProvider proxy_ssl(ASYNC, OK);  // SSL to the proxy

  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&proxy_ssl);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_TUNNEL_CONNECTION_FAILED));
}

// Tests that an HTTPS (SPDY) Proxy's cannot redirect a CONNECT request for main
// frames.
TEST_P(HttpNetworkTransactionTest, RedirectOfHttpsConnectViaSpdyProxy) {
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();

  const base::TimeDelta kTimeIncrement = base::Seconds(4);
  session_deps_.host_resolver->set_ondemand_mode(true);

  HttpRequestInfo request;
  request.method = "GET";
  request.load_flags = LOAD_MAIN_FRAME_DEPRECATED;
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  spdy::SpdySerializedFrame conn(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));
  spdy::SpdySerializedFrame goaway(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
  MockWrite data_writes[] = {
      CreateMockWrite(conn, 0, SYNCHRONOUS),
      CreateMockWrite(goaway, 3, SYNCHRONOUS),
  };

  static const char* const kExtraHeaders[] = {
      "location",
      "http://login.example.com/",
  };
  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyReplyError(
      "302", kExtraHeaders, std::size(kExtraHeaders) / 2, 1));
  MockRead data_reads[] = {
      // Pause on first read.
      MockRead(ASYNC, ERR_IO_PENDING, 1), CreateMockRead(resp, 2),
      MockRead(ASYNC, 0, 4),  // EOF
  };

  SequencedSocketData data(MockConnect(ASYNC, OK), data_reads, data_writes);
  SSLSocketDataProvider proxy_ssl(ASYNC, OK);  // SSL to the proxy
  proxy_ssl.next_proto = kProtoHTTP2;

  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&proxy_ssl);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_TRUE(session_deps_.host_resolver->has_pending_requests());

  // Host resolution takes |kTimeIncrement|.
  FastForwardBy(kTimeIncrement);
  // Resolving the current request with |ResolveNow| will cause the pending
  // request to instantly complete, and the async connect will start as well.
  session_deps_.host_resolver->ResolveOnlyRequestNow();

  // Connecting takes |kTimeIncrement|.
  FastForwardBy(kTimeIncrement);
  data.RunUntilPaused();

  FastForwardBy(kTimeIncrement);
  data.Resume();
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_TUNNEL_CONNECTION_FAILED));
}

// Test that an HTTPS proxy's response to a CONNECT request is filtered.
TEST_P(HttpNetworkTransactionTest, ErrorResponseToHttpsConnectViaHttpsProxy) {
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite data_writes[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 404 Not Found\r\n"),
      MockRead("Content-Length: 23\r\n\r\n"),
      MockRead("The host does not exist"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  SSLSocketDataProvider proxy_ssl(ASYNC, OK);  // SSL to the proxy

  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&proxy_ssl);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_TUNNEL_CONNECTION_FAILED));

  // TODO(juliatuttle): Anything else to check here?
}

// Test that a SPDY proxy's response to a CONNECT request is filtered.
TEST_P(HttpNetworkTransactionTest, ErrorResponseToHttpsConnectViaSpdyProxy) {
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  spdy::SpdySerializedFrame conn(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
  MockWrite data_writes[] = {
      CreateMockWrite(conn, 0),
      CreateMockWrite(rst, 3),
  };

  static const char* const kExtraHeaders[] = {
      "location",
      "http://login.example.com/",
  };
  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyReplyError(
      "404", kExtraHeaders, std::size(kExtraHeaders) / 2, 1));
  spdy::SpdySerializedFrame body(
      spdy_util_.ConstructSpdyDataFrame(1, "The host does not exist", true));
  MockRead data_reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 4),  // EOF
  };

  SequencedSocketData data(data_reads, data_writes);
  SSLSocketDataProvider proxy_ssl(ASYNC, OK);  // SSL to the proxy
  proxy_ssl.next_proto = kProtoHTTP2;

  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&proxy_ssl);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_TUNNEL_CONNECTION_FAILED));

  // TODO(juliatuttle): Anything else to check here?
}

// Test the request-challenge-retry sequence for basic auth, through
// a SPDY proxy over a single SPDY session.
TEST_P(HttpNetworkTransactionTest, BasicAuthSpdyProxy) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  // when the no authentication data flag is set.
  request.privacy_mode = PRIVACY_MODE_ENABLED;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against https proxy server "myproxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "HTTPS myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  RecordingNetLogObserver net_log_observer;
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since we have proxy, should try to establish tunnel.
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
  spdy_util_.UpdateWithStreamDestruction(1);

  // After calling trans.RestartWithAuth(), this is the request we should
  // be issuing -- the final header line contains the credentials.
  const char* const kAuthCredentials[] = {
      "user-agent",
      "test-ua",
      "proxy-authorization",
      "Basic Zm9vOmJhcg==",
  };
  spdy::SpdySerializedFrame connect2(spdy_util_.ConstructSpdyConnect(
      kAuthCredentials, std::size(kAuthCredentials) / 2, 3,
      HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));
  // fetch https://www.example.org/ via HTTP
  const char kGet[] =
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get(
      spdy_util_.ConstructSpdyDataFrame(3, kGet, false));

  MockWrite spdy_writes[] = {
      CreateMockWrite(req, 0, ASYNC),
      CreateMockWrite(rst, 2, ASYNC),
      CreateMockWrite(connect2, 3),
      CreateMockWrite(wrapped_get, 5),
  };

  // The proxy responds to the connect with a 407, using a persistent
  // connection.
  const char kAuthStatus[] = "407";
  const char* const kAuthChallenge[] = {
      "proxy-authenticate",
      "Basic realm=\"MyRealm1\"",
  };
  spdy::SpdySerializedFrame conn_auth_resp(spdy_util_.ConstructSpdyReplyError(
      kAuthStatus, kAuthChallenge, std::size(kAuthChallenge) / 2, 1));

  spdy::SpdySerializedFrame conn_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  const char kResp[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 5\r\n\r\n";

  spdy::SpdySerializedFrame wrapped_get_resp(
      spdy_util_.ConstructSpdyDataFrame(3, kResp, false));
  spdy::SpdySerializedFrame wrapped_body(
      spdy_util_.ConstructSpdyDataFrame(3, "hello", false));
  MockRead spdy_reads[] = {
      CreateMockRead(conn_auth_resp, 1, ASYNC),
      CreateMockRead(conn_resp, 4, ASYNC),
      CreateMockRead(wrapped_get_resp, 6, ASYNC),
      CreateMockRead(wrapped_body, 7, ASYNC),
      MockRead(ASYNC, OK, 8),  // EOF.  May or may not be read.
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);
  // Negotiate SPDY to the proxy
  SSLSocketDataProvider proxy(ASYNC, OK);
  proxy.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&proxy);
  // Vanilla SSL to the server
  SSLSocketDataProvider server(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&server);

  TestCompletionCallback callback1;

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

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
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(response->auth_challenge.has_value());
  EXPECT_TRUE(CheckBasicSecureProxyAuth(response->auth_challenge));

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

  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge.has_value());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);

  trans.reset();
  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

// Test HTTPS connections to a site with a bad certificate, going through an
// HTTPS proxy
TEST_P(HttpNetworkTransactionTest, HTTPSBadCertificateViaHttpsProxy) {
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Attempt to fetch the URL from a server with a bad cert
  MockWrite bad_cert_writes[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
  };

  MockRead bad_cert_reads[] = {MockRead("HTTP/1.0 200 Connected\r\n\r\n"),
                               MockRead(SYNCHRONOUS, OK)};

  // Attempt to fetch the URL with a good cert
  MockWrite good_data_writes[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead good_cert_reads[] = {
      MockRead("HTTP/1.0 200 Connected\r\n\r\n"),
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider ssl_bad_certificate(bad_cert_reads, bad_cert_writes);
  StaticSocketDataProvider data(good_cert_reads, good_data_writes);
  SSLSocketDataProvider ssl_bad(ASYNC, ERR_CERT_AUTHORITY_INVALID);
  SSLSocketDataProvider ssl(ASYNC, OK);

  // SSL to the proxy, then CONNECT request, then SSL with bad certificate
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  session_deps_.socket_factory->AddSocketDataProvider(&ssl_bad_certificate);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_bad);

  // SSL to the proxy, then CONNECT request, then valid SSL certificate
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CERT_AUTHORITY_INVALID));

  rv = trans.RestartIgnoringLastError(callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();

  ASSERT_TRUE(response);
  EXPECT_EQ(100, response->headers->GetContentLength());
}

TEST_P(HttpNetworkTransactionTest, BuildRequest_UserAgent) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.extra_headers.SetHeader(HttpRequestHeaders::kUserAgent,
                                  "Chromium Ultra Awesome X Edition");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "User-Agent: Chromium Ultra Awesome X Edition\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
}

TEST_P(HttpNetworkTransactionTest, BuildRequest_UserAgentOverTunnel) {
  // Test user agent values, used both for the request header of the original
  // request, and the value returned by the HttpUserAgentSettings. nullptr means
  // no request header / no HttpUserAgentSettings object.
  const char* kTestUserAgents[] = {nullptr, "", "Foopy"};

  for (const char* setting_user_agent : kTestUserAgents) {
    if (!setting_user_agent) {
      session_deps_.http_user_agent_settings.reset();
    } else {
      session_deps_.http_user_agent_settings =
          std::make_unique<StaticHttpUserAgentSettings>(
              std::string() /* accept-language */, setting_user_agent);
    }
    session_deps_.proxy_resolution_service =
        ConfiguredProxyResolutionService::CreateFixedForTest(
            "myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
    std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
    for (const char* request_user_agent : kTestUserAgents) {
      HttpRequestInfo request;
      request.method = "GET";
      request.url = GURL("https://www.example.org/");
      if (request_user_agent) {
        request.extra_headers.SetHeader(HttpRequestHeaders::kUserAgent,
                                        request_user_agent);
      }
      request.traffic_annotation =
          MutableNetworkTrafficAnnotationTag(
```