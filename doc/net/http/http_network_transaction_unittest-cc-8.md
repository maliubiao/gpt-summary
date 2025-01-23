Response:
My thinking process to analyze the provided code snippet and generate the detailed response involved several steps:

1. **Understand the Goal:** The request asks for a functional summary of a C++ unit test file (`http_network_transaction_unittest.cc`) within the Chromium networking stack. It also requires identifying connections to JavaScript, providing input/output examples, highlighting common user/programmer errors, describing the user journey to this code, and summarizing its function as part of a larger series.

2. **Initial Code Scan and Keyword Identification:** I started by quickly scanning the code for key terms and patterns. I noticed:
    * `TEST_P`: Indicates parameterized tests.
    * `HttpNetworkTransaction`: The core class being tested.
    * `HttpRequestInfo`, `HttpResponseInfo`: Structures representing requests and responses.
    * `HttpNetworkSession`:  The context in which transactions occur.
    * `ProxyConfig`, `ProxyResolutionService`: Components dealing with proxy settings.
    * `MockWrite`, `MockRead`, `StaticSocketDataProvider`, `SequencedSocketData`:  Tools for simulating network interactions.
    * `SSLSocketDataProvider`:  For simulating SSL/TLS connections.
    * `SpdySerializedFrame`, `SpdyTestUtil`:  For simulating SPDY/HTTP2 interactions.
    * `EXPECT_THAT`, `ASSERT_TRUE`, `EXPECT_EQ`, `IsOk`, `IsError`:  GTest assertions.
    * Error codes like `ERR_IO_PENDING`, `ERR_FAILED`, `ERR_PROXY_CONNECTION_FAILED`, `ERR_DNS_TIMED_OUT`, `ERR_HTTP2_PROTOCOL_ERROR`.

3. **Identify Test Scenarios:** I then focused on the individual `TEST_P` blocks. Each test represents a specific scenario being evaluated. I categorized these scenarios based on the actions and configurations being tested:
    * **Basic Request and Reuse:**  Testing the lifecycle of a simple request and the reuse of a persistent connection.
    * **Proxy Interaction:**  Several tests focus on different proxy configurations:
        * PAC file usage (`ProxyResolvedWithNetworkAnonymizationKey`).
        * Proxy hostname resolution failures (`ProxyHostResolutionFailure`).
        * HTTPS proxy for HTTP (`HttpsProxyGet`).
        * Nested HTTPS proxies (`HttpsNestedProxyGet`).
        * SPDY/HTTP2 proxying (`HttpsProxySpdyGet`, `HttpsNestedProxySpdyGet`, `HttpsNestedProxySameProxyTwiceSpdyGet`).
        * Handling SPDY protocol errors in nested proxy scenarios (`NestedProxyHttpOverSpdyProtocolError`).
        * Client certificate requests from proxies (`HttpsClientAuthCertNeededNoCrash`).

4. **Infer Functionality from Tests:**  Based on the identified scenarios, I deduced the functionalities being tested in `HttpNetworkTransaction`:
    * Initiating and managing HTTP requests.
    * Handling different proxy configurations (HTTP, HTTPS, nested).
    * Supporting SPDY/HTTP2 proxying.
    * Managing connection reuse.
    * Correctly passing network anonymization keys.
    * Handling proxy resolution failures.
    * Processing server responses.
    * Extracting load timing information.
    * Handling authentication challenges (implicitly, though not explicitly tested in this snippet).
    * Managing connection closure.
    * Handling protocol errors.
    * Dealing with client certificate requests.

5. **Address Specific Requirements:**

    * **Relationship to JavaScript:** I considered how these network functionalities might relate to JavaScript in a browser. JavaScript uses APIs like `fetch()` and `XMLHttpRequest` which rely on the underlying network stack. I focused on areas like URL handling, proxy settings (which users might configure, affecting these tests), and error reporting.

    * **Input/Output Examples:** For logical deductions (even though the tests are more about simulating scenarios than direct user input/output), I crafted hypothetical user actions and the resulting state of the `HttpNetworkTransaction` object.

    * **User/Programmer Errors:** I thought about common mistakes developers might make when using the networking APIs, such as incorrect proxy configurations, neglecting error handling, or misinterpreting network events.

    * **User Journey:** I traced a potential user action (like clicking a link or a script making a request) through the browser's layers to the point where `HttpNetworkTransaction` would be involved.

    * **Part 9 of 34 Summary:** I considered the context of being in the early part of a larger test suite. This suggests the focus is on core functionalities and basic scenarios before moving to more complex or edge cases.

6. **Structure the Response:**  I organized the information into the requested categories for clarity and readability. I used bullet points and examples to make the information easy to digest.

7. **Refine and Review:**  I reread the generated response and the code snippet to ensure accuracy, completeness, and coherence. I checked for any misinterpretations or missing information. For example, I initially missed explicitly mentioning connection reuse as a tested feature and added it during the review. I also made sure the JavaScript examples were relevant to the tested functionalities.

By following this systematic approach, I could effectively analyze the code snippet and generate a comprehensive and informative response that addressed all the requirements of the prompt.
好的，这是对`net/http/http_network_transaction_unittest.cc`文件第9部分代码的功能分析：

**功能归纳 (基于第9部分代码):**

这部分代码主要集中在测试 `HttpNetworkTransaction` 类在各种代理场景下的行为，特别是 HTTPS 代理和嵌套 HTTPS 代理，以及涉及 SPDY/HTTP2 协议的代理场景。测试重点在于：

* **HTTPS 代理 (HTTP -> HTTPS):**
    * 验证通过 HTTPS 代理请求 HTTP 资源时的请求头（包括 `Proxy-Connection` 和 `User-Agent`）。
    * 检查响应头、状态码、内容长度和 HTTP 版本。
    * 确认负载时序信息 (`LoadTimingInfo`) 的正确性。
    * 验证是否正确记录了代理链 (`proxy_chain`)。
    * 确认是否没有设置密码提示信息 (`auth_challenge`)。
    * 确认通过 HTTPS 代理连接的 SSL 信息不会作为源站的属性报告。

* **嵌套 HTTPS 代理 (HTTP -> HTTPS -> HTTPS):**
    * 验证通过多层 HTTPS 代理请求 HTTP 资源的请求和响应流程。
    * 检查是否正确建立了到两层代理的 CONNECT 隧道。
    * 验证最终到目标服务器的请求头。
    * 检查响应头、状态码和内容长度。
    * 确认负载时序信息的正确性。
    * 验证代理链的长度和类型。

* **HTTPS 代理与 SPDY/HTTP2:**
    * 验证通过 HTTPS (SPDY) 代理请求 HTTP 资源时的流程。
    * 检查 SPDY 帧的构造和解析。
    * 确认负载时序信息。
    * 验证代理链和协商的协议。

* **嵌套 HTTPS 代理与 SPDY/HTTP2:**
    * 验证通过多层 HTTPS (SPDY) 代理请求 HTTP 资源的复杂流程。
    * 检查多层 SPDY CONNECT 隧道的建立和数据传输的封装。
    * 处理需要在多层隧道中进行双重封装的 HTTP 请求。
    * 验证负载时序信息和代理链。

* **相同的 HTTPS (SPDY) 代理多次嵌套:**
    * 测试当嵌套的代理服务器是同一个时，请求是否能够正确处理。

* **嵌套代理中 SPDY 协议错误处理:**
    * 测试在多层代理场景下，如果 SPDY 连接发生协议错误，`HttpNetworkTransaction` 是否能够正确处理，而不会发生崩溃。

* **HTTPS 代理请求客户端认证证书:**
    * 验证当 HTTPS 代理请求客户端认证证书时，`HttpNetworkTransaction` 不会崩溃。

**功能列举:**

1. **测试通过 HTTPS 代理获取 HTTP 资源:** 验证基本的 HTTPS 代理场景，包括请求头的构建、响应的解析以及连接信息的记录。
2. **测试通过两层 HTTPS 代理获取 HTTP 资源:**  验证处理嵌套代理的能力，包括建立多层 CONNECT 隧道和处理中间代理的通信。
3. **测试通过 HTTPS (SPDY) 代理获取 HTTP 资源:** 验证与 SPDY 代理的互操作性，包括 SPDY 帧的构造和解析。
4. **测试通过两层 HTTPS (SPDY) 代理获取 HTTP 资源:** 验证处理多层 SPDY 代理的能力，涉及 SPDY 连接的嵌套和 HTTP 请求的封装。
5. **测试通过相同的 HTTPS (SPDY) 代理多次嵌套获取 HTTP 资源:**  验证处理重复代理的逻辑。
6. **测试嵌套代理中 HTTP over SPDY 时的协议错误处理:** 验证在复杂的代理场景下，对底层协议错误的鲁棒性。
7. **测试 HTTPS 代理请求客户端认证证书的处理:** 验证对需要客户端认证的代理的正常处理，避免崩溃。

**与 JavaScript 的关系:**

虽然这段 C++ 代码本身不直接包含 JavaScript，但它所测试的网络功能是 Web 浏览器的核心，直接支撑着 JavaScript 发起的网络请求。

* **`fetch()` API 和 `XMLHttpRequest`:** JavaScript 代码可以使用 `fetch()` 或 `XMLHttpRequest` 发起 HTTP 请求。当配置了代理服务器时，这些请求会触发 Chromium 网络栈中相应的逻辑，最终会涉及到 `HttpNetworkTransaction` 的处理。
* **Proxy 设置:** 用户在浏览器中配置的代理服务器设置（例如，通过操作系统设置或浏览器扩展）会影响这里的测试场景。例如，如果用户设置了一个 HTTPS 代理，那么 JavaScript 发起的 HTTP 请求就会按照这些测试用例中的方式进行处理。

**举例说明:**

假设一个 JavaScript 脚本尝试通过一个需要认证的 HTTPS 代理访问一个 HTTP 网站：

```javascript
fetch('http://example.com', {
  // ... 其他配置
});
```

如果用户配置了一个 HTTPS 代理服务器 `proxy.example.net:8080`，并且这个代理服务器需要客户端提供证书，那么：

1. **用户操作:** 用户在浏览器设置中配置了代理服务器。
2. **JavaScript 发起请求:** JavaScript 代码执行 `fetch()`。
3. **网络栈处理:** Chromium 网络栈会根据代理配置，创建一个 `HttpNetworkTransaction` 来处理这个请求。
4. **到达此处代码的场景:**  `HttpsClientAuthCertNeededNoCrash` 这个测试用例模拟了代理服务器返回 `ERR_SSL_CLIENT_AUTH_CERT_NEEDED` 的情况。虽然这个测试用例本身没有模拟用户交互，但它验证了在真实场景中，当代理服务器请求客户端证书时，`HttpNetworkTransaction` 不会崩溃，并且可以触发相应的证书选择流程（在其他代码中实现）。

**逻辑推理 (假设输入与输出):**

以 `HttpsProxyGet` 测试为例：

* **假设输入:**
    * `HttpRequestInfo`:  包含 `method = "GET"`, `url = "http://www.example.org/"`。
    * 代理配置:  设置为 `https://proxy:70`。
    * 模拟的网络数据流 (`MockWrite`, `MockRead`) 模拟了与代理服务器的 TLS 连接建立，发送包含完整 URL 的 GET 请求，并接收一个 HTTP 200 OK 响应。
* **预期输出:**
    * `HttpResponseInfo`: 包含 `response_code = 200`, `content-length = 100`。
    * `load_timing_info`:  记录了连接建立和请求发送的耗时。
    * `proxy_chain`:  包含一个 HTTPS 代理服务器的信息。
    * `trans->GetLoadTimingInfo(&load_timing_info)` 返回 `true`。
    * `callback.WaitForResult()` 返回 `OK`。

**用户或编程常见的使用错误:**

* **错误的代理配置:** 用户可能在浏览器中配置了错误的代理服务器地址或端口，导致连接失败 (`ERR_PROXY_CONNECTION_FAILED`)。例如，输入了不存在的代理地址或错误的端口号。
* **代理服务器需要认证但未提供凭据:** 如果代理服务器需要用户名和密码，但用户没有在浏览器中配置或配置错误，会导致认证失败，请求无法到达目标服务器。
* **HTTPS 代理的证书问题:** 如果用户配置的 HTTPS 代理服务器使用了无效或过期的 SSL 证书，浏览器可能会拒绝连接，导致 `ERR_CERT_AUTHORITY_INVALID` 或类似错误。
* **程序错误地处理代理相关的网络错误:** 开发者在使用网络 API 时，可能没有充分处理与代理相关的错误，例如代理连接超时、认证失败等，导致程序行为异常。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中输入 URL 或点击链接:**  这是最常见的触发网络请求的方式。
2. **浏览器检查代理设置:** 浏览器会根据用户的配置（系统设置、浏览器设置、扩展等）确定是否需要使用代理服务器。
3. **如果需要代理，则进行代理解析:**  `ProxyResolutionService` 负责根据配置找到合适的代理服务器。
4. **建立与代理服务器的连接:** 如果是 HTTPS 代理，则需要先建立 TLS 连接。
5. **创建 `HttpNetworkTransaction`:**  `HttpNetworkTransaction` 对象被创建来处理实际的 HTTP 请求，它会根据是否使用代理以及代理的类型采取不同的行为。
6. **调用 `trans->Start()`:**  开始请求处理流程。
7. **在代理场景下，会执行相应的代理逻辑:** 例如，对于 HTTPS 代理，会发送 CONNECT 请求，然后通过代理发送实际的 HTTP 请求。
8. **测试用例模拟这些步骤:** 这里的单元测试通过 `MockWrite` 和 `MockRead` 模拟了网络数据包的发送和接收，覆盖了各种代理场景下的 `HttpNetworkTransaction` 的行为。

作为调试线索，如果网络请求在代理环境下出现问题，可以关注以下几点：

* **检查浏览器的代理配置是否正确。**
* **使用网络抓包工具 (如 Wireshark) 查看与代理服务器的通信过程，确认 CONNECT 请求和后续的 HTTP 请求是否正确发送。**
* **查看 Chrome 的内部网络日志 (chrome://net-export/)，可以获取更详细的网络事件信息，包括代理解析、连接建立、请求发送和响应接收等。**
* **如果涉及到 SPDY/HTTP2 代理，需要确认代理服务器是否支持这些协议，以及协商过程是否正常。**

**这是第9部分，共34部分，其功能归纳:**

考虑到这是测试文件的前半部分，并且集中在代理场景，可以推断：

这部分 (`net/http/http_network_transaction_unittest.cc` 的第9部分) 的主要功能是 **测试 `HttpNetworkTransaction` 类在各种代理场景下的正确性和鲁棒性**。它验证了在不同的代理配置下，`HttpNetworkTransaction` 是否能够正确地发起请求、处理响应、管理连接以及处理可能出现的错误，例如代理连接失败、协议错误和需要客户端认证等。这为后续更复杂的网络功能测试奠定了基础。

### 提示词
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共34部分，请归纳一下它的功能
```

### 源代码
```cpp
rans2 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  rv = trans2->Start(&request2, callback2.callback(), net_log_with_source);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response2 = trans2->GetResponseInfo();
  ASSERT_TRUE(response2);
  ASSERT_TRUE(response2->headers);
  EXPECT_EQ(2, response2->headers->GetContentLength());

  LoadTimingInfo load_timing_info2;
  EXPECT_TRUE(trans2->GetLoadTimingInfo(&load_timing_info2));
  TestLoadTimingReusedWithPac(load_timing_info2);

  EXPECT_EQ(load_timing_info1.socket_log_id, load_timing_info2.socket_log_id);

  trans2.reset();
  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

// Make sure that NetworkAnonymizationKeys are passed down to the proxy layer.
TEST_P(HttpNetworkTransactionTest, ProxyResolvedWithNetworkAnonymizationKey) {
  ProxyConfig proxy_config;
  proxy_config.set_auto_detect(true);
  proxy_config.set_pac_url(GURL("http://fooproxyurl"));

  CapturingProxyResolver capturing_proxy_resolver;
  capturing_proxy_resolver.set_proxy_chain(ProxyChain::Direct());
  session_deps_.proxy_resolution_service =
      std::make_unique<ConfiguredProxyResolutionService>(
          std::make_unique<ProxyConfigServiceFixed>(ProxyConfigWithAnnotation(
              proxy_config, TRAFFIC_ANNOTATION_FOR_TESTS)),
          std::make_unique<CapturingProxyResolverFactory>(
              &capturing_proxy_resolver),
          nullptr, /*quick_check_enabled=*/true);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // No need to continue with the network request - proxy resolution occurs
  // before establishing a data.
  StaticSocketDataProvider data{base::span<MockRead>(),
                                base::span<MockWrite>()};
  data.set_connect_data(MockConnect(SYNCHRONOUS, ERR_FAILED));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  // Run first request until an auth challenge is observed.
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://foo.test/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  request.network_isolation_key = kNetworkIsolationKey;
  request.network_anonymization_key = kNetworkAnonymizationKey;
  HttpNetworkTransaction trans(LOWEST, session.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_FAILED));

  ASSERT_EQ(1u, capturing_proxy_resolver.lookup_info().size());
  ASSERT_EQ(
      kNetworkAnonymizationKey,
      capturing_proxy_resolver.lookup_info()[0].network_anonymization_key);
  ASSERT_EQ(request.url, capturing_proxy_resolver.lookup_info()[0].url);
}

// Test that a failure in resolving the proxy hostname is retrievable.
TEST_P(HttpNetworkTransactionTest, ProxyHostResolutionFailure) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against https proxy server "proxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  auto resolver = std::make_unique<MockHostResolver>();
  resolver->rules()->AddSimulatedTimeoutFailure("proxy");
  session_deps_.net_log = NetLog::Get();
  session_deps_.host_resolver = std::move(resolver);
  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_PROXY_CONNECTION_FAILED));

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_THAT(response->resolve_error_info.error, IsError(ERR_DNS_TIMED_OUT));
}

// Test a simple GET (for an HTTP endpoint) through an HTTPS Proxy
// (HTTPS -> HTTP).
TEST_P(HttpNetworkTransactionTest, HttpsProxyGet) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  // GET should use UA header from the request, not from the
  // `HttpUserAgentSettings` in session_deps_.
  request.extra_headers.SetHeader(HttpRequestHeaders::kUserAgent, "request-ua");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against https proxy server "proxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since we have proxy, should use full url
  MockWrite data_writes1[] = {
      MockWrite("GET http://www.example.org/ HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: request-ua\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");
  ASSERT_TRUE(ssl.ssl_info.cert);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  ConnectedHandler connected_handler;
  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  trans.SetConnectedCallback(connected_handler.Callback());

  int rv = trans.Start(&request, callback.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info,
                          CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  ASSERT_EQ(1u, response->proxy_chain.length());
  EXPECT_TRUE(response->proxy_chain.GetProxyServer(0).is_https());
  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(100, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  // DNS aliases should be empty when using a proxy.
  EXPECT_TRUE(response->dns_aliases.empty());

  TransportInfo expected_transport;
  expected_transport.type = TransportType::kProxied;
  expected_transport.endpoint = IPEndPoint(IPAddress::IPv4Localhost(), 70);
  expected_transport.negotiated_protocol = kProtoUnknown;
  EXPECT_THAT(connected_handler.transports(), ElementsAre(expected_transport));

  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge.has_value());

  // Although we use an HTTPS proxy, the `SSLInfo` from that connection should
  // not be reported as a property of the origin.
  EXPECT_FALSE(response->ssl_info.cert);
}

// Test a simple GET (for an HTTP endpoint) through two HTTPS proxies
// (HTTPS -> HTTPS -> HTTP). This should tunnel through both proxies.
TEST_P(HttpNetworkTransactionTest, HttpsNestedProxyGet) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure a nested proxy.
  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 70)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 71)};
  const ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({{kProxyServer1, kProxyServer2}});

  ProxyList proxy_list;
  proxy_list.AddProxyChain(kNestedProxyChain);
  ProxyConfig proxy_config = ProxyConfig::CreateForTesting(proxy_list);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          ProxyConfigWithAnnotation(proxy_config,
                                    TRAFFIC_ANNOTATION_FOR_TESTS));
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  MockWrite data_writes1[] = {
      MockWrite("CONNECT proxy2.test:71 HTTP/1.1\r\n"
                "Host: proxy2.test:71\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
      MockWrite("CONNECT www.example.org:80 HTTP/1.1\r\n"
                "Host: www.example.org:80\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  SSLSocketDataProvider ssl2(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  ConnectedHandler connected_handler;
  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  trans.SetConnectedCallback(connected_handler.Callback());

  int rv = trans.Start(&request, callback.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info,
                          CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_EQ(2u, response->proxy_chain.length());
  EXPECT_TRUE(response->proxy_chain.GetProxyServer(0).is_https());
  EXPECT_TRUE(response->proxy_chain.GetProxyServer(1).is_https());
  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(100, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  // DNS aliases should be empty when using a proxy.
  EXPECT_TRUE(response->dns_aliases.empty());

  TransportInfo expected_transport;
  expected_transport.type = TransportType::kProxied;
  expected_transport.endpoint = IPEndPoint(IPAddress::IPv4Localhost(), 70);
  EXPECT_THAT(connected_handler.transports(), ElementsAre(expected_transport));

  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge.has_value());

  // Although we use an HTTPS proxy, the `SSLInfo` from that connection should
  // not be reported as a property of the origin.
  EXPECT_FALSE(response->ssl_info.cert);
}

// Test a SPDY GET (for an HTTP endpoint) through an HTTPS (SPDY) proxy
// (SPDY -> HTTP).
TEST_P(HttpNetworkTransactionTest, HttpsProxySpdyGet) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against https proxy server "proxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // fetch http://www.example.org/ via SPDY
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet("http://www.example.org/", 1, LOWEST));
  MockWrite spdy_writes[] = {CreateMockWrite(req, 0)};

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame data(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead spdy_reads[] = {
      CreateMockRead(resp, 1),
      CreateMockRead(data, 2),
      MockRead(ASYNC, 0, 3),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");
  ASSERT_TRUE(ssl.ssl_info.cert);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  ConnectedHandler connected_handler;
  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  trans.SetConnectedCallback(connected_handler.Callback());

  int rv = trans.Start(&request, callback.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info,
                          CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_EQ(1u, response->proxy_chain.length());
  EXPECT_TRUE(response->proxy_chain.GetProxyServer(0).is_https());
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());

  // DNS aliases should be empty when using a proxy.
  EXPECT_TRUE(response->dns_aliases.empty());

  TransportInfo expected_transport;
  expected_transport.type = TransportType::kProxied;
  expected_transport.endpoint = IPEndPoint(IPAddress::IPv4Localhost(), 70);
  expected_transport.negotiated_protocol = kProtoHTTP2;
  EXPECT_THAT(connected_handler.transports(), ElementsAre(expected_transport));

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ(kUploadData, response_data);

  // Although we use an HTTPS proxy, the `SSLInfo` from that connection should
  // not be reported as a property of the origin.
  EXPECT_FALSE(response->ssl_info.cert);
}

// Test a SPDY GET (for an HTTP endpoint) through two HTTPS (SPDY) proxies
// (SPDY -> SPDY -> HTTP).
TEST_P(HttpNetworkTransactionTest, HttpsNestedProxySpdyGet) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure a nested proxy.
  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 70)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 71)};
  const ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({{kProxyServer1, kProxyServer2}});

  ProxyList proxy_list;
  proxy_list.AddProxyChain(kNestedProxyChain);
  ProxyConfig proxy_config = ProxyConfig::CreateForTesting(proxy_list);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          ProxyConfigWithAnnotation(proxy_config,
                                    TRAFFIC_ANNOTATION_FOR_TESTS));
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // CONNECT to proxy2.test:71 via SPDY.
  spdy::SpdySerializedFrame proxy2_connect(spdy_util_.ConstructSpdyConnect(
      /*extra_headers=*/nullptr, 0, 1,
      HttpProxyConnectJob::kH2QuicTunnelPriority,
      kProxyServer2.host_port_pair()));

  spdy::SpdySerializedFrame proxy2_connect_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  // CONNECT to www.example.org:80 via SPDY.
  // Need to use a new `SpdyTestUtil()` so that the stream parent ID of this
  // request is calculated correctly.
  SpdyTestUtil spdy_util2(/*use_priority_header=*/true);
  spdy::SpdySerializedFrame endpoint_connect(spdy_util2.ConstructSpdyConnect(
      /*extra_headers=*/nullptr, 0, 1,
      HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 80)));
  spdy::SpdySerializedFrame wrapped_endpoint_connect(
      spdy_util_.ConstructWrappedSpdyFrame(endpoint_connect, 1));

  spdy::SpdySerializedFrame endpoint_connect_resp(
      spdy_util2.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame wrapped_endpoint_connect_resp(
      spdy_util_.ConstructWrappedSpdyFrame(endpoint_connect_resp, 1));

  // fetch http://www.example.org/ via HTTP.
  // Since this request will go over two tunnels, it needs to be double-wrapped.
  const char kGet[] =
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get(
      spdy_util2.ConstructSpdyDataFrame(1, kGet, false));
  spdy::SpdySerializedFrame wrapped_wrapped_get(
      spdy_util_.ConstructWrappedSpdyFrame(wrapped_get, 1));

  const char kResp[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 10\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get_resp(
      spdy_util2.ConstructSpdyDataFrame(1, kResp, false));
  spdy::SpdySerializedFrame wrapped_wrapped_get_resp(
      spdy_util_.ConstructWrappedSpdyFrame(wrapped_get_resp, 1));

  const char kRespData[] = "1234567890";
  spdy::SpdySerializedFrame wrapped_body(
      spdy_util2.ConstructSpdyDataFrame(1, kRespData, false));
  spdy::SpdySerializedFrame wrapped_wrapped_body(
      spdy_util_.ConstructWrappedSpdyFrame(wrapped_body, 1));

  MockWrite spdy_writes[] = {
      CreateMockWrite(proxy2_connect, 0),
      CreateMockWrite(wrapped_endpoint_connect, 2),
      CreateMockWrite(wrapped_wrapped_get, 5),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(proxy2_connect_resp, 1),
      // TODO(crbug.com/41180906): We have to manually delay this read so
      // that the higher-level SPDY stream doesn't get notified of an available
      // read before the write it initiated (the second CONNECT) finishes,
      // triggering a DCHECK.
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      CreateMockRead(wrapped_endpoint_connect_resp, 4, ASYNC),
      CreateMockRead(wrapped_wrapped_get_resp, 6, ASYNC),
      CreateMockRead(wrapped_wrapped_body, 7, ASYNC),
      MockRead(ASYNC, 0, 8),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  SSLSocketDataProvider ssl2(ASYNC, OK);
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  ConnectedHandler connected_handler;
  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  trans.SetConnectedCallback(connected_handler.Callback());

  int rv = trans.Start(&request, callback.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  spdy_data.RunUntilPaused();
  base::RunLoop().RunUntilIdle();
  spdy_data.Resume();

  rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info,
                          CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_EQ(response->proxy_chain.GetProxyServer(/*chain_index=*/0),
            kProxyServer1);
  EXPECT_EQ(response->proxy_chain.GetProxyServer(/*chain_index=*/1),
            kProxyServer2);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  // DNS aliases should be empty when using a proxy.
  EXPECT_TRUE(response->dns_aliases.empty());

  TransportInfo expected_transport;
  expected_transport.type = TransportType::kProxied;
  expected_transport.endpoint = IPEndPoint(IPAddress::IPv4Localhost(), 70);
  expected_transport.negotiated_protocol = kProtoUnknown;
  EXPECT_THAT(connected_handler.transports(), ElementsAre(expected_transport));

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ(kRespData, response_data);

  // Although we use an HTTPS proxy, the `SSLInfo` from that connection should
  // not be reported as a property of the origin.
  EXPECT_FALSE(response->ssl_info.cert);
}

// Test a SPDY GET (for an HTTP endpoint) through the same HTTPS (SPDY) proxy
// twice (SPDY -> SPDY -> HTTP).
TEST_P(HttpNetworkTransactionTest, HttpsNestedProxySameProxyTwiceSpdyGet) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure a nested proxy.
  const ProxyServer kProxyServer{ProxyServer::SCHEME_HTTPS,
                                 HostPortPair("proxy.test", 70)};
  const ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({{kProxyServer, kProxyServer}});

  ProxyList proxy_list;
  proxy_list.AddProxyChain(kNestedProxyChain);
  ProxyConfig proxy_config = ProxyConfig::CreateForTesting(proxy_list);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          ProxyConfigWithAnnotation(proxy_config,
                                    TRAFFIC_ANNOTATION_FOR_TESTS));

  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // CONNECT to proxy.test:70 via SPDY.
  spdy::SpdySerializedFrame proxy_connect(spdy_util_.ConstructSpdyConnect(
      /*extra_headers=*/nullptr, 0, 1,
      HttpProxyConnectJob::kH2QuicTunnelPriority,
      kProxyServer.host_port_pair()));

  spdy::SpdySerializedFrame proxy_connect_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  // CONNECT to www.example.org:80 via SPDY.
  // Need to use a new `SpdyTestUtil()` so that the stream parent ID of this
  // request is calculated correctly.
  SpdyTestUtil new_spdy_util(/*use_priority_header=*/true);
  spdy::SpdySerializedFrame endpoint_connect(new_spdy_util.ConstructSpdyConnect(
      /*extra_headers=*/nullptr, 0, 1,
      HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 80)));
  spdy::SpdySerializedFrame wrapped_endpoint_connect(
      spdy_util_.ConstructWrappedSpdyFrame(endpoint_connect, 1));

  spdy::SpdySerializedFrame endpoint_connect_resp(
      new_spdy_util.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame wrapped_endpoint_connect_resp(
      spdy_util_.ConstructWrappedSpdyFrame(endpoint_connect_resp, 1));

  // fetch http://www.example.org/ via HTTP.
  // Since this request will go over two tunnels, it needs to be double-wrapped.
  const char kGet[] =
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get(
      new_spdy_util.ConstructSpdyDataFrame(1, kGet, false));
  spdy::SpdySerializedFrame wrapped_wrapped_get(
      spdy_util_.ConstructWrappedSpdyFrame(wrapped_get, 1));

  const char kResp[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 10\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get_resp(
      new_spdy_util.ConstructSpdyDataFrame(1, kResp, false));
  spdy::SpdySerializedFrame wrapped_wrapped_get_resp(
      spdy_util_.ConstructWrappedSpdyFrame(wrapped_get_resp, 1));

  const char kRespData[] = "1234567890";
  spdy::SpdySerializedFrame wrapped_body(
      new_spdy_util.ConstructSpdyDataFrame(1, kRespData, false));
  spdy::SpdySerializedFrame wrapped_wrapped_body(
      spdy_util_.ConstructWrappedSpdyFrame(wrapped_body, 1));

  MockWrite spdy_writes[] = {
      CreateMockWrite(proxy_connect, 0),
      CreateMockWrite(wrapped_endpoint_connect, 2),
      CreateMockWrite(wrapped_wrapped_get, 5),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(proxy_connect_resp, 1),
      // TODO(crbug.com/41180906): We have to manually delay this read so
      // that the higher-level SPDY stream doesn't get notified of an available
      // read before the write it initiated (the second CONNECT) finishes,
      // triggering a DCHECK.
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      CreateMockRead(wrapped_endpoint_connect_resp, 4, ASYNC),
      CreateMockRead(wrapped_wrapped_get_resp, 6, ASYNC),
      CreateMockRead(wrapped_wrapped_body, 7, ASYNC),
      MockRead(ASYNC, 0, 8),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  SSLSocketDataProvider ssl2(ASYNC, OK);
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  ConnectedHandler connected_handler;
  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  trans.SetConnectedCallback(connected_handler.Callback());

  int rv = trans.Start(&request, callback.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  spdy_data.RunUntilPaused();
  base::RunLoop().RunUntilIdle();
  spdy_data.Resume();

  rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info,
                          CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_EQ(response->proxy_chain.GetProxyServer(/*chain_index=*/0),
            kProxyServer);
  EXPECT_EQ(response->proxy_chain.GetProxyServer(/*chain_index=*/1),
            kProxyServer);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  // DNS aliases should be empty when using a proxy.
  EXPECT_TRUE(response->dns_aliases.empty());

  TransportInfo expected_transport;
  expected_transport.type = TransportType::kProxied;
  expected_transport.endpoint = IPEndPoint(IPAddress::IPv4Localhost(), 70);
  expected_transport.negotiated_protocol = kProtoUnknown;
  EXPECT_THAT(connected_handler.transports(), ElementsAre(expected_transport));

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ(kRespData, response_data);

  // Although we use an HTTPS proxy, the `SSLInfo` from that connection should
  // not be reported as a property of the origin.
  EXPECT_FALSE(response->ssl_info.cert);
}

// Test that a SPDY protocol error encountered when attempting to perform an
// HTTP request over a multi-proxy chain is handled correctly.
TEST_P(HttpNetworkTransactionTest, NestedProxyHttpOverSpdyProtocolError) {
  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 70)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 71)};
  const ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({{kProxyServer1, kProxyServer2}});

  ProxyList proxy_list;
  proxy_list.AddProxyChain(kNestedProxyChain);
  ProxyConfig proxy_config = ProxyConfig::CreateForTesting(proxy_list);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          ProxyConfigWithAnnotation(proxy_config,
                                    TRAFFIC_ANNOTATION_FOR_TESTS));
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // CONNECT to proxy2.test:71 via SPDY.
  spdy::SpdySerializedFrame proxy2_connect(spdy_util_.ConstructSpdyConnect(
      /*extra_headers=*/nullptr, 0, 1,
      HttpProxyConnectJob::kH2QuicTunnelPriority,
      kProxyServer2.host_port_pair()));

  spdy::SpdySerializedFrame proxy2_connect_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  // CONNECT to www.example.org:80 via SPDY.
  // Need to use a new `SpdyTestUtil()` so that the stream parent ID of this
  // request is calculated correctly.
  SpdyTestUtil spdy_util2(/*use_priority_header=*/true);
  spdy::SpdySerializedFrame endpoint_connect(spdy_util2.ConstructSpdyConnect(
      /*extra_headers=*/nullptr, 0, 1,
      HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 80)));
  spdy::SpdySerializedFrame wrapped_endpoint_connect(
      spdy_util_.ConstructWrappedSpdyFrame(endpoint_connect, 1));

  spdy::SpdySerializedFrame data(spdy_util2.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame wrapped_data(
      spdy_util_.ConstructWrappedSpdyFrame(data, 1));

  MockWrite spdy_writes[] = {
      CreateMockWrite(proxy2_connect, 0),
      CreateMockWrite(wrapped_endpoint_connect, 2),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(proxy2_connect_resp, 1),
      // TODO(crbug.com/41180906): We have to manually delay this read so
      // that the higher-level SPDY stream doesn't get notified of an available
      // read before the write it initiated (the second CONNECT) finishes,
      // triggering a DCHECK.
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      // Instead of returning a valid response, just return wrapped data. This
      // should trigger an HTTP2 protocol error and not CHECK when nested
      // proxies are in use.
      CreateMockRead(wrapped_data, 4),
      MockRead(ASYNC, 0, 5),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  SSLSocketDataProvider ssl2(ASYNC, OK);
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  spdy_data.RunUntilPaused();
  base::RunLoop().RunUntilIdle();
  spdy_data.Resume();

  rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsError(ERR_HTTP2_PROTOCOL_ERROR));
}

// Test that a proxy server requesting a client auth cert doesn't cause a crash.
// TODO(crbug.com/40284947): This test can be deleted once we no longer
// need the multi-proxy chain version below, since this functionality should
// be sufficiently tested elsewhere. For now this test just shows that
// single-proxy and multi-proxy behavior is consistent (when a read returns
// ERR_SSL_CLIENT_AUTH_CERT_NEEDED).
TEST_P(HttpNetworkTransactionTest, HttpsClientAuthCertNeededNoCrash) {
  // Configure against https proxy server "proxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);

  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // CONNECT to www.example.org:443 via SPDY.
  spdy::SpdySerializedFr
```