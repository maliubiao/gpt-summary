Response:
My thinking process to analyze the provided code snippet and fulfill the request involved the following steps:

1. **Understand the Goal:** The main objective is to understand the functionality of the given C++ code snippet from Chromium's network stack, specifically the `http_network_transaction_unittest.cc` file. The request also asks about relationships with JavaScript, logical inference with inputs and outputs, common user/programming errors, debugging context, and a summary of the current part's functionality within the larger file.

2. **Identify Key Components:** I scanned the code for recurring patterns, class names, and function calls. The prominent components were:
    * `HttpNetworkTransactionTest`:  This immediately signaled that the code is a unit test fixture.
    * `TEST_P`: This indicates parameterized testing, likely using different network layer configurations.
    * `HttpRequestInfo`: A structure holding details about an HTTP request (method, URL, flags).
    * `MockRead`, `MockWrite`, `StaticSocketDataProvider`, `SSLSocketDataProvider`: These are mocking tools for simulating network I/O and SSL handshakes.
    * `HttpNetworkSession`, `HttpServerProperties`: Core classes for managing network sessions and storing HTTP server properties (like alternative services).
    * `AlternativeService`: Represents an alternative way to connect to a server (e.g., using HTTP/2 or QUIC).
    * `NetworkAnonymizationKey`: A concept related to privacy and separating network state.
    * `TestCompletionCallback`: A utility for asynchronous testing.
    * `EXPECT_...`, `ASSERT_...`:  Assertion macros used in unit tests.
    * Specific test names like `DoNotParseAlternativeServiceHeaderOnInsecureRequest`, `DisableHTTP2AlternativeServicesWithDifferentHost`, `ClearAlternativeServices`, etc. These names provide high-level clues about what each test is verifying.

3. **Analyze Individual Tests:** I went through each `TEST_P` block, focusing on:
    * **Setup:** What mock data and session configurations are being set up?  This involves understanding what `MockRead`, `MockWrite`, and the various `...SocketDataProvider` classes are simulating.
    * **Action:** What is the test doing? Usually, it involves creating an `HttpRequestInfo`, starting an `HttpNetworkTransaction`, and waiting for a result.
    * **Verification:** What assertions are being made? This is crucial for understanding the test's expectations. Assertions involve checking response headers, response body, and the state of `HttpServerProperties` (specifically regarding alternative services).

4. **Look for Common Themes:**  As I analyzed the tests, I noticed recurring patterns:
    * **Alternative Services (Alt-Svc):**  Many tests explicitly deal with setting, retrieving, clearing, and handling `Alt-Svc` headers.
    * **HTTP/2 and QUIC:**  Several tests focus on the interaction of `HttpNetworkTransaction` with these newer protocols, often in the context of alternative services.
    * **Secure vs. Insecure Requests:** Some tests differentiate between `http://` and `https://` URLs.
    * **Port Restrictions:**  Tests explore how the transaction handles alternative services on different ports, especially restricted ports (< 1024).
    * **Marking Broken Alternatives:**  Tests verify the mechanism for marking alternative protocols as broken and falling back to the original protocol.

5. **Address Specific Requirements:** Once I had a general understanding, I addressed each part of the request:

    * **Functionality Listing:** I summarized the core functionalities based on the test themes.
    * **Relationship with JavaScript:** I recognized that this C++ code is part of the *underlying network implementation* that JavaScript in a browser relies on. I provided examples of how JavaScript's `fetch` API or XMLHttpRequest would trigger this code.
    * **Logical Inference (Input/Output):** I chose a representative test (`HonorMultipleAlternativeServiceHeaders`) and described the assumed input (server response headers) and the expected output (updated `HttpServerProperties`).
    * **Common Errors:** I identified potential issues related to incorrect `Alt-Svc` headers and mismatched configurations, explaining how these could lead to connection problems.
    * **User Operation to Reach Code:** I outlined the steps a user might take in a browser that would lead to this code being executed (e.g., visiting a website that uses alternative services).
    * **Part Summary:** Based on the analyzed tests, I concluded that this section focuses on testing the `HttpNetworkTransaction`'s ability to handle HTTP Alternative Services and related fallback mechanisms.

6. **Refine and Organize:** I reviewed my notes and organized the information logically, using clear and concise language. I paid attention to formatting to improve readability. I tried to connect the dots between the individual tests and the overall functionality being tested. For example,  the tests about port restrictions and marking broken alternatives contribute to a robust and reliable alternative service implementation.

By following these steps, I was able to dissect the C++ code, understand its purpose, and address all aspects of the user's request. The key was to treat the unit tests as specifications of the code's behavior.
这是 Chromium 网络栈中 `net/http/http_network_transaction_unittest.cc` 文件的第 21 部分（共 34 部分）。从代码内容来看，这部分主要专注于测试 `HttpNetworkTransaction` 类处理 HTTP 替代服务（Alternative Services，Alt-Svc）相关的逻辑。

**功能归纳:**

这部分代码主要测试了 `HttpNetworkTransaction` 如何处理和应用 HTTP 替代服务，包括：

* **存储和检索替代服务信息:** 验证 `HttpServerProperties` 是否能正确存储和检索与特定主机和网络匿名化密钥关联的替代服务信息。
* **拒绝在不安全连接上解析 Alt-Svc 头部:**  测试对于 `http://` 连接，即使服务器返回 `Alt-Svc` 头部，也不会被解析和应用。
* **禁用 HTTP/2 替代服务:** 验证在显式禁用 HTTP/2 替代服务时，即使服务器通告了也不会尝试使用。
* **禁用不安全来源的替代服务:** 测试对于 `http://` 来源，即使配置了替代服务也不会尝试使用。
* **清除替代服务:** 测试接收到 "Alt-Svc: clear" 头部时，能够正确清除已存储的替代服务信息。
* **处理多个 Alt-Svc 头部:** 验证能够正确解析和存储多个 `Alt-Svc` 头部提供的替代服务信息。
* **识别 QUIC 连接中断:** 测试当尝试使用 QUIC 替代服务连接失败时，能够正确标记该替代服务为中断。
* **识别 QUIC 连接未中断:**  测试在存在多个 QUIC 替代服务的情况下，即使其中一个中断，也不会将所有 QUIC 服务都标记为中断。
* **标记中断的替代协议并回退:** 测试当尝试使用替代协议连接失败时，能够回退到原始协议，并将该替代协议标记为中断。
* **阻止重定向到受限端口的替代协议:** 验证当原始请求使用受限端口（< 1024）时，不会尝试重定向到使用非受限端口（>= 1024）的替代协议，除非明确允许。
* **允许重定向到受限端口的替代协议（特定配置下）:** 测试在 `enable_user_alternate_protocol_ports` 设置为 true 时，允许从受限端口重定向到非受限端口的替代协议。
* **允许重定向到同为受限或非受限端口的替代协议:**  验证当原始请求和替代协议使用相同类型的端口（都受限或都非受限）时，允许重定向。
* **阻止重定向到不安全端口的替代协议:** 测试不会尝试重定向到被认为是不安全的端口的替代协议。

**与 JavaScript 的关系：**

这段 C++ 代码是 Chromium 浏览器网络栈的底层实现，与 JavaScript 的网络功能有着密切的关系。当 JavaScript 代码发起网络请求时（例如使用 `fetch` API 或 `XMLHttpRequest`），最终会调用到 Chromium 网络栈的 C++ 代码来执行实际的网络通信。

**举例说明：**

假设一个网站 `https://www.example.org/` 在其 HTTP 响应头中包含了如下 `Alt-Svc` 头部：

```
Alt-Svc: h2="alt.example.org:443", h3-29=":8000"
```

当浏览器中的 JavaScript 代码使用 `fetch('https://www.example.org/')` 发起请求时，`HttpNetworkTransaction` 会解析这个 `Alt-Svc` 头部，并尝试与 `alt.example.org:443` 使用 HTTP/2 (h2) 协议建立连接，或者与 `www.example.org:8000` 使用 HTTP/3 (h3-29) 协议建立连接（如果浏览器支持 HTTP/3）。

这段 C++ 代码中的测试用例就模拟了这种场景，验证了 `HttpNetworkTransaction` 能否正确地解析和存储这些替代服务信息，并在后续的请求中尝试使用它们。

**逻辑推理与假设输入输出：**

**测试用例:** `TEST_P(HttpNetworkTransactionTest, HonorMultipleAlternativeServiceHeaders)`

**假设输入:**

* 一个 HTTPS 请求到 `https://www.example.org/`。
* 服务器的响应头包含以下内容：
  ```
  HTTP/1.1 200 OK
  Alt-Svc: h2="www.example.com:443",h2=":1234"
  ```

**预期输出:**

* `HttpServerProperties` 中会存储两个与 `https://www.example.org:443` 关联的替代服务：
    * `h2` 协议，主机 `www.example.com`，端口 `443`
    * `h2` 协议，主机 `www.example.org`，端口 `1234`
* 后续对 `https://www.example.org/` 的请求可能会尝试使用这两个替代服务进行连接。

**用户或编程常见的使用错误：**

* **错误的 Alt-Svc 头部格式:**  如果服务器配置了错误的 `Alt-Svc` 头部格式，例如缺少引号、格式不正确等，`HttpNetworkTransaction` 可能无法正确解析，导致替代服务无法生效。
    * **例子:** `Alt-Svc: h2=alt.example.org:443` (缺少引号)
* **替代服务配置错误:** 服务器配置了无法访问或不支持的替代服务，会导致连接失败。
    * **例子:** 配置了一个不存在的 HTTP/3 服务。
* **对不安全连接使用 Alt-Svc:**  正如测试用例所展示的，浏览器通常不会在不安全的 `http://` 连接上解析和应用 `Alt-Svc` 头部，这是一个常见的安全措施。开发者如果期望在 HTTP 连接上使用替代服务，可能会遇到问题。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入一个 HTTPS 网址，例如 `https://www.example.org/`，或者点击了一个 HTTPS 链接。**
2. **浏览器发起网络请求。**
3. **`HttpNetworkTransaction` 类被创建，负责处理这个请求。**
4. **在接收到服务器的响应头后，`HttpNetworkTransaction` 会检查是否存在 `Alt-Svc` 头部。**
5. **如果存在 `Alt-Svc` 头部，代码会解析这个头部，并尝试更新 `HttpServerProperties` 中存储的替代服务信息。**
6. **如果后续对同一个 origin 的请求再次发生，`HttpNetworkTransaction` 可能会尝试使用之前存储的替代服务进行连接，以优化连接速度和性能。**
7. **如果在尝试使用替代服务连接时发生错误（例如连接被拒绝），相关的逻辑会尝试回退到原始协议，并可能将该替代服务标记为中断。**

在调试网络问题时，开发者可以通过以下方式观察是否涉及到替代服务：

* **使用 Chrome 的 `chrome://net-internals/#http2` 或 `chrome://net-internals/#quic` 查看 HTTP/2 和 QUIC 连接状态。**
* **使用 `chrome://net-internals/#events` 捕获网络事件，查看是否有尝试使用替代服务的记录以及是否连接成功。**
* **检查服务器返回的 HTTP 响应头，确认是否存在 `Alt-Svc` 头部以及其内容。**

**总结这部分的功能:**

总而言之，这部分 `http_network_transaction_unittest.cc` 的代码主要负责测试 `HttpNetworkTransaction` 类在处理 HTTP 替代服务时的正确性和健壮性，涵盖了替代服务的存储、解析、应用、错误处理以及安全限制等多个方面。这是确保 Chromium 浏览器能够正确高效地利用替代服务，提升网络性能和用户体验的关键部分。

### 提示词
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第21部分，共34部分，请归纳一下它的功能
```

### 源代码
```cpp
operties->GetAlternativeServiceInfos(
          test_server, kNetworkAnonymizationKey1);
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  AlternativeService alternative_service(kProtoHTTP2, "mail.example.org", 443);
  EXPECT_EQ(alternative_service,
            alternative_service_info_vector[0].alternative_service());

  // Make sure the alternative service information is only associated with
  // kNetworkAnonymizationKey1.
  EXPECT_TRUE(
      http_server_properties
          ->GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey())
          .empty());
  EXPECT_TRUE(
      http_server_properties
          ->GetAlternativeServiceInfos(test_server, kNetworkAnonymizationKey2)
          .empty());
}

// Regression test for https://crbug.com/615497.
TEST_P(HttpNetworkTransactionTest,
       DoNotParseAlternativeServiceHeaderOnInsecureRequest) {
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(kAlternativeServiceHttpHeader),
      MockRead("\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.load_flags = 0;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  url::SchemeHostPort test_server(request.url);
  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  EXPECT_TRUE(
      http_server_properties
          ->GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey())
          .empty());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_FALSE(response->was_alpn_negotiated);

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  EXPECT_TRUE(
      http_server_properties
          ->GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey())
          .empty());
}

// HTTP/2 Alternative Services should be disabled by default.
// TODO(bnc): Remove when https://crbug.com/615413 is fixed.
TEST_P(HttpNetworkTransactionTest,
       DisableHTTP2AlternativeServicesWithDifferentHost) {
  session_deps_.enable_http2_alternative_service = false;

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.load_flags = 0;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockConnect mock_connect(ASYNC, ERR_CONNECTION_REFUSED);
  StaticSocketDataProvider first_data;
  first_data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&first_data);
  SSLSocketDataProvider ssl_http11(ASYNC, OK);
  ssl_http11.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_http11);

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(ASYNC, OK),
  };
  StaticSocketDataProvider second_data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&second_data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  AlternativeService alternative_service(kProtoHTTP2, "different.example.org",
                                         444);
  base::Time expiration = base::Time::Now() + base::Days(1);
  http_server_properties->SetHttp2AlternativeService(
      url::SchemeHostPort(request.url), NetworkAnonymizationKey(),
      alternative_service, expiration);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  // Alternative service is not used, request fails.
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_CONNECTION_REFUSED));
}

// Regression test for https://crbug.com/615497:
// Alternative Services should be disabled for http origin.
TEST_P(HttpNetworkTransactionTest,
       DisableAlternativeServicesForInsecureOrigin) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.load_flags = 0;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockConnect mock_connect(ASYNC, ERR_CONNECTION_REFUSED);
  StaticSocketDataProvider first_data;
  first_data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&first_data);

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(ASYNC, OK),
  };
  StaticSocketDataProvider second_data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&second_data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  AlternativeService alternative_service(kProtoHTTP2, "", 444);
  base::Time expiration = base::Time::Now() + base::Days(1);
  http_server_properties->SetHttp2AlternativeService(
      url::SchemeHostPort(request.url), NetworkAnonymizationKey(),
      alternative_service, expiration);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  // Alternative service is not used, request fails.
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_CONNECTION_REFUSED));
}

TEST_P(HttpNetworkTransactionTest, ClearAlternativeServices) {
  // Set an alternative service for origin.
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  url::SchemeHostPort test_server("https", "www.example.org", 443);
  AlternativeService alternative_service(kProtoQUIC, "", 80);
  base::Time expiration = base::Time::Now() + base::Days(1);
  http_server_properties->SetQuicAlternativeService(
      test_server, NetworkAnonymizationKey(), alternative_service, expiration,
      session->context().quic_context->params()->supported_versions);
  EXPECT_EQ(1u, http_server_properties
                    ->GetAlternativeServiceInfos(test_server,
                                                 NetworkAnonymizationKey())
                    .size());

  // Send a clear header.
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Alt-Svc: clear\r\n"),
      MockRead("\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
  ASSERT_TRUE(ssl.ssl_info.cert);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_FALSE(response->was_alpn_negotiated);

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  EXPECT_TRUE(
      http_server_properties
          ->GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey())
          .empty());
}

TEST_P(HttpNetworkTransactionTest, HonorMultipleAlternativeServiceHeaders) {
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Alt-Svc: h2=\"www.example.com:443\","),
      MockRead("h2=\":1234\"\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
  ASSERT_TRUE(ssl.ssl_info.cert);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  url::SchemeHostPort test_server("https", "www.example.org", 443);
  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  EXPECT_TRUE(
      http_server_properties
          ->GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey())
          .empty());

  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_FALSE(response->was_alpn_negotiated);

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  AlternativeServiceInfoVector alternative_service_info_vector =
      http_server_properties->GetAlternativeServiceInfos(
          test_server, NetworkAnonymizationKey());
  ASSERT_EQ(2u, alternative_service_info_vector.size());

  AlternativeService alternative_service(kProtoHTTP2, "www.example.com", 443);
  EXPECT_EQ(alternative_service,
            alternative_service_info_vector[0].alternative_service());
  AlternativeService alternative_service_2(kProtoHTTP2, "www.example.org",
                                           1234);
  EXPECT_EQ(alternative_service_2,
            alternative_service_info_vector[1].alternative_service());
}

TEST_P(HttpNetworkTransactionTest, IdentifyQuicBroken) {
  url::SchemeHostPort server("https", "origin.example.org", 443);
  HostPortPair alternative("alternative.example.org", 443);
  std::string origin_url = "https://origin.example.org:443";
  std::string alternative_url = "https://alternative.example.org:443";

  // Negotiate HTTP/1.1 with alternative.example.org.
  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  // HTTP/1.1 data for request.
  MockWrite http_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: alternative.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Content-Type: text/html; charset=iso-8859-1\r\n"
               "Content-Length: 40\r\n\r\n"
               "first HTTP/1.1 response from alternative"),
  };
  StaticSocketDataProvider http_data(http_reads, http_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&http_data);

  StaticSocketDataProvider data_refused;
  data_refused.set_connect_data(MockConnect(ASYNC, ERR_CONNECTION_REFUSED));
  session_deps_.socket_factory->AddSocketDataProvider(&data_refused);

  // Set up a QUIC alternative service for server.
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  AlternativeService alternative_service(kProtoQUIC, alternative);
  base::Time expiration = base::Time::Now() + base::Days(1);
  http_server_properties->SetQuicAlternativeService(
      server, NetworkAnonymizationKey(), alternative_service, expiration,
      DefaultSupportedQuicVersions());
  // Mark the QUIC alternative service as broken.
  http_server_properties->MarkAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey());

  HttpRequestInfo request;
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  request.method = "GET";
  request.url = GURL(origin_url);
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  TestCompletionCallback callback;
  NetErrorDetails details;
  EXPECT_FALSE(details.quic_broken);

  trans.Start(&request, callback.callback(), NetLogWithSource());
  trans.PopulateNetErrorDetails(&details);
  EXPECT_TRUE(details.quic_broken);
}

TEST_P(HttpNetworkTransactionTest, IdentifyQuicNotBroken) {
  url::SchemeHostPort server("https", "origin.example.org", 443);
  HostPortPair alternative1("alternative1.example.org", 443);
  HostPortPair alternative2("alternative2.example.org", 443);
  std::string origin_url = "https://origin.example.org:443";
  std::string alternative_url1 = "https://alternative1.example.org:443";
  std::string alternative_url2 = "https://alternative2.example.org:443";

  // Negotiate HTTP/1.1 with alternative1.example.org.
  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  // HTTP/1.1 data for request.
  MockWrite http_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: alternative1.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Content-Type: text/html; charset=iso-8859-1\r\n"
               "Content-Length: 40\r\n\r\n"
               "first HTTP/1.1 response from alternative1"),
  };
  StaticSocketDataProvider http_data(http_reads, http_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&http_data);

  StaticSocketDataProvider data_refused;
  data_refused.set_connect_data(MockConnect(ASYNC, ERR_CONNECTION_REFUSED));
  session_deps_.socket_factory->AddSocketDataProvider(&data_refused);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpServerProperties* http_server_properties =
      session->http_server_properties();

  // Set up two QUIC alternative services for server.
  AlternativeServiceInfoVector alternative_service_info_vector;
  base::Time expiration = base::Time::Now() + base::Days(1);

  AlternativeService alternative_service1(kProtoQUIC, alternative1);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          alternative_service1, expiration,
          session->context().quic_context->params()->supported_versions));
  AlternativeService alternative_service2(kProtoQUIC, alternative2);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          alternative_service2, expiration,
          session->context().quic_context->params()->supported_versions));

  http_server_properties->SetAlternativeServices(
      server, NetworkAnonymizationKey(), alternative_service_info_vector);

  // Mark one of the QUIC alternative service as broken.
  http_server_properties->MarkAlternativeServiceBroken(
      alternative_service1, NetworkAnonymizationKey());
  EXPECT_EQ(2u,
            http_server_properties
                ->GetAlternativeServiceInfos(server, NetworkAnonymizationKey())
                .size());

  HttpRequestInfo request;
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  request.method = "GET";
  request.url = GURL(origin_url);
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  TestCompletionCallback callback;
  NetErrorDetails details;
  EXPECT_FALSE(details.quic_broken);

  trans.Start(&request, callback.callback(), NetLogWithSource());
  trans.PopulateNetErrorDetails(&details);
  EXPECT_FALSE(details.quic_broken);
}

TEST_P(HttpNetworkTransactionTest, MarkBrokenAlternateProtocolAndFallback) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockConnect mock_connect(ASYNC, ERR_CONNECTION_REFUSED);
  StaticSocketDataProvider first_data;
  first_data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&first_data);
  SSLSocketDataProvider ssl_http11(ASYNC, OK);
  ssl_http11.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_http11);

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(ASYNC, OK),
  };
  StaticSocketDataProvider second_data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&second_data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  const url::SchemeHostPort server(request.url);
  // Port must be < 1024, or the header will be ignored (since initial port was
  // port 80 (another restricted port).
  // Port is ignored by MockConnect anyway.
  const AlternativeService alternative_service(kProtoHTTP2, "www.example.org",
                                               666);
  base::Time expiration = base::Time::Now() + base::Days(1);
  http_server_properties->SetHttp2AlternativeService(
      server, NetworkAnonymizationKey(), alternative_service, expiration);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  const AlternativeServiceInfoVector alternative_service_info_vector =
      http_server_properties->GetAlternativeServiceInfos(
          server, NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service,
            alternative_service_info_vector[0].alternative_service());
  EXPECT_TRUE(http_server_properties->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
}

// Ensure that we are not allowed to redirect traffic via an alternate protocol
// to an unrestricted (port >= 1024) when the original traffic was on a
// restricted port (port < 1024).  Ensure that we can redirect in all other
// cases.
TEST_P(HttpNetworkTransactionTest, AlternateProtocolPortRestrictedBlocked) {
  HttpRequestInfo restricted_port_request;
  restricted_port_request.method = "GET";
  restricted_port_request.url = GURL("https://www.example.org:1023/");
  restricted_port_request.load_flags = 0;
  restricted_port_request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockConnect mock_connect(ASYNC, ERR_CONNECTION_REFUSED);
  StaticSocketDataProvider first_data;
  first_data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&first_data);

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(ASYNC, OK),
  };
  StaticSocketDataProvider second_data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&second_data);
  SSLSocketDataProvider ssl_http11(ASYNC, OK);
  ssl_http11.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_http11);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  const int kUnrestrictedAlternatePort = 1024;
  AlternativeService alternative_service(kProtoHTTP2, "www.example.org",
                                         kUnrestrictedAlternatePort);
  base::Time expiration = base::Time::Now() + base::Days(1);
  http_server_properties->SetHttp2AlternativeService(
      url::SchemeHostPort(restricted_port_request.url),
      NetworkAnonymizationKey(), alternative_service, expiration);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;

  int rv = trans.Start(&restricted_port_request, callback.callback(),
                       NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Invalid change to unrestricted port should fail.
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_CONNECTION_REFUSED));
}

// Ensure that we are allowed to redirect traffic via an alternate protocol to
// an unrestricted (port >= 1024) when the original traffic was on a restricted
// port (port < 1024) if we set |enable_user_alternate_protocol_ports|.
TEST_P(HttpNetworkTransactionTest, AlternateProtocolPortRestrictedPermitted) {
  session_deps_.enable_user_alternate_protocol_ports = true;

  HttpRequestInfo restricted_port_request;
  restricted_port_request.method = "GET";
  restricted_port_request.url = GURL("https://www.example.org:1023/");
  restricted_port_request.load_flags = 0;
  restricted_port_request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockConnect mock_connect(ASYNC, ERR_CONNECTION_REFUSED);
  StaticSocketDataProvider first_data;
  first_data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&first_data);

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(ASYNC, OK),
  };
  StaticSocketDataProvider second_data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&second_data);
  SSLSocketDataProvider ssl_http11(ASYNC, OK);
  ssl_http11.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_http11);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  const int kUnrestrictedAlternatePort = 1024;
  AlternativeService alternative_service(kProtoHTTP2, "www.example.org",
                                         kUnrestrictedAlternatePort);
  base::Time expiration = base::Time::Now() + base::Days(1);
  http_server_properties->SetHttp2AlternativeService(
      url::SchemeHostPort(restricted_port_request.url),
      NetworkAnonymizationKey(), alternative_service, expiration);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;

  EXPECT_EQ(ERR_IO_PENDING,
            trans.Start(&restricted_port_request, callback.callback(),
                        NetLogWithSource()));
  // Change to unrestricted port should succeed.
  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

// Ensure that we are not allowed to redirect traffic via an alternate protocol
// to an unrestricted (port >= 1024) when the original traffic was on a
// restricted port (port < 1024).  Ensure that we can redirect in all other
// cases.
TEST_P(HttpNetworkTransactionTest, AlternateProtocolPortRestrictedAllowed) {
  HttpRequestInfo restricted_port_request;
  restricted_port_request.method = "GET";
  restricted_port_request.url = GURL("https://www.example.org:1023/");
  restricted_port_request.load_flags = 0;
  restricted_port_request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockConnect mock_connect(ASYNC, ERR_CONNECTION_REFUSED);
  StaticSocketDataProvider first_data;
  first_data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&first_data);

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(ASYNC, OK),
  };
  StaticSocketDataProvider second_data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&second_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  const int kRestrictedAlternatePort = 80;
  AlternativeService alternative_service(kProtoHTTP2, "www.example.org",
                                         kRestrictedAlternatePort);
  base::Time expiration = base::Time::Now() + base::Days(1);
  http_server_properties->SetHttp2AlternativeService(
      url::SchemeHostPort(restricted_port_request.url),
      NetworkAnonymizationKey(), alternative_service, expiration);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;

  int rv = trans.Start(&restricted_port_request, callback.callback(),
                       NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Valid change to restricted port should pass.
  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

// Ensure that we are not allowed to redirect traffic via an alternate protocol
// to an unrestricted (port >= 1024) when the original traffic was on a
// restricted port (port < 1024).  Ensure that we can redirect in all other
// cases.
TEST_P(HttpNetworkTransactionTest, AlternateProtocolPortUnrestrictedAllowed1) {
  HttpRequestInfo unrestricted_port_request;
  unrestricted_port_request.method = "GET";
  unrestricted_port_request.url = GURL("https://www.example.org:1024/");
  unrestricted_port_request.load_flags = 0;
  unrestricted_port_request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockConnect mock_connect(ASYNC, ERR_CONNECTION_REFUSED);
  StaticSocketDataProvider first_data;
  first_data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&first_data);

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(ASYNC, OK),
  };
  StaticSocketDataProvider second_data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&second_data);
  SSLSocketDataProvider ssl_http11(ASYNC, OK);
  ssl_http11.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_http11);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  const int kRestrictedAlternatePort = 80;
  AlternativeService alternative_service(kProtoHTTP2, "www.example.org",
                                         kRestrictedAlternatePort);
  base::Time expiration = base::Time::Now() + base::Days(1);
  http_server_properties->SetHttp2AlternativeService(
      url::SchemeHostPort(unrestricted_port_request.url),
      NetworkAnonymizationKey(), alternative_service, expiration);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;

  int rv = trans.Start(&unrestricted_port_request, callback.callback(),
                       NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Valid change to restricted port should pass.
  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

// Ensure that we are not allowed to redirect traffic via an alternate protocol
// to an unrestricted (port >= 1024) when the original traffic was on a
// restricted port (port < 1024).  Ensure that we can redirect in all other
// cases.
TEST_P(HttpNetworkTransactionTest, AlternateProtocolPortUnrestrictedAllowed2) {
  HttpRequestInfo unrestricted_port_request;
  unrestricted_port_request.method = "GET";
  unrestricted_port_request.url = GURL("https://www.example.org:1024/");
  unrestricted_port_request.load_flags = 0;
  unrestricted_port_request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockConnect mock_connect(ASYNC, ERR_CONNECTION_REFUSED);
  StaticSocketDataProvider first_data;
  first_data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&first_data);

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(ASYNC, OK),
  };
  StaticSocketDataProvider second_data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&second_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  const int kUnrestrictedAlternatePort = 1025;
  AlternativeService alternative_service(kProtoHTTP2, "www.example.org",
                                         kUnrestrictedAlternatePort);
  base::Time expiration = base::Time::Now() + base::Days(1);
  http_server_properties->SetHttp2AlternativeService(
      url::SchemeHostPort(unrestricted_port_request.url),
      NetworkAnonymizationKey(), alternative_service, expiration);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;

  int rv = trans.Start(&unrestricted_port_request, callback.callback(),
                       NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Valid change to an unrestricted port should pass.
  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

// Ensure that we are not allowed to redirect traffic via an alternate protocol
// to an unsafe port, and that we resume the second HttpStreamFactory::Job once
// the alternate protocol request fails.
TEST_P(HttpNetworkTransactionTest, AlternateProtocolUnsafeBlocked) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // The alternate protocol request will error out before we attempt to connect,
  // so only the standard HTTP request will try to connect.
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(ASYNC, OK),
  };
  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  const int kUnsafePort = 7;
  AlternativeService alternative_service(kProtoHTTP2, "www.example.org",
                                         kUnsafePort);
  base::Time expiration = base::Time::Now() + base::Days(1);
  http_server_properties->SetHttp2AlternativeService(
      url::SchemeHostPort(request.url), NetworkAnonymizationKey(),
      alternative_service, expiration);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // The HTTP request should succeed.
  EXPECT_THAT(cal
```