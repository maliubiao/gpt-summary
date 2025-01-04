Response:
Let's break down the thought process for analyzing this C++ unit test file.

**1. Initial Understanding of the Goal:**

The first step is to recognize that this is a unit test file (`*_unittest.cc`). Unit tests are designed to verify the behavior of individual components of a software system. The filename `spdy_network_transaction_unittest.cc` strongly suggests that the focus is on testing the `SpdyNetworkTransaction` class (or related classes) within Chromium's networking stack. The "spdy" part indicates it likely deals with the SPDY/HTTP2 protocol.

**2. High-Level Overview of the Code:**

Quickly scan the code to identify common patterns in unit tests:

* **`TEST_P` macros:** This signifies parameterized tests. This means the same test logic is run with different input values (defined by the `INSTANTIATE_TEST_SUITE_P` macro, though it's not included here). We need to understand what parameterization is being used (likely different versions or configurations of SPDY/HTTP2).
* **`helper` objects:**  There's a recurring `helper` object (likely `NormalSpdyTransactionHelper`). This suggests a test fixture or helper class to set up common test scenarios.
* **`MockWrite` and `MockRead`:** These are strong indicators of mocking network interactions. The tests are not making real network connections but simulating them using predefined data.
* **`SequencedSocketData`:** This class manages the mocked reads and writes in a specific sequence, essential for deterministic testing of asynchronous network operations.
* **`spdy::SpdySerializedFrame`:**  This indicates direct manipulation of SPDY/HTTP2 frames, confirming the protocol focus.
* **`EXPECT_*` macros:** These are assertion macros that verify expected outcomes.
* **`HttpServerProperties`:** This class is likely related to storing information about HTTP servers, potentially for optimizations or protocol negotiation.
* **Proxy-related keywords:**  "ProxyServer", "ProxyChain", "ProxyConfig" indicate tests involving HTTP proxies.
* **Authentication keywords:** "BasicAuth" suggests testing authentication mechanisms.
* **Error codes:**  `ERR_IO_PENDING`, `ERR_CONNECTION_RESET`, `ERR_HTTP2_PROTOCOL_ERROR` point to testing error handling.

**3. Deeper Dive into Specific Tests:**

Now, examine individual test cases (`TEST_P` blocks) to understand their specific purpose:

* **`HTTP11RequiredProxy`:** This test checks the scenario where a proxy requires HTTP/1.1. It simulates the server indicating this preference and verifies the client falls back to HTTP/1.1.
* **`HTTP11RequiredNestedProxySecondProxyRetry`:** This expands on the previous test by introducing nested proxies and simulating the second proxy requiring HTTP/1.1. It also checks retry behavior.
* **`ProxyConnect`:** This tests a basic successful connection through an HTTP proxy using the `CONNECT` method.
* **`DirectConnectProxyReconnect`:** This is a more complex scenario testing what happens when a direct connection exists and then a proxy connection is attempted to the same destination. It checks if the existing direct connection is handled correctly.
* **`VerifyRetryOnConnectionReset`:** This focuses on testing the client's ability to retry a request if the connection is unexpectedly closed (RST). It has variations to test different timing scenarios.
* **`SpdyBasicAuth`:**  This verifies that Basic HTTP authentication works correctly over a SPDY/HTTP2 connection.
* **`ResponseHeadersTwice`:** This tests error handling for receiving multiple sets of HTTP headers for a single response (an HTTP/2 protocol violation).
* **`SyncReplyDataAfterTrailers`:** This also tests an HTTP/2 protocol violation: sending data after trailing headers.
* **`RetryAfterRefused`:** This tests the retry mechanism when a server explicitly refuses a stream (`REFUSED_STREAM`).
* **`OutOfOrderHeaders`:**  This is a more intricate test exploring how the client handles situations where HTTP/2 streams are created in a different order than their priority would suggest.

**4. Identifying Functionality and Relationships to JavaScript:**

After understanding the individual tests, synthesize the overall functionality being tested:

* **Core SPDY/HTTP2 transaction handling:**  Establishing connections, sending requests, receiving responses, handling data.
* **Proxy support:**  Connecting through various types of proxies, including those requiring HTTP/1.1.
* **Error handling:**  Dealing with connection resets, refused streams, and HTTP/2 protocol errors.
* **Authentication:** Implementing Basic HTTP authentication.
* **Priority handling:**  Ensuring requests are sent and processed according to their priority.

Relating this to JavaScript:  While this C++ code doesn't directly execute JavaScript, it's a foundational part of Chromium's networking stack that **enables** JavaScript to perform network requests. The `fetch` API or `XMLHttpRequest` in JavaScript rely on this underlying C++ code to handle the complexities of protocols like SPDY/HTTP2.

**5. Logical Reasoning (Input/Output Examples):**

For simpler tests, like `ProxyConnect`, it's easier to give concrete examples:

* **Input:** A JavaScript `fetch` request to `https://www.example.org` with a proxy configured.
* **Output (Internal to C++):** The `SpdyNetworkTransaction` would:
    1. Initiate a `CONNECT` request to the proxy.
    2. Upon successful `CONNECT`, establish a tunneled SPDY/HTTP2 connection.
    3. Send the actual request over the tunneled connection.
    4. Receive and process the response.
    5. Make the response data available to the JavaScript `fetch` promise.

**6. Common User/Programming Errors:**

Think about how misconfigurations or incorrect usage might lead to these code paths being executed:

* **Incorrect proxy settings:** Users entering wrong proxy details or scripts misconfiguring proxies. This could lead to scenarios tested in the proxy-related tests.
* **Server-side issues:**  A server unexpectedly closing connections (leading to `VerifyRetryOnConnectionReset`).
* **Protocol mismatches:**  A server incorrectly implementing HTTP/2, leading to protocol errors (`ResponseHeadersTwice`, `SyncReplyDataAfterTrailers`).
* **Authentication problems:**  Users providing wrong credentials, leading to the flow in `SpdyBasicAuth`.

**7. User Operation to Reach the Code:**

Trace back from the C++ code to user actions:

1. **User types a URL in the address bar or a website initiates a `fetch` request.**
2. **Chromium's network stack determines the appropriate protocol (potentially negotiating SPDY/HTTP2).**
3. **If a proxy is configured, the `ProxyResolutionService` is used.**
4. **The `SpdyNetworkTransaction` is created to handle the request.**
5. **Mocked data (in tests) or real network data is processed by `SpdyNetworkTransaction`.**
6. **Errors or specific server responses (like 401 for authentication) might trigger specific code paths within `SpdyNetworkTransaction` and the tested scenarios.**

**8. Summarizing Functionality (Part 7 of 12):**

Based on the individual test analysis, the functionality of this part of the test suite is primarily focused on:

* **Testing proxy interactions:** This includes basic proxy connections, proxies requiring HTTP/1.1, and nested proxy scenarios.
* **Verifying retry mechanisms:**  Specifically, retrying after connection resets and after receiving a `REFUSED_STREAM` error.
* **Testing Basic HTTP authentication over SPDY/HTTP2.**
* **Validating error handling for HTTP/2 protocol violations related to header and data frame sequencing.**

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on individual frame construction. It's more important to understand the *higher-level scenarios* being tested (proxying, retries, authentication).
* I needed to explicitly connect the C++ testing to the *user-facing* aspects of web browsing (typing URLs, JavaScript requests).
* Recognizing the "part 7 of 12" constraint helps to narrow down the scope of this specific file within the larger test suite. It suggests that other parts likely cover different aspects of `SpdyNetworkTransaction` or related classes.
这个C++源代码文件 `net/spdy/spdy_network_transaction_unittest.cc` 是 Chromium 网络栈中用于测试 `SpdyNetworkTransaction` 类的单元测试文件。`SpdyNetworkTransaction` 负责处理基于 SPDY（现在主要是 HTTP/2 和 HTTP/3）协议的网络事务。

**这个文件的主要功能可以归纳为：**

1. **测试 `SpdyNetworkTransaction` 在各种网络场景下的行为:**  它模拟各种网络条件和服务器响应，以验证 `SpdyNetworkTransaction` 是否按照预期工作。

2. **验证与代理服务器的交互:**  测试通过各种类型的代理服务器（如 HTTPS 代理）建立连接，包括处理代理服务器要求使用 HTTP/1.1 的情况，以及嵌套代理的情况。

3. **测试连接重试机制:**  验证在连接被重置（TCP RST）或被服务器拒绝（REFUSED_STREAM）后，`SpdyNetworkTransaction` 是否能正确地重试请求。

4. **测试 HTTP 认证机制:**  验证在 SPDY/HTTP2 连接上使用 Basic 认证是否正常工作。

5. **测试 HTTP/2 协议的特定行为和错误处理:**  例如，测试接收到错误的 HEADERS 和 DATA 帧序列时是否能正确地处理并返回错误。

6. **测试请求的优先级处理:**  验证 `SpdyNetworkTransaction` 是否能按照请求的优先级顺序发送和处理请求。

**与 JavaScript 的功能关系：**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它所测试的功能是 JavaScript 中网络请求（例如使用 `fetch` API 或 `XMLHttpRequest`）的基础。

* **`fetch` API 和 `XMLHttpRequest`:** 当 JavaScript 代码发起一个网络请求时，Chromium 的网络栈会处理这个请求。如果目标服务器支持 HTTP/2 或 HTTP/3，`SpdyNetworkTransaction` 就会被用来处理这个请求。这个文件中的测试确保了在各种复杂场景下，由 JavaScript 发起的请求能够被正确地处理。
* **代理配置:** JavaScript 可以通过浏览器的代理设置来配置代理服务器。这个文件中的测试验证了当用户配置了代理服务器时，网络栈能够正确地通过这些代理服务器进行通信。
* **身份验证:** JavaScript 可以使用 `Authorization` 请求头来发送身份验证信息。这个文件中的测试验证了当 JavaScript 代码需要进行 Basic 认证时，网络栈能够正确地处理认证流程。

**举例说明（与 JavaScript 的关系）：**

假设一个 JavaScript 应用使用 `fetch` API 向一个 HTTPS 网站发起请求，并且用户配置了一个 HTTPS 代理服务器。

1. **假设输入（JavaScript 代码）：**
   ```javascript
   fetch('https://www.example.org/data')
     .then(response => response.json())
     .then(data => console.log(data));
   ```
   同时，用户的浏览器配置了一个 HTTPS 代理服务器 `proxy.example.com:8080`。

2. **逻辑推理（C++ 代码中的 `HTTP11RequiredProxy` 测试）：**
   如果代理服务器 `proxy.example.com` 响应了一个指示需要使用 HTTP/1.1 的消息（例如，在 `CONNECT` 请求的响应中或在后续的请求中），那么 `SpdyNetworkTransaction` 需要能够回退到 HTTP/1.1。`HTTP11RequiredProxy` 测试就模拟了这种情况。

3. **输出（C++ 代码中的行为）：**
   * `SpdyNetworkTransaction` 首先尝试使用 HTTP/2 连接到代理服务器。
   * 如果代理服务器指示需要 HTTP/1.1，`SpdyNetworkTransaction` 会关闭当前的连接。
   * `SpdyNetworkTransaction` 会重新建立一个 HTTP/1.1 连接到代理服务器。
   * 通过 HTTP/1.1 连接发送 `CONNECT` 请求到目标服务器 `www.example.org`。
   * 建立隧道后，发送实际的 HTTP/1.1 请求 `/data`。
   * 接收来自目标服务器的 HTTP/1.1 响应，并将数据传递回 JavaScript。

**假设输入与输出（更具体的 C++ 测试）：**

**测试用例：`HTTP11RequiredProxy`**

* **假设输入:**
    * 客户端发起一个到 `https://www.example.org` 的请求，配置了一个 HTTPS 代理服务器 `proxy1.test:70`。
    * 模拟代理服务器 `proxy1.test:70` 最初尝试使用 HTTP/2 连接，然后发送一个指示需要 HTTP/1.1 的响应。
* **输出:**
    * `SpdyNetworkTransaction` 成功建立一个到代理服务器的 HTTP/1.1 连接。
    * `HttpServerProperties` 中记录了 `proxy1.test:70` 需要使用 HTTP/1.1。
    * 请求最终通过 HTTP/1.1 成功完成。
    * `response->was_fetched_via_spdy` 为 `false`，`response->connection_info` 为 `HttpConnectionInfo::kHTTP1_1`。

**用户或编程常见的使用错误举例：**

* **代理配置错误：** 用户在浏览器中配置了错误的代理服务器地址或端口。这可能导致连接无法建立，或者出现认证错误，这些场景在代理相关的测试用例中会被覆盖。例如，如果用户错误地配置了一个需要认证的代理，但没有提供用户名和密码，那么认证相关的测试用例会验证 `SpdyNetworkTransaction` 是否正确处理了 407 Proxy Authentication Required 响应。
* **服务器配置错误：**  服务器错误地实现了 HTTP/2 协议，例如发送了不符合协议规范的 HEADERS 或 DATA 帧序列。`ResponseHeadersTwice` 和 `SyncReplyDataAfterTrailers` 等测试用例就是为了验证在这种情况下 `SpdyNetworkTransaction` 能否正确地处理错误。
* **代码中错误地处理身份验证：**  如果 JavaScript 代码尝试使用 Basic 认证，但提供的用户名或密码不正确，`SpdyBasicAuth` 测试用例验证了 `SpdyNetworkTransaction` 能否正确处理 401 Authentication Required 响应，并触发身份验证流程。

**用户操作如何一步步地到达这里（作为调试线索）：**

1. **用户在 Chrome 浏览器中输入一个 HTTPS URL，例如 `https://www.example.org`，并且配置了一个代理服务器。**
2. **Chrome 的网络栈开始解析 URL，并查询代理设置。**
3. **`ProxyResolutionService` 确定需要使用配置的代理服务器。**
4. **`HttpNetworkTransaction` 被创建以处理这个请求。**
5. **`SpdySessionPool` 尝试查找或创建一个到代理服务器的 SPDY/HTTP2 会话。**
6. **如果需要建立新的连接，`SpdyNetworkTransaction` 开始与代理服务器进行 TLS 握手和 ALPN 协商。**
7. **如果代理服务器指示需要使用 HTTP/1.1 (就像 `HTTP11RequiredProxy` 测试中模拟的那样)，`SpdyNetworkTransaction` 会处理这个指示。**
8. **调试时，可以在网络栈的关键点设置断点，例如在 `SpdyNetworkTransaction::Start()`，或者在处理 TLS 握手和 ALPN 协商的代码中，以观察请求的处理流程。**
9. **查看网络日志 (chrome://net-internals/#events) 可以提供更详细的连接和请求信息，帮助定位问题。**

**作为第 7 部分（共 12 部分）的功能归纳：**

考虑到这是一个单元测试文件的第 7 部分，并且之前的分析，可以推断这部分测试可能专注于 `SpdyNetworkTransaction` 在特定场景下的核心功能，特别是：

* **代理交互的核心逻辑：**  建立代理连接，处理代理的需求（例如 HTTP/1.1 回退）。
* **基本的重试机制：**  在连接级别或流级别出现错误时进行重试。
* **基本的身份验证流程：**  处理需要身份验证的请求。
* **HTTP/2 协议基本错误的检测：**  验证能否识别和处理简单的协议违规。

总的来说，`net/spdy/spdy_network_transaction_unittest.cc` 的这部分旨在确保 `SpdyNetworkTransaction` 在涉及代理、连接错误、身份验证以及基本 HTTP/2 协议一致性方面能够可靠地工作，从而为 Chromium 的网络功能提供坚实的基础。

Prompt: 
```
这是目录为net/spdy/spdy_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共12部分，请归纳一下它的功能

"""
LConfig.
  ssl_provider1->next_protos_expected_in_ssl_config =
      NextProtoVector{kProtoHTTP11};
  // Force HTTP/1.1.
  ssl_provider1->next_proto = kProtoHTTP11;
  helper.AddDataWithSSLSocketDataProvider(&data1, std::move(ssl_provider1));

  // A third and fourth socket are needed for the connection to the second hop
  // and for the tunnelled GET request.
  auto ssl_provider2 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl_provider2->next_protos_expected_in_ssl_config =
      NextProtoVector{kProtoHTTP2, kProtoHTTP11};
  helper.session_deps()->socket_factory->AddSSLSocketDataProvider(
      ssl_provider2.get());
  auto ssl_provider3 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  helper.session_deps()->socket_factory->AddSSLSocketDataProvider(
      ssl_provider3.get());

  HttpServerProperties* http_server_properties =
      helper.session()->spdy_session_pool()->http_server_properties();
  url::SchemeHostPort proxy_scheme_host_port(
      url::kHttpsScheme, kProxyServer1.host_port_pair().host(),
      kProxyServer1.host_port_pair().port());
  EXPECT_FALSE(http_server_properties->RequiresHTTP11(
      proxy_scheme_host_port, NetworkAnonymizationKey()));

  helper.RunPreTestSetup();
  helper.StartDefaultTest();
  helper.FinishDefaultTestWithoutVerification();
  helper.VerifyDataConsumed();
  EXPECT_TRUE(http_server_properties->RequiresHTTP11(
      proxy_scheme_host_port, NetworkAnonymizationKey()));

  const HttpResponseInfo* response = helper.trans()->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_EQ(HttpConnectionInfo::kHTTP1_1, response->connection_info);
  EXPECT_FALSE(response->was_alpn_negotiated);
  EXPECT_TRUE(request_.url.SchemeIs("https"));
  EXPECT_EQ("127.0.0.1", response->remote_endpoint.ToStringWithoutPort());
  EXPECT_EQ(70, response->remote_endpoint.port());
  std::string response_data;
  ASSERT_THAT(ReadTransaction(helper.trans(), &response_data), IsOk());
  EXPECT_EQ("hello", response_data);
}

// Same as above except for nested proxies where HTTP_1_1_REQUIRED is received
// from the second proxy in the chain.
// TODO(crbug.com/365771838): Add tests for non-ip protection nested proxy
// chains if support is enabled for all builds.
TEST_P(SpdyNetworkTransactionTest, HTTP11RequiredNestedProxySecondProxyRetry) {
  request_.method = "GET";

  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 70)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 71)};
  const ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({{kProxyServer1, kProxyServer2}});

  ProxyList proxy_list;
  proxy_list.AddProxyChain(kNestedProxyChain);
  ProxyConfig proxy_config = ProxyConfig::CreateForTesting(proxy_list);

  auto session_deps = std::make_unique<SpdySessionDependencies>(
      ConfiguredProxyResolutionService::CreateFixedForTest(
          ProxyConfigWithAnnotation(proxy_config,
                                    TRAFFIC_ANNOTATION_FOR_TESTS)));
  // Do not force SPDY so that second socket can negotiate HTTP/1.1.
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                     std::move(session_deps));

  // CONNECT to proxy2.test:71 via SPDY.
  spdy::SpdySerializedFrame proxy2_connect(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      kProxyServer2.host_port_pair()));

  spdy::SpdySerializedFrame proxy2_connect_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  // Need to use a new `SpdyTestUtil()` so that the stream parent ID of this
  // request is calculated correctly.
  SpdyTestUtil new_spdy_util;
  // HTTP/2 endpoint CONNECT rejected with HTTP_1_1_REQUIRED.
  spdy::SpdySerializedFrame endpoint_connect(new_spdy_util.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));
  spdy::SpdySerializedFrame server_rst(new_spdy_util.ConstructSpdyRstStream(
      1, spdy::ERROR_CODE_HTTP_1_1_REQUIRED));
  spdy::SpdySerializedFrame client_rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));

  // Since this request and response are sent over the tunnel established
  // previously, from a socket-perspective these need to be wrapped as data
  // frames.
  spdy::SpdySerializedFrame wrapped_endpoint_connect(
      new_spdy_util.ConstructSpdyDataFrame(1, endpoint_connect, false));
  spdy::SpdySerializedFrame wrapped_server_rst(
      new_spdy_util.ConstructSpdyDataFrame(1, server_rst, /*fin=*/true));

  MockWrite writes0[] = {
      CreateMockWrite(proxy2_connect, 0),
      CreateMockWrite(wrapped_endpoint_connect, 2),
      CreateMockWrite(client_rst, 5),
  };

  MockRead reads0[] = {
      CreateMockRead(proxy2_connect_resp, 1),
      CreateMockRead(wrapped_server_rst, 3),
      MockRead(ASYNC, 0, 4),
  };

  SequencedSocketData data0(reads0, writes0);

  auto ssl_provider0 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  // Expect HTTP/2 protocols too in SSLConfig.
  ssl_provider0->next_protos_expected_in_ssl_config =
      NextProtoVector{kProtoHTTP2, kProtoHTTP11};
  ssl_provider0->next_proto = kProtoHTTP2;
  helper.session_deps()->socket_factory->AddSSLSocketDataProvider(
      ssl_provider0.get());

  auto ssl_provider1 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl_provider1->next_protos_expected_in_ssl_config =
      NextProtoVector{kProtoHTTP2, kProtoHTTP11};
  // Force SPDY.
  ssl_provider1->next_proto = kProtoHTTP2;
  helper.AddDataWithSSLSocketDataProvider(&data0, std::move(ssl_provider1));

  // Second socket: retry using HTTP/1.1.
  MockWrite writes1[] = {
      MockWrite(ASYNC, 0,
                "CONNECT proxy2.test:71 HTTP/1.1\r\n"
                "Host: proxy2.test:71\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
      MockWrite(ASYNC, 2,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
      MockWrite(ASYNC, 4,
                "GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead reads1[] = {
      MockRead(ASYNC, 1, "HTTP/1.1 200 OK\r\n\r\n"),
      MockRead(ASYNC, 3, "HTTP/1.1 200 OK\r\n\r\n"),
      MockRead(ASYNC, 5,
               "HTTP/1.1 200 OK\r\n"
               "Content-Length: 5\r\n\r\n"
               "hello"),
  };
  SequencedSocketData data1(reads1, writes1);

  // Create a new SSLSocketDataProvider for the new connection to the first
  // proxy.
  auto ssl_provider2 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  // Force HTTP/1.1 for the reconnection to the first proxy for simplicity.
  ssl_provider2->next_protos_expected_in_ssl_config =
      NextProtoVector{kProtoHTTP2, kProtoHTTP11};
  ssl_provider2->next_proto = kProtoHTTP11;
  helper.AddDataWithSSLSocketDataProvider(&data1, std::move(ssl_provider2));

  // Create a new SSLSocketDataProvider for the new connection to the second
  // proxy.
  auto ssl_provider3 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  // Expect only HTTP/1.1 protocol in the SSLConfig for the second proxy.
  ssl_provider3->next_protos_expected_in_ssl_config =
      NextProtoVector{kProtoHTTP11};
  // Force HTTP/1.1.
  ssl_provider3->next_proto = kProtoHTTP11;
  helper.session_deps()->socket_factory->AddSSLSocketDataProvider(
      ssl_provider3.get());

  // One final SSL provider for the connection through the proxy.
  auto ssl_provider4 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  helper.session_deps()->socket_factory->AddSSLSocketDataProvider(
      ssl_provider4.get());

  HttpServerProperties* http_server_properties =
      helper.session()->spdy_session_pool()->http_server_properties();
  url::SchemeHostPort proxy_scheme_host_port(
      url::kHttpsScheme, kProxyServer2.host_port_pair().host(),
      kProxyServer2.host_port_pair().port());
  EXPECT_FALSE(http_server_properties->RequiresHTTP11(
      proxy_scheme_host_port, NetworkAnonymizationKey()));

  helper.RunPreTestSetup();
  helper.StartDefaultTest();
  helper.FinishDefaultTestWithoutVerification();
  helper.VerifyDataConsumed();
  EXPECT_TRUE(http_server_properties->RequiresHTTP11(
      proxy_scheme_host_port, NetworkAnonymizationKey()));

  const HttpResponseInfo* response = helper.trans()->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_EQ(HttpConnectionInfo::kHTTP1_1, response->connection_info);
  EXPECT_FALSE(response->was_alpn_negotiated);
  EXPECT_TRUE(request_.url.SchemeIs("https"));
  EXPECT_EQ("127.0.0.1", response->remote_endpoint.ToStringWithoutPort());
  EXPECT_EQ(70, response->remote_endpoint.port());
  std::string response_data;
  ASSERT_THAT(ReadTransaction(helper.trans(), &response_data), IsOk());
  EXPECT_EQ("hello", response_data);
}

// Test to make sure we can correctly connect through a proxy.
TEST_P(SpdyNetworkTransactionTest, ProxyConnect) {
  auto session_deps = std::make_unique<SpdySessionDependencies>(
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "PROXY myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS));
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                     std::move(session_deps));
  helper.RunPreTestSetup();
  HttpNetworkTransaction* trans = helper.trans();

  const char kConnect443[] = {
      "CONNECT www.example.org:443 HTTP/1.1\r\n"
      "Host: www.example.org:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n\r\n"};
  const char kHTTP200[] = {"HTTP/1.1 200 OK\r\n\r\n"};
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));

  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, kConnect443, std::size(kConnect443) - 1, 0),
      CreateMockWrite(req, 2),
  };
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, kHTTP200, std::size(kHTTP200) - 1, 1),
      CreateMockRead(resp, 3),
      CreateMockRead(body, 4),
      MockRead(ASYNC, nullptr, 0, 5),
  };
  SequencedSocketData data(reads, writes);

  helper.AddData(&data);
  TestCompletionCallback callback;

  int rv = trans->Start(&request_, callback.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_EQ(0, rv);

  // Verify the response headers.
  HttpResponseInfo response = *trans->GetResponseInfo();
  ASSERT_TRUE(response.headers);
  EXPECT_EQ("HTTP/1.1 200", response.headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(trans, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
  helper.VerifyDataConsumed();
}

// Test to make sure we can correctly connect through a proxy to
// www.example.org, if there already exists a direct spdy connection to
// www.example.org. See https://crbug.com/49874.
TEST_P(SpdyNetworkTransactionTest, DirectConnectProxyReconnect) {
  // Use a proxy service which returns a proxy fallback list from DIRECT to
  // myproxy:70. For this test there will be no fallback, so it is equivalent
  // to simply DIRECT. The reason for appending the second proxy is to verify
  // that the session pool key used does is just "DIRECT".
  auto session_deps = std::make_unique<SpdySessionDependencies>(
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "DIRECT; PROXY myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS));
  // When setting up the first transaction, we store the SpdySessionPool so that
  // we can use the same pool in the second transaction.
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                     std::move(session_deps));

  SpdySessionPool* spdy_session_pool = helper.session()->spdy_session_pool();
  helper.RunPreTestSetup();

  // Construct and send a simple GET request.
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 3),  // Force a pause
  };
  SequencedSocketData data(reads, writes);
  helper.AddData(&data);
  HttpNetworkTransaction* trans = helper.trans();

  TestCompletionCallback callback;
  TransactionHelperResult out;
  out.rv = trans->Start(&request_, callback.callback(), log_);

  EXPECT_EQ(out.rv, ERR_IO_PENDING);
  out.rv = callback.WaitForResult();
  EXPECT_EQ(out.rv, OK);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  EXPECT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);
  out.rv = ReadTransaction(trans, &out.response_data);
  EXPECT_THAT(out.rv, IsOk());
  out.status_line = response->headers->GetStatusLine();
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);

  // Check that the SpdySession is still in the SpdySessionPool.
  SpdySessionKey session_pool_key_direct(
      host_port_pair_, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
      SessionUsage::kDestination, SocketTag(), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow,
      /*disable_cert_verification_network_fetches=*/false);
  EXPECT_TRUE(HasSpdySession(spdy_session_pool, session_pool_key_direct));
  SpdySessionKey session_pool_key_proxy(
      host_port_pair_, PRIVACY_MODE_DISABLED,
      ProxyUriToProxyChain("www.foo.com", ProxyServer::SCHEME_HTTP),
      SessionUsage::kDestination, SocketTag(), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow,
      /*disable_cert_verification_network_fetches=*/false);
  EXPECT_FALSE(HasSpdySession(spdy_session_pool, session_pool_key_proxy));

  // New SpdyTestUtil instance for the session that will be used for the
  // proxy connection.
  SpdyTestUtil spdy_util_2(/*use_priority_header=*/true);

  // Set up data for the proxy connection.
  const char kConnect443[] = {
      "CONNECT www.example.org:443 HTTP/1.1\r\n"
      "Host: www.example.org:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n\r\n"};
  const char kHTTP200[] = {"HTTP/1.1 200 OK\r\n\r\n"};
  spdy::SpdySerializedFrame req2(
      spdy_util_2.ConstructSpdyGet(kPushedUrl, 1, LOWEST));
  spdy::SpdySerializedFrame resp2(
      spdy_util_2.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body2(spdy_util_2.ConstructSpdyDataFrame(1, true));

  MockWrite writes2[] = {
      MockWrite(SYNCHRONOUS, kConnect443, std::size(kConnect443) - 1, 0),
      CreateMockWrite(req2, 2),
  };
  MockRead reads2[] = {
      MockRead(SYNCHRONOUS, kHTTP200, std::size(kHTTP200) - 1, 1),
      CreateMockRead(resp2, 3), CreateMockRead(body2, 4),
      MockRead(ASYNC, 0, 5)  // EOF
  };

  SequencedSocketData data_proxy(reads2, writes2);

  // Create another request to www.example.org, but this time through a proxy.
  request_.method = "GET";
  request_.url = GURL(kPushedUrl);
  auto session_deps_proxy = std::make_unique<SpdySessionDependencies>(
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "PROXY myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS));
  NormalSpdyTransactionHelper helper_proxy(request_, DEFAULT_PRIORITY, log_,
                                           std::move(session_deps_proxy));

  helper_proxy.RunPreTestSetup();
  helper_proxy.AddData(&data_proxy);

  HttpNetworkTransaction* trans_proxy = helper_proxy.trans();
  TestCompletionCallback callback_proxy;
  int rv = trans_proxy->Start(&request_, callback_proxy.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback_proxy.WaitForResult();
  EXPECT_EQ(0, rv);

  HttpResponseInfo response_proxy = *trans_proxy->GetResponseInfo();
  ASSERT_TRUE(response_proxy.headers);
  EXPECT_EQ("HTTP/1.1 200", response_proxy.headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(trans_proxy, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);

  helper_proxy.VerifyDataConsumed();
}

// When we get a TCP-level RST, we need to retry a HttpNetworkTransaction
// on a new connection, if the connection was previously known to be good.
// This can happen when a server reboots without saying goodbye, or when
// we're behind a NAT that masked the RST.
TEST_P(SpdyNetworkTransactionTest, VerifyRetryOnConnectionReset) {
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1),
      CreateMockRead(body, 2),
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      MockRead(ASYNC, ERR_CONNECTION_RESET, 4),
  };

  MockRead reads2[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  // In all cases the connection will be reset before req3 can be
  // dispatched, destroying both streams.
  spdy_util_.UpdateWithStreamDestruction(1);
  spdy::SpdySerializedFrame req3(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOWEST));
  MockWrite writes1[] = {CreateMockWrite(req, 0), CreateMockWrite(req3, 5)};
  MockWrite writes2[] = {CreateMockWrite(req, 0)};

  // This test has a couple of variants.
  enum : size_t {
    // Induce the RST while waiting for our transaction to send.
    VARIANT_RST_DURING_SEND_COMPLETION = 0,
    // Induce the RST while waiting for our transaction to read.
    // In this case, the send completed - everything copied into the SNDBUF.
    VARIANT_RST_DURING_READ_COMPLETION = 1
  };

  for (size_t variant = VARIANT_RST_DURING_SEND_COMPLETION;
       variant <= VARIANT_RST_DURING_READ_COMPLETION; ++variant) {
    SequencedSocketData data1(reads,
                              base::make_span(writes1).first(1u + variant));

    SequencedSocketData data2(reads2, writes2);

    NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                       nullptr);
    helper.AddData(&data1);
    helper.AddData(&data2);
    helper.RunPreTestSetup();

    for (int i = 0; i < 2; ++i) {
      HttpNetworkTransaction trans(DEFAULT_PRIORITY, helper.session());

      TestCompletionCallback callback;
      int rv = trans.Start(&request_, callback.callback(), log_);
      EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
      // On the second transaction, we trigger the RST.
      if (i == 1) {
        if (variant == VARIANT_RST_DURING_READ_COMPLETION) {
          // Writes to the socket complete asynchronously on SPDY by running
          // through the message loop.  Complete the write here.
          base::RunLoop().RunUntilIdle();
        }

        // Now schedule the ERR_CONNECTION_RESET.
        data1.Resume();
      }
      rv = callback.WaitForResult();
      EXPECT_THAT(rv, IsOk());

      const HttpResponseInfo* response = trans.GetResponseInfo();
      ASSERT_TRUE(response);
      EXPECT_TRUE(response->headers);
      EXPECT_TRUE(response->was_fetched_via_spdy);
      std::string response_data;
      rv = ReadTransaction(&trans, &response_data);
      EXPECT_THAT(rv, IsOk());
      EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
      EXPECT_EQ("hello!", response_data);
      base::RunLoop().RunUntilIdle();
    }

    helper.VerifyDataConsumed();
    base::RunLoop().RunUntilIdle();
  }
}

// Tests that Basic authentication works over SPDY
TEST_P(SpdyNetworkTransactionTest, SpdyBasicAuth) {
  // The first request will be a bare GET, the second request will be a
  // GET with an Authorization header.
  spdy::SpdySerializedFrame req_get(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  // Will be refused for lack of auth.
  spdy_util_.UpdateWithStreamDestruction(1);
  const char* const kExtraAuthorizationHeaders[] = {"authorization",
                                                    "Basic Zm9vOmJhcg=="};
  spdy::SpdySerializedFrame req_get_authorization(spdy_util_.ConstructSpdyGet(
      kExtraAuthorizationHeaders, std::size(kExtraAuthorizationHeaders) / 2, 3,
      LOWEST));
  MockWrite spdy_writes[] = {
      CreateMockWrite(req_get, 0),
      CreateMockWrite(req_get_authorization, 3),
  };

  // The first response is a 401 authentication challenge, and the second
  // response will be a 200 response since the second request includes a valid
  // Authorization header.
  const char* const kExtraAuthenticationHeaders[] = {"www-authenticate",
                                                     "Basic realm=\"MyRealm\""};
  spdy::SpdySerializedFrame resp_authentication(
      spdy_util_.ConstructSpdyReplyError(
          "401", kExtraAuthenticationHeaders,
          std::size(kExtraAuthenticationHeaders) / 2, 1));
  spdy::SpdySerializedFrame body_authentication(
      spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame resp_data(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body_data(
      spdy_util_.ConstructSpdyDataFrame(3, true));

  MockRead spdy_reads[] = {
      CreateMockRead(resp_authentication, 1),
      CreateMockRead(body_authentication, 2, SYNCHRONOUS),
      CreateMockRead(resp_data, 4),
      CreateMockRead(body_data, 5),
      MockRead(ASYNC, 0, 6),
  };

  SequencedSocketData data(spdy_reads, spdy_writes);
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);

  helper.RunPreTestSetup();
  helper.AddData(&data);
  helper.StartDefaultTest();
  EXPECT_THAT(helper.output().rv, IsError(ERR_IO_PENDING));

  helper.WaitForCallbackToComplete();
  EXPECT_THAT(helper.output().rv, IsOk());

  // Make sure the response has an auth challenge.
  HttpNetworkTransaction* trans = helper.trans();
  const HttpResponseInfo* const response_start = trans->GetResponseInfo();
  ASSERT_TRUE(response_start);
  ASSERT_TRUE(response_start->headers);
  EXPECT_EQ(401, response_start->headers->response_code());
  EXPECT_TRUE(response_start->was_fetched_via_spdy);
  const std::optional<AuthChallengeInfo>& auth_challenge =
      response_start->auth_challenge;
  ASSERT_TRUE(auth_challenge);
  EXPECT_FALSE(auth_challenge->is_proxy);
  EXPECT_EQ(kBasicAuthScheme, auth_challenge->scheme);
  EXPECT_EQ("MyRealm", auth_challenge->realm);

  // Restart with a username/password.
  AuthCredentials credentials(u"foo", u"bar");
  TestCompletionCallback callback_restart;
  const int rv_restart =
      trans->RestartWithAuth(credentials, callback_restart.callback());
  EXPECT_THAT(rv_restart, IsError(ERR_IO_PENDING));
  const int rv_restart_complete = callback_restart.WaitForResult();
  EXPECT_THAT(rv_restart_complete, IsOk());
  // TODO(cbentzel): This is actually the same response object as before, but
  // data has changed.
  const HttpResponseInfo* const response_restart = trans->GetResponseInfo();
  ASSERT_TRUE(response_restart);
  ASSERT_TRUE(response_restart->headers);
  EXPECT_EQ(200, response_restart->headers->response_code());
  EXPECT_FALSE(response_restart->auth_challenge);
}

TEST_P(SpdyNetworkTransactionTest, ResponseHeadersTwice) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_PROTOCOL_ERROR));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
      CreateMockWrite(rst, 4),
  };

  spdy::SpdySerializedFrame stream1_reply(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  quiche::HttpHeaderBlock late_headers;
  late_headers["hello"] = "bye";
  spdy::SpdySerializedFrame stream1_headers(
      spdy_util_.ConstructSpdyResponseHeaders(1, std::move(late_headers),
                                              false));
  spdy::SpdySerializedFrame stream1_body(
      spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(stream1_reply, 1), CreateMockRead(stream1_headers, 2),
      CreateMockRead(stream1_body, 3), MockRead(ASYNC, 0, 5)  // EOF
  };

  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_HTTP2_PROTOCOL_ERROR));
}

// Tests that receiving HEADERS, DATA, HEADERS, and DATA in that sequence will
// trigger a ERR_HTTP2_PROTOCOL_ERROR because trailing HEADERS must not be
// followed by any DATA frames.
TEST_P(SpdyNetworkTransactionTest, SyncReplyDataAfterTrailers) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_PROTOCOL_ERROR));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
      CreateMockWrite(rst, 5),
  };

  spdy::SpdySerializedFrame stream1_reply(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame stream1_body(
      spdy_util_.ConstructSpdyDataFrame(1, false));

  quiche::HttpHeaderBlock late_headers;
  late_headers["hello"] = "bye";
  spdy::SpdySerializedFrame stream1_headers(
      spdy_util_.ConstructSpdyResponseHeaders(1, std::move(late_headers),
                                              false));
  spdy::SpdySerializedFrame stream1_body2(
      spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(stream1_reply, 1), CreateMockRead(stream1_body, 2),
      CreateMockRead(stream1_headers, 3), CreateMockRead(stream1_body2, 4),
      MockRead(ASYNC, 0, 6)  // EOF
  };

  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_HTTP2_PROTOCOL_ERROR));
}

TEST_P(SpdyNetworkTransactionTest, RetryAfterRefused) {
  // Construct the request.
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  // Will be destroyed by the RST before stream 3 starts.
  spdy_util_.UpdateWithStreamDestruction(1);
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOWEST));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
      CreateMockWrite(req2, 2),
  };

  spdy::SpdySerializedFrame refused(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_REFUSED_STREAM));
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(3, true));
  MockRead reads[] = {
      CreateMockRead(refused, 1), CreateMockRead(resp, 3),
      CreateMockRead(body, 4), MockRead(ASYNC, 0, 5)  // EOF
  };

  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);

  helper.RunPreTestSetup();
  helper.AddData(&data);

  HttpNetworkTransaction* trans = helper.trans();

  // Start the transaction with basic parameters.
  TestCompletionCallback callback;
  int rv = trans->Start(&request_, callback.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  // Finish async network reads.
  base::RunLoop().RunUntilIdle();

  // Verify that we consumed all test data.
  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());

  // Verify the response headers.
  HttpResponseInfo response = *trans->GetResponseInfo();
  EXPECT_TRUE(response.headers);
  EXPECT_EQ("HTTP/1.1 200", response.headers->GetStatusLine());
}

TEST_P(SpdyNetworkTransactionTest, OutOfOrderHeaders) {
  // This first request will start to establish the SpdySession.
  // Then we will start the second (MEDIUM priority) and then third
  // (HIGHEST priority) request in such a way that the third will actually
  // start before the second, causing the second to be numbered differently
  // than the order they were created.
  //
  // Note that the requests and responses created below are expectations
  // of what the above will produce on the wire, and hence are in the
  // initial->HIGHEST->LOWEST priority.
  //
  // Frames are created by SpdySession just before the write associated
  // with the frame is attempted, so stream dependencies will be based
  // on the streams alive at the point of the request write attempt.  Thus
  // req1 is alive when req2 is attempted (during but not after the
  // |data.RunFor(2);| statement below) but not when req3 is attempted.
  // The call to spdy_util_.UpdateWithStreamDestruction() reflects this.
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, HIGHEST));
  spdy_util_.UpdateWithStreamDestruction(1);
  spdy::SpdySerializedFrame req3(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 5, MEDIUM));
  MockWrite writes[] = {
      MockWrite(ASYNC, ERR_IO_PENDING, 0),
      CreateMockWrite(req1, 1),
      CreateMockWrite(req2, 5),
      CreateMockWrite(req3, 6),
  };

  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, true));
  spdy::SpdySerializedFrame resp3(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 5));
  spdy::SpdySerializedFrame body3(spdy_util_.ConstructSpdyDataFrame(5, true));
  MockRead reads[] = {
      CreateMockRead(resp1, 2),  MockRead(ASYNC, ERR_IO_PENDING, 3),
      CreateMockRead(body1, 4),  CreateMockRead(resp2, 7),
      CreateMockRead(body2, 8),  CreateMockRead(resp3, 9),
      CreateMockRead(body3, 10), MockRead(ASYNC, 0, 11)  // EOF
  };

  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(request_, LOWEST, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);

  // Start the first transaction to set up the SpdySession
  HttpNetworkTransaction* trans = helper.trans();
  TestCompletionCallback callback;
  int rv = trans->Start(&request_, callback.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Run the message loop, but do not allow the write to complete.
  // This leaves the SpdySession with a write pending, which prevents
  // SpdySession from attempting subsequent writes until this write completes.
  base::RunLoop().RunUntilIdle();

  // Now, start both new transactions
  TestCompletionCallback callback2;
  HttpNetworkTransaction trans2(MEDIUM, helper.session());
  rv = trans2.Start(&request_, callback2.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  base::RunLoop().RunUntilIdle();

  TestCompletionCallback callback3;
  HttpNetworkTransaction trans3(HIGHEST, helper.session());
  rv = trans3.Start(&request_, callback3.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  base::RunLoop().RunUntilIdle();

  // We now have two HEADERS frames queued up which will be
  // dequeued only once the first write completes, which we
  // now allow to happen.
  ASSERT_TRUE(data.IsPaused());
  data.Resume();
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  // And now we can allow everything else to run to completion.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_THAT(callback3.WaitForResult(), IsOk());

  helper.VerifyDataConsumed();

  // At this point the test is completed and we need to safely destroy
  // all allocated structures. Helper stores a transaction that has a
  // reference to a stack allocated request, which has a short lifetime,
  // and is accessed during the transaction destruction. We need to delete
  // the transaction while the request is still a valid obj
"""


```