Response:
The user wants to understand the functionality of a specific chunk of C++ code from Chromium's networking stack. This code appears to be part of a unit test file (`http_network_transaction_unittest.cc`) focusing on testing `HttpNetworkTransaction` with various proxy configurations, especially nested HTTPS proxies using SPDY (HTTP/2).

Here's a breakdown of the thought process to answer the request:

1. **Identify the Core Functionality:** The code consists of several test cases (functions starting with `TEST_P`). Each test case sets up specific network scenarios involving proxy configurations and then uses `HttpNetworkTransaction` to make requests. The core goal seems to be testing socket reuse and connection management in complex proxy setups, especially when SPDY is involved.

2. **Analyze Individual Test Cases:**  Go through each test function and understand its specific scenario:
    * `HttpsNestedProxyNoSocketReuseFirstHop`, `HttpsNestedProxyNoSocketReuseSecondHop`, `HttpsNestedProxyNoSocketReuseReversedChain`: These test that socket reuse *doesn't* happen when the proxy chain changes (different first hop, different second hop, reversed order) for regular HTTPS proxies. This is expected because the TLS handshake is specific to the exact proxy chain.
    * `HttpsNestedProxySpdySocketReuseDifferentChains`: This tests that socket *reuse does* happen when the first part of the proxy chain is the same and uses SPDY. It explores scenarios where requests go through the full nested proxy chain and then only through the first hop or only the second hop. The expectation is that the SPDY connection to the first proxy will be reused.
    * `HttpsNestedProxySpdySocketReuseDifferentRequests`:  Tests socket reuse with SPDY across *multiple* requests to different endpoints but using the same nested proxy chain. This verifies that a single SPDY connection can handle multiple requests.
    * `HttpsNestedProxySpdySocketReuseAfterError`: Tests socket reuse after an error occurs on a SPDY connection within a nested proxy setup. It simulates an error and then verifies that a subsequent request can reuse the underlying connection.
    * `ProxiedH2SessionAppearsDuringAuth`: This test focuses on a scenario where a proxied HTTP/2 session doesn't exist initially but becomes available during the authentication process.

3. **Relate to Javascript (if applicable):**  Consider how these low-level networking details might affect Javascript in a browser context. Javascript uses APIs like `fetch` or `XMLHttpRequest`. While Javascript doesn't directly control socket reuse, the underlying network stack (tested here) significantly impacts performance. For example, proper socket reuse reduces connection establishment time, leading to faster page loads.

4. **Identify Logic and Assumptions:**  The tests rely on the `MockWrite` and `MockRead` classes to simulate network interactions. The input is the sequence of mock writes and reads, and the output is the success or failure of the `HttpNetworkTransaction` and the properties of the resulting `HttpResponseInfo`. The assumptions are that the mocking framework accurately represents network behavior and that the test setup (proxy configurations, SSL data providers) is correct.

5. **Spot User/Programming Errors:**  Consider common mistakes users or developers might make that would lead them to these parts of the code (e.g., incorrect proxy settings, unexpected authentication challenges, issues with SPDY connection management).

6. **Outline the User Journey (Debugging):** Think about how a developer might end up debugging this code. They might be investigating:
    * Performance issues related to connection establishment.
    * Problems with proxy configurations.
    * Unexpected connection errors or authentication failures.
    * Issues specific to SPDY or HTTP/2 when using proxies.
    * Socket reuse behavior in complex scenarios.

7. **Summarize the Chunk's Functionality:**  Provide a concise overview of what the code segment is doing within the broader context of the file. Since the prompt indicated this is part 12 of 34, acknowledge that this is an intermediate section and its purpose is contributing to a larger set of tests.

8. **Structure the Answer:** Organize the findings into clear sections addressing each part of the user's request: functionality, relationship to Javascript, logic/assumptions, user errors, user journey, and summary. Use examples and clear language.

9. **Review and Refine:**  Read through the answer to ensure clarity, accuracy, and completeness. Check if all aspects of the user's request have been addressed. For instance, ensure the assumptions and input/output examples are concrete. Make sure the JavaScript relation is explained clearly.
这是 Chromium 网络栈的源代码文件 `net/http/http_network_transaction_unittest.cc` 的一部分，它主要用于测试 `HttpNetworkTransaction` 类的各种功能，特别是涉及到 HTTPS 嵌套代理和 SPDY (HTTP/2) 的场景。

**本代码片段的功能归纳：**

这段代码主要测试了在涉及多层 HTTPS 代理（嵌套代理）的情况下，`HttpNetworkTransaction` 如何处理连接的复用和避免不必要的复用，尤其是在使用 SPDY (HTTP/2) 作为代理连接协议时。

具体来说，它测试了以下几种场景：

* **非 SPDY 嵌套代理下的 socket 不复用:** 验证当代理链发生变化时（例如，从通过两个代理到只通过第一个或第二个代理），`HttpNetworkTransaction` 不会复用之前的 socket 连接。这是因为 TLS 连接是端到端的，代理链的变化意味着需要建立新的 TLS 连接。
* **SPDY 嵌套代理下的 socket 复用（部分场景）:** 验证当使用 SPDY 作为代理连接协议时，如果后续请求的代理链是之前已建立连接的代理链的前缀，则可以复用已有的 SPDY 连接。例如，如果先建立了到 `proxy1 -> proxy2 -> 目标服务器` 的 SPDY 连接，那么后续到 `proxy1 -> 目标服务器` 的请求可以复用与 `proxy1` 的 SPDY 连接。
* **SPDY 嵌套代理下的 socket 不复用（部分场景）:** 验证当使用 SPDY 作为代理连接协议时，如果后续请求的代理链与之前建立的连接不匹配，即使代理服务器相同，也不会复用 socket。例如，从 `proxy1 -> proxy2` 到只 `proxy2` 的请求，或者代理顺序反转 `proxy2 -> proxy1`。
* **SPDY 嵌套代理下跨请求的 socket 复用:** 验证在相同的嵌套 SPDY 代理链下，即使请求不同的目标地址，也可以复用已建立的代理连接。
* **SPDY 嵌套代理连接发生错误后的 socket 复用:** 验证在一个经过嵌套 SPDY 代理的连接发生错误后，后续的请求仍然可以复用相同的连接（如果符合复用条件）。
* **在认证过程中出现 HTTP/2 会话:** 测试一种特殊情况，即在开始请求时没有可用的 HTTP/2 会话，但在提供认证信息后，会话变得可用。

**与 JavaScript 的功能关系及举例说明：**

这段代码测试的是浏览器底层网络栈的行为，虽然 JavaScript 代码本身不直接操作 socket，但这些底层的行为会直接影响 JavaScript 发起的网络请求的性能和行为。

* **性能优化：** Socket 复用可以减少 TCP 连接建立和 TLS 握手的次数，显著提升网页加载速度和 API 请求的响应时间。JavaScript 发起的 `fetch` 或 `XMLHttpRequest` 请求会受益于底层的 socket 复用机制。例如，在同一个网站下请求多个资源时，如果底层成功复用 socket，用户会感觉加载速度更快。
* **代理行为一致性：**  这段代码确保了在复杂的代理场景下，网络栈的行为是符合预期的。这保证了 JavaScript 代码在不同网络环境下的行为一致性。例如，如果一个使用了多个代理的企业网络环境下，JavaScript 发起的请求应该能够正确地通过代理链，并且尽可能地复用连接。

**逻辑推理、假设输入与输出：**

以 `HttpsNestedProxySpdySocketReuseDifferentChains` 这个测试为例：

**假设输入：**

1. **初始请求:**  请求 `https://www.example.org/`，配置使用嵌套代理 `proxy1.test:70` (SPDY) -> `proxy2.test:71` (SPDY)。
2. **第二次请求:** 请求相同的 `https://www.example.org/`，但配置只使用第一个代理 `proxy1.test:70` (SPDY)。
3. **第三次请求:** 请求相同的 `https://www.example.org/`，但配置只使用第二个代理 `proxy2.test:71` (SPDY)。

**预期输出：**

1. 第一次请求会建立到 `proxy1` 和 `proxy2` 的 SPDY 连接。
2. 第二次请求会复用已建立的到 `proxy1` 的 SPDY 连接，并直接向目标服务器发起连接。
3. 第三次请求不会复用任何已有的 SPDY 连接，因为它需要建立一个新的到 `proxy2` 的连接。

**代码中的体现：**

* `MockWrite` 和 `MockRead` 定义了模拟的网络数据交互，包括 SPDY 的 CONNECT 帧和数据帧。
* `SequencedSocketData` 确保了模拟数据按照预期的顺序发送和接收。
* `EXPECT_TRUE(spdy_data1.AllReadDataConsumed());` 和 `EXPECT_TRUE(spdy_data1.AllWriteDataConsumed());` 等断言用于验证是否使用了预期的 socket 以及数据是否被完全消费。

**用户或编程常见的使用错误：**

* **错误的代理配置：** 用户或开发者可能会配置错误的代理服务器地址或端口，导致连接失败或请求被路由到错误的地方。这段代码测试了网络栈在处理代理时的正确性，有助于发现由于代理配置错误导致的问题。
* **对 SPDY 连接复用的误解：** 开发者可能误以为只要代理服务器相同，SPDY 连接就可以复用，而忽略了代理链的完整性。这段测试强调了 SPDY 连接复用的条件，避免开发者做出错误的假设。
* **在需要认证的代理环境下没有提供认证信息：** 当代理服务器需要认证时，如果 JavaScript 代码没有提供相应的认证信息，会导致连接失败。`ProxiedH2SessionAppearsDuringAuth` 这个测试场景就与认证相关。

**用户操作是如何一步步到达这里的（调试线索）：**

当开发者遇到与代理或 SPDY 相关的问题时，可能会需要调试 Chromium 的网络栈代码。以下是一些可能的步骤：

1. **用户报告网络问题：** 用户反馈网站加载缓慢，或者在特定网络环境下无法访问。
2. **开发者尝试复现：** 开发者尝试在类似的代理环境下复现问题。
3. **使用网络抓包工具：** 开发者可以使用 Wireshark 或 Chrome 开发者工具的网络面板来查看网络请求的详细信息，包括是否使用了代理，以及连接是否被复用。
4. **查看 Chrome 的内部日志 (net-internals)：**  开发者可以访问 `chrome://net-internals/#http2` 或 `chrome://net-internals/#sockets` 来查看 HTTP/2 会话和 socket 的状态，从而判断是否发生了预期的连接复用。
5. **如果怀疑是代理或 SPDY 的问题：** 开发者可能会查看 `net/http` 目录下与代理和 SPDY 相关的代码，例如 `http_proxy_client_socket_pool.cc`，`spdy_session.cc` 等。
6. **运行相关的单元测试：** 为了验证网络栈在特定代理场景下的行为是否正确，开发者可能会运行 `net/http/http_network_transaction_unittest.cc` 中的相关测试，例如上面列出的测试用例，来定位问题。他们可能会设置断点，查看变量的值，以理解代码的执行流程。

**总结本代码片段的功能 (作为第 12 部分)：**

作为 `http_network_transaction_unittest.cc` 的第 12 部分，这段代码专注于验证 `HttpNetworkTransaction` 在涉及多层 HTTPS 代理和 SPDY 时的连接管理和复用逻辑的正确性。它通过模拟不同的代理配置和网络交互，测试了连接复用的边界条件，确保了网络栈在复杂代理场景下的稳定性和性能。这部分测试是更大范围的网络栈测试的一部分，旨在覆盖各种可能的网络场景，保证 Chromium 浏览器网络功能的可靠性。

### 提示词
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第12部分，共34部分，请归纳一下它的功能
```

### 源代码
```cpp
hain2.length(); ++proxy_index) {
    ssl_socket_data_providers.emplace_back(ASYNC, OK);
    session_deps_.socket_factory->AddSSLSocketDataProvider(
        &ssl_socket_data_providers.back());
  }

  TestCompletionCallback callback2;
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());

  rv = trans2.Start(&request, callback2.callback(),
                    NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans2.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(chain2, response->proxy_chain);

  EXPECT_TRUE(data1.AllReadDataConsumed());
  EXPECT_TRUE(data1.AllWriteDataConsumed());
  EXPECT_TRUE(data2.AllReadDataConsumed());
  EXPECT_TRUE(data2.AllWriteDataConsumed());
}

// If we have established a proxy tunnel through a two hop proxy and then
// establish a tunnel through only the first hop, ensure that socket re-use does
// not occur (HTTPS A -> HTTPS B != HTTPS A).
TEST_P(HttpNetworkTransactionTest, HttpsNestedProxyNoSocketReuseFirstHop) {
  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 70)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 71)};
  const ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({{kProxyServer1, kProxyServer2}});

  const ProxyChain kFirstHopOnlyChain{{kProxyServer1}};
  HttpsNestedProxyNoSocketReuseHelper(kNestedProxyChain, kFirstHopOnlyChain);
}

// If we have established a proxy tunnel through a two hop proxy and then
// establish a tunnel through only the second hop, ensure that socket re-use
// does not occur (HTTPS A -> HTTPS B != HTTPS B).
TEST_P(HttpNetworkTransactionTest, HttpsNestedProxyNoSocketReuseSecondHop) {
  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 70)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 71)};
  const ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({{kProxyServer1, kProxyServer2}});

  const ProxyChain kSecondHopOnlyChain{{kProxyServer2}};

  HttpsNestedProxyNoSocketReuseHelper(kNestedProxyChain, kSecondHopOnlyChain);
}

// If we have established a proxy tunnel through a two hop proxy and then
// establish a tunnel through the same proxies with the order reversed, ensure
// that socket re-use does not occur (HTTPS A -> HTTPS B != HTTPS B -> HTTPS A).
TEST_P(HttpNetworkTransactionTest, HttpsNestedProxyNoSocketReuseReversedChain) {
  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 70)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 71)};
  const ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({{kProxyServer1, kProxyServer2}});

  const ProxyChain kReversedChain =
      ProxyChain::ForIpProtection({{kProxyServer2, kProxyServer1}});

  HttpsNestedProxyNoSocketReuseHelper(kNestedProxyChain, kReversedChain);
}

// If we have established a proxy tunnel through a two hop proxy using SPDY,
// ensure that socket reuse occurs as expected. Specifically, for:
// (SPDY A -> SPDY B -> HTTPS Endpoint),
// (SPDY A -> HTTPS Endpoint) should send the endpoint CONNECT to
// the existing SPDY A socket but for:
// (SPDY B -> HTTPS Endpoint), the SPDY A -> SPDY B socket should not be used.
TEST_P(HttpNetworkTransactionTest,
       HttpsNestedProxySpdySocketReuseDifferentChains) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure a nested proxy.
  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 70)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 71)};
  const ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({{kProxyServer1, kProxyServer2}});
  const ProxyChain kFirstHopOnlyChain{{kProxyServer1}};
  const ProxyChain kSecondHopOnlyChain{{kProxyServer1}};

  session_deps_.proxy_delegate = std::make_unique<TestProxyDelegate>();
  auto* proxy_delegate =
      static_cast<TestProxyDelegate*>(session_deps_.proxy_delegate.get());
  proxy_delegate->set_proxy_chain(kNestedProxyChain);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://not-used:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.proxy_resolution_service->SetProxyDelegate(proxy_delegate);

  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // CONNECT to proxy2.test:71 via SPDY.
  spdy::SpdySerializedFrame proxy2_connect(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      kProxyServer2.host_port_pair()));

  spdy::SpdySerializedFrame proxy2_connect_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  // CONNECT to www.example.org:443 via SPDY.
  // Need to use a new `SpdyTestUtil()` so that the stream parent ID of this
  // CONNECT is calculated correctly.
  SpdyTestUtil new_spdy_util;
  spdy::SpdySerializedFrame endpoint_connect(new_spdy_util.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));

  // Since this request and response are sent over the tunnel established
  // previously, from a socket-perspective these need to be wrapped as data
  // frames.
  spdy::SpdySerializedFrame wrapped_endpoint_connect(
      spdy_util_.ConstructWrappedSpdyFrame(endpoint_connect, 1));

  spdy::SpdySerializedFrame endpoint_connect_resp(
      new_spdy_util.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame wrapped_endpoint_connect_resp(
      spdy_util_.ConstructWrappedSpdyFrame(endpoint_connect_resp, 1));

  // fetch https://www.example.org/ via HTTP.
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

  const char kTrans1RespData[] = "1234567890";
  spdy::SpdySerializedFrame wrapped_body(
      new_spdy_util.ConstructSpdyDataFrame(1, kTrans1RespData, false));
  spdy::SpdySerializedFrame wrapped_wrapped_body(
      spdy_util_.ConstructWrappedSpdyFrame(wrapped_body, 1));

  const char kTrans2RespData[] = "abcdefghij";
  spdy::SpdySerializedFrame second_trans_endpoint_connect(
      spdy_util_.ConstructSpdyConnect(
          nullptr, 0, 3, HttpProxyConnectJob::kH2QuicTunnelPriority,
          HostPortPair("www.example.org", 443)));
  spdy::SpdySerializedFrame second_trans_endpoint_connect_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame second_trans_wrapped_get(
      new_spdy_util.ConstructSpdyDataFrame(3, kGet, false));
  spdy::SpdySerializedFrame second_trans_wrapped_get_resp(
      new_spdy_util.ConstructSpdyDataFrame(3, kResp, false));
  spdy::SpdySerializedFrame second_trans_wrapped_body(
      new_spdy_util.ConstructSpdyDataFrame(3, kTrans2RespData, false));

  MockWrite spdy_writes1[] = {
      CreateMockWrite(proxy2_connect, 0),
      CreateMockWrite(wrapped_endpoint_connect, 2),
      CreateMockWrite(wrapped_wrapped_get, 5),
      // For the second transaction, we expect the endpoint connect on this
      // socket.
      CreateMockWrite(second_trans_endpoint_connect, 8),
      CreateMockWrite(second_trans_wrapped_get, 10),

  };

  MockRead spdy_reads1[] = {
      CreateMockRead(proxy2_connect_resp, 1, ASYNC),
      // TODO(crbug.com/41180906): We have to manually delay this read so
      // that the higher-level SPDY stream doesn't get notified of an available
      // read before the write it initiated (the second CONNECT) finishes,
      // triggering a DCHECK.
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      CreateMockRead(wrapped_endpoint_connect_resp, 4, ASYNC),
      CreateMockRead(wrapped_wrapped_get_resp, 6, ASYNC),
      CreateMockRead(wrapped_wrapped_body, 7, ASYNC),
      CreateMockRead(second_trans_endpoint_connect_resp, 9),
      CreateMockRead(second_trans_wrapped_get_resp, 11, ASYNC),
      CreateMockRead(second_trans_wrapped_body, 12, ASYNC),
      MockRead(ASYNC, 0, 13),
  };

  SequencedSocketData spdy_data1(spdy_reads1, spdy_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data1);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);
  SSLSocketDataProvider ssl3(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl3);

  TestCompletionCallback callback1;
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, session.get());

  int rv = trans1.Start(&request, callback1.callback(),
                        NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  spdy_data1.RunUntilPaused();
  base::RunLoop().RunUntilIdle();
  spdy_data1.Resume();

  rv = callback1.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans1.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_EQ(kNestedProxyChain, response->proxy_chain);

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans1, &response_data), IsOk());
  EXPECT_EQ(kTrans1RespData, response_data);

  // Now use a proxy chain consisting of only the first proxy. We expect that it
  // will re-use the existing socket to the proxy, so we will look for the reads
  // and writes associated with this in the same SocketDataProvider used by the
  // first transaction.
  proxy_delegate->set_proxy_chain(kFirstHopOnlyChain);

  SSLSocketDataProvider ssl4(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl4);

  TestCompletionCallback callback2;
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());

  rv = trans2.Start(&request, callback2.callback(),
                    NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  response = trans2.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_EQ(kFirstHopOnlyChain, response->proxy_chain);

  ASSERT_THAT(ReadTransaction(&trans2, &response_data), IsOk());
  EXPECT_EQ(kTrans2RespData, response_data);

  // Now use a proxy chain consisting of only the second proxy. We expect that
  // it will not re-use the existing socket to the first proxy, so we will look
  // for the reads and writes associated with this in a new SocketDataProvider.
  proxy_delegate->set_proxy_chain(kSecondHopOnlyChain);

  // CONNECT to www.example.org:443 via SPDY.
  SpdyTestUtil third_spdy_util;
  spdy::SpdySerializedFrame third_trans_endpoint_connect(
      third_spdy_util.ConstructSpdyConnect(
          nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
          HostPortPair("www.example.org", 443)));

  spdy::SpdySerializedFrame third_trans_endpoint_connect_resp(
      third_spdy_util.ConstructSpdyGetReply(nullptr, 0, 1));

  // fetch https://www.example.org/ via HTTP.
  spdy::SpdySerializedFrame third_trans_wrapped_get(
      third_spdy_util.ConstructSpdyDataFrame(1, kGet, false));

  spdy::SpdySerializedFrame third_trans_wrapped_get_resp(
      third_spdy_util.ConstructSpdyDataFrame(1, kResp, false));

  const char kTrans3RespData[] = "!@#$%^&*()";
  spdy::SpdySerializedFrame third_trans_wrapped_body(
      third_spdy_util.ConstructSpdyDataFrame(1, kTrans3RespData, false));

  MockWrite spdy_writes2[] = {
      CreateMockWrite(third_trans_endpoint_connect, 0),
      CreateMockWrite(third_trans_wrapped_get, 2),
  };

  MockRead spdy_reads2[] = {
      CreateMockRead(third_trans_endpoint_connect_resp, 1, ASYNC),
      CreateMockRead(third_trans_wrapped_get_resp, 3, ASYNC),
      CreateMockRead(third_trans_wrapped_body, 4, ASYNC),
      MockRead(ASYNC, 0, 5),
  };

  SequencedSocketData spdy_data2(spdy_reads2, spdy_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data2);

  SSLSocketDataProvider ssl5(ASYNC, OK);
  ssl5.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl5);

  SSLSocketDataProvider ssl6(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl6);

  TestCompletionCallback callback3;
  HttpNetworkTransaction trans3(DEFAULT_PRIORITY, session.get());

  rv = trans3.Start(&request, callback3.callback(),
                    NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback3.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  response = trans3.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_EQ(kFirstHopOnlyChain, response->proxy_chain);

  ASSERT_THAT(ReadTransaction(&trans3, &response_data), IsOk());
  EXPECT_EQ(kTrans3RespData, response_data);

  EXPECT_EQ(proxy_delegate->on_before_tunnel_request_call_count(), 4u);

  EXPECT_TRUE(spdy_data1.AllReadDataConsumed());
  EXPECT_TRUE(spdy_data1.AllWriteDataConsumed());
  EXPECT_TRUE(spdy_data2.AllReadDataConsumed());
  EXPECT_TRUE(spdy_data2.AllWriteDataConsumed());
}

// If we have established a proxy tunnel through a two-hop proxy using SPDY,
// ensure that socket reuse occurs as expected for two different requests (test
// that there is only one CONNECT for the second proxy in the chain).
TEST_P(HttpNetworkTransactionTest,
       HttpsNestedProxySpdySocketReuseDifferentRequests) {
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org/");
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 70)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 71)};
  const ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({{kProxyServer1, kProxyServer2}});

  session_deps_.proxy_delegate = std::make_unique<TestProxyDelegate>();
  auto* proxy_delegate =
      static_cast<TestProxyDelegate*>(session_deps_.proxy_delegate.get());
  proxy_delegate->set_proxy_chain(kNestedProxyChain);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://not-used:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.proxy_resolution_service->SetProxyDelegate(proxy_delegate);

  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // CONNECT to proxy2.test:71 via SPDY.
  spdy::SpdySerializedFrame proxy2_connect(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      kProxyServer2.host_port_pair()));

  spdy::SpdySerializedFrame proxy2_connect_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  // CONNECT to www.example.org:443 via SPDY.
  // Need to use a new `SpdyTestUtil()` so that the stream parent ID of this
  // CONNECT is calculated correctly.
  SpdyTestUtil new_spdy_util;
  spdy::SpdySerializedFrame endpoint_connect(new_spdy_util.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));

  // Since the first request and response are sent over the tunnel established
  // previously, from a socket-perspective these need to be wrapped as data
  // frames.
  spdy::SpdySerializedFrame wrapped_endpoint_connect(
      spdy_util_.ConstructWrappedSpdyFrame(endpoint_connect, 1));

  spdy::SpdySerializedFrame endpoint_connect_resp(
      new_spdy_util.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame wrapped_endpoint_connect_resp(
      spdy_util_.ConstructWrappedSpdyFrame(endpoint_connect_resp, 1));

  // fetch https://www.example.org/ via HTTP.
  // Since the first request will go over two tunnels, it needs to be
  // double-wrapped.
  const char kGet1[] =
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get(
      new_spdy_util.ConstructSpdyDataFrame(1, kGet1, false));
  spdy::SpdySerializedFrame wrapped_wrapped_get(
      spdy_util_.ConstructWrappedSpdyFrame(wrapped_get, 1));

  const char kResp[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 10\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get_resp(
      new_spdy_util.ConstructSpdyDataFrame(1, kResp, false));
  spdy::SpdySerializedFrame wrapped_wrapped_get_resp(
      spdy_util_.ConstructWrappedSpdyFrame(wrapped_get_resp, 1));

  const char kTrans1RespData[] = "1234567890";
  spdy::SpdySerializedFrame wrapped_body(
      new_spdy_util.ConstructSpdyDataFrame(1, kTrans1RespData, false));
  spdy::SpdySerializedFrame wrapped_wrapped_body(
      spdy_util_.ConstructWrappedSpdyFrame(wrapped_body, 1));

  // CONNECT to www.example.com:443 via SPDY.
  spdy::SpdySerializedFrame second_trans_endpoint_connect(
      new_spdy_util.ConstructSpdyConnect(
          nullptr, 0, 3, HttpProxyConnectJob::kH2QuicTunnelPriority,
          HostPortPair("www.example.com", 443)));
  spdy::SpdySerializedFrame second_trans_wrapped_endpoint_connect(
      spdy_util_.ConstructWrappedSpdyFrame(second_trans_endpoint_connect, 1));

  spdy::SpdySerializedFrame second_trans_endpoint_connect_resp(
      new_spdy_util.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame second_trans_wrapped_endpoint_connect_resp(
      spdy_util_.ConstructWrappedSpdyFrame(second_trans_endpoint_connect_resp,
                                           1));

  // fetch https://www.example.com/2 via HTTP.
  const char kGet2[] =
      "GET /2 HTTP/1.1\r\n"
      "Host: www.example.com\r\n"
      "Connection: keep-alive\r\n\r\n";
  SpdyTestUtil second_trans_spdy_util;
  spdy::SpdySerializedFrame second_trans_wrapped_get(
      second_trans_spdy_util.ConstructSpdyDataFrame(3, kGet2, false));
  spdy::SpdySerializedFrame second_trans_wrapped_wrapped_get(
      spdy_util_.ConstructWrappedSpdyFrame(second_trans_wrapped_get, 1));

  spdy::SpdySerializedFrame second_trans_wrapped_get_resp(
      second_trans_spdy_util.ConstructSpdyDataFrame(3, kResp, false));
  spdy::SpdySerializedFrame second_trans_wrapped_wrapped_get_resp(
      spdy_util_.ConstructWrappedSpdyFrame(second_trans_wrapped_get_resp, 1));

  const char kTrans2RespData[] = "abcdefghij";
  spdy::SpdySerializedFrame second_trans_wrapped_body(
      second_trans_spdy_util.ConstructSpdyDataFrame(3, kTrans2RespData, false));
  spdy::SpdySerializedFrame second_trans_wrapped_wrapped_body(
      spdy_util_.ConstructWrappedSpdyFrame(second_trans_wrapped_body, 1));

  MockWrite spdy_writes1[] = {
      CreateMockWrite(proxy2_connect, 0),
      CreateMockWrite(wrapped_endpoint_connect, 2),
      CreateMockWrite(wrapped_wrapped_get, 5),
      // For the second transaction, we expect the endpoint connect on this
      // socket with no duplicated proxy2 CONNECT.
      CreateMockWrite(second_trans_wrapped_endpoint_connect, 8),
      CreateMockWrite(second_trans_wrapped_wrapped_get, 11),
  };

  MockRead spdy_reads1[] = {
      CreateMockRead(proxy2_connect_resp, 1, ASYNC),
      // TODO(crbug.com/41180906): We have to manually delay this read so
      // that the higher-level SPDY stream doesn't get notified of an available
      // read before the write it initiated (the second CONNECT) finishes,
      // triggering a DCHECK.
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      CreateMockRead(wrapped_endpoint_connect_resp, 4, ASYNC),
      CreateMockRead(wrapped_wrapped_get_resp, 6, ASYNC),
      CreateMockRead(wrapped_wrapped_body, 7, ASYNC),
      // TODO(crbug.com/41180906): We have to manually delay this read so
      // that the higher-level SPDY stream doesn't get notified of an available
      // read before the write it initiated (the second CONNECT) finishes,
      // triggering a DCHECK.
      MockRead(ASYNC, ERR_IO_PENDING, 9),
      CreateMockRead(second_trans_wrapped_endpoint_connect_resp, 10),
      CreateMockRead(second_trans_wrapped_wrapped_get_resp, 12),
      CreateMockRead(second_trans_wrapped_wrapped_body, 13),
      MockRead(ASYNC, 0, 14),
  };

  SequencedSocketData spdy_data1(spdy_reads1, spdy_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data1);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);
  SSLSocketDataProvider ssl3(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl3);

  TestCompletionCallback callback1;
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, session.get());

  int rv = trans1.Start(&request1, callback1.callback(),
                        NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  spdy_data1.RunUntilPaused();
  base::RunLoop().RunUntilIdle();
  spdy_data1.Resume();

  rv = callback1.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans1.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_EQ(kNestedProxyChain, response->proxy_chain);

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans1, &response_data), IsOk());
  EXPECT_EQ(kTrans1RespData, response_data);

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://www.example.com/2");
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  SSLSocketDataProvider ssl4(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl4);

  TestCompletionCallback callback2;
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());

  rv = trans2.Start(&request2, callback2.callback(),
                    NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  spdy_data1.RunUntilPaused();
  base::RunLoop().RunUntilIdle();
  spdy_data1.Resume();

  rv = callback2.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  response = trans2.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_EQ(kNestedProxyChain, response->proxy_chain);

  ASSERT_THAT(ReadTransaction(&trans2, &response_data), IsOk());
  EXPECT_EQ(kTrans2RespData, response_data);
}

// Ensure that socket reuse occurs after an error from a SPDY connection through
// the nested proxy.
TEST_P(HttpNetworkTransactionTest, HttpsNestedProxySpdySocketReuseAfterError) {
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
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      kProxyServer2.host_port_pair()));

  spdy::SpdySerializedFrame proxy2_connect_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  // CONNECT to www.example.org:443 via SPDY.
  // Need to use a new `SpdyTestUtil()` so that the stream parent ID of this
  // CONNECT is calculated correctly.
  SpdyTestUtil new_spdy_util;
  spdy::SpdySerializedFrame endpoint_connect(new_spdy_util.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));

  // Since this request and response are sent over the tunnel established
  // previously, from a socket-perspective these need to be wrapped as data
  // frames.
  spdy::SpdySerializedFrame wrapped_endpoint_connect(
      spdy_util_.ConstructWrappedSpdyFrame(endpoint_connect, 1));

  spdy::SpdySerializedFrame endpoint_connect_resp(
      new_spdy_util.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame wrapped_endpoint_connect_resp(
      spdy_util_.ConstructWrappedSpdyFrame(endpoint_connect_resp, 1));

  spdy::SpdySerializedFrame rst(
      new_spdy_util.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
  spdy::SpdySerializedFrame wrapped_rst(
      spdy_util_.ConstructWrappedSpdyFrame(rst, 1));

  new_spdy_util.UpdateWithStreamDestruction(1);
  spdy::SpdySerializedFrame attempt2_endpoint_connect(
      new_spdy_util.ConstructSpdyConnect(
          nullptr, 0, 3, HttpProxyConnectJob::kH2QuicTunnelPriority,
          HostPortPair("www.example.org", 443)));
  spdy::SpdySerializedFrame attempt2_wrapped_endpoint_connect(
      spdy_util_.ConstructWrappedSpdyFrame(attempt2_endpoint_connect, 1));

  spdy::SpdySerializedFrame attempt2_endpoint_connect_resp(
      new_spdy_util.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame attempt2_wrapped_endpoint_connect_resp(
      spdy_util_.ConstructWrappedSpdyFrame(attempt2_endpoint_connect_resp, 1));

  // fetch https://www.example.org/ via HTTPS.
  // Since this request will go over two tunnels, it needs to be double-wrapped.
  const char kGet[] =
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  SpdyTestUtil attempt2_spdy_util(/*use_priority_header=*/true);
  spdy::SpdySerializedFrame attempt2_wrapped_get(
      attempt2_spdy_util.ConstructSpdyDataFrame(3, kGet, false));
  spdy::SpdySerializedFrame attempt2_wrapped_wrapped_get(
      spdy_util_.ConstructWrappedSpdyFrame(attempt2_wrapped_get, 1));

  const char kResp[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 10\r\n\r\n";
  spdy::SpdySerializedFrame attempt2_wrapped_get_resp(
      attempt2_spdy_util.ConstructSpdyDataFrame(3, kResp, false));
  spdy::SpdySerializedFrame attempt2_wrapped_wrapped_get_resp(
      spdy_util_.ConstructWrappedSpdyFrame(attempt2_wrapped_get_resp, 1));

  const char kRespData[] = "1234567890";
  spdy::SpdySerializedFrame attempt2_wrapped_body(
      attempt2_spdy_util.ConstructSpdyDataFrame(3, kRespData, false));
  spdy::SpdySerializedFrame attempt2_wrapped_wrapped_body(
      spdy_util_.ConstructWrappedSpdyFrame(attempt2_wrapped_body, 1));

  MockWrite spdy_writes[] = {
      CreateMockWrite(proxy2_connect, 0),
      CreateMockWrite(wrapped_endpoint_connect, 2),
      CreateMockWrite(wrapped_rst, 5),
      CreateMockWrite(attempt2_wrapped_endpoint_connect, 6),
      CreateMockWrite(attempt2_wrapped_wrapped_get, 9),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(proxy2_connect_resp, 1, ASYNC),
      // TODO(crbug.com/41180906): We have to manually delay this read so
      // that the higher-level SPDY stream doesn't get notified of an available
      // read before the write it initiated (the second CONNECT) finishes,
      // triggering a DCHECK.
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      CreateMockRead(wrapped_endpoint_connect_resp, 4, ASYNC),
      // The SSL socket error should occur here.
      MockRead(ASYNC, ERR_IO_PENDING, 7),
      CreateMockRead(attempt2_wrapped_endpoint_connect_resp, 8, ASYNC),
      CreateMockRead(attempt2_wrapped_wrapped_get_resp, 10, ASYNC),
      CreateMockRead(attempt2_wrapped_wrapped_body, 11, ASYNC),
      MockRead(ASYNC, 0, 12),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  SSLSocketDataProvider ssl2(ASYNC, OK);
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  auto cert_request_info_proxy = base::MakeRefCounted<SSLCertRequestInfo>();
  cert_request_info_proxy->host_and_port = kProxyServer1.host_port_pair();

  SSLSocketDataProvider ssl3(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  ssl3.cert_request_info = cert_request_info_proxy;
  ssl3.expected_send_client_cert = false;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl3);

  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org/");
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, session.get());

  int rv = trans1.Start(&request1, callback1.callback(),
                        NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  spdy_data.RunUntilPaused();
  base::RunLoop().RunUntilIdle();
  spdy_data.Resume();

  rv = callback1.WaitForResult();
  ASSERT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));

  SSLSocketDataProvider ssl4(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl4);

  TestCompletionCallback callback2;

  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());

  rv = trans2.Start(&request1, callback2.callback(),
                    NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  spdy_data.RunUntilPaused();
  base::RunLoop().RunUntilIdle();
  spdy_data.Resume();

  rv = callback2.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans2.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans2, &response_data), IsOk());
  EXPECT_EQ(kRespData, response_data);
}

// Test the case where a proxied H2 session doesn't exist when an auth challenge
// is observed, but does exist by the time auth credentials are provided. In
// this case, auth and SSL are fully negotated on the second request, but then
// the socket is discarded to use the shared session.
TEST_P(HttpNetworkTransactionTest, ProxiedH2SessionAppearsDuringAuth) {
  ProxyConfig proxy_config;
  proxy_config.set_auto_detect(true);
  proxy_config.set_pac_url(GURL("http://fooproxyurl"));

  CapturingProxyResolver capturing_proxy_resolver;
  capturing_proxy_resolver.set_proxy_chain(
      ProxyChain(ProxyServer::SCHEME_HTTP, HostPortPair("myproxy", 70)));
  session_deps_.proxy_resolution_service =
      std::make_unique<ConfiguredProxyResolutionService>(
          std::make_unique<ProxyConfigServiceFixed>(ProxyConfigWithAnnotation(
              proxy_config, TRAFFIC_ANNOTATION_FOR_TESTS)),
          std::make_unique<Captur
```