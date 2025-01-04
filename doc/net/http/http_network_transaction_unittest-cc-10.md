Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The user wants a functional overview of a C++ source file (`http_network_transaction_unittest.cc`) within the Chromium network stack. They also want to know about its relation to JavaScript, examples of logic and errors, debugging information, and a summary of its purpose as part of a larger sequence.

2. **Identify the File's Purpose:** The filename itself is a big clue: `http_network_transaction_unittest.cc`. The `unittest` suffix strongly indicates this file contains unit tests for the `HttpNetworkTransaction` class. Unit tests are designed to verify the behavior of individual components in isolation.

3. **Analyze the Provided Code Snippet:**  The provided code is a series of C++ test cases using the Google Test framework (`TEST_P`, `EXPECT_THAT`, `ASSERT_THAT`). Each test case seems to set up specific network scenarios and then verify that `HttpNetworkTransaction` behaves correctly in those scenarios. Key observations:
    * **`HttpRequestInfo`:**  This struct likely defines the details of an HTTP request (method, URL, etc.).
    * **`HttpNetworkSession`:**  This represents a network session, managing things like connections and cookies.
    * **`HttpNetworkTransaction`:** The class under test, responsible for executing an HTTP transaction.
    * **`MockWrite` and `MockRead`:** These are mock objects used to simulate network I/O, allowing controlled testing without real network connections. They define what data is sent and received at each step.
    * **`SequencedSocketData`:**  This manages the sequence of mock reads and writes for a socket.
    * **`SSLSocketDataProvider`:** Used to simulate SSL/TLS connections.
    * **SPDY/HTTP2:** The code frequently mentions `spdy`, `kProtoHTTP2`, and uses `spdy::SpdySerializedFrame`. This indicates that the tests cover scenarios involving SPDY/HTTP2.
    * **Proxy Scenarios:**  Several test cases configure proxy servers (`ConfiguredProxyResolutionService`, `ProxyServer`, `ProxyChain`).
    * **CONNECT Method:** The tests frequently use the `CONNECT` method, particularly for establishing tunnels through proxies.
    * **Error Handling:** Some tests explicitly check for error conditions (`ERR_IO_PENDING`, `ERR_TUNNEL_CONNECTION_FAILED`).
    * **Load Timing:** The code checks `GetLoadTimingInfo`, suggesting tests related to performance metrics.

4. **Infer Functionality based on Test Cases:** By examining the different test case names and the setup within them, I can deduce the various functionalities being tested:
    * Basic HTTP requests.
    * HTTP requests through HTTPS proxies.
    * SPDY CONNECT requests through HTTPS proxies (including nested proxies).
    * Handling of successful and failed SPDY CONNECT attempts.
    * Scenarios involving different combinations of HTTP and SPDY proxies.
    * Prevention of socket reuse between different proxy chains.

5. **Address the Specific Questions:**

    * **Functionality:**  The file tests the core functionality of `HttpNetworkTransaction`, specifically how it handles different network configurations, including proxies and SPDY/HTTP2.
    * **JavaScript Relation:**  HTTP is fundamental to web communication, and JavaScript running in a browser relies heavily on it. The tests ensure the underlying network stack can handle requests initiated by JavaScript. Example:  A JavaScript `fetch()` call triggers an HTTP request, and these tests verify that the Chromium network stack correctly processes such requests, including proxy handling.
    * **Logic and I/O:** The tests use `MockWrite` and `MockRead` to simulate network I/O. By defining specific sequences of data, they test the logic of how `HttpNetworkTransaction` handles different inputs and outputs.
    * **User/Programming Errors:** The proxy configuration scenarios and error handling tests demonstrate common misconfigurations or network issues a user or programmer might encounter (e.g., incorrect proxy settings, failing proxy servers).
    * **User Operation to Reach Here:**  A user navigates to a website or a web application makes an API call. The browser's network stack then uses `HttpNetworkTransaction` to handle the underlying HTTP request. Debugging involves looking at network logs and potentially stepping through the code in this file.
    * **Part 11 of 34:**  Given that it's part 11, and the file seems to focus on proxy and SPDY scenarios, it likely builds upon earlier parts that tested simpler HTTP requests and forms a foundation for later parts that might cover more complex features or error handling scenarios.

6. **Structure the Answer:** Organize the information logically, starting with the core functionality and then addressing each of the user's questions with specific examples and explanations derived from the code analysis. Use clear and concise language.

7. **Refine and Review:**  Read through the answer to ensure accuracy, completeness, and clarity. Make sure the examples are relevant and easy to understand. For instance, the JavaScript `fetch()` example directly connects the C++ code to a common web development scenario.

By following these steps, I can generate a comprehensive and informative answer that addresses all aspects of the user's request. The key is to understand the purpose of unit tests and then carefully analyze the provided code to infer the functionalities being tested.

这是 Chromium 网络栈中 `net/http/http_network_transaction_unittest.cc` 文件的第 11 部分（共 34 部分）。根据提供的代码片段，我们可以归纳出以下功能：

**核心功能：针对 `HttpNetworkTransaction` 类进行网络请求场景的单元测试，特别是涉及到 HTTPS 代理和 SPDY/HTTP2 协议的复杂场景。**

更具体地说，这一部分主要测试了 `HttpNetworkTransaction` 如何处理以下情况：

1. **HTTPS 代理下的 SPDY CONNECT 请求 (SPDY -> HTTPS/SPDY):**
   - 测试了通过 HTTPS 代理使用 SPDY 的 `CONNECT` 方法连接到目标服务器的情况。
   - 验证了在成功建立隧道后，如何通过该隧道发送和接收 HTTP 请求和响应。
   - 代码中模拟了 SPDY 的握手、数据帧的发送和接收。

2. **HTTPS 代理下的 SPDY CONNECT 请求到 SPDY 服务器 (SPDY -> SPDY):**
   -  测试了通过 HTTPS 代理，使用 SPDY 的 `CONNECT` 方法连接到 *目标也是 SPDY 服务器* 的情况。
   - 涉及到双层 SPDY 封装，需要在代理和目标服务器之间建立两条 SPDY 连接。

3. **多层 HTTPS 代理和 SPDY 的混合使用:**
   - 测试了更复杂的代理场景，例如：
     - HTTPS (非 SPDY) 代理 -> HTTPS (SPDY) 代理 -> HTTPS 终端 (非 SPDY)。
     - HTTPS (SPDY) 代理 -> HTTPS (非 SPDY) 代理 -> HTTPS 终端 (非 SPDY)。
   - 验证了在多层代理下，`HttpNetworkTransaction` 如何正确地建立连接，封装和解封装数据帧。

4. **SPDY CONNECT 连接失败场景:**
   - 测试了通过 HTTPS (SPDY) 代理进行 SPDY `CONNECT` 请求失败的情况。
   - 模拟了代理服务器返回错误响应（例如 RST_STREAM）。
   - 验证了 `HttpNetworkTransaction` 是否能正确处理连接失败，并返回相应的错误码 (`ERR_TUNNEL_CONNECTION_FAILED`).

5. **多层 HTTPS (SPDY) 代理中连接失败的场景:**
   - 测试了在多层 HTTPS (SPDY) 代理中，连接到第一个或第二个代理失败的情况。
   - 验证了在嵌套代理场景下，连接失败的处理逻辑。

6. **防止多层代理之间 socket 的意外重用:**
   - 通过 `HttpsNestedProxyNoSocketReuseHelper` 函数，测试了当使用不同的代理链时，`HttpNetworkTransaction` 是否会创建新的 socket 连接，而不是意外地重用之前的连接。

**与 JavaScript 的关系：**

`HttpNetworkTransaction` 是浏览器网络栈的核心组件之一，负责处理所有类型的 HTTP(S) 请求，包括 JavaScript 发起的请求。

* **举例说明：** 当 JavaScript 代码中使用 `fetch()` API 发起一个 HTTPS 请求，并且该请求需要通过一个 HTTPS 代理时，`HttpNetworkTransaction` 就会被调用来处理这个请求。本文件中测试的场景，例如通过 HTTPS 代理建立 SPDY 连接，就直接关系到浏览器如何高效地处理 JavaScript 发起的网络请求。如果这些测试失败，可能会导致 JavaScript 发起的网络请求出错，例如无法连接到服务器，或者连接过程中发生错误。

**逻辑推理、假设输入与输出：**

这些测试用例通过 `MockWrite` 和 `MockRead` 模拟了网络 I/O 的行为。

* **假设输入（以 `HttpsProxySpdyConnectSpdy` 测试为例）：**
    - 请求的 URL： `https://www.example.org/`
    - 配置的代理服务器： `https://proxy:70` (支持 SPDY/HTTP2)
    - 模拟的 socket 数据流：
        - **写入 (MockWrite):** SPDY 的 `CONNECT` 帧，封装后的 GET 请求帧，Window Update 帧。
        - **读取 (MockRead):** SPDY 的 `CONNECT` 响应帧，封装后的 GET 响应头和 body 帧。
* **输出：**
    - `trans.Start()` 返回 `ERR_IO_PENDING` 表示异步操作。
    - `callback1.WaitForResult()` 返回 `OK` 表示请求成功完成。
    - `trans.GetResponseInfo()` 返回包含状态码 200 的 HTTP 响应头。
    - `ReadTransaction(&trans, &response_data)` 返回 `OK`，并且 `response_data` 包含了预期的数据 (`kUploadData`)。
    - `load_timing_info` 中的连接时间信息包含 SSL 时间。

**用户或编程常见的使用错误：**

这些测试覆盖了一些用户或编程中常见的错误情景：

* **错误的代理配置:** 如果用户配置了错误的代理服务器地址或端口，可能会导致连接失败，这与测试中模拟的连接失败场景相关。
* **代理服务器故障:**  测试中模拟了代理服务器返回错误的情况，这对应于实际网络中代理服务器不可用或返回错误的情况。
* **协议不匹配:**  如果客户端和代理服务器之间支持的协议不一致（例如，客户端尝试使用 SPDY 连接到一个不支持 SPDY 的代理），可能会导致连接失败。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器中输入一个 HTTPS URL (例如 `https://www.example.org/`) 并按下回车。**
2. **浏览器首先会进行 DNS 解析，获取服务器的 IP 地址。**
3. **浏览器会检查是否配置了代理服务器。** 如果配置了 HTTPS 代理，则会进入本文件测试的场景。
4. **`HttpNetworkTransaction` 对象会被创建，并根据请求的信息和代理配置，尝试与代理服务器建立连接。**
5. **如果代理支持 SPDY/HTTP2，`HttpNetworkTransaction` 可能会尝试使用 SPDY 的 `CONNECT` 方法建立隧道。** 这正是本文件中测试的主要场景。
6. **在建立隧道后，浏览器会通过该隧道向目标服务器发送请求。**
7. **在调试过程中，网络开发者可以使用 Chrome 的开发者工具 (Network 面板) 查看网络请求的详细信息，包括请求头、响应头、状态码以及连接时间等。**  如果发现连接建立失败，或者使用了错误的协议，开发者可能会检查浏览器的代理配置，或者查看网络栈的日志信息，这可能会引导他们查看 `HttpNetworkTransaction` 相关的代码。
8. **更底层的调试可能涉及到查看 `netlog`，它会记录网络栈的详细事件，包括 socket 的创建、数据的发送和接收等。**  开发者可以通过 `netlog` 追踪请求的整个生命周期，从而定位问题。

**第 11 部分的功能归纳：**

总而言之，`net/http/http_network_transaction_unittest.cc` 文件的第 11 部分专注于 **测试 `HttpNetworkTransaction` 类在各种复杂的 HTTPS 代理和 SPDY/HTTP2 组合场景下的连接建立、数据传输和错误处理能力。** 它确保了 Chromium 网络栈在面对现代网络协议和代理配置时能够正确可靠地工作，从而保证用户浏览网页和使用网络应用的体验。这一部分特别强调了通过 HTTPS 代理使用 SPDY 进行连接的各种情况，包括成功和失败的场景，以及多层代理的复杂性。

Prompt: 
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第11部分，共34部分，请归纳一下它的功能

"""

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

  const char kRespData[] = "1234567890";
  spdy::SpdySerializedFrame wrapped_body(
      new_spdy_util.ConstructSpdyDataFrame(1, kRespData, false));
  spdy::SpdySerializedFrame wrapped_wrapped_body(
      spdy_util_.ConstructWrappedSpdyFrame(wrapped_body, 1));

  MockWrite spdy_writes[] = {
      CreateMockWrite(proxy2_connect, 0),
      CreateMockWrite(wrapped_endpoint_connect, 2),
      CreateMockWrite(wrapped_wrapped_get, 5),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(proxy2_connect_resp, 1, ASYNC),
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
  SSLSocketDataProvider ssl3(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl3);

  TestCompletionCallback callback1;

  int rv = trans.Start(&request, callback1.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  spdy_data.RunUntilPaused();
  base::RunLoop().RunUntilIdle();
  spdy_data.Resume();

  rv = callback1.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_SSL_TIMES);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ(kRespData, response_data);
}

// Test a SPDY CONNECT through an HTTPS Proxy to a SPDY server (SPDY -> SPDY).
TEST_P(HttpNetworkTransactionTest, HttpsProxySpdyConnectSpdy) {
  SpdyTestUtil spdy_util_wrapped(/*use_priority_header=*/true);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against https proxy server "proxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // CONNECT to www.example.org:443 via SPDY
  spdy::SpdySerializedFrame connect(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));
  // fetch https://www.example.org/ via SPDY
  const char kMyUrl[] = "https://www.example.org/";
  spdy::SpdySerializedFrame get(
      spdy_util_wrapped.ConstructSpdyGet(kMyUrl, 1, LOWEST));
  spdy::SpdySerializedFrame wrapped_get(
      spdy_util_.ConstructWrappedSpdyFrame(get, 1));
  spdy::SpdySerializedFrame conn_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame get_resp(
      spdy_util_wrapped.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame wrapped_get_resp(
      spdy_util_.ConstructWrappedSpdyFrame(get_resp, 1));
  spdy::SpdySerializedFrame body(
      spdy_util_wrapped.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame wrapped_body(
      spdy_util_.ConstructWrappedSpdyFrame(body, 1));
  spdy::SpdySerializedFrame window_update_get_resp(
      spdy_util_.ConstructSpdyWindowUpdate(1, wrapped_get_resp.size()));
  spdy::SpdySerializedFrame window_update_body(
      spdy_util_.ConstructSpdyWindowUpdate(1, wrapped_body.size()));

  MockWrite spdy_writes[] = {
      CreateMockWrite(connect, 0),
      CreateMockWrite(wrapped_get, 2),
      CreateMockWrite(window_update_get_resp, 6),
      CreateMockWrite(window_update_body, 7),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(conn_resp, 1, ASYNC),
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      CreateMockRead(wrapped_get_resp, 4, ASYNC),
      CreateMockRead(wrapped_body, 5, ASYNC),
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

  TestCompletionCallback callback1;

  int rv = trans.Start(&request, callback1.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Allow the SpdyProxyClientSocket's write callback to complete.
  base::RunLoop().RunUntilIdle();
  // Now allow the read of the response to complete.
  spdy_data.Resume();
  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_SSL_TIMES);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ(kUploadData, response_data);
}

// Test a SPDY CONNECT for an HTTPS (non-SPDY) endpoint through an HTTPS
// (non-SPDY) proxy and HTTPS (SPDY) proxy chain (HTTPS -> SPDY -> HTTPS).
TEST_P(HttpNetworkTransactionTest, HttpsNestedProxyMixedConnectSpdy) {
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

  ProxyList proxy_list;
  proxy_list.AddProxyChain(kNestedProxyChain);
  ProxyConfig proxy_config = ProxyConfig::CreateForTesting(proxy_list);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          ProxyConfigWithAnnotation(proxy_config,
                                    TRAFFIC_ANNOTATION_FOR_TESTS));
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // CONNECT to proxy2.test:71 via HTTP.
  const char kProxy2Connect[] =
      "CONNECT proxy2.test:71 HTTP/1.1\r\n"
      "Host: proxy2.test:71\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n\r\n";

  const char kProxy2ConnectResp[] =
      "HTTP/1.1 200 Connection Established\r\n\r\n";

  // CONNECT to www.example.org:443 via SPDY.
  spdy::SpdySerializedFrame endpoint_connect(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));

  spdy::SpdySerializedFrame endpoint_connect_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  // fetch https://www.example.org/ via HTTP.
  // Since this request and response are sent over the tunnel established
  // previously, from a socket-perspective these need to be wrapped as data
  // frames.
  const char kGet[] =
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get(
      spdy_util_.ConstructSpdyDataFrame(1, kGet, false));

  const char kResp[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 10\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get_resp(
      spdy_util_.ConstructSpdyDataFrame(1, kResp, false));

  const char kRespData[] = "1234567890";
  spdy::SpdySerializedFrame wrapped_body(
      spdy_util_.ConstructSpdyDataFrame(1, kRespData, false));

  MockWrite socket_writes[] = {
      MockWrite(ASYNC, 0, kProxy2Connect),
      CreateMockWrite(endpoint_connect, 2),
      CreateMockWrite(wrapped_get, 4),
  };

  MockRead socket_reads[] = {
      MockRead(ASYNC, 1, kProxy2ConnectResp),
      CreateMockRead(endpoint_connect_resp, 3, ASYNC),
      CreateMockRead(wrapped_get_resp, 5, ASYNC),
      CreateMockRead(wrapped_body, 6, ASYNC),
      MockRead(ASYNC, 0, 7),
  };

  SequencedSocketData socket_data(socket_reads, socket_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&socket_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);
  SSLSocketDataProvider ssl3(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl3);

  TestCompletionCallback callback1;

  int rv = trans.Start(&request, callback1.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_SSL_TIMES);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ(kRespData, response_data);
}

// Test an HTTP CONNECT for an HTTPS (non-SPDY) endpoint through an HTTPS (SPDY)
// proxy and HTTPS (non-SPDY) proxy chain (SPDY -> HTTPS -> HTTPS).
TEST_P(HttpNetworkTransactionTest, HttpsNestedProxyMixedConnectHttps) {
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

  ProxyList proxy_list;
  proxy_list.AddProxyChain(kNestedProxyChain);
  ProxyConfig proxy_config = ProxyConfig::CreateForTesting(proxy_list);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          ProxyConfigWithAnnotation(proxy_config,
                                    TRAFFIC_ANNOTATION_FOR_TESTS));
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // CONNECT to proxy2.test:71 via SPDY.
  spdy::SpdySerializedFrame proxy2_connect(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      kProxyServer2.host_port_pair()));

  spdy::SpdySerializedFrame proxy2_connect_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  // CONNECT to www.example.org:443 via HTTPS.
  const char kEndpointConnect[] =
      "CONNECT www.example.org:443 HTTP/1.1\r\n"
      "Host: www.example.org:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n\r\n";

  const char kEndpointConnectResp[] =
      "HTTP/1.1 200 Connection Established\r\n\r\n";

  // Since this request and response are sent over the tunnel established
  // previously, from a socket-perspective these need to be wrapped as data
  // frames.
  spdy::SpdySerializedFrame wrapped_endpoint_connect(
      spdy_util_.ConstructSpdyDataFrame(1, kEndpointConnect, false));
  spdy::SpdySerializedFrame wrapped_endpoint_connect_resp(
      spdy_util_.ConstructSpdyDataFrame(1, kEndpointConnectResp, false));

  // fetch https://www.example.org/ via HTTP.
  // Since this request will go over the SPDY tunnel, it needs to be wrapped as
  // well.
  const char kGet[] =
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get(
      spdy_util_.ConstructSpdyDataFrame(1, kGet, false));

  const char kResp[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 10\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get_resp(
      spdy_util_.ConstructSpdyDataFrame(1, kResp, false));

  const char kRespData[] = "1234567890";
  spdy::SpdySerializedFrame wrapped_body(
      spdy_util_.ConstructSpdyDataFrame(1, kRespData, false));

  MockWrite spdy_writes[] = {
      CreateMockWrite(proxy2_connect, 0),
      CreateMockWrite(wrapped_endpoint_connect, 2),
      CreateMockWrite(wrapped_get, 4),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(proxy2_connect_resp, 1, ASYNC),
      CreateMockRead(wrapped_endpoint_connect_resp, 3, ASYNC),
      CreateMockRead(wrapped_get_resp, 5, ASYNC),
      CreateMockRead(wrapped_body, 6, ASYNC),
      MockRead(ASYNC, 0, 7),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);
  SSLSocketDataProvider ssl3(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl3);

  TestCompletionCallback callback1;

  int rv = trans.Start(&request, callback1.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_SSL_TIMES);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ(kRespData, response_data);
}

// Test a SPDY CONNECT failure through an HTTPS (SPDY) proxy
// (SPDY -> HTTPS/SPDY).
TEST_P(HttpNetworkTransactionTest, HttpsProxySpdyConnectFailure) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against https proxy server "proxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // CONNECT to www.example.org:443 via SPDY.
  spdy::SpdySerializedFrame connect(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));

  MockWrite spdy_writes[] = {
      CreateMockWrite(connect, 0),
      CreateMockWrite(rst, 2),
  };

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyReplyError(1));
  MockRead spdy_reads[] = {
      CreateMockRead(resp, 1, ASYNC),
      // Pause instead of triggering a connection close so that it's more clear
      // which action is causing the tunnel error (the endpoint connect error
      // above).
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      MockRead(ASYNC, 0, 4),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  int rv = trans.Start(&request, callback1.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_TUNNEL_CONNECTION_FAILED));

  // TODO(juliatuttle): Anything else to check here?
}

// Test a SPDY CONNECT failure through two HTTPS (SPDY) proxies where the
// connection to the first proxy fails (SPDY -> HTTPS/SPDY -> HTTPS/SPDY).
TEST_P(HttpNetworkTransactionTest,
       HttpsNestedProxySpdyConnectFirstProxyFailure) {
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

  ProxyList proxy_list;
  proxy_list.AddProxyChain(kNestedProxyChain);
  ProxyConfig proxy_config = ProxyConfig::CreateForTesting(proxy_list);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          ProxyConfigWithAnnotation(proxy_config,
                                    TRAFFIC_ANNOTATION_FOR_TESTS));
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // CONNECT to proxy2.test:71 via SPDY.
  spdy::SpdySerializedFrame proxy2_connect(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      kProxyServer2.host_port_pair()));
  spdy::SpdySerializedFrame proxy2_connect_error_resp(
      spdy_util_.ConstructSpdyReplyError(1));

  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));

  MockWrite spdy_writes[] = {
      CreateMockWrite(proxy2_connect, 0),
      CreateMockWrite(rst, 2),
  };
  MockRead spdy_reads[] = {
      CreateMockRead(proxy2_connect_error_resp, 1, ASYNC),
      // Pause instead of triggering a connection close so that it's more clear
      // which action is causing the tunnel error (the endpoint connect error
      // above).
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      MockRead(ASYNC, 0, 4),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  int rv = trans.Start(&request, callback1.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_TUNNEL_CONNECTION_FAILED));
}

// Test a SPDY CONNECT failure through two HTTPS (SPDY) proxies where the
// connection to the second proxy fails (SPDY -> SPDY -> HTTPS/SPDY).
TEST_P(HttpNetworkTransactionTest,
       HttpsNestedProxySpdyConnectSecondProxyFailure) {
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

  ProxyList proxy_list;
  proxy_list.AddProxyChain(kNestedProxyChain);
  ProxyConfig proxy_config = ProxyConfig::CreateForTesting(proxy_list);

  session_deps_.proxy_resolution_service =
      std::make_unique<ConfiguredProxyResolutionService>(
          std::make_unique<ProxyConfigServiceFixed>(ProxyConfigWithAnnotation(
              proxy_config, TRAFFIC_ANNOTATION_FOR_TESTS)),
          /*resolver_factory=*/nullptr,
          /*net_log=*/nullptr, /*quick_check_enabled=*/true);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // CONNECT to proxy2.test:71 via SPDY.
  spdy::SpdySerializedFrame proxy2_connect(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      kProxyServer2.host_port_pair()));

  spdy::SpdySerializedFrame proxy2_connect_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  // Need to use a new `SpdyTestUtil()` so that the stream parent ID of this
  // request is calculated correctly.
  SpdyTestUtil new_spdy_util;
  // CONNECT to www.example.org:443 via SPDY.
  spdy::SpdySerializedFrame endpoint_connect(new_spdy_util.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));
  spdy::SpdySerializedFrame rst(
      new_spdy_util.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));

  // Since this request and response are sent over the tunnel established
  // previously, from a socket-perspective these need to be wrapped as data
  // frames.
  spdy::SpdySerializedFrame wrapped_endpoint_connect(
      spdy_util_.ConstructSpdyDataFrame(1, endpoint_connect, false));
  spdy::SpdySerializedFrame wrapped_rst(
      spdy_util_.ConstructSpdyDataFrame(1, rst, false));

  spdy::SpdySerializedFrame endpoint_connect_error_resp(
      new_spdy_util.ConstructSpdyReplyError(1));
  spdy::SpdySerializedFrame wrapped_endpoint_connect_error_resp(
      spdy_util_.ConstructSpdyDataFrame(1, endpoint_connect_error_resp, false));

  MockWrite spdy_writes[] = {
      CreateMockWrite(proxy2_connect, 0),
      CreateMockWrite(wrapped_endpoint_connect, 2),
      CreateMockWrite(wrapped_rst, 5),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(proxy2_connect_resp, 1, ASYNC),
      // TODO(crbug.com/41180906): We have to manually delay this read so
      // that the higher-level SPDY stream doesn't get notified of an available
      // read before the write it initiated (the second CONNECT) finishes,
      // triggering a DCHECK.
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      CreateMockRead(wrapped_endpoint_connect_error_resp, 4, ASYNC),
      // Pause instead of triggering a connection close so that it's more clear
      // which action is causing the tunnel error (the endpoint connect error
      // above).
      MockRead(ASYNC, ERR_IO_PENDING, 6),
      MockRead(ASYNC, 0, 7),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  TestCompletionCallback callback1;

  int rv = trans.Start(&request, callback1.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  spdy_data.RunUntilPaused();
  base::RunLoop().RunUntilIdle();
  spdy_data.Resume();

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_TUNNEL_CONNECTION_FAILED));
}

// This method creates a tunnel using `chain1`, proxies an HTTP GET request
// through it to ensure that it has been created successfully, and then creates
// another tunnel using `chain2` to check whether a new socket is used for it.
// This is used to test that no unexpected socket reuse occurs between different
// proxy chains.
void HttpNetworkTransactionTestBase::HttpsNestedProxyNoSocketReuseHelper(
    const ProxyChain& chain1,
    const ProxyChain& chain2) {
  ASSERT_NE(chain1, chain2);

  session_deps_.proxy_delegate = std::make_unique<TestProxyDelegate>();
  auto* proxy_delegate =
      static_cast<TestProxyDelegate*>(session_deps_.proxy_delegate.get());
  proxy_delegate->set_proxy_chain(chain1);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://not-used:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.proxy_resolution_service->SetProxyDelegate(proxy_delegate);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  std::vector<SSLSocketDataProvider> ssl_socket_data_providers;
  std::vector<std::string> connects;
  // Allocate enough space in each of these so that the address of each entry
  // will not change after insertion.
  ssl_socket_data_providers.reserve(chain1.length() + chain2.length());
  connects.reserve(chain1.length() - 1 + chain2.length() - 1);

  std::vector<MockWrite> data_writes1;
  std::vector<MockRead> data_reads1;

  for (size_t proxy_index = 1; proxy_index < chain1.length(); ++proxy_index) {
    const auto& proxy_host_port_pair_string =
        chain1.GetProxyServer(proxy_index).host_port_pair().ToString();
    connects.push_back(
        base::StringPrintf("CONNECT %s HTTP/1.1\r\n"
                           "Host: %s\r\n"
                           "Proxy-Connection: keep-alive\r\n"
                           "User-Agent: test-ua\r\n\r\n",
                           proxy_host_port_pair_string.c_str(),
                           proxy_host_port_pair_string.c_str()));
    data_writes1.emplace_back(connects.back().c_str());
    data_reads1.emplace_back("HTTP/1.1 200 Connection Established\r\n\r\n");
  }

  if (chain1.is_multi_proxy()) {
    // Since this is a multi-proxy chain, CONNECT to the endpoint.
    data_writes1.emplace_back(
        "CONNECT www.example.org:80 HTTP/1.1\r\n"
        "Host: www.example.org:80\r\n"
        "Proxy-Connection: keep-alive\r\n"
        "User-Agent: test-ua\r\n\r\n");
    data_reads1.emplace_back("HTTP/1.1 200 Connection Established\r\n\r\n");

    // Make the request to the endpoint.
    data_writes1.emplace_back(
        "GET / HTTP/1.1\r\n"
        "Host: www.example.org\r\n"
        "Connection: keep-alive\r\n\r\n");
  } else {
    // For a single-proxy chain, use GET.
    data_writes1.emplace_back(
        "GET http://www.example.org/ HTTP/1.1\r\n"
        "Host: www.example.org\r\n"
        "Proxy-Connection: keep-alive\r\n"
        "User-Agent: test-ua\r\n\r\n");
  }

  data_reads1.emplace_back("HTTP/1.1 200 OK\r\n");
  data_reads1.emplace_back(SYNCHRONOUS, OK);

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  for (size_t proxy_index = 0; proxy_index < chain1.length(); ++proxy_index) {
    ssl_socket_data_providers.emplace_back(ASYNC, OK);
    session_deps_.socket_factory->AddSSLSocketDataProvider(
        &ssl_socket_data_providers.back());
  }

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, session.get());

  int rv = trans1.Start(&request, callback1.callback(),
                        NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans1.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(chain1, response->proxy_chain);

  // Now use the second proxy chain. We expect that it will use a new
  // socket, so to test this we will create a new socket data provider and
  // expect that this gets used instead of the one created above for the
  // first transaction.
  proxy_delegate->set_proxy_chain(chain2);

  std::vector<MockWrite> data_writes2;
  std::vector<MockRead> data_reads2;

  for (size_t proxy_index = 1; proxy_index < chain2.length(); ++proxy_index) {
    const auto& proxy_host_port_pair_string =
        chain2.GetProxyServer(proxy_index).host_port_pair().ToString();
    connects.push_back(
        base::StringPrintf("CONNECT %s HTTP/1.1\r\n"
                           "Host: %s\r\n"
                           "Proxy-Connection: keep-alive\r\n"
                           "User-Agent: test-ua\r\n\r\n",
                           proxy_host_port_pair_string.c_str(),
                           proxy_host_port_pair_string.c_str()));
    data_writes2.emplace_back(connects.back().c_str());
    data_reads2.emplace_back("HTTP/1.1 200 Connection Established\r\n\r\n");
  }

  if (chain2.is_multi_proxy()) {
    // Since this is a multi-proxy chain, CONNECT to the endpoint.
    data_writes2.emplace_back(
        "CONNECT www.example.org:80 HTTP/1.1\r\n"
        "Host: www.example.org:80\r\n"
        "Proxy-Connection: keep-alive\r\n"
        "User-Agent: test-ua\r\n\r\n");
    data_reads2.emplace_back("HTTP/1.1 200 Connection Established\r\n\r\n");

    // Make the request to the endpoint.
    data_writes2.emplace_back(
        "GET / HTTP/1.1\r\n"
        "Host: www.example.org\r\n"
        "Connection: keep-alive\r\n\r\n");
  } else {
    // For a single-proxy chain, use GET.
    data_writes2.emplace_back(
        "GET http://www.example.org/ HTTP/1.1\r\n"
        "Host: www.example.org\r\n"
        "Proxy-Connection: keep-alive\r\n\r\n");
  }
  data_reads2.emplace_back("HTTP/1.1 200 OK\r\n");
  data_reads2.emplace_back(SYNCHRONOUS, OK);

  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  for (size_t proxy_index = 0; proxy_index < c
"""


```