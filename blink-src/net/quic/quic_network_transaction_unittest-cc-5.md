Response:
The user wants a summary of the functionality of the provided C++ code snippet from `net/quic/quic_network_transaction_unittest.cc`. They are particularly interested in:

1. **Functionality:** What does this code do?
2. **JavaScript Relation:** Does it interact with JavaScript, and if so, how?
3. **Logical Inference:**  Can I infer input/output behavior?
4. **Common Errors:** What user or programming errors might lead to this code being executed?
5. **User Journey:** How does a user's action lead to this code?
6. **Part Summary:**  A concise summary of this specific code section.

Let's break down the code and address each point.

**Code Analysis:**

The code consists of several test cases (`TEST_P`) within a larger unit test class (`QuicNetworkTransactionTest`). These test cases focus on how the Chromium network stack handles QUIC connections, especially in relation to alternative services (Alt-Svc). Key patterns emerge:

* **Mocking:** The tests heavily rely on mocking network behavior using `MockRead`, `MockWrite`, `StaticSocketDataProvider`, and `MockQuicData`. This allows for controlled simulation of network interactions.
* **Alternative Services (Alt-Svc):** A central theme is testing how the browser handles Alt-Svc headers, which advertise the availability of QUIC on a given domain.
* **Connection Pooling:** Several tests verify that the browser correctly reuses existing QUIC connections for subsequent requests to the same origin or destination, even across different origins in some cases.
* **Network Isolation Keys:**  The code includes tests related to network isolation keys and how they impact Alt-Svc behavior.
* **Zero-RTT:** One test specifically examines the behavior of zero round-trip time (0-RTT) QUIC connections.
* **Error Handling:**  Some tests simulate scenarios where the QUIC connection hangs or is broken.

**Addressing the User's Points:**

1. **Functionality:** The code tests the network stack's ability to:
    * Parse and respect Alt-Svc headers to establish QUIC connections.
    * Select appropriate QUIC sessions based on availability, origin, and destination.
    * Handle situations with multiple alternative services.
    * Pool QUIC connections effectively.
    * Handle network isolation keys in the context of Alt-Svc.
    * Recover from hung or broken QUIC connections.
    * Utilize 0-RTT QUIC connections.

2. **JavaScript Relation:**  While this specific C++ code doesn't directly execute JavaScript, the functionality it tests is crucial for how websites using QUIC (and therefore potentially HTTP/3) perform in the browser. JavaScript making network requests (e.g., using `fetch` or `XMLHttpRequest`) will indirectly benefit from the correct behavior of this code. If this code has bugs, a JavaScript application might experience slower loading times or connection errors when QUIC is expected.

3. **Logical Inference:**

    * **Assumption:** A website at `https://example.org` sends an Alt-Svc header indicating QUIC is available on port 443.
    * **Input:** The browser makes an initial HTTP request to `https://example.org`.
    * **Output:** The browser parses the Alt-Svc header, attempts a QUIC handshake, and if successful, uses QUIC for subsequent requests to that domain (or potentially other related domains depending on pooling rules).

    * **Assumption:** A website advertises multiple Alt-Svc entries, including one matching an existing QUIC connection.
    * **Input:** The browser needs to make a new request.
    * **Output:** The browser will prioritize using the existing QUIC connection advertised in the Alt-Svc list.

4. **Common Errors:**

    * **User Error:** A user might experience issues if their network blocks UDP traffic (the underlying protocol for QUIC). This would prevent QUIC connections from being established, even if the server advertises it. The browser would then fall back to TCP.
    * **Programming Error (Server-side):** An incorrectly configured web server might send an invalid Alt-Svc header. This could lead the browser to attempt QUIC connections to the wrong host or port, causing connection failures.
    * **Programming Error (Browser-side):** Bugs in this C++ code could cause the browser to misinterpret Alt-Svc headers, fail to pool connections correctly, or not handle errors gracefully, leading to performance issues or connection errors.

5. **User Journey (Debugging Clues):**

    1. **User navigates to a website (e.g., `https://example.org`) in the browser.**
    2. **The browser sends an initial HTTP request to the server.**
    3. **The server's HTTP response includes an `Alt-Svc` header indicating QUIC support.**
    4. **The browser parses this header.**
    5. **The browser attempts a QUIC connection to the specified host and port.**
    6. **If the QUIC connection is successful, subsequent requests to this domain (or potentially related domains) might use QUIC.**

    If debugging QUIC-related issues, inspecting the network logs in the browser's developer tools would show whether a QUIC connection was attempted and whether it succeeded or failed. Looking for `Alt-Svc` headers in the initial HTTP response is also a key step. Network capture tools like Wireshark could provide even more detailed information about the QUIC handshake.

6. **Part Summary:** This section of the unit test focuses on verifying the correct implementation of alternative service (Alt-Svc) handling for QUIC in the Chromium network stack. It tests scenarios related to connection pooling, selecting the right QUIC session, handling different ports, confirming and marking broken alternative services, and the interaction with network isolation keys. It also includes a test for zero round-trip time (0-RTT) connections and how the browser handles hung alternative service connections.


这是文件 `net/quic/quic_network_transaction_unittest.cc` 的第 6 部分，主要功能是测试 Chromium 网络栈中关于 QUIC 协议与 HTTP 的交互，特别是关于 **Alternative Services (Alt-Svc)** 的处理。 这部分代码专注于测试浏览器如何利用服务器提供的 Alt-Svc 信息来建立和复用 QUIC 连接。

**功能归纳:**

1. **利用已有的 QUIC 会话:**  测试当服务器通告多个可用的 QUIC 服务时，浏览器是否能正确选择已存在的 QUIC 会话进行复用，避免重复建立连接。如果不存在可复用的 QUIC 会话，则应该使用 Alt-Svc 列表中第一个可用的服务。
2. **基于 Origin 进行连接池化:** 即使 Alternative Service 指向不同的目的地，只要 Origin (域名和端口) 相同，浏览器也应该能够复用已有的 QUIC 会话。
3. **基于 Destination 进行连接池化:**  即使 Origin 不同，只要目的地 (IP 地址或域名和端口) 和证书匹配，浏览器也应该能够复用已有的 QUIC 会话，并且即使匹配的 Alt-Svc 不是列表中的第一个也能正确选择。
4. **共享已有的 QUIC 会话 (证书有效):**  当多个 Origin 列出了相同的 Alternative Services，并且存在一个由其他 Origin 发起的有效 QUIC 会话时，浏览器应该能够复用这个已有的 QUIC 会话。
5. **Alternative Service 使用不同的端口:** 测试浏览器能否正确解析并使用 Alt-Svc 中指定的非标准 QUIC 端口。
6. **确认 Alternative Service 可用性:** 测试在通过 QUIC 成功连接后，浏览器会标记该 Alternative Service 为可用状态，取消之前的 "已损坏" 标记。
7. **确认 Alternative Service 可用性 (Network Isolation Key):**  在启用 Network Isolation Key 的情况下，测试浏览器是否能正确地根据不同的 Network Isolation Key 独立地标记和确认 Alternative Service 的可用性。
8. **HTTPS 使用 QUIC Alternative Service:** 测试对于 HTTPS 请求，浏览器能否正确利用 Alt-Svc 信息建立 QUIC 连接。
9. **处理挂起的 Alternative Service:** 测试当尝试使用 QUIC 进行连接时发生挂起，浏览器是否能回退到标准的 HTTP 连接。
10. **Zero-RTT 和 HTTP 竞争:** 测试在 0-RTT 的情况下，QUIC 连接能否与标准的 HTTP 连接进行竞争，并最终优先使用 QUIC。

**与 Javascript 的关系:**

虽然这段 C++ 代码本身不涉及直接的 Javascript 代码执行，但它测试的网络栈功能是 Javascript 网络请求的基础。

* **`fetch()` API 和 `XMLHttpRequest`:**  当 Javascript 代码使用 `fetch()` 或 `XMLHttpRequest` 发起网络请求时，底层的 Chromium 网络栈会根据服务器的配置和网络状态来决定是否使用 QUIC。这段代码测试了网络栈如何根据 Alt-Svc 信息来选择使用 QUIC，这直接影响了 Javascript 发起的网络请求的性能和效率。
* **举例说明:**
    * 假设一个网站 `https://example.com` 在 HTTP 响应头中设置了 `Alt-Svc: h3=":443"`。
    * 当 Javascript 代码执行 `fetch('https://example.com/data.json')` 时，这段 C++ 代码测试的逻辑会判断是否应该尝试建立到 `example.com:443` 的 QUIC 连接。
    * 如果测试通过，网络栈就能正确利用 Alt-Svc 信息，并使用 QUIC 加速 Javascript 发起的请求。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  一个 HTTPS 网站 `https://test.example.org` 的 HTTP 响应头包含 `Alt-Svc: h3-29=":443"`。 用户通过浏览器访问该网站的某个页面，页面上的 Javascript 代码发起了一个 `fetch('https://test.example.org/api/data')` 请求。
* **输出:**  Chromium 网络栈会解析 `Alt-Svc` 头，并尝试建立到 `test.example.org:443` 的 HTTP/3 (基于 QUIC) 连接。如果连接成功，Javascript 的 `fetch` 请求将会通过 QUIC 进行传输，从而可能获得更低的延迟和更高的性能。

**用户或编程常见的使用错误:**

* **用户错误:**
    * **网络防火墙阻止 UDP 流量:** QUIC 协议基于 UDP，如果用户的网络防火墙阻止了 UDP 流量，浏览器将无法建立 QUIC 连接，即使服务器支持。用户可能会遇到连接超时或回退到 TCP 的情况。
* **编程错误:**
    * **服务器配置错误的 Alt-Svc 头:**  如果服务器配置了错误的 `Alt-Svc` 头，例如指定了错误的端口或协议，浏览器可能会尝试连接到不存在的服务，导致连接失败。
    * **浏览器端 QUIC 功能被禁用:**  用户或程序可能禁用了浏览器的 QUIC 功能，导致即使服务器支持，也不会尝试建立 QUIC 连接。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在浏览器地址栏输入一个 HTTPS 网址，例如 `https://example.com`，并按下回车键。**
2. **浏览器发起一个 HTTP 请求到 `example.com`。**
3. **服务器返回 HTTP 响应，其中包含 `Alt-Svc` 头，例如 `Alt-Svc: h3-29=":443"`。**
4. **Chromium 网络栈的 HTTP 模块接收到响应头，并解析 `Alt-Svc` 头信息。**
5. **网络栈的 QUIC 模块根据解析到的信息，尝试建立到 `example.com:443` 的 QUIC 连接。**
6. **这段 `quic_network_transaction_unittest.cc` 中的测试代码模拟了上述过程中的各种场景，例如：**
    *  服务器返回不同的 `Alt-Svc` 信息。
    *  网络中存在已有的 QUIC 连接。
    *  QUIC 连接建立成功或失败。
    *  存在多个可用的 Alternative Services。
7. **开发者可以通过以下方式进行调试:**
    * **Chrome DevTools 的 Network 面板:**  查看请求的 `Protocol` 列，确认是否使用了 `h3` (HTTP/3 over QUIC)。
    * **Chrome DevTools 的 `chrome://net-internals/#quic`:** 查看当前活跃的 QUIC 会话信息。
    * **抓包工具 (如 Wireshark):**  捕获网络数据包，分析 QUIC 连接的建立过程。
    * **查看 Chrome 的 NetLog (`chrome://net-export/`):**  导出网络日志，其中包含了更详细的网络事件信息，可以帮助分析 QUIC 连接的建立和使用情况。

**总结第 6 部分的功能:**

这部分单元测试主要验证了 Chromium 网络栈在处理 HTTP 响应中的 `Alt-Svc` 头时，能够正确地建立和管理 QUIC 连接，并能够根据不同的情况 (例如已有的连接、相同的 Origin 或 Destination) 进行连接池化，以及处理连接失败的情况。 这些测试确保了浏览器能够有效地利用 QUIC 协议来提升网络性能。

Prompt: 
```
这是目录为net/quic/quic_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共13部分，请归纳一下它的功能

"""

      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(altsvc_header.c_str()),
      MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();

  SendRequestAndExpectHttpResponse(kHttpRespData);
  SendRequestAndExpectHttpResponse(kHttpRespData);
}

// When multiple alternative services are advertised, HttpStreamFactory should
// select the alternative service which uses existing QUIC session if available.
// If no existing QUIC session can be used, use the first alternative service
// from the list.
TEST_P(QuicNetworkTransactionTest, UseExistingAlternativeServiceForQuic) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  context_.params()->allow_remote_alt_svc = true;
  std::string alt_svc_header = base::StrCat(
      {"Alt-Svc: ",
       GenerateQuicAltSvcHeaderValue({version_}, "foo.example.org", 443), ",",
       GenerateQuicAltSvcHeaderValue({version_}, 444), "\r\n\r\n"});
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(alt_svc_header.data()),
      MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  AddCertificate(&ssl_data_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  // First QUIC request data.
  // Open a session to foo.example.org:443 using the first entry of the
  // alternative service list.
  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));

  std::string alt_svc_list = base::StrCat(
      {GenerateQuicAltSvcHeaderValue({version_}, "mail.example.org", 444), ",",
       GenerateQuicAltSvcHeaderValue({version_}, "foo.example.org", 443), ",",
       GenerateQuicAltSvcHeaderValue({version_}, "bar.example.org", 445)});
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200", alt_svc_list)));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));

  // Second QUIC request data.
  // Connection pooling, using existing session, no need to include version
  // as version negotiation has been completed.
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(1), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 3, GetNthClientInitiatedBidirectionalStreamId(1), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 4, GetNthClientInitiatedBidirectionalStreamId(1), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 4, 3));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();
  QuicSessionPoolPeer::SetAlarmFactory(
      session_->quic_session_pool(),
      std::make_unique<QuicChromiumAlarmFactory>(quic_task_runner_.get(),
                                                 context_.clock()));

  SendRequestAndExpectHttpResponse(kHttpRespData);

  SendRequestAndExpectQuicResponse(kQuicRespData);
  SendRequestAndExpectQuicResponse(kQuicRespData);
}

// Pool to existing session with matching quic::QuicServerId
// even if alternative service destination is different.
TEST_P(QuicNetworkTransactionTest, PoolByOrigin) {
  context_.params()->allow_remote_alt_svc = true;
  MockQuicData mock_quic_data(version_);

  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  // First request.
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));

  // Second request.
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(1), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 3, GetNthClientInitiatedBidirectionalStreamId(1), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 4, GetNthClientInitiatedBidirectionalStreamId(1), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 4, 3));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();
  AddHangingNonAlternateProtocolSocketData();

  CreateSession();
  QuicSessionPoolPeer::SetAlarmFactory(
      session_->quic_session_pool(),
      std::make_unique<QuicChromiumAlarmFactory>(quic_task_runner_.get(),
                                                 context_.clock()));

  const char kDestination1[] = "first.example.com";
  const char kDestination2[] = "second.example.com";

  // Set up alternative service entry to `kDestination1`.
  url::SchemeHostPort server(request_.url);
  AlternativeService alternative_service(kProtoQUIC, kDestination1, 443);
  base::Time expiration = base::Time::Now() + base::Days(1);
  http_server_properties_->SetQuicAlternativeService(
      server, NetworkAnonymizationKey(), alternative_service, expiration,
      supported_versions_);
  // First request opens connection to `kDestination1`
  // with quic::QuicServerId.host() == kDefaultServerHostName.
  SendRequestAndExpectQuicResponse(kQuicRespData);

  // Set up alternative service entry to a different destination.
  alternative_service = AlternativeService(kProtoQUIC, kDestination2, 443);
  http_server_properties_->SetQuicAlternativeService(
      server, NetworkAnonymizationKey(), alternative_service, expiration,
      supported_versions_);
  // Second request pools to existing connection with same quic::QuicServerId,
  // even though alternative service destination is different.
  SendRequestAndExpectQuicResponse(kQuicRespData);
}

// Pool to existing session with matching destination and matching certificate
// even if origin is different, and even if the alternative service with
// matching destination is not the first one on the list.
TEST_P(QuicNetworkTransactionTest, PoolByDestination) {
  context_.params()->allow_remote_alt_svc = true;
  GURL origin1 = request_.url;
  GURL origin2("https://www.example.org/");
  ASSERT_NE(origin1.host(), origin2.host());

  MockQuicData mock_quic_data(version_);

  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  // First request.
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));

  // Second request.
  QuicTestPacketMaker client_maker2(
      version_,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), origin2.host(), quic::Perspective::IS_CLIENT, true);
  QuicTestPacketMaker server_maker2(
      version_,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), origin2.host(), quic::Perspective::IS_SERVER, false);
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(1), true,
          GetRequestHeaders("GET", "https", "/", &client_maker2)));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 3, GetNthClientInitiatedBidirectionalStreamId(1), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 4, GetNthClientInitiatedBidirectionalStreamId(1), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 4, 3));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();
  AddHangingNonAlternateProtocolSocketData();

  CreateSession();
  QuicSessionPoolPeer::SetAlarmFactory(
      session_->quic_session_pool(),
      std::make_unique<QuicChromiumAlarmFactory>(quic_task_runner_.get(),
                                                 context_.clock()));

  const char kDestination1[] = "first.example.com";
  const char kDestination2[] = "second.example.com";

  // Set up alternative service for |origin1|.
  AlternativeService alternative_service1(kProtoQUIC, kDestination1, 443);
  base::Time expiration = base::Time::Now() + base::Days(1);
  http_server_properties_->SetQuicAlternativeService(
      url::SchemeHostPort(origin1), NetworkAnonymizationKey(),
      alternative_service1, expiration, supported_versions_);

  // Set up multiple alternative service entries for |origin2|,
  // the first one with a different destination as for |origin1|,
  // the second one with the same.  The second one should be used,
  // because the request can be pooled to that one.
  AlternativeService alternative_service2(kProtoQUIC, kDestination2, 443);
  AlternativeServiceInfoVector alternative_services;
  alternative_services.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          alternative_service2, expiration,
          context_.params()->supported_versions));
  alternative_services.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          alternative_service1, expiration,
          context_.params()->supported_versions));
  http_server_properties_->SetAlternativeServices(url::SchemeHostPort(origin2),
                                                  NetworkAnonymizationKey(),
                                                  alternative_services);
  // First request opens connection to `kDestination1`
  // with quic::QuicServerId.host() == origin1.host().
  SendRequestAndExpectQuicResponse(kQuicRespData);

  // Second request pools to existing connection with same destination,
  // because certificate matches, even though quic::QuicServerId is different.
  request_.url = origin2;

  SendRequestAndExpectQuicResponse(kQuicRespData);
}

// Multiple origins have listed the same alternative services. When there's a
// existing QUIC session opened by a request to other origin,
// if the cert is valid, should select this QUIC session to make the request
// if this is also the first existing QUIC session.
TEST_P(QuicNetworkTransactionTest,
       UseSharedExistingAlternativeServiceForQuicWithValidCert) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  context_.params()->allow_remote_alt_svc = true;
  // Default cert is valid for *.example.org

  // HTTP data for request to www.example.org.
  const char kWwwHttpRespData[] = "hello world from www.example.org";
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(alt_svc_header_.data()),
      MockRead(kWwwHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  AddCertificate(&ssl_data_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  // HTTP data for request to mail.example.org.
  std::string alt_svc_header2 = base::StrCat(
      {"Alt-Svc: ", GenerateQuicAltSvcHeaderValue({version_}, 444), ",",
       GenerateQuicAltSvcHeaderValue({version_}, "www.example.org", 443),
       "\r\n\r\n"});
  const char kMailHttpRespData[] = "hello world from mail.example.org";
  MockRead http_reads2[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(alt_svc_header2.data()),
      MockRead(kMailHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data2(http_reads2, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data2);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  QuicTestPacketMaker client_maker(
      version_,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), "mail.example.org", quic::Perspective::IS_CLIENT, true);
  server_maker_.set_hostname("www.example.org");
  client_maker_->set_hostname("www.example.org");
  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  // First QUIC request data.
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));

  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));
  const char kMailQuicRespData[] = "hello from mail QUIC!";
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kMailQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));
  // Second QUIC request data.
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(1), true,
          GetRequestHeaders("GET", "https", "/", &client_maker)));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 3, GetNthClientInitiatedBidirectionalStreamId(1), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 4, GetNthClientInitiatedBidirectionalStreamId(1), true,
                 ConstructDataFrame(kMailQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 4, 3));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();
  QuicSessionPoolPeer::SetAlarmFactory(
      session_->quic_session_pool(),
      std::make_unique<QuicChromiumAlarmFactory>(quic_task_runner_.get(),
                                                 context_.clock()));

  // Send two HTTP requests, responses set up alt-svc lists for the origins.
  request_.url = GURL("https://www.example.org/");
  SendRequestAndExpectHttpResponse(kWwwHttpRespData);
  request_.url = GURL("https://mail.example.org/");
  SendRequestAndExpectHttpResponse(kMailHttpRespData);

  // Open a QUIC session to mail.example.org:443 when making request
  // to mail.example.org.
  request_.url = GURL("https://www.example.org/");
  SendRequestAndExpectQuicResponse(kMailQuicRespData);

  // Uses the existing QUIC session when making request to www.example.org.
  request_.url = GURL("https://mail.example.org/");
  SendRequestAndExpectQuicResponse(kMailQuicRespData);
}

TEST_P(QuicNetworkTransactionTest, AlternativeServiceDifferentPort) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  std::string alt_svc_header =
      base::StrCat({"Alt-Svc: ", GenerateQuicAltSvcHeaderValue({version_}, 137),
                    "\r\n\r\n"});
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(alt_svc_header.data()),
      MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  AddCertificate(&ssl_data_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();

  SendRequestAndExpectHttpResponse(kHttpRespData);

  url::SchemeHostPort http_server("https", kDefaultServerHostName, 443);
  AlternativeServiceInfoVector alternative_service_info_vector =
      http_server_properties_->GetAlternativeServiceInfos(
          http_server, NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  const AlternativeService alternative_service =
      alternative_service_info_vector[0].alternative_service();
  EXPECT_EQ(kProtoQUIC, alternative_service.protocol);
  EXPECT_EQ(kDefaultServerHostName, alternative_service.host);
  EXPECT_EQ(137, alternative_service.port);
}

TEST_P(QuicNetworkTransactionTest, ConfirmAlternativeService) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(alt_svc_header_.data()),
      MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  AddCertificate(&ssl_data_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();

  AlternativeService alternative_service(kProtoQUIC,
                                         HostPortPair::FromURL(request_.url));
  http_server_properties_->MarkAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey());
  EXPECT_TRUE(http_server_properties_->WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));

  SendRequestAndExpectHttpResponse(kHttpRespData);
  SendRequestAndExpectQuicResponse(kQuicRespData);

  mock_quic_data.Resume();

  EXPECT_FALSE(http_server_properties_->WasAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey()));
  EXPECT_NE(nullptr, http_server_properties_->GetServerNetworkStats(
                         url::SchemeHostPort("https", request_.url.host(), 443),
                         NetworkAnonymizationKey()));
}

TEST_P(QuicNetworkTransactionTest,
       ConfirmAlternativeServiceWithNetworkIsolationKey) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const net::NetworkIsolationKey kNetworkIsolationKey1(kSite1, kSite1);
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const net::NetworkIsolationKey kNetworkIsolationKey2(kSite2, kSite2);
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);

  base::test::ScopedFeatureList feature_list;
  std::vector<base::test::FeatureRef> enable_features;
  std::vector<base::test::FeatureRef> disable_features;
  enable_features.emplace_back(
      features::kPartitionConnectionsByNetworkIsolationKey);
  // Disable AsyncQuicSession for HappyEyeballsV3 because AsyncQuicSession
  // delays QUIC session establishment and requires another mock TCP socket
  // in the HappyEyeballsV3 code path.
  // TODO(crbug.com/346835898): Avoid disable AsyncQuicSession if possible.
  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    disable_features.emplace_back(features::kAsyncQuicSession);
  }
  feature_list.InitWithFeatures(enable_features, disable_features);

  // Since HttpServerProperties caches the feature value, have to create a new
  // one.
  http_server_properties_ = std::make_unique<HttpServerProperties>();

  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(alt_svc_header_.data()),
      MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  AddCertificate(&ssl_data_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  CreateSession();

  AlternativeService alternative_service(kProtoQUIC,
                                         HostPortPair::FromURL(request_.url));
  http_server_properties_->MarkAlternativeServiceRecentlyBroken(
      alternative_service, kNetworkAnonymizationKey1);
  http_server_properties_->MarkAlternativeServiceRecentlyBroken(
      alternative_service, kNetworkAnonymizationKey2);
  EXPECT_TRUE(http_server_properties_->WasAlternativeServiceRecentlyBroken(
      alternative_service, kNetworkAnonymizationKey1));
  EXPECT_TRUE(http_server_properties_->WasAlternativeServiceRecentlyBroken(
      alternative_service, kNetworkAnonymizationKey2));

  request_.network_isolation_key = kNetworkIsolationKey1;
  request_.network_anonymization_key = kNetworkAnonymizationKey1;
  SendRequestAndExpectHttpResponse(kHttpRespData);
  SendRequestAndExpectQuicResponse(kQuicRespData);

  mock_quic_data.Resume();

  EXPECT_FALSE(http_server_properties_->WasAlternativeServiceRecentlyBroken(
      alternative_service, kNetworkAnonymizationKey1));
  EXPECT_NE(nullptr, http_server_properties_->GetServerNetworkStats(
                         url::SchemeHostPort("https", request_.url.host(), 443),
                         kNetworkAnonymizationKey1));
  EXPECT_TRUE(http_server_properties_->WasAlternativeServiceRecentlyBroken(
      alternative_service, kNetworkAnonymizationKey2));
  EXPECT_EQ(nullptr, http_server_properties_->GetServerNetworkStats(
                         url::SchemeHostPort("https", request_.url.host(), 443),
                         kNetworkAnonymizationKey2));
}

TEST_P(QuicNetworkTransactionTest, UseAlternativeServiceForQuicForHttps) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(alt_svc_header_.data()),
      MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame("hello!")));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));
  mock_quic_data.AddRead(SYNCHRONOUS, 0);  // EOF

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();

  // TODO(rtenneti): Test QUIC over HTTPS, GetSSLInfo().
  SendRequestAndExpectHttpResponse(kHttpRespData);
}

TEST_P(QuicNetworkTransactionTest, HungAlternativeService) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);

  MockWrite http_writes[] = {
      MockWrite(SYNCHRONOUS, 0, "GET / HTTP/1.1\r\n"),
      MockWrite(SYNCHRONOUS, 1, "Host: mail.example.org\r\n"),
      MockWrite(SYNCHRONOUS, 2, "Connection: keep-alive\r\n\r\n")};

  MockRead http_reads[] = {MockRead(SYNCHRONOUS, 3, "HTTP/1.1 200 OK\r\n"),
                           MockRead(SYNCHRONOUS, 4, alt_svc_header_.data()),
                           MockRead(SYNCHRONOUS, 5, kHttpRespData),
                           MockRead(SYNCHRONOUS, OK, 6)};

  SequencedSocketData http_data(http_reads, http_writes);
  socket_factory_.AddSocketDataProvider(&http_data);
  AddCertificate(&ssl_data_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  // The QUIC transaction will not be allowed to complete.
  MockWrite quic_writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  MockRead quic_reads[] = {
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0),
  };
  SequencedSocketData quic_data(quic_reads, quic_writes);
  socket_factory_.AddSocketDataProvider(&quic_data);

  // The HTTP transaction will complete.
  SequencedSocketData http_data2(http_reads, http_writes);
  socket_factory_.AddSocketDataProvider(&http_data2);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();

  // Run the first request.
  SendRequestAndExpectHttpResponse(kHttpRespData);
  ASSERT_TRUE(http_data.AllReadDataConsumed());
  ASSERT_TRUE(http_data.AllWriteDataConsumed());

  // Now run the second request in which the QUIC socket hangs,
  // and verify the the transaction continues over HTTP.
  SendRequestAndExpectHttpResponse(kHttpRespData);
  base::RunLoop().RunUntilIdle();

  ASSERT_TRUE(http_data2.AllReadDataConsumed());
  ASSERT_TRUE(http_data2.AllWriteDataConsumed());
  ASSERT_TRUE(quic_data.AllReadDataConsumed());
}

TEST_P(QuicNetworkTransactionTest, ZeroRTTWithHttpRace) {
  MockQuicData mock_quic_data(version_);
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // Pause
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  CreateSession();
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  EXPECT_THAT(trans.Start(&request_, callback.callback(), net_log_with_source_),
              IsError(ERR_IO_PENDING));
  // Complete host resolution in next message loop so that QUIC job could
  // proceed.
  base::RunLoop().RunUntilIdle();
  // Explicitly confirm the handshake.
  crypt
"""


```