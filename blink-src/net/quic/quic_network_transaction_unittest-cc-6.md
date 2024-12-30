Response:
The user wants to understand the functionality of the provided C++ code snippet from `net/quic/quic_network_transaction_unittest.cc`. This file seems to contain unit tests for QUIC network transactions within the Chromium network stack.

Here's a breakdown of the thought process to address the user's request:

1. **Identify the Core Functionality:** The filename `quic_network_transaction_unittest.cc` strongly suggests that this file contains unit tests for the `QuicNetworkTransaction` class. Unit tests aim to verify the correct behavior of specific units of code, in this case, how QUIC transactions are handled.

2. **Analyze the Code Snippet:** The provided snippet contains several `TEST_P` functions. `TEST_P` in Google Test indicates parameterized tests, meaning these tests are run with different sets of input parameters (likely different QUIC versions in this context, as suggested by `version_`).

3. **Infer Test Scenarios:** Each `TEST_P` function name hints at the specific scenario being tested:
    * `ZeroRTTNoRace`: Tests successful 0-RTT connection without racing with HTTP.
    * `ZeroRTTWithProxy`: Tests behavior when a proxy is involved with 0-RTT.
    * `ZeroRTTWithConfirmationRequired`: Tests 0-RTT behavior when confirmation is required.
    * `ZeroRTTWithTooEarlyResponse`: Tests handling of "425 Too Early" responses in 0-RTT.
    * `ZeroRTTWithMultipleTooEarlyResponse`: Similar to the above but with multiple 425 responses.
    * `LogGranularQuicErrorCodeOnQuicProtocolErrorLocal/Remote`: Tests logging of specific QUIC error codes.
    * `RstStreamErrorHandling/BeforeHeaders`: Tests how RST_STREAM frames are handled.
    * `BrokenAlternateProtocol`: Tests scenarios where the QUIC connection fails, and the fallback to TCP occurs.
    * `BrokenAlternateProtocolWithNetworkIsolationKey`: Similar to the above but with Network Isolation Keys.
    * `BrokenAlternateProtocolReadError`: Tests failure due to a read error in the QUIC connection.
    * `NoBrokenAlternateProtocolIfTcpFails`: Tests that if TCP also fails, it's not considered a "broken" QUIC connection in the same way.
    * `DelayTCPOnStartWithQuicSupportOnSameIP`: Tests the behavior of delaying TCP connections when QUIC has recently worked on the same IP.

4. **Relate to JavaScript (If Applicable):** QUIC is a transport protocol that sits below HTTP. While JavaScript doesn't directly interact with QUIC at a low level in a browser, it uses the browser's networking stack. Therefore, the success or failure of these QUIC transactions *affects* the performance and reliability of web requests initiated by JavaScript code. Examples could be:
    * Faster page loads due to 0-RTT.
    * More resilient connections due to QUIC's connection migration features (though not directly tested here).
    * Potential fallback to TCP if QUIC fails, ensuring the request still completes.

5. **Explain Logical Reasoning (Hypothetical Input/Output):** For tests involving specific scenarios like "ZeroRTTWithTooEarlyResponse,"  the input is the mocked QUIC handshake and data exchange. The output is the expected behavior of the `HttpNetworkTransaction`, including the HTTP response code and data, and any internal state changes (e.g., the session being marked as needing confirmation). For error cases, the expected output is an error code.

6. **Identify Common User/Programming Errors:**  These unit tests implicitly highlight potential errors:
    * Server misconfiguration leading to "425 Too Early" responses.
    * Network issues causing connection resets or errors.
    * Incorrect handling of QUIC protocol errors in the client implementation.
    * Issues with proxy configurations when using QUIC.

7. **Describe User Steps to Reach the Code:** This involves tracing the user's action from a high level down to the execution of this code:
    * User opens a web page (initiates a network request).
    * The browser checks if QUIC is available for the target server (based on previous successful connections or Alt-Svc hints).
    * If QUIC is a possibility, the `HttpNetworkTransaction` might attempt a QUIC connection.
    * The code being analyzed represents the unit tests for that `HttpNetworkTransaction`'s QUIC handling logic.

8. **Summarize the Functionality (Part 7 of 13):** Considering the test cases in this specific snippet, the primary focus of *this part* seems to be testing various 0-RTT connection scenarios, error handling during QUIC connections (especially `RST_STREAM` and protocol errors), and the fallback mechanism to TCP when QUIC encounters issues ("broken alternate protocol"). It also touches upon how proxy configurations interact with QUIC.

By following these steps, I can provide a comprehensive answer that addresses all aspects of the user's request, including the specific code snippet and its broader context within the Chromium network stack.
这个文件 `net/quic/quic_network_transaction_unittest.cc` 是 Chromium 网络栈中 QUIC (Quick UDP Internet Connections) 协议相关网络事务的单元测试文件。 它主要用于测试 `QuicNetworkTransaction` 类的各种功能和场景。

**主要功能归纳 (基于提供的代码片段，第 7 部分):**

这部分代码主要关注以下 `QuicNetworkTransaction` 的功能测试：

1. **0-RTT (Zero Round Trip Time) 连接的各种场景：**
   - **`ZeroRTTNoRace`:** 测试在没有 HTTP 连接竞争的情况下成功建立 0-RTT 连接。
   - **`ZeroRTTWithProxy`:** 测试在使用代理服务器时 0-RTT 连接的行为。
   - **`ZeroRTTWithConfirmationRequired`:** 测试在需要确认握手的情况下 0-RTT 连接的行为。
   - **`ZeroRTTWithTooEarlyResponse`:** 测试处理服务器返回 "425 Too Early" 响应的 0-RTT 连接。
   - **`ZeroRTTWithMultipleTooEarlyResponse`:** 测试处理服务器返回多个 "425 Too Early" 响应的 0-RTT 连接。

2. **QUIC 协议错误处理和日志记录：**
   - **`LogGranularQuicErrorCodeOnQuicProtocolErrorLocal`:** 测试当本地发生 QUIC 协议错误时，是否能记录详细的错误代码。
   - **`LogGranularQuicErrorCodeOnQuicProtocolErrorRemote`:** 测试当远端发生 QUIC 协议错误时，是否能记录详细的错误代码。

3. **RST_STREAM 帧的处理：**
   - **`RstStreamErrorHandling`:** 测试在接收到响应头之后收到 RST_STREAM 帧时的处理逻辑。
   - **`RstStreamBeforeHeaders`:** 测试在接收到响应头之前收到 RST_STREAM 帧时的处理逻辑。

4. **Broken Alternate Protocol (备用协议失效) 的处理：**
   - **`BrokenAlternateProtocol`:** 测试当 QUIC 连接失败时，回退到 TCP 连接的机制。
   - **`BrokenAlternateProtocolWithNetworkIsolationKey`:**  与上一个测试类似，但考虑了网络隔离密钥 (Network Isolation Key) 的情况。
   - **`BrokenAlternateProtocolReadError`:** 测试当 QUIC 连接尝试读取数据时发生错误时的处理逻辑。
   - **`NoBrokenAlternateProtocolIfTcpFails`:** 测试当 QUIC 连接失败并且 TCP 连接也失败时，不将 QUIC 标记为永久失效。

5. **延迟 TCP 连接的场景：**
   - **`DelayTCPOnStartWithQuicSupportOnSameIP`:** 测试如果最近在相同的 IP 地址上成功使用了 QUIC，是否会延迟启动 TCP 连接。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不是 JavaScript，但它直接影响着浏览器中 JavaScript 发起的网络请求的性能和可靠性。

* **0-RTT 连接:**  如果 JavaScript 发起的 HTTPS 请求可以使用 0-RTT QUIC 连接，则可以显著减少请求的延迟，因为在建立连接时不需要额外的往返。这对于改善网页加载速度和 Web 应用的响应速度至关重要。
    * **举例:** 用户在 JavaScript 中使用 `fetch()` API 或 `XMLHttpRequest` 发起一个 HTTPS 请求。如果浏览器与目标服务器之前已经建立了 QUIC 连接，并且满足 0-RTT 的条件，那么这个请求的握手阶段会更快，JavaScript 代码会更快地收到服务器的响应。

* **Broken Alternate Protocol 回退:** 当 QUIC 连接遇到问题时，Chromium 会回退到传统的 TCP 连接，确保 JavaScript 发起的请求仍然能够完成，尽管可能性能会受到影响。
    * **举例:**  用户在 JavaScript 中发起一个请求，浏览器尝试使用 QUIC，但由于网络问题或服务器配置问题导致 QUIC 连接失败。这时，浏览器会透明地回退到 TCP 连接，用户和 JavaScript 代码通常不会感知到这个切换过程，但请求最终会通过 TCP 完成。

**逻辑推理、假设输入与输出：**

以 `TEST_P(QuicNetworkTransactionTest, ZeroRTTNoRace)` 为例：

* **假设输入:**
    * 客户端和服务端都支持 QUIC。
    * 客户端之前与服务端成功建立过 QUIC 连接，并保存了足够的信息以进行 0-RTT 连接。
    * 没有并行的 HTTP 连接尝试与服务端建立连接。
    * `mock_quic_data` 模拟了成功的 0-RTT QUIC 握手和数据传输过程，包括 `InitialSettings` 包和请求头。
* **预期输出:**
    * `callback.WaitForResult()` 返回 `IsOk()`，表示请求成功完成。
    * `trans.GetResponseInfo()` 返回的响应信息指示这是一个 QUIC 响应 (`CheckWasQuicResponse(&trans)`)。
    * 响应数据与预期的数据一致 (`CheckResponseData(&trans, kQuicRespData)`)。

以 `TEST_P(QuicNetworkTransactionTest, ZeroRTTWithTooEarlyResponse)` 为例：

* **假设输入:**
    * 客户端尝试使用 0-RTT 连接。
    * 服务端返回 "425 Too Early" 响应，表示客户端过早发送了 0-RTT 数据。
    * 客户端随后会进行正常的握手并重试请求。
    * `mock_quic_data` 模拟了上述交互过程。
* **预期输出:**
    * 第一次 0-RTT 尝试不会成功 (`EXPECT_FALSE(callback.have_result())`)。
    * 在完成正常的握手后，请求会成功 (`EXPECT_THAT(callback.WaitForResult(), IsOk())`)。
    * 响应数据与预期的数据一致 (`CheckResponseData(&trans, kQuicRespData)`)。

**用户或编程常见的使用错误：**

* **服务器配置错误:** 服务器可能没有正确配置 QUIC 支持，导致客户端无法建立 QUIC 连接，或者在 0-RTT 时返回错误，例如 "425 Too Early"。
    * **举例:** 服务器的防火墙阻止了 UDP 端口的通信，或者服务器的 TLS 配置不兼容 QUIC 的要求。
* **网络问题:**  不稳定的网络连接或丢包可能导致 QUIC 连接中断，触发 Broken Alternate Protocol 回退到 TCP。
    * **举例:** 用户在移动网络信号不好的环境下浏览网页，可能会频繁看到回退到 TCP 的情况。
* **客户端配置错误:** 浏览器或操作系统的 QUIC 配置可能被禁用或损坏，导致无法使用 QUIC。
* **中间件干扰:** 一些网络中间件（例如代理服务器或防火墙）可能不支持或错误地处理 QUIC 协议，导致连接失败。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入 HTTPS URL 或点击 HTTPS 链接。**
2. **浏览器首先会查找该域名是否支持 QUIC。** 这可能基于本地缓存（HTTP/3 或 Alt-Svc 记录）或通过 DNS 查询。
3. **如果支持 QUIC，浏览器会尝试建立 QUIC 连接。** 这涉及到与服务器进行 UDP 握手。
4. **`QuicNetworkTransaction` 类负责管理这个 QUIC 连接的生命周期和数据传输。**
5. **如果尝试的是 0-RTT 连接，`QuicNetworkTransaction` 会尝试使用之前保存的会话信息快速建立连接。**
6. **如果服务器返回 "425 Too Early" 或其他错误，`QuicNetworkTransaction` 会根据测试中的逻辑进行处理，例如重试或回退到 TCP。**
7. **如果 QUIC 连接过程中发生错误（例如接收到 RST_STREAM 帧或连接关闭帧），`QuicNetworkTransaction` 会处理这些错误，并可能触发 Broken Alternate Protocol 机制。**

因此，当用户访问一个支持 QUIC 的 HTTPS 网站时，`QuicNetworkTransaction` 的代码就会被执行，而 `quic_network_transaction_unittest.cc` 中的测试则确保了 `QuicNetworkTransaction` 在各种场景下都能按预期工作。 这对于开发者调试和验证 QUIC 功能的正确性至关重要。

Prompt: 
```
这是目录为net/quic/quic_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共13部分，请归纳一下它的功能

"""
o_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();

  ASSERT_FALSE(mock_quic_data.AllReadDataConsumed());
  mock_quic_data.Resume();

  // Run the QUIC session to completion.
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(callback.WaitForResult(), IsOk());

  CheckWasQuicResponse(&trans);
  CheckResponseData(&trans, kQuicRespData);

  EXPECT_EQ(nullptr, http_server_properties_->GetServerNetworkStats(
                         url::SchemeHostPort("https", request_.url.host(), 443),
                         NetworkAnonymizationKey()));
}

TEST_P(QuicNetworkTransactionTest, ZeroRTTWithNoHttpRace) {
  MockQuicData mock_quic_data(version_);
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  int packet_number = 1;
  mock_quic_data.AddWrite(
      SYNCHRONOUS, client_maker_->MakeInitialSettingsPacket(packet_number++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_number++, GetNthClientInitiatedBidirectionalStreamId(0), true,
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
                          ConstructClientAckPacket(packet_number++, 2, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");

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
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();

  ASSERT_FALSE(mock_quic_data.AllReadDataConsumed());
  mock_quic_data.Resume();

  // Run the QUIC session to completion.
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(callback.WaitForResult(), IsOk());

  CheckWasQuicResponse(&trans);
  CheckResponseData(&trans, kQuicRespData);
}

TEST_P(QuicNetworkTransactionTest, ZeroRTTWithProxy) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  proxy_resolution_service_ =
      ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
          {ProxyChain::FromSchemeHostAndPort(ProxyServer::SCHEME_HTTP,
                                             "myproxy", 70)},
          TRAFFIC_ANNOTATION_FOR_TESTS);

  // Since we are using a proxy, the QUIC job will not succeed.
  MockWrite http_writes[] = {
      MockWrite(SYNCHRONOUS, 0, "GET http://mail.example.org/ HTTP/1.1\r\n"),
      MockWrite(SYNCHRONOUS, 1, "Host: mail.example.org\r\n"),
      MockWrite(SYNCHRONOUS, 2, "Proxy-Connection: keep-alive\r\n\r\n")};

  MockRead http_reads[] = {MockRead(SYNCHRONOUS, 3, "HTTP/1.1 200 OK\r\n"),
                           MockRead(SYNCHRONOUS, 4, alt_svc_header_.data()),
                           MockRead(SYNCHRONOUS, 5, kHttpRespData),
                           MockRead(SYNCHRONOUS, OK, 6)};

  StaticSocketDataProvider http_data(http_reads, http_writes);
  socket_factory_.AddSocketDataProvider(&http_data);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");

  request_.url = GURL("http://mail.example.org/");
  CreateSession();
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);
  SendRequestAndExpectHttpResponse(kHttpRespData);
}

TEST_P(QuicNetworkTransactionTest, ZeroRTTWithConfirmationRequired) {
  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
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
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");

  CreateSession();
  session_->quic_session_pool()->set_has_quic_ever_worked_on_current_network(
      false);
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  base::RunLoop().RunUntilIdle();
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  CheckWasQuicResponse(&trans);
  CheckResponseData(&trans, kQuicRespData);
}

TEST_P(QuicNetworkTransactionTest, ZeroRTTWithTooEarlyResponse) {
  uint64_t packet_number = 1;
  MockQuicData mock_quic_data(version_);
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  mock_quic_data.AddWrite(
      SYNCHRONOUS, client_maker_->MakeInitialSettingsPacket(packet_number++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_number++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("425")));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientAckDataAndRst(
          packet_number++, GetNthClientInitiatedBidirectionalStreamId(0),
          quic::QUIC_STREAM_CANCELLED, 1, 1, GetQpackDecoderStreamId(), false,
          StreamCancellationQpackDecoderInstruction(0)));

  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);

  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_number++, GetNthClientInitiatedBidirectionalStreamId(1), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(1), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 3, GetNthClientInitiatedBidirectionalStreamId(1), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_number++, 3, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);
  QuicSessionPoolPeer::SetAlarmFactory(
      session_->quic_session_pool(),
      std::make_unique<QuicChromiumAlarmFactory>(quic_task_runner_.get(),
                                                 context_.clock()));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Confirm the handshake after the 425 Too Early.
  base::RunLoop().RunUntilIdle();

  // The handshake hasn't been confirmed yet, so the retry should not have
  // succeeded.
  EXPECT_FALSE(callback.have_result());

  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();

  EXPECT_THAT(callback.WaitForResult(), IsOk());
  CheckWasQuicResponse(&trans);
  CheckResponseData(&trans, kQuicRespData);
}

TEST_P(QuicNetworkTransactionTest, ZeroRTTWithMultipleTooEarlyResponse) {
  uint64_t packet_number = 1;
  MockQuicData mock_quic_data(version_);
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  mock_quic_data.AddWrite(
      SYNCHRONOUS, client_maker_->MakeInitialSettingsPacket(packet_number++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_number++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("425")));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientAckDataAndRst(
          packet_number++, GetNthClientInitiatedBidirectionalStreamId(0),
          quic::QUIC_STREAM_CANCELLED, 1, 1, GetQpackDecoderStreamId(), false,
          StreamCancellationQpackDecoderInstruction(0)));

  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);

  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_number++, GetNthClientInitiatedBidirectionalStreamId(1), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(1), false,
                 GetResponseHeaders("425")));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientAckDataAndRst(
          packet_number++, GetNthClientInitiatedBidirectionalStreamId(1),
          quic::QUIC_STREAM_CANCELLED, 2, 1, GetQpackDecoderStreamId(), false,
          StreamCancellationQpackDecoderInstruction(1, false)));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);
  QuicSessionPoolPeer::SetAlarmFactory(
      session_->quic_session_pool(),
      std::make_unique<QuicChromiumAlarmFactory>(quic_task_runner_.get(),
                                                 context_.clock()));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Confirm the handshake after the 425 Too Early.
  base::RunLoop().RunUntilIdle();

  // The handshake hasn't been confirmed yet, so the retry should not have
  // succeeded.
  EXPECT_FALSE(callback.have_result());

  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();

  EXPECT_THAT(callback.WaitForResult(), IsOk());
  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response != nullptr);
  ASSERT_TRUE(response->headers.get() != nullptr);
  EXPECT_EQ("HTTP/1.1 425", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  EXPECT_EQ(QuicHttpStream::ConnectionInfoFromQuicVersion(version_),
            response->connection_info);
}

TEST_P(QuicNetworkTransactionTest,
       LogGranularQuicErrorCodeOnQuicProtocolErrorLocal) {
  context_.params()->retry_without_alt_svc_on_quic_errors = false;
  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  // Read a close connection packet with
  // quic::QuicErrorCode: quic::QUIC_CRYPTO_VERSION_NOT_SUPPORTED from the peer.
  mock_quic_data.AddRead(ASYNC, ConstructServerConnectionClosePacket(1));
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");

  CreateSession();
  session_->quic_session_pool()->set_has_quic_ever_worked_on_current_network(
      false);
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  base::RunLoop().RunUntilIdle();
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_QUIC_PROTOCOL_ERROR));

  NetErrorDetails details;
  EXPECT_EQ(quic::QUIC_NO_ERROR, details.quic_connection_error);

  trans.PopulateNetErrorDetails(&details);
  // Verify the error code logged is what sent by the peer.
  EXPECT_EQ(quic::QUIC_CRYPTO_VERSION_NOT_SUPPORTED,
            details.quic_connection_error);
}

TEST_P(QuicNetworkTransactionTest,
       LogGranularQuicErrorCodeOnQuicProtocolErrorRemote) {
  context_.params()->retry_without_alt_svc_on_quic_errors = false;
  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  // Peer sending data from an non-existing stream causes this end to raise
  // error and close connection.
  mock_quic_data.AddRead(ASYNC,
                         ConstructServerRstPacket(
                             1, GetNthClientInitiatedBidirectionalStreamId(47),
                             quic::QUIC_STREAM_LAST_ERROR));
  std::string quic_error_details = "Data for nonexistent stream";
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientAckAndConnectionClosePacket(
          packet_num++, 1, 1, quic::QUIC_HTTP_STREAM_WRONG_DIRECTION,
          quic_error_details, quic::IETF_STOP_SENDING));
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");

  CreateSession();
  session_->quic_session_pool()->set_has_quic_ever_worked_on_current_network(
      false);
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  base::RunLoop().RunUntilIdle();
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_QUIC_PROTOCOL_ERROR));
  NetErrorDetails details;
  EXPECT_EQ(quic::QUIC_NO_ERROR, details.quic_connection_error);

  trans.PopulateNetErrorDetails(&details);
  EXPECT_EQ(quic::QUIC_HTTP_STREAM_WRONG_DIRECTION,
            details.quic_connection_error);
}

TEST_P(QuicNetworkTransactionTest, RstStreamErrorHandling) {
  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  // Read the response headers, then a RST_STREAM frame.
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC,
      ConstructServerRstPacket(2, GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED));

  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_->Packet(packet_num++)
          .AddAckFrame(/*first_received=*/1, /*largest_received=*/2,
                       /*smallest_received=*/1)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_STREAM_CANCELLED)
          .Build());
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more read data.
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");

  CreateSession();
  session_->quic_session_pool()->set_has_quic_ever_worked_on_current_network(
      false);
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  base::RunLoop().RunUntilIdle();
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  // Read the headers.
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response != nullptr);
  ASSERT_TRUE(response->headers.get() != nullptr);
  EXPECT_EQ(kQuic200RespStatusLine, response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  EXPECT_EQ(QuicHttpStream::ConnectionInfoFromQuicVersion(version_),
            response->connection_info);

  std::string response_data;
  ASSERT_EQ(ERR_QUIC_PROTOCOL_ERROR, ReadTransaction(&trans, &response_data));
}

TEST_P(QuicNetworkTransactionTest, RstStreamBeforeHeaders) {
  context_.params()->retry_without_alt_svc_on_quic_errors = false;
  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC,
      ConstructServerRstPacket(1, GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED));

  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_->Packet(packet_num++)
          .AddAckFrame(/*first_received=*/1, /*largest_received=*/1,
                       /*smallest_received=*/1)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_STREAM_CANCELLED)
          .Build());

  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more read data.
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");

  CreateSession();
  session_->quic_session_pool()->set_has_quic_ever_worked_on_current_network(
      false);
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  base::RunLoop().RunUntilIdle();
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  // Read the headers.
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_QUIC_PROTOCOL_ERROR));
}

TEST_P(QuicNetworkTransactionTest, BrokenAlternateProtocol) {
  // Alternate-protocol job
  std::unique_ptr<quic::QuicEncryptedPacket> close(
      ConstructServerConnectionClosePacket(1));
  MockRead quic_reads[] = {
      MockRead(ASYNC, close->data(), close->length()),
      MockRead(ASYNC, ERR_IO_PENDING),  // No more data to read
      MockRead(ASYNC, OK),              // EOF
  };
  StaticSocketDataProvider quic_data(quic_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&quic_data);

  // Main job which will succeed even though the alternate job fails.
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"), MockRead("hello from http"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();
  AddQuicAlternateProtocolMapping(
      MockCryptoClientStream::COLD_START_WITH_CHLO_SENT);
  SendRequestAndExpectHttpResponse("hello from http");
  ExpectBrokenAlternateProtocolMapping();
}

TEST_P(QuicNetworkTransactionTest,
       BrokenAlternateProtocolWithNetworkIsolationKey) {
  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const net::NetworkIsolationKey kNetworkIsolationKey1(kSite1, kSite1);
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const net::NetworkIsolationKey kNetworkIsolationKey2(kSite2, kSite2);
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);

  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);
  // Since HttpServerProperties caches the feature value, have to create a new
  // one.
  http_server_properties_ = std::make_unique<HttpServerProperties>();

  // Alternate-protocol job
  std::unique_ptr<quic::QuicEncryptedPacket> close(
      ConstructServerConnectionClosePacket(1));
  MockRead quic_reads[] = {
      MockRead(ASYNC, close->data(), close->length()),
      MockRead(ASYNC, ERR_IO_PENDING),  // No more data to read
      MockRead(ASYNC, OK),              // EOF
  };
  StaticSocketDataProvider quic_data(quic_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&quic_data);

  // Main job which will succeed even though the alternate job fails.
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"), MockRead("hello from http"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();
  AddQuicAlternateProtocolMapping(
      MockCryptoClientStream::COLD_START_WITH_CHLO_SENT,
      kNetworkAnonymizationKey1);
  AddQuicAlternateProtocolMapping(
      MockCryptoClientStream::COLD_START_WITH_CHLO_SENT,
      kNetworkAnonymizationKey2);
  request_.network_isolation_key = kNetworkIsolationKey1;
  request_.network_anonymization_key = kNetworkAnonymizationKey1;
  SendRequestAndExpectHttpResponse("hello from http");

  ExpectBrokenAlternateProtocolMapping(kNetworkAnonymizationKey1);
  ExpectQuicAlternateProtocolMapping(kNetworkAnonymizationKey2);
}

TEST_P(QuicNetworkTransactionTest, BrokenAlternateProtocolReadError) {
  // Alternate-protocol job
  MockRead quic_reads[] = {
      MockRead(ASYNC, ERR_SOCKET_NOT_CONNECTED),
  };
  StaticSocketDataProvider quic_data(quic_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&quic_data);

  // Main job which will succeed even though the alternate job fails.
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"), MockRead("hello from http"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::COLD_START);
  SendRequestAndExpectHttpResponse("hello from http");
  ExpectBrokenAlternateProtocolMapping();
}

TEST_P(QuicNetworkTransactionTest, NoBrokenAlternateProtocolIfTcpFails) {
  // Alternate-protocol job will fail when the session attempts to read.
  MockRead quic_reads[] = {
      MockRead(ASYNC, ERR_SOCKET_NOT_CONNECTED),
  };
  StaticSocketDataProvider quic_data(quic_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&quic_data);

  // Main job will also fail.
  MockRead http_reads[] = {
      MockRead(ASYNC, ERR_SOCKET_NOT_CONNECTED),
  };

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  http_data.set_connect_data(MockConnect(ASYNC, ERR_SOCKET_NOT_CONNECTED));
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::COLD_START);
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_SOCKET_NOT_CONNECTED));
  ExpectQuicAlternateProtocolMapping();
}

TEST_P(QuicNetworkTransactionTest, DelayTCPOnStartWithQuicSupportOnSameIP) {
  // Tests that TCP job is delayed and QUIC job does not require confirmation
  // if QUIC was recently supported on the same IP on start.

  // Set QUIC support on the last IP address, which is same with the local IP
  // address. Require confirmation mode will be turned off immediately when
  // local IP address is sorted out after we configure the UDP socket.
  http_server_properties_->SetLastLocalAddressWhenQuicWorked(
      IPAddress(192, 0, 2, 33));

  MockQuicData mock_quic_data(version_);
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  int packet_number = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_number++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_number++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  mo
"""


```