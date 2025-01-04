Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack. This file, `quic_session_pool_test.cc`, is a test file for the `QuicSessionPool` class.

Here's a breakdown of how to approach the request:

1. **Identify the core purpose:** The file tests the `QuicSessionPool` class. This class manages a pool of active QUIC sessions.

2. **Analyze the test cases:** Each `TEST_P` block represents a specific scenario being tested. I need to understand what each test case aims to verify. Look for keywords like "Pooling", "NoPooling", "GoAway", "Https", "Error", "Cancel", etc.

3. **Look for patterns:** Notice how the tests set up mock network conditions (using `MockQuicData` and `MockHostResolver`), initiate requests (using `RequestBuilder`), and then assert expectations about session creation, pooling, and error handling.

4. **Address specific instructions:**
    * **Functionality:** Summarize the different aspects of `QuicSessionPool` being tested.
    * **JavaScript relationship:** Consider if any features tested here directly impact how QUIC is used in a browser context initiated by JavaScript. Think about things like connection reuse, security, and error handling.
    * **Logical reasoning (assumptions/inputs/outputs):**  For specific test cases, identify the initial setup (assumptions/inputs) and the expected outcome (output).
    * **Common usage errors:** Think about how a developer or user interacting with the network might cause scenarios covered in the tests.
    * **User operation to reach this point:** Trace back the steps a user might take in a browser to trigger the creation and management of QUIC sessions.
    * **Summary of functionality (for this part):** Condense the findings from analyzing the current code snippet.

5. **Structure the response:** Organize the information logically, addressing each part of the user's request.

**Detailed analysis of the provided code snippet:**

* **`IgnoreIpMatchingWhenFindingExistingSessions` and `IgnoreIpMatchingWhenFindingExistingSessionsAndSkipDns`:** Test cases focusing on a feature that allows session reuse even if the IP address doesn't match, potentially skipping DNS lookups. This is relevant for scenarios like server migration or when a server has multiple IP addresses.
* **`Pooling`:** A core test case demonstrating different pooling scenarios based on IP address and ALPN (Application-Layer Protocol Negotiation). This is crucial for efficient resource usage.
* **`PoolingWithServerMigration`:** Tests how the session pool handles sessions that have undergone server migration (the server changed its IP address).
* **`NoPoolingAfterGoAway`:** Verifies that once a session is marked as "going away" (due to a server-initiated close), it won't be used for new requests.
* **`HttpsPooling`:** Tests basic pooling for HTTPS connections.
* **`HttpsPoolingWithMatchingPins` and `NoHttpsPoolingWithDifferentPins`:** Focus on the impact of TLS certificate pinning on session pooling. Sessions should only be pooled if the certificate pins match.
* **`Goaway`:** Tests the behavior when a server sends a `GOAWAY` frame, indicating it's shutting down.
* **`MaxOpenStream`:** Checks the handling of the maximum number of concurrent streams allowed on a QUIC connection.
* **`ResolutionErrorInCreate`:** Tests how the session pool handles DNS resolution failures when trying to create a new session.
* **`SyncConnectErrorInCreate` and `AsyncConnectErrorInCreate`:** Test error handling during the connection establishment phase (socket errors).
* **`SyncCancelCreate` and `AsyncCancelCreate`:** Test the cancellation of session creation requests.
* **`CloseAllSessions`:** Checks the functionality to close all active QUIC sessions, simulating a network disconnection.
* **`WriteErrorInCryptoConnectWithAsyncHostResolutionSyncSessionCreation`:** Tests error handling during the QUIC handshake process.

**JavaScript connection:** The pooling and security aspects directly impact web performance and security, which are relevant to JavaScript-initiated network requests.

**Hypothetical inputs and outputs:** For example, in the `Pooling` test:

* **Input:** Two requests to different hostnames resolving to the same IP address, with compatible ALPN.
* **Output:** Both requests use the same underlying QUIC session (pooling occurs).

**Common usage errors:** A user might configure incorrect TLS pinning, leading to unexpected connection failures or lack of pooling.
这是目录为 `net/quic/quic_session_pool_test.cc` 的 Chromium 网络栈的源代码文件的第 3 部分，共 20 部分。基于你提供的代码片段，我们可以归纳一下这部分代码主要测试了 `QuicSessionPool` 的以下功能：

**归纳的功能：**

* **跨域名 Session Pooling 的各种场景:**
    * **忽略 IP 地址匹配进行 Session Pooling 并跳过 DNS 查询:** 测试当配置 `ignore_ip_matching_when_finding_existing_sessions` 为 true 时，即使新请求的目标服务器 IP 地址与现有 Session 的不同，只要其他条件满足（如主机名），就可以复用现有 Session，并跳过 DNS 解析。
    * **基于 IP 地址和 ALPN 的 Session Pooling:**  详细测试了在不同情况下（IP 地址相同但 ALPN 不同，或通过不同的 DNS 记录类型解析）如何进行 Session Pooling。验证了只有当 IP 地址和 ALPN 都匹配时，才能复用 Session。
    * **与服务器迁移的 Session Pooling:** 测试了在现有 Session 发生服务器 IP 地址迁移后，新的请求是否能正确地创建新的 Session，并且不会与旧的 Session 发生冲突。
    * **`GOAWAY` 后的禁止 Session Pooling:** 验证了当一个 Session 被标记为 `GOING_AWAY` 后，即使目标服务器相同，新的请求也不会复用这个即将关闭的 Session。
    * **HTTPS 的 Session Pooling:** 测试了对于 HTTPS 请求，当目标服务器的 IP 地址相同时，可以进行 Session Pooling。
    * **基于 TLS 证书 Pinning 的 Session Pooling:**  测试了当启用 TLS 证书 Pinning 时，只有当目标服务器的 Pinning 信息相同时，才能进行 Session Pooling。如果 Pinning 信息不同，则不会复用 Session。
* **Session 管理和错误处理:**
    * **处理 `GOAWAY` 帧:** 测试了当接收到服务器发送的 `GOAWAY` 帧时，Session Pool 如何标记 Session 状态，并确保后续请求不会复用该 Session。
    * **最大并发 Stream 数量的限制:** 测试了当达到最大并发 Stream 数量限制时，新的 Stream 请求会被阻塞，直到有 Stream 关闭。同时也测试了当接收到 `MAX_STREAMS` 帧时，可以增加并发 Stream 的限制。
    * **Session 创建过程中的 DNS 解析错误:** 测试了当 DNS 解析失败时，Session Pool 如何处理并返回相应的错误。
    * **Session 创建过程中的连接错误 (同步和异步):** 测试了在创建 Socket 连接时发生错误（例如地址被占用）时，Session Pool 如何处理并返回相应的错误。
    * **取消 Session 创建请求 (同步和异步):** 测试了在 Session 创建过程中取消请求时，Session Pool 如何清理资源。
    * **关闭所有 Session:** 测试了 `CloseAllSessions` 方法，验证它可以正确关闭所有活跃的 QUIC Session，并通知相关的 Stream 发生错误。
    * **Crypto 连接过程中的写错误:** 测试了在 QUIC 握手阶段发生写错误时，Session Pool 如何处理并返回 `ERR_QUIC_HANDSHAKE_FAILED` 错误，并确保后续请求可以正常发起。

**与 JavaScript 的功能关系 (举例说明):**

这些测试的功能都直接影响着浏览器中由 JavaScript 发起的网络请求的性能和安全性。例如：

* **Session Pooling:** 当用户在同一个网站的不同页面或不同的子域名之间导航时，如果启用了 Session Pooling，浏览器就可以复用已建立的 QUIC 连接，从而减少了建立新连接的延迟，提升了页面加载速度。这对于用 JavaScript 实现的 Single-Page Application (SPA) 尤其重要。
* **TLS 证书 Pinning:** JavaScript 可以通过一些 API（例如 `Public-Key-Pins` HTTP 头）来影响浏览器的证书 Pinning 策略。`QuicSessionPool` 的测试确保了当 Pinning 策略生效时，QUIC 连接的复用会考虑到 Pinning 的一致性，从而提升安全性。
* **错误处理:** 当 QUIC 连接发生错误时（例如 DNS 解析失败、连接被拒绝），`QuicSessionPool` 的测试确保了这些错误可以被正确地捕获和处理，并最终反馈给 JavaScript 代码，让开发者可以进行相应的处理，例如显示错误信息或重试请求.

**逻辑推理 (假设输入与输出):**

以 `TEST_P(QuicSessionPoolTest, Pooling)` 为例：

* **假设输入:**
    * 发起一个到 `kDefaultServerHostName` 的 HTTPS 请求。
    * 发起另一个到 `kServer2HostName` 的 HTTPS 请求，`kServer2HostName` 解析到与 `kDefaultServerHostName` 相同的 IP 地址，并且 ALPN 匹配。
* **输出:**
    * 两个请求会复用同一个 QUIC Session。`GetActiveSession(kDefaultDestination)` 和 `GetActiveSession(server2)` 返回相同的 Session 指针。

**涉及用户或编程常见的使用错误 (举例说明):**

* **错误配置 TLS 证书 Pinning:** 如果开发者在服务器端配置了错误的 TLS 证书 Pinning 信息，或者在客户端（例如通过 HTTP 头）配置了与服务器不匹配的 Pinning 信息，那么即使 IP 地址相同，`QuicSessionPool` 也会阻止 Session Pooling，导致连接建立失败或者性能下降。
* **依赖于 IP 地址进行 Session 管理:**  如果应用程序逻辑假设对于同一个主机名，只要 IP 地址相同就可以复用连接，那么在 `ignore_ip_matching_when_finding_existing_sessions` 为 false 的情况下，可能会遇到问题，因为 IP 地址可能会改变，导致无法复用连接。

**用户操作是如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入一个 HTTPS 的 URL 并回车。**
2. **浏览器首先会进行 DNS 解析，获取目标服务器的 IP 地址。**
3. **浏览器检查 `QuicSessionPool` 中是否已经存在与目标服务器匹配的活跃 QUIC Session。**
    * **如果存在，并且满足 Pooling 的条件（例如 IP 地址、ALPN、Pinning 等匹配），则复用现有的 Session。**  这段测试代码就在验证这些 Pooling 的条件。
    * **如果不存在，则会创建一个新的 QUIC Session。**
4. **创建新的 QUIC Session 涉及到建立 TCP 连接 (或者 UDP 连接，取决于 QUIC 的版本)，进行 TLS 握手 (QUIC 的握手过程与 TLS 集成在一起)。**
5. **一旦 QUIC Session 建立成功，浏览器就可以通过该 Session 发送 HTTP 请求并接收响应。**

如果你在调试 QUIC 连接问题，例如连接建立失败或者性能不佳，你可能会关注 `QuicSessionPool` 的行为，查看是否发生了预期的 Session Pooling，或者为什么没有发生 Pooling。这段测试代码可以帮助你理解 `QuicSessionPool` 的工作原理，并帮助你定位问题。

**总结这部分的功能:**

总而言之，这段代码主要集中测试了 `QuicSessionPool` 中关于跨域名 Session Pooling 的各种策略和条件，以及 Session 管理和错误处理的机制。它确保了 `QuicSessionPool` 能够根据不同的网络环境和配置正确地管理 QUIC Session，提高网络连接的效率和安全性。

Prompt: 
```
这是目录为net/quic/quic_session_pool_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共20部分，请归纳一下它的功能

"""
estination), GetActiveSession(server2));

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest,
       IgnoreIpMatchingWhenFindingExistingSessionsAndSkipDns) {
  quic_params_->ignore_ip_matching_when_finding_existing_sessions = true;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  url::SchemeHostPort server2(url::kHttpsScheme, kServer2HostName,
                              kDefaultServerPort);
  host_resolver_->set_synchronous_mode(true);
  host_resolver_->rules()->AddIPLiteralRule(kDefaultServerHostName,
                                            "192.168.0.1", "");

  // Establish a QUIC session to pool against.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Receive NOIP connection option.
  quic::QuicTagVector initial_received_options;
  initial_received_options.push_back(quic::kNOIP);
  EXPECT_TRUE(
      GetActiveSession(kDefaultDestination)
          ->config()
          ->SetInitialReceivedConnectionOptions(initial_received_options));

  // `server2` can pool with the existing session and DNS gets skipped.
  TestCompletionCallback callback;
  RequestBuilder builder2(this);
  builder2.destination = server2;
  builder2.url = GURL(kServer2Url);
  ASSERT_EQ(OK, builder2.CallRequest());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());
  EXPECT_EQ(GetActiveSession(kDefaultDestination), GetActiveSession(server2));

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, Pooling) {
  quic_params_->supported_versions = {version_};
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  client_maker_.Reset();
  MockQuicData socket_data2(version_);
  socket_data2.AddReadPauseForever();
  socket_data2.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data2.AddSocketDataToFactory(socket_factory_.get());

  const IPEndPoint kRightIP(*IPAddress::FromIPLiteral("192.168.0.1"),
                            kDefaultServerPort);
  const IPEndPoint kWrongIP(*IPAddress::FromIPLiteral("192.168.0.2"),
                            kDefaultServerPort);
  const std::string kRightALPN = quic::AlpnForVersion(version_);
  const std::string kWrongALPN = "h2";

  url::SchemeHostPort server2(url::kHttpsScheme, kServer2HostName,
                              kDefaultServerPort);
  url::SchemeHostPort server3(url::kHttpsScheme, kServer3HostName,
                              kDefaultServerPort);
  url::SchemeHostPort server4(url::kHttpsScheme, kServer4HostName,
                              kDefaultServerPort);
  url::SchemeHostPort server5(url::kHttpsScheme, kServer5HostName,
                              kDefaultServerPort);
  host_resolver_->set_synchronous_mode(true);
  host_resolver_->rules()->AddIPLiteralRule(kDefaultServerHostName,
                                            "192.168.0.1", "");

  // `server2` resolves to the same IP address via A/AAAA records, i.e. without
  // ALPN information.
  host_resolver_->rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  // `server3` resolves to the same IP address, but only via an alternative
  // endpoint with matching ALPN.
  std::vector<HostResolverEndpointResult> endpoints(1);
  endpoints[0].ip_endpoints = {kRightIP};
  endpoints[0].metadata.supported_protocol_alpns = {kRightALPN};
  host_resolver_->rules()->AddRule(
      server3.host(),
      MockHostResolverBase::RuleResolver::RuleResult({std::move(endpoints)}));

  // `server4` resolves to the same IP address, but only via an alternative
  // endpoint with a mismatching ALPN.
  endpoints = std::vector<HostResolverEndpointResult>(2);
  endpoints[0].ip_endpoints = {kRightIP};
  endpoints[0].metadata.supported_protocol_alpns = {kWrongALPN};
  endpoints[1].ip_endpoints = {kWrongIP};
  endpoints[1].metadata.supported_protocol_alpns = {kRightALPN};
  host_resolver_->rules()->AddRule(
      server4.host(),
      MockHostResolverBase::RuleResolver::RuleResult({std::move(endpoints)}));

  // `server5` resolves to the same IP address via A/AAAA records, i.e. without
  // ALPN information.
  host_resolver_->rules()->AddIPLiteralRule(server5.host(), "192.168.0.1", "");

  // Establish a QUIC session to pool against.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // `server2` can pool with the existing session. Although the endpoint does
  // not specify ALPN, we connect here with preexisting knowledge of the version
  // (from Alt-Svc), so an A/AAAA match is sufficient.
  TestCompletionCallback callback;
  RequestBuilder builder2(this);
  builder2.destination = server2;
  builder2.url = GURL(kServer2Url);
  EXPECT_EQ(OK, builder2.CallRequest());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());
  EXPECT_EQ(GetActiveSession(kDefaultDestination), GetActiveSession(server2));

  // `server3` can pool with the existing session. The endpoint's ALPN protocol
  // matches.
  RequestBuilder builder3(this);
  builder3.destination = server3;
  builder3.url = GURL(kServer3Url);
  EXPECT_EQ(OK, builder3.CallRequest());
  std::unique_ptr<HttpStream> stream3 = CreateStream(&builder3.request);
  EXPECT_TRUE(stream3.get());
  EXPECT_EQ(GetActiveSession(kDefaultDestination), GetActiveSession(server3));

  // `server4` cannot pool with the existing session. No endpoint matches both
  // IP and ALPN protocol.
  RequestBuilder builder4(this);
  builder4.destination = server4;
  builder4.url = GURL(kServer4Url);
  EXPECT_EQ(ERR_IO_PENDING, builder4.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream4 = CreateStream(&builder4.request);
  EXPECT_TRUE(stream4.get());
  EXPECT_NE(GetActiveSession(kDefaultDestination), GetActiveSession(server4));

  // `server5` cannot pool with the existing session. Although the IP address
  // matches, if we connect without prior knowledge of QUIC support, endpoints
  // are only eligible for cross-name pooling when associated with a QUIC ALPN.
  //
  // Without pooling, the DNS response is insufficient to start a QUIC
  // connection, so the connection will fail.
  RequestBuilder builder5(this);
  builder5.destination = server5;
  builder5.quic_version = quic::ParsedQuicVersion::Unsupported();
  builder5.require_dns_https_alpn = true;
  builder5.url = GURL(kServer5Url);
  EXPECT_EQ(ERR_DNS_NO_MATCHING_SUPPORTED_ALPN, builder5.CallRequest());

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  socket_data2.ExpectAllReadDataConsumed();
  socket_data2.ExpectAllWriteDataConsumed();
}

// Regression test for https://crbug.com/639916.
TEST_P(QuicSessionPoolTest, PoolingWithServerMigration) {
  // Set up session to migrate.
  host_resolver_->rules()->AddIPLiteralRule(kDefaultServerHostName,
                                            "192.168.0.1", "");
  IPEndPoint alt_address = IPEndPoint(IPAddress(1, 2, 3, 4), 443);
  quic::QuicConfig config;
  config.SetIPv4AlternateServerAddressToSend(ToQuicSocketAddress(alt_address));
  config.SetPreferredAddressConnectionIdAndTokenToSend(
      kNewCID, quic::QuicUtils::GenerateStatelessResetToken(kNewCID));
  quic::QuicConnectionId cid_on_old_path =
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator());
  VerifyServerMigration(config, alt_address);

  // Close server-migrated session.
  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  session->CloseSessionOnError(0u, quic::QUIC_NO_ERROR,
                               quic::ConnectionCloseBehavior::SILENT_CLOSE);
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));

  client_maker_.Reset();
  // Set up server IP, socket, proof, and config for new session.
  url::SchemeHostPort server2(url::kHttpsScheme, kServer2HostName,
                              kDefaultServerPort);
  host_resolver_->rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  MockQuicData socket_data1(version_);
  socket_data1.AddReadPauseForever();
  client_maker_.set_connection_id(cid_on_old_path);
  int packet_number = 1;
  socket_data1.AddWrite(ASYNC,
                        client_maker_.MakeDummyCHLOPacket(packet_number++));
  // Change the encryption level after handshake is confirmed.
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  socket_data1.AddWrite(SYNCHRONOUS,
                        ConstructInitialSettingsPacket(packet_number++));
  socket_data1.AddSocketDataToFactory(socket_factory_.get());

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  quic::QuicConfig config2;
  crypto_client_stream_factory_.SetConfig(config2);

  // Create new request to cause new session creation.
  TestCompletionCallback callback;
  RequestBuilder builder2(this);
  builder2.destination = server2;
  builder2.url = GURL(kServer2Url);
  builder2.callback = callback.callback();
  EXPECT_EQ(ERR_IO_PENDING, builder2.CallRequest());
  base::RunLoop().RunUntilIdle();

  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();

  EXPECT_EQ(OK, callback.WaitForResult());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());

  socket_data1.ExpectAllReadDataConsumed();
  socket_data1.ExpectAllWriteDataConsumed();

  EXPECT_TRUE(HasActiveSession(server2));

  // No zombie entry in session map.
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
}

TEST_P(QuicSessionPoolTest, NoPoolingAfterGoAway) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data1(version_);
  socket_data1.AddReadPauseForever();
  socket_data1.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data1.AddSocketDataToFactory(socket_factory_.get());
  client_maker_.Reset();
  MockQuicData socket_data2(version_);
  socket_data2.AddReadPauseForever();
  socket_data2.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data2.AddSocketDataToFactory(socket_factory_.get());

  url::SchemeHostPort server2(url::kHttpsScheme, kServer2HostName,
                              kDefaultServerPort);
  host_resolver_->set_synchronous_mode(true);
  host_resolver_->rules()->AddIPLiteralRule(kDefaultServerHostName,
                                            "192.168.0.1", "");
  host_resolver_->rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  TestCompletionCallback callback;
  RequestBuilder builder2(this);
  builder2.destination = server2;
  builder2.url = GURL(kServer2Url);
  builder2.callback = callback.callback();
  EXPECT_EQ(OK, builder2.CallRequest());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());

  factory_->OnSessionGoingAway(GetActiveSession(kDefaultDestination));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_FALSE(HasActiveSession(server2));

  TestCompletionCallback callback3;
  RequestBuilder builder3(this);
  builder3.destination = server2;
  builder3.url = GURL(kServer2Url);
  builder3.callback = callback3.callback();
  EXPECT_EQ(ERR_IO_PENDING, builder3.CallRequest());
  EXPECT_THAT(callback3.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream3 = CreateStream(&builder3.request);
  EXPECT_TRUE(stream3.get());

  EXPECT_TRUE(HasActiveSession(server2));

  socket_data1.ExpectAllReadDataConsumed();
  socket_data1.ExpectAllWriteDataConsumed();
  socket_data2.ExpectAllReadDataConsumed();
  socket_data2.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, HttpsPooling) {
  Initialize();

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  url::SchemeHostPort server1(url::kHttpsScheme, kDefaultServerHostName, 443);
  url::SchemeHostPort server2(url::kHttpsScheme, kServer2HostName, 443);

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  host_resolver_->set_synchronous_mode(true);
  host_resolver_->rules()->AddIPLiteralRule(server1.host(), "192.168.0.1", "");
  host_resolver_->rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  RequestBuilder builder(this);
  builder.destination = server1;
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  RequestBuilder builder2(this);
  builder2.destination = server2;
  builder2.url = GURL(kServer2Url);
  EXPECT_EQ(OK, builder2.CallRequest());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());

  EXPECT_EQ(GetActiveSession(server1), GetActiveSession(server2));

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, HttpsPoolingWithMatchingPins) {
  Initialize();
  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  url::SchemeHostPort server1(url::kHttpsScheme, kDefaultServerHostName, 443);
  url::SchemeHostPort server2(url::kHttpsScheme, kServer2HostName, 443);
  transport_security_state_.EnableStaticPinsForTesting();
  ScopedTransportSecurityStateSource scoped_security_state_source;

  HashValue primary_pin(HASH_VALUE_SHA256);
  EXPECT_TRUE(primary_pin.FromString(
      "sha256/Nn8jk5By4Vkq6BeOVZ7R7AC6XUUBZsWmUbJR1f1Y5FY="));
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  verify_details.cert_verify_result.public_key_hashes.push_back(primary_pin);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  host_resolver_->set_synchronous_mode(true);
  host_resolver_->rules()->AddIPLiteralRule(server1.host(), "192.168.0.1", "");
  host_resolver_->rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  RequestBuilder builder(this);
  builder.destination = server1;
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  RequestBuilder builder2(this);
  builder2.destination = server2;
  builder2.url = GURL(kServer2Url);
  EXPECT_EQ(OK, builder2.CallRequest());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());

  EXPECT_EQ(GetActiveSession(server1), GetActiveSession(server2));

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, NoHttpsPoolingWithDifferentPins) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(
      net::features::kStaticKeyPinningEnforcement);
  Initialize();

  MockQuicData socket_data1(version_);
  socket_data1.AddReadPauseForever();
  socket_data1.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data1.AddSocketDataToFactory(socket_factory_.get());
  client_maker_.Reset();
  MockQuicData socket_data2(version_);
  socket_data2.AddReadPauseForever();
  socket_data2.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data2.AddSocketDataToFactory(socket_factory_.get());

  url::SchemeHostPort server1(url::kHttpsScheme, kDefaultServerHostName, 443);
  url::SchemeHostPort server2(url::kHttpsScheme, kServer2HostName, 443);
  transport_security_state_.EnableStaticPinsForTesting();
  transport_security_state_.SetPinningListAlwaysTimelyForTesting(true);
  ScopedTransportSecurityStateSource scoped_security_state_source;

  ProofVerifyDetailsChromium verify_details1 = DefaultProofVerifyDetails();
  uint8_t bad_pin = 3;
  verify_details1.cert_verify_result.public_key_hashes.push_back(
      test::GetTestHashValue(bad_pin));
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details1);

  HashValue primary_pin(HASH_VALUE_SHA256);
  EXPECT_TRUE(primary_pin.FromString(
      "sha256/Nn8jk5By4Vkq6BeOVZ7R7AC6XUUBZsWmUbJR1f1Y5FY="));
  ProofVerifyDetailsChromium verify_details2 = DefaultProofVerifyDetails();
  verify_details2.cert_verify_result.public_key_hashes.push_back(primary_pin);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details2);

  host_resolver_->set_synchronous_mode(true);
  host_resolver_->rules()->AddIPLiteralRule(server1.host(), "192.168.0.1", "");
  host_resolver_->rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  RequestBuilder builder(this);
  builder.destination = server1;
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  RequestBuilder builder2(this);
  builder2.destination = server2;
  builder2.url = GURL(kServer2Url);
  EXPECT_EQ(ERR_IO_PENDING, builder2.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());

  EXPECT_NE(GetActiveSession(server1), GetActiveSession(server2));

  socket_data1.ExpectAllReadDataConsumed();
  socket_data1.ExpectAllWriteDataConsumed();
  socket_data2.ExpectAllReadDataConsumed();
  socket_data2.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, Goaway) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());
  client_maker_.Reset();
  MockQuicData socket_data2(version_);
  socket_data2.AddReadPauseForever();
  socket_data2.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data2.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Mark the session as going away.  Ensure that while it is still alive
  // that it is no longer active.
  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  factory_->OnSessionGoingAway(session);
  EXPECT_EQ(true, QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));

  // Create a new request for the same destination and verify that a
  // new session is created.
  RequestBuilder builder2(this);
  EXPECT_EQ(ERR_IO_PENDING, builder2.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());

  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_NE(session, GetActiveSession(kDefaultDestination));
  EXPECT_EQ(true, QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));

  stream2.reset();
  stream.reset();

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  socket_data2.ExpectAllReadDataConsumed();
  socket_data2.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, MaxOpenStream) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  quic::QuicStreamId stream_id = GetNthClientInitiatedBidirectionalStreamId(0);
  MockQuicData socket_data(version_);
  int packet_num = 1;
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructInitialSettingsPacket(packet_num++));
  socket_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num++)
          .AddStreamsBlockedFrame(/*control_frame_id=*/1, /*stream_count=*/50,
                                  /*unidirectional=*/false)
          .Build());

  socket_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num++)
          .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                          StreamCancellationQpackDecoderInstruction(0))
          .AddStopSendingFrame(stream_id, quic::QUIC_STREAM_CANCELLED)
          .AddRstStreamFrame(stream_id, quic::QUIC_STREAM_CANCELLED)
          .Build());
  socket_data.AddRead(
      ASYNC, server_maker_.Packet(1)
                 .AddStopSendingFrame(stream_id, quic::QUIC_STREAM_CANCELLED)
                 .AddRstStreamFrame(stream_id, quic::QUIC_STREAM_CANCELLED)
                 .Build());
  socket_data.AddRead(ASYNC, server_maker_.Packet(2)
                                 .AddMaxStreamsFrame(/*control_frame_id=*/1,
                                                     /*stream_count=*/52,
                                                     /*unidirectional=*/false)
                                 .Build());
  socket_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num++).AddAckFrame(1, 2, 1).Build());
  socket_data.AddReadPauseForever();
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  HttpRequestInfo request_info;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::vector<std::unique_ptr<HttpStream>> streams;
  // The MockCryptoClientStream sets max_open_streams to be
  // quic::kDefaultMaxStreamsPerConnection / 2.
  for (size_t i = 0; i < quic::kDefaultMaxStreamsPerConnection / 2; i++) {
    RequestBuilder builder(this);
    int rv = builder.CallRequest();
    if (i == 0) {
      EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
      EXPECT_THAT(callback_.WaitForResult(), IsOk());
    } else {
      EXPECT_THAT(rv, IsOk());
    }
    std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
    EXPECT_TRUE(stream);
    stream->RegisterRequest(&request_info);
    EXPECT_EQ(OK, stream->InitializeStream(false, DEFAULT_PRIORITY, net_log_,
                                           CompletionOnceCallback()));
    streams.push_back(std::move(stream));
  }

  RequestBuilder builder(this);
  builder.callback = CompletionOnceCallback();
  EXPECT_EQ(OK, builder.CallRequest());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream);
  stream->RegisterRequest(&request_info);
  EXPECT_EQ(ERR_IO_PENDING,
            stream->InitializeStream(false, DEFAULT_PRIORITY, net_log_,
                                     callback_.callback()));

  // Close the first stream.
  streams.front()->Close(false);
  // Trigger exchange of RSTs that in turn allow progress for the last
  // stream.
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(callback_.WaitForResult(), IsOk());

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();

  // Force close of the connection to suppress the generation of RST
  // packets when streams are torn down, which wouldn't be relevant to
  // this test anyway.
  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  session->connection()->CloseConnection(
      quic::QUIC_PUBLIC_RESET, "test",
      quic::ConnectionCloseBehavior::SILENT_CLOSE);
}

TEST_P(QuicSessionPoolTest, ResolutionErrorInCreate) {
  Initialize();
  MockQuicData socket_data(version_);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  host_resolver_->rules()->AddSimulatedFailure(kDefaultServerHostName);

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsError(ERR_NAME_NOT_RESOLVED));

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

// This test uses synchronous QUIC session creation.
TEST_P(QuicSessionPoolTest, SyncConnectErrorInCreate) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndDisableFeature(net::features::kAsyncQuicSession);
  Initialize();

  MockQuicData socket_data(version_);
  socket_data.AddConnect(SYNCHRONOUS, ERR_ADDRESS_IN_USE);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsError(ERR_ADDRESS_IN_USE));

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, AsyncConnectErrorInCreate) {
  Initialize();

  MockQuicData socket_data(version_);
  socket_data.AddConnect(SYNCHRONOUS, ERR_ADDRESS_IN_USE);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsError(ERR_ADDRESS_IN_USE));

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

// This test uses synchronous QUIC session creation.
TEST_P(QuicSessionPoolTest, SyncCancelCreate) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndDisableFeature(net::features::kAsyncQuicSession);
  Initialize();
  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());
  {
    RequestBuilder builder(this);
    EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  }

  base::RunLoop().RunUntilIdle();

  RequestBuilder builder2(this);
  EXPECT_EQ(OK, builder2.CallRequest());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder2.request);

  EXPECT_TRUE(stream.get());
  stream.reset();

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, AsyncCancelCreate) {
  Initialize();
  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());
  {
    RequestBuilder builder(this);
    EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  }

  base::RunLoop().RunUntilIdle();

  RequestBuilder builder2(this);
  EXPECT_EQ(OK, builder2.CallRequest());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder2.request);

  EXPECT_TRUE(stream.get());
  stream.reset();

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, CloseAllSessions) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  int packet_num = 1;
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructInitialSettingsPacket(packet_num++));
  socket_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num++)
          .AddConnectionCloseFrame(quic::QUIC_PEER_GOING_AWAY, "net error")
          .Build());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  client_maker_.Reset();
  MockQuicData socket_data2(version_);
  socket_data2.AddReadPauseForever();
  socket_data2.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data2.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  HttpRequestInfo request_info;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream->RegisterRequest(&request_info);
  EXPECT_EQ(OK, stream->InitializeStream(false, DEFAULT_PRIORITY, net_log_,
                                         CompletionOnceCallback()));

  // Close the session and verify that stream saw the error.
  factory_->CloseAllSessions(ERR_INTERNET_DISCONNECTED,
                             quic::QUIC_PEER_GOING_AWAY);
  EXPECT_EQ(ERR_INTERNET_DISCONNECTED,
            stream->ReadResponseHeaders(callback_.callback()));

  // Now attempting to request a stream to the same origin should create
  // a new session.

  RequestBuilder builder2(this);
  EXPECT_EQ(ERR_IO_PENDING, builder2.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  stream = CreateStream(&builder2.request);
  stream.reset();  // Will reset stream 3.

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  socket_data2.ExpectAllReadDataConsumed();
  socket_data2.ExpectAllWriteDataConsumed();
}

// Regression test for crbug.com/700617. Test a write error during the
// crypto handshake will not hang QuicSessionPool::Job and should
// report QUIC_HANDSHAKE_FAILED to upper layers. Subsequent
// QuicSessionRequest should succeed without hanging.
TEST_P(QuicSessionPoolTest,
       WriteErrorInCryptoConnectWithAsyncHostResolutionSyncSessionCreation) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndDisableFeature(net::features::kAsyncQuicSession);
  Initialize();
  // Use unmocked crypto stream to do crypto connect.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START_WITH_CHLO_SENT);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  // Trigger PACKET_WRITE_ERROR when sending packets in crypto connect.
  socket_data.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Create request, should fail after the write of the CHLO fails.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_EQ(ERR_QUIC_HANDSHAKE_FAILED, callback_.WaitForResult());
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_FALSE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));

  // Verify new requests can be sent normally without hanging.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.Reset();
  MockQuicData socket_data2(version_);
  socket_data2.AddReadPauseForever();
  socket_data2.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data2.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder2(this);
  EXPECT_EQ(ERR_IO_PENDING, builder2.CallRequest());
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_TRUE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));
  // Run the message loop to complete host resolution.
  base::RunLoop().RunUntilIdle();

  // Complete handshake. QuicSessionPool::Job should complete and succeed.
  crypto_client_stream_factory_.las
"""


```