Response:
My thought process for analyzing the `quic_session_pool_test.cc` file went something like this:

1. **Identify the Core Purpose:** The file name itself is a strong indicator: `quic_session_pool_test.cc`. The "test" suffix immediately tells me this is a testing file. The "quic_session_pool" part pinpoints the specific component being tested. Therefore, the primary function is to test the `QuicSessionPool` class in Chromium's network stack.

2. **Scan for Key Test Structures:** I looked for patterns common in C++ unit tests. Key things I searched for included:
    * `TEST_P`:  This indicates parameterized tests, meaning the same test logic is run with different sets of input values. The `_P` suffix is a giveaway.
    * `TEST`: Standard non-parameterized tests.
    * `EXPECT_...`:  These are assertion macros used to check if the code behaves as expected. `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `EXPECT_NE`, `EXPECT_THAT` are common examples.
    * Setup and Teardown: I looked for methods like `Initialize()` which likely sets up the test environment. While not explicitly present in this snippet, in larger test files, you often see `SetUp()` and `TearDown()` methods.
    * Mocking:  Keywords like `MockQuicData`, `MockTaggingClientSocketFactory`, and `MockCryptoClientStream` suggest the use of mocking to simulate dependencies and control their behavior during testing.

3. **Analyze Individual Tests (High-Level):**  I skimmed through the names of the test cases to get a sense of what aspects of `QuicSessionPool` are being tested. For example:
    * `DifferentProxyChain`:  Tests that sessions aren't reused if the proxy chain is different.
    * `DifferentSessionUsage`: Tests that sessions aren't reused based on intended usage (destination vs. proxy).
    * `DisjointCertificate`: Tests that certificate mismatches prevent session reuse.
    * `ClearCachedStatesInCryptoConfig`: Tests the ability to clear cached crypto states.
    * `ConfigConnectionOptions`: Tests that connection options are correctly applied.
    * `HostResolverUsesRequestPriority`: Checks how request priority affects host resolution.
    * `ResultAfterQuicSessionCreationCallback...`:  Tests asynchronous callbacks related to session creation.
    * `Tag`: Tests how socket tagging affects session reuse.

4. **Look for JavaScript Relevance:**  I considered how the `QuicSessionPool` might interact with JavaScript in a browser context. Key areas of connection include:
    * Fetch API:  JavaScript's `fetch()` API is a primary way to make network requests. The `QuicSessionPool` is part of the underlying mechanism that handles these requests efficiently.
    * WebSockets:  While not explicitly tested in this snippet, QUIC is used as a transport for WebSockets in some cases. Session pooling would be relevant here.
    * Service Workers:  Service workers can intercept network requests. The `QuicSessionPool` would be involved when a service worker initiates or intercepts a QUIC connection.

5. **Identify Potential User/Programming Errors:** Based on the tests, I thought about common mistakes:
    * Incorrect Proxy Configuration:  Using the wrong proxy settings can lead to connection failures or not reusing existing connections when they should be.
    * Certificate Issues:  Self-signed certificates or mismatched certificates can prevent secure connections.
    * Incorrectly Assuming Session Reuse: Developers might assume a new request will automatically reuse an existing session, but the tests highlight conditions (proxy chain, certificate, usage) that prevent this.

6. **Consider Debugging Scenarios:**  I imagined how a developer might end up looking at this code during debugging:
    * Investigating Connection Issues:  If a website isn't loading or is slow, a developer might look at network logs and then dive into the QUIC implementation to understand why a connection isn't being established or reused.
    * Debugging Proxy Behavior: If traffic isn't going through the expected proxy, this code could help understand how proxy chains are handled.
    * Understanding Session Pooling:  If a developer is trying to optimize network performance, they might investigate how session pooling works and why connections are (or aren't) being reused.

7. **Synthesize and Organize:** Finally, I organized my findings into the different categories requested: functionality, JavaScript relevance, logical reasoning (with hypothetical inputs/outputs), user/programming errors, debugging scenarios, and a summary of the file's purpose as part of a larger set. I tried to use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial Over-Focus on Specific Tests:** I initially spent too much time analyzing the details of individual tests. I realized I needed to step back and get a broader understanding of the overall purpose first.
* **Connecting to JavaScript:**  I initially struggled to make concrete connections to JavaScript. Thinking about the core browser APIs like `fetch()` and WebSockets helped bridge the gap.
* **Hypothetical Inputs/Outputs:**  For the logical reasoning, I had to think about what data the `QuicSessionPool` receives (request parameters, network conditions) and what it outputs (new sessions, reused sessions, errors). Framing it as specific test cases made it clearer.
* **User Errors vs. Programming Errors:** I refined my understanding of the difference. User errors are usually related to configuration, while programming errors are mistakes in the code using the API.

By following this structured approach, I could effectively analyze the provided code snippet and provide a comprehensive overview of its functionality and context within the Chromium project.
好的，这是对`net/quic/quic_session_pool_test.cc`文件功能的详细分析：

**文件功能总览:**

`net/quic/quic_session_pool_test.cc` 文件是 Chromium 网络栈中专门用于测试 `QuicSessionPool` 类的单元测试文件。 `QuicSessionPool` 的主要职责是管理和复用 QUIC 会话（connections），以提高网络连接效率和性能。

这个测试文件涵盖了 `QuicSessionPool` 的各种功能和边界情况，确保其在不同场景下都能正确工作。

**具体功能列举:**

1. **测试会话复用逻辑:**
   - 验证在满足特定条件（如相同的目标地址、证书、代理配置等）时，新的请求能够复用已存在的 QUIC 会话。
   - 验证在不满足复用条件时，`QuicSessionPool` 会创建新的会话。
   - 例如，测试 `DifferentProxyChain` 用例，它验证了当代理链不同时，会创建新的会话。

2. **测试阻止会话复用的场景:**
   - 验证在某些情况下，即使目标地址相同，会话也不应该被复用，例如：
     - 不同的代理配置 (`DifferentProxyChain`)
     - 不同的会话用途 (`DifferentSessionUsage`)，例如用于目标服务器与用于代理服务器的会话不应混用。
     - 目标服务器的证书不匹配 (`DisjointCertificate`)。

3. **测试 `QuicCryptoClientConfig` 的状态管理:**
   - 验证 `ClearCachedStatesInCryptoConfig` 方法能够正确清除与特定域名或所有域名相关的缓存的加密状态（例如，服务器的公钥、会话票据等）。这对于隐私保护和处理证书变更非常重要。

4. **测试 QUIC 配置参数:**
   - 验证通过 `QuicSessionPool` 设置的连接选项 (`connection_options`, `client_connection_options`) 和超时参数 (`max_time_before_crypto_handshake`, `max_idle_time_before_crypto_handshake`) 能正确传递到 `quic::QuicConfig` 中。

5. **测试 HostResolver 集成:**
   - 验证 `QuicSessionPool` 在请求连接时，能够正确使用 `HostResolver` 进行域名解析。
   - 验证能够传递和使用请求的优先级 (`MAXIMUM_PRIORITY`, `DEFAULT_PRIORITY`) 到 `HostResolver`。
   - 验证能够传递和使用安全 DNS 策略 (`SecureDnsPolicy::kDisable`) 和 `NetworkAnonymizationKey` 到 `HostResolver`。

6. **测试异步操作和回调:**
   - 验证 `WaitForQuicSessionCreation` 回调在 QUIC 会话创建成功或失败时能被正确触发。
   - 验证 `WaitForHostResolution` 回调在域名解析成功或失败时能被正确触发。
   - 测试了各种异步场景，包括主机解析和 TLS 握手同步或异步完成的情况。

7. **测试 Socket Tagging (套接字标记):**
   - 验证可以使用 `SocketTag` 来标记 QUIC 连接使用的套接字。
   - 验证具有相同 `SocketTag` 的请求可以复用相同的 QUIC 会话，而具有不同 `SocketTag` 的请求会创建新的会话。这在 Android 等平台上用于区分不同应用的流量。

8. **测试连接错误处理:**
   - 验证当底层套接字发生读取错误时，QUIC 连接会被正确关闭。

**与 JavaScript 功能的关系:**

`QuicSessionPool` 本身不直接与 JavaScript 代码交互。然而，它是浏览器网络栈的关键组成部分，当 JavaScript 发起网络请求时（例如，通过 `fetch` API 或 `XMLHttpRequest`），如果符合 QUIC 协议的条件，浏览器底层会使用 QUIC 进行连接，并由 `QuicSessionPool` 管理这些 QUIC 会话。

**举例说明:**

假设一个网页上的 JavaScript 代码使用 `fetch` API 请求两个不同的资源，来自同一个域名 `https://www.example.org`:

```javascript
fetch('https://www.example.org/resource1');
fetch('https://www.example.org/resource2');
```

当浏览器执行这段代码时，底层的网络栈会尝试建立到 `www.example.org` 的连接。`QuicSessionPool` 会负责查找是否已经存在到该域名的可复用的 QUIC 会话。如果存在，第二个 `fetch` 请求很可能会复用第一个请求建立的会话，从而减少连接建立的延迟。

如果两个 `fetch` 请求的目标域名不同，例如：

```javascript
fetch('https://www.example.org/resource1');
fetch('https://mail.example.org/resource2');
```

那么 `QuicSessionPool` 大概率不会复用会话，因为它管理的是到特定源 (origin) 的会话。

**逻辑推理和假设输入/输出:**

**假设输入:**

1. 两个连续的 HTTPS 请求，目标是相同的域名和端口 (`https://www.example.org`).
2. 没有中间代理或代理配置相同。
3. 服务器证书有效且匹配域名。
4. `QuicSessionPool` 中没有关于该域名的过期会话。

**预期输出:**

1. 第一个请求会创建一个新的 QUIC 会话。
2. 第二个请求会识别到已存在的会话，并复用该会话，而不是创建新的连接。

**用户或编程常见的使用错误:**

1. **错误地假设会话总是会被复用:** 开发者可能会认为只要目标域名相同，所有请求都会复用 QUIC 会话。但实际上，如测试用例所示，代理配置、证书等因素都会影响会话复用。如果依赖于错误的假设，可能会导致性能分析不准确或对网络行为的误解。

2. **不理解 Socket Tagging 的作用:** 在需要区分不同应用或场景的网络流量时，没有正确使用 `SocketTag` 可能会导致流量被错误地归类或影响 QoS 策略。

3. **在测试环境中没有正确模拟网络条件:**  开发者在测试网络功能时，如果没有考虑到 QUIC 会话复用的各种条件，可能会在本地测试中看到与实际部署环境不同的行为。

**用户操作如何到达这里 (调试线索):**

假设用户报告一个网站加载缓慢的问题，并且怀疑是 QUIC 连接没有被正确复用导致的。作为一名 Chromium 开发者，你可以按照以下步骤进行调试：

1. **启用 QUIC 日志:** 在 Chrome 中启用 `chrome://net-internals/#quic` 查看 QUIC 连接的详细信息。
2. **检查会话是否被复用:** 在 `chrome://net-internals/#events` 中查找与 QUIC 相关的事件，查看是否为同一个源创建了多个会话。
3. **分析 `QuicSessionPool` 的行为:** 如果怀疑是 `QuicSessionPool` 的问题，可以查看相关的代码和测试用例。
4. **运行 `quic_session_pool_test.cc` 中的特定测试:**  根据怀疑的问题，运行相关的测试用例，例如 `DifferentProxyChain` 或 `DisjointCertificate`，来验证 `QuicSessionPool` 在特定条件下的行为是否符合预期。
5. **添加调试日志:**  在 `QuicSessionPool` 的代码中添加额外的日志，以便更深入地了解会话创建和复用的决策过程。

**作为第 19 部分，共 20 部分的功能归纳:**

作为系列测试的第 19 部分，`quic_session_pool_test.cc` 继续深入测试 `QuicSessionPool` 的核心功能，特别关注了：

- **复杂的会话复用场景:**  例如，当涉及到代理和不同的会话用途时。
- **与底层网络组件的集成:**  例如，与 `HostResolver` 的交互以及如何传递和使用请求参数。
- **异步操作的处理:**  确保在各种异步完成的情况下，会话创建和域名解析的回调都能正确工作。
- **更细粒度的控制:** 例如，通过 `SocketTag` 对 QUIC 连接进行标记和管理。

这部分测试旨在确保 `QuicSessionPool` 在更复杂的实际网络环境中能够稳定可靠地工作，并且与其他网络组件能够良好地协同。它构建在之前的测试基础上，涵盖了更多边界情况和集成测试。

Prompt: 
```
这是目录为net/quic/quic_session_pool_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第19部分，共20部分，请归纳一下它的功能

"""
riority_header=*/true);
  client_maker_.Reset();
  server_maker_.Reset();

  MockQuicData socket_data2(version_);
  socket_data2.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(1));
  socket_data2.AddWrite(
      SYNCHRONOUS, ConstructConnectUdpRequestPacket(
                       2, stream_id, proxy2.host(),
                       "/.well-known/masque/udp/mail.example.org/443/", false));
  socket_data2.AddRead(ASYNC, ConstructServerSettingsPacket(3));
  socket_data2.AddRead(ASYNC, ConstructOkResponsePacket(4, stream_id, true));
  socket_data2.AddReadPauseForever();
  socket_data2.AddWrite(ASYNC,
                        client_maker_.Packet(3).AddAckFrame(3, 4, 3).Build());
  socket_data2.AddWrite(ASYNC,
                        ConstructClientH3DatagramPacket(
                            4, stream_id, kConnectUdpContextId,
                            endpoint_maker2.MakeInitialSettingsPacket(1)));
  socket_data2.AddSocketDataToFactory(socket_factory_.get());

  auto proxy_chain1 = ProxyChain::ForIpProtection({
      ProxyServer::FromSchemeHostAndPort(ProxyServer::SCHEME_QUIC,
                                         proxy1_origin.host(), 443),
  });
  EXPECT_TRUE(proxy_chain1.IsValid());

  auto proxy_chain2 = ProxyChain::ForIpProtection({
      ProxyServer::FromSchemeHostAndPort(ProxyServer::SCHEME_QUIC,
                                         proxy2_origin.host(), 443),
  });
  EXPECT_TRUE(proxy_chain2.IsValid());
  EXPECT_NE(proxy_chain1, proxy_chain2);

  RequestBuilder builder1(this);
  builder1.destination = destination;
  builder1.proxy_chain = proxy_chain1;
  builder1.http_user_agent_settings = &http_user_agent_settings_;
  builder1.url = url1;
  EXPECT_EQ(ERR_IO_PENDING, builder1.CallRequest());
  ASSERT_EQ(OK, callback_.WaitForResult());
  std::unique_ptr<HttpStream> stream1 = CreateStream(&builder1.request);
  EXPECT_TRUE(stream1.get());
  EXPECT_TRUE(HasActiveSession(origin1_, PRIVACY_MODE_DISABLED,
                               NetworkAnonymizationKey(), proxy_chain1));

  // There are ACKs still pending at this point, so to avoid confusing logs let
  // those finish before proceeding.
  RunUntilIdle();

  TestCompletionCallback callback2;
  RequestBuilder builder2(this);
  builder2.destination = destination;
  builder2.proxy_chain = proxy_chain2;
  builder2.http_user_agent_settings = &http_user_agent_settings_;
  builder2.url = url2;
  builder2.callback = callback2.callback();
  EXPECT_EQ(ERR_IO_PENDING, builder2.CallRequest());
  EXPECT_EQ(OK, callback2.WaitForResult());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());

  // `request2` does not pool to the first session, because `proxy_chain` does
  // not match.
  QuicChromiumClientSession::Handle* session1 =
      QuicHttpStreamPeer::GetSessionHandle(stream1.get());
  QuicChromiumClientSession::Handle* session2 =
      QuicHttpStreamPeer::GetSessionHandle(stream2.get());
  EXPECT_FALSE(session1->SharesSameSession(*session2));

  // Ensure the session finishes creating before proceeding.
  RunUntilIdle();

  socket_data1.ExpectAllReadDataConsumed();
  socket_data1.ExpectAllWriteDataConsumed();
  socket_data2.ExpectAllReadDataConsumed();
  socket_data2.ExpectAllWriteDataConsumed();
}

// QuicSessionRequest is not pooled if the SessionUsage field differs.
TEST_P(QuicSessionPoolWithDestinationTest, DifferentSessionUsage) {
  Initialize();

  GURL url1("https://www.example.org/");
  GURL url2("https://mail.example.org/");
  origin1_ = url::SchemeHostPort(url1);
  origin2_ = url::SchemeHostPort(url2);

  url::SchemeHostPort destination = GetDestination();

  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  ASSERT_TRUE(cert->VerifyNameMatch(origin1_.host()));
  ASSERT_TRUE(cert->VerifyNameMatch(origin2_.host()));
  ASSERT_FALSE(cert->VerifyNameMatch(kDifferentHostname));

  ProofVerifyDetailsChromium verify_details1;
  verify_details1.cert_verify_result.verified_cert = cert;
  verify_details1.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details1);

  ProofVerifyDetailsChromium verify_details2;
  verify_details2.cert_verify_result.verified_cert = cert;
  verify_details2.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details2);

  MockQuicData socket_data1(version_);
  socket_data1.AddReadPauseForever();
  socket_data1.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data1.AddSocketDataToFactory(socket_factory_.get());
  client_maker_.Reset();
  MockQuicData socket_data2(version_);
  socket_data2.AddReadPauseForever();
  socket_data2.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data2.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder1(this);
  builder1.destination = destination;
  builder1.session_usage = SessionUsage::kDestination;
  builder1.url = url1;
  EXPECT_EQ(ERR_IO_PENDING, builder1.CallRequest());
  EXPECT_EQ(OK, callback_.WaitForResult());
  std::unique_ptr<HttpStream> stream1 = CreateStream(&builder1.request);
  EXPECT_TRUE(stream1.get());
  EXPECT_TRUE(HasActiveSession(origin1_));

  TestCompletionCallback callback2;
  RequestBuilder builder2(this);
  builder2.destination = destination;
  builder2.session_usage = SessionUsage::kProxy;
  builder2.url = url2;
  builder2.callback = callback2.callback();
  EXPECT_EQ(ERR_IO_PENDING, builder2.CallRequest());
  EXPECT_EQ(OK, callback2.WaitForResult());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());

  // `request2` does not pool to the first session, because `session_usage`
  // does not match.
  QuicChromiumClientSession::Handle* session1 =
      QuicHttpStreamPeer::GetSessionHandle(stream1.get());
  QuicChromiumClientSession::Handle* session2 =
      QuicHttpStreamPeer::GetSessionHandle(stream2.get());
  EXPECT_FALSE(session1->SharesSameSession(*session2));
  socket_data1.ExpectAllReadDataConsumed();
  socket_data1.ExpectAllWriteDataConsumed();
  socket_data2.ExpectAllReadDataConsumed();
  socket_data2.ExpectAllWriteDataConsumed();
}

// QuicSessionRequest is not pooled if certificate does not match its origin.
TEST_P(QuicSessionPoolWithDestinationTest, DisjointCertificate) {
  Initialize();

  GURL url1("https://news.example.org/");
  GURL url2("https://mail.example.com/");
  origin1_ = url::SchemeHostPort(url1);
  origin2_ = url::SchemeHostPort(url2);

  url::SchemeHostPort destination = GetDestination();

  scoped_refptr<X509Certificate> cert1(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  ASSERT_TRUE(cert1->VerifyNameMatch(origin1_.host()));
  ASSERT_FALSE(cert1->VerifyNameMatch(origin2_.host()));
  ASSERT_FALSE(cert1->VerifyNameMatch(kDifferentHostname));

  ProofVerifyDetailsChromium verify_details1;
  verify_details1.cert_verify_result.verified_cert = cert1;
  verify_details1.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details1);

  scoped_refptr<X509Certificate> cert2(
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem"));
  ASSERT_TRUE(cert2->VerifyNameMatch(origin2_.host()));
  ASSERT_FALSE(cert2->VerifyNameMatch(kDifferentHostname));

  ProofVerifyDetailsChromium verify_details2;
  verify_details2.cert_verify_result.verified_cert = cert2;
  verify_details2.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details2);

  MockQuicData socket_data1(version_);
  socket_data1.AddReadPauseForever();
  socket_data1.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data1.AddSocketDataToFactory(socket_factory_.get());
  client_maker_.Reset();
  MockQuicData socket_data2(version_);
  socket_data2.AddReadPauseForever();
  socket_data2.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data2.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder1(this);
  builder1.destination = destination;
  builder1.url = url1;
  EXPECT_EQ(ERR_IO_PENDING, builder1.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream1 = CreateStream(&builder1.request);
  EXPECT_TRUE(stream1.get());
  EXPECT_TRUE(HasActiveSession(origin1_));

  TestCompletionCallback callback2;
  RequestBuilder builder2(this);
  builder2.destination = destination;
  builder2.url = url2;
  builder2.callback = callback2.callback();
  EXPECT_EQ(ERR_IO_PENDING, builder2.CallRequest());
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());

  // |request2| does not pool to the first session, because the certificate does
  // not match.  Instead, another session is opened to the same destination, but
  // with a different quic::QuicServerId.
  QuicChromiumClientSession::Handle* session1 =
      QuicHttpStreamPeer::GetSessionHandle(stream1.get());
  QuicChromiumClientSession::Handle* session2 =
      QuicHttpStreamPeer::GetSessionHandle(stream2.get());
  EXPECT_FALSE(session1->SharesSameSession(*session2));

  EXPECT_EQ(quic::QuicServerId(origin1_.host(), origin1_.port()),
            session1->server_id());
  EXPECT_EQ(quic::QuicServerId(origin2_.host(), origin2_.port()),
            session2->server_id());

  socket_data1.ExpectAllReadDataConsumed();
  socket_data1.ExpectAllWriteDataConsumed();
  socket_data2.ExpectAllReadDataConsumed();
  socket_data2.ExpectAllWriteDataConsumed();
}

// This test verifies that QuicSessionPool::ClearCachedStatesInCryptoConfig
// correctly transform an origin filter to a ServerIdFilter. Whether the
// deletion itself works correctly is tested in QuicCryptoClientConfigTest.
TEST_P(QuicSessionPoolTest, ClearCachedStatesInCryptoConfig) {
  Initialize();
  // Need to hold onto this through the test, to keep the QuicCryptoClientConfig
  // alive.
  std::unique_ptr<QuicCryptoClientConfigHandle> crypto_config_handle =
      QuicSessionPoolPeer::GetCryptoConfig(factory_.get(),
                                           NetworkAnonymizationKey());

  struct TestCase {
    TestCase(const std::string& host,
             int port,
             quic::QuicCryptoClientConfig* crypto_config)
        : server_id(host, port),
          state(crypto_config->LookupOrCreate(server_id)) {
      std::vector<string> certs(1);
      certs[0] = "cert";
      state->SetProof(certs, "cert_sct", "chlo_hash", "signature");
      state->set_source_address_token("TOKEN");
      state->SetProofValid();

      EXPECT_FALSE(state->certs().empty());
    }

    quic::QuicServerId server_id;
    raw_ptr<quic::QuicCryptoClientConfig::CachedState> state;
  } test_cases[] = {
      TestCase("www.google.com", 443, crypto_config_handle->GetConfig()),
      TestCase("www.example.com", 443, crypto_config_handle->GetConfig()),
      TestCase("www.example.com", 4433, crypto_config_handle->GetConfig())};

  // Clear cached states for the origin https://www.example.com:4433.
  GURL origin("https://www.example.com:4433");
  factory_->ClearCachedStatesInCryptoConfig(base::BindRepeating(
      static_cast<bool (*)(const GURL&, const GURL&)>(::operator==), origin));
  EXPECT_FALSE(test_cases[0].state->certs().empty());
  EXPECT_FALSE(test_cases[1].state->certs().empty());
  EXPECT_TRUE(test_cases[2].state->certs().empty());

  // Clear all cached states.
  factory_->ClearCachedStatesInCryptoConfig(
      base::RepeatingCallback<bool(const GURL&)>());
  EXPECT_TRUE(test_cases[0].state->certs().empty());
  EXPECT_TRUE(test_cases[1].state->certs().empty());
  EXPECT_TRUE(test_cases[2].state->certs().empty());
}

// Passes connection options and client connection options to QuicSessionPool,
// then checks that its internal quic::QuicConfig is correct.
TEST_P(QuicSessionPoolTest, ConfigConnectionOptions) {
  quic_params_->connection_options.push_back(quic::kTIME);
  quic_params_->connection_options.push_back(quic::kTBBR);
  quic_params_->connection_options.push_back(quic::kREJ);

  quic_params_->client_connection_options.push_back(quic::kTBBR);
  quic_params_->client_connection_options.push_back(quic::k1RTT);

  Initialize();

  const quic::QuicConfig* config =
      QuicSessionPoolPeer::GetConfig(factory_.get());
  EXPECT_EQ(quic_params_->connection_options, config->SendConnectionOptions());
  EXPECT_TRUE(config->HasClientRequestedIndependentOption(
      quic::kTBBR, quic::Perspective::IS_CLIENT));
  EXPECT_TRUE(config->HasClientRequestedIndependentOption(
      quic::k1RTT, quic::Perspective::IS_CLIENT));
}

// Verifies that the host resolver uses the request priority passed to
// QuicSessionRequest::Request().
TEST_P(QuicSessionPoolTest, HostResolverUsesRequestPriority) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  builder.priority = MAXIMUM_PRIORITY;
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  EXPECT_EQ(MAXIMUM_PRIORITY, host_resolver_->last_request_priority());

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, HostResolverRequestReprioritizedOnSetPriority) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  builder.priority = MAXIMUM_PRIORITY;
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_EQ(MAXIMUM_PRIORITY, host_resolver_->last_request_priority());
  EXPECT_EQ(MAXIMUM_PRIORITY, host_resolver_->request_priority(1));

  RequestBuilder builder2(this);
  builder2.priority = DEFAULT_PRIORITY;
  builder2.url = GURL(kServer2Url);
  EXPECT_EQ(ERR_IO_PENDING, builder2.CallRequest());
  EXPECT_EQ(DEFAULT_PRIORITY, host_resolver_->last_request_priority());
  EXPECT_EQ(DEFAULT_PRIORITY, host_resolver_->request_priority(2));

  builder.request.SetPriority(LOWEST);
  EXPECT_EQ(LOWEST, host_resolver_->request_priority(1));
  EXPECT_EQ(DEFAULT_PRIORITY, host_resolver_->request_priority(2));
}

// Verifies that the host resolver uses the disable secure DNS setting and
// NetworkAnonymizationKey passed to QuicSessionRequest::Request().
TEST_P(QuicSessionPoolTest, HostResolverUsesParams) {
  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  builder.network_anonymization_key = kNetworkAnonymizationKey;
  builder.secure_dns_policy = SecureDnsPolicy::kDisable;
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  EXPECT_EQ(net::SecureDnsPolicy::kDisable,
            host_resolver_->last_secure_dns_policy());
  ASSERT_TRUE(
      host_resolver_->last_request_network_anonymization_key().has_value());
  EXPECT_EQ(kNetworkAnonymizationKey,
            host_resolver_->last_request_network_anonymization_key().value());

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, ConfigMaxTimeBeforeCryptoHandshake) {
  quic_params_->max_time_before_crypto_handshake = base::Seconds(11);
  quic_params_->max_idle_time_before_crypto_handshake = base::Seconds(13);
  Initialize();

  const quic::QuicConfig* config =
      QuicSessionPoolPeer::GetConfig(factory_.get());
  EXPECT_EQ(quic::QuicTime::Delta::FromSeconds(11),
            config->max_time_before_crypto_handshake());
  EXPECT_EQ(quic::QuicTime::Delta::FromSeconds(13),
            config->max_idle_time_before_crypto_handshake());
}

// Verify ResultAfterQuicSessionCreationCallback behavior when the crypto
// handshake fails.
TEST_P(QuicSessionPoolTest, ResultAfterQuicSessionCreationCallbackFail) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddRead(SYNCHRONOUS, ERR_FAILED);
  socket_data.AddWrite(SYNCHRONOUS, ERR_FAILED);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());

  TestCompletionCallback quic_session_callback;
  EXPECT_TRUE(builder.request.WaitForQuicSessionCreation(
      quic_session_callback.callback()));

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(quic_session_callback.have_result());
  EXPECT_EQ(ERR_QUIC_PROTOCOL_ERROR, quic_session_callback.WaitForResult());

  // Calling WaitForQuicSessionCreation() a second time should return
  // false since the session has been created.
  EXPECT_FALSE(builder.request.WaitForQuicSessionCreation(
      quic_session_callback.callback()));

  EXPECT_TRUE(callback_.have_result());
  EXPECT_EQ(ERR_QUIC_PROTOCOL_ERROR, callback_.WaitForResult());
}

// Verify ResultAfterQuicSessionCreationCallback behavior when the crypto
// handshake succeeds synchronously.
TEST_P(QuicSessionPoolTest, ResultAfterQuicSessionCreationCallbackSuccessSync) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddRead(SYNCHRONOUS, OK);
  socket_data.AddWrite(SYNCHRONOUS, OK);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());

  TestCompletionCallback quic_session_callback;
  EXPECT_TRUE(builder.request.WaitForQuicSessionCreation(
      quic_session_callback.callback()));

  EXPECT_EQ(OK, quic_session_callback.WaitForResult());

  // Calling WaitForQuicSessionCreation() a second time should return
  // false since the session has been created.
  EXPECT_FALSE(builder.request.WaitForQuicSessionCreation(
      quic_session_callback.callback()));

  EXPECT_TRUE(callback_.have_result());
  EXPECT_EQ(OK, callback_.WaitForResult());
}

// Verify ResultAfterQuicSessionCreationCallback behavior when the crypto
// handshake succeeds asynchronously.
TEST_P(QuicSessionPoolTest,
       ResultAfterQuicSessionCreationCallbackSuccessAsync) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);

  MockQuicData socket_data(version_);
  socket_data.AddRead(SYNCHRONOUS, OK);
  socket_data.AddWrite(SYNCHRONOUS, OK);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());

  TestCompletionCallback quic_session_callback;
  EXPECT_TRUE(builder.request.WaitForQuicSessionCreation(
      quic_session_callback.callback()));

  EXPECT_EQ(ERR_IO_PENDING, quic_session_callback.WaitForResult());

  // Send Crypto handshake so connect will call back.
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  // Calling WaitForQuicSessionCreation() a second time should return
  // false since the session has been created.
  EXPECT_FALSE(builder.request.WaitForQuicSessionCreation(
      quic_session_callback.callback()));

  EXPECT_EQ(OK, callback_.WaitForResult());
}

// Verify ResultAfterHostResolutionCallback behavior when host resolution
// succeeds asynchronously, then crypto handshake fails synchronously.
TEST_P(QuicSessionPoolTest, ResultAfterHostResolutionCallbackAsyncSync) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  host_resolver_->set_ondemand_mode(true);

  MockQuicData socket_data(version_);
  socket_data.AddRead(SYNCHRONOUS, ERR_FAILED);
  socket_data.AddWrite(SYNCHRONOUS, ERR_FAILED);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());

  TestCompletionCallback host_resolution_callback;
  EXPECT_TRUE(builder.request.WaitForHostResolution(
      host_resolution_callback.callback()));

  // |host_resolver_| has not finished host resolution at this point, so
  // |host_resolution_callback| should not have a result.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(host_resolution_callback.have_result());

  // Allow |host_resolver_| to finish host resolution.
  // Since the request fails immediately after host resolution (getting
  // ERR_FAILED from socket reads/writes), |host_resolution_callback| should be
  // called with ERR_QUIC_PROTOCOL_ERROR since that's the next result in
  // forming the connection.
  host_resolver_->ResolveAllPending();
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(host_resolution_callback.have_result());
  EXPECT_EQ(ERR_IO_PENDING, host_resolution_callback.WaitForResult());

  // Calling WaitForHostResolution() a second time should return
  // false since host resolution has finished already.
  EXPECT_FALSE(builder.request.WaitForHostResolution(
      host_resolution_callback.callback()));

  EXPECT_TRUE(callback_.have_result());
  EXPECT_EQ(ERR_QUIC_PROTOCOL_ERROR, callback_.WaitForResult());
}

// Verify ResultAfterHostResolutionCallback behavior when host resolution
// succeeds asynchronously, then crypto handshake fails asynchronously.
TEST_P(QuicSessionPoolTest, ResultAfterHostResolutionCallbackAsyncAsync) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  host_resolver_->set_ondemand_mode(true);
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  factory_->set_has_quic_ever_worked_on_current_network(false);

  MockQuicData socket_data(version_);
  socket_data.AddReadPause();
  socket_data.AddRead(ASYNC, ERR_FAILED);
  socket_data.AddWrite(ASYNC, ERR_FAILED);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());

  TestCompletionCallback host_resolution_callback;
  EXPECT_TRUE(builder.request.WaitForHostResolution(
      host_resolution_callback.callback()));

  // |host_resolver_| has not finished host resolution at this point, so
  // |host_resolution_callback| should not have a result.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(host_resolution_callback.have_result());

  // Allow |host_resolver_| to finish host resolution. Since crypto handshake
  // will hang after host resolution, |host_resolution_callback| should run with
  // ERR_IO_PENDING since that's the next result in forming the connection.
  host_resolver_->ResolveAllPending();
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(host_resolution_callback.have_result());
  EXPECT_EQ(ERR_IO_PENDING, host_resolution_callback.WaitForResult());

  // Calling WaitForHostResolution() a second time should return
  // false since host resolution has finished already.
  EXPECT_FALSE(builder.request.WaitForHostResolution(
      host_resolution_callback.callback()));

  EXPECT_FALSE(callback_.have_result());
  socket_data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(callback_.have_result());
  EXPECT_EQ(ERR_QUIC_PROTOCOL_ERROR, callback_.WaitForResult());
}

// Verify ResultAfterHostResolutionCallback behavior when host resolution
// succeeds synchronously, then crypto handshake fails synchronously.
TEST_P(QuicSessionPoolTest, ResultAfterHostResolutionCallbackSyncSync) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  host_resolver_->set_synchronous_mode(true);

  MockQuicData socket_data(version_);
  socket_data.AddRead(SYNCHRONOUS, ERR_FAILED);
  socket_data.AddWrite(SYNCHRONOUS, ERR_FAILED);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());

  // WaitForHostResolution() should return false since host
  // resolution has finished already.
  TestCompletionCallback host_resolution_callback;
  EXPECT_FALSE(builder.request.WaitForHostResolution(
      host_resolution_callback.callback()));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(host_resolution_callback.have_result());
  EXPECT_TRUE(callback_.have_result());
  EXPECT_EQ(ERR_QUIC_PROTOCOL_ERROR, callback_.WaitForResult());
}

// Verify ResultAfterHostResolutionCallback behavior when host resolution
// succeeds synchronously, then crypto handshake fails asynchronously.
TEST_P(QuicSessionPoolTest, ResultAfterHostResolutionCallbackSyncAsync) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  // Host resolution will succeed synchronously, but Request() as a whole
  // will fail asynchronously.
  host_resolver_->set_synchronous_mode(true);
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  factory_->set_has_quic_ever_worked_on_current_network(false);

  MockQuicData socket_data(version_);
  socket_data.AddReadPause();
  socket_data.AddRead(ASYNC, ERR_FAILED);
  socket_data.AddWrite(ASYNC, ERR_FAILED);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());

  // WaitForHostResolution() should return false since host
  // resolution has finished already.
  TestCompletionCallback host_resolution_callback;
  EXPECT_FALSE(builder.request.WaitForHostResolution(
      host_resolution_callback.callback()));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(host_resolution_callback.have_result());

  EXPECT_FALSE(callback_.have_result());
  socket_data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(callback_.have_result());
  EXPECT_EQ(ERR_QUIC_PROTOCOL_ERROR, callback_.WaitForResult());
}

// Verify ResultAfterHostResolutionCallback behavior when host resolution fails
// synchronously.
TEST_P(QuicSessionPoolTest, ResultAfterHostResolutionCallbackFailSync) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  // Host resolution will fail synchronously.
  host_resolver_->rules()->AddSimulatedFailure(kDefaultServerHostName);
  host_resolver_->set_synchronous_mode(true);

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_NAME_NOT_RESOLVED, builder.CallRequest());

  // WaitForHostResolution() should return false since host
  // resolution has failed already.
  TestCompletionCallback host_resolution_callback;
  EXPECT_FALSE(builder.request.WaitForHostResolution(
      host_resolution_callback.callback()));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(host_resolution_callback.have_result());
}

// Verify ResultAfterHostResolutionCallback behavior when host resolution fails
// asynchronously.
TEST_P(QuicSessionPoolTest, ResultAfterHostResolutionCallbackFailAsync) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  host_resolver_->rules()->AddSimulatedFailure(kDefaultServerHostName);

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());

  TestCompletionCallback host_resolution_callback;
  EXPECT_TRUE(builder.request.WaitForHostResolution(
      host_resolution_callback.callback()));

  // Allow |host_resolver_| to fail host resolution. |host_resolution_callback|
  // Should run with ERR_NAME_NOT_RESOLVED since that's the error host
  // resolution failed with.
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(host_resolution_callback.have_result());
  EXPECT_EQ(ERR_NAME_NOT_RESOLVED, host_resolution_callback.WaitForResult());

  EXPECT_TRUE(callback_.have_result());
  EXPECT_EQ(ERR_NAME_NOT_RESOLVED, callback_.WaitForResult());
}

// Test that QuicSessionRequests with similar and different tags results in
// reused and unique QUIC streams using appropriately tagged sockets.
TEST_P(QuicSessionPoolTest, Tag) {
  socket_factory_ = std::make_unique<MockTaggingClientSocketFactory>();
  auto* socket_factory =
      static_cast<MockTaggingClientSocketFactory*>(socket_factory_.get());
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  // Prepare to establish two QUIC sessions.
  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());
  client_maker_.Reset();
  MockQuicData socket_data2(version_);
  socket_data2.AddReadPauseForever();
  socket_data2.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data2.AddSocketDataToFactory(socket_factory_.get());

#if BUILDFLAG(IS_ANDROID)
  SocketTag tag1(SocketTag::UNSET_UID, 0x12345678);
  SocketTag tag2(getuid(), 0x87654321);
#else
  // On non-Android platforms we can only use the default constructor.
  SocketTag tag1, tag2;
#endif

  // Request a stream with |tag1|.
  RequestBuilder builder1(this);
  builder1.socket_tag = tag1;
  int rv = builder1.CallRequest();
  EXPECT_THAT(callback_.GetResult(rv), IsOk());
  EXPECT_EQ(socket_factory->GetLastProducedUDPSocket()->tag(), tag1);
  EXPECT_TRUE(socket_factory->GetLastProducedUDPSocket()
                  ->tagged_before_data_transferred());
  std::unique_ptr<QuicChromiumClientSession::Handle> stream1 =
      builder1.request.ReleaseSessionHandle();
  EXPECT_TRUE(stream1);
  EXPECT_TRUE(stream1->IsConnected());

  // Request a stream with |tag1| and verify underlying session is reused.
  RequestBuilder builder2(this);
  builder2.socket_tag = tag1;
  rv = builder2.CallRequest();
  EXPECT_THAT(callback_.GetResult(rv), IsOk());
  std::unique_ptr<QuicChromiumClientSession::Handle> stream2 =
      builder2.request.ReleaseSessionHandle();
  EXPECT_TRUE(stream2);
  EXPECT_TRUE(stream2->IsConnected());
  EXPECT_TRUE(stream2->SharesSameSession(*stream1));

  // Request a stream with |tag2| and verify a new session is created.
  RequestBuilder builder3(this);
  builder3.socket_tag = tag2;
  rv = builder3.CallRequest();
  EXPECT_THAT(callback_.GetResult(rv), IsOk());
  EXPECT_EQ(socket_factory->GetLastProducedUDPSocket()->tag(), tag2);
  EXPECT_TRUE(socket_factory->GetLastProducedUDPSocket()
                  ->tagged_before_data_transferred());
  std::unique_ptr<QuicChromiumClientSession::Handle> stream3 =
      builder3.request.ReleaseSessionHandle();
  EXPECT_TRUE(stream3);
  EXPECT_TRUE(stream3->IsConnected());
#if BUILDFLAG(IS_ANDROID)
  EXPECT_FALSE(stream3->SharesSameSession(*stream1));
#else
  // Same tag should reuse session.
  EXPECT_TRUE(stream3->SharesSameSession(*stream1));
#endif
}

TEST_P(QuicSessionPoolTest, ReadErrorClosesConnection) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetail
"""


```