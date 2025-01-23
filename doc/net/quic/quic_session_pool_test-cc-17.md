Response:
My thought process for analyzing the provided C++ code snippet and generating the response went through these stages:

1. **Understanding the Core Task:** The request asks for an analysis of a Chromium networking stack source file, `net/quic/quic_session_pool_test.cc`. The key aspects to cover are its function, relationship to JavaScript, logical reasoning with examples, potential user/programming errors, debugging, and a summary of its functionality in the broader context.

2. **Initial Code Scan and Keyword Identification:** I started by quickly reading through the code, looking for recurring patterns, key classes, and function names. I noticed:
    * `TEST_P`: Indicates parameterized tests, suggesting a focus on testing various scenarios and configurations.
    * `QuicSessionPoolTest`: The primary test fixture, clearly the central subject.
    * `QuicSessionPoolPeer`:  A peer class, likely used for accessing private members for testing purposes.
    * `CryptoConfig`: Repeatedly used, hinting at the testing of crypto configuration management.
    * `NetworkAnonymizationKey`:  A significant concept being tested, related to connection partitioning.
    * `HttpServerProperties`:  Indicates interaction with caching of server properties.
    * `MockQuicData`, `MockCryptoClientStream`:  Test doubles (mocks) for simulating network behavior and crypto streams.
    * `RequestBuilder`:  A helper class for initiating requests within the tests.
    * `YieldAfterPackets`, `YieldAfterDuration`: Testing connection yielding mechanisms.
    * `PoolByOrigin`, `SharedCertificate`, `DifferentPrivacyMode`, `DifferentSecureDnsPolicy`, `DifferentProxyChain`: Explicit test cases for connection pooling logic based on different criteria.

3. **Deduction of Primary Functionality:** Based on the identified keywords and patterns, I concluded that the primary function of this file is to **thoroughly test the `QuicSessionPool` class**. This involves verifying:
    * **Connection Pooling Logic:** How and when connections are reused based on destination, origin, certificates, privacy mode, secure DNS policy, and proxy chains.
    * **Crypto Configuration Management:**  How crypto configurations are cached and reused, especially when `NetworkAnonymizationKey` is involved. The MRU (Most Recently Used) behavior of the cache is explicitly tested.
    * **Connection Yielding Mechanisms:**  Testing the `YieldAfterPackets` and `YieldAfterDuration` features.
    * **Error Handling and Failure Scenarios:**  Like the `InvalidCertificate` test.

4. **JavaScript Relationship Analysis:**  I considered the role of QUIC in the browser. QUIC is a transport protocol used for fetching web resources. JavaScript running in a browser initiates these resource requests. Therefore, while the C++ code itself isn't directly interacting with JavaScript *code*, the behavior it tests directly *affects* JavaScript's ability to load web pages efficiently and securely. The connection pooling and crypto configuration directly impact the performance and security of network requests initiated by JavaScript.

5. **Logical Reasoning and Examples:** For scenarios like crypto config caching and connection pooling, I constructed simple hypothetical inputs and outputs to illustrate the logic being tested. For instance, with `NetworkAnonymizationKey`, I showed how different keys lead to different configs initially and how those configs are retrieved later. For connection pooling, I demonstrated how requests to the same origin (or with a shared certificate) would be pooled.

6. **Identifying Potential Errors:** Based on my understanding of connection management and security, I identified potential user errors (like incorrect certificate configurations) and programming errors (like incorrect cache keying or logic for determining connection reusability).

7. **Debugging Context:** I explained how these tests serve as debugging tools for developers working on the QUIC implementation. A failing test pinpoints a bug in the connection pooling or crypto configuration logic. The specific test cases (like those involving different privacy modes) highlight the specific criteria being evaluated.

8. **归纳总结 (Summarization):**  Finally, I synthesized the findings into a concise summary, highlighting the key areas of functionality tested within this specific file. I also noted its position within the larger test suite (part 18 of 20), implying that it's a substantial part of the overall QUIC testing effort.

**Self-Correction/Refinement During the Process:**

* Initially, I might have focused too much on the low-level details of the QUIC protocol. I realized the request was more about the *testing* aspect and the higher-level functionalities being validated.
* I made sure to explicitly connect the C++ testing to the broader context of web browsing and how JavaScript interacts with the network.
* I paid attention to the specific prompts in the request, like providing examples for JavaScript relationships and user errors.
* I ensured the language was clear and avoided overly technical jargon where possible, while still maintaining accuracy.

By following this structured approach, I could systematically analyze the code snippet and provide a comprehensive and informative response that addressed all aspects of the request.
这是 Chromium 网络栈中 `net/quic/quic_session_pool_test.cc` 文件的第 18 部分，总共 20 部分。因此，这部分代码的功能可以被理解为 `QuicSessionPool` 类的测试用例集合中的一部分。

**主要功能归纳:**

这部分代码主要专注于测试 `QuicSessionPool` 类在以下几个方面的行为：

1. **`QuicCryptoClientConfig` 的缓存机制和 `NetworkAnonymizationKey` 的影响:**
   - **缓存的 MRU (Most Recently Used) 行为:**  测试在启用 `NetworkAnonymizationKey` 时，`QuicCryptoClientConfig` 缓存的最近最少使用策略是否正确工作。它验证了当缓存达到上限时，旧的配置是否会被正确地移除。
   - **`NetworkAnonymizationKey` 的隔离性:** 测试了不同的 `NetworkAnonymizationKey` 是否会对应不同的 `QuicCryptoClientConfig` 实例，以及这些配置是如何被缓存和恢复的。

2. **连接建立过程中的延时 (Yielding):**
   - **`YieldAfterPackets`:** 测试在发送一定数量的数据包后，连接建立过程是否会主动让出控制权，以避免阻塞事件循环。
   - **`YieldAfterDuration`:** 测试在经过一定时间后，连接建立过程是否会主动让出控制权。

3. **连接池化 (Connection Pooling) 的行为:**
   - **基于 Origin 的池化:** 测试了即使请求的目标地址不同，但 Origin 相同的情况下，是否能够重用已有的 QUIC 连接。
   - **基于 Destination 的池化和证书匹配:** 测试了连接是否会基于目标地址进行池化，并且验证了证书是否匹配目标地址。
   - **不同 `PrivacyMode` 的隔离:** 测试了具有不同 `PrivacyMode` 的请求是否会建立独立的 QUIC 连接，而不会重用现有的连接。
   - **不同安全 DNS 策略 (`SecureDnsPolicy`) 的隔离:** 测试了具有不同安全 DNS 策略的请求是否会建立独立的 QUIC 连接。
   - **不同代理链 (`ProxyChain`) 的隔离:** 测试了使用不同代理链的请求是否会建立独立的 QUIC 连接。

**与 JavaScript 的关系及举例:**

QUIC 协议是 HTTP/3 的底层传输协议，而 HTTP/3 是现代 Web 应用程序的重要组成部分。JavaScript 代码在浏览器中发起网络请求时，浏览器可能会选择使用 QUIC 协议来建立连接。

* **Crypto 配置缓存:**  当 JavaScript 发起 HTTPS 请求时，浏览器需要与服务器进行 TLS 握手来建立安全连接。`QuicCryptoClientConfig` 存储了与服务器的加密握手信息。如果配置被正确缓存，后续与同一服务器（或具有相同 `NetworkAnonymizationKey` 的服务器）的连接建立速度会更快。
    * **举例:** 用户访问 `https://example.com`，浏览器使用 QUIC 连接并缓存了相关的加密配置。之后，同一个页面上的 JavaScript 代码发起对 `https://example.com/api` 的请求，浏览器可以复用之前缓存的配置，加速连接建立过程。
* **连接池化:** 当 JavaScript 发起多个请求到同一个 Origin (域名 + 端口 + 协议) 时，浏览器会尝试复用已建立的 QUIC 连接，而不是为每个请求都建立新的连接，从而提高性能。
    * **举例:** 网页上的 JavaScript 代码同时加载多个图片资源，这些资源都来自同一个 CDN 服务器 (`https://cdn.example.com`)。浏览器会使用同一个 QUIC 连接来并行下载这些图片。
* **`NetworkAnonymizationKey`:**  这是一个用于在某些情况下（例如，使用不同的网络隔离策略）隔离连接的机制。这会影响浏览器如何决定是否可以重用现有的连接。
    * **举例:** 如果用户在不同的浏览情境下访问同一个网站（例如，普通浏览和隐私浏览），浏览器可能会使用不同的 `NetworkAnonymizationKey`，从而建立独立的 QUIC 连接，即使目标是同一个服务器。

**逻辑推理与假设输入输出:**

**示例 1: `CryptoConfigCacheMRUWithNetworkAnonymizationKey` 测试**

* **假设输入:**
    * 启用了 `features::kPartitionConnectionsByNetworkIsolationKey` 特性。
    * `kMaxRecentCryptoConfigs` 设置为 3。
    * 创建了 5 个不同的 `NetworkAnonymizationKey`，分别对应 `https://foo0.test/` 到 `https://foo4.test/`。
    * 依次为每个 `NetworkAnonymizationKey` 获取 `QuicCryptoClientConfigHandle`，并设置不同的 `user_agent_id` (0 到 4)。
    * 释放前 3 个 `NetworkAnonymizationKey` 对应的 `QuicCryptoClientConfigHandle`。
* **逻辑推理:** 由于缓存大小限制为 3，释放前 3 个 handle 后，重新获取这些 handle 时，由于它们是最近使用的，应该仍然能获取到之前设置的 `user_agent_id`。而最初的两个 `NetworkAnonymizationKey` 对应的配置可能已经被移除。
* **预期输出:**
    * 获取 `network_anonymization_keys[0]` 和 `network_anonymization_keys[1]` 的新 handle 时，`user_agent_id` 为空字符串 (或默认值)，因为它们可能已被移除。
    * 获取 `network_anonymization_keys[2]`, `network_anonymization_keys[3]`, `network_anonymization_keys[4]` 的新 handle 时，`user_agent_id` 分别为 "2", "3", "4"。

**示例 2: `PoolByOrigin` 测试**

* **假设输入:**
    * 发起对 `https://first.example.com` 的 QUIC 请求并成功建立连接。
    * 随后发起对 `https://second.example.com` 的 QUIC 请求，但这两个域名解析到相同的 IP 地址，且目标服务器支持相同的 Origin。
* **逻辑推理:** 由于 Origin (域名和端口) 相同，连接池应该尝试重用已建立的连接。
* **预期输出:** 第二个请求会复用第一个请求建立的 QUIC 连接，不会建立新的连接。

**用户或编程常见的使用错误:**

* **错误地配置证书:** 如果服务器的证书与请求的域名不匹配，QUIC 连接建立会失败。用户可能会看到类似 `NET::ERR_CERT_COMMON_NAME_INVALID` 的错误。测试用例 `InvalidCertificate` 就是为了验证这种情况。
* **缓存策略不当:** 如果 `QuicCryptoClientConfig` 的缓存策略配置不当，可能会导致性能下降（频繁进行 TLS 握手）或者安全问题。
* **连接池化逻辑错误:** 如果连接池的逻辑存在错误，可能导致连接无法被正确复用，或者在不应该复用的时候被复用，这会影响性能和安全性。例如，如果 `PrivacyMode` 或 `SecureDnsPolicy` 不同，应该建立新的连接，如果逻辑错误则可能复用旧连接。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入一个 HTTPS 地址 (例如 `https://example.com`) 并回车。**
2. **浏览器开始解析域名 `example.com` 的 IP 地址。**
3. **浏览器检查本地是否有可用的 QUIC 会话可以复用。** 这涉及到 `QuicSessionPool` 的查找逻辑。
4. **如果没有可用的会话，或者需要建立新的会话 (例如，`PrivacyMode` 不同)，浏览器会创建一个 `QuicSessionRequest`。**
5. **`QuicSessionPool` 负责管理 QUIC 会话的创建和复用。** 相关的测试用例会覆盖各种连接池化的场景。
6. **在建立连接的过程中，浏览器会获取服务器的证书并进行校验。** `InvalidCertificate` 测试覆盖了证书校验失败的情况。
7. **如果启用了 `NetworkAnonymizationKey`，浏览器会根据当前的上下文生成对应的 key，并影响 `QuicCryptoClientConfig` 的选择。** 相关的测试用例验证了 `NetworkAnonymizationKey` 对缓存的影响。
8. **在连接建立的早期阶段，可能会触发连接让出控制权的操作 (`YieldAfterPackets`, `YieldAfterDuration`)，以避免阻塞 UI 线程。** 相关的测试用例模拟了这种情况。

**作为第 18 部分的功能总结:**

作为 `quic_session_pool_test.cc` 文件的一部分，这部分代码深入测试了 `QuicSessionPool` 的核心功能，特别是：

* **`QuicCryptoClientConfig` 的精细化缓存行为和 `NetworkAnonymizationKey` 的作用。**
* **QUIC 连接建立过程中的延时控制机制。**
* **在不同场景下 (Origin, Destination, PrivacyMode, SecureDnsPolicy, ProxyChain) 的连接池化逻辑的正确性。**

这部分测试用例确保了 `QuicSessionPool` 能够高效、安全地管理 QUIC 连接，并能根据不同的网络环境和用户配置做出正确的决策。 它是保证 Chromium QUIC 实现质量的关键组成部分。

### 提示词
```
这是目录为net/quic/quic_session_pool_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第18部分，共20部分，请归纳一下它的功能
```

### 源代码
```cpp
onPoolPeer::GetCryptoConfig(factory_.get(),
                                           kNetworkAnonymizationKey1);
  std::unique_ptr<QuicCryptoClientConfigHandle> crypto_config_handle2_2 =
      QuicSessionPoolPeer::GetCryptoConfig(factory_.get(),
                                           kNetworkAnonymizationKey2);
  EXPECT_EQ(kUserAgentId1,
            crypto_config_handle1_2->GetConfig()->user_agent_id());
  EXPECT_EQ(kUserAgentId2,
            crypto_config_handle2_2->GetConfig()->user_agent_id());

  // Destroying all handles and creating a new one with yet another
  // NetworkAnonymizationKey return yet another config.
  crypto_config_handle1.reset();
  crypto_config_handle2.reset();
  crypto_config_handle1_2.reset();
  crypto_config_handle2_2.reset();

  std::unique_ptr<QuicCryptoClientConfigHandle> crypto_config_handle3 =
      QuicSessionPoolPeer::GetCryptoConfig(factory_.get(),
                                           kNetworkAnonymizationKey3);
  EXPECT_EQ("", crypto_config_handle3->GetConfig()->user_agent_id());
  crypto_config_handle3->GetConfig()->set_user_agent_id(kUserAgentId3);
  EXPECT_EQ(kUserAgentId3, crypto_config_handle3->GetConfig()->user_agent_id());
  crypto_config_handle3.reset();

  // The old CryptoConfigs should be recovered when creating handles with the
  // same NAKs as before.
  crypto_config_handle2 = QuicSessionPoolPeer::GetCryptoConfig(
      factory_.get(), kNetworkAnonymizationKey2);
  crypto_config_handle1 = QuicSessionPoolPeer::GetCryptoConfig(
      factory_.get(), kNetworkAnonymizationKey1);
  crypto_config_handle3 = QuicSessionPoolPeer::GetCryptoConfig(
      factory_.get(), kNetworkAnonymizationKey3);
  EXPECT_EQ(kUserAgentId1, crypto_config_handle1->GetConfig()->user_agent_id());
  EXPECT_EQ(kUserAgentId2, crypto_config_handle2->GetConfig()->user_agent_id());
  EXPECT_EQ(kUserAgentId3, crypto_config_handle3->GetConfig()->user_agent_id());
}

// Makes Verifies MRU behavior of the crypto config caches. Without
// NetworkAnonymizationKeys enabled, behavior is uninteresting, since there's
// only one cache, so nothing is ever evicted.
TEST_P(QuicSessionPoolTest, CryptoConfigCacheMRUWithNetworkAnonymizationKey) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  const int kNumSessionsToMake = kMaxRecentCryptoConfigs + 5;

  Initialize();

  // Make more entries than the maximum, setting a unique user agent for each,
  // and keeping the handles alives.
  std::vector<std::unique_ptr<QuicCryptoClientConfigHandle>>
      crypto_config_handles;
  std::vector<NetworkAnonymizationKey> network_anonymization_keys;
  for (int i = 0; i < kNumSessionsToMake; ++i) {
    SchemefulSite site(GURL(base::StringPrintf("https://foo%i.test/", i)));
    network_anonymization_keys.emplace_back(
        NetworkAnonymizationKey::CreateSameSite(site));

    std::unique_ptr<QuicCryptoClientConfigHandle> crypto_config_handle =
        QuicSessionPoolPeer::GetCryptoConfig(factory_.get(),
                                             network_anonymization_keys[i]);
    crypto_config_handle->GetConfig()->set_user_agent_id(
        base::NumberToString(i));
    crypto_config_handles.emplace_back(std::move(crypto_config_handle));
  }

  // Since all the handles are still alive, nothing should be evicted yet.
  for (int i = 0; i < kNumSessionsToMake; ++i) {
    SCOPED_TRACE(i);
    EXPECT_EQ(base::NumberToString(i),
              crypto_config_handles[i]->GetConfig()->user_agent_id());

    // A new handle for the same NAK returns the same crypto config.
    std::unique_ptr<QuicCryptoClientConfigHandle> crypto_config_handle =
        QuicSessionPoolPeer::GetCryptoConfig(factory_.get(),
                                             network_anonymization_keys[i]);
    EXPECT_EQ(base::NumberToString(i),
              crypto_config_handle->GetConfig()->user_agent_id());
  }

  // Destroying the only remaining handle for a NAK results in evicting entries,
  // until there are exactly |kMaxRecentCryptoConfigs| handles.
  for (int i = 0; i < kNumSessionsToMake; ++i) {
    SCOPED_TRACE(i);
    EXPECT_EQ(base::NumberToString(i),
              crypto_config_handles[i]->GetConfig()->user_agent_id());

    crypto_config_handles[i].reset();

    // A new handle for the same NAK will return a new config, if the config was
    // evicted. Otherwise, it will return the same one.
    std::unique_ptr<QuicCryptoClientConfigHandle> crypto_config_handle =
        QuicSessionPoolPeer::GetCryptoConfig(factory_.get(),
                                             network_anonymization_keys[i]);
    if (kNumSessionsToMake - i > kNumSessionsToMake) {
      EXPECT_EQ("", crypto_config_handle->GetConfig()->user_agent_id());
    } else {
      EXPECT_EQ(base::NumberToString(i),
                crypto_config_handle->GetConfig()->user_agent_id());
    }
  }
}

// Similar to above test, but uses real requests, and doesn't keep Handles
// around, so evictions happen immediately.
TEST_P(QuicSessionPoolTest,
       CryptoConfigCacheMRUWithRealRequestsAndWithNetworkAnonymizationKey) {
  const int kNumSessionsToMake = kMaxRecentCryptoConfigs + 5;

  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);
  // Since HttpServerProperties caches the feature value, have to create a new
  // one.
  http_server_properties_ = std::make_unique<HttpServerProperties>();

  std::vector<NetworkAnonymizationKey> network_anonymization_keys;
  for (int i = 0; i < kNumSessionsToMake; ++i) {
    SchemefulSite site(GURL(base::StringPrintf("https://foo%i.test/", i)));
    network_anonymization_keys.emplace_back(
        NetworkAnonymizationKey::CreateSameSite(site));
  }

  const quic::QuicServerId kQuicServerId(kDefaultServerHostName,
                                         kDefaultServerPort);

  quic_params_->max_server_configs_stored_in_properties = 1;
  quic_params_->idle_connection_timeout = base::Seconds(500);
  Initialize();
  factory_->set_has_quic_ever_worked_on_current_network(true);
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  const quic::QuicConfig* config =
      QuicSessionPoolPeer::GetConfig(factory_.get());
  EXPECT_EQ(500, config->IdleNetworkTimeout().ToSeconds());
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();

  for (int i = 0; i < kNumSessionsToMake; ++i) {
    SCOPED_TRACE(i);
    crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

    QuicSessionPoolPeer::SetTaskRunner(factory_.get(), runner_.get());

    const AlternativeService alternative_service1(
        kProtoQUIC, kDefaultServerHostName, kDefaultServerPort);
    AlternativeServiceInfoVector alternative_service_info_vector;
    base::Time expiration = base::Time::Now() + base::Days(1);
    alternative_service_info_vector.push_back(
        AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
            alternative_service1, expiration, {version_}));
    http_server_properties_->SetAlternativeServices(
        url::SchemeHostPort(GURL(kDefaultUrl)), network_anonymization_keys[i],
        alternative_service_info_vector);

    http_server_properties_->SetMaxServerConfigsStoredInProperties(
        kDefaultMaxQuicServerEntries);

    std::unique_ptr<QuicServerInfo> quic_server_info =
        std::make_unique<PropertiesBasedQuicServerInfo>(
            kQuicServerId, PRIVACY_MODE_DISABLED, network_anonymization_keys[i],
            http_server_properties_.get());

    // Update quic_server_info's server_config and persist it.
    QuicServerInfo::State* state = quic_server_info->mutable_state();
    // Minimum SCFG that passes config validation checks.
    const char scfg[] = {// SCFG
                         0x53, 0x43, 0x46, 0x47,
                         // num entries
                         0x01, 0x00,
                         // padding
                         0x00, 0x00,
                         // EXPY
                         0x45, 0x58, 0x50, 0x59,
                         // EXPY end offset
                         0x08, 0x00, 0x00, 0x00,
                         // Value
                         '1', '2', '3', '4', '5', '6', '7', '8'};

    // Create temporary strings because Persist() clears string data in |state|.
    string server_config(reinterpret_cast<const char*>(&scfg), sizeof(scfg));
    string source_address_token("test_source_address_token");
    string cert_sct("test_cert_sct");
    string chlo_hash("test_chlo_hash");
    string signature("test_signature");
    string test_cert("test_cert");
    std::vector<string> certs;
    certs.push_back(test_cert);
    state->server_config = server_config;
    state->source_address_token = source_address_token;
    state->cert_sct = cert_sct;
    state->chlo_hash = chlo_hash;
    state->server_config_sig = signature;
    state->certs = certs;

    quic_server_info->Persist();

    // Create a session and verify that the cached state is loaded.
    MockQuicData socket_data(version_);
    socket_data.AddReadPauseForever();
    client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
    socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
    // For the close socket message.
    socket_data.AddWrite(SYNCHRONOUS, ERR_IO_PENDING);
    socket_data.AddSocketDataToFactory(socket_factory_.get());
    client_maker_.Reset();

    RequestBuilder builder(this);
    builder.destination = url::SchemeHostPort(
        url::kHttpsScheme, kDefaultServerHostName, kDefaultServerPort);
    builder.network_anonymization_key = network_anonymization_keys[i];
    int rv = builder.CallRequest();
    EXPECT_THAT(callback_.GetResult(rv), IsOk());

    // While the session is still alive, there should be
    // kMaxRecentCryptoConfigs+1 CryptoConfigCaches alive, since active configs
    // don't count towards the limit.
    for (int j = 0; j < kNumSessionsToMake; ++j) {
      SCOPED_TRACE(j);
      EXPECT_EQ(
          i - (kMaxRecentCryptoConfigs + 1) < j && j <= i,
          !QuicSessionPoolPeer::CryptoConfigCacheIsEmpty(
              factory_.get(), kQuicServerId, network_anonymization_keys[j]));
    }

    // Close the sessions, which should cause its CryptoConfigCache to be moved
    // to the MRU cache, potentially evicting the oldest entry..
    factory_->CloseAllSessions(ERR_FAILED, quic::QUIC_PEER_GOING_AWAY);

    // There should now be at most kMaxRecentCryptoConfigs live
    // CryptoConfigCaches
    for (int j = 0; j < kNumSessionsToMake; ++j) {
      SCOPED_TRACE(j);
      EXPECT_EQ(
          i - kMaxRecentCryptoConfigs < j && j <= i,
          !QuicSessionPoolPeer::CryptoConfigCacheIsEmpty(
              factory_.get(), kQuicServerId, network_anonymization_keys[j]));
    }
  }
}

TEST_P(QuicSessionPoolTest, YieldAfterPackets) {
  Initialize();
  factory_->set_has_quic_ever_worked_on_current_network(true);
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  QuicSessionPoolPeer::SetYieldAfterPackets(factory_.get(), 0);

  MockQuicData socket_data(version_);
  socket_data.AddRead(SYNCHRONOUS, ConstructServerConnectionClosePacket(1));
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_->set_synchronous_mode(true);
  host_resolver_->rules()->AddIPLiteralRule(kDefaultServerHostName,
                                            "192.168.0.1", "");

  // Set up the TaskObserver to verify QuicChromiumPacketReader::StartReading
  // posts a task.
  // TODO(rtenneti): Change SpdySessionTestTaskObserver to NetTestTaskObserver??
  SpdySessionTestTaskObserver observer("quic_chromium_packet_reader.cc",
                                       "StartReading");

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  // Call run_loop so that QuicChromiumPacketReader::OnReadComplete() gets
  // called.
  base::RunLoop().RunUntilIdle();

  // Verify task that the observer's executed_count is 1, which indicates
  // QuicChromiumPacketReader::StartReading() has posted only one task and
  // yielded the read.
  EXPECT_EQ(1u, observer.executed_count());

  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_FALSE(stream.get());  // Session is already closed.
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, YieldAfterDuration) {
  Initialize();
  factory_->set_has_quic_ever_worked_on_current_network(true);
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  QuicSessionPoolPeer::SetYieldAfterDuration(
      factory_.get(), quic::QuicTime::Delta::FromMilliseconds(-1));

  MockQuicData socket_data(version_);
  socket_data.AddRead(SYNCHRONOUS, ConstructServerConnectionClosePacket(1));
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_->set_synchronous_mode(true);
  host_resolver_->rules()->AddIPLiteralRule(kDefaultServerHostName,
                                            "192.168.0.1", "");

  // Set up the TaskObserver to verify QuicChromiumPacketReader::StartReading
  // posts a task.
  // TODO(rtenneti): Change SpdySessionTestTaskObserver to NetTestTaskObserver??
  SpdySessionTestTaskObserver observer("quic_chromium_packet_reader.cc",
                                       "StartReading");

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  // Call run_loop so that QuicChromiumPacketReader::OnReadComplete() gets
  // called.
  base::RunLoop().RunUntilIdle();

  // Verify task that the observer's executed_count is 1, which indicates
  // QuicChromiumPacketReader::StartReading() has posted only one task and
  // yielded the read.
  EXPECT_EQ(1u, observer.executed_count());

  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_FALSE(stream.get());  // Session is already closed.
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

// Pool to existing session with matching quic::QuicServerId
// even if destination is different.
TEST_P(QuicSessionPoolTest, PoolByOrigin) {
  Initialize();

  url::SchemeHostPort destination1(url::kHttpsScheme, "first.example.com", 443);
  url::SchemeHostPort destination2(url::kHttpsScheme, "second.example.com",
                                   443);

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder1(this);
  builder1.destination = destination1;
  EXPECT_EQ(ERR_IO_PENDING, builder1.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream1 = CreateStream(&builder1.request);
  EXPECT_TRUE(stream1.get());
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  // Second request returns synchronously because it pools to existing session.
  TestCompletionCallback callback2;
  RequestBuilder builder2(this);
  builder2.destination = destination2;
  builder2.callback = callback2.callback();
  EXPECT_EQ(OK, builder2.CallRequest());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());

  QuicChromiumClientSession::Handle* session1 =
      QuicHttpStreamPeer::GetSessionHandle(stream1.get());
  QuicChromiumClientSession::Handle* session2 =
      QuicHttpStreamPeer::GetSessionHandle(stream2.get());
  EXPECT_TRUE(session1->SharesSameSession(*session2));
  EXPECT_EQ(quic::QuicServerId(kDefaultServerHostName, kDefaultServerPort),
            session1->server_id());

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

namespace {

enum DestinationType {
  // In pooling tests with two requests for different origins to the same
  // destination, the destination should be
  SAME_AS_FIRST,   // the same as the first origin,
  SAME_AS_SECOND,  // the same as the second origin, or
  DIFFERENT,       // different from both.
};

// Run QuicSessionPoolWithDestinationTest instances with all value
// combinations of version and destination_type.
struct PoolingTestParams {
  quic::ParsedQuicVersion version;
  DestinationType destination_type;
};

// Used by ::testing::PrintToStringParamName().
std::string PrintToString(const PoolingTestParams& p) {
  const char* destination_string = "";
  switch (p.destination_type) {
    case SAME_AS_FIRST:
      destination_string = "SAME_AS_FIRST";
      break;
    case SAME_AS_SECOND:
      destination_string = "SAME_AS_SECOND";
      break;
    case DIFFERENT:
      destination_string = "DIFFERENT";
      break;
  }
  return base::StrCat(
      {ParsedQuicVersionToString(p.version), "_", destination_string});
}

std::vector<PoolingTestParams> GetPoolingTestParams() {
  std::vector<PoolingTestParams> params;
  quic::ParsedQuicVersionVector all_supported_versions =
      AllSupportedQuicVersions();
  for (const quic::ParsedQuicVersion& version : all_supported_versions) {
    params.push_back(PoolingTestParams{version, SAME_AS_FIRST});
    params.push_back(PoolingTestParams{version, SAME_AS_SECOND});
    params.push_back(PoolingTestParams{version, DIFFERENT});
  }
  return params;
}

}  // namespace

class QuicSessionPoolWithDestinationTest
    : public QuicSessionPoolTestBase,
      public ::testing::TestWithParam<PoolingTestParams> {
 protected:
  QuicSessionPoolWithDestinationTest()
      : QuicSessionPoolTestBase(GetParam().version),
        destination_type_(GetParam().destination_type),
        hanging_read_(SYNCHRONOUS, ERR_IO_PENDING, 0) {}

  url::SchemeHostPort GetDestination() {
    switch (destination_type_) {
      case SAME_AS_FIRST:
        return origin1_;
      case SAME_AS_SECOND:
        return origin2_;
      case DIFFERENT:
        return url::SchemeHostPort(url::kHttpsScheme, kDifferentHostname, 443);
      default:
        NOTREACHED();
    }
  }

  void AddHangingSocketData() {
    auto sequenced_socket_data = std::make_unique<SequencedSocketData>(
        base::span_from_ref(hanging_read_), base::span<MockWrite>());
    socket_factory_->AddSocketDataProvider(sequenced_socket_data.get());
    sequenced_socket_data_vector_.push_back(std::move(sequenced_socket_data));
  }

  bool AllDataConsumed() {
    for (const auto& socket_data_ptr : sequenced_socket_data_vector_) {
      if (!socket_data_ptr->AllReadDataConsumed() ||
          !socket_data_ptr->AllWriteDataConsumed()) {
        return false;
      }
    }
    return true;
  }

  DestinationType destination_type_;
  url::SchemeHostPort origin1_;
  url::SchemeHostPort origin2_;
  MockRead hanging_read_;
  std::vector<std::unique_ptr<SequencedSocketData>>
      sequenced_socket_data_vector_;
};

INSTANTIATE_TEST_SUITE_P(VersionIncludeStreamDependencySequence,
                         QuicSessionPoolWithDestinationTest,
                         ::testing::ValuesIn(GetPoolingTestParams()),
                         ::testing::PrintToStringParamName());

// A single QUIC request fails because the certificate does not match the origin
// hostname, regardless of whether it matches the alternative service hostname.
TEST_P(QuicSessionPoolWithDestinationTest, InvalidCertificate) {
  if (destination_type_ == DIFFERENT) {
    return;
  }

  Initialize();

  GURL url("https://mail.example.com/");
  origin1_ = url::SchemeHostPort(url);

  // Not used for requests, but this provides a test case where the certificate
  // is valid for the hostname of the alternative service.
  origin2_ = url::SchemeHostPort(url::kHttpsScheme, "mail.example.org", 433);

  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  ASSERT_FALSE(cert->VerifyNameMatch(origin1_.host()));
  ASSERT_TRUE(cert->VerifyNameMatch(origin2_.host()));

  ProofVerifyDetailsChromium verify_details;
  verify_details.cert_verify_result.verified_cert = cert;
  verify_details.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  AddHangingSocketData();

  RequestBuilder builder(this);
  builder.destination = GetDestination();
  builder.url = url;
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsError(ERR_QUIC_HANDSHAKE_FAILED));

  EXPECT_TRUE(AllDataConsumed());
}

// QuicSessionRequest is pooled based on |destination| if certificate matches.
TEST_P(QuicSessionPoolWithDestinationTest, SharedCertificate) {
  Initialize();

  GURL url1("https://www.example.org/");
  GURL url2("https://mail.example.org/");
  origin1_ = url::SchemeHostPort(url1);
  origin2_ = url::SchemeHostPort(url2);

  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  ASSERT_TRUE(cert->VerifyNameMatch(origin1_.host()));
  ASSERT_TRUE(cert->VerifyNameMatch(origin2_.host()));
  ASSERT_FALSE(cert->VerifyNameMatch(kDifferentHostname));

  ProofVerifyDetailsChromium verify_details;
  verify_details.cert_verify_result.verified_cert = cert;
  verify_details.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder1(this);
  builder1.destination = GetDestination();
  builder1.url = url1;
  EXPECT_EQ(ERR_IO_PENDING, builder1.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());

  std::unique_ptr<HttpStream> stream1 = CreateStream(&builder1.request);
  EXPECT_TRUE(stream1.get());
  EXPECT_TRUE(HasActiveSession(origin1_));

  // Second request returns synchronously because it pools to existing session.
  TestCompletionCallback callback2;
  RequestBuilder builder2(this);
  builder2.destination = GetDestination();
  builder2.url = url2;
  builder2.callback = callback2.callback();
  EXPECT_EQ(OK, builder2.CallRequest());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());

  QuicChromiumClientSession::Handle* session1 =
      QuicHttpStreamPeer::GetSessionHandle(stream1.get());
  QuicChromiumClientSession::Handle* session2 =
      QuicHttpStreamPeer::GetSessionHandle(stream2.get());
  EXPECT_TRUE(session1->SharesSameSession(*session2));

  EXPECT_EQ(quic::QuicServerId(origin1_.host(), origin1_.port()),
            session1->server_id());

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

// QuicSessionRequest is not pooled if PrivacyMode differs.
TEST_P(QuicSessionPoolWithDestinationTest, DifferentPrivacyMode) {
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
  builder1.privacy_mode = PRIVACY_MODE_DISABLED;
  builder1.url = url1;
  EXPECT_EQ(ERR_IO_PENDING, builder1.CallRequest());
  EXPECT_EQ(OK, callback_.WaitForResult());
  std::unique_ptr<HttpStream> stream1 = CreateStream(&builder1.request);
  EXPECT_TRUE(stream1.get());
  EXPECT_TRUE(HasActiveSession(origin1_));

  TestCompletionCallback callback2;
  RequestBuilder builder2(this);
  builder2.destination = destination;
  builder2.privacy_mode = PRIVACY_MODE_ENABLED;
  builder2.url = url2;
  builder2.callback = callback2.callback();
  EXPECT_EQ(ERR_IO_PENDING, builder2.CallRequest());
  EXPECT_EQ(OK, callback2.WaitForResult());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());

  // |request2| does not pool to the first session, because PrivacyMode does not
  // match.  Instead, another session is opened to the same destination, but
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

// QuicSessionRequest is not pooled if the secure_dns_policy field differs.
TEST_P(QuicSessionPoolWithDestinationTest, DifferentSecureDnsPolicy) {
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
  builder1.secure_dns_policy = SecureDnsPolicy::kAllow;
  builder1.url = url1;
  EXPECT_EQ(ERR_IO_PENDING, builder1.CallRequest());
  EXPECT_EQ(OK, callback_.WaitForResult());
  std::unique_ptr<HttpStream> stream1 = CreateStream(&builder1.request);
  EXPECT_TRUE(stream1.get());
  EXPECT_TRUE(HasActiveSession(origin1_));

  TestCompletionCallback callback2;
  RequestBuilder builder2(this);
  builder2.destination = destination;
  builder2.secure_dns_policy = SecureDnsPolicy::kDisable;
  builder2.url = url2;
  builder2.callback = callback2.callback();
  EXPECT_EQ(ERR_IO_PENDING, builder2.CallRequest());
  EXPECT_EQ(OK, callback2.WaitForResult());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());

  // |request2| does not pool to the first session, because |secure_dns_policy|
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

// QuicSessionRequest is not pooled if the ProxyChain field differs.
TEST_P(QuicSessionPoolWithDestinationTest, DifferentProxyChain) {
  Initialize();

  GURL url1("https://www.example.org/");
  GURL url2("https://mail.example.org/");
  GURL proxy1(kProxy1Url);
  GURL proxy2(kProxy2Url);
  origin1_ = url::SchemeHostPort(url1);
  origin2_ = url::SchemeHostPort(url2);
  auto proxy1_origin = url::SchemeHostPort(proxy1);
  auto proxy2_origin = url::SchemeHostPort(proxy2);

  url::SchemeHostPort destination = GetDestination();

  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  ASSERT_TRUE(cert->VerifyNameMatch(origin1_.host()));
  ASSERT_TRUE(cert->VerifyNameMatch(origin2_.host()));
  ASSERT_TRUE(cert->VerifyNameMatch(proxy1_origin.host()));
  ASSERT_TRUE(cert->VerifyNameMatch(proxy2_origin.host()));

  ProofVerifyDetailsChromium verify_details1;
  verify_details1.cert_verify_result.verified_cert = cert;
  verify_details1.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details1);

  ProofVerifyDetailsChromium verify_details2;
  verify_details2.cert_verify_result.verified_cert = cert;
  verify_details2.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details2);

  client_maker_.set_use_priority_header(false);

  QuicTestPacketMaker endpoint_maker1(
      version_,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), origin1_.host(), quic::Perspective::IS_CLIENT,
      /*client_priority_uses_incremental=*/true,
      /*use_priority_header=*/true);

  const uint64_t stream_id = GetNthClientInitiatedBidirectionalStreamId(0);
  MockQuicData socket_data1(version_);
  socket_data1.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(1));
  socket_data1.AddWrite(
      SYNCHRONOUS, ConstructConnectUdpRequestPacket(
                       2, stream_id, proxy1.host(),
                       "/.well-known/masque/udp/www.example.org/443/", false));
  socket_data1.AddRead(ASYNC, ConstructServerSettingsPacket(3));
  socket_data1.AddRead(ASYNC, ConstructOkResponsePacket(4, stream_id, true));
  socket_data1.AddReadPauseForever();
  socket_data1.AddWrite(ASYNC,
                        client_maker_.Packet(3).AddAckFrame(3, 4, 3).Build());
  socket_data1.AddWrite(ASYNC,
                        ConstructClientH3DatagramPacket(
                            4, stream_id, kConnectUdpContextId,
                            endpoint_maker1.MakeInitialSettingsPacket(1)));
  socket_data1.AddSocketDataToFactory(socket_factory_.get());

  QuicTestPacketMaker endpoint_maker2(
      version_,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), origin2_.host(), quic::Perspective::IS_CLIENT,
      /*client_priority_uses_incremental=*/true,
      /*use_p
```