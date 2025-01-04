Response:
The user wants a summary of the functionality of the provided C++ code snippet from Chromium's network stack. I need to analyze the code and list its main purposes. Specifically, I should look for:

1. **Core Functionality:** What does the code primarily test?  It looks like tests for `SSLClientSocket`.
2. **Interaction with JavaScript:**  Is there any explicit mention or implication of interaction with JavaScript?
3. **Logical Reasoning:** Are there test cases with clear inputs and expected outputs?
4. **Common Usage Errors:** Does the code highlight potential mistakes users or developers might make when using SSL?
5. **Debugging Information:** How would a user end up in this code during debugging?
6. **Overall Function:** A concise summary of the code's purpose.

Let's break down the code section by section:

*   **Client Certificate Management:**  The first test (`ClientCertCallbacks`) deals with setting and observing changes in client certificates. This suggests testing the client certificate management features of `SSLClientSocket`.
*   **Client Certificate Signature Algorithm Selection:** The `ClientCertSignatureAlgorithm` test focuses on how the client selects the signature algorithm during client authentication, considering server preferences and TLS versions.
*   **Public Key Pinning (PKP) Bypass:** The `PKPBypassedSet` test checks if the `pkp_bypassed` flag is correctly set when PKP is bypassed due to a local trust anchor.
*   **Public Key Pinning (PKP) Enforcement:** The `PKPEnforced` test verifies that connections fail when the server certificate doesn't match the configured pins.
*   **Key Usage Extension:** The `SSLClientSocketKeyUsageTest` examines the enforcement of the `keyUsage` extension in certificates based on the chosen cipher suite.
*   **Certificate Transparency (CT) Requirement:** The `CTIsRequired` test checks if a connection fails when CT is required but not fulfilled.
*   **Ignoring Certificate Errors and CT:** `IgnoreCertificateErrorsBypassesRequiredCT` verifies that the `ignore_certificate_errors` flag bypasses CT requirements.
*   **PKP vs. CT Priority:** `PKPMoreImportantThanCT` confirms that PKP errors take precedence over CT errors.
*   **SCT Auditing:** `SCTAuditingReportCollected` tests that SCT reports are enqueued when auditing is enabled.
*   **Handshake Failure Handling:** Several tests (`HandshakeFailureServerHello`, `HandshakeFailureNoClientCerts`, `LateHandshakeFailureMissingClientCerts`, `LateHandshakeFailureSendClientCerts`) investigate how different `handshake_failure` alerts are handled.
*   **Access Denied Handling:** `AccessDeniedNoClientCerts` and `AccessDeniedClientCerts` check how `access_denied` alerts are interpreted.

Based on this analysis, I can now formulate the answer.
这个代码片段是 Chromium 网络栈中 `net/socket/ssl_client_socket_unittest.cc` 文件的一部分，主要功能是 **测试 `SSLClientSocket` 在处理客户端证书、公钥 pinning (PKP)、证书透明度 (CT) 以及各种 TLS 握手错误情况下的行为**。

以下是针对您提出的问题的详细说明：

**1. 功能列举:**

*   **客户端证书管理和回调测试 (`ClientCertCallbacks`):** 测试当设置或移除客户端证书时，`SSLClientContextObserver` 是否会收到正确的通知，以及客户端会话缓存是否受到影响。
*   **客户端证书签名算法选择 (`ClientCertSignatureAlgorithm`):**  测试 `SSLClientSocket` 如何根据客户端和服务器支持的签名算法以及 TLS 版本选择合适的签名算法。
*   **公钥 Pinning (PKP) 绕过测试 (`PKPBypassedSet`):**  测试当服务器证书被本地信任锚信任，但其公钥哈希与配置的 pin 不匹配时，`SSLInfo::pkp_bypassed` 标志是否被正确设置。
*   **公钥 Pinning (PKP) 强制执行测试 (`PKPEnforced`):** 测试当服务器证书的公钥哈希与配置的 pin 不匹配时，连接是否会失败，并返回 `ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN` 错误。
*   **证书 `keyUsage` 扩展测试 (`SSLClientSocketKeyUsageTest`):**  测试当服务器证书的 `keyUsage` 扩展与所选的密码套件不兼容时，连接是否会失败。
*   **证书透明度 (CT) 要求测试 (`CTIsRequired`):**  测试当服务器需要 CT 并且没有提供足够的 SCTs (Signed Certificate Timestamps) 时，连接是否会失败，并返回 `ERR_CERTIFICATE_TRANSPARENCY_REQUIRED` 错误。
*   **忽略证书错误绕过 CT 要求测试 (`IgnoreCertificateErrorsBypassesRequiredCT`):** 测试当 `SSLConfig::ignore_certificate_errors` 设置为 true 时，是否会忽略 CT 相关的错误。
*   **PKP 优先级高于 CT 测试 (`PKPMoreImportantThanCT`):**  测试当 PKP 和 CT 均不满足时，PKP 错误是否具有更高的优先级。
*   **SCT 审计报告收集测试 (`SCTAuditingReportCollected`):** 测试当 SCT 审计功能启用时，是否会调用 `SCTAuditingDelegate` 来收集 SCT 报告。
*   **TLS 握手失败错误处理测试 (`HandshakeFailureServerHello`, `HandshakeFailureNoClientCerts`, `LateHandshakeFailureMissingClientCerts`, `LateHandshakeFailureSendClientCerts`):** 测试 `SSLClientSocket` 如何将不同的 `handshake_failure` 警报映射到相应的网络错误码。
*   **TLS `access_denied` 错误处理测试 (`AccessDeniedNoClientCerts`, `AccessDeniedClientCerts`):** 测试 `SSLClientSocket` 如何将 `access_denied` 警报映射到相应的网络错误码，特别是针对是否请求客户端证书的情况。

**2. 与 JavaScript 的关系:**

这段 C++ 代码本身并不直接涉及 JavaScript 的执行。然而，Chromium 是一个浏览器，其网络栈负责处理浏览器发出的网络请求。JavaScript 代码可以通过浏览器提供的 API（例如 `fetch` 或 `XMLHttpRequest`）发起 HTTPS 请求，这些请求最终会由 Chromium 的网络栈（包括 `SSLClientSocket`）处理。

**举例说明:**

假设一个 JavaScript 网站尝试连接到一个需要客户端证书的 HTTPS 服务器：

```javascript
// JavaScript 代码
fetch('https://example.com:42', {
  // ... 其他 fetch 参数
}).then(response => {
  console.log('连接成功', response);
}).catch(error => {
  console.error('连接失败', error);
});
```

当执行这段 JavaScript 代码时，浏览器会创建相应的网络请求，并调用底层的 C++ 网络栈。`SSLClientSocket` 会负责建立与服务器的 SSL/TLS 连接，包括处理客户端证书的协商和验证，这正是这段 C++ 单元测试所覆盖的场景。如果服务器需要特定的客户端证书签名算法，`ClientCertSignatureAlgorithm` 测试中的逻辑就会被用到。如果服务器配置了公钥 pinning，那么 `PKPBypassedSet` 和 `PKPEnforced` 测试的相关代码会被执行。

**3. 逻辑推理和假设输入输出:**

**示例 1: `ClientCertSignatureAlgorithm` 测试**

*   **假设输入:**
    *   TLS 版本: TLS 1.3
    *   服务器支持的签名算法: `SSL_SIGN_RSA_PKCS1_SHA256_LEGACY`
    *   客户端支持的签名算法: `SSL_SIGN_RSA_PKCS1_SHA256`
    *   `net::features::kLegacyPKCS1ForTLS13` 特性启用

*   **预期输出:**
    *   连接成功 (`rv` 为 `IsOk()`)
    *   服务器收到的客户端签名算法为 `SSL_SIGN_RSA_PKCS1_SHA256_LEGACY`

**示例 2: `PKPEnforced` 测试**

*   **假设输入:**
    *   服务器证书的公钥哈希值与配置的 pin 不匹配。

*   **预期输出:**
    *   连接失败 (`rv` 为 `IsError(ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN)`)
    *   `SSLInfo::cert_status` 中包含 `CERT_STATUS_PINNED_KEY_MISSING`
    *   连接未建立 (`sock_->IsConnected()` 为 `false`)

**4. 用户或编程常见的使用错误:**

*   **未配置客户端证书:** 如果服务器要求客户端证书，但用户（通过浏览器设置或 JavaScript API）没有配置客户端证书，那么在 `LateHandshakeFailureMissingClientCerts` 测试场景中，可能会导致 `ERR_BAD_SSL_CLIENT_AUTH_CERT` 错误。
*   **客户端证书签名算法不匹配:** 如果客户端的证书和私钥不支持服务器要求的签名算法，`ClientCertSignatureAlgorithm` 测试会覆盖这种情况，并可能导致连接失败。
*   **公钥 Pinning 配置错误:**  开发者可能会错误地配置 PKP，例如使用了错误的公钥哈希值，导致 `PKPEnforced` 测试场景中的错误，用户会遇到 `ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN` 错误。
*   **忽略 CT 要求:**  如果服务器要求 CT，但用户的浏览器或网络环境无法满足 CT 的要求，`CTIsRequired` 测试会模拟这种情况，用户可能会遇到 `ERR_CERTIFICATE_TRANSPARENCY_REQUIRED` 错误。

**5. 用户操作如何到达这里 (调试线索):**

作为一个开发者，在调试网络连接问题时，可能会遇到以下情况并深入到 `SSLClientSocket` 的代码：

1. **客户端证书问题:** 用户报告无法连接到某个需要客户端证书的网站。开发者可能会查看网络日志，发现 SSL 握手失败，并怀疑是客户端证书配置或协商的问题。此时，可能会断点调试 `SSLClientSocket` 中处理客户端证书相关的代码。
2. **公钥 Pinning 错误:**  用户访问某个网站时出现 `ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN` 错误。开发者可能会检查该网站的 PKP 配置，并分析 `SSLClientSocket` 中 PKP 验证的逻辑。
3. **证书透明度 (CT) 错误:** 用户访问某个网站时出现 `ERR_CERTIFICATE_TRANSPARENCY_REQUIRED` 错误。开发者可能会检查服务器的 CT 配置，并调试 `SSLClientSocket` 中处理 CT 相关的代码。
4. **TLS 握手失败:**  用户连接网站时遇到连接被重置或超时等问题，网络日志显示 SSL 握手失败。开发者可能会检查服务器的 SSL/TLS 配置，并分析 `SSLClientSocket` 如何处理各种握手失败的警报。

**具体的调试步骤可能包括:**

*   **查看 net-internals:**  Chromium 提供了 `chrome://net-internals/#events` 页面，可以查看详细的网络事件日志，包括 SSL 握手过程和错误信息。
*   **使用 Wireshark 等抓包工具:**  可以捕获网络数据包，分析 SSL/TLS 握手的详细过程，包括发送的证书和警报信息。
*   **在 `SSLClientSocket` 的相关代码中设置断点:**  例如，在 `ClientCertSignatureAlgorithm` 测试涉及的代码中设置断点，可以观察客户端如何选择签名算法。
*   **修改测试代码并运行:**  开发者可能会修改 `ssl_client_socket_unittest.cc` 中的测试用例，模拟用户遇到的问题场景，以便更好地理解和调试。

**6. 功能归纳:**

总而言之，这段 `ssl_client_socket_unittest.cc` 的代码片段的主要功能是 **全面测试 `SSLClientSocket` 类在各种 SSL/TLS 连接场景下的正确性和健壮性**，特别关注客户端证书处理、公钥 pinning 实施、证书透明度验证以及对各种 TLS 握手错误的处理。这些测试确保了 Chromium 浏览器在处理 HTTPS 连接时的安全性、兼容性和可靠性。

Prompt: 
```
这是目录为net/socket/ssl_client_socket_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共8部分，请归纳一下它的功能

"""
on_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.client_cert_type = SSLServerConfig::REQUIRE_CLIENT_CERT;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  HostPortPair host_port_pair2("example.com", 42);
  testing::StrictMock<MockSSLClientContextObserver> observer;
  EXPECT_CALL(observer, OnSSLConfigForServersChanged(
                            base::flat_set<HostPortPair>({host_port_pair()})));
  EXPECT_CALL(observer, OnSSLConfigForServersChanged(
                            base::flat_set<HostPortPair>({host_port_pair2})));
  EXPECT_CALL(observer,
              OnSSLConfigChanged(
                  SSLClientContext::SSLConfigChangeType::kCertDatabaseChanged));

  context_->AddObserver(&observer);

  base::FilePath certs_dir = GetTestCertsDirectory();
  context_->SetClientCertificate(
      host_port_pair(), ImportCertFromFile(certs_dir, "client_1.pem"),
      key_util::LoadPrivateKeyOpenSSL(certs_dir.AppendASCII("client_1.key")));

  context_->SetClientCertificate(
      host_port_pair2, ImportCertFromFile(certs_dir, "client_2.pem"),
      key_util::LoadPrivateKeyOpenSSL(certs_dir.AppendASCII("client_2.key")));

  EXPECT_EQ(2U, context_->GetClientCertificateCachedServersForTesting().size());

  // Connect to `host_port_pair()` using the client cert.
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());

  EXPECT_EQ(1U, context_->ssl_client_session_cache()->size());

  CertDatabase::GetInstance()->NotifyObserversTrustStoreChanged();
  base::RunLoop().RunUntilIdle();

  // The `OnSSLConfigChanged` observer call should be verified by the
  // mock observer, but the client auth and client session cache should be
  // untouched.

  EXPECT_EQ(2U, context_->GetClientCertificateCachedServersForTesting().size());
  EXPECT_EQ(1U, context_->ssl_client_session_cache()->size());

  context_->RemoveObserver(&observer);
}

// Test client certificate signature algorithm selection.
TEST_F(SSLClientSocketTest, ClientCertSignatureAlgorithm) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<net::X509Certificate> client_cert =
      ImportCertFromFile(certs_dir, "client_1.pem");
  scoped_refptr<net::SSLPrivateKey> client_key =
      key_util::LoadPrivateKeyOpenSSL(certs_dir.AppendASCII("client_1.key"));

  const struct {
    const char* name;
    bool legacy_pkcs1_enabled = true;
    uint16_t version;
    std::vector<uint16_t> server_prefs;
    std::vector<uint16_t> client_prefs;
    Error error = OK;
    uint16_t expected_signature_algorithm = 0;
  } kTests[] = {
      {
          .name = "TLS 1.2 client preference",
          .version = SSL_PROTOCOL_VERSION_TLS1_2,
          .server_prefs = {SSL_SIGN_RSA_PSS_RSAE_SHA384,
                           SSL_SIGN_RSA_PSS_RSAE_SHA256},
          .client_prefs = {SSL_SIGN_RSA_PSS_RSAE_SHA256,
                           SSL_SIGN_RSA_PSS_RSAE_SHA384},
          // The client's preference should be used.
          .expected_signature_algorithm = SSL_SIGN_RSA_PSS_RSAE_SHA256,
      },
      {
          .name = "TLS 1.3 client preference",
          .version = SSL_PROTOCOL_VERSION_TLS1_3,
          .server_prefs = {SSL_SIGN_RSA_PSS_RSAE_SHA384,
                           SSL_SIGN_RSA_PSS_RSAE_SHA256},
          .client_prefs = {SSL_SIGN_RSA_PSS_RSAE_SHA256,
                           SSL_SIGN_RSA_PSS_RSAE_SHA384},
          // The client's preference should be used.
          .expected_signature_algorithm = SSL_SIGN_RSA_PSS_RSAE_SHA256,
      },

      {
          .name = "TLS 1.2 no common algorithms",
          .version = SSL_PROTOCOL_VERSION_TLS1_2,
          .server_prefs = {SSL_SIGN_RSA_PSS_RSAE_SHA384},
          .client_prefs = {SSL_SIGN_RSA_PSS_RSAE_SHA256},
          .error = ERR_SSL_CLIENT_AUTH_NO_COMMON_ALGORITHMS,
      },
      {
          .name = "TLS 1.3 no common algorithms",
          .version = SSL_PROTOCOL_VERSION_TLS1_3,
          .server_prefs = {SSL_SIGN_RSA_PSS_RSAE_SHA384},
          .client_prefs = {SSL_SIGN_RSA_PSS_RSAE_SHA256},
          .error = ERR_SSL_CLIENT_AUTH_NO_COMMON_ALGORITHMS,
      },

      {
          .name = "TLS 1.2 PKCS#1",
          .version = SSL_PROTOCOL_VERSION_TLS1_2,
          .server_prefs = {SSL_SIGN_RSA_PKCS1_SHA256},
          .client_prefs = {SSL_SIGN_RSA_PKCS1_SHA256},
          .expected_signature_algorithm = SSL_SIGN_RSA_PKCS1_SHA256,
      },
      {
          .name = "TLS 1.2 no PKCS#1",
          .version = SSL_PROTOCOL_VERSION_TLS1_3,
          .server_prefs = {SSL_SIGN_RSA_PKCS1_SHA256},
          .client_prefs = {SSL_SIGN_RSA_PKCS1_SHA256},
          // The rsa_pkcs1_sha256 codepoint may not be used in TLS 1.3, so the
          // TLS library should exclude it.
          .error = ERR_SSL_CLIENT_AUTH_NO_COMMON_ALGORITHMS,
      },

      // Test rsa_pkcs1_sha256_legacy. The value is omitted from `client_prefs`
      // because SSLPrivateKey implementations are not expected to specify
      // `SSL_SIGN_RSA_PKCS1_SHA256_LEGACY`. Instead, SSLClientSocket
      // automatically applies support when `SSL_SIGN_RSA_PKCS1_SHA256` is
      // available.
      {
          .name = "TLS 1.2 no legacy PKCS#1",
          .version = SSL_PROTOCOL_VERSION_TLS1_2,
          .server_prefs = {SSL_SIGN_RSA_PKCS1_SHA256_LEGACY},
          .client_prefs = {SSL_SIGN_RSA_PKCS1_SHA256},
          // The rsa_pkcs1_sha256_legacy codepoint is specifically for
          // restoring PKCS#1 to TLS 1.3, so it should not be accepted.
          .error = ERR_SSL_CLIENT_AUTH_NO_COMMON_ALGORITHMS,
      },
      {
          .name = "TLS 1.3 legacy PKCS#1",
          .version = SSL_PROTOCOL_VERSION_TLS1_3,
          .server_prefs = {SSL_SIGN_RSA_PKCS1_SHA256_LEGACY},
          .client_prefs = {SSL_SIGN_RSA_PKCS1_SHA256},
          // The rsa_pkcs1_sha256_legacy codepoint may be used in TLS 1.3.
          .expected_signature_algorithm = SSL_SIGN_RSA_PKCS1_SHA256_LEGACY,
      },
      {
          .name = "TLS 1.3 legacy PKCS#1 disabled",
          .legacy_pkcs1_enabled = false,
          .version = SSL_PROTOCOL_VERSION_TLS1_3,
          .server_prefs = {SSL_SIGN_RSA_PKCS1_SHA256_LEGACY},
          .client_prefs = {SSL_SIGN_RSA_PKCS1_SHA256},
          // The rsa_pkcs1_sha256_legacy codepoint may be used in TLS 1.3, but
          // was disabled.
          .error = ERR_SSL_CLIENT_AUTH_NO_COMMON_ALGORITHMS,
      },
      {
          .name = "TLS 1.3 legacy PKCS#1 not preferred",
          .version = SSL_PROTOCOL_VERSION_TLS1_3,
          .server_prefs = {SSL_SIGN_RSA_PKCS1_SHA256_LEGACY,
                           SSL_SIGN_RSA_PSS_RSAE_SHA256},
          .client_prefs = {SSL_SIGN_RSA_PKCS1_SHA256,
                           SSL_SIGN_RSA_PSS_RSAE_SHA256},
          // The legacy codepoint is only used when no other options are
          // available. The key supports PSS, so we will use PSS instead.
          .expected_signature_algorithm = SSL_SIGN_RSA_PSS_RSAE_SHA256,
      },
  };
  for (const auto& test : kTests) {
    SCOPED_TRACE(test.name);

    base::test::ScopedFeatureList scoped_feature_list;
    scoped_feature_list.InitWithFeatureState(
        net::features::kLegacyPKCS1ForTLS13, test.legacy_pkcs1_enabled);

    SSLServerConfig server_config;
    server_config.version_min = test.version;
    server_config.version_max = test.version;
    server_config.client_cert_type = SSLServerConfig::REQUIRE_CLIENT_CERT;
    server_config.client_cert_signature_algorithms = test.server_prefs;
    ASSERT_TRUE(
        StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

    // Connect with the client certificate.
    context_->SetClientCertificate(
        host_port_pair(), client_cert,
        WrapSSLPrivateKeyWithPreferences(client_key, test.client_prefs));
    int rv;
    ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
    if (test.error != OK) {
      EXPECT_THAT(rv, IsError(test.error));
      continue;
    }

    EXPECT_THAT(rv, IsOk());
    EXPECT_TRUE(sock_->IsConnected());

    // Capture the SSLInfo from the server to get the client's chosen signature
    // algorithm.
    EXPECT_THAT(MakeHTTPRequest(sock_.get(), "/ssl-info"), IsOk());
    std::optional<SSLInfo> server_ssl_info = LastSSLInfoFromServer();
    ASSERT_TRUE(server_ssl_info);
    EXPECT_EQ(server_ssl_info->peer_signature_algorithm,
              test.expected_signature_algorithm);
  }
}
#endif  // BUILDFLAG(ENABLE_CLIENT_CERTIFICATES)

HashValueVector MakeHashValueVector(uint8_t value) {
  HashValueVector out;
  HashValue hash(HASH_VALUE_SHA256);
  memset(hash.data(), value, hash.size());
  out.push_back(hash);
  return out;
}

// Test that |ssl_info.pkp_bypassed| is set when a local trust anchor causes
// pinning to be bypassed.
TEST_P(SSLClientSocketVersionTest, PKPBypassedSet) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      net::features::kStaticKeyPinningEnforcement);
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));
  scoped_refptr<X509Certificate> server_cert =
      embedded_test_server()->GetCertificate();

  // The certificate needs to be trusted, but chain to a local root with
  // different public key hashes than specified in the pin.
  CertVerifyResult verify_result;
  verify_result.is_issued_by_known_root = false;
  verify_result.verified_cert = server_cert;
  verify_result.public_key_hashes =
      MakeHashValueVector(kBadHashValueVectorInput);
  cert_verifier_->AddResultForCert(server_cert.get(), verify_result, OK);

  transport_security_state_->EnableStaticPinsForTesting();
  transport_security_state_->SetPinningListAlwaysTimelyForTesting(true);
  ScopedTransportSecurityStateSource scoped_security_state_source;

  SSLConfig ssl_config;
  int rv;
  HostPortPair new_host_port_pair("example.test", host_port_pair().port());
  ASSERT_TRUE(CreateAndConnectSSLClientSocketWithHost(ssl_config,
                                                      new_host_port_pair, &rv));
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));

  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());

  EXPECT_TRUE(ssl_info.pkp_bypassed);
  EXPECT_FALSE(ssl_info.cert_status & CERT_STATUS_PINNED_KEY_MISSING);
}

TEST_P(SSLClientSocketVersionTest, PKPEnforced) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      net::features::kStaticKeyPinningEnforcement);
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));
  scoped_refptr<X509Certificate> server_cert =
      embedded_test_server()->GetCertificate();

  // Certificate is trusted, but chains to a public root that doesn't match the
  // pin hashes.
  CertVerifyResult verify_result;
  verify_result.is_issued_by_known_root = true;
  verify_result.verified_cert = server_cert;
  verify_result.public_key_hashes =
      MakeHashValueVector(kBadHashValueVectorInput);
  cert_verifier_->AddResultForCert(server_cert.get(), verify_result, OK);

  transport_security_state_->EnableStaticPinsForTesting();
  transport_security_state_->SetPinningListAlwaysTimelyForTesting(true);
  ScopedTransportSecurityStateSource scoped_security_state_source;

  SSLConfig ssl_config;
  int rv;
  HostPortPair new_host_port_pair("example.test", host_port_pair().port());
  ASSERT_TRUE(CreateAndConnectSSLClientSocketWithHost(ssl_config,
                                                      new_host_port_pair, &rv));
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));

  EXPECT_THAT(rv, IsError(ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN));
  EXPECT_TRUE(ssl_info.cert_status & CERT_STATUS_PINNED_KEY_MISSING);
  EXPECT_FALSE(sock_->IsConnected());

  EXPECT_FALSE(ssl_info.pkp_bypassed);
}

namespace {
// TLS_RSA_WITH_AES_128_GCM_SHA256's key exchange involves encrypting to the
// server long-term key.
const uint16_t kEncryptingCipher = kRSACipher;
// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256's key exchange involves a signature by
// the server long-term key.
const uint16_t kSigningCipher = kModernTLS12Cipher;
}  // namespace

struct KeyUsageTest {
  EmbeddedTestServer::ServerCertificate server_cert;
  uint16_t cipher_suite;
  bool match;
};

class SSLClientSocketKeyUsageTest
    : public SSLClientSocketTest,
      public ::testing::WithParamInterface<
          std::tuple<KeyUsageTest, bool /*known_root*/>> {};

const KeyUsageTest kKeyUsageTests[] = {
    // keyUsage matches cipher suite.
    {EmbeddedTestServer::CERT_KEY_USAGE_RSA_DIGITAL_SIGNATURE, kSigningCipher,
     true},
    {EmbeddedTestServer::CERT_KEY_USAGE_RSA_ENCIPHERMENT, kEncryptingCipher,
     true},
    // keyUsage does not match cipher suite.
    {EmbeddedTestServer::CERT_KEY_USAGE_RSA_ENCIPHERMENT, kSigningCipher,
     false},
    {EmbeddedTestServer::CERT_KEY_USAGE_RSA_DIGITAL_SIGNATURE,
     kEncryptingCipher, false},
};

TEST_P(SSLClientSocketKeyUsageTest, RSAKeyUsage) {
  const auto& [test, known_root] = GetParam();
  SSLServerConfig server_config;
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.cipher_suite_for_testing = test.cipher_suite;
  ASSERT_TRUE(StartEmbeddedTestServer(test.server_cert, server_config));
  scoped_refptr<X509Certificate> server_cert =
      embedded_test_server()->GetCertificate();

  // Certificate is trusted.
  CertVerifyResult verify_result;
  verify_result.is_issued_by_known_root = known_root;
  verify_result.verified_cert = server_cert;
  verify_result.public_key_hashes =
      MakeHashValueVector(kGoodHashValueVectorInput);
  cert_verifier_->AddResultForCert(server_cert.get(), verify_result, OK);

  SSLConfig ssl_config;
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));

  if (test.match) {
    EXPECT_THAT(rv, IsOk());
    EXPECT_TRUE(sock_->IsConnected());
  } else {
    EXPECT_THAT(rv, IsError(ERR_SSL_KEY_USAGE_INCOMPATIBLE));
    EXPECT_FALSE(sock_->IsConnected());
  }
}

INSTANTIATE_TEST_SUITE_P(RSAKeyUsageInstantiation,
                         SSLClientSocketKeyUsageTest,
                         Combine(ValuesIn(kKeyUsageTests), Bool()));

// Test that when CT is required (in this case, by the delegate), the
// absence of CT information is a socket error.
TEST_P(SSLClientSocketVersionTest, CTIsRequired) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));
  scoped_refptr<X509Certificate> server_cert =
      embedded_test_server()->GetCertificate();

  // Certificate is trusted and chains to a public root.
  CertVerifyResult verify_result;
  verify_result.is_issued_by_known_root = true;
  verify_result.verified_cert = server_cert;
  verify_result.public_key_hashes =
      MakeHashValueVector(kGoodHashValueVectorInput);
  verify_result.policy_compliance =
      ct::CTPolicyCompliance::CT_POLICY_NOT_ENOUGH_SCTS;
  cert_verifier_->AddResultForCert(server_cert.get(), verify_result, OK);

  // Set up CT
  MockRequireCTDelegate require_ct_delegate;
  transport_security_state_->SetRequireCTDelegate(&require_ct_delegate);
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost(_, _, _))
      .WillRepeatedly(Return(TransportSecurityState::RequireCTDelegate::
                                 CTRequirementLevel::NOT_REQUIRED));
  EXPECT_CALL(require_ct_delegate,
              IsCTRequiredForHost(host_port_pair().host(), _, _))
      .WillRepeatedly(Return(TransportSecurityState::RequireCTDelegate::
                                 CTRequirementLevel::REQUIRED));

  SSLConfig ssl_config;
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));

  EXPECT_THAT(rv, IsError(ERR_CERTIFICATE_TRANSPARENCY_REQUIRED));
  EXPECT_TRUE(ssl_info.cert_status &
              CERT_STATUS_CERTIFICATE_TRANSPARENCY_REQUIRED);
  EXPECT_FALSE(sock_->IsConnected());
}

// Test that when CT is required, setting ignore_certificate_errors
// ignores errors in CT.
TEST_P(SSLClientSocketVersionTest, IgnoreCertificateErrorsBypassesRequiredCT) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));
  scoped_refptr<X509Certificate> server_cert =
      embedded_test_server()->GetCertificate();

  // Certificate is trusted and chains to a public root.
  CertVerifyResult verify_result;
  verify_result.is_issued_by_known_root = true;
  verify_result.verified_cert = server_cert;
  verify_result.public_key_hashes =
      MakeHashValueVector(kGoodHashValueVectorInput);
  verify_result.policy_compliance =
      ct::CTPolicyCompliance::CT_POLICY_NOT_ENOUGH_SCTS;
  cert_verifier_->AddResultForCert(server_cert.get(), verify_result, OK);

  // Set up CT
  MockRequireCTDelegate require_ct_delegate;
  transport_security_state_->SetRequireCTDelegate(&require_ct_delegate);
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost(_, _, _))
      .WillRepeatedly(Return(TransportSecurityState::RequireCTDelegate::
                                 CTRequirementLevel::NOT_REQUIRED));
  EXPECT_CALL(require_ct_delegate,
              IsCTRequiredForHost(host_port_pair().host(), _, _))
      .WillRepeatedly(Return(TransportSecurityState::RequireCTDelegate::
                                 CTRequirementLevel::REQUIRED));

  SSLConfig ssl_config;
  ssl_config.ignore_certificate_errors = true;
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));

  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(ssl_info.cert_status &
              CERT_STATUS_CERTIFICATE_TRANSPARENCY_REQUIRED);
  EXPECT_TRUE(sock_->IsConnected());
}

// When both PKP and CT are required for a host, and both fail, the more
// serious error is that the pin validation failed.
TEST_P(SSLClientSocketVersionTest, PKPMoreImportantThanCT) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      net::features::kStaticKeyPinningEnforcement);
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));
  scoped_refptr<X509Certificate> server_cert =
      embedded_test_server()->GetCertificate();

  // Certificate is trusted, but chains to a public root that doesn't match the
  // pin hashes.
  CertVerifyResult verify_result;
  verify_result.is_issued_by_known_root = true;
  verify_result.verified_cert = server_cert;
  verify_result.public_key_hashes =
      MakeHashValueVector(kBadHashValueVectorInput);
  verify_result.policy_compliance =
      ct::CTPolicyCompliance::CT_POLICY_NOT_ENOUGH_SCTS;
  cert_verifier_->AddResultForCert(server_cert.get(), verify_result, OK);

  transport_security_state_->EnableStaticPinsForTesting();
  transport_security_state_->SetPinningListAlwaysTimelyForTesting(true);
  ScopedTransportSecurityStateSource scoped_security_state_source;

  const char kCTHost[] = "hsts-hpkp-preloaded.test";

  // Set up CT.
  MockRequireCTDelegate require_ct_delegate;
  transport_security_state_->SetRequireCTDelegate(&require_ct_delegate);
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost(_, _, _))
      .WillRepeatedly(Return(TransportSecurityState::RequireCTDelegate::
                                 CTRequirementLevel::NOT_REQUIRED));
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost(kCTHost, _, _))
      .WillRepeatedly(Return(TransportSecurityState::RequireCTDelegate::
                                 CTRequirementLevel::REQUIRED));

  SSLConfig ssl_config;
  int rv;
  HostPortPair ct_host_port_pair(kCTHost, host_port_pair().port());
  ASSERT_TRUE(CreateAndConnectSSLClientSocketWithHost(ssl_config,
                                                      ct_host_port_pair, &rv));
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));

  EXPECT_THAT(rv, IsError(ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN));
  EXPECT_TRUE(ssl_info.cert_status & CERT_STATUS_PINNED_KEY_MISSING);
  EXPECT_TRUE(ssl_info.cert_status &
              CERT_STATUS_CERTIFICATE_TRANSPARENCY_REQUIRED);
  EXPECT_FALSE(sock_->IsConnected());
}

// Tests that the SCTAuditingDelegate is called to enqueue SCT reports.
TEST_P(SSLClientSocketVersionTest, SCTAuditingReportCollected) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));
  scoped_refptr<X509Certificate> server_cert =
      embedded_test_server()->GetCertificate();

  // Certificate is trusted and chains to a public root.
  CertVerifyResult verify_result;
  verify_result.is_issued_by_known_root = true;
  verify_result.verified_cert = server_cert;
  verify_result.public_key_hashes =
      MakeHashValueVector(kGoodHashValueVectorInput);
  verify_result.policy_compliance =
      ct::CTPolicyCompliance::CT_POLICY_COMPLIES_VIA_SCTS;
  cert_verifier_->AddResultForCert(server_cert.get(), verify_result, OK);

  // Set up CT and auditing delegate.
  MockRequireCTDelegate require_ct_delegate;
  transport_security_state_->SetRequireCTDelegate(&require_ct_delegate);
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost(_, _, _))
      .WillRepeatedly(Return(TransportSecurityState::RequireCTDelegate::
                                 CTRequirementLevel::REQUIRED));

  MockSCTAuditingDelegate sct_auditing_delegate;
  context_ = std::make_unique<SSLClientContext>(
      ssl_config_service_.get(), cert_verifier_.get(),
      transport_security_state_.get(), ssl_client_session_cache_.get(),
      &sct_auditing_delegate);

  EXPECT_CALL(sct_auditing_delegate, IsSCTAuditingEnabled())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(sct_auditing_delegate,
              MaybeEnqueueReport(host_port_pair(), server_cert.get(), _))
      .Times(1);

  SSLConfig ssl_config;
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  EXPECT_THAT(rv, 0);
  EXPECT_TRUE(sock_->IsConnected());
}

// Test that handshake_failure alerts at the ServerHello are mapped to
// ERR_SSL_VERSION_OR_CIPHER_MISMATCH.
TEST_F(SSLClientSocketTest, HandshakeFailureServerHello) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, SSLServerConfig()));

  TestCompletionCallback callback;
  auto real_transport = std::make_unique<TCPClientSocket>(
      addr(), nullptr, nullptr, nullptr, NetLogSource());
  auto transport =
      std::make_unique<FakeBlockingStreamSocket>(std::move(real_transport));
  FakeBlockingStreamSocket* raw_transport = transport.get();
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  ASSERT_THAT(rv, IsOk());

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), host_port_pair(), SSLConfig()));

  // Connect. Stop before the client processes ServerHello.
  raw_transport->BlockReadResult();
  rv = sock->Connect(callback.callback());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  raw_transport->WaitForReadResult();

  // Replace it with an alert.
  raw_transport->ReplaceReadResult(
      FormatTLS12Alert(40 /* AlertDescription.handshake_failure */));
  raw_transport->UnblockReadResult();

  rv = callback.GetResult(rv);
  EXPECT_THAT(rv, IsError(ERR_SSL_VERSION_OR_CIPHER_MISMATCH));
}

// Test that handshake_failure alerts after the ServerHello but without a
// CertificateRequest are mapped to ERR_SSL_PROTOCOL_ERROR.
TEST_F(SSLClientSocketTest, HandshakeFailureNoClientCerts) {
  SSLServerConfig server_config;
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  TestCompletionCallback callback;
  auto real_transport = std::make_unique<TCPClientSocket>(
      addr(), nullptr, nullptr, nullptr, NetLogSource());
  auto transport =
      std::make_unique<FakeBlockingStreamSocket>(std::move(real_transport));
  FakeBlockingStreamSocket* raw_transport = transport.get();
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  ASSERT_THAT(rv, IsOk());

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), host_port_pair(), SSLConfig()));

  // Connect. Stop before the client processes ServerHello.
  raw_transport->BlockReadResult();
  rv = sock->Connect(callback.callback());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  raw_transport->WaitForReadResult();

  // Release the ServerHello and wait for the client to write its second flight.
  raw_transport->BlockWrite();
  raw_transport->UnblockReadResult();
  raw_transport->WaitForWrite();

  // Wait for the server's final flight.
  raw_transport->BlockReadResult();
  raw_transport->UnblockWrite();
  raw_transport->WaitForReadResult();

  // Replace it with an alert.
  raw_transport->ReplaceReadResult(
      FormatTLS12Alert(40 /* AlertDescription.handshake_failure */));
  raw_transport->UnblockReadResult();

  rv = callback.GetResult(rv);
  EXPECT_THAT(rv, IsError(ERR_SSL_PROTOCOL_ERROR));
}

// Test that handshake_failure alerts after the ServerHello map to
// ERR_BAD_SSL_CLIENT_AUTH_CERT if a client certificate was requested but not
// supplied. TLS does not have an alert for this case, so handshake_failure is
// common. See https://crbug.com/646567.
TEST_F(SSLClientSocketTest, LateHandshakeFailureMissingClientCerts) {
  // Request a client certificate.
  SSLServerConfig server_config;
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.client_cert_type = SSLServerConfig::OPTIONAL_CLIENT_CERT;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  TestCompletionCallback callback;
  auto real_transport = std::make_unique<TCPClientSocket>(
      addr(), nullptr, nullptr, nullptr, NetLogSource());
  auto transport =
      std::make_unique<FakeBlockingStreamSocket>(std::move(real_transport));
  FakeBlockingStreamSocket* raw_transport = transport.get();
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  ASSERT_THAT(rv, IsOk());

  // Send no client certificate.
  context_->SetClientCertificate(host_port_pair(), nullptr, nullptr);
  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), host_port_pair(), SSLConfig()));

  // Connect. Stop before the client processes ServerHello.
  raw_transport->BlockReadResult();
  rv = sock->Connect(callback.callback());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  raw_transport->WaitForReadResult();

  // Release the ServerHello and wait for the client to write its second flight.
  raw_transport->BlockWrite();
  raw_transport->UnblockReadResult();
  raw_transport->WaitForWrite();

  // Wait for the server's final flight.
  raw_transport->BlockReadResult();
  raw_transport->UnblockWrite();
  raw_transport->WaitForReadResult();

  // Replace it with an alert.
  raw_transport->ReplaceReadResult(
      FormatTLS12Alert(40 /* AlertDescription.handshake_failure */));
  raw_transport->UnblockReadResult();

  rv = callback.GetResult(rv);
  EXPECT_THAT(rv, IsError(ERR_BAD_SSL_CLIENT_AUTH_CERT));
}

// Test that handshake_failure alerts after the ServerHello map to
// ERR_SSL_PROTOCOL_ERROR if received after sending a client certificate. It is
// assumed servers will send a more appropriate alert in this case.
TEST_F(SSLClientSocketTest, LateHandshakeFailureSendClientCerts) {
  // Request a client certificate.
  SSLServerConfig server_config;
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.client_cert_type = SSLServerConfig::OPTIONAL_CLIENT_CERT;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  TestCompletionCallback callback;
  auto real_transport = std::make_unique<TCPClientSocket>(
      addr(), nullptr, nullptr, nullptr, NetLogSource());
  auto transport =
      std::make_unique<FakeBlockingStreamSocket>(std::move(real_transport));
  FakeBlockingStreamSocket* raw_transport = transport.get();
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  ASSERT_THAT(rv, IsOk());

  // Send a client certificate.
  base::FilePath certs_dir = GetTestCertsDirectory();
  context_->SetClientCertificate(
      host_port_pair(), ImportCertFromFile(certs_dir, "client_1.pem"),
      key_util::LoadPrivateKeyOpenSSL(certs_dir.AppendASCII("client_1.key")));
  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), host_port_pair(), SSLConfig()));

  // Connect. Stop before the client processes ServerHello.
  raw_transport->BlockReadResult();
  rv = sock->Connect(callback.callback());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  raw_transport->WaitForReadResult();

  // Release the ServerHello and wait for the client to write its second flight.
  raw_transport->BlockWrite();
  raw_transport->UnblockReadResult();
  raw_transport->WaitForWrite();

  // Wait for the server's final flight.
  raw_transport->BlockReadResult();
  raw_transport->UnblockWrite();
  raw_transport->WaitForReadResult();

  // Replace it with an alert.
  raw_transport->ReplaceReadResult(
      FormatTLS12Alert(40 /* AlertDescription.handshake_failure */));
  raw_transport->UnblockReadResult();

  rv = callback.GetResult(rv);
  EXPECT_THAT(rv, IsError(ERR_SSL_PROTOCOL_ERROR));
}

// Test that access_denied alerts are mapped to ERR_SSL_PROTOCOL_ERROR if
// received on a connection not requesting client certificates. This is an
// incorrect use of the alert but is common. See https://crbug.com/630883.
TEST_F(SSLClientSocketTest, AccessDeniedNoClientCerts) {
  // Request a client certificate.
  SSLServerConfig server_config;
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  TestCompletionCallback callback;
  auto real_transport = std::make_unique<TCPClientSocket>(
      addr(), nullptr, nullptr, nullptr, NetLogSource());
  auto transport =
      std::make_unique<FakeBlockingStreamSocket>(std::move(real_transport));
  FakeBlockingStreamSocket* raw_transport = transport.get();
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  ASSERT_THAT(rv, IsOk());

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), host_port_pair(), SSLConfig()));

  // Connect. Stop before the client processes ServerHello.
  raw_transport->BlockReadResult();
  rv = sock->Connect(callback.callback());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  raw_transport->WaitForReadResult();

  // Release the ServerHello and wait for the client to write its second flight.
  raw_transport->BlockWrite();
  raw_transport->UnblockReadResult();
  raw_transport->WaitForWrite();

  // Wait for the server's final flight.
  raw_transport->BlockReadResult();
  raw_transport->UnblockWrite();
  raw_transport->WaitForReadResult();

  // Replace it with an alert.
  raw_transport->ReplaceReadResult(
      FormatTLS12Alert(49 /* AlertDescription.access_denied */));
  raw_transport->UnblockReadResult();

  rv = callback.GetResult(rv);
  EXPECT_THAT(rv, IsError(ERR_SSL_PROTOCOL_ERROR));
}

// Test that access_denied alerts are mapped to ERR_BAD_SSL_CLIENT_AUTH_CERT if
// received on a connection requesting client certificates.
TEST_F(SSLClientSocketTest, AccessDeniedClientCerts) {
  // Request a client certificate.
  SSLServerConfig server_config;
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.client_cert_type = SSLServerConfig::OPTIONAL_CLIENT_CERT;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  TestCompletionCallback callback;
  auto real_transport = std::make_unique<TCPClientSocket>(
      addr(), nullptr, nullptr, nullptr, NetLogSource());
  auto transport =
      std::make_unique<FakeBlockingStreamSocket>(std::move(real_transport));
  FakeBlockingStreamSocket* raw_transport = transport.get();
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  ASSERT_THAT(rv, IsOk());

  // Send a client certificate.
  base::FilePath certs_dir = GetTestCertsDirectory();
  context_->SetClientCertificate(
      host_port_pair(), ImportCertFromFile(certs_dir, "client_1.pem"),
      key_util::LoadPrivateKeyOpenSSL(certs_dir.AppendASCII("client_1.key")));
  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), host_port_pair(), SSLConfig()));

  // Connect. Stop before the client processes ServerHello.
  raw_transport->BlockReadResult();
  rv = sock->Connect(callback.callback());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  raw_transport->WaitForReadResult();

  // Release the ServerHello and wait for the client to write its second flight.
  raw_transport->BlockWrite();
  raw_transport->UnblockReadResult(
"""


```