Response:
Let's break down the thought process for analyzing this code snippet.

**1. Understanding the Goal:**

The request asks for a functional summary of the provided C++ code, specifically focusing on its purpose within Chromium's networking stack (SSL client socket testing). It also requests connections to JavaScript, logical reasoning examples, common user/programming errors, debugging tips, and a final summary. The "Part 4 of 8" indicates this is part of a larger analysis, so the summary should reflect this portion.

**2. Initial Scan and Keyword Recognition:**

The first step is to quickly scan the code for recognizable keywords and patterns:

* **`net/socket/ssl_client_socket_unittest.cc`:** This immediately tells us it's a unit test file for SSL client socket functionality.
* **`TEST_P`, `TEST_F`:** These are Google Test macros, confirming it's a test file.
* **`SSLClientSocket`, `SSLConfig`, `SSLInfo`:**  These are core classes related to SSL/TLS client connections in Chromium.
* **`EmbeddedTestServer`:** This signifies the tests involve setting up a local test server to simulate real-world scenarios.
* **`cert_verifier_`, `transport_security_state_`:** These point to components responsible for certificate verification and HSTS (HTTP Strict Transport Security).
* **`ssl_client_session_cache_`:** This indicates testing of session resumption and caching.
* **`ALPN`, `False Start`, `SessionResumption`, `NetworkAnonymizationKey`:**  These are specific SSL/TLS features being tested.
* **`EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `EXPECT_THAT`, `ASSERT_TRUE`, `ASSERT_EQ`, `ASSERT_THAT`:** These are Google Test assertion macros, showing the expected outcomes of the tests.
* **File paths like `"redundant-validated-chain.pem"`:**  Indicates loading certificate files for testing.
* **Error codes like `ERR_CERT_DATE_INVALID`, `ERR_SSL_VERSION_OR_CIPHER_MISMATCH`:** Shows testing of error handling.
* **`BUILDFLAG(ENABLE_CLIENT_CERTIFICATES)`:**  Indicates conditional compilation and testing of client certificate features.

**3. Grouping Functionality by Test Case:**

The code is organized into distinct test cases using `TEST_P` and `TEST_F`. This is the logical way to group the functionality:

* **Redundant Chain Validation (`ConnectRedundantValidatedChain`):**  Focuses on how the client handles and reconstructs certificate chains with extra intermediate certificates.
* **Client Certificate Requests (`SSLClientSocketCertRequestInfoTest`):** Tests scenarios related to client certificate requests, including authorities and key types.
* **Certificate Transparency (`ConnectSignedCertTimestampsTLSExtension`, `ConnectSignedCertTimestampsEnablesOCSP`):** Verifies support for SCTs and OCSP stapling.
* **Connection States (`ReuseStates`):**  Tests the behavior of `IsConnectedAndIdle` and `WasEverUsed`.
* **Fatal Certificate Errors (`IsFatalErrorNotSetOnNonFatalError`, `IsFatalErrorSetOnFatalError`):** Checks how `is_fatal_cert_error` is set based on HSTS.
* **Write Buffering and Reusability (`ReusableAfterWrite`):** Tests socket reusability when writes are buffered.
* **Session Resumption (`SessionResumption`, `SessionResumption_RSA`, `SessionResumptionAlpn`, `SessionResumptionNetworkIsolationKeyDisabled`, `SessionResumptionNetworkIsolationKeyEnabled`, `CertificateErrorNoResume`):**  Extensive testing of session resumption scenarios, including ALPN and network isolation keys.
* **Cipher and Protocol Restrictions (`RequireECDHE`, `3DES`, `SHA1`):** Tests how the client handles restricted or disabled ciphers and signature algorithms.
* **False Start (`FalseStartEnabled`, `NoAlpn`, `RSA`, `NoAEAD`, `SessionResumption`, `CompleteHandshakeWithoutRequest`):** Tests the False Start optimization under various conditions.

**4. Identifying Key Concepts and Relationships:**

As we group the tests, we can identify the underlying concepts being validated:

* **Certificate Handling:** Correctly processing certificate chains, handling invalid certificates, verifying against trusted roots.
* **SSL/TLS Handshake:**  Initiating, negotiating, and completing the handshake process. Distinguishing between full handshakes and resumptions.
* **Session Management:** Caching and reusing SSL/TLS sessions for performance.
* **Security Features:**  Testing the implementation of features like Certificate Transparency, HSTS, ALPN, and False Start.
* **Error Handling:**  Properly handling and reporting SSL/TLS errors.

**5. Answering Specific Questions:**

* **Functionality Listing:**  This is a direct result of grouping the test cases.
* **JavaScript Relationship:**  Think about how these underlying SSL/TLS functionalities impact web browsers. Examples include secure HTTPS connections, the ability to handle certificate errors, and the performance benefits of session resumption.
* **Logical Reasoning (Input/Output):** For specific tests, consider what the setup is (e.g., adding a redundant certificate, configuring the server for a specific error) and what the expected outcome is (e.g., the `SSLInfo` containing the correct chain, a specific error code being returned).
* **User/Programming Errors:**  Think about common mistakes related to SSL/TLS, such as misconfigured certificates, disabled protocols, or incorrect handling of certificate errors in applications.
* **Debugging:** Consider how a developer might reach this code – by investigating SSL connection failures, performance issues, or security vulnerabilities. Logging and stepping through the code are key techniques.
* **Functionality Summary:** Combine the grouped functionalities and highlight the core purpose of the code.

**6. Iteration and Refinement:**

The initial analysis might be a bit rough. Review the code again, focusing on the details of each test case. Ensure the explanations are clear and concise. For example, when describing session resumption tests, mention the different scenarios being covered (different hostnames, network isolation keys, etc.).

**7. Structuring the Output:**

Organize the information logically using headings and bullet points to make it easy to read and understand. Start with the main function and then delve into specifics. Address each part of the request systematically.

By following this process, we can systematically analyze the code snippet and provide a comprehensive and accurate summary of its functionality. The key is to break down the problem into smaller, manageable parts and then synthesize the results.
这是目录为 `net/socket/ssl_client_socket_unittest.cc` 的 Chromium 网络栈源代码文件的第 4 部分，共 8 部分。基于提供的代码片段，我们可以归纳一下这部分的功能主要是测试 `SSLClientSocket` 的以下几个方面：

**主要功能归纳:**

1. **冗余证书链的处理:** 测试当服务器发送包含冗余证书的证书链时，客户端能否正确处理并构建出验证过的证书链。
2. **客户端证书请求信息:**  测试客户端在需要或可选客户端证书认证时，能否正确获取服务端发送的证书请求信息，包括可接受的证书颁发机构和签名算法等。
3. **证书透明度 (Certificate Transparency, CT):**  测试客户端是否支持并处理服务器发送的签名证书时间戳 (Signed Certificate Timestamps, SCTs) TLS 扩展，以及是否会因为 CT 的要求而启用 OCSP Stapling。
4. **连接状态管理:** 测试 `SSLClientSocket` 的连接状态，包括 `IsConnectedAndIdle` 和 `WasEverUsed` 的行为，以及在写入数据但未完全发送时连接状态的判断。
5. **致命证书错误处理:** 测试在非 HSTS 主机和 HSTS 主机上遇到证书错误时，`SSLInfo` 中 `is_fatal_cert_error` 标志的设置情况。
6. **会话恢复 (Session Resumption):**  测试客户端能否利用缓存的会话信息进行会话恢复，减少完整握手次数，包括在不同条件下（例如，不同的 HostPortPair、不同的网络隔离密钥 NetworkAnonymizationKey、遇到证书错误后）的会话恢复行为。
7. **特定密码套件和协议的限制:** 测试客户端对于禁用的密码套件（如 3DES）和签名算法（如 SHA-1）的处理，以及强制使用 ECDHE 密码套件的配置。
8. **TLS False Start:** 测试 TLS False Start 优化功能在各种条件下的启用和行为，以及 False Start 后会话是否可以恢复。
9. **握手完成即使没有请求:** 测试客户端即使在连接建立后没有发送任何请求，也能在后台完成 TLS 握手并保存会话信息。

**与 JavaScript 功能的关系及举例说明:**

虽然这段 C++ 代码是网络栈的底层实现，但其功能直接影响着 JavaScript 在浏览器中的 HTTPS 连接行为：

* **HTTPS 连接的建立:**  这段代码测试了客户端如何与服务器建立安全的 HTTPS 连接，这直接关系到 JavaScript 通过 `fetch` 或 `XMLHttpRequest` 发起 HTTPS 请求的成功与否。
* **证书验证和错误处理:** JavaScript 代码通常无法直接访问底层的证书验证细节，但当证书出现问题时（例如，过期、域名不匹配），浏览器会阻止 JavaScript 发起请求或显示安全警告。这段代码的测试确保了底层的证书验证逻辑的正确性。
    * **举例:**  如果 `IsFatalErrorSetOnFatalError` 测试失败，意味着在 HSTS 站点上遇到证书错误时，`is_fatal_cert_error` 没有被正确设置，浏览器可能不会阻止 JavaScript 发起潜在不安全的请求。
* **会话恢复的性能提升:**  JavaScript 发起的多个 HTTPS 请求，如果可以复用之前的 SSL/TLS 会话，可以显著减少握手时间，提高页面加载速度和网络性能。这段代码的会话恢复测试保证了这一优化的有效性。
    * **举例:**  `SessionResumption` 系列的测试确保了当用户多次访问同一个 HTTPS 站点时，后续的连接可以更快地建立。
* **ALPN 协议协商:** 这段代码测试了 ALPN 协议的协商，直接影响着浏览器和服务器之间选择的 HTTP 版本（例如，HTTP/2 或 HTTP/1.1），进而影响 JavaScript 代码的请求和响应方式。
    * **举例:**  `SessionResumptionAlpn` 测试确保了即使在会话恢复的情况下，ALPN 协议也能被正确地重新协商。
* **TLS False Start 的优化:**  TLS False Start 允许在 TLS 握手完成前发送应用数据，进一步提升 HTTPS 连接速度，这对 JavaScript 应用的性能至关重要。
    * **举例:**  `FalseStartEnabled` 测试确保了在满足条件的情况下，False Start 功能能够正常工作，从而加快 JavaScript 发起的请求的响应速度。

**逻辑推理的假设输入与输出:**

**假设输入 (以 `ConnectRedundantValidatedChain` 为例):**

* **输入:**
    * 服务器发送的证书链包含额外的中间证书，例如 A -> B -> C1 -> C2，其中 C1 是冗余的。
    * 客户端本地配置了一个规则，将服务器证书 A 映射到预期的验证链 A -> B -> C2。
    * 客户端信任 C2 作为根证书。
* **操作:** 客户端尝试与服务器建立 SSL 连接。

**输出:**

* `certs.size()` (加载的证书数量) 为 3。
* `ssl_info.cert` (验证后的证书链) 包含 2 个中间证书 (B 和 C2)，并且根证书为 C2 对应的根证书。
* `ssl_info.unverified_cert` (服务器发送的原始证书链) 包含 3 个中间证书 (B, C1, C2)。
* 连接建立成功 (`rv` 为 `IsOk()`)。

**涉及用户或编程常见的使用错误及举例说明:**

* **未正确处理证书错误:** 开发者可能会忽略证书错误，导致应用连接到不安全的站点。这段代码测试了在 HSTS 站点上证书错误的严重性，提醒开发者需要正确处理此类错误。
    * **举例:**  用户访问一个 HSTS 站点，但该站点的证书过期。如果开发者没有正确处理 `ERR_CERT_DATE_INVALID` 错误，可能会导致应用出现安全漏洞。
* **对 TLS False Start 的理解不足:** 开发者可能不清楚 TLS False Start 的工作原理和限制条件，导致在不满足条件的情况下期望 False Start 生效，从而难以排查性能问题。
    * **举例:**  开发者发现应用在某些情况下 HTTPS 连接建立速度较慢，可能需要检查服务器和客户端是否都支持 ALPN 和必要的密码套件，以确保 False Start 可以启用。
* **错误配置客户端证书:** 如果服务端要求客户端证书，开发者需要确保客户端已安装正确的证书，并且在 `SSLConfig` 中进行了正确的配置。

**用户操作如何一步步到达这里，作为调试线索:**

一个开发者在调试 Chromium 的网络功能时，可能会因为以下原因查看 `ssl_client_socket_unittest.cc`：

1. **HTTPS 连接问题:** 用户报告无法连接到某个 HTTPS 站点，或者连接过程中出现证书错误。开发者可能会运行相关的单元测试，例如测试证书验证、会话恢复或特定密码套件协商的测试，来验证客户端的实现是否正确。
2. **性能问题:** 用户报告页面加载速度慢，可能是 HTTPS 握手耗时过长。开发者可能会运行会话恢复和 TLS False Start 的测试，来排查性能瓶颈是否在 SSL/TLS 层。
3. **安全漏洞修复:** 当发现与 SSL/TLS 相关的安全漏洞时，开发者会编写或修改单元测试来验证修复方案的有效性，确保漏洞不再出现。
4. **新功能开发:** 在添加新的 SSL/TLS 功能时（例如，支持新的 TLS 版本或扩展），开发者会编写相应的单元测试来验证新功能的正确性。

**调试线索:**

* **复现问题:** 首先尝试在测试环境中复现用户报告的问题。
* **运行相关测试:**  根据问题的现象，运行 `ssl_client_socket_unittest.cc` 中相关的测试用例。例如，如果怀疑是证书问题，可以运行包含 "Cert" 关键字的测试；如果怀疑是会话恢复问题，可以运行包含 "SessionResumption" 关键字的测试。
* **查看日志:**  单元测试通常会输出详细的日志信息，可以帮助开发者了解测试的执行过程和结果。
* **断点调试:**  在单元测试代码中设置断点，可以单步执行代码，查看变量的值和程序的执行流程，从而定位问题。
* **分析测试覆盖率:**  检查单元测试的覆盖率，确保关键的网络栈代码都被充分测试到。

**总结 (针对第 4 部分):**

这部分 `ssl_client_socket_unittest.cc` 的代码主要集中在测试 `SSLClientSocket` 在处理复杂的证书链（包含冗余证书）、客户端证书请求、证书透明度相关功能、连接状态管理、致命证书错误处理以及会话恢复等方面的正确性和健壮性。此外，还测试了客户端对于特定密码套件和协议的限制以及 TLS False Start 优化功能的实现。这些测试覆盖了 SSL/TLS 客户端连接建立和管理的关键环节，对于保证 Chromium 浏览器的网络安全性和性能至关重要。

### 提示词
```
这是目录为net/socket/ssl_client_socket_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
"redundant-validated-chain.pem",
                                    X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(3U, certs.size());

  ASSERT_TRUE(certs[0]->EqualsExcludingChain(unverified_certs[0].get()));

  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> temp_intermediates;
  temp_intermediates.push_back(bssl::UpRef(certs[1]->cert_buffer()));
  temp_intermediates.push_back(bssl::UpRef(certs[2]->cert_buffer()));

  CertVerifyResult verify_result;
  verify_result.verified_cert = X509Certificate::CreateFromBuffer(
      bssl::UpRef(certs[0]->cert_buffer()), std::move(temp_intermediates));
  ASSERT_TRUE(verify_result.verified_cert);

  // Add a rule that maps the server cert (A) to the chain of A->B->C2
  // rather than A->B->C.
  cert_verifier_->AddResultForCert(certs[0].get(), verify_result, OK);

  // Load and install the root for the validated chain.
  scoped_refptr<X509Certificate> root_cert = ImportCertFromFile(
      GetTestCertsDirectory(), "redundant-validated-chain-root.pem");
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), root_cert.get());
  ScopedTestRoot scoped_root(root_cert);

  // Set up a test server with CERT_CHAIN_WRONG_ROOT.
  ASSERT_TRUE(StartEmbeddedTestServer(EmbeddedTestServer::CERT_CHAIN_WRONG_ROOT,
                                      GetServerConfig()));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());

  auto entries = log_observer_.GetEntries();
  EXPECT_TRUE(LogContainsEndEvent(entries, -1, NetLogEventType::SSL_CONNECT));

  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));

  // Verify that SSLInfo contains the corrected re-constructed chain A -> B
  // -> C2.
  ASSERT_TRUE(ssl_info.cert);
  const auto& intermediates = ssl_info.cert->intermediate_buffers();
  ASSERT_EQ(2U, intermediates.size());
  EXPECT_TRUE(x509_util::CryptoBufferEqual(ssl_info.cert->cert_buffer(),
                                           certs[0]->cert_buffer()));
  EXPECT_TRUE(x509_util::CryptoBufferEqual(intermediates[0].get(),
                                           certs[1]->cert_buffer()));
  EXPECT_TRUE(x509_util::CryptoBufferEqual(intermediates[1].get(),
                                           certs[2]->cert_buffer()));

  // Verify that SSLInfo also contains the chain as received from the server.
  ASSERT_TRUE(ssl_info.unverified_cert);
  const auto& served_intermediates =
      ssl_info.unverified_cert->intermediate_buffers();
  ASSERT_EQ(3U, served_intermediates.size());
  EXPECT_TRUE(x509_util::CryptoBufferEqual(ssl_info.cert->cert_buffer(),
                                           unverified_certs[0]->cert_buffer()));
  EXPECT_TRUE(x509_util::CryptoBufferEqual(served_intermediates[0].get(),
                                           unverified_certs[1]->cert_buffer()));
  EXPECT_TRUE(x509_util::CryptoBufferEqual(served_intermediates[1].get(),
                                           unverified_certs[2]->cert_buffer()));
  EXPECT_TRUE(x509_util::CryptoBufferEqual(served_intermediates[2].get(),
                                           unverified_certs[3]->cert_buffer()));

  sock_->Disconnect();
  EXPECT_FALSE(sock_->IsConnected());
}

// Client certificates are disabled on iOS.
#if BUILDFLAG(ENABLE_CLIENT_CERTIFICATES)
INSTANTIATE_TEST_SUITE_P(TLSVersion,
                         SSLClientSocketCertRequestInfoTest,
                         ValuesIn(GetTLSVersions()));

TEST_P(SSLClientSocketCertRequestInfoTest,
       DontRequestClientCertsIfServerCertInvalid) {
  SSLServerConfig config = GetServerConfig();
  config.client_cert_type = SSLServerConfig::OPTIONAL_CLIENT_CERT;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_EXPIRED, config));

  cert_verifier_->set_default_result(ERR_CERT_DATE_INVALID);
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsError(ERR_CERT_DATE_INVALID));
}

TEST_P(SSLClientSocketCertRequestInfoTest, NoAuthorities) {
  SSLServerConfig config = GetServerConfig();
  config.client_cert_type = SSLServerConfig::OPTIONAL_CLIENT_CERT;
  ASSERT_TRUE(StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, config));
  scoped_refptr<SSLCertRequestInfo> request_info = GetCertRequest();
  ASSERT_TRUE(request_info.get());
  EXPECT_EQ(0u, request_info->cert_authorities.size());
}

TEST_P(SSLClientSocketCertRequestInfoTest, TwoAuthorities) {
  const unsigned char kThawteDN[] = {
      0x30, 0x4c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
      0x02, 0x5a, 0x41, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x0a,
      0x13, 0x1c, 0x54, 0x68, 0x61, 0x77, 0x74, 0x65, 0x20, 0x43, 0x6f, 0x6e,
      0x73, 0x75, 0x6c, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x28, 0x50, 0x74, 0x79,
      0x29, 0x20, 0x4c, 0x74, 0x64, 0x2e, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03,
      0x55, 0x04, 0x03, 0x13, 0x0d, 0x54, 0x68, 0x61, 0x77, 0x74, 0x65, 0x20,
      0x53, 0x47, 0x43, 0x20, 0x43, 0x41};

  const unsigned char kDiginotarDN[] = {
      0x30, 0x5f, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
      0x02, 0x4e, 0x4c, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a,
      0x13, 0x09, 0x44, 0x69, 0x67, 0x69, 0x4e, 0x6f, 0x74, 0x61, 0x72, 0x31,
      0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x11, 0x44, 0x69,
      0x67, 0x69, 0x4e, 0x6f, 0x74, 0x61, 0x72, 0x20, 0x52, 0x6f, 0x6f, 0x74,
      0x20, 0x43, 0x41, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x09, 0x2a, 0x86, 0x48,
      0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x11, 0x69, 0x6e, 0x66, 0x6f,
      0x40, 0x64, 0x69, 0x67, 0x69, 0x6e, 0x6f, 0x74, 0x61, 0x72, 0x2e, 0x6e,
      0x6c};

  SSLServerConfig config = GetServerConfig();
  config.client_cert_type = SSLServerConfig::OPTIONAL_CLIENT_CERT;
  config.cert_authorities.emplace_back(std::begin(kThawteDN),
                                       std::end(kThawteDN));
  config.cert_authorities.emplace_back(std::begin(kDiginotarDN),
                                       std::end(kDiginotarDN));
  ASSERT_TRUE(StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, config));
  scoped_refptr<SSLCertRequestInfo> request_info = GetCertRequest();
  ASSERT_TRUE(request_info.get());
  EXPECT_EQ(config.cert_authorities, request_info->cert_authorities);
}

TEST_P(SSLClientSocketCertRequestInfoTest, CertKeyTypes) {
  SSLServerConfig config = GetServerConfig();
  config.client_cert_type = SSLServerConfig::OPTIONAL_CLIENT_CERT;
  ASSERT_TRUE(StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, config));
  scoped_refptr<SSLCertRequestInfo> request_info = GetCertRequest();
  ASSERT_TRUE(request_info);
  // Look for some values we expect BoringSSL to always send.
  EXPECT_THAT(request_info->signature_algorithms,
              testing::Contains(SSL_SIGN_ECDSA_SECP256R1_SHA256));
  EXPECT_THAT(request_info->signature_algorithms,
              testing::Contains(SSL_SIGN_RSA_PSS_RSAE_SHA256));
}
#endif  // BUILDFLAG(ENABLE_CLIENT_CERTIFICATES)

// Tests that the Certificate Transparency (RFC 6962) TLS extension is
// supported.
TEST_P(SSLClientSocketVersionTest, ConnectSignedCertTimestampsTLSExtension) {
  // Encoding of SCT List containing 'test'.
  std::string_view sct_ext("\x00\x06\x00\x04test", 8);

  SSLServerConfig server_config = GetServerConfig();
  server_config.signed_cert_timestamp_list =
      std::vector<uint8_t>(sct_ext.begin(), sct_ext.end());
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());

  EXPECT_TRUE(sock_->signed_cert_timestamps_received_);

  ASSERT_EQ(cert_verifier_->GetVerifyParams().size(), 1u);
  const auto& params = cert_verifier_->GetVerifyParams().front();
  EXPECT_TRUE(params.certificate()->EqualsIncludingChain(
      embedded_test_server()->GetCertificate().get()));
  EXPECT_EQ(params.hostname(), embedded_test_server()->host_port_pair().host());
  EXPECT_EQ(params.ocsp_response(), "");
  EXPECT_EQ(params.sct_list(), sct_ext);

  sock_ = nullptr;
  context_ = nullptr;
}

// Tests that OCSP stapling is requested, as per Certificate Transparency (RFC
// 6962).
TEST_P(SSLClientSocketVersionTest, ConnectSignedCertTimestampsEnablesOCSP) {
  // The test server currently only knows how to generate OCSP responses
  // for a freshly minted certificate.
  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.stapled_ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});

  ASSERT_TRUE(StartEmbeddedTestServer(cert_config, GetServerConfig()));

  SSLConfig ssl_config;

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  EXPECT_THAT(rv, IsOk());

  EXPECT_TRUE(sock_->stapled_ocsp_response_received_);
}

// Tests that IsConnectedAndIdle and WasEverUsed behave as expected.
TEST_P(SSLClientSocketVersionTest, ReuseStates) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));

  // The socket was just connected. It should be idle because it is speaking
  // HTTP. Although the transport has been used for the handshake, WasEverUsed()
  // returns false.
  EXPECT_TRUE(sock_->IsConnected());
  EXPECT_TRUE(sock_->IsConnectedAndIdle());
  EXPECT_FALSE(sock_->WasEverUsed());

  const char kRequestText[] = "GET / HTTP/1.0\r\n\r\n";
  const size_t kRequestLen = std::size(kRequestText) - 1;
  auto request_buffer = base::MakeRefCounted<IOBufferWithSize>(kRequestLen);
  memcpy(request_buffer->data(), kRequestText, kRequestLen);

  TestCompletionCallback callback;
  rv = callback.GetResult(sock_->Write(request_buffer.get(), kRequestLen,
                                       callback.callback(),
                                       TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_EQ(static_cast<int>(kRequestLen), rv);

  // The socket has now been used.
  EXPECT_TRUE(sock_->WasEverUsed());

  // TODO(davidben): Read one byte to ensure the test server has responded and
  // then assert IsConnectedAndIdle is false. This currently doesn't work
  // because SSLClientSocketImpl doesn't check the implementation's internal
  // buffer. Call SSL_pending.
}

// Tests that |is_fatal_cert_error| does not get set for a certificate error,
// on a non-HSTS host.
TEST_P(SSLClientSocketVersionTest, IsFatalErrorNotSetOnNonFatalError) {
  cert_verifier_->set_default_result(ERR_CERT_DATE_INVALID);
  ASSERT_TRUE(StartEmbeddedTestServer(EmbeddedTestServer::CERT_CHAIN_WRONG_ROOT,
                                      GetServerConfig()));
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_FALSE(ssl_info.is_fatal_cert_error);
}

// Tests that |is_fatal_cert_error| gets set for a certificate error on an
// HSTS host.
TEST_P(SSLClientSocketVersionTest, IsFatalErrorSetOnFatalError) {
  cert_verifier_->set_default_result(ERR_CERT_DATE_INVALID);
  ASSERT_TRUE(StartEmbeddedTestServer(EmbeddedTestServer::CERT_CHAIN_WRONG_ROOT,
                                      GetServerConfig()));
  int rv;
  const base::Time expiry = base::Time::Now() + base::Seconds(1000);
  transport_security_state_->AddHSTS(host_port_pair().host(), expiry, true);
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_TRUE(ssl_info.is_fatal_cert_error);
}

// Tests that IsConnectedAndIdle treats a socket as idle even if a Write hasn't
// been flushed completely out of SSLClientSocket's internal buffers. This is a
// regression test for https://crbug.com/466147.
TEST_P(SSLClientSocketVersionTest, ReusableAfterWrite) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));

  TestCompletionCallback callback;
  auto real_transport = std::make_unique<TCPClientSocket>(
      addr(), nullptr, nullptr, nullptr, NetLogSource());
  auto transport =
      std::make_unique<FakeBlockingStreamSocket>(std::move(real_transport));
  FakeBlockingStreamSocket* raw_transport = transport.get();
  ASSERT_THAT(callback.GetResult(transport->Connect(callback.callback())),
              IsOk());

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), host_port_pair(), SSLConfig()));
  ASSERT_THAT(callback.GetResult(sock->Connect(callback.callback())), IsOk());

  // Block any application data from reaching the network.
  raw_transport->BlockWrite();

  // Write a partial HTTP request.
  const char kRequestText[] = "GET / HTTP/1.0";
  const size_t kRequestLen = std::size(kRequestText) - 1;
  auto request_buffer = base::MakeRefCounted<IOBufferWithSize>(kRequestLen);
  memcpy(request_buffer->data(), kRequestText, kRequestLen);

  // Although transport writes are blocked, SSLClientSocketImpl completes the
  // outer Write operation.
  EXPECT_EQ(static_cast<int>(kRequestLen),
            callback.GetResult(sock->Write(request_buffer.get(), kRequestLen,
                                           callback.callback(),
                                           TRAFFIC_ANNOTATION_FOR_TESTS)));

  // The Write operation is complete, so the socket should be treated as
  // reusable, in case the server returns an HTTP response before completely
  // consuming the request body. In this case, we assume the server will
  // properly drain the request body before trying to read the next request.
  EXPECT_TRUE(sock->IsConnectedAndIdle());
}

// Tests that basic session resumption works.
TEST_P(SSLClientSocketVersionTest, SessionResumption) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));

  // First, perform a full handshake.
  SSLConfig ssl_config;
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);

  // TLS 1.2 with False Start and TLS 1.3 cause the ticket to arrive later, so
  // use the socket to ensure the session ticket has been picked up.
  EXPECT_THAT(MakeHTTPRequest(sock_.get()), IsOk());

  // The next connection should resume.
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
  sock_.reset();

  // Using a different HostPortPair uses a different session cache key.
  auto transport = std::make_unique<TCPClientSocket>(
      addr(), nullptr, nullptr, NetLog::Get(), NetLogSource());
  TestCompletionCallback callback;
  ASSERT_THAT(callback.GetResult(transport->Connect(callback.callback())),
              IsOk());
  std::unique_ptr<SSLClientSocket> sock = CreateSSLClientSocket(
      std::move(transport), HostPortPair("example.com", 443), ssl_config);
  ASSERT_THAT(callback.GetResult(sock->Connect(callback.callback())), IsOk());
  ASSERT_TRUE(sock->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);
  sock.reset();

  ssl_client_session_cache_->Flush();

  // After clearing the session cache, the next handshake doesn't resume.
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);

  // Pick up the ticket again and confirm resumption works.
  EXPECT_THAT(MakeHTTPRequest(sock_.get()), IsOk());
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
  sock_.reset();

  // Updating the context-wide configuration should flush the session cache.
  SSLContextConfig config;
  config.disabled_cipher_suites = {1234};
  ssl_config_service_->UpdateSSLConfigAndNotify(config);
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
}

namespace {

// FakePeerAddressSocket wraps a |StreamSocket|, forwarding all calls except
// that it provides a given answer for |GetPeerAddress|.
class FakePeerAddressSocket : public WrappedStreamSocket {
 public:
  FakePeerAddressSocket(std::unique_ptr<StreamSocket> socket,
                        const IPEndPoint& address)
      : WrappedStreamSocket(std::move(socket)), address_(address) {}
  ~FakePeerAddressSocket() override = default;

  int GetPeerAddress(IPEndPoint* address) const override {
    *address = address_;
    return OK;
  }

 private:
  const IPEndPoint address_;
};

}  // namespace

TEST_F(SSLClientSocketTest, SessionResumption_RSA) {
  for (bool use_rsa : {false, true}) {
    SCOPED_TRACE(use_rsa);

    SSLServerConfig server_config;
    server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
    server_config.cipher_suite_for_testing =
        use_rsa ? kRSACipher : kModernTLS12Cipher;
    ASSERT_TRUE(
        StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));
    SSLConfig ssl_config;
    ssl_client_session_cache_->Flush();

    for (int i = 0; i < 3; i++) {
      SCOPED_TRACE(i);

      auto transport = std::make_unique<TCPClientSocket>(
          addr(), nullptr, nullptr, NetLog::Get(), NetLogSource());
      TestCompletionCallback callback;
      ASSERT_THAT(callback.GetResult(transport->Connect(callback.callback())),
                  IsOk());
      // The third handshake sees a different destination IP address.
      IPEndPoint fake_peer_address(IPAddress(1, 1, 1, i == 2 ? 2 : 1), 443);
      auto socket = std::make_unique<FakePeerAddressSocket>(
          std::move(transport), fake_peer_address);
      std::unique_ptr<SSLClientSocket> sock = CreateSSLClientSocket(
          std::move(socket), HostPortPair("example.com", 443), ssl_config);
      ASSERT_THAT(callback.GetResult(sock->Connect(callback.callback())),
                  IsOk());
      SSLInfo ssl_info;
      ASSERT_TRUE(sock->GetSSLInfo(&ssl_info));
      sock.reset();

      switch (i) {
        case 0:
          // Initial handshake should be a full handshake.
          EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);
          break;
        case 1:
          // Second handshake should resume.
          EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
          break;
        case 2:
          // Third handshake gets a different IP address and, if the
          // session used RSA key exchange, it should not resume.
          EXPECT_EQ(
              use_rsa ? SSLInfo::HANDSHAKE_FULL : SSLInfo::HANDSHAKE_RESUME,
              ssl_info.handshake_type);
          break;
        default:
          NOTREACHED();
      }
    }
  }
}

// Tests that ALPN works with session resumption.
TEST_F(SSLClientSocketTest, SessionResumptionAlpn) {
  SSLServerConfig server_config;
  server_config.alpn_protos = {NextProto::kProtoHTTP2, NextProto::kProtoHTTP11};
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  // First, perform a full handshake.
  SSLConfig ssl_config;
  ssl_config.alpn_protos.push_back(kProtoHTTP2);
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);
  EXPECT_EQ(kProtoHTTP2, sock_->GetNegotiatedProtocol());

  // TLS 1.2 with False Start and TLS 1.3 cause the ticket to arrive later, so
  // use the socket to ensure the session ticket has been picked up.
  EXPECT_THAT(MakeHTTPRequest(sock_.get()), IsOk());

  // The next connection should resume; ALPN should be renegotiated.
  ssl_config.alpn_protos.clear();
  ssl_config.alpn_protos.push_back(kProtoHTTP11);
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
  EXPECT_EQ(kProtoHTTP11, sock_->GetNegotiatedProtocol());
}

// Tests that the session cache is not sharded by NetworkAnonymizationKey if the
// feature is disabled.
TEST_P(SSLClientSocketVersionTest,
       SessionResumptionNetworkIsolationKeyDisabled) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndDisableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));

  // First, perform a full handshake.
  SSLConfig ssl_config;
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);

  // TLS 1.2 with False Start and TLS 1.3 cause the ticket to arrive later, so
  // use the socket to ensure the session ticket has been picked up. Do this for
  // every connection to avoid problems with TLS 1.3 single-use tickets.
  EXPECT_THAT(MakeHTTPRequest(sock_.get()), IsOk());

  // The next connection should resume.
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
  EXPECT_THAT(MakeHTTPRequest(sock_.get()), IsOk());
  sock_.reset();

  // Using a different NetworkAnonymizationKey shares session cache key because
  // sharding is disabled.
  const SchemefulSite kSiteA(GURL("https://a.test"));
  ssl_config.network_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(kSiteA);
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
  EXPECT_THAT(MakeHTTPRequest(sock_.get()), IsOk());
  sock_.reset();

  const SchemefulSite kSiteB(GURL("https://a.test"));
  ssl_config.network_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(kSiteB);
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
  EXPECT_THAT(MakeHTTPRequest(sock_.get()), IsOk());
  sock_.reset();
}

// Tests that the session cache is sharded by NetworkAnonymizationKey if the
// feature is enabled.
TEST_P(SSLClientSocketVersionTest,
       SessionResumptionNetworkIsolationKeyEnabled) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  const SchemefulSite kSiteA(GURL("https://a.test"));
  const SchemefulSite kSiteB(GURL("https://b.test"));
  const auto kNetworkAnonymizationKeyA =
      NetworkAnonymizationKey::CreateSameSite(kSiteA);
  const auto kNetworkAnonymizationKeyB =
      NetworkAnonymizationKey::CreateSameSite(kSiteB);

  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));

  // First, perform a full handshake.
  SSLConfig ssl_config;
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);

  // TLS 1.2 with False Start and TLS 1.3 cause the ticket to arrive later, so
  // use the socket to ensure the session ticket has been picked up. Do this for
  // every connection to avoid problems with TLS 1.3 single-use tickets.
  EXPECT_THAT(MakeHTTPRequest(sock_.get()), IsOk());

  // The next connection should resume.
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
  EXPECT_THAT(MakeHTTPRequest(sock_.get()), IsOk());
  sock_.reset();

  // Using a different NetworkAnonymizationKey uses a different session cache
  // key.
  ssl_config.network_anonymization_key = kNetworkAnonymizationKeyA;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);
  EXPECT_THAT(MakeHTTPRequest(sock_.get()), IsOk());
  sock_.reset();

  // We, however, can resume under that newly-established session.
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
  EXPECT_THAT(MakeHTTPRequest(sock_.get()), IsOk());
  sock_.reset();

  // Repeat with another non-null key.
  ssl_config.network_anonymization_key = kNetworkAnonymizationKeyB;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);
  EXPECT_THAT(MakeHTTPRequest(sock_.get()), IsOk());
  sock_.reset();

  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
  EXPECT_THAT(MakeHTTPRequest(sock_.get()), IsOk());
  sock_.reset();

  // b.test does not evict a.test's session.
  ssl_config.network_anonymization_key = kNetworkAnonymizationKeyA;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
  EXPECT_THAT(MakeHTTPRequest(sock_.get()), IsOk());
  sock_.reset();
}

// Tests that connections with certificate errors do not add entries to the
// session cache.
TEST_P(SSLClientSocketVersionTest, CertificateErrorNoResume) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));

  cert_verifier_->set_default_result(ERR_CERT_COMMON_NAME_INVALID);

  SSLConfig ssl_config;
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsError(ERR_CERT_COMMON_NAME_INVALID));

  cert_verifier_->set_default_result(OK);

  // The next connection should perform a full handshake.
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);
}

TEST_F(SSLClientSocketTest, RequireECDHE) {
  // Run test server without ECDHE.
  SSLServerConfig server_config;
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.cipher_suite_for_testing = kRSACipher;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  SSLConfig config;
  config.require_ecdhe = true;
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(config, &rv));
  EXPECT_THAT(rv, IsError(ERR_SSL_VERSION_OR_CIPHER_MISMATCH));
}

TEST_F(SSLClientSocketTest, 3DES) {
  SSLServerConfig server_config;
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.cipher_suite_for_testing = k3DESCipher;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  // 3DES is always disabled.
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsError(ERR_SSL_VERSION_OR_CIPHER_MISMATCH));
}

TEST_F(SSLClientSocketTest, SHA1) {
  SSLServerConfig server_config;
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  // Disable RSA key exchange, to ensure the server does not pick a non-signing
  // cipher.
  server_config.require_ecdhe = true;
  server_config.signature_algorithm_for_testing = SSL_SIGN_RSA_PKCS1_SHA1;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  // SHA-1 server signatures are always disabled.
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsError(ERR_SSL_VERSION_OR_CIPHER_MISMATCH));
}

TEST_F(SSLClientSocketFalseStartTest, FalseStartEnabled) {
  // False Start requires ALPN, ECDHE, and an AEAD.
  SSLServerConfig server_config;
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.cipher_suite_for_testing = kModernTLS12Cipher;
  server_config.alpn_protos = {NextProto::kProtoHTTP11};
  SSLConfig client_config;
  client_config.alpn_protos.push_back(kProtoHTTP11);
  ASSERT_NO_FATAL_FAILURE(TestFalseStart(server_config, client_config, true));
}

// Test that False Start is disabled without ALPN.
TEST_F(SSLClientSocketFalseStartTest, NoAlpn) {
  SSLServerConfig server_config;
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.cipher_suite_for_testing = kModernTLS12Cipher;
  SSLConfig client_config;
  client_config.alpn_protos.clear();
  ASSERT_NO_FATAL_FAILURE(TestFalseStart(server_config, client_config, false));
}

// Test that False Start is disabled with plain RSA ciphers.
TEST_F(SSLClientSocketFalseStartTest, RSA) {
  SSLServerConfig server_config;
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.cipher_suite_for_testing = kRSACipher;
  server_config.alpn_protos = {NextProto::kProtoHTTP11};
  SSLConfig client_config;
  client_config.alpn_protos.push_back(kProtoHTTP11);
  ASSERT_NO_FATAL_FAILURE(TestFalseStart(server_config, client_config, false));
}

// Test that False Start is disabled without an AEAD.
TEST_F(SSLClientSocketFalseStartTest, NoAEAD) {
  SSLServerConfig server_config;
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.cipher_suite_for_testing = kCBCCipher;
  server_config.alpn_protos = {NextProto::kProtoHTTP11};
  SSLConfig client_config;
  client_config.alpn_protos.push_back(kProtoHTTP11);
  ASSERT_NO_FATAL_FAILURE(TestFalseStart(server_config, client_config, false));
}

// Test that sessions are resumable after receiving the server Finished message.
TEST_F(SSLClientSocketFalseStartTest, SessionResumption) {
  // Start a server.
  SSLServerConfig server_config;
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.cipher_suite_for_testing = kModernTLS12Cipher;
  server_config.alpn_protos = {NextProto::kProtoHTTP11};
  SSLConfig client_config;
  client_config.alpn_protos.push_back(kProtoHTTP11);

  // Let a full handshake complete with False Start.
  ASSERT_NO_FATAL_FAILURE(TestFalseStart(server_config, client_config, true));

  // Make a second connection.
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(client_config, &rv));
  EXPECT_THAT(rv, IsOk());

  // It should resume the session.
  SSLInfo ssl_info;
  EXPECT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
}

// Test that the client completes the handshake in the background and installs
// new sessions, even if the socket isn't used. This also avoids a theoretical
// deadlock if NewSessionTicket is sufficiently large that neither it nor the
// client's HTTP/1.1 POST fit in transport windows.
TEST_F(SSLClientSocketFalseStartTest, CompleteHandshakeWithoutRequest) {
  // Start a server.
  SSLServerConfig server_config;
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.cipher_suite_for_testing = kModernTLS12Cipher;
  server_config.alpn_protos = {NextProto::kProtoHTTP11};
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  SSLConfig client_config;
  client_config.alpn_protos.push_back(kProtoHTTP11);

  // Start a handshake up to the server Finished message.
  TestCompletionCallback callback;
  FakeBlockingStreamSocket* raw_transport = nullptr;
  std::unique_ptr<SSLClientSocket> sock;
  ASSERT_NO_FATAL_FAILURE(CreateAndConnectUntilServerFinishedReceived(
      client_config, &callback, &raw_transport, &sock));

  // Wait for the server Finished to arrive, release it, and allow
  // SSLClientSocket to process it. This should install a session. It make take
  // a few iterations to complete if the server writes in small chunks
  while (ssl_client_session_cache_->size() == 0) {
    raw_transport->WaitForReadResult();
    raw_transport->UnblockReadResult();
    base::RunLoop().RunUntilIdle();
    raw_transport->BlockReadResult();
  }

  // Drop the old socket. This is needed because the Python test server can't
  // service two sockets in parallel
```