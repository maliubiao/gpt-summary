Response:
The user wants to understand the functionality of the provided C++ code snippet from `net/url_request/url_request_unittest.cc`. This is part 13 of 17, suggesting it's a chunk of a larger test file.

Here's a breakdown of the thought process:

1. **Identify the Core Functionality:** The code primarily focuses on testing HTTPS-related features within Chromium's network stack. Keywords like `HTTPSRequestTest`, `ClientAuth`, `ResumeTest`, `SSLSessionCache`, `HTTPSFallbackTest`, `HTTPSSessionTest`, `HTTPSCertNetFetchingTest`, `HTTPSEVTest`, and `HTTPSOCSPTest` are strong indicators.

2. **Analyze Individual Test Cases:** Go through each `TEST_F` block to understand its specific purpose.

    * **`ClientAuthBadSigning`:** Tests the scenario where a client certificate is provided, but the private key fails to sign, and how the system handles retries and caching in this situation.
    * **`ClientAuthFailSigningRetry`:** Similar to the previous one, but focuses on a scenario where a *cached* private key fails to sign, leading to a retry and a new certificate request.
    * **`ResumeTest`:**  Checks if SSL session resumption works correctly when connecting to the same host multiple times. It verifies the handshake type changes from `HANDSHAKE_FULL` to `HANDSHAKE_RESUME`.
    * **`SSLSessionCacheShardTest`:** Verifies that SSL sessions are not shared across different `URLRequestContext` objects, ensuring proper isolation.
    * **`NoSessionResumptionBetweenPrivacyModes`:** Tests that SSL sessions initiated with and without privacy mode (incognito) are not resumed across each other.
    * **`HTTPSFallbackTest` (and its sub-tests):** Examines how the system handles server-initiated TLS version fallback. Specifically, it tests that automatic fallback to older TLS versions does *not* happen.
    * **`HTTPSSessionTest`:** Tests the behavior of session resumption when encountering invalid certificates. It ensures that sessions are not resumed if the previous connection had an invalid certificate.
    * **`HTTPSCertNetFetchingTest` (and its sub-tests):** This is a base class for tests that involve fetching resources during certificate verification. It sets up interceptors to ensure secure DNS is disabled during these fetches.
    * **`HTTPSEVTest`:**  Focuses on testing Extended Validation (EV) certificate handling.
    * **`HTTPSOCSPTest` (and its sub-tests):**  Deals with testing Online Certificate Status Protocol (OCSP) functionality, including stapled OCSP responses and handling of different OCSP statuses (valid, revoked, invalid).

3. **Identify Relationships to JavaScript:**  The code interacts with the network stack, which is the foundation for web requests made by JavaScript in a browser environment. Specifically, HTTPS and SSL/TLS are crucial for secure communication.

4. **Provide Concrete JavaScript Examples:**  Illustrate how JavaScript code (using `fetch` or `XMLHttpRequest`) would trigger the underlying C++ code being tested. Emphasize the secure nature of `https://` requests.

5. **Infer Logical Reasoning and Provide Examples:** For tests involving retries or session resumption, construct hypothetical scenarios with input URLs and expected outcomes (e.g., number of certificate requests, handshake types).

6. **Highlight Common User/Programming Errors:** Think about what mistakes developers or users might make that would lead them to the scenarios being tested (e.g., providing an incorrect client certificate, relying on session resumption across different profiles).

7. **Describe User Actions Leading to the Code:** Outline the user's interaction with the browser that would result in these network requests being initiated (e.g., visiting an HTTPS website, a website requiring client authentication).

8. **Summarize the Functionality:**  Condense the findings into a concise summary, focusing on the key areas of HTTPS testing covered by this code segment.

9. **Address the "Part 13 of 17" Instruction:** Explicitly state that this is a portion of a larger test file and summarize its specific contribution to the overall testing effort.

**Self-Correction/Refinement:**

* Initially, I might have focused too much on the low-level details of the C++ code. I needed to shift the focus to the *functionality being tested* and how it relates to the broader network stack and user experience.
* I ensured the JavaScript examples were simple and illustrative, not overly complex.
* I made sure the assumptions and outputs were clear and directly related to the test cases.
* I reviewed the common errors and user actions to make them realistic and understandable.
* I double-checked that the summary accurately captured the main themes of the code segment.这个 Chromium 网络栈的源代码文件 `net/url_request/url_request_unittest.cc` 的第 13 部分主要专注于 **HTTPS（安全 HTTP）相关的网络请求测试**。更具体地说，它涵盖了以下几个关键功能：

**1. 客户端证书认证 (Client Authentication)：**

* **功能:** 测试当服务器要求客户端提供证书进行身份验证时，`URLRequest` 的行为。
* **测试场景:**
    * **`ClientAuthBadSigning`:** 测试客户端提供的私钥无法正确签名时会发生什么。它验证了在签名失败后，是否会报告错误 `ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED`，并且在清除连接和会话缓存后，是否会再次请求客户端证书。
    * **`ClientAuthFailSigningRetry`:** 测试当缓存的私钥签名失败时，系统是否会尝试重试并再次请求客户端证书。这模拟了智能卡被拔出的情况。
* **与 JavaScript 的关系:**  当网站需要客户端证书认证时，浏览器（使用底层的网络栈）会弹出对话框让用户选择证书。用户在 JavaScript 中发起 HTTPS 请求时，如果服务器要求客户端证书，这些底层的认证流程会被触发。
* **假设输入与输出 (`ClientAuthBadSigning`)：**
    * **假设输入:**
        * 服务器配置为需要客户端证书。
        * 客户端提供了一个证书和一个无法正确签名的私钥。
    * **预期输出:**
        * 第一次请求会收到 `ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED` 错误。
        * 清除连接和会话缓存后，第二次请求会再次触发 `OnCertificateRequested`，要求客户端提供证书。
* **假设输入与输出 (`ClientAuthFailSigningRetry`)：**
    * **假设输入:**
        * 服务器配置为需要客户端证书。
        * 第一次请求成功使用了客户端证书。
        * 清除连接和会话缓存后，模拟私钥签名失败。
    * **预期输出:**
        * 第二次请求会尝试使用缓存的证书，但由于签名失败，会再次触发 `OnCertificateRequested`。
* **用户或编程常见的使用错误:**
    * **用户错误:** 选择了错误的客户端证书或对应的私钥未正确安装。
    * **编程错误:** 在客户端代码中没有正确处理服务器返回的客户端证书请求。
* **用户操作到达这里的调试线索:**
    1. 用户访问一个需要客户端证书认证的 HTTPS 网站。
    2. 浏览器接收到服务器的客户端证书请求。
    3. 如果用户选择了证书，但对应的私钥有问题（例如损坏或不匹配），则会触发 `ClientAuthBadSigning` 测试中的场景。
    4. 如果用户第一次成功连接并进行了客户端证书认证，但在后续连接中模拟了私钥失效的情况（例如智能卡被拔出），则会触发 `ClientAuthFailSigningRetry` 测试中的场景。

**2. SSL 会话恢复 (SSL Session Resumption)：**

* **功能:** 测试当客户端与同一主机建立多个 HTTPS 连接时，是否能够复用之前的 SSL 会话，从而减少握手次数，提高性能。
* **测试场景:**
    * **`ResumeTest`:**  验证在建立第二个连接时，SSL 握手类型是否为 `SSLInfo::HANDSHAKE_RESUME`，表示成功恢复了会话。
    * **`SSLSessionCacheShardTest`:** 确保不同 `URLRequestContext` 之间的 SSL 会话缓存是隔离的，即在一个 `URLRequestContext` 中建立的会话不能在另一个 `URLRequestContext` 中恢复。
    * **`NoSessionResumptionBetweenPrivacyModes`:** 测试在隐私模式（例如，隐身模式）下建立的 SSL 会话不会在非隐私模式下恢复，反之亦然。
    * **`DontResumeSessionsForInvalidCertificates`:** 验证如果之前的连接遇到了证书错误，则不会尝试恢复该会话。
* **与 JavaScript 的关系:**  JavaScript 发起的 HTTPS 请求会受益于 SSL 会话恢复，因为它减少了建立安全连接所需的时间。开发者通常不需要直接处理会话恢复，这是由浏览器底层自动管理的。
* **假设输入与输出 (`ResumeTest`)：**
    * **假设输入:**  连续两次向同一个 HTTPS 地址发起请求。
    * **预期输出:** 第一次请求的 SSL 握手类型为 `SSLInfo::HANDSHAKE_FULL`，第二次请求的 SSL 握手类型为 `SSLInfo::HANDSHAKE_RESUME`。
* **假设输入与输出 (`SSLSessionCacheShardTest`)：**
    * **假设输入:**  使用一个 `URLRequestContext` 向 HTTPS 地址发起请求，然后使用另一个 `URLRequestContext` 向相同的地址发起请求。
    * **预期输出:** 两个请求的 SSL 握手类型都为 `SSLInfo::HANDSHAKE_FULL`。
* **假设输入与输出 (`NoSessionResumptionBetweenPrivacyModes`)：**
    * **假设输入:**  先在非隐私模式下向 HTTPS 地址发起请求，然后在隐私模式下向相同的地址发起请求（反之亦然）。
    * **预期输出:** 两个请求的 SSL 握手类型都为 `SSLInfo::HANDSHAKE_FULL`。
* **假设输入与输出 (`DontResumeSessionsForInvalidCertificates`)：**
    * **假设输入:**  第一次请求由于证书过期而失败，然后修复证书问题后再次请求。
    * **预期输出:** 第二次请求的 SSL 握手类型为 `SSLInfo::HANDSHAKE_FULL`。
* **用户或编程常见的使用错误:**
    * **用户错误:**  用户可能不会意识到会话恢复的存在，但如果由于某些原因会话无法恢复（例如，服务器配置），用户可能会注意到连接速度变慢。
    * **编程错误:**  开发者在测试时可能会错误地认为会话总是会被恢复，从而忽略了第一次连接建立时的性能开销。
* **用户操作到达这里的调试线索:**
    1. 用户多次访问同一个 HTTPS 网站。
    2. 开发者想要了解浏览器是否正确地使用了 SSL 会话恢复机制。
    3. 开发者想要验证在不同浏览器配置文件或隐私模式下，SSL 会话是否被正确隔离。
    4. 开发者在调试证书问题时，想要确认之前由于证书错误导致的连接是否影响了后续的会话恢复。

**3. TLS 版本回退测试 (TLS Version Fallback Test)：**

* **功能:** 测试当服务器只支持较低版本的 TLS 协议时，客户端的行为。这些测试旨在验证浏览器不会意外地回退到不安全的 TLS 版本。
* **测试场景:**
    * **`TLSv1NoFallback`，`TLSv1_1NoFallback`，`TLSv1_2NoFallback`:**  分别模拟服务器拒绝 TLS 1.1 及更高版本、TLS 1.2 及更高版本以及支持 TLS 1.3 的 ClientHello 消息，验证客户端是否会报错 `ERR_SSL_VERSION_OR_CIPHER_MISMATCH` 而不是回退到较低版本。
* **与 JavaScript 的关系:**  JavaScript 发起的 HTTPS 请求依赖于底层的 TLS 协议协商。用户和开发者通常不需要直接处理 TLS 版本回退，这由浏览器自动管理以确保安全。
* **假设输入与输出:**
    * **假设输入:**  客户端尝试连接到一个只支持 TLS 1.0 的 HTTPS 服务器。
    * **预期输出:**  连接失败并显示 `ERR_SSL_VERSION_OR_CIPHER_MISMATCH` 错误。
* **用户或编程常见的使用错误:**
    * **用户错误:**  用户可能会遇到连接错误，如果他们尝试访问一个只支持过时 TLS 版本的网站，并且他们的浏览器配置不允许使用这些版本。
    * **编程错误:**  开发者在配置服务器时可能会错误地限制了支持的 TLS 版本，导致一些用户无法访问。
* **用户操作到达这里的调试线索:**
    1. 用户尝试访问一个使用了过时 TLS 协议的 HTTPS 网站。
    2. 开发者想要验证他们的浏览器是否按照预期阻止了与不安全 TLS 版本的连接。

**4. HTTPS 证书网络获取测试 (HTTPS Certificate Network Fetching Test)：**

* **功能:**  测试在证书验证过程中，如果需要从网络获取额外的信息（例如，OCSP 响应，CRL），`URLRequest` 的行为。
* **测试场景:**  这个部分定义了一个基础测试类 `HTTPSCertNetFetchingTest`，以及相关的子类 `HTTPSEVTest` (用于测试扩展验证证书) 和 `HTTPSOCSPTest` (用于测试 OCSP)。它设置了拦截器来确保在证书验证期间的网络请求不会使用安全 DNS。
* **与 JavaScript 的关系:** 当 JavaScript 发起 HTTPS 请求时，浏览器会进行证书验证，这可能涉及到网络请求。
* **用户操作到达这里的调试线索:**
    1. 用户访问一个 HTTPS 网站，该网站的证书验证需要从网络获取额外信息（例如，检查证书是否被吊销）。
    2. 开发者想要确保在证书验证期间发起的网络请求不会受到安全 DNS 的影响，以避免潜在的死锁或其他问题。

**5. OCSP 测试 (Online Certificate Status Protocol Test)：**

* **功能:** 测试 `URLRequest` 如何处理 OCSP 响应，包括有效的、吊销的、无效的以及 Stapled OCSP 响应。
* **测试场景:**
    * **`Valid`，`Revoked`，`Invalid`:** 测试基本的 OCSP 响应处理。
    * **`IntermediateValid`，`IntermediateResponseOldButStillValid`，`IntermediateResponseTooOldKnownRoot`，`IntermediateResponseTooOld`，`IntermediateRevoked`:** 测试中间证书的 OCSP 响应处理。
    * **`ValidStapled`，`RevokedStapled`，`OldStapledAndInvalidAIA`:** 测试 Stapled OCSP 响应的处理。
* **与 JavaScript 的关系:**  OCSP 用于检查服务器证书的吊销状态，这有助于提高 HTTPS 连接的安全性。JavaScript 发起的 HTTPS 请求会受益于底层的 OCSP 检查。
* **假设输入与输出 (例如，`Valid`)：**
    * **假设输入:** 服务器提供了一个有效的 OCSP 响应，指示其证书未被吊销。
    * **预期输出:**  连接成功，并且证书状态 `cert_status` 不包含任何错误。
* **假设输入与输出 (例如，`Revoked`)：**
    * **假设输入:** 服务器提供了一个 OCSP 响应，指示其证书已被吊销。
    * **预期输出:** 连接失败，并且证书状态 `cert_status` 包含 `CERT_STATUS_REVOKED` 错误。
* **用户或编程常见的使用错误:**
    * **用户错误:**  用户可能会遇到连接错误，如果他们尝试访问一个证书已被吊销的网站。
    * **编程错误:**  服务器配置不当可能导致 OCSP 响应错误或不可用。
* **用户操作到达这里的调试线索:**
    1. 用户访问一个启用了 OCSP 的 HTTPS 网站。
    2. 开发者想要验证浏览器是否正确地处理了各种 OCSP 响应。

**6. EV 证书测试 (Extended Validation Certificate Test)：**

* **功能:** 测试 `URLRequest` 如何处理扩展验证 (EV) 证书。
* **测试场景:**
    * **`EVCheckNoOCSP`:** 测试在没有 OCSP 信息的情况下，EV 证书是否被正确识别。
* **与 JavaScript 的关系:** EV 证书提供更高的信任保证，浏览器通常会在地址栏中显示特殊的指示器（例如，公司名称）。JavaScript 发起的 HTTPS 请求可以连接到使用 EV 证书的网站。
* **假设输入与输出 (`EVCheckNoOCSP`)：**
    * **假设输入:**  服务器提供了一个有效的 EV 证书，但没有提供 OCSP 信息。
    * **预期输出:** 连接成功，并且证书状态 `cert_status` 包含 `CERT_STATUS_IS_EV` 标志。
* **用户操作到达这里的调试线索:**
    1. 用户访问一个使用 EV 证书的 HTTPS 网站。
    2. 开发者想要验证浏览器是否正确地识别了 EV 证书。

**总结第 13 部分的功能：**

`net/url_request/url_request_unittest.cc` 的第 13 部分主要负责对 Chromium 网络栈中与 **HTTPS 安全连接**相关的关键功能进行单元测试。这些功能包括：**客户端证书认证、SSL 会话恢复、TLS 版本回退、证书验证期间的网络获取（特别是 OCSP）以及 EV 证书的处理**。这些测试确保了 Chromium 能够安全可靠地处理各种 HTTPS 连接场景。

作为 17 个部分中的第 13 部分，它专注于 HTTPS 协议的具体实现和安全性保障，是整个网络请求测试套件中至关重要的一个环节，用于验证 Chromium 在处理安全连接时的正确性和健壮性。

Prompt: 
```
这是目录为net/url_request/url_request_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第13部分，共17部分，请归纳一下它的功能

"""
CertType::REQUIRE_CLIENT_CERT;
  test_server.SetSSLConfig(EmbeddedTestServer::CERT_OK, ssl_config);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());

  {
    SSLClientAuthTestDelegate d;
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        test_server.GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilCertificateRequested();
    EXPECT_TRUE(r->is_pending());

    EXPECT_EQ(1, d.on_certificate_requested_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(0, d.bytes_received());

    // Send a certificate.
    r->ContinueWithCertificate(identity->certificate(), private_key);
    d.RunUntilComplete();

    // The private key cannot sign anything, so we report an error.
    EXPECT_EQ(ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED, d.request_status());
    EXPECT_EQ(1, d.response_started_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(0, d.bytes_received());

    // The private key should have been used.
    EXPECT_EQ(1, private_key->sign_count());
  }

  // Close all connections and clear the session cache to force a new handshake.
  default_context()
      .http_transaction_factory()
      ->GetSession()
      ->CloseAllConnections(ERR_FAILED, "Very good reason");
  default_context()
      .http_transaction_factory()
      ->GetSession()
      ->ClearSSLSessionCache();

  // The bad identity should have been evicted from the cache, so connecting
  // again should call OnCertificateRequested again.
  {
    SSLClientAuthTestDelegate d;
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        test_server.GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilCertificateRequested();
    EXPECT_TRUE(r->is_pending());

    EXPECT_EQ(1, d.on_certificate_requested_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(0, d.bytes_received());

    // There should have been no additional uses of the private key.
    EXPECT_EQ(1, private_key->sign_count());
  }
}

// Test that cached private keys that fail to sign anything trigger a
// retry. This is so we handle unplugged smartcards
// gracefully. https://crbug.com/813022.
TEST_F(HTTPSRequestTest, ClientAuthFailSigningRetry) {
  std::unique_ptr<FakeClientCertIdentity> identity =
      FakeClientCertIdentity::CreateFromCertAndKeyFiles(
          GetTestCertsDirectory(), "client_1.pem", "client_1.pk8");
  ASSERT_TRUE(identity);
  scoped_refptr<TestSSLPrivateKey> private_key =
      base::MakeRefCounted<TestSSLPrivateKey>(identity->ssl_private_key());

  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  net::SSLServerConfig ssl_config;
  ssl_config.client_cert_type =
      SSLServerConfig::ClientCertType::REQUIRE_CLIENT_CERT;
  test_server.SetSSLConfig(EmbeddedTestServer::CERT_OK, ssl_config);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());

  // Connect with a client certificate to put it in the client auth cache.
  {
    SSLClientAuthTestDelegate d;
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        test_server.GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilCertificateRequested();
    EXPECT_TRUE(r->is_pending());

    EXPECT_EQ(1, d.on_certificate_requested_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(0, d.bytes_received());

    r->ContinueWithCertificate(identity->certificate(), private_key);
    d.RunUntilComplete();

    EXPECT_EQ(OK, d.request_status());
    EXPECT_EQ(1, d.response_started_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_NE(0, d.bytes_received());

    // The private key should have been used.
    EXPECT_EQ(1, private_key->sign_count());
  }

  // Close all connections and clear the session cache to force a new handshake.
  default_context()
      .http_transaction_factory()
      ->GetSession()
      ->CloseAllConnections(ERR_FAILED, "Very good reason");
  default_context()
      .http_transaction_factory()
      ->GetSession()
      ->ClearSSLSessionCache();

  // Cause the private key to fail. Connecting again should attempt to use it,
  // notice the failure, and then request a new identity via
  // OnCertificateRequested.
  private_key->set_fail_signing(true);

  {
    SSLClientAuthTestDelegate d;
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        test_server.GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilCertificateRequested();
    EXPECT_TRUE(r->is_pending());

    // There was an additional signing call on the private key (the one which
    // failed).
    EXPECT_EQ(2, private_key->sign_count());

    // That caused another OnCertificateRequested call.
    EXPECT_EQ(1, d.on_certificate_requested_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(0, d.bytes_received());
  }
}

TEST_F(HTTPSRequestTest, ResumeTest) {
  // Test that we attempt resume sessions when making two connections to the
  // same host.
  EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());
  const auto url = test_server.GetURL("/");

  default_context()
      .http_transaction_factory()
      ->GetSession()
      ->ClearSSLSessionCache();

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, r->ssl_info().handshake_type);
  }

  reinterpret_cast<HttpCache*>(default_context().http_transaction_factory())
      ->CloseAllConnections(ERR_FAILED, "Very good reason");

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, r->ssl_info().handshake_type);
  }
}

// Test that sessions aren't resumed across URLRequestContexts.
TEST_F(HTTPSRequestTest, SSLSessionCacheShardTest) {
  // Start a server.
  EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());
  const auto url = test_server.GetURL("/");

  // Connect to the server once. This will add an entry to the session cache.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, r->ssl_info().handshake_type);
  }

  // Clear the socket pools and connect again. This should resume the previous
  // session.
  default_context()
      .http_transaction_factory()
      ->GetSession()
      ->CloseAllConnections(ERR_FAILED, /*net_log_reason_utf8=*/"");

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, r->ssl_info().handshake_type);
  }

  // Now fetch on a new URLRequestContext. This should not resume the session.
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto other_context = context_builder->Build();

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(other_context->CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, r->ssl_info().handshake_type);
  }
}

// Test that sessions started with privacy mode enabled cannot be resumed when
// it is disabled, and vice versa.
TEST_F(HTTPSRequestTest, NoSessionResumptionBetweenPrivacyModes) {
  // Start a server.
  EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());
  const auto url = test_server.GetURL("/");

  auto ConnectAndCheckHandshake = [this, url](bool allow_credentials,
                                              auto expected_handshake) {
    // Construct request and indirectly set the privacy mode.
    TestDelegate d;
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    r->set_allow_credentials(allow_credentials);

    // Start the request and check the SSL handshake type.
    r->Start();
    EXPECT_TRUE(r->is_pending());
    d.RunUntilComplete();
    EXPECT_EQ(1, d.response_started_count());
    EXPECT_EQ(expected_handshake, r->ssl_info().handshake_type);
  };

  // Exhaustively check all pairs of privacy mode values. Note that we are using
  // allow_credentials to indirectly enable/disable privacy mode.
  const bool kAllowCredentialsValues[] = {false, true};
  for (const auto allow_creds_1 : kAllowCredentialsValues) {
    for (const auto allow_creds_2 : kAllowCredentialsValues) {
      SCOPED_TRACE(base::StringPrintf("allow_creds_1=%d, allow_creds_2=%d",
                                      allow_creds_1, allow_creds_2));

      // The session cache starts off empty, so we expect a full handshake.
      ConnectAndCheckHandshake(allow_creds_1, SSLInfo::HANDSHAKE_FULL);

      // The second handshake depends on whether we are using the same session
      // cache as the first request.
      ConnectAndCheckHandshake(allow_creds_2, allow_creds_1 == allow_creds_2
                                                  ? SSLInfo::HANDSHAKE_RESUME
                                                  : SSLInfo::HANDSHAKE_FULL);
      // Flush both session caches.
      auto* network_session =
          default_context().http_transaction_factory()->GetSession();
      network_session->ClearSSLSessionCache();
    }
  }
}

class HTTPSFallbackTest : public TestWithTaskEnvironment {
 public:
  HTTPSFallbackTest() {
    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->set_ssl_config_service(
        std::make_unique<TestSSLConfigService>(SSLContextConfig()));
    context_ = context_builder->Build();
  }
  ~HTTPSFallbackTest() override = default;

 protected:
  void DoFallbackTest(const SSLServerConfig& ssl_config) {
    DCHECK(!request_);
    delegate_.set_allow_certificate_errors(true);

    EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTPS);
    test_server.SetSSLConfig(EmbeddedTestServer::CERT_OK, ssl_config);
    ASSERT_TRUE(test_server.Start());

    request_ =
        context_->CreateRequest(test_server.GetURL("/"), DEFAULT_PRIORITY,
                                &delegate_, TRAFFIC_ANNOTATION_FOR_TESTS);
    request_->Start();

    delegate_.RunUntilComplete();
  }

  void ExpectConnection(int version) {
    EXPECT_EQ(1, delegate_.response_started_count());
    EXPECT_NE(0, delegate_.bytes_received());
    EXPECT_EQ(version, SSLConnectionStatusToVersion(
                           request_->ssl_info().connection_status));
  }

  void ExpectFailure(int error) {
    EXPECT_EQ(1, delegate_.response_started_count());
    EXPECT_EQ(error, delegate_.request_status());
  }

 private:
  TestDelegate delegate_;
  std::unique_ptr<URLRequestContext> context_;
  std::unique_ptr<URLRequest> request_;
};

// Tests the TLS 1.0 fallback doesn't happen.
TEST_F(HTTPSFallbackTest, TLSv1NoFallback) {
  net::SSLServerConfig ssl_config;
  ssl_config.client_hello_callback_for_testing =
      base::BindRepeating([](const SSL_CLIENT_HELLO* client_hello) {
        // Reject ClientHellos with version >= TLS 1.1.
        return client_hello->version <= TLS1_VERSION;
      });

  ASSERT_NO_FATAL_FAILURE(DoFallbackTest(ssl_config));
  ExpectFailure(ERR_SSL_VERSION_OR_CIPHER_MISMATCH);
}

// Tests the TLS 1.1 fallback doesn't happen.
TEST_F(HTTPSFallbackTest, TLSv1_1NoFallback) {
  net::SSLServerConfig ssl_config;
  ssl_config.client_hello_callback_for_testing =
      base::BindRepeating([](const SSL_CLIENT_HELLO* client_hello) {
        // Reject ClientHellos with version >= TLS 1.2.
        return client_hello->version <= TLS1_1_VERSION;
      });

  ASSERT_NO_FATAL_FAILURE(DoFallbackTest(ssl_config));
  ExpectFailure(ERR_SSL_VERSION_OR_CIPHER_MISMATCH);
}

// Tests the TLS 1.2 fallback doesn't happen.
TEST_F(HTTPSFallbackTest, TLSv1_2NoFallback) {
  net::SSLServerConfig ssl_config;
  ssl_config.client_hello_callback_for_testing =
      base::BindRepeating([](const SSL_CLIENT_HELLO* client_hello) {
        // Reject ClientHellos with a supported_versions extension. TLS 1.3 is
        // signaled via an extension rather than the legacy version field.
        const uint8_t* data;
        size_t len;
        return !SSL_early_callback_ctx_extension_get(
            client_hello, TLSEXT_TYPE_supported_versions, &data, &len);
      });

  ASSERT_NO_FATAL_FAILURE(DoFallbackTest(ssl_config));
  ExpectFailure(ERR_SSL_VERSION_OR_CIPHER_MISMATCH);
}

class HTTPSSessionTest : public TestWithTaskEnvironment {
 public:
  HTTPSSessionTest() {
    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->SetCertVerifier(std::make_unique<MockCertVerifier>());
    default_context_ = context_builder->Build();

    default_cert_verifier().set_default_result(OK);
  }
  ~HTTPSSessionTest() override = default;

  URLRequestContext& default_context() { return *default_context_; }
  MockCertVerifier& default_cert_verifier() {
    // This cast is safe because we provided a MockCertVerifier in the ctor.
    return *static_cast<MockCertVerifier*>(default_context_->cert_verifier());
  }

 private:
  std::unique_ptr<URLRequestContext> default_context_;
};

// Tests that session resumption is not attempted if an invalid certificate
// is presented.
TEST_F(HTTPSSessionTest, DontResumeSessionsForInvalidCertificates) {
  EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());
  const auto url = test_server.GetURL("/");

  default_context()
      .http_transaction_factory()
      ->GetSession()
      ->ClearSSLSessionCache();

  // Simulate the certificate being expired and attempt a connection.
  default_cert_verifier().set_default_result(ERR_CERT_DATE_INVALID);
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
  }

  reinterpret_cast<HttpCache*>(default_context().http_transaction_factory())
      ->CloseAllConnections(ERR_FAILED, "Very good reason");

  // Now change the certificate to be acceptable (so that the response is
  // loaded), and ensure that no session id is presented to the peer.
  default_cert_verifier().set_default_result(OK);
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, r->ssl_info().handshake_type);
  }
}

// Interceptor to check that secure DNS has been disabled. Secure DNS should be
// disabled for any network fetch triggered during certificate verification as
// it could cause a deadlock.
class SecureDnsInterceptor : public net::URLRequestInterceptor {
 public:
  SecureDnsInterceptor() = default;
  ~SecureDnsInterceptor() override = default;

 private:
  // URLRequestInterceptor implementation:
  std::unique_ptr<net::URLRequestJob> MaybeInterceptRequest(
      net::URLRequest* request) const override {
    EXPECT_EQ(SecureDnsPolicy::kDisable, request->secure_dns_policy());
    return nullptr;
  }
};

class HTTPSCertNetFetchingTest : public HTTPSRequestTest {
 public:
  HTTPSCertNetFetchingTest() = default;

  void SetUp() override {
    cert_net_fetcher_ = base::MakeRefCounted<CertNetFetcherURLRequest>();
    auto cert_verifier =
        CertVerifier::CreateDefaultWithoutCaching(cert_net_fetcher_);
    updatable_cert_verifier_ = cert_verifier.get();

    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->SetCertVerifier(std::make_unique<CachingCertVerifier>(
        std::make_unique<CoalescingCertVerifier>(std::move(cert_verifier))));
    context_ = context_builder->Build();

    net::URLRequestFilter::GetInstance()->AddHostnameInterceptor(
        "http", "127.0.0.1", std::make_unique<SecureDnsInterceptor>());

    cert_net_fetcher_->SetURLRequestContext(context_.get());
    context_->cert_verifier()->SetConfig(GetCertVerifierConfig());
  }

  void TearDown() override {
    cert_net_fetcher_->Shutdown();
    net::URLRequestFilter::GetInstance()->ClearHandlers();
  }

  void DoConnectionWithDelegate(
      std::string_view hostname,
      const EmbeddedTestServer::ServerCertificateConfig& cert_config,
      TestDelegate* delegate,
      SSLInfo* out_ssl_info) {
    // Always overwrite |out_ssl_info|.
    out_ssl_info->Reset();

    EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTPS);
    test_server.SetSSLConfig(cert_config);
    RegisterDefaultHandlers(&test_server);
    ASSERT_TRUE(test_server.Start());

    delegate->set_allow_certificate_errors(true);
    std::unique_ptr<URLRequest> r(context_->CreateRequest(
        test_server.GetURL(hostname, "/"), DEFAULT_PRIORITY, delegate,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->Start();

    delegate->RunUntilComplete();
    EXPECT_EQ(1, delegate->response_started_count());

    *out_ssl_info = r->ssl_info();
  }

  void DoConnectionWithDelegate(
      const EmbeddedTestServer::ServerCertificateConfig& cert_config,
      TestDelegate* delegate,
      SSLInfo* out_ssl_info) {
    DoConnectionWithDelegate("127.0.0.1", cert_config, delegate, out_ssl_info);
  }

  void DoConnection(
      std::string_view hostname,
      const EmbeddedTestServer::ServerCertificateConfig& cert_config,
      CertStatus* out_cert_status) {
    // Always overwrite |out_cert_status|.
    *out_cert_status = 0;

    TestDelegate d;
    SSLInfo ssl_info;
    ASSERT_NO_FATAL_FAILURE(
        DoConnectionWithDelegate(hostname, cert_config, &d, &ssl_info));

    *out_cert_status = ssl_info.cert_status;
  }

  void DoConnection(
      const EmbeddedTestServer::ServerCertificateConfig& cert_config,
      CertStatus* out_cert_status) {
    DoConnection("127.0.0.1", cert_config, out_cert_status);
  }

 protected:
  // GetCertVerifierConfig() configures the URLRequestContext that will be used
  // for making connections to the testserver. This can be overridden in test
  // subclasses for different behaviour.
  virtual CertVerifier::Config GetCertVerifierConfig() {
    CertVerifier::Config config;
    return config;
  }

  void UpdateCertVerifier(scoped_refptr<CRLSet> crl_set) {
    net::CertVerifyProc::ImplParams params;
    params.crl_set = std::move(crl_set);
    updatable_cert_verifier_->UpdateVerifyProcData(cert_net_fetcher_, params,
                                                   {});
  }

  scoped_refptr<CertNetFetcherURLRequest> cert_net_fetcher_;
  std::unique_ptr<URLRequestContext> context_;
  raw_ptr<CertVerifierWithUpdatableProc> updatable_cert_verifier_;
};

// The test EV policy OID used for generated certs.
static const char kEVTestCertPolicy[] = "1.3.6.1.4.1.11129.2.4.1";

class HTTPSEVTest : public HTTPSCertNetFetchingTest {
 public:
  void SetUp() override {
    HTTPSCertNetFetchingTest::SetUp();

    scoped_refptr<X509Certificate> root_cert =
        ImportCertFromFile(GetTestCertsDirectory(), "root_ca_cert.pem");
    ASSERT_TRUE(root_cert);

    ev_test_policy_ = std::make_unique<ScopedTestEVPolicy>(
        EVRootCAMetadata::GetInstance(),
        X509Certificate::CalculateFingerprint256(root_cert->cert_buffer()),
        kEVTestCertPolicy);
  }

  void TearDown() override { HTTPSCertNetFetchingTest::TearDown(); }

 private:
  std::unique_ptr<ScopedTestEVPolicy> ev_test_policy_;
};

class HTTPSOCSPTest : public HTTPSCertNetFetchingTest {
 public:
  CertVerifier::Config GetCertVerifierConfig() override {
    CertVerifier::Config config;
    config.enable_rev_checking = true;
    return config;
  }
};

static bool UsingBuiltinCertVerifier() {
#if BUILDFLAG(IS_FUCHSIA) || BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS) || \
    BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
  return true;
#else
  return false;
#endif
}

// SystemSupportsHardFailRevocationChecking returns true iff the current
// operating system supports revocation checking and can distinguish between
// situations where a given certificate lacks any revocation information (eg:
// no CRLDistributionPoints and no OCSP Responder AuthorityInfoAccess) and when
// revocation information cannot be obtained (eg: the CRL was unreachable).
// If it does not, then tests which rely on 'hard fail' behaviour should be
// skipped.
static bool SystemSupportsHardFailRevocationChecking() {
  return UsingBuiltinCertVerifier();
}

// SystemUsesChromiumEVMetadata returns true iff the current operating system
// uses Chromium's EV metadata (i.e. EVRootCAMetadata). If it does not, then
// several tests are effected because our testing EV certificate won't be
// recognised as EV.
static bool SystemUsesChromiumEVMetadata() {
#if defined(PLATFORM_USES_CHROMIUM_EV_METADATA)
  return true;
#else
  return false;
#endif
}

static bool SystemSupportsOCSP() {
#if BUILDFLAG(IS_ANDROID)
  // Unsupported, see http://crbug.com/117478.
  return false;
#else
  return true;
#endif
}

static bool SystemSupportsOCSPStapling() {
  if (UsingBuiltinCertVerifier())
    return true;
#if BUILDFLAG(IS_ANDROID)
  return false;
#else
  return true;
#endif
}

static bool SystemSupportsCRLSets() {
  if (UsingBuiltinCertVerifier())
    return true;
#if BUILDFLAG(IS_ANDROID)
  return false;
#else
  return true;
#endif
}

TEST_F(HTTPSEVTest, EVCheckNoOCSP) {
  if (!SystemUsesChromiumEVMetadata()) {
    LOG(WARNING) << "Skipping test because system doesn't support EV";
    return;
  }
  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.policy_oids = {kEVTestCertPolicy};

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  EXPECT_EQ(0u, cert_status & CERT_STATUS_ALL_ERRORS);

  EXPECT_EQ(SystemUsesChromiumEVMetadata(),
            static_cast<bool>(cert_status & CERT_STATUS_IS_EV));

  EXPECT_FALSE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSOCSPTest, Valid) {
  if (!SystemSupportsOCSP()) {
    LOG(WARNING) << "Skipping test because system doesn't support OCSP";
    return;
  }

  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  EXPECT_EQ(0u, cert_status & CERT_STATUS_ALL_ERRORS);

  EXPECT_TRUE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSOCSPTest, Revoked) {
  if (!SystemSupportsOCSP()) {
    LOG(WARNING) << "Skipping test because system doesn't support OCSP";
    return;
  }

  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::REVOKED,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  EXPECT_EQ(CERT_STATUS_REVOKED, cert_status & CERT_STATUS_ALL_ERRORS);
  EXPECT_FALSE(cert_status & CERT_STATUS_IS_EV);
  EXPECT_TRUE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSOCSPTest, Invalid) {
  if (!SystemSupportsOCSP()) {
    LOG(WARNING) << "Skipping test because system doesn't support OCSP";
    return;
  }

  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      EmbeddedTestServer::OCSPConfig::ResponseType::kInvalidResponse);

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  // Without a positive OCSP response, we shouldn't show the EV status, but also
  // should not show any revocation checking errors.
  EXPECT_FALSE(cert_status & CERT_STATUS_IS_EV);
  EXPECT_EQ(0u, cert_status & CERT_STATUS_ALL_ERRORS);
  EXPECT_TRUE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSOCSPTest, IntermediateValid) {
  if (!SystemSupportsOCSP()) {
    LOG(WARNING) << "Skipping test because system doesn't support OCSP";
    return;
  }

  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.intermediate = EmbeddedTestServer::IntermediateType::kInHandshake;
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});
  cert_config.intermediate_ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  EXPECT_EQ(0u, cert_status & CERT_STATUS_ALL_ERRORS);

  EXPECT_TRUE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSOCSPTest, IntermediateResponseOldButStillValid) {
  if (!SystemSupportsOCSP()) {
    LOG(WARNING) << "Skipping test because system doesn't support OCSP";
    return;
  }

  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.intermediate = EmbeddedTestServer::IntermediateType::kInHandshake;
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});
  // Use an OCSP response for the intermediate that would be too old for a leaf
  // cert, but is still valid for an intermediate.
  cert_config.intermediate_ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::REVOKED,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kLong}});

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  EXPECT_EQ(CERT_STATUS_REVOKED, cert_status & CERT_STATUS_ALL_ERRORS);
  EXPECT_TRUE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSOCSPTest, IntermediateResponseTooOldKnownRoot) {
  if (!SystemSupportsOCSP()) {
    LOG(WARNING) << "Skipping test because system doesn't support OCSP";
    return;
  }

  scoped_refptr<X509Certificate> root_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "root_ca_cert.pem");
  ASSERT_TRUE(root_cert);
  ScopedTestKnownRoot scoped_known_root(root_cert.get());

  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.intermediate = EmbeddedTestServer::IntermediateType::kInHandshake;
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});
  cert_config.intermediate_ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::REVOKED,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kLonger}});
  cert_config.dns_names = {"example.com"};

  CertStatus cert_status;
  DoConnection("example.com", cert_config, &cert_status);

  if (UsingBuiltinCertVerifier()) {
    // The intermediate certificate is marked as a known root and has an OCSP
    // response indicating REVOKED status, but the response is too old
    // according to the Baseline Requirements, thus the response should be
    // ignored and the verification succeeds.
    EXPECT_EQ(0u, cert_status & CERT_STATUS_ALL_ERRORS);
  } else {
    EXPECT_EQ(CERT_STATUS_REVOKED, cert_status & CERT_STATUS_ALL_ERRORS);
  }
  EXPECT_TRUE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSOCSPTest, IntermediateResponseTooOld) {
  if (!SystemSupportsOCSP()) {
    LOG(WARNING) << "Skipping test because system doesn't support OCSP";
    return;
  }

  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.intermediate = EmbeddedTestServer::IntermediateType::kInHandshake;
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});
  cert_config.intermediate_ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::REVOKED,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kLonger}});

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  // The test root is not a known root, therefore the Baseline Requirements
  // limits on maximum age of a response do not apply and the intermediate OCSP
  // response indicating revoked is honored.
  EXPECT_EQ(CERT_STATUS_REVOKED, cert_status & CERT_STATUS_ALL_ERRORS);
  EXPECT_TRUE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSOCSPTest, IntermediateRevoked) {
  if (!SystemSupportsOCSP()) {
    LOG(WARNING) << "Skipping test because system doesn't support OCSP";
    return;
  }

  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.intermediate = EmbeddedTestServer::IntermediateType::kInHandshake;
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});
  cert_config.intermediate_ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::REVOKED,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  EXPECT_EQ(CERT_STATUS_REVOKED, cert_status & CERT_STATUS_ALL_ERRORS);
  EXPECT_TRUE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSOCSPTest, ValidStapled) {
  if (!SystemSupportsOCSPStapling()) {
    LOG(WARNING)
        << "Skipping test because system doesn't support OCSP stapling";
    return;
  }

  EmbeddedTestServer::ServerCertificateConfig cert_config;

  // AIA OCSP url is included, but does not return a successful ocsp response.
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      EmbeddedTestServer::OCSPConfig::ResponseType::kTryLater);

  cert_config.stapled_ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  EXPECT_EQ(0u, cert_status & CERT_STATUS_ALL_ERRORS);
  EXPECT_TRUE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSOCSPTest, RevokedStapled) {
  if (!SystemSupportsOCSPStapling()) {
    LOG(WARNING)
        << "Skipping test because system doesn't support OCSP stapling";
    return;
  }

  EmbeddedTestServer::ServerCertificateConfig cert_config;

  // AIA OCSP url is included, but does not return a successful ocsp response.
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      EmbeddedTestServer::OCSPConfig::ResponseType::kTryLater);

  cert_config.stapled_ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::REVOKED,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});

  CertStatus cert_status;
  DoConnection(cert_config, &cert_status);

  EXPECT_EQ(CERT_STATUS_REVOKED, cert_status & CERT_STATUS_ALL_ERRORS);
  EXPECT_TRUE(cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_F(HTTPSOCSPTest, OldStapledAndInvalidAIA) {
  if (!SystemSupportsOCSPStapling()) {
    LOG(WARNING)
        << "Skipping test because system doesn't support OCSP stapling";
    return;
  }

  EmbeddedTestServer::ServerCertificateConfig cert_config;

  // Stapled response indicates good, but is too old.
  cert_config.stapled_ocsp_config = EmbeddedTestServer::O
"""


```