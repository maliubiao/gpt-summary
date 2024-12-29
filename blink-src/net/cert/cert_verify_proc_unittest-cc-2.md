Response:
The user wants to understand the functionality of the given C++ code snippet from `net/cert/cert_verify_proc_unittest.cc`. I need to analyze the code and identify its purpose, especially focusing on:

1. **Overall Functionality:** What does this code test?
2. **Relation to Javascript:** Are there any connections, and if so, how?
3. **Logical Reasoning:** Can I infer inputs and outputs for specific tests?
4. **User/Programming Errors:** What common mistakes could lead to these tests failing?
5. **User Interaction:** How does a user's action eventually trigger this code?
6. **Summary:** Condense the functionality into a concise description.

Let's break down the code section by section:

*   **`TEST_P(CertVerifyProcInternalTest, ExcludeSymantec)`:** Tests the ability to exclude Symantec legacy certificates during verification, either explicitly or based on built-in logic.
*   **`TEST_P(CertVerifyProcInternalTest, VerifyReturnChainProperlyOrdered)`:** Tests if the `CertVerifyProc` can reorder out-of-order intermediate certificates.
*   **`TEST_P(CertVerifyProcInternalTest, VerifyReturnChainFiltersUnrelatedCerts)`:** Tests if the `CertVerifyProc` filters out unrelated certificates from the provided intermediate list.
*   **`TEST_P(CertVerifyProcInternalTest, AdditionalTrustAnchors)`:** Tests the functionality of adding additional trusted root certificates for verification.
*   **`TEST_P(CertVerifyProcInternalTest, AdditionalIntermediates)`:** Tests the functionality of providing additional intermediate certificates to aid in path building.
*   **`TEST_P(CertVerifyProcInternalTest, AdditionalIntermediateDuplicatesRoot)`:** Tests how the system handles an additional intermediate certificate that is also a trusted root.
*   **`TEST_P(CertVerifyProcInternalTest, AdditionalTrustAnchorDuplicateIntermediate)`:** Tests how the system handles a trusted root certificate that is also present in the intermediate list.
*   **`TEST_P(CertVerifyProcInternalTest, IsIssuedByKnownRootIgnoresTestRoots)`:** Tests that certificates issued by test roots are not incorrectly flagged as issued by known, globally trusted roots.
*   **`TEST_P(CertVerifyProcInternalTest, CRLSet)`:** Tests the functionality of Certificate Revocation Lists (CRLSets) to mark certificates as revoked.
*   **`TEST_P(CertVerifyProcInternalTest, CRLSetLeafSerial)`:** Tests CRLSet revocation based on the serial number of a non-root certificate.
*   **`TEST_P(CertVerifyProcInternalTest, CRLSetRootReturnsChain)`:** Tests that a CRLSet revocation of a root certificate still returns the validated chain.
*   **`TEST_P(CertVerifyProcInternalTest, CRLSetRevokedBySubject)`:** Tests CRLSet revocation based on the certificate subject.
*   **`TEST_P(CertVerifyProcInternalTest, BlockedInterceptionByRoot)`:** Tests the ability of CRLSets to block certificates issued by known interception root authorities.
*   **`TEST_P(CertVerifyProcInternalTest, BlockedInterceptionByIntermediate)`:** Tests the ability of CRLSets to block certificates issued by known interception intermediate authorities.
*   **`TEST_P(CertVerifyProcInternalTest, DetectsInterceptionByRoot)`:** Tests the ability of CRLSets to detect (but not necessarily block) certificates issued by known interception root authorities.
*   **`TEST_P(CertVerifyProcInternalTest, CRLSetDuringPathBuilding)`:** Tests the interaction of CRLSets with the certificate path building process.
*   **`TEST_P(CertVerifyProcInternalTest, ValidityDayPlus5MinutesBeforeNotBefore)`**, **`TEST_P(CertVerifyProcInternalTest, ValidityDayBeforeNotBefore)`**, **`TEST_P(CertVerifyProcInternalTest, ValidityJustBeforeNotBefore)`**, **`TEST_P(CertVerifyProcInternalTest, ValidityJustAfterNotBefore)`:** Tests certificate validity checks based on the "notBefore" date.

The common theme is testing the `CertVerifyProc` class's ability to correctly validate certificates under various conditions, including handling intermediate certificates, trust anchors, and certificate revocation lists.

Regarding Javascript, while this C++ code doesn't directly interact with Javascript, the functionality it tests is crucial for secure communication on the web. When a Javascript application makes an HTTPS request, the browser's network stack (which includes this C++ code) is responsible for verifying the server's certificate.

For logical reasoning, I can pick a couple of tests and create hypothetical inputs and outputs.

For user errors, common mistakes involve incorrect certificate configurations or ignoring browser security warnings.

Finally, I need to describe how a user action leads to this code being executed, which is typically through initiating a secure network connection.
这是 `net/cert/cert_verify_proc_unittest.cc` 文件的一部分，主要功能是**测试 `CertVerifyProc` 类的各种证书验证逻辑**。 `CertVerifyProc` 是 Chromium 网络栈中负责执行证书链构建和验证的核心组件。

**具体来说，这部分代码测试了以下功能：**

*   **排除旧版赛门铁克证书 (Exclude Symantec):**  验证 `CertVerifyProc` 是否能够正确处理旧版赛门铁克颁发的证书，可以强制将其视为无效，或者允许忽略这些策略。
*   **验证返回的链条顺序正确 (VerifyReturnChainProperlyOrdered):** 测试当提供的证书链中间证书顺序不正确时，`CertVerifyProc` 是否能够重新排序，使其符合从终端实体到根的顺序。
*   **验证返回的链条会过滤掉无关证书 (VerifyReturnChainFiltersUnrelatedCerts):**  测试当提供的中间证书列表中包含与待验证证书链无关的证书时，`CertVerifyProc` 是否能够正确地将其过滤掉。
*   **额外的信任锚点 (AdditionalTrustAnchors):** 测试在验证过程中添加额外的用户信任的根证书 (trust anchors) 的功能。这允许用户信任一些非内置的 CA 证书。
*   **额外的中间证书 (AdditionalIntermediates):** 测试在验证过程中提供额外的中间证书来帮助构建完整的证书链的功能。
*   **额外的中间证书与根证书重复 (AdditionalIntermediateDuplicatesRoot):** 测试当提供的额外中间证书中包含已经被信任的根证书时，`CertVerifyProc` 的处理逻辑。
*   **额外的信任锚点与中间证书重复 (AdditionalTrustAnchorDuplicateIntermediate):** 测试当一个证书既作为额外的信任锚点又作为中间证书提供时，`CertVerifyProc` 的处理逻辑。
*   **忽略测试根证书的已知根标记 (IsIssuedByKnownRootIgnoresTestRoots):** 测试由测试环境中设置的根证书颁发的证书不会被错误地标记为由已知的、内置的根证书颁发。
*   **证书吊销列表集合 (CRLSet):** 测试使用 CRLSet (Certificate Revocation List Set) 来标记证书为已吊销的功能。测试了通过 SPKI (Subject Public Key Info) 和证书序列号进行吊销。
*   **CRLSet 吊销叶子证书序列号 (CRLSetLeafSerial):** 测试通过 CRLSet 吊销非根证书的功能。
*   **CRLSet 根证书返回链 (CRLSetRootReturnsChain):** 测试当根证书被 CRLSet 吊销时，验证过程仍然能返回已验证的证书链信息。
*   **CRLSet 通过主体吊销 (CRLSetRevokedBySubject):** 测试通过 CRLSet 使用证书的主题 (Subject) 来进行吊销的功能。
*   **阻止已知的中间人攻击根证书 (BlockedInterceptionByRoot):** 测试 CRLSet 是否能够阻止已知的中间人攻击根证书。
*   **阻止已知的中间人攻击中间证书 (BlockedInterceptionByIntermediate):** 测试 CRLSet 是否能够阻止已知的中间人攻击中间证书。
*   **检测到中间人攻击根证书 (DetectsInterceptionByRoot):** 测试即使不阻止，CRLSet 也能检测到已知的中间人攻击根证书。
*   **路径构建期间的 CRLSet (CRLSetDuringPathBuilding):** 测试 CRLSet 如何在证书路径构建过程中发挥作用，即使存在多个可能的路径，也能根据 CRLSet 的吊销信息选择有效的路径。
*   **证书有效期检查 (Validity...):** 测试证书的有效期检查，包括在 `notBefore` 日期之前的各种情况。

**与 Javascript 的关系：**

虽然这段 C++ 代码本身不是 Javascript，但它直接影响着 Javascript 在浏览器环境中的安全通信。当 Javascript 代码发起一个 HTTPS 请求时，Chromium 的网络栈会使用 `CertVerifyProc` 来验证服务器提供的证书。如果证书验证失败（例如，证书已过期、未被信任的 CA 签名、已被吊销等），浏览器会阻止 Javascript 代码访问该网站，并显示安全警告。

**举例说明:**

假设一个 Javascript 应用程序尝试访问 `https://www.example.com`。服务器返回一个证书，该证书由一个不在浏览器默认信任列表中的 CA 颁发。

*   **假设输入：**
    *   待验证的证书：`www.example.com` 的服务器证书
    *   主机名：`www.example.com`
    *   浏览器默认的信任锚点集合
*   **预期输出（在没有额外配置的情况下）：**  证书验证失败，返回 `ERR_CERT_AUTHORITY_INVALID` 错误。浏览器会阻止 Javascript 代码访问该网站。

如果用户手动添加了颁发 `www.example.com` 证书的 CA 到浏览器的信任列表中（相当于测试中的 `AdditionalTrustAnchors` 测试），那么：

*   **假设输入：**
    *   待验证的证书：`www.example.com` 的服务器证书
    *   主机名：`www.example.com`
    *   浏览器默认的信任锚点集合 + 用户添加的 CA 证书
*   **预期输出：** 证书验证成功。Javascript 代码可以正常访问 `www.example.com`。

**用户或编程常见的使用错误：**

*   **用户错误：**
    *   **忽略浏览器安全警告：** 用户可能会选择忽略浏览器显示的证书错误警告，继续访问不安全的网站。这会绕过 `CertVerifyProc` 的安全检查。
    *   **错误地安装根证书：** 用户可能会安装来自不可信来源的根证书到系统中，导致 `CertVerifyProc` 信任恶意的证书。
*   **编程错误：**
    *   **服务器配置错误的证书链：** 服务器管理员可能配置了不完整的证书链（缺少中间证书），导致客户端无法验证服务器证书。这会触发 `VerifyReturnChainProperlyOrdered` 和 `VerifyReturnChainFiltersUnrelatedCerts` 相关的测试场景。
    *   **使用了过期的证书：** 服务器使用了已过期的证书，会导致 `Validity...` 相关的测试失败，用户访问网站时会收到证书过期警告。
    *   **未及时更新 CRLSet：** 如果浏览器或操作系统没有及时更新 CRLSet，可能会导致本应被吊销的证书仍然被信任，这与 `CRLSet` 相关的测试直接相关。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户在浏览器地址栏输入一个 HTTPS 网址，例如 `https://www.example.com`，或者点击一个 HTTPS 链接。**
2. **浏览器的网络线程发起与 `www.example.com` 服务器的 TLS 连接请求。**
3. **服务器在 TLS 握手过程中向浏览器发送其证书。**
4. **Chromium 的网络栈接收到服务器的证书。**
5. **`CertVerifyProc` 类被调用，开始执行证书链的构建和验证过程。** 这涉及到：
    *   查找证书链中的中间证书（可能从本地缓存或服务器提供的证书中获取）。
    *   验证证书的签名，确保证书是由其声明的签发者签名的。
    *   检查证书的有效期。
    *   检查证书是否在 CRLSet 中被吊销。
    *   检查证书是否由受信任的根证书签发。
    *   应用额外的配置，例如用户添加的信任锚点。
6. **`CertVerifyProc` 返回验证结果（成功或失败）以及证书状态信息。**
7. **如果验证失败，浏览器会显示安全警告，并阻止 Javascript 代码访问该网站。相关的错误信息可能会在浏览器的开发者工具中的 Network 或 Security 标签中显示。**
8. **为了调试证书验证问题，开发人员可能会运行 `cert_verify_proc_unittest.cc` 中的测试用例，以验证 `CertVerifyProc` 的行为是否符合预期。** 这些单元测试模拟了各种证书验证场景，帮助定位问题。

**功能归纳 (第 3 部分):**

这部分 `cert_verify_proc_unittest.cc` 代码主要负责测试 Chromium 网络栈中 `CertVerifyProc` 组件在处理证书验证过程中的核心逻辑，包括处理旧版证书、重新排序和过滤中间证书、支持额外的信任锚点和中间证书、以及利用 CRLSet 进行证书吊销检查等关键功能。 这些测试确保了 `CertVerifyProc` 能够正确且安全地验证服务器证书，从而保障用户的网络安全。

Prompt: 
```
这是目录为net/cert/cert_verify_proc_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共8部分，请归纳一下它的功能

"""
d_result);

  CertVerifyResult test_result_2;
  error = verify_proc->Verify(cert.get(), "www.example.com",
                              /*ocsp_response=*/std::string(),
                              /*sct_list=*/std::string(), 0, &test_result_2,
                              NetLogWithSource());
  EXPECT_THAT(error, IsOk());
  EXPECT_FALSE(test_result_2.cert_status & CERT_STATUS_AUTHORITY_INVALID);

  // ... Or the caller disabled enforcement of Symantec policies.
  CertVerifyResult test_result_3;
  error = verify_proc->Verify(
      cert.get(), "www.example.com", /*ocsp_response=*/std::string(),
      /*sct_list=*/std::string(),
      CertVerifyProc::VERIFY_DISABLE_SYMANTEC_ENFORCEMENT, &test_result_3,
      NetLogWithSource());
  EXPECT_THAT(error, IsOk());
  EXPECT_FALSE(test_result_3.cert_status & CERT_STATUS_SYMANTEC_LEGACY);
}

// Test that the certificate returned in CertVerifyResult is able to reorder
// certificates that are not ordered from end-entity to root. While this is
// a protocol violation if sent during a TLS handshake, if multiple sources
// of intermediate certificates are combined, it's possible that order may
// not be maintained.
TEST_P(CertVerifyProcInternalTest, VerifyReturnChainProperlyOrdered) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  CertificateList certs = CreateCertificateListFromFile(
      certs_dir, "x509_verify_results.chain.pem", X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(3U, certs.size());

  // Construct the chain out of order.
  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
  intermediates.push_back(bssl::UpRef(certs[2]->cert_buffer()));
  intermediates.push_back(bssl::UpRef(certs[1]->cert_buffer()));

  ScopedTestRoot scoped_root(certs[2]);

  scoped_refptr<X509Certificate> google_full_chain =
      X509Certificate::CreateFromBuffer(bssl::UpRef(certs[0]->cert_buffer()),
                                        std::move(intermediates));
  ASSERT_TRUE(google_full_chain);
  ASSERT_EQ(2U, google_full_chain->intermediate_buffers().size());

  CertVerifyResult verify_result;
  EXPECT_FALSE(verify_result.verified_cert);
  int error = Verify(google_full_chain.get(), "127.0.0.1", 0, &verify_result);
  EXPECT_THAT(error, IsOk());
  ASSERT_TRUE(verify_result.verified_cert);

  EXPECT_NE(google_full_chain, verify_result.verified_cert);
  EXPECT_TRUE(
      x509_util::CryptoBufferEqual(google_full_chain->cert_buffer(),
                                   verify_result.verified_cert->cert_buffer()));
  const auto& return_intermediates =
      verify_result.verified_cert->intermediate_buffers();
  ASSERT_EQ(2U, return_intermediates.size());
  EXPECT_TRUE(x509_util::CryptoBufferEqual(return_intermediates[0].get(),
                                           certs[1]->cert_buffer()));
  EXPECT_TRUE(x509_util::CryptoBufferEqual(return_intermediates[1].get(),
                                           certs[2]->cert_buffer()));
}

// Test that Verify() filters out certificates which are not related to
// or part of the certificate chain being verified.
TEST_P(CertVerifyProcInternalTest, VerifyReturnChainFiltersUnrelatedCerts) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  CertificateList certs = CreateCertificateListFromFile(
      certs_dir, "x509_verify_results.chain.pem", X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(3U, certs.size());
  ScopedTestRoot scoped_root(certs[2]);

  scoped_refptr<X509Certificate> unrelated_certificate =
      ImportCertFromFile(certs_dir, "duplicate_cn_1.pem");
  scoped_refptr<X509Certificate> unrelated_certificate2 =
      ImportCertFromFile(certs_dir, "google.single.pem");
  ASSERT_NE(static_cast<X509Certificate*>(nullptr),
            unrelated_certificate.get());
  ASSERT_NE(static_cast<X509Certificate*>(nullptr),
            unrelated_certificate2.get());

  // Interject unrelated certificates into the list of intermediates.
  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
  intermediates.push_back(bssl::UpRef(unrelated_certificate->cert_buffer()));
  intermediates.push_back(bssl::UpRef(certs[1]->cert_buffer()));
  intermediates.push_back(bssl::UpRef(unrelated_certificate2->cert_buffer()));
  intermediates.push_back(bssl::UpRef(certs[2]->cert_buffer()));

  scoped_refptr<X509Certificate> google_full_chain =
      X509Certificate::CreateFromBuffer(bssl::UpRef(certs[0]->cert_buffer()),
                                        std::move(intermediates));
  ASSERT_TRUE(google_full_chain);
  ASSERT_EQ(4U, google_full_chain->intermediate_buffers().size());

  CertVerifyResult verify_result;
  EXPECT_FALSE(verify_result.verified_cert);
  int error = Verify(google_full_chain.get(), "127.0.0.1", 0, &verify_result);
  EXPECT_THAT(error, IsOk());
  ASSERT_TRUE(verify_result.verified_cert);

  EXPECT_NE(google_full_chain, verify_result.verified_cert);
  EXPECT_TRUE(
      x509_util::CryptoBufferEqual(google_full_chain->cert_buffer(),
                                   verify_result.verified_cert->cert_buffer()));
  const auto& return_intermediates =
      verify_result.verified_cert->intermediate_buffers();
  ASSERT_EQ(2U, return_intermediates.size());
  EXPECT_TRUE(x509_util::CryptoBufferEqual(return_intermediates[0].get(),
                                           certs[1]->cert_buffer()));
  EXPECT_TRUE(x509_util::CryptoBufferEqual(return_intermediates[1].get(),
                                           certs[2]->cert_buffer()));
}

TEST_P(CertVerifyProcInternalTest, AdditionalTrustAnchors) {
  if (!VerifyProcTypeIsBuiltin()) {
    LOG(INFO) << "Skipping this test in this platform.";
    return;
  }

  // |ca_cert| is the issuer of |cert|.
  CertificateList ca_cert_list =
      CreateCertificateListFromFile(GetTestCertsDirectory(), "root_ca_cert.pem",
                                    X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, ca_cert_list.size());
  scoped_refptr<X509Certificate> ca_cert(ca_cert_list[0]);

  CertificateList cert_list = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "ok_cert.pem", X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, cert_list.size());
  scoped_refptr<X509Certificate> cert(cert_list[0]);

  // Verification of |cert| fails when |ca_cert| is not in the trust anchors
  // list.
  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(cert.get(), "127.0.0.1", flags, &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, verify_result.cert_status);
  EXPECT_FALSE(verify_result.is_issued_by_additional_trust_anchor);

  // Now add the |ca_cert| to the |trust_anchors|, and verification should pass.
  CertificateList trust_anchors;
  trust_anchors.push_back(ca_cert);
  SetUpWithAdditionalCerts(trust_anchors, {});
  error = Verify(cert.get(), "127.0.0.1", flags, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);
  EXPECT_TRUE(verify_result.is_issued_by_additional_trust_anchor);

  // Clearing the |trust_anchors| makes verification fail again (the cache
  // should be skipped).
  SetUpWithAdditionalCerts({}, {});
  error = Verify(cert.get(), "127.0.0.1", flags, &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, verify_result.cert_status);
  EXPECT_FALSE(verify_result.is_issued_by_additional_trust_anchor);
}

TEST_P(CertVerifyProcInternalTest, AdditionalIntermediates) {
  if (!VerifyProcTypeIsBuiltin()) {
    LOG(INFO) << "Skipping this test in this platform.";
    return;
  }

  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  scoped_refptr<X509Certificate> leaf_cert = leaf->GetX509Certificate();
  scoped_refptr<X509Certificate> intermediate_cert =
      intermediate->GetX509Certificate();
  scoped_refptr<X509Certificate> root_cert = root->GetX509Certificate();
  constexpr char kHostname[] = "www.example.com";

  ScopedTestRoot trust_root(root_cert);
  // Leaf should not verify without intermediate found
  EXPECT_THAT(Verify(leaf_cert.get(), kHostname),
              IsError(ERR_CERT_AUTHORITY_INVALID));

  // Leaf should verify after intermediate is passed in to CertVerifyProc. Chain
  // should be {leaf, intermediate, root}.
  SetUpWithAdditionalCerts({}, {intermediate->GetX509Certificate()});
  CertVerifyResult verify_result;
  int error = Verify(leaf_cert.get(), kHostname, /*flags=*/0, &verify_result);
  EXPECT_THAT(error, IsOk());
  ASSERT_TRUE(verify_result.verified_cert);
  EXPECT_EQ(verify_result.verified_cert->intermediate_buffers().size(), 2U);
  EXPECT_TRUE(x509_util::CryptoBufferEqual(
      verify_result.verified_cert->intermediate_buffers().back().get(),
      root_cert->cert_buffer()));
  EXPECT_TRUE(x509_util::CryptoBufferEqual(
      verify_result.verified_cert->intermediate_buffers().front().get(),
      intermediate_cert->cert_buffer()));
  EXPECT_FALSE(verify_result.is_issued_by_additional_trust_anchor);
}

TEST_P(CertVerifyProcInternalTest, AdditionalIntermediateDuplicatesRoot) {
  if (!VerifyProcTypeIsBuiltin()) {
    LOG(INFO) << "Skipping this test in this platform.";
    return;
  }

  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  scoped_refptr<X509Certificate> leaf_cert = leaf->GetX509Certificate();
  scoped_refptr<X509Certificate> intermediate_cert =
      intermediate->GetX509Certificate();
  scoped_refptr<X509Certificate> root_cert = root->GetX509Certificate();
  constexpr char kHostname[] = "www.example.com";

  // The root is trusted through ScopedTestRoot, not through
  // additional_trust_anchors.
  ScopedTestRoot trust_root(root_cert);
  // In addition to the intermediate cert, the root cert is also configured as
  // an additional *untrusted* certificate, which is harmless. This shouldn't
  // cause the result to be considered as is_issued_by_additional_trust_anchor.
  SetUpWithAdditionalCerts(
      {}, {root->GetX509Certificate(), intermediate->GetX509Certificate()});
  CertVerifyResult verify_result;
  int error = Verify(leaf_cert.get(), kHostname, /*flags=*/0, &verify_result);
  EXPECT_THAT(error, IsOk());
  ASSERT_TRUE(verify_result.verified_cert);
  EXPECT_EQ(verify_result.verified_cert->intermediate_buffers().size(), 2U);
  EXPECT_FALSE(verify_result.is_issued_by_additional_trust_anchor);
}

TEST_P(CertVerifyProcInternalTest, AdditionalTrustAnchorDuplicateIntermediate) {
  if (!VerifyProcTypeIsBuiltin()) {
    LOG(INFO) << "Skipping this test in this platform.";
    return;
  }

  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  constexpr char kHostname[] = "www.example.com";

  // Leaf should not verify without anything set up.
  EXPECT_THAT(Verify(leaf->GetX509Certificate().get(), kHostname),
              IsError(ERR_CERT_AUTHORITY_INVALID));

  // Leaf should verify with intermediate and root added.
  CertificateList trust_anchors, intermediates;
  intermediates.push_back(intermediate->GetX509Certificate());
  trust_anchors.push_back(root->GetX509Certificate());
  SetUpWithAdditionalCerts(trust_anchors, intermediates);
  CertVerifyResult verify_result;
  EXPECT_THAT(Verify(leaf->GetX509Certificate().get(), kHostname,
                     /*flags=*/0, &verify_result),
              IsOk());
  EXPECT_TRUE(verify_result.is_issued_by_additional_trust_anchor);

  // Leaf should still verify after root is also in intermediates list.
  intermediates.push_back(root->GetX509Certificate());
  SetUpWithAdditionalCerts(trust_anchors, intermediates);
  EXPECT_THAT(Verify(leaf->GetX509Certificate().get(), kHostname,
                     /*flags=*/0, &verify_result),
              IsOk());
  EXPECT_TRUE(verify_result.is_issued_by_additional_trust_anchor);
}

// Tests that certificates issued by user-supplied roots are not flagged as
// issued by a known root. This should pass whether or not the platform supports
// detecting known roots.
TEST_P(CertVerifyProcInternalTest, IsIssuedByKnownRootIgnoresTestRoots) {
  // Load root_ca_cert.pem into the test root store.
  ScopedTestRoot test_root(
      ImportCertFromFile(GetTestCertsDirectory(), "root_ca_cert.pem"));

  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem"));

  // Verification should pass.
  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(cert.get(), "127.0.0.1", flags, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);
  // But should not be marked as a known root.
  EXPECT_FALSE(verify_result.is_issued_by_known_root);
}

// Test that CRLSets are effective in making a certificate appear to be
// revoked.
TEST_P(CertVerifyProcInternalTest, CRLSet) {
  if (!SupportsCRLSet()) {
    LOG(INFO) << "Skipping test as verifier doesn't support CRLSet";
    return;
  }

  CertificateList ca_cert_list =
      CreateCertificateListFromFile(GetTestCertsDirectory(), "root_ca_cert.pem",
                                    X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, ca_cert_list.size());
  ScopedTestRoot test_root(ca_cert_list[0]);

  CertificateList cert_list = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "ok_cert.pem", X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, cert_list.size());
  scoped_refptr<X509Certificate> cert(cert_list[0]);

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(cert.get(), "127.0.0.1", flags, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);

  scoped_refptr<CRLSet> crl_set;
  std::string crl_set_bytes;

  // First test blocking by SPKI.
  EXPECT_TRUE(base::ReadFileToString(
      GetTestCertsDirectory().AppendASCII("crlset_by_leaf_spki.raw"),
      &crl_set_bytes));
  ASSERT_TRUE(CRLSet::Parse(crl_set_bytes, &crl_set));

  SetUpCertVerifyProc(crl_set);
  error = Verify(cert.get(), "127.0.0.1", flags, &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_REVOKED));

  // Second, test revocation by serial number of a cert directly under the
  // root.
  crl_set_bytes.clear();
  EXPECT_TRUE(base::ReadFileToString(
      GetTestCertsDirectory().AppendASCII("crlset_by_root_serial.raw"),
      &crl_set_bytes));
  ASSERT_TRUE(CRLSet::Parse(crl_set_bytes, &crl_set));

  SetUpCertVerifyProc(crl_set);
  error = Verify(cert.get(), "127.0.0.1", flags, &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_REVOKED));
}

TEST_P(CertVerifyProcInternalTest, CRLSetLeafSerial) {
  if (!SupportsCRLSet()) {
    LOG(INFO) << "Skipping test as verifier doesn't support CRLSet";
    return;
  }

  CertificateList ca_cert_list =
      CreateCertificateListFromFile(GetTestCertsDirectory(), "root_ca_cert.pem",
                                    X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, ca_cert_list.size());
  ScopedTestRoot test_root(ca_cert_list[0]);

  scoped_refptr<X509Certificate> leaf = CreateCertificateChainFromFile(
      GetTestCertsDirectory(), "ok_cert_by_intermediate.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_TRUE(leaf);
  ASSERT_EQ(1U, leaf->intermediate_buffers().size());

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(leaf.get(), "127.0.0.1", flags, &verify_result);
  EXPECT_THAT(error, IsOk());

  // Test revocation by serial number of a certificate not under the root.
  scoped_refptr<CRLSet> crl_set;
  std::string crl_set_bytes;
  ASSERT_TRUE(base::ReadFileToString(
      GetTestCertsDirectory().AppendASCII("crlset_by_intermediate_serial.raw"),
      &crl_set_bytes));
  ASSERT_TRUE(CRLSet::Parse(crl_set_bytes, &crl_set));

  SetUpCertVerifyProc(crl_set);
  error = Verify(leaf.get(), "127.0.0.1", flags, &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_REVOKED));
}

TEST_P(CertVerifyProcInternalTest, CRLSetRootReturnsChain) {
  if (!SupportsCRLSet()) {
    LOG(INFO) << "Skipping test as verifier doesn't support CRLSet";
    return;
  }

  CertificateList ca_cert_list =
      CreateCertificateListFromFile(GetTestCertsDirectory(), "root_ca_cert.pem",
                                    X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, ca_cert_list.size());
  ScopedTestRoot test_root(ca_cert_list[0]);

  scoped_refptr<X509Certificate> leaf = CreateCertificateChainFromFile(
      GetTestCertsDirectory(), "ok_cert_by_intermediate.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_TRUE(leaf);
  ASSERT_EQ(1U, leaf->intermediate_buffers().size());

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(leaf.get(), "127.0.0.1", flags, &verify_result);
  EXPECT_THAT(error, IsOk());

  // Test revocation of the root itself.
  scoped_refptr<CRLSet> crl_set;
  std::string crl_set_bytes;
  ASSERT_TRUE(base::ReadFileToString(
      GetTestCertsDirectory().AppendASCII("crlset_by_root_spki.raw"),
      &crl_set_bytes));
  ASSERT_TRUE(CRLSet::Parse(crl_set_bytes, &crl_set));

  SetUpCertVerifyProc(crl_set);
  error = Verify(leaf.get(), "127.0.0.1", flags, &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_REVOKED));

  EXPECT_EQ(3u, verify_result.public_key_hashes.size());
  ASSERT_TRUE(verify_result.verified_cert);
  EXPECT_EQ(2u, verify_result.verified_cert->intermediate_buffers().size());
}

// Tests that CertVerifyProc implementations apply CRLSet revocations by
// subject.
TEST_P(CertVerifyProcInternalTest, CRLSetRevokedBySubject) {
  if (!SupportsCRLSet()) {
    LOG(INFO) << "Skipping test as verifier doesn't support CRLSet";
    return;
  }

  scoped_refptr<X509Certificate> root(
      ImportCertFromFile(GetTestCertsDirectory(), "root_ca_cert.pem"));
  ASSERT_TRUE(root);

  scoped_refptr<X509Certificate> leaf(
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem"));
  ASSERT_TRUE(leaf);

  ScopedTestRoot scoped_root(root);

  int flags = 0;
  CertVerifyResult verify_result;

  // Confirm that verifying the certificate chain with an empty CRLSet succeeds.
  SetUpCertVerifyProc(CRLSet::EmptyCRLSetForTesting());
  int error = Verify(leaf.get(), "127.0.0.1", flags, &verify_result);
  EXPECT_THAT(error, IsOk());

  std::string crl_set_bytes;
  scoped_refptr<CRLSet> crl_set;

  // Revoke the leaf by subject. Verification should now fail.
  ASSERT_TRUE(base::ReadFileToString(
      GetTestCertsDirectory().AppendASCII("crlset_by_leaf_subject_no_spki.raw"),
      &crl_set_bytes));
  ASSERT_TRUE(CRLSet::Parse(crl_set_bytes, &crl_set));

  SetUpCertVerifyProc(crl_set);
  error = Verify(leaf.get(), "127.0.0.1", flags, &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_REVOKED));

  // Revoke the root by subject. Verification should now fail.
  ASSERT_TRUE(base::ReadFileToString(
      GetTestCertsDirectory().AppendASCII("crlset_by_root_subject_no_spki.raw"),
      &crl_set_bytes));
  ASSERT_TRUE(CRLSet::Parse(crl_set_bytes, &crl_set));

  SetUpCertVerifyProc(crl_set);
  error = Verify(leaf.get(), "127.0.0.1", flags, &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_REVOKED));

  // Revoke the leaf by subject, but only if the SPKI doesn't match the given
  // one. Verification should pass when using the certificate's actual SPKI.
  ASSERT_TRUE(base::ReadFileToString(
      GetTestCertsDirectory().AppendASCII("crlset_by_root_subject.raw"),
      &crl_set_bytes));
  ASSERT_TRUE(CRLSet::Parse(crl_set_bytes, &crl_set));

  SetUpCertVerifyProc(crl_set);
  error = Verify(leaf.get(), "127.0.0.1", flags, &verify_result);
  EXPECT_THAT(error, IsOk());
}

// Ensures that CRLSets can be used to block known interception roots on
// platforms that support CRLSets, while otherwise detect known interception
// on platforms that do not.
TEST_P(CertVerifyProcInternalTest, BlockedInterceptionByRoot) {
  scoped_refptr<X509Certificate> root =
      ImportCertFromFile(GetTestCertsDirectory(), "root_ca_cert.pem");
  ASSERT_TRUE(root);
  ScopedTestRoot test_root(root);

  scoped_refptr<X509Certificate> cert = CreateCertificateChainFromFile(
      GetTestCertsDirectory(), "ok_cert_by_intermediate.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_TRUE(cert);

  // A default/built-in CRLSet should not block
  scoped_refptr<CRLSet> crl_set = CRLSet::BuiltinCRLSet();
  SetUpCertVerifyProc(crl_set);
  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(cert.get(), "127.0.0.1", flags, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);

  // Read in a CRLSet that marks the root as blocked for interception.
  std::string crl_set_bytes;
  ASSERT_TRUE(
      base::ReadFileToString(GetTestCertsDirectory().AppendASCII(
                                 "crlset_blocked_interception_by_root.raw"),
                             &crl_set_bytes));
  ASSERT_TRUE(CRLSet::Parse(crl_set_bytes, &crl_set));

  SetUpCertVerifyProc(crl_set);
  error = Verify(cert.get(), "127.0.0.1", flags, &verify_result);
  if (SupportsCRLSet()) {
    EXPECT_THAT(error, IsError(ERR_CERT_KNOWN_INTERCEPTION_BLOCKED));
    EXPECT_TRUE(verify_result.cert_status &
                CERT_STATUS_KNOWN_INTERCEPTION_BLOCKED);
  } else {
    EXPECT_THAT(error, IsOk());
    EXPECT_TRUE(verify_result.cert_status &
                CERT_STATUS_KNOWN_INTERCEPTION_DETECTED);
  }
}

// Ensures that CRLSets can be used to block known interception intermediates,
// while still allowing other certificates from that root..
TEST_P(CertVerifyProcInternalTest, BlockedInterceptionByIntermediate) {
  scoped_refptr<X509Certificate> root =
      ImportCertFromFile(GetTestCertsDirectory(), "root_ca_cert.pem");
  ASSERT_TRUE(root);
  ScopedTestRoot test_root(root);

  scoped_refptr<X509Certificate> cert = CreateCertificateChainFromFile(
      GetTestCertsDirectory(), "ok_cert_by_intermediate.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_TRUE(cert);

  // A default/built-in CRLSEt should not block
  scoped_refptr<CRLSet> crl_set = CRLSet::BuiltinCRLSet();
  SetUpCertVerifyProc(crl_set);
  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(cert.get(), "127.0.0.1", flags, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);

  // Read in a CRLSet that marks the intermediate as blocked for interception.
  std::string crl_set_bytes;
  ASSERT_TRUE(base::ReadFileToString(
      GetTestCertsDirectory().AppendASCII(
          "crlset_blocked_interception_by_intermediate.raw"),
      &crl_set_bytes));
  ASSERT_TRUE(CRLSet::Parse(crl_set_bytes, &crl_set));

  SetUpCertVerifyProc(crl_set);
  error = Verify(cert.get(), "127.0.0.1", flags, &verify_result);
  if (SupportsCRLSet()) {
    EXPECT_THAT(error, IsError(ERR_CERT_KNOWN_INTERCEPTION_BLOCKED));
    EXPECT_TRUE(verify_result.cert_status &
                CERT_STATUS_KNOWN_INTERCEPTION_BLOCKED);
  } else {
    EXPECT_THAT(error, IsOk());
    EXPECT_TRUE(verify_result.cert_status &
                CERT_STATUS_KNOWN_INTERCEPTION_DETECTED);
  }

  // Load a different certificate from that root, which should be unaffected.
  scoped_refptr<X509Certificate> second_cert = CreateCertificateChainFromFile(
      GetTestCertsDirectory(), "ok_cert.pem", X509Certificate::FORMAT_AUTO);
  ASSERT_TRUE(second_cert);

  SetUpCertVerifyProc(crl_set);
  error = Verify(second_cert.get(), "127.0.0.1", flags, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);
}

// Ensures that CRLSets can be used to flag known interception roots, even
// when they are not blocked.
TEST_P(CertVerifyProcInternalTest, DetectsInterceptionByRoot) {
  scoped_refptr<X509Certificate> root =
      ImportCertFromFile(GetTestCertsDirectory(), "root_ca_cert.pem");
  ASSERT_TRUE(root);
  ScopedTestRoot test_root(root);

  scoped_refptr<X509Certificate> cert = CreateCertificateChainFromFile(
      GetTestCertsDirectory(), "ok_cert_by_intermediate.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_TRUE(cert);

  // A default/built-in CRLSet should not block
  scoped_refptr<CRLSet> crl_set = CRLSet::BuiltinCRLSet();
  SetUpCertVerifyProc(crl_set);
  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(cert.get(), "127.0.0.1", flags, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);

  // Read in a CRLSet that marks the root as blocked for interception.
  std::string crl_set_bytes;
  ASSERT_TRUE(
      base::ReadFileToString(GetTestCertsDirectory().AppendASCII(
                                 "crlset_known_interception_by_root.raw"),
                             &crl_set_bytes));
  ASSERT_TRUE(CRLSet::Parse(crl_set_bytes, &crl_set));

  SetUpCertVerifyProc(crl_set);
  error = Verify(cert.get(), "127.0.0.1", flags, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_TRUE(verify_result.cert_status &
              CERT_STATUS_KNOWN_INTERCEPTION_DETECTED);
}

// Tests that CRLSets participate in path building functions, and that as
// long as a valid path exists within the verification graph, verification
// succeeds.
//
// In this test, there are two roots (D and E), and three possible paths
// to validate a leaf (A):
// 1. A(B) -> B(C) -> C(D) -> D(D)
// 2. A(B) -> B(C) -> C(E) -> E(E)
// 3. A(B) -> B(F) -> F(E) -> E(E)
//
// Each permutation of revocation is tried:
// 1. Revoking E by SPKI, so that only Path 1 is valid (as E is in Paths 2 & 3)
// 2. Revoking C(D) and F(E) by serial, so that only Path 2 is valid.
// 3. Revoking C by SPKI, so that only Path 3 is valid (as C is in Paths 1 & 2)
TEST_P(CertVerifyProcInternalTest, CRLSetDuringPathBuilding) {
  if (!SupportsCRLSetsInPathBuilding()) {
    LOG(INFO) << "Skipping this test on this platform.";
    return;
  }

  CertificateList path_1_certs;
  ASSERT_TRUE(
      LoadCertificateFiles({"multi-root-A-by-B.pem", "multi-root-B-by-C.pem",
                            "multi-root-C-by-D.pem", "multi-root-D-by-D.pem"},
                           &path_1_certs));

  CertificateList path_2_certs;
  ASSERT_TRUE(
      LoadCertificateFiles({"multi-root-A-by-B.pem", "multi-root-B-by-C.pem",
                            "multi-root-C-by-E.pem", "multi-root-E-by-E.pem"},
                           &path_2_certs));

  CertificateList path_3_certs;
  ASSERT_TRUE(
      LoadCertificateFiles({"multi-root-A-by-B.pem", "multi-root-B-by-F.pem",
                            "multi-root-F-by-E.pem", "multi-root-E-by-E.pem"},
                           &path_3_certs));

  // Add D and E as trust anchors.
  ScopedTestRoot test_root_D(path_1_certs[3]);  // D-by-D
  ScopedTestRoot test_root_E(path_2_certs[3]);  // E-by-E

  // Create a chain that contains all the certificate paths possible.
  // CertVerifyProcInternalTest.VerifyReturnChainFiltersUnrelatedCerts already
  // ensures that it's safe to send additional certificates as inputs, and
  // that they're ignored if not necessary.
  // This is to avoid relying on AIA or internal object caches when
  // interacting with the underlying library.
  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
  intermediates.push_back(
      bssl::UpRef(path_1_certs[1]->cert_buffer()));  // B-by-C
  intermediates.push_back(
      bssl::UpRef(path_1_certs[2]->cert_buffer()));  // C-by-D
  intermediates.push_back(
      bssl::UpRef(path_2_certs[2]->cert_buffer()));  // C-by-E
  intermediates.push_back(
      bssl::UpRef(path_3_certs[1]->cert_buffer()));  // B-by-F
  intermediates.push_back(
      bssl::UpRef(path_3_certs[2]->cert_buffer()));  // F-by-E
  scoped_refptr<X509Certificate> cert = X509Certificate::CreateFromBuffer(
      bssl::UpRef(path_1_certs[0]->cert_buffer()), std::move(intermediates));
  ASSERT_TRUE(cert);

  struct TestPermutations {
    const char* crlset;
    bool expect_valid;
    scoped_refptr<X509Certificate> expected_intermediate;
  } kTests[] = {
      {"multi-root-crlset-D-and-E.raw", false, nullptr},
      {"multi-root-crlset-E.raw", true, path_1_certs[2].get()},
      {"multi-root-crlset-CD-and-FE.raw", true, path_2_certs[2].get()},
      {"multi-root-crlset-C.raw", true, path_3_certs[2].get()},
      {"multi-root-crlset-unrelated.raw", true, nullptr}};

  for (const auto& testcase : kTests) {
    SCOPED_TRACE(testcase.crlset);
    scoped_refptr<CRLSet> crl_set;
    std::string crl_set_bytes;
    EXPECT_TRUE(base::ReadFileToString(
        GetTestCertsDirectory().AppendASCII(testcase.crlset), &crl_set_bytes));
    ASSERT_TRUE(CRLSet::Parse(crl_set_bytes, &crl_set));

    SetUpCertVerifyProc(crl_set);
    int flags = 0;
    CertVerifyResult verify_result;
    int error = Verify(cert.get(), "127.0.0.1", flags, &verify_result);

    if (!testcase.expect_valid) {
      EXPECT_NE(OK, error);
      EXPECT_NE(0U, verify_result.cert_status);
      continue;
    }

    ASSERT_THAT(error, IsOk());
    ASSERT_EQ(0U, verify_result.cert_status);
    ASSERT_TRUE(verify_result.verified_cert.get());

    if (!testcase.expected_intermediate)
      continue;

    const auto& verified_intermediates =
        verify_result.verified_cert->intermediate_buffers();
    ASSERT_EQ(3U, verified_intermediates.size());

    scoped_refptr<X509Certificate> intermediate =
        X509Certificate::CreateFromBuffer(
            bssl::UpRef(verified_intermediates[1].get()), {});
    ASSERT_TRUE(intermediate);

    EXPECT_TRUE(testcase.expected_intermediate->EqualsExcludingChain(
        intermediate.get()))
        << "Expected: " << testcase.expected_intermediate->subject().common_name
        << " issued by " << testcase.expected_intermediate->issuer().common_name
        << "; Got: " << intermediate->subject().common_name << " issued by "
        << intermediate->issuer().common_name;
  }
}

TEST_P(CertVerifyProcInternalTest, ValidityDayPlus5MinutesBeforeNotBefore) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  base::Time not_before = base::Time::Now() + base::Days(1) + base::Minutes(5);
  base::Time not_after = base::Time::Now() + base::Days(30);
  leaf->SetValidity(not_before, not_after);

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), "www.example.com", flags, &verify_result);
  // Current time is before certificate's notBefore. Verification should fail.
  EXPECT_THAT(error, IsError(ERR_CERT_DATE_INVALID));
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_DATE_INVALID);
}

TEST_P(CertVerifyProcInternalTest, ValidityDayBeforeNotBefore) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  base::Time not_before = base::Time::Now() + base::Days(1);
  base::Time not_after = base::Time::Now() + base::Days(30);
  leaf->SetValidity(not_before, not_after);

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), "www.example.com", flags, &verify_result);
  // Current time is before certificate's notBefore. Verification should fail.
  EXPECT_THAT(error, IsError(ERR_CERT_DATE_INVALID));
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_DATE_INVALID);
}

TEST_P(CertVerifyProcInternalTest, ValidityJustBeforeNotBefore) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  base::Time not_before = base::Time::Now() + base::Minutes(5);
  base::Time not_after = base::Time::Now() + base::Days(30);
  leaf->SetValidity(not_before, not_after);

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), "www.example.com", flags, &verify_result);
  // Current time is before certificate's notBefore. Verification should fail.
  EXPECT_THAT(error, IsError(ERR_CERT_DATE_INVALID));
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_DATE_INVALID);
}

TEST_P(CertVerifyProcInternalTest, ValidityJustAfterNotBefore) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  base::Time not_before = base::Time::Now() - base::Seconds(1);
  base::Time not_after = base::Time::Now() + base::Days(30);
  leaf->SetValidity(not_before, not_after);

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), "www.exa
"""


```