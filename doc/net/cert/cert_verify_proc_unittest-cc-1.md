Response:
The user wants to understand the functionality of the provided C++ code snippet from `net/cert/cert_verify_proc_unittest.cc`. This file seems to contain unit tests for certificate verification logic within Chromium's network stack.

I need to:
1. **Summarize the functionality** demonstrated by the code. It primarily tests various aspects of certificate verification.
2. **Identify any relationship to JavaScript.** Certificate verification in the browser is relevant to secure web communication, which directly impacts JavaScript running on web pages.
3. **Provide examples with assumed input and output** for some of the test cases.
4. **Illustrate common user or programming errors** that these tests aim to prevent or detect.
5. **Explain how a user's actions might lead to this code being executed**, focusing on the certificate verification process during a secure connection.
6. **Synthesize a high-level summary** of the code's purpose as the second part of an eight-part series.
这是`net/cert/cert_verify_proc_unittest.cc` 文件第 2 部分的代码，主要功能是 **测试 `CertVerifyProc` 类在各种场景下的证书验证行为**。它涵盖了证书有效期、弱密钥、多余根证书、吊销检查、名称约束、签名算法不匹配、证书有效期过长以及是否由已知根 CA 签发等多个方面的验证逻辑。

以下是对代码功能的详细归纳和说明：

**功能归纳:**

1. **测试证书有效期:**  测试验证过期证书是否会返回 `ERR_CERT_DATE_INVALID` 错误，并设置相应的证书状态 `CERT_STATUS_DATE_INVALID`。
2. **测试拒绝弱密钥:**  测试当证书链中使用弱密钥（例如 RSA-768, RSA-1024）时，验证是否会返回错误，并设置 `CERT_STATUS_WEAK_KEY` 状态。对于无效的密钥类型，则会设置 `CERT_STATUS_INVALID`。
3. **测试处理多余根证书:**  模拟存在一个受信任的 SHA256 根证书，和一个具有相同身份信息但使用 SHA1 签名的额外根证书的情况。测试验证器是否会优先选择受信任的根证书，构建最优路径。
4. **测试处理特定的证书吊销场景:**  针对 DigiNotar 签发的恶意证书进行测试，即使关闭吊销检查，也应该验证失败。
5. **测试名称约束:**  测试名称约束的生效情况，包括约束允许的域名和不允许的域名，验证是否会正确返回 `ERR_CERT_NAME_CONSTRAINT_VIOLATION` 和设置 `CERT_STATUS_NAME_CONSTRAINT_VIOLATION`。
6. **测试签名算法不匹配:**  测试证书的 `signatureAlgorithm` 和 `TBSCertificate.algorithm` 字段不匹配时，验证是否会返回 `ERR_CERT_INVALID` 错误。同时测试了根证书中出现不识别的签名算法的情况。
7. **测试证书有效期过长:**  测试 `CertVerifyProc::HasTooLongValidity` 函数是否能正确判断证书有效期是否超过浏览器限制。同时测试了当验证公开信任的证书时，如果有效期过长，即使内部验证成功，外部也会返回 `ERR_CERT_VALIDITY_TOO_LONG` 并设置 `CERT_STATUS_VALIDITY_TOO_LONG`。
8. **测试已知根 CA 签发的证书:**  测试由已知根 CA 签发的证书是否会被标记为 `is_issued_by_known_root = true`。
9. **测试返回证书链的公钥哈希:**  测试验证成功后，`CertVerifyResult::public_key_hashes` 是否包含了证书链中所有证书的 SHA256 哈希值。
10. **测试返回验证后的证书链:**  测试验证成功后，`CertVerifyResult::verified_cert` 是否返回了验证后的证书链。
11. **测试拒绝由公共 CA 签发的内网主机证书:** 测试对于由已知公共 CA 签发的、用于内网主机的证书，是否会标记 `CERT_STATUS_NON_UNIQUE_NAME` （在 Cronet 构建中可能不会报错以兼容测试）。
12. **测试拒绝赛门铁克遗留基础设施签发的证书:** 测试是否会根据策略拒绝赛门铁克遗留基础设施签发的证书，除非显式禁用该策略或证书链包含允许的中间证书。

**与 JavaScript 的关系:**

虽然这段 C++ 代码本身不包含 JavaScript，但它所测试的证书验证功能是浏览器安全性的核心组成部分，直接影响到 JavaScript 代码的运行环境。

* **HTTPS 连接:** 当 JavaScript 代码尝试通过 `https://` 发起网络请求时，浏览器会使用 `CertVerifyProc` 来验证服务器提供的 SSL/TLS 证书。如果验证失败，浏览器会阻止 JavaScript 代码的请求，防止潜在的安全风险。
* **WebSockets over TLS (WSS):**  与 HTTPS 类似，当 JavaScript 使用 WSS 协议建立安全 WebSocket 连接时，也需要进行证书验证。
* **Fetch API 和 XMLHttpRequest:** 这些 JavaScript API 用于发起网络请求，底层依赖于浏览器的网络栈，其中就包括证书验证。
* **Service Workers:**  Service Workers 可以在后台拦截和处理网络请求，它们同样依赖于底层的证书验证机制来确保安全性。

**举例说明:**

**场景:** 用户访问一个使用了过期证书的网站 `https://expired.example.com`。

**假设输入:**

* `cert`:  一个表示 `expired.example.com` 服务器证书的 `X509Certificate` 对象，该证书的有效期已过。
* `hostname`:  字符串 "expired.example.com"。
* `flags`:  证书验证标志，可能为 0。

**预期输出:**

* `error`:  `ERR_CERT_DATE_INVALID`  (-202)。
* `verify_result.cert_status`:  包含 `CERT_STATUS_DATE_INVALID` 标志。

**用户或编程常见的使用错误:**

1. **服务器配置了过期的 SSL/TLS 证书:**  这是最常见的情况，用户访问网站时会触发证书验证，如果证书过期，浏览器会阻止访问并显示错误。
2. **中间证书缺失:**  如果服务器没有正确配置发送完整的证书链，导致浏览器无法构建到信任根的完整路径，会导致验证失败。
3. **使用了自签名证书但未被用户信任:**  自签名证书默认不被浏览器信任，需要用户手动添加例外或安装到信任存储区。
4. **名称不匹配:**  证书上的域名与用户访问的域名不一致，例如访问 `https://www.example.net` 但证书是为 `www.example.com` 颁发的。
5. **使用了不安全的加密算法或密钥长度:**  随着安全标准的提高，一些旧的或弱的加密算法和密钥长度不再被认为是安全的，浏览器可能会拒绝使用这些证书。
6. **未启用 OCSP Stapling 或 CRL 支持:**  虽然不是直接的验证错误，但缺乏这些机制可能会导致浏览器在某些情况下无法及时获取证书的吊销状态。

**用户操作到达此处的调试线索:**

1. **用户在浏览器地址栏输入 `https://expired.example.com` 并回车。**
2. **浏览器开始与 `expired.example.com` 服务器建立 TLS 连接。**
3. **服务器发送其 SSL/TLS 证书给浏览器。**
4. **浏览器的网络栈中的 `CertVerifyProc` 组件被调用，开始验证接收到的证书。**
5. **`CertVerifyProcInternalTest.RejectExpiredCert` 测试模拟了这种情况，并断言验证结果为 `ERR_CERT_DATE_INVALID`。**

**总结（作为第 2 部分）：**

作为单元测试的一部分，本代码段主要负责详尽地测试 Chromium 网络栈中 `CertVerifyProc` 类的证书验证逻辑。它涵盖了证书有效性、密钥强度、证书链构建、吊销检查、名称约束以及签名算法等多个关键方面的测试用例，旨在确保在各种复杂场景下证书验证的正确性和安全性。这些测试对于保障用户浏览安全至关重要，因为它们直接验证了浏览器拒绝无效或不安全证书的能力，从而保护用户免受潜在的网络攻击。

### 提示词
```
这是目录为net/cert/cert_verify_proc_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
nFromFile(
      certs_dir, "expired_cert.pem", X509Certificate::FORMAT_AUTO);
  ASSERT_TRUE(cert);
  ASSERT_EQ(0U, cert->intermediate_buffers().size());

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(cert.get(), "127.0.0.1", flags, &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_DATE_INVALID));
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_DATE_INVALID);
}

TEST_P(CertVerifyProcInternalTest, RejectWeakKeys) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  typedef std::vector<std::string> Strings;
  Strings key_types;

  // These values mush match the prefixes of the key filenames generated by
  // generate-test-keys.sh:
  key_types.push_back("rsa-768");
  key_types.push_back("rsa-1024");
  key_types.push_back("rsa-2048");
  key_types.push_back("ec-prime256v1");

  // Now test each chain.
  for (const std::string& ee_type : key_types) {
    for (const std::string& signer_type : key_types) {
      SCOPED_TRACE("ee_type:" + ee_type + " signer_type:" + signer_type);

      auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

      ASSERT_TRUE(
          leaf->UseKeyFromFile(certs_dir.AppendASCII(ee_type + "-1.key")));
      ASSERT_TRUE(intermediate->UseKeyFromFile(
          certs_dir.AppendASCII(signer_type + "-2.key")));

      ScopedTestRoot scoped_root(root->GetX509Certificate());

      CertVerifyResult verify_result;
      int error = Verify(leaf->GetX509CertificateChain().get(),
                         "www.example.com", 0, &verify_result);

      if (IsInvalidKeyType(ee_type) || IsInvalidKeyType(signer_type)) {
        EXPECT_NE(OK, error);
        EXPECT_EQ(CERT_STATUS_INVALID,
                  verify_result.cert_status & CERT_STATUS_INVALID);
      } else if (IsWeakKeyType(ee_type) || IsWeakKeyType(signer_type)) {
        EXPECT_NE(OK, error);
        EXPECT_EQ(CERT_STATUS_WEAK_KEY,
                  verify_result.cert_status & CERT_STATUS_WEAK_KEY);
        EXPECT_EQ(0u, verify_result.cert_status & CERT_STATUS_INVALID);
      } else {
        EXPECT_THAT(error, IsOk());
        EXPECT_EQ(0U, verify_result.cert_status & CERT_STATUS_WEAK_KEY);
      }
    }
  }
}

// Regression test for http://crbug.com/108514.
// Generates a chain with a root with a SHA256 signature, and another root with
// the same name/SPKI/keyid but with a SHA1 signature. The SHA256 root is
// trusted. The SHA1 certificate is supplied as an extra cert, but should be
// ignored as the verifier should prefer the trusted cert when path building
// from the leaf, generating the shortest chain of "leaf -> sha256root". If the
// path builder doesn't prioritize it could build an unoptimal but valid path
// like "leaf -> sha1root -> sha256root".
TEST_P(CertVerifyProcInternalTest, ExtraneousRootCert) {
  auto [leaf_builder, root_builder] = CertBuilder::CreateSimpleChain2();

  root_builder->SetSignatureAlgorithm(bssl::SignatureAlgorithm::kEcdsaSha256);
  scoped_refptr<X509Certificate> root_cert = root_builder->GetX509Certificate();

  scoped_refptr<X509Certificate> server_cert =
      leaf_builder->GetX509Certificate();

  // Use the same root_builder but with a new serial number and setting the
  // signature to SHA1, to generate an extraneous self-signed certificate that
  // also signs the leaf cert and which could be used in path-building if the
  // path builder doesn't prioritize trusted roots above other certs.
  root_builder->SetRandomSerialNumber();
  root_builder->SetSignatureAlgorithm(bssl::SignatureAlgorithm::kEcdsaSha1);
  scoped_refptr<X509Certificate> extra_cert =
      root_builder->GetX509Certificate();

  ScopedTestRoot scoped_root(root_cert);

  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
  intermediates.push_back(bssl::UpRef(extra_cert->cert_buffer()));
  scoped_refptr<X509Certificate> cert_chain = X509Certificate::CreateFromBuffer(
      bssl::UpRef(server_cert->cert_buffer()), std::move(intermediates));
  ASSERT_TRUE(cert_chain);

  CertVerifyResult verify_result;
  int flags = 0;
  int error =
      Verify(cert_chain.get(), "www.example.com", flags, &verify_result);
  EXPECT_THAT(error, IsOk());

  // The extra root should be discarded.
  ASSERT_TRUE(verify_result.verified_cert.get());
  ASSERT_EQ(1u, verify_result.verified_cert->intermediate_buffers().size());
  EXPECT_TRUE(x509_util::CryptoBufferEqual(
      verify_result.verified_cert->intermediate_buffers().front().get(),
      root_cert->cert_buffer()));
}

// Test for bug 94673.
TEST_P(CertVerifyProcInternalTest, GoogleDigiNotarTest) {
  base::FilePath certs_dir = GetTestCertsDirectory();

  scoped_refptr<X509Certificate> server_cert =
      ImportCertFromFile(certs_dir, "google_diginotar.pem");
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), server_cert.get());

  scoped_refptr<X509Certificate> intermediate_cert =
      ImportCertFromFile(certs_dir, "diginotar_public_ca_2025.pem");
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), intermediate_cert.get());

  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
  intermediates.push_back(bssl::UpRef(intermediate_cert->cert_buffer()));
  scoped_refptr<X509Certificate> cert_chain = X509Certificate::CreateFromBuffer(
      bssl::UpRef(server_cert->cert_buffer()), std::move(intermediates));
  ASSERT_TRUE(cert_chain);

  CertVerifyResult verify_result;
  int flags = CertVerifyProc::VERIFY_REV_CHECKING_ENABLED;
  int error =
      Verify(cert_chain.get(), "mail.google.com", flags, &verify_result);
  EXPECT_NE(OK, error);

  // Now turn off revocation checking.  Certificate verification should still
  // fail.
  flags = 0;
  error = Verify(cert_chain.get(), "mail.google.com", flags, &verify_result);
  EXPECT_NE(OK, error);
}

TEST_P(CertVerifyProcInternalTest, NameConstraintsOk) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();

  // Use the private key matching the public_key_hash of the kDomainsTest
  // constraint in CertVerifyProc::HasNameConstraintsViolation.
  ASSERT_TRUE(leaf->UseKeyFromFile(
      GetTestCertsDirectory().AppendASCII("name_constrained_key.pem")));
  // example.com is allowed by kDomainsTest, and notarealtld is not a known
  // TLD, so that's allowed too.
  leaf->SetSubjectAltNames({"test.ExAmPlE.CoM", "example.notarealtld",
                            "*.test2.ExAmPlE.CoM", "*.example2.notarealtld"},
                           {});

  ScopedTestRoot test_root(root->GetX509Certificate());

  scoped_refptr<X509Certificate> leaf_cert = leaf->GetX509Certificate();

  int flags = 0;
  CertVerifyResult verify_result;
  int error =
      Verify(leaf_cert.get(), "test.example.com", flags, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);

  error =
      Verify(leaf_cert.get(), "foo.test2.example.com", flags, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);
}

TEST_P(CertVerifyProcInternalTest, NameConstraintsFailure) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();

  // Use the private key matching the public_key_hash of the kDomainsTest
  // constraint in CertVerifyProc::HasNameConstraintsViolation.
  ASSERT_TRUE(leaf->UseKeyFromFile(
      GetTestCertsDirectory().AppendASCII("name_constrained_key.pem")));
  // example.com is allowed by kDomainsTest, but example.org is not.
  leaf->SetSubjectAltNames({"test.ExAmPlE.CoM", "test.ExAmPlE.OrG"}, {});

  ScopedTestRoot test_root(root->GetX509Certificate());

  scoped_refptr<X509Certificate> leaf_cert = leaf->GetX509Certificate();

  int flags = 0;
  CertVerifyResult verify_result;
  int error =
      Verify(leaf_cert.get(), "test.example.com", flags, &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_NAME_CONSTRAINT_VIOLATION));
  EXPECT_EQ(CERT_STATUS_NAME_CONSTRAINT_VIOLATION,
            verify_result.cert_status & CERT_STATUS_NAME_CONSTRAINT_VIOLATION);
}

// This fixture is for testing the verification of a certificate chain which
// has some sort of mismatched signature algorithm (i.e.
// Certificate.signatureAlgorithm and TBSCertificate.algorithm are different).
class CertVerifyProcInspectSignatureAlgorithmsTest : public ::testing::Test {
 protected:
  // In the test setup, SHA384 is given special treatment as an unknown
  // algorithm.
  static constexpr bssl::DigestAlgorithm kUnknownDigestAlgorithm =
      bssl::DigestAlgorithm::Sha384;

  struct CertParams {
    // Certificate.signatureAlgorithm
    bssl::DigestAlgorithm cert_algorithm;

    // TBSCertificate.algorithm
    bssl::DigestAlgorithm tbs_algorithm;
  };

  // Shorthand for VerifyChain() where only the leaf's parameters need
  // to be specified.
  [[nodiscard]] int VerifyLeaf(const CertParams& leaf_params) {
    return VerifyChain(
        {// Target
         leaf_params,
         // Root
         {bssl::DigestAlgorithm::Sha256, bssl::DigestAlgorithm::Sha256}});
  }

  // Shorthand for VerifyChain() where only the intermediate's parameters need
  // to be specified.
  [[nodiscard]] int VerifyIntermediate(const CertParams& intermediate_params) {
    return VerifyChain(
        {// Target
         {bssl::DigestAlgorithm::Sha256, bssl::DigestAlgorithm::Sha256},
         // Intermediate
         intermediate_params,
         // Root
         {bssl::DigestAlgorithm::Sha256, bssl::DigestAlgorithm::Sha256}});
  }

  // Shorthand for VerifyChain() where only the root's parameters need to be
  // specified.
  [[nodiscard]] int VerifyRoot(const CertParams& root_params) {
    return VerifyChain(
        {// Target
         {bssl::DigestAlgorithm::Sha256, bssl::DigestAlgorithm::Sha256},
         // Intermediate
         {bssl::DigestAlgorithm::Sha256, bssl::DigestAlgorithm::Sha256},
         // Root
         root_params});
  }

  // Manufactures a certificate chain where each certificate has the indicated
  // signature algorithms, and then returns the result of verifying this chain.
  [[nodiscard]] int VerifyChain(const std::vector<CertParams>& chain_params) {
    // Manufacture a chain with the given combinations of signature algorithms.
    // This chain isn't actually a valid chain, but it is good enough for
    // testing the base CertVerifyProc.
    std::vector<std::unique_ptr<CertBuilder>> builders =
        CertBuilder::CreateSimpleChain(chain_params.size());
    for (size_t i = 0; i < chain_params.size(); i++) {
      builders[i]->SetOuterSignatureAlgorithmTLV(base::as_string_view(
          GetAlgorithmSequence(chain_params[i].cert_algorithm)));
      builders[i]->SetTBSSignatureAlgorithmTLV(base::as_string_view(
          GetAlgorithmSequence(chain_params[i].tbs_algorithm)));
    }

    scoped_refptr<X509Certificate> chain =
        builders.front()->GetX509CertificateFullChain();
    if (!chain) {
      ADD_FAILURE() << "Failed creating certificate chain";
      return ERR_UNEXPECTED;
    }

    int flags = 0;
    CertVerifyResult dummy_result;
    CertVerifyResult verify_result;

    auto verify_proc = base::MakeRefCounted<MockCertVerifyProc>(dummy_result);

    return verify_proc->Verify(
        chain.get(), "www.example.com", /*ocsp_response=*/std::string(),
        /*sct_list=*/std::string(), flags, &verify_result, NetLogWithSource());
  }

 private:
  static base::span<const uint8_t> GetAlgorithmSequence(
      bssl::DigestAlgorithm algorithm) {
    switch (algorithm) {
      case bssl::DigestAlgorithm::Sha1:
        static const uint8_t kSha1WithRSAEncryption[] = {
            0x30, 0x0D, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00};
        return kSha1WithRSAEncryption;
      case bssl::DigestAlgorithm::Sha256:
        static const uint8_t kSha256WithRSAEncryption[] = {
            0x30, 0x0D, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00};
        return kSha256WithRSAEncryption;
      case kUnknownDigestAlgorithm:
        static const uint8_t kUnknownAlgorithm[] = {
            0x30, 0x0D, 0x06, 0x09, 0x8a, 0x87, 0x18, 0x46,
            0xd7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00};
        return kUnknownAlgorithm;
      default:
        NOTREACHED() << "Unsupported digest algorithm";
    }
  }
};

// This is a control test to make sure that the test helper
// VerifyLeaf() works as expected. There is no actual mismatch in the
// algorithms used here.
//
//  Certificate.signatureAlgorithm:  sha1WithRSASignature
//  TBSCertificate.algorithm:        sha1WithRSAEncryption
TEST_F(CertVerifyProcInspectSignatureAlgorithmsTest, LeafSha1Sha1) {
  int rv =
      VerifyLeaf({bssl::DigestAlgorithm::Sha1, bssl::DigestAlgorithm::Sha1});
  ASSERT_THAT(rv, IsError(ERR_CERT_WEAK_SIGNATURE_ALGORITHM));
}

// This is a control test to make sure that the test helper
// VerifyLeaf() works as expected. There is no actual mismatch in the
// algorithms used here.
//
//  Certificate.signatureAlgorithm:  sha256WithRSASignature
//  TBSCertificate.algorithm:        sha256WithRSAEncryption
TEST_F(CertVerifyProcInspectSignatureAlgorithmsTest, LeafSha256Sha256) {
  int rv = VerifyLeaf(
      {bssl::DigestAlgorithm::Sha256, bssl::DigestAlgorithm::Sha256});
  ASSERT_THAT(rv, IsOk());
}

// Mismatched signature algorithms in the leaf certificate.
//
//  Certificate.signatureAlgorithm:  sha1WithRSASignature
//  TBSCertificate.algorithm:        sha256WithRSAEncryption
TEST_F(CertVerifyProcInspectSignatureAlgorithmsTest, LeafSha1Sha256) {
  int rv =
      VerifyLeaf({bssl::DigestAlgorithm::Sha1, bssl::DigestAlgorithm::Sha256});
  ASSERT_THAT(rv, IsError(ERR_CERT_INVALID));
}

// Mismatched signature algorithms in the leaf certificate.
//
//  Certificate.signatureAlgorithm:  sha256WithRSAEncryption
//  TBSCertificate.algorithm:        sha1WithRSASignature
TEST_F(CertVerifyProcInspectSignatureAlgorithmsTest, LeafSha256Sha1) {
  int rv =
      VerifyLeaf({bssl::DigestAlgorithm::Sha256, bssl::DigestAlgorithm::Sha1});
  ASSERT_THAT(rv, IsError(ERR_CERT_INVALID));
}

// Unrecognized signature algorithm in the leaf certificate.
//
//  Certificate.signatureAlgorithm:  sha256WithRSAEncryption
//  TBSCertificate.algorithm:        ?
TEST_F(CertVerifyProcInspectSignatureAlgorithmsTest, LeafSha256Unknown) {
  int rv = VerifyLeaf({bssl::DigestAlgorithm::Sha256, kUnknownDigestAlgorithm});
  ASSERT_THAT(rv, IsError(ERR_CERT_INVALID));
}

// Unrecognized signature algorithm in the leaf certificate.
//
//  Certificate.signatureAlgorithm:  ?
//  TBSCertificate.algorithm:        sha256WithRSAEncryption
TEST_F(CertVerifyProcInspectSignatureAlgorithmsTest, LeafUnknownSha256) {
  int rv = VerifyLeaf({kUnknownDigestAlgorithm, bssl::DigestAlgorithm::Sha256});
  ASSERT_THAT(rv, IsError(ERR_CERT_INVALID));
}

// Mismatched signature algorithms in the intermediate certificate.
//
//  Certificate.signatureAlgorithm:  sha1WithRSASignature
//  TBSCertificate.algorithm:        sha256WithRSAEncryption
TEST_F(CertVerifyProcInspectSignatureAlgorithmsTest, IntermediateSha1Sha256) {
  int rv = VerifyIntermediate(
      {bssl::DigestAlgorithm::Sha1, bssl::DigestAlgorithm::Sha256});
  ASSERT_THAT(rv, IsError(ERR_CERT_INVALID));
}

// Mismatched signature algorithms in the intermediate certificate.
//
//  Certificate.signatureAlgorithm:  sha256WithRSAEncryption
//  TBSCertificate.algorithm:        sha1WithRSASignature
TEST_F(CertVerifyProcInspectSignatureAlgorithmsTest, IntermediateSha256Sha1) {
  int rv = VerifyIntermediate(
      {bssl::DigestAlgorithm::Sha256, bssl::DigestAlgorithm::Sha1});
  ASSERT_THAT(rv, IsError(ERR_CERT_INVALID));
}

// Mismatched signature algorithms in the root certificate.
//
//  Certificate.signatureAlgorithm:  sha256WithRSAEncryption
//  TBSCertificate.algorithm:        sha1WithRSASignature
TEST_F(CertVerifyProcInspectSignatureAlgorithmsTest, RootSha256Sha1) {
  int rv =
      VerifyRoot({bssl::DigestAlgorithm::Sha256, bssl::DigestAlgorithm::Sha1});
  ASSERT_THAT(rv, IsOk());
}

// Unrecognized signature algorithm in the root certificate.
//
//  Certificate.signatureAlgorithm:  ?
//  TBSCertificate.algorithm:        sha256WithRSAEncryption
TEST_F(CertVerifyProcInspectSignatureAlgorithmsTest, RootUnknownSha256) {
  int rv = VerifyRoot({kUnknownDigestAlgorithm, bssl::DigestAlgorithm::Sha256});
  ASSERT_THAT(rv, IsOk());
}

TEST(CertVerifyProcTest, TestHasTooLongValidity) {
  struct {
    const char* const test_name;
    base::Time not_before;
    base::TimeDelta validity;
    bool is_valid_too_long;
  } tests[] = {
      {"start after expiry", base::Time::Now(), -base::Days(1), true},
      {"399 days, before BRs",
       base::Time::FromMillisecondsSinceUnixEpoch(1199145600000),  // 2008-01-01
       base::Days(399), true},
      {"399 days, before 2020-09-01",
       base::Time::FromMillisecondsSinceUnixEpoch(1598832000000),  // 2020-08-31
       base::Days(399), true},
      {"398 days, after 2020-09-01",
       base::Time::FromMillisecondsSinceUnixEpoch(1599004800000),  // 2020-09-02
       base::Days(398), false},
      {"399 days, after 2020-09-01",
       base::Time::FromMillisecondsSinceUnixEpoch(1599004800000),  // 2020-09-02
       base::Days(399), true},
      {"398 days 1 second, after 2020-09-01",
       base::Time::FromMillisecondsSinceUnixEpoch(1599004800000),  // 2020-09-02
       base::Days(398) + base::Seconds(1), true},
  };

  auto [leaf, root] = CertBuilder::CreateSimpleChain2();
  for (const auto& test : tests) {
    SCOPED_TRACE(test.test_name);

    leaf->SetValidity(test.not_before, test.not_before + test.validity);
    EXPECT_EQ(test.is_valid_too_long,
              CertVerifyProc::HasTooLongValidity(*leaf->GetX509Certificate()));
  }
}

// Integration test for CertVerifyProc::HasTooLongValidity.
// HasTooLongValidity is checked by the outer CertVerifyProc::Verify. Thus the
// test can mock the VerifyInternal result to pretend there was a successful
// verification with is_issued_by_known_root and see that Verify overrides that
// with error.
// TODO(mattm): consider if there would be any benefit to using
// ScopedTestKnownRoot and testing with the real CertVerifyProc subclasses?
TEST(CertVerifyProcTest, VerifyCertValidityTooLong) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();
  base::Time not_before = base::Time::Now() - base::Days(1);
  leaf->SetValidity(not_before, not_before + base::Days(399));

  {
    // Locally trusted cert should be ok.
    CertVerifyResult dummy_result;
    dummy_result.is_issued_by_known_root = false;
    auto verify_proc = base::MakeRefCounted<MockCertVerifyProc>(dummy_result);
    CertVerifyResult verify_result;
    int error = verify_proc->Verify(
        leaf->GetX509Certificate().get(), "www.example.com",
        /*ocsp_response=*/std::string(),
        /*sct_list=*/std::string(), 0, &verify_result, NetLogWithSource());
    EXPECT_THAT(error, IsOk());
    EXPECT_EQ(0u, verify_result.cert_status & CERT_STATUS_ALL_ERRORS);
  }

  {
    // Publicly trusted cert that was otherwise okay should get changed to
    // ERR_CERT_VALIDITY_TOO_LONG.
    CertVerifyResult dummy_result;
    dummy_result.is_issued_by_known_root = true;
    auto verify_proc = base::MakeRefCounted<MockCertVerifyProc>(dummy_result);
    CertVerifyResult verify_result;
    int error = verify_proc->Verify(
        leaf->GetX509Certificate().get(), "www.example.com",
        /*ocsp_response=*/std::string(),
        /*sct_list=*/std::string(), 0, &verify_result, NetLogWithSource());
    EXPECT_THAT(error, IsError(ERR_CERT_VALIDITY_TOO_LONG));
    EXPECT_EQ(CERT_STATUS_VALIDITY_TOO_LONG,
              verify_result.cert_status & CERT_STATUS_ALL_ERRORS);
  }

  {
    // Publicly trusted cert that had some other error should retain the
    // original error, but CERT_STATUS_VALIDITY_TOO_LONG should be added to
    // cert_status.
    CertVerifyResult dummy_result;
    dummy_result.is_issued_by_known_root = true;
    dummy_result.cert_status = CERT_STATUS_AUTHORITY_INVALID;
    auto verify_proc = base::MakeRefCounted<MockCertVerifyProc>(
        dummy_result, ERR_CERT_AUTHORITY_INVALID);
    CertVerifyResult verify_result;
    int error = verify_proc->Verify(
        leaf->GetX509Certificate().get(), "www.example.com",
        /*ocsp_response=*/std::string(),
        /*sct_list=*/std::string(), 0, &verify_result, NetLogWithSource());
    EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
    EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID | CERT_STATUS_VALIDITY_TOO_LONG,
              verify_result.cert_status & CERT_STATUS_ALL_ERRORS);
  }
}

TEST_P(CertVerifyProcInternalTest, TestKnownRoot) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<X509Certificate> cert_chain = CreateCertificateChainFromFile(
      certs_dir, "leaf_from_known_root.pem", X509Certificate::FORMAT_AUTO);
  ASSERT_TRUE(cert_chain);

  int flags = 0;
  CertVerifyResult verify_result;
  int error =
      Verify(cert_chain.get(), "timberfirepizza.com", flags, &verify_result);
  EXPECT_THAT(error, IsOk())
      << "This test relies on a real certificate that "
      << "expires on Nov 09 2025. If failing on/after "
      << "that date, please disable and file a bug "
      << "against mattm. Current time: " << base::Time::Now();
  EXPECT_TRUE(verify_result.is_issued_by_known_root);
}

// This tests that on successful certificate verification,
// CertVerifyResult::public_key_hashes is filled with a SHA256 hash for each
// of the certificates in the chain.
TEST_P(CertVerifyProcInternalTest, PublicKeyHashes) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  CertificateList certs = CreateCertificateListFromFile(
      certs_dir, "x509_verify_results.chain.pem", X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(3U, certs.size());

  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
  intermediates.push_back(bssl::UpRef(certs[1]->cert_buffer()));
  intermediates.push_back(bssl::UpRef(certs[2]->cert_buffer()));

  ScopedTestRoot scoped_root(certs[2]);
  scoped_refptr<X509Certificate> cert_chain = X509Certificate::CreateFromBuffer(
      bssl::UpRef(certs[0]->cert_buffer()), std::move(intermediates));
  ASSERT_TRUE(cert_chain);
  ASSERT_EQ(2U, cert_chain->intermediate_buffers().size());

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(cert_chain.get(), "127.0.0.1", flags, &verify_result);
  EXPECT_THAT(error, IsOk());

  EXPECT_EQ(3u, verify_result.public_key_hashes.size());

  // Convert |public_key_hashes| to strings for ease of comparison.
  std::vector<std::string> public_key_hash_strings;
  for (const auto& public_key_hash : verify_result.public_key_hashes)
    public_key_hash_strings.push_back(public_key_hash.ToString());

  std::vector<std::string> expected_public_key_hashes = {
      // Target
      "sha256/Ru/08Ru275Zlf42sbI6lqi2OUun3r4YgrrK/vJ3+Yzk=",

      // Intermediate
      "sha256/D9u0epgvPYlG9YiVp7V+IMT+xhUpB5BhsS/INjDXc4Y=",

      // Trust anchor
      "sha256/VypP3VWL7OaqTJ7mIBehWYlv8khPuFHpWiearZI2YjI="};

  // |public_key_hashes| does not have an ordering guarantee.
  EXPECT_THAT(expected_public_key_hashes,
              testing::UnorderedElementsAreArray(public_key_hash_strings));
}

// Basic test for returning the chain in CertVerifyResult. Note that the
// returned chain may just be a reflection of the originally supplied chain;
// that is, if any errors occur, the default chain returned is an exact copy
// of the certificate to be verified. The remaining VerifyReturn* tests are
// used to ensure that the actual, verified chain is being returned by
// Verify().
TEST_P(CertVerifyProcInternalTest, VerifyReturnChainBasic) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  CertificateList certs = CreateCertificateListFromFile(
      certs_dir, "x509_verify_results.chain.pem", X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(3U, certs.size());

  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
  intermediates.push_back(bssl::UpRef(certs[1]->cert_buffer()));
  intermediates.push_back(bssl::UpRef(certs[2]->cert_buffer()));

  ScopedTestRoot scoped_root(certs[2]);

  scoped_refptr<X509Certificate> google_full_chain =
      X509Certificate::CreateFromBuffer(bssl::UpRef(certs[0]->cert_buffer()),
                                        std::move(intermediates));
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), google_full_chain.get());
  ASSERT_EQ(2U, google_full_chain->intermediate_buffers().size());

  CertVerifyResult verify_result;
  EXPECT_EQ(static_cast<X509Certificate*>(nullptr),
            verify_result.verified_cert.get());
  int error = Verify(google_full_chain.get(), "127.0.0.1", 0, &verify_result);
  EXPECT_THAT(error, IsOk());
  ASSERT_NE(static_cast<X509Certificate*>(nullptr),
            verify_result.verified_cert.get());

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

// Test that certificates issued for 'intranet' names (that is, containing no
// known public registry controlled domain information) issued by well-known
// CAs are flagged appropriately, while certificates that are issued by
// internal CAs are not flagged.
TEST(CertVerifyProcTest, IntranetHostsRejected) {
  const std::string kIntranetHostname = "webmail";

  auto [leaf, root] = CertBuilder::CreateSimpleChain2();
  leaf->SetSubjectAltName(kIntranetHostname);

  scoped_refptr<X509Certificate> cert(leaf->GetX509Certificate());

  CertVerifyResult verify_result;
  int error = 0;

  // Intranet names for public CAs should be flagged:
  CertVerifyResult dummy_result;
  dummy_result.is_issued_by_known_root = true;
  auto verify_proc = base::MakeRefCounted<MockCertVerifyProc>(dummy_result);
  error = verify_proc->Verify(cert.get(), kIntranetHostname,
                              /*ocsp_response=*/std::string(),
                              /*sct_list=*/std::string(), 0, &verify_result,
                              NetLogWithSource());
  // Intranet certificates from known roots are accepted without error in Cronet
  // to avoid breaking consumer tests. See b/337196170 (Google-internal).
#if BUILDFLAG(CRONET_BUILD)
  EXPECT_THAT(error, IsOk());
#else
  EXPECT_THAT(error, IsError(ERR_CERT_NON_UNIQUE_NAME));
#endif  // BUILDFLAG(CRONET_BUILD)
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_NON_UNIQUE_NAME);

  // However, if the CA is not well known, these should not be flagged:
  dummy_result.Reset();
  dummy_result.is_issued_by_known_root = false;
  verify_proc = base::MakeRefCounted<MockCertVerifyProc>(dummy_result);
  error = verify_proc->Verify(cert.get(), kIntranetHostname,
                              /*ocsp_response=*/std::string(),
                              /*sct_list=*/std::string(), 0, &verify_result,
                              NetLogWithSource());
  EXPECT_THAT(error, IsOk());
  EXPECT_FALSE(verify_result.cert_status & CERT_STATUS_NON_UNIQUE_NAME);
}

// Tests that certificates issued by Symantec's legacy infrastructure
// are rejected according to the policies outlined in
// https://security.googleblog.com/2017/09/chromes-plan-to-distrust-symantec.html
// unless the caller has explicitly disabled that enforcement.
TEST(CertVerifyProcTest, SymantecCertsRejected) {
  constexpr SHA256HashValue kSymantecHashValue = {
      {0xb2, 0xde, 0xf5, 0x36, 0x2a, 0xd3, 0xfa, 0xcd, 0x04, 0xbd, 0x29,
       0x04, 0x7a, 0x43, 0x84, 0x4f, 0x76, 0x70, 0x34, 0xea, 0x48, 0x92,
       0xf8, 0x0e, 0x56, 0xbe, 0xe6, 0x90, 0x24, 0x3e, 0x25, 0x02}};
  constexpr SHA256HashValue kGoogleHashValue = {
      {0xec, 0x72, 0x29, 0x69, 0xcb, 0x64, 0x20, 0x0a, 0xb6, 0x63, 0x8f,
       0x68, 0xac, 0x53, 0x8e, 0x40, 0xab, 0xab, 0x5b, 0x19, 0xa6, 0x48,
       0x56, 0x61, 0x04, 0x2a, 0x10, 0x61, 0xc4, 0x61, 0x27, 0x76}};

  auto [leaf, root] = CertBuilder::CreateSimpleChain2();

  static constexpr base::Time may_1_2016 = base::Time::FromTimeT(1462060800);
  leaf->SetValidity(may_1_2016, may_1_2016 + base::Days(1));
  scoped_refptr<X509Certificate> leaf_pre_june_2016 =
      leaf->GetX509Certificate();

  static constexpr base::Time june_1_2016 = base::Time::FromTimeT(1464739200);
  leaf->SetValidity(june_1_2016, june_1_2016 + base::Days(1));
  scoped_refptr<X509Certificate> leaf_post_june_2016 =
      leaf->GetX509Certificate();

  static constexpr base::Time dec_20_2017 = base::Time::FromTimeT(1513728000);
  leaf->SetValidity(dec_20_2017, dec_20_2017 + base::Days(1));
  scoped_refptr<X509Certificate> leaf_dec_2017 = leaf->GetX509Certificate();

  // Test that certificates from the legacy Symantec infrastructure are
  // rejected:
  // leaf_dec_2017: A certificate issued after 2017-12-01, which is rejected
  //                as of M65
  // leaf_pre_june_2016: A certificate issued prior to 2016-06-01, which is
  //                     rejected as of M66.
  for (X509Certificate* cert :
       {leaf_dec_2017.get(), leaf_pre_june_2016.get()}) {
    scoped_refptr<CertVerifyProc> verify_proc;
    int error = 0;

    // Test that a legacy Symantec certificate is rejected.
    CertVerifyResult symantec_result;
    symantec_result.verified_cert = cert;
    symantec_result.public_key_hashes.push_back(HashValue(kSymantecHashValue));
    symantec_result.is_issued_by_known_root = true;
    verify_proc = base::MakeRefCounted<MockCertVerifyProc>(symantec_result);

    CertVerifyResult test_result_1;
    error = verify_proc->Verify(
        cert, "www.example.com", /*ocsp_response=*/std::string(),
        /*sct_list=*/std::string(), 0, &test_result_1, NetLogWithSource());
    EXPECT_THAT(error, IsError(ERR_CERT_SYMANTEC_LEGACY));
    EXPECT_TRUE(test_result_1.cert_status & CERT_STATUS_SYMANTEC_LEGACY);

    // ... Unless the Symantec cert chains through a allowlisted intermediate.
    CertVerifyResult allowlisted_result;
    allowlisted_result.verified_cert = cert;
    allowlisted_result.public_key_hashes.push_back(
        HashValue(kSymantecHashValue));
    allowlisted_result.public_key_hashes.push_back(HashValue(kGoogleHashValue));
    allowlisted_result.is_issued_by_known_root = true;
    verify_proc = base::MakeRefCounted<MockCertVerifyProc>(allowlisted_result);

    CertVerifyResult test_result_2;
    error = verify_proc->Verify(
        cert, "www.example.com", /*ocsp_response=*/std::string(),
        /*sct_list=*/std::string(), 0, &test_result_2, NetLogWithSource());
    EXPECT_THAT(error, IsOk());
    EXPECT_FALSE(test_result_2.cert_status & CERT_STATUS_AUTHORITY_INVALID);

    // ... Or the caller disabled enforcement of Symantec policies.
    CertVerifyResult test_result_3;
    error = verify_proc->Verify(
        cert, "www.example.com", /*ocsp_response=*/std::string(),
        /*sct_list=*/std::string(),
        CertVerifyProc::VERIFY_DISABLE_SYMANTEC_ENFORCEMENT, &test_result_3,
        NetLogWithSource());
    EXPECT_THAT(error, IsOk());
    EXPECT_FALSE(test_result_3.cert_status & CERT_STATUS_SYMANTEC_LEGACY);
  }

  // Test that certificates from the legacy Symantec infrastructure issued
  // after 2016-06-01 appropriately rejected.
  scoped_refptr<X509Certificate> cert = leaf_post_june_2016;

  scoped_refptr<CertVerifyProc> verify_proc;
  int error = 0;

  // Test that a legacy Symantec certificate is rejected if the feature
  // flag is enabled, and accepted if it is not.
  CertVerifyResult symantec_result;
  symantec_result.verified_cert = cert;
  symantec_result.public_key_hashes.push_back(HashValue(kSymantecHashValue));
  symantec_result.is_issued_by_known_root = true;
  verify_proc = base::MakeRefCounted<MockCertVerifyProc>(symantec_result);

  CertVerifyResult test_result_1;
  error = verify_proc->Verify(cert.get(), "www.example.com",
                              /*ocsp_response=*/std::string(),
                              /*sct_list=*/std::string(), 0, &test_result_1,
                              NetLogWithSource());
  EXPECT_THAT(error, IsError(ERR_CERT_SYMANTEC_LEGACY));
  EXPECT_TRUE(test_result_1.cert_status & CERT_STATUS_SYMANTEC_LEGACY);

  // ... Unless the Symantec cert chains through a allowlisted intermediate.
  CertVerifyResult allowlisted_result;
  allowlisted_result.verified_cert = cert;
  allowlisted_result.public_key_hashes.push_back(HashValue(kSymantecHashValue));
  allowlisted_result.public_key_hashes.push_back(HashValue(kGoogleHashValue));
  allowlisted_result.is_issued_by_known_root = true;
  verify_proc = base::MakeRefCounted<MockCertVerifyProc>(allowliste
```