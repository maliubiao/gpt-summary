Response:
The user wants a summary of the functionalities of the provided C++ code snippet from `cert_verify_proc_unittest.cc`. I need to explain what this code does, especially concerning:
1. **Core Functionality:** What is being tested here?
2. **JavaScript Relation:**  Is there any connection to JavaScript?
3. **Logic and I/O:** Can I provide examples of input and expected output for specific test cases?
4. **Common Errors:** What mistakes might developers or users make related to this code?
5. **User Journey:** How might a user's actions lead to this code being executed?
6. **Overall Purpose:** What is the high-level goal of this part of the file?

This code appears to be a series of unit tests for the certificate verification process in Chromium's network stack. The tests focus on scenarios involving "trusted leaf" certificates and self-signed certificates, exploring how different certificate constraints are enforced.

**JavaScript Relation:**  Certificate verification is crucial for secure HTTPS connections, which are the backbone of the web and therefore heavily used by JavaScript in web browsers.

**Logic and I/O:** I can analyze specific `TEST_P` blocks and provide example inputs (certificate properties) and expected outputs (verification success or failure and specific error codes).

**Common Errors:**  Misconfiguring certificate properties, such as validity dates, key usages, or basic constraints, are potential errors.

**User Journey:**  A user browsing to a website using HTTPS triggers certificate verification. If the website's certificate has issues, these tests are simulating those scenarios to ensure the browser handles them correctly.

**Overall Purpose:** This section specifically tests how the certificate verification logic handles scenarios where a certificate is explicitly marked as trusted (either as a leaf or self-signed), and how various X.509 constraints are applied in these cases. It's about ensuring that even trusted certificates are validated according to the rules, and to identify differences in behavior between the built-in verifier and other platform verifiers.

Since this is part 7 of 8, the overall file likely tests various aspects of the `CertVerifyProc` class. This specific part seems to be focused on the nuances of trusted leaf and self-signed certificate validation.
这是 `net/cert/cert_verify_proc_unittest.cc` 文件的第七部分，它主要的功能是**测试 `CertVerifyProc` 类在处理被显式信任为叶子证书或自签名证书时，对各种证书约束的处理和验证行为。**  它关注的是当证书被标记为可信时，证书链验证过程如何以及是否会继续执行各种 X.509 证书标准的约束检查。

**具体功能列举：**

* **针对被信任的叶子证书的约束测试 (CertVerifyProcConstraintsTrustedLeafTest):**
    * 测试当叶子证书被显式信任时，各种证书约束（例如 `Basic Constraints`, `Name Constraints`, `Validity`, `Policy Constraints`, `Key Usage`, `Extended Key Usage`, `Signature Algorithm`, `Unknown Extension` 等）是否仍然会被检查，以及不同的验证器类型（内置 vs. 平台）的行为差异。
    * 测试根证书是否也被信任的情况，以及对叶子证书设置不同信任级别（例如，不指定信任、明确不信任）的影响。
* **针对被信任的自签名证书的约束测试 (CertVerifyProcConstraintsTrustedSelfSignedTest):**
    * 测试当自签名证书被显式信任时，各种证书约束是否仍然会被检查。
    * 特别关注自签名证书作为信任锚点时的约束检查行为。
* **测试对弱签名算法的处理 (RejectsPublicSHA1, RejectsPrivateSHA1UnlessFlag, CertVerifyProcWeakDigestTest):**
    * 测试 `CertVerifyProc` 如何处理使用弱哈希算法（例如 MD5, MD4, MD2, SHA-1）签名的证书，包括根证书、中间证书和叶子证书。
    * 区分公有根证书和私有根证书对 SHA-1 签名的处理策略。
* **测试证书名称验证 (CertVerifyProcNameTest):**
    * 测试 `CertVerifyProc` 如何根据 Subject Alternative Name (SAN) 和 Common Name (CN) 验证主机名。

**与 JavaScript 的功能关系：**

尽管这段 C++ 代码本身不直接包含 JavaScript，但它所测试的证书验证功能是 Web 安全的基础，与 JavaScript 在浏览器中的行为息息相关。

**举例说明：**

当 JavaScript 代码尝试通过 HTTPS 连接到服务器时，浏览器会使用 `CertVerifyProc` 来验证服务器提供的 SSL/TLS 证书。

* **假设输入 (JavaScript 触发 HTTPS 请求):** 用户在浏览器地址栏输入 `https://example.com`，或者 JavaScript 代码使用 `fetch` 或 `XMLHttpRequest` 发起对 `https://example.com` 的请求。
* **输出 (通过 `CertVerifyProc` 进行验证):**
    * 如果 `example.com` 的证书是自签名的，并且用户之前已经将其添加为信任的根证书（或作为受信任的叶子证书），那么相关的 `CertVerifyProcConstraintsTrustedSelfSignedTest` 或 `CertVerifyProcConstraintsTrustedLeafTest` 中的测试场景就会被覆盖。
    * 如果证书过期 (`ValidityExpired` 测试场景)，`CertVerifyProc` 会返回 `ERR_CERT_DATE_INVALID` 错误，浏览器会显示证书过期警告，JavaScript 代码可能会捕获到网络错误。
    * 如果证书使用了弱签名算法 (`WeakSignatureAlgorithm` 或 `CertVerifyProcWeakDigestTest` 测试场景)，`CertVerifyProc` 可能会返回 `ERR_CERT_WEAK_SIGNATURE_ALGORITHM` 或 `ERR_CERT_INVALID` 错误，浏览器会显示安全警告。

**逻辑推理的假设输入与输出：**

**示例 1 (CertVerifyProcConstraintsTrustedLeafTest, ValidityExpired):**

* **假设输入:**
    * 一个证书链，叶子证书被添加到信任列表中。
    * 叶子证书的有效期已经过期。
* **预期输出 (VerifyProcTypeIsBuiltin() 为 true):**
    * `Verify()` 返回 `ERR_CERT_AUTHORITY_INVALID` (因为即使叶子被信任，默认验证仍然会检查链的有效性)。
    * `VerifyAsTrustedLeaf()` 返回 `ERR_CERT_DATE_INVALID` (当作为可信叶子直接验证时，会检查其自身有效期)。

**示例 2 (CertVerifyProcConstraintsTrustedSelfSignedTest, BasicConstraintsIsCa):**

* **假设输入:**
    * 一个自签名证书被添加到信任列表中。
    * 该证书的 `Basic Constraints` 扩展中 `CA` 字段设置为 `true` (表示它可以签发其他证书)。
* **预期输出:**
    * `Verify()` 返回 `IsOk()` (自签名且被信任，可以作为自己的锚点)。
    * `VerifyAsTrustedSelfSignedLeaf()` 返回 `IsOk()` (作为可信自签名叶子验证通过)。

**涉及用户或编程常见的使用错误：**

* **用户错误：**
    * **添加过期的或有问题的自签名证书到信任列表：** 用户可能会忽略浏览器的安全警告，强行信任一个存在问题的证书，这会导致即使证书存在漏洞或过期，浏览器仍然认为它是可信的。
    * **误解信任模型：** 用户可能不理解将证书添加为信任根或信任叶子的区别，导致安全风险。
* **编程错误：**
    * **服务器配置错误的证书链：** 开发人员可能在服务器上配置了不完整或顺序错误的证书链，导致验证失败。
    * **使用过期的或弱签名的证书：** 开发人员可能没有及时更新证书或使用了不安全的签名算法。
    * **没有正确处理证书验证错误：** JavaScript 代码可能没有捕获到证书验证失败的错误，导致用户体验不佳或安全漏洞。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在浏览器中输入一个 HTTPS 网址或点击一个 HTTPS 链接。**
2. **浏览器向目标服务器发起 TLS 连接请求。**
3. **服务器将包含其证书的证书链发送给浏览器。**
4. **浏览器调用 `CertVerifyProc` 开始证书链验证过程。**
5. **如果服务器的证书被用户或系统显式信任为叶子证书或自签名证书，那么这段代码中测试的逻辑就会被触发。**
6. **在调试过程中，如果怀疑是证书验证的问题，可以设置断点在 `CertVerifyProc::Verify` 函数或者相关的测试用例中，例如 `CertVerifyProcConstraintsTrustedLeafTest` 或 `CertVerifyProcConstraintsTrustedSelfSignedTest`，来观察验证过程中的状态和错误信息。**
7. **查看 `EXPECT_THAT` 宏的输出可以帮助理解验证的预期结果和实际结果，从而定位问题。**

**归纳一下它的功能 (作为第 7 部分):**

作为整个 `net/cert/cert_verify_proc_unittest.cc` 文件的一部分，这第七部分专注于 **深入测试 `CertVerifyProc` 在处理被显式信任的证书（特别是叶子证书和自签名证书）时，对各种证书标准约束的执行情况。** 它旨在确保即使证书被标记为可信，其自身的属性和签名算法仍然会受到一定程度的检查，并验证不同平台证书验证器在这些场景下的行为一致性。此外，它还涵盖了对弱签名算法的检测和处理，以及基本的证书名称验证逻辑，进一步完善了对证书验证流程的测试覆盖。

Prompt: 
```
这是目录为net/cert/cert_verify_proc_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共8部分，请归纳一下它的功能

"""
n the rest of the tests in this class
  // are unlikely to be useful.
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_AUTHORITY_INVALID));
    EXPECT_THAT(VerifyAsTrustedLeaf(), IsOk());
    EXPECT_THAT(VerifyWithTrust(bssl::CertificateTrust::ForTrustAnchorOrLeaf()),
                IsOk());
    EXPECT_THAT(VerifyWithTrust(bssl::CertificateTrust::ForTrustedLeaf()
                                    .WithRequireLeafSelfSigned()),
                IsError(ERR_CERT_AUTHORITY_INVALID));
    EXPECT_THAT(VerifyWithTrust(bssl::CertificateTrust::ForTrustAnchorOrLeaf()
                                    .WithRequireLeafSelfSigned()),
                IsError(ERR_CERT_AUTHORITY_INVALID));
  } else {
    EXPECT_THAT(Verify(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTrustedLeafTest, RootAlsoTrusted) {
  // Test verifying a chain where both the leaf and the root are marked as
  // trusted.
  // (Repeating the ScopedTestRoot before each call is due to the limitation
  // with destroying any ScopedTestRoot removing all test roots.)
  {
    ScopedTestRoot test_root(chain_[1]->GetX509Certificate());
    EXPECT_THAT(Verify(), IsOk());
  }

  if (VerifyProcTypeIsBuiltin()) {
    {
      ScopedTestRoot test_root1(chain_[1]->GetX509Certificate());
      // An explicit trust entry for the leaf with a value of Unspecified
      // should be no different than the leaf not being in the trust store at
      // all.
      EXPECT_THAT(VerifyWithTrust(bssl::CertificateTrust::ForUnspecified()),
                  IsOk());
    }
    {
      ScopedTestRoot test_root1(chain_[1]->GetX509Certificate());
      // If the leaf is explicitly distrusted, verification should fail even if
      // the root is trusted.
      EXPECT_THAT(VerifyWithTrust(bssl::CertificateTrust::ForDistrusted()),
                  IsError(ERR_CERT_AUTHORITY_INVALID));
    }
    {
      ScopedTestRoot test_root(chain_[1]->GetX509Certificate());
      EXPECT_THAT(VerifyAsTrustedLeaf(), IsOk());
    }
    {
      ScopedTestRoot test_root(chain_[1]->GetX509Certificate());
      EXPECT_THAT(
          VerifyWithTrust(bssl::CertificateTrust::ForTrustAnchorOrLeaf()),
          IsOk());
    }
    {
      ScopedTestRoot test_root(chain_[1]->GetX509Certificate());
      EXPECT_THAT(
          VerifyWithTrust(bssl::CertificateTrust::ForTrustAnchorOrLeaf()),
          IsOk());
    }
    {
      ScopedTestRoot test_root(chain_[1]->GetX509Certificate());
      EXPECT_THAT(VerifyWithTrust(bssl::CertificateTrust::ForTrustAnchorOrLeaf()
                                      .WithRequireLeafSelfSigned()),
                  IsOk());
    }
  }
}

TEST_P(CertVerifyProcConstraintsTrustedLeafTest, BasicConstraintsIsCa) {
  for (bool has_key_usage_cert_sign : {false, true}) {
    chain_[0]->SetBasicConstraints(/*is_ca=*/true, /*path_len=*/-1);

    if (has_key_usage_cert_sign) {
      chain_[0]->SetKeyUsages({bssl::KEY_USAGE_BIT_KEY_CERT_SIGN,
                               bssl::KEY_USAGE_BIT_DIGITAL_SIGNATURE});
    } else {
      chain_[0]->SetKeyUsages({bssl::KEY_USAGE_BIT_DIGITAL_SIGNATURE});
    }

    if (VerifyProcTypeIsBuiltin()) {
      EXPECT_THAT(Verify(), IsError(ERR_CERT_AUTHORITY_INVALID));
      EXPECT_THAT(VerifyAsTrustedLeaf(), IsOk());
    } else {
      EXPECT_THAT(Verify(), IsOk());
    }
  }
}

TEST_P(CertVerifyProcConstraintsTrustedLeafTest, BasicConstraintsPathlen) {
  chain_[0]->SetBasicConstraints(/*is_ca=*/false, /*path_len=*/0);

  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_AUTHORITY_INVALID));
  } else {
    EXPECT_THAT(Verify(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTrustedLeafTest, BasicConstraintsMissing) {
  chain_[0]->EraseExtension(bssl::der::Input(bssl::kBasicConstraintsOid));

  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_AUTHORITY_INVALID));
    EXPECT_THAT(VerifyAsTrustedLeaf(), IsOk());
  } else {
    EXPECT_THAT(Verify(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTrustedLeafTest, NameConstraintsNotMatching) {
  chain_[0]->SetNameConstraintsDnsNames(/*permitted_dns_names=*/{"example.org"},
                                        /*excluded_dns_names=*/{});

  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_AUTHORITY_INVALID));
  } else {
    EXPECT_THAT(Verify(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTrustedLeafTest, ValidityExpired) {
  chain_[0]->SetValidity(base::Time::Now() - base::Days(14),
                         base::Time::Now() - base::Days(7));

  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_AUTHORITY_INVALID));
    EXPECT_THAT(VerifyAsTrustedLeaf(), IsError(ERR_CERT_DATE_INVALID));
  } else {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_DATE_INVALID));
  }
}

TEST_P(CertVerifyProcConstraintsTrustedLeafTest, PolicyConstraints) {
  static const char kPolicy1[] = "1.2.3.4";

  for (bool leaf_has_policy : {false, true}) {
    SCOPED_TRACE(leaf_has_policy);

    chain_[0]->SetPolicyConstraints(
        /*require_explicit_policy=*/0,
        /*inhibit_policy_mapping=*/std::nullopt);
    if (leaf_has_policy) {
      chain_[0]->SetCertificatePolicies({kPolicy1});
    } else {
      chain_[0]->SetCertificatePolicies({});
    }

    if (VerifyProcTypeIsBuiltin()) {
      EXPECT_THAT(Verify(), IsError(ERR_CERT_AUTHORITY_INVALID));
      EXPECT_THAT(VerifyAsTrustedLeaf(), IsOk());
    } else {
      // Succeeds since the ios/android verifiers appear to not enforce
      // this constraint in the "directly trusted leaf" case.
      EXPECT_THAT(Verify(), IsOk());
    }
  }
}

TEST_P(CertVerifyProcConstraintsTrustedLeafTest, InhibitAnyPolicy) {
  static const char kAnyPolicy[] = "2.5.29.32.0";
  chain_[0]->SetPolicyConstraints(
      /*require_explicit_policy=*/0,
      /*inhibit_policy_mapping=*/std::nullopt);
  chain_[0]->SetInhibitAnyPolicy(0);
  chain_[0]->SetCertificatePolicies({kAnyPolicy});

  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_AUTHORITY_INVALID));
    EXPECT_THAT(VerifyAsTrustedLeaf(), IsOk());
  } else {
    EXPECT_THAT(Verify(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTrustedLeafTest, KeyUsageNoDigitalSignature) {
  // This test is mostly uninteresting since keyUsage on the end-entity is only
  // checked at the TLS layer, not during cert verification.
  chain_[0]->SetKeyUsages({bssl::KEY_USAGE_BIT_CRL_SIGN});

  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_AUTHORITY_INVALID));
    EXPECT_THAT(VerifyAsTrustedLeaf(), IsOk());
  } else {
    EXPECT_THAT(Verify(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTrustedLeafTest, KeyUsageCertSignLeaf) {
  // Test a leaf that has keyUsage asserting keyCertSign with basicConstraints
  // CA=false, which is an error according to 5280 (4.2.1.3 and 4.2.1.9).
  chain_[0]->SetKeyUsages({bssl::KEY_USAGE_BIT_KEY_CERT_SIGN,
                           bssl::KEY_USAGE_BIT_DIGITAL_SIGNATURE});

  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_AUTHORITY_INVALID));
    EXPECT_THAT(VerifyAsTrustedLeaf(), IsOk());
  } else {
    EXPECT_THAT(Verify(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTrustedLeafTest, ExtendedKeyUsageNoServerAuth) {
  chain_[0]->SetExtendedKeyUsages({bssl::der::Input(bssl::kCodeSigning)});

  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_AUTHORITY_INVALID));
    EXPECT_THAT(VerifyAsTrustedLeaf(), IsError(ERR_CERT_INVALID));
  } else {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));
  }
}

TEST_P(CertVerifyProcConstraintsTrustedLeafTest, UnknownSignatureAlgorithm) {
  chain_[0]->SetSignatureAlgorithmTLV(TestOid0SignatureAlgorithmTLV());

  if (VerifyProcTypeIsBuiltin()) {
    // Since no chain is found, signature is not checked, fails with generic
    // error for untrusted chain.
    EXPECT_THAT(Verify(), IsError(ERR_CERT_AUTHORITY_INVALID));
    // Valid since signature on directly trusted leaf is not checked.
    EXPECT_THAT(VerifyAsTrustedLeaf(), IsOk());
  } else {
    EXPECT_THAT(Verify(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTrustedLeafTest, WeakSignatureAlgorithm) {
  chain_[0]->SetSignatureAlgorithm(bssl::SignatureAlgorithm::kEcdsaSha1);

  if (VerifyProcTypeIsBuiltin()) {
    // Since no chain is found, signature is not checked, fails with generic
    // error for untrusted chain.
    EXPECT_THAT(Verify(), IsError(ERR_CERT_AUTHORITY_INVALID));

    // Valid since signature on directly trusted leaf is not checked.
    EXPECT_THAT(VerifyAsTrustedLeaf(), IsOk());

    // Cert is not self-signed so directly trusted leaf with
    // require_leaf_selfsigned should fail.
    EXPECT_THAT(VerifyWithTrust(bssl::CertificateTrust::ForTrustedLeaf()
                                    .WithRequireLeafSelfSigned()),
                IsError(ERR_CERT_AUTHORITY_INVALID));
  } else if (verify_proc_type() == CERT_VERIFY_PROC_IOS) {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));
  } else {
    EXPECT_THAT(Verify(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTrustedLeafTest, UnknownExtension) {
  for (bool critical : {true, false}) {
    SCOPED_TRACE(critical);
    chain_[0]->SetExtension(TestOid0(), "hello world", critical);

    if (VerifyProcTypeIsBuiltin()) {
      EXPECT_THAT(Verify(), IsError(ERR_CERT_AUTHORITY_INVALID));
      if (critical) {
        EXPECT_THAT(VerifyAsTrustedLeaf(), IsError(ERR_CERT_INVALID));
      } else {
        EXPECT_THAT(VerifyAsTrustedLeaf(), IsOk());
      }
    } else {
      EXPECT_THAT(Verify(), IsOk());
    }
  }
}

// A set of tests that check how various constraints are enforced when they
// are applied to a directly trusted self-signed leaf certificate.
class CertVerifyProcConstraintsTrustedSelfSignedTest
    : public CertVerifyProcInternalTest {
 protected:
  void SetUp() override {
    CertVerifyProcInternalTest::SetUp();

    cert_ = std::move(CertBuilder::CreateSimpleChain(/*chain_length=*/1)[0]);
  }

  int VerifyWithTrust(bssl::CertificateTrust trust) {
    ScopedTestRoot test_root(cert_->GetX509Certificate(), trust);
    CertVerifyResult verify_result;
    int flags = 0;
    return CertVerifyProcInternalTest::Verify(cert_->GetX509Certificate().get(),
                                              "www.example.com", flags,
                                              &verify_result);
  }

  int Verify() {
    return VerifyWithTrust(bssl::CertificateTrust::ForTrustAnchor());
  }

  int VerifyAsTrustedSelfSignedLeaf() {
    return VerifyWithTrust(
        bssl::CertificateTrust::ForTrustedLeaf().WithRequireLeafSelfSigned());
  }

  std::unique_ptr<CertBuilder> cert_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         CertVerifyProcConstraintsTrustedSelfSignedTest,
                         testing::ValuesIn(kAllCertVerifiers),
                         VerifyProcTypeToName);

TEST_P(CertVerifyProcConstraintsTrustedSelfSignedTest, BaseCase) {
  // Without changing anything on the test cert, it should validate
  // successfully. If this is not true then the rest of the tests in this class
  // are unlikely to be useful.
  if (VerifyProcTypeIsBuiltin()) {
    // Should succeed when verified as a trusted leaf.
    EXPECT_THAT(VerifyAsTrustedSelfSignedLeaf(), IsOk());
    EXPECT_THAT(VerifyWithTrust(bssl::CertificateTrust::ForTrustedLeaf()),
                IsOk());
    EXPECT_THAT(VerifyWithTrust(bssl::CertificateTrust::ForTrustAnchorOrLeaf()),
                IsOk());

    // Should also be allowed by verifying as anchor for itself.
    EXPECT_THAT(Verify(), IsOk());

    // Should fail if verified as anchor of itself with constraints enabled,
    // enforcing the basicConstraints on the anchor will fail since the cert
    // has CA=false.
    EXPECT_THAT(VerifyWithTrust(bssl::CertificateTrust::ForTrustAnchor()
                                    .WithEnforceAnchorConstraints()),
                IsError(ERR_CERT_INVALID));

    // Should be allowed since it will be evaluated as a trusted leaf, so
    // anchor constraints being enabled doesn't matter.
    EXPECT_THAT(VerifyWithTrust(bssl::CertificateTrust::ForTrustAnchorOrLeaf()
                                    .WithEnforceAnchorConstraints()),
                IsOk());
  } else {
    EXPECT_THAT(Verify(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTrustedSelfSignedTest, BasicConstraintsIsCa) {
  for (bool has_key_usage_cert_sign : {false, true}) {
    cert_->SetBasicConstraints(/*is_ca=*/true, /*path_len=*/-1);

    if (has_key_usage_cert_sign) {
      cert_->SetKeyUsages({bssl::KEY_USAGE_BIT_KEY_CERT_SIGN,
                           bssl::KEY_USAGE_BIT_DIGITAL_SIGNATURE});
    } else {
      cert_->SetKeyUsages({bssl::KEY_USAGE_BIT_DIGITAL_SIGNATURE});
    }
    EXPECT_THAT(Verify(), IsOk());
    if (VerifyProcTypeIsBuiltin()) {
      EXPECT_THAT(VerifyAsTrustedSelfSignedLeaf(), IsOk());
    }
  }
}

TEST_P(CertVerifyProcConstraintsTrustedSelfSignedTest,
       BasicConstraintsNotCaPathlen) {
  cert_->SetBasicConstraints(/*is_ca=*/false, /*path_len=*/0);

  EXPECT_THAT(Verify(), IsOk());
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(VerifyAsTrustedSelfSignedLeaf(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTrustedSelfSignedTest,
       BasicConstraintsIsCaPathlen) {
  cert_->SetBasicConstraints(/*is_ca=*/true, /*path_len=*/0);

  EXPECT_THAT(Verify(), IsOk());
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(VerifyAsTrustedSelfSignedLeaf(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTrustedSelfSignedTest,
       BasicConstraintsMissing) {
  cert_->EraseExtension(bssl::der::Input(bssl::kBasicConstraintsOid));

  EXPECT_THAT(Verify(), IsOk());
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(VerifyAsTrustedSelfSignedLeaf(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTrustedSelfSignedTest,
       NameConstraintsNotMatching) {
  cert_->SetNameConstraintsDnsNames(/*permitted_dns_names=*/{"example.org"},
                                    /*excluded_dns_names=*/{});

  EXPECT_THAT(Verify(), IsOk());
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(VerifyAsTrustedSelfSignedLeaf(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTrustedSelfSignedTest, ValidityExpired) {
  cert_->SetValidity(base::Time::Now() - base::Days(14),
                     base::Time::Now() - base::Days(7));

  EXPECT_THAT(Verify(), IsError(ERR_CERT_DATE_INVALID));
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(VerifyAsTrustedSelfSignedLeaf(),
                IsError(ERR_CERT_DATE_INVALID));
  }
}

TEST_P(CertVerifyProcConstraintsTrustedSelfSignedTest, PolicyConstraints) {
  static const char kPolicy1[] = "1.2.3.4";

  for (bool leaf_has_policy : {false, true}) {
    SCOPED_TRACE(leaf_has_policy);

    cert_->SetPolicyConstraints(
        /*require_explicit_policy=*/0,
        /*inhibit_policy_mapping=*/std::nullopt);
    if (leaf_has_policy) {
      cert_->SetCertificatePolicies({kPolicy1});

      EXPECT_THAT(Verify(), IsOk());
    } else {
      cert_->SetCertificatePolicies({});

      if (VerifyProcTypeIsBuiltin()) {
        EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));
        EXPECT_THAT(VerifyAsTrustedSelfSignedLeaf(), IsOk());
      } else {
        EXPECT_THAT(Verify(), IsOk());
      }
    }
  }
}

TEST_P(CertVerifyProcConstraintsTrustedSelfSignedTest, InhibitAnyPolicy) {
  static const char kAnyPolicy[] = "2.5.29.32.0";
  cert_->SetPolicyConstraints(
      /*require_explicit_policy=*/0,
      /*inhibit_policy_mapping=*/std::nullopt);
  cert_->SetInhibitAnyPolicy(0);
  cert_->SetCertificatePolicies({kAnyPolicy});

  EXPECT_THAT(Verify(), IsOk());
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(VerifyAsTrustedSelfSignedLeaf(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTrustedSelfSignedTest,
       KeyUsageNoDigitalSignature) {
  // This test is mostly uninteresting since keyUsage on the end-entity is only
  // checked at the TLS layer, not during cert verification.
  cert_->SetKeyUsages({bssl::KEY_USAGE_BIT_CRL_SIGN});

  EXPECT_THAT(Verify(), IsOk());
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(VerifyAsTrustedSelfSignedLeaf(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTrustedSelfSignedTest, KeyUsageCertSignLeaf) {
  // Test a leaf that has keyUsage asserting keyCertSign with basicConstraints
  // CA=false, which is an error according to 5280 (4.2.1.3 and 4.2.1.9).
  cert_->SetKeyUsages({bssl::KEY_USAGE_BIT_KEY_CERT_SIGN,
                       bssl::KEY_USAGE_BIT_DIGITAL_SIGNATURE});

  EXPECT_THAT(Verify(), IsOk());
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(VerifyWithTrust(bssl::CertificateTrust::ForTrustAnchor()
                                    .WithEnforceAnchorConstraints()),
                IsError(ERR_CERT_INVALID));
    EXPECT_THAT(VerifyAsTrustedSelfSignedLeaf(), IsOk());
    EXPECT_THAT(VerifyWithTrust(bssl::CertificateTrust::ForTrustAnchorOrLeaf()
                                    .WithEnforceAnchorConstraints()
                                    .WithRequireLeafSelfSigned()),
                IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTrustedSelfSignedTest,
       ExtendedKeyUsageNoServerAuth) {
  cert_->SetExtendedKeyUsages({bssl::der::Input(bssl::kCodeSigning)});

  EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(VerifyAsTrustedSelfSignedLeaf(), IsError(ERR_CERT_INVALID));
  }
}

TEST_P(CertVerifyProcConstraintsTrustedSelfSignedTest,
       UnknownSignatureAlgorithm) {
  cert_->SetSignatureAlgorithmTLV(TestOid0SignatureAlgorithmTLV());
  if (VerifyProcTypeIsBuiltin()) {
    // Attempts to verify as anchor of itself, which fails when verifying the
    // signature.
    EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));

    // Signature not checked when verified as a directly trusted leaf without
    // require_leaf_selfsigned.
    EXPECT_THAT(VerifyWithTrust(bssl::CertificateTrust::ForTrustedLeaf()),
                IsOk());

    // PathBuilder override ignores require_leaf_selfsigned due to the
    // self-signed check returning false (due to the invalid signature
    // algorithm), thus this fails with AUTHORITY_INVALID due to failing to
    // find a chain to another root.
    EXPECT_THAT(VerifyAsTrustedSelfSignedLeaf(),
                IsError(ERR_CERT_AUTHORITY_INVALID));

    // PathBuilder override ignores require_leaf_selfsigned due to the invalid
    // signature algorithm, thus this tries to verify as anchor of itself,
    // which fails when verifying the signature.
    EXPECT_THAT(VerifyWithTrust(bssl::CertificateTrust::ForTrustAnchorOrLeaf()
                                    .WithRequireLeafSelfSigned()),
                IsError(ERR_CERT_INVALID));
  } else {
    EXPECT_THAT(Verify(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTrustedSelfSignedTest, WeakSignatureAlgorithm) {
  cert_->SetSignatureAlgorithm(bssl::SignatureAlgorithm::kEcdsaSha1);
  if (VerifyProcTypeIsBuiltin()) {
    // Attempts to verify as anchor of itself, which fails due to the weak
    // signature algorithm.
    EXPECT_THAT(Verify(), IsError(ERR_CERT_WEAK_SIGNATURE_ALGORITHM));

    // Signature not checked when verified as a directly trusted leaf without
    // require_leaf_selfsigned.
    EXPECT_THAT(VerifyWithTrust(bssl::CertificateTrust::ForTrustedLeaf()),
                IsOk());

    // require_leaf_selfsigned allows any supported signature algorithm when
    // doing the self-signed check, so this is okay.
    EXPECT_THAT(VerifyAsTrustedSelfSignedLeaf(), IsOk());
    EXPECT_THAT(VerifyWithTrust(bssl::CertificateTrust::ForTrustAnchorOrLeaf()
                                    .WithRequireLeafSelfSigned()),
                IsOk());
  } else {
    EXPECT_THAT(Verify(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTrustedSelfSignedTest, UnknownExtension) {
  for (bool critical : {true, false}) {
    SCOPED_TRACE(critical);
    cert_->SetExtension(TestOid0(), "hello world", critical);

    if (VerifyProcTypeIsBuiltin()) {
      if (critical) {
        EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));
        EXPECT_THAT(VerifyAsTrustedSelfSignedLeaf(), IsError(ERR_CERT_INVALID));
      } else {
        EXPECT_THAT(Verify(), IsOk());
        EXPECT_THAT(VerifyAsTrustedSelfSignedLeaf(), IsOk());
      }
    } else {
      EXPECT_THAT(Verify(), IsOk());
    }
  }
}

TEST(CertVerifyProcTest, RejectsPublicSHA1) {
  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem"));
  ASSERT_TRUE(cert);

  CertVerifyResult result;
  result.has_sha1 = true;
  result.is_issued_by_known_root = true;
  auto verify_proc = base::MakeRefCounted<MockCertVerifyProc>(result);

  int flags = 0;
  CertVerifyResult verify_result;
  int error = verify_proc->Verify(
      cert.get(), "127.0.0.1", /*ocsp_response=*/std::string(),
      /*sct_list=*/std::string(), flags, &verify_result, NetLogWithSource());
  EXPECT_THAT(error, IsError(ERR_CERT_WEAK_SIGNATURE_ALGORITHM));
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_WEAK_SIGNATURE_ALGORITHM);

  // VERIFY_ENABLE_SHA1_LOCAL_ANCHORS should not impact this.
  flags = CertVerifyProc::VERIFY_ENABLE_SHA1_LOCAL_ANCHORS;
  verify_result.Reset();
  error = verify_proc->Verify(
      cert.get(), "127.0.0.1", /*ocsp_response=*/std::string(),
      /*sct_list=*/std::string(), flags, &verify_result, NetLogWithSource());
  EXPECT_THAT(error, IsError(ERR_CERT_WEAK_SIGNATURE_ALGORITHM));
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_WEAK_SIGNATURE_ALGORITHM);
}

TEST(CertVerifyProcTest, RejectsPrivateSHA1UnlessFlag) {
  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem"));
  ASSERT_TRUE(cert);

  CertVerifyResult result;
  result.has_sha1 = true;
  result.is_issued_by_known_root = false;
  auto verify_proc = base::MakeRefCounted<MockCertVerifyProc>(result);

  // SHA-1 should be rejected by default for private roots...
  int flags = 0;
  CertVerifyResult verify_result;
  int error = verify_proc->Verify(
      cert.get(), "127.0.0.1", /*ocsp_response=*/std::string(),
      /*sct_list=*/std::string(), flags, &verify_result, NetLogWithSource());
  EXPECT_THAT(error, IsError(ERR_CERT_WEAK_SIGNATURE_ALGORITHM));
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_SHA1_SIGNATURE_PRESENT);

  // ... unless VERIFY_ENABLE_SHA1_LOCAL_ANCHORS was supplied.
  flags = CertVerifyProc::VERIFY_ENABLE_SHA1_LOCAL_ANCHORS;
  verify_result.Reset();
  error = verify_proc->Verify(
      cert.get(), "127.0.0.1", /*ocsp_response=*/std::string(),
      /*sct_list=*/std::string(), flags, &verify_result, NetLogWithSource());
  EXPECT_THAT(error, IsOk());
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_SHA1_SIGNATURE_PRESENT);
}

enum ExpectedAlgorithms {
  EXPECT_SHA1 = 1 << 0,
  EXPECT_STATUS_INVALID = 1 << 1,
};

struct WeakDigestTestData {
  const char* root_cert_filename;
  const char* intermediate_cert_filename;
  const char* ee_cert_filename;
  int expected_algorithms;
};

const char* StringOrDefault(const char* str, const char* default_value) {
  if (!str)
    return default_value;
  return str;
}

// GTest 'magic' pretty-printer, so that if/when a test fails, it knows how
// to output the parameter that was passed. Without this, it will simply
// attempt to print out the first twenty bytes of the object, which depending
// on platform and alignment, may result in an invalid read.
void PrintTo(const WeakDigestTestData& data, std::ostream* os) {
  *os << "root: " << StringOrDefault(data.root_cert_filename, "none")
      << "; intermediate: "
      << StringOrDefault(data.intermediate_cert_filename, "none")
      << "; end-entity: " << data.ee_cert_filename;
}

class CertVerifyProcWeakDigestTest
    : public testing::TestWithParam<WeakDigestTestData> {
 public:
  CertVerifyProcWeakDigestTest() = default;
  ~CertVerifyProcWeakDigestTest() override = default;
};

// Tests that the CertVerifyProc::Verify() properly surfaces the (weak) hash
// algorithms used in the chain.
TEST_P(CertVerifyProcWeakDigestTest, VerifyDetectsAlgorithm) {
  WeakDigestTestData data = GetParam();
  base::FilePath certs_dir = GetTestCertsDirectory();

  // Build |intermediates| as the full chain (including trust anchor).
  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;

  if (data.intermediate_cert_filename) {
    scoped_refptr<X509Certificate> intermediate_cert =
        ImportCertFromFile(certs_dir, data.intermediate_cert_filename);
    ASSERT_TRUE(intermediate_cert);
    intermediates.push_back(bssl::UpRef(intermediate_cert->cert_buffer()));
  }

  if (data.root_cert_filename) {
    scoped_refptr<X509Certificate> root_cert =
        ImportCertFromFile(certs_dir, data.root_cert_filename);
    ASSERT_TRUE(root_cert);
    intermediates.push_back(bssl::UpRef(root_cert->cert_buffer()));
  }

  scoped_refptr<X509Certificate> ee_cert =
      ImportCertFromFile(certs_dir, data.ee_cert_filename);
  ASSERT_TRUE(ee_cert);

  scoped_refptr<X509Certificate> ee_chain = X509Certificate::CreateFromBuffer(
      bssl::UpRef(ee_cert->cert_buffer()), std::move(intermediates));
  ASSERT_TRUE(ee_chain);

  int flags = 0;
  CertVerifyResult verify_result;

  // Use a mock CertVerifyProc that returns success with a verified_cert of
  // |ee_chain|.
  //
  // This is sufficient for the purposes of this test, as the checking for weak
  // hash algorithms is done by CertVerifyProc::Verify().
  auto proc = base::MakeRefCounted<MockCertVerifyProc>(CertVerifyResult());
  int error = proc->Verify(ee_chain.get(), "127.0.0.1",
                           /*ocsp_response=*/std::string(),
                           /*sct_list=*/std::string(), flags, &verify_result,
                           NetLogWithSource());
  EXPECT_EQ(!!(data.expected_algorithms & EXPECT_SHA1), verify_result.has_sha1);
  EXPECT_EQ(!!(data.expected_algorithms & EXPECT_STATUS_INVALID),
            !!(verify_result.cert_status & CERT_STATUS_INVALID));
  EXPECT_EQ(!!(data.expected_algorithms & EXPECT_STATUS_INVALID),
            error == ERR_CERT_INVALID);
}

// The signature algorithm of the root CA should not matter.
const WeakDigestTestData kVerifyRootCATestData[] = {
    {"weak_digest_md5_root.pem", "weak_digest_sha1_intermediate.pem",
     "weak_digest_sha1_ee.pem", EXPECT_SHA1},
    {"weak_digest_md4_root.pem", "weak_digest_sha1_intermediate.pem",
     "weak_digest_sha1_ee.pem", EXPECT_SHA1},
    {"weak_digest_md2_root.pem", "weak_digest_sha1_intermediate.pem",
     "weak_digest_sha1_ee.pem", EXPECT_SHA1},
};
INSTANTIATE_TEST_SUITE_P(VerifyRoot,
                         CertVerifyProcWeakDigestTest,
                         testing::ValuesIn(kVerifyRootCATestData));

// The signature algorithm of intermediates should be properly detected.
const WeakDigestTestData kVerifyIntermediateCATestData[] = {
    {"weak_digest_sha1_root.pem", "weak_digest_md5_intermediate.pem",
     "weak_digest_sha1_ee.pem", EXPECT_STATUS_INVALID | EXPECT_SHA1},
    {"weak_digest_sha1_root.pem", "weak_digest_md4_intermediate.pem",
     "weak_digest_sha1_ee.pem", EXPECT_STATUS_INVALID | EXPECT_SHA1},
    {"weak_digest_sha1_root.pem", "weak_digest_md2_intermediate.pem",
     "weak_digest_sha1_ee.pem", EXPECT_STATUS_INVALID | EXPECT_SHA1},
};

INSTANTIATE_TEST_SUITE_P(VerifyIntermediate,
                         CertVerifyProcWeakDigestTest,
                         testing::ValuesIn(kVerifyIntermediateCATestData));

// The signature algorithm of end-entity should be properly detected.
const WeakDigestTestData kVerifyEndEntityTestData[] = {
    {"weak_digest_sha1_root.pem", "weak_digest_sha1_intermediate.pem",
     "weak_digest_md5_ee.pem", EXPECT_STATUS_INVALID},
    {"weak_digest_sha1_root.pem", "weak_digest_sha1_intermediate.pem",
     "weak_digest_md4_ee.pem", EXPECT_STATUS_INVALID},
    {"weak_digest_sha1_root.pem", "weak_digest_sha1_intermediate.pem",
     "weak_digest_md2_ee.pem", EXPECT_STATUS_INVALID},
};

INSTANTIATE_TEST_SUITE_P(VerifyEndEntity,
                         CertVerifyProcWeakDigestTest,
                         testing::ValuesIn(kVerifyEndEntityTestData));

// Incomplete chains do not report the status of the intermediate.
// Note: really each of these tests should also expect the digest algorithm of
// the intermediate (included as a comment). However CertVerifyProc::Verify() is
// unable to distinguish that this is an intermediate and not a trust anchor, so
// this intermediate is treated like a trust anchor.
const WeakDigestTestData kVerifyIncompleteIntermediateTestData[] = {
    {nullptr, "weak_digest_md5_intermediate.pem", "weak_digest_sha1_ee.pem",
     EXPECT_SHA1},
    {nullptr, "weak_digest_md4_intermediate.pem", "weak_digest_sha1_ee.pem",
     EXPECT_SHA1},
    {nullptr, "weak_digest_md2_intermediate.pem", "weak_digest_sha1_ee.pem",
     EXPECT_SHA1},
};

INSTANTIATE_TEST_SUITE_P(
    MAYBE_VerifyIncompleteIntermediate,
    CertVerifyProcWeakDigestTest,
    testing::ValuesIn(kVerifyIncompleteIntermediateTestData));

// Incomplete chains should report the status of the end-entity.
// since the intermediate is treated as a trust anchor these should
// be still simply be invalid.
const WeakDigestTestData kVerifyIncompleteEETestData[] = {
    {nullptr, "weak_digest_sha1_intermediate.pem", "weak_digest_md5_ee.pem",
     EXPECT_STATUS_INVALID},
    {nullptr, "weak_digest_sha1_intermediate.pem", "weak_digest_md4_ee.pem",
     EXPECT_STATUS_INVALID},
    {nullptr, "weak_digest_sha1_intermediate.pem", "weak_digest_md2_ee.pem",
     EXPECT_STATUS_INVALID},
};

INSTANTIATE_TEST_SUITE_P(VerifyIncompleteEndEntity,
                         CertVerifyProcWeakDigestTest,
                         testing::ValuesIn(kVerifyIncompleteEETestData));

// Md2, Md4, and Md5 are all considered invalid.
const WeakDigestTestData kVerifyMixedTestData[] = {
    {"weak_digest_sha1_root.pem", "weak_digest_md5_intermediate.pem",
     "weak_digest_md2_ee.pem", EXPECT_STATUS_INVALID},
    {"weak_digest_sha1_root.pem", "weak_digest_md2_intermediate.pem",
     "weak_digest_md5_ee.pem", EXPECT_STATUS_INVALID},
    {"weak_digest_sha1_root.pem", "weak_digest_md4_intermediate.pem",
     "weak_digest_md2_ee.pem", EXPECT_STATUS_INVALID},
};

INSTANTIATE_TEST_SUITE_P(VerifyMixed,
                         CertVerifyProcWeakDigestTest,
                         testing::ValuesIn(kVerifyMixedTestData));

// The EE is a trusted certificate. Even though it uses weak hashes, these
// should not be reported.
const WeakDigestTestData kVerifyTrustedEETestData[] = {
    {nullptr, nullptr, "weak_digest_md5_ee.pem", 0},
    {nullptr, nullptr, "weak_digest_md4_ee.pem", 0},
    {nullptr, nullptr, "weak_digest_md2_ee.pem", 0},
    {nullptr, nullptr, "weak_digest_sha1_ee.pem", 0},
};

INSTANTIATE_TEST_SUITE_P(VerifyTrustedEE,
                         CertVerifyProcWeakDigestTest,
                         testing::ValuesIn(kVerifyTrustedEETestData));

// Test fixture for verifying certificate names.
class CertVerifyProcNameTest : public ::testing::Test {
 protected:
  void VerifyCertName(const char* hostname, bool valid) {
    scoped_refptr<X509Certificate> cert(ImportCertFromFile(
        GetTestCertsDirectory(), "subjectAltName_sanity_check.pem"));
    ASSERT_TRUE(cert);
    CertVerifyResult result;
    result.is_issued_by_known_root = false;
    auto verify_proc = base::MakeRefCounted<MockCertVerifyProc>(result);

    CertVerifyResult verify_result;
    int error = verify_proc->Verify(
        cert.get(), hostname, /*ocsp_response=*/std::string(),
        /*sct_list=*/std::string(), 0, &verify_result, NetLogWithSource());
    if (valid) {
      EXPECT_THAT(error, IsOk());
      EXPECT_FALSE(verify_result.cert_status & CERT_STATUS_COMMON_NAME_INVALID);
    } else {
      EXPECT_THAT(error, IsError(ERR_CERT_COMMON_NAME_INVALID));
      EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_COMMON_NAME_INVALID);
    }
  }
};

// Don't match the common name
TEST_F(CertVerifyProcNameTest, DontMatchCommonName) {
  VerifyCertName("127.0.0.1", false);
}

// Matches the iPAddress SAN (IPv4)
TEST_F(CertVerifyProcNameTest, MatchesIpSanIpv4) {
  VerifyCertName("127.0.0.2", true);
}

// Matches the iPAddress SAN (IPv6)
TEST_F(CertVerifyProcNameTest, MatchesIpSanIpv6) {
  VerifyCertName("FE80:0:0:0:0:0:0:1", true);
}

// Should not match the iPAddress SAN
TEST_F(CertVerifyProcNameTest, DoesntMatchIpSanIpv6) {
  VerifyCertName("[FE80:0:0:0:0:0:0:1]", false);
}

// Compressed form matches the iPAddress SAN (IPv6)
TEST_F(CertVerifyProcNameTest, MatchesIpSanCompressedIpv6) {
  VerifyCertName("FE80::1", true);
}

// IPv6 mapped form should NOT match iPAddress SAN
TEST_F(CertVerifyProcNameTest, DoesntMatchIpSanIPv6Mapped) {
  VerifyCertName("::127.0.0.2", false);
}

// Matches the dNSName SAN
TEST_F(CertVerifyP
"""


```