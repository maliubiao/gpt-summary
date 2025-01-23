Response:
My thought process for analyzing the provided code snippet and generating the summary goes through these stages:

1. **Understand the Goal:** The request asks for a summary of the functionality of the C++ test file `net/cert/cert_verify_proc_unittest.cc`, specifically focusing on the provided section (part 6 of 8). It also asks about relationships to JavaScript, logical reasoning with inputs/outputs, common user errors, debugging, and a general summarization of this part.

2. **Identify the Core Functionality:**  The filename `cert_verify_proc_unittest.cc` and the test class names like `CertVerifyProcConstraintsTest` strongly suggest that this file contains unit tests for the certificate verification process in Chromium's network stack. The focus is on *constraints* related to X.509 certificates.

3. **Analyze the Test Cases:** I'll scan the provided code, paying attention to the `TEST_P` macros and the operations within them. Key elements to look for:
    * **Test Names:**  These are very descriptive (e.g., `BasicConstraintsPathlen0Root`, `NameConstraintsNotMatchingIntermediate`). They immediately give clues about what's being tested.
    * **Setup:**  The `SetUp()` method initializes a certificate chain (`chain_`). This is the primary input for the tests.
    * **Certificate Manipulation:**  Methods like `SetBasicConstraints`, `EraseExtension`, `SetNameConstraintsDnsNames`, `SetValidity`, `SetPolicyConstraints`, `SetKeyUsages`, `SetExtendedKeyUsages`, `SetSignatureAlgorithmTLV`, and `SetExtension` are used to modify the properties of the certificates in the chain.
    * **Verification:** The `Verify()`, `VerifyWithExpiryAndConstraints()`, and `VerifyWithExpiryAndFullConstraints()` methods (inherited from the base class) are used to perform the certificate verification.
    * **Assertions:** `EXPECT_THAT()` is the assertion mechanism, checking if the verification result matches the expected outcome (e.g., `IsOk()`, `IsError(ERR_CERT_INVALID)`).
    * **Conditional Logic:** `if (VerifyProcTypeIsBuiltin())`, `else if (...)`, `else` blocks indicate that the expected behavior might differ based on the underlying certificate verification implementation (e.g., built-in, iOS, Android).
    * **Looping and Scoped Tracing:** Constructs like `for (bool ...)` and `SCOPED_TRACE()` suggest testing different scenarios within a single test case, making it easier to track which scenario failed.

4. **Categorize the Tests:**  Based on the test names and the certificate manipulation methods, I can categorize the tests:
    * **Basic Constraints:** Testing `ca` flag and `pathLenConstraint`.
    * **Name Constraints:** Testing permitted and excluded DNS names.
    * **Validity:** Testing expired and not-yet-valid dates.
    * **Policy Constraints:** Testing `requireExplicitPolicy` and `inhibitPolicyMapping`.
    * **Inhibit Any Policy:** Testing the `inhibitAnyPolicy` extension.
    * **Certificate Policies and Policy Mappings:** Testing the effect of policies and mappings on the root certificate.
    * **Key Usage:** Testing the `keyUsage` extension, particularly `keyCertSign`.
    * **Extended Key Usage:** Testing the `extendedKeyUsage` extension, particularly `serverAuth`.
    * **Signature Algorithm:** Testing unknown signature algorithms.
    * **Unknown Extensions:** Testing the handling of unknown certificate extensions.

5. **Address Specific Questions:**
    * **Functionality:** The primary function is to test the `CertVerifyProc` class, specifically its handling of various X.509 certificate constraints.
    * **JavaScript Relationship:**  Certificate verification happens at the network layer, *below* the JavaScript level. JavaScript might trigger network requests that *require* certificate verification, but it doesn't directly implement or interact with the logic being tested here.
    * **Logical Reasoning (Input/Output):** I'll pick a few representative test cases and describe the assumed input (modified certificate chain) and expected output (success or a specific error code).
    * **User/Programming Errors:**  I'll think about common mistakes developers or users might make that would be caught by these tests. For instance, a CA certificate not having the `ca` flag set, or a certificate being used outside its validity period.
    * **User Operations/Debugging:** I'll consider how a user's action (e.g., visiting a website) might lead to this code being executed during debugging, especially when investigating certificate-related issues.

6. **Synthesize the Summary:**  I'll combine the categorized test information and the answers to the specific questions into a concise summary that captures the essence of the provided code section. I'll emphasize that this section focuses on constraint testing and how different certificate properties influence the verification outcome.

7. **Review and Refine:** I'll read through the summary to ensure clarity, accuracy, and completeness, addressing all aspects of the original request. I'll make sure the language is appropriate and understandable. I will also double check that the summary correctly identifies the part number.

By following these steps, I can systematically analyze the code and generate a comprehensive and informative summary that addresses all the requirements of the prompt.
这是目录为net/cert/cert_verify_proc_unittest.cc的chromium 网络栈的源代码文件的第6部分，共8部分。 根据提供的代码片段，我们可以归纳出这一部分的主要功能是：**详细测试 `CertVerifyProc` 类在处理各种 X.509 证书约束时的行为。**

具体来说，这部分代码专注于以下类型的证书约束测试：

**1. 基本约束 (Basic Constraints):**

* **`ca` 标志:** 测试根证书和中间证书的 `ca` 标志是否正确设置。
* **`pathLenConstraint`:** 测试根证书和中间证书的 `pathLenConstraint` 限制对证书链长度的影响。
* **`basicConstraints` 扩展缺失:** 测试根证书、中间证书和叶子证书缺少 `basicConstraints` 扩展时的验证结果。
* 针对不同的验证器类型 (Builtin, iOS, Android) 测试结果的差异。

**2. 名称约束 (Name Constraints):**

* 测试根证书和中间证书的 `nameConstraints` 扩展对允许和排除的 DNS 名称的限制。
* 测试叶子证书上设置 `nameConstraints` 扩展的行为（虽然 RFC 规定只能在 CA 证书中使用）。

**3. 有效期 (Validity):**

* 测试根证书和中间证书过期或尚未生效时的验证结果。
* 针对不同的验证器类型 (Android) 测试结果的差异。

**4. 策略约束 (Policy Constraints):**

* **`requireExplicitPolicy`:** 测试根证书和中间证书的 `requireExplicitPolicy` 约束对策略处理的影响。
* **`inhibitPolicyMapping`:** 测试根证书的 `inhibitPolicyMapping` 约束对策略映射的限制。
* 针对不同的验证器类型 (Builtin, iOS, Android) 测试结果的差异。
* 测试叶子证书上设置 `requireExplicitPolicy` 的行为。

**5. 抑制任何策略 (Inhibit Any Policy):**

* 测试根证书和中间证书的 `inhibitAnyPolicy` 约束对 `anyPolicy` OID 的影响。
* 针对不同的验证器类型 (Builtin, iOS, Android) 测试结果的差异。

**6. 证书策略 (Certificate Policies) 和策略映射 (Policy Mappings):**

* 测试根证书上的证书策略和策略映射对证书链验证的影响。
* 针对不同的验证器类型 (Builtin, iOS, Android) 测试结果的差异。

**7. 密钥用途 (Key Usage):**

* 测试根证书和中间证书缺少或设置了不正确的 `keyUsage` 扩展（缺少 `keyCertSign` 位）时的验证结果。
* 测试叶子证书的 `keyUsage` 扩展（即使设置了 `keyCertSign`，通常也不会影响验证）。
* 针对不同的验证器类型 (Builtin, Android) 测试结果的差异。

**8. 扩展密钥用途 (Extended Key Usage):**

* 测试根证书、中间证书和叶子证书缺少或设置了不正确的 `extendedKeyUsage` 扩展（缺少 `serverAuth` OID）时的验证结果。
* 针对不同的验证器类型 (Builtin, Android, iOS) 测试结果的差异。

**9. 未知的签名算法 (Unknown Signature Algorithm):**

* 测试根证书、中间证书和叶子证书使用未知签名算法时的验证结果。
* 针对不同的验证器类型 (iOS) 测试结果的差异。

**10. 未知的扩展 (Unknown Extension):**

* 测试根证书、中间证书和叶子证书包含未知扩展，且 `critical` 标志设置为 `true` 或 `false` 时的验证结果。
* 针对不同的验证器类型 (Builtin, iOS, Android) 测试结果的差异。

**与 JavaScript 的关系：**

此部分代码主要关注网络栈底层的证书验证逻辑，与 JavaScript 的功能没有直接的编程接口关系。 然而，当 JavaScript 发起需要安全连接（HTTPS）的网络请求时，Chromium 浏览器会使用其网络栈进行证书验证。  如果证书验证失败（例如，由于约束冲突），JavaScript 代码可能会收到一个错误，表明连接不安全。

**举例说明：**

假设一个 JavaScript 应用程序尝试访问一个使用了由证书链验证不通过的 HTTPS 网站。 `CertVerifyProcConstraintsTest` 中的测试用例模拟了各种证书约束不满足的情况。 例如，`TEST_P(CertVerifyProcConstraintsTest, BasicConstraintsPathlen0Root)` 测试用例模拟了根证书设置了 `pathLenConstraint=0` 的情况。  如果用户访问的网站的证书链超过了这个长度，`CertVerifyProc` 的验证就会失败，最终浏览器会阻止 JavaScript 应用程序建立连接，并可能在控制台中显示一个安全错误。

**逻辑推理、假设输入与输出：**

**示例 1：`TEST_P(CertVerifyProcConstraintsTest, BasicConstraintsPathlen0Root)`**

* **假设输入:** 一个包含四个证书的链，根证书（chain_[3]）设置了 `basicConstraints: CA=TRUE, pathLenConstraint=0`。
* **预期输出:**
    * 如果 `VerifyProcTypeIsBuiltin()` 为 true，则 `Verify()` 返回 `IsOk()` (部分情况下内置验证器不强制执行所有约束)，`VerifyWithExpiryAndConstraints()` 返回 `IsError(ERR_CERT_INVALID)`。
    * 如果 `VerifyProcTypeIsIOSAtMostOS14()` 或 `verify_proc_type() == CERT_VERIFY_PROC_ANDROID` 为 true，则 `Verify()` 返回 `IsOk()`。
    * 否则（其他验证器），`Verify()` 返回 `IsError(ERR_CERT_INVALID)`，因为 `pathLenConstraint=0` 意味着根证书不允许任何子 CA。

**示例 2：`TEST_P(CertVerifyProcConstraintsTest, ValidityExpiredIntermediate)`**

* **假设输入:** 一个包含四个证书的链，中间证书（chain_[2]）的有效期已过期。
* **预期输出:**
    * 如果 `verify_proc_type() == CERT_VERIFY_PROC_ANDROID` 为 true，则 `Verify()` 返回 `IsError(ERR_CERT_AUTHORITY_INVALID)`。
    * 否则，`Verify()` 返回 `IsError(ERR_CERT_DATE_INVALID)`。

**用户或编程常见的使用错误：**

* **颁发证书时 `ca` 标志设置错误:**  一个应该作为 CA 的证书，其 `basicConstraints` 扩展中的 `CA` 标志未设置为 `TRUE`。 `TEST_P(CertVerifyProcConstraintsTest, BasicConstraintsNotPresentIntermediate)` 测试了这种情况。
* **`pathLenConstraint` 设置不当:** 根 CA 将 `pathLenConstraint` 设置得过小，导致有效的证书链无法验证。 `TEST_P(CertVerifyProcConstraintsTest, BasicConstraintsPathlen0Root)` 测试了这种情况。
* **证书有效期设置错误:**  证书的有效期早于当前时间或晚于当前时间，导致证书不可用。 `TEST_P(CertVerifyProcConstraintsTest, ValidityExpiredIntermediate)` 和 `TEST_P(CertVerifyProcConstraintsTest, ValidityNotYetValidRoot)` 测试了这些情况。
* **在非 CA 证书上设置 `nameConstraints`:** 虽然 Chromium 的验证器可能允许，但这违反了 RFC 5280 规范。 `TEST_P(CertVerifyProcConstraintsTest, NameConstraintsOnLeaf)`  测试了这种情况。
* **密钥用途限制不当:**  CA 证书的 `keyUsage` 扩展中缺少 `keyCertSign` 位。 `TEST_P(CertVerifyProcConstraintsTest, KeyUsageNoCertSignIntermediate)` 测试了这种情况。

**用户操作如何一步步的到达这里（作为调试线索）：**

1. **用户尝试访问一个 HTTPS 网站。**
2. **浏览器开始建立 TLS 连接，并从服务器接收到证书链。**
3. **Chromium 的网络栈会调用 `CertVerifyProc` 类来验证接收到的证书链的有效性。**
4. **`CertVerifyProc` 内部会检查证书链中每个证书的各种约束。**
5. **如果某个约束不满足，例如，中间证书的有效期已过期，`CertVerifyProc` 会返回一个错误代码（例如 `ERR_CERT_DATE_INVALID`）。**
6. **浏览器会根据错误代码采取相应的措施，例如阻止连接并显示安全警告。**
7. **在调试阶段，开发人员可能会设置断点在 `net/cert/cert_verify_proc_unittest.cc` 中的相关测试用例中，以便理解证书验证失败的具体原因和步骤。** 例如，如果用户报告某个网站的证书错误，开发人员可能会运行与有效期相关的测试用例，并使用相同的证书链进行测试，以复现和诊断问题。

总而言之，这段代码是 Chromium 网络栈中用于测试证书验证过程中约束处理逻辑的关键部分，确保了浏览器能够正确地识别和处理不符合安全规范的证书，从而保护用户的网络安全。

### 提示词
```
这是目录为net/cert/cert_verify_proc_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
ITAL_SIGNATURE});
    }
    EXPECT_THAT(Verify(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTest, BasicConstraintsPathlen0Root) {
  chain_[3]->SetBasicConstraints(/*is_ca=*/true, /*path_len=*/0);

  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(Verify(), IsOk());
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsError(ERR_CERT_INVALID));
  } else if (VerifyProcTypeIsIOSAtMostOS14() ||
             verify_proc_type() == CERT_VERIFY_PROC_ANDROID) {
    EXPECT_THAT(Verify(), IsOk());
  } else {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));
  }
}

TEST_P(CertVerifyProcConstraintsTest, BasicConstraintsPathlen1Root) {
  chain_[3]->SetBasicConstraints(/*is_ca=*/true, /*path_len=*/1);

  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(Verify(), IsOk());
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsError(ERR_CERT_INVALID));
  } else if (VerifyProcTypeIsIOSAtMostOS14() ||
             verify_proc_type() == CERT_VERIFY_PROC_ANDROID) {
    EXPECT_THAT(Verify(), IsOk());
  } else {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));
  }
}

TEST_P(CertVerifyProcConstraintsTest, BasicConstraintsPathlen2Root) {
  chain_[3]->SetBasicConstraints(/*is_ca=*/true, /*path_len=*/2);

  EXPECT_THAT(Verify(), IsOk());
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTest,
       BasicConstraintsPathlen0IntermediateParent) {
  chain_[2]->SetBasicConstraints(/*is_ca=*/true, /*path_len=*/0);

  EXPECT_THAT(Verify(), IsError(ExpectedIntermediateConstraintError()));
}

TEST_P(CertVerifyProcConstraintsTest,
       BasicConstraintsPathlen1IntermediateParent) {
  chain_[2]->SetBasicConstraints(/*is_ca=*/true, /*path_len=*/1);

  EXPECT_THAT(Verify(), IsOk());
}

TEST_P(CertVerifyProcConstraintsTest,
       BasicConstraintsPathlen0IntermediateChild) {
  chain_[1]->SetBasicConstraints(/*is_ca=*/true, /*path_len=*/0);

  EXPECT_THAT(Verify(), IsOk());
}

TEST_P(CertVerifyProcConstraintsTest, BasicConstraintsNotPresentRoot) {
  chain_[3]->EraseExtension(bssl::der::Input(bssl::kBasicConstraintsOid));

  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(Verify(), IsOk());
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsOk());
    EXPECT_THAT(VerifyWithExpiryAndFullConstraints(),
                IsError(ERR_CERT_INVALID));
  } else if (verify_proc_type() == CERT_VERIFY_PROC_ANDROID) {
    EXPECT_THAT(Verify(), IsOk());
  } else {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));
  }
}

TEST_P(CertVerifyProcConstraintsTest, BasicConstraintsNotPresentRootX509V1) {
  chain_[3]->SetCertificateVersion(bssl::CertificateVersion::V1);
  chain_[3]->ClearExtensions();

  EXPECT_THAT(Verify(), IsOk());
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsOk());
    EXPECT_THAT(VerifyWithExpiryAndFullConstraints(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTest, BasicConstraintsNotPresentIntermediate) {
  chain_[2]->EraseExtension(bssl::der::Input(bssl::kBasicConstraintsOid));

  EXPECT_THAT(Verify(), IsError(ExpectedIntermediateConstraintError()));
}

TEST_P(CertVerifyProcConstraintsTest, BasicConstraintsNotPresentLeaf) {
  chain_[0]->EraseExtension(bssl::der::Input(bssl::kBasicConstraintsOid));

  EXPECT_THAT(Verify(), IsOk());
}

TEST_P(CertVerifyProcConstraintsTest, NameConstraintsNotMatchingRoot) {
  chain_[3]->SetNameConstraintsDnsNames(/*permitted_dns_names=*/{"example.org"},
                                        /*excluded_dns_names=*/{});

  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(Verify(), IsOk());
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsError(ERR_CERT_INVALID));
  } else if (verify_proc_type() == CERT_VERIFY_PROC_ANDROID) {
    EXPECT_THAT(Verify(), IsOk());
  } else {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));
  }
}

TEST_P(CertVerifyProcConstraintsTest, NameConstraintsNotMatchingIntermediate) {
  chain_[2]->SetNameConstraintsDnsNames(
      /*permitted_dns_names=*/{"example.org"},
      /*excluded_dns_names=*/{});

  EXPECT_THAT(Verify(), IsError(ExpectedIntermediateConstraintError()));
}

TEST_P(CertVerifyProcConstraintsTest, NameConstraintsMatchingRoot) {
  chain_[3]->SetNameConstraintsDnsNames(/*permitted_dns_names=*/{"example.com"},
                                        /*excluded_dns_names=*/{});

  EXPECT_THAT(Verify(), IsOk());
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTest, NameConstraintsMatchingIntermediate) {
  chain_[2]->SetNameConstraintsDnsNames(
      /*permitted_dns_names=*/{"example.com"},
      /*excluded_dns_names=*/{});

  EXPECT_THAT(Verify(), IsOk());
}

TEST_P(CertVerifyProcConstraintsTest, NameConstraintsOnLeaf) {
  chain_[0]->SetNameConstraintsDnsNames(
      /*permitted_dns_names=*/{"example.com"},
      /*excluded_dns_names=*/{});

  // TODO(mattm): this should be an error
  // RFC 5280 4.2.1.10 says: "The name constraints extension, which MUST be
  // used only in a CA certificate, ..."
  EXPECT_THAT(Verify(), IsOk());
}

TEST_P(CertVerifyProcConstraintsTest, ValidityExpiredRoot) {
  chain_[3]->SetValidity(base::Time::Now() - base::Days(14),
                         base::Time::Now() - base::Days(7));

  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(Verify(), IsOk());
    EXPECT_THAT(VerifyWithExpiryAndConstraints(),
                IsError(ERR_CERT_DATE_INVALID));
    EXPECT_THAT(VerifyWithExpiryAndFullConstraints(),
                IsError(ERR_CERT_DATE_INVALID));
  } else if (verify_proc_type() == CERT_VERIFY_PROC_ANDROID) {
    EXPECT_THAT(Verify(), IsOk());
  } else {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_DATE_INVALID));
  }
}

TEST_P(CertVerifyProcConstraintsTest, ValidityNotYetValidRoot) {
  chain_[3]->SetValidity(base::Time::Now() + base::Days(7),
                         base::Time::Now() + base::Days(14));

  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(Verify(), IsOk());
    EXPECT_THAT(VerifyWithExpiryAndConstraints(),
                IsError(ERR_CERT_DATE_INVALID));
    EXPECT_THAT(VerifyWithExpiryAndFullConstraints(),
                IsError(ERR_CERT_DATE_INVALID));
  } else if (verify_proc_type() == CERT_VERIFY_PROC_ANDROID) {
    EXPECT_THAT(Verify(), IsOk());
  } else {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_DATE_INVALID));
  }
}

TEST_P(CertVerifyProcConstraintsTest, ValidityExpiredIntermediate) {
  chain_[2]->SetValidity(base::Time::Now() - base::Days(14),
                         base::Time::Now() - base::Days(7));

  if (verify_proc_type() == CERT_VERIFY_PROC_ANDROID) {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_AUTHORITY_INVALID));
  } else {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_DATE_INVALID));
  }
}

TEST_P(CertVerifyProcConstraintsTest, ValidityNotYetValidIntermediate) {
  chain_[2]->SetValidity(base::Time::Now() + base::Days(7),
                         base::Time::Now() + base::Days(14));

  if (verify_proc_type() == CERT_VERIFY_PROC_ANDROID) {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_AUTHORITY_INVALID));
  } else {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_DATE_INVALID));
  }
}

TEST_P(CertVerifyProcConstraintsTest, PolicyConstraints0Root) {
  for (bool leaf_has_policy : {false, true}) {
    SCOPED_TRACE(leaf_has_policy);

    static const char kPolicy1[] = "1.2.3.4";
    static const char kPolicy2[] = "1.2.3.4.5";
    static const char kPolicy3[] = "1.2.3.5";
    chain_[3]->SetPolicyConstraints(
        /*require_explicit_policy=*/0,
        /*inhibit_policy_mapping=*/std::nullopt);
    chain_[3]->SetCertificatePolicies({kPolicy1, kPolicy2});
    chain_[2]->SetCertificatePolicies({kPolicy3, kPolicy1});
    chain_[1]->SetCertificatePolicies({kPolicy1});

    if (leaf_has_policy) {
      chain_[0]->SetCertificatePolicies({kPolicy1});
      EXPECT_THAT(Verify(), IsOk());
      if (VerifyProcTypeIsBuiltin()) {
        EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsOk());
      }
    } else {
      chain_[0]->SetCertificatePolicies({});
      if (VerifyProcTypeIsBuiltin()) {
        EXPECT_THAT(Verify(), IsOk());
        EXPECT_THAT(VerifyWithExpiryAndConstraints(),
                    IsError(ERR_CERT_INVALID));
      } else if (verify_proc_type() == CERT_VERIFY_PROC_IOS ||
                 verify_proc_type() == CERT_VERIFY_PROC_ANDROID) {
        EXPECT_THAT(Verify(), IsOk());
      } else {
        EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));
      }
    }
  }
}

TEST_P(CertVerifyProcConstraintsTest, PolicyConstraints4Root) {
  // Explicit policy is required after 4 certs. Since the chain is 4 certs
  // long, an explicit policy is never required.
  chain_[3]->SetPolicyConstraints(
      /*require_explicit_policy=*/4,
      /*inhibit_policy_mapping=*/std::nullopt);

  EXPECT_THAT(Verify(), IsOk());
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTest, PolicyConstraints3Root) {
  // Explicit policy is required after 3 certs. Since the chain is 4 certs
  // long, an explicit policy is required and the chain should fail if anchor
  // constraints are enforced.
  chain_[3]->SetPolicyConstraints(
      /*require_explicit_policy=*/3,
      /*inhibit_policy_mapping=*/std::nullopt);

  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(Verify(), IsOk());
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsError(ERR_CERT_INVALID));
  } else {
    // Windows seems to have an off-by-one error in how it enforces
    // requireExplicitPolicy.
    // (The mac/android verifiers are Ok here since they don't enforce
    // policyConstraints on anchors.)
    EXPECT_THAT(Verify(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTest, PolicyConstraints2Root) {
  // Explicit policy is required after 2 certs. Since the chain is 4 certs
  // long, an explicit policy is required and the chain should fail if anchor
  // constraints are enforced.
  chain_[3]->SetPolicyConstraints(
      /*require_explicit_policy=*/2,
      /*inhibit_policy_mapping=*/std::nullopt);

  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(Verify(), IsOk());
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsError(ERR_CERT_INVALID));
  } else if (verify_proc_type() == CERT_VERIFY_PROC_IOS ||
             verify_proc_type() == CERT_VERIFY_PROC_ANDROID) {
    EXPECT_THAT(Verify(), IsOk());
  } else {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));
  }
}

// This is also a regression test for https://crbug.com/31497: If an
// intermediate has requireExplicitPolicy in its policyConstraints extension,
// verification should still succeed as long as some policy is valid for the
// chain, since Chrome does not specify any required policy as an input to
// certificate verification (allows anyPolicy).
TEST_P(CertVerifyProcConstraintsTest, PolicyConstraints0Intermediate) {
  for (bool leaf_has_policy : {false, true}) {
    SCOPED_TRACE(leaf_has_policy);

    static const char kPolicy1[] = "1.2.3.4";
    static const char kPolicy2[] = "1.2.3.4.5";
    static const char kPolicy3[] = "1.2.3.5";
    chain_[2]->SetPolicyConstraints(
        /*require_explicit_policy=*/0,
        /*inhibit_policy_mapping=*/std::nullopt);
    chain_[2]->SetCertificatePolicies({kPolicy1, kPolicy2});
    chain_[1]->SetCertificatePolicies({kPolicy3, kPolicy1});

    if (leaf_has_policy) {
      chain_[0]->SetCertificatePolicies({kPolicy1});
      EXPECT_THAT(Verify(), IsOk());
      if (VerifyProcTypeIsBuiltin()) {
        EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsOk());
      }
    } else {
      chain_[0]->SetCertificatePolicies({});
      EXPECT_THAT(Verify(), IsError(ExpectedIntermediateConstraintError()));
      if (VerifyProcTypeIsBuiltin()) {
        EXPECT_THAT(VerifyWithExpiryAndConstraints(),
                    IsError(ERR_CERT_INVALID));
      }
    }
  }
}

TEST_P(CertVerifyProcConstraintsTest, PolicyConstraints3Intermediate) {
  // Explicit policy is required after 3 certs. Since the chain up to
  // |chain_[2]| is 3 certs long, an explicit policy is never required.
  chain_[2]->SetPolicyConstraints(
      /*require_explicit_policy=*/3,
      /*inhibit_policy_mapping=*/std::nullopt);

  EXPECT_THAT(Verify(), IsOk());
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTest, PolicyConstraints2Intermediate) {
  // Explicit policy is required after 2 certs. Since the chain up to
  // |chain_[2]| is 3 certs long, an explicit policy will be required and this
  // should fail to verify.
  chain_[2]->SetPolicyConstraints(
      /*require_explicit_policy=*/2,
      /*inhibit_policy_mapping=*/std::nullopt);

  EXPECT_THAT(Verify(), IsError(ExpectedIntermediateConstraintError()));
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsError(ERR_CERT_INVALID));
    }
}

TEST_P(CertVerifyProcConstraintsTest, PolicyConstraints1Intermediate) {
  // Explicit policy is required after 1 cert. Since the chain up to
  // |chain_[2]| is 3 certs long, an explicit policy will be required and this
  // should fail to verify.
  chain_[2]->SetPolicyConstraints(
      /*require_explicit_policy=*/1,
      /*inhibit_policy_mapping=*/std::nullopt);

  EXPECT_THAT(Verify(), IsError(ExpectedIntermediateConstraintError()));
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsError(ERR_CERT_INVALID));
  }
}

TEST_P(CertVerifyProcConstraintsTest, PolicyConstraints0Leaf) {
  // Setting requireExplicitPolicy to 0 on the target certificate should make
  // an explicit policy required for the chain. (Ref: RFC 5280 section 6.1.5.b
  // and the final paragraph of 6.1.5)
  chain_[0]->SetPolicyConstraints(
      /*require_explicit_policy=*/0,
      /*inhibit_policy_mapping=*/std::nullopt);

  EXPECT_THAT(Verify(), IsError(ExpectedIntermediateConstraintError()));
}

TEST_P(CertVerifyProcConstraintsTest, InhibitPolicyMapping0Root) {
  static const char kPolicy1[] = "1.2.3.4";
  static const char kPolicy2[] = "1.2.3.5";

  // Root inhibits policy mapping immediately.
  chain_[3]->SetPolicyConstraints(
      /*require_explicit_policy=*/std::nullopt,
      /*inhibit_policy_mapping=*/0);

  // Policy constraints are specified on an intermediate so that an explicit
  // policy will be required regardless if root constraints are applied.
  chain_[2]->SetPolicyConstraints(
      /*require_explicit_policy=*/0,
      /*inhibit_policy_mapping=*/std::nullopt);

  // Intermediate uses policy mappings. This should not be allowed if the root
  // constraints were enforced.
  chain_[2]->SetCertificatePolicies({kPolicy1});
  chain_[2]->SetPolicyMappings({{kPolicy1, kPolicy2}});

  // Children require the policy mapping to have a valid policy.
  chain_[1]->SetCertificatePolicies({kPolicy2});
  chain_[0]->SetCertificatePolicies({kPolicy2});

  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(Verify(), IsOk());
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsError(ERR_CERT_INVALID));
  } else if (verify_proc_type() == CERT_VERIFY_PROC_IOS ||
             verify_proc_type() == CERT_VERIFY_PROC_ANDROID) {
    EXPECT_THAT(Verify(), IsOk());
  } else {
    // Windows enforces inhibitPolicyMapping on the root.
    EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));
  }
}

TEST_P(CertVerifyProcConstraintsTest, InhibitPolicyMapping1Root) {
  static const char kPolicy1[] = "1.2.3.4";
  static const char kPolicy2[] = "1.2.3.5";

  // Root inhibits policy mapping after 1 cert.
  chain_[3]->SetPolicyConstraints(
      /*require_explicit_policy=*/std::nullopt,
      /*inhibit_policy_mapping=*/1);

  // Policy constraints are specified on an intermediate so that an explicit
  // policy will be required regardless if root constraints are applied.
  chain_[2]->SetPolicyConstraints(
      /*require_explicit_policy=*/0,
      /*inhibit_policy_mapping=*/std::nullopt);

  // Intermediate uses policy mappings. This should be allowed even if the root
  // constraints were enforced, since policy mapping was allowed for 1 cert
  // following the root.
  chain_[2]->SetCertificatePolicies({kPolicy1});
  chain_[2]->SetPolicyMappings({{kPolicy1, kPolicy2}});

  // Children require the policy mapping to have a valid policy.
  chain_[1]->SetCertificatePolicies({kPolicy2});
  chain_[0]->SetCertificatePolicies({kPolicy2});

  EXPECT_THAT(Verify(), IsOk());
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTest, InhibitAnyPolicy0Root) {
  static const char kAnyPolicy[] = "2.5.29.32.0";
  static const char kPolicy1[] = "1.2.3.4";

  // Since inhibitAnyPolicy is 0, anyPolicy should not be allow for any certs
  // after the root.
  chain_[3]->SetInhibitAnyPolicy(0);
  chain_[3]->SetCertificatePolicies({kAnyPolicy});

  // Policy constraints are specified on an intermediate so that an explicit
  // policy will be required regardless if root constraints are applied.
  chain_[2]->SetPolicyConstraints(
      /*require_explicit_policy=*/0,
      /*inhibit_policy_mapping=*/std::nullopt);

  // This intermediate only asserts anyPolicy, so this chain should
  // be invalid if policyConstraints from the root cert are enforced.
  chain_[2]->SetCertificatePolicies({kAnyPolicy});

  chain_[1]->SetCertificatePolicies({kPolicy1});
  chain_[0]->SetCertificatePolicies({kPolicy1});

  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(Verify(), IsOk());
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsError(ERR_CERT_INVALID));
  } else if (verify_proc_type() == CERT_VERIFY_PROC_IOS ||
             verify_proc_type() == CERT_VERIFY_PROC_ANDROID) {
    EXPECT_THAT(Verify(), IsOk());
  } else {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));
  }
}

TEST_P(CertVerifyProcConstraintsTest, InhibitAnyPolicy1Root) {
  for (bool chain_1_has_any_policy : {false, true}) {
    SCOPED_TRACE(chain_1_has_any_policy);

    static const char kAnyPolicy[] = "2.5.29.32.0";
    static const char kPolicy1[] = "1.2.3.4";

    // Since inhibitAnyPolicy is 1, anyPolicy should be allowed for the root's
    // immediate child, but not after that.
    chain_[3]->SetInhibitAnyPolicy(1);
    chain_[3]->SetCertificatePolicies({kAnyPolicy});

    // Policy constraints are specified on an intermediate so that an explicit
    // policy will be required regardless if root constraints are applied.
    chain_[2]->SetPolicyConstraints(
        /*require_explicit_policy=*/0,
        /*inhibit_policy_mapping=*/std::nullopt);

    // AnyPolicy should be allowed in this cert.
    chain_[2]->SetCertificatePolicies({kAnyPolicy});

    chain_[0]->SetCertificatePolicies({kPolicy1});

    if (chain_1_has_any_policy) {
      // AnyPolicy should not be allowed in this cert if the inhibitAnyPolicy
      // constraint from the root is honored.
      chain_[1]->SetCertificatePolicies({kAnyPolicy});

      if (VerifyProcTypeIsBuiltin()) {
        EXPECT_THAT(Verify(), IsOk());
        EXPECT_THAT(VerifyWithExpiryAndConstraints(),
                    IsError(ERR_CERT_INVALID));
      } else if (verify_proc_type() == CERT_VERIFY_PROC_IOS ||
                 verify_proc_type() == CERT_VERIFY_PROC_ANDROID) {
        EXPECT_THAT(Verify(), IsOk());
      } else {
        EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));
      }
    } else {
      chain_[1]->SetCertificatePolicies({kPolicy1});

      EXPECT_THAT(Verify(), IsOk());
      if (VerifyProcTypeIsBuiltin()) {
        EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsOk());
      }
    }
  }
}

TEST_P(CertVerifyProcConstraintsTest, InhibitAnyPolicy0Intermediate) {
  static const char kAnyPolicy[] = "2.5.29.32.0";
  static const char kPolicy1[] = "1.2.3.4";

  chain_[2]->SetInhibitAnyPolicy(0);
  chain_[2]->SetPolicyConstraints(
      /*require_explicit_policy=*/0,
      /*inhibit_policy_mapping=*/std::nullopt);

  chain_[2]->SetCertificatePolicies({kAnyPolicy});
  // This shouldn't be allowed as the parent cert set inhibitAnyPolicy=0.
  chain_[1]->SetCertificatePolicies({kAnyPolicy});
  chain_[0]->SetCertificatePolicies({kPolicy1});

  EXPECT_THAT(Verify(), IsError(ExpectedIntermediateConstraintError()));
}

TEST_P(CertVerifyProcConstraintsTest, InhibitAnyPolicy1Intermediate) {
  static const char kAnyPolicy[] = "2.5.29.32.0";
  static const char kPolicy1[] = "1.2.3.4";

  chain_[2]->SetInhibitAnyPolicy(1);
  chain_[2]->SetPolicyConstraints(
      /*require_explicit_policy=*/0,
      /*inhibit_policy_mapping=*/std::nullopt);

  chain_[2]->SetCertificatePolicies({kAnyPolicy});
  // This is okay as the parent cert set inhibitAnyPolicy=1.
  chain_[1]->SetCertificatePolicies({kAnyPolicy});
  chain_[0]->SetCertificatePolicies({kPolicy1});

  EXPECT_THAT(Verify(), IsOk());
}

TEST_P(CertVerifyProcConstraintsTest, PoliciesRoot) {
  static const char kPolicy1[] = "1.2.3.4";
  static const char kPolicy2[] = "1.2.3.5";

  for (bool root_has_matching_policy : {false, true}) {
    SCOPED_TRACE(root_has_matching_policy);

    if (root_has_matching_policy) {
      // This chain should be valid whether or not policies from the root are
      // processed.
      chain_[3]->SetCertificatePolicies({kPolicy1});
    } else {
      // If the policies from the root are processed, this chain will not be
      // valid for any policy.
      chain_[3]->SetCertificatePolicies({kPolicy2});
    }

    // Policy constraints are specified on an intermediate so that an explicit
    // policy will be required regardless if root constraints are applied.
    chain_[2]->SetPolicyConstraints(
        /*require_explicit_policy=*/0,
        /*inhibit_policy_mapping=*/std::nullopt);

    chain_[2]->SetCertificatePolicies({kPolicy1});
    chain_[1]->SetCertificatePolicies({kPolicy1});
    chain_[0]->SetCertificatePolicies({kPolicy1});

    if (root_has_matching_policy) {
      EXPECT_THAT(Verify(), IsOk());
      if (VerifyProcTypeIsBuiltin()) {
        EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsOk());
      }
    } else {
      if (VerifyProcTypeIsBuiltin()) {
        EXPECT_THAT(Verify(), IsOk());
        EXPECT_THAT(VerifyWithExpiryAndConstraints(),
                    IsError(ERR_CERT_INVALID));
      } else if (verify_proc_type() == CERT_VERIFY_PROC_IOS ||
                 verify_proc_type() == CERT_VERIFY_PROC_ANDROID) {
        EXPECT_THAT(Verify(), IsOk());
      } else {
        EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));
      }
    }
  }
}

TEST_P(CertVerifyProcConstraintsTest, PolicyMappingsRoot) {
  static const char kPolicy1[] = "1.2.3.4";
  static const char kPolicy2[] = "1.2.3.5";
  static const char kPolicy3[] = "1.2.3.6";

  for (bool root_has_matching_policy_mapping : {false, true}) {
    SCOPED_TRACE(root_has_matching_policy_mapping);

    if (root_has_matching_policy_mapping) {
      // This chain should be valid if the policies and policy mapping on the
      // root are processed, or if neither is processed. It will not be valid
      // if the policies were processed and the policyMappings were not.
      chain_[3]->SetCertificatePolicies({kPolicy1});
      chain_[3]->SetPolicyMappings({{kPolicy1, kPolicy2}});
    } else {
      // This chain should not be valid if the policies and policyMappings on
      // the root were processed. It will be valid if the policies were
      // processed and policyMappings were not.
      chain_[3]->SetCertificatePolicies({kPolicy2});
      chain_[3]->SetPolicyMappings({{kPolicy2, kPolicy3}});
    }

    // Policy constraints are specified on an intermediate so that an explicit
    // policy will be required regardless if root constraints are applied.
    chain_[2]->SetPolicyConstraints(
        /*require_explicit_policy=*/0,
        /*inhibit_policy_mapping=*/std::nullopt);

    chain_[2]->SetCertificatePolicies({kPolicy2});
    chain_[1]->SetCertificatePolicies({kPolicy2});
    chain_[0]->SetCertificatePolicies({kPolicy2});

    if (root_has_matching_policy_mapping) {
      EXPECT_THAT(Verify(), IsOk());
      if (VerifyProcTypeIsBuiltin()) {
        EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsOk());
      }
    } else {
      if (VerifyProcTypeIsBuiltin()) {
        EXPECT_THAT(Verify(), IsOk());
        EXPECT_THAT(VerifyWithExpiryAndConstraints(),
                    IsError(ERR_CERT_INVALID));
      } else if (verify_proc_type() == CERT_VERIFY_PROC_IOS ||
                 verify_proc_type() == CERT_VERIFY_PROC_ANDROID) {
        EXPECT_THAT(Verify(), IsOk());
      } else {
        EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));
      }
    }
  }
}

TEST_P(CertVerifyProcConstraintsTest, KeyUsageNoCertSignRoot) {
  chain_[3]->SetKeyUsages({bssl::KEY_USAGE_BIT_CRL_SIGN});

  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(Verify(), IsOk());
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsError(ERR_CERT_INVALID));
    EXPECT_THAT(VerifyWithExpiryAndFullConstraints(),
                IsError(ERR_CERT_INVALID));
  } else if (verify_proc_type() == CERT_VERIFY_PROC_ANDROID) {
    EXPECT_THAT(Verify(), IsOk());
  } else {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));
  }
}

TEST_P(CertVerifyProcConstraintsTest, KeyUsageNotPresentRoot) {
  chain_[3]->EraseExtension(bssl::der::Input(bssl::kKeyUsageOid));

  EXPECT_THAT(Verify(), IsOk());
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsOk());
    EXPECT_THAT(VerifyWithExpiryAndFullConstraints(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTest, KeyUsageNoCertSignIntermediate) {
  chain_[2]->SetKeyUsages({bssl::KEY_USAGE_BIT_CRL_SIGN});

  EXPECT_THAT(Verify(), IsError(ExpectedIntermediateConstraintError()));
}

TEST_P(CertVerifyProcConstraintsTest, KeyUsageNotPresentIntermediate) {
  chain_[2]->EraseExtension(bssl::der::Input(bssl::kKeyUsageOid));

  EXPECT_THAT(Verify(), IsOk());
}

TEST_P(CertVerifyProcConstraintsTest, KeyUsageNoDigitalSignatureLeaf) {
  // This test is mostly uninteresting since keyUsage on the end-entity is only
  // checked at the TLS layer, not during cert verification.
  chain_[0]->SetKeyUsages({bssl::KEY_USAGE_BIT_CRL_SIGN});

  EXPECT_THAT(Verify(), IsOk());
}

TEST_P(CertVerifyProcConstraintsTest, KeyUsageNotPresentLeaf) {
  // This test is mostly uninteresting since keyUsage on the end-entity is only
  // checked at the TLS layer, not during cert verification.
  chain_[0]->EraseExtension(bssl::der::Input(bssl::kKeyUsageOid));

  EXPECT_THAT(Verify(), IsOk());
}

TEST_P(CertVerifyProcConstraintsTest, KeyUsageCertSignLeaf) {
  // Test a leaf that has keyUsage asserting keyCertSign and basicConstraints
  // asserting CA=false. This should be an error according to 5280 section
  // 4.2.1.3 and 4.2.1.9, however most implementations seem to allow it.
  // Perhaps because 5280 section 6 does not explicitly say to enforce this on
  // the target cert.
  chain_[0]->SetKeyUsages({bssl::KEY_USAGE_BIT_KEY_CERT_SIGN,
                           bssl::KEY_USAGE_BIT_DIGITAL_SIGNATURE});

  EXPECT_THAT(Verify(), IsOk());
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsOk());
    EXPECT_THAT(VerifyWithExpiryAndFullConstraints(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTest, ExtendedKeyUsageNoServerAuthRoot) {
  chain_[3]->SetExtendedKeyUsages({bssl::der::Input(bssl::kCodeSigning)});

  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(Verify(), IsOk());
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsError(ERR_CERT_INVALID));
    EXPECT_THAT(VerifyWithExpiryAndFullConstraints(),
                IsError(ERR_CERT_INVALID));
  } else if (verify_proc_type() == CERT_VERIFY_PROC_ANDROID ||
             verify_proc_type() == CERT_VERIFY_PROC_IOS) {
    EXPECT_THAT(Verify(), IsOk());
  } else {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));
  }
}

TEST_P(CertVerifyProcConstraintsTest, ExtendedKeyUsageServerAuthRoot) {
  chain_[3]->SetExtendedKeyUsages({bssl::der::Input(bssl::kServerAuth)});

  EXPECT_THAT(Verify(), IsOk());
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTest,
       ExtendedKeyUsageNoServerAuthIntermediate) {
  chain_[2]->SetExtendedKeyUsages({bssl::der::Input(bssl::kCodeSigning)});

  if (verify_proc_type() == CERT_VERIFY_PROC_ANDROID ||
      VerifyProcTypeIsIOSAtMostOS15()) {
    EXPECT_THAT(Verify(), IsOk());
  } else {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));
  }
}

TEST_P(CertVerifyProcConstraintsTest, ExtendedKeyUsageServerAuthIntermediate) {
  chain_[2]->SetExtendedKeyUsages({bssl::der::Input(bssl::kServerAuth)});

  EXPECT_THAT(Verify(), IsOk());
}

TEST_P(CertVerifyProcConstraintsTest, ExtendedKeyUsageNoServerAuthLeaf) {
  chain_[0]->SetExtendedKeyUsages({bssl::der::Input(bssl::kCodeSigning)});

  EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));
}

TEST_P(CertVerifyProcConstraintsTest, UnknownSignatureAlgorithmRoot) {
  chain_[3]->SetSignatureAlgorithmTLV(TestOid0SignatureAlgorithmTLV());

  EXPECT_THAT(Verify(), IsOk());
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsOk());
  }
}

TEST_P(CertVerifyProcConstraintsTest, UnknownSignatureAlgorithmIntermediate) {
  chain_[2]->SetSignatureAlgorithmTLV(TestOid0SignatureAlgorithmTLV());

  if (verify_proc_type() == CERT_VERIFY_PROC_IOS) {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_AUTHORITY_INVALID));
  } else {
    EXPECT_THAT(Verify(), IsError(ExpectedIntermediateConstraintError()));
  }
}

TEST_P(CertVerifyProcConstraintsTest, UnknownSignatureAlgorithmLeaf) {
  chain_[0]->SetSignatureAlgorithmTLV(TestOid0SignatureAlgorithmTLV());

  if (verify_proc_type() == CERT_VERIFY_PROC_IOS) {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_AUTHORITY_INVALID));
  } else {
    EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));
  }
}

TEST_P(CertVerifyProcConstraintsTest, UnknownExtensionRoot) {
  for (bool critical : {true, false}) {
    SCOPED_TRACE(critical);
    chain_[3]->SetExtension(TestOid0(), "hello world", critical);

    if (critical) {
      if (VerifyProcTypeIsBuiltin()) {
        EXPECT_THAT(Verify(), IsOk());
        EXPECT_THAT(VerifyWithExpiryAndConstraints(),
                    IsError(ERR_CERT_INVALID));
        EXPECT_THAT(VerifyWithExpiryAndFullConstraints(),
                    IsError(ERR_CERT_INVALID));
      } else if (verify_proc_type() == CERT_VERIFY_PROC_IOS ||
                 verify_proc_type() == CERT_VERIFY_PROC_ANDROID) {
        EXPECT_THAT(Verify(), IsOk());
      } else {
        EXPECT_THAT(Verify(), IsError(ERR_CERT_INVALID));
      }
    } else {
      EXPECT_THAT(Verify(), IsOk());
      if (VerifyProcTypeIsBuiltin()) {
        EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsOk());
      }
    }
  }
}

TEST_P(CertVerifyProcConstraintsTest, UnknownExtensionIntermediate) {
  for (bool critical : {true, false}) {
    SCOPED_TRACE(critical);
    chain_[2]->SetExtension(TestOid0(), "hello world", critical);

    if (critical) {
      EXPECT_THAT(Verify(), IsError(ExpectedIntermediateConstraintError()));
    } else {
      EXPECT_THAT(Verify(), IsOk());
    }
  }
}

TEST_P(CertVerifyProcConstraintsTest, UnknownExtensionLeaf) {
  for (bool critical : {true, false}) {
    SCOPED_TRACE(critical);
    chain_[0]->SetExtension(TestOid0(), "hello world", critical);

    if (critical) {
      EXPECT_THAT(Verify(), IsError(ExpectedIntermediateConstraintError()));
    } else {
      EXPECT_THAT(Verify(), IsOk());
    }
  }
}

// A set of tests that check how various constraints are enforced when they
// are applied to a directly trusted non-self-signed leaf certificate.
class CertVerifyProcConstraintsTrustedLeafTest
    : public CertVerifyProcInternalTest {
 protected:
  void SetUp() override {
    CertVerifyProcInternalTest::SetUp();

    chain_ = CertBuilder::CreateSimpleChain(/*chain_length=*/2);
  }

  int VerifyWithTrust(bssl::CertificateTrust trust) {
    ScopedTestRoot test_root(chain_[0]->GetX509Certificate(), trust);
    CertVerifyResult verify_result;
    int flags = 0;
    return CertVerifyProcInternalTest::Verify(
        chain_.front()->GetX509Certificate().get(), "www.example.com", flags,
        &verify_result);
  }

  int Verify() {
    return VerifyWithTrust(bssl::CertificateTrust::ForTrustAnchor());
  }

  int VerifyAsTrustedLeaf() {
    return VerifyWithTrust(bssl::CertificateTrust::ForTrustedLeaf());
  }

  std::vector<std::unique_ptr<CertBuilder>> chain_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         CertVerifyProcConstraintsTrustedLeafTest,
                         testing::ValuesIn(kAllCertVerifiers),
                         VerifyProcTypeToName);

TEST_P(CertVerifyProcConstraintsTrustedLeafTest, BaseCase) {
  // Without changing anything on the test chain, it should validate
  // successfully. If this is not true the
```