Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack. The file is `cert_verify_proc_builtin_unittest.cc`, suggesting it's a unit test file.

Here's a breakdown of how to approach the request:

1. **Identify the core functionality:** The file name and the test names within the snippet clearly indicate that it's testing the built-in certificate verification process (`CertVerifyProcBuiltin`). Specifically, it seems to be focusing on how the process handles "Chrome Root Store Constraints".

2. **Analyze individual tests:** Go through each `TEST_F` function and understand what aspect of certificate verification it's testing. Look for keywords like `ChromeRootStoreConstraint`, `min_version`, `max_version`, `nameConstraints`, `SCT`, etc.

3. **Look for relationships with JavaScript:** Certificate verification is fundamental to web security. Think about how JavaScript interacts with secure connections (HTTPS).

4. **Consider logical reasoning and examples:**  For tests involving constraints, identify the setup (assumed inputs like certificate properties and constraint settings) and the expected outcome (verification success or failure).

5. **Identify potential user errors:** Think about how misconfigured certificates or browser settings could lead to the scenarios tested in the code.

6. **Determine user actions leading to this code:** Trace back the steps a user might take that would trigger certificate verification.

7. **Summarize the overall functionality:** Based on the analysis of individual tests, provide a concise summary of the file's purpose.

**Mental Sandbox:**

* **Constraint tests:** The tests with `ChromeRootStoreConstraint` clearly simulate different scenarios where certificates either meet or violate specific constraints defined for root certificates. This involves setting up mock constraints and then verifying a certificate chain.
* **JavaScript relevance:** When a user visits an HTTPS website, the browser uses its network stack (including the certificate verification logic being tested here) to validate the server's certificate. JavaScript code running on that page might be affected by verification failures (e.g., security warnings, blocked requests).
* **Error scenarios:** Tests that expect `ERR_CERT_AUTHORITY_INVALID` or `ERR_CERT_INVALID` highlight situations where the verification process detects a problem. This could be due to outdated certificates, incorrect root CA lists, or manipulated certificates.
* **Debugging:** The tests use logging (`NetLogSource`). This is a key debugging tool. Understanding these tests can help developers troubleshoot certificate-related issues.

**Constraint Logic Breakdown Example:**

The `ChromeRootStoreConstraintVersion` test has a clear structure:

* **Setup:** Create a certificate chain.
* **Scenario 1:** Set `min_version` in the future, verify - expect failure.
* **Scenario 2:** Set `max_version_exclusive` in the past, verify - expect failure.
* **Scenario 3:** Set both `min_version` and `max_version_exclusive` to allow the current version, verify - expect success.

This kind of step-by-step reasoning helps understand each test's purpose.

**Final Summary:** The file appears to be a comprehensive suite of unit tests specifically designed to verify the correct implementation of Chrome Root Store constraints within Chromium's built-in certificate verification process.
这是Chromium网络栈源代码文件 `net/cert/cert_verify_proc_builtin_unittest.cc` 的第三部分，延续了前两部分的内容，继续测试 `CertVerifyProcBuiltin` 类的功能，特别是它如何处理 Chrome 根证书存储的约束条件（Chrome Root Store Constraints）。

**功能归纳（基于第三部分内容和上下文）：**

这部分代码主要测试了 `CertVerifyProcBuiltin` 在证书验证过程中对 Chrome 根证书存储约束条件的执行情况。具体来说，它涵盖了以下功能点：

* **版本约束 (`min_version`, `max_version_exclusive`):**  测试了证书链中的根证书是否满足 Chrome 根证书存储中指定的最小版本和最大版本（不包含）的要求。
* **名称约束 (`permitted_dns_names`):** 测试了当 Chrome 根证书存储中定义了域名约束时，待验证证书的域名是否符合这些约束。
* **多重约束 (`ChromeRootStoreConstraintMultipleConstraints`):**  测试了当 Chrome 根证书存储中存在多个约束对象时，只要满足其中一个约束，验证是否会成功。这个例子中关注了 `sct_not_after` 和 `sct_all_after` 约束与证书透明度（SCT）的交互。
* **本地信任和额外信任的例外 (`ChromeRootStoreConstraintNotEnforcedIfAnchorLocallyTrusted`, `ChromeRootStoreConstraintNotEnforcedIfAnchorAdditionallyTrusted`):** 验证了如果根证书已经被本地操作系统信任或者通过 `additional_trust_anchors` 添加为信任锚点，则 Chrome 根证书存储的约束条件将不会被强制执行。
* **同步获取颁发者超时 (`DeadlineExceededDuringSyncGetIssuers`):** 测试了在同步获取中间证书颁发者信息时，如果超过了预设的截止时间，证书验证过程会如何处理，并验证是否会返回部分构建的证书链以及 `ERR_CERT_AUTHORITY_INVALID` 错误。
* **未知或无法解析的签名算法 (`UnknownSignatureAlgorithmTarget`, `UnparsableMismatchedTBSSignatureAlgorithmTarget`, `UnknownSignatureAlgorithmIntermediate`, `UnparsableMismatchedTBSSignatureAlgorithmIntermediate`, `UnknownSignatureAlgorithmRoot`, `MAYBE_UnparsableMismatchedTBSSignatureAlgorithmRoot`):** 测试了当证书（目标证书、中间证书、根证书）的签名算法是未知或者无法解析时，证书验证过程的行为。它特别关注了 `tbsCertificate` 部分的签名算法与实际签名算法不匹配的情况。
* **路径构建迭代限制 (`IterationLimit`):**  测试了当存在大量可能的证书路径时，路径构建器是否会因为达到迭代次数限制而停止，并返回相应的错误。

**与 JavaScript 的关系：**

这些测试的功能与 JavaScript 在网络安全方面密切相关。当 JavaScript 代码发起 HTTPS 请求时，浏览器会使用底层的网络栈进行安全连接的建立，其中就包括证书验证。

* **证书验证失败导致连接失败:** 如果这里测试的任何约束条件不满足，或者证书的签名算法存在问题，`CertVerifyProcBuiltin` 会返回错误，导致 HTTPS 连接建立失败。这会直接影响到 JavaScript 代码发起的网络请求，例如 `fetch()` 或 `XMLHttpRequest` 会抛出错误，或者浏览器会显示安全警告，阻止 JavaScript 代码的执行。
* **影响 JavaScript 能否安全地与服务器通信:**  证书验证的目的是确保 JavaScript 代码正在与预期的服务器进行通信，而不是中间人攻击。这些测试保证了浏览器能够正确地执行这些安全检查。

**逻辑推理、假设输入与输出：**

**示例 1: 版本约束**

* **假设输入:**
    * 一个证书链，其根证书的版本低于 Chrome 根证书存储中设置的 `min_version`。
    * `SetMockChromeRootConstraints` 被调用，设置了 `min_version` 为一个未来的版本字符串。
* **预期输出:**
    * `Verify` 函数返回的 `error` 为 `ERR_CERT_AUTHORITY_INVALID`。

**示例 2: 名称约束**

* **假设输入:**
    * 一个证书链，其目标证书的域名是 "www.example.com"。
    * `SetMockChromeRootConstraints` 被调用，设置了 `permitted_dns_names` 为 `{"example.org", "foo.example.com"}`。
* **预期输出:**
    * `Verify` 函数返回的 `error` 为 `ERR_CERT_AUTHORITY_INVALID`。

**示例 3: 同步获取颁发者超时**

* **假设输入:**
    * 一个三级证书链（leaf -> intermediate -> root）。
    * 中间证书存在于一个会阻塞 `SyncGetIssuersOf` 调用的 `BlockingTrustStore` 中。
    * 在 `SyncGetIssuersOf` 被调用后，系统时间被推进超过了证书验证的截止时间。
* **预期输出:**
    * `Verify` 函数返回的 `error` 为 `ERR_CERT_AUTHORITY_INVALID`。
    * `verify_result.verified_cert->intermediate_buffers()` 中包含中间证书。

**用户或编程常见的使用错误：**

* **配置错误的 Chrome 根证书存储:** 虽然用户无法直接修改 Chrome 根证书存储，但在某些开发或测试场景下，可能会人为地配置错误的约束条件，导致原本有效的证书被判定为无效。
* **服务器使用了不满足 Chrome 根证书存储约束的证书:**  如果网站的服务器使用了版本过旧、域名不符合约束或者使用了未知签名算法的根证书，Chrome 浏览器会拒绝连接。
* **本地系统时间不正确:**  对于版本约束等基于时间的约束，如果用户的本地系统时间不准确，可能会导致证书验证失败。
* **中间证书缺失或不可访问:**  在 `DeadlineExceededDuringSyncGetIssuers` 测试的场景中，如果中间证书信息获取超时，会导致验证失败。这可能是由于网络问题或者中间证书的存储不可用造成的。
* **在构建证书链时使用了不支持的签名算法:**  开发者在创建自签名证书或测试证书链时，可能会错误地使用了浏览器不支持的签名算法。

**用户操作到达这里的调试线索：**

以下是用户操作如何一步步地可能触发到这些证书验证逻辑的场景：

1. **用户在 Chrome 浏览器中输入一个 HTTPS 网址并访问。**
2. **Chrome 的网络栈开始建立与服务器的安全连接。**
3. **服务器向浏览器发送其证书链。**
4. **`CertVerifyProcBuiltin` 类被调用来验证服务器发送的证书链。**
5. **在验证过程中，会检查 Chrome 根证书存储的约束条件：**
    * **版本约束:**  检查根证书的版本是否在允许的范围内。
    * **名称约束:** 检查目标证书的域名是否在根证书允许的域名列表中。
    * **签名算法:** 检查证书使用的签名算法是否被浏览器支持。
6. **如果任何约束条件不满足，或者证书存在签名算法问题，`CertVerifyProcBuiltin` 会返回错误，导致连接失败。**
7. **在调试模式下，开发者可以通过 Chrome 的 `net-internals` 工具 (chrome://net-internals/#events) 观察到证书验证的详细过程，包括是否应用了 Chrome 根证书存储的约束，以及具体的错误信息。**
8. **开发者也可以通过抓包工具（如 Wireshark）查看服务器发送的证书链，以及浏览器和服务器之间的 TLS 握手过程。**
9. **如果怀疑是 Chrome 根证书存储约束导致的问题，开发者可以尝试禁用 Chrome 根证书存储功能（虽然不建议在生产环境进行此操作）进行排查。**

**总结来说，这部分单元测试主要验证了 Chromium 的内置证书验证过程如何正确地实施和处理 Chrome 根证书存储中定义的各种约束条件，以及在遇到错误情况时的行为。这对于确保 HTTPS 连接的安全性和防止中间人攻击至关重要。**

Prompt: 
```
这是目录为net/cert/cert_verify_proc_builtin_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
();
    EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  }

  // min_version not satisfied, max_version_exclusive satisfied = not trusted.
  SetMockChromeRootConstraints(
      {{.min_version = NextVersionString(),
        .max_version_exclusive = NextVersionString()}});
  {
    CertVerifyResult verify_result;
    NetLogSource verify_net_log_source;
    TestCompletionCallback callback;
    Verify(chain.get(), "www.example.com",
           /*flags=*/0, &verify_result, &verify_net_log_source,
           callback.callback());

    int error = callback.WaitForResult();
    EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  }

  // min_version satisfied, max_version_exclusive satisfied = trusted.
  SetMockChromeRootConstraints(
      {{.min_version = CurVersionString(),
        .max_version_exclusive = NextVersionString()}});
  {
    CertVerifyResult verify_result;
    NetLogSource verify_net_log_source;
    TestCompletionCallback callback;
    Verify(chain.get(), "www.example.com",
           /*flags=*/0, &verify_result, &verify_net_log_source,
           callback.callback());

    int error = callback.WaitForResult();
    EXPECT_THAT(error, IsOk());
  }
}

TEST_F(CertVerifyProcBuiltinTest, ChromeRootStoreConstraintNameConstraints) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();
  ScopedTestRoot scoped_root(root->GetX509Certificate());

  // If the the CRS root has dns name constraints and the cert's names don't
  // match the name constraints, verification should fail.
  {
    std::array<std::string_view, 2> permitted_dns_names = {
        std::string_view("example.org"),
        std::string_view("foo.example.com"),
    };
    SetMockChromeRootConstraints(
        {{.permitted_dns_names = permitted_dns_names}});
    CertVerifyResult verify_result;
    NetLogSource verify_net_log_source;
    TestCompletionCallback callback;
    Verify(leaf->GetX509Certificate(), "www.example.com",
           /*flags=*/0, &verify_result, &verify_net_log_source,
           callback.callback());

    int error = callback.WaitForResult();
    EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  }

  // If cert's names match the CRS name constraints, verification should
  // succeed.
  {
    std::array<std::string_view, 2> permitted_dns_names = {
        std::string_view("example.org"),
        std::string_view("example.com"),
    };
    SetMockChromeRootConstraints(
        {{.permitted_dns_names = permitted_dns_names}});
    CertVerifyResult verify_result;
    NetLogSource verify_net_log_source;
    TestCompletionCallback callback;
    Verify(leaf->GetX509Certificate(), "www.example.com",
           /*flags=*/0, &verify_result, &verify_net_log_source,
           callback.callback());

    int error = callback.WaitForResult();
    EXPECT_THAT(error, IsOk());
  }
}

// Tests multiple constraint objects in the constraints vector. The CRS
// constraints are satisfied if at least one of the constraint objects is
// satisfied.
//
// The first constraint has a SctNotAfter that is before the SCT and thus is
// not satisfied.
// The second constraint has a SctAllAfter set to the same time, which is
// before the certificate SCT, and thus the certificate verification succeeds.
//
// TODO(https://crbug.com/40941039): This test isn't very interesting right
// now. Once more constraint types are added change the test to be more
// realistic of how multiple constraint sets is expected to be used.
TEST_F(CertVerifyProcBuiltinTest,
       ChromeRootStoreConstraintMultipleConstraints) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();
  ScopedTestRoot scoped_root(root->GetX509Certificate());

  const std::string kSctList = "SCT list";
  const std::string kLog1 = "log1";
  base::Time now = base::Time::Now();
  base::Time t1 = now - base::Days(2);
  base::Time t2 = now - base::Days(1);
  SignedCertificateTimestampAndStatusList sct_and_status_list;
  sct_and_status_list.emplace_back(MakeSct(t2, kLog1), ct::SCT_STATUS_OK);

  EXPECT_CALL(*mock_ct_policy_enforcer(), IsCtEnabled())
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*mock_ct_verifier(), Verify(_, _, kSctList, _, _, _))
      .WillOnce(testing::SetArgPointee<4>(sct_and_status_list));
  EXPECT_CALL(*mock_ct_policy_enforcer(), GetLogDisqualificationTime(kLog1))
      .WillRepeatedly(testing::Return(std::nullopt));
  EXPECT_CALL(*mock_ct_policy_enforcer(), CheckCompliance(_, _, _, _))
      .WillRepeatedly(
          testing::Return(ct::CTPolicyCompliance::CT_POLICY_COMPLIES_VIA_SCTS));

  SetMockChromeRootConstraints({{.sct_not_after = t1}, {.sct_all_after = t1}});

  scoped_refptr<X509Certificate> chain = leaf->GetX509Certificate();
  ASSERT_TRUE(chain.get());

  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", /*ocsp_response=*/std::string(),
         kSctList, /*flags=*/0, &verify_result, &verify_net_log_source,
         callback.callback());

  int error = callback.WaitForResult();
  EXPECT_THAT(error, IsOk());
}

TEST_F(CertVerifyProcBuiltinTest,
       ChromeRootStoreConstraintNotEnforcedIfAnchorLocallyTrusted) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509Certificate();
  ASSERT_TRUE(chain.get());

  SetMockChromeRootConstraints({{.min_version = NextVersionString()}});
  {
    CertVerifyResult verify_result;
    NetLogSource verify_net_log_source;
    TestCompletionCallback callback;
    Verify(chain.get(), "www.example.com",
           /*flags=*/0, &verify_result, &verify_net_log_source,
           callback.callback());

    int error = callback.WaitForResult();
    EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  }

  // If the anchor is trusted locally, the Chrome Root Store constraints should
  // not be enforced.
  SetMockIsLocallyTrustedRoot(true);
  {
    CertVerifyResult verify_result;
    NetLogSource verify_net_log_source;
    TestCompletionCallback callback;
    Verify(chain.get(), "www.example.com",
           /*flags=*/0, &verify_result, &verify_net_log_source,
           callback.callback());

    int error = callback.WaitForResult();
    EXPECT_THAT(error, IsOk());
  }
}

TEST_F(CertVerifyProcBuiltinTest,
       ChromeRootStoreConstraintNotEnforcedIfAnchorAdditionallyTrusted) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();
  // The anchor is trusted through additional_trust_anchors, so the Chrome Root
  // Store constraints should not be enforced.
  InitializeVerifyProc(CreateParams(
      /*additional_trust_anchors=*/{root->GetX509Certificate()}));
  scoped_refptr<X509Certificate> chain = leaf->GetX509Certificate();
  ASSERT_TRUE(chain.get());

  SetMockChromeRootConstraints({{.min_version = NextVersionString()}});

  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com",
         /*flags=*/0, &verify_result, &verify_net_log_source,
         callback.callback());

  int error = callback.WaitForResult();
  EXPECT_THAT(error, IsOk());
}
#endif  // BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)

TEST_F(CertVerifyProcBuiltinTest, DeadlineExceededDuringSyncGetIssuers) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  InitializeVerifyProc(CreateParams(
      /*additional_trust_anchors=*/{root->GetX509Certificate()}));

  BlockingTrustStore trust_store;
  AddTrustStore(&trust_store);

  auto intermediate_parsed_cert = bssl::ParsedCertificate::Create(
      intermediate->DupCertBuffer(), {}, nullptr);
  ASSERT_TRUE(intermediate_parsed_cert);
  trust_store.backing_trust_store_.AddCertificateWithUnspecifiedTrust(
      intermediate_parsed_cert);

  scoped_refptr<X509Certificate> chain = leaf->GetX509Certificate();
  ASSERT_TRUE(chain.get());

  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback verify_callback;
  Verify(chain.get(), "www.example.com",
         /*flags=*/0,
         &verify_result, &verify_net_log_source, verify_callback.callback());

  // Wait for trust_store.SyncGetIssuersOf to be called.
  trust_store.sync_get_issuer_started_event_.Wait();

  // Advance the clock past the verifier deadline.
  const base::TimeDelta timeout_increment =
      GetCertVerifyProcBuiltinTimeLimitForTesting() + base::Milliseconds(1);
  task_environment().AdvanceClock(timeout_increment);

  // Signal trust_store.SyncGetIssuersOf to finish.
  trust_store.sync_get_issuer_ok_to_finish_event_.Signal();

  int error = verify_callback.WaitForResult();
  // Because the deadline was reached while retrieving the intermediate, path
  // building should have stopped there and not found the root. The partial
  // path built up to that point should be returned, and the error should be
  // CERT_AUTHORITY_INVALID.
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  ASSERT_EQ(1u, verify_result.verified_cert->intermediate_buffers().size());
  EXPECT_EQ(intermediate->GetCertBuffer(),
            verify_result.verified_cert->intermediate_buffers()[0].get());
}

namespace {

// Returns a TLV to use as an unknown signature algorithm when building a cert.
// The specific contents are as follows (the OID is from
// https://davidben.net/oid):
//
// SEQUENCE {
//   OBJECT_IDENTIFIER { 1.2.840.113554.4.1.72585.0 }
//   NULL {}
// }
std::string UnknownSignatureAlgorithmTLV() {
  const uint8_t kInvalidSignatureAlgorithmTLV[] = {
      0x30, 0x10, 0x06, 0x0c, 0x2a, 0x86, 0x48, 0x86, 0xf7,
      0x12, 0x04, 0x01, 0x84, 0xb7, 0x09, 0x00, 0x05, 0x00};
  return std::string(std::begin(kInvalidSignatureAlgorithmTLV),
                     std::end(kInvalidSignatureAlgorithmTLV));
}

// Returns a TLV to use as an invalid signature algorithm when building a cert.
// This is a SEQUENCE so that it will pass the bssl::ParseCertificate code
// and fail inside bssl::ParseSignatureAlgorithm.
// SEQUENCE {
//   INTEGER { 42 }
// }
std::string InvalidSignatureAlgorithmTLV() {
  const uint8_t kInvalidSignatureAlgorithmTLV[] = {0x30, 0x03, 0x02, 0x01,
                                                   0x2a};
  return std::string(std::begin(kInvalidSignatureAlgorithmTLV),
                     std::end(kInvalidSignatureAlgorithmTLV));
}

}  // namespace

TEST_F(CertVerifyProcBuiltinTest, UnknownSignatureAlgorithmTarget) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  leaf->SetSignatureAlgorithmTLV(UnknownSignatureAlgorithmTLV());

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  int flags = 0;
  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", flags, &verify_result,
         &verify_net_log_source, callback.callback());
  int error = callback.WaitForResult();
  // Unknown signature algorithm in the leaf cert should result in the cert
  // being invalid.
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_INVALID);
  EXPECT_THAT(error, IsError(ERR_CERT_INVALID));
}

TEST_F(CertVerifyProcBuiltinTest,
       UnparsableMismatchedTBSSignatureAlgorithmTarget) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();
  // Set only the tbsCertificate signature to an invalid value.
  leaf->SetTBSSignatureAlgorithmTLV(InvalidSignatureAlgorithmTLV());

  // Trust the root and build a chain to verify.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  int flags = 0;
  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", flags, &verify_result,
         &verify_net_log_source, callback.callback());
  int error = callback.WaitForResult();
  // Invalid signature algorithm in the leaf cert should result in the
  // cert being invalid.
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_INVALID);
  EXPECT_THAT(error, IsError(ERR_CERT_INVALID));
}

TEST_F(CertVerifyProcBuiltinTest, UnknownSignatureAlgorithmIntermediate) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  intermediate->SetSignatureAlgorithmTLV(UnknownSignatureAlgorithmTLV());

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  int flags = 0;
  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", flags, &verify_result,
         &verify_net_log_source, callback.callback());
  int error = callback.WaitForResult();
  // Unknown signature algorithm in the intermediate cert should result in the
  // cert being invalid.
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_INVALID);
  EXPECT_THAT(error, IsError(ERR_CERT_INVALID));
}

TEST_F(CertVerifyProcBuiltinTest,
       UnparsableMismatchedTBSSignatureAlgorithmIntermediate) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  // Set only the tbsCertificate signature to an invalid value.
  intermediate->SetTBSSignatureAlgorithmTLV(InvalidSignatureAlgorithmTLV());

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());
  ASSERT_EQ(chain->intermediate_buffers().size(), 1U);

  int flags = 0;
  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", flags, &verify_result,
         &verify_net_log_source, callback.callback());
  int error = callback.WaitForResult();
  // Invalid signature algorithm in the intermediate cert should result in the
  // cert being invalid.
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_INVALID);
  EXPECT_THAT(error, IsError(ERR_CERT_INVALID));
}

TEST_F(CertVerifyProcBuiltinTest, UnknownSignatureAlgorithmRoot) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  root->SetSignatureAlgorithmTLV(UnknownSignatureAlgorithmTLV());

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  int flags = 0;
  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", flags, &verify_result,
         &verify_net_log_source, callback.callback());
  int error = callback.WaitForResult();
  // Unknown signature algorithm in the root cert should have no effect on
  // verification.
  EXPECT_THAT(error, IsOk());
}

// This test is disabled on Android as adding the invalid root through
// ScopedTestRoot causes it to be parsed by the Java X509 code which barfs. We
// could re-enable if Chrome on Android has fully switched to the
// builtin-verifier and ScopedTestRoot no longer has Android-specific code.
#if BUILDFLAG(IS_ANDROID)
#define MAYBE_UnparsableMismatchedTBSSignatureAlgorithmRoot \
  DISABLED_UnparsableMismatchedTBSSignatureAlgorithmRoot
#else
#define MAYBE_UnparsableMismatchedTBSSignatureAlgorithmRoot \
  UnparsableMismatchedTBSSignatureAlgorithmRoot
#endif
TEST_F(CertVerifyProcBuiltinTest,
       MAYBE_UnparsableMismatchedTBSSignatureAlgorithmRoot) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  // Set only the tbsCertificate signature to an invalid value.
  root->SetTBSSignatureAlgorithmTLV(InvalidSignatureAlgorithmTLV());

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  int flags = 0;
  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", flags, &verify_result,
         &verify_net_log_source, callback.callback());
  int error = callback.WaitForResult();
  // Invalid signature algorithm in the root cert should have no effect on
  // verification.
  EXPECT_THAT(error, IsOk());
}

TEST_F(CertVerifyProcBuiltinTest, IterationLimit) {
  // Create a chain which will require many iterations in the path builder.
  std::vector<std::unique_ptr<CertBuilder>> builders =
      CertBuilder::CreateSimpleChain(6);

  base::Time not_before = base::Time::Now() - base::Days(1);
  base::Time not_after = base::Time::Now() + base::Days(1);
  for (auto& builder : builders) {
    builder->SetValidity(not_before, not_after);
  }

  // Generate certificates, making two versions of each intermediate.
  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
  for (size_t i = 1; i < builders.size(); i++) {
    intermediates.push_back(builders[i]->DupCertBuffer());
    builders[i]->SetValidity(not_before, not_after + base::Seconds(1));
    intermediates.push_back(builders[i]->DupCertBuffer());
  }

  // The above alone is enough to make the path builder explore many paths, but
  // it will always return the best path it has found, so the error will be the
  // same. Instead, arrange for all those paths to be invalid (untrusted root),
  // and add a separate chain that is valid.
  CertBuilder root_ok(/*orig_cert=*/builders[2]->GetCertBuffer(),
                      /*issuer=*/nullptr);
  CertBuilder intermediate_ok(/*orig_cert=*/builders[1]->GetCertBuffer(),
                              /*issuer=*/&root_ok);
  // Using the old intermediate as a template does not preserve the subject,
  // SKID, or key.
  intermediate_ok.SetSubjectTLV(base::as_byte_span(builders[1]->GetSubject()));
  intermediate_ok.SetKey(bssl::UpRef(builders[1]->GetKey()));
  intermediate_ok.SetSubjectKeyIdentifier(
      builders[1]->GetSubjectKeyIdentifier());
  // Make the valid intermediate older than the invalid ones, so that it is
  // explored last.
  intermediate_ok.SetValidity(not_before - base::Seconds(10),
                              not_after - base::Seconds(10));
  intermediates.push_back(intermediate_ok.DupCertBuffer());

  // Verify the chain.
  ScopedTestRoot scoped_root(root_ok.GetX509Certificate().get());
  scoped_refptr<X509Certificate> chain = X509Certificate::CreateFromBuffer(
      builders[0]->DupCertBuffer(), std::move(intermediates));
  ASSERT_TRUE(chain.get());

  RecordingNetLogObserver net_log_observer(NetLogCaptureMode::kDefault);
  int flags = 0;
  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", flags, &verify_result,
         &verify_net_log_source, callback.callback());
  int error = callback.WaitForResult();

  auto events = net_log_observer.GetEntriesForSource(verify_net_log_source);
  auto event = base::ranges::find_if(events, [](const NetLogEntry& e) {
    return e.type == NetLogEventType::CERT_VERIFY_PROC_PATH_BUILD_ATTEMPT &&
           e.phase == NetLogEventPhase::END;
  });
  ASSERT_NE(event, events.end());

  // The path builder gives up before it finishes all the invalid paths.
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_AUTHORITY_INVALID);
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  EXPECT_EQ(true, event->params.FindBool("exceeded_iteration_limit"));
}

}  // namespace net

"""


```