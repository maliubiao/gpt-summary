Response:
The user wants to understand the functionality of the provided C++ code snippet from `cert_verify_proc_builtin_unittest.cc`. This file is part of Chromium's network stack and is used for unit testing the built-in certificate verification process.

Here's a breakdown of the thought process to analyze the code:

1. **Identify the Core Functionality:** The filename and the test fixture name (`CertVerifyProcBuiltinTest`) strongly suggest that this code is testing the built-in certificate verification logic. The tests use a `Verify` function, which is central to this process.

2. **Examine Individual Tests:** Go through each `TEST_F` function to understand what specific aspect of certificate verification is being tested.

    * **`CRLNotCheckedForLocallyTrustedRoots`:** This test checks that CRL (Certificate Revocation List) checking is skipped when the root certificate is explicitly trusted (added to the `additional_trust_anchors_with_enforced_constraints`). This is a performance optimization in cases where trust is pre-established.

    * **`CRLNotCheckedForKnownRoots`:** This test verifies that CRL checking is also skipped for root certificates that are part of the browser's built-in trust store ("known roots"). This is another performance optimization. It tests the behavior with and without marking the root as a "known root" using `SetMockIsKnownRoot(true)`.

    * **`RevocationCheckDeadlineCRL`:** This test focuses on the behavior when revocation checking (using CRLs) times out. It simulates this by making several requests to CRL endpoints that intentionally hang. The test verifies that the system stops making further requests after the deadline and doesn't crash or get stuck.

    * **`RevocationCheckDeadlineOCSP`:** Similar to the previous test, but this one focuses on OCSP (Online Certificate Status Protocol) revocation checking and its behavior under timeout conditions.

    * **`EVNoOCSPRevocationChecks`:** This test checks that OCSP revocation checks are not performed for certificates that qualify for Extended Validation (EV). EV certificates have stricter validation requirements, and OCSP checks might be considered redundant or add unnecessary latency.

    * **Tests with `ChromeRootStoreConstraint...`:**  These tests focus on the Chrome Root Store and its ability to impose constraints on certificates issued by those roots. The constraints tested involve Signed Certificate Timestamps (SCTs) and versioning.

        * **`...WithCtDisabled`:**  Checks that SCT constraints are ignored if Certificate Transparency (CT) is disabled.

        * **`...SctNotAfter`:** Tests the `sct_not_after` constraint, which requires at least one valid SCT with a timestamp before the specified time.

        * **`...SctNotAfterLogUnknown`:** Tests that SCTs from unknown logs don't satisfy the `sct_not_after` constraint.

        * **`...SctNotAfterFromDisqualifiedLogBeforeDisqualification` & `...AfterDisqualification`:** Tests that SCTs from logs that have been disqualified do not satisfy the `sct_not_after` constraint, regardless of whether the SCT timestamp is before or after the disqualification.

        * **`...SctNotAfterFromFutureDisqualifiedLog`:** Tests that an SCT from a log that *will* be disqualified in the future *does* satisfy the constraint if its timestamp is before the constraint.

        * **`...SctAllAfter`:** Tests the `sct_all_after` constraint, requiring *all* valid SCTs to have timestamps after the specified time.

        * **`...MinVersion` & `...MaxVersion` & `...MinAndMaxVersion`:** Test constraints based on the minimum and maximum allowed Chrome version.

3. **Identify Relationships to JavaScript:**  While the core logic is in C++, these tests touch on security features that have implications for web browsing, which is heavily reliant on JavaScript. Specifically:

    * **Certificate Revocation:** If a certificate is revoked, browsers need to know this to prevent users from connecting to potentially malicious sites. JavaScript code interacting with HTTPS websites will be affected by successful revocation checking (or lack thereof due to optimizations).
    * **Extended Validation (EV):** The presence of EV certificates is often indicated in the browser's UI, and JavaScript code might have access to information about the security state of a connection.
    * **Certificate Transparency (CT):**  CT is a mechanism to ensure that TLS certificates are publicly logged. While not directly interacted with by most JavaScript, its presence is a security indicator. JavaScript making secure requests relies on the underlying CT verification.

4. **Infer User Actions and Debugging:** Consider how a user might end up triggering this code path and how a developer might use these tests for debugging:

    * **User Actions:**  A user simply browsing the web and accessing HTTPS websites will trigger certificate verification. Specific scenarios could involve:
        * Visiting a website with a certificate issued by a locally trusted root.
        * Visiting a website with a certificate issued by a well-known CA.
        * Visiting a website with a revoked certificate.
        * Visiting a website with an EV certificate.
        * Visiting a website that requires CT.
    * **Debugging:** Developers working on the network stack, particularly certificate handling, would use these unit tests to:
        * Verify that changes to the verification logic don't break existing behavior.
        * Test new features, like the Chrome Root Store constraints.
        * Isolate and reproduce bugs related to certificate verification.

5. **Construct Hypothesized Inputs and Outputs:** For each test, imagine the specific setup (certificate chains, mocked behaviors, server responses) and the expected outcome (success or a specific error code). This helps to solidify understanding.

6. **Identify Common Errors:** Think about the types of mistakes developers might make when working with certificate verification:
    * Incorrectly handling revocation status.
    * Not considering timeout scenarios.
    * Not properly implementing or testing CT requirements.
    * Making assumptions about the behavior of trusted roots.

7. **Synthesize a Summary:** Combine the findings from the individual tests and broader context into a concise summary of the code's functionality.
这是`net/cert/cert_verify_proc_builtin_unittest.cc` 文件的一部分，主要功能是**测试内置的证书验证过程（Built-in CertVerifyProc）的各种场景和行为，特别关注证书吊销检查和 Chrome Root Store 的约束机制。**

**具体来说，这部分代码测试了以下功能点：**

1. **已知根证书的 CRL 检查豁免：**
   - **`CRLNotCheckedForLocallyTrustedRoots` 测试：**  验证当证书链的根证书被显式添加到信任锚点（`additional_trust_anchors_with_enforced_constraints`）时，即使叶子证书的 CRL 分发点指向一个撤销了该证书的 CRL，验证仍然会成功。这表明对于显式信任的根证书，CRL 检查会被跳过。
   - **`CRLNotCheckedForKnownRoots` 测试：** 验证对于浏览器内置信任的根证书（"known roots"），即使配置了启用吊销检查，也不会进行 CRL 检查。这个测试模拟了根证书是否是 "known root" 两种情况。

2. **吊销检查的超时处理：**
   - **`RevocationCheckDeadlineCRL` 测试：** 模拟在 CRL 吊销检查过程中，如果超过了验证截止时间，系统将不会尝试进一步的 CRL 获取。它通过设置多个会挂起的 CRL 分发点 URL 来实现超时。
   - **`RevocationCheckDeadlineOCSP` 测试：**  类似地，模拟在 OCSP 吊销检查过程中，如果超过了验证截止时间，系统将不会尝试进一步的 OCSP 获取。

3. **EV 证书的 OCSP 检查豁免：**
   - **`EVNoOCSPRevocationChecks` 测试：** 验证对于符合 Extended Validation (EV) 规范的证书，不会进行 OCSP 吊销检查。即使中间证书配置了会触发测试失败的 OCSP URL，也不会被请求。

4. **Chrome Root Store 的约束机制：** 这部分测试针对使用 Chrome Root Store 的根证书所施加的各种约束。
   - **SCT 约束和 CT 未启用时的行为：**
     - **`ChromeRootStoreConstraintSctConstraintsWithCtDisabled` 测试：**  验证当 Certificate Transparency (CT) 功能被禁用时，即使根证书设置了 `sct_not_after` 或 `sct_all_after` 的约束，验证过程也会忽略这些约束并成功。
   - **`SctNotAfter` 约束：**
     - **`ChromeRootStoreConstraintSctNotAfter` 测试：** 验证 `sct_not_after` 约束，它要求证书必须至少有一个有效的 SCT，且该 SCT 的时间戳早于约束指定的时间。
     - **`ChromeRootStoreConstraintSctNotAfterLogUnknown` 测试：** 验证来自未知日志的 SCT 不会被计入 `sct_not_after` 约束的满足条件。
     - **`ChromeRootStoreConstraintSctNotAfterFromDisqualifiedLogBeforeDisqualification` 和 `ChromeRootStoreConstraintSctNotAfterFromDisqualifiedLogAfterDisqualification` 测试：** 验证来自已被取消资格的日志的 SCT 不会被计入 `sct_not_after` 约束的满足条件，无论 SCT 的时间戳是否在取消资格之前。
     - **`ChromeRootStoreConstraintSctNotAfterFromFutureDisqualifiedLog` 测试：** 验证如果一个日志在未来会被取消资格，那么在该取消资格时间之前由该日志签发的 SCT 仍然可以满足 `sct_not_after` 约束。
   - **`SctAllAfter` 约束：**
     - **`ChromeRootStoreConstraintSctAllAfter` 测试：** 验证 `sct_all_after` 约束，它要求证书的所有有效 SCT 的时间戳都晚于约束指定的时间。
   - **版本约束：**
     - **`ChromeRootStoreConstraintMinVersion` 测试：** 验证 `min_version` 约束，它要求 Chrome 的版本必须大于或等于约束指定的版本。
     - **`ChromeRootStoreConstraintMaxVersion` 测试：** 验证 `max_version_exclusive` 约束，它要求 Chrome 的版本必须小于约束指定的版本。
     - **`ChromeRootStoreConstraintMinAndMaxVersion` 测试：** 同时测试 `min_version` 和 `max_version_exclusive` 约束的组合使用。

**与 JavaScript 的关系：**

这些测试虽然是 C++ 代码，但直接影响了浏览器在处理 HTTPS 连接时的行为，这与 JavaScript 功能息息相关。

* **证书吊销检查：** 当 JavaScript 代码发起 HTTPS 请求时，浏览器会进行证书验证，包括吊销检查。如果证书被吊销，浏览器会阻止连接，JavaScript 代码可能会收到网络错误，例如 `net::ERR_CERT_REVOKED`。
* **EV 证书：**  JavaScript 代码可以通过某些 API（尽管通常不直接访问证书细节）间接地知道当前连接是否使用了 EV 证书。例如，浏览器可能会在地址栏显示特殊的指示器，而 JavaScript 可以通过检测这些 UI 变化来感知。
* **Chrome Root Store 和 CT：**  JavaScript 代码本身通常不直接处理 Chrome Root Store 的约束或 CT 信息。然而，这些底层的安全机制保证了 HTTPS 连接的安全性。如果一个证书违反了 Chrome Root Store 的约束（例如，SCT 不满足要求），浏览器会阻止连接，JavaScript 代码同样会遇到网络错误。

**假设输入与输出 (以 `CRLNotCheckedForLocallyTrustedRoots` 为例)：**

**假设输入：**

* 创建一个自签名根证书 `root`。
* 创建一个由 `root` 签名的叶子证书 `leaf`。
* 将 `root` 添加到 `additional_trust_anchors_with_enforced_constraints`，使其成为本地显式信任的根证书。
* 配置一个 HTTP 测试服务器，并设置一个 CRL 端点，该 CRL 将 `leaf` 标记为已吊销。
* 使用 `CertVerifyProc::VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS` 标志进行证书验证。

**预期输出：**

* 证书验证应该成功 (`error` 为 `IsOk()`)。
* 即使 CRL 表明叶子证书已被吊销，由于根证书是本地显式信任的，CRL 检查被跳过。

**用户或编程常见的使用错误：**

* **错误地假设本地信任的证书总是会被检查吊销：** 开发者可能会认为设置了吊销检查标志就一定会执行检查，而忽略了本地信任根证书的特殊性。
* **在测试或开发环境中使用自签名证书但不将其添加到信任列表：**  这会导致证书验证失败。正确的做法是将这些证书添加到操作系统的信任存储或 Chromium 的特定配置中。
* **没有考虑到吊销检查可能超时的情况：**  如果依赖于实时的吊销检查，而网络环境不稳定，可能会导致连接失败。应该考虑使用软失败等策略。
* **对 Chrome Root Store 的约束理解不足：** 开发者可能不清楚特定根证书可能存在的 SCT 或版本约束，导致使用了不符合要求的证书。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户尝试访问一个 HTTPS 网站。**
2. **浏览器开始与服务器建立 TLS 连接。**
3. **服务器提供其证书链。**
4. **浏览器调用 `CertVerifyProcBuiltin` 来验证证书链。**
5. **如果证书链的根证书与 `additional_trust_anchors_with_enforced_constraints` 中的某项匹配（例如，用户手动添加了该根证书），则会触发 `CRLNotCheckedForLocallyTrustedRoots` 测试所覆盖的逻辑。**
6. **如果证书链的根证书是浏览器内置信任的根证书，且设置了跳过 CRL 检查的策略，则会触发 `CRLNotCheckedForKnownRoots` 测试所覆盖的逻辑。**
7. **如果启用了吊销检查，并且在获取 CRL 或 OCSP 响应时网络延迟过高，则会触发 `RevocationCheckDeadlineCRL` 或 `RevocationCheckDeadlineOCSP` 测试所覆盖的超时处理逻辑。**
8. **如果访问的网站使用了 EV 证书，并且浏览器正在执行证书验证，则会触发 `EVNoOCSPRevocationChecks` 测试所覆盖的逻辑。**
9. **如果证书链的根证书属于 Chrome Root Store，并且设置了 SCT 或版本约束，则会触发相应的 `ChromeRootStoreConstraint...` 测试所覆盖的逻辑。**

**归纳一下它的功能：**

这部分代码的主要功能是**详尽地测试 Chromium 内置证书验证过程的关键特性，包括对本地信任和已知根证书的 CRL 检查优化、吊销检查的超时处理、EV 证书的 OCSP 检查豁免以及 Chrome Root Store 的各种约束机制。** 这些测试确保了 Chromium 在处理各种证书场景时的正确性和安全性。

### 提示词
```
这是目录为net/cert/cert_verify_proc_builtin_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
nd succeed.
  InitializeVerifyProc(
      CreateParams(
          /*additional_trust_anchors=*/{},
          /*additional_trust_anchors_with_enforced_constraints=*/
          {root->GetX509Certificate()},
          /*additional_distrusted_certificates=*/{}),
      base::Time::Now() - base::Days(2));

  EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTP);
  ASSERT_TRUE(test_server.InitializeAndListen());
  // Valid CRL that does not mark the leaf as revoked.
  leaf->SetCrlDistributionPointUrl(
      CreateAndServeCrl(&test_server, root.get(), {1234}));
  test_server.StartAcceptingConnections();

  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com",
         CertVerifyProc::VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS,
         &verify_result, &verify_net_log_source, callback.callback());

  int error = callback.WaitForResult();
  EXPECT_THAT(error, IsOk());
}

TEST_F(CertVerifyProcBuiltinTest, CRLNotCheckedForKnownRoots) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();
  InitializeVerifyProc(CreateParams(
      /*additional_trust_anchors=*/{root->GetX509Certificate()}));

  EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTP);
  ASSERT_TRUE(test_server.InitializeAndListen());

  // CRL that marks leaf as revoked.
  leaf->SetCrlDistributionPointUrl(
      CreateAndServeCrl(&test_server, root.get(), {leaf->GetSerialNumber()}));

  test_server.StartAcceptingConnections();

  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  NetLogSource verify_net_log_source;

  {
    CertVerifyResult verify_result;
    TestCompletionCallback verify_callback;
    Verify(chain.get(), "www.example.com",
           CertVerifyProc::VERIFY_REV_CHECKING_ENABLED,
           &verify_result, &verify_net_log_source, verify_callback.callback());

    int error = verify_callback.WaitForResult();
    EXPECT_THAT(error, IsError(ERR_CERT_REVOKED));
    EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
  }

  {
    // Pretend the root is a known root.
    SetMockIsKnownRoot(true);
    CertVerifyResult verify_result;
    TestCompletionCallback verify_callback;
    Verify(chain.get(), "www.example.com",
           CertVerifyProc::VERIFY_REV_CHECKING_ENABLED,
           &verify_result, &verify_net_log_source, verify_callback.callback());

    int error = verify_callback.WaitForResult();
    // CRLs are not checked for chains issued by known roots, so verification
    // should be successful.
    EXPECT_THAT(error, IsOk());
    EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
  }
}

// Tests that if the verification deadline is exceeded during revocation
// checking, additional CRL fetches will not be attempted.
TEST_F(CertVerifyProcBuiltinTest, RevocationCheckDeadlineCRL) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  InitializeVerifyProc(CreateParams(
      /*additional_trust_anchors=*/{root->GetX509Certificate()}));

  const base::TimeDelta timeout_increment =
      CertNetFetcherURLRequest::GetDefaultTimeoutForTesting() +
      base::Milliseconds(1);
  const int expected_request_count =
      base::ClampFloor(GetCertVerifyProcBuiltinTimeLimitForTesting() /
                       timeout_increment) +
      1;

  EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTP);
  ASSERT_TRUE(test_server.InitializeAndListen());

  // Set up the test cert to have enough crlDistributionPoint urls that if the
  // first N-1 requests hang the deadline will be exceeded before the Nth
  // request is made.
  std::vector<GURL> crl_urls;
  std::vector<base::RunLoop> runloops(expected_request_count);
  for (int i = 0; i < expected_request_count; ++i) {
    std::string path = base::StringPrintf("/hung/%i", i);
    crl_urls.emplace_back(test_server.GetURL(path));
    test_server.RegisterRequestHandler(
        base::BindRepeating(&test_server::HandlePrefixedRequest, path,
                            base::BindRepeating(&HangRequestAndCallback,
                                                runloops[i].QuitClosure())));
  }
  // Add CRL URLs and handlers that will add test failures if requested.
  for (int i = expected_request_count; i < expected_request_count + 1; ++i) {
    std::string path = base::StringPrintf("/failtest/%i", i);
    crl_urls.emplace_back(test_server.GetURL(path));
    test_server.RegisterRequestHandler(base::BindRepeating(
        &test_server::HandlePrefixedRequest, path,
        base::BindRepeating(FailRequestAndFailTest,
                            "additional request made after deadline exceeded",
                            base::SequencedTaskRunner::GetCurrentDefault())));
  }
  leaf->SetCrlDistributionPointUrls(crl_urls);

  test_server.StartAcceptingConnections();

  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback verify_callback;
  Verify(chain.get(), "www.example.com",
         CertVerifyProc::VERIFY_REV_CHECKING_ENABLED,
         &verify_result, &verify_net_log_source, verify_callback.callback());

  for (int i = 0; i < expected_request_count; i++) {
    // Wait for request #|i| to be made.
    runloops[i].Run();
    // Advance virtual time to cause the timeout task to become runnable.
    task_environment().AdvanceClock(timeout_increment);
  }

  // Once |expected_request_count| requests have been made and timed out, the
  // overall deadline should be reached, and no more requests should have been
  // made. (If they were, the test will fail due to the ADD_FAILURE callback in
  // the request handlers.)
  int error = verify_callback.WaitForResult();
  // Soft-fail revocation checking was used, therefore verification result
  // should be OK even though none of the CRLs could be retrieved.
  EXPECT_THAT(error, IsOk());
}

// Tests that if the verification deadline is exceeded during revocation
// checking, additional OCSP fetches will not be attempted.
TEST_F(CertVerifyProcBuiltinTest, RevocationCheckDeadlineOCSP) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  InitializeVerifyProc(CreateParams(
      /*additional_trust_anchors=*/{root->GetX509Certificate()}));

  const base::TimeDelta timeout_increment =
      CertNetFetcherURLRequest::GetDefaultTimeoutForTesting() +
      base::Milliseconds(1);
  const int expected_request_count =
      base::ClampFloor(GetCertVerifyProcBuiltinTimeLimitForTesting() /
                       timeout_increment) +
      1;

  EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTP);
  ASSERT_TRUE(test_server.InitializeAndListen());

  // Set up the test cert to have enough OCSP urls that if the
  // first N-1 requests hang the deadline will be exceeded before the Nth
  // request is made.
  std::vector<GURL> ocsp_urls;
  std::vector<base::RunLoop> runloops(expected_request_count);
  for (int i = 0; i < expected_request_count; ++i) {
    std::string path = base::StringPrintf("/hung/%i", i);
    ocsp_urls.emplace_back(test_server.GetURL(path));
    test_server.RegisterRequestHandler(
        base::BindRepeating(&test_server::HandlePrefixedRequest, path,
                            base::BindRepeating(&HangRequestAndCallback,
                                                runloops[i].QuitClosure())));
  }
  // Add OCSP URLs and handlers that will add test failures if requested.
  for (int i = expected_request_count; i < expected_request_count + 1; ++i) {
    std::string path = base::StringPrintf("/failtest/%i", i);
    ocsp_urls.emplace_back(test_server.GetURL(path));
    test_server.RegisterRequestHandler(base::BindRepeating(
        &test_server::HandlePrefixedRequest, path,
        base::BindRepeating(FailRequestAndFailTest,
                            "additional request made after deadline exceeded",
                            base::SequencedTaskRunner::GetCurrentDefault())));
  }
  leaf->SetCaIssuersAndOCSPUrls({}, ocsp_urls);

  test_server.StartAcceptingConnections();

  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback verify_callback;
  Verify(chain.get(), "www.example.com",
         CertVerifyProc::VERIFY_REV_CHECKING_ENABLED,
         &verify_result, &verify_net_log_source, verify_callback.callback());

  for (int i = 0; i < expected_request_count; i++) {
    // Wait for request #|i| to be made.
    runloops[i].Run();
    // Advance virtual time to cause the timeout task to become runnable.
    task_environment().AdvanceClock(timeout_increment);
  }

  // Once |expected_request_count| requests have been made and timed out, the
  // overall deadline should be reached, and no more requests should have been
  // made. (If they were, the test will fail due to the ADD_FAILURE callback in
  // the request handlers.)
  int error = verify_callback.WaitForResult();
  // Soft-fail revocation checking was used, therefore verification result
  // should be OK even though none of the OCSP responses could be retrieved.
  EXPECT_THAT(error, IsOk());
}

#if defined(PLATFORM_USES_CHROMIUM_EV_METADATA)
// Tests that if we're doing EV verification, that no OCSP revocation checking
// is done.
TEST_F(CertVerifyProcBuiltinTest, EVNoOCSPRevocationChecks) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  InitializeVerifyProc(CreateParams(
      /*additional_trust_anchors=*/{root->GetX509Certificate()}));

  // Add test EV policy to leaf and intermediate.
  static const char kEVTestCertPolicy[] = "1.2.3.4";
  leaf->SetCertificatePolicies({kEVTestCertPolicy});
  intermediate->SetCertificatePolicies({kEVTestCertPolicy});

  EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTP);
  ASSERT_TRUE(test_server.InitializeAndListen());

  // Set up the test intermediate to have an OCSP url that fails the test if
  // called.
  std::vector<GURL> ocsp_urls;
  std::string path = "/failtest";
  ocsp_urls.emplace_back(test_server.GetURL(path));
  test_server.RegisterRequestHandler(base::BindRepeating(
      &test_server::HandlePrefixedRequest, path,
      base::BindRepeating(FailRequestAndFailTest,
                          "no OCSP requests should be sent",
                          base::SequencedTaskRunner::GetCurrentDefault())));
  intermediate->SetCaIssuersAndOCSPUrls({}, ocsp_urls);
  test_server.StartAcceptingConnections();

  // Consider the root of the test chain a valid EV root for the test policy.
  ScopedTestEVPolicy scoped_test_ev_policy(
      EVRootCAMetadata::GetInstance(),
      X509Certificate::CalculateFingerprint256(root->GetCertBuffer()),
      kEVTestCertPolicy);

  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  RecordingNetLogObserver net_log_observer(NetLogCaptureMode::kDefault);
  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback verify_callback;
  Verify(chain.get(), "www.example.com",
         /*flags=*/0,
         &verify_result, &verify_net_log_source, verify_callback.callback());

  // EV doesn't do revocation checking, therefore verification result
  // should be OK and EV.
  int error = verify_callback.WaitForResult();
  EXPECT_THAT(error, IsOk());
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_IS_EV);
  EXPECT_FALSE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);

  auto events = net_log_observer.GetEntriesForSource(verify_net_log_source);

  auto event = base::ranges::find(
      events, NetLogEventType::CERT_VERIFY_PROC_PATH_BUILD_ATTEMPT,
      &NetLogEntry::type);
  ASSERT_NE(event, events.end());
  EXPECT_EQ(net::NetLogEventPhase::BEGIN, event->phase);
  EXPECT_EQ(true, event->params.FindBool("is_ev_attempt"));

  event = base::ranges::find(++event, events.end(),
                             NetLogEventType::CERT_VERIFY_PROC_PATH_BUILT,
                             &NetLogEntry::type);
  ASSERT_NE(event, events.end());
  EXPECT_EQ(net::NetLogEventPhase::BEGIN, event->phase);

  event = base::ranges::find(++event, events.end(),
                             NetLogEventType::CERT_VERIFY_PROC_PATH_BUILT,
                             &NetLogEntry::type);
  ASSERT_NE(event, events.end());
  EXPECT_EQ(net::NetLogEventPhase::END, event->phase);
  EXPECT_FALSE(event->params.FindString("errors"));

  event = base::ranges::find(
      ++event, events.end(),
      NetLogEventType::CERT_VERIFY_PROC_PATH_BUILD_ATTEMPT, &NetLogEntry::type);
  ASSERT_NE(event, events.end());
  EXPECT_EQ(net::NetLogEventPhase::END, event->phase);
  EXPECT_EQ(true, event->params.FindBool("has_valid_path"));
}
#endif  // defined(PLATFORM_USES_CHROMIUM_EV_METADATA)

#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)

scoped_refptr<ct::SignedCertificateTimestamp> MakeSct(base::Time t,
                                                      std::string_view log_id) {
  auto sct = base::MakeRefCounted<ct::SignedCertificateTimestamp>();
  sct->timestamp = t;
  sct->log_id = log_id;
  return sct;
}

// Test SCT constraints fail-open if CT is disabled.
TEST_F(CertVerifyProcBuiltinTest,
       ChromeRootStoreConstraintSctConstraintsWithCtDisabled) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();
  ScopedTestRoot scoped_root(root->GetX509Certificate());

  EXPECT_CALL(*mock_ct_policy_enforcer(), IsCtEnabled())
      .WillRepeatedly(testing::Return(false));
  EXPECT_CALL(*mock_ct_verifier(), Verify(_, _, _, _, _, _)).Times(2);

  scoped_refptr<X509Certificate> chain = leaf->GetX509Certificate();
  ASSERT_TRUE(chain.get());

  SetMockChromeRootConstraints(
      {{.sct_not_after = base::Time::Now() - base::Days(365)}});

  {
    CertVerifyResult verify_result;
    NetLogSource verify_net_log_source;
    TestCompletionCallback callback;
    Verify(chain.get(), "www.example.com", /*ocsp_response=*/std::string(),
           /*sct_list=*/std::string(), /*flags=*/0, &verify_result,
           &verify_net_log_source, callback.callback());

    int error = callback.WaitForResult();
    EXPECT_THAT(error, IsOk());
    ASSERT_EQ(verify_result.scts.size(), 0u);
  }

  SetMockChromeRootConstraints(
      {{.sct_all_after = base::Time::Now() + base::Days(365)}});

  {
    CertVerifyResult verify_result;
    NetLogSource verify_net_log_source;
    TestCompletionCallback callback;
    Verify(chain.get(), "www.example.com", /*ocsp_response=*/std::string(),
           /*sct_list=*/std::string(), /*flags=*/0, &verify_result,
           &verify_net_log_source, callback.callback());

    int error = callback.WaitForResult();
    EXPECT_THAT(error, IsOk());
    ASSERT_EQ(verify_result.scts.size(), 0u);
  }
}

// Test SctNotAfter constraint only requires 1 valid SCT that satisfies the
// constraint.
// Set a SctNotAfter constraint at time t1.
// Mock that there are two SCTs, one of which is at t1 and thus satisfies the
// constraint. The second is at t2 and does not satisfy the constraint, but
// this is ok as only one valid SCT that meets the constraint is needed.
TEST_F(CertVerifyProcBuiltinTest, ChromeRootStoreConstraintSctNotAfter) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();
  ScopedTestRoot scoped_root(root->GetX509Certificate());

  const std::string kSctList = "SCT list";
  const std::string kLog1 = "log1";
  const std::string kLog2 = "log2";
  base::Time now = base::Time::Now();
  base::Time t1 = now - base::Days(2);
  base::Time t2 = now - base::Days(1);
  SignedCertificateTimestampAndStatusList sct_and_status_list;
  sct_and_status_list.emplace_back(MakeSct(t1, kLog1), ct::SCT_STATUS_OK);
  sct_and_status_list.emplace_back(MakeSct(t2, kLog2), ct::SCT_STATUS_OK);

  EXPECT_CALL(*mock_ct_verifier(), Verify(_, _, kSctList, _, _, _))
      .WillRepeatedly(testing::SetArgPointee<4>(sct_and_status_list));

  SetMockChromeRootConstraints({{.sct_not_after = t1}});

  EXPECT_CALL(*mock_ct_policy_enforcer(), IsCtEnabled())
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*mock_ct_policy_enforcer(), GetLogDisqualificationTime(kLog1))
      .WillRepeatedly(testing::Return(std::nullopt));
  EXPECT_CALL(*mock_ct_policy_enforcer(), GetLogDisqualificationTime(kLog2))
      .WillRepeatedly(testing::Return(std::nullopt));
  EXPECT_CALL(*mock_ct_policy_enforcer(), CheckCompliance(_, _, _, _))
      .WillRepeatedly(
          testing::Return(ct::CTPolicyCompliance::CT_POLICY_COMPLIES_VIA_SCTS));

  scoped_refptr<X509Certificate> chain = leaf->GetX509Certificate();
  ASSERT_TRUE(chain.get());

  {
    CertVerifyResult verify_result;
    NetLogSource verify_net_log_source;
    TestCompletionCallback callback;
    Verify(chain.get(), "www.example.com", /*ocsp_response=*/std::string(),
           kSctList, /*flags=*/0, &verify_result, &verify_net_log_source,
           callback.callback());

    int error = callback.WaitForResult();
    EXPECT_THAT(error, IsOk());
    ASSERT_EQ(verify_result.scts.size(), 2u);
  }

  // Try again with the SctNotAfter set to before both SCTs. Verification should
  // fail.
  SetMockChromeRootConstraints({{.sct_not_after = t1 - base::Seconds(1)}});
  {
    CertVerifyResult verify_result;
    NetLogSource verify_net_log_source;
    TestCompletionCallback callback;
    Verify(chain.get(), "www.example.com", /*ocsp_response=*/std::string(),
           kSctList, /*flags=*/0, &verify_result, &verify_net_log_source,
           callback.callback());

    int error = callback.WaitForResult();
    EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
    ASSERT_EQ(verify_result.scts.size(), 2u);
  }
}

// Test SctNotAfter constraint is only satisfied by successfully verified SCTs.
// Set a SctNotAfter constraint at time t1.
// Mock that there are two SCTs. One SCT for time t1 but from an unknown log,
// thus should not be usable for the SctNotAfter constraint. The second CT is
// from a known log but is at time t2 which is after t1, so does not satisfy
// the constraint. Therefore the certificate should fail verification.
TEST_F(CertVerifyProcBuiltinTest,
       ChromeRootStoreConstraintSctNotAfterLogUnknown) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();
  ScopedTestRoot scoped_root(root->GetX509Certificate());

  const std::string kSctList = "SCT list";
  const std::string kLog1 = "log1";
  const std::string kLog2 = "log2";
  base::Time now = base::Time::Now();
  base::Time t1 = now - base::Days(2);
  base::Time t2 = now - base::Days(1);
  SignedCertificateTimestampAndStatusList sct_and_status_list;
  sct_and_status_list.emplace_back(MakeSct(t1, kLog1),
                                   ct::SCT_STATUS_LOG_UNKNOWN);
  sct_and_status_list.emplace_back(MakeSct(t2, kLog2), ct::SCT_STATUS_OK);

  EXPECT_CALL(*mock_ct_policy_enforcer(), IsCtEnabled())
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*mock_ct_verifier(), Verify(_, _, kSctList, _, _, _))
      .WillOnce(testing::SetArgPointee<4>(sct_and_status_list));

  SetMockChromeRootConstraints({{.sct_not_after = t1}});

  scoped_refptr<X509Certificate> chain = leaf->GetX509Certificate();
  ASSERT_TRUE(chain.get());

  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", /*ocsp_response=*/std::string(),
         kSctList, /*flags=*/0, &verify_result, &verify_net_log_source,
         callback.callback());

  int error = callback.WaitForResult();
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  ASSERT_EQ(verify_result.scts.size(), 2u);
}

// Test SctNotAfter constraint is not satisfied by a SCT from a disqualified
// log even if the SCT timestamp is before the log was disqualified. Once a log
// is disqualified we assume it can not be trusted and could sign SCTs for any
// timestamp.
// SCT #1 is from a disqualified log and the timestamp is before the log was
// disqualified.
// SCT #2 is from a valid log but is after the SctNotAfter constraint, so does
// not satisfy the constraint.
TEST_F(
    CertVerifyProcBuiltinTest,
    ChromeRootStoreConstraintSctNotAfterFromDisqualifiedLogBeforeDisqualification) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();
  ScopedTestRoot scoped_root(root->GetX509Certificate());

  const std::string kSctList = "SCT list";
  const std::string kLog1 = "log1";
  const std::string kLog2 = "log2";
  base::Time now = base::Time::Now();
  base::Time t1 = now - base::Days(2);
  base::Time t2 = now - base::Days(1);
  SignedCertificateTimestampAndStatusList sct_and_status_list;
  sct_and_status_list.emplace_back(MakeSct(t1, kLog1), ct::SCT_STATUS_OK);
  sct_and_status_list.emplace_back(MakeSct(t2, kLog2), ct::SCT_STATUS_OK);

  EXPECT_CALL(*mock_ct_verifier(), Verify(_, _, kSctList, _, _, _))
      .WillOnce(testing::SetArgPointee<4>(sct_and_status_list));

  SetMockChromeRootConstraints({{.sct_not_after = t1}});

  EXPECT_CALL(*mock_ct_policy_enforcer(), IsCtEnabled())
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*mock_ct_policy_enforcer(), GetLogDisqualificationTime(kLog1))
      .WillRepeatedly(testing::Return(t2));
  EXPECT_CALL(*mock_ct_policy_enforcer(), GetLogDisqualificationTime(kLog2))
      .WillRepeatedly(testing::Return(std::nullopt));

  EXPECT_CALL(*mock_ct_policy_enforcer(), CheckCompliance(_, _, _, _))
      .WillRepeatedly(
          testing::Return(ct::CTPolicyCompliance::CT_POLICY_COMPLIES_VIA_SCTS));

  scoped_refptr<X509Certificate> chain = leaf->GetX509Certificate();
  ASSERT_TRUE(chain.get());

  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", /*ocsp_response=*/std::string(),
         kSctList, /*flags=*/0, &verify_result, &verify_net_log_source,
         callback.callback());

  int error = callback.WaitForResult();
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
}

// Test SctNotAfter constraint is not satisfied by a SCT from a disqualified
// log if the SCT timestamp is after the log was disqualified.
// SCT #1 is from a disqualified log and the timestamp is after the log was
// disqualified.
// SCT #2 is from a valid log but is after the SctNotAfter constraint, so does
// not satisfy the constraint.
TEST_F(
    CertVerifyProcBuiltinTest,
    ChromeRootStoreConstraintSctNotAfterFromDisqualifiedLogAfterDisqualification) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();
  ScopedTestRoot scoped_root(root->GetX509Certificate());

  const std::string kSctList = "SCT list";
  const std::string kLog1 = "log1";
  const std::string kLog2 = "log2";
  base::Time now = base::Time::Now();
  base::Time t1 = now - base::Days(2);
  base::Time t2 = now - base::Days(1);
  SignedCertificateTimestampAndStatusList sct_and_status_list;
  sct_and_status_list.emplace_back(MakeSct(t1, kLog1), ct::SCT_STATUS_OK);
  sct_and_status_list.emplace_back(MakeSct(t2, kLog2), ct::SCT_STATUS_OK);

  EXPECT_CALL(*mock_ct_verifier(), Verify(_, _, kSctList, _, _, _))
      .WillOnce(testing::SetArgPointee<4>(sct_and_status_list));

  SetMockChromeRootConstraints({{.sct_not_after = t1}});

  EXPECT_CALL(*mock_ct_policy_enforcer(), IsCtEnabled())
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*mock_ct_policy_enforcer(), GetLogDisqualificationTime(kLog1))
      .WillRepeatedly(testing::Return(t1));
  EXPECT_CALL(*mock_ct_policy_enforcer(), GetLogDisqualificationTime(kLog2))
      .WillRepeatedly(testing::Return(std::nullopt));

  EXPECT_CALL(*mock_ct_policy_enforcer(), CheckCompliance(_, _, _, _))
      .WillRepeatedly(
          testing::Return(ct::CTPolicyCompliance::CT_POLICY_COMPLIES_VIA_SCTS));

  scoped_refptr<X509Certificate> chain = leaf->GetX509Certificate();
  ASSERT_TRUE(chain.get());

  CertVerifyResult verify_result;
  NetLogSource verify_net_log_source;
  TestCompletionCallback callback;
  Verify(chain.get(), "www.example.com", /*ocsp_response=*/std::string(),
         kSctList, /*flags=*/0, &verify_result, &verify_net_log_source,
         callback.callback());

  int error = callback.WaitForResult();
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
}

// Test SctNotAfter constraint is satisfied by a SCT from a disqualified
// log if the log disqualification time is in the future.
TEST_F(CertVerifyProcBuiltinTest,
       ChromeRootStoreConstraintSctNotAfterFromFutureDisqualifiedLog) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();
  ScopedTestRoot scoped_root(root->GetX509Certificate());

  const std::string kSctList = "SCT list";
  const std::string kLog1 = "log1";
  const std::string kLog2 = "log2";
  base::Time now = base::Time::Now();
  base::Time t1 = now - base::Days(2);
  base::Time future_t = now + base::Days(1);
  SignedCertificateTimestampAndStatusList sct_and_status_list;
  sct_and_status_list.emplace_back(MakeSct(t1, kLog1), ct::SCT_STATUS_OK);

  EXPECT_CALL(*mock_ct_verifier(), Verify(_, _, kSctList, _, _, _))
      .WillOnce(testing::SetArgPointee<4>(sct_and_status_list));

  SetMockChromeRootConstraints({{.sct_not_after = t1}});

  EXPECT_CALL(*mock_ct_policy_enforcer(), IsCtEnabled())
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*mock_ct_policy_enforcer(), GetLogDisqualificationTime(kLog1))
      .WillRepeatedly(testing::Return(future_t));

  EXPECT_CALL(*mock_ct_policy_enforcer(), CheckCompliance(_, _, _, _))
      .WillRepeatedly(
          testing::Return(ct::CTPolicyCompliance::CT_POLICY_COMPLIES_VIA_SCTS));

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

// Test SctAllAfter constraint requires all valid SCTs to satisfy the
// constraint.
TEST_F(CertVerifyProcBuiltinTest, ChromeRootStoreConstraintSctAllAfter) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();
  ScopedTestRoot scoped_root(root->GetX509Certificate());

  const std::string kSctList = "SCT list";
  const std::string kLog1 = "log1";
  const std::string kLog2 = "log2";
  base::Time now = base::Time::Now();
  base::Time t0 = now - base::Days(3);
  base::Time t1 = now - base::Days(2);
  base::Time t2 = now - base::Days(1);
  SignedCertificateTimestampAndStatusList sct_and_status_list;
  sct_and_status_list.emplace_back(MakeSct(t1, kLog1), ct::SCT_STATUS_OK);
  sct_and_status_list.emplace_back(MakeSct(t2, kLog2), ct::SCT_STATUS_OK);

  EXPECT_CALL(*mock_ct_verifier(), Verify(_, _, kSctList, _, _, _))
      .WillRepeatedly(testing::SetArgPointee<4>(sct_and_status_list));

  // Set a SctAllAfter constraint before the timestamp of either SCT.
  SetMockChromeRootConstraints({{.sct_all_after = t0}});

  EXPECT_CALL(*mock_ct_policy_enforcer(), IsCtEnabled())
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*mock_ct_policy_enforcer(), GetLogDisqualificationTime(kLog1))
      .WillRepeatedly(testing::Return(std::nullopt));
  EXPECT_CALL(*mock_ct_policy_enforcer(), GetLogDisqualificationTime(kLog2))
      .WillRepeatedly(testing::Return(std::nullopt));
  EXPECT_CALL(*mock_ct_policy_enforcer(), CheckCompliance(_, _, _, _))
      .WillRepeatedly(
          testing::Return(ct::CTPolicyCompliance::CT_POLICY_COMPLIES_VIA_SCTS));

  scoped_refptr<X509Certificate> chain = leaf->GetX509Certificate();
  ASSERT_TRUE(chain.get());

  {
    CertVerifyResult verify_result;
    NetLogSource verify_net_log_source;
    TestCompletionCallback callback;
    Verify(chain.get(), "www.example.com", /*ocsp_response=*/std::string(),
           kSctList, /*flags=*/0, &verify_result, &verify_net_log_source,
           callback.callback());

    int error = callback.WaitForResult();
    EXPECT_THAT(error, IsOk());
    ASSERT_EQ(verify_result.scts.size(), 2u);
  }

  // Try again with the SctAllAfter set to the same time as one of the SCTs.
  // Verification should now fail.
  SetMockChromeRootConstraints({{.sct_all_after = t1}});
  {
    CertVerifyResult verify_result;
    NetLogSource verify_net_log_source;
    TestCompletionCallback callback;
    Verify(chain.get(), "www.example.com", /*ocsp_response=*/std::string(),
           kSctList, /*flags=*/0, &verify_result, &verify_net_log_source,
           callback.callback());

    int error = callback.WaitForResult();
    EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
    ASSERT_EQ(verify_result.scts.size(), 2u);
  }
}

std::string CurVersionString() {
  return version_info::GetVersion().GetString();
}
std::string NextVersionString() {
  const std::vector<uint32_t>& components =
      version_info::GetVersion().components();
  return base::Version(
             {components[0], components[1], components[2], components[3] + 1})
      .GetString();
}
std::string PrevVersionString() {
  const std::vector<uint32_t>& components =
      version_info::GetVersion().components();
  if (components[3] > 0) {
    return base::Version(
               {components[0], components[1], components[2], components[3] - 1})
        .GetString();
  } else {
    return base::Version(
               {components[0], components[1], components[2] - 1, UINT32_MAX})
        .GetString();
  }
}

TEST_F(CertVerifyProcBuiltinTest, ChromeRootStoreConstraintMinVersion) {
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

  SetMockChromeRootConstraints({{.min_version = CurVersionString()}});
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

TEST_F(CertVerifyProcBuiltinTest, ChromeRootStoreConstraintMaxVersion) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509Certificate();
  ASSERT_TRUE(chain.get());

  SetMockChromeRootConstraints({{.max_version_exclusive = CurVersionString()}});
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

  SetMockChromeRootConstraints(
      {{.max_version_exclusive = NextVersionString()}});
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

TEST_F(CertVerifyProcBuiltinTest, ChromeRootStoreConstraintMinAndMaxVersion) {
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509Certificate();
  ASSERT_TRUE(chain.get());

  // min_version satisfied, max_version_exclusive not satisfied = not trusted.
  SetMockChromeRootConstraints({{.min_version = PrevVersionString(),
                                 .max_version_exclusive = CurVersionString()}});
  {
    CertVerifyResult verify_result;
    NetLogSource verify_net_log_source;
    TestCompletionCallback callback;
    Verify(chain.get(), "www.example.com",
           /*flags=*/0, &verify_result, &verify_net_log_source,
           callback.callback());

    int error = callback.WaitForResult
```