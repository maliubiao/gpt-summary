Response:
The user wants a summary of the provided C++ code snippet, which is part of a larger unit test file for Chromium's network stack. The specific file is `net/cert/cert_verify_proc_unittest.cc`.

Here's a breakdown of the thinking process to generate the response:

1. **Identify the core functionality:** The code consists primarily of `TEST_P` blocks, indicating parameterized tests. These tests are grouped into test suites. The names of the tests and the code within them heavily revolve around certificate verification, particularly focusing on revocation checking (CRL and OCSP) under different conditions (hard-fail, soft-fail).

2. **Categorize the tests:**  Group the tests by the feature they are testing. The primary categories are:
    * Hard-fail revocation checking with CRLs.
    * Soft-fail revocation checking with CRLs.
    * OCSP revocation checking for EV certificates.
    * Basic constraints checking.

3. **Explain "hard-fail" vs. "soft-fail":** Define these terms in the context of certificate revocation. Hard-fail means verification fails if revocation status cannot be determined. Soft-fail means verification succeeds despite the inability to check revocation, but a flag is set.

4. **Analyze individual test cases:**  For each category, understand the specific scenarios being tested. Look for keywords like "good," "revoked," "http error," "no CRLs," etc. This helps in understanding the input and expected output of each test.

5. **Relate to JavaScript (if applicable):**  Consider how these low-level certificate verification mechanisms might impact web developers using JavaScript. The most direct link is the effect on website security and the `https` protocol. Browsers use these mechanisms to decide if a connection is secure.

6. **Provide examples with assumptions:** Create hypothetical scenarios to illustrate the tests. For example, if a test checks for hard-fail CRL revocation, provide a scenario where a revoked certificate would cause the browser to refuse the connection.

7. **Address common user errors:**  Think about situations where users or developers might encounter these issues. Misconfigured servers or revoked certificates are common culprits.

8. **Explain the debugging perspective:**  Describe how a developer might end up investigating these tests. Usually, it's due to observed certificate errors in the browser.

9. **Focus on the specific code snippet:** Acknowledge that this is a part of a larger file and therefore represents a focused set of functionalities.

10. **Address the "part X of 8" instruction:** Emphasize that this is a subset and summarize the specific functionalities covered within this subset.

11. **Structure the response:** Organize the information logically with clear headings and bullet points for readability.

**Self-Correction/Refinement During Thinking:**

* **Initial thought:** Simply list the tests.
* **Refinement:** Realized that grouping by functionality and explaining the underlying concepts (hard-fail/soft-fail) would be much more helpful.
* **Initial thought:**  Focus heavily on the C++ code.
* **Refinement:**  Made a conscious effort to connect it to the user perspective (JavaScript, website security, debugging).
* **Initial thought:**  Provide very detailed input/output for each test.
* **Refinement:**  Decided to give general examples with assumptions for brevity and clarity, as explicitly stating the certificate data for each test would be overly verbose.
* **Initial thought:**  Only describe the positive tests.
* **Refinement:** Included examples of negative tests (where verification fails) and explained why.

By following these steps, I could generate a comprehensive and informative summary of the provided code snippet, addressing all aspects of the user's request.
好的，让我们来分析一下 `net/cert/cert_verify_proc_unittest.cc` 文件的这部分代码的功能。

**功能归纳：**

这部分代码主要针对 `CertVerifyProc` 组件的证书吊销检查功能进行单元测试，具体包括以下几个方面：

1. **硬性失败 (Hard-Fail) 的 CRL 吊销检查：**  测试在启用强制吊销检查时，各种 CRL 场景下的证书验证行为。例如：
    *  存在有效的、未吊销当前证书的 CRL。
    *  CRL 中吊销了不相关的证书。
    *  叶子证书或中间证书被 CRL 吊销。
    *  获取 CRL 的 HTTP 端点返回错误（如 404）。
2. **软性失败 (Soft-Fail) 的 CRL 吊销检查：** 测试在启用非强制吊销检查时，各种 CRL 场景下的证书验证行为。例如：
    *  没有可用的 CRL。
    *  存在有效的、未吊销当前证书的 CRL。
    *  CRL 中吊销了不相关的证书。
    *  叶子证书或中间证书被 CRL 吊销。
    *  禁用网络请求时，即使证书被 CRL 吊销也应通过验证。
    *  CRL 使用不支持的签名算法 (如 MD5)。
    *  获取 CRL 的 HTTP 端点返回错误（如 404）。
3. **在线 OCSP 吊销检查对 EV 证书的影响：** 测试在线 OCSP 吊销检查的不同结果（成功、失败、吊销）如何影响 EV 证书的验证状态。
4. **证书约束 (Constraints) 的测试：** 测试证书链中不同位置的约束（如基本约束）如何影响证书验证。

**与 JavaScript 的关系及举例说明：**

虽然这段 C++ 代码本身不直接包含 JavaScript，但它所测试的证书验证逻辑直接影响着基于 JavaScript 的 Web 应用的安全性。当用户通过浏览器访问一个使用 HTTPS 的网站时，浏览器会使用类似 `CertVerifyProc` 的组件来验证服务器提供的证书链。

* **HTTPS 连接的安全性：**  JavaScript 代码通常运行在浏览器环境中，依赖浏览器建立安全的 HTTPS 连接。如果证书验证失败（例如，证书被吊销且是硬性失败的情况），浏览器会阻止 JavaScript 代码访问该网站，并向用户显示安全警告。
* **`fetch` API 和安全上下文：**  JavaScript 的 `fetch` API 用于进行网络请求。对于 HTTPS 请求，浏览器会在底层进行证书验证。如果验证失败，`fetch` 请求可能会被拒绝或返回错误状态。
* **Service Workers 和安全：** Service Workers 运行在浏览器后台，可以拦截和处理网络请求。它们也依赖浏览器的证书验证机制来确保请求的安全性。

**举例说明：**

假设一个网站的服务器证书被吊销了，并且浏览器配置为进行硬性失败的 CRL 检查。

1. **用户操作：** 用户在浏览器地址栏输入该网站的 URL 并按下回车。
2. **浏览器行为：** 浏览器发起 HTTPS 连接请求。
3. **证书验证：** 浏览器（通过 `CertVerifyProc`）尝试验证服务器提供的证书链。
4. **CRL 检查：** 浏览器检查证书吊销列表 (CRL)，发现该服务器证书已被吊销。
5. **验证结果：** 由于是硬性失败检查，证书验证失败。
6. **JavaScript 影响：** 浏览器会阻止加载该网站的任何资源，包括 HTML、CSS 和 JavaScript 文件。页面会显示一个安全错误，并且 JavaScript 代码不会执行。

**逻辑推理 (假设输入与输出)：**

**假设输入 1:**

*   **证书链:** 包含叶子证书 (leaf)、中间证书 (intermediate) 和根证书 (root)。
*   **吊销信息:** 中间证书发布了一个 CRL，其中吊销了叶子证书的序列号。
*   **验证标志:** `CertVerifyProc::VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS` (硬性失败吊销检查)。
*   **主机名:** "www.example.com"。

**预期输出 1:**

*   **错误代码:** `ERR_CERT_REVOKED`。
*   **`verify_result.cert_status`:**  包含 `CERT_STATUS_REV_CHECKING_ENABLED`。

**假设输入 2:**

*   **证书链:** 包含叶子证书、中间证书和根证书。
*   **吊销信息:** 叶子证书和中间证书都没有发布 CRL。
*   **验证标志:** `CertVerifyProc::VERIFY_REV_CHECKING_ENABLED` (软性失败吊销检查)。
*   **主机名:** "www.example.com"。

**预期输出 2:**

*   **错误代码:** `IsOk()` (验证通过)。
*   **`verify_result.cert_status`:** 包含 `CERT_STATUS_REV_CHECKING_ENABLED`，但不包含 `CERT_STATUS_NO_REVOCATION_MECHANISM` 或 `CERT_STATUS_UNABLE_TO_CHECK_REVOCATION` (因为软性失败不会因为缺少 CRL 而标记为无法检查吊销)。

**用户或编程常见的使用错误：**

1. **服务器未配置正确的 CRL 分发点 (CDP)：**  如果服务器证书或中间证书的 CDP 信息不正确，浏览器将无法获取 CRL，导致吊销检查失败（如果是硬性失败）。
    *   **用户操作：**  网站管理员配置服务器证书时，错误地填写了 CRL 的 URL。
    *   **调试线索：** 浏览器开发者工具的网络面板可能会显示获取 CRL 失败的请求（如 404 错误）。`CertVerifyProc` 的日志也可能包含相关错误信息。
2. **防火墙或网络问题阻止访问 CRL 服务器：**  用户的网络环境可能阻止浏览器访问 CRL 服务器，导致吊销检查失败。
    *   **用户操作：**  用户在一个有严格防火墙限制的网络环境下访问网站。
    *   **调试线索：** 浏览器开发者工具的网络面板可能会显示获取 CRL 的请求被阻止或超时。
3. **本地时间错误导致 CRL 验证失败：** CRL 有有效期，如果用户的本地时间不正确，可能导致 CRL 被认为无效。
    *   **用户操作：**  用户计算机的系统时间设置错误。
    *   **调试线索：** `CertVerifyProc` 的日志可能会显示 CRL 的有效期检查失败。
4. **开发者在测试环境中混淆硬性失败和软性失败的配置：** 开发者可能在测试时错误地启用了硬性失败吊销检查，导致一些本应通过的证书验证失败。
    *   **用户操作：**  开发者在浏览器或测试框架中配置了错误的证书验证选项。
    *   **调试线索：**  仔细检查浏览器或测试框架的证书验证配置。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户报告网站安全错误：** 用户在使用 Chrome 浏览器访问某个网站时，看到了安全警告页面，提示证书无效或已被吊销。
2. **开发者开始调查：** 网站开发者或 Chrome 浏览器开发者开始调查此问题。
3. **检查证书信息：** 开发者可能会使用浏览器开发者工具的安全面板来查看网站的证书链信息，包括证书是否被吊销以及 CRL 或 OCSP 信息。
4. **分析网络请求：** 开发者可能会检查网络面板，查看浏览器是否尝试获取 CRL 或 OCSP 响应，以及请求是否成功。
5. **查看 Chrome 内部日志：** 开发者可能会启用 Chrome 的内部日志记录（例如，通过 `chrome://net-internals/#events`），查找与证书验证相关的事件，包括 `CertVerifyProc` 的输出。
6. **运行单元测试：** 如果是 Chrome 浏览器开发者，他们可能会运行 `net/cert/cert_verify_proc_unittest.cc` 中的相关单元测试，以验证证书验证逻辑是否按预期工作，并复现用户报告的问题。例如，他们可能会运行与硬性失败 CRL 检查相关的测试，来验证在证书被吊销的情况下是否会正确地返回 `ERR_CERT_REVOKED` 错误。
7. **代码调试：** 如果单元测试失败或需要更深入的分析，开发者可能会使用调试器来单步执行 `CertVerifyProc` 的代码，查看证书链的处理过程、CRL 的获取和解析过程，以及吊销状态的判断逻辑。 这时，就会深入到 `net/cert/cert_verify_proc_unittest.cc` 中测试所覆盖的代码逻辑。

**作为第 5 部分的功能归纳：**

这部分代码专注于测试 `CertVerifyProc` 组件在处理证书吊销时的各种场景，特别是通过 CRL 进行吊销检查的硬性失败和软性失败行为，以及在线 OCSP 检查对 EV 证书的影响。此外，还包含了对证书基本约束的测试。这部分测试确保了 Chrome 浏览器能够正确地执行证书吊销检查，从而保障用户的网络安全。

### 提示词
```
这是目录为net/cert/cert_verify_proc_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
EXPECT_FALSE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

// CRL hard fail test where both leaf and intermediate are covered by valid
// CRLs which have empty (non-present) revokedCertificates list. Verification
// should succeed.
TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       RevocationHardFailCrlGoodNoRevokedCertificates) {
  if (!SupportsRevCheckingRequiredLocalAnchors()) {
    LOG(INFO) << "Skipping test as verifier doesn't support "
                 "VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS";
    return;
  }

  const char kHostname[] = "www.example.com";
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  // Serve a root-issued CRL which does not revoke intermediate.
  intermediate->SetCrlDistributionPointUrl(CreateAndServeCrl(root.get(), {}));

  // Serve an intermediate-issued CRL which does not revoke leaf.
  leaf->SetCrlDistributionPointUrl(CreateAndServeCrl(intermediate.get(), {}));

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  // Verify with hard-fail revocation checking for local anchors.
  const int flags = CertVerifyProc::VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), kHostname, flags, &verify_result);

  // Should pass, leaf and intermediate were covered by CRLs and were not
  // revoked.
  EXPECT_THAT(error, IsOk());
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

// CRL hard fail test where both leaf and intermediate are covered by valid
// CRLs which have revokedCertificates lists that revoke other irrelevant
// serial numbers. Verification should succeed.
TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       RevocationHardFailCrlGoodIrrelevantSerialsRevoked) {
  if (!SupportsRevCheckingRequiredLocalAnchors()) {
    LOG(INFO) << "Skipping test as verifier doesn't support "
                 "VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS";
    return;
  }

  const char kHostname[] = "www.example.com";
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  // Root-issued CRL revokes leaf's serial number. This is irrelevant.
  intermediate->SetCrlDistributionPointUrl(
      CreateAndServeCrl(root.get(), {leaf->GetSerialNumber()}));

  // Intermediate-issued CRL revokes intermediates's serial number. This is
  // irrelevant.
  leaf->SetCrlDistributionPointUrl(
      CreateAndServeCrl(intermediate.get(), {intermediate->GetSerialNumber()}));

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  // Verify with hard-fail revocation checking for local anchors.
  const int flags = CertVerifyProc::VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), kHostname, flags, &verify_result);

  // Should pass, leaf and intermediate were covered by CRLs and were not
  // revoked.
  EXPECT_THAT(error, IsOk());
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       RevocationHardFailLeafRevokedByCrl) {
  if (!SupportsRevCheckingRequiredLocalAnchors()) {
    LOG(INFO) << "Skipping test as verifier doesn't support "
                 "VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS";
    return;
  }

  const char kHostname[] = "www.example.com";
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  // Root-issued CRL which does not revoke intermediate.
  intermediate->SetCrlDistributionPointUrl(CreateAndServeCrl(root.get(), {}));

  // Leaf is revoked by intermediate issued CRL.
  leaf->SetCrlDistributionPointUrl(
      CreateAndServeCrl(intermediate.get(), {leaf->GetSerialNumber()}));

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  // Verify with hard-fail revocation checking for local anchors.
  const int flags = CertVerifyProc::VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), kHostname, flags, &verify_result);

  // Should fail, leaf is revoked.
  EXPECT_THAT(error, IsError(ERR_CERT_REVOKED));
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       RevocationHardFailIntermediateRevokedByCrl) {
  if (!SupportsRevCheckingRequiredLocalAnchors()) {
    LOG(INFO) << "Skipping test as verifier doesn't support "
                 "VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS";
    return;
  }

  const char kHostname[] = "www.example.com";
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  // Intermediate is revoked by root issued CRL.
  intermediate->SetCrlDistributionPointUrl(
      CreateAndServeCrl(root.get(), {intermediate->GetSerialNumber()}));

  // Intermediate-issued CRL which does not revoke leaf.
  leaf->SetCrlDistributionPointUrl(CreateAndServeCrl(intermediate.get(), {}));

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  // Verify with hard-fail revocation checking for local anchors.
  const int flags = CertVerifyProc::VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), kHostname, flags, &verify_result);

  // Should fail, intermediate is revoked.
  EXPECT_THAT(error, IsError(ERR_CERT_REVOKED));
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

// CRL hard fail test where the intermediate certificate has a good CRL, but
// the leaf's distribution point returns an http error. Verification should
// fail.
TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       RevocationHardFailLeafCrlDpHttpError) {
  if (!SupportsRevCheckingRequiredLocalAnchors()) {
    LOG(INFO) << "Skipping test as verifier doesn't support "
                 "VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS";
    return;
  }

  const char kHostname[] = "www.example.com";
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  // Serve a root-issued CRL which does not revoke intermediate.
  intermediate->SetCrlDistributionPointUrl(CreateAndServeCrl(root.get(), {}));

  // Serve a 404 for the intermediate-issued CRL distribution point url.
  leaf->SetCrlDistributionPointUrl(RegisterSimpleTestServerHandler(
      MakeRandomPath(".crl"), HTTP_NOT_FOUND, "text/plain", "Not Found"));

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  // Verify with hard-fail revocation checking for local anchors.
  const int flags = CertVerifyProc::VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), kHostname, flags, &verify_result);

  // Should fail since no revocation information was available for the leaf.
  EXPECT_THAT(error, IsError(ERR_CERT_UNABLE_TO_CHECK_REVOCATION));
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

// CRL hard fail test where the leaf certificate has a good CRL, but
// the intermediate's distribution point returns an http error. Verification
// should fail.
TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       RevocationHardFailIntermediateCrlDpHttpError) {
  if (!SupportsRevCheckingRequiredLocalAnchors()) {
    LOG(INFO) << "Skipping test as verifier doesn't support "
                 "VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS";
    return;
  }

  const char kHostname[] = "www.example.com";
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  // Serve a 404 for the root-issued CRL distribution point url.
  intermediate->SetCrlDistributionPointUrl(RegisterSimpleTestServerHandler(
      MakeRandomPath(".crl"), HTTP_NOT_FOUND, "text/plain", "Not Found"));

  // Serve an intermediate-issued CRL which does not revoke leaf.
  leaf->SetCrlDistributionPointUrl(CreateAndServeCrl(intermediate.get(), {}));

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  // Verify with hard-fail revocation checking for local anchors.
  const int flags = CertVerifyProc::VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), kHostname, flags, &verify_result);

  // Should fail since no revocation information was available for the
  // intermediate.
  EXPECT_THAT(error, IsError(ERR_CERT_UNABLE_TO_CHECK_REVOCATION));
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_P(CertVerifyProcInternalWithNetFetchingTest, RevocationSoftFailNoCrls) {
  if (!SupportsSoftFailRevChecking()) {
    LOG(INFO) << "Skipping test as verifier doesn't support "
                 "VERIFY_REV_CHECKING_ENABLED";
    return;
  }

  // Create certs which have no AIA or CRL distribution points.
  const char kHostname[] = "www.example.com";
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  // Verify with soft-fail revocation checking.
  const int flags = CertVerifyProc::VERIFY_REV_CHECKING_ENABLED;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), kHostname, flags, &verify_result);

  EXPECT_THAT(error, IsOk());
  EXPECT_FALSE(verify_result.cert_status & CERT_STATUS_NO_REVOCATION_MECHANISM);
  EXPECT_FALSE(verify_result.cert_status &
               CERT_STATUS_UNABLE_TO_CHECK_REVOCATION);
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

// CRL soft fail test where both leaf and intermediate are covered by valid
// CRLs which have empty (non-present) revokedCertificates list. Verification
// should succeed.
TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       RevocationSoftFailCrlGoodNoRevokedCertificates) {
  if (!SupportsSoftFailRevChecking()) {
    LOG(INFO) << "Skipping test as verifier doesn't support "
                 "VERIFY_REV_CHECKING_ENABLED";
    return;
  }

  const char kHostname[] = "www.example.com";
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  // Serve a root-issued CRL which does not revoke intermediate.
  intermediate->SetCrlDistributionPointUrl(CreateAndServeCrl(root.get(), {}));

  // Serve an intermediate-issued CRL which does not revoke leaf.
  leaf->SetCrlDistributionPointUrl(CreateAndServeCrl(intermediate.get(), {}));

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  // Verify with soft-fail revocation checking.
  const int flags = CertVerifyProc::VERIFY_REV_CHECKING_ENABLED;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), kHostname, flags, &verify_result);

  EXPECT_THAT(error, IsOk());
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

// CRL soft fail test where both leaf and intermediate are covered by valid
// CRLs which have revokedCertificates lists that revoke other irrelevant
// serial numbers. Verification should succeed.
TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       RevocationSoftFailCrlGoodIrrelevantSerialsRevoked) {
  if (!SupportsSoftFailRevChecking()) {
    LOG(INFO) << "Skipping test as verifier doesn't support "
                 "VERIFY_REV_CHECKING_ENABLED";
    return;
  }

  const char kHostname[] = "www.example.com";
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  // Root-issued CRL revokes leaf's serial number. This is irrelevant.
  intermediate->SetCrlDistributionPointUrl(
      CreateAndServeCrl(root.get(), {leaf->GetSerialNumber()}));

  // Intermediate-issued CRL revokes intermediates's serial number. This is
  // irrelevant.
  leaf->SetCrlDistributionPointUrl(
      CreateAndServeCrl(intermediate.get(), {intermediate->GetSerialNumber()}));

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  // Verify with soft-fail revocation checking.
  const int flags = CertVerifyProc::VERIFY_REV_CHECKING_ENABLED;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), kHostname, flags, &verify_result);

  EXPECT_THAT(error, IsOk());
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       RevocationSoftFailLeafRevokedByCrl) {
  if (!SupportsSoftFailRevChecking()) {
    LOG(INFO) << "Skipping test as verifier doesn't support "
                 "VERIFY_REV_CHECKING_ENABLED";
    return;
  }

  const char kHostname[] = "www.example.com";
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  // Root-issued CRL which does not revoke intermediate.
  intermediate->SetCrlDistributionPointUrl(CreateAndServeCrl(root.get(), {}));

  // Leaf is revoked by intermediate issued CRL.
  leaf->SetCrlDistributionPointUrl(
      CreateAndServeCrl(intermediate.get(), {leaf->GetSerialNumber()}));

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  // Verify with soft-fail revocation checking.
  const int flags = CertVerifyProc::VERIFY_REV_CHECKING_ENABLED;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), kHostname, flags, &verify_result);

  // Should fail, leaf is revoked.
  EXPECT_THAT(error, IsError(ERR_CERT_REVOKED));
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       RevocationSoftFailLeafRevokedByCrlDisableNetworkFetches) {
  if (!SupportsSoftFailRevChecking()) {
    LOG(INFO) << "Skipping test as verifier doesn't support "
                 "VERIFY_REV_CHECKING_ENABLED";
    return;
  }

  const char kHostname[] = "www.example.com";
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  // Root-issued CRL which does not revoke intermediate.
  intermediate->SetCrlDistributionPointUrl(CreateAndServeCrl(root.get(), {}));

  // Leaf is revoked by intermediate issued CRL.
  leaf->SetCrlDistributionPointUrl(
      CreateAndServeCrl(intermediate.get(), {leaf->GetSerialNumber()}));

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  // Verify with flags for both soft-fail revocation checking and disabling
  // network fetches.
  const int flags = CertVerifyProc::VERIFY_REV_CHECKING_ENABLED |
                    CertVerifyProc::VERIFY_DISABLE_NETWORK_FETCHES;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), kHostname, flags, &verify_result);

  // Should succeed, VERIFY_DISABLE_NETWORK_FETCHES takes priority.
  EXPECT_THAT(error, IsOk());
  EXPECT_FALSE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       RevocationSoftFailIntermediateRevokedByCrl) {
  if (!SupportsSoftFailRevChecking()) {
    LOG(INFO) << "Skipping test as verifier doesn't support "
                 "VERIFY_REV_CHECKING_ENABLED";
    return;
  }

  const char kHostname[] = "www.example.com";
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  // Intermediate is revoked by root issued CRL.
  intermediate->SetCrlDistributionPointUrl(
      CreateAndServeCrl(root.get(), {intermediate->GetSerialNumber()}));

  // Intermediate-issued CRL which does not revoke leaf.
  leaf->SetCrlDistributionPointUrl(CreateAndServeCrl(intermediate.get(), {}));

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  // Verify with soft-fail revocation checking.
  const int flags = CertVerifyProc::VERIFY_REV_CHECKING_ENABLED;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), kHostname, flags, &verify_result);

  // Should fail, intermediate is revoked.
  EXPECT_THAT(error, IsError(ERR_CERT_REVOKED));
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       RevocationSoftFailLeafRevokedBySha1Crl) {
  if (!SupportsSoftFailRevChecking()) {
    LOG(INFO) << "Skipping test as verifier doesn't support "
                 "VERIFY_REV_CHECKING_ENABLED";
    return;
  }

  const char kHostname[] = "www.example.com";
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  // Root-issued CRL which does not revoke intermediate.
  intermediate->SetCrlDistributionPointUrl(CreateAndServeCrl(root.get(), {}));

  // Leaf is revoked by intermediate issued CRL which is signed with
  // ecdsaWithSha256.
  leaf->SetCrlDistributionPointUrl(
      CreateAndServeCrl(intermediate.get(), {leaf->GetSerialNumber()},
                        bssl::SignatureAlgorithm::kEcdsaSha1));

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  // Verify with soft-fail revocation checking.
  const int flags = CertVerifyProc::VERIFY_REV_CHECKING_ENABLED;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), kHostname, flags, &verify_result);

  // Should fail, leaf is revoked.
  EXPECT_THAT(error, IsError(ERR_CERT_REVOKED));
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       RevocationSoftFailLeafRevokedByMd5Crl) {
  if (!SupportsSoftFailRevChecking()) {
    LOG(INFO) << "Skipping test as verifier doesn't support "
                 "VERIFY_REV_CHECKING_ENABLED";
    return;
  }

  const char kHostname[] = "www.example.com";
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  // Root-issued CRL which does not revoke intermediate.
  intermediate->SetCrlDistributionPointUrl(CreateAndServeCrl(root.get(), {}));
  // This test wants to check handling of MD5 CRLs, but ecdsa-with-md5
  // signatureAlgorithm does not exist. Use an RSA private key for intermediate
  // so that the CRL will be signed with the md5WithRSAEncryption algorithm.
  ASSERT_TRUE(intermediate->UseKeyFromFile(
      GetTestCertsDirectory().AppendASCII("rsa-2048-1.key")));
  leaf->SetSignatureAlgorithm(bssl::SignatureAlgorithm::kRsaPkcs1Sha256);

  // Leaf is revoked by intermediate issued CRL which is signed with
  // md5WithRSAEncryption.
  leaf->SetCrlDistributionPointUrl(CreateAndServeCrlWithAlgorithmTlvAndDigest(
      intermediate.get(), {leaf->GetSerialNumber()}, Md5WithRSAEncryption(),
      EVP_md5()));

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  // Verify with soft-fail revocation checking.
  const int flags = CertVerifyProc::VERIFY_REV_CHECKING_ENABLED;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), kHostname, flags, &verify_result);

  // Verification should succeed: MD5 signature algorithm is not supported
  // and soft-fail checking will ignore the inability to get revocation
  // status.
  EXPECT_THAT(error, IsOk());
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

// CRL soft fail test where the intermediate certificate has a good CRL, but
// the leaf's distribution point returns an http error. Verification should
// succeed.
TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       RevocationSoftFailLeafCrlDpHttpError) {
  if (!SupportsSoftFailRevChecking()) {
    LOG(INFO) << "Skipping test as verifier doesn't support "
                 "VERIFY_REV_CHECKING_ENABLED";
    return;
  }

  const char kHostname[] = "www.example.com";
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  // Serve a root-issued CRL which does not revoke intermediate.
  intermediate->SetCrlDistributionPointUrl(CreateAndServeCrl(root.get(), {}));

  // Serve a 404 for the intermediate-issued CRL distribution point url.
  leaf->SetCrlDistributionPointUrl(RegisterSimpleTestServerHandler(
      MakeRandomPath(".crl"), HTTP_NOT_FOUND, "text/plain", "Not Found"));

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  // Verify with soft-fail revocation checking.
  const int flags = CertVerifyProc::VERIFY_REV_CHECKING_ENABLED;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), kHostname, flags, &verify_result);

  // Should succeed due to soft-fail revocation checking.
  EXPECT_THAT(error, IsOk());
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

// CRL soft fail test where the leaf certificate has a good CRL, but
// the intermediate's distribution point returns an http error. Verification
// should succeed.
TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       RevocationSoftFailIntermediateCrlDpHttpError) {
  if (!SupportsSoftFailRevChecking()) {
    LOG(INFO) << "Skipping test as verifier doesn't support "
                 "VERIFY_REV_CHECKING_ENABLED";
    return;
  }

  const char kHostname[] = "www.example.com";
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  // Serve a 404 for the root-issued CRL distribution point url.
  intermediate->SetCrlDistributionPointUrl(RegisterSimpleTestServerHandler(
      MakeRandomPath(".crl"), HTTP_NOT_FOUND, "text/plain", "Not Found"));

  // Serve an intermediate-issued CRL which does not revoke leaf.
  leaf->SetCrlDistributionPointUrl(CreateAndServeCrl(intermediate.get(), {}));

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  // Verify with soft-fail revocation checking.
  const int flags = CertVerifyProc::VERIFY_REV_CHECKING_ENABLED;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), kHostname, flags, &verify_result);

  // Should succeed due to soft-fail revocation checking.
  EXPECT_THAT(error, IsOk());
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

// Tests that an EV cert verification with successful online OCSP revocation
// checks is marked as CERT_STATUS_IS_EV.
TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       EVOnlineOCSPRevocationCheckingGood) {
  if (!SupportsEV()) {
    LOG(INFO) << "Skipping test as EV verification is not yet supported";
    return;
  }

  const char kEVTestCertPolicy[] = "1.2.3.4";
  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.policy_oids = {kEVTestCertPolicy};
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::GOOD,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});

  EmbeddedTestServer ocsp_test_server(EmbeddedTestServer::TYPE_HTTPS);
  ocsp_test_server.SetSSLConfig(cert_config);
  EXPECT_TRUE(ocsp_test_server.Start());

  scoped_refptr<X509Certificate> root =
      ImportCertFromFile(GetTestCertsDirectory(), "root_ca_cert.pem");
  ASSERT_TRUE(root.get());

  scoped_refptr<X509Certificate> chain = ocsp_test_server.GetCertificate();
  ASSERT_TRUE(chain.get());

  // Consider the root of the test chain a valid EV root for the test policy.
  ScopedTestEVPolicy scoped_test_ev_policy(
      EVRootCAMetadata::GetInstance(),
      X509Certificate::CalculateFingerprint256(root->cert_buffer()),
      kEVTestCertPolicy);

  CertVerifyResult verify_result;
  int flags = 0;
  int error = Verify(chain.get(), ocsp_test_server.host_port_pair().host(),
                     flags, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_IS_EV);
  EXPECT_FALSE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

// Tests that an EV cert verification with that could not retrieve online OCSP
// revocation information is verified but still marked as CERT_STATUS_IS_EV.
TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       EVOnlineOCSPRevocationCheckingSoftFail) {
  if (!SupportsEV()) {
    LOG(INFO) << "Skipping test as EV verification is not yet supported";
    return;
  }

  const char kEVTestCertPolicy[] = "1.2.3.4";
  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.policy_oids = {kEVTestCertPolicy};
  // Retrieving OCSP status returns an error.
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      EmbeddedTestServer::OCSPConfig::ResponseType::kInternalError);

  EmbeddedTestServer ocsp_test_server(EmbeddedTestServer::TYPE_HTTPS);
  ocsp_test_server.SetSSLConfig(cert_config);
  EXPECT_TRUE(ocsp_test_server.Start());

  scoped_refptr<X509Certificate> root =
      ImportCertFromFile(GetTestCertsDirectory(), "root_ca_cert.pem");
  ASSERT_TRUE(root.get());

  scoped_refptr<X509Certificate> chain = ocsp_test_server.GetCertificate();
  ASSERT_TRUE(chain.get());

  // Consider the root of the test chain a valid EV root for the test policy.
  ScopedTestEVPolicy scoped_test_ev_policy(
      EVRootCAMetadata::GetInstance(),
      X509Certificate::CalculateFingerprint256(root->cert_buffer()),
      kEVTestCertPolicy);

  CertVerifyResult verify_result;
  int flags = 0;
  int error = Verify(chain.get(), ocsp_test_server.host_port_pair().host(),
                     flags, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_IS_EV);
  EXPECT_FALSE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

// Tests that an EV cert verification with online OCSP returning affirmatively
// revoked is marked as CERT_STATUS_IS_EV.
TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       EVOnlineOCSPRevocationCheckingRevoked) {
  if (!SupportsEV()) {
    LOG(INFO) << "Skipping test as EV verification is not yet supported";
    return;
  }

  const char kEVTestCertPolicy[] = "1.2.3.4";
  EmbeddedTestServer::ServerCertificateConfig cert_config;
  cert_config.policy_oids = {kEVTestCertPolicy};
  cert_config.ocsp_config = EmbeddedTestServer::OCSPConfig(
      {{bssl::OCSPRevocationStatus::REVOKED,
        EmbeddedTestServer::OCSPConfig::SingleResponse::Date::kValid}});

  EmbeddedTestServer ocsp_test_server(EmbeddedTestServer::TYPE_HTTPS);
  ocsp_test_server.SetSSLConfig(cert_config);
  EXPECT_TRUE(ocsp_test_server.Start());

  scoped_refptr<X509Certificate> root =
      ImportCertFromFile(GetTestCertsDirectory(), "root_ca_cert.pem");
  ASSERT_TRUE(root.get());

  scoped_refptr<X509Certificate> chain = ocsp_test_server.GetCertificate();
  ASSERT_TRUE(chain.get());

  // Consider the root of the test chain a valid EV root for the test policy.
  ScopedTestEVPolicy scoped_test_ev_policy(
      EVRootCAMetadata::GetInstance(),
      X509Certificate::CalculateFingerprint256(root->cert_buffer()),
      kEVTestCertPolicy);

  CertVerifyResult verify_result;
  int flags = 0;
  int error = Verify(chain.get(), ocsp_test_server.host_port_pair().host(),
                     flags, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_IS_EV);
  EXPECT_FALSE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

// A set of tests that check how various constraints are enforced when they
// appear at different points in the chain, such as on the trust anchor versus
// on intermediates.
class CertVerifyProcConstraintsTest : public CertVerifyProcInternalTest {
 protected:
  void SetUp() override {
    CertVerifyProcInternalTest::SetUp();

    chain_ = CertBuilder::CreateSimpleChain(/*chain_length=*/4);
  }

  int VerifyWithTrust(bssl::CertificateTrust trust) {
    ScopedTestRoot test_root(chain_.back()->GetX509Certificate(), trust);
    CertVerifyResult verify_result;
    int flags = 0;
    return CertVerifyProcInternalTest::Verify(
        chain_.front()->GetX509CertificateChain().get(), "www.example.com",
        flags, &verify_result);
  }

  int Verify() {
    return VerifyWithTrust(bssl::CertificateTrust::ForTrustAnchor());
  }

  int VerifyWithExpiryAndConstraints() {
    return VerifyWithTrust(bssl::CertificateTrust::ForTrustAnchor()
                               .WithEnforceAnchorExpiry()
                               .WithEnforceAnchorConstraints());
  }

  int VerifyWithExpiryAndFullConstraints() {
    return VerifyWithTrust(bssl::CertificateTrust::ForTrustAnchor()
                               .WithEnforceAnchorExpiry()
                               .WithEnforceAnchorConstraints()
                               .WithRequireAnchorBasicConstraints());
  }

  int ExpectedIntermediateConstraintError() {
    if (verify_proc_type() == CERT_VERIFY_PROC_ANDROID)
      return ERR_CERT_AUTHORITY_INVALID;
    return ERR_CERT_INVALID;
  }

  std::vector<std::unique_ptr<CertBuilder>> chain_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         CertVerifyProcConstraintsTest,
                         testing::ValuesIn(kAllCertVerifiers),
                         VerifyProcTypeToName);

TEST_P(CertVerifyProcConstraintsTest, BaseCase) {
  // Without changing anything on the test chain, it should validate
  // successfully. If this is not true then the rest of the tests in this class
  // are unlikely to be useful.
  EXPECT_THAT(Verify(), IsOk());
  if (VerifyProcTypeIsBuiltin()) {
    EXPECT_THAT(VerifyWithExpiryAndConstraints(), IsOk());
    EXPECT_THAT(VerifyWithExpiryAndFullConstraints(), IsOk());
    EXPECT_THAT(VerifyWithTrust(bssl::CertificateTrust::ForTrustAnchorOrLeaf()),
                IsOk());
    EXPECT_THAT(VerifyWithTrust(bssl::CertificateTrust::ForTrustedLeaf()),
                IsError(ERR_CERT_AUTHORITY_INVALID));
  }
}

TEST_P(CertVerifyProcConstraintsTest, BasicConstraintsNotCaRoot) {
  chain_[3]->SetBasicConstraints(/*is_ca=*/false, /*path_len=*/-1);

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

TEST_P(CertVerifyProcConstraintsTest, BasicConstraintsNotCaIntermediate) {
  chain_[2]->SetBasicConstraints(/*is_ca=*/false, /*path_len=*/-1);

  EXPECT_THAT(Verify(), IsError(ExpectedIntermediateConstraintError()));
}

TEST_P(CertVerifyProcConstraintsTest, BasicConstraintsIsCaLeaf) {
  for (bool has_key_usage_cert_sign : {false, true}) {
    chain_[0]->SetBasicConstraints(/*is_ca=*/true, /*path_len=*/-1);

    if (has_key_usage_cert_sign) {
      chain_[0]->SetKeyUsages({bssl::KEY_USAGE_BIT_KEY_CERT_SIGN,
                               bssl::KEY_USAGE_BIT_DIGITAL_SIGNATURE});
    } else {
      chain_[0]->SetKeyUsages({bssl::KEY_USAGE_BIT_DIG
```