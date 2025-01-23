Response:
The user wants to understand the functionality of the C++ source code file `net/cert/cert_verify_proc_unittest.cc` in the Chromium project.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Function:** The filename `cert_verify_proc_unittest.cc` immediately suggests this file contains unit tests for certificate verification functionality. The `TEST_P` macros and `EXPECT_THAT` assertions confirm this.

2. **Analyze Test Categories:**  Scanning the test names reveals distinct categories of tests:
    * Validity checks (date ranges)
    * Signature validation (intermediate and target)
    * Name normalization (handling different string encodings and case)
    * Network fetching (AIA, CRLs)
    * Revocation checking

3. **Detail Each Category:** For each category, summarize the tested aspects:
    * **Validity:** Tests boundary conditions (just before and after validity periods) and negative cases (expired certificates).
    * **Signature:**  Focuses on cases where signatures don't match due to key mismatches, especially when `authorityKeyIdentifier` is missing, forcing signature verification.
    * **Normalization:**  Explores scenarios where issuer and subject names have different string encodings (PrintableString vs. UTF8String) or case variations. Highlights the use of histograms to track normalization outcomes.
    * **Network Fetching:**  Examines AIA fetching (successful and 404 responses), handling of DER and PEM encoded certificates, and the interaction of network fetching with revocation checks. Specifically notes the `VERIFY_DISABLE_NETWORK_FETCHES` flag.
    * **Revocation:** Tests hard-fail revocation scenarios when CRL information isn't available.

4. **Look for JavaScript Relevance:**  Consider where certificate verification plays a role in a browser context that might involve JavaScript. HTTPS is the key connection. JavaScript running in a webpage relies on the browser's secure connection. Certificate errors directly impact what JavaScript can do (e.g., accessing APIs on a secure site).

5. **Provide JavaScript Examples:** Illustrate the connection with concrete JavaScript code snippets:
    * `fetch` failing due to certificate errors.
    * `XMLHttpRequest` experiencing similar issues.
    * `navigator.mediaDevices.getUserMedia` being blocked due to security concerns related to certificates.

6. **Construct Logic Inference Examples (Input/Output):** Create simplified scenarios based on the tests:
    * **Validity:** Show a certificate with a future `notBefore` date and the expected `ERR_CERT_DATE_INVALID`.
    * **Signature:** Illustrate a leaf signed by an unknown key and the `ERR_CERT_AUTHORITY_INVALID`.
    * **Normalization:** Demonstrate the case-insensitive matching with different casing in CN.
    * **AIA Fetching:** Show a leaf certificate referencing an AIA URL and the retrieval of the intermediate.

7. **Identify User/Programming Errors:** Think about common mistakes related to certificates:
    * Incorrect system clock leading to validity errors.
    * Self-signed or untrusted certificates.
    * Missing intermediate certificates.
    * Firewall/network issues blocking AIA/CRL retrieval.

8. **Describe User Steps to Reach the Code:** Trace back typical user actions that trigger certificate verification:
    * Navigating to an HTTPS website.
    * Accessing resources on an HTTPS site via JavaScript.
    * Installing a new root certificate.

9. **Summarize Functionality:**  Provide a concise overview of the file's purpose, focusing on testing different aspects of certificate verification.

10. **Address Part Number:**  Explicitly acknowledge that this is part 4/8 and reiterate the summarized functionality in that context.

**Self-Correction/Refinement during thought process:**

* **Initial thought:** Focus heavily on the C++ aspects of the tests.
* **Correction:**  Realize the prompt asks for JavaScript relevance, so need to bridge the gap between the C++ testing and how certificate verification impacts the browser's interaction with web pages and JavaScript.
* **Initial thought:**  Provide very detailed C++ code examples for input/output.
* **Correction:** Simplify the input/output examples to focus on the logical outcome rather than low-level C++ details, making them easier to understand.
* **Initial thought:**  Just list the errors.
* **Correction:** Explain *why* those errors occur in the context of user actions or programming mistakes.
这是文件 `net/cert/cert_verify_proc_unittest.cc` 的第 4 部分，其主要功能是**对 Chromium 网络栈中负责证书验证的核心组件 `CertVerifyProc` 进行单元测试**。

**归纳其功能：**

这部分代码主要集中在以下几个方面的 `CertVerifyProc` 功能测试：

* **证书有效期验证 (Validity):**  测试证书的 `notBefore` 和 `notAfter` 时间限制是否被正确处理。包括边界情况的测试，例如当前时间刚好在有效期之前、刚好在有效期之后的情况。
* **证书签名验证 (Signature Validation):**  测试当证书链中某个证书（中间证书或叶子证书）的签名无效时，`CertVerifyProc` 的行为。重点测试了在缺少 `authorityKeyIdentifier` 扩展的情况下，验证过程如何尝试签名验证。
* **证书名称规范化 (Name Normalization):** 测试 `CertVerifyProc` 如何处理证书签发者和主题名称的不同表示形式，例如不同的字符串类型（PrintableString 和 UTF8String）以及大小写差异。并使用直方图来记录规范化结果。
* **通过网络获取证书 (Network Fetching - AIA):**  测试当证书链缺少中间证书时，`CertVerifyProc` 是否能够通过 Authority Information Access (AIA) 扩展中指定的 URL 获取缺失的中间证书。测试了获取成功（DER 和 PEM 格式）和获取失败（404 错误）的情况。
* **SHA1 中间证书与 AIA 获取 SHA256 证书:** 测试当本地提供的证书链包含 SHA1 签名的中间证书，但可以通过 AIA 获取到 SHA256 签名的相同中间证书时，`CertVerifyProc` 是否能够选择更强的 SHA256 证书。
* **吊销硬失败 (Revocation Hard Fail):**  测试在启用硬失败吊销检查（`VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS` 标志）但没有可用的吊销机制（例如 CRL）时，`CertVerifyProc` 的行为。

**与 JavaScript 的功能关系及举例说明：**

`CertVerifyProc` 是浏览器进行 HTTPS 连接安全验证的关键组件。当 JavaScript 代码尝试访问一个 HTTPS 网站或者使用需要安全连接的 API 时，浏览器会在底层使用 `CertVerifyProc` 来验证服务器提供的 SSL/TLS 证书。

**举例说明：**

假设一个网页中的 JavaScript 代码尝试使用 `fetch` API 访问一个 HTTPS 网站：

```javascript
fetch('https://www.example.com')
  .then(response => {
    console.log('请求成功', response);
  })
  .catch(error => {
    console.error('请求失败', error);
  });
```

* **证书有效期问题:** 如果 `CertVerifyProc` 检测到 `www.example.com` 的证书已过期（对应本部分代码中 `ValidityJustAfterNotAfter` 的测试），`fetch` 请求将会失败，并且在 `catch` 代码块中 `error` 对象会包含与证书错误相关的信息。用户在浏览器中也会看到证书错误的警告或提示。

* **证书签名无效:** 如果服务器提供的证书链中某个证书的签名无效（对应本部分代码中 `FailedIntermediateSignatureValidation` 或 `FailedTargetSignatureValidation` 的测试），`CertVerifyProc` 验证失败，`fetch` 请求同样会失败，JavaScript 代码无法成功获取数据。

* **缺少中间证书，但可通过 AIA 获取:** 如果服务器仅发送了叶子证书，而 JavaScript 代码尝试访问该服务器，`CertVerifyProc` 会尝试根据叶子证书的 AIA 信息去下载中间证书（对应本部分代码中 `IntermediateFromAia200Der` 和 `IntermediateFromAia200Pem` 的测试）。如果获取成功，则验证通过，`fetch` 请求成功。如果获取失败（例如 404 错误，对应 `IntermediateFromAia404` 的测试），则验证失败，`fetch` 请求失败。

**逻辑推理的假设输入与输出：**

**假设输入 1 (对应 `ValidityJustAfterNotAfter`):**

* **叶子证书的 `notAfter` 时间:**  当前时间 - 1 秒
* **当前系统时间:**  现在
* **其他证书链信息:**  有效且可信

**预期输出 1:**

* `CertVerifyProc` 返回错误代码 `ERR_CERT_DATE_INVALID`。
* `verify_result.cert_status` 包含 `CERT_STATUS_DATE_INVALID` 标志。

**假设输入 2 (对应 `FailedTargetSignatureValidation`):**

* **叶子证书的签名:** 使用错误的私钥签名。
* **中间证书:**  使用正确的私钥签名。
* **根证书:**  可信。
* **叶子证书缺少 `authorityKeyIdentifier` 扩展。**

**预期输出 2:**

* `CertVerifyProc` 返回错误代码 `ERR_CERT_AUTHORITY_INVALID`。
* `verify_result.cert_status` 包含 `CERT_STATUS_AUTHORITY_INVALID` 标志。

**假设输入 3 (对应 `StringType`，且 `verify_proc_type()` 为 `CERT_VERIFY_PROC_IOS`):**

* **叶子证书的签发者 CN (Common Name):**  使用 `PrintableString` 类型编码。
* **中间证书的主题 CN:** 使用 `UTF8String` 类型编码，内容与叶子证书签发者 CN 相同。
* **根证书:** 可信。

**预期输出 3:**

* `CertVerifyProc` 返回错误代码 `ERR_CERT_AUTHORITY_INVALID` (在 iOS 上，由于名称规范化差异可能导致验证失败)。

**涉及用户或编程常见的使用错误及举例说明：**

* **用户错误：系统时间不正确。** 如果用户的计算机系统时间比证书的 `notBefore` 时间还早，或者比 `notAfter` 时间还晚，`CertVerifyProc` 将会判断证书无效，导致 HTTPS 连接失败。用户可能会看到 "您的连接不是私密连接" 类似的错误提示。

* **编程错误：服务器配置错误，缺少中间证书。**  服务器管理员可能没有正确配置服务器，导致服务器在 TLS 握手过程中只发送了叶子证书，而没有发送中间证书。这会导致客户端的 `CertVerifyProc` 无法构建完整的信任链，从而验证失败（除非客户端能够通过 AIA 获取到中间证书，对应本部分代码的测试）。

* **编程错误：使用了自签名或未被信任的证书。** 如果服务器使用了自签名证书或者由未被客户端信任的 CA 签发的证书，`CertVerifyProc` 无法找到信任锚点，验证将会失败。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入一个 `https://` 开头的网址，或者点击一个 `https://` 链接。**
2. **浏览器开始与目标服务器建立 TLS 连接。**
3. **服务器向浏览器发送其 SSL/TLS 证书。**
4. **浏览器网络栈的底层代码会调用 `CertVerifyProc` 来验证服务器发送的证书。**
5. **`CertVerifyProc` 会执行一系列检查，包括：**
    * 检查证书的有效期（对应本部分代码的有效期测试）。
    * 检查证书的签名是否有效，是否能找到可信的根证书（对应签名验证测试）。
    * 如果缺少中间证书，尝试通过 AIA 获取（对应网络获取证书测试）。
    * 进行名称规范化检查（对应名称规范化测试）。
    * 如果启用了吊销检查，会检查证书是否被吊销。
6. **`CertVerifyProc` 返回验证结果（成功或失败，以及具体的错误代码）。**
7. **如果验证失败，浏览器会显示安全警告或阻止用户访问该网站。**

**调试线索：**

当开发者在调试与证书相关的问题时，可以关注以下几点：

* **检查系统时间:** 确保客户端和服务器的系统时间是同步的。
* **检查证书链:** 使用工具（如 OpenSSL）检查服务器返回的证书链是否完整，是否包含所有必要的中间证书。
* **检查证书的有效期和签名:** 使用工具查看证书的 `notBefore`、`notAfter` 时间以及签名算法和签名是否有效。
* **检查 AIA 信息:**  查看证书的 AIA 扩展，确认其 URL 是否可访问，以及返回的内容是否正确。
* **检查网络连接:** 确保客户端可以正常访问 AIA 扩展中指定的 URL。
* **查看浏览器日志:**  Chromium 提供了丰富的网络日志，可以帮助开发者了解证书验证的详细过程和遇到的错误。

总而言之，`net/cert/cert_verify_proc_unittest.cc` 的这部分代码通过一系列单元测试，确保了 `CertVerifyProc` 组件在处理各种证书场景时的正确性和健壮性，这对于保证 Chromium 浏览器的 HTTPS 安全至关重要。它涵盖了证书有效期、签名验证、名称规范化以及通过网络获取证书等核心功能。

### 提示词
```
这是目录为net/cert/cert_verify_proc_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
mple.com", flags, &verify_result);
  // Current time is between notBefore and notAfter. Verification should
  // succeed.
  EXPECT_THAT(error, IsOk());
}

TEST_P(CertVerifyProcInternalTest, ValidityJustBeforeNotAfter) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  base::Time not_before = base::Time::Now() - base::Days(30);
  base::Time not_after = base::Time::Now() + base::Minutes(5);
  leaf->SetValidity(not_before, not_after);

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), "www.example.com", flags, &verify_result);
  // Current time is between notBefore and notAfter. Verification should
  // succeed.
  EXPECT_THAT(error, IsOk());
}

TEST_P(CertVerifyProcInternalTest, ValidityJustAfterNotAfter) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();
  base::Time not_before = base::Time::Now() - base::Days(30);
  base::Time not_after = base::Time::Now() - base::Seconds(1);
  leaf->SetValidity(not_before, not_after);

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), "www.example.com", flags, &verify_result);
  // Current time is after certificate's notAfter. Verification should fail.
  EXPECT_THAT(error, IsError(ERR_CERT_DATE_INVALID));
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_DATE_INVALID);
}

TEST_P(CertVerifyProcInternalTest, FailedIntermediateSignatureValidation) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  // Intermediate has no authorityKeyIdentifier. Also remove
  // subjectKeyIdentifier from root for good measure.
  intermediate->EraseExtension(
      bssl::der::Input(bssl::kAuthorityKeyIdentifierOid));
  root->EraseExtension(bssl::der::Input(bssl::kSubjectKeyIdentifierOid));

  // Get the chain with the leaf and the intermediate signed by the original
  // key of |root|.
  scoped_refptr<X509Certificate> cert = leaf->GetX509CertificateChain();

  // Generate a new key for root.
  root->GenerateECKey();

  // Trust the new root certificate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(cert.get(), "www.example.com", flags, &verify_result);

  // The intermediate was signed by a different root with a different key but
  // with the same name as the trusted one, and the intermediate has no
  // authorityKeyIdentifier, so the verifier must try verifying the signature.
  // Should fail with AUTHORITY_INVALID.
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_AUTHORITY_INVALID);
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
}

TEST_P(CertVerifyProcInternalTest, FailedTargetSignatureValidation) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  // Leaf has no authorityKeyIdentifier. Also remove subjectKeyIdentifier from
  // intermediate for good measure.
  leaf->EraseExtension(bssl::der::Input(bssl::kAuthorityKeyIdentifierOid));
  intermediate->EraseExtension(
      bssl::der::Input(bssl::kSubjectKeyIdentifierOid));

  // Get a copy of the leaf signed by the original key of intermediate.
  bssl::UniquePtr<CRYPTO_BUFFER> leaf_wrong_signature = leaf->DupCertBuffer();

  // Generate a new key for intermediate.
  intermediate->GenerateECKey();

  // Make a chain that includes the original leaf with the wrong signature and
  // the new intermediate.
  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
  intermediates.push_back(intermediate->DupCertBuffer());

  scoped_refptr<X509Certificate> cert = X509Certificate::CreateFromBuffer(
      bssl::UpRef(leaf_wrong_signature), std::move(intermediates));
  ASSERT_TRUE(cert.get());

  // Trust the root certificate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(cert.get(), "www.example.com", flags, &verify_result);

  // The leaf was signed by a different intermediate with a different key but
  // with the same name as the one in the chain, and the leaf has no
  // authorityKeyIdentifier, so the verifier must try verifying the signature.
  // Should fail with AUTHORITY_INVALID.
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_AUTHORITY_INVALID);
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
}

class CertVerifyProcNameNormalizationTest : public CertVerifyProcInternalTest {
 protected:
  std::string HistogramName() const {
    std::string prefix("Net.CertVerifier.NameNormalizationPrivateRoots.");
    switch (verify_proc_type()) {
      case CERT_VERIFY_PROC_ANDROID:
        return prefix + "Android";
      case CERT_VERIFY_PROC_IOS:
        return prefix + "IOS";
      case CERT_VERIFY_PROC_BUILTIN:
      case CERT_VERIFY_PROC_BUILTIN_CHROME_ROOTS:
        return prefix + "Builtin";
    }
  }

  void ExpectNormalizationHistogram(int verify_error) {
    if (verify_error == OK) {
      histograms_.ExpectUniqueSample(
          HistogramName(), CertVerifyProc::NameNormalizationResult::kNormalized,
          1);
    } else {
      histograms_.ExpectTotalCount(HistogramName(), 0);
    }
  }

  void ExpectByteEqualHistogram() {
    histograms_.ExpectUniqueSample(
        HistogramName(), CertVerifyProc::NameNormalizationResult::kByteEqual,
        1);
  }

 private:
  base::HistogramTester histograms_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         CertVerifyProcNameNormalizationTest,
                         testing::ValuesIn(kAllCertVerifiers),
                         VerifyProcTypeToName);

// Tries to verify a chain where the leaf's issuer CN is PrintableString, while
// the intermediate's subject CN is UTF8String, and verifies the proper
// histogram is logged.
TEST_P(CertVerifyProcNameNormalizationTest, StringType) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  std::string issuer_cn = CertBuilder::MakeRandomHexString(12);
  leaf->SetIssuerTLV(CertBuilder::BuildNameWithCommonNameOfType(
      issuer_cn, CBS_ASN1_PRINTABLESTRING));
  intermediate->SetSubjectTLV(CertBuilder::BuildNameWithCommonNameOfType(
      issuer_cn, CBS_ASN1_UTF8STRING));

  ScopedTestRoot scoped_root(root->GetX509Certificate());

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(leaf->GetX509CertificateChain().get(), "www.example.com",
                     flags, &verify_result);

  switch (verify_proc_type()) {
    case CERT_VERIFY_PROC_IOS:
      EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
      break;
    case CERT_VERIFY_PROC_ANDROID:
    case CERT_VERIFY_PROC_BUILTIN:
    case CERT_VERIFY_PROC_BUILTIN_CHROME_ROOTS:
      EXPECT_THAT(error, IsOk());
      break;
  }

  ExpectNormalizationHistogram(error);
}

// Tries to verify a chain where the leaf's issuer CN and intermediate's
// subject CN are both PrintableString but have differing case on the first
// character, and verifies the proper histogram is logged.
TEST_P(CertVerifyProcNameNormalizationTest, CaseFolding) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  std::string issuer_hex = CertBuilder::MakeRandomHexString(12);
  leaf->SetIssuerTLV(CertBuilder::BuildNameWithCommonNameOfType(
      "Z" + issuer_hex, CBS_ASN1_PRINTABLESTRING));
  intermediate->SetSubjectTLV(CertBuilder::BuildNameWithCommonNameOfType(
      "z" + issuer_hex, CBS_ASN1_PRINTABLESTRING));

  ScopedTestRoot scoped_root(root->GetX509Certificate());

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(leaf->GetX509CertificateChain().get(), "www.example.com",
                     flags, &verify_result);

  EXPECT_THAT(error, IsOk());
  ExpectNormalizationHistogram(error);
}

// Confirms that a chain generated by the same pattern as the other
// NameNormalizationTest cases which does not require normalization validates
// ok, and that the ByteEqual histogram is logged.
TEST_P(CertVerifyProcNameNormalizationTest, ByteEqual) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  std::string issuer_hex = CertBuilder::MakeRandomHexString(12);
  leaf->SetIssuerTLV(CertBuilder::BuildNameWithCommonNameOfType(
      issuer_hex, CBS_ASN1_PRINTABLESTRING));
  intermediate->SetSubjectTLV(CertBuilder::BuildNameWithCommonNameOfType(
      issuer_hex, CBS_ASN1_PRINTABLESTRING));

  ScopedTestRoot scoped_root(root->GetX509Certificate());

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(leaf->GetX509CertificateChain().get(), "www.example.com",
                     flags, &verify_result);

  EXPECT_THAT(error, IsOk());
  ExpectByteEqualHistogram();
}

std::string Md5WithRSAEncryption() {
  const uint8_t kMd5WithRSAEncryption[] = {0x30, 0x0d, 0x06, 0x09, 0x2a,
                                           0x86, 0x48, 0x86, 0xf7, 0x0d,
                                           0x01, 0x01, 0x04, 0x05, 0x00};
  return std::string(std::begin(kMd5WithRSAEncryption),
                     std::end(kMd5WithRSAEncryption));
}

// This is the same as CertVerifyProcInternalTest, but it additionally sets up
// networking capabilities for the cert verifiers, and a test server that can be
// used to serve mock responses for AIA/OCSP/CRL.
//
// An actual HTTP test server is used rather than simply mocking the network
// layer, since the certificate fetching networking layer is not mockable for
// all of the cert verifier implementations.
//
// The approach taken in this test fixture is to generate certificates
// on the fly so they use randomly chosen URLs, subjects, and serial
// numbers, in order to defeat global caching effects from the platform
// verifiers. Moreover, the AIA needs to be chosen dynamically since the
// test server's port number cannot be known statically.
class CertVerifyProcInternalWithNetFetchingTest
    : public CertVerifyProcInternalTest {
 protected:
  CertVerifyProcInternalWithNetFetchingTest()
      : task_environment_(
            base::test::TaskEnvironment::MainThreadType::DEFAULT) {}

  void SetUp() override {
    // Create a network thread to be used for network fetches, and wait for
    // initialization to complete on that thread.
    base::Thread::Options options(base::MessagePumpType::IO, 0);
    network_thread_ = std::make_unique<base::Thread>("network_thread");
    CHECK(network_thread_->StartWithOptions(std::move(options)));

    base::WaitableEvent initialization_complete_event(
        base::WaitableEvent::ResetPolicy::MANUAL,
        base::WaitableEvent::InitialState::NOT_SIGNALED);
    network_thread_->task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(&SetUpOnNetworkThread, &context_, &cert_net_fetcher_,
                       &initialization_complete_event));
    initialization_complete_event.Wait();
    EXPECT_TRUE(cert_net_fetcher_);

    CertVerifyProcInternalTest::SetUp();

    EXPECT_FALSE(test_server_.Started());

    // Register a single request handler with the EmbeddedTestServer, that in
    // turn dispatches to the internally managed registry of request handlers.
    //
    // This allows registering subsequent handlers dynamically during the course
    // of the test, since EmbeddedTestServer requires its handlers be registered
    // prior to Start().
    test_server_.RegisterRequestHandler(base::BindRepeating(
        &CertVerifyProcInternalWithNetFetchingTest::DispatchToRequestHandler,
        base::Unretained(this)));
    EXPECT_TRUE(test_server_.Start());
  }

  void SetUpCertVerifyProc(scoped_refptr<CRLSet> crl_set) override {
    EXPECT_TRUE(cert_net_fetcher_);
    SetUpWithCertNetFetcher(cert_net_fetcher_, std::move(crl_set),
                            /*additional_trust_anchors=*/{},
                            /*additional_untrusted_authorities=*/{});
  }

  void TearDown() override {
    // Do cleanup on network thread.
    network_thread_->task_runner()->PostTask(
        FROM_HERE, base::BindOnce(&ShutdownOnNetworkThread, &context_,
                                  &cert_net_fetcher_));
    network_thread_->Stop();
    network_thread_.reset();

    CertVerifyProcInternalTest::TearDown();
  }

  // Registers a handler with the test server that responds with the given
  // Content-Type, HTTP status code, and response body, for GET requests
  // to |path|.
  // Returns the full URL to |path| for the current test server.
  GURL RegisterSimpleTestServerHandler(std::string path,
                                       HttpStatusCode status_code,
                                       std::string content_type,
                                       std::string content) {
    GURL handler_url(GetTestServerAbsoluteUrl(path));
    base::AutoLock lock(request_handlers_lock_);
    request_handlers_.push_back(base::BindRepeating(
        &SimpleTestServerHandler, std::move(path), status_code,
        std::move(content_type), std::move(content)));
    return handler_url;
  }

  // Returns a random URL path (starting with /) that has the given suffix.
  static std::string MakeRandomPath(std::string_view suffix) {
    return "/" + MakeRandomHexString(12) + std::string(suffix);
  }

  // Returns a URL to |path| for the current test server.
  GURL GetTestServerAbsoluteUrl(const std::string& path) {
    return test_server_.GetURL(path);
  }

  // Creates a certificate chain for www.example.com, where the leaf certificate
  // has an AIA URL pointing to the test server.
  void CreateSimpleChainWithAIA(
      scoped_refptr<X509Certificate>* out_leaf,
      std::string* ca_issuers_path,
      bssl::UniquePtr<CRYPTO_BUFFER>* out_intermediate,
      scoped_refptr<X509Certificate>* out_root) {
    auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

    // Make the leaf certificate have an AIA (CA Issuers) that points to the
    // embedded test server. This uses a random URL for predictable behavior in
    // the presence of global caching.
    *ca_issuers_path = MakeRandomPath(".cer");
    GURL ca_issuers_url = GetTestServerAbsoluteUrl(*ca_issuers_path);
    leaf->SetCaIssuersUrl(ca_issuers_url);

    // The chain being verified is solely the leaf certificate (missing the
    // intermediate and root).
    *out_leaf = leaf->GetX509Certificate();
    *out_root = root->GetX509Certificate();
    *out_intermediate = intermediate->DupCertBuffer();
  }

  // Creates a CRL issued and signed by |crl_issuer|, marking |revoked_serials|
  // as revoked, and registers it to be served by the test server.
  // Returns the full URL to retrieve the CRL from the test server.
  GURL CreateAndServeCrl(CertBuilder* crl_issuer,
                         const std::vector<uint64_t>& revoked_serials,
                         std::optional<bssl::SignatureAlgorithm>
                             signature_algorithm = std::nullopt) {
    std::string crl = BuildCrl(crl_issuer->GetSubject(), crl_issuer->GetKey(),
                               revoked_serials, signature_algorithm);
    std::string crl_path = MakeRandomPath(".crl");
    return RegisterSimpleTestServerHandler(crl_path, HTTP_OK,
                                           "application/pkix-crl", crl);
  }

  GURL CreateAndServeCrlWithAlgorithmTlvAndDigest(
      CertBuilder* crl_issuer,
      const std::vector<uint64_t>& revoked_serials,
      const std::string& signature_algorithm_tlv,
      const EVP_MD* digest) {
    std::string crl = BuildCrlWithAlgorithmTlvAndDigest(
        crl_issuer->GetSubject(), crl_issuer->GetKey(), revoked_serials,
        signature_algorithm_tlv, digest);
    std::string crl_path = MakeRandomPath(".crl");
    return RegisterSimpleTestServerHandler(crl_path, HTTP_OK,
                                           "application/pkix-crl", crl);
  }

 private:
  std::unique_ptr<test_server::HttpResponse> DispatchToRequestHandler(
      const test_server::HttpRequest& request) {
    // Called on the embedded test server's IO thread.
    base::AutoLock lock(request_handlers_lock_);
    for (const auto& handler : request_handlers_) {
      auto response = handler.Run(request);
      if (response)
        return response;
    }

    return nullptr;
  }

  // Serves (|status_code|, |content_type|, |content|) in response to GET
  // requests for |path|.
  static std::unique_ptr<test_server::HttpResponse> SimpleTestServerHandler(
      const std::string& path,
      HttpStatusCode status_code,
      const std::string& content_type,
      const std::string& content,
      const test_server::HttpRequest& request) {
    if (request.relative_url != path)
      return nullptr;

    auto http_response = std::make_unique<test_server::BasicHttpResponse>();

    http_response->set_code(status_code);
    http_response->set_content_type(content_type);
    http_response->set_content(content);
    return http_response;
  }

  static void SetUpOnNetworkThread(
      std::unique_ptr<URLRequestContext>* context,
      scoped_refptr<CertNetFetcherURLRequest>* cert_net_fetcher,
      base::WaitableEvent* initialization_complete_event) {
    URLRequestContextBuilder url_request_context_builder;
    url_request_context_builder.set_user_agent("cert_verify_proc_unittest/0.1");
    url_request_context_builder.set_proxy_config_service(
        std::make_unique<ProxyConfigServiceFixed>(ProxyConfigWithAnnotation()));
    *context = url_request_context_builder.Build();

    *cert_net_fetcher = base::MakeRefCounted<net::CertNetFetcherURLRequest>();
    (*cert_net_fetcher)->SetURLRequestContext(context->get());
    initialization_complete_event->Signal();
  }

  static void ShutdownOnNetworkThread(
      std::unique_ptr<URLRequestContext>* context,
      scoped_refptr<net::CertNetFetcherURLRequest>* cert_net_fetcher) {
    (*cert_net_fetcher)->Shutdown();
    cert_net_fetcher->reset();
    context->reset();
  }

  base::test::TaskEnvironment task_environment_;

  std::unique_ptr<base::Thread> network_thread_;

  // Owned by this thread, but initialized, used, and shutdown on the network
  // thread.
  std::unique_ptr<URLRequestContext> context_;
  scoped_refptr<CertNetFetcherURLRequest> cert_net_fetcher_;

  EmbeddedTestServer test_server_;

  // The list of registered handlers. Can only be accessed when the lock is
  // held, as this data is shared between the embedded server's IO thread, and
  // the test main thread.
  base::Lock request_handlers_lock_;
  std::vector<test_server::EmbeddedTestServer::HandleRequestCallback>
      request_handlers_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         CertVerifyProcInternalWithNetFetchingTest,
                         testing::ValuesIn(kAllCertVerifiers),
                         VerifyProcTypeToName);

// Tries verifying a certificate chain that is missing an intermediate. The
// intermediate is available via AIA, however the server responds with a 404.
//
// NOTE: This test is separate from IntermediateFromAia200 as a different URL
// needs to be used to avoid having the result depend on globally cached success
// or failure of the fetch.
// Test is flaky on iOS crbug.com/860189
#if BUILDFLAG(IS_IOS)
#define MAYBE_IntermediateFromAia404 DISABLED_IntermediateFromAia404
#else
#define MAYBE_IntermediateFromAia404 IntermediateFromAia404
#endif
TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       MAYBE_IntermediateFromAia404) {
  const char kHostname[] = "www.example.com";

  // Create a chain where the leaf has an AIA that points to test server.
  scoped_refptr<X509Certificate> leaf;
  std::string ca_issuers_path;
  bssl::UniquePtr<CRYPTO_BUFFER> intermediate;
  scoped_refptr<X509Certificate> root;
  CreateSimpleChainWithAIA(&leaf, &ca_issuers_path, &intermediate, &root);

  // Serve a 404 for the AIA url.
  RegisterSimpleTestServerHandler(ca_issuers_path, HTTP_NOT_FOUND, "text/plain",
                                  "Not Found");

  // Trust the root certificate.
  ScopedTestRoot scoped_root(root);

  // The chain being verified is solely the leaf certificate (missing the
  // intermediate and root).
  ASSERT_EQ(0u, leaf->intermediate_buffers().size());

  const int flags = 0;
  int error;
  CertVerifyResult verify_result;

  // Verifying the chain should fail as the intermediate is missing, and
  // cannot be fetched via AIA.
  error = Verify(leaf.get(), kHostname, flags, &verify_result);
  EXPECT_NE(OK, error);

  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
}
#undef MAYBE_IntermediateFromAia404

// Tries verifying a certificate chain that is missing an intermediate. The
// intermediate is available via AIA.
// TODO(crbug.com/41399468): Failing on iOS
#if BUILDFLAG(IS_IOS)
#define MAYBE_IntermediateFromAia200Der DISABLED_IntermediateFromAia200Der
#else
#define MAYBE_IntermediateFromAia200Der IntermediateFromAia200Der
#endif
TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       MAYBE_IntermediateFromAia200Der) {
  const char kHostname[] = "www.example.com";

  // Create a chain where the leaf has an AIA that points to test server.
  scoped_refptr<X509Certificate> leaf;
  std::string ca_issuers_path;
  bssl::UniquePtr<CRYPTO_BUFFER> intermediate;
  scoped_refptr<X509Certificate> root;
  CreateSimpleChainWithAIA(&leaf, &ca_issuers_path, &intermediate, &root);

  // Setup the test server to reply with the correct intermediate.
  RegisterSimpleTestServerHandler(
      ca_issuers_path, HTTP_OK, "application/pkix-cert",
      std::string(x509_util::CryptoBufferAsStringPiece(intermediate.get())));

  // Trust the root certificate.
  ScopedTestRoot scoped_root(root);

  // The chain being verified is solely the leaf certificate (missing the
  // intermediate and root).
  ASSERT_EQ(0u, leaf->intermediate_buffers().size());

  // VERIFY_DISABLE_NETWORK_FETCHES flag is not implemented in
  // CertVerifyProcIOS, only test it on other verifiers.
  if (verify_proc_type() != CERT_VERIFY_PROC_IOS) {
    CertVerifyResult verify_result;
    // If VERIFY_DISABLE_NETWORK_FETCHES is specified, AIA should not be
    // attempted and verifying the chain should fail since the intermediate
    // can't be found.
    int error =
        Verify(leaf.get(), kHostname,
               CertVerifyProc::VERIFY_DISABLE_NETWORK_FETCHES, &verify_result);
    EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
    EXPECT_EQ(0u, verify_result.verified_cert->intermediate_buffers().size());
  }

  {
    CertVerifyResult verify_result;
    // Verifying the chain should succeed as the missing intermediate can be
    // fetched via AIA.
    int error = Verify(leaf.get(), kHostname, /*flags=*/0, &verify_result);
    EXPECT_THAT(error, IsOk());
  }
}

// This test is the same as IntermediateFromAia200Der, except the certificate is
// served as PEM rather than DER.
//
// Tries verifying a certificate chain that is missing an intermediate. The
// intermediate is available via AIA, however is served as a PEM file rather
// than DER.
// TODO(crbug.com/41399468): Failing on iOS
#if BUILDFLAG(IS_IOS)
#define MAYBE_IntermediateFromAia200Pem DISABLED_IntermediateFromAia200Pem
#else
#define MAYBE_IntermediateFromAia200Pem IntermediateFromAia200Pem
#endif
TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       MAYBE_IntermediateFromAia200Pem) {
  const char kHostname[] = "www.example.com";

  // Create a chain where the leaf has an AIA that points to test server.
  scoped_refptr<X509Certificate> leaf;
  std::string ca_issuers_path;
  bssl::UniquePtr<CRYPTO_BUFFER> intermediate;
  scoped_refptr<X509Certificate> root;
  CreateSimpleChainWithAIA(&leaf, &ca_issuers_path, &intermediate, &root);

  std::string intermediate_pem;
  ASSERT_TRUE(
      X509Certificate::GetPEMEncoded(intermediate.get(), &intermediate_pem));

  // Setup the test server to reply with the correct intermediate.
  RegisterSimpleTestServerHandler(
      ca_issuers_path, HTTP_OK, "application/x-x509-ca-cert", intermediate_pem);

  // Trust the root certificate.
  ScopedTestRoot scoped_root(root);

  // The chain being verified is solely the leaf certificate (missing the
  // intermediate and root).
  ASSERT_EQ(0u, leaf->intermediate_buffers().size());

  const int flags = 0;
  int error;
  CertVerifyResult verify_result;

  // Verifying the chain should succeed as the missing intermediate can be
  // fetched via AIA.
  error = Verify(leaf.get(), kHostname, flags, &verify_result);

  if (verify_proc_type() == CERT_VERIFY_PROC_ANDROID) {
    // Android doesn't support PEM - https://crbug.com/725180
    EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  } else {
    EXPECT_THAT(error, IsOk());
  }

}

// This test is the same as IntermediateFromAia200Pem, but with a different
// formatting on the PEM data.
//
// TODO(crbug.com/41399468): Failing on iOS
#if BUILDFLAG(IS_IOS)
#define MAYBE_IntermediateFromAia200Pem2 DISABLED_IntermediateFromAia200Pem2
#else
#define MAYBE_IntermediateFromAia200Pem2 IntermediateFromAia200Pem2
#endif
TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       MAYBE_IntermediateFromAia200Pem2) {
  const char kHostname[] = "www.example.com";

  // Create a chain where the leaf has an AIA that points to test server.
  scoped_refptr<X509Certificate> leaf;
  std::string ca_issuers_path;
  bssl::UniquePtr<CRYPTO_BUFFER> intermediate;
  scoped_refptr<X509Certificate> root;
  CreateSimpleChainWithAIA(&leaf, &ca_issuers_path, &intermediate, &root);

  std::string intermediate_pem;
  ASSERT_TRUE(
      X509Certificate::GetPEMEncoded(intermediate.get(), &intermediate_pem));
  intermediate_pem = "Text at start of file\n" + intermediate_pem;

  // Setup the test server to reply with the correct intermediate.
  RegisterSimpleTestServerHandler(
      ca_issuers_path, HTTP_OK, "application/x-x509-ca-cert", intermediate_pem);

  // Trust the root certificate.
  ScopedTestRoot scoped_root(root);

  // The chain being verified is solely the leaf certificate (missing the
  // intermediate and root).
  ASSERT_EQ(0u, leaf->intermediate_buffers().size());

  const int flags = 0;
  int error;
  CertVerifyResult verify_result;

  // Verifying the chain should succeed as the missing intermediate can be
  // fetched via AIA.
  error = Verify(leaf.get(), kHostname, flags, &verify_result);

  if (verify_proc_type() == CERT_VERIFY_PROC_ANDROID) {
    // Android doesn't support PEM - https://crbug.com/725180
    EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  } else {
    EXPECT_THAT(error, IsOk());
  }
}

// Tries verifying a certificate chain that uses a SHA1 intermediate,
// however, chasing the AIA can discover a SHA256 version of the intermediate.
//
// Path building should discover the stronger intermediate and use it.
TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       Sha1IntermediateButAIAHasSha256) {
  const char kHostname[] = "www.example.com";

  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  // Make the leaf certificate have an AIA (CA Issuers) that points to the
  // embedded test server. This uses a random URL for predictable behavior in
  // the presence of global caching.
  std::string ca_issuers_path = MakeRandomPath(".cer");
  GURL ca_issuers_url = GetTestServerAbsoluteUrl(ca_issuers_path);
  leaf->SetCaIssuersUrl(ca_issuers_url);
  leaf->SetSubjectAltName(kHostname);

  // Make two versions of the intermediate - one that is SHA256 signed, and one
  // that is SHA1 signed. Note that the subjectKeyIdentifier for `intermediate`
  // is intentionally not changed, so that path building will consider both
  // certificate paths.
  intermediate->SetSignatureAlgorithm(bssl::SignatureAlgorithm::kEcdsaSha256);
  intermediate->SetRandomSerialNumber();
  auto intermediate_sha256 = intermediate->DupCertBuffer();

  intermediate->SetSignatureAlgorithm(bssl::SignatureAlgorithm::kEcdsaSha1);
  intermediate->SetRandomSerialNumber();
  auto intermediate_sha1 = intermediate->DupCertBuffer();

  // Trust the root certificate.
  auto root_cert = root->GetX509Certificate();
  ScopedTestRoot scoped_root(root_cert);

  // Setup the test server to reply with the SHA256 intermediate.
  RegisterSimpleTestServerHandler(
      ca_issuers_path, HTTP_OK, "application/pkix-cert",
      std::string(
          x509_util::CryptoBufferAsStringPiece(intermediate_sha256.get())));

  // Build a chain to verify that includes the SHA1 intermediate.
  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
  intermediates.push_back(bssl::UpRef(intermediate_sha1.get()));
  scoped_refptr<X509Certificate> chain_sha1 = X509Certificate::CreateFromBuffer(
      leaf->DupCertBuffer(), std::move(intermediates));
  ASSERT_TRUE(chain_sha1.get());

  const int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(chain_sha1.get(), kHostname, flags, &verify_result);

  if (VerifyProcTypeIsBuiltin()) {
    // Should have built a chain through the SHA256 intermediate. This was only
    // available via AIA, and not the (SHA1) one provided directly to path
    // building.
    ASSERT_EQ(2u, verify_result.verified_cert->intermediate_buffers().size());
    EXPECT_TRUE(x509_util::CryptoBufferEqual(
        verify_result.verified_cert->intermediate_buffers()[0].get(),
        intermediate_sha256.get()));
    ASSERT_EQ(2u, verify_result.verified_cert->intermediate_buffers().size());

    EXPECT_FALSE(verify_result.has_sha1);
    EXPECT_THAT(error, IsOk());
  } else {
    EXPECT_NE(OK, error);
    if (verify_proc_type() == CERT_VERIFY_PROC_ANDROID &&
        error == ERR_CERT_AUTHORITY_INVALID) {
      // Newer Android versions reject the chain due to the SHA1 intermediate,
      // but do not build the correct chain by AIA. Since only the partial
      // chain is returned, CertVerifyProc does not mark it as SHA1 as it does
      // not examine the last cert in the chain. Therefore, if
      // ERR_CERT_AUTHORITY_INVALID is returned, don't check the rest of the
      // statuses. See https://crbug.com/1191795.
      return;
    }
    EXPECT_TRUE(verify_result.cert_status &
                CERT_STATUS_WEAK_SIGNATURE_ALGORITHM);
    EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_SHA1_SIGNATURE_PRESENT);
    EXPECT_TRUE(verify_result.has_sha1);
  }
}

TEST_P(CertVerifyProcInternalWithNetFetchingTest, RevocationHardFailNoCrls) {
  if (!SupportsRevCheckingRequiredLocalAnchors()) {
    LOG(INFO) << "Skipping test as verifier doesn't support "
                 "VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS";
    return;
  }

  // Create certs which have no AIA or CRL distribution points.
  const char kHostname[] = "www.example.com";
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  // Verify with hard-fail revocation checking for local anchors.
  const int flags = CertVerifyProc::VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), kHostname, flags, &verify_result);

  EXPECT_THAT(error, IsError(ERR_CERT_NO_REVOCATION_MECHANISM));
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_REV_CHECKING_ENABLED);
}

TEST_P(CertVerifyProcInternalWithNetFetchingTest,
       RevocationHardFailNoCrlsDisableNetworkFetches) {
  if (!SupportsRevCheckingRequiredLocalAnchors()) {
    LOG(INFO) << "Skipping test as verifier doesn't support "
                 "VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS";
    return;
  }

  // Create certs which have no AIA or CRL distribution points.
  const char kHostname[] = "www.example.com";
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  // Trust the root and build a chain to verify that includes the intermediate.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  scoped_refptr<X509Certificate> chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(chain.get());

  // Verify with flags for both hard-fail revocation checking for local anchors
  // and disabling network fetches.
  const int flags = CertVerifyProc::VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS |
                    CertVerifyProc::VERIFY_DISABLE_NETWORK_FETCHES;
  CertVerifyResult verify_result;
  int error = Verify(chain.get(), kHostname, flags, &verify_result);

  // Should succeed, VERIFY_DISABLE_NETWORK_FETCHES takes priority.
  EXPECT_THAT(error, IsOk());
```