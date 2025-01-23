Response:
Let's break down the thought process to analyze the CachingCertVerifier unittest file.

1. **Understand the Goal:** The primary goal is to understand the functionality of `CachingCertVerifier` and how this test file verifies its behavior. The prompt also specifically asks for connections to JavaScript, logical reasoning (with inputs/outputs), common errors, and debugging steps.

2. **Identify the Core Class Under Test:** The filename `caching_cert_verifier_unittest.cc` immediately tells us the central subject is the `CachingCertVerifier` class. Looking at the includes and the test fixture reinforces this.

3. **Analyze the Test Structure:** The file uses Google Test (gtest). This means we should look for `TEST_F` macros which define individual test cases. The `CachingCertVerifierTest` and `CachingCertVerifierCacheClearingTest` are the main test fixtures.

4. **Deconstruct Individual Tests:** For each `TEST_F`, try to understand its purpose by reading the test name and the code within it.

    * **`CacheHit`:** This name strongly suggests it tests the caching mechanism. The code verifies that a second request for the same certificate results in a cache hit. It checks the counters (`requests`, `cache_hits`, `GetCacheSize`).

    * **`CacheHitCTResultsCached`:**  Similar to `CacheHit`, but focuses on whether Certificate Transparency (CT) results are also cached. It sets up a mock verifier with CT data and verifies it's present on the cache hit.

    * **`DifferentCACerts`:** This test explores a specific caching scenario: requests with the same server certificate but different intermediate CA certificates. The expectation is that these are treated as distinct entries in the cache.

    * **`ObserverIsForwarded`:** This test checks if notifications from the underlying `CertVerifier` are correctly propagated to observers of the `CachingCertVerifier`.

    * **`CachingCertVerifierCacheClearingTest`:**  This is a parameterized test, meaning it runs the same test logic with different "ChangeType" values. This hints at testing different scenarios that should cause the cache to be cleared.

        * **`CacheClearedSyncVerification`:** Tests cache clearing with synchronous verification. It verifies the cache is cleared and a subsequent request is not a cache hit.

        * **`CacheClearedAsyncVerification`:** Similar to the above, but tests with asynchronous verification, adding complexity about when the cache is cleared relative to the async operation's completion.

5. **Identify Key Functionalities of `CachingCertVerifier`:** Based on the tests, we can infer the main functionalities:

    * **Caching:**  Storing the results of certificate verification to speed up subsequent requests.
    * **Cache Hits:**  Successfully retrieving results from the cache.
    * **Cache Misses:**  Needing to perform a new verification.
    * **Keying:**  The cache uses the certificate chain (including intermediate CAs) and hostname as part of its key.
    * **CT Result Caching:**  Caching Certificate Transparency information along with the verification result.
    * **Observer Pattern:**  Allowing other components to be notified of changes affecting the verifier.
    * **Cache Clearing:**  Invalidating cached entries when certain events occur (configuration changes, underlying verifier changes, certificate database changes).
    * **Synchronous and Asynchronous Operations:** Handling both types of verification requests.

6. **Connect to JavaScript (if applicable):** Think about how certificate verification relates to web browsers and JavaScript. While the *implementation* in this file is C++, the *concept* of certificate verification is crucial for HTTPS security, which directly impacts JavaScript running in web pages. The `CertVerifier`'s job is to ensure the website's certificate is valid and trusted. JavaScript code making HTTPS requests relies on this process.

7. **Logical Reasoning and Examples:** For each test, identify the input (certificate, hostname, etc.) and the expected output (success/failure, cache hit/miss, etc.). This helps formalize the logic being tested.

8. **Common Errors:** Consider what could go wrong from a user's or programmer's perspective. A user might encounter certificate errors in their browser. A programmer might misuse the `CachingCertVerifier` or its underlying components.

9. **Debugging Steps:** Imagine a scenario where a certificate isn't being cached correctly. How would you use the information in this test file to debug?  The tests demonstrate the expected behavior, so discrepancies point to potential issues in the `CachingCertVerifier`'s implementation.

10. **Structure the Answer:** Organize the findings logically, addressing each part of the prompt. Start with the main functionality, then delve into specific examples, JavaScript connections, logical reasoning, errors, and debugging. Use clear headings and bullet points for readability.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** "This just tests caching."  **Correction:**  Realized it tests different caching scenarios (same cert, different CAs), CT caching, and cache clearing.
* **Initial thought:** "No direct link to JavaScript." **Correction:**  Recognized the underlying importance for HTTPS and therefore indirectly for JavaScript's interaction with secure websites.
* **While analyzing `CacheClearedAsyncVerification`:** Initially was confused about the order of operations. **Correction:** Carefully traced the execution flow, noting when the `DoCacheClearingAction()` happens relative to the async `Verify()` calls and the `WaitForResult()`.

By following this structured analysis and refining understanding along the way, a comprehensive answer can be generated.
这个C++源代码文件 `caching_cert_verifier_unittest.cc` 是 Chromium 网络栈中 `CachingCertVerifier` 类的单元测试文件。它的主要功能是验证 `CachingCertVerifier` 类的行为是否符合预期。

以下是它所测试的主要功能点：

**1. 缓存命中 (Cache Hit):**

* **功能:** 验证当对同一个证书进行多次验证请求时，第二次及以后的请求能够从缓存中直接获取结果，而无需再次进行耗时的证书验证过程。
* **测试用例:** `TEST_F(CachingCertVerifierTest, CacheHit)`
* **假设输入:**
    * 第一次请求：一个特定的证书 (例如 `ok_cert.pem`) 和一个主机名 ("www.example.com")。
    * 第二次请求：相同的证书和主机名。
* **预期输出:**
    * 第一次请求：`verifier_.cache_hits()` 为 0，表示未命中缓存。`verifier_.GetCacheSize()` 为 1，表示缓存中新增了一个条目。
    * 第二次请求：`verifier_.cache_hits()` 为 1，表示命中了缓存。`verifier_.GetCacheSize()` 仍然为 1，表示缓存大小没有改变。

**2. 缓存命中时 CT 结果也被缓存 (Cache Hit CTResultsCached):**

* **功能:** 验证证书透明度 (Certificate Transparency, CT) 的验证结果也会被缓存，并在缓存命中时一并返回。
* **测试用例:** `TEST_F(CachingCertVerifierTest, CacheHitCTResultsCached)`
* **假设输入:**
    * 第一次请求：一个配置了 CT 信息的证书。
    * 第二次请求：相同的证书。
* **预期输出:**
    * 第一次请求：`verify_result.scts` 中包含 CT 信息。
    * 第二次请求：`verify_result.scts` 中仍然包含相同的 CT 信息，并且 `cache_hits` 计数器增加。

**3. 不同 CA 证书的链被视为不同 (DifferentCACerts):**

* **功能:** 验证即使服务器证书相同，但如果其所属的证书链（中间 CA 证书不同）不同，则会被 `CachingCertVerifier` 视为不同的验证请求，不会命中缓存。
* **测试用例:** `TEST_F(CachingCertVerifierTest, DifferentCACerts)`
* **假设输入:**
    * 第一次请求：包含服务器证书和第一个中间 CA 证书的证书链。
    * 第二次请求：包含相同的服务器证书和第二个不同的中间 CA 证书的证书链。
* **预期输出:**
    * 两次请求都不会命中缓存，`cache_hits` 始终为 0，`GetCacheSize()` 会增加。

**4. 观察者模式 (ObserverIsForwarded):**

* **功能:** 验证 `CachingCertVerifier` 是否正确地将底层 `CertVerifier` 的 `OnCertVerifierChanged` 事件转发给注册的观察者。
* **测试用例:** `TEST_F(CachingCertVerifierTest, ObserverIsForwarded)`
* **假设操作:** 调用底层 `MockCertVerifier` 的 `SimulateOnCertVerifierChanged()` 方法。
* **预期输出:** 注册到 `CachingCertVerifier` 的观察者的计数器会增加。

**5. 缓存清除 (Cache Clearing):**

* **功能:** 验证在特定事件发生时，`CachingCertVerifier` 的缓存会被正确清除。这些事件包括：
    * 设置新的配置 (`SetConfig`)
    * 底层 `CertVerifier` 发生变化 (`CertVerifierChanged`)
    * 证书数据库发生变化 (`CertDBChanged`)
* **测试用例:** `TEST_P(CachingCertVerifierCacheClearingTest, ...)` 使用参数化测试覆盖不同的清除场景。
* **假设操作:**
    * 先进行一次证书验证，将结果缓存。
    * 然后触发一个缓存清除事件 (例如调用 `verifier_->SetConfig({})`)。
    * 再次进行相同的证书验证。
* **预期输出:**
    * 清除事件发生后，`verifier_->GetCacheSize()` 变为 0。
    * 第二次验证不会命中缓存，需要重新进行验证。

**与 Javascript 的关系:**

虽然这个文件本身是 C++ 代码，直接与 JavaScript 没有交互，但 `CachingCertVerifier` 的功能对于 Web 浏览器的安全至关重要，而 JavaScript 代码运行在浏览器环境中，会受到其影响。

* **HTTPS 连接:** 当 JavaScript 代码通过 `fetch` 或 `XMLHttpRequest` 发起 HTTPS 请求时，浏览器会使用 `CertVerifier` (包括 `CachingCertVerifier`) 来验证服务器的 SSL/TLS 证书。如果证书验证失败，JavaScript 代码将无法安全地与服务器通信。
* **性能优化:** `CachingCertVerifier` 的缓存机制可以显著提高 HTTPS 连接的性能。当用户访问同一个网站多次时，无需每次都重新验证证书，从而加快页面加载速度。这对运行在浏览器中的 JavaScript 应用来说是重要的。

**用户或编程常见的使用错误:**

这个单元测试主要关注 `CachingCertVerifier` 内部的逻辑，但可以从中推断出一些用户或编程常见的使用错误：

* **用户错误:**
    * **遇到证书错误:**  如果用户的操作系统或浏览器配置了不信任的根证书，或者访问的网站使用了无效的证书，`CertVerifier` 会返回错误，导致 HTTPS 连接失败。用户可能会看到浏览器显示 "您的连接不是私密连接" 等错误信息。
    * **时间不准确:**  证书的有效期是有限的，如果用户的系统时间不正确，可能会导致有效的证书被误判为过期。

* **编程错误:**
    * **错误地配置 `CertVerifier`:**  在嵌入式环境或其他非标准 Chromium 使用场景中，如果开发者错误地配置了 `CertVerifier` 的参数，可能会导致证书验证失败或缓存行为异常。
    * **假设缓存总是有效:**  开发者不应该假设缓存中的证书验证结果永远有效。证书可能会被吊销，CA 证书可能会发生变化，配置也可能更新，这些都会导致缓存失效。应该依赖 `CertVerifier` 的机制来处理这些情况。

**用户操作如何一步步到达这里，作为调试线索:**

假设用户在使用 Chrome 浏览器浏览网页时遇到了证书问题，想要进行调试，可能会触发 `CachingCertVerifier` 的相关代码：

1. **用户在地址栏输入 HTTPS 网址或点击 HTTPS 链接。**
2. **浏览器网络栈发起与服务器的 TLS 握手。**
3. **在 TLS 握手过程中，服务器会提供其证书链。**
4. **浏览器网络栈调用 `CertVerifier` (很可能是 `CachingCertVerifier`) 来验证服务器的证书链。**
5. **`CachingCertVerifier` 首先检查缓存中是否已经有该证书链的验证结果。**
    * **如果缓存命中，** 则直接返回缓存结果。
    * **如果缓存未命中，** 则调用底层的 `CertVerifier` 进行实际的证书验证。
6. **底层的 `CertVerifier` 会进行一系列检查，例如：**
    * 证书签名是否有效。
    * 证书是否在有效期内。
    * 证书链是否完整并能追溯到信任的根证书。
    * 是否有任何吊销信息 (CRL, OCSP)。
    * 是否符合证书透明度策略。
7. **验证结果（成功或失败）会被 `CachingCertVerifier` 缓存起来。**
8. **如果验证失败，浏览器会显示证书错误信息，用户可能会看到错误页面。**

**作为调试线索：**

* **网络日志 (net-internals):**  在 Chrome 浏览器中打开 `chrome://net-internals/#events` 可以查看详细的网络事件，包括证书验证的步骤和结果。这可以帮助开发者判断证书验证在哪里失败，以及是否命中了缓存。
* **`chrome://components`:**  可以查看 Certificate Provider 的状态，了解证书相关的组件是否正常工作。
* **源代码分析和断点调试:**  对于 Chromium 开发者，可以结合源代码和调试工具（如 gdb）来深入分析 `CachingCertVerifier` 的行为。例如，可以在 `Verify` 方法中设置断点，查看缓存的查找和插入过程。
* **单元测试:**  `caching_cert_verifier_unittest.cc` 文件本身就是调试 `CachingCertVerifier` 的重要参考。通过阅读和理解这些测试用例，可以更好地理解 `CachingCertVerifier` 的预期行为，从而更容易定位问题。例如，如果发现缓存行为与某个测试用例的预期不符，就可能找到了一个 bug。

总而言之，`caching_cert_verifier_unittest.cc` 是一个关键的测试文件，用于确保 Chromium 的证书验证缓存机制的正确性和可靠性，这对于保证用户的网络安全和提升浏览体验至关重要。

### 提示词
```
这是目录为net/cert/caching_cert_verifier_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/caching_cert_verifier.h"

#include <memory>

#include "base/files/file_path.h"
#include "base/memory/ref_counted.h"
#include "base/test/task_environment.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/cert/cert_database.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "net/log/net_log_with_source.h"
#include "net/test/cert_test_util.h"
#include "net/test/ct_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

using testing::_;
using testing::Mock;
using testing::Return;
using testing::ReturnRef;

namespace net {

class CachingCertVerifierTest : public TestWithTaskEnvironment {
 public:
  CachingCertVerifierTest() : verifier_(std::make_unique<MockCertVerifier>()) {}
  ~CachingCertVerifierTest() override = default;

 protected:
  CachingCertVerifier verifier_;
};

TEST_F(CachingCertVerifierTest, CacheHit) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<X509Certificate> test_cert(
      ImportCertFromFile(certs_dir, "ok_cert.pem"));
  ASSERT_TRUE(test_cert.get());

  int error;
  CertVerifyResult verify_result;
  TestCompletionCallback callback;
  std::unique_ptr<CertVerifier::Request> request;

  error = callback.GetResult(verifier_.Verify(
      CertVerifier::RequestParams(test_cert, "www.example.com", 0,
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string()),
      &verify_result, callback.callback(), &request, NetLogWithSource()));
  ASSERT_TRUE(IsCertificateError(error));
  ASSERT_EQ(1u, verifier_.requests());
  ASSERT_EQ(0u, verifier_.cache_hits());
  ASSERT_EQ(1u, verifier_.GetCacheSize());

  error = verifier_.Verify(
      CertVerifier::RequestParams(test_cert, "www.example.com", 0,
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string()),
      &verify_result, callback.callback(), &request, NetLogWithSource());
  // Synchronous completion.
  ASSERT_NE(ERR_IO_PENDING, error);
  ASSERT_TRUE(IsCertificateError(error));
  ASSERT_FALSE(request);
  ASSERT_EQ(2u, verifier_.requests());
  ASSERT_EQ(1u, verifier_.cache_hits());
  ASSERT_EQ(1u, verifier_.GetCacheSize());
}

TEST_F(CachingCertVerifierTest, CacheHitCTResultsCached) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<X509Certificate> test_cert(
      ImportCertFromFile(certs_dir, "ok_cert.pem"));
  ASSERT_TRUE(test_cert.get());

  auto cert_verifier = std::make_unique<MockCertVerifier>();
  // Mock the cert verification and CT verification results.
  CertVerifyResult mock_result;
  mock_result.cert_status = OK;
  mock_result.verified_cert = test_cert;

  scoped_refptr<ct::SignedCertificateTimestamp> sct;
  ct::GetX509CertSCT(&sct);
  SignedCertificateTimestampAndStatus sct_and_status(sct, ct::SCT_STATUS_OK);
  SignedCertificateTimestampAndStatusList sct_list{sct_and_status};
  mock_result.scts = sct_list;
  cert_verifier->AddResultForCert(test_cert, mock_result, OK);

  // We don't use verifier_ here because we needed to call AddResultForCert from
  // the mock verifier.
  CachingCertVerifier cache_verifier(std::move(cert_verifier));

  int result;
  CertVerifyResult verify_result;
  TestCompletionCallback callback;
  std::unique_ptr<CertVerifier::Request> request;

  result = callback.GetResult(cache_verifier.Verify(
      CertVerifier::RequestParams(test_cert, "www.example.com", 0,
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string()),
      &verify_result, callback.callback(), &request, NetLogWithSource()));
  ASSERT_EQ(OK, result);
  ASSERT_EQ(1u, verify_result.scts.size());
  ASSERT_EQ(ct::SCT_STATUS_OK, verify_result.scts[0].status);
  ASSERT_EQ(1u, cache_verifier.requests());
  ASSERT_EQ(0u, cache_verifier.cache_hits());
  ASSERT_EQ(1u, cache_verifier.GetCacheSize());

  result = cache_verifier.Verify(
      CertVerifier::RequestParams(test_cert, "www.example.com", 0,
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string()),
      &verify_result, callback.callback(), &request, NetLogWithSource());
  // Synchronous completion.
  ASSERT_EQ(OK, result);
  ASSERT_FALSE(request);
  ASSERT_EQ(1u, verify_result.scts.size());
  ASSERT_EQ(ct::SCT_STATUS_OK, verify_result.scts[0].status);
  ASSERT_EQ(2u, cache_verifier.requests());
  ASSERT_EQ(1u, cache_verifier.cache_hits());
  ASSERT_EQ(1u, cache_verifier.GetCacheSize());
}

// Tests the same server certificate with different intermediate CA
// certificates.  These should be treated as different certificate chains even
// though the two X509Certificate objects contain the same server certificate.
TEST_F(CachingCertVerifierTest, DifferentCACerts) {
  base::FilePath certs_dir = GetTestCertsDirectory();

  scoped_refptr<X509Certificate> server_cert =
      ImportCertFromFile(certs_dir, "salesforce_com_test.pem");
  ASSERT_TRUE(server_cert);

  scoped_refptr<X509Certificate> intermediate_cert1 =
      ImportCertFromFile(certs_dir, "verisign_intermediate_ca_2011.pem");
  ASSERT_TRUE(intermediate_cert1);

  scoped_refptr<X509Certificate> intermediate_cert2 =
      ImportCertFromFile(certs_dir, "verisign_intermediate_ca_2016.pem");
  ASSERT_TRUE(intermediate_cert2);

  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
  intermediates.push_back(bssl::UpRef(intermediate_cert1->cert_buffer()));
  scoped_refptr<X509Certificate> cert_chain1 =
      X509Certificate::CreateFromBuffer(bssl::UpRef(server_cert->cert_buffer()),
                                        std::move(intermediates));
  ASSERT_TRUE(cert_chain1);

  intermediates.clear();
  intermediates.push_back(bssl::UpRef(intermediate_cert2->cert_buffer()));
  scoped_refptr<X509Certificate> cert_chain2 =
      X509Certificate::CreateFromBuffer(bssl::UpRef(server_cert->cert_buffer()),
                                        std::move(intermediates));
  ASSERT_TRUE(cert_chain2);

  int error;
  CertVerifyResult verify_result;
  TestCompletionCallback callback;
  std::unique_ptr<CertVerifier::Request> request;

  error = callback.GetResult(verifier_.Verify(
      CertVerifier::RequestParams(cert_chain1, "www.example.com", 0,
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string()),
      &verify_result, callback.callback(), &request, NetLogWithSource()));
  ASSERT_TRUE(IsCertificateError(error));
  ASSERT_EQ(1u, verifier_.requests());
  ASSERT_EQ(0u, verifier_.cache_hits());
  ASSERT_EQ(1u, verifier_.GetCacheSize());

  error = callback.GetResult(verifier_.Verify(
      CertVerifier::RequestParams(cert_chain2, "www.example.com", 0,
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string()),
      &verify_result, callback.callback(), &request, NetLogWithSource()));
  ASSERT_TRUE(IsCertificateError(error));
  ASSERT_EQ(2u, verifier_.requests());
  ASSERT_EQ(0u, verifier_.cache_hits());
  ASSERT_EQ(2u, verifier_.GetCacheSize());
}

TEST_F(CachingCertVerifierTest, ObserverIsForwarded) {
  auto mock_cert_verifier = std::make_unique<MockCertVerifier>();
  MockCertVerifier* mock_cert_verifier_ptr = mock_cert_verifier.get();
  CachingCertVerifier cache_verifier(std::move(mock_cert_verifier));

  CertVerifierObserverCounter observer_(&cache_verifier);
  EXPECT_EQ(observer_.change_count(), 0u);
  // A CertVerifierChanged event on the wrapped verifier should be forwarded to
  // observers registered on CachingCertVerifier.
  mock_cert_verifier_ptr->SimulateOnCertVerifierChanged();
  EXPECT_EQ(observer_.change_count(), 1u);
}

namespace {
enum class ChangeType {
  kSetConfig,
  kCertVerifierChanged,
  kCertDBChanged,
};
}  // namespace

class CachingCertVerifierCacheClearingTest
    : public testing::TestWithParam<ChangeType> {
 public:
  CachingCertVerifierCacheClearingTest() {
    auto mock_cert_verifier = std::make_unique<MockCertVerifier>();
    mock_verifier_ = mock_cert_verifier.get();
    verifier_ =
        std::make_unique<CachingCertVerifier>(std::move(mock_cert_verifier));
  }

  ChangeType change_type() const { return GetParam(); }

  void DoCacheClearingAction() {
    switch (change_type()) {
      case ChangeType::kSetConfig:
        verifier_->SetConfig({});
        break;
      case ChangeType::kCertVerifierChanged:
        mock_verifier_->SimulateOnCertVerifierChanged();
        break;
      case ChangeType::kCertDBChanged:
        CertDatabase::GetInstance()->NotifyObserversTrustStoreChanged();
        base::RunLoop().RunUntilIdle();
        break;
    }
  }

 protected:
  base::test::SingleThreadTaskEnvironment task_environment_;
  std::unique_ptr<CachingCertVerifier> verifier_;
  raw_ptr<MockCertVerifier> mock_verifier_;
};

TEST_P(CachingCertVerifierCacheClearingTest, CacheClearedSyncVerification) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<X509Certificate> test_cert(
      ImportCertFromFile(certs_dir, "ok_cert.pem"));
  ASSERT_TRUE(test_cert.get());

  mock_verifier_->set_async(false);

  int error;
  CertVerifyResult verify_result;
  TestCompletionCallback callback;
  std::unique_ptr<CertVerifier::Request> request;

  error = verifier_->Verify(
      CertVerifier::RequestParams(test_cert, "www.example.com", 0,
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string()),
      &verify_result, callback.callback(), &request, NetLogWithSource());
  ASSERT_TRUE(IsCertificateError(error));
  ASSERT_EQ(1u, verifier_->requests());
  ASSERT_EQ(0u, verifier_->cache_hits());
  ASSERT_EQ(1u, verifier_->GetCacheSize());

  DoCacheClearingAction();
  ASSERT_EQ(0u, verifier_->GetCacheSize());

  error = verifier_->Verify(
      CertVerifier::RequestParams(test_cert, "www.example.com", 0,
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string()),
      &verify_result, callback.callback(), &request, NetLogWithSource());
  ASSERT_TRUE(IsCertificateError(error));
  ASSERT_FALSE(request);
  ASSERT_EQ(2u, verifier_->requests());
  ASSERT_EQ(0u, verifier_->cache_hits());
  ASSERT_EQ(1u, verifier_->GetCacheSize());
}

TEST_P(CachingCertVerifierCacheClearingTest, CacheClearedAsyncVerification) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<X509Certificate> test_cert(
      ImportCertFromFile(certs_dir, "ok_cert.pem"));
  ASSERT_TRUE(test_cert.get());

  mock_verifier_->set_async(true);

  int error;
  CertVerifyResult verify_result;
  TestCompletionCallback callback;
  std::unique_ptr<CertVerifier::Request> request;

  error = verifier_->Verify(
      CertVerifier::RequestParams(test_cert, "www.example.com", 0,
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string()),
      &verify_result, callback.callback(), &request, NetLogWithSource());
  ASSERT_EQ(ERR_IO_PENDING, error);
  ASSERT_TRUE(request);
  ASSERT_EQ(1u, verifier_->requests());
  ASSERT_EQ(0u, verifier_->cache_hits());
  ASSERT_EQ(0u, verifier_->GetCacheSize());

  DoCacheClearingAction();
  ASSERT_EQ(0u, verifier_->GetCacheSize());

  error = callback.WaitForResult();
  ASSERT_TRUE(IsCertificateError(error));
  // Async result should not have been cached since it was from a verification
  // started before the config changed.
  ASSERT_EQ(0u, verifier_->GetCacheSize());

  error = verifier_->Verify(
      CertVerifier::RequestParams(test_cert, "www.example.com", 0,
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string()),
      &verify_result, callback.callback(), &request, NetLogWithSource());
  ASSERT_EQ(ERR_IO_PENDING, error);
  ASSERT_TRUE(request);
  ASSERT_EQ(2u, verifier_->requests());
  ASSERT_EQ(0u, verifier_->cache_hits());
  ASSERT_EQ(0u, verifier_->GetCacheSize());

  error = callback.WaitForResult();
  ASSERT_TRUE(IsCertificateError(error));
  // New async result should be cached since it was from a verification started
  // after the config changed.
  ASSERT_EQ(1u, verifier_->GetCacheSize());

  // Verify again. Result should be synchronous this time since it will get the
  // cached result.
  error = verifier_->Verify(
      CertVerifier::RequestParams(test_cert, "www.example.com", 0,
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string()),
      &verify_result, callback.callback(), &request, NetLogWithSource());
  ASSERT_TRUE(IsCertificateError(error));
  ASSERT_FALSE(request);
  ASSERT_EQ(3u, verifier_->requests());
  ASSERT_EQ(1u, verifier_->cache_hits());
  ASSERT_EQ(1u, verifier_->GetCacheSize());
}

INSTANTIATE_TEST_SUITE_P(All,
                         CachingCertVerifierCacheClearingTest,
                         testing::Values(ChangeType::kSetConfig,
                                         ChangeType::kCertVerifierChanged,
                                         ChangeType::kCertDBChanged));

}  // namespace net
```