Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Understanding the Goal:**

The primary goal is to understand the purpose and functionality of the `net/cert/test_root_certs_unittest.cc` file within the Chromium networking stack. This involves identifying what it tests, how it tests it, and any connections to other concepts (like JavaScript).

**2. Initial Scan and Keyword Recognition:**

Quickly scan the file for recognizable keywords and patterns:

* `#include`: Indicates dependencies on other parts of the codebase. Notice `net/cert/test_root_certs.h`. This suggests the file is testing the functionality defined in that header.
* `namespace net`:  Confirms it's part of the `net` namespace, relating to networking.
* `TEST_P`, `TEST`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_NE`, `EXPECT_EQ`, `EXPECT_THAT`: These are all standard Google Test (gtest) macros, clearly indicating this is a unit test file.
* `CertVerifyProc`, `X509Certificate`, `CertVerifyResult`, `CERT_STATUS_AUTHORITY_INVALID`: These terms relate to certificate verification and trust.
* `ScopedTestRoot`, `ScopedTestKnownRoot`: These seem to be helper classes specific to the tests. Their names strongly suggest they manage the addition and removal of test root certificates.
* `ImportCertFromFile`, `GetTestCertsDirectory`: These indicate the tests load certificate data from files.

**3. Identifying the Core Tested Class:**

The `#include "net/cert/test_root_certs.h"` is a strong indicator. The class being tested is likely `TestRootCerts`.

**4. Deciphering the Test Cases:**

Examine each `TEST_P` or `TEST` function to understand its specific purpose:

* **`AddFromPointer`:**  This test loads a certificate and uses `ScopedTestRoot` to add it to `TestRootCerts`. It then checks if `TestRootCerts` is empty before and after the scope of `ScopedTestRoot`. This tests the basic addition and automatic removal of a test root certificate.

* **`OverrideTrust`:** This test is more involved. It verifies that a certificate *fails* verification initially, then *succeeds* after adding the root certificate using `ScopedTestRoot`, and finally *fails* again after the `ScopedTestRoot` goes out of scope. This demonstrates the ability to temporarily override trust settings during testing.

* **`OverrideKnownRoot`:**  Similar to `OverrideTrust`, but it specifically tests the `is_issued_by_known_root` flag. It adds a root certificate using `ScopedTestKnownRoot` and verifies this flag is set, and then that it's cleared after the scope ends.

* **`Moveable`:** This test focuses on the move semantics of `ScopedTestRoot`. It shows that the ownership of the added test root certificate can be transferred between `ScopedTestRoot` instances, ensuring the trust remains active as long as at least one `ScopedTestRoot` holds it.

**5. Analyzing `ScopedTestRoot` and `ScopedTestKnownRoot`:**

Based on their usage in the tests, it's clear these classes are RAII (Resource Acquisition Is Initialization) wrappers. They likely add the specified certificate to `TestRootCerts` in their constructor and remove it in their destructor (or revert the trust status). `ScopedTestKnownRoot` likely has the additional responsibility of marking a certificate as a "known root" for testing purposes.

**6. Identifying Functionality:**

Based on the tests, the core functionality of `TestRootCerts` and its associated helper classes is:

* **Temporarily adding test root certificates:** This allows tests to simulate scenarios where a particular certificate is trusted.
* **Temporarily marking certificates as "known roots":** This helps test logic that depends on whether a certificate is issued by a well-known authority.
* **Automatic cleanup:** The `ScopedTestRoot` and `ScopedTestKnownRoot` classes ensure that the added test roots and modified trust settings are automatically removed when they go out of scope, preventing interference between tests.

**7. Considering the JavaScript Connection:**

Think about where certificate verification plays a role in a web browser, which often involves JavaScript. JavaScript itself doesn't directly handle the low-level details of certificate verification. However, JavaScript running in a browser makes requests to servers over HTTPS. The browser's networking stack (which includes the code being tested here) is responsible for verifying the server's certificate. Therefore, while no direct JavaScript code is present, the functionality being tested directly *enables* secure HTTPS communication that JavaScript relies on.

**8. Formulating Examples and Explanations:**

Now, translate the understanding into concrete explanations:

* **Functionality:**  Summarize the core purposes.
* **JavaScript Relation:** Explain the indirect connection through HTTPS and browser security. Provide an example of a JavaScript `fetch()` call and how the underlying certificate verification (influenced by these tests) impacts it.
* **Logical Reasoning:** Create simple scenarios with inputs and expected outputs to illustrate the `OverrideTrust` and `OverrideKnownRoot` tests.
* **User/Programming Errors:** Think about how developers might misuse the `TestRootCerts` mechanism, like forgetting to scope it correctly or making assumptions about its persistence.
* **Debugging:** Describe the user actions that lead to a certificate verification process, thus bringing this code into play. This involves visiting HTTPS websites and the browser's certificate handling.

**9. Refinement and Review:**

Read through the explanations to ensure clarity, accuracy, and completeness. Check for any logical inconsistencies or areas that could be explained more effectively. For example, initially, I might have focused too much on the C++ aspects. Refining it to explicitly connect to the *purpose* within a browser environment is crucial.

This systematic approach, starting with high-level goals and progressively digging into the code's details, is essential for understanding complex software like the Chromium networking stack.
好的，让我们来分析一下 `net/cert/test_root_certs_unittest.cc` 这个文件。

**文件功能:**

这个文件是 Chromium 网络栈中用于测试 `net/cert/test_root_certs.h` 中定义的 `TestRootCerts` 及其相关辅助类的单元测试。 `TestRootCerts` 的主要功能是：

1. **在单元测试环境中临时添加和移除信任的根证书。**  这允许开发者在测试网络代码时，模拟特定的证书信任环境，而无需修改系统或浏览器的全局信任设置。
2. **临时标记某些根证书为“已知根证书”。**  这可以测试代码中关于判断证书是否由公共信任的 CA 签发的逻辑。

简单来说，这个文件通过编写一系列测试用例，验证 `TestRootCerts` 类能否正确地添加、移除测试根证书，以及这些操作是否会影响证书验证的结果（例如，证书是否被认为是受信任的，是否被认为是已知根签发的）。

**与 JavaScript 功能的关系:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它所测试的功能与 JavaScript 的安全通信密切相关。当 JavaScript 代码通过 HTTPS 发起网络请求时，浏览器需要验证服务器提供的 SSL/TLS 证书。这个验证过程会检查证书是否由浏览器信任的根证书颁发机构 (CA) 签名。

`TestRootCerts` 提供的功能允许 Chromium 开发者编写单元测试，来验证网络栈在各种证书信任场景下的行为。例如，可以测试以下情况：

* **测试一个由自签名证书保护的 HTTPS 站点:**  通过 `TestRootCerts` 临时添加该自签名证书作为信任的根证书，可以模拟用户手动信任该证书的情况，并测试 JavaScript 代码能否成功访问该站点。
* **测试一个由中间 CA 签发的证书:**  可以添加中间 CA 的证书作为信任的根证书，来验证证书链的验证逻辑。
* **测试已知根证书的影响:**  可以临时将某个证书标记为已知根证书，测试 JavaScript 代码是否能正确识别由公共信任 CA 签发的证书。

**举例说明:**

假设有一个 JavaScript 代码尝试访问一个使用自签名证书的 HTTPS 站点：

```javascript
fetch('https://self-signed.example.com')
  .then(response => response.text())
  .then(data => console.log(data))
  .catch(error => console.error('Error:', error));
```

在默认情况下，浏览器会拒绝连接，因为该自签名证书不被信任。但是，在单元测试中，可以使用 `TestRootCerts` 临时添加该自签名证书到信任列表，然后运行这个 JavaScript 代码，验证网络栈是否能正确处理这种情况。

**逻辑推理与假设输入/输出:**

我们来看 `OverrideTrust` 这个测试用例：

**假设输入:**

1. 一个由 `kRootCertificateFile` 中定义的根证书签发的证书 (`kGoodCertificateFile`)。
2. 初始状态下，`TestRootCerts` 是空的，即没有添加任何测试根证书。

**预期输出 (第一次验证):**

* 证书验证会失败 (`bad_status` 不等于 `OK`)。
* 证书状态会包含 `CERT_STATUS_AUTHORITY_INVALID`，表明证书的颁发机构不被信任。
* `is_issued_by_known_root` 为 `false`。

**假设输入 (添加根证书后):**

1. 与上述相同的证书。
2. 通过 `ScopedTestRoot` 将 `kRootCertificateFile` 中定义的根证书添加到 `TestRootCerts`。

**预期输出 (第二次验证):**

* 证书验证会成功 (`good_status` 等于 `OK`)。
* 证书状态不包含错误 (`good_verify_result.cert_status` 为 0)。
* `is_issued_by_known_root` 为 `false` (因为我们只是临时信任了这个根证书，它不是系统或浏览器默认信任的根)。

**假设输入 (移除根证书后):**

1. 与上述相同的证书。
2. `ScopedTestRoot` 的作用域结束，之前添加的根证书被移除。

**预期输出 (第三次验证):**

* 证书验证会失败 (`restored_status` 不等于 `OK`)。
* 证书状态会重新包含 `CERT_STATUS_AUTHORITY_INVALID`。
* 恢复到第一次验证时的状态 (`restored_status` 等于 `bad_status`, `restored_verify_result.cert_status` 等于 `bad_verify_result.cert_status`)。
* `is_issued_by_known_root` 为 `false`。

**用户或编程常见的使用错误:**

1. **忘记使用 `ScopedTestRoot` 或 `ScopedTestKnownRoot`:** 如果直接操作 `TestRootCerts` 的单例而不使用这些 RAII 风格的类，可能会导致在测试结束后，测试根证书仍然存在，影响后续测试的结果。
2. **在多线程环境中使用 `TestRootCerts` 而不进行适当的同步:**  `TestRootCerts` 是一个单例，如果在多线程测试中并发地修改其状态，可能会导致竞态条件和不可预测的结果。虽然这个文件中的测试看起来是单线程的，但在更复杂的集成测试中需要注意。
3. **错误地假设 `TestRootCerts` 的作用域:** 开发者可能会错误地认为在某个函数中添加的测试根证书会在整个测试套件中生效。实际上，`ScopedTestRoot` 的作用域是其生命周期，超出这个作用域，添加的根证书会被移除。
4. **在不需要修改信任设置的测试中引入 `TestRootCerts`:**  这会增加测试的复杂性，并可能引入不必要的副作用。应该仅在需要模拟特定证书信任环境时使用 `TestRootCerts`。

**用户操作如何一步步到达这里 (作为调试线索):**

作为一个普通的最终用户，你通常不会直接涉及到 `net/cert/test_root_certs_unittest.cc` 这个文件。这个文件是 Chromium 的开发者用来测试网络栈功能的。但是，你的操作可能会触发与证书验证相关的代码，而这些代码的行为正是这个文件所测试的。

以下是一个模拟的调试场景：

1. **用户报告了一个网站的证书错误:** 用户尝试访问一个 HTTPS 网站，浏览器显示“您的连接不是私密连接”或类似的错误信息。
2. **开发者开始调查:** 开发者可能会怀疑是 Chromium 的证书验证逻辑出现了问题，或者该网站的证书存在问题。
3. **运行相关的单元测试:** 开发者可能会运行 `net/cert/test_root_certs_unittest.cc` 中的测试用例，来验证 `TestRootCerts` 和证书验证相关的代码是否按预期工作。
4. **模拟用户遇到的情况:** 开发者可能会尝试使用 `TestRootCerts` 临时添加或移除某些根证书，来模拟用户可能遇到的证书信任环境，并重现该错误。
5. **单步调试:** 如果单元测试无法直接重现问题，开发者可能会使用调试器 (例如 gdb) 单步执行与证书验证相关的代码，例如 `CertVerifyProc::Verify` 函数，来跟踪证书验证的流程，并查看 `TestRootCerts` 的状态如何影响验证结果。

**更具体的调试步骤可能如下:**

* **设置断点:** 在 `net/cert/test_root_certs_unittest.cc` 中，开发者可能会在 `OverrideTrust` 或 `OverrideKnownRoot` 等测试用例的 `verify_proc->Verify` 调用前后设置断点，查看证书验证的结果。
* **检查 `TestRootCerts` 的状态:**  在调试器中，可以查看 `TestRootCerts::GetInstance()` 返回的单例对象，确认在测试的不同阶段，哪些证书被添加为信任的根证书。
* **跟踪证书验证过程:**  单步执行 `CertVerifyProc::Verify` 函数，查看它如何使用 `TestRootCerts` 中提供的信任信息来进行验证。
* **检查证书状态标志:**  查看 `CertVerifyResult` 对象中的 `cert_status` 标志，了解证书验证失败或成功的原因，以及 `TestRootCerts` 的操作是否影响了这些标志。

总之，`net/cert/test_root_certs_unittest.cc` 是 Chromium 网络栈中一个重要的测试文件，它确保了临时添加测试根证书的功能能够正确工作，从而保障了 HTTPS 连接的安全性。虽然普通用户不会直接接触这个文件，但这个文件所测试的代码直接影响了用户在使用浏览器时的安全体验。

Prompt: 
```
这是目录为net/cert/test_root_certs_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/test_root_certs.h"

#include "base/files/file_path.h"
#include "build/build_config.h"
#include "net/base/features.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_net_fetcher.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verify_proc.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/crl_set.h"
#include "net/cert/do_nothing_ct_verifier.h"
#include "net/cert/x509_certificate.h"
#include "net/log/net_log_with_source.h"
#include "net/net_buildflags.h"
#include "net/test/cert_builder.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsOk;

namespace net {

namespace {

// The local test root certificate.
const char kRootCertificateFile[] = "root_ca_cert.pem";
// A certificate issued by the local test root for 127.0.0.1.
const char kGoodCertificateFile[] = "ok_cert.pem";

}  // namespace

class TestRootCertsTest : public testing::TestWithParam<bool> {
 public:
  scoped_refptr<CertVerifyProc> CreateCertVerifyProc() {
#if BUILDFLAG(CHROME_ROOT_STORE_OPTIONAL)
    // If CCV/CRS is optional, test with and without CCV/CRS.
    if (use_chrome_cert_validator()) {
      return CertVerifyProc::CreateBuiltinWithChromeRootStore(
          /*cert_net_fetcher=*/nullptr, CRLSet::BuiltinCRLSet().get(),
          std::make_unique<DoNothingCTVerifier>(),
          base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
          /*root_store_data=*/nullptr, /*instance_params=*/{}, std::nullopt);
    } else {
      return CertVerifyProc::CreateSystemVerifyProc(
          /*cert_net_fetcher=*/nullptr, CRLSet::BuiltinCRLSet().get());
    }
#elif BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
    return CertVerifyProc::CreateBuiltinWithChromeRootStore(
        /*cert_net_fetcher=*/nullptr, CRLSet::BuiltinCRLSet().get(),
        std::make_unique<DoNothingCTVerifier>(),
        base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
        /*root_store_data=*/nullptr, /*instance_params=*/{}, std::nullopt);
#elif BUILDFLAG(IS_FUCHSIA)
    return CertVerifyProc::CreateBuiltinVerifyProc(
        /*cert_net_fetcher=*/nullptr, CRLSet::BuiltinCRLSet().get(),
        std::make_unique<DoNothingCTVerifier>(),
        base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
        /*instance_params=*/{}, std::nullopt);
#else
  return CertVerifyProc::CreateSystemVerifyProc(/*cert_net_fetcher=*/nullptr,
                                                CRLSet::BuiltinCRLSet().get());
#endif
  }

  // Whether we use Chrome Cert Validator or not. Only relevant for platforms
  // where CHROME_ROOT_STORE_OPTIONAL is set; on other platforms both test
  // params will run the same test.
  bool use_chrome_cert_validator() { return GetParam(); }
};

// Test basic functionality when adding from an existing X509Certificate.
TEST_P(TestRootCertsTest, AddFromPointer) {
  scoped_refptr<X509Certificate> root_cert =
      ImportCertFromFile(GetTestCertsDirectory(), kRootCertificateFile);
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), root_cert.get());

  TestRootCerts* test_roots = TestRootCerts::GetInstance();
  ASSERT_NE(static_cast<TestRootCerts*>(nullptr), test_roots);
  EXPECT_TRUE(test_roots->IsEmpty());

  {
    ScopedTestRoot scoped_root(root_cert);
    EXPECT_FALSE(test_roots->IsEmpty());
  }
  EXPECT_TRUE(test_roots->IsEmpty());
}

// Test that TestRootCerts actually adds the appropriate trust status flags
// when requested, and that the trusted status is cleared once the root is
// removed the TestRootCerts. This test acts as a canary/sanity check for
// the results of the rest of net_unittests, ensuring that the trust status
// is properly being set and cleared.
TEST_P(TestRootCertsTest, OverrideTrust) {
  TestRootCerts* test_roots = TestRootCerts::GetInstance();
  ASSERT_NE(static_cast<TestRootCerts*>(nullptr), test_roots);
  EXPECT_TRUE(test_roots->IsEmpty());

  scoped_refptr<X509Certificate> test_cert =
      ImportCertFromFile(GetTestCertsDirectory(), kGoodCertificateFile);
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), test_cert.get());

  // Test that the good certificate fails verification, because the root
  // certificate should not yet be trusted.
  int flags = 0;
  CertVerifyResult bad_verify_result;
  scoped_refptr<CertVerifyProc> verify_proc(CreateCertVerifyProc());
  int bad_status = verify_proc->Verify(test_cert.get(), "127.0.0.1",
                                       /*ocsp_response=*/std::string(),
                                       /*sct_list=*/std::string(), flags,
                                       &bad_verify_result, NetLogWithSource());
  EXPECT_NE(OK, bad_status);
  EXPECT_NE(0u, bad_verify_result.cert_status & CERT_STATUS_AUTHORITY_INVALID);
  EXPECT_FALSE(bad_verify_result.is_issued_by_known_root);

  // Add the root certificate and mark it as trusted.
  scoped_refptr<X509Certificate> root_cert =
      ImportCertFromFile(GetTestCertsDirectory(), kRootCertificateFile);
  ASSERT_TRUE(root_cert);
  ScopedTestRoot scoped_root(root_cert);
  EXPECT_FALSE(test_roots->IsEmpty());

  // Test that the certificate verification now succeeds, because the
  // TestRootCerts is successfully imbuing trust.
  CertVerifyResult good_verify_result;
  int good_status = verify_proc->Verify(
      test_cert.get(), "127.0.0.1", /*ocsp_response=*/std::string(),
      /*sct_list=*/std::string(), flags, &good_verify_result,
      NetLogWithSource());
  EXPECT_THAT(good_status, IsOk());
  EXPECT_EQ(0u, good_verify_result.cert_status);
  EXPECT_FALSE(good_verify_result.is_issued_by_known_root);

  test_roots->Clear();
  EXPECT_TRUE(test_roots->IsEmpty());

  // Ensure that when the TestRootCerts is cleared, the trust settings
  // revert to their original state, and don't linger. If trust status
  // lingers, it will likely break other tests in net_unittests.
  CertVerifyResult restored_verify_result;
  int restored_status = verify_proc->Verify(
      test_cert.get(), "127.0.0.1", /*ocsp_response=*/std::string(),
      /*sct_list=*/std::string(), flags, &restored_verify_result,
      NetLogWithSource());
  EXPECT_NE(OK, restored_status);
  EXPECT_NE(0u,
            restored_verify_result.cert_status & CERT_STATUS_AUTHORITY_INVALID);
  EXPECT_EQ(bad_status, restored_status);
  EXPECT_EQ(bad_verify_result.cert_status, restored_verify_result.cert_status);
  EXPECT_FALSE(restored_verify_result.is_issued_by_known_root);
}

TEST_P(TestRootCertsTest, OverrideKnownRoot) {
  TestRootCerts* test_roots = TestRootCerts::GetInstance();
  ASSERT_NE(static_cast<TestRootCerts*>(nullptr), test_roots);
  EXPECT_TRUE(test_roots->IsEmpty());

  // Use a runtime generated certificate chain so that the cert lifetime is not
  // too long, and so that it will have an allowable hostname for a publicly
  // trusted cert.
  auto [leaf, root] = net::CertBuilder::CreateSimpleChain2();

  // Add the root certificate and mark it as trusted and as a known root.
  ScopedTestRoot scoped_root(root->GetX509Certificate());
  ScopedTestKnownRoot scoped_known_root(root->GetX509Certificate().get());
  EXPECT_FALSE(test_roots->IsEmpty());

  // Test that the certificate verification sets the `is_issued_by_known_root`
  // flag.
  CertVerifyResult good_verify_result;
  scoped_refptr<CertVerifyProc> verify_proc(CreateCertVerifyProc());
  int flags = 0;
  int good_status =
      verify_proc->Verify(leaf->GetX509Certificate().get(), "www.example.com",
                          /*ocsp_response=*/std::string(),
                          /*sct_list=*/std::string(), flags,
                          &good_verify_result, NetLogWithSource());
  EXPECT_THAT(good_status, IsOk());
  EXPECT_EQ(0u, good_verify_result.cert_status);
  EXPECT_TRUE(good_verify_result.is_issued_by_known_root);

  test_roots->Clear();
  EXPECT_TRUE(test_roots->IsEmpty());

  // Ensure that when the TestRootCerts is cleared, the test known root status
  // revert to their original state, and don't linger. If known root status
  // lingers, it will likely break other tests in net_unittests.
  // Trust the root again so that the `is_issued_by_known_root` value will be
  // calculated, and ensure that it is false now.
  ScopedTestRoot scoped_root2(root->GetX509Certificate());
  CertVerifyResult restored_verify_result;
  int restored_status =
      verify_proc->Verify(leaf->GetX509Certificate().get(), "www.example.com",
                          /*ocsp_response=*/std::string(),
                          /*sct_list=*/std::string(), flags,
                          &restored_verify_result, NetLogWithSource());
  EXPECT_THAT(restored_status, IsOk());
  EXPECT_EQ(0u, restored_verify_result.cert_status);
  EXPECT_FALSE(restored_verify_result.is_issued_by_known_root);
}

TEST_P(TestRootCertsTest, Moveable) {
  TestRootCerts* test_roots = TestRootCerts::GetInstance();
  ASSERT_NE(static_cast<TestRootCerts*>(nullptr), test_roots);
  EXPECT_TRUE(test_roots->IsEmpty());

  scoped_refptr<X509Certificate> test_cert =
      ImportCertFromFile(GetTestCertsDirectory(), kGoodCertificateFile);
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), test_cert.get());

  int flags = 0;
  CertVerifyResult bad_verify_result;
  int bad_status;
  scoped_refptr<CertVerifyProc> verify_proc(CreateCertVerifyProc());
  {
    // Empty ScopedTestRoot at outer scope has no effect.
    ScopedTestRoot scoped_root_outer;
    EXPECT_TRUE(test_roots->IsEmpty());

    // Test that the good certificate fails verification, because the root
    // certificate should not yet be trusted.
    bad_status = verify_proc->Verify(test_cert.get(), "127.0.0.1",
                                     /*ocsp_response=*/std::string(),
                                     /*sct_list=*/std::string(), flags,
                                     &bad_verify_result, NetLogWithSource());
    EXPECT_NE(OK, bad_status);
    EXPECT_NE(0u,
              bad_verify_result.cert_status & CERT_STATUS_AUTHORITY_INVALID);

    {
      // Add the root certificate and mark it as trusted.
      scoped_refptr<X509Certificate> root_cert =
          ImportCertFromFile(GetTestCertsDirectory(), kRootCertificateFile);
      ASSERT_TRUE(root_cert);
      ScopedTestRoot scoped_root_inner(root_cert);
      EXPECT_FALSE(test_roots->IsEmpty());

      // Test that the certificate verification now succeeds, because the
      // TestRootCerts is successfully imbuing trust.
      CertVerifyResult good_verify_result;
      int good_status = verify_proc->Verify(
          test_cert.get(), "127.0.0.1", /*ocsp_response=*/std::string(),
          /*sct_list=*/std::string(), flags, &good_verify_result,
          NetLogWithSource());
      EXPECT_THAT(good_status, IsOk());
      EXPECT_EQ(0u, good_verify_result.cert_status);

      EXPECT_FALSE(scoped_root_inner.IsEmpty());
      EXPECT_TRUE(scoped_root_outer.IsEmpty());
      // Move from inner scoped root to outer
      scoped_root_outer = std::move(scoped_root_inner);
      EXPECT_FALSE(test_roots->IsEmpty());
      EXPECT_FALSE(scoped_root_outer.IsEmpty());
    }
    // After inner scoper was freed, test root is still trusted since ownership
    // was moved to the outer scoper.
    EXPECT_FALSE(test_roots->IsEmpty());
    EXPECT_FALSE(scoped_root_outer.IsEmpty());

    // Test that the certificate verification still succeeds, because the
    // TestRootCerts is successfully imbuing trust.
    CertVerifyResult good_verify_result;
    int good_status = verify_proc->Verify(
        test_cert.get(), "127.0.0.1", /*ocsp_response=*/std::string(),
        /*sct_list=*/std::string(), flags, &good_verify_result,
        NetLogWithSource());
    EXPECT_THAT(good_status, IsOk());
    EXPECT_EQ(0u, good_verify_result.cert_status);
  }
  EXPECT_TRUE(test_roots->IsEmpty());

  // Ensure that when the TestRootCerts is cleared, the trust settings
  // revert to their original state, and don't linger. If trust status
  // lingers, it will likely break other tests in net_unittests.
  CertVerifyResult restored_verify_result;
  int restored_status = verify_proc->Verify(
      test_cert.get(), "127.0.0.1", /*ocsp_response=*/std::string(),
      /*sct_list=*/std::string(), flags, &restored_verify_result,
      NetLogWithSource());
  EXPECT_NE(OK, restored_status);
  EXPECT_NE(0u,
            restored_verify_result.cert_status & CERT_STATUS_AUTHORITY_INVALID);
  EXPECT_EQ(bad_status, restored_status);
  EXPECT_EQ(bad_verify_result.cert_status, restored_verify_result.cert_status);
}

INSTANTIATE_TEST_SUITE_P(All, TestRootCertsTest, ::testing::Bool());

// TODO(rsleevi): Add tests for revocation checking via CRLs, ensuring that
// TestRootCerts properly injects itself into the validation process. See
// http://crbug.com/63958

}  // namespace net

"""

```