Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Understanding of the Goal:**

The filename `trust_store_mac_unittest.cc` immediately signals that this file contains unit tests for a component named `TrustStoreMac`. The `unittest.cc` convention is standard in Chromium. The `mac` part indicates it's specific to macOS.

**2. Core Component Identification:**

The first few lines of the code confirm this: `#include "net/cert/internal/trust_store_mac.h"`. This tells us the code is testing the functionality of the `TrustStoreMac` class.

**3. Purpose of `TrustStoreMac`:**

From the name, we can infer that `TrustStoreMac` is responsible for managing trusted certificates on macOS. It likely interacts with the macOS Keychain to determine which certificates are trusted by the system.

**4. Test Structure Analysis:**

The file uses Google Test (`TEST_P`, `TEST`, `ASSERT_TRUE`, `EXPECT_EQ`, etc.). This is the standard testing framework in Chromium. The `TEST_P` indicates parameterized tests, which we'll need to investigate further. The `TEST` macros define individual test cases.

**5. Key Concepts and Functionality to Look For:**

Based on the understanding of `TrustStoreMac`, we can anticipate the tests will cover:

* **Loading and parsing certificates:**  The presence of `#include "net/cert/x509_certificate.h"` and helper functions like `ReadTestCert` confirms this.
* **Determining trust:**  The core function of `TrustStoreMac`. We'll expect tests that verify whether a certificate is considered trusted or not.
* **Interaction with the macOS Keychain:**  The inclusion of `TestKeychainSearchListMac.h` and mentions of `SecKeychainOpen` are strong indicators.
* **Handling different trust levels:**  Concepts like "trust anchors" (root certificates) and user-added certificates are likely involved.
* **Error handling:**  Although less explicitly tested here, the underlying implementation would need to handle errors from Keychain APIs.
* **Performance considerations (potentially):** The parameterized tests might relate to different implementation strategies for the trust store.

**6. Detailed Code Inspection (Iterative Process):**

Now we go through the code section by section, paying attention to the following:

* **Includes:** What other modules are being used?  This gives clues about dependencies and functionality. (e.g., `base/files/file_util.h` for file operations, `crypto/mac_security_services_lock.h` for thread safety).
* **Helper Functions:**  `ReadTestCert`, `ParsedCertificateListAsDER`, `ParseFindCertificateOutputToDerCerts`, `TrustImplTypeToString`. These simplify test setup and assertions. Understanding these helps understand the test logic.
* **Test Cases:**
    * `MultiRootNotTrusted`: Focuses on certificates in a specific keychain that are *not* trusted by default. It verifies that issuer searching works correctly and that the certificates are reported as untrusted.
    * `SystemCerts`: Tests against the *system's* keychain certificates. This is a more comprehensive test, comparing the trust status reported by `TrustStoreMac` with the system's own determination (`SecTrustEvaluateWithError`).
* **Parameterized Test Setup (`INSTANTIATE_TEST_SUITE_P`):** This reveals that `TrustStoreMac` has different implementation types (`kDomainCacheFullCerts`, `kKeychainCacheFullCerts`). The tests are run for each of these implementations. This suggests different caching or retrieval strategies.
* **Assertions and Expectations:**  `ASSERT_TRUE` checks for critical errors, while `EXPECT_EQ`, `EXPECT_THAT`, `EXPECT_FALSE` verify the expected behavior.
* **Histograms:** The use of `base::test::metrics::HistogramTester` indicates that the tests also verify that certain performance metrics are being logged.

**7. Connecting to JavaScript (as requested):**

Since this is a C++ file dealing with low-level system interactions, the direct connection to JavaScript is limited. The key connection is through the browser's network stack. JavaScript code in a web page can trigger TLS/SSL connections. The browser then uses the operating system's trust store (which `TrustStoreMac` interacts with) to validate the server's certificate.

**8. Logical Reasoning (Hypothetical Input/Output):**

For the `MultiRootNotTrusted` test, we can imagine:

* **Input:** A keychain file (`multi-root.keychain`) containing a set of inter-related but untrusted certificates. A `TrustStoreMac` instance initialized with a specific `TrustImplType`.
* **Processing:** The test code calls `SyncGetIssuersOf` to find potential issuers for given certificates. It also calls `GetTrust` to determine the trust status.
* **Output:** Assertions confirming the correct issuers are found and that the certificates are reported as untrusted.

**9. User/Programming Errors:**

The test code itself doesn't directly *cause* user errors. However, it *tests* the correctness of `TrustStoreMac`, which is crucial for preventing security errors. A bug in `TrustStoreMac` could lead to:

* **Incorrectly trusting malicious certificates:** If `TrustStoreMac` fails to correctly evaluate trust, a user might connect to a fraudulent website.
* **Incorrectly rejecting valid certificates:** This could lead to users being unable to access legitimate websites.

A common *programming* error might be misconfiguring the keychain or providing invalid certificate data to `TrustStoreMac`. The tests help ensure the library is robust against such errors (although the tests focus on correct behavior with valid inputs).

**10. Debugging Scenario:**

Imagine a user reports an issue where a website is being incorrectly flagged as insecure on macOS. A developer might:

1. **Check the browser's error messages:** This might indicate a certificate problem.
2. **Examine the certificate details:**  Is it a valid certificate?  Is it expired?
3. **Investigate the macOS Keychain:** Are the necessary root certificates present?  Has the user manually distrusted the certificate?
4. **Run these unit tests (or similar internal tests):** This can help isolate whether the issue lies within Chromium's `TrustStoreMac` implementation or with the system's keychain configuration. Specifically, running `SystemCerts` could reveal discrepancies between Chromium's understanding of trust and the OS's.

This iterative and multi-faceted approach, combining code inspection, conceptual understanding, and reasoning, allows for a comprehensive analysis of the test file's functionality and its role in the larger system.
这个文件 `net/cert/internal/trust_store_mac_unittest.cc` 是 Chromium 网络栈的一部分，专门用于测试 `TrustStoreMac` 类的功能。`TrustStoreMac` 类负责在 macOS 系统上管理和查询受信任的证书。

**文件功能总结:**

1. **单元测试 `TrustStoreMac` 类:**  该文件包含了多个单元测试用例，用于验证 `TrustStoreMac` 类的各种功能是否正常工作。
2. **测试证书加载和解析:**  测试代码会加载本地的测试证书文件（PEM 格式），并使用 `bssl::ParsedCertificate` 进行解析。
3. **测试证书信任判断:**  核心功能是测试 `TrustStoreMac` 如何判断一个证书是否受信任。这包括检查系统 keychain 中存在的证书，以及用户手动添加的证书。
4. **测试 issuer 查找:**  测试 `TrustStoreMac` 是否能够根据给定的证书，正确地找到其 issuer 证书（即签发该证书的 CA 证书）。
5. **模拟不同的信任实现方式:**  该文件使用了参数化测试 (`TEST_P`) 来测试 `TrustStoreMac` 的不同实现方式 (`kDomainCacheFullCerts` 和 `kKeychainCacheFullCerts`)，这可能涉及到不同的缓存策略或数据来源。
6. **比较 Chromium 的信任判断和系统信任判断:**  `SystemCerts` 测试用例会获取系统中所有证书的信息，并比较 `TrustStoreMac` 的信任判断结果和 macOS 系统本身的信任判断结果 (`SecTrustEvaluateWithError`)，以确保一致性。
7. **测试性能指标 (通过 histograms):** 测试代码会检查某些性能指标是否被正确记录，例如信任存储初始化时间、证书数量等。

**与 JavaScript 的关系:**

`TrustStoreMac` 本身是 C++ 代码，直接与 JavaScript 没有交互。但是，它在浏览器安全中扮演着关键角色，而 JavaScript 代码经常会触发需要证书验证的操作。

**举例说明:**

当 JavaScript 代码发起一个 HTTPS 请求时（例如使用 `fetch` 或 `XMLHttpRequest`）：

1. 浏览器（使用 C++ 实现）会建立与服务器的 TLS/SSL 连接。
2. 服务器会向浏览器发送其数字证书。
3. 浏览器网络栈会使用 `TrustStoreMac` (在 macOS 上) 来验证服务器证书的有效性和可信度。
4. `TrustStoreMac` 会查询 macOS 的 keychain，检查证书是否由受信任的根 CA 签发，或者用户是否明确信任了该证书。
5. 如果证书被认为是可信任的，连接就会建立成功，JavaScript 代码才能正常获取数据。
6. 如果证书不可信任，浏览器可能会阻止连接，并向用户显示安全警告，JavaScript 代码可能会收到错误信息。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* **测试用例 `MultiRootNotTrusted`:**
    *  加载了一个包含多个证书的 keychain 文件 (`multi-root.keychain`)，这些证书之间存在签发关系，但默认情况下不被系统信任。
    *  调用 `TrustStoreMac::SyncGetIssuersOf` 并传入一个证书 (例如 `a_by_b`)。
* **测试用例 `SystemCerts`:**
    *  系统 keychain 中存在一个由知名 CA 签发的证书 (例如 `google.com` 的证书)。
    *  调用 `TrustStoreMac::GetTrust` 并传入该证书。

**预期输出:**

* **`MultiRootNotTrusted`:**
    *  `SyncGetIssuersOf(a_by_b)` 应该返回签发 `a_by_b` 的证书列表 (`b_by_c`, `b_by_f`)。
    *  调用 `TrustStoreMac::GetTrust` 查询 `a_by_b` 等证书的信任状态，预期结果是“不受信任” (`bssl::CertificateTrust::ForUnspecified()`)。
* **`SystemCerts`:**
    *  `TrustStoreMac::GetTrust(google.com 证书)` 应该返回该证书是受信任的 (`bssl::CertificateTrust::ForTrustAnchorOrLeaf()` 或类似表示信任的状态)。这个结果应该与 macOS 系统使用 `SecTrustEvaluateWithError` 的判断结果一致。

**用户或编程常见的使用错误:**

1. **用户手动将根证书设置为“永不信任”:** 用户可能会在 macOS 的 Keychain Access 应用中，错误地将一些重要的根证书设置为“永不信任”。这将导致 `TrustStoreMac` 判断所有由该根证书签发的证书都不可信，浏览器会阻止访问大量网站。
   * **调试线索:** 用户反馈无法访问多个网站，浏览器显示证书错误。开发者可以检查 `TrustStoreMac` 的测试结果，并引导用户检查 Keychain Access 中的证书信任设置。
2. **编程错误 -  `TrustStoreMac` 的实现逻辑错误:**  如果 `TrustStoreMac` 的代码存在 bug，可能导致它错误地判断证书的信任状态。例如，可能无法正确解析某些证书的扩展信息，或者在查询 keychain 时出现错误。
   * **调试线索:**  在特定 macOS 版本或特定证书下出现信任判断错误，但系统本身的信任判断是正确的。开发者需要检查 `TrustStoreMac` 的代码逻辑，并运行相关的单元测试进行验证。
3. **测试环境配置错误:** 在运行单元测试时，如果测试 keychain 文件缺失或损坏，会导致测试失败。
   * **调试线索:** 单元测试报告文件加载失败或断言失败。开发者需要检查测试数据目录和 keychain 文件的完整性。

**用户操作到达这里的步骤 (调试线索):**

假设一个用户报告在 macOS 上使用 Chromium 浏览器访问某个 HTTPS 网站时出现证书错误：

1. **用户尝试访问 HTTPS 网站:** 用户在 Chromium 浏览器的地址栏中输入一个以 `https://` 开头的网址并回车。
2. **浏览器建立连接:** Chromium 的网络栈开始尝试与服务器建立 TCP 连接，并进行 TLS/SSL 握手。
3. **服务器发送证书:** 服务器将包含其公钥和身份信息的数字证书发送给浏览器。
4. **Chromium 调用 `TrustStoreMac` 进行证书验证:**
   *  网络栈会获取服务器发送的证书。
   *  在 macOS 系统上，Chromium 会使用 `TrustStoreMac` 类来判断该证书是否可信。
   *  `TrustStoreMac` 会查询 macOS 的 keychain，检查证书链的有效性，并判断根证书是否受信任。
5. **`TrustStoreMac` 返回验证结果:**
   *  如果证书被认为是可信任的，TLS/SSL 握手成功，浏览器与服务器建立安全连接，网页内容加载。
   *  如果证书不可信任（例如，证书过期、自签名、根证书不受信任），`TrustStoreMac` 会返回相应的错误信息。
6. **浏览器处理验证结果:**
   *  如果验证失败，Chromium 会显示安全警告页面，阻止用户继续访问，或者允许用户选择继续访问（取决于安全策略）。
   *  开发者可能会查看 Chromium 的网络日志（`chrome://net-export/`）来获取更详细的证书验证信息。

当开发者需要调试此类问题时，可能会深入研究 `TrustStoreMac` 的代码和相关的单元测试，例如本文件中的测试用例，来确定问题的原因，例如：

*  `MultiRootNotTrusted` 测试可以帮助验证在没有系统信任的情况下，issuer 查找功能是否正确。
*  `SystemCerts` 测试可以帮助确认 `TrustStoreMac` 对系统默认证书的信任判断是否与 macOS 系统一致。

总而言之，`net/cert/internal/trust_store_mac_unittest.cc` 文件通过一系列单元测试，确保了 Chromium 在 macOS 系统上正确地管理和验证数字证书，这对于保障用户的网络安全至关重要。

### 提示词
```
这是目录为net/cert/internal/trust_store_mac_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/trust_store_mac.h"

#include <algorithm>
#include <set>

#include "base/apple/scoped_cftyperef.h"
#include "base/base_paths.h"
#include "base/containers/to_vector.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/logging.h"
#include "base/path_service.h"
#include "base/process/launch.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/synchronization/lock.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "crypto/mac_security_services_lock.h"
#include "crypto/sha2.h"
#include "net/base/features.h"
#include "net/cert/internal/test_helpers.h"
#include "net/cert/test_keychain_search_list_mac.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "net/cert/x509_util_apple.h"
#include "net/test/test_data_directory.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/pki/cert_errors.h"
#include "third_party/boringssl/src/pki/parsed_certificate.h"
#include "third_party/boringssl/src/pki/pem.h"
#include "third_party/boringssl/src/pki/trust_store.h"

using ::testing::UnorderedElementsAreArray;

namespace net {

namespace {

// The PEM block header used for DER certificates
const char kCertificateHeader[] = "CERTIFICATE";

// Parses a PEM encoded certificate from |file_name| and stores in |result|.
::testing::AssertionResult ReadTestCert(
    const std::string& file_name,
    std::shared_ptr<const bssl::ParsedCertificate>* result) {
  std::string der;
  const PemBlockMapping mappings[] = {
      {kCertificateHeader, &der},
  };

  ::testing::AssertionResult r = ReadTestDataFromPemFile(
      "net/data/ssl/certificates/" + file_name, mappings);
  if (!r)
    return r;

  bssl::CertErrors errors;
  *result = bssl::ParsedCertificate::Create(x509_util::CreateCryptoBuffer(der),
                                            {}, &errors);
  if (!*result) {
    return ::testing::AssertionFailure()
           << "bssl::ParseCertificate::Create() failed:\n"
           << errors.ToDebugString();
  }
  return ::testing::AssertionSuccess();
}

// Returns the DER encodings of the ParsedCertificates in |list|.
std::vector<std::string> ParsedCertificateListAsDER(
    bssl::ParsedCertificateList list) {
  std::vector<std::string> result;
  for (const auto& it : list)
    result.push_back(it->der_cert().AsString());
  return result;
}

std::set<std::string> ParseFindCertificateOutputToDerCerts(std::string output) {
  std::set<std::string> certs;
  for (const std::string& hash_and_pem_partial : base::SplitStringUsingSubstr(
           output, "-----END CERTIFICATE-----", base::TRIM_WHITESPACE,
           base::SPLIT_WANT_NONEMPTY)) {
    // Re-add the PEM ending mark, since SplitStringUsingSubstr eats it.
    const std::string hash_and_pem =
        hash_and_pem_partial + "\n-----END CERTIFICATE-----\n";

    // Parse the PEM encoded text to DER bytes.
    bssl::PEMTokenizer pem_tokenizer(hash_and_pem, {kCertificateHeader});
    if (!pem_tokenizer.GetNext()) {
      ADD_FAILURE() << "!pem_tokenizer.GetNext()";
      continue;
    }
    std::string cert_der(pem_tokenizer.data());
    EXPECT_FALSE(pem_tokenizer.GetNext());
    certs.insert(cert_der);
  }
  return certs;
}

const char* TrustImplTypeToString(TrustStoreMac::TrustImplType t) {
  switch (t) {
    case TrustStoreMac::TrustImplType::kDomainCacheFullCerts:
      return "DomainCacheFullCerts";
    case TrustStoreMac::TrustImplType::kKeychainCacheFullCerts:
      return "KeychainCacheFullCerts";
    case TrustStoreMac::TrustImplType::kUnknown:
      return "Unknown";
  }
}

}  // namespace

class TrustStoreMacImplTest
    : public testing::TestWithParam<TrustStoreMac::TrustImplType> {
 public:
  TrustStoreMac::TrustImplType GetImplParam() const { return GetParam(); }

  bssl::CertificateTrust ExpectedTrustForAnchor() const {
    return bssl::CertificateTrust::ForTrustAnchorOrLeaf()
        .WithEnforceAnchorExpiry()
        .WithEnforceAnchorConstraints()
        .WithRequireAnchorBasicConstraints();
  }
};

// Much of the Keychain API was marked deprecated as of the macOS 13 SDK.
// Removal of its use is tracked in https://crbug.com/1348251 but deprecation
// warnings are disabled in the meanwhile.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// Test the trust store using known test certificates in a keychain.  Tests
// that issuer searching returns the expected certificates, and that none of
// the certificates are trusted.
TEST_P(TrustStoreMacImplTest, MultiRootNotTrusted) {
  std::unique_ptr<TestKeychainSearchList> test_keychain_search_list(
      TestKeychainSearchList::Create());
  ASSERT_TRUE(test_keychain_search_list);
  base::FilePath keychain_path(
      GetTestCertsDirectory().AppendASCII("multi-root.keychain"));
  // SecKeychainOpen does not fail if the file doesn't exist, so assert it here
  // for easier debugging.
  ASSERT_TRUE(base::PathExists(keychain_path));
  base::apple::ScopedCFTypeRef<SecKeychainRef> keychain;
  OSStatus status = SecKeychainOpen(keychain_path.MaybeAsASCII().c_str(),
                                    keychain.InitializeInto());
  ASSERT_EQ(errSecSuccess, status);
  ASSERT_TRUE(keychain);
  test_keychain_search_list->AddKeychain(keychain.get());

#pragma clang diagnostic pop

  const TrustStoreMac::TrustImplType trust_impl = GetImplParam();
  TrustStoreMac trust_store(kSecPolicyAppleSSL, trust_impl);

  std::map<std::vector<uint8_t>, bssl::CertificateTrust> user_added_certs;
  for (const auto& cert_with_trust : trust_store.GetAllUserAddedCerts()) {
    user_added_certs[cert_with_trust.cert_bytes] = cert_with_trust.trust;
  }

  std::shared_ptr<const bssl::ParsedCertificate> a_by_b, b_by_c, b_by_f, c_by_d,
      c_by_e, f_by_e, d_by_d, e_by_e;
  ASSERT_TRUE(ReadTestCert("multi-root-A-by-B.pem", &a_by_b));
  ASSERT_TRUE(ReadTestCert("multi-root-B-by-C.pem", &b_by_c));
  ASSERT_TRUE(ReadTestCert("multi-root-B-by-F.pem", &b_by_f));
  ASSERT_TRUE(ReadTestCert("multi-root-C-by-D.pem", &c_by_d));
  ASSERT_TRUE(ReadTestCert("multi-root-C-by-E.pem", &c_by_e));
  ASSERT_TRUE(ReadTestCert("multi-root-F-by-E.pem", &f_by_e));
  ASSERT_TRUE(ReadTestCert("multi-root-D-by-D.pem", &d_by_d));
  ASSERT_TRUE(ReadTestCert("multi-root-E-by-E.pem", &e_by_e));

  // Test that the untrusted keychain certs would be found during issuer
  // searching.
  {
    bssl::ParsedCertificateList found_issuers;
    trust_store.SyncGetIssuersOf(a_by_b.get(), &found_issuers);
    EXPECT_THAT(ParsedCertificateListAsDER(found_issuers),
                UnorderedElementsAreArray(
                    ParsedCertificateListAsDER({b_by_c, b_by_f})));
  }

  {
    bssl::ParsedCertificateList found_issuers;
    trust_store.SyncGetIssuersOf(b_by_c.get(), &found_issuers);
    EXPECT_THAT(ParsedCertificateListAsDER(found_issuers),
                UnorderedElementsAreArray(
                    ParsedCertificateListAsDER({c_by_d, c_by_e})));
  }

  {
    bssl::ParsedCertificateList found_issuers;
    trust_store.SyncGetIssuersOf(b_by_f.get(), &found_issuers);
    EXPECT_THAT(
        ParsedCertificateListAsDER(found_issuers),
        UnorderedElementsAreArray(ParsedCertificateListAsDER({f_by_e})));
  }

  {
    bssl::ParsedCertificateList found_issuers;
    trust_store.SyncGetIssuersOf(c_by_d.get(), &found_issuers);
    EXPECT_THAT(
        ParsedCertificateListAsDER(found_issuers),
        UnorderedElementsAreArray(ParsedCertificateListAsDER({d_by_d})));
  }

  {
    bssl::ParsedCertificateList found_issuers;
    trust_store.SyncGetIssuersOf(f_by_e.get(), &found_issuers);
    EXPECT_THAT(
        ParsedCertificateListAsDER(found_issuers),
        UnorderedElementsAreArray(ParsedCertificateListAsDER({e_by_e})));
  }

  // Verify that none of the added certificates are considered trusted (since
  // the test certs in the keychain aren't trusted, unless someone manually
  // added and trusted the test certs on the machine the test is being run on).
  for (const auto& cert :
       {a_by_b, b_by_c, b_by_f, c_by_d, c_by_e, f_by_e, d_by_d, e_by_e}) {
    bssl::CertificateTrust trust = trust_store.GetTrust(cert.get());
    EXPECT_EQ(bssl::CertificateTrust::ForUnspecified().ToDebugString(),
              trust.ToDebugString());

    std::vector<uint8_t> cert_bytes = base::ToVector(cert->der_cert());
    if (cert == a_by_b) {
      // If the certificate is the leaf, it should not be present in the
      // GetAllUserAddedCerts results, which only returns trusted/distrusted
      // certs or intermediates.
      EXPECT_FALSE(user_added_certs.contains(cert_bytes));
    } else {
      // Otherwise it should be present in the list and be untrusted.
      EXPECT_TRUE(user_added_certs.contains(cert_bytes));
      EXPECT_TRUE(user_added_certs[cert_bytes].HasUnspecifiedTrust());
    }
  }
}

// Test against all the certificates in the default keychains. Confirms that
// the computed trust value matches that of SecTrustEvaluateWithError.
TEST_P(TrustStoreMacImplTest, SystemCerts) {
  // Get the list of all certificates in the user & system keychains.
  // This may include both trusted and untrusted certificates.
  //
  // The output contains zero or more repetitions of:
  // "SHA-1 hash: <hash>\n<PEM encoded cert>\n"
  // Starting with macOS 10.15, it includes both SHA-256 and SHA-1 hashes:
  // "SHA-256 hash: <hash>\nSHA-1 hash: <hash>\n<PEM encoded cert>\n"
  std::string find_certificate_default_search_list_output;
  ASSERT_TRUE(
      base::GetAppOutput({"security", "find-certificate", "-a", "-p", "-Z"},
                         &find_certificate_default_search_list_output));
  // Get the list of all certificates in the system roots keychain.
  // (Same details as above.)
  std::string find_certificate_system_roots_output;
  ASSERT_TRUE(base::GetAppOutput(
      {"security", "find-certificate", "-a", "-p", "-Z",
       "/System/Library/Keychains/SystemRootCertificates.keychain"},
      &find_certificate_system_roots_output));

  std::set<std::string> find_certificate_default_search_list_certs =
      ParseFindCertificateOutputToDerCerts(
          find_certificate_default_search_list_output);
  std::set<std::string> find_certificate_system_roots_certs =
      ParseFindCertificateOutputToDerCerts(
          find_certificate_system_roots_output);

  const TrustStoreMac::TrustImplType trust_impl = GetImplParam();

  base::HistogramTester histogram_tester;
  TrustStoreMac trust_store(kSecPolicyAppleX509Basic, trust_impl);

  std::map<std::string, bssl::CertificateTrust> user_added_certs;
  for (const auto& cert_with_trust : trust_store.GetAllUserAddedCerts()) {
    user_added_certs[std::string(base::as_string_view(
        cert_with_trust.cert_bytes))] = cert_with_trust.trust;
  }

  base::apple::ScopedCFTypeRef<SecPolicyRef> sec_policy(
      SecPolicyCreateBasicX509());
  ASSERT_TRUE(sec_policy);
  std::vector<std::string> all_certs;
  std::set_union(find_certificate_default_search_list_certs.begin(),
                 find_certificate_default_search_list_certs.end(),
                 find_certificate_system_roots_certs.begin(),
                 find_certificate_system_roots_certs.end(),
                 std::back_inserter(all_certs));
  for (const std::string& cert_der : all_certs) {
    std::string hash = crypto::SHA256HashString(cert_der);
    std::string hash_text = base::HexEncode(hash);
    SCOPED_TRACE(hash_text);

    bssl::CertErrors errors;
    // Note: don't actually need to make a bssl::ParsedCertificate here, just
    // need the DER bytes. But parsing it here ensures the test can skip any
    // certs that won't be returned due to parsing failures inside
    // TrustStoreMac. The parsing options set here need to match the ones used
    // in trust_store_mac.cc.
    bssl::ParseCertificateOptions options;
    // For https://crt.sh/?q=D3EEFBCBBCF49867838626E23BB59CA01E305DB7:
    options.allow_invalid_serial_numbers = true;
    std::shared_ptr<const bssl::ParsedCertificate> cert =
        bssl::ParsedCertificate::Create(x509_util::CreateCryptoBuffer(cert_der),
                                        options, &errors);
    if (!cert) {
      LOG(WARNING) << "bssl::ParseCertificate::Create " << hash_text
                   << " failed:\n"
                   << errors.ToDebugString();
      continue;
    }

    base::apple::ScopedCFTypeRef<SecCertificateRef> cert_handle(
        x509_util::CreateSecCertificateFromBytes(cert->der_cert()));
    if (!cert_handle) {
      ADD_FAILURE() << "CreateCertBufferFromBytes " << hash_text;
      continue;
    }

    // Check if this cert is considered a trust anchor by TrustStoreMac.
    bssl::CertificateTrust cert_trust = trust_store.GetTrust(cert.get());
    bool is_trusted = cert_trust.IsTrustAnchor() || cert_trust.IsTrustLeaf();
    if (is_trusted) {
      EXPECT_EQ(ExpectedTrustForAnchor().ToDebugString(),
                cert_trust.ToDebugString());
      // If the cert is trusted, it should be in the GetAllUserAddedCerts
      // result with the same trust value. (If it's not trusted, it may or may
      // not be present so we can't test that here, MultiRootNotTrusted tests
      // that.)
      EXPECT_TRUE(user_added_certs.contains(cert_der));
      EXPECT_EQ(user_added_certs[cert_der].ToDebugString(),
                cert_trust.ToDebugString());
    }

    // Check if this cert is considered a trust anchor by the OS.
    base::apple::ScopedCFTypeRef<SecTrustRef> trust;
    {
      base::AutoLock lock(crypto::GetMacSecurityServicesLock());
      ASSERT_EQ(noErr, SecTrustCreateWithCertificates(cert_handle.get(),
                                                      sec_policy.get(),
                                                      trust.InitializeInto()));
      ASSERT_EQ(noErr, SecTrustSetOptions(trust.get(),
                                          kSecTrustOptionLeafIsCA |
                                              kSecTrustOptionAllowExpired |
                                              kSecTrustOptionAllowExpiredRoot));

      if (find_certificate_default_search_list_certs.count(cert_der) &&
          find_certificate_system_roots_certs.count(cert_der)) {
        // If the same certificate is present in both the System and User/Admin
        // domains, and TrustStoreMac is only using trust settings from
        // User/Admin, then it's not possible for this test to know whether the
        // result from SecTrustEvaluate should match the TrustStoreMac result.
        // Just ignore such certificates.
      } else if (!find_certificate_default_search_list_certs.count(cert_der)) {
        // Cert is only in the system domain. It should be untrusted.
        EXPECT_FALSE(is_trusted);
        // It should not be in the GetAllUserAddedCerts results either.
        EXPECT_FALSE(user_added_certs.contains(cert_der));
      } else {
        bool trusted = SecTrustEvaluateWithError(trust.get(), nullptr);
        bool expected_trust_anchor =
            trusted && (SecTrustGetCertificateCount(trust.get()) == 1);
        EXPECT_EQ(expected_trust_anchor, is_trusted);
      }
    }

    // Call GetTrust again on the same cert. This should exercise the code
    // that checks the trust value for a cert which has already been cached.
    bssl::CertificateTrust cert_trust2 = trust_store.GetTrust(cert.get());
    EXPECT_EQ(cert_trust.ToDebugString(), cert_trust2.ToDebugString());
  }

  // Since this is testing the actual platform certs and trust settings, we
  // don't know what values the histograms should be, so just verify that the
  // histogram is recorded (or not) depending on the requested trust impl.

  {
    // Histograms only logged by DomainCacheFullCerts impl:
    const int expected_count =
        (trust_impl == TrustStoreMac::TrustImplType::kDomainCacheFullCerts) ? 1
                                                                            : 0;
    histogram_tester.ExpectTotalCount(
        "Net.CertVerifier.MacTrustDomainCertCount.User", expected_count);
    histogram_tester.ExpectTotalCount(
        "Net.CertVerifier.MacTrustDomainCertCount.Admin", expected_count);
    histogram_tester.ExpectTotalCount(
        "Net.CertVerifier.MacTrustDomainCacheInitTime", expected_count);
    histogram_tester.ExpectTotalCount(
        "Net.CertVerifier.MacKeychainCerts.IntermediateCacheInitTime",
        expected_count);
  }

  {
    // Histograms only logged by KeychainCacheFullCerts impl:
    const int expected_count =
        (trust_impl == TrustStoreMac::TrustImplType::kKeychainCacheFullCerts)
            ? 1
            : 0;
    histogram_tester.ExpectTotalCount(
        "Net.CertVerifier.MacKeychainCerts.TrustCount", expected_count);
  }

  {
    // Histograms logged by both DomainCacheFullCerts and KeychainCacheFullCerts
    // impls:
    const int expected_count =
        (trust_impl == TrustStoreMac::TrustImplType::kDomainCacheFullCerts ||
         trust_impl == TrustStoreMac::TrustImplType::kKeychainCacheFullCerts)
            ? 1
            : 0;
    histogram_tester.ExpectTotalCount(
        "Net.CertVerifier.MacKeychainCerts.IntermediateCount", expected_count);
    histogram_tester.ExpectTotalCount(
        "Net.CertVerifier.MacKeychainCerts.TotalCount", expected_count);
    histogram_tester.ExpectTotalCount(
        "Net.CertVerifier.MacTrustImplCacheInitTime", expected_count);
  }
}

INSTANTIATE_TEST_SUITE_P(
    Impl,
    TrustStoreMacImplTest,
    testing::Values(TrustStoreMac::TrustImplType::kDomainCacheFullCerts,
                    TrustStoreMac::TrustImplType::kKeychainCacheFullCerts),
    [](const testing::TestParamInfo<TrustStoreMacImplTest::ParamType>& info) {
      return TrustImplTypeToString(info.param);
    });

}  // namespace net
```