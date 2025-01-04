Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Identify the Core Functionality:** The file name itself, `cert_verify_proc_android_unittest.cc`, strongly suggests this file tests the `CertVerifyProcAndroid` class. The `#include "net/cert/cert_verify_proc_android.h"` confirms this. The "unittest" part signifies this is a unit test file, focused on testing individual units of code.

2. **Examine Includes:**  The included headers provide crucial context:
    * `net/cert/cert_verify_proc_android.h`: The header for the class being tested.
    * `net/cert/cert_net_fetcher.h`, `net/cert/mock_cert_net_fetcher.h`: Indicate that network fetching of certificates is involved, and that a mock implementation is used for testing purposes. This is a strong clue about the class's responsibility.
    * `net/cert/cert_verify_result.h`:  Suggests the class produces results related to certificate verification.
    * `net/cert/crl_set.h`: Indicates involvement with Certificate Revocation Lists (CRLs).
    * `net/cert/internal/test_helpers.h`, `net/cert/test_root_certs.h`: Point to testing utilities.
    * `net/cert/x509_certificate.h`, `net/cert/x509_util.h`:  Show that X.509 certificates are the core data being handled.
    * `net/log/net_log_with_source.h`: Hints at logging functionality.
    * `net/test/*`:  Indicates the usage of Chromium's network testing framework for creating test certificates and environments.
    * `testing/gmock/*`, `testing/gtest/*`:  Confirm the use of Google Mock and Google Test frameworks for creating and running tests.
    * `url/gurl.h`:  Shows URLs are involved, likely for fetching certificate information.

3. **Analyze the Test Fixture:** The `CertVerifyProcAndroidTestWithAIAFetching` class is the central setup for many tests. Its `SetUp` method is key:
    * It creates a `MockCertNetFetcher`. This immediately tells us that the tests will control network behavior.
    * It generates a certificate chain (`leaf_`, `intermediate_`, `root_`) using `CertBuilder`. This reveals the scenario being tested: verifying a certificate chain.
    * It sets "Authority Information Access" (AIA) URLs on the certificates. This is a critical piece of information pointing to the main feature being tested: fetching intermediate certificates from URLs.

4. **Examine Individual Test Cases:**  Each `TEST_F` function focuses on a specific aspect of `CertVerifyProcAndroid`'s behavior related to AIA fetching:
    * `NoFetchIfProperIntermediatesSupplied`: Tests the case where no AIA fetch is needed because the intermediate is already present.
    * `NoAIAURL`: Tests the case where no AIA fetch occurs because the leaf certificate doesn't have an AIA URL.
    * `OneFileAndOneHTTPURL`: Tests handling of different URL schemes in AIA.
    * `UnsuccessfulVerificationWithLeafOnly`: Tests failure scenarios when the fetched intermediate is wrong.
    * `UnsuccessfulVerificationWithLeafOnlyAndErrorOnFetch`: Tests failure when the AIA fetch fails.
    * `UnsuccessfulVerificationWithLeafOnlyAndUnparseableFetch`: Tests failure when the fetched data is not a valid certificate.
    * `TwoHTTPURLs`: Tests fetching from multiple AIA URLs.
    * `AIAFetchForFetchedIntermediate`: Tests the recursive fetching of AIA information for fetched intermediates.
    * `MaxAIAFetches`: Tests the limit on the number of AIA fetches.
    * `FetchForSuppliedIntermediate`: Tests fetching AIA for intermediates already in the provided chain.

5. **Infer the Class's Purpose:** Based on the tests, `CertVerifyProcAndroid` is responsible for:
    * Verifying X.509 certificate chains on Android.
    * Handling the case where intermediate certificates are missing from the server-provided chain.
    * Using AIA URLs in certificates to fetch these missing intermediates.
    * Managing network requests for fetching certificates.
    * Handling various success and failure scenarios during fetching and verification.
    * Limiting the number of AIA fetches to prevent infinite loops or excessive requests.

6. **Identify Connections to JavaScript (or lack thereof):**  A key part of the request is to identify relevance to JavaScript. Since this is a low-level networking component in Chromium's C++ codebase, there's *no direct interaction with JavaScript*. However, it *indirectly* supports secure web browsing, which JavaScript code in web pages relies on. The connection is that this code ensures the security of HTTPS connections initiated by the browser, which is essential for JavaScript's ability to interact with web servers securely.

7. **Construct Examples (Hypothetical Inputs and Outputs):**  The test cases themselves provide excellent examples. By looking at the `EXPECT_EQ` calls and the mock setup, you can infer the expected input (certificate chains, AIA URLs) and output (success or failure of verification, specific error codes).

8. **Consider User/Programming Errors:** Common errors relate to:
    * Server misconfiguration: Incorrect AIA URLs in certificates.
    * Network issues:  AIA servers being unavailable.
    * Trust store issues: The root certificate not being trusted.
    * Limitations on AIA fetches:  Having excessively long chains requiring many AIA fetches.

9. **Trace User Actions (Debugging Perspective):**  Think about the steps a user takes that lead to this code being executed. It starts with the user navigating to an HTTPS website. This triggers the browser to establish a secure connection, which involves certificate verification. If the server doesn't provide the full chain, this `CertVerifyProcAndroid` code might be invoked to fetch missing intermediates.

10. **Structure the Answer:**  Organize the findings into the requested categories: functionality, JavaScript relation, logic/inference, common errors, and debugging. Use clear and concise language.

By following these steps, we can effectively analyze the C++ code and provide a comprehensive answer to the user's request. The process involves understanding the code's purpose, its dependencies, and the scenarios it handles, as revealed by the unit tests.
这个文件 `net/cert/cert_verify_proc_android_unittest.cc` 是 Chromium 网络栈的一部分，专门用于测试 `CertVerifyProcAndroid` 类的功能。`CertVerifyProcAndroid`  是 Chromium 中用于在 Android 平台上执行证书链验证的组件。

以下是该文件的功能列表：

**核心功能：测试 `CertVerifyProcAndroid` 的证书链验证功能，特别是与 "Authority Information Access" (AIA) 扩展相关的行为。**

具体来说，它测试了以下方面：

1. **AIA Fetching 机制:**
   - **当服务器提供了完整的证书链时，不进行 AIA 获取。** 测试用例 `NoFetchIfProperIntermediatesSupplied` 验证了这种情况。
   - **当证书没有 AIA URL 时，不进行 AIA 获取。** 测试用例 `NoAIAURL` 验证了这种情况。
   - **处理不同类型的 AIA URL（例如 file:// 和 http://）。** 测试用例 `OneFileAndOneHTTPURL` 验证了这种情况。
   - **当 AIA 请求返回错误的中间证书时，验证失败。** 测试用例 `UnsuccessfulVerificationWithLeafOnly` 验证了这种情况。
   - **当 AIA 请求返回错误时，验证失败。** 测试用例 `UnsuccessfulVerificationWithLeafOnlyAndErrorOnFetch` 验证了这种情况。
   - **当 AIA 请求返回无法解析的证书时，验证失败。** 测试用例 `UnsuccessfulVerificationWithLeafOnlyAndUnparseableFetch` 验证了这种情况。
   - **处理多个 AIA URL，并尝试获取直到找到有效的中间证书。** 测试用例 `TwoHTTPURLs` 验证了这种情况。
   - **递归 AIA 获取：当通过 AIA 获取的中间证书本身也包含 AIA URL 时，会继续进行获取。** 测试用例 `AIAFetchForFetchedIntermediate` 验证了这种情况。
   - **限制 AIA 获取的最大次数。** 测试用例 `MaxAIAFetches` 验证了这种情况。
   - **即使中间证书已经提供，如果根证书不可信，并且中间证书有 AIA URL，也会尝试获取根证书。** 测试用例 `FetchForSuppliedIntermediate` 验证了这种情况。

2. **模拟网络请求:**  该文件使用 `MockCertNetFetcher` 来模拟证书的下载过程，以便在测试中控制网络行为，例如返回特定的证书数据或错误。

3. **证书链构建和验证:** 测试用例会创建不同的证书链场景，并使用 `CertVerifyProcAndroid` 来验证这些链，检查验证结果是否符合预期。

**与 Javascript 的关系:**

虽然这个 C++ 文件本身不包含任何 Javascript 代码，但它所测试的功能对 Javascript 在浏览器中的安全通信至关重要。

* **HTTPS 安全连接:** 当 Javascript 代码通过 `fetch()` API 或其他方式发起 HTTPS 请求时，浏览器会使用底层的网络栈（包括 `CertVerifyProcAndroid` 在 Android 上）来验证服务器提供的证书，确保连接的安全性。如果证书验证失败，浏览器会阻止 Javascript 代码与该服务器进行通信，从而保护用户数据。

**举例说明:**

假设一个 Javascript 应用尝试通过 HTTPS 连接到一个服务器：

```javascript
fetch('https://example.com')
  .then(response => response.text())
  .then(data => console.log(data));
```

当执行 `fetch('https://example.com')` 时，浏览器会执行以下（简化的）步骤：

1. **建立 TCP 连接。**
2. **发起 TLS 握手。** 在握手过程中，服务器会将它的证书链发送给浏览器。
3. **证书验证:**  在 Android 平台上，Chromium 会使用 `CertVerifyProcAndroid` 来验证服务器发送的证书链。
   - 如果服务器只发送了叶子证书，而缺少中间证书，`CertVerifyProcAndroid` 会检查叶子证书的 AIA 扩展，找到中间证书的下载地址。
   - `MockCertNetFetcher` 在测试中模拟了这个下载过程。在实际运行中，Chromium 会发起网络请求下载中间证书。
   - `CertVerifyProcAndroid` 会使用下载的中间证书构建完整的证书链，并验证其有效性，包括检查签名、有效期和信任锚点。
4. **如果证书验证成功，TLS 握手完成，浏览器与服务器建立安全连接。** Javascript 代码可以安全地发送和接收数据。
5. **如果证书验证失败（例如，AIA 下载失败，下载的证书无效，或者根证书不可信），浏览器会阻止连接，`fetch()` 操作会失败，并可能在控制台输出错误信息。**

**逻辑推理：假设输入与输出**

**假设输入:**

* **Leaf 证书:**  一个签发给 `example.com` 的叶子证书，其 AIA 扩展指向 `http://aia.test/intermediate`。
* **Intermediate 证书:**  一个由根证书签发的中间证书，位于 `http://aia.test/intermediate`。
* **Root 证书:**  一个自签名的根证书，并且该根证书在测试环境中被设置为信任锚点。
* **`CertVerifyProcAndroid` 实例:**  配置为使用模拟的 `CertNetFetcher`。

**预期输出 (基于 `NoFetchIfProperIntermediatesSupplied` 测试用例的修改版本):**

如果调用 `CertVerifyProcAndroid::Verify` 时，提供的证书链已经包含了 Leaf 证书和 Intermediate 证书，那么：

* **输入:**  `LeafWithIntermediate().get()` (包含叶子和中间证书的链)。
* **输出:** `verify_result` 的状态为 `OK`，表示证书链验证成功。
* **网络行为:**  `MockCertNetFetcher` 的 `FetchCaIssuers` 方法 **不会** 被调用，因为不需要进行 AIA 获取。

**假设输入 (基于 `UnsuccessfulVerificationWithLeafOnly` 测试用例):**

* **Leaf 证书:**  一个签发给 `example.com` 的叶子证书，其 AIA 扩展指向 `http://aia.test/intermediate`。
* **错误的 Intermediate 证书:**  一个不相关的证书（例如 `ok_cert.pem`）。
* **Root 证书:**  一个自签名的根证书，并且该根证书在测试环境中被设置为信任锚点。
* **`CertVerifyProcAndroid` 实例:**  配置为使用模拟的 `CertNetFetcher`。

**预期输出:**

如果调用 `CertVerifyProcAndroid::Verify` 时，只提供了 Leaf 证书，并且模拟的 `CertNetFetcher` 返回了错误的中间证书：

* **输入:** `LeafOnly().get()` (只包含叶子证书)。
* **模拟网络行为:** `MockCertNetFetcher` 的 `FetchCaIssuers` 方法会被调用，并返回错误的 Intermediate 证书。
* **输出:** `verify_result` 的状态为 `ERR_CERT_AUTHORITY_INVALID`，表示证书链验证失败，因为下载的中间证书无法有效连接到信任的根证书。

**用户或编程常见的使用错误:**

1. **服务器配置错误：** 服务器管理员配置了错误的 AIA URL 在证书中。例如，URL 指向一个不存在的资源或一个返回错误内容的资源。这会导致 `CertVerifyProcAndroid` 尝试下载错误的或无效的中间证书，最终导致连接失败。

   **用户操作到达这里的步骤 (调试线索):**
   - 用户尝试访问一个 HTTPS 网站。
   - 浏览器接收到服务器的叶子证书。
   - `CertVerifyProcAndroid` 检查证书的 AIA 扩展并尝试从指定的 URL 下载中间证书。
   - 由于 URL 配置错误，下载失败或下载到无效的证书。
   - `CertVerifyProcAndroid` 无法构建有效的证书链，返回错误。
   - 浏览器显示证书错误，例如 "NET::ERR_CERT_AUTHORITY_INVALID"。

2. **网络问题：**  AIA URL 指向的服务器暂时不可用或网络连接存在问题。这会导致 `CertVerifyProcAndroid` 无法下载中间证书。

   **用户操作到达这里的步骤 (调试线索):**
   - 用户尝试访问一个 HTTPS 网站。
   - 浏览器接收到服务器的叶子证书。
   - `CertVerifyProcAndroid` 检查证书的 AIA 扩展并尝试从指定的 URL 下载中间证书。
   - 由于网络问题，下载请求超时或失败。
   - `CertVerifyProcAndroid` 无法构建有效的证书链，返回错误。
   - 浏览器可能显示与网络相关的错误，或者证书错误。

3. **中间证书服务器配置错误：**  AIA URL 指向的服务器存在配置错误，例如返回了 HTTP 错误代码（404 Not Found, 500 Internal Server Error）或返回的内容不是一个有效的 X.509 证书。

   **用户操作到达这里的步骤 (调试线索):**
   - 用户尝试访问一个 HTTPS 网站。
   - 浏览器接收到服务器的叶子证书。
   - `CertVerifyProcAndroid` 检查证书的 AIA 扩展并尝试从指定的 URL 下载中间证书。
   - 下载成功，但返回的内容不是有效的证书或是一个 HTTP 错误。
   - `CertVerifyProcAndroid` 无法解析或使用下载的内容，返回错误。
   - 浏览器显示证书错误。

4. **根证书未安装或不受信任：**  即使 AIA 获取成功，如果最终构建的证书链的根证书在用户的设备上未安装或被标记为不受信任，证书验证仍然会失败。

   **用户操作到达这里的步骤 (调试线索):**
   - 用户尝试访问一个使用了自签名证书或私有 CA 签发证书的 HTTPS 网站。
   - `CertVerifyProcAndroid` 可能会成功下载中间证书。
   - 但是，由于根证书不在系统的信任存储中，验证过程会失败。
   - 浏览器显示证书错误，例如 "NET::ERR_CERT_AUTHORITY_INVALID"。

理解这些测试用例以及 `CertVerifyProcAndroid` 的功能对于理解 Chromium 如何在 Android 平台上处理证书验证至关重要，尤其是在涉及到动态获取中间证书的场景下。 这也有助于诊断和解决用户在使用 HTTPS 连接时遇到的证书相关问题。

Prompt: 
```
这是目录为net/cert/cert_verify_proc_android_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_verify_proc_android.h"

#include <memory>
#include <vector>

#include "net/cert/cert_net_fetcher.h"
#include "net/cert/cert_verify_proc_android.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/crl_set.h"
#include "net/cert/internal/test_helpers.h"
#include "net/cert/mock_cert_net_fetcher.h"
#include "net/cert/test_root_certs.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "net/log/net_log_with_source.h"
#include "net/test/cert_builder.h"
#include "net/test/cert_test_util.h"
#include "net/test/test_certificate_data.h"
#include "net/test/test_data_directory.h"
#include "testing/gmock/include/gmock/gmock-matchers.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

using ::testing::ByMove;
using ::testing::Return;
using ::testing::_;

namespace net {

namespace {

const char kHostname[] = "example.com";
const GURL kRootURL("http://aia.test/root");
const GURL kIntermediateURL("http://aia.test/intermediate");

std::unique_ptr<CertNetFetcher::Request>
CreateMockRequestWithInvalidCertificate() {
  return MockCertNetFetcherRequest::Create(std::vector<uint8_t>({1, 2, 3}));
}

// A test fixture for testing CertVerifyProcAndroid AIA fetching. It creates,
// sets up, and shuts down a MockCertNetFetcher for CertVerifyProcAndroid to
// use, and enables the field trial for AIA fetching.
class CertVerifyProcAndroidTestWithAIAFetching : public testing::Test {
 public:
  void SetUp() override {
    fetcher_ = base::MakeRefCounted<MockCertNetFetcher>();

    // Generate a certificate chain with AIA pointers. Tests can modify these
    // if testing a different scenario.
    std::tie(leaf_, intermediate_, root_) = CertBuilder::CreateSimpleChain3();
    root_->SetCaIssuersUrl(kRootURL);
    intermediate_->SetCaIssuersUrl(kRootURL);
    leaf_->SetCaIssuersUrl(kIntermediateURL);
    leaf_->SetSubjectAltName(kHostname);
  }

  void TearDown() override {
    // Ensure that mock expectations are checked, since the CertNetFetcher is
    // global and leaky.
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(fetcher_.get()));
  }

  scoped_refptr<X509Certificate> LeafOnly() {
    return leaf_->GetX509Certificate();
  }

  scoped_refptr<X509Certificate> LeafWithIntermediate() {
    return leaf_->GetX509CertificateChain();
  }

 protected:
  void TrustTestRoot() {
    scoped_test_root_.Reset({root_->GetX509Certificate()});
  }

  scoped_refptr<MockCertNetFetcher> fetcher_;
  std::unique_ptr<CertBuilder> root_;
  std::unique_ptr<CertBuilder> intermediate_;
  std::unique_ptr<CertBuilder> leaf_;

 private:
  ScopedTestRoot scoped_test_root_;
};

}  // namespace

// Tests that if the proper intermediates are supplied in the server-sent chain,
// no AIA fetch occurs.
TEST_F(CertVerifyProcAndroidTestWithAIAFetching,
       NoFetchIfProperIntermediatesSupplied) {
  TrustTestRoot();
  scoped_refptr<CertVerifyProcAndroid> proc =
      base::MakeRefCounted<CertVerifyProcAndroid>(fetcher_,
                                                  CRLSet::BuiltinCRLSet());
  CertVerifyResult verify_result;
  EXPECT_EQ(OK, proc->Verify(LeafWithIntermediate().get(), kHostname,
                             /*ocsp_response=*/std::string(),
                             /*sct_list=*/std::string(), 0, &verify_result,
                             NetLogWithSource()));
}

// Tests that if the certificate does not contain an AIA URL, no AIA fetch
// occurs.
TEST_F(CertVerifyProcAndroidTestWithAIAFetching, NoAIAURL) {
  leaf_->SetCaIssuersAndOCSPUrls(/*ca_issuers_urls=*/{}, /*ocsp_urls=*/{});
  TrustTestRoot();
  scoped_refptr<CertVerifyProcAndroid> proc =
      base::MakeRefCounted<CertVerifyProcAndroid>(fetcher_,
                                                  CRLSet::BuiltinCRLSet());
  CertVerifyResult verify_result;
  EXPECT_EQ(
      ERR_CERT_AUTHORITY_INVALID,
      proc->Verify(LeafOnly().get(), kHostname, /*ocsp_response=*/std::string(),
                   /*sct_list=*/std::string(), 0, &verify_result,
                   NetLogWithSource()));
}

// Tests that if a certificate contains one file:// URL and one http:// URL,
// there are two fetches, with the latter resulting in a successful
// verification.
TEST_F(CertVerifyProcAndroidTestWithAIAFetching, OneFileAndOneHTTPURL) {
  const GURL kFileURL("file:///dev/null");
  leaf_->SetCaIssuersAndOCSPUrls(
      /*ca_issuers_urls=*/{kFileURL, kIntermediateURL},
      /*ocsp_urls=*/{});
  TrustTestRoot();
  scoped_refptr<CertVerifyProcAndroid> proc =
      base::MakeRefCounted<CertVerifyProcAndroid>(fetcher_,
                                                  CRLSet::BuiltinCRLSet());

  // Expect two fetches: the file:// URL (which returns an error), and the
  // http:// URL that returns a valid intermediate signed by |root_|. Though the
  // intermediate itself contains an AIA URL, it should not be fetched because
  // |root_| is in the test trust store.
  EXPECT_CALL(*fetcher_, FetchCaIssuers(kFileURL, _, _))
      .WillOnce(Return(ByMove(
          MockCertNetFetcherRequest::Create(ERR_DISALLOWED_URL_SCHEME))));
  EXPECT_CALL(*fetcher_, FetchCaIssuers(kIntermediateURL, _, _))
      .WillOnce(Return(ByMove(
          MockCertNetFetcherRequest::Create(intermediate_->GetCertBuffer()))));

  CertVerifyResult verify_result;
  EXPECT_EQ(OK, proc->Verify(LeafOnly().get(), kHostname,
                             /*ocsp_response=*/std::string(),
                             /*sct_list=*/std::string(), 0, &verify_result,
                             NetLogWithSource()));
}

// Tests that if an AIA request returns the wrong intermediate, certificate
// verification should fail.
TEST_F(CertVerifyProcAndroidTestWithAIAFetching,
       UnsuccessfulVerificationWithLeafOnly) {
  TrustTestRoot();
  scoped_refptr<CertVerifyProcAndroid> proc =
      base::MakeRefCounted<CertVerifyProcAndroid>(fetcher_,
                                                  CRLSet::BuiltinCRLSet());
  const scoped_refptr<X509Certificate> bad_intermediate =
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");

  EXPECT_CALL(*fetcher_, FetchCaIssuers(kIntermediateURL, _, _))
      .WillOnce(Return(ByMove(
          MockCertNetFetcherRequest::Create(bad_intermediate->cert_buffer()))));

  CertVerifyResult verify_result;
  EXPECT_EQ(
      ERR_CERT_AUTHORITY_INVALID,
      proc->Verify(LeafOnly().get(), kHostname, /*ocsp_response=*/std::string(),
                   /*sct_list=*/std::string(), 0, &verify_result,
                   NetLogWithSource()));
}

// Tests that if an AIA request returns an error, certificate verification
// should fail.
TEST_F(CertVerifyProcAndroidTestWithAIAFetching,
       UnsuccessfulVerificationWithLeafOnlyAndErrorOnFetch) {
  TrustTestRoot();
  scoped_refptr<CertVerifyProcAndroid> proc =
      base::MakeRefCounted<CertVerifyProcAndroid>(fetcher_,
                                                  CRLSet::BuiltinCRLSet());

  EXPECT_CALL(*fetcher_, FetchCaIssuers(kIntermediateURL, _, _))
      .WillOnce(Return(ByMove(MockCertNetFetcherRequest::Create(ERR_FAILED))));

  CertVerifyResult verify_result;
  EXPECT_EQ(
      ERR_CERT_AUTHORITY_INVALID,
      proc->Verify(LeafOnly().get(), kHostname, /*ocsp_response=*/std::string(),
                   /*sct_list=*/std::string(), 0, &verify_result,
                   NetLogWithSource()));
}

// Tests that if an AIA request returns an unparseable cert, certificate
// verification should fail.
TEST_F(CertVerifyProcAndroidTestWithAIAFetching,
       UnsuccessfulVerificationWithLeafOnlyAndUnparseableFetch) {
  TrustTestRoot();
  scoped_refptr<CertVerifyProcAndroid> proc =
      base::MakeRefCounted<CertVerifyProcAndroid>(fetcher_,
                                                  CRLSet::BuiltinCRLSet());

  EXPECT_CALL(*fetcher_, FetchCaIssuers(kIntermediateURL, _, _))
      .WillOnce(Return(ByMove(CreateMockRequestWithInvalidCertificate())));

  CertVerifyResult verify_result;
  EXPECT_EQ(
      ERR_CERT_AUTHORITY_INVALID,
      proc->Verify(LeafOnly().get(), kHostname, /*ocsp_response=*/std::string(),
                   /*sct_list=*/std::string(), 0, &verify_result,
                   NetLogWithSource()));
}

// Tests that if a certificate has two HTTP AIA URLs, they are both fetched. If
// one serves an unrelated certificate and one serves a proper intermediate, the
// latter should be used to build a valid chain.
TEST_F(CertVerifyProcAndroidTestWithAIAFetching, TwoHTTPURLs) {
  const GURL kUnrelatedURL("http://aia.test/unrelated");
  leaf_->SetCaIssuersAndOCSPUrls(
      /*ca_issuers_urls=*/{kUnrelatedURL, kIntermediateURL},
      /*ocsp_urls=*/{});
  scoped_refptr<X509Certificate> unrelated =
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");
  ASSERT_TRUE(unrelated);

  TrustTestRoot();
  scoped_refptr<CertVerifyProcAndroid> proc =
      base::MakeRefCounted<CertVerifyProcAndroid>(fetcher_,
                                                  CRLSet::BuiltinCRLSet());

  // Expect two fetches, the first of which returns an unrelated certificate
  // that is not useful in chain-building, and the second of which returns a
  // valid intermediate signed by |root_|. Though the intermediate itself
  // contains an AIA URL, it should not be fetched because |root_| is in the
  // trust store.
  EXPECT_CALL(*fetcher_, FetchCaIssuers(kUnrelatedURL, _, _))
      .WillOnce(Return(
          ByMove(MockCertNetFetcherRequest::Create(unrelated->cert_buffer()))));
  EXPECT_CALL(*fetcher_, FetchCaIssuers(kIntermediateURL, _, _))
      .WillOnce(Return(ByMove(
          MockCertNetFetcherRequest::Create(intermediate_->GetCertBuffer()))));

  CertVerifyResult verify_result;
  EXPECT_EQ(OK, proc->Verify(LeafOnly().get(), kHostname,
                             /*ocsp_response=*/std::string(),
                             /*sct_list=*/std::string(), 0, &verify_result,
                             NetLogWithSource()));
}

// Tests that if an intermediate is fetched via AIA, and the intermediate itself
// has an AIA URL, that URL is fetched if necessary.
TEST_F(CertVerifyProcAndroidTestWithAIAFetching,
       AIAFetchForFetchedIntermediate) {
  // Do not set up the test root to be trusted. If the test root were trusted,
  // then the intermediate would not require an AIA fetch. With the test root
  // untrusted, the intermediate does not verify and so it will trigger an AIA
  // fetch.
  scoped_refptr<CertVerifyProcAndroid> proc =
      base::MakeRefCounted<CertVerifyProcAndroid>(fetcher_,
                                                  CRLSet::BuiltinCRLSet());

  // Expect two fetches, the first of which returns an intermediate that itself
  // has an AIA URL.
  EXPECT_CALL(*fetcher_, FetchCaIssuers(kIntermediateURL, _, _))
      .WillOnce(Return(ByMove(
          MockCertNetFetcherRequest::Create(intermediate_->GetCertBuffer()))));
  EXPECT_CALL(*fetcher_, FetchCaIssuers(kRootURL, _, _))
      .WillOnce(Return(
          ByMove(MockCertNetFetcherRequest::Create(root_->GetCertBuffer()))));

  CertVerifyResult verify_result;
  // This chain results in an AUTHORITY_INVALID root because |root_| is not
  // trusted.
  EXPECT_EQ(
      ERR_CERT_AUTHORITY_INVALID,
      proc->Verify(LeafOnly().get(), kHostname, /*ocsp_response=*/std::string(),
                   /*sct_list=*/std::string(), 0, &verify_result,
                   NetLogWithSource()));
}

// Tests that if a certificate contains six AIA URLs, only the first five are
// fetched, since the maximum number of fetches per Verify() call is five.
TEST_F(CertVerifyProcAndroidTestWithAIAFetching, MaxAIAFetches) {
  leaf_->SetCaIssuersAndOCSPUrls(
      /*ca_issuers_urls=*/{GURL("http://aia.test/1"), GURL("http://aia.test/2"),
                           GURL("http://aia.test/3"), GURL("http://aia.test/4"),
                           GURL("http://aia.test/5"),
                           GURL("http://aia.test/6")},
      /*ocsp_urls=*/{});
  TrustTestRoot();
  scoped_refptr<CertVerifyProcAndroid> proc =
      base::MakeRefCounted<CertVerifyProcAndroid>(fetcher_,
                                                  CRLSet::BuiltinCRLSet());

  EXPECT_CALL(*fetcher_, FetchCaIssuers(_, _, _))
      .WillOnce(Return(ByMove(MockCertNetFetcherRequest::Create(ERR_FAILED))))
      .WillOnce(Return(ByMove(MockCertNetFetcherRequest::Create(ERR_FAILED))))
      .WillOnce(Return(ByMove(MockCertNetFetcherRequest::Create(ERR_FAILED))))
      .WillOnce(Return(ByMove(MockCertNetFetcherRequest::Create(ERR_FAILED))))
      .WillOnce(Return(ByMove(MockCertNetFetcherRequest::Create(ERR_FAILED))));

  CertVerifyResult verify_result;
  EXPECT_EQ(
      ERR_CERT_AUTHORITY_INVALID,
      proc->Verify(LeafOnly().get(), kHostname, /*ocsp_response=*/std::string(),
                   /*sct_list=*/std::string(), 0, &verify_result,
                   NetLogWithSource()));
}

// Tests that if the supplied chain contains an intermediate with an AIA URL,
// that AIA URL is fetched if necessary.
TEST_F(CertVerifyProcAndroidTestWithAIAFetching, FetchForSuppliedIntermediate) {
  // Do not set up the test root to be trusted. If the test root were trusted,
  // then the intermediate would not require an AIA fetch. With the test root
  // untrusted, the intermediate does not verify and so it will trigger an AIA
  // fetch.
  scoped_refptr<CertVerifyProcAndroid> proc =
      base::MakeRefCounted<CertVerifyProcAndroid>(fetcher_,
                                                  CRLSet::BuiltinCRLSet());

  EXPECT_CALL(*fetcher_, FetchCaIssuers(kRootURL, _, _))
      .WillOnce(Return(
          ByMove(MockCertNetFetcherRequest::Create(root_->GetCertBuffer()))));

  CertVerifyResult verify_result;
  // This chain results in an AUTHORITY_INVALID root because |root_| is not
  // trusted.
  EXPECT_EQ(ERR_CERT_AUTHORITY_INVALID,
            proc->Verify(LeafWithIntermediate().get(), kHostname,
                         /*ocsp_response=*/std::string(),
                         /*sct_list=*/std::string(), 0, &verify_result,
                         NetLogWithSource()));
}

}  // namespace net

"""

```