Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Identify the Core Purpose:** The filename `cert_issuer_source_aia_unittest.cc` immediately suggests that this file contains unit tests for a component related to fetching certificate issuers, specifically using the Authority Information Access (AIA) extension. The `unittest` suffix confirms this.

2. **Understand the Tested Class:** The `#include "net/cert/internal/cert_issuer_source_aia.h"` line is crucial. It tells us the class being tested is `CertIssuerSourceAia`. This is the central subject of our analysis.

3. **Recognize the Testing Framework:**  The presence of `#include "testing/gmock/include/gmock/gmock.h"` and `#include "testing/gtest/include/gtest/gtest.h"` indicates that Google Test (gtest) and Google Mock (gmock) are used for writing the tests. This is standard practice in Chromium.

4. **Analyze Key Dependencies:**  Look at other includes:
    * `base/files/file_util.h`:  Indicates file system operations, likely for loading test certificates.
    * `net/cert/internal/test_helpers.h`:  Suggests helper functions are used to set up test scenarios.
    * `net/cert/mock_cert_net_fetcher.h`:  This is a *mock* object. It means the tests don't perform actual network requests; instead, they use a mock to control the behavior of the network fetcher. This is key to unit testing in isolation.
    * `net/cert/x509_certificate.h` and `net/cert/x509_util.h`: These deal with X.509 certificates, the core data this component handles.
    * `net/test/test_data_directory.h`: Points to where test data (like certificate files) is located.
    * `url/gurl.h`: Used for handling URLs, which are part of the AIA extension.
    * `third_party/boringssl/src/pki/...`: Boringssl is the cryptography library Chromium uses. These headers deal with parsing and handling certificates.

5. **Examine the Test Structure:**  The code uses `TEST(CertIssuerSourceAiaTest, ...)` macros. This tells us there's a test suite named `CertIssuerSourceAiaTest`, and each `TEST` macro defines an individual test case.

6. **Deconstruct Individual Tests:**  Go through each test case and understand its purpose. Look for:
    * **Setup:** How is the test environment prepared? This often involves loading certificates using `ReadTestCert` and creating a `MockCertNetFetcher`.
    * **Expectations:** What behavior is being verified?  This is where `EXPECT_CALL` (from gmock) is crucial. It sets up expectations on how the mock object should be called and what it should return.
    * **Actions:** What is the code under test doing?  This usually involves calling methods on the `CertIssuerSourceAia` object, such as `AsyncGetIssuersOf` or `SyncGetIssuersOf`.
    * **Assertions:** How is the outcome verified? This involves `EXPECT_EQ`, `ASSERT_NE`, `EXPECT_TRUE`, and `ASSERT_EQ` to check the results of the actions.

7. **Identify Key Scenarios:**  Notice the different test cases and what aspects of `CertIssuerSourceAia` they are targeting. Common patterns emerge:
    * Handling missing AIA extensions.
    * Handling different URL schemes in AIA.
    * Handling invalid URLs.
    * Successful fetching of issuer certificates.
    * Handling network errors during fetching.
    * Handling parsing errors of fetched certificates.
    * Handling multiple AIA entries.
    * Enforcing limits on the number of fetches.
    * Handling CMS messages containing certificates.

8. **Look for Potential Connections to JavaScript:**  Consider how the functionality being tested might be exposed to JavaScript in a browser context. Certificate verification and trust establishment are crucial for secure web browsing. JavaScript uses APIs that rely on the underlying network stack to perform these operations.

9. **Infer Logical Reasoning:**  For tests involving `MockCertNetFetcher`, pay attention to the input (the URL being fetched) and the output (the mocked response, either a certificate or an error). This demonstrates the logical reasoning being tested within `CertIssuerSourceAia`.

10. **Consider User Errors:** Think about how incorrect configurations or unexpected server behavior could lead to the scenarios tested in the unit tests. For example, a website providing an incorrect AIA URL or a server returning a malformed certificate.

11. **Trace User Actions (Debugging Perspective):**  Imagine how a user browsing the web might trigger the code being tested. This involves a chain of events starting with the user visiting a website, the browser receiving the server's certificate, and then the browser needing to find the issuer certificate for verification.

12. **Refine and Organize:**  Structure the findings logically, categorizing the functionality, JavaScript connections, logical reasoning, user errors, and debugging steps. Use clear and concise language.

Self-Correction/Refinement During the Process:

* **Initial thought:**  "This is just about fetching certificates."  **Refinement:**  "It's *specifically* about fetching issuer certificates using the AIA extension, and it's being tested in isolation using mocks."
* **Initial thought:** "Does this directly interact with JavaScript?" **Refinement:** "Not directly in the C++ code, but the *results* of this component's work (the fetched issuer certificates) are crucial for the browser's overall trust evaluation, which *is* relevant to JavaScript's secure context."
* **While analyzing a specific test:** "Why is it checking for `nullptr`?" **Refinement:**  "Ah, it's testing the synchronous vs. asynchronous behavior based on the presence and validity of the AIA extension."
* **After seeing multiple tests with `MockCertNetFetcher`:** "The key is understanding the mocked interactions and return values to understand what scenarios are being tested."

By following these steps and continually refining the understanding, one can effectively analyze and explain the functionality of a C++ unittest file like the one provided.
这个C++源代码文件 `cert_issuer_source_aia_unittest.cc` 是 Chromium 网络栈的一部分，专门用于测试 `CertIssuerSourceAia` 类的功能。`CertIssuerSourceAia` 类的作用是从证书的 Authority Information Access (AIA) 扩展中指定的URL获取证书颁发者的证书。

**功能列表:**

1. **异步获取颁发者证书 (AsyncGetIssuersOf):**  测试 `CertIssuerSourceAia` 类是否能够根据目标证书的 AIA 扩展中的 URL 异步地获取颁发者证书。
2. **同步获取颁发者证书 (SyncGetIssuersOf):**  测试 `CertIssuerSourceAia` 类的同步获取颁发者证书的功能。虽然代码注释中明确指出 `CertIssuerSourceAia` 不支持同步获取，但测试用例会验证这一点。
3. **处理不存在 AIA 扩展的情况:** 测试当目标证书没有 AIA 扩展时，`CertIssuerSourceAia` 的行为。
4. **处理 AIA 扩展中包含非 HTTP URL 的情况:** 测试当 AIA 扩展中包含 `file://` 等非 HTTP(S) URL 时，`CertIssuerSourceAia` 的行为，以及如何处理 `ERR_DISALLOWED_URL_SCHEME` 错误。
5. **处理 AIA 扩展中包含无效 URL 的情况:** 测试当 AIA 扩展中包含格式错误的 URL 时，`CertIssuerSourceAia` 的行为。
6. **处理成功的 HTTP 获取:** 测试当 AIA 扩展中包含有效的 HTTP(S) URL 并且成功获取到颁发者证书时的场景。
7. **处理 HTTP 获取失败的情况:** 测试当 HTTP 获取颁发者证书失败（例如，网络错误）时，`CertIssuerSourceAia` 的行为。
8. **处理获取到的数据无法解析为证书的情况:** 测试当从 AIA URL 获取到数据，但该数据不是有效的证书格式时，`CertIssuerSourceAia` 的行为。
9. **处理 AIA 扩展中包含多个 URL 的情况:** 测试当 AIA 扩展中包含多个 URL 时，`CertIssuerSourceAia` 如何处理并按顺序尝试获取。
10. **限制每个证书的最大获取请求数:** 测试 `CertIssuerSourceAia` 是否会限制对同一个证书发起的获取请求数量，防止无限尝试。
11. **处理包含证书的 CMS 消息 (certs-only CMS message):** 测试当从 AIA URL 获取到的数据是包含多个证书的 CMS 消息时，`CertIssuerSourceAia` 是否能够正确解析并返回这些证书。

**与 Javascript 的关系:**

虽然这个 C++ 代码文件本身不包含 Javascript 代码，但 `CertIssuerSourceAia` 的功能是浏览器安全机制的关键组成部分，它直接影响着浏览器如何验证服务器证书的有效性。  当用户通过浏览器访问一个使用 HTTPS 的网站时，浏览器会执行以下步骤，其中就可能涉及到 `CertIssuerSourceAia`：

1. **浏览器接收到服务器的证书。**
2. **浏览器需要验证该证书的信任链。** 这意味着浏览器需要找到颁发该服务器证书的 CA (Certificate Authority) 证书。
3. **如果浏览器本地没有颁发者证书，它会查看服务器证书的 AIA 扩展。**
4. **AIA 扩展中会包含一个或多个 URL，指向可能包含颁发者证书的位置。**
5. **Chromium 的网络栈会使用 `CertIssuerSourceAia` 组件来异步地从这些 URL 下载可能的颁发者证书。**

**Javascript 层面举例:**

在 Javascript 中，你无法直接调用 `CertIssuerSourceAia` 的功能。然而，当 Javascript 代码尝试建立一个安全的 HTTPS 连接（例如，使用 `fetch` 或 `XMLHttpRequest` 访问一个 HTTPS URL）时，底层的浏览器网络栈（包括 `CertIssuerSourceAia`）会在幕后工作来验证服务器证书。

如果由于某种原因，`CertIssuerSourceAia` 无法成功获取到必要的颁发者证书，或者获取到的证书无法验证，那么 Javascript 发起的网络请求可能会失败，或者浏览器会显示安全警告。

例如，以下 Javascript 代码尝试访问一个 HTTPS 网站：

```javascript
fetch('https://example.com')
  .then(response => {
    console.log('连接成功:', response);
  })
  .catch(error => {
    console.error('连接失败:', error);
  });
```

如果 `example.com` 的证书链有问题，例如缺少中间证书，并且浏览器的 `CertIssuerSourceAia` 组件无法从 AIA 获取到该中间证书，那么 `fetch` 请求可能会失败，`catch` 代码块会被执行，`error` 对象中会包含与证书验证失败相关的信息。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* **目标证书:**  一个包含以下 AIA 扩展的证书：
  ```asn1
  AuthorityInfoAccessSyntax  ::=
          SEQUENCE SIZE (1..MAX) OF AccessDescription

  AccessDescription  ::=  SEQUENCE  {
          accessMethod          OBJECT IDENTIFIER,
          accessLocation        GeneralName  }

  id-ad-caIssuers         OBJECT IDENTIFIER ::=  { id-ad 2 }

  GeneralName ::= CHOICE {
          otherName                       [0]     IMPLICIT SEQUENCE {
              type-id    OBJECT IDENTIFIER,
              value      [0] EXPLICIT ANY DEFINED BY type-id }
          rfc822Name                      [1]     IMPLICIT IA5String,
          dNSName                         [2]     IMPLICIT IA5String,
          x400Address                     [3]     IMPLICIT ORAddress,
          directoryName                   [4]     IMPLICIT Name,
          ediPartyName                    [5]     IMPLICIT SEQUENCE {
              nameAssigner            [0]     IMPLICIT Name OPTIONAL,
              partyName               [1]     IMPLICIT Name },
          uniformResourceIdentifier       [6]     IMPLICIT IA5String,
          iPAddress                       [7]     IMPLICIT OCTET STRING,
          registeredID                    [8]     IMPLICIT OBJECT IDENTIFIER }

  --  Example AIA Extension:
  AuthorityInfoAccess {
    { id-ad-caIssuers, "http://url-for-aia/intermediate.crt" },
    { id-ad-caIssuers, "https://another-url/issuer.cer" }
  }
  ```
* **MockCertNetFetcher:** 一个模拟的网络请求器，配置为：
    * 当请求 `http://url-for-aia/intermediate.crt` 时，返回包含一个有效中间证书的 DER 编码数据。
    * 当请求 `https://another-url/issuer.cer` 时，返回 HTTP 404 错误。

**预期输出:**

调用 `AsyncGetIssuersOf` 后，`CertIssuerSourceAia` 会：

1. 尝试从 `http://url-for-aia/intermediate.crt` 获取证书。 **输出:** 成功获取并解析中间证书。
2. 尝试从 `https://another-url/issuer.cer` 获取证书。 **输出:** 获取失败 (HTTP 404)。
3. `GetNext` 方法被调用时，会返回一个包含成功获取到的中间证书的 `ParsedCertificateList`。后续的 `GetNext` 调用将返回空列表。

**用户或编程常见的使用错误:**

1. **服务器配置错误:**  网站管理员在配置服务器证书时，可能没有正确配置 AIA 扩展，或者 AIA 扩展中的 URL 指向了不存在的资源或者错误的证书文件。 这会导致浏览器无法自动获取中间证书，从而可能导致连接失败或安全警告。
   * **例子:**  AIA URL 拼写错误，例如 `http://example.com/intermidiate.crt` 而不是 `http://example.com/intermediate.crt`。
2. **网络问题:**  用户的网络连接不稳定，或者防火墙阻止了浏览器访问 AIA 扩展中指定的 URL。 这会导致浏览器无法获取颁发者证书。
3. **中间证书缺失:**  服务器只发送了叶子证书，而没有发送必要的中间证书。在这种情况下，浏览器会尝试使用 AIA 来获取中间证书。如果 AIA 配置不正确或获取失败，则验证会失败。
4. **编程错误 (测试代码中):**  在编写使用 `CertIssuerSourceAia` 的代码时，没有正确处理异步获取的结果，或者没有考虑到获取可能失败的情况。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入一个 HTTPS 网址并访问 (例如 `https://example.com`)。**
2. **浏览器向 `example.com` 服务器发起连接请求。**
3. **服务器返回其证书。**
4. **浏览器开始验证服务器证书的有效性。**
5. **浏览器检查本地是否已有所需的颁发者证书。** 如果没有，则会解析服务器证书的 AIA 扩展。
6. **`CertIssuerSourceAia` 组件被调用，根据 AIA 扩展中的 URL，异步地发起 HTTP(S) 请求去下载可能的颁发者证书。**  这会涉及到 `MockCertNetFetcher` (在测试环境中) 或者实际的网络请求。
7. **如果网络请求成功，返回的数据会被尝试解析为 X.509 证书。**
8. **解析后的证书会被用于构建证书链，并进行信任验证。**
9. **如果所有验证步骤都成功，浏览器会认为连接是安全的，用户可以正常访问网页。**  否则，浏览器可能会显示安全警告或阻止访问。

在调试网络安全相关问题时，开发者可能会关注以下几点：

* **查看浏览器开发者工具的安全选项卡:**  可以查看证书链的信息以及证书的 AIA 扩展。
* **使用网络抓包工具 (如 Wireshark):**  可以查看浏览器是否尝试请求 AIA URL 以及服务器的响应。
* **检查 Chromium 的网络日志 (net-internals):**  可以查看更详细的证书获取和验证过程的信息，包括 `CertIssuerSourceAia` 的活动。

总而言之，`cert_issuer_source_aia_unittest.cc` 文件通过各种测试用例，确保 `CertIssuerSourceAia` 组件能够可靠地从证书的 AIA 扩展中获取颁发者证书，这是保证 HTTPS 连接安全性的一个关键环节。

### 提示词
```
这是目录为net/cert/internal/cert_issuer_source_aia_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/cert/internal/cert_issuer_source_aia.h"

#include <memory>

#include "base/files/file_util.h"
#include "net/cert/internal/test_helpers.h"
#include "net/cert/mock_cert_net_fetcher.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "net/test/test_data_directory.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/pki/cert_errors.h"
#include "third_party/boringssl/src/pki/parsed_certificate.h"
#include "url/gurl.h"

namespace net {

namespace {

using ::testing::ByMove;
using ::testing::Mock;
using ::testing::Return;
using ::testing::StrictMock;
using ::testing::_;

::testing::AssertionResult ReadTestPem(const std::string& file_name,
                                       const std::string& block_name,
                                       std::string* result) {
  const PemBlockMapping mappings[] = {
      {block_name.c_str(), result},
  };

  return ReadTestDataFromPemFile(file_name, mappings);
}

::testing::AssertionResult ReadTestCert(
    const std::string& file_name,
    std::shared_ptr<const bssl::ParsedCertificate>* result) {
  std::string der;
  ::testing::AssertionResult r =
      ReadTestPem("net/data/cert_issuer_source_aia_unittest/" + file_name,
                  "CERTIFICATE", &der);
  if (!r)
    return r;
  bssl::CertErrors errors;
  *result = bssl::ParsedCertificate::Create(x509_util::CreateCryptoBuffer(der),
                                            {}, &errors);
  if (!*result) {
    return ::testing::AssertionFailure()
           << "bssl::ParsedCertificate::Create() failed:\n"
           << errors.ToDebugString();
  }
  return ::testing::AssertionSuccess();
}

// CertIssuerSourceAia does not return results for SyncGetIssuersOf.
TEST(CertIssuerSourceAiaTest, NoSyncResults) {
  std::shared_ptr<const bssl::ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_two_aia.pem", &cert));

  // No methods on |mock_fetcher| should be called.
  auto mock_fetcher = base::MakeRefCounted<StrictMock<MockCertNetFetcher>>();
  CertIssuerSourceAia aia_source(mock_fetcher);
  bssl::ParsedCertificateList issuers;
  aia_source.SyncGetIssuersOf(cert.get(), &issuers);
  EXPECT_EQ(0U, issuers.size());
}

// If the AuthorityInfoAccess extension is not present, AsyncGetIssuersOf should
// synchronously indicate no results.
TEST(CertIssuerSourceAiaTest, NoAia) {
  std::shared_ptr<const bssl::ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_no_aia.pem", &cert));

  // No methods on |mock_fetcher| should be called.
  auto mock_fetcher = base::MakeRefCounted<StrictMock<MockCertNetFetcher>>();
  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<bssl::CertIssuerSource::Request> request;
  aia_source.AsyncGetIssuersOf(cert.get(), &request);
  EXPECT_EQ(nullptr, request);
}

// If the AuthorityInfoAccess extension only contains non-HTTP URIs,
// AsyncGetIssuersOf should create a Request object. The URL scheme check is
// part of the specific CertNetFetcher implementation, this tests that we handle
// ERR_DISALLOWED_URL_SCHEME properly. If FetchCaIssuers is modified to fail
// synchronously in that case, this test will be more interesting.
TEST(CertIssuerSourceAiaTest, FileAia) {
  std::shared_ptr<const bssl::ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_file_aia.pem", &cert));

  auto mock_fetcher = base::MakeRefCounted<StrictMock<MockCertNetFetcher>>();
  EXPECT_CALL(*mock_fetcher, FetchCaIssuers(GURL("file:///dev/null"), _, _))
      .WillOnce(Return(ByMove(
          MockCertNetFetcherRequest::Create(ERR_DISALLOWED_URL_SCHEME))));

  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<bssl::CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(), &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  // No results.
  bssl::ParsedCertificateList result_certs;
  cert_source_request->GetNext(&result_certs);
  EXPECT_TRUE(result_certs.empty());
}

// If the AuthorityInfoAccess extension contains an invalid URL,
// AsyncGetIssuersOf should synchronously indicate no results.
TEST(CertIssuerSourceAiaTest, OneInvalidURL) {
  std::shared_ptr<const bssl::ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_invalid_url_aia.pem", &cert));

  auto mock_fetcher = base::MakeRefCounted<StrictMock<MockCertNetFetcher>>();
  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<bssl::CertIssuerSource::Request> request;
  aia_source.AsyncGetIssuersOf(cert.get(), &request);
  EXPECT_EQ(nullptr, request);
}

// AuthorityInfoAccess with a single HTTP url pointing to a single DER cert.
TEST(CertIssuerSourceAiaTest, OneAia) {
  std::shared_ptr<const bssl::ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_one_aia.pem", &cert));
  std::shared_ptr<const bssl::ParsedCertificate> intermediate_cert;
  ASSERT_TRUE(ReadTestCert("i.pem", &intermediate_cert));

  auto mock_fetcher = base::MakeRefCounted<StrictMock<MockCertNetFetcher>>();

  EXPECT_CALL(*mock_fetcher,
              FetchCaIssuers(GURL("http://url-for-aia/I.cer"), _, _))
      .WillOnce(Return(ByMove(MockCertNetFetcherRequest::Create(
          intermediate_cert->cert_buffer()))));

  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<bssl::CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(), &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  bssl::ParsedCertificateList result_certs;
  cert_source_request->GetNext(&result_certs);
  ASSERT_EQ(1u, result_certs.size());
  ASSERT_EQ(result_certs.front()->der_cert(), intermediate_cert->der_cert());

  result_certs.clear();
  cert_source_request->GetNext(&result_certs);
  EXPECT_TRUE(result_certs.empty());
}

// AuthorityInfoAccess with two URIs, one a FILE, the other a HTTP.
// Simulate a ERR_DISALLOWED_URL_SCHEME for the file URL. If FetchCaIssuers is
// modified to synchronously reject disallowed schemes, this test will be more
// interesting.
TEST(CertIssuerSourceAiaTest, OneFileOneHttpAia) {
  std::shared_ptr<const bssl::ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_file_and_http_aia.pem", &cert));
  std::shared_ptr<const bssl::ParsedCertificate> intermediate_cert;
  ASSERT_TRUE(ReadTestCert("i2.pem", &intermediate_cert));

  auto mock_fetcher = base::MakeRefCounted<StrictMock<MockCertNetFetcher>>();

  EXPECT_CALL(*mock_fetcher, FetchCaIssuers(GURL("file:///dev/null"), _, _))
      .WillOnce(Return(ByMove(
          MockCertNetFetcherRequest::Create(ERR_DISALLOWED_URL_SCHEME))));

  EXPECT_CALL(*mock_fetcher,
              FetchCaIssuers(GURL("http://url-for-aia2/I2.foo"), _, _))
      .WillOnce(Return(ByMove(MockCertNetFetcherRequest::Create(
          intermediate_cert->cert_buffer()))));

  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<bssl::CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(), &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  bssl::ParsedCertificateList result_certs;
  cert_source_request->GetNext(&result_certs);
  ASSERT_EQ(1u, result_certs.size());
  ASSERT_EQ(result_certs.front()->der_cert(), intermediate_cert->der_cert());

  cert_source_request->GetNext(&result_certs);
  EXPECT_EQ(1u, result_certs.size());
}

// AuthorityInfoAccess with two URIs, one is invalid, the other HTTP.
TEST(CertIssuerSourceAiaTest, OneInvalidOneHttpAia) {
  std::shared_ptr<const bssl::ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_invalid_and_http_aia.pem", &cert));
  std::shared_ptr<const bssl::ParsedCertificate> intermediate_cert;
  ASSERT_TRUE(ReadTestCert("i2.pem", &intermediate_cert));

  auto mock_fetcher = base::MakeRefCounted<StrictMock<MockCertNetFetcher>>();

  EXPECT_CALL(*mock_fetcher,
              FetchCaIssuers(GURL("http://url-for-aia2/I2.foo"), _, _))
      .WillOnce(Return(ByMove(MockCertNetFetcherRequest::Create(
          intermediate_cert->cert_buffer()))));

  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<bssl::CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(), &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  bssl::ParsedCertificateList result_certs;
  cert_source_request->GetNext(&result_certs);
  ASSERT_EQ(1u, result_certs.size());
  EXPECT_EQ(result_certs.front()->der_cert(), intermediate_cert->der_cert());

  // No more results.
  result_certs.clear();
  cert_source_request->GetNext(&result_certs);
  EXPECT_EQ(0u, result_certs.size());
}

// AuthorityInfoAccess with two HTTP urls, each pointing to a single DER cert.
// One request completes, results are retrieved, then the next request completes
// and the results are retrieved.
TEST(CertIssuerSourceAiaTest, TwoAiaCompletedInSeries) {
  std::shared_ptr<const bssl::ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_two_aia.pem", &cert));
  std::shared_ptr<const bssl::ParsedCertificate> intermediate_cert;
  ASSERT_TRUE(ReadTestCert("i.pem", &intermediate_cert));
  std::shared_ptr<const bssl::ParsedCertificate> intermediate_cert2;
  ASSERT_TRUE(ReadTestCert("i2.pem", &intermediate_cert2));

  auto mock_fetcher = base::MakeRefCounted<StrictMock<MockCertNetFetcher>>();

  EXPECT_CALL(*mock_fetcher,
              FetchCaIssuers(GURL("http://url-for-aia/I.cer"), _, _))
      .WillOnce(Return(ByMove(MockCertNetFetcherRequest::Create(
          intermediate_cert->cert_buffer()))));

  EXPECT_CALL(*mock_fetcher,
              FetchCaIssuers(GURL("http://url-for-aia2/I2.foo"), _, _))
      .WillOnce(Return(ByMove(MockCertNetFetcherRequest::Create(
          intermediate_cert2->cert_buffer()))));

  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<bssl::CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(), &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  // GetNext() should return intermediate_cert followed by intermediate_cert2.
  // They are returned in two separate batches.
  bssl::ParsedCertificateList result_certs;
  cert_source_request->GetNext(&result_certs);
  ASSERT_EQ(1u, result_certs.size());
  EXPECT_EQ(result_certs.front()->der_cert(), intermediate_cert->der_cert());

  result_certs.clear();
  cert_source_request->GetNext(&result_certs);
  ASSERT_EQ(1u, result_certs.size());
  EXPECT_EQ(result_certs.front()->der_cert(), intermediate_cert2->der_cert());

  // No more results.
  result_certs.clear();
  cert_source_request->GetNext(&result_certs);
  EXPECT_EQ(0u, result_certs.size());
}

// AuthorityInfoAccess with a single HTTP url pointing to a single DER cert,
// CertNetFetcher request fails.
TEST(CertIssuerSourceAiaTest, OneAiaHttpError) {
  std::shared_ptr<const bssl::ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_one_aia.pem", &cert));

  auto mock_fetcher = base::MakeRefCounted<StrictMock<MockCertNetFetcher>>();

  // HTTP request returns with an error.
  EXPECT_CALL(*mock_fetcher,
              FetchCaIssuers(GURL("http://url-for-aia/I.cer"), _, _))
      .WillOnce(Return(ByMove(MockCertNetFetcherRequest::Create(ERR_FAILED))));

  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<bssl::CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(), &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  // No results.
  bssl::ParsedCertificateList result_certs;
  cert_source_request->GetNext(&result_certs);
  ASSERT_EQ(0u, result_certs.size());
}

// AuthorityInfoAccess with a single HTTP url pointing to a single DER cert,
// CertNetFetcher request completes, but the DER cert fails to parse.
TEST(CertIssuerSourceAiaTest, OneAiaParseError) {
  std::shared_ptr<const bssl::ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_one_aia.pem", &cert));

  auto mock_fetcher = base::MakeRefCounted<StrictMock<MockCertNetFetcher>>();

  // HTTP request returns invalid certificate data.
  EXPECT_CALL(*mock_fetcher,
              FetchCaIssuers(GURL("http://url-for-aia/I.cer"), _, _))
      .WillOnce(Return(ByMove(MockCertNetFetcherRequest::Create(
          std::vector<uint8_t>({1, 2, 3, 4, 5})))));

  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<bssl::CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(), &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  // No results.
  bssl::ParsedCertificateList result_certs;
  cert_source_request->GetNext(&result_certs);
  ASSERT_EQ(0u, result_certs.size());
}

// AuthorityInfoAccess with two HTTP urls, each pointing to a single DER cert.
// One request fails.
TEST(CertIssuerSourceAiaTest, TwoAiaCompletedInSeriesFirstFails) {
  std::shared_ptr<const bssl::ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_two_aia.pem", &cert));
  std::shared_ptr<const bssl::ParsedCertificate> intermediate_cert2;
  ASSERT_TRUE(ReadTestCert("i2.pem", &intermediate_cert2));

  auto mock_fetcher = base::MakeRefCounted<StrictMock<MockCertNetFetcher>>();

  // Request for I.cer completes first, but fails.
  EXPECT_CALL(*mock_fetcher,
              FetchCaIssuers(GURL("http://url-for-aia/I.cer"), _, _))
      .WillOnce(Return(
          ByMove(MockCertNetFetcherRequest::Create(ERR_INVALID_RESPONSE))));

  // Request for I2.foo succeeds.
  EXPECT_CALL(*mock_fetcher,
              FetchCaIssuers(GURL("http://url-for-aia2/I2.foo"), _, _))
      .WillOnce(Return(ByMove(MockCertNetFetcherRequest::Create(
          intermediate_cert2->cert_buffer()))));

  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<bssl::CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(), &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  // GetNext() should return intermediate_cert2.
  bssl::ParsedCertificateList result_certs;
  cert_source_request->GetNext(&result_certs);
  ASSERT_EQ(1u, result_certs.size());
  EXPECT_EQ(result_certs.front()->der_cert(), intermediate_cert2->der_cert());

  // No more results.
  result_certs.clear();
  cert_source_request->GetNext(&result_certs);
  EXPECT_EQ(0u, result_certs.size());
}

// AuthorityInfoAccess with two HTTP urls, each pointing to a single DER cert.
// First request completes, result is retrieved, then the second request fails.
TEST(CertIssuerSourceAiaTest, TwoAiaCompletedInSeriesSecondFails) {
  std::shared_ptr<const bssl::ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_two_aia.pem", &cert));
  std::shared_ptr<const bssl::ParsedCertificate> intermediate_cert;
  ASSERT_TRUE(ReadTestCert("i.pem", &intermediate_cert));

  auto mock_fetcher = base::MakeRefCounted<StrictMock<MockCertNetFetcher>>();

  // Request for I.cer completes first.
  EXPECT_CALL(*mock_fetcher,
              FetchCaIssuers(GURL("http://url-for-aia/I.cer"), _, _))
      .WillOnce(Return(ByMove(MockCertNetFetcherRequest::Create(
          intermediate_cert->cert_buffer()))));

  // Request for I2.foo fails.
  EXPECT_CALL(*mock_fetcher,
              FetchCaIssuers(GURL("http://url-for-aia2/I2.foo"), _, _))
      .WillOnce(Return(
          ByMove(MockCertNetFetcherRequest::Create(ERR_INVALID_RESPONSE))));

  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<bssl::CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(), &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  // GetNext() should return intermediate_cert.
  bssl::ParsedCertificateList result_certs;
  cert_source_request->GetNext(&result_certs);
  ASSERT_EQ(1u, result_certs.size());
  EXPECT_EQ(result_certs.front()->der_cert(), intermediate_cert->der_cert());

  // No more results.
  result_certs.clear();
  cert_source_request->GetNext(&result_certs);
  EXPECT_EQ(0u, result_certs.size());
}

// AuthorityInfoAccess with six HTTP URLs.  kMaxFetchesPerCert is 5, so the
// sixth URL should be ignored.
TEST(CertIssuerSourceAiaTest, MaxFetchesPerCert) {
  std::shared_ptr<const bssl::ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_six_aia.pem", &cert));

  auto mock_fetcher = base::MakeRefCounted<StrictMock<MockCertNetFetcher>>();

  std::vector<uint8_t> bad_der({1, 2, 3, 4, 5});

  EXPECT_CALL(*mock_fetcher,
              FetchCaIssuers(GURL("http://url-for-aia/I.cer"), _, _))
      .WillOnce(Return(ByMove(MockCertNetFetcherRequest::Create(bad_der))));

  EXPECT_CALL(*mock_fetcher,
              FetchCaIssuers(GURL("http://url-for-aia2/I2.foo"), _, _))
      .WillOnce(Return(ByMove(MockCertNetFetcherRequest::Create(bad_der))));

  EXPECT_CALL(*mock_fetcher,
              FetchCaIssuers(GURL("http://url-for-aia3/I3.foo"), _, _))
      .WillOnce(Return(ByMove(MockCertNetFetcherRequest::Create(bad_der))));

  EXPECT_CALL(*mock_fetcher,
              FetchCaIssuers(GURL("http://url-for-aia4/I4.foo"), _, _))
      .WillOnce(Return(ByMove(MockCertNetFetcherRequest::Create(bad_der))));

  EXPECT_CALL(*mock_fetcher,
              FetchCaIssuers(GURL("http://url-for-aia5/I5.foo"), _, _))
      .WillOnce(Return(ByMove(MockCertNetFetcherRequest::Create(bad_der))));

  // Note that the sixth URL (http://url-for-aia6/I6.foo) will not be requested.

  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<bssl::CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(), &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  // GetNext() will not get any certificates (since the first 5 fail to be
  // parsed, and the sixth URL is not attempted).
  bssl::ParsedCertificateList result_certs;
  cert_source_request->GetNext(&result_certs);
  ASSERT_EQ(0u, result_certs.size());
}

// AuthorityInfoAccess that returns a certs-only CMS message containing two
// certificates.
TEST(CertIssuerSourceAiaTest, CertsOnlyCmsMessage) {
  base::FilePath cert_path =
      GetTestCertsDirectory().AppendASCII("google.binary.p7b");
  std::string cert_data;
  ASSERT_TRUE(base::ReadFileToString(cert_path, &cert_data));

  std::shared_ptr<const bssl::ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_one_aia.pem", &cert));

  auto mock_fetcher = base::MakeRefCounted<StrictMock<MockCertNetFetcher>>();

  EXPECT_CALL(*mock_fetcher,
              FetchCaIssuers(GURL("http://url-for-aia/I.cer"), _, _))
      .WillOnce(Return(ByMove(MockCertNetFetcherRequest::Create(
          std::vector<uint8_t>(cert_data.begin(), cert_data.end())))));

  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<bssl::CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(), &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  bssl::ParsedCertificateList result_certs;
  cert_source_request->GetNext(&result_certs);
  ASSERT_EQ(2u, result_certs.size());

  // The fingerprint of the Google certificate used in the parsing tests.
  SHA256HashValue google_parse_fingerprint = {
      {0xf6, 0x41, 0xc3, 0x6c, 0xfe, 0xf4, 0x9b, 0xc0, 0x71, 0x35, 0x9e,
       0xcf, 0x88, 0xee, 0xd9, 0x31, 0x7b, 0x73, 0x8b, 0x59, 0x89, 0x41,
       0x6a, 0xd4, 0x01, 0x72, 0x0c, 0x0a, 0x4e, 0x2e, 0x63, 0x52}};
  // The fingerprint for the Thawte SGC certificate
  SHA256HashValue thawte_parse_fingerprint = {
      {0x10, 0x85, 0xa6, 0xf4, 0x54, 0xd0, 0xc9, 0x11, 0x98, 0xfd, 0xda,
       0xb1, 0x1a, 0x31, 0xc7, 0x16, 0xd5, 0xdc, 0xd6, 0x8d, 0xf9, 0x1c,
       0x03, 0x9c, 0xe1, 0x8d, 0xca, 0x9b, 0xeb, 0x3c, 0xde, 0x3d}};
  EXPECT_EQ(google_parse_fingerprint, X509Certificate::CalculateFingerprint256(
                                          result_certs[0]->cert_buffer()));
  EXPECT_EQ(thawte_parse_fingerprint, X509Certificate::CalculateFingerprint256(
                                          result_certs[1]->cert_buffer()));
  result_certs.clear();
  cert_source_request->GetNext(&result_certs);
  EXPECT_TRUE(result_certs.empty());
}

}  // namespace

}  // namespace net
```