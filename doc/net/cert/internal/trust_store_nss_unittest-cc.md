Response:
My thinking process to generate the response involves these steps:

1. **Understand the Goal:** The request asks for an analysis of the provided C++ unit test code for `trust_store_nss_unittest.cc`. The analysis needs to cover functionality, relationship to JavaScript (if any), logical reasoning with input/output examples, common user errors, debugging steps, and a summary of functionality. The request explicitly marks this as "Part 1 of 2".

2. **Initial Code Scan (High-Level):** I first scan the code for key elements:
    * **Includes:**  See standard C++ headers, NSS-related headers (`<cert.h>`, etc.), Chromium-specific headers (`base/strings/...`, `net/cert/...`), and testing frameworks (`gtest`). This immediately tells me it's dealing with certificate trust within the NSS library, being tested in a Chromium context.
    * **Namespaces:** The code uses `net` and an anonymous namespace, indicating standard Chromium practices.
    * **Helper Functions:** Functions like `TrustTypeToNSSTrust`, `GetASSLTrustedBuiltinRoot`, `GetNSSTrustForCert`, `AddCertToNSSSlot`, `ChangeCertTrust`, and `TrustStoreContains` suggest the core operations being tested: converting trust types, accessing built-in roots, getting trust status, and manipulating the NSS database.
    * **Test Fixtures:** The `TrustStoreNSSTestBase` class acts as a test fixture, setting up test certificates and the `TrustStoreNSS` object under test. The `TrustStoreNSSTestWithSlotFilterType` and `TrustStoreNSSTestIgnoreSystemCerts` classes indicate different testing scenarios.
    * **`TEST_P` and `TEST_F` Macros:** These clearly mark the individual test cases.
    * **Assertions and Expectations:** `ASSERT_TRUE`, `EXPECT_TRUE`, `EXPECT_EQ` are used extensively for verifying test conditions.

3. **Inferring Functionality:** Based on the code structure and helper function names, I can infer the main functionalities being tested:
    * **Reading and Importing Certificates:** The `ReadCertChainFromFile` function suggests loading certificate data from files. The `AddCertToNSSSlot` function confirms the ability to import certificates into the NSS database.
    * **Setting and Retrieving Trust:**  Functions like `TrustCert`, `DistrustCert`, `ChangeCertTrust`, and `GetNSSTrustForCert` indicate testing the modification and retrieval of certificate trust settings.
    * **Filtering Trust Stores:** The different test fixtures (`TrustStoreNSSTestWithSlotFilterType`, `TrustStoreNSSTestIgnoreSystemCerts`) suggest testing how `TrustStoreNSS` behaves with different filtering rules (e.g., ignoring system roots, filtering by slot).
    * **Listing Certificates:** Functions like `ListCertsIgnoringNSSRoots` and `GetAllUserAddedCerts` indicate testing the ability to enumerate certificates in the NSS database with specific filtering.

4. **JavaScript Relationship (or Lack Thereof):**  I look for any direct interaction with JavaScript APIs or concepts. Since this is low-level C++ code interacting directly with NSS, there's no *direct* connection. However, I recognize the *indirect* relationship: the certificate trust decisions made by this code influence how secure connections are established in the browser, which *does* affect JavaScript code running in web pages. This leads to the example of `fetch` and HTTPS.

5. **Logical Reasoning and Examples:** For each major functionality, I consider what inputs would lead to specific outputs.
    * **Adding a certificate and then querying issuers:**  Input: A certificate and its issuer certificate. Output: The issuer certificate being found.
    * **Setting trust and then getting trust:** Input: A certificate and a trust level (e.g., trusted CA). Output: The `GetTrust` function returning the corresponding `CertificateTrust` object.
    * **Filtering scenarios:** Input: A system root certificate in the system store, and a `TrustStoreNSS` configured to ignore system roots. Output: The system root not being reported as trusted.

6. **Common User/Programming Errors:** I think about common mistakes related to certificate management and how this code might expose them:
    * **Incorrect Trust Settings:**  Users might accidentally distrust a necessary root CA.
    * **Forgetting to Import:** A certificate needed for trust validation might not be present in the NSS database.
    * **Slot Confusion:**  Especially with multiple slots, users might expect a certificate to be in one slot when it's in another.

7. **Debugging Steps:** I consider how a developer might end up examining this code while debugging:
    * **Connection Errors:** If a secure connection fails, developers might trace the certificate validation process down to the trust store.
    * **Certificate Installation Issues:** Problems installing or trusting certificates would lead developers to investigate the underlying trust mechanisms.

8. **Summarizing Functionality:** I condense the identified functionalities into a concise summary.

9. **Considering "Part 1 of 2":**  I keep in mind that this is only the first part. The second part likely involves more detailed testing and potentially more complex scenarios. This influences the level of detail I provide and avoids going too deep into specific test cases.

10. **Refinement and Clarity:** I review the generated response for clarity, accuracy, and completeness, ensuring it addresses all aspects of the request. I use clear and concise language, avoiding jargon where possible. I structure the response with headings and bullet points for readability.
好的，让我们来分析一下 `net/cert/internal/trust_store_nss_unittest.cc` 这个文件的功能。

**功能归纳（第1部分）：**

这个 C++ 文件是 Chromium 网络栈中 `net/cert/internal/trust_store_nss.h` 的单元测试文件。 `TrustStoreNSS` 类负责与 Network Security Services (NSS) 库交互，管理和查询系统中的证书信任信息。因此，这个单元测试文件的主要功能是：

1. **测试 `TrustStoreNSS` 类的各种功能**:  它通过创建 `TrustStoreNSS` 实例，并调用其方法，来验证其行为是否符合预期。这包括：
    * **获取证书的信任状态**: 测试 `GetTrust()` 方法，验证对于不同信任状态（信任的根证书、信任的叶子证书、不信任的证书等）的证书，`TrustStoreNSS` 能否正确返回其信任信息。
    * **列出信任的证书**: 测试 `ListCertsIgnoringNSSRoots()` 和 `GetAllUserAddedCerts()` 方法，验证能否正确列出用户添加的证书，并排除内置的系统根证书。
    * **根据证书查找颁发者**: 测试 `SyncGetIssuersOf()` 方法，验证能否根据给定的证书，找到其颁发者。
    * **处理不同类型的证书**: 测试对不同类型的证书（根证书、中间证书、服务器证书、客户端证书）的信任处理。
    * **处理 NSS 数据库中的不同状态**:  测试当证书存在于 NSS 数据库中但未被信任，或者被显式信任或不信任时的行为。
    * **处理用户添加的证书**: 验证对于用户手动添加到 NSS 数据库的证书，`TrustStoreNSS` 能否正确识别和处理其信任状态。
    * **处理系统内置根证书**:  验证 `TrustStoreNSS` 对系统内置根证书的处理方式（通常不应该被用户策略直接修改）。
    * **测试不同的 Slot 过滤策略**:  通过 `TrustStoreNSSTestWithSlotFilterType`，测试在不同的 Slot 过滤策略下，`TrustStoreNSS` 的行为是否符合预期。

**与 JavaScript 功能的关系：**

这个 C++ 文件本身不包含 JavaScript 代码，因此没有直接的 JavaScript 功能。但是，它测试的 `TrustStoreNSS` 类在 Chromium 浏览器中扮演着关键角色，直接影响到 HTTPS 连接的安全性，而 HTTPS 连接是 JavaScript 代码通过 `fetch` API 或其他网络请求进行交互的基础。

**举例说明：**

假设一个 JavaScript 脚本使用 `fetch` API 向一个 HTTPS 网站发起请求。

```javascript
fetch('https://example.com')
  .then(response => {
    if (response.ok) {
      return response.text();
    } else {
      throw new Error('网络请求失败');
    }
  })
  .then(data => console.log(data))
  .catch(error => console.error(error));
```

在这个过程中，Chromium 浏览器会使用 `TrustStoreNSS` 来验证 `example.com` 服务器提供的 SSL/TLS 证书的有效性。`TrustStoreNSS` 会查询 NSS 数据库，判断该证书是否由受信任的 CA 签发。如果 `TrustStoreNSS` 判断证书是可信的，HTTPS 连接才能成功建立，JavaScript 的 `fetch` 请求才能顺利完成。如果 `TrustStoreNSS` 判断证书不可信（例如，证书过期、被吊销、由未知的 CA 签发），浏览器可能会阻止连接，JavaScript 代码会捕获到错误。

**逻辑推理，假设输入与输出：**

**假设输入 1：**  一个由系统信任的根证书签发的服务器证书被添加到 NSS 数据库中。

**预期输出 1：**  `TrustStoreNSS::GetTrust()` 方法应该返回该服务器证书的信任状态为 `TRUSTED_LEAF` (或者在某些配置下，如果该证书也被明确信任为 CA，则可能是 `TRUSTED_ANCHOR_OR_LEAF`)。

**假设输入 2：** 一个自签名证书被添加到 NSS 数据库中，但没有被显式标记为信任。

**预期输出 2：**  `TrustStoreNSS::GetTrust()` 方法应该返回该证书的信任状态为 `UNSPECIFIED`。

**假设输入 3：** 一个之前被信任的根证书被用户手动设置为不信任。

**预期输出 3：** `TrustStoreNSS::GetTrust()` 方法应该返回该证书的信任状态为 `DISTRUSTED`。

**用户或编程常见的使用错误举例说明：**

1. **用户错误：意外地不信任了必要的根证书。** 用户可能通过操作系统或浏览器设置，错误地将一个用于验证大量网站证书的根证书设置为不信任。这将导致用户无法访问这些网站，浏览器会显示证书错误。`TrustStoreNSS` 会正确反映这种不信任状态。

2. **编程错误：假设所有添加到 NSS 的证书都是可信的。** 开发者在编写与证书相关的代码时，不能假设所有在 NSS 数据库中的证书都是受信任的。必须使用 `TrustStoreNSS` 或类似的 API 来显式检查证书的信任状态，否则可能会导致安全漏洞。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户尝试访问一个 HTTPS 网站：** 用户在浏览器地址栏输入一个 `https://` 开头的网址，或者点击一个 HTTPS 链接。

2. **浏览器发起 SSL/TLS 握手：** 浏览器与服务器建立 TCP 连接后，会发起 SSL/TLS 握手过程。

3. **服务器提供证书链：** 服务器会将自己的证书以及可能的中间证书发送给浏览器。

4. **Chromium 网络栈调用 `TrustStoreNSS` 进行证书验证：**  网络栈会使用 `TrustStoreNSS` 来验证服务器提供的证书链的有效性，包括：
    * 验证证书签名。
    * 检查证书是否过期。
    * 查找证书链中的根证书，并确认该根证书是否被信任。

5. **如果验证失败，可能会涉及此单元测试的代码：** 如果证书验证失败（例如，找不到信任的根证书），开发人员在调试时可能会查看 `TrustStoreNSS` 的实现，并可能运行相关的单元测试，例如 `trust_store_nss_unittest.cc` 中的测试用例，来确认 `TrustStoreNSS` 的行为是否正确。他们可能会：
    * **检查 NSS 数据库的状态：** 使用 NSS 工具查看当前系统或用户 NSS 数据库中安装的证书和它们的信任状态。
    * **断点调试 `TrustStoreNSS` 的代码：**  在 Chromium 源代码中设置断点，跟踪 `TrustStoreNSS` 获取证书信任信息的过程。
    * **运行相关的单元测试：**  运行 `trust_store_nss_unittest.cc` 中的特定测试用例，来隔离和验证 `TrustStoreNSS` 的特定功能。例如，测试当一个根证书被显式不信任时，`GetTrust()` 方法是否返回 `DISTRUSTED`。

**总结第1部分的功能：**

总而言之，`net/cert/internal/trust_store_nss_unittest.cc` 文件的主要功能是全面测试 `TrustStoreNSS` 类与 NSS 库的交互，确保它能够正确地管理和查询系统中的证书信任信息。这对于保证 Chromium 浏览器安全地建立 HTTPS 连接至关重要。通过各种测试用例，该文件验证了 `TrustStoreNSS` 在处理不同类型的证书、不同的信任状态以及不同的 NSS 数据库配置时的行为是否符合预期。

### 提示词
```
这是目录为net/cert/internal/trust_store_nss_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/trust_store_nss.h"

#include <cert.h>
#include <certdb.h>
#include <pkcs11n.h>
#include <prtypes.h>

#include <memory>

#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/scoped_feature_list.h"
#include "crypto/scoped_test_nss_db.h"
#include "net/base/features.h"
#include "net/cert/internal/cert_issuer_source_sync_unittest.h"
#include "net/cert/internal/test_helpers.h"
#include "net/cert/scoped_nss_types.h"
#include "net/cert/x509_util.h"
#include "net/cert/x509_util_nss.h"
#include "net/test/cert_test_util.h"
#include "net/test/test_data_directory.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/include/openssl/pool.h"
#include "third_party/boringssl/src/pki/parsed_certificate.h"
#include "third_party/boringssl/src/pki/trust_store.h"

namespace net {

namespace {

unsigned TrustTypeToNSSTrust(bssl::CertificateTrustType trust) {
  switch (trust) {
    case bssl::CertificateTrustType::DISTRUSTED:
      return CERTDB_TERMINAL_RECORD;
    case bssl::CertificateTrustType::UNSPECIFIED:
      return 0;
    case bssl::CertificateTrustType::TRUSTED_ANCHOR:
      return CERTDB_TRUSTED_CA | CERTDB_VALID_CA;
    case bssl::CertificateTrustType::TRUSTED_LEAF:
      return CERTDB_TRUSTED | CERTDB_TERMINAL_RECORD;
    case bssl::CertificateTrustType::TRUSTED_ANCHOR_OR_LEAF:
      return CERTDB_TRUSTED_CA | CERTDB_VALID_CA | CERTDB_TRUSTED |
             CERTDB_TERMINAL_RECORD;
  }
}

std::shared_ptr<const bssl::ParsedCertificate> GetASSLTrustedBuiltinRoot() {
  bssl::CertErrors parsing_errors;
  ScopedCERTCertificate nss_cert = GetAnNssBuiltinSslTrustedRoot();
  if (!nss_cert) {
    return nullptr;
  }
  scoped_refptr<X509Certificate> ssl_trusted_root =
      x509_util::CreateX509CertificateFromCERTCertificate(nss_cert.get());
  if (!ssl_trusted_root) {
    return nullptr;
  }
  return bssl::ParsedCertificate::Create(
      bssl::UpRef(ssl_trusted_root->cert_buffer()),
      x509_util::DefaultParseCertificateOptions(), &parsing_errors);
}

std::optional<unsigned> GetNSSTrustForCert(
    const bssl::ParsedCertificate* cert) {
  SECItem der_cert;
  der_cert.data = const_cast<uint8_t*>(cert->der_cert().data());
  der_cert.len = base::checked_cast<unsigned>(cert->der_cert().size());
  der_cert.type = siDERCertBuffer;
  ScopedCERTCertificate nss_cert(
      CERT_FindCertByDERCert(CERT_GetDefaultCertDB(), &der_cert));
  if (!nss_cert) {
    return std::nullopt;
  }

  CERTCertTrust nss_cert_trust;
  if (CERT_GetCertTrust(nss_cert.get(), &nss_cert_trust) != SECSuccess) {
    return std::nullopt;
  }

  return SEC_GET_TRUST_FLAGS(&nss_cert_trust, trustSSL);
}

class TrustStoreNSSTestBase : public ::testing::Test {
 public:
  bssl::CertificateTrust ExpectedTrustForBuiltinAnchor() const {
    return bssl::CertificateTrust::ForTrustAnchor();
  }

  bssl::CertificateTrust ExpectedTrustForAnchor() const {
    return bssl::CertificateTrust::ForTrustAnchor()
        .WithEnforceAnchorConstraints()
        .WithEnforceAnchorExpiry();
  }

  bssl::CertificateTrust ExpectedTrustForAnchorOrLeaf() const {
    return bssl::CertificateTrust::ForTrustAnchorOrLeaf()
        .WithEnforceAnchorConstraints()
        .WithEnforceAnchorExpiry();
  }

  bssl::CertificateTrust ExpectedTrustForLeaf() const {
    return bssl::CertificateTrust::ForTrustedLeaf();
  }

  void SetUp() override {
    ASSERT_TRUE(first_test_nssdb_.is_open());
    ASSERT_TRUE(test_nssdb_.is_open());
    ASSERT_TRUE(other_test_nssdb_.is_open());
    bssl::ParsedCertificateList chain;
    ReadCertChainFromFile(
        "net/data/verify_certificate_chain_unittest/key-rollover/oldchain.pem",
        &chain);

    ASSERT_EQ(3U, chain.size());
    target_ = chain[0];
    oldintermediate_ = chain[1];
    oldroot_ = chain[2];
    ASSERT_TRUE(target_);
    ASSERT_TRUE(oldintermediate_);
    ASSERT_TRUE(oldroot_);

    ReadCertChainFromFile(
        "net/data/verify_certificate_chain_unittest/"
        "key-rollover/longrolloverchain.pem",
        &chain);

    ASSERT_EQ(5U, chain.size());
    newintermediate_ = chain[1];
    newroot_ = chain[2];
    newrootrollover_ = chain[3];
    ASSERT_TRUE(newintermediate_);
    ASSERT_TRUE(newroot_);
    ASSERT_TRUE(newrootrollover_);

    trust_store_nss_ = CreateTrustStoreNSS();
  }

  // Creates the TrustStoreNSS instance. Subclasses will customize the slot
  // filtering behavior here.
  virtual std::unique_ptr<TrustStoreNSS> CreateTrustStoreNSS() = 0;

  std::string GetUniqueNickname() {
    return "trust_store_nss_unittest" +
           base::NumberToString(nickname_counter_++);
  }

  void AddCertToNSSSlot(const bssl::ParsedCertificate* cert,
                        PK11SlotInfo* slot) {
    ScopedCERTCertificate nss_cert(
        x509_util::CreateCERTCertificateFromBytes(cert->der_cert()));
    ASSERT_TRUE(nss_cert);
    SECStatus srv = PK11_ImportCert(slot, nss_cert.get(), CK_INVALID_HANDLE,
                                    GetUniqueNickname().c_str(),
                                    PR_FALSE /* includeTrust (unused) */);
    ASSERT_EQ(SECSuccess, srv);
  }

  // Import `cert` into `slot` and create a trust record with `trust` type.
  // Tries to ensure that the created trust record ends up in the same `slot`.
  // (That isn't always the case if `cert` exists in multiple slots and
  // CERT_ChangeCertTrust was just used on an arbitrary CERTCertificate handle
  // for `cert`.)
  void AddCertToNSSSlotWithTrust(const bssl::ParsedCertificate* cert,
                                 PK11SlotInfo* slot,
                                 bssl::CertificateTrustType trust) {
    AddCertToNSSSlot(cert, slot);
    ChangeCertTrustInSlot(cert, slot, trust);
  }

  void AddCertsToNSS() {
    AddCertToNSSSlot(target_.get(), test_nssdb_.slot());
    AddCertToNSSSlot(oldintermediate_.get(), test_nssdb_.slot());
    AddCertToNSSSlot(newintermediate_.get(), test_nssdb_.slot());
    AddCertToNSSSlot(oldroot_.get(), test_nssdb_.slot());
    AddCertToNSSSlot(newroot_.get(), test_nssdb_.slot());
    AddCertToNSSSlot(newrootrollover_.get(), test_nssdb_.slot());

    // Check that the certificates can be retrieved as expected.
    EXPECT_TRUE(
        TrustStoreContains(target_, {newintermediate_, oldintermediate_}));

    EXPECT_TRUE(TrustStoreContains(newintermediate_,
                                   {newroot_, newrootrollover_, oldroot_}));
    EXPECT_TRUE(TrustStoreContains(oldintermediate_,
                                   {newroot_, newrootrollover_, oldroot_}));
    EXPECT_TRUE(TrustStoreContains(newrootrollover_,
                                   {newroot_, newrootrollover_, oldroot_}));
    EXPECT_TRUE(
        TrustStoreContains(oldroot_, {newroot_, newrootrollover_, oldroot_}));
    EXPECT_TRUE(
        TrustStoreContains(newroot_, {newroot_, newrootrollover_, oldroot_}));
  }

  // Trusts |cert|. Assumes the cert was already imported into NSS.
  void TrustCert(const bssl::ParsedCertificate* cert) {
    ChangeCertTrust(cert, CERTDB_TRUSTED_CA | CERTDB_VALID_CA);
  }

  // Trusts |cert| as a server, but not as a CA. Assumes the cert was already
  // imported into NSS.
  void TrustServerCert(const bssl::ParsedCertificate* cert) {
    ChangeCertTrust(cert, CERTDB_TERMINAL_RECORD | CERTDB_TRUSTED);
  }

  // Trusts |cert| as both a server and as a CA. Assumes the cert was already
  // imported into NSS.
  void TrustCaAndServerCert(const bssl::ParsedCertificate* cert) {
    ChangeCertTrust(cert, CERTDB_TERMINAL_RECORD | CERTDB_TRUSTED |
                              CERTDB_TRUSTED_CA | CERTDB_VALID_CA);
  }

  // Distrusts |cert|. Assumes the cert was already imported into NSS.
  void DistrustCert(const bssl::ParsedCertificate* cert) {
    ChangeCertTrust(cert, CERTDB_TERMINAL_RECORD);
  }

  void ChangeCertTrust(const bssl::ParsedCertificate* cert, int flags) {
    SECItem der_cert;
    der_cert.data = const_cast<uint8_t*>(cert->der_cert().data());
    der_cert.len = base::checked_cast<unsigned>(cert->der_cert().size());
    der_cert.type = siDERCertBuffer;

    ScopedCERTCertificate nss_cert(
        CERT_FindCertByDERCert(CERT_GetDefaultCertDB(), &der_cert));
    ASSERT_TRUE(nss_cert);

    CERTCertTrust trust = {0};
    trust.sslFlags = flags;
    SECStatus srv =
        CERT_ChangeCertTrust(CERT_GetDefaultCertDB(), nss_cert.get(), &trust);
    ASSERT_EQ(SECSuccess, srv);
  }

  // Change the trust for `cert` in `slot` to `trust`.
  // `cert` must already exist in `slot'.
  // Tries to ensure that the created trust record ends up in the same `slot`.
  // (That isn't always the case if `cert` exists in multiple slots and
  // CERT_ChangeCertTrust was just used on an arbitrary CERTCertificate handle
  // for `cert`.)
  // (An alternative approach would be to create the CKO_NSS_TRUST object
  // directly using PK11_CreateManagedGenericObject, which has the advantage of
  // being able to specify the slot directly, but the disadvantage that there's
  // no guarantee the way the test creates the trust object matches what NSS
  // actually does. See
  // https://crrev.com/c/3732801/9/net/cert/internal/trust_store_nss_unittest.cc#412
  // for some example code if that's ever needed.)
  void ChangeCertTrustInSlot(const bssl::ParsedCertificate* cert,
                             PK11SlotInfo* slot,
                             bssl::CertificateTrustType trust) {
    crypto::ScopedCERTCertList cert_list(PK11_ListCertsInSlot(slot));
    ASSERT_TRUE(cert_list);

    for (CERTCertListNode* node = CERT_LIST_HEAD(cert_list);
         !CERT_LIST_END(node, cert_list); node = CERT_LIST_NEXT(node)) {
      if (x509_util::IsSameCertificate(node->cert, cert->cert_buffer())) {
        CERTCertTrust nss_trust = {0};
        nss_trust.sslFlags = TrustTypeToNSSTrust(trust);
        if (CERT_ChangeCertTrust(CERT_GetDefaultCertDB(), node->cert,
                                 &nss_trust) != SECSuccess) {
          ADD_FAILURE() << "CERT_ChangeCertTrust failed: " << PORT_GetError();
        }
        return;
      }
    }
    ADD_FAILURE() << "cert not found in slot";
  }

 protected:
  bool TrustStoreContains(std::shared_ptr<const bssl::ParsedCertificate> cert,
                          bssl::ParsedCertificateList expected_matches) {
    bssl::ParsedCertificateList matches;
    trust_store_nss_->SyncGetIssuersOf(cert.get(), &matches);

    std::vector<std::string> name_result_matches;
    for (const auto& it : matches)
      name_result_matches.push_back(GetCertString(it));
    std::sort(name_result_matches.begin(), name_result_matches.end());

    std::vector<std::string> name_expected_matches;
    for (const auto& it : expected_matches)
      name_expected_matches.push_back(GetCertString(it));
    std::sort(name_expected_matches.begin(), name_expected_matches.end());

    if (name_expected_matches == name_result_matches)
      return true;

    // Print some extra information for debugging.
    EXPECT_EQ(name_expected_matches, name_result_matches);
    return false;
  }

  // Give simpler names to certificate DER (for identifying them in tests by
  // their symbolic name).
  std::string GetCertString(
      const std::shared_ptr<const bssl::ParsedCertificate>& cert) const {
    if (cert->der_cert() == oldroot_->der_cert())
      return "oldroot_";
    if (cert->der_cert() == newroot_->der_cert())
      return "newroot_";
    if (cert->der_cert() == target_->der_cert())
      return "target_";
    if (cert->der_cert() == oldintermediate_->der_cert())
      return "oldintermediate_";
    if (cert->der_cert() == newintermediate_->der_cert())
      return "newintermediate_";
    if (cert->der_cert() == newrootrollover_->der_cert())
      return "newrootrollover_";
    return cert->der_cert().AsString();
  }

  bool HasTrust(const bssl::ParsedCertificateList& certs,
                bssl::CertificateTrust expected_trust) {
    bool success = true;
    for (const std::shared_ptr<const bssl::ParsedCertificate>& cert : certs) {
      bssl::CertificateTrust trust = trust_store_nss_->GetTrust(cert.get());
      std::string trust_string = trust.ToDebugString();
      std::string expected_trust_string = expected_trust.ToDebugString();
      if (trust_string != expected_trust_string) {
        EXPECT_EQ(expected_trust_string, trust_string) << GetCertString(cert);
        success = false;
      }
    }

    return success;
  }

  std::shared_ptr<const bssl::ParsedCertificate> oldroot_;
  std::shared_ptr<const bssl::ParsedCertificate> newroot_;

  std::shared_ptr<const bssl::ParsedCertificate> target_;
  std::shared_ptr<const bssl::ParsedCertificate> oldintermediate_;
  std::shared_ptr<const bssl::ParsedCertificate> newintermediate_;
  std::shared_ptr<const bssl::ParsedCertificate> newrootrollover_;
  crypto::ScopedTestNSSDB first_test_nssdb_;
  crypto::ScopedTestNSSDB test_nssdb_;
  crypto::ScopedTestNSSDB other_test_nssdb_;
  std::unique_ptr<TrustStoreNSS> trust_store_nss_;
  unsigned nickname_counter_ = 0;
};

// Specifies which kind of per-slot filtering the TrustStoreNSS is supposed to
// perform in the parametrized TrustStoreNSSTestWithSlotFilterType.
enum class SlotFilterType {
  kDontFilter,
  kAllowSpecifiedUserSlot
};

std::string SlotFilterTypeToString(SlotFilterType slot_filter_type) {
  switch (slot_filter_type) {
    case SlotFilterType::kDontFilter:
      return "DontFilter";
    case SlotFilterType::kAllowSpecifiedUserSlot:
      return "AllowSpecifiedUserSlot";
  }
}

// Used for testing a TrustStoreNSS with the slot filter type specified by the
// test parameter. These tests are cases that are expected to be the same
// regardless of the slot filter type.
class TrustStoreNSSTestWithSlotFilterType
    : public TrustStoreNSSTestBase,
      public testing::WithParamInterface<SlotFilterType> {
 public:
  TrustStoreNSSTestWithSlotFilterType() = default;
  ~TrustStoreNSSTestWithSlotFilterType() override = default;

  SlotFilterType slot_filter_type() const { return GetParam(); }

  std::unique_ptr<TrustStoreNSS> CreateTrustStoreNSS() override {
    switch (slot_filter_type()) {
      case SlotFilterType::kDontFilter:
        return std::make_unique<TrustStoreNSS>(
            TrustStoreNSS::UseTrustFromAllUserSlots());
      case SlotFilterType::kAllowSpecifiedUserSlot:
        return std::make_unique<TrustStoreNSS>(
            crypto::ScopedPK11Slot(PK11_ReferenceSlot(test_nssdb_.slot())));
    }
  }
};

// Without adding any certs to the NSS DB, should get no anchor results for
// any of the test certs.
TEST_P(TrustStoreNSSTestWithSlotFilterType, CertsNotPresent) {
  EXPECT_TRUE(TrustStoreContains(target_, bssl::ParsedCertificateList()));
  EXPECT_TRUE(
      TrustStoreContains(newintermediate_, bssl::ParsedCertificateList()));
  EXPECT_TRUE(TrustStoreContains(newroot_, bssl::ParsedCertificateList()));
  EXPECT_TRUE(HasTrust({target_}, bssl::CertificateTrust::ForUnspecified()));
  EXPECT_TRUE(
      HasTrust({newintermediate_}, bssl::CertificateTrust::ForUnspecified()));
  EXPECT_TRUE(HasTrust({newroot_}, bssl::CertificateTrust::ForUnspecified()));
}

// TrustStoreNSS should return temporary certs on Chrome OS, because on Chrome
// OS temporary certs are used to supply policy-provided untrusted authority
// certs. (See https://crbug.com/978854)
// On other platforms it's not required but doesn't hurt anything.
TEST_P(TrustStoreNSSTestWithSlotFilterType, TempCertPresent) {
  ScopedCERTCertificate temp_nss_cert(
      x509_util::CreateCERTCertificateFromBytes(newintermediate_->der_cert()));
  EXPECT_TRUE(TrustStoreContains(target_, {newintermediate_}));
  EXPECT_TRUE(HasTrust({target_}, bssl::CertificateTrust::ForUnspecified()));
}

// Independent of the specified slot-based filtering mode, built-in root certs
// should never be trusted.
TEST_P(TrustStoreNSSTestWithSlotFilterType, TrustAllowedForBuiltinRootCerts) {
  auto builtin_root_cert = GetASSLTrustedBuiltinRoot();
  ASSERT_TRUE(builtin_root_cert);
  EXPECT_TRUE(
      HasTrust({builtin_root_cert}, bssl::CertificateTrust::ForUnspecified()));
}

// Check that ListCertsIgnoringNSSRoots and GetAllUserAddedCerts don't
// return built-in roots.
TEST_P(TrustStoreNSSTestWithSlotFilterType, ListCertsIgnoresBuiltinRoots) {
  ScopedCERTCertificate root_cert = GetAnNssBuiltinSslTrustedRoot();
  ASSERT_TRUE(root_cert);

  for (const auto& result :
       trust_store_nss_->TrustStoreNSS::ListCertsIgnoringNSSRoots()) {
    EXPECT_FALSE(
        x509_util::IsSameCertificate(result.cert.get(), root_cert.get()));
  }

  for (const auto& cert_with_trust : trust_store_nss_->GetAllUserAddedCerts()) {
    EXPECT_FALSE(x509_util::IsSameCertificate(
        x509_util::CreateCryptoBuffer(cert_with_trust.cert_bytes).get(),
        root_cert.get()));
  }
}

// Check that GetAllUserAddedCerts doesn't return any client certs, as it is
// only supposed to return server certs.
TEST_P(TrustStoreNSSTestWithSlotFilterType, GetAllUserAddedCertsNoClientCerts) {
  scoped_refptr<X509Certificate> client_cert =
      ImportClientCertAndKeyFromFile(GetTestCertsDirectory(), "client_1.pem",
                                     "client_1.pk8", test_nssdb_.slot());
  ASSERT_TRUE(client_cert);

  bool found = false;
  for (const auto& result :
       trust_store_nss_->TrustStoreNSS::ListCertsIgnoringNSSRoots()) {
    found |= x509_util::IsSameCertificate(result.cert.get(), client_cert.get());
  }
  EXPECT_TRUE(found);

  for (const auto& cert_with_trust : trust_store_nss_->GetAllUserAddedCerts()) {
    EXPECT_FALSE(x509_util::CryptoBufferEqual(
        x509_util::CreateCryptoBuffer(cert_with_trust.cert_bytes).get(),
        client_cert->cert_buffer()));
  }
}

// Check that GetAllUserAddedCerts will return a client cert that has had trust
// bits added for server auth.
TEST_P(TrustStoreNSSTestWithSlotFilterType,
       GetAllUserAddedCertsManualTrustClientCert) {
  scoped_refptr<X509Certificate> client_cert =
      ImportClientCertAndKeyFromFile(GetTestCertsDirectory(), "client_1.pem",
                                     "client_1.pk8", test_nssdb_.slot());
  ASSERT_TRUE(client_cert);
  std::shared_ptr<const bssl::ParsedCertificate> parsed_client_cert =
      bssl::ParsedCertificate::Create(
          bssl::UpRef(client_cert->cert_buffer()),
          x509_util::DefaultParseCertificateOptions(), nullptr);
  ASSERT_TRUE(parsed_client_cert);
  TrustCert(parsed_client_cert.get());

  {
    bool found = false;
    for (const auto& result :
         trust_store_nss_->TrustStoreNSS::ListCertsIgnoringNSSRoots()) {
      found |=
          x509_util::IsSameCertificate(result.cert.get(), client_cert.get());
    }
    EXPECT_TRUE(found);
  }

  {
    bool found = false;
    for (const auto& cert_with_trust :
         trust_store_nss_->GetAllUserAddedCerts()) {
      found |= x509_util::CryptoBufferEqual(
          x509_util::CreateCryptoBuffer(cert_with_trust.cert_bytes).get(),
          client_cert->cert_buffer());
    }
    EXPECT_TRUE(found);
  }
}

INSTANTIATE_TEST_SUITE_P(
    All,
    TrustStoreNSSTestWithSlotFilterType,
    ::testing::Values(SlotFilterType::kDontFilter,
                      SlotFilterType::kAllowSpecifiedUserSlot),
    [](const testing::TestParamInfo<
        TrustStoreNSSTestWithSlotFilterType::ParamType>& info) {
      return SlotFilterTypeToString(info.param);
    });

// Tests a TrustStoreNSS that ignores system root certs.
class TrustStoreNSSTestIgnoreSystemCerts : public TrustStoreNSSTestBase {
 public:
  std::unique_ptr<TrustStoreNSS> CreateTrustStoreNSS() override {
    return std::make_unique<TrustStoreNSS>(
        TrustStoreNSS::UseTrustFromAllUserSlots());
  }
};

TEST_F(TrustStoreNSSTestIgnoreSystemCerts, UnknownCertIgnored) {
  EXPECT_TRUE(HasTrust({newroot_}, bssl::CertificateTrust::ForUnspecified()));
}

// An NSS CERTCertificate object exists for the cert, but it is not
// imported into any DB. Should be unspecified trust.
TEST_F(TrustStoreNSSTestIgnoreSystemCerts, TemporaryCertIgnored) {
  ScopedCERTCertificate nss_cert(
      x509_util::CreateCERTCertificateFromBytes(newroot_->der_cert()));
  EXPECT_TRUE(HasTrust({newroot_}, bssl::CertificateTrust::ForUnspecified()));
}

// Cert is added to user DB, but without explicitly calling
// CERT_ChangeCertTrust. Should be unspecified trust.
TEST_F(TrustStoreNSSTestIgnoreSystemCerts, UserCertWithNoTrust) {
  AddCertsToNSS();
  EXPECT_TRUE(HasTrust({newroot_}, bssl::CertificateTrust::ForUnspecified()));
}

TEST_F(TrustStoreNSSTestIgnoreSystemCerts, UserRootTrusted) {
  AddCertsToNSS();
  TrustCert(newroot_.get());
  EXPECT_TRUE(HasTrust({newroot_}, ExpectedTrustForAnchor()));
}

TEST_F(TrustStoreNSSTestIgnoreSystemCerts, UserRootDistrusted) {
  AddCertsToNSS();
  DistrustCert(newroot_.get());
  EXPECT_TRUE(HasTrust({newroot_}, bssl::CertificateTrust::ForDistrusted()));
}

TEST_F(TrustStoreNSSTestIgnoreSystemCerts, UserTrustedServer) {
  AddCertsToNSS();
  TrustServerCert(target_.get());
  EXPECT_TRUE(HasTrust({target_}, ExpectedTrustForLeaf()));
}

TEST_F(TrustStoreNSSTestIgnoreSystemCerts, UserTrustedCaAndServer) {
  AddCertsToNSS();
  TrustCaAndServerCert(target_.get());
  EXPECT_TRUE(HasTrust({target_}, ExpectedTrustForAnchorOrLeaf()));
}

TEST_F(TrustStoreNSSTestIgnoreSystemCerts, SystemRootCertIgnored) {
  std::shared_ptr<const bssl::ParsedCertificate> system_root =
      GetASSLTrustedBuiltinRoot();
  ASSERT_TRUE(system_root);
  EXPECT_TRUE(
      HasTrust({system_root}, bssl::CertificateTrust::ForUnspecified()));
}

// A system trusted root is also present in a user DB, but without any trust
// settings in the user DB. The system trust settings should not be used.
TEST_F(TrustStoreNSSTestIgnoreSystemCerts,
       SystemRootCertIgnoredWhenPresentInUserDb) {
  std::shared_ptr<const bssl::ParsedCertificate> system_root =
      GetASSLTrustedBuiltinRoot();
  ASSERT_TRUE(system_root);

  AddCertToNSSSlot(system_root.get(), test_nssdb_.slot());

  // TrustStoreNSS should see an Unspecified since we are ignoring the system
  // slot.
  EXPECT_TRUE(
      HasTrust({system_root}, bssl::CertificateTrust::ForUnspecified()));
}

// A system trusted root is also present in a user DB, with TRUSTED_CA settings
// in the user DB. The system trust settings should not be used, but the trust
// from the user DB should be honored.
TEST_F(TrustStoreNSSTestIgnoreSystemCerts, UserDbTrustForSystemRootHonored) {
  std::shared_ptr<const bssl::ParsedCertificate> system_root =
      GetASSLTrustedBuiltinRoot();
  ASSERT_TRUE(system_root);

  AddCertToNSSSlotWithTrust(system_root.get(), test_nssdb_.slot(),
                            bssl::CertificateTrustType::TRUSTED_ANCHOR);
  // NSS should see the cert as trusted.
  EXPECT_EQ(CERTDB_TRUSTED_CA | CERTDB_VALID_CA,
            GetNSSTrustForCert(system_root.get()));

  // TrustStoreNSS should see as TrustAnchor since the cert was trusted in the
  // user slot.
  EXPECT_TRUE(HasTrust({system_root}, ExpectedTrustForAnchor()));
}

// A system trusted root is also present in a user DB, with leaf trust in the
// user DB. The system trust settings should not be used, but the trust from
// the user DB should be honored.
TEST_F(TrustStoreNSSTestIgnoreSystemCerts,
       UserDbLeafTrustForSystemRootHonored) {
  std::shared_ptr<const bssl::ParsedCertificate> system_root =
      GetASSLTrustedBuiltinRoot();
  ASSERT_TRUE(system_root);

  // Add unrelated trust record to test that we find the correct one.
  AddCertToNSSSlotWithTrust(newroot_.get(), test_nssdb_.slot(),
                            bssl::CertificateTrustType::TRUSTED_ANCHOR);

  // Trust the system cert as a leaf.
  AddCertToNSSSlotWithTrust(system_root.get(), test_nssdb_.slot(),
                            bssl::CertificateTrustType::TRUSTED_LEAF);

  // Add unrelated trust record to test that we find the correct one.
  AddCertToNSSSlotWithTrust(newintermediate_.get(), test_nssdb_.slot(),
                            bssl::CertificateTrustType::DISTRUSTED);

  // NSS should see the cert as a trusted leaf.
  EXPECT_EQ(CERTDB_TRUSTED | CERTDB_TERMINAL_RECORD,
            GetNSSTrustForCert(system_root.get()));

  // TrustStoreNSS should see as TrustedLeaf since the cert was trusted in the
  // user slot.
  EXPECT_TRUE(HasTrust({system_root}, ExpectedTrustForLeaf()));
}

// A system trusted root is also present in a user DB, with both CA and leaf
// trust in the user DB. The system trust settings should not be used, but the
// trust from the user DB should be honored.
TEST_F(TrustStoreNSSTestIgnoreSystemCerts,
       UserDbAnchorAndLeafTrustForSystemRootHonored) {
  std::shared_ptr<const bssl::ParsedCertificate> system_root =
      GetASSLTrustedBuiltinRoot();
  ASSERT_TRUE(system_root);

  AddCertToNSSSlotWithTrust(system_root.get(), test_nssdb_.slot(),
                            bssl::CertificateTrustType::TRUSTED_ANCHOR_OR_LEAF);

  // NSS should see the cert as both trusted leaf and CA.
  EXPECT_EQ(CERTDB_TRUSTED_CA | CERTDB_VALID_CA | CERTDB_TRUSTED |
                CERTDB_TERMINAL_RECORD,
            GetNSSTrustForCert(system_root.get()));

  // TrustStoreNSS should see as TrustAnchor since the cert was trusted in the
  // user slot. The TrustStoreNSS implementation isn't able to pick up both the
  // CA and Leaf trust in this case, but we don't really care.
  EXPECT_TRUE(HasTrust({system_root}, ExpectedTrustForAnchor()));
}

// A system trusted root is also present in a user DB, with TERMINAL_RECORD
// settings in the user DB. The system trust settings should not be used, and
// the distrust from the user DB should be honored.
TEST_F(TrustStoreNSSTestIgnoreSystemCerts, UserDbDistrustForSystemRootHonored) {
  std::shared_ptr<const bssl::ParsedCertificate> system_root =
      GetASSLTrustedBuiltinRoot();
  ASSERT_TRUE(system_root);

  AddCertToNSSSlotWithTrust(system_root.get(), test_nssdb_.slot(),
                            bssl::CertificateTrustType::DISTRUSTED);

  // NSS should see the cert as distrusted.
  EXPECT_EQ(CERTDB_TERMINAL_RECORD, GetNSSTrustForCert(system_root.get()));

  // TrustStoreNSS should see as Distrusted since the cert was distrusted in
  // the user slot.
  EXPECT_TRUE(HasTrust({system_root}, bssl::CertificateTrust::ForDistrusted()));
}

// A system trusted root is also present in a user DB, with a trust object with
// no SSL trust flags set in the user DB. The system trust settings should not
// be used, and the lack of trust flags in the user DB should result in
// unspecified trust.
TEST_F(TrustStoreNSSTestIgnoreSystemCerts,
       UserDbUnspecifiedTrustForSystemRootHonored) {
  std::shared_ptr<const bssl::ParsedCertificate> system_root =
      GetASSLTrustedBuiltinRoot();
  ASSERT_TRUE(system_root);

  AddCertToNSSSlotWithTrust(system_root.get(), test_nssdb_.slot(),
                            bssl::CertificateTrustType::UNSPECIFIED);

  // NSS should see the cert as unspecified trust.
  EXPECT_EQ(0u, GetNSSTrustForCert(system_root.get()));

  // TrustStoreNSS should see as Unspecified since the cert was marked
  // unspecified in the user slot.
  EXPECT_TRUE(
      HasTrust({system_root}, bssl::CertificateTrust::ForUnspecified()));
}

// Tests a TrustStoreNSS that does not filter which certificates
class TrustStoreNSSTestWithoutSlotFilter : public TrustStoreNSSTestBase {
 public:
  std::unique_ptr<TrustStoreNSS> CreateTrustStoreNSS() override {
    return std::make_unique<TrustStoreNSS>(
        TrustStoreNSS::UseTrustFromAllUserSlots());
  }
};

// If certs are present in NSS DB but aren't marked as trusted, should get no
// anchor results for any of the test certs.
TEST_F(TrustStoreNSSTestWithoutSlotFilter, CertsPresentButNotTrusted) {
  AddCertsToNSS();

  // None of the certificates are trusted.
  EXPECT_TRUE(HasTrust({oldroot_, newroot_, target_, oldintermediate_,
                        newintermediate_, newrootrollover_},
                       bssl::CertificateTrust::ForUnspecified()));
}

// Trust a single self-signed CA certificate.
TEST_F(TrustStoreNSSTestWithoutSlotFilter, TrustedCA) {
  AddCertsToNSS();
  TrustCert(newroot_.get());

  // Only one of the certificates are trusted.
  EXPECT_TRUE(HasTrust(
      {oldroot_, target_, oldintermediate_, newintermediate_, newrootrollover_},
      bssl::CertificateTrust::ForUnspecified()));

  EXPECT_TRUE(HasTrust({newroot_}, ExpectedTrustForAnchor()));
}

// Distrust a single self-signed CA certificate.
TEST_F(TrustStoreNSSTestWithoutSlotFilter, DistrustedCA) {
  AddCertsToNSS();
  DistrustCert(newroot_.get());

  // Only one of the certificates are trusted.
  EXPECT_TRUE(HasTrust(
      {oldroot_, target_, oldintermediate_, newintermediate_, newrootrollover_},
      bssl::CertificateTrust::ForUnspecified()));

  EXPECT_TRUE(HasTrust({newroot_}, bssl::CertificateTrust::ForDistrusted()));
}

// Trust a single intermediate certificate.
TEST_F(TrustStoreNSSTestWithoutSlotFilter, TrustedIntermediate) {
  AddCertsToNSS();
  TrustCert(newintermediate_.get());

  EXPECT_TRUE(HasTrust(
      {oldroot_, newroot_, target_, oldintermediate_, newrootrollover_},
      bssl::CertificateTrust::ForUnspecified()));
  EXPECT_TRUE(HasTrust({newintermediate_}, ExpectedTrustForAnchor()));
}

// Distrust a single intermediate certificate.
TEST_F(TrustStoreNSSTestWithoutSlotFilter, DistrustedIntermediate) {
  AddCertsToNSS();
  DistrustCert(newintermediate_.get());

  EXPECT_TRUE(HasTrust(
      {oldroot_, newroot_, target_, oldintermediate_, newrootrollover_},
      bssl::CertificateTrust::ForUnspecified()));
  EXPECT_TRUE(
      HasTrust({newintermediate_}, bssl::CertificateTrust::ForDistrusted()));
}

// Trust a single server certificate.
TEST_F(TrustStoreNSSTestWithoutSlotFilter, TrustedServer) {
  AddCertsToNSS();
  TrustServerCert(target_.get());

  EXPECT_TRUE(HasTrust({oldroot_, newroot_, oldintermediate_, newintermediate_,
                        newrootrollover_},
                       bssl::CertificateTrust::ForUnspecified()));
  EXPECT_TRUE(HasTrust({target_}, ExpectedTrustForLeaf()));
}

// Trust a single certificate with both CA and server trust bits.
TEST_F(TrustStoreNSSTestWithoutSlotFilter, TrustedCaAndServer) {
  AddCertsToNSS();
  TrustCaAndServerCert(target_.get());

  EXPECT_TRUE(HasTrust({oldroot_, newroot_, oldintermediate_, newintermediate_,
                        newrootrollover_},
                       bssl::CertificateTrust::ForUnspecified()));
  EXPECT_TRUE(HasTrust({target_}, ExpectedTrustForAnchorOrLeaf()));
}

// Trust multiple self-signed CA certificates with the same name.
TEST_F(TrustStoreNSSTestWithoutSlotFilter, MultipleTrustedCAWithSameSubject) {
  AddCertsToNSS();
  TrustCert(oldroot_.get());
  TrustCert(newroot_.get());

  EXPECT_TRUE(
      HasTrust({target_, oldintermediate_, newintermediate_, newrootrollover_},
               bssl::CertificateTrust::ForUnspecified()));
  EXPECT_TRUE(HasTrust({oldroot_, newroot_}, ExpectedTrustForAnchor()));
}

// Different trust settings for multiple self-signed CA certificates with the
// same name.
TEST_F(TrustStoreNSSTestWithoutSlotFilter, DifferingTrustCAWithSameSubject) {
  AddCertsToNSS();
  DistrustCert(oldroot_.get());
  TrustCert(newroot_.get());

  EXPECT_TRUE(
      HasTrust({target_, oldintermediate_, newintermediate_, newrootrollover_},
               bssl::CertificateTrust::ForUnspecified()));
  EXPECT_TRUE(HasTrust({oldroot_}, bssl::CertificateTrust::ForDistrusted()));
  EXPECT_TRUE(HasTrust({newroot_}, ExpectedTrustForAnchor()));
}

// Check that ListCertsIgnoringNssRoots and GetAllUserAddedCerts are correctly
// looking at all slots.
TEST_F(TrustStoreNSSTestWithoutSlotFilter, ListCertsLooksAtAllSlots) {
  AddCertToNSSSlotWithTrust(oldroot_.get(), first_test_nssdb_.slot(),
                            bssl::CertificateTrustType::DISTRUSTED);
  AddCertToNSSSlotWithTrust(newroot_.get(), test_nssdb_.slot(),
                            bssl::CertificateTrustType::TRUSTED_LEAF);

  {
    bool found_newroot = false;
    bool found_oldroot = false;
    for (const auto& result :
         trust_store_nss_->TrustStoreNSS::ListCertsIgnoringNSSRoots()) {
      found_oldroot |= x509_util::IsSameCertificate(result.cert.get(),
                                                    oldroot_->cert_buffer());
      found_newroot |= x509_util::IsSameCertificate(result.cert.get(),
                                                    newroot_->cert_buffer());
    }
    EXPECT_TRUE(found_newroot);
    EXPECT_TRUE(found_oldroot);
  }

  {
    bool found_newroot = false;
    bool found_oldroot = false;
    for (const auto& cert_with_trust :
         trust_store_nss_->GetAllUserAddedCerts()) {
      found_oldroot |= x509_util::CryptoBuffe
```