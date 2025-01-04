Response:
The user wants a summary of the functionality of the C++ code in `net/cert/nss_cert_database_unittest.cc`. They also want to know:
1. If the code has any relation to JavaScript.
2. Examples of logical reasoning with hypothetical inputs and outputs.
3. Common user or programming errors related to the code.
4. How a user might reach this code during debugging.

**Plan:**

1. **Analyze the code:** Read through the code to understand its purpose and the tests it performs.
2. **Summarize functionality:**  Describe the main goal of the file.
3. **JavaScript relation:** Determine if there are any direct or indirect connections to JavaScript.
4. **Logical reasoning examples:**  Identify test cases that involve logical checks and create hypothetical scenarios.
5. **Usage errors:**  Find tests that expose potential errors users or developers might make.
6. **Debugging scenario:**  Imagine a situation where a developer might step into this code.
```
net/cert/nss_cert_database_unittest.cc``` 是 Chromium 网络栈中的一个单元测试文件，它专门用于测试 `net::NSSCertDatabase` 类的功能。`NSSCertDatabase` 类是对 NSS (Network Security Services) 库中证书数据库功能的封装，用于管理和操作证书，例如导入、导出、列出和设置信任状态。

**功能归纳:**

该文件的主要功能是：

1. **测试证书的列举功能:**  测试 `NSSCertDatabase::ListCerts` 和 `NSSCertDatabase::ListCertsInfo` 方法，验证是否能正确列出数据库中的证书信息，包括区分 NSS 内置根证书和用户导入的证书。
2. **测试 PKCS#12 格式证书的导入和导出功能:** 测试 `NSSCertDatabase::ImportFromPKCS12` 和 `NSSCertDatabase::ExportToPKCS12` 方法，验证导入不同密码、可导出/不可导出的 PKCS#12 文件以及重复导入的情况。
3. **测试 CA 证书的导入和信任设置功能:** 测试 `NSSCertDatabase::ImportCACerts` 方法，验证导入不同信任级别的 CA 证书，包括 SSL、邮件和对象签名信任，以及处理导入非 CA 证书、证书链和证书层级结构的情况。
4. **测试服务器证书的导入功能:** 测试 `NSSCertDatabase::ImportServerCert` 方法，验证导入服务器证书及其证书链，并检查默认的信任设置。
5. **测试观察者模式:** 测试 `NSSCertDatabase` 类的观察者模式，验证当证书数据库发生变化时，观察者是否能收到通知。

**与 JavaScript 的关系:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的功能直接影响到浏览器中与安全相关的 JavaScript API 的行为。例如：

*   **`navigator.credentials.get()` 和 `navigator.credentials.store()`:**  这些 API 允许网页访问和管理用户的凭据，其中可能包括客户端证书。`NSSCertDatabase` 负责管理这些客户端证书的存储，因此这里的测试确保了证书的正确导入和管理，从而保证了这些 JavaScript API 的正常工作。
    *   **举例说明:**  假设一个网站需要用户提供客户端证书进行身份验证。网站会调用 `navigator.credentials.get({ publicKey: { challenge: '...' } })`。浏览器底层会依赖 `NSSCertDatabase` 来查找和提供合适的客户端证书。如果 `NSSCertDatabase` 的导入功能存在问题（例如，无法正确导入 PKCS#12 文件），那么这个 JavaScript API 调用可能会失败，导致用户无法完成身份验证。

**逻辑推理的举例说明:**

*   **假设输入:** 调用 `cert_db_->ImportFromPKCS12` 方法，并提供一个包含单个用户证书和私钥的 PKCS#12 文件（`client.p12`），密码为 "12345"，并设置为可导出 (`is_extractable = true`)。
*   **逻辑推理:**  `ImportFromPKCS12` 方法应该能够成功解析 PKCS#12 文件，将证书和私钥导入到 NSS 数据库中。由于设置为可导出，后续应该能够使用 `ExportToPKCS12` 方法导出该证书。
*   **预期输出:** `ImportFromPKCS12` 方法返回 `OK`，并且调用 `ListCerts()` 应该返回包含一个证书的列表，该证书的主题 CN 应该为 "testusercert"。`observer_->client_cert_store_changes()` 的值应该增加 1。后续调用 `ExportToPKCS12` 应该返回 1，并生成导出的数据。

**用户或编程常见的使用错误举例说明:**

*   **用户错误:** 用户在导入 PKCS#12 文件时输入了错误的密码。
    *   **代码体现:**  `TEST_F(CertDatabaseNSSTest, ImportFromPKCS12WrongPassword)` 测试用例模拟了这种情况。
    *   **现象:** `cert_db_->ImportFromPKCS12` 方法将返回 `ERR_PKCS12_IMPORT_BAD_PASSWORD` 错误码，并且数据库中不会添加新的证书。
*   **编程错误:** 开发者在调用 `ImportCACerts` 方法时，尝试导入一个非 CA 证书并将其设置为 CA 信任。
    *   **代码体现:** `TEST_F(CertDatabaseNSSTest, ImportCA_NotCACert)` 测试用例模拟了这种情况。
    *   **现象:** `ImportCACerts` 方法会返回 `true`，但 `failed` 列表中会包含导入失败的证书，并且 `failed[0].net_error` 会是 `ERR_IMPORT_CA_CERT_NOT_CA`。数据库中不会添加该证书。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在使用 Chromium 浏览器时，遇到了一个与证书相关的问题，例如：

1. **无法访问某个 HTTPS 网站:** 浏览器显示证书错误，例如 "NET::ERR_CERT_AUTHORITY_INVALID"。
2. **导入客户端证书失败:** 用户尝试导入 PKCS#12 文件时，浏览器提示导入失败。

作为开发者，为了调试这些问题，可能会采取以下步骤，最终可能涉及到 `nss_cert_database_unittest.cc` 中测试的代码：

1. **检查网络请求:** 使用浏览器的开发者工具 (F12) 查看网络请求，确认是否是证书错误导致连接失败。
2. **检查证书管理器:**  查看浏览器内置的证书管理器，确认相关的证书是否存在，信任状态是否正确。
3. **查看网络日志:** 启用 Chromium 的网络日志 (chrome://net-export/)，捕获更详细的网络事件，包括证书验证过程。
4. **源码调试:** 如果问题比较复杂，需要深入代码层面进行调试。开发者可能会：
    *   **设置断点:** 在 `net::NSSCertDatabase` 类的相关方法中设置断点，例如 `ImportFromPKCS12`、`ImportCACerts`、`GetCertTrust` 等。
    *   **单步执行:**  逐步执行代码，查看证书数据是如何被处理的，NSS 库的调用结果是什么。
    *   **查看 NSS 数据库状态:**  在调试过程中，可能需要查看底层的 NSS 数据库状态，例如证书列表和信任设置。
5. **单元测试:** 为了验证修复方案的正确性，开发者可能会编写或修改 `nss_cert_database_unittest.cc` 中的单元测试用例，确保相关功能在各种场景下都能正常工作。例如，如果修复了 PKCS#12 导入的 bug，可能会添加一个新的测试用例来覆盖该 bug 修复的场景。

因此，`nss_cert_database_unittest.cc` 文件中的测试用例实际上模拟了用户在浏览器中可能触发的各种证书操作，并验证了 `NSSCertDatabase` 类的正确性。开发者可以通过运行这些测试用例来确保证书管理功能的稳定性和可靠性。
```
Prompt: 
```
这是目录为net/cert/nss_cert_database_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/nss_cert_database.h"

#include <cert.h>
#include <certdb.h>
#include <pk11pub.h>
#include <seccomon.h>

#include <algorithm>
#include <memory>
#include <string>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/lazy_instance.h"
#include "base/run_loop.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/test_future.h"
#include "crypto/scoped_nss_types.h"
#include "crypto/scoped_test_nss_db.h"
#include "net/base/features.h"
#include "net/base/hash_value.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_database.h"
#include "net/cert/cert_net_fetcher.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verify_proc.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/crl_set.h"
#include "net/cert/ct_verifier.h"
#include "net/cert/do_nothing_ct_verifier.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util_nss.h"
#include "net/log/net_log_with_source.h"
#include "net/test/cert_builder.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/mozilla_security_manager/nsNSSCertificateDB.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::ASCIIToUTF16;
using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {

std::string GetSubjectCN(CERTCertificate* cert) {
  char* cn = CERT_GetCommonName(&cert->subject);
  std::string s = cn;
  PORT_Free(cn);
  return s;
}

bool GetCertIsPerm(const CERTCertificate* cert) {
  PRBool is_perm;
  CHECK_EQ(CERT_GetCertIsPerm(cert, &is_perm), SECSuccess);
  return is_perm != PR_FALSE;
}

const NSSCertDatabase::CertInfo* FindCertInfoForCert(
    const NSSCertDatabase::CertInfoList& cert_info_list,
    CERTCertificate* target_cert) {
  for (const auto& c : cert_info_list) {
    if (x509_util::IsSameCertificate(c.cert.get(), target_cert)) {
      return &c;
    }
  }
  return nullptr;
}

class MockCertDatabaseObserver : public CertDatabase::Observer {
 public:
  MockCertDatabaseObserver() { CertDatabase::GetInstance()->AddObserver(this); }

  ~MockCertDatabaseObserver() override {
    CertDatabase::GetInstance()->RemoveObserver(this);
  }

  void OnTrustStoreChanged() override { trust_store_changes_++; }

  void OnClientCertStoreChanged() override { client_cert_store_changes_++; }

  int trust_store_changes_ = 0;
  int client_cert_store_changes_ = 0;
};

class MockNSSCertDatabaseObserver : public NSSCertDatabase::Observer {
 public:
  explicit MockNSSCertDatabaseObserver(NSSCertDatabase* nss_cert_database)
      : nss_cert_database_(nss_cert_database) {
    nss_cert_database_->AddObserver(this);
  }

  ~MockNSSCertDatabaseObserver() override {
    nss_cert_database_->RemoveObserver(this);
  }

  void OnTrustStoreChanged() override { trust_store_changes_++; }

  void OnClientCertStoreChanged() override { client_cert_store_changes_++; }

  int trust_store_changes() const {
    // Also check that the NSSCertDatabase notifications were mirrored to the
    // CertDatabase observers.
    EXPECT_EQ(global_db_observer_.trust_store_changes_, trust_store_changes_);

    return trust_store_changes_;
  }

  int client_cert_store_changes() const {
    // Also check that the NSSCertDatabase notifications were mirrored to the
    // CertDatabase observers.
    EXPECT_EQ(global_db_observer_.client_cert_store_changes_,
              client_cert_store_changes_);

    return client_cert_store_changes_;
  }

  int all_changes() const {
    return trust_store_changes() + client_cert_store_changes();
  }

 private:
  raw_ptr<NSSCertDatabase> nss_cert_database_;
  MockCertDatabaseObserver global_db_observer_;
  int trust_store_changes_ = 0;
  int client_cert_store_changes_ = 0;
};

}  // namespace

class CertDatabaseNSSTest : public TestWithTaskEnvironment {
 public:
  void SetUp() override {
    ASSERT_TRUE(test_nssdb_.is_open());
    cert_db_ = std::make_unique<NSSCertDatabase>(
        crypto::ScopedPK11Slot(
            PK11_ReferenceSlot(test_nssdb_.slot())) /* public slot */,
        crypto::ScopedPK11Slot(
            PK11_ReferenceSlot(test_nssdb_.slot())) /* private slot */);
    observer_ = std::make_unique<MockNSSCertDatabaseObserver>(cert_db_.get());
    public_slot_ = cert_db_->GetPublicSlot();
    crl_set_ = CRLSet::BuiltinCRLSet();

    // Test db should be empty at start of test.
    EXPECT_EQ(0U, ListCerts().size());
  }

  void TearDown() override {
    // Run the message loop to process any observer callbacks (e.g. for the
    // ClientSocketFactory singleton) so that the scoped ref ptrs created in
    // NSSCertDatabase::NotifyObservers* get released.
    base::RunLoop().RunUntilIdle();
  }

 protected:
  PK11SlotInfo* GetPublicSlot() { return public_slot_.get(); }

  static std::string ReadTestFile(const std::string& name) {
    std::string result;
    base::FilePath cert_path = GetTestCertsDirectory().AppendASCII(name);
    EXPECT_TRUE(base::ReadFileToString(cert_path, &result));
    return result;
  }

  static bool ReadCertIntoList(const std::string& name,
                               ScopedCERTCertificateList* certs) {
    ScopedCERTCertificate cert =
        ImportCERTCertificateFromFile(GetTestCertsDirectory(), name);
    if (!cert)
      return false;

    certs->push_back(std::move(cert));
    return true;
  }

  ScopedCERTCertificateList ListCerts() {
    ScopedCERTCertificateList result;
    crypto::ScopedCERTCertList cert_list(
        PK11_ListCertsInSlot(test_nssdb_.slot()));
    if (!cert_list)
      return result;
    for (CERTCertListNode* node = CERT_LIST_HEAD(cert_list);
         !CERT_LIST_END(node, cert_list);
         node = CERT_LIST_NEXT(node)) {
      result.push_back(x509_util::DupCERTCertificate(node->cert));
    }

    // Sort the result so that test comparisons can be deterministic.
    std::sort(
        result.begin(), result.end(),
        [](const ScopedCERTCertificate& lhs, const ScopedCERTCertificate& rhs) {
          return x509_util::CalculateFingerprint256(lhs.get()) <
                 x509_util::CalculateFingerprint256(rhs.get());
        });
    return result;
  }

  std::unique_ptr<NSSCertDatabase> cert_db_;
  std::unique_ptr<MockNSSCertDatabaseObserver> observer_;
  crypto::ScopedTestNSSDB test_nssdb_;
  crypto::ScopedPK11Slot public_slot_;
  scoped_refptr<CRLSet> crl_set_;
};

TEST_F(CertDatabaseNSSTest, ListCerts) {
  // This test isn't terribly useful, though it might help with memory
  // leak tests.
  base::test::TestFuture<ScopedCERTCertificateList> future;
  cert_db_->ListCerts(future.GetCallback());

  ScopedCERTCertificateList certs = future.Take();
  // The test DB is empty, but let's assume there will always be something in
  // the other slots.
  EXPECT_LT(0U, certs.size());
}

TEST_F(CertDatabaseNSSTest, ListCertsInfo) {
  // Since ListCertsInfo queries all the "permanent" certs NSS knows about,
  // including NSS builtin trust anchors and any locally installed certs of the
  // user running the test, it's hard to do really precise testing here. Try to
  // do some general testing as well as testing that a cert added through
  // ScopedTestNSSDB is handled properly.

  // Load a test certificate
  ScopedCERTCertificateList test_root_certs = CreateCERTCertificateListFromFile(
      GetTestCertsDirectory(), "root_ca_cert.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, test_root_certs.size());
  // Should be only a temp certificate at this point, and thus not be returned
  // in the listed certs.
  EXPECT_FALSE(GetCertIsPerm(test_root_certs[0].get()));

  // Get lists of all certs both including and excluding NSS roots.
  NSSCertDatabase::CertInfoList certs_including_nss;
  NSSCertDatabase::CertInfoList certs_excluding_nss;
  {
    base::test::TestFuture<NSSCertDatabase::CertInfoList> future;
    cert_db_->ListCertsInfo(future.GetCallback(),
                            NSSCertDatabase::NSSRootsHandling::kInclude);
    certs_including_nss = future.Take();
  }
  {
    base::test::TestFuture<NSSCertDatabase::CertInfoList> future;
    cert_db_->ListCertsInfo(future.GetCallback(),
                            NSSCertDatabase::NSSRootsHandling::kExclude);
    certs_excluding_nss = future.Take();
  }

  // The tests based on GetAnNssSslTrustedBuiltinRoot could be flaky in obscure
  // local configurations (if the user running the test has manually imported
  // the same certificate into their user NSS DB.) Oh well.
  ScopedCERTCertificate nss_root = GetAnNssBuiltinSslTrustedRoot();
  // (Also this will fail if we ever do the "don't load libnssckbi.so" thing.)
  ASSERT_TRUE(nss_root);
  {
    const NSSCertDatabase::CertInfo* nss_root_info =
        FindCertInfoForCert(certs_including_nss, nss_root.get());
    ASSERT_TRUE(nss_root_info);
    EXPECT_TRUE(nss_root_info->web_trust_anchor);
    EXPECT_FALSE(nss_root_info->untrusted);
    EXPECT_FALSE(nss_root_info->device_wide);
    EXPECT_FALSE(nss_root_info->hardware_backed);
    EXPECT_TRUE(nss_root_info->on_read_only_slot);
  }
  EXPECT_FALSE(FindCertInfoForCert(certs_excluding_nss, nss_root.get()));

  // Test root cert should not be in the lists retrieved before it was imported.
  EXPECT_FALSE(
      FindCertInfoForCert(certs_including_nss, test_root_certs[0].get()));
  EXPECT_FALSE(
      FindCertInfoForCert(certs_excluding_nss, test_root_certs[0].get()));

  // Import the NSS root into the test DB.
  SECStatus srv =
      PK11_ImportCert(test_nssdb_.slot(), nss_root.get(), CK_INVALID_HANDLE,
                      net::x509_util::GetDefaultUniqueNickname(
                          nss_root.get(), net::CA_CERT, test_nssdb_.slot())
                          .c_str(),
                      PR_FALSE /* includeTrust (unused) */);
  ASSERT_EQ(SECSuccess, srv);

  // Import test certificate to the test DB.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(test_root_certs,
                                      NSSCertDatabase::TRUSTED_SSL, &failed));
  EXPECT_EQ(0U, failed.size());

  // Get new lists of all certs both including and excluding NSS roots, which
  // should now also include the test db certificates.
  NSSCertDatabase::CertInfoList certs_including_nss_with_local;
  NSSCertDatabase::CertInfoList certs_excluding_nss_with_local;
  {
    base::test::TestFuture<NSSCertDatabase::CertInfoList> future;
    cert_db_->ListCertsInfo(future.GetCallback(),
                            NSSCertDatabase::NSSRootsHandling::kInclude);
    certs_including_nss_with_local = future.Take();
  }
  {
    base::test::TestFuture<NSSCertDatabase::CertInfoList> future;
    cert_db_->ListCertsInfo(future.GetCallback(),
                            NSSCertDatabase::NSSRootsHandling::kExclude);
    certs_excluding_nss_with_local = future.Take();
  }

  // After adding the certs to the test db, the number certs returned should be
  // 1 more than before in kInclude and and 2 more in kExclude cases.
  EXPECT_EQ(certs_including_nss_with_local.size(),
            1 + certs_including_nss.size());
  EXPECT_EQ(certs_excluding_nss_with_local.size(),
            2 + certs_excluding_nss.size());

  // Using kExclude should give a smaller number of results than kInclude.
  // (Although this would be wrong if we ever do the "don't load libnssckbi.so"
  // thing.)
  EXPECT_LT(certs_excluding_nss_with_local.size(),
            certs_including_nss_with_local.size());

  // The NSS root that was imported to the test db should be in both lists now.
  {
    const NSSCertDatabase::CertInfo* nss_root_info =
        FindCertInfoForCert(certs_including_nss_with_local, nss_root.get());
    ASSERT_TRUE(nss_root_info);
    EXPECT_TRUE(nss_root_info->web_trust_anchor);
    EXPECT_FALSE(nss_root_info->untrusted);
    EXPECT_FALSE(nss_root_info->device_wide);
    EXPECT_FALSE(nss_root_info->hardware_backed);
    // `on_read_only_slot` is not tested here as the way it is calculated could
    // be potentially flaky if the cert exists on both a readonly and
    // non-readonly slot.
  }
  {
    const NSSCertDatabase::CertInfo* nss_root_info =
        FindCertInfoForCert(certs_excluding_nss_with_local, nss_root.get());
    ASSERT_TRUE(nss_root_info);
    EXPECT_FALSE(nss_root_info->web_trust_anchor);
    EXPECT_TRUE(nss_root_info->untrusted);
    EXPECT_FALSE(nss_root_info->device_wide);
    EXPECT_FALSE(nss_root_info->hardware_backed);
    // `on_read_only_slot` is not tested here as the way it is calculated could
    // be potentially flaky if the cert exists on both a readonly and
    // non-readonly slot.
  }

  // Ensure the test root cert is present in the lists retrieved after it was
  // imported, and that the info returned is as expected.
  {
    const NSSCertDatabase::CertInfo* test_cert_info = FindCertInfoForCert(
        certs_including_nss_with_local, test_root_certs[0].get());
    ASSERT_TRUE(test_cert_info);
    EXPECT_TRUE(test_cert_info->web_trust_anchor);
    EXPECT_FALSE(test_cert_info->untrusted);
    EXPECT_FALSE(test_cert_info->device_wide);
    EXPECT_FALSE(test_cert_info->hardware_backed);
    EXPECT_FALSE(test_cert_info->on_read_only_slot);
  }
  {
    const NSSCertDatabase::CertInfo* test_cert_info = FindCertInfoForCert(
        certs_excluding_nss_with_local, test_root_certs[0].get());
    ASSERT_TRUE(test_cert_info);
    EXPECT_TRUE(test_cert_info->web_trust_anchor);
    EXPECT_FALSE(test_cert_info->untrusted);
    EXPECT_FALSE(test_cert_info->device_wide);
    EXPECT_FALSE(test_cert_info->hardware_backed);
    EXPECT_FALSE(test_cert_info->on_read_only_slot);
  }
}

TEST_F(CertDatabaseNSSTest, ImportFromPKCS12WrongPassword) {
  std::string pkcs12_data = ReadTestFile("client.p12");

  EXPECT_EQ(
      ERR_PKCS12_IMPORT_BAD_PASSWORD,
      cert_db_->ImportFromPKCS12(GetPublicSlot(), pkcs12_data, std::u16string(),
                                 true,  // is_extractable
                                 nullptr));

  // Test db should still be empty.
  EXPECT_EQ(0U, ListCerts().size());

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, observer_->all_changes());
}

TEST_F(CertDatabaseNSSTest, ImportFromPKCS12AsExtractableAndExportAgain) {
  std::string pkcs12_data = ReadTestFile("client.p12");

  EXPECT_EQ(OK,
            cert_db_->ImportFromPKCS12(GetPublicSlot(), pkcs12_data, u"12345",
                                       true,  // is_extractable
                                       nullptr));

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, observer_->client_cert_store_changes());
  EXPECT_EQ(0, observer_->trust_store_changes());

  ScopedCERTCertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  EXPECT_EQ("testusercert", GetSubjectCN(cert_list[0].get()));

  // TODO(mattm): move export test to separate test case?
  std::string exported_data;
  EXPECT_EQ(1,
            cert_db_->ExportToPKCS12(cert_list, u"exportpw", &exported_data));
  ASSERT_LT(0U, exported_data.size());
  // TODO(mattm): further verification of exported data?

  base::RunLoop().RunUntilIdle();
  // Exporting should not cause an observer notification.
  EXPECT_EQ(1, observer_->all_changes());
}

TEST_F(CertDatabaseNSSTest, ImportFromPKCS12Twice) {
  std::string pkcs12_data = ReadTestFile("client.p12");

  EXPECT_EQ(OK,
            cert_db_->ImportFromPKCS12(GetPublicSlot(), pkcs12_data, u"12345",
                                       true,  // is_extractable
                                       nullptr));
  EXPECT_EQ(1U, ListCerts().size());

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, observer_->client_cert_store_changes());
  EXPECT_EQ(0, observer_->trust_store_changes());

  // NSS has a SEC_ERROR_PKCS12_DUPLICATE_DATA error, but it doesn't look like
  // it's ever used.  This test verifies that.
  EXPECT_EQ(OK,
            cert_db_->ImportFromPKCS12(GetPublicSlot(), pkcs12_data, u"12345",
                                       true,  // is_extractable
                                       nullptr));
  EXPECT_EQ(1U, ListCerts().size());

  base::RunLoop().RunUntilIdle();
  // Theoretically it should not send another notification for re-importing the
  // same thing, but probably not worth the effort to try to detect this case.
  EXPECT_EQ(2, observer_->client_cert_store_changes());
  EXPECT_EQ(0, observer_->trust_store_changes());
}

TEST_F(CertDatabaseNSSTest, ImportFromPKCS12AsUnextractableAndExportAgain) {
  std::string pkcs12_data = ReadTestFile("client.p12");

  EXPECT_EQ(OK,
            cert_db_->ImportFromPKCS12(GetPublicSlot(), pkcs12_data, u"12345",
                                       false,  // is_extractable
                                       nullptr));

  ScopedCERTCertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  EXPECT_EQ("testusercert", GetSubjectCN(cert_list[0].get()));

  std::string exported_data;
  EXPECT_EQ(0,
            cert_db_->ExportToPKCS12(cert_list, u"exportpw", &exported_data));
}

// Importing a PKCS#12 file with a certificate but no corresponding
// private key should not mark an existing private key as unextractable.
TEST_F(CertDatabaseNSSTest, ImportFromPKCS12OnlyMarkIncludedKey) {
  std::string pkcs12_data = ReadTestFile("client.p12");
  EXPECT_EQ(OK,
            cert_db_->ImportFromPKCS12(GetPublicSlot(), pkcs12_data, u"12345",
                                       true,  // is_extractable
                                       nullptr));

  ScopedCERTCertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());

  // Now import a PKCS#12 file with just a certificate but no private key.
  pkcs12_data = ReadTestFile("client-nokey.p12");
  EXPECT_EQ(OK,
            cert_db_->ImportFromPKCS12(GetPublicSlot(), pkcs12_data, u"12345",
                                       false,  // is_extractable
                                       nullptr));

  cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());

  // Make sure the imported private key is still extractable.
  std::string exported_data;
  EXPECT_EQ(1,
            cert_db_->ExportToPKCS12(cert_list, u"exportpw", &exported_data));
  ASSERT_LT(0U, exported_data.size());
}

TEST_F(CertDatabaseNSSTest, ImportFromPKCS12InvalidFile) {
  std::string pkcs12_data = "Foobarbaz";

  EXPECT_EQ(
      ERR_PKCS12_IMPORT_INVALID_FILE,
      cert_db_->ImportFromPKCS12(GetPublicSlot(), pkcs12_data, std::u16string(),
                                 true,  // is_extractable
                                 nullptr));

  // Test db should still be empty.
  EXPECT_EQ(0U, ListCerts().size());
}

TEST_F(CertDatabaseNSSTest, ImportFromPKCS12EmptyPassword) {
  std::string pkcs12_data = ReadTestFile("client-empty-password.p12");

  EXPECT_EQ(OK, cert_db_->ImportFromPKCS12(GetPublicSlot(), pkcs12_data,
                                           std::u16string(),
                                           true,  // is_extractable
                                           nullptr));
  EXPECT_EQ(1U, ListCerts().size());
}

TEST_F(CertDatabaseNSSTest, ImportFromPKCS12NullPassword) {
  std::string pkcs12_data = ReadTestFile("client-null-password.p12");

  EXPECT_EQ(OK, cert_db_->ImportFromPKCS12(GetPublicSlot(), pkcs12_data,
                                           std::u16string(),
                                           true,  // is_extractable
                                           nullptr));
  EXPECT_EQ(1U, ListCerts().size());
}

TEST_F(CertDatabaseNSSTest, ImportCACert_SSLTrust) {
  ScopedCERTCertificateList certs = CreateCERTCertificateListFromFile(
      GetTestCertsDirectory(), "root_ca_cert.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());
  EXPECT_FALSE(GetCertIsPerm(certs[0].get()));

  // Import it.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(certs, NSSCertDatabase::TRUSTED_SSL,
                                      &failed));

  EXPECT_EQ(0U, failed.size());

  ScopedCERTCertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  CERTCertificate* cert = cert_list[0].get();
  EXPECT_EQ("Test Root CA", GetSubjectCN(cert));

  EXPECT_EQ(NSSCertDatabase::TRUSTED_SSL,
            cert_db_->GetCertTrust(cert, CA_CERT));

  EXPECT_EQ(
      unsigned(CERTDB_VALID_CA | CERTDB_TRUSTED_CA | CERTDB_TRUSTED_CLIENT_CA),
      cert->trust->sslFlags);
  EXPECT_EQ(unsigned(CERTDB_VALID_CA), cert->trust->emailFlags);
  EXPECT_EQ(unsigned(CERTDB_VALID_CA), cert->trust->objectSigningFlags);

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, observer_->client_cert_store_changes());
  EXPECT_EQ(1, observer_->trust_store_changes());
}

TEST_F(CertDatabaseNSSTest, ImportCACert_EmailTrust) {
  ScopedCERTCertificateList certs = CreateCERTCertificateListFromFile(
      GetTestCertsDirectory(), "root_ca_cert.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());
  EXPECT_FALSE(GetCertIsPerm(certs[0].get()));

  // Import it.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(certs, NSSCertDatabase::TRUSTED_EMAIL,
                                      &failed));

  EXPECT_EQ(0U, failed.size());

  ScopedCERTCertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  CERTCertificate* cert = cert_list[0].get();
  EXPECT_EQ("Test Root CA", GetSubjectCN(cert));

  EXPECT_EQ(NSSCertDatabase::TRUSTED_EMAIL,
            cert_db_->GetCertTrust(cert, CA_CERT));

  EXPECT_EQ(unsigned(CERTDB_VALID_CA), cert->trust->sslFlags);
  EXPECT_EQ(
      unsigned(CERTDB_VALID_CA | CERTDB_TRUSTED_CA | CERTDB_TRUSTED_CLIENT_CA),
      cert->trust->emailFlags);
  EXPECT_EQ(unsigned(CERTDB_VALID_CA), cert->trust->objectSigningFlags);

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, observer_->client_cert_store_changes());
  // Theoretically we could avoid notifying for changes that aren't relevant
  // for server auth, but probably not worth the effort.
  EXPECT_EQ(1, observer_->trust_store_changes());
}

TEST_F(CertDatabaseNSSTest, ImportCACert_ObjSignTrust) {
  ScopedCERTCertificateList certs = CreateCERTCertificateListFromFile(
      GetTestCertsDirectory(), "root_ca_cert.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());
  EXPECT_FALSE(GetCertIsPerm(certs[0].get()));

  // Import it.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(certs, NSSCertDatabase::TRUSTED_OBJ_SIGN,
                                      &failed));

  EXPECT_EQ(0U, failed.size());

  ScopedCERTCertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  CERTCertificate* cert = cert_list[0].get();
  EXPECT_EQ("Test Root CA", GetSubjectCN(cert));

  EXPECT_EQ(NSSCertDatabase::TRUSTED_OBJ_SIGN,
            cert_db_->GetCertTrust(cert, CA_CERT));

  EXPECT_EQ(unsigned(CERTDB_VALID_CA), cert->trust->sslFlags);
  EXPECT_EQ(unsigned(CERTDB_VALID_CA), cert->trust->emailFlags);
  EXPECT_EQ(
      unsigned(CERTDB_VALID_CA | CERTDB_TRUSTED_CA | CERTDB_TRUSTED_CLIENT_CA),
      cert->trust->objectSigningFlags);

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, observer_->client_cert_store_changes());
  // Theoretically we could avoid notifying for changes that aren't relevant
  // for server auth, but probably not worth the effort.
  EXPECT_EQ(1, observer_->trust_store_changes());
}

TEST_F(CertDatabaseNSSTest, ImportCA_NotCACert) {
  ScopedCERTCertificateList certs = CreateCERTCertificateListFromFile(
      GetTestCertsDirectory(), "ok_cert.pem", X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());
  EXPECT_FALSE(GetCertIsPerm(certs[0].get()));

  // Import it.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(certs, NSSCertDatabase::TRUSTED_SSL,
                                      &failed));
  ASSERT_EQ(1U, failed.size());
  // Note: this compares pointers directly.  It's okay in this case because
  // ImportCACerts returns the same pointers that were passed in.  In the
  // general case x509_util::CryptoBufferEqual should be used.
  EXPECT_EQ(certs[0], failed[0].certificate);
  EXPECT_THAT(failed[0].net_error, IsError(ERR_IMPORT_CA_CERT_NOT_CA));

  EXPECT_EQ(0U, ListCerts().size());
}

TEST_F(CertDatabaseNSSTest, ImportCACertHierarchy) {
  ScopedCERTCertificateList certs;
  ASSERT_TRUE(ReadCertIntoList("multi-root-D-by-D.pem", &certs));
  ASSERT_TRUE(ReadCertIntoList("multi-root-C-by-D.pem", &certs));
  ASSERT_TRUE(ReadCertIntoList("multi-root-B-by-C.pem", &certs));
  ASSERT_TRUE(ReadCertIntoList("multi-root-A-by-B.pem", &certs));

  // Import it.
  NSSCertDatabase::ImportCertFailureList failed;
  // Have to specify email trust for the cert verification of the child cert to
  // work (see
  // http://mxr.mozilla.org/mozilla/source/security/nss/lib/certhigh/certvfy.c#752
  // "XXX This choice of trustType seems arbitrary.")
  EXPECT_TRUE(cert_db_->ImportCACerts(
      certs, NSSCertDatabase::TRUSTED_SSL | NSSCertDatabase::TRUSTED_EMAIL,
      &failed));

  ASSERT_EQ(1U, failed.size());
  EXPECT_EQ("127.0.0.1", GetSubjectCN(failed[0].certificate.get()));
  EXPECT_THAT(failed[0].net_error, IsError(ERR_IMPORT_CA_CERT_NOT_CA));

  ScopedCERTCertificateList cert_list = ListCerts();
  ASSERT_EQ(3U, cert_list.size());
  EXPECT_EQ("B CA - Multi-root", GetSubjectCN(cert_list[0].get()));
  EXPECT_EQ("D Root CA - Multi-root", GetSubjectCN(cert_list[1].get()));
  EXPECT_EQ("C CA - Multi-root", GetSubjectCN(cert_list[2].get()));

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, observer_->client_cert_store_changes());
  EXPECT_EQ(1, observer_->trust_store_changes());
}

TEST_F(CertDatabaseNSSTest, ImportCACertHierarchyDupeRoot) {
  ScopedCERTCertificateList certs;
  ASSERT_TRUE(ReadCertIntoList("multi-root-D-by-D.pem", &certs));

  // First import just the root.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(
      certs, NSSCertDatabase::TRUSTED_SSL | NSSCertDatabase::TRUSTED_EMAIL,
      &failed));

  EXPECT_EQ(0U, failed.size());
  ScopedCERTCertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  EXPECT_EQ("D Root CA - Multi-root", GetSubjectCN(cert_list[0].get()));

  ASSERT_TRUE(ReadCertIntoList("multi-root-C-by-D.pem", &certs));
  ASSERT_TRUE(ReadCertIntoList("multi-root-B-by-C.pem", &certs));
  ASSERT_TRUE(ReadCertIntoList("multi-root-A-by-B.pem", &certs));

  // Now import with the other certs in the list too.  Even though the root is
  // already present, we should still import the rest.
  failed.clear();
  EXPECT_TRUE(cert_db_->ImportCACerts(
      certs, NSSCertDatabase::TRUSTED_SSL | NSSCertDatabase::TRUSTED_EMAIL,
      &failed));

  ASSERT_EQ(2U, failed.size());
  EXPECT_EQ("D Root CA - Multi-root",
            GetSubjectCN(failed[0].certificate.get()));
  EXPECT_THAT(failed[0].net_error, IsError(ERR_IMPORT_CERT_ALREADY_EXISTS));
  EXPECT_EQ("127.0.0.1", GetSubjectCN(failed[1].certificate.get()));
  EXPECT_THAT(failed[1].net_error, IsError(ERR_IMPORT_CA_CERT_NOT_CA));

  cert_list = ListCerts();
  ASSERT_EQ(3U, cert_list.size());
  EXPECT_EQ("B CA - Multi-root", GetSubjectCN(cert_list[0].get()));
  EXPECT_EQ("D Root CA - Multi-root", GetSubjectCN(cert_list[1].get()));
  EXPECT_EQ("C CA - Multi-root", GetSubjectCN(cert_list[2].get()));

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, observer_->client_cert_store_changes());
  EXPECT_EQ(2, observer_->trust_store_changes());
}

TEST_F(CertDatabaseNSSTest, ImportCACertHierarchyUntrusted) {
  ScopedCERTCertificateList certs;
  ASSERT_TRUE(ReadCertIntoList("multi-root-D-by-D.pem", &certs));
  ASSERT_TRUE(ReadCertIntoList("multi-root-C-by-D.pem", &certs));

  // Import it.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(certs, NSSCertDatabase::TRUST_DEFAULT,
                                      &failed));

  ASSERT_EQ(1U, failed.size());
  EXPECT_EQ("C CA - Multi-root", GetSubjectCN(failed[0].certificate.get()));
  // TODO(mattm): should check for net error equivalent of
  // SEC_ERROR_UNTRUSTED_ISSUER
  EXPECT_THAT(failed[0].net_error, IsError(ERR_FAILED));

  ScopedCERTCertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  EXPECT_EQ("D Root CA - Multi-root", GetSubjectCN(cert_list[0].get()));

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, observer_->client_cert_store_changes());
  // We generate a notification even if not trusting the root. The certs could
  // still affect trust decisions by affecting path building.
  EXPECT_EQ(1, observer_->trust_store_changes());
}

TEST_F(CertDatabaseNSSTest, ImportCACertHierarchyTree) {
  ScopedCERTCertificateList certs;
  ASSERT_TRUE(ReadCertIntoList("multi-root-E-by-E.pem", &certs));
  ASSERT_TRUE(ReadCertIntoList("multi-root-C-by-E.pem", &certs));
  ASSERT_TRUE(ReadCertIntoList("multi-root-F-by-E.pem", &certs));

  // Import it.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(
      certs, NSSCertDatabase::TRUSTED_SSL | NSSCertDatabase::TRUSTED_EMAIL,
      &failed));

  ScopedCERTCertificateList cert_list = ListCerts();
  ASSERT_EQ(3U, cert_list.size());
  EXPECT_EQ("F CA - Multi-root", GetSubjectCN(cert_list[0].get()));
  EXPECT_EQ("C CA - Multi-root", GetSubjectCN(cert_list[1].get()));
  EXPECT_EQ("E Root CA - Multi-root", GetSubjectCN(cert_list[2].get()));
}

TEST_F(CertDatabaseNSSTest, ImportCACertNotHierarchy) {
  ScopedCERTCertificateList certs = CreateCERTCertificateListFromFile(
      GetTestCertsDirectory(), "root_ca_cert.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());
  ASSERT_TRUE(ReadCertIntoList("multi-root-F-by-E.pem", &certs));
  ASSERT_TRUE(ReadCertIntoList("multi-root-C-by-E.pem", &certs));

  // Import it.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(
      certs, NSSCertDatabase::TRUSTED_SSL | NSSCertDatabase::TRUSTED_EMAIL,
      &failed));

  ASSERT_EQ(2U, failed.size());
  // TODO(mattm): should check for net error equivalent of
  // SEC_ERROR_UNKNOWN_ISSUER
  EXPECT_EQ("F CA - Multi-root", GetSubjectCN(failed[0].certificate.get()));
  EXPECT_THAT(failed[0].net_error, IsError(ERR_FAILED));
  EXPECT_EQ("C CA - Multi-root", GetSubjectCN(failed[1].certificate.get()));
  EXPECT_THAT(failed[1].net_error, IsError(ERR_FAILED));

  ScopedCERTCertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  EXPECT_EQ("Test Root CA", GetSubjectCN(cert_list[0].get()));
}

// Test importing a server cert + chain to the NSS DB with default trust. After
// importing, all the certs should be found in the DB and should have default
// trust flags.
TEST_F(CertDatabaseNSSTest, ImportServerCert) {
  // Import the server and its chain.
  ScopedCERTCertificateList certs_to_import;
  ASSERT_TRUE(
      ReadCertIntoList("ok_cert_by_intermediate.pem", &certs_to_import));
  ASSERT_TRUE(ReadCertIntoList("intermediate_ca_cert.pem", &certs_to_import));
  ASSERT_TRUE(ReadCertIntoList("root_ca_cert.pem", &certs_to_import));

  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportServerCert(
      certs_to_import, NSSCertDatabase::TRUST_DEFAULT, &failed));
  EXPECT_EQ(0U, failed.size());

  // All the certs in the imported list should now be found in the NSS DB.
  ScopedCERTCertificateList cert_list = ListCerts();
  ASSERT_EQ(3U, cert_list.size());
  CERTCertificate* found_server_cert = nullptr;
  CERTCertificate* found_intermediate_cert = nullptr;
  CERTCertificate* found_root_cert = nullptr;
  for (const auto& cert : cert_list) {
    if (GetSubjectCN(cert.get()) == "127.0.0.1")
      found_server_cert = cert.get();
    else if (GetSubjectCN(cert.get()) == "Test Intermediate CA")
      found_intermediate_cert = cert.get();
    else if (GetSubjectCN(cert.get()) == "Test Root CA")
      found_root_cert = cert.get();
  }
  ASSERT_TRUE(found_server_cert);
  ASSERT_TRUE(found_intermediate_cert);
  ASSERT_TRUE(found_root_cert);

  EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
            cert_db_->GetCertTrust(found_server_cert, SERVER_CERT));
  EXPECT_EQ(0U, found_server_cert->trust->sslFlags);
  EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
            cert_db_->GetCertTrust(found_intermediate_cert, CA_CERT));
  EXPECT_EQ(0U, found_intermediate_cert->trust->sslFlags);
  EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
            cert_db_->GetCertTrust(found_root_cert, CA_CERT));
  EXPECT_EQ(0U, found_root_cert->trust->sslFlags);

  // Verification fails, as t
"""


```