Response:
Let's break down the thought process for analyzing the C++ unittest file.

**1. Understanding the Goal:** The primary goal is to analyze a given C++ source file and extract information about its functionality, potential connections to JavaScript, logical reasoning within the code, common user/programming errors it might help catch, and how a user might reach this code during debugging.

**2. Initial Scan and High-Level Understanding:**

* **File Name:** `nss_cert_database_chromeos_unittest.cc`. The `unittest.cc` suffix immediately signals this is a testing file. The `nss_cert_database_chromeos` part suggests it's testing functionality related to certificate management within the Chrome OS environment using NSS (Network Security Services).

* **Includes:**  A quick glance at the included headers reveals core testing frameworks (`gtest/gtest.h`), Chromium base libraries (`base/...`), cryptography (`crypto/...`), and network stack components (`net/...`). This reinforces the understanding that it's a C++ test file within the Chromium project.

* **Namespace:** The code is within the `net` namespace, further confirming it's part of Chromium's network stack.

* **Test Fixture:** The `NSSCertDatabaseChromeOSTest` class inherits from `TestWithTaskEnvironment` and `CertDatabase::Observer`. This indicates the tests will likely involve asynchronous operations (due to the task environment) and interaction with a `CertDatabase`. The observer pattern suggests it's testing notifications about certificate changes.

* **Helper Functions:** The presence of `IsCertInCertificateList` and `SwapCertLists` suggests common operations performed within the tests.

**3. Analyzing Individual Tests (Iterative Process):**  The core of understanding the file is examining each `TEST_F` function. For each test:

* **Test Name:** The name provides a concise description of what's being tested (e.g., `ListModules`, `ImportCACerts`, `SetCertTrustCertIsAlreadyOnPublicSlot`).

* **Setup:** Look for the `SetUp()` method. This often initializes the environment required for the tests (in this case, setting up NSS user profiles).

* **Core Logic:**  Focus on the actions performed within the test:
    * **Object Instantiation:**  The tests often create instances of `NSSCertDatabaseChromeOS`.
    * **Method Calls:** Key methods being tested are called (e.g., `ListModules`, `ImportCACerts`, `ImportServerCert`, `ListCerts`, `SetCertTrust`).
    * **Assertions (`EXPECT_TRUE`, `EXPECT_FALSE`, `ASSERT_EQ`, etc.):**  These are the critical parts that verify the expected behavior of the code under test. Analyze what conditions are being checked.

* **Data:**  Note how test data is being used (e.g., loading certificates from files).

* **Asynchronous Behavior:** Pay attention to `RunUntilIdle()`. This signifies that the test is dealing with asynchronous operations and needs to wait for them to complete before making assertions.

**4. Identifying Functionality:** Based on the analyzed tests, summarize the functionalities being tested:

* Listing modules/slots.
* Importing CA certificates and server certificates.
* Listing certificates.
* Setting certificate trust levels.
* Handling database shutdown during asynchronous operations.
* Interactions with the system certificate slot.
* Ensuring proper isolation between user-specific certificate databases.
* Verifying observer notifications.

**5. Considering JavaScript Relevance:**

* **Initial Thought:**  Directly, this C++ code doesn't interact with JavaScript.
* **Broader Context:**  Think about the *purpose* of the tested code. Certificate management is crucial for secure web browsing. JavaScript in web browsers relies on the underlying certificate infrastructure to establish secure connections (HTTPS).
* **Connecting the Dots:**  Explain that while the C++ code doesn't *directly* interact with JavaScript, the functionalities it tests are *essential* for the security features JavaScript relies on. Give examples like `fetch()` or `XMLHttpRequest` over HTTPS.

**6. Logical Reasoning (Input/Output):** For each test, consider:

* **Hypothetical Input:**  What data or state is being set up *before* the main action? (e.g., specific certificates, user profiles).
* **Expected Output:** What should the state of the system be *after* the action? (e.g., certificates present in specific slots, trust levels set correctly, notifications sent).

**7. Identifying Potential User/Programming Errors:**

* **Misunderstanding Certificate Scope:**  Users might expect certificates imported for one user to be available to others. The tests demonstrate the isolation, highlighting a potential misunderstanding.
* **Incorrect Trust Settings:**  The trust setting tests point to potential errors in configuring certificate trust.
* **Race Conditions/Asynchronous Issues:** The test about shutdown during worker pool processing addresses a potential programming error related to managing asynchronous operations.

**8. Debugging Scenario:**

* **Start with the Problem:** Think about a user-facing issue that could lead to investigating this code (e.g., a website showing a certificate error).
* **Trace the Steps Backwards:** How does the browser handle certificate verification?  This involves checking the certificate against the trust store.
* **Connect to the Code:**  Where is the user's certificate store managed?  On Chrome OS, this likely involves `NSSCertDatabaseChromeOS`.
* **Debugging Tools:**  Mention tools like `chrome://net-internals` that expose certificate information.

**Self-Correction/Refinement During the Process:**

* **Initial Over-Emphasis on Direct JS Interaction:**  Realized the connection is more indirect and focused on the underlying security infrastructure.
* **Ensuring Clarity in Input/Output Examples:**  Made sure the examples were concrete and tied directly to the tested scenarios.
* **Focusing on *Why* the Tests Matter:**  Explained how the tested functionalities impact the overall user experience and security.

By following this structured approach, and iteratively refining the analysis, a comprehensive understanding of the C++ unittest file can be achieved.
This C++ source file `net/cert/nss_cert_database_chromeos_unittest.cc` contains unit tests for the `NSSCertDatabaseChromeOS` class in Chromium's network stack. This class is responsible for managing certificate databases within the Chrome OS environment, specifically using the Network Security Services (NSS) library.

Here's a breakdown of its functions:

**Core Functionality Tested:**

1. **Isolation of User Certificate Databases:** The tests verify that each Chrome OS user has their own isolated NSS certificate database. Certificates imported or trust settings modified for one user should not affect other users. This is a key security feature.

2. **Listing Modules (Slots):** The tests ensure that when listing available NSS modules (cryptographic token slots), each user's database includes their own software slot and *excludes* the slots of other users.

3. **Importing Certificates:**
   - **CA Certificates (`ImportCACerts`):** Tests confirm that CA certificates are imported into the correct user's database and are only visible when listing certificates for that user. It also verifies that `OnTrustStoreChanged` notifications are triggered correctly.
   - **Server Certificates (`ImportServerCert`):** Similar to CA certificates, tests ensure server certificates are imported correctly and isolated to the importing user.

4. **Listing Certificates (`ListCerts`):** Tests verify that listing certificates for a specific user retrieves the correct set of certificates, including those in the user's private slot and the system-wide slot. It also confirms that it *doesn't* include certificates from other users' slots.

5. **Setting Certificate Trust (`SetCertTrust`):**
   - Tests scenarios where the certificate is already in the user's public slot and where it's only present in a different slot. The tests verify that trust settings can be modified correctly.
   - A specific test checks the behavior when the user's public slot is the same as the system slot, ensuring that trust modifications don't inadvertently affect system-wide trust settings.

6. **Handling Asynchronous Operations:** A test ensures that the program doesn't crash if the `NSSCertDatabaseChromeOS` object is deleted while a `ListCerts` operation is still running on a worker thread. This tests the robustness of the implementation.

7. **Observing Certificate Database Changes:** The tests utilize the `CertDatabase::Observer` interface to verify that `NSSCertDatabaseChromeOS` correctly notifies the global `CertDatabase` when trust store changes occur (`OnTrustStoreChanged`).

**Relationship with JavaScript Functionality:**

While this C++ code doesn't directly interact with JavaScript code in the same file, the functionalities it tests are **crucial for the security of web browsing and other network operations initiated by JavaScript within the Chrome browser on Chrome OS.**

Here's how it relates:

* **HTTPS Security:** When a JavaScript application (e.g., a web page) makes an HTTPS request using `fetch()` or `XMLHttpRequest`, the browser needs to verify the server's certificate. The `NSSCertDatabaseChromeOS` is responsible for managing the trusted CA certificates that this verification process relies on. The tests for `ImportCACerts` and `SetCertTrust` directly ensure this functionality works correctly.

* **Client Certificates:** Some web applications or network services require client-side certificates for authentication. The `NSSCertDatabaseChromeOS` manages these certificates. While not explicitly tested in *this specific file*, the underlying infrastructure being tested is essential for features like client certificate selection dialogs that might be triggered by JavaScript.

**Example:**

Imagine a user installs a new root CA certificate for their work VPN. This action would eventually involve the `ImportCACerts` functionality tested here. If the tests pass, it gives confidence that:

1. The certificate will be stored in the correct user's profile.
2. JavaScript code within that user's Chrome session will be able to successfully establish secure HTTPS connections to services signed by that new CA.
3. Other users on the same Chrome OS device won't be affected by this newly installed certificate.

**Logical Reasoning (Hypothetical Input and Output):**

Let's take the `ImportCACerts` test as an example:

**Hypothetical Input:**

1. **User State:** Two Chrome OS users, "user1" and "user2", are logged in. Their respective NSS databases are initialized.
2. **Certificate Data:** Two valid X.509 CA certificates are loaded from files: `root_ca_cert.pem` for `db_1_` (user1) and another generated certificate for `db_2_` (user2).
3. **Import Calls:** `db_1_->ImportCACerts(...)` is called with the first certificate, and `db_2_->ImportCACerts(...)` is called with the second certificate.

**Expected Output:**

1. **Successful Import:** Both `ImportCACerts` calls return `true`, indicating successful import.
2. **Certificate Presence (User 1):** When listing certificates for `db_1_`, the `root_ca_cert.pem` certificate is present.
3. **Certificate Absence (User 1):** When listing certificates for `db_1_`, the other generated certificate is *not* present.
4. **Certificate Presence (User 2):** When listing certificates for `db_2_`, the other generated certificate is present.
5. **Certificate Absence (User 2):** When listing certificates for `db_2_`, the `root_ca_cert.pem` certificate is *not* present.
6. **Notifications:** The `trust_store_changed_count_` is incremented twice, indicating that the `CertDatabase` was notified of the trust store changes for both users.

**User or Programming Common Usage Errors:**

1. **Assuming Shared Certificate Stores:** A user might mistakenly believe that installing a certificate for one Chrome OS user makes it available to all users on the device. These tests highlight the isolated nature of the certificate databases, preventing such assumptions from leading to security issues.

   * **Example:** A user installs a personal website's self-signed certificate for development. They might be surprised that another user on the same Chromebook still gets a certificate error when visiting that site.

2. **Incorrect Trust Settings:** A programmer working with certificate management APIs might incorrectly set the trust level of a certificate, potentially leading to security vulnerabilities (e.g., trusting a malicious CA). The `SetCertTrust` tests help ensure that these APIs function as expected, preventing such errors.

   * **Example:** A developer might intend to temporarily trust a certificate for testing but accidentally sets the trust level to always trust, which could be a security risk if that certificate is later compromised.

3. **Race Conditions in Asynchronous Operations:** If the `NSSCertDatabaseChromeOS` class wasn't implemented carefully, there could be race conditions when performing operations like listing certificates while the database is being shut down. The `NoCrashIfShutdownBeforeDoneOnWorkerPool` test specifically addresses this potential programming error.

**User Operation Steps to Reach This Code (as a Debugging Clue):**

Let's imagine a user is encountering an issue where a website they expect to work is showing a certificate error. Here's a potential path that might lead a developer to investigate `nss_cert_database_chromeos_unittest.cc`:

1. **User Reports Certificate Error:** The user reports that a specific HTTPS website is showing a "Your connection is not private" error.

2. **Initial Troubleshooting:** The user or support personnel might try basic steps like clearing browser cache, checking the system clock, etc.

3. **Investigating Certificate Details:** The user or a technician might examine the certificate details presented by the browser, noting the issuer, validity period, etc.

4. **Suspecting Certificate Store Issues:** If the certificate seems valid but the error persists, suspicion might fall on the user's certificate store.

5. **Checking for Installed Certificates:** The user or technician might navigate to Chrome's settings (e.g., `chrome://settings/security`) and view the list of installed certificates.

6. **Chrome OS Specific Investigation:** Since it's a Chrome OS device, the developer might realize that certificate management is handled by `NSSCertDatabaseChromeOS`.

7. **Looking at Unit Tests:** To understand how this component is supposed to work and to verify if the observed behavior is a bug, developers would look at the unit tests. `nss_cert_database_chromeos_unittest.cc` would be a key file to examine.

8. **Analyzing Test Scenarios:** By studying the tests, the developer can understand:
   - How certificates are imported and stored for different users.
   - How trust settings are managed.
   - Potential edge cases and error handling scenarios.

9. **Reproducing the Issue (Potentially with Test Setup):** The developer might try to reproduce the user's issue in a controlled environment, potentially using the testing infrastructure set up in `nss_cert_database_chromeos_unittest.cc` to simulate different user profiles and certificate states.

In essence, this unittest file provides a comprehensive set of checks to ensure the correct and secure operation of certificate management within the Chrome OS environment, which directly impacts the security and functionality of web browsing and other network interactions.

Prompt: 
```
这是目录为net/cert/nss_cert_database_chromeos_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/nss_cert_database_chromeos.h"

#include <memory>

#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/run_loop.h"
#include "crypto/nss_util_internal.h"
#include "crypto/scoped_test_nss_chromeos_user.h"
#include "crypto/scoped_test_nss_db.h"
#include "net/cert/cert_database.h"
#include "net/cert/x509_util_nss.h"
#include "net/test/cert_builder.h"
#include "net/test/cert_test_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

bool IsCertInCertificateList(const X509Certificate* cert,
                             const ScopedCERTCertificateList& cert_list) {
  for (const auto& other : cert_list) {
    if (x509_util::IsSameCertificate(other.get(), cert))
      return true;
  }
  return false;
}

bool IsCertInCertificateList(CERTCertificate* cert,
                             const ScopedCERTCertificateList& cert_list) {
  for (const auto& other : cert_list) {
    if (x509_util::IsSameCertificate(other.get(), cert))
      return true;
  }
  return false;
}

void SwapCertLists(ScopedCERTCertificateList* destination,
                   ScopedCERTCertificateList source) {
  ASSERT_TRUE(destination);

  destination->swap(source);
}

}  // namespace

class NSSCertDatabaseChromeOSTest : public TestWithTaskEnvironment,
                                    public CertDatabase::Observer {
 public:
  NSSCertDatabaseChromeOSTest() : user_1_("user1"), user_2_("user2") {}

  void SetUp() override {
    // Initialize nss_util slots.
    ASSERT_TRUE(user_1_.constructed_successfully());
    ASSERT_TRUE(user_2_.constructed_successfully());
    user_1_.FinishInit();
    user_2_.FinishInit();

    // Create NSSCertDatabaseChromeOS for each user.
    db_1_ = std::make_unique<NSSCertDatabaseChromeOS>(
        crypto::GetPublicSlotForChromeOSUser(user_1_.username_hash()),
        crypto::GetPrivateSlotForChromeOSUser(
            user_1_.username_hash(),
            base::OnceCallback<void(crypto::ScopedPK11Slot)>()));
    db_1_->SetSystemSlot(
        crypto::ScopedPK11Slot(PK11_ReferenceSlot(system_db_.slot())));
    db_2_ = std::make_unique<NSSCertDatabaseChromeOS>(
        crypto::GetPublicSlotForChromeOSUser(user_2_.username_hash()),
        crypto::GetPrivateSlotForChromeOSUser(
            user_2_.username_hash(),
            base::OnceCallback<void(crypto::ScopedPK11Slot)>()));

    // Add observer to CertDatabase for checking that notifications from
    // NSSCertDatabaseChromeOS are proxied to the CertDatabase.
    CertDatabase::GetInstance()->AddObserver(this);
    observer_added_ = true;
  }

  void TearDown() override {
    if (observer_added_)
      CertDatabase::GetInstance()->RemoveObserver(this);
  }

  // CertDatabase::Observer:
  void OnTrustStoreChanged() override { trust_store_changed_count_++; }
  void OnClientCertStoreChanged() override { client_cert_changed_count_++; }

 protected:
  bool observer_added_ = false;
  int trust_store_changed_count_ = 0;
  int client_cert_changed_count_ = 0;

  crypto::ScopedTestNSSChromeOSUser user_1_;
  crypto::ScopedTestNSSChromeOSUser user_2_;
  crypto::ScopedTestNSSDB system_db_;
  std::unique_ptr<NSSCertDatabaseChromeOS> db_1_;
  std::unique_ptr<NSSCertDatabaseChromeOS> db_2_;
};

// Test that ListModules() on each user includes that user's NSS software slot,
// and does not include the software slot of the other user. (Does not check the
// private slot, since it is the same as the public slot in tests.)
TEST_F(NSSCertDatabaseChromeOSTest, ListModules) {
  std::vector<crypto::ScopedPK11Slot> modules_1;
  std::vector<crypto::ScopedPK11Slot> modules_2;

  db_1_->ListModules(&modules_1, false /* need_rw */);
  db_2_->ListModules(&modules_2, false /* need_rw */);

  bool found_1 = false;
  for (std::vector<crypto::ScopedPK11Slot>::iterator it = modules_1.begin();
       it != modules_1.end(); ++it) {
    EXPECT_NE(db_2_->GetPublicSlot().get(), (*it).get());
    if ((*it).get() == db_1_->GetPublicSlot().get())
      found_1 = true;
  }
  EXPECT_TRUE(found_1);

  bool found_2 = false;
  for (std::vector<crypto::ScopedPK11Slot>::iterator it = modules_2.begin();
       it != modules_2.end(); ++it) {
    EXPECT_NE(db_1_->GetPublicSlot().get(), (*it).get());
    if ((*it).get() == db_2_->GetPublicSlot().get())
      found_2 = true;
  }
  EXPECT_TRUE(found_2);
}

// Test that ImportCACerts imports the cert to the correct slot, and that
// ListCerts includes the added cert for the correct user, and does not include
// it for the other user.
TEST_F(NSSCertDatabaseChromeOSTest, ImportCACerts) {
  // Load test certs from disk.
  ScopedCERTCertificateList certs_1 = CreateCERTCertificateListFromFile(
      GetTestCertsDirectory(), "root_ca_cert.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs_1.size());

  auto [leaf2, root2] = CertBuilder::CreateSimpleChain2();
  ScopedCERTCertificateList certs_2 =
      x509_util::CreateCERTCertificateListFromX509Certificate(
          root2->GetX509Certificate().get());
  ASSERT_EQ(1U, certs_2.size());

  // Import one cert for each user.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(
      db_1_->ImportCACerts(certs_1, NSSCertDatabase::TRUSTED_SSL, &failed));
  EXPECT_EQ(0U, failed.size());
  failed.clear();
  EXPECT_TRUE(
      db_2_->ImportCACerts(certs_2, NSSCertDatabase::TRUSTED_SSL, &failed));
  EXPECT_EQ(0U, failed.size());

  // Get cert list for each user.
  ScopedCERTCertificateList user_1_certlist;
  ScopedCERTCertificateList user_2_certlist;
  db_1_->ListCerts(
      base::BindOnce(&SwapCertLists, base::Unretained(&user_1_certlist)));
  db_2_->ListCerts(
      base::BindOnce(&SwapCertLists, base::Unretained(&user_2_certlist)));

  // Run the message loop so the observer notifications get processed and
  // lookups are completed.
  RunUntilIdle();
  // Should have gotten two OnTrustStoreChanged notifications.
  EXPECT_EQ(2, trust_store_changed_count_);
  EXPECT_EQ(0, client_cert_changed_count_);

  EXPECT_TRUE(IsCertInCertificateList(certs_1[0].get(), user_1_certlist));
  EXPECT_FALSE(IsCertInCertificateList(certs_1[0].get(), user_2_certlist));

  EXPECT_TRUE(IsCertInCertificateList(certs_2[0].get(), user_2_certlist));
  EXPECT_FALSE(IsCertInCertificateList(certs_2[0].get(), user_1_certlist));
}

// Test that ImportServerCerts imports the cert to the correct slot, and that
// ListCerts includes the added cert for the correct user, and does not include
// it for the other user.
TEST_F(NSSCertDatabaseChromeOSTest, ImportServerCert) {
  // Load test certs from disk.
  ScopedCERTCertificateList certs_1 = CreateCERTCertificateListFromFile(
      GetTestCertsDirectory(), "ok_cert.pem", X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs_1.size());

  auto [leaf2, root2] = CertBuilder::CreateSimpleChain2();
  ScopedCERTCertificateList certs_2 =
      x509_util::CreateCERTCertificateListFromX509Certificate(
          leaf2->GetX509Certificate().get());
  ASSERT_EQ(1U, certs_2.size());

  // Import one cert for each user.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(
      db_1_->ImportServerCert(certs_1, NSSCertDatabase::TRUSTED_SSL, &failed));
  EXPECT_EQ(0U, failed.size());
  failed.clear();
  EXPECT_TRUE(
      db_2_->ImportServerCert(certs_2, NSSCertDatabase::TRUSTED_SSL, &failed));
  EXPECT_EQ(0U, failed.size());

  // Get cert list for each user.
  ScopedCERTCertificateList user_1_certlist;
  ScopedCERTCertificateList user_2_certlist;
  db_1_->ListCerts(
      base::BindOnce(&SwapCertLists, base::Unretained(&user_1_certlist)));
  db_2_->ListCerts(
      base::BindOnce(&SwapCertLists, base::Unretained(&user_2_certlist)));

  // Run the message loop so the observer notifications get processed and
  // lookups are completed.
  RunUntilIdle();
  // TODO(mattm): this should be 2, but ImportServerCert doesn't currently
  // generate notifications.
  EXPECT_EQ(0, trust_store_changed_count_);
  EXPECT_EQ(0, client_cert_changed_count_);

  EXPECT_TRUE(IsCertInCertificateList(certs_1[0].get(), user_1_certlist));
  EXPECT_FALSE(IsCertInCertificateList(certs_1[0].get(), user_2_certlist));

  EXPECT_TRUE(IsCertInCertificateList(certs_2[0].get(), user_2_certlist));
  EXPECT_FALSE(IsCertInCertificateList(certs_2[0].get(), user_1_certlist));
}

// Tests that There is no crash if the database is deleted while ListCerts
// is being processed on the worker pool.
TEST_F(NSSCertDatabaseChromeOSTest, NoCrashIfShutdownBeforeDoneOnWorkerPool) {
  ScopedCERTCertificateList certlist;
  db_1_->ListCerts(base::BindOnce(&SwapCertLists, base::Unretained(&certlist)));
  EXPECT_EQ(0U, certlist.size());

  db_1_.reset();

  RunUntilIdle();

  EXPECT_LT(0U, certlist.size());
}

TEST_F(NSSCertDatabaseChromeOSTest, ListCertsReadsSystemSlot) {
  scoped_refptr<X509Certificate> cert_1(
      ImportClientCertAndKeyFromFile(GetTestCertsDirectory(),
                                     "client_1.pem",
                                     "client_1.pk8",
                                     db_1_->GetPublicSlot().get()));

  scoped_refptr<X509Certificate> cert_2(
      ImportClientCertAndKeyFromFile(GetTestCertsDirectory(),
                                     "client_2.pem",
                                     "client_2.pk8",
                                     db_1_->GetSystemSlot().get()));

  ScopedCERTCertificateList certs;
  db_1_->ListCerts(base::BindOnce(&SwapCertLists, base::Unretained(&certs)));
  RunUntilIdle();
  EXPECT_TRUE(IsCertInCertificateList(cert_1.get(), certs));
  EXPECT_TRUE(IsCertInCertificateList(cert_2.get(), certs));
}

TEST_F(NSSCertDatabaseChromeOSTest, ListCertsDoesNotCrossReadSystemSlot) {
  scoped_refptr<X509Certificate> cert_1(
      ImportClientCertAndKeyFromFile(GetTestCertsDirectory(),
                                     "client_1.pem",
                                     "client_1.pk8",
                                     db_2_->GetPublicSlot().get()));

  scoped_refptr<X509Certificate> cert_2(
      ImportClientCertAndKeyFromFile(GetTestCertsDirectory(),
                                     "client_2.pem",
                                     "client_2.pk8",
                                     system_db_.slot()));
  ScopedCERTCertificateList certs;
  db_2_->ListCerts(base::BindOnce(&SwapCertLists, base::Unretained(&certs)));
  RunUntilIdle();
  EXPECT_TRUE(IsCertInCertificateList(cert_1.get(), certs));
  EXPECT_FALSE(IsCertInCertificateList(cert_2.get(), certs));
}

TEST_F(NSSCertDatabaseChromeOSTest, SetCertTrustCertIsAlreadyOnPublicSlot) {
  // Import a certificate onto the public slot (and safety check that it ended
  // up there).
  ScopedCERTCertificateList certs = CreateCERTCertificateListFromFile(
      GetTestCertsDirectory(), "root_ca_cert.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());

  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(
      db_1_->ImportCACerts(certs, NSSCertDatabase::TRUST_DEFAULT, &failed));
  EXPECT_EQ(0U, failed.size());

  ASSERT_TRUE(NSSCertDatabase::IsCertificateOnSlot(
      certs[0].get(), db_1_->GetPublicSlot().get()));

  // Check that trust settings modification works.
  EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
            db_1_->GetCertTrust(certs[0].get(), CA_CERT));

  EXPECT_TRUE(db_1_->SetCertTrust(certs[0].get(), CA_CERT,
                                  NSSCertDatabase::TRUSTED_SSL));

  EXPECT_EQ(NSSCertDatabase::TRUSTED_SSL,
            db_1_->GetCertTrust(certs[0].get(), CA_CERT));
}

TEST_F(NSSCertDatabaseChromeOSTest, SetCertTrustCertIsOnlyOnOtherSlot) {
  crypto::ScopedTestNSSDB other_slot;

  // Import a certificate onto a slot known by NSS which is not the
  // NSSCertDatabase's public slot.
  ScopedCERTCertificateList certs = CreateCERTCertificateListFromFile(
      GetTestCertsDirectory(), "root_ca_cert.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());
  ASSERT_EQ(SECSuccess, PK11_ImportCert(other_slot.slot(), certs[0].get(),
                                        CK_INVALID_HANDLE, "cert0",
                                        PR_FALSE /* includeTrust (unused) */));
  ASSERT_FALSE(NSSCertDatabase::IsCertificateOnSlot(
      certs[0].get(), db_1_->GetPublicSlot().get()));

  // Check that trust settings modification works.
  EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
            db_1_->GetCertTrust(certs[0].get(), CA_CERT));

  EXPECT_TRUE(db_1_->SetCertTrust(certs[0].get(), CA_CERT,
                                  NSSCertDatabase::TRUSTED_SSL));

  EXPECT_EQ(NSSCertDatabase::TRUSTED_SSL,
            db_1_->GetCertTrust(certs[0].get(), CA_CERT));

  // Check that the certificate has been put onto the public slot as a side
  // effect of changing trust.
  EXPECT_TRUE(NSSCertDatabase::IsCertificateOnSlot(
      certs[0].get(), db_1_->GetPublicSlot().get()));
}

TEST_F(NSSCertDatabaseChromeOSTest, SetCertTrustPublicSlotIsSystemSlot) {
  // Create a NSSCertDatabase with |public_slot|==|system_slot|.
  NSSCertDatabaseChromeOS test_db_for_system_slot(
      /*public_slot=*/crypto::ScopedPK11Slot(
          PK11_ReferenceSlot(system_db_.slot())),
      /*private_slot=*/{});
  test_db_for_system_slot.SetSystemSlot(
      crypto::ScopedPK11Slot(PK11_ReferenceSlot(system_db_.slot())));

  // Import a certificate onto a slot known by NSS which is not the
  // NSSCertDatabase's public slot.
  crypto::ScopedTestNSSDB other_slot;
  ScopedCERTCertificateList certs = CreateCERTCertificateListFromFile(
      GetTestCertsDirectory(), "root_ca_cert.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());
  ASSERT_EQ(SECSuccess, PK11_ImportCert(other_slot.slot(), certs[0].get(),
                                        CK_INVALID_HANDLE, "cert0",
                                        PR_FALSE /* includeTrust (unused) */));
  ASSERT_FALSE(NSSCertDatabase::IsCertificateOnSlot(
      certs[0].get(), test_db_for_system_slot.GetPublicSlot().get()));

  // Changing trust through |test_db_for_system_slot| should fail and not do
  // anything, because the database is not allowed to put the certificate onto
  // its public slot (because it is also the system slot).
  EXPECT_FALSE(test_db_for_system_slot.SetCertTrust(
      certs[0].get(), CA_CERT, NSSCertDatabase::TRUSTED_SSL));
  EXPECT_FALSE(NSSCertDatabase::IsCertificateOnSlot(
      certs[0].get(), test_db_for_system_slot.GetPublicSlot().get()));
}

}  // namespace net

"""

```