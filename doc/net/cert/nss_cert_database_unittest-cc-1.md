Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is a part of a unit test file for Chromium's network stack, specifically for the `NSSCertDatabase` class.

Here's a breakdown of the thought process to analyze the code and generate the summary:

1. **Identify the Core Class Under Test:** The filename `nss_cert_database_unittest.cc` and the test fixture `CertDatabaseNSSTest` clearly indicate that the primary focus is on testing the `NSSCertDatabase` class.

2. **Recognize the Test Structure:** The code is structured as a series of individual test cases using the `TEST_F` macro. Each test case focuses on a specific aspect of the `NSSCertDatabase` functionality.

3. **Analyze Individual Test Cases:**  Go through each `TEST_F` block and determine its purpose:
    * **`ImportEmptyCertList`:** Checks the behavior when importing an empty list of certificates.
    * **`ImportCaCert_NoTrust`:**  Verifies importing a CA certificate without explicitly trusting it.
    * **`ImportCaCert_Trusted`:** Checks importing and trusting a CA certificate.
    * **`ImportServerCert_UntrustedIssuer`:**  Tests importing a server certificate issued by an untrusted CA.
    * **`ImportServerCert_SelfSigned`:** Tests importing a self-signed server certificate without trust.
    * **`ImportServerCert_SelfSigned_Trusted`:** Tests importing and trusting a self-signed server certificate.
    * **`ImportCaAndServerCert`:** Checks importing a CA certificate (trusting it) and then a server certificate issued by it.
    * **`ImportCaAndServerCert_DistrustServer`:**  Tests importing a trusted CA and then a server certificate issued by it but explicitly distrusting the server certificate.
    * **`TrustIntermediateCa`**, **`TrustIntermediateCa2`**, **`TrustIntermediateCa3`**, **`TrustIntermediateCa4`:** These tests focus on different scenarios of trusting and distrusting intermediate CA certificates and their impact on server certificate verification. They explore combinations of default trust, explicit trust, and explicit distrust for root and intermediate CAs.
    * **`ImportDuplicateCommonName`:**  Tests importing two different certificates that share the same common name.

4. **Identify Key Functionality Being Tested:** Based on the analysis of the individual tests, identify the core functionalities of `NSSCertDatabase` being exercised:
    * Importing CA certificates (`ImportCACerts`) with different trust settings.
    * Importing server certificates (`ImportServerCert`) with different trust settings.
    * Setting the trust status of certificates (`SetCertTrust`).
    * Verifying certificate chains using `CertVerifyProc`.
    * Observing changes in the certificate and trust stores.
    * Handling duplicate common names.

5. **Look for Interactions with Other Components:** Notice the use of:
    * `ScopedCERTCertificateList`:  For managing lists of certificates.
    * `x509_util::CreateX509CertificateFromCERTCertificate`: For converting certificate formats.
    * `CertVerifyProc`: For performing certificate verification.
    * `CertVerifyResult`: For capturing the results of certificate verification.
    * `NetLogWithSource`: For logging network events.
    * `CertBuilder`: For creating test certificates.
    * `MockCertDatabaseObserver`: For observing changes in the certificate database.

6. **Consider the Context of Unit Tests:**  Recognize that these tests are designed to be isolated and repeatable. They often involve setting up specific scenarios (e.g., importing specific certificates with certain trust levels) and then asserting that the expected outcomes occur (e.g., certificate verification succeeds or fails with the expected error).

7. **Address Specific Questions from the Prompt:**
    * **Functionality Listing:**  List the identified core functionalities.
    * **Relationship to JavaScript:**  Consider how certificate management relates to web browsers and JavaScript. HTTPS relies on certificates, and while JavaScript doesn't directly manage the certificate database, it interacts with the browser's security features which in turn rely on it. Examples include fetching resources over HTTPS.
    * **Logical Reasoning (Assumptions and Outputs):** For some tests, it's easy to formulate assumptions and expected outputs. For example, importing a trusted CA and then a server certificate issued by it *should* lead to successful verification. Conversely, importing a server certificate issued by an untrusted CA *should* lead to a verification error.
    * **User/Programming Errors:** Think about common mistakes developers or users might make when dealing with certificates, such as importing the wrong type of certificate or forgetting to trust a CA.
    * **User Actions Leading to this Code:** Consider the user actions that would trigger the underlying certificate management logic, such as visiting a website over HTTPS or manually importing a certificate in browser settings.
    * **归纳功能 (Summarize Functionality):** Provide a concise overview of the file's purpose.

8. **Structure the Output:** Organize the findings logically, addressing each part of the user's request clearly. Use bullet points and clear language to enhance readability.

By following these steps, we can effectively analyze the provided C++ code and generate a comprehensive summary of its functionality, including its relevance to JavaScript, logical reasoning, potential errors, user interaction, and a concise overall description.
```cpp
// The intermediate & CA certs are imported without
// trust.
scoped_refptr<X509Certificate> x509_found_server_cert =
    x509_util::CreateX509CertificateFromCERTCertificate(found_server_cert);
ASSERT_TRUE(x509_found_server_cert);
scoped_refptr<CertVerifyProc> verify_proc(
    CertVerifyProc::CreateBuiltinWithChromeRootStore(
        /*cert_net_fetcher=*/nullptr, crl_set_,
        std::make_unique<DoNothingCTVerifier>(),
        base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
        /*root_store_data=*/nullptr,
        /*instance_params=*/{}, std::nullopt));
int flags = 0;
CertVerifyResult verify_result;
int error = verify_proc->Verify(x509_found_server_cert.get(), "127.0.0.1",
                                /*ocsp_response=*/std::string(),
                                /*sct_list=*/std::string(), flags,
                                &verify_result, NetLogWithSource());
EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, verify_result.cert_status);

base::RunLoop().RunUntilIdle();
EXPECT_EQ(0, observer_->client_cert_store_changes());
EXPECT_EQ(0, observer_->trust_store_changes());
}

TEST_F(CertDatabaseNSSTest, ImportServerCert_SelfSigned) {
ScopedCERTCertificateList certs;
ASSERT_TRUE(ReadCertIntoList("punycodetest.pem", &certs));

NSSCertDatabase::ImportCertFailureList failed;
EXPECT_TRUE(cert_db_->ImportServerCert(certs, NSSCertDatabase::TRUST_DEFAULT,
                                       &failed));

EXPECT_EQ(0U, failed.size());

ScopedCERTCertificateList cert_list = ListCerts();
ASSERT_EQ(1U, cert_list.size());
CERTCertificate* puny_cert = cert_list[0].get();

EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
          cert_db_->GetCertTrust(puny_cert, SERVER_CERT));
EXPECT_EQ(0U, puny_cert->trust->sslFlags);

scoped_refptr<X509Certificate> x509_puny_cert =
    x509_util::CreateX509CertificateFromCERTCertificate(puny_cert);
ASSERT_TRUE(x509_puny_cert);
scoped_refptr<CertVerifyProc> verify_proc(
    CertVerifyProc::CreateBuiltinWithChromeRootStore(
        /*cert_net_fetcher=*/nullptr, crl_set_,
        std::make_unique<DoNothingCTVerifier>(),
        base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
        /*root_store_data=*/nullptr,
        /*instance_params=*/{}, std::nullopt));
int flags = 0;
CertVerifyResult verify_result;
int error = verify_proc->Verify(x509_puny_cert.get(), "xn--wgv71a119e.com",
                                /*ocsp_response=*/std::string(),
                                /*sct_list=*/std::string(), flags,
                                &verify_result, NetLogWithSource());
EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, verify_result.cert_status);

base::RunLoop().RunUntilIdle();
EXPECT_EQ(0, observer_->client_cert_store_changes());
EXPECT_EQ(0, observer_->trust_store_changes());
}

TEST_F(CertDatabaseNSSTest, ImportServerCert_SelfSigned_Trusted) {
ScopedCERTCertificateList certs;
ASSERT_TRUE(ReadCertIntoList("punycodetest.pem", &certs));

NSSCertDatabase::ImportCertFailureList failed;
EXPECT_TRUE(cert_db_->ImportServerCert(certs, NSSCertDatabase::TRUSTED_SSL,
                                       &failed));

EXPECT_EQ(0U, failed.size());

ScopedCERTCertificateList cert_list = ListCerts();
ASSERT_EQ(1U, cert_list.size());
CERTCertificate* puny_cert = cert_list[0].get();

EXPECT_EQ(NSSCertDatabase::TRUSTED_SSL,
          cert_db_->GetCertTrust(puny_cert, SERVER_CERT));
EXPECT_EQ(unsigned(CERTDB_TRUSTED | CERTDB_TERMINAL_RECORD),
          puny_cert->trust->sslFlags);

scoped_refptr<X509Certificate> x509_puny_cert =
    x509_util::CreateX509CertificateFromCERTCertificate(puny_cert);
ASSERT_TRUE(x509_puny_cert);
scoped_refptr<CertVerifyProc> verify_proc(
    CertVerifyProc::CreateBuiltinWithChromeRootStore(
        /*cert_net_fetcher=*/nullptr, crl_set_,
        std::make_unique<DoNothingCTVerifier>(),
        base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
        /*root_store_data=*/nullptr,
        /*instance_params=*/{}, std::nullopt));
int flags = 0;
CertVerifyResult verify_result;
int error = verify_proc->Verify(x509_puny_cert.get(), "xn--wgv71a119e.com",
                                /*ocsp_response=*/std::string(),
                                /*sct_list=*/std::string(), flags,
                                &verify_result, NetLogWithSource());
EXPECT_THAT(error, IsOk());
EXPECT_EQ(0U, verify_result.cert_status);

base::RunLoop().RunUntilIdle();
EXPECT_EQ(0, observer_->client_cert_store_changes());
// TODO(mattm): this should be 1, but ImportServerCert doesn't currently
// generate notifications.
EXPECT_EQ(0, observer_->trust_store_changes());
}

TEST_F(CertDatabaseNSSTest, ImportCaAndServerCert) {
ScopedCERTCertificateList ca_certs = CreateCERTCertificateListFromFile(
    GetTestCertsDirectory(), "root_ca_cert.pem",
    X509Certificate::FORMAT_AUTO);
ASSERT_EQ(1U, ca_certs.size());

// Import CA cert and trust it.
NSSCertDatabase::ImportCertFailureList failed;
EXPECT_TRUE(cert_db_->ImportCACerts(ca_certs, NSSCertDatabase::TRUSTED_SSL,
                                    &failed));
EXPECT_EQ(0U, failed.size());

ScopedCERTCertificateList certs = CreateCERTCertificateListFromFile(
    GetTestCertsDirectory(), "ok_cert.pem", X509Certificate::FORMAT_AUTO);
ASSERT_EQ(1U, certs.size());

// Import server cert with default trust.
EXPECT_TRUE(cert_db_->ImportServerCert(certs, NSSCertDatabase::TRUST_DEFAULT,
                                       &failed));
EXPECT_EQ(0U, failed.size());

// Server cert should verify.
scoped_refptr<X509Certificate> x509_server_cert =
    x509_util::CreateX509CertificateFromCERTCertificate(certs[0].get());
ASSERT_TRUE(x509_server_cert);
scoped_refptr<CertVerifyProc> verify_proc(
    CertVerifyProc::CreateBuiltinWithChromeRootStore(
        /*cert_net_fetcher=*/nullptr, crl_set_,
        std::make_unique<DoNothingCTVerifier>(),
        base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
        /*root_store_data=*/nullptr,
        /*instance_params=*/{}, std::nullopt));
int flags = 0;
CertVerifyResult verify_result;
int error = verify_proc->Verify(x509_server_cert.get(), "127.0.0.1",
                                /*ocsp_response=*/std::string(),
                                /*sct_list=*/std::string(), flags,
                                &verify_result, NetLogWithSource());
EXPECT_THAT(error, IsOk());
EXPECT_EQ(0U, verify_result.cert_status);
}

TEST_F(CertDatabaseNSSTest, ImportCaAndServerCert_DistrustServer) {
ScopedCERTCertificateList ca_certs = CreateCERTCertificateListFromFile(
    GetTestCertsDirectory(), "root_ca_cert.pem",
    X509Certificate::FORMAT_AUTO);
ASSERT_EQ(1U, ca_certs.size());

// Import CA cert and trust it.
NSSCertDatabase::ImportCertFailureList failed;
EXPECT_TRUE(cert_db_->ImportCACerts(ca_certs, NSSCertDatabase::TRUSTED_SSL,
                                    &failed));
EXPECT_EQ(0U, failed.size());

ScopedCERTCertificateList certs = CreateCERTCertificateListFromFile(
    GetTestCertsDirectory(), "ok_cert.pem", X509Certificate::FORMAT_AUTO);
ASSERT_EQ(1U, certs.size());

// Import server cert without inheriting trust from issuer (explicit
// distrust).
EXPECT_TRUE(cert_db_->ImportServerCert(certs, NSSCertDatabase::DISTRUSTED_SSL,
                                       &failed));
EXPECT_EQ(0U, failed.size());
EXPECT_EQ(NSSCertDatabase::DISTRUSTED_SSL,
          cert_db_->GetCertTrust(certs[0].get(), SERVER_CERT));

EXPECT_EQ(unsigned(CERTDB_TERMINAL_RECORD), certs[0]->trust->sslFlags);

// Server cert should fail to verify.
scoped_refptr<X509Certificate> x509_server_cert =
    x509_util::CreateX509CertificateFromCERTCertificate(certs[0].get());
ASSERT_TRUE(x509_server_cert);
scoped_refptr<CertVerifyProc> verify_proc(
    CertVerifyProc::CreateBuiltinWithChromeRootStore(
        /*cert_net_fetcher=*/nullptr, crl_set_,
        std::make_unique<DoNothingCTVerifier>(),
        base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
        /*root_store_data=*/nullptr,
        /*instance_params=*/{}, std::nullopt));
int flags = 0;
CertVerifyResult verify_result;
int error = verify_proc->Verify(x509_server_cert.get(), "127.0.0.1",
                                /*ocsp_response=*/std::string(),
                                /*sct_list=*/std::string(), flags,
                                &verify_result, NetLogWithSource());
EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, verify_result.cert_status);
}

TEST_F(CertDatabaseNSSTest, TrustIntermediateCa) {
auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

ScopedCERTCertificateList ca_certs =
    x509_util::CreateCERTCertificateListFromX509Certificate(
        root->GetX509Certificate().get());
ASSERT_EQ(1U, ca_certs.size());

// Import Root CA cert and distrust it.
NSSCertDatabase::ImportCertFailureList failed;
EXPECT_TRUE(cert_db_->ImportCACerts(ca_certs, NSSCertDatabase::DISTRUSTED_SSL,
                                    &failed));
EXPECT_EQ(0U, failed.size());

base::RunLoop().RunUntilIdle();
EXPECT_EQ(0, observer_->client_cert_store_changes());
EXPECT_EQ(1, observer_->trust_store_changes());

ScopedCERTCertificateList intermediate_certs =
    x509_util::CreateCERTCertificateListFromX509Certificate(
        intermediate->GetX509Certificate().get());
ASSERT_EQ(1U, intermediate_certs.size());

// Import Intermediate CA cert and trust it.
EXPECT_TRUE(cert_db_->ImportCACerts(intermediate_certs,
                                    NSSCertDatabase::TRUSTED_SSL, &failed));
EXPECT_EQ(0U, failed.size());

base::RunLoop().RunUntilIdle();
EXPECT_EQ(0, observer_->client_cert_store_changes());
EXPECT_EQ(2, observer_->trust_store_changes());

scoped_refptr<X509Certificate> x509_server_cert = leaf->GetX509Certificate();
ScopedCERTCertificateList certs =
    x509_util::CreateCERTCertificateListFromX509Certificate(
        x509_server_cert.get());
ASSERT_EQ(1U, certs.size());

// Import server cert with default trust.
EXPECT_TRUE(cert_db_->ImportServerCert(certs, NSSCertDatabase::TRUST_DEFAULT,
                                       &failed));
EXPECT_EQ(0U, failed.size());
EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
          cert_db_->GetCertTrust(certs[0].get(), SERVER_CERT));

// Server cert should verify.
scoped_refptr<CertVerifyProc> verify_proc(
    CertVerifyProc::CreateBuiltinWithChromeRootStore(
        /*cert_net_fetcher=*/nullptr, crl_set_,
        std::make_unique<DoNothingCTVerifier>(),
        base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
        /*root_store_data=*/nullptr,
        /*instance_params=*/{}, std::nullopt));
int flags = 0;
CertVerifyResult verify_result;
int error = verify_proc->Verify(x509_server_cert.get(), "www.example.com",
                                /*ocsp_response=*/std::string(),
                                /*sct_list=*/std::string(), flags,
                                &verify_result, NetLogWithSource());
EXPECT_THAT(error, IsOk());
EXPECT_EQ(0U, verify_result.cert_status);

// Trust the root cert and distrust the intermediate.
EXPECT_TRUE(cert_db_->SetCertTrust(
    ca_certs[0].get(), CA_CERT, NSSCertDatabase::TRUSTED_SSL));
EXPECT_TRUE(cert_db_->SetCertTrust(
    intermediate_certs[0].get(), CA_CERT, NSSCertDatabase::DISTRUSTED_SSL));
EXPECT_EQ(
    unsigned(CERTDB_VALID_CA | CERTDB_TRUSTED_CA | CERTDB_TRUSTED_CLIENT_CA),
    ca_certs[0]->trust->sslFlags);
EXPECT_EQ(unsigned(CERTDB_VALID_CA), ca_certs[0]->trust->emailFlags);
EXPECT_EQ(unsigned(CERTDB_VALID_CA), ca_certs[0]->trust->objectSigningFlags);
EXPECT_EQ(unsigned(CERTDB_TERMINAL_RECORD),
          intermediate_certs[0]->trust->sslFlags);
EXPECT_EQ(unsigned(CERTDB_VALID_CA),
          intermediate_certs[0]->trust->emailFlags);
EXPECT_EQ(unsigned(CERTDB_VALID_CA),
          intermediate_certs[0]->trust->objectSigningFlags);

// Server cert should fail to verify.
CertVerifyResult verify_result2;
error = verify_proc->Verify(x509_server_cert.get(), "www.example.com",
                            /*ocsp_response=*/std::string(),
                            /*sct_list=*/std::string(), flags,
                            &verify_result2, NetLogWithSource());
EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, verify_result2.cert_status);
}

TEST_F(CertDatabaseNSSTest, TrustIntermediateCa2) {
NSSCertDatabase::ImportCertFailureList failed;
auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

ScopedCERTCertificateList intermediate_certs =
    x509_util::CreateCERTCertificateListFromX509Certificate(
        intermediate->GetX509Certificate().get());
ASSERT_EQ(1U, intermediate_certs.size());

// Import Intermediate CA cert and trust it.
EXPECT_TRUE(cert_db_->ImportCACerts(intermediate_certs,
                                    NSSCertDatabase::TRUSTED_SSL, &failed));
EXPECT_EQ(0U, failed.size());

scoped_refptr<X509Certificate> x509_server_cert = leaf->GetX509Certificate();
ScopedCERTCertificateList certs =
    x509_util::CreateCERTCertificateListFromX509Certificate(
        x509_server_cert.get());

// Import server cert with default trust.
EXPECT_TRUE(cert_db_->ImportServerCert(certs, NSSCertDatabase::TRUST_DEFAULT,
                                       &failed));
EXPECT_EQ(0U, failed.size());
EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
          cert_db_->GetCertTrust(certs[0].get(), SERVER_CERT));

// Server cert should verify.
scoped_refptr<CertVerifyProc> verify_proc(
    CertVerifyProc::CreateBuiltinWithChromeRootStore(
        /*cert_net_fetcher=*/nullptr, crl_set_,
        std::make_unique<DoNothingCTVerifier>(),
        base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
        /*root_store_data=*/nullptr,
        /*instance_params=*/{}, std::nullopt));
int flags = 0;
CertVerifyResult verify_result;
int error = verify_proc->Verify(x509_server_cert.get(), "www.example.com",
                                /*ocsp_response=*/std::string(),
                                /*sct_list=*/std::string(), flags,
                                &verify_result, NetLogWithSource());
EXPECT_THAT(error, IsOk());
EXPECT_EQ(0U, verify_result.cert_status);

// Without explicit trust of the intermediate, verification should fail.
EXPECT_TRUE(cert_db_->SetCertTrust(
    intermediate_certs[0].get(), CA_CERT, NSSCertDatabase::TRUST_DEFAULT));

// Server cert should fail to verify.
CertVerifyResult verify_result2;
error = verify_proc->Verify(x509_server_cert.get(), "www.example.com",
                            /*ocsp_response=*/std::string(),
                            /*sct_list=*/std::string(), flags,
                            &verify_result2, NetLogWithSource());
EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, verify_result2.cert_status);
}

TEST_F(CertDatabaseNSSTest, TrustIntermediateCa3) {
NSSCertDatabase::ImportCertFailureList failed;
auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

ScopedCERTCertificateList ca_certs =
    x509_util::CreateCERTCertificateListFromX509Certificate(
        root->GetX509Certificate().get());
ASSERT_EQ(1U, ca_certs.size());

// Import Root CA cert and default trust it.
EXPECT_TRUE(cert_db_->ImportCACerts(ca_certs, NSSCertDatabase::TRUST_DEFAULT,
                                    &failed));
EXPECT_EQ(0U, failed.size());

ScopedCERTCertificateList intermediate_certs =
    x509_util::CreateCERTCertificateListFromX509Certificate(
        intermediate->GetX509Certificate().get());
ASSERT_EQ(1U, intermediate_certs.size());

// Import Intermediate CA cert and trust it.
EXPECT_TRUE(cert_db_->ImportCACerts(intermediate_certs,
                                    NSSCertDatabase::TRUSTED_SSL, &failed));
EXPECT_EQ(0U, failed.size());

scoped_refptr<X509Certificate> x509_server_cert = leaf->GetX509Certificate();
ScopedCERTCertificateList certs =
    x509_util::CreateCERTCertificateListFromX509Certificate(
        x509_server_cert.get());
ASSERT_EQ(1U, certs.size());

// Import server cert with default trust.
EXPECT_TRUE(cert_db_->ImportServerCert(certs, NSSCertDatabase::TRUST_DEFAULT,
                                       &failed));
EXPECT_EQ(0U, failed.size());
EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
          cert_db_->GetCertTrust(certs[0].get(), SERVER_CERT));

// Server cert should verify.
scoped_refptr<CertVerifyProc> verify_proc(
    CertVerifyProc::CreateBuiltinWithChromeRootStore(
        /*cert_net_fetcher=*/nullptr, crl_set_,
        std::make_unique<DoNothingCTVerifier>(),
        base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
        /*root_store_data=*/nullptr,
        /*instance_params=*/{}, std::nullopt));
int flags = 0;
CertVerifyResult verify_result;
int error = verify_proc->Verify(x509_server_cert.get(), "www.example.com",
                                /*ocsp_response=*/std::string(),
                                /*sct_list=*/std::string(), flags,
                                &verify_result, NetLogWithSource());
EXPECT_THAT(error, IsOk());
EXPECT_EQ(0U, verify_result.cert_status);

// Without explicit trust of the intermediate, verification should fail.
EXPECT_TRUE(cert_db_->SetCertTrust(
    intermediate_certs[0].get(), CA_CERT, NSSCertDatabase::TRUST_DEFAULT));

// Server cert should fail to verify.
CertVerifyResult verify_result2;
error = verify_proc->Verify(x509_server_cert.get(), "www.example.com",
                            /*ocsp_response=*/std::string(),
                            /*sct_list=*/std::string(), flags,
                            &verify_result2, NetLogWithSource());
EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, verify_result2.cert_status);
}

TEST_F(CertDatabaseNSSTest, TrustIntermediateCa4) {
NSSCertDatabase::ImportCertFailureList failed;
auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

ScopedCERTCertificateList ca_certs =
    x509_util::CreateCERTCertificateListFromX509Certificate(
        root->GetX509Certificate().get());
ASSERT_EQ(1U, ca_certs.size());

// Import Root CA cert and trust it.
EXPECT_TRUE(cert_db_->ImportCACerts(ca_certs, NSSCertDatabase::TRUSTED_SSL,
                                    &failed));
EXPECT_EQ(0U, failed.size());

ScopedCERTCertificateList intermediate_certs =
    x509_util::CreateCERTCertificateListFromX509Certificate(
        intermediate->GetX509Certificate().get());
ASSERT_EQ(1U, intermediate_certs.size());

// Import Intermediate CA cert and distrust it.
EXPECT_TRUE(cert_db_->ImportCACerts(
    intermediate_certs, NSSCertDatabase::DISTRUSTED_SSL, &failed));
EXPECT_EQ(0U, failed.size());

scoped_refptr<X509Certificate> x509_server_cert = leaf->GetX509Certificate();
ScopedCERTCertificateList certs =
    x509_util::CreateCERTCertificateListFromX509Certificate(
        x509_server_cert.get());
ASSERT_EQ(1U, certs.size());

// Import server cert with default trust.
EXPECT_TRUE(cert_db_->ImportServerCert(certs, NSSCertDatabase::TRUST_DEFAULT,
                                       &failed));
EXPECT_EQ(0U, failed.size());
EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
          cert_db_->GetCertTrust(certs[0].get(), SERVER_CERT));

// Server cert should not verify.
scoped_refptr<CertVerifyProc> verify_proc(
    CertVerifyProc::CreateBuiltinWithChromeRootStore(
        /*cert_net_fetcher=*/nullptr, crl_set_,
        std::make_unique<DoNothingCTVerifier>(),
        base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
        /*root_store_data=*/nullptr,
        /*instance_params=*/{}, std::nullopt));
int flags = 0;
CertVerifyResult verify_result;
int error = verify_proc->Verify(x509_server_cert.get(), "www.example.com",
                                /*ocsp_response=*/std::string(),
                                /*sct_list=*/std::string(), flags,
                                &verify_result, NetLogWithSource());
EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, verify_result.cert_status);

// Without explicit distrust of the intermediate, verification should succeed.
EXPECT_TRUE(cert_db_->SetCertTrust(
    intermediate_certs[0].get(), CA_CERT, NSSCertDatabase::TRUST_DEFAULT));

// Server cert should verify.
CertVerifyResult verify_result2;
error = verify_proc->Verify(x509_server_cert.get(), "www.example.com",
                            /*ocsp_response=*/std::string(),
                            /*sct_list=*/std::string(), flags,
                            &verify_result2, NetLogWithSource());
EXPECT_THAT(error, IsOk());
EXPECT_EQ(0U, verify_result2.cert_status);
}

// Importing two certificates with the same issuer and subject common name,
// but overall distinct subject names, should succeed and generate a unique
// nickname for the second certificate.
TEST_F(CertDatabaseNSSTest, ImportDuplicateCommonName) {
ScopedCERTCertificateList certs = CreateCERTCertificateListFromFile(
    GetTestCertsDirectory(), "duplicate_cn_1.pem",
    X509Certificate::FORMAT_AUTO);
ASSERT_EQ(1U, certs.size());

EXPECT_EQ(0U, ListCerts().size());

// Import server cert with default trust.
NSSCertDatabase::ImportCertFailureList failed;
EXPECT_TRUE(cert_db_->ImportServerCert(certs, NSSCertDatabase::TRUST_DEFAULT,
                                       &failed));
EXPECT_EQ(0U, failed.size());
EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
          cert_db_->GetCertTrust(certs[0].get(), SERVER_CERT));

ScopedCERTCertificateList new_certs = ListCerts();
ASSERT_EQ(1U, new_certs.size());

// Now attempt to import a different certificate with the same common name.
ScopedCERTCertificateList certs2 = CreateCERTCertificateListFromFile(
    GetTestCertsDirectory(), "duplicate_cn_2.pem",
    X509Certificate::FORMAT_AUTO);
ASSERT_EQ(1U, certs2.size());

// Import server cert with default trust.
EXPECT_TRUE(cert_db_->ImportServerCert(certs2, NSSCertDatabase::TRUST_DEFAULT,
                                       &failed));
EXPECT_EQ(0U, failed.size());
EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
          cert_db_->GetCertTrust(certs2[0].get(), SERVER_CERT));

new_certs = ListCerts();
ASSERT_EQ(2U, new_certs.size());
EXPECT_STRNE(new_certs[0]->nickname, new_certs[1]->nickname);
}

}  // namespace net
```

## 功能归纳

这部分代码主要包含针对 `NSSCertDatabase` 类的单元测试，专注于 **证书导入和信任管理** 的功能。具体来说，它测试了以下场景：

1. **导入服务器证书：**
   - 导入不被信任的颁发者签名的服务器证书，验证其无法通过校验。
   - 导入自签名服务器证书，默认不信任，验证其无法通过校验。
   - 导入自签名服务器证书并显式信任，验证其可以通过校验。
2. **导入CA证书：**
   - 导入CA证书但不信任，后续导入由该CA签名的服务器证书时，验证服务器证书无法通过校验。
   - 导入CA证书并信任，后续导入由该CA签名的服务器证书时，验证服务器证书可以通过校验。
3. **证书信任和不信任的组合：**
   - 先信任根CA，然后导入由该根CA签名的服务器证书，但显式不信任该服务器证书，验证服务器证书无法通过校验。
4. **中间CA证书的信任管理：**
   - 测试在存在证书链的情况下，对中间CA证书进行信任和不信任操作，以及这些操作如何影响最终服务器证书的校验结果。涵盖了以下情况：
     - 不信任根CA，信任中间CA，验证服务器证书可以信任。
     - 信任根CA，不信任中间CA，验证服务器证书无法信任。
     - 仅信任中间CA，验证服务器证书可以信任。
     - 默认信任根CA，信任中间CA，然后将中间CA设置为默认信任，验证服务器证书仍然无法信任。
     - 信任根CA，不信任中间CA，然后将中间CA设置为默认信任，验证
### 提示词
```
这是目录为net/cert/nss_cert_database_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
he intermediate & CA certs are imported without
  // trust.
  scoped_refptr<X509Certificate> x509_found_server_cert =
      x509_util::CreateX509CertificateFromCERTCertificate(found_server_cert);
  ASSERT_TRUE(x509_found_server_cert);
  scoped_refptr<CertVerifyProc> verify_proc(
      CertVerifyProc::CreateBuiltinWithChromeRootStore(
          /*cert_net_fetcher=*/nullptr, crl_set_,
          std::make_unique<DoNothingCTVerifier>(),
          base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
          /*root_store_data=*/nullptr,
          /*instance_params=*/{}, std::nullopt));
  int flags = 0;
  CertVerifyResult verify_result;
  int error = verify_proc->Verify(x509_found_server_cert.get(), "127.0.0.1",
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string(), flags,
                                  &verify_result, NetLogWithSource());
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, verify_result.cert_status);

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, observer_->client_cert_store_changes());
  EXPECT_EQ(0, observer_->trust_store_changes());
}

TEST_F(CertDatabaseNSSTest, ImportServerCert_SelfSigned) {
  ScopedCERTCertificateList certs;
  ASSERT_TRUE(ReadCertIntoList("punycodetest.pem", &certs));

  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportServerCert(certs, NSSCertDatabase::TRUST_DEFAULT,
                                         &failed));

  EXPECT_EQ(0U, failed.size());

  ScopedCERTCertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  CERTCertificate* puny_cert = cert_list[0].get();

  EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
            cert_db_->GetCertTrust(puny_cert, SERVER_CERT));
  EXPECT_EQ(0U, puny_cert->trust->sslFlags);

  scoped_refptr<X509Certificate> x509_puny_cert =
      x509_util::CreateX509CertificateFromCERTCertificate(puny_cert);
  ASSERT_TRUE(x509_puny_cert);
  scoped_refptr<CertVerifyProc> verify_proc(
      CertVerifyProc::CreateBuiltinWithChromeRootStore(
          /*cert_net_fetcher=*/nullptr, crl_set_,
          std::make_unique<DoNothingCTVerifier>(),
          base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
          /*root_store_data=*/nullptr,
          /*instance_params=*/{}, std::nullopt));
  int flags = 0;
  CertVerifyResult verify_result;
  int error = verify_proc->Verify(x509_puny_cert.get(), "xn--wgv71a119e.com",
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string(), flags,
                                  &verify_result, NetLogWithSource());
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, verify_result.cert_status);

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, observer_->client_cert_store_changes());
  EXPECT_EQ(0, observer_->trust_store_changes());
}

TEST_F(CertDatabaseNSSTest, ImportServerCert_SelfSigned_Trusted) {
  ScopedCERTCertificateList certs;
  ASSERT_TRUE(ReadCertIntoList("punycodetest.pem", &certs));

  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportServerCert(certs, NSSCertDatabase::TRUSTED_SSL,
                                         &failed));

  EXPECT_EQ(0U, failed.size());

  ScopedCERTCertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  CERTCertificate* puny_cert = cert_list[0].get();

  EXPECT_EQ(NSSCertDatabase::TRUSTED_SSL,
            cert_db_->GetCertTrust(puny_cert, SERVER_CERT));
  EXPECT_EQ(unsigned(CERTDB_TRUSTED | CERTDB_TERMINAL_RECORD),
            puny_cert->trust->sslFlags);

  scoped_refptr<X509Certificate> x509_puny_cert =
      x509_util::CreateX509CertificateFromCERTCertificate(puny_cert);
  ASSERT_TRUE(x509_puny_cert);
  scoped_refptr<CertVerifyProc> verify_proc(
      CertVerifyProc::CreateBuiltinWithChromeRootStore(
          /*cert_net_fetcher=*/nullptr, crl_set_,
          std::make_unique<DoNothingCTVerifier>(),
          base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
          /*root_store_data=*/nullptr,
          /*instance_params=*/{}, std::nullopt));
  int flags = 0;
  CertVerifyResult verify_result;
  int error = verify_proc->Verify(x509_puny_cert.get(), "xn--wgv71a119e.com",
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string(), flags,
                                  &verify_result, NetLogWithSource());
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, observer_->client_cert_store_changes());
  // TODO(mattm): this should be 1, but ImportServerCert doesn't currently
  // generate notifications.
  EXPECT_EQ(0, observer_->trust_store_changes());
}

TEST_F(CertDatabaseNSSTest, ImportCaAndServerCert) {
  ScopedCERTCertificateList ca_certs = CreateCERTCertificateListFromFile(
      GetTestCertsDirectory(), "root_ca_cert.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, ca_certs.size());

  // Import CA cert and trust it.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(ca_certs, NSSCertDatabase::TRUSTED_SSL,
                                      &failed));
  EXPECT_EQ(0U, failed.size());

  ScopedCERTCertificateList certs = CreateCERTCertificateListFromFile(
      GetTestCertsDirectory(), "ok_cert.pem", X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());

  // Import server cert with default trust.
  EXPECT_TRUE(cert_db_->ImportServerCert(certs, NSSCertDatabase::TRUST_DEFAULT,
                                         &failed));
  EXPECT_EQ(0U, failed.size());

  // Server cert should verify.
  scoped_refptr<X509Certificate> x509_server_cert =
      x509_util::CreateX509CertificateFromCERTCertificate(certs[0].get());
  ASSERT_TRUE(x509_server_cert);
  scoped_refptr<CertVerifyProc> verify_proc(
      CertVerifyProc::CreateBuiltinWithChromeRootStore(
          /*cert_net_fetcher=*/nullptr, crl_set_,
          std::make_unique<DoNothingCTVerifier>(),
          base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
          /*root_store_data=*/nullptr,
          /*instance_params=*/{}, std::nullopt));
  int flags = 0;
  CertVerifyResult verify_result;
  int error = verify_proc->Verify(x509_server_cert.get(), "127.0.0.1",
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string(), flags,
                                  &verify_result, NetLogWithSource());
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);
}

TEST_F(CertDatabaseNSSTest, ImportCaAndServerCert_DistrustServer) {
  ScopedCERTCertificateList ca_certs = CreateCERTCertificateListFromFile(
      GetTestCertsDirectory(), "root_ca_cert.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, ca_certs.size());

  // Import CA cert and trust it.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(ca_certs, NSSCertDatabase::TRUSTED_SSL,
                                      &failed));
  EXPECT_EQ(0U, failed.size());

  ScopedCERTCertificateList certs = CreateCERTCertificateListFromFile(
      GetTestCertsDirectory(), "ok_cert.pem", X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());

  // Import server cert without inheriting trust from issuer (explicit
  // distrust).
  EXPECT_TRUE(cert_db_->ImportServerCert(certs, NSSCertDatabase::DISTRUSTED_SSL,
                                         &failed));
  EXPECT_EQ(0U, failed.size());
  EXPECT_EQ(NSSCertDatabase::DISTRUSTED_SSL,
            cert_db_->GetCertTrust(certs[0].get(), SERVER_CERT));

  EXPECT_EQ(unsigned(CERTDB_TERMINAL_RECORD), certs[0]->trust->sslFlags);

  // Server cert should fail to verify.
  scoped_refptr<X509Certificate> x509_server_cert =
      x509_util::CreateX509CertificateFromCERTCertificate(certs[0].get());
  ASSERT_TRUE(x509_server_cert);
  scoped_refptr<CertVerifyProc> verify_proc(
      CertVerifyProc::CreateBuiltinWithChromeRootStore(
          /*cert_net_fetcher=*/nullptr, crl_set_,
          std::make_unique<DoNothingCTVerifier>(),
          base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
          /*root_store_data=*/nullptr,
          /*instance_params=*/{}, std::nullopt));
  int flags = 0;
  CertVerifyResult verify_result;
  int error = verify_proc->Verify(x509_server_cert.get(), "127.0.0.1",
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string(), flags,
                                  &verify_result, NetLogWithSource());
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, verify_result.cert_status);
}

TEST_F(CertDatabaseNSSTest, TrustIntermediateCa) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  ScopedCERTCertificateList ca_certs =
      x509_util::CreateCERTCertificateListFromX509Certificate(
          root->GetX509Certificate().get());
  ASSERT_EQ(1U, ca_certs.size());

  // Import Root CA cert and distrust it.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(ca_certs, NSSCertDatabase::DISTRUSTED_SSL,
                                      &failed));
  EXPECT_EQ(0U, failed.size());

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, observer_->client_cert_store_changes());
  EXPECT_EQ(1, observer_->trust_store_changes());

  ScopedCERTCertificateList intermediate_certs =
      x509_util::CreateCERTCertificateListFromX509Certificate(
          intermediate->GetX509Certificate().get());
  ASSERT_EQ(1U, intermediate_certs.size());

  // Import Intermediate CA cert and trust it.
  EXPECT_TRUE(cert_db_->ImportCACerts(intermediate_certs,
                                      NSSCertDatabase::TRUSTED_SSL, &failed));
  EXPECT_EQ(0U, failed.size());

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, observer_->client_cert_store_changes());
  EXPECT_EQ(2, observer_->trust_store_changes());

  scoped_refptr<X509Certificate> x509_server_cert = leaf->GetX509Certificate();
  ScopedCERTCertificateList certs =
      x509_util::CreateCERTCertificateListFromX509Certificate(
          x509_server_cert.get());
  ASSERT_EQ(1U, certs.size());

  // Import server cert with default trust.
  EXPECT_TRUE(cert_db_->ImportServerCert(certs, NSSCertDatabase::TRUST_DEFAULT,
                                         &failed));
  EXPECT_EQ(0U, failed.size());
  EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
            cert_db_->GetCertTrust(certs[0].get(), SERVER_CERT));

  // Server cert should verify.
  scoped_refptr<CertVerifyProc> verify_proc(
      CertVerifyProc::CreateBuiltinWithChromeRootStore(
          /*cert_net_fetcher=*/nullptr, crl_set_,
          std::make_unique<DoNothingCTVerifier>(),
          base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
          /*root_store_data=*/nullptr,
          /*instance_params=*/{}, std::nullopt));
  int flags = 0;
  CertVerifyResult verify_result;
  int error = verify_proc->Verify(x509_server_cert.get(), "www.example.com",
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string(), flags,
                                  &verify_result, NetLogWithSource());
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);

  // Trust the root cert and distrust the intermediate.
  EXPECT_TRUE(cert_db_->SetCertTrust(
      ca_certs[0].get(), CA_CERT, NSSCertDatabase::TRUSTED_SSL));
  EXPECT_TRUE(cert_db_->SetCertTrust(
      intermediate_certs[0].get(), CA_CERT, NSSCertDatabase::DISTRUSTED_SSL));
  EXPECT_EQ(
      unsigned(CERTDB_VALID_CA | CERTDB_TRUSTED_CA | CERTDB_TRUSTED_CLIENT_CA),
      ca_certs[0]->trust->sslFlags);
  EXPECT_EQ(unsigned(CERTDB_VALID_CA), ca_certs[0]->trust->emailFlags);
  EXPECT_EQ(unsigned(CERTDB_VALID_CA), ca_certs[0]->trust->objectSigningFlags);
  EXPECT_EQ(unsigned(CERTDB_TERMINAL_RECORD),
            intermediate_certs[0]->trust->sslFlags);
  EXPECT_EQ(unsigned(CERTDB_VALID_CA),
            intermediate_certs[0]->trust->emailFlags);
  EXPECT_EQ(unsigned(CERTDB_VALID_CA),
            intermediate_certs[0]->trust->objectSigningFlags);

  // Server cert should fail to verify.
  CertVerifyResult verify_result2;
  error = verify_proc->Verify(x509_server_cert.get(), "www.example.com",
                              /*ocsp_response=*/std::string(),
                              /*sct_list=*/std::string(), flags,
                              &verify_result2, NetLogWithSource());
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, verify_result2.cert_status);
}

TEST_F(CertDatabaseNSSTest, TrustIntermediateCa2) {
  NSSCertDatabase::ImportCertFailureList failed;
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  ScopedCERTCertificateList intermediate_certs =
      x509_util::CreateCERTCertificateListFromX509Certificate(
          intermediate->GetX509Certificate().get());
  ASSERT_EQ(1U, intermediate_certs.size());

  // Import Intermediate CA cert and trust it.
  EXPECT_TRUE(cert_db_->ImportCACerts(intermediate_certs,
                                      NSSCertDatabase::TRUSTED_SSL, &failed));
  EXPECT_EQ(0U, failed.size());

  scoped_refptr<X509Certificate> x509_server_cert = leaf->GetX509Certificate();
  ScopedCERTCertificateList certs =
      x509_util::CreateCERTCertificateListFromX509Certificate(
          x509_server_cert.get());

  // Import server cert with default trust.
  EXPECT_TRUE(cert_db_->ImportServerCert(certs, NSSCertDatabase::TRUST_DEFAULT,
                                         &failed));
  EXPECT_EQ(0U, failed.size());
  EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
            cert_db_->GetCertTrust(certs[0].get(), SERVER_CERT));

  // Server cert should verify.
  scoped_refptr<CertVerifyProc> verify_proc(
      CertVerifyProc::CreateBuiltinWithChromeRootStore(
          /*cert_net_fetcher=*/nullptr, crl_set_,
          std::make_unique<DoNothingCTVerifier>(),
          base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
          /*root_store_data=*/nullptr,
          /*instance_params=*/{}, std::nullopt));
  int flags = 0;
  CertVerifyResult verify_result;
  int error = verify_proc->Verify(x509_server_cert.get(), "www.example.com",
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string(), flags,
                                  &verify_result, NetLogWithSource());
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);

  // Without explicit trust of the intermediate, verification should fail.
  EXPECT_TRUE(cert_db_->SetCertTrust(
      intermediate_certs[0].get(), CA_CERT, NSSCertDatabase::TRUST_DEFAULT));

  // Server cert should fail to verify.
  CertVerifyResult verify_result2;
  error = verify_proc->Verify(x509_server_cert.get(), "www.example.com",
                              /*ocsp_response=*/std::string(),
                              /*sct_list=*/std::string(), flags,
                              &verify_result2, NetLogWithSource());
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, verify_result2.cert_status);
}

TEST_F(CertDatabaseNSSTest, TrustIntermediateCa3) {
  NSSCertDatabase::ImportCertFailureList failed;
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  ScopedCERTCertificateList ca_certs =
      x509_util::CreateCERTCertificateListFromX509Certificate(
          root->GetX509Certificate().get());
  ASSERT_EQ(1U, ca_certs.size());

  // Import Root CA cert and default trust it.
  EXPECT_TRUE(cert_db_->ImportCACerts(ca_certs, NSSCertDatabase::TRUST_DEFAULT,
                                      &failed));
  EXPECT_EQ(0U, failed.size());

  ScopedCERTCertificateList intermediate_certs =
      x509_util::CreateCERTCertificateListFromX509Certificate(
          intermediate->GetX509Certificate().get());
  ASSERT_EQ(1U, intermediate_certs.size());

  // Import Intermediate CA cert and trust it.
  EXPECT_TRUE(cert_db_->ImportCACerts(intermediate_certs,
                                      NSSCertDatabase::TRUSTED_SSL, &failed));
  EXPECT_EQ(0U, failed.size());

  scoped_refptr<X509Certificate> x509_server_cert = leaf->GetX509Certificate();
  ScopedCERTCertificateList certs =
      x509_util::CreateCERTCertificateListFromX509Certificate(
          x509_server_cert.get());
  ASSERT_EQ(1U, certs.size());

  // Import server cert with default trust.
  EXPECT_TRUE(cert_db_->ImportServerCert(certs, NSSCertDatabase::TRUST_DEFAULT,
                                         &failed));
  EXPECT_EQ(0U, failed.size());
  EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
            cert_db_->GetCertTrust(certs[0].get(), SERVER_CERT));

  // Server cert should verify.
  scoped_refptr<CertVerifyProc> verify_proc(
      CertVerifyProc::CreateBuiltinWithChromeRootStore(
          /*cert_net_fetcher=*/nullptr, crl_set_,
          std::make_unique<DoNothingCTVerifier>(),
          base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
          /*root_store_data=*/nullptr,
          /*instance_params=*/{}, std::nullopt));
  int flags = 0;
  CertVerifyResult verify_result;
  int error = verify_proc->Verify(x509_server_cert.get(), "www.example.com",
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string(), flags,
                                  &verify_result, NetLogWithSource());
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);

  // Without explicit trust of the intermediate, verification should fail.
  EXPECT_TRUE(cert_db_->SetCertTrust(
      intermediate_certs[0].get(), CA_CERT, NSSCertDatabase::TRUST_DEFAULT));

  // Server cert should fail to verify.
  CertVerifyResult verify_result2;
  error = verify_proc->Verify(x509_server_cert.get(), "www.example.com",
                              /*ocsp_response=*/std::string(),
                              /*sct_list=*/std::string(), flags,
                              &verify_result2, NetLogWithSource());
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, verify_result2.cert_status);
}

TEST_F(CertDatabaseNSSTest, TrustIntermediateCa4) {
  NSSCertDatabase::ImportCertFailureList failed;
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  ScopedCERTCertificateList ca_certs =
      x509_util::CreateCERTCertificateListFromX509Certificate(
          root->GetX509Certificate().get());
  ASSERT_EQ(1U, ca_certs.size());

  // Import Root CA cert and trust it.
  EXPECT_TRUE(cert_db_->ImportCACerts(ca_certs, NSSCertDatabase::TRUSTED_SSL,
                                      &failed));
  EXPECT_EQ(0U, failed.size());

  ScopedCERTCertificateList intermediate_certs =
      x509_util::CreateCERTCertificateListFromX509Certificate(
          intermediate->GetX509Certificate().get());
  ASSERT_EQ(1U, intermediate_certs.size());

  // Import Intermediate CA cert and distrust it.
  EXPECT_TRUE(cert_db_->ImportCACerts(
      intermediate_certs, NSSCertDatabase::DISTRUSTED_SSL, &failed));
  EXPECT_EQ(0U, failed.size());

  scoped_refptr<X509Certificate> x509_server_cert = leaf->GetX509Certificate();
  ScopedCERTCertificateList certs =
      x509_util::CreateCERTCertificateListFromX509Certificate(
          x509_server_cert.get());
  ASSERT_EQ(1U, certs.size());

  // Import server cert with default trust.
  EXPECT_TRUE(cert_db_->ImportServerCert(certs, NSSCertDatabase::TRUST_DEFAULT,
                                         &failed));
  EXPECT_EQ(0U, failed.size());
  EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
            cert_db_->GetCertTrust(certs[0].get(), SERVER_CERT));

  // Server cert should not verify.
  scoped_refptr<CertVerifyProc> verify_proc(
      CertVerifyProc::CreateBuiltinWithChromeRootStore(
          /*cert_net_fetcher=*/nullptr, crl_set_,
          std::make_unique<DoNothingCTVerifier>(),
          base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
          /*root_store_data=*/nullptr,
          /*instance_params=*/{}, std::nullopt));
  int flags = 0;
  CertVerifyResult verify_result;
  int error = verify_proc->Verify(x509_server_cert.get(), "www.example.com",
                                  /*ocsp_response=*/std::string(),
                                  /*sct_list=*/std::string(), flags,
                                  &verify_result, NetLogWithSource());
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, verify_result.cert_status);

  // Without explicit distrust of the intermediate, verification should succeed.
  EXPECT_TRUE(cert_db_->SetCertTrust(
      intermediate_certs[0].get(), CA_CERT, NSSCertDatabase::TRUST_DEFAULT));

  // Server cert should verify.
  CertVerifyResult verify_result2;
  error = verify_proc->Verify(x509_server_cert.get(), "www.example.com",
                              /*ocsp_response=*/std::string(),
                              /*sct_list=*/std::string(), flags,
                              &verify_result2, NetLogWithSource());
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result2.cert_status);
}

// Importing two certificates with the same issuer and subject common name,
// but overall distinct subject names, should succeed and generate a unique
// nickname for the second certificate.
TEST_F(CertDatabaseNSSTest, ImportDuplicateCommonName) {
  ScopedCERTCertificateList certs = CreateCERTCertificateListFromFile(
      GetTestCertsDirectory(), "duplicate_cn_1.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());

  EXPECT_EQ(0U, ListCerts().size());

  // Import server cert with default trust.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportServerCert(certs, NSSCertDatabase::TRUST_DEFAULT,
                                         &failed));
  EXPECT_EQ(0U, failed.size());
  EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
            cert_db_->GetCertTrust(certs[0].get(), SERVER_CERT));

  ScopedCERTCertificateList new_certs = ListCerts();
  ASSERT_EQ(1U, new_certs.size());

  // Now attempt to import a different certificate with the same common name.
  ScopedCERTCertificateList certs2 = CreateCERTCertificateListFromFile(
      GetTestCertsDirectory(), "duplicate_cn_2.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs2.size());

  // Import server cert with default trust.
  EXPECT_TRUE(cert_db_->ImportServerCert(certs2, NSSCertDatabase::TRUST_DEFAULT,
                                         &failed));
  EXPECT_EQ(0U, failed.size());
  EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
            cert_db_->GetCertTrust(certs2[0].get(), SERVER_CERT));

  new_certs = ListCerts();
  ASSERT_EQ(2U, new_certs.size());
  EXPECT_STRNE(new_certs[0]->nickname, new_certs[1]->nickname);
}

}  // namespace net
```