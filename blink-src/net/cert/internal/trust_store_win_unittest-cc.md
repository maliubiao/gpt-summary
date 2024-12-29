Response:
Let's break down the thought process for analyzing this C++ unittest file and generating the explanation.

1. **Identify the Core Purpose:** The filename `trust_store_win_unittest.cc` immediately suggests this code tests the `TrustStoreWin` class. The `unittest` suffix confirms it's a unit test. The `win` part indicates it's specific to Windows.

2. **Understand the Tested Class:**  Scan the includes. `#include "net/cert/internal/trust_store_win.h"` is the key. This tells us the file tests the `TrustStoreWin` class, likely responsible for managing certificate trust on Windows.

3. **Analyze the Test Structure:** Look for standard testing patterns. The presence of `#include "testing/gmock/include/gmock/gmock.h"` and `#include "testing/gtest/include/gtest/gtest.h"` strongly indicates Google Test is being used. The `TEST_F` macros are the entry points for individual test cases within the `TrustStoreWinTest` fixture.

4. **Examine the Test Fixture (`TrustStoreWinTest`):**
    * `SetUp()`: This method initializes test data. It parses certificate files (`.pem`) using `ParseCertFromFile` and stores them in member variables (`a_by_b_`, `b_by_c_`, etc.). This tells us the tests will be working with a set of predefined certificates.
    * Helper Functions:  Functions like `ExpectedTrustForAnchor`, `ExpectedTrustForPeer`, `AddToStore`, `AddToStoreWithEKURestriction`, and `CreateTrustStoreWin` provide utilities for setting up the test environment and assertions. Pay attention to what these functions do. `AddToStore` adds certificates to Windows certificate stores. `AddToStoreWithEKURestriction` does the same but also sets Enhanced Key Usage (EKU) restrictions. `CreateTrustStoreWin` instantiates the class being tested.
    * `stores_`: This member variable of type `TrustStoreWin::CertStores` holds the in-memory certificate stores used for testing. The comment explains they are nullified after `CreateTrustStoreWin()` is called. This is a crucial detail for understanding how tests isolate their environments.

5. **Analyze Individual Test Cases:** Go through each `TEST_F` function:
    * **Focus on the Test Name:**  The name usually clearly describes what's being tested (e.g., `GetTrustInitializationError`, `GetTrust`, `GetTrustRestrictedEKU`, `GetIssuers`, `GetAllUserAddedCerts`).
    * **Understand the Setup:** How is the `TrustStoreWin` instance being created? Are certificates being added? Are EKU restrictions being set?
    * **Identify the Action:** What method of `TrustStoreWin` is being called (e.g., `GetTrust`, `SyncGetIssuersOf`, `GetAllUserAddedCerts`)?
    * **Examine the Assertions:** What are the `EXPECT_EQ`, `ASSERT_EQ`, `EXPECT_THAT` calls checking?  These are the core verifications of the test. Pay attention to the expected values. For example, in `GetTrust`, it checks the `CertificateTrust` returned by `GetTrust` against expected values like `ExpectedTrustForAnchor` and `ExpectedTrustForPeer`.
    * **Look for Edge Cases/Specific Scenarios:**  Tests like `GetTrustRestrictedEKU` and `GetTrustDisallowedCerts` target specific scenarios related to EKU restrictions and disallowed certificates.

6. **Relate to Javascript (or Lack Thereof):**  Actively consider if any part of the code directly interacts with Javascript. In this case, the code is deeply embedded in the Chromium network stack and deals with low-level certificate management on Windows. There's no direct Javascript interaction. However, it's important to explain *why* there isn't a direct relationship, pointing out that this code is part of the *browser's* implementation, which handles certificate validation when a Javascript application makes network requests.

7. **Consider Logic and I/O:** For tests involving logic (like `GetTrust`), think about the inputs (the certificate being checked) and the expected output (the `CertificateTrust`). If a test involves setting up certificate stores, consider that as input as well.

8. **Identify Potential User Errors:** Think about how a user's actions (like installing a certificate) or a developer's configuration errors could lead to the behavior being tested. For example, installing an untrusted root certificate or a certificate with incorrect EKU settings are relevant scenarios.

9. **Trace User Actions (Debugging):** Think about the steps a user would take in a browser that would eventually trigger this code. Accessing a website over HTTPS is the most obvious scenario. Consider the path from typing a URL to the browser validating the server's certificate.

10. **Synthesize and Organize:**  Structure the explanation clearly, addressing each part of the prompt:
    * Functionality of the file.
    * Relationship to Javascript (and why/how).
    * Logical reasoning with examples.
    * Common user/programming errors.
    * User actions as debugging clues.

**Self-Correction/Refinement During Analysis:**

* **Initial Thought:** "This looks like it directly interacts with Javascript's `crypto` API."
* **Correction:**  After analyzing the includes and the class being tested, realize this is a lower-level component within the browser itself. Javascript interacts with certificates at a higher level. The `TrustStoreWin` is part of the underlying implementation that *supports* those higher-level APIs.

* **Initial Thought:** "The input is just a certificate."
* **Refinement:**  Recognize that the *setup* of the test (adding certificates to specific stores, setting EKU restrictions) is also part of the input that influences the output.

By following these steps, you can effectively analyze the provided C++ unittest file and generate a comprehensive explanation addressing all aspects of the prompt.
This C++ source code file, `trust_store_win_unittest.cc`, is a **unit test file** for the `TrustStoreWin` class in the Chromium network stack. The `TrustStoreWin` class is responsible for managing and querying the **system's certificate trust store on Windows**. This involves determining whether a given X.509 certificate is trusted as a root CA (Certificate Authority) or a trusted peer.

Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Testing `TrustStoreWin`'s ability to retrieve trust information for certificates on Windows.** This includes:
    * Checking if a certificate is a trusted root CA.
    * Checking if a certificate is a trusted peer (e.g., a user-installed certificate).
    * Checking if a certificate is explicitly distrusted.
    * Handling cases where trust information is not available.
    * Testing the behavior when the `TrustStoreWin` encounters initialization errors (e.g., accessing null certificate stores).

2. **Testing the influence of Enhanced Key Usage (EKU) restrictions on trust determination.**  Windows allows certificates to be marked with specific purposes (e.g., server authentication, client authentication). The tests verify that `TrustStoreWin` respects these restrictions when deciding if a certificate is trusted for a particular purpose (though the tests themselves don't specify the purpose, they test the *presence* or *absence* of EKU and its effect on overall trust).

3. **Testing the behavior when duplicate certificates with different EKU restrictions are present in the trust store.** This ensures that if at least one version of the certificate allows the usage, it's considered trusted.

4. **Testing the handling of explicitly disallowed certificates.** Certificates can be explicitly marked as untrusted, and these tests verify that `TrustStoreWin` correctly identifies them as distrusted, overriding any trust they might have due to being present in other stores.

5. **Testing the `SyncGetIssuersOf` method, which retrieves the potential issuer certificates for a given certificate.** This functionality is crucial for building certificate chains.

6. **Testing the `GetAllUserAddedCerts` method, which retrieves all user-added certificates from the trust store along with their trust status.**

**Relationship to Javascript Functionality:**

While this C++ code doesn't directly execute Javascript, it is **fundamental to the security of web browsing and any network communication initiated by Javascript code within a Chromium-based browser.**

Here's how it relates:

* **HTTPS Certificate Validation:** When Javascript code (e.g., in a web page) makes an HTTPS request, the browser needs to verify the server's certificate. The `TrustStoreWin` (or its platform-independent counterpart on other OSes) is a key component in this process. It provides the browser with the list of trusted root CAs. The browser uses this information to build a chain of trust from the server's certificate back to a trusted root.
* **`navigator.credentials.get()` and related APIs:**  Javascript APIs that deal with client certificates rely on the underlying platform's certificate management. While `TrustStoreWin` primarily deals with server certificate validation, the general principles of certificate trust management are shared. If a website requests a client certificate, the browser's UI will present certificates from the Windows certificate store, which is managed (in part) by the mechanisms tested here.
* **Certificate Pinning:** While not directly tested here, the information from the trust store contributes to the browser's ability to enforce certificate pinning policies.

**Example:**

Imagine a Javascript application running in a Chromium browser tries to connect to `https://example.com`.

1. The browser initiates an SSL/TLS handshake with `example.com`.
2. The server presents its SSL certificate.
3. The browser needs to verify if this certificate is trusted.
4. The `TrustStoreWin` (or a similar component) is consulted to check if the root CA that signed `example.com`'s certificate is present in the Windows trust store.
5. Based on the information provided by `TrustStoreWin`, the browser decides whether to proceed with the connection or display a security warning.

**Logical Reasoning with Assumptions, Inputs, and Outputs:**

Let's take the `TEST_F(TrustStoreWinTest, GetTrust)` as an example:

**Assumptions:**

* The test environment has access to the certificate files "multi-root-A-by-B.pem", "multi-root-B-by-C.pem", etc.
* The `AddToStore` function correctly adds certificates to the in-memory Windows certificate stores.
* The `CreateTrustStoreWin` function correctly creates an instance of `TrustStoreWin` using the provided certificate stores.

**Hypothetical Input:**

* **Certificate Stores:**
    * `stores_.roots`: Contains the certificate from "multi-root-D-by-D.pem" (a self-signed root).
    * `stores_.intermediates`: Contains the certificate from "multi-root-C-by-D.pem" (an intermediate CA).
    * `stores_.trusted_people`: Contains the certificate from "multi-root-A-by-B.pem" (a user-trusted certificate).
* **`GetTrust()` calls with different certificates:**
    * `d_by_d_.get()` (the self-signed root)
    * `a_by_b_.get()` (the user-trusted certificate)
    * `c_by_d_.get()` (the intermediate CA)
    * `e_by_e_.get()` (an unknown self-signed certificate)

**Expected Output:**

* `trust_store_win->GetTrust(d_by_d_.get())` should return a `CertificateTrust` indicating it's a trusted anchor (root CA).
* `trust_store_win->GetTrust(a_by_b_.get())` should return a `CertificateTrust` indicating it's a trusted peer.
* `trust_store_win->GetTrust(c_by_d_.get())` should return a `CertificateTrust` indicating it's unspecified (intermediates are not inherently trusted).
* `trust_store_win->GetTrust(e_by_e_.get())` should return a `CertificateTrust` indicating it's unspecified (unknown roots are not trusted).

**User or Programming Common Usage Errors:**

1. **User installing an untrusted root certificate:** If a user manually installs a self-signed certificate or a certificate from an unrecognized CA into the Windows "Trusted Root Certification Authorities" store, `TrustStoreWin` will report these certificates as trusted roots. This could lead to security vulnerabilities if the user is tricked into trusting a malicious CA. The test `TEST_F(TrustStoreWinTest, GetTrust)` directly simulates this scenario to ensure the `TrustStoreWin` behaves as expected.

2. **User installing a certificate into the wrong store:**  A user might intend to trust a specific website's certificate but accidentally install it into the "Intermediate Certification Authorities" store. `TrustStoreWin` would then treat this certificate as an intermediate, not a directly trusted entity. The test `TEST_F(TrustStoreWinTest, GetTrust)` verifies this distinction.

3. **Developer error in configuring certificate verification:** A developer might incorrectly assume that all certificates in the system store are automatically trusted. They might bypass proper certificate chain validation, potentially accepting invalid or compromised certificates. The tests in this file help ensure that Chromium's certificate validation logic (which relies on `TrustStoreWin`) is correct.

4. **Incorrect EKU settings on certificates:** If a certificate is created with incorrect or missing EKU settings, it might not be considered valid for its intended purpose. For example, a root CA certificate without any EKU restrictions (or with the "anyExtendedKeyUsage" OID) will be considered valid for any purpose. The tests like `TEST_F(TrustStoreWinTest, GetTrustRestrictedEKU)` verify that `TrustStoreWin` respects these EKU constraints.

**User Operations Leading to This Code (Debugging Clues):**

The `TrustStoreWin` code is involved in almost any network operation within a Chromium browser that involves secure connections (HTTPS). Here's a step-by-step example of how a user action can lead to this code being executed:

1. **User types a URL in the address bar and presses Enter:**  Let's say the user types `https://www.example.com`.
2. **Browser initiates a connection:** The browser starts the process of connecting to the server at `www.example.com`.
3. **TLS Handshake:** The browser and server perform a TLS handshake to establish a secure connection.
4. **Server presents its certificate:** The server sends its SSL/TLS certificate to the browser.
5. **Certificate Chain Building and Validation:** The browser needs to verify the authenticity of the server's certificate. This involves:
    * **Retrieving potential issuer certificates:**  The browser might look in its cache or request intermediate certificates from the server. The `SyncGetIssuersOf` method tested here is part of this process.
    * **Checking for a trusted root:** The browser consults the system's trust store to see if the root CA that signed the server's certificate (or an intermediate CA in the chain) is trusted. This is where `TrustStoreWin` comes into play. Its `GetTrust` method is called to determine the trust status of certificates in the chain.
    * **Checking for revocation:** The browser might perform checks to see if any certificate in the chain has been revoked (though this is a separate mechanism not directly tested in this file).
    * **Verifying certificate validity periods and other properties.**
6. **Decision on Connection Security:** Based on the validation results (including the trust information provided by `TrustStoreWin`), the browser decides whether the connection is secure. If the certificate chain can be traced back to a trusted root, and there are no other validation errors, the connection is considered secure, and the user sees the padlock icon in the address bar. Otherwise, a security warning is displayed.
7. **Javascript execution:** Once a secure connection is established, Javascript code on the web page can interact with the server securely, relying on the underlying TLS connection validated using the trust store information managed by `TrustStoreWin`.

Therefore, every time a user accesses an HTTPS website on Windows using Chromium, the `TrustStoreWin` class is likely to be involved in the certificate validation process. Debugging network issues, especially certificate-related errors, often involves examining the state of the Windows certificate store and understanding how `TrustStoreWin` interprets that state.

Prompt: 
```
这是目录为net/cert/internal/trust_store_win_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/trust_store_win.h"

#include <memory>
#include <string_view>

#include "base/containers/to_vector.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/ranges/algorithm.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/scoped_feature_list.h"
#include "base/win/wincrypt_shim.h"
#include "crypto/scoped_capi_types.h"
#include "net/base/features.h"
#include "net/cert/cert_net_fetcher.h"
#include "net/cert/internal/test_helpers.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "net/cert/x509_util_win.h"
#include "net/test/cert_test_util.h"
#include "net/test/test_data_directory.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/include/openssl/pool.h"
#include "third_party/boringssl/src/pki/cert_errors.h"
#include "third_party/boringssl/src/pki/parsed_certificate.h"
#include "third_party/boringssl/src/pki/trust_store.h"

namespace net {

namespace {

::testing::AssertionResult ParseCertFromFile(
    std::string_view file_name,
    std::shared_ptr<const bssl::ParsedCertificate>* out_cert) {
  const scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(net::GetTestCertsDirectory(), file_name);
  if (!cert) {
    return ::testing::AssertionFailure() << "ImportCertFromFile failed";
  }
  bssl::CertErrors errors;
  std::shared_ptr<const bssl::ParsedCertificate> parsed =
      bssl::ParsedCertificate::Create(
          bssl::UpRef(cert->cert_buffer()),
          x509_util::DefaultParseCertificateOptions(), &errors);
  if (!parsed) {
    return ::testing::AssertionFailure()
           << "bssl::ParseCertificate::Create failed:\n"
           << errors.ToDebugString();
  }
  *out_cert = parsed;
  return ::testing::AssertionSuccess();
}

class TrustStoreWinTest : public testing::Test {
 public:
  void SetUp() override {
    ASSERT_TRUE(ParseCertFromFile("multi-root-A-by-B.pem", &a_by_b_));
    ASSERT_TRUE(ParseCertFromFile("multi-root-B-by-C.pem", &b_by_c_));
    ASSERT_TRUE(ParseCertFromFile("multi-root-B-by-F.pem", &b_by_f_));
    ASSERT_TRUE(ParseCertFromFile("multi-root-C-by-D.pem", &c_by_d_));
    ASSERT_TRUE(ParseCertFromFile("multi-root-C-by-E.pem", &c_by_e_));
    ASSERT_TRUE(ParseCertFromFile("multi-root-D-by-D.pem", &d_by_d_));
    ASSERT_TRUE(ParseCertFromFile("multi-root-E-by-E.pem", &e_by_e_));
    ASSERT_TRUE(ParseCertFromFile("multi-root-F-by-E.pem", &f_by_e_));
  }

  bssl::CertificateTrust ExpectedTrustForAnchor() const {
    return bssl::CertificateTrust::ForTrustAnchorOrLeaf()
        .WithEnforceAnchorExpiry()
        .WithEnforceAnchorConstraints()
        .WithRequireLeafSelfSigned();
  }

  bssl::CertificateTrust ExpectedTrustForPeer() const {
    return bssl::CertificateTrust::ForTrustedLeaf().WithRequireLeafSelfSigned();
  }

  // Returns true if |cert| successfully added to store, false otherwise.
  bool AddToStore(HCERTSTORE store,
                  std::shared_ptr<const bssl::ParsedCertificate> cert) {
    crypto::ScopedPCCERT_CONTEXT os_cert(CertCreateCertificateContext(
        X509_ASN_ENCODING, CRYPTO_BUFFER_data(cert->cert_buffer()),
        CRYPTO_BUFFER_len(cert->cert_buffer())));
    return CertAddCertificateContextToStore(store, os_cert.get(),
                                            CERT_STORE_ADD_ALWAYS, nullptr);
  }

  // Returns true if cert at file_name successfully added to store with
  // restricted usage, false otherwise.
  bool AddToStoreWithEKURestriction(
      HCERTSTORE store,
      std::shared_ptr<const bssl::ParsedCertificate> cert,
      LPCSTR usage_identifier) {
    crypto::ScopedPCCERT_CONTEXT os_cert(CertCreateCertificateContext(
        X509_ASN_ENCODING, CRYPTO_BUFFER_data(cert->cert_buffer()),
        CRYPTO_BUFFER_len(cert->cert_buffer())));

    CERT_ENHKEY_USAGE usage;
    memset(&usage, 0, sizeof(usage));
    if (!CertSetEnhancedKeyUsage(os_cert.get(), &usage)) {
      return false;
    }
    if (usage_identifier) {
      if (!CertAddEnhancedKeyUsageIdentifier(os_cert.get(), usage_identifier)) {
        return false;
      }
    }
    return !!CertAddCertificateContextToStore(store, os_cert.get(),
                                              CERT_STORE_ADD_ALWAYS, nullptr);
  }

  std::unique_ptr<TrustStoreWin> CreateTrustStoreWin() {
    return TrustStoreWin::CreateForTesting(std::move(stores_));
  }

  // The cert stores that will be used to create the trust store. These handles
  // will be null after CreateTrustStoreWin() is called.
  TrustStoreWin::CertStores stores_ =
      TrustStoreWin::CertStores::CreateInMemoryStoresForTesting();

  std::shared_ptr<const bssl::ParsedCertificate> a_by_b_, b_by_c_, b_by_f_,
      c_by_d_, c_by_e_, d_by_d_, e_by_e_, f_by_e_;
};

TEST_F(TrustStoreWinTest, GetTrustInitializationError) {
  // Simulate an initialization error by using null stores.
  std::unique_ptr<TrustStoreWin> trust_store_win =
      TrustStoreWin::CreateForTesting(
          TrustStoreWin::CertStores::CreateNullStoresForTesting());
  ASSERT_TRUE(trust_store_win);
  bssl::CertificateTrust trust = trust_store_win->GetTrust(d_by_d_.get());
  EXPECT_EQ(bssl::CertificateTrust::ForUnspecified().ToDebugString(),
            trust.ToDebugString());
}

TEST_F(TrustStoreWinTest, GetTrust) {
  ASSERT_TRUE(AddToStore(stores_.roots.get(), d_by_d_));
  ASSERT_TRUE(AddToStore(stores_.intermediates.get(), c_by_d_));
  ASSERT_TRUE(AddToStore(stores_.trusted_people.get(), a_by_b_));

  std::unique_ptr<TrustStoreWin> trust_store_win = CreateTrustStoreWin();
  ASSERT_TRUE(trust_store_win);

  // Explicitly trusted root should be trusted.
  EXPECT_EQ(ExpectedTrustForAnchor().ToDebugString(),
            trust_store_win->GetTrust(d_by_d_.get()).ToDebugString());

  // Explicitly trusted peer should be trusted.
  // (Although it wouldn't actually verify since it's not self-signed but has
  // require_leaf_selfsigned set. That doesn't matter for the purposes of these
  // tests.)
  EXPECT_EQ(ExpectedTrustForPeer().ToDebugString(),
            trust_store_win->GetTrust(a_by_b_.get()).ToDebugString());

  // Intermediate for path building should not be trusted.
  EXPECT_EQ(bssl::CertificateTrust::ForUnspecified().ToDebugString(),
            trust_store_win->GetTrust(c_by_d_.get()).ToDebugString());

  // Unknown roots should not be trusted (e.g. just because they're
  // self-signed doesn't make them a root)
  EXPECT_EQ(bssl::CertificateTrust::ForUnspecified().ToDebugString(),
            trust_store_win->GetTrust(e_by_e_.get()).ToDebugString());
}

// This test has a special TrustStoreWin setup with restricted EKU usages.
// Specifically, the only certs set up in the root store are set up
// as follows:
//
// - kMultiRootDByD: only has szOID_PKIX_KP_SERVER_AUTH EKU set
// - kMultiRootEByE: only has szOID_PKIX_KP_CLIENT_AUTH set
// - kMultiRootCByE: only has szOID_ANY_ENHANCED_KEY_USAGE set
// - kMultiRootCByD: no EKU usages set
TEST_F(TrustStoreWinTest, GetTrustRestrictedEKU) {
  ASSERT_TRUE(AddToStoreWithEKURestriction(stores_.roots.get(), d_by_d_,
                                           szOID_PKIX_KP_SERVER_AUTH));
  ASSERT_TRUE(AddToStoreWithEKURestriction(stores_.roots.get(), e_by_e_,
                                           szOID_PKIX_KP_CLIENT_AUTH));
  ASSERT_TRUE(AddToStoreWithEKURestriction(stores_.roots.get(), c_by_e_,
                                           szOID_ANY_ENHANCED_KEY_USAGE));
  ASSERT_TRUE(
      AddToStoreWithEKURestriction(stores_.roots.get(), c_by_d_, nullptr));

  std::unique_ptr<TrustStoreWin> trust_store_win = CreateTrustStoreWin();
  ASSERT_TRUE(trust_store_win);

  // Root cert with EKU szOID_PKIX_KP_SERVER_AUTH usage set should be
  // trusted.
  EXPECT_EQ(ExpectedTrustForAnchor().ToDebugString(),
            trust_store_win->GetTrust(d_by_d_.get()).ToDebugString());

  // Root cert with EKU szOID_ANY_ENHANCED_KEY_USAGE usage set should be
  // trusted.
  EXPECT_EQ(ExpectedTrustForAnchor().ToDebugString(),
            trust_store_win->GetTrust(c_by_e_.get()).ToDebugString());

  // Root cert with EKU szOID_PKIX_KP_CLIENT_AUTH does not allow usage of
  // cert for server auth, return UNSPECIFIED.
  EXPECT_EQ(bssl::CertificateTrust::ForUnspecified().ToDebugString(),
            trust_store_win->GetTrust(e_by_e_.get()).ToDebugString());

  // Root cert with no EKU usages, return UNSPECIFIED.
  EXPECT_EQ(bssl::CertificateTrust::ForUnspecified().ToDebugString(),
            trust_store_win->GetTrust(c_by_d_.get()).ToDebugString());

  // Unknown cert has unspecified trust.
  EXPECT_EQ(bssl::CertificateTrust::ForUnspecified().ToDebugString(),
            trust_store_win->GetTrust(f_by_e_.get()).ToDebugString());
}

// Same as GetTrustRestrictedEKU but for the Trusted People store.
TEST_F(TrustStoreWinTest, GetTrustTrustedPeopleRestrictedEKU) {
  ASSERT_TRUE(AddToStoreWithEKURestriction(stores_.trusted_people.get(),
                                           d_by_d_, szOID_PKIX_KP_SERVER_AUTH));
  ASSERT_TRUE(AddToStoreWithEKURestriction(stores_.trusted_people.get(),
                                           e_by_e_, szOID_PKIX_KP_CLIENT_AUTH));
  ASSERT_TRUE(AddToStoreWithEKURestriction(
      stores_.trusted_people.get(), c_by_e_, szOID_ANY_ENHANCED_KEY_USAGE));
  ASSERT_TRUE(AddToStoreWithEKURestriction(stores_.trusted_people.get(),
                                           c_by_d_, nullptr));

  std::unique_ptr<TrustStoreWin> trust_store_win = CreateTrustStoreWin();
  ASSERT_TRUE(trust_store_win);

  // TrustedPeople cert with EKU szOID_PKIX_KP_SERVER_AUTH usage set should be
  // trusted.
  EXPECT_EQ(ExpectedTrustForPeer().ToDebugString(),
            trust_store_win->GetTrust(d_by_d_.get()).ToDebugString());

  // TrustedPeople cert with EKU szOID_ANY_ENHANCED_KEY_USAGE usage set should
  // be trusted.
  EXPECT_EQ(ExpectedTrustForPeer().ToDebugString(),
            trust_store_win->GetTrust(c_by_e_.get()).ToDebugString());

  // TrustedPeople cert with EKU szOID_PKIX_KP_CLIENT_AUTH does not allow usage
  // of cert for server auth, return UNSPECIFIED.
  EXPECT_EQ(bssl::CertificateTrust::ForUnspecified().ToDebugString(),
            trust_store_win->GetTrust(e_by_e_.get()).ToDebugString());

  // TrustedPeople cert with no EKU usages, return UNSPECIFIED.
  EXPECT_EQ(bssl::CertificateTrust::ForUnspecified().ToDebugString(),
            trust_store_win->GetTrust(c_by_d_.get()).ToDebugString());

  // Unknown cert has unspecified trust.
  EXPECT_EQ(bssl::CertificateTrust::ForUnspecified().ToDebugString(),
            trust_store_win->GetTrust(f_by_e_.get()).ToDebugString());
}

// If duplicate certs are added to the root store with different EKU usages,
// the cert should be trusted if any one of the usages is valid.
// Root store set up as follows:
//
// - kMultiRootDByD: only has szOID_PKIX_KP_CLIENT_AUTH EKU set
// - kMultiRootDByD (dupe): only has szOID_PKIX_KP_SERVER_AUTH set
// - kMultiRootDByD (dupe 2): no EKU usages set
TEST_F(TrustStoreWinTest, GetTrustRestrictedEKUDuplicateCerts) {
  ASSERT_TRUE(AddToStoreWithEKURestriction(stores_.roots.get(), d_by_d_,
                                           szOID_PKIX_KP_CLIENT_AUTH));
  ASSERT_TRUE(AddToStoreWithEKURestriction(stores_.roots.get(), d_by_d_,
                                           szOID_PKIX_KP_SERVER_AUTH));
  ASSERT_TRUE(
      AddToStoreWithEKURestriction(stores_.roots.get(), d_by_d_, nullptr));

  std::unique_ptr<TrustStoreWin> trust_store_win = CreateTrustStoreWin();
  ASSERT_TRUE(trust_store_win);

  // One copy of the Root cert is trusted for TLS Server Auth.
  EXPECT_EQ(ExpectedTrustForAnchor().ToDebugString(),
            trust_store_win->GetTrust(d_by_d_.get()).ToDebugString());
}

// Test that disallowed certs will be distrusted regardless of EKU settings.
TEST_F(TrustStoreWinTest, GetTrustDisallowedCerts) {
  ASSERT_TRUE(AddToStore(stores_.roots.get(), d_by_d_));
  ASSERT_TRUE(AddToStore(stores_.roots.get(), e_by_e_));
  ASSERT_TRUE(AddToStore(stores_.trusted_people.get(), f_by_e_));

  ASSERT_TRUE(AddToStoreWithEKURestriction(stores_.disallowed.get(), d_by_d_,
                                           szOID_PKIX_KP_CLIENT_AUTH));
  ASSERT_TRUE(AddToStore(stores_.disallowed.get(), e_by_e_));
  ASSERT_TRUE(AddToStore(stores_.disallowed.get(), f_by_e_));

  std::unique_ptr<TrustStoreWin> trust_store_win = CreateTrustStoreWin();
  ASSERT_TRUE(trust_store_win);

  // E-by-E is in both root and distrusted store. Distrust takes precedence.
  EXPECT_EQ(bssl::CertificateTrust::ForDistrusted().ToDebugString(),
            trust_store_win->GetTrust(e_by_e_.get()).ToDebugString());

  // F-by-E is in both trusted people and distrusted store. Distrust takes
  // precedence.
  EXPECT_EQ(bssl::CertificateTrust::ForDistrusted().ToDebugString(),
            trust_store_win->GetTrust(f_by_e_.get()).ToDebugString());

  // D-by-D is in root and in distrusted but without szOID_PKIX_KP_SERVER_AUTH
  // set. It should still be distrusted since the EKU settings aren't checked
  // on distrust.
  EXPECT_EQ(bssl::CertificateTrust::ForDistrusted().ToDebugString(),
            trust_store_win->GetTrust(d_by_d_.get()).ToDebugString());
}

MATCHER_P(ParsedCertEq, expected_cert, "") {
  return arg && expected_cert &&
         base::ranges::equal(arg->der_cert(), expected_cert->der_cert());
}

TEST_F(TrustStoreWinTest, GetIssuersInitializationError) {
  // Simulate an initialization error by using null stores.
  std::unique_ptr<TrustStoreWin> trust_store_win =
      TrustStoreWin::CreateForTesting(
          TrustStoreWin::CertStores::CreateNullStoresForTesting());
  ASSERT_TRUE(trust_store_win);
  bssl::ParsedCertificateList issuers;
  trust_store_win->SyncGetIssuersOf(b_by_f_.get(), &issuers);
  ASSERT_EQ(0U, issuers.size());
}

TEST_F(TrustStoreWinTest, GetIssuers) {
  ASSERT_TRUE(AddToStore(stores_.roots.get(), d_by_d_));

  ASSERT_TRUE(AddToStore(stores_.intermediates.get(), c_by_d_));
  ASSERT_TRUE(AddToStore(stores_.intermediates.get(), c_by_e_));
  ASSERT_TRUE(AddToStore(stores_.intermediates.get(), f_by_e_));

  ASSERT_TRUE(AddToStore(stores_.trusted_people.get(), b_by_c_));

  ASSERT_TRUE(AddToStore(stores_.disallowed.get(), b_by_f_));

  std::unique_ptr<TrustStoreWin> trust_store_win = CreateTrustStoreWin();

  // No matching issuer (Trusted People and Disallowed are not consulted).
  {
    bssl::ParsedCertificateList issuers;
    trust_store_win->SyncGetIssuersOf(a_by_b_.get(), &issuers);
    ASSERT_EQ(0U, issuers.size());
  }

  // Single matching issuer found in intermediates.
  {
    bssl::ParsedCertificateList issuers;
    trust_store_win->SyncGetIssuersOf(b_by_f_.get(), &issuers);
    ASSERT_EQ(1U, issuers.size());
    EXPECT_THAT(issuers, testing::UnorderedElementsAre(ParsedCertEq(f_by_e_)));
  }

  // Single matching issuer found in roots.
  {
    bssl::ParsedCertificateList issuers;
    trust_store_win->SyncGetIssuersOf(d_by_d_.get(), &issuers);
    ASSERT_EQ(1U, issuers.size());
    EXPECT_THAT(issuers, testing::UnorderedElementsAre(ParsedCertEq(d_by_d_)));
  }

  // Multiple issuers found.
  {
    bssl::ParsedCertificateList issuers;
    trust_store_win->SyncGetIssuersOf(b_by_c_.get(), &issuers);
    ASSERT_EQ(2U, issuers.size());
    EXPECT_THAT(issuers, testing::UnorderedElementsAre(ParsedCertEq(c_by_d_),
                                                       ParsedCertEq(c_by_e_)));
  }
}

MATCHER_P(CertWithTrustEq, expected_cert_with_trust, "") {
  return arg.cert_bytes == expected_cert_with_trust.cert_bytes &&
         arg.trust.ToDebugString() ==
             expected_cert_with_trust.trust.ToDebugString();
}

TEST_F(TrustStoreWinTest, GetAllUserAddedCerts) {
  ASSERT_TRUE(AddToStore(stores_.roots.get(), d_by_d_));
  ASSERT_TRUE(
      AddToStoreWithEKURestriction(stores_.roots.get(), c_by_d_, nullptr));

  ASSERT_TRUE(AddToStore(stores_.intermediates.get(), c_by_e_));
  ASSERT_TRUE(AddToStore(stores_.intermediates.get(), f_by_e_));

  ASSERT_TRUE(AddToStore(stores_.trusted_people.get(), b_by_c_));

  ASSERT_TRUE(AddToStore(stores_.disallowed.get(), b_by_f_));

  std::unique_ptr<TrustStoreWin> trust_store_win = CreateTrustStoreWin();

  std::vector<net::PlatformTrustStore::CertWithTrust> certs =
      trust_store_win->GetAllUserAddedCerts();
  ASSERT_EQ(5U, certs.size());
  EXPECT_THAT(certs, testing::UnorderedElementsAre(
                         CertWithTrustEq(net::PlatformTrustStore::CertWithTrust(
                             base::ToVector(d_by_d_->der_cert()),
                             bssl::CertificateTrust::ForTrustAnchorOrLeaf()
                                 .WithEnforceAnchorExpiry()
                                 .WithEnforceAnchorConstraints()
                                 .WithRequireLeafSelfSigned())),
                         CertWithTrustEq(net::PlatformTrustStore::CertWithTrust(
                             base::ToVector(c_by_e_->der_cert()),
                             bssl::CertificateTrust::ForUnspecified())),
                         CertWithTrustEq(net::PlatformTrustStore::CertWithTrust(
                             base::ToVector(f_by_e_->der_cert()),
                             bssl::CertificateTrust::ForUnspecified())),
                         CertWithTrustEq(net::PlatformTrustStore::CertWithTrust(
                             base::ToVector(b_by_c_->der_cert()),
                             bssl::CertificateTrust::ForTrustedLeaf()
                                 .WithRequireLeafSelfSigned())),
                         CertWithTrustEq(net::PlatformTrustStore::CertWithTrust(
                             base::ToVector(b_by_f_->der_cert()),
                             bssl::CertificateTrust::ForDistrusted()))));
}

}  // namespace
}  // namespace net

"""

```