Response:
Let's break down the thought process for analyzing the `x509_util_nss_unittest.cc` file and generating the response.

**1. Understanding the Goal:**

The request asks for a breakdown of the functionality of the provided C++ unit test file, specifically relating it to JavaScript if possible, explaining logic through examples, highlighting common user errors, and describing user journey for debugging.

**2. Initial Scan and Identification of Key Areas:**

Quickly scan the `#include` statements and the test names (`TEST(X509UtilNSSTest, ...)`). This immediately reveals the core purpose: testing functions within the `net::x509_util` namespace that interact with NSS (Network Security Services). The included headers like `net/cert/x509_util.h`, `net/cert/x509_certificate.h`, and `net/cert/scoped_nss_types.h` confirm this. The test names themselves are quite descriptive, like `IsSameCertificate`, `CreateCERTCertificateFromBytes`, etc., hinting at the specific functionalities being tested.

**3. Analyzing Each Test Case:**

Go through each `TEST` block and understand what it's doing:

* **`IsSameCertificate`**:  Compares different representations of the same and different certificates (NSS and `X509Certificate` objects).
* **`CreateCERTCertificateFromBytes`**: Tests creating NSS certificate objects from raw byte arrays. Includes a test for invalid input.
* **`CreateCERTCertificateFromX509Certificate`**: Tests creating NSS certificate objects from `X509Certificate` objects.
* **`CreateCERTCertificateListFromX509Certificate`**: Tests creating lists of NSS certificates from `X509Certificate` objects, including handling intermediate certificates and errors.
* **`CreateCERTCertificateListFromBytes`**: Tests creating lists of NSS certificates from a raw byte array of a certificate chain.
* **`DupCERTCertificate` and `DupCERTCertificateList`**: Test the functionality of duplicating NSS certificate objects and lists, ensuring proper reference counting.
* **`CreateX509CertificateFromCERTCertificate`**: Tests creating `X509Certificate` objects from NSS certificate objects, with and without a chain.
* **`CreateX509CertificateListFromCERTCertificates`**: Tests creating lists of `X509Certificate` objects from lists of NSS certificates.
* **`GetDEREncoded`**: Tests retrieving the DER encoding of an NSS certificate.
* **`GetDefaultNickname`**: Tests generating a default nickname for a certificate.
* **`GetCERTNameDisplayName`**: Tests getting a user-friendly display name from the certificate's subject.
* **`ParseClientSubjectAltNames`**: Tests parsing Subject Alternative Names (SANs) from a certificate.
* **`GetValidityTimes`**: Tests retrieving the validity start and end dates of a certificate.
* **`CalculateFingerprint256`**: Tests calculating the SHA-256 fingerprint of a certificate.

**4. Identifying Core Functionalities:**

Based on the test cases, identify the primary functionalities of the `x509_util_nss.cc` file itself (not just the test file):

* Converting between different certificate representations (NSS's `CERTCertificate` and Chromium's `X509Certificate`).
* Creating certificate objects from raw data.
* Comparing certificates for equality.
* Duplicating certificate objects and lists.
* Extracting information from certificates (subject name, validity times, SANs, fingerprints).
* Generating default nicknames.
* Getting the DER encoding.

**5. Considering JavaScript Relevance:**

Think about how these functionalities might relate to JavaScript in a browser context. The most obvious connection is through the browser's handling of HTTPS and certificate verification. JavaScript APIs might expose information about certificates or trigger certificate-related actions.

* **Example:** When a website uses HTTPS, JavaScript might be able to access information about the server's certificate, like its subject name or validity. This information is likely processed internally by the browser's network stack, which uses components like the ones being tested here.

**6. Developing Logic Examples (Input/Output):**

For functions like `IsSameCertificate` or `CreateCERTCertificateFromBytes`, simple examples with "google_der" and "webkit_der" as input and `true`/`false` or a `CERTCertificate` object as output are easy to formulate based on the test cases.

**7. Identifying Potential User Errors:**

Think about how developers or even end-users might encounter errors related to certificate handling.

* **Developers:** Providing invalid certificate data, trying to create certificates from malformed strings, not handling potential null pointers returned by creation functions.
* **End-users:**  While they don't directly interact with these APIs, their actions (like visiting an HTTPS site with a broken certificate chain) can trigger the underlying code and potentially surface errors in the UI (e.g., "Your connection is not private").

**8. Tracing the User Journey (Debugging):**

Consider how a developer might end up investigating this code during a debugging session. Start from a high-level user action:

* **User Action:** A user navigates to an HTTPS website.
* **Browser Action:** The browser attempts to establish a secure connection.
* **Certificate Handling:** This involves fetching the server's certificate, verifying its validity, and potentially building a chain of trust.
* **`x509_util_nss.cc` in the Picture:**  If the browser uses NSS for certificate handling, functions in this file might be called to parse the certificate data, compare certificates, or build the certificate chain. A debugger might be used to step through these functions if issues arise during this process (e.g., a certificate is not being recognized as valid).

**9. Structuring the Response:**

Organize the information logically, following the prompts in the request:

* Start with a summary of the file's purpose.
* List the key functionalities.
* Explain the JavaScript connection with an example.
* Provide input/output examples for logical functions.
* Detail common user/programmer errors.
* Describe the user journey for debugging.

**10. Refinement and Review:**

Read through the generated response, ensuring clarity, accuracy, and completeness. Check if all parts of the initial request have been addressed. Ensure the language is accessible and avoids overly technical jargon where possible. For instance, instead of just saying "DER encoding," briefly explain what it is.

This iterative process of scanning, analyzing, connecting, exemplifying, and structuring helps to generate a comprehensive and informative response to the given request.
This C++ source code file, `net/cert/x509_util_nss_unittest.cc`, is a unit test file within the Chromium project's network stack. Its primary function is to test the functionalities of the `net::x509_util` namespace, specifically those parts that interact with **NSS (Network Security Services)**. NSS is a set of libraries designed to support cross-platform development of security-enabled client and server applications.

Here's a breakdown of the functionalities tested in this file:

**Core Functionalities Tested:**

* **Certificate Comparison (`IsSameCertificate`):** Tests the ability to correctly determine if two certificate objects (represented by NSS's `CERTCertificate` and Chromium's `X509Certificate`) represent the same underlying certificate.
* **Creating NSS Certificates from Byte Arrays (`CreateCERTCertificateFromBytes`):** Verifies that NSS certificate objects can be created successfully from raw byte arrays (DER encoded). It also tests error handling for invalid byte arrays.
* **Creating NSS Certificates from `X509Certificate` (`CreateCERTCertificateFromX509Certificate`):** Checks if NSS certificate objects can be created correctly from existing Chromium `X509Certificate` objects.
* **Creating Lists of NSS Certificates from `X509Certificate` (`CreateCERTCertificateListFromX509Certificate`):** Tests the creation of a list of NSS certificate objects, including the main certificate and its intermediate certificates, from a single `X509Certificate` object representing a certificate chain. It also tests error handling for invalid intermediate certificates.
* **Creating Lists of NSS Certificates from Byte Arrays (`CreateCERTCertificateListFromBytes`):** Verifies that a list of NSS certificates can be created by parsing a byte array containing a sequence of certificates (like a PEM file).
* **Duplicating NSS Certificates and Lists (`DupCERTCertificate`, `DupCERTCertificateList`):** Tests the functionality for creating independent copies of NSS certificate objects and lists of them, ensuring that the underlying certificate data is properly referenced and managed.
* **Creating `X509Certificate` from NSS Certificates (`CreateX509CertificateFromCERTCertificate`):** Checks the reverse process of creating Chromium `X509Certificate` objects from NSS certificate objects, including handling certificate chains.
* **Creating Lists of `X509Certificate` from NSS Certificate Lists (`CreateX509CertificateListFromCERTCertificates`):** Tests the conversion of a list of NSS certificates into a list of Chromium `X509Certificate` objects.
* **Getting the DER Encoding of an NSS Certificate (`GetDEREncoded`):** Verifies the ability to retrieve the raw DER-encoded byte representation of an NSS certificate.
* **Getting Default Nicknames (`GetDefaultNickname`):** Tests the logic for generating a default, user-friendly nickname for a certificate, especially when the common name is missing.
* **Getting Display Names (`GetCERTNameDisplayName`):** Tests the function that extracts a human-readable display name from a certificate's subject information.
* **Parsing Subject Alternative Names (SANs) (`ParseClientSubjectAltNames`):** Checks the functionality for extracting email addresses (rfc822Name) and User Principal Names (UPNs) from the Subject Alternative Name extension of a certificate.
* **Getting Validity Times (`GetValidityTimes`):** Tests the extraction of the "not before" and "not after" dates from a certificate, indicating its validity period.
* **Calculating Fingerprints (`CalculateFingerprint256`):** Verifies the calculation of the SHA-256 fingerprint of a certificate.

**Relationship to JavaScript Functionality:**

While this C++ code itself doesn't directly execute in a JavaScript environment, the functionalities it tests are crucial for secure communication on the web, which heavily involves JavaScript. Here's how they relate:

* **HTTPS and Certificate Verification:** When a website uses HTTPS, the browser (which has a network stack built with components like this) needs to verify the server's SSL/TLS certificate. JavaScript code running on the page might interact with browser APIs to understand the security state of the connection. The underlying certificate handling, including parsing, comparison, and validation, relies on code similar to what's being tested here.
* **`navigator.credentials.get()` and Web Authentication API:**  JavaScript's Web Authentication API allows websites to use cryptographic credentials, which can involve client certificates. The browser's internal mechanisms for handling and verifying these client certificates would utilize the tested functionalities.
* **Reporting Security Information:** Browser developer tools and security information panels often display details about the certificates used for a connection. The information presented (like subject name, validity period, fingerprints) is extracted using code similar to the tested functions.

**Example of JavaScript Interaction (Conceptual):**

Imagine a simplified browser API that exposes certificate information:

```javascript
// This is a conceptual API, not necessarily a direct Chromium API
async function getWebsiteCertificateInfo(url) {
  const securityInfo = await navigator.connection.getSecurityInfo(url);
  const serverCertificate = securityInfo.serverCertificate;
  console.log("Server Certificate Subject:", serverCertificate.subjectName);
  console.log("Server Certificate Fingerprint:", serverCertificate.fingerprintSHA256);
  // ... other properties
}

getWebsiteCertificateInfo("https://www.example.com");
```

Internally, when `navigator.connection.getSecurityInfo()` is called, the browser's C++ network stack will be involved in fetching and processing the server's certificate. Functions tested in `x509_util_nss_unittest.cc` would likely be used to parse the certificate bytes, extract the subject name, calculate the fingerprint, and so on, before this information is made available to the JavaScript code.

**Logical Reasoning with Assumptions and Examples:**

Let's take the `IsSameCertificate` test as an example:

**Assumption:** We have two different representations of the same Google certificate: `google_nss_cert` (an NSS certificate object) and `google_x509_cert` (a Chromium `X509Certificate` object).

**Input:**  Calling `x509_util::IsSameCertificate(google_nss_cert.get(), google_x509_cert.get())`.

**Output:** `true` (because they represent the same underlying certificate).

**Another Example (Negative Case):**

**Assumption:** We have an NSS certificate for Google (`google_nss_cert`) and an NSS certificate for WebKit (`webkit_nss_cert`).

**Input:** Calling `x509_util::IsSameCertificate(google_nss_cert.get(), webkit_nss_cert.get())`.

**Output:** `false` (because they are different certificates).

**User or Programming Common Usage Errors:**

* **Providing Invalid Certificate Data:** A common programming error is attempting to create a certificate object from malformed or incomplete byte arrays. The `CreateCERTCertificateFromBytesGarbage` test specifically checks for this scenario and expects the function to return `nullptr`.

   ```c++
   // Example of incorrect usage:
   const uint8_t bad_data[] = "this is not a valid certificate";
   ScopedCERTCertificate bad_cert(
       x509_util::CreateCERTCertificateFromBytes(bad_data));
   // Developers need to check if bad_cert is not null before using it.
   if (!bad_cert) {
     // Handle the error, e.g., log it, return an error code.
   }
   ```

* **Incorrectly Handling Certificate Chains:** When dealing with certificate chains, developers might provide the intermediate certificates in the wrong order or miss some intermediate certificates. The `CreateCERTCertificateListFromX509CertificateErrors` test demonstrates how the system handles invalid intermediate certificates. Forgetting to include necessary intermediate certificates can lead to certificate verification failures.

* **Memory Management Issues:**  While the `ScopedCERTCertificate` type helps with RAII (Resource Acquisition Is Initialization), manually managing `CERTCertificate*` pointers without proper cleanup can lead to memory leaks. The unit tests implicitly check for these issues by ensuring proper destruction of objects.

**User Operations Leading to This Code (Debugging Context):**

Imagine a scenario where a user is experiencing issues with a website's security:

1. **User Action:** The user navigates to an HTTPS website and encounters a "Your connection is not private" error or a similar security warning.
2. **Browser Action:** The browser attempts to establish a secure connection, which involves:
   * Fetching the server's certificate.
   * Verifying the certificate's validity (checking expiry dates, signatures, trust chain).
3. **Potential Issues and Debugging Entry Point:** If the certificate verification fails, developers might need to investigate the root cause. This could involve:
   * **Examining the Server's Certificate:** Using browser developer tools or command-line tools like `openssl s_client -connect <host>:<port>` to inspect the certificate presented by the server.
   * **Analyzing the Certificate Chain:** Checking if all necessary intermediate certificates are present and valid.
   * **Debugging Chromium's Network Stack:** If the issue seems to be within the browser's certificate handling logic, developers might set breakpoints in code related to certificate parsing and verification. This is where files like `x509_util_nss_unittest.cc` and the corresponding source code (`x509_util_nss.cc`) become relevant.
4. **Stepping Through the Code:**  A developer debugging a certificate verification issue might step through functions like:
   * `x509_util::CreateCERTCertificateFromBytes`: To see if the server's certificate can be parsed correctly.
   * `x509_util::IsSameCertificate`: To compare certificates in the chain against known trusted roots.
   * `x509_util::GetValidityTimes`: To check if the certificate has expired.
   * Functions in `x509_cert_verify_proc_nss.cc` (which likely uses the utilities tested here) to understand the trust evaluation process.

In essence, while the user's direct interaction is with the browser, the underlying mechanics of secure communication, especially certificate handling, rely on the correct functioning of the code being tested in this unit test file. Developers use these unit tests to ensure the reliability and correctness of these fundamental network security components.

Prompt: 
```
这是目录为net/cert/x509_util_nss_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/x509_util_nss.h"

#include <string_view>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/time/time.h"
#include "net/cert/scoped_nss_types.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "net/test/cert_test_util.h"
#include "net/test/test_certificate_data.h"
#include "net/test/test_data_directory.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

std::string BytesForNSSCert(CERTCertificate* cert) {
  std::string der_encoded;
  if (!x509_util::GetDEREncoded(cert, &der_encoded))
    ADD_FAILURE();
  return der_encoded;
}

}  // namespace

TEST(X509UtilNSSTest, IsSameCertificate) {
  ScopedCERTCertificate google_nss_cert(
      x509_util::CreateCERTCertificateFromBytes(google_der));
  ASSERT_TRUE(google_nss_cert);

  ScopedCERTCertificate google_nss_cert2(
      x509_util::CreateCERTCertificateFromBytes(google_der));
  ASSERT_TRUE(google_nss_cert2);

  ScopedCERTCertificate webkit_nss_cert(
      x509_util::CreateCERTCertificateFromBytes(webkit_der));
  ASSERT_TRUE(webkit_nss_cert);

  scoped_refptr<X509Certificate> google_x509_cert(
      X509Certificate::CreateFromBytes(google_der));
  ASSERT_TRUE(google_x509_cert);

  scoped_refptr<X509Certificate> webkit_x509_cert(
      X509Certificate::CreateFromBytes(webkit_der));
  ASSERT_TRUE(webkit_x509_cert);

  EXPECT_TRUE(x509_util::IsSameCertificate(google_nss_cert.get(),
                                           google_nss_cert.get()));
  EXPECT_TRUE(x509_util::IsSameCertificate(google_nss_cert.get(),
                                           google_nss_cert2.get()));
  EXPECT_TRUE(x509_util::IsSameCertificate(google_nss_cert.get(),
                                           google_x509_cert.get()));
  EXPECT_TRUE(x509_util::IsSameCertificate(google_x509_cert.get(),
                                           google_nss_cert.get()));

  EXPECT_TRUE(x509_util::IsSameCertificate(webkit_nss_cert.get(),
                                           webkit_nss_cert.get()));
  EXPECT_TRUE(x509_util::IsSameCertificate(webkit_nss_cert.get(),
                                           webkit_x509_cert.get()));
  EXPECT_TRUE(x509_util::IsSameCertificate(webkit_x509_cert.get(),
                                           webkit_nss_cert.get()));

  EXPECT_FALSE(x509_util::IsSameCertificate(google_nss_cert.get(),
                                            webkit_nss_cert.get()));
  EXPECT_FALSE(x509_util::IsSameCertificate(google_nss_cert.get(),
                                            webkit_x509_cert.get()));
  EXPECT_FALSE(x509_util::IsSameCertificate(google_x509_cert.get(),
                                            webkit_nss_cert.get()));
}

TEST(X509UtilNSSTest, CreateCERTCertificateFromBytes) {
  ScopedCERTCertificate google_cert(
      x509_util::CreateCERTCertificateFromBytes(google_der));
  ASSERT_TRUE(google_cert);
  EXPECT_STREQ(
      "CN=www.google.com,O=Google Inc,L=Mountain View,ST=California,C=US",
      google_cert->subjectName);
}

TEST(X509UtilNSSTest, CreateCERTCertificateFromBytesGarbage) {
  EXPECT_EQ(nullptr, x509_util::CreateCERTCertificateFromBytes(
                         base::span<const uint8_t>()));

  static const uint8_t garbage_data[] = "garbage";
  EXPECT_EQ(nullptr, x509_util::CreateCERTCertificateFromBytes(garbage_data));
}

TEST(X509UtilNSSTest, CreateCERTCertificateFromX509Certificate) {
  scoped_refptr<X509Certificate> x509_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");
  ASSERT_TRUE(x509_cert);
  ScopedCERTCertificate nss_cert =
      x509_util::CreateCERTCertificateFromX509Certificate(x509_cert.get());
  ASSERT_TRUE(nss_cert);
  EXPECT_STREQ("CN=127.0.0.1,O=Test CA,L=Mountain View,ST=California,C=US",
               nss_cert->subjectName);
}

TEST(X509UtilNSSTest, CreateCERTCertificateListFromX509Certificate) {
  scoped_refptr<X509Certificate> x509_cert = CreateCertificateChainFromFile(
      GetTestCertsDirectory(), "multi-root-chain1.pem",
      X509Certificate::FORMAT_PEM_CERT_SEQUENCE);
  ASSERT_TRUE(x509_cert);
  EXPECT_EQ(3U, x509_cert->intermediate_buffers().size());

  ScopedCERTCertificateList nss_certs =
      x509_util::CreateCERTCertificateListFromX509Certificate(x509_cert.get());
  ASSERT_EQ(4U, nss_certs.size());
  for (int i = 0; i < 4; ++i)
    ASSERT_TRUE(nss_certs[i]);

  EXPECT_EQ(x509_util::CryptoBufferAsStringPiece(x509_cert->cert_buffer()),
            BytesForNSSCert(nss_certs[0].get()));
  EXPECT_EQ(x509_util::CryptoBufferAsStringPiece(
                x509_cert->intermediate_buffers()[0].get()),
            BytesForNSSCert(nss_certs[1].get()));
  EXPECT_EQ(x509_util::CryptoBufferAsStringPiece(
                x509_cert->intermediate_buffers()[1].get()),
            BytesForNSSCert(nss_certs[2].get()));
  EXPECT_EQ(x509_util::CryptoBufferAsStringPiece(
                x509_cert->intermediate_buffers()[2].get()),
            BytesForNSSCert(nss_certs[3].get()));
}

TEST(X509UtilTest, CreateCERTCertificateListFromX509CertificateErrors) {
  scoped_refptr<X509Certificate> ok_cert(
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem"));
  ASSERT_TRUE(ok_cert);

  bssl::UniquePtr<CRYPTO_BUFFER> bad_cert =
      x509_util::CreateCryptoBuffer(std::string_view("invalid"));
  ASSERT_TRUE(bad_cert);

  scoped_refptr<X509Certificate> ok_cert2(
      ImportCertFromFile(GetTestCertsDirectory(), "root_ca_cert.pem"));
  ASSERT_TRUE(ok_cert);

  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
  intermediates.push_back(std::move(bad_cert));
  intermediates.push_back(bssl::UpRef(ok_cert2->cert_buffer()));
  scoped_refptr<X509Certificate> cert_with_intermediates(
      X509Certificate::CreateFromBuffer(bssl::UpRef(ok_cert->cert_buffer()),
                                        std::move(intermediates)));
  ASSERT_TRUE(cert_with_intermediates);
  EXPECT_EQ(2U, cert_with_intermediates->intermediate_buffers().size());

  // Normal CreateCERTCertificateListFromX509Certificate fails with invalid
  // certs in chain.
  ScopedCERTCertificateList nss_certs =
      x509_util::CreateCERTCertificateListFromX509Certificate(
          cert_with_intermediates.get());
  EXPECT_TRUE(nss_certs.empty());

  // With InvalidIntermediateBehavior::kIgnore, invalid intermediate certs
  // should be silently dropped.
  nss_certs = x509_util::CreateCERTCertificateListFromX509Certificate(
      cert_with_intermediates.get(),
      x509_util::InvalidIntermediateBehavior::kIgnore);
  ASSERT_EQ(2U, nss_certs.size());
  for (const auto& nss_cert : nss_certs)
    ASSERT_TRUE(nss_cert.get());

  EXPECT_EQ(x509_util::CryptoBufferAsStringPiece(ok_cert->cert_buffer()),
            BytesForNSSCert(nss_certs[0].get()));
  EXPECT_EQ(x509_util::CryptoBufferAsStringPiece(ok_cert2->cert_buffer()),
            BytesForNSSCert(nss_certs[1].get()));
}

TEST(X509UtilNSSTest, CreateCERTCertificateListFromBytes) {
  base::FilePath cert_path =
      GetTestCertsDirectory().AppendASCII("multi-root-chain1.pem");
  std::string cert_data;
  ASSERT_TRUE(base::ReadFileToString(cert_path, &cert_data));

  ScopedCERTCertificateList certs =
      x509_util::CreateCERTCertificateListFromBytes(
          base::as_byte_span(cert_data), X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(4U, certs.size());
  EXPECT_STREQ("CN=127.0.0.1,O=Test CA,L=Mountain View,ST=California,C=US",
               certs[0]->subjectName);
  EXPECT_STREQ("CN=B CA - Multi-root", certs[1]->subjectName);
  EXPECT_STREQ("CN=C CA - Multi-root", certs[2]->subjectName);
  EXPECT_STREQ("CN=D Root CA - Multi-root", certs[3]->subjectName);
}

TEST(X509UtilNSSTest, DupCERTCertificate) {
  ScopedCERTCertificate cert(
      x509_util::CreateCERTCertificateFromBytes(google_der));
  ASSERT_TRUE(cert);

  ScopedCERTCertificate cert2 = x509_util::DupCERTCertificate(cert.get());
  // Both handles should hold a reference to the same CERTCertificate object.
  ASSERT_EQ(cert.get(), cert2.get());

  // Release the initial handle.
  cert.reset();
  // The duped handle should still be safe to access.
  EXPECT_STREQ(
      "CN=www.google.com,O=Google Inc,L=Mountain View,ST=California,C=US",
      cert2->subjectName);
}

TEST(X509UtilNSSTest, DupCERTCertificateList) {
  ScopedCERTCertificate cert(
      x509_util::CreateCERTCertificateFromBytes(google_der));
  ASSERT_TRUE(cert);
  ScopedCERTCertificate cert2(
      x509_util::CreateCERTCertificateFromBytes(webkit_der));
  ASSERT_TRUE(cert2);
  ScopedCERTCertificateList certs;
  certs.push_back(std::move(cert));
  certs.push_back(std::move(cert2));

  ScopedCERTCertificateList certs_dup =
      x509_util::DupCERTCertificateList(certs);
  ASSERT_EQ(2U, certs_dup.size());
  ASSERT_EQ(certs[0].get(), certs_dup[0].get());
  ASSERT_EQ(certs[1].get(), certs_dup[1].get());

  // Release the initial handles.
  certs.clear();
  // The duped handles should still be safe to access.
  EXPECT_STREQ(
      "CN=www.google.com,O=Google Inc,L=Mountain View,ST=California,C=US",
      certs_dup[0]->subjectName);
  EXPECT_STREQ(
      "CN=*.webkit.org,OU=Mac OS Forge,O=Apple "
      "Inc.,L=Cupertino,ST=California,C=US",
      certs_dup[1]->subjectName);
}

TEST(X509UtilNSSTest, DupCERTCertificateList_EmptyList) {
  EXPECT_EQ(0U, x509_util::DupCERTCertificateList({}).size());
}

TEST(X509UtilNSSTest, CreateX509CertificateFromCERTCertificate_NoChain) {
  ScopedCERTCertificate nss_cert(
      x509_util::CreateCERTCertificateFromBytes(google_der));
  ASSERT_TRUE(nss_cert);
  scoped_refptr<X509Certificate> x509_cert =
      x509_util::CreateX509CertificateFromCERTCertificate(nss_cert.get());
  EXPECT_EQ(BytesForNSSCert(nss_cert.get()),
            x509_util::CryptoBufferAsStringPiece(x509_cert->cert_buffer()));
  EXPECT_TRUE(x509_cert->intermediate_buffers().empty());
}

TEST(X509UtilNSSTest, CreateX509CertificateFromCERTCertificate_EmptyChain) {
  ScopedCERTCertificate nss_cert(
      x509_util::CreateCERTCertificateFromBytes(google_der));
  ASSERT_TRUE(nss_cert);
  scoped_refptr<X509Certificate> x509_cert =
      x509_util::CreateX509CertificateFromCERTCertificate(
          nss_cert.get(), std::vector<CERTCertificate*>());
  EXPECT_EQ(BytesForNSSCert(nss_cert.get()),
            x509_util::CryptoBufferAsStringPiece(x509_cert->cert_buffer()));
  EXPECT_TRUE(x509_cert->intermediate_buffers().empty());
}

TEST(X509UtilNSSTest, CreateX509CertificateFromCERTCertificate_WithChain) {
  ScopedCERTCertificate nss_cert(
      x509_util::CreateCERTCertificateFromBytes(google_der));
  ASSERT_TRUE(nss_cert);
  ScopedCERTCertificate nss_cert2(
      x509_util::CreateCERTCertificateFromBytes(webkit_der));
  ASSERT_TRUE(nss_cert2);

  std::vector<CERTCertificate*> chain;
  chain.push_back(nss_cert2.get());

  scoped_refptr<X509Certificate> x509_cert =
      x509_util::CreateX509CertificateFromCERTCertificate(nss_cert.get(),
                                                          chain);
  EXPECT_EQ(BytesForNSSCert(nss_cert.get()),
            x509_util::CryptoBufferAsStringPiece(x509_cert->cert_buffer()));
  ASSERT_EQ(1U, x509_cert->intermediate_buffers().size());
  EXPECT_EQ(x509_util::CryptoBufferAsStringPiece(
                x509_cert->intermediate_buffers()[0].get()),
            BytesForNSSCert(nss_cert2.get()));
}

TEST(X509UtilNSSTest, CreateX509CertificateListFromCERTCertificates) {
  ScopedCERTCertificate nss_cert(
      x509_util::CreateCERTCertificateFromBytes(google_der));
  ASSERT_TRUE(nss_cert);
  ScopedCERTCertificate nss_cert2(
      x509_util::CreateCERTCertificateFromBytes(webkit_der));
  ASSERT_TRUE(nss_cert2);
  ScopedCERTCertificateList nss_certs;
  nss_certs.push_back(std::move(nss_cert));
  nss_certs.push_back(std::move(nss_cert2));

  CertificateList x509_certs =
      x509_util::CreateX509CertificateListFromCERTCertificates(nss_certs);
  ASSERT_EQ(2U, x509_certs.size());

  EXPECT_EQ(BytesForNSSCert(nss_certs[0].get()),
            x509_util::CryptoBufferAsStringPiece(x509_certs[0]->cert_buffer()));
  EXPECT_EQ(BytesForNSSCert(nss_certs[1].get()),
            x509_util::CryptoBufferAsStringPiece(x509_certs[1]->cert_buffer()));
}

TEST(X509UtilNSSTest, CreateX509CertificateListFromCERTCertificates_EmptyList) {
  ScopedCERTCertificateList nss_certs;
  CertificateList x509_certs =
      x509_util::CreateX509CertificateListFromCERTCertificates(nss_certs);
  ASSERT_EQ(0U, x509_certs.size());
}

TEST(X509UtilNSSTest, GetDEREncoded) {
  ScopedCERTCertificate google_cert(
      x509_util::CreateCERTCertificateFromBytes(google_der));
  ASSERT_TRUE(google_cert);
  std::string der_encoded;
  ASSERT_TRUE(x509_util::GetDEREncoded(google_cert.get(), &der_encoded));
  EXPECT_EQ(std::string(reinterpret_cast<const char*>(google_der),
                        std::size(google_der)),
            der_encoded);
}

TEST(X509UtilNSSTest, GetDefaultNickname) {
  base::FilePath certs_dir = GetTestCertsDirectory();

  ScopedCERTCertificate test_cert = ImportCERTCertificateFromFile(
      certs_dir, "no_subject_common_name_cert.pem");
  ASSERT_TRUE(test_cert);

  std::string nickname = x509_util::GetDefaultUniqueNickname(
      test_cert.get(), USER_CERT, nullptr /*slot*/);
  EXPECT_EQ(
      "wtc@google.com's COMODO Client Authentication and "
      "Secure Email CA ID",
      nickname);
}

TEST(X509UtilNSSTest, GetCERTNameDisplayName_CN) {
  base::FilePath certs_dir = GetTestCertsDirectory();

  ScopedCERTCertificate test_cert =
      ImportCERTCertificateFromFile(certs_dir, "ok_cert.pem");
  ASSERT_TRUE(test_cert);
  scoped_refptr<X509Certificate> x509_test_cert =
      ImportCertFromFile(certs_dir, "ok_cert.pem");
  ASSERT_TRUE(x509_test_cert);

  std::string name = x509_util::GetCERTNameDisplayName(&test_cert->subject);
  EXPECT_EQ("127.0.0.1", name);
  EXPECT_EQ(x509_test_cert->subject().GetDisplayName(), name);
}

TEST(X509UtilNSSTest, GetCERTNameDisplayName_O) {
  base::FilePath certs_dir =
      GetTestNetDataDirectory().AppendASCII("parse_certificate_unittest");

  ScopedCERTCertificate test_cert =
      ImportCERTCertificateFromFile(certs_dir, "subject_t61string.pem");
  ASSERT_TRUE(test_cert);
  scoped_refptr<X509Certificate> x509_test_cert =
      ImportCertFromFile(certs_dir, "subject_t61string.pem");
  ASSERT_TRUE(x509_test_cert);

  std::string name = x509_util::GetCERTNameDisplayName(&test_cert->subject);
  EXPECT_EQ(
      " !\"#$%&'()*+,-./"
      "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
      "abcdefghijklmnopqrstuvwxyz{|}~"
      " ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæç"
      "èéêëìíîïðñòóôõö÷øùúûüýþÿ",
      name);
  EXPECT_EQ(x509_test_cert->subject().GetDisplayName(), name);
}

TEST(X509UtilNSSTest, ParseClientSubjectAltNames) {
  base::FilePath certs_dir = GetTestCertsDirectory();

  // This cert contains one rfc822Name field, and one Microsoft UPN
  // otherName field.
  ScopedCERTCertificate san_cert =
      ImportCERTCertificateFromFile(certs_dir, "client_3.pem");
  ASSERT_TRUE(san_cert);

  std::vector<std::string> rfc822_names;
  x509_util::GetRFC822SubjectAltNames(san_cert.get(), &rfc822_names);
  ASSERT_EQ(1U, rfc822_names.size());
  EXPECT_EQ("santest@example.com", rfc822_names[0]);

  std::vector<std::string> upn_names;
  x509_util::GetUPNSubjectAltNames(san_cert.get(), &upn_names);
  ASSERT_EQ(1U, upn_names.size());
  EXPECT_EQ("santest@ad.corp.example.com", upn_names[0]);
}

TEST(X509UtilNSSTest, GetValidityTimes) {
  ScopedCERTCertificate google_cert(
      x509_util::CreateCERTCertificateFromBytes(google_der));
  ASSERT_TRUE(google_cert);

  base::Time not_before, not_after;
  EXPECT_TRUE(
      x509_util::GetValidityTimes(google_cert.get(), &not_before, &not_after));

  // Constants copied from x509_certificate_unittest.cc.
  EXPECT_EQ(1238192407,  // Mar 27 22:20:07 2009 GMT
            not_before.InSecondsFSinceUnixEpoch());
  EXPECT_EQ(1269728407,  // Mar 27 22:20:07 2010 GMT
            not_after.InSecondsFSinceUnixEpoch());
}

TEST(X509UtilNSSTest, GetValidityTimesOptionalArgs) {
  ScopedCERTCertificate google_cert(
      x509_util::CreateCERTCertificateFromBytes(google_der));
  ASSERT_TRUE(google_cert);

  base::Time not_before;
  EXPECT_TRUE(
      x509_util::GetValidityTimes(google_cert.get(), &not_before, nullptr));
  // Constants copied from x509_certificate_unittest.cc.
  EXPECT_EQ(1238192407,  // Mar 27 22:20:07 2009 GMT
            not_before.InSecondsFSinceUnixEpoch());

  base::Time not_after;
  EXPECT_TRUE(
      x509_util::GetValidityTimes(google_cert.get(), nullptr, &not_after));
  EXPECT_EQ(1269728407,  // Mar 27 22:20:07 2010 GMT
            not_after.InSecondsFSinceUnixEpoch());
}

TEST(X509UtilNSSTest, CalculateFingerprint256) {
  static const SHA256HashValue google_fingerprint = {
      {0x21, 0xaf, 0x58, 0x74, 0xea, 0x6b, 0xad, 0xbd, 0xe4, 0xb3, 0xb1,
       0xaa, 0x53, 0x32, 0x80, 0x8f, 0xbf, 0x8a, 0x24, 0x7d, 0x98, 0xec,
       0x7f, 0x77, 0x49, 0x38, 0x42, 0x81, 0x26, 0x7f, 0xed, 0x38}};

  ScopedCERTCertificate google_cert(
      x509_util::CreateCERTCertificateFromBytes(google_der));
  ASSERT_TRUE(google_cert);

  EXPECT_EQ(google_fingerprint,
            x509_util::CalculateFingerprint256(google_cert.get()));
}

}  // namespace net

"""

```