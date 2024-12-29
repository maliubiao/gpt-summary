Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Understand the Goal:** The request asks for an analysis of a specific C++ file (`cert_util_unittest.cc`) within the Chromium project's network stack. The key areas of focus are its functionality, relationship to JavaScript, logic and examples, common user errors, and how a user might reach this code (debugging context).

2. **Identify the File Type and Purpose:** The filename `cert_util_unittest.cc` strongly suggests this is a unit test file. Unit tests are designed to verify the correctness of individual units of code (in this case, functions or classes related to certificate utilities).

3. **Scan for Key Includes:** The `#include` directives at the beginning are crucial. They tell us about the dependencies and the area the file focuses on:
    * `"net/tools/transport_security_state_generator/cert_util.h"`:  This is the header file for the code being tested. It confirms the file is testing certificate utility functions.
    * `"net/tools/transport_security_state_generator/spki_hash.h"`:  Indicates interaction with Subject Public Key Information (SPKI) hashes.
    * `"testing/gmock/include/gmock/gmock.h"` and `"testing/gtest/include/gtest/gtest.h"`: These are the Google Mock and Google Test frameworks, confirming this is a test file.
    * `"third_party/boringssl/src/include/openssl/x509v3.h"`:  This points to the use of the BoringSSL library for X.509 certificate handling.

4. **Analyze the Test Structure:**  Look for the `TEST()` macros. Each `TEST()` defines an individual test case. The names of the tests provide valuable clues about the functionality being tested:
    * `GetX509CertificateFromPEM`:  Suggests testing a function that parses PEM-encoded certificates.
    * `CalculateSPKIHashFromCertificate`: Implies testing SPKI hash calculation from certificates.
    * `CalculateSPKIHashFromKey`: Implies testing SPKI hash calculation from public keys.
    * `ExtractSubjectNameFromCertificate`: Suggests testing the extraction of subject names from certificates.

5. **Examine the Test Logic (Inside the `TEST()` blocks):**  Pay attention to:
    * **Input Data:**  Look for string literals that represent PEM-encoded certificates and public keys (e.g., `kSelfSignedWithCommonNamePEM`, `kPublicKeyPEM`). These are the test inputs. Notice the variations (with and without common names, invalid formats, etc.).
    * **Function Calls:** Identify the functions from `cert_util.h` being called (e.g., `GetX509CertificateFromPEM`, `CalculateSPKIHashFromCertificate`, `CalculateSPKIHashFromKey`, `ExtractSubjectNameFromCertificate`).
    * **Assertions:** Focus on the `EXPECT_NE`, `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, and `EXPECT_THAT` macros. These are the checks that determine if the tested code is behaving as expected. `EXPECT_THAT` often uses matchers like `testing::ElementsAreArray` to compare byte arrays.
    * **Expected Outputs:** Infer the expected outputs based on the input data and the assertions. For example, parsing a valid PEM certificate should return a non-null pointer. Calculating the SPKI hash should produce a specific byte sequence.

6. **Address Specific Questions in the Request:**

    * **Functionality:** Summarize the purpose of the file based on the test names and the functions being tested.
    * **Relationship to JavaScript:** Carefully consider the functions being tested. Certificate handling and SPKI hashes are foundational security concepts, but the *specific C++ code* here isn't directly executed in a JavaScript environment. However, JavaScript running in a browser interacts with these concepts indirectly (e.g., when establishing secure connections). Provide concrete examples of this indirect relationship.
    * **Logic and Examples (Input/Output):** For each test case, describe the input (the PEM strings) and the expected output (the assertion results). This demonstrates logical reasoning based on the test code.
    * **Common User Errors:** Think about what mistakes a developer or user might make when dealing with certificates and public keys. Invalid PEM formatting, incorrect headers, and expecting specific subject fields to always be present are common issues. Relate these errors back to the tests that specifically check for these scenarios.
    * **User Operations and Debugging:**  Consider how a user's actions in a browser (navigating to a secure site, encountering certificate errors) might lead to the execution of code related to certificate handling. Explain how a developer might use these unit tests during debugging (e.g., to isolate and fix issues in the certificate parsing or SPKI calculation logic).

7. **Structure the Answer:** Organize the findings logically, addressing each part of the original request clearly and concisely. Use headings and bullet points to improve readability.

8. **Review and Refine:** After drafting the answer, review it for accuracy, clarity, and completeness. Ensure that the examples are relevant and that the explanations are easy to understand. For instance, initially, I might have just said "parses certificates."  Refining it to "parses PEM-encoded X.509 certificates" is more precise. Similarly, explaining the *indirect* relationship with JavaScript is crucial.
This file, `cert_util_unittest.cc`, within the Chromium network stack, serves as a **unit test suite** for the `cert_util.h` file located in the same directory. Its primary function is to **verify the correctness and robustness of the certificate utility functions** provided by `cert_util.h`.

Here's a breakdown of its functionalities:

**1. Testing Certificate Parsing:**

* **Function:**  It tests the ability of functions (likely `GetX509CertificateFromPEM`) to correctly parse PEM-encoded X.509 certificates.
* **Logic & Examples:**
    * **Valid Certificates:** It uses various valid PEM-encoded certificates (`kSelfSignedWithCommonNamePEM`, `kSelfSignedWithoutCommonNamePEM`, `kSelfSignedWithoutSubject`) as input and asserts that the parsing function returns a valid `X509` object (not null).
    * **Invalid Certificates:** It provides invalid PEM-encoded data (`kInvalidCertificatePEM`) and asserts that the parsing function correctly returns a null pointer, indicating failure.
    * **Incorrect PEM Types:** It tests cases where the PEM headers are incorrect (`kUnknownPEMHeaders`) or represent a public key instead of a certificate (`kInvalidPublicKeyPEM`) and verifies that the parsing function handles these cases appropriately (likely by returning null).
    * **Assumption:** The underlying parsing logic should be able to handle certificates with and without common names in the subject field, as well as certificates with minimal subject information.
    * **Input (Example):** `kSelfSignedWithCommonNamePEM` (a string containing a valid PEM-encoded certificate).
    * **Output (Example):** A non-null `bssl::UniquePtr<X509>` object representing the parsed certificate.

**2. Testing SPKI (Subject Public Key Information) Hash Calculation:**

* **Function:** It tests the ability of functions (likely `CalculateSPKIHashFromCertificate` and `CalculateSPKIHashFromKey`) to compute the correct SHA-256 hash of the Subject Public Key Info from both certificates and raw public keys.
* **Logic & Examples:**
    * **From Certificates:** It takes valid, parsed `X509` certificates and asserts that the calculated SPKI hash matches a pre-computed expected hash value.
        * **Input (Example):** A parsed `X509` certificate from `kSelfSignedWithCommonNamePEM`.
        * **Output (Example):** The `SPKIHash` structure containing the byte array: `{0xAC, 0xFB, 0x2B, 0xF3, 0x6A, 0x90, 0x47, 0xF1, 0x74, 0xAE, 0xF1, 0xCE, 0x63, 0x3D, 0xA9, 0x45, 0xCB, 0xA,  0xA7, 0x3F, 0x16, 0x2A, 0xF3, 0x88, 0x9A, 0xE2, 0x72, 0xC,  0x07, 0x63, 0x45, 0xB0}`.
    * **From Public Keys:** It takes PEM-encoded public keys and asserts that the calculated SPKI hash matches the expected value. It also tests cases with invalid PEM-encoded public keys and incorrect PEM headers, expecting the function to fail.
        * **Input (Example):** `kPublicKeyPEM` (a string containing a valid PEM-encoded public key).
        * **Output (Example):** The `SPKIHash` structure containing the byte array: `{0x63, 0xB0, 0x21, 0x4,  0x3,  0x13, 0x9E, 0x36, 0xEE, 0xCB, 0x6F, 0xA5, 0x7A, 0x94, 0x56, 0x18, 0xBA, 0x41, 0x13, 0x8C, 0x4A, 0x48, 0x99, 0x80, 0x51, 0x66, 0xF8, 0x85, 0x2,  0xFC, 0x48, 0x9E}`.
    * **Assumption:** The SPKI hash calculation logic correctly implements the standard algorithm (likely SHA-256) on the public key portion of the certificate or the provided public key.

**3. Testing Subject Name Extraction:**

* **Function:** It tests the ability of a function (likely `ExtractSubjectNameFromCertificate`) to extract a human-readable subject name from a parsed X.509 certificate.
* **Logic & Examples:**
    * **With Common Name:** For certificates containing a subject common name (CN), it asserts that the extracted name is the value of the CN.
        * **Input (Example):** A parsed `X509` certificate from `kSelfSignedWithCommonNamePEM`.
        * **Output (Example):** The string "Chromium".
    * **Without Common Name:** For certificates lacking a CN, it asserts that the extracted name is constructed by concatenating the subject organization (O) and organizational unit (OU) fields, separated by a space.
        * **Input (Example):** A parsed `X509` certificate from `kSelfSignedWithoutCommonNamePEM`.
        * **Output (Example):** The string "The Chromium Projects Security".
    * **Without Subject Information:** For certificates with minimal subject information, it asserts that the extraction function fails (returns `false`).
        * **Input (Example):** A parsed `X509` certificate from `kSelfSignedWithoutSubject`.
        * **Output (Example):** `false`.
    * **Assumption:** The name extraction logic prioritizes the common name if present, and falls back to organization and organizational unit if the common name is missing.

**Relationship to JavaScript:**

While this C++ code doesn't directly execute in a JavaScript environment, it is **indirectly related** to JavaScript functionality, particularly in the context of web browsers:

* **TLS/SSL Connections:** When a browser (which heavily uses JavaScript) establishes a secure HTTPS connection to a website, it receives a server certificate. The browser's underlying network stack (including code like this) parses and validates this certificate.
* **Certificate Pinning/Public Key Pinning:**  The SPKI hashes calculated by functions tested here are crucial for certificate pinning or public key pinning. This security mechanism allows websites to instruct browsers to only trust specific certificates or public keys for their domain, mitigating the risk of man-in-the-middle attacks. JavaScript code within a website might interact with browser APIs related to pinning.
* **Web Crypto API:** The Web Crypto API in JavaScript allows web pages to perform cryptographic operations. While it doesn't directly call these C++ functions, it works with the same underlying cryptographic principles and data structures (like public keys) that this code manipulates.

**Example of Indirect Relationship:**

1. A user navigates to `https://example.com` in their Chrome browser.
2. The browser initiates a TLS handshake with the server.
3. The server sends its SSL certificate to the browser.
4. **The C++ code tested by `cert_util_unittest.cc` (specifically the functions in `cert_util.h`) is used to parse this server certificate.**
5. If `example.com` has implemented HTTP Public Key Pinning (HPKP) or a similar mechanism, the browser might use the SPKI hash of the server's public key (calculated by functions like `CalculateSPKIHashFromCertificate`) to verify if the received certificate matches the pinned key.
6. JavaScript code on the `example.com` website might interact with the browser's security features, potentially influenced by the success or failure of certificate validation performed by this C++ code.

**Common User or Programming Errors and Examples:**

1. **Incorrect PEM Formatting:**
   * **Error:** Providing a certificate or public key with invalid base64 encoding or missing/incorrect `BEGIN`/`END` markers.
   * **Example:** Trying to parse `kInvalidCertificatePEM` or `kInvalidPublicKeyPEM`. The test asserts that `GetX509CertificateFromPEM` and similar functions return null in such cases.

2. **Expecting Common Name to Always Exist:**
   * **Error:**  Assuming every certificate will have a subject common name and failing to handle cases where it's missing.
   * **Example:** The test case `ExtractSubjectNameFromCertificate` checks how the code handles certificates without a common name (`kSelfSignedWithoutCommonNamePEM`), demonstrating the fallback mechanism to organization and organizational unit. A developer might incorrectly assume they can always access the common name directly.

3. **Using the Wrong PEM Type:**
   * **Error:** Trying to parse a public key using a function intended for certificates, or vice-versa.
   * **Example:** The test case `GetX509CertificateFromPEM` with `kInvalidPublicKeyPEM` demonstrates that the certificate parsing function should not successfully parse a public key.

4. **Incorrectly Calculating or Comparing SPKI Hashes:**
   * **Error:** Implementing SPKI hash calculation incorrectly or comparing hashes against the wrong expected values.
   * **Example:** The `CalculateSPKIHashFromCertificate` and `CalculateSPKIHashFromKey` tests use hardcoded expected hash values to ensure the calculation logic is correct. A developer implementing similar functionality might make mistakes in the hashing algorithm or the data being hashed.

**User Operations and Debugging线索 (Debugging Clues):**

A user's actions can lead to this code being executed in various scenarios. Here's a step-by-step example leading to potential debugging involving `cert_util_unittest.cc`:

1. **User Action:** A user navigates to a website using HTTPS in their Chrome browser (e.g., `https://example.com`).

2. **Browser Behavior:** The browser initiates a secure connection, and the server presents its SSL/TLS certificate.

3. **Network Stack Involvement:** The browser's network stack receives the certificate data.

4. **Certificate Parsing:** The functions tested by `cert_util_unittest.cc` (specifically those in `cert_util.h`) are invoked to parse the raw certificate data (likely in PEM or DER format) into an internal representation (like `X509`).

5. **Potential Issues and Debugging:**

   * **Certificate Parsing Errors:** If the server's certificate is malformed or uses an unusual format, the parsing functions might fail. A developer debugging this issue might use the tests in `cert_util_unittest.cc` to:
      * **Reproduce the parsing failure:** Create a test case with a similar malformed certificate to see if the parsing function behaves as expected (returns null).
      * **Verify the parsing logic:** Step through the parsing code in `cert_util.cc` to understand why it's failing with the specific certificate.

   * **SPKI Hash Mismatch (Certificate Pinning Issues):** If the website has certificate pinning enabled and the server presents a certificate whose SPKI hash doesn't match the pinned value, the connection will fail. A developer debugging this might:
      * **Verify SPKI calculation:** Use the `CalculateSPKIHashFromCertificate` test with the server's actual certificate to confirm the SPKI hash is being calculated correctly.
      * **Compare with pinned values:**  Check if the calculated SPKI hash matches the pinned values configured for the website.

   * **Subject Name Extraction Issues:**  In scenarios where the browser needs to display information about the certificate (e.g., in the certificate viewer), the subject name extraction function is used. If the displayed name is incorrect, a developer might:
      * **Test subject name extraction:** Use the `ExtractSubjectNameFromCertificate` test with the problematic certificate to see if the extracted name matches expectations.
      * **Debug the extraction logic:** Step through the code in `cert_util.cc` to understand how the subject name is being extracted and identify any errors in the logic.

In essence, `cert_util_unittest.cc` provides a safety net and a debugging tool for developers working on the core certificate handling logic within the Chromium network stack. When users encounter certificate-related issues, these unit tests serve as a starting point for isolating and fixing the underlying problems.

Prompt: 
```
这是目录为net/tools/transport_security_state_generator/cert_util_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include <string>
#include <vector>

#include "net/tools/transport_security_state_generator/cert_util.h"
#include "net/tools/transport_security_state_generator/spki_hash.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/include/openssl/x509v3.h"

namespace net::transport_security_state {

namespace {

// Certficate with the subject CN set to "Chromium", the subject organisation
// set to "The Chromium Projects", and the subject organizational unit set to
// "Security."
static const char kSelfSignedWithCommonNamePEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDeTCCAmGgAwIBAgIJAKZbsC4gPYAUMA0GCSqGSIb3DQEBCwUAMFMxETAPBgNV\n"
    "BAMMCENocm9taXVtMR4wHAYDVQQKDBVUaGUgQ2hyb21pdW0gUHJvamVjdHMxETAP\n"
    "BgNVBAsMCFNlY3VyaXR5MQswCQYDVQQGEwJVUzAeFw0xNzAxMjkyMDU1NDFaFw0x\n"
    "ODAxMjkyMDU1NDFaMFMxETAPBgNVBAMMCENocm9taXVtMR4wHAYDVQQKDBVUaGUg\n"
    "Q2hyb21pdW0gUHJvamVjdHMxETAPBgNVBAsMCFNlY3VyaXR5MQswCQYDVQQGEwJV\n"
    "UzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMlir9M85QOvQ5ok+uvH\n"
    "XF7kmW21B22Ffdw+B2mXTV6NLGvINCdwocIlebQlAdWS2QY/WM08uAYJ3m0IGD+t\n"
    "6OG4zG3vOmWMdFQy4XkxMsDkbV11F9n4dsF5TXEvILlupOtOWu6Up8vfFkii/x+/\n"
    "bz4aGBDdFu6U8TdQ8ELSmHxJYi4LM0lUKTdLLte3T5Grv3UUXQW33Qs6RXZlH/ul\n"
    "jf7/v0HQefM3XdT9djG1XRv8Ga32c8tz+wtSw7PPIWjt0ZDJxZ2/fX7YLwAt2D6N\n"
    "zQgrNJtL0/I/j9sO6A0YQeHzmnlyoAd14VhBfEllZc51pFaut31wpbPPxtH0K0Ro\n"
    "2XUCAwEAAaNQME4wHQYDVR0OBBYEFD7eitJ8KlIaVS4J9w2Nz+5OE8H0MB8GA1Ud\n"
    "IwQYMBaAFD7eitJ8KlIaVS4J9w2Nz+5OE8H0MAwGA1UdEwQFMAMBAf8wDQYJKoZI\n"
    "hvcNAQELBQADggEBAFjuy0Jhj2E/ALOkOst53/nHIpT5suru4H6YEmmPye+KCQnC\n"
    "ws1msPyLQ8V10/kyQzJTSLbeehNyOaK99KJk+hZBVEKBa9uH3WXPpiwz1xr3STJO\n"
    "hhV2wXGTMqe5gryR7r+n88+2TpRiZ/mAVyJm4NQgev4HZbFsl3sT50AQrrEbHHiY\n"
    "Sh38NCR8JCVuzLBjcEEIWxjhDPkdNPJtx3cBkIDP+Cz1AUSPretGk7CQAGivq7Kq\n"
    "9y6A59guc1RFVPeEQAxUIUDZGDQlB3PtmrXrp1/LAaDYvQCstDBgiZoamy+xSROP\n"
    "BU2KIzRj2EUOWqtIURU4Q2QC1fbVqxVjfPowX/A=\n"
    "-----END CERTIFICATE-----\n";

// Certificate without a subject CN. The subject organisation is set to
// "The Chromium Projects" and the subject origanisational unit is set to
// "Security".
static const char kSelfSignedWithoutCommonNamePEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDUzCCAjugAwIBAgIJAI18Ifktf3YOMA0GCSqGSIb3DQEBCwUAMEAxHjAcBgNV\n"
    "BAoMFVRoZSBDaHJvbWl1bSBQcm9qZWN0czERMA8GA1UECwwIU2VjdXJpdHkxCzAJ\n"
    "BgNVBAYTAlVTMB4XDTE3MDEyOTIxMTMwMloXDTE4MDEyOTIxMTMwMlowQDEeMBwG\n"
    "A1UECgwVVGhlIENocm9taXVtIFByb2plY3RzMREwDwYDVQQLDAhTZWN1cml0eTEL\n"
    "MAkGA1UEBhMCVVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCxfBIg\n"
    "4hVljlFbyZ88mhLEKCfy/8X127H16ywcy+q+jlj7YtlWqGKlfIjKQkXKeI/xUB1F\n"
    "ZC1S0kmVycAoahb4m+NqkfBkuxbpc5gYsv9TdgiNIhEezx6Z9OTPjGnTZVDjJNsQ\n"
    "MVKfG+DD3qAf22PhpU2zGXCF2ECL7J/Lh6Wu/W3InuIcJGm3D7F182UK86stvC/+\n"
    "mS9K7AJyX320vHWYsVB/jA9w6cSdlZf454E+wtsS0b+UIMF6fewg2Xb/FYxRsOjp\n"
    "ppVpF8/2v6JzDjBhdZkYufR5M43tCEUBBK6TwfXAPfK3v2IDcoW+iOuztW5/cdTs\n"
    "rVaGK9YqRDIeFWKNAgMBAAGjUDBOMB0GA1UdDgQWBBRh2Ef5+mRtj2sJHpXWlWai\n"
    "D3zNXTAfBgNVHSMEGDAWgBRh2Ef5+mRtj2sJHpXWlWaiD3zNXTAMBgNVHRMEBTAD\n"
    "AQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAmxdLSlb76yre3VmugMQqybSkJr4+OZm6c\n"
    "ES6TQeBzNrbPQhYPAfTUa2i4Cx5r4tMTp1IfUKgtng4qnKyLRgC+BV4zAfSRxbuw\n"
    "aqicO1Whtl/Vs2Cdou10EU68kKOxLqNdzfXVVSQ/HxGFJFFJdSLfjpRTcfbORfeh\n"
    "BfFQkjdlK8DdX8pPLjHImFKXT/8IpPPq41k2KuIhG3cd2vBNV7n7U793LSE+dPQk\n"
    "0jKehPOfiPBl1nWr7ZTF8bYtgxboVsv73E6IoQhPGPnnDF3ISQ5/ulDQNXJr2PI3\n"
    "ZYZ4PtSKcBi97BucW7lkt3bWY44TZGVHY1s4EGQFqU4aDyP+aR7Z\n"
    "-----END CERTIFICATE-----\n";

// Certificate without a subject CN, organisation or organizational unit.
static const char kSelfSignedWithoutSubject[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIC7TCCAdWgAwIBAgIJAOPMcoAKhzZPMA0GCSqGSIb3DQEBCwUAMA0xCzAJBgNV\n"
    "BAYTAlVTMB4XDTE3MDEyOTIxNDA1MloXDTE4MDEyOTIxNDA1MlowDTELMAkGA1UE\n"
    "BhMCVVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLn0oths5iUbDN\n"
    "h5IssWAf4jBRVh0c7AfVpnsriSdpgMEfApjE4Fcb3ma/8g+f2SB0x7bSLKMfpKZl\n"
    "v7tQBuNXsbMcv1l4Ip595ZznSr74Fpuc6K0pqaVUSrgt2EVDp6lx12fFcXMI08Ar\n"
    "76v06loe7HnO+cOCAXn3Yd89UznB7w8a+RiJlUzb4vksksSQyxCOYwahx6kuN9vh\n"
    "MkjmzoVSbO6vtHktECsq5M2k98GZMmbXimW+lkyqsG3qJnmAYsIapDE1droPp5Cx\n"
    "l/tQ95CKEZQDuF4Zv+fgg0eHnnCAhuCPnM8GblOTsAsSjNd8GM+4eJPPtAHdB1nn\n"
    "HCYB/QadAgMBAAGjUDBOMB0GA1UdDgQWBBTxlQlna2f2VttJkEoeayPsCF7SxzAf\n"
    "BgNVHSMEGDAWgBTxlQlna2f2VttJkEoeayPsCF7SxzAMBgNVHRMEBTADAQH/MA0G\n"
    "CSqGSIb3DQEBCwUAA4IBAQBUOmDhs3K1v+tPeO+TWFw8NDfOkcWy6EX+c6K7mSwF\n"
    "mJjqWsEUBp+WbTK6RoVjuLucH5mRF3FmRrW/hOnxIWxpHg5/9vodReLDPnUw0Anb\n"
    "QoxKgJ41VfD8aGK8GDPOrETwbIR6+d9P6bDKukiuW41Yh5TjXLufaQ1g9C1AIEoG\n"
    "88Akr6g9Q0vJJXGl9YcPFz6M1wm3l/lH08v2Ual52elFXYcDcoxhLCOdImmWGlnn\n"
    "MYXxdl1ivj3hHgFXxkIbrlYKVSBhwPPgjVYKkimFcZF5Xw7wfmIl/WUtVaRpmkGp\n"
    "3TgH7jdRQ1WXlROBct/4Z8jzs7i+Ttk8oxct2r+PdqeZ\n"
    "-----END CERTIFICATE-----\n";

// Valid PEM certificate headers but invalid BASE64 content.
static const char kInvalidCertificatePEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "This is invalid base64.\n"
    "It contains some (#$*) invalid characters.\n"
    "-----END CERTIFICATE-----\n";

// Valid PEM public key headers but invalid BASE64 content.
static const char kInvalidPublicKeyPEM[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "This is invalid base64.\n"
    "It contains some (#$*) invalid characters.\n"
    "-----END PUBLIC KEY-----\n";

// Valid 2048 bit RSA public key.
static const char kPublicKeyPEM[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAujzwcb5bJuC/A/Y9izGl\n"
    "LlA3fnKGbeyn53BdVznJN4fQwU82WKVYdqt8d/1ZDRdYyhGrTgXJeCURe9VSJyX1\n"
    "X2a5EApSFsopP8Yjy0Rl6dNOLO84KCW9dPmfHC3uP0ac4hnHT5dUr05YvhJmHCkf\n"
    "as6v/aEgpPLDhRF6UruSUh+gIpUg/F3+vlD99HLfbloukoDtQyxW+86s9sO7RQ00\n"
    "pd79VOoa/v09FvoS7MFgnBBOtvBQLOXjEH7/qBsnrXFtHBeOtxSLar/FL3OhVXuh\n"
    "dUTRyc1Mg0ECtz8zHZugW+LleIm5Bf5Yr0bN1O/HfDPCkDaCldcm6xohEHn9pBaW\n"
    "+wIDAQAB\n"
    "-----END PUBLIC KEY-----\n";

// Valid 2048 bit RSA public key with incorrect PEM headers.
static const char kUnknownPEMHeaders[] =
    "-----BEGIN OF SOMETHING-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAujzwcb5bJuC/A/Y9izGl\n"
    "LlA3fnKGbeyn53BdVznJN4fQwU82WKVYdqt8d/1ZDRdYyhGrTgXJeCURe9VSJyX1\n"
    "X2a5EApSFsopP8Yjy0Rl6dNOLO84KCW9dPmfHC3uP0ac4hnHT5dUr05YvhJmHCkf\n"
    "as6v/aEgpPLDhRF6UruSUh+gIpUg/F3+vlD99HLfbloukoDtQyxW+86s9sO7RQ00\n"
    "pd79VOoa/v09FvoS7MFgnBBOtvBQLOXjEH7/qBsnrXFtHBeOtxSLar/FL3OhVXuh\n"
    "dUTRyc1Mg0ECtz8zHZugW+LleIm5Bf5Yr0bN1O/HfDPCkDaCldcm6xohEHn9pBaW\n"
    "+wIDAQAB\n"
    "-----END OF SOMETHING-----\n";

TEST(CertUtilTest, GetX509CertificateFromPEM) {
  EXPECT_NE(nullptr, GetX509CertificateFromPEM(kSelfSignedWithCommonNamePEM));
  EXPECT_NE(nullptr, GetX509CertificateFromPEM(kSelfSignedWithoutSubject));
  EXPECT_EQ(nullptr, GetX509CertificateFromPEM(kInvalidCertificatePEM));
  EXPECT_EQ(nullptr, GetX509CertificateFromPEM(kInvalidPublicKeyPEM));
}

// Test that the SPKI digest is correctly calculated for valid certificates.
TEST(CertUtilTest, CalculateSPKIHashFromCertificate) {
  SPKIHash hash1;
  bssl::UniquePtr<X509> cert1 =
      GetX509CertificateFromPEM(kSelfSignedWithCommonNamePEM);
  EXPECT_TRUE(CalculateSPKIHashFromCertificate(cert1.get(), &hash1));
  std::vector<uint8_t> hash_vector(hash1.data(), hash1.data() + hash1.size());
  EXPECT_THAT(
      hash_vector,
      testing::ElementsAreArray(
          {0xAC, 0xFB, 0x2B, 0xF3, 0x6A, 0x90, 0x47, 0xF1, 0x74, 0xAE, 0xF1,
           0xCE, 0x63, 0x3D, 0xA9, 0x45, 0xCB, 0xA,  0xA7, 0x3F, 0x16, 0x2A,
           0xF3, 0x88, 0x9A, 0xE2, 0x72, 0xC,  0x07, 0x63, 0x45, 0xB0}));

  SPKIHash hash2;
  bssl::UniquePtr<X509> cert2 =
      GetX509CertificateFromPEM(kSelfSignedWithoutCommonNamePEM);
  EXPECT_TRUE(CalculateSPKIHashFromCertificate(cert2.get(), &hash2));
  std::vector<uint8_t> hash_vector2(hash2.data(), hash2.data() + hash2.size());
  EXPECT_THAT(
      hash_vector2,
      testing::ElementsAreArray(
          {0x40, 0xBC, 0xD6, 0xE4, 0x10, 0x70, 0x37, 0x3C, 0xF7, 0x21, 0x51,
           0xD7, 0x27, 0x64, 0xFD, 0xF1, 0xA,  0x89, 0x0,  0xAD, 0x75, 0xDF,
           0xB3, 0xEA, 0x21, 0xFC, 0x6E, 0x67, 0xD5, 0xAE, 0xA4, 0x94}));
}

// Test that the SPKI digest for public key's are calculated correctly.
TEST(CertUtilTest, CalculateSPKIHashFromKey) {
  SPKIHash hash1;
  EXPECT_TRUE(CalculateSPKIHashFromKey(kPublicKeyPEM, &hash1));
  std::vector<uint8_t> hash_vector(hash1.data(), hash1.data() + hash1.size());
  EXPECT_THAT(
      hash_vector,
      testing::ElementsAreArray(
          {0x63, 0xB0, 0x21, 0x4,  0x3,  0x13, 0x9E, 0x36, 0xEE, 0xCB, 0x6F,
           0xA5, 0x7A, 0x94, 0x56, 0x18, 0xBA, 0x41, 0x13, 0x8C, 0x4A, 0x48,
           0x99, 0x80, 0x51, 0x66, 0xF8, 0x85, 0x2,  0xFC, 0x48, 0x9E}));
  SPKIHash hash2;
  EXPECT_FALSE(CalculateSPKIHashFromKey(kInvalidPublicKeyPEM, &hash2));

  SPKIHash hash3;
  EXPECT_FALSE(
      CalculateSPKIHashFromKey(kSelfSignedWithoutCommonNamePEM, &hash3));

  SPKIHash hash4;
  EXPECT_FALSE(CalculateSPKIHashFromKey(kUnknownPEMHeaders, &hash4));
}

// Test that the subject name is extracted correctly. This should default to the
// subject common name and fall back to the organisation + organizational unit.
TEST(CertUtilTest, ExtractSubjectNameFromCertificate) {
  std::string name1;
  bssl::UniquePtr<X509> cert1 =
      GetX509CertificateFromPEM(kSelfSignedWithCommonNamePEM);
  EXPECT_TRUE(ExtractSubjectNameFromCertificate(cert1.get(), &name1));

  // For certficates with the subject common name field set, we should get the
  // value of the subject common name.
  EXPECT_EQ("Chromium", name1);

  std::string name2;
  bssl::UniquePtr<X509> cert2 =
      GetX509CertificateFromPEM(kSelfSignedWithoutCommonNamePEM);
  EXPECT_TRUE(ExtractSubjectNameFromCertificate(cert2.get(), &name2));

  // For certificates without a subject common name field, we should get
  // the subject organization + " " + organizational unit instead.
  EXPECT_EQ("The Chromium Projects Security", name2);

  std::string name3;
  bssl::UniquePtr<X509> cert3 =
      GetX509CertificateFromPEM(kSelfSignedWithoutSubject);
  EXPECT_FALSE(ExtractSubjectNameFromCertificate(cert3.get(), &name3));
}

}  // namespace

}  // namespace net::transport_security_state

"""

```