Response:
Let's break down the thought process for analyzing this C++ code snippet.

**1. Initial Understanding of the Request:**

The request asks for an analysis of a C++ source file related to ASN.1 parsing within Chromium's network stack. Key aspects to address include:

* **Functionality:** What does the code *do*?  This requires looking at the defined functions and their internal logic.
* **Relationship to JavaScript:** How might this C++ code interact with JavaScript, if at all?  This necessitates thinking about the boundaries between C++ and the browser's JavaScript engine.
* **Logical Reasoning (Hypothetical Inputs/Outputs):** Can we illustrate the function of individual methods with examples?
* **Common Usage Errors:** What mistakes might developers make when using this code?
* **Debugging Clues (User Operations):** How might a user's actions in the browser lead to this code being executed?

**2. High-Level Overview of the Code:**

The first step is to skim the code and identify the main components. Keywords like `net::asn1`, `#include "net/cert/asn1_util.h"`, and calls to `bssl::der::*` immediately suggest this code is involved in parsing ASN.1 encoded data, specifically related to X.509 certificates within the `net` (network) component of Chromium. The presence of functions like `ExtractSubjectFromDERCert`, `ExtractSPKIFromDERCert`, and `ExtractExtensionFromDERCert` reinforces this idea.

**3. Analyzing Individual Functions:**

Next, examine each function in detail:

* **`SeekToSubject`, `SeekToSPKI`, `SeekToExtensions`:** These functions share a common pattern: they take a DER-encoded certificate as input and use a `bssl::der::Parser` to navigate through the ASN.1 structure. They "seek" to specific parts of the certificate (Subject, SubjectPublicKeyInfo, Extensions) by skipping over preceding fields according to the X.509 certificate structure (defined in RFC 5280). This reveals the core functionality: dissecting the certificate's structure.

* **`ExtractExtensionWithOID`:** This function builds upon `SeekToExtensions`. It iterates through the extensions and compares their OIDs (Object Identifiers) to a target OID. This highlights the ability to extract specific extensions.

* **`ExtractSubjectFromDERCert`, `ExtractSPKIFromDERCert`, `ExtractSubjectPublicKeyFromSPKI`:** These are higher-level functions that use the "seek" functions to isolate specific components of the certificate and then extract their raw DER encoding.

* **`HasCanSignHttpExchangesDraftExtension`:** This function demonstrates how to use `ExtractExtensionWithOID` to check for the presence of a specific extension (related to HTTP Exchanges). It also shows how to verify the content of that extension.

* **`ExtractSignatureAlgorithmsFromDERCert`:** This function targets the signature-related parts of the certificate.

* **`ExtractExtensionFromDERCert`:** This function provides a more comprehensive way to extract an extension, including its criticality and content.

**4. Identifying Core Concepts:**

From the function analysis, several key concepts emerge:

* **ASN.1 DER Encoding:** The code deals with binary data encoded using ASN.1 Distinguished Encoding Rules (DER).
* **X.509 Certificates:** The specific ASN.1 structure being parsed is that of an X.509 certificate, used for verifying digital identities.
* **Object Identifiers (OIDs):**  Extensions are identified by OIDs.
* **BoringSSL:** The code relies on BoringSSL's ASN.1 parsing library (`bssl::der::*`).

**5. Addressing the Request's Specific Points:**

Now, systematically address each part of the request:

* **Functionality:** Summarize the core purpose: parsing ASN.1 encoded X.509 certificates to extract specific information.

* **Relationship to JavaScript:** This requires understanding the browser's architecture. C++ handles low-level operations, while JavaScript interacts with the web page. The connection lies in features that rely on certificate information, like TLS/HTTPS. JavaScript might indirectly trigger this C++ code when establishing secure connections or accessing website security information. Provide a concrete example like `chrome.certificateProvider.requestPin`.

* **Logical Reasoning (Hypothetical Inputs/Outputs):**  For each extraction function, create a simplified scenario: a piece of DER-encoded data and the expected output. Focus on clarity and demonstrate the function's purpose. Use placeholder values like `<DER encoded subject>` to avoid getting bogged down in the specifics of ASN.1 encoding.

* **Common Usage Errors:** Think about how a developer might misuse this low-level library. Common errors involve:
    * Providing invalid DER data.
    * Expecting an extension to always be present.
    * Incorrectly interpreting the "critical" flag.

* **Debugging Clues (User Operations):** Trace back user actions that might involve certificate processing:
    * Visiting HTTPS websites.
    * Installing/viewing certificates.
    * Using features that rely on client certificates.

**6. Structuring the Output:**

Organize the findings logically, using clear headings and bullet points for readability. Start with a high-level summary and then delve into specifics. Provide code examples where appropriate.

**7. Review and Refine:**

Finally, review the entire analysis for accuracy, clarity, and completeness. Ensure all aspects of the request have been addressed. Check for any inconsistencies or areas that could be explained more effectively. For instance, initially, I might have just said "parses certificates," but refining it to "parses ASN.1 encoded X.509 certificates to extract specific information" is more precise.

This iterative process of understanding the code, identifying core concepts, and then systematically addressing the request's points is crucial for generating a comprehensive and accurate analysis.
This C++ source file, `asn1_util.cc`, located within Chromium's network stack (`net/cert`), provides a set of utility functions for parsing and extracting information from ASN.1 (Abstract Syntax Notation One) encoded data, specifically focusing on X.509 certificates. ASN.1 is a standard for describing data structures, and DER (Distinguished Encoding Rules) is a common encoding format for ASN.1. X.509 certificates are used for verifying the identity of servers and clients in secure communication protocols like HTTPS.

Here's a breakdown of its functionalities:

**Core Functionality:**

* **Navigating ASN.1 Structures:** The file provides functions (`SeekToSubject`, `SeekToSPKI`, `SeekToExtensions`) to efficiently move the parsing cursor to specific sections within a DER-encoded X.509 certificate. This avoids parsing the entire certificate when only a specific part is needed.
* **Extracting Data:**  It offers functions to extract specific data elements from certificates, including:
    * **Subject:**  The entity the certificate is issued to (`ExtractSubjectFromDERCert`).
    * **Subject Public Key Info (SPKI):** Contains the public key and algorithm information (`ExtractSPKIFromDERCert`).
    * **Subject Public Key:** The raw public key bytes (`ExtractSubjectPublicKeyFromSPKI`).
    * **Extensions:**  Various optional fields that add functionality to certificates (`SeekToExtensions`, `ExtractExtensionWithOID`, `ExtractExtensionFromDERCert`).
    * **Signature Algorithms:** The algorithms used to sign the certificate (`ExtractSignatureAlgorithmsFromDERCert`).
* **Checking for Specific Extensions:**  It includes functions to check for the presence of specific extensions, such as the `canSignHttpExchangesDraft` extension (`HasCanSignHttpExchangesDraftExtension`).

**Relationship to JavaScript:**

While this C++ code itself doesn't directly execute JavaScript, it plays a crucial role in the underlying implementation of web security features that are exposed to JavaScript. Here's how they relate:

* **`chrome.certificateProvider` API:**  JavaScript APIs like `chrome.certificateProvider` (used in Chrome extensions) allow web pages or extensions to interact with client certificates. When a website requests a client certificate, this C++ code is likely involved in parsing the user's selected certificate to extract its information and present it to the website.

    **Example:** Imagine a banking website requiring a client certificate for authentication.

    1. **User Action (JavaScript Context):** The JavaScript on the banking website might call `navigator.credentials.get({ publicKey: { challenge: ...,  // Server's challenge
                                                                             allowCredentials: [...] } })`. This might eventually trigger the browser's certificate selection UI.
    2. **Certificate Selection:** The user selects a client certificate stored in the browser.
    3. **C++ Processing (asn1_util.cc):**  The browser's C++ code, potentially including functions from `asn1_util.cc`, would parse the selected certificate to extract its subject, public key, and potentially other extensions.
    4. **Decision/Action:** The extracted information might be used to verify the certificate against the server's requirements or to sign a challenge.
    5. **Response (JavaScript Context):** The result of the authentication process (success or failure) is eventually communicated back to the JavaScript code on the website.

* **TLS/HTTPS Handshake:** When a browser establishes a secure HTTPS connection, the server presents its certificate. The browser's network stack (written in C++) uses functions like those in `asn1_util.cc` to parse the server's certificate, verify its signature, and extract information like the subject's domain name to ensure the connection is secure and to the intended website. This happens transparently to JavaScript code but is fundamental to web security.

**Logical Reasoning (Hypothetical Input and Output):**

Let's consider the `ExtractSubjectFromDERCert` function:

**Hypothetical Input:**

```
std::string_view cert = {
    0x30, 0x82, 0x01, 0x0A, // Sequence, length
    0x30, 0x82, 0x00, 0xF6, // TBSCertificate, length
    // ... (rest of the TBSCertificate data) ...
    0x30, 0x0D,             // Subject sequence, length
    0x31, 0x0B,             // Set
    0x30, 0x09,             // Sequence
    0x06, 0x03, 0x55, 0x04, 0x03, // OID for commonName (CN)
    0x0C, 0x02, 0x41, 0x42  // UTF8String: "AB" (Example Subject CN)
    // ... (rest of the certificate data) ...
};
```

**Expected Output:**

```
std::string_view subject_out;
ExtractSubjectFromDERCert(cert, &subject_out);
// subject_out will contain the DER encoded bytes of the Subject field:
// 0x30, 0x0D, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x02, 0x41, 0x42
```

**Explanation:**  The function parses the certificate, navigates to the `Subject` field within the `TBSCertificate`, and extracts its raw DER encoding.

**Common Usage Errors and Examples:**

* **Providing Invalid DER Data:** If the input `cert` is not a valid DER-encoded X.509 certificate, the parsing functions will likely return `false`.

    **Example:**

    ```c++
    std::string_view invalid_cert = "This is not a valid certificate";
    std::string_view subject;
    if (!ExtractSubjectFromDERCert(invalid_cert, &subject)) {
      // Handle the error: Invalid certificate format.
      std::cerr << "Error: Invalid certificate format." << std::endl;
    }
    ```

* **Assuming an Extension Always Exists:** If code tries to extract an optional extension without first checking if it's present, it might lead to errors.

    **Example:**

    ```c++
    std::string_view cert_data = /* ... certificate data ... */;
    std::string_view my_extension_oid = /* ... OID of the extension ... */;
    bool extension_present;
    bool extension_critical;
    std::string_view extension_contents;

    if (ExtractExtensionFromDERCert(cert_data, my_extension_oid,
                                    &extension_present, &extension_critical,
                                    &extension_contents)) {
      if (extension_present) {
        // Process the extension contents
        std::cout << "Extension contents: " << extension_contents << std::endl;
      } else {
        std::cout << "Extension not present." << std::endl;
      }
    } else {
      std::cerr << "Error parsing certificate." << std::endl;
    }
    ```

* **Incorrectly Interpreting Extension Criticality:**  The `critical` flag in an extension indicates whether the extension *must* be understood and processed by the recipient. Ignoring a critical extension can lead to security vulnerabilities.

**User Operations Leading to This Code (Debugging Clues):**

Here's how user actions can trigger the execution of code in `asn1_util.cc`:

1. **Visiting an HTTPS Website:**
   * **Action:** A user types an HTTPS URL in the address bar and presses Enter.
   * **Process:** The browser initiates a TLS handshake with the server. The server presents its X.509 certificate.
   * **`asn1_util.cc` Involvement:**  Functions in this file are used to parse the server's certificate to verify its validity, check its expiration date, and extract the subject's domain name to ensure it matches the website being visited.

2. **Installing a Certificate:**
   * **Action:** A user manually installs a certificate (e.g., a root CA certificate) through the browser's settings.
   * **Process:** The browser needs to parse the certificate data to store its information securely.
   * **`asn1_util.cc` Involvement:** Functions in this file are used to parse the certificate being installed.

3. **Using Client Certificates for Authentication:**
   * **Action:** A website requires client certificate authentication. The browser prompts the user to select a certificate.
   * **Process:** The browser needs to read and parse the user's selected client certificate.
   * **`asn1_util.cc` Involvement:** Functions in this file are used to extract information from the client certificate to be sent to the server for authentication.

4. **Chrome Extensions Interacting with Certificates:**
   * **Action:** A Chrome extension uses the `chrome.certificateProvider` API to request access to certificates or to perform operations involving certificates.
   * **Process:** The extension's JavaScript code interacts with the browser's C++ backend.
   * **`asn1_util.cc` Involvement:** When the browser needs to process certificate data related to the extension's request, functions in this file might be called.

5. **Checking Website Security Information:**
   * **Action:** A user clicks the padlock icon in the address bar to view the website's security information (certificate details).
   * **Process:** The browser retrieves the website's certificate and displays its properties.
   * **`asn1_util.cc` Involvement:** Functions in this file are used to parse the certificate and extract the relevant information to display to the user.

By understanding these user interactions, developers can trace the execution flow and identify if issues related to certificate parsing might be occurring in the network stack. Debugging tools and logging within the Chromium network stack would provide further insights into the specific functions being called and the data being processed.

Prompt: 
```
这是目录为net/cert/asn1_util.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/asn1_util.h"

#include <optional>
#include <string_view>

#include "third_party/boringssl/src/pki/input.h"
#include "third_party/boringssl/src/pki/parse_certificate.h"
#include "third_party/boringssl/src/pki/parser.h"

namespace net::asn1 {

namespace {

// Parses input |in| which should point to the beginning of a Certificate, and
// sets |*tbs_certificate| ready to parse the Subject. If parsing
// fails, this function returns false and |*tbs_certificate| is left in an
// undefined state.
bool SeekToSubject(bssl::der::Input in, bssl::der::Parser* tbs_certificate) {
  // From RFC 5280, section 4.1
  //    Certificate  ::=  SEQUENCE  {
  //      tbsCertificate       TBSCertificate,
  //      signatureAlgorithm   AlgorithmIdentifier,
  //      signatureValue       BIT STRING  }

  // TBSCertificate  ::=  SEQUENCE  {
  //      version         [0]  EXPLICIT Version DEFAULT v1,
  //      serialNumber         CertificateSerialNumber,
  //      signature            AlgorithmIdentifier,
  //      issuer               Name,
  //      validity             Validity,
  //      subject              Name,
  //      subjectPublicKeyInfo SubjectPublicKeyInfo,
  //      ... }

  bssl::der::Parser parser(in);
  bssl::der::Parser certificate;
  if (!parser.ReadSequence(&certificate))
    return false;

  // We don't allow junk after the certificate.
  if (parser.HasMore())
    return false;

  if (!certificate.ReadSequence(tbs_certificate))
    return false;

  bool unused;
  if (!tbs_certificate->SkipOptionalTag(
          CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 0, &unused)) {
    return false;
  }

  // serialNumber
  if (!tbs_certificate->SkipTag(CBS_ASN1_INTEGER)) {
    return false;
  }
  // signature
  if (!tbs_certificate->SkipTag(CBS_ASN1_SEQUENCE)) {
    return false;
  }
  // issuer
  if (!tbs_certificate->SkipTag(CBS_ASN1_SEQUENCE)) {
    return false;
  }
  // validity
  if (!tbs_certificate->SkipTag(CBS_ASN1_SEQUENCE)) {
    return false;
  }
  return true;
}

// Parses input |in| which should point to the beginning of a Certificate, and
// sets |*tbs_certificate| ready to parse the SubjectPublicKeyInfo. If parsing
// fails, this function returns false and |*tbs_certificate| is left in an
// undefined state.
bool SeekToSPKI(bssl::der::Input in, bssl::der::Parser* tbs_certificate) {
  return SeekToSubject(in, tbs_certificate) &&
         // Skip over Subject.
         tbs_certificate->SkipTag(CBS_ASN1_SEQUENCE);
}

// Parses input |in| which should point to the beginning of a
// Certificate. If parsing fails, this function returns false, with
// |*extensions_present| and |*extensions_parser| left in an undefined
// state. If parsing succeeds and extensions are present, this function
// sets |*extensions_present| to true and sets |*extensions_parser|
// ready to parse the Extensions. If extensions are not present, it sets
// |*extensions_present| to false and |*extensions_parser| is left in an
// undefined state.
bool SeekToExtensions(bssl::der::Input in,
                      bool* extensions_present,
                      bssl::der::Parser* extensions_parser) {
  bool present;
  bssl::der::Parser tbs_cert_parser;
  if (!SeekToSPKI(in, &tbs_cert_parser))
    return false;

  // From RFC 5280, section 4.1
  // TBSCertificate  ::=  SEQUENCE  {
  //      ...
  //      subjectPublicKeyInfo SubjectPublicKeyInfo,
  //      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
  //      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
  //      extensions      [3]  EXPLICIT Extensions OPTIONAL }

  // subjectPublicKeyInfo
  if (!tbs_cert_parser.SkipTag(CBS_ASN1_SEQUENCE)) {
    return false;
  }
  // issuerUniqueID
  if (!tbs_cert_parser.SkipOptionalTag(CBS_ASN1_CONTEXT_SPECIFIC | 1,
                                       &present)) {
    return false;
  }
  // subjectUniqueID
  if (!tbs_cert_parser.SkipOptionalTag(CBS_ASN1_CONTEXT_SPECIFIC | 2,
                                       &present)) {
    return false;
  }

  std::optional<bssl::der::Input> extensions;
  if (!tbs_cert_parser.ReadOptionalTag(
          CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 3, &extensions)) {
    return false;
  }

  if (!extensions) {
    *extensions_present = false;
    return true;
  }

  // Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
  // Extension   ::=  SEQUENCE  {
  //      extnID      OBJECT IDENTIFIER,
  //      critical    BOOLEAN DEFAULT FALSE,
  //      extnValue   OCTET STRING }

  // |extensions| was EXPLICITly tagged, so we still need to remove the
  // ASN.1 SEQUENCE header.
  bssl::der::Parser explicit_extensions_parser(extensions.value());
  if (!explicit_extensions_parser.ReadSequence(extensions_parser))
    return false;

  if (explicit_extensions_parser.HasMore())
    return false;

  *extensions_present = true;
  return true;
}

// Parse a DER-encoded, X.509 certificate in |cert| and find an extension with
// the given OID. Returns false on parse error or true if the parse was
// successful. |*out_extension_present| will be true iff the extension was
// found. In the case where it was found, |*out_extension| will describe the
// extension, or is undefined on parse error or if the extension is missing.
bool ExtractExtensionWithOID(std::string_view cert,
                             bssl::der::Input extension_oid,
                             bool* out_extension_present,
                             bssl::ParsedExtension* out_extension) {
  bssl::der::Parser extensions;
  bool extensions_present;
  if (!SeekToExtensions(bssl::der::Input(cert), &extensions_present,
                        &extensions)) {
    return false;
  }
  if (!extensions_present) {
    *out_extension_present = false;
    return true;
  }

  while (extensions.HasMore()) {
    bssl::der::Input extension_tlv;
    if (!extensions.ReadRawTLV(&extension_tlv) ||
        !ParseExtension(extension_tlv, out_extension)) {
      return false;
    }

    if (out_extension->oid == extension_oid) {
      *out_extension_present = true;
      return true;
    }
  }

  *out_extension_present = false;
  return true;
}

}  // namespace

bool ExtractSubjectFromDERCert(std::string_view cert,
                               std::string_view* subject_out) {
  bssl::der::Parser parser;
  if (!SeekToSubject(bssl::der::Input(cert), &parser)) {
    return false;
  }
  bssl::der::Input subject;
  if (!parser.ReadRawTLV(&subject))
    return false;
  *subject_out = subject.AsStringView();
  return true;
}

bool ExtractSPKIFromDERCert(std::string_view cert, std::string_view* spki_out) {
  bssl::der::Parser parser;
  if (!SeekToSPKI(bssl::der::Input(cert), &parser)) {
    return false;
  }
  bssl::der::Input spki;
  if (!parser.ReadRawTLV(&spki))
    return false;
  *spki_out = spki.AsStringView();
  return true;
}

bool ExtractSubjectPublicKeyFromSPKI(std::string_view spki,
                                     std::string_view* spk_out) {
  // From RFC 5280, Section 4.1
  //   SubjectPublicKeyInfo  ::=  SEQUENCE  {
  //     algorithm            AlgorithmIdentifier,
  //     subjectPublicKey     BIT STRING  }
  //
  //   AlgorithmIdentifier  ::=  SEQUENCE  {
  //     algorithm               OBJECT IDENTIFIER,
  //     parameters              ANY DEFINED BY algorithm OPTIONAL  }

  // Step into SubjectPublicKeyInfo sequence.
  bssl::der::Parser parser((bssl::der::Input(spki)));
  bssl::der::Parser spki_parser;
  if (!parser.ReadSequence(&spki_parser))
    return false;

  // Step over algorithm field (a SEQUENCE).
  if (!spki_parser.SkipTag(CBS_ASN1_SEQUENCE)) {
    return false;
  }

  // Extract the subjectPublicKey field.
  bssl::der::Input spk;
  if (!spki_parser.ReadTag(CBS_ASN1_BITSTRING, &spk)) {
    return false;
  }
  *spk_out = spk.AsStringView();
  return true;
}

bool HasCanSignHttpExchangesDraftExtension(std::string_view cert) {
  // kCanSignHttpExchangesDraftOid is the DER encoding of the OID for
  // canSignHttpExchangesDraft defined in:
  // https://wicg.github.io/webpackage/draft-yasskin-http-origin-signed-responses.html
  static const uint8_t kCanSignHttpExchangesDraftOid[] = {
      0x2B, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x16};

  bool extension_present;
  bssl::ParsedExtension extension;
  if (!ExtractExtensionWithOID(cert,
                               bssl::der::Input(kCanSignHttpExchangesDraftOid),
                               &extension_present, &extension) ||
      !extension_present) {
    return false;
  }

  // The extension should have contents NULL.
  static const uint8_t kNull[] = {0x05, 0x00};
  return extension.value == bssl::der::Input(kNull);
}

bool ExtractSignatureAlgorithmsFromDERCert(
    std::string_view cert,
    std::string_view* cert_signature_algorithm_sequence,
    std::string_view* tbs_signature_algorithm_sequence) {
  // From RFC 5280, section 4.1
  //    Certificate  ::=  SEQUENCE  {
  //      tbsCertificate       TBSCertificate,
  //      signatureAlgorithm   AlgorithmIdentifier,
  //      signatureValue       BIT STRING  }

  // TBSCertificate  ::=  SEQUENCE  {
  //      version         [0]  EXPLICIT Version DEFAULT v1,
  //      serialNumber         CertificateSerialNumber,
  //      signature            AlgorithmIdentifier,
  //      issuer               Name,
  //      validity             Validity,
  //      subject              Name,
  //      subjectPublicKeyInfo SubjectPublicKeyInfo,
  //      ... }

  bssl::der::Parser parser((bssl::der::Input(cert)));
  bssl::der::Parser certificate;
  if (!parser.ReadSequence(&certificate))
    return false;

  bssl::der::Parser tbs_certificate;
  if (!certificate.ReadSequence(&tbs_certificate))
    return false;

  bool unused;
  if (!tbs_certificate.SkipOptionalTag(
          CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 0, &unused)) {
    return false;
  }

  // serialNumber
  if (!tbs_certificate.SkipTag(CBS_ASN1_INTEGER)) {
    return false;
  }
  // signature
  bssl::der::Input tbs_algorithm;
  if (!tbs_certificate.ReadRawTLV(&tbs_algorithm))
    return false;

  bssl::der::Input cert_algorithm;
  if (!certificate.ReadRawTLV(&cert_algorithm))
    return false;

  *cert_signature_algorithm_sequence = cert_algorithm.AsStringView();
  *tbs_signature_algorithm_sequence = tbs_algorithm.AsStringView();
  return true;
}

bool ExtractExtensionFromDERCert(std::string_view cert,
                                 std::string_view extension_oid,
                                 bool* out_extension_present,
                                 bool* out_extension_critical,
                                 std::string_view* out_contents) {
  *out_extension_present = false;
  *out_extension_critical = false;
  *out_contents = std::string_view();

  bssl::ParsedExtension extension;
  if (!ExtractExtensionWithOID(cert, bssl::der::Input(extension_oid),
                               out_extension_present, &extension)) {
    return false;
  }
  if (!*out_extension_present)
    return true;

  *out_extension_critical = extension.critical;
  *out_contents = extension.value.AsStringView();
  return true;
}

}  // namespace net::asn1

"""

```