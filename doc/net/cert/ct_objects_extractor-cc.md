Response:
Let's break down the thought process for analyzing this C++ code and generating the response.

1. **Understand the Core Task:** The first step is to read the code and identify its primary purpose. The filename `ct_objects_extractor.cc` and the namespace `net::ct` strongly suggest it's related to Certificate Transparency (CT). The function names like `ExtractEmbeddedSCTList`, `GetPrecertSignedEntry`, and `ExtractSCTListFromOCSPResponse` further reinforce this. The code seems to be about extracting and manipulating CT-related data from various sources like certificates and OCSP responses.

2. **Identify Key Data Structures and Formats:** CT involves specific data structures defined in RFCs. Looking at the `#include` statements reveals interaction with ASN.1 (Abstract Syntax Notation One), X.509 certificates, and OCSP (Online Certificate Status Protocol) responses. Keywords like `SignedCertificateTimestamp` (SCT), `TBSCertificate`, `extensions`, and `OCSPResponse` stand out. The use of `CBS` (Const Byte String) from BoringSSL indicates the code parses and manipulates raw byte data.

3. **Analyze Individual Functions:**  Go through each function and understand its role:
    * `ExtractEmbeddedSCTList`: Looks for SCTs directly within the certificate's extensions.
    * `GetPrecertSignedEntry`:  Processes "precertificates" (certificates before they are fully signed) to prepare them for CT logging. This involves removing the embedded SCT extension.
    * `GetX509SignedEntry`:  Handles regular, fully signed X.509 certificates for CT logging.
    * `ExtractSCTListFromOCSPResponse`: Extracts SCTs from an OCSP response.

4. **Identify Relationships and Flow:** Notice how the functions relate to each other. `ExtractEmbeddedSCTList` is a simple extraction. `GetPrecertSignedEntry` modifies the certificate structure. `ExtractSCTListFromOCSPResponse` deals with a different data source. These functions are likely used at different points in the certificate validation and CT reporting process.

5. **Look for JavaScript Relevance (and Lack Thereof):** Carefully consider if any part of this C++ code directly interacts with JavaScript. This is a *network stack* component, deeply involved in parsing binary data. It operates at a level below where JavaScript typically interacts directly with network protocols. While JavaScript might *trigger* network requests that eventually lead to this code being executed, there's no direct function call or data passing between them. The interaction is indirect through network APIs.

6. **Consider Logic and Assumptions:**  For functions like `GetPrecertSignedEntry`, think about the steps involved. It needs to parse the certificate, find the SCT extension, and construct a modified TBSCertificate without that extension. This involves assumptions about the input format and the presence of specific extensions.

7. **Think About User Errors:**  Common programming errors in this context might involve:
    * Passing incorrectly formatted certificates or OCSP responses.
    * Not handling cases where SCTs are missing.
    * Incorrectly interpreting the extracted data.

8. **Trace User Actions (Debugging Perspective):** Imagine how a user action might lead to this code being executed. A user browsing a website initiates an HTTPS connection. This triggers certificate validation, which may involve checking for CT information. The browser might fetch an OCSP response, and this code would be involved in parsing it. The key is to trace the path from a high-level user action down to this low-level C++ code.

9. **Structure the Response:** Organize the findings logically according to the prompt's requests:
    * Functionality description.
    * JavaScript relationship (explain the indirect connection).
    * Logic and assumptions (provide examples with inputs and outputs).
    * User/programming errors (give concrete scenarios).
    * User journey (describe the steps leading to this code).

10. **Refine and Elaborate:** Review the response and add details. For example, when explaining the logic, specify the ASN.1 structures being parsed. When discussing user errors, explain *why* those errors are problematic. Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Maybe JavaScript interacts through some kind of native module interface?"  **Correction:**  While possible in theory, for core network stack components like this, the interaction is typically at a lower level (network requests, callbacks in C++, etc.), not direct JS function calls.
* **Initial thought:** "Just list the function names as functionality." **Correction:**  Provide a higher-level description of what the *file* does overall, then elaborate on the individual functions.
* **Initial thought:** "Simply say 'invalid input' as a user error." **Correction:**  Be more specific about *what kind* of invalid input (e.g., malformed certificate, OCSP response without SCTs).

By following these steps, analyzing the code carefully, and thinking about the broader context, we can generate a comprehensive and accurate response to the prompt.
这个文件 `net/cert/ct_objects_extractor.cc` 是 Chromium 网络栈中的一个源代码文件，它的主要功能是**从各种网络协议和数据结构中提取与 Certificate Transparency (CT) 相关的信息，特别是 Signed Certificate Timestamps (SCTs)**。

**功能列表:**

1. **从 X.509 证书中提取嵌入的 SCT 列表 (`ExtractEmbeddedSCTList`)**:
   - 解析 X.509 证书的 ASN.1 结构。
   - 查找特定的扩展字段，该字段包含嵌入的 SCT 列表 (OID 为 `kEmbeddedSCTOid`)。
   - 将提取到的 SCT 列表以字符串形式返回。

2. **为预证书 (Precertificate) 获取签名条目数据 (`GetPrecertSignedEntry`)**:
   - 预证书是在最终签名之前提交给 CT Log 的证书。
   - 该函数解析预证书的 TBSCertificate 部分。
   - 从预证书的扩展中移除嵌入的 SCT 扩展，生成用于提交给 CT Log 的 TBSCertificate。
   - 计算颁发者密钥的 SHA256 哈希值。
   - 将条目类型设置为 `LOG_ENTRY_TYPE_PRECERT`，并填充 TBSCertificate 和颁发者密钥哈希。

3. **为普通 X.509 证书获取签名条目数据 (`GetX509SignedEntry`)**:
   - 处理已完全签名的 X.509 证书。
   - 将条目类型设置为 `LOG_ENTRY_TYPE_X509`。
   - 将整个证书内容作为 `leaf_certificate` 存储。

4. **从 OCSP 响应中提取 SCT 列表 (`ExtractSCTListFromOCSPResponse`)**:
   - 解析 OCSP (Online Certificate Status Protocol) 响应的 ASN.1 结构。
   - 查找与目标证书的序列号和颁发者匹配的 `SingleResponse`。
   - 在匹配的 `SingleResponse` 的扩展字段中查找包含 SCT 列表的扩展 (OID 为 `kOCSPExtensionOid`)。
   - 将提取到的 SCT 列表以字符串形式返回。

**与 JavaScript 的关系:**

这个 C++ 文件本身不包含任何 JavaScript 代码，并且主要在 Chromium 的网络栈的底层运行。然而，它的功能与 JavaScript 的执行有间接关系：

- **HTTPS 连接建立**: 当用户通过浏览器访问一个使用 HTTPS 的网站时，浏览器会下载服务器的证书。`ExtractEmbeddedSCTList` 可能会被调用来检查证书中是否嵌入了 SCT。
- **OCSP Stapling**:  浏览器可能会收到服务器提供的 OCSP stapling 响应，其中包含了证书状态信息以及可能的 SCT。`ExtractSCTListFromOCSPResponse` 会被用来从这个响应中提取 SCT。
- **Certificate Transparency Enforcement**: Chromium 使用提取到的 SCT 信息来执行 CT 策略，例如检查证书是否已被记录到 CT Log 中。如果策略要求，浏览器可能会拒绝连接或显示警告，这会影响 JavaScript 代码的执行，因为网页可能无法加载或安全上下文受到影响。

**举例说明:**

假设一个网站的 HTTPS 证书中嵌入了 SCT 列表。

**假设输入 (对于 `ExtractEmbeddedSCTList`):**

一个包含嵌入 SCT 扩展的 X.509 证书的 `CRYPTO_BUFFER`。 扩展字段的 ASN.1 结构可能如下：

```asn1
Extension  ::=  SEQUENCE  {
    extnID      OBJECT IDENTIFIER,
    critical    BOOLEAN DEFAULT FALSE,
    extnValue   OCTET STRING
}

...

extnID: 1.3.6.1.4.1.11129.2.4.2 (kEmbeddedSCTOid)
critical: FALSE
extnValue:  OCTET STRING containing the serialized SCT list
```

**假设输出 (对于 `ExtractEmbeddedSCTList`):**

一个字符串，包含了 `extnValue` 中解码后的 SCT 列表的二进制数据。

**逻辑推理举例 (对于 `GetPrecertSignedEntry`):**

**假设输入:**

- `leaf`: 一个预证书的 `CRYPTO_BUFFER`，其扩展中包含嵌入的 SCT。
- `issuer`: 颁发该预证书的 CA 证书的 `CRYPTO_BUFFER`。

**处理步骤:**

1. 函数会解析 `leaf` 预证书的 ASN.1 结构。
2. 它会定位到包含嵌入 SCT 的扩展。
3. 它会构建一个新的 TBSCertificate，**不包含**这个嵌入的 SCT 扩展。
4. 它会从 `issuer` 证书中提取公钥，并计算其 SHA256 哈希值。

**假设输出:**

一个 `SignedEntryData` 结构，包含：

- `type`: `LOG_ENTRY_TYPE_PRECERT`
- `tbs_certificate`:  不包含嵌入 SCT 扩展的 TBSCertificate 的 DER 编码。
- `issuer_key_hash`: 颁发者公钥的 SHA256 哈希值。

**用户或编程常见的使用错误:**

1. **传入格式错误的证书或 OCSP 响应**:  如果传入的 `CRYPTO_BUFFER` 不符合 X.509 或 OCSP 的 ASN.1 结构，解析会失败，函数会返回 `false`。
   ```c++
   CRYPTO_BUFFER* invalid_cert_buffer = CRYPTO_BUFFER_new(nullptr, 10); // 创建一个空的 buffer
   std::string sct_list;
   if (!ExtractEmbeddedSCTList(invalid_cert_buffer, &sct_list)) {
       // 处理提取失败的情况
       LOG(ERROR) << "Failed to extract SCT from invalid certificate.";
   }
   CRYPTO_BUFFER_free(invalid_cert_buffer);
   ```

2. **期望在没有 SCT 的证书或 OCSP 响应中找到 SCT**:  如果证书或 OCSP 响应中没有包含 SCT 列表的扩展，相应的提取函数会返回 `false`。程序需要正确处理这种情况，避免假设所有证书都包含 SCT。

3. **在 `GetPrecertSignedEntry` 中使用错误的颁发者证书**: 如果提供的颁发者证书与实际颁发预证书的 CA 不符，计算出的 `issuer_key_hash` 将不正确。

**用户操作到达此处的调试线索:**

假设用户访问一个使用了 CT 的 HTTPS 网站，并且我们想知道 `ExtractEmbeddedSCTList` 是如何被调用的。

1. **用户在浏览器地址栏输入 URL 并按下 Enter 键。**
2. **Chromium 的网络栈开始建立 HTTPS 连接。**
3. **TLS 握手过程开始。**
4. **服务器将证书链发送给浏览器。**
5. **Chromium 的证书验证器开始验证服务器证书。**
6. **在证书验证过程中，为了进行 CT 检查，可能会调用 `ExtractEmbeddedSCTList` 来查看证书中是否直接嵌入了 SCT。** 这是对接收到的服务器证书进行处理的一部分。
7. **如果证书没有嵌入 SCT，或者需要从 OCSP 响应中获取 SCT，可能会在后续步骤中调用 `ExtractSCTListFromOCSPResponse`。**  这可能发生在浏览器请求并接收到 OCSP stapling 响应或者单独的 OCSP 响应时。

为了调试，可以在 Chromium 的网络栈中设置断点，例如在 `ExtractEmbeddedSCTList` 函数的入口处，然后复现用户访问该网站的操作。通过查看调用栈，可以确认 `ExtractEmbeddedSCTList` 是从哪个更高级别的网络组件调用的。 此外，Chromium 提供了网络相关的日志记录功能 (例如使用 `chrome://net-export/`)，可以用来追踪证书和 CT 相关的事件。

Prompt: 
```
这是目录为net/cert/ct_objects_extractor.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/cert/ct_objects_extractor.h"

#include <string.h>

#include <string_view>

#include "base/hash/sha1.h"
#include "base/logging.h"
#include "base/strings/string_util.h"
#include "crypto/sha2.h"
#include "net/cert/asn1_util.h"
#include "net/cert/signed_certificate_timestamp.h"
#include "net/cert/x509_util.h"
#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/mem.h"

namespace net::ct {

namespace {

// The wire form of the OID 1.3.6.1.4.1.11129.2.4.5 - OCSP SingleExtension for
// X.509v3 Certificate Transparency Signed Certificate Timestamp List, see
// Section 3.3 of RFC6962.
const uint8_t kOCSPExtensionOid[] = {0x2B, 0x06, 0x01, 0x04, 0x01,
                                     0xD6, 0x79, 0x02, 0x04, 0x05};

// The wire form of the OID 1.3.6.1.5.5.7.48.1.1. See RFC 6960.
const uint8_t kOCSPBasicResponseOid[] = {0x2b, 0x06, 0x01, 0x05, 0x05,
                                         0x07, 0x30, 0x01, 0x01};

// The wire form of the OID 1.3.14.3.2.26.
const uint8_t kSHA1Oid[] = {0x2b, 0x0e, 0x03, 0x02, 0x1a};

// The wire form of the OID 2.16.840.1.101.3.4.2.1.
const uint8_t kSHA256Oid[] = {0x60, 0x86, 0x48, 0x01, 0x65,
                              0x03, 0x04, 0x02, 0x01};

bool StringEqualToCBS(const std::string& value1, const CBS* value2) {
  if (CBS_len(value2) != value1.size())
    return false;
  return memcmp(value1.data(), CBS_data(value2), CBS_len(value2)) == 0;
}

bool SkipElements(CBS* cbs, int count) {
  for (int i = 0; i < count; i++) {
    if (!CBS_get_any_asn1_element(cbs, nullptr, nullptr, nullptr))
      return false;
  }
  return true;
}

bool SkipOptionalElement(CBS* cbs, unsigned tag) {
  CBS unused;
  return !CBS_peek_asn1_tag(cbs, tag) || CBS_get_asn1(cbs, &unused, tag);
}

// Copies all the bytes in |outer| which are before |inner| to |out|. |inner|
// must be a subset of |outer|.
bool CopyBefore(const CBS& outer, const CBS& inner, CBB* out) {
  CHECK_LE(CBS_data(&outer), CBS_data(&inner));
  CHECK_LE(CBS_data(&inner) + CBS_len(&inner),
           CBS_data(&outer) + CBS_len(&outer));

  return !!CBB_add_bytes(out, CBS_data(&outer),
                         CBS_data(&inner) - CBS_data(&outer));
}

// Copies all the bytes in |outer| which are after |inner| to |out|. |inner|
// must be a subset of |outer|.
bool CopyAfter(const CBS& outer, const CBS& inner, CBB* out) {
  CHECK_LE(CBS_data(&outer), CBS_data(&inner));
  CHECK_LE(CBS_data(&inner) + CBS_len(&inner),
           CBS_data(&outer) + CBS_len(&outer));

  return !!CBB_add_bytes(
      out, CBS_data(&inner) + CBS_len(&inner),
      CBS_data(&outer) + CBS_len(&outer) - CBS_data(&inner) - CBS_len(&inner));
}

// Skips |tbs_cert|, which must be a TBSCertificate body, to just before the
// extensions element.
bool SkipTBSCertificateToExtensions(CBS* tbs_cert) {
  constexpr unsigned kVersionTag =
      CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0;
  constexpr unsigned kIssuerUniqueIDTag = CBS_ASN1_CONTEXT_SPECIFIC | 1;
  constexpr unsigned kSubjectUniqueIDTag = CBS_ASN1_CONTEXT_SPECIFIC | 2;
  return SkipOptionalElement(tbs_cert, kVersionTag) &&
         SkipElements(tbs_cert,
                      6 /* serialNumber through subjectPublicKeyInfo */) &&
         SkipOptionalElement(tbs_cert, kIssuerUniqueIDTag) &&
         SkipOptionalElement(tbs_cert, kSubjectUniqueIDTag);
}

// Looks for the extension with the specified OID in |extensions|, which must
// contain the contents of a SEQUENCE of X.509 extension structures. If found,
// returns true and sets |*out| to the full extension element.
bool FindExtensionElement(const CBS& extensions,
                          const uint8_t* oid,
                          size_t oid_len,
                          CBS* out) {
  CBS extensions_copy = extensions;
  CBS result;
  CBS_init(&result, nullptr, 0);
  bool found = false;
  while (CBS_len(&extensions_copy) > 0) {
    CBS extension_element;
    if (!CBS_get_asn1_element(&extensions_copy, &extension_element,
                              CBS_ASN1_SEQUENCE)) {
      return false;
    }

    CBS copy = extension_element;
    CBS extension, extension_oid;
    if (!CBS_get_asn1(&copy, &extension, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&extension, &extension_oid, CBS_ASN1_OBJECT)) {
      return false;
    }

    if (CBS_mem_equal(&extension_oid, oid, oid_len)) {
      if (found)
        return false;
      found = true;
      result = extension_element;
    }
  }
  if (!found)
    return false;

  *out = result;
  return true;
}

// Finds the SignedCertificateTimestampList in an extension with OID |oid| in
// |x509_exts|. If found, returns true and sets |*out_sct_list| to the encoded
// SCT list.
bool ParseSCTListFromExtensions(const CBS& extensions,
                                const uint8_t* oid,
                                size_t oid_len,
                                std::string* out_sct_list) {
  CBS extension_element, extension, extension_oid, value, sct_list;
  if (!FindExtensionElement(extensions, oid, oid_len, &extension_element) ||
      !CBS_get_asn1(&extension_element, &extension, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1(&extension, &extension_oid, CBS_ASN1_OBJECT) ||
      // Skip the optional critical element.
      !SkipOptionalElement(&extension, CBS_ASN1_BOOLEAN) ||
      // The extension value is stored in an OCTET STRING.
      !CBS_get_asn1(&extension, &value, CBS_ASN1_OCTETSTRING) ||
      CBS_len(&extension) != 0 ||
      // The extension value itself is an OCTET STRING containing the
      // serialized SCT list.
      !CBS_get_asn1(&value, &sct_list, CBS_ASN1_OCTETSTRING) ||
      CBS_len(&value) != 0) {
    return false;
  }

  DCHECK(CBS_mem_equal(&extension_oid, oid, oid_len));
  *out_sct_list = std::string(
      reinterpret_cast<const char*>(CBS_data(&sct_list)), CBS_len(&sct_list));
  return true;
}

// Finds the SingleResponse in |responses| which matches |issuer| and
// |cert_serial_number|. On success, returns true and sets
// |*out_single_response| to the body of the SingleResponse starting at the
// |certStatus| field.
bool FindMatchingSingleResponse(CBS* responses,
                                const CRYPTO_BUFFER* issuer,
                                const std::string& cert_serial_number,
                                CBS* out_single_response) {
  std::string_view issuer_spki;
  if (!asn1::ExtractSPKIFromDERCert(
          x509_util::CryptoBufferAsStringPiece(issuer), &issuer_spki))
    return false;

  // In OCSP, only the key itself is under hash.
  std::string_view issuer_spk;
  if (!asn1::ExtractSubjectPublicKeyFromSPKI(issuer_spki, &issuer_spk))
    return false;

  // ExtractSubjectPublicKeyFromSPKI does not remove the initial octet encoding
  // the number of unused bits in the ASN.1 BIT STRING so we do it here. For
  // public keys, the bitstring is in practice always byte-aligned.
  if (issuer_spk.empty() || issuer_spk[0] != 0)
    return false;
  issuer_spk.remove_prefix(1);

  // TODO(ekasper): add SHA-384 to crypto/sha2.h and here if it proves
  // necessary.
  // TODO(ekasper): only compute the hashes on demand.
  std::string issuer_key_sha256_hash = crypto::SHA256HashString(issuer_spk);
  std::string issuer_key_sha1_hash =
      base::SHA1HashString(std::string(issuer_spk));

  while (CBS_len(responses) > 0) {
    CBS single_response, cert_id;
    if (!CBS_get_asn1(responses, &single_response, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&single_response, &cert_id, CBS_ASN1_SEQUENCE)) {
      return false;
    }

    CBS hash_algorithm, hash, serial_number, issuer_name_hash, issuer_key_hash;
    if (!CBS_get_asn1(&cert_id, &hash_algorithm, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&hash_algorithm, &hash, CBS_ASN1_OBJECT) ||
        !CBS_get_asn1(&cert_id, &issuer_name_hash, CBS_ASN1_OCTETSTRING) ||
        !CBS_get_asn1(&cert_id, &issuer_key_hash, CBS_ASN1_OCTETSTRING) ||
        !CBS_get_asn1(&cert_id, &serial_number, CBS_ASN1_INTEGER) ||
        CBS_len(&cert_id) != 0) {
      return false;
    }

    // Check the serial number matches.
    if (!StringEqualToCBS(cert_serial_number, &serial_number))
      continue;

    // Check if the issuer_key_hash matches.
    // TODO(ekasper): also use the issuer name hash in matching.
    if (CBS_mem_equal(&hash, kSHA1Oid, sizeof(kSHA1Oid))) {
      if (StringEqualToCBS(issuer_key_sha1_hash, &issuer_key_hash)) {
        *out_single_response = single_response;
        return true;
      }
    } else if (CBS_mem_equal(&hash, kSHA256Oid, sizeof(kSHA256Oid))) {
      if (StringEqualToCBS(issuer_key_sha256_hash, &issuer_key_hash)) {
        *out_single_response = single_response;
        return true;
      }
    }
  }

  return false;
}

}  // namespace

bool ExtractEmbeddedSCTList(const CRYPTO_BUFFER* cert, std::string* sct_list) {
  CBS cert_cbs;
  CBS_init(&cert_cbs, CRYPTO_BUFFER_data(cert), CRYPTO_BUFFER_len(cert));
  CBS cert_body, tbs_cert, extensions_wrap, extensions;
  if (!CBS_get_asn1(&cert_cbs, &cert_body, CBS_ASN1_SEQUENCE) ||
      CBS_len(&cert_cbs) != 0 ||
      !CBS_get_asn1(&cert_body, &tbs_cert, CBS_ASN1_SEQUENCE) ||
      !SkipTBSCertificateToExtensions(&tbs_cert) ||
      // Extract the extensions list.
      !CBS_get_asn1(&tbs_cert, &extensions_wrap,
                    CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 3) ||
      !CBS_get_asn1(&extensions_wrap, &extensions, CBS_ASN1_SEQUENCE) ||
      CBS_len(&extensions_wrap) != 0 || CBS_len(&tbs_cert) != 0) {
    return false;
  }

  return ParseSCTListFromExtensions(extensions, kEmbeddedSCTOid,
                                    sizeof(kEmbeddedSCTOid), sct_list);
}

bool GetPrecertSignedEntry(const CRYPTO_BUFFER* leaf,
                           const CRYPTO_BUFFER* issuer,
                           SignedEntryData* result) {
  result->Reset();

  // Parse the TBSCertificate.
  CBS cert_cbs;
  CBS_init(&cert_cbs, CRYPTO_BUFFER_data(leaf), CRYPTO_BUFFER_len(leaf));
  CBS cert_body, tbs_cert;
  if (!CBS_get_asn1(&cert_cbs, &cert_body, CBS_ASN1_SEQUENCE) ||
      CBS_len(&cert_cbs) != 0 ||
      !CBS_get_asn1(&cert_body, &tbs_cert, CBS_ASN1_SEQUENCE)) {
    return false;
  }

  CBS tbs_cert_copy = tbs_cert;
  if (!SkipTBSCertificateToExtensions(&tbs_cert))
    return false;

  // Start filling in a new TBSCertificate. Copy everything parsed or skipped
  // so far to the |new_tbs_cert|.
  bssl::ScopedCBB cbb;
  CBB new_tbs_cert;
  if (!CBB_init(cbb.get(), CBS_len(&tbs_cert_copy)) ||
      !CBB_add_asn1(cbb.get(), &new_tbs_cert, CBS_ASN1_SEQUENCE) ||
      !CopyBefore(tbs_cert_copy, tbs_cert, &new_tbs_cert)) {
    return false;
  }

  // Parse the extensions list and find the SCT extension.
  //
  // XXX(rsleevi): We could generate precerts for certs without the extension
  // by leaving the TBSCertificate as-is. The reference implementation does not
  // do this.
  constexpr unsigned kExtensionsTag =
      CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 3;
  CBS extensions_wrap, extensions, sct_extension;
  if (!CBS_get_asn1(&tbs_cert, &extensions_wrap, kExtensionsTag) ||
      !CBS_get_asn1(&extensions_wrap, &extensions, CBS_ASN1_SEQUENCE) ||
      CBS_len(&extensions_wrap) != 0 || CBS_len(&tbs_cert) != 0 ||
      !FindExtensionElement(extensions, kEmbeddedSCTOid,
                            sizeof(kEmbeddedSCTOid), &sct_extension)) {
    return false;
  }

  // Add extensions to the TBSCertificate. Copy all extensions except the
  // embedded SCT extension.
  CBB new_extensions_wrap, new_extensions;
  if (!CBB_add_asn1(&new_tbs_cert, &new_extensions_wrap, kExtensionsTag) ||
      !CBB_add_asn1(&new_extensions_wrap, &new_extensions, CBS_ASN1_SEQUENCE) ||
      !CopyBefore(extensions, sct_extension, &new_extensions) ||
      !CopyAfter(extensions, sct_extension, &new_extensions)) {
    return false;
  }

  uint8_t* new_tbs_cert_der;
  size_t new_tbs_cert_len;
  if (!CBB_finish(cbb.get(), &new_tbs_cert_der, &new_tbs_cert_len))
    return false;
  bssl::UniquePtr<uint8_t> scoped_new_tbs_cert_der(new_tbs_cert_der);

  // Extract the issuer's public key.
  std::string_view issuer_key;
  if (!asn1::ExtractSPKIFromDERCert(
          x509_util::CryptoBufferAsStringPiece(issuer), &issuer_key)) {
    return false;
  }

  // Fill in the SignedEntryData.
  result->type = ct::SignedEntryData::LOG_ENTRY_TYPE_PRECERT;
  result->tbs_certificate.assign(
      reinterpret_cast<const char*>(new_tbs_cert_der), new_tbs_cert_len);
  crypto::SHA256HashString(issuer_key, result->issuer_key_hash.data,
                           sizeof(result->issuer_key_hash.data));

  return true;
}

bool GetX509SignedEntry(const CRYPTO_BUFFER* leaf, SignedEntryData* result) {
  DCHECK(leaf);

  result->Reset();
  result->type = ct::SignedEntryData::LOG_ENTRY_TYPE_X509;
  result->leaf_certificate =
      std::string(x509_util::CryptoBufferAsStringPiece(leaf));
  return true;
}

bool ExtractSCTListFromOCSPResponse(const CRYPTO_BUFFER* issuer,
                                    const std::string& cert_serial_number,
                                    std::string_view ocsp_response,
                                    std::string* sct_list) {
  // The input is an bssl::OCSPResponse. See RFC2560, section 4.2.1. The SCT
  // list is in the extensions field of the SingleResponse which matches the
  // input certificate.
  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(ocsp_response.data()),
           ocsp_response.size());

  // Parse down to the ResponseBytes. The ResponseBytes is optional, but if it's
  // missing, this can't include an SCT list.
  CBS sequence, tagged_response_bytes, response_bytes, response_type, response;
  if (!CBS_get_asn1(&cbs, &sequence, CBS_ASN1_SEQUENCE) || CBS_len(&cbs) != 0 ||
      !SkipElements(&sequence, 1 /* responseStatus */) ||
      !CBS_get_asn1(&sequence, &tagged_response_bytes,
                    CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
      CBS_len(&sequence) != 0 ||
      !CBS_get_asn1(&tagged_response_bytes, &response_bytes,
                    CBS_ASN1_SEQUENCE) ||
      CBS_len(&tagged_response_bytes) != 0 ||
      !CBS_get_asn1(&response_bytes, &response_type, CBS_ASN1_OBJECT) ||
      !CBS_get_asn1(&response_bytes, &response, CBS_ASN1_OCTETSTRING) ||
      CBS_len(&response_bytes) != 0) {
    return false;
  }

  // The only relevant ResponseType is id-pkix-ocsp-basic.
  if (!CBS_mem_equal(&response_type, kOCSPBasicResponseOid,
                     sizeof(kOCSPBasicResponseOid))) {
    return false;
  }

  // Parse the ResponseData out of the BasicOCSPResponse. Ignore the rest.
  constexpr unsigned kVersionTag =
      CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0;
  CBS basic_response, response_data, responses;
  if (!CBS_get_asn1(&response, &basic_response, CBS_ASN1_SEQUENCE) ||
      CBS_len(&response) != 0 ||
      !CBS_get_asn1(&basic_response, &response_data, CBS_ASN1_SEQUENCE)) {
    return false;
  }

  // Extract the list of SingleResponses from the ResponseData.
  if (!SkipOptionalElement(&response_data, kVersionTag) ||
      !SkipElements(&response_data, 2 /* responderID, producedAt */) ||
      !CBS_get_asn1(&response_data, &responses, CBS_ASN1_SEQUENCE)) {
    return false;
  }

  CBS single_response;
  if (!FindMatchingSingleResponse(&responses, issuer, cert_serial_number,
                                  &single_response)) {
    return false;
  }

  // Parse the extensions out of the SingleResponse.
  constexpr unsigned kNextUpdateTag =
      CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0;
  constexpr unsigned kSingleExtensionsTag =
      CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 1;
  CBS extensions_wrap, extensions;
  if (!SkipElements(&single_response, 2 /* certStatus, thisUpdate */) ||
      !SkipOptionalElement(&single_response, kNextUpdateTag) ||
      !CBS_get_asn1(&single_response, &extensions_wrap, kSingleExtensionsTag) ||
      !CBS_get_asn1(&extensions_wrap, &extensions, CBS_ASN1_SEQUENCE) ||
      CBS_len(&extensions_wrap) != 0) {
    return false;
  }

  return ParseSCTListFromExtensions(extensions, kOCSPExtensionOid,
                                    sizeof(kOCSPExtensionOid), sct_list);
}

}  // namespace net::ct

"""

```