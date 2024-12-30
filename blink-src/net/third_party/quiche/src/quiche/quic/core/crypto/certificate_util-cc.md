Response:
Let's break down the thought process for analyzing this C++ code and generating the explanation.

**1. Understanding the Goal:**

The request asks for a functional breakdown of the provided C++ code, focusing on:

* **Core Functionality:** What does this code *do*?
* **JavaScript Relevance:** Does it have any direct or indirect connections to JavaScript?
* **Logical Reasoning:** Can we infer inputs and outputs of functions?
* **Common Errors:** What mistakes might users or developers make when using this code or related concepts?
* **Debugging Context:** How does a user end up interacting with this code?

**2. Initial Code Scan and Keyword Recognition:**

I start by quickly skimming the code, looking for recognizable patterns and keywords:

* **Headers:** `#include` directives tell us about dependencies: `<string>`, `<vector>`, `<openssl/...>`, `quiche/...`. This immediately points to cryptography (OpenSSL) and the QUIC protocol.
* **Namespaces:** `namespace quic` indicates this is part of the QUIC library.
* **Function Names:**  `AddEcdsa256SignatureAlgorithm`, `AddName`, `CBBAddTime`, `CBBAddExtension`, `IsEcdsa256Key`, `MakeKeyPairForSelfSignedCertificate`, `CreateSelfSignedCertificate`. These names are highly descriptive and give strong clues about the functionality. "SelfSignedCertificate" stands out.
* **Data Structures:** `CBB` (likely Certificate Building Block, based on usage with OpenSSL), `CertificateTimestamp`, `CertificateOptions`.
* **OpenSSL Functions:**  `EVP_...`, `EC_...`, `CBB_...` clearly relate to OpenSSL's cryptographic API.
* **String Manipulation:** `absl::StrSplit`, `absl::StrFormat`, `absl::StripAsciiWhitespace`.
* **Logging:** `QUIC_LOG(ERROR)`.
* **Assertions:** `QUICHE_DCHECK_EQ`.

**3. Deconstructing Key Functions:**

Now, I focus on the core functions, understanding their purpose and data flow:

* **Helper Functions (Add...):** Functions like `AddEcdsa256SignatureAlgorithm`, `AddName`, `CBBAddTime`, and `CBBAddExtension` are clearly building blocks for constructing X.509 certificates. They handle specific parts of the certificate structure (signature algorithm, subject/issuer names, validity periods, extensions). The `CBB` objects suggest they are building an ASN.1 encoded structure.
* **`IsEcdsa256Key`:** This is a straightforward check to ensure a provided key is the expected type for the self-signed certificate generation.
* **`MakeKeyPairForSelfSignedCertificate`:** This function uses OpenSSL to generate an ECDSA P-256 key pair. This is a prerequisite for creating a self-signed certificate.
* **`CreateSelfSignedCertificate`:** This is the main function. It takes a key and `CertificateOptions` as input and generates a self-signed X.509 certificate. The steps involve:
    * Constructing the TBSCertificate (To Be Signed Certificate).
    * Adding various fields (version, serial number, signature algorithm, issuer, subject, validity, public key).
    * Adding extensions (Key Usage).
    * Signing the TBSCertificate using the provided private key.
    * Encoding the final certificate.

**4. Identifying JavaScript Relevance (or Lack Thereof):**

I explicitly look for connections to JavaScript. While this code deals with cryptography and certificates, which are *used* in web security (and thus interact with JavaScript in browsers), this specific C++ code is a low-level implementation within Chromium. It's not directly called from JavaScript. The connection is *indirect* – the generated certificates are used by the browser, which has a JavaScript engine. Therefore, the JavaScript relevance is about *what this code enables* rather than direct interaction.

**5. Logical Reasoning (Inputs and Outputs):**

For `CreateSelfSignedCertificate`, I consider the inputs and outputs:

* **Input:**
    * `EVP_PKEY& key`:  An ECDSA P-256 private key (as enforced by the `IsEcdsa256Key` check).
    * `CertificateOptions options`: A structure containing details like subject, validity start/end, serial number.
* **Output:**
    * A `std::string` containing the DER-encoded X.509 certificate.
    * An empty string if there's an error.

I also consider the helper functions and their roles in constructing the certificate data.

**6. Identifying Common Errors:**

Based on my understanding of certificate generation and OpenSSL usage, I consider common mistakes:

* **Incorrect Key Type:**  The code explicitly checks for ECDSA P-256 keys. Using other key types will fail.
* **Invalid Distinguished Name (DN):** The `AddName` function parses the DN string. Incorrect formatting will cause errors.
* **Incorrect Date/Time Formats:** While the code handles UTC and generalized time, providing invalid date components in `CertificateTimestamp` would lead to problems (though the code itself might not directly validate this).
* **OpenSSL Errors:** Failures in OpenSSL functions (memory allocation, ASN.1 encoding) are possible. The code uses `QUIC_LOG(ERROR)` to report some of these.

**7. Tracing User Operations (Debugging Context):**

This requires understanding where certificate generation fits within the Chromium networking stack. Key scenarios include:

* **Local Development/Testing:** Developers might need to generate self-signed certificates for testing purposes. This code could be part of a tool or process for this.
* **QUIC Connection Establishment:**  While less likely for *self-signed* certificates in production, understanding how certificates are used during TLS/QUIC handshakes is relevant. The browser needs a certificate to present to the server (or vice-versa).
* **Internal Chromium Processes:** Chromium might use self-signed certificates for internal components or testing infrastructure.

The debugging path involves tracing how the `CreateSelfSignedCertificate` function is called, what parameters are passed, and if any errors occur during the OpenSSL operations.

**8. Structuring the Explanation:**

Finally, I organize my findings into a clear and structured explanation, addressing each part of the original request:

* **Functionality:** Describe the purpose of the file and the key functions.
* **JavaScript Relevance:** Explain the indirect relationship.
* **Logical Reasoning:** Provide concrete examples of inputs and outputs.
* **Common Errors:** List potential user and developer mistakes.
* **User Operations/Debugging:** Outline how a user might indirectly trigger this code.

**Self-Correction/Refinement:**

During this process, I might revisit parts of the code if I'm unsure about something. For instance, I might initially overlook the specific ASN.1 structures being built but then realize their importance when looking at the `CBB_add_asn1` calls. I also double-check the OpenSSL function documentation (even mentally, based on experience) to ensure my understanding is correct. I also considered whether the code deals with certificate *validation*, and realized it focuses on *creation*. This refinement is important to keep the explanation accurate.
这个文件 `net/third_party/quiche/src/quiche/quic/core/crypto/certificate_util.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，它提供了一些用于创建和处理 X.509 证书的实用工具函数。更具体地说，从代码内容来看，它主要专注于 **创建自签名证书**。

以下是该文件的功能分解：

**核心功能:**

1. **生成自签名证书:**  `CreateSelfSignedCertificate` 函数是该文件的核心功能。它接收一个密钥对 (`EVP_PKEY`) 和一个 `CertificateOptions` 结构体作为输入，然后生成一个自签名的 X.509 证书。
2. **生成用于自签名证书的密钥对:** `MakeKeyPairForSelfSignedCertificate` 函数用于生成一个适合自签名证书的 ECDSA P-256 密钥对。
3. **构建 ASN.1 结构:**  代码中使用了 BoringSSL 的 `CBB` (Certificate Building Block) API 来构建证书的 ASN.1 结构。这包括添加版本号、序列号、签名算法、颁发者、使用者、有效期、公钥信息和扩展字段等。
4. **添加特定的证书字段:**  文件中包含了一些辅助函数来添加证书的特定部分，例如：
    * `AddEcdsa256SignatureAlgorithm`: 添加 ECDSA with SHA-256 签名算法标识。
    * `AddName`: 添加证书的“名称”字段（例如，颁发者和使用者），可以包含通用名称 (CN)、国家名称 (C)、组织名称 (O) 和组织单元名称 (OU)。
    * `CBBAddTime`: 添加证书的有效起始时间和结束时间。
    * `CBBAddExtension`: 添加证书扩展字段，目前示例中添加了密钥用途 (Key Usage) 扩展，指定了数字签名用途。
5. **处理时间戳:** `CBBAddTime` 函数根据年份选择使用 `UTCTime` 或 `GeneralizedTime` 格式来编码时间。
6. **检查密钥类型:** `IsEcdsa256Key` 函数用于检查提供的密钥是否为 ECDSA P-256 类型，这是 `CreateSelfSignedCertificate` 函数的要求。

**与 JavaScript 的关系:**

这个 C++ 文件本身不直接与 JavaScript 代码交互。然而，它生成的证书在 Web 开发和网络安全中扮演着重要的角色，而 JavaScript 代码通常会与这些证书间接交互。

**举例说明:**

假设一个 Web 开发者想要在本地搭建一个使用 HTTPS 的开发环境，但又不想购买或使用 CA 签发的证书。他可以使用 Chromium 浏览器（或者基于 Chromium 的浏览器）的内部机制来生成一个自签名证书。

1. **用户操作:** 开发者在浏览器的设置或开发者工具中，可能会找到一个选项来生成或管理安全证书。
2. **内部调用:** 当用户触发生成自签名证书的操作时，浏览器内部的代码（很可能就包含了类似 `certificate_util.cc` 中功能的代码）会被调用。
3. **C++ 代码执行:** `MakeKeyPairForSelfSignedCertificate` 会被调用生成密钥对，然后 `CreateSelfSignedCertificate` 会被调用，使用生成的密钥对和一些默认的或用户提供的选项（例如，域名作为 CN）来创建自签名证书。
4. **证书使用:** 生成的证书会被浏览器存储并用于本地的 HTTPS 服务。当开发者在浏览器中访问 `https://localhost` 时，浏览器会使用这个自签名证书来建立安全连接。
5. **JavaScript 交互 (间接):**  开发者编写的 JavaScript 代码运行在 `https://localhost` 页面上，并通过 HTTPS 安全地加载和执行。JavaScript 代码本身并不直接调用 `certificate_util.cc` 中的函数，但它受益于该代码生成的证书所提供的安全连接。浏览器会提示用户该证书不是由受信任的机构签发的，需要用户确认信任。

**逻辑推理 (假设输入与输出):**

**假设输入 (针对 `CreateSelfSignedCertificate` 函数):**

* `key`: 一个由 `MakeKeyPairForSelfSignedCertificate` 生成的 ECDSA P-256 私钥。
* `options`:  `CertificateOptions` 结构体，包含以下值：
    * `serial_number`:  12345
    * `subject`: "CN=localhost"
    * `validity_start`: `{ year: 2023, month: 10, day: 27, hour: 10, minute: 0, second: 0 }`
    * `validity_end`: `{ year: 2024, month: 10, day: 27, hour: 10, minute: 0, second: 0 }`

**预期输出:**

一个表示自签名 X.509 证书的 DER 编码字符串。这个字符串会包含以下信息 (以 ASN.1 结构体现)：

* 版本: 3 (X.509 v3)
* 序列号: 12345
* 签名算法: ecdsa-with-SHA256
* 颁发者: CN=localhost
* 使用者: CN=localhost
* 有效期: 从 2023-10-27 10:00:00 到 2024-10-27 10:00:00
* 使用者的公钥 (对应于输入的私钥)
* 密钥用途扩展: digitalSignature

**涉及的用户或编程常见的使用错误:**

1. **密钥类型不匹配:**  `CreateSelfSignedCertificate` 函数要求使用 ECDSA P-256 密钥。如果用户尝试传入其他类型的密钥（例如 RSA 密钥），`IsEcdsa256Key` 检查会失败，函数会返回错误。
    * **举例:** 开发者错误地使用 `EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr)` 生成了 RSA 密钥，并将其传递给 `CreateSelfSignedCertificate`。
2. **Distinguished Name (DN) 格式错误:** `AddName` 函数期望特定的 DN 格式 (例如 "CN=example.com,O=MyOrg")。如果用户提供的 `CertificateOptions.subject` 字符串格式不正确，`absl::StrSplit` 或后续的解析逻辑可能会出错。
    * **举例:** 开发者提供的 subject 字符串为 "example.com; MyOrg"，使用了分号而不是逗号分隔属性。
3. **日期时间格式错误:** 虽然代码本身会处理 `UTCTime` 和 `GeneralizedTime` 的转换，但如果 `CertificateOptions.validity_start` 或 `validity_end` 中的年份、月份、日期等值超出范围，可能会导致 `CBBAddTime` 生成无效的日期时间编码。
    * **举例:** 开发者设置 `validity_start.month` 为 13。
4. **OpenSSL API 使用错误:**  直接使用 BoringSSL/OpenSSL API 时，可能会出现内存管理错误（例如，忘记释放分配的内存），或者 API 调用顺序错误。这个文件中的代码封装了一些 OpenSSL 的使用，降低了直接出错的风险，但如果修改了代码，仍然需要注意这些问题。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户尝试访问一个使用自签名证书的网站:**  例如，一个本地开发的 Web 服务，开发者自己生成了一个证书。
2. **浏览器进行 TLS 握手:** 当浏览器尝试连接到该网站时，服务器会发送其自签名证书。
3. **浏览器校验证书:** 浏览器会检查证书的有效性，包括签名、有效期、颁发者等。由于是自签名证书，浏览器通常会发现该证书不受信任。
4. **浏览器安全策略检查:**  Chromium 的网络栈会进行一系列的安全策略检查，确定如何处理这个不受信任的证书。
5. **代码执行路径可能涉及证书处理逻辑:**  在校验证书的过程中，Chromium 的代码可能会涉及到解析证书的各个字段，提取信息，并进行比较。虽然用户操作不会直接触发 `certificate_util.cc` 中的 *创建* 函数，但可能会触发与证书 *解析* 和 *验证* 相关的代码，而这些代码与证书的结构密切相关。
6. **调试线索:** 如果开发者遇到了与自签名证书相关的问题（例如，浏览器拒绝连接，或者连接显示不安全），他们可能会查看浏览器的控制台或网络日志，以获取更多错误信息。如果错误信息指向证书的特定字段或结构问题，那么开发者可能需要回头检查生成证书的代码（如果他们自己生成了证书）或者服务器提供的证书本身。对于 Chromium 开发者来说，他们可能会需要在 Chromium 的源代码中搜索与证书处理相关的代码，例如 `net/cert/` 或 `quiche/` 目录下的文件，来追踪问题。`certificate_util.cc` 虽然用于创建，但其生成的结构是其他代码解析的基础，因此理解它的功能有助于理解整个证书处理流程。

总而言之，`certificate_util.cc` 提供了一种在 Chromium 的 QUIC 实现中创建自签名证书的方法。虽然普通用户不会直接调用这个文件中的函数，但其生成的结果在网络安全和 Web 开发中扮演着重要的角色，并与 JavaScript 代码的执行环境间接相关。理解这个文件的功能有助于理解 Chromium 网络栈中证书处理的机制。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/crypto/certificate_util.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/crypto/certificate_util.h"

#include <string>
#include <vector>

#include "absl/strings/str_format.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "openssl/bn.h"
#include "openssl/bytestring.h"
#include "openssl/digest.h"
#include "openssl/ec_key.h"
#include "openssl/mem.h"
#include "openssl/pkcs7.h"
#include "openssl/pool.h"
#include "openssl/rsa.h"
#include "openssl/stack.h"
#include "quiche/quic/core/crypto/boring_utils.h"
#include "quiche/quic/platform/api/quic_logging.h"

namespace quic {
namespace {
bool AddEcdsa256SignatureAlgorithm(CBB* cbb) {
  // See RFC 5758. This is the encoding of OID 1.2.840.10045.4.3.2.
  static const uint8_t kEcdsaWithSha256[] = {0x2a, 0x86, 0x48, 0xce,
                                             0x3d, 0x04, 0x03, 0x02};

  // An AlgorithmIdentifier is described in RFC 5280, 4.1.1.2.
  CBB sequence, oid;
  if (!CBB_add_asn1(cbb, &sequence, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&sequence, &oid, CBS_ASN1_OBJECT)) {
    return false;
  }

  if (!CBB_add_bytes(&oid, kEcdsaWithSha256, sizeof(kEcdsaWithSha256))) {
    return false;
  }

  // RFC 5758, section 3.2: ecdsa-with-sha256 MUST omit the parameters field.
  return CBB_flush(cbb);
}

// Adds an X.509 Name with the specified distinguished name to |cbb|.
bool AddName(CBB* cbb, absl::string_view name) {
  // See RFC 4519.
  static const uint8_t kCommonName[] = {0x55, 0x04, 0x03};
  static const uint8_t kCountryName[] = {0x55, 0x04, 0x06};
  static const uint8_t kOrganizationName[] = {0x55, 0x04, 0x0a};
  static const uint8_t kOrganizationalUnitName[] = {0x55, 0x04, 0x0b};

  std::vector<std::string> attributes =
      absl::StrSplit(name, ',', absl::SkipEmpty());

  if (attributes.empty()) {
    QUIC_LOG(ERROR) << "Missing DN or wrong format";
    return false;
  }

  // See RFC 5280, section 4.1.2.4.
  CBB rdns;
  if (!CBB_add_asn1(cbb, &rdns, CBS_ASN1_SEQUENCE)) {
    return false;
  }

  for (const std::string& attribute : attributes) {
    std::vector<std::string> parts =
        absl::StrSplit(absl::StripAsciiWhitespace(attribute), '=');
    if (parts.size() != 2) {
      QUIC_LOG(ERROR) << "Wrong DN format at " + attribute;
      return false;
    }

    const std::string& type_string = parts[0];
    const std::string& value_string = parts[1];
    absl::Span<const uint8_t> type_bytes;
    if (type_string == "CN") {
      type_bytes = kCommonName;
    } else if (type_string == "C") {
      type_bytes = kCountryName;
    } else if (type_string == "O") {
      type_bytes = kOrganizationName;
    } else if (type_string == "OU") {
      type_bytes = kOrganizationalUnitName;
    } else {
      QUIC_LOG(ERROR) << "Unrecognized type " + type_string;
      return false;
    }

    CBB rdn, attr, type, value;
    if (!CBB_add_asn1(&rdns, &rdn, CBS_ASN1_SET) ||
        !CBB_add_asn1(&rdn, &attr, CBS_ASN1_SEQUENCE) ||
        !CBB_add_asn1(&attr, &type, CBS_ASN1_OBJECT) ||
        !CBB_add_bytes(&type, type_bytes.data(), type_bytes.size()) ||
        !CBB_add_asn1(&attr, &value,
                      type_string == "C" ? CBS_ASN1_PRINTABLESTRING
                                         : CBS_ASN1_UTF8STRING) ||
        !AddStringToCbb(&value, value_string) || !CBB_flush(&rdns)) {
      return false;
    }
  }
  if (!CBB_flush(cbb)) {
    return false;
  }
  return true;
}

bool CBBAddTime(CBB* cbb, const CertificateTimestamp& timestamp) {
  CBB child;
  std::string formatted_time;

  // Per RFC 5280, 4.1.2.5, times which fit in UTCTime must be encoded as
  // UTCTime rather than GeneralizedTime.
  const bool is_utc_time = (1950 <= timestamp.year && timestamp.year < 2050);
  if (is_utc_time) {
    uint16_t year = timestamp.year - 1900;
    if (year >= 100) {
      year -= 100;
    }
    formatted_time = absl::StrFormat("%02d", year);
    if (!CBB_add_asn1(cbb, &child, CBS_ASN1_UTCTIME)) {
      return false;
    }
  } else {
    formatted_time = absl::StrFormat("%04d", timestamp.year);
    if (!CBB_add_asn1(cbb, &child, CBS_ASN1_GENERALIZEDTIME)) {
      return false;
    }
  }

  absl::StrAppendFormat(&formatted_time, "%02d%02d%02d%02d%02dZ",
                        timestamp.month, timestamp.day, timestamp.hour,
                        timestamp.minute, timestamp.second);

  static const size_t kGeneralizedTimeLength = 15;
  static const size_t kUTCTimeLength = 13;
  QUICHE_DCHECK_EQ(formatted_time.size(),
                   is_utc_time ? kUTCTimeLength : kGeneralizedTimeLength);

  return AddStringToCbb(&child, formatted_time) && CBB_flush(cbb);
}

bool CBBAddExtension(CBB* extensions, absl::Span<const uint8_t> oid,
                     bool critical, absl::Span<const uint8_t> contents) {
  CBB extension, cbb_oid, cbb_contents;
  if (!CBB_add_asn1(extensions, &extension, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&extension, &cbb_oid, CBS_ASN1_OBJECT) ||
      !CBB_add_bytes(&cbb_oid, oid.data(), oid.size()) ||
      (critical && !CBB_add_asn1_bool(&extension, 1)) ||
      !CBB_add_asn1(&extension, &cbb_contents, CBS_ASN1_OCTETSTRING) ||
      !CBB_add_bytes(&cbb_contents, contents.data(), contents.size()) ||
      !CBB_flush(extensions)) {
    return false;
  }

  return true;
}

bool IsEcdsa256Key(const EVP_PKEY& evp_key) {
  if (EVP_PKEY_id(&evp_key) != EVP_PKEY_EC) {
    return false;
  }
  const EC_KEY* key = EVP_PKEY_get0_EC_KEY(&evp_key);
  if (key == nullptr) {
    return false;
  }
  const EC_GROUP* group = EC_KEY_get0_group(key);
  if (group == nullptr) {
    return false;
  }
  return EC_GROUP_get_curve_name(group) == NID_X9_62_prime256v1;
}

}  // namespace

bssl::UniquePtr<EVP_PKEY> MakeKeyPairForSelfSignedCertificate() {
  bssl::UniquePtr<EVP_PKEY_CTX> context(
      EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
  if (!context) {
    return nullptr;
  }
  if (EVP_PKEY_keygen_init(context.get()) != 1) {
    return nullptr;
  }
  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context.get(),
                                             NID_X9_62_prime256v1) != 1) {
    return nullptr;
  }
  EVP_PKEY* raw_key = nullptr;
  if (EVP_PKEY_keygen(context.get(), &raw_key) != 1) {
    return nullptr;
  }
  return bssl::UniquePtr<EVP_PKEY>(raw_key);
}

std::string CreateSelfSignedCertificate(EVP_PKEY& key,
                                        const CertificateOptions& options) {
  std::string error;
  if (!IsEcdsa256Key(key)) {
    QUIC_LOG(ERROR) << "CreateSelfSignedCert only accepts ECDSA P-256 keys";
    return error;
  }

  // See RFC 5280, section 4.1. First, construct the TBSCertificate.
  bssl::ScopedCBB cbb;
  CBB tbs_cert, version, validity;
  uint8_t* tbs_cert_bytes;
  size_t tbs_cert_len;

  if (!CBB_init(cbb.get(), 64) ||
      !CBB_add_asn1(cbb.get(), &tbs_cert, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&tbs_cert, &version,
                    CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
      !CBB_add_asn1_uint64(&version, 2) ||  // X.509 version 3
      !CBB_add_asn1_uint64(&tbs_cert, options.serial_number) ||
      !AddEcdsa256SignatureAlgorithm(&tbs_cert) ||  // signature algorithm
      !AddName(&tbs_cert, options.subject) ||       // issuer
      !CBB_add_asn1(&tbs_cert, &validity, CBS_ASN1_SEQUENCE) ||
      !CBBAddTime(&validity, options.validity_start) ||
      !CBBAddTime(&validity, options.validity_end) ||
      !AddName(&tbs_cert, options.subject) ||      // subject
      !EVP_marshal_public_key(&tbs_cert, &key)) {  // subjectPublicKeyInfo
    return error;
  }

  CBB outer_extensions, extensions;
  if (!CBB_add_asn1(&tbs_cert, &outer_extensions,
                    3 | CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED) ||
      !CBB_add_asn1(&outer_extensions, &extensions, CBS_ASN1_SEQUENCE)) {
    return error;
  }

  // Key Usage
  constexpr uint8_t kKeyUsageOid[] = {0x55, 0x1d, 0x0f};
  constexpr uint8_t kKeyUsageContent[] = {
      0x3,   // BIT STRING
      0x2,   // Length
      0x0,   // Unused bits
      0x80,  // bit(0): digitalSignature
  };
  CBBAddExtension(&extensions, kKeyUsageOid, true, kKeyUsageContent);

  // TODO(wub): Add more extensions here if needed.

  if (!CBB_finish(cbb.get(), &tbs_cert_bytes, &tbs_cert_len)) {
    return error;
  }

  bssl::UniquePtr<uint8_t> delete_tbs_cert_bytes(tbs_cert_bytes);

  // Sign the TBSCertificate and write the entire certificate.
  CBB cert, signature;
  bssl::ScopedEVP_MD_CTX ctx;
  uint8_t* sig_out;
  size_t sig_len;
  uint8_t* cert_bytes;
  size_t cert_len;
  if (!CBB_init(cbb.get(), tbs_cert_len) ||
      !CBB_add_asn1(cbb.get(), &cert, CBS_ASN1_SEQUENCE) ||
      !CBB_add_bytes(&cert, tbs_cert_bytes, tbs_cert_len) ||
      !AddEcdsa256SignatureAlgorithm(&cert) ||
      !CBB_add_asn1(&cert, &signature, CBS_ASN1_BITSTRING) ||
      !CBB_add_u8(&signature, 0 /* no unused bits */) ||
      !EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, &key) ||
      // Compute the maximum signature length.
      !EVP_DigestSign(ctx.get(), nullptr, &sig_len, tbs_cert_bytes,
                      tbs_cert_len) ||
      !CBB_reserve(&signature, &sig_out, sig_len) ||
      // Actually sign the TBSCertificate.
      !EVP_DigestSign(ctx.get(), sig_out, &sig_len, tbs_cert_bytes,
                      tbs_cert_len) ||
      !CBB_did_write(&signature, sig_len) ||
      !CBB_finish(cbb.get(), &cert_bytes, &cert_len)) {
    return error;
  }
  bssl::UniquePtr<uint8_t> delete_cert_bytes(cert_bytes);
  return std::string(reinterpret_cast<char*>(cert_bytes), cert_len);
}

}  // namespace quic

"""

```