Response:
Let's break down the thought process for analyzing the provided C++ code and answering the prompt.

**1. Understanding the Core Task:**

The request is about understanding the functionality of `net/cert/x509_certificate.cc` in the Chromium network stack. It also asks for connections to JavaScript, examples of logic, common errors, and debugging information. This means the analysis needs to cover several aspects:

* **Primary Purpose:** What is this file *for*?
* **Key Operations:** What are the main actions it performs?
* **Data Structures:** What are the important data types involved?
* **JavaScript Interaction (if any):** How does this relate to the web browser's scripting?
* **Logical Flows:**  Demonstrate how data is processed.
* **Error Scenarios:** Identify potential mistakes developers or users could make.
* **Debugging Context:** How does someone end up looking at this code during debugging?

**2. Initial Code Scan and Keyword Identification:**

The first step is a quick read-through of the code, looking for recognizable keywords and patterns:

* **Includes:**  `#include` statements reveal dependencies. Notable ones here are related to OpenSSL (`crypto/openssl_util.h`, `third_party/boringssl/...`), basic types (`<string>`, `<vector>`), and Chromium-specific utilities (`base/...`, `net/base/...`).
* **Class Name:** `X509Certificate` is the central class, so focus on its methods.
* **"CreateFrom..." Methods:**  These immediately suggest ways to instantiate the `X509Certificate` object from various data formats (buffer, DER, bytes, pickle).
* **"Get..." Methods:** These likely retrieve information about the certificate (subject alt name, expiration, PEM encoding, public key info).
* **"Verify..." Methods:**  These clearly relate to validating the certificate (hostname matching, self-signature).
* **Format Constants:** `FORMAT_SINGLE_CERTIFICATE`, `FORMAT_PKCS7`, `FORMAT_PEM_CERT_SEQUENCE` indicate different ways certificates can be represented.
* **Namespaces:** The code is within the `net` namespace.
* **`CRYPTO_BUFFER`:** This appears frequently, hinting at how certificate data is stored.
* **`bssl::...`:**  This confirms the heavy use of BoringSSL for cryptographic operations.
* **Comments:** Pay attention to any comments explaining the purpose of code sections.

**3. Grouping Functionality:**

Based on the keywords and method names, we can start grouping the file's functions:

* **Creation:** Methods for creating `X509Certificate` objects from different sources.
* **Inspection/Information Retrieval:** Methods for getting details about the certificate.
* **Verification:** Methods for validating the certificate.
* **Serialization/Deserialization:** Methods for converting the certificate to and from different formats (Pickle, PEM).
* **Internal Helpers:**  Private or static utility functions.

**4. Identifying JavaScript Relevance:**

Think about how a web browser uses certificates. The browser needs to:

* **Load certificates:** When a user visits an HTTPS website.
* **Verify certificates:** To ensure the connection is secure.
* **Access certificate information:**  Potentially exposed through JavaScript APIs for advanced use cases or developer tools.

This leads to the connection with JavaScript's ability to access certificate information through APIs like `chrome.certificate` or the `Certificate` interface.

**5. Constructing Logic Examples:**

For logic examples, choose a relatively straightforward function. `VerifyHostname` is a good choice because it involves a clear input (hostname) and output (boolean). Think about different scenarios:

* **Exact Match:** Hostname directly matches a SAN.
* **Wildcard Match:** Hostname matches a wildcard SAN.
* **Mismatch:** Hostname doesn't match any SAN.
* **IP Address:** Hostname is an IP address.

**6. Considering User/Programming Errors:**

Think about common mistakes developers or users might make when dealing with certificates:

* **Incorrect Format:** Trying to load a certificate in the wrong format.
* **Expired Certificates:**  A common issue.
* **Hostname Mismatch:** Visiting a site with a certificate that doesn't cover the domain.
* **Incorrect Intermediate Certificates:**  Missing or incorrect intermediate certificates leading to trust issues.

**7. Developing Debugging Scenarios:**

Imagine a user encountering a certificate-related error in their browser. What steps would lead a developer to this code?

* **HTTPS Connection Failure:**  The most common scenario.
* **Certificate Error Messages:**  The browser displaying warnings about invalid certificates.
* **Developer Tools Investigation:** Using the Security tab in DevTools to inspect certificate details.

**8. Structuring the Answer:**

Organize the findings logically using the prompts as a guide:

* **Functionality Overview:** Start with a high-level description of the file's purpose.
* **Detailed Functions:** List and describe the key methods, grouping them by function.
* **JavaScript Relationship:** Explain the connection and provide examples.
* **Logic Examples:**  Present clear input/output scenarios for a selected function.
* **Common Errors:** Describe potential pitfalls for users and developers.
* **Debugging Scenario:** Outline the steps leading to this code during debugging.

**9. Refinement and Detail:**

Go back through the code and add more specific details:

* Mention specific data structures like `CRYPTO_BUFFER`.
* Note the use of BoringSSL functions.
* Elaborate on the different certificate formats.
* Provide concrete examples of JavaScript code snippets.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe focus heavily on the low-level OpenSSL details.
* **Correction:**  Shift focus to the *purpose* of the file within Chromium's network stack and its interactions with higher-level concepts. The OpenSSL details are important but secondary to the overall functionality.
* **Initial thought:**  Just list the functions.
* **Correction:** Group functions logically to make the explanation clearer and more understandable.
* **Initial thought:**  Focus only on developer errors.
* **Correction:**  Also consider user-facing errors that might lead to debugging this code.

By following these steps, combining code analysis with knowledge of web browser architecture and common certificate-related issues, we can construct a comprehensive and accurate answer to the prompt.
这个文件 `net/cert/x509_certificate.cc` 是 Chromium 网络栈中负责处理 X.509 证书的核心组件。它提供了创建、解析、检查和操作 X.509 证书的功能。

以下是其主要功能列表：

**核心功能：**

1. **证书创建:**
   - 从各种来源创建 `X509Certificate` 对象：
     - DER 编码的证书或证书链 (`CreateFromDERCertChain`, `CreateFromBytes`)
     - PEM 编码的证书或证书链 (`CreateCertificateListFromBytes`)
     - 二进制缓冲区 (`CreateFromBuffer`)
     - 已序列化的数据（通过 `base::Pickle`，用于缓存或持久化） (`CreateFromPickle`)

2. **证书解析和信息提取:**
   - 解析证书的各个字段，如主题 (Subject)、颁发者 (Issuer)、有效期 (validity period)、序列号等。
   - 提取主题备用名称 (Subject Alternative Name, SAN)，包括 DNS 名称和 IP 地址 (`GetSubjectAltName`)。
   - 获取证书的公钥信息，包括类型 (RSA, ECDSA) 和大小 (`GetPublicKeyInfo`)。

3. **证书验证和检查:**
   - 检查证书是否已过期 (`HasExpired`)。
   - 比较两个证书是否相等，可以排除证书链的比较 (`EqualsExcludingChain`) 或包含证书链的比较 (`EqualsIncludingChain`)。
   - 验证主机名是否与证书的 SAN 或通用名称匹配 (`VerifyHostname`, `VerifyNameMatch`)。
   - 判断证书是否由指定的颁发者签发 (`IsIssuedByEncoded`)。
   - 判断证书是否是自签名证书 (`IsSelfSigned`)。

4. **证书格式转换:**
   - 将 DER 编码的证书转换为 PEM 编码 (`GetPEMEncodedFromDER`, `GetPEMEncoded`)。
   - 获取包含证书链的 PEM 编码字符串列表 (`GetPEMEncodedChain`)。

5. **证书序列化和反序列化:**
   - 将 `X509Certificate` 对象序列化到 `base::Pickle` 对象中，用于存储或传输 (`Persist`, `CreateFromPickle`).

6. **证书指纹计算:**
   - 计算证书的 SHA-256 指纹 (`CalculateFingerprint256`)。
   - 计算包含证书链的 SHA-256 指纹 (`CalculateChainFingerprint256`)。

7. **证书链管理:**
   - 存储和管理证书链中的中间证书。
   - 创建具有不同中间证书链的克隆证书 (`CloneWithDifferentIntermediates`).

**与 JavaScript 的关系：**

`net/cert/x509_certificate.cc` 本身是用 C++ 编写的，不直接包含 JavaScript 代码。然而，它提供的功能是浏览器安全机制的基础，而这些机制会影响到 JavaScript 的行为和可访问的 API。

**举例说明：**

* **HTTPS 连接安全:** 当 JavaScript 发起一个到 HTTPS 网站的请求 (例如，使用 `fetch` API 或 `XMLHttpRequest`)，浏览器会在底层使用 `X509Certificate` 类来验证服务器提供的证书。如果证书验证失败（例如，过期、主机名不匹配、不受信任的颁发者），浏览器可能会阻止 JavaScript 代码访问该网站，并显示安全警告。

   **用户操作：** 用户在地址栏输入一个 HTTPS 网址并访问。
   **调试线索：** 如果访问失败，开发者可能会在浏览器的开发者工具的 "Security" 选项卡中查看证书信息。如果证书有问题，底层的 C++ 代码（包括 `x509_certificate.cc`）会被调用来判断验证失败的原因。

* **`chrome.certificate` API:**  Chromium 提供了 `chrome.certificate` API，允许扩展程序访问客户端证书和服务器证书信息。这个 API 底层会调用 `X509Certificate` 类来获取证书的详细信息，然后将这些信息传递给 JavaScript 代码。

   **用户操作：** 用户安装了一个使用 `chrome.certificate` API 的浏览器扩展。
   **调试线索：**  如果扩展程序无法正确获取或处理证书信息，开发者可能会需要查看 `x509_certificate.cc` 中与证书信息提取相关的代码（例如 `GetSubjectAltName`, `GetPublicKeyInfo`）来理解数据是如何被解析的。

**逻辑推理示例（针对 `VerifyHostname` 函数）：**

**假设输入：**

* `hostname`: "www.example.com"
* `cert_san_dns_names`: {"www.example.com", "*.example.net"}
* `cert_san_ip_addrs`: {}

**输出：** `true`

**推理过程：** `VerifyHostname` 函数会将输入的主机名与证书的 SAN DNS 名称进行比较。因为 `cert_san_dns_names` 中包含与 `hostname` 完全匹配的 "www.example.com"，所以函数返回 `true`。

**假设输入：**

* `hostname`: "sub.example.net"
* `cert_san_dns_names`: {"www.example.com", "*.example.net"}
* `cert_san_ip_addrs`: {}

**输出：** `true`

**推理过程：** `VerifyHostname` 函数会将输入的主机名与证书的 SAN DNS 名称进行比较。`cert_san_dns_names` 中包含通配符域名 "*.example.net"，它可以匹配 "sub.example.net"，所以函数返回 `true`。

**假设输入：**

* `hostname`: "www.another.com"
* `cert_san_dns_names`: {"www.example.com", "*.example.net"}
* `cert_san_ip_addrs`: {}

**输出：** `false`

**推理过程：** 输入的主机名 "www.another.com" 既不与 `cert_san_dns_names` 中的精确匹配项 "www.example.com" 相符，也不与通配符 "*.example.net" 匹配，所以函数返回 `false`。

**用户或编程常见的错误示例：**

1. **使用错误的证书格式创建 `X509Certificate` 对象:**

   ```c++
   // 假设 der_data 实际上是 PEM 编码的
   std::string der_data = "-----BEGIN CERTIFICATE-----\n...-----END CERTIFICATE-----\n";
   scoped_refptr<X509Certificate> cert = X509Certificate::CreateFromBytes(
       base::as_bytes(base::make_span(der_data)));
   // cert 将为 nullptr，因为 CreateFromBytes 默认尝试解析 DER 格式
   ```

   **用户操作：**  开发者试图加载一个 PEM 编码的证书，但使用了期望 DER 编码的函数。
   **调试线索：** 检查 `CreateFromBytes` 的返回值，如果为 `nullptr`，则可能是格式不匹配。可以尝试使用 `CreateCertificateListFromBytes` 并指定 `FORMAT_PEM_CERT_SEQUENCE`。

2. **忘记处理证书过期的情况:**

   ```c++
   scoped_refptr<X509Certificate> cert = LoadCertificate();
   if (cert->VerifyNameMatch("www.example.com")) {
       // 假设这里直接信任证书，没有检查是否过期
       // ...
   }
   ```

   **用户操作：** 开发者在代码中验证了主机名，但没有检查证书是否已过期。
   **调试线索：** 在进行安全相关的操作前，始终调用 `cert->HasExpired()` 进行检查。浏览器通常会在证书过期时显示警告，开发者需要在代码中也进行相应的处理。

3. **在 `IsIssuedByEncoded` 中使用未规范化的颁发者名称:**

   `IsIssuedByEncoded` 期望的颁发者名称是 DER 编码的。如果直接使用从其他地方获取的字符串，可能会导致匹配失败。

   **用户操作：** 开发者尝试验证证书是否由特定的 CA 签发，但提供的颁发者名称格式不正确。
   **调试线索：**  确保传递给 `IsIssuedByEncoded` 的颁发者名称是 DER 编码的 X.500 Distinguished Name。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户访问 HTTPS 网站遇到安全错误:**
   - 用户在浏览器地址栏输入一个网址 (例如 `https://insecure.example.com`)。
   - 浏览器尝试建立 TLS 连接。
   - 服务器发送其证书链。
   - Chromium 网络栈的 SSL 代码会调用 `X509Certificate::CreateFromDERCertChain` 或 `X509Certificate::CreateCertificateListFromBytes` 来解析证书。
   - 接着，会调用各种验证函数，如 `cert->HasExpired()`, `cert->VerifyNameMatch()`, `cert->IsIssuedByEncoded()` (通过证书路径构建和验证)。
   - 如果任何验证步骤失败，浏览器会显示安全警告或阻止连接。开发者查看浏览器开发者工具的 "Security" 选项卡，可能会看到证书相关的错误信息。

2. **开发者使用 `chrome.certificate` API 的扩展程序出现问题:**
   - 开发者编写了一个浏览器扩展，使用 `chrome.certificate.getCertificates` 或 `chrome.certificate.getServerCertificate` API 来获取证书信息。
   - JavaScript 代码调用这些 API。
   - 底层实现会调用 `x509_certificate.cc` 中的相关方法来获取和解析证书数据。
   - 如果返回的数据不符合预期，或者扩展程序无法正确处理，开发者可能需要查看 `x509_certificate.cc` 中与信息提取相关的代码，例如 `GetSubjectAltName` 或 `GetPublicKeyInfo`，来理解数据是如何被构建的。

3. **Chromium 自身进行证书处理或测试:**
   - Chromium 的网络代码在处理各种安全相关的操作时，会广泛使用 `X509Certificate` 类。
   - 例如，在处理客户端证书认证、OCSP Stapling、证书吊销列表 (CRL) 检查等功能时。
   - 如果这些功能出现 bug 或需要调试，开发者可能会需要深入研究 `x509_certificate.cc` 的实现细节。

总而言之，`net/cert/x509_certificate.cc` 是 Chromium 网络安全的关键组成部分，它封装了 X.509 证书的处理逻辑，为浏览器提供安全可靠的网络连接奠定了基础。理解这个文件的功能对于理解 Chromium 的网络安全机制至关重要。

### 提示词
```
这是目录为net/cert/x509_certificate.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/x509_certificate.h"

#include <limits.h>
#include <stdlib.h>

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "base/containers/contains.h"
#include "base/containers/span.h"
#include "base/logging.h"
#include "base/notreached.h"
#include "base/numerics/safe_conversions.h"
#include "base/pickle.h"
#include "base/strings/strcat.h"
#include "base/strings/string_util.h"
#include "base/time/time.h"
#include "crypto/openssl_util.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"
#include "net/base/tracing.h"
#include "net/base/url_util.h"
#include "net/cert/asn1_util.h"
#include "net/cert/time_conversions.h"
#include "net/cert/x509_util.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/pool.h"
#include "third_party/boringssl/src/include/openssl/sha.h"
#include "third_party/boringssl/src/pki/cert_errors.h"
#include "third_party/boringssl/src/pki/name_constraints.h"
#include "third_party/boringssl/src/pki/parsed_certificate.h"
#include "third_party/boringssl/src/pki/parser.h"
#include "third_party/boringssl/src/pki/pem.h"
#include "third_party/boringssl/src/pki/signature_algorithm.h"
#include "third_party/boringssl/src/pki/verify_certificate_chain.h"
#include "third_party/boringssl/src/pki/verify_name_match.h"
#include "third_party/boringssl/src/pki/verify_signed_data.h"
#include "url/url_canon.h"

namespace net {

namespace {

// Indicates the order to use when trying to decode binary data, which is
// based on (speculation) as to what will be most common -> least common
constexpr auto kFormatDecodePriority = std::to_array<X509Certificate::Format>(
    {X509Certificate::FORMAT_SINGLE_CERTIFICATE,
     X509Certificate::FORMAT_PKCS7});

// The PEM block header used for DER certificates
const char kCertificateHeader[] = "CERTIFICATE";
// The PEM block header used for PKCS#7 data
const char kPKCS7Header[] = "PKCS7";

// Utility to split |src| on the first occurrence of |c|, if any. |right| will
// either be empty if |c| was not found, or will contain the remainder of the
// string including the split character itself.
void SplitOnChar(std::string_view src,
                 char c,
                 std::string_view* left,
                 std::string_view* right) {
  size_t pos = src.find(c);
  if (pos == std::string_view::npos) {
    *left = src;
    *right = std::string_view();
  } else {
    *left = src.substr(0, pos);
    *right = src.substr(pos);
  }
}

// Sets |value| to the Value from a DER Sequence Tag-Length-Value and return
// true, or return false if the TLV was not a valid DER Sequence.
[[nodiscard]] bool ParseSequenceValue(const bssl::der::Input& tlv,
                                      bssl::der::Input* value) {
  bssl::der::Parser parser(tlv);
  return parser.ReadTag(CBS_ASN1_SEQUENCE, value) && !parser.HasMore();
}

// Normalize |cert|'s Issuer and store it in |out_normalized_issuer|, returning
// true on success or false if there was a parsing error.
bool GetNormalizedCertIssuer(CRYPTO_BUFFER* cert,
                             std::string* out_normalized_issuer) {
  bssl::der::Input tbs_certificate_tlv;
  bssl::der::Input signature_algorithm_tlv;
  bssl::der::BitString signature_value;
  if (!bssl::ParseCertificate(
          bssl::der::Input(x509_util::CryptoBufferAsSpan(cert)),
          &tbs_certificate_tlv, &signature_algorithm_tlv, &signature_value,
          nullptr)) {
    return false;
  }
  bssl::ParsedTbsCertificate tbs;
  if (!ParseTbsCertificate(tbs_certificate_tlv,
                           x509_util::DefaultParseCertificateOptions(), &tbs,
                           nullptr))
    return false;

  bssl::der::Input issuer_value;
  if (!ParseSequenceValue(tbs.issuer_tlv, &issuer_value))
    return false;

  bssl::CertErrors errors;
  return NormalizeName(issuer_value, out_normalized_issuer, &errors);
}

bssl::UniquePtr<CRYPTO_BUFFER> CreateCertBufferFromBytesWithSanityCheck(
    base::span<const uint8_t> data) {
  bssl::der::Input tbs_certificate_tlv;
  bssl::der::Input signature_algorithm_tlv;
  bssl::der::BitString signature_value;
  // Do a bare minimum of DER parsing here to see if the input looks
  // certificate-ish.
  if (!bssl::ParseCertificate(bssl::der::Input(data), &tbs_certificate_tlv,
                              &signature_algorithm_tlv, &signature_value,
                              nullptr)) {
    return nullptr;
  }
  return x509_util::CreateCryptoBuffer(data);
}

}  // namespace

// static
scoped_refptr<X509Certificate> X509Certificate::CreateFromBuffer(
    bssl::UniquePtr<CRYPTO_BUFFER> cert_buffer,
    std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates) {
  return CreateFromBufferUnsafeOptions(std::move(cert_buffer),
                                       std::move(intermediates), {});
}

// static
scoped_refptr<X509Certificate> X509Certificate::CreateFromBufferUnsafeOptions(
    bssl::UniquePtr<CRYPTO_BUFFER> cert_buffer,
    std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates,
    UnsafeCreateOptions options) {
  DCHECK(cert_buffer);
  ParsedFields parsed;
  if (!parsed.Initialize(cert_buffer.get(), options)) {
    return nullptr;
  }
  return base::WrapRefCounted(new X509Certificate(
      std::move(parsed), std::move(cert_buffer), std::move(intermediates)));
}

// static
scoped_refptr<X509Certificate> X509Certificate::CreateFromDERCertChain(
    const std::vector<std::string_view>& der_certs) {
  return CreateFromDERCertChainUnsafeOptions(der_certs, {});
}

// static
scoped_refptr<X509Certificate>
X509Certificate::CreateFromDERCertChainUnsafeOptions(
    const std::vector<std::string_view>& der_certs,
    UnsafeCreateOptions options) {
  TRACE_EVENT0("io", "X509Certificate::CreateFromDERCertChain");
  if (der_certs.empty())
    return nullptr;

  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediate_ca_certs;
  intermediate_ca_certs.reserve(der_certs.size() - 1);
  for (size_t i = 1; i < der_certs.size(); i++) {
    intermediate_ca_certs.push_back(
        x509_util::CreateCryptoBuffer(der_certs[i]));
  }

  return CreateFromBufferUnsafeOptions(
      x509_util::CreateCryptoBuffer(der_certs[0]),
      std::move(intermediate_ca_certs), options);
}

// static
scoped_refptr<X509Certificate> X509Certificate::CreateFromBytes(
    base::span<const uint8_t> data) {
  return CreateFromBytesUnsafeOptions(data, {});
}

// static
scoped_refptr<X509Certificate> X509Certificate::CreateFromBytesUnsafeOptions(
    base::span<const uint8_t> data,
    UnsafeCreateOptions options) {
  scoped_refptr<X509Certificate> cert = CreateFromBufferUnsafeOptions(
      x509_util::CreateCryptoBuffer(data), {}, options);
  return cert;
}

// static
scoped_refptr<X509Certificate> X509Certificate::CreateFromPickle(
    base::PickleIterator* pickle_iter) {
  return CreateFromPickleUnsafeOptions(pickle_iter, {});
}

// static
scoped_refptr<X509Certificate> X509Certificate::CreateFromPickleUnsafeOptions(
    base::PickleIterator* pickle_iter,
    UnsafeCreateOptions options) {
  size_t chain_length = 0;
  if (!pickle_iter->ReadLength(&chain_length))
    return nullptr;

  std::vector<std::string_view> cert_chain;
  const char* data = nullptr;
  size_t data_length = 0;
  for (size_t i = 0; i < chain_length; ++i) {
    if (!pickle_iter->ReadData(&data, &data_length))
      return nullptr;
    cert_chain.emplace_back(data, data_length);
  }
  return CreateFromDERCertChainUnsafeOptions(cert_chain, options);
}

// static
CertificateList X509Certificate::CreateCertificateListFromBytes(
    base::span<const uint8_t> data,
    int format) {
  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> certificates;

  // Check to see if it is in a PEM-encoded form. This check is performed
  // first, as both OS X and NSS will both try to convert if they detect
  // PEM encoding, except they don't do it consistently between the two.
  std::vector<std::string> pem_headers;

  // To maintain compatibility with NSS/Firefox, CERTIFICATE is a universally
  // valid PEM block header for any format.
  pem_headers.push_back(kCertificateHeader);
  if (format & FORMAT_PKCS7)
    pem_headers.push_back(kPKCS7Header);

  bssl::PEMTokenizer pem_tokenizer(base::as_string_view(data), pem_headers);
  while (pem_tokenizer.GetNext()) {
    std::string decoded(pem_tokenizer.data());

    bssl::UniquePtr<CRYPTO_BUFFER> handle;
    if (format & FORMAT_PEM_CERT_SEQUENCE) {
      handle =
          CreateCertBufferFromBytesWithSanityCheck(base::as_byte_span(decoded));
    }
    if (handle) {
      // Parsed a DER encoded certificate. All PEM blocks that follow must
      // also be DER encoded certificates wrapped inside of PEM blocks.
      format = FORMAT_PEM_CERT_SEQUENCE;
      certificates.push_back(std::move(handle));
      continue;
    }

    // If the first block failed to parse as a DER certificate, and
    // formats other than PEM are acceptable, check to see if the decoded
    // data is one of the accepted formats.
    if (format & ~FORMAT_PEM_CERT_SEQUENCE) {
      for (size_t i = 0;
           certificates.empty() && i < std::size(kFormatDecodePriority); ++i) {
        if (format & kFormatDecodePriority[i]) {
          certificates = CreateCertBuffersFromBytes(base::as_byte_span(decoded),
                                                    kFormatDecodePriority[i]);
        }
      }
    }

    // Stop parsing after the first block for any format but a sequence of
    // PEM-encoded DER certificates. The case of FORMAT_PEM_CERT_SEQUENCE
    // is handled above, and continues processing until a certificate fails
    // to parse.
    break;
  }

  // Try each of the formats, in order of parse preference, to see if |data|
  // contains the binary representation of a Format, if it failed to parse
  // as a PEM certificate/chain.
  for (size_t i = 0;
       certificates.empty() && i < std::size(kFormatDecodePriority); ++i) {
    if (format & kFormatDecodePriority[i])
      certificates = CreateCertBuffersFromBytes(data, kFormatDecodePriority[i]);
  }

  CertificateList results;
  // No certificates parsed.
  if (certificates.empty())
    return results;

  for (auto& it : certificates) {
    scoped_refptr<X509Certificate> cert = CreateFromBuffer(std::move(it), {});
    if (cert)
      results.push_back(std::move(cert));
  }

  return results;
}

scoped_refptr<X509Certificate> X509Certificate::CloneWithDifferentIntermediates(
    std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates) {
  // If intermediates are the same, return another reference to the same
  // object. Note that this only does a pointer equality comparison on the
  // CRYPTO_BUFFERs, which is generally sufficient, but in some edge cases
  // buffers have equal contents but with different addresses. This is
  // acceptable as this is just an optimization.
  if (intermediates == intermediate_ca_certs_) {
    return this;
  }

  return base::WrapRefCounted(
      new X509Certificate(*this, std::move(intermediates)));
}

void X509Certificate::Persist(base::Pickle* pickle) const {
  DCHECK(cert_buffer_);
  // This would be an absolutely insane number of intermediates.
  if (intermediate_ca_certs_.size() > static_cast<size_t>(INT_MAX) - 1) {
    NOTREACHED();
  }
  pickle->WriteInt(static_cast<int>(intermediate_ca_certs_.size() + 1));
  pickle->WriteString(x509_util::CryptoBufferAsStringPiece(cert_buffer_.get()));
  for (const auto& intermediate : intermediate_ca_certs_) {
    pickle->WriteString(
        x509_util::CryptoBufferAsStringPiece(intermediate.get()));
  }
}

bool X509Certificate::GetSubjectAltName(
    std::vector<std::string>* dns_names,
    std::vector<std::string>* ip_addrs) const {
  if (dns_names)
    dns_names->clear();
  if (ip_addrs)
    ip_addrs->clear();

  bssl::der::Input tbs_certificate_tlv;
  bssl::der::Input signature_algorithm_tlv;
  bssl::der::BitString signature_value;
  if (!bssl::ParseCertificate(bssl::der::Input(cert_span()),
                              &tbs_certificate_tlv, &signature_algorithm_tlv,
                              &signature_value, nullptr)) {
    return false;
  }

  bssl::ParsedTbsCertificate tbs;
  if (!ParseTbsCertificate(tbs_certificate_tlv,
                           x509_util::DefaultParseCertificateOptions(), &tbs,
                           nullptr))
    return false;
  if (!tbs.extensions_tlv)
    return false;

  std::map<bssl::der::Input, bssl::ParsedExtension> extensions;
  if (!ParseExtensions(tbs.extensions_tlv.value(), &extensions))
    return false;

  bssl::ParsedExtension subject_alt_names_extension;
  if (!ConsumeExtension(bssl::der::Input(bssl::kSubjectAltNameOid), &extensions,
                        &subject_alt_names_extension)) {
    return false;
  }

  bssl::CertErrors errors;
  std::unique_ptr<bssl::GeneralNames> subject_alt_names =
      bssl::GeneralNames::Create(subject_alt_names_extension.value, &errors);
  if (!subject_alt_names)
    return false;

  if (dns_names) {
    for (const auto& dns_name : subject_alt_names->dns_names)
      dns_names->push_back(std::string(dns_name));
  }
  if (ip_addrs) {
    for (const auto& addr : subject_alt_names->ip_addresses) {
      ip_addrs->push_back(std::string(addr.AsStringView()));
    }
  }

  return !subject_alt_names->dns_names.empty() ||
         !subject_alt_names->ip_addresses.empty();
}

bool X509Certificate::HasExpired() const {
  return base::Time::Now() > valid_expiry();
}

bool X509Certificate::EqualsExcludingChain(const X509Certificate* other) const {
  return x509_util::CryptoBufferEqual(cert_buffer_.get(),
                                      other->cert_buffer_.get());
}

bool X509Certificate::EqualsIncludingChain(const X509Certificate* other) const {
  if (intermediate_ca_certs_.size() != other->intermediate_ca_certs_.size() ||
      !EqualsExcludingChain(other)) {
    return false;
  }
  for (size_t i = 0; i < intermediate_ca_certs_.size(); ++i) {
    if (!x509_util::CryptoBufferEqual(intermediate_ca_certs_[i].get(),
                                      other->intermediate_ca_certs_[i].get())) {
      return false;
    }
  }
  return true;
}

bool X509Certificate::IsIssuedByEncoded(
    const std::vector<std::string>& valid_issuers) const {
  std::vector<std::string> normalized_issuers;
  bssl::CertErrors errors;
  for (const auto& raw_issuer : valid_issuers) {
    bssl::der::Input issuer_value;
    std::string normalized_issuer;
    if (!ParseSequenceValue(bssl::der::Input(raw_issuer), &issuer_value) ||
        !NormalizeName(issuer_value, &normalized_issuer, &errors)) {
      continue;
    }
    normalized_issuers.push_back(std::move(normalized_issuer));
  }

  std::string normalized_cert_issuer;
  if (!GetNormalizedCertIssuer(cert_buffer_.get(), &normalized_cert_issuer))
    return false;
  if (base::Contains(normalized_issuers, normalized_cert_issuer))
    return true;

  for (const auto& intermediate : intermediate_ca_certs_) {
    if (!GetNormalizedCertIssuer(intermediate.get(), &normalized_cert_issuer))
      return false;
    if (base::Contains(normalized_issuers, normalized_cert_issuer))
      return true;
  }
  return false;
}

// static
bool X509Certificate::VerifyHostname(
    std::string_view hostname,
    const std::vector<std::string>& cert_san_dns_names,
    const std::vector<std::string>& cert_san_ip_addrs) {
  DCHECK(!hostname.empty());

  if (cert_san_dns_names.empty() && cert_san_ip_addrs.empty()) {
    // Either a dNSName or iPAddress subjectAltName MUST be present in order
    // to match, so fail quickly if not.
    return false;
  }

  // Perform name verification following http://tools.ietf.org/html/rfc6125.
  // The terminology used in this method is as per that RFC:-
  // Reference identifier == the host the local user/agent is intending to
  //                         access, i.e. the thing displayed in the URL bar.
  // Presented identifier(s) == name(s) the server knows itself as, in its cert.

  // CanonicalizeHost requires surrounding brackets to parse an IPv6 address.
  const std::string host_or_ip = hostname.find(':') != std::string::npos
                                     ? base::StrCat({"[", hostname, "]"})
                                     : std::string(hostname);
  url::CanonHostInfo host_info;
  std::string reference_name = CanonicalizeHost(host_or_ip, &host_info);

  // If the host cannot be canonicalized, fail fast.
  if (reference_name.empty())
    return false;

  // Fully handle all cases where |hostname| contains an IP address.
  if (host_info.IsIPAddress()) {
    std::string_view ip_addr_string(
        reinterpret_cast<const char*>(host_info.address),
        host_info.AddressLength());
    return base::Contains(cert_san_ip_addrs, ip_addr_string);
  }

  // The host portion of a URL may support a variety of name resolution formats
  // and services. However, the only supported name types in this code are IP
  // addresses, which have been handled above via iPAddress subjectAltNames,
  // and DNS names, via dNSName subjectAltNames.
  // Validate that the host conforms to the DNS preferred name syntax, in
  // either relative or absolute form, and exclude the "root" label for DNS.
  if (reference_name == "." || !IsCanonicalizedHostCompliant(reference_name))
    return false;

  // CanonicalizeHost does not normalize absolute vs relative DNS names. If
  // the input name was absolute (included trailing .), normalize it as if it
  // was relative.
  if (reference_name.back() == '.')
    reference_name.pop_back();

  // |reference_domain| is the remainder of |host| after the leading host
  // component is stripped off, but includes the leading dot e.g.
  // "www.f.com" -> ".f.com".
  // If there is no meaningful domain part to |host| (e.g. it contains no dots)
  // then |reference_domain| will be empty.
  std::string_view reference_host, reference_domain;
  SplitOnChar(reference_name, '.', &reference_host, &reference_domain);
  bool allow_wildcards = false;
  if (!reference_domain.empty()) {
    DCHECK(reference_domain.starts_with("."));

    // Do not allow wildcards for public/ICANN registry controlled domains -
    // that is, prevent *.com or *.co.uk as valid presented names, but do not
    // prevent *.appspot.com (a private registry controlled domain).
    // In addition, unknown top-level domains (such as 'intranet' domains or
    // new TLDs/gTLDs not yet added to the registry controlled domain dataset)
    // are also implicitly prevented.
    // Because |reference_domain| must contain at least one name component that
    // is not registry controlled, this ensures that all reference domains
    // contain at least three domain components when using wildcards.
    size_t registry_length =
        registry_controlled_domains::GetCanonicalHostRegistryLength(
            reference_name,
            registry_controlled_domains::INCLUDE_UNKNOWN_REGISTRIES,
            registry_controlled_domains::EXCLUDE_PRIVATE_REGISTRIES);

    // Because |reference_name| was already canonicalized, the following
    // should never happen.
    CHECK_NE(std::string::npos, registry_length);

    // Account for the leading dot in |reference_domain|.
    bool is_registry_controlled =
        registry_length != 0 &&
        registry_length == (reference_domain.size() - 1);

    // Additionally, do not attempt wildcard matching for purely numeric
    // hostnames.
    allow_wildcards =
        !is_registry_controlled &&
        reference_name.find_first_not_of("0123456789.") != std::string::npos;
  }

  // Now step through the DNS names doing wild card comparison (if necessary)
  // on each against the reference name.
  for (const auto& cert_san_dns_name : cert_san_dns_names) {
    // Catch badly corrupt cert names up front.
    if (cert_san_dns_name.empty() ||
        cert_san_dns_name.find('\0') != std::string::npos) {
      continue;
    }
    std::string presented_name(base::ToLowerASCII(cert_san_dns_name));

    // Remove trailing dot, if any.
    if (*presented_name.rbegin() == '.')
      presented_name.resize(presented_name.length() - 1);

    // The hostname must be at least as long as the cert name it is matching,
    // as we require the wildcard (if present) to match at least one character.
    if (presented_name.length() > reference_name.length())
      continue;

    std::string_view presented_host, presented_domain;
    SplitOnChar(presented_name, '.', &presented_host, &presented_domain);

    if (presented_domain != reference_domain)
      continue;

    if (presented_host != "*") {
      if (presented_host == reference_host)
        return true;
      continue;
    }

    if (!allow_wildcards)
      continue;

    return true;
  }
  return false;
}

bool X509Certificate::VerifyNameMatch(std::string_view hostname) const {
  std::vector<std::string> dns_names, ip_addrs;
  GetSubjectAltName(&dns_names, &ip_addrs);
  return VerifyHostname(hostname, dns_names, ip_addrs);
}

// static
bool X509Certificate::GetPEMEncodedFromDER(std::string_view der_encoded,
                                           std::string* pem_encoded) {
  if (der_encoded.empty())
    return false;

  *pem_encoded = bssl::PEMEncode(der_encoded, "CERTIFICATE");
  return true;
}

// static
bool X509Certificate::GetPEMEncoded(const CRYPTO_BUFFER* cert_buffer,
                                    std::string* pem_encoded) {
  return GetPEMEncodedFromDER(x509_util::CryptoBufferAsStringPiece(cert_buffer),
                              pem_encoded);
}

bool X509Certificate::GetPEMEncodedChain(
    std::vector<std::string>* pem_encoded) const {
  std::vector<std::string> encoded_chain;
  std::string pem_data;
  if (!GetPEMEncoded(cert_buffer(), &pem_data))
    return false;
  encoded_chain.push_back(pem_data);
  for (const auto& intermediate_ca_cert : intermediate_ca_certs_) {
    if (!GetPEMEncoded(intermediate_ca_cert.get(), &pem_data))
      return false;
    encoded_chain.push_back(pem_data);
  }
  pem_encoded->swap(encoded_chain);
  return true;
}

// static
void X509Certificate::GetPublicKeyInfo(const CRYPTO_BUFFER* cert_buffer,
                                       size_t* size_bits,
                                       PublicKeyType* type) {
  *type = kPublicKeyTypeUnknown;
  *size_bits = 0;

  std::string_view spki;
  if (!asn1::ExtractSPKIFromDERCert(
          x509_util::CryptoBufferAsStringPiece(cert_buffer), &spki)) {
    return;
  }

  bssl::UniquePtr<EVP_PKEY> pkey;
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(spki.data()), spki.size());
  pkey.reset(EVP_parse_public_key(&cbs));
  if (!pkey)
    return;

  switch (EVP_PKEY_id(pkey.get())) {
    case EVP_PKEY_RSA:
      *type = kPublicKeyTypeRSA;
      break;
    case EVP_PKEY_EC:
      *type = kPublicKeyTypeECDSA;
      break;
  }
  *size_bits = base::saturated_cast<size_t>(EVP_PKEY_bits(pkey.get()));
}

// static
std::vector<bssl::UniquePtr<CRYPTO_BUFFER>>
X509Certificate::CreateCertBuffersFromBytes(base::span<const uint8_t> data,
                                            Format format) {
  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> results;

  switch (format) {
    case FORMAT_SINGLE_CERTIFICATE: {
      bssl::UniquePtr<CRYPTO_BUFFER> handle =
          CreateCertBufferFromBytesWithSanityCheck(data);
      if (handle)
        results.push_back(std::move(handle));
      break;
    }
    case FORMAT_PKCS7: {
      x509_util::CreateCertBuffersFromPKCS7Bytes(data, &results);
      break;
    }
    default: {
      NOTREACHED() << "Certificate format " << format << " unimplemented";
    }
  }

  return results;
}

// static
SHA256HashValue X509Certificate::CalculateFingerprint256(
    const CRYPTO_BUFFER* cert) {
  SHA256HashValue sha256;

  SHA256(CRYPTO_BUFFER_data(cert), CRYPTO_BUFFER_len(cert), sha256.data);
  return sha256;
}

SHA256HashValue X509Certificate::CalculateChainFingerprint256() const {
  SHA256HashValue sha256;
  memset(sha256.data, 0, sizeof(sha256.data));

  SHA256_CTX sha256_ctx;
  SHA256_Init(&sha256_ctx);
  SHA256_Update(&sha256_ctx, CRYPTO_BUFFER_data(cert_buffer_.get()),
                CRYPTO_BUFFER_len(cert_buffer_.get()));
  for (const auto& cert : intermediate_ca_certs_) {
    SHA256_Update(&sha256_ctx, CRYPTO_BUFFER_data(cert.get()),
                  CRYPTO_BUFFER_len(cert.get()));
  }
  SHA256_Final(sha256.data, &sha256_ctx);

  return sha256;
}

// static
bool X509Certificate::IsSelfSigned(CRYPTO_BUFFER* cert_buffer) {
  std::shared_ptr<const bssl::ParsedCertificate> parsed_cert =
      bssl::ParsedCertificate::Create(
          bssl::UpRef(cert_buffer), x509_util::DefaultParseCertificateOptions(),
          /*errors=*/nullptr);
  if (!parsed_cert) {
    return false;
  }
  return VerifyCertificateIsSelfSigned(*parsed_cert, /*cache=*/nullptr,
                                       /*errors=*/nullptr);
}

X509Certificate::X509Certificate(
    ParsedFields parsed,
    bssl::UniquePtr<CRYPTO_BUFFER> cert_buffer,
    std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates)
    : parsed_(std::move(parsed)),
      cert_buffer_(std::move(cert_buffer)),
      intermediate_ca_certs_(std::move(intermediates)) {}

X509Certificate::X509Certificate(
    const X509Certificate& other,
    std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates)
    : parsed_(other.parsed_),
      cert_buffer_(bssl::UpRef(other.cert_buffer_)),
      intermediate_ca_certs_(std::move(intermediates)) {}

X509Certificate::~X509Certificate() = default;

base::span<const uint8_t> X509Certificate::cert_span() const {
  return x509_util::CryptoBufferAsSpan(cert_buffer_.get());
}

X509Certificate::ParsedFields::ParsedFields() = default;
X509Certificate::ParsedFields::ParsedFields(const ParsedFields&) = default;
X509Certificate::ParsedFields::ParsedFields(ParsedFields&&) = default;
X509Certificate::ParsedFields::~ParsedFields() = default;

bool X509Certificate::ParsedFields::Initialize(
    const CRYPTO_BUFFER* cert_buffer,
    X509Certificate::UnsafeCreateOptions options) {
  bssl::der::Input tbs_certificate_tlv;
  bssl::der::Input signature_algorithm_tlv;
  bssl::der::BitString signature_value;

  if (!bssl::ParseCertificate(
          bssl::der::Input(x509_util::CryptoBufferAsSpan(cert_buffer)),
          &tbs_certificate_tlv, &signature_algorithm_tlv, &signature_value,
          nullptr)) {
    return false;
  }

  bssl::ParsedTbsCertificate tbs;
  if (!ParseTbsCertificate(tbs_certificate_tlv,
                           x509_util::DefaultParseCertificateOptions(), &tbs,
                           nullptr))
    return false;

  CertPrincipal::PrintableStringHandling printable_string_handling =
      options.printable_string_is_utf8
          ? CertPrincipal::PrintableStringHandling::kAsUTF8Hack
          : CertPrincipal::PrintableStringHandling::kDefault;
  if (!subject_.ParseDistinguishedName(tbs.subject_tlv,
                                       printable_string_handling) ||
      !issuer_.ParseDistinguishedName(tbs.issuer_tlv,
                                      printable_string_handling)) {
    return false;
  }

  if (!GeneralizedTimeToTime(tbs.validity_not_before, &valid_start_) ||
      !GeneralizedTimeToTime(tbs.validity_not_after, &valid_expiry_)) {
    return false;
  }
  serial_number_ = tbs.serial_number.AsString();
  return true;
}

}  // namespace net
```