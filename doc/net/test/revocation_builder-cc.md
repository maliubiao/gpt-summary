Response:
Let's break down the thought process for analyzing the `revocation_builder.cc` file.

**1. Initial Understanding of the Purpose:**

The filename `revocation_builder.cc` immediately suggests its primary function: creating data structures related to certificate revocation. The `#include` statements confirm this, particularly including headers related to ASN.1 encoding (`net/cert/asn1_util.h`), time conversions (`net/cert/time_conversions.h`), X.509 utilities (`net/cert/x509_util.h`), and a certificate builder (`net/test/cert_builder.h`). The presence of `third_party/boringssl` headers indicates the use of BoringSSL for cryptographic operations.

**2. High-Level Functionality Identification:**

Scanning the code, we can see several distinct functions:

* **OCSP Response Building:**  Functions like `BuildOCSPResponseError`, `BuildOCSPResponse`, and `BuildOCSPResponseWithResponseData` clearly deal with constructing OCSP (Online Certificate Status Protocol) responses. The presence of `bssl::OCSPResponse` and related structures reinforces this.
* **CRL Building:**  Functions like `BuildCrl`, `BuildCrlWithSigner`, and `BuildCrlWithAlgorithmTlvAndDigest` are responsible for creating Certificate Revocation Lists (CRLs).
* **Helper Functions:**  Smaller functions like `Sha1`, `CBBAddBytes`, `CBBAddGeneralizedTime`, `FinishCBB`, and `PKeyToSPK` seem to be utility functions used by the main builders. The `CBB` prefix strongly suggests they are related to BoringSSL's Certificate Building Block API.

**3. Detailed Analysis of Key Functions (Example: `BuildOCSPResponse`)**

* **Input Parameters:**  The function takes a responder subject, responder key, production time, and a vector of `OCSPBuilderSingleResponse`. This tells us what information is needed to construct an OCSP response.
* **Core Logic:**
    * It calculates SHA-1 hashes of the responder's name and public key.
    * It uses BoringSSL's CBB API to construct the `ResponseData` structure according to RFC 6960. This involves adding ASN.1 sequences, context-specific tags, and specific data elements.
    * It iterates through the `responses` vector and calls `AddOCSPSingleResponse` for each.
    * It then calls `BuildOCSPResponseWithResponseData` to finalize the OCSP response, including signing.
* **ASN.1 Structure Awareness:** The code is heavily reliant on understanding the ASN.1 structure of OCSP responses. The comments explicitly refer to RFC 6960 and break down the ASN.1 sequences and fields. This is a crucial aspect.

**4. Identifying Relationships with JavaScript (and Browser Interactions):**

This is where we connect the low-level C++ code to higher-level browser behavior.

* **OCSP Stapling/Fetching:** The generated OCSP responses are used by the browser to verify the revocation status of certificates. When a website presents a certificate, the browser might perform OCSP stapling (the server includes the OCSP response) or fetch the OCSP response from a designated responder. This directly involves the output of functions like `BuildOCSPResponse`.
* **CRL Distribution:** Similarly, CRLs are used for revocation checking. Browsers can download CRLs from specified distribution points. The output of `BuildCrl` is what these CRL files look like.
* **No Direct JavaScript Interaction *in this file*:** It's crucial to realize that this C++ code *doesn't directly execute JavaScript*. It *provides the data* that the browser (which *does* execute JavaScript) uses for security decisions.

**5. Logical Inference (Hypothetical Inputs and Outputs):**

This involves creating concrete examples.

* **OCSP Example:**  Imagine a scenario where a certificate with serial number 123 is revoked. We can construct an `OCSPBuilderSingleResponse` object indicating this revocation, specify the issuer details, and call `BuildOCSPResponse`. The output would be a DER-encoded OCSP response stating the revocation.
* **CRL Example:**  Similarly, we can create a `std::vector<uint64_t>` containing the serial number of revoked certificates and call `BuildCrl`. The output would be a DER-encoded CRL listing those revoked certificates.

**6. Identifying User/Programming Errors:**

Common errors when *using* this code (or similar code) include:

* **Incorrect ASN.1 Structure:** Manually constructing these structures is error-prone. Forgetting a field, using the wrong tag, or incorrect ordering can lead to parsing failures.
* **Incorrect Hashing:**  Getting the SHA-1 hashes of issuer names or keys wrong will result in OCSP responses or CRLs that don't match the certificates.
* **Time Issues:** Incorrect `thisUpdate` or `nextUpdate` times can cause browsers to misinterpret revocation information.
* **Key Mismatches:** Signing OCSP responses or CRLs with the wrong key will invalidate the signature.

**7. Tracing User Actions (Debugging):**

This is about understanding how a user action can lead to this code being involved.

* **Visiting an HTTPS Website:** The most common scenario. The browser needs to verify the server's certificate, which might involve checking OCSP or CRLs.
* **Certificate Error:** If a user encounters a certificate error (e.g., "Your connection is not private"), the browser's revocation checking mechanisms might have failed. Debugging this could involve examining the OCSP responses or CRLs that were attempted to be used.
* **Developer Tools (Security Tab):**  Browsers often have developer tools that provide information about certificate status and revocation checks. This can give clues about whether OCSP or CRL checks are being performed and whether they are succeeding or failing.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This code directly interacts with the network."
* **Correction:**  "No, this code *builds the data structures* that are then transmitted over the network by other parts of the browser's networking stack."
* **Initial thought:** "JavaScript directly calls these C++ functions."
* **Correction:** "This C++ code is part of the Chromium browser. JavaScript running in a web page doesn't directly call these low-level functions. Instead, the browser's internal logic (often written in C++ itself) uses this code when handling HTTPS connections."

By following this detailed breakdown and continually refining understanding, we arrive at a comprehensive explanation of the `revocation_builder.cc` file's functionality and its place within the larger browser context.
这个文件 `net/test/revocation_builder.cc` 是 Chromium 网络栈的一部分，它的主要功能是提供 **构建工具**，用于 **创建和编码** 与证书吊销相关的各种数据结构，主要包括 **OCSP (在线证书状态协议) 响应** 和 **CRL (证书吊销列表)**。

**以下是该文件的详细功能列表：**

1. **构建 OCSP 响应 (OCSP Responses):**
   - `BuildOCSPResponseError`: 构建一个表示 OCSP 错误的响应，例如请求格式错误、内部错误等。
   - `BuildOCSPResponse`: 构建一个成功的 OCSP 响应，包含关于特定证书状态的信息（例如，是否已吊销）。这个函数会构建 `ResponseData` 部分，包括响应者 ID、生成时间以及一系列的 `SingleResponse`。
   - `BuildOCSPResponseWithResponseData`:  在已有的 `ResponseData` 基础上，构建完整的 OCSP 响应，包括签名信息。

2. **构建 CRL (Certificate Revocation Lists):**
   - `BuildCrlWithSigner`: 提供更灵活的 CRL 构建方式，允许传入一个自定义的签名函数。
   - `BuildCrl`: 构建一个标准的 CRL，列出已被吊销的证书的序列号。
   - `BuildCrlWithAlgorithmTlvAndDigest`: 类似 `BuildCrlWithSigner`，但专门用于使用指定的摘要算法进行签名。

3. **辅助函数:**
   - `Sha1()`: 返回一个 DER 编码的 SHA1 算法标识符。
   - `CBBAddBytes`: 将字节数据添加到 BoringSSL 的 `CBB` (Certificate Building Block) 中。
   - `CBBAddGeneralizedTime`: 将 `base::Time` 对象编码为 ASN.1 的 GeneralizedTime 格式并添加到 `CBB` 中。
   - `FinishCBB`: 完成 BoringSSL 的 `CBB` 操作，并返回编码后的字符串。
   - `PKeyToSPK`: 从 EVP_PKEY (公钥) 中提取 Subject Public Key Info (SPKI) 并进行处理。
   - `EncodeOCSPResponse`:  将 OCSP 响应状态和可选的响应字节编码为 DER 格式。
   - `AddOCSPSingleResponse`: 将一个单独证书的吊销状态信息添加到 OCSP 响应的 `responses` 字段中。

**与 Javascript 的关系：**

这个 C++ 文件本身并不直接包含 Javascript 代码或执行 Javascript。然而，它构建的数据结构（OCSP 响应和 CRL）是网络安全的关键组成部分，浏览器使用这些信息来验证网站证书的有效性。  **Javascript 可以通过浏览器提供的 Web API 间接地受到这些功能的影响。**

**举例说明：**

假设一个网站使用了已吊销的证书。

1. **当用户通过浏览器访问该网站时，** 浏览器的网络栈（其中就包含 `revocation_builder.cc` 提供的构建工具）可能会尝试验证服务器证书的吊销状态。
2. **如果浏览器采用 OCSP 方式验证，** 它可能会向 OCSP 服务器发送请求，询问该证书的状态。 OCSP 服务器会生成一个响应，这个响应的构建逻辑类似于 `BuildOCSPResponse`。
3. **如果浏览器采用 CRL 方式验证，** 它可能会下载由证书颁发机构发布的 CRL 文件，该文件的构建逻辑类似于 `BuildCrl`.
4. **浏览器接收到 OCSP 响应或 CRL 后，**  会判断证书是否已被吊销。
5. **如果证书已被吊销，浏览器会采取安全措施，例如阻止用户访问该网站，并显示安全警告。**

**这时，Javascript 代码可以通过以下方式观察到这种影响：**

- **`navigator.onLine`:**  如果吊销检查需要联网，而网络连接中断，Javascript 可以通过这个 API 检测到。虽然这不直接关联到 `revocation_builder.cc`，但网络连接是吊销检查的前提。
- **错误处理：** 当浏览器阻止访问已吊销证书的网站时，网页的 Javascript 代码可能会捕获到网络请求失败的错误（例如，`net::ERR_CERT_REVOKED`），并执行相应的错误处理逻辑。
- **开发者工具 API:**  在浏览器的开发者工具中，Javascript 代码（例如，Chrome 扩展）可以访问与安全相关的 API，获取有关证书状态和吊销信息，这些信息最终来源于像 `revocation_builder.cc` 构建的数据。

**逻辑推理 (假设输入与输出):**

**假设输入 (OCSP):**

- `responder_subject`: 字符串，OCSP 响应者的主题 distinguished name (DN)。
- `responder_key`: `EVP_PKEY` 指针，OCSP 响应者的私钥，用于签名响应。
- `produced_at`: `base::Time` 对象，响应的生成时间。
- `responses`: `std::vector<OCSPBuilderSingleResponse>`，包含一个或多个证书的状态信息。例如，一个 `OCSPBuilderSingleResponse` 可能表示某个证书的序列号、状态（GOOD, REVOKED, UNKNOWN）以及吊销时间等。

**假设输出 (OCSP):**

一个 `std::string`，包含 DER 编码的 OCSP 响应。这个字符串会包含以下结构：

```asn1
OCSPResponse ::= SEQUENCE {
  responseStatus         OCSPResponseStatus,
  responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL
}

ResponseBytes ::= SEQUENCE {
  responseType   OBJECT IDENTIFIER,
  response       OCTET STRING
}

BasicOCSPResponse ::= SEQUENCE {
  tbsResponseData      ResponseData,
  signatureAlgorithm   AlgorithmIdentifier,
  signature            BIT STRING,
  certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
}

ResponseData ::= SEQUENCE {
  version              [0] EXPLICIT Version DEFAULT v1,
  responderID              ResponderID,
  producedAt               GeneralizedTime,
  responses                SEQUENCE OF SingleResponse,
  responseExtensions   [1] EXPLICIT Extensions OPTIONAL
}

SingleResponse ::= SEQUENCE {
  certID                       CertID,
  certStatus                   CertStatus,
  thisUpdate                   GeneralizedTime,
  nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
  singleExtensions   [1]       EXPLICIT Extensions OPTIONAL
}
```

**假设输入 (CRL):**

- `crl_issuer_subject`: 字符串，CRL 发布者的主题 distinguished name (DN)。
- `crl_issuer_key`: `EVP_PKEY` 指针，CRL 发布者的私钥，用于签名 CRL。
- `revoked_serials`: `std::vector<uint64_t>`，包含已吊销证书的序列号列表。

**假设输出 (CRL):**

一个 `std::string`，包含 DER 编码的 CRL。这个字符串会包含以下结构：

```asn1
CertificateList  ::=  SEQUENCE  {
  tbsCertList          TBSCertList,
  signatureAlgorithm   AlgorithmIdentifier,
  signatureValue       BIT STRING
}

TBSCertList  ::=  SEQUENCE  {
  version                 Version OPTIONAL,
  signature               AlgorithmIdentifier,
  issuer                  Name,
  thisUpdate              Time,
  nextUpdate              Time OPTIONAL,
  revokedCertificates     SEQUENCE OF SEQUENCE  {
       userCertificate         CertificateSerialNumber,
       revocationDate          Time,
       crlEntryExtensions      Extensions OPTIONAL
   }  OPTIONAL,
  crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
}
```

**用户或编程常见的使用错误：**

1. **参数错误:**
   - 传递空的或无效的密钥指针 (`EVP_PKEY*`)。
   - `revoked_serials` 列表中的序列号类型不正确。
   - `responder_subject` 或 `crl_issuer_subject` 的格式不符合 Distinguished Name 的要求。
   - 时间参数 (`produced_at`, 吊销时间等) 设置不合理，例如早于证书颁发时间。

2. **逻辑错误:**
   - 在构建 OCSP 响应时，提供的吊销信息与实际情况不符。
   - CRL 的更新时间 (`thisUpdate`, `nextUpdate`) 设置不合理，导致浏览器无法正确判断 CRL 的有效性。
   - 使用错误的签名算法或密钥进行签名。

3. **BoringSSL API 使用错误:**
   - 不正确地初始化或释放 `CBB` 对象。
   - 使用错误的 ASN.1 标签或结构进行编码。
   - 在调用 `CBB_finish` 后尝试继续修改 `CBB`。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户遇到了一个与证书吊销相关的错误，例如浏览器显示 "此连接不是私密连接" 或 "此证书已被吊销"。 开发者可能会进行以下调试：

1. **用户访问网站:** 用户在浏览器地址栏输入 URL 并访问一个 HTTPS 网站。

2. **TLS 握手:** 浏览器与服务器开始 TLS 握手过程。

3. **证书验证:** 在握手过程中，服务器向浏览器发送其证书。浏览器需要验证该证书的有效性，其中包括检查证书是否已被吊销。

4. **吊销检查:** 浏览器可能会尝试以下一种或多种方法进行吊销检查：
   - **OCSP 查询:** 浏览器根据证书中指示的 OCSP 服务器地址，构建并发送 OCSP 请求。如果需要模拟 OCSP 服务器行为进行测试，`revocation_builder.cc` 可以用来构建预期的 OCSP 响应。
   - **OCSP Stapling:** 服务器在 TLS 握手中将 OCSP 响应附加在证书后发送给浏览器。  虽然 `revocation_builder.cc` 不直接处理接收，但可以用来生成用于测试的 stapled OCSP 响应。
   - **CRL 下载:** 浏览器根据证书中指示的 CRL 分发点 (CDP)，下载 CRL 文件。 `revocation_builder.cc` 可以用来构建用于测试的 CRL 文件。

5. **`revocation_builder.cc` 的角色:** 在测试或模拟这些场景时，`revocation_builder.cc` 中的函数被用来 **创建预期的 OCSP 响应或 CRL 数据**，以便验证浏览器的吊销检查逻辑是否正确。例如：
   - 可以使用 `BuildOCSPResponse` 创建一个表示证书已被吊销的 OCSP 响应，并将其配置为测试环境中的 OCSP 服务器返回。
   - 可以使用 `BuildCrl` 创建一个包含特定证书序列号的 CRL 文件，并将其放置在测试环境中的 CRL 分发点。

6. **浏览器行为:** 浏览器接收到 OCSP 响应或 CRL 后，会解析这些数据，判断证书的吊销状态。如果检测到证书已被吊销，浏览器会采取相应的安全措施。

**作为调试线索，了解 `revocation_builder.cc` 的功能可以帮助开发者：**

- **理解浏览器如何构建和处理吊销信息。**
- **模拟不同的吊销场景，例如证书已被吊销、OCSP 服务器不可用、CRL 下载失败等。**
- **验证浏览器在各种吊销场景下的行为是否符合预期。**
- **排查由于 OCSP 或 CRL 相关问题导致的连接错误。**
- **在开发和测试网络安全功能时，生成测试用的 OCSP 响应和 CRL 数据。**

总而言之，`net/test/revocation_builder.cc` 是一个测试工具，它并不直接参与到用户浏览的实时网络请求中，而是在开发和测试阶段，帮助开发者构建和验证与证书吊销相关的各种数据结构，从而确保 Chromium 网络栈的安全性。

Prompt: 
```
这是目录为net/test/revocation_builder.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/revocation_builder.h"

#include <string_view>

#include "base/containers/span.h"
#include "base/functional/callback.h"
#include "base/hash/sha1.h"
#include "base/strings/string_util.h"
#include "base/test/bind.h"
#include "net/cert/asn1_util.h"
#include "net/cert/time_conversions.h"
#include "net/cert/x509_util.h"
#include "net/test/cert_builder.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/pki/input.h"

namespace net {

namespace {

std::string Sha1() {
  // SEQUENCE { OBJECT_IDENTIFIER { 1.3.14.3.2.26 } }
  const uint8_t kSHA1[] = {0x30, 0x07, 0x06, 0x05, 0x2b,
                           0x0e, 0x03, 0x02, 0x1a};
  return std::string(std::begin(kSHA1), std::end(kSHA1));
}

// Adds bytes (specified as a std::string_view) to the given CBB.
// The argument ordering follows the boringssl CBB_* api style.
bool CBBAddBytes(CBB* cbb, std::string_view bytes) {
  return CBB_add_bytes(cbb, reinterpret_cast<const uint8_t*>(bytes.data()),
                       bytes.size());
}

// Adds bytes (specified as a span) to the given CBB.
// The argument ordering follows the boringssl CBB_* api style.
bool CBBAddBytes(CBB* cbb, base::span<const uint8_t> data) {
  return CBB_add_bytes(cbb, data.data(), data.size());
}

// Adds a GeneralizedTime value to the given CBB.
// The argument ordering follows the boringssl CBB_* api style.
bool CBBAddGeneralizedTime(CBB* cbb, const base::Time& time) {
  bssl::der::GeneralizedTime generalized_time;
  if (!EncodeTimeAsGeneralizedTime(time, &generalized_time)) {
    return false;
  }
  CBB time_cbb;
  uint8_t out[bssl::der::kGeneralizedTimeLength];
  if (!bssl::der::EncodeGeneralizedTime(generalized_time, out) ||
      !CBB_add_asn1(cbb, &time_cbb, CBS_ASN1_GENERALIZEDTIME) ||
      !CBBAddBytes(&time_cbb, out) || !CBB_flush(cbb)) {
    return false;
  }
  return true;
}

// Finalizes the CBB to a std::string.
std::string FinishCBB(CBB* cbb) {
  size_t cbb_len;
  uint8_t* cbb_bytes;

  if (!CBB_finish(cbb, &cbb_bytes, &cbb_len)) {
    ADD_FAILURE() << "CBB_finish() failed";
    return std::string();
  }

  bssl::UniquePtr<uint8_t> delete_bytes(cbb_bytes);
  return std::string(reinterpret_cast<char*>(cbb_bytes), cbb_len);
}

std::string PKeyToSPK(const EVP_PKEY* pkey) {
  bssl::ScopedCBB cbb;
  if (!CBB_init(cbb.get(), 64) || !EVP_marshal_public_key(cbb.get(), pkey)) {
    ADD_FAILURE();
    return std::string();
  }
  std::string spki = FinishCBB(cbb.get());

  std::string_view spk;
  if (!asn1::ExtractSubjectPublicKeyFromSPKI(spki, &spk)) {
    ADD_FAILURE();
    return std::string();
  }

  // ExtractSubjectPublicKeyFromSPKI() includes the unused bit count. For this
  // application, the unused bit count must be zero, and is not included in the
  // result.
  if (spk.empty() || spk[0] != '\0') {
    ADD_FAILURE();
    return std::string();
  }
  spk.remove_prefix(1);

  return std::string(spk);
}

// Returns a DER-encoded bssl::OCSPResponse with the given |response_status|.
// |response_type| and |response| are optional and may be empty.
std::string EncodeOCSPResponse(
    bssl::OCSPResponse::ResponseStatus response_status,
    bssl::der::Input response_type,
    std::string response) {
  // RFC 6960 section 4.2.1:
  //
  //    bssl::OCSPResponse ::= SEQUENCE {
  //       responseStatus         OCSPResponseStatus,
  //       responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
  //
  //    OCSPResponseStatus ::= ENUMERATED {
  //        successful            (0),  -- Response has valid confirmations
  //        malformedRequest      (1),  -- Illegal confirmation request
  //        internalError         (2),  -- Internal error in issuer
  //        tryLater              (3),  -- Try again later
  //                                    -- (4) is not used
  //        sigRequired           (5),  -- Must sign the request
  //        unauthorized          (6)   -- Request unauthorized
  //    }
  //
  //    The value for responseBytes consists of an OBJECT IDENTIFIER and a
  //    response syntax identified by that OID encoded as an OCTET STRING.
  //
  //    ResponseBytes ::=       SEQUENCE {
  //        responseType   OBJECT IDENTIFIER,
  //        response       OCTET STRING }
  bssl::ScopedCBB cbb;
  CBB ocsp_response, ocsp_response_status, ocsp_response_bytes,
      ocsp_response_bytes_sequence, ocsp_response_type,
      ocsp_response_octet_string;

  if (!CBB_init(cbb.get(), 64 + response_type.size() + response.size()) ||
      !CBB_add_asn1(cbb.get(), &ocsp_response, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&ocsp_response, &ocsp_response_status,
                    CBS_ASN1_ENUMERATED) ||
      !CBB_add_u8(&ocsp_response_status,
                  static_cast<uint8_t>(response_status))) {
    ADD_FAILURE();
    return std::string();
  }

  if (!response_type.empty()) {
    if (!CBB_add_asn1(&ocsp_response, &ocsp_response_bytes,
                      CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
        !CBB_add_asn1(&ocsp_response_bytes, &ocsp_response_bytes_sequence,
                      CBS_ASN1_SEQUENCE) ||
        !CBB_add_asn1(&ocsp_response_bytes_sequence, &ocsp_response_type,
                      CBS_ASN1_OBJECT) ||
        !CBBAddBytes(&ocsp_response_type, response_type) ||
        !CBB_add_asn1(&ocsp_response_bytes_sequence,
                      &ocsp_response_octet_string, CBS_ASN1_OCTETSTRING) ||
        !CBBAddBytes(&ocsp_response_octet_string, response)) {
      ADD_FAILURE();
      return std::string();
    }
  }

  return FinishCBB(cbb.get());
}

// Adds a DER-encoded OCSP SingleResponse to |responses_cbb|.
// |issuer_name_hash| and |issuer_key_hash| should be binary SHA1 hashes.
bool AddOCSPSingleResponse(CBB* responses_cbb,
                           const OCSPBuilderSingleResponse& response,
                           const std::string& issuer_name_hash,
                           const std::string& issuer_key_hash) {
  // RFC 6960 section 4.2.1:
  //
  //    SingleResponse ::= SEQUENCE {
  //       certID                       CertID,
  //       certStatus                   CertStatus,
  //       thisUpdate                   GeneralizedTime,
  //       nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
  //       singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
  //
  //    CertStatus ::= CHOICE {
  //        good        [0]     IMPLICIT NULL,
  //        revoked     [1]     IMPLICIT RevokedInfo,
  //        unknown     [2]     IMPLICIT UnknownInfo }
  //
  //    RevokedInfo ::= SEQUENCE {
  //        revocationTime              GeneralizedTime,
  //        revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }
  //
  //    UnknownInfo ::= NULL
  //
  // RFC 6960 section 4.1.1:
  //   CertID          ::=     SEQUENCE {
  //        hashAlgorithm       AlgorithmIdentifier,
  //        issuerNameHash      OCTET STRING, -- Hash of issuer's DN
  //        issuerKeyHash       OCTET STRING, -- Hash of issuer's public key
  //        serialNumber        CertificateSerialNumber }
  //
  //  The contents of CertID include the following fields:
  //
  //    o  hashAlgorithm is the hash algorithm used to generate the
  //       issuerNameHash and issuerKeyHash values.
  //
  //    o  issuerNameHash is the hash of the issuer's distinguished name
  //       (DN).  The hash shall be calculated over the DER encoding of the
  //       issuer's name field in the certificate being checked.
  //
  //    o  issuerKeyHash is the hash of the issuer's public key.  The hash
  //       shall be calculated over the value (excluding tag and length) of
  //       the subject public key field in the issuer's certificate.
  //
  //    o  serialNumber is the serial number of the certificate for which
  //       status is being requested.

  CBB single_response, issuer_name_hash_cbb, issuer_key_hash_cbb, cert_id;
  if (!CBB_add_asn1(responses_cbb, &single_response, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&single_response, &cert_id, CBS_ASN1_SEQUENCE) ||
      !CBBAddBytes(&cert_id, Sha1()) ||
      !CBB_add_asn1(&cert_id, &issuer_name_hash_cbb, CBS_ASN1_OCTETSTRING) ||
      !CBBAddBytes(&issuer_name_hash_cbb, issuer_name_hash) ||
      !CBB_add_asn1(&cert_id, &issuer_key_hash_cbb, CBS_ASN1_OCTETSTRING) ||
      !CBBAddBytes(&issuer_key_hash_cbb, issuer_key_hash) ||
      !CBB_add_asn1_uint64(&cert_id, response.serial)) {
    ADD_FAILURE();
    return false;
  }

  unsigned int cert_status_tag_number;
  switch (response.cert_status) {
    case bssl::OCSPRevocationStatus::GOOD:
      cert_status_tag_number = CBS_ASN1_CONTEXT_SPECIFIC | 0;
      break;
    case bssl::OCSPRevocationStatus::REVOKED:
      cert_status_tag_number =
          CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 1;
      break;
    case bssl::OCSPRevocationStatus::UNKNOWN:
      cert_status_tag_number = CBS_ASN1_CONTEXT_SPECIFIC | 2;
      break;
  }

  CBB cert_status_cbb;
  if (!CBB_add_asn1(&single_response, &cert_status_cbb,
                    cert_status_tag_number)) {
    ADD_FAILURE();
    return false;
  }
  if (response.cert_status == bssl::OCSPRevocationStatus::REVOKED &&
      !CBBAddGeneralizedTime(&cert_status_cbb, response.revocation_time)) {
    ADD_FAILURE();
    return false;
  }

  CBB next_update_cbb;
  if (!CBBAddGeneralizedTime(&single_response, response.this_update) ||
      !CBB_add_asn1(&single_response, &next_update_cbb,
                    CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
      !CBBAddGeneralizedTime(&next_update_cbb, response.next_update)) {
    ADD_FAILURE();
    return false;
  }

  return CBB_flush(responses_cbb);
}

}  // namespace

std::string BuildOCSPResponseError(
    bssl::OCSPResponse::ResponseStatus response_status) {
  DCHECK_NE(response_status, bssl::OCSPResponse::ResponseStatus::SUCCESSFUL);
  return EncodeOCSPResponse(response_status, bssl::der::Input(), std::string());
}

std::string BuildOCSPResponse(
    const std::string& responder_subject,
    EVP_PKEY* responder_key,
    base::Time produced_at,
    const std::vector<OCSPBuilderSingleResponse>& responses) {
  std::string responder_name_hash = base::SHA1HashString(responder_subject);
  std::string responder_key_hash =
      base::SHA1HashString(PKeyToSPK(responder_key));

  // RFC 6960 section 4.2.1:
  //
  //    ResponseData ::= SEQUENCE {
  //       version              [0] EXPLICIT Version DEFAULT v1,
  //       responderID              ResponderID,
  //       producedAt               GeneralizedTime,
  //       responses                SEQUENCE OF SingleResponse,
  //       responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
  //
  //    ResponderID ::= CHOICE {
  //       byName               [1] Name,
  //       byKey                [2] KeyHash }
  //
  //    KeyHash ::= OCTET STRING -- SHA-1 hash of responder's public key
  //    (excluding the tag and length fields)
  bssl::ScopedCBB tbs_cbb;
  CBB response_data, responder_id, responder_id_by_key, responses_cbb;
  if (!CBB_init(tbs_cbb.get(), 64) ||
      !CBB_add_asn1(tbs_cbb.get(), &response_data, CBS_ASN1_SEQUENCE) ||
      // Version is the default v1, so it is not encoded.
      !CBB_add_asn1(&response_data, &responder_id,
                    CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 2) ||
      !CBB_add_asn1(&responder_id, &responder_id_by_key,
                    CBS_ASN1_OCTETSTRING) ||
      !CBBAddBytes(&responder_id_by_key, responder_key_hash) ||
      !CBBAddGeneralizedTime(&response_data, produced_at) ||
      !CBB_add_asn1(&response_data, &responses_cbb, CBS_ASN1_SEQUENCE)) {
    ADD_FAILURE();
    return std::string();
  }

  for (const auto& response : responses) {
    if (!AddOCSPSingleResponse(&responses_cbb, response, responder_name_hash,
                               responder_key_hash)) {
      return std::string();
    }
  }

  // responseExtensions not currently supported.

  return BuildOCSPResponseWithResponseData(responder_key,
                                           FinishCBB(tbs_cbb.get()));
}

std::string BuildOCSPResponseWithResponseData(
    EVP_PKEY* responder_key,
    const std::string& tbs_response_data,
    std::optional<bssl::SignatureAlgorithm> signature_algorithm) {
  //    For a basic OCSP responder, responseType will be id-pkix-ocsp-basic.
  //
  //    id-pkix-ocsp           OBJECT IDENTIFIER ::= { id-ad-ocsp }
  //    id-pkix-ocsp-basic     OBJECT IDENTIFIER ::= { id-pkix-ocsp 1 }
  //
  //    The value for response SHALL be the DER encoding of
  //    BasicOCSPResponse.
  //
  //    BasicOCSPResponse       ::= SEQUENCE {
  //       tbsResponseData      ResponseData,
  //       signatureAlgorithm   AlgorithmIdentifier,
  //       signature            BIT STRING,
  //       certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
  //
  //    The value for signature SHALL be computed on the hash of the DER
  //    encoding of ResponseData.  The responder MAY include certificates in
  //    the certs field of BasicOCSPResponse that help the OCSP client verify
  //    the responder's signature.  If no certificates are included, then
  //    certs SHOULD be absent.
  //
  bssl::ScopedCBB basic_ocsp_response_cbb;
  CBB basic_ocsp_response, signature;
  if (!responder_key) {
    ADD_FAILURE();
    return std::string();
  }
  if (!signature_algorithm)
    signature_algorithm =
        CertBuilder::DefaultSignatureAlgorithmForKey(responder_key);
  if (!signature_algorithm) {
    ADD_FAILURE();
    return std::string();
  }
  std::string signature_algorithm_tlv =
      CertBuilder::SignatureAlgorithmToDer(*signature_algorithm);
  if (signature_algorithm_tlv.empty() ||
      !CBB_init(basic_ocsp_response_cbb.get(), 64 + tbs_response_data.size()) ||
      !CBB_add_asn1(basic_ocsp_response_cbb.get(), &basic_ocsp_response,
                    CBS_ASN1_SEQUENCE) ||
      !CBBAddBytes(&basic_ocsp_response, tbs_response_data) ||
      !CBBAddBytes(&basic_ocsp_response, signature_algorithm_tlv) ||
      !CBB_add_asn1(&basic_ocsp_response, &signature, CBS_ASN1_BITSTRING) ||
      !CBB_add_u8(&signature, 0 /* no unused bits */) ||
      !CertBuilder::SignData(*signature_algorithm, tbs_response_data,
                             responder_key, &signature)) {
    ADD_FAILURE();
    return std::string();
  }

  // certs field not currently supported.

  return EncodeOCSPResponse(bssl::OCSPResponse::ResponseStatus::SUCCESSFUL,
                            bssl::der::Input(bssl::kBasicOCSPResponseOid),
                            FinishCBB(basic_ocsp_response_cbb.get()));
}

std::string BuildCrlWithSigner(
    const std::string& crl_issuer_subject,
    EVP_PKEY* crl_issuer_key,
    const std::vector<uint64_t>& revoked_serials,
    const std::string& signature_algorithm_tlv,
    base::OnceCallback<bool(std::string, CBB*)> signer) {
  if (!crl_issuer_key) {
    ADD_FAILURE();
    return std::string();
  }
  //    TBSCertList  ::=  SEQUENCE  {
  //         version                 Version OPTIONAL,
  //                                      -- if present, MUST be v2
  //         signature               AlgorithmIdentifier,
  //         issuer                  Name,
  //         thisUpdate              Time,
  //         nextUpdate              Time OPTIONAL,
  //         revokedCertificates     SEQUENCE OF SEQUENCE  {
  //              userCertificate         CertificateSerialNumber,
  //              revocationDate          Time,
  //              crlEntryExtensions      Extensions OPTIONAL
  //                                       -- if present, version MUST be v2
  //                                   }  OPTIONAL,
  //         crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
  //                                       -- if present, version MUST be v2
  //                                   }
  bssl::ScopedCBB tbs_cbb;
  CBB tbs_cert_list, revoked_serials_cbb;
  if (!CBB_init(tbs_cbb.get(), 10) ||
      !CBB_add_asn1(tbs_cbb.get(), &tbs_cert_list, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1_uint64(&tbs_cert_list, 1 /* V2 */) ||
      !CBBAddBytes(&tbs_cert_list, signature_algorithm_tlv) ||
      !CBBAddBytes(&tbs_cert_list, crl_issuer_subject) ||
      !x509_util::CBBAddTime(&tbs_cert_list,
                             base::Time::Now() - base::Days(1)) ||
      !x509_util::CBBAddTime(&tbs_cert_list,
                             base::Time::Now() + base::Days(6))) {
    ADD_FAILURE();
    return std::string();
  }
  if (!revoked_serials.empty()) {
    if (!CBB_add_asn1(&tbs_cert_list, &revoked_serials_cbb,
                      CBS_ASN1_SEQUENCE)) {
      ADD_FAILURE();
      return std::string();
    }
    for (const int64_t revoked_serial : revoked_serials) {
      CBB revoked_serial_cbb;
      if (!CBB_add_asn1(&revoked_serials_cbb, &revoked_serial_cbb,
                        CBS_ASN1_SEQUENCE) ||
          !CBB_add_asn1_uint64(&revoked_serial_cbb, revoked_serial) ||
          !x509_util::CBBAddTime(&revoked_serial_cbb,
                                 base::Time::Now() - base::Days(1)) ||
          !CBB_flush(&revoked_serials_cbb)) {
        ADD_FAILURE();
        return std::string();
      }
    }
  }

  std::string tbs_tlv = FinishCBB(tbs_cbb.get());

  //    CertificateList  ::=  SEQUENCE  {
  //         tbsCertList          TBSCertList,
  //         signatureAlgorithm   AlgorithmIdentifier,
  //         signatureValue       BIT STRING  }
  bssl::ScopedCBB crl_cbb;
  CBB cert_list, signature;
  if (!CBB_init(crl_cbb.get(), 10) ||
      !CBB_add_asn1(crl_cbb.get(), &cert_list, CBS_ASN1_SEQUENCE) ||
      !CBBAddBytes(&cert_list, tbs_tlv) ||
      !CBBAddBytes(&cert_list, signature_algorithm_tlv) ||
      !CBB_add_asn1(&cert_list, &signature, CBS_ASN1_BITSTRING) ||
      !CBB_add_u8(&signature, 0 /* no unused bits */) ||
      !std::move(signer).Run(tbs_tlv, &signature)) {
    ADD_FAILURE();
    return std::string();
  }
  return FinishCBB(crl_cbb.get());
}

std::string BuildCrl(
    const std::string& crl_issuer_subject,
    EVP_PKEY* crl_issuer_key,
    const std::vector<uint64_t>& revoked_serials,
    std::optional<bssl::SignatureAlgorithm> signature_algorithm) {
  if (!signature_algorithm) {
    signature_algorithm =
        CertBuilder::DefaultSignatureAlgorithmForKey(crl_issuer_key);
  }
  if (!signature_algorithm) {
    ADD_FAILURE();
    return std::string();
  }
  std::string signature_algorithm_tlv =
      CertBuilder::SignatureAlgorithmToDer(*signature_algorithm);
  if (signature_algorithm_tlv.empty()) {
    ADD_FAILURE();
    return std::string();
  }

  auto signer =
      base::BindLambdaForTesting([&](std::string tbs_tlv, CBB* signature) {
        return CertBuilder::SignData(*signature_algorithm, tbs_tlv,
                                     crl_issuer_key, signature);
      });
  return BuildCrlWithSigner(crl_issuer_subject, crl_issuer_key, revoked_serials,
                            signature_algorithm_tlv, signer);
}

std::string BuildCrlWithAlgorithmTlvAndDigest(
    const std::string& crl_issuer_subject,
    EVP_PKEY* crl_issuer_key,
    const std::vector<uint64_t>& revoked_serials,
    const std::string& signature_algorithm_tlv,
    const EVP_MD* digest) {
  auto signer =
      base::BindLambdaForTesting([&](std::string tbs_tlv, CBB* signature) {
        return CertBuilder::SignDataWithDigest(digest, tbs_tlv, crl_issuer_key,
                                               signature);
      });
  return BuildCrlWithSigner(crl_issuer_subject, crl_issuer_key, revoked_serials,
                            signature_algorithm_tlv, signer);
}

}  // namespace net

"""

```