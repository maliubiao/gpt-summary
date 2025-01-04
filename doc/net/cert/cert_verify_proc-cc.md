Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The user wants to understand the functionality of the `cert_verify_proc.cc` file in Chromium's network stack. They are also interested in its relationship to JavaScript, logical inference with input/output, common usage errors, debugging, and a summary of its function. They explicitly mention this is part 1 of 2.

2. **Initial Scan and Keyword Identification:** I quickly scan the code for key terms and patterns. I see things like:
    * `#include "net/cert/cert_verify_proc.h"` (self-reference, important for understanding the file's purpose)
    * `CertVerifyProc` (the main class)
    * `VerifyInternal` (a core function)
    * `X509Certificate` (deals with certificates)
    * `hostname`, `ocsp_response`, `sct_list`, `flags` (inputs to verification)
    * `CertVerifyResult` (output of verification)
    * `CERT_STATUS_*` (various certificate status flags)
    * `NetLog` (for logging and debugging)
    * `crypto`, `boringssl` (underlying crypto library)
    * `UMA_HISTOGRAM_*` (for metrics)
    * Conditional compilation (`#if BUILDFLAG(...)`) indicating platform-specific behavior.

3. **Identify the Central Functionality:** The name of the file and the `CertVerifyProc` class strongly suggest its primary function is *certificate verification*. The `Verify` method is the entry point, and it calls `VerifyInternal`. This is the core of the work.

4. **Break Down the Verification Process:** I look at the code within `Verify` and the helper functions it calls to understand the steps involved in certificate verification. I notice checks for:
    * Name matching (`VerifyNameMatch`)
    * OCSP status (`BestEffortCheckOCSP`)
    * Known interception keys
    * Name constraints (`HasNameConstraintsViolation`)
    * Weak keys (`ExaminePublicKeys`)
    * SHA-1 signatures
    * Symantec distrust
    * Long validity periods
    * Non-unique hostnames

5. **Consider JavaScript Interaction:** I think about how certificate verification relates to JavaScript in a browser. JavaScript running in a web page makes requests to servers. The browser needs to verify the server's certificate to ensure secure communication (HTTPS). Therefore, while the `cert_verify_proc.cc` code isn't directly *written* in JavaScript, its outcome (successful or failed verification) directly impacts the JavaScript environment. I can illustrate this with an example of a fetch request failing due to an invalid certificate.

6. **Logical Inference (Hypothetical Input/Output):** I consider a simple scenario. If a user navigates to an HTTPS website with a valid certificate, the `CertVerifyProc` should succeed. If the certificate is expired or doesn't match the hostname, it should fail. This leads to simple input/output examples.

7. **Common Usage Errors:**  I think about what can go wrong from a user's or programmer's perspective. Users might encounter certificate errors due to incorrect system time, firewalls blocking OCSP, or the website having an invalid certificate. Programmers interacting with the network stack might misuse flags or have issues with certificate handling.

8. **Debugging:** The `NetLog` usage is a major clue for debugging. I explain how a developer can use the `chrome://net-export` tool to capture logs and trace the certificate verification process, including the parameters passed to `CertVerifyProc`. I connect the user action (navigating to a website) to the execution of this code.

9. **Address the "Part 1 of 2" Constraint:** Since this is part 1, I focus on summarizing the *overall* function of the file and avoid going into deep implementation details that might be covered in the next part.

10. **Structure and Refine:**  I organize the information into logical sections based on the user's request. I use clear headings and bullet points to make the information easy to read and understand. I review and refine the language to be precise and accurate.

11. **Self-Correction/Refinement During the Process:**
    * **Initial thought:** Maybe the interaction with JavaScript is more direct through some API.
    * **Correction:**  While there might be internal APIs, the most significant impact on JavaScript is the success or failure of network requests due to certificate validation.
    * **Initial thought:** Focus heavily on the different platform implementations.
    * **Correction:**  Since it's part 1, a high-level overview of the common functionality is more appropriate, with a brief mention of platform differences. Detailed platform specifics can be assumed to be in part 2.

By following these steps, I can generate a comprehensive and accurate answer that addresses all aspects of the user's request, focusing on the core functionalities of the `cert_verify_proc.cc` file and its place within the Chromium network stack.
这是对 Chromium 网络栈中 `net/cert/cert_verify_proc.cc` 文件功能的详细分析，涵盖了其核心职责、与 JavaScript 的关系、逻辑推理、常见错误、调试线索以及功能归纳。

**功能列举:**

`cert_verify_proc.cc` 文件实现了 `CertVerifyProc` 类，该类负责执行证书验证的核心逻辑。其主要功能包括：

1. **证书链验证:** 接收一个目标证书及其可能的中间证书链，并根据一系列规则和策略验证该证书链的有效性。
2. **主机名匹配:** 验证证书中的主机名或 SAN (Subject Alternative Name) 是否与请求的主机名匹配。
3. **OCSP (在线证书状态协议) 检查:**  检查证书是否被吊销，可以通过 OCSP stapling 或主动查询 OCSP 服务器。
4. **SCT (签名证书时间戳) 验证:** 验证证书是否包含有效的 SCT，用于确保证书已记录到证书透明度日志中。
5. **CRLSet (证书吊销列表集) 检查:**  使用 CRLSet 检查证书是否在已知的吊销列表中。
6. **公钥检查:** 检查证书及其颁发者证书的公钥是否符合安全要求，例如 RSA 密钥长度不小于 1024 位。
7. **签名算法检查:** 检查证书链中使用的签名算法是否安全，例如标记使用 SHA-1 算法的证书。
8. **名称约束检查:**  验证证书是否违反了某些特定的名称约束策略。
9. **有效期检查:** 检查证书的有效期是否合理，例如防止颁发有效期过长的证书。
10. **Symantec 证书处理:**  处理对旧版 Symantec 颁发的证书的不信任策略。
11. **内部主机名检查:**  检查由公共信任的 CA 颁发的证书是否用于内部（非唯一）主机名。
12. **NetLog 集成:**  使用 NetLog 记录证书验证过程中的事件和参数，用于调试和分析。
13. **指标收集 (UMA Histograms):**  收集关于证书验证的各种指标，例如使用的密钥类型、密钥长度、信任锚点等。
14. **平台特定实现:**  根据不同的操作系统（Android、iOS、Fuchsia 等），可能会调用平台特定的证书验证方法。
15. **Chrome Root Store 支持:** 如果启用了 Chrome Root Store，则使用内置的根证书列表进行验证。

**与 JavaScript 的关系及举例说明:**

`cert_verify_proc.cc` 的功能虽然不是直接用 JavaScript 编写的，但它对于在浏览器中运行的 JavaScript 代码至关重要，因为它直接影响 HTTPS 连接的安全性。

**举例说明:**

假设一个 JavaScript 代码尝试使用 `fetch` API 发起一个 HTTPS 请求到一个域名为 `example.com` 的服务器：

```javascript
fetch('https://example.com/data')
  .then(response => {
    console.log('请求成功:', response);
  })
  .catch(error => {
    console.error('请求失败:', error);
  });
```

在这个过程中，`cert_verify_proc.cc` 会被调用来验证 `example.com` 服务器提供的 SSL/TLS 证书。

* **成功场景:** 如果 `cert_verify_proc.cc` 成功验证了证书（主机名匹配、未过期、CA 可信等），那么 JavaScript 的 `fetch` 请求会成功，`then` 代码块会被执行。
* **失败场景:** 如果 `cert_verify_proc.cc` 验证证书失败（例如，证书已过期，`CERT_STATUS_DATE_INVALID`），那么 `fetch` 请求会失败，`catch` 代码块会被执行，并且浏览器可能会显示一个安全警告或错误页面，阻止 JavaScript 代码继续访问该网站。

**逻辑推理、假设输入与输出:**

**假设输入:**

* `cert`: 一个 `X509Certificate` 对象，包含目标服务器的证书和可能的中间证书。
* `hostname`: 字符串 `"example.com"`，表示用户尝试访问的主机名。
* `ocsp_response`:  一个可选的 OCSP 响应字符串，可能来自 OCSP stapling。
* `sct_list`: 一个可选的 SCT 列表字符串。
* `flags`:  证书验证的标志位，例如 `VERIFY_ENABLE_SHA1_LOCAL_ANCHORS`。

**逻辑推理:**

1. `CertVerifyProc::Verify` 方法被调用，传入上述输入。
2. `VerifyInternal` 方法会被调用以执行核心的证书验证逻辑。
3. 文件会检查证书的有效期，如果当前时间晚于证书的 `valid_expiry()`，则会设置 `verify_result->cert_status` 包含 `CERT_STATUS_DATE_INVALID`。
4. 文件会检查证书的主机名，如果 `example.com` 不匹配证书的 CN 或 SAN，则会设置 `verify_result->cert_status` 包含 `CERT_STATUS_COMMON_NAME_INVALID`。
5. 如果提供了 `ocsp_response`，文件会尝试解析并验证 OCSP 响应，检查证书是否被吊销。
6. 文件还会根据 `flags` 和其他策略执行诸如弱密钥检查、签名算法检查等。

**假设输出 (如果证书过期):**

* `rv`: 返回 `net::ERR_CERT_DATE_INVALID`。
* `verify_result->cert_status`: 包含 `CERT_STATUS_DATE_INVALID`。

**假设输出 (如果证书有效):**

* `rv`: 返回 `net::OK`。
* `verify_result->cert_status`: 可能包含其他状态，但不会包含表示错误的标志（除非有警告性质的状态）。
* `verify_result->verified_cert`: 指向输入的 `cert` 对象。
* `verify_result->public_key_hashes`: 包含证书链中公钥的哈希值。
* `verify_result->is_issued_by_known_root`:  布尔值，指示证书是否由已知的根 CA 颁发。

**用户或编程常见的使用错误及举例说明:**

1. **用户系统时间不正确:** 如果用户的计算机时间设置不正确（例如，提前或延迟），可能导致对尚未生效或已过期的证书的误判。
   * **举例:** 用户系统时间设置为未来某个日期，访问一个当前有效的 HTTPS 网站，`cert_verify_proc.cc` 可能会因为时间不匹配而返回 `ERR_CERT_DATE_INVALID`。

2. **防火墙或网络配置阻止 OCSP 请求:** 如果用户的网络环境阻止浏览器访问 OCSP 服务器，可能导致无法获取证书的吊销状态。
   * **举例:**  用户网络防火墙阻止访问 `ocsp.example.com`，即使证书被吊销，`cert_verify_proc.cc` 也可能无法验证其吊销状态，但通常会有其他机制或超时来处理这种情况。

3. **程序员错误地配置证书验证标志:**  在嵌入式环境或特殊场景下，程序员可能会修改证书验证的标志，如果配置不当，可能会导致安全漏洞或不必要的错误。
   * **举例:** 错误地设置 `VERIFY_DISABLE_SYMANTEC_ENFORCEMENT` 可能会允许不安全的 Symantec 证书被信任。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户在地址栏输入 HTTPS 网址或点击 HTTPS 链接:** 这是触发证书验证过程的最常见方式。
2. **浏览器发起与服务器的 TLS 握手:** 在 TLS 握手过程中，服务器会向浏览器发送其 SSL/TLS 证书。
3. **网络栈接收到服务器证书:** Chromium 的网络栈接收到服务器发送的证书链。
4. **调用 `CertVerifier::Verify` 或类似方法:** 网络栈中的某个组件（例如 `TransportSecurityState` 或 `CertVerifier`) 会调用 `CertVerifyProc::Verify` 方法，将接收到的证书、目标主机名等信息传递给它。
5. **`CertVerifyProc::Verify` 执行验证逻辑:**  `cert_verify_proc.cc` 中的代码会执行上述的功能，进行各种证书检查。
6. **返回验证结果:** `CertVerifyProc::Verify` 方法会返回验证结果（`net::OK` 或错误码）以及 `CertVerifyResult` 对象，其中包含详细的验证状态。
7. **浏览器根据验证结果采取行动:**  如果验证成功，浏览器会继续进行 HTTPS 连接；如果验证失败，浏览器会显示错误页面或安全警告。

**作为调试线索:**

* **使用 `chrome://net-export/` 捕获网络日志:**  通过捕获网络日志，开发者可以查看证书验证的详细过程，包括传递给 `CertVerifyProc::Verify` 的参数和返回的 `CertVerifyResult`。
* **查看 `chrome://flags/` 中与证书相关的实验性功能:**  某些实验性功能可能会影响证书验证的行为。
* **检查系统时间:** 确保操作系统的时间和日期设置正确。
* **检查网络连接和防火墙设置:**  确认网络连接正常，并且防火墙没有阻止必要的 OCSP 或其他证书验证相关的请求。
* **查看开发者工具的安全标签页:**  开发者工具的安全标签页会显示关于当前网站证书的详细信息和验证状态。

**功能归纳 (第 1 部分):**

`net/cert/cert_verify_proc.cc` 文件是 Chromium 网络栈中负责核心证书验证逻辑的关键组件。它接收证书链和相关信息，执行一系列的安全检查（如主机名匹配、有效期、吊销状态、签名算法等），并将验证结果返回给调用者。这个过程对于确保 HTTPS 连接的安全性至关重要，直接影响着在浏览器中运行的 JavaScript 代码与服务器的安全交互。 该文件的主要目标是判断一个给定的证书是否可以被信任，从而保护用户免受中间人攻击和其他基于证书的威胁。

Prompt: 
```
这是目录为net/cert/cert_verify_proc.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_verify_proc.h"

#include <stdint.h>

#include <algorithm>
#include <optional>
#include <string_view>

#include "base/containers/flat_set.h"
#include "base/containers/span.h"
#include "base/memory/raw_span.h"
#include "base/metrics/histogram.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/strings/strcat.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/threading/scoped_blocking_call.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "crypto/crypto_buildflags.h"
#include "crypto/sha2.h"
#include "net/base/cronet_buildflags.h"
#include "net/base/features.h"
#include "net/base/net_errors.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"
#include "net/base/url_util.h"
#include "net/cert/asn1_util.h"
#include "net/cert/cert_net_fetcher.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/crl_set.h"
#include "net/cert/internal/revocation_checker.h"
#include "net/cert/internal/system_trust_store.h"
#include "net/cert/known_roots.h"
#include "net/cert/symantec_certs.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_certificate_net_log_param.h"
#include "net/cert/x509_util.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_values.h"
#include "net/log/net_log_with_source.h"
#include "third_party/boringssl/src/include/openssl/pool.h"
#include "third_party/boringssl/src/pki/encode_values.h"
#include "third_party/boringssl/src/pki/extended_key_usage.h"
#include "third_party/boringssl/src/pki/ocsp.h"
#include "third_party/boringssl/src/pki/ocsp_revocation_status.h"
#include "third_party/boringssl/src/pki/parse_certificate.h"
#include "third_party/boringssl/src/pki/pem.h"
#include "third_party/boringssl/src/pki/signature_algorithm.h"
#include "url/url_canon.h"

#if BUILDFLAG(IS_FUCHSIA) || BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
#include "net/cert/cert_verify_proc_builtin.h"
#endif

#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
#include "net/cert/internal/trust_store_chrome.h"
#endif  // CHROME_ROOT_STORE_SUPPORTED

#if BUILDFLAG(IS_ANDROID)
#include "net/cert/cert_verify_proc_android.h"
#elif BUILDFLAG(IS_IOS)
#include "net/cert/cert_verify_proc_ios.h"
#endif

namespace net {

namespace {

// Constants used to build histogram names
const char kLeafCert[] = "Leaf";
const char kIntermediateCert[] = "Intermediate";
const char kRootCert[] = "Root";

// Histogram buckets for RSA key sizes, as well as unknown key types. RSA key
// sizes < 1024 bits should cause errors, while key sizes > 16K are not
// supported by BoringSSL.
const int kRsaKeySizes[] = {512,  768,  1024, 1536, 2048,
                            3072, 4096, 8192, 16384};
// Histogram buckets for ECDSA key sizes. The list was historically based upon
// FIPS 186-4 approved curves, but most are impossible. BoringSSL will only ever
// return P-224, P-256, P-384, or P-521, and the verifier will reject P-224.
const int kEcdsaKeySizes[] = {163, 192, 224, 233, 256, 283, 384, 409, 521, 571};

const char* CertTypeToString(X509Certificate::PublicKeyType cert_type) {
  switch (cert_type) {
    case X509Certificate::kPublicKeyTypeUnknown:
      return "Unknown";
    case X509Certificate::kPublicKeyTypeRSA:
      return "RSA";
    case X509Certificate::kPublicKeyTypeECDSA:
      return "ECDSA";
  }
  NOTREACHED();
}

void RecordPublicKeyHistogram(const char* chain_position,
                              bool baseline_keysize_applies,
                              size_t size_bits,
                              X509Certificate::PublicKeyType cert_type) {
  std::string histogram_name =
      base::StringPrintf("CertificateType2.%s.%s.%s",
                         baseline_keysize_applies ? "BR" : "NonBR",
                         chain_position,
                         CertTypeToString(cert_type));
  // Do not use UMA_HISTOGRAM_... macros here, as it caches the Histogram
  // instance and thus only works if |histogram_name| is constant.
  base::HistogramBase* counter = nullptr;

  // Histogram buckets are contingent upon the underlying algorithm being used.
  switch (cert_type) {
    case X509Certificate::kPublicKeyTypeECDSA:
      counter = base::CustomHistogram::FactoryGet(
          histogram_name,
          base::CustomHistogram::ArrayToCustomEnumRanges(kEcdsaKeySizes),
          base::HistogramBase::kUmaTargetedHistogramFlag);
      break;
    case X509Certificate::kPublicKeyTypeRSA:
    case X509Certificate::kPublicKeyTypeUnknown:
      counter = base::CustomHistogram::FactoryGet(
          histogram_name,
          base::CustomHistogram::ArrayToCustomEnumRanges(kRsaKeySizes),
          base::HistogramBase::kUmaTargetedHistogramFlag);
      break;
  }
  counter->Add(size_bits);
}

// Returns true if |type| is |kPublicKeyTypeRSA| and if |size_bits| is < 1024.
// Note that this means there may be false negatives: keys for other algorithms
// and which are weak will pass this test.
bool IsWeakKey(X509Certificate::PublicKeyType type, size_t size_bits) {
  switch (type) {
    case X509Certificate::kPublicKeyTypeRSA:
      return size_bits < 1024;
    default:
      return false;
  }
}

// Returns true if |cert| contains a known-weak key. Additionally, histograms
// the observed keys for future tightening of the definition of what
// constitutes a weak key.
bool ExaminePublicKeys(const scoped_refptr<X509Certificate>& cert,
                       bool should_histogram) {
  // The effective date of the CA/Browser Forum's Baseline Requirements -
  // 2012-07-01 00:00:00 UTC.
  const base::Time kBaselineEffectiveDate =
      base::Time::FromInternalValue(INT64_C(12985574400000000));
  // The effective date of the key size requirements from Appendix A, v1.1.5
  // 2014-01-01 00:00:00 UTC.
  const base::Time kBaselineKeysizeEffectiveDate =
      base::Time::FromInternalValue(INT64_C(13033008000000000));

  size_t size_bits = 0;
  X509Certificate::PublicKeyType type = X509Certificate::kPublicKeyTypeUnknown;
  bool weak_key = false;
  bool baseline_keysize_applies =
      cert->valid_start() >= kBaselineEffectiveDate &&
      cert->valid_expiry() >= kBaselineKeysizeEffectiveDate;

  X509Certificate::GetPublicKeyInfo(cert->cert_buffer(), &size_bits, &type);
  if (should_histogram) {
    RecordPublicKeyHistogram(kLeafCert, baseline_keysize_applies, size_bits,
                             type);
  }
  if (IsWeakKey(type, size_bits))
    weak_key = true;

  const std::vector<bssl::UniquePtr<CRYPTO_BUFFER>>& intermediates =
      cert->intermediate_buffers();
  for (size_t i = 0; i < intermediates.size(); ++i) {
    X509Certificate::GetPublicKeyInfo(intermediates[i].get(), &size_bits,
                                      &type);
    if (should_histogram) {
      RecordPublicKeyHistogram(
          (i < intermediates.size() - 1) ? kIntermediateCert : kRootCert,
          baseline_keysize_applies,
          size_bits,
          type);
    }
    if (!weak_key && IsWeakKey(type, size_bits))
      weak_key = true;
  }

  return weak_key;
}

void BestEffortCheckOCSP(const std::string& raw_response,
                         const X509Certificate& certificate,
                         bssl::OCSPVerifyResult* verify_result) {
  if (raw_response.empty()) {
    *verify_result = bssl::OCSPVerifyResult();
    verify_result->response_status = bssl::OCSPVerifyResult::MISSING;
    return;
  }

  std::string_view cert_der =
      x509_util::CryptoBufferAsStringPiece(certificate.cert_buffer());

  // Try to get the certificate that signed |certificate|. This will run into
  // problems if the CertVerifyProc implementation doesn't return the ordered
  // certificates. If that happens the OCSP verification may be incorrect.
  std::string_view issuer_der;
  if (certificate.intermediate_buffers().empty()) {
    if (X509Certificate::IsSelfSigned(certificate.cert_buffer())) {
      issuer_der = cert_der;
    } else {
      // A valid cert chain wasn't provided.
      *verify_result = bssl::OCSPVerifyResult();
      return;
    }
  } else {
    issuer_der = x509_util::CryptoBufferAsStringPiece(
        certificate.intermediate_buffers().front().get());
  }

  verify_result->revocation_status = bssl::CheckOCSP(
      raw_response, cert_der, issuer_der, base::Time::Now().ToTimeT(),
      kMaxRevocationLeafUpdateAge.InSeconds(), &verify_result->response_status);
}

// Records details about the most-specific trust anchor in |hashes|, which is
// expected to be ordered with the leaf cert first and the root cert last.
// "Most-specific" refers to the case that it is not uncommon to have multiple
// potential trust anchors present in a chain, depending on the client trust
// store. For example, '1999-Root' cross-signing '2005-Root' cross-signing
// '2012-Root' cross-signing '2017-Root', then followed by intermediate and
// leaf. For purposes of assessing impact of, say, removing 1999-Root, while
// including 2017-Root as a trust anchor, then the validation should be
// counted as 2017-Root, rather than 1999-Root.
//
// This also accounts for situations in which a new CA is introduced, and
// has been cross-signed by an existing CA. Assessing impact should use the
// most-specific trust anchor, when possible.
//
// This also histograms for divergence between the root store and
// |spki_hashes| - that is, situations in which the OS methods of detecting
// a known root flag a certificate as known, but its hash is not known as part
// of the built-in list.
void RecordTrustAnchorHistogram(const HashValueVector& spki_hashes,
                                bool is_issued_by_known_root) {
  int32_t id = 0;
  for (const auto& hash : spki_hashes) {
    id = GetNetTrustAnchorHistogramIdForSPKI(hash);
    if (id != 0)
      break;
  }
  base::UmaHistogramSparse("Net.Certificate.TrustAnchor.Verify", id);

  // Record when a known trust anchor is not found within the chain, but the
  // certificate is flagged as being from a known root (meaning a fallback to
  // OS-based methods of determination).
  if (id == 0) {
    UMA_HISTOGRAM_BOOLEAN("Net.Certificate.TrustAnchor.VerifyOutOfDate",
                          is_issued_by_known_root);
  }
}

// Inspects the signature algorithms in a single certificate |cert|.
//
//   * Sets |verify_result->has_sha1| to true if the certificate uses SHA1.
//
// Returns false if the signature algorithm was unknown or mismatched.
[[nodiscard]] bool InspectSignatureAlgorithmForCert(
    const CRYPTO_BUFFER* cert,
    CertVerifyResult* verify_result) {
  std::string_view cert_algorithm_sequence;
  std::string_view tbs_algorithm_sequence;

  // Extract the AlgorithmIdentifier SEQUENCEs
  if (!asn1::ExtractSignatureAlgorithmsFromDERCert(
          x509_util::CryptoBufferAsStringPiece(cert), &cert_algorithm_sequence,
          &tbs_algorithm_sequence)) {
    return false;
  }

  std::optional<bssl::SignatureAlgorithm> cert_algorithm =
      bssl::ParseSignatureAlgorithm(bssl::der::Input(cert_algorithm_sequence));
  std::optional<bssl::SignatureAlgorithm> tbs_algorithm =
      bssl::ParseSignatureAlgorithm(bssl::der::Input(tbs_algorithm_sequence));
  if (!cert_algorithm || !tbs_algorithm || *cert_algorithm != *tbs_algorithm) {
    return false;
  }

  switch (*cert_algorithm) {
    case bssl::SignatureAlgorithm::kRsaPkcs1Sha1:
    case bssl::SignatureAlgorithm::kEcdsaSha1:
      verify_result->has_sha1 = true;
      return true;  // For now.

    case bssl::SignatureAlgorithm::kRsaPkcs1Sha256:
    case bssl::SignatureAlgorithm::kRsaPkcs1Sha384:
    case bssl::SignatureAlgorithm::kRsaPkcs1Sha512:
    case bssl::SignatureAlgorithm::kEcdsaSha256:
    case bssl::SignatureAlgorithm::kEcdsaSha384:
    case bssl::SignatureAlgorithm::kEcdsaSha512:
    case bssl::SignatureAlgorithm::kRsaPssSha256:
    case bssl::SignatureAlgorithm::kRsaPssSha384:
    case bssl::SignatureAlgorithm::kRsaPssSha512:
      return true;
  }

  NOTREACHED();
}

// InspectSignatureAlgorithmsInChain() sets |verify_result->has_*| based on
// the signature algorithms used in the chain, and also checks that certificates
// don't have contradictory signature algorithms.
//
// Returns false if any signature algorithm in the chain is unknown or
// mismatched.
//
// Background:
//
// X.509 certificates contain two redundant descriptors for the signature
// algorithm; one is covered by the signature, but in order to verify the
// signature, the other signature algorithm is untrusted.
//
// RFC 5280 states that the two should be equal, in order to mitigate risk of
// signature substitution attacks, but also discourages verifiers from enforcing
// the profile of RFC 5280.
//
// System verifiers are inconsistent - some use the unsigned signature, some use
// the signed signature, and they generally do not enforce that both match. This
// creates confusion, as it's possible that the signature itself may be checked
// using algorithm A, but if subsequent consumers report the certificate
// algorithm, they may end up reporting algorithm B, which was not used to
// verify the certificate. This function enforces that the two signatures match
// in order to prevent such confusion.
[[nodiscard]] bool InspectSignatureAlgorithmsInChain(
    CertVerifyResult* verify_result) {
  const std::vector<bssl::UniquePtr<CRYPTO_BUFFER>>& intermediates =
      verify_result->verified_cert->intermediate_buffers();

  // If there are no intermediates, then the leaf is trusted or verification
  // failed.
  if (intermediates.empty())
    return true;

  DCHECK(!verify_result->has_sha1);

  // Fill in hash algorithms for the leaf certificate.
  if (!InspectSignatureAlgorithmForCert(
          verify_result->verified_cert->cert_buffer(), verify_result)) {
    return false;
  }

  // Fill in hash algorithms for the intermediate cerificates, excluding the
  // final one (which is presumably the trust anchor; may be incorrect for
  // partial chains).
  for (size_t i = 0; i + 1 < intermediates.size(); ++i) {
    if (!InspectSignatureAlgorithmForCert(intermediates[i].get(),
                                          verify_result))
      return false;
  }

  return true;
}

base::Value::Dict CertVerifyParams(X509Certificate* cert,
                                   const std::string& hostname,
                                   const std::string& ocsp_response,
                                   const std::string& sct_list,
                                   int flags,
                                   CRLSet* crl_set) {
  base::Value::Dict dict;
  dict.Set("certificates", NetLogX509CertificateList(cert));
  if (!ocsp_response.empty()) {
    dict.Set("ocsp_response",
             bssl::PEMEncode(ocsp_response, "NETLOG OCSP RESPONSE"));
  }
  if (!sct_list.empty()) {
    dict.Set("sct_list", bssl::PEMEncode(sct_list, "NETLOG SCT LIST"));
  }
  dict.Set("host", NetLogStringValue(hostname));
  dict.Set("verify_flags", flags);
  dict.Set("crlset_sequence", NetLogNumberValue(crl_set->sequence()));
  if (crl_set->IsExpired())
    dict.Set("crlset_is_expired", true);

  return dict;
}

}  // namespace

#if !(BUILDFLAG(IS_FUCHSIA) || BUILDFLAG(CHROME_ROOT_STORE_ONLY))
// static
scoped_refptr<CertVerifyProc> CertVerifyProc::CreateSystemVerifyProc(
    scoped_refptr<CertNetFetcher> cert_net_fetcher,
    scoped_refptr<CRLSet> crl_set) {
#if BUILDFLAG(IS_ANDROID)
  return base::MakeRefCounted<CertVerifyProcAndroid>(
      std::move(cert_net_fetcher), std::move(crl_set));
#elif BUILDFLAG(IS_IOS)
  return base::MakeRefCounted<CertVerifyProcIOS>(std::move(crl_set));
#else
#error Unsupported platform
#endif
}
#endif

#if BUILDFLAG(IS_FUCHSIA)
// static
scoped_refptr<CertVerifyProc> CertVerifyProc::CreateBuiltinVerifyProc(
    scoped_refptr<CertNetFetcher> cert_net_fetcher,
    scoped_refptr<CRLSet> crl_set,
    std::unique_ptr<CTVerifier> ct_verifier,
    scoped_refptr<CTPolicyEnforcer> ct_policy_enforcer,
    const InstanceParams instance_params,
    std::optional<network_time::TimeTracker> time_tracker) {
  return CreateCertVerifyProcBuiltin(
      std::move(cert_net_fetcher), std::move(crl_set), std::move(ct_verifier),
      std::move(ct_policy_enforcer), CreateSslSystemTrustStore(),
      instance_params, std::move(time_tracker));
}
#endif

#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
// static
scoped_refptr<CertVerifyProc> CertVerifyProc::CreateBuiltinWithChromeRootStore(
    scoped_refptr<CertNetFetcher> cert_net_fetcher,
    scoped_refptr<CRLSet> crl_set,
    std::unique_ptr<CTVerifier> ct_verifier,
    scoped_refptr<CTPolicyEnforcer> ct_policy_enforcer,
    const ChromeRootStoreData* root_store_data,
    const InstanceParams instance_params,
    std::optional<network_time::TimeTracker> time_tracker) {
  std::unique_ptr<TrustStoreChrome> chrome_root =
      root_store_data ? std::make_unique<TrustStoreChrome>(*root_store_data)
                      : std::make_unique<TrustStoreChrome>();
  return CreateCertVerifyProcBuiltin(
      std::move(cert_net_fetcher), std::move(crl_set), std::move(ct_verifier),
      std::move(ct_policy_enforcer),
      CreateSslSystemTrustStoreChromeRoot(std::move(chrome_root)),
      instance_params, std::move(time_tracker));
}
#endif

CertVerifyProc::CertVerifyProc(scoped_refptr<CRLSet> crl_set)
    : crl_set_(std::move(crl_set)) {
  CHECK(crl_set_);
}

CertVerifyProc::~CertVerifyProc() = default;

int CertVerifyProc::Verify(X509Certificate* cert,
                           const std::string& hostname,
                           const std::string& ocsp_response,
                           const std::string& sct_list,
                           int flags,
                           CertVerifyResult* verify_result,
                           const NetLogWithSource& net_log) {
  CHECK(cert);
  CHECK(verify_result);

  net_log.BeginEvent(NetLogEventType::CERT_VERIFY_PROC, [&] {
    return CertVerifyParams(cert, hostname, ocsp_response, sct_list, flags,
                            crl_set());
  });
  // CertVerifyProc's contract allows ::VerifyInternal() to wait on File I/O
  // (such as the Windows registry or smart cards on all platforms) or may re-
  // enter this code via extension hooks (such as smart card UI). To ensure
  // threads are not starved or deadlocked, the base::ScopedBlockingCall below
  // increments the thread pool capacity when this method takes too much time to
  // run.
  base::ScopedBlockingCall scoped_blocking_call(FROM_HERE,
                                                base::BlockingType::MAY_BLOCK);

  verify_result->Reset();
  verify_result->verified_cert = cert;

  int rv = VerifyInternal(cert, hostname, ocsp_response, sct_list, flags,
                          verify_result, net_log);

  CHECK(verify_result->verified_cert);

  // Check for mismatched signature algorithms and unknown signature algorithms
  // in the chain. Also fills in the has_* booleans for the digest algorithms
  // present in the chain.
  if (!InspectSignatureAlgorithmsInChain(verify_result)) {
    verify_result->cert_status |= CERT_STATUS_INVALID;
    rv = MapCertStatusToNetError(verify_result->cert_status);
  }

  if (!cert->VerifyNameMatch(hostname)) {
    verify_result->cert_status |= CERT_STATUS_COMMON_NAME_INVALID;
    rv = MapCertStatusToNetError(verify_result->cert_status);
  }

  if (verify_result->ocsp_result.response_status ==
      bssl::OCSPVerifyResult::NOT_CHECKED) {
    // If VerifyInternal did not record the result of checking stapled OCSP,
    // do it now.
    BestEffortCheckOCSP(ocsp_response, *verify_result->verified_cert,
                        &verify_result->ocsp_result);
  }

  // Check to see if the connection is being intercepted.
  for (const auto& hash : verify_result->public_key_hashes) {
    if (hash.tag() != HASH_VALUE_SHA256) {
      continue;
    }
    if (!crl_set()->IsKnownInterceptionKey(std::string_view(
            reinterpret_cast<const char*>(hash.data()), hash.size()))) {
      continue;
    }

    if (verify_result->cert_status & CERT_STATUS_REVOKED) {
      // If the chain was revoked, and a known MITM was present, signal that
      // with a more meaningful error message.
      verify_result->cert_status |= CERT_STATUS_KNOWN_INTERCEPTION_BLOCKED;
      rv = MapCertStatusToNetError(verify_result->cert_status);
    } else {
      // Otherwise, simply signal informatively. Both statuses are not set
      // simultaneously.
      verify_result->cert_status |= CERT_STATUS_KNOWN_INTERCEPTION_DETECTED;
    }
    break;
  }

  std::vector<std::string> dns_names, ip_addrs;
  cert->GetSubjectAltName(&dns_names, &ip_addrs);
  if (HasNameConstraintsViolation(verify_result->public_key_hashes,
                                  cert->subject().common_name,
                                  dns_names,
                                  ip_addrs)) {
    verify_result->cert_status |= CERT_STATUS_NAME_CONSTRAINT_VIOLATION;
    rv = MapCertStatusToNetError(verify_result->cert_status);
  }

  // Check for weak keys in the entire verified chain.
  bool weak_key = ExaminePublicKeys(verify_result->verified_cert,
                                    verify_result->is_issued_by_known_root);

  if (weak_key) {
    verify_result->cert_status |= CERT_STATUS_WEAK_KEY;
    // Avoid replacing a more serious error, such as an OS/library failure,
    // by ensuring that if verification failed, it failed with a certificate
    // error.
    if (rv == OK || IsCertificateError(rv))
      rv = MapCertStatusToNetError(verify_result->cert_status);
  }

  if (verify_result->has_sha1)
    verify_result->cert_status |= CERT_STATUS_SHA1_SIGNATURE_PRESENT;

  // Flag certificates using weak signature algorithms.
  bool sha1_allowed = (flags & VERIFY_ENABLE_SHA1_LOCAL_ANCHORS) &&
                      !verify_result->is_issued_by_known_root;
  if (!sha1_allowed && verify_result->has_sha1) {
    verify_result->cert_status |= CERT_STATUS_WEAK_SIGNATURE_ALGORITHM;
    // Avoid replacing a more serious error, such as an OS/library failure,
    // by ensuring that if verification failed, it failed with a certificate
    // error.
    if (rv == OK || IsCertificateError(rv))
      rv = MapCertStatusToNetError(verify_result->cert_status);
  }

  // Distrust Symantec-issued certificates, as described at
  // https://security.googleblog.com/2017/09/chromes-plan-to-distrust-symantec.html
  if (!(flags & VERIFY_DISABLE_SYMANTEC_ENFORCEMENT) &&
      IsLegacySymantecCert(verify_result->public_key_hashes)) {
    verify_result->cert_status |= CERT_STATUS_SYMANTEC_LEGACY;
    if (rv == OK || IsCertificateError(rv))
      rv = MapCertStatusToNetError(verify_result->cert_status);
  }

  // Flag certificates using too long validity periods.
  if (verify_result->is_issued_by_known_root && HasTooLongValidity(*cert)) {
    verify_result->cert_status |= CERT_STATUS_VALIDITY_TOO_LONG;
    if (rv == OK)
      rv = MapCertStatusToNetError(verify_result->cert_status);
  }

  // Flag certificates from publicly-trusted CAs that are issued to intranet
  // hosts. These are not allowed per the CA/Browser Forum requirements.
  //
  // Validity period is checked first just for testing convenience; there's not
  // a strong security reason to let validity period vs non-unique names take
  // precedence.
  if (verify_result->is_issued_by_known_root && IsHostnameNonUnique(hostname)) {
    verify_result->cert_status |= CERT_STATUS_NON_UNIQUE_NAME;
    // On Cronet, CERT_STATUS_NON_UNIQUE_NAME is recorded as a warning but not
    // treated as an error, because consumers have tests that use certs with
    // non-unique names. See b/337196170 (Google-internal).
#if !BUILDFLAG(CRONET_BUILD)
    if (rv == OK) {
      rv = MapCertStatusToNetError(verify_result->cert_status);
    }
#endif  // !BUILDFLAG(CRONET_BUILD)
  }

  // Record a histogram for per-verification usage of root certs.
  if (rv == OK) {
    RecordTrustAnchorHistogram(verify_result->public_key_hashes,
                               verify_result->is_issued_by_known_root);
  }

  net_log.EndEvent(NetLogEventType::CERT_VERIFY_PROC,
                   [&] { return verify_result->NetLogParams(rv); });
  return rv;
}

// static
void CertVerifyProc::LogNameNormalizationResult(
    const std::string& histogram_suffix,
    NameNormalizationResult result) {
  base::UmaHistogramEnumeration(
      std::string("Net.CertVerifier.NameNormalizationPrivateRoots") +
          histogram_suffix,
      result);
}

// static
void CertVerifyProc::LogNameNormalizationMetrics(
    const std::string& histogram_suffix,
    X509Certificate* verified_cert,
    bool is_issued_by_known_root) {
  if (is_issued_by_known_root)
    return;

  if (verified_cert->intermediate_buffers().empty()) {
    LogNameNormalizationResult(histogram_suffix,
                               NameNormalizationResult::kChainLengthOne);
    return;
  }

  std::vector<CRYPTO_BUFFER*> der_certs;
  der_certs.push_back(verified_cert->cert_buffer());
  for (const auto& buf : verified_cert->intermediate_buffers())
    der_certs.push_back(buf.get());

  bssl::ParseCertificateOptions options;
  options.allow_invalid_serial_numbers = true;

  std::vector<bssl::der::Input> subjects;
  std::vector<bssl::der::Input> issuers;

  for (auto* buf : der_certs) {
    bssl::der::Input tbs_certificate_tlv;
    bssl::der::Input signature_algorithm_tlv;
    bssl::der::BitString signature_value;
    bssl::ParsedTbsCertificate tbs;
    if (!bssl::ParseCertificate(
            bssl::der::Input(CRYPTO_BUFFER_data(buf), CRYPTO_BUFFER_len(buf)),
            &tbs_certificate_tlv, &signature_algorithm_tlv, &signature_value,
            nullptr /* errors*/) ||
        !ParseTbsCertificate(tbs_certificate_tlv, options, &tbs,
                             nullptr /*errors*/)) {
      LogNameNormalizationResult(histogram_suffix,
                                 NameNormalizationResult::kError);
      return;
    }
    subjects.push_back(tbs.subject_tlv);
    issuers.push_back(tbs.issuer_tlv);
  }

  for (size_t i = 0; i < subjects.size() - 1; ++i) {
    if (issuers[i] != subjects[i + 1]) {
      LogNameNormalizationResult(histogram_suffix,
                                 NameNormalizationResult::kNormalized);
      return;
    }
  }

  LogNameNormalizationResult(histogram_suffix,
                             NameNormalizationResult::kByteEqual);
}

// CheckNameConstraints verifies that every name in |dns_names| is in one of
// the domains specified by |domains|.
static bool CheckNameConstraints(const std::vector<std::string>& dns_names,
                                 base::span<const std::string_view> domains) {
  for (const auto& host : dns_names) {
    bool ok = false;
    url::CanonHostInfo host_info;
    const std::string dns_name = CanonicalizeHost(host, &host_info);
    if (host_info.IsIPAddress())
      continue;

    // If the name is not in a known TLD, ignore it. This permits internal
    // server names.
    if (!registry_controlled_domains::HostHasRegistryControlledDomain(
            dns_name, registry_controlled_domains::EXCLUDE_UNKNOWN_REGISTRIES,
            registry_controlled_domains::INCLUDE_PRIVATE_REGISTRIES)) {
      continue;
    }

    for (const auto& domain : domains) {
      // The |domain| must be of ".somesuffix" form, and |dns_name| must
      // have |domain| as a suffix.
      DCHECK_EQ('.', domain[0]);
      if (dns_name.size() <= domain.size())
        continue;
      std::string_view suffix =
          std::string_view(dns_name).substr(dns_name.size() - domain.size());
      if (!base::EqualsCaseInsensitiveASCII(suffix, domain))
        continue;
      ok = true;
      break;
    }

    if (!ok)
      return false;
  }

  return true;
}

// static
bool CertVerifyProc::HasNameConstraintsViolation(
    const HashValueVector& public_key_hashes,
    const std::string& common_name,
    const std::vector<std::string>& dns_names,
    const std::vector<std::string>& ip_addrs) {
  static constexpr std::string_view kDomainsANSSI[] = {
      ".fr",  // France
      ".gp",  // Guadeloupe
      ".gf",  // Guyane
      ".mq",  // Martinique
      ".re",  // Réunion
      ".yt",  // Mayotte
      ".pm",  // Saint-Pierre et Miquelon
      ".bl",  // Saint Barthélemy
      ".mf",  // Saint Martin
      ".wf",  // Wallis et Futuna
      ".pf",  // Polynésie française
      ".nc",  // Nouvelle Calédonie
      ".tf",  // Terres australes et antarctiques françaises
  };

  static constexpr std::string_view kDomainsTest[] = {
      ".example.com",
  };

  // PublicKeyDomainLimitation contains SHA-256(SPKI) and a pointer to an array
  // of fixed-length strings that contain the domains that the SPKI is allowed
  // to issue for.
  //
  // A public key hash can be generated with the following command:
  // openssl x509 -noout -in <cert>.pem -pubkey | \
  //   openssl asn1parse -noout -inform pem -out - | \
  //   openssl dgst -sha256 -binary | xxd -i
  static const struct PublicKeyDomainLimitation {
    SHA256HashValue public_key_hash;
    base::raw_span<const std::string_view> domains;
  } kLimits[] = {
      // C=FR, ST=France, L=Paris, O=PM/SGDN, OU=DCSSI,
      // CN=IGC/A/emailAddress=igca@sgdn.pm.gouv.fr
      //
      // net/data/ssl/name_constrained/b9bea7860a962ea3611dab97ab6da3e21c1068b97d55575ed0e11279c11c8932.pem
      {
          {{0x86, 0xc1, 0x3a, 0x34, 0x08, 0xdd, 0x1a, 0xa7, 0x7e, 0xe8, 0xb6,
            0x94, 0x7c, 0x03, 0x95, 0x87, 0x72, 0xf5, 0x31, 0x24, 0x8c, 0x16,
            0x27, 0xbe, 0xfb, 0x2c, 0x4f, 0x4b, 0x04, 0xd0, 0x44, 0x96}},
          kDomainsANSSI,
      },
      // Not a real certificate - just for testing.
      // net/data/ssl/certificates/name_constrained_key.pem
      {
          {{0xa2, 0x2a, 0x88, 0x82, 0xba, 0x0c, 0xae, 0x9d, 0xf2, 0xc4, 0x5b,
            0x15, 0xa6, 0x1e, 0xfd, 0xfd, 0x19, 0x6b, 0xb1, 0x09, 0x19, 0xfd,
            0xac, 0x77, 0x9b, 0xd6, 0x08, 0x66, 0xda, 0xa8, 0xd2, 0x88}},
          kDomainsTest,
      },
  };

  for (const auto& limit : kLimits) {
    for (const auto& hash : public_key_hashes) {
      if (hash.tag() != HASH_VALUE_SHA256)
        continue;
      if (memcmp(hash.data(), limit.public_key_hash.data, hash.size()) != 0)
        continue;
      if (dns_names.empty() && ip_addrs.empty()) {
        std::vector<std::string> names;
        names.push_back(common_name);
        if (!CheckNameConstraints(names, limit.domains))
          return true;
      } else {
        if (!CheckNameConstraints(dns_names, limit.domains))
          return true;
      }
    }
  }

  return false;
}

// static
bool CertVerifyProc::HasTooLongValidity(const X509Certificate& cert) {
  const base::Time& start = cert.valid_start();
  const base::Time& expiry = cert.valid_expiry();
  if (start.is_max() || start.is_null() || expiry.is_max() ||
      expiry.is_null() || start > expiry) {
    return true;
  }

  // The maximum lifetime of publicly trusted certificates has reduced
  // gradually over time. These dates are derived from the transitions noted in
  // Section 1.2.2 (Relevant Dates) of the Baseline Requirements.
  //
  // * Certificates issued before BRs took effect, Chrome limited to max of ten
  // years validity and a max notAfter date of 2019-07-01.
  //   * Last possible expiry: 2019-07-01.
  //
  // * Cerificates issued on-or-after the BR effective date of 1 July 2012: 60
  // months.
  //   * Last possible expiry: 1 April 2015 + 60 months = 2020-04-01
  //
  // * Certificates issued on-or-after 1 April 2015: 39 months.
  //   * Last possible expiry: 1 March 2018 + 39 months = 2021-06-01
  //
  // * Certificates issued on-or-after 1 March 2018: 825 days.
  //   * Last possible expiry: 1 September 2020 + 825 days = 2022-12-05
  //
  // The current limit, from Chrome Root Certificate Policy:
  // * Certificates issued on-or-after 1 September 2020: 398 days.

  base::TimeDelta validity_duration = cert.valid_expiry() - cert.valid_start();

  // No certificates issued before the latest lifetime requirement was enacted
  // could possibly still be accepted, so we don't need to check the older
  // limits explicitly.
  return validity_duration > base::Days(398);
}

CertVerifyProc::ImplParams::ImplParams() {
  crl_set = net::CRLSet::BuiltinCRLSet();
#if BUILDFLAG(CHROME_ROOT_STORE_OPTIONAL)
  // Defaults to using Chrome Root Store, though we have to keep this option in
  // here to allow WebView to turn this option off.
  use_chrome_root_store = true;
#endif
}

CertVerifyProc::ImplParams::~ImplParams() = default;

CertVerifyProc::ImplPa
"""


```