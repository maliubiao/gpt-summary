Response:
Let's break down the thought process for analyzing this C++ file and fulfilling the request.

**1. Initial Understanding (Skimming and Identifying Key Areas):**

The first step is a quick skim to get the gist of the code. Keywords and structure jump out:

* `#include`:  Indicates system and Chromium libraries related to certificates, security, and Apple's CoreFoundation framework. This immediately suggests it's dealing with certificate verification on iOS.
* `namespace net`:  Confirms it's part of Chromium's networking stack.
* `CertVerifyProcIOS`:  The central class name, clearly pointing to a certificate verification procedure specific to iOS.
* `OSStatus`, `SecTrustRef`, `CFArrayRef`, `CFDataRef`:  These are Apple's CoreFoundation types, solidifying the iOS focus.
* Functions like `CreateTrustPolicies`, `BuildAndEvaluateSecTrustRef`, `GetCertChainInfo`:  These suggest the steps involved in certificate verification.
* Error handling with `NetErrorFromOSStatus` and `CertStatusFromOSStatus`:  Essential for mapping iOS errors to Chromium's internal error codes.

**2. Deconstructing the Functionality (Core Logic):**

Now, a more detailed read, focusing on what each section does:

* **Error Mapping:** The functions `NetErrorFromOSStatus` and `CertStatusFromOSStatus` are critical. They translate iOS-specific error codes into Chromium's network error codes and certificate status flags. This highlights the interoperability aspect.
* **Trust Policy Creation (`CreateTrustPolicies`):**  This function sets up the criteria for evaluating trust, specifically for SSL servers. The use of `SecPolicyCreateSSL` confirms this.
* **Trust Evaluation (`BuildAndEvaluateSecTrustRef`):** This is the heart of the verification process. It takes the certificate chain, trust policies, OCSP responses, and SCTs as input. It uses Apple's `SecTrustCreateWithCertificates` and `SecTrustEvaluateWithError` (or the older `SecTrustEvaluate`) to perform the actual verification. The handling of TestRootCerts is a special case for testing environments.
* **Certificate Chain Information (`GetCertChainInfo`):**  This function extracts details from the verified certificate chain, including public key hashes and the verified certificate itself. The use of `asn1::ExtractSPKIFromDERCert` shows interaction with certificate data formats.
* **`CertVerifyProcIOS` Class:** The constructor takes a `CRLSet` (Certificate Revocation List Set), suggesting support for revocation checking (though the TODO comment indicates it's not fully implemented in this specific file). The `VerifyInternal` method orchestrates the entire verification process.
* **Platform-Specific Error Handling (Pre-iOS 12):** The `#if !defined(__IPHONE_12_0)` block reveals a workaround for getting more detailed error information on older iOS versions by comparing error strings. This highlights the challenges of dealing with platform-specific APIs.

**3. Identifying Connections to JavaScript (Indirect):**

The file itself *doesn't* directly interact with JavaScript. However, the *purpose* of this code is crucial for web security, which directly impacts JavaScript running in a browser:

* **HTTPS:** Certificate verification is fundamental to HTTPS. When a user visits an HTTPS website, this code (or similar code on other platforms) validates the server's certificate. If validation fails, the browser will likely display a warning or block the connection, preventing JavaScript on that page from running securely (or at all).
* **Fetch API/XMLHttpRequest:** JavaScript's built-in networking APIs rely on the underlying browser's network stack, which includes certificate verification. If a `fetch()` request is made to an HTTPS URL with an invalid certificate, the request will fail due to the verification process handled by this kind of code.

**4. Logical Reasoning (Hypothetical Scenarios):**

Think about different inputs and their expected outputs:

* **Valid Certificate:**  Input: A certificate chain for a legitimate website. Output: `is_trusted` is true, `verify_result->cert_status` is OK (or no error flags set).
* **Expired Certificate:** Input: A certificate chain where the server's certificate has expired. Output: `is_trusted` is false, `verify_result->cert_status` includes `CERT_STATUS_DATE_INVALID`.
* **Hostname Mismatch:** Input: A certificate that doesn't match the hostname being accessed. Output: `is_trusted` is false, `verify_result->cert_status` includes `CERT_STATUS_COMMON_NAME_INVALID`.
* **Untrusted Root:** Input: A certificate chain signed by a root CA not trusted by the system. Output: `is_trusted` is false, `verify_result->cert_status` includes `CERT_STATUS_AUTHORITY_INVALID`.

**5. Common Usage Errors (Developer Perspective):**

Consider how a *developer* might misuse the *Chromium networking stack* (though they wouldn't directly interact with this low-level file):

* **Incorrect Certificate Configuration on Server:**  A website administrator might install an expired certificate or one with a hostname mismatch. This would lead to the certificate verification failing on the client-side.
* **Missing Intermediate Certificates:**  The server might not provide the full certificate chain, causing the client to be unable to build a path to a trusted root.

**6. Debugging Scenario (User Actions and Code Execution Flow):**

Trace how a user action leads to this code being executed:

1. **User types an HTTPS URL in the browser's address bar or clicks a link to an HTTPS website.**
2. **The browser initiates a network connection to the server.**
3. **During the TLS handshake, the server presents its certificate chain.**
4. **Chromium's networking stack on iOS (which includes `CertVerifyProcIOS`) receives the certificate chain.**
5. **`CertVerifyProcIOS::VerifyInternal` is called.**
6. **`CreateTrustPolicies` sets up the verification rules.**
7. **`x509_util::CreateSecCertificateArrayForX509Certificate` converts the certificate data into Apple's `SecCertificateRef` format.**
8. **`BuildAndEvaluateSecTrustRef` calls Apple's security APIs (`SecTrustCreateWithCertificates`, `SecTrustEvaluateWithError`) to perform the core verification.**
9. **Based on the result, `GetCertFailureStatusFromError` or `GetCertFailureStatusFromTrust` (on older iOS versions) maps the error to Chromium's `CertStatus` flags.**
10. **`GetCertChainInfo` extracts details from the validated chain.**
11. **The `CertVerifyResult` is populated with the verification outcome.**
12. **The browser uses the `CertVerifyResult` to decide whether to proceed with the connection, display a warning, or block the request.**

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this file directly interacts with JavaScript.
* **Correction:**  Realized the interaction is indirect, through the browser's core functionality. The C++ code provides the *security foundation* that JavaScript relies on.
* **Initial thought:** Focus heavily on the low-level CoreFoundation details.
* **Refinement:** Balance the low-level explanation with the higher-level purpose and the impact on user experience and web security. Emphasize *why* this code is important.
* **Realization:** The pre-iOS 12 error handling is a significant detail, demonstrating platform-specific challenges and the need for workarounds.

By following this structured approach, combining code analysis with reasoning about the broader system and potential usage scenarios, we can effectively understand and explain the functionality of this C++ file within the context of a large project like Chromium.
这个文件 `net/cert/cert_verify_proc_ios.cc` 是 Chromium 网络栈中专门用于 **iOS 平台上证书验证过程** 的实现。它利用了苹果 iOS 提供的安全框架 (`Security.framework`) 来进行证书链的构建和验证。

以下是它的主要功能：

**1. 证书链构建与评估:**

*   它接收一个待验证的 X.509 证书以及可选的主机名、OCSP 响应和 SCT (Signed Certificate Timestamp) 列表。
*   它使用 `x509_util::CreateSecCertificateArrayForX509Certificate` 将 Chromium 的 `X509Certificate` 对象转换为 iOS 的 `SecCertificateRef` 数组。
*   它使用 `CreateTrustPolicies` 创建用于服务器身份验证的 `SecPolicyRef` 策略（例如，基本 X.509 策略和 SSL 策略）。
*   它使用 `BuildAndEvaluateSecTrustRef` 核心函数，调用 iOS 的 `SecTrustCreateWithCertificates` 和 `SecTrustEvaluateWithError` (或旧版本的 `SecTrustEvaluate`) 来构建和评估证书链的信任。这包括：
    *   验证证书签名和有效期。
    *   检查证书链是否可以追溯到受信任的根证书。
    *   执行主机名匹配检查（如果提供了主机名）。
    *   处理 OCSP 响应和 SCT，以进行证书吊销和透明度验证。
*   `TestRootCerts::GetInstance()->FixupSecTrustRef` 用于测试环境，允许添加或修改信任锚点。

**2. 错误处理与状态映射:**

*   它将 iOS 安全框架返回的 `OSStatus` 错误代码映射到 Chromium 的网络错误代码 (`net::NetError`) 和证书状态标志 (`net::CertStatus`)。
*   `NetErrorFromOSStatus` 将底层的 `OSStatus` 转换为更通用的网络错误代码。
*   `CertStatusFromOSStatus` 将 `OSStatus` 映射到更具体的证书状态标志，例如 `CERT_STATUS_COMMON_NAME_INVALID` (主机名不匹配)、`CERT_STATUS_DATE_INVALID` (日期无效)、`CERT_STATUS_AUTHORITY_INVALID` (颁发机构无效) 等。
*   对于 iOS 12.0 之前的版本，由于 API 限制，它使用了一种基于本地化错误字符串匹配的策略 (`GetCertFailureStatusFromTrust`) 来推断更详细的证书失败原因。这是一种权宜之计，因为旧版本 iOS 的 `SecTrustEvaluate` 返回的错误信息有限。

**3. 提取证书链信息:**

*   `GetCertChainInfo` 函数从验证后的证书链 (`CFArrayRef`) 中提取信息，例如：
    *   验证后的证书本身 (`verify_result->verified_cert`)。
    *   证书链中的所有证书 (`verified_chain`)。
    *   每个证书的 Subject Public Key Info (SPKI) 的 SHA256 哈希值 (`verify_result->public_key_hashes`)。

**4. CRLSet 集成 (部分):**

*   该类继承自 `CertVerifyProc`，后者包含对 CRLSet (Certificate Revocation List Set) 的支持。然而，在 `CertVerifyProcIOS::VerifyInternal` 中，有一个 TODO 注释 `// TODO(rsleevi): Support CRLSet revocation.`，表明当前此文件可能尚未完全实现 CRLSet 吊销检查，而是依赖 iOS 系统自身的吊销检查机制。

**与 JavaScript 的关系:**

该文件本身是用 C++ 编写的，不直接包含 JavaScript 代码。然而，它是 Chromium 浏览器网络栈的关键组成部分，而浏览器正是 JavaScript 代码的运行环境。它的功能直接影响到通过 HTTPS 加载的网页和 JavaScript 发起的网络请求的安全性。

**举例说明:**

假设一个 JavaScript 代码尝试通过 `fetch` API 访问一个使用 HTTPS 的网站，但该网站的 SSL 证书已过期：

```javascript
fetch('https://expired.example.com')
  .then(response => {
    console.log('请求成功', response);
  })
  .catch(error => {
    console.error('请求失败', error); // 这里会捕获到错误
  });
```

**用户操作到达这里的步骤 (调试线索):**

1. **用户在 Chromium 浏览器中输入 `https://expired.example.com` 并按下回车键，或者点击了一个指向该链接的 HTTPS 链接。**
2. **Chromium 的网络栈开始尝试与 `expired.example.com` 建立安全连接 (TLS/SSL 握手)。**
3. **在 TLS 握手过程中，`expired.example.com` 的服务器会将其 SSL 证书发送给浏览器。**
4. **Chromium 在 iOS 平台上会调用 `net::CertVerifyProcIOS::VerifyInternal` 来验证接收到的证书。**
5. **`VerifyInternal` 内部会调用 iOS 的安全框架进行证书链构建和评估。**
6. **由于证书已过期，iOS 的安全框架会返回一个指示证书过期的 `OSStatus` 错误代码 (例如 `errSecCertificateExpired`)。**
7. **`CertVerifyProcIOS::CertStatusFromOSStatus` 会将 `errSecCertificateExpired` 映射到 `net::CERT_STATUS_DATE_INVALID`。**
8. **`VerifyInternal` 会将 `CERT_STATUS_DATE_INVALID` 映射到相应的网络错误代码 (例如 `net::ERR_CERT_DATE_INVALID`)。**
9. **网络栈将验证失败的结果返回给 Chromium 的上层组件。**
10. **Chromium 的渲染进程会收到证书验证失败的通知，并可能显示一个安全警告页面，阻止 JavaScript 代码成功地发起 `fetch` 请求。**
11. **在 JavaScript 代码中，`fetch` API 的 `catch` 块会被调用，`error` 对象会包含与证书验证失败相关的信息。**

**假设输入与输出 (逻辑推理):**

**假设输入:**

*   `cert`: 一个表示 `expired.example.com` 服务器过期 SSL 证书的 `X509Certificate` 对象。
*   `hostname`: 字符串 "expired.example.com"。
*   `ocsp_response`: 空字符串 (假设没有提供 OCSP Stapling)。
*   `sct_list`: 空字符串 (假设没有提供 SCT)。
*   `flags`: 一些标志，指示验证选项。
*   `verify_result`: 一个空的 `CertVerifyResult` 对象。

**预期输出:**

*   `verify_result->cert_status` 将包含 `net::CERT_STATUS_DATE_INVALID`。
*   `VerifyInternal` 函数将返回 `net::ERR_CERT_DATE_INVALID`。
*   `verify_result->verified_cert` 将指向传入的过期证书。
*   `verify_result->is_issued_by_known_root` 的值取决于该过期证书是否由系统已知的根证书颁发机构签名。

**用户或编程常见的使用错误 (举例说明):**

*   **用户错误:** 用户可能会忽略浏览器显示的证书错误警告，选择继续访问不安全的网站。这虽然与 `cert_verify_proc_ios.cc` 的代码无关，但却是证书验证机制需要防范的用户行为。
*   **编程错误 (服务器配置):**  网站管理员可能会错误地配置服务器，例如：
    *   安装了过期的 SSL 证书。
    *   安装的证书的主机名与网站域名不匹配。
    *   忘记配置中间证书，导致客户端无法构建完整的证书链。
    这些服务器配置错误会导致 `cert_verify_proc_ios.cc` 进行的证书验证失败。

总而言之，`net/cert/cert_verify_proc_ios.cc` 是 Chromium 在 iOS 平台上实现安全连接的关键组件，它负责利用 iOS 的安全框架来验证服务器的身份，确保用户与网站之间的通信安全。它虽然不直接与 JavaScript 交互，但其验证结果直接影响到 JavaScript 代码的网络请求行为和页面的安全性。

Prompt: 
```
这是目录为net/cert/cert_verify_proc_ios.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_verify_proc_ios.h"

#include <CommonCrypto/CommonDigest.h>

#include <string_view>

#include "base/apple/foundation_util.h"
#include "base/apple/osstatus_logging.h"
#include "base/apple/scoped_cftyperef.h"
#include "base/containers/span.h"
#include "base/logging.h"
#include "base/notreached.h"
#include "crypto/sha2.h"
#include "net/base/net_errors.h"
#include "net/cert/asn1_util.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/crl_set.h"
#include "net/cert/ct_serialization.h"
#include "net/cert/known_roots.h"
#include "net/cert/test_root_certs.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "net/cert/x509_util_apple.h"

using base::apple::ScopedCFTypeRef;

namespace net {

namespace {

int NetErrorFromOSStatus(OSStatus status) {
  switch (status) {
    case noErr:
      return OK;
    case errSecNotAvailable:
      return ERR_NOT_IMPLEMENTED;
    case errSecAuthFailed:
      return ERR_ACCESS_DENIED;
    default:
      return ERR_FAILED;
  }
}

// Maps errors from OSStatus codes to CertStatus flags.
//
// The selection of errors is based off of Apple's SecPolicyChecks.list, and
// any unknown errors are mapped to CERT_STATUS_INVALID for safety.
CertStatus CertStatusFromOSStatus(OSStatus status) {
  switch (status) {
    case errSecHostNameMismatch:
      return CERT_STATUS_COMMON_NAME_INVALID;

    case errSecCertificateExpired:
    case errSecCertificateNotValidYet:
      return CERT_STATUS_DATE_INVALID;

    case errSecCreateChainFailed:
    case errSecNotTrusted:
    // errSecVerifyActionFailed is used when CT is required
    // and not present. The OS rejected this chain, and so mapping
    // to CERT_STATUS_CT_COMPLIANCE_FAILED (which is informational,
    // as policy enforcement is not handled in the CertVerifier)
    // would cause this error to be ignored and mapped to
    // CERT_STATUS_INVALID. Rather than do that, mark it simply as
    // "untrusted". The CT_COMPLIANCE_FAILED bit is not set, since
    // it's not necessarily a compliance failure with the embedder's
    // CT policy. It's a bit of a hack, but hopefully temporary.
    // errSecNotTrusted is somewhat similar. It applies for
    // situations where a root isn't trusted or an intermediate
    // isn't trusted, when a key is restricted, or when the calling
    // application requested CT enforcement (which CertVerifier
    // should never being doing).
    case errSecVerifyActionFailed:
      return CERT_STATUS_AUTHORITY_INVALID;

    case errSecInvalidIDLinkage:
    case errSecNoBasicConstraintsCA:
    case errSecInvalidSubjectName:
    case errSecInvalidExtendedKeyUsage:
    case errSecInvalidKeyUsageForPolicy:
    case errSecMissingRequiredExtension:
    case errSecNoBasicConstraints:
    case errSecPathLengthConstraintExceeded:
    case errSecUnknownCertExtension:
    case errSecUnknownCriticalExtensionFlag:
    // errSecCertificatePolicyNotAllowed and errSecCertificateNameNotAllowed
    // are used for certificates that violate the constraints imposed upon the
    // issuer. Nominally this could be mapped to CERT_STATUS_AUTHORITY_INVALID,
    // except the trustd behaviour is to treat this as a fatal
    // (non-recoverable) error. That behavior is preserved here for consistency
    // with Safari.
    case errSecCertificatePolicyNotAllowed:
    case errSecCertificateNameNotAllowed:
      return CERT_STATUS_INVALID;

    // Unfortunately, iOS's handling of weak digest algorithms and key sizes
    // doesn't map exactly to Chrome's. errSecInvalidDigestAlgorithm and
    // errSecUnsupportedKeySize may indicate errors that iOS considers fatal
    // (too weak to process at all) or recoverable (too weak according to
    // compliance policies).
    // Further, because SecTrustEvaluateWithError only returns a single error
    // code, a fatal error may have occurred elsewhere in the chain, so the
    // overall result can't be used to distinguish individual certificate
    // errors. For this complicated reason, the weak key and weak digest cases
    // also map to CERT_STATUS_INVALID for safety.
    case errSecInvalidDigestAlgorithm:
      return CERT_STATUS_WEAK_SIGNATURE_ALGORITHM | CERT_STATUS_INVALID;
    case errSecUnsupportedKeySize:
      return CERT_STATUS_WEAK_KEY | CERT_STATUS_INVALID;

    case errSecCertificateRevoked:
      return CERT_STATUS_REVOKED;

    case errSecIncompleteCertRevocationCheck:
      return CERT_STATUS_UNABLE_TO_CHECK_REVOCATION;

    case errSecCertificateValidityPeriodTooLong:
      return CERT_STATUS_VALIDITY_TOO_LONG;

    case errSecInvalidCertificateRef:
    case errSecInvalidName:
    case errSecInvalidPolicyIdentifiers:
      return CERT_STATUS_INVALID;

    // This function should only be called on errors, so should always return a
    // CertStatus code that is considered an error. If the input is unexpectedly
    // errSecSuccess, return CERT_STATUS_INVALID for safety.
    case errSecSuccess:
    default:
      OSSTATUS_LOG(WARNING, status)
          << "Unknown error mapped to CERT_STATUS_INVALID";
      return CERT_STATUS_INVALID;
  }
}

// Creates a series of SecPolicyRefs to be added to a SecTrustRef used to
// validate a certificate for an SSL server. |hostname| contains the name of
// the SSL server that the certificate should be verified against. If
// successful, returns noErr, and stores the resultant array of SecPolicyRefs
// in |policies|.
OSStatus CreateTrustPolicies(ScopedCFTypeRef<CFArrayRef>* policies) {
  ScopedCFTypeRef<CFMutableArrayRef> local_policies(
      CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks));
  if (!local_policies)
    return errSecAllocate;

  base::apple::ScopedCFTypeRef<SecPolicyRef> ssl_policy(
      SecPolicyCreateBasicX509());
  CFArrayAppendValue(local_policies.get(), ssl_policy.get());
  ssl_policy.reset(SecPolicyCreateSSL(/*server=*/true, /*hostname=*/nullptr));
  CFArrayAppendValue(local_policies.get(), ssl_policy.get());

  *policies = std::move(local_policies);
  return noErr;
}

// Builds and evaluates a SecTrustRef for the certificate chain contained
// in |cert_array|, using the verification policies in |trust_policies|. On
// success, returns OK, and updates |trust_ref|, |is_trusted|, and
// |trust_error|. On failure, no output parameters are modified.
//
// Note: An OK return does not mean that |cert_array| is trusted, merely that
// verification was performed successfully.
int BuildAndEvaluateSecTrustRef(CFArrayRef cert_array,
                                CFArrayRef trust_policies,
                                CFDataRef ocsp_response_ref,
                                CFArrayRef sct_array_ref,
                                ScopedCFTypeRef<SecTrustRef>* trust_ref,
                                ScopedCFTypeRef<CFArrayRef>* verified_chain,
                                bool* is_trusted,
                                ScopedCFTypeRef<CFErrorRef>* trust_error) {
  ScopedCFTypeRef<SecTrustRef> tmp_trust;
  OSStatus status = SecTrustCreateWithCertificates(cert_array, trust_policies,
                                                   tmp_trust.InitializeInto());
  if (status)
    return NetErrorFromOSStatus(status);

  if (TestRootCerts::HasInstance()) {
    status = TestRootCerts::GetInstance()->FixupSecTrustRef(tmp_trust.get());
    if (status)
      return NetErrorFromOSStatus(status);
  }

  if (ocsp_response_ref) {
    status = SecTrustSetOCSPResponse(tmp_trust.get(), ocsp_response_ref);
    if (status)
      return NetErrorFromOSStatus(status);
  }

  if (sct_array_ref) {
    if (__builtin_available(iOS 12.1.1, *)) {
      status = SecTrustSetSignedCertificateTimestamps(tmp_trust.get(),
                                                      sct_array_ref);
      if (status)
        return NetErrorFromOSStatus(status);
    }
  }

  ScopedCFTypeRef<CFErrorRef> tmp_error;
  bool tmp_is_trusted = false;
  if (__builtin_available(iOS 12.0, *)) {
    tmp_is_trusted =
        SecTrustEvaluateWithError(tmp_trust.get(), tmp_error.InitializeInto());
  } else {
#if !defined(__IPHONE_12_0) || __IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_12_0
    SecTrustResultType tmp_trust_result;
    status = SecTrustEvaluate(tmp_trust.get(), &tmp_trust_result);
    if (status)
      return NetErrorFromOSStatus(status);
    switch (tmp_trust_result) {
      case kSecTrustResultUnspecified:
      case kSecTrustResultProceed:
        tmp_is_trusted = true;
        break;
      case kSecTrustResultInvalid:
        return ERR_FAILED;
      default:
        tmp_is_trusted = false;
    }
#endif
  }

  trust_ref->swap(tmp_trust);
  trust_error->swap(tmp_error);
  *verified_chain = x509_util::CertificateChainFromSecTrust(trust_ref->get());
  *is_trusted = tmp_is_trusted;
  return OK;
}

void GetCertChainInfo(CFArrayRef cert_chain, CertVerifyResult* verify_result) {
  DCHECK_LT(0, CFArrayGetCount(cert_chain));

  base::apple::ScopedCFTypeRef<SecCertificateRef> verified_cert;
  std::vector<base::apple::ScopedCFTypeRef<SecCertificateRef>> verified_chain;
  for (CFIndex i = 0, count = CFArrayGetCount(cert_chain); i < count; ++i) {
    SecCertificateRef chain_cert = reinterpret_cast<SecCertificateRef>(
        const_cast<void*>(CFArrayGetValueAtIndex(cert_chain, i)));
    if (i == 0) {
      verified_cert.reset(chain_cert, base::scoped_policy::RETAIN);
    } else {
      verified_chain.emplace_back(chain_cert, base::scoped_policy::RETAIN);
    }

    base::apple::ScopedCFTypeRef<CFDataRef> der_data(
        SecCertificateCopyData(chain_cert));
    if (!der_data) {
      verify_result->cert_status |= CERT_STATUS_INVALID;
      return;
    }

    std::string_view spki_bytes;
    if (!asn1::ExtractSPKIFromDERCert(
            base::as_string_view(base::apple::CFDataToSpan(der_data.get())),
            &spki_bytes)) {
      verify_result->cert_status |= CERT_STATUS_INVALID;
      return;
    }

    HashValue sha256(HASH_VALUE_SHA256);
    CC_SHA256(spki_bytes.data(), spki_bytes.size(), sha256.data());
    verify_result->public_key_hashes.push_back(sha256);
  }
  if (!verified_cert.get()) {
    NOTREACHED();
  }

  scoped_refptr<X509Certificate> verified_cert_with_chain =
      x509_util::CreateX509CertificateFromSecCertificate(verified_cert,
                                                         verified_chain);
  if (verified_cert_with_chain)
    verify_result->verified_cert = std::move(verified_cert_with_chain);
  else
    verify_result->cert_status |= CERT_STATUS_INVALID;
}

}  // namespace

CertVerifyProcIOS::CertVerifyProcIOS(scoped_refptr<CRLSet> crl_set)
    : CertVerifyProc(std::move(crl_set)) {}

// static
CertStatus CertVerifyProcIOS::GetCertFailureStatusFromError(CFErrorRef error) {
  if (!error)
    return CERT_STATUS_INVALID;

  base::apple::ScopedCFTypeRef<CFStringRef> error_domain(
      CFErrorGetDomain(error));
  CFIndex error_code = CFErrorGetCode(error);

  if (error_domain.get() != kCFErrorDomainOSStatus) {
    LOG(WARNING) << "Unhandled error domain: " << error;
    return CERT_STATUS_INVALID;
  }

  return CertStatusFromOSStatus(error_code);
}

#if !defined(__IPHONE_12_0) || __IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_12_0
// The iOS APIs don't expose an API-stable set of reasons for certificate
// validation failures. However, internally, the reason is tracked, and it's
// converted to user-facing localized strings.
//
// In the absence of a consistent API, convert the English strings to their
// localized counterpart, and then compare that with the error properties. If
// they're equal, it's a strong sign that this was the cause for the error.
// While this will break if/when iOS changes the contents of these strings,
// it's sufficient enough for now.
//
// TODO(rsleevi): https://crbug.com/601915 - Use a less brittle solution when
// possible.
// static
CertStatus CertVerifyProcIOS::GetCertFailureStatusFromTrust(SecTrustRef trust) {
  CertStatus reason = 0;

  base::apple::ScopedCFTypeRef<CFArrayRef> properties(
      SecTrustCopyProperties(trust));
  if (!properties)
    return CERT_STATUS_INVALID;

  const CFIndex properties_length = CFArrayGetCount(properties.get());
  if (properties_length == 0)
    return CERT_STATUS_INVALID;

  CFBundleRef bundle =
      CFBundleGetBundleWithIdentifier(CFSTR("com.apple.Security"));
  CFStringRef date_string =
      CFSTR("One or more certificates have expired or are not valid yet.");
  ScopedCFTypeRef<CFStringRef> date_error(CFBundleCopyLocalizedString(
      bundle, date_string, date_string, CFSTR("SecCertificate")));
  CFStringRef trust_string = CFSTR("Root certificate is not trusted.");
  ScopedCFTypeRef<CFStringRef> trust_error(CFBundleCopyLocalizedString(
      bundle, trust_string, trust_string, CFSTR("SecCertificate")));
  CFStringRef weak_string =
      CFSTR("One or more certificates is using a weak key size.");
  ScopedCFTypeRef<CFStringRef> weak_error(CFBundleCopyLocalizedString(
      bundle, weak_string, weak_string, CFSTR("SecCertificate")));
  CFStringRef hostname_mismatch_string = CFSTR("Hostname mismatch.");
  ScopedCFTypeRef<CFStringRef> hostname_mismatch_error(
      CFBundleCopyLocalizedString(bundle, hostname_mismatch_string,
                                  hostname_mismatch_string,
                                  CFSTR("SecCertificate")));
  CFStringRef root_certificate_string =
      CFSTR("Unable to build chain to root certificate.");
  ScopedCFTypeRef<CFStringRef> root_certificate_error(
      CFBundleCopyLocalizedString(bundle, root_certificate_string,
                                  root_certificate_string,
                                  CFSTR("SecCertificate")));
  CFStringRef policy_requirements_not_met_string =
      CFSTR("Policy requirements not met.");
  ScopedCFTypeRef<CFStringRef> policy_requirements_not_met_error(
      CFBundleCopyLocalizedString(bundle, policy_requirements_not_met_string,
                                  policy_requirements_not_met_string,
                                  CFSTR("SecCertificate")));

  for (CFIndex i = 0; i < properties_length; ++i) {
    CFDictionaryRef dict = reinterpret_cast<CFDictionaryRef>(
        const_cast<void*>(CFArrayGetValueAtIndex(properties.get(), i)));
    CFStringRef error = reinterpret_cast<CFStringRef>(
        const_cast<void*>(CFDictionaryGetValue(dict, CFSTR("value"))));

    if (CFEqual(error, date_error.get())) {
      reason |= CERT_STATUS_DATE_INVALID;
    } else if (CFEqual(error, trust_error.get())) {
      reason |= CERT_STATUS_AUTHORITY_INVALID;
    } else if (CFEqual(error, weak_error.get())) {
      reason |= CERT_STATUS_WEAK_KEY;
    } else if (CFEqual(error, hostname_mismatch_error.get())) {
      reason |= CERT_STATUS_COMMON_NAME_INVALID;
    } else if (CFEqual(error, policy_requirements_not_met_error.get())) {
      reason |= CERT_STATUS_INVALID | CERT_STATUS_AUTHORITY_INVALID;
    } else if (CFEqual(error, root_certificate_error.get())) {
      reason |= CERT_STATUS_AUTHORITY_INVALID;
    } else {
      LOG(ERROR) << "Unrecognized error: " << error;
      reason |= CERT_STATUS_INVALID;
    }
  }

  return reason;
}
#endif  // !defined(__IPHONE_12_0) || __IPHONE_OS_VERSION_MIN_REQUIRED <
        // __IPHONE_12_0

CertVerifyProcIOS::~CertVerifyProcIOS() = default;

int CertVerifyProcIOS::VerifyInternal(X509Certificate* cert,
                                      const std::string& hostname,
                                      const std::string& ocsp_response,
                                      const std::string& sct_list,
                                      int flags,
                                      CertVerifyResult* verify_result,
                                      const NetLogWithSource& net_log) {
  ScopedCFTypeRef<CFArrayRef> trust_policies;
  OSStatus status = CreateTrustPolicies(&trust_policies);
  if (status)
    return NetErrorFromOSStatus(status);

  ScopedCFTypeRef<CFMutableArrayRef> cert_array(
      x509_util::CreateSecCertificateArrayForX509Certificate(
          cert, x509_util::InvalidIntermediateBehavior::kIgnore));
  if (!cert_array) {
    verify_result->cert_status |= CERT_STATUS_INVALID;
    return ERR_CERT_INVALID;
  }

  ScopedCFTypeRef<CFDataRef> ocsp_response_ref;
  if (!ocsp_response.empty()) {
    ocsp_response_ref.reset(
        CFDataCreate(kCFAllocatorDefault,
                     reinterpret_cast<const UInt8*>(ocsp_response.data()),
                     base::checked_cast<CFIndex>(ocsp_response.size())));
    if (!ocsp_response_ref)
      return ERR_OUT_OF_MEMORY;
  }

  ScopedCFTypeRef<CFMutableArrayRef> sct_array_ref;
  if (!sct_list.empty()) {
    if (__builtin_available(iOS 12.1.1, *)) {
      std::vector<std::string_view> decoded_sct_list;
      if (ct::DecodeSCTList(sct_list, &decoded_sct_list)) {
        sct_array_ref.reset(CFArrayCreateMutable(kCFAllocatorDefault,
                                                 decoded_sct_list.size(),
                                                 &kCFTypeArrayCallBacks));
        if (!sct_array_ref)
          return ERR_OUT_OF_MEMORY;
        for (const auto& sct : decoded_sct_list) {
          ScopedCFTypeRef<CFDataRef> sct_ref(CFDataCreate(
              kCFAllocatorDefault, reinterpret_cast<const UInt8*>(sct.data()),
              base::checked_cast<CFIndex>(sct.size())));
          if (!sct_ref)
            return ERR_OUT_OF_MEMORY;
          CFArrayAppendValue(sct_array_ref.get(), sct_ref.get());
        }
      }
    }
  }

  ScopedCFTypeRef<SecTrustRef> trust_ref;
  bool is_trusted = false;
  ScopedCFTypeRef<CFArrayRef> final_chain;
  ScopedCFTypeRef<CFErrorRef> trust_error;

  int err = BuildAndEvaluateSecTrustRef(
      cert_array.get(), trust_policies.get(), ocsp_response_ref.get(),
      sct_array_ref.get(), &trust_ref, &final_chain, &is_trusted, &trust_error);
  if (err)
    return err;

  if (CFArrayGetCount(final_chain.get()) == 0) {
    return ERR_FAILED;
  }

  // TODO(rsleevi): Support CRLSet revocation.
  if (!is_trusted) {
    if (__builtin_available(iOS 12.0, *)) {
      verify_result->cert_status |=
          GetCertFailureStatusFromError(trust_error.get());
    } else {
#if !defined(__IPHONE_12_0) || __IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_12_0
      SecTrustResultType trust_result = kSecTrustResultInvalid;
      status = SecTrustGetTrustResult(trust_ref.get(), &trust_result);
      if (status)
        return NetErrorFromOSStatus(status);
      switch (trust_result) {
        case kSecTrustResultUnspecified:
        case kSecTrustResultProceed:
          NOTREACHED();
        case kSecTrustResultDeny:
          verify_result->cert_status |= CERT_STATUS_AUTHORITY_INVALID;
          break;
        default:
          verify_result->cert_status |=
              GetCertFailureStatusFromTrust(trust_ref.get());
      }
#else
      // It should be impossible to reach this code, but if somehow it is
      // reached it would allow any certificate as valid since no errors would
      // be added to cert_status. Therefore, add a CHECK as a fail safe.
      CHECK(false);
#endif
    }
  }
  GetCertChainInfo(final_chain.get(), verify_result);

  // While iOS lacks the ability to distinguish system-trusted versus
  // user-installed roots, the set of roots that are expected to comply with
  // the Baseline Requirements can be determined by
  // GetNetTrustAnchorHistogramForSPKI() - a non-zero value means that it is
  // known as a publicly trusted, and therefore subject to the BRs, cert.
  for (auto it = verify_result->public_key_hashes.rbegin();
       it != verify_result->public_key_hashes.rend() &&
       !verify_result->is_issued_by_known_root;
       ++it) {
    verify_result->is_issued_by_known_root =
        GetNetTrustAnchorHistogramIdForSPKI(*it) != 0;
  }

  if (IsCertStatusError(verify_result->cert_status))
    return MapCertStatusToNetError(verify_result->cert_status);

  if (TestRootCerts::HasInstance() &&
      !verify_result->verified_cert->intermediate_buffers().empty() &&
      TestRootCerts::GetInstance()->IsKnownRoot(x509_util::CryptoBufferAsSpan(
          verify_result->verified_cert->intermediate_buffers().back().get()))) {
    verify_result->is_issued_by_known_root = true;
  }

  LogNameNormalizationMetrics(".IOS", verify_result->verified_cert.get(),
                              verify_result->is_issued_by_known_root);

  return OK;
}

}  // namespace net

"""

```