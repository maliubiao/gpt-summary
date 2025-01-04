Response:
My thinking process to answer the prompt about `cert_verify_proc_builtin.cc` goes like this:

1. **Understand the Core Request:** The user wants to know the *functionality* of this specific Chromium file. They also want to see connections to JavaScript, examples of logical inference, common usage errors, debugging guidance, and a summary of its functions. The "Part 1 of 2" suggests there's more context to come.

2. **Initial Scan and Keyword Identification:** I quickly scan the provided C++ code, looking for key terms and concepts. I see things like:

    * `#include` statements indicating dependencies (e.g., `net/cert/...`, `crypto/...`, `base/...`).
    * Class names like `CertVerifyProcBuiltin`, `PathBuilderDelegateImpl`, `CertVerifyProcTrustStore`.
    * Function names like `VerifyInternal`, `CheckPathAfterVerification`, `ChooseRevocationPolicy`.
    * Logging with `net_log_`.
    * Handling of certificates (`X509Certificate`, `ParsedCertificate`).
    * Concepts like "trust store", "revocation", "EV policy", "CT (Certificate Transparency)".

3. **Infer the Primary Purpose:** Based on the filename and the included headers, I deduce that `cert_verify_proc_builtin.cc` is a core component of Chromium's certificate verification process. It's likely responsible for the main logic of validating server certificates. The "builtin" likely refers to a standard or default implementation within Chromium.

4. **Break Down Functionality into Logical Groups:**  I start categorizing the identified concepts into broader functional areas:

    * **Path Building:** The presence of `bssl::CertPathBuilder` and related classes indicates the file deals with constructing and validating chains of certificates.
    * **Trust Management:**  `CertVerifyProcTrustStore` suggests managing trusted root certificates and potentially other trust anchors.
    * **Revocation Checking:**  Keywords like "revocation", "CRLSet", and "OCSP" point to mechanisms for checking if certificates have been revoked.
    * **EV (Extended Validation):** The `EVRootCAMetadata` suggests handling of EV certificates.
    * **CT (Certificate Transparency):** The `CTVerifier` and `CTPolicyEnforcer` indicate support for Certificate Transparency.
    * **Constraints and Policies:**  The code mentions constraints on certificates (name constraints, Chrome Root Store constraints).
    * **Error Handling and Logging:**  The use of `bssl::CertErrors` and `net_log_` shows error reporting and logging.

5. **Address Specific Questions:**

    * **Relationship to JavaScript:** I think about how certificate verification relates to web browsing. JavaScript running in a browser needs to know if a website's certificate is valid to establish a secure connection (HTTPS). While this C++ code doesn't directly *execute* JavaScript, it's a crucial *underlying mechanism* that allows secure communication for JavaScript-based web applications. I'd give an example like `fetch()` failing due to an invalid certificate.
    * **Logical Inference:**  I look for places where the code makes decisions based on input. The `ChooseRevocationPolicy` function is a good example. The input is the flags and the certificate chain, and the output is a `RevocationPolicy` object. I would create a simple input/output example to illustrate this.
    * **Common User/Programming Errors:**  I consider how things can go wrong. Users might see certificate errors in their browser. For programmers, misconfiguring trust stores or incorrectly handling certificate paths could be errors. I'd provide examples.
    * **Debugging:** I think about how a developer would reach this code. A user encountering a certificate error is the starting point. The browser's network stack would then call the certificate verification logic. I'd outline the steps involved.

6. **Summarize the Functionality:** Based on the categorized functionalities, I write a concise summary of what the file does.

7. **Review and Refine:** I reread my answer to ensure clarity, accuracy, and completeness. I double-check that I've addressed all parts of the user's prompt. I make sure the language is accessible and avoids overly technical jargon where possible. I consider the "Part 1 of 2" and make sure my summary reflects the scope of the provided code snippet.

Essentially, my approach is to understand the core purpose, break it down into manageable components, address specific questions, and then synthesize a clear and comprehensive answer. The code itself provides strong clues about its functionality through its structure, naming conventions, and included libraries.

这个 `net/cert/cert_verify_proc_builtin.cc` 文件是 Chromium 网络栈中负责**内置证书验证处理**的核心组件。它实现了 `CertVerifyProc` 抽象类的具体子类 `CertVerifyProcBuiltin`，并负责执行证书链的构建和验证过程。

以下是它的主要功能归纳：

**核心功能：证书路径构建与验证**

1. **证书链构建 (Path Building):**
   - 它使用 BoringSSL 的 `CertPathBuilder` 类来尝试构建从待验证证书到受信任根证书的有效证书链。
   - 它会考虑中间证书（如果有）以及从各种来源获取潜在的中间证书（例如，通过 AIA 扩展）。
   - 它限制了路径构建的迭代次数，以防止拒绝服务攻击。

2. **证书链验证 (Path Validation):**
   - 一旦构建出候选证书链，它会对链中的每个证书进行一系列检查，包括：
     - **基本 X.509 验证:** 证书签名是否有效，证书是否过期等。
     - **名称约束:** 检查证书是否满足名称约束条件。
     - **策略 OID:** 检查证书是否声明了特定的策略。
     - **EV 验证:** 如果需要扩展验证 (EV)，则检查证书链是否符合 EV 策略。
     - **Chrome Root Store 约束 (如果启用):**  检查证书链是否满足 Chrome 根证书存储的特定约束。

3. **信任管理 (Trust Management):**
   - 它使用 `CertVerifyProcTrustStore` 类来管理受信任的根证书。
   - 它整合了系统信任存储、额外的信任锚点（由 Chromium 配置提供）和测试根证书（用于测试环境）。
   - 它可以区分已知的根证书和本地添加的信任锚点。

4. **撤销检查 (Revocation Checking):**
   - 它支持使用 CRLSet（证书吊销列表）进行初步的撤销检查。
   - 根据配置和策略，它可以执行在线撤销检查，例如 OCSP (在线证书状态协议)。
   - 撤销策略可以配置为“硬失败”（如果撤销状态未知则验证失败）或“软失败”（即使撤销状态未知也继续，但会标记问题）。

5. **证书透明度 (Certificate Transparency - CT):**
   - 它与 `CTVerifier` 和 `CTPolicyEnforcer` 集成，以验证证书是否符合证书透明度策略。
   - 它会检查从 TLS 扩展或证书本身获取的 SCT（签名证书时间戳）。

6. **时间处理:**
   - 它使用 `network_time::TimeTracker` (如果可用) 来获取可靠的当前时间，用于证书有效期和 CT 验证。

7. **日志记录:**
   - 它使用 Chromium 的 `net::NetLog` 框架来记录证书验证过程中的各种事件和参数，用于调试和监控。

**与 JavaScript 的关系：**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它是浏览器网络安全的关键基础设施，直接影响着 JavaScript 代码发起的网络请求的安全性。

**举例说明:**

假设一个 JavaScript 脚本尝试使用 `fetch()` API 请求一个 HTTPS 网站：

```javascript
fetch('https://example.com')
  .then(response => {
    // 处理响应
  })
  .catch(error => {
    // 处理错误
  });
```

当浏览器发起这个请求时，`CertVerifyProcBuiltin.cc` 的代码会被调用来验证 `example.com` 服务器提供的 SSL/TLS 证书。

- **假设输入:**
  - 服务器提供的证书链（包括服务器证书和可能的中间证书）。
  - 请求的域名: "example.com"。
  - 当前时间。
  - 配置的信任存储。
  - 启用的验证标志（例如，是否需要 EV 验证，是否启用撤销检查）。
- **可能的输出:**
  - **成功:**  `CertVerifyResult` 表明证书有效，JavaScript 的 `fetch()` 请求将成功完成。
  - **失败:** `CertVerifyResult` 表明证书无效，`fetch()` 请求将失败，`catch` 代码块会捕获错误。用户可能会在浏览器中看到证书错误页面。

**逻辑推理的例子:**

**假设输入:**
- 待验证的证书链中，服务器证书已过期。
- 当前时间晚于服务器证书的 `notAfter` 日期。

**逻辑推理:**
- `CertVerifyProcBuiltin` 中的代码会解析服务器证书的有效期。
- 它会将当前时间与证书的 `notBefore` 和 `notAfter` 日期进行比较。
- 由于当前时间晚于 `notAfter`，代码会推断出证书已过期。

**输出:**
- `CertVerifyResult` 将包含一个表示证书已过期的错误。

**用户或编程常见的错误:**

1. **用户的错误:**
   - **系统时间不正确:** 如果用户的计算机时间不准确，可能导致本应有效的证书被判断为无效（例如，早于 `notBefore` 或晚于 `notAfter`）。
   - **网络拦截或中间人攻击:**  如果用户的网络流量被拦截，攻击者可能会提供伪造的证书，导致验证失败。

2. **编程错误:**
   - **错误配置信任锚点:** 开发者可能错误地添加或删除了受信任的根证书，导致某些有效的证书无法被验证。
   - **在测试环境中使用生产环境的证书或反之:** 这可能导致证书不匹配或验证失败。
   - **忽略证书错误:**  开发者不应该简单地忽略证书错误，因为这会带来安全风险。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入一个 HTTPS 网址，例如 `https://example.com`，或者点击一个 HTTPS 链接。**
2. **浏览器发起与 `example.com` 服务器的 TLS 连接。**
3. **服务器向浏览器发送其 SSL/TLS 证书。**
4. **浏览器网络栈接收到服务器证书。**
5. **网络栈将证书传递给 Chromium 的证书验证模块。**
6. **`CertVerifyProcBuiltin::VerifyInternal` 函数被调用，开始证书链的构建和验证过程。**
7. **`CertVerifyProcBuiltin` 内部会调用 `bssl::CertPathBuilder` 来尝试构建有效的证书链。**
8. **在路径构建过程中，可能会涉及到从 AIA 扩展获取中间证书的操作。**
9. **构建出的证书链会经过一系列的验证检查，例如有效期、签名、名称约束、EV 策略、CT 等。**
10. **如果配置了撤销检查，还会进行 CRLSet 或 OCSP 的检查。**
11. **验证结果会存储在 `CertVerifyResult` 对象中。**
12. **如果验证成功，TLS 连接建立，用户可以正常访问网站。**
13. **如果验证失败，浏览器会显示证书错误页面，并且开发者工具的网络面板会显示相应的错误信息。**

**作为第 1 部分的功能归纳:**

到目前为止，`net/cert/cert_verify_proc_builtin.cc` 的主要功能是作为 Chromium 内置的证书验证处理器，负责**构建和验证服务器提供的证书链**，以确保 HTTPS 连接的安全性。它涉及到信任管理、撤销检查和证书透明度等多个方面，是 Chromium 网络安全的核心组成部分。它通过 `CertVerifyProcTrustStore` 管理信任，使用 `CertPathBuilder` 构建路径，并执行各种验证检查以确保证书的有效性和可信度。

Prompt: 
```
这是目录为net/cert/cert_verify_proc_builtin.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_verify_proc_builtin.h"

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "base/feature_list.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/time/time.h"
#include "base/values.h"
#include "components/network_time/time_tracker/time_tracker.h"
#include "crypto/sha2.h"
#include "net/base/features.h"
#include "net/base/ip_address.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_net_fetcher.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/cert_verify_proc.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/ct_policy_status.h"
#include "net/cert/ct_verifier.h"
#include "net/cert/ev_root_ca_metadata.h"
#include "net/cert/internal/cert_issuer_source_aia.h"
#include "net/cert/internal/revocation_checker.h"
#include "net/cert/internal/system_trust_store.h"
#include "net/cert/signed_certificate_timestamp_and_status.h"
#include "net/cert/test_root_certs.h"
#include "net/cert/time_conversions.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "net/log/net_log_values.h"
#include "net/log/net_log_with_source.h"
#include "third_party/boringssl/src/pki/cert_errors.h"
#include "third_party/boringssl/src/pki/cert_issuer_source_static.h"
#include "third_party/boringssl/src/pki/common_cert_errors.h"
#include "third_party/boringssl/src/pki/name_constraints.h"
#include "third_party/boringssl/src/pki/parsed_certificate.h"
#include "third_party/boringssl/src/pki/path_builder.h"
#include "third_party/boringssl/src/pki/simple_path_builder_delegate.h"
#include "third_party/boringssl/src/pki/trust_store.h"
#include "third_party/boringssl/src/pki/trust_store_collection.h"
#include "third_party/boringssl/src/pki/trust_store_in_memory.h"

#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
#include "base/version_info/version_info.h"  // nogncheck
#include "net/cert/internal/trust_store_chrome.h"
#endif

using bssl::CertErrorId;

namespace net {

namespace {

// To avoid a denial-of-service risk, cap iterations by the path builder.
// Without a limit, path building is potentially exponential. This limit was
// set based on UMA histograms in the wild. See https://crrev.com/c/4903550.
//
// TODO(crbug.com/41267856): Move this limit into BoringSSL as a default.
constexpr uint32_t kPathBuilderIterationLimit = 20;

constexpr base::TimeDelta kMaxVerificationTime = base::Seconds(60);

constexpr base::TimeDelta kPerAttemptMinVerificationTimeLimit =
    base::Seconds(5);

DEFINE_CERT_ERROR_ID(kPathLacksEVPolicy, "Path does not have an EV policy");
DEFINE_CERT_ERROR_ID(kChromeRootConstraintsFailed,
                     "Path does not satisfy CRS constraints");

base::Value::Dict NetLogCertParams(const CRYPTO_BUFFER* cert_handle,
                                   const bssl::CertErrors& errors) {
  base::Value::Dict results;

  std::string pem_encoded;
  if (X509Certificate::GetPEMEncodedFromDER(
          x509_util::CryptoBufferAsStringPiece(cert_handle), &pem_encoded)) {
    results.Set("certificate", pem_encoded);
  }

  std::string errors_string = errors.ToDebugString();
  if (!errors_string.empty())
    results.Set("errors", errors_string);

  return results;
}

base::Value::Dict NetLogAdditionalCert(const CRYPTO_BUFFER* cert_handle,
                                       const bssl::CertificateTrust& trust,
                                       const bssl::CertErrors& errors) {
  base::Value::Dict results = NetLogCertParams(cert_handle, errors);
  results.Set("trust", trust.ToDebugString());
  return results;
}

#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
base::Value::Dict NetLogChromeRootStoreVersion(
    int64_t chrome_root_store_version) {
  base::Value::Dict results;
  results.Set("version_major", NetLogNumberValue(chrome_root_store_version));
  return results;
}
#endif

base::Value::List PEMCertValueList(const bssl::ParsedCertificateList& certs) {
  base::Value::List value;
  for (const auto& cert : certs) {
    std::string pem;
    X509Certificate::GetPEMEncodedFromDER(cert->der_cert().AsStringView(),
                                          &pem);
    value.Append(std::move(pem));
  }
  return value;
}

base::Value::Dict NetLogPathBuilderResultPath(
    const bssl::CertPathBuilderResultPath& result_path) {
  base::Value::Dict dict;
  dict.Set("is_valid", result_path.IsValid());
  dict.Set("last_cert_trust", result_path.last_cert_trust.ToDebugString());
  dict.Set("certificates", PEMCertValueList(result_path.certs));
  // TODO(crbug.com/40479281): netlog user_constrained_policy_set.
  std::string errors_string =
      result_path.errors.ToDebugString(result_path.certs);
  if (!errors_string.empty())
    dict.Set("errors", errors_string);
  return dict;
}

base::Value::Dict NetLogPathBuilderResult(
    const bssl::CertPathBuilder::Result& result) {
  base::Value::Dict dict;
  // TODO(crbug.com/40479281): include debug data (or just have things netlog it
  // directly).
  dict.Set("has_valid_path", result.HasValidPath());
  dict.Set("best_result_index", static_cast<int>(result.best_result_index));
  if (result.exceeded_iteration_limit)
    dict.Set("exceeded_iteration_limit", true);
  if (result.exceeded_deadline)
    dict.Set("exceeded_deadline", true);
  return dict;
}

RevocationPolicy NoRevocationChecking() {
  RevocationPolicy policy;
  policy.check_revocation = false;
  policy.networking_allowed = false;
  policy.crl_allowed = false;
  policy.allow_missing_info = true;
  policy.allow_unable_to_check = true;
  policy.enforce_baseline_requirements = false;
  return policy;
}

// Gets the set of policy OIDs in |cert| that are recognized as EV OIDs for some
// root.
void GetEVPolicyOids(const EVRootCAMetadata* ev_metadata,
                     const bssl::ParsedCertificate* cert,
                     std::set<bssl::der::Input>* oids) {
  oids->clear();

  if (!cert->has_policy_oids())
    return;

  for (const bssl::der::Input& oid : cert->policy_oids()) {
    if (ev_metadata->IsEVPolicyOID(oid)) {
      oids->insert(oid);
    }
  }
}

// Returns true if |cert| could be an EV certificate, based on its policies
// extension. A return of false means it definitely is not an EV certificate,
// whereas a return of true means it could be EV.
bool IsEVCandidate(const EVRootCAMetadata* ev_metadata,
                   const bssl::ParsedCertificate* cert) {
  std::set<bssl::der::Input> oids;
  GetEVPolicyOids(ev_metadata, cert, &oids);
  return !oids.empty();
}

// CertVerifyProcTrustStore wraps a SystemTrustStore with additional trust
// anchors and TestRootCerts.
class CertVerifyProcTrustStore {
 public:
  // |system_trust_store| must outlive this object.
  explicit CertVerifyProcTrustStore(
      SystemTrustStore* system_trust_store,
      bssl::TrustStoreInMemory* additional_trust_store)
      : system_trust_store_(system_trust_store),
        additional_trust_store_(additional_trust_store) {
    trust_store_.AddTrustStore(additional_trust_store_);
    trust_store_.AddTrustStore(system_trust_store_->GetTrustStore());
    // When running in test mode, also layer in the test-only root certificates.
    //
    // Note that this integration requires TestRootCerts::HasInstance() to be
    // true by the time CertVerifyProcTrustStore is created - a limitation which
    // is acceptable for the test-only code that consumes this.
    if (TestRootCerts::HasInstance()) {
      trust_store_.AddTrustStore(
          TestRootCerts::GetInstance()->test_trust_store());
    }
  }

  bssl::TrustStore* trust_store() { return &trust_store_; }

  bool IsKnownRoot(const bssl::ParsedCertificate* trust_anchor) const {
    if (TestRootCerts::HasInstance() &&
        TestRootCerts::GetInstance()->IsKnownRoot(trust_anchor->der_cert())) {
      return true;
    }
    return system_trust_store_->IsKnownRoot(trust_anchor);
  }

#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
  base::span<const ChromeRootCertConstraints> GetChromeRootConstraints(
      const bssl::ParsedCertificate* cert) const {
    return system_trust_store_->GetChromeRootConstraints(cert);
  }

  bool IsNonChromeRootStoreTrustAnchor(
      const bssl::ParsedCertificate* trust_anchor) const {
    return IsAdditionalTrustAnchor(trust_anchor) ||
           system_trust_store_->IsLocallyTrustedRoot(trust_anchor);
  }
#endif

  bool IsAdditionalTrustAnchor(
      const bssl::ParsedCertificate* trust_anchor) const {
    return additional_trust_store_->GetTrust(trust_anchor).IsTrustAnchor();
  }

 private:
  raw_ptr<SystemTrustStore> system_trust_store_;
  raw_ptr<bssl::TrustStoreInMemory> additional_trust_store_;
  bssl::TrustStoreCollection trust_store_;
};

// Enum for whether path building is attempting to verify a certificate as EV or
// as DV.
enum class VerificationType {
  kEV,  // Extended Validation
  kDV,  // Domain Validation
};

class PathBuilderDelegateDataImpl : public bssl::CertPathBuilderDelegateData {
 public:
  ~PathBuilderDelegateDataImpl() override = default;

  static const PathBuilderDelegateDataImpl* Get(
      const bssl::CertPathBuilderResultPath& path) {
    return static_cast<PathBuilderDelegateDataImpl*>(path.delegate_data.get());
  }

  static PathBuilderDelegateDataImpl* GetOrCreate(
      bssl::CertPathBuilderResultPath* path) {
    if (!path->delegate_data)
      path->delegate_data = std::make_unique<PathBuilderDelegateDataImpl>();
    return static_cast<PathBuilderDelegateDataImpl*>(path->delegate_data.get());
  }

  bssl::OCSPVerifyResult stapled_ocsp_verify_result;
  SignedCertificateTimestampAndStatusList scts;
  ct::CTPolicyCompliance ct_policy_compliance;
};

// TODO(eroman): The path building code in this file enforces its idea of weak
// keys, and signature algorithms, but separately cert_verify_proc.cc also
// checks the chains with its own policy. These policies must be aligned to
// give path building the best chance of finding a good path.
class PathBuilderDelegateImpl : public bssl::SimplePathBuilderDelegate {
 public:
  // Uses the default policy from bssl::SimplePathBuilderDelegate, which
  // requires RSA keys to be at least 1024-bits large, and optionally accepts
  // SHA1 certificates.
  PathBuilderDelegateImpl(
      const CRLSet* crl_set,
      CTVerifier* ct_verifier,
      const CTPolicyEnforcer* ct_policy_enforcer,
      CertNetFetcher* net_fetcher,
      VerificationType verification_type,
      bssl::SimplePathBuilderDelegate::DigestPolicy digest_policy,
      int flags,
      const CertVerifyProcTrustStore* trust_store,
      const std::vector<net::CertVerifyProc::CertificateWithConstraints>&
          additional_constraints,
      std::string_view stapled_leaf_ocsp_response,
      std::string_view sct_list_from_tls_extension,
      const EVRootCAMetadata* ev_metadata,
      base::TimeTicks deadline,
      base::Time current_time,
      bool* checked_revocation_for_some_path,
      const NetLogWithSource& net_log)
      : bssl::SimplePathBuilderDelegate(1024, digest_policy),
        crl_set_(crl_set),
        ct_verifier_(ct_verifier),
        ct_policy_enforcer_(ct_policy_enforcer),
        net_fetcher_(net_fetcher),
        verification_type_(verification_type),
        flags_(flags),
        trust_store_(trust_store),
        additional_constraints_(additional_constraints),
        stapled_leaf_ocsp_response_(stapled_leaf_ocsp_response),
        sct_list_from_tls_extension_(sct_list_from_tls_extension),
        ev_metadata_(ev_metadata),
        deadline_(deadline),
        current_time_(current_time),
        checked_revocation_for_some_path_(checked_revocation_for_some_path),
        net_log_(net_log) {}

  // This is called for each built chain, including ones which failed. It is
  // responsible for adding errors to the built chain if it is not acceptable.
  void CheckPathAfterVerification(
      const bssl::CertPathBuilder& path_builder,
      bssl::CertPathBuilderResultPath* path) override {
    net_log_->BeginEvent(NetLogEventType::CERT_VERIFY_PROC_PATH_BUILT);

    CheckPathAfterVerificationImpl(path_builder, path);

    net_log_->EndEvent(NetLogEventType::CERT_VERIFY_PROC_PATH_BUILT,
                       [&] { return NetLogPathBuilderResultPath(*path); });
  }

 private:
  void CheckPathAfterVerificationImpl(const bssl::CertPathBuilder& path_builder,
                                      bssl::CertPathBuilderResultPath* path) {
    PathBuilderDelegateDataImpl* delegate_data =
        PathBuilderDelegateDataImpl::GetOrCreate(path);

    // TODO(https://crbug.com/1211074, https://crbug.com/848277): making a
    // temporary X509Certificate just to pass into CTVerifier and
    // CTPolicyEnforcer is silly, refactor so they take CRYPTO_BUFFER or
    // ParsedCertificate or something.
    std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
    if (path->certs.size() > 1) {
      intermediates.push_back(bssl::UpRef(path->certs[1]->cert_buffer()));
    }
    auto cert_for_ct_verify = X509Certificate::CreateFromBuffer(
        bssl::UpRef(path->certs[0]->cert_buffer()), std::move(intermediates));
    ct_verifier_->Verify(cert_for_ct_verify.get(), stapled_leaf_ocsp_response_,
                         sct_list_from_tls_extension_, current_time_,
                         &delegate_data->scts, *net_log_);

    // Check any extra constraints that might exist outside of the certificates.
    CheckExtraConstraints(path->certs, &path->errors);
#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
    CheckChromeRootConstraints(path);
#endif

    // If the path is already invalid, don't check revocation status. The
    // chain is expected to be valid when doing revocation checks (since for
    // instance the correct issuer for a certificate may need to be known).
    // Also if certificates are already expired, obtaining their revocation
    // status may fail.
    //
    // TODO(eroman): When CertVerifyProcBuiltin fails to find a valid path,
    //               whatever (partial/incomplete) path it does return should
    //               minimally be checked with the CRLSet.
    if (!path->IsValid()) {
      return;
    }

    // If EV was requested the certificate must chain to a recognized EV root
    // and have one of its recognized EV policy OIDs.
    if (verification_type_ == VerificationType::kEV) {
      if (!ConformsToEVPolicy(path)) {
        path->errors.GetErrorsForCert(0)->AddError(kPathLacksEVPolicy);
        return;
      }
    }

    // Select an appropriate revocation policy for this chain based on the
    // verifier flags and root.
    RevocationPolicy policy = ChooseRevocationPolicy(path->certs);

    // Check for revocations using the CRLSet.
    switch (
        CheckChainRevocationUsingCRLSet(crl_set_, path->certs, &path->errors)) {
      case CRLSet::Result::REVOKED:
        return;
      case CRLSet::Result::GOOD:
        break;
      case CRLSet::Result::UNKNOWN:
        // CRLSet was inconclusive.
        break;
    }

    if (policy.check_revocation) {
      *checked_revocation_for_some_path_ = true;
    }

    // Check the revocation status for each certificate in the chain according
    // to |policy|. Depending on the policy, errors will be added to the
    // respective certificates, so |errors->ContainsHighSeverityErrors()| will
    // reflect the revocation status of the chain after this call.
    CheckValidatedChainRevocation(path->certs, policy, deadline_,
                                  stapled_leaf_ocsp_response_, current_time_,
                                  net_fetcher_, &path->errors,
                                  &delegate_data->stapled_ocsp_verify_result);

    ct::SCTList verified_scts;
    for (const auto& sct_and_status : delegate_data->scts) {
      if (sct_and_status.status == ct::SCT_STATUS_OK) {
        verified_scts.push_back(sct_and_status.sct);
      }
    }
    delegate_data->ct_policy_compliance = ct_policy_enforcer_->CheckCompliance(
        cert_for_ct_verify.get(), verified_scts, current_time_, *net_log_);
  }

#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
  // Returns the SCTs from `scts` that are verified successfully and signed by
  // a log which was not disqualified.
  ct::SCTList ValidScts(const SignedCertificateTimestampAndStatusList& scts) {
    ct::SCTList valid_scts;
    for (const auto& sct_and_status : scts) {
      if (sct_and_status.status != ct::SCT_STATUS_OK) {
        continue;
      }
      std::optional<base::Time> disqualification_time =
          ct_policy_enforcer_->GetLogDisqualificationTime(
              sct_and_status.sct->log_id);
      // TODO(https://crbug.com/40840044): use the same time source here as for
      // the rest of verification.
      if (disqualification_time && base::Time::Now() >= disqualification_time) {
        continue;
      }
      valid_scts.push_back(sct_and_status.sct);
    }
    return valid_scts;
  }

  bool CheckPathSatisfiesChromeRootConstraint(
      bssl::CertPathBuilderResultPath* path,
      const ChromeRootCertConstraints& constraint) {
    PathBuilderDelegateDataImpl* delegate_data =
        PathBuilderDelegateDataImpl::GetOrCreate(path);

    // TODO(https://crbug.com/40941039): add more specific netlog or CertError
    // logs about which constraint failed exactly? (Note that it could be
    // confusing when there are multiple ChromeRootCertConstraints objects,
    // would need to clearly distinguish which set of constraints had errors.)

    if (ct_policy_enforcer_->IsCtEnabled()) {
      if (constraint.sct_not_after.has_value()) {
        bool found_matching_sct = false;
        for (const auto& sct : ValidScts(delegate_data->scts)) {
          if (sct->timestamp <= constraint.sct_not_after.value()) {
            found_matching_sct = true;
            break;
          }
        }
        if (!found_matching_sct) {
          return false;
        }
      }

      if (constraint.sct_all_after.has_value()) {
        ct::SCTList valid_scts = ValidScts(delegate_data->scts);
        if (valid_scts.empty()) {
          return false;
        }
        for (const auto& sct : ValidScts(delegate_data->scts)) {
          if (sct->timestamp <= constraint.sct_all_after.value()) {
            return false;
          }
        }
      }
    }

    if (!constraint.permitted_dns_names.empty()) {
      bssl::GeneralNames permitted_names;
      for (const auto& dns_name : constraint.permitted_dns_names) {
        permitted_names.dns_names.push_back(dns_name);
      }
      permitted_names.present_name_types |=
          bssl::GeneralNameTypes::GENERAL_NAME_DNS_NAME;

      std::unique_ptr<bssl::NameConstraints> nc =
          bssl::NameConstraints::CreateFromPermittedSubtrees(
              std::move(permitted_names));

      const std::shared_ptr<const bssl::ParsedCertificate>& leaf_cert =
          path->certs[0];
      bssl::CertErrors name_constraint_errors;
      nc->IsPermittedCert(leaf_cert->normalized_subject(),
                          leaf_cert->subject_alt_names(),
                          &name_constraint_errors);
      if (name_constraint_errors.ContainsAnyErrorWithSeverity(
              bssl::CertError::SEVERITY_HIGH)) {
        return false;
      }
    }

    if (constraint.min_version.has_value() &&
        version_info::GetVersion() < constraint.min_version.value()) {
      return false;
    }

    if (constraint.max_version_exclusive.has_value() &&
        version_info::GetVersion() >=
            constraint.max_version_exclusive.value()) {
      return false;
    }

    return true;
  }

  void CheckChromeRootConstraints(bssl::CertPathBuilderResultPath* path) {
    // If the root is trusted locally, do not enforce CRS constraints, even if
    // some exist.
    if (trust_store_->IsNonChromeRootStoreTrustAnchor(
            path->certs.back().get())) {
      return;
    }

    if (base::span<const ChromeRootCertConstraints> constraints =
            trust_store_->GetChromeRootConstraints(path->certs.back().get());
        !constraints.empty()) {
      bool found_valid_constraint = false;
      for (const ChromeRootCertConstraints& constraint : constraints) {
        found_valid_constraint |=
            CheckPathSatisfiesChromeRootConstraint(path, constraint);
      }
      if (!found_valid_constraint) {
        path->errors.GetOtherErrors()->AddError(kChromeRootConstraintsFailed);
      }
    }
  }
#endif

  // Check extra constraints that aren't encoded in the certificates themselves.
  void CheckExtraConstraints(const bssl::ParsedCertificateList& certs,
                             bssl::CertPathErrors* errors) {
    const std::shared_ptr<const bssl::ParsedCertificate> root_cert =
        certs.back();
    // An assumption being made is that there will be at most a few (2-3) certs
    // in here; if there are more and this ends up being a drag on performance
    // it may be worth making additional_constraints_ into a map storing certs
    // by hash.
    for (const auto& cert_with_constraints : *additional_constraints_) {
      if (!x509_util::CryptoBufferEqual(
              root_cert->cert_buffer(),
              cert_with_constraints.certificate->cert_buffer())) {
        continue;
      }
      // Found the cert, check constraints
      if (cert_with_constraints.permitted_dns_names.empty() &&
          cert_with_constraints.permitted_cidrs.empty()) {
        // No constraints to check.
        return;
      }

      bssl::GeneralNames permitted_names;

      if (!cert_with_constraints.permitted_dns_names.empty()) {
        for (const auto& dns_name : cert_with_constraints.permitted_dns_names) {
          permitted_names.dns_names.push_back(dns_name);
        }
        permitted_names.present_name_types |=
            bssl::GeneralNameTypes::GENERAL_NAME_DNS_NAME;
      }

      if (!cert_with_constraints.permitted_cidrs.empty()) {
        for (const auto& cidr : cert_with_constraints.permitted_cidrs) {
          permitted_names.ip_address_ranges.emplace_back(cidr.ip.bytes(),
                                                         cidr.mask.bytes());
        }
        permitted_names.present_name_types |=
            bssl::GeneralNameTypes::GENERAL_NAME_IP_ADDRESS;
      }

      std::unique_ptr<bssl::NameConstraints> nc =
          bssl::NameConstraints::CreateFromPermittedSubtrees(
              std::move(permitted_names));

      const std::shared_ptr<const bssl::ParsedCertificate>& leaf_cert =
          certs[0];

      nc->IsPermittedCert(leaf_cert->normalized_subject(),
                          leaf_cert->subject_alt_names(),
                          errors->GetErrorsForCert(0));
      return;
    }
  }

  // Selects a revocation policy based on the CertVerifier flags and the given
  // certificate chain.
  RevocationPolicy ChooseRevocationPolicy(
      const bssl::ParsedCertificateList& certs) {
    if (flags_ & CertVerifyProc::VERIFY_DISABLE_NETWORK_FETCHES) {
      // In theory when network fetches are disabled but revocation is enabled
      // we could continue with networking_allowed=false (and
      // VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS would also have to change
      // allow_missing_info and allow_unable_to_check to true).
      // That theoretically could allow still consulting any cached CRLs/etc.
      // However in the way things are currently implemented in the builtin
      // verifier there really is no point to bothering, just disable
      // revocation checking if network fetches are disabled.
      return NoRevocationChecking();
    }

    // Use hard-fail revocation checking for local trust anchors, if requested
    // by the load flag and the chain uses a non-public root.
    if ((flags_ & CertVerifyProc::VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS) &&
        !certs.empty() && !trust_store_->IsKnownRoot(certs.back().get())) {
      RevocationPolicy policy;
      policy.check_revocation = true;
      policy.networking_allowed = true;
      policy.crl_allowed = true;
      policy.allow_missing_info = false;
      policy.allow_unable_to_check = false;
      policy.enforce_baseline_requirements = false;
      return policy;
    }

    // Use soft-fail revocation checking for VERIFY_REV_CHECKING_ENABLED.
    if (flags_ & CertVerifyProc::VERIFY_REV_CHECKING_ENABLED) {
      const bool is_known_root =
          !certs.empty() && trust_store_->IsKnownRoot(certs.back().get());
      RevocationPolicy policy;
      policy.check_revocation = true;
      policy.networking_allowed = true;
      // Publicly trusted certs are required to have OCSP by the Baseline
      // Requirements and CRLs can be quite large, so disable the fallback to
      // CRLs for chains to known roots.
      policy.crl_allowed = !is_known_root;
      policy.allow_missing_info = true;
      policy.allow_unable_to_check = true;
      policy.enforce_baseline_requirements = is_known_root;
      return policy;
    }

    return NoRevocationChecking();
  }

  // Returns true if |path| chains to an EV root, and the chain conforms to
  // one of its EV policy OIDs. When building paths all candidate EV policy
  // OIDs were requested, so it is just a matter of testing each of the
  // policies the chain conforms to.
  bool ConformsToEVPolicy(const bssl::CertPathBuilderResultPath* path) {
    const bssl::ParsedCertificate* root = path->GetTrustedCert();
    if (!root) {
      return false;
    }

    SHA256HashValue root_fingerprint;
    crypto::SHA256HashString(root->der_cert().AsStringView(),
                             root_fingerprint.data,
                             sizeof(root_fingerprint.data));

    for (const bssl::der::Input& oid : path->user_constrained_policy_set) {
      if (ev_metadata_->HasEVPolicyOID(root_fingerprint, oid)) {
        return true;
      }
    }

    return false;
  }

  bool IsDeadlineExpired() override {
    return !deadline_.is_null() && base::TimeTicks::Now() > deadline_;
  }

  bool IsDebugLogEnabled() override { return net_log_->IsCapturing(); }

  void DebugLog(std::string_view msg) override {
    net_log_->AddEventWithStringParams(
        NetLogEventType::CERT_VERIFY_PROC_PATH_BUILDER_DEBUG, "debug", msg);
  }

  raw_ptr<const CRLSet> crl_set_;
  raw_ptr<CTVerifier> ct_verifier_;
  raw_ptr<const CTPolicyEnforcer> ct_policy_enforcer_;
  raw_ptr<CertNetFetcher> net_fetcher_;
  const VerificationType verification_type_;
  const int flags_;
  raw_ptr<const CertVerifyProcTrustStore> trust_store_;
  raw_ref<const std::vector<net::CertVerifyProc::CertificateWithConstraints>>
      additional_constraints_;
  const std::string_view stapled_leaf_ocsp_response_;
  const std::string_view sct_list_from_tls_extension_;
  raw_ptr<const EVRootCAMetadata> ev_metadata_;
  base::TimeTicks deadline_;
  base::Time current_time_;
  raw_ptr<bool> checked_revocation_for_some_path_;
  raw_ref<const NetLogWithSource> net_log_;
};

std::shared_ptr<const bssl::ParsedCertificate> ParseCertificateFromBuffer(
    CRYPTO_BUFFER* cert_handle,
    bssl::CertErrors* errors) {
  return bssl::ParsedCertificate::Create(
      bssl::UpRef(cert_handle), x509_util::DefaultParseCertificateOptions(),
      errors);
}

class CertVerifyProcBuiltin : public CertVerifyProc {
 public:
  CertVerifyProcBuiltin(scoped_refptr<CertNetFetcher> net_fetcher,
                        scoped_refptr<CRLSet> crl_set,
                        std::unique_ptr<CTVerifier> ct_verifier,
                        scoped_refptr<CTPolicyEnforcer> ct_policy_enforcer,
                        std::unique_ptr<SystemTrustStore> system_trust_store,
                        const CertVerifyProc::InstanceParams& instance_params,
                        std::optional<network_time::TimeTracker> time_tracker);

 protected:
  ~CertVerifyProcBuiltin() override;

 private:
  int VerifyInternal(X509Certificate* cert,
                     const std::string& hostname,
                     const std::string& ocsp_response,
                     const std::string& sct_list,
                     int flags,
                     CertVerifyResult* verify_result,
                     const NetLogWithSource& net_log) override;

  const scoped_refptr<CertNetFetcher> net_fetcher_;
  const std::unique_ptr<CTVerifier> ct_verifier_;
  const scoped_refptr<CTPolicyEnforcer> ct_policy_enforcer_;
  const std::unique_ptr<SystemTrustStore> system_trust_store_;
  std::vector<net::CertVerifyProc::CertificateWithConstraints>
      additional_constraints_;
  bssl::TrustStoreInMemory additional_trust_store_;
  const std::optional<network_time::TimeTracker> time_tracker_;
};

CertVerifyProcBuiltin::CertVerifyProcBuiltin(
    scoped_refptr<CertNetFetcher> net_fetcher,
    scoped_refptr<CRLSet> crl_set,
    std::unique_ptr<CTVerifier> ct_verifier,
    scoped_refptr<CTPolicyEnforcer> ct_policy_enforcer,
    std::unique_ptr<SystemTrustStore> system_trust_store,
    const CertVerifyProc::InstanceParams& instance_params,
    std::optional<network_time::TimeTracker> time_tracker)
    : CertVerifyProc(std::move(crl_set)),
      net_fetcher_(std::move(net_fetcher)),
      ct_verifier_(std::move(ct_verifier)),
      ct_policy_enforcer_(std::move(ct_policy_enforcer)),
      system_trust_store_(std::move(system_trust_store)),
      time_tracker_(std::move(time_tracker)) {
  DCHECK(system_trust_store_);

  NetLogWithSource net_log =
      NetLogWithSource::Make(net::NetLogSourceType::CERT_VERIFY_PROC_CREATED);
  net_log.BeginEvent(NetLogEventType::CERT_VERIFY_PROC_CREATED);

  // When adding additional certs from instance params, there needs to be a
  // priority order if a cert is added with multiple different trust types.
  //
  // The priority is as follows:
  //
  //  (a) Distrusted SPKIs (though we don't check for SPKI collisions in added
  //      certs; we rely on that to happen in path building).
  //  (b) Trusted certs with enforced constraints both in the cert and
  //      specified externally outside of the cert.
  //  (c) Trusted certs with enforced constraints only within the cert.
  //  (d) Trusted certs w/o enforced constraints.
  //  (e) Unspecified certs.
  //
  //  No effort was made to categorize what applies if a cert is specified
  //  within the same category multiple times.

  for (const auto& spki : instance_params.additional_distrusted_spkis) {
    additional_trust_store_.AddDistrustedCertificateBySPKI(
        std::string(base::as_string_view(spki)));
    net_log.AddEvent(NetLogEventType::CERT_VERIFY_PROC_ADDITIONAL_CERT, [&] {
      base::Value::Dict results;
      results.Set("spki", NetLogBinaryValue(base::make_span(spki)));
      results.Set("trust",
                  bssl::CertificateTrust::ForDistrusted().ToDebugString());
      return results;
    });
  }

  bssl::CertificateTrust anchor_trust_enforcement =
      bssl::CertificateTrust::ForTrustAnchor()
          .WithEnforceAnchorConstraints()
          .WithEnforceAnchorExpiry();

  for (const auto& cert_with_constraints :
       instance_params.additional_trust_anchors_with_constraints) {
    const std::shared_ptr<const bssl::ParsedCertificate>& cert =
        cert_with_constraints.certificate;
    additional_trust_store_.AddCertificate(cert, anchor_trust_enforcement);
    additional_constraints_.push_back(cert_with_constraints);
    bssl::CertErrors parsing_errors;
    net_log.AddEvent(NetLogEventType::CERT_VERIFY_PROC_ADDITIONAL_CERT, [&] {
      return NetLogAdditionalCert(cert->cert_buffer(),
                                  bssl::CertificateTrust::ForTrustAnchor(),
                                  parsing_errors);
    });
  }

  bssl::CertificateTrust leaf_trust = bssl::CertificateTrust::ForTrustedLeaf();

  for (const auto& cert_with_possible_constraints :
       instance_params.additional_trust_leafs) {
    const std::shared_ptr<const bssl::ParsedCertificate>& cert =
        cert_with_possible_constraints.certificate;
    if (!additional_trust_store_.Contains(cert.get())) {
      if (!cert_with_possible_constraints.permitted_dns_names.empty() ||
          !cert_with_possible_constraints.permitted_cidrs.empty()) {
        additional_constraints_.push_back(cert_with_possible_constraints);
      }

      bssl::CertErrors parsing_errors;
      additional_trust_store_.AddCertificate(cert, leaf_trust);
      net_log.AddEvent(NetLogEventType::CERT_VERIFY_PROC_ADDITIONAL_CERT, [&] {
        return NetLogAdditionalCert(cert->cert_buffer(), leaf_trust,
                                    parsing_errors);
      });
    }
  }

  bssl::CertificateTrust anchor_leaf_trust =
      bssl::CertificateTrust::ForTrustAnchorOrLeaf()
          .WithEnforceAnchorConstraints()
       
"""


```