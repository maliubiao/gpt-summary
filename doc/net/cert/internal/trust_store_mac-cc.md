Response:
The user wants me to analyze a C++ source code file for the Chromium network stack, specifically `net/cert/internal/trust_store_mac.cc`. I need to:

1. **Summarize its functionality.**
2. **Identify any connections to JavaScript functionality.**
3. **Provide examples of logical reasoning with hypothetical inputs and outputs.**
4. **Highlight common user or programming errors.**
5. **Explain how a user action might lead to this code being executed (debugging clues).**
6. **Focus on the content provided in "Part 1" of the code.**

**Plan:**

1. **Read through the provided code snippet to understand its core purpose.** It seems to be managing certificate trust on macOS by interacting with the system's Security framework.
2. **Look for explicit mentions of JavaScript or web browser interactions.**
3. **Analyze the logic within the functions, especially those related to trust evaluation, and create hypothetical scenarios to illustrate the input and output.**
4. **Consider potential errors a user might encounter or mistakes a programmer could make when working with this code or related systems.**
5. **Think about user actions that trigger network requests or certificate validation on macOS.**
6. **Focus solely on the functionality exposed in the provided snippet, noting that this is only part of the file.**
这是 Chromium 网络栈中 `net/cert/internal/trust_store_mac.cc` 文件的第一部分。根据提供的代码，其主要功能是：

**1. 管理 macOS 上的证书信任：**

* **与 macOS Security Framework 交互：** 该代码使用 macOS 的 `Security.framework` 来获取和解释系统、管理员和用户配置的证书信任设置。它调用诸如 `SecTrustSettingsCopyTrustSettings` 和 `SecItemCopyMatching` 等 Security Framework 的 API。
* **确定证书的信任状态：**  代码定义了 `TrustStatus` 枚举，表示证书的信任状态（未知、未指定、受信任、不信任）。它实现了将 macOS 特定的信任设置映射到 Chromium 的 `bssl::CertificateTrust` 结构的过程。
* **处理不同的信任域：** 代码区分用户域 (`kSecTrustSettingsDomainUser`)、管理员域 (`kSecTrustSettingsDomainAdmin`) 和系统域（虽然代码中提到但不直接检查）。它遵循用户设置覆盖管理员设置的原则。
* **考虑策略（Policy）：** 代码能够处理针对特定策略（例如 SSL）的信任设置，使用 `kSecTrustSettingsPolicy` 和 `kSecPolicyAppleSSL` 等常量。
* **缓存信任状态：** 为了提高性能，代码实现了缓存机制 (`TrustDomainCacheFullCerts`)，用于存储每个信任域中证书的信任状态。当信任设置发生变化时，缓存会被更新。

**2. 提供证书颁发者来源：**

* **缓存证书：**  `TrustDomainCacheFullCerts` 维护了每个信任域中所有证书的缓存。
* **提供证书颁发者信息：**  它使用 `bssl::CertIssuerSourceStatic` 来存储和提供证书的颁发者信息，这对于构建证书链至关重要。

**3. 监听 Keychain 事件：**

* **监控信任设置更改：** `KeychainChangedNotifier` 和 `KeychainObserver` 模板类用于监听 macOS Keychain 中信任设置的更改 (`kSecTrustSettingsChangedEventMask`)。
* **监控证书添加和 Keychain 列表更改：** 代码也监听证书的添加事件和 Keychain 列表的更改事件 (`kSecAddEventMask | kSecKeychainListChangedMask`)，用于更新中间证书的缓存。

**4. 提供用户添加的证书列表：**

* `GetAllUserAddedCerts` 方法用于获取用户和管理员添加的受信任证书的列表。

**与 JavaScript 功能的关系：**

这段 C++ 代码直接与 JavaScript 功能没有明显的直接关系。然而，它在幕后支撑着 Chromium 网络栈的安全功能，而这些安全功能对于 JavaScript 发起的网络请求至关重要。

**举例说明：**

当 JavaScript 代码通过 `fetch` API 或 `XMLHttpRequest` 发起一个 HTTPS 请求时，Chromium 的网络栈会使用这个 `trust_store_mac.cc` 文件中的代码来验证服务器提供的 SSL/TLS 证书链。

* **假设输入：** JavaScript 代码发起一个到 `https://example.com` 的请求。服务器返回一个证书链，其中包含服务器证书、一个或多个中间证书以及一个根证书。
* **逻辑推理：**  `TrustStoreMac` 中的代码会被调用来检查服务器证书链中每个证书的信任状态。它会查询 macOS 的 Keychain，查看这些证书是否被用户、管理员或系统标记为受信任。
* **输出：** `TrustStoreMac` 的代码会返回一个指示证书链是否可信的结果。如果证书链中的所有证书都被信任（或能够通过有效的信任路径连接到受信任的根证书），则请求会成功。否则，请求可能会失败，浏览器会显示安全警告。

**用户或编程常见的使用错误：**

1. **用户错误：**
   * **错误地将证书标记为“始终信任”：** 用户可能在 macOS 的“钥匙串访问”应用中错误地将一个恶意或过期的证书标记为“始终信任”。这会导致 Chromium 信任该证书，从而可能受到中间人攻击。
   * **删除或修改了系统信任的根证书：** 用户不小心删除了或修改了 macOS 系统信任的根证书，可能导致许多网站的证书验证失败。

2. **编程错误：**
   * **在 Chromium 中错误地使用 `TrustStoreMac` API：**  开发者可能会错误地调用 `TrustStoreMac` 的接口，例如，在不应该信任所有证书的情况下，错误地认为某个证书是受信任的。
   * **未正确处理 Keychain 事件：** 如果监听 Keychain 事件的代码存在缺陷，可能导致信任状态缓存与系统状态不同步，从而导致不一致的信任决策。

**用户操作到达这里的调试线索：**

以下用户操作可能会触发 `trust_store_mac.cc` 中的代码执行，并可作为调试线索：

1. **用户访问 HTTPS 网站：** 当用户在 Chrome 浏览器中输入一个 `https://` 开头的网址时，Chromium 会尝试与服务器建立安全的 TLS 连接，这需要验证服务器的证书。
2. **用户导入证书到 Keychain：** 用户通过“钥匙串访问”应用手动导入一个证书（例如，自签名证书或企业内部的证书）。这会触发 Keychain 的添加事件，`trust_store_mac.cc` 中的监听器会接收到该事件并更新缓存。
3. **用户修改证书的信任设置：** 用户在“钥匙串访问”应用中修改某个证书的信任设置（例如，从“系统默认”改为“始终信任”或“永不信任”）。这会触发 Keychain 的信任设置更改事件，`trust_store_mac.cc` 中的监听器会接收到该事件并更新缓存。
4. **网络配置更改：**  某些网络配置更改，例如连接到使用不同证书颁发机构的 Wi-Fi 网络，可能会导致系统信任设置的更新，从而间接触发此代码。

**功能归纳 (Part 1)：**

`net/cert/internal/trust_store_mac.cc` 的第一部分主要负责**管理和缓存 macOS 系统中证书的信任状态，并提供证书的颁发者信息**。它通过与 macOS Security Framework 交互，监听 Keychain 事件，并维护不同信任域的证书缓存，为 Chromium 的证书验证过程提供基础支持。这部分代码的核心目标是高效、准确地确定证书的信任与否，以便安全地建立 HTTPS 连接。

Prompt: 
```
这是目录为net/cert/internal/trust_store_mac.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/cert/internal/trust_store_mac.h"

#include <Security/Security.h>

#include <map>
#include <string_view>
#include <vector>

#include "base/apple/foundation_util.h"
#include "base/apple/osstatus_logging.h"
#include "base/apple/scoped_cftyperef.h"
#include "base/atomicops.h"
#include "base/callback_list.h"
#include "base/containers/contains.h"
#include "base/containers/flat_map.h"
#include "base/containers/to_vector.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/metrics/histogram_functions.h"
#include "base/no_destructor.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/strcat.h"
#include "base/synchronization/lock.h"
#include "base/timer/elapsed_timer.h"
#include "crypto/mac_security_services_lock.h"
#include "net/base/features.h"
#include "net/base/hash_value.h"
#include "net/base/network_notification_thread_mac.h"
#include "net/cert/internal/platform_trust_store.h"
#include "net/cert/test_keychain_search_list_mac.h"
#include "net/cert/x509_util.h"
#include "net/cert/x509_util_apple.h"
#include "third_party/boringssl/src/include/openssl/sha.h"
#include "third_party/boringssl/src/pki/cert_errors.h"
#include "third_party/boringssl/src/pki/cert_issuer_source_static.h"
#include "third_party/boringssl/src/pki/extended_key_usage.h"
#include "third_party/boringssl/src/pki/parse_name.h"
#include "third_party/boringssl/src/pki/parsed_certificate.h"
#include "third_party/boringssl/src/pki/trust_store.h"

namespace net {

namespace {

// The rules for interpreting trust settings are documented at:
// https://developer.apple.com/reference/security/1400261-sectrustsettingscopytrustsetting?language=objc

// Indicates the trust status of a certificate.
enum class TrustStatus {
  // Trust status is unknown / uninitialized.
  UNKNOWN,
  // Certificate inherits trust value from its issuer. If the certificate is the
  // root of the chain, this implies distrust.
  UNSPECIFIED,
  // Certificate is a trust anchor.
  TRUSTED,
  // Certificate is blocked / explicitly distrusted.
  DISTRUSTED
};

bssl::CertificateTrust TrustStatusToCertificateTrust(TrustStatus trust_status) {
  switch (trust_status) {
    case TrustStatus::TRUSTED: {
      // Mac trust settings don't distinguish between trusted anchors and
      // trusted leafs, return a trust record valid for both, which will
      // depend on the context the certificate is encountered in.
      bssl::CertificateTrust trust =
          bssl::CertificateTrust::ForTrustAnchorOrLeaf()
              .WithEnforceAnchorExpiry()
              .WithEnforceAnchorConstraints()
              .WithRequireAnchorBasicConstraints();
      return trust;
    }
    case TrustStatus::DISTRUSTED:
      return bssl::CertificateTrust::ForDistrusted();
    case TrustStatus::UNSPECIFIED:
      return bssl::CertificateTrust::ForUnspecified();
    case TrustStatus::UNKNOWN:
      // UNKNOWN is an implementation detail of TrustImpl and should never be
      // returned.
      NOTREACHED();
  }

  return bssl::CertificateTrust::ForUnspecified();
}

// Returns trust status of usage constraints dictionary |trust_dict| for a
// certificate that |is_self_issued|.
TrustStatus IsTrustDictionaryTrustedForPolicy(
    CFDictionaryRef trust_dict,
    bool is_self_issued,
    const CFStringRef target_policy_oid) {
  crypto::GetMacSecurityServicesLock().AssertAcquired();

  // An empty trust dict should be interpreted as
  // kSecTrustSettingsResultTrustRoot. This is handled by falling through all
  // the conditions below with the default value of |trust_settings_result|.

  // Trust settings may be scoped to a single application, by checking that the
  // code signing identity of the current application matches the serialized
  // code signing identity in the kSecTrustSettingsApplication key.
  // As this is not presently supported, skip any trust settings scoped to the
  // application.
  if (CFDictionaryContainsKey(trust_dict, kSecTrustSettingsApplication))
    return TrustStatus::UNSPECIFIED;

  // Trust settings may be scoped using policy-specific constraints. For
  // example, SSL trust settings might be scoped to a single hostname, or EAP
  // settings specific to a particular WiFi network.
  // As this is not presently supported, skip any policy-specific trust
  // settings.
  if (CFDictionaryContainsKey(trust_dict, kSecTrustSettingsPolicyString))
    return TrustStatus::UNSPECIFIED;

  // Ignoring kSecTrustSettingsKeyUsage for now; it does not seem relevant to
  // the TLS case.

  // If the trust settings are scoped to a specific policy (via
  // kSecTrustSettingsPolicy), ensure that the policy is the same policy as
  // |target_policy_oid|. If there is no kSecTrustSettingsPolicy key, it's
  // considered a match for all policies.
  if (CFDictionaryContainsKey(trust_dict, kSecTrustSettingsPolicy)) {
    SecPolicyRef policy_ref = base::apple::GetValueFromDictionary<SecPolicyRef>(
        trust_dict, kSecTrustSettingsPolicy);
    if (!policy_ref) {
      return TrustStatus::UNSPECIFIED;
    }
    base::apple::ScopedCFTypeRef<CFDictionaryRef> policy_dict(
        SecPolicyCopyProperties(policy_ref));

    // kSecPolicyOid is guaranteed to be present in the policy dictionary.
    CFStringRef policy_oid = base::apple::GetValueFromDictionary<CFStringRef>(
        policy_dict.get(), kSecPolicyOid);

    if (!CFEqual(policy_oid, target_policy_oid))
      return TrustStatus::UNSPECIFIED;
  }

  // If kSecTrustSettingsResult is not present in the trust dict,
  // kSecTrustSettingsResultTrustRoot is assumed.
  int trust_settings_result = kSecTrustSettingsResultTrustRoot;
  if (CFDictionaryContainsKey(trust_dict, kSecTrustSettingsResult)) {
    CFNumberRef trust_settings_result_ref =
        base::apple::GetValueFromDictionary<CFNumberRef>(
            trust_dict, kSecTrustSettingsResult);
    if (!trust_settings_result_ref ||
        !CFNumberGetValue(trust_settings_result_ref, kCFNumberIntType,
                          &trust_settings_result)) {
      return TrustStatus::UNSPECIFIED;
    }
  }

  if (trust_settings_result == kSecTrustSettingsResultDeny)
    return TrustStatus::DISTRUSTED;

  // This is a bit of a hack: if the cert is self-issued allow either
  // kSecTrustSettingsResultTrustRoot or kSecTrustSettingsResultTrustAsRoot on
  // the basis that SecTrustSetTrustSettings should not allow creating an
  // invalid trust record in the first place. (The spec is that
  // kSecTrustSettingsResultTrustRoot can only be applied to root(self-signed)
  // certs and kSecTrustSettingsResultTrustAsRoot is used for other certs.)
  // This hack avoids having to check the signature on the cert which is slow
  // if using the platform APIs, and may require supporting MD5 signature
  // algorithms on some older OSX versions or locally added roots, which is
  // undesirable in the built-in signature verifier.
  if (is_self_issued) {
    return (trust_settings_result == kSecTrustSettingsResultTrustRoot ||
            trust_settings_result == kSecTrustSettingsResultTrustAsRoot)
               ? TrustStatus::TRUSTED
               : TrustStatus::UNSPECIFIED;
  }

  // kSecTrustSettingsResultTrustAsRoot can only be applied to non-root certs.
  return (trust_settings_result == kSecTrustSettingsResultTrustAsRoot)
             ? TrustStatus::TRUSTED
             : TrustStatus::UNSPECIFIED;
}

// Returns true if the trust settings array |trust_settings| for a certificate
// that |is_self_issued| should be treated as a trust anchor.
TrustStatus IsTrustSettingsTrustedForPolicy(CFArrayRef trust_settings,
                                            bool is_self_issued,
                                            const CFStringRef policy_oid) {
  // An empty trust settings array (that is, the trust_settings parameter
  // returns a valid but empty CFArray) means "always trust this certificate"
  // with an overall trust setting for the certificate of
  // kSecTrustSettingsResultTrustRoot.
  if (CFArrayGetCount(trust_settings) == 0) {
    return is_self_issued ? TrustStatus::TRUSTED : TrustStatus::UNSPECIFIED;
  }

  for (CFIndex i = 0, settings_count = CFArrayGetCount(trust_settings);
       i < settings_count; ++i) {
    CFDictionaryRef trust_dict = reinterpret_cast<CFDictionaryRef>(
        const_cast<void*>(CFArrayGetValueAtIndex(trust_settings, i)));
    TrustStatus trust = IsTrustDictionaryTrustedForPolicy(
        trust_dict, is_self_issued, policy_oid);
    if (trust != TrustStatus::UNSPECIFIED)
      return trust;
  }
  return TrustStatus::UNSPECIFIED;
}

// Returns the trust status for |cert_handle| for the policy |policy_oid| in
// |trust_domain|.
TrustStatus IsSecCertificateTrustedForPolicyInDomain(
    SecCertificateRef cert_handle,
    const bool is_self_issued,
    const CFStringRef policy_oid,
    SecTrustSettingsDomain trust_domain) {
  crypto::GetMacSecurityServicesLock().AssertAcquired();

  base::apple::ScopedCFTypeRef<CFArrayRef> trust_settings;
  OSStatus err = SecTrustSettingsCopyTrustSettings(
      cert_handle, trust_domain, trust_settings.InitializeInto());

  if (err == errSecItemNotFound) {
    // No trust settings for that domain.. try the next.
    return TrustStatus::UNSPECIFIED;
  }
  if (err) {
    OSSTATUS_LOG(ERROR, err) << "SecTrustSettingsCopyTrustSettings error";
    return TrustStatus::UNSPECIFIED;
  }
  TrustStatus trust = IsTrustSettingsTrustedForPolicy(
      trust_settings.get(), is_self_issued, policy_oid);
  return trust;
}

TrustStatus IsCertificateTrustedForPolicyInDomain(
    const bssl::ParsedCertificate* cert,
    const CFStringRef policy_oid,
    SecTrustSettingsDomain trust_domain) {
  // TODO(eroman): Inefficient -- path building will convert between
  // SecCertificateRef and bssl::ParsedCertificate representations multiple
  // times (when getting the issuers, and again here).
  //
  // This conversion will also be done for each domain the cert policy is
  // checked, but the TrustDomainCache ensures this function is only called on
  // domains that actually have settings for the cert. The common case is that
  // a cert will have trust settings in only zero or one domains, and when in
  // more than one domain it would generally be because one domain is
  // overriding the setting in the next, so it would only get done once anyway.
  base::apple::ScopedCFTypeRef<SecCertificateRef> cert_handle =
      x509_util::CreateSecCertificateFromBytes(cert->der_cert());
  if (!cert_handle)
    return TrustStatus::UNSPECIFIED;

  const bool is_self_issued =
      cert->normalized_subject() == cert->normalized_issuer();

  return IsSecCertificateTrustedForPolicyInDomain(
      cert_handle.get(), is_self_issued, policy_oid, trust_domain);
}

TrustStatus IsCertificateTrustedForPolicy(const bssl::ParsedCertificate* cert,
                                          SecCertificateRef cert_handle,
                                          const CFStringRef policy_oid) {
  crypto::GetMacSecurityServicesLock().AssertAcquired();

  const bool is_self_issued =
      cert->normalized_subject() == cert->normalized_issuer();

  // Evaluate user trust domain, then admin. User settings can override
  // admin (and both override the system domain, but we don't check that).
  for (const auto& trust_domain :
       {kSecTrustSettingsDomainUser, kSecTrustSettingsDomainAdmin}) {
    base::apple::ScopedCFTypeRef<CFArrayRef> trust_settings;
    OSStatus err;
    err = SecTrustSettingsCopyTrustSettings(cert_handle, trust_domain,
                                            trust_settings.InitializeInto());
    if (err != errSecSuccess) {
      if (err == errSecItemNotFound) {
        // No trust settings for that domain.. try the next.
        continue;
      }
      OSSTATUS_LOG(ERROR, err) << "SecTrustSettingsCopyTrustSettings error";
      continue;
    }
    TrustStatus trust = IsTrustSettingsTrustedForPolicy(
        trust_settings.get(), is_self_issued, policy_oid);
    if (trust != TrustStatus::UNSPECIFIED)
      return trust;
  }

  // No trust settings, or none of the settings were for the correct policy, or
  // had the correct trust result.
  return TrustStatus::UNSPECIFIED;
}

// Returns true if |cert| would never be a valid intermediate. (A return
// value of false does not imply that it is valid.) This is an optimization
// to avoid using memory for caching certs that would never lead to a valid
// chain. It's not intended to exhaustively test everything that
// VerifyCertificateChain does, just to filter out some of the most obviously
// unusable certs.
bool IsNotAcceptableIntermediate(const bssl::ParsedCertificate* cert,
                                 const CFStringRef policy_oid) {
  if (!cert->has_basic_constraints() || !cert->basic_constraints().is_ca) {
    return true;
  }

  // EKU filter is only implemented for TLS server auth since that's all we
  // actually care about.
  if (cert->has_extended_key_usage() &&
      CFEqual(policy_oid, kSecPolicyAppleSSL) &&
      !base::Contains(cert->extended_key_usage(),
                      bssl::der::Input(bssl::kAnyEKU)) &&
      !base::Contains(cert->extended_key_usage(),
                      bssl::der::Input(bssl::kServerAuth))) {
    return true;
  }

  // TODO(mattm): filter on other things too? (key usage, ...?)
  return false;
}

// Caches certificates and calculated trust status for certificates present in
// a single trust domain.
class TrustDomainCacheFullCerts {
 public:
  struct TrustStatusDetails {
    TrustStatus trust_status = TrustStatus::UNKNOWN;
  };

  TrustDomainCacheFullCerts(SecTrustSettingsDomain domain,
                            CFStringRef policy_oid)
      : domain_(domain), policy_oid_(policy_oid) {
    DCHECK(policy_oid_);
  }

  TrustDomainCacheFullCerts(const TrustDomainCacheFullCerts&) = delete;
  TrustDomainCacheFullCerts& operator=(const TrustDomainCacheFullCerts&) =
      delete;

  // (Re-)Initializes the cache with the certs in |domain_| set to UNKNOWN trust
  // status.
  void Initialize() {
    trust_status_cache_.clear();
    cert_issuer_source_.Clear();

    base::apple::ScopedCFTypeRef<CFArrayRef> cert_array;
    OSStatus rv;
    {
      base::AutoLock lock(crypto::GetMacSecurityServicesLock());
      rv = SecTrustSettingsCopyCertificates(domain_,
                                            cert_array.InitializeInto());
    }
    if (rv != noErr) {
      // Note: SecTrustSettingsCopyCertificates can legitimately return
      // errSecNoTrustSettings if there are no trust settings in |domain_|.
      HistogramTrustDomainCertCount(0U);
      return;
    }
    std::vector<std::pair<SHA256HashValue, TrustStatusDetails>>
        trust_status_vector;
    for (CFIndex i = 0, size = CFArrayGetCount(cert_array.get()); i < size;
         ++i) {
      SecCertificateRef cert = reinterpret_cast<SecCertificateRef>(
          const_cast<void*>(CFArrayGetValueAtIndex(cert_array.get(), i)));
      base::apple::ScopedCFTypeRef<CFDataRef> der_data(
          SecCertificateCopyData(cert));
      if (!der_data) {
        LOG(ERROR) << "SecCertificateCopyData error";
        continue;
      }
      auto buffer = x509_util::CreateCryptoBuffer(
          base::apple::CFDataToSpan(der_data.get()));
      bssl::CertErrors errors;
      bssl::ParseCertificateOptions options;
      options.allow_invalid_serial_numbers = true;
      std::shared_ptr<const bssl::ParsedCertificate> parsed_cert =
          bssl::ParsedCertificate::Create(std::move(buffer), options, &errors);
      if (!parsed_cert) {
        LOG(ERROR) << "Error parsing certificate:\n" << errors.ToDebugString();
        continue;
      }
      cert_issuer_source_.AddCert(std::move(parsed_cert));
      trust_status_vector.emplace_back(x509_util::CalculateFingerprint256(cert),
                                       TrustStatusDetails());
    }
    HistogramTrustDomainCertCount(trust_status_vector.size());
    trust_status_cache_ = base::flat_map<SHA256HashValue, TrustStatusDetails>(
        std::move(trust_status_vector));
  }

  // Returns the trust status for |cert| in |domain_|.
  TrustStatus IsCertTrusted(const bssl::ParsedCertificate* cert,
                            const SHA256HashValue& cert_hash) {
    auto cache_iter = trust_status_cache_.find(cert_hash);
    if (cache_iter == trust_status_cache_.end()) {
      // Cert does not have trust settings in this domain, return UNSPECIFIED.
      return TrustStatus::UNSPECIFIED;
    }

    if (cache_iter->second.trust_status != TrustStatus::UNKNOWN) {
      // Cert has trust settings and trust has already been calculated, return
      // the cached value.
      return cache_iter->second.trust_status;
    }

    base::AutoLock lock(crypto::GetMacSecurityServicesLock());

    // Cert has trust settings but trust has not been calculated yet.
    // Calculate it now, insert into cache, and return.
    TrustStatus cert_trust =
        IsCertificateTrustedForPolicyInDomain(cert, policy_oid_, domain_);
    cache_iter->second.trust_status = cert_trust;
    return cert_trust;
  }

  // Returns true if the certificate with |cert_hash| is present in |domain_|.
  bool ContainsCert(const SHA256HashValue& cert_hash) const {
    return trust_status_cache_.find(cert_hash) != trust_status_cache_.end();
  }

  // Returns a bssl::CertIssuerSource containing all the certificates that are
  // present in |domain_|.
  bssl::CertIssuerSourceStatic& cert_issuer_source() {
    return cert_issuer_source_;
  }

 private:
  void HistogramTrustDomainCertCount(size_t count) const {
    std::string_view domain_name;
    switch (domain_) {
      case kSecTrustSettingsDomainUser:
        domain_name = "User";
        break;
      case kSecTrustSettingsDomainAdmin:
        domain_name = "Admin";
        break;
      case kSecTrustSettingsDomainSystem:
        NOTREACHED();
    }
    base::UmaHistogramCounts1000(
        base::StrCat(
            {"Net.CertVerifier.MacTrustDomainCertCount.", domain_name}),
        count);
  }

  const SecTrustSettingsDomain domain_;
  const CFStringRef policy_oid_;
  base::flat_map<SHA256HashValue, TrustStatusDetails> trust_status_cache_;
  bssl::CertIssuerSourceStatic cert_issuer_source_;
};

SHA256HashValue CalculateFingerprint256(const bssl::der::Input& buffer) {
  SHA256HashValue sha256;
  SHA256(buffer.data(), buffer.size(), sha256.data);
  return sha256;
}

// Watches macOS keychain for |event_mask| notifications, and notifies any
// registered callbacks. This is necessary as the keychain callback API is
// keyed only on the callback function pointer rather than function pointer +
// context, so it cannot be safely registered multiple callbacks with the same
// function pointer and different contexts.
template <SecKeychainEventMask event_mask>
class KeychainChangedNotifier {
 public:
  KeychainChangedNotifier(const KeychainChangedNotifier&) = delete;
  KeychainChangedNotifier& operator=(const KeychainChangedNotifier&) = delete;

  // Registers |callback| to be run when the keychain trust settings change.
  // Must be called on the network notification thread.  |callback| will be run
  // on the network notification thread. The returned subscription must be
  // destroyed on the network notification thread.
  static base::CallbackListSubscription AddCallback(
      base::RepeatingClosure callback) {
    DCHECK(GetNetworkNotificationThreadMac()->RunsTasksInCurrentSequence());
    return Get()->callback_list_.Add(std::move(callback));
  }

 private:
  friend base::NoDestructor<KeychainChangedNotifier>;

// Much of the Keychain API was marked deprecated as of the macOS 13 SDK.
// Removal of its use is tracked in https://crbug.com/1348251 but deprecation
// warnings are disabled in the meanwhile.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

  KeychainChangedNotifier() {
    DCHECK(GetNetworkNotificationThreadMac()->RunsTasksInCurrentSequence());
    OSStatus status =
        SecKeychainAddCallback(&KeychainChangedNotifier::KeychainCallback,
                               event_mask, /*context=*/nullptr);
    if (status != noErr)
      OSSTATUS_LOG(ERROR, status) << "SecKeychainAddCallback failed";
  }

#pragma clang diagnostic pop

  ~KeychainChangedNotifier() = delete;

  static OSStatus KeychainCallback(SecKeychainEvent keychain_event,
                                   SecKeychainCallbackInfo* info,
                                   void* context) {
    // Since SecKeychainAddCallback is keyed on the function pointer only, we
    // need to ensure that each template instantiation of this function has a
    // different address. Calling the static Get() method here to get the
    // |callback_list_| (rather than passing a |this| pointer through
    // |context|) should require each instantiation of KeychainCallback to be
    // unique.
    Get()->callback_list_.Notify();
    return errSecSuccess;
  }

  static KeychainChangedNotifier* Get() {
    static base::NoDestructor<KeychainChangedNotifier> notifier;
    return notifier.get();
  }

  base::RepeatingClosureList callback_list_;
};

// Observes keychain events and increments the value returned by Iteration()
// each time an event indicated by |event_mask| is notified.
template <SecKeychainEventMask event_mask>
class KeychainObserver {
 public:
  KeychainObserver() {
    GetNetworkNotificationThreadMac()->PostTask(
        FROM_HERE,
        base::BindOnce(&KeychainObserver::RegisterCallbackOnNotificationThread,
                       base::Unretained(this)));
  }

  KeychainObserver(const KeychainObserver&) = delete;
  KeychainObserver& operator=(const KeychainObserver&) = delete;

  // Destroying the observer unregisters the callback. Must be destroyed on the
  // notification thread in order to safely release |subscription_|.
  ~KeychainObserver() {
    DCHECK(GetNetworkNotificationThreadMac()->RunsTasksInCurrentSequence());
  }

  // Returns the current iteration count, which is incremented every time
  // keychain trust settings change. This may be called from any thread.
  int64_t Iteration() const { return base::subtle::Acquire_Load(&iteration_); }

 private:
  void RegisterCallbackOnNotificationThread() {
    DCHECK(GetNetworkNotificationThreadMac()->RunsTasksInCurrentSequence());
    subscription_ =
        KeychainChangedNotifier<event_mask>::AddCallback(base::BindRepeating(
            &KeychainObserver::Increment, base::Unretained(this)));
  }

  void Increment() { base::subtle::Barrier_AtomicIncrement(&iteration_, 1); }

  // Only accessed on the notification thread.
  base::CallbackListSubscription subscription_;

  base::subtle::Atomic64 iteration_ = 0;
};

using KeychainTrustObserver =
    KeychainObserver<kSecTrustSettingsChangedEventMask>;

// kSecDeleteEventMask events could also be checked here, but it's not
// necessary for correct behavior. Not including that just means the
// intermediates cache might occasionally be a little larger then necessary.
// In theory, the kSecAddEvent events could also be filtered to only notify on
// events for added certificates as opposed to other keychain objects, however
// that requires some fairly nasty CSSM hackery, so we don't do it.
using KeychainCertsObserver =
    KeychainObserver<kSecAddEventMask | kSecKeychainListChangedMask>;

using KeychainTrustOrCertsObserver =
    KeychainObserver<kSecTrustSettingsChangedEventMask | kSecAddEventMask |
                     kSecKeychainListChangedMask>;

}  // namespace


// Interface for different implementations of getting trust settings from the
// Mac APIs. This abstraction can be removed once a single implementation has
// been chosen and launched.
class TrustStoreMac::TrustImpl {
 public:
  virtual ~TrustImpl() = default;

  virtual TrustStatus IsCertTrusted(const bssl::ParsedCertificate* cert) = 0;
  virtual void SyncGetIssuersOf(const bssl::ParsedCertificate* cert,
                                bssl::ParsedCertificateList* issuers) {}
  virtual void InitializeTrustCache() = 0;
  virtual std::vector<PlatformTrustStore::CertWithTrust>
  GetAllUserAddedCerts() = 0;
};

// TrustImplDomainCacheFullCerts uses SecTrustSettingsCopyCertificates to get
// the list of certs in each trust domain and caches the full certificates so
// that pathbuilding does not need to touch any Mac APIs unless one of those
// certificates is encountered, at which point the calculated trust status of
// that cert is cached. The cache is reset if trust settings are modified.
class TrustStoreMac::TrustImplDomainCacheFullCerts
    : public TrustStoreMac::TrustImpl {
 public:
  explicit TrustImplDomainCacheFullCerts(CFStringRef policy_oid)
      // KeyChainObservers must be destroyed on the network notification
      // thread as they use a non-threadsafe CallbackListSubscription.
      : keychain_trust_observer_(
            new KeychainTrustObserver,
            base::OnTaskRunnerDeleter(GetNetworkNotificationThreadMac())),
        keychain_certs_observer_(
            new KeychainCertsObserver,
            base::OnTaskRunnerDeleter(GetNetworkNotificationThreadMac())),
        policy_oid_(policy_oid, base::scoped_policy::RETAIN),
        admin_domain_cache_(kSecTrustSettingsDomainAdmin, policy_oid),
        user_domain_cache_(kSecTrustSettingsDomainUser, policy_oid) {}

  TrustImplDomainCacheFullCerts(const TrustImplDomainCacheFullCerts&) = delete;
  TrustImplDomainCacheFullCerts& operator=(
      const TrustImplDomainCacheFullCerts&) = delete;

  // Returns the trust status for |cert|.
  TrustStatus IsCertTrusted(const bssl::ParsedCertificate* cert) override {
    SHA256HashValue cert_hash = CalculateFingerprint256(cert->der_cert());

    base::AutoLock lock(cache_lock_);
    MaybeInitializeCache();

    return IsCertTrustedImpl(cert, cert_hash);
  }

  TrustStatus IsCertTrustedImpl(const bssl::ParsedCertificate* cert,
                                const SHA256HashValue& cert_hash)
      EXCLUSIVE_LOCKS_REQUIRED(cache_lock_) {
    // Evaluate user trust domain, then admin. User settings can override
    // admin (and both override the system domain, but we don't check that).
    for (TrustDomainCacheFullCerts* trust_domain_cache :
         {&user_domain_cache_, &admin_domain_cache_}) {
      TrustStatus ts = trust_domain_cache->IsCertTrusted(cert, cert_hash);
      if (ts != TrustStatus::UNSPECIFIED)
        return ts;
    }

    // Cert did not have trust settings in any domain.
    return TrustStatus::UNSPECIFIED;
  }

  void SyncGetIssuersOf(const bssl::ParsedCertificate* cert,
                        bssl::ParsedCertificateList* issuers) override {
    base::AutoLock lock(cache_lock_);
    MaybeInitializeCache();
    user_domain_cache_.cert_issuer_source().SyncGetIssuersOf(cert, issuers);
    admin_domain_cache_.cert_issuer_source().SyncGetIssuersOf(cert, issuers);
    intermediates_cert_issuer_source_.SyncGetIssuersOf(cert, issuers);
  }

  // Initializes the cache, if it isn't already initialized.
  void InitializeTrustCache() override {
    base::AutoLock lock(cache_lock_);
    MaybeInitializeCache();
  }

  std::vector<PlatformTrustStore::CertWithTrust> GetAllUserAddedCerts()
      override {
    base::AutoLock lock(cache_lock_);
    MaybeInitializeCache();

    std::vector<net::PlatformTrustStore::CertWithTrust> results;

    // The same cert might be present in both user_domain_cache_ and
    // admin_domain_cache_ so we need to dedupe and only include each cert in
    // the results once.
    std::map<base::span<const uint8_t>,
             std::shared_ptr<const bssl::ParsedCertificate>>
        all_trusted_certs;
    for (auto& cert : user_domain_cache_.cert_issuer_source().Certs()) {
      all_trusted_certs[cert->der_cert()] = std::move(cert);
    }
    for (auto& cert : admin_domain_cache_.cert_issuer_source().Certs()) {
      all_trusted_certs[cert->der_cert()] = std::move(cert);
    }
    for (const auto& [key, cert] : all_trusted_certs) {
      SHA256HashValue cert_hash = CalculateFingerprint256(cert->der_cert());
      results.emplace_back(base::ToVector(cert->der_cert()),
                           TrustStatusToCertificateTrust(
                               IsCertTrustedImpl(cert.get(), cert_hash)));
    }

    // InitializeIntermediatesCache already ensures that certs in the domain
    // caches are not duplicated in the intemediate cert source, so we don't
    // need to check for duplicates here.
    for (const auto& cert : intermediates_cert_issuer_source_.Certs()) {
      results.emplace_back(base::ToVector(cert->der_cert()),
                           bssl::CertificateTrust::ForUnspecified());
    }

    return results;
  }

 private:
  // (Re-)Initialize the cache if necessary. Must be called after acquiring
  // |cache_lock_| and before accessing any of the |*_domain_cache_| members.
  void MaybeInitializeCache() EXCLUSIVE_LOCKS_REQUIRED(cache_lock_) {
    cache_lock_.AssertAcquired();

    const int64_t keychain_trust_iteration =
        keychain_trust_observer_->Iteration();
    const bool trust_changed = trust_iteration_ != keychain_trust_iteration;
    base::ElapsedTimer trust_domain_cache_init_timer;
    if (trust_changed) {
      trust_iteration_ = keychain_trust_iteration;
      user_domain_cache_.Initialize();
      admin_domain_cache_.Initialize();
      base::UmaHistogramMediumTimes(
          "Net.CertVerifier.MacTrustDomainCacheInitTime",
          trust_domain_cache_init_timer.Elapsed());
    }

    const int64_t keychain_certs_iteration =
        keychain_certs_observer_->Iteration();
    const bool certs_changed = certs_iteration_ != keychain_certs_iteration;
    // Intermediates cache is updated on trust changes too, since the
    // intermediates cache is exclusive of any certs in trust domain caches.
    if (trust_changed || certs_changed) {
      certs_iteration_ = keychain_certs_iteration;
      InitializeIntermediatesCache();
    }
    if (trust_changed) {
      // Histogram of total init time for the case where both the trust cache
      // and intermediates cache were updated.
      base::UmaHistogramMediumTimes(
          "Net.CertVerifier.MacTrustImplCacheInitTime",
          trust_domain_cache_init_timer.Elapsed());
    }
  }

  void InitializeIntermediatesCache() EXCLUSIVE_LOCKS_REQUIRED(cache_lock_) {
    cache_lock_.AssertAcquired();

    base::ElapsedTimer timer;

    intermediates_cert_issuer_source_.Clear();

    base::apple::ScopedCFTypeRef<CFMutableDictionaryRef> query(
        CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks,
                                  &kCFTypeDictionaryValueCallBacks));

    CFDictionarySetValue(query.get(), kSecClass, kSecClassCertificate);
    CFDictionarySetValue(query.get(), kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(query.get(), kSecMatchLimit, kSecMatchLimitAll);

    base::AutoLock lock(crypto::GetMacSecurityServicesLock());

    base::apple::ScopedCFTypeRef<CFArrayRef>
        scoped_alternate_keychain_search_list;
    if (TestKeychainSearchList::HasInstance()) {
      OSStatus status = TestKeychainSearchList::GetInstance()->CopySearchList(
          scoped_alternate_keychain_search_list.InitializeInto());
      if (status) {
        OSSTATUS_LOG(ERROR, status)
            << "TestKeychainSearchList::CopySearchList error";
        return;
      }
      CFDictionarySetValue(query.get(), kSecMatchSearchList,
                           scoped_alternate_keychain_search_list.get());
    }

    base::apple::ScopedCFTypeRef<CFTypeRef> matching_items;
    OSStatus err =
        SecItemCopyMatching(query.get(), matching_items.InitializeInto());
    if (err == errSecItemNotFound) {
      RecordCachedIntermediatesHistograms(0, timer.Elapsed());
      // No matches found.
      return;
    }
    if (err) {
      RecordCachedIntermediatesHistograms(0, timer.Elapsed());
      OSSTATUS_LOG(ERROR, err) << "SecItemCopyMatching error";
      return;
    }
    CFArrayRef matching_items_array =
        base::apple::CFCastStrict<CFArrayRef>(matching_items.get());
    for (CFIndex i = 0, item_count = CFArrayGetCount(matching_items_array);
         i < item_count; ++i) {
      SecCertificateRef match_cert_handle =
          base::apple::CFCastStrict<SecCertificateRef>(
              CFArrayGetValueAtIndex(matching_items_array, i));

      // If cert is already in the trust domain certs cache, don't bother
      // including it in the intermediates cache.
      SHA256HashValue cert_hash =
          x509_util::CalculateFingerprin
"""


```