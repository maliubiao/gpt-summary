Response:
My thinking process for analyzing the provided code and generating the response involved several steps:

1. **Understanding the Goal:** The core request is to understand the functionality of the provided C++ code snippet from `trust_store_mac.cc`, specifically focusing on its role in Chromium's networking stack, its relationship to JavaScript (if any), and potential usage errors. Since this is "part 2," the goal also includes summarizing the overall functionality based on both parts.

2. **Initial Code Scan and Keyword Identification:** I started by reading through the code, paying attention to key terms and data structures. Terms like `TrustStoreMac`, `TrustImpl`, `Keychain`, `SecCertificate`, `ParsedCertificate`, `TrustStatus`, `Cache`, `Observer`, `Histogram`, and `policy_oid` immediately jumped out as important. This gave me a high-level understanding that the code is about managing certificate trust on macOS by interacting with the Keychain.

3. **Dissecting the Classes (`TrustImpl` implementations):** I then focused on the two main classes implementing `TrustImpl`:
    * `TrustImplDomainCacheFullCerts`: The name suggests it caches trust information based on "domains," likely referring to the user and admin domains in macOS's Keychain. I looked for how it populates this cache, focusing on `SecTrustSettingsCopyTrustSettings`, and the logic for distinguishing user and admin added certificates. The presence of `KeychainTrustObserver` and `KeychainCertsObserver` signaled that it listens for Keychain changes.
    * `TrustImplKeychainCacheFullCerts`:  This class seemed to directly cache all certificates from the Keychain. The usage of `SecItemCopyMatching` to fetch all certificates was a key indicator. The logic then iterated through these certificates, checking their trust status and adding them to the cache.

4. **Identifying Key Functionalities within Each Class:**  For each `TrustImpl`, I pinpointed the core functionalities:
    * `IsCertTrusted`:  Determining the trust status of a given certificate.
    * `SyncGetIssuersOf`: Finding the issuers of a certificate (used for building certificate chains).
    * `InitializeTrustCache`:  Triggering the initial or re-initialization of the cache.
    * `GetAllUserAddedCerts`: Retrieving all user-added certificates and their trust status.
    * The `MaybeInitializeCache` method in both classes was crucial for understanding the caching strategy.

5. **Analyzing Data Structures and Operations:**  I paid attention to the data structures used for caching:
    * `TrustDomainCacheFullCerts`:  Appears to store full certificate information, separated by domain (user/admin).
    * `trust_status_cache_`:  Stores the trust status of certificates.
    * `intermediates_cert_issuer_source_` and `cert_issuer_source_`:  Used for storing intermediate certificates, aiding in issuer lookup.

6. **Looking for JavaScript Connections:** I specifically searched for any interactions with JavaScript APIs or data structures. The code interacts directly with macOS system APIs and Chromium's internal certificate handling mechanisms. There's no direct JavaScript involvement evident in this specific code snippet. However, I recognized that this code is part of Chromium's networking stack, which *is* used by the browser and, therefore, indirectly supports JavaScript functionality by ensuring secure HTTPS connections.

7. **Inferring Logic and Creating Examples:**  Based on my understanding of the code, I constructed hypothetical input and output examples for the `IsCertTrusted` function. This involved considering different trust scenarios (trusted, distrusted, unspecified).

8. **Identifying Potential User/Programming Errors:** I thought about how a developer or user might misuse this component. Incorrectly configured Keychain settings, problems with certificate parsing, and assumptions about caching behavior were potential error scenarios.

9. **Tracing User Actions:** I considered the user actions that would lead to this code being executed. Browsing an HTTPS website, installing a certificate, or changing trust settings are the primary triggers.

10. **Synthesizing the Summary (Part 2):**  Finally, I combined my understanding of the two `TrustImpl` classes to create a concise summary of the file's overall functionality, emphasizing its role in caching trusted certificates and intermediates on macOS.

11. **Review and Refinement:** I reviewed my analysis to ensure accuracy, clarity, and completeness, making sure to address all aspects of the prompt. I particularly focused on clearly distinguishing the functionalities of the two `TrustImpl` classes and their respective caching strategies.

By following these steps, I was able to break down the complex code into manageable parts, understand its purpose, and generate a comprehensive and informative response. The iterative nature of understanding code, going back and forth between different sections, and making inferences based on names and structures is crucial for this type of analysis.
感谢提供代码片段。这是 `net/cert/internal/trust_store_mac.cc` 文件的第二部分，主要定义了 `TrustStoreMac` 类及其内部的两种 `TrustImpl` 实现方式。

基于你提供的代码片段（第二部分）和之前的分析（假设存在第一部分），我们可以归纳一下 `TrustStoreMac` 的功能：

**核心功能归纳 (基于第二部分):**

* **`TrustStoreMac` 类作为 macOS 平台证书信任信息的统一访问接口。** 它封装了不同的证书信任信息获取和缓存策略。
* **提供了两种 `TrustImpl` 的实现方式，用于获取和缓存证书信任信息：**
    * **`TrustImplDomainCacheFullCerts` (第一部分推测):**  可能基于 macOS 的安全域（admin 和 user）来缓存完整的证书信息，并监听 Keychain 的变动来更新缓存。它侧重于区分用户添加和管理员添加的证书，并缓存中间证书。
    * **`TrustImplKeychainCacheFullCerts` (第二部分):**  直接从 macOS 的 Keychain 中获取所有证书，并缓存证书的信任状态和作为中间证书的可能性。它不区分证书的来源（user/admin），而是直接枚举 Keychain 中的所有证书。
* **`IsCertTrusted` 方法：** 用于判断给定证书是否被信任。它会先尝试从缓存中查找，如果缓存未初始化则会进行初始化。
* **`SyncGetIssuersOf` 方法：**  用于同步获取给定证书的签发者。这依赖于缓存中存储的证书信息。
* **`InitializeTrustCache` 方法：**  强制初始化或重新初始化证书信任信息的缓存。
* **`GetAllUserAddedCerts` 方法：** 返回所有用户添加的证书及其信任状态（仅在 `TrustImplKeychainCacheFullCerts` 中实现并基于该实现方式的缓存）。
* **使用观察者模式监听 Keychain 的变化：**  `KeychainTrustObserver` 和 `KeychainCertsObserver` 用于监听 macOS Keychain 的变动，并在发生变化时触发缓存的更新。
* **性能监控和统计：** 使用 UMA 宏记录缓存初始化时间、证书总数、中间证书数量和信任证书数量等信息，用于性能分析和监控。
* **处理证书策略 (policy_oid_)：**  允许根据特定的策略 OID 来过滤和判断证书的信任状态。

**结合第一部分和第二部分，`TrustStoreMac` 的总体功能是：**

`TrustStoreMac` 负责在 Chromium 的 macOS 版本中高效地管理和访问系统级别的证书信任信息。它通过不同的策略实现（`TrustImpl`），利用 macOS 的 Keychain 服务来获取证书和它们的信任设置。它维护一个本地缓存，以减少对 Keychain 的重复查询，提高性能。同时，它监听 Keychain 的变化，以保持缓存与系统状态的同步。`TrustStoreMac` 提供的接口允许 Chromium 网络栈查询证书的信任状态、获取证书的签发者，并获取所有用户添加的证书。选择哪种 `TrustImpl` 实现方式可能基于性能考虑或对证书来源的特定需求。

**与 JavaScript 的关系：**

`TrustStoreMac` 本身是用 C++ 实现的，不直接与 JavaScript 交互。然而，它的功能是 Chromium 网络栈的关键组成部分，而网络栈是浏览器执行 JavaScript 代码时进行网络请求的基础。

**举例说明：**

当 JavaScript 代码尝试发起一个 HTTPS 请求时（例如，使用 `fetch` 或 `XMLHttpRequest`）：

1. **JavaScript 发起请求:** JavaScript 代码通过浏览器提供的 API (如 `fetch`) 发起一个到 HTTPS 网站的请求。
2. **网络栈处理请求:** Chromium 的网络栈接收到这个请求。
3. **证书验证:** 网络栈会尝试与服务器建立安全连接，这涉及到服务器发送其 SSL/TLS 证书。
4. **`TrustStoreMac` 参与验证:**  网络栈会使用 `TrustStoreMac` 来验证服务器证书的有效性和信任状态。
    * 网络栈可能会调用 `TrustStoreMac::IsCertTrusted()` 来检查服务器证书的根证书是否在系统的信任存储中。
    * 如果需要构建证书链，网络栈可能会调用 `TrustStoreMac::SyncGetIssuersOf()` 来查找中间证书。
5. **连接建立或失败:**  根据证书验证的结果，HTTPS 连接可能会成功建立，或者因为证书不受信任而失败。
6. **JavaScript 得到响应:**  最终，JavaScript 代码会得到请求的结果（成功或失败）。

在这个过程中，`TrustStoreMac` 在后台默默地工作，确保浏览器信任的证书是合法的。JavaScript 开发者通常不需要直接与 `TrustStoreMac` 交互，但它的正确运行对于保证 Web 应用的安全至关重要。

**逻辑推理、假设输入与输出 (以 `TrustImplKeychainCacheFullCerts::IsCertTrusted` 为例):**

**假设输入:**

* `cert`: 一个指向 `bssl::ParsedCertificate` 对象的指针，代表一个从服务器收到的证书。该证书的 SHA256 指纹为 `A1B2C3D4...`.
* `TrustStoreMac` 使用 `TrustImplType::kKeychainCacheFullCerts` 初始化。
* 用户之前安装了一个自签名证书，该证书的 SHA256 指纹恰好是 `A1B2C3D4...`，并且用户将其标记为“始终信任”。

**推理过程:**

1. 当 `IsCertTrusted` 被调用时，首先计算输入 `cert` 的 SHA256 指纹。
2. 获取 `cache_lock_`。
3. 调用 `MaybeInitializeCache()`。由于是第一次调用或 Keychain 有变动，`MaybeInitializeCache` 会执行：
    * 清空 `trust_status_cache_` 和 `cert_issuer_source_`。
    * 使用 `SecItemCopyMatching` 从 Keychain 中获取所有证书。
    * 遍历获取到的证书，解析它们，并使用 `IsCertificateTrustedForPolicy` 检查其信任状态。
    * 对于用户标记为“始终信任”的自签名证书（指纹为 `A1B2C3D4...` 的证书），`IsCertificateTrustedForPolicy` 将返回 `TrustStatus::TRUSTED`。
    * 该证书的指纹和 `TrustStatus::TRUSTED` 将被添加到 `trust_status_cache_` 中。
4. 在 `IsCertTrustedImpl` 中，使用输入的证书指纹 `A1B2C3D4...` 在 `trust_status_cache_` 中查找。
5. 找到匹配的条目，其值为 `TrustStatus::TRUSTED`。

**假设输出:**

`TrustStoreMac::IsCertTrusted(cert)` 将返回 `TrustStatus::TRUSTED`。

**用户或编程常见的使用错误举例说明:**

1. **假设缓存总是最新的:** 开发者可能会错误地认为 `TrustStoreMac` 的缓存总是与系统的 Keychain 完全同步。虽然有观察者监听变化，但在某些极端情况下，可能会存在短暂的延迟。依赖缓存的即时一致性可能会导致问题。

2. **错误地配置或修改 Keychain:** 用户或恶意软件可能会错误地修改 macOS 的 Keychain 设置，例如意外地删除了根证书或错误地信任了恶意证书。`TrustStoreMac` 会反映这些系统级别的设置，如果系统信任配置被破坏，`TrustStoreMac` 也会认为那些恶意证书是受信任的。

3. **在测试环境中不正确地模拟 Keychain 状态:**  在进行网络相关的单元测试或集成测试时，如果需要模拟证书信任场景，开发者可能需要使用 `TestKeychainSearchList` 等机制来控制 `TrustStoreMac` 的行为。如果模拟不正确，测试结果可能不准确。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在使用 Chrome 浏览器访问一个使用 HTTPS 的网站，并且该网站的证书链中包含一个中间证书，而该中间证书不在 Chrome 的内置根证书列表中，但已添加到用户的 macOS Keychain 中。

1. **用户在 Chrome 浏览器地址栏输入 HTTPS 网址并访问。**
2. **Chrome 的网络栈开始与服务器建立 TLS 连接。**
3. **服务器发送证书链给 Chrome。**
4. **Chrome 的证书验证模块开始验证服务器证书的有效性。**
5. **验证过程中，发现需要查找中间证书以完成证书链的构建。**
6. **网络栈调用 `TrustStoreMac::SyncGetIssuersOf()`，尝试从系统 Keychain 中查找签发该服务器证书的中间证书。**
7. **在 `SyncGetIssuersOf()` 内部，`TrustImplKeychainCacheFullCerts::MaybeInitializeCache()` (如果尚未初始化) 会被调用，它会查询 macOS Keychain 获取所有证书。**
8. **在枚举 Keychain 证书的过程中，找到了匹配的中间证书。**
9. **该中间证书被添加到用于构建证书链的列表中。**
10. **最终，整个证书链被验证为有效，TLS 连接建立成功。**
11. **用户能够正常访问该 HTTPS 网站。**

如果在这个过程中出现问题（例如，中间证书未添加到 Keychain，或者 Keychain 数据损坏），开发者可以通过查看 Chrome 的网络日志 (`chrome://net-export/`) 或使用调试器断点在 `TrustStoreMac` 的相关方法中进行调试，以追踪证书查找和验证的流程。

希望这些详细的解释能够帮助你更好地理解 `net/cert/internal/trust_store_mac.cc` 的功能。

### 提示词
```
这是目录为net/cert/internal/trust_store_mac.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
t256(match_cert_handle);
      if (user_domain_cache_.ContainsCert(cert_hash) ||
          admin_domain_cache_.ContainsCert(cert_hash)) {
        continue;
      }

      base::apple::ScopedCFTypeRef<CFDataRef> der_data(
          SecCertificateCopyData(match_cert_handle));
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
      if (IsNotAcceptableIntermediate(parsed_cert.get(), policy_oid_.get())) {
        continue;
      }
      intermediates_cert_issuer_source_.AddCert(std::move(parsed_cert));
    }
    RecordCachedIntermediatesHistograms(CFArrayGetCount(matching_items_array),
                                        timer.Elapsed());
  }

  void RecordCachedIntermediatesHistograms(CFIndex total_cert_count,
                                           base::TimeDelta cache_init_time)
      const EXCLUSIVE_LOCKS_REQUIRED(cache_lock_) {
    cache_lock_.AssertAcquired();
    base::UmaHistogramMediumTimes(
        "Net.CertVerifier.MacKeychainCerts.IntermediateCacheInitTime",
        cache_init_time);
    base::UmaHistogramCounts1000("Net.CertVerifier.MacKeychainCerts.TotalCount",
                                 total_cert_count);
    base::UmaHistogramCounts1000(
        "Net.CertVerifier.MacKeychainCerts.IntermediateCount",
        intermediates_cert_issuer_source_.size());
  }

  const std::unique_ptr<KeychainTrustObserver, base::OnTaskRunnerDeleter>
      keychain_trust_observer_;
  const std::unique_ptr<KeychainCertsObserver, base::OnTaskRunnerDeleter>
      keychain_certs_observer_;
  const base::apple::ScopedCFTypeRef<CFStringRef> policy_oid_;

  base::Lock cache_lock_;
  // |cache_lock_| must be held while accessing any following members.
  int64_t trust_iteration_ GUARDED_BY(cache_lock_) = -1;
  int64_t certs_iteration_ GUARDED_BY(cache_lock_) = -1;

  TrustDomainCacheFullCerts admin_domain_cache_ GUARDED_BY(cache_lock_);
  TrustDomainCacheFullCerts user_domain_cache_ GUARDED_BY(cache_lock_);

  bssl::CertIssuerSourceStatic intermediates_cert_issuer_source_
      GUARDED_BY(cache_lock_);
};

// TrustImplKeychainCacheFullCerts uses SecItemCopyMatching to get the list of
// all user and admin added certificates, then checks each to see if has trust
// settings. Certs will be cached if they are trusted or are potentially valid
// intermediates.
class TrustStoreMac::TrustImplKeychainCacheFullCerts
    : public TrustStoreMac::TrustImpl {
 public:
  explicit TrustImplKeychainCacheFullCerts(CFStringRef policy_oid)
      : keychain_observer_(
            new KeychainTrustOrCertsObserver,
            // KeyChainObserver must be destroyed on the network notification
            // thread as it uses a non-threadsafe CallbackListSubscription.
            base::OnTaskRunnerDeleter(GetNetworkNotificationThreadMac())),
        policy_oid_(policy_oid, base::scoped_policy::RETAIN) {}

  TrustImplKeychainCacheFullCerts(const TrustImplKeychainCacheFullCerts&) =
      delete;
  TrustImplKeychainCacheFullCerts& operator=(
      const TrustImplKeychainCacheFullCerts&) = delete;

  TrustStatus IsCertTrusted(const bssl::ParsedCertificate* cert) override {
    SHA256HashValue cert_hash = CalculateFingerprint256(cert->der_cert());

    base::AutoLock lock(cache_lock_);
    MaybeInitializeCache();

    return IsCertTrustedImpl(cert_hash);
  }

  TrustStatus IsCertTrustedImpl(const SHA256HashValue& cert_hash)
      EXCLUSIVE_LOCKS_REQUIRED(cache_lock_) {
    auto cache_iter = trust_status_cache_.find(cert_hash);
    if (cache_iter == trust_status_cache_.end())
      return TrustStatus::UNSPECIFIED;
    return cache_iter->second;
  }

  void SyncGetIssuersOf(const bssl::ParsedCertificate* cert,
                        bssl::ParsedCertificateList* issuers) override {
    base::AutoLock lock(cache_lock_);
    MaybeInitializeCache();
    cert_issuer_source_.SyncGetIssuersOf(cert, issuers);
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
    for (const auto& cert : cert_issuer_source_.Certs()) {
      SHA256HashValue cert_hash = CalculateFingerprint256(cert->der_cert());
      results.emplace_back(
          base::ToVector(cert->der_cert()),
          TrustStatusToCertificateTrust(IsCertTrustedImpl(cert_hash)));
    }
    return results;
  }

 private:
  // (Re-)Initialize the cache if necessary. Must be called after acquiring
  // |cache_lock_| and before accessing any of the |*_domain_cache_| members.
  void MaybeInitializeCache() EXCLUSIVE_LOCKS_REQUIRED(cache_lock_) {
    cache_lock_.AssertAcquired();

    const int64_t keychain_iteration = keychain_observer_->Iteration();
    const bool keychain_changed = keychain_iteration_ != keychain_iteration;
    if (!keychain_changed)
      return;
    keychain_iteration_ = keychain_iteration;

    base::ElapsedTimer timer;

    trust_status_cache_.clear();
    cert_issuer_source_.Clear();

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
      RecordHistograms(0, timer.Elapsed());
      // No matches found.
      return;
    }
    if (err) {
      RecordHistograms(0, timer.Elapsed());
      OSSTATUS_LOG(ERROR, err) << "SecItemCopyMatching error";
      return;
    }
    CFArrayRef matching_items_array =
        base::apple::CFCastStrict<CFArrayRef>(matching_items.get());
    std::vector<std::pair<SHA256HashValue, TrustStatus>> trust_status_vector;
    for (CFIndex i = 0, item_count = CFArrayGetCount(matching_items_array);
         i < item_count; ++i) {
      SecCertificateRef sec_cert = base::apple::CFCastStrict<SecCertificateRef>(
          CFArrayGetValueAtIndex(matching_items_array, i));

      base::apple::ScopedCFTypeRef<CFDataRef> der_data(
          SecCertificateCopyData(sec_cert));
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

      TrustStatus trust_status = IsCertificateTrustedForPolicy(
          parsed_cert.get(), sec_cert, policy_oid_.get());

      if (trust_status == TrustStatus::TRUSTED ||
          trust_status == TrustStatus::DISTRUSTED) {
        trust_status_vector.emplace_back(
            X509Certificate::CalculateFingerprint256(
                parsed_cert->cert_buffer()),
            trust_status);
        cert_issuer_source_.AddCert(std::move(parsed_cert));
        continue;
      }

      if (IsNotAcceptableIntermediate(parsed_cert.get(), policy_oid_.get())) {
        continue;
      }
      cert_issuer_source_.AddCert(std::move(parsed_cert));
    }
    trust_status_cache_ = base::flat_map<SHA256HashValue, TrustStatus>(
        std::move(trust_status_vector));
    RecordHistograms(CFArrayGetCount(matching_items_array), timer.Elapsed());
  }

  void RecordHistograms(CFIndex total_cert_count,
                        base::TimeDelta init_time) const
      EXCLUSIVE_LOCKS_REQUIRED(cache_lock_) {
    cache_lock_.AssertAcquired();
    base::UmaHistogramMediumTimes("Net.CertVerifier.MacTrustImplCacheInitTime",
                                  init_time);
    base::UmaHistogramCounts1000("Net.CertVerifier.MacKeychainCerts.TotalCount",
                                 total_cert_count);
    base::UmaHistogramCounts1000(
        "Net.CertVerifier.MacKeychainCerts.IntermediateCount",
        cert_issuer_source_.size() - trust_status_cache_.size());
    base::UmaHistogramCounts1000("Net.CertVerifier.MacKeychainCerts.TrustCount",
                                 trust_status_cache_.size());
  }

  const std::unique_ptr<KeychainTrustOrCertsObserver, base::OnTaskRunnerDeleter>
      keychain_observer_;
  const base::apple::ScopedCFTypeRef<CFStringRef> policy_oid_;

  base::Lock cache_lock_;
  // |cache_lock_| must be held while accessing any following members.
  int64_t keychain_iteration_ GUARDED_BY(cache_lock_) = -1;
  base::flat_map<SHA256HashValue, TrustStatus> trust_status_cache_
      GUARDED_BY(cache_lock_);
  bssl::CertIssuerSourceStatic cert_issuer_source_ GUARDED_BY(cache_lock_);
};

TrustStoreMac::TrustStoreMac(CFStringRef policy_oid, TrustImplType impl) {
  switch (impl) {
    case TrustImplType::kUnknown:
      DCHECK(false);
      break;
    case TrustImplType::kDomainCacheFullCerts:
      trust_cache_ =
          std::make_unique<TrustImplDomainCacheFullCerts>(policy_oid);
      break;
    case TrustImplType::kKeychainCacheFullCerts:
      trust_cache_ =
          std::make_unique<TrustImplKeychainCacheFullCerts>(policy_oid);
      break;
  }
}

TrustStoreMac::~TrustStoreMac() = default;

void TrustStoreMac::InitializeTrustCache() const {
  trust_cache_->InitializeTrustCache();
}

void TrustStoreMac::SyncGetIssuersOf(const bssl::ParsedCertificate* cert,
                                     bssl::ParsedCertificateList* issuers) {
  trust_cache_->SyncGetIssuersOf(cert, issuers);
}

bssl::CertificateTrust TrustStoreMac::GetTrust(
    const bssl::ParsedCertificate* cert) {
  return TrustStatusToCertificateTrust(trust_cache_->IsCertTrusted(cert));
}

std::vector<PlatformTrustStore::CertWithTrust>
TrustStoreMac::GetAllUserAddedCerts() {
  return trust_cache_->GetAllUserAddedCerts();
}

}  // namespace net
```