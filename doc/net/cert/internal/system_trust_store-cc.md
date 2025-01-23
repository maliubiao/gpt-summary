Response:
Let's break down the thought process for analyzing the `system_trust_store.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relation to JavaScript, logical inference examples, common errors, and debugging hints.

2. **Initial Scan and Keyword Recognition:**  Quickly read through the code, looking for key terms and patterns:
    * `#include`:  Indicates dependencies and what functionalities are being used. Notice includes for different platforms (`USE_NSS_CERTS`, `IS_MAC`, `IS_WIN`, `IS_ANDROID`, `IS_FUCHSIA`), and components like `net/cert`, `crypto`, `base`. This suggests platform-specific implementations for managing trusted certificates.
    * `SystemTrustStore`: This is the central class. Its methods (`GetTrustStore`, `IsKnownRoot`, `IsLocallyTrustedRoot`, etc.) reveal its core purpose: managing trust anchors (root certificates).
    * `TrustStoreChrome`, `TrustStoreNSS`, `TrustStoreMac`, `TrustStoreWin`, `TrustStoreAndroid`, `TrustStoreInMemory`: These are different implementations of trust stores, likely for different platforms or scenarios.
    * `CreateSslSystemTrustStoreChromeRoot`, `CreateSystemTrustStoreChrome`: Factory functions for creating `SystemTrustStore` instances. The names suggest different configurations (with or without Chrome Root Store, potentially different underlying platform stores).
    * `InitializeTrustStore...`: Functions that seem to initialize the trust stores, often on worker threads. This hints at potentially blocking operations.
    * `bssl::TrustStore`:  The underlying trust store interface from BoringSSL.
    * Conditional Compilation (`#if BUILDFLAG(...)`):  Highlights platform-specific logic.

3. **Identify Core Functionality:** Based on the keywords and structure, the primary function is managing the system's trusted root certificates. This involves:
    * Loading trusted certificates from various sources (system stores, files, Chrome Root Store).
    * Providing a unified interface (`SystemTrustStore`) to access these certificates.
    * Differentiating between standard/Chrome-provided roots and user-installed roots.
    * Potentially handling platform-specific nuances of trust store management.

4. **JavaScript Relationship:** Consider how this code interacts with the browser's rendering process and web requests. The trust store is crucial for TLS/SSL certificate validation. When a website presents a certificate, the browser needs to check if it's signed by a trusted root CA. This check involves the `SystemTrustStore`. *Crucially*, the C++ code itself doesn't directly execute JavaScript, but its *output* (the decision to trust or not trust a certificate) directly *affects* the behavior of JavaScript running on a webpage. A failure to validate a certificate will likely lead to a blocked request or a security warning in the browser, which would prevent JavaScript on that page from working correctly.

5. **Logical Inference (Hypothetical Inputs and Outputs):** Think about the methods of `SystemTrustStore` and the different trust store implementations.

    * **Input:**  A website presents a certificate.
    * **Process:** The browser's network stack uses the `SystemTrustStore` to check if the certificate's signing chain leads back to a trusted root.
    * **Output:**  `IsKnownRoot` or `IsLocallyTrustedRoot` would return `true` if the root is found, `false` otherwise. The overall validation process (not strictly within *this* file, but using its services) would then succeed or fail.

    * **Input:**  A user installs a new root certificate on their system.
    * **Process:**  The platform-specific trust store (e.g., `TrustStoreMac`, `TrustStoreWin`) would be updated. The `SystemTrustStore` would then reflect this change, potentially through mechanisms like observing database changes.
    * **Output:** `IsLocallyTrustedRoot` would return `true` for certificates signed by the newly installed root.

6. **Common User/Programming Errors:** Think about how incorrect configuration or usage could lead to problems.

    * **User Error:**  Manually removing or distrusting a root certificate that is actually required for legitimate websites.
    * **Programming Error:** Incorrectly configuring or initializing the `SystemTrustStore` in tests or embedded environments. Forgetting to handle platform differences. Not properly handling asynchronous initialization.

7. **Debugging Hints (User Steps):**  Trace the user's actions that could lead to this code being involved. The most direct path is encountering a website with an SSL/TLS certificate.

    * User navigates to a website (`https://example.com`).
    * The browser initiates a TLS handshake.
    * The server presents its certificate.
    * The browser uses the `SystemTrustStore` to validate the certificate.

8. **Structure and Refine:** Organize the findings into the requested categories. Use clear and concise language. Explain technical terms briefly. Provide concrete examples. Review for accuracy and completeness.

**(Self-Correction during the process):**

* **Initial thought:**  Maybe there's a direct JavaScript API for manipulating trust stores. *Correction:* No, this C++ code operates at a lower level. The interaction is indirect through the impact on network requests.
* **Initial thought:**  Focus only on the `SystemTrustStore` class. *Correction:*  Need to also explain the role of the platform-specific `TrustStore` implementations and the factory functions.
* **Initial thought:**  Just list the file's functionality. *Correction:* The request also asks for logical inference, errors, and debugging hints, so expand on those areas.

By following these steps, you can systematically analyze a complex C++ file like `system_trust_store.cc` and provide a comprehensive answer to the given prompt.
`net/cert/internal/system_trust_store.cc` 文件是 Chromium 网络栈中负责管理系统信任锚（即受信任的根证书）的关键组件。它的主要功能是提供一个统一的接口，供 Chromium 使用，以访问和查询操作系统或其他来源提供的受信任的证书。这对于验证 HTTPS 连接的服务器证书至关重要。

**主要功能：**

1. **抽象系统信任存储:** 该文件定义了 `SystemTrustStore` 抽象类，为不同的操作系统和平台提供了统一的访问系统信任证书的方式。这样，Chromium 的其他部分就不需要关心底层平台是如何存储和管理证书的。

2. **平台特定实现:**  根据不同的编译配置（`BUILDFLAG`），该文件会包含并使用特定于平台的信任存储实现：
   - **`USE_NSS_CERTS` (Linux 等):** 使用 Network Security Services (NSS) 库来访问系统证书。
   - **`IS_MAC` (macOS):** 使用 macOS 的 Security Framework API (`Security.h`)。
   - **`IS_WIN` (Windows):** 使用 Windows 的证书存储 API。
   - **`IS_ANDROID` (Android):** 使用 Android 的 KeyStore API。
   - **`IS_FUCHSIA` (Fuchsia):** 从配置文件中读取证书。
   - **`CHROME_ROOT_STORE_SUPPORTED`:** 支持 Chrome Root Store，这是一个由 Chromium 维护的受信任根证书列表。

3. **Chrome Root Store 支持:** 如果启用了 `CHROME_ROOT_STORE_SUPPORTED`，该文件可以创建一个 `SystemTrustStore` 实例，它结合了系统提供的证书和 Chrome 自身维护的证书列表。这允许 Chromium 在某些情况下使用自己的信任根，例如，在系统证书过期或存在安全风险时。

4. **测试支持 (ChromeOS):** 在 ChromeOS 上，如果检测到测试镜像，该文件还会尝试加载 `/etc/fake_root_ca_certs.pem` 文件中的证书，用于测试目的。

5. **信任状态查询:** `SystemTrustStore` 类提供了方法来查询证书的信任状态，例如：
   - `GetTrustStore()`: 返回底层的 `bssl::TrustStore` 对象，用于执行证书路径验证。
   - `IsKnownRoot(const bssl::ParsedCertificate* trust_anchor)`: 检查给定的证书是否是标准（非用户安装）的受信任根证书（通常来自 Chrome Root Store）。
   - `IsLocallyTrustedRoot(const bssl::ParsedCertificate* trust_anchor)`: 检查给定的证书是否在本地被信任。
   - `chrome_root_store_version()`: 返回 Chrome Root Store 的版本。
   - `GetChromeRootConstraints()`: 获取 Chrome Root Store 中特定证书的约束。

6. **初始化:**  该文件中的函数，例如 `InitializeTrustStoreMacCache()` 和 `InitializeTrustStoreWinSystem()`,  负责在后台线程初始化平台特定的信任存储，因为加载系统证书可能涉及 I/O 操作，不应阻塞主线程。

**与 JavaScript 的关系：**

`net/cert/internal/system_trust_store.cc` 本身是用 C++ 编写的，不直接包含 JavaScript 代码。然而，它的功能对 JavaScript 在浏览器环境中的运行至关重要。

当 JavaScript 代码尝试访问一个 `https://` 网站时，浏览器会执行以下步骤：

1. **发起 HTTPS 连接:**  浏览器使用网络栈建立与服务器的安全连接。
2. **服务器证书验证:**  服务器会向浏览器发送其 SSL/TLS 证书。浏览器需要验证这个证书是否由受信任的证书颁发机构 (CA) 签名。
3. **使用 SystemTrustStore:**  浏览器会调用 `SystemTrustStore` 来获取系统信任的根证书列表。
4. **证书链验证:** 浏览器会尝试构建从服务器证书到受信任根证书的证书链。
5. **JavaScript 的影响:** 如果证书验证成功，HTTPS 连接建立，JavaScript 代码可以安全地与服务器进行交互。如果验证失败，浏览器通常会阻止连接，并向用户显示安全警告，JavaScript 代码将无法正常执行或可能根本无法加载。

**举例说明 JavaScript 的关系：**

假设一个 JavaScript 代码尝试通过 `fetch` API 访问 `https://example.com`:

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data))
  .catch(error => console.error('Error fetching data:', error));
```

在这个过程中，`net/cert/internal/system_trust_store.cc` 的代码会在后台参与到验证 `example.com` 的服务器证书的过程中。如果 `example.com` 的证书是由一个 `SystemTrustStore` 认为可信的 CA 签名的，那么 `fetch` 请求会成功，JavaScript 代码可以获取并处理数据。如果证书不可信（例如，自签名证书，或者签名 CA 不在信任列表中），浏览器可能会阻止请求，`catch` 块中的错误处理逻辑会被执行。

**逻辑推理（假设输入与输出）：**

假设输入：一个指向 `bssl::ParsedCertificate` 对象的指针，表示一个待验证的证书。

调用 `IsLocallyTrustedRoot()` 方法：

- **假设输入 1：**  证书是由操作系统信任的根证书签名的（例如，用户安装的企业证书）。
  - **输出 1：** `IsLocallyTrustedRoot()` 返回 `true`.

- **假设输入 2：** 证书是由一个不在操作系统信任列表中的 CA 签名的，但可能在 Chrome Root Store 中。
  - **输出 2：** `IsLocallyTrustedRoot()` 返回 `false`，但 `IsKnownRoot()` 可能返回 `true` (如果该 CA 在 Chrome Root Store 中)。

- **假设输入 3：** 证书是由一个既不在操作系统信任列表也不在 Chrome Root Store 中的 CA 签名的（例如，一个新出现的，还未被广泛信任的 CA）。
  - **输出 3：** `IsLocallyTrustedRoot()` 和 `IsKnownRoot()` 都返回 `false`.

**用户或编程常见的使用错误：**

1. **用户错误：**
   - **手动删除或禁用系统信任的根证书：**  用户可能会因为不了解其作用而删除或禁用一些系统预装的根证书。这会导致许多合法的 HTTPS 网站无法访问，浏览器会显示证书错误。
   - **信任恶意或不安全的根证书：**  用户可能会被诱导安装不安全的根证书，这会使他们的浏览器信任由这些恶意 CA 签名的证书，从而可能遭受中间人攻击。

2. **编程错误：**
   - **在测试环境中没有正确配置信任存储：**  在进行网络相关的测试时，如果没有正确配置测试环境的信任存储，可能会导致测试失败，因为测试服务器使用的自签名证书或其他非标准证书无法被信任。
   - **错误地假设所有平台都使用相同的信任存储机制：**  开发者需要注意不同操作系统管理信任证书的方式不同，直接操作平台特定的证书存储可能会导致兼容性问题。Chromium 的 `SystemTrustStore` 旨在解决这个问题，提供一个跨平台的抽象。
   - **在不需要阻塞的情况下进行同步的证书加载操作：**  某些平台加载系统证书可能涉及耗时的 I/O 操作。在主线程同步执行这些操作会导致 UI 卡顿。Chromium 通过在后台线程初始化信任存储来避免这个问题。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户在浏览器地址栏输入一个 `https://` 开头的网址，或者点击一个 `https://` 链接。**
2. **Chromium 的网络栈开始建立与目标服务器的 TCP 连接。**
3. **在 TCP 连接建立后，网络栈发起 TLS 握手。**
4. **服务器在 TLS 握手过程中向客户端（浏览器）发送其 SSL/TLS 证书。**
5. **Chromium 的证书验证逻辑被触发。**
6. **证书验证逻辑会调用 `net/cert/internal/system_trust_store.cc` 中定义的 `SystemTrustStore` 接口。**
7. **`SystemTrustStore` 的具体实现（取决于操作系统和编译配置）会被调用，以获取系统信任的根证书列表。**
   - 例如，在 macOS 上，会调用 `TrustStoreMac` 来与 Security Framework 交互。
   - 在 Windows 上，会调用 `TrustStoreWin` 来访问 Windows 证书存储。
8. **证书验证逻辑会将服务器提供的证书链与 `SystemTrustStore` 返回的受信任根证书进行比对，以验证证书的有效性。**
9. **如果验证成功，TLS 握手完成，浏览器可以安全地与服务器进行通信，加载网页内容。**
10. **如果验证失败，浏览器会显示安全警告（例如 "您的连接不是私密连接"），阻止或警告用户继续访问。**

作为调试线索，当遇到 HTTPS 相关的连接问题或证书错误时，可以检查以下方面：

- **操作系统的信任证书存储：** 用户是否意外移除了某些根证书？是否安装了不信任的根证书？
- **Chrome 的设置：** 是否启用了某些影响证书验证的实验性功能？
- **网络环境：** 是否存在中间人攻击导致证书被替换？
- **服务器配置：** 服务器的证书是否有效？证书链是否完整？

通过理解 `net/cert/internal/system_trust_store.cc` 的功能，可以更好地诊断和解决与 HTTPS 相关的网络问题。

### 提示词
```
这是目录为net/cert/internal/system_trust_store.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/system_trust_store.h"

#include <memory>
#include <optional>
#include <vector>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/no_destructor.h"
#include "base/task/task_traits.h"
#include "base/task/thread_pool.h"
#include "base/threading/thread_restrictions.h"
#include "build/build_config.h"
#include "crypto/crypto_buildflags.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "third_party/boringssl/src/pki/cert_errors.h"
#include "third_party/boringssl/src/pki/parsed_certificate.h"
#include "third_party/boringssl/src/pki/trust_store_collection.h"
#include "third_party/boringssl/src/pki/trust_store_in_memory.h"

#if BUILDFLAG(USE_NSS_CERTS)
#include "net/cert/internal/system_trust_store_nss.h"
#include "net/cert/internal/trust_store_nss.h"
#elif BUILDFLAG(IS_MAC)
#include <Security/Security.h>

#include "net/base/features.h"
#include "net/cert/internal/trust_store_mac.h"
#include "net/cert/x509_util_apple.h"
#elif BUILDFLAG(IS_FUCHSIA)
#include "base/lazy_instance.h"
#include "third_party/boringssl/src/include/openssl/pool.h"
#elif BUILDFLAG(IS_WIN)
#include "net/cert/internal/trust_store_win.h"
#elif BUILDFLAG(IS_ANDROID)
#include "net/cert/internal/trust_store_android.h"
#endif

#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
#include "net/cert/internal/trust_store_chrome.h"
#endif  // CHROME_ROOT_STORE_SUPPORTED

#if BUILDFLAG(IS_CHROMEOS)
#include "base/system/sys_info.h"
#endif

namespace net {

#if BUILDFLAG(IS_CHROMEOS)
namespace internal {
class PemFileCertStore {
 public:
  explicit PemFileCertStore(std::string_view file_name) {
    // This will block on the cert verifier service thread, so the effect will
    // just be to block any cert verifications (interactions with the cert
    // verifier service are async mojo calls, so it shouldn't block the browser
    // UI). There would be no benefit to moving this to a worker thread, since
    // all cert verifications would still need to block on loading of the roots
    // to complete.
    base::ScopedAllowBlocking allow_blocking;
    std::optional<std::vector<uint8_t>> certs_file =
        base::ReadFileToBytes(base::FilePath(file_name));
    if (!certs_file) {
      return;
    }

    trust_store_ = std::make_unique<bssl::TrustStoreInMemory>();

    CertificateList certs = X509Certificate::CreateCertificateListFromBytes(
        *certs_file, X509Certificate::FORMAT_AUTO);

    for (const auto& cert : certs) {
      bssl::CertErrors errors;
      auto parsed = bssl::ParsedCertificate::Create(
          bssl::UpRef(cert->cert_buffer()),
          x509_util::DefaultParseCertificateOptions(), &errors);
      if (!parsed) {
        LOG(ERROR) << file_name << ": " << errors.ToDebugString();
        continue;
      }
      trust_store_->AddTrustAnchor(std::move(parsed));
    }
  }

  bssl::TrustStoreInMemory* trust_store() { return trust_store_.get(); }

 private:
  std::unique_ptr<bssl::TrustStoreInMemory> trust_store_;
};
}  // namespace internal

namespace {

// On ChromeOS look for a PEM file of root CA certs to trust which may be
// present on test images.
bssl::TrustStoreInMemory* GetChromeOSTestTrustStore() {
  constexpr char kCrosTestRootCertsFile[] = "/etc/fake_root_ca_certs.pem";
  static base::NoDestructor<internal::PemFileCertStore> cros_test_roots{
      kCrosTestRootCertsFile};
  return cros_test_roots->trust_store();
}

}  // namespace
#endif

#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
class SystemTrustStoreChromeWithUnOwnedSystemStore : public SystemTrustStore {
 public:
  // Creates a SystemTrustStore that gets publicly trusted roots from
  // |trust_store_chrome| and local trust settings from |trust_store_system|,
  // if non-null. Does not take ownership of |trust_store_system|, which must
  // outlive this object.
  explicit SystemTrustStoreChromeWithUnOwnedSystemStore(
      std::unique_ptr<TrustStoreChrome> trust_store_chrome,
      net::PlatformTrustStore* trust_store_system)
      : trust_store_chrome_(std::move(trust_store_chrome)),
        platform_trust_store_(trust_store_system) {
#if BUILDFLAG(IS_CHROMEOS)
    if (GetChromeOSTestTrustStore()) {
      // The fake_root_ca_certs.pem file is only intended for testing purposes,
      // crash if it is present on a ChromeOS device in a non-test image.
      base::SysInfo::CrashIfChromeOSNonTestImage();

      trust_store_collection_.AddTrustStore(GetChromeOSTestTrustStore());
      non_crs_trust_store_collection_.AddTrustStore(
          GetChromeOSTestTrustStore());
    }
#endif
    if (trust_store_system) {
      trust_store_collection_.AddTrustStore(trust_store_system);
      non_crs_trust_store_collection_.AddTrustStore(trust_store_system);
    }

    trust_store_collection_.AddTrustStore(trust_store_chrome_.get());
  }

  bssl::TrustStore* GetTrustStore() override {
    return &trust_store_collection_;
  }

  // IsKnownRoot returns true if the given trust anchor is a standard one (as
  // opposed to a user-installed root)
  bool IsKnownRoot(const bssl::ParsedCertificate* trust_anchor) const override {
    return trust_store_chrome_->Contains(trust_anchor);
  }

  bool IsLocallyTrustedRoot(
      const bssl::ParsedCertificate* trust_anchor) override {
    return non_crs_trust_store_collection_.GetTrust(trust_anchor)
        .IsTrustAnchor();
  }

  int64_t chrome_root_store_version() const override {
    return trust_store_chrome_->version();
  }

  base::span<const ChromeRootCertConstraints> GetChromeRootConstraints(
      const bssl::ParsedCertificate* cert) const override {
    return trust_store_chrome_->GetConstraintsForCert(cert);
  }

  net::PlatformTrustStore* GetPlatformTrustStore() override {
    return platform_trust_store_;
  }

 private:
  std::unique_ptr<TrustStoreChrome> trust_store_chrome_;
  bssl::TrustStoreCollection trust_store_collection_;
  bssl::TrustStoreCollection non_crs_trust_store_collection_;
  net::PlatformTrustStore* platform_trust_store_;
};

std::unique_ptr<SystemTrustStore> CreateChromeOnlySystemTrustStore(
    std::unique_ptr<TrustStoreChrome> chrome_root) {
  return std::make_unique<SystemTrustStoreChromeWithUnOwnedSystemStore>(
      std::move(chrome_root), /*trust_store_system=*/nullptr);
}

class SystemTrustStoreChrome
    : public SystemTrustStoreChromeWithUnOwnedSystemStore {
 public:
  // Creates a SystemTrustStore that gets publicly trusted roots from
  // |trust_store_chrome| and local trust settings from |trust_store_system|.
  explicit SystemTrustStoreChrome(
      std::unique_ptr<TrustStoreChrome> trust_store_chrome,
      std::unique_ptr<net::PlatformTrustStore> trust_store_system)
      : SystemTrustStoreChromeWithUnOwnedSystemStore(
            std::move(trust_store_chrome),
            trust_store_system.get()),
        trust_store_system_(std::move(trust_store_system)) {}

 private:
  std::unique_ptr<net::PlatformTrustStore> trust_store_system_;
};

std::unique_ptr<SystemTrustStore> CreateSystemTrustStoreChromeForTesting(
    std::unique_ptr<TrustStoreChrome> trust_store_chrome,
    std::unique_ptr<net::PlatformTrustStore> trust_store_system) {
  return std::make_unique<SystemTrustStoreChrome>(
      std::move(trust_store_chrome), std::move(trust_store_system));
}
#endif  // CHROME_ROOT_STORE_SUPPORTED

#if BUILDFLAG(USE_NSS_CERTS)

std::unique_ptr<SystemTrustStore> CreateSslSystemTrustStoreChromeRoot(
    std::unique_ptr<TrustStoreChrome> chrome_root) {
  return std::make_unique<SystemTrustStoreChrome>(
      std::move(chrome_root), std::make_unique<TrustStoreNSS>(
                                  TrustStoreNSS::UseTrustFromAllUserSlots()));
}

std::unique_ptr<SystemTrustStore>
CreateSslSystemTrustStoreChromeRootWithUserSlotRestriction(
    std::unique_ptr<TrustStoreChrome> chrome_root,
    crypto::ScopedPK11Slot user_slot_restriction) {
  return std::make_unique<SystemTrustStoreChrome>(
      std::move(chrome_root),
      std::make_unique<TrustStoreNSS>(std::move(user_slot_restriction)));
}

#elif BUILDFLAG(IS_MAC)

namespace {

TrustStoreMac* GetGlobalTrustStoreMacForCRS() {
  constexpr TrustStoreMac::TrustImplType kDefaultMacTrustImplForCRS =
      TrustStoreMac::TrustImplType::kDomainCacheFullCerts;
  static base::NoDestructor<TrustStoreMac> static_trust_store_mac(
      kSecPolicyAppleSSL, kDefaultMacTrustImplForCRS);
  return static_trust_store_mac.get();
}

void InitializeTrustCacheForCRSOnWorkerThread() {
  GetGlobalTrustStoreMacForCRS()->InitializeTrustCache();
}

}  // namespace

std::unique_ptr<SystemTrustStore> CreateSslSystemTrustStoreChromeRoot(
    std::unique_ptr<TrustStoreChrome> chrome_root) {
  return std::make_unique<SystemTrustStoreChromeWithUnOwnedSystemStore>(
      std::move(chrome_root), GetGlobalTrustStoreMacForCRS());
}

void InitializeTrustStoreMacCache() {
  base::ThreadPool::PostTask(
      FROM_HERE,
      {base::MayBlock(), base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
      base::BindOnce(&InitializeTrustCacheForCRSOnWorkerThread));
}

#elif BUILDFLAG(IS_FUCHSIA)

namespace {

constexpr char kRootCertsFileFuchsia[] = "/config/ssl/cert.pem";

class FuchsiaSystemCerts {
 public:
  FuchsiaSystemCerts() {
    base::FilePath filename(kRootCertsFileFuchsia);
    std::string certs_file;
    if (!base::ReadFileToString(filename, &certs_file)) {
      LOG(ERROR) << "Can't load root certificates from " << filename;
      return;
    }

    CertificateList certs = X509Certificate::CreateCertificateListFromBytes(
        base::as_byte_span(certs_file), X509Certificate::FORMAT_AUTO);

    for (const auto& cert : certs) {
      bssl::CertErrors errors;
      auto parsed = bssl::ParsedCertificate::Create(
          bssl::UpRef(cert->cert_buffer()),
          x509_util::DefaultParseCertificateOptions(), &errors);
      CHECK(parsed) << errors.ToDebugString();
      system_trust_store_.AddTrustAnchor(std::move(parsed));
    }
  }

  bssl::TrustStoreInMemory* system_trust_store() {
    return &system_trust_store_;
  }

 private:
  bssl::TrustStoreInMemory system_trust_store_;
};

base::LazyInstance<FuchsiaSystemCerts>::Leaky g_root_certs_fuchsia =
    LAZY_INSTANCE_INITIALIZER;

}  // namespace

class SystemTrustStoreFuchsia : public SystemTrustStore {
 public:
  SystemTrustStoreFuchsia() = default;

  bssl::TrustStore* GetTrustStore() override {
    return g_root_certs_fuchsia.Get().system_trust_store();
  }

  bool IsKnownRoot(const bssl::ParsedCertificate* trust_anchor) const override {
    return g_root_certs_fuchsia.Get().system_trust_store()->Contains(
        trust_anchor);
  }
};

std::unique_ptr<SystemTrustStore> CreateSslSystemTrustStore() {
  return std::make_unique<SystemTrustStoreFuchsia>();
}

#elif BUILDFLAG(IS_WIN)

namespace {
TrustStoreWin* GetGlobalTrustStoreWinForCRS() {
  static base::NoDestructor<TrustStoreWin> static_trust_store_win;
  return static_trust_store_win.get();
}

void InitializeTrustStoreForCRSOnWorkerThread() {
  GetGlobalTrustStoreWinForCRS()->InitializeStores();
}
}  // namespace

std::unique_ptr<SystemTrustStore> CreateSslSystemTrustStoreChromeRoot(
    std::unique_ptr<TrustStoreChrome> chrome_root) {
  return std::make_unique<SystemTrustStoreChromeWithUnOwnedSystemStore>(
      std::move(chrome_root), GetGlobalTrustStoreWinForCRS());
}

// We do this in a separate thread as loading the Windows Cert Stores can cause
// quite a bit of I/O. See crbug.com/1399974 for more context.
void InitializeTrustStoreWinSystem() {
  base::ThreadPool::PostTask(
      FROM_HERE,
      {base::MayBlock(), base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
      base::BindOnce(&InitializeTrustStoreForCRSOnWorkerThread));
}

#elif BUILDFLAG(IS_ANDROID)

#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)

namespace {
TrustStoreAndroid* GetGlobalTrustStoreAndroidForCRS() {
  static base::NoDestructor<TrustStoreAndroid> static_trust_store_android;
  return static_trust_store_android.get();
}

void InitializeTrustStoreForCRSOnWorkerThread() {
  GetGlobalTrustStoreAndroidForCRS()->Initialize();
}
}  // namespace

std::unique_ptr<SystemTrustStore> CreateSslSystemTrustStoreChromeRoot(
    std::unique_ptr<TrustStoreChrome> chrome_root) {
  return std::make_unique<SystemTrustStoreChromeWithUnOwnedSystemStore>(
      std::move(chrome_root), GetGlobalTrustStoreAndroidForCRS());
}

void InitializeTrustStoreAndroid() {
  // Start observing DB change before the Trust Store is initialized so we don't
  // accidentally miss any changes. See https://crrev.com/c/4226436 for context.
  //
  // This call is safe here because we're the only callers of
  // ObserveCertDBChanges on the singleton TrustStoreAndroid.
  GetGlobalTrustStoreAndroidForCRS()->ObserveCertDBChanges();

  base::ThreadPool::PostTask(
      FROM_HERE,
      {base::MayBlock(), base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN},
      base::BindOnce(&InitializeTrustStoreForCRSOnWorkerThread));
}

#else

void InitializeTrustStoreAndroid() {}

#endif  // CHROME_ROOT_STORE_SUPPORTED

#endif

}  // namespace net
```