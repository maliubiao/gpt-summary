Response:
Let's break down the thought process for analyzing the `trust_store_win.cc` file.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of this Chromium networking stack file and relate it to JavaScript, user errors, debugging, and logical deductions with input/output examples.

**2. Initial Scan and High-Level Understanding:**

* **Filename:** `trust_store_win.cc` immediately suggests it's related to trust management on Windows.
* **Copyright and License:** Standard Chromium boilerplate.
* **Includes:**  A mix of Chromium base libraries (`base/`), networking (`net/`), and external libraries like BoringSSL (`third_party/boringssl`). This confirms the file deals with cryptographic trust. The presence of `win_util.h` indicates interactions with the Windows CryptoAPI.
* **Namespaces:** The code resides within the `net` namespace.
* **Key Types and Structures:**  `HCERTSTORE`, `PCCERT_CONTEXT`, `CERT_ENHKEY_USAGE`, `bssl::ParsedCertificate`, `bssl::CertificateTrust`, `PlatformTrustStore::CertWithTrust`. These are core to certificate management on Windows and in BoringSSL.
* **`#ifdef UNSAFE_BUFFERS_BUILD`:**  A potential area for caution, indicating the handling of raw memory.

**3. Identifying Core Functionality by Examining Key Functions and Data Structures:**

* **`TrustStoreWin` class:**  The central class, responsible for managing trust on Windows.
* **`CertStores` struct:**  Clearly represents different certificate stores (roots, intermediates, trusted people, disallowed). The `CreateInMemoryStoresForTesting`, `CreateNullStoresForTesting`, and `CreateWithCollections` static methods indicate different modes of operation, likely for testing and actual usage.
* **`Impl` class:** A private implementation detail, likely used for managing the lifetime and internal state of the `TrustStoreWin`. This pattern is common for encapsulation.
* **`IsCertTrustedForServerAuth` function:** A critical function that determines if a certificate is trusted for server authentication based on Extended Key Usage (EKU). The detailed comments explaining the logic of EKU checking are very helpful.
* **`AddCertWithTrust` function:**  Simple helper to package a certificate and its trust status.
* **`SyncGetIssuersOf` function:**  Looks up certificates that could have issued a given certificate.
* **`GetTrust` function:**  The core function that determines the trust status of a certificate based on its presence and properties in the Windows certificate stores. The logic for handling the disallowed store, root store, and trusted people store is key.
* **`GetAllUserAddedCerts` function:**  Retrieves all user-added certificates and their trust status from the various Windows stores.
* **`GatherEnterpriseCertsForLocation` function:**  (Although not explicitly defined in the provided snippet, its usage implies its functionality) This function is crucial for fetching certificates from different system and user certificate stores on Windows.

**4. Answering Specific Questions:**

* **Functionality:**  Summarize the purpose of each major component and how they work together. Focus on trust management, retrieving certificates from Windows stores, and checking trust based on EKUs.
* **Relationship to JavaScript:**  Consider how JavaScript in a browser might interact with this code. The key link is through secure connections (HTTPS). When a website presents a certificate, the browser (using code like this) verifies its trust. Provide a concrete example like `fetch('https://example.com')`.
* **Logical Deduction (Input/Output):**  Choose a simple but illustrative scenario, like a self-signed certificate in the Trusted People store. Specify the input (certificate data, store location) and the expected output (trusted). Similarly, create an example for a distrusted certificate.
* **User/Programming Errors:** Think about common mistakes when dealing with certificates on Windows. Incorrectly importing certificates, especially into the wrong store, is a prime example. Also, mention the importance of EKU settings.
* **User Actions and Debugging:** Trace the user's actions from visiting a website to the point where this code might be involved. Focus on the SSL handshake and certificate verification process. This helps explain *why* this code is executed.

**5. Refinement and Organization:**

* Structure the answer logically using headings and bullet points.
* Use clear and concise language.
* Emphasize key concepts like certificate stores, trust anchors, and EKUs.
* Ensure the examples are easy to understand.
* Review and edit for accuracy and completeness.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus heavily on the Windows API calls.
* **Correction:**  Realize that the higher-level functionality and its connection to the browser are more important for the user's understanding. Shift the focus to the *purpose* rather than just the *implementation details*.
* **Initial thought:**  Provide very technical details about certificate encoding.
* **Correction:**  Simplify the explanations, focusing on the *concept* of a certificate and its properties (like EKU) without getting bogged down in the ASN.1 specifics.
* **Initial thought:**  Only consider successful scenarios for input/output.
* **Correction:**  Include examples of both trusted and distrusted scenarios to illustrate the logic.

By following this process of scanning, identifying core components, answering specific questions, and refining the answer, we can generate a comprehensive and informative explanation of the `trust_store_win.cc` file.
这个文件 `net/cert/internal/trust_store_win.cc` 是 Chromium 网络栈中负责管理 Windows 操作系统提供的证书信任存储的组件。它的主要功能是：

**主要功能：**

1. **访问 Windows 证书存储:**  它使用 Windows CryptoAPI (CertOpenStore, CertFindCertificateInStore, CertEnumCertificatesInStore 等) 来访问和读取 Windows 系统中存储的证书，包括：
    * **Root 证书存储 (ROOT):**  包含被操作系统信任的根证书颁发机构 (CA) 的证书。这些证书被认为是信任的起点。
    * **中间证书存储 (CA):**  包含中间 CA 的证书，用于构建证书链。
    * **受信任的人员存储 (TrustedPeople):**  包含用户明确信任的服务器证书，通常是自签名证书。
    * **不允许的证书存储 (Disallowed):** 包含被用户或系统明确标记为不信任的证书。

2. **将 Windows 证书映射到 Chromium 的信任模型:**  Chromium 有自己的信任模型 (`bssl::CertificateTrust`)。这个文件负责将从 Windows 证书存储中检索到的证书转换为 Chromium 可以理解的信任状态。

3. **确定证书的信任状态 (`GetTrust`):**  给定一个证书，这个文件会检查它是否存在于 Windows 的各个证书存储中，并根据其所在的位置和属性（例如，增强型密钥用法 EKU）来确定其信任状态。
    * 如果证书在 **不允许的证书存储** 中，则被认为是 **不信任的 (Distrusted)**。
    * 如果证书在 **根证书存储** 中，并且其 EKU 允许用于服务器身份验证 (TLS Server Auth)，则被认为是 **信任的 (Trusted)**，可以作为信任锚点。
    * 如果证书在 **受信任的人员存储** 中，并且其 EKU 允许用于服务器身份验证，则被认为是 **信任的 (Trusted Leaf)**。
    * 如果证书在 **中间证书存储** 中，其信任状态通常是 **未指定 (Unspecified)**，需要进一步的验证。

4. **查找证书的颁发者 (`SyncGetIssuersOf`):**  给定一个证书，这个文件会在 Windows 的证书存储中查找可能的颁发者证书，用于构建证书链。

5. **获取所有用户添加的证书 (`GetAllUserAddedCerts`):**  遍历 Windows 的各个证书存储，获取用户明确添加的证书及其信任状态。

6. **处理企业策略添加的证书:**  代码会从本地机器和当前用户的组策略以及企业存储中加载证书，这意味着它可以处理由组织管理员配置的信任设置。

7. **支持证书存储的自动同步:**  使用 `CertControlStore` 启用证书存储的自动同步，以便及时反映 Windows 证书存储的变化。

**与 JavaScript 的关系：**

虽然这个 C++ 代码本身不直接与 JavaScript 交互，但它是浏览器安全机制的关键组成部分，而浏览器正是 JavaScript 代码的运行环境。

**举例说明：**

当 JavaScript 代码尝试建立一个 HTTPS 连接（例如，使用 `fetch` 或 `XMLHttpRequest`）到一个网站时，浏览器需要验证网站服务器提供的 SSL/TLS 证书的有效性和可信度。`trust_store_win.cc` 中的代码就会被调用来：

1. **获取操作系统提供的信任根证书:**  JavaScript 代码间接地依赖于这个文件来访问 Windows 系统信任的根证书列表。
2. **验证服务器证书的信任链:**  当浏览器收到服务器证书时，它需要构建一个信任链，从服务器证书回溯到已知的受信任的根证书。`SyncGetIssuersOf` 功能会参与到这个过程中。
3. **检查用户添加的信任设置:**  如果用户手动将某个自签名证书添加到 Windows 的 "受信任的人员" 存储中，那么当 JavaScript 连接到使用该证书的服务器时，`GetTrust` 函数会识别出该证书是可信的。
4. **检查用户添加的不信任设置:**  如果用户将某个证书添加到 Windows 的 "不允许的" 存储中，那么即使该证书可能被其他方式认为是有效的，`GetTrust` 也会将其标记为不信任的，从而阻止 JavaScript 代码与使用该证书的网站建立连接。

**假设输入与输出 (逻辑推理):**

**假设输入 1:**

* **操作:**  用户访问一个使用自签名证书的内部网站 `https://internal.example.com`。
* **Windows 证书存储状态:**  该自签名证书已由用户添加到 Windows 的 "受信任的人员" 存储中。
* **Chromium 调用:**  当尝试建立连接时，Chromium 的证书验证逻辑会调用 `trust_store_win.cc` 中的 `GetTrust` 函数，并将服务器提供的证书作为输入。

**预期输出 1:**

* `GetTrust` 函数会识别出该证书存在于 "受信任的人员" 存储中，并且其 EKU 允许服务器身份验证，因此返回 `bssl::CertificateTrust` 对象，表示该证书是受信任的 (Trusted Leaf)。

**假设输入 2:**

* **操作:**  用户访问一个由已知但已被用户明确设置为不信任的 CA 签名的网站 `https://bad.example.com`。
* **Windows 证书存储状态:**  该 CA 的证书已被用户添加到 Windows 的 "不允许的" 存储中。
* **Chromium 调用:**  当尝试建立连接时，Chromium 的证书验证逻辑会调用 `trust_store_win.cc` 中的 `GetTrust` 函数，并将服务器证书链中的 CA 证书作为输入。

**预期输出 2:**

* `GetTrust` 函数会识别出该 CA 证书存在于 "不允许的" 存储中，因此返回 `bssl::CertificateTrust` 对象，表示该证书是 **不信任的 (Distrusted)**。

**用户或编程常见的使用错误：**

1. **错误地将证书导入到错误的存储:**  用户可能将根证书错误地导入到 "中间证书" 存储，或者反之。这会导致 Chromium 在验证证书链时找不到预期的信任锚点，从而导致连接失败。
    * **例如:** 用户下载了一个根 CA 证书，但在导入时选择了 "将所有证书放入以下存储" -> "CA"，而不是 "受信任的根证书颁发机构"。

2. **忘记导入中间证书:**  如果服务器只发送了其自身的证书，而没有发送必要的中间证书，Chromium 可能无法构建完整的信任链。虽然这更多是服务器配置问题，但与用户的证书管理也相关。

3. **意外地将受信任的根证书标记为不信任:**  用户可能误操作，将一个原本受信任的根证书添加到 "不允许的" 存储中，导致所有由该根 CA 签名的网站都无法访问。
    * **例如:** 用户在 `certmgr.msc` 中错误地将某个根证书移动到了 "不受信任的证书" 文件夹。

4. **程序错误地依赖于用户手动添加的证书:**  开发者可能假设用户已经手动安装了某个特定的证书，但实际上并非如此。这会导致程序在某些用户的环境中无法正常工作。

**用户操作到达这里的步骤（作为调试线索）：**

1. **用户在 Chromium 浏览器中输入一个 HTTPS 网址并尝试访问。**
2. **Chromium 发起与服务器的 TLS 握手。**
3. **服务器向 Chromium 提供其 SSL/TLS 证书。**
4. **Chromium 的证书验证模块被激活。**
5. **证书验证模块需要检查服务器证书的信任状态。**
6. **由于是 Windows 系统，Chromium 的证书验证模块会调用 `net::TrustStoreWin` 的相关方法。**
7. **`TrustStoreWin` 的 `GetTrust` 方法会被调用，传入服务器证书的解析结果 (`bssl::ParsedCertificate`) 作为参数。**
8. **`GetTrust` 方法内部会使用 Windows CryptoAPI 来搜索各个证书存储 (根证书、中间证书、受信任的人员、不允许的证书)，查找与服务器证书匹配的证书。**
9. **根据证书在不同存储中的存在情况和属性（例如 EKU），`GetTrust` 方法返回服务器证书的信任状态。**
10. **证书验证模块根据返回的信任状态决定是否继续连接，如果证书不可信，则会向用户显示安全警告或阻止连接。**

**调试线索：**

* **网络日志 (net-internals):**  Chromium 的 `chrome://net-internals/#events` 可以记录详细的网络事件，包括证书验证过程。可以查看是否有关于 "TrustStoreWin" 或证书查找的日志信息。
* **BoringSSL 日志:**  如果启用了 BoringSSL 的调试日志，可能会有更底层的关于证书处理的信息。
* **Windows 事件查看器:**  在某些情况下，Windows 的事件查看器可能会记录与证书存储相关的错误或警告。
* **使用 `certmgr.msc`:**  用户可以通过运行 `certmgr.msc` 打开 Windows 的证书管理器，手动检查各个证书存储的内容，确认证书是否被添加到了预期的位置，以及是否存在意外的 "不允许的" 证书。
* **检查组策略设置:**  如果怀疑是企业策略导致的问题，可以检查本地组策略编辑器 (`gpedit.msc`) 中与证书服务相关的设置。

总而言之，`net/cert/internal/trust_store_win.cc` 是 Chromium 在 Windows 平台上实现证书信任验证的关键组件，它充当了 Chromium 和 Windows 操作系统证书存储之间的桥梁，确保用户能够安全地访问 HTTPS 网站。

### 提示词
```
这是目录为net/cert/internal/trust_store_win.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/374320451): Fix and remove.
#pragma allow_unsafe_buffers
#endif

#include "net/cert/internal/trust_store_win.h"

#include <string_view>

#include "base/containers/span.h"
#include "base/containers/to_vector.h"
#include "base/hash/sha1.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/ranges/algorithm.h"
#include "base/strings/string_number_conversions.h"
#include "base/threading/scoped_blocking_call.h"
#include "net/base/features.h"
#include "net/cert/x509_util.h"
#include "net/cert/x509_util_win.h"
#include "net/third_party/mozilla_win/cert/win_util.h"
#include "third_party/boringssl/src/pki/cert_errors.h"
#include "third_party/boringssl/src/pki/parsed_certificate.h"

namespace net {

namespace {

// Certificates in the Windows roots store may be used as either trust
// anchors or trusted leafs (if self-signed).
constexpr bssl::CertificateTrust kRootCertTrust =
    bssl::CertificateTrust::ForTrustAnchorOrLeaf()
        .WithEnforceAnchorExpiry()
        .WithEnforceAnchorConstraints()
        .WithRequireLeafSelfSigned();

// Certificates in the Trusted People store may be trusted leafs (if
// self-signed).
constexpr bssl::CertificateTrust kTrustedPeopleTrust =
    bssl::CertificateTrust::ForTrustedLeaf().WithRequireLeafSelfSigned();

// Returns true if the cert can be used for server authentication, based on
// certificate properties.
//
// While there are a variety of certificate properties that can affect how
// trust is computed, the main property is CERT_ENHKEY_USAGE_PROP_ID, which
// is intersected with the certificate's EKU extension (if present).
// The intersection is documented in the Remarks section of
// CertGetEnhancedKeyUsage, and is as follows:
// - No EKU property, and no EKU extension = Trusted for all purpose
// - Either an EKU property, or EKU extension, but not both = Trusted only
//   for the listed purposes
// - Both an EKU property and an EKU extension = Trusted for the set
//   intersection of the listed purposes
// CertGetEnhancedKeyUsage handles this logic, and if an empty set is
// returned, the distinction between the first and third case can be
// determined by GetLastError() returning CRYPT_E_NOT_FOUND.
//
// See:
// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetenhancedkeyusage
//
// If we run into any errors reading the certificate properties, we fail
// closed.
bool IsCertTrustedForServerAuth(PCCERT_CONTEXT cert) {
  DWORD usage_size = 0;

  if (!CertGetEnhancedKeyUsage(cert, 0, nullptr, &usage_size)) {
    return false;
  }

  std::vector<BYTE> usage_bytes(usage_size);
  CERT_ENHKEY_USAGE* usage =
      reinterpret_cast<CERT_ENHKEY_USAGE*>(usage_bytes.data());
  if (!CertGetEnhancedKeyUsage(cert, 0, usage, &usage_size)) {
    return false;
  }

  if (usage->cUsageIdentifier == 0) {
    // check GetLastError
    HRESULT error_code = GetLastError();

    switch (error_code) {
      case CRYPT_E_NOT_FOUND:
        return true;
      case S_OK:
        return false;
      default:
        return false;
    }
  }

  // SAFETY: `usage->rgpszUsageIdentifier` is an array of LPSTR (pointer to null
  // terminated string) of length `usage->cUsageIdentifier`.
  base::span<LPSTR> usage_identifiers = UNSAFE_BUFFERS(
      base::make_span(usage->rgpszUsageIdentifier, usage->cUsageIdentifier));
  for (std::string_view eku : usage_identifiers) {
    if ((eku == szOID_PKIX_KP_SERVER_AUTH) ||
        (eku == szOID_ANY_ENHANCED_KEY_USAGE)) {
      return true;
    }
  }
  return false;
}

void AddCertWithTrust(
    PCCERT_CONTEXT cert,
    const bssl::CertificateTrust trust,
    std::vector<net::PlatformTrustStore::CertWithTrust>* certs) {
  certs->push_back(net::PlatformTrustStore::CertWithTrust(
      base::ToVector(x509_util::CertContextAsSpan(cert)), trust));
}

}  // namespace

TrustStoreWin::CertStores::CertStores() = default;
TrustStoreWin::CertStores::~CertStores() = default;
TrustStoreWin::CertStores::CertStores(CertStores&& other) = default;
TrustStoreWin::CertStores& TrustStoreWin::CertStores::operator=(
    CertStores&& other) = default;

// static
TrustStoreWin::CertStores
TrustStoreWin::CertStores::CreateInMemoryStoresForTesting() {
  TrustStoreWin::CertStores stores;
  stores.roots = crypto::ScopedHCERTSTORE(CertOpenStore(
      CERT_STORE_PROV_MEMORY, X509_ASN_ENCODING, NULL, 0, nullptr));
  stores.intermediates = crypto::ScopedHCERTSTORE(CertOpenStore(
      CERT_STORE_PROV_MEMORY, X509_ASN_ENCODING, NULL, 0, nullptr));
  stores.trusted_people = crypto::ScopedHCERTSTORE(CertOpenStore(
      CERT_STORE_PROV_MEMORY, X509_ASN_ENCODING, NULL, 0, nullptr));
  stores.disallowed = crypto::ScopedHCERTSTORE(CertOpenStore(
      CERT_STORE_PROV_MEMORY, X509_ASN_ENCODING, NULL, 0, nullptr));
  stores.InitializeAllCertsStore();
  return stores;
}

TrustStoreWin::CertStores
TrustStoreWin::CertStores::CreateNullStoresForTesting() {
  return TrustStoreWin::CertStores();
}

// static
TrustStoreWin::CertStores TrustStoreWin::CertStores::CreateWithCollections() {
  TrustStoreWin::CertStores stores;
  stores.roots = crypto::ScopedHCERTSTORE(
      CertOpenStore(CERT_STORE_PROV_COLLECTION, 0, NULL, 0, nullptr));
  stores.intermediates = crypto::ScopedHCERTSTORE(
      CertOpenStore(CERT_STORE_PROV_COLLECTION, 0, NULL, 0, nullptr));
  stores.trusted_people = crypto::ScopedHCERTSTORE(
      CertOpenStore(CERT_STORE_PROV_COLLECTION, 0, NULL, 0, nullptr));
  stores.disallowed = crypto::ScopedHCERTSTORE(
      CertOpenStore(CERT_STORE_PROV_COLLECTION, 0, NULL, 0, nullptr));
  stores.InitializeAllCertsStore();
  return stores;
}

void TrustStoreWin::CertStores::InitializeAllCertsStore() {
  all = crypto::ScopedHCERTSTORE(
      CertOpenStore(CERT_STORE_PROV_COLLECTION, 0, NULL, 0, nullptr));
  if (is_null()) {
    return;
  }
  // Add intermediate and root cert stores to the all_cert_store collection so
  // SyncGetIssuersOf will find them. disallowed_cert_store is not added
  // because the certs are distrusted; making them non-findable in
  // SyncGetIssuersOf helps us fail path-building faster.
  // `trusted_people` is not added because it can only contain end-entity
  // certs, so checking it for issuers during path building is not necessary.
  if (!CertAddStoreToCollection(all.get(), intermediates.get(),
                                /*dwUpdateFlags=*/0, /*dwPriority=*/0)) {
    return;
  }
  if (!CertAddStoreToCollection(all.get(), roots.get(),
                                /*dwUpdateFlags=*/0, /*dwPriority=*/0)) {
    return;
  }
}

class TrustStoreWin::Impl {
 public:
  // Creates a TrustStoreWin.
  Impl() {
    base::ScopedBlockingCall scoped_blocking_call(
        FROM_HERE, base::BlockingType::MAY_BLOCK);

    CertStores stores = CertStores::CreateWithCollections();
    if (stores.is_null()) {
      // If there was an error initializing the cert store collections, give
      // up. The Impl object will still be created but any calls to its public
      // methods will return no results.
      return;
    }

    // Grab the user-added roots.
    GatherEnterpriseCertsForLocation(stores.roots.get(),
                                     CERT_SYSTEM_STORE_LOCAL_MACHINE, L"ROOT");
    GatherEnterpriseCertsForLocation(
        stores.roots.get(), CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY,
        L"ROOT");
    GatherEnterpriseCertsForLocation(stores.roots.get(),
                                     CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE,
                                     L"ROOT");
    GatherEnterpriseCertsForLocation(stores.roots.get(),
                                     CERT_SYSTEM_STORE_CURRENT_USER, L"ROOT");
    GatherEnterpriseCertsForLocation(
        stores.roots.get(), CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY,
        L"ROOT");

    // Grab the user-added intermediates.
    GatherEnterpriseCertsForLocation(stores.intermediates.get(),
                                     CERT_SYSTEM_STORE_LOCAL_MACHINE, L"CA");
    GatherEnterpriseCertsForLocation(
        stores.intermediates.get(),
        CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY, L"CA");
    GatherEnterpriseCertsForLocation(stores.intermediates.get(),
                                     CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE,
                                     L"CA");
    GatherEnterpriseCertsForLocation(stores.intermediates.get(),
                                     CERT_SYSTEM_STORE_CURRENT_USER, L"CA");
    GatherEnterpriseCertsForLocation(
        stores.intermediates.get(), CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY,
        L"CA");

    // Grab the user-added trusted server certs. Trusted end-entity certs are
    // only allowed for server auth in the "local machine" store, but not in the
    // "current user" store.
    GatherEnterpriseCertsForLocation(stores.trusted_people.get(),
                                     CERT_SYSTEM_STORE_LOCAL_MACHINE,
                                     L"TrustedPeople");
    GatherEnterpriseCertsForLocation(
        stores.trusted_people.get(),
        CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY, L"TrustedPeople");
    GatherEnterpriseCertsForLocation(stores.trusted_people.get(),
                                     CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE,
                                     L"TrustedPeople");

    // Grab the user-added disallowed certs.
    GatherEnterpriseCertsForLocation(stores.disallowed.get(),
                                     CERT_SYSTEM_STORE_LOCAL_MACHINE,
                                     L"Disallowed");
    GatherEnterpriseCertsForLocation(
        stores.disallowed.get(), CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY,
        L"Disallowed");
    GatherEnterpriseCertsForLocation(stores.disallowed.get(),
                                     CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE,
                                     L"Disallowed");
    GatherEnterpriseCertsForLocation(
        stores.disallowed.get(), CERT_SYSTEM_STORE_CURRENT_USER, L"Disallowed");
    GatherEnterpriseCertsForLocation(
        stores.disallowed.get(), CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY,
        L"Disallowed");

    // Auto-sync all of the cert stores to get updates to the cert store.
    // Auto-syncing on all_certs_store seems to work to resync the nested
    // stores, although the docs at
    // https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certcontrolstore
    // are somewhat unclear. If and when root store changes are linked to
    // clearing various caches, this should be replaced with
    // CERT_STORE_CTRL_NOTIFY_CHANGE and CERT_STORE_CTRL_RESYNC.
    if (!CertControlStore(stores.all.get(), 0, CERT_STORE_CTRL_AUTO_RESYNC,
                          0) ||
        !CertControlStore(stores.trusted_people.get(), 0,
                          CERT_STORE_CTRL_AUTO_RESYNC, 0) ||
        !CertControlStore(stores.disallowed.get(), 0,
                          CERT_STORE_CTRL_AUTO_RESYNC, 0)) {
      PLOG(ERROR) << "Error enabling CERT_STORE_CTRL_AUTO_RESYNC";
    }

    root_cert_store_ = std::move(stores.roots);
    intermediate_cert_store_ = std::move(stores.intermediates);
    trusted_people_cert_store_ = std::move(stores.trusted_people);
    disallowed_cert_store_ = std::move(stores.disallowed);
    all_certs_store_ = std::move(stores.all);
  }

  Impl(CertStores stores)
      : root_cert_store_(std::move(stores.roots)),
        intermediate_cert_store_(std::move(stores.intermediates)),
        all_certs_store_(std::move(stores.all)),
        trusted_people_cert_store_(std::move(stores.trusted_people)),
        disallowed_cert_store_(std::move(stores.disallowed)) {}

  ~Impl() = default;
  Impl(const Impl& other) = delete;
  Impl& operator=(const Impl& other) = delete;

  void SyncGetIssuersOf(const bssl::ParsedCertificate* cert,
                        bssl::ParsedCertificateList* issuers) {
    if (!root_cert_store_.get() || !intermediate_cert_store_.get() ||
        !trusted_people_cert_store_.get() || !all_certs_store_.get() ||
        !disallowed_cert_store_.get()) {
      return;
    }
    base::span<const uint8_t> issuer_span = cert->issuer_tlv();

    CERT_NAME_BLOB cert_issuer_blob;
    cert_issuer_blob.cbData = static_cast<DWORD>(issuer_span.size());
    cert_issuer_blob.pbData = const_cast<uint8_t*>(issuer_span.data());

    PCCERT_CONTEXT cert_from_store = nullptr;
    while ((cert_from_store = CertFindCertificateInStore(
                all_certs_store_.get(), X509_ASN_ENCODING, 0,
                CERT_FIND_SUBJECT_NAME, &cert_issuer_blob, cert_from_store))) {
      bssl::UniquePtr<CRYPTO_BUFFER> der_crypto = x509_util::CreateCryptoBuffer(
          x509_util::CertContextAsSpan(cert_from_store));
      bssl::CertErrors errors;
      bssl::ParsedCertificate::CreateAndAddToVector(
          std::move(der_crypto), x509_util::DefaultParseCertificateOptions(),
          issuers, &errors);
    }
  }

  bssl::CertificateTrust GetTrust(const bssl::ParsedCertificate* cert) {
    if (!root_cert_store_.get() || !intermediate_cert_store_.get() ||
        !trusted_people_cert_store_.get() || !all_certs_store_.get() ||
        !disallowed_cert_store_.get()) {
      return bssl::CertificateTrust::ForUnspecified();
    }

    base::span<const uint8_t> cert_span = cert->der_cert();
    base::SHA1Digest cert_hash = base::SHA1Hash(cert_span);
    CRYPT_HASH_BLOB cert_hash_blob;
    cert_hash_blob.cbData = static_cast<DWORD>(cert_hash.size());
    cert_hash_blob.pbData = cert_hash.data();

    PCCERT_CONTEXT cert_from_store = nullptr;

    // Check Disallowed store first.
    while ((cert_from_store = CertFindCertificateInStore(
                disallowed_cert_store_.get(), X509_ASN_ENCODING, 0,
                CERT_FIND_SHA1_HASH, &cert_hash_blob, cert_from_store))) {
      base::span<const uint8_t> cert_from_store_span =
          x509_util::CertContextAsSpan(cert_from_store);
      // If a cert is in the windows distruted store, it is considered
      // distrusted for all purporses. EKU isn't checked. See crbug.com/1355961.
      if (base::ranges::equal(cert_span, cert_from_store_span)) {
        return bssl::CertificateTrust::ForDistrusted();
      }
    }

    while ((cert_from_store = CertFindCertificateInStore(
                root_cert_store_.get(), X509_ASN_ENCODING, 0,
                CERT_FIND_SHA1_HASH, &cert_hash_blob, cert_from_store))) {
      base::span<const uint8_t> cert_from_store_span =
          x509_util::CertContextAsSpan(cert_from_store);
      if (base::ranges::equal(cert_span, cert_from_store_span)) {
        // If we find at least one version of the cert that is trusted for TLS
        // Server Auth, we will trust the cert.
        if (IsCertTrustedForServerAuth(cert_from_store)) {
          return kRootCertTrust;
        }
      }
    }

    while ((cert_from_store = CertFindCertificateInStore(
                trusted_people_cert_store_.get(), X509_ASN_ENCODING, 0,
                CERT_FIND_SHA1_HASH, &cert_hash_blob, cert_from_store))) {
      base::span<const uint8_t> cert_from_store_span =
          x509_util::CertContextAsSpan(cert_from_store);
      if (base::ranges::equal(cert_span, cert_from_store_span)) {
        // If we find at least one version of the cert that is trusted for TLS
        // Server Auth, we will trust the cert.
        if (IsCertTrustedForServerAuth(cert_from_store)) {
          return kTrustedPeopleTrust;
        }
      }
    }

    // If we fall through here, we've either
    //
    // (a) found the cert but it is not usable for server auth. Treat this as
    //     Unspecified trust. Originally this was treated as Distrusted, but
    //     this is inconsistent with how the Windows verifier works, which is to
    //     union all of the EKU usages for all instances of the cert, whereas
    //     sending back Distrusted would not do that.
    //
    // or
    //
    // (b) Haven't found the cert. Tell everyone Unspecified.
    return bssl::CertificateTrust::ForUnspecified();
  }

  std::vector<net::PlatformTrustStore::CertWithTrust> GetAllUserAddedCerts() {
    std::vector<net::PlatformTrustStore::CertWithTrust> certs;
    if (!root_cert_store_.get() || !intermediate_cert_store_.get() ||
        !trusted_people_cert_store_.get() || !all_certs_store_.get() ||
        !disallowed_cert_store_.get()) {
      return certs;
    }

    PCCERT_CONTEXT cert_from_store = nullptr;
    while ((cert_from_store = CertEnumCertificatesInStore(
                disallowed_cert_store_.get(), cert_from_store))) {
      AddCertWithTrust(cert_from_store, bssl::CertificateTrust::ForDistrusted(),
                       &certs);
    }

    while ((cert_from_store = CertEnumCertificatesInStore(
                trusted_people_cert_store_.get(), cert_from_store))) {
      if (IsCertTrustedForServerAuth(cert_from_store)) {
        AddCertWithTrust(cert_from_store, kTrustedPeopleTrust, &certs);
      }
    }

    while ((cert_from_store = CertEnumCertificatesInStore(
                root_cert_store_.get(), cert_from_store))) {
      if (IsCertTrustedForServerAuth(cert_from_store)) {
        AddCertWithTrust(cert_from_store, kRootCertTrust, &certs);
      }
    }

    while ((cert_from_store = CertEnumCertificatesInStore(
                intermediate_cert_store_.get(), cert_from_store))) {
      AddCertWithTrust(cert_from_store,
                       bssl::CertificateTrust::ForUnspecified(), &certs);
    }

    return certs;
  }

 private:
  // Cert Collection containing all user-added trust anchors.
  crypto::ScopedHCERTSTORE root_cert_store_;

  // Cert Collection containing all user-added intermediates.
  crypto::ScopedHCERTSTORE intermediate_cert_store_;

  // Cert Collection for searching via SyncGetIssuersOf()
  crypto::ScopedHCERTSTORE all_certs_store_;

  // Cert Collection containing all user-added trust leafs.
  crypto::ScopedHCERTSTORE trusted_people_cert_store_;

  // Cert Collection for all disallowed certs.
  crypto::ScopedHCERTSTORE disallowed_cert_store_;
};

// TODO(crbug.com/40784681): support CTLs.
TrustStoreWin::TrustStoreWin() = default;

void TrustStoreWin::InitializeStores() {
  // Don't need return value
  MaybeInitializeAndGetImpl();
}

TrustStoreWin::Impl* TrustStoreWin::MaybeInitializeAndGetImpl() {
  base::AutoLock lock(init_lock_);
  if (!impl_) {
    impl_ = std::make_unique<TrustStoreWin::Impl>();
  }
  return impl_.get();
}

std::unique_ptr<TrustStoreWin> TrustStoreWin::CreateForTesting(
    CertStores stores) {
  return base::WrapUnique(new TrustStoreWin(
      std::make_unique<TrustStoreWin::Impl>(std::move(stores))));
}

TrustStoreWin::TrustStoreWin(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}

TrustStoreWin::~TrustStoreWin() = default;

void TrustStoreWin::SyncGetIssuersOf(const bssl::ParsedCertificate* cert,
                                     bssl::ParsedCertificateList* issuers) {
  MaybeInitializeAndGetImpl()->SyncGetIssuersOf(cert, issuers);
}

// As documented in IsCertTrustedForServerAuth(), on Windows, the
// set of extended key usages present in a certificate can be further
// scoped down by user setting; effectively, disabling a given EKU for
// a given intermediate or root.
//
// Windows uses this during path building when filtering the EKUs; if it
// encounters this property, it uses the combined EKUs to determine
// whether to continue path building, but doesn't treat the certificate
// as affirmatively revoked/distrusted.
//
// This behaviour is replicated here by returning Unspecified trust if
// we find instances of the cert that do not have the correct EKUs set
// for TLS Server Auth. This allows path building to continue and allows
// us to later trust the cert if it is present in Chrome Root Store.
//
// Windows does have some idiosyncrasies here, which result in the
// following treatment:
//
//   - If a certificate is in the Disallowed store, it is distrusted for
//     all purposes regardless of any EKUs that are set.
//   - If a certificate is in the ROOT store, and usable for TLS Server Auth,
//     then it's trusted.
//   - If a certificate is in the root store, and lacks the EKU, then continue
//     path building, but don't treat it as trusted (aka Unspecified).
//   - If we can't find the cert anywhere, then continue path
//     building, but don't treat it as trusted (aka Unspecified).
//
// If a certificate is found multiple times in the ROOT store, it is trusted
// for TLS server auth if any instance of the certificate found
// is usable for TLS server auth.
bssl::CertificateTrust TrustStoreWin::GetTrust(
    const bssl::ParsedCertificate* cert) {
  return MaybeInitializeAndGetImpl()->GetTrust(cert);
}

std::vector<net::PlatformTrustStore::CertWithTrust>
TrustStoreWin::GetAllUserAddedCerts() {
  return MaybeInitializeAndGetImpl()->GetAllUserAddedCerts();
}

}  // namespace net
```