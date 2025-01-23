Response:
Let's break down the thought process for analyzing this `nss_cert_database.cc` file.

**1. Initial Reading and Identifying the Core Purpose:**

The first step is to read through the code, paying attention to the class name (`NSSCertDatabase`), included headers, and key functions. Keywords like "cert," "trust," "PKCS12," "slot," and "NSS" immediately stand out. The `#include` directives confirm the interaction with NSS (Network Security Services) libraries. The class name itself strongly suggests it's responsible for managing certificates within an NSS database.

**2. Deconstructing Functionality by Category:**

Instead of trying to understand every line at once, it's better to group functions by their apparent purpose. Looking at the public methods provides a good starting point:

* **Listing Certificates:** `ListCerts`, `ListCertsInSlot`, `ListCertsInfo`. These clearly deal with retrieving certificate information.
* **Accessing Slots:** `GetPublicSlot`, `GetPrivateSlot`, `ListModules`. These manage access to the underlying NSS key storage locations.
* **Trust Management:** `SetCertTrust`, `GetCertTrust`, `IsUntrusted`, `IsWebTrustAnchor`. These are central to the file's role in managing certificate validity and trust.
* **Import/Export:** `ImportFromPKCS12`, `ExportToPKCS12`, `ImportUserCert`, `ImportCACerts`, `ImportServerCert`. This deals with moving certificates in and out of the database.
* **Deletion:** `DeleteCertAndKey`, `DeleteCertAndKeyAsync`. This concerns removing certificates.
* **Properties:** `IsReadOnly`, `IsHardwareBacked`. These provide metadata about certificates.
* **Observers:** `AddObserver`, `RemoveObserver`. This suggests a mechanism for notifying other parts of the system about changes.

**3. Examining Key Implementation Details within Categories:**

Once the broad categories are identified, delve into the implementation of representative functions within each category.

* **Listing:** Notice the use of `base::ThreadPool::PostTaskAndReplyWithResult`. This indicates asynchronous operations, important for UI responsiveness. The `ListCertsInfoImpl` function is the core logic, and its `NSSRootsHandling` parameter hints at different ways of listing certificates (including/excluding system roots).
* **Trust Management:**  The code interacts with `psm::SetCertTrust` and `CERT_GetCertTrust`, clearly delegating to NSS for trust decisions. The logic in `IsUntrusted` and `IsWebTrustAnchor` directly manipulates the `CERTCertTrust` structure.
* **Import/Export:** The code leverages Mozilla's `nsPKCS12Blob` for PKCS12 operations. Different `Import...` functions target different certificate types (user, CA, server).
* **Deletion:** The `DeleteCertAndKeyImpl` function checks for the presence of a private key, implying a distinction between client certificates and other types.

**4. Identifying Relationships with JavaScript (and Web Browsing):**

Now, consider how these functions relate to the user's web browsing experience and potentially JavaScript.

* **HTTPS/TLS:** The entire purpose of certificate management is foundational for HTTPS. JavaScript making secure requests relies on the browser's ability to validate server certificates.
* **Client Certificates:** Websites might require client certificates for authentication. The `ImportFromPKCS12`, `ImportUserCert`, and listing functions are relevant here. JavaScript might trigger a client certificate selection dialog.
* **Certificate Errors:**  If a certificate is deemed "untrusted" (based on `IsUntrusted`), the browser will display an error page, often impacting JavaScript functionality on that page.
* **Web Crypto API:** While not directly calling these functions, the Web Crypto API in JavaScript relies on the browser's underlying certificate management for tasks like signing and verifying data.

**5. Considering Logical Inference and Assumptions:**

Look for places where the code makes assumptions or performs logical deductions. The `FindRootInList` function is a good example. It assumes a certain ordering of certificates in a chain. The logic in `IsUntrusted` regarding self-signed certificates is another example of a specific rule. Formulating input/output scenarios helps clarify these inferences.

**6. Identifying Potential User/Programming Errors:**

Think about how users or developers might misuse this functionality or encounter errors.

* **Incorrect Passwords:**  `ImportFromPKCS12` failing due to a wrong password is a common user error.
* **Corrupted PKCS12 Files:** The import might fail if the data is invalid.
* **Missing Dependencies:**  NSS relies on shared libraries. Runtime errors can occur if these are missing or misconfigured.
* **Incorrect Trust Settings:**  Manually setting incorrect trust flags could lead to unexpected behavior.

**7. Tracing User Actions (Debugging):**

Consider how a user's actions might lead to this code being executed.

* **Visiting an HTTPS Website:** This is the most common path, triggering certificate validation.
* **Importing Certificates:**  Users might import certificates through browser settings.
* **Responding to Client Certificate Requests:** Websites might prompt the user to select a certificate.
* **Encountering Certificate Errors:** This signals that the certificate validation process (involving this code) has failed.

**8. Iterative Refinement:**

The process isn't strictly linear. As you analyze one part, you might gain insights that help understand another. For example, understanding the observer pattern helps explain how changes in the NSS database are propagated. You might revisit earlier assumptions or conclusions as you learn more.

**Self-Correction Example During Analysis:**

Initially, I might focus too much on the low-level NSS details. However, when considering the relationship with JavaScript, I realize the importance of the higher-level concepts like HTTPS, client certificates, and the Web Crypto API, even though JavaScript doesn't directly call these C++ functions. This shifts the focus to how this C++ code *enables* those JavaScript functionalities. Similarly, when looking at error conditions, thinking from the user's perspective ("what could the user do wrong?") is more effective than just focusing on potential low-level NSS errors.
好的，我们来分析一下 `net/cert/nss_cert_database.cc` 这个 Chromium 网络栈的源代码文件。

**文件功能概述：**

`nss_cert_database.cc` 文件实现了 `NSSCertDatabase` 类，这个类是 Chromium 中与 Network Security Services (NSS) 交互的核心组件，负责管理和操作证书数据库。其主要功能包括：

1. **证书列表管理:**
   - 列出所有可用的证书，可以指定列出特定插槽 (slot) 中的证书。
   - 获取证书的详细信息，包括是否受信任、是否为 Web Trust Anchor、是否只读、是否由硬件支持等。

2. **信任管理:**
   - 设置证书的信任状态 (Trusted, Distrusted, Default)，用于不同的目的 (SSL, Email, Object Signing)。
   - 查询证书的信任状态。
   - 判断证书是否被标记为不受信任。
   - 判断证书是否为 Web Trust Anchor (根证书)。

3. **证书导入和导出:**
   - 从 PKCS#12 文件导入证书和私钥。
   - 导出证书到 PKCS#12 文件。
   - 导入用户证书、CA 证书和服务器证书。

4. **证书删除:**
   - 删除证书及其关联的私钥。

5. **插槽 (Slot) 管理:**
   - 获取公有和私有插槽。
   - 列出所有可用的安全模块 (modules)。

6. **观察者模式:**
   - 提供观察者机制，允许其他组件监听证书数据库的变化 (例如信任状态或客户端证书存储的变化)。

**与 JavaScript 功能的关系及举例：**

`NSSCertDatabase` 本身是用 C++ 实现的，JavaScript 代码无法直接调用它。但是，它为 Chromium 的网络栈提供了证书管理的基础设施，而这个基础设施直接影响着 JavaScript 在浏览器中的行为，尤其是在处理 HTTPS 连接和需要客户端证书的场景中。

**举例说明：**

1. **HTTPS 连接的证书验证:**
   - 当 JavaScript 代码发起一个 HTTPS 请求时 (例如使用 `fetch` 或 `XMLHttpRequest`)，Chromium 的网络栈会使用 `NSSCertDatabase` 来验证服务器返回的 SSL 证书是否受信任。
   - `IsUntrusted` 和 `IsWebTrustAnchor` 等函数会被调用来判断证书的有效性。
   - **假设输入：** 服务器返回一个证书链。
   - **输出：** `NSSCertDatabase` 判断该证书链是否可以追溯到一个受信任的根证书，并返回验证结果。如果证书不受信任，JavaScript 代码可能会收到一个网络错误，导致请求失败。

2. **客户端证书身份验证:**
   - 某些网站可能需要客户端证书进行身份验证。
   - 当网站要求客户端证书时，浏览器会调用 `NSSCertDatabase` 列出可用的客户端证书 (`ListCerts`)，并显示给用户选择。
   - 用户选择证书后，`NSSCertDatabase` 会提供该证书用于身份验证过程。
   - **假设输入：** 网站请求客户端证书认证。
   - **输出：** 浏览器显示一个包含 `NSSCertDatabase` 中客户端证书的列表供用户选择。用户选择证书后，该证书用于与服务器建立安全连接。

3. **Web Crypto API:**
   - 虽然 JavaScript 的 Web Crypto API 不直接调用 `NSSCertDatabase` 的方法，但其底层的密钥存储和证书管理可能依赖于 `NSSCertDatabase` (尤其是在 Chromium 中使用 NSS 作为加密库的情况下)。
   - 例如，当使用 Web Crypto API 生成或导入密钥对时，这些密钥可能存储在 NSS 管理的插槽中。

**逻辑推理及假设输入与输出：**

让我们以 `IsUntrusted` 函数为例进行逻辑推理：

**假设输入：**

- 一个 `CERTCertificate*` 指向一个特定的证书。

**逻辑推理：**

1. `CERT_GetCertTrust` 函数被调用以获取证书的 NSS 信任状态 (`CERTCertTrust`).
2. 检查 `nsstrust.sslFlags`、`nsstrust.emailFlags` 和 `nsstrust.objectSigningFlags` 中的 `CERTDB_TERMINAL_RECORD` 位。如果设置了该位，表示存在显式的信任或不信任记录。
3. 如果 `CERTDB_TERMINAL_RECORD` 被设置，则进一步检查 `CERTDB_TRUSTED_CA` 和 `CERTDB_TRUSTED` 位。如果这两个位都没有设置，则认为该证书被显式地不信任。
4. 如果没有设置 `CERTDB_TERMINAL_RECORD`，则检查证书是否是自签名的 (Issuer 和 Subject 相同)。
5. 如果是自签名的，则检查是否设置了任何信任位 (`CERTDB_TRUSTED_CA` 或 `CERTDB_TRUSTED`)。如果没有设置，则认为该自签名证书不受信任。
6. 如果不是自签名的，且没有显式的不信任记录，则认为该证书可能可以通过信任链被信任。

**输出：**

- `true`：如果证书被判断为不受信任。
- `false`：如果证书被判断为可能受信任。

**用户或编程常见的使用错误及举例：**

1. **用户错误：导入错误的 PKCS#12 文件或使用错误的密码。**
   - 用户可能尝试导入一个损坏的 PKCS#12 文件，或者在导入时输入了错误的密码。
   - 这会导致 `ImportFromPKCS12` 函数返回错误代码，例如 `SEC_ERROR_BAD_PASSWORD` 或 `SEC_ERROR_PKCS12_PBE_UNSUPPORTED`。

2. **用户错误：手动修改 NSS 数据库导致不一致的状态。**
   - 用户可能使用第三方工具或其他方法直接修改 NSS 数据库，这可能导致证书的信任状态与 Chromium 的预期不符，引发安全问题或程序崩溃。

3. **编程错误：在多线程环境下不正确地使用 `NSSCertDatabase` 的方法。**
   - 许多 NSS 的函数不是线程安全的。如果开发者在多线程环境下不进行适当的同步，可能会导致数据竞争和未定义的行为。Chromium 使用线程池来执行某些操作，例如列出证书，这需要注意线程安全。

4. **编程错误：忘记处理 `ImportCertFailureList`。**
   - 在导入 CA 证书或服务器证书时，某些证书可能因为各种原因导入失败。开发者应该检查 `ImportCertFailureList` 以了解哪些证书未导入，并进行适当的处理。

**用户操作如何一步步到达这里，作为调试线索：**

以下是一些用户操作可能触发 `nss_cert_database.cc` 中代码执行的场景：

1. **访问 HTTPS 网站：**
   - 用户在地址栏输入一个以 `https://` 开头的网址并按下回车。
   - Chromium 的网络栈开始与服务器建立 TLS 连接。
   - 在 TLS 握手过程中，服务器会提供其 SSL 证书。
   - Chromium 的网络栈会调用 `NSSCertDatabase` 中的函数 (例如 `IsUntrusted`) 来验证该证书的有效性和信任状态。

2. **导入证书：**
   - 用户在 Chromium 的设置中 (例如 "隐私设置和安全性" -> "管理证书")，点击 "导入" 按钮。
   - 浏览器会弹出一个文件选择对话框，用户选择一个 PKCS#12 文件或其他格式的证书文件。
   - 当用户提供文件和密码后，Chromium 会调用 `NSSCertDatabase` 中的 `ImportFromPKCS12` 或其他导入函数。

3. **处理客户端证书请求：**
   - 用户访问一个需要客户端证书进行身份验证的网站。
   - 网站的服务器会发起一个客户端证书请求。
   - Chromium 会调用 `NSSCertDatabase` 中的 `ListCerts` 来获取用户可用的客户端证书，并显示一个选择对话框。

4. **查看证书信息：**
   - 用户在 Chromium 的设置中查看已安装的证书信息。
   - 浏览器会调用 `NSSCertDatabase` 中的 `ListCertsInfo` 来获取证书的详细信息并显示给用户。

5. **手动修改证书信任设置：**
   - 用户在 Chromium 的证书管理界面中，可以手动更改某个证书的信任设置 (例如，将某个 CA 证书标记为不受信任)。
   - 这会触发 `NSSCertDatabase` 中的 `SetCertTrust` 函数。

作为调试线索，当出现与证书相关的问题时，例如 HTTPS 连接失败、客户端证书选择问题或证书导入错误，开发者可以：

- **设置断点：** 在 `nss_cert_database.cc` 中的关键函数 (如 `IsUntrusted`, `ImportFromPKCS12`, `SetCertTrust`) 设置断点，跟踪代码执行流程，查看传入的证书数据和信任状态。
- **查看日志：** Chromium 的日志系统 (例如 `chrome://net-internals/#events`) 可能会记录与证书相关的事件和错误信息。
- **使用 NSS 工具：** 可以使用 NSS 提供的命令行工具 (例如 `certutil`) 来检查底层的 NSS 数据库状态，验证 Chromium 的行为是否与 NSS 数据库的状态一致。

希望以上分析能够帮助你理解 `net/cert/nss_cert_database.cc` 文件的功能以及它与 JavaScript 交互的方式。

### 提示词
```
这是目录为net/cert/nss_cert_database.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/cert/nss_cert_database.h"

#include <cert.h>
#include <certdb.h>
#include <certt.h>
#include <dlfcn.h>
#include <keyhi.h>
#include <pk11pub.h>
#include <secmod.h>

#include <memory>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/observer_list_threadsafe.h"
#include "base/task/thread_pool.h"
#include "base/threading/scoped_blocking_call.h"
#include "build/build_config.h"
#include "build/chromeos_buildflags.h"
#include "crypto/nss_util_internal.h"
#include "crypto/scoped_nss_types.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_database.h"
#include "net/cert/internal/trust_store_nss.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util_nss.h"
#include "net/third_party/mozilla_security_manager/nsNSSCertificateDB.h"
#include "net/third_party/mozilla_security_manager/nsPKCS12Blob.h"

#if BUILDFLAG(IS_CHROMEOS_ASH) || BUILDFLAG(IS_CHROMEOS_LACROS)
#include "crypto/chaps_support.h"
#endif

// PSM = Mozilla's Personal Security Manager.
namespace psm = mozilla_security_manager;

namespace net {

namespace {

using PK11HasAttributeSetFunction = CK_BBOOL (*)(PK11SlotInfo* slot,
                                                 CK_OBJECT_HANDLE id,
                                                 CK_ATTRIBUTE_TYPE type,
                                                 PRBool haslock);

// TODO(pneubeck): Move this class out of NSSCertDatabase and to the caller of
// the c'tor of NSSCertDatabase, see https://crbug.com/395983 .
// Helper that observes events from the NSSCertDatabase and forwards them to
// the given CertDatabase.
class CertNotificationForwarder : public NSSCertDatabase::Observer {
 public:
  explicit CertNotificationForwarder(CertDatabase* cert_db)
      : cert_db_(cert_db) {}

  CertNotificationForwarder(const CertNotificationForwarder&) = delete;
  CertNotificationForwarder& operator=(const CertNotificationForwarder&) =
      delete;

  ~CertNotificationForwarder() override = default;

  void OnTrustStoreChanged() override {
    cert_db_->NotifyObserversTrustStoreChanged();
  }
  void OnClientCertStoreChanged() override {
    cert_db_->NotifyObserversClientCertStoreChanged();
  }

 private:
  raw_ptr<CertDatabase> cert_db_;
};

// TODO(crbug.com/40890963): once the other IsUntrusted impl is deleted,
// rename this.
bool IsUntrustedUsingTrustStore(const CERTCertificate* cert,
                                bssl::CertificateTrust trust) {
  if (trust.IsDistrusted()) {
    return true;
  }

  // Self-signed certificates that don't have any trust bits set are untrusted.
  // Other certificates that don't have any trust bits set may still be trusted
  // if they chain up to a trust anchor.
  // TODO(mattm): this is weird, but just match the behavior of the existing
  // IsUntrusted function for now.
  if (SECITEM_CompareItem(&cert->derIssuer, &cert->derSubject) == SECEqual) {
    return !trust.IsTrustAnchor();
  }

  return false;
}

}  // namespace

NSSCertDatabase::CertInfo::CertInfo() = default;
NSSCertDatabase::CertInfo::CertInfo(CertInfo&& other) = default;
NSSCertDatabase::CertInfo::~CertInfo() = default;
NSSCertDatabase::CertInfo& NSSCertDatabase::CertInfo::operator=(
    NSSCertDatabase::CertInfo&& other) = default;

NSSCertDatabase::ImportCertFailure::ImportCertFailure(
    ScopedCERTCertificate cert,
    int err)
    : certificate(std::move(cert)), net_error(err) {}

NSSCertDatabase::ImportCertFailure::ImportCertFailure(
    ImportCertFailure&& other) = default;

NSSCertDatabase::ImportCertFailure::~ImportCertFailure() = default;

NSSCertDatabase::NSSCertDatabase(crypto::ScopedPK11Slot public_slot,
                                 crypto::ScopedPK11Slot private_slot)
    : public_slot_(std::move(public_slot)),
      private_slot_(std::move(private_slot)),
      observer_list_(
          base::MakeRefCounted<base::ObserverListThreadSafe<Observer>>()) {
  CHECK(public_slot_);

  CertDatabase* cert_db = CertDatabase::GetInstance();
  cert_notification_forwarder_ =
      std::make_unique<CertNotificationForwarder>(cert_db);
  AddObserver(cert_notification_forwarder_.get());

  psm::EnsurePKCS12Init();
}

NSSCertDatabase::~NSSCertDatabase() = default;

void NSSCertDatabase::ListCerts(ListCertsCallback callback) {
  base::ThreadPool::PostTaskAndReplyWithResult(
      FROM_HERE,
      {base::MayBlock(), base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
      base::BindOnce(&NSSCertDatabase::ListCertsImpl, crypto::ScopedPK11Slot()),
      std::move(callback));
}

void NSSCertDatabase::ListCertsInSlot(ListCertsCallback callback,
                                      PK11SlotInfo* slot) {
  DCHECK(slot);
  base::ThreadPool::PostTaskAndReplyWithResult(
      FROM_HERE,
      {base::MayBlock(), base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
      base::BindOnce(&NSSCertDatabase::ListCertsImpl,
                     crypto::ScopedPK11Slot(PK11_ReferenceSlot(slot))),
      std::move(callback));
}

void NSSCertDatabase::ListCertsInfo(ListCertsInfoCallback callback,
                                    NSSRootsHandling nss_roots_handling) {
  base::ThreadPool::PostTaskAndReplyWithResult(
      FROM_HERE,
      {base::MayBlock(), base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
      base::BindOnce(&NSSCertDatabase::ListCertsInfoImpl,
                     /*slot=*/nullptr,
                     /*add_certs_info=*/true, nss_roots_handling),
      std::move(callback));
}

#if BUILDFLAG(IS_CHROMEOS)
crypto::ScopedPK11Slot NSSCertDatabase::GetSystemSlot() const {
  return crypto::ScopedPK11Slot();
}

// static
bool NSSCertDatabase::IsCertificateOnSlot(CERTCertificate* cert,
                                          PK11SlotInfo* slot) {
  if (!slot)
    return false;

  return PK11_FindCertInSlot(slot, cert, nullptr) != CK_INVALID_HANDLE;
}
#endif  // BUILDFLAG(IS_CHROMEOS)

crypto::ScopedPK11Slot NSSCertDatabase::GetPublicSlot() const {
  return crypto::ScopedPK11Slot(PK11_ReferenceSlot(public_slot_.get()));
}

crypto::ScopedPK11Slot NSSCertDatabase::GetPrivateSlot() const {
  if (!private_slot_)
    return crypto::ScopedPK11Slot();
  return crypto::ScopedPK11Slot(PK11_ReferenceSlot(private_slot_.get()));
}

void NSSCertDatabase::ListModules(std::vector<crypto::ScopedPK11Slot>* modules,
                                  bool need_rw) const {
  modules->clear();

  // The wincx arg is unused since we don't call PK11_SetIsLoggedInFunc.
  crypto::ScopedPK11SlotList slot_list(
      PK11_GetAllTokens(CKM_INVALID_MECHANISM,
                        need_rw ? PR_TRUE : PR_FALSE,  // needRW
                        PR_TRUE,                       // loadCerts (unused)
                        nullptr));                     // wincx
  if (!slot_list) {
    LOG(ERROR) << "PK11_GetAllTokens failed: " << PORT_GetError();
    return;
  }

  PK11SlotListElement* slot_element = PK11_GetFirstSafe(slot_list.get());
  while (slot_element) {
    modules->push_back(
        crypto::ScopedPK11Slot(PK11_ReferenceSlot(slot_element->slot)));
    slot_element = PK11_GetNextSafe(slot_list.get(), slot_element,
                                    PR_FALSE);  // restart
  }
}

bool NSSCertDatabase::SetCertTrust(CERTCertificate* cert,
                                   CertType type,
                                   TrustBits trust_bits) {
  bool success = psm::SetCertTrust(cert, type, trust_bits);
  if (success) {
    NotifyObserversTrustStoreChanged();
  }

  return success;
}

int NSSCertDatabase::ImportFromPKCS12(
    PK11SlotInfo* slot_info,
    const std::string& data,
    const std::u16string& password,
    bool is_extractable,
    ScopedCERTCertificateList* imported_certs) {
  int result =
      psm::nsPKCS12Blob_Import(slot_info, data.data(), data.size(), password,
                               is_extractable, imported_certs);
  if (result == OK) {
    NotifyObserversClientCertStoreChanged();
  }

  return result;
}

// static
int NSSCertDatabase::ExportToPKCS12(const ScopedCERTCertificateList& certs,
                                    const std::u16string& password,
                                    std::string* output) {
  return psm::nsPKCS12Blob_Export(output, certs, password);
}

CERTCertificate* NSSCertDatabase::FindRootInList(
    const ScopedCERTCertificateList& certificates) const {
  DCHECK_GT(certificates.size(), 0U);

  if (certificates.size() == 1)
    return certificates[0].get();

  CERTCertificate* cert0 = certificates[0].get();
  CERTCertificate* cert1 = certificates[1].get();
  CERTCertificate* certn_2 = certificates[certificates.size() - 2].get();
  CERTCertificate* certn_1 = certificates[certificates.size() - 1].get();

  // Using CERT_CompareName is an alternative, except that it is broken until
  // NSS 3.32 (see https://bugzilla.mozilla.org/show_bug.cgi?id=1361197 ).
  if (SECITEM_CompareItem(&cert1->derIssuer, &cert0->derSubject) == SECEqual)
    return cert0;

  if (SECITEM_CompareItem(&certn_2->derIssuer, &certn_1->derSubject) ==
      SECEqual) {
    return certn_1;
  }

  LOG(WARNING) << "certificate list is not a hierarchy";
  return cert0;
}

int NSSCertDatabase::ImportUserCert(const std::string& data) {
  ScopedCERTCertificateList certificates =
      x509_util::CreateCERTCertificateListFromBytes(
          base::as_byte_span(data), net::X509Certificate::FORMAT_AUTO);
  if (certificates.empty())
    return ERR_CERT_INVALID;

  int result = psm::ImportUserCert(certificates[0].get(), GetPublicSlot());

  if (result == OK) {
    NotifyObserversClientCertStoreChanged();
  }

  return result;
}

int NSSCertDatabase::ImportUserCert(CERTCertificate* cert) {
  int result = psm::ImportUserCert(cert, GetPublicSlot());

  if (result == OK) {
    NotifyObserversClientCertStoreChanged();
  }

  return result;
}

bool NSSCertDatabase::ImportCACerts(
    const ScopedCERTCertificateList& certificates,
    TrustBits trust_bits,
    ImportCertFailureList* not_imported) {
  crypto::ScopedPK11Slot slot(GetPublicSlot());
  CERTCertificate* root = FindRootInList(certificates);

  bool success = psm::ImportCACerts(slot.get(), certificates, root, trust_bits,
                                    not_imported);
  if (success) {
    NotifyObserversTrustStoreChanged();
  }

  return success;
}

bool NSSCertDatabase::ImportServerCert(
    const ScopedCERTCertificateList& certificates,
    TrustBits trust_bits,
    ImportCertFailureList* not_imported) {
  crypto::ScopedPK11Slot slot(GetPublicSlot());
  return psm::ImportServerCert(slot.get(), certificates, trust_bits,
                               not_imported);
  // TODO(mattm): should generate OnTrustStoreChanged notification? The ability
  // to set a server cert as trusted isn't hooked up anywhere currently, but
  // technically we should generate a notification.
}

NSSCertDatabase::TrustBits NSSCertDatabase::GetCertTrust(
    const CERTCertificate* cert,
    CertType type) const {
  CERTCertTrust trust;
  SECStatus srv = CERT_GetCertTrust(cert, &trust);
  if (srv != SECSuccess) {
    LOG(ERROR) << "CERT_GetCertTrust failed with error " << PORT_GetError();
    return TRUST_DEFAULT;
  }
  // We define our own more "friendly" TrustBits, which means we aren't able to
  // round-trip all possible NSS trust flag combinations.  We try to map them in
  // a sensible way.
  switch (type) {
    case CA_CERT: {
      const unsigned kTrustedCA = CERTDB_TRUSTED_CA | CERTDB_TRUSTED_CLIENT_CA;
      const unsigned kCAFlags = kTrustedCA | CERTDB_TERMINAL_RECORD;

      TrustBits trust_bits = TRUST_DEFAULT;
      if ((trust.sslFlags & kCAFlags) == CERTDB_TERMINAL_RECORD)
        trust_bits |= DISTRUSTED_SSL;
      else if (trust.sslFlags & kTrustedCA)
        trust_bits |= TRUSTED_SSL;

      if ((trust.emailFlags & kCAFlags) == CERTDB_TERMINAL_RECORD)
        trust_bits |= DISTRUSTED_EMAIL;
      else if (trust.emailFlags & kTrustedCA)
        trust_bits |= TRUSTED_EMAIL;

      if ((trust.objectSigningFlags & kCAFlags) == CERTDB_TERMINAL_RECORD)
        trust_bits |= DISTRUSTED_OBJ_SIGN;
      else if (trust.objectSigningFlags & kTrustedCA)
        trust_bits |= TRUSTED_OBJ_SIGN;

      return trust_bits;
    }
    case SERVER_CERT:
      if (trust.sslFlags & CERTDB_TERMINAL_RECORD) {
        if (trust.sslFlags & CERTDB_TRUSTED)
          return TRUSTED_SSL;
        return DISTRUSTED_SSL;
      }
      return TRUST_DEFAULT;
    default:
      return TRUST_DEFAULT;
  }
}

bool NSSCertDatabase::DeleteCertAndKey(CERTCertificate* cert) {
  // This makes the assumption that if there was a matching private key, the
  // cert was probably a client cert, and if not, it may have been a trust
  // anchor or intemediate CA cert. This is used as a simple approximation as
  // otherwise this requires checking and combining multiple things
  // (basicConstraints if present, trust settings, etc).
  switch (DeleteCertAndKeyImpl(cert)) {
    case DeleteCertAndKeyResult::OK_NO_KEY:
      NotifyObserversTrustStoreChanged();
      return true;
    case DeleteCertAndKeyResult::OK_FOUND_KEY:
      NotifyObserversClientCertStoreChanged();
      return true;
    case DeleteCertAndKeyResult::ERROR:
      return false;
  }
}

void NSSCertDatabase::DeleteCertAndKeyAsync(ScopedCERTCertificate cert,
                                            DeleteCertCallback callback) {
  base::ThreadPool::PostTaskAndReplyWithResult(
      FROM_HERE,
      {base::MayBlock(), base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
      base::BindOnce(&NSSCertDatabase::DeleteCertAndKeyImplScoped,
                     std::move(cert)),
      base::BindOnce(&NSSCertDatabase::NotifyCertRemovalAndCallBack,
                     weak_factory_.GetWeakPtr(), std::move(callback)));
}

// static
bool NSSCertDatabase::IsUntrusted(const CERTCertificate* cert) {
  CERTCertTrust nsstrust;
  SECStatus rv = CERT_GetCertTrust(cert, &nsstrust);
  if (rv != SECSuccess) {
    LOG(ERROR) << "CERT_GetCertTrust failed with error " << PORT_GetError();
    return false;
  }

  // The CERTCertTrust structure contains three trust records:
  // sslFlags, emailFlags, and objectSigningFlags.  The three
  // trust records are independent of each other.
  //
  // If the CERTDB_TERMINAL_RECORD bit in a trust record is set,
  // then that trust record is a terminal record.  A terminal
  // record is used for explicit trust and distrust of an
  // end-entity or intermediate CA cert.
  //
  // In a terminal record, if neither CERTDB_TRUSTED_CA nor
  // CERTDB_TRUSTED is set, then the terminal record means
  // explicit distrust.  On the other hand, if the terminal
  // record has either CERTDB_TRUSTED_CA or CERTDB_TRUSTED bit
  // set, then the terminal record means explicit trust.
  //
  // For a root CA, the trust record does not have
  // the CERTDB_TERMINAL_RECORD bit set.

  static const unsigned int kTrusted = CERTDB_TRUSTED_CA | CERTDB_TRUSTED;
  if ((nsstrust.sslFlags & CERTDB_TERMINAL_RECORD) != 0 &&
      (nsstrust.sslFlags & kTrusted) == 0) {
    return true;
  }
  if ((nsstrust.emailFlags & CERTDB_TERMINAL_RECORD) != 0 &&
      (nsstrust.emailFlags & kTrusted) == 0) {
    return true;
  }
  if ((nsstrust.objectSigningFlags & CERTDB_TERMINAL_RECORD) != 0 &&
      (nsstrust.objectSigningFlags & kTrusted) == 0) {
    return true;
  }

  // Self-signed certificates that don't have any trust bits set are untrusted.
  // Other certificates that don't have any trust bits set may still be trusted
  // if they chain up to a trust anchor.
  if (SECITEM_CompareItem(&cert->derIssuer, &cert->derSubject) == SECEqual) {
    return (nsstrust.sslFlags & kTrusted) == 0 &&
           (nsstrust.emailFlags & kTrusted) == 0 &&
           (nsstrust.objectSigningFlags & kTrusted) == 0;
  }

  return false;
}

// static
bool NSSCertDatabase::IsWebTrustAnchor(const CERTCertificate* cert) {
  CERTCertTrust nsstrust;
  SECStatus rv = CERT_GetCertTrust(cert, &nsstrust);
  if (rv != SECSuccess) {
    LOG(ERROR) << "CERT_GetCertTrust failed with error " << PORT_GetError();
    return false;
  }

  // Note: This should return true iff a net::TrustStoreNSS instantiated with
  // SECTrustType trustSSL would classify |cert| as a trust anchor.
  const unsigned int ssl_trust_flags = nsstrust.sslFlags;

  // Determine if the certificate is a trust anchor.
  if ((ssl_trust_flags & CERTDB_TRUSTED_CA) == CERTDB_TRUSTED_CA) {
    return true;
  }

  return false;
}

// static
bool NSSCertDatabase::IsReadOnly(const CERTCertificate* cert) {
  PK11SlotInfo* slot = cert->slot;
  return slot && PK11_IsReadOnly(slot);
}

// static
bool NSSCertDatabase::IsHardwareBacked(const CERTCertificate* cert) {
  PK11SlotInfo* slot = cert->slot;
  if (!slot)
    return false;

#if BUILDFLAG(IS_CHROMEOS_ASH) || BUILDFLAG(IS_CHROMEOS_LACROS)
  // For keys in Chaps, it's possible that they are truly hardware backed, or
  // they can be software-backed, such as if the creator requested it, or if the
  // TPM does not support the key algorithm. Chaps sets a kKeyInSoftware
  // attribute to true for private keys that aren't wrapped by the TPM.
  if (crypto::IsSlotProvidedByChaps(slot)) {
    constexpr CK_ATTRIBUTE_TYPE kKeyInSoftware = CKA_VENDOR_DEFINED + 5;
    SECKEYPrivateKey* private_key = PK11_FindPrivateKeyFromCert(
        slot, const_cast<CERTCertificate*>(cert), nullptr);
    // PK11_HasAttributeSet returns true if the object in the given slot has
    // the attribute set to true. Otherwise it returns false.
    if (private_key &&
        PK11_HasAttributeSet(slot, private_key->pkcs11ID, kKeyInSoftware,
                             /*haslock=*/PR_FALSE)) {
      return false;
    }
    // All keys in chaps without the attribute are hardware backed.
    return true;
  }
#endif
  return PK11_IsHW(slot);
}

void NSSCertDatabase::AddObserver(Observer* observer) {
  observer_list_->AddObserver(observer);
}

void NSSCertDatabase::RemoveObserver(Observer* observer) {
  observer_list_->RemoveObserver(observer);
}

// static
ScopedCERTCertificateList NSSCertDatabase::ExtractCertificates(
    CertInfoList certs_info) {
  ScopedCERTCertificateList certs;
  certs.reserve(certs_info.size());

  for (auto& cert_info : certs_info)
    certs.push_back(std::move(cert_info.cert));

  return certs;
}

// static
ScopedCERTCertificateList NSSCertDatabase::ListCertsImpl(
    crypto::ScopedPK11Slot slot) {
  CertInfoList certs_info = ListCertsInfoImpl(
      std::move(slot), /*add_certs_info=*/false, NSSRootsHandling::kInclude);

  return ExtractCertificates(std::move(certs_info));
}

// static
NSSCertDatabase::CertInfoList NSSCertDatabase::ListCertsInfoImpl(
    crypto::ScopedPK11Slot slot,
    bool add_certs_info,
    NSSRootsHandling nss_roots_handling) {
  // This method may acquire the NSS lock or reenter this code via extension
  // hooks (such as smart card UI). To ensure threads are not starved or
  // deadlocked, the base::ScopedBlockingCall below increments the thread pool
  // capacity if this method takes too much time to run.
  base::ScopedBlockingCall scoped_blocking_call(FROM_HERE,
                                                base::BlockingType::MAY_BLOCK);

  if (nss_roots_handling == NSSRootsHandling::kExclude) {
    // This assumes that using a new TrustStoreNSS instance on each
    // ListCertsInfo call is not expensive. If that ever changes this might
    // need to be rethought.
    TrustStoreNSS trust_store_nss(
        slot ? TrustStoreNSS::UserSlotTrustSetting(
                   crypto::ScopedPK11Slot(PK11_ReferenceSlot(slot.get())))
             : TrustStoreNSS::UseTrustFromAllUserSlots());

    std::vector<TrustStoreNSS::ListCertsResult> cert_list(
        trust_store_nss.ListCertsIgnoringNSSRoots());

    CertInfoList certs_info;
    for (const auto& node : cert_list) {
      CertInfo cert_info;
      cert_info.cert = x509_util::DupCERTCertificate(node.cert.get());
      if (add_certs_info) {
        cert_info.untrusted =
            IsUntrustedUsingTrustStore(cert_info.cert.get(), node.trust);
        cert_info.web_trust_anchor = node.trust.IsTrustAnchor();
        cert_info.on_read_only_slot = IsReadOnly(cert_info.cert.get());
        cert_info.hardware_backed = IsHardwareBacked(cert_info.cert.get());
      }
      certs_info.push_back(std::move(cert_info));
    }
    return certs_info;
  } else {
    CertInfoList certs_info;
    crypto::ScopedCERTCertList cert_list = nullptr;
    if (slot) {
      cert_list.reset(PK11_ListCertsInSlot(slot.get()));
    } else {
      cert_list.reset(PK11_ListCerts(PK11CertListUnique, nullptr));
    }
    // PK11_ListCerts[InSlot] can return nullptr, e.g. because the PKCS#11 token
    // that was backing the specified slot is not available anymore.
    // Treat it as no certificates being present on the slot.
    if (!cert_list) {
      LOG(WARNING) << (slot ? "PK11_ListCertsInSlot" : "PK11_ListCerts")
                   << " returned null";
      return certs_info;
    }

    CERTCertListNode* node;
    for (node = CERT_LIST_HEAD(cert_list); !CERT_LIST_END(node, cert_list);
         node = CERT_LIST_NEXT(node)) {
      CertInfo cert_info;
      cert_info.cert = x509_util::DupCERTCertificate(node->cert);

      if (add_certs_info) {
        cert_info.on_read_only_slot = IsReadOnly(cert_info.cert.get());
        cert_info.untrusted = IsUntrusted(cert_info.cert.get());
        cert_info.web_trust_anchor = IsWebTrustAnchor(cert_info.cert.get());
        cert_info.hardware_backed = IsHardwareBacked(cert_info.cert.get());
      }

      certs_info.push_back(std::move(cert_info));
    }
    return certs_info;
  }
}

void NSSCertDatabase::NotifyCertRemovalAndCallBack(
    DeleteCertCallback callback,
    DeleteCertAndKeyResult result) {
  // This makes the assumption that if there was a matching private key, the
  // cert was probably a client cert, and if not, it may have been a trust
  // anchor or intemediate CA cert.
  switch (result) {
    case DeleteCertAndKeyResult::OK_NO_KEY:
      NotifyObserversTrustStoreChanged();
      std::move(callback).Run(true);
      break;
    case DeleteCertAndKeyResult::OK_FOUND_KEY:
      NotifyObserversClientCertStoreChanged();
      std::move(callback).Run(true);
      break;
    case DeleteCertAndKeyResult::ERROR:
      std::move(callback).Run(false);
      break;
  }
}

void NSSCertDatabase::NotifyObserversTrustStoreChanged() {
  observer_list_->Notify(FROM_HERE, &Observer::OnTrustStoreChanged);
}

void NSSCertDatabase::NotifyObserversClientCertStoreChanged() {
  observer_list_->Notify(FROM_HERE, &Observer::OnClientCertStoreChanged);
}

// static
NSSCertDatabase::DeleteCertAndKeyResult NSSCertDatabase::DeleteCertAndKeyImpl(
    CERTCertificate* cert) {
  // This method may acquire the NSS lock or reenter this code via extension
  // hooks (such as smart card UI). To ensure threads are not starved or
  // deadlocked, the base::ScopedBlockingCall below increments the thread pool
  // capacity if this method takes too much time to run.
  base::ScopedBlockingCall scoped_blocking_call(FROM_HERE,
                                                base::BlockingType::MAY_BLOCK);

  // For some reason, PK11_DeleteTokenCertAndKey only calls
  // SEC_DeletePermCertificate if the private key is found.  So, we check
  // whether a private key exists before deciding which function to call to
  // delete the cert.
  SECKEYPrivateKey* privKey = PK11_FindKeyByAnyCert(cert, nullptr);
  if (privKey) {
    SECKEY_DestroyPrivateKey(privKey);
    if (PK11_DeleteTokenCertAndKey(cert, nullptr)) {
      LOG(ERROR) << "PK11_DeleteTokenCertAndKey failed: " << PORT_GetError();
      return DeleteCertAndKeyResult::ERROR;
    }
    return DeleteCertAndKeyResult::OK_FOUND_KEY;
  } else {
    if (SEC_DeletePermCertificate(cert)) {
      LOG(ERROR) << "SEC_DeletePermCertificate failed: " << PORT_GetError();
      return DeleteCertAndKeyResult::ERROR;
    }
    return DeleteCertAndKeyResult::OK_NO_KEY;
  }
}

// static
NSSCertDatabase::DeleteCertAndKeyResult
NSSCertDatabase::DeleteCertAndKeyImplScoped(ScopedCERTCertificate cert) {
  return NSSCertDatabase::DeleteCertAndKeyImpl(cert.get());
}

}  // namespace net
```