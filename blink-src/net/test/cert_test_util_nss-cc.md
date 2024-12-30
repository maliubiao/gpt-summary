Response:
Let's break down the thought process to analyze the C++ code and generate the explanation.

1. **Understand the Goal:** The request asks for an analysis of a specific C++ file (`net/test/cert_test_util_nss.cc`) related to Chromium's network stack. The analysis should cover functionality, relationship to JavaScript (if any), logical deductions with examples, common usage errors, and debugging guidance.

2. **Initial Code Scan (Keywords and Structure):**  Quickly scan the code for keywords and the overall structure. Look for:
    * `#include` directives: Indicate dependencies (e.g., `<certdb.h>`, `<pk11pub.h>`, file system access, logging, crypto). The `#ifdef UNSAFE_BUFFERS_BUILD` section can be noted, although it's conditional.
    * Namespace: `net` – confirms it's part of the network stack.
    * Functions: Identify the public functions. These are the primary functionalities offered by the file. Names like `ImportSensitiveKeyFromFile`, `ImportClientCertToSlot`, `ImportClientCertAndKeyFromFile`, `ImportCERTCertificateFromFile`, `CreateCERTCertificateListFromFile`, and `GetAnNssBuiltinSslTrustedRoot` are strong indicators of the file's purpose.
    * Static/anonymous namespace: The `namespace { ... }` block likely contains helper functions (`IsKnownRoot`, `IsNssBuiltInRootSlot`, `GetNssBuiltInRootCertsSlot`).
    * Data structures:  Notice the use of `base::FilePath`, `std::string_view`, `crypto::Scoped...`, `net::X509Certificate`, `CERTCertificate*`, `PK11SlotInfo*`. These suggest interaction with files, strings, cryptographic objects, and certificate management.

3. **Function-by-Function Analysis:**  Go through each public function and the helper functions in the anonymous namespace to understand their purpose.

    * **Anonymous Namespace Helpers:**
        * `IsKnownRoot`:  Determines if a certificate is a standard root CA by checking if it's present in the NSS built-in trust store (specifically looking for the `CKA_NSS_MOZILLA_CA_POLICY` attribute).
        * `IsNssBuiltInRootSlot`: Checks if a given PKCS#11 slot appears to hold built-in root certificates by iterating through its certificates and using `IsKnownRoot`.
        * `GetNssBuiltInRootCertsSlot`:  Finds and returns the PKCS#11 slot containing the built-in root certificates. It iterates through available modules and slots.

    * **Public Functions:**
        * `ImportSensitiveKeyFromFile`: Reads a private key from a file (PKCS#8 format) and imports it into a given PKCS#11 slot.
        * `ImportClientCertToSlot` (two overloads): Imports a client certificate (either a `CERTCertificate*` or an `X509Certificate`) into a PKCS#11 slot.
        * `ImportClientCertAndKeyFromFile` (two overloads):  Combines importing a client certificate and its corresponding private key from separate files into a PKCS#11 slot.
        * `ImportCERTCertificateFromFile`: Imports a certificate from a file into an NSS `CERTCertificate` object.
        * `CreateCERTCertificateListFromFile`: Imports multiple certificates from a file into a list of NSS `CERTCertificate` objects.
        * `GetAnNssBuiltinSslTrustedRoot`: Retrieves one of the built-in root certificates trusted for SSL. It uses `GetNssBuiltInRootCertsSlot` and checks the trust settings.

4. **Identify the Core Functionality:**  The core function of this file is to provide utility functions for importing certificates and private keys into the NSS (Network Security Services) database, primarily for testing purposes. It also includes functions to identify and retrieve built-in root certificates.

5. **JavaScript Relationship:**  Think about how certificates are used in a browser context. While this C++ code *directly* manipulates the underlying certificate store, JavaScript doesn't directly call these functions. Instead, JavaScript interacts with higher-level browser APIs related to:
    * HTTPS connections: The browser uses the certificate store managed by NSS (or a similar system on other platforms) to validate server certificates.
    * Client certificates: Websites can request client certificates for authentication. This C++ code could be used in testing scenarios where client certificates need to be added programmatically.
    * Certificate errors: When a website presents an invalid certificate, JavaScript code might be involved in displaying the error to the user.

6. **Logical Deductions (Input/Output):** For each function, consider:
    * What are the inputs? (file paths, filenames, slot information)
    * What is the expected output? (success/failure, a `CERTCertificate`, a list of certificates)
    * What are some example scenarios?  Importing a test client certificate and key, retrieving a built-in root CA.

7. **Common User/Programming Errors:**  Consider the common mistakes developers might make when using these functions:
    * Incorrect file paths or filenames.
    * Trying to import into a read-only slot.
    * Providing a private key that doesn't match the certificate.
    * Incorrect certificate or key format.

8. **Debugging Scenario:**  Imagine a scenario where a website isn't accepting a client certificate. Trace the steps a developer might take to reach this code:
    * User attempts to access a website requiring a client certificate.
    * The browser tries to use the configured client certificate.
    * If the certificate isn't found or is invalid, the connection fails.
    * A developer might use this `cert_test_util_nss.cc` file in a test to programmatically install the correct client certificate to verify if the website-side logic works correctly.

9. **Structure and Refine:** Organize the findings into the requested categories: functionality, JavaScript relationship, logical deductions, usage errors, and debugging. Use clear and concise language. Provide concrete examples where possible. Ensure that the explanation is easy to understand, even for someone who might not be deeply familiar with NSS or Chromium internals.

10. **Review and Iterate:** Read through the generated explanation. Are there any gaps in the information? Is anything unclear or misleading?  For example, initially, the JavaScript connection might be too vague. Refining it to specific scenarios like HTTPS connections and client certificate requests improves clarity. Also, double-check the accuracy of the technical details (e.g., PKCS#8 format for private keys).
这个文件 `net/test/cert_test_util_nss.cc` 是 Chromium 网络栈的一部分，专门用于提供在 **NSS (Network Security Services)** 环境下进行证书相关测试的实用工具函数。NSS 是一个跨平台的安全库，被 Firefox 和 Chromium 等浏览器用于处理 SSL/TLS 连接中的证书管理、加密等操作。

**功能列表:**

1. **导入私钥:**
   - `ImportSensitiveKeyFromFile(const base::FilePath& dir, std::string_view key_filename, PK11SlotInfo* slot)`: 从文件中读取私钥（通常是 PKCS#8 格式），并将其导入到指定的 NSS 密钥槽 (`PK11SlotInfo`) 中。这通常用于设置测试环境，以便模拟客户端认证等场景。

2. **导入客户端证书:**
   - `ImportClientCertToSlot(CERTCertificate* nss_cert, PK11SlotInfo* slot)`: 将一个已经加载到内存中的 NSS 证书对象导入到指定的 NSS 密钥槽中。
   - `ImportClientCertToSlot(const scoped_refptr<X509Certificate>& cert, PK11SlotInfo* slot)`:  接收一个 Chromium 的 `X509Certificate` 对象，将其转换为 NSS 的 `CERTCertificate` 对象，然后导入到指定的 NSS 密钥槽中。

3. **从文件导入客户端证书和密钥:**
   - `ImportClientCertAndKeyFromFile(const base::FilePath& dir, std::string_view cert_filename, std::string_view key_filename, PK11SlotInfo* slot, ScopedCERTCertificate* nss_cert)`:  组合了导入私钥和证书的操作。它从指定目录读取证书和密钥文件，并将它们导入到指定的 NSS 密钥槽中。
   - `ImportClientCertAndKeyFromFile(const base::FilePath& dir, std::string_view cert_filename, std::string_view key_filename, PK11SlotInfo* slot)`:  是上述函数的重载版本，不返回导入的 NSS 证书对象。

4. **从文件导入证书:**
   - `ImportCERTCertificateFromFile(const base::FilePath& certs_dir, std::string_view cert_file)`: 从文件中读取证书，并创建一个 NSS 的 `CERTCertificate` 对象。

5. **从文件创建证书列表:**
   - `CreateCERTCertificateListFromFile(const base::FilePath& certs_dir, std::string_view cert_file, int format)`: 从文件中读取一个或多个证书（支持不同的格式），并创建一个包含 NSS `CERTCertificate` 对象的列表。

6. **获取内置的 SSL 信任根证书:**
   - `GetAnNssBuiltinSslTrustedRoot()`:  返回一个 NSS 内置的、被信任用于 SSL/TLS 连接的根证书。这对于测试证书链验证等功能很有用。

7. **辅助函数（在匿名命名空间中）:**
   - `IsKnownRoot(CERTCertificate* root)`: 判断给定的证书是否是 Chromium 认为的标准（内置）根证书。
   - `IsNssBuiltInRootSlot(PK11SlotInfo* slot)`: 判断给定的 NSS 密钥槽是否包含内置的根证书。
   - `GetNssBuiltInRootCertsSlot()`: 获取包含内置根证书的 NSS 密钥槽。

**与 JavaScript 的关系:**

该文件本身是用 C++ 编写的，JavaScript 代码 **不能直接调用** 其中的函数。然而，这个文件提供的功能对于测试涉及 SSL/TLS 证书的 Web 功能非常重要，而这些功能最终会影响到在浏览器中运行的 JavaScript 代码的行为。

**举例说明:**

假设你正在开发一个需要客户端证书认证的 Web 应用。为了进行端到端测试，你需要在测试环境中设置客户端证书。你可以使用这个文件中的函数来完成这个任务：

1. **测试步骤 (概念性):**
   - 在 C++ 测试代码中，使用 `ImportClientCertAndKeyFromFile` 函数将测试用的客户端证书和私钥导入到 NSS 密钥槽中。
   - 启动 Chromium 浏览器实例，该实例会使用配置好的 NSS 数据库。
   - 使用 JavaScript 代码访问需要客户端证书认证的 Web 页面。
   - 浏览器会从 NSS 密钥槽中找到匹配的客户端证书，并用于认证。
   - 测试 JavaScript 代码验证是否成功通过认证。

2. **JavaScript 代码 (伪代码):**
   ```javascript
   // 假设测试框架提供了访问特定 URL 的能力
   await browser.navigateTo("https://your-client-cert-protected-website.com");

   // 验证页面是否加载成功，这隐含了客户端证书认证成功
   const pageTitle = await browser.getTitle();
   expect(pageTitle).toBe("Welcome to the secure area!");
   ```

在这个场景中，C++ 代码 (`cert_test_util_nss.cc`) 负责幕后工作，配置浏览器的证书环境，而 JavaScript 代码则在浏览器中执行，并依赖于这个环境。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* `ImportSensitiveKeyFromFile`:
    * `dir`: 一个包含私钥文件的目录路径，例如 `/tmp/test_certs/`
    * `key_filename`: 私钥文件名，例如 `client.key.pk8`
    * `slot`: 一个指向有效的 NSS 密钥槽的 `PK11SlotInfo` 指针。
* `ImportClientCertToSlot`:
    * `cert`: 一个有效的 `X509Certificate` 对象，代表客户端证书。
    * `slot`: 一个指向有效的 NSS 密钥槽的 `PK11SlotInfo` 指针。

**预期输出:**

* `ImportSensitiveKeyFromFile`: 如果成功导入私钥，返回 `true`；否则返回 `false`。副作用是将私钥添加到指定的 NSS 密钥槽中。
* `ImportClientCertToSlot`: 如果成功导入证书，返回一个指向导入的 NSS 证书的 `ScopedCERTCertificate` 对象（或 `nullptr` 如果失败）。副作用是将证书添加到指定的 NSS 密钥槽中。

**例如:**

```c++
#include "net/test/cert_test_util_nss.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "base/files/file_util.h"
#include "crypto/nss_init.h"
#include "crypto/scoped_nss_types.h"

namespace net {
namespace {

TEST(CertTestUtilNssTest, ImportClientCertAndKey) {
  // 假设你已经初始化了 NSS 环境
  crypto::EnsureNSSInitInitialized();

  // 创建一个临时目录用于存放测试证书文件
  base::ScopedTempDir temp_dir_;
  ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());

  // 假设你已经有 client.crt 和 client.key.pk8 文件
  base::FilePath cert_path = temp_dir_.GetPath().AppendASCII("client.crt");
  base::FilePath key_path = temp_dir_.GetPath().AppendASCII("client.key.pk8");

  // 写入一些假的证书和密钥数据 (实际测试中需要有效的证书)
  std::string fake_cert_data = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n";
  std::string fake_key_data = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n";
  base::WriteFile(cert_path, fake_cert_data);
  base::WriteFile(key_path, fake_key_data);

  // 获取一个用户可写的 NSS 密钥槽 (实际测试中可能需要更复杂的方法获取)
  crypto::ScopedPK11Slot slot(PK11_GetUserSlot());
  ASSERT_TRUE(slot);

  // 导入客户端证书和密钥
  ScopedCERTCertificate client_cert;
  scoped_refptr<X509Certificate> imported_cert =
      ImportClientCertAndKeyFromFile(temp_dir_.GetPath(), "client.crt", "client.key.pk8", slot.get(), &client_cert);

  // 验证导入是否成功
  EXPECT_NE(nullptr, imported_cert);
  EXPECT_TRUE(client_cert);

  // 清理 NSS 槽 (可选)
  PK11_WipeSlot(slot.get());
}

} // namespace
} // namespace net
```

**用户或编程常见的使用错误:**

1. **文件路径错误:** 提供了错误的证书或私钥文件路径，导致无法读取文件。
   ```c++
   // 错误示例：路径拼写错误
   ImportClientCertAndKeyFromFile(temp_dir_.GetPath(), "clinet.crt", "client.key.pk8", slot.get());
   ```

2. **NSS 密钥槽无效:**  尝试将证书或密钥导入到一个不可用的或没有权限写入的密钥槽。
   ```c++
   // 错误示例：使用一个未初始化的 slot 指针
   PK11SlotInfo* invalid_slot = nullptr;
   ImportClientCertToSlot(nss_cert.get(), invalid_slot); // 导致崩溃或错误
   ```

3. **证书和私钥不匹配:** 导入的私钥与证书不对应，导致认证失败。
   ```c++
   // 错误示例：使用了错误的密钥文件
   ImportClientCertAndKeyFromFile(temp_dir_.GetPath(), "client.crt", "wrong_key.pk8", slot.get());
   ```

4. **证书或密钥格式错误:** 提供的文件不是有效的 PEM 或 DER 格式。
   ```c++
   // 错误示例：文件内容不是有效的证书格式
   base::WriteFile(cert_path, "invalid certificate data");
   ImportClientCertAndKeyFromFile(temp_dir_.GetPath(), "client.crt", "client.key.pk8", slot.get());
   ```

5. **NSS 环境未初始化:** 在调用这些函数之前，没有正确地初始化 NSS 环境。
   ```c++
   // 错误示例：在 NSS 初始化之前调用导入函数
   // crypto::EnsureNSSInitInitialized(); // 缺失这一步
   crypto::ScopedPK11Slot slot(PK11_GetUserSlot());
   ImportClientCertAndKeyFromFile(temp_dir_.GetPath(), "client.crt", "client.key.pk8", slot.get());
   ```

**用户操作是如何一步步的到达这里，作为调试线索:**

作为一个最终用户，你通常不会直接与这个 C++ 文件交互。但是，当你遇到与证书相关的问题时，开发人员可能会使用这些工具进行调试和测试。以下是一个可能的调试场景：

1. **用户报告问题:** 用户在使用 Chromium 浏览器访问某个网站时遇到证书错误，例如 "您的连接不是私密连接" 或客户端证书认证失败。

2. **开发人员尝试复现:** 开发人员尝试在自己的环境中复现该问题。

3. **设置测试环境:** 为了更精确地模拟用户环境，开发人员可能需要手动配置证书。这时，`cert_test_util_nss.cc` 中的函数就派上用场了。

4. **使用工具函数:**
   - 开发人员可以使用 `ImportCERTCertificateFromFile` 导入服务器证书，以测试证书链验证。
   - 如果问题涉及到客户端证书，他们可以使用 `ImportClientCertAndKeyFromFile` 将用户的（或测试用的）客户端证书和私钥导入到测试浏览器的 NSS 数据库中。

5. **运行测试:** 开发人员可以编写 C++ 测试代码，使用这些工具函数来设置证书环境，然后启动浏览器进行自动化测试，或者手动操作浏览器来重现用户遇到的问题。

6. **查看日志和调试信息:**  通过日志输出（例如 `LOG(ERROR)`），开发人员可以了解证书导入是否成功，或者在哪个环节失败。

**例如，一个调试客户端证书认证失败的场景:**

1. 用户报告某个网站无法使用客户端证书登录。
2. 开发人员怀疑用户的客户端证书可能没有正确安装或配置。
3. 开发人员使用 `ImportClientCertAndKeyFromFile` 函数，使用用户的证书和私钥（在用户允许的情况下）在本地测试环境中导入证书。
4. 开发人员运行一个 Chromium 实例，并尝试访问该网站。
5. 如果导入成功，并且网站可以正常访问，那么问题可能出在用户的证书安装或配置上。
6. 如果即使在开发人员的测试环境中也失败，那么问题可能更深层，例如网站的证书认证配置错误，或者 Chromium 的 NSS 集成存在 bug。

总而言之，`net/test/cert_test_util_nss.cc` 是 Chromium 网络栈中一个重要的测试工具文件，它提供了一组用于在 NSS 环境下操作证书和密钥的实用函数，帮助开发人员进行与证书相关的测试和调试工作。虽然普通用户不会直接使用它，但它的功能对于保证浏览器安全和正确处理证书至关重要。

Prompt: 
```
这是目录为net/test/cert_test_util_nss.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/test/cert_test_util.h"

#include <certdb.h>
#include <pk11pub.h>
#include <secmod.h>
#include <secmodt.h>
#include <string.h>

#include <memory>
#include <string_view>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/logging.h"
#include "crypto/nss_key_util.h"
#include "crypto/nss_util_internal.h"
#include "crypto/scoped_nss_types.h"
#include "net/cert/cert_type.h"
#include "net/cert/x509_util_nss.h"

namespace net {

namespace {

// IsKnownRoot returns true if the given certificate is one that we believe
// is a standard (as opposed to user-installed) root.
bool IsKnownRoot(CERTCertificate* root) {
  if (!root || !root->slot) {
    return false;
  }

  // Historically, the set of root certs was determined based on whether or
  // not it was part of nssckbi.[so,dll], the read-only PKCS#11 module that
  // exported the certs with trust settings. However, some distributions,
  // notably those in the Red Hat family, replace nssckbi with a redirect to
  // their own store, such as from p11-kit, which can support more robust
  // trust settings, like per-system trust, admin-defined, and user-defined
  // trust.
  //
  // As a given certificate may exist in multiple modules and slots, scan
  // through all of the available modules, all of the (connected) slots on
  // those modules, and check to see if it has the CKA_NSS_MOZILLA_CA_POLICY
  // attribute set. This attribute indicates it's from the upstream Mozilla
  // trust store, and these distributions preserve the attribute as a flag.
  crypto::AutoSECMODListReadLock lock_id;
  for (const SECMODModuleList* item = SECMOD_GetDefaultModuleList();
       item != nullptr; item = item->next) {
    for (int i = 0; i < item->module->slotCount; ++i) {
      PK11SlotInfo* slot = item->module->slots[i];
      if (PK11_IsPresent(slot) && PK11_HasRootCerts(slot)) {
        CK_OBJECT_HANDLE handle = PK11_FindCertInSlot(slot, root, nullptr);
        if (handle != CK_INVALID_HANDLE &&
            PK11_HasAttributeSet(slot, handle, CKA_NSS_MOZILLA_CA_POLICY,
                                 PR_FALSE) == CK_TRUE) {
          return true;
        }
      }
    }
  }

  return false;
}

// Returns true if the provided slot looks like it contains built-in root.
bool IsNssBuiltInRootSlot(PK11SlotInfo* slot) {
  if (!PK11_IsPresent(slot) || !PK11_HasRootCerts(slot)) {
    return false;
  }
  crypto::ScopedCERTCertList cert_list(PK11_ListCertsInSlot(slot));
  if (!cert_list) {
    return false;
  }
  bool built_in_cert_found = false;
  for (CERTCertListNode* node = CERT_LIST_HEAD(cert_list);
       !CERT_LIST_END(node, cert_list); node = CERT_LIST_NEXT(node)) {
    if (IsKnownRoot(node->cert)) {
      built_in_cert_found = true;
      break;
    }
  }
  return built_in_cert_found;
}

// Returns the slot which holds the built-in root certificates.
crypto::ScopedPK11Slot GetNssBuiltInRootCertsSlot() {
  crypto::AutoSECMODListReadLock auto_lock;
  SECMODModuleList* head = SECMOD_GetDefaultModuleList();
  for (SECMODModuleList* item = head; item != nullptr; item = item->next) {
    int slot_count = item->module->loaded ? item->module->slotCount : 0;
    for (int i = 0; i < slot_count; i++) {
      PK11SlotInfo* slot = item->module->slots[i];
      if (IsNssBuiltInRootSlot(slot)) {
        return crypto::ScopedPK11Slot(PK11_ReferenceSlot(slot));
      }
    }
  }
  return crypto::ScopedPK11Slot();
}

}  // namespace

bool ImportSensitiveKeyFromFile(const base::FilePath& dir,
                                std::string_view key_filename,
                                PK11SlotInfo* slot) {
  base::FilePath key_path = dir.AppendASCII(key_filename);
  std::string key_pkcs8;
  bool success = base::ReadFileToString(key_path, &key_pkcs8);
  if (!success) {
    LOG(ERROR) << "Failed to read file " << key_path.value();
    return false;
  }

  crypto::ScopedSECKEYPrivateKey private_key(
      crypto::ImportNSSKeyFromPrivateKeyInfo(slot,
                                             base::as_byte_span(key_pkcs8),
                                             /*permanent=*/true));
  LOG_IF(ERROR, !private_key)
      << "Could not create key from file " << key_path.value();
  return !!private_key;
}

bool ImportClientCertToSlot(CERTCertificate* nss_cert, PK11SlotInfo* slot) {
  std::string nickname =
      x509_util::GetDefaultUniqueNickname(nss_cert, USER_CERT, slot);
  SECStatus rv = PK11_ImportCert(slot, nss_cert, CK_INVALID_HANDLE,
                                 nickname.c_str(), PR_FALSE);
  if (rv != SECSuccess) {
    LOG(ERROR) << "Could not import cert";
    return false;
  }
  return true;
}

ScopedCERTCertificate ImportClientCertToSlot(
    const scoped_refptr<X509Certificate>& cert,
    PK11SlotInfo* slot) {
  ScopedCERTCertificate nss_cert =
      x509_util::CreateCERTCertificateFromX509Certificate(cert.get());
  if (!nss_cert)
    return nullptr;

  if (!ImportClientCertToSlot(nss_cert.get(), slot))
    return nullptr;

  return nss_cert;
}

scoped_refptr<X509Certificate> ImportClientCertAndKeyFromFile(
    const base::FilePath& dir,
    std::string_view cert_filename,
    std::string_view key_filename,
    PK11SlotInfo* slot,
    ScopedCERTCertificate* nss_cert) {
  if (!ImportSensitiveKeyFromFile(dir, key_filename, slot)) {
    LOG(ERROR) << "Could not import private key from file " << key_filename;
    return nullptr;
  }

  scoped_refptr<X509Certificate> cert(ImportCertFromFile(dir, cert_filename));

  if (!cert.get()) {
    LOG(ERROR) << "Failed to parse cert from file " << cert_filename;
    return nullptr;
  }

  *nss_cert = ImportClientCertToSlot(cert, slot);
  if (!*nss_cert)
    return nullptr;

  // |cert| continues to point to the original X509Certificate before the
  // import to |slot|. However this should not make a difference as NSS handles
  // state globally.
  return cert;
}

scoped_refptr<X509Certificate> ImportClientCertAndKeyFromFile(
    const base::FilePath& dir,
    std::string_view cert_filename,
    std::string_view key_filename,
    PK11SlotInfo* slot) {
  ScopedCERTCertificate nss_cert;
  return ImportClientCertAndKeyFromFile(dir, cert_filename, key_filename, slot,
                                        &nss_cert);
}

ScopedCERTCertificate ImportCERTCertificateFromFile(
    const base::FilePath& certs_dir,
    std::string_view cert_file) {
  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(certs_dir, cert_file);
  if (!cert)
    return nullptr;
  return x509_util::CreateCERTCertificateFromX509Certificate(cert.get());
}

ScopedCERTCertificateList CreateCERTCertificateListFromFile(
    const base::FilePath& certs_dir,
    std::string_view cert_file,
    int format) {
  CertificateList certs =
      CreateCertificateListFromFile(certs_dir, cert_file, format);
  ScopedCERTCertificateList nss_certs;
  for (const auto& cert : certs) {
    ScopedCERTCertificate nss_cert =
        x509_util::CreateCERTCertificateFromX509Certificate(cert.get());
    if (!nss_cert)
      return {};
    nss_certs.push_back(std::move(nss_cert));
  }
  return nss_certs;
}

ScopedCERTCertificate GetAnNssBuiltinSslTrustedRoot() {
  crypto::ScopedPK11Slot root_certs_slot = GetNssBuiltInRootCertsSlot();
  if (!root_certs_slot) {
    return nullptr;
  }

  scoped_refptr<X509Certificate> ssl_trusted_root;

  crypto::ScopedCERTCertList cert_list(
      PK11_ListCertsInSlot(root_certs_slot.get()));
  if (!cert_list) {
    return nullptr;
  }
  for (CERTCertListNode* node = CERT_LIST_HEAD(cert_list);
       !CERT_LIST_END(node, cert_list); node = CERT_LIST_NEXT(node)) {
    CERTCertTrust trust;
    if (CERT_GetCertTrust(node->cert, &trust) != SECSuccess) {
      continue;
    }
    int trust_flags = SEC_GET_TRUST_FLAGS(&trust, trustSSL);
    if ((trust_flags & CERTDB_TRUSTED_CA) == CERTDB_TRUSTED_CA) {
      return x509_util::DupCERTCertificate(node->cert);
    }
  }

  return nullptr;
}

}  // namespace net

"""

```