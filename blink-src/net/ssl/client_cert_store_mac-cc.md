Response:
Let's break down the thought process for analyzing the `client_cert_store_mac.cc` file and answering the prompt.

1. **Understand the Goal:** The core request is to understand the functionality of this specific Chromium source file, particularly in relation to client certificates on macOS. The request also probes for connections to JavaScript, logical reasoning (with input/output), potential user errors, and debugging steps.

2. **Initial Code Scan (High-Level):**  Read through the file quickly to get a general sense of its purpose. Keywords like "client cert," "mac," "Keychain," "SecIdentity," "SecCertificate," and "SSL" immediately jump out, confirming its role in handling client certificates on macOS. The inclusion of `#include <Security/Security.h>` reinforces this.

3. **Identify Key Functions:** Look for the main functions and their roles. `GetClientCerts` seems like the primary entry point. Other functions with descriptive names like `CopyCertChain`, `IsIssuedByInKeychain`, `SupportsSSLClientAuth`, `GetClientCertsImpl`, and `AddIdentity` suggest specific steps in the client certificate retrieval and filtering process.

4. **Deconstruct `GetClientCerts`:** This is the main function. Notice it calls `GetSSLPlatformKeyTaskRunner()->PostTaskAndReplyWithResult`. This indicates asynchronous operation, likely offloading the potentially blocking Keychain operations to a background thread. The background task is `GetClientCertsOnBackgroundThread`, and the reply is handled by `OnClientCertsResponse`.

5. **Analyze `GetClientCertsOnBackgroundThread`:** This function is crucial. It performs the core logic of fetching client certificates. Key steps observed:
    * **Preferred Identity:** It tries to find a "preferred" client certificate for the given server domain using `SecIdentityCopyPreferred`.
    * **Enumerating Identities:** It uses *two* methods to enumerate client identities: the deprecated `SecIdentitySearchCreate` and the newer `SecItemCopyMatching`. The comment explicitly states *why* both are needed (different sets of certificates).
    * **`AddIdentity`:**  This helper function extracts the certificate from a `SecIdentityRef` and adds it to the appropriate list (preferred or regular).
    * **`GetClientCertsImpl`:** Finally, it calls `GetClientCertsImpl` to filter the retrieved certificates based on the server's request.

6. **Examine `GetClientCertsImpl`:**  This function performs the filtering logic. Key steps:
    * **Expiration Check:** It discards expired certificates.
    * **`SupportsSSLClientAuth`:** It checks if the certificate is valid for client authentication.
    * **Duplicate Check:** It avoids adding the same certificate multiple times.
    * **Issuer Check:** It verifies if the certificate is issued by a trusted authority (provided by the server). Crucially, it uses `IsIssuedByInKeychain` to handle cases where the intermediate certificates aren't directly attached.
    * **Sorting:** It sorts the selected certificates, placing the preferred one first.

7. **Delve into Helper Functions:** Understand the purpose of functions called by `GetClientCertsImpl`:
    * **`SupportsSSLClientAuth`:** Parses the certificate to check for `keyUsage` and `extendedKeyUsage` extensions to determine if it's suitable for client authentication.
    * **`IsIssuedByInKeychain`:**  Uses `SecTrust` to build the full certificate chain from the Keychain and then checks if the root CA matches the server's allowed issuers.
    * **`CopyCertChain`:**  A utility function to retrieve the certificate chain.

8. **Address Specific Prompt Questions:**

    * **Functionality Summary:** Combine the understanding gained from the previous steps to provide a concise summary of the file's role in retrieving and filtering client certificates on macOS.

    * **Relationship to JavaScript:**  Recognize that this is low-level C++ code within the browser's network stack. JavaScript interacts with this indirectly through higher-level Web APIs. The example of `navigator.mediaDevices.getUserMedia` for accessing client certificates is a relevant illustration.

    * **Logical Reasoning (Input/Output):**  Choose a specific scenario (e.g., a server requesting a client certificate from a specific issuer). Trace the flow through the code with a hypothetical input and describe the expected output (a filtered list of matching certificates).

    * **User/Programming Errors:** Think about common mistakes users or developers might make. Expired certificates, incorrect server configurations, and issues with the macOS Keychain itself are good examples.

    * **Debugging Steps:**  Consider how a developer might reach this code during debugging. Start with a user action (accessing a website requiring a client certificate) and trace the execution flow through the browser's network stack, eventually arriving at this specific C++ file. Highlighting logging statements and breakpoints is relevant.

9. **Refine and Organize:** Structure the answers clearly and logically, using headings and bullet points where appropriate. Ensure the language is precise and avoids jargon where possible, or explains it when necessary. Review for accuracy and completeness.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This file just reads certificates from the Keychain."  **Correction:**  It does more than just read. It *filters* based on server requests, checks for validity, and handles preferred certificates.
* **Initial thought:** "JavaScript directly calls this code." **Correction:**  JavaScript interacts indirectly via Web APIs. It's important to clarify the level of interaction.
* **Overlooking details:**  Initially, I might have missed the significance of using *both* `SecIdentitySearchCreate` and `SecItemCopyMatching`. The comment in the code is crucial for understanding this nuance. Going back and carefully reading comments is essential.
* **Being too technical:**  While technical details are important, the explanation should also be understandable to someone with a general understanding of web technologies. Balancing technical accuracy with clarity is key.

By following this iterative process of scanning, analyzing, deconstructing, and refining, one can effectively understand the functionality of a complex source file like `client_cert_store_mac.cc` and address the specific points raised in the prompt.
好的，这是对 `net/ssl/client_cert_store_mac.cc` 文件的功能进行的分析：

**文件功能概述:**

`client_cert_store_mac.cc` 文件的主要功能是为 Chromium 浏览器在 macOS 平台上提供访问和管理客户端证书的功能。它负责与 macOS 的 Keychain 服务进行交互，检索用户已安装的客户端证书，并根据服务器的请求（`SSLCertRequestInfo`）筛选出合适的证书提供给用户选择或自动用于身份验证。

**核心功能点:**

1. **枚举客户端证书:** 该文件使用 macOS 提供的 Security Framework API (例如 `SecIdentitySearchCreate`, `SecItemCopyMatching`) 来枚举用户 Keychain 中可用的客户端证书。它尝试使用两种不同的方法来确保能够检索到所有类型的证书，包括智能卡上的证书。

2. **处理证书偏好:**  对于特定的服务器域名，macOS 可以设置首选的客户端证书。该文件会尝试检索这些偏好设置 (`SecIdentityCopyPreferred`)，并在后续的证书选择过程中优先考虑。

3. **证书筛选:**  根据 `SSLCertRequestInfo` 中包含的信息（例如，服务器接受的证书颁发机构列表），该文件会对枚举到的证书进行筛选。筛选条件包括：
    * **证书是否过期:** 检查证书的有效期。
    * **证书是否支持客户端认证:** 检查证书的扩展密钥用法（Extended Key Usage）或密钥用法（Key Usage）扩展，以确定其是否可用于 SSL 客户端身份验证。
    * **证书颁发者是否被服务器信任:**  验证证书的颁发者是否在服务器提供的受信任 CA 列表中。它可以直接比较证书信息，也可以查询 Keychain 来获取完整的证书链并进行验证。

4. **构建完整的证书链:**  在某些情况下，客户端证书可能只包含用户的私钥和证书本身，而缺少中间证书。该文件可以使用 `SecTrust` API 来构建完整的证书链，以便更准确地进行颁发者验证。

5. **与 Chromium 网络栈集成:** 该文件提供的功能被 Chromium 的网络栈所使用，当服务器要求客户端提供证书进行身份验证时，会调用此文件的方法来获取可用的客户端证书列表。

6. **测试辅助功能:**  文件中包含以 `ForTesting` 结尾的函数，这些函数主要用于单元测试，允许在不实际访问 Keychain 的情况下模拟证书选择过程。

**与 JavaScript 功能的关系:**

`client_cert_store_mac.cc` 本身是 C++ 代码，JavaScript 无法直接调用它。然而，它的功能会间接地影响到 JavaScript 中与客户端证书相关的 API 和行为：

* **`navigator.mediaDevices.getUserMedia()` 和客户端证书选择:** 当网站通过 `getUserMedia()` 请求访问用户的摄像头或麦克风，并且需要客户端证书进行身份验证时，浏览器底层会使用 `client_cert_store_mac.cc` 来获取可用的证书列表。用户可能会在弹出的对话框中看到这些证书选项，这个对话框的生成就依赖于此文件的功能。
    * **举例说明:** 假设一个视频会议网站要求用户提供客户端证书进行身份验证。当用户点击“加入会议”时，网站可能会调用 `getUserMedia()`。如果服务器要求客户端证书，浏览器会调用 `client_cert_store_mac.cc` 获取证书列表，并在一个对话框中展示给用户。用户选择一个证书后，浏览器会使用该证书与服务器建立安全连接。

* **`fetch()` 或 `XMLHttpRequest` 请求和客户端证书:**  当 JavaScript 发起 HTTPS 请求，并且服务器要求客户端证书时，浏览器也会使用 `client_cert_store_mac.cc` 来查找合适的证书。
    * **举例说明:**  一个企业内部的 Web 应用可能需要客户端证书才能访问 API。当 JavaScript 代码使用 `fetch()` 向该 API 发送请求时，如果服务器返回要求客户端证书的响应，浏览器会调用 `client_cert_store_mac.cc` 来选择或提示用户选择证书。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* **`SSLCertRequestInfo`:**
    * `host_and_port`: "mycompany.com:443"
    * `cert_authorities`: 一个包含以下 Subject Key Identifier 的列表：
        *  "1A:2B:3C:4D:5E:6F:7A:8B:9C:0D:1E:2F:3A:4B:5C:6D:7E:8F:90:01"
        *  "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
* **macOS Keychain 中的客户端证书:**
    * **证书 1:**
        * Subject: "User A"
        * Issuer Subject Key Identifier: "1A:2B:3C:4D:5E:6F:7A:8B:9C:0D:1E:2F:3A:4B:5C:6D:7E:8F:90:01"
        * 未过期
        * 支持客户端认证
    * **证书 2:**
        * Subject: "User B"
        * Issuer Subject Key Identifier: "XX:YY:ZZ:..." (不在 `cert_authorities` 列表中)
        * 未过期
        * 支持客户端认证
    * **证书 3:**
        * Subject: "Expired Cert"
        * Issuer Subject Key Identifier: "1A:2B:3C:4D:5E:6F:7A:8B:9C:0D:1E:2F:3A:4B:5C:6D:7E:8F:90:01"
        * 已过期
        * 支持客户端认证

**预期输出:**

`GetClientCertsImpl` 或 `GetClientCertsOnBackgroundThread` 函数的输出 `selected_identities` 应该包含一个 `ClientCertIdentityMac` 对象的列表，其中只包含 **证书 1**。

**推理过程:**

1. 函数会枚举 Keychain 中的所有客户端证书。
2. **证书 3** 因为已过期而被排除。
3. **证书 2** 因为其颁发者不在 `SSLCertRequestInfo` 提供的受信任 CA 列表中而被排除。
4. **证书 1** 未过期，支持客户端认证，并且其颁发者在受信任 CA 列表中，因此被选中。

**用户或编程常见的使用错误:**

1. **客户端证书未安装或未导入到 Keychain:** 用户可能没有安装所需的客户端证书，或者证书没有正确导入到 macOS 的 Keychain 中。这将导致 `client_cert_store_mac.cc` 无法找到可用的证书。
    * **示例:** 用户尝试访问需要客户端证书的网站，但没有将证书 `.p12` 文件导入到 Keychain Access 应用中。
2. **Keychain 访问权限问题:** 浏览器进程可能没有足够的权限访问用户的 Keychain，导致无法枚举或读取证书信息。
    * **示例:**  用户更改了 Keychain 的访问权限，阻止了 Chrome 浏览器的访问。
3. **服务器配置错误:** 服务器可能配置了错误的受信任 CA 列表，导致有效的客户端证书被错误地排除。
    * **示例:** 服务器的 `SSLCertRequestInfo` 中指定的 CA 列表与实际颁发用户证书的 CA 不匹配。
4. **证书过期:**  用户使用的客户端证书已经过期，导致无法用于身份验证。
    * **示例:** 用户长期未更新其企业颁发的客户端证书。
5. **证书用途不正确:**  证书的扩展密钥用法（Extended Key Usage）中可能没有包含 `id-kp-clientAuth`，这意味着该证书不适用于 SSL 客户端身份验证。
    * **示例:** 用户尝试使用一个仅用于代码签名的证书进行网站身份验证。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在 Chromium 浏览器中访问一个 HTTPS 网站，该网站配置为需要客户端证书进行身份验证。**
2. **服务器在 TLS 握手过程中发送一个 `CertificateRequest` 消息。**  这个消息包含了服务器信任的证书颁发机构列表。
3. **Chromium 的网络栈接收到 `CertificateRequest` 消息，并解析其中的信息，创建 `SSLCertRequestInfo` 对象。**
4. **网络栈调用 `ClientCertStore::GetClientCerts()` 方法，对于 macOS 平台，这将调用到 `ClientCertStoreMac::GetClientCerts()`。**
5. **`ClientCertStoreMac::GetClientCerts()` 将任务提交到后台线程执行 `GetClientCertsOnBackgroundThread()`。** 这是为了避免阻塞 UI 线程，因为访问 Keychain 可能需要一些时间。
6. **`GetClientCertsOnBackgroundThread()`:**
    * 尝试获取特定域名的首选证书。
    * 使用 `SecIdentitySearchCreate` 和 `SecItemCopyMatching` 枚举 Keychain 中的客户端身份。
    * 对于每个找到的身份，使用 `SecIdentityCopyCertificate` 获取对应的证书。
    * 调用 `AddIdentity` 将证书添加到 `regular_identities` 或 `preferred_identity` 列表中。
7. **`GetClientCertsOnBackgroundThread()` 调用 `GetClientCertsImpl()` 进行证书筛选。**
8. **`GetClientCertsImpl()`:**
    * 遍历枚举到的证书。
    * 检查证书是否过期 (`cert->certificate()->HasExpired()`)。
    * 检查证书是否支持客户端认证 (`SupportsSSLClientAuth(cert->certificate()->cert_buffer())`)。
    * 检查证书颁发者是否被服务器信任 (`cert->certificate()->IsIssuedByEncoded(request.cert_authorities)` 或 `IsIssuedByInKeychain(...)`)。
    * 将符合条件的证书添加到 `selected_identities` 列表中。
9. **`GetClientCertsOnBackgroundThread()` 将筛选后的证书列表返回。**
10. **`ClientCertStoreMac::OnClientCertsResponse()` 被调用，并将结果传递给原始的回调函数。**
11. **Chromium 的网络栈收到客户端证书列表后，可能会：**
    * 如果只找到一个匹配的证书，则自动使用该证书进行身份验证。
    * 如果找到多个匹配的证书，则可能会向用户显示一个对话框，让用户选择要使用的证书。
    * 如果没有找到匹配的证书，则身份验证可能会失败。

**调试线索:**

* **日志输出:** Chromium 的网络栈和 Security Framework 都有相关的日志输出。启用这些日志可以帮助跟踪证书的枚举和筛选过程，查看是否有 Keychain 访问错误或证书解析错误。
* **断点:** 在 `client_cert_store_mac.cc` 的关键函数（如 `GetClientCertsOnBackgroundThread`, `GetClientCertsImpl`, `IsIssuedByInKeychain`) 设置断点，可以逐步骤地查看证书的加载和筛选过程，检查 `SSLCertRequestInfo` 的内容以及 Keychain 中证书的信息。
* **macOS Console 应用:**  macOS 的 Console 应用可以显示来自 Security Framework 的错误和调试信息，有助于诊断 Keychain 相关的问题。
* **Keychain Access 应用:**  检查 Keychain Access 应用，确认客户端证书是否已正确安装，并且其信任设置是否正确。
* **`chrome://net-internals/#ssl`:**  Chrome 的 `net-internals` 工具可以提供关于 SSL 连接的详细信息，包括客户端证书的选择过程。

希望以上分析对您有所帮助！

Prompt: 
```
这是目录为net/ssl/client_cert_store_mac.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/client_cert_store_mac.h"

#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CFArray.h>
#include <CoreServices/CoreServices.h>
#include <Security/SecBase.h>
#include <Security/Security.h>

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/apple/osstatus_logging.h"
#include "base/apple/scoped_cftyperef.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/functional/callback_helpers.h"
#include "base/logging.h"
#include "base/ranges/algorithm.h"
#include "base/strings/sys_string_conversions.h"
#include "base/synchronization/lock.h"
#include "crypto/mac_security_services_lock.h"
#include "net/base/host_port_pair.h"
#include "net/cert/x509_util.h"
#include "net/cert/x509_util_apple.h"
#include "net/ssl/client_cert_identity_mac.h"
#include "net/ssl/ssl_platform_key_util.h"
#include "third_party/boringssl/src/pki/extended_key_usage.h"
#include "third_party/boringssl/src/pki/parse_certificate.h"

using base::apple::ScopedCFTypeRef;

namespace net {

namespace {

using ClientCertIdentityMacList =
    std::vector<std::unique_ptr<ClientCertIdentityMac>>;

// Gets the issuer for a given cert, starting with the cert itself and
// including the intermediate and finally root certificates (if any).
// This function calls SecTrust but doesn't actually pay attention to the trust
// result: it shouldn't be used to determine trust, just to traverse the chain.
OSStatus CopyCertChain(
    SecCertificateRef cert_handle,
    base::apple::ScopedCFTypeRef<CFArrayRef>* out_cert_chain) {
  DCHECK(cert_handle);
  DCHECK(out_cert_chain);

  // Create an SSL policy ref configured for client cert evaluation.
  ScopedCFTypeRef<SecPolicyRef> ssl_policy(
      SecPolicyCreateSSL(/*server=*/false, /*hostname=*/nullptr));
  if (!ssl_policy)
    return errSecNoPolicyModule;

  // Create a SecTrustRef.
  ScopedCFTypeRef<CFArrayRef> input_certs(CFArrayCreate(
      nullptr, const_cast<const void**>(reinterpret_cast<void**>(&cert_handle)),
      1, &kCFTypeArrayCallBacks));
  OSStatus result;
  SecTrustRef trust_ref = nullptr;
  {
    base::AutoLock lock(crypto::GetMacSecurityServicesLock());
    result = SecTrustCreateWithCertificates(input_certs.get(), ssl_policy.get(),
                                            &trust_ref);
  }
  if (result)
    return result;
  ScopedCFTypeRef<SecTrustRef> trust(trust_ref);

  // Evaluate trust, which creates the cert chain.
  {
    base::AutoLock lock(crypto::GetMacSecurityServicesLock());
    // The return value is intentionally ignored since we only care about
    // building a cert chain, not whether it is trusted (the server is the
    // only one that can decide that.)
    std::ignore = SecTrustEvaluateWithError(trust.get(), nullptr);
    *out_cert_chain = x509_util::CertificateChainFromSecTrust(trust.get());
  }
  return result;
}

// Returns true if |*identity| is issued by an authority in |valid_issuers|
// according to Keychain Services, rather than using |identity|'s intermediate
// certificates. If it is, |*identity| is updated to include the intermediates.
bool IsIssuedByInKeychain(const std::vector<std::string>& valid_issuers,
                          ClientCertIdentityMac* identity) {
  DCHECK(identity);
  DCHECK(identity->sec_identity_ref());

  ScopedCFTypeRef<SecCertificateRef> os_cert;
  int err = SecIdentityCopyCertificate(identity->sec_identity_ref(),
                                       os_cert.InitializeInto());
  if (err != noErr)
    return false;
  base::apple::ScopedCFTypeRef<CFArrayRef> cert_chain;
  OSStatus result = CopyCertChain(os_cert.get(), &cert_chain);
  if (result) {
    OSSTATUS_LOG(ERROR, result) << "CopyCertChain error";
    return false;
  }

  if (!cert_chain)
    return false;

  std::vector<base::apple::ScopedCFTypeRef<SecCertificateRef>> intermediates;
  for (CFIndex i = 1, chain_count = CFArrayGetCount(cert_chain.get());
       i < chain_count; ++i) {
    SecCertificateRef sec_cert = reinterpret_cast<SecCertificateRef>(
        const_cast<void*>(CFArrayGetValueAtIndex(cert_chain.get(), i)));
    intermediates.emplace_back(sec_cert, base::scoped_policy::RETAIN);
  }

  // Allow UTF-8 inside PrintableStrings in client certificates. See
  // crbug.com/770323.
  X509Certificate::UnsafeCreateOptions options;
  options.printable_string_is_utf8 = true;
  scoped_refptr<X509Certificate> new_cert(
      x509_util::CreateX509CertificateFromSecCertificate(os_cert, intermediates,
                                                         options));

  if (!new_cert || !new_cert->IsIssuedByEncoded(valid_issuers))
    return false;

  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediate_buffers;
  intermediate_buffers.reserve(new_cert->intermediate_buffers().size());
  for (const auto& intermediate : new_cert->intermediate_buffers()) {
    intermediate_buffers.push_back(bssl::UpRef(intermediate.get()));
  }
  identity->SetIntermediates(std::move(intermediate_buffers));
  return true;
}

// Does |cert|'s usage allow SSL client authentication?
bool SupportsSSLClientAuth(CRYPTO_BUFFER* cert) {
  DCHECK(cert);

  bssl::ParseCertificateOptions options;
  options.allow_invalid_serial_numbers = true;
  bssl::der::Input tbs_certificate_tlv;
  bssl::der::Input signature_algorithm_tlv;
  bssl::der::BitString signature_value;
  bssl::ParsedTbsCertificate tbs;
  if (!bssl::ParseCertificate(
          bssl::der::Input(CRYPTO_BUFFER_data(cert), CRYPTO_BUFFER_len(cert)),
          &tbs_certificate_tlv, &signature_algorithm_tlv, &signature_value,
          nullptr /* errors*/) ||
      !ParseTbsCertificate(tbs_certificate_tlv, options, &tbs,
                           nullptr /*errors*/)) {
    return false;
  }

  if (!tbs.extensions_tlv)
    return true;

  std::map<bssl::der::Input, bssl::ParsedExtension> extensions;
  if (!ParseExtensions(tbs.extensions_tlv.value(), &extensions))
    return false;

  // RFC5280 says to take the intersection of the two extensions.
  //
  // We only support signature-based client certificates, so we need the
  // digitalSignature bit.
  //
  // In particular, if a key has the nonRepudiation bit and not the
  // digitalSignature one, we will not offer it to the user.
  if (auto it = extensions.find(bssl::der::Input(bssl::kKeyUsageOid));
      it != extensions.end()) {
    bssl::der::BitString key_usage;
    if (!bssl::ParseKeyUsage(it->second.value, &key_usage) ||
        !key_usage.AssertsBit(bssl::KEY_USAGE_BIT_DIGITAL_SIGNATURE)) {
      return false;
    }
  }

  if (auto it = extensions.find(bssl::der::Input(bssl::kExtKeyUsageOid));
      it != extensions.end()) {
    std::vector<bssl::der::Input> extended_key_usage;
    if (!bssl::ParseEKUExtension(it->second.value, &extended_key_usage)) {
      return false;
    }
    bool found_acceptable_eku = false;
    for (const auto& oid : extended_key_usage) {
      if (oid == bssl::der::Input(bssl::kAnyEKU) ||
          oid == bssl::der::Input(bssl::kClientAuth)) {
        found_acceptable_eku = true;
        break;
      }
    }
    if (!found_acceptable_eku)
      return false;
  }

  return true;
}

// Examines the certificates in |preferred_identity| and |regular_identities| to
// find all certificates that match the client certificate request in |request|,
// storing the matching certificates in |selected_identities|.
// If |query_keychain| is true, Keychain Services will be queried to construct
// full certificate chains. If it is false, only the the certificates and their
// intermediates (available via X509Certificate::intermediate_buffers())
// will be considered.
void GetClientCertsImpl(
    std::unique_ptr<ClientCertIdentityMac> preferred_identity,
    ClientCertIdentityMacList regular_identities,
    const SSLCertRequestInfo& request,
    bool query_keychain,
    ClientCertIdentityList* selected_identities) {
  scoped_refptr<X509Certificate> preferred_cert_orig;
  ClientCertIdentityMacList preliminary_list = std::move(regular_identities);
  if (preferred_identity) {
    preferred_cert_orig = preferred_identity->certificate();
    preliminary_list.insert(preliminary_list.begin(),
                            std::move(preferred_identity));
  }

  selected_identities->clear();
  for (size_t i = 0; i < preliminary_list.size(); ++i) {
    std::unique_ptr<ClientCertIdentityMac>& cert = preliminary_list[i];
    if (cert->certificate()->HasExpired() ||
        !SupportsSSLClientAuth(cert->certificate()->cert_buffer())) {
      continue;
    }

    // Skip duplicates (a cert may be in multiple keychains).
    if (base::ranges::any_of(
            *selected_identities,
            [&cert](const std::unique_ptr<ClientCertIdentity>&
                        other_cert_identity) {
              return x509_util::CryptoBufferEqual(
                  cert->certificate()->cert_buffer(),
                  other_cert_identity->certificate()->cert_buffer());
            })) {
      continue;
    }

    // Check if the certificate issuer is allowed by the server.
    if (request.cert_authorities.empty() ||
        cert->certificate()->IsIssuedByEncoded(request.cert_authorities) ||
        (query_keychain &&
         IsIssuedByInKeychain(request.cert_authorities, cert.get()))) {
      selected_identities->push_back(std::move(cert));
    }
  }

  // Preferred cert should appear first in the ui, so exclude it from the
  // sorting.  Compare the cert_buffer since the X509Certificate object may
  // have changed if intermediates were added.
  ClientCertIdentityList::iterator sort_begin = selected_identities->begin();
  ClientCertIdentityList::iterator sort_end = selected_identities->end();
  if (preferred_cert_orig && sort_begin != sort_end &&
      x509_util::CryptoBufferEqual(
          sort_begin->get()->certificate()->cert_buffer(),
          preferred_cert_orig->cert_buffer())) {
    ++sort_begin;
  }
  sort(sort_begin, sort_end, ClientCertIdentitySorter());
}

// Given a |sec_identity|, identifies its corresponding certificate, and either
// adds it to |regular_identities| or assigns it to |preferred_identity|, if the
// |sec_identity| matches the |preferred_sec_identity|.
void AddIdentity(ScopedCFTypeRef<SecIdentityRef> sec_identity,
                 SecIdentityRef preferred_sec_identity,
                 ClientCertIdentityMacList* regular_identities,
                 std::unique_ptr<ClientCertIdentityMac>* preferred_identity) {
  OSStatus err;
  ScopedCFTypeRef<SecCertificateRef> cert_handle;
  err = SecIdentityCopyCertificate(sec_identity.get(),
                                   cert_handle.InitializeInto());
  if (err != noErr)
    return;

  // Allow UTF-8 inside PrintableStrings in client certificates. See
  // crbug.com/770323.
  X509Certificate::UnsafeCreateOptions options;
  options.printable_string_is_utf8 = true;
  scoped_refptr<X509Certificate> cert(
      x509_util::CreateX509CertificateFromSecCertificate(cert_handle, {},
                                                         options));
  if (!cert)
    return;

  if (preferred_sec_identity &&
      CFEqual(preferred_sec_identity, sec_identity.get())) {
    *preferred_identity = std::make_unique<ClientCertIdentityMac>(
        std::move(cert), std::move(sec_identity));
  } else {
    regular_identities->push_back(std::make_unique<ClientCertIdentityMac>(
        std::move(cert), std::move(sec_identity)));
  }
}

ClientCertIdentityList GetClientCertsOnBackgroundThread(
    scoped_refptr<const SSLCertRequestInfo> request) {
  std::string server_domain = request->host_and_port.host();

  ScopedCFTypeRef<SecIdentityRef> preferred_sec_identity;
  if (!server_domain.empty()) {
    // See if there's an identity preference for this domain:
    ScopedCFTypeRef<CFStringRef> domain_str(
        base::SysUTF8ToCFStringRef("https://" + server_domain));
    // While SecIdentityCopyPreferred appears to take a list of CA issuers
    // to restrict the identity search to, within Security.framework the
    // argument is ignored and filtering unimplemented. See SecIdentity.cpp in
    // libsecurity_keychain, specifically
    // _SecIdentityCopyPreferenceMatchingName().
    {
      base::AutoLock lock(crypto::GetMacSecurityServicesLock());
      preferred_sec_identity.reset(
          SecIdentityCopyPreferred(domain_str.get(), nullptr, nullptr));
    }
  }

  // Now enumerate the identities in the available keychains.
  std::unique_ptr<ClientCertIdentityMac> preferred_identity;
  ClientCertIdentityMacList regular_identities;

// TODO(crbug.com/40233280): Is it still true, as claimed below, that
// SecIdentitySearchCopyNext sometimes returns identities missed by
// SecItemCopyMatching? Add some histograms to test this and, if none are
// missing, remove this code.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  SecIdentitySearchRef search = nullptr;
  OSStatus err;
  {
    base::AutoLock lock(crypto::GetMacSecurityServicesLock());
    err = SecIdentitySearchCreate(nullptr, CSSM_KEYUSE_SIGN, &search);
  }
  if (err)
    return ClientCertIdentityList();
  ScopedCFTypeRef<SecIdentitySearchRef> scoped_search(search);
  while (!err) {
    ScopedCFTypeRef<SecIdentityRef> sec_identity;
    {
      base::AutoLock lock(crypto::GetMacSecurityServicesLock());
      err = SecIdentitySearchCopyNext(search, sec_identity.InitializeInto());
    }
    if (err)
      break;
    AddIdentity(std::move(sec_identity), preferred_sec_identity.get(),
                &regular_identities, &preferred_identity);
  }

  if (err != errSecItemNotFound) {
    OSSTATUS_LOG(ERROR, err) << "SecIdentitySearch error";
    return ClientCertIdentityList();
  }
#pragma clang diagnostic pop  // "-Wdeprecated-declarations"

  // macOS provides two ways to search for identities. SecIdentitySearchCreate()
  // is deprecated, as it relies on CSSM_KEYUSE_SIGN (part of the deprecated
  // CDSM/CSSA implementation), but is necessary to return some certificates
  // that would otherwise not be returned by SecItemCopyMatching(), which is the
  // non-deprecated way. However, SecIdentitySearchCreate() will not return all
  // items, particularly smart-card based identities, so it's necessary to call
  // both functions.
  static const void* kKeys[] = {
      kSecClass, kSecMatchLimit, kSecReturnRef, kSecAttrCanSign,
  };
  static const void* kValues[] = {
      kSecClassIdentity, kSecMatchLimitAll, kCFBooleanTrue, kCFBooleanTrue,
  };
  ScopedCFTypeRef<CFDictionaryRef> query(CFDictionaryCreate(
      kCFAllocatorDefault, kKeys, kValues, std::size(kValues),
      &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
  ScopedCFTypeRef<CFArrayRef> result;
  {
    base::AutoLock lock(crypto::GetMacSecurityServicesLock());
    err = SecItemCopyMatching(
        query.get(), reinterpret_cast<CFTypeRef*>(result.InitializeInto()));
  }
  if (!err) {
    for (CFIndex i = 0; i < CFArrayGetCount(result.get()); i++) {
      SecIdentityRef item = reinterpret_cast<SecIdentityRef>(
          const_cast<void*>(CFArrayGetValueAtIndex(result.get(), i)));
      AddIdentity(
          ScopedCFTypeRef<SecIdentityRef>(item, base::scoped_policy::RETAIN),
          preferred_sec_identity.get(), &regular_identities,
          &preferred_identity);
    }
  }

  ClientCertIdentityList selected_identities;
  GetClientCertsImpl(std::move(preferred_identity),
                     std::move(regular_identities), *request, true,
                     &selected_identities);
  return selected_identities;
}

}  // namespace

ClientCertStoreMac::ClientCertStoreMac() = default;

ClientCertStoreMac::~ClientCertStoreMac() = default;

void ClientCertStoreMac::GetClientCerts(
    scoped_refptr<const SSLCertRequestInfo> request,
    ClientCertListCallback callback) {
  GetSSLPlatformKeyTaskRunner()->PostTaskAndReplyWithResult(
      FROM_HERE,
      base::BindOnce(&GetClientCertsOnBackgroundThread, std::move(request)),
      base::BindOnce(&ClientCertStoreMac::OnClientCertsResponse,
                     weak_factory_.GetWeakPtr(), std::move(callback)));
}

void ClientCertStoreMac::OnClientCertsResponse(
    ClientCertListCallback callback,
    ClientCertIdentityList identities) {
  std::move(callback).Run(std::move(identities));
}

bool ClientCertStoreMac::SelectClientCertsForTesting(
    ClientCertIdentityMacList input_identities,
    const SSLCertRequestInfo& request,
    ClientCertIdentityList* selected_identities) {
  GetClientCertsImpl(nullptr, std::move(input_identities), request, false,
                     selected_identities);
  return true;
}

bool ClientCertStoreMac::SelectClientCertsGivenPreferredForTesting(
    std::unique_ptr<ClientCertIdentityMac> preferred_identity,
    ClientCertIdentityMacList regular_identities,
    const SSLCertRequestInfo& request,
    ClientCertIdentityList* selected_identities) {
  GetClientCertsImpl(std::move(preferred_identity),
                     std::move(regular_identities), request, false,
                     selected_identities);
  return true;
}

}  // namespace net

"""

```