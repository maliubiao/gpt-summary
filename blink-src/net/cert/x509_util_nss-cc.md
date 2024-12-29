Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Understanding the Goal:**

The core request is to analyze the `net/cert/x509_util_nss.cc` file within the Chromium network stack. The analysis should cover its functions, potential relationships with JavaScript, logical deductions with examples, common user/programming errors, and how a user's actions might lead to this code being executed.

**2. Initial Skim and Key Libraries:**

The first step is to quickly read through the code, paying attention to the `#include` directives. This gives a high-level overview of the involved libraries:

* **NSS (Network Security Services):**  The presence of `<cert.h>`, `<certdb.h>`, `<pk11pub.h>`, etc., immediately signals that this code heavily interacts with NSS, a crucial library for cryptographic operations in Firefox and Chromium. This is the most important piece of information for understanding the file's purpose.
* **Chromium Base Libraries:**  Includes like `base/compiler_specific.h`, `base/logging.h`, `base/strings/stringprintf.h` indicate this is part of the Chromium codebase and uses its utilities.
* **Chromium Crypto Libraries:** `crypto/nss_util.h` and `crypto/scoped_nss_types.h` suggest wrappers and utilities specifically for NSS usage within Chromium.
* **BoringSSL:** `third_party/boringssl/src/include/openssl/pool.h` shows interaction with BoringSSL, Chromium's fork of OpenSSL.
* **`net/cert/x509_util.h`:**  This hints at a broader set of X.509 certificate utilities, with this file being a specific implementation for NSS.
* **`net/third_party/mozilla_security_manager/nsNSSCertificateDB.h`:** This strongly suggests integration with NSS's certificate database.

**3. Identifying Key Functionalities (Iterative Process):**

Now, read through the code function by function, understanding their purpose. This is the core of the analysis. Look for:

* **Function names:**  Descriptive names often reveal the function's intent (e.g., `CreateCERTCertificateFromBytes`, `IsSameCertificate`, `GetDefaultNickname`).
* **Input and output types:**  Pay attention to the data types being passed in and returned. This often clarifies the function's role (e.g., `CERTCertificate*`, `base::span<const uint8_t>`, `ScopedCERTCertificate`).
* **NSS function calls:** Notice functions like `CERT_NewTempCertificate`, `PK11_FindPrivateKeyFromCert`, `CERT_GetCertTimes`, `HASH_HashBuf`. These are the core actions being performed.
* **Logic and control flow:** Understand how the functions manipulate data and make decisions (e.g., the `while` loop in `GetUniqueNicknameForSlot`, the `switch` statement in `GetDefaultNickname`).

As you analyze each function, mentally categorize its role:

* **Creation/Parsing:** Functions that create `CERTCertificate` objects from various sources (bytes, `X509Certificate`).
* **Comparison:** Functions that check if two certificates are the same.
* **Conversion:** Functions that convert between NSS's `CERTCertificate` and Chromium's `X509Certificate`.
* **Encoding/Decoding:** Functions for getting DER and PEM representations.
* **Information Extraction:** Functions to get subject alternative names, nicknames, validity times, etc.
* **Hashing:** Functions for calculating certificate fingerprints.
* **Import:** Functions for importing certificates into the NSS database.
* **Utility/Helper:**  Helper functions like `DecodeAVAValue` and `SECItemAsSpan`.

**4. Identifying Potential JavaScript Relationships:**

The key here is to understand how Chromium's networking stack interacts with the browser's JavaScript environment. Think about common browser features involving certificates:

* **HTTPS Connections:** JavaScript makes requests to HTTPS websites, requiring certificate validation.
* **Certificate Management:**  Browsers allow users to view, import, and manage certificates.
* **Web Crypto API:** JavaScript can use cryptographic functions, potentially involving certificates.

Connect the C++ functionalities to these JavaScript scenarios. For instance:

* Functions creating `X509Certificate` from `CERTCertificate` are relevant when the browser needs to present certificate information to JavaScript.
* Functions related to certificate validation (implicitly through the use of NSS functions for trust evaluation) are crucial for secure HTTPS connections initiated by JavaScript.
* Functions dealing with certificate import are relevant when a user imports a certificate through the browser's settings, an action often triggered by user interaction within the browser UI (which has JavaScript components).

**5. Logical Deductions with Examples:**

For each function, consider a simple input and trace what the code would do, predicting the output. This clarifies the function's behavior and can reveal edge cases. For example, with `GetUniqueNicknameForSlot`:

* **Input:** Nickname "MyCert", subject data, a slot.
* **Logic:**  Check if "MyCert" exists in the slot. If so, try "MyCert #2", then "MyCert #3", etc.
* **Output:**  A unique nickname like "MyCert" or "MyCert #2".

**6. Identifying Common Errors:**

Think about how a developer or the system might misuse these functions:

* **Incorrect data format:** Passing invalid byte arrays to functions expecting DER-encoded certificates.
* **Null pointers:** Failing to handle cases where NSS functions return null.
* **Resource leaks:**  Forgetting to free NSS objects (although the use of `ScopedCERTCertificate` mitigates this).
* **Incorrect assumptions about nicknames:**  Not understanding that nicknames might need token prefixes.

**7. Tracing User Actions:**

Consider how a user's actions in the browser might trigger this code:

* **Visiting an HTTPS website:**  The browser needs to validate the server's certificate.
* **Importing a certificate:**  The browser uses NSS to add the certificate to the store.
* **Exporting a certificate:** The browser retrieves the certificate data from NSS.
* **A website requesting a client certificate:** The browser interacts with the certificate store to select and present a certificate.

Connect these user actions to the C++ functions. For example, when visiting an HTTPS site, the browser might use `CreateCERTCertificateFromBytes` to parse the server's certificate and then use functions like `GetValidityTimes` to check its validity.

**8. Structuring the Output:**

Finally, organize the information clearly, following the structure requested in the prompt:

* **Functionality Summary:** Briefly describe the main purposes of the file.
* **JavaScript Relationship:** Explain how the C++ code interacts with JavaScript, providing concrete examples.
* **Logical Deductions:** Present input/output examples for key functions.
* **Common Errors:** List potential errors and explain how they might occur.
* **User Action Trace:** Describe the steps a user might take to reach this code.

**Self-Correction/Refinement during the Process:**

* **Initial overly broad understanding:**  You might start with a very general idea. As you analyze the functions, refine your understanding to be more specific.
* **Missing key connections:**  You might initially miss some of the JavaScript relationships. Revisit the JavaScript interaction points and see if any C++ functions align.
* **Too technical/not user-friendly:**  Adjust the language to be understandable for someone who might not be a C++ expert, especially when discussing user actions. Focus on the *what* and *why* rather than just the *how*.
* **Lack of concrete examples:**  If your explanations feel abstract, try to come up with specific scenarios and examples to illustrate the concepts.

By following these steps, combining careful code reading with knowledge of web browser architecture and security concepts, you can effectively analyze a complex C++ file like `x509_util_nss.cc`.
这个文件 `net/cert/x509_util_nss.cc` 是 Chromium 网络栈中专门用于处理 X.509 证书的实用工具函数集合，它与 **NSS (Network Security Services)** 库紧密相关。NSS 是一个跨平台的安全库，被 Firefox 和 Chromium 等浏览器用于实现 TLS/SSL 和其他安全功能。

**主要功能列举：**

1. **创建和销毁 NSS 证书对象 (`CERTCertificate`)：**
   - `CreateCERTCertificateFromBytes`: 从原始字节数据（DER 编码）创建 NSS 的证书对象。
   - `CreateCERTCertificateFromX509Certificate`: 从 Chromium 的 `X509Certificate` 对象创建 NSS 证书对象。
   - `CreateCERTCertificateListFromBytes`: 从字节数据创建包含多个证书的列表。
   - `DupCERTCertificate`: 复制一个 NSS 证书对象。
   - `DupCERTCertificateList`: 复制一个 NSS 证书对象列表。

2. **NSS 证书对象与 Chromium 证书对象 (`X509Certificate`) 之间的转换：**
   - `CreateX509CertificateFromCERTCertificate`: 从 NSS 证书对象创建 Chromium 的 `X509Certificate` 对象。
   - `CreateX509CertificateListFromCERTCertificates`: 从 NSS 证书对象列表创建 Chromium 的证书对象列表。

3. **比较 NSS 证书对象：**
   - `IsSameCertificate`: 判断两个 NSS 证书对象是否相同（基于 DER 编码比较）。
   - `IsSameCertificate`: 提供与其他证书表示（如 `X509Certificate`, `CRYPTO_BUFFER`）的比较。

4. **获取证书的编码表示：**
   - `GetDEREncoded`: 获取 NSS 证书的 DER 编码。
   - `GetPEMEncoded`: 获取 NSS 证书的 PEM 编码。

5. **提取证书的各种信息：**
   - `GetRFC822SubjectAltNames`: 获取证书中 Subject Alternative Name 扩展中的 RFC822 (电子邮件) 类型的名称。
   - `GetUPNSubjectAltNames`: 获取证书中 Subject Alternative Name 扩展中的 User Principal Name (UPN)。
   - `GetDefaultNickname`: 获取证书的默认昵称，根据证书类型和内容生成。
   - `GetUniqueNicknameForSlot`: 为证书生成在特定 NSS 槽位中唯一的昵称。
   - `GetDefaultUniqueNickname`: 获取证书在特定槽位中的默认唯一昵称。
   - `GetCERTNameDisplayName`: 从证书的 Subject 或 Issuer 名称中提取用于显示的名称 (通常是 CN、O 或 OU)。
   - `GetValidityTimes`: 获取证书的有效期起始时间和结束时间。

6. **计算证书的哈希值：**
   - `CalculateFingerprint256`: 计算证书的 SHA-256 指纹。

7. **导入用户证书：**
   - `ImportUserCert`: 将证书导入到 NSS 的用户证书数据库中。

8. **其他辅助功能：**
   - `SECItemAsSpan`: 将 NSS 的 `SECItem` 结构体转换为 `base::span`，方便操作。
   - `CERTCertificateAsSpan`: 将 NSS 的 `CERTCertificate` 对象的 DER 编码部分转换为 `base::span`。
   - `DecodeAVAValue`: 解码证书属性值 (Attribute Value Assertion)。

**与 JavaScript 的关系：**

该文件本身是 C++ 代码，JavaScript 无法直接调用其中的函数。然而，它间接地与 JavaScript 的功能有很强的关系，因为：

- **HTTPS 连接：** 当用户通过浏览器访问 HTTPS 网站时，JavaScript 发起的网络请求会触发 Chromium 网络栈进行 TLS 握手。在这个过程中，`x509_util_nss.cc` 中的函数会被调用来处理服务器发送的证书，例如验证证书的有效性、提取证书信息等。
- **Web Crypto API：**  JavaScript 通过 Web Crypto API 可以进行加密解密、签名验签等操作，这些操作可能涉及到证书的管理和使用。`x509_util_nss.cc` 提供的功能可以被 Chromium 用于支持 Web Crypto API 中与证书相关的操作。
- **证书管理界面：**  浏览器通常提供一个界面供用户查看、导入和导出证书。当用户在浏览器设置中操作证书时，底层的 C++ 代码（包括 `x509_util_nss.cc`）会被调用来执行相应的操作。

**举例说明（HTTPS 连接）：**

假设用户在浏览器地址栏输入 `https://example.com` 并回车。

1. **JavaScript 发起请求：** 浏览器渲染进程中的 JavaScript 代码会发起一个网络请求。
2. **网络栈处理：** Chromium 的网络栈接管该请求，并尝试与 `example.com` 的服务器建立 TLS 连接。
3. **证书接收：** 服务器在 TLS 握手过程中会发送其 SSL/TLS 证书。
4. **`CreateCERTCertificateFromBytes` (假设)：**  Chromium 可能会调用 `CreateCERTCertificateFromBytes` 将服务器发送的证书的 DER 编码数据解析成 NSS 的 `CERTCertificate` 对象。
5. **证书验证：**  接下来，可能会调用 NSS 的其他函数（可能被 `x509_util_nss.cc` 中的辅助函数包装）来验证证书的签名、有效期、是否被吊销等。
6. **证书信息提取：**  `GetCERTNameDisplayName` 等函数可能会被调用来提取证书的主题 (Subject) 名称，用于在浏览器的安全提示中显示。
7. **连接建立：** 如果证书验证通过，TLS 连接建立，JavaScript 代码可以安全地与服务器通信。

**逻辑推理，假设输入与输出：**

**函数:** `GetDefaultNickname(CERTCertificate* nss_cert, CertType type)`

**假设输入 1:**
- `nss_cert`: 一个表示用户证书的 `CERTCertificate` 对象，其 Subject 名称包含 "John Doe"，Issuer 名称包含 "CA Inc."。
- `type`: `USER_CERT`

**预期输出 1:**
- 字符串: "John Doe's CA Inc. ID"

**假设输入 2:**
- `nss_cert`: 一个表示 CA 证书的 `CERTCertificate` 对象，其 Subject 名称包含 "Root CA"。
- `type`: `CA_CERT`

**预期输出 2:**
- 字符串:  一个基于 "Root CA" 生成的 CA 证书昵称，具体格式可能由 `CERT_MakeCANickname` 决定，例如 "Root CA"。

**常见的使用错误举例：**

1. **传递无效的 DER 编码数据：**  如果调用 `CreateCERTCertificateFromBytes` 时传递的 `data` 参数不是有效的 DER 编码的证书数据，该函数会返回 `nullptr`。**用户或程序员的错误**：可能从错误的文件或来源读取了证书数据，或者在处理过程中数据被损坏。

2. **忘记释放 NSS 对象：** 虽然代码中使用了 `ScopedCERTCertificate` 等智能指针来管理 NSS 对象的生命周期，但如果直接使用底层的 NSS 函数并且没有正确释放分配的内存，会导致内存泄漏。 **程序员的错误**：未能遵循 NSS 的内存管理规范。

3. **假设昵称的唯一性：**  在添加证书时，如果直接使用 `GetDefaultNickname` 生成的昵称而不调用 `GetUniqueNicknameForSlot` 进行唯一性检查，可能会导致昵称冲突，尤其是在添加来自不同来源但具有相似信息的证书时。 **程序员的错误**：未能充分考虑昵称冲突的可能性。

**用户操作到达此处的调试线索：**

假设用户报告一个 HTTPS 网站的证书错误，或者在使用 Web Crypto API 时遇到证书相关的问题。作为调试人员，可以按照以下步骤追踪：

1. **用户访问 HTTPS 网站：** 用户在浏览器地址栏输入 URL 并访问。网络请求的发送会触发 TLS 握手。
2. **检查网络请求日志：** 使用 Chromium 的 `net-internals` 工具 (在地址栏输入 `chrome://net-internals/#events`) 可以查看网络请求的详细信息，包括证书的加载和验证过程。相关的事件可能会显示证书的 DER 编码数据。
3. **查看证书错误信息：** 如果有证书错误，浏览器会显示相应的错误信息。错误信息中可能包含证书的指纹、主题等信息，这些信息可以通过 `CalculateFingerprint256` 或 `GetCERTNameDisplayName` 等函数提取。
4. **断点调试 Chromium 源码：** 如果有源码调试环境，可以在 `x509_util_nss.cc` 中设置断点，例如在 `CreateCERTCertificateFromBytes` 或证书验证相关的函数处。当用户访问触发问题的网站时，断点会被命中，可以查看当时的证书数据和调用堆栈，从而了解代码是如何执行到这里的。
5. **分析 NSS 日志：**  NSS 库本身也有日志记录功能。配置并查看 NSS 的日志，可以获取更底层的证书处理信息。

**总结：**

`net/cert/x509_util_nss.cc` 是 Chromium 网络栈中一个关键的 C++ 文件，它充当了 Chromium 与 NSS 证书库之间的桥梁，提供了各种实用工具函数来创建、转换、比较和分析 X.509 证书。虽然 JavaScript 不能直接调用它，但它为浏览器处理 HTTPS 连接、支持 Web Crypto API 以及实现证书管理功能提供了必要的底层支持。理解这个文件的功能对于调试网络安全相关问题至关重要。

Prompt: 
```
这是目录为net/cert/x509_util_nss.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/x509_util_nss.h"

#include <cert.h>  // Must be included before certdb.h
#include <certdb.h>
#include <cryptohi.h>
#include <dlfcn.h>
#include <nss.h>
#include <pk11pub.h>
#include <prerror.h>
#include <seccomon.h>
#include <secder.h>
#include <sechash.h>
#include <secmod.h>
#include <secport.h>
#include <string.h>

#include "base/compiler_specific.h"
#include "base/logging.h"
#include "base/strings/stringprintf.h"
#include "crypto/nss_util.h"
#include "crypto/scoped_nss_types.h"
#include "net/cert/x509_util.h"
#include "net/third_party/mozilla_security_manager/nsNSSCertificateDB.h"
#include "third_party/boringssl/src/include/openssl/pool.h"

namespace net::x509_util {

namespace {

// Microsoft User Principal Name: 1.3.6.1.4.1.311.20.2.3
const uint8_t kUpnOid[] = {0x2b, 0x6,  0x1,  0x4, 0x1,
                           0x82, 0x37, 0x14, 0x2, 0x3};

std::string DecodeAVAValue(CERTAVA* ava) {
  SECItem* decode_item = CERT_DecodeAVAValue(&ava->value);
  if (!decode_item)
    return std::string();
  std::string value(base::as_string_view(SECItemAsSpan(*decode_item)));
  SECITEM_FreeItem(decode_item, PR_TRUE);
  return value;
}

// Generates a unique nickname for |slot|, returning |nickname| if it is
// already unique.
//
// Note: The nickname returned will NOT include the token name, thus the
// token name must be prepended if calling an NSS function that expects
// <token>:<nickname>.
// TODO(gspencer): Internationalize this: it's wrong to hard-code English.
std::string GetUniqueNicknameForSlot(const std::string& nickname,
                                     const SECItem* subject,
                                     PK11SlotInfo* slot) {
  int index = 2;
  std::string new_name = nickname;
  std::string temp_nickname = new_name;
  std::string token_name;

  if (!slot)
    return new_name;

  if (!PK11_IsInternalKeySlot(slot)) {
    token_name.assign(PK11_GetTokenName(slot));
    token_name.append(":");

    temp_nickname = token_name + new_name;
  }

  while (SEC_CertNicknameConflict(temp_nickname.c_str(),
                                  const_cast<SECItem*>(subject),
                                  CERT_GetDefaultCertDB())) {
    new_name = base::StringPrintf("%s #%d", nickname.c_str(), index++);
    temp_nickname = token_name + new_name;
  }

  return new_name;
}

// The default nickname of the certificate, based on the certificate type
// passed in.
std::string GetDefaultNickname(CERTCertificate* nss_cert, CertType type) {
  std::string result;
  if (type == USER_CERT && nss_cert->slot) {
    // Find the private key for this certificate and see if it has a
    // nickname.  If there is a private key, and it has a nickname, then
    // return that nickname.
    SECKEYPrivateKey* private_key = PK11_FindPrivateKeyFromCert(
        nss_cert->slot, nss_cert, nullptr /*wincx*/);
    if (private_key) {
      char* private_key_nickname = PK11_GetPrivateKeyNickname(private_key);
      if (private_key_nickname) {
        result = private_key_nickname;
        PORT_Free(private_key_nickname);
        SECKEY_DestroyPrivateKey(private_key);
        return result;
      }
      SECKEY_DestroyPrivateKey(private_key);
    }
  }

  switch (type) {
    case CA_CERT: {
      char* nickname = CERT_MakeCANickname(nss_cert);
      result = nickname;
      PORT_Free(nickname);
      break;
    }
    case USER_CERT: {
      std::string subject_name = GetCERTNameDisplayName(&nss_cert->subject);
      if (subject_name.empty()) {
        const char* email = CERT_GetFirstEmailAddress(nss_cert);
        if (email)
          subject_name = email;
      }
      // TODO(gspencer): Internationalize this. It's wrong to assume English
      // here.
      result =
          base::StringPrintf("%s's %s ID", subject_name.c_str(),
                             GetCERTNameDisplayName(&nss_cert->issuer).c_str());
      break;
    }
    case SERVER_CERT: {
      result = GetCERTNameDisplayName(&nss_cert->subject);
      break;
    }
    case OTHER_CERT:
    default:
      break;
  }
  return result;
}

}  // namespace

base::span<const uint8_t> SECItemAsSpan(const SECItem& item) {
  // SAFETY: item is an NSS SECItem struct that represents an array of bytes
  // pointed to by `data` of length `len`.
  return UNSAFE_BUFFERS(base::make_span(item.data, item.len));
}

base::span<const uint8_t> CERTCertificateAsSpan(
    const CERTCertificate* nss_cert) {
  return SECItemAsSpan(nss_cert->derCert);
}

bool IsSameCertificate(CERTCertificate* a, CERTCertificate* b) {
  DCHECK(a && b);
  if (a == b)
    return true;
  return CERTCertificateAsSpan(a) == CERTCertificateAsSpan(b);
}

bool IsSameCertificate(CERTCertificate* a, const X509Certificate* b) {
  return IsSameCertificate(a, b->cert_buffer());
}
bool IsSameCertificate(const X509Certificate* a, CERTCertificate* b) {
  return IsSameCertificate(b, a->cert_buffer());
}

bool IsSameCertificate(CERTCertificate* a, const CRYPTO_BUFFER* b) {
  return CERTCertificateAsSpan(a) == CryptoBufferAsSpan(b);
}
bool IsSameCertificate(const CRYPTO_BUFFER* a, CERTCertificate* b) {
  return IsSameCertificate(b, a);
}

ScopedCERTCertificate CreateCERTCertificateFromBytes(
    base::span<const uint8_t> data) {
  crypto::EnsureNSSInit();

  if (!NSS_IsInitialized())
    return nullptr;

  SECItem der_cert;
  der_cert.data = const_cast<uint8_t*>(data.data());
  der_cert.len = base::checked_cast<unsigned>(data.size());
  der_cert.type = siDERCertBuffer;

  // Parse into a certificate structure.
  return ScopedCERTCertificate(CERT_NewTempCertificate(
      CERT_GetDefaultCertDB(), &der_cert, nullptr /* nickname */,
      PR_FALSE /* is_perm */, PR_TRUE /* copyDER */));
}

ScopedCERTCertificate CreateCERTCertificateFromX509Certificate(
    const X509Certificate* cert) {
  return CreateCERTCertificateFromBytes(
      CryptoBufferAsSpan(cert->cert_buffer()));
}

ScopedCERTCertificateList CreateCERTCertificateListFromX509Certificate(
    const X509Certificate* cert) {
  return x509_util::CreateCERTCertificateListFromX509Certificate(
      cert, InvalidIntermediateBehavior::kFail);
}

ScopedCERTCertificateList CreateCERTCertificateListFromX509Certificate(
    const X509Certificate* cert,
    InvalidIntermediateBehavior invalid_intermediate_behavior) {
  ScopedCERTCertificateList nss_chain;
  nss_chain.reserve(1 + cert->intermediate_buffers().size());
  ScopedCERTCertificate nss_cert =
      CreateCERTCertificateFromX509Certificate(cert);
  if (!nss_cert)
    return {};
  nss_chain.push_back(std::move(nss_cert));
  for (const auto& intermediate : cert->intermediate_buffers()) {
    ScopedCERTCertificate nss_intermediate =
        CreateCERTCertificateFromBytes(CryptoBufferAsSpan(intermediate.get()));
    if (!nss_intermediate) {
      if (invalid_intermediate_behavior == InvalidIntermediateBehavior::kFail)
        return {};
      LOG(WARNING) << "error parsing intermediate";
      continue;
    }
    nss_chain.push_back(std::move(nss_intermediate));
  }
  return nss_chain;
}

ScopedCERTCertificateList CreateCERTCertificateListFromBytes(
    base::span<const uint8_t> data,
    int format) {
  CertificateList certs =
      X509Certificate::CreateCertificateListFromBytes(data, format);
  ScopedCERTCertificateList nss_chain;
  nss_chain.reserve(certs.size());
  for (const scoped_refptr<X509Certificate>& cert : certs) {
    ScopedCERTCertificate nss_cert =
        CreateCERTCertificateFromX509Certificate(cert.get());
    if (!nss_cert)
      return {};
    nss_chain.push_back(std::move(nss_cert));
  }
  return nss_chain;
}

ScopedCERTCertificate DupCERTCertificate(CERTCertificate* cert) {
  return ScopedCERTCertificate(CERT_DupCertificate(cert));
}

ScopedCERTCertificateList DupCERTCertificateList(
    const ScopedCERTCertificateList& certs) {
  ScopedCERTCertificateList result;
  result.reserve(certs.size());
  for (const ScopedCERTCertificate& cert : certs)
    result.push_back(DupCERTCertificate(cert.get()));
  return result;
}

scoped_refptr<X509Certificate> CreateX509CertificateFromCERTCertificate(
    CERTCertificate* nss_cert,
    const std::vector<CERTCertificate*>& nss_chain) {
  return CreateX509CertificateFromCERTCertificate(nss_cert, nss_chain, {});
}

scoped_refptr<X509Certificate> CreateX509CertificateFromCERTCertificate(
    CERTCertificate* nss_cert,
    const std::vector<CERTCertificate*>& nss_chain,
    X509Certificate::UnsafeCreateOptions options) {
  if (!nss_cert || !nss_cert->derCert.len) {
    return nullptr;
  }
  bssl::UniquePtr<CRYPTO_BUFFER> cert_handle(
      x509_util::CreateCryptoBuffer(CERTCertificateAsSpan(nss_cert)));

  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
  intermediates.reserve(nss_chain.size());
  for (const CERTCertificate* nss_intermediate : nss_chain) {
    if (!nss_intermediate || !nss_intermediate->derCert.len) {
      return nullptr;
    }
    intermediates.push_back(
        x509_util::CreateCryptoBuffer(CERTCertificateAsSpan(nss_intermediate)));
  }

  return X509Certificate::CreateFromBufferUnsafeOptions(
      std::move(cert_handle), std::move(intermediates), options);
}

scoped_refptr<X509Certificate> CreateX509CertificateFromCERTCertificate(
    CERTCertificate* cert) {
  return CreateX509CertificateFromCERTCertificate(
      cert, std::vector<CERTCertificate*>());
}

CertificateList CreateX509CertificateListFromCERTCertificates(
    const ScopedCERTCertificateList& certs) {
  CertificateList result;
  result.reserve(certs.size());
  for (const ScopedCERTCertificate& cert : certs) {
    scoped_refptr<X509Certificate> x509_cert(
        CreateX509CertificateFromCERTCertificate(cert.get()));
    if (!x509_cert)
      return {};
    result.push_back(std::move(x509_cert));
  }
  return result;
}

bool GetDEREncoded(CERTCertificate* cert, std::string* der_encoded) {
  if (!cert || !cert->derCert.len)
    return false;
  *der_encoded = base::as_string_view(CERTCertificateAsSpan(cert));
  return true;
}

bool GetPEMEncoded(CERTCertificate* cert, std::string* pem_encoded) {
  if (!cert || !cert->derCert.len)
    return false;
  return X509Certificate::GetPEMEncodedFromDER(
      base::as_string_view(CERTCertificateAsSpan(cert)), pem_encoded);
}

void GetRFC822SubjectAltNames(CERTCertificate* cert_handle,
                              std::vector<std::string>* names) {
  crypto::ScopedSECItem alt_name(SECITEM_AllocItem(nullptr, nullptr, 0));
  DCHECK(alt_name.get());

  names->clear();
  SECStatus rv = CERT_FindCertExtension(
      cert_handle, SEC_OID_X509_SUBJECT_ALT_NAME, alt_name.get());
  if (rv != SECSuccess)
    return;

  crypto::ScopedPLArenaPool arena(PORT_NewArena(DER_DEFAULT_CHUNKSIZE));
  DCHECK(arena.get());

  CERTGeneralName* alt_name_list;
  alt_name_list = CERT_DecodeAltNameExtension(arena.get(), alt_name.get());

  CERTGeneralName* name = alt_name_list;
  while (name) {
    if (name->type == certRFC822Name) {
      names->emplace_back(
          base::as_string_view(SECItemAsSpan(name->name.other)));
    }
    name = CERT_GetNextGeneralName(name);
    if (name == alt_name_list)
      break;
  }
}

void GetUPNSubjectAltNames(CERTCertificate* cert_handle,
                           std::vector<std::string>* names) {
  crypto::ScopedSECItem alt_name(SECITEM_AllocItem(nullptr, nullptr, 0));
  DCHECK(alt_name.get());

  names->clear();
  SECStatus rv = CERT_FindCertExtension(
      cert_handle, SEC_OID_X509_SUBJECT_ALT_NAME, alt_name.get());
  if (rv != SECSuccess)
    return;

  crypto::ScopedPLArenaPool arena(PORT_NewArena(DER_DEFAULT_CHUNKSIZE));
  DCHECK(arena.get());

  CERTGeneralName* alt_name_list;
  alt_name_list = CERT_DecodeAltNameExtension(arena.get(), alt_name.get());

  CERTGeneralName* name = alt_name_list;
  while (name) {
    if (name->type == certOtherName) {
      OtherName* on = &name->name.OthName;
      if (SECItemAsSpan(on->oid) == kUpnOid) {
        SECItem decoded;
        if (SEC_QuickDERDecodeItem(arena.get(), &decoded,
                                   SEC_ASN1_GET(SEC_UTF8StringTemplate),
                                   &name->name.OthName.name) == SECSuccess) {
          names->emplace_back(base::as_string_view(SECItemAsSpan(decoded)));
        }
      }
    }
    name = CERT_GetNextGeneralName(name);
    if (name == alt_name_list)
      break;
  }
}

std::string GetDefaultUniqueNickname(CERTCertificate* nss_cert,
                                     CertType type,
                                     PK11SlotInfo* slot) {
  return GetUniqueNicknameForSlot(GetDefaultNickname(nss_cert, type),
                                  &nss_cert->derSubject, slot);
}

std::string GetCERTNameDisplayName(CERTName* name) {
  // Search for attributes in the Name, in this order: CN, O and OU.
  CERTAVA* ou_ava = nullptr;
  CERTAVA* o_ava = nullptr;
  CERTRDN** rdns = name->rdns;
  // SAFETY: TODO(crbug.com/40284755): Add a helper for iterating over
  // null-terminated arrays, or delete the code that uses this, or convert it
  // to use our own certificate parsing functions.
  UNSAFE_BUFFERS(for (size_t rdn = 0; rdns[rdn]; ++rdn) {
    CERTAVA** avas = rdns[rdn]->avas;
    for (size_t pair = 0; avas[pair] != nullptr; ++pair) {
      SECOidTag tag = CERT_GetAVATag(avas[pair]);
      if (tag == SEC_OID_AVA_COMMON_NAME) {
        // If CN is found, return immediately.
        return DecodeAVAValue(avas[pair]);
      }
      // If O or OU is found, save the first one of each so that it can be
      // returned later if no CN attribute is found.
      if (tag == SEC_OID_AVA_ORGANIZATION_NAME && !o_ava)
        o_ava = avas[pair];
      if (tag == SEC_OID_AVA_ORGANIZATIONAL_UNIT_NAME && !ou_ava)
        ou_ava = avas[pair];
    }
  });
  if (o_ava)
    return DecodeAVAValue(o_ava);
  if (ou_ava)
    return DecodeAVAValue(ou_ava);
  return std::string();
}

bool GetValidityTimes(CERTCertificate* cert,
                      base::Time* not_before,
                      base::Time* not_after) {
  PRTime pr_not_before, pr_not_after;
  if (CERT_GetCertTimes(cert, &pr_not_before, &pr_not_after) == SECSuccess) {
    if (not_before)
      *not_before = crypto::PRTimeToBaseTime(pr_not_before);
    if (not_after)
      *not_after = crypto::PRTimeToBaseTime(pr_not_after);
    return true;
  }
  return false;
}

SHA256HashValue CalculateFingerprint256(CERTCertificate* cert) {
  SHA256HashValue sha256;
  memset(sha256.data, 0, sizeof(sha256.data));

  DCHECK(cert->derCert.data);
  DCHECK_NE(0U, cert->derCert.len);

  SECStatus rv = HASH_HashBuf(HASH_AlgSHA256, sha256.data, cert->derCert.data,
                              cert->derCert.len);
  DCHECK_EQ(SECSuccess, rv);

  return sha256;
}

int ImportUserCert(CERTCertificate* cert,
                   crypto::ScopedPK11Slot preferred_slot) {
  return mozilla_security_manager::ImportUserCert(cert,
                                                  std::move(preferred_slot));
}

}  // namespace net::x509_util

"""

```