Response:
Let's break down the thought process for analyzing this C++ code and generating the response.

**1. Understanding the Goal:**

The request asks for a functional breakdown of the `ssl_platform_key_win.cc` file within the Chromium network stack, specifically looking for connections to JavaScript, logical reasoning, common usage errors, and debugging steps to reach this code.

**2. Initial Code Scan and Keyword Recognition:**

I started by quickly scanning the code for key terms and patterns:

* **Includes:**  `net/ssl/`, `crypto/`, `third_party/boringssl/`, `#ifdef`, `namespace net`. This immediately tells me it's related to SSL/TLS functionality, cryptography (specifically on Windows), and uses BoringSSL. The `#ifdef UNSAFE_BUFFERS_BUILD` suggests conditional compilation for development/testing.
* **Class Names:** `SSLPlatformKeyCAPI`, `SSLPlatformKeyCNG`. The suffixes "CAPI" and "CNG" are strong indicators of interaction with the Windows CryptoAPI and Cryptography Next Generation API.
* **Function Names:**  `WrapCAPIPrivateKey`, `WrapCNGPrivateKey`, `FetchClientCertPrivateKey`, `WrapUnexportableKeySlowly`, `Sign`, `GetAlgorithmPreferences`, `ProbeSHA256`. These names directly relate to wrapping and using private keys for cryptographic operations.
* **Data Structures/Types:** `HCRYPTPROV`, `NCRYPT_KEY_HANDLE`, `X509Certificate`, `SSLPrivateKey`, `EVP_MD`. These are core cryptographic types in Windows and OpenSSL.
* **Error Handling:**  `net::Error`, `ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED`, `PLOG(ERROR)`, `FAILED(status)`. This highlights the error-prone nature of cryptographic operations and the need for careful handling.
* **Specific Windows API calls:** `CryptGetProvParam`, `CryptCreateHash`, `CryptSignHash`, `CryptAcquireCertificatePrivateKey`, `NCryptGetProperty`, `NCryptSignHash`. These confirm direct interaction with the Windows cryptographic subsystems.
* **BoringSSL functions:** `SSL_get_signature_algorithm_digest`, `EVP_Digest`, `SSL_get_signature_algorithm_key_type`, `SSL_is_signature_algorithm_rsa_pss`, `ECDSA_SIG_new`, `BN_bin2bn`, `i2d_ECDSA_SIG`. This confirms the use of BoringSSL for the underlying cryptographic primitives.

**3. Deconstructing the Functionality - Core Logic:**

Based on the keywords, I deduced the main purpose: this code is about handling client certificates and their associated private keys on Windows, leveraging either the older CAPI or the newer CNG.

* **`SSLPlatformKeyCAPI`:** Wraps a CAPI private key handle (`HCRYPTPROV`). It handles signing operations using the CAPI. The `ProbeSHA256` function is a clever way to detect if the CAPI provider supports SHA-256 and adjust algorithm preferences accordingly.
* **`SSLPlatformKeyCNG`:** Wraps a CNG private key handle (`NCRYPT_KEY_HANDLE`). It handles signing using the CNG API. It has similar logic for adjusting algorithm preferences based on key size and TPM capabilities. It also handles the conversion of raw ECDSA signatures to DER format.
* **`WrapCAPIPrivateKey` and `WrapCNGPrivateKey`:** These are factory functions to create `SSLPrivateKey` objects from the underlying CAPI/CNG handles. They use `ThreadedSSLPrivateKey` to perform operations on a separate thread, preventing blocking the main browser process.
* **`FetchClientCertPrivateKey`:** This is the crucial function for retrieving the private key associated with a client certificate from the Windows certificate store. It attempts to acquire the private key handle, preferring CNG, and then wraps it appropriately.
* **`WrapUnexportableKeySlowly`:** This handles the case of unexportable keys (likely TPM-backed), retrieving the key handle and wrapping it using CNG.

**4. Addressing Specific Request Points:**

* **Functionality Listing:** Based on the deconstruction, I could list the core functionalities (wrapping, signing, algorithm preference, fetching).
* **Relationship to JavaScript:** This required inferring the connection. JavaScript in a browser *cannot* directly access these native Windows cryptographic APIs. The connection is through the browser's internal workings. The browser uses this C++ code to handle client authentication, which is triggered by JavaScript making HTTPS requests to servers requiring client certificates. The example scenarios illustrate this indirect relationship.
* **Logical Reasoning (Input/Output):**  For `ProbeSHA256`, it's straightforward. For the signing functions, the input is the signing algorithm and data, and the output is the signature. I made sure to highlight the platform-specific details (little-endian for CAPI, raw ECDSA for CNG).
* **User/Programming Errors:**  I focused on common issues: incorrect certificate setup, missing drivers, and API usage errors (like not freeing resources).
* **User Operation to Reach the Code (Debugging):**  This involved thinking about the typical flow of client certificate authentication: user initiates an HTTPS request, the server requests a certificate, the browser interacts with the OS to find a suitable certificate and its private key. I outlined these steps.

**5. Refinement and Organization:**

Finally, I organized the information logically, using headings and bullet points for clarity. I reviewed the generated text to ensure accuracy and completeness, making sure to connect the low-level C++ code to the higher-level user experience. I double-checked the explanation of the JavaScript interaction to be precise and avoid implying direct access. I also made sure to explain the purpose of `ThreadedSSLPrivateKey` for context.
这个文件 `net/ssl/ssl_platform_key_win.cc` 是 Chromium 网络栈中专门用于处理 Windows 平台上 SSL/TLS 客户端证书私钥的核心组件。它负责桥接 Chromium 的 SSL 代码和 Windows 操作系统提供的加密 API (CAPI 和 CNG)。

以下是它的主要功能：

**1. 封装 Windows 平台私钥句柄:**

*   **支持 CAPI (Cryptographic API):**  通过 `SSLPlatformKeyCAPI` 类，封装由 Windows CAPI 管理的私钥句柄 (`HCRYPTPROV`)。这通常用于旧式的证书存储和硬件 token。
*   **支持 CNG (Cryptography Next Generation):** 通过 `SSLPlatformKeyCNG` 类，封装由 Windows CNG 管理的私钥句柄 (`NCRYPT_KEY_HANDLE`)。这是较新的、更推荐使用的 API。
*   这些封装类实现了 `ThreadedSSLPrivateKey::Delegate` 接口，使得私钥操作（如签名）可以在单独的线程中执行，避免阻塞浏览器的主线程。

**2. 实现签名操作:**

*   `SSLPlatformKeyCAPI::Sign` 和 `SSLPlatformKeyCNG::Sign` 方法负责使用 Windows 的加密 API 对数据进行签名。
*   它们根据传入的签名算法 (`algorithm`)，使用相应的 CAPI 或 CNG 函数（如 `CryptSignHash` 或 `NCryptSignHash`）执行签名。
*   需要注意的是，CAPI 签名结果是小端序，因此代码中会进行反转。CNG 对于 ECDSA 签名会产生原始格式，需要转换为 DER 编码。

**3. 获取算法偏好:**

*   `SSLPlatformKeyCAPI::GetAlgorithmPreferences` 和 `SSLPlatformKeyCNG::GetAlgorithmPreferences` 方法返回此私钥支持的签名算法列表。
*   它们会根据私钥的类型和提供者的能力进行调整。例如，对于某些旧的智能卡，可能只支持 SHA-1 签名。`ProbeSHA256` 函数用于检测 CAPI 提供者是否支持 SHA-256。
*   对于 CNG 和 TPM 密钥，会考虑对 RSA-PSS 签名的支持，特别是对于 TPM，需要检查盐的长度是否与摘要长度匹配以确保与 TLS 兼容。

**4. 获取私钥句柄:**

*   `FetchClientCertPrivateKey` 函数尝试从 Windows 证书存储中获取与给定证书关联的私钥句柄。
*   它优先尝试使用 CNG，如果失败则回退到 CAPI。
*   它使用 `CryptAcquireCertificatePrivateKey` API 来获取私钥句柄。

**5. 处理不可导出的私钥:**

*   `WrapUnexportableKeySlowly` 函数用于处理那些无法直接导出私钥材料的密钥，例如存储在 TPM (Trusted Platform Module) 中的密钥。
*   它通过 `crypto::UnexportableSigningKey` 接口获取封装的密钥数据，然后使用 CNG API 加载并封装该密钥。

**与 JavaScript 的关系及举例说明:**

该文件本身不包含 JavaScript 代码，但它提供的功能是浏览器安全通信的关键部分，而这直接影响到 Web 应用的安全性。当 JavaScript 发起需要客户端证书认证的 HTTPS 请求时，这个文件中的代码会被调用。

**举例说明:**

1. **用户尝试访问需要客户端证书的网站:**
    *   JavaScript 代码（例如，通过 `fetch` API 或 `XMLHttpRequest`）发起一个 HTTPS 请求到某个服务器。
    *   服务器要求客户端提供证书进行身份验证。
    *   浏览器会提示用户选择一个客户端证书。
    *   一旦用户选择了证书，Chromium 的网络栈会调用 `FetchClientCertPrivateKey` 来获取与该证书关联的私钥句柄。
    *   如果私钥由 Windows 的 CAPI 或 CNG 管理，那么 `WrapCAPIPrivateKey` 或 `WrapCNGPrivateKey` 会被调用，创建 `SSLPrivateKey` 对象。
    *   当需要对握手消息进行签名时，例如在 TLS 握手期间的 `CertificateVerify` 消息，`SSLPlatformKeyCAPI::Sign` 或 `SSLPlatformKeyCNG::Sign` 会被调用，使用 Windows 的加密 API 进行签名。
    *   签名后的数据会被发送到服务器进行验证。

**逻辑推理 (假设输入与输出):**

**假设输入 (针对 `SSLPlatformKeyCNG::Sign`):**

*   `algorithm`: `SSL_SIGN_RSA_PKCS1_SHA256` (表示使用 RSA PKCS#1 v1.5 签名，使用 SHA-256 摘要)
*   `input`:  一个包含要签名数据的 `base::span<const uint8_t>`，例如 TLS 握手消息的摘要。

**输出:**

*   `signature`: 一个 `std::vector<uint8_t>`，包含使用 CNG API 和指定的私钥，对输入数据进行 RSA PKCS#1 v1.5 SHA-256 签名后的结果。

**假设输入 (针对 `ProbeSHA256`):**

*   `delegate`: 一个指向 `ThreadedSSLPrivateKey::Delegate` 实现的指针，例如 `SSLPlatformKeyCAPI` 的实例。

**输出:**

*   `true`: 如果私钥能够使用 SHA-256 算法成功签名预定义的数据。
*   `false`: 如果签名失败，表明该私钥或其提供者不支持 SHA-256。

**用户或编程常见的使用错误及举例说明:**

1. **客户端证书未正确安装或关联私钥:**
    *   **用户错误:** 用户可能导入了证书，但私钥没有正确导入，或者证书和私钥没有正确关联。
    *   **表现:** 当浏览器尝试使用该证书进行身份验证时，`FetchClientCertPrivateKey` 可能会返回空指针，或者签名操作失败。

2. **智能卡驱动程序问题:**
    *   **用户错误/系统错误:** 如果客户端证书存储在智能卡上，但智能卡驱动程序未正确安装或出现故障，可能导致无法访问私钥。
    *   **表现:** `CryptAcquireCertificatePrivateKey` 可能会失败，并显示与驱动程序相关的错误代码。日志中可能会出现 "Could not acquire private key" 的警告。

3. **权限问题:**
    *   **编程错误/系统配置错误:**  运行 Chromium 的进程可能没有足够的权限访问存储私钥的密钥容器。
    *   **表现:** 尝试获取私钥句柄或进行签名操作时，Windows API 可能会返回权限相关的错误。

4. **不支持的签名算法:**
    *   **编程错误:**  Chromium 尝试使用客户端证书不支持的签名算法进行签名。
    *   **表现:**  `SSLPlatformKeyCAPI::Sign` 或 `SSLPlatformKeyCNG::Sign` 中，调用 Windows API 进行签名时会失败，返回 `ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED`。`GetAlgorithmPreferences` 的逻辑旨在避免这种情况，但如果服务器强制使用不支持的算法，仍然可能发生。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户尝试访问一个需要客户端证书认证的 HTTPS 网站。** 例如，一个企业内部的应用或某些政府服务网站。
2. **服务器在 TLS 握手阶段发送 `CertificateRequest` 消息。** 这告知客户端需要提供证书。
3. **Chromium 接收到 `CertificateRequest`，并检查系统上可用的客户端证书。**
4. **如果找到匹配的证书，Chromium 会尝试获取与该证书关联的私钥。** 这时会调用 `FetchClientCertPrivateKey`，传入证书的上下文 (`PCCERT_CONTEXT`)。
5. **`FetchClientCertPrivateKey` 内部会调用 `CryptAcquireCertificatePrivateKey` 来获取私钥句柄。**
6. **根据获取到的句柄类型 (`CERT_NCRYPT_KEY_SPEC` 或其他)，会调用 `WrapCNGPrivateKey` 或 `WrapCAPIPrivateKey` 来创建 `SSLPrivateKey` 对象。**
7. **在 TLS 握手过程中，当需要生成 `CertificateVerify` 消息时，会调用 `SSLPrivateKey::Sign` 方法。** 对于 Windows 平台，这最终会调用到 `SSLPlatformKeyCAPI::Sign` 或 `SSLPlatformKeyCNG::Sign`。
8. **在 `Sign` 方法内部，会调用 Windows 的 CAPI 或 CNG API (如 `CryptSignHash` 或 `NCryptSignHash`) 来执行实际的签名操作。**

**调试线索:**

*   **网络日志 (net-internals):** 可以查看 TLS 握手过程，确认服务器是否请求客户端证书，以及客户端是否成功发送了 `CertificateVerify` 消息。如果 `CertificateVerify` 发送失败，可能是私钥问题。
*   **Windows 事件查看器:**  如果签名操作失败，Windows 可能会记录相关的加密错误事件，提供更详细的错误信息。
*   **Chromium 日志:** 启用 Chromium 的网络日志 (例如，通过 `--enable-logging --v=1`) 可以查看 `FetchClientCertPrivateKey` 和 `Sign` 方法的执行情况，以及任何相关的错误信息。
*   **断点调试:**  在 `net/ssl/ssl_platform_key_win.cc` 中设置断点，可以逐步跟踪私钥的获取和签名过程，查看 Windows API 的返回值和参数，帮助定位问题。
*   **检查客户端证书状态:**  在 Windows 证书管理器中检查客户端证书的状态，确认证书是否有效，并且关联了私钥。

总而言之，`net/ssl/ssl_platform_key_win.cc` 是 Chromium 在 Windows 平台上处理客户端证书私钥的关键桥梁，它负责与 Windows 的加密 API 交互，完成签名等操作，确保安全的客户端身份验证。理解这个文件的功能对于调试客户端证书相关的问题至关重要。

Prompt: 
```
这是目录为net/ssl/ssl_platform_key_win.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/ssl/ssl_platform_key_win.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/logging.h"
#include "base/ranges/algorithm.h"
#include "base/strings/utf_string_conversions.h"
#include "crypto/openssl_util.h"
#include "crypto/scoped_capi_types.h"
#include "crypto/scoped_cng_types.h"
#include "crypto/unexportable_key_win.h"
#include "net/base/net_errors.h"
#include "net/cert/x509_certificate.h"
#include "net/ssl/ssl_platform_key_util.h"
#include "net/ssl/ssl_private_key.h"
#include "net/ssl/threaded_ssl_private_key.h"
#include "third_party/boringssl/src/include/openssl/bn.h"
#include "third_party/boringssl/src/include/openssl/ecdsa.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"

namespace net {

namespace {

bool ProbeSHA256(ThreadedSSLPrivateKey::Delegate* delegate) {
  // This input is chosen to avoid colliding with other signing inputs used in
  // TLS 1.2 or TLS 1.3. We use the construct in RFC 8446, section 4.4.3, but
  // change the context string. The context string ensures we don't collide with
  // TLS 1.3 and any future version. The 0x20 (space) prefix ensures we don't
  // collide with TLS 1.2 ServerKeyExchange or CertificateVerify.
  static const uint8_t kSHA256ProbeInput[] = {
      0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
      0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
      0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
      0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
      0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
      0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 'C',  'h',
      'r',  'o',  'm',  'i',  'u',  'm',  ',',  ' ',  'S',  'H',  'A',
      '2',  ' ',  'P',  'r',  'o',  'b',  'e',  0x00,
  };
  std::vector<uint8_t> signature;
  return delegate->Sign(SSL_SIGN_RSA_PKCS1_SHA256, kSHA256ProbeInput,
                        &signature) == OK;
}

std::string GetCAPIProviderName(HCRYPTPROV provider) {
  DWORD name_len;
  if (!CryptGetProvParam(provider, PP_NAME, nullptr, &name_len, 0)) {
    return "(error getting name)";
  }
  std::vector<BYTE> name(name_len);
  if (!CryptGetProvParam(provider, PP_NAME, name.data(), &name_len, 0)) {
    return "(error getting name)";
  }
  // Per Microsoft's documentation, PP_NAME is NUL-terminated. However,
  // smartcard drivers are notoriously buggy, so check this.
  auto nul = base::ranges::find(name, 0);
  if (nul != name.end()) {
    name_len = nul - name.begin();
  }
  return std::string(reinterpret_cast<const char*>(name.data()), name_len);
}

class SSLPlatformKeyCAPI : public ThreadedSSLPrivateKey::Delegate {
 public:
  // Takes ownership of |provider|.
  SSLPlatformKeyCAPI(crypto::ScopedHCRYPTPROV provider, DWORD key_spec)
      : provider_name_(GetCAPIProviderName(provider.get())),
        provider_(std::move(provider)),
        key_spec_(key_spec) {
    // Check for SHA-256 support. The CAPI service provider may only be able to
    // sign pre-TLS-1.2 and SHA-1 hashes. If SHA-256 doesn't work, prioritize
    // SHA-1 as a workaround. See https://crbug.com/278370.
    prefer_sha1_ = !ProbeSHA256(this);
  }

  SSLPlatformKeyCAPI(const SSLPlatformKeyCAPI&) = delete;
  SSLPlatformKeyCAPI& operator=(const SSLPlatformKeyCAPI&) = delete;

  ~SSLPlatformKeyCAPI() override = default;

  std::string GetProviderName() override { return "CAPI: " + provider_name_; }

  std::vector<uint16_t> GetAlgorithmPreferences() override {
    if (prefer_sha1_) {
      return {SSL_SIGN_RSA_PKCS1_SHA1, SSL_SIGN_RSA_PKCS1_SHA256,
              SSL_SIGN_RSA_PKCS1_SHA384, SSL_SIGN_RSA_PKCS1_SHA512};
    }
    return {SSL_SIGN_RSA_PKCS1_SHA256, SSL_SIGN_RSA_PKCS1_SHA384,
            SSL_SIGN_RSA_PKCS1_SHA512, SSL_SIGN_RSA_PKCS1_SHA1};
  }

  Error Sign(uint16_t algorithm,
             base::span<const uint8_t> input,
             std::vector<uint8_t>* signature) override {
    const EVP_MD* md = SSL_get_signature_algorithm_digest(algorithm);
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned digest_len;
    if (!md || !EVP_Digest(input.data(), input.size(), digest, &digest_len, md,
                           nullptr)) {
      return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
    }

    ALG_ID hash_alg;
    switch (EVP_MD_type(md)) {
      case NID_md5_sha1:
        hash_alg = CALG_SSL3_SHAMD5;
        break;
      case NID_sha1:
        hash_alg = CALG_SHA1;
        break;
      case NID_sha256:
        hash_alg = CALG_SHA_256;
        break;
      case NID_sha384:
        hash_alg = CALG_SHA_384;
        break;
      case NID_sha512:
        hash_alg = CALG_SHA_512;
        break;
      default:
        NOTREACHED();
    }

    crypto::ScopedHCRYPTHASH hash_handle;
    if (!CryptCreateHash(
            provider_.get(), hash_alg, 0, 0,
            crypto::ScopedHCRYPTHASH::Receiver(hash_handle).get())) {
      PLOG(ERROR) << "CreateCreateHash failed";
      return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
    }
    DWORD hash_len;
    DWORD arg_len = sizeof(hash_len);
    if (!CryptGetHashParam(hash_handle.get(), HP_HASHSIZE,
                           reinterpret_cast<BYTE*>(&hash_len), &arg_len, 0)) {
      PLOG(ERROR) << "CryptGetHashParam HP_HASHSIZE failed";
      return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
    }
    if (hash_len != digest_len)
      return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
    if (!CryptSetHashParam(hash_handle.get(), HP_HASHVAL,
                           const_cast<BYTE*>(digest), 0)) {
      PLOG(ERROR) << "CryptSetHashParam HP_HASHVAL failed";
      return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
    }
    DWORD signature_len = 0;
    if (!CryptSignHash(hash_handle.get(), key_spec_, nullptr, 0, nullptr,
                       &signature_len)) {
      PLOG(ERROR) << "CryptSignHash failed";
      return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
    }
    signature->resize(signature_len);
    if (!CryptSignHash(hash_handle.get(), key_spec_, nullptr, 0,
                       signature->data(), &signature_len)) {
      PLOG(ERROR) << "CryptSignHash failed";
      return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
    }
    signature->resize(signature_len);

    // CryptoAPI signs in little-endian, so reverse it.
    std::reverse(signature->begin(), signature->end());
    return OK;
  }

 private:
  std::string provider_name_;
  crypto::ScopedHCRYPTPROV provider_;
  DWORD key_spec_;
  bool prefer_sha1_ = false;
};

std::wstring GetCNGProviderName(NCRYPT_KEY_HANDLE key) {
  crypto::ScopedNCryptProvider prov;
  DWORD prov_len = 0;
  SECURITY_STATUS status = NCryptGetProperty(
      key, NCRYPT_PROVIDER_HANDLE_PROPERTY,
      reinterpret_cast<BYTE*>(
          crypto::ScopedNCryptProvider::Receiver(prov).get()),
      sizeof(NCRYPT_PROV_HANDLE), &prov_len, NCRYPT_SILENT_FLAG);
  if (FAILED(status)) {
    return L"(error getting provider)";
  }
  DCHECK_EQ(sizeof(NCRYPT_PROV_HANDLE), prov_len);

  // NCRYPT_NAME_PROPERTY is a NUL-terminated Unicode string, which means an
  // array of wchar_t, however NCryptGetProperty works in bytes, so lengths must
  // be converted.
  DWORD name_len = 0;
  status = NCryptGetProperty(prov.get(), NCRYPT_NAME_PROPERTY, nullptr, 0,
                             &name_len, NCRYPT_SILENT_FLAG);
  if (FAILED(status) || name_len % sizeof(wchar_t) != 0) {
    return L"(error getting provider name)";
  }
  std::vector<wchar_t> name;
  name.reserve(name_len / sizeof(wchar_t));
  status = NCryptGetProperty(
      prov.get(), NCRYPT_NAME_PROPERTY, reinterpret_cast<BYTE*>(name.data()),
      name.size() * sizeof(wchar_t), &name_len, NCRYPT_SILENT_FLAG);
  if (FAILED(status)) {
    return L"(error getting provider name)";
  }
  name.resize(name_len / sizeof(wchar_t));

  // Per Microsoft's documentation, the name is NUL-terminated. However,
  // smartcard drivers are notoriously buggy, so check this.
  auto nul = base::ranges::find(name, 0);
  if (nul != name.end()) {
    name.erase(nul, name.end());
  }
  return std::wstring(name.begin(), name.end());
}

class SSLPlatformKeyCNG : public ThreadedSSLPrivateKey::Delegate {
 public:
  // Takes ownership of |key|.
  SSLPlatformKeyCNG(crypto::ScopedNCryptKey key, int type, size_t max_length)
      : provider_name_(GetCNGProviderName(key.get())),
        key_(std::move(key)),
        type_(type),
        max_length_(max_length) {
    // If this is a 1024-bit RSA key or below, check for SHA-256 support. Older
    // Estonian ID cards can only sign SHA-1 hashes. If SHA-256 does not work,
    // prioritize SHA-1 as a workaround. See https://crbug.com/278370.
    prefer_sha1_ =
        type_ == EVP_PKEY_RSA && max_length_ <= 1024 / 8 && !ProbeSHA256(this);
  }

  SSLPlatformKeyCNG(const SSLPlatformKeyCNG&) = delete;
  SSLPlatformKeyCNG& operator=(const SSLPlatformKeyCNG&) = delete;

  std::string GetProviderName() override {
    return "CNG: " + base::WideToUTF8(provider_name_);
  }

  std::vector<uint16_t> GetAlgorithmPreferences() override {
    // Per TLS 1.3 (RFC 8446), the RSA-PSS code points in TLS correspond to
    // RSA-PSS with salt length equal to the digest length. TPM 2.0's
    // TPM_ALG_RSAPSS algorithm, however, uses the maximum possible salt length.
    // The TPM provider will fail signing requests for other salt lengths and
    // thus cannot generate TLS-compatible PSS signatures.
    //
    // However, as of TPM revision 1.16, TPMs which follow FIPS 186-4 will
    // instead interpret TPM_ALG_RSAPSS using salt length equal to the digest
    // length. Those TPMs can generate TLS-compatible PSS signatures. As a
    // result, if this is a TPM-based key, we only report PSS as supported if
    // the salt length will match the digest length.
    bool supports_pss = true;
    if (provider_name_ == MS_PLATFORM_KEY_STORAGE_PROVIDER) {
      DWORD salt_size = 0;
      DWORD size_of_salt_size = sizeof(salt_size);
      HRESULT status =
          NCryptGetProperty(key_.get(), NCRYPT_PCP_PSS_SALT_SIZE_PROPERTY,
                            reinterpret_cast<PBYTE>(&salt_size),
                            size_of_salt_size, &size_of_salt_size, 0);
      if (FAILED(status) || salt_size != NCRYPT_TPM_PSS_SALT_SIZE_HASHSIZE) {
        supports_pss = false;
      }
    }
    if (prefer_sha1_) {
      std::vector<uint16_t> ret = {
          SSL_SIGN_RSA_PKCS1_SHA1,
          SSL_SIGN_RSA_PKCS1_SHA256,
          SSL_SIGN_RSA_PKCS1_SHA384,
          SSL_SIGN_RSA_PKCS1_SHA512,
      };
      if (supports_pss) {
        ret.push_back(SSL_SIGN_RSA_PSS_SHA256);
        ret.push_back(SSL_SIGN_RSA_PSS_SHA384);
        ret.push_back(SSL_SIGN_RSA_PSS_SHA512);
      }
      return ret;
    }
    return SSLPrivateKey::DefaultAlgorithmPreferences(type_, supports_pss);
  }

  Error Sign(uint16_t algorithm,
             base::span<const uint8_t> input,
             std::vector<uint8_t>* signature) override {
    crypto::OpenSSLErrStackTracer tracer(FROM_HERE);

    const EVP_MD* md = SSL_get_signature_algorithm_digest(algorithm);
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned digest_len;
    if (!md || !EVP_Digest(input.data(), input.size(), digest, &digest_len, md,
                           nullptr)) {
      return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
    }

    BCRYPT_PKCS1_PADDING_INFO pkcs1_padding_info = {nullptr};
    BCRYPT_PSS_PADDING_INFO pss_padding_info = {nullptr};
    void* padding_info = nullptr;
    DWORD flags = 0;
    if (SSL_get_signature_algorithm_key_type(algorithm) == EVP_PKEY_RSA) {
      const WCHAR* hash_alg;
      switch (EVP_MD_type(md)) {
        case NID_md5_sha1:
          hash_alg = nullptr;
          break;
        case NID_sha1:
          hash_alg = BCRYPT_SHA1_ALGORITHM;
          break;
        case NID_sha256:
          hash_alg = BCRYPT_SHA256_ALGORITHM;
          break;
        case NID_sha384:
          hash_alg = BCRYPT_SHA384_ALGORITHM;
          break;
        case NID_sha512:
          hash_alg = BCRYPT_SHA512_ALGORITHM;
          break;
        default:
          NOTREACHED();
      }
      if (SSL_is_signature_algorithm_rsa_pss(algorithm)) {
        pss_padding_info.pszAlgId = hash_alg;
        pss_padding_info.cbSalt = EVP_MD_size(md);
        padding_info = &pss_padding_info;
        flags |= BCRYPT_PAD_PSS;
      } else {
        pkcs1_padding_info.pszAlgId = hash_alg;
        padding_info = &pkcs1_padding_info;
        flags |= BCRYPT_PAD_PKCS1;
      }
    }

    DWORD signature_len;
    SECURITY_STATUS status =
        NCryptSignHash(key_.get(), padding_info, const_cast<BYTE*>(digest),
                       digest_len, nullptr, 0, &signature_len, flags);
    if (FAILED(status)) {
      LOG(ERROR) << "NCryptSignHash failed: " << status;
      return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
    }
    signature->resize(signature_len);
    status = NCryptSignHash(key_.get(), padding_info, const_cast<BYTE*>(digest),
                            digest_len, signature->data(), signature_len,
                            &signature_len, flags);
    if (FAILED(status)) {
      LOG(ERROR) << "NCryptSignHash failed: " << status;
      return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
    }
    signature->resize(signature_len);

    // CNG emits raw ECDSA signatures, but BoringSSL expects a DER-encoded
    // ECDSA-Sig-Value.
    if (type_ == EVP_PKEY_EC) {
      if (signature->size() % 2 != 0) {
        LOG(ERROR) << "Bad signature length";
        return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
      }
      size_t order_len = signature->size() / 2;

      // Convert the RAW ECDSA signature to a DER-encoded ECDSA-Sig-Value.
      bssl::UniquePtr<ECDSA_SIG> sig(ECDSA_SIG_new());
      if (!sig || !BN_bin2bn(signature->data(), order_len, sig->r) ||
          !BN_bin2bn(signature->data() + order_len, order_len, sig->s)) {
        return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
      }

      int len = i2d_ECDSA_SIG(sig.get(), nullptr);
      if (len <= 0)
        return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
      signature->resize(len);
      uint8_t* ptr = signature->data();
      len = i2d_ECDSA_SIG(sig.get(), &ptr);
      if (len <= 0)
        return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
      signature->resize(len);
    }

    return OK;
  }

 private:
  std::wstring provider_name_;
  crypto::ScopedNCryptKey key_;
  int type_;
  size_t max_length_;
  bool prefer_sha1_ = false;
};

}  // namespace

scoped_refptr<SSLPrivateKey> WrapCAPIPrivateKey(
    const X509Certificate* certificate,
    crypto::ScopedHCRYPTPROV prov,
    DWORD key_spec) {
  return base::MakeRefCounted<ThreadedSSLPrivateKey>(
      std::make_unique<SSLPlatformKeyCAPI>(std::move(prov), key_spec),
      GetSSLPlatformKeyTaskRunner());
}

scoped_refptr<SSLPrivateKey> WrapCNGPrivateKey(
    const X509Certificate* certificate,
    crypto::ScopedNCryptKey key) {
  // Rather than query the private key for metadata, extract the public key from
  // the certificate without using Windows APIs. CNG does not consistently work
  // depending on the system. See https://crbug.com/468345.
  int key_type;
  size_t max_length;
  if (!GetClientCertInfo(certificate, &key_type, &max_length)) {
    return nullptr;
  }

  return base::MakeRefCounted<ThreadedSSLPrivateKey>(
      std::make_unique<SSLPlatformKeyCNG>(std::move(key), key_type, max_length),
      GetSSLPlatformKeyTaskRunner());
}

scoped_refptr<SSLPrivateKey> FetchClientCertPrivateKey(
    const X509Certificate* certificate,
    PCCERT_CONTEXT cert_context) {
  HCRYPTPROV_OR_NCRYPT_KEY_HANDLE prov_or_key = 0;
  DWORD key_spec = 0;
  BOOL must_free = FALSE;
  DWORD flags = CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG;

  if (!CryptAcquireCertificatePrivateKey(cert_context, flags, nullptr,
                                         &prov_or_key, &key_spec, &must_free)) {
    PLOG(WARNING) << "Could not acquire private key";
    return nullptr;
  }

  // Should never get a cached handle back - ownership must always be
  // transferred.
  CHECK_EQ(must_free, TRUE);

  if (key_spec == CERT_NCRYPT_KEY_SPEC) {
    return WrapCNGPrivateKey(certificate, crypto::ScopedNCryptKey(prov_or_key));
  } else {
    return WrapCAPIPrivateKey(certificate,
                              crypto::ScopedHCRYPTPROV(prov_or_key), key_spec);
  }
}

scoped_refptr<SSLPrivateKey> WrapUnexportableKeySlowly(
    const crypto::UnexportableSigningKey& key) {
  // Load NCRYPT_KEY_HANDLE from wrapped.
  auto wrapped = key.GetWrappedKey();
  crypto::ScopedNCryptProvider provider;
  crypto::ScopedNCryptKey key_handle;
  if (!crypto::LoadWrappedTPMKey(wrapped, provider, key_handle)) {
    return nullptr;
  }

  int key_type;
  size_t max_length;
  if (!GetPublicKeyInfo(key.GetSubjectPublicKeyInfo(), &key_type,
                        &max_length)) {
    return nullptr;
  }

  return base::MakeRefCounted<ThreadedSSLPrivateKey>(
      std::make_unique<SSLPlatformKeyCNG>(std::move(key_handle), key_type,
                                          max_length),
      GetSSLPlatformKeyTaskRunner());
}

}  // namespace net

"""

```