Response:
Let's break down the thought process for analyzing the C++ code and generating the response.

1. **Understand the Goal:** The request asks for an analysis of the `ssl_platform_key_win_unittest.cc` file, focusing on its functionality, potential relation to JavaScript, logic inference, common errors, and debugging clues.

2. **Initial Skim and Keyword Identification:**  A quick read reveals keywords like "test," "SSL," "platform," "Windows," "CNG," "CAPI," "certificate," "private key," "RSA," "EC," "PKCS#8," and "BLOB."  This immediately suggests the file is about testing how Chromium handles SSL private keys on Windows, specifically those managed by the operating system's cryptographic providers (CNG and CAPI). The "unittest" suffix confirms its testing nature.

3. **Identify Core Functionality:**  The code imports certificates and private keys from files, then converts these keys into formats (BLOBs) suitable for the Windows cryptographic APIs (CNG and CAPI). It then wraps these Windows-managed keys into Chromium's `SSLPrivateKey` interface and verifies that these wrapped keys behave correctly. The core function is to test the `WrapCNGPrivateKey` and `WrapCAPIPrivateKey` functions found in `ssl_platform_key_win.h` (as indicated by the `#include`).

4. **Look for JavaScript Connections (and the lack thereof):**  The keywords and the nature of the file (testing low-level cryptographic interactions with the OS) strongly suggest *no direct relationship* with JavaScript. However, it's crucial to explain *why*. The reasoning is that this code is part of Chromium's *network stack*, which operates at a lower level than the JavaScript engine. The connection to JavaScript is *indirect*: when a website uses HTTPS, the browser's network stack (which includes this code) handles the TLS handshake and secure communication, and JavaScript running in the browser benefits from this secure connection. This needs to be clearly articulated.

5. **Analyze Logic Inference and Test Cases:** The test cases (`TEST_P`, `TEST`) provide clear examples of logic inference.
    * **Input:**  The `kTestKeys` array defines different key types (RSA, P256, P384, P521) and points to certificate and private key files. The test functions then load these files. The `PKCS8ToBLOBForCNG` and `PKCS8ToBLOBForCAPI` functions perform the key conversion.
    * **Processing:** The core logic is the conversion from PKCS#8 private key format to Windows BLOB formats, followed by importing these BLOBs into CNG or CAPI. The wrapping functions (`WrapCNGPrivateKey`, `WrapCAPIPrivateKey`) are then invoked.
    * **Output:** The tests use `ASSERT_TRUE` and `EXPECT_EQ` to check if the key wrapping is successful and if the resulting `SSLPrivateKey` object has the expected properties (e.g., matching the original private key, having the correct algorithm preferences). For example, `TestSSLPrivateKeyMatches` verifies the wrapped key can perform cryptographic operations correctly.

6. **Identify Potential User/Programming Errors:** Common errors arise from misconfiguring the cryptographic providers, incorrect file paths, or using unsupported key types with specific APIs (like CAPI and EC keys). The example given about missing cryptographic providers or incorrect permissions is a good illustration.

7. **Trace User Actions to the Code:**  This requires thinking about the steps a user takes that would lead to this code being executed during debugging. The flow involves:
    * User navigates to an HTTPS website.
    * The browser initiates a TLS handshake.
    * The server presents a certificate, and the browser needs to use a client certificate (if required).
    * If a client certificate is needed, and it's stored in the Windows certificate store (or a smart card managed by Windows), the browser might use the Windows cryptographic APIs (CNG or CAPI) to access the corresponding private key.
    * This is where the `WrapCNGPrivateKey` or `WrapCAPIPrivateKey` functions (and thus the code in the unit test) become relevant.

8. **Address the "Unexportable Key" Test:** The `UnexportableSSLPlatformKeyWinTest` is a separate but related test. It focuses on hardware-backed keys that cannot be exported from the secure enclave. The logic here is simpler: generate such a key and try to wrap it. The potential skip conditions are important to note.

9. **Structure the Response:** Organize the information logically with clear headings and bullet points. Start with the main functionality, then address the specific points in the request (JavaScript, logic, errors, debugging).

10. **Refine and Elaborate:**  After drafting the initial response, review it for clarity and completeness. Add details where necessary, explain technical terms (like PKCS#8 and BLOB), and ensure the examples are concrete and easy to understand. For instance, explicitly stating that the unit test simulates the browser's behavior is important. Also, the explanation of the assumptions and outputs for the logical inference adds significant value.

By following these steps, combining code understanding with domain knowledge about SSL/TLS and Windows cryptography, and focusing on the specific questions in the prompt, a comprehensive and helpful analysis can be generated.
这个文件 `net/ssl/ssl_platform_key_win_unittest.cc` 是 Chromium 网络栈的一部分，它专门用于测试在 Windows 平台上使用操作系统提供的密钥存储功能（通过 CNG 和 CAPI 接口）来管理 SSL 私钥的功能。

以下是它的主要功能：

1. **测试 `WrapCNGPrivateKey` 函数:**  这个函数的作用是将 Windows CNG (Cryptography Next Generation) API 管理的私钥包装成 Chromium 的 `SSLPrivateKey` 对象。测试会验证包装后的 `SSLPrivateKey` 是否能够正确执行签名等加密操作，并且其算法偏好设置是否符合预期。

2. **测试 `WrapCAPIPrivateKey` 函数:**  类似于 CNG，这个函数是将 Windows CAPI (Cryptography API) 管理的私钥包装成 Chromium 的 `SSLPrivateKey` 对象。测试同样会验证其功能和算法偏好。

3. **密钥格式转换测试:**  测试代码包含了将 PKCS#8 格式的私钥转换为 Windows CNG 和 CAPI 可以导入的 BLOB (Binary Large Object) 格式的逻辑 (`PKCS8ToBLOBForCNG` 和 `PKCS8ToBLOBForCAPI` 函数)。这部分是间接测试，确保了 Chromium 可以正确地使用从文件中加载的私钥来模拟 Windows 系统中存储的密钥。

4. **支持不同类型的密钥:** 测试用例覆盖了 RSA 和 ECDSA (P256, P384, P521) 等不同类型的私钥，确保代码可以处理各种常见的密钥算法。

5. **测试非导出型密钥 (Unexportable Keys):**  `UnexportableSSLPlatformKeyWinTest` 测试了对硬件保护的、不可导出的密钥的支持。这通常涉及到智能卡或者 TPM (Trusted Platform Module) 等安全硬件。

**它与 JavaScript 的功能关系:**

这个 C++ 文件本身并不包含 JavaScript 代码，并且在浏览器运行的较低层次的网络栈中工作。然而，它所测试的功能对于支持 HTTPS 连接至关重要，而 HTTPS 是 JavaScript 代码通过浏览器进行网络通信的基础。

**举例说明:**

当一个网站使用 HTTPS，并且需要客户端提供证书进行身份验证时（例如，企业内部网站或者某些需要高安全性的服务），浏览器可能会需要访问存储在操作系统中的客户端证书及其对应的私钥。

1. **用户操作（JavaScript 触发）：**  一个网页上的 JavaScript 代码尝试发起一个到需要客户端证书的 HTTPS 服务器的请求，例如使用 `fetch` API 或者 `XMLHttpRequest`。

   ```javascript
   fetch('https://internal.example.com', {credentials: 'include'})
     .then(response => {
       // 处理响应
     });
   ```

2. **浏览器行为：** 浏览器检测到需要客户端证书。如果用户配置了客户端证书并且该证书的私钥是由 Windows 的密钥存储管理（例如，存储在 Windows 证书存储中），浏览器会调用 Windows 的 API 来访问该私钥。

3. **`ssl_platform_key_win.cc` 的作用：** `WrapCNGPrivateKey` 或 `WrapCAPIPrivateKey` 函数会被调用，将 Windows CNG 或 CAPI 提供的私钥句柄转换为 Chromium 可以使用的 `SSLPrivateKey` 对象。这个对象会被用于 TLS 握手期间的签名操作，以完成客户端身份验证。

**逻辑推理、假设输入与输出:**

**测试用例: `KeyMatchesCNG` (RSA 密钥)**

* **假设输入:**
    * `test_key.cert_file`: "client_1.pem" (包含客户端证书)
    * `test_key.key_file`: "client_1.pk8" (包含 PKCS#8 格式的客户端私钥)
    * Windows 系统上已安装 CNG 密钥存储提供程序。
* **处理逻辑:**
    1. 从文件中加载证书和 PKCS#8 私钥。
    2. 使用 `PKCS8ToBLOBForCNG` 将 PKCS#8 私钥转换为 CNG BLOB 格式。
    3. 调用 Windows CNG API (`NCryptImportKey`) 将 BLOB 导入到 CNG 中（这里是临时导入，没有指定持久化名称）。
    4. 调用 `WrapCNGPrivateKey` 将 CNG 密钥句柄包装成 `SSLPrivateKey`。
    5. 使用 `TestSSLPrivateKeyMatches` 函数，对比包装后的 `SSLPrivateKey` 和原始的 PKCS#8 私钥，验证它们在签名等操作上是否一致。
* **预期输出:**  `TestSSLPrivateKeyMatches` 断言成功，表明通过 CNG 包装的私钥可以正确使用。

**涉及用户或者编程常见的使用错误:**

1. **缺少或错误的证书/密钥文件:**  用户可能没有正确配置客户端证书，或者提供的证书/密钥文件路径不正确，导致 `ImportCertFromFile` 或 `base::ReadFileToString` 失败。
   ```c++
   // 假设用户提供的 client_1.pem 文件不存在
   base::FilePath cert_path = GetTestCertsDirectory().AppendASCII("client_1.pem");
   scoped_refptr<X509Certificate> cert = ImportCertFromFile(GetTestCertsDirectory(), "non_existent.pem");
   ASSERT_TRUE(cert); // 这里会断言失败
   ```

2. **Windows 密钥存储服务未运行或配置错误:**  如果 Windows CNG 或 CAPI 服务没有正确运行，或者相关的权限配置不正确，调用 Windows API (如 `NCryptOpenStorageProvider` 或 `CryptAcquireContext`) 可能会失败。
   ```c++
   crypto::ScopedNCryptProvider prov;
   SECURITY_STATUS status = NCryptOpenStorageProvider(
       crypto::ScopedNCryptProvider::Receiver(prov).get(),
       MS_KEY_STORAGE_PROVIDER, 0);
   ASSERT_FALSE(FAILED(status)) << status; // 如果 CNG 服务有问题，status 可能指示错误
   ```

3. **尝试将不支持的密钥类型导入到特定的 API:**  例如，早期的 CAPI 对椭圆曲线密钥的支持有限。测试代码中也体现了这一点，`KeyMatchesCAPI` 测试会跳过非 RSA 密钥。

4. **编程错误：BLOB 转换逻辑错误:**  `PKCS8ToBLOBForCNG` 和 `PKCS8ToBLOBForCAPI` 函数的实现如果存在错误，会导致生成的 BLOB 数据不正确，从而导致密钥导入 Windows API 失败。

**用户操作如何一步步的到达这里，作为调试线索:**

假设用户在使用 Chromium 浏览器访问一个需要客户端证书的网站时遇到问题，以下是可能到达这个代码的调试路径：

1. **用户访问 HTTPS 网站:** 用户在地址栏输入或点击一个 HTTPS 链接，服务器需要客户端证书进行身份验证。

2. **浏览器尝试进行 TLS 握手:** Chromium 的网络栈开始与服务器进行 TLS 握手。

3. **服务器请求客户端证书:** 在 TLS 握手过程中，服务器发送 `CertificateRequest` 消息，要求客户端提供证书。

4. **Chromium 查找合适的客户端证书:** 浏览器会检查用户系统中安装的客户端证书。

5. **如果找到合适的证书，但私钥由 Windows 管理:**  如果找到的客户端证书的私钥不是由 Chromium 自己管理（例如，从 PKCS#12 文件导入），而是存储在 Windows 证书存储中，Chromium 需要使用 Windows API 来访问私钥。

6. **调用 `WrapCNGPrivateKey` 或 `WrapCAPIPrivateKey`:**  这时，`net/ssl/ssl_platform_key_win.cc` 中的 `WrapCNGPrivateKey` 或 `WrapCAPIPrivateKey` 函数会被调用，尝试将 Windows 提供的私钥句柄转换为 Chromium 的 `SSLPrivateKey` 对象。

7. **如果包装或后续签名操作失败:**  如果在上述步骤中出现错误（例如，Windows API 调用失败，BLOB 转换错误，或者包装后的 `SSLPrivateKey` 无法正确签名），可能会导致 TLS 握手失败，用户在浏览器中会看到连接错误，例如 `ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED` 或类似的错误。

**调试线索:**

* **网络日志 (net-internals):**  Chromium 的 `chrome://net-internals/#ssl` 和 `chrome://net-internals/#events` 可以提供关于 SSL 握手过程的详细信息，包括是否成功找到客户端证书，以及在签名过程中是否发生错误。

* **Windows 事件查看器:**  如果涉及到 Windows 密钥存储服务的问题，Windows 的事件查看器可能会记录相关的错误信息。

* **断点调试:**  在 Chromium 源代码中设置断点，例如在 `WrapCNGPrivateKey` 和 `WrapCAPIPrivateKey` 函数的入口处，以及在调用 Windows API 的地方，可以帮助开发者逐步跟踪问题的发生。

* **检查证书和密钥配置:**  确保客户端证书已正确安装在 Windows 证书存储中，并且对应的私钥可以访问。

总而言之，`net/ssl/ssl_platform_key_win_unittest.cc` 是一个测试文件，用于确保 Chromium 在 Windows 平台上能够正确地与操作系统的密钥管理功能集成，从而支持需要客户端证书的 HTTPS 连接。它虽然不直接包含 JavaScript 代码，但其测试的功能是支撑安全 Web 通信的关键基础设施。

### 提示词
```
这是目录为net/ssl/ssl_platform_key_win_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/ssl/ssl_platform_key_win.h"

#include <string>
#include <vector>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "crypto/scoped_capi_types.h"
#include "crypto/scoped_cng_types.h"
#include "crypto/unexportable_key.h"
#include "net/base/features.h"
#include "net/cert/x509_certificate.h"
#include "net/ssl/ssl_private_key.h"
#include "net/ssl/ssl_private_key_test_util.h"
#include "net/test/cert_test_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/include/openssl/bn.h"
#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/ec.h"
#include "third_party/boringssl/src/include/openssl/ec_key.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/rsa.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"

namespace net {

namespace {

struct TestKey {
  const char* name;
  const char* cert_file;
  const char* key_file;
  int type;
};

const TestKey kTestKeys[] = {
    {.name = "RSA",
     .cert_file = "client_1.pem",
     .key_file = "client_1.pk8",
     .type = EVP_PKEY_RSA},
    {.name = "P256",
     .cert_file = "client_4.pem",
     .key_file = "client_4.pk8",
     .type = EVP_PKEY_EC},
    {.name = "P384",
     .cert_file = "client_5.pem",
     .key_file = "client_5.pk8",
     .type = EVP_PKEY_EC},
    {.name = "P521",
     .cert_file = "client_6.pem",
     .key_file = "client_6.pk8",
     .type = EVP_PKEY_EC},
    {.name = "RSA1024",
     .cert_file = "client_7.pem",
     .key_file = "client_7.pk8",
     .type = EVP_PKEY_RSA},
};

std::string TestParamsToString(const testing::TestParamInfo<TestKey>& params) {
  return params.param.name;
}

// Appends |bn| to |cbb|, represented as |len| bytes in little-endian order,
// zero-padded as needed. Returns true on success and false if |len| is too
// small.
bool AddBIGNUMLittleEndian(CBB* cbb, const BIGNUM* bn, size_t len) {
  uint8_t* ptr;
  return CBB_add_space(cbb, &ptr, len) && BN_bn2le_padded(ptr, len, bn);
}

// Converts the PKCS#8 PrivateKeyInfo structure serialized in |pkcs8| to a
// private key BLOB, suitable for import with CAPI using Microsoft Base
// Cryptographic Provider.
bool PKCS8ToBLOBForCAPI(const std::string& pkcs8, std::vector<uint8_t>* blob) {
  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(pkcs8.data()), pkcs8.size());
  bssl::UniquePtr<EVP_PKEY> key(EVP_parse_private_key(&cbs));
  if (!key || CBS_len(&cbs) != 0 || EVP_PKEY_id(key.get()) != EVP_PKEY_RSA)
    return false;
  const RSA* rsa = EVP_PKEY_get0_RSA(key.get());

  // See
  // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375601(v=vs.85).aspx
  PUBLICKEYSTRUC header = {0};
  header.bType = PRIVATEKEYBLOB;
  header.bVersion = 2;
  header.aiKeyAlg = CALG_RSA_SIGN;

  RSAPUBKEY rsapubkey = {0};
  rsapubkey.magic = 0x32415352;
  rsapubkey.bitlen = RSA_bits(rsa);
  rsapubkey.pubexp = BN_get_word(RSA_get0_e(rsa));

  uint8_t* blob_data;
  size_t blob_len;
  bssl::ScopedCBB cbb;
  if (!CBB_init(cbb.get(), sizeof(header) + sizeof(rsapubkey) + pkcs8.size()) ||
      !CBB_add_bytes(cbb.get(), reinterpret_cast<const uint8_t*>(&header),
                     sizeof(header)) ||
      !CBB_add_bytes(cbb.get(), reinterpret_cast<const uint8_t*>(&rsapubkey),
                     sizeof(rsapubkey)) ||
      !AddBIGNUMLittleEndian(cbb.get(), RSA_get0_n(rsa),
                             rsapubkey.bitlen / 8) ||
      !AddBIGNUMLittleEndian(cbb.get(), RSA_get0_p(rsa),
                             rsapubkey.bitlen / 16) ||
      !AddBIGNUMLittleEndian(cbb.get(), RSA_get0_q(rsa),
                             rsapubkey.bitlen / 16) ||
      !AddBIGNUMLittleEndian(cbb.get(), RSA_get0_dmp1(rsa),
                             rsapubkey.bitlen / 16) ||
      !AddBIGNUMLittleEndian(cbb.get(), RSA_get0_dmq1(rsa),
                             rsapubkey.bitlen / 16) ||
      !AddBIGNUMLittleEndian(cbb.get(), RSA_get0_iqmp(rsa),
                             rsapubkey.bitlen / 16) ||
      !AddBIGNUMLittleEndian(cbb.get(), RSA_get0_d(rsa),
                             rsapubkey.bitlen / 8) ||
      !CBB_finish(cbb.get(), &blob_data, &blob_len)) {
    return false;
  }

  blob->assign(blob_data, blob_data + blob_len);
  OPENSSL_free(blob_data);
  return true;
}

// Appends |bn| to |cbb|, represented as |len| bytes in big-endian order,
// zero-padded as needed. Returns true on success and false if |len| is too
// small.
bool AddBIGNUMBigEndian(CBB* cbb, const BIGNUM* bn, size_t len) {
  uint8_t* ptr;
  return CBB_add_space(cbb, &ptr, len) && BN_bn2bin_padded(ptr, len, bn);
}

// Converts the PKCS#8 PrivateKeyInfo structure serialized in |pkcs8| to a
// private key BLOB, suitable for import with CNG using the Microsoft Software
// KSP, and sets |*blob_type| to the type of the BLOB.
bool PKCS8ToBLOBForCNG(const std::string& pkcs8,
                       LPCWSTR* blob_type,
                       std::vector<uint8_t>* blob) {
  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(pkcs8.data()), pkcs8.size());
  bssl::UniquePtr<EVP_PKEY> key(EVP_parse_private_key(&cbs));
  if (!key || CBS_len(&cbs) != 0)
    return false;

  if (EVP_PKEY_id(key.get()) == EVP_PKEY_RSA) {
    // See
    // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375531(v=vs.85).aspx.
    const RSA* rsa = EVP_PKEY_get0_RSA(key.get());
    BCRYPT_RSAKEY_BLOB header = {0};
    header.Magic = BCRYPT_RSAFULLPRIVATE_MAGIC;
    header.BitLength = RSA_bits(rsa);
    header.cbPublicExp = BN_num_bytes(RSA_get0_e(rsa));
    header.cbModulus = BN_num_bytes(RSA_get0_n(rsa));
    header.cbPrime1 = BN_num_bytes(RSA_get0_p(rsa));
    header.cbPrime2 = BN_num_bytes(RSA_get0_q(rsa));

    uint8_t* blob_data;
    size_t blob_len;
    bssl::ScopedCBB cbb;
    if (!CBB_init(cbb.get(), sizeof(header) + pkcs8.size()) ||
        !CBB_add_bytes(cbb.get(), reinterpret_cast<const uint8_t*>(&header),
                       sizeof(header)) ||
        !AddBIGNUMBigEndian(cbb.get(), RSA_get0_e(rsa), header.cbPublicExp) ||
        !AddBIGNUMBigEndian(cbb.get(), RSA_get0_n(rsa), header.cbModulus) ||
        !AddBIGNUMBigEndian(cbb.get(), RSA_get0_p(rsa), header.cbPrime1) ||
        !AddBIGNUMBigEndian(cbb.get(), RSA_get0_q(rsa), header.cbPrime2) ||
        !AddBIGNUMBigEndian(cbb.get(), RSA_get0_dmp1(rsa), header.cbPrime1) ||
        !AddBIGNUMBigEndian(cbb.get(), RSA_get0_dmq1(rsa), header.cbPrime2) ||
        !AddBIGNUMBigEndian(cbb.get(), RSA_get0_iqmp(rsa), header.cbPrime1) ||
        !AddBIGNUMBigEndian(cbb.get(), RSA_get0_d(rsa), header.cbModulus) ||
        !CBB_finish(cbb.get(), &blob_data, &blob_len)) {
      return false;
    }

    *blob_type = BCRYPT_RSAFULLPRIVATE_BLOB;
    blob->assign(blob_data, blob_data + blob_len);
    OPENSSL_free(blob_data);
    return true;
  }

  if (EVP_PKEY_id(key.get()) == EVP_PKEY_EC) {
    // See
    // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375520(v=vs.85).aspx.
    const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(key.get());
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    bssl::UniquePtr<BIGNUM> x(BN_new());
    bssl::UniquePtr<BIGNUM> y(BN_new());
    if (!EC_POINT_get_affine_coordinates_GFp(
            group, EC_KEY_get0_public_key(ec_key), x.get(), y.get(), nullptr)) {
      return false;
    }

    BCRYPT_ECCKEY_BLOB header = {0};
    switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key))) {
      case NID_X9_62_prime256v1:
        header.dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
        break;
      case NID_secp384r1:
        header.dwMagic = BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
        break;
      case NID_secp521r1:
        header.dwMagic = BCRYPT_ECDSA_PRIVATE_P521_MAGIC;
        break;
      default:
        return false;
    }
    header.cbKey = BN_num_bytes(EC_GROUP_get0_order(group));

    uint8_t* blob_data;
    size_t blob_len;
    bssl::ScopedCBB cbb;
    if (!CBB_init(cbb.get(), sizeof(header) + header.cbKey * 3) ||
        !CBB_add_bytes(cbb.get(), reinterpret_cast<const uint8_t*>(&header),
                       sizeof(header)) ||
        !AddBIGNUMBigEndian(cbb.get(), x.get(), header.cbKey) ||
        !AddBIGNUMBigEndian(cbb.get(), y.get(), header.cbKey) ||
        !AddBIGNUMBigEndian(cbb.get(), EC_KEY_get0_private_key(ec_key),
                            header.cbKey) ||
        !CBB_finish(cbb.get(), &blob_data, &blob_len)) {
      return false;
    }

    *blob_type = BCRYPT_ECCPRIVATE_BLOB;
    blob->assign(blob_data, blob_data + blob_len);
    OPENSSL_free(blob_data);
    return true;
  }

  return false;
}

}  // namespace

class SSLPlatformKeyWinTest
    : public testing::TestWithParam<TestKey>,
      public WithTaskEnvironment {
 public:
  const TestKey& GetTestKey() const { return GetParam(); }
};

TEST_P(SSLPlatformKeyWinTest, KeyMatchesCNG) {
  const TestKey& test_key = GetTestKey();

  // Load test data.
  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(GetTestCertsDirectory(), test_key.cert_file);
  ASSERT_TRUE(cert);

  std::string pkcs8;
  base::FilePath pkcs8_path =
      GetTestCertsDirectory().AppendASCII(test_key.key_file);
  ASSERT_TRUE(base::ReadFileToString(pkcs8_path, &pkcs8));

  // Import the key into CNG. Per MSDN's documentation on NCryptImportKey, if a
  // key name is not supplied (via the pParameterList parameter for the BLOB
  // types we use), the Microsoft Software KSP will treat the key as ephemeral.
  //
  // https://msdn.microsoft.com/en-us/library/windows/desktop/aa376276(v=vs.85).aspx
  crypto::ScopedNCryptProvider prov;
  SECURITY_STATUS status = NCryptOpenStorageProvider(
      crypto::ScopedNCryptProvider::Receiver(prov).get(),
      MS_KEY_STORAGE_PROVIDER, 0);
  ASSERT_FALSE(FAILED(status)) << status;

  LPCWSTR blob_type;
  std::vector<uint8_t> blob;
  ASSERT_TRUE(PKCS8ToBLOBForCNG(pkcs8, &blob_type, &blob));
  crypto::ScopedNCryptKey ncrypt_key;
  status = NCryptImportKey(prov.get(), /*hImportKey=*/0, blob_type,
                           /*pParameterList=*/nullptr,
                           crypto::ScopedNCryptKey::Receiver(ncrypt_key).get(),
                           blob.data(), blob.size(), NCRYPT_SILENT_FLAG);
  ASSERT_FALSE(FAILED(status)) << status;

  scoped_refptr<SSLPrivateKey> key =
      WrapCNGPrivateKey(cert.get(), std::move(ncrypt_key));
  ASSERT_TRUE(key);

  EXPECT_EQ(SSLPrivateKey::DefaultAlgorithmPreferences(test_key.type,
                                                       /*supports_pss=*/true),
            key->GetAlgorithmPreferences());
  TestSSLPrivateKeyMatches(key.get(), pkcs8);
}

TEST_P(SSLPlatformKeyWinTest, KeyMatchesCAPI) {
  const TestKey& test_key = GetTestKey();
  if (test_key.type != EVP_PKEY_RSA) {
    GTEST_SKIP() << "CAPI only supports RSA keys";
  }

  // Load test data.
  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(GetTestCertsDirectory(), test_key.cert_file);
  ASSERT_TRUE(cert);

  std::string pkcs8;
  base::FilePath pkcs8_path =
      GetTestCertsDirectory().AppendASCII(test_key.key_file);
  ASSERT_TRUE(base::ReadFileToString(pkcs8_path, &pkcs8));

  // Import the key into CAPI. Use CRYPT_VERIFYCONTEXT for an ephemeral key.
  crypto::ScopedHCRYPTPROV prov;
  ASSERT_NE(FALSE,
            CryptAcquireContext(crypto::ScopedHCRYPTPROV::Receiver(prov).get(),
                                nullptr, nullptr, PROV_RSA_AES,
                                CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
      << GetLastError();

  std::vector<uint8_t> blob;
  ASSERT_TRUE(PKCS8ToBLOBForCAPI(pkcs8, &blob));

  crypto::ScopedHCRYPTKEY hcryptkey;
  ASSERT_NE(FALSE,
            CryptImportKey(prov.get(), blob.data(), blob.size(),
                           /*hPubKey=*/0, /*dwFlags=*/0,
                           crypto::ScopedHCRYPTKEY::Receiver(hcryptkey).get()))
      << GetLastError();
  // Release |hcryptkey| so it does not outlive |prov|.
  hcryptkey.reset();

  scoped_refptr<SSLPrivateKey> key =
      WrapCAPIPrivateKey(cert.get(), std::move(prov), AT_SIGNATURE);
  ASSERT_TRUE(key);

  std::vector<uint16_t> expected = {
      SSL_SIGN_RSA_PKCS1_SHA256,
      SSL_SIGN_RSA_PKCS1_SHA384,
      SSL_SIGN_RSA_PKCS1_SHA512,
      SSL_SIGN_RSA_PKCS1_SHA1,
  };
  EXPECT_EQ(expected, key->GetAlgorithmPreferences());
  TestSSLPrivateKeyMatches(key.get(), pkcs8);
}

INSTANTIATE_TEST_SUITE_P(All,
                         SSLPlatformKeyWinTest,
                         testing::ValuesIn(kTestKeys),
                         TestParamsToString);

TEST(UnexportableSSLPlatformKeyWinTest, WrapUnexportableKeySlowly) {
  auto provider = crypto::GetUnexportableKeyProvider({});
  if (!provider) {
    GTEST_SKIP() << "Hardware-backed keys are not supported.";
  }

  const crypto::SignatureVerifier::SignatureAlgorithm algorithms[] = {
      crypto::SignatureVerifier::SignatureAlgorithm::ECDSA_SHA256,
      crypto::SignatureVerifier::SignatureAlgorithm::RSA_PKCS1_SHA256};
  auto key = provider->GenerateSigningKeySlowly(algorithms);
  if (!key) {
    // Could be hitting crbug.com/41494935. Fine to skip the test as the
    // UnexportableKeyProvider logic is covered in another test suite.
    GTEST_SKIP()
        << "Workaround for https://issues.chromium.org/issues/41494935";
  }

  auto ssl_private_key = WrapUnexportableKeySlowly(*key);
  ASSERT_TRUE(ssl_private_key);
}

}  // namespace net
```