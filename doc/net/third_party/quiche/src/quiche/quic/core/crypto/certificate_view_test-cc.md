Response:
Let's break down the thought process for analyzing this C++ test file and generating the response.

1. **Understanding the Goal:** The primary request is to understand the purpose of `certificate_view_test.cc`, identify its functionalities, potential connections to JavaScript, reasoning with hypothetical inputs/outputs, common errors, and debugging steps.

2. **Initial Scan and Keyword Recognition:**  A quick scan of the code reveals several important keywords and patterns:
    * `#include`:  Indicates dependencies on other C++ files, including `"quiche/quic/core/crypto/certificate_view.h"`. This immediately suggests the file is testing the `CertificateView` class.
    * `TEST`:  Macros from a testing framework (likely Google Test), signifying this is a unit test file.
    * `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_THAT`:  Assertions used in unit tests to verify expected behavior.
    * `CertificateView`, `CertificatePrivateKey`: Core classes related to certificate handling.
    * `ParseSingleCertificate`, `LoadPemFromStream`, `Sign`, `VerifySignature`:  Methods within `CertificateView` and related classes.
    * `subject_alt_name_domains`, `subject_alt_name_ips`, `validity_start`, `validity_end`: Accessors for certificate properties.
    * `kTestCertificate`, `kTestCertificatePem`, `kTestCertificatePrivateKey`, `kTestCertificatePrivateKeyPem`, etc.:  Constants likely holding test certificate data in various formats (DER, PEM).
    * `SSL_SIGN_*`: Constants related to signature algorithms.
    * `PemReadResult`: A structure likely used for parsing PEM-encoded data.

3. **Identifying Core Functionalities by Examining Tests:** The test names provide direct clues about the functionality being tested:
    * `PemParser`: Tests the ability to parse PEM-encoded data.
    * `Parse`: Tests parsing a single certificate in DER format.
    * `ParseCertWithUnknownSanType`: Tests handling certificates with unknown Subject Alternative Name types.
    * `PemSingleCertificate`, `PemMultipleCertificates`, `PemNoCertificates`: Tests loading certificate chains from PEM streams.
    * `SignAndVerify`: Tests signing data with a private key and verifying the signature with the corresponding public key from a certificate.
    * `PrivateKeyPem`, `PrivateKeyEcdsaPem`: Tests loading private keys from PEM files.
    * `DerTime`: Tests parsing different date/time formats within certificates.
    * `NameAttribute`: Tests parsing and representing attributes within the certificate's subject name.
    * `SupportedSignatureAlgorithmsForQuicIsUpToDate`:  Tests that the list of supported signature algorithms is current.

4. **Summarizing the Functionality:** Based on the identified tests, the file primarily focuses on verifying the correctness of the `CertificateView` class and related utility functions. Key functionalities include:
    * Parsing certificates from DER and PEM formats.
    * Extracting information from certificates (SANs, validity dates, public key type, subject).
    * Loading private keys from PEM format.
    * Performing signing and signature verification operations.
    * Handling different date/time formats and certificate attributes.

5. **Considering JavaScript Relevance:** The core C++ code has no direct execution in a JavaScript environment. However, its *purpose* relates to security aspects that are also relevant in JavaScript, particularly in browser contexts or Node.js applications dealing with HTTPS, TLS, and certificate validation. This leads to the examples of:
    * Browser certificate validation.
    * Node.js HTTPS server setup.
    * Web Crypto API usage.

6. **Developing Hypothetical Inputs and Outputs:** For each test case, consider a simple scenario:
    * **`PemParser`:** Input: PEM-formatted certificate string. Output: Parsed certificate data (type and contents).
    * **`Parse`:** Input: DER-encoded certificate. Output: Extracted certificate information (SANs, validity, etc.).
    * **`SignAndVerify`:** Input: Data to sign, private key. Output: Signature. Then, input: Data, signature, public key. Output: Verification result (true/false).

7. **Identifying Common Errors:** Think about typical mistakes developers make when working with certificates:
    * Incorrect PEM formatting.
    * Mismatched private keys and certificates.
    * Expired certificates.
    * Incorrect signature algorithm usage.

8. **Tracing User Actions for Debugging:**  Imagine a scenario where a certificate issue arises. How might a user end up relying on this code?  The most common path involves establishing a secure connection:
    * User types a URL (HTTPS).
    * Browser initiates a TLS handshake.
    * Server provides a certificate.
    * The browser (or QUIC implementation) uses code similar to this to validate the certificate.

9. **Structuring the Response:** Organize the findings into clear sections as requested: Functionality, JavaScript Relevance, Logic Reasoning, Common Errors, and Debugging. Use bullet points and code examples for clarity.

10. **Review and Refine:**  Read through the generated response to ensure accuracy, completeness, and clarity. Check for any logical inconsistencies or missing information. For example, initially, I might have focused too much on the C++ specifics. The refinement step involves explicitly connecting these C++ functionalities to their real-world implications, especially concerning JavaScript and web security.
这个C++源代码文件 `certificate_view_test.cc` 的主要功能是 **测试 `certificate_view.h` 中定义的 `CertificateView` 类及其相关功能**。 `CertificateView` 类在 Chromium 的 QUIC 协议实现中扮演着重要的角色，它用于**解析、存储和操作 X.509 证书**。

下面详细列举其功能点，并根据要求进行分析：

**1. 功能列举:**

* **PEM 格式解析测试 (`PemParser`):**
    * 测试从 PEM 格式的字符串流中读取下一个 PEM 消息的功能。
    * 验证是否能正确识别 PEM 消息的类型（例如 "CERTIFICATE"）和内容。
    * 测试到达 PEM 流末尾的情况。
* **证书解析测试 (`Parse`):**
    * 测试从 DER 编码的证书数据中解析 `CertificateView` 对象的功能。
    * 验证解析后的 `CertificateView` 对象是否能正确提取证书的各个关键信息，例如：
        * **主体备用名称 (Subject Alternative Names, SANs):**  包括域名和 IP 地址。
        * **公钥类型 (Public Key Type):** 例如 RSA。
        * **有效期 (Validity Period):** 开始时间和结束时间。
        * **可读的主题 (Human-Readable Subject):**  例如 "C=US,ST=California,...CN=127.0.0.1"。
* **处理未知 SAN 类型证书测试 (`ParseCertWithUnknownSanType`):**
    * 测试 `CertificateView` 是否能处理包含未知类型 SAN 的证书，并能够成功解析。
* **从 PEM 加载单个证书测试 (`PemSingleCertificate`):**
    * 测试从包含单个 PEM 编码证书的流中加载证书链的功能。
    * 验证加载的链中是否只包含该证书。
* **从 PEM 加载多个证书测试 (`PemMultipleCertificates`):**
    * 测试从包含多个 PEM 编码证书的流中加载证书链的功能。
    * 验证加载的链中是否包含所有证书，并能正确识别其内容。
* **从 PEM 加载空证书测试 (`PemNoCertificates`):**
    * 测试从不包含任何证书的 PEM 流中加载证书链的功能。
    * 验证加载的链是否为空。
* **签名和验证测试 (`SignAndVerify`):**
    * 测试使用私钥对数据进行签名的功能。
    * 测试使用 `CertificateView` 对象（持有公钥）来验证签名的功能。
    * 验证使用正确的密钥和数据可以成功验证签名，而使用错误的密钥或数据验证会失败。
* **从 PEM 加载私钥测试 (`PrivateKeyPem` 和 `PrivateKeyEcdsaPem`):**
    * 测试从 PEM 格式的私钥文件中加载 `CertificatePrivateKey` 对象的功能。
    * 验证加载的私钥与对应的证书公钥是否匹配。
    * 针对 ECDSA 私钥，验证其是否支持特定的签名算法。
* **DER 时间解析测试 (`DerTime`):**
    * 测试解析 DER 编码的时间戳的功能，支持 `ASN1_GENERALIZEDTIME` 和 `ASN1_UTCTIME` 两种格式。
    * 验证对于不同格式和有效的时间字符串，能否正确解析为 `QuicWallTime` 对象。
    * 测试解析无效时间字符串的情况，预期返回空值。
* **名称属性测试 (`NameAttribute`):**
    * 测试将 X.509 证书的名称属性（例如 Common Name, Organization）转换为可读字符串的功能。
    * 能够处理包含特殊字符的属性值。
    * 能够处理未知的 OID (Object Identifier)。
* **支持的签名算法测试 (`SupportedSignatureAlgorithmsForQuicIsUpToDate`):**
    * 测试 QUIC 支持的签名算法列表是否是最新的。
    * 遍历所有可能的签名算法值，并验证其是否与预期的公钥类型一致。

**2. 与 JavaScript 的关系及举例:**

虽然这段 C++ 代码本身并不直接在 JavaScript 环境中运行，但它所测试的功能 **与 JavaScript 在处理网络安全和加密时息息相关**。  尤其是在浏览器环境中，JavaScript 需要与底层的网络栈交互来建立安全的 HTTPS 连接。

以下是一些 JavaScript 与 `CertificateView` 功能相关的场景举例：

* **浏览器证书验证:** 当用户访问一个 HTTPS 网站时，浏览器会从服务器接收到证书。浏览器内部的 C++ 代码（例如 Chromium 的网络栈）会使用类似于 `CertificateView` 的类来解析和验证这个证书。
    * **假设输入:**  浏览器收到一个服务器发送的 DER 编码的证书数据（对应 `Parse` 测试的输入）。
    * **逻辑推理:**  底层的 C++ 代码会使用 `CertificateView::ParseSingleCertificate` 解析这个数据。
    * **JavaScript 的体现:**  JavaScript 代码可以通过 `navigator.connection.getSecurityInfo()` 或类似的 API 获取连接的安全信息，其中就包含了证书的相关信息。虽然 JavaScript 不能直接操作 `CertificateView` 对象，但它能间接地通过浏览器提供的 API 获取其解析后的结果，例如证书的有效期、SANs 等，并根据这些信息来显示安全状态。
* **Node.js HTTPS 服务器:** 在 Node.js 中，可以使用 `https` 模块创建 HTTPS 服务器。创建服务器时，需要提供服务器的证书和私钥。
    * **假设输入:**  开发者在 Node.js 中配置 HTTPS 服务器时，提供了 PEM 格式的证书和私钥文件（对应 `PemSingleCertificate` 和 `PrivateKeyPem` 测试的相关数据）。
    * **逻辑推理:**  Node.js 底层（可能也依赖于 OpenSSL 或类似的库）会解析这些 PEM 文件。虽然不是直接使用 `CertificateView`，但其功能是类似的。
    * **JavaScript 的体现:**  JavaScript 代码调用 `https.createServer()` 时，会将证书和私钥传递给底层，从而建立安全的连接。客户端浏览器在连接到这个服务器时，会进行证书验证，这个过程又会涉及到类似 `CertificateView` 的功能。
* **Web Crypto API:**  Web Crypto API 允许 JavaScript 执行加密操作，包括签名和验证。虽然通常情况下 JavaScript 不会直接解析原始的 X.509 证书，但它可以利用浏览器提供的证书对象进行操作。
    * **假设输入:**  一个 JavaScript 应用程序需要验证一个由服务器签名的消息。服务器提供了签名和它的证书。
    * **逻辑推理:**  浏览器底层的 C++ 代码（类似于 `CertificateView`）已经解析并验证了这个服务器的证书。
    * **JavaScript 的体现:**  JavaScript 代码可以使用 `crypto.subtle.verify()` 方法，并传入从服务器获取的签名、原始数据以及代表服务器公钥的 `CryptoKey` 对象（这个 `CryptoKey` 对象通常是从服务器证书中提取出来的）。浏览器内部会使用已经验证过的证书信息来进行签名验证，这与 `SignAndVerify` 测试的功能类似。

**3. 逻辑推理的假设输入与输出:**

以下是一些测试用例的假设输入和输出，对应代码中的一些测试：

* **`PemParser` Test:**
    * **假设输入:**  包含以下内容的字符串流:
      ```
      -----BEGIN CERTIFICATE-----
      MIIE...（证书内容）...
      -----END CERTIFICATE-----
      ```
    * **预期输出:**  第一次 `ReadNextPemMessage` 调用返回 `PemReadResult::kOk`，`type` 为 "CERTIFICATE"，`contents` 为 "MIIE...（证书内容）..."。第二次调用返回 `PemReadResult::kEof`。
* **`Parse` Test:**
    * **假设输入:**  DER 编码的证书数据，例如 `kTestCertificate`。
    * **预期输出:**  `CertificateView::ParseSingleCertificate` 返回一个非空的 `CertificateView` 指针。调用 `view->subject_alt_name_domains()` 返回包含 "www.example.org", "mail.example.org", "mail.example.com" 的容器。调用 `view->validity_start()` 返回表示 2020年1月30日的时间戳。
* **`SignAndVerify` Test:**
    * **假设输入:**  字符串 "A really important message"，使用 `kTestCertificatePrivateKey` 加载的私钥，签名算法 `SSL_SIGN_RSA_PSS_RSAE_SHA256`。
    * **预期输出:**  `key->Sign()` 返回一个非空的签名字符串。使用 `kTestCertificate` 加载的 `CertificateView` 调用 `view->VerifySignature()`，传入相同的数据、签名和算法，返回 `true`。如果传入不同的数据或签名，则返回 `false`。

**4. 涉及用户或编程常见的使用错误:**

* **PEM 格式错误:** 用户可能提供了格式不正确的 PEM 文件，例如缺少 `-----BEGIN ...-----` 或 `-----END ...-----` 行，或者内容不是 Base64 编码。这会导致 `LoadPemFromStream` 或 `ReadNextPemMessage` 解析失败。
    * **示例:**  提供的 PEM 文件内容为 "MIIE...（证书内容）..."，缺少起始和结束标记。
* **私钥和证书不匹配:** 用户可能提供的私钥与证书的公钥不匹配。这会导致 `PrivateKey::MatchesPublicKey` 返回 `false`，并且使用该私钥签名的消息无法被对应的证书验证。
    * **示例:**  使用 `key1.pem` 的私钥生成签名，然后尝试用从 `cert2.pem` 解析出的 `CertificateView` 来验证签名。
* **证书过期:** 用户可能使用了过期的证书。虽然 `CertificateView` 可以解析过期证书，但在实际的网络连接中，浏览器或其他客户端会拒绝连接，因为证书的有效期已经失效。
    * **示例:**  服务器配置了一个有效期已过的证书。当客户端尝试连接时，会收到证书无效的错误。
* **使用了不支持的签名算法:**  在签名和验证过程中，如果使用了客户端或服务器不支持的签名算法，会导致连接失败或验证失败。
    * **示例:**  服务器配置为使用一个过时的或非常规的签名算法，而客户端的 QUIC 实现不支持该算法。

**5. 用户操作如何一步步到达这里 (作为调试线索):**

通常情况下，普通用户不会直接与这个 C++ 代码交互。这个代码是 Chromium 浏览器网络栈的一部分，主要在浏览器内部运行。以下是一些可能导致这个代码被执行的场景，作为调试线索：

1. **用户在浏览器地址栏输入一个 HTTPS 网址并访问:**
   * 浏览器会解析 URL，识别出是 HTTPS 协议。
   * 浏览器会尝试与服务器建立 TLS 或 QUIC 连接。
   * 在连接握手阶段，服务器会向浏览器发送其证书链。
   * **Chromium 的网络栈会调用类似 `CertificateView::LoadPemFromStream` 或 `CertificateView::ParseSingleCertificate` 来解析服务器发送的证书数据。**
   * `CertificateView` 会提取证书的 SANs，用于验证服务器的域名是否与用户访问的域名匹配。
   * `CertificateView` 会检查证书的有效期，确保证书尚未过期。
   * `CertificateView` 会提取证书的公钥，用于验证服务器发送的签名或加密数据。

2. **浏览器加载包含 HTTPS 内容的网页:**
   * 网页可能包含来自其他 HTTPS 来源的资源（例如图片、脚本）。
   * 浏览器会为这些资源建立新的 HTTPS 连接。
   * 同样，证书的解析和验证过程会触发 `CertificateView` 的相关代码。

3. **Chromium 浏览器自身进行更新或组件加载:**
   * Chromium 的某些组件可能需要加载或验证自身的签名，这可能会涉及到证书的解析。

4. **开发者在开发与网络相关的 Chromium 功能:**
   * 开发人员可能会编写涉及证书处理的代码，并使用单元测试（如 `certificate_view_test.cc`）来验证其功能的正确性。
   * 他们可能会使用调试器单步执行代码，查看 `CertificateView` 对象的内部状态，以排查证书解析或验证过程中的问题。

**调试线索:**

如果用户报告了与 HTTPS 连接相关的问题（例如证书错误、连接不安全），开发人员可以按照以下步骤进行调试，并可能最终追溯到 `certificate_view_test.cc` 中测试的功能：

* **检查浏览器的安全信息:**  查看浏览器地址栏的锁形图标，点击查看证书详情。这可以提供关于证书是否有效、SANs 是否匹配等初步信息。
* **使用 `chrome://net-internals/#events`:**  这个 Chromium 内部工具可以记录网络事件，包括 TLS 握手过程和证书验证的详细信息。可以查看是否有与证书解析或验证相关的错误日志。
* **使用网络抓包工具 (如 Wireshark):**  可以捕获浏览器与服务器之间的网络数据包，查看服务器发送的原始证书数据，并手动分析其结构。
* **在 Chromium 源代码中设置断点:**  如果怀疑 `CertificateView` 的解析过程有问题，可以在 `certificate_view.cc` 或相关的 BoringSSL 代码中设置断点，单步执行代码，查看证书数据的解析过程。`certificate_view_test.cc` 中的测试用例可以作为理解代码逻辑和验证修复的参考。

总而言之，`certificate_view_test.cc` 是 Chromium QUIC 协议中非常重要的一个测试文件，它确保了 `CertificateView` 类能够正确地处理各种证书格式和场景，从而保障了 HTTPS 连接的安全性和可靠性。虽然 JavaScript 不直接操作这些底层的 C++ 类，但其安全机制的基石正是这些代码的正确运行。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/crypto/certificate_view_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/crypto/certificate_view.h"

#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "openssl/base.h"
#include "openssl/bytestring.h"
#include "openssl/evp.h"
#include "openssl/ssl.h"
#include "quiche/quic/core/crypto/boring_utils.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/test_certificates.h"
#include "quiche/common/platform/api/quiche_time_utils.h"

namespace quic {
namespace test {
namespace {

using ::testing::ElementsAre;
using ::testing::HasSubstr;
using ::testing::Optional;

TEST(CertificateViewTest, PemParser) {
  std::stringstream stream(kTestCertificatePem);
  PemReadResult result = ReadNextPemMessage(&stream);
  EXPECT_EQ(result.status, PemReadResult::kOk);
  EXPECT_EQ(result.type, "CERTIFICATE");
  EXPECT_EQ(result.contents, kTestCertificate);

  result = ReadNextPemMessage(&stream);
  EXPECT_EQ(result.status, PemReadResult::kEof);
}

TEST(CertificateViewTest, Parse) {
  std::unique_ptr<CertificateView> view =
      CertificateView::ParseSingleCertificate(kTestCertificate);
  ASSERT_TRUE(view != nullptr);

  EXPECT_THAT(view->subject_alt_name_domains(),
              ElementsAre(absl::string_view("www.example.org"),
                          absl::string_view("mail.example.org"),
                          absl::string_view("mail.example.com")));
  EXPECT_THAT(view->subject_alt_name_ips(),
              ElementsAre(QuicIpAddress::Loopback4()));
  EXPECT_EQ(EVP_PKEY_id(view->public_key()), EVP_PKEY_RSA);

  const QuicWallTime validity_start = QuicWallTime::FromUNIXSeconds(
      *quiche::QuicheUtcDateTimeToUnixSeconds(2020, 1, 30, 18, 13, 59));
  EXPECT_EQ(view->validity_start(), validity_start);
  const QuicWallTime validity_end = QuicWallTime::FromUNIXSeconds(
      *quiche::QuicheUtcDateTimeToUnixSeconds(2020, 2, 2, 18, 13, 59));
  EXPECT_EQ(view->validity_end(), validity_end);
  EXPECT_EQ(view->public_key_type(), PublicKeyType::kRsa);
  EXPECT_EQ(PublicKeyTypeToString(view->public_key_type()), "RSA");

  EXPECT_EQ("C=US,ST=California,L=Mountain View,O=QUIC Server,CN=127.0.0.1",
            view->GetHumanReadableSubject());
}

TEST(CertificateViewTest, ParseCertWithUnknownSanType) {
  std::stringstream stream(kTestCertWithUnknownSanTypePem);
  PemReadResult result = ReadNextPemMessage(&stream);
  EXPECT_EQ(result.status, PemReadResult::kOk);
  EXPECT_EQ(result.type, "CERTIFICATE");

  std::unique_ptr<CertificateView> view =
      CertificateView::ParseSingleCertificate(result.contents);
  EXPECT_TRUE(view != nullptr);
}

TEST(CertificateViewTest, PemSingleCertificate) {
  std::stringstream pem_stream(kTestCertificatePem);
  std::vector<std::string> chain =
      CertificateView::LoadPemFromStream(&pem_stream);
  EXPECT_THAT(chain, ElementsAre(kTestCertificate));
}

TEST(CertificateViewTest, PemMultipleCertificates) {
  std::stringstream pem_stream(kTestCertificateChainPem);
  std::vector<std::string> chain =
      CertificateView::LoadPemFromStream(&pem_stream);
  EXPECT_THAT(chain,
              ElementsAre(kTestCertificate, HasSubstr("QUIC Server Root CA")));
}

TEST(CertificateViewTest, PemNoCertificates) {
  std::stringstream pem_stream("one\ntwo\nthree\n");
  std::vector<std::string> chain =
      CertificateView::LoadPemFromStream(&pem_stream);
  EXPECT_TRUE(chain.empty());
}

TEST(CertificateViewTest, SignAndVerify) {
  std::unique_ptr<CertificatePrivateKey> key =
      CertificatePrivateKey::LoadFromDer(kTestCertificatePrivateKey);
  ASSERT_TRUE(key != nullptr);

  std::string data = "A really important message";
  std::string signature = key->Sign(data, SSL_SIGN_RSA_PSS_RSAE_SHA256);
  ASSERT_FALSE(signature.empty());

  std::unique_ptr<CertificateView> view =
      CertificateView::ParseSingleCertificate(kTestCertificate);
  ASSERT_TRUE(view != nullptr);
  EXPECT_TRUE(key->MatchesPublicKey(*view));

  EXPECT_TRUE(
      view->VerifySignature(data, signature, SSL_SIGN_RSA_PSS_RSAE_SHA256));
  EXPECT_FALSE(view->VerifySignature("An unimportant message", signature,
                                     SSL_SIGN_RSA_PSS_RSAE_SHA256));
  EXPECT_FALSE(view->VerifySignature(data, "Not a signature",
                                     SSL_SIGN_RSA_PSS_RSAE_SHA256));
}

TEST(CertificateViewTest, PrivateKeyPem) {
  std::unique_ptr<CertificateView> view =
      CertificateView::ParseSingleCertificate(kTestCertificate);
  ASSERT_TRUE(view != nullptr);

  std::stringstream pem_stream(kTestCertificatePrivateKeyPem);
  std::unique_ptr<CertificatePrivateKey> pem_key =
      CertificatePrivateKey::LoadPemFromStream(&pem_stream);
  ASSERT_TRUE(pem_key != nullptr);
  EXPECT_TRUE(pem_key->MatchesPublicKey(*view));

  std::stringstream legacy_stream(kTestCertificatePrivateKeyLegacyPem);
  std::unique_ptr<CertificatePrivateKey> legacy_key =
      CertificatePrivateKey::LoadPemFromStream(&legacy_stream);
  ASSERT_TRUE(legacy_key != nullptr);
  EXPECT_TRUE(legacy_key->MatchesPublicKey(*view));
}

TEST(CertificateViewTest, PrivateKeyEcdsaPem) {
  std::stringstream pem_stream(kTestEcPrivateKeyLegacyPem);
  std::unique_ptr<CertificatePrivateKey> key =
      CertificatePrivateKey::LoadPemFromStream(&pem_stream);
  ASSERT_TRUE(key != nullptr);
  EXPECT_TRUE(key->ValidForSignatureAlgorithm(SSL_SIGN_ECDSA_SECP256R1_SHA256));
}

TEST(CertificateViewTest, DerTime) {
  EXPECT_THAT(ParseDerTime(CBS_ASN1_GENERALIZEDTIME, "19700101000024Z"),
              Optional(QuicWallTime::FromUNIXSeconds(24)));
  EXPECT_THAT(ParseDerTime(CBS_ASN1_GENERALIZEDTIME, "19710101000024Z"),
              Optional(QuicWallTime::FromUNIXSeconds(365 * 86400 + 24)));
  EXPECT_THAT(ParseDerTime(CBS_ASN1_UTCTIME, "700101000024Z"),
              Optional(QuicWallTime::FromUNIXSeconds(24)));
  EXPECT_TRUE(ParseDerTime(CBS_ASN1_UTCTIME, "200101000024Z").has_value());

  EXPECT_EQ(ParseDerTime(CBS_ASN1_GENERALIZEDTIME, ""), std::nullopt);
  EXPECT_EQ(ParseDerTime(CBS_ASN1_GENERALIZEDTIME, "19700101000024.001Z"),
            std::nullopt);
  EXPECT_EQ(ParseDerTime(CBS_ASN1_GENERALIZEDTIME, "19700101000024Q"),
            std::nullopt);
  EXPECT_EQ(ParseDerTime(CBS_ASN1_GENERALIZEDTIME, "19700101000024-0500"),
            std::nullopt);
  EXPECT_EQ(ParseDerTime(CBS_ASN1_GENERALIZEDTIME, "700101000024ZZ"),
            std::nullopt);
  EXPECT_EQ(ParseDerTime(CBS_ASN1_GENERALIZEDTIME, "19700101000024.00Z"),
            std::nullopt);
  EXPECT_EQ(ParseDerTime(CBS_ASN1_GENERALIZEDTIME, "19700101000024.Z"),
            std::nullopt);
  EXPECT_EQ(ParseDerTime(CBS_ASN1_GENERALIZEDTIME, "197O0101000024Z"),
            std::nullopt);
  EXPECT_EQ(ParseDerTime(CBS_ASN1_GENERALIZEDTIME, "19700101000024.0O1Z"),
            std::nullopt);
  EXPECT_EQ(ParseDerTime(CBS_ASN1_GENERALIZEDTIME, "-9700101000024Z"),
            std::nullopt);
  EXPECT_EQ(ParseDerTime(CBS_ASN1_GENERALIZEDTIME, "1970-101000024Z"),
            std::nullopt);

  EXPECT_TRUE(ParseDerTime(CBS_ASN1_UTCTIME, "490101000024Z").has_value());
  // This should parse as 1950, which predates UNIX epoch.
  EXPECT_FALSE(ParseDerTime(CBS_ASN1_UTCTIME, "500101000024Z").has_value());

  EXPECT_THAT(ParseDerTime(CBS_ASN1_GENERALIZEDTIME, "19700101230000Z"),
              Optional(QuicWallTime::FromUNIXSeconds(23 * 3600)));
  EXPECT_EQ(ParseDerTime(CBS_ASN1_GENERALIZEDTIME, "19700101240000Z"),
            std::nullopt);
}

TEST(CertificateViewTest, NameAttribute) {
  // OBJECT_IDENTIFIER { 1.2.840.113554.4.1.112411 }
  // UTF8String { "Test" }
  std::string unknown_oid;
  ASSERT_TRUE(absl::HexStringToBytes("060b2a864886f712040186ee1b0c0454657374",
                                     &unknown_oid));
  EXPECT_EQ("1.2.840.113554.4.1.112411=Test",
            X509NameAttributeToString(StringPieceToCbs(unknown_oid)));

  // OBJECT_IDENTIFIER { 2.5.4.3 }
  // UTF8String { "Bell: \x07" }
  std::string non_printable;
  ASSERT_TRUE(
      absl::HexStringToBytes("06035504030c0742656c6c3a2007", &non_printable));
  EXPECT_EQ(R"(CN=Bell: \x07)",
            X509NameAttributeToString(StringPieceToCbs(non_printable)));

  // OBJECT_IDENTIFIER { "\x55\x80" }
  // UTF8String { "Test" }
  std::string invalid_oid;
  ASSERT_TRUE(absl::HexStringToBytes("060255800c0454657374", &invalid_oid));
  EXPECT_EQ("(5580)=Test",
            X509NameAttributeToString(StringPieceToCbs(invalid_oid)));
}

TEST(CertificateViewTest, SupportedSignatureAlgorithmsForQuicIsUpToDate) {
  QuicSignatureAlgorithmVector supported =
      SupportedSignatureAlgorithmsForQuic();
  for (int i = 0; i < std::numeric_limits<uint16_t>::max(); i++) {
    uint16_t sigalg = static_cast<uint16_t>(i);
    PublicKeyType key_type = PublicKeyTypeFromSignatureAlgorithm(sigalg);
    if (absl::c_find(supported, sigalg) == supported.end()) {
      EXPECT_EQ(key_type, PublicKeyType::kUnknown);
    } else {
      EXPECT_NE(key_type, PublicKeyType::kUnknown);
    }
  }
}

}  // namespace
}  // namespace test
}  // namespace quic
```