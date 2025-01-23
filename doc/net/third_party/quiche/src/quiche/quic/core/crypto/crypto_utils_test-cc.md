Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The request asks for the file's functionality, its relation to JavaScript, logical reasoning examples, common usage errors, and debugging information. This means we need to understand *what* the code does, *how* it might interact with web technologies, *how* we can use it to infer behavior, *what* mistakes developers make, and *how* someone might end up examining this file.

2. **Initial Scan and Keywords:**  Quickly read through the code, looking for recognizable patterns and keywords.
    * Includes: `crypto_utils.h`, `quic_test.h`, `openssl/err.h`, `openssl/ssl.h`. These suggest this file is testing cryptographic utilities within the QUIC protocol, likely using OpenSSL.
    * `namespace quic::test`: This confirms it's a test file.
    * `TEST_F(CryptoUtilsTest, ...)`:  These are Google Test framework test cases. Each `TEST_F` defines a specific aspect of `CryptoUtils` being tested.
    * Function names in `TEST_F` blocks: `HandshakeFailureReasonToString`, `AuthTagLengths`, `ValidateChosenVersion`, `ValidateServerVersions...`, `ValidateCryptoLabels`, `GetSSLErrorStack`. These directly point to the functions being tested in the `crypto_utils.h` file (which we don't have the content of, but can infer its purpose).

3. **Analyze Each Test Case:**  Go through each `TEST_F` and deduce its purpose.

    * `HandshakeFailureReasonToString`:  This is clearly testing a function that converts an enum (`HandshakeFailureReason`) to a human-readable string. This is a common utility for logging and debugging.

    * `AuthTagLengths`: This checks the size of the authentication tag added to encrypted data for different QUIC versions and encryption algorithms (`kAESG`, `kCC20`). The size varies based on the QUIC version.

    * `ValidateChosenVersion`: This tests a function that ensures the client and server agree on a single QUIC version. It iterates through all supported versions.

    * `ValidateServerVersions...`: These three test cases examine the logic for version negotiation and potential downgrade attacks.
        * `NoVersionNegotiation`: Tests the case where the server doesn't offer alternatives.
        * `WithVersionNegotiation`: Tests the scenario where the server offers the client's preferred version.
        * `WithDowngrade`: Checks if the server correctly rejects downgrading to an older version if the client initially supported a newer one.

    * `ValidateCryptoLabels`: This is a crucial test. It verifies that the correct initial encryption keys are generated for different QUIC versions (draft-29, RFCv1, v2) using hardcoded test vectors from the respective specifications. This ensures interoperability.

    * `GetSSLErrorStack`: Tests a function that retrieves and formats the OpenSSL error stack, useful for diagnosing SSL-related issues.

4. **Address Specific Request Points:** Now, go back to the initial request and address each point systematically:

    * **Functionality:** Summarize the purpose of each test case as described above. Group similar functionalities (like version validation).

    * **Relation to JavaScript:**  This requires thinking about *where* QUIC is used in web technologies. QUIC is the underlying transport for HTTP/3. Therefore, the crypto aspects are indirectly related to securing web traffic initiated by JavaScript in browsers. Focus on the *impact* of these cryptographic functions: secure connections, preventing tampering, and ensuring version compatibility. A concrete example would be a `fetch()` request over HTTP/3.

    * **Logical Reasoning:** Select a test case suitable for illustrating logical reasoning. `ValidateServerVersionsWithDowngrade` is a good choice. Formulate clear input (client and server supported versions) and expected output (failure to validate).

    * **Common Usage Errors:** Think about *how* developers might misuse or misunderstand these functions. A common issue would be incorrect version negotiation logic or failing to handle version mismatches gracefully. Provide a scenario.

    * **Debugging:**  Explain the typical workflow of a developer debugging a QUIC connection issue. Start from the user action (e.g., accessing a website) and trace the path to potentially needing to examine this low-level crypto code. Emphasize logging and the role of this test file in verifying the core crypto logic.

5. **Refine and Organize:** Review the generated response for clarity, accuracy, and organization. Ensure the language is precise and easy to understand. Use bullet points or numbered lists where appropriate. Make sure the examples are relevant and illustrate the concepts effectively. For instance, ensuring the JavaScript example links the high-level action to the low-level crypto operation.

6. **Self-Correction/Improvements:**  Initially, I might have focused too much on the specific OpenSSL calls. However, the request is about the *functionality* and its *impact*. Therefore, shifting the focus to the broader implications for QUIC and web security is important. Also, initially, the JavaScript connection might have been too vague. Specifying `fetch()` over HTTP/3 makes it more concrete. Similarly, for debugging, starting from a user-visible problem provides better context.
这个文件 `crypto_utils_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，它的主要功能是 **测试 `crypto_utils.h` 中定义的加密相关工具函数的功能和正确性**。

具体来说，这个测试文件通过一系列的单元测试来验证 `CryptoUtils` 类中的各种静态方法，涵盖了以下几个方面：

**核心功能：**

1. **握手失败原因的字符串表示：**
   - `HandshakeFailureReasonToString` 测试函数验证了 `CryptoUtils::HandshakeFailureReasonToString` 方法能够将 `HandshakeFailureReason` 枚举类型的值正确转换为对应的字符串描述。这对于调试和日志记录非常有用，可以更清晰地了解握手失败的原因。

2. **认证标签长度的确定：**
   - `AuthTagLengths` 测试函数验证了对于不同的 QUIC 版本和加密算法（例如 AES-GCM 和 ChaCha20-Poly1305），`CryptoUtils` 正确计算和返回认证标签的长度。这对于数据包的加密和解密至关重要。

3. **选择的 QUIC 版本的验证：**
   - `ValidateChosenVersion` 测试函数验证了 `CryptoUtils::ValidateChosenVersion` 方法能够正确判断客户端和服务器选择的 QUIC 版本是否一致。这对于确保双方能够使用相同的协议进行通信至关重要。

4. **服务器支持的 QUIC 版本的验证：**
   - `ValidateServerVersionsNoVersionNegotiation`、`ValidateServerVersionsWithVersionNegotiation` 和 `ValidateServerVersionsWithDowngrade` 这三个测试函数共同验证了 `CryptoUtils::ValidateServerVersions` 方法在不同场景下（没有版本协商、有版本协商、潜在的降级攻击）的正确性。这保证了版本协商过程的安全可靠。

5. **加密标签的验证：**
   - `ValidateCryptoLabels` 测试函数验证了 `CryptoUtils::CreateInitialObfuscators` 方法能够根据不同的 QUIC 版本和连接 ID 生成正确的初始加密密钥。这对于 QUIC 握手阶段的加密至关重要，并且使用了 RFC 中定义的测试向量进行验证。

6. **获取 OpenSSL 错误堆栈信息：**
   - `GetSSLErrorStack` 测试函数验证了 `CryptoUtils::GetSSLErrorStack` 方法能够正确获取并格式化 OpenSSL 库的错误信息。这对于诊断加密相关的错误非常有用。

**与 JavaScript 功能的关系：**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它所测试的功能直接关系到基于 QUIC 协议的 Web 应用的安全性，而这些 Web 应用通常会使用 JavaScript 进行开发。

**举例说明：**

假设一个 Web 浏览器使用 HTTP/3 (基于 QUIC) 与服务器建立连接。

1. **握手失败：** 如果握手过程中出现问题，例如客户端发送的 Nonce 不正确，`CryptoUtils::HandshakeFailureReasonToString` 的输出可能会出现在浏览器的开发者工具或者服务器的日志中，帮助开发人员快速定位问题（例如 "CLIENT_NONCE_INVALID_FAILURE"）。在 JavaScript 中，这可能会表现为 `fetch()` 请求失败，并且错误信息中包含与 QUIC 握手相关的提示。

2. **版本协商：**  当浏览器和服务器尝试建立连接时，它们会协商使用哪个 QUIC 版本。 `CryptoUtils::ValidateServerVersions` 的测试确保了这个协商过程的安全性。 如果协商失败或存在降级攻击的风险，浏览器的 JavaScript 代码可能会收到连接错误，用户可能会看到 "连接被重置" 或类似的提示。

3. **加密：** QUIC 连接的所有数据都经过加密。 `AuthTagLengths` 和 `ValidateCryptoLabels` 中测试的功能保证了加密算法和密钥的正确性。 这确保了通过 JavaScript 的 `fetch()` 或 WebSocket 发送的数据能够安全地传输。

**逻辑推理的例子：**

考虑 `ValidateServerVersionsWithDowngrade` 测试函数。

**假设输入：**

* `client_version`: 最新支持的 QUIC 版本 (例如：ParsedQuicVersion::RFCv1())
* `server_version`: 较旧的 QUIC 版本 (例如：ParsedQuicVersion::Draft29())
* `version_information_other_versions`: 服务器通告的其它版本，包含客户端支持的最新版本。
* `client_original_supported_versions`: 客户端最初支持的版本列表，包含最新版本。

**预期输出：**

* `CryptoUtils::ValidateServerVersions` 返回 `false` (表示验证失败)。
* `error_details` 包含非空的错误信息，指示存在潜在的降级攻击。

**原因：**  如果服务器选择了客户端最初支持的较旧版本，即使客户端也支持更新的版本，这可能是一个降级攻击。QUIC 协议需要能够检测并防止这种攻击。

**用户或编程常见的使用错误：**

1. **错误的版本配置：**  开发者在配置 QUIC 服务器时，可能会错误地配置支持的 QUIC 版本列表，导致 `ValidateChosenVersion` 或 `ValidateServerVersions` 检测到不一致，从而导致连接失败。用户可能看到浏览器报告 "ERR_QUIC_PROTOCOL_ERROR" 或类似的错误。

2. **未处理握手失败：**  服务器或客户端在握手失败后没有正确处理错误，例如没有记录详细的错误信息 (`HandshakeFailureReasonToString` 的输出)，导致问题难以追踪。

3. **错误的加密参数配置：**  虽然 `CryptoUtils` 封装了底层的加密操作，但在某些情况下，开发者可能需要配置相关的加密参数。如果配置不当，可能会导致加密失败，`AuthTagLengths` 的测试就保证了这些参数的正确计算。

**用户操作到达这里的调试线索：**

1. **用户报告网站连接问题：** 用户在使用 Chrome 浏览器访问某个网站时，遇到连接失败或者连接不稳定等问题。

2. **开发人员检查网络日志：** 开发人员查看 Chrome 浏览器的 `chrome://net-export/` 或服务器端的网络日志，发现与 QUIC 握手相关的错误信息。

3. **定位到 QUIC 握手失败：** 日志信息可能包含 `HandshakeFailureReason` 的枚举值，例如 `CLIENT_NONCE_INVALID_FAILURE`。

4. **需要深入了解 QUIC 加密细节：** 为了理解为什么会出现这个握手失败原因，开发人员可能需要查看 QUIC 协议的实现细节，包括加密相关的部分。

5. **查看 `crypto_utils_test.cc`：**  为了验证 QUIC 加密工具函数的正确性，以及理解各种握手失败原因的含义，开发人员可能会查看 `net/third_party/quiche/src/quiche/quic/core/crypto/crypto_utils_test.cc` 这个测试文件，了解这些函数的具体功能和预期行为，以及相关的错误场景。他们可以通过测试用例的命名和内容来推断实际代码的行为。

**总而言之，`crypto_utils_test.cc` 是 QUIC 协议安全性的重要保障，它通过单元测试确保了核心加密工具函数的正确性，从而间接地保障了基于 QUIC 的 Web 应用的安全稳定运行。当用户遇到网络连接问题，特别是与安全协议相关的错误时，开发人员可能会通过检查此类测试文件来理解问题的根源。**

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/crypto/crypto_utils_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/crypto/crypto_utils.h"

#include <memory>
#include <string>

#include "absl/base/macros.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/err.h"
#include "openssl/ssl.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/test_tools/quiche_test_utils.h"

namespace quic {
namespace test {
namespace {

using ::testing::AllOf;
using ::testing::HasSubstr;

class CryptoUtilsTest : public QuicTest {};

TEST_F(CryptoUtilsTest, HandshakeFailureReasonToString) {
  EXPECT_STREQ("HANDSHAKE_OK",
               CryptoUtils::HandshakeFailureReasonToString(HANDSHAKE_OK));
  EXPECT_STREQ("CLIENT_NONCE_UNKNOWN_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_UNKNOWN_FAILURE));
  EXPECT_STREQ("CLIENT_NONCE_INVALID_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_INVALID_FAILURE));
  EXPECT_STREQ("CLIENT_NONCE_NOT_UNIQUE_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_NOT_UNIQUE_FAILURE));
  EXPECT_STREQ("CLIENT_NONCE_INVALID_ORBIT_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_INVALID_ORBIT_FAILURE));
  EXPECT_STREQ("CLIENT_NONCE_INVALID_TIME_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_INVALID_TIME_FAILURE));
  EXPECT_STREQ("CLIENT_NONCE_STRIKE_REGISTER_TIMEOUT",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_STRIKE_REGISTER_TIMEOUT));
  EXPECT_STREQ("CLIENT_NONCE_STRIKE_REGISTER_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_STRIKE_REGISTER_FAILURE));
  EXPECT_STREQ("SERVER_NONCE_DECRYPTION_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_NONCE_DECRYPTION_FAILURE));
  EXPECT_STREQ("SERVER_NONCE_INVALID_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_NONCE_INVALID_FAILURE));
  EXPECT_STREQ("SERVER_NONCE_NOT_UNIQUE_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_NONCE_NOT_UNIQUE_FAILURE));
  EXPECT_STREQ("SERVER_NONCE_INVALID_TIME_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_NONCE_INVALID_TIME_FAILURE));
  EXPECT_STREQ("SERVER_NONCE_REQUIRED_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_NONCE_REQUIRED_FAILURE));
  EXPECT_STREQ("SERVER_CONFIG_INCHOATE_HELLO_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_CONFIG_INCHOATE_HELLO_FAILURE));
  EXPECT_STREQ("SERVER_CONFIG_UNKNOWN_CONFIG_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_CONFIG_UNKNOWN_CONFIG_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_INVALID_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_INVALID_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_PARSE_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_PARSE_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_CLOCK_SKEW_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_CLOCK_SKEW_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_EXPIRED_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_EXPIRED_FAILURE));
  EXPECT_STREQ("INVALID_EXPECTED_LEAF_CERTIFICATE",
               CryptoUtils::HandshakeFailureReasonToString(
                   INVALID_EXPECTED_LEAF_CERTIFICATE));
  EXPECT_STREQ("MAX_FAILURE_REASON",
               CryptoUtils::HandshakeFailureReasonToString(MAX_FAILURE_REASON));
  EXPECT_STREQ(
      "INVALID_HANDSHAKE_FAILURE_REASON",
      CryptoUtils::HandshakeFailureReasonToString(
          static_cast<HandshakeFailureReason>(MAX_FAILURE_REASON + 1)));
}

TEST_F(CryptoUtilsTest, AuthTagLengths) {
  for (const auto& version : AllSupportedVersions()) {
    for (QuicTag algo : {kAESG, kCC20}) {
      SCOPED_TRACE(version);
      std::unique_ptr<QuicEncrypter> encrypter(
          QuicEncrypter::Create(version, algo));
      size_t auth_tag_size = 12;
      if (version.UsesInitialObfuscators()) {
        auth_tag_size = 16;
      }
      EXPECT_EQ(encrypter->GetCiphertextSize(0), auth_tag_size);
    }
  }
}

TEST_F(CryptoUtilsTest, ValidateChosenVersion) {
  for (const ParsedQuicVersion& v1 : AllSupportedVersions()) {
    for (const ParsedQuicVersion& v2 : AllSupportedVersions()) {
      std::string error_details;
      bool success = CryptoUtils::ValidateChosenVersion(
          CreateQuicVersionLabel(v1), v2, &error_details);
      EXPECT_EQ(success, v1 == v2);
      EXPECT_EQ(success, error_details.empty());
    }
  }
}

TEST_F(CryptoUtilsTest, ValidateServerVersionsNoVersionNegotiation) {
  QuicVersionLabelVector version_information_other_versions;
  ParsedQuicVersionVector client_original_supported_versions;
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    std::string error_details;
    EXPECT_TRUE(CryptoUtils::ValidateServerVersions(
        version_information_other_versions, version,
        client_original_supported_versions, &error_details));
    EXPECT_TRUE(error_details.empty());
  }
}

TEST_F(CryptoUtilsTest, ValidateServerVersionsWithVersionNegotiation) {
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    QuicVersionLabelVector version_information_other_versions{
        CreateQuicVersionLabel(version)};
    ParsedQuicVersionVector client_original_supported_versions{
        ParsedQuicVersion::ReservedForNegotiation(), version};
    std::string error_details;
    EXPECT_TRUE(CryptoUtils::ValidateServerVersions(
        version_information_other_versions, version,
        client_original_supported_versions, &error_details));
    EXPECT_TRUE(error_details.empty());
  }
}

TEST_F(CryptoUtilsTest, ValidateServerVersionsWithDowngrade) {
  if (AllSupportedVersions().size() <= 1) {
    // We are not vulnerable to downgrade if we only support one version.
    return;
  }
  ParsedQuicVersion client_version = AllSupportedVersions().front();
  ParsedQuicVersion server_version = AllSupportedVersions().back();
  ASSERT_NE(client_version, server_version);
  QuicVersionLabelVector version_information_other_versions{
      CreateQuicVersionLabel(client_version)};
  ParsedQuicVersionVector client_original_supported_versions{
      ParsedQuicVersion::ReservedForNegotiation(), server_version};
  std::string error_details;
  EXPECT_FALSE(CryptoUtils::ValidateServerVersions(
      version_information_other_versions, server_version,
      client_original_supported_versions, &error_details));
  EXPECT_FALSE(error_details.empty());
}

// Test that the library is using the correct labels for each version, and
// therefore generating correct obfuscators, using the test vectors in appendix
// A of each RFC or internet-draft.
TEST_F(CryptoUtilsTest, ValidateCryptoLabels) {
  // if the number of HTTP/3 QUIC versions has changed, we need to change the
  // expected_keys hardcoded into this test. Regrettably, this is not a
  // compile-time constant.
  EXPECT_EQ(AllSupportedVersionsWithTls().size(), 3u);
  const char draft_29_key[] = {// test vector from draft-ietf-quic-tls-29, A.1
                               0x14,
                               static_cast<char>(0x9d),
                               0x0b,
                               0x16,
                               0x62,
                               static_cast<char>(0xab),
                               static_cast<char>(0x87),
                               0x1f,
                               static_cast<char>(0xbe),
                               0x63,
                               static_cast<char>(0xc4),
                               static_cast<char>(0x9b),
                               0x5e,
                               0x65,
                               0x5a,
                               0x5d};
  const char v1_key[] = {// test vector from RFC 9001, A.1
                         static_cast<char>(0xcf),
                         0x3a,
                         0x53,
                         0x31,
                         0x65,
                         0x3c,
                         0x36,
                         0x4c,
                         static_cast<char>(0x88),
                         static_cast<char>(0xf0),
                         static_cast<char>(0xf3),
                         0x79,
                         static_cast<char>(0xb6),
                         0x06,
                         0x7e,
                         0x37};
  const char v2_08_key[] = {// test vector from draft-ietf-quic-v2-08
                            static_cast<char>(0x82),
                            static_cast<char>(0xdb),
                            static_cast<char>(0x63),
                            static_cast<char>(0x78),
                            static_cast<char>(0x61),
                            static_cast<char>(0xd5),
                            static_cast<char>(0x5e),
                            0x1d,
                            static_cast<char>(0x01),
                            static_cast<char>(0x1f),
                            0x19,
                            static_cast<char>(0xea),
                            0x71,
                            static_cast<char>(0xd5),
                            static_cast<char>(0xd2),
                            static_cast<char>(0xa7)};
  const char connection_id[] =  // test vector from both docs
      {static_cast<char>(0x83),
       static_cast<char>(0x94),
       static_cast<char>(0xc8),
       static_cast<char>(0xf0),
       0x3e,
       0x51,
       0x57,
       0x08};
  const QuicConnectionId cid(connection_id, sizeof(connection_id));
  const char* key_str;
  size_t key_size;
  for (const ParsedQuicVersion& version : AllSupportedVersionsWithTls()) {
    if (version == ParsedQuicVersion::Draft29()) {
      key_str = draft_29_key;
      key_size = sizeof(draft_29_key);
    } else if (version == ParsedQuicVersion::RFCv1()) {
      key_str = v1_key;
      key_size = sizeof(v1_key);
    } else {  // draft-ietf-quic-v2-01
      key_str = v2_08_key;
      key_size = sizeof(v2_08_key);
    }
    const absl::string_view expected_key{key_str, key_size};

    CrypterPair crypters;
    CryptoUtils::CreateInitialObfuscators(Perspective::IS_SERVER, version, cid,
                                          &crypters);
    EXPECT_EQ(crypters.encrypter->GetKey(), expected_key);
  }
}

TEST_F(CryptoUtilsTest, GetSSLErrorStack) {
  ERR_clear_error();
  const int line = (OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_SSL_VERSION), __LINE__);
  std::string error_location = absl::StrCat("crypto_utils_test.cc:", line);
  EXPECT_THAT(CryptoUtils::GetSSLErrorStack(),
              AllOf(HasSubstr(error_location), HasSubstr("WRONG_SSL_VERSION")));
  EXPECT_TRUE(CryptoUtils::GetSSLErrorStack().empty());
  ERR_clear_error();
}

}  // namespace
}  // namespace test
}  // namespace quic
```