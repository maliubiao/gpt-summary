Response:
The user wants to understand the functionality of the C++ source code file `oblivious_http_header_key_config_test.cc`. I need to analyze the code and identify its purpose, its relationship with JavaScript (if any), provide examples of logical reasoning with inputs and outputs, illustrate common usage errors, and explain how a user might reach this code during debugging.

**Plan:**

1. **Functionality:** Identify the main purpose of the test file. It seems to be testing the `ObliviousHttpHeaderKeyConfig` and `ObliviousHttpKeyConfigs` classes. I'll look for test cases that cover serialization, deserialization, validation, and parsing of header key configurations.

2. **JavaScript Relationship:** Scan the code for any direct interactions or dependencies on JavaScript. Based on the file path and content, it seems unlikely, but I should confirm.

3. **Logical Reasoning (Input/Output):**  Choose a few representative test cases and explain the input values and the expected output or behavior. Good candidates are the serialization and parsing tests.

4. **Common Usage Errors:**  Look for test cases that check for invalid configurations or inputs. These tests often demonstrate how a user might misuse the API.

5. **User Path to Code (Debugging):**  Think about the context of Oblivious HTTP and how developers working with it might encounter issues related to header key configuration. This could involve setting up OHTTP connections or handling OHTTP requests.

**Detailed Breakdown:**

*   **Parsing Header:** The `TestParsingValidHeader` and `TestParsingInvalidHeader` functions demonstrate how the code handles valid and invalid OHTTP headers. I can use these for input/output examples.
*   **Serialization:**  The `TestSerializeRecipientContextInfo` and `TestSerializeOhttpPayloadHeader` functions show how the key configuration is serialized. This is another good candidate for input/output.
*   **Key Config Creation:**  The `TestValidKeyConfig` and `TestInvalidKeyConfig` functions show how valid and invalid `ObliviousHttpHeaderKeyConfig` objects are created. These highlight potential user errors.
*   **Multiple Key Configurations:** The `ObliviousHttpKeyConfigs` tests demonstrate handling multiple key configurations, which can introduce complexity and potential errors.
*   **JavaScript:**  A quick scan for keywords like `JavaScript`, `Node.js`, or any bridging mechanisms reveals no direct connections. I'll state that explicitly.

**Self-Correction/Refinement:**

*   Initially, I might focus too much on the low-level details of each test case. I need to abstract and explain the *purpose* of the tests in relation to the overall functionality of the classes.
*   The user asks for "举例说明" (give examples), so I need to ensure my explanations are concrete and easy to understand.
*   For the user path to the code, I should consider the broader context of network debugging and how developers trace issues related to HTTP headers or connection setup.
这个文件是 Chromium 网络栈中关于 **Oblivious HTTP (OHTTP)** 的实现的一部分，具体来说，它是一个 **单元测试文件**，用于测试 `ObliviousHttpHeaderKeyConfig` 和 `ObliviousHttpKeyConfigs` 这两个 C++ 类的功能。这两个类负责处理 OHTTP 消息头中的密钥配置信息。

**主要功能:**

1. **测试 `ObliviousHttpHeaderKeyConfig` 类:**
    *   **创建和验证密钥配置:** 测试使用不同的 HPKE (Hybrid Public Key Encryption) 参数 (KEM, KDF, AEAD) 创建 `ObliviousHttpHeaderKeyConfig` 对象，并验证创建是否成功，以及对于无效参数是否会返回错误。
    *   **序列化密钥上下文信息:** 测试将密钥配置信息序列化为用于构建 OHTTP 请求的特定格式。
    *   **解析 OHTTP 负载头:** 测试从接收到的 OHTTP 负载头中解析密钥配置信息，并验证解析是否正确。
    *   **序列化 OHTTP 负载头:** 测试将密钥配置信息序列化为 OHTTP 负载头的格式。
    *   **提取密钥 ID:** 测试从 OHTTP 请求的负载中解析出密钥 ID。
    *   **测试可复制性:** 验证 `ObliviousHttpHeaderKeyConfig` 对象可以被正确地复制。

2. **测试 `ObliviousHttpKeyConfigs` 类:**
    *   **解析连接的密钥配置:** 测试解析由多个连接在一起的密钥配置组成的字符串。
    *   **获取首选配置:** 测试从多个密钥配置中选择首选配置。
    *   **根据 ID 获取公钥:** 测试根据密钥 ID 获取对应的公钥。
    *   **处理重复的密钥 ID:** 测试当存在重复的密钥 ID 时，解析是否会失败。
    *   **使用单个密钥配置创建 `ObliviousHttpKeyConfigs`:** 测试使用单个 `ObliviousHttpHeaderKeyConfig` 对象创建 `ObliviousHttpKeyConfigs` 对象。
    *   **使用多个密钥配置创建 `ObliviousHttpKeyConfigs`:** 测试使用多个 `OhttpKeyConfig` 结构体创建 `ObliviousHttpKeyConfigs` 对象。
    *   **处理无效的密钥配置:** 测试创建包含无效配置的 `ObliviousHttpKeyConfigs` 对象是否会失败。
    *   **生成连接的密钥:** 测试将多个密钥配置序列化为一个连接的字符串。
    *   **测试哈希实现:** 测试用于存储密钥配置的哈希数据结构的正确性。

**与 JavaScript 的关系:**

这个 C++ 文件本身 **不直接与 JavaScript 功能有关系**。它是在 Chromium 的网络栈中实现的，负责处理底层的网络协议逻辑。

但是，Oblivious HTTP 作为一种技术，旨在提高网络请求的隐私性。在 Web 开发中，JavaScript 代码可能会使用浏览器提供的 API (例如 `fetch` API) 发起 HTTP 请求。如果浏览器支持 Oblivious HTTP，并且配置了相应的代理或服务器，那么这些 JavaScript 发起的请求可能会使用到这里测试的 C++ 代码来处理 OHTTP 相关的头信息和密钥配置。

**举例说明:**

假设一个网页上的 JavaScript 代码需要发起一个 OHTTP 请求。浏览器会执行以下步骤 (简化说明):

1. **JavaScript 调用 `fetch` API 发起请求。**
2. **浏览器检查是否需要使用 OHTTP。** 这可能基于一些配置或目标服务器的支持情况。
3. **如果需要使用 OHTTP，Chromium 的网络栈会使用 `ObliviousHttpKeyConfigs` 类来获取目标服务器的密钥配置。** 这些配置可能从服务器的 HTTP 响应头中获取并缓存。
4. **`ObliviousHttpHeaderKeyConfig` 类会被用来构建 OHTTP 请求头，包括加密所需的密钥信息。**
5. **请求被发送到 OHTTP 网关或代理。**

**逻辑推理 (假设输入与输出):**

**场景 1: 测试解析有效的 OHTTP 负载头 (`TestParsingValidHeader`)**

*   **假设输入:**
    *   `ObliviousHttpHeaderKeyConfig` 对象已创建，其 `key_id` 为 5，`kem_id` 为 `EVP_HPKE_DHKEM_X25519_HKDF_SHA256`，`kdf_id` 为 `EVP_HPKE_HKDF_SHA256`，`aead_id` 为 `EVP_HPKE_AES_256_GCM`。
    *   接收到的 OHTTP 负载头字符串 `good_hdr` 是通过 `BuildHeader(5, EVP_HPKE_DHKEM_X25519_HKDF_SHA256, EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_256_GCM)` 构建的，即包含匹配的密钥 ID 和 HPKE 参数的二进制数据。

*   **预期输出:**
    *   `instance.value().ParseOhttpPayloadHeader(good_hdr).ok()` 返回 `true`，表示成功解析了负载头，并且负载头中的信息与 `ObliviousHttpHeaderKeyConfig` 对象的配置匹配。

**场景 2: 测试序列化接收者上下文信息 (`TestSerializeRecipientContextInfo`)**

*   **假设输入:**
    *   `ObliviousHttpHeaderKeyConfig` 对象已创建，其 `key_id` 为 3，`kem_id` 为 `EVP_HPKE_DHKEM_X25519_HKDF_SHA256`，`kdf_id` 为 `EVP_HPKE_HKDF_SHA256`，`aead_id` 为 `EVP_HPKE_AES_256_GCM`。

*   **预期输出:**
    *   `instance.value().SerializeRecipientContextInfo()` 返回一个字符串，该字符串以 "message/bhttp request" 标签开头，后跟一个零字节，然后是密钥 ID 和 HPKE 参数的二进制表示。这个输出用于构建 OHTTP 请求中的特定部分。

**用户或编程常见的使用错误:**

1. **创建无效的密钥配置:**
    *   **错误示例:**  `ObliviousHttpHeaderKeyConfig::Create(3, 0, EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_256_GCM)`  (使用了无效的 KEM ID 0)。
    *   **结果:** `Create` 方法会返回一个包含 `absl::StatusCode::kInvalidArgument` 错误的 `absl::StatusOr` 对象。

2. **解析不匹配的负载头:**
    *   **错误示例:**  一个 `ObliviousHttpHeaderKeyConfig` 对象的 `key_id` 是 8，但尝试解析的负载头 `keyid_mismatch_hdr` 的密钥 ID 是 0。
    *   **结果:** `ParseOhttpPayloadHeader` 方法会返回一个包含 `absl::StatusCode::kInvalidArgument` 错误的 `absl::Status` 对象。

3. **提供错误长度的公钥:**
    *   **错误示例:** 在 `TestCreateSingleKeyConfigWithInvalidConfig` 中，尝试使用一个空字符串或长度不符合预期 KEM 算法的字符串作为公钥来创建 `ObliviousHttpKeyConfigs` 对象。
    *   **结果:** `ObliviousHttpKeyConfigs::Create` 方法会返回一个包含 `absl::StatusCode::kInvalidArgument` 错误的 `absl::StatusOr` 对象。

4. **使用重复的密钥 ID:**
    *   **错误示例:** 在 `Test(ObliviousHttpKeyConfigs, DuplicateKeyId)` 中，提供了一个包含两个具有相同密钥 ID 的密钥配置的连接字符串。
    *   **结果:** `ObliviousHttpKeyConfigs::ParseConcatenatedKeys` 方法会返回一个 `absl::nullopt`，表示解析失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设一个开发者正在调试一个与 Oblivious HTTP 相关的网络请求问题，并且怀疑问题可能出在密钥配置上。以下是可能的步骤：

1. **用户在浏览器中或通过程序发起了一个使用了 Oblivious HTTP 的请求。**
2. **请求失败或行为异常。** 例如，连接无法建立，或者返回了错误的代码。
3. **开发者开始检查网络请求的详细信息。** 使用浏览器的开发者工具 (例如 Chrome 的 "Network" 标签页) 或者抓包工具 (例如 Wireshark)。
4. **开发者注意到 OHTTP 相关的请求头或响应头有问题，或者怀疑密钥配置不正确。**
5. **如果开发者有 Chromium 的源代码，他们可能会设置断点在与 OHTTP 相关的代码中。**  他们可能会怀疑 `ObliviousHttpHeaderKeyConfig` 或 `ObliviousHttpKeyConfigs` 的初始化、解析或序列化过程有问题。
6. **开发者可能会查看网络栈的日志，寻找与 OHTTP 密钥配置相关的错误信息。**  `QUICHE_LOG` 宏在代码中用于记录日志。
7. **开发者可能会逐步执行 `ObliviousHttpHeaderKeyConfig::Create` 或 `ObliviousHttpKeyConfigs::ParseConcatenatedKeys` 等方法，来查看密钥配置是如何创建和解析的。**
8. **如果问题涉及到接收到的 OHTTP 响应，开发者可能会检查 `ObliviousHttpHeaderKeyConfig::ParseOhttpPayloadHeader` 的执行过程，确认接收到的负载头是否能被正确解析。**
9. **通过分析堆栈信息和变量的值，开发者可能会最终定位到 `oblivious_http_header_key_config_test.cc` 中测试的某些逻辑存在问题，或者他们自己的代码在使用这些类时出现了错误。** 例如，他们可能发现服务器返回的密钥配置格式不正确，或者客户端代码在构建 OHTTP 请求时使用了错误的参数。

总之，`oblivious_http_header_key_config_test.cc` 提供了对 OHTTP 密钥配置相关核心逻辑的详尽测试，是理解和调试 OHTTP 实现的关键部分。开发者在遇到与 OHTTP 请求相关的密钥配置问题时，很可能会查阅或调试这个文件中的代码。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/oblivious_http/common/oblivious_http_header_key_config_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#include "quiche/oblivious_http/common/oblivious_http_header_key_config.h"

#include <cstdint>
#include <string>

#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "openssl/hpke.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_data_writer.h"

namespace quiche {
namespace {
using ::testing::AllOf;
using ::testing::Property;
using ::testing::StrEq;
using ::testing::UnorderedElementsAre;
using ::testing::UnorderedElementsAreArray;

/**
 * Build Request header.
 */
std::string BuildHeader(uint8_t key_id, uint16_t kem_id, uint16_t kdf_id,
                        uint16_t aead_id) {
  int buf_len =
      sizeof(key_id) + sizeof(kem_id) + sizeof(kdf_id) + sizeof(aead_id);
  std::string hdr(buf_len, '\0');
  QuicheDataWriter writer(hdr.size(), hdr.data());
  EXPECT_TRUE(writer.WriteUInt8(key_id));
  EXPECT_TRUE(writer.WriteUInt16(kem_id));   // kemID
  EXPECT_TRUE(writer.WriteUInt16(kdf_id));   // kdfID
  EXPECT_TRUE(writer.WriteUInt16(aead_id));  // aeadID
  return hdr;
}

std::string GetSerializedKeyConfig(
    ObliviousHttpKeyConfigs::OhttpKeyConfig& key_config) {
  uint16_t symmetric_algs_length =
      key_config.symmetric_algorithms.size() *
      (sizeof(key_config.symmetric_algorithms.cbegin()->kdf_id) +
       sizeof(key_config.symmetric_algorithms.cbegin()->aead_id));
  int buf_len = sizeof(key_config.key_id) + sizeof(key_config.kem_id) +
                key_config.public_key.size() + sizeof(symmetric_algs_length) +
                symmetric_algs_length;
  std::string ohttp_key(buf_len, '\0');
  QuicheDataWriter writer(ohttp_key.size(), ohttp_key.data());
  EXPECT_TRUE(writer.WriteUInt8(key_config.key_id));
  EXPECT_TRUE(writer.WriteUInt16(key_config.kem_id));
  EXPECT_TRUE(writer.WriteStringPiece(key_config.public_key));
  EXPECT_TRUE(writer.WriteUInt16(symmetric_algs_length));
  for (const auto& symmetric_alg : key_config.symmetric_algorithms) {
    EXPECT_TRUE(writer.WriteUInt16(symmetric_alg.kdf_id));
    EXPECT_TRUE(writer.WriteUInt16(symmetric_alg.aead_id));
  }
  return ohttp_key;
}

TEST(ObliviousHttpHeaderKeyConfig, TestSerializeRecipientContextInfo) {
  uint8_t key_id = 3;
  uint16_t kem_id = EVP_HPKE_DHKEM_X25519_HKDF_SHA256;
  uint16_t kdf_id = EVP_HPKE_HKDF_SHA256;
  uint16_t aead_id = EVP_HPKE_AES_256_GCM;
  absl::string_view ohttp_req_label = "message/bhttp request";
  std::string expected(ohttp_req_label);
  uint8_t zero_byte = 0x00;
  int buf_len = ohttp_req_label.size() + sizeof(zero_byte) + sizeof(key_id) +
                sizeof(kem_id) + sizeof(kdf_id) + sizeof(aead_id);
  expected.reserve(buf_len);
  expected.push_back(zero_byte);
  std::string ohttp_cfg(BuildHeader(key_id, kem_id, kdf_id, aead_id));
  expected.insert(expected.end(), ohttp_cfg.begin(), ohttp_cfg.end());
  auto instance =
      ObliviousHttpHeaderKeyConfig::Create(key_id, kem_id, kdf_id, aead_id);
  ASSERT_TRUE(instance.ok());
  EXPECT_EQ(instance.value().SerializeRecipientContextInfo(), expected);
}

TEST(ObliviousHttpHeaderKeyConfig, TestValidKeyConfig) {
  auto valid_key_config = ObliviousHttpHeaderKeyConfig::Create(
      2, EVP_HPKE_DHKEM_X25519_HKDF_SHA256, EVP_HPKE_HKDF_SHA256,
      EVP_HPKE_AES_256_GCM);
  ASSERT_TRUE(valid_key_config.ok());
}

TEST(ObliviousHttpHeaderKeyConfig, TestInvalidKeyConfig) {
  auto invalid_kem = ObliviousHttpHeaderKeyConfig::Create(
      3, 0, EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_256_GCM);
  EXPECT_EQ(invalid_kem.status().code(), absl::StatusCode::kInvalidArgument);
  auto invalid_kdf = ObliviousHttpHeaderKeyConfig::Create(
      3, EVP_HPKE_DHKEM_X25519_HKDF_SHA256, 0, EVP_HPKE_AES_256_GCM);
  EXPECT_EQ(invalid_kdf.status().code(), absl::StatusCode::kInvalidArgument);
  auto invalid_aead = ObliviousHttpHeaderKeyConfig::Create(
      3, EVP_HPKE_DHKEM_X25519_HKDF_SHA256, EVP_HPKE_HKDF_SHA256, 0);
  EXPECT_EQ(invalid_kdf.status().code(), absl::StatusCode::kInvalidArgument);
}

TEST(ObliviousHttpHeaderKeyConfig, TestParsingValidHeader) {
  auto instance = ObliviousHttpHeaderKeyConfig::Create(
      5, EVP_HPKE_DHKEM_X25519_HKDF_SHA256, EVP_HPKE_HKDF_SHA256,
      EVP_HPKE_AES_256_GCM);
  ASSERT_TRUE(instance.ok());
  std::string good_hdr(BuildHeader(5, EVP_HPKE_DHKEM_X25519_HKDF_SHA256,
                                   EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_256_GCM));
  ASSERT_TRUE(instance.value().ParseOhttpPayloadHeader(good_hdr).ok());
}

TEST(ObliviousHttpHeaderKeyConfig, TestParsingInvalidHeader) {
  auto instance = ObliviousHttpHeaderKeyConfig::Create(
      8, EVP_HPKE_DHKEM_X25519_HKDF_SHA256, EVP_HPKE_HKDF_SHA256,
      EVP_HPKE_AES_256_GCM);
  ASSERT_TRUE(instance.ok());
  std::string keyid_mismatch_hdr(
      BuildHeader(0, EVP_HPKE_DHKEM_X25519_HKDF_SHA256, EVP_HPKE_HKDF_SHA256,
                  EVP_HPKE_AES_256_GCM));
  EXPECT_EQ(instance.value().ParseOhttpPayloadHeader(keyid_mismatch_hdr).code(),
            absl::StatusCode::kInvalidArgument);
  std::string invalid_hpke_hdr(BuildHeader(8, 0, 0, 0));
  EXPECT_EQ(instance.value().ParseOhttpPayloadHeader(invalid_hpke_hdr).code(),
            absl::StatusCode::kInvalidArgument);
}

TEST(ObliviousHttpHeaderKeyConfig, TestParsingKeyIdFromObliviousHttpRequest) {
  std::string key_id(sizeof(uint8_t), '\0');
  QuicheDataWriter writer(key_id.size(), key_id.data());
  EXPECT_TRUE(writer.WriteUInt8(99));
  auto parsed_key_id =
      ObliviousHttpHeaderKeyConfig::ParseKeyIdFromObliviousHttpRequestPayload(
          key_id);
  ASSERT_TRUE(parsed_key_id.ok());
  EXPECT_EQ(parsed_key_id.value(), 99);
}

TEST(ObliviousHttpHeaderKeyConfig, TestCopyable) {
  auto obj1 = ObliviousHttpHeaderKeyConfig::Create(
      4, EVP_HPKE_DHKEM_X25519_HKDF_SHA256, EVP_HPKE_HKDF_SHA256,
      EVP_HPKE_AES_256_GCM);
  ASSERT_TRUE(obj1.ok());
  auto copy_obj1_to_obj2 = obj1.value();
  EXPECT_EQ(copy_obj1_to_obj2.kHeaderLength, obj1->kHeaderLength);
  EXPECT_EQ(copy_obj1_to_obj2.SerializeRecipientContextInfo(),
            obj1->SerializeRecipientContextInfo());
}

TEST(ObliviousHttpHeaderKeyConfig, TestSerializeOhttpPayloadHeader) {
  auto instance = ObliviousHttpHeaderKeyConfig::Create(
      7, EVP_HPKE_DHKEM_X25519_HKDF_SHA256, EVP_HPKE_HKDF_SHA256,
      EVP_HPKE_AES_128_GCM);
  ASSERT_TRUE(instance.ok());
  EXPECT_EQ(instance->SerializeOhttpPayloadHeader(),
            BuildHeader(7, EVP_HPKE_DHKEM_X25519_HKDF_SHA256,
                        EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_128_GCM));
}

MATCHER_P(HasKeyId, id, "") {
  *result_listener << "has key_id=" << arg.GetKeyId();
  return arg.GetKeyId() == id;
}
MATCHER_P(HasKemId, id, "") {
  *result_listener << "has kem_id=" << arg.GetHpkeKemId();
  return arg.GetHpkeKemId() == id;
}
MATCHER_P(HasKdfId, id, "") {
  *result_listener << "has kdf_id=" << arg.GetHpkeKdfId();
  return arg.GetHpkeKdfId() == id;
}
MATCHER_P(HasAeadId, id, "") {
  *result_listener << "has aead_id=" << arg.GetHpkeAeadId();
  return arg.GetHpkeAeadId() == id;
}

TEST(ObliviousHttpKeyConfigs, SingleKeyConfig) {
  std::string key;
  ASSERT_TRUE(absl::HexStringToBytes(
      "4b0020f83e0a17cbdb18d2684dd2a9b087a43e5f3fa3fa27a049bc746a6e97a1e0244b00"
      "0400010002",
      &key));
  auto configs = ObliviousHttpKeyConfigs::ParseConcatenatedKeys(key).value();
  EXPECT_THAT(configs, Property(&ObliviousHttpKeyConfigs::NumKeys, 1));
  EXPECT_THAT(
      configs.PreferredConfig(),
      AllOf(HasKeyId(0x4b), HasKemId(EVP_HPKE_DHKEM_X25519_HKDF_SHA256),
            HasKdfId(EVP_HPKE_HKDF_SHA256), HasAeadId(EVP_HPKE_AES_256_GCM)));
  std::string expected_public_key;
  ASSERT_TRUE(absl::HexStringToBytes(
      "f83e0a17cbdb18d2684dd2a9b087a43e5f3fa3fa27a049bc746a6e97a1e0244b",
      &expected_public_key));
  EXPECT_THAT(
      configs.GetPublicKeyForId(configs.PreferredConfig().GetKeyId()).value(),
      StrEq(expected_public_key));
}

TEST(ObliviousHttpKeyConfigs, TwoSimilarKeyConfigs) {
  std::string key;
  ASSERT_TRUE(absl::HexStringToBytes(
      "4b0020f83e0a17cbdb18d2684dd2a9b087a43e5f3fa3fa27a049bc746a6e97a1e0244b00"
      "0400010002"  // Intentional concatenation
      "4f0020f83e0a17cbdb18d2684dd2a9b087a43e5f3fa3fa27a049bc746a6e97a1e0244b00"
      "0400010001",
      &key));
  EXPECT_THAT(ObliviousHttpKeyConfigs::ParseConcatenatedKeys(key).value(),
              Property(&ObliviousHttpKeyConfigs::NumKeys, 2));
  EXPECT_THAT(
      ObliviousHttpKeyConfigs::ParseConcatenatedKeys(key)->PreferredConfig(),
      AllOf(HasKeyId(0x4f), HasKemId(EVP_HPKE_DHKEM_X25519_HKDF_SHA256),
            HasKdfId(EVP_HPKE_HKDF_SHA256), HasAeadId(EVP_HPKE_AES_128_GCM)));
}

TEST(ObliviousHttpKeyConfigs, RFCExample) {
  std::string key;
  ASSERT_TRUE(absl::HexStringToBytes(
      "01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500"
      "080001000100010003",
      &key));
  auto configs = ObliviousHttpKeyConfigs::ParseConcatenatedKeys(key).value();
  EXPECT_THAT(configs, Property(&ObliviousHttpKeyConfigs::NumKeys, 1));
  EXPECT_THAT(
      configs.PreferredConfig(),
      AllOf(HasKeyId(0x01), HasKemId(EVP_HPKE_DHKEM_X25519_HKDF_SHA256),
            HasKdfId(EVP_HPKE_HKDF_SHA256), HasAeadId(EVP_HPKE_AES_128_GCM)));
  std::string expected_public_key;
  ASSERT_TRUE(absl::HexStringToBytes(
      "31e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155",
      &expected_public_key));
  EXPECT_THAT(
      configs.GetPublicKeyForId(configs.PreferredConfig().GetKeyId()).value(),
      StrEq(expected_public_key));
}

TEST(ObliviousHttpKeyConfigs, DuplicateKeyId) {
  std::string key;
  ASSERT_TRUE(absl::HexStringToBytes(
      "4b0020f83e0a17cbdb18d2684dd2a9b087a43e5f3fa3fa27a049bc746a6e97a1e0244b00"
      "0400010002"  // Intentional concatenation
      "4b0020f83e0a17cbdb18d2684dd2a9b087a43e5f3fa3fb27a049bc746a6e97a1e0244b00"
      "0400010001",
      &key));
  EXPECT_FALSE(ObliviousHttpKeyConfigs::ParseConcatenatedKeys(key).ok());
}

TEST(ObliviousHttpHeaderKeyConfigs, TestCreateWithSingleKeyConfig) {
  auto instance = ObliviousHttpHeaderKeyConfig::Create(
      123, EVP_HPKE_DHKEM_X25519_HKDF_SHA256, EVP_HPKE_HKDF_SHA256,
      EVP_HPKE_CHACHA20_POLY1305);
  EXPECT_TRUE(instance.ok());
  std::string test_public_key(
      EVP_HPKE_KEM_public_key_len(instance->GetHpkeKem()), 'a');
  auto configs =
      ObliviousHttpKeyConfigs::Create(instance.value(), test_public_key);
  EXPECT_TRUE(configs.ok());
  auto serialized_key = configs->GenerateConcatenatedKeys();
  EXPECT_TRUE(serialized_key.ok());
  auto ohttp_configs =
      ObliviousHttpKeyConfigs::ParseConcatenatedKeys(serialized_key.value());
  EXPECT_TRUE(ohttp_configs.ok());
  ASSERT_EQ(ohttp_configs->PreferredConfig().GetKeyId(), 123);
  auto parsed_public_key = ohttp_configs->GetPublicKeyForId(123);
  EXPECT_TRUE(parsed_public_key.ok());
  EXPECT_EQ(parsed_public_key.value(), test_public_key);
}

TEST(ObliviousHttpHeaderKeyConfigs, TestCreateWithWithMultipleKeys) {
  std::string expected_preferred_public_key(32, 'b');
  ObliviousHttpKeyConfigs::OhttpKeyConfig config1 = {
      100,
      EVP_HPKE_DHKEM_X25519_HKDF_SHA256,
      std::string(32, 'a'),
      {{EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_256_GCM}}};
  ObliviousHttpKeyConfigs::OhttpKeyConfig config2 = {
      200,
      EVP_HPKE_DHKEM_X25519_HKDF_SHA256,
      expected_preferred_public_key,
      {{EVP_HPKE_HKDF_SHA256, EVP_HPKE_CHACHA20_POLY1305}}};
  auto configs = ObliviousHttpKeyConfigs::Create({config1, config2});
  EXPECT_TRUE(configs.ok());
  auto serialized_key = configs->GenerateConcatenatedKeys();
  EXPECT_TRUE(serialized_key.ok());
  ASSERT_EQ(serialized_key.value(),
            absl::StrCat(GetSerializedKeyConfig(config2),
                         GetSerializedKeyConfig(config1)));
  auto ohttp_configs =
      ObliviousHttpKeyConfigs::ParseConcatenatedKeys(serialized_key.value());
  EXPECT_TRUE(ohttp_configs.ok());
  ASSERT_EQ(ohttp_configs->NumKeys(), 2);
  EXPECT_THAT(configs->PreferredConfig(),
              AllOf(HasKeyId(200), HasKemId(EVP_HPKE_DHKEM_X25519_HKDF_SHA256),
                    HasKdfId(EVP_HPKE_HKDF_SHA256),
                    HasAeadId(EVP_HPKE_CHACHA20_POLY1305)));
  auto parsed_preferred_public_key = ohttp_configs->GetPublicKeyForId(
      ohttp_configs->PreferredConfig().GetKeyId());
  EXPECT_TRUE(parsed_preferred_public_key.ok());
  EXPECT_EQ(parsed_preferred_public_key.value(), expected_preferred_public_key);
}

TEST(ObliviousHttpHeaderKeyConfigs, TestCreateWithInvalidConfigs) {
  ASSERT_EQ(ObliviousHttpKeyConfigs::Create({}).status().code(),
            absl::StatusCode::kInvalidArgument);
  ASSERT_EQ(ObliviousHttpKeyConfigs::Create(
                {{100, 2, std::string(32, 'a'), {{2, 3}, {4, 5}}},
                 {200, 6, std::string(32, 'b'), {{7, 8}, {9, 10}}}})
                .status()
                .code(),
            absl::StatusCode::kInvalidArgument);

  EXPECT_EQ(
      ObliviousHttpKeyConfigs::Create(
          {{123,
            EVP_HPKE_DHKEM_X25519_HKDF_SHA256,
            "invalid key length" /*expected length for given kem_id is 32*/,
            {{EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_128_GCM}}}})
          .status()
          .code(),
      absl::StatusCode::kInvalidArgument);
}

TEST(ObliviousHttpHeaderKeyConfigs,
     TestCreateSingleKeyConfigWithInvalidConfig) {
  const auto sample_ohttp_hdr_config = ObliviousHttpHeaderKeyConfig::Create(
      123, EVP_HPKE_DHKEM_X25519_HKDF_SHA256, EVP_HPKE_HKDF_SHA256,
      EVP_HPKE_AES_128_GCM);
  ASSERT_TRUE(sample_ohttp_hdr_config.ok());
  ASSERT_EQ(ObliviousHttpKeyConfigs::Create(sample_ohttp_hdr_config.value(),
                                            "" /*empty public_key*/)
                .status()
                .code(),
            absl::StatusCode::kInvalidArgument);
  EXPECT_EQ(ObliviousHttpKeyConfigs::Create(
                sample_ohttp_hdr_config.value(),
                "invalid key length" /*expected length for given kem_id is 32*/)
                .status()
                .code(),
            absl::StatusCode::kInvalidArgument);
}

TEST(ObliviousHttpHeaderKeyConfigs, TestHashImplWithObliviousStruct) {
  // Insert different symmetric algorithms 50 times.
  absl::flat_hash_set<ObliviousHttpKeyConfigs::SymmetricAlgorithmsConfig>
      symmetric_algs_set;
  for (int i = 0; i < 50; ++i) {
    symmetric_algs_set.insert({EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_128_GCM});
    symmetric_algs_set.insert({EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_256_GCM});
    symmetric_algs_set.insert(
        {EVP_HPKE_HKDF_SHA256, EVP_HPKE_CHACHA20_POLY1305});
  }
  ASSERT_EQ(symmetric_algs_set.size(), 3);
  EXPECT_THAT(symmetric_algs_set,
              UnorderedElementsAreArray<
                  ObliviousHttpKeyConfigs::SymmetricAlgorithmsConfig>({
                  {EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_128_GCM},
                  {EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_256_GCM},
                  {EVP_HPKE_HKDF_SHA256, EVP_HPKE_CHACHA20_POLY1305},
              }));

  // Insert different Key configs 50 times.
  absl::flat_hash_set<ObliviousHttpKeyConfigs::OhttpKeyConfig>
      ohttp_key_configs_set;
  ObliviousHttpKeyConfigs::OhttpKeyConfig expected_key_config{
      100,
      EVP_HPKE_DHKEM_X25519_HKDF_SHA256,
      std::string(32, 'c'),
      {{EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_128_GCM},
       {EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_256_GCM}}};
  for (int i = 0; i < 50; ++i) {
    ohttp_key_configs_set.insert(expected_key_config);
  }
  ASSERT_EQ(ohttp_key_configs_set.size(), 1);
  EXPECT_THAT(ohttp_key_configs_set, UnorderedElementsAre(expected_key_config));
}

}  // namespace
}  // namespace quiche

"""

```