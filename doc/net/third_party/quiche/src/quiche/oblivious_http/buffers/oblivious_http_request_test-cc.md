Response:
My thinking process to analyze the C++ test file and generate the detailed explanation went through these steps:

1. **Understand the Goal:** The core request is to understand the functionality of `oblivious_http_request_test.cc`, its relationship with JavaScript (if any), its logic with example inputs/outputs, potential user errors, and how a user might reach this code.

2. **Identify the Core Functionality:**  The file name `oblivious_http_request_test.cc` and the included header `oblivious_http_request.h` immediately suggest that this file contains unit tests for the `ObliviousHttpRequest` class. The "oblivious HTTP" part hints at privacy-preserving HTTP requests, likely involving encryption.

3. **Scan for Key Concepts and APIs:** I quickly scanned the code for recurring patterns and important function calls. I noticed:
    * Includes of OpenSSL headers (`openssl/hkdf.h`, `openssl/hpke.h`): This confirms the use of cryptographic primitives. HPKE (Hybrid Public Key Encryption) is a key component.
    * `ObliviousHttpHeaderKeyConfig`:  This suggests configuration of cryptographic parameters for the oblivious HTTP protocol.
    * `CreateClientObliviousRequest`, `CreateServerObliviousRequest`: These are likely factory methods for creating oblivious HTTP request objects on the client and server sides, respectively.
    * `EncapsulateAndSerialize`, `GetPlaintextData`: These methods point to the core operations of encrypting and decrypting the request.
    * `absl::HexStringToBytes`: Used extensively for converting hexadecimal strings to byte arrays, indicating that cryptographic keys and data are represented in hex.
    * `TEST` macros: This confirms that the file uses Google Test for unit testing.
    * Specific test case names (e.g., `TestDecapsulateWithSpecAppendixAExample`): These give strong hints about what each test is verifying.

4. **Analyze Individual Test Cases:** I went through each test case, focusing on:
    * **Setup:** What data is being initialized (keys, configuration, plaintext, ciphertext)?
    * **Action:** What function is being called (`CreateClientObliviousRequest`, `CreateServerObliviousRequest`, `EncapsulateAndSerialize`, etc.)?
    * **Assertions:** What is being checked using `EXPECT_TRUE`, `EXPECT_EQ`, `EXPECT_NE`?  These assertions reveal the expected behavior of the code.
    * **Specific Examples:**  The test case `TestDecapsulateWithSpecAppendixAExample` is particularly valuable as it directly references the OHTTP specification, providing a concrete scenario.

5. **Infer Functionality from Tests:** By analyzing the test cases, I could deduce the following functionalities of the `ObliviousHttpRequest` class:
    * **Creation:**  Creating requests on both client and server sides.
    * **Encryption (Encapsulation):**  Encrypting the HTTP request using HPKE.
    * **Decryption (Decapsulation):** Decrypting the oblivious HTTP request.
    * **Header Handling:**  Dealing with a specific header format containing key configuration.
    * **Deterministic Encryption (with seed):**  Generating the same ciphertext for the same plaintext and seed.
    * **Handling of Invalid Inputs:**  Testing error conditions with incorrect or missing data.

6. **Identify Relationship with JavaScript:**  Based on the code, there is *no direct* relationship with JavaScript. The code is purely C++. However, since this is part of Chromium's network stack, it's highly likely that JavaScript code running in a browser will *use* this functionality indirectly. JavaScript's `fetch` API, for example, could be configured to make oblivious HTTP requests, which would then be handled by this C++ code in the underlying browser implementation. This indirect relationship is important to highlight.

7. **Construct Logic Examples (Inputs/Outputs):** I selected a simple test case (like `EndToEndTestForRequest`) and explicitly stated the hypothetical input (plaintext "test") and expected output (decrypted plaintext "test"). For the seeded test, I pointed out how the seed makes the output predictable.

8. **Identify Potential User Errors:** Based on the tests for invalid inputs, I identified common mistakes users (or developers using this API) might make, such as providing empty plaintexts, public keys, or encrypted data. I also highlighted the potential for key mismatch leading to decryption failures.

9. **Trace User Operations (Debugging):** I described a likely scenario where a user interacts with a website that uses oblivious HTTP. I outlined the steps from the user's action in the browser to the point where this C++ code might be involved in processing the request. This helps understand the context of the code.

10. **Structure the Explanation:** Finally, I organized the information into clear sections (Functionality, JavaScript Relationship, Logic Examples, User Errors, Debugging) to make it easy to understand. I used bullet points and code snippets where appropriate for clarity.

Throughout this process, I constantly referred back to the code to ensure my explanations were accurate and grounded in the implementation. I also tried to anticipate what a reader unfamiliar with oblivious HTTP might find confusing and provide context where needed.
这个 C++ 文件 `oblivious_http_request_test.cc` 是 Chromium 网络栈中 QUIC 协议库的一部分，专门用于测试 `oblivious_http_request.h` 中定义的 `ObliviousHttpRequest` 类的功能。  `ObliviousHttpRequest` 类是用来处理 Oblivious HTTP (OHTTP) 请求的，这是一种旨在提高隐私性的 HTTP 请求方式。

以下是该文件的详细功能分解：

**1. 单元测试框架:**

* 该文件使用 Google Test 框架 (`quiche/common/platform/api/quiche_test.h`) 来编写单元测试。
* 每个以 `TEST` 开头的宏定义一个独立的测试用例，用于验证 `ObliviousHttpRequest` 类的特定功能。

**2. 测试 `ObliviousHttpRequest` 的核心功能:**

* **创建客户端请求:** 测试 `ObliviousHttpRequest::CreateClientObliviousRequest` 函数，该函数用于在客户端创建 OHTTP 请求。这包括：
    *  使用给定的明文 payload 和服务器的 HPKE 公钥创建请求。
    *  验证创建的请求对象是否成功，并检查内部状态。
    *  测试使用种子 (seed) 创建确定性请求 (`CreateClientWithSeedForTesting`)，确保相同的输入产生相同的加密输出，这对于某些测试和调试场景很有用。
* **创建服务端请求 (解密):** 测试 `ObliviousHttpRequest::CreateServerObliviousRequest` 函数，该函数用于在服务端接收并解密 OHTTP 请求。这包括：
    * 使用加密的请求数据和服务器的 HPKE 私钥创建请求对象。
    * 验证创建的请求对象是否成功。
    * 测试使用错误的密钥进行解密，验证是否会抛出错误。
* **加密和序列化:** 测试 `EncapsulateAndSerialize` 方法，该方法将 OHTTP 请求进行加密并序列化成字节流，以便通过网络传输。测试验证：
    * 输出的字节流是否包含预期的头部信息 (Key ID, KEM ID, KDF ID, AEAD ID)。
    * 输出的字节流的结构是否符合 OHTTP 规范，包括加密的密钥和密文部分。
* **解密和获取明文数据:** 测试 `GetPlaintextData` 方法，该方法从服务端解密的 OHTTP 请求中获取原始的 HTTP 请求 payload。
* **上下文管理:** 测试请求上下文 (`ObliviousHttpRequest::RequestContext`) 的创建和释放，其中包含了加密过程中的临时密钥等信息。

**3. 测试 OHTTP 协议的特定场景:**

* **Spec Appendix A 示例:** 实现了 OHTTP 规范文档中 Appendix A 的示例，用于验证客户端加密和服务端解密的正确性。这提供了与其他 OHTTP 实现互操作性的保证。
* **确定性加密:** 测试使用相同的明文和种子创建的 OHTTP 请求是否产生相同的密文，以及使用不同的明文是否产生不同的密文。这对于确保某些测试的可重复性至关重要。

**4. 测试错误处理:**

* **客户端无效输入:** 测试在客户端创建请求时，如果提供无效的输入（例如，空的 payload 或空的公钥）是否会返回错误状态。
* **服务端无效输入:** 测试在服务端处理请求时，如果提供无效的输入（例如，空的加密数据或空的私钥）是否会返回错误状态。

**与 JavaScript 的关系:**

该 C++ 文件本身不包含任何 JavaScript 代码，它属于 Chromium 的网络栈底层实现。然而，Oblivious HTTP 的功能最终会被 JavaScript 代码所使用，例如通过 `fetch` API 发起 OHTTP 请求。

**举例说明:**

假设一个 JavaScript 应用程序想要发送一个使用 OHTTP 保护的请求到服务器。

**JavaScript 代码 (示例):**

```javascript
async function sendOhttpRequest(url, data, ohttpKey) {
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(data);

  // 假设 ohttpKey 包含了必要的 OHTTP 参数，例如服务器的公钥
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/ohttp-req',
      // 可能还需要其他 OHTTP 相关的头部信息
    },
    body: await encapsulateOhttpRequest(encodedData, ohttpKey) // 假设 encapsulateOhttpRequest 是一个 JavaScript 函数，用于根据 OHTTP 协议格式化请求
  });

  // 处理响应
  const responseText = await response.text();
  console.log(responseText);
}

// 简化的 encapsulateOhttpRequest 的概念
async function encapsulateOhttpRequest(plaintext, ohttpKey) {
  // 在实际的 JavaScript OHTTP 库中，这里会执行 HPKE 加密等操作
  // 并将请求格式化为 application/ohttp-req
  // ...
  return encapsulatedRequestData; // 返回格式化后的 OHTTP 请求数据
}

const serverPublicKey = '...'; // 服务器的 HPKE 公钥
const requestData = 'This is the request payload.';
const serverUrl = 'https://example.com/ohttp-endpoint';

sendOhttpRequest(serverUrl, requestData, { publicKey: serverPublicKey });
```

**背后的 C++ 流程:**

1. 当 JavaScript 代码调用 `fetch` 并指定 `Content-Type: application/ohttp-req` 时，Chromium 的网络栈会识别这是一个 OHTTP 请求。
2. 浏览器可能会使用 JavaScript 实现的 OHTTP 库来对请求进行初步的格式化和加密 (如果 `encapsulateOhttpRequest` 函数存在)。
3. 最终，底层的网络请求处理会调用到 C++ 代码，其中包括 `net/third_party/quiche/src/quiche/oblivious_http/buffers/oblivious_http_request.cc` 中测试的 `ObliviousHttpRequest` 类。
4. 如果是客户端发送请求，相关的 C++ 代码会执行 HPKE 加密，将 HTTP payload 封装成 OHTTP 格式，并发送到服务器。
5. 如果是服务器接收请求，服务器端的代码会使用 `ObliviousHttpRequest::CreateServerObliviousRequest` 创建对象，并使用服务器的私钥解密请求，最终提取出原始的 HTTP payload。

**逻辑推理 (假设输入与输出):**

**假设输入 (客户端测试):**

* `plaintext_payload`: "Hello, OHTTP!"
* `hpke_public_key`: 一个有效的 HPKE 公钥的十六进制字符串 (例如 `GetHpkePublicKey()`)
* `ohttp_key_config`: 一个有效的 `ObliviousHttpHeaderKeyConfig` 对象

**预期输出 (客户端测试 - `EncapsulateAndSerialize`):**

* `EncapsulateAndSerialize()` 方法会返回一个 `std::string`，包含以下结构的数据：
    * OHTTP 头部 (Key ID, KEM ID, KDF ID, AEAD ID)
    * 使用 HPKE 加密的临时公钥
    * 使用 HPKE 加密的 `plaintext_payload`

**假设输入 (服务端测试):**

* `encrypted_data`:  一个由客户端加密并序列化后的 OHTTP 请求字节流 (例如上面客户端测试的输出)
* `gateway_key`:  一个与用于加密的 `ohttp_key_config` 相匹配的 HPKE 私钥对象 (例如 `ConstructHpkeKey(GetHpkePrivateKey(), ohttp_key_config)`)
* `ohttp_key_config`:  与客户端加密时使用的相同的 `ObliviousHttpHeaderKeyConfig` 对象

**预期输出 (服务端测试 - `GetPlaintextData`):**

* `GetPlaintextData()` 方法会返回客户端发送的原始 `plaintext_payload`: "Hello, OHTTP!"

**用户或编程常见的使用错误:**

1. **客户端使用错误的公钥:** 客户端在创建 OHTTP 请求时，如果使用了错误的服务器公钥，服务端将无法使用其私钥正确解密请求，导致解密失败。测试用例 `EndToEndTestForRequestWithWrongKey` 就覆盖了这种情况。

   ```c++
   TEST(ObliviousHttpRequest, EndToEndTestForRequestWithWrongKey) {
     // ...
     auto encapsulate = ObliviousHttpRequest::CreateClientObliviousRequest(
         "test", GetAlternativeHpkePublicKey(), ohttp_key_config); // 使用了错误的公钥
     // ...
     auto decapsulate = ObliviousHttpRequest::CreateServerObliviousRequest(
         oblivious_request,
         *(ConstructHpkeKey(GetHpkePrivateKey(), ohttp_key_config)),
         ohttp_key_config);
     EXPECT_EQ(decapsulate.status().code(), absl::StatusCode::kInvalidArgument); // 预期解密失败
   }
   ```

2. **服务端使用错误的私钥:** 服务端在尝试解密 OHTTP 请求时，如果使用了与加密时公钥不匹配的私钥，解密也会失败。虽然这个测试文件中没有直接测试这种情况，但在实际应用中这是常见的错误。

3. **OHTTP 配置不一致:** 客户端和服务端使用的 OHTTP 密钥配置 (Key ID, KEM ID, KDF ID, AEAD ID) 如果不一致，会导致加密和解密过程中的参数不匹配，从而导致解密失败。

4. **构造无效的 OHTTP 请求数据:**  手动构造 OHTTP 请求数据时，如果格式不正确（例如，头部信息错误，加密数据损坏），服务端将无法正确解析和解密。测试用例 `TestInvalidInputsOnServerSide` 覆盖了空加密数据的情况。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中访问一个支持 Oblivious HTTP 的网站或应用。**
2. **浏览器或应用中的 JavaScript 代码发起一个使用了 OHTTP 的网络请求。** 这可能通过配置 `fetch` API 的 `Content-Type` 头部为 `application/ohttp-req` 来实现，或者使用专门的 OHTTP JavaScript 库。
3. **浏览器的网络栈接收到该请求，并识别出这是一个 OHTTP 请求。**
4. **Chromium 的网络栈会调用到处理 OHTTP 请求的 C++ 代码。** 这包括 `net/third_party/quiche/src/quiche/oblivious_http/buffers/oblivious_http_request.h` 中定义的 `ObliviousHttpRequest` 类。
5. **客户端 (浏览器) 会使用 `ObliviousHttpRequest::CreateClientObliviousRequest` 创建 OHTTP 请求对象，并使用服务器提供的公钥进行加密 (encapsulation)。**
6. **加密后的 OHTTP 请求数据通过网络发送到服务器。**
7. **服务器接收到 OHTTP 请求后，其网络栈会调用相应的 C++ 代码进行处理。**
8. **服务端使用 `ObliviousHttpRequest::CreateServerObliviousRequest` 创建 OHTTP 请求对象，并使用其私钥尝试解密 (decapsulation)。**
9. **如果解密成功，`GetPlaintextData` 方法将返回原始的 HTTP 请求 payload，服务器可以继续处理该请求。**
10. **在调试过程中，如果 OHTTP 请求处理出现问题 (例如，解密失败)，开发者可能会查看服务器端的日志，或者在 Chromium 的网络栈代码中设置断点。** 这时，就会涉及到 `oblivious_http_request_test.cc` 中测试的这些 C++ 代码。通过查看相关的日志和断点信息，开发者可以逐步追踪 OHTTP 请求的处理流程，分析是在哪个环节出现了错误，例如密钥配置错误、数据格式错误等。

总而言之，`oblivious_http_request_test.cc` 是一个关键的测试文件，用于确保 Chromium 中 Oblivious HTTP 请求处理功能的正确性和健壮性。它覆盖了 OHTTP 协议的客户端加密、服务端解密、错误处理等关键流程，为 OHTTP 功能的稳定运行提供了保障。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/oblivious_http/buffers/oblivious_http_request_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
#include "quiche/oblivious_http/buffers/oblivious_http_request.h"

#include <stddef.h>

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/hkdf.h"
#include "openssl/hpke.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_data_reader.h"
#include "quiche/oblivious_http/common/oblivious_http_header_key_config.h"

namespace quiche {

namespace {
const uint32_t kHeaderLength = ObliviousHttpHeaderKeyConfig::kHeaderLength;
std::string GetHpkePrivateKey() {
  absl::string_view hpke_key_hex =
      "b77431ecfa8f4cfc30d6e467aafa06944dffe28cb9dd1409e33a3045f5adc8a1";
  std::string hpke_key_bytes;
  EXPECT_TRUE(absl::HexStringToBytes(hpke_key_hex, &hpke_key_bytes));
  return hpke_key_bytes;
}

std::string GetHpkePublicKey() {
  absl::string_view public_key =
      "6d21cfe09fbea5122f9ebc2eb2a69fcc4f06408cd54aac934f012e76fcdcef62";
  std::string public_key_bytes;
  EXPECT_TRUE(absl::HexStringToBytes(public_key, &public_key_bytes));
  return public_key_bytes;
}

std::string GetAlternativeHpkePublicKey() {
  absl::string_view public_key =
      "6d21cfe09fbea5122f9ebc2eb2a69fcc4f06408cd54aac934f012e76fcdcef63";
  std::string public_key_bytes;
  EXPECT_TRUE(absl::HexStringToBytes(public_key, &public_key_bytes));
  return public_key_bytes;
}

std::string GetSeed() {
  absl::string_view seed =
      "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736";
  std::string seed_bytes;
  EXPECT_TRUE(absl::HexStringToBytes(seed, &seed_bytes));
  return seed_bytes;
}

std::string GetSeededEncapsulatedKey() {
  absl::string_view encapsulated_key =
      "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";
  std::string encapsulated_key_bytes;
  EXPECT_TRUE(
      absl::HexStringToBytes(encapsulated_key, &encapsulated_key_bytes));
  return encapsulated_key_bytes;
}

bssl::UniquePtr<EVP_HPKE_KEY> ConstructHpkeKey(
    absl::string_view hpke_key,
    const ObliviousHttpHeaderKeyConfig &ohttp_key_config) {
  bssl::UniquePtr<EVP_HPKE_KEY> bssl_hpke_key(EVP_HPKE_KEY_new());
  EXPECT_NE(bssl_hpke_key, nullptr);
  EXPECT_TRUE(EVP_HPKE_KEY_init(
      bssl_hpke_key.get(), ohttp_key_config.GetHpkeKem(),
      reinterpret_cast<const uint8_t *>(hpke_key.data()), hpke_key.size()));
  return bssl_hpke_key;
}

const ObliviousHttpHeaderKeyConfig GetOhttpKeyConfig(uint8_t key_id,
                                                     uint16_t kem_id,
                                                     uint16_t kdf_id,
                                                     uint16_t aead_id) {
  auto ohttp_key_config =
      ObliviousHttpHeaderKeyConfig::Create(key_id, kem_id, kdf_id, aead_id);
  EXPECT_TRUE(ohttp_key_config.ok());
  return std::move(ohttp_key_config.value());
}
}  // namespace

// Direct test example from OHttp spec.
// https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-03.html#appendix-A
TEST(ObliviousHttpRequest, TestDecapsulateWithSpecAppendixAExample) {
  auto ohttp_key_config =
      GetOhttpKeyConfig(/*key_id=*/1, EVP_HPKE_DHKEM_X25519_HKDF_SHA256,
                        EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_128_GCM);

  // X25519 Secret key (priv key).
  // https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-03.html#appendix-A-2
  constexpr absl::string_view kX25519SecretKey =
      "3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a";

  // Encapsulated request.
  // https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-03.html#appendix-A-14
  constexpr absl::string_view kEncapsulatedRequest =
      "010020000100014b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c2"
      "08b4726374e469135906992e1268c594d2a10c695d858c40a026e7965e7d86b83dd440b2"
      "c0185204b4d63525";

  // Initialize Request obj to Decapsulate (decrypt).
  std::string encapsulated_request_bytes;
  ASSERT_TRUE(absl::HexStringToBytes(kEncapsulatedRequest,
                                     &encapsulated_request_bytes));
  std::string x25519_secret_key_bytes;
  ASSERT_TRUE(
      absl::HexStringToBytes(kX25519SecretKey, &x25519_secret_key_bytes));
  auto instance = ObliviousHttpRequest::CreateServerObliviousRequest(
      encapsulated_request_bytes,
      *(ConstructHpkeKey(x25519_secret_key_bytes, ohttp_key_config)),
      ohttp_key_config);
  ASSERT_TRUE(instance.ok());
  auto decrypted = instance->GetPlaintextData();

  // Encapsulated/Ephemeral public key.
  // https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-03.html#appendix-A-10
  constexpr absl::string_view kExpectedEphemeralPublicKey =
      "4b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b472";
  std::string expected_ephemeral_public_key_bytes;
  ASSERT_TRUE(absl::HexStringToBytes(kExpectedEphemeralPublicKey,
                                     &expected_ephemeral_public_key_bytes));
  auto oblivious_request_context = std::move(instance.value()).ReleaseContext();
  EXPECT_EQ(oblivious_request_context.encapsulated_key_,
            expected_ephemeral_public_key_bytes);

  // Binary HTTP message.
  // https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-03.html#appendix-A-6
  constexpr absl::string_view kExpectedBinaryHTTPMessage =
      "00034745540568747470730b6578616d706c652e636f6d012f";
  std::string expected_binary_http_message_bytes;
  ASSERT_TRUE(absl::HexStringToBytes(kExpectedBinaryHTTPMessage,
                                     &expected_binary_http_message_bytes));
  EXPECT_EQ(decrypted, expected_binary_http_message_bytes);
}

TEST(ObliviousHttpRequest, TestEncapsulatedRequestStructure) {
  uint8_t test_key_id = 7;
  uint16_t test_kem_id = EVP_HPKE_DHKEM_X25519_HKDF_SHA256;
  uint16_t test_kdf_id = EVP_HPKE_HKDF_SHA256;
  uint16_t test_aead_id = EVP_HPKE_AES_256_GCM;
  std::string plaintext = "test";
  auto instance = ObliviousHttpRequest::CreateClientObliviousRequest(
      plaintext, GetHpkePublicKey(),
      GetOhttpKeyConfig(test_key_id, test_kem_id, test_kdf_id, test_aead_id));
  ASSERT_TRUE(instance.ok());
  auto payload_bytes = instance->EncapsulateAndSerialize();
  EXPECT_GE(payload_bytes.size(), kHeaderLength);
  // Parse header.
  QuicheDataReader reader(payload_bytes);
  uint8_t key_id;
  EXPECT_TRUE(reader.ReadUInt8(&key_id));
  EXPECT_EQ(key_id, test_key_id);
  uint16_t kem_id;
  EXPECT_TRUE(reader.ReadUInt16(&kem_id));
  EXPECT_EQ(kem_id, test_kem_id);
  uint16_t kdf_id;
  EXPECT_TRUE(reader.ReadUInt16(&kdf_id));
  EXPECT_EQ(kdf_id, test_kdf_id);
  uint16_t aead_id;
  EXPECT_TRUE(reader.ReadUInt16(&aead_id));
  EXPECT_EQ(aead_id, test_aead_id);
  auto client_request_context = std::move(instance.value()).ReleaseContext();
  auto client_encapsulated_key = client_request_context.encapsulated_key_;
  EXPECT_EQ(client_encapsulated_key.size(), X25519_PUBLIC_VALUE_LEN);
  auto enc_key_plus_ciphertext = payload_bytes.substr(kHeaderLength);
  auto packed_encapsulated_key =
      enc_key_plus_ciphertext.substr(0, X25519_PUBLIC_VALUE_LEN);
  EXPECT_EQ(packed_encapsulated_key, client_encapsulated_key);
  auto ciphertext = enc_key_plus_ciphertext.substr(X25519_PUBLIC_VALUE_LEN);
  EXPECT_GE(ciphertext.size(), plaintext.size());
}

TEST(ObliviousHttpRequest, TestDeterministicSeededOhttpRequest) {
  auto ohttp_key_config =
      GetOhttpKeyConfig(4, EVP_HPKE_DHKEM_X25519_HKDF_SHA256,
                        EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_256_GCM);
  auto encapsulated = ObliviousHttpRequest::CreateClientWithSeedForTesting(
      "test", GetHpkePublicKey(), ohttp_key_config, GetSeed());
  ASSERT_TRUE(encapsulated.ok());
  auto encapsulated_request = encapsulated->EncapsulateAndSerialize();
  auto ohttp_request_context = std::move(encapsulated.value()).ReleaseContext();
  EXPECT_EQ(ohttp_request_context.encapsulated_key_,
            GetSeededEncapsulatedKey());
  absl::string_view expected_encrypted_request =
      "9f37cfed07d0111ecd2c34f794671759bcbd922a";
  std::string expected_encrypted_request_bytes;
  ASSERT_TRUE(absl::HexStringToBytes(expected_encrypted_request,
                                     &expected_encrypted_request_bytes));
  EXPECT_NE(ohttp_request_context.hpke_context_, nullptr);
  size_t encapsulated_key_len = EVP_HPKE_KEM_enc_len(
      EVP_HPKE_CTX_kem(ohttp_request_context.hpke_context_.get()));
  int encrypted_payload_offset = kHeaderLength + encapsulated_key_len;
  EXPECT_EQ(encapsulated_request.substr(encrypted_payload_offset),
            expected_encrypted_request_bytes);
}

TEST(ObliviousHttpRequest,
     TestSeededEncapsulatedKeySamePlaintextsSameCiphertexts) {
  auto ohttp_key_config =
      GetOhttpKeyConfig(8, EVP_HPKE_DHKEM_X25519_HKDF_SHA256,
                        EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_256_GCM);
  auto req_with_same_plaintext_1 =
      ObliviousHttpRequest::CreateClientWithSeedForTesting(
          "same plaintext", GetHpkePublicKey(), ohttp_key_config, GetSeed());
  ASSERT_TRUE(req_with_same_plaintext_1.ok());
  auto ciphertext_1 = req_with_same_plaintext_1->EncapsulateAndSerialize();
  auto req_with_same_plaintext_2 =
      ObliviousHttpRequest::CreateClientWithSeedForTesting(
          "same plaintext", GetHpkePublicKey(), ohttp_key_config, GetSeed());
  ASSERT_TRUE(req_with_same_plaintext_2.ok());
  auto ciphertext_2 = req_with_same_plaintext_2->EncapsulateAndSerialize();
  EXPECT_EQ(ciphertext_1, ciphertext_2);
}

TEST(ObliviousHttpRequest,
     TestSeededEncapsulatedKeyDifferentPlaintextsDifferentCiphertexts) {
  auto ohttp_key_config =
      GetOhttpKeyConfig(8, EVP_HPKE_DHKEM_X25519_HKDF_SHA256,
                        EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_256_GCM);
  auto req_with_different_plaintext_1 =
      ObliviousHttpRequest::CreateClientWithSeedForTesting(
          "different 1", GetHpkePublicKey(), ohttp_key_config, GetSeed());
  ASSERT_TRUE(req_with_different_plaintext_1.ok());
  auto ciphertext_1 = req_with_different_plaintext_1->EncapsulateAndSerialize();
  auto req_with_different_plaintext_2 =
      ObliviousHttpRequest::CreateClientWithSeedForTesting(
          "different 2", GetHpkePublicKey(), ohttp_key_config, GetSeed());
  ASSERT_TRUE(req_with_different_plaintext_2.ok());
  auto ciphertext_2 = req_with_different_plaintext_2->EncapsulateAndSerialize();
  EXPECT_NE(ciphertext_1, ciphertext_2);
}

TEST(ObliviousHttpRequest, TestInvalidInputsOnClientSide) {
  auto ohttp_key_config =
      GetOhttpKeyConfig(30, EVP_HPKE_DHKEM_X25519_HKDF_SHA256,
                        EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_256_GCM);
  // Empty plaintext.
  EXPECT_EQ(ObliviousHttpRequest::CreateClientObliviousRequest(
                /*plaintext_payload*/ "", GetHpkePublicKey(), ohttp_key_config)
                .status()
                .code(),
            absl::StatusCode::kInvalidArgument);
  // Empty HPKE public key.
  EXPECT_EQ(ObliviousHttpRequest::CreateClientObliviousRequest(
                "some plaintext",
                /*hpke_public_key*/ "", ohttp_key_config)
                .status()
                .code(),
            absl::StatusCode::kInvalidArgument);
}

TEST(ObliviousHttpRequest, TestInvalidInputsOnServerSide) {
  auto ohttp_key_config =
      GetOhttpKeyConfig(4, EVP_HPKE_DHKEM_X25519_HKDF_SHA256,
                        EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_256_GCM);
  // Empty encrypted payload.
  EXPECT_EQ(ObliviousHttpRequest::CreateServerObliviousRequest(
                /*encrypted_data*/ "",
                *(ConstructHpkeKey(GetHpkePrivateKey(), ohttp_key_config)),
                ohttp_key_config)
                .status()
                .code(),
            absl::StatusCode::kInvalidArgument);
  // Empty EVP_HPKE_KEY struct.
  EXPECT_EQ(ObliviousHttpRequest::CreateServerObliviousRequest(
                absl::StrCat(ohttp_key_config.SerializeOhttpPayloadHeader(),
                             GetSeededEncapsulatedKey(),
                             "9f37cfed07d0111ecd2c34f794671759bcbd922a"),
                /*gateway_key*/ {}, ohttp_key_config)
                .status()
                .code(),
            absl::StatusCode::kInvalidArgument);
}

TEST(ObliviousHttpRequest, EndToEndTestForRequest) {
  auto ohttp_key_config =
      GetOhttpKeyConfig(5, EVP_HPKE_DHKEM_X25519_HKDF_SHA256,
                        EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_256_GCM);
  auto encapsulate = ObliviousHttpRequest::CreateClientObliviousRequest(
      "test", GetHpkePublicKey(), ohttp_key_config);
  ASSERT_TRUE(encapsulate.ok());
  auto oblivious_request = encapsulate->EncapsulateAndSerialize();
  auto decapsulate = ObliviousHttpRequest::CreateServerObliviousRequest(
      oblivious_request,
      *(ConstructHpkeKey(GetHpkePrivateKey(), ohttp_key_config)),
      ohttp_key_config);
  ASSERT_TRUE(decapsulate.ok());
  auto decrypted = decapsulate->GetPlaintextData();
  EXPECT_EQ(decrypted, "test");
}

TEST(ObliviousHttpRequest, EndToEndTestForRequestWithWrongKey) {
  auto ohttp_key_config =
      GetOhttpKeyConfig(5, EVP_HPKE_DHKEM_X25519_HKDF_SHA256,
                        EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_256_GCM);
  auto encapsulate = ObliviousHttpRequest::CreateClientObliviousRequest(
      "test", GetAlternativeHpkePublicKey(), ohttp_key_config);
  ASSERT_TRUE(encapsulate.ok());
  auto oblivious_request = encapsulate->EncapsulateAndSerialize();
  auto decapsulate = ObliviousHttpRequest::CreateServerObliviousRequest(
      oblivious_request,
      *(ConstructHpkeKey(GetHpkePrivateKey(), ohttp_key_config)),
      ohttp_key_config);
  EXPECT_EQ(decapsulate.status().code(), absl::StatusCode::kInvalidArgument);
}
}  // namespace quiche
```