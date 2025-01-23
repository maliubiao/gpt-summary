Response:
Let's break down the thought process for analyzing the C++ test file.

1. **Understand the Goal:** The request asks for the functionality of the C++ test file, its relation to JavaScript, example inputs/outputs, common errors, and debugging steps. Essentially, it's about understanding what this test code does and how it relates to a broader context.

2. **Identify the Core Subject:** The file name `aes_128_gcm_encrypter_test.cc` immediately tells us this is a test file for something called `Aes128GcmEncrypter`. The "test" suffix is a strong indicator.

3. **Scan the Includes:**  The `#include` directives are crucial. They reveal the dependencies:
    * `"quiche/quic/core/crypto/aes_128_gcm_encrypter.h"`:  This confirms that the test is for the `Aes128GcmEncrypter` class.
    * Standard library headers (`<memory>`, `<string>`, `<vector>`).
    * `absl/base/macros.h`, `absl/strings/escaping.h`: Indicate use of the Abseil library, likely for string manipulation and hex encoding.
    * `"quiche/quic/core/quic_utils.h"`:  Suggests the encrypter is part of the QUIC protocol implementation.
    * `"quiche/quic/platform/api/quic_test.h"`: Confirms this is a QUIC test.
    * `"quiche/quic/test_tools/quic_test_utils.h"` and `"quiche/common/test_tools/quiche_test_utils.h"`: Point to testing utility functions.

4. **Examine the Test Structure:** The file uses the Google Test framework (evident from `TEST_F`). This means tests are organized into test cases within a test fixture class. The class `Aes128GcmEncrypterTest` is the fixture.

5. **Analyze Individual Tests:** Go through each `TEST_F`:
    * `Encrypt`: This test uses a large set of hardcoded test vectors from a NIST file. It decodes the hex strings (key, IV, plaintext, AAD, ciphertext, tag) and then uses `Aes128GcmEncrypter` to encrypt the plaintext with the given key, IV, and AAD. It then compares the generated ciphertext and tag with the expected values. This is the primary function of the test file: verifying the core encryption functionality.
    * `EncryptPacket`: This test seems to test a specific `EncryptPacket` method, possibly an optimized version or one with a slightly different interface (it takes a `packet_num`). It again uses hardcoded values.
    * `GetMaxPlaintextSize`: This tests a method for calculating the maximum plaintext size given the ciphertext size. It's likely related to buffer management.
    * `GetCiphertextSize`: This tests the reverse: calculating the ciphertext size from the plaintext size.
    * `GenerateHeaderProtectionMask`:  This test focuses on a specific header protection mechanism, again with hardcoded key and sample data, and verifies the generated mask.

6. **Identify Key Concepts:**  The core functionality revolves around AES-128 in GCM mode. Key terms to understand:
    * AES-128: Advanced Encryption Standard with a 128-bit key.
    * GCM: Galois/Counter Mode, an authenticated encryption algorithm.
    * Key: The secret used for encryption.
    * IV (Initialization Vector) or Nonce:  A value used to ensure the same plaintext encrypts to different ciphertexts.
    * Plaintext: The data to be encrypted.
    * Ciphertext: The encrypted data.
    * AAD (Authenticated Additional Data): Data that is authenticated but not encrypted.
    * Tag:  The authentication tag produced by GCM.
    * Header Protection: A mechanism to protect packet headers.

7. **Address the JavaScript Question:**  Think about where encryption is used in web technologies. TLS/SSL is a prime example. While this specific C++ code isn't directly runnable in JavaScript, the *concepts* of AES-GCM encryption are used in JavaScript Web Crypto API for secure communication. Provide a simple example using `crypto.subtle.encrypt`.

8. **Consider Inputs and Outputs:** For the `Encrypt` test, the inputs are the key, IV, plaintext, and AAD (all as hex strings), and the expected outputs are the ciphertext and tag (also hex strings). For other tests, the inputs and outputs relate to the specific methods being tested.

9. **Think About Common Errors:**  Consider mistakes developers might make when using such an encrypter:
    * Incorrect key length.
    * Reusing IVs with the same key (a security vulnerability in GCM).
    * Not handling the output buffer correctly.
    * Incorrectly encoding or decoding hex strings.

10. **Imagine the Debugging Scenario:** How might a developer end up looking at this test file? They might be investigating a QUIC connection issue, suspecting an encryption problem, or working on the encryption implementation itself. Tracing network packets and stepping through encryption/decryption code could lead them here.

11. **Structure the Answer:** Organize the findings into clear sections: Functionality, Relation to JavaScript, Input/Output Examples, Common Errors, and Debugging. Use bullet points and code examples to enhance readability.

12. **Refine and Review:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Check for any jargon that might need explanation. Ensure the JavaScript example is correct and relevant.

This systematic approach allows for a comprehensive understanding of the C++ test file and its implications. The key is to move from the specific code to the underlying concepts and then connect those concepts to broader contexts like web technologies and common programming practices.
这个文件 `aes_128_gcm_encrypter_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，专门用于测试 `Aes128GcmEncrypter` 类的功能。`Aes128GcmEncrypter` 类负责使用 AES-128 算法在 Galois/Counter Mode (GCM) 下进行加密操作。

**主要功能:**

1. **单元测试 `Aes128GcmEncrypter` 类的加密功能:**  该文件包含了多个单元测试，旨在验证 `Aes128GcmEncrypter` 类在不同场景下的加密操作是否正确。这些场景包括：
    * 使用不同的密钥、初始化向量 (IV)、明文、认证附加数据 (AAD) 进行加密。
    * 验证加密后的密文和认证标签是否与预期的值一致。
    * 测试 `EncryptPacket` 方法，该方法可能针对 QUIC 数据包的加密做了特殊优化或处理。
    * 测试获取最大明文大小 (`GetMaxPlaintextSize`) 和密文大小 (`GetCiphertextSize`) 的功能。
    * 测试生成包头保护掩码 (`GenerateHeaderProtectionMask`) 的功能。

2. **使用 NIST 提供的测试向量:**  代码中使用了从美国国家标准与技术研究院 (NIST) 获取的 AES-GCM 测试向量。这些测试向量包含了预先计算好的密钥、IV、明文、AAD、密文和标签，用于验证加密实现的正确性。

**与 JavaScript 的关系:**

虽然这个 C++ 文件本身不能直接在 JavaScript 中运行，但它所测试的 AES-128-GCM 加密算法是 Web Cryptography API 中常用的加密算法之一。JavaScript 可以使用 `crypto.subtle.encrypt` 方法来实现相同的加密功能。

**举例说明:**

假设在 JavaScript 中，我们需要使用 AES-128-GCM 加密一段数据，我们可以这样做：

```javascript
async function encryptData(keyData, ivData, aadData, plaintextData) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "AES-GCM", length: 128 },
    false,
    ["encrypt"]
  );

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: ivData,
      additionalData: aadData // 可选
    },
    key,
    plaintextData
  );

  return ciphertext;
}

// 假设我们有以下十六进制表示的密钥、IV、AAD 和明文
const keyHex = "11754cd72aec309bf52f7687212e8957";
const ivHex = "3c819d9a9bed087615030b65";
const aadHex = "";
const plaintextHex = "";

// 将十六进制字符串转换为 Uint8Array
function hexToUint8Array(hexString) {
  const byteLength = hexString.length / 2;
  const byteArray = new Uint8Array(byteLength);
  for (let i = 0; i < byteLength; i++) {
    const hexByte = hexString.substring(i * 2, i * 2 + 2);
    byteArray[i] = parseInt(hexByte, 16);
  }
  return byteArray;
}

const keyData = hexToUint8Array(keyHex);
const ivData = hexToUint8Array(ivHex);
const aadData = hexToUint8Array(aadHex);
const plaintextData = hexToUint8Array(plaintextHex);

encryptData(keyData, ivData, aadData, plaintextData)
  .then(ciphertext => {
    console.log("Ciphertext (ArrayBuffer):", ciphertext);
    // 可以将 ArrayBuffer 转换为十六进制字符串进行比较
  })
  .catch(error => {
    console.error("Encryption error:", error);
  });
```

在这个例子中，JavaScript 使用了与 C++ 代码中 `Aes128GcmEncrypter` 相同的 AES-128-GCM 算法进行加密。这个 C++ 测试文件的目的是确保其实现的加密行为与标准算法一致，这对于跨平台通信（比如浏览器和服务器之间的 QUIC 连接）至关重要。

**逻辑推理与假设输入/输出:**

以 `TEST_F(Aes128GcmEncrypterTest, Encrypt)` 中的一个测试向量为例：

**假设输入:**

* **密钥 (Key):** `11754cd72aec309bf52f7687212e8957` (十六进制字符串)
* **初始化向量 (IV):** `3c819d9a9bed087615030b65` (十六进制字符串)
* **明文 (PT):**  "" (空字符串)
* **认证附加数据 (AAD):** "" (空字符串)

**预期输出:**

* **密文 (CT):** "" (空字符串)
* **认证标签 (Tag):** `250327c674aaf477aef2675748cf6971` (十六进制字符串)

**逻辑推理:**

这个测试用例使用给定的密钥和 IV 对空明文进行加密，并计算认证标签。`Aes128GcmEncrypter` 类的 `Encrypt` 方法应该返回一个包含空密文和特定标签的结果。测试代码会将实际生成的密文和标签与预期的值进行比较，如果一致，则说明加密功能正常。

**用户或编程常见的使用错误:**

1. **密钥长度错误:** AES-128 需要 128 位的密钥（16 字节）。如果提供的密钥长度不正确，`SetKey` 方法可能会失败或导致加密结果不正确。
   ```c++
   Aes128GcmEncrypter encrypter;
   std::string short_key = "0123456789ABCDEF"; // 密钥长度不足
   ASSERT_FALSE(encrypter.SetKey(short_key)); // 应该返回 false
   ```

2. **重复使用相同的 IV 和密钥:** 在 GCM 模式下，对于相同的密钥，绝对不能重复使用相同的 IV。否则，可能会泄露有关明文的信息。
   ```c++
   Aes128GcmEncrypter encrypter;
   std::string key = /* ... */;
   std::string iv = /* ... */;
   std::string plaintext1 = /* ... */;
   std::string plaintext2 = /* ... */;

   encrypter.SetKey(key);

   // 错误：对不同的明文使用相同的 IV
   std::unique_ptr<QuicData> encrypted1 = EncryptWithNonce(&encrypter, iv, "", plaintext1);
   std::unique_ptr<QuicData> encrypted2 = EncryptWithNonce(&encrypter, iv, "", plaintext2);
   ```

3. **AAD 处理不当:** 认证附加数据 (AAD) 用于提供不加密但需要认证的数据。如果发送方和接收方对 AAD 的理解不一致，接收方可能无法验证消息的完整性。
   ```c++
   // 发送方使用 AAD
   std::string aad_send = "context_info";
   std::unique_ptr<QuicData> encrypted = EncryptWithNonce(&encrypter, iv, aad_send, plaintext);

   // 接收方没有提供相同的 AAD 进行解密验证（在解密测试中会体现）
   ```

4. **输出缓冲区大小不足:** 在使用 `EncryptPacket` 等方法时，如果提供的输出缓冲区大小不足以容纳密文和标签，可能会导致数据截断或程序崩溃。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户报告 QUIC 连接在握手或数据传输阶段出现加密相关的问题，调试过程可能会如下：

1. **用户报告连接错误:** 用户在使用基于 Chromium 的浏览器或其他使用 QUIC 的应用程序时，遇到了连接失败、数据传输中断或内容损坏等问题。

2. **网络工程师或开发人员开始调查:**  他们可能会首先检查网络连接是否稳定，排除网络基础设施问题。

3. **抓包分析:** 使用 Wireshark 等工具抓取网络数据包，查看 QUIC 握手和数据传输过程中的加密帧。可能会注意到加密失败或认证错误。

4. **查看 Chromium 的 QUIC 内部日志:**  Chromium 提供了详细的 QUIC 内部日志，可以查看加密和解密的详细过程，包括使用的密钥、IV、AAD 等。

5. **怀疑加密实现问题:** 如果日志显示加密或解密过程中出现错误，例如认证标签验证失败，开发人员可能会怀疑 `Aes128GcmEncrypter` 的实现是否存在 bug。

6. **定位到 `aes_128_gcm_encrypter_test.cc`:** 为了验证 `Aes128GcmEncrypter` 的正确性，开发人员会查看其单元测试。这个测试文件提供了大量的测试用例，可以帮助他们理解加密算法的预期行为，并对比实际运行时的行为。

7. **运行或修改测试:** 开发人员可能会运行这些单元测试，或者添加新的测试用例来复现用户报告的问题。如果测试失败，则表明 `Aes128GcmEncrypter` 的实现存在问题，需要进行修复。

8. **代码审查:**  开发人员会仔细审查 `Aes128GcmEncrypter` 的源代码，查找潜在的逻辑错误、边界条件处理不当等问题。

9. **修复和验证:** 修复代码后，重新运行单元测试，确保所有测试都通过，以验证修复的正确性。

总而言之，`aes_128_gcm_encrypter_test.cc` 文件是保证 Chromium QUIC 协议加密功能正确性和安全性的重要组成部分。它通过大量的测试用例来验证 `Aes128GcmEncrypter` 类的实现是否符合预期，这对于构建可靠的网络应用程序至关重要。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/crypto/aes_128_gcm_encrypter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/crypto/aes_128_gcm_encrypter.h"

#include <memory>
#include <string>
#include <vector>

#include "absl/base/macros.h"
#include "absl/strings/escaping.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/test_tools/quiche_test_utils.h"

namespace {

// The AES GCM test vectors come from the file gcmEncryptExtIV128.rsp
// downloaded from http://csrc.nist.gov/groups/STM/cavp/index.html on
// 2013-02-01. The test vectors in that file look like this:
//
// [Keylen = 128]
// [IVlen = 96]
// [PTlen = 0]
// [AADlen = 0]
// [Taglen = 128]
//
// Count = 0
// Key = 11754cd72aec309bf52f7687212e8957
// IV = 3c819d9a9bed087615030b65
// PT =
// AAD =
// CT =
// Tag = 250327c674aaf477aef2675748cf6971
//
// Count = 1
// Key = ca47248ac0b6f8372a97ac43508308ed
// IV = ffd2b598feabc9019262d2be
// PT =
// AAD =
// CT =
// Tag = 60d20404af527d248d893ae495707d1a
//
// ...
//
// The gcmEncryptExtIV128.rsp file is huge (2.8 MB), so I selected just a
// few test vectors for this unit test.

// Describes a group of test vectors that all have a given key length, IV
// length, plaintext length, AAD length, and tag length.
struct TestGroupInfo {
  size_t key_len;
  size_t iv_len;
  size_t pt_len;
  size_t aad_len;
  size_t tag_len;
};

// Each test vector consists of six strings of lowercase hexadecimal digits.
// The strings may be empty (zero length). A test vector with a nullptr |key|
// marks the end of an array of test vectors.
struct TestVector {
  const char* key;
  const char* iv;
  const char* pt;
  const char* aad;
  const char* ct;
  const char* tag;
};

const TestGroupInfo test_group_info[] = {
    {128, 96, 0, 0, 128},     {128, 96, 0, 128, 128},   {128, 96, 128, 0, 128},
    {128, 96, 408, 160, 128}, {128, 96, 408, 720, 128}, {128, 96, 104, 0, 128},
};

const TestVector test_group_0[] = {
    {"11754cd72aec309bf52f7687212e8957", "3c819d9a9bed087615030b65", "", "", "",
     "250327c674aaf477aef2675748cf6971"},
    {"ca47248ac0b6f8372a97ac43508308ed", "ffd2b598feabc9019262d2be", "", "", "",
     "60d20404af527d248d893ae495707d1a"},
    {nullptr, nullptr, nullptr, nullptr, nullptr, nullptr}};

const TestVector test_group_1[] = {
    {"77be63708971c4e240d1cb79e8d77feb", "e0e00f19fed7ba0136a797f3", "",
     "7a43ec1d9c0a5a78a0b16533a6213cab", "",
     "209fcc8d3675ed938e9c7166709dd946"},
    {"7680c5d3ca6154758e510f4d25b98820", "f8f105f9c3df4965780321f8", "",
     "c94c410194c765e3dcc7964379758ed3", "",
     "94dca8edfcf90bb74b153c8d48a17930"},
    {nullptr, nullptr, nullptr, nullptr, nullptr, nullptr}};

const TestVector test_group_2[] = {
    {"7fddb57453c241d03efbed3ac44e371c", "ee283a3fc75575e33efd4887",
     "d5de42b461646c255c87bd2962d3b9a2", "", "2ccda4a5415cb91e135c2a0f78c9b2fd",
     "b36d1df9b9d5e596f83e8b7f52971cb3"},
    {"ab72c77b97cb5fe9a382d9fe81ffdbed", "54cc7dc2c37ec006bcc6d1da",
     "007c5e5b3e59df24a7c355584fc1518d", "", "0e1bde206a07a9c2c1b65300f8c64997",
     "2b4401346697138c7a4891ee59867d0c"},
    {nullptr, nullptr, nullptr, nullptr, nullptr, nullptr}};

const TestVector test_group_3[] = {
    {"fe47fcce5fc32665d2ae399e4eec72ba", "5adb9609dbaeb58cbd6e7275",
     "7c0e88c88899a779228465074797cd4c2e1498d259b54390b85e3eef1c02df60e743f1"
     "b840382c4bccaf3bafb4ca8429bea063",
     "88319d6e1d3ffa5f987199166c8a9b56c2aeba5a",
     "98f4826f05a265e6dd2be82db241c0fbbbf9ffb1c173aa83964b7cf539304373636525"
     "3ddbc5db8778371495da76d269e5db3e",
     "291ef1982e4defedaa2249f898556b47"},
    {"ec0c2ba17aa95cd6afffe949da9cc3a8", "296bce5b50b7d66096d627ef",
     "b85b3753535b825cbe5f632c0b843c741351f18aa484281aebec2f45bb9eea2d79d987"
     "b764b9611f6c0f8641843d5d58f3a242",
     "f8d00f05d22bf68599bcdeb131292ad6e2df5d14",
     "a7443d31c26bdf2a1c945e29ee4bd344a99cfaf3aa71f8b3f191f83c2adfc7a0716299"
     "5506fde6309ffc19e716eddf1a828c5a",
     "890147971946b627c40016da1ecf3e77"},
    {nullptr, nullptr, nullptr, nullptr, nullptr, nullptr}};

const TestVector test_group_4[] = {
    {"2c1f21cf0f6fb3661943155c3e3d8492", "23cb5ff362e22426984d1907",
     "42f758836986954db44bf37c6ef5e4ac0adaf38f27252a1b82d02ea949c8a1a2dbc0d6"
     "8b5615ba7c1220ff6510e259f06655d8",
     "5d3624879d35e46849953e45a32a624d6a6c536ed9857c613b572b0333e701557a713e"
     "3f010ecdf9a6bd6c9e3e44b065208645aff4aabee611b391528514170084ccf587177f"
     "4488f33cfb5e979e42b6e1cfc0a60238982a7aec",
     "81824f0e0d523db30d3da369fdc0d60894c7a0a20646dd015073ad2732bd989b14a222"
     "b6ad57af43e1895df9dca2a5344a62cc",
     "57a3ee28136e94c74838997ae9823f3a"},
    {"d9f7d2411091f947b4d6f1e2d1f0fb2e", "e1934f5db57cc983e6b180e7",
     "73ed042327f70fe9c572a61545eda8b2a0c6e1d6c291ef19248e973aee6c312012f490"
     "c2c6f6166f4a59431e182663fcaea05a",
     "0a8a18a7150e940c3d87b38e73baee9a5c049ee21795663e264b694a949822b639092d"
     "0e67015e86363583fcf0ca645af9f43375f05fdb4ce84f411dcbca73c2220dea03a201"
     "15d2e51398344b16bee1ed7c499b353d6c597af8",
     "aaadbd5c92e9151ce3db7210b8714126b73e43436d242677afa50384f2149b831f1d57"
     "3c7891c2a91fbc48db29967ec9542b23",
     "21b51ca862cb637cdd03b99a0f93b134"},
    {nullptr, nullptr, nullptr, nullptr, nullptr, nullptr}};

const TestVector test_group_5[] = {
    {"fe9bb47deb3a61e423c2231841cfd1fb", "4d328eb776f500a2f7fb47aa",
     "f1cc3818e421876bb6b8bbd6c9", "", "b88c5c1977b35b517b0aeae967",
     "43fd4727fe5cdb4b5b42818dea7ef8c9"},
    {"6703df3701a7f54911ca72e24dca046a", "12823ab601c350ea4bc2488c",
     "793cd125b0b84a043e3ac67717", "", "b2051c80014f42f08735a7b0cd",
     "38e6bcd29962e5f2c13626b85a877101"},
    {nullptr, nullptr, nullptr, nullptr, nullptr, nullptr}};

const TestVector* const test_group_array[] = {
    test_group_0, test_group_1, test_group_2,
    test_group_3, test_group_4, test_group_5,
};

}  // namespace

namespace quic {
namespace test {

// EncryptWithNonce wraps the |Encrypt| method of |encrypter| to allow passing
// in an nonce and also to allocate the buffer needed for the ciphertext.
QuicData* EncryptWithNonce(Aes128GcmEncrypter* encrypter,
                           absl::string_view nonce,
                           absl::string_view associated_data,
                           absl::string_view plaintext) {
  size_t ciphertext_size = encrypter->GetCiphertextSize(plaintext.length());
  std::unique_ptr<char[]> ciphertext(new char[ciphertext_size]);

  if (!encrypter->Encrypt(nonce, associated_data, plaintext,
                          reinterpret_cast<unsigned char*>(ciphertext.get()))) {
    return nullptr;
  }

  return new QuicData(ciphertext.release(), ciphertext_size, true);
}

class Aes128GcmEncrypterTest : public QuicTest {};

TEST_F(Aes128GcmEncrypterTest, Encrypt) {
  for (size_t i = 0; i < ABSL_ARRAYSIZE(test_group_array); i++) {
    SCOPED_TRACE(i);
    const TestVector* test_vectors = test_group_array[i];
    const TestGroupInfo& test_info = test_group_info[i];
    for (size_t j = 0; test_vectors[j].key != nullptr; j++) {
      // Decode the test vector.
      std::string key;
      std::string iv;
      std::string pt;
      std::string aad;
      std::string ct;
      std::string tag;
      ASSERT_TRUE(absl::HexStringToBytes(test_vectors[j].key, &key));
      ASSERT_TRUE(absl::HexStringToBytes(test_vectors[j].iv, &iv));
      ASSERT_TRUE(absl::HexStringToBytes(test_vectors[j].pt, &pt));
      ASSERT_TRUE(absl::HexStringToBytes(test_vectors[j].aad, &aad));
      ASSERT_TRUE(absl::HexStringToBytes(test_vectors[j].ct, &ct));
      ASSERT_TRUE(absl::HexStringToBytes(test_vectors[j].tag, &tag));

      // The test vector's lengths should look sane. Note that the lengths
      // in |test_info| are in bits.
      EXPECT_EQ(test_info.key_len, key.length() * 8);
      EXPECT_EQ(test_info.iv_len, iv.length() * 8);
      EXPECT_EQ(test_info.pt_len, pt.length() * 8);
      EXPECT_EQ(test_info.aad_len, aad.length() * 8);
      EXPECT_EQ(test_info.pt_len, ct.length() * 8);
      EXPECT_EQ(test_info.tag_len, tag.length() * 8);

      Aes128GcmEncrypter encrypter;
      ASSERT_TRUE(encrypter.SetKey(key));
      std::unique_ptr<QuicData> encrypted(
          EncryptWithNonce(&encrypter, iv,
                           // This deliberately tests that the encrypter can
                           // handle an AAD that is set to nullptr, as opposed
                           // to a zero-length, non-nullptr pointer.
                           aad.length() ? aad : absl::string_view(), pt));
      ASSERT_TRUE(encrypted.get());

      ASSERT_EQ(ct.length() + tag.length(), encrypted->length());
      quiche::test::CompareCharArraysWithHexError(
          "ciphertext", encrypted->data(), ct.length(), ct.data(), ct.length());
      quiche::test::CompareCharArraysWithHexError(
          "authentication tag", encrypted->data() + ct.length(), tag.length(),
          tag.data(), tag.length());
    }
  }
}

TEST_F(Aes128GcmEncrypterTest, EncryptPacket) {
  std::string key;
  std::string iv;
  std::string aad;
  std::string pt;
  std::string ct;
  ASSERT_TRUE(absl::HexStringToBytes("d95a145250826c25a77b6a84fd4d34fc", &key));
  ASSERT_TRUE(absl::HexStringToBytes("50c4431ebb18283448e276e2", &iv));
  ASSERT_TRUE(
      absl::HexStringToBytes("875d49f64a70c9cbe713278f44ff000005", &aad));
  ASSERT_TRUE(absl::HexStringToBytes("aa0003a250bd000000000001", &pt));
  ASSERT_TRUE(absl::HexStringToBytes(
      "7dd4708b989ee7d38a013e3656e9b37beefd05808fe1ab41e3b4f2c0", &ct));
  uint64_t packet_num = 0x13278f44;

  std::vector<char> out(ct.size());
  size_t out_size;

  Aes128GcmEncrypter encrypter;
  ASSERT_TRUE(encrypter.SetKey(key));
  ASSERT_TRUE(encrypter.SetIV(iv));
  ASSERT_TRUE(encrypter.EncryptPacket(packet_num, aad, pt, out.data(),
                                      &out_size, out.size()));
  EXPECT_EQ(out_size, out.size());
  quiche::test::CompareCharArraysWithHexError("ciphertext", out.data(),
                                              out.size(), ct.data(), ct.size());
}

TEST_F(Aes128GcmEncrypterTest, GetMaxPlaintextSize) {
  Aes128GcmEncrypter encrypter;
  EXPECT_EQ(1000u, encrypter.GetMaxPlaintextSize(1016));
  EXPECT_EQ(100u, encrypter.GetMaxPlaintextSize(116));
  EXPECT_EQ(10u, encrypter.GetMaxPlaintextSize(26));
}

TEST_F(Aes128GcmEncrypterTest, GetCiphertextSize) {
  Aes128GcmEncrypter encrypter;
  EXPECT_EQ(1016u, encrypter.GetCiphertextSize(1000));
  EXPECT_EQ(116u, encrypter.GetCiphertextSize(100));
  EXPECT_EQ(26u, encrypter.GetCiphertextSize(10));
}

TEST_F(Aes128GcmEncrypterTest, GenerateHeaderProtectionMask) {
  Aes128GcmEncrypter encrypter;
  std::string key;
  std::string sample;
  std::string expected_mask;
  ASSERT_TRUE(absl::HexStringToBytes("d9132370cb18476ab833649cf080d970", &key));
  ASSERT_TRUE(
      absl::HexStringToBytes("d1d7998068517adb769b48b924a32c47", &sample));
  ASSERT_TRUE(absl::HexStringToBytes("b132c37d6164da4ea4dc9b763aceec27",
                                     &expected_mask));
  ASSERT_TRUE(encrypter.SetHeaderProtectionKey(key));
  std::string mask = encrypter.GenerateHeaderProtectionMask(sample);
  quiche::test::CompareCharArraysWithHexError(
      "header protection mask", mask.data(), mask.size(), expected_mask.data(),
      expected_mask.size());
}

}  // namespace test
}  // namespace quic
```