Response:
Let's break down the thought process to arrive at the comprehensive explanation of the `aes_128_gcm_12_encrypter_test.cc` file.

1. **Understand the Goal:** The core request is to understand the purpose of this test file in the Chromium networking stack, specifically focusing on its functionality, potential relation to JavaScript, logic inference through examples, common user errors, and debugging context.

2. **Identify the Core Component:** The filename `aes_128_gcm_12_encrypter_test.cc` immediately points to the testing of a component named `Aes128Gcm12Encrypter`. The `.cc` extension signifies a C++ source file.

3. **Examine the Includes:** The included headers provide crucial context:
    * `aes_128_gcm_12_encrypter.h`:  Confirms the existence of the `Aes128Gcm12Encrypter` class and its definition.
    * `<memory>`, `<string>`: Standard C++ library headers, indicating the use of memory management and string manipulation.
    * `absl/...`:  Headers from the Abseil library, used extensively within Chromium, suggest the use of utilities like string views and hex encoding.
    * `quiche/...`: Headers from the QUIC implementation, showing that this encrypter is part of the QUIC protocol implementation. Specifically, `quic_utils.h`, `quic_test.h`, and `quic_test_utils.h` strongly indicate this is a test file within the QUIC context. `quiche_test_utils.h` provides generic testing utilities.

4. **Analyze the Test Structure:** The file defines a namespace `quic::test` and contains a test fixture class `Aes128Gcm12EncrypterTest` inheriting from `QuicTest`. This confirms it's using a standard testing framework.

5. **Deconstruct the Test Cases:**  The file contains several `TEST_F` macros, indicating individual test cases within the fixture:
    * `Encrypt`: This is the main test, iterating through test vectors to verify the encryption process.
    * `GetMaxPlaintextSize`: Tests a method related to determining the maximum plaintext size based on the ciphertext size.
    * `GetCiphertextSize`: Tests a method to calculate the ciphertext size given the plaintext size.

6. **Focus on the `Encrypt` Test:** This is the most significant test case. Key observations:
    * **Test Vectors:** The code heavily relies on pre-defined test vectors loaded from what appears to be a historical NIST file (`gcmEncryptExtIV128.rsp`). These vectors contain known keys, IVs (Initialization Vectors), plaintexts, associated data, ciphertexts, and authentication tags.
    * **Hex Decoding:**  The `absl::HexStringToBytes` function is used to convert the hexadecimal string representations in the test vectors into binary data.
    * **Encryption and Verification:** The test instantiates `Aes128Gcm12Encrypter`, sets the key, encrypts using `EncryptWithNonce`, and then compares the resulting ciphertext and authentication tag with the expected values from the test vector using `quiche::test::CompareCharArraysWithHexError`.
    * **Nonce Handling:** The `EncryptWithNonce` helper function shows how the nonce is passed to the encrypter.
    * **AAD Handling:** The test explicitly checks how the encrypter handles an empty AAD (Associated Authenticated Data).

7. **Infer Functionality:** Based on the tests, the `Aes128Gcm12Encrypter` class clearly:
    * Implements AES-128 encryption using the GCM (Galois/Counter Mode) with a 12-byte nonce.
    * Takes a key, nonce, associated data, and plaintext as input.
    * Produces ciphertext and an authentication tag as output.
    * Has methods to determine the maximum plaintext size and ciphertext size.

8. **Consider JavaScript Relevance:**  Since this is C++ code within Chromium, its direct use in JavaScript is unlikely. However, QUIC is a transport protocol used by web browsers (including Chrome). Therefore, the encryption performed by this code is *indirectly* related to JavaScript applications running in the browser that communicate over QUIC. The browser's networking stack uses this C++ code to secure the communication.

9. **Develop Examples (Logic Inference):** Create simple scenarios based on the test vectors to illustrate the input and output of the encryption process. Focus on a single test vector for clarity.

10. **Identify Potential User Errors:** Think about how a developer might misuse this encrypter. Common mistakes include:
    * Incorrect key size.
    * Incorrect nonce size or reuse.
    * Mismatch between the expected and actual authentication tag.
    * Incorrect handling of AAD.

11. **Trace User Operations (Debugging Context):** Consider how a user action in a browser could lead to this code being executed. A typical scenario is a secure web request (HTTPS) over QUIC. Trace the steps from the user initiating the request to the point where encryption is needed.

12. **Refine and Organize:** Structure the findings logically, starting with the core functionality, then addressing JavaScript relevance, logic inference, user errors, and debugging context. Use clear and concise language. Ensure all parts of the original request are addressed. For instance, explicitly mentioning the use of test vectors and the comparison logic is crucial.

By following this thought process, dissecting the code, and understanding the context within Chromium and the QUIC protocol, a comprehensive explanation like the example provided can be generated.
这个文件 `aes_128_gcm_12_encrypter_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，它专门用于测试 `Aes128Gcm12Encrypter` 类的功能。 `Aes128Gcm12Encrypter` 类负责使用 AES-128 算法在 Galois/Counter Mode (GCM) 下进行加密，并使用 12 字节的初始化向量 (IV) 或 nonce。

以下是该文件的主要功能：

1. **单元测试 `Aes128Gcm12Encrypter` 类:**  该文件通过编写一系列测试用例来验证 `Aes128Gcm12Encrypter` 类的加密功能是否正确。

2. **使用 NIST 提供的测试向量:**  测试用例使用了从美国国家标准与技术研究院 (NIST) 下载的测试向量（`gcmEncryptExtIV128.rsp` 文件）。这些测试向量包含了预先计算好的密钥、IV、明文、附加认证数据 (AAD)、密文和认证标签，用于验证加密结果的正确性。

3. **覆盖多种测试场景:**  测试用例覆盖了不同的密钥长度、IV 长度、明文长度、AAD 长度和标签长度的组合，以确保加密器在各种情况下都能正常工作。

4. **测试加密操作:**  `Encrypt` 测试用例读取测试向量中的数据，使用 `Aes128Gcm12Encrypter` 类进行加密，并将生成的密文和认证标签与测试向量中的预期值进行比较。

5. **测试辅助方法:**  `GetMaxPlaintextSize` 和 `GetCiphertextSize` 测试用例分别验证了获取最大明文长度和密文长度的方法是否正确。

**与 JavaScript 的功能关系：**

该 C++ 代码本身并不直接在 JavaScript 中运行。然而，QUIC 是一种网络传输协议，被现代浏览器（如 Chrome）广泛使用。当 JavaScript 代码在浏览器中发起 HTTPS 请求，并且浏览器选择使用 QUIC 协议时，底层的网络栈就会使用类似 `Aes128Gcm12Encrypter` 这样的 C++ 类来加密传输的数据。

**举例说明：**

假设你在一个网页上使用 JavaScript 发起一个 `fetch` 请求到 `https://example.com`：

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

当浏览器建立与 `example.com` 的 QUIC 连接后，所有通过该连接发送和接收的数据都需要进行加密。 `Aes128Gcm12Encrypter` (或者类似的加密器) 会在浏览器底层的网络栈中被调用，对请求头、请求体、响应头和响应体进行加密。

**逻辑推理与假设输入输出：**

假设我们使用 `test_group_0` 中的第一个测试向量：

* **假设输入:**
    * `Key`: "11754cd72aec309bf52f7687212e8957" (十六进制字符串)
    * `IV`: "3c819d9a9bed087615030b65" (十六进制字符串)
    * `PT` (明文): "" (空字符串)
    * `AAD` (附加认证数据): "" (空字符串)

* **加密过程:**
    1. 将十六进制字符串的 Key 和 IV 转换为字节数组。
    2. 创建 `Aes128Gcm12Encrypter` 实例并设置 Key。
    3. 调用加密方法，传入 IV、AAD 和明文。

* **预期输出:**
    * `CT` (密文): "" (空字符串)
    * `Tag`: "250327c674aaf477aef2675748cf6971" (十六进制字符串，前 12 字节)

测试代码会执行加密操作，并将生成的密文和标签与预期输出进行比较，以验证加密器的正确性。

**用户或编程常见的使用错误：**

1. **密钥设置错误:**  忘记调用 `SetKey` 方法设置密钥，或者设置了错误的密钥长度。`Aes128Gcm12Encrypter` 期望 16 字节的密钥。

   ```c++
   Aes128Gcm12Encrypter encrypter;
   // 错误：忘记设置密钥
   // std::string key = ...;
   // ASSERT_TRUE(encrypter.SetKey(key));
   std::string iv_str = "3c819d9a9bed087615030b65";
   std::string plaintext = "some data";
   std::string iv;
   absl::HexStringToBytes(iv_str, &iv);
   std::unique_ptr<QuicData> encrypted = EncryptWithNonce(
       &encrypter, iv, absl::string_view(), plaintext); // 可能导致加密失败或异常
   ```

2. **Nonce (IV) 重复使用:** 在相同的密钥下，对不同的明文使用相同的 nonce 会严重破坏 GCM 模式的安全性。

   ```c++
   Aes128Gcm12Encrypter encrypter;
   std::string key_str = "11754cd72aec309bf52f7687212e8957";
   std::string iv_str = "3c819d9a9bed087615030b65";
   std::string key, iv;
   absl::HexStringToBytes(key_str, &key);
   absl::HexStringToBytes(iv_str, &iv);
   ASSERT_TRUE(encrypter.SetKey(key));

   std::unique_ptr<QuicData> encrypted1 = EncryptWithNonce(
       &encrypter, iv, absl::string_view(), "message1");
   std::unique_ptr<QuicData> encrypted2 = EncryptWithNonce(
       &encrypter, iv, absl::string_view(), "message2"); // 错误：重复使用 nonce
   ```

3. **附加认证数据 (AAD) 处理不一致:** 加密和解密时使用的 AAD 必须完全相同。如果 AAD 不一致，解密将失败。

   ```c++
   Aes128Gcm12Encrypter encrypter;
   // ... 设置 key 和 nonce ...
   std::string aad_encrypt = "associated data";
   std::string aad_decrypt = "different data"; // 错误：AAD 不一致
   std::unique_ptr<QuicData> encrypted = EncryptWithNonce(
       &encrypter, iv, aad_encrypt, "plaintext");

   // 在解密端，使用不同的 AAD 将导致认证失败
   // ... 解密操作 ...
   ```

4. **密文长度计算错误:**  在使用加密结果前，没有正确获取密文的长度，可能导致数据截断或其他错误。

   ```c++
   Aes128Gcm12Encrypter encrypter;
   // ... 设置 key 和 nonce ...
   std::unique_ptr<QuicData> encrypted = EncryptWithNonce(
       &encrypter, iv, absl::string_view(), "plaintext");
   // 错误：假设了错误的密文长度
   // size_t expected_length = plaintext.length(); // 实际长度会更长，包含认证标签
   // std::string ciphertext(encrypted->data(), expected_length);
   ```

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中访问一个使用 HTTPS 协议的网站。**
2. **浏览器与服务器协商使用 QUIC 协议进行连接。**
3. **当需要发送或接收应用层数据时 (例如，请求网页资源或发送表单数据)，QUIC 协议栈会被激活。**
4. **QUIC 协议栈中的加密层负责对数据进行加密和解密。**
5. **对于需要 AES-128-GCM 加密的连接 (这是 QUIC 中常用的加密算法之一)，`Aes128Gcm12Encrypter` 类 (或其对应的解密器) 会被实例化。**
6. **在调试过程中，如果怀疑加密过程出现问题，开发者可能会查看 `net/third_party/quiche/src/quiche/quic/core/crypto/` 目录下的代码，包括 `aes_128_gcm_12_encrypter_test.cc`，以了解加密算法的实现细节和测试用例。**
7. **开发者可能会使用断点调试等工具，逐步跟踪 `Aes128Gcm12Encrypter` 类的加密过程，查看密钥、nonce、明文和密文的值，以找出问题所在。**

例如，如果用户在访问某个网站时遇到连接错误或者数据传输异常，网络工程师可能会检查浏览器底层的 QUIC 连接状态，查看加密协商是否成功，并检查加密和解密过程中是否有错误发生。这时，对 `Aes128Gcm12Encrypter` 的测试代码的理解就变得很有价值，因为它提供了验证该组件功能正确性的依据。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/crypto/aes_128_gcm_12_encrypter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "quiche/quic/core/crypto/aes_128_gcm_12_encrypter.h"

#include <memory>
#include <string>

#include "absl/base/macros.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
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
QuicData* EncryptWithNonce(Aes128Gcm12Encrypter* encrypter,
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

class Aes128Gcm12EncrypterTest : public QuicTest {};

TEST_F(Aes128Gcm12EncrypterTest, Encrypt) {
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

      Aes128Gcm12Encrypter encrypter;
      ASSERT_TRUE(encrypter.SetKey(key));
      std::unique_ptr<QuicData> encrypted(
          EncryptWithNonce(&encrypter, iv,
                           // This deliberately tests that the encrypter can
                           // handle an AAD that is set to nullptr, as opposed
                           // to a zero-length, non-nullptr pointer.
                           aad.length() ? aad : absl::string_view(), pt));
      ASSERT_TRUE(encrypted.get());

      // The test vectors have 16 byte authenticators but this code only uses
      // the first 12.
      ASSERT_LE(static_cast<size_t>(Aes128Gcm12Encrypter::kAuthTagSize),
                tag.length());
      tag.resize(Aes128Gcm12Encrypter::kAuthTagSize);

      ASSERT_EQ(ct.length() + tag.length(), encrypted->length());
      quiche::test::CompareCharArraysWithHexError(
          "ciphertext", encrypted->data(), ct.length(), ct.data(), ct.length());
      quiche::test::CompareCharArraysWithHexError(
          "authentication tag", encrypted->data() + ct.length(), tag.length(),
          tag.data(), tag.length());
    }
  }
}

TEST_F(Aes128Gcm12EncrypterTest, GetMaxPlaintextSize) {
  Aes128Gcm12Encrypter encrypter;
  EXPECT_EQ(1000u, encrypter.GetMaxPlaintextSize(1012));
  EXPECT_EQ(100u, encrypter.GetMaxPlaintextSize(112));
  EXPECT_EQ(10u, encrypter.GetMaxPlaintextSize(22));
  EXPECT_EQ(0u, encrypter.GetMaxPlaintextSize(11));
}

TEST_F(Aes128Gcm12EncrypterTest, GetCiphertextSize) {
  Aes128Gcm12Encrypter encrypter;
  EXPECT_EQ(1012u, encrypter.GetCiphertextSize(1000));
  EXPECT_EQ(112u, encrypter.GetCiphertextSize(100));
  EXPECT_EQ(22u, encrypter.GetCiphertextSize(10));
}

}  // namespace test
}  // namespace quic
```