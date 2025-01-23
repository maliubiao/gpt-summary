Response:
Let's break down the thought process for analyzing the provided C++ test file.

1. **Identify the Core Functionality:** The file name `aes_128_gcm_12_decrypter_test.cc` immediately tells us this is a test file for something related to AES-128-GCM-12 decryption. The `_test.cc` suffix is a common convention.

2. **Examine the Includes:** The included headers reveal dependencies and the context of the code:
    * `aes_128_gcm_12_decrypter.h`: This is the header for the class being tested. It confirms the focus on AES-128-GCM-12 decryption.
    * Standard library headers (`memory`, `string`): Basic C++ utilities.
    * `absl/base/macros.h`, `absl/strings/...`:  Indicates the use of the Abseil library, common in Chromium projects, for string manipulation and other utilities.
    * `quiche/quic/core/...`: Places this code within the QUIC implementation of Chromium's networking stack.
    * `quiche/quic/platform/api/quic_test.h`, `quiche/quic/test_tools/...`, `quiche/common/test_tools/...`: Confirms this is a unit test using QUIC-specific and general testing utilities.

3. **Analyze the Test Structure:**
    * **Namespaces:** The code is within anonymous and named namespaces (`quic::test`). This is standard practice to avoid naming collisions.
    * **Test Vectors:** The large block of `TestGroupInfo` and `TestVector` structs is a key indicator. These structures hold predefined inputs and expected outputs for various decryption scenarios. The comments explaining the source of these vectors (`gcmDecrypt128.rsp` from NIST) are valuable for understanding their purpose.
    * **`DecryptWithNonce` Function:** This helper function suggests a specific way the `Aes128Gcm12Decrypter` class is used, involving a nonce (IV) and potentially packet numbers.
    * **`Aes128Gcm12DecrypterTest` Class:** This is the main test fixture, inheriting from `QuicTest`, a base class for QUIC unit tests.
    * **`TEST_F` Macro:** This macro defines the actual test case (`Decrypt`). The loop structures within this test are designed to iterate through the test vectors.

4. **Understand the Test Logic:**
    * The outer loop iterates through different test groups, each with specific key/IV/data lengths.
    * The inner loop iterates through individual test vectors within each group.
    * For each test vector:
        * The hexadecimal input strings (key, IV, ciphertext, AAD, tag) are converted to byte arrays.
        * An `Aes128Gcm12Decrypter` object is created.
        * The key is set using `SetKey`.
        * The `DecryptWithNonce` function is called.
        * The result of the decryption is checked against the expected outcome (success/failure and the expected plaintext). `CompareCharArraysWithHexError` is used for detailed comparison.
        * The `has_pt` flag controls whether a successful decryption is expected.

5. **Identify Key Concepts and Functionality:** From the analysis, we can pinpoint the core purpose: verifying the correctness of the `Aes128Gcm12Decrypter` class by decrypting various ciphertexts using known keys, initialization vectors (IVs/nonces), associated authenticated data (AAD), and tags. The test vectors cover different lengths and scenarios, including cases where decryption should fail.

6. **Consider JavaScript Relevance:**  Think about where cryptographic operations like AES-GCM are used in a web context. The most likely connection is with secure communication protocols like TLS (used in HTTPS) and potentially Web Crypto API.

7. **Hypothesize Inputs and Outputs:** Select a specific test vector and trace the expected flow:
    * **Input:** Key (hex string), IV (hex string), ciphertext (hex string including tag), AAD (hex string).
    * **Process:**  The `Aes128Gcm12Decrypter` uses the key and IV to perform the decryption. It verifies the tag using the key and AAD.
    * **Output:** Either the decrypted plaintext (as a byte array) or an indication of failure.

8. **Think about User/Programming Errors:** Common mistakes in using cryptographic APIs often involve:
    * Incorrect key length or format.
    * Reusing nonces with the same key.
    * Incorrect handling of AAD.
    * Not verifying the authentication tag.

9. **Consider Debugging Context:**  Imagine a scenario where decryption is failing in a real application. The test file provides insights into how to construct test cases for debugging. You would need to gather the key, IV, ciphertext, and AAD involved in the failing case.

10. **Structure the Answer:** Organize the findings into logical sections based on the prompt's questions: functionality, JavaScript relevance, input/output examples, common errors, and debugging context. Use clear and concise language. Provide specific examples where possible.

This detailed thought process allows for a comprehensive understanding of the test file and its implications. It moves beyond a superficial reading to extract the key information and connect it to broader concepts.
这个文件 `aes_128_gcm_12_decrypter_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，专门用于测试 `Aes128Gcm12Decrypter` 类的功能。 `Aes128Gcm12Decrypter` 类负责使用 AES-128-GCM 算法进行数据包的解密，其中 GCM (Galois/Counter Mode) 是一种认证加密算法，可以提供数据的机密性、完整性和身份验证。这里的 "12" 指的是认证标签 (Authentication Tag) 的长度为 12 字节（96 bits）。

**主要功能：**

1. **单元测试 `Aes128Gcm12Decrypter` 类:**  该文件包含了多个测试用例，用于验证 `Aes128Gcm12Decrypter` 类的 `DecryptPacket` 方法在各种情况下的正确性。
2. **使用 NIST 提供的测试向量:** 代码中包含大量的测试向量（来自 NIST 的 gcmDecrypt128.rsp 文件），这些向量包含了不同的密钥 (Key)、初始化向量 (IV)、密文 (CT)、附加认证数据 (AAD)、认证标签 (Tag) 以及对应的明文 (PT)。这些测试向量用于覆盖不同的加密场景，确保解密器的健壮性。
3. **覆盖成功和失败的解密场景:**  测试用例不仅包含了解密成功的场景，还包含了预期解密失败的场景（通过在 `TestVector` 结构体中使用 `nullptr` 来标记）。这有助于验证解密器能够正确处理无效的密文或认证标签。
4. **测试带有关联数据的解密:** GCM 算法允许使用附加认证数据 (AAD)，该数据不会被加密，但会被用于生成认证标签，以验证数据的完整性。测试用例覆盖了使用 AAD 的解密场景。
5. **测试不同的数据长度:**  测试向量涵盖了不同长度的明文、密文和 AAD，以确保解密器能够处理各种数据大小。
6. **使用 Nonce (IV) 进行解密:** 测试代码展示了如何设置 Nonce 前缀以及如何将数据包编号合并到 Nonce 中进行解密。这反映了 QUIC 协议中对数据包进行加密和解密的方式。

**与 JavaScript 功能的关系：**

虽然这段 C++ 代码本身不直接在 JavaScript 中运行，但它所测试的加密算法 AES-128-GCM 及其在安全通信协议中的应用与 JavaScript 有密切关系，主要体现在以下几个方面：

1. **Web Crypto API:**  现代浏览器提供了 Web Crypto API，允许 JavaScript 代码执行加密和解密操作，包括 AES-GCM 算法。例如，可以使用 `crypto.subtle.decrypt` 方法进行 AES-GCM 解密。

   **JavaScript 示例：**

   ```javascript
   async function decryptData(keyData, ivData, aadData, ciphertextData, tagData) {
     try {
       const key = await crypto.subtle.importKey(
         "raw",
         keyData,
         { name: "AES-GCM", length: 128 },
         false,
         ["decrypt"]
       );

       const plaintextBuffer = await crypto.subtle.decrypt(
         {
           name: "AES-GCM",
           iv: ivData,
           additionalData: aadData,
           tagLength: 128 // 注意这里 tagLength 单位是 bits
         },
         key,
         ciphertextData
       );
       return new Uint8Array(plaintextBuffer);
     } catch (error) {
       console.error("解密失败:", error);
       return null;
     }
   }

   // 假设从服务器接收到加密数据和相关参数（通常以 ArrayBuffer 或 Uint8Array 形式存在）
   const keyHex = "cf063a34d4a9a76c2c86787d3f96db71";
   const ivHex = "113b9785971864c83b01c787";
   const aadHex = "";
   const ciphertextHex = "72ac8493e3a5228b5d130a69d2510e42"; // 这里包含了密文和 tag，因为 PT 为空
   // ... 将 Hex 字符串转换为 Uint8Array ...
   const keyData = hexToUint8Array(keyHex);
   const ivData = hexToUint8Array(ivHex);
   const aadData = hexToUint8Array(aadHex);
   const ciphertextData = hexToUint8Array(ciphertextHex);

   decryptData(keyData, ivData, aadData, ciphertextData.subarray(0, ciphertextData.length - 16), ciphertextData.subarray(ciphertextData.length - 16))
     .then(plaintext => {
       if (plaintext) {
         console.log("解密成功:", new TextDecoder().decode(plaintext));
       }
     });

   function hexToUint8Array(hexString) {
     const byteLength = hexString.length / 2;
     const byteArray = new Uint8Array(byteLength);
     for (let i = 0; i < byteLength; i++) {
       const hexByte = hexString.substring(i * 2, i * 2 + 2);
       byteArray[i] = parseInt(hexByte, 16);
     }
     return byteArray;
   }
   ```

2. **QUIC 协议在浏览器中的实现:**  QUIC 协议旨在提供更快速、更可靠的网络连接，它在传输层使用了类似于 AES-GCM 的加密机制来保护数据。浏览器在与支持 QUIC 的服务器通信时，底层的加密和解密操作可能涉及到类似的算法。

3. **TLS 1.3 及更早版本中的加密套件:**  虽然 QUIC 协议有自己的加密机制，但在 TLS 1.3 及更早版本中，浏览器与服务器协商的加密套件中可能包含使用 AES-128-GCM 的选项。JavaScript 通过 HTTPS 进行网络请求时，浏览器会自动处理底层的 TLS 加密和解密。

**逻辑推理的假设输入与输出：**

**假设输入：**

* **Key (16 字节):** `cf063a34d4a9a76c2c86787d3f96db71` (十六进制字符串)
* **IV (12 字节):** `113b9785971864c83b01c787` (十六进制字符串)
* **Ciphertext (0 字节):** `""` (空字符串，意味着原始明文长度为 0)
* **AAD (0 字节):** `""` (空字符串)
* **Tag (16 字节):** `72ac8493e3a5228b5d130a69d2510e42` (十六进制字符串)

**预期输出：**

* 解密成功，明文为空 (长度为 0)。

**假设输入（解密失败场景）：**

* **Key (16 字节):** `a49a5e26a2f8cb63d05546c2a62f5343`
* **IV (12 字节):** `907763b19b9b4ab6bd4f0281`
* **Ciphertext (0 字节):** `""`
* **AAD (0 字节):** `""`
* **Tag (16 字节):** `a2be08210d8c470a8df6e8fbd79ec5cf`

**预期输出：**

* 解密失败（因为测试向量中标记为 `FAIL`），返回错误或指示解密失败的信号。

**用户或编程常见的使用错误：**

1. **密钥错误:** 使用了错误的密钥进行解密。AES 是对称加密算法，加密和解密使用相同的密钥。如果密钥不匹配，解密将失败。

   **示例：** 使用了与加密时不同的密钥进行解密。

2. **初始化向量 (IV) 重用:** 对于相同的密钥，重复使用相同的 IV 会危及加密的安全性，可能导致信息泄露。GCM 模式对 IV 的唯一性要求很高。

   **示例：** 在加密多个数据包时，使用了相同的密钥和 IV。

3. **认证标签 (Tag) 验证失败:** 解密器会验证接收到的认证标签是否与使用密钥和相关数据计算出的标签一致。如果标签被篡改或数据传输过程中发生错误，验证将失败，解密器应报告错误。

   **示例：** 接收到的数据包在传输过程中被修改，导致认证标签不再有效。

4. **附加认证数据 (AAD) 不匹配:** 加密和解密时使用的 AAD 必须完全一致。如果 AAD 不匹配，认证标签的验证将失败。

   **示例：** 加密时使用了 AAD "context1"，而解密时使用了 "context2"。

5. **Nonce 前缀设置错误:**  在 QUIC 中，Nonce 通常由一个固定前缀和包编号组成。如果 Nonce 前缀设置错误，会导致 Nonce 不正确，解密失败。

   **示例：**  调用 `SetNoncePrefix` 时传入了错误的字节序列。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在使用 Chrome 浏览器访问一个使用 QUIC 协议的网站，并且在网络交互过程中遇到了解密错误，导致页面加载失败或部分内容无法正常显示。以下是可能的步骤：

1. **用户发起网络请求:** 用户在浏览器地址栏输入 URL，或点击页面上的链接，发起对服务器的网络请求。
2. **浏览器与服务器建立 QUIC 连接:** 如果服务器支持 QUIC 协议，并且浏览器也启用了 QUIC，浏览器会尝试与服务器建立 QUIC 连接。
3. **数据包的加密传输:**  在 QUIC 连接建立后，浏览器和服务器之间的数据（例如 HTTP/3 数据帧）会被加密并通过 UDP 数据包传输。发送方会使用 `Aes128Gcm12Encrypter` 进行加密，接收方使用 `Aes128Gcm12Decrypter` 进行解密。
4. **接收到加密的数据包:** 浏览器接收到来自服务器的加密数据包。
5. **调用 `Aes128Gcm12Decrypter::DecryptPacket`:**  QUIC 的接收处理逻辑会调用 `Aes128Gcm12Decrypter` 类的 `DecryptPacket` 方法尝试解密接收到的数据包。此时，会传入从数据包中提取的 Nonce、密钥、密文和 AAD。
6. **解密失败:** 如果由于密钥不匹配、Nonce 重用、AAD 不一致或认证标签验证失败等原因，`DecryptPacket` 方法返回失败。
7. **错误处理和调试:**  QUIC 协议栈的更高层会捕获到解密错误，并可能触发错误处理逻辑。

**调试线索：**

* **网络抓包 (如 Wireshark):** 可以捕获到浏览器和服务器之间的 QUIC 数据包，检查加密数据包的内容，包括可能的 Nonce 和密文。
* **Chrome NetLog:** Chrome 浏览器提供了 `chrome://net-export/` 功能，可以记录详细的网络事件，包括 QUIC 连接的建立、数据包的发送和接收，以及加密和解密操作的日志。检查 NetLog 可以看到解密操作是否失败，以及可能的错误原因。
* **QUIC 协议栈的日志:**  在 Chromium 的开发版本或带有调试符号的版本中，可以查看 QUIC 协议栈的内部日志，了解 `Aes128Gcm12Decrypter` 在解密过程中遇到的具体问题。
* **对比测试向量:**  如果怀疑是解密逻辑本身的问题，可以尝试使用代码中提供的测试向量来重现问题，或者编写新的测试用例来验证特定的解密场景。

总而言之，`aes_128_gcm_12_decrypter_test.cc` 文件对于确保 Chromium QUIC 协议中数据包解密的正确性和安全性至关重要。它通过大量的测试用例覆盖了各种场景，帮助开发者验证和调试解密器的实现。虽然 C++ 代码不直接在 JavaScript 中运行，但其测试的加密算法在 Web 领域的安全通信中扮演着关键角色。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/crypto/aes_128_gcm_12_decrypter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "quiche/quic/core/crypto/aes_128_gcm_12_decrypter.h"

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

// The AES GCM test vectors come from the file gcmDecrypt128.rsp
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
// Key = cf063a34d4a9a76c2c86787d3f96db71
// IV = 113b9785971864c83b01c787
// CT =
// AAD =
// Tag = 72ac8493e3a5228b5d130a69d2510e42
// PT =
//
// Count = 1
// Key = a49a5e26a2f8cb63d05546c2a62f5343
// IV = 907763b19b9b4ab6bd4f0281
// CT =
// AAD =
// Tag = a2be08210d8c470a8df6e8fbd79ec5cf
// FAIL
//
// ...
//
// The gcmDecrypt128.rsp file is huge (2.6 MB), so I selected just a
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
  // Input:
  const char* key;
  const char* iv;
  const char* ct;
  const char* aad;
  const char* tag;

  // Expected output:
  const char* pt;  // An empty string "" means decryption succeeded and
                   // the plaintext is zero-length. nullptr means decryption
                   // failed.
};

const TestGroupInfo test_group_info[] = {
    {128, 96, 0, 0, 128},     {128, 96, 0, 128, 128},   {128, 96, 128, 0, 128},
    {128, 96, 408, 160, 128}, {128, 96, 408, 720, 128}, {128, 96, 104, 0, 128},
};

const TestVector test_group_0[] = {
    {"cf063a34d4a9a76c2c86787d3f96db71", "113b9785971864c83b01c787", "", "",
     "72ac8493e3a5228b5d130a69d2510e42", ""},
    {
        "a49a5e26a2f8cb63d05546c2a62f5343", "907763b19b9b4ab6bd4f0281", "", "",
        "a2be08210d8c470a8df6e8fbd79ec5cf",
        nullptr  // FAIL
    },
    {nullptr, nullptr, nullptr, nullptr, nullptr, nullptr}};

const TestVector test_group_1[] = {
    {
        "d1f6af919cde85661208bdce0c27cb22", "898c6929b435017bf031c3c5", "",
        "7c5faa40e636bbc91107e68010c92b9f", "ae45f11777540a2caeb128be8092468a",
        nullptr  // FAIL
    },
    {"2370e320d4344208e0ff5683f243b213", "04dbb82f044d30831c441228", "",
     "d43a8e5089eea0d026c03a85178b27da", "2a049c049d25aa95969b451d93c31c6e",
     ""},
    {nullptr, nullptr, nullptr, nullptr, nullptr, nullptr}};

const TestVector test_group_2[] = {
    {"e98b72a9881a84ca6b76e0f43e68647a", "8b23299fde174053f3d652ba",
     "5a3c1cf1985dbb8bed818036fdd5ab42", "", "23c7ab0f952b7091cd324835043b5eb5",
     "28286a321293253c3e0aa2704a278032"},
    {"33240636cd3236165f1a553b773e728e", "17c4d61493ecdc8f31700b12",
     "47bb7e23f7bdfe05a8091ac90e4f8b2e", "", "b723c70e931d9785f40fd4ab1d612dc9",
     "95695a5b12f2870b9cc5fdc8f218a97d"},
    {
        "5164df856f1e9cac04a79b808dc5be39", "e76925d5355e0584ce871b2b",
        "0216c899c88d6e32c958c7e553daa5bc", "",
        "a145319896329c96df291f64efbe0e3a",
        nullptr  // FAIL
    },
    {nullptr, nullptr, nullptr, nullptr, nullptr, nullptr}};

const TestVector test_group_3[] = {
    {"af57f42c60c0fc5a09adb81ab86ca1c3", "a2dc01871f37025dc0fc9a79",
     "b9a535864f48ea7b6b1367914978f9bfa087d854bb0e269bed8d279d2eea1210e48947"
     "338b22f9bad09093276a331e9c79c7f4",
     "41dc38988945fcb44faf2ef72d0061289ef8efd8",
     "4f71e72bde0018f555c5adcce062e005",
     "3803a0727eeb0ade441e0ec107161ded2d425ec0d102f21f51bf2cf9947c7ec4aa7279"
     "5b2f69b041596e8817d0a3c16f8fadeb"},
    {"ebc753e5422b377d3cb64b58ffa41b61", "2e1821efaced9acf1f241c9b",
     "069567190554e9ab2b50a4e1fbf9c147340a5025fdbd201929834eaf6532325899ccb9"
     "f401823e04b05817243d2142a3589878",
     "b9673412fd4f88ba0e920f46dd6438ff791d8eef",
     "534d9234d2351cf30e565de47baece0b",
     "39077edb35e9c5a4b1e4c2a6b9bb1fce77f00f5023af40333d6d699014c2bcf4209c18"
     "353a18017f5b36bfc00b1f6dcb7ed485"},
    {
        "52bdbbf9cf477f187ec010589cb39d58", "d3be36d3393134951d324b31",
        "700188da144fa692cf46e4a8499510a53d90903c967f7f13e8a1bd8151a74adc4fe63e"
        "32b992760b3a5f99e9a47838867000a9",
        "93c4fc6a4135f54d640b0c976bf755a06a292c33",
        "8ca4e38aa3dfa6b1d0297021ccf3ea5f",
        nullptr  // FAIL
    },
    {nullptr, nullptr, nullptr, nullptr, nullptr, nullptr}};

const TestVector test_group_4[] = {
    {"da2bb7d581493d692380c77105590201", "44aa3e7856ca279d2eb020c6",
     "9290d430c9e89c37f0446dbd620c9a6b34b1274aeb6f911f75867efcf95b6feda69f1a"
     "f4ee16c761b3c9aeac3da03aa9889c88",
     "4cd171b23bddb3a53cdf959d5c1710b481eb3785a90eb20a2345ee00d0bb7868c367ab"
     "12e6f4dd1dee72af4eee1d197777d1d6499cc541f34edbf45cda6ef90b3c024f9272d7"
     "2ec1909fb8fba7db88a4d6f7d3d925980f9f9f72",
     "9e3ac938d3eb0cadd6f5c9e35d22ba38",
     "9bbf4c1a2742f6ac80cb4e8a052e4a8f4f07c43602361355b717381edf9fabd4cb7e3a"
     "d65dbd1378b196ac270588dd0621f642"},
    {"d74e4958717a9d5c0e235b76a926cae8", "0b7471141e0c70b1995fd7b1",
     "e701c57d2330bf066f9ff8cf3ca4343cafe4894651cd199bdaaa681ba486b4a65c5a22"
     "b0f1420be29ea547d42c713bc6af66aa",
     "4a42b7aae8c245c6f1598a395316e4b8484dbd6e64648d5e302021b1d3fa0a38f46e22"
     "bd9c8080b863dc0016482538a8562a4bd0ba84edbe2697c76fd039527ac179ec5506cf"
     "34a6039312774cedebf4961f3978b14a26509f96",
     "e192c23cb036f0b31592989119eed55d",
     "840d9fb95e32559fb3602e48590280a172ca36d9b49ab69510f5bd552bfab7a306f85f"
     "f0a34bc305b88b804c60b90add594a17"},
    {
        "1986310c725ac94ecfe6422e75fc3ee7", "93ec4214fa8e6dc4e3afc775",
        "b178ec72f85a311ac4168f42a4b2c23113fbea4b85f4b9dabb74e143eb1b8b0a361e02"
        "43edfd365b90d5b325950df0ada058f9",
        "e80b88e62c49c958b5e0b8b54f532d9ff6aa84c8a40132e93e55b59fc24e8decf28463"
        "139f155d1e8ce4ee76aaeefcd245baa0fc519f83a5fb9ad9aa40c4b21126013f576c42"
        "72c2cb136c8fd091cc4539877a5d1e72d607f960",
        "8b347853f11d75e81e8a95010be81f17",
        nullptr  // FAIL
    },
    {nullptr, nullptr, nullptr, nullptr, nullptr, nullptr}};

const TestVector test_group_5[] = {
    {"387218b246c1a8257748b56980e50c94", "dd7e014198672be39f95b69d",
     "cdba9e73eaf3d38eceb2b04a8d", "", "ecf90f4a47c9c626d6fb2c765d201556",
     "48f5b426baca03064554cc2b30"},
    {"294de463721e359863887c820524b3d4", "3338b35c9d57a5d28190e8c9",
     "2f46634e74b8e4c89812ac83b9", "", "dabd506764e68b82a7e720aa18da0abe",
     "46a2e55c8e264df211bd112685"},
    {"28ead7fd2179e0d12aa6d5d88c58c2dc", "5055347f18b4d5add0ae5c41",
     "142d8210c3fb84774cdbd0447a", "", "5fd321d9cdb01952dc85f034736c2a7d",
     "3b95b981086ee73cc4d0cc1422"},
    {
        "7d7b6c988137b8d470c57bf674a09c87", "9edf2aa970d016ac962e1fd8",
        "a85b66c3cb5eab91d5bdc8bc0e", "", "dc054efc01f3afd21d9c2484819f569a",
        nullptr  // FAIL
    },
    {nullptr, nullptr, nullptr, nullptr, nullptr, nullptr}};

const TestVector* const test_group_array[] = {
    test_group_0, test_group_1, test_group_2,
    test_group_3, test_group_4, test_group_5,
};

}  // namespace

namespace quic {
namespace test {

// DecryptWithNonce wraps the |Decrypt| method of |decrypter| to allow passing
// in an nonce and also to allocate the buffer needed for the plaintext.
QuicData* DecryptWithNonce(Aes128Gcm12Decrypter* decrypter,
                           absl::string_view nonce,
                           absl::string_view associated_data,
                           absl::string_view ciphertext) {
  uint64_t packet_number;
  absl::string_view nonce_prefix(nonce.data(),
                                 nonce.size() - sizeof(packet_number));
  decrypter->SetNoncePrefix(nonce_prefix);
  memcpy(&packet_number, nonce.data() + nonce_prefix.size(),
         sizeof(packet_number));
  std::unique_ptr<char[]> output(new char[ciphertext.length()]);
  size_t output_length = 0;
  const bool success = decrypter->DecryptPacket(
      packet_number, associated_data, ciphertext, output.get(), &output_length,
      ciphertext.length());
  if (!success) {
    return nullptr;
  }
  return new QuicData(output.release(), output_length, true);
}

class Aes128Gcm12DecrypterTest : public QuicTest {};

TEST_F(Aes128Gcm12DecrypterTest, Decrypt) {
  for (size_t i = 0; i < ABSL_ARRAYSIZE(test_group_array); i++) {
    SCOPED_TRACE(i);
    const TestVector* test_vectors = test_group_array[i];
    const TestGroupInfo& test_info = test_group_info[i];
    for (size_t j = 0; test_vectors[j].key != nullptr; j++) {
      // If not present then decryption is expected to fail.
      bool has_pt = test_vectors[j].pt;

      // Decode the test vector.
      std::string key;
      std::string iv;
      std::string ct;
      std::string aad;
      std::string tag;
      std::string pt;
      ASSERT_TRUE(absl::HexStringToBytes(test_vectors[j].key, &key));
      ASSERT_TRUE(absl::HexStringToBytes(test_vectors[j].iv, &iv));
      ASSERT_TRUE(absl::HexStringToBytes(test_vectors[j].ct, &ct));
      ASSERT_TRUE(absl::HexStringToBytes(test_vectors[j].aad, &aad));
      ASSERT_TRUE(absl::HexStringToBytes(test_vectors[j].tag, &tag));
      if (has_pt) {
        ASSERT_TRUE(absl::HexStringToBytes(test_vectors[j].pt, &pt));
      }

      // The test vector's lengths should look sane. Note that the lengths
      // in |test_info| are in bits.
      EXPECT_EQ(test_info.key_len, key.length() * 8);
      EXPECT_EQ(test_info.iv_len, iv.length() * 8);
      EXPECT_EQ(test_info.pt_len, ct.length() * 8);
      EXPECT_EQ(test_info.aad_len, aad.length() * 8);
      EXPECT_EQ(test_info.tag_len, tag.length() * 8);
      if (has_pt) {
        EXPECT_EQ(test_info.pt_len, pt.length() * 8);
      }

      // The test vectors have 16 byte authenticators but this code only uses
      // the first 12.
      ASSERT_LE(static_cast<size_t>(Aes128Gcm12Decrypter::kAuthTagSize),
                tag.length());
      tag.resize(Aes128Gcm12Decrypter::kAuthTagSize);
      std::string ciphertext = ct + tag;

      Aes128Gcm12Decrypter decrypter;
      ASSERT_TRUE(decrypter.SetKey(key));

      std::unique_ptr<QuicData> decrypted(DecryptWithNonce(
          &decrypter, iv,
          // This deliberately tests that the decrypter can
          // handle an AAD that is set to nullptr, as opposed
          // to a zero-length, non-nullptr pointer.
          aad.length() ? aad : absl::string_view(), ciphertext));
      if (!decrypted) {
        EXPECT_FALSE(has_pt);
        continue;
      }
      EXPECT_TRUE(has_pt);

      ASSERT_EQ(pt.length(), decrypted->length());
      quiche::test::CompareCharArraysWithHexError(
          "plaintext", decrypted->data(), pt.length(), pt.data(), pt.length());
    }
  }
}

}  // namespace test
}  // namespace quic
```