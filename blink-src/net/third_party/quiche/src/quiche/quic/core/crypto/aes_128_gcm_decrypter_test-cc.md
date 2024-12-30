Response:
Let's break down the thought process for analyzing the C++ test file.

**1. Understanding the Goal:**

The primary goal is to understand the *purpose* of the provided C++ test file and how it relates to broader web development concepts, especially JavaScript. The request also asks for specific examples related to logic, common errors, and debugging.

**2. Initial Code Scan and Keywords:**

I first scanned the code for obvious keywords and patterns:

* `#include`:  Indicates dependencies on other code. `aes_128_gcm_decrypter.h` is the most important one, suggesting this test file is for the `Aes128GcmDecrypter` class.
* `namespace quic::test`:  Clearly marks this as a test within the QUIC networking library.
* `TEST_F`:  A Google Test macro, confirming this is a unit test file.
* `Decrypt`, `DecryptWithNonce`, `GenerateHeaderProtectionMask`: These are the main functions being tested.
* `TestGroupInfo`, `TestVector`:  These structs define test case data structures, hinting at how the tests are organized.
* Hexadecimal string conversions (`absl::HexStringToBytes`): Suggests the test cases use hex-encoded cryptographic data.
* "GCM", "AES-128": These are cryptographic terms related to encryption and authentication.
* `FAIL`: A comment within the test data indicating expected decryption failures.
* `Copyright`, `BSD-style license`: Standard boilerplate for open-source code.

**3. Identifying Core Functionality:**

Based on the keywords and included header, I deduced the core functionality:

* **Testing AES-128-GCM Decryption:** The file tests the `Aes128GcmDecrypter` class, specifically its ability to decrypt data encrypted using the AES-128-GCM algorithm. The presence of test vectors confirms this.
* **Header Protection Mask Generation:** The `GenerateHeaderProtectionMask` test indicates an additional function related to QUIC's header protection mechanism.

**4. Analyzing Test Structure:**

I examined the `TestGroupInfo` and `TestVector` structures and the way the tests are organized:

* **Test Vectors:** The `TestVector` structure holds input data (key, IV, ciphertext, AAD, tag) and the expected output (plaintext or `nullptr` for failure).
* **Test Groups:**  `TestGroupInfo` describes common characteristics of a set of test vectors (key length, IV length, etc.). The `test_group_array` holds arrays of `TestVector`s, grouped by these characteristics.
* **Looping and Validation:** The `Decrypt` test uses nested loops to iterate through the test groups and individual test vectors. It asserts that decryption succeeds or fails as expected and compares the decrypted plaintext with the expected plaintext.

**5. Connecting to JavaScript (If Applicable):**

This is where the thinking requires bridging the gap between low-level C++ networking and higher-level JavaScript. I considered:

* **Browser Context:** QUIC is heavily used in web browsers. The encryption and decryption happening here are fundamental to secure web communication (HTTPS).
* **JavaScript APIs:**  JavaScript has cryptographic APIs (like `crypto.subtle`) that can perform similar encryption and decryption tasks.
* **Conceptual Link:**  Even if the C++ code isn't *directly* called by JavaScript, the underlying principles of AES-GCM are the same. A JavaScript developer might use similar concepts when implementing secure communication or data storage.

**6. Generating Examples (Logic, Errors, Debugging):**

With a good understanding of the code, I could create concrete examples:

* **Logic:**  I chose a successful decryption case and a failure case from the test data, explaining the inputs and expected outputs. This directly demonstrates the function's core logic.
* **Common Errors:** I thought about typical mistakes when dealing with cryptography: incorrect keys, IVs, or tags. I provided scenarios and their likely outcomes.
* **Debugging:** I considered how a developer would end up in this code: investigating decryption issues, security vulnerabilities, or performance problems related to QUIC. Tracing the network stack and examining decryption failures were logical steps.

**7. Refining and Structuring the Output:**

Finally, I organized the information into the requested sections: functionality, JavaScript relation, logic examples, error examples, and debugging. I tried to be clear and concise, using the information gleaned from the code analysis.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this file tests some internal utility functions.
* **Correction:** The presence of "Decrypter" in the class name and the use of standard cryptographic terms strongly points to testing the core decryption functionality.
* **Initial thought:**  The JavaScript connection might be weak.
* **Refinement:**  Focus on the conceptual link and the fact that the underlying cryptography is the same, even if the implementation differs. Highlight the browser context.
* **Initial thought:**  Just list the test function names.
* **Refinement:**  Explain *what* each test function does and *how* it verifies the functionality. Describe the role of test vectors.

By following these steps, I could thoroughly analyze the C++ code and provide a comprehensive answer that addresses all aspects of the request.
这个文件 `aes_128_gcm_decrypter_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，它的主要功能是 **测试 `Aes128GcmDecrypter` 类的解密功能**。 `Aes128GcmDecrypter` 类负责使用 AES-128 算法在 GCM 模式下解密数据。

更具体地说，这个测试文件做了以下事情：

1. **定义了一系列测试用例 (Test Vectors):** 这些测试用例来源于 NIST 提供的 AES-GCM 标准测试向量。每个测试用例包含：
    * **密钥 (Key):** 用于解密的密钥。
    * **初始向量 (IV):**  用于保证相同密钥加密不同数据产生不同密文的随机数。
    * **密文 (CT):** 需要解密的数据。
    * **附加认证数据 (AAD):**  在加密时绑定到密文上的额外数据，用于验证数据的完整性，但不加密。
    * **认证标签 (Tag):**  由 GCM 模式生成的用于验证数据完整性的标签。
    * **明文 (PT):**  期望解密得到的原始数据。如果为 `nullptr`，则表示解密应该失败。

2. **组织测试用例 (Test Groups):** 测试用例被组织成不同的组 (`test_group_0`, `test_group_1`, ...)，每组的密钥长度、IV 长度等参数可能相同。

3. **创建 `Aes128GcmDecrypter` 实例:**  在每个测试用例中，会创建一个 `Aes128GcmDecrypter` 的实例。

4. **设置密钥和 IV:**  使用测试用例中的密钥和 IV 调用 `SetKey` 和 `SetIV` 方法设置解密器。

5. **执行解密:**  调用 `DecryptPacket` 或 `DecryptWithNonce` 函数对密文进行解密，并使用附加认证数据进行完整性校验。

6. **验证结果:**
    * **成功解密的情况:** 比较解密得到的明文与测试用例中预期的明文是否一致。
    * **预期解密失败的情况:** 断言解密操作返回失败。

7. **测试头部保护掩码生成:**  `TEST_F(Aes128GcmDecrypterTest, GenerateHeaderProtectionMask)` 测试了 `GenerateHeaderProtectionMask` 方法，该方法用于生成 QUIC 头部保护所需的掩码。

**与 Javascript 的功能关系：**

虽然这个 C++ 文件本身不是 JavaScript 代码，但它测试的解密功能在 Web 开发中至关重要，并且与 JavaScript 有着密切的联系：

* **HTTPS 加密:** 当你在浏览器中访问 HTTPS 网站时，浏览器和服务器之间的通信通常使用 TLS (Transport Layer Security) 协议进行加密。而 TLS 可以使用 AES-GCM 等加密算法来保护数据的机密性和完整性。因此，`Aes128GcmDecrypter` 的功能直接支持了 HTTPS 的安全通信。JavaScript 通过浏览器内置的 API (例如 `fetch` 或 `XMLHttpRequest`) 发送和接收数据，这些数据在底层可能经过类似 AES-GCM 的加密。
* **Web Crypto API:** JavaScript 提供了 Web Crypto API，允许在浏览器中进行加密和解密操作。虽然 Web Crypto API 的实现细节可能不同，但它支持 AES-GCM 算法。因此，开发者可以使用 JavaScript 的 Web Crypto API 实现与 `Aes128GcmDecrypter` 类似的解密功能。

**JavaScript 举例说明:**

假设服务器使用 AES-128-GCM 加密了一段数据，你需要用 JavaScript 在浏览器端解密：

```javascript
async function decryptData(keyHex, ivHex, ciphertextHex, aadHex, tagHex) {
  try {
    const keyBytes = hexStringToUint8Array(keyHex);
    const ivBytes = hexStringToUint8Array(ivHex);
    const ciphertextBytes = hexStringToUint8Array(ciphertextHex);
    const aadBytes = hexStringToUint8Array(aadHex);
    const tagBytes = hexStringToUint8Array(tagHex);

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    const combinedCiphertext = new Uint8Array([...ciphertextBytes, ...tagBytes]);

    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: ivBytes,
        additionalData: aadBytes,
        tagLength: 128, // Tag length in bits
      },
      cryptoKey,
      combinedCiphertext
    );

    const plaintext = new TextDecoder().decode(decrypted);
    console.log("解密后的数据:", plaintext);
    return plaintext;
  } catch (error) {
    console.error("解密失败:", error);
    return null;
  }
}

// 辅助函数，将十六进制字符串转换为 Uint8Array
function hexStringToUint8Array(hexString) {
  const byteLength = hexString.length / 2;
  const byteArray = new Uint8Array(byteLength);
  for (let i = 0; i < byteLength; i++) {
    const hexByte = hexString.substring(i * 2, i * 2 + 2);
    byteArray[i] = parseInt(hexByte, 16);
  }
  return byteArray;
}

// 使用与 C++ 测试用例相似的数据进行测试 (例如，使用 test_group_0[0] 的数据)
const keyHex = "cf063a34d4a9a76c2c86787d3f96db71";
const ivHex = "113b9785971864c83b01c787";
const ciphertextHex = ""; // 空字符串
const aadHex = ""; // 空字符串
const tagHex = "72ac8493e3a5228b5d130a69d2510e42";

decryptData(keyHex, ivHex, ciphertextHex, aadHex, tagHex);
```

这个 JavaScript 代码片段使用了 Web Crypto API 的 `crypto.subtle.decrypt` 方法，模拟了 `Aes128GcmDecrypter` 的解密过程。它使用了与 C++ 测试用例中类似的密钥、IV、密文、AAD 和标签。

**逻辑推理：假设输入与输出**

假设我们使用 `test_group_0[0]` 的数据作为输入：

**假设输入:**

* **密钥 (Key):** "cf063a34d4a9a76c2c86787d3f96db71" (十六进制字符串)
* **初始向量 (IV):** "113b9785971864c83b01c787" (十六进制字符串)
* **密文 (CT):** "" (空字符串，十六进制字符串)
* **附加认证数据 (AAD):** "" (空字符串，十六进制字符串)
* **认证标签 (Tag):** "72ac8493e3a5228b5d130a69d2510e42" (十六进制字符串)

**逻辑推理:**

`Aes128GcmDecrypter` 会使用提供的密钥和 IV 对密文进行解密，并使用 AAD 和 Tag 进行数据完整性校验。由于密文为空，附加认证数据为空，并且提供的标签是有效的，解密应该成功。

**预期输出:**

* 解密操作成功，返回表示成功的状态。
* 解密后的明文为空字符串 `""`。

**假设输入与输出 (解密失败的情况):**

假设我们使用 `test_group_0[1]` 的数据作为输入 (预期解密失败的情况)：

**假设输入:**

* **密钥 (Key):** "a49a5e26a2f8cb63d05546c2a62f5343"
* **初始向量 (IV):** "907763b19b9b4ab6bd4f0281"
* **密文 (CT):** ""
* **附加认证数据 (AAD):** ""
* **认证标签 (Tag):** "a2be08210d8c470a8df6e8fbd79ec5cf"

**逻辑推理:**

根据测试用例的注释 `"nullptr  // FAIL"`，这个测试用例预期解密会失败。这可能是因为提供的标签与使用给定密钥、IV 和 AAD 加密空字符串得到的标签不匹配。

**预期输出:**

* 解密操作失败，返回表示失败的状态 (例如，返回 `false` 或抛出异常)。

**用户或编程常见的使用错误：**

1. **密钥错误 (Incorrect Key):** 使用错误的密钥进行解密会导致解密失败，并且通常无法恢复原始数据。
   * **示例:** 用户在配置网络连接时，错误地输入了加密密钥。

2. **初始向量 (IV) 重复使用:**  对于相同的密钥和不同的数据，应该使用不同的 IV。如果 IV 被重复使用，可能会破坏加密的安全性。
   * **示例:** 程序员在实现加密逻辑时，没有正确生成或管理 IV，导致在加密多个数据包时使用了相同的 IV。

3. **附加认证数据 (AAD) 不一致:**  在加密和解密时必须使用相同的 AAD。如果 AAD 不一致，解密会失败，因为无法验证数据的完整性。
   * **示例:**  在网络通信中，发送方在加密时包含了源 IP 地址作为 AAD，但接收方在解密时没有提供或提供了错误的源 IP 地址。

4. **认证标签 (Tag) 校验失败:**  如果密文或 AAD 在传输过程中被篡改，或者解密使用的密钥或 IV 不正确，认证标签的校验会失败，导致解密失败。
   * **示例:**  网络攻击者尝试修改加密的数据包，但由于修改导致认证标签校验失败，接收方可以检测到数据被篡改。

5. **缓冲区溢出:** 在 C++ 中，如果没有正确管理缓冲区大小，可能会导致缓冲区溢出。虽然这个测试文件主要关注逻辑正确性，但在实际应用中，如果解密输出的缓冲区太小，会导致数据丢失或程序崩溃。
   * **示例:**  `DecryptPacket` 函数的 `output_length` 参数没有正确设置，导致解密后的数据写入超出分配的缓冲区。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在使用 Chromium 浏览器访问一个使用 QUIC 协议的网站时遇到了解密错误，导致页面无法正常加载或显示错误信息。作为调试线索，可以按照以下步骤追踪到 `aes_128_gcm_decrypter_test.cc`：

1. **用户报告问题:** 用户反馈浏览器访问特定网站出现问题，例如页面显示不完整、加载缓慢或出现加密相关的错误提示。

2. **开发者检查网络请求:**  开发人员使用浏览器的开发者工具 (Network 面板) 检查网络请求，发现使用了 QUIC 协议的连接出现异常。可能会看到连接建立失败或者数据传输过程中出现错误。

3. **QUIC 连接调试:** 开发人员可能会启用 QUIC 相关的调试日志或工具，以查看更详细的 QUIC 连接信息。这些信息可能指示解密过程中出现了问题，例如认证标签校验失败。

4. **定位解密代码:**  根据错误信息和 QUIC 协议的实现细节，开发人员会定位到负责 QUIC 数据包解密的代码部分，这可能涉及到 `quiche/quic/core/crypto` 目录下的相关文件。

5. **查看 `Aes128GcmDecrypter` 的使用:**  开发人员会查看 `Aes128GcmDecrypter` 类在 QUIC 代码中的使用方式，例如在哪里创建实例，如何设置密钥和 IV，以及如何调用解密函数。

6. **运行单元测试:** 为了验证 `Aes128GcmDecrypter` 类的功能是否正常，开发人员会运行 `aes_128_gcm_decrypter_test.cc` 中的单元测试。如果测试失败，则表明解密器本身存在问题。

7. **检查测试用例:**  开发人员会仔细检查 `aes_128_gcm_decrypter_test.cc` 中的测试用例，特别是那些与当前遇到的问题类似的场景，例如特定的密钥长度、IV 长度或 AAD。

8. **添加额外的调试信息:**  如果在单元测试中没有发现问题，开发人员可能会在 `Aes128GcmDecrypter` 的实现代码中添加额外的日志或断点，以便在实际运行环境中追踪解密过程中的变量值和状态。

9. **分析网络数据包:** 使用网络抓包工具 (如 Wireshark) 捕获浏览器和服务器之间的 QUIC 数据包，分析加密的数据和头部信息，以便更深入地了解解密失败的原因。

通过以上步骤，开发人员可以逐步缩小问题范围，最终可能定位到 `Aes_128_gcm_decrypter_test.cc` 文件，以理解该解密器的功能和测试用例，从而更好地诊断和解决用户遇到的解密错误问题。这个测试文件本身为开发者提供了一个验证解密器功能的基础，是调试过程中的重要参考。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/crypto/aes_128_gcm_decrypter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/crypto/aes_128_gcm_decrypter.h"

#include <memory>
#include <string>

#include "absl/base/macros.h"
#include "absl/strings/escaping.h"
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
QuicData* DecryptWithNonce(Aes128GcmDecrypter* decrypter,
                           absl::string_view nonce,
                           absl::string_view associated_data,
                           absl::string_view ciphertext) {
  decrypter->SetIV(nonce);
  std::unique_ptr<char[]> output(new char[ciphertext.length()]);
  size_t output_length = 0;
  const bool success =
      decrypter->DecryptPacket(0, associated_data, ciphertext, output.get(),
                               &output_length, ciphertext.length());
  if (!success) {
    return nullptr;
  }
  return new QuicData(output.release(), output_length, true);
}

class Aes128GcmDecrypterTest : public QuicTest {};

TEST_F(Aes128GcmDecrypterTest, Decrypt) {
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
      std::string ciphertext = ct + tag;

      Aes128GcmDecrypter decrypter;
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

TEST_F(Aes128GcmDecrypterTest, GenerateHeaderProtectionMask) {
  Aes128GcmDecrypter decrypter;
  std::string key;
  std::string sample;
  std::string expected_mask;
  ASSERT_TRUE(absl::HexStringToBytes("d9132370cb18476ab833649cf080d970", &key));
  ASSERT_TRUE(
      absl::HexStringToBytes("d1d7998068517adb769b48b924a32c47", &sample));
  ASSERT_TRUE(absl::HexStringToBytes("b132c37d6164da4ea4dc9b763aceec27",
                                     &expected_mask));
  QuicDataReader sample_reader(sample.data(), sample.size());
  ASSERT_TRUE(decrypter.SetHeaderProtectionKey(key));
  std::string mask = decrypter.GenerateHeaderProtectionMask(&sample_reader);
  quiche::test::CompareCharArraysWithHexError(
      "header protection mask", mask.data(), mask.size(), expected_mask.data(),
      expected_mask.size());
}

}  // namespace test
}  // namespace quic

"""

```