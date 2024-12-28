Response:
Let's break down the thought process to analyze the `web_crypto_algorithm.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relation to web technologies (JavaScript, HTML, CSS), potential logical inferences with examples, and common usage errors.

2. **Initial Scan for Keywords:** Look for immediately recognizable terms: `WebCrypto`, algorithm names (AES, HMAC, RSA, SHA, etc.), parameters, `JavaScript`, `HTML`, `CSS`. This gives a high-level idea of the file's purpose.

3. **Identify the Core Data Structure:** The `kAlgorithmIdToInfo` array is central. It maps `WebCryptoAlgorithmId` to `WebCryptoAlgorithmInfo`. This suggests the file is about defining and managing cryptographic algorithms supported by the Web Crypto API.

4. **Analyze `WebCryptoAlgorithmInfo`:** This structure seems to hold information about how each algorithm is used (encrypt, decrypt, sign, etc.) and what parameter types are associated with each operation. The `kWebCryptoAlgorithmParamsType...` enums are important here.

5. **Relate to Web Crypto API:** The names and structure strongly suggest this file is a core part of the Blink rendering engine's implementation of the Web Crypto API. This API allows JavaScript in web pages to perform cryptographic operations.

6. **Connect to JavaScript:**  The algorithm names (e.g., "AES-CBC", "HMAC") are strings that likely correspond to the `algorithm` parameter passed to Web Crypto API methods like `crypto.subtle.encrypt()`, `crypto.subtle.sign()`, etc. The parameter types likely correspond to the `algorithm` object's properties in JavaScript.

7. **Consider HTML and CSS:**  While the *direct* connection might be less obvious, the Web Crypto API is used within the context of web pages. Therefore, HTML and CSS provide the structure and styling for the user interface where scripts using the Web Crypto API run. For example, a website might use the Web Crypto API to encrypt data entered into an HTML form.

8. **Identify the `WebCryptoAlgorithm` Class:**  This class appears to be a C++ representation of a specific cryptographic algorithm instance, holding its ID and parameters. The `WebCryptoAlgorithmPrivate` likely manages the lifetime and data of the parameters.

9. **Analyze the Helper Functions:** Functions like `LookupAlgorithmInfo`, `IsHash`, and `IsKdf` provide utilities for checking algorithm properties. These are likely used internally within Blink's Web Crypto implementation.

10. **Infer Logical Relationships (Assumptions and Outputs):**

    * **Input:** A JavaScript call to `crypto.subtle.encrypt('AES-CBC', key, data)`.
    * **Output:** The Blink engine would look up the "AES-CBC" algorithm in `kAlgorithmIdToInfo`, find the corresponding entry, and then use the associated parameter type (`kWebCryptoAlgorithmParamsTypeAesCbcParams`) to handle the encryption process.

    * **Input:** A JavaScript call to `crypto.subtle.digest('SHA-256', data)`.
    * **Output:** Blink would look up "SHA-256", identify it as a digest algorithm, and perform the SHA-256 hashing.

11. **Consider Potential User/Programming Errors:**

    * **Incorrect Algorithm Name:**  Passing a misspelled or unsupported algorithm name to `crypto.subtle.encrypt()` would lead to an error.
    * **Mismatched Parameters:** Providing parameters that don't match the algorithm's requirements (e.g., missing the IV for AES-CBC) would also cause errors.
    * **Security Mistakes:** While the file itself doesn't *cause* these, it *supports* the secure implementation. Misusing the API (e.g., hardcoding keys, using weak algorithms when stronger ones are available) is a common user error.

12. **Address Specific Instructions:**  Go back through the prompt and ensure all parts are covered. Have I listed functionalities?  Are the connections to JavaScript, HTML, and CSS explained? Are there examples of logical inference? Are common errors discussed?

13. **Refine and Organize:**  Structure the answer logically with clear headings and bullet points for readability. Ensure the language is precise and avoids jargon where possible, while still being technically accurate. For example, explicitly stating that the file *defines* the supported algorithms, rather than just *implements* them, provides a more accurate picture.

This iterative process of scanning, identifying key structures, connecting to web concepts, inferring logic, and considering error scenarios allows for a comprehensive understanding of the `web_crypto_algorithm.cc` file's role within the Blink rendering engine.
这个文件 `blink/renderer/platform/exported/web_crypto_algorithm.cc` 是 Chromium Blink 引擎中关于 **Web Crypto API 算法** 的定义和管理的核心组件。它不直接实现加密算法本身，而是定义了 Blink 引擎支持的各种 Web Crypto 算法的元数据信息。

**主要功能:**

1. **定义支持的 Web Crypto 算法:**  文件中定义了一个名为 `kAlgorithmIdToInfo` 的静态常量数组。这个数组将 `WebCryptoAlgorithmId` 枚举值映射到 `WebCryptoAlgorithmInfo` 结构体。`WebCryptoAlgorithmInfo` 包含了关于特定加密算法的各种信息，例如：
    * 算法名称 (例如 "AES-CBC", "HMAC", "SHA-256")
    * 该算法支持的操作类型 (加密、解密、签名、校验、摘要、生成密钥、导入密钥、获取密钥长度、派生密钥、密钥包装、密钥解包)
    * 每个操作类型对应的参数类型 (例如 `kWebCryptoAlgorithmParamsTypeAesCbcParams` 表示 AES-CBC 加密/解密需要 `WebCryptoAesCbcParams` 类型的参数)

2. **提供算法信息查找功能:**  `WebCryptoAlgorithm::LookupAlgorithmInfo(WebCryptoAlgorithmId id)` 函数允许根据算法 ID 查找对应的 `WebCryptoAlgorithmInfo`，从而获取该算法的详细信息。

3. **表示 Web Crypto 算法实例:** `WebCryptoAlgorithm` 类用于表示一个特定的 Web Crypto 算法实例。它包含算法的 ID 和相关的参数。

4. **提供访问算法参数的接口:** `WebCryptoAlgorithm` 类提供了一系列成员函数 (例如 `AesCbcParams()`, `HmacKeyGenParams()`)，用于安全地访问存储在算法实例中的特定参数。

5. **提供算法类型判断功能:** `WebCryptoAlgorithm::IsHash(WebCryptoAlgorithmId id)` 和 `WebCryptoAlgorithm::IsKdf(WebCryptoAlgorithmId id)` 等函数用于判断给定的算法 ID 是否属于哈希算法或密钥派生函数。

**与 JavaScript, HTML, CSS 的关系:**

这个 C++ 文件是 Blink 引擎的内部实现，它直接支持了 **Web Crypto API**，这是一个暴露给 JavaScript 的 Web API。

* **JavaScript:**
    * 当 JavaScript 代码使用 `window.crypto.subtle` API (Web Crypto API) 来执行加密操作时，例如加密、解密、签名等，浏览器引擎 (Blink) 会根据 JavaScript 中指定的算法名称 (例如 `AES-CBC`)，在这个 `web_crypto_algorithm.cc` 文件中查找对应的算法信息。
    * JavaScript 代码传递给 Web Crypto API 方法的 `algorithm` 参数 (一个对象或字符串) 会被映射到这里定义的 `WebCryptoAlgorithmId` 和参数类型。

    **举例说明:**

    ```javascript
    // JavaScript 代码使用 AES-CBC 算法加密数据
    async function encryptData(key, data) {
      const iv = window.crypto.getRandomValues(new Uint8Array(16));
      const algorithm = { name: "AES-CBC", iv: iv };
      const encrypted = await window.crypto.subtle.encrypt(algorithm, key, data);
      return encrypted;
    }
    ```

    在这个例子中，当 JavaScript 执行 `window.crypto.subtle.encrypt(algorithm, key, data)` 时，Blink 引擎会：
    1. 解析 `algorithm` 对象，识别出 `name` 为 "AES-CBC"。
    2. 在 `web_crypto_algorithm.cc` 的 `kAlgorithmIdToInfo` 中查找 "AES-CBC"，找到对应的 `WebCryptoAlgorithmId` 和 `kWebCryptoAlgorithmParamsTypeAesCbcParams`。
    3. 根据 `kWebCryptoAlgorithmParamsTypeAesCbcParams`，确定需要一个 `WebCryptoAesCbcParams` 类型的参数，并将 JavaScript 传递的 `iv` 映射到这个参数。
    4. 调用相应的 C++ 加密实现来执行 AES-CBC 加密。

* **HTML 和 CSS:**
    * HTML 和 CSS 本身不直接与这个文件交互。但是，它们定义了网页的结构和样式，而 JavaScript 代码 (包括使用 Web Crypto API 的代码) 通常是网页交互逻辑的一部分。
    * 例如，一个网页可能包含一个表单，用户输入的数据通过 JavaScript 和 Web Crypto API 进行加密后再发送到服务器。

**逻辑推理 (假设输入与输出):**

假设输入是一个 JavaScript 调用 `crypto.subtle.encrypt`，且 `algorithm.name` 为 "SHA-256"。

* **假设输入:**
    ```javascript
    const algorithm = { name: "SHA-256" };
    const data = new TextEncoder().encode("Hello, world!");
    crypto.subtle.digest(algorithm, data).then(hashBuffer => {
      // 处理 hashBuffer
    });
    ```

* **逻辑推理过程:**
    1. Blink 引擎接收到 `digest` 请求，算法名称为 "SHA-256"。
    2. `WebCryptoAlgorithm::LookupAlgorithmInfo(kWebCryptoAlgorithmIdSha256)` 被调用 (假设 "SHA-256" 映射到 `kWebCryptoAlgorithmIdSha256`)。
    3. `LookupAlgorithmInfo` 在 `kAlgorithmIdToInfo` 数组中查找索引为 4 的元素 (SHA-256 的索引)。
    4. 返回该索引对应的 `WebCryptoAlgorithmInfo` 结构体，其中 `digest` 字段的参数类型为 `kWebCryptoAlgorithmParamsTypeNone`。

* **预期输出:**
    `LookupAlgorithmInfo` 函数返回指向 SHA-256 算法信息的指针，指示这是一个摘要算法，并且不需要额外的参数。Blink 引擎会继续调用相应的 SHA-256 哈希实现来计算数据的摘要。

**用户或编程常见的使用错误举例:**

1. **算法名称拼写错误或使用不支持的算法:**
   ```javascript
   // 错误：算法名称拼写错误
   const algorithm = { name: "AES-CVC", iv: ... };
   crypto.subtle.encrypt(algorithm, key, data); // 会导致错误，因为 "AES-CVC" 不是支持的算法
   ```
   Blink 引擎在 `kAlgorithmIdToInfo` 中找不到匹配的算法名称，会抛出错误。

2. **提供的参数与算法要求不符:**
   ```javascript
   // 错误：AES-CBC 需要 iv 参数
   const algorithm = { name: "AES-CBC" }; // 缺少 iv
   crypto.subtle.encrypt(algorithm, key, data); // 会导致错误
   ```
   Blink 引擎会检查算法的参数类型，发现 AES-CBC 需要 `iv` 参数，但 JavaScript 代码没有提供，从而抛出错误。

3. **在不支持特定操作的算法上调用该操作:**
   ```javascript
   // 错误：SHA-256 是哈希算法，不能用于加密
   const algorithm = { name: "SHA-256" };
   crypto.subtle.encrypt(algorithm, key, data); // 会导致错误
   ```
   `kAlgorithmIdToInfo` 中 SHA-256 的 `encrypt` 字段为 `WebCryptoAlgorithmInfo::kUndefined`，表示不支持加密操作，Blink 引擎会拒绝该操作。

**总结:**

`web_crypto_algorithm.cc` 文件是 Blink 引擎中定义和管理 Web Crypto API 支持的加密算法的关键部分。它通过一个静态数据结构来维护算法的元信息，并提供查找和访问这些信息的接口。这使得 Blink 引擎能够正确地处理来自 JavaScript 的 Web Crypto API 请求，并根据指定的算法和参数执行相应的加密操作。 开发者在使用 Web Crypto API 时需要仔细参考支持的算法名称和参数要求，避免常见的拼写错误、参数缺失或操作类型不匹配等问题。

Prompt: 
```
这是目录为blink/renderer/platform/exported/web_crypto_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/public/platform/web_crypto_algorithm.h"

#include <memory>
#include <utility>

#include "base/memory/ptr_util.h"
#include "third_party/blink/public/platform/web_crypto_algorithm_params.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/thread_safe_ref_counted.h"

namespace blink {

namespace {

// A mapping from the algorithm ID to information about the algorithm.
constexpr WebCryptoAlgorithmInfo kAlgorithmIdToInfo[] = {
    {// Index 0
     "AES-CBC",
     {
         kWebCryptoAlgorithmParamsTypeAesCbcParams,         // Encrypt
         kWebCryptoAlgorithmParamsTypeAesCbcParams,         // Decrypt
         WebCryptoAlgorithmInfo::kUndefined,                // Sign
         WebCryptoAlgorithmInfo::kUndefined,                // Verify
         WebCryptoAlgorithmInfo::kUndefined,                // Digest
         kWebCryptoAlgorithmParamsTypeAesKeyGenParams,      // GenerateKey
         kWebCryptoAlgorithmParamsTypeNone,                 // ImportKey
         kWebCryptoAlgorithmParamsTypeAesDerivedKeyParams,  // GetKeyLength
         WebCryptoAlgorithmInfo::kUndefined,                // DeriveBits
         kWebCryptoAlgorithmParamsTypeAesCbcParams,         // WrapKey
         kWebCryptoAlgorithmParamsTypeAesCbcParams          // UnwrapKey
     }},
    {// Index 1
     "HMAC",
     {
         WebCryptoAlgorithmInfo::kUndefined,             // Encrypt
         WebCryptoAlgorithmInfo::kUndefined,             // Decrypt
         kWebCryptoAlgorithmParamsTypeNone,              // Sign
         kWebCryptoAlgorithmParamsTypeNone,              // Verify
         WebCryptoAlgorithmInfo::kUndefined,             // Digest
         kWebCryptoAlgorithmParamsTypeHmacKeyGenParams,  // GenerateKey
         kWebCryptoAlgorithmParamsTypeHmacImportParams,  // ImportKey
         kWebCryptoAlgorithmParamsTypeHmacImportParams,  // GetKeyLength
         WebCryptoAlgorithmInfo::kUndefined,             // DeriveBits
         WebCryptoAlgorithmInfo::kUndefined,             // WrapKey
         WebCryptoAlgorithmInfo::kUndefined              // UnwrapKey
     }},
    {// Index 2
     "RSASSA-PKCS1-v1_5",
     {
         WebCryptoAlgorithmInfo::kUndefined,                  // Encrypt
         WebCryptoAlgorithmInfo::kUndefined,                  // Decrypt
         kWebCryptoAlgorithmParamsTypeNone,                   // Sign
         kWebCryptoAlgorithmParamsTypeNone,                   // Verify
         WebCryptoAlgorithmInfo::kUndefined,                  // Digest
         kWebCryptoAlgorithmParamsTypeRsaHashedKeyGenParams,  // GenerateKey
         kWebCryptoAlgorithmParamsTypeRsaHashedImportParams,  // ImportKey
         WebCryptoAlgorithmInfo::kUndefined,                  // GetKeyLength
         WebCryptoAlgorithmInfo::kUndefined,                  // DeriveBits
         WebCryptoAlgorithmInfo::kUndefined,                  // WrapKey
         WebCryptoAlgorithmInfo::kUndefined                   // UnwrapKey
     }},
    {// Index 3
     "SHA-1",
     {
         WebCryptoAlgorithmInfo::kUndefined,  // Encrypt
         WebCryptoAlgorithmInfo::kUndefined,  // Decrypt
         WebCryptoAlgorithmInfo::kUndefined,  // Sign
         WebCryptoAlgorithmInfo::kUndefined,  // Verify
         kWebCryptoAlgorithmParamsTypeNone,   // Digest
         WebCryptoAlgorithmInfo::kUndefined,  // GenerateKey
         WebCryptoAlgorithmInfo::kUndefined,  // ImportKey
         WebCryptoAlgorithmInfo::kUndefined,  // GetKeyLength
         WebCryptoAlgorithmInfo::kUndefined,  // DeriveBits
         WebCryptoAlgorithmInfo::kUndefined,  // WrapKey
         WebCryptoAlgorithmInfo::kUndefined   // UnwrapKey
     }},
    {// Index 4
     "SHA-256",
     {
         WebCryptoAlgorithmInfo::kUndefined,  // Encrypt
         WebCryptoAlgorithmInfo::kUndefined,  // Decrypt
         WebCryptoAlgorithmInfo::kUndefined,  // Sign
         WebCryptoAlgorithmInfo::kUndefined,  // Verify
         kWebCryptoAlgorithmParamsTypeNone,   // Digest
         WebCryptoAlgorithmInfo::kUndefined,  // GenerateKey
         WebCryptoAlgorithmInfo::kUndefined,  // ImportKey
         WebCryptoAlgorithmInfo::kUndefined,  // GetKeyLength
         WebCryptoAlgorithmInfo::kUndefined,  // DeriveBits
         WebCryptoAlgorithmInfo::kUndefined,  // WrapKey
         WebCryptoAlgorithmInfo::kUndefined   // UnwrapKey
     }},
    {// Index 5
     "SHA-384",
     {
         WebCryptoAlgorithmInfo::kUndefined,  // Encrypt
         WebCryptoAlgorithmInfo::kUndefined,  // Decrypt
         WebCryptoAlgorithmInfo::kUndefined,  // Sign
         WebCryptoAlgorithmInfo::kUndefined,  // Verify
         kWebCryptoAlgorithmParamsTypeNone,   // Digest
         WebCryptoAlgorithmInfo::kUndefined,  // GenerateKey
         WebCryptoAlgorithmInfo::kUndefined,  // ImportKey
         WebCryptoAlgorithmInfo::kUndefined,  // GetKeyLength
         WebCryptoAlgorithmInfo::kUndefined,  // DeriveBits
         WebCryptoAlgorithmInfo::kUndefined,  // WrapKey
         WebCryptoAlgorithmInfo::kUndefined   // UnwrapKey
     }},
    {// Index 6
     "SHA-512",
     {
         WebCryptoAlgorithmInfo::kUndefined,  // Encrypt
         WebCryptoAlgorithmInfo::kUndefined,  // Decrypt
         WebCryptoAlgorithmInfo::kUndefined,  // Sign
         WebCryptoAlgorithmInfo::kUndefined,  // Verify
         kWebCryptoAlgorithmParamsTypeNone,   // Digest
         WebCryptoAlgorithmInfo::kUndefined,  // GenerateKey
         WebCryptoAlgorithmInfo::kUndefined,  // ImportKey
         WebCryptoAlgorithmInfo::kUndefined,  // GetKeyLength
         WebCryptoAlgorithmInfo::kUndefined,  // DeriveBits
         WebCryptoAlgorithmInfo::kUndefined,  // WrapKey
         WebCryptoAlgorithmInfo::kUndefined   // UnwrapKey
     }},
    {// Index 7
     "AES-GCM",
     {
         kWebCryptoAlgorithmParamsTypeAesGcmParams,         // Encrypt
         kWebCryptoAlgorithmParamsTypeAesGcmParams,         // Decrypt
         WebCryptoAlgorithmInfo::kUndefined,                // Sign
         WebCryptoAlgorithmInfo::kUndefined,                // Verify
         WebCryptoAlgorithmInfo::kUndefined,                // Digest
         kWebCryptoAlgorithmParamsTypeAesKeyGenParams,      // GenerateKey
         kWebCryptoAlgorithmParamsTypeNone,                 // ImportKey
         kWebCryptoAlgorithmParamsTypeAesDerivedKeyParams,  // GetKeyLength
         WebCryptoAlgorithmInfo::kUndefined,                // DeriveBits
         kWebCryptoAlgorithmParamsTypeAesGcmParams,         // WrapKey
         kWebCryptoAlgorithmParamsTypeAesGcmParams          // UnwrapKey
     }},
    {// Index 8
     "RSA-OAEP",
     {
         kWebCryptoAlgorithmParamsTypeRsaOaepParams,          // Encrypt
         kWebCryptoAlgorithmParamsTypeRsaOaepParams,          // Decrypt
         WebCryptoAlgorithmInfo::kUndefined,                  // Sign
         WebCryptoAlgorithmInfo::kUndefined,                  // Verify
         WebCryptoAlgorithmInfo::kUndefined,                  // Digest
         kWebCryptoAlgorithmParamsTypeRsaHashedKeyGenParams,  // GenerateKey
         kWebCryptoAlgorithmParamsTypeRsaHashedImportParams,  // ImportKey
         WebCryptoAlgorithmInfo::kUndefined,                  // GetKeyLength
         WebCryptoAlgorithmInfo::kUndefined,                  // DeriveBits
         kWebCryptoAlgorithmParamsTypeRsaOaepParams,          // WrapKey
         kWebCryptoAlgorithmParamsTypeRsaOaepParams           // UnwrapKey
     }},
    {// Index 9
     "AES-CTR",
     {
         kWebCryptoAlgorithmParamsTypeAesCtrParams,         // Encrypt
         kWebCryptoAlgorithmParamsTypeAesCtrParams,         // Decrypt
         WebCryptoAlgorithmInfo::kUndefined,                // Sign
         WebCryptoAlgorithmInfo::kUndefined,                // Verify
         WebCryptoAlgorithmInfo::kUndefined,                // Digest
         kWebCryptoAlgorithmParamsTypeAesKeyGenParams,      // GenerateKey
         kWebCryptoAlgorithmParamsTypeNone,                 // ImportKey
         kWebCryptoAlgorithmParamsTypeAesDerivedKeyParams,  // GetKeyLength
         WebCryptoAlgorithmInfo::kUndefined,                // DeriveBits
         kWebCryptoAlgorithmParamsTypeAesCtrParams,         // WrapKey
         kWebCryptoAlgorithmParamsTypeAesCtrParams          // UnwrapKey
     }},
    {// Index 10
     "AES-KW",
     {
         WebCryptoAlgorithmInfo::kUndefined,                // Encrypt
         WebCryptoAlgorithmInfo::kUndefined,                // Decrypt
         WebCryptoAlgorithmInfo::kUndefined,                // Sign
         WebCryptoAlgorithmInfo::kUndefined,                // Verify
         WebCryptoAlgorithmInfo::kUndefined,                // Digest
         kWebCryptoAlgorithmParamsTypeAesKeyGenParams,      // GenerateKey
         kWebCryptoAlgorithmParamsTypeNone,                 // ImportKey
         kWebCryptoAlgorithmParamsTypeAesDerivedKeyParams,  // GetKeyLength
         WebCryptoAlgorithmInfo::kUndefined,                // DeriveBits
         kWebCryptoAlgorithmParamsTypeNone,                 // WrapKey
         kWebCryptoAlgorithmParamsTypeNone                  // UnwrapKey
     }},
    {// Index 11
     "RSA-PSS",
     {
         WebCryptoAlgorithmInfo::kUndefined,                  // Encrypt
         WebCryptoAlgorithmInfo::kUndefined,                  // Decrypt
         kWebCryptoAlgorithmParamsTypeRsaPssParams,           // Sign
         kWebCryptoAlgorithmParamsTypeRsaPssParams,           // Verify
         WebCryptoAlgorithmInfo::kUndefined,                  // Digest
         kWebCryptoAlgorithmParamsTypeRsaHashedKeyGenParams,  // GenerateKey
         kWebCryptoAlgorithmParamsTypeRsaHashedImportParams,  // ImportKey
         WebCryptoAlgorithmInfo::kUndefined,                  // GetKeyLength
         WebCryptoAlgorithmInfo::kUndefined,                  // DeriveBits
         WebCryptoAlgorithmInfo::kUndefined,                  // WrapKey
         WebCryptoAlgorithmInfo::kUndefined                   // UnwrapKey
     }},
    {// Index 12
     "ECDSA",
     {
         WebCryptoAlgorithmInfo::kUndefined,              // Encrypt
         WebCryptoAlgorithmInfo::kUndefined,              // Decrypt
         kWebCryptoAlgorithmParamsTypeEcdsaParams,        // Sign
         kWebCryptoAlgorithmParamsTypeEcdsaParams,        // Verify
         WebCryptoAlgorithmInfo::kUndefined,              // Digest
         kWebCryptoAlgorithmParamsTypeEcKeyGenParams,     // GenerateKey
         kWebCryptoAlgorithmParamsTypeEcKeyImportParams,  // ImportKey
         WebCryptoAlgorithmInfo::kUndefined,              // GetKeyLength
         WebCryptoAlgorithmInfo::kUndefined,              // DeriveBits
         WebCryptoAlgorithmInfo::kUndefined,              // WrapKey
         WebCryptoAlgorithmInfo::kUndefined               // UnwrapKey
     }},
    {// Index 13
     "ECDH",
     {
         WebCryptoAlgorithmInfo::kUndefined,                // Encrypt
         WebCryptoAlgorithmInfo::kUndefined,                // Decrypt
         WebCryptoAlgorithmInfo::kUndefined,                // Sign
         WebCryptoAlgorithmInfo::kUndefined,                // Verify
         WebCryptoAlgorithmInfo::kUndefined,                // Digest
         kWebCryptoAlgorithmParamsTypeEcKeyGenParams,       // GenerateKey
         kWebCryptoAlgorithmParamsTypeEcKeyImportParams,    // ImportKey
         WebCryptoAlgorithmInfo::kUndefined,                // GetKeyLength
         kWebCryptoAlgorithmParamsTypeEcdhKeyDeriveParams,  // DeriveBits
         WebCryptoAlgorithmInfo::kUndefined,                // WrapKey
         WebCryptoAlgorithmInfo::kUndefined                 // UnwrapKey
     }},
    {// Index 14
     "HKDF",
     {
         WebCryptoAlgorithmInfo::kUndefined,       // Encrypt
         WebCryptoAlgorithmInfo::kUndefined,       // Decrypt
         WebCryptoAlgorithmInfo::kUndefined,       // Sign
         WebCryptoAlgorithmInfo::kUndefined,       // Verify
         WebCryptoAlgorithmInfo::kUndefined,       // Digest
         WebCryptoAlgorithmInfo::kUndefined,       // GenerateKey
         kWebCryptoAlgorithmParamsTypeNone,        // ImportKey
         kWebCryptoAlgorithmParamsTypeNone,        // GetKeyLength
         kWebCryptoAlgorithmParamsTypeHkdfParams,  // DeriveBits
         WebCryptoAlgorithmInfo::kUndefined,       // WrapKey
         WebCryptoAlgorithmInfo::kUndefined        // UnwrapKey
     }},
    {// Index 15
     "PBKDF2",
     {
         WebCryptoAlgorithmInfo::kUndefined,         // Encrypt
         WebCryptoAlgorithmInfo::kUndefined,         // Decrypt
         WebCryptoAlgorithmInfo::kUndefined,         // Sign
         WebCryptoAlgorithmInfo::kUndefined,         // Verify
         WebCryptoAlgorithmInfo::kUndefined,         // Digest
         WebCryptoAlgorithmInfo::kUndefined,         // GenerateKey
         kWebCryptoAlgorithmParamsTypeNone,          // ImportKey
         kWebCryptoAlgorithmParamsTypeNone,          // GetKeyLength
         kWebCryptoAlgorithmParamsTypePbkdf2Params,  // DeriveBits
         WebCryptoAlgorithmInfo::kUndefined,         // WrapKey
         WebCryptoAlgorithmInfo::kUndefined          // UnwrapKey
     }},
    {// Index 16
     // TODO(crbug.com/1370697): Ed25519 is experimental behind a flag. See
     // https://chromestatus.com/feature/4913922408710144 for the status.
     "Ed25519",
     {
         WebCryptoAlgorithmInfo::kUndefined,  // Encrypt
         WebCryptoAlgorithmInfo::kUndefined,  // Decrypt
         kWebCryptoAlgorithmParamsTypeNone,   // Sign
         kWebCryptoAlgorithmParamsTypeNone,   // Verify
         WebCryptoAlgorithmInfo::kUndefined,  // Digest
         kWebCryptoAlgorithmParamsTypeNone,   // GenerateKey
         kWebCryptoAlgorithmParamsTypeNone,   // ImportKey
         WebCryptoAlgorithmInfo::kUndefined,  // GetKeyLength
         WebCryptoAlgorithmInfo::kUndefined,  // DeriveBits
         WebCryptoAlgorithmInfo::kUndefined,  // WrapKey
         WebCryptoAlgorithmInfo::kUndefined   // UnwrapKey
     }},
    {// Index 17
     // TODO(crbug.com/1370697): X25519 is experimental behind a flag. See
     // https://chromestatus.com/feature/4913922408710144 for the status.
     "X25519",
     {
         WebCryptoAlgorithmInfo::kUndefined,                // Encrypt
         WebCryptoAlgorithmInfo::kUndefined,                // Decrypt
         WebCryptoAlgorithmInfo::kUndefined,                // Sign
         WebCryptoAlgorithmInfo::kUndefined,                // Verify
         WebCryptoAlgorithmInfo::kUndefined,                // Digest
         kWebCryptoAlgorithmParamsTypeNone,                 // GenerateKey
         kWebCryptoAlgorithmParamsTypeNone,                 // ImportKey
         WebCryptoAlgorithmInfo::kUndefined,                // GetKeyLength
         kWebCryptoAlgorithmParamsTypeEcdhKeyDeriveParams,  // DeriveBits
         WebCryptoAlgorithmInfo::kUndefined,                // WrapKey
         WebCryptoAlgorithmInfo::kUndefined                 // UnwrapKey
     }},
};

// Initializing the algorithmIdToInfo table above depends on knowing the enum
// values for algorithm IDs. If those ever change, the table will need to be
// updated.
static_assert(kWebCryptoAlgorithmIdAesCbc == 0, "AES CBC id must match");
static_assert(kWebCryptoAlgorithmIdHmac == 1, "HMAC id must match");
static_assert(kWebCryptoAlgorithmIdRsaSsaPkcs1v1_5 == 2,
              "RSASSA-PKCS1-v1_5 id must match");
static_assert(kWebCryptoAlgorithmIdSha1 == 3, "SHA1 id must match");
static_assert(kWebCryptoAlgorithmIdSha256 == 4, "SHA256 id must match");
static_assert(kWebCryptoAlgorithmIdSha384 == 5, "SHA384 id must match");
static_assert(kWebCryptoAlgorithmIdSha512 == 6, "SHA512 id must match");
static_assert(kWebCryptoAlgorithmIdAesGcm == 7, "AES GCM id must match");
static_assert(kWebCryptoAlgorithmIdRsaOaep == 8, "RSA OAEP id must match");
static_assert(kWebCryptoAlgorithmIdAesCtr == 9, "AES CTR id must match");
static_assert(kWebCryptoAlgorithmIdAesKw == 10, "AESKW id must match");
static_assert(kWebCryptoAlgorithmIdRsaPss == 11, "RSA-PSS id must match");
static_assert(kWebCryptoAlgorithmIdEcdsa == 12, "ECDSA id must match");
static_assert(kWebCryptoAlgorithmIdEcdh == 13, "ECDH id must match");
static_assert(kWebCryptoAlgorithmIdHkdf == 14, "HKDF id must match");
static_assert(kWebCryptoAlgorithmIdPbkdf2 == 15, "Pbkdf2 id must match");
static_assert(kWebCryptoAlgorithmIdEd25519 == 16, "Ed25519 id must match");
static_assert(kWebCryptoAlgorithmIdX25519 == 17, "X25519 id must match");
static_assert(kWebCryptoAlgorithmIdLast == 17, "last id must match");
static_assert(10 == kWebCryptoOperationLast,
              "the parameter mapping needs to be updated");

}  // namespace

class WebCryptoAlgorithmPrivate
    : public ThreadSafeRefCounted<WebCryptoAlgorithmPrivate> {
 public:
  WebCryptoAlgorithmPrivate(WebCryptoAlgorithmId id,
                            std::unique_ptr<WebCryptoAlgorithmParams> params)
      : id(id), params(std::move(params)) {}

  WebCryptoAlgorithmId id;
  std::unique_ptr<WebCryptoAlgorithmParams> params;
};

WebCryptoAlgorithm::WebCryptoAlgorithm(
    WebCryptoAlgorithmId id,
    std::unique_ptr<WebCryptoAlgorithmParams> params)
    : private_(base::AdoptRef(
          new WebCryptoAlgorithmPrivate(id, std::move(params)))) {}

WebCryptoAlgorithm WebCryptoAlgorithm::CreateNull() {
  return WebCryptoAlgorithm();
}

WebCryptoAlgorithm WebCryptoAlgorithm::AdoptParamsAndCreate(
    WebCryptoAlgorithmId id,
    WebCryptoAlgorithmParams* params) {
  return WebCryptoAlgorithm(id, base::WrapUnique(params));
}

const WebCryptoAlgorithmInfo* WebCryptoAlgorithm::LookupAlgorithmInfo(
    WebCryptoAlgorithmId id) {
  const unsigned id_int = id;
  if (id_int >= std::size(kAlgorithmIdToInfo))
    return nullptr;
  return &kAlgorithmIdToInfo[id];
}

bool WebCryptoAlgorithm::IsNull() const {
  return private_.IsNull();
}

WebCryptoAlgorithmId WebCryptoAlgorithm::Id() const {
  DCHECK(!IsNull());
  return private_->id;
}

WebCryptoAlgorithmParamsType WebCryptoAlgorithm::ParamsType() const {
  DCHECK(!IsNull());
  if (!private_->params)
    return kWebCryptoAlgorithmParamsTypeNone;
  return private_->params->GetType();
}

const WebCryptoAesCbcParams* WebCryptoAlgorithm::AesCbcParams() const {
  DCHECK(!IsNull());
  if (ParamsType() == kWebCryptoAlgorithmParamsTypeAesCbcParams)
    return static_cast<WebCryptoAesCbcParams*>(private_->params.get());
  return nullptr;
}

const WebCryptoAesCtrParams* WebCryptoAlgorithm::AesCtrParams() const {
  DCHECK(!IsNull());
  if (ParamsType() == kWebCryptoAlgorithmParamsTypeAesCtrParams)
    return static_cast<WebCryptoAesCtrParams*>(private_->params.get());
  return nullptr;
}

const WebCryptoAesKeyGenParams* WebCryptoAlgorithm::AesKeyGenParams() const {
  DCHECK(!IsNull());
  if (ParamsType() == kWebCryptoAlgorithmParamsTypeAesKeyGenParams)
    return static_cast<WebCryptoAesKeyGenParams*>(private_->params.get());
  return nullptr;
}

const WebCryptoHmacImportParams* WebCryptoAlgorithm::HmacImportParams() const {
  DCHECK(!IsNull());
  if (ParamsType() == kWebCryptoAlgorithmParamsTypeHmacImportParams)
    return static_cast<WebCryptoHmacImportParams*>(private_->params.get());
  return nullptr;
}

const WebCryptoHmacKeyGenParams* WebCryptoAlgorithm::HmacKeyGenParams() const {
  DCHECK(!IsNull());
  if (ParamsType() == kWebCryptoAlgorithmParamsTypeHmacKeyGenParams)
    return static_cast<WebCryptoHmacKeyGenParams*>(private_->params.get());
  return nullptr;
}

const WebCryptoAesGcmParams* WebCryptoAlgorithm::AesGcmParams() const {
  DCHECK(!IsNull());
  if (ParamsType() == kWebCryptoAlgorithmParamsTypeAesGcmParams)
    return static_cast<WebCryptoAesGcmParams*>(private_->params.get());
  return nullptr;
}

const WebCryptoRsaOaepParams* WebCryptoAlgorithm::RsaOaepParams() const {
  DCHECK(!IsNull());
  if (ParamsType() == kWebCryptoAlgorithmParamsTypeRsaOaepParams)
    return static_cast<WebCryptoRsaOaepParams*>(private_->params.get());
  return nullptr;
}

const WebCryptoRsaHashedImportParams*
WebCryptoAlgorithm::RsaHashedImportParams() const {
  DCHECK(!IsNull());
  if (ParamsType() == kWebCryptoAlgorithmParamsTypeRsaHashedImportParams)
    return static_cast<WebCryptoRsaHashedImportParams*>(private_->params.get());
  return nullptr;
}

const WebCryptoRsaHashedKeyGenParams*
WebCryptoAlgorithm::RsaHashedKeyGenParams() const {
  DCHECK(!IsNull());
  if (ParamsType() == kWebCryptoAlgorithmParamsTypeRsaHashedKeyGenParams)
    return static_cast<WebCryptoRsaHashedKeyGenParams*>(private_->params.get());
  return nullptr;
}

const WebCryptoRsaPssParams* WebCryptoAlgorithm::RsaPssParams() const {
  DCHECK(!IsNull());
  if (ParamsType() == kWebCryptoAlgorithmParamsTypeRsaPssParams)
    return static_cast<WebCryptoRsaPssParams*>(private_->params.get());
  return nullptr;
}

const WebCryptoEcdsaParams* WebCryptoAlgorithm::EcdsaParams() const {
  DCHECK(!IsNull());
  if (ParamsType() == kWebCryptoAlgorithmParamsTypeEcdsaParams)
    return static_cast<WebCryptoEcdsaParams*>(private_->params.get());
  return nullptr;
}

const WebCryptoEcKeyGenParams* WebCryptoAlgorithm::EcKeyGenParams() const {
  DCHECK(!IsNull());
  if (ParamsType() == kWebCryptoAlgorithmParamsTypeEcKeyGenParams)
    return static_cast<WebCryptoEcKeyGenParams*>(private_->params.get());
  return nullptr;
}

const WebCryptoEcKeyImportParams* WebCryptoAlgorithm::EcKeyImportParams()
    const {
  DCHECK(!IsNull());
  if (ParamsType() == kWebCryptoAlgorithmParamsTypeEcKeyImportParams)
    return static_cast<WebCryptoEcKeyImportParams*>(private_->params.get());
  return nullptr;
}

const WebCryptoEcdhKeyDeriveParams* WebCryptoAlgorithm::EcdhKeyDeriveParams()
    const {
  DCHECK(!IsNull());
  if (ParamsType() == kWebCryptoAlgorithmParamsTypeEcdhKeyDeriveParams)
    return static_cast<WebCryptoEcdhKeyDeriveParams*>(private_->params.get());
  return nullptr;
}

const WebCryptoAesDerivedKeyParams* WebCryptoAlgorithm::AesDerivedKeyParams()
    const {
  DCHECK(!IsNull());
  if (ParamsType() == kWebCryptoAlgorithmParamsTypeAesDerivedKeyParams)
    return static_cast<WebCryptoAesDerivedKeyParams*>(private_->params.get());
  return nullptr;
}

const WebCryptoHkdfParams* WebCryptoAlgorithm::HkdfParams() const {
  DCHECK(!IsNull());
  if (ParamsType() == kWebCryptoAlgorithmParamsTypeHkdfParams)
    return static_cast<WebCryptoHkdfParams*>(private_->params.get());
  return nullptr;
}

const WebCryptoPbkdf2Params* WebCryptoAlgorithm::Pbkdf2Params() const {
  DCHECK(!IsNull());
  if (ParamsType() == kWebCryptoAlgorithmParamsTypePbkdf2Params)
    return static_cast<WebCryptoPbkdf2Params*>(private_->params.get());
  return nullptr;
}

bool WebCryptoAlgorithm::IsHash(WebCryptoAlgorithmId id) {
  switch (id) {
    case kWebCryptoAlgorithmIdSha1:
    case kWebCryptoAlgorithmIdSha256:
    case kWebCryptoAlgorithmIdSha384:
    case kWebCryptoAlgorithmIdSha512:
      return true;
    case kWebCryptoAlgorithmIdAesCbc:
    case kWebCryptoAlgorithmIdHmac:
    case kWebCryptoAlgorithmIdRsaSsaPkcs1v1_5:
    case kWebCryptoAlgorithmIdAesGcm:
    case kWebCryptoAlgorithmIdRsaOaep:
    case kWebCryptoAlgorithmIdAesCtr:
    case kWebCryptoAlgorithmIdAesKw:
    case kWebCryptoAlgorithmIdRsaPss:
    case kWebCryptoAlgorithmIdEcdsa:
    case kWebCryptoAlgorithmIdEcdh:
    case kWebCryptoAlgorithmIdHkdf:
    case kWebCryptoAlgorithmIdPbkdf2:
    case kWebCryptoAlgorithmIdEd25519:
    case kWebCryptoAlgorithmIdX25519:
      break;
  }
  return false;
}

bool WebCryptoAlgorithm::IsKdf(WebCryptoAlgorithmId id) {
  switch (id) {
    case kWebCryptoAlgorithmIdHkdf:
    case kWebCryptoAlgorithmIdPbkdf2:
      return true;
    case kWebCryptoAlgorithmIdSha1:
    case kWebCryptoAlgorithmIdSha256:
    case kWebCryptoAlgorithmIdSha384:
    case kWebCryptoAlgorithmIdSha512:
    case kWebCryptoAlgorithmIdAesCbc:
    case kWebCryptoAlgorithmIdHmac:
    case kWebCryptoAlgorithmIdRsaSsaPkcs1v1_5:
    case kWebCryptoAlgorithmIdAesGcm:
    case kWebCryptoAlgorithmIdRsaOaep:
    case kWebCryptoAlgorithmIdAesCtr:
    case kWebCryptoAlgorithmIdAesKw:
    case kWebCryptoAlgorithmIdRsaPss:
    case kWebCryptoAlgorithmIdEcdsa:
    case kWebCryptoAlgorithmIdEcdh:
    case kWebCryptoAlgorithmIdEd25519:
    case kWebCryptoAlgorithmIdX25519:
      break;
  }
  return false;
}

void WebCryptoAlgorithm::Assign(const WebCryptoAlgorithm& other) {
  private_ = other.private_;
}

void WebCryptoAlgorithm::Reset() {
  private_.Reset();
}

}  // namespace blink

"""

```