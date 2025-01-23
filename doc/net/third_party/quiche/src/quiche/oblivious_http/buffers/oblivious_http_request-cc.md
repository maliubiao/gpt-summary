Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `oblivious_http_request.cc` file within the Chromium network stack. This involves identifying its purpose, potential interactions with JavaScript, logical reasoning with input/output, common errors, and debugging steps.

**2. Initial Code Scan and Keyword Identification:**

I started by scanning the code for key terms and patterns:

* **Namespaces:** `quiche` (suggests a QUIC-related component), `oblivious_http`. This immediately tells me it's about a privacy-preserving HTTP mechanism.
* **Classes:** `ObliviousHttpRequest`, `Context`, `ObliviousHttpHeaderKeyConfig`. This indicates the core data structures and supporting configurations.
* **Methods:** `CreateServerObliviousRequest`, `CreateClientObliviousRequest`, `EncapsulateWithSeed`, `EncapsulateAndSerialize`, `GetPlaintextData`. These are the main actions the class performs.
* **Cryptographic Primitives:** `EVP_HPKE_CTX`, `EVP_HPKE_KEY`. This confirms it's dealing with Hybrid Public Key Encryption (HPKE).
* **Data Handling:** `std::string`, `absl::string_view`, `QuicheDataReader`. This points to how request data is stored and processed.
* **Error Handling:** `absl::StatusOr`, `absl::InvalidArgumentError`, `SslErrorAsStatus`. This highlights how errors are managed.
* **Comments:**  The comments provide valuable context, especially the one linking to the OHTTP draft.

**3. Dissecting Key Methods:**

I focused on understanding the core functionalities by examining the methods:

* **`CreateServerObliviousRequest`:**  The name strongly suggests this is for the server-side processing of an Oblivious HTTP request. It takes encrypted data, a gateway key, and key configuration. It performs HPKE decryption using the gateway's private key.
* **`CreateClientObliviousRequest`:**  Likely for the client-side, creating an OHTTP request. It takes plaintext, the server's public key, and key configuration. It performs HPKE encryption.
* **`EncapsulateWithSeed`:**  A variation of the client-side request creation, allowing for a deterministic encryption process using a `seed`. This is often used for testing.
* **`EncapsulateAndSerialize`:**  Combines the encrypted data with other metadata (like the encapsulated key) into a final serialized request format. The comment referencing the OHTTP draft is crucial here.
* **`GetPlaintextData`:**  Returns the original plaintext (for clients) or the decrypted plaintext (for servers).

**4. Identifying Functionality:**

Based on the method analysis, I concluded that the file's primary function is to handle the creation, processing (encryption/decryption), and serialization of Oblivious HTTP requests.

**5. Considering JavaScript Interaction:**

I considered how a browser (which uses JavaScript) might interact with this C++ code. The crucial link is the network stack. JavaScript's `fetch` API (or similar mechanisms) would be used to initiate network requests. The browser's networking components (written in C++, including this code) would then handle the OHTTP specifics.

* **Client-side:** JavaScript would provide the plaintext request body and the target server's public key. The C++ code would use this information to encrypt and format the OHTTP request.
* **Server-side:**  The server's C++ networking code would receive the OHTTP request, and this file would be used to decrypt the request body.

**6. Logical Reasoning and Examples:**

I then thought about concrete examples:

* **Client-side (Encryption):** What are the inputs (plaintext, public key, config)? What's the output (serialized OHTTP request)? I visualized the HPKE process and the resulting structure.
* **Server-side (Decryption):**  What are the inputs (serialized OHTTP request, private key, config)? What's the output (decrypted plaintext)?  I mentally reversed the encryption process.

**7. Common Errors:**

I considered the common pitfalls when dealing with cryptography and network protocols:

* **Incorrect Keys:** Using the wrong public/private key pair would lead to decryption failures.
* **Mismatched Configurations:**  If the client and server don't agree on the HPKE parameters (KEM, KDF, AEAD), decryption will fail.
* **Data Corruption:**  Any modification of the encrypted data would likely cause decryption errors.
* **Incorrect Serialization:**  If the client doesn't correctly format the OHTTP request, the server won't be able to parse it.

**8. Debugging Steps and User Actions:**

I traced the path a user's request might take to reach this code:

1. User initiates a request in a browser (JavaScript).
2. The browser detects the target URL requires Oblivious HTTP.
3. The browser's network stack (C++) is invoked.
4. The `CreateClientObliviousRequest` function (or similar) in this file is called to encrypt the request.
5. The request is sent over the network.
6. On the server, the request is received by the server's network stack.
7. The `CreateServerObliviousRequest` function in this file is called to decrypt the request.

This step-by-step process helps identify where things might go wrong and provides debugging clues.

**9. Structuring the Answer:**

Finally, I organized the information into clear sections based on the prompt's requirements: Functionality, JavaScript Relationship, Logical Reasoning, Common Errors, and Debugging. I used clear language and provided specific examples to illustrate the concepts.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too heavily on the cryptographic details. I then realized the importance of explaining the broader OHTTP context and how it fits within the networking stack.
* I made sure to explicitly link the C++ code to the JavaScript layer via the browser's network stack.
* I refined the error examples to be more concrete and relatable.
* I ensured the debugging steps were logical and followed the flow of a network request.

By following this structured approach, I could systematically analyze the code and generate a comprehensive and informative answer that addresses all aspects of the prompt.这个文件 `oblivious_http_request.cc` 是 Chromium 网络栈中 QUIC 库的一部分，专门处理 **Oblivious HTTP (OHTTP)** 请求的创建、封装、解封装和序列化。

以下是它的主要功能分解：

**核心功能:**

1. **创建 Oblivious HTTP 请求 (客户端):**
   - `CreateClientObliviousRequest`:  接收明文的 HTTP 请求负载 (`plaintext_payload`) 和服务器的 HPKE 公钥 (`hpke_public_key`) 以及相关的配置信息 (`ObliviousHttpHeaderKeyConfig`)。
   - 使用 HPKE (Hybrid Public Key Encryption) 对请求负载进行加密，生成密文 (`request_ciphertext_`) 和一个用于密钥协商的封装密钥 (`encapsulated_key_`)。
   - 可选地使用 `CreateClientWithSeedForTesting` 或 `EncapsulateWithSeed` 方法，允许在测试场景下使用种子来使加密过程可预测。

2. **解封装 Oblivious HTTP 请求 (服务端):**
   - `CreateServerObliviousRequest`: 接收加密后的 OHTTP 数据 (`encrypted_data`)、网关/服务器的 HPKE 私钥 (`gateway_key`) 和配置信息。
   - 从 `encrypted_data` 中提取封装密钥。
   - 使用服务器的私钥和封装密钥，利用 HPKE 对密文进行解密，恢复出原始的明文请求负载 (`request_plaintext_`)。

3. **封装和序列化 Oblivious HTTP 请求:**
   - `EncapsulateAndSerialize`:  将 OHTTP 请求的各个部分（配置头部、封装密钥、加密后的请求体）组合成一个可以发送的网络数据包。
   -  格式通常为 `[header, encapsulated_key, ciphertext]`，符合 OHTTP 草案规范。

4. **获取明文数据:**
   - `GetPlaintextData`:  返回请求的明文数据。对于客户端创建的请求，返回的是客户端提供的原始明文；对于服务端解封装的请求，返回的是解密后的明文。

**与 JavaScript 的关系及举例:**

这个 C++ 文件本身不直接包含 JavaScript 代码，但它是 Chromium 网络栈的一部分，而浏览器中的网络请求通常由 JavaScript 发起。

**举例说明:**

假设一个使用了 OHTTP 的网站，用户在浏览器中点击一个链接或提交一个表单：

1. **JavaScript 发起请求:**  浏览器中的 JavaScript 代码会使用 `fetch` API 或 `XMLHttpRequest` 发起一个网络请求，目标 URL 指向一个 OHTTP 中继或最终服务器。

   ```javascript
   fetch('https://relay.example/resource', {
       method: 'POST',
       body: '敏感数据', // 这部分是明文的 HTTP 请求体
       headers: {
           'Content-Type': 'text/plain'
           // ... 其他头部
       }
   }).then(response => {
       // 处理响应
   });
   ```

2. **C++ 代码介入 (客户端):** 当浏览器确定这是一个需要使用 OHTTP 的请求时，Chromium 的网络栈会调用 `ObliviousHttpRequest::CreateClientObliviousRequest` 或其变体。
   - JavaScript 传递的 `body` (`'敏感数据'`) 会作为 `plaintext_payload` 传入。
   - 服务器的 HPKE 公钥会通过某种方式（例如，通过 DNS 查询获取的 `_ohttp._udp` 记录）传递给 C++ 代码。
   - `ObliviousHttpRequest` 对象会被创建，其中包含了加密后的请求体。
   - `EncapsulateAndSerialize` 方法会被调用，生成最终要发送到 `https://relay.example/resource` 的加密后的 OHTTP 请求。

3. **网络传输:**  加密后的 OHTTP 请求通过网络发送出去。

4. **C++ 代码介入 (服务端):**  OHTTP 中继服务器或最终服务器接收到请求后，Chromium 的网络栈（如果服务器也使用了 Chromium 或类似的 OHTTP 实现）会调用 `ObliviousHttpRequest::CreateServerObliviousRequest`。
   - 接收到的加密数据作为 `encrypted_data` 传入。
   - 服务器的 HPKE 私钥被用于解密。
   - `ObliviousHttpRequest` 对象被创建，其 `request_plaintext_` 成员包含了原始的 `'敏感数据'`。

**逻辑推理 (假设输入与输出):**

**场景 1: 客户端创建请求**

* **假设输入:**
    * `plaintext_payload`: "GET /sensitive-data HTTP/1.1\r\nHost: example.com\r\n\r\n"
    * `hpke_public_key`:  一个有效的 HPKE 公钥的二进制表示 (例如，从服务器的 `_ohttp._udp` DNS 记录中获取)。
    * `ohttp_key_config`: 包含了 HPKE 算法套件等配置信息的对象。
    * `request_label`:  一个用于上下文绑定的字符串，例如请求的 URL 路径。

* **预期输出:**
    * 一个 `ObliviousHttpRequest` 对象，其中包含：
        * `request_ciphertext_`:  `plaintext_payload` 使用 `hpke_public_key` 加密后的密文。
        * `oblivious_http_request_context_->encapsulated_key_`:  HPKE 密钥协商过程中生成的封装密钥。
    * 调用 `EncapsulateAndSerialize()` 应该返回一个类似 `[0x01, 封装密钥, 加密后的请求体]` 的二进制字符串。

**场景 2: 服务端解封装请求**

* **假设输入:**
    * `encrypted_data`:  一个客户端发送过来的、符合 OHTTP 格式的二进制数据，例如 `[0x01, 封装密钥, 加密后的请求体]`.
    * `gateway_key`:  服务器持有的与客户端使用的公钥配对的 HPKE 私钥。
    * `ohttp_key_config`: 与客户端创建请求时相同的配置信息。
    * `request_label`:  与客户端创建请求时使用的相同的 `request_label`。

* **预期输出:**
    * 一个 `ObliviousHttpRequest` 对象，其中包含：
        * `request_plaintext_`: 解密后的字符串 "GET /sensitive-data HTTP/1.1\r\nHost: example.com\r\n\r\n"。

**用户或编程常见的使用错误:**

1. **客户端使用错误的 HPKE 公钥:**  如果客户端使用了错误的公钥进行加密，服务端使用对应的私钥将无法解密，导致 `CreateServerObliviousRequest` 返回错误状态。

   ```c++
   // 错误示例：使用了错误的公钥
   auto request_or = ObliviousHttpRequest::CreateClientObliviousRequest(
       "...", wrong_hpke_public_key, ohttp_key_config, "...");
   if (!request_or.ok()) {
       // 错误：解密将会失败
   }
   ```

2. **服务端使用错误的 HPKE 私钥:**  如果服务端配置了错误的私钥，即使收到了正确的加密数据，也无法成功解密。

   ```c++
   // 错误示例：使用了错误的私钥
   auto request_or = ObliviousHttpRequest::CreateServerObliviousRequest(
       encrypted_data, wrong_gateway_key, ohttp_key_config, "...");
   if (!request_or.ok()) {
       // 错误：解密失败
   }
   ```

3. **配置信息不匹配:**  客户端和服务端使用的 `ObliviousHttpHeaderKeyConfig` 对象中的 HPKE 算法套件（KEM, KDF, AEAD）必须一致，否则密钥协商和加解密会失败。

   ```c++
   // 错误示例：客户端和服务端使用了不同的配置
   ObliviousHttpHeaderKeyConfig client_config;
   ObliviousHttpHeaderKeyConfig server_config;
   // ... 修改了 server_config 的某些参数

   auto client_request_or = ObliviousHttpRequest::CreateClientObliviousRequest(
       "...", public_key, client_config, "...");

   auto server_request_or = ObliviousHttpRequest::CreateServerObliviousRequest(
       encrypted_data, private_key, server_config, "..."); // 解密可能会失败
   ```

4. **篡改加密数据:**  如果客户端发送的加密数据在传输过程中被篡改，服务端解密时会失败。

5. **在调用 `ReleaseContext()` 后尝试使用上下文:**  `EncapsulateAndSerialize` 方法内部依赖于 `oblivious_http_request_context_`，如果在调用 `ReleaseContext()` 后调用此方法会导致程序错误。

   ```c++
   ObliviousHttpRequest request = // ... 创建请求
   request.ReleaseContext();
   std::string serialized_request = request.EncapsulateAndSerialize(); // 错误：context 已被释放
   ```

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在浏览器中访问一个使用了 OHTTP 保护的网站 `https://ohttp.example.com/secure-page`。

1. **用户在浏览器地址栏输入 `https://ohttp.example.com/secure-page` 并按下回车键。**
2. **浏览器解析 URL 并确定需要建立连接。**
3. **浏览器检查是否需要使用 Oblivious HTTP。** 这可能通过以下方式确定：
   - 该网站的配置指示需要使用 OHTTP。
   - 浏览器缓存了之前与该网站交互的 OHTTP 信息。
   - 浏览器可能首先尝试不使用 OHTTP 连接，如果失败，则回退到 OHTTP。
4. **浏览器需要获取服务器的 HPKE 公钥。** 这通常通过查询 DNS 的 `_ohttp._udp.ohttp.example.com` 记录来完成。该记录会包含服务器的 OHTTP 配置，包括 HPKE 公钥。
5. **一旦获取到公钥，浏览器会准备 Oblivious HTTP 请求。**
6. **当 JavaScript 代码（例如，页面上的脚本）发起一个需要使用 OHTTP 的 `fetch` 请求时，或者浏览器自身需要获取资源时：**
   - JavaScript 代码调用 `fetch` API，指定请求的 URL、方法、头部和主体。
   - Chromium 的网络栈拦截该请求，并识别出需要使用 OHTTP。
   - **`ObliviousHttpRequest::CreateClientObliviousRequest` (或其变体) 被调用。**
     - JavaScript 提供的请求体（`body`）作为 `plaintext_payload` 传入。
     - 从 DNS 查询获取的 HPKE 公钥作为 `hpke_public_key` 传入。
     - 相关的 OHTTP 配置信息被传递给 `ohttp_key_config`。
     - 一个 `ObliviousHttpRequest` 对象被创建，包含了加密后的请求。
   - **`ObliviousHttpRequest::EncapsulateAndSerialize` 被调用。**
     -  将加密后的请求封装成 OHTTP 格式的二进制数据。
7. **封装后的 OHTTP 请求被发送到 OHTTP 中继服务器或直接发送到最终服务器（取决于部署方式）。**
8. **在接收端（中继或最终服务器），如果使用了 Chromium 或类似的 OHTTP 实现：**
   - 网络栈接收到 OHTTP 请求。
   - **`ObliviousHttpRequest::CreateServerObliviousRequest` 被调用。**
     - 接收到的 OHTTP 数据作为 `encrypted_data` 传入。
     - 服务器配置的 HPKE 私钥作为 `gateway_key` 传入。
     - 相应的 OHTTP 配置信息作为 `ohttp_key_config` 传入。
   - `CreateServerObliviousRequest` 尝试解密请求。如果成功，可以获取原始的 HTTP 请求信息。

**调试线索:**

如果在调试过程中遇到了与 OHTTP 相关的问题，例如请求失败或解密错误，可以检查以下内容：

- **DNS 配置:** 确保服务器的 `_ohttp._udp` 记录配置正确，客户端能够正确获取到 HPKE 公钥。
- **客户端和服务器的 HPKE 密钥:** 确保客户端使用的公钥与服务器配置的私钥是配对的。
- **HPKE 算法套件:**  检查客户端和服务端使用的 KEM, KDF, AEAD 算法是否一致。
- **请求格式:** 确保客户端生成的 OHTTP 请求格式符合规范。
- **网络传输:**  检查网络传输过程中是否发生了数据损坏或篡改。
- **错误日志:** 查看 Chromium 或服务器的错误日志，可能会有与 OHTTP 加解密相关的错误信息。
- **抓包分析:** 使用网络抓包工具（如 Wireshark）查看客户端发送的 OHTTP 请求和服务器的响应，分析数据包的结构和内容。

理解 `oblivious_http_request.cc` 的功能以及它在网络请求生命周期中的位置，对于调试和理解 OHTTP 的工作原理至关重要。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/oblivious_http/buffers/oblivious_http_request.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
#include "quiche/oblivious_http/buffers/oblivious_http_request.h"

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/hpke.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_crypto_logging.h"

namespace quiche {
// Ctor.
ObliviousHttpRequest::Context::Context(
    bssl::UniquePtr<EVP_HPKE_CTX> hpke_context, std::string encapsulated_key)
    : hpke_context_(std::move(hpke_context)),
      encapsulated_key_(std::move(encapsulated_key)) {}

// Ctor.
ObliviousHttpRequest::ObliviousHttpRequest(
    bssl::UniquePtr<EVP_HPKE_CTX> hpke_context, std::string encapsulated_key,
    const ObliviousHttpHeaderKeyConfig& ohttp_key_config,
    std::string req_ciphertext, std::string req_plaintext)
    : oblivious_http_request_context_(absl::make_optional(
          Context(std::move(hpke_context), std::move(encapsulated_key)))),
      key_config_(ohttp_key_config),
      request_ciphertext_(std::move(req_ciphertext)),
      request_plaintext_(std::move(req_plaintext)) {}

// Request Decapsulation.
absl::StatusOr<ObliviousHttpRequest>
ObliviousHttpRequest::CreateServerObliviousRequest(
    absl::string_view encrypted_data, const EVP_HPKE_KEY& gateway_key,
    const ObliviousHttpHeaderKeyConfig& ohttp_key_config,
    absl::string_view request_label) {
  if (EVP_HPKE_KEY_kem(&gateway_key) == nullptr) {
    return absl::InvalidArgumentError(
        "Invalid input param. Failed to import gateway_key.");
  }
  bssl::UniquePtr<EVP_HPKE_CTX> gateway_ctx(EVP_HPKE_CTX_new());
  if (gateway_ctx == nullptr) {
    return SslErrorAsStatus("Failed to initialize Gateway/Server's Context.");
  }

  QuicheDataReader reader(encrypted_data);

  auto is_hdr_ok = ohttp_key_config.ParseOhttpPayloadHeader(reader);
  if (!is_hdr_ok.ok()) {
    return is_hdr_ok;
  }

  size_t enc_key_len = EVP_HPKE_KEM_enc_len(EVP_HPKE_KEY_kem(&gateway_key));

  absl::string_view enc_key_received;
  if (!reader.ReadStringPiece(&enc_key_received, enc_key_len)) {
    return absl::FailedPreconditionError(absl::StrCat(
        "Failed to extract encapsulation key of expected len=", enc_key_len,
        "from payload."));
  }
  std::string info =
      ohttp_key_config.SerializeRecipientContextInfo(request_label);
  if (!EVP_HPKE_CTX_setup_recipient(
          gateway_ctx.get(), &gateway_key, ohttp_key_config.GetHpkeKdf(),
          ohttp_key_config.GetHpkeAead(),
          reinterpret_cast<const uint8_t*>(enc_key_received.data()),
          enc_key_received.size(),
          reinterpret_cast<const uint8_t*>(info.data()), info.size())) {
    return SslErrorAsStatus("Failed to setup recipient context");
  }

  absl::string_view ciphertext_received = reader.ReadRemainingPayload();
  // Decrypt the message.
  std::string decrypted(ciphertext_received.size(), '\0');
  size_t decrypted_len;
  if (!EVP_HPKE_CTX_open(
          gateway_ctx.get(), reinterpret_cast<uint8_t*>(decrypted.data()),
          &decrypted_len, decrypted.size(),
          reinterpret_cast<const uint8_t*>(ciphertext_received.data()),
          ciphertext_received.size(), nullptr, 0)) {
    return SslErrorAsStatus("Failed to decrypt.",
                            absl::StatusCode::kInvalidArgument);
  }
  decrypted.resize(decrypted_len);
  return ObliviousHttpRequest(
      std::move(gateway_ctx), std::string(enc_key_received), ohttp_key_config,
      std::string(ciphertext_received), std::move(decrypted));
}

// Request Encapsulation.
absl::StatusOr<ObliviousHttpRequest>
ObliviousHttpRequest::CreateClientObliviousRequest(
    std::string plaintext_payload, absl::string_view hpke_public_key,
    const ObliviousHttpHeaderKeyConfig& ohttp_key_config,
    absl::string_view request_label) {
  return EncapsulateWithSeed(std::move(plaintext_payload), hpke_public_key,
                             ohttp_key_config, /*seed=*/"", request_label);
}

absl::StatusOr<ObliviousHttpRequest>
ObliviousHttpRequest::CreateClientWithSeedForTesting(
    std::string plaintext_payload, absl::string_view hpke_public_key,
    const ObliviousHttpHeaderKeyConfig& ohttp_key_config,
    absl::string_view seed, absl::string_view request_label) {
  return ObliviousHttpRequest::EncapsulateWithSeed(
      std::move(plaintext_payload), hpke_public_key, ohttp_key_config, seed,
      request_label);
}

absl::StatusOr<ObliviousHttpRequest> ObliviousHttpRequest::EncapsulateWithSeed(
    std::string plaintext_payload, absl::string_view hpke_public_key,
    const ObliviousHttpHeaderKeyConfig& ohttp_key_config,
    absl::string_view seed, absl::string_view request_label) {
  if (plaintext_payload.empty() || hpke_public_key.empty()) {
    return absl::InvalidArgumentError("Invalid input.");
  }
  // Initialize HPKE key and context.
  bssl::UniquePtr<EVP_HPKE_KEY> client_key(EVP_HPKE_KEY_new());
  if (client_key == nullptr) {
    return SslErrorAsStatus("Failed to initialize HPKE Client Key.");
  }
  bssl::UniquePtr<EVP_HPKE_CTX> client_ctx(EVP_HPKE_CTX_new());
  if (client_ctx == nullptr) {
    return SslErrorAsStatus("Failed to initialize HPKE Client Context.");
  }
  // Setup the sender (client)
  std::string encapsulated_key(EVP_HPKE_MAX_ENC_LENGTH, '\0');
  size_t enc_len;
  std::string info =
      ohttp_key_config.SerializeRecipientContextInfo(request_label);
  if (seed.empty()) {
    if (!EVP_HPKE_CTX_setup_sender(
            client_ctx.get(),
            reinterpret_cast<uint8_t*>(encapsulated_key.data()), &enc_len,
            encapsulated_key.size(), ohttp_key_config.GetHpkeKem(),
            ohttp_key_config.GetHpkeKdf(), ohttp_key_config.GetHpkeAead(),
            reinterpret_cast<const uint8_t*>(hpke_public_key.data()),
            hpke_public_key.size(),
            reinterpret_cast<const uint8_t*>(info.data()), info.size())) {
      return SslErrorAsStatus(
          "Failed to setup HPKE context with given public key param "
          "hpke_public_key.");
    }
  } else {
    if (!EVP_HPKE_CTX_setup_sender_with_seed_for_testing(
            client_ctx.get(),
            reinterpret_cast<uint8_t*>(encapsulated_key.data()), &enc_len,
            encapsulated_key.size(), ohttp_key_config.GetHpkeKem(),
            ohttp_key_config.GetHpkeKdf(), ohttp_key_config.GetHpkeAead(),
            reinterpret_cast<const uint8_t*>(hpke_public_key.data()),
            hpke_public_key.size(),
            reinterpret_cast<const uint8_t*>(info.data()), info.size(),
            reinterpret_cast<const uint8_t*>(seed.data()), seed.size())) {
      return SslErrorAsStatus(
          "Failed to setup HPKE context with given public key param "
          "hpke_public_key and seed.");
    }
  }
  encapsulated_key.resize(enc_len);
  std::string ciphertext(
      plaintext_payload.size() + EVP_HPKE_CTX_max_overhead(client_ctx.get()),
      '\0');
  size_t ciphertext_len;
  if (!EVP_HPKE_CTX_seal(
          client_ctx.get(), reinterpret_cast<uint8_t*>(ciphertext.data()),
          &ciphertext_len, ciphertext.size(),
          reinterpret_cast<const uint8_t*>(plaintext_payload.data()),
          plaintext_payload.size(), nullptr, 0)) {
    return SslErrorAsStatus(
        "Failed to encrypt plaintext_payload with given public key param "
        "hpke_public_key.");
  }
  ciphertext.resize(ciphertext_len);
  if (encapsulated_key.empty() || ciphertext.empty()) {
    return absl::InternalError(absl::StrCat(
        "Failed to generate required data: ",
        (encapsulated_key.empty() ? "encapsulated key is empty" : ""),
        (ciphertext.empty() ? "encrypted data is empty" : ""), "."));
  }

  return ObliviousHttpRequest(
      std::move(client_ctx), std::move(encapsulated_key), ohttp_key_config,
      std::move(ciphertext), std::move(plaintext_payload));
}

// Request Serialize.
// Builds request=[hdr, enc, ct].
// https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-03.html#section-4.1-4.5
std::string ObliviousHttpRequest::EncapsulateAndSerialize() const {
  if (!oblivious_http_request_context_.has_value()) {
    QUICHE_BUG(ohttp_encapsulate_after_context_extract)
        << "EncapsulateAndSerialize cannot be called after ReleaseContext()";
    return "";
  }
  return absl::StrCat(key_config_.SerializeOhttpPayloadHeader(),
                      oblivious_http_request_context_->encapsulated_key_,
                      request_ciphertext_);
}

// Returns Decrypted blob in the case of server, and returns plaintext used by
// the client while `CreateClientObliviousRequest`.
absl::string_view ObliviousHttpRequest::GetPlaintextData() const {
  return request_plaintext_;
}

}  // namespace quiche
```