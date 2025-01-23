Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

1. **Understand the Goal:** The primary goal is to explain the functionality of the provided C++ code file (`oblivious_http_response.cc`) within the Chromium networking stack. We need to cover its purpose, relationship to JavaScript (if any), logic with input/output examples, potential user errors, and how a user might reach this code during debugging.

2. **Initial Code Scan and Keyword Recognition:**  The first step is to quickly scan the code and identify key terms and concepts. Words like "ObliviousHttpResponse," "encrypted_data," "plaintext," "HPKE," "AEAD," "HKDF," "encapsulation," "decapsulation," and "response_nonce" immediately stand out. The file path itself, `net/third_party/quiche/src/quiche/oblivious_http/buffers/`, indicates this is related to the Oblivious HTTP (OHTTP) protocol and likely involves buffering and processing HTTP responses.

3. **Identify Core Functionality:**  Based on the keywords and structure, it's clear the code deals with creating, encrypting, and decrypting OHTTP responses. The functions `CreateClientObliviousResponse` and `CreateServerObliviousResponse` are central, indicating client-side (decryption) and server-side (encryption) operations. The presence of `EncapsulateAndSerialize` and `GetPlaintextData` suggests serialization and access to the decrypted data.

4. **Trace the Encryption/Decryption Flow:** The comments within the code are extremely helpful. They explicitly outline the steps involved in response encapsulation and decapsulation according to the OHTTP specification. I would carefully read these comments and correlate them with the corresponding code. For example, the comments in `CreateClientObliviousResponse` like "Extract resp_nonce," "Build prk," "Derive aead_key," etc., provide a clear roadmap of the decryption process. Similarly, the comments in `CreateServerObliviousResponse` detail the encryption steps.

5. **Analyze Helper Functions:**  Functions like `GetCommonAeadParams` and `CommonOperationsToEncapDecap` appear to encapsulate reusable logic. Analyzing these helps to understand the common steps involved in both encryption and decryption, particularly the derivation of AEAD keys and nonces using HKDF.

6. **Look for JavaScript Interaction (or Lack Thereof):**  The code uses standard C++ features, BoringSSL for cryptography, and doesn't directly interact with any JavaScript APIs. Therefore, the relationship to JavaScript will be indirect. The key connection is that this C++ code will be part of the Chromium browser, which *renders* and *processes* web pages that might use JavaScript. OHTTP is a transport-level mechanism, so JavaScript would likely use higher-level fetch APIs or similar, and the browser's networking stack (including this code) would handle the underlying OHTTP details.

7. **Construct Input/Output Examples:**  To illustrate the logic, I would devise simple hypothetical scenarios. For encryption, a plaintext response and the request context are inputs, and the output is the serialized encrypted response. For decryption, the encrypted data and the request context are inputs, and the output is the plaintext response. It's important to note the role of the `ObliviousHttpRequest::Context`, which carries essential cryptographic information.

8. **Identify Potential User/Programming Errors:** Based on the code's preconditions and error checks (e.g., checking for null HPKE context, empty data), I can identify common mistakes. Forgetting to initialize the request context, providing incorrect key lengths, or attempting to decrypt without the correct context are all potential issues.

9. **Consider the Debugging Perspective:**  How would a developer end up looking at this code during debugging?  This involves thinking about the user's actions in the browser that might trigger OHTTP. Visiting a website that uses OHTTP, and encountering issues with response processing (e.g., failure to load resources) would be a typical scenario. Debugging tools in the browser's developer console or network inspection tools would lead a developer to investigate the network stack, potentially reaching this code.

10. **Structure the Explanation:**  Finally, organize the information into a clear and logical structure, covering the requested points: functionality, JavaScript relationship, input/output examples, user errors, and debugging context. Use clear language and provide specific examples where possible. The use of bullet points and headings makes the explanation easier to read and understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe JavaScript directly calls some OHTTP functions. **Correction:**  Realized OHTTP is lower-level and the interaction is likely through browser APIs.
* **Input/Output:** First thought of just providing types. **Refinement:** Realized providing example *data* (even if simplified) makes it clearer.
* **User Errors:**  Initially focused on just code errors. **Refinement:** Expanded to include user actions that might *lead* to those errors.
* **Debugging:** Initially just mentioned "debugging." **Refinement:**  Specified user actions and the tools they might use, providing a more concrete path.

By following this thought process, systematically analyzing the code, and considering the broader context of how it fits within the Chromium browser, I can generate a comprehensive and accurate explanation of the `oblivious_http_response.cc` file.
这个C++文件 `oblivious_http_response.cc` 是 Chromium 网络栈中 QUIC 协议库 (quiche) 的一部分，专门处理 **Oblivious HTTP (OHTTP) 响应** 的缓冲区操作。它的主要功能是实现 OHTTP 响应的 **加密 (Encapsulation)** 和 **解密 (Decapsulation)** 过程。

以下是该文件的详细功能列表：

**核心功能:**

1. **`ObliviousHttpResponse` 类的构造和管理:**  定义了 `ObliviousHttpResponse` 类，用于存储和操作 OHTTP 响应数据，包括加密后的数据和解密后的明文数据。

2. **客户端解密 (Decapsulation): `CreateClientObliviousResponse`:**
   - 接收加密的响应数据 (`encrypted_data`) 和一个包含请求上下文信息的 `ObliviousHttpRequest::Context` 对象。
   - 从加密数据中提取响应 nonce (`resp_nonce`)。
   - 使用 HKDF (基于 HMAC 的密钥派生函数) 从共享密钥（通过 HPKE 上下文导出）和响应 nonce 派生出用于 AEAD (Authenticated Encryption with Associated Data) 加密的密钥 (`aead_key`) 和 nonce (`aead_nonce`)。
   - 使用派生的密钥和 nonce，以及 AEAD 算法解密加密的响应负载。
   - 创建并返回一个包含原始加密数据和解密后明文数据的 `ObliviousHttpResponse` 对象。

3. **服务端加密 (Encapsulation): `CreateServerObliviousResponse`:**
   - 接收明文的响应负载 (`plaintext_payload`) 和一个包含请求上下文信息的 `ObliviousHttpRequest::Context` 对象。
   - 生成一个随机的响应 nonce (`response_nonce`)。
   - 使用 HKDF 从共享密钥（通过 HPKE 上下文导出）和生成的响应 nonce 派生出用于 AEAD 加密的密钥 (`aead_key`) 和 nonce (`aead_nonce`)。
   - 使用派生的密钥和 nonce，以及 AEAD 算法加密响应负载。
   - 将生成的响应 nonce 添加到加密数据的开头。
   - 创建并返回一个包含加密后的数据和原始明文数据的 `ObliviousHttpResponse` 对象。

4. **序列化: `EncapsulateAndSerialize`:**
   - 将加密后的响应数据（包括响应 nonce 和加密负载）拼接成一个字符串，用于网络传输。

5. **获取解密后的数据: `GetPlaintextData`:**
   - 返回解密后的明文响应负载。

6. **通用 AEAD 参数获取: `GetCommonAeadParams`:**
   - 从 `ObliviousHttpRequest::Context` 中获取 HPKE (Hybrid Public Key Encryption) 上下文，并根据配置的 AEAD 算法，获取 AEAD 密钥长度、nonce 长度以及用于密钥派生的 secret 长度。

7. **通用加密/解密操作: `CommonOperationsToEncapDecap`:**
   - 封装了客户端解密和服务端加密过程中共同的密钥派生步骤：
     - 从 HPKE 上下文中导出共享密钥。
     - 使用 HKDF 的 `Extract` 函数，结合导出的密钥和拼接的盐（encapsulated_key + response_nonce）生成伪随机密钥 (PRK)。
     - 使用 HKDF 的 `Expand` 函数，从 PRK 派生出 AEAD 密钥和 AEAD nonce。
     - 初始化 AEAD 上下文。

**与 JavaScript 功能的关系:**

该 C++ 文件本身不直接包含 JavaScript 代码，因此没有直接的 JavaScript 函数调用或交互。但是，它作为 Chromium 浏览器网络栈的一部分，其功能对于支持使用 Oblivious HTTP 协议的 Web 应用至关重要。

**举例说明:**

假设一个使用了 OHTTP 的网站，当浏览器发送一个 OHTTP 请求到服务端并收到响应时，以下过程会发生：

1. **JavaScript 发起请求:** 网页上的 JavaScript 代码使用 `fetch` API 或 XMLHttpRequest 发起一个请求。浏览器内部会识别该请求需要使用 OHTTP 协议。

2. **C++ 网络栈处理请求:** Chromium 的 C++ 网络栈会处理该请求，并根据 OHTTP 协议规范构建 OHTTP 请求。相关的代码可能在 `oblivious_http_request.cc` 中。

3. **服务端响应:** 服务端接收到 OHTTP 请求并处理，然后构建 OHTTP 响应。

4. **C++ 网络栈接收响应:** 浏览器接收到服务端返回的加密的 OHTTP 响应数据。

5. **`ObliviousHttpResponse::CreateClientObliviousResponse` 被调用:**  `oblivious_http_response.cc` 中的 `CreateClientObliviousResponse` 函数会被调用，传入接收到的加密数据以及与该请求相关的上下文信息。

6. **解密过程:**  `CreateClientObliviousResponse` 函数按照 OHTTP 规范执行解密步骤，包括提取 nonce、派生密钥和 nonce、使用 AEAD 解密等。

7. **JavaScript 获取解密后的数据:**  解密后的明文 HTTP 响应数据最终会传递回 JavaScript 代码，例如通过 `fetch` API 返回的 `Response` 对象，JavaScript 可以访问响应头、响应体等信息。

**逻辑推理与假设输入/输出:**

**假设输入 (客户端解密):**

- `encrypted_data`:  一段包含响应 nonce 和加密负载的二进制数据，例如：`\x10\x20\x30\x40\x50\x60\x70\x80\x90\xA0\xB0\xC0\xD0\xE0\xF0\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF` (前 16 字节是 nonce，后面是加密负载)
- `oblivious_http_request_context`: 一个包含 HPKE 上下文、encapsulated_key 等信息的对象。 假设其中 HPKE 上下文已经正确建立，并且包含协商好的密钥信息。

**假设输出 (客户端解密):**

- 如果解密成功，`CreateClientObliviousResponse` 会返回一个 `ObliviousHttpResponse` 对象，其中:
    - `encrypted_data_` 成员变量保存原始的加密数据。
    - `response_plaintext_` 成员变量保存解密后的明文 HTTP 响应，例如: `"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello, OHTTP!"`

- 如果解密失败（例如，使用了错误的密钥或 nonce），`CreateClientObliviousResponse` 会返回一个包含错误状态的 `absl::StatusOr` 对象。

**假设输入 (服务端加密):**

- `plaintext_payload`: 明文的 HTTP 响应负载，例如: `"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello, OHTTP!"`
- `oblivious_http_request_context`:  一个包含 HPKE 上下文等信息的对象。

**假设输出 (服务端加密):**

- 如果加密成功，`CreateServerObliviousResponse` 会返回一个 `ObliviousHttpResponse` 对象，其中:
    - `encrypted_data_` 成员变量保存加密后的数据，包括随机生成的 nonce 和加密后的负载，例如：`\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\x...encrypted_payload...`
    - `response_plaintext_` 成员变量保存原始的明文负载。

- 如果加密失败，`CreateServerObliviousResponse` 会返回一个包含错误状态的 `absl::StatusOr` 对象。

**用户或编程常见的使用错误:**

1. **未初始化请求上下文:** 在调用 `CreateClientObliviousResponse` 或 `CreateServerObliviousResponse` 之前，必须正确初始化 `ObliviousHttpRequest::Context` 对象，包括建立 HPKE 上下文。如果 `hpke_context_` 为空，会返回 `absl::FailedPreconditionError`。

   ```c++
   // 错误示例：未初始化上下文
   ObliviousHttpRequest::Context context;
   auto response_or = ObliviousHttpResponse::CreateClientObliviousResponse(encrypted_data, context, "resp");
   // response_or 会包含一个错误，因为 context.hpke_context_ 为空。
   ```

2. **错误的 `encapsulated_key` 长度:** `encapsulated_key_` 的长度必须与协商的 HPKE KEM (Key Encapsulation Mechanism) 的输出长度一致。如果长度不匹配，会返回 `absl::InvalidArgumentError`。

   ```c++
   // 错误示例：错误的 encapsulated_key 长度
   ObliviousHttpRequest::Context context;
   context.encapsulated_key_ = "invalid_length"; // 假设预期长度不是这个
   // ... 初始化 HPKE 上下文 ...
   auto response_or = ObliviousHttpResponse::CreateClientObliviousResponse(encrypted_data, context, "resp");
   // response_or 会包含一个关于 encapsulated_key 长度不匹配的错误。
   ```

3. **传入空的加密数据或明文负载:**  `CreateClientObliviousResponse` 和 `CreateServerObliviousResponse` 会检查输入的数据是否为空。如果为空，会返回 `absl::InvalidArgumentError`。

   ```c++
   // 错误示例：传入空的加密数据
   ObliviousHttpRequest::Context context;
   // ... 初始化上下文 ...
   auto response_or = ObliviousHttpResponse::CreateClientObliviousResponse("", context, "resp");
   // response_or 会包含一个关于 encrypted_data 为空的错误。
   ```

4. **AEAD 密钥或 nonce 推导失败:** 如果 HKDF 推导密钥或 nonce 的过程中发生错误（例如，HPKE 配置不支持），则会返回 `SslErrorAsStatus`。这通常意味着底层的 OpenSSL/BoringSSL 库返回了错误。

**用户操作如何一步步的到达这里，作为调试线索:**

假设用户在使用 Chromium 浏览器访问一个启用了 Oblivious HTTP 的网站，并遇到了页面加载错误或资源加载失败的问题。作为一名开发人员，在进行调试时，可能会按照以下步骤逐步深入到这个代码文件：

1. **用户报告问题:** 用户报告访问特定网站时出现问题。

2. **开发者检查网络请求:** 开发者使用 Chromium 的开发者工具 (DevTools) 的 "Network" 标签来检查网络请求。他们可能会看到一个或多个请求失败，状态码异常，或者请求类型显示为 "application/ohttp-req" 或 "application/ohttp-res"。

3. **怀疑 OHTTP 相关问题:** 如果请求或响应的 Content-Type 表明使用了 Oblivious HTTP，开发者会怀疑问题可能与 OHTTP 的加密或解密过程有关。

4. **查看 Chromium 网络栈日志:** 开发者可能会启用 Chromium 的网络栈日志（通过 `chrome://net-export/` 或命令行参数），以获取更详细的网络事件信息。日志中可能会包含与 HPKE 协商、AEAD 加密/解密相关的错误信息。

5. **设置断点或查看源代码:**  根据日志中的错误信息或对 OHTTP 协议的理解，开发者可能会怀疑响应处理过程中出现了问题。他们可能会在 Chromium 源代码中搜索与 "ObliviousHttpResponse" 相关的代码，或者在 `net/` 目录下找到 `oblivious_http` 相关的目录和文件。

6. **定位到 `oblivious_http_response.cc`:** 开发者最终会定位到 `oblivious_http_response.cc` 文件，并开始分析 `CreateClientObliviousResponse` 函数，因为它负责处理接收到的 OHTTP 响应的解密过程。

7. **设置断点进行调试:** 开发者可能会在 `CreateClientObliviousResponse` 函数的关键步骤（例如，提取 nonce、HKDF 推导、AEAD 解密）设置断点，以便查看中间变量的值，例如：
   - `encrypted_data` 的内容
   - 提取出的 `response_nonce`
   - 派生出的 `aead_key` 和 `aead_nonce`
   - AEAD 解密的结果
   - HPKE 上下文的状态

8. **分析错误原因:** 通过断点调试和查看日志，开发者可以确定是哪个环节出现了问题，例如：
   - HPKE 协商失败导致密钥不匹配。
   - 接收到的加密数据格式不正确。
   - AEAD 解密过程中出现错误，可能是由于密钥或 nonce 推导错误。

通过以上步骤，开发者可以逐步深入到 `oblivious_http_response.cc` 文件，并利用断点调试和日志分析来诊断与 OHTTP 响应处理相关的网络问题。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/oblivious_http/buffers/oblivious_http_response.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
#include "quiche/oblivious_http/buffers/oblivious_http_response.h"

#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/aead.h"
#include "openssl/hkdf.h"
#include "openssl/hpke.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/quiche_crypto_logging.h"
#include "quiche/common/quiche_random.h"
#include "quiche/oblivious_http/common/oblivious_http_header_key_config.h"

namespace quiche {
namespace {
// Generate a random string.
void random(QuicheRandom* quiche_random, char* dest, size_t len) {
  if (quiche_random == nullptr) {
    quiche_random = QuicheRandom::GetInstance();
  }
  quiche_random->RandBytes(dest, len);
}
}  // namespace

// Ctor.
ObliviousHttpResponse::ObliviousHttpResponse(std::string encrypted_data,
                                             std::string resp_plaintext)
    : encrypted_data_(std::move(encrypted_data)),
      response_plaintext_(std::move(resp_plaintext)) {}

// Response Decapsulation.
// 1. Extract resp_nonce
// 2. Build prk (pseudorandom key) using HKDF_Extract
// 3. Derive aead_key using HKDF_Labeled_Expand
// 4. Derive aead_nonce using HKDF_Labeled_Expand
// 5. Setup AEAD context and Decrypt.
// https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-03.html#section-4.2-4
absl::StatusOr<ObliviousHttpResponse>
ObliviousHttpResponse::CreateClientObliviousResponse(
    std::string encrypted_data,
    ObliviousHttpRequest::Context& oblivious_http_request_context,
    absl::string_view resp_label) {
  if (oblivious_http_request_context.hpke_context_ == nullptr) {
    return absl::FailedPreconditionError(
        "HPKE context wasn't initialized before proceeding with this Response "
        "Decapsulation on Client-side.");
  }
  size_t expected_key_len = EVP_HPKE_KEM_enc_len(
      EVP_HPKE_CTX_kem(oblivious_http_request_context.hpke_context_.get()));
  if (oblivious_http_request_context.encapsulated_key_.size() !=
      expected_key_len) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Invalid len for encapsulated_key arg. Expected:", expected_key_len,
        " Actual:", oblivious_http_request_context.encapsulated_key_.size()));
  }
  if (encrypted_data.empty()) {
    return absl::InvalidArgumentError("Empty encrypted_data input param.");
  }

  absl::StatusOr<CommonAeadParamsResult> aead_params_st =
      GetCommonAeadParams(oblivious_http_request_context);
  if (!aead_params_st.ok()) {
    return aead_params_st.status();
  }

  // secret_len = [max(Nn, Nk)] where Nk and Nn are the length of AEAD
  // key and nonce associated with HPKE context.
  // https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-03.html#section-4.2-2.1
  size_t secret_len = aead_params_st.value().secret_len;
  if (encrypted_data.size() < secret_len) {
    return absl::InvalidArgumentError(
        absl::StrCat("Invalid input response. Failed to parse required minimum "
                     "expected_len=",
                     secret_len, " bytes."));
  }
  // Extract response_nonce. Step 2
  // https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-03.html#section-4.2-2.2
  absl::string_view response_nonce =
      absl::string_view(encrypted_data).substr(0, secret_len);
  absl::string_view encrypted_response =
      absl::string_view(encrypted_data).substr(secret_len);

  // Steps (1, 3 to 5) + AEAD context SetUp before 6th step is performed in
  // CommonOperations.
  auto common_ops_st = CommonOperationsToEncapDecap(
      response_nonce, oblivious_http_request_context, resp_label,
      aead_params_st.value().aead_key_len,
      aead_params_st.value().aead_nonce_len, aead_params_st.value().secret_len);
  if (!common_ops_st.ok()) {
    return common_ops_st.status();
  }

  std::string decrypted(encrypted_response.size(), '\0');
  size_t decrypted_len;

  // Decrypt with initialized AEAD context.
  // response, error = Open(aead_key, aead_nonce, "", ct)
  // https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-03.html#section-4.2-6
  if (!EVP_AEAD_CTX_open(
          common_ops_st.value().aead_ctx.get(),
          reinterpret_cast<uint8_t*>(decrypted.data()), &decrypted_len,
          decrypted.size(),
          reinterpret_cast<const uint8_t*>(
              common_ops_st.value().aead_nonce.data()),
          aead_params_st.value().aead_nonce_len,
          reinterpret_cast<const uint8_t*>(encrypted_response.data()),
          encrypted_response.size(), nullptr, 0)) {
    return SslErrorAsStatus(
        "Failed to decrypt the response with derived AEAD key and nonce.");
  }
  decrypted.resize(decrypted_len);
  ObliviousHttpResponse oblivious_response(std::move(encrypted_data),
                                           std::move(decrypted));
  return oblivious_response;
}

// Response Encapsulation.
// Follows the Ohttp spec section-4.2 (Encapsulation of Responses) Ref
// https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-03.html#section-4.2
// Use HPKE context from BoringSSL to export a secret and use it to Seal (AKA
// encrypt) the response back to the Sender(client)
absl::StatusOr<ObliviousHttpResponse>
ObliviousHttpResponse::CreateServerObliviousResponse(
    std::string plaintext_payload,
    ObliviousHttpRequest::Context& oblivious_http_request_context,
    absl::string_view response_label, QuicheRandom* quiche_random) {
  if (oblivious_http_request_context.hpke_context_ == nullptr) {
    return absl::FailedPreconditionError(
        "HPKE context wasn't initialized before proceeding with this Response "
        "Encapsulation on Server-side.");
  }
  size_t expected_key_len = EVP_HPKE_KEM_enc_len(
      EVP_HPKE_CTX_kem(oblivious_http_request_context.hpke_context_.get()));
  if (oblivious_http_request_context.encapsulated_key_.size() !=
      expected_key_len) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Invalid len for encapsulated_key arg. Expected:", expected_key_len,
        " Actual:", oblivious_http_request_context.encapsulated_key_.size()));
  }
  if (plaintext_payload.empty()) {
    return absl::InvalidArgumentError("Empty plaintext_payload input param.");
  }
  absl::StatusOr<CommonAeadParamsResult> aead_params_st =
      GetCommonAeadParams(oblivious_http_request_context);
  if (!aead_params_st.ok()) {
    return aead_params_st.status();
  }
  const size_t nonce_size = aead_params_st->secret_len;
  const size_t max_encrypted_data_size =
      nonce_size + plaintext_payload.size() +
      EVP_AEAD_max_overhead(EVP_HPKE_AEAD_aead(EVP_HPKE_CTX_aead(
          oblivious_http_request_context.hpke_context_.get())));
  std::string encrypted_data(max_encrypted_data_size, '\0');
  // response_nonce = random(max(Nn, Nk))
  // https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-03.html#section-4.2-2.2
  random(quiche_random, encrypted_data.data(), nonce_size);
  absl::string_view response_nonce =
      absl::string_view(encrypted_data).substr(0, nonce_size);

  // Steps (1, 3 to 5) + AEAD context SetUp before 6th step is performed in
  // CommonOperations.
  auto common_ops_st = CommonOperationsToEncapDecap(
      response_nonce, oblivious_http_request_context, response_label,
      aead_params_st.value().aead_key_len,
      aead_params_st.value().aead_nonce_len, aead_params_st.value().secret_len);
  if (!common_ops_st.ok()) {
    return common_ops_st.status();
  }

  // ct = Seal(aead_key, aead_nonce, "", response)
  // https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-03.html#section-4.2-2.6
  size_t ciphertext_len;
  if (!EVP_AEAD_CTX_seal(
          common_ops_st.value().aead_ctx.get(),
          reinterpret_cast<uint8_t*>(encrypted_data.data() + nonce_size),
          &ciphertext_len, encrypted_data.size() - nonce_size,
          reinterpret_cast<const uint8_t*>(
              common_ops_st.value().aead_nonce.data()),
          aead_params_st.value().aead_nonce_len,
          reinterpret_cast<const uint8_t*>(plaintext_payload.data()),
          plaintext_payload.size(), nullptr, 0)) {
    return SslErrorAsStatus(
        "Failed to encrypt the payload with derived AEAD key.");
  }
  encrypted_data.resize(nonce_size + ciphertext_len);
  if (nonce_size == 0 || ciphertext_len == 0) {
    return absl::InternalError(absl::StrCat(
        "ObliviousHttpResponse Object wasn't initialized with required fields.",
        (nonce_size == 0 ? "Generated nonce is empty." : ""),
        (ciphertext_len == 0 ? "Generated Encrypted payload is empty." : "")));
  }
  ObliviousHttpResponse oblivious_response(std::move(encrypted_data),
                                           std::move(plaintext_payload));
  return oblivious_response;
}

// Serialize.
// enc_response = concat(response_nonce, ct)
// https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-03.html#section-4.2-4
const std::string& ObliviousHttpResponse::EncapsulateAndSerialize() const {
  return encrypted_data_;
}

// Decrypted blob.
const std::string& ObliviousHttpResponse::GetPlaintextData() const {
  return response_plaintext_;
}

// This section mainly deals with common operations performed by both
// Sender(client) and Receiver(gateway) on ObliviousHttpResponse.

absl::StatusOr<ObliviousHttpResponse::CommonAeadParamsResult>
ObliviousHttpResponse::GetCommonAeadParams(
    ObliviousHttpRequest::Context& oblivious_http_request_context) {
  const EVP_AEAD* evp_hpke_aead = EVP_HPKE_AEAD_aead(
      EVP_HPKE_CTX_aead(oblivious_http_request_context.hpke_context_.get()));
  if (evp_hpke_aead == nullptr) {
    return absl::FailedPreconditionError(
        "Key Configuration not supported by HPKE AEADs. Check your key "
        "config.");
  }
  // Nk = [AEAD key len], is determined by BoringSSL.
  const size_t aead_key_len = EVP_AEAD_key_length(evp_hpke_aead);
  // Nn = [AEAD nonce len], is determined by BoringSSL.
  const size_t aead_nonce_len = EVP_AEAD_nonce_length(evp_hpke_aead);
  const size_t secret_len = std::max(aead_key_len, aead_nonce_len);
  CommonAeadParamsResult result{evp_hpke_aead, aead_key_len, aead_nonce_len,
                                secret_len};
  return result;
}

// Common Steps of AEAD key and AEAD nonce derivation common to both
// client(decapsulation) & Gateway(encapsulation) in handling
// Oblivious-Response. Ref Steps (1, 3-to-5, and setting up AEAD context in
// preparation for 6th step's Seal/Open) in spec.
// https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-03.html#section-4.2-4
absl::StatusOr<ObliviousHttpResponse::CommonOperationsResult>
ObliviousHttpResponse::CommonOperationsToEncapDecap(
    absl::string_view response_nonce,
    ObliviousHttpRequest::Context& oblivious_http_request_context,
    absl::string_view resp_label, const size_t aead_key_len,
    const size_t aead_nonce_len, const size_t secret_len) {
  if (response_nonce.empty()) {
    return absl::InvalidArgumentError("Invalid input params.");
  }
  // secret = context.Export("message/bhttp response", Nk)
  // Export secret of len [max(Nn, Nk)] where Nk and Nn are the length of AEAD
  // key and nonce associated with context.
  // https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-03.html#section-4.2-2.1
  std::string secret(secret_len, '\0');
  if (!EVP_HPKE_CTX_export(oblivious_http_request_context.hpke_context_.get(),
                           reinterpret_cast<uint8_t*>(secret.data()),
                           secret.size(),
                           reinterpret_cast<const uint8_t*>(resp_label.data()),
                           resp_label.size())) {
    return SslErrorAsStatus("Failed to export secret.");
  }

  // salt = concat(enc, response_nonce)
  // https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-03.html#section-4.2-2.3
  std::string salt = absl::StrCat(
      oblivious_http_request_context.encapsulated_key_, response_nonce);

  // prk = Extract(salt, secret)
  // https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-03.html#section-4.2-2.3
  std::string pseudorandom_key(EVP_MAX_MD_SIZE, '\0');
  size_t prk_len;
  auto evp_md = EVP_HPKE_KDF_hkdf_md(
      EVP_HPKE_CTX_kdf(oblivious_http_request_context.hpke_context_.get()));
  if (evp_md == nullptr) {
    QUICHE_BUG(Invalid Key Configuration
               : Unsupported BoringSSL HPKE KDFs)
        << "Update KeyConfig to support only BoringSSL HKDFs.";
    return absl::FailedPreconditionError(
        "Key Configuration not supported by BoringSSL HPKE KDFs. Check your "
        "Key "
        "Config.");
  }
  if (!HKDF_extract(
          reinterpret_cast<uint8_t*>(pseudorandom_key.data()), &prk_len, evp_md,
          reinterpret_cast<const uint8_t*>(secret.data()), secret_len,
          reinterpret_cast<const uint8_t*>(salt.data()), salt.size())) {
    return SslErrorAsStatus(
        "Failed to derive pesudorandom key from salt and secret.");
  }
  pseudorandom_key.resize(prk_len);

  // aead_key = Expand(prk, "key", Nk)
  // https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-03.html#section-4.2-2.4
  std::string aead_key(aead_key_len, '\0');
  absl::string_view hkdf_info = ObliviousHttpHeaderKeyConfig::kKeyHkdfInfo;
  // All currently supported KDFs are HKDF-based. See CheckKdfId in
  // `ObliviousHttpHeaderKeyConfig`.
  if (!HKDF_expand(reinterpret_cast<uint8_t*>(aead_key.data()), aead_key_len,
                   evp_md,
                   reinterpret_cast<const uint8_t*>(pseudorandom_key.data()),
                   prk_len, reinterpret_cast<const uint8_t*>(hkdf_info.data()),
                   hkdf_info.size())) {
    return SslErrorAsStatus(
        "Failed to expand AEAD key using pseudorandom key(prk).");
  }

  // aead_nonce = Expand(prk, "nonce", Nn)
  // https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-03.html#section-4.2-2.5
  std::string aead_nonce(aead_nonce_len, '\0');
  hkdf_info = ObliviousHttpHeaderKeyConfig::kNonceHkdfInfo;
  // All currently supported KDFs are HKDF-based. See CheckKdfId in
  // `ObliviousHttpHeaderKeyConfig`.
  if (!HKDF_expand(reinterpret_cast<uint8_t*>(aead_nonce.data()),
                   aead_nonce_len, evp_md,
                   reinterpret_cast<const uint8_t*>(pseudorandom_key.data()),
                   prk_len, reinterpret_cast<const uint8_t*>(hkdf_info.data()),
                   hkdf_info.size())) {
    return SslErrorAsStatus(
        "Failed to expand AEAD nonce using pseudorandom key(prk).");
  }

  const EVP_AEAD* evp_hpke_aead = EVP_HPKE_AEAD_aead(
      EVP_HPKE_CTX_aead(oblivious_http_request_context.hpke_context_.get()));
  if (evp_hpke_aead == nullptr) {
    return absl::FailedPreconditionError(
        "Key Configuration not supported by HPKE AEADs. Check your key "
        "config.");
  }

  // Setup AEAD context for subsequent Seal/Open operation in response handling.
  bssl::UniquePtr<EVP_AEAD_CTX> aead_ctx(EVP_AEAD_CTX_new(
      evp_hpke_aead, reinterpret_cast<const uint8_t*>(aead_key.data()),
      aead_key.size(), 0));
  if (aead_ctx == nullptr) {
    return SslErrorAsStatus("Failed to initialize AEAD context.");
  }
  if (!EVP_AEAD_CTX_init(aead_ctx.get(), evp_hpke_aead,
                         reinterpret_cast<const uint8_t*>(aead_key.data()),
                         aead_key.size(), 0, nullptr)) {
    return SslErrorAsStatus(
        "Failed to initialize AEAD context with derived key.");
  }
  CommonOperationsResult result{std::move(aead_ctx), std::move(aead_nonce)};
  return result;
}

}  // namespace quiche
```