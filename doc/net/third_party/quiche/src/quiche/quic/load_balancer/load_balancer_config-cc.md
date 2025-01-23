Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

1. **Understand the Goal:** The request asks for an analysis of the `load_balancer_config.cc` file within the Chromium network stack (specifically the QUIC implementation). The key aspects to address are functionality, relation to JavaScript (if any), logical reasoning with examples, potential user/programming errors, and debugging information.

2. **Initial Code Scan and High-Level Understanding:**
   - Look at the `#include` directives. This tells us the file interacts with:
     - Standard C++ libraries (`cstdint`, `cstring`, `optional`).
     - Abseil libraries (`absl/strings/string_view`, `absl/types/span`).
     - OpenSSL (`openssl/aes.h`).
     - QUIC core components (`quiche/quic/core/quic_connection_id.h`).
     - QUIC load balancing specific components (`quiche/quic/load_balancer/load_balancer_server_id.h`).
     - QUIC platform API (`quiche/quic/platform/api/quic_bug_tracker.h`).
   - Identify the main class: `LoadBalancerConfig`. This is the central entity we need to analyze.
   - Notice the namespace `quic`. This confirms it's part of the QUIC implementation.
   - Observe the helper namespaces and functions within the `quic` namespace but outside the class: the anonymous namespace with `CommonValidation` and `BuildKey`. These are likely utility functions used by the `LoadBalancerConfig` class.

3. **Deconstruct the `LoadBalancerConfig` Class:**
   - **Member Variables:** Identify the key data members: `config_id_`, `server_id_len_`, `nonce_len_`, `key_`, `block_decrypt_key_`. Infer their purpose based on their names (config ID, server ID length, nonce length, encryption key, decryption key).
   - **Constructors:**  Analyze the constructors. The primary constructor takes `config_id`, `server_id_len`, `nonce_len`, and `key`. There are also static factory methods like `Create` and `CreateUnencrypted`.
   - **Methods:**  Examine the public methods:
     - `Create`, `CreateUnencrypted`: Static factory methods for creating `LoadBalancerConfig` objects.
     - `FourPassDecrypt`, `FourPassEncrypt`: Methods related to a specific decryption/encryption scheme. The name "FourPass" is suggestive of the number of rounds involved.
     - `BlockEncrypt`, `BlockDecrypt`: Methods for simpler block-based encryption/decryption, likely using AES.
     - Accessors (implicitly through the member variable names).
   - **Helper Methods:** Analyze the private helper methods:
     - `CommonValidation`:  Likely performs checks on the input parameters.
     - `BuildKey`:  Seems to handle the creation of the OpenSSL AES key.
     - `InitializeFourPass`:  Appears to be the setup for the four-pass encryption/decryption.
     - `EncryptionPass`:  Likely performs a single pass of the four-pass algorithm.

4. **Infer Functionality:** Based on the identified components, deduce the overall purpose of the file and the `LoadBalancerConfig` class. It's clearly about configuring how load balancers interact with QUIC connections. The configuration involves IDs, lengths, and cryptographic keys. The presence of different encryption/decryption methods (`FourPass` and `Block`) suggests flexibility or different use cases.

5. **JavaScript Relationship (or Lack Thereof):** Carefully consider if any part of this code directly interacts with JavaScript. Since it's low-level C++ code within the network stack, direct interaction is unlikely. However, remember that Chromium uses this code, and JavaScript within a browser might *trigger* the use of this code indirectly through network requests. The key is to distinguish between direct code interaction and indirect system-level interaction.

6. **Logical Reasoning and Examples:**
   - For each key function (especially `Create`, `FourPassEncrypt`, `FourPassDecrypt`), devise example scenarios with hypothetical inputs and expected outputs. This helps to illustrate the function's behavior. For instance, with `Create`, think about valid and invalid key lengths. For the encryption/decryption, consider the data transformation.

7. **User/Programming Errors:**  Think about common mistakes developers might make when using this configuration. Incorrect key lengths, invalid parameter values, and misuse of the encryption/decryption methods are potential candidates. Provide concrete examples.

8. **Debugging Clues and User Actions:**  Trace how a user action (like accessing a website) could eventually lead to the execution of this code. This involves understanding the high-level network flow within Chromium. The connection setup phase, where load balancers might be involved, is a crucial area. Think about how configuration values are passed down through the system.

9. **Structure the Explanation:** Organize the findings into logical sections, as demonstrated in the provided example answer. Use headings and bullet points for clarity.

10. **Refine and Elaborate:** Review the generated explanation and add details or clarifications where necessary. Ensure the language is clear and concise. For instance, explain *why* certain checks are performed (e.g., why the key length matters for AES). Explain the purpose of the constants mentioned in the code.

**Self-Correction/Refinement during the Process:**

- **Initial thought:**  Maybe the "FourPass" algorithm is related to OAuth or some web authentication scheme.
- **Correction:** After examining the code, it's clearly a custom encryption/decryption method specific to load balancing within QUIC, manipulating byte arrays directly. The "FourPass" likely refers to the number of encryption rounds.

- **Initial thought:** There might be direct JavaScript bindings to this C++ code.
- **Correction:** While Chromium allows for bindings in some cases, for core network stack components like this, direct interaction is less common. The interaction is more likely through higher-level browser APIs.

By following this structured approach, combining code analysis with logical reasoning and consideration of the broader context, we can generate a comprehensive and accurate explanation of the given source code.
好的，让我们来分析一下 `net/third_party/quiche/src/quiche/quic/load_balancer/load_balancer_config.cc` 这个文件。

**功能概要:**

这个 C++ 文件定义了 `LoadBalancerConfig` 类，该类负责配置 QUIC 连接的负载均衡行为。更具体地说，它定义了用于加密和解密负载均衡信息的参数，这些信息通常嵌入在 QUIC 连接 ID 中。

主要功能包括：

1. **配置管理:**  `LoadBalancerConfig` 存储了与负载均衡相关的配置信息，例如配置 ID (`config_id_`)、服务器 ID 的长度 (`server_id_len_`)、随机数（nonce）的长度 (`nonce_len_`) 以及用于加密和解密的密钥 (`key_`, `block_decrypt_key_`)。

2. **配置创建:** 提供了静态工厂方法 `Create` 和 `CreateUnencrypted` 来创建 `LoadBalancerConfig` 对象。`Create` 方法用于创建加密的配置，需要提供密钥；`CreateUnencrypted` 用于创建非加密的配置。

3. **连接 ID 加密 (FourPassEncrypt):** `FourPassEncrypt` 方法使用一种自定义的四轮加密算法（可能是为了性能或特定的安全需求）将负载均衡信息（包括服务器 ID 和 nonce）加密嵌入到 QUIC 连接 ID 中。

4. **连接 ID 解密 (FourPassDecrypt):** `FourPassDecrypt` 方法执行相反的操作，使用相同的四轮算法解密 QUIC 连接 ID，提取出负载均衡信息，特别是服务器 ID。

5. **块加密/解密 (BlockEncrypt, BlockDecrypt):**  提供了标准的 AES 块加密和解密方法。这可能用于某些特定的负载均衡信息处理场景。

6. **参数校验:**  在配置创建时进行参数校验，例如检查密钥长度、ID 长度和 nonce 长度的有效性，以防止配置错误。

**与 JavaScript 的关系:**

这个 C++ 文件本身并不直接与 JavaScript 交互。它是 Chromium 网络栈的底层 C++ 代码。然而，JavaScript 代码（例如在浏览器中运行的 Web 应用）可以通过以下方式间接影响到这个文件的功能：

* **发起网络连接:** 当 JavaScript 代码使用 `fetch` API 或其他网络请求方法建立 QUIC 连接时，Chromium 的网络栈会处理这些连接。如果目标服务器启用了基于连接 ID 的负载均衡，那么 `LoadBalancerConfig` 就会被用来加密连接 ID。
* **网络配置:**  在某些高级场景下，可能存在允许开发者或管理员配置 Chromium 网络行为的机制，这些配置可能会影响是否启用或如何使用负载均衡。虽然 JavaScript 不会直接调用 `LoadBalancerConfig` 的方法，但它可能会间接影响到相关配置。

**举例说明 (间接关系):**

假设一个 Web 应用需要连接到一个使用 QUIC 并且启用了基于连接 ID 负载均衡的服务器。

1. **JavaScript 发起请求:**
   ```javascript
   fetch('https://example.com/data')
     .then(response => response.json())
     .then(data => console.log(data));
   ```

2. **Chromium 网络栈处理:** 当上述 `fetch` 请求被执行时，Chromium 的网络栈会尝试建立到 `example.com` 的 QUIC 连接。

3. **负载均衡配置应用:** 如果 `example.com` 的服务器配置要求使用负载均衡，并且配置了相应的 `LoadBalancerConfig` (例如，通过服务器的 ALPN 协商或本地策略)，Chromium 会使用 `LoadBalancerConfig::FourPassEncrypt` 来生成带有负载均衡信息的连接 ID。

4. **服务器识别:**  当这个带有负载均衡信息的连接 ID 到达服务器时，服务器（或其负载均衡器）可以使用相应的解密配置来提取服务器 ID，从而将连接路由到正确的后端实例。

**逻辑推理与假设输入/输出:**

**假设场景：创建并使用加密的 LoadBalancerConfig**

**假设输入:**

* `config_id`: 1 (假设的配置 ID)
* `server_id_len`: 8 (服务器 ID 长度为 8 字节)
* `nonce_len`: 4 (nonce 长度为 4 字节)
* `key`: "0123456789abcdef" (16 字节的 AES 密钥)
* `plaintext` (用于加密):  假设负载均衡信息部分为 `\x01\x02\x03\x04\x05\x06\x07\x08\x0a\x0b\x0c\x0d` (前 8 字节是 server ID，后 4 字节是 nonce)

**逻辑推理:**

1. 使用 `LoadBalancerConfig::Create` 创建配置对象。
2. 使用 `LoadBalancerConfig::FourPassEncrypt` 加密 `plaintext`。

**预期输出:**

* `LoadBalancerConfig` 对象被成功创建。
* `FourPassEncrypt` 会返回一个 `QuicConnectionId` 对象，其内部的字节数组会是被加密后的连接 ID，包含了加密的负载均衡信息。具体的加密结果取决于四轮加密算法的实现细节。

**假设场景：使用非加密的 LoadBalancerConfig 进行解密**

**假设输入:**

* `config_id`: 2
* `server_id_len`: 5
* `nonce_len`: 3
* `ciphertext` (假设的连接 ID，不包含第一个长度字节): `\xaa\xbb\xcc\xdd\xee\xff\x11\x22` (前 5 字节是 server ID，后 3 字节是 nonce)
* 创建一个非加密的 `LoadBalancerConfig` 对象。

**逻辑推理:**

1. 使用 `LoadBalancerConfig::CreateUnencrypted` 创建配置对象。
2. 使用 `LoadBalancerConfig::FourPassDecrypt` 解密 `ciphertext`。

**预期输出:**

* `LoadBalancerConfig` 对象被成功创建。
* `FourPassDecrypt` 会将解密后的服务器 ID 写入提供的 `LoadBalancerServerId` 对象。在这个非加密的情况下，解密过程可能只是简单地提取字节。

**用户或编程常见的使用错误:**

1. **密钥长度错误:**  `LoadBalancerConfig::Create` 要求密钥长度为 `kLoadBalancerKeyLen` (通常是 16 字节，对应 AES-128)。提供错误的密钥长度会导致配置创建失败。
   ```c++
   // 错误：密钥长度不正确
   auto config = LoadBalancerConfig::Create(1, 8, 4, "shortkey");
   if (!config.has_value()) {
     // 处理错误
   }
   ```

2. **加密和解密配置不匹配:**  如果在加密连接 ID 时使用的 `LoadBalancerConfig` 与解密时使用的配置不一致（例如，密钥不同，ID 或 nonce 长度不同），解密将会失败，导致负载均衡失效。

3. **在需要加密时使用未加密的配置:** 尝试使用 `FourPassEncrypt` 但 `LoadBalancerConfig` 是通过 `CreateUnencrypted` 创建的，会导致加密过程无法正常进行。

4. **传递错误的连接 ID 长度给解密函数:** `FourPassDecrypt` 依赖于传入的连接 ID 长度与配置中的长度信息一致。如果长度不匹配，会导致越界访问或解密失败。

5. **忘记检查 `std::optional` 的返回值:**  `Create` 和 `CreateUnencrypted` 返回 `std::optional<LoadBalancerConfig>`。用户必须检查返回值是否包含有效对象，以避免使用空对象。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户访问一个网站 `https://example.com`，该网站使用 QUIC 协议并且服务端配置了基于连接 ID 的负载均衡。以下是可能触发 `load_balancer_config.cc` 中代码执行的步骤：

1. **用户在浏览器地址栏输入 `https://example.com` 并按下回车。**

2. **浏览器解析 URL 并确定需要建立 HTTPS 连接。**

3. **浏览器检查是否支持 QUIC 协议，并尝试与服务器进行 QUIC 握手。**

4. **QUIC 握手过程中，客户端（浏览器）和服务器会协商连接参数，包括是否使用负载均衡以及相关的配置。**  这可能通过 ALPN (Application-Layer Protocol Negotiation) 扩展来完成。

5. **如果协商结果表明需要使用负载均衡，并且服务器提供了负载均衡配置信息（例如，配置 ID、密钥等），Chromium 的 QUIC 实现会根据这些信息创建一个 `LoadBalancerConfig` 对象。** 这可能会调用 `LoadBalancerConfig::Create`。

6. **当客户端需要发送新的 QUIC 连接时，Chromium 会生成一个连接 ID。如果启用了负载均衡，并且有有效的 `LoadBalancerConfig`，则会调用 `LoadBalancerConfig::FourPassEncrypt` 来加密负载均衡信息并嵌入到连接 ID 中。**

7. **加密后的连接 ID 会被包含在 QUIC 数据包中发送到服务器。**

8. **在服务器端，负载均衡器或服务器的 QUIC 实现会接收到带有负载均衡信息的连接 ID。**

9. **服务器端会使用相应的 `LoadBalancerConfig` (可能与客户端的配置相同或相关) 调用 `LoadBalancerConfig::FourPassDecrypt` 来解密连接 ID，提取出服务器 ID，并将连接路由到正确的后端实例。**

**调试线索:**

* **网络抓包:** 使用 Wireshark 或 Chrome 的 `chrome://webrtc-internals` 可以捕获 QUIC 数据包，查看连接 ID 的格式和内容，判断是否包含负载均衡信息。
* **QUIC 事件日志:** Chromium 内部有 QUIC 事件日志，可以记录负载均衡配置的加载、连接 ID 的生成和解密过程。
* **断点调试:** 在 `load_balancer_config.cc` 的关键函数（如 `Create`, `FourPassEncrypt`, `FourPassDecrypt`) 设置断点，可以查看配置参数的值，以及加密和解密过程中的中间状态。
* **查看 Chromium 网络内部状态:**  `chrome://net-internals/#quic` 可以提供关于 QUIC 连接的详细信息，包括使用的负载均衡配置。

总而言之，`net/third_party/quiche/src/quiche/quic/load_balancer/load_balancer_config.cc` 是 Chromium QUIC 实现中负责管理负载均衡配置的核心组件，它定义了如何加密和解密连接 ID 中嵌入的负载均衡信息，从而实现将连接路由到后端服务器的目的。虽然 JavaScript 不直接操作这个文件，但用户的网络请求会间接地触发其功能。理解这个文件的功能对于调试 QUIC 连接的负载均衡问题至关重要。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/load_balancer/load_balancer_config.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/load_balancer/load_balancer_config.h"

#include <cstdint>
#include <cstring>
#include <optional>

#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/aes.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/load_balancer/load_balancer_server_id.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"

namespace quic {

namespace {

// Validates all non-key parts of the input.
bool CommonValidation(const uint8_t config_id, const uint8_t server_id_len,
                      const uint8_t nonce_len) {
  if (config_id >= kNumLoadBalancerConfigs || server_id_len == 0 ||
      nonce_len < kLoadBalancerMinNonceLen ||
      nonce_len > kLoadBalancerMaxNonceLen ||
      server_id_len >
          (kQuicMaxConnectionIdWithLengthPrefixLength - nonce_len - 1)) {
    QUIC_BUG(quic_bug_433862549_01)
        << "Invalid LoadBalancerConfig "
        << "Config ID " << static_cast<int>(config_id) << " Server ID Length "
        << static_cast<int>(server_id_len) << " Nonce Length "
        << static_cast<int>(nonce_len);
    return false;
  }
  return true;
}

// Initialize the key in the constructor
std::optional<AES_KEY> BuildKey(absl::string_view key, bool encrypt) {
  if (key.empty()) {
    return std::optional<AES_KEY>();
  }
  AES_KEY raw_key;
  if (encrypt) {
    if (AES_set_encrypt_key(reinterpret_cast<const uint8_t *>(key.data()),
                            key.size() * 8, &raw_key) < 0) {
      return std::optional<AES_KEY>();
    }
  } else if (AES_set_decrypt_key(reinterpret_cast<const uint8_t *>(key.data()),
                                 key.size() * 8, &raw_key) < 0) {
    return std::optional<AES_KEY>();
  }
  return raw_key;
}

}  // namespace

std::optional<LoadBalancerConfig> LoadBalancerConfig::Create(
    const uint8_t config_id, const uint8_t server_id_len,
    const uint8_t nonce_len, const absl::string_view key) {
  //  Check for valid parameters.
  if (key.size() != kLoadBalancerKeyLen) {
    QUIC_BUG(quic_bug_433862549_02)
        << "Invalid LoadBalancerConfig Key Length: " << key.size();
    return std::optional<LoadBalancerConfig>();
  }
  if (!CommonValidation(config_id, server_id_len, nonce_len)) {
    return std::optional<LoadBalancerConfig>();
  }
  auto new_config =
      LoadBalancerConfig(config_id, server_id_len, nonce_len, key);
  if (!new_config.IsEncrypted()) {
    // Something went wrong in assigning the key!
    QUIC_BUG(quic_bug_433862549_03) << "Something went wrong in initializing "
                                       "the load balancing key.";
    return std::optional<LoadBalancerConfig>();
  }
  return new_config;
}

// Creates an unencrypted config.
std::optional<LoadBalancerConfig> LoadBalancerConfig::CreateUnencrypted(
    const uint8_t config_id, const uint8_t server_id_len,
    const uint8_t nonce_len) {
  return CommonValidation(config_id, server_id_len, nonce_len)
             ? LoadBalancerConfig(config_id, server_id_len, nonce_len, "")
             : std::optional<LoadBalancerConfig>();
}

// Note that |ciphertext| does not include the first byte of the connection ID.
bool LoadBalancerConfig::FourPassDecrypt(
    absl::Span<const uint8_t> ciphertext,
    LoadBalancerServerId& server_id) const {
  if (ciphertext.size() < plaintext_len()) {
    QUIC_BUG(quic_bug_599862571_02)
        << "Called FourPassDecrypt with a short Connection ID";
    return false;
  }
  if (!key_.has_value()) {
    return false;
  }
  // Do 3 or 4 passes. Only 3 are necessary if the server_id is short enough
  // to fit in the first half of the connection ID (the decoder doesn't need
  // to extract the nonce).
  uint8_t* left = server_id.mutable_data();
  uint8_t right[kLoadBalancerBlockSize];
  uint8_t half_len;  // half the length of the plaintext, rounded up
  bool is_length_odd =
      InitializeFourPass(ciphertext.data(), left, right, &half_len);
  uint8_t end_index = (server_id_len_ > nonce_len_) ? 1 : 2;
  for (uint8_t index = kNumLoadBalancerCryptoPasses; index >= end_index;
       --index) {
    // Encrypt left/right and xor the result with right/left, respectively.
    EncryptionPass(index, half_len, is_length_odd, left, right);
  }
  // Consolidate left and right into a server ID with minimum copying.
  if (server_id_len_ < half_len ||
      (server_id_len_ == half_len && !is_length_odd)) {
    // There is no half-byte to handle. Server ID is already written in to
    // server_id.
    return true;
  }
  if (is_length_odd) {
    right[0] |= *(left + --half_len);  // Combine the halves of the odd byte.
  }
  memcpy(server_id.mutable_data() + half_len, right, server_id_len_ - half_len);
  return true;
}

// Note that |plaintext| includes the first byte of the connection ID.
QuicConnectionId LoadBalancerConfig::FourPassEncrypt(
    absl::Span<uint8_t> plaintext) const {
  if (plaintext.size() < total_len()) {
    QUIC_BUG(quic_bug_599862571_03)
        << "Called FourPassEncrypt with a short Connection ID";
    return QuicConnectionId();
  }
  if (!key_.has_value()) {
    return QuicConnectionId();
  }
  uint8_t left[kLoadBalancerBlockSize];
  uint8_t right[kLoadBalancerBlockSize];
  uint8_t half_len;  // half the length of the plaintext, rounded up
  bool is_length_odd =
      InitializeFourPass(plaintext.data() + 1, left, right, &half_len);
  for (uint8_t index = 1; index <= kNumLoadBalancerCryptoPasses; ++index) {
    EncryptionPass(index, half_len, is_length_odd, left, right);
  }
  // Consolidate left and right into a server ID with minimum copying.
  if (is_length_odd) {
    // Combine the halves of the odd byte.
    right[0] |= left[--half_len];
  }
  memcpy(plaintext.data() + 1, left, half_len);
  memcpy(plaintext.data() + half_len + 1, right, plaintext_len() - half_len);
  return QuicConnectionId(reinterpret_cast<char*>(plaintext.data()),
                          total_len());
}

bool LoadBalancerConfig::BlockEncrypt(
    const uint8_t plaintext[kLoadBalancerBlockSize],
    uint8_t ciphertext[kLoadBalancerBlockSize]) const {
  if (!key_.has_value()) {
    return false;
  }
  AES_encrypt(plaintext, ciphertext, &*key_);
  return true;
}

bool LoadBalancerConfig::BlockDecrypt(
    const uint8_t ciphertext[kLoadBalancerBlockSize],
    uint8_t plaintext[kLoadBalancerBlockSize]) const {
  if (!block_decrypt_key_.has_value()) {
    return false;
  }
  AES_decrypt(ciphertext, plaintext, &*block_decrypt_key_);
  return true;
}

LoadBalancerConfig::LoadBalancerConfig(const uint8_t config_id,
                                       const uint8_t server_id_len,
                                       const uint8_t nonce_len,
                                       const absl::string_view key)
    : config_id_(config_id),
      server_id_len_(server_id_len),
      nonce_len_(nonce_len),
      key_(BuildKey(key, /* encrypt = */ true)),
      block_decrypt_key_((server_id_len + nonce_len == kLoadBalancerBlockSize)
                             ? BuildKey(key, /* encrypt = */ false)
                             : std::optional<AES_KEY>()) {}

// Note that |input| does not include the first byte of the connection ID.
bool LoadBalancerConfig::InitializeFourPass(const uint8_t* input, uint8_t* left,
                                            uint8_t* right,
                                            uint8_t* half_len) const {
  *half_len = plaintext_len() / 2;
  bool is_length_odd;
  if (plaintext_len() % 2 == 1) {
    ++(*half_len);
    is_length_odd = true;
  } else {
    is_length_odd = false;
  }
  memset(left, 0, kLoadBalancerBlockSize);
  memset(right, 0, kLoadBalancerBlockSize);
  // The first byte is the plaintext/ciphertext length, the second byte will be
  // the index of the pass. Half the plaintext or ciphertext follows.
  left[kLoadBalancerBlockSize - 2] = plaintext_len();
  right[kLoadBalancerBlockSize - 2] = plaintext_len();
  // Leave left_[15]], right_[15] as zero. It will be set for each pass.
  memcpy(left, input, *half_len);
  // If is_length_odd, then both left and right will have part of the middle
  // byte. Then that middle byte will be split in half via the bitmask in the
  // next step.
  memcpy(right, input + (plaintext_len() / 2), *half_len);
  if (is_length_odd) {
    left[*half_len - 1] &= 0xf0;
    right[0] &= 0x0f;
  }
  return is_length_odd;
}

void LoadBalancerConfig::EncryptionPass(uint8_t index, uint8_t half_len,
                                        bool is_length_odd, uint8_t* left,
                                        uint8_t* right) const {
  uint8_t ciphertext[kLoadBalancerBlockSize];
  if (index % 2 == 0) {  // Go right to left.
    right[kLoadBalancerBlockSize - 1] = index;
    AES_encrypt(right, ciphertext, &*key_);
    for (int i = 0; i < half_len; ++i) {
      // Skip over the first two bytes, which have the plaintext_len and the
      // index. The CID bits are in [2, half_len - 1].
      left[i] ^= ciphertext[i];
    }
    if (is_length_odd) {
      left[half_len - 1] &= 0xf0;
    }
    return;
  }
  // Go left to right.
  left[kLoadBalancerBlockSize - 1] = index;
  AES_encrypt(left, ciphertext, &*key_);
  for (int i = 0; i < half_len; ++i) {
    right[i] ^= ciphertext[i];
  }
  if (is_length_odd) {
    right[0] &= 0x0f;
  }
}

}  // namespace quic
```