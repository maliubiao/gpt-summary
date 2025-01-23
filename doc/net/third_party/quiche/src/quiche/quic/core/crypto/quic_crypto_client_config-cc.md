Response:
Let's break down the thought process to analyze the given C++ code.

1. **Understand the Goal:** The request asks for the functionality of `quic_crypto_client_config.cc`, its relation to JavaScript (if any), logic examples, common usage errors, and debugging tips. Essentially, a comprehensive overview for someone trying to understand or debug QUIC client crypto.

2. **Initial Skim and Identification of Key Components:** Quickly read through the code, paying attention to class names, function names, and included headers. I noticed:
    * `QuicCryptoClientConfig`: The main class. Likely responsible for managing client-side crypto configuration.
    * `CachedState`:  Seems to hold cached server crypto information.
    * `ProofVerifier`:  Used for verifying server certificates.
    * `SessionCache`:  For storing and retrieving session information.
    * `CryptoHandshakeMessage`:  Representing crypto handshake messages (CHLO, SHLO, REJ, SCFG, etc.).
    * Various crypto-related headers (`chacha20`, `crypto_framer`, `key_exchange`, `tls_client_connection`).
    * Includes from `quic/platform/api`, suggesting platform-specific abstractions.

3. **Focus on the Core Class `QuicCryptoClientConfig`:**  What are its primary responsibilities?
    * **Configuration:**  It holds settings like supported key exchange algorithms (`kexs`), AEAD algorithms (`aead`), and potentially a proof verifier.
    * **Caching:**  It manages `CachedState` objects to store server crypto information, avoiding redundant handshakes.
    * **Client Hello Generation:**  Functions like `FillInchoateClientHello` and `FillClientHello` are clearly responsible for creating client hello messages.
    * **Message Processing:** Functions like `ProcessRejection`, `ProcessServerHello`, and `ProcessServerConfigUpdate` handle incoming server messages.
    * **Proof Verification:**  It uses the `ProofVerifier` to validate server certificates.
    * **Session Management:**  Interaction with `SessionCache`.

4. **Analyze `CachedState`:** This class is crucial for understanding the caching mechanism.
    * **Data Storage:**  It stores the server config (`server_config_`), source address token (`source_address_token_`), certificates (`certs_`), and proof-related data.
    * **Validity Tracking:**  `server_config_valid_` indicates if the cached proof is valid.
    * **Expiration:** `expiration_time_` manages the lifetime of cached data.
    * **Initialization and Updates:** Functions like `Initialize`, `SetServerConfig`, `SetProof`, and `Clear` manage the state of the cache.

5. **Look for JavaScript Relevance:** Scan the code for any direct interaction with JavaScript. Keywords like "JavaScript," "V8," "Node.js," or web platform APIs would be indicators. *In this specific code*, there's no direct mention or integration with JavaScript. Therefore, the connection is *indirect* through the usage of Chromium's networking stack in a browser or Node.js environment.

6. **Identify Logic Examples:**  Choose a key function and trace its execution flow with hypothetical inputs and outputs. `FillClientHello` is a good candidate because it's central to the handshake process. Think about the necessary inputs (server ID, versions, cached state) and the resulting output (a `CryptoHandshakeMessage`). Consider different scenarios (cache hit, cache miss, errors).

7. **Consider Common Usage Errors:**  Think about how a developer might misuse this API. For example, not providing a `ProofVerifier`, incorrect server IDs, ignoring error codes, or issues with the caching mechanism.

8. **Trace User Operations to Reach This Code:**  Think about the user's journey that leads to the execution of this code. Starting from a high-level action (typing a URL, clicking a link), trace the steps down to the QUIC client initiating a connection and the crypto handshake.

9. **Structure the Output:** Organize the findings into the requested categories: functionality, JavaScript relation, logic examples, common errors, and debugging. Use clear and concise language.

10. **Refine and Elaborate:** Review the initial analysis and add details. For example, when discussing functionality, mention the specific crypto primitives being used (AES-GCM, ChaCha20-Poly1305, Curve25519). For debugging, suggest specific log messages or tools.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe there's a direct JS API here. *Correction:*  After closer inspection, realize it's a C++ backend component of a larger system. The JS interaction is at a higher level (e.g., using browser APIs that *use* this code).
* **Overly technical description:**  Realize the explanation should be understandable to someone who might not be a QUIC expert. Simplify technical terms where possible.
* **Missing error examples:** Initially focused on functional aspects. *Correction:*  Specifically think about what could go wrong from a *developer's* perspective using this code.
* **Vague debugging tips:** *Correction:* Provide concrete examples of what to look for in logs or how to reproduce issues.

By following this thought process, breaking down the code into manageable parts, and iteratively refining the analysis, I can construct a comprehensive and accurate response to the request.
这个 C++ 源代码文件 `quic_crypto_client_config.cc` 属于 Chromium 网络栈中 QUIC 协议的实现。它的主要功能是管理 QUIC 客户端的加密配置和状态，以便与 QUIC 服务器建立安全的连接。

以下是该文件的详细功能列表：

**核心功能：**

1. **管理客户端加密配置:**
   - 存储客户端支持的加密算法套件（AEAD，认证加密及关联数据）和密钥交换算法。
   - 设置默认的加密偏好（例如，优先使用 AES-GCM 如果硬件支持）。
   - 维护 TLS 客户端连接的 SSL 上下文。

2. **缓存服务器配置 (SCFG):**
   - 维护一个本地缓存 (`cached_states_`)，用于存储从服务器接收到的加密配置信息 (Server Config)。
   - 缓存的信息包括服务器配置本身、源地址令牌 (Source Address Token)、服务器证书链、证书的 SCT (Signed Certificate Timestamp)、CHLO (Client Hello) 的哈希值、服务器配置签名以及过期时间。
   - 提供方法来查找或创建特定服务器 ID 的缓存状态 (`LookupOrCreate`).
   - 提供方法来清除缓存状态 (`ClearCachedStates`).

3. **生成和处理 Client Hello (CHLO) 消息:**
   - `FillInchoateClientHello`:  生成一个初步的、不完整的 CHLO 消息，通常在没有有效缓存信息时发送。
   - `FillClientHello`: 生成完整的 CHLO 消息，包含必要的加密协商参数，使用缓存的服务器配置信息。

4. **处理服务器响应消息 (REJ, SHLO, SCUP):**
   - `ProcessRejection`: 处理服务器拒绝连接 (REJ) 消息，通常包含新的服务器配置信息。
   - `ProcessServerHello`: 处理服务器 Hello (SHLO) 消息，完成密钥交换并建立加密通道。
   - `ProcessServerConfigUpdate`: 处理服务器配置更新 (SCUP) 消息，更新本地缓存的服务器配置。

5. **验证服务器身份:**
   - 使用 `ProofVerifier` 接口来验证服务器提供的证书链和签名，确保连接到合法的服务器。

6. **管理会话缓存:**
   - 可以关联一个 `SessionCache` 对象，用于存储和重用 TLS 会话信息，以加速后续连接建立。

7. **处理规范主机名:**
   - 支持规范主机名 (Canonical Hostnames) 的概念，允许将一个主机名的缓存信息用于其他相似的主机名，以减少握手次数。

**与 JavaScript 的关系：**

该 C++ 文件本身并不直接包含 JavaScript 代码或与 JavaScript 直接交互。然而，它在 Chromium 浏览器或其他基于 Chromium 的应用中发挥着关键作用，而这些应用通常会运行 JavaScript 代码。

**关系举例：**

当用户在浏览器中访问一个使用 QUIC 协议的网站时，以下过程可能会涉及到 `quic_crypto_client_config.cc`：

1. **用户操作 (JavaScript 层面):** 用户在地址栏输入 URL 并按下回车，或者点击一个链接。浏览器中的 JavaScript 代码（例如，网络请求相关的 API）会发起一个网络请求。

2. **网络栈处理 (C++ 层面):** Chromium 的网络栈接收到请求，并确定需要使用 QUIC 协议进行连接。

3. **`QuicCryptoClientConfig` 的作用:**
   - **查找缓存:** `QuicCryptoClientConfig` 会检查是否已经缓存了该服务器的加密配置信息。如果存在有效的缓存，可以用于快速建立连接（0-RTT 或 1-RTT）。
   - **生成 CHLO:** 如果没有有效的缓存或者需要更新配置，`QuicCryptoClientConfig` 会根据配置和缓存状态生成 CHLO 消息。
   - **发送 CHLO:** 生成的 CHLO 消息会被发送到服务器。
   - **处理服务器响应:**  当服务器返回 REJ、SHLO 或 SCUP 消息时，`QuicCryptoClientConfig` 会解析这些消息，更新缓存，并完成加密握手。
   - **验证证书:** 使用配置的 `ProofVerifier` 来验证服务器的证书，这对于确保安全至关重要。

4. **连接建立 (C++ 层面):** 一旦加密握手完成，QUIC 连接建立，数据可以在加密通道上传输。

5. **数据传输 (JavaScript 层面):**  浏览器接收到来自服务器的数据，这些数据会被传递给执行网络请求的 JavaScript 代码。

**逻辑推理举例：**

**假设输入:**

- `server_id`: `example.com:443`
- 客户端本地没有关于 `example.com` 的缓存信息。
- 客户端支持的 AEAD 列表: `[kAESG, kCC20]` (AES-GCM, ChaCha20-Poly1305)
- 客户端支持的 KEX 列表: `[kC255, kP256]` (Curve25519, P-256)

**输出 (在 `FillInchoateClientHello` 中):**

- 生成一个 CHLO 消息，包含以下关键字段：
    - `kCHLO` (消息类型)
    - `kSNI`: "example.com" (服务器名称指示)
    - `kVER`:  客户端支持的 QUIC 版本
    - `kAEAD`:  `[kAESG, kCC20]` (客户端的 AEAD 偏好)
    - `kKEXS`:  `[kC255, kP256]` (客户端的密钥交换偏好)
    - `kNONP`:  一个随机生成的 nonce，用于防止重放攻击 (如果 `demand_x509_proof` 为 true)
    - 其他一些可选字段。

**假设输入 (在 `FillClientHello` 中，假设已经收到并缓存了服务器的 SCFG):**

- `server_id`: `example.com:443`
- `cached`: 包含从服务器获取的 SCFG，其中服务器支持的 AEAD 为 `[kCC20]`, KEX 为 `[kC255]`, 并包含服务器的公钥等信息。
- 客户端支持的 AEAD 列表: `[kAESG, kCC20]`
- 客户端支持的 KEX 列表: `[kC255, kP256]`

**输出 (在 `FillClientHello` 中):**

- 生成一个 CHLO 消息，包含：
    - `kCHLO`
    - `kSNI`: "example.com"
    - `kVER`
    - `kSCID`:  从缓存的 SCFG 中获取的服务器配置 ID
    - `kAEAD`: `[kCC20]` (选择双方都支持的 ChaCha20-Poly1305)
    - `kKEXS`: `[kC255]` (选择双方都支持的 Curve25519)
    - `kPUBS`:  客户端生成的密钥交换公钥
    - `kNONC`:  客户端生成的 nonce
    - 可能包含源地址令牌等其他信息。

**用户或编程常见的使用错误：**

1. **未提供 `ProofVerifier`:**  如果没有正确配置 `ProofVerifier`，客户端将无法验证服务器的证书，从而可能连接到恶意服务器。这通常发生在集成 QUIC 客户端时配置不当。

   ```c++
   // 错误示例：未设置 ProofVerifier
   QuicCryptoClientConfig config(nullptr); // 潜在的安全风险
   ```

2. **错误的服务器 ID:**  如果传递给 `LookupOrCreate` 或其他函数的 `QuicServerId` 与实际连接的服务器不匹配，可能导致无法找到或使用正确的缓存信息。

   ```c++
   QuicServerId server_id("wrong-example.com", 443);
   config.LookupOrCreate(server_id); // 查找错误的缓存
   ```

3. **忽略错误码:**  在处理服务器响应消息时，如果没有检查函数返回的 `QuicErrorCode`，可能会忽略重要的错误信息，导致连接建立失败或安全问题。

   ```c++
   std::string error_details;
   QuicErrorCode error = config.ProcessRejection(rej_message, now, version, chlo_hash, cached_state, negotiated_params, &error_details);
   // 错误示例：未检查 error
   ```

4. **缓存策略不当:**  如果缓存策略配置不当，例如缓存过期时间设置过短或过长，可能会影响连接性能和安全性。

5. **并发访问缓存:**  如果没有适当的同步机制，在多线程环境下并发访问 `cached_states_` 可能会导致数据竞争和程序崩溃。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在 Chrome 浏览器中访问 `https://www.example.com` (假设 `example.com` 支持 QUIC)。

1. **用户在地址栏输入 `www.example.com` 并按下回车。**

2. **浏览器解析 URL，确定需要建立 HTTPS 连接。**

3. **浏览器的网络栈检查是否需要使用 QUIC。** 这可能基于之前与 `example.com` 的连接记录或通过 DNS 查询获取的 ALPN 信息。

4. **如果决定使用 QUIC，网络栈会创建一个 QUIC 连接。**

5. **在 QUIC 连接建立的初始阶段，会调用 `QuicCryptoClientConfig` 的相关方法来处理加密握手。**

6. **`QuicCryptoClientConfig::LookupOrCreate(QuicServerId("www.example.com", 443))` 被调用。**

   - **调试线索:**  检查此时 `cached_states_` 中是否已经存在 `www.example.com` 的条目。如果存在，说明之前已经访问过该网站，可以尝试重用缓存信息。

7. **如果缓存中没有找到或缓存已过期，`QuicCryptoClientConfig::FillInchoateClientHello(...)` 或 `QuicCryptoClientConfig::FillClientHello(...)` 被调用，生成 CHLO 消息。**

   - **调试线索:**  查看生成的 CHLO 消息的内容，例如 `kSNI`, `kVER`, `kAEAD`, `kKEXS` 等字段是否符合预期。

8. **CHLO 消息被发送到服务器。**

9. **服务器响应 REJ 或 SHLO 消息。**

10. **`QuicCryptoClientConfig::ProcessRejection(...)` 或 `QuicCryptoClientConfig::ProcessServerHello(...)` 被调用，处理服务器的响应。**

    - **调试线索:**
        - 如果收到 REJ，检查 `CacheNewServerConfig` 的执行情况，看是否成功缓存了新的服务器配置。
        - 如果收到 SHLO，检查密钥交换是否成功，以及是否成功协商了加密算法。查看 `error_details` 可以获取更详细的错误信息。

11. **如果需要验证服务器证书，`QuicCryptoClientConfig::proof_verifier()->VerifyProof(...)` 会被调用。**

    - **调试线索:**  如果证书验证失败，需要检查 `ProofVerifier` 的配置以及服务器提供的证书链。

**通过查看 Chromium 的网络日志 (chrome://net-export/) 或使用 Wireshark 等网络抓包工具，可以更详细地跟踪 QUIC 连接建立的过程，包括 CHLO、SHLO 等消息的内容，从而帮助调试与 `quic_crypto_client_config.cc` 相关的加密握手问题。**

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/crypto/quic_crypto_client_config.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/crypto/quic_crypto_client_config.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/macros.h"
#include "absl/memory/memory.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "openssl/ssl.h"
#include "quiche/quic/core/crypto/cert_compressor.h"
#include "quiche/quic/core/crypto/chacha20_poly1305_encrypter.h"
#include "quiche/quic/core/crypto/crypto_framer.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/crypto/crypto_utils.h"
#include "quiche/quic/core/crypto/curve25519_key_exchange.h"
#include "quiche/quic/core/crypto/key_exchange.h"
#include "quiche/quic/core/crypto/p256_key_exchange.h"
#include "quiche/quic/core/crypto/proof_verifier.h"
#include "quiche/quic/core/crypto/quic_encrypter.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/crypto/tls_client_connection.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_client_stats.h"
#include "quiche/quic/platform/api/quic_hostname_utils.h"
#include "quiche/quic/platform/api/quic_logging.h"

namespace quic {

namespace {

// Tracks the reason (the state of the server config) for sending inchoate
// ClientHello to the server.
void RecordInchoateClientHelloReason(
    QuicCryptoClientConfig::CachedState::ServerConfigState state) {
  QUIC_CLIENT_HISTOGRAM_ENUM(
      "QuicInchoateClientHelloReason", state,
      QuicCryptoClientConfig::CachedState::SERVER_CONFIG_COUNT, "");
}

// Tracks the state of the QUIC server information loaded from the disk cache.
void RecordDiskCacheServerConfigState(
    QuicCryptoClientConfig::CachedState::ServerConfigState state) {
  QUIC_CLIENT_HISTOGRAM_ENUM(
      "QuicServerInfo.DiskCacheState", state,
      QuicCryptoClientConfig::CachedState::SERVER_CONFIG_COUNT, "");
}

}  // namespace

QuicCryptoClientConfig::QuicCryptoClientConfig(
    std::unique_ptr<ProofVerifier> proof_verifier)
    : QuicCryptoClientConfig(std::move(proof_verifier), nullptr) {}

QuicCryptoClientConfig::QuicCryptoClientConfig(
    std::unique_ptr<ProofVerifier> proof_verifier,
    std::shared_ptr<SessionCache> session_cache)
    : proof_verifier_(std::move(proof_verifier)),
      session_cache_(std::move(session_cache)),
      ssl_ctx_(TlsClientConnection::CreateSslCtx(
          !GetQuicFlag(quic_disable_client_tls_zero_rtt))) {
  QUICHE_DCHECK(proof_verifier_.get());
  SetDefaults();
}

QuicCryptoClientConfig::~QuicCryptoClientConfig() {}

QuicCryptoClientConfig::CachedState::CachedState()
    : server_config_valid_(false),
      expiration_time_(QuicWallTime::Zero()),
      generation_counter_(0) {}

QuicCryptoClientConfig::CachedState::~CachedState() {}

bool QuicCryptoClientConfig::CachedState::IsComplete(QuicWallTime now) const {
  if (server_config_.empty()) {
    RecordInchoateClientHelloReason(SERVER_CONFIG_EMPTY);
    return false;
  }

  if (!server_config_valid_) {
    RecordInchoateClientHelloReason(SERVER_CONFIG_INVALID);
    return false;
  }

  const CryptoHandshakeMessage* scfg = GetServerConfig();
  if (!scfg) {
    // Should be impossible short of cache corruption.
    RecordInchoateClientHelloReason(SERVER_CONFIG_CORRUPTED);
    QUICHE_DCHECK(false);
    return false;
  }

  if (now.IsBefore(expiration_time_)) {
    return true;
  }

  QUIC_CLIENT_HISTOGRAM_TIMES(
      "QuicClientHelloServerConfig.InvalidDuration",
      QuicTime::Delta::FromSeconds(now.ToUNIXSeconds() -
                                   expiration_time_.ToUNIXSeconds()),
      QuicTime::Delta::FromSeconds(60),              // 1 min.
      QuicTime::Delta::FromSeconds(20 * 24 * 3600),  // 20 days.
      50, "");
  RecordInchoateClientHelloReason(SERVER_CONFIG_EXPIRED);
  return false;
}

bool QuicCryptoClientConfig::CachedState::IsEmpty() const {
  return server_config_.empty();
}

const CryptoHandshakeMessage*
QuicCryptoClientConfig::CachedState::GetServerConfig() const {
  if (server_config_.empty()) {
    return nullptr;
  }

  if (!scfg_) {
    scfg_ = CryptoFramer::ParseMessage(server_config_);
    QUICHE_DCHECK(scfg_.get());
  }
  return scfg_.get();
}

QuicCryptoClientConfig::CachedState::ServerConfigState
QuicCryptoClientConfig::CachedState::SetServerConfig(
    absl::string_view server_config, QuicWallTime now, QuicWallTime expiry_time,
    std::string* error_details) {
  const bool matches_existing = server_config == server_config_;

  // Even if the new server config matches the existing one, we still wish to
  // reject it if it has expired.
  std::unique_ptr<CryptoHandshakeMessage> new_scfg_storage;
  const CryptoHandshakeMessage* new_scfg;

  if (!matches_existing) {
    new_scfg_storage = CryptoFramer::ParseMessage(server_config);
    new_scfg = new_scfg_storage.get();
  } else {
    new_scfg = GetServerConfig();
  }

  if (!new_scfg) {
    *error_details = "SCFG invalid";
    return SERVER_CONFIG_INVALID;
  }

  if (expiry_time.IsZero()) {
    uint64_t expiry_seconds;
    if (new_scfg->GetUint64(kEXPY, &expiry_seconds) != QUIC_NO_ERROR) {
      *error_details = "SCFG missing EXPY";
      return SERVER_CONFIG_INVALID_EXPIRY;
    }
    expiration_time_ = QuicWallTime::FromUNIXSeconds(expiry_seconds);
  } else {
    expiration_time_ = expiry_time;
  }

  if (now.IsAfter(expiration_time_)) {
    *error_details = "SCFG has expired";
    return SERVER_CONFIG_EXPIRED;
  }

  if (!matches_existing) {
    server_config_ = std::string(server_config);
    SetProofInvalid();
    scfg_ = std::move(new_scfg_storage);
  }
  return SERVER_CONFIG_VALID;
}

void QuicCryptoClientConfig::CachedState::InvalidateServerConfig() {
  server_config_.clear();
  scfg_.reset();
  SetProofInvalid();
}

void QuicCryptoClientConfig::CachedState::SetProof(
    const std::vector<std::string>& certs, absl::string_view cert_sct,
    absl::string_view chlo_hash, absl::string_view signature) {
  bool has_changed = signature != server_config_sig_ ||
                     chlo_hash != chlo_hash_ || certs_.size() != certs.size();

  if (!has_changed) {
    for (size_t i = 0; i < certs_.size(); i++) {
      if (certs_[i] != certs[i]) {
        has_changed = true;
        break;
      }
    }
  }

  if (!has_changed) {
    return;
  }

  // If the proof has changed then it needs to be revalidated.
  SetProofInvalid();
  certs_ = certs;
  cert_sct_ = std::string(cert_sct);
  chlo_hash_ = std::string(chlo_hash);
  server_config_sig_ = std::string(signature);
}

void QuicCryptoClientConfig::CachedState::Clear() {
  server_config_.clear();
  source_address_token_.clear();
  certs_.clear();
  cert_sct_.clear();
  chlo_hash_.clear();
  server_config_sig_.clear();
  server_config_valid_ = false;
  proof_verify_details_.reset();
  scfg_.reset();
  ++generation_counter_;
}

void QuicCryptoClientConfig::CachedState::ClearProof() {
  SetProofInvalid();
  certs_.clear();
  cert_sct_.clear();
  chlo_hash_.clear();
  server_config_sig_.clear();
}

void QuicCryptoClientConfig::CachedState::SetProofValid() {
  server_config_valid_ = true;
}

void QuicCryptoClientConfig::CachedState::SetProofInvalid() {
  server_config_valid_ = false;
  ++generation_counter_;
}

bool QuicCryptoClientConfig::CachedState::Initialize(
    absl::string_view server_config, absl::string_view source_address_token,
    const std::vector<std::string>& certs, const std::string& cert_sct,
    absl::string_view chlo_hash, absl::string_view signature, QuicWallTime now,
    QuicWallTime expiration_time) {
  QUICHE_DCHECK(server_config_.empty());

  if (server_config.empty()) {
    RecordDiskCacheServerConfigState(SERVER_CONFIG_EMPTY);
    return false;
  }

  std::string error_details;
  ServerConfigState state =
      SetServerConfig(server_config, now, expiration_time, &error_details);
  RecordDiskCacheServerConfigState(state);
  if (state != SERVER_CONFIG_VALID) {
    QUIC_DVLOG(1) << "SetServerConfig failed with " << error_details;
    return false;
  }

  chlo_hash_.assign(chlo_hash.data(), chlo_hash.size());
  server_config_sig_.assign(signature.data(), signature.size());
  source_address_token_.assign(source_address_token.data(),
                               source_address_token.size());
  certs_ = certs;
  cert_sct_ = cert_sct;
  return true;
}

const std::string& QuicCryptoClientConfig::CachedState::server_config() const {
  return server_config_;
}

const std::string& QuicCryptoClientConfig::CachedState::source_address_token()
    const {
  return source_address_token_;
}

const std::vector<std::string>& QuicCryptoClientConfig::CachedState::certs()
    const {
  return certs_;
}

const std::string& QuicCryptoClientConfig::CachedState::cert_sct() const {
  return cert_sct_;
}

const std::string& QuicCryptoClientConfig::CachedState::chlo_hash() const {
  return chlo_hash_;
}

const std::string& QuicCryptoClientConfig::CachedState::signature() const {
  return server_config_sig_;
}

bool QuicCryptoClientConfig::CachedState::proof_valid() const {
  return server_config_valid_;
}

uint64_t QuicCryptoClientConfig::CachedState::generation_counter() const {
  return generation_counter_;
}

const ProofVerifyDetails*
QuicCryptoClientConfig::CachedState::proof_verify_details() const {
  return proof_verify_details_.get();
}

void QuicCryptoClientConfig::CachedState::set_source_address_token(
    absl::string_view token) {
  source_address_token_ = std::string(token);
}

void QuicCryptoClientConfig::CachedState::set_cert_sct(
    absl::string_view cert_sct) {
  cert_sct_ = std::string(cert_sct);
}

void QuicCryptoClientConfig::CachedState::SetProofVerifyDetails(
    ProofVerifyDetails* details) {
  proof_verify_details_.reset(details);
}

void QuicCryptoClientConfig::CachedState::InitializeFrom(
    const QuicCryptoClientConfig::CachedState& other) {
  QUICHE_DCHECK(server_config_.empty());
  QUICHE_DCHECK(!server_config_valid_);
  server_config_ = other.server_config_;
  source_address_token_ = other.source_address_token_;
  certs_ = other.certs_;
  cert_sct_ = other.cert_sct_;
  chlo_hash_ = other.chlo_hash_;
  server_config_sig_ = other.server_config_sig_;
  server_config_valid_ = other.server_config_valid_;
  expiration_time_ = other.expiration_time_;
  if (other.proof_verify_details_ != nullptr) {
    proof_verify_details_.reset(other.proof_verify_details_->Clone());
  }
  ++generation_counter_;
}

void QuicCryptoClientConfig::SetDefaults() {
  // Key exchange methods.
  kexs = {kC255, kP256};

  // Authenticated encryption algorithms. Prefer AES-GCM if hardware-supported
  // fast implementation is available.
  if (EVP_has_aes_hardware() == 1) {
    aead = {kAESG, kCC20};
  } else {
    aead = {kCC20, kAESG};
  }
}

QuicCryptoClientConfig::CachedState* QuicCryptoClientConfig::LookupOrCreate(
    const QuicServerId& server_id) {
  auto it = cached_states_.find(server_id);
  if (it != cached_states_.end()) {
    return it->second.get();
  }

  CachedState* cached = new CachedState;
  cached_states_.insert(std::make_pair(server_id, absl::WrapUnique(cached)));
  bool cache_populated = PopulateFromCanonicalConfig(server_id, cached);
  QUIC_CLIENT_HISTOGRAM_BOOL(
      "QuicCryptoClientConfig.PopulatedFromCanonicalConfig", cache_populated,
      "");
  return cached;
}

void QuicCryptoClientConfig::ClearCachedStates(const ServerIdFilter& filter) {
  for (auto it = cached_states_.begin(); it != cached_states_.end(); ++it) {
    if (filter.Matches(it->first)) it->second->Clear();
  }
}

void QuicCryptoClientConfig::FillInchoateClientHello(
    const QuicServerId& server_id, const ParsedQuicVersion preferred_version,
    const CachedState* cached, QuicRandom* rand, bool demand_x509_proof,
    quiche::QuicheReferenceCountedPointer<QuicCryptoNegotiatedParameters>
        out_params,
    CryptoHandshakeMessage* out) const {
  out->set_tag(kCHLO);
  out->set_minimum_size(1);

  // Server name indication. We only send SNI if it's a valid domain name, as
  // per the spec.
  if (QuicHostnameUtils::IsValidSNI(server_id.host())) {
    out->SetStringPiece(kSNI, server_id.host());
  }
  out->SetVersion(kVER, preferred_version);

  if (!user_agent_id_.empty()) {
    out->SetStringPiece(kUAID, user_agent_id_);
  }

  if (!alpn_.empty()) {
    out->SetStringPiece(kALPN, alpn_);
  }

  // Even though this is an inchoate CHLO, send the SCID so that
  // the STK can be validated by the server.
  const CryptoHandshakeMessage* scfg = cached->GetServerConfig();
  if (scfg != nullptr) {
    absl::string_view scid;
    if (scfg->GetStringPiece(kSCID, &scid)) {
      out->SetStringPiece(kSCID, scid);
    }
  }

  if (!cached->source_address_token().empty()) {
    out->SetStringPiece(kSourceAddressTokenTag, cached->source_address_token());
  }

  if (!demand_x509_proof) {
    return;
  }

  char proof_nonce[32];
  rand->RandBytes(proof_nonce, ABSL_ARRAYSIZE(proof_nonce));
  out->SetStringPiece(
      kNONP, absl::string_view(proof_nonce, ABSL_ARRAYSIZE(proof_nonce)));

  out->SetVector(kPDMD, QuicTagVector{kX509});

  out->SetStringPiece(kCertificateSCTTag, "");

  const std::vector<std::string>& certs = cached->certs();
  // We save |certs| in the QuicCryptoNegotiatedParameters so that, if the
  // client config is being used for multiple connections, another connection
  // doesn't update the cached certificates and cause us to be unable to
  // process the server's compressed certificate chain.
  out_params->cached_certs = certs;
  if (!certs.empty()) {
    std::vector<uint64_t> hashes;
    hashes.reserve(certs.size());
    for (auto i = certs.begin(); i != certs.end(); ++i) {
      hashes.push_back(QuicUtils::FNV1a_64_Hash(*i));
    }
    out->SetVector(kCCRT, hashes);
  }
}

QuicErrorCode QuicCryptoClientConfig::FillClientHello(
    const QuicServerId& server_id, QuicConnectionId connection_id,
    const ParsedQuicVersion preferred_version,
    const ParsedQuicVersion actual_version, const CachedState* cached,
    QuicWallTime now, QuicRandom* rand,
    quiche::QuicheReferenceCountedPointer<QuicCryptoNegotiatedParameters>
        out_params,
    CryptoHandshakeMessage* out, std::string* error_details) const {
  QUICHE_DCHECK(error_details != nullptr);
  QUIC_BUG_IF(quic_bug_12943_2,
              !QuicUtils::IsConnectionIdValidForVersion(
                  connection_id, preferred_version.transport_version))
      << "FillClientHello: attempted to use connection ID " << connection_id
      << " which is invalid with version " << preferred_version;

  FillInchoateClientHello(server_id, preferred_version, cached, rand,
                          /* demand_x509_proof= */ true, out_params, out);

  out->set_minimum_size(1);

  const CryptoHandshakeMessage* scfg = cached->GetServerConfig();
  if (!scfg) {
    // This should never happen as our caller should have checked
    // cached->IsComplete() before calling this function.
    *error_details = "Handshake not ready";
    return QUIC_CRYPTO_INTERNAL_ERROR;
  }

  absl::string_view scid;
  if (!scfg->GetStringPiece(kSCID, &scid)) {
    *error_details = "SCFG missing SCID";
    return QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER;
  }
  out->SetStringPiece(kSCID, scid);

  out->SetStringPiece(kCertificateSCTTag, "");

  QuicTagVector their_aeads;
  QuicTagVector their_key_exchanges;
  if (scfg->GetTaglist(kAEAD, &their_aeads) != QUIC_NO_ERROR ||
      scfg->GetTaglist(kKEXS, &their_key_exchanges) != QUIC_NO_ERROR) {
    *error_details = "Missing AEAD or KEXS";
    return QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER;
  }

  // AEAD: the work loads on the client and server are symmetric. Since the
  // client is more likely to be CPU-constrained, break the tie by favoring
  // the client's preference.
  // Key exchange: the client does more work than the server, so favor the
  // client's preference.
  size_t key_exchange_index;
  if (!FindMutualQuicTag(aead, their_aeads, &out_params->aead, nullptr) ||
      !FindMutualQuicTag(kexs, their_key_exchanges, &out_params->key_exchange,
                         &key_exchange_index)) {
    *error_details = "Unsupported AEAD or KEXS";
    return QUIC_CRYPTO_NO_SUPPORT;
  }
  out->SetVector(kAEAD, QuicTagVector{out_params->aead});
  out->SetVector(kKEXS, QuicTagVector{out_params->key_exchange});

  absl::string_view public_value;
  if (scfg->GetNthValue24(kPUBS, key_exchange_index, &public_value) !=
      QUIC_NO_ERROR) {
    *error_details = "Missing public value";
    return QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER;
  }

  absl::string_view orbit;
  if (!scfg->GetStringPiece(kORBT, &orbit) || orbit.size() != kOrbitSize) {
    *error_details = "SCFG missing OBIT";
    return QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND;
  }

  CryptoUtils::GenerateNonce(now, rand, orbit, &out_params->client_nonce);
  out->SetStringPiece(kNONC, out_params->client_nonce);
  if (!out_params->server_nonce.empty()) {
    out->SetStringPiece(kServerNonceTag, out_params->server_nonce);
  }

  switch (out_params->key_exchange) {
    case kC255:
      out_params->client_key_exchange = Curve25519KeyExchange::New(
          Curve25519KeyExchange::NewPrivateKey(rand));
      break;
    case kP256:
      out_params->client_key_exchange =
          P256KeyExchange::New(P256KeyExchange::NewPrivateKey());
      break;
    default:
      QUICHE_DCHECK(false);
      *error_details = "Configured to support an unknown key exchange";
      return QUIC_CRYPTO_INTERNAL_ERROR;
  }

  if (!out_params->client_key_exchange->CalculateSharedKeySync(
          public_value, &out_params->initial_premaster_secret)) {
    *error_details = "Key exchange failure";
    return QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER;
  }
  out->SetStringPiece(kPUBS, out_params->client_key_exchange->public_value());

  const std::vector<std::string>& certs = cached->certs();
  if (certs.empty()) {
    *error_details = "No certs to calculate XLCT";
    return QUIC_CRYPTO_INTERNAL_ERROR;
  }
  out->SetValue(kXLCT, CryptoUtils::ComputeLeafCertHash(certs[0]));

  // Derive the symmetric keys and set up the encrypters and decrypters.
  // Set the following members of out_params:
  //   out_params->hkdf_input_suffix
  //   out_params->initial_crypters
  out_params->hkdf_input_suffix.clear();
  out_params->hkdf_input_suffix.append(connection_id.data(),
                                       connection_id.length());
  const QuicData& client_hello_serialized = out->GetSerialized();
  out_params->hkdf_input_suffix.append(client_hello_serialized.data(),
                                       client_hello_serialized.length());
  out_params->hkdf_input_suffix.append(cached->server_config());
  if (certs.empty()) {
    *error_details = "No certs found to include in KDF";
    return QUIC_CRYPTO_INTERNAL_ERROR;
  }
  out_params->hkdf_input_suffix.append(certs[0]);

  std::string hkdf_input;
  const size_t label_len = strlen(QuicCryptoConfig::kInitialLabel) + 1;
  hkdf_input.reserve(label_len + out_params->hkdf_input_suffix.size());
  hkdf_input.append(QuicCryptoConfig::kInitialLabel, label_len);
  hkdf_input.append(out_params->hkdf_input_suffix);

  std::string* subkey_secret = &out_params->initial_subkey_secret;

  if (!CryptoUtils::DeriveKeys(
          actual_version, out_params->initial_premaster_secret,
          out_params->aead, out_params->client_nonce, out_params->server_nonce,
          pre_shared_key_, hkdf_input, Perspective::IS_CLIENT,
          CryptoUtils::Diversification::Pending(),
          &out_params->initial_crypters, subkey_secret)) {
    *error_details = "Symmetric key setup failed";
    return QUIC_CRYPTO_SYMMETRIC_KEY_SETUP_FAILED;
  }

  return QUIC_NO_ERROR;
}

QuicErrorCode QuicCryptoClientConfig::CacheNewServerConfig(
    const CryptoHandshakeMessage& message, QuicWallTime now,
    QuicTransportVersion /*version*/, absl::string_view chlo_hash,
    const std::vector<std::string>& cached_certs, CachedState* cached,
    std::string* error_details) {
  QUICHE_DCHECK(error_details != nullptr);

  absl::string_view scfg;
  if (!message.GetStringPiece(kSCFG, &scfg)) {
    *error_details = "Missing SCFG";
    return QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND;
  }

  QuicWallTime expiration_time = QuicWallTime::Zero();
  uint64_t expiry_seconds;
  if (message.GetUint64(kSTTL, &expiry_seconds) == QUIC_NO_ERROR) {
    // Only cache configs for a maximum of 1 week.
    expiration_time = now.Add(QuicTime::Delta::FromSeconds(
        std::min(expiry_seconds, kNumSecondsPerWeek)));
  }

  CachedState::ServerConfigState state =
      cached->SetServerConfig(scfg, now, expiration_time, error_details);
  if (state == CachedState::SERVER_CONFIG_EXPIRED) {
    return QUIC_CRYPTO_SERVER_CONFIG_EXPIRED;
  }
  // TODO(rtenneti): Return more specific error code than returning
  // QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER.
  if (state != CachedState::SERVER_CONFIG_VALID) {
    return QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER;
  }

  absl::string_view token;
  if (message.GetStringPiece(kSourceAddressTokenTag, &token)) {
    cached->set_source_address_token(token);
  }

  absl::string_view proof, cert_bytes, cert_sct;
  bool has_proof = message.GetStringPiece(kPROF, &proof);
  bool has_cert = message.GetStringPiece(kCertificateTag, &cert_bytes);
  if (has_proof && has_cert) {
    std::vector<std::string> certs;
    if (!CertCompressor::DecompressChain(cert_bytes, cached_certs, &certs)) {
      *error_details = "Certificate data invalid";
      return QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER;
    }

    message.GetStringPiece(kCertificateSCTTag, &cert_sct);
    cached->SetProof(certs, cert_sct, chlo_hash, proof);
  } else {
    // Secure QUIC: clear existing proof as we have been sent a new SCFG
    // without matching proof/certs.
    cached->ClearProof();

    if (has_proof && !has_cert) {
      *error_details = "Certificate missing";
      return QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER;
    }

    if (!has_proof && has_cert) {
      *error_details = "Proof missing";
      return QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER;
    }
  }

  return QUIC_NO_ERROR;
}

QuicErrorCode QuicCryptoClientConfig::ProcessRejection(
    const CryptoHandshakeMessage& rej, QuicWallTime now,
    const QuicTransportVersion version, absl::string_view chlo_hash,
    CachedState* cached,
    quiche::QuicheReferenceCountedPointer<QuicCryptoNegotiatedParameters>
        out_params,
    std::string* error_details) {
  QUICHE_DCHECK(error_details != nullptr);

  if (rej.tag() != kREJ) {
    *error_details = "Message is not REJ";
    return QUIC_CRYPTO_INTERNAL_ERROR;
  }

  QuicErrorCode error =
      CacheNewServerConfig(rej, now, version, chlo_hash,
                           out_params->cached_certs, cached, error_details);
  if (error != QUIC_NO_ERROR) {
    return error;
  }

  absl::string_view nonce;
  if (rej.GetStringPiece(kServerNonceTag, &nonce)) {
    out_params->server_nonce = std::string(nonce);
  }

  return QUIC_NO_ERROR;
}

QuicErrorCode QuicCryptoClientConfig::ProcessServerHello(
    const CryptoHandshakeMessage& server_hello,
    QuicConnectionId /*connection_id*/, ParsedQuicVersion version,
    const ParsedQuicVersionVector& negotiated_versions, CachedState* cached,
    quiche::QuicheReferenceCountedPointer<QuicCryptoNegotiatedParameters>
        out_params,
    std::string* error_details) {
  QUICHE_DCHECK(error_details != nullptr);

  QuicErrorCode valid = CryptoUtils::ValidateServerHello(
      server_hello, negotiated_versions, error_details);
  if (valid != QUIC_NO_ERROR) {
    return valid;
  }

  // Learn about updated source address tokens.
  absl::string_view token;
  if (server_hello.GetStringPiece(kSourceAddressTokenTag, &token)) {
    cached->set_source_address_token(token);
  }

  absl::string_view shlo_nonce;
  if (!server_hello.GetStringPiece(kServerNonceTag, &shlo_nonce)) {
    *error_details = "server hello missing server nonce";
    return QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER;
  }

  // TODO(agl):
  //   learn about updated SCFGs.

  absl::string_view public_value;
  if (!server_hello.GetStringPiece(kPUBS, &public_value)) {
    *error_details = "server hello missing forward secure public value";
    return QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER;
  }

  if (!out_params->client_key_exchange->CalculateSharedKeySync(
          public_value, &out_params->forward_secure_premaster_secret)) {
    *error_details = "Key exchange failure";
    return QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER;
  }

  std::string hkdf_input;
  const size_t label_len = strlen(QuicCryptoConfig::kForwardSecureLabel) + 1;
  hkdf_input.reserve(label_len + out_params->hkdf_input_suffix.size());
  hkdf_input.append(QuicCryptoConfig::kForwardSecureLabel, label_len);
  hkdf_input.append(out_params->hkdf_input_suffix);

  if (!CryptoUtils::DeriveKeys(
          version, out_params->forward_secure_premaster_secret,
          out_params->aead, out_params->client_nonce,
          shlo_nonce.empty() ? out_params->server_nonce : shlo_nonce,
          pre_shared_key_, hkdf_input, Perspective::IS_CLIENT,
          CryptoUtils::Diversification::Never(),
          &out_params->forward_secure_crypters, &out_params->subkey_secret)) {
    *error_details = "Symmetric key setup failed";
    return QUIC_CRYPTO_SYMMETRIC_KEY_SETUP_FAILED;
  }

  return QUIC_NO_ERROR;
}

QuicErrorCode QuicCryptoClientConfig::ProcessServerConfigUpdate(
    const CryptoHandshakeMessage& server_config_update, QuicWallTime now,
    const QuicTransportVersion version, absl::string_view chlo_hash,
    CachedState* cached,
    quiche::QuicheReferenceCountedPointer<QuicCryptoNegotiatedParameters>
        out_params,
    std::string* error_details) {
  QUICHE_DCHECK(error_details != nullptr);

  if (server_config_update.tag() != kSCUP) {
    *error_details = "ServerConfigUpdate must have kSCUP tag.";
    return QUIC_INVALID_CRYPTO_MESSAGE_TYPE;
  }
  return CacheNewServerConfig(server_config_update, now, version, chlo_hash,
                              out_params->cached_certs, cached, error_details);
}

ProofVerifier* QuicCryptoClientConfig::proof_verifier() const {
  return proof_verifier_.get();
}

SessionCache* QuicCryptoClientConfig::session_cache() const {
  return session_cache_.get();
}

void QuicCryptoClientConfig::set_session_cache(
    std::shared_ptr<SessionCache> session_cache) {
  session_cache_ = std::move(session_cache);
}

ClientProofSource* QuicCryptoClientConfig::proof_source() const {
  return proof_source_.get();
}

void QuicCryptoClientConfig::set_proof_source(
    std::unique_ptr<ClientProofSource> proof_source) {
  proof_source_ = std::move(proof_source);
}

SSL_CTX* QuicCryptoClientConfig::ssl_ctx() const { return ssl_ctx_.get(); }

void QuicCryptoClientConfig::InitializeFrom(
    const QuicServerId& server_id, const QuicServerId& canonical_server_id,
    QuicCryptoClientConfig* canonical_crypto_config) {
  CachedState* canonical_cached =
      canonical_crypto_config->LookupOrCreate(canonical_server_id);
  if (!canonical_cached->proof_valid()) {
    return;
  }
  CachedState* cached = LookupOrCreate(server_id);
  cached->InitializeFrom(*canonical_cached);
}

void QuicCryptoClientConfig::AddCanonicalSuffix(const std::string& suffix) {
  canonical_suffixes_.push_back(suffix);
}

bool QuicCryptoClientConfig::PopulateFromCanonicalConfig(
    const QuicServerId& server_id, CachedState* cached) {
  QUICHE_DCHECK(cached->IsEmpty());
  size_t i = 0;
  for (; i < canonical_suffixes_.size(); ++i) {
    if (absl::EndsWithIgnoreCase(server_id.host(), canonical_suffixes_[i])) {
      break;
    }
  }
  if (i == canonical_suffixes_.size()) {
    return false;
  }

  QuicServerId suffix_server_id(canonical_suffixes_[i], server_id.port());
  auto it = canonical_server_map_.lower_bound(suffix_server_id);
  if (it == canonical_server_map_.end() || it->first != suffix_server_id) {
    // This is the first host we've seen which matches the suffix, so make it
    // canonical.  Use |it| as position hint for faster insertion.
    canonical_server_map_.insert(
        it, std::make_pair(std::move(suffix_server_id), std::move(server_id)));
    return false;
  }

  const QuicServerId& canonical_server_id = it->second;
  CachedState* canonical_state = cached_states_[canonical_server_id].get();
  if (!canonical_state->proof_valid()) {
    return false;
  }

  // Update canonical version to point at the "most recent" entry.
  it->second = server_id;

  cached->InitializeFrom(*canonical_state);
  return true;
}

}  // namespace quic
```