Response:
My thinking process to analyze the provided C++ code snippet and address the user's request involved these steps:

1. **Understand the Goal:** The user wants to understand the functionality of `quic_crypto_server_config.cc`, its relation to JavaScript (if any), common usage errors, debugging tips, and a summary of its function within the provided snippet. This is part 1 of a 3-part analysis, so focusing on the given code is crucial.

2. **Initial Code Scan and Keyword Identification:** I quickly scanned the code for key terms and patterns. I noticed:
    * `#include` statements indicating dependencies (crypto, networking, protobuf).
    * Class definition: `QuicCryptoServerConfig`.
    * Methods with names like `ValidateClientHello`, `ProcessClientHello`, `AddConfig`, `GenerateConfig`, `SetConfigs`. These suggest the core purpose is managing server-side crypto configuration and handling client hello messages.
    * Cryptographic primitives: AES-GCM, ChaCha20-Poly1305, key exchange (Curve25519, P-256), HKDF.
    * Protocol concepts: SCID, source address token, server nonce, diversification nonce, handshake messages (CHLO, REJ, SHLO).
    * `ProofSource`: Implies certificate handling and verification.
    *  Locking mechanisms (`configs_lock_`).
    *  Logging and debugging utilities (`QUIC_LOG`, `QUIC_BUG`).

3. **Identify Core Functionality:** Based on the keywords and methods, I deduced the primary functions of the file:
    * **Server Configuration Management:**  Creating, storing, updating, and selecting server crypto configurations (SCFG). This involves generating keys, public parameters, and identifiers (SCID).
    * **Client Hello Processing:** Receiving and validating client hello messages (CHLO). This includes checking the version, supported features, and requesting configurations.
    * **Security Negotiation:**  Handling key exchange, AEAD selection, and proof requests.
    * **Rejection Handling:**  Constructing and sending rejection messages (REJ) when necessary.
    * **Source Address Token Management:** Generating and validating tokens to prevent amplification attacks.
    * **Proof of Possession:**  Interacting with a `ProofSource` to obtain and verify certificates.

4. **JavaScript Relationship Analysis:** I carefully considered potential links to JavaScript. Since this is server-side Chromium networking code, direct interaction is unlikely. The connection is more conceptual:
    * **TLS/QUIC in Browsers:** JavaScript running in a browser *uses* the QUIC protocol, which relies on configurations managed by code like this on the server. However, JavaScript doesn't directly manipulate these C++ classes.
    * **Web Crypto API:**  While the *purpose* of this C++ code is to establish secure connections,  the *Web Crypto API* in JavaScript provides similar cryptographic functionalities *within the browser*. These are separate implementations but serve related goals.

5. **Logical Inference (Hypothetical Input/Output):** I considered a simplified scenario for `ValidateClientHello`:
    * **Input:** A raw CHLO message, client IP address, server IP address, QUIC version.
    * **Processing:** The function would parse the CHLO, check for a matching SCID, retrieve the corresponding server configuration, and potentially initiate proof verification.
    * **Output:**  A success or failure indication, potentially with an error code and details. The `ValidateClientHelloResultCallback` handles the asynchronous nature.

6. **Common Usage Errors:** I brainstormed typical mistakes a *developer* implementing or using this class might make:
    * **Incorrect Configuration:** Providing invalid or mismatched private keys, certificates, or other configuration parameters.
    * **Missing Dependencies:** Failing to initialize the `ProofSource` or `KeyExchangeSource`.
    * **Incorrect Timing:**  Issues with the expiration times of configurations or source address tokens.
    * **Concurrency Issues:** Although the code uses locks, misuse in a larger system could lead to race conditions.
    * **Misunderstanding the Asynchronous Nature:** Not properly handling the callbacks for validation and processing.

7. **Debugging Clues (User Operation to Code):** I thought about how a user's action might lead to this code being executed:
    * **User Browsing a Website:**  The most common scenario. The browser initiates a QUIC connection.
    * **Browser Sends CHLO:** The browser constructs a Client Hello message.
    * **Server Receives CHLO:** The server's QUIC stack receives the CHLO.
    * **`QuicCryptoServerConfig::ValidateClientHello` is Called:**  The server calls this function to validate the incoming CHLO.

8. **Summarization (Part 1):** Based on the analysis, I formulated a concise summary of the code's functionality, focusing on the key aspects evident in the provided snippet: managing server-side crypto configurations and the initial validation of client hello messages.

9. **Structure and Refine:** I organized my thoughts into the requested sections: functionality, JavaScript relationship, logical inference, common errors, debugging clues, and summarization. I used clear and concise language, avoiding excessive jargon where possible. I made sure to emphasize that this analysis is based *only* on the provided snippet.

This iterative process of scanning, identifying, deducing, and organizing helped me arrive at the detailed and structured answer provided earlier. I anticipated the user's intent to understand the role of this specific file within the broader QUIC implementation.
好的，根据您提供的 Chromium 网络栈的源代码文件 `net/third_party/quiche/src/quiche/quic/core/crypto/quic_crypto_server_config.cc` 的前一部分，我们可以归纳一下它的主要功能：

**核心功能：管理 QUIC 服务器的加密配置**

这个文件的主要目的是实现 `QuicCryptoServerConfig` 类，该类负责管理 QUIC 服务器用于建立安全连接所需的各种加密配置。  这些配置包括：

* **服务器配置 (SCFG):**  生成、存储和管理服务器的长期加密配置信息，例如公钥、支持的密钥交换算法 (KEXS)、认证加密算法 (AEAD) 等。
* **密钥交换 (Key Exchange):**  管理和选择用于密钥协商的算法，例如 Curve25519 和 P-256。
* **认证 (Proof):**  与 `ProofSource` 接口交互，获取服务器的证书链和签名，用于向客户端证明服务器的身份。
* **源地址令牌 (Source Address Token):**  生成和验证源地址令牌，用于防止放大攻击。
* **服务器 Nonce:**  生成和管理服务器 Nonce，用于防止重放攻击。
* **客户端 Hello 处理 (Client Hello Processing):**  接收、验证和处理客户端发送的 `ClientHello` 消息 (CHLO)。
* **拒绝消息 (Rejection Message):**  构建和发送拒绝消息 (REJ) 给客户端，当客户端的 `ClientHello` 消息不符合要求时。
* **配置更新:** 支持动态更新服务器配置。

**具体功能点概括：**

1. **配置生成与存储:**
   - 提供 `GenerateConfig` 静态方法，用于生成新的 `QuicServerConfigProtobuf` 格式的服务器配置。
   - 维护一个 `configs_` 映射，用于存储可用的服务器配置，并使用 `configs_lock_` 进行并发控制。
   - 支持添加新的配置 (`AddConfig`, `AddDefaultConfig`) 和批量设置配置 (`SetConfigs`).

2. **客户端 Hello 验证 (`ValidateClientHello`):**
   - 接收客户端的 `ClientHello` 消息，并对其进行初步验证，例如检查是否存在请求的服务器配置 ID (SCID)。
   - 与 `ProofSource` 交互，请求获取用于验证服务器身份的证书链和签名。

3. **客户端 Hello 处理 (`ProcessClientHello`):**
   - 在 `ValidateClientHello` 成功后，对客户端的 `ClientHello` 消息进行更深入的处理。
   - 检查客户端是否要求 X.509 证书。
   - 协商加密参数，例如密钥交换算法和认证加密算法。
   - 如果验证失败，则构建并发送拒绝消息 (REJ)。
   - 与 `ProofSource` 交互，获取或使用已获取的证书链和签名。

4. **源地址令牌管理:**
   - 使用 `source_address_token_boxer_` 生成和解密源地址令牌。
   - 提供 `DeriveSourceAddressTokenKey` 函数来派生用于令牌加密的密钥。

5. **密钥交换管理:**
   - 使用 `KeyExchangeSource` 接口来创建密钥交换对象，默认使用 `DefaultKeyExchangeSource`。

6. **错误处理与日志记录:**
   - 使用 `QUIC_LOG` 进行日志记录，方便调试。
   - 在处理过程中，如果出现错误，会设置相应的错误码和错误信息。

**与 JavaScript 的关系：**

这段 C++ 代码直接运行在服务器端，负责处理 QUIC 连接的底层加密握手。JavaScript 通常运行在客户端（浏览器或 Node.js 环境）。

* **间接关系：** JavaScript 通过浏览器或 Node.js 的网络 API 发起 QUIC 连接，最终服务器会执行这段 C++ 代码来处理连接请求和进行加密协商。  JavaScript 代码不需要直接操作这些 C++ 类。
* **概念上的联系：**  QUIC 协议的设计目标之一是提升 Web 应用的性能和安全性。  JavaScript 编写的 Web 应用会受益于 QUIC 提供的更快的连接建立和更强的加密保护。

**举例说明：**

假设一个用户在浏览器中访问一个使用了 QUIC 协议的网站：

1. **用户操作：** 用户在浏览器地址栏输入网址并按下回车。
2. **浏览器行为：** 浏览器尝试与服务器建立 QUIC 连接。
3. **CHLO 发送：** 浏览器构造一个 `ClientHello` 消息 (CHLO)，其中包含浏览器支持的 QUIC 版本、加密算法等信息。
4. **服务器接收：** 服务器接收到浏览器的 CHLO 消息。
5. **`ValidateClientHello` 调用：** 服务器上的 QUIC 实现调用 `QuicCryptoServerConfig` 的 `ValidateClientHello` 方法来初步验证 CHLO。
    * **假设输入：** 一个包含了客户端支持的 QUIC 版本、请求的 SCID、以及其他加密参数的 `CryptoHandshakeMessage` 对象，客户端和服务器的 IP 地址，当前的 `QuicClock`。
    * **逻辑推理：** `ValidateClientHello` 会检查 CHLO 的基本格式，尝试找到与 CHLO 中 SCID 匹配的服务器配置，并请求 `ProofSource` 提供证书链和签名。
    * **假设输出：** 如果初步验证通过，会调用传入的 `ValidateClientHelloResultCallback`，指示验证成功，并可能包含找到的服务器配置信息。如果验证失败，会指示验证失败，并包含错误码和错误信息。
6. **`ProcessClientHello` 调用：** 如果 `ValidateClientHello` 成功，服务器可能会调用 `ProcessClientHello` 方法进行更深入的处理。
    * **假设输入：**  `ValidateClientHello` 的结果，连接 ID，服务器和客户端地址，支持的 QUIC 版本，当前时间，随机数生成器，证书缓存，已协商的参数，签名后的服务器配置，帧开销，CHLO 包大小等。
    * **逻辑推理：** `ProcessClientHello` 会进一步验证 CHLO 的内容，例如检查是否要求 X.509 证书，协商加密算法，并最终构建服务器的响应消息 (例如 Server Hello 或 Rejection)。
    * **假设输出：** 如果处理成功，会调用 `ProcessClientHelloResultCallback`，携带服务器的响应消息、分化 Nonce 和证明细节。如果处理失败，会携带错误码和错误信息。

**用户或编程常见的使用错误：**

1. **配置错误：**  服务器管理员配置了错误的证书、私钥或者加密参数，导致握手失败。
   * **例子：**  服务器配置的私钥与证书不匹配。
2. **`ProofSource` 未正确实现或配置：** `QuicCryptoServerConfig` 依赖于 `ProofSource` 来获取证书和签名。如果 `ProofSource` 没有正确实现或者配置，服务器将无法提供有效的身份证明。
   * **例子：**  `ProofSource` 指向的证书文件不存在或者格式不正确。
3. **源地址令牌密钥管理不当：** 如果源地址令牌的密钥泄露或者轮换不当，可能导致安全风险。
4. **并发问题：**  在多线程环境下，如果没有正确使用锁 (`configs_lock_`)，可能会导致配置数据竞争和不一致。
5. **回调函数处理错误：**  `ValidateClientHello` 和 `ProcessClientHello` 使用回调函数来处理异步操作的结果。如果回调函数没有正确实现，可能会导致资源泄漏或者程序逻辑错误。

**用户操作如何到达这里（调试线索）：**

1. 用户尝试通过支持 QUIC 协议的浏览器访问一个启用了 QUIC 的网站。
2. 浏览器发起 QUIC 连接，并发送一个 `ClientHello` 数据包。
3. 服务器的网络栈接收到该数据包。
4. 服务器的 QUIC 实现解析该数据包，提取出 `ClientHello` 消息。
5. 服务器的 QUIC 加密组件会调用 `QuicCryptoServerConfig::ValidateClientHello` 方法来处理这个 `ClientHello` 消息。
6. 在 `ValidateClientHello` 内部，会涉及到从 `configs_` 映射中查找匹配的服务器配置，并与配置的 `ProofSource` 交互。
7. 如果需要更深入的处理，例如协商加密参数，则会调用 `QuicCryptoServerConfig::ProcessClientHello` 方法。

因此，在调试 QUIC 服务器的连接问题时，如果发现握手阶段出现问题，例如服务器发送了 REJECT 消息或者连接建立失败，可以查看服务器端的日志，重点关注 `QuicCryptoServerConfig` 相关的日志信息，例如配置加载情况、`ValidateClientHello` 和 `ProcessClientHello` 的执行结果，以及与 `ProofSource` 交互的信息，从而定位问题。

**总结 (针对第 1 部分):**

`net/third_party/quiche/src/quiche/quic/core/crypto/quic_crypto_server_config.cc` 的第一部分主要定义了 `QuicCryptoServerConfig` 类的基本结构和核心功能，包括服务器加密配置的生成、存储和管理，以及对客户端 `ClientHello` 消息的初步验证和处理框架。它为后续的加密协商和连接建立奠定了基础。  核心是围绕 `ValidateClientHello` 展开，初步判断客户端的请求是否可以接受，并为后续的 `ProcessClientHello` 做好准备。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/crypto/quic_crypto_server_config.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/crypto/quic_crypto_server_config.h"

#include <algorithm>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "openssl/sha.h"
#include "openssl/ssl.h"
#include "quiche/quic/core/crypto/aes_128_gcm_12_decrypter.h"
#include "quiche/quic/core/crypto/aes_128_gcm_12_encrypter.h"
#include "quiche/quic/core/crypto/cert_compressor.h"
#include "quiche/quic/core/crypto/certificate_view.h"
#include "quiche/quic/core/crypto/chacha20_poly1305_encrypter.h"
#include "quiche/quic/core/crypto/channel_id.h"
#include "quiche/quic/core/crypto/crypto_framer.h"
#include "quiche/quic/core/crypto/crypto_handshake_message.h"
#include "quiche/quic/core/crypto/crypto_utils.h"
#include "quiche/quic/core/crypto/curve25519_key_exchange.h"
#include "quiche/quic/core/crypto/key_exchange.h"
#include "quiche/quic/core/crypto/p256_key_exchange.h"
#include "quiche/quic/core/crypto/proof_source.h"
#include "quiche/quic/core/crypto/quic_decrypter.h"
#include "quiche/quic/core/crypto/quic_encrypter.h"
#include "quiche/quic/core/crypto/quic_hkdf.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/crypto/tls_server_connection.h"
#include "quiche/quic/core/proto/crypto_server_config_proto.h"
#include "quiche/quic/core/proto/source_address_token_proto.h"
#include "quiche/quic/core/quic_clock.h"
#include "quiche/quic/core/quic_connection_context.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_socket_address_coder.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_hostname_utils.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/platform/api/quic_testvalue.h"
#include "quiche/common/platform/api/quiche_reference_counted.h"

namespace quic {

namespace {

// kMultiplier is the multiple of the CHLO message size that a REJ message
// must stay under when the client doesn't present a valid source-address
// token. This is used to protect QUIC from amplification attacks.
// TODO(rch): Reduce this to 2 again once b/25933682 is fixed.
const size_t kMultiplier = 3;

const int kMaxTokenAddresses = 4;

std::string DeriveSourceAddressTokenKey(
    absl::string_view source_address_token_secret) {
  QuicHKDF hkdf(source_address_token_secret, absl::string_view() /* no salt */,
                "QUIC source address token key",
                CryptoSecretBoxer::GetKeySize(), 0 /* no fixed IV needed */,
                0 /* no subkey secret */);
  return std::string(hkdf.server_write_key());
}

// Default source for creating KeyExchange objects.
class DefaultKeyExchangeSource : public KeyExchangeSource {
 public:
  DefaultKeyExchangeSource() = default;
  ~DefaultKeyExchangeSource() override = default;

  std::unique_ptr<AsynchronousKeyExchange> Create(
      std::string /*server_config_id*/, bool /* is_fallback */, QuicTag type,
      absl::string_view private_key) override {
    if (private_key.empty()) {
      QUIC_LOG(WARNING) << "Server config contains key exchange method without "
                           "corresponding private key of type "
                        << QuicTagToString(type);
      return nullptr;
    }

    std::unique_ptr<SynchronousKeyExchange> ka =
        CreateLocalSynchronousKeyExchange(type, private_key);
    if (!ka) {
      QUIC_LOG(WARNING) << "Failed to create key exchange method of type "
                        << QuicTagToString(type);
    }
    return ka;
  }
};

// Returns true if the PDMD field from the client hello demands an X509
// certificate.
bool ClientDemandsX509Proof(const CryptoHandshakeMessage& client_hello) {
  QuicTagVector their_proof_demands;

  if (client_hello.GetTaglist(kPDMD, &their_proof_demands) != QUIC_NO_ERROR) {
    return false;
  }

  for (const QuicTag tag : their_proof_demands) {
    if (tag == kX509) {
      return true;
    }
  }
  return false;
}

std::string FormatCryptoHandshakeMessageForTrace(
    const CryptoHandshakeMessage* message) {
  if (message == nullptr) {
    return "<null message>";
  }

  std::string s = QuicTagToString(message->tag());

  // Append the reasons for REJ.
  if (const auto it = message->tag_value_map().find(kRREJ);
      it != message->tag_value_map().end()) {
    const std::string& value = it->second;
    // The value is a vector of uint32_t(s).
    if (value.size() % sizeof(uint32_t) == 0) {
      absl::StrAppend(&s, " RREJ:[");
      // Append comma-separated list of reasons to |s|.
      for (size_t j = 0; j < value.size(); j += sizeof(uint32_t)) {
        uint32_t reason;
        memcpy(&reason, value.data() + j, sizeof(reason));
        if (j > 0) {
          absl::StrAppend(&s, ",");
        }
        absl::StrAppend(&s, CryptoUtils::HandshakeFailureReasonToString(
                                static_cast<HandshakeFailureReason>(reason)));
      }
      absl::StrAppend(&s, "]");
    } else {
      absl::StrAppendFormat(&s, " RREJ:[unexpected length:%u]", value.size());
    }
  }

  return s;
}

}  // namespace

// static
std::unique_ptr<KeyExchangeSource> KeyExchangeSource::Default() {
  return std::make_unique<DefaultKeyExchangeSource>();
}

class ValidateClientHelloHelper {
 public:
  // Note: stores a pointer to a unique_ptr, and std::moves the unique_ptr when
  // ValidationComplete is called.
  ValidateClientHelloHelper(
      quiche::QuicheReferenceCountedPointer<
          ValidateClientHelloResultCallback::Result>
          result,
      std::unique_ptr<ValidateClientHelloResultCallback>* done_cb)
      : result_(std::move(result)), done_cb_(done_cb) {}
  ValidateClientHelloHelper(const ValidateClientHelloHelper&) = delete;
  ValidateClientHelloHelper& operator=(const ValidateClientHelloHelper&) =
      delete;

  ~ValidateClientHelloHelper() {
    QUIC_BUG_IF(quic_bug_12963_1, done_cb_ != nullptr)
        << "Deleting ValidateClientHelloHelper with a pending callback.";
  }

  void ValidationComplete(
      QuicErrorCode error_code, const char* error_details,
      std::unique_ptr<ProofSource::Details> proof_source_details) {
    result_->error_code = error_code;
    result_->error_details = error_details;
    (*done_cb_)->Run(std::move(result_), std::move(proof_source_details));
    DetachCallback();
  }

  void DetachCallback() {
    QUIC_BUG_IF(quic_bug_10630_1, done_cb_ == nullptr)
        << "Callback already detached.";
    done_cb_ = nullptr;
  }

 private:
  quiche::QuicheReferenceCountedPointer<
      ValidateClientHelloResultCallback::Result>
      result_;
  std::unique_ptr<ValidateClientHelloResultCallback>* done_cb_;
};

// static
const char QuicCryptoServerConfig::TESTING[] = "secret string for testing";

ClientHelloInfo::ClientHelloInfo(const QuicIpAddress& in_client_ip,
                                 QuicWallTime in_now)
    : client_ip(in_client_ip), now(in_now), valid_source_address_token(false) {}

ClientHelloInfo::ClientHelloInfo(const ClientHelloInfo& other) = default;

ClientHelloInfo::~ClientHelloInfo() {}

PrimaryConfigChangedCallback::PrimaryConfigChangedCallback() {}

PrimaryConfigChangedCallback::~PrimaryConfigChangedCallback() {}

ValidateClientHelloResultCallback::Result::Result(
    const CryptoHandshakeMessage& in_client_hello, QuicIpAddress in_client_ip,
    QuicWallTime in_now)
    : client_hello(in_client_hello),
      info(in_client_ip, in_now),
      error_code(QUIC_NO_ERROR) {}

ValidateClientHelloResultCallback::Result::~Result() {}

ValidateClientHelloResultCallback::ValidateClientHelloResultCallback() {}

ValidateClientHelloResultCallback::~ValidateClientHelloResultCallback() {}

ProcessClientHelloResultCallback::ProcessClientHelloResultCallback() {}

ProcessClientHelloResultCallback::~ProcessClientHelloResultCallback() {}

QuicCryptoServerConfig::ConfigOptions::ConfigOptions()
    : expiry_time(QuicWallTime::Zero()),
      channel_id_enabled(false),
      p256(false) {}

QuicCryptoServerConfig::ConfigOptions::ConfigOptions(
    const ConfigOptions& other) = default;

QuicCryptoServerConfig::ConfigOptions::~ConfigOptions() {}

QuicCryptoServerConfig::ProcessClientHelloContext::
    ~ProcessClientHelloContext() {
  if (done_cb_ != nullptr) {
    QUIC_LOG(WARNING)
        << "Deleting ProcessClientHelloContext with a pending callback.";
  }
}

void QuicCryptoServerConfig::ProcessClientHelloContext::Fail(
    QuicErrorCode error, const std::string& error_details) {
  QUIC_TRACEPRINTF("ProcessClientHello failed: error=%s, details=%s",
                   QuicErrorCodeToString(error), error_details);
  done_cb_->Run(error, error_details, nullptr, nullptr, nullptr);
  done_cb_ = nullptr;
}

void QuicCryptoServerConfig::ProcessClientHelloContext::Succeed(
    std::unique_ptr<CryptoHandshakeMessage> message,
    std::unique_ptr<DiversificationNonce> diversification_nonce,
    std::unique_ptr<ProofSource::Details> proof_source_details) {
  QUIC_TRACEPRINTF("ProcessClientHello succeeded: %s",
                   FormatCryptoHandshakeMessageForTrace(message.get()));

  done_cb_->Run(QUIC_NO_ERROR, std::string(), std::move(message),
                std::move(diversification_nonce),
                std::move(proof_source_details));
  done_cb_ = nullptr;
}

QuicCryptoServerConfig::QuicCryptoServerConfig(
    absl::string_view source_address_token_secret,
    QuicRandom* server_nonce_entropy, std::unique_ptr<ProofSource> proof_source,
    std::unique_ptr<KeyExchangeSource> key_exchange_source)
    : replay_protection_(true),
      chlo_multiplier_(kMultiplier),
      configs_lock_(),
      primary_config_(nullptr),
      next_config_promotion_time_(QuicWallTime::Zero()),
      proof_source_(std::move(proof_source)),
      key_exchange_source_(std::move(key_exchange_source)),
      ssl_ctx_(TlsServerConnection::CreateSslCtx(proof_source_.get())),
      source_address_token_future_secs_(3600),
      source_address_token_lifetime_secs_(86400),
      enable_serving_sct_(false),
      rejection_observer_(nullptr),
      pad_rej_(true),
      pad_shlo_(true),
      validate_chlo_size_(true),
      validate_source_address_token_(true) {
  QUICHE_DCHECK(proof_source_.get());
  source_address_token_boxer_.SetKeys(
      {DeriveSourceAddressTokenKey(source_address_token_secret)});

  // Generate a random key and orbit for server nonces.
  server_nonce_entropy->RandBytes(server_nonce_orbit_,
                                  sizeof(server_nonce_orbit_));
  const size_t key_size = server_nonce_boxer_.GetKeySize();
  std::unique_ptr<uint8_t[]> key_bytes(new uint8_t[key_size]);
  server_nonce_entropy->RandBytes(key_bytes.get(), key_size);

  server_nonce_boxer_.SetKeys(
      {std::string(reinterpret_cast<char*>(key_bytes.get()), key_size)});
}

QuicCryptoServerConfig::~QuicCryptoServerConfig() {}

// static
QuicServerConfigProtobuf QuicCryptoServerConfig::GenerateConfig(
    QuicRandom* rand, const QuicClock* clock, const ConfigOptions& options) {
  CryptoHandshakeMessage msg;

  const std::string curve25519_private_key =
      Curve25519KeyExchange::NewPrivateKey(rand);
  std::unique_ptr<Curve25519KeyExchange> curve25519 =
      Curve25519KeyExchange::New(curve25519_private_key);
  absl::string_view curve25519_public_value = curve25519->public_value();

  std::string encoded_public_values;
  // First three bytes encode the length of the public value.
  QUICHE_DCHECK_LT(curve25519_public_value.size(), (1U << 24));
  encoded_public_values.push_back(
      static_cast<char>(curve25519_public_value.size()));
  encoded_public_values.push_back(
      static_cast<char>(curve25519_public_value.size() >> 8));
  encoded_public_values.push_back(
      static_cast<char>(curve25519_public_value.size() >> 16));
  encoded_public_values.append(curve25519_public_value.data(),
                               curve25519_public_value.size());

  std::string p256_private_key;
  if (options.p256) {
    p256_private_key = P256KeyExchange::NewPrivateKey();
    std::unique_ptr<P256KeyExchange> p256(
        P256KeyExchange::New(p256_private_key));
    absl::string_view p256_public_value = p256->public_value();

    QUICHE_DCHECK_LT(p256_public_value.size(), (1U << 24));
    encoded_public_values.push_back(
        static_cast<char>(p256_public_value.size()));
    encoded_public_values.push_back(
        static_cast<char>(p256_public_value.size() >> 8));
    encoded_public_values.push_back(
        static_cast<char>(p256_public_value.size() >> 16));
    encoded_public_values.append(p256_public_value.data(),
                                 p256_public_value.size());
  }

  msg.set_tag(kSCFG);
  if (options.p256) {
    msg.SetVector(kKEXS, QuicTagVector{kC255, kP256});
  } else {
    msg.SetVector(kKEXS, QuicTagVector{kC255});
  }
  msg.SetVector(kAEAD, QuicTagVector{kAESG, kCC20});
  msg.SetStringPiece(kPUBS, encoded_public_values);

  if (options.expiry_time.IsZero()) {
    const QuicWallTime now = clock->WallNow();
    const QuicWallTime expiry = now.Add(QuicTime::Delta::FromSeconds(
        60 * 60 * 24 * 180 /* 180 days, ~six months */));
    const uint64_t expiry_seconds = expiry.ToUNIXSeconds();
    msg.SetValue(kEXPY, expiry_seconds);
  } else {
    msg.SetValue(kEXPY, options.expiry_time.ToUNIXSeconds());
  }

  char orbit_bytes[kOrbitSize];
  if (options.orbit.size() == sizeof(orbit_bytes)) {
    memcpy(orbit_bytes, options.orbit.data(), sizeof(orbit_bytes));
  } else {
    QUICHE_DCHECK(options.orbit.empty());
    rand->RandBytes(orbit_bytes, sizeof(orbit_bytes));
  }
  msg.SetStringPiece(kORBT,
                     absl::string_view(orbit_bytes, sizeof(orbit_bytes)));

  if (options.channel_id_enabled) {
    msg.SetVector(kPDMD, QuicTagVector{kCHID});
  }

  if (options.id.empty()) {
    // We need to ensure that the SCID changes whenever the server config does
    // thus we make it a hash of the rest of the server config.
    std::unique_ptr<QuicData> serialized =
        CryptoFramer::ConstructHandshakeMessage(msg);

    uint8_t scid_bytes[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const uint8_t*>(serialized->data()),
           serialized->length(), scid_bytes);
    // The SCID is a truncated SHA-256 digest.
    static_assert(16 <= SHA256_DIGEST_LENGTH, "SCID length too high.");
    msg.SetStringPiece(
        kSCID,
        absl::string_view(reinterpret_cast<const char*>(scid_bytes), 16));
  } else {
    msg.SetStringPiece(kSCID, options.id);
  }
  // Don't put new tags below this point. The SCID generation should hash over
  // everything but itself and so extra tags should be added prior to the
  // preceding if block.

  std::unique_ptr<QuicData> serialized =
      CryptoFramer::ConstructHandshakeMessage(msg);

  QuicServerConfigProtobuf config;
  config.set_config(std::string(serialized->AsStringPiece()));
  QuicServerConfigProtobuf::PrivateKey* curve25519_key = config.add_key();
  curve25519_key->set_tag(kC255);
  curve25519_key->set_private_key(curve25519_private_key);

  if (options.p256) {
    QuicServerConfigProtobuf::PrivateKey* p256_key = config.add_key();
    p256_key->set_tag(kP256);
    p256_key->set_private_key(p256_private_key);
  }

  return config;
}

std::unique_ptr<CryptoHandshakeMessage> QuicCryptoServerConfig::AddConfig(
    const QuicServerConfigProtobuf& protobuf, const QuicWallTime now) {
  std::unique_ptr<CryptoHandshakeMessage> msg =
      CryptoFramer::ParseMessage(protobuf.config());

  if (!msg) {
    QUIC_LOG(WARNING) << "Failed to parse server config message";
    return nullptr;
  }

  quiche::QuicheReferenceCountedPointer<Config> config =
      ParseConfigProtobuf(protobuf, /* is_fallback = */ false);
  if (!config) {
    QUIC_LOG(WARNING) << "Failed to parse server config message";
    return nullptr;
  }

  {
    quiche::QuicheWriterMutexLock locked(&configs_lock_);
    if (configs_.find(config->id) != configs_.end()) {
      QUIC_LOG(WARNING) << "Failed to add config because another with the same "
                           "server config id already exists: "
                        << absl::BytesToHexString(config->id);
      return nullptr;
    }

    configs_[config->id] = config;
    SelectNewPrimaryConfig(now);
    QUICHE_DCHECK(primary_config_.get());
    QUICHE_DCHECK_EQ(configs_.find(primary_config_->id)->second.get(),
                     primary_config_.get());
  }

  return msg;
}

std::unique_ptr<CryptoHandshakeMessage>
QuicCryptoServerConfig::AddDefaultConfig(QuicRandom* rand,
                                         const QuicClock* clock,
                                         const ConfigOptions& options) {
  return AddConfig(GenerateConfig(rand, clock, options), clock->WallNow());
}

bool QuicCryptoServerConfig::SetConfigs(
    const std::vector<QuicServerConfigProtobuf>& protobufs,
    const QuicServerConfigProtobuf* fallback_protobuf, const QuicWallTime now) {
  std::vector<quiche::QuicheReferenceCountedPointer<Config>> parsed_configs;
  for (auto& protobuf : protobufs) {
    quiche::QuicheReferenceCountedPointer<Config> config =
        ParseConfigProtobuf(protobuf, /* is_fallback = */ false);
    if (!config) {
      QUIC_LOG(WARNING) << "Rejecting QUIC configs because of above errors";
      return false;
    }

    parsed_configs.push_back(config);
  }

  quiche::QuicheReferenceCountedPointer<Config> fallback_config;
  if (fallback_protobuf != nullptr) {
    fallback_config =
        ParseConfigProtobuf(*fallback_protobuf, /* is_fallback = */ true);
    if (!fallback_config) {
      QUIC_LOG(WARNING) << "Rejecting QUIC configs because of above errors";
      return false;
    }
    QUIC_LOG(INFO) << "Fallback config has scid "
                   << absl::BytesToHexString(fallback_config->id);
    parsed_configs.push_back(fallback_config);
  } else {
    QUIC_LOG(INFO) << "No fallback config provided";
  }

  if (parsed_configs.empty()) {
    QUIC_LOG(WARNING)
        << "Rejecting QUIC configs because new config list is empty.";
    return false;
  }

  QUIC_LOG(INFO) << "Updating configs:";

  quiche::QuicheWriterMutexLock locked(&configs_lock_);
  ConfigMap new_configs;

  for (const quiche::QuicheReferenceCountedPointer<Config>& config :
       parsed_configs) {
    auto it = configs_.find(config->id);
    if (it != configs_.end()) {
      QUIC_LOG(INFO) << "Keeping scid: " << absl::BytesToHexString(config->id)
                     << " orbit: "
                     << absl::BytesToHexString(absl::string_view(
                            reinterpret_cast<const char*>(config->orbit),
                            kOrbitSize))
                     << " new primary_time "
                     << config->primary_time.ToUNIXSeconds()
                     << " old primary_time "
                     << it->second->primary_time.ToUNIXSeconds()
                     << " new priority " << config->priority << " old priority "
                     << it->second->priority;
      // Update primary_time and priority.
      it->second->primary_time = config->primary_time;
      it->second->priority = config->priority;
      new_configs.insert(*it);
    } else {
      QUIC_LOG(INFO) << "Adding scid: " << absl::BytesToHexString(config->id)
                     << " orbit: "
                     << absl::BytesToHexString(absl::string_view(
                            reinterpret_cast<const char*>(config->orbit),
                            kOrbitSize))
                     << " primary_time " << config->primary_time.ToUNIXSeconds()
                     << " priority " << config->priority;
      new_configs.emplace(config->id, config);
    }
  }

  configs_ = std::move(new_configs);
  fallback_config_ = fallback_config;
  SelectNewPrimaryConfig(now);
  QUICHE_DCHECK(primary_config_.get());
  QUICHE_DCHECK_EQ(configs_.find(primary_config_->id)->second.get(),
                   primary_config_.get());

  return true;
}

void QuicCryptoServerConfig::SetSourceAddressTokenKeys(
    const std::vector<std::string>& keys) {
  // TODO(b/208866709)
  source_address_token_boxer_.SetKeys(keys);
}

std::vector<std::string> QuicCryptoServerConfig::GetConfigIds() const {
  quiche::QuicheReaderMutexLock locked(&configs_lock_);
  std::vector<std::string> scids;
  for (auto it = configs_.begin(); it != configs_.end(); ++it) {
    scids.push_back(it->first);
  }
  return scids;
}

void QuicCryptoServerConfig::ValidateClientHello(
    const CryptoHandshakeMessage& client_hello,
    const QuicSocketAddress& client_address,
    const QuicSocketAddress& server_address, QuicTransportVersion version,
    const QuicClock* clock,
    quiche::QuicheReferenceCountedPointer<QuicSignedServerConfig> signed_config,
    std::unique_ptr<ValidateClientHelloResultCallback> done_cb) const {
  const QuicWallTime now(clock->WallNow());

  quiche::QuicheReferenceCountedPointer<
      ValidateClientHelloResultCallback::Result>
      result(new ValidateClientHelloResultCallback::Result(
          client_hello, client_address.host(), now));

  absl::string_view requested_scid;
  // We ignore here the return value from GetStringPiece. If there is no SCID
  // tag, EvaluateClientHello will discover that because GetCurrentConfigs will
  // not have found the requested config (i.e. because none of the configs will
  // have an empty string as its id).
  client_hello.GetStringPiece(kSCID, &requested_scid);
  Configs configs;
  if (!GetCurrentConfigs(now, requested_scid,
                         /* old_primary_config = */ nullptr, &configs)) {
    result->error_code = QUIC_CRYPTO_INTERNAL_ERROR;
    result->error_details = "No configurations loaded";
  }
  signed_config->config = configs.primary;

  if (result->error_code == QUIC_NO_ERROR) {
    // QUIC requires a new proof for each CHLO so clear any existing proof.
    signed_config->chain = nullptr;
    signed_config->proof.signature = "";
    signed_config->proof.leaf_cert_scts = "";
    EvaluateClientHello(server_address, client_address, version, configs,
                        result, std::move(done_cb));
  } else {
    done_cb->Run(result, /* details = */ nullptr);
  }
}

class QuicCryptoServerConfig::ProcessClientHelloCallback
    : public ProofSource::Callback {
 public:
  ProcessClientHelloCallback(const QuicCryptoServerConfig* config,
                             std::unique_ptr<ProcessClientHelloContext> context,
                             const Configs& configs)
      : config_(config), context_(std::move(context)), configs_(configs) {}

  void Run(
      bool ok,
      const quiche::QuicheReferenceCountedPointer<ProofSource::Chain>& chain,
      const QuicCryptoProof& proof,
      std::unique_ptr<ProofSource::Details> details) override {
    if (ok) {
      context_->signed_config()->chain = chain;
      context_->signed_config()->proof = proof;
    }
    config_->ProcessClientHelloAfterGetProof(!ok, std::move(details),
                                             std::move(context_), configs_);
  }

 private:
  const QuicCryptoServerConfig* config_;
  std::unique_ptr<ProcessClientHelloContext> context_;
  const Configs configs_;
};

class QuicCryptoServerConfig::ProcessClientHelloAfterGetProofCallback
    : public AsynchronousKeyExchange::Callback {
 public:
  ProcessClientHelloAfterGetProofCallback(
      const QuicCryptoServerConfig* config,
      std::unique_ptr<ProofSource::Details> proof_source_details,
      QuicTag key_exchange_type, std::unique_ptr<CryptoHandshakeMessage> out,
      absl::string_view public_value,
      std::unique_ptr<ProcessClientHelloContext> context,
      const Configs& configs)
      : config_(config),
        proof_source_details_(std::move(proof_source_details)),
        key_exchange_type_(key_exchange_type),
        out_(std::move(out)),
        public_value_(public_value),
        context_(std::move(context)),
        configs_(configs) {}

  void Run(bool ok) override {
    config_->ProcessClientHelloAfterCalculateSharedKeys(
        !ok, std::move(proof_source_details_), key_exchange_type_,
        std::move(out_), public_value_, std::move(context_), configs_);
  }

 private:
  const QuicCryptoServerConfig* config_;
  std::unique_ptr<ProofSource::Details> proof_source_details_;
  const QuicTag key_exchange_type_;
  std::unique_ptr<CryptoHandshakeMessage> out_;
  const std::string public_value_;
  std::unique_ptr<ProcessClientHelloContext> context_;
  const Configs configs_;
  std::unique_ptr<ProcessClientHelloResultCallback> done_cb_;
};

class QuicCryptoServerConfig::SendRejectWithFallbackConfigCallback
    : public ProofSource::Callback {
 public:
  SendRejectWithFallbackConfigCallback(
      const QuicCryptoServerConfig* config,
      std::unique_ptr<ProcessClientHelloContext> context,
      quiche::QuicheReferenceCountedPointer<Config> fallback_config)
      : config_(config),
        context_(std::move(context)),
        fallback_config_(fallback_config) {}

  // Capture |chain| and |proof| into the signed config, and then invoke
  // SendRejectWithFallbackConfigAfterGetProof.
  void Run(
      bool ok,
      const quiche::QuicheReferenceCountedPointer<ProofSource::Chain>& chain,
      const QuicCryptoProof& proof,
      std::unique_ptr<ProofSource::Details> details) override {
    if (ok) {
      context_->signed_config()->chain = chain;
      context_->signed_config()->proof = proof;
    }
    config_->SendRejectWithFallbackConfigAfterGetProof(
        !ok, std::move(details), std::move(context_), fallback_config_);
  }

 private:
  const QuicCryptoServerConfig* config_;
  std::unique_ptr<ProcessClientHelloContext> context_;
  quiche::QuicheReferenceCountedPointer<Config> fallback_config_;
};

void QuicCryptoServerConfig::ProcessClientHello(
    quiche::QuicheReferenceCountedPointer<
        ValidateClientHelloResultCallback::Result>
        validate_chlo_result,
    bool reject_only, QuicConnectionId connection_id,
    const QuicSocketAddress& server_address,
    const QuicSocketAddress& client_address, ParsedQuicVersion version,
    const ParsedQuicVersionVector& supported_versions, const QuicClock* clock,
    QuicRandom* rand, QuicCompressedCertsCache* compressed_certs_cache,
    quiche::QuicheReferenceCountedPointer<QuicCryptoNegotiatedParameters>
        params,
    quiche::QuicheReferenceCountedPointer<QuicSignedServerConfig> signed_config,
    QuicByteCount total_framing_overhead, QuicByteCount chlo_packet_size,
    std::shared_ptr<ProcessClientHelloResultCallback> done_cb) const {
  QUICHE_DCHECK(done_cb);
  auto context = std::make_unique<ProcessClientHelloContext>(
      validate_chlo_result, reject_only, connection_id, server_address,
      client_address, version, supported_versions, clock, rand,
      compressed_certs_cache, params, signed_config, total_framing_overhead,
      chlo_packet_size, std::move(done_cb));

  // Verify that various parts of the CHLO are valid
  std::string error_details;
  QuicErrorCode valid = CryptoUtils::ValidateClientHello(
      context->client_hello(), context->version(),
      context->supported_versions(), &error_details);
  if (valid != QUIC_NO_ERROR) {
    context->Fail(valid, error_details);
    return;
  }

  absl::string_view requested_scid;
  context->client_hello().GetStringPiece(kSCID, &requested_scid);
  Configs configs;
  if (!GetCurrentConfigs(context->clock()->WallNow(), requested_scid,
                         signed_config->config, &configs)) {
    context->Fail(QUIC_CRYPTO_INTERNAL_ERROR, "No configurations loaded");
    return;
  }

  if (context->validate_chlo_result()->error_code != QUIC_NO_ERROR) {
    context->Fail(context->validate_chlo_result()->error_code,
                  context->validate_chlo_result()->error_details);
    return;
  }

  if (!ClientDemandsX509Proof(context->client_hello())) {
    context->Fail(QUIC_UNSUPPORTED_PROOF_DEMAND, "Missing or invalid PDMD");
    return;
  }

  // No need to get a new proof if one was already generated.
  if (!context->signed_config()->chain) {
    const std::string chlo_hash = CryptoUtils::HashHandshakeMessage(
        context->client_hello(), Perspective::IS_SERVER);
    const QuicSocketAddress context_server_address = context->server_address();
    const std::string sni = std::string(context->info().sni);
    const QuicTransportVersion transport_version = context->transport_version();

    auto cb = std::make_unique<ProcessClientHelloCallback>(
        this, std::move(context), configs);

    QUICHE_DCHECK(proof_source_.get());
    proof_source_->GetProof(context_server_address, client_address, sni,
                            configs.primary->serialized, transport_version,
                            chlo_hash, std::move(cb));
    return;
  }

  ProcessClientHelloAfterGetProof(
      /* found_error = */ false, /* proof_source_details = */ nullptr,
      std::move(context), configs);
}

void QuicCryptoServerConfig::ProcessClientHelloAfterGetProof(
    bool found_error,
    std::unique_ptr<ProofSource::Details> proof_source_details,
    std::unique_ptr<ProcessClientHelloContext> context,
    const Configs& configs) const {
  QUIC_BUG_IF(quic_bug_12963_2,
              !QuicUtils::IsConnectionIdValidForVersion(
                  context->connection_id(), context->transport_version()))
      << "ProcessClientHelloAfterGetProof: attempted to use connection ID "
      << context->connection_id() << " which is invalid with version "
      << context->version();

  if (context->info().reject_reasons.empty()) {
    if (!context->signed_config() || !context->signed_config()->chain) {
      // No chain.
      context->validate_chlo_result()->info.reject_reasons.push_back(
          SERVER_CONFIG_UNKNOWN_CONFIG_FAILURE);
    } else if (!ValidateExpectedLeafCertificate(
                   context->client_hello(),
                   context->signed_config()->chain->certs)) {
      // Has chain but leaf is invalid.
      context->validate_chlo_result()->info.reject_reasons.push_back(
          INVALID_EXPECTED_LEAF_CERTIFICATE);
    }
  }

  if (found_error) {
    context->Fail(QUIC_HANDSHAKE_FAILED, "Failed to get proof");
    return;
  }

  auto out_diversification_nonce = std::make_unique<DiversificationNonce>();

  absl::string_view cert_sct;
  if (context->client_hello().GetStringPiece(kCertificateSCTTag, &cert_sct) &&
      cert_sct.empty()) {
    context->params()->sct_supported_by_client = true;
  }

  auto out = std::make_unique<CryptoHandshakeMessage>();
  if (!context->info().reject_reasons.empty() || !configs.requested) {
    BuildRejectionAndRecordStats(*context, *configs.primary,
                                 context->info().reject_reasons, out.get());
    context->Succeed(std::move(out), std::move(out_diversification_nonce),
                     std::move(proof_source_details));
    return;
  }

  if (context->reject_only()) {
    context->Succeed(std::move(out), std::move(out_diversification_nonce),
                     std::move(proof_source_details));
    return;
  }

  QuicTagVector their_aeads;
  QuicTagVector their_key_exchanges;
  if (context->client_hello().GetTaglist(kAEAD, &their_aeads) !=
          QUIC_NO_ERROR ||
      context->client_hello().GetTaglist(kKEXS, &their_key_exchanges) !=
          QUIC_NO_ERROR ||
      their_aeads.size() != 1 || their_key_exchanges.size() != 1) {
    context->Fail(QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER,
                  "Missing or invalid AEAD or KEXS");
    return;
  }

  size_t key_exchange_index;
  if (!FindMutualQuicTag(configs.requested->aead, their_aeads,
                         &context->params()->aead, nullptr) ||
      !FindMutualQuicTag(configs.requested->kexs, their_key_exchanges,
                         &context->params()->key_exchange,
                         &key_exchange_index)) {
    context->Fail(QUIC_CRYPTO_NO_SUPPORT, "Unsupported AEAD or KEXS");
    return;
  }

  absl::string_view public_value;
  if (!context->client_hello().GetStringPiece(kPUBS, &public_value)) {
    context->Fail(QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER,
                  "Missing public value");
    return;
  }

  // Allow testing a specific adversarial case in which a client sends a public
  // value of incorrect size.
  AdjustTestValue("quic::QuicCryptoServerConfig::public_value_adjust",
                  &public_value);

  const Asynchrono
"""


```