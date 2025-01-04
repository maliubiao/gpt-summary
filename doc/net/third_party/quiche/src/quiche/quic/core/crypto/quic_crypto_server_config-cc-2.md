Response:
Let's break down the thought process for analyzing this code snippet.

**1. Understanding the Request:**

The core request is to analyze a specific C++ source file (`quic_crypto_server_config.cc`) from Chromium's QUIC implementation. The breakdown asks for:

* **Functionality:** What does this code do?
* **Relationship to JavaScript:**  Is there a connection to web browser scripting?
* **Logical Reasoning (Input/Output):** Can we analyze the behavior of specific functions?
* **Common Errors:** What mistakes could developers make when using this code?
* **User Steps (Debugging):** How does a user's action in a browser eventually lead to this code being executed?
* **Summary of Functionality:** A concise overview of the file's purpose.

The request also explicitly states this is "part 3 of 3," implying previous parts provided context. Since we don't have the previous parts, we'll focus on understanding the code in isolation and making reasonable assumptions about the overall QUIC handshake process.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for prominent keywords and patterns. This helps in forming initial hypotheses about the file's purpose. Keywords that stand out include:

* `QuicCryptoServerConfig` (class name, appears frequently)
* `ProofSource`, `SSL_CTX` (related to TLS/SSL)
* `SourceAddressToken` (handling client IP addresses)
* `ServerNonce` (random values for replay protection)
* `CryptoSecretBoxer` (encryption/decryption)
* `HandshakeFailureReason` (error handling during the connection setup)
* `Validate`, `New` (indicating creation and verification of data structures)
* `expiry_time`, `set_`, `Acquire` (configuration and management)
* `kEXPY`, `kXLCT` (likely constants representing tags in the QUIC handshake messages)

**3. Dissecting Key Functions:**

Next, we examine the most important functions in detail. Focusing on public methods is a good starting point as they define the interface of the class.

* **`NewSourceAddressToken`:**  This clearly creates a token containing the client's IP address, a timestamp, and optionally cached network parameters. It also incorporates previous tokens. The use of `CryptoSecretBoxer` implies encryption. *Hypothesis: This is used to remember the client's IP address to prevent address spoofing.*

* **`ParseSourceAddressToken`:** This function does the reverse of `NewSourceAddressToken`. It decrypts and parses a token. *Hypothesis: This verifies a previously issued token.*

* **`ValidateSourceAddressTokens` and `ValidateSingleSourceAddressToken`:** These functions check if a given token is valid for the current client IP and if it hasn't expired. *Hypothesis: These are used to enforce the lifetime and IP address association of the tokens.*

* **`NewServerNonce`:**  Generates a random value with a timestamp and encrypts it. *Hypothesis: This is used for replay protection, preventing attackers from reusing old handshake messages.*

* **`ValidateExpectedLeafCertificate`:**  Compares a hash of the server's certificate sent by the client. *Hypothesis: This is an optimization or security measure to quickly verify the expected certificate.*

* **`FromMessage`:** This static method constructs a `QuicCryptoServerConfig::Config` object from a `CryptoHandshakeMessage`. *Hypothesis: This is how server configuration parameters are extracted from the client's initial handshake message.*

* **`AcquirePrimaryConfigChangedCb`:**  Deals with a callback when the primary configuration changes. *Hypothesis: This allows other parts of the QUIC server to react to configuration updates.*

**4. Identifying Relationships and Dependencies:**

Observe how different parts of the code interact. For example:

* `NewSourceAddressToken` uses `CryptoSecretBoxer` for encryption.
* `ParseSourceAddressToken` uses `CryptoSecretBoxer` for decryption.
* Several functions rely on `QuicWallTime` for handling time.
* The `Config` struct holds various configuration parameters.

**5. Addressing Specific Questions from the Request:**

* **Functionality:**  Based on the dissected functions, the file manages server-side cryptographic configurations for the QUIC handshake, including generating and validating source address tokens, server nonces, and handling certificate verification.

* **Relationship to JavaScript:** While the C++ code itself doesn't directly interact with JavaScript, the *effects* of this code are crucial for a web browser. The QUIC handshake establishes a secure connection, enabling JavaScript running in the browser to communicate securely with a web server. The source address tokens and other mechanisms help in preventing attacks and ensuring a reliable connection.

* **Logical Reasoning (Input/Output):**  We can create simple scenarios. For example, `NewSourceAddressToken` takes an IP address and returns an encrypted token. `ParseSourceAddressToken` takes that token and returns the original IP (if valid).

* **Common Errors:** Consider typical programming mistakes: incorrect configuration settings, failing to handle token validation errors, clock synchronization issues.

* **User Steps (Debugging):** Think about the sequence of events when a user opens a website using QUIC. The browser initiates the handshake, sending a ClientHello. The server processes this, potentially using the code in this file to generate responses.

* **Summary of Functionality:** Condense the detailed analysis into a concise description.

**6. Structuring the Answer:**

Organize the information logically, addressing each part of the request clearly. Use headings and bullet points to improve readability. Provide specific code examples where relevant.

**7. Iteration and Refinement:**

After drafting the initial answer, review it for clarity, accuracy, and completeness. Ensure that the explanations are easy to understand and that all parts of the request have been addressed. For example, initially, I might have just said "manages crypto config."  But refining it to include specific aspects like source address tokens and server nonces makes the answer more informative. Similarly, explicitly stating the *indirect* relationship with JavaScript is important.

This iterative process of scanning, analyzing, hypothesizing, and refining is key to understanding complex code like this.
好的，让我们继续分析 `net/third_party/quiche/src/quiche/quic/core/crypto/quic_crypto_server_config.cc` 文件的剩余部分，并总结其功能。

```c++
// kServerNoncePlaintextSize is the number of bytes in an unencrypted server
// nonce.
static const size_t kServerNoncePlaintextSize =
    4 /* timestamp */ + 20 /* random bytes */;

std::string QuicCryptoServerConfig::NewServerNonce(QuicRandom* rand,
                                                   QuicWallTime now) const {
  const uint32_t timestamp = static_cast<uint32_t>(now.ToUNIXSeconds());

  uint8_t server_nonce[kServerNoncePlaintextSize];
  static_assert(sizeof(server_nonce) > sizeof(timestamp), "nonce too small");
  server_nonce[0] = static_cast<uint8_t>(timestamp >> 24);
  server_nonce[1] = static_cast<uint8_t>(timestamp >> 16);
  server_nonce[2] = static_cast<uint8_t>(timestamp >> 8);
  server_nonce[3] = static_cast<uint8_t>(timestamp);
  rand->RandBytes(&server_nonce[sizeof(timestamp)],
                  sizeof(server_nonce) - sizeof(timestamp));

  return server_nonce_boxer_.Box(
      rand, absl::string_view(reinterpret_cast<char*>(server_nonce),
                              sizeof(server_nonce)));
}

bool QuicCryptoServerConfig::ValidateExpectedLeafCertificate(
    const CryptoHandshakeMessage& client_hello,
    const std::vector<std::string>& certs) const {
  if (certs.empty()) {
    return false;
  }

  uint64_t hash_from_client;
  if (client_hello.GetUint64(kXLCT, &hash_from_client) != QUIC_NO_ERROR) {
    return false;
  }
  return CryptoUtils::ComputeLeafCertHash(certs[0]) == hash_from_client;
}

bool QuicCryptoServerConfig::IsNextConfigReady(QuicWallTime now) const {
  return !next_config_promotion_time_.IsZero() &&
         !next_config_promotion_time_.IsAfter(now);
}

QuicCryptoServerConfig::Config::Config()
    : channel_id_enabled(false),
      is_primary(false),
      primary_time(QuicWallTime::Zero()),
      expiry_time(QuicWallTime::Zero()),
      priority(0),
      source_address_token_boxer(nullptr) {}

QuicCryptoServerConfig::Config::~Config() {}

QuicSignedServerConfig::QuicSignedServerConfig() {}
QuicSignedServerConfig::~QuicSignedServerConfig() {}

}  // namespace quic
```

### 功能列举：

1. **生成服务器 Nonce (NewServerNonce):**
   - 该函数用于生成一个服务器 Nonce (Number used once)。Nonce 用于防止重放攻击，确保握手的新鲜性。
   - Nonce 包含一个时间戳和一些随机字节。
   - 生成的 Nonce 会使用 `server_nonce_boxer_` 进行加密处理。

2. **验证预期的叶子证书 (ValidateExpectedLeafCertificate):**
   - 此函数用于验证客户端在 `ClientHello` 消息中提供的叶子证书哈希值是否与服务器当前配置的证书哈希值匹配。
   - 客户端可以通过 `kXLCT` 标签发送其所知的服务器叶子证书的哈希值。
   - 这可以作为一种优化手段，如果客户端知道正确的证书，服务器可以避免发送完整的证书链。

3. **检查下一个配置是否就绪 (IsNextConfigReady):**
   - 该函数检查下一个服务器配置是否已经到了可以激活的时间。
   - `next_config_promotion_time_` 存储了下一个配置可以被使用的时刻。

4. **`QuicCryptoServerConfig::Config` 结构体的构造和析构:**
   - 定义了一个内部结构体 `Config`，用于存储单个服务器配置的信息，例如是否启用 Channel ID、是否是主配置、过期时间等。
   - 提供了默认构造函数和析构函数。

5. **`QuicSignedServerConfig` 结构体的构造和析构:**
   - 定义了另一个结构体 `QuicSignedServerConfig`，用于存储签名后的服务器配置。
   - 提供了默认构造函数和析构函数。

### 与 JavaScript 的关系：

这段 C++ 代码本身不直接与 JavaScript 交互。然而，它所实现的功能是 QUIC 协议服务器端的核心部分，直接影响到通过 QUIC 连接的 Web 应用（通常包含 JavaScript 代码）的安全性和性能。

- **服务器 Nonce:**  客户端在握手过程中会收到并使用服务器 Nonce，这有助于防止重放攻击，保护用户通过浏览器（运行 JavaScript）发起的请求。
- **叶子证书验证:**  虽然验证逻辑在服务器端，但客户端（浏览器）的行为会受到影响。如果客户端缓存了服务器证书的哈希值，可以加速握手过程，从而提高网页加载速度，这对于依赖 JavaScript 执行的 Web 应用来说是有益的。
- **服务器配置:**  服务器配置的变更最终会影响到客户端的连接行为和安全策略，这间接地影响了 JavaScript 代码与服务器的交互方式。

**举例说明:**

假设一个用户通过 Chrome 浏览器访问一个使用 QUIC 协议的网站。

1. 浏览器（运行 JavaScript）发起连接请求。
2. 服务器端的 `QuicCryptoServerConfig::NewServerNonce` 生成一个服务器 Nonce 并发送给浏览器。
3. 浏览器在后续的握手消息中包含这个 Nonce。
4. 服务器端通过检查 Nonce 来确认这是一个新的连接尝试，而不是重放攻击。

### 逻辑推理：

**假设输入 (NewServerNonce):**

- `rand`: 一个指向 `QuicRandom` 接口的指针，用于生成随机数。
- `now`: 当前的 `QuicWallTime` 对象。

**输出 (NewServerNonce):**

- 一个 `std::string` 类型的字符串，表示加密后的服务器 Nonce。这个字符串包含了当前时间戳的编码和一定数量的随机字节。

**假设输入 (ValidateExpectedLeafCertificate):**

- `client_hello`: 一个包含客户端发送的握手信息的 `CryptoHandshakeMessage` 对象。假设其中包含 `kXLCT` 标签，其值为客户端期望的服务器叶子证书的哈希值。
- `certs`: 一个 `std::vector<std::string>`，包含了服务器的证书链。

**输出 (ValidateExpectedLeafCertificate):**

- `true`: 如果 `client_hello` 中提供的哈希值与服务器当前叶子证书的哈希值匹配。
- `false`: 如果哈希值不匹配，或者 `client_hello` 中没有提供哈希值，或者服务器证书列表为空。

### 用户或编程常见的使用错误：

1. **服务器 Nonce 的加密配置错误:** 如果 `server_nonce_boxer_` 初始化不正确或者密钥管理有问题，可能导致生成的 Nonce 无法被正确解密或验证。
   - **用户操作如何到达:**  这通常是服务器配置错误，用户无法直接触发。但如果服务器配置错误，用户在尝试建立 QUIC 连接时可能会遇到连接失败或安全警告。
   - **调试线索:** 服务器日志会显示 Nonce 加密/解密失败的错误。检查 `server_nonce_boxer_` 的初始化和密钥配置。

2. **叶子证书哈希校验失败:**  如果服务器更新了证书，但客户端仍然发送旧证书的哈希值，`ValidateExpectedLeafCertificate` 将返回 `false`。
   - **用户操作如何到达:** 用户可能在短时间内多次访问服务器，第一次访问时缓存了旧的证书哈希。服务器更新证书后，用户再次访问，浏览器可能会发送旧哈希。
   - **调试线索:** 服务器日志可能会显示客户端提供的叶子证书哈希与预期不符。可以检查客户端发送的 `ClientHello` 消息中的 `kXLCT` 值以及服务器当前的证书哈希。

3. **服务器时间不同步:** `NewServerNonce` 中使用了当前时间戳。如果服务器时间不准确，可能导致生成的 Nonce 在客户端看来是过期的或未来的，从而导致握手失败。
   - **用户操作如何到达:** 用户尝试连接到时间不同步的服务器。
   - **调试线索:** 客户端可能会报告 Nonce 无效或时间戳错误。检查服务器的系统时间。

### 用户操作是如何一步步的到达这里，作为调试线索：

假设用户在 Chrome 浏览器中访问一个使用 QUIC 的网站 `https://example.com`。

1. **用户在地址栏输入 `https://example.com` 并按下回车。**
2. **Chrome 浏览器的 DNS 解析器查找 `example.com` 的 IP 地址。**
3. **Chrome 浏览器尝试与服务器建立连接，优先尝试 QUIC 协议。**
4. **Chrome 浏览器构造并发送一个 `ClientHello` 消息。** 这个消息可能包含客户端已知的服务器叶子证书的哈希值（存储在浏览器缓存中）。
5. **服务器接收到 `ClientHello` 消息。**
6. **服务器端的 QUIC 实现会调用 `QuicCryptoServerConfig::ValidateExpectedLeafCertificate`。**
   - 服务器会从 `ClientHello` 中提取 `kXLCT` 的值（如果存在）。
   - 服务器会计算当前配置的叶子证书的哈希值。
   - 进行比较，如果匹配，服务器可以跳过发送完整证书链。
7. **服务器端的 QUIC 实现会调用 `QuicCryptoServerConfig::NewServerNonce`。**
   - 生成一个新的服务器 Nonce，用于后续的握手过程。
8. **服务器构造 `ServerHello` 消息（或类似的消息），其中包含生成的服务器 Nonce。**
9. **服务器将 `ServerHello` 消息发送回客户端。**

**调试线索:**

如果在上述过程中出现问题，例如连接失败或安全错误，开发者可以：

- **抓包分析:** 使用 Wireshark 等工具捕获客户端和服务器之间的网络包，查看 `ClientHello` 和 `ServerHello` 消息的内容，特别是 `kXLCT` 标签和服务器 Nonce 的值。
- **查看服务器日志:**  服务器端的 QUIC 实现通常会记录关键事件，例如证书验证结果、Nonce 生成情况等。
- **浏览器 NetLog:** Chrome 浏览器提供了 `chrome://net-export/` 功能，可以导出网络日志，其中包含了 QUIC 连接的详细信息，可以查看握手过程中的错误。
- **断点调试:** 如果可以访问服务器源代码，可以在 `QuicCryptoServerConfig::ValidateExpectedLeafCertificate` 和 `QuicCryptoServerConfig::NewServerNonce` 等关键函数设置断点，查看执行过程中的变量值。

### 功能归纳 (第3部分)：

这部分代码主要负责以下关键的服务器端 QUIC 握手和配置功能：

- **生成用于防止重放攻击的服务器 Nonce。**
- **验证客户端提供的预期服务器叶子证书哈希，以优化握手过程。**
- **检查下一个服务器配置是否到了生效时间。**
- **定义了用于存储服务器配置信息和签名后配置信息的内部数据结构。**

结合前两部分的分析，`quic_crypto_server_config.cc` 文件总体上负责管理 QUIC 服务器的加密配置，包括密钥的管理、证书的处理、会话票据的处理、源地址令牌的处理以及服务器 Nonce 的生成和验证。它确保了 QUIC 连接的安全性和效率，是 QUIC 协议服务器端实现的核心组件之一。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/crypto/quic_crypto_server_config.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
fig->key_exchanges.push_back(std::move(ka));
  }

  uint64_t expiry_seconds;
  if (msg->GetUint64(kEXPY, &expiry_seconds) != QUIC_NO_ERROR) {
    QUIC_LOG(WARNING) << "Server config message is missing EXPY";
    return nullptr;
  }
  config->expiry_time = QuicWallTime::FromUNIXSeconds(expiry_seconds);

  return config;
}

void QuicCryptoServerConfig::set_replay_protection(bool on) {
  replay_protection_ = on;
}

void QuicCryptoServerConfig::set_chlo_multiplier(size_t multiplier) {
  chlo_multiplier_ = multiplier;
}

void QuicCryptoServerConfig::set_source_address_token_future_secs(
    uint32_t future_secs) {
  source_address_token_future_secs_ = future_secs;
}

void QuicCryptoServerConfig::set_source_address_token_lifetime_secs(
    uint32_t lifetime_secs) {
  source_address_token_lifetime_secs_ = lifetime_secs;
}

void QuicCryptoServerConfig::set_enable_serving_sct(bool enable_serving_sct) {
  enable_serving_sct_ = enable_serving_sct;
}

void QuicCryptoServerConfig::AcquirePrimaryConfigChangedCb(
    std::unique_ptr<PrimaryConfigChangedCallback> cb) {
  quiche::QuicheWriterMutexLock locked(&configs_lock_);
  primary_config_changed_cb_ = std::move(cb);
}

std::string QuicCryptoServerConfig::NewSourceAddressToken(
    const CryptoSecretBoxer& crypto_secret_boxer,
    const SourceAddressTokens& previous_tokens, const QuicIpAddress& ip,
    QuicRandom* rand, QuicWallTime now,
    const CachedNetworkParameters* cached_network_params) const {
  SourceAddressTokens source_address_tokens;
  SourceAddressToken* source_address_token = source_address_tokens.add_tokens();
  source_address_token->set_ip(ip.DualStacked().ToPackedString());
  source_address_token->set_timestamp(now.ToUNIXSeconds());
  if (cached_network_params != nullptr) {
    *(source_address_token->mutable_cached_network_parameters()) =
        *cached_network_params;
  }

  // Append previous tokens.
  for (const SourceAddressToken& token : previous_tokens.tokens()) {
    if (source_address_tokens.tokens_size() > kMaxTokenAddresses) {
      break;
    }

    if (token.ip() == source_address_token->ip()) {
      // It's for the same IP address.
      continue;
    }

    if (ValidateSourceAddressTokenTimestamp(token, now) != HANDSHAKE_OK) {
      continue;
    }

    *(source_address_tokens.add_tokens()) = token;
  }

  return crypto_secret_boxer.Box(rand,
                                 source_address_tokens.SerializeAsString());
}

int QuicCryptoServerConfig::NumberOfConfigs() const {
  quiche::QuicheReaderMutexLock locked(&configs_lock_);
  return configs_.size();
}

ProofSource* QuicCryptoServerConfig::proof_source() const {
  return proof_source_.get();
}

SSL_CTX* QuicCryptoServerConfig::ssl_ctx() const { return ssl_ctx_.get(); }

HandshakeFailureReason QuicCryptoServerConfig::ParseSourceAddressToken(
    const CryptoSecretBoxer& crypto_secret_boxer, absl::string_view token,
    SourceAddressTokens& tokens) const {
  std::string storage;
  absl::string_view plaintext;
  if (!crypto_secret_boxer.Unbox(token, &storage, &plaintext)) {
    return SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE;
  }

  if (!tokens.ParseFromArray(plaintext.data(), plaintext.size())) {
    // Some clients might still be using the old source token format so
    // attempt to parse that format.
    // TODO(rch): remove this code once the new format is ubiquitous.
    SourceAddressToken old_source_token;
    if (!old_source_token.ParseFromArray(plaintext.data(), plaintext.size())) {
      return SOURCE_ADDRESS_TOKEN_PARSE_FAILURE;
    }
    *tokens.add_tokens() = old_source_token;
  }

  return HANDSHAKE_OK;
}

HandshakeFailureReason QuicCryptoServerConfig::ValidateSourceAddressTokens(
    const SourceAddressTokens& source_address_tokens, const QuicIpAddress& ip,
    QuicWallTime now, CachedNetworkParameters* cached_network_params) const {
  HandshakeFailureReason reason =
      SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE;
  for (const SourceAddressToken& token : source_address_tokens.tokens()) {
    reason = ValidateSingleSourceAddressToken(token, ip, now);
    if (reason == HANDSHAKE_OK) {
      if (cached_network_params != nullptr &&
          token.has_cached_network_parameters()) {
        *cached_network_params = token.cached_network_parameters();
      }
      break;
    }
  }
  return reason;
}

HandshakeFailureReason QuicCryptoServerConfig::ValidateSingleSourceAddressToken(
    const SourceAddressToken& source_address_token, const QuicIpAddress& ip,
    QuicWallTime now) const {
  if (source_address_token.ip() != ip.DualStacked().ToPackedString()) {
    // It's for a different IP address.
    return SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE;
  }

  return ValidateSourceAddressTokenTimestamp(source_address_token, now);
}

HandshakeFailureReason
QuicCryptoServerConfig::ValidateSourceAddressTokenTimestamp(
    const SourceAddressToken& source_address_token, QuicWallTime now) const {
  const QuicWallTime timestamp(
      QuicWallTime::FromUNIXSeconds(source_address_token.timestamp()));
  const QuicTime::Delta delta(now.AbsoluteDifference(timestamp));

  if (now.IsBefore(timestamp) &&
      delta.ToSeconds() > source_address_token_future_secs_) {
    return SOURCE_ADDRESS_TOKEN_CLOCK_SKEW_FAILURE;
  }

  if (now.IsAfter(timestamp) &&
      delta.ToSeconds() > source_address_token_lifetime_secs_) {
    return SOURCE_ADDRESS_TOKEN_EXPIRED_FAILURE;
  }

  return HANDSHAKE_OK;
}

// kServerNoncePlaintextSize is the number of bytes in an unencrypted server
// nonce.
static const size_t kServerNoncePlaintextSize =
    4 /* timestamp */ + 20 /* random bytes */;

std::string QuicCryptoServerConfig::NewServerNonce(QuicRandom* rand,
                                                   QuicWallTime now) const {
  const uint32_t timestamp = static_cast<uint32_t>(now.ToUNIXSeconds());

  uint8_t server_nonce[kServerNoncePlaintextSize];
  static_assert(sizeof(server_nonce) > sizeof(timestamp), "nonce too small");
  server_nonce[0] = static_cast<uint8_t>(timestamp >> 24);
  server_nonce[1] = static_cast<uint8_t>(timestamp >> 16);
  server_nonce[2] = static_cast<uint8_t>(timestamp >> 8);
  server_nonce[3] = static_cast<uint8_t>(timestamp);
  rand->RandBytes(&server_nonce[sizeof(timestamp)],
                  sizeof(server_nonce) - sizeof(timestamp));

  return server_nonce_boxer_.Box(
      rand, absl::string_view(reinterpret_cast<char*>(server_nonce),
                              sizeof(server_nonce)));
}

bool QuicCryptoServerConfig::ValidateExpectedLeafCertificate(
    const CryptoHandshakeMessage& client_hello,
    const std::vector<std::string>& certs) const {
  if (certs.empty()) {
    return false;
  }

  uint64_t hash_from_client;
  if (client_hello.GetUint64(kXLCT, &hash_from_client) != QUIC_NO_ERROR) {
    return false;
  }
  return CryptoUtils::ComputeLeafCertHash(certs[0]) == hash_from_client;
}

bool QuicCryptoServerConfig::IsNextConfigReady(QuicWallTime now) const {
  return !next_config_promotion_time_.IsZero() &&
         !next_config_promotion_time_.IsAfter(now);
}

QuicCryptoServerConfig::Config::Config()
    : channel_id_enabled(false),
      is_primary(false),
      primary_time(QuicWallTime::Zero()),
      expiry_time(QuicWallTime::Zero()),
      priority(0),
      source_address_token_boxer(nullptr) {}

QuicCryptoServerConfig::Config::~Config() {}

QuicSignedServerConfig::QuicSignedServerConfig() {}
QuicSignedServerConfig::~QuicSignedServerConfig() {}

}  // namespace quic

"""


```