Response:
The user wants me to summarize the functionality of the provided C++ code snippet, which is part of the `QuicCryptoServerConfig` class in Chromium's network stack.

Here's a breakdown of the code's actions and my plan:

1. **Identify Key Functions:**  The code defines two main methods: `ProcessClientHelloAfterGetProof` and `ProcessClientHelloAfterCalculateSharedKeys`.
2. **Analyze `ProcessClientHelloAfterGetProof`:** This function appears to handle the callback after the proof source provides necessary data. It calculates the shared key using the chosen key exchange and initiates the next step by calling `CalculateSharedKeyAsync`.
3. **Analyze `ProcessClientHelloAfterCalculateSharedKeys`:** This function handles the callback after the shared key calculation. It performs several critical steps:
    - Error checking.
    - Fallback logic if shared key calculation fails.
    - Normalization of the Server Name Indication (SNI).
    - Generation of HKDF suffix.
    - Handling of Channel ID (CETV).
    - Derivation of initial encryption keys.
    - Generating forward-secure keys and deriving keys from them.
    - Constructing the Server Hello (SHLO) message.
    - Setting source address token.
    - Providing the forward-secure public value.
    - Signaling success.
4. **Identify Relationships:** These two functions are clearly sequential steps in the server-side QUIC handshake process.
5. **Summarize the Overall Functionality:**  The code handles the server's processing of the client hello message after the proof and shared key calculations are completed. It's responsible for key derivation, generating the server hello, and handling fallback scenarios.
6. **Consider Javascript Relevance:**  While this is C++ code, its actions directly influence the security parameters and handshake process that a Javascript QUIC implementation (if one existed or interacted with this) would need to understand. I'll need to highlight this indirect relationship.
7. **Construct Hypothetical Input/Output:**  For the `ProcessClientHelloAfterCalculateSharedKeys` function, I can outline a successful and a failed scenario in terms of input and output.
8. **Identify Potential User/Programming Errors:** I'll think about common mistakes a developer might make when interacting with or extending this code.
9. **Trace User Operations:** I'll describe how a client connecting to a server would eventually lead to this code being executed.
这段代码是 `QuicCryptoServerConfig` 类中处理客户端 `ClientHello` 消息的后续步骤。它主要负责在获取到证明信息并计算完共享密钥后，继续完成握手过程，构建并发送 `ServerHello` (SHLO) 消息。

**具体功能归纳如下:**

1. **处理共享密钥计算结果:**
   - 检查共享密钥计算是否出错 (`found_error`)。
   - 如果出错，并且存在可用的回退配置 (`fallback config`)，则发送包含回退配置的 `REJ` 消息。
   - 如果出错，且没有回退配置可用，则直接终止握手。

2. **处理 SNI (Server Name Indication):**
   - 如果客户端提供了 SNI，则对 SNI 进行规范化处理。

3. **生成 HKDF (HMAC-based Extract-and-Expand Key Derivation Function) 后缀:**
   -  拼接连接 ID、序列化后的 `ClientHello` 和所选 `ServerConfig` 的序列化数据，用于后续密钥派生。

4. **处理 Channel ID (CETV - Channel Endpoint Token V2):**
   - 如果 `ServerConfig` 启用了 Channel ID 并且 `ClientHello` 中包含 CETV，则尝试解密和验证 CETV。
   - 解密 CETV 使用根据初始密钥派生的密钥。
   - 验证 CETV 中的签名，确保其有效性。
   - 如果 CETV 验证成功，则将 Channel ID 存储到握手上下文中。

5. **派生初始加密密钥:**
   - 使用 HKDF 基于初始主密钥 (initial_premaster_secret)、客户端随机数 (client_nonce) 和服务器随机数 (server_nonce) 派生出初始的加密密钥。
   - 使用 diversification nonce 来增加密钥的随机性。

6. **生成前向安全密钥并派生密钥:**
   - 创建一个本地的同步密钥交换对象 (`SynchronousKeyExchange`)。
   - 生成前向安全的公钥。
   - 使用客户端提供的公钥计算前向安全的共享密钥。
   - 使用 HKDF 基于前向安全的共享密钥、客户端随机数和新的服务器随机数 (shlo_nonce) 派生出前向安全的加密密钥。

7. **构建 ServerHello (SHLO) 消息:**
   - 设置消息类型为 `kSHLO`。
   - 设置支持的 QUIC 版本。
   - 生成并设置源地址令牌 (Source Address Token)。
   - 设置客户端的地址信息。
   - 设置前向安全的公钥。

8. **标记握手成功:**
   - 调用 `context->Succeed`，传递构建好的 `SHLO` 消息、diversification nonce 和证明信息，表示握手处理成功。

**与 JavaScript 的关系:**

虽然这段代码是 C++，但其功能直接影响到基于 JavaScript 的 QUIC 实现（如果存在或需要与之交互）。

**举例说明:**

假设一个使用 JavaScript 的 QUIC 客户端连接到一个使用这个 C++ 服务端的场景：

- **客户端发送 ClientHello:** JavaScript 客户端构造并发送一个 `ClientHello` 消息，其中包含客户端支持的版本、随机数、SNI 等信息。
- **服务端处理 ClientHello:** C++ 服务端接收到 `ClientHello` 并进行初步处理（第 1 部分代码的功能）。
- **获取 Proof 和计算共享密钥:** 服务端根据客户端的请求，获取 TLS 证明并计算共享密钥。
- **执行此段代码:**  当证明信息就绪并且初始共享密钥计算完成后，会执行这段 C++ 代码。
- **密钥派生影响 JavaScript:**  这段 C++ 代码派生出的加密密钥将被用于加密服务端发往客户端的 `ServerHello` 和后续数据包。JavaScript 客户端在接收到这些加密的数据包后，需要使用相同的密钥派生逻辑（在 JavaScript 中实现）来解密数据。
- **ServerHello 影响 JavaScript:**  C++ 服务端构建的 `ServerHello` 消息中包含服务端选择的 QUIC 版本、Session Ticket、前向安全公钥等关键信息。JavaScript 客户端需要解析这个 `ServerHello` 消息，提取这些信息，并用于后续的握手和数据传输。例如，JavaScript 客户端会使用服务端的前向安全公钥进行后续的密钥交换或数据加密。

**假设输入与输出 (针对 `ProcessClientHelloAfterCalculateSharedKeys`):**

**假设输入 (成功场景):**

- `found_error`: `false`
- `proof_source_details`: 包含有效的证明信息。
- `key_exchange_type`: 服务端选择的密钥交换算法的标签。
- `out`: 一个空的 `CryptoHandshakeMessage` 对象。
- `public_value`: 客户端提供的公钥。
- `context`: 包含客户端 `ClientHello` 信息、连接 ID、版本信息等的上下文对象。
- `configs`: 包含服务端配置信息的对象。

**假设输出 (成功场景):**

- `out`: `CryptoHandshakeMessage` 对象被填充，包含 `kSHLO` 标签、支持的 QUIC 版本、源地址令牌、客户端地址、前向安全公钥等信息。
- `context` 的状态被更新为成功。

**假设输入 (失败场景):**

- `found_error`: `true`
- `context`: 包含客户端 `ClientHello` 信息、连接 ID、版本信息等的上下文对象。
- `configs`: 包含服务端配置信息的对象，假设存在一个可用的 `fallback` 配置。

**假设输出 (失败场景 - 使用回退配置):**

- 调用 `SendRejectWithFallbackConfig` 函数，开始发送包含回退配置信息的 `REJ` 消息。
- `context` 的状态可能会被更新，指示需要发送回退 `REJ`。

**用户或编程常见的使用错误:**

1. **配置错误导致共享密钥计算失败:**
   - **错误示例:** 服务端配置的密钥交换算法与客户端支持的算法不匹配。
   - **后果:**  `found_error` 为 `true`，导致服务端可能发送包含回退配置的 `REJ` 或者直接断开连接。

2. **ProofSource 实现问题:**
   - **错误示例:** `proof_source_->GetProof`  未能正确返回有效的证明信息。
   - **后果:**  即使共享密钥计算本身没有问题，后续步骤也无法正常进行，可能导致握手失败。

3. **HKDF 参数错误:**
   - **错误示例:** 在派生密钥时，使用了错误的 label 或者 salt。
   - **后果:** 派生出的密钥与客户端不一致，导致加密和解密失败。

4. **Channel ID 验证逻辑错误:**
   - **错误示例:**  `ChannelIDVerifier::Verify` 的实现存在 bug，导致本应成功的 Channel ID 验证失败。
   - **后果:**  即使客户端提供了有效的 CETV，服务端也可能因验证失败而拒绝连接。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中输入网址并尝试访问 HTTPS 网站 (假设网站使用 QUIC 协议):** 用户的这个操作触发了浏览器与服务器建立连接的请求。

2. **浏览器发起 QUIC 连接:** 浏览器根据协议配置，尝试与服务器建立 QUIC 连接。

3. **客户端发送 ClientHello (CHLO):** 浏览器作为 QUIC 客户端，构建并发送 `ClientHello` 消息到服务器，其中包含必要的握手信息，例如支持的 QUIC 版本、加密套件、SNI 等。

4. **服务端接收并处理 ClientHello (可能涉及到第 1 部分代码):**  服务器的网络栈接收到 `ClientHello` 消息，并开始进行初步的处理，例如解析消息、验证基本格式等。

5. **服务端请求 Proof 和计算共享密钥:** 服务器根据 `ClientHello` 中的信息，请求 TLS 证明（例如从磁盘或远程服务加载证书和签名），并尝试计算与客户端的共享密钥。

6. **Proof 获取完成，开始执行 `ProcessClientHelloAfterGetProof`:** 当服务器获取到必要的证明信息后，会调用 `ProcessClientHelloAfterGetProof` 函数，开始进行下一步处理。

7. **共享密钥计算完成，执行 `ProcessClientHelloAfterCalculateSharedKeys` (当前代码片段):** 在成功或失败地计算出共享密钥后，会调用 `ProcessClientHelloAfterCalculateSharedKeys` 函数，执行这段代码，完成后续的握手流程，例如派生密钥、构建 `ServerHello` 等。

8. **服务端发送 ServerHello (SHLO):** 如果一切顺利，这段代码会构建 `ServerHello` 消息并发送回客户端。

9. **客户端处理 ServerHello，完成握手:** 客户端接收到 `ServerHello` 后，会进行相应的处理，例如验证消息、提取密钥等，最终完成 QUIC 握手。

因此，用户尝试访问 HTTPS 网站的操作是整个流程的起点，而这段代码 (`ProcessClientHelloAfterCalculateSharedKeys`) 是服务端处理 `ClientHello` 消息的关键步骤之一，发生在获取证明信息和计算共享密钥之后。 调试时，如果发现连接建立失败，可以检查这段代码的执行情况，例如查看日志输出，确认密钥派生、`ServerHello` 构建等环节是否正常。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/crypto/quic_crypto_server_config.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
usKeyExchange* key_exchange =
      configs.requested->key_exchanges[key_exchange_index].get();
  std::string* initial_premaster_secret =
      &context->params()->initial_premaster_secret;
  auto cb = std::make_unique<ProcessClientHelloAfterGetProofCallback>(
      this, std::move(proof_source_details), key_exchange->type(),
      std::move(out), public_value, std::move(context), configs);
  key_exchange->CalculateSharedKeyAsync(public_value, initial_premaster_secret,
                                        std::move(cb));
}

void QuicCryptoServerConfig::ProcessClientHelloAfterCalculateSharedKeys(
    bool found_error,
    std::unique_ptr<ProofSource::Details> proof_source_details,
    QuicTag key_exchange_type, std::unique_ptr<CryptoHandshakeMessage> out,
    absl::string_view public_value,
    std::unique_ptr<ProcessClientHelloContext> context,
    const Configs& configs) const {
  QUIC_BUG_IF(quic_bug_12963_3,
              !QuicUtils::IsConnectionIdValidForVersion(
                  context->connection_id(), context->transport_version()))
      << "ProcessClientHelloAfterCalculateSharedKeys:"
         " attempted to use connection ID "
      << context->connection_id() << " which is invalid with version "
      << context->version();

  if (found_error) {
    // If we are already using the fallback config, or there is no fallback
    // config to use, just bail out of the handshake.
    if (configs.fallback == nullptr ||
        context->signed_config()->config == configs.fallback) {
      context->Fail(QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER,
                    "Failed to calculate shared key");
    } else {
      SendRejectWithFallbackConfig(std::move(context), configs.fallback);
    }
    return;
  }

  if (!context->info().sni.empty()) {
    context->params()->sni =
        QuicHostnameUtils::NormalizeHostname(context->info().sni);
  }

  std::string hkdf_suffix;
  const QuicData& client_hello_serialized =
      context->client_hello().GetSerialized();
  hkdf_suffix.reserve(context->connection_id().length() +
                      client_hello_serialized.length() +
                      configs.requested->serialized.size());
  hkdf_suffix.append(context->connection_id().data(),
                     context->connection_id().length());
  hkdf_suffix.append(client_hello_serialized.data(),
                     client_hello_serialized.length());
  hkdf_suffix.append(configs.requested->serialized);
  QUICHE_DCHECK(proof_source_.get());
  if (context->signed_config()->chain->certs.empty()) {
    context->Fail(QUIC_CRYPTO_INTERNAL_ERROR, "Failed to get certs");
    return;
  }
  hkdf_suffix.append(context->signed_config()->chain->certs[0]);

  absl::string_view cetv_ciphertext;
  if (configs.requested->channel_id_enabled &&
      context->client_hello().GetStringPiece(kCETV, &cetv_ciphertext)) {
    CryptoHandshakeMessage client_hello_copy(context->client_hello());
    client_hello_copy.Erase(kCETV);
    client_hello_copy.Erase(kPAD);

    const QuicData& client_hello_copy_serialized =
        client_hello_copy.GetSerialized();
    std::string hkdf_input;
    hkdf_input.append(QuicCryptoConfig::kCETVLabel,
                      strlen(QuicCryptoConfig::kCETVLabel) + 1);
    hkdf_input.append(context->connection_id().data(),
                      context->connection_id().length());
    hkdf_input.append(client_hello_copy_serialized.data(),
                      client_hello_copy_serialized.length());
    hkdf_input.append(configs.requested->serialized);

    CrypterPair crypters;
    if (!CryptoUtils::DeriveKeys(
            context->version(), context->params()->initial_premaster_secret,
            context->params()->aead, context->info().client_nonce,
            context->info().server_nonce, pre_shared_key_, hkdf_input,
            Perspective::IS_SERVER, CryptoUtils::Diversification::Never(),
            &crypters, nullptr /* subkey secret */)) {
      context->Fail(QUIC_CRYPTO_SYMMETRIC_KEY_SETUP_FAILED,
                    "Symmetric key setup failed");
      return;
    }

    char plaintext[kMaxOutgoingPacketSize];
    size_t plaintext_length = 0;
    const bool success = crypters.decrypter->DecryptPacket(
        0 /* packet number */, absl::string_view() /* associated data */,
        cetv_ciphertext, plaintext, &plaintext_length, kMaxOutgoingPacketSize);
    if (!success) {
      context->Fail(QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER,
                    "CETV decryption failure");
      return;
    }
    std::unique_ptr<CryptoHandshakeMessage> cetv(CryptoFramer::ParseMessage(
        absl::string_view(plaintext, plaintext_length)));
    if (!cetv) {
      context->Fail(QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER, "CETV parse error");
      return;
    }

    absl::string_view key, signature;
    if (cetv->GetStringPiece(kCIDK, &key) &&
        cetv->GetStringPiece(kCIDS, &signature)) {
      if (!ChannelIDVerifier::Verify(key, hkdf_input, signature)) {
        context->Fail(QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER,
                      "ChannelID signature failure");
        return;
      }

      context->params()->channel_id = std::string(key);
    }
  }

  std::string hkdf_input;
  size_t label_len = strlen(QuicCryptoConfig::kInitialLabel) + 1;
  hkdf_input.reserve(label_len + hkdf_suffix.size());
  hkdf_input.append(QuicCryptoConfig::kInitialLabel, label_len);
  hkdf_input.append(hkdf_suffix);

  auto out_diversification_nonce = std::make_unique<DiversificationNonce>();
  context->rand()->RandBytes(out_diversification_nonce->data(),
                             out_diversification_nonce->size());
  CryptoUtils::Diversification diversification =
      CryptoUtils::Diversification::Now(out_diversification_nonce.get());
  if (!CryptoUtils::DeriveKeys(
          context->version(), context->params()->initial_premaster_secret,
          context->params()->aead, context->info().client_nonce,
          context->info().server_nonce, pre_shared_key_, hkdf_input,
          Perspective::IS_SERVER, diversification,
          &context->params()->initial_crypters,
          &context->params()->initial_subkey_secret)) {
    context->Fail(QUIC_CRYPTO_SYMMETRIC_KEY_SETUP_FAILED,
                  "Symmetric key setup failed");
    return;
  }

  std::string forward_secure_public_value;
  std::unique_ptr<SynchronousKeyExchange> forward_secure_key_exchange =
      CreateLocalSynchronousKeyExchange(key_exchange_type, context->rand());
  if (!forward_secure_key_exchange) {
    QUIC_DLOG(WARNING) << "Failed to create keypair";
    context->Fail(QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER,
                  "Failed to create keypair");
    return;
  }

  forward_secure_public_value =
      std::string(forward_secure_key_exchange->public_value());
  if (!forward_secure_key_exchange->CalculateSharedKeySync(
          public_value, &context->params()->forward_secure_premaster_secret)) {
    context->Fail(QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER,
                  "Invalid public value");
    return;
  }

  std::string forward_secure_hkdf_input;
  label_len = strlen(QuicCryptoConfig::kForwardSecureLabel) + 1;
  forward_secure_hkdf_input.reserve(label_len + hkdf_suffix.size());
  forward_secure_hkdf_input.append(QuicCryptoConfig::kForwardSecureLabel,
                                   label_len);
  forward_secure_hkdf_input.append(hkdf_suffix);

  std::string shlo_nonce;
  shlo_nonce = NewServerNonce(context->rand(), context->info().now);
  out->SetStringPiece(kServerNonceTag, shlo_nonce);

  if (!CryptoUtils::DeriveKeys(
          context->version(),
          context->params()->forward_secure_premaster_secret,
          context->params()->aead, context->info().client_nonce,
          shlo_nonce.empty() ? context->info().server_nonce : shlo_nonce,
          pre_shared_key_, forward_secure_hkdf_input, Perspective::IS_SERVER,
          CryptoUtils::Diversification::Never(),
          &context->params()->forward_secure_crypters,
          &context->params()->subkey_secret)) {
    context->Fail(QUIC_CRYPTO_SYMMETRIC_KEY_SETUP_FAILED,
                  "Symmetric key setup failed");
    return;
  }

  out->set_tag(kSHLO);
  out->SetVersionVector(kVER, context->supported_versions());
  out->SetStringPiece(
      kSourceAddressTokenTag,
      NewSourceAddressToken(*configs.requested->source_address_token_boxer,
                            context->info().source_address_tokens,
                            context->client_address().host(), context->rand(),
                            context->info().now, nullptr));
  QuicSocketAddressCoder address_coder(context->client_address());
  out->SetStringPiece(kCADR, address_coder.Encode());
  out->SetStringPiece(kPUBS, forward_secure_public_value);

  context->Succeed(std::move(out), std::move(out_diversification_nonce),
                   std::move(proof_source_details));
}

void QuicCryptoServerConfig::SendRejectWithFallbackConfig(
    std::unique_ptr<ProcessClientHelloContext> context,
    quiche::QuicheReferenceCountedPointer<Config> fallback_config) const {
  // We failed to calculate a shared initial key, likely because we tried to use
  // a remote key-exchange service which could not be reached.  We want to send
  // a REJ which tells the client to use a different ServerConfig which
  // corresponds to a local keypair.  To generate the REJ we need to request a
  // new proof.
  const std::string chlo_hash = CryptoUtils::HashHandshakeMessage(
      context->client_hello(), Perspective::IS_SERVER);
  const QuicSocketAddress server_address = context->server_address();
  const std::string sni(context->info().sni);
  const QuicTransportVersion transport_version = context->transport_version();

  const QuicSocketAddress& client_address = context->client_address();
  auto cb = std::make_unique<SendRejectWithFallbackConfigCallback>(
      this, std::move(context), fallback_config);
  proof_source_->GetProof(server_address, client_address, sni,
                          fallback_config->serialized, transport_version,
                          chlo_hash, std::move(cb));
}

void QuicCryptoServerConfig::SendRejectWithFallbackConfigAfterGetProof(
    bool found_error,
    std::unique_ptr<ProofSource::Details> proof_source_details,
    std::unique_ptr<ProcessClientHelloContext> context,
    quiche::QuicheReferenceCountedPointer<Config> fallback_config) const {
  if (found_error) {
    context->Fail(QUIC_HANDSHAKE_FAILED, "Failed to get proof");
    return;
  }

  auto out = std::make_unique<CryptoHandshakeMessage>();
  BuildRejectionAndRecordStats(*context, *fallback_config,
                               {SERVER_CONFIG_UNKNOWN_CONFIG_FAILURE},
                               out.get());

  context->Succeed(std::move(out), std::make_unique<DiversificationNonce>(),
                   std::move(proof_source_details));
}

quiche::QuicheReferenceCountedPointer<QuicCryptoServerConfig::Config>
QuicCryptoServerConfig::GetConfigWithScid(
    absl::string_view requested_scid) const {
  configs_lock_.AssertReaderHeld();

  if (!requested_scid.empty()) {
    auto it = configs_.find((std::string(requested_scid)));
    if (it != configs_.end()) {
      // We'll use the config that the client requested in order to do
      // key-agreement.
      return quiche::QuicheReferenceCountedPointer<Config>(it->second);
    }
  }

  return quiche::QuicheReferenceCountedPointer<Config>();
}

bool QuicCryptoServerConfig::GetCurrentConfigs(
    const QuicWallTime& now, absl::string_view requested_scid,
    quiche::QuicheReferenceCountedPointer<Config> old_primary_config,
    Configs* configs) const {
  quiche::QuicheReaderMutexLock locked(&configs_lock_);

  if (!primary_config_) {
    return false;
  }

  if (IsNextConfigReady(now)) {
    configs_lock_.ReaderUnlock();
    configs_lock_.WriterLock();
    SelectNewPrimaryConfig(now);
    QUICHE_DCHECK(primary_config_.get());
    QUICHE_DCHECK_EQ(configs_.find(primary_config_->id)->second.get(),
                     primary_config_.get());
    configs_lock_.WriterUnlock();
    configs_lock_.ReaderLock();
  }

  if (old_primary_config != nullptr) {
    configs->primary = old_primary_config;
  } else {
    configs->primary = primary_config_;
  }
  configs->requested = GetConfigWithScid(requested_scid);
  configs->fallback = fallback_config_;

  return true;
}

// ConfigPrimaryTimeLessThan is a comparator that implements "less than" for
// Config's based on their primary_time.
// static
bool QuicCryptoServerConfig::ConfigPrimaryTimeLessThan(
    const quiche::QuicheReferenceCountedPointer<Config>& a,
    const quiche::QuicheReferenceCountedPointer<Config>& b) {
  if (a->primary_time.IsBefore(b->primary_time) ||
      b->primary_time.IsBefore(a->primary_time)) {
    // Primary times differ.
    return a->primary_time.IsBefore(b->primary_time);
  } else if (a->priority != b->priority) {
    // Primary times are equal, sort backwards by priority.
    return a->priority < b->priority;
  } else {
    // Primary times and priorities are equal, sort by config id.
    return a->id < b->id;
  }
}

void QuicCryptoServerConfig::SelectNewPrimaryConfig(
    const QuicWallTime now) const {
  std::vector<quiche::QuicheReferenceCountedPointer<Config>> configs;
  configs.reserve(configs_.size());

  for (auto it = configs_.begin(); it != configs_.end(); ++it) {
    // TODO(avd) Exclude expired configs?
    configs.push_back(it->second);
  }

  if (configs.empty()) {
    if (primary_config_ != nullptr) {
      QUIC_BUG(quic_bug_10630_2)
          << "No valid QUIC server config. Keeping the current config.";
    } else {
      QUIC_BUG(quic_bug_10630_3) << "No valid QUIC server config.";
    }
    return;
  }

  std::sort(configs.begin(), configs.end(), ConfigPrimaryTimeLessThan);

  quiche::QuicheReferenceCountedPointer<Config> best_candidate = configs[0];

  for (size_t i = 0; i < configs.size(); ++i) {
    const quiche::QuicheReferenceCountedPointer<Config> config(configs[i]);
    if (!config->primary_time.IsAfter(now)) {
      if (config->primary_time.IsAfter(best_candidate->primary_time)) {
        best_candidate = config;
      }
      continue;
    }

    // This is the first config with a primary_time in the future. Thus the
    // previous Config should be the primary and this one should determine the
    // next_config_promotion_time_.
    quiche::QuicheReferenceCountedPointer<Config> new_primary = best_candidate;
    if (i == 0) {
      // We need the primary_time of the next config.
      if (configs.size() > 1) {
        next_config_promotion_time_ = configs[1]->primary_time;
      } else {
        next_config_promotion_time_ = QuicWallTime::Zero();
      }
    } else {
      next_config_promotion_time_ = config->primary_time;
    }

    if (primary_config_) {
      primary_config_->is_primary = false;
    }
    primary_config_ = new_primary;
    new_primary->is_primary = true;
    QUIC_DLOG(INFO) << "New primary config.  orbit: "
                    << absl::BytesToHexString(
                           absl::string_view(reinterpret_cast<const char*>(
                                                 primary_config_->orbit),
                                             kOrbitSize));
    if (primary_config_changed_cb_ != nullptr) {
      primary_config_changed_cb_->Run(primary_config_->id);
    }

    return;
  }

  // All config's primary times are in the past. We should make the most recent
  // and highest priority candidate primary.
  quiche::QuicheReferenceCountedPointer<Config> new_primary = best_candidate;
  if (primary_config_) {
    primary_config_->is_primary = false;
  }
  primary_config_ = new_primary;
  new_primary->is_primary = true;
  QUIC_DLOG(INFO) << "New primary config.  orbit: "
                  << absl::BytesToHexString(absl::string_view(
                         reinterpret_cast<const char*>(primary_config_->orbit),
                         kOrbitSize))
                  << " scid: " << absl::BytesToHexString(primary_config_->id);
  next_config_promotion_time_ = QuicWallTime::Zero();
  if (primary_config_changed_cb_ != nullptr) {
    primary_config_changed_cb_->Run(primary_config_->id);
  }
}

void QuicCryptoServerConfig::EvaluateClientHello(
    const QuicSocketAddress& /*server_address*/,
    const QuicSocketAddress& /*client_address*/,
    QuicTransportVersion /*version*/, const Configs& configs,
    quiche::QuicheReferenceCountedPointer<
        ValidateClientHelloResultCallback::Result>
        client_hello_state,
    std::unique_ptr<ValidateClientHelloResultCallback> done_cb) const {
  ValidateClientHelloHelper helper(client_hello_state, &done_cb);

  const CryptoHandshakeMessage& client_hello = client_hello_state->client_hello;
  ClientHelloInfo* info = &(client_hello_state->info);

  if (client_hello.GetStringPiece(kSNI, &info->sni) &&
      !QuicHostnameUtils::IsValidSNI(info->sni)) {
    helper.ValidationComplete(QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER,
                              "Invalid SNI name", nullptr);
    return;
  }

  client_hello.GetStringPiece(kUAID, &info->user_agent_id);

  HandshakeFailureReason source_address_token_error = MAX_FAILURE_REASON;
  if (validate_source_address_token_) {
    absl::string_view srct;
    if (client_hello.GetStringPiece(kSourceAddressTokenTag, &srct)) {
      Config& config =
          configs.requested != nullptr ? *configs.requested : *configs.primary;
      source_address_token_error =
          ParseSourceAddressToken(*config.source_address_token_boxer, srct,
                                  info->source_address_tokens);

      if (source_address_token_error == HANDSHAKE_OK) {
        source_address_token_error = ValidateSourceAddressTokens(
            info->source_address_tokens, info->client_ip, info->now,
            &client_hello_state->cached_network_params);
      }
      info->valid_source_address_token =
          (source_address_token_error == HANDSHAKE_OK);
    } else {
      source_address_token_error = SOURCE_ADDRESS_TOKEN_INVALID_FAILURE;
    }
  } else {
    source_address_token_error = HANDSHAKE_OK;
    info->valid_source_address_token = true;
  }

  if (!configs.requested) {
    absl::string_view requested_scid;
    if (client_hello.GetStringPiece(kSCID, &requested_scid)) {
      info->reject_reasons.push_back(SERVER_CONFIG_UNKNOWN_CONFIG_FAILURE);
    } else {
      info->reject_reasons.push_back(SERVER_CONFIG_INCHOATE_HELLO_FAILURE);
    }
    // No server config with the requested ID.
    helper.ValidationComplete(QUIC_NO_ERROR, "", nullptr);
    return;
  }

  if (!client_hello.GetStringPiece(kNONC, &info->client_nonce)) {
    info->reject_reasons.push_back(SERVER_CONFIG_INCHOATE_HELLO_FAILURE);
    // Report no client nonce as INCHOATE_HELLO_FAILURE.
    helper.ValidationComplete(QUIC_NO_ERROR, "", nullptr);
    return;
  }

  if (source_address_token_error != HANDSHAKE_OK) {
    info->reject_reasons.push_back(source_address_token_error);
    // No valid source address token.
  }

  if (info->client_nonce.size() != kNonceSize) {
    info->reject_reasons.push_back(CLIENT_NONCE_INVALID_FAILURE);
    // Invalid client nonce.
    QUIC_LOG_FIRST_N(ERROR, 2)
        << "Invalid client nonce: " << client_hello.DebugString();
    QUIC_DLOG(INFO) << "Invalid client nonce.";
  }

  // Server nonce is optional, and used for key derivation if present.
  client_hello.GetStringPiece(kServerNonceTag, &info->server_nonce);

  // If the server nonce is empty and we're requiring handshake confirmation
  // for DoS reasons then we must reject the CHLO.
  if (GetQuicReloadableFlag(quic_require_handshake_confirmation) &&
      info->server_nonce.empty()) {
    QUIC_RELOADABLE_FLAG_COUNT(quic_require_handshake_confirmation);
    info->reject_reasons.push_back(SERVER_NONCE_REQUIRED_FAILURE);
  }
  helper.ValidationComplete(QUIC_NO_ERROR, "",
                            std::unique_ptr<ProofSource::Details>());
}

void QuicCryptoServerConfig::BuildServerConfigUpdateMessage(
    QuicTransportVersion version, absl::string_view chlo_hash,
    const SourceAddressTokens& previous_source_address_tokens,
    const QuicSocketAddress& server_address,
    const QuicSocketAddress& client_address, const QuicClock* clock,
    QuicRandom* rand, QuicCompressedCertsCache* compressed_certs_cache,
    const QuicCryptoNegotiatedParameters& params,
    const CachedNetworkParameters* cached_network_params,
    std::unique_ptr<BuildServerConfigUpdateMessageResultCallback> cb) const {
  std::string serialized;
  std::string source_address_token;
  {
    quiche::QuicheReaderMutexLock locked(&configs_lock_);
    serialized = primary_config_->serialized;
    source_address_token = NewSourceAddressToken(
        *primary_config_->source_address_token_boxer,
        previous_source_address_tokens, client_address.host(), rand,
        clock->WallNow(), cached_network_params);
  }

  CryptoHandshakeMessage message;
  message.set_tag(kSCUP);
  message.SetStringPiece(kSCFG, serialized);
  message.SetStringPiece(kSourceAddressTokenTag, source_address_token);

  auto proof_source_cb =
      std::make_unique<BuildServerConfigUpdateMessageProofSourceCallback>(
          this, compressed_certs_cache, params, std::move(message),
          std::move(cb));

  proof_source_->GetProof(server_address, client_address, params.sni,
                          serialized, version, chlo_hash,
                          std::move(proof_source_cb));
}

QuicCryptoServerConfig::BuildServerConfigUpdateMessageProofSourceCallback::
    ~BuildServerConfigUpdateMessageProofSourceCallback() {}

QuicCryptoServerConfig::BuildServerConfigUpdateMessageProofSourceCallback::
    BuildServerConfigUpdateMessageProofSourceCallback(
        const QuicCryptoServerConfig* config,
        QuicCompressedCertsCache* compressed_certs_cache,
        const QuicCryptoNegotiatedParameters& params,
        CryptoHandshakeMessage message,
        std::unique_ptr<BuildServerConfigUpdateMessageResultCallback> cb)
    : config_(config),
      compressed_certs_cache_(compressed_certs_cache),
      client_cached_cert_hashes_(params.client_cached_cert_hashes),
      sct_supported_by_client_(params.sct_supported_by_client),
      sni_(params.sni),
      message_(std::move(message)),
      cb_(std::move(cb)) {}

void QuicCryptoServerConfig::BuildServerConfigUpdateMessageProofSourceCallback::
    Run(bool ok,
        const quiche::QuicheReferenceCountedPointer<ProofSource::Chain>& chain,
        const QuicCryptoProof& proof,
        std::unique_ptr<ProofSource::Details> details) {
  config_->FinishBuildServerConfigUpdateMessage(
      compressed_certs_cache_, client_cached_cert_hashes_,
      sct_supported_by_client_, sni_, ok, chain, proof.signature,
      proof.leaf_cert_scts, std::move(details), std::move(message_),
      std::move(cb_));
}

void QuicCryptoServerConfig::FinishBuildServerConfigUpdateMessage(
    QuicCompressedCertsCache* compressed_certs_cache,
    const std::string& client_cached_cert_hashes, bool sct_supported_by_client,
    const std::string& sni, bool ok,
    const quiche::QuicheReferenceCountedPointer<ProofSource::Chain>& chain,
    const std::string& signature, const std::string& leaf_cert_sct,
    std::unique_ptr<ProofSource::Details> /*details*/,
    CryptoHandshakeMessage message,
    std::unique_ptr<BuildServerConfigUpdateMessageResultCallback> cb) const {
  if (!ok) {
    cb->Run(false, message);
    return;
  }

  const std::string compressed =
      CompressChain(compressed_certs_cache, chain, client_cached_cert_hashes);

  message.SetStringPiece(kCertificateTag, compressed);
  message.SetStringPiece(kPROF, signature);
  if (sct_supported_by_client && enable_serving_sct_) {
    if (leaf_cert_sct.empty()) {
      QUIC_LOG_EVERY_N_SEC(WARNING, 60)
          << "SCT is expected but it is empty. SNI: " << sni;
    } else {
      message.SetStringPiece(kCertificateSCTTag, leaf_cert_sct);
    }
  }

  cb->Run(true, message);
}

void QuicCryptoServerConfig::BuildRejectionAndRecordStats(
    const ProcessClientHelloContext& context, const Config& config,
    const std::vector<uint32_t>& reject_reasons,
    CryptoHandshakeMessage* out) const {
  BuildRejection(context, config, reject_reasons, out);
  if (rejection_observer_ != nullptr) {
    rejection_observer_->OnRejectionBuilt(reject_reasons, out);
  }
}

void QuicCryptoServerConfig::BuildRejection(
    const ProcessClientHelloContext& context, const Config& config,
    const std::vector<uint32_t>& reject_reasons,
    CryptoHandshakeMessage* out) const {
  const QuicWallTime now = context.clock()->WallNow();

  out->set_tag(kREJ);
  out->SetStringPiece(kSCFG, config.serialized);
  out->SetStringPiece(
      kSourceAddressTokenTag,
      NewSourceAddressToken(
          *config.source_address_token_boxer,
          context.info().source_address_tokens, context.info().client_ip,
          context.rand(), context.info().now,
          &context.validate_chlo_result()->cached_network_params));
  out->SetValue(kSTTL, config.expiry_time.AbsoluteDifference(now).ToSeconds());
  if (replay_protection_) {
    out->SetStringPiece(kServerNonceTag,
                        NewServerNonce(context.rand(), context.info().now));
  }

  // Send client the reject reason for debugging purposes.
  QUICHE_DCHECK_LT(0u, reject_reasons.size());
  out->SetVector(kRREJ, reject_reasons);

  // The client may have requested a certificate chain.
  if (!ClientDemandsX509Proof(context.client_hello())) {
    QUIC_BUG(quic_bug_10630_4)
        << "x509 certificates not supported in proof demand";
    return;
  }

  absl::string_view client_cached_cert_hashes;
  if (context.client_hello().GetStringPiece(kCCRT,
                                            &client_cached_cert_hashes)) {
    context.params()->client_cached_cert_hashes =
        std::string(client_cached_cert_hashes);
  } else {
    context.params()->client_cached_cert_hashes.clear();
  }

  const std::string compressed = CompressChain(
      context.compressed_certs_cache(), context.signed_config()->chain,
      context.params()->client_cached_cert_hashes);

  QUICHE_DCHECK_GT(context.chlo_packet_size(), context.client_hello().size());
  // kREJOverheadBytes is a very rough estimate of how much of a REJ
  // message is taken up by things other than the certificates.
  // STK: 56 bytes
  // SNO: 56 bytes
  // SCFG
  //   SCID: 16 bytes
  //   PUBS: 38 bytes
  const size_t kREJOverheadBytes = 166;
  // max_unverified_size is the number of bytes that the certificate chain,
  // signature, and (optionally) signed certificate timestamp can consume before
  // we will demand a valid source-address token.
  const size_t max_unverified_size =
      chlo_multiplier_ *
          (context.chlo_packet_size() - context.total_framing_overhead()) -
      kREJOverheadBytes;
  static_assert(kClientHelloMinimumSize * kMultiplier >= kREJOverheadBytes,
                "overhead calculation may underflow");
  bool should_return_sct =
      context.params()->sct_supported_by_client && enable_serving_sct_;
  const std::string& cert_sct = context.signed_config()->proof.leaf_cert_scts;
  const size_t sct_size = should_return_sct ? cert_sct.size() : 0;
  const size_t total_size = context.signed_config()->proof.signature.size() +
                            compressed.size() + sct_size;
  if (context.info().valid_source_address_token ||
      total_size < max_unverified_size) {
    out->SetStringPiece(kCertificateTag, compressed);
    out->SetStringPiece(kPROF, context.signed_config()->proof.signature);
    if (should_return_sct) {
      if (cert_sct.empty()) {
        // Log SNI and subject name for the leaf cert if its SCT is empty.
        // This is for debugging b/28342827.
        const std::vector<std::string>& certs =
            context.signed_config()->chain->certs;
        std::string ca_subject;
        if (!certs.empty()) {
          std::unique_ptr<CertificateView> view =
              CertificateView::ParseSingleCertificate(certs[0]);
          if (view != nullptr) {
            std::optional<std::string> maybe_ca_subject =
                view->GetHumanReadableSubject();
            if (maybe_ca_subject.has_value()) {
              ca_subject = *maybe_ca_subject;
            }
          }
        }
        QUIC_LOG_EVERY_N_SEC(WARNING, 60)
            << "SCT is expected but it is empty. sni: '"
            << context.params()->sni << "' cert subject: '" << ca_subject
            << "'";
      } else {
        out->SetStringPiece(kCertificateSCTTag, cert_sct);
      }
    }
  } else {
    QUIC_LOG_EVERY_N_SEC(WARNING, 60)
        << "Sending inchoate REJ for hostname: " << context.info().sni
        << " signature: " << context.signed_config()->proof.signature.size()
        << " cert: " << compressed.size() << " sct:" << sct_size
        << " total: " << total_size << " max: " << max_unverified_size;
  }
}

std::string QuicCryptoServerConfig::CompressChain(
    QuicCompressedCertsCache* compressed_certs_cache,
    const quiche::QuicheReferenceCountedPointer<ProofSource::Chain>& chain,
    const std::string& client_cached_cert_hashes) {
  // Check whether the compressed certs is available in the cache.
  QUICHE_DCHECK(compressed_certs_cache);
  const std::string* cached_value = compressed_certs_cache->GetCompressedCert(
      chain, client_cached_cert_hashes);
  if (cached_value) {
    return *cached_value;
  }
  std::string compressed =
      CertCompressor::CompressChain(chain->certs, client_cached_cert_hashes);
  // Insert the newly compressed cert to cache.
  compressed_certs_cache->Insert(chain, client_cached_cert_hashes, compressed);
  return compressed;
}

quiche::QuicheReferenceCountedPointer<QuicCryptoServerConfig::Config>
QuicCryptoServerConfig::ParseConfigProtobuf(
    const QuicServerConfigProtobuf& protobuf, bool is_fallback) const {
  std::unique_ptr<CryptoHandshakeMessage> msg =
      CryptoFramer::ParseMessage(protobuf.config());

  if (!msg) {
    QUIC_LOG(WARNING) << "Failed to parse server config message";
    return nullptr;
  }

  if (msg->tag() != kSCFG) {
    QUIC_LOG(WARNING) << "Server config message has tag " << msg->tag()
                      << ", but expected " << kSCFG;
    return nullptr;
  }

  quiche::QuicheReferenceCountedPointer<Config> config(new Config);
  config->serialized = protobuf.config();
  config->source_address_token_boxer = &source_address_token_boxer_;

  if (protobuf.has_primary_time()) {
    config->primary_time =
        QuicWallTime::FromUNIXSeconds(protobuf.primary_time());
  }

  config->priority = protobuf.priority();

  absl::string_view scid;
  if (!msg->GetStringPiece(kSCID, &scid)) {
    QUIC_LOG(WARNING) << "Server config message is missing SCID";
    return nullptr;
  }
  if (scid.empty()) {
    QUIC_LOG(WARNING) << "Server config message contains an empty SCID";
    return nullptr;
  }
  config->id = std::string(scid);

  if (msg->GetTaglist(kAEAD, &config->aead) != QUIC_NO_ERROR) {
    QUIC_LOG(WARNING) << "Server config message is missing AEAD";
    return nullptr;
  }

  QuicTagVector kexs_tags;
  if (msg->GetTaglist(kKEXS, &kexs_tags) != QUIC_NO_ERROR) {
    QUIC_LOG(WARNING) << "Server config message is missing KEXS";
    return nullptr;
  }

  absl::string_view orbit;
  if (!msg->GetStringPiece(kORBT, &orbit)) {
    QUIC_LOG(WARNING) << "Server config message is missing ORBT";
    return nullptr;
  }

  if (orbit.size() != kOrbitSize) {
    QUIC_LOG(WARNING) << "Orbit value in server config is the wrong length."
                         " Got "
                      << orbit.size() << " want " << kOrbitSize;
    return nullptr;
  }
  static_assert(sizeof(config->orbit) == kOrbitSize, "incorrect orbit size");
  memcpy(config->orbit, orbit.data(), sizeof(config->orbit));

  QuicTagVector proof_demand_tags;
  if (msg->GetTaglist(kPDMD, &proof_demand_tags) == QUIC_NO_ERROR) {
    for (QuicTag tag : proof_demand_tags) {
      if (tag == kCHID) {
        config->channel_id_enabled = true;
        break;
      }
    }
  }

  for (size_t i = 0; i < kexs_tags.size(); i++) {
    const QuicTag tag = kexs_tags[i];
    std::string private_key;

    config->kexs.push_back(tag);

    for (int j = 0; j < protobuf.key_size(); j++) {
      const QuicServerConfigProtobuf::PrivateKey& key = protobuf.key(i);
      if (key.tag() == tag) {
        private_key = key.private_key();
        break;
      }
    }

    std::unique_ptr<AsynchronousKeyExchange> ka =
        key_exchange_source_->Create(config->id, is_fallback, tag, private_key);
    if (!ka) {
      return nullptr;
    }
    for (const auto& key_exchange : config->key_exchanges) {
      if (key_exchange->type() == tag) {
        QUIC_LOG(WARNING) << "Duplicate key exchange in config: " << tag;
        return nullptr;
      }
    }

    con
```