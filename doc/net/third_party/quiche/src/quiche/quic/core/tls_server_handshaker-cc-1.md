Response:
The user wants to understand the functionality of the provided C++ code snippet, which is part of the Chromium network stack and specifically deals with the TLS server handshake in the QUIC protocol. I need to analyze the code and describe its purpose.

Here's a breakdown of the functions and their likely roles:

- **`FinalizeSessionTicketOpen`**: This function appears to handle the final steps after attempting to open/decrypt a session ticket. It checks if decryption was successful and copies the decrypted ticket data if it was.
- **`EarlySelectCertCallback`**: This function seems to be an early callback in the TLS handshake process related to certificate selection. It likely retrieves information from the client hello, processes transport parameters, selects a certificate, and sets up ALPN.
- **`OnSelectCertificateDone`**:  This function is probably called after the asynchronous certificate selection is complete. It handles the result (success or failure), processes the selected certificate, and potentially updates the TLS connection state.
- **`WillNotCallComputeSignature`**:  This function likely checks if the server will need to compute a signature as part of the handshake.
- **`GetCiphersuite`**: This function retrieves the negotiated cipher suite.
- **`ValidateHostname`**: This function validates the hostname received in the Server Name Indication (SNI).
- **`TlsExtServernameCallback`**: This is likely a callback for handling the server name extension.
- **`SelectAlpn`**: This function handles the selection of the Application-Layer Protocol Negotiation (ALPN).
- **`SetApplicationSettings`**: This function seems to set application-specific settings, including the Accept-CH header.
- **`GetSsl`**:  A simple getter for the underlying SSL object.
- **`IsCryptoFrameExpectedForEncryptionLevel`**: This function determines if a crypto frame is expected at a given encryption level.
- **`GetEncryptionLevelToSendCryptoDataOfSpace`**: This function determines the appropriate encryption level for sending crypto data in a specific packet number space.

Based on these observations, I can formulate the overall functionality and address the user's specific requests regarding JavaScript interaction, logical reasoning, common errors, and debugging steps.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/tls_server_handshaker.cc` 文件的第二部分，延续了第一部分的功能，主要负责 TLS 服务器握手过程中的一些关键步骤，特别是与会话票证处理、证书选择、ALPN 协商以及应用层设置相关的操作。

**归纳一下它的功能：**

这部分代码主要负责以下功能，延续了 TLS 服务器握手的流程：

1. **完成会话票证的打开 (FinalizeSessionTicketOpen):**  在尝试解密会话票证后，该函数会进行最终处理。如果解密成功，它会将解密后的票证数据复制出来。如果解密失败，则会忽略该票证。
2. **提前选择证书回调 (EarlySelectCertCallback):** 这是在 TLS 握手早期调用的一个关键回调函数。它负责：
    - 处理客户端的 ClientHello 消息。
    - 检查是否收到了 Pre-Shared Key (PSK) (但当前代码中不支持 PSK)。
    - 检查是否收到了会话票证和 Early Data 指示。
    - 处理 ALPS (Application Layer Protocol Settings) 扩展。
    - 获取并验证客户端提供的 SNI (Server Name Indication) 主机名。
    - 处理客户端提供的传输参数。
    - 设置服务器的传输参数。
    - 设置 ALPN (Application-Layer Protocol Negotiation)。
    - 调用 `proof_source_handle_` 来异步选择证书。
3. **完成证书选择 (OnSelectCertificateDone):**  当异步证书选择操作完成后，该函数会被调用。它负责：
    - 处理证书选择的结果 (成功或失败)。
    - 存储票证加密密钥。
    - 从 `ProofSource` 获取的配置更新 SSL 对象，例如传输参数和客户端证书模式。
    - 设置服务器的证书链。
    - 处理来自 `HintsSSLConfig` 的 ALPN 选择逻辑。
    - 记录证书选择操作的统计信息，包括异步延迟。
    - 如果是异步操作，则继续握手流程。
4. **确定是否会调用签名计算 (WillNotCallComputeSignature):**  检查 BoringSSL 内部状态，判断是否需要进行签名计算。
5. **获取密码套件 (GetCiphersuite):**  获取当前正在使用的 TLS 密码套件。
6. **验证主机名 (ValidateHostname):**  验证客户端提供的 SNI 主机名是否有效。
7. **处理服务器名称扩展回调 (TlsExtServernameCallback):**  简单地确认收到了服务器名称扩展。
8. **选择 ALPN (SelectAlpn):**  与客户端协商选择应用层协议。如果提供了 `select_alpn_` 回调，则使用该回调。否则，它会解析客户端提供的 ALPN 列表，并与服务器支持的协议进行匹配。
9. **设置应用层设置 (SetApplicationSettings):**  设置应用层相关的设置，例如 Accept-CH 首部，用于指示服务器支持的客户端提示功能。
10. **获取 SSL 对象 (GetSsl):**  提供访问底层 BoringSSL `SSL` 对象的接口。
11. **判断特定加密级别是否需要 Crypto 帧 (IsCryptoFrameExpectedForEncryptionLevel):**  判断在给定的加密级别下是否需要发送 QUIC Crypto 帧。
12. **获取发送特定 PacketNumberSpace 的 Crypto 数据的加密级别 (GetEncryptionLevelToSendCryptoDataOfSpace):**  确定发送 Initial、Handshake 或 Application 数据时应使用的加密级别。

**与 JavaScript 功能的关系：**

这个 C++ 代码直接运行在服务器端，负责处理 QUIC 连接的 TLS 握手。它本身不直接与 JavaScript 代码交互。但是，它的功能直接影响到运行在浏览器中的 JavaScript 代码，因为：

* **HTTPS 连接的建立:**  这段代码负责建立安全的 HTTPS 连接，这是 JavaScript 通过 `fetch` 或 `XMLHttpRequest` 等 API 发起网络请求的基础。如果服务器端的 TLS 握手失败，浏览器的 JavaScript 代码将无法成功建立连接。
* **QUIC 协议的支持:** 这段代码是 QUIC 协议服务器端实现的一部分。如果服务器支持 QUIC，浏览器可以通过 QUIC 协议与服务器进行通信，这可以提高网络性能和用户体验。JavaScript 代码通常不需要知道底层使用的是 TCP 还是 QUIC，网络栈会处理这些细节。
* **ALPN 协商:**  服务器通过 `SelectAlpn` 函数选择的应用层协议（例如 HTTP/3），会影响浏览器如何与服务器进行 HTTP 通信。JavaScript 的 `fetch` API 会根据协商的协议进行相应的操作。
* **会话恢复:**  `FinalizeSessionTicketOpen` 和相关的会话票证机制允许客户端在后续连接中恢复之前的会话，从而减少握手延迟。这对于提升 JavaScript 应用的加载速度和性能是有益的。

**逻辑推理，假设输入与输出：**

**场景：处理客户端的 ClientHello 消息 (EarlySelectCertCallback)**

**假设输入：**

* `client_hello`: 一个包含客户端 ClientHello 消息的 `SSL_CLIENT_HELLO` 结构体。
    * 包含了客户端支持的 TLS 版本、密码套件、扩展（例如 SNI、ALPN、传输参数、会话票证等）。
    * 假设客户端提供了 SNI "example.com"。
    * 假设客户端提供了支持的 ALPN 列表 ["h3-29", "h3-28", "http/1.1"]。
    * 假设客户端尝试进行 0-RTT Early Data。
* 服务器配置了支持 "h3-29" 和 "http/1.1" 协议。
* 服务器的 `ProofSource` 能够为 "example.com" 提供证书。

**预期输出：**

* `crypto_negotiated_params_->sni` 将被设置为 "example.com"。
* 服务器的 ALPN 将被选择为 "h3-29"。
* `early_data_attempted_` 将被设置为 true。
* `proof_source_handle_->SelectCertificate` 将被调用，并传入相关参数，包括 SNI、ALPN 等。
* 如果证书选择是异步的，函数将返回 `ssl_select_cert_retry`，并设置期望的 SSL 错误为 `SSL_ERROR_PENDING_CERTIFICATE`。
* 如果证书选择是同步的并且成功，函数将返回 `ssl_select_cert_success`。

**用户或编程常见的使用错误：**

1. **`ProofSource` 配置错误:**  如果 `ProofSource` 没有为请求的 SNI 配置有效的证书，`EarlySelectCertCallback` 中的证书选择过程将失败，导致握手失败。
    * **例子:** 用户部署了一个服务器，但忘记为域名配置 TLS 证书，或者证书已过期。
2. **ALPN 配置不匹配:**  如果客户端提供的 ALPN 列表与服务器配置的 ALPN 列表没有交集，`SelectAlpn` 函数将返回 `SSL_TLSEXT_ERR_NOACK`，导致握手失败。
    * **例子:** 用户在服务器上只配置了支持 HTTP/3，但客户端只支持 HTTP/2。
3. **传输参数处理错误:**  如果客户端提供的传输参数无法被服务器正确解析或验证，`ProcessTransportParameters` 函数将返回错误，导致握手失败。
    * **例子:** 客户端发送的传输参数中包含了无效的标识符或值。
4. **`OnSelectCertificateDone` 中未处理异步完成:**  如果证书选择是异步的，开发者需要在 `OnSelectCertificateDone` 回调中正确处理结果，并继续握手流程。如果处理不当，可能导致握手停滞或失败。
5. **忘记设置必要的 SSL 配置:** 在 `OnSelectCertificateDone` 中，如果没有正确设置证书链或其他必要的 SSL 配置，后续的握手步骤可能会失败。
    * **例子:**  `LocalSSLConfig` 中的 `chain` 为空。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中输入一个 HTTPS 地址 (例如 `https://example.com`) 并按下回车。**
2. **浏览器开始与服务器建立连接。** 如果支持 QUIC 且服务器也支持，浏览器可能会尝试建立 QUIC 连接。
3. **QUIC 客户端 (在浏览器中) 发送一个 Initial 包给服务器。**
4. **QUIC 服务器接收到 Initial 包，并创建 `TlsServerHandshaker` 对象开始处理握手。**
5. **服务器的 QUIC 代码解析 Initial 包，并调用 BoringSSL 的相关 API 进行 TLS 握手。**
6. **在 TLS 握手早期，BoringSSL 会调用 `TlsServerHandshaker::EarlySelectCertCallback`。** 此时，`client_hello` 参数包含了从客户端发送过来的 ClientHello 消息。
7. **`EarlySelectCertCallback` 函数会提取客户端的 SNI，并根据 SNI 调用 `proof_source_handle_->SelectCertificate` 来选择合适的证书。** 如果证书选择是异步的，函数会返回 `ssl_select_cert_retry`。
8. **当 `ProofSource` 完成证书选择后，会调用 `TlsServerHandshaker::OnSelectCertificateDone`。**  这个回调会处理证书选择的结果。
9. **在握手过程中，BoringSSL 会调用 `TlsServerHandshaker::SelectAlpn` 来协商应用层协议。**
10. **当需要处理会话票证时，可能会调用 `TlsServerHandshaker::FinalizeSessionTicketOpen`。**

**调试线索:**

* **查看 QUIC 连接的事件日志:**  Chromium 的网络日志 (可以通过 `chrome://net-export/` 导出) 可以提供关于 QUIC 连接建立过程的详细信息，包括 TLS 握手的状态和错误。
* **BoringSSL 的调试输出:**  可以通过设置环境变量或编译选项来启用 BoringSSL 的调试输出，以查看更底层的 TLS 握手过程。
* **在 `EarlySelectCertCallback` 和 `OnSelectCertificateDone` 等关键函数中添加日志:**  打印关键变量的值，例如 SNI、选择的 ALPN、证书选择的结果等，可以帮助理解握手过程中的状态。
* **检查 `ProofSource` 的实现:**  确认 `ProofSource` 能够正确地为请求的 SNI 提供证书。
* **分析网络抓包:**  使用 Wireshark 等工具抓取网络包，可以查看客户端和服务器之间交换的 TLS 握手消息，包括 ClientHello 和 ServerHello，从而诊断握手失败的原因。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/tls_server_handshaker.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
cket_stats =
      std::move(decrypt_ticket_stats);

  return result;
}

ssl_ticket_aead_result_t TlsServerHandshaker::FinalizeSessionTicketOpen(
    uint8_t* out, size_t* out_len, size_t max_out_len) {
  ticket_decryption_callback_ = nullptr;
  set_expected_ssl_error(SSL_ERROR_WANT_READ);
  if (decrypted_session_ticket_.empty()) {
    QUIC_DLOG(ERROR) << "Session ticket decryption failed; ignoring ticket";
    // Ticket decryption failed. Ignore the ticket.
    QUIC_CODE_COUNT(quic_tls_server_handshaker_tickets_ignored_2);
    return ssl_ticket_aead_ignore_ticket;
  }
  if (max_out_len < decrypted_session_ticket_.size()) {
    return ssl_ticket_aead_error;
  }
  memcpy(out, decrypted_session_ticket_.data(),
         decrypted_session_ticket_.size());
  *out_len = decrypted_session_ticket_.size();

  QUIC_CODE_COUNT(quic_tls_server_handshaker_tickets_opened);
  return ssl_ticket_aead_success;
}

ssl_select_cert_result_t TlsServerHandshaker::EarlySelectCertCallback(
    const SSL_CLIENT_HELLO* client_hello) {
  // EarlySelectCertCallback can be called twice from BoringSSL: If the first
  // call returns ssl_select_cert_retry, when cert selection completes,
  // SSL_do_handshake will call it again.

  if (select_cert_status_.has_value()) {
    // This is the second call, return the result directly.
    QUIC_DVLOG(1) << "EarlySelectCertCallback called to continue handshake, "
                     "returning directly. success:"
                  << (*select_cert_status_ == QUIC_SUCCESS);
    return (*select_cert_status_ == QUIC_SUCCESS) ? ssl_select_cert_success
                                                  : ssl_select_cert_error;
  }

  // This is the first call.
  select_cert_status_ = QUIC_PENDING;
  proof_source_handle_ = MaybeCreateProofSourceHandle();

  if (!pre_shared_key_.empty()) {
    // TODO(b/154162689) add PSK support to QUIC+TLS.
    QUIC_BUG(quic_bug_10341_6)
        << "QUIC server pre-shared keys not yet supported with TLS";
    set_extra_error_details("select_cert_error: pre-shared keys not supported");
    return ssl_select_cert_error;
  }

  {
    const uint8_t* unused_extension_bytes;
    size_t unused_extension_len;
    ticket_received_ = SSL_early_callback_ctx_extension_get(
        client_hello, TLSEXT_TYPE_pre_shared_key, &unused_extension_bytes,
        &unused_extension_len);

    early_data_attempted_ = SSL_early_callback_ctx_extension_get(
        client_hello, TLSEXT_TYPE_early_data, &unused_extension_bytes,
        &unused_extension_len);

    int use_alps_new_codepoint = 0;

#if BORINGSSL_API_VERSION >= 27
    if (GetQuicReloadableFlag(quic_gfe_allow_alps_new_codepoint)) {
      QUIC_RELOADABLE_FLAG_COUNT(quic_gfe_allow_alps_new_codepoint);

      alps_new_codepoint_received_ = SSL_early_callback_ctx_extension_get(
          client_hello, TLSEXT_TYPE_application_settings,
          &unused_extension_bytes, &unused_extension_len);
      // Make sure we use the right ALPS codepoint.
      if (alps_new_codepoint_received_) {
        QUIC_CODE_COUNT(quic_gfe_alps_use_new_codepoint);
        use_alps_new_codepoint = 1;
      }
      QUIC_DLOG(INFO) << "ALPS use new codepoint: " << use_alps_new_codepoint;
      SSL_set_alps_use_new_codepoint(ssl(), use_alps_new_codepoint);
    }
#endif  // BORINGSSL_API_VERSION

    if (use_alps_new_codepoint == 0) {
      QUIC_CODE_COUNT(quic_gfe_alps_use_old_codepoint);
    }
  }

  // This callback is called very early by Boring SSL, most of the SSL_get_foo
  // function do not work at this point, but SSL_get_servername does.
  const char* hostname = SSL_get_servername(ssl(), TLSEXT_NAMETYPE_host_name);
  if (hostname) {
    crypto_negotiated_params_->sni =
        QuicHostnameUtils::NormalizeHostname(hostname);
    if (!ValidateHostname(hostname)) {
      CloseConnection(QUIC_HANDSHAKE_FAILED_INVALID_HOSTNAME,
                      "invalid hostname");
      return ssl_select_cert_error;
    }
    if (hostname != crypto_negotiated_params_->sni) {
      QUIC_CODE_COUNT(quic_tls_server_hostname_diff);
      QUIC_LOG_EVERY_N_SEC(WARNING, 300)
          << "Raw and normalized hostnames differ, but both are valid SNIs. "
             "raw hostname:"
          << hostname << ", normalized:" << crypto_negotiated_params_->sni;
    } else {
      QUIC_CODE_COUNT(quic_tls_server_hostname_same);
    }
  } else {
    QUIC_LOG(INFO) << "No hostname indicated in SNI";
  }

  std::string error_details;
  if (!ProcessTransportParameters(client_hello, &error_details)) {
    // No need to set_extra_error_details() - error_details already contains
    // enough information to indicate this is an error from
    // ProcessTransportParameters.
    CloseConnection(QUIC_HANDSHAKE_FAILED, error_details);
    return ssl_select_cert_error;
  }
  OverrideQuicConfigDefaults(session()->config());
  session()->OnConfigNegotiated();

  auto set_transport_params_result = SetTransportParameters();
  if (!set_transport_params_result.success) {
    set_extra_error_details("select_cert_error: set tp failure");
    return ssl_select_cert_error;
  }

  bssl::UniquePtr<uint8_t> ssl_capabilities;
  size_t ssl_capabilities_len = 0;
  absl::string_view ssl_capabilities_view;

  if (CryptoUtils::GetSSLCapabilities(ssl(), &ssl_capabilities,
                                      &ssl_capabilities_len)) {
    ssl_capabilities_view =
        absl::string_view(reinterpret_cast<const char*>(ssl_capabilities.get()),
                          ssl_capabilities_len);
  }

  // Enable ALPS for the session's ALPN.
  SetApplicationSettingsResult alps_result =
      SetApplicationSettings(AlpnForVersion(session()->version()));
  if (!alps_result.success) {
    set_extra_error_details("select_cert_error: set alps failure");
    return ssl_select_cert_error;
  }

  if (!session()->connection()->connected()) {
    select_cert_status_ = QUIC_FAILURE;
    return ssl_select_cert_error;
  }

  can_disable_resumption_ = false;
  const QuicAsyncStatus status = proof_source_handle_->SelectCertificate(
      session()->connection()->self_address().Normalized(),
      session()->connection()->peer_address().Normalized(),
      session()->connection()->GetOriginalDestinationConnectionId(),
      ssl_capabilities_view, crypto_negotiated_params_->sni,
      absl::string_view(
          reinterpret_cast<const char*>(client_hello->client_hello),
          client_hello->client_hello_len),
      AlpnForVersion(session()->version()), std::move(alps_result.alps_buffer),
      set_transport_params_result.quic_transport_params,
      set_transport_params_result.early_data_context,
      tls_connection_.ssl_config());

  QUICHE_DCHECK_EQ(status, *select_cert_status());

  if (status == QUIC_PENDING) {
    set_expected_ssl_error(SSL_ERROR_PENDING_CERTIFICATE);
    if (async_op_timer_.has_value()) {
      QUIC_CODE_COUNT(quic_tls_server_selecting_cert_while_another_op_pending);
    }
    async_op_timer_ = QuicTimeAccumulator();
    async_op_timer_->Start(now());
    return ssl_select_cert_retry;
  }

  if (status == QUIC_FAILURE) {
    set_extra_error_details("select_cert_error: proof_source_handle failure");
    return ssl_select_cert_error;
  }

  return ssl_select_cert_success;
}

void TlsServerHandshaker::OnSelectCertificateDone(
    bool ok, bool is_sync, SSLConfig ssl_config,
    absl::string_view ticket_encryption_key, bool cert_matched_sni) {
  QUIC_DVLOG(1) << "OnSelectCertificateDone. ok:" << ok
                << ", is_sync:" << is_sync << ", len(ticket_encryption_key):"
                << ticket_encryption_key.size();
  std::optional<QuicConnectionContextSwitcher> context_switcher;
  if (!is_sync) {
    context_switcher.emplace(connection_context());
  }

  QUIC_TRACESTRING(absl::StrCat(
      "TLS select certificate done: ok:", ok,
      ", len(ticket_encryption_key):", ticket_encryption_key.size()));

  ticket_encryption_key_ = std::string(ticket_encryption_key);
  select_cert_status_ = QUIC_FAILURE;
  cert_matched_sni_ = cert_matched_sni;

  // Extract the delayed SSL config from either LocalSSLConfig or
  // HintsSSLConfig.
  const QuicDelayedSSLConfig& delayed_ssl_config = absl::visit(
      [](const auto& config) { return config.delayed_ssl_config; }, ssl_config);

  if (delayed_ssl_config.quic_transport_parameters.has_value()) {
    // In case of any error the SSL object is still valid. Handshaker may need
    // to call ComputeSignature but otherwise can proceed.
    if (TransportParametersMatch(
            absl::MakeSpan(*delayed_ssl_config.quic_transport_parameters))) {
      if (SSL_set_quic_transport_params(
              ssl(), delayed_ssl_config.quic_transport_parameters->data(),
              delayed_ssl_config.quic_transport_parameters->size()) != 1) {
        QUIC_DVLOG(1) << "SSL_set_quic_transport_params override failed";
      }
    } else {
      QUIC_DVLOG(1)
          << "QUIC transport parameters mismatch with ProofSourceHandle";
    }
  }

  if (delayed_ssl_config.client_cert_mode.has_value()) {
    tls_connection_.SetClientCertMode(*delayed_ssl_config.client_cert_mode);
    QUIC_DVLOG(1) << "client_cert_mode after cert selection: "
                  << client_cert_mode();
  }

  if (ok) {
    if (auto* local_config = absl::get_if<LocalSSLConfig>(&ssl_config);
        local_config != nullptr) {
      if (local_config->chain && !local_config->chain->certs.empty()) {
        tls_connection_.SetCertChain(
            local_config->chain->ToCryptoBuffers().value);
        select_cert_status_ = QUIC_SUCCESS;
      } else {
        QUIC_DLOG(ERROR) << "No certs provided for host '"
                         << crypto_negotiated_params_->sni
                         << "', server_address:"
                         << session()->connection()->self_address()
                         << ", client_address:"
                         << session()->connection()->peer_address();
      }
    } else if (auto* hints_config = absl::get_if<HintsSSLConfig>(&ssl_config);
               hints_config != nullptr) {
      select_alpn_ = std::move(hints_config->select_alpn);
      if (hints_config->configure_ssl) {
        if (const absl::Status status = tls_connection_.ConfigureSSL(
                std::move(hints_config->configure_ssl));
            !status.ok()) {
          QUIC_CODE_COUNT(quic_tls_server_set_handshake_hints_failed);
          QUIC_DVLOG(1) << "SSL_set_handshake_hints failed: " << status;
        }
        select_cert_status_ = QUIC_SUCCESS;
      }
    } else {
      QUIC_DLOG(FATAL) << "Neither branch hit";
    }
  }

  QuicConnectionStats::TlsServerOperationStats select_cert_stats;
  select_cert_stats.success = (select_cert_status_ == QUIC_SUCCESS);
  if (!select_cert_stats.success) {
    set_extra_error_details(
        "select_cert_error: proof_source_handle async failure");
  }

  QUICHE_DCHECK_NE(is_sync, async_op_timer_.has_value());
  if (async_op_timer_.has_value()) {
    async_op_timer_->Stop(now());
    select_cert_stats.async_latency = async_op_timer_->GetTotalElapsedTime();
    async_op_timer_.reset();
    RECORD_LATENCY_IN_US("tls_server_async_select_cert_latency_us",
                         select_cert_stats.async_latency,
                         "Async select cert latency in microseconds");
  }
  connection_stats().tls_server_select_cert_stats =
      std::move(select_cert_stats);

  const int last_expected_ssl_error = expected_ssl_error();
  set_expected_ssl_error(SSL_ERROR_WANT_READ);
  if (!is_sync) {
    QUICHE_DCHECK_EQ(last_expected_ssl_error, SSL_ERROR_PENDING_CERTIFICATE);
    AdvanceHandshakeFromCallback();
  }
}

bool TlsServerHandshaker::WillNotCallComputeSignature() const {
  return SSL_can_release_private_key(ssl());
}

std::optional<uint16_t> TlsServerHandshaker::GetCiphersuite() const {
  const SSL_CIPHER* cipher = SSL_get_pending_cipher(ssl());
  if (cipher == nullptr) {
    return std::nullopt;
  }
  return SSL_CIPHER_get_protocol_id(cipher);
}

bool TlsServerHandshaker::ValidateHostname(const std::string& hostname) const {
  if (!QuicHostnameUtils::IsValidSNI(hostname)) {
    // TODO(b/151676147): Include this error string in the CONNECTION_CLOSE
    // frame.
    QUIC_DLOG(ERROR) << "Invalid SNI provided: \"" << hostname << "\"";
    return false;
  }
  return true;
}

int TlsServerHandshaker::TlsExtServernameCallback(int* /*out_alert*/) {
  // SSL_TLSEXT_ERR_OK causes the server_name extension to be acked in
  // ServerHello.
  return SSL_TLSEXT_ERR_OK;
}

int TlsServerHandshaker::SelectAlpn(const uint8_t** out, uint8_t* out_len,
                                    const uint8_t* in, unsigned in_len) {
  if (select_alpn_) {
    const int result =
        std::move(select_alpn_)(*ssl(), out, out_len, in, in_len);
    if (result == SSL_TLSEXT_ERR_OK) {
      valid_alpn_received_ = true;
      session()->OnAlpnSelected(
          absl::string_view(reinterpret_cast<const char*>(*out), *out_len));
    }
    return result;
  }

  // |in| contains a sequence of 1-byte-length-prefixed values.
  *out_len = 0;
  *out = nullptr;
  if (in_len == 0) {
    QUIC_DLOG(ERROR) << "No ALPN provided by client";
    return SSL_TLSEXT_ERR_NOACK;
  }

  CBS all_alpns;
  CBS_init(&all_alpns, in, in_len);

  std::vector<absl::string_view> alpns;
  while (CBS_len(&all_alpns) > 0) {
    CBS alpn;
    if (!CBS_get_u8_length_prefixed(&all_alpns, &alpn)) {
      QUIC_DLOG(ERROR) << "Failed to parse ALPN length";
      return SSL_TLSEXT_ERR_NOACK;
    }

    const size_t alpn_length = CBS_len(&alpn);
    if (alpn_length == 0) {
      QUIC_DLOG(ERROR) << "Received invalid zero-length ALPN";
      return SSL_TLSEXT_ERR_NOACK;
    }

    alpns.emplace_back(reinterpret_cast<const char*>(CBS_data(&alpn)),
                       alpn_length);
  }

  // TODO(wub): Remove QuicSession::SelectAlpn. QuicSessions should know the
  // ALPN on construction.
  auto selected_alpn = session()->SelectAlpn(alpns);
  if (selected_alpn == alpns.end()) {
    QUIC_DLOG(ERROR) << "No known ALPN provided by client";
    return SSL_TLSEXT_ERR_NOACK;
  }

  session()->OnAlpnSelected(*selected_alpn);
  valid_alpn_received_ = true;
  *out_len = selected_alpn->size();
  *out = reinterpret_cast<const uint8_t*>(selected_alpn->data());
  return SSL_TLSEXT_ERR_OK;
}

TlsServerHandshaker::SetApplicationSettingsResult
TlsServerHandshaker::SetApplicationSettings(absl::string_view alpn) {
  TlsServerHandshaker::SetApplicationSettingsResult result;

  const std::string& hostname = crypto_negotiated_params_->sni;
  std::string accept_ch_value = GetAcceptChValueForHostname(hostname);
  std::string origin = absl::StrCat("https://", hostname);
  uint16_t port = session()->self_address().port();
  if (port != kDefaultPort) {
    // This should be rare in production, but useful for test servers.
    QUIC_CODE_COUNT(quic_server_alps_non_default_port);
    absl::StrAppend(&origin, ":", port);
  }

  if (!accept_ch_value.empty()) {
    AcceptChFrame frame{{{std::move(origin), std::move(accept_ch_value)}}};
    result.alps_buffer = HttpEncoder::SerializeAcceptChFrame(frame);
  }

  const std::string& alps = result.alps_buffer;
  if (SSL_add_application_settings(
          ssl(), reinterpret_cast<const uint8_t*>(alpn.data()), alpn.size(),
          reinterpret_cast<const uint8_t*>(alps.data()), alps.size()) != 1) {
    QUIC_DLOG(ERROR) << "Failed to enable ALPS";
    result.success = false;
  } else {
    result.success = true;
  }
  return result;
}

SSL* TlsServerHandshaker::GetSsl() const { return ssl(); }

bool TlsServerHandshaker::IsCryptoFrameExpectedForEncryptionLevel(
    EncryptionLevel level) const {
  return level != ENCRYPTION_ZERO_RTT;
}

EncryptionLevel TlsServerHandshaker::GetEncryptionLevelToSendCryptoDataOfSpace(
    PacketNumberSpace space) const {
  switch (space) {
    case INITIAL_DATA:
      return ENCRYPTION_INITIAL;
    case HANDSHAKE_DATA:
      return ENCRYPTION_HANDSHAKE;
    case APPLICATION_DATA:
      return ENCRYPTION_FORWARD_SECURE;
    default:
      QUICHE_DCHECK(false);
      return NUM_ENCRYPTION_LEVELS;
  }
}

}  // namespace quic
```